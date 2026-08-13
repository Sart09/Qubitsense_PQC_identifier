"""
Certificate Transparency log discovery.
Queries the crt.sh public API to find subdomains from issued certificates.
Falls back to CertSpotter API if crt.sh is unavailable or rate-limited.
"""

import urllib.request
import urllib.error
import json
import os
import re
import sys
import time
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import SourceUnavailable


def discover_from_ct(domain: str) -> list[str]:
    """
    Query CT log APIs for certificates matching ``*.domain``.

    Tries crt.sh first with rate-limit handling, then falls back to
    CertSpotter if crt.sh fails after retries.

    Parameters
    ----------
    domain : str
        The parent domain to search (e.g. ``example.com``).

    Returns
    -------
    list[str]
        Deduplicated list of discovered hostnames.
    """
    hosts, crtsh_errored = _query_crtsh(domain)

    # Fall back when crt.sh could not answer, OR when it answered empty —
    # an empty CT result for a real domain is unusual enough to be worth a
    # second opinion, and CertSpotter is cheap when crt.sh already returned.
    certspotter_errored = False
    if crtsh_errored or not hosts:
        print("  [ct_logs] crt.sh failed — trying CertSpotter fallback...", flush=True)
        fallback, certspotter_errored = _query_certspotter(domain)
        hosts = hosts or fallback

    # Both providers unreachable: report that as a failure rather than as an
    # empty result. Returning [] here made a rate-limited CT lookup look
    # identical to a domain with no certificates, and the pipeline then
    # published the shrunken host list with full confidence.
    if crtsh_errored and certspotter_errored and not hosts:
        raise SourceUnavailable("CT logs: crt.sh and CertSpotter both unreachable")

    return sorted(hosts)


def _query_crtsh(domain: str) -> set[str]:
    """
    Query crt.sh, bounded to at most ~2 attempts and a few seconds of total
    retry sleep regardless of HOW it fails.

    Originally retried up to 4 times with growing backoff on EVERY failure
    mode (429, 5xx, other HTTP errors, timeouts, generic exceptions alike).
    Measured live: on a day crt.sh was degraded, that produced a 15s hard
    timeout on attempt 1, then three more attempts each hitting a fast 404,
    with cumulative backoff sleeps between them — over 50s total before
    even reaching the CertSpotter fallback. A 429 (server alive, actively
    throttling) is the one case worth a real backoff; everything else
    (dead/misbehaving service, malformed response, network timeout) is
    exactly as likely to succeed on attempt 2 as attempt 4, so there is no
    value in more than one retry.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    hosts: set[str] = set()
    max_attempts = 2

    for attempt in range(max_attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "QubitsensePQC/2.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())

            for entry in data:
                for field in ("name_value", "common_name"):
                    raw = entry.get(field, "")
                    for name in raw.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and name.endswith(domain) and _is_valid_hostname(name):
                            hosts.add(name)

            return hosts, False  # Success — an empty set here is a real answer

        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = (2 ** attempt) + random.uniform(0, 1)
                print(f"  [ct_logs] crt.sh rate limited (429). Waiting {wait:.1f}s (attempt {attempt+1}/{max_attempts})...", flush=True)
                time.sleep(wait)
                continue
            print(f"  [ct_logs] crt.sh HTTP error {e.code}: {e.reason}", flush=True)
            if attempt < max_attempts - 1:
                time.sleep(1.5)
                continue
            break

        except TimeoutError:
            # A hard read-timeout already burned the full per-request
            # timeout once; a hung connection rarely un-hangs immediately,
            # so retrying buys another full timeout for the same result.
            print(f"  [ct_logs] crt.sh timed out — not retrying.", flush=True)
            break

        except Exception as exc:
            print(f"  [ct_logs] crt.sh query failed: {exc}", flush=True)
            if attempt < max_attempts - 1:
                time.sleep(1.5)
                continue
            break

    # Every path to here exhausted or aborted the attempts, so the empty
    # set means "could not ask", not "nothing to find".
    return hosts, True


def _query_certspotter(domain: str) -> set[str]:
    """Fallback: query CertSpotter API for subdomain discovery. Single
    attempt, short timeout — this only runs when crt.sh already failed, so
    a slow failure here directly extends the whole discovery phase."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    hosts: set[str] = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "QubitsensePQC/2.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())

        for entry in data:
            dns_names = entry.get("dns_names", [])
            for name in dns_names:
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain) and _is_valid_hostname(name):
                    hosts.add(name)

        print(f"  [ct_logs] CertSpotter returned {len(hosts)} hosts", flush=True)
        return hosts, False

    except Exception as exc:
        print(f"  [ct_logs] CertSpotter fallback failed: {exc}", flush=True)

    return hosts, True


def _is_valid_hostname(name: str) -> bool:
    """Basic check that a string looks like a hostname."""
    return bool(re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", name))
