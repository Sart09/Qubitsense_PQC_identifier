"""
Certificate Transparency log discovery.
Queries the crt.sh public API to find subdomains from issued certificates.
Falls back to CertSpotter API if crt.sh is unavailable or rate-limited.
"""

import urllib.request
import urllib.error
import json
import re
import time
import random


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
    hosts = _query_crtsh(domain)

    if not hosts:
        print("  [ct_logs] crt.sh failed — trying CertSpotter fallback...", flush=True)
        hosts = _query_certspotter(domain)

    return sorted(hosts)


def _query_crtsh(domain: str, retries: int = 4) -> set[str]:
    """Query crt.sh with exponential backoff for rate limiting (FIX 9)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    hosts: set[str] = set()

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "QubitsensePQC/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                # Check for rate limiting via status
                data = json.loads(resp.read().decode())

            for entry in data:
                for field in ("name_value", "common_name"):
                    raw = entry.get(field, "")
                    for name in raw.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and name.endswith(domain) and _is_valid_hostname(name):
                            hosts.add(name)

            return hosts  # Success

        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = (2 ** attempt) + random.uniform(0, 1)
                print(f"  [ct_logs] crt.sh rate limited (429). Waiting {wait:.1f}s (attempt {attempt+1}/{retries})...", flush=True)
                time.sleep(wait)
                continue
            else:
                print(f"  [ct_logs] crt.sh HTTP error {e.code}: {e.reason}", flush=True)
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                break

        except Exception as exc:
            print(f"  [ct_logs] crt.sh query failed: {exc}", flush=True)
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            break

    return hosts


def _query_certspotter(domain: str) -> set[str]:
    """Fallback: query CertSpotter API for subdomain discovery (FIX 9)."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    hosts: set[str] = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "QubitsensePQC/2.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())

        for entry in data:
            dns_names = entry.get("dns_names", [])
            for name in dns_names:
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain) and _is_valid_hostname(name):
                    hosts.add(name)

        print(f"  [ct_logs] CertSpotter returned {len(hosts)} hosts", flush=True)

    except Exception as exc:
        print(f"  [ct_logs] CertSpotter fallback failed: {exc}", flush=True)

    return hosts


def _is_valid_hostname(name: str) -> bool:
    """Basic check that a string looks like a hostname."""
    return bool(re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", name))
