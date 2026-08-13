"""
Domain Discovery Engine — Improved.
Orchestrates CT logs, AlienVault OTX, DNS brute force,
and DNS record mining to discover all assets associated with a domain.

Improvements over previous version:
- Wildcard cert stripping (*. prefix removed, base domain added as candidate)
- Ghost filter moved to END of pipeline (was filtering mid-pipeline)
- AlienVault with exponential backoff on 429 rate limiting
- API key support for AlienVault via ALIENVAULT_API_KEY env var
- Per-technique discovery counts logged for benchmarking
- Scopes all hosts to target domain before ghost filtering
"""

import os
import sys
import re
import socket
import json
import time
import asyncio
import concurrent.futures
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    GHOST_FILTER_CONCURRENCY, DEFINITIVE_NXDOMAIN,
    SourceUnavailable, SourceNotConfigured,
)
import dns_cache
from ct_logs import discover_from_ct
from dns_enum import dns_bruteforce, dns_records
from database import get_connection


# ══════════════════════════════════════════════════════════════════════
# FILTERS
# ══════════════════════════════════════════════════════════════════════

def _scope_to_domain(hosts: set[str], domain: str) -> set[str]:
    """Keep only hostnames that belong to the target domain."""
    return {h for h in hosts if h.lower().endswith(domain.lower())}


def _strip_wildcards(hosts: set[str]) -> set[str]:
    """
    Strip *. prefix from wildcard entries and add the base domain.
    '*.api.bank.com' → 'api.bank.com'
    Wildcard entries in CT logs indicate the base domain exists
    even if the wildcard itself cannot be scanned directly.
    """
    cleaned: set[str] = set()
    for h in hosts:
        if h.startswith("*."):
            cleaned.add(h[2:])   # strip *. and keep base
        else:
            cleaned.add(h)
    return cleaned


# ══════════════════════════════════════════════════════════════════════
# GHOST FILTER — Run ONCE at end of pipeline
# ══════════════════════════════════════════════════════════════════════

# Shared with dns_enum's brute-force resolver — see config.DEFINITIVE_NXDOMAIN.
_DEFINITIVE_NXDOMAIN = DEFINITIVE_NXDOMAIN


def _resolve_one(hostname: str) -> bool:
    """
    True if the hostname has at least one A or AAAA record, False only if
    the resolver definitively said it does not exist.

    The distinction is load-bearing. The previous version caught every
    exception and returned False, which conflated NXDOMAIN ("this is a
    ghost") with SERVFAIL / EAI_AGAIN / timeout ("ask me later") — so
    whenever the local resolver was overloaded, live hosts were silently
    deleted from the inventory. Verified live: a wikipedia.org scan lost
    all 14 candidates including the apex domain, which plainly resolves.

    Ambiguous answers are retried once and then FAIL OPEN (host kept). A
    host wrongly kept costs one TLS attempt that fails and is recorded as a
    visible, attributable scan failure. A host wrongly removed vanishes from
    the inventory with no trace and shrinks the reported attack surface —
    for a posture tool, under-reporting the estate is the worse error.
    """
    cached = dns_cache.get(f"live:{hostname}")
    if cached is not dns_cache.MISS:
        return cached

    definitive_miss = False

    for attempt in range(2):
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
                dns_cache.put(f"live:{hostname}", True)
                return True
            except socket.gaierror as exc:
                if exc.errno in _DEFINITIVE_NXDOMAIN:
                    definitive_miss = True
                # Anything else (EAI_AGAIN, EAI_FAIL, WSATRY_AGAIN) is the
                # resolver failing, not the name being absent.
            except Exception:
                # Timeouts and unexpected socket errors are equally
                # inconclusive — never proof of absence.
                pass

        if definitive_miss:
            dns_cache.put(f"live:{hostname}", False)
            return False
        if attempt == 0:
            # Brief pause before the retry: these failures cluster when the
            # resolver is saturated, and retrying instantly just re-hits the
            # same saturated resolver.
            time.sleep(0.25)

    # Inconclusive after a retry — keep the host rather than delete it, and
    # deliberately do NOT cache: a transient failure must not become the
    # answer of record for the next TTL.
    return True


def _filter_live_hosts_sync(hosts: list[str],
                            max_workers: int = GHOST_FILTER_CONCURRENCY) -> tuple[list[str], int]:
    """
    Ghost filter — resolves each hostname and keeps only those with at
    least one DNS A or AAAA record.

    Threaded (getaddrinfo releases the GIL during I/O), matching the
    concurrency pattern already used for brute-force resolution in
    dns_enum.py. A sequential version of this loop measured ~300s at
    5000 hosts; with discovery yield now in the hundreds (subdomain.center),
    a sequential ghost filter would itself have become the dominant cost.

    Returns
    -------
    tuple[live_hosts, ghost_count]
    """
    if not hosts:
        return [], 0

    live: list[str] = []
    ghost_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for hostname, resolved in zip(hosts, executor.map(_resolve_one, hosts)):
            if resolved:
                live.append(hostname)
            else:
                ghost_count += 1

    return live, ghost_count


# ══════════════════════════════════════════════════════════════════════
# MASTER DISCOVERY PIPELINE
# ══════════════════════════════════════════════════════════════════════

def discover_assets(domain: str, log=None) -> tuple[list[str], int, list[str]]:
    """
    Run the full discovery pipeline and return a deduplicated,
    ghost-filtered list of live hostnames ready for TLS scanning.

    Techniques used (run concurrently — independent network calls with no
    data dependency between them):
    0. subdomain.center (no key required)
    1. Certificate Transparency logs (crt.sh + CertSpotter fallback)
    2. AlienVault OTX passive DNS (with rate-limit backoff + API key)
    3. DNS brute force (200+ word wordlist, 100 concurrent workers,
       CNAME chain following, A+AAAA dual-stack)
    4. DNS record mining (MX, NS, TXT, SOA, SRV + SPF/DMARC regex)

    Ghost subdomains (no DNS A/AAAA record) are filtered ONCE at the
    very end — after ALL techniques have run and merged.

    Parameters
    ----------
    domain : str
        The parent domain to scan (e.g. ``example.com``).
    log : callable, optional
        Sink for progress lines. Everything this pipeline learns used to go
        to the worker's stdout only, so the operator watching the browser
        saw one summary count for a phase that had just made five separate
        network calls and thrown away the detail. Pass the scan's log
        writer here and the per-technique yields, the scope filter, the
        ghost filter and the full live inventory all reach the Live
        Execution Trace. Defaults to stdout when omitted, so calling this
        function outside a scan (tests, REPL) behaves exactly as before.

    Returns
    -------
    tuple[list[str], int, list[str]]
        Sorted, deduplicated list of live hostnames; the ghost count
        (candidates that definitively resolved to nothing); and the names of
        any discovery sources that were unavailable. A non-empty third
        element means the host list is a lower bound — the caller must not
        present it as a complete inventory or let it displace a fuller
        earlier result.
    """
    def emit(message: str) -> None:
        """One line to whichever sink the caller gave us — never both, or
        the worker console double-prints every discovery line."""
        if log is not None:
            log(message)
        else:
            print(f"  [discovery] {message}", flush=True)

    all_hosts: set[str] = set()

    # Always include the root domain
    all_hosts.add(domain.lower())

    # ── Techniques 0-4: run concurrently ────────────────────────────────
    # These are five independent network calls with no data dependency
    # between them (each returns its own host list; merging happens after
    # all complete). Running them sequentially meant the wall clock was
    # their SUM — dominated by CT logs' worst case (crt.sh + CertSpotter
    # both timing out, ~11s) stacked on top of DNS brute force (~9s) and
    # everything else. Concurrently, the wall clock is close to their MAX.
    techniques = {
        "subdomain.center": discover_from_subdomain_center,
        "CT logs": discover_from_ct,
        "AlienVault OTX": discover_from_alienvault,
        "DNS brute force": dns_bruteforce,
        "DNS record mining": dns_records,
    }
    emit(f"[DISCOVERY] Running {len(techniques)} discovery techniques "
         f"concurrently for {domain}...")

    raw_results: dict[str, list[str]] = {}
    failed_sources: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(techniques)) as executor:
        futures = {executor.submit(fn, domain): name for name, fn in techniques.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                raw_results[name] = future.result()
            except SourceNotConfigured as exc:
                # Known permanent gap, not a degraded run — logged so the
                # operator can close it, but deliberately kept OUT of
                # failed_sources so it does not flag every scan.
                emit(f"[DISCOVERY] ○ {name} not configured — {exc}")
                raw_results[name] = []
                continue
            except SourceUnavailable as exc:
                # Recorded separately from "returned nothing". This is the
                # distinction that stops a rate-limited run from being
                # reported as a genuinely smaller estate.
                emit(f"[DISCOVERY] ✗ {name} UNAVAILABLE — {exc}. "
                     f"Its subdomains are missing from this scan, not absent "
                     f"from the estate.")
                failed_sources.append(name)
                raw_results[name] = []
                continue
            except Exception as exc:
                emit(f"[DISCOVERY] ✗ {name} raised an exception: {exc}")
                failed_sources.append(name)
                raw_results[name] = []
                continue
            # Reported as each technique lands rather than after all five,
            # so a source that is slow or returning nothing is visible while
            # the others are still running.
            emit(f"[DISCOVERY] ↳ {name}: {len(raw_results[name])} hosts")

    # CT hosts get wildcard-stripped before merging; everything else merges directly.
    ct_cleaned = _strip_wildcards(set(raw_results.get("CT logs", [])))
    emit(f"[DISCOVERY] CT logs: {len(raw_results.get('CT logs', []))} raw → "
         f"{len(ct_cleaned)} after wildcard strip")
    all_hosts.update(ct_cleaned)

    for name in ("subdomain.center", "AlienVault OTX", "DNS brute force", "DNS record mining"):
        all_hosts.update(raw_results.get(name, []))

    # ── Scope to target domain only ───────────────────────────────────
    scoped = _scope_to_domain(all_hosts, domain)
    out_of_scope = len(all_hosts) - len(scoped)
    emit(f"[DISCOVERY] Merged to {len(scoped)} unique in-scope candidates "
         f"({out_of_scope} out-of-scope dropped)")

    # ── Ghost filter — ONCE at end of pipeline ────────────────────────
    # Previous version ran this mid-pipeline which caused valid hosts
    # to be dropped before all techniques had run.
    emit(f"[DISCOVERY] Ghost filter: DNS A/AAAA check on {len(scoped)} candidates...")
    live_hosts, ghost_count = _filter_live_hosts_sync(list(scoped))

    emit(f"[DISCOVERY] Ghost filter: {ghost_count} removed (no DNS record) • "
         f"{len(live_hosts)} live")

    if failed_sources:
        emit(f"[DISCOVERY] ⚠ PARTIAL DISCOVERY — {len(failed_sources)} source(s) "
             f"unavailable ({', '.join(sorted(failed_sources))}). "
             f"{len(live_hosts)} hosts is a lower bound for this estate, not a "
             f"complete inventory. Re-run in a few minutes for full coverage.")

    return sorted(live_hosts), ghost_count, failed_sources


# ══════════════════════════════════════════════════════════════════════
# SUBDOMAIN.CENTER — no key required
# ══════════════════════════════════════════════════════════════════════

def discover_from_subdomain_center(domain: str) -> list[str]:
    """Query api.subdomain.center — no API key required."""
    try:
        req = urllib.request.Request(
            f"https://api.subdomain.center/?domain={domain}",
            headers={"User-Agent": "QubitsensePQC/2.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        return [h.strip().lower() for h in data if isinstance(h, str) and h.strip()]
    except Exception as e:
        print(f"  [discovery] subdomain.center failed: {e}", flush=True)
        # Raise rather than return [] — an unreachable source and a source
        # with nothing to report are not the same answer, and the pipeline
        # can only tell them apart if this one propagates.
        raise SourceUnavailable(f"subdomain.center: {e}") from e


# ══════════════════════════════════════════════════════════════════════
# ALIENVAULT OTX — With Backoff + API Key Support
# ══════════════════════════════════════════════════════════════════════

def discover_from_alienvault(domain: str) -> list[str]:
    """
    Query AlienVault OTX passive DNS API for subdomain enumeration.

    Handles:
    - Rate limiting (HTTP 429) with exponential backoff (keyed requests only)
    - API key from ALIENVAULT_API_KEY environment variable
    - Network timeouts with retry (keyed requests only)
    - Malformed responses

    Without a key, this makes exactly ONE attempt with a short timeout and
    does not retry on 429/timeout/generic error. The anonymous OTX tier's
    rate limiting is measured in minutes to hours — retries totaling a few
    seconds can never clear it, so retrying was always going to return
    empty while burning the scan's time budget on a source that structurally
    cannot succeed. A keyed request has a real chance on retry, so it keeps
    the original patient behavior.
    """
    hosts: set[str] = set()
    api_key = os.environ.get("ALIENVAULT_API_KEY", "").strip()
    max_attempts = 3 if api_key else 1
    req_timeout = 20 if api_key else 6

    url = (f"https://otx.alienvault.com/api/v1/indicators"
           f"/domain/{domain}/passive_dns")

    for attempt in range(max_attempts):
        try:
            headers = {
                "User-Agent": "QubitsensePQC/2.0",
                "Accept": "application/json",
            }
            if api_key:
                headers["X-OTX-API-KEY"] = api_key

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=req_timeout) as resp:
                data = json.loads(resp.read().decode())
                for entry in data.get("passive_dns", []):
                    host = entry.get("hostname", "").strip().lower()
                    if (host
                            and not host.startswith("*")
                            and host.endswith(domain)):
                        hosts.add(host)
                return sorted(hosts)[:2000]

        except urllib.error.HTTPError as e:
            if e.code == 429:
                if not api_key:
                    # Chronic, not transient: the anonymous tier is always
                    # throttled. A config gap, not a failed lookup.
                    raise SourceNotConfigured(
                        "AlienVault OTX: anonymous tier is rate limited — "
                        "set ALIENVAULT_API_KEY for this source to contribute"
                    )
                wait = 2 ** attempt
                print(f"  [discovery] AlienVault rate limited. "
                      f"Waiting {wait}s... ({attempt+1}/{max_attempts})", flush=True)
                time.sleep(wait)
                continue
            elif e.code == 401:
                raise SourceNotConfigured(
                    "AlienVault OTX: ALIENVAULT_API_KEY rejected (HTTP 401)"
                )
            elif e.code in (400, 404):
                # A real answer: OTX has no passive DNS for this domain.
                return []
            else:
                print(f"  [discovery] AlienVault HTTP {e.code}: "
                      f"{e.reason}", flush=True)
                if not api_key:
                    raise SourceUnavailable(f"AlienVault OTX: HTTP {e.code}")
                continue

        except socket.timeout:
            if not api_key:
                raise SourceNotConfigured(
                    "AlienVault OTX: timed out on the anonymous tier — "
                    "set ALIENVAULT_API_KEY for this source to contribute"
                )
            wait = 3 * (attempt + 1)
            print(f"  [discovery] AlienVault timeout. "
                  f"Retrying in {wait}s... ({attempt+1}/{max_attempts})", flush=True)
            time.sleep(wait)
            continue

        except json.JSONDecodeError as exc:
            raise SourceUnavailable(
                "AlienVault OTX: malformed JSON response"
            ) from exc

        except Exception as exc:
            print(f"  [discovery] AlienVault error: {exc}. "
                  f"Attempt {attempt+1}/{max_attempts}", flush=True)
            if api_key and attempt < max_attempts - 1:
                time.sleep(1)
                continue
            raise SourceUnavailable(f"AlienVault OTX: {exc}") from exc

    # Retries exhausted without a usable response. Partial results (if any)
    # are still worth returning, but an empty set here means "could not
    # ask", not "nothing to find".
    if not hosts:
        raise SourceUnavailable("AlienVault OTX: exhausted retries")
    print(f"  [discovery] AlienVault exhausted retries. "
          f"Continuing with partial results.", flush=True)
    return sorted(hosts)


# ══════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════

def resolve_ip(hostname: str) -> str:
    """Best-effort IPv4 resolution; returns empty string on failure."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return ""


def store_asset(
    scan_id: int,
    hostname: str,
    ip_address: str,
    method: str
) -> int:
    """
    Insert a discovered asset into the database.

    Parameters
    ----------
    scan_id : int
        Parent scan job ID.
    hostname : str
        The discovered hostname.
    ip_address : str
        Resolved IP address (may be empty).
    method : str
        Discovery method.

    Returns
    -------
    int
        Row ID of the inserted asset.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO discovered_assets
                (scan_id, hostname, ip_address, discovery_method, created_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            (
                scan_id,
                hostname,
                ip_address,
                method,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()
