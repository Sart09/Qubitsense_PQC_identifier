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
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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

def _filter_live_hosts_sync(hosts: list[str]) -> tuple[list[str], int]:
    """
    Synchronous ghost filter — resolves each hostname and keeps only
    those with at least one DNS A or AAAA record.

    Runs in the calling thread (safe in both sync and async contexts).

    Returns
    -------
    tuple[live_hosts, ghost_count]
    """
    live: list[str] = []
    ghost_count = 0

    for hostname in hosts:
        resolved = False
        # A record
        try:
            socket.getaddrinfo(
                hostname, None, socket.AF_INET, socket.SOCK_STREAM
            )
            resolved = True
        except Exception:
            pass

        # AAAA fallback
        if not resolved:
            try:
                socket.getaddrinfo(
                    hostname, None, socket.AF_INET6, socket.SOCK_STREAM
                )
                resolved = True
            except Exception:
                pass

        if resolved:
            live.append(hostname)
        else:
            ghost_count += 1

    return live, ghost_count


# ══════════════════════════════════════════════════════════════════════
# MASTER DISCOVERY PIPELINE
# ══════════════════════════════════════════════════════════════════════

def discover_assets(domain: str) -> list[str]:
    """
    Run the full discovery pipeline and return a deduplicated,
    ghost-filtered list of live hostnames ready for TLS scanning.

    Techniques used:
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

    Returns
    -------
    list[str]
        Sorted, deduplicated list of live hostnames.
    """
    all_hosts: set[str] = set()

    # Always include the root domain
    all_hosts.add(domain.lower())

    # ── Technique 1: CT Logs ──────────────────────────────────────────
    print(f"  [discovery] Running CT log lookup for {domain}...",
          flush=True)
    ct_hosts = discover_from_ct(domain)
    # Strip wildcards before adding — *. prefix → base domain
    ct_cleaned = _strip_wildcards(set(ct_hosts))
    print(f"  [discovery] CT logs: {len(ct_hosts)} raw → "
          f"{len(ct_cleaned)} after wildcard strip", flush=True)
    all_hosts.update(ct_cleaned)

    # ── Technique 2: AlienVault OTX ──────────────────────────────────
    print(f"  [discovery] Running AlienVault OTX lookup for {domain}...",
          flush=True)
    av_hosts = discover_from_alienvault(domain)
    print(f"  [discovery] AlienVault OTX returned "
          f"{len(av_hosts)} hosts", flush=True)
    all_hosts.update(av_hosts)

    # ── Technique 3: DNS Brute Force ──────────────────────────────────
    print(f"  [discovery] Running DNS brute force for {domain}...",
          flush=True)
    dns_hosts = dns_bruteforce(domain)
    print(f"  [discovery] DNS brute force found "
          f"{len(dns_hosts)} hosts", flush=True)
    all_hosts.update(dns_hosts)

    # ── Technique 4: DNS Record Mining ───────────────────────────────
    print(f"  [discovery] Mining DNS records for {domain}...",
          flush=True)
    record_hosts = dns_records(domain)
    print(f"  [discovery] DNS record mining found "
          f"{len(record_hosts)} hosts", flush=True)
    all_hosts.update(record_hosts)

    # ── Scope to target domain only ───────────────────────────────────
    scoped = _scope_to_domain(all_hosts, domain)
    print(f"  [discovery] Total unique candidates "
          f"(in-scope): {len(scoped)}", flush=True)

    # ── Ghost filter — ONCE at end of pipeline ────────────────────────
    # Previous version ran this mid-pipeline which caused valid hosts
    # to be dropped before all techniques had run.
    print(f"  [discovery] Running ghost filter (DNS A/AAAA check)...",
          flush=True)
    live_hosts, ghost_count = _filter_live_hosts_sync(list(scoped))

    print(f"  [discovery] Ghost subdomains removed : {ghost_count}",
          flush=True)
    print(f"  [discovery] Live hosts for TLS scan  : {len(live_hosts)}",
          flush=True)

    return sorted(live_hosts)


# ══════════════════════════════════════════════════════════════════════
# ALIENVAULT OTX — With Backoff + API Key Support
# ══════════════════════════════════════════════════════════════════════

def discover_from_alienvault(domain: str) -> list[str]:
    """
    Query AlienVault OTX passive DNS API for subdomain enumeration.

    Handles:
    - Rate limiting (HTTP 429) with exponential backoff
    - API key from ALIENVAULT_API_KEY environment variable
    - Network timeouts with retry (3 attempts)
    - Malformed responses
    """
    hosts: set[str] = set()
    api_key = os.environ.get("ALIENVAULT_API_KEY", "").strip()

    url = (f"https://otx.alienvault.com/api/v1/indicators"
           f"/domain/{domain}/passive_dns")

    for attempt in range(3):
        try:
            headers = {
                "User-Agent": "QubitsensePQC/2.0",
                "Accept": "application/json",
            }
            if api_key:
                headers["X-OTX-API-KEY"] = api_key

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
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
                wait = 2 ** attempt
                print(f"  [discovery] AlienVault rate limited. "
                      f"Waiting {wait}s... ({attempt+1}/3)", flush=True)
                time.sleep(wait)
                continue
            elif e.code == 401:
                print(f"  [discovery] AlienVault auth failed. "
                      f"Set ALIENVAULT_API_KEY env var.", flush=True)
                return []
            elif e.code in (400, 404):
                return []
            else:
                print(f"  [discovery] AlienVault HTTP {e.code}: "
                      f"{e.reason}", flush=True)
                continue

        except socket.timeout:
            wait = 3 * (attempt + 1)
            print(f"  [discovery] AlienVault timeout. "
                  f"Retrying in {wait}s... ({attempt+1}/3)", flush=True)
            time.sleep(wait)
            continue

        except json.JSONDecodeError:
            print(f"  [discovery] AlienVault returned invalid JSON.",
                  flush=True)
            return []

        except Exception as exc:
            print(f"  [discovery] AlienVault error: {exc}. "
                  f"Attempt {attempt+1}/3", flush=True)
            if attempt < 2:
                time.sleep(1)
                continue
            break

    print(f"  [discovery] AlienVault exhausted retries. "
          f"Continuing with other sources.", flush=True)
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
