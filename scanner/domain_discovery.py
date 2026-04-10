"""
Domain Discovery Engine.
Orchestrates CT logs, DNS brute force, and DNS record mining
to discover all assets associated with a domain.
Filters ghost subdomains (no DNS A record) before returning.
"""

import os
import sys
import socket
import json
import time
import asyncio
import urllib.error
import urllib.request
from datetime import datetime, timezone

# Ensure backend and scanner packages are importable.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ct_logs import discover_from_ct
from dns_enum import dns_bruteforce, dns_records
from database import get_connection


def _should_scan_host(hostname: str, domain: str) -> bool:
    """Filter out hosts that definitely won't have TLS/SSL on port 443.
    
    Returns False for:
    - Highly specific mail-only backend protocols (smtp, pop3, imap)
    - External third-party infrastructure
    - External SPF/DKIM services
    """
    lower_host = hostname.lower()
    
    # Skip mail backend services - but keep generic 'mail.' as it often hosts webmail
    if any(pattern in lower_host for pattern in ['smtp.', 'pop.', 'pop3.', 'imap.']):
        return False
    
    # Skip external message delivery systems
    if 'messagelabs' in lower_host or 'protection.outlook.com' in lower_host:
        return False
        
    # Skip external SPF/DKIM/DMARC services
    if any(pattern in lower_host for pattern in ['spf.', 'dkim.', 'dmarc.']):
        return False
    
    # Only scan hosts within the target domain (no external services)
    if not lower_host.endswith(domain.lower()):
        return False
    
    return True


def discover_assets(domain: str) -> list[str]:
    """
    Run the full discovery pipeline and return a deduplicated list of hostnames.

    Techniques used:
    1. Certificate Transparency logs (crt.sh + CertSpotter fallback)
    2. DNS brute force enumeration
    3. DNS record mining (MX / NS / TXT - filtered to internal only)
    4. AlienVault OTX passive DNS

    Ghost subdomains (no DNS A record) are filtered out before returning.

    Parameters
    ----------
    domain : str
        The parent domain to scan (e.g. ``example.com``).

    Returns
    -------
    list[str]
        Sorted, deduplicated list of discovered hostnames (TLS-scannable only).
    """
    all_hosts: set[str] = set()

    # Always include the root domain itself
    all_hosts.add(domain)

    print(f"  [discovery] Running CT log lookup for {domain}...", flush=True)
    ct_hosts = discover_from_ct(domain)
    print(f"  [discovery] CT logs returned {len(ct_hosts)} hosts", flush=True)
    all_hosts.update(ct_hosts)

    print(f"  [discovery] Running AlienVault OTX lookup for {domain}...", flush=True)
    av_hosts = discover_from_alienvault(domain)
    print(f"  [discovery] AlienVault OTX returned {len(av_hosts)} hosts", flush=True)
    all_hosts.update(av_hosts)

    print(f"  [discovery] Running DNS brute force for {domain}...", flush=True)
    dns_hosts = dns_bruteforce(domain)
    print(f"  [discovery] DNS brute force found {len(dns_hosts)} hosts", flush=True)
    all_hosts.update(dns_hosts)

    print(f"  [discovery] Mining DNS records for {domain}...", flush=True)
    record_hosts = dns_records(domain)
    print(f"  [discovery] DNS records returned {len(record_hosts)} hosts", flush=True)
    all_hosts.update(record_hosts)

    # Filter out hosts that won't have TLS on port 443
    scanned_hosts = []
    skipped_hosts = []
    for h in all_hosts:
        if _should_scan_host(h, domain):
            scanned_hosts.append(h)
        else:
            skipped_hosts.append(h)
            
    filtered_count = len(skipped_hosts)
    
    if filtered_count > 0:
        print(f"  [discovery] Filtered out {filtered_count} non-TLS hosts (specific mail protocols, external CDNs)", flush=True)
        # Optional: log a few examples if needed for debugging
    
    print(f"  [discovery] Total unique hosts before ghost filter: {len(scanned_hosts)}", flush=True)

    # FIX 2: Pre-scan ghost filter — remove subdomains with no DNS A record
    # This eliminates CT log ghosts and decommissioned hosts BEFORE TLS scanning
    try:
        from tls_scanner_async_concurrent import filter_live_subdomains
        
        # Run the async filter
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        if loop and loop.is_running():
            # Already in an async context — we can't nest asyncio.run()
            # The caller (scan_worker) will handle ghost filtering separately
            print(f"  [discovery] Ghost filtering deferred to scan worker (async context active)", flush=True)
            return sorted(scanned_hosts)
        else:
            import sys
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            live_hosts, ghost_count = asyncio.run(filter_live_subdomains(scanned_hosts))
            if ghost_count > 0:
                print(f"  [discovery] ⚠ Filtered out {ghost_count} ghost subdomains (no DNS A record)", flush=True)
            print(f"  [discovery] Live hosts for TLS scanning: {len(live_hosts)}", flush=True)
            return sorted(live_hosts)
    except ImportError:
        print(f"  [discovery] Ghost filter unavailable, returning all hosts", flush=True)
        return sorted(scanned_hosts)


def resolve_ip(hostname: str) -> str:
    """Best-effort IP resolution; returns empty string on failure."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return ""


def discover_from_alienvault(domain: str) -> list[str]:
    """Query AlienVault OTX passive DNS API for subdomain enumeration.
    
    Handles:
    - Rate limiting (HTTP 429) with backoff
    - API key authentication (from ALIENVAULT_API_KEY env var)
    - Network timeouts with retry
    - Malformed responses
    """
    hosts = set()
    
    # Try to get API key from environment
    api_key = os.environ.get('ALIENVAULT_API_KEY', '').strip()
    
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    
    for attempt in range(3):  # Retry up to 3 times
        try:
            headers = {
                "User-Agent": "QubitsensePQC/2.0",
                "Accept": "application/json",
            }
            
            # Add API key if available
            if api_key:
                headers['X-OTX-API-KEY'] = api_key
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
                for entry in data.get("passive_dns", []):
                    host = entry.get("hostname", "").strip().lower()
                    if host and not host.startswith("*") and host.endswith(domain):
                        hosts.add(host)
                return sorted(hosts)[:2000]  # Success - return results
                
        except urllib.error.HTTPError as e:
            if e.code == 429:  # Rate limited
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                print(f"  [discovery] AlienVault rate limited (429). Waiting {wait_time}s before retry {attempt+1}/3...", flush=True)
                time.sleep(wait_time)
                continue
            elif e.code == 401:  # Unauthorized
                print(f"  [discovery] AlienVault authentication failed. Check ALIENVAULT_API_KEY environment variable.", flush=True)
                return []
            elif e.code in [400, 404]:  # Client errors - don't retry
                print(f"  [discovery] AlienVault API error {e.code}: {e.reason}. Skipping.", flush=True)
                return []
            else:
                print(f"  [discovery] AlienVault HTTP error {e.code}: {e.reason}", flush=True)
                continue
                
        except socket.timeout:
            if attempt < 2:
                wait_time = 3 * (attempt + 1)
                print(f"  [discovery] AlienVault timeout. Retrying in {wait_time}s... ({attempt+1}/3)", flush=True)
                time.sleep(wait_time)
                continue
            else:
                print(f"  [discovery] AlienVault query timed out after 3 attempts. Skipping.", flush=True)
                return []
                
        except json.JSONDecodeError:
            print(f"  [discovery] AlienVault returned invalid JSON. Skipping.", flush=True)
            return []
            
        except Exception as exc:
            print(f"  [discovery] AlienVault query error: {exc}. Attempt {attempt+1}/3", flush=True)
            if attempt < 2:
                time.sleep(1)
                continue
            break
    
    # If we get here, all retries failed
    print(f"  [discovery] AlienVault exhausted all retries. Proceeding with other discovery methods.", flush=True)
    return sorted(hosts)


def store_asset(scan_id: int, hostname: str, ip_address: str, method: str) -> int:
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
        Discovery method (``ct_logs``, ``dns_bruteforce``, ``dns_records``, ``root``).

    Returns
    -------
    int
        Row ID of the inserted asset.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO discovered_assets (scan_id, hostname, ip_address, discovery_method, created_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            (scan_id, hostname, ip_address, method, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()
