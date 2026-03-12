"""
Domain Discovery Engine.
Orchestrates CT logs, DNS brute force, and DNS record mining
to discover all assets associated with a domain.
"""

import os
import sys
import socket
from datetime import datetime, timezone

# Ensure backend and scanner packages are importable.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ct_logs import discover_from_ct
from dns_enum import dns_bruteforce, dns_records
from database import get_connection


def discover_assets(domain: str) -> list[str]:
    """
    Run the full discovery pipeline and return a deduplicated list of hostnames.

    Techniques used:
    1. Certificate Transparency logs (crt.sh)
    2. DNS brute force enumeration
    3. DNS record mining (MX / NS / TXT)

    Parameters
    ----------
    domain : str
        The parent domain to scan (e.g. ``example.com``).

    Returns
    -------
    list[str]
        Sorted, deduplicated list of discovered hostnames.
    """
    all_hosts: set[str] = set()

    # Always include the root domain itself
    all_hosts.add(domain)

    print(f"  [discovery] Running CT log lookup for {domain}...")
    ct_hosts = discover_from_ct(domain)
    print(f"  [discovery] CT logs returned {len(ct_hosts)} hosts")
    all_hosts.update(ct_hosts)

    print(f"  [discovery] Running DNS brute force for {domain}...")
    dns_hosts = dns_bruteforce(domain)
    print(f"  [discovery] DNS brute force found {len(dns_hosts)} hosts")
    all_hosts.update(dns_hosts)

    print(f"  [discovery] Mining DNS records for {domain}...")
    record_hosts = dns_records(domain)
    print(f"  [discovery] DNS records returned {len(record_hosts)} hosts")
    all_hosts.update(record_hosts)

    return sorted(all_hosts)


def resolve_ip(hostname: str) -> str:
    """Best-effort IP resolution; returns empty string on failure."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return ""


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
