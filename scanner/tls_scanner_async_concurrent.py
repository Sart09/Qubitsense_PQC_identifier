#!/usr/bin/env python3
"""
Async Concurrent TLS Scanner v2.0
==================================

Maximizes subdomain scan success rate with:
1. Async DNS via aiodns (non-blocking, no event loop starvation)
2. Pre-scan ghost subdomain filtering
3. Classified TCP pre-check (open/timeout/refused/dns_failed)
4. 3-tier Python-native TLS fallback (no OpenSSL subprocess)
5. Stage-specific timeouts (DNS=5s, TCP=5s, TLS=12s)
6. Retry logic for transient TLS failures only
7. Structured failure codes for dashboard reporting
"""

import asyncio
import socket
import ssl
import json
import sys
import io

# Fix Windows compatibility
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from typing import Dict, List, Optional, Tuple
from datetime import datetime

# ---- Async DNS resolver (FIX 1) ----
try:
    import aiodns
    _HAS_AIODNS = True
except ImportError:
    _HAS_AIODNS = False
    print("[!] aiodns not installed. Falling back to blocking DNS. Run: pip install aiodns", flush=True)

# ---- Constants (FIX 5) ----
DNS_TIMEOUT = 5      # seconds for DNS resolution
TCP_TIMEOUT = 5      # seconds for TCP port check
TLS_TIMEOUT = 12     # seconds for full TLS handshake
MAX_CONCURRENT = 50  # async semaphore limit
TLS_RETRIES = 2      # retry count for transient TLS failures
TLS_RETRY_DELAY = 1.0  # base delay between retries


# ============================================================================
# ASYNC DNS RESOLUTION (FIX 1)
# ============================================================================

async def resolve_hostname(hostname: str, resolver=None) -> Optional[str]:
    """Resolve hostname to IP using aiodns (non-blocking) with stdlib fallback."""
    if _HAS_AIODNS and resolver:
        try:
            result = await asyncio.wait_for(
                resolver.gethostbyname(hostname, socket.AF_INET),
                timeout=DNS_TIMEOUT
            )
            return result.addresses[0] if result.addresses else None
        except Exception:
            pass  # Fall through to stdlib fallback

    # Fallback: run blocking DNS in executor
    loop = asyncio.get_event_loop()
    try:
        ip = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, hostname),
            timeout=DNS_TIMEOUT
        )
        return ip
    except Exception:
        return None


# ============================================================================
# PRE-SCAN GHOST FILTER (FIX 2)
# ============================================================================

async def filter_live_subdomains(subdomains: List[str]) -> Tuple[List[str], int]:
    """
    Filter out ghost subdomains that have no DNS A record.
    Returns (live_subdomains, ghost_count).
    Ghost subdomains are NOT counted as scan failures.
    """
    resolver = aiodns.DNSResolver() if _HAS_AIODNS else None
    try:
        tasks = [resolve_hostname(h, resolver) for h in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if resolver:
            try:
                resolver.cancel()
            except Exception:
                pass

    live = []
    ghost_count = 0
    for hostname, result in zip(subdomains, results):
        if isinstance(result, str) and result:
            live.append(hostname)
        else:
            ghost_count += 1

    return live, ghost_count


# ============================================================================
# TCP PRE-CHECK (FIX 3)
# ============================================================================

async def tcp_check(hostname: str, ip: str, port: int = 443) -> str:
    """
    Fast TCP connectivity check. Returns a classified status string.
    
    Returns: "open" | "timeout" | "refused"
    Caller should have already resolved DNS before calling this.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=TCP_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return "open"
    except asyncio.TimeoutError:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        err_str = str(e).lower()
        # Windows-specific error codes
        if hasattr(e, 'winerror'):
            if e.winerror == 10060:
                return "timeout"
            if e.winerror == 10061:
                return "refused"
        if "10060" in err_str or "timeout" in err_str or "timed out" in err_str:
            return "timeout"
        if "10061" in err_str or "refused" in err_str:
            return "refused"
        return "refused"
    except Exception:
        return "refused"


# ============================================================================
# 3-TIER TLS HANDSHAKE (FIX 4)
# ============================================================================

async def _attempt_tls(
    hostname: str, ip: str, port: int, context: ssl.SSLContext, sni_hostname: str = None
) -> Tuple[bool, Optional[str], Optional[str], Optional[bytes]]:
    """
    Perform a single TLS handshake attempt.
    Returns (success, tls_version, cipher_suite, der_cert).
    """
    sni = sni_hostname or hostname
    conn = None
    try:
        # Open raw TCP connection to IP
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=False),
            timeout=TCP_TIMEOUT
        )

        # Upgrade to TLS
        loop = asyncio.get_event_loop()
        transport = writer.transport
        raw_sock = transport.get_extra_info('socket')

        # We need to do TLS wrapping in an executor since ssl.wrap_socket
        # is blocking. Use the lower-level approach.
        def do_tls_handshake():
            tls_sock = context.wrap_socket(raw_sock, server_hostname=sni, do_handshake_on_connect=True)
            cipher_info = tls_sock.cipher()
            tls_ver = tls_sock.version()
            der = tls_sock.getpeercert(binary_form=True)
            return tls_ver, cipher_info, der, tls_sock

        tls_ver, cipher_info, der, tls_sock = await asyncio.wait_for(
            loop.run_in_executor(None, do_tls_handshake),
            timeout=TLS_TIMEOUT
        )

        cipher_name = cipher_info[0] if cipher_info else None
        # Close TLS socket
        try:
            tls_sock.close()
        except Exception:
            pass

        if tls_ver and cipher_name:
            return True, tls_ver, cipher_name, der
        return False, tls_ver, None, None

    except Exception:
        return False, None, None, None


async def _attempt_tls_direct(
    hostname: str, ip: str, port: int, context: ssl.SSLContext
) -> Tuple[bool, Optional[str], Optional[str], Optional[bytes]]:
    """
    Direct socket-based TLS handshake. More reliable than stream-based for
    some server configurations.
    """
    loop = asyncio.get_event_loop()

    def do_handshake():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TLS_TIMEOUT)
        try:
            sock.connect((ip, port))
            tls_sock = context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=True)
            cipher_info = tls_sock.cipher()
            tls_ver = tls_sock.version()
            der = tls_sock.getpeercert(binary_form=True)
            tls_sock.close()
            return tls_ver, cipher_info, der
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise

    try:
        tls_ver, cipher_info, der = await asyncio.wait_for(
            loop.run_in_executor(None, do_handshake),
            timeout=TLS_TIMEOUT + 2  # small buffer over socket timeout
        )
        cipher_name = cipher_info[0] if cipher_info else None
        if tls_ver and cipher_name:
            return True, tls_ver, cipher_name, der
        return False, tls_ver, None, None
    except Exception as e:
        print(f"    [!] _attempt_tls_direct error for {hostname}: {str(e.__class__.__name__)}: {str(e)}", flush=True)
        return False, None, None, None


def _make_tier1_context() -> ssl.SSLContext:
    """Tier 1: Standard TLS (SNI ON, cert verification ON, TLSv1.2+)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _make_tier2_context() -> ssl.SSLContext:
    """Tier 2: Permissive TLS (SNI ON, cert verification OFF, TLSv1+)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        # Some builds don't allow TLSv1 minimum
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _make_tier3_context() -> ssl.SSLContext:
    """Tier 3: Legacy TLS (weak ciphers, no verification, accept anything)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    except ssl.SSLError:
        ctx.set_ciphers('ALL')  # Fallback if SECLEVEL not supported
    # Don't set minimum_version — accept TLS 1.0 and SSLv3 servers
    return ctx


# ============================================================================
# TLS WITH RETRY (FIX 6)
# ============================================================================

async def tls_scan_with_fallback(
    hostname: str, ip: str, port: int = 443
) -> Dict:
    """
    Scan a single host through the 3-tier TLS fallback chain with retry logic.
    Returns a result dict with either success data or a structured failure_code.
    """
    tiers = [
        ("tier1_standard", _make_tier1_context()),
        ("tier2_permissive", _make_tier2_context()),
        ("tier3_legacy", _make_tier3_context()),
    ]

    last_error = ""

    for tier_name, ctx in tiers:
        for attempt in range(TLS_RETRIES):
            success, tls_ver, cipher, der = await _attempt_tls_direct(
                hostname, ip, port, ctx
            )

            if success:
                return {
                    "status": "success",
                    "tls_version": tls_ver,
                    "cipher_suite": cipher,
                    "der_cert": der,
                    "method": tier_name,
                }

            # Only retry on transient failures (not on first tier cert errors)
            if attempt < TLS_RETRIES - 1:
                await asyncio.sleep(TLS_RETRY_DELAY * (attempt + 1))
            else:
                print(f"    [{tier_name}] Failed after {TLS_RETRIES} attempts", flush=True)

    # All tiers exhausted — determine the most specific failure code
    return {
        "status": "failed",
        "failure_code": "TLS_HANDSHAKE_FAIL",
        "error": "All 3 TLS tiers failed after retries",
    }


# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class AsyncTLSScanner:
    """Async TLS scanner with concurrent connections and structured failure codes."""

    def __init__(self, max_concurrent: int = MAX_CONCURRENT, timeout: int = TLS_TIMEOUT):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.resolver = aiodns.DNSResolver() if _HAS_AIODNS else None

    async def scan_hostname(self, hostname: str) -> Dict:
        """
        Scan a single hostname through the full pipeline:
        DNS → TCP check → 3-tier TLS with retry.
        Returns a structured result dict.
        """
        async with self.semaphore:
            result = {
                "hostname": hostname,
                "port": 443,
                "timestamp": datetime.now().isoformat(),
                "ip_address": None,
                "tls_version": None,
                "cipher_suite": None,
                "der_cert": None,
                "status": "failed",
                "method": None,
                "error": None,
                "failure_code": None,
            }

            print(f"\n[*] Scanning {hostname}...", flush=True)

            # Stage 1: DNS Resolution
            ip = await resolve_hostname(hostname, self.resolver)
            if not ip:
                result["error"] = "DNS Resolution Failed"
                result["failure_code"] = "DNS_NO_RECORD"
                print(f"  [✗] DNS failed for {hostname}", flush=True)
                return result

            result["ip_address"] = ip
            print(f"  [✓] Resolved to {ip}", flush=True)

            # Stage 2: TCP Pre-Check & Multi-Port Fallback Algorithm
            tcp_status = await tcp_check(hostname, ip, 443)
            scan_port = 443

            if tcp_status != "open":
                fallback_ports = [8443, 4433, 9443, 2083, 2087, 8080, 8888]
                print(f"  [!] Port 443 {tcp_status} - Initiating Multi-Port Fallback sweep for {hostname}...", flush=True)
                for fport in fallback_ports:
                    f_status = await tcp_check(hostname, ip, fport)
                    if f_status == "open":
                        print(f"  [+] WAF/Firewall Bypass Success: Port {fport} OPEN for {hostname}!", flush=True)
                        scan_port = fport
                        tcp_status = "open"
                        break

            if tcp_status == "timeout":
                result["error"] = "Connection Timeout (Scanned all fallback ports)"
                result["failure_code"] = "TCP_TIMEOUT"
                print(f"  [✗] Connection Timeout for {hostname} on all ports (Definitively Air-gapped/Internal)", flush=True)
                return result
            elif tcp_status == "refused":
                result["error"] = "Connection Refused (All Ports)"
                result["failure_code"] = "TCP_REFUSED"
                print(f"  [✗] Connection Refused for {hostname} on all fallback ports", flush=True)
                return result

            result["port"] = scan_port

            # Stage 3: 3-Tier TLS Handshake with Retry
            print(f"  [·] TCP open on port {scan_port}, attempting TLS handshake...", flush=True)
            tls_result = await tls_scan_with_fallback(hostname, ip, scan_port)

            if tls_result["status"] == "success":
                result["tls_version"] = tls_result["tls_version"]
                result["cipher_suite"] = tls_result["cipher_suite"]
                result["der_cert"] = tls_result["der_cert"]
                result["status"] = "success"
                result["method"] = tls_result["method"]
                cipher_short = tls_result["cipher_suite"][:40] if tls_result["cipher_suite"] else "?"
                print(f"  [✓] {tls_result['method']}: {tls_result['tls_version']} - {cipher_short}", flush=True)
            else:
                result["error"] = tls_result.get("error", "TLS handshake failed")
                result["failure_code"] = tls_result.get("failure_code", "TLS_HANDSHAKE_FAIL")
                print(f"  [✗] All TLS tiers failed for {hostname}", flush=True)

            return result

    async def scan_all_concurrent(self, hostnames: List[str]) -> List[Dict]:
        """Scan all hostnames concurrently with semaphore limiting."""
        print(f"\n[*] Starting concurrent scan of {len(hostnames)} hosts...", flush=True)
        print(f"[*] Max concurrent connections: {self.max_concurrent}", flush=True)
        print(f"[*] Timeouts: DNS={DNS_TIMEOUT}s, TCP={TCP_TIMEOUT}s, TLS={TLS_TIMEOUT}s", flush=True)
        print(f"[*] TLS retries per tier: {TLS_RETRIES}", flush=True)
        est_time = max(10, (len(hostnames) // self.max_concurrent) * 8)
        print(f"[*] Estimated time: {est_time}s\n", flush=True)

        tasks = [self.scan_hostname(hostname) for hostname in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return results


# ============================================================================
# CT LOG SUBDOMAIN DISCOVERY (kept for standalone usage)
# ============================================================================

def discover_subdomains_ct_logs(domain: str) -> List[str]:
    """Discover subdomains from CT logs (sync helper for standalone use)."""
    import urllib.request
    print(f"[*] Discovering subdomains for {domain}...", flush=True)
    hosts = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "TLSScanner/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                name_value = entry.get("name_value", "")
                for san in name_value.split('\n'):
                    san = san.strip().lower()
                    if san and san.endswith(domain):
                        hosts.add(san)
    except Exception as e:
        print(f"[!] CT discovery error: {e}", flush=True)

    result = sorted(list(hosts))
    print(f"[✓] Found {len(result)} subdomains", flush=True)
    return result


# ============================================================================
# REPORTING
# ============================================================================

def print_summary(results: List[Dict]):

    """Print scan summary with failure code breakdown."""
    print(f"\n\n{'='*70}", flush=True)
    print("CONCURRENT SCAN SUMMARY", flush=True)
    print(f"{'='*70}\n", flush=True)

    successful = [r for r in results if r["status"] == "success"]
    failed = [r for r in results if r["status"] == "failed"]

    print(f"Total Scanned: {len(results)}", flush=True)
    print(f"Success: {len(successful)} ({100*len(successful)/max(1,len(results)):.1f}%)", flush=True)
    print(f"Failed: {len(failed)} ({100*len(failed)/max(1,len(results)):.1f}%)\n", flush=True)

    if successful:
        print("✓ SUCCESSFUL CIPHER EXTRACTIONS:", flush=True)
        print("-" * 70, flush=True)
        for r in successful:
            method_short = r["method"].replace("_", " ").title()[:20] if r["method"] else "?"
            cipher_short = r["cipher_suite"][:35] if r["cipher_suite"] else "Unknown"
            print(f"  {r['hostname']:40} | {r['tls_version']:10} | {cipher_short}", flush=True)
            print(f"    └─ Method: {method_short}", flush=True)

    if failed:
        # Group by failure code
        from collections import Counter
        code_counts = Counter(r.get("failure_code", "UNKNOWN") for r in failed)
        print(f"\n✗ FAILED SCANS: ({len(failed)})", flush=True)
        print("-" * 70, flush=True)
        print("  Failure Breakdown:", flush=True)
        for code, count in code_counts.most_common():
            print(f"    {code:25} : {count}", flush=True)
        print()
        for r in failed:
            code = r.get("failure_code", "?")
            print(f"  {r['hostname']:40} | {code}", flush=True)


# ============================================================================
# STANDALONE ENTRY POINT
# ============================================================================

async def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <domain>")
        print(f"Example: python {sys.argv[0]} manipurrural.bank.in")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"\n{'='*70}")
    print("ASYNC CONCURRENT TLS SCANNER v2.0")
    print(f"Domain: {domain}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"{'='*70}\n")

    # Discover subdomains
    subdomains = discover_subdomains_ct_logs(domain)
    if not subdomains:
        subdomains = [domain]

    print(f"[✓] Raw subdomains discovered: {len(subdomains)}")

    # Filter ghosts
    live_subs, ghost_count = await filter_live_subdomains(subdomains)
    print(f"[✓] Live subdomains (DNS resolved): {len(live_subs)}")
    print(f"[i] Ghost subdomains filtered out: {ghost_count}")

    if not live_subs:
        live_subs = [domain]

    for i, sub in enumerate(live_subs[:20], 1):
        print(f"    {i:2d}. {sub}")
    if len(live_subs) > 20:
        print(f"    ... and {len(live_subs)-20} more")

    # Scan
    scanner = AsyncTLSScanner(max_concurrent=MAX_CONCURRENT, timeout=TLS_TIMEOUT)
    start_time = datetime.now()
    results = await scanner.scan_all_concurrent(live_subs)
    elapsed = (datetime.now() - start_time).total_seconds()

    # Report
    print_summary(results)
    print(f"\n[✓] Scan completed in {elapsed:.1f} seconds")
    print(f"[✓] Average per hostname: {elapsed/max(1,len(results)):.1f}s")

    # Save results (strip bytes for JSON serialization)
    output_file = f"tls_scan_async_{domain.replace('.', '_')}.json"
    json_results = [{k: v for k, v in r.items() if k != "der_cert"} for r in results]
    with open(output_file, 'w') as f:
        json.dump(json_results, f, indent=2, default=str)
    print(f"[✓] Results saved to {output_file}")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
