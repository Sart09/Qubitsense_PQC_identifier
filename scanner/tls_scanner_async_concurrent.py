#!/usr/bin/env python3
"""
Async Concurrent TLS Scanner v3.0
==================================

Native-async TLS scanning, replacing the v2.0 thread-pool-backed handshake.

Why this rewrite exists: v2.0 advertised MAX_CONCURRENT=50 via a semaphore,
but every handshake ran through ``loop.run_in_executor(None, ...)``, and
asyncio's default ThreadPoolExecutor is sized ``min(32, cpu_count+4)`` —
measured at 12 threads on the target machine. 38 of every 50 admitted
coroutines queued behind 12 real threads, and their wait_for() timeout
counted down *while queued*, manufacturing false TimeoutErrors for hosts
that were simply waiting for a thread. This version uses
``asyncio.open_connection(..., ssl=ctx)`` directly, so concurrency is real
and bounded only by the semaphore.

Design:
1. Async DNS via aiodns (non-blocking)
2. One handshake per host in the common case (was up to 6: 3 tiers x 2
   retries) via exception classification instead of blind tier cycling
3. Per-host deadline that starts only AFTER semaphore admission
4. Parallel port-fallback race (was a 45s sequential sweep), gated on
   "refused" only — a filtered/timed-out 443 means the whole host drops
   traffic, racing more ports just buys more timeouts
5. Streaming results via as_completed (was gather — one slow host no
   longer sets the wall clock for the whole batch)
6. Certificate validation from the DER already fetched: SAN names,
   hostname mismatch, expiry, self-signed — see certificate_parser.py
"""

import asyncio
import socket
import ssl
import json
import sys
import io
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Tuple
from datetime import datetime

# Fix Windows compatibility
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else __file__.rsplit("/", 1)[0])

from config import (
    TLS_CONCURRENCY, DNS_TIMEOUT, TLS_CONNECT_TIMEOUT, TLS_HANDSHAKE_TIMEOUT,
    HOST_DEADLINE, TLS_RETRIES, TLS_RETRY_DELAY, SCAN_BUDGET_S,
    FALLBACK_PORTS, PORT_RACE_TIMEOUT, PORT_FALLBACK_MAX_HOSTS,
)

# ---- Async DNS resolver ----
try:
    import aiodns
    _HAS_AIODNS = True
except ImportError:
    _HAS_AIODNS = False
    print("[!] aiodns not installed. Falling back to blocking DNS. Run: pip install aiodns", flush=True)

# Backward-compat constants (some callers/tests may still reference these).
MAX_CONCURRENT = TLS_CONCURRENCY
TLS_TIMEOUT = TLS_HANDSHAKE_TIMEOUT + TLS_CONNECT_TIMEOUT
TCP_TIMEOUT = TLS_CONNECT_TIMEOUT


# ============================================================================
# ASYNC DNS RESOLUTION
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
# PRE-SCAN GHOST FILTER (kept for standalone/library use)
# ============================================================================

async def filter_live_subdomains(subdomains: List[str]) -> Tuple[List[str], int]:
    """
    Filter out ghost subdomains that have no DNS A record.
    Returns (live_subdomains, ghost_count).
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
# SHARED SSL CONTEXTS — built once, not per host
# ============================================================================
# ssl.create_default_context() (the old tier-1 context) measured 18.9ms on
# the target machine — it loads the full Windows CA store. Nothing in the
# schema records verification status, so a verifying handshake was pure
# cost: 18.9ms of event-loop stall plus up to two wasted full-timeout
# handshakes, for a result that was thrown away. Real validation now comes
# from parsing the DER we fetch regardless (certificate_parser.py).

_CTX_MAIN: Optional[ssl.SSLContext] = None
_CTX_LEGACY: Optional[ssl.SSLContext] = None


def _ctx_main() -> ssl.SSLContext:
    global _CTX_MAIN
    if _CTX_MAIN is None:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        try:
            c.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError):
            pass
        _CTX_MAIN = c
    return _CTX_MAIN


def _ctx_legacy() -> ssl.SSLContext:
    global _CTX_LEGACY
    if _CTX_LEGACY is None:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        try:
            c.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            c.set_ciphers("ALL")
        _CTX_LEGACY = c
    return _CTX_LEGACY


# ============================================================================
# SINGLE HANDSHAKE PRIMITIVE + EXCEPTION CLASSIFICATION
# ============================================================================

@dataclass(slots=True)
class HandshakeResult:
    ok: bool
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    der: Optional[bytes] = None
    action: str = "dead"   # ok | retry | downgrade | dead | not_tls | refused | timeout
    code: str = "TLS_HANDSHAKE_FAIL"
    detail: str = ""


async def _handshake(ip: str, port: int, sni: str, ctx: ssl.SSLContext) -> HandshakeResult:
    writer = None
    try:
        coro = asyncio.open_connection(
            ip, port,
            ssl=ctx,
            server_hostname=sni,
            ssl_handshake_timeout=TLS_HANDSHAKE_TIMEOUT,
        )
        reader, writer = await asyncio.wait_for(
            coro, timeout=TLS_CONNECT_TIMEOUT + TLS_HANDSHAKE_TIMEOUT
        )
        sobj = writer.get_extra_info("ssl_object")
        if sobj is None:
            return HandshakeResult(False, action="retry", code="TLS_NO_SSL_OBJECT")
        cipher = sobj.cipher()
        return HandshakeResult(
            ok=True,
            tls_version=sobj.version(),
            cipher=cipher[0] if cipher else None,
            der=sobj.getpeercert(binary_form=True),
            action="ok",
            code="OK",
        )
    except BaseException as e:
        return _classify(e)
    finally:
        if writer is not None:
            # abort() skips the close_notify round trip and cannot hang —
            # close()+wait_closed() can block on a server that never sends
            # close_notify, which matters when doing this hundreds of times.
            try:
                writer.transport.abort()
            except Exception:
                pass


_DOWNGRADE_REASONS = frozenset({
    "WRONG_VERSION_NUMBER", "UNSUPPORTED_PROTOCOL", "NO_PROTOCOLS_AVAILABLE",
    "TLSV1_ALERT_PROTOCOL_VERSION", "VERSION_TOO_LOW", "UNSUPPORTED_PROTOCOL_VERSION",
    "SSLV3_ALERT_HANDSHAKE_FAILURE", "HANDSHAKE_FAILURE", "NO_SHARED_CIPHER",
    "DH_KEY_TOO_SMALL", "EE_KEY_TOO_SMALL", "CA_MD_TOO_WEAK",
    "UNSAFE_LEGACY_RENEGOTIATION_DISABLED", "NO_CIPHERS_AVAILABLE",
    "SSLV3_ALERT_ILLEGAL_PARAMETER", "TLSV1_ALERT_INSUFFICIENT_SECURITY",
})
_TRANSIENT_REASONS = frozenset({
    "TLSV1_ALERT_INTERNAL_ERROR", "BAD_RECORD_MAC", "DECRYPT_ERROR",
    "TLSV1_ALERT_USER_CANCELLED", "PACKET_LENGTH_TOO_LONG",
})
_NOT_TLS_REASONS = frozenset({
    "UNEXPECTED_EOF_WHILE_READING", "HTTP_REQUEST", "HTTPS_PROXY_REQUEST",
})


def _classify(e: BaseException) -> HandshakeResult:
    """Turn a raw exception into a routing decision instead of a bare False."""
    if isinstance(e, asyncio.CancelledError):
        raise e  # never swallow cancellation

    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return HandshakeResult(False, action="timeout", code="TCP_TIMEOUT",
                                detail="connect/handshake timed out")

    if isinstance(e, ConnectionRefusedError):
        return HandshakeResult(False, action="refused", code="TCP_REFUSED",
                                detail="connection refused")

    if isinstance(e, socket.gaierror):
        return HandshakeResult(False, action="dead", code="DNS_NO_RECORD", detail=str(e))

    if isinstance(e, ssl.SSLCertVerificationError):
        # Unreachable with CERT_NONE contexts; kept defensively.
        return HandshakeResult(False, action="downgrade", code="CERT_INVALID", detail=str(e))

    if isinstance(e, ssl.SSLZeroReturnError):
        return HandshakeResult(False, action="retry", code="TLS_ZERO_RETURN")

    if isinstance(e, ssl.SSLError):
        reason = (getattr(e, "reason", "") or "").upper()
        blob = f"{reason} {e}".upper()
        if reason in _DOWNGRADE_REASONS or any(r in blob for r in _DOWNGRADE_REASONS):
            return HandshakeResult(False, action="downgrade",
                                    code="TLS_LEGACY_CIPHER", detail=reason or str(e)[:80])
        if reason in _NOT_TLS_REASONS or "EOF OCCURRED IN VIOLATION" in blob:
            return HandshakeResult(False, action="not_tls",
                                    code="NOT_TLS", detail=reason or "plaintext service")
        if reason in _TRANSIENT_REASONS:
            return HandshakeResult(False, action="retry",
                                    code="TLS_TRANSIENT", detail=reason)
        return HandshakeResult(False, action="downgrade",
                                code="TLS_HANDSHAKE_FAIL", detail=reason or str(e)[:80])

    if isinstance(e, OSError):
        win = getattr(e, "winerror", None)
        if win == 10060:
            return HandshakeResult(False, action="timeout", code="TCP_TIMEOUT")
        if win == 10061:
            return HandshakeResult(False, action="refused", code="TCP_REFUSED")
        if win == 10054:
            # RST mid-handshake — overwhelmingly a TLS-version reject on
            # hardened appliances. Worth one legacy attempt.
            return HandshakeResult(False, action="downgrade", code="TLS_RESET")
        if win in (10051, 10065, 10013):
            return HandshakeResult(False, action="dead", code="TCP_UNREACHABLE")
        return HandshakeResult(False, action="retry", code="TCP_ERROR", detail=str(e)[:80])

    return HandshakeResult(False, action="retry", code="INTERNAL",
                            detail=f"{type(e).__name__}: {e}"[:120])


async def _race_ports(ip: str, sni: str, ports: Tuple[int, ...], ctx: ssl.SSLContext
                       ) -> Optional[Tuple[int, HandshakeResult]]:
    """Race fallback ports in parallel (was a 45s sequential sweep). Cancels losers."""
    if not ports:
        return None
    tasks = {asyncio.create_task(_handshake(ip, p, sni, ctx)): p for p in ports}
    try:
        done, pending = await asyncio.wait(
            tasks, timeout=PORT_RACE_TIMEOUT, return_when=asyncio.ALL_COMPLETED
        )
        for t in done:
            r = t.result()
            if r.ok:
                return tasks[t], r
        return None
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class AsyncTLSScanner:
    """Async TLS scanner: one handshake per host in the common case, real concurrency."""

    def __init__(self, max_concurrent: int = TLS_CONCURRENCY, timeout: float = HOST_DEADLINE,
                 port_fallback: Optional[bool] = None, budget_s: float = SCAN_BUDGET_S):
        self.max_concurrent = max_concurrent
        self.host_deadline = timeout
        self.budget_s = budget_s
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.resolver = aiodns.DNSResolver() if _HAS_AIODNS else None
        self._loop = None
        self._deadline = None
        self._port_fallback = port_fallback  # resolved per-batch in scan_stream if None

    async def _scan_one(self, hostname: str) -> Dict:
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
            "attempts": 0,
        }

        ip = await resolve_hostname(hostname, self.resolver)
        if not ip:
            result["error"] = "DNS Resolution Failed"
            result["failure_code"] = "DNS_NO_RECORD"
            return result
        result["ip_address"] = ip

        port = 443
        attempts = 1
        r = await _handshake(ip, port, hostname, _ctx_main())

        if r.action == "retry":
            await asyncio.sleep(TLS_RETRY_DELAY)
            attempts += 1
            r = await _handshake(ip, port, hostname, _ctx_main())

        if not r.ok and r.action in ("downgrade", "retry"):
            attempts += 1
            r = await _handshake(ip, port, hostname, _ctx_legacy())

        if not r.ok and r.action == "refused" and self._port_fallback:
            attempts += len(FALLBACK_PORTS)
            raced = await _race_ports(ip, hostname, FALLBACK_PORTS, _ctx_main())
            if raced:
                port, r = raced

        result["attempts"] = attempts

        if r.ok:
            result.update(
                status="success", port=port,
                tls_version=r.tls_version, cipher_suite=r.cipher, der_cert=r.der,
                method="legacy" if r.code == "TLS_LEGACY_CIPHER" else "standard",
            )
        else:
            result.update(port=port, error=r.detail or r.code, failure_code=r.code)

        return result

    async def scan_hostname(self, hostname: str) -> Dict:
        """Scan one host, respecting the per-host deadline. Clock starts only
        after semaphore admission — this is the fix for the queue-starvation
        bug where a timeout counted down while a host waited its turn."""
        if self._loop is None:
            self._loop = asyncio.get_event_loop()
        if self._deadline is not None and self._loop.time() > self._deadline:
            return {
                "hostname": hostname, "port": 443, "ip_address": None,
                "tls_version": None, "cipher_suite": None, "der_cert": None,
                "status": "failed", "method": None,
                "error": "global scan budget exhausted", "failure_code": "BUDGET_EXCEEDED",
            }
        async with self.semaphore:
            try:
                return await asyncio.wait_for(self._scan_one(hostname), self.host_deadline)
            except (asyncio.TimeoutError, TimeoutError):
                return {
                    "hostname": hostname, "port": 443, "ip_address": None,
                    "tls_version": None, "cipher_suite": None, "der_cert": None,
                    "status": "failed", "method": None,
                    "error": f"exceeded {self.host_deadline}s host budget",
                    "failure_code": "HOST_DEADLINE",
                }
            except asyncio.CancelledError:
                raise
            except Exception as e:
                return {
                    "hostname": hostname, "port": 443, "ip_address": None,
                    "tls_version": None, "cipher_suite": None, "der_cert": None,
                    "status": "failed", "method": None,
                    "error": f"{type(e).__name__}: {e}"[:150], "failure_code": "INTERNAL",
                }

    async def scan_stream(self, hostnames: List[str]) -> AsyncIterator[Dict]:
        """Yield results as they complete (was gather — one slow host no
        longer holds up the whole batch's wall clock)."""
        loop = asyncio.get_event_loop()
        self._loop = loop
        self._deadline = loop.time() + self.budget_s
        if self._port_fallback is None:
            self._port_fallback = len(hostnames) <= PORT_FALLBACK_MAX_HOSTS

        print(f"\n[*] Starting concurrent scan of {len(hostnames)} hosts...", flush=True)
        print(f"[*] Max concurrent connections: {self.max_concurrent}", flush=True)
        print(f"[*] Per-host deadline: {self.host_deadline}s | Scan budget: {self.budget_s}s", flush=True)
        print(f"[*] Port fallback race: {'enabled' if self._port_fallback else 'disabled (large batch)'}\n",
              flush=True)

        tasks = [asyncio.create_task(self.scan_hostname(h)) for h in hostnames]
        try:
            for fut in asyncio.as_completed(tasks):
                yield await fut
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def scan_all_concurrent(self, hostnames: List[str]) -> List[Dict]:
        """Backward-compat wrapper: collect scan_stream() into a list."""
        return [r async for r in self.scan_stream(hostnames)]


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
    print("ASYNC CONCURRENT TLS SCANNER v3.0")
    print(f"Domain: {domain}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"{'='*70}\n")

    subdomains = discover_subdomains_ct_logs(domain)
    if not subdomains:
        subdomains = [domain]

    print(f"[✓] Raw subdomains discovered: {len(subdomains)}")

    live_subs, ghost_count = await filter_live_subdomains(subdomains)
    print(f"[✓] Live subdomains (DNS resolved): {len(live_subs)}")
    print(f"[i] Ghost subdomains filtered out: {ghost_count}")

    if not live_subs:
        live_subs = [domain]

    for i, sub in enumerate(live_subs[:20], 1):
        print(f"    {i:2d}. {sub}")
    if len(live_subs) > 20:
        print(f"    ... and {len(live_subs)-20} more")

    scanner = AsyncTLSScanner()
    start_time = datetime.now()
    results = await scanner.scan_all_concurrent(live_subs)
    elapsed = (datetime.now() - start_time).total_seconds()

    print_summary(results)
    print(f"\n[✓] Scan completed in {elapsed:.1f} seconds")
    print(f"[✓] Average per hostname: {elapsed/max(1,len(results)):.1f}s")

    output_file = f"tls_scan_async_{domain.replace('.', '_')}.json"
    json_results = [{k: v for k, v in r.items() if k != "der_cert"} for r in results]
    with open(output_file, 'w') as f:
        json.dump(json_results, f, indent=2, default=str)
    print(f"[✓] Results saved to {output_file}")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
