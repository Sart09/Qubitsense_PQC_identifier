"""
Process-local DNS answer cache shared by the brute-force resolver
(dns_enum) and the ghost filter (domain_discovery).

Why this exists
---------------
Rescanning a domain re-asks the resolver the exact same questions. A single
pnb.bank.in scan issues ~394 brute-force lookups plus ~173 ghost-filter
lookups; three rescans in a few minutes push well past 1500 queries and the
resolver starts returning SERVFAIL/timeout instead of answers. Measured
directly: 52-79 of 394 wordlist candidates came back inconclusive per run,
and lowering thread count from 100 to 40 did not help — sustained query
volume is the binding constraint, not concurrency.

The scan worker is a long-lived process, so this cache spans scans: the
second scan of a domain mostly reads memory instead of hitting the network.

The one rule that matters
-------------------------
Only DEFINITIVE answers are cached — a real resolution, or a real NXDOMAIN.
An inconclusive result (timeout, SERVFAIL, refused) is never stored. Caching
"I could not find out" would freeze one transient resolver hiccup into a
permanent wrong answer for the whole TTL, which is precisely the
failed-measurement-as-negative-result bug this module was written to avoid.
"""

import threading
import time

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import DNS_CACHE_TTL_S

MISS = object()

_lock = threading.Lock()
_store: dict[str, tuple[float, object]] = {}


def get(key: str):
    """Return the cached value, or ``MISS`` if absent or expired."""
    now = time.monotonic()
    with _lock:
        entry = _store.get(key)
        if entry is None:
            return MISS
        expires_at, value = entry
        if now >= expires_at:
            # Expired — drop it so the dict does not accumulate dead keys
            # across a long-running worker's lifetime.
            del _store[key]
            return MISS
        return value


def put(key: str, value) -> None:
    """Cache a DEFINITIVE answer. Never call this with an inconclusive result."""
    with _lock:
        _store[key] = (time.monotonic() + DNS_CACHE_TTL_S, value)


def stats() -> dict:
    """Current entry count — used by tests and for operator visibility."""
    with _lock:
        return {"entries": len(_store)}


def clear() -> None:
    """Drop everything. Used by tests that need a cold cache."""
    with _lock:
        _store.clear()
