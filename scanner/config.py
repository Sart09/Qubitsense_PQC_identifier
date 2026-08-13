"""
Scanner configuration — env-driven concurrency, timeouts, and budgets.

Every value here was previously a hardcoded literal scattered across
tls_scanner_async_concurrent.py and scan_worker.py (including a duplicated
``50`` for max_concurrent). Centralized so a single env var change tunes the
whole pipeline without touching source.
"""

import os
import socket
import sys


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# Resolver codes meaning "this name definitively does not exist", as opposed
# to "the resolver could not answer right now". Feature-detected because the
# constants differ per platform: POSIX exposes EAI_NONAME/EAI_NODATA on the
# socket module, Windows reports raw WSA codes instead (11001
# WSAHOST_NOT_FOUND, 11004 WSANO_DATA).
#
# Lives in config so both domain_discovery (ghost filter) and dns_enum
# (brute force) can import it — domain_discovery imports dns_enum, so the
# reverse direction would be a cycle.
DEFINITIVE_NXDOMAIN = {
    v for v in (getattr(socket, n, None) for n in ("EAI_NONAME", "EAI_NODATA"))
    if v is not None
}
DEFINITIVE_NXDOMAIN.update({11001, 11004})


class SourceNotConfigured(Exception):
    """A discovery source is unusable because it lacks credentials.

    Deliberately NOT a SourceUnavailable. An unconfigured source is a
    permanent, known gap in coverage, not a transient failure — treating it
    as degradation would flag every single scan and block all caching,
    which is worse than the bug it was meant to catch. Reported to the
    operator as an actionable config gap instead.
    """


class SourceUnavailable(Exception):
    """A discovery source could not be reached (rate-limited, timed out, 5xx).

    Lives here rather than in domain_discovery.py because ct_logs.py must
    raise it and domain_discovery.py imports ct_logs — config is the shared
    leaf module both can import without a cycle.

    Exists because a source returning ``[]`` on failure is indistinguishable
    from a source legitimately finding nothing, which let a rate-limited
    scan report a shrunken inventory as fact.
    """


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# Concurrency ---------------------------------------------------------------
TLS_CONCURRENCY = _env_int("TLS_CONCURRENCY", 256)
DNS_CONCURRENCY = _env_int("DNS_CONCURRENCY", 128)

# Windows's default asyncio event loop is SelectorEventLoop (ProactorEventLoop
# cannot host aiodns/pycares, which need add_reader). SelectorEventLoop is
# backed by select(), and this was measured directly: 512 concurrent sockets
# succeed, 600 raises "ValueError: too many file descriptors in select()".
# Keep meaningful headroom below that ceiling.
if sys.platform == "win32":
    assert TLS_CONCURRENCY + DNS_CONCURRENCY < 460, (
        "TLS_CONCURRENCY + DNS_CONCURRENCY must stay under the Windows "
        "select() cap (measured ceiling ~512 fds) or every scan will die "
        "with an opaque ValueError."
    )

# Timeouts (seconds) ---------------------------------------------------------
TLS_CONNECT_TIMEOUT = _env_float("TLS_CONNECT_TIMEOUT", 4.0)
TLS_HANDSHAKE_TIMEOUT = _env_float("TLS_HANDSHAKE_TIMEOUT", 5.0)
DNS_TIMEOUT = _env_float("DNS_TIMEOUT", 5.0)

# Per-host wall-clock budget. The semaphore must be acquired BEFORE this
# clock starts — starting it while a host is still queued behind the
# concurrency limit manufactures false timeouts for work that never ran.
HOST_DEADLINE = _env_float("HOST_DEADLINE", 12.0)

# Retry policy ----------------------------------------------------------
TLS_RETRIES = _env_int("TLS_RETRIES", 1)
TLS_RETRY_DELAY = _env_float("TLS_RETRY_DELAY", 0.4)

# Global scan budget — a hang-guard, not a result cap. Every discovered host
# is still scanned; hosts not yet started when this expires are recorded as
# BUDGET_EXCEEDED instead of hanging the demo indefinitely.
SCAN_BUDGET_S = _env_float("SCAN_BUDGET_S", 600.0)

# Fallback ports tried only when 443 is actively refused (not on timeout —
# a filtered/dropped 443 means the whole host is unreachable, not that a
# specific port is closed). 8080/8888 removed: plaintext HTTP, a TLS
# handshake there can never succeed.
FALLBACK_PORTS = tuple(
    int(p) for p in os.environ.get("FALLBACK_PORTS", "8443,4433,9443").split(",") if p.strip()
)
PORT_RACE_TIMEOUT = _env_float("PORT_RACE_TIMEOUT", 6.0)
# Auto-disable the port race entirely once a scan is large enough that
# racing extra ports per unreachable host would meaningfully add to wall
# clock across the whole batch.
PORT_FALLBACK_MAX_HOSTS = _env_int("PORT_FALLBACK_MAX_HOSTS", 1500)

# Reconciliation pass — after the main scan, connection-level failures
# (TCP_TIMEOUT/REFUSED/ERROR, HOST_DEADLINE, BUDGET_EXCEEDED) are retried
# once at low concurrency before being finalized. Measured live on a real
# bank domain: scanning ~126 hosts at full concurrency in one burst tripped
# the target's own rate-limiting, and which specific hosts got caught
# shifted between otherwise-identical runs (76 vs 93-94 successful across
# four scans of the same domain). Retrying just the connection-level
# failures in isolation, at RECONCILE_CONCURRENCY, distinguishes "target
# genuinely down" from "we tripped their rate limiter" — the same 18-host
# set recovered on manual low-concurrency retest matched almost exactly
# what this pass is designed to catch.
RECONCILE_CONCURRENCY = _env_int("RECONCILE_CONCURRENCY", 12)
# Caps worst-case reconciliation time on a domain that's genuinely mostly
# offline (thousands of real TCP_TIMEOUTs would otherwise turn a small,
# cheap second pass into a second full-length scan). Hosts beyond this
# count are left as first-pass failures, unretried.
RECONCILE_MAX_HOSTS = _env_int("RECONCILE_MAX_HOSTS", 500)
# A recovered false-failure (our own burst tripping the target's rate
# limiter) succeeds fast once retried alone at low concurrency — there is
# no reason to wait the full main-pass HOST_DEADLINE (12s) a second time.
# Shorter here means a genuinely-dead host (e.g. a hostname that only ever
# existed as one entry in a certificate's SAN list, never a live server —
# measured live against badssl.com's SAN-stress-test certificate, which
# lists ~100+ such names) fails fast on retry too, instead of burning a
# full second timeout per host on an outcome that was never going to change.
RECONCILE_HOST_DEADLINE = _env_float("RECONCILE_HOST_DEADLINE", 6.0)
# Independent wall-clock cap for the whole reconciliation pass. Without
# this, RECONCILE_MAX_HOSTS (500) at RECONCILE_CONCURRENCY (12) with the
# full HOST_DEADLINE could still run ~15-20 minutes on a domain that is
# mostly permanent failures — SCAN_BUDGET_S does not help here because
# AsyncTLSScanner resets its own deadline fresh each time scan_stream() is
# called, so the main pass's budget does not carry over and cap this pass.
# Hosts still pending when this expires finalize as failures (failure_code
# BUDGET_EXCEEDED), the same graceful-cutoff pattern already used for hosts
# beyond RECONCILE_MAX_HOSTS.
RECONCILE_BUDGET_S = _env_float("RECONCILE_BUDGET_S", 90.0)

# Cooldown before EACH reconciliation pass. The first-pass burst is what
# trips a defended target's rate limiter, so retrying the instant it ends
# just re-confirms the same false failures against a still-hot limiter.
# Measured on pnb.bank.in (all 132 hosts in one /23): an immediate retry
# recovered 24/80 and was still recovering when the pass ended — the
# recovery curve had not flattened, which is the signature of a limiter
# relaxing rather than hosts being genuinely offline.
RECONCILE_COOLDOWN_S = _env_float("RECONCILE_COOLDOWN_S", 8.0)
# Number of reconciliation passes. Each pass only retries what the previous
# one still could not reach, so a clean scan costs nothing extra (an empty
# pending set skips straight out) while a rate-limited one gets a second
# chance after a further cooldown.
RECONCILE_PASSES = _env_int("RECONCILE_PASSES", 2)

# Scan-quality thresholds. A run where this fraction of the estate died on
# HOST_DEADLINE was almost certainly throttled rather than genuinely
# offline — the count it reports is a floor, not an inventory, and must not
# silently replace a better previous result.
DEGRADED_DEADLINE_RATIO = _env_float("DEGRADED_DEADLINE_RATIO", 0.25)

# Ghost-filter resolver concurrency. Was hardcoded at 200 parallel
# getaddrinfo calls, which saturates the local/ISP resolver — and a
# saturated resolver returns the ambiguous failures that used to delete
# live hosts from the inventory. Lower and configurable: the filter is a
# few seconds of a multi-minute scan, so trading a little wall clock for
# resolver answers we can actually trust is the right side of that deal.
GHOST_FILTER_CONCURRENCY = _env_int("GHOST_FILTER_CONCURRENCY", 64)

# DNS brute-force resolver concurrency. Exposed for tuning, but note what
# was actually measured on pnb.bank.in (394 wordlist candidates): dropping
# this from 100 to 40 did NOT reduce inconclusive answers (52-73 per run at
# 100, 44-79 at 40). Concurrency is not the binding constraint — sustained
# query VOLUME is. Three back-to-back rescans issue ~1200 lookups in under
# a minute and the resolver starts refusing regardless of how many threads
# are asking. The effective fix is DNS_CACHE_TTL_S below, which stops a
# rescan from re-asking the same questions at all.
DNS_BRUTEFORCE_CONCURRENCY = _env_int("DNS_BRUTEFORCE_CONCURRENCY", 64)

# Lifetime of the in-process DNS answer cache shared by the brute-force
# resolver and the ghost filter. The scan worker is a long-lived process,
# so this survives across scans: a rescan of the same domain within the
# window reuses definitive answers instead of re-querying an already
# saturated resolver. Only DEFINITIVE answers are ever cached — caching an
# inconclusive result would freeze a transient resolver failure into a
# permanent one, which is the exact bug class this whole pass exists to fix.
DNS_CACHE_TTL_S = _env_float("DNS_CACHE_TTL_S", 600.0)

# A discovery run where this many passive sources failed outright is not a
# smaller estate, it is a partial view of the same estate — flagged so it
# cannot silently replace a more complete cached result.
DEGRADED_SOURCE_FAILURES = _env_int("DEGRADED_SOURCE_FAILURES", 1)

# Batched DB writer -----------------------------------------------------
DB_FLUSH_ROWS = _env_int("DB_FLUSH_ROWS", 200)
DB_FLUSH_SECONDS = _env_float("DB_FLUSH_SECONDS", 1.0)
