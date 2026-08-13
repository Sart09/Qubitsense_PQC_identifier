"""
Batched DB writer for a single scan.

Replaces the per-row connect + PRAGMA + INSERT + commit(fsync) + close cycle
in result_manager.py — measured at 33.6ms/row versus 0.085ms/row batched via
executemany, a ~400x gap that dominated scan wall clock once host counts
went from tens to hundreds.

Buffers rows in memory and flushes on EITHER a row-count threshold OR a time
threshold, whichever comes first. Pure end-of-scan flushing was rejected:
the progress page polls scan_logs every 2 seconds, so writes need to land
incrementally or the UI freezes for the whole scan.

result_manager.py is left untouched — server.py and test_system.py still
call those single-row functions directly. This writer is used only in the
scan worker's hot loop.
"""

from __future__ import annotations

import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timezone

from database import DB_PATH

_SQL = {
    "discovered_assets": (
        "INSERT INTO discovered_assets "
        "(scan_id, hostname, ip_address, discovery_method, created_at) "
        "VALUES (?, ?, ?, ?, ?);"
    ),
    "tls_results": (
        "INSERT INTO tls_results "
        "(scan_id, hostname, port, tls_version, cipher_suite, key_algorithm, "
        "key_size, signature_algorithm, certificate_expiry, hostname_mismatch, "
        "is_self_signed, is_expired, days_until_expiry, issuer, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
    ),
    "algorithm_analysis": (
        "INSERT INTO algorithm_analysis "
        "(scan_id, hostname, cipher_suite, key_exchange, signature, encryption, "
        "hash, classification, quantum_risk_estimate, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
    ),
    "hndl_results": (
        "INSERT INTO hndl_results "
        "(scan_id, hostname, port, service_type, hndl_multiplier, risk_level, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);"
    ),
    "scan_failures": (
        "INSERT INTO scan_failures "
        "(scan_id, hostname, failure_category, failure_reason, failure_code, "
        "attempt_count, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);"
    ),
    "scan_logs": (
        "INSERT INTO scan_logs (scan_id, message, created_at) VALUES (?, ?, ?);"
    ),
}


class BatchWriter:
    """One connection, one scan, buffered writes flushed by size or time."""

    def __init__(self, scan_id: int, flush_rows: int = 200, flush_seconds: float = 1.0):
        self.scan_id = scan_id
        self.flush_rows = flush_rows
        self.flush_seconds = flush_seconds

        self.conn = sqlite3.connect(DB_PATH, isolation_level=None)
        self.conn.execute("PRAGMA busy_timeout=5000;")
        # synchronous=NORMAL removes the per-commit fsync that FULL (the
        # live DB's setting) forces on every write, while still being
        # durable against a process crash under WAL (only an OS crash can
        # lose data). This was the single largest per-row cost measured.
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA temp_store=MEMORY;")
        self.conn.execute("PRAGMA cache_size=-16000;")

        self._buf: dict[str, list[tuple]] = defaultdict(list)
        self._n = 0
        self._last_flush = time.monotonic()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def add_asset(self, hostname: str, ip_address: str, method: str) -> None:
        self._buf["discovered_assets"].append(
            (self.scan_id, hostname, ip_address, method, self._now())
        )
        self._n += 1
        self._maybe_flush()

    def add_tls_result(self, hostname: str, port: int, tls_version, cipher_suite,
                        key_algorithm, key_size, signature_algorithm, certificate_expiry,
                        hostname_mismatch=None, is_self_signed=None, is_expired=None,
                        days_until_expiry=None, issuer=None) -> None:
        self._buf["tls_results"].append((
            self.scan_id, hostname, port, tls_version, cipher_suite,
            key_algorithm, key_size, signature_algorithm, certificate_expiry,
            hostname_mismatch, is_self_signed, is_expired, days_until_expiry, issuer,
            self._now(),
        ))
        self._n += 1
        self._maybe_flush()

    def add_algorithm_analysis(self, hostname: str, cipher_suite, key_exchange, signature,
                                encryption, hash_alg, classification, quantum_risk_estimate) -> None:
        self._buf["algorithm_analysis"].append((
            self.scan_id, hostname, cipher_suite, key_exchange, signature,
            encryption, hash_alg, classification, str(quantum_risk_estimate), self._now(),
        ))
        self._n += 1
        self._maybe_flush()

    def add_hndl_result(self, hostname: str, port: int, service_type: str,
                         hndl_multiplier: float, risk_level: str) -> None:
        self._buf["hndl_results"].append((
            self.scan_id, hostname, port, service_type, hndl_multiplier, risk_level, self._now(),
        ))
        self._n += 1
        self._maybe_flush()

    def add_failure(self, hostname: str, failure_category: str, failure_reason: str,
                     failure_code: str, attempt_count: int) -> None:
        self._buf["scan_failures"].append((
            self.scan_id, hostname, failure_category, failure_reason,
            failure_code, attempt_count, self._now(),
        ))
        self._n += 1
        self._maybe_flush()

    def log(self, message: str, flush_now: bool = True) -> None:
        """Progress log line. Flushes immediately by default — it's the UI's
        heartbeat (the progress page polls scan_logs every 2s) and
        latency-visible.

        flush_now=False is for the high-volume per-host trace lines. One
        commit per host would put a synchronous write on the scanner's hot
        path — the exact cost this class exists to remove — so those lines
        ride the normal size/time flush instead. The 1.0s time threshold is
        still half the UI's 2s poll interval, so they land in time to be
        seen on the next tick; they just don't each pay for their own fsync.
        """
        print(f"  [scan] {message}", flush=True)
        self._buf["scan_logs"].append((self.scan_id, message, self._now()))
        self._n += 1
        if flush_now:
            self.flush()
        else:
            self._maybe_flush()

    def _maybe_flush(self) -> None:
        if self._n >= self.flush_rows:
            self.flush()
        elif (time.monotonic() - self._last_flush) >= self.flush_seconds:
            self.flush()

    def tick(self) -> None:
        """Call periodically from a loop that doesn't call add_*/log() every
        iteration, so a slow trickle of results still flushes on schedule."""
        if self._n and (time.monotonic() - self._last_flush) >= self.flush_seconds:
            self.flush()

    def flush(self) -> None:
        if not self._n:
            return
        batches, self._buf = self._buf, defaultdict(list)
        self._n = 0
        try:
            self.conn.execute("BEGIN IMMEDIATE;")
            for table, rows in batches.items():
                if rows:
                    self.conn.executemany(_SQL[table], rows)
            self.conn.execute("COMMIT;")
        except Exception:
            try:
                self.conn.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            self._last_flush = time.monotonic()

    def close(self) -> None:
        try:
            self.flush()
        finally:
            self.conn.close()

    def __enter__(self) -> "BatchWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
