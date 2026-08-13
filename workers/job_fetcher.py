"""
Job fetcher — queries the database for pending scan jobs.
"""

import os
import sys
from datetime import datetime, timezone

# Add backend directory to path so we can import shared modules.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

from database import get_connection


def get_next_job() -> dict | None:
    """
    Fetch the next queued scan job.
    Priority jobs (priority=1) are always picked first.
    Within the same priority level, oldest job wins (FIFO).

    Returns
    -------
    dict or None
        A dict with keys ``id``, ``target_domain``, ``parent_domain``,
        ``status``, ``created_at``; or ``None`` if no queued jobs exist.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT * FROM scans
            WHERE status = 'queued'
            ORDER BY priority DESC, created_at ASC
            LIMIT 1;
            """
        ).fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        conn.close()


def pause_running_jobs() -> int:
    """
    Pause all currently running scan jobs by setting status to 'paused'.
    Returns the number of jobs paused.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE scans SET status = 'paused' WHERE status = 'running';"
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def resume_paused_jobs() -> int:
    """
    Resume all paused jobs by resetting their status to 'queued'.
    Returns the number of jobs resumed.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE scans SET status = 'queued' WHERE status = 'paused';"
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def claim_job(scan_id: int) -> bool:
    """
    Atomically transition a job 'queued' -> 'running'.

    get_next_job() SELECTs and this UPDATEs, so there is a window between
    them. Requiring status='queued' in the WHERE clause closes it: a job
    cancelled (or claimed by a second worker) in that gap fails the claim
    and returns False instead of being scanned anyway with its 'cancelled'
    status silently overwritten by 'running'.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE scans SET status = 'running' WHERE id = ? AND status = 'queued';",
            (scan_id,),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def is_cancelled(scan_id: int) -> bool:
    """
    Return True if this scan has been cancelled out from under the worker
    (i.e. someone hit Stop via POST /scan/{id}/stop while it was running).

    The worker polls this at phase boundaries so a cancel actually stops
    work, rather than only relabelling the row while the scan keeps
    hammering the network for another few minutes.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT status FROM scans WHERE id = ?;", (scan_id,)
        ).fetchone()
        return row is not None and row["status"] == "cancelled"
    finally:
        conn.close()


def finalize_job_status(scan_id: int, status: str) -> bool:
    """
    Write a TERMINAL status ('completed' / 'failed') without resurrecting a
    cancelled scan.

    The guard is in the WHERE clause rather than a read-then-write, so a
    stop request landing between the check and the update still wins.
    Returns False if the write was suppressed because the scan was cancelled.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "UPDATE scans SET status = ? WHERE id = ? AND status != 'cancelled';",
            (status, scan_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def reconcile_orphaned_jobs() -> dict:
    """
    Clean up jobs left mid-flight by a worker that died (crash, Ctrl+C,
    machine sleep). Called once at worker startup.

    'running' -> 'failed': that scan's process is gone and its partial rows
    are already in tls_results, so re-running the same scan_id would double
    up the data. Terminal-fail it and let the user re-scan cleanly.

    'paused'  -> 'queued': paused jobs never started, so requeuing is safe
    and loses nothing.

    Without this, a killed worker leaves the scan showing 'running' forever
    and the UI spins on a job no process will ever finish.
    """
    conn = get_connection()
    try:
        orphaned = [
            r["id"] for r in conn.execute(
                "SELECT id FROM scans WHERE status = 'running';"
            ).fetchall()
        ]
        now = datetime.now(timezone.utc).isoformat()
        failed = 0
        salvaged = 0
        for scan_id in orphaned:
            # The status write is the LAST step of a scan, so a worker killed
            # in the window between "[SUMMARY ✓] Scan complete!" and that
            # write leaves a fully-finished scan looking stranded. Blanket
            # -failing those throws away a complete result set — observed
            # live on a 255-host scan. Trust the evidence in the tables
            # instead of the status column.
            done = conn.execute(
                "SELECT COUNT(*) c FROM scan_logs WHERE scan_id = ? "
                "AND message LIKE '[SUMMARY %] Scan complete!%';",
                (scan_id,),
            ).fetchone()["c"]
            rows = conn.execute(
                "SELECT COUNT(*) c FROM tls_results WHERE scan_id = ?;", (scan_id,)
            ).fetchone()["c"]

            if done and rows:
                conn.execute(
                    "INSERT INTO scan_logs (scan_id, message, created_at) VALUES (?, ?, ?);",
                    (scan_id,
                     "[RECOVERED] Worker exited after this scan finished but before "
                     "its status was written — results are complete, marked completed "
                     "on worker restart.", now),
                )
                conn.execute("UPDATE scans SET status = 'completed' WHERE id = ?;", (scan_id,))
                salvaged += 1
            else:
                conn.execute(
                    "INSERT INTO scan_logs (scan_id, message, created_at) VALUES (?, ?, ?);",
                    (scan_id,
                     "[FAILED] Worker exited while this scan was running — "
                     "marked failed on worker restart. Re-run the scan.", now),
                )
                conn.execute("UPDATE scans SET status = 'failed' WHERE id = ?;", (scan_id,))
                failed += 1
        requeued = conn.execute(
            "UPDATE scans SET status = 'queued' WHERE status = 'paused';"
        ).rowcount
        conn.commit()
        return {"failed": failed, "salvaged": salvaged, "requeued": requeued}
    finally:
        conn.close()


def update_job_status(scan_id: int, status: str) -> None:
    """
    Update the status of a scan job.

    Parameters
    ----------
    scan_id : int
        ID of the scan to update.
    status : str
        New status value (``running``, ``completed``, ``failed``).
    """
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE scans SET status = ? WHERE id = ?;",
            (status, scan_id),
        )
        conn.commit()
    finally:
        conn.close()
