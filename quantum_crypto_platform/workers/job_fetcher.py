"""
Job fetcher — queries the database for pending scan jobs.
"""

import os
import sys

# Add backend directory to path so we can import shared modules.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

from database import get_connection


def get_next_job() -> dict | None:
    """
    Fetch the oldest queued scan job.

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
            ORDER BY created_at
            LIMIT 1;
            """
        ).fetchone()
        if row is None:
            return None
        return dict(row)
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
