"""
Job manager — creates and manages scan jobs in the database.
"""

from datetime import datetime, timezone
from database import get_connection


def create_scan_job(domain: str, parent_domain: str) -> int:
    """
    Insert a new scan job with status 'queued'.

    Parameters
    ----------
    domain : str
        The normalized target hostname.
    parent_domain : str
        The derived parent domain.

    Returns
    -------
    int
        The id of the newly created scan row.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO scans (target_domain, parent_domain, status, created_at)
            VALUES (?, ?, 'queued', ?);
            """,
            (domain, parent_domain, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()
