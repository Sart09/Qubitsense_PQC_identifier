"""
Result manager — stores scan results in the database.
"""

from datetime import datetime, timezone
from database import get_connection


def store_result(scan_id: int, host: str, port: int, service: str) -> int:
    """
    Insert a scan result row.

    Parameters
    ----------
    scan_id : int
        The parent scan job ID.
    host : str
        The scanned hostname.
    port : int
        The port number.
    service : str
        The detected service name.

    Returns
    -------
    int
        The id of the newly created result row.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO scan_results (scan_id, host, port, service, status, created_at)
            VALUES (?, ?, ?, ?, 'analyzed', ?);
            """,
            (scan_id, host, port, service, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def store_tls_result(
    scan_id: int,
    hostname: str,
    port: int,
    tls_version: str | None,
    cipher_suite: str | None,
    key_algorithm: str | None,
    key_size: int | None,
    signature_algorithm: str | None,
    certificate_expiry: str | None,
) -> int:
    """Insert a TLS scan result row."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO tls_results (
                scan_id, hostname, port, tls_version, cipher_suite,
                key_algorithm, key_size, signature_algorithm, certificate_expiry, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                scan_id, hostname, port, tls_version, cipher_suite,
                key_algorithm, key_size, signature_algorithm, certificate_expiry,
                datetime.now(timezone.utc).isoformat()
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()





def store_hndl_result(
    scan_id: int,
    hostname: str,
    port: int,
    service_type: str,
    hndl_multiplier: float,
    risk_level: str,
) -> int:
    """Insert an HNDL detection result row."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO hndl_results (
                scan_id, hostname, port, service_type,
                hndl_multiplier, risk_level, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                scan_id, hostname, port, service_type,
                hndl_multiplier, risk_level,
                datetime.now(timezone.utc).isoformat()
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def store_algorithm_analysis(
    scan_id: int,
    hostname: str,
    cipher_suite: str | None,
    key_exchange: str,
    signature: str,
    encryption: str,
    hash_alg: str,
    classification: str,
    quantum_risk_estimate: int,
) -> int:
    """Insert an algorithm analysis result row."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO algorithm_analysis (
                scan_id, hostname, cipher_suite,
                key_exchange, signature, encryption, hash,
                classification, quantum_risk_estimate, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                scan_id, hostname, cipher_suite,
                key_exchange, signature, encryption, hash_alg,
                classification, quantum_risk_estimate,
                datetime.now(timezone.utc).isoformat()
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()
