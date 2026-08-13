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
    hostname_mismatch: bool | None = None,
    is_self_signed: bool | None = None,
    is_expired: bool | None = None,
    days_until_expiry: int | None = None,
    issuer: str | None = None,
) -> int:
    """Insert a TLS scan result row."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO tls_results (
                scan_id, hostname, port, tls_version, cipher_suite,
                key_algorithm, key_size, signature_algorithm, certificate_expiry,
                hostname_mismatch, is_self_signed, is_expired, days_until_expiry, issuer,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                scan_id, hostname, port, tls_version, cipher_suite,
                key_algorithm, key_size, signature_algorithm, certificate_expiry,
                hostname_mismatch, is_self_signed, is_expired, days_until_expiry, issuer,
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
    quantum_risk_estimate: int | str,
) -> int:
    """
    Insert an algorithm analysis result row.
    
    Handles both numeric risk estimates and string values like "unknown"
    for graceful degradation when analysis fails.
    """
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
                classification, str(quantum_risk_estimate),
                datetime.now(timezone.utc).isoformat()
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def store_scan_failure(
    scan_id: int,
    hostname: str,
    failure_category: str,
    failure_reason: str,
    attempt_count: int = 1,
    failure_code: str = "",
) -> int:
    """
    Insert a scan failure record for tracking and reporting.
    
    Parameters
    ----------
    scan_id : int
        Parent scan ID
    hostname : str
        The hostname that failed to scan
    failure_category : str
        Category of failure (e.g., 'CONNECTION_TIMEOUT', 'CERT_ERROR', 'DNS_RESOLUTION_ERROR')
    failure_reason : str
        Detailed reason for failure
    attempt_count : int
        Number of attempts made before failure
    failure_code : str
        Structured failure code for dashboard breakdown:
        DNS_NO_RECORD, TCP_TIMEOUT, TCP_REFUSED, TLS_HANDSHAKE_FAIL,
        TLS_LEGACY_CIPHER, CERT_MISMATCH
    
    Returns
    -------
    int
        Row ID of the inserted failure record
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO scan_failures (
                scan_id, hostname, failure_category, failure_reason,
                failure_code, attempt_count, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                scan_id, hostname, failure_category, failure_reason,
                failure_code, attempt_count,
                datetime.now(timezone.utc).isoformat()
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()
