"""
Database module for Quantum Crypto Intelligence Platform.
Manages SQLite connection and schema initialization.
"""

import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
DB_PATH = os.path.join(DB_DIR, "platform.db")


def get_connection() -> sqlite3.Connection:
    """Return a connection to the SQLite database."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    """Create database tables if they do not exist."""
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                target_domain   TEXT    NOT NULL,
                parent_domain   TEXT,
                status          TEXT    NOT NULL DEFAULT 'queued',
                created_at      TEXT    NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                host        TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                service     TEXT    NOT NULL,
                status      TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS discovered_assets (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id           INTEGER NOT NULL,
                hostname          TEXT    NOT NULL,
                ip_address        TEXT,
                discovery_method  TEXT    NOT NULL,
                created_at        TEXT    NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tls_results (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id              INTEGER NOT NULL,
                hostname             TEXT    NOT NULL,
                port                 INTEGER NOT NULL DEFAULT 443,
                tls_version          TEXT,
                cipher_suite         TEXT,
                key_algorithm        TEXT,
                key_size             INTEGER,
                signature_algorithm  TEXT,
                certificate_expiry   TEXT,
                created_at           TEXT    NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )

        
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hndl_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         INTEGER NOT NULL,
                hostname        TEXT    NOT NULL,
                port            INTEGER NOT NULL,
                service_type    TEXT    NOT NULL,
                hndl_multiplier REAL    NOT NULL,
                risk_level      TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS algorithm_analysis (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id                 INTEGER NOT NULL,
                hostname                TEXT    NOT NULL,
                cipher_suite            TEXT,
                key_exchange            TEXT,
                signature               TEXT,
                encryption              TEXT,
                hash                    TEXT,
                classification          TEXT,
                quantum_risk_estimate   INTEGER,
                created_at              TEXT    NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS crypto_registry (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm_name    TEXT    NOT NULL UNIQUE,
                algorithm_family  TEXT    NOT NULL,
                quantum_safe      INTEGER NOT NULL DEFAULT 0,
                risk_level        TEXT    NOT NULL,
                source            TEXT,
                last_updated      TEXT    NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_cache (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT    NOT NULL,
                scan_id     INTEGER NOT NULL,
                created_at  TEXT    NOT NULL,
                expires_at  TEXT    NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                email           TEXT    NOT NULL UNIQUE,
                password_hash   TEXT    NOT NULL,
                created_at      TEXT    NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                scan_id     INTEGER NOT NULL,
                domain      TEXT    NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'queued',
                monitored   INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()
