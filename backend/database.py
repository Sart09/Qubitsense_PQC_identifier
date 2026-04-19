"""
Database module for Quantum Proof System Scanner.
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
                source          TEXT    DEFAULT 'manual',
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
                note        TEXT,
                created_at  TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                hostname TEXT NOT NULL,
                failure_category TEXT NOT NULL,
                failure_reason TEXT NOT NULL,
                failure_code TEXT,
                attempt_count INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT NOT NULL,
                frequency       TEXT NOT NULL CHECK(frequency IN ('daily','weekly','monthly','custom')),
                custom_interval_hours INTEGER,         
                is_active       INTEGER DEFAULT 1,     
                created_by      INTEGER,               
                created_at      TEXT DEFAULT (datetime('now')),
                last_run_at     TEXT,                  
                next_run_at     TEXT NOT NULL,         
                last_scan_id    INTEGER,               
                last_risk_score REAL,                  
                prev_risk_score REAL,                  
                run_count       INTEGER DEFAULT 0,     
                notify_on_change INTEGER DEFAULT 0,    
                UNIQUE(domain, frequency),
                FOREIGN KEY (created_by) REFERENCES users(id),
                FOREIGN KEY (last_scan_id) REFERENCES scans(id) ON DELETE SET NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schedule_run_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id     INTEGER NOT NULL,      
                scan_id         INTEGER,               
                triggered_at    TEXT DEFAULT (datetime('now')),
                completed_at    TEXT,
                status          TEXT CHECK(status IN ('triggered','running','completed','failed')),
                risk_score      REAL,
                subdomains_found INTEGER,
                subdomains_scanned INTEGER,
                error_message   TEXT,
                FOREIGN KEY(schedule_id) REFERENCES scheduled_scans(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
            );
            """
        )
        conn.commit()

        # Migrate existing databases: add failure_code column to scan_failures
        try:
            conn.execute("ALTER TABLE scan_failures ADD COLUMN failure_code TEXT;")
            conn.commit()
        except Exception:
            pass  # Column already exists

        # Migrate: add priority column to scans
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;")
            conn.commit()
        except Exception:
            pass  # Already exists

        # Migrate existing databases: add source column to scans
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN source TEXT DEFAULT 'manual';")
            conn.commit()
        except Exception:
            pass  # Column already exists
    finally:
        conn.close()
