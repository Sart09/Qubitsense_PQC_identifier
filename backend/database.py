"""
Database module for Quantum Proof System Scanner.
Manages SQLite connection and schema initialization.
"""

import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
DB_PATH = os.path.join(DB_DIR, "platform.db")

os.makedirs(DB_DIR, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    """Return a connection to the SQLite database.

    journal_mode is a persistent property of the DB file, not the connection,
    so it's set once in init_db() rather than on every connect (that PRAGMA
    round-trip was measured at a meaningful fraction of per-row write cost
    under high row counts).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def init_db() -> None:
    """Create database tables if they do not exist."""
    conn = get_connection()
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
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
            CREATE TABLE IF NOT EXISTS login_audit (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER,
                email           TEXT    NOT NULL,
                event           TEXT    NOT NULL,
                ip_address      TEXT,
                user_agent      TEXT,
                created_at      TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_challenges (
                token           TEXT    PRIMARY KEY,
                user_id         INTEGER NOT NULL,
                expires_at      TEXT    NOT NULL,
                attempt_count   INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
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

        # Migrate: certificate validation fields — computed in
        # certificate_parser.py since the async TLS rewrite, but previously
        # discarded before reaching the DB. Real findings (expired,
        # self-signed, hostname-mismatched certs) with nowhere to land.
        for stmt in (
            "ALTER TABLE tls_results ADD COLUMN hostname_mismatch INTEGER;",
            "ALTER TABLE tls_results ADD COLUMN is_self_signed INTEGER;",
            "ALTER TABLE tls_results ADD COLUMN is_expired INTEGER;",
            "ALTER TABLE tls_results ADD COLUMN days_until_expiry INTEGER;",
            "ALTER TABLE tls_results ADD COLUMN issuer TEXT;",
        ):
            try:
                conn.execute(stmt)
                conn.commit()
            except Exception:
                pass  # Column already exists

        # Migrate: roles, account status, MFA and Supabase identity mirror
        # on users. Additive only — supabase_uid stays NULL for local-only
        # accounts, so nothing here requires a Supabase project to exist.
        for stmt in (
            "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';",
            "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;",
            "ALTER TABLE users ADD COLUMN last_login_at TEXT;",
            "ALTER TABLE users ADD COLUMN supabase_uid TEXT;",
            "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;",
            "ALTER TABLE users ADD COLUMN mfa_secret TEXT;",
            "ALTER TABLE users ADD COLUMN mfa_pending_secret TEXT;",
        ):
            try:
                conn.execute(stmt)
                conn.commit()
            except Exception:
                pass  # Column already exists

        # Migrate: reclassify scans that finished cleanly but scanned zero
        # hosts. The worker used to mark any non-crashing run 'completed',
        # so a typo'd or parked domain produced a scan that looked
        # successful, rendered a dashboard of zeroes, and would export an
        # empty report. Those are failures, not successes.
        #
        # Deliberately narrow: only status='completed' rows with no
        # tls_results at all. A 'running' scan legitimately has zero rows
        # mid-flight and must not be touched.
        reclassified = conn.execute(
            """
            UPDATE scans SET status = 'failed'
            WHERE status = 'completed'
              AND NOT EXISTS (SELECT 1 FROM tls_results WHERE tls_results.scan_id = scans.id);
            """
        ).rowcount
        if reclassified:
            # A cache entry pointing at an empty scan would serve that
            # emptiness to the next re-scan of the same domain, so those
            # entries go too.
            conn.execute(
                """
                DELETE FROM scan_cache WHERE scan_id IN (
                    SELECT id FROM scans WHERE status = 'failed'
                );
                """
            )
            print(f"[db] Reclassified {reclassified} zero-host scan(s) from completed -> failed")
        conn.commit()

        # Indexes: every scan_id lookup was a full table scan without these.
        # idx_scans_queue serves the worker's job poll, which runs every 3s
        # forever; idx_logs_scan_id serves the progress page's 2s poll.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tls_scan      ON tls_results(scan_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_scan   ON discovered_assets(scan_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hndl_scan     ON hndl_results(scan_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_algo_scan     ON algorithm_analysis(scan_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_failures_scan ON scan_failures(scan_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_results_scan  ON scan_results(scan_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_scan_id  ON scan_logs(scan_id, id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_queue   ON scans(status, priority DESC, created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_domain  ON scan_cache(domain, expires_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_user_scans_u  ON user_scans(user_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_audit_user ON login_audit(user_id, created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);")
        conn.commit()
    finally:
        conn.close()
