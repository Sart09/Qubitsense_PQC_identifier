"""
Registry Updater module.
Manages the crypto_registry database table — seeds initial data,
inserts new algorithms, and updates existing entries.
"""

import os
import sys

# Ensure backend modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

from datetime import datetime, timezone
from database import get_connection
from pqc_registry import get_full_registry


def seed_registry() -> int:
    """
    Populate the crypto_registry table with all known algorithms
    from the built-in PQC + classical registries.

    Skips algorithms that already exist (idempotent).

    Returns
    -------
    int
        Number of new rows inserted.
    """
    registry = get_full_registry()
    conn = get_connection()
    inserted = 0
    try:
        for name, info in registry.items():
            existing = conn.execute(
                "SELECT id FROM crypto_registry WHERE algorithm_name = ?;",
                (name,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO crypto_registry
                        (algorithm_name, algorithm_family, quantum_safe,
                         risk_level, source, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        name,
                        info["family"],
                        1 if info["quantum_safe"] else 0,
                        info["risk_level"],
                        info.get("source", "built-in"),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                inserted += 1
        conn.commit()
    finally:
        conn.close()
    return inserted


def upsert_algorithm(
    algorithm_name: str,
    algorithm_family: str,
    quantum_safe: bool,
    risk_level: str,
    source: str = "threat_feed",
) -> None:
    """
    Insert or update a single algorithm in the registry.

    Parameters
    ----------
    algorithm_name : str
        Algorithm identifier (e.g. ``"ML-KEM"``).
    algorithm_family : str
        Family classification (e.g. ``"lattice"``).
    quantum_safe : bool
        Whether the algorithm is quantum-resistant.
    risk_level : str
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``.
    source : str
        Where the information originated.
    """
    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM crypto_registry WHERE algorithm_name = ?;",
            (algorithm_name,),
        ).fetchone()

        now = datetime.now(timezone.utc).isoformat()

        if existing:
            conn.execute(
                """
                UPDATE crypto_registry
                SET algorithm_family = ?, quantum_safe = ?, risk_level = ?,
                    source = ?, last_updated = ?
                WHERE algorithm_name = ?;
                """,
                (algorithm_family, 1 if quantum_safe else 0, risk_level,
                 source, now, algorithm_name),
            )
        else:
            conn.execute(
                """
                INSERT INTO crypto_registry
                    (algorithm_name, algorithm_family, quantum_safe,
                     risk_level, source, last_updated)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (algorithm_name, algorithm_family, 1 if quantum_safe else 0,
                 risk_level, source, now),
            )
        conn.commit()
    finally:
        conn.close()


def lookup_from_db(algorithm_name: str) -> dict | None:
    """
    Query the crypto_registry table for an algorithm.

    Returns a dict with registry info, or None if not found.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM crypto_registry WHERE algorithm_name = ?;",
            (algorithm_name.upper().strip(),),
        ).fetchone()
        if row is None:
            # Try partial match
            row = conn.execute(
                "SELECT * FROM crypto_registry WHERE ? LIKE '%' || algorithm_name || '%' OR algorithm_name LIKE '%' || ? || '%' LIMIT 1;",
                (algorithm_name.upper().strip(), algorithm_name.upper().strip()),
            ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all_registry_entries() -> list[dict]:
    """Return all entries in the crypto_registry table."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT algorithm_name, algorithm_family, quantum_safe, risk_level, source, last_updated "
            "FROM crypto_registry ORDER BY algorithm_name;"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
