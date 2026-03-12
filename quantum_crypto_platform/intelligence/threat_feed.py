"""
Threat Feed Worker module.
Background process that periodically refreshes the crypto_registry
with the latest algorithm intelligence data.

Run standalone:
    python intelligence/threat_feed.py

Or call ``run_feed_update()`` from within the scan worker.
"""

import time
import os
import sys

# Ensure sibling packages are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))

from database import init_db
from registry_updater import seed_registry, upsert_algorithm
from pqc_registry import get_full_registry

UPDATE_INTERVAL = 86400  # 24 hours in seconds


def fetch_remote_updates() -> list[dict]:
    """
    Fetch updates from external threat intelligence sources.

    In production this would query:
      - NIST PQC announcements
      - Cryptography research feeds (ePrint / IACR)
      - Security advisories (CVE, NVD)

    Currently returns simulated updates to demonstrate the pipeline.
    """
    # Simulated feed entries — in production, replace with HTTP calls
    return [
        {
            "algorithm_name": "ML-KEM-768",
            "algorithm_family": "lattice",
            "quantum_safe": True,
            "risk_level": "low",
            "source": "NIST FIPS 203 (parameter set)",
        },
        {
            "algorithm_name": "ML-DSA-65",
            "algorithm_family": "lattice",
            "quantum_safe": True,
            "risk_level": "low",
            "source": "NIST FIPS 204 (parameter set)",
        },
        {
            "algorithm_name": "FrodoKEM",
            "algorithm_family": "lattice",
            "quantum_safe": True,
            "risk_level": "low",
            "source": "Alternative PQC candidate",
        },
    ]


def run_feed_update() -> dict:
    """
    Execute a single feed update cycle.

    1. Ensure registry is seeded with built-in algorithms.
    2. Fetch remote updates (simulated).
    3. Upsert each entry into the crypto_registry table.

    Returns
    -------
    dict
        Summary with ``seeded`` and ``updated`` counts.
    """
    seeded = seed_registry()
    remote = fetch_remote_updates()

    updated = 0
    for entry in remote:
        upsert_algorithm(
            algorithm_name=entry["algorithm_name"],
            algorithm_family=entry["algorithm_family"],
            quantum_safe=entry["quantum_safe"],
            risk_level=entry["risk_level"],
            source=entry.get("source", "threat_feed"),
        )
        updated += 1

    return {"seeded": seeded, "updated": updated}


def main() -> None:
    """Main loop — run periodic feed updates."""
    init_db()

    print("=" * 60)
    print("  Quantum Crypto Intelligence -- Threat Feed Worker")
    print("=" * 60)

    while True:
        print("[threat-feed] Running update cycle...")
        result = run_feed_update()
        print(f"[threat-feed] Seeded {result['seeded']} built-in, updated {result['updated']} from feed")
        print(f"[threat-feed] Next update in {UPDATE_INTERVAL // 3600}h\n")
        time.sleep(UPDATE_INTERVAL)


if __name__ == "__main__":
    main()
