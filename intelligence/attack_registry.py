"""
Attack Registry module.
Catalogs known quantum computing attacks and the cryptographic
families / algorithms they threaten.
"""

# ---- Quantum attack definitions ------------------------------------------

QUANTUM_ATTACKS: dict[str, dict] = {
    "Shor": {
        "description": "Shor's algorithm efficiently factors large integers and computes "
                       "discrete logarithms on a quantum computer.",
        "impact": "breaks",
        "targets": ["RSA", "DSA", "DH", "DHE", "ECDH", "ECDHE", "ECDSA", "ED25519", "ED448", "DSS"],
        "target_families": ["factoring", "discrete_log", "elliptic_curve"],
        "risk_level": "critical",
    },
    "Grover": {
        "description": "Grover's algorithm provides quadratic speedup for brute-force search, "
                       "effectively halving symmetric key and hash security levels.",
        "impact": "weakens",
        "targets": ["AES", "CHACHA20", "CAMELLIA", "3DES", "DES", "RC4",
                     "SHA256", "SHA384", "SHA512", "SHA1", "MD5"],
        "target_families": ["symmetric", "hash"],
        "risk_level": "medium",
    },
    "Harvest-Now-Decrypt-Later": {
        "description": "Adversaries capture encrypted traffic today for future decryption "
                       "once quantum computers become available.",
        "impact": "enables_future_attack",
        "targets": ["RSA", "ECDHE", "DHE"],
        "target_families": ["factoring", "elliptic_curve", "discrete_log"],
        "risk_level": "high",
    },
}


def get_all_attacks() -> dict[str, dict]:
    """Return the full attack registry."""
    return QUANTUM_ATTACKS.copy()


def is_algorithm_broken(algorithm_name: str) -> dict | None:
    """
    Check if a given algorithm is broken or weakened by any known quantum attack.

    Parameters
    ----------
    algorithm_name : str
        Algorithm name (e.g. ``"RSA"``, ``"AES"``).

    Returns
    -------
    dict or None
        Attack info dict with keys ``attack_name``, ``impact``, ``risk_level``,
        or None if no known attack targets this algorithm.
    """
    upper = algorithm_name.upper().strip()
    for attack_name, info in QUANTUM_ATTACKS.items():
        if upper in info["targets"]:
            return {
                "attack_name": attack_name,
                "impact": info["impact"],
                "risk_level": info["risk_level"],
            }
    return None


def is_family_targeted(family: str) -> dict | None:
    """
    Check if an algorithm family is targeted by any known quantum attack.

    Parameters
    ----------
    family : str
        Algorithm family (e.g. ``"factoring"``, ``"symmetric"``).

    Returns
    -------
    dict or None
        Attack info dict, or None if no known attack targets this family.
    """
    lower = family.lower().strip()
    for attack_name, info in QUANTUM_ATTACKS.items():
        if lower in info["target_families"]:
            return {
                "attack_name": attack_name,
                "impact": info["impact"],
                "risk_level": info["risk_level"],
            }
    return None
