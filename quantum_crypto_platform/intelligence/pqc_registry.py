"""
PQC Registry module.
Maintains the built-in catalog of post-quantum cryptographic algorithms
as standardized by NIST and the broader PQC community.
"""

# ---- Built-in PQC algorithm registry ------------------------------------
# Each entry: algorithm_name → { family, quantum_safe, risk_level, source }

PQC_ALGORITHMS: dict[str, dict] = {
    # ── NIST Standards (FIPS 203 / 204 / 205) ──
    "ML-KEM":   {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "NIST FIPS 203"},
    "ML-DSA":   {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "NIST FIPS 204"},
    "SLH-DSA":  {"family": "hash_based_sig",  "quantum_safe": True,  "risk_level": "low", "source": "NIST FIPS 205"},
    # ── NIST Round 4 candidates ──
    "BIKE":     {"family": "code_based",      "quantum_safe": True,  "risk_level": "low", "source": "NIST PQC Round 4"},
    "HQC":      {"family": "code_based",      "quantum_safe": True,  "risk_level": "low", "source": "NIST PQC Round 4"},
    "Classic-McEliece": {"family": "code_based", "quantum_safe": True, "risk_level": "low", "source": "NIST PQC Round 4"},
    # ── Legacy names / aliases ──
    "KYBER":      {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "NIST (renamed ML-KEM)"},
    "DILITHIUM":  {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "NIST (renamed ML-DSA)"},
    "FALCON":     {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "NIST PQC"},
    "SPHINCS":    {"family": "hash_based_sig",  "quantum_safe": True,  "risk_level": "low", "source": "NIST (renamed SLH-DSA)"},
    "SPHINCS+":   {"family": "hash_based_sig",  "quantum_safe": True,  "risk_level": "low", "source": "NIST PQC"},
    "XMSS":       {"family": "hash_based_sig",  "quantum_safe": True,  "risk_level": "low", "source": "IETF RFC 8391"},
    "LMS":        {"family": "hash_based_sig",  "quantum_safe": True,  "risk_level": "low", "source": "NIST SP 800-208"},
    # ── Hybrid / experimental ──
    "CECPQ2":     {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "Google experiment"},
    "SNTRUP":     {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "OpenSSH"},
    "SNTRUP761":  {"family": "lattice",         "quantum_safe": True,  "risk_level": "low", "source": "OpenSSH/IETF"},
}

# ---- Classical (quantum-vulnerable) algorithms ---------------------------

CLASSICAL_ALGORITHMS: dict[str, dict] = {
    "RSA":      {"family": "factoring",       "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "DSA":      {"family": "discrete_log",    "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "DSS":      {"family": "discrete_log",    "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "DH":       {"family": "discrete_log",    "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "DHE":      {"family": "discrete_log",    "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "ECDH":     {"family": "elliptic_curve",  "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "ECDHE":    {"family": "elliptic_curve",  "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "ECDSA":    {"family": "elliptic_curve",  "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "ED25519":  {"family": "elliptic_curve",  "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "ED448":    {"family": "elliptic_curve",  "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    # Symmetric (weakened, not broken)
    "AES":      {"family": "symmetric",       "quantum_safe": False, "risk_level": "medium",   "source": "classical"},
    "CHACHA20": {"family": "symmetric",       "quantum_safe": False, "risk_level": "medium",   "source": "classical"},
    "CAMELLIA": {"family": "symmetric",       "quantum_safe": False, "risk_level": "medium",   "source": "classical"},
    "3DES":     {"family": "symmetric",       "quantum_safe": False, "risk_level": "high",     "source": "classical"},
    "DES":      {"family": "symmetric",       "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    "RC4":      {"family": "symmetric",       "quantum_safe": False, "risk_level": "critical", "source": "classical"},
    # Hashes (weakened, not broken)
    "SHA256":   {"family": "hash",            "quantum_safe": False, "risk_level": "medium",   "source": "classical"},
    "SHA384":   {"family": "hash",            "quantum_safe": False, "risk_level": "medium",   "source": "classical"},
    "SHA512":   {"family": "hash",            "quantum_safe": False, "risk_level": "medium",   "source": "classical"},
    "SHA1":     {"family": "hash",            "quantum_safe": False, "risk_level": "high",     "source": "classical"},
    "MD5":      {"family": "hash",            "quantum_safe": False, "risk_level": "critical", "source": "classical"},
}


def get_full_registry() -> dict[str, dict]:
    """Return the combined PQC + classical algorithm registry."""
    combined = {}
    combined.update(CLASSICAL_ALGORITHMS)
    combined.update(PQC_ALGORITHMS)  # PQC entries override any classical duplicates
    return combined


def lookup_algorithm(name: str) -> dict | None:
    """
    Look up an algorithm by name (case-insensitive).

    Returns the registry entry dict, or None if not found.
    """
    registry = get_full_registry()
    upper = name.upper().strip()
    # Direct match
    if upper in registry:
        return registry[upper]
    # Partial match
    for algo_name, info in registry.items():
        if algo_name in upper or upper in algo_name:
            return info
    return None
