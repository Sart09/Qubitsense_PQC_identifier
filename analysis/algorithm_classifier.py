"""
Algorithm Classifier module.
Parses TLS cipher suites to identify key exchange and signature algorithms.
"""


def classify_algorithm(cipher_suite: str, key_algorithm: str | None, signature_algorithm: str | None) -> dict:
    """
    Classify the algorithms used in a TLS connection.

    Parses standard TLS cipher suites like TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    to extract the key exchange and signature mechanisms. If the cipher suite
    doesn't specify (like in TLS 1.3), it falls back to the certificate metadata.

    Parameters
    ----------
    cipher_suite : str
        The negotiated cipher suite (e.g. TLS_AES_256_GCM_SHA384).
    key_algorithm : str or None
        The public key algorithm from the certificate.
    signature_algorithm : str or None
        The signature algorithm from the certificate.

    Returns
    -------
    dict
        Keys: ``key_exchange``, ``signature``
    """
    if not cipher_suite:
        return {
            "key_exchange": "unknown",
            "signature": signature_algorithm or "unknown"
        }

    kex = "unknown"
    sig = signature_algorithm or "unknown"

    cv = cipher_suite.upper()

    # TLS 1.2 and below standard naming (e.g. TLS_ECDHE_RSA_WITH_...)
    if "WITH" in cv:
        prefix = cv.split("_WITH_")[0]
        parts = prefix.split("_")
        
        if "ECDHE" in parts:
            kex = "ECDHE"
        elif "DHE" in parts:
            kex = "DHE"
        elif "RSA" in parts:
            # RSA key transport (no forward secrecy)
            kex = "RSA"

        if "RSA" in parts and kex != "RSA":
            sig = "RSA"
        elif "ECDSA" in parts:
            sig = "ECDSA"
        elif "DSS" in parts:
            sig = "DSA"
    else:
        # TLS 1.3 suites (e.g. TLS_AES_256_GCM_SHA384) don't specify kex/sig in the name.
        # Kex is usually negotiated via supported_groups (ECDHE/DHE), not visible here.
        # We rely on the cert for signature type.
        kex = "ECDHE (assumed for TLS 1.3)"
        if key_algorithm:
            # If cert is RSA, the signature is likely RSA-PSS or RSA.
            if "RSA" in key_algorithm.upper():
                sig = "RSA"
            elif "EC" in key_algorithm.upper():
                sig = "ECDSA"

    return {
        "key_exchange": kex,
        "signature": sig
    }


# ---- Algorithm family classification ------------------------------------

ALGORITHM_FAMILIES: dict[str, str] = {
    # Factoring-based (Shor-vulnerable)
    "RSA":       "factoring",
    # Elliptic curve (Shor-vulnerable)
    "ECDHE":     "elliptic_curve",
    "ECDH":      "elliptic_curve",
    "ECDSA":     "elliptic_curve",
    "ED25519":   "elliptic_curve",
    "ED448":     "elliptic_curve",
    # Discrete log (Shor-vulnerable)
    "DHE":       "discrete_log",
    "DH":        "discrete_log",
    "DSA":       "discrete_log",
    "DSS":       "discrete_log",
    # Lattice-based (quantum resistant)
    "KYBER":     "lattice",
    "ML-KEM":    "lattice",
    "DILITHIUM": "lattice",
    "ML-DSA":    "lattice",
    "SNTRUP":    "lattice",
    "FALCON":    "lattice",
    "CECPQ2":    "lattice",
    # Hash-based signatures (quantum resistant)
    "SPHINCS":   "hash_based_sig",
    "XMSS":      "hash_based_sig",
    # Symmetric ciphers (Grover-weakened)
    "AES":       "symmetric",
    "CHACHA20":  "symmetric",
    "CAMELLIA":  "symmetric",
    "ARIA":      "symmetric",
    "3DES":      "symmetric",
    "DES":       "symmetric",
    "RC4":       "symmetric",
    # Hash functions (Grover-weakened)
    "SHA256":    "hash",
    "SHA384":    "hash",
    "SHA512":    "hash",
    "SHA1":      "hash",
    "SHA":       "hash",
    "MD5":       "hash",
    "BLAKE2":    "hash",
    "SHAKE256":  "hash",
}


def classify_family(parsed_cipher: dict) -> dict:
    """
    Classify each cipher component into an algorithm family.

    Parameters
    ----------
    parsed_cipher : dict
        Output from ``cipher_parser.parse_cipher_suite()``.
        Keys: ``key_exchange``, ``signature``, ``encryption``, ``hash``.

    Returns
    -------
    dict
        Keys: ``key_exchange_family``, ``signature_family``,
        ``encryption_family``, ``hash_family``.
    """
    def _lookup(token: str) -> str:
        if not token or token == "unknown":
            return "unknown"
        t = token.upper().strip()
        # Direct match
        if t in ALGORITHM_FAMILIES:
            return ALGORITHM_FAMILIES[t]
        # Partial match — scan for known substrings
        for alg, family in ALGORITHM_FAMILIES.items():
            if alg in t:
                return family
        return "unknown"

    # For encryption, strip size/mode suffixes before lookup
    enc_token = parsed_cipher.get("encryption", "unknown")
    enc_base = enc_token.split("_")[0] if enc_token else "unknown"

    return {
        "key_exchange_family": _lookup(parsed_cipher.get("key_exchange", "unknown")),
        "signature_family":    _lookup(parsed_cipher.get("signature", "unknown")),
        "encryption_family":   _lookup(enc_base),
        "hash_family":         _lookup(parsed_cipher.get("hash", "unknown")),
    }
