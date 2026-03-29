"""
Cipher Parser module.
Parses TLS cipher suite strings into structured components,
handling both standard and unknown cipher formats gracefully.
"""


# ---- Known token categories for classification ----

KEY_EXCHANGE_TOKENS = {
    "ECDHE", "DHE", "RSA", "ECDH", "DH", "PSK", "SRP",
    "KYBER", "ML-KEM", "SNTRUP", "CECPQ2",
}

SIGNATURE_TOKENS = {
    "RSA", "ECDSA", "DSA", "DSS", "ED25519", "ED448",
    "DILITHIUM", "FALCON", "ML-DSA", "SPHINCS", "XMSS",
}

ENCRYPTION_TOKENS = {
    "AES", "CHACHA20", "CAMELLIA", "ARIA", "3DES", "DES",
    "RC4", "SEED", "POLY1305",
}

HASH_TOKENS = {
    "SHA256", "SHA384", "SHA512", "SHA1", "SHA",
    "MD5", "BLAKE2", "SHAKE256",
}

MODE_TOKENS = {
    "GCM", "CBC", "CCM", "CTR", "ECB",
}

SIZE_TOKENS = {"128", "192", "256", "512"}


def parse_cipher_suite(cipher_string: str) -> dict:
    """
    Parse a TLS cipher suite string into structured components.

    Handles standard formats like::

        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

    And unknown / hybrid formats like::

        TLS_XYZZY_KYBER_AES256_SHA512

    Parameters
    ----------
    cipher_string : str
        The raw cipher suite name from the TLS handshake.

    Returns
    -------
    dict
        Keys: ``key_exchange``, ``signature``, ``encryption``, ``hash``.
        Values are strings; ``"unknown"`` when a component cannot be determined.
    """
    if not cipher_string:
        return {
            "key_exchange": "unknown",
            "signature": "unknown",
            "encryption": "unknown",
            "hash": "unknown",
        }

    result = {
        "key_exchange": "unknown",
        "signature": "unknown",
        "encryption": "unknown",
        "hash": "unknown",
    }

    # Normalize
    upper = cipher_string.upper().strip()

    # Split on underscore; also handle hyphen-separated variants
    tokens = upper.replace("-", "_").split("_")

    # Remove common prefixes
    if tokens and tokens[0] == "TLS":
        tokens = tokens[1:]
    if "WITH" in tokens:
        idx = tokens.index("WITH")
        pre_with = tokens[:idx]
        post_with = tokens[idx + 1:]
    else:
        pre_with = tokens
        post_with = []

    # ---- Identify key exchange from pre-WITH tokens ----
    for t in pre_with:
        if t in KEY_EXCHANGE_TOKENS and result["key_exchange"] == "unknown":
            result["key_exchange"] = t
            break

    # ---- Identify signature from pre-WITH tokens ----
    for t in pre_with:
        if t in SIGNATURE_TOKENS and t != result["key_exchange"]:
            result["signature"] = t
            break

    # ---- Identify encryption (prefer post-WITH, then any token) ----
    enc_parts = []
    search_pool = post_with if post_with else pre_with
    for t in search_pool:
        if t in ENCRYPTION_TOKENS:
            enc_parts.append(t)
        elif t in SIZE_TOKENS and enc_parts:
            enc_parts.append(t)
        elif t in MODE_TOKENS and enc_parts:
            enc_parts.append(t)
    if enc_parts:
        result["encryption"] = "_".join(enc_parts)

    # ---- Identify hash (last SHA/hash token) ----
    all_tokens = pre_with + post_with
    for t in reversed(all_tokens):
        if t in HASH_TOKENS:
            result["hash"] = t
            break

    return result
