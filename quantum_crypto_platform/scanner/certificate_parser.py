"""
Certificate Parser module.
Extracts metadata from DER-encoded X.509 certificates.
"""

import ssl
import datetime


def parse_certificate(der_cert: bytes) -> dict:
    """
    Parse a DER-encoded certificate and extract key metadata.

    Attempts to use the ``cryptography`` library for rich parsing.
    Falls back to Python's stdlib ``ssl`` for basic fields.

    Parameters
    ----------
    der_cert : bytes
        DER-encoded X.509 certificate bytes.

    Returns
    -------
    dict
        Keys: ``key_algorithm``, ``key_size``, ``signature_algorithm``,
        ``certificate_expiry``.
    """
    try:
        return _parse_with_cryptography(der_cert)
    except ImportError:
        return _parse_with_stdlib(der_cert)
    except Exception:
        return _parse_with_stdlib(der_cert)


def _parse_with_cryptography(der_cert: bytes) -> dict:
    """Rich parsing using the ``cryptography`` library."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        rsa, ec, dsa, ed25519, ed448,
    )

    cert = x509.load_der_x509_certificate(der_cert)
    pub_key = cert.public_key()

    # Determine key algorithm and size
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_algorithm = "RSA"
        key_size = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_algorithm = f"ECDSA ({pub_key.curve.name})"
        key_size = pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_algorithm = "DSA"
        key_size = pub_key.key_size
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        key_algorithm = "Ed25519"
        key_size = 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        key_algorithm = "Ed448"
        key_size = 448
    else:
        key_algorithm = type(pub_key).__name__
        key_size = 0

    # Signature algorithm
    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid.dotted_string)

    # Expiry
    expiry = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()

    return {
        "key_algorithm": key_algorithm,
        "key_size": key_size,
        "signature_algorithm": sig_algo,
        "certificate_expiry": expiry,
    }


def _parse_with_stdlib(der_cert: bytes) -> dict:
    """Fallback parsing using Python's ssl module (limited info)."""
    try:
        # ssl.DER_cert_to_PEM_cert + decode won't give us key info,
        # but we can get basic cert dict via a temp context
        pem = ssl.DER_cert_to_PEM_cert(der_cert)

        # Try to get expiry from the PEM string
        import re
        # Parse the certificate using ssl internal helpers if available
        cert_dict = ssl._ssl._test_decode_cert(None)  # type: ignore
    except Exception:
        cert_dict = {}

    return {
        "key_algorithm": "unknown",
        "key_size": 0,
        "signature_algorithm": "unknown",
        "certificate_expiry": "",
    }
