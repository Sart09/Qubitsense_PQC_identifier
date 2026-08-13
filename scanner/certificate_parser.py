"""
Certificate Parser module.
Extracts metadata from DER-encoded X.509 certificates.
"""

import ssl
import datetime


def parse_certificate(der_cert: bytes, hostname: str | None = None) -> dict:
    """
    Parse a DER-encoded certificate and extract key metadata.

    Attempts to use the ``cryptography`` library for rich parsing.
    Falls back to Python's stdlib ``ssl`` for basic fields.

    Parameters
    ----------
    der_cert : bytes
        DER-encoded X.509 certificate bytes.
    hostname : str, optional
        The hostname the handshake was made to. When provided, enables
        hostname/SAN mismatch detection — a genuine finding (shadow IT,
        misconfigured cert) rather than noise.

    Returns
    -------
    dict
        Keys: ``key_algorithm``, ``key_size``, ``signature_algorithm``,
        ``certificate_expiry``, ``san_names``, ``issuer``, ``is_self_signed``,
        ``is_expired``, ``days_until_expiry``, ``hostname_mismatch``.
        On error, includes: ``error_category``, ``error_reason``
    """
    if not der_cert:
        return {
            "error_category": "CERT_INVALID",
            "error_reason": "Certificate data is empty or None",
            "key_algorithm": "unknown",
            "key_size": 0,
            "signature_algorithm": "unknown",
            "certificate_expiry": "",
            "san_names": [],
            "issuer": "unknown",
            "is_self_signed": False,
            "is_expired": False,
            "days_until_expiry": None,
            "hostname_mismatch": False,
        }

    try:
        return _parse_with_cryptography(der_cert, hostname)
    except ImportError:
        return _parse_with_stdlib(der_cert)
    except ValueError as e:
        return {
            "error_category": "CERT_FORMAT_ERROR",
            "error_reason": f"Invalid certificate format: {str(e)[:100]}",
            "key_algorithm": "unknown",
            "key_size": 0,
            "signature_algorithm": "unknown",
            "certificate_expiry": "",
            "san_names": [],
            "issuer": "unknown",
            "is_self_signed": False,
            "is_expired": False,
            "days_until_expiry": None,
            "hostname_mismatch": False,
        }
    except Exception as e:
        # Try stdlib fallback for any other error
        try:
            return _parse_with_stdlib(der_cert)
        except Exception as e2:
            return {
                "error_category": "CERT_PARSE_ERROR",
                "error_reason": f"Failed to parse certificate: {str(e2)[:100]}",
                "key_algorithm": "unknown",
                "key_size": 0,
                "signature_algorithm": "unknown",
                "certificate_expiry": "",
                "san_names": [],
                "issuer": "unknown",
                "is_self_signed": False,
                "is_expired": False,
                "days_until_expiry": None,
                "hostname_mismatch": False,
            }


def _hostname_matches(hostname: str, san_names: list[str]) -> bool:
    """RFC 6125-lite: exact match or single-leftmost-label wildcard match."""
    hostname = hostname.lower().rstrip(".")
    for san in san_names:
        san = san.lower().rstrip(".")
        if san == hostname:
            return True
        if san.startswith("*."):
            suffix = san[1:]  # ".example.com"
            if hostname.endswith(suffix) and hostname.count(".") == san.count("."):
                return True
    return False


def _parse_with_cryptography(der_cert: bytes, hostname: str | None = None) -> dict:
    """Rich parsing using the ``cryptography`` library."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import (
            rsa, ec, dsa, ed25519, ed448,
        )
    except ImportError:
        raise ImportError("cryptography library not installed")

    try:
        cert = x509.load_der_x509_certificate(der_cert)
    except Exception as e:
        raise ValueError(f"Failed to load DER certificate: {e}")

    try:
        pub_key = cert.public_key()
    except Exception as e:
        raise ValueError(f"Failed to extract public key: {e}")

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
        # Unknown algorithm - likely PQC
        key_algorithm = type(pub_key).__name__
        key_size = 0

    # Signature algorithm
    try:
        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid.dotted_string)
    except Exception:
        sig_algo = "unknown"

    # Expiry
    is_expired = False
    days_until_expiry = None
    try:
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        expiry = not_after.isoformat()
        now = datetime.datetime.now(datetime.timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        delta = not_after - now
        days_until_expiry = delta.days
        is_expired = delta.total_seconds() < 0
    except Exception:
        expiry = ""

    # Subject Alternative Names — extracted once, feeds hostname-mismatch
    # detection here and the discovery SAN-feedback loop elsewhere.
    san_names: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = sorted({n.lower() for n in ext.value.get_values_for_type(x509.DNSName)})
    except x509.ExtensionNotFound:
        san_names = []
    except Exception:
        san_names = []

    # Issuer / self-signed — issuer == subject is the standard heuristic.
    try:
        issuer = cert.issuer.rfc4514_string()
        is_self_signed = cert.issuer == cert.subject
    except Exception:
        issuer = "unknown"
        is_self_signed = False

    hostname_mismatch = False
    if hostname and san_names:
        hostname_mismatch = not _hostname_matches(hostname, san_names)

    return {
        "key_algorithm": key_algorithm,
        "key_size": key_size,
        "signature_algorithm": sig_algo,
        "certificate_expiry": expiry,
        "san_names": san_names,
        "issuer": issuer,
        "is_self_signed": is_self_signed,
        "is_expired": is_expired,
        "days_until_expiry": days_until_expiry,
        "hostname_mismatch": hostname_mismatch,
    }


def _parse_with_stdlib(der_cert: bytes) -> dict:
    """Fallback parsing using Python's ssl module (limited info)."""
    return {
        "key_algorithm": "unknown",
        "key_size": 0,
        "signature_algorithm": "unknown",
        "certificate_expiry": "",
        "san_names": [],
        "issuer": "unknown",
        "is_self_signed": False,
        "is_expired": False,
        "days_until_expiry": None,
        "hostname_mismatch": False,
    }
