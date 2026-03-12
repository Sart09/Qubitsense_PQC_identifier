"""
TLS Scanner module.
Performs TLS handshakes against hosts to extract cipher suites,
TLS versions, and raw certificates.
"""

import socket
import ssl


def scan_tls(host: str, port: int = 443) -> dict | None:
    """
    Perform a TLS handshake and extract connection metadata.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port (default 443).

    Returns
    -------
    dict or None
        Keys: ``tls_version``, ``cipher_suite``, ``der_cert``
        Returns ``None`` if the handshake fails.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cipher_info = tls_sock.cipher()      # (name, version, bits)
                tls_version = tls_sock.version()      # e.g. 'TLSv1.3'
                der_cert = tls_sock.getpeercert(binary_form=True)

                return {
                    "tls_version": tls_version or "",
                    "cipher_suite": cipher_info[0] if cipher_info else "",
                    "der_cert": der_cert,
                }

    except ssl.SSLCertVerificationError:
        # Retry without verification to still capture cipher info
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as raw_sock:
                with ctx2.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cipher_info = tls_sock.cipher()
                    tls_version = tls_sock.version()
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    return {
                        "tls_version": tls_version or "",
                        "cipher_suite": cipher_info[0] if cipher_info else "",
                        "der_cert": der_cert,
                    }
        except Exception:
            return None

    except Exception as exc:
        print(f"  [tls] Failed to connect to {host}:{port} - {exc}")
        return None
