"""
TLS Scanner module.
Performs TLS handshakes against hosts to extract cipher suites,
TLS versions, and raw certificates.
"""

import socket
import ssl
import time


def scan_tls(host: str, port: int = 443, retries: int = 3, backoff: float = 2.0) -> dict | None:
    """
    Perform a TLS handshake with automatic retry logic.

    Attempts the handshake multiple times with exponential backoff before failing.
    Gracefully handles certificate verification errors by retrying without verification.

    Parameters
    ----------
    host : str
        The hostname to connect to.
    port : int
        The port (default 443).
    retries : int
        Number of retry attempts (default 3). Total attempts = retries + 1.
    backoff : float
        Backoff multiplier between retries (default 2.0).

    Returns
    -------
    dict or None
        Keys: ``tls_version``, ``cipher_suite``, ``der_cert``, ``error`` (optional).
        Returns ``None`` only if all retry attempts fail.
        If error occurs, includes ``error_category`` and ``error_reason``.
    """
    attempt = 0
    last_error = None
    error_category = None

    while attempt <= retries:
        attempt += 1

        if attempt > 1:
            wait_time = backoff ** (attempt - 2)
            print(f"  [tls] Retry {attempt - 1}/{retries} for {host}:{port} (waiting {wait_time}s)...", flush=True)
            time.sleep(wait_time)

        # First attempt: with certificate verification
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((host, port), timeout=10) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cipher_info = tls_sock.cipher()      # (name, version, bits)
                    tls_version = tls_sock.version()      # e.g. 'TLSv1.3'
                    der_cert = tls_sock.getpeercert(binary_form=True)

                    # Validate we got required data
                    if not tls_version:
                        return {
                            "error_category": "PROTOCOL_ERROR",
                            "error_reason": "TLS version not negotiated",
                        }
                    
                    if not cipher_info:
                        return {
                            "error_category": "PROTOCOL_ERROR",
                            "error_reason": "No cipher suite negotiated",
                        }
                    
                    if not der_cert:
                        return {
                            "error_category": "CERT_ERROR",
                            "error_reason": "Server did not provide certificate despite TLS handshake",
                        }

                    return {
                        "tls_version": tls_version or "",
                        "cipher_suite": cipher_info[0] if cipher_info else "",
                        "der_cert": der_cert,
                    }

        except ssl.SSLCertVerificationError as e:
            error_category = "CERT_VERIFICATION_ERROR"
            last_error = str(e)
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
                        
                        if not der_cert:
                            return {
                                "error_category": "CERT_ERROR",
                                "error_reason": "Server did not provide certificate (even unverified)",
                            }
                        
                        return {
                            "tls_version": tls_version or "",
                            "cipher_suite": cipher_info[0] if cipher_info else "",
                            "der_cert": der_cert,
                            "cert_verification_failed": True,
                        }
            except Exception as e2:
                error_category = "CERT_VERIFICATION_ERROR"
                last_error = f"Unverified connection failed: {e2}"
                continue

        except ssl.SSLError as e:
            error_category = "SSL_ERROR"
            last_error = str(e)
            if "certificate verify failed" in str(e).lower():
                error_category = "CERT_VERIFICATION_ERROR"
            continue
        except socket.timeout:
            error_category = "CONNECTION_TIMEOUT"
            last_error = f"Connection timeout ({10}s)"
            continue
        except ConnectionRefusedError:
            error_category = "CONNECTION_REFUSED"
            last_error = "Connection refused"
            break  # No point retrying this
        except socket.gaierror as e:
            error_category = "DNS_RESOLUTION_ERROR"
            last_error = f"DNS resolution failed: {e}"
            break  # No point retrying this
        except OSError as e:
            if "too many open files" in str(e).lower():
                error_category = "RESOURCE_LIMIT"
                last_error = "Too many open files (file descriptor limit reached)"
            else:
                error_category = "OS_ERROR"
                last_error = str(e)
            continue
        except Exception as exc:
            error_category = "UNKNOWN_ERROR"
            last_error = str(exc)
            continue

    # --- Final attempt: Try cipher suite discovery on last retry ---
    # Use older/alternate cipher suites if standard attempts failed
    if attempt > retries and "certificate" not in error_category.lower():
        print(f"  [tls] Attempting cipher suite discovery fallback...", flush=True)
        try:
            ctx3 = ssl.create_default_context()
            ctx3.check_hostname = False
            ctx3.verify_mode = ssl.CERT_NONE
            # Allow older TLS versions for compatibility
            ctx3.minimum_version = ssl.TLSVersion.TLSv1
            
            with socket.create_connection((host, port), timeout=10) as raw_sock:
                with ctx3.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cipher_info = tls_sock.cipher()
                    tls_version = tls_sock.version()
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    
                    if tls_version and cipher_info:
                        print(f"  [tls] ✓ Cipher suite discovery succeeded: {tls_version} - {cipher_info[0]}", flush=True)
                        return {
                            "tls_version": tls_version,
                            "cipher_suite": cipher_info[0],
                            "der_cert": der_cert,
                            "discovery_fallback": True,
                        }
        except Exception as e:
            pass  # Fall through to error return

    # All retries exhausted
    print(f"  [tls] All {attempt} attempts failed for {host}:{port} - {error_category}: {last_error}", flush=True)
    return {
        "error_category": error_category or "UNKNOWN_ERROR",
        "error_reason": last_error or "Unknown error after all retries",
    }
