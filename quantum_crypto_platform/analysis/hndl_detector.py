"""
HNDL Detector module.
Evaluates Harvest Now, Decrypt Later risk for a given service.

Nation-state adversaries may capture encrypted traffic today and decrypt it
later once quantum computers break RSA / ECC.  Services that carry high-value,
long-lived secrets (VPNs, authentication, email, financial APIs) receive
elevated HNDL multipliers.
"""


# ---- HNDL multiplier table -----------------------------------------------
# Higher values indicate greater attractiveness for harvest-now attacks.

SERVICE_MULTIPLIERS: dict[str, float] = {
    "OpenVPN":       2.0,
    "IPSec":         2.0,
    "SSL-VPN":       1.8,
    "WireGuard":     1.5,
    "LDAPS":         1.6,
    "IMAPS":         1.4,
    "SMTPS":         1.3,
    "Auth-Service":  1.6,
    "Financial-API": 1.7,
    "SSH":           1.3,
    "POP3S":         1.3,
    "FTPS":          1.2,
    "HTTPS":         1.0,
}

DEFAULT_MULTIPLIER: float = 1.0


def _risk_level(multiplier: float) -> str:
    """Map a numeric multiplier to a human-readable risk label."""
    if multiplier >= 2.0:
        return "critical"
    if multiplier >= 1.5:
        return "high"
    if multiplier >= 1.2:
        return "medium"
    return "low"


def detect_hndl_risk(hostname: str, port: int, service_type: str) -> dict:
    """
    Assess HNDL risk for a single service endpoint.

    Parameters
    ----------
    hostname : str
        The target hostname.
    port : int
        The target port number.
    service_type : str
        Service label produced by :func:`service_classifier.classify_service`.

    Returns
    -------
    dict
        Keys: ``hostname``, ``port``, ``service_type``,
        ``hndl_multiplier``, ``risk_level``.
    """
    multiplier = SERVICE_MULTIPLIERS.get(service_type, DEFAULT_MULTIPLIER)
    risk = _risk_level(multiplier)

    return {
        "hostname":        hostname,
        "port":            port,
        "service_type":    service_type,
        "hndl_multiplier": multiplier,
        "risk_level":      risk,
    }
