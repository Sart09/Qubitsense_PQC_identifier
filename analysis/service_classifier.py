"""
Service Classifier module.
Determines the type of service running on a given hostname:port
using port-number mapping and hostname keyword analysis.
"""


# ---- Port-based classification -------------------------------------------

PORT_MAP: dict[int, str] = {
    443:   "HTTPS",
    8443:  "HTTPS",
    1194:  "OpenVPN",
    500:   "IPSec",
    4500:  "IPSec",
    51820: "WireGuard",
    993:   "IMAPS",
    995:   "POP3S",
    636:   "LDAPS",
    465:   "SMTPS",
    587:   "SMTPS",
    22:    "SSH",
    990:   "FTPS",
}

# ---- Hostname keyword → service mapping ----------------------------------

KEYWORD_MAP: dict[str, str] = {
    "vpn":   "SSL-VPN",
    "openvpn": "OpenVPN",
    "ipsec": "IPSec",
    "wg":    "WireGuard",
    "auth":  "Auth-Service",
    "login": "Auth-Service",
    "sso":   "Auth-Service",
    "mail":  "IMAPS",
    "smtp":  "SMTPS",
    "api":   "Financial-API",
    "pay":   "Financial-API",
    "bank":  "Financial-API",
}


def classify_service(hostname: str, port: int) -> str:
    """
    Classify the service running on *hostname*:*port*.

    Classification priority:
        1. Well-known port mapping (most reliable).
        2. Hostname keyword matching (fallback / override for generic ports).

    Parameters
    ----------
    hostname : str
        The target hostname (e.g. ``vpn.bank.com``).
    port : int
        The target port number.

    Returns
    -------
    str
        A service-type label such as ``"OpenVPN"``, ``"HTTPS"``, ``"IMAPS"``, etc.
    """
    # 1. Exact port match
    service = PORT_MAP.get(port)

    # 2. Refine / override via hostname keywords (lower-cased comparison)
    host_lower = hostname.lower()
    for keyword, kw_service in KEYWORD_MAP.items():
        if keyword in host_lower:
            # Keyword match overrides only for generic ports (443 / unknown)
            if service is None or service == "HTTPS":
                service = kw_service
            break  # first match wins

    return service or "Unknown"
