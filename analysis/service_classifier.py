"""
Service Classifier module.
Determines the type of service running on a given hostname:port
using port-number mapping and hostname keyword analysis.

SCOPE OF THE KEYWORD MATCH
--------------------------
Keywords are matched **only against the subdomain labels below the
registrable domain**, never against the registrable domain itself.

This matters more than it sounds. The classifier previously tested each
keyword as a bare substring of the whole hostname, which meant the
customer's own domain name leaked into every verdict: scanning
``pnb.bank.in`` classified all 101 discovered hosts as ``Financial-API``
— including ``images.`` and ``locate.`` — purely because the apex
contains the token "bank". The resulting HNDL multiplier (1.7) was then
applied fleet-wide, moving the whole estate a full posture tier. The
signal was the customer's brand, not the service.

Restricting the match to the labels the operator actually chose per host
(``ibanking``, ``upi``, ``images``) makes the classification a property of
the endpoint rather than of the domain it happens to live under, which is
the only way it can mean anything across different customers.
"""

import re


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
    # Generic retail-banking service vocabulary. These are ordinary industry
    # terms that recur across any bank's estate, not names taken from one
    # target — the point of the list is that it transfers to the next
    # customer unchanged.
    "payment": "Financial-API",
    "netbanking": "Financial-API",
    "upi":   "Financial-API",
    "creditcard": "Financial-API",
    "loan":  "Financial-API",
    "wallet": "Financial-API",
}

# Matching strictness scales with keyword length, because collision risk
# does. A 2-char key like "wg" fires inside "wgateway"; a 3-char key like
# "api" fires inside "rapid". Longer keys are specific enough that a bare
# substring test is safe and is what catches real compound service names
# ("ibanking", "netbanking") that no whole-label rule would ever match.
_WHOLE_LABEL_MAX_LEN: int = 2   # <=2 chars: whole label / delimited token only
_BOUNDARY_MAX_LEN: int = 3      # ==3 chars: must also align to a label edge

# Labels that identify no service and only add false-positive surface.
_IGNORED_LABELS: frozenset[str] = frozenset({"www"})

_TOKEN_SPLIT = re.compile(r"[-_0-9]+")


def _service_labels(hostname: str, target_domain: str | None = None) -> list[str]:
    """
    Return the subdomain labels below the registrable domain.

    When *target_domain* is known (the worker always has it — it is the
    domain the scan was submitted for) it is stripped exactly. Otherwise the
    last two labels are treated as the registrable domain, which is the
    correct guess for the common ``example.com`` shape and degrades safely
    for multi-label suffixes: it strips too little, never too much, so a
    keyword can still be found in a genuine service label.
    """
    host = (hostname or "").lower().strip().strip(".")
    if not host:
        return []

    if target_domain:
        apex = target_domain.lower().strip().strip(".")
        if host == apex:
            return []
        if apex and host.endswith("." + apex):
            host = host[: -(len(apex) + 1)]
            return [l for l in host.split(".") if l and l not in _IGNORED_LABELS]
        # Host is not under the scan target (CNAME chase, third-party CDN):
        # fall through to the generic rule rather than mis-stripping.

    labels = [l for l in host.split(".") if l]
    labels = labels[:-2] if len(labels) > 2 else []
    return [l for l in labels if l not in _IGNORED_LABELS]


def _keyword_matches(keyword: str, labels: list[str]) -> bool:
    """True when *keyword* identifies a service in any of *labels*."""
    for label in labels:
        if label == keyword:
            return True
        # A delimited token always counts, at every length: "api-gateway",
        # "pay_v2", "wg-1" are unambiguous however short the keyword is.
        if keyword in _TOKEN_SPLIT.split(label):
            return True
        if len(keyword) <= _WHOLE_LABEL_MAX_LEN:
            continue
        if len(keyword) <= _BOUNDARY_MAX_LEN:
            # Edge-aligned only: matches "apim" and "payments", not "rapid".
            if label.startswith(keyword) or label.endswith(keyword):
                return True
            continue
        if keyword in label:
            return True
    return False


def classify_service(hostname: str, port: int, target_domain: str | None = None) -> str:
    """
    Classify the service running on *hostname*:*port*.

    Classification priority:
        1. Well-known port mapping (most reliable).
        2. Hostname keyword matching on the subdomain labels only.

    Keywords are tested longest-first so a specific match wins over a
    substring of itself — without this, ``openvpn.example.com`` matched the
    shorter "vpn" key and was classified ``SSL-VPN`` (multiplier 1.8)
    instead of ``OpenVPN`` (2.0), because dict order decided the winner.

    Parameters
    ----------
    hostname : str
        The target hostname (e.g. ``vpn.bank.com``).
    port : int
        The target port number.
    target_domain : str, optional
        The domain the scan was submitted for. When given, it is stripped
        from *hostname* exactly, so the customer's own brand can never
        drive the classification. See the module docstring.

    Returns
    -------
    str
        A service-type label such as ``"OpenVPN"``, ``"HTTPS"``, ``"IMAPS"``, etc.

    Known limitation
    ----------------
    Within a subdomain label the match is still a substring test, so a label
    that merely embeds a keyword ("authors" contains "auth") can be
    misclassified. That is a bounded, per-host error; the apex leak this
    replaced was systematic and affected every host in a scan at once.
    """
    # 1. Exact port match
    service = PORT_MAP.get(port)

    # 2. Refine / override via keywords on the subdomain labels
    labels = _service_labels(hostname, target_domain)
    if labels:
        for keyword in sorted(KEYWORD_MAP, key=len, reverse=True):
            if _keyword_matches(keyword, labels):
                # Keyword match overrides only for generic ports (443 / unknown)
                if service is None or service == "HTTPS":
                    service = KEYWORD_MAP[keyword]
                break  # most specific match wins

    return service or "Unknown"
