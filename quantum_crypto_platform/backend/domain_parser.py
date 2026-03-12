"""
Domain parsing and normalization module.
Accepts raw domains or full URLs and extracts clean hostnames.
"""

from urllib.parse import urlparse
import re
from models import DomainInfo



def parse_domain(target: str) -> DomainInfo:
    """
    Parse a target string into a clean hostname and parent domain.

    Examples
    --------
    >>> parse_domain("https://login.bank.com/mobile")
    DomainInfo(host='login.bank.com', parent_domain='bank.com')

    >>> parse_domain("example.com")
    DomainInfo(host='example.com', parent_domain='example.com')
    """
    target = target.strip()

    # If there is no scheme, urlparse puts everything in the path component.
    # Prepend a scheme so we can reliably extract the hostname.
    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)
    host = (parsed.hostname or "").lower().strip(".")

    if not host or not re.match(r"^[a-z0-9.-]+$", host):
        raise ValueError(f"Could not extract a valid hostname from the input.")

    # Derive the parent domain (last two labels, e.g. login.bank.com -> bank.com)
    labels = host.split(".")
    if len(labels) >= 2:
        parent_domain = ".".join(labels[-2:])
    else:
        parent_domain = host

    return DomainInfo(host=host, parent_domain=parent_domain)
