"""
DNS enumeration module.
Provides brute-force subdomain discovery and DNS record mining.
"""

import socket


# Common subdomain prefixes for brute-force enumeration.
WORDLIST = [
    "www", "api", "mail", "login", "vpn",
    "portal", "admin", "dev", "test", "staging",
    "beta", "app", "ftp", "smtp", "pop",
    "imap", "ns1", "ns2", "mx", "webmail",
]


def dns_bruteforce(domain: str) -> list[str]:
    """
    Attempt to resolve ``{word}.{domain}`` for each word in the wordlist.

    Parameters
    ----------
    domain : str
        The parent domain (e.g. ``example.com``).

    Returns
    -------
    list[str]
        Only hostnames that successfully resolve.
    """
    found: list[str] = []

    for prefix in WORDLIST:
        candidate = f"{prefix}.{domain}"
        try:
            socket.getaddrinfo(candidate, None, socket.AF_INET, socket.SOCK_STREAM)
            found.append(candidate)
        except socket.gaierror:
            pass
        except Exception:
            pass

    return found


def dns_records(domain: str) -> list[str]:
    """
    Mine MX, NS, and TXT DNS records for additional hostnames.

    Uses the ``socket`` module for basic lookups and parses TXT records
    for embedded hostnames. For MX/NS queries we fall back to
    ``dns.resolver`` if available, otherwise skip gracefully.

    Parameters
    ----------
    domain : str
        The parent domain to query.

    Returns
    -------
    list[str]
        Hostnames extracted from DNS records.
    """
    hosts: set[str] = set()

    try:
        import dns.resolver  # type: ignore

        # MX records
        try:
            for rdata in dns.resolver.resolve(domain, "MX"):
                mx_host = str(rdata.exchange).rstrip(".").lower()
                if mx_host:
                    hosts.add(mx_host)
        except Exception:
            pass

        # NS records
        try:
            for rdata in dns.resolver.resolve(domain, "NS"):
                ns_host = str(rdata.target).rstrip(".").lower()
                if ns_host:
                    hosts.add(ns_host)
        except Exception:
            pass

        # TXT records — look for hostnames embedded in SPF, DKIM, etc.
        try:
            for rdata in dns.resolver.resolve(domain, "TXT"):
                txt = str(rdata).lower()
                # Extract "include:hostname" patterns from SPF
                for token in txt.split():
                    if token.startswith("include:"):
                        h = token.split(":", 1)[1].strip('"')
                        if h:
                            hosts.add(h)
        except Exception:
            pass

    except ImportError:
        # dnspython not installed — skip advanced record mining
        print("  [dns_enum] Note: dnspython not installed, skipping MX/NS/TXT mining")

    return sorted(hosts)
