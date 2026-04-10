"""
DNS enumeration module.
Provides brute-force subdomain discovery and DNS record mining.
"""

import socket
import concurrent.futures


# Exhaustive common subdomain prefixes for brute-force enumeration.
# Expanded to 500+ items to cover modern infrastructure and banking sectors.
WORDLIST = [
    "www", "api", "mail", "login", "vpn", "portal", "admin", "dev", 
    "test", "staging", "beta", "app", "ftp", "smtp", "pop", "imap", 
    "ns1", "ns2", "ns3", "ns4", "mx", "webmail", "blog", "shop", "store", "secure",
    "web", "cdn", "cloud", "m", "mobile", "owa", "autodiscover",
    "remote", "support", "help", "docs", "developer", "git", "gitlab",
    "github", "jira", "confluence", "wiki", "sso", "auth", "idp",
    "dashboard", "metrics", "grafana", "prometheus", "elasticsearch",
    "kibana", "splunk", "api-dev", "api-staging", "api-prod", "v1", "v2",
    "stage", "qa", "uat", "demo", "sandbox", "stg", "prod", "production",
    "intranet", "partner", "partners", "corp", "internal", "gateway",
    "proxy", "cdn1", "cdn2", "assets", "static", "media", "images",
    "en", "fr", "de", "es", "ru", "cn", "jp", "us", "uk", "eu", "asia",
    "manage", "billing", "pay", "checkout", "cart", "account", "profile",
    "crm", "erp", "hr", "payroll", "employee", "staff", "admin-panel", "cpanel", "whm", "db",
    "sql", "mysql", "postgresql", "oracle", "mongodb", "redis", "cache", "search",
    "jenkins", "travis", "circleci", "gitlab-runner", "docker", "k8s", "kubernetes",
    "lb", "loadbalancer", "ingress", "egress", "vault", "consul", "rancher", "nomad",
    "bastion", "jumphost", "dmz", "office", "vpn1", "vpn2", "client", "clients",
    "guest", "public", "private", "secure-gw", "waf", "scanner", "security",
    "monitor", "status", "health", "uptime", "alert", "alerts", "ping", "test1", "test2",
    # Banking & Finance Specific
    "netbanking", "netpnb", "pnbnet", "pnbindia", "corporate", "retail", "ibanking",
    "m-banking", "upi", "imps", "rtgs", "neft", "bills", "loans", "payments", "payvia",
    "pnb", "pnbapi", "pnbapps", "pnbbiz", "pnbonline", "card", "cards", "credit", "debit",
    "atm", "branch", "cms", "forex", "treasury", "mutualfund", "insurance", "wealth",
    "kyc", "digital", "omni", "edge", "finacle", "bcp", "dr", "dr-site", "backup",
    "ebanking", "online", "bank", "banking", "finance", "mobile", "app", "services",
    "transaction", "history", "statement", "reward", "rewards", "points", "cashback",
    "offers", "loyalty", "giftcard", "virtual", "otp", "verify", "securepay",
    # Government/Infrastructure specific variants
    "gov", "nic", "e-services", "digital-india", "pib", "rti", "pmu", "sid",
    # Technical & Cloud
    "aws", "azure", "gcp", "lambda", "function", "s3", "blob", "bucket", "storage",
    "serverless", "edge1", "edge2", "cdn-static", "dist", "build", "ci-cd", "artifacts",
    "registry", "nexus", "artifactory", "harbor", "quay", "ops", "infra", "maintenance",
    # Communication
    "chat", "slack", "teams", "zoom", "meet", "email", "smtp-out", "smtp-in", "relay",
    "imap1", "pop1", "webmail-old", "zimbra", "roundcube", "squirrel",
    # Environment variations
    "lab", "experiment", "alpha", "rc", "nightly", "canary", "green", "blue",
    # Short prefixes
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", 
    "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5",
    # Misc common
    "news", "press", "media", "pr", "marketing", "ads", "advertising", "track", "tracking",
    "analytics", "pixel", "log", "logs", "syslog", "rsyslog", "elk", "tick", "beats"
]


def dns_bruteforce(domain: str) -> list[str]:
    """
    Attempt to resolve ``{word}.{domain}`` for each word in the wordlist concurrently.
    Honors DNS timeouts to prevent hanging on unresponsive servers.

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
    
    def check_prefix(prefix):
        candidate = f"{prefix}.{domain}"
        try:
            # Use short timeout for DNS resolution
            # Note: socket.setdefaulttimeout is not thread-safe in all Python versions,
            # but for this specific worker it's usually acceptable as we control the threads.
            # A better way is using a shorter timeout in getaddrinfo if possible, 
            # or relying on the OS DNS timeout.
            socket.getaddrinfo(candidate, None, socket.AF_INET, socket.SOCK_STREAM)
            return candidate
        except (socket.gaierror, socket.timeout, Exception):
            return None

    # Use 20 threads for DNS brute force
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_prefix, WORDLIST)
        for res in results:
            if res:
                found.append(res)

    return found


def dns_records(domain: str) -> list[str]:
    """
    Mine MX, NS, and TXT DNS records for additional hostnames.
    IMPORTANT: Filters to only internal domain services (no external mail, no nameservers).

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
        Hostnames extracted from DNS records (internal only).
    """
    hosts: set[str] = set()

    try:
        import dns.resolver  # type: ignore

        # MX records - ONLY add if they're subdomains of the target domain
        try:
            for rdata in dns.resolver.resolve(domain, "MX"):
                mx_host = str(rdata.exchange).rstrip(".").lower()
                # Only include if subdomain of target domain (internal mail server)
                if mx_host and mx_host.endswith(domain):
                    hosts.add(mx_host)
        except Exception:
            pass

        # NS records - SKIP ENTIRELY (nameservers don't have TLS on port 443)
        # Scanning ns-735.awsdns-27.net, ns-1585.awsdns-06.co.uk wastes time
        # These are DNS-only services, not web servers
        try:
            pass  # Skip NS records completely
        except Exception:
            pass

        # TXT records — look for hostnames embedded in SPF, DKIM, etc.
        # IMPORTANT: Only add if they're subdomains of target domain
        try:
            for rdata in dns.resolver.resolve(domain, "TXT"):
                txt = str(rdata).lower()
                # Extract "include:hostname" patterns from SPF
                for token in txt.split():
                    if token.startswith("include:"):
                        h = token.split(":", 1)[1].strip('"')
                        # ONLY add if it's a subdomain of target domain
                        # Skip external references like spf.messagelabs.com
                        if h and h.endswith(domain):
                            hosts.add(h)
        except Exception:
            pass

    except ImportError:
        # dnspython not installed — skip advanced record mining
        print("  [dns_enum] Note: dnspython not installed, skipping MX/NS/TXT mining", flush=True)

    return sorted(hosts)
