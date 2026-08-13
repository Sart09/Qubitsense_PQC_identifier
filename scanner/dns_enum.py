"""
DNS enumeration module — Improved.
Provides brute-force subdomain discovery and DNS record mining.

Improvements over previous version:
- Expanded categorized wordlist (200+ banking/fintech-aware entries)
- Concurrent DNS resolution (100 workers vs sequential)
- A + AAAA dual-stack resolution (catches IPv6-only hosts)
- CNAME chain following (catches CDN-hosted subdomains)
- SOA + SRV record mining (was missing)
- SPF/DKIM/DMARC regex extraction from TXT records (was basic)
- SRV prefix scanning for service endpoints
"""

import os
import re
import socket
import sys
import time
import concurrent.futures
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (
    DEFINITIVE_NXDOMAIN as _DEFINITIVE_NXDOMAIN,
    DNS_BRUTEFORCE_CONCURRENCY,
)
import dns_cache

# ── Attempt to import dnspython ────────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False
    print("  [dns_enum] Warning: dnspython not installed. "
          "Install with: pip install dnspython")

# ══════════════════════════════════════════════════════════════════════
# WORDLIST — Categorized and Expanded (200+ entries)
# ══════════════════════════════════════════════════════════════════════

WORDLIST = [
    # ── Web Tier ──────────────────────────────────────────────────────
    "www", "web", "portal", "secure", "online", "home",
    "www2", "www3", "www4", "m", "mobile", "wap", "app", "apps",
    "site", "sites", "shop", "store", "ecommerce",

    # ── API Tier ──────────────────────────────────────────────────────
    "api", "api2", "api3", "api-v1", "api-v2", "api-v3", "apis",
    "rest", "restapi", "graphql", "grpc", "gateway", "apigw",
    "api-gateway", "services", "service", "microservice", "ms",
    "backend", "internal-api", "external-api", "public-api",
    "private-api", "partner-api", "open-api", "sandbox-api",
    "v1", "v2", "v3",

    # ── Auth / Identity ───────────────────────────────────────────────
    "auth", "auth2", "login", "signin", "signup", "logout",
    "sso", "oauth", "oauth2", "openid", "saml", "cas",
    "identity", "id", "ids", "idp", "iam", "mfa", "otp",
    "account", "accounts", "myaccount", "profile", "user", "users",
    "password", "reset", "verify", "verification",

    # ── Banking / Fintech Specific ─────────────────────────────────────
    "netbanking", "ibanking", "ebanking", "onlinebanking",
    "internetbanking", "mobilebanking", "homebanking",
    "payments", "payment", "pay", "payout", "payouts",
    "transaction", "transactions", "transfer", "transfers",
    "cards", "card", "credit", "creditcard", "debit", "debitcard",
    "prepaid", "virtual-card", "wallet", "ewallet", "upi",
    "neft", "rtgs", "imps", "swift", "ach", "sepa",
    "loans", "loan", "mortgage", "emi", "loanapp",
    "invest", "investment", "wealth", "trading", "forex",
    "insurance", "kyc", "aml", "compliance", "audit",
    "branch", "atm", "pos", "merchant", "acquiring",
    "clearing", "settlement", "reconciliation", "ledger",
    "treasury", "corporate", "retail", "sme", "msme",
    "rekyc", "rekycrrb", "vkyc", "pnbvkyc",
    "netc", "netcm2p", "npciservices",
    "pfms", "pfmsrrb", "cgps", "dpip", "dcms", "drms",

    # ── VPN / Remote Access (HNDL high-risk targets) ──────────────────
    "vpn", "vpn1", "vpn2", "vpn3", "vpngw", "vpn-gw",
    "remote", "remote-access", "ra", "ras", "ssl-vpn", "sslvpn",
    "citrix", "anyconnect", "globalprotect", "pulse", "ivanti",
    "rdp", "rdgateway", "rd-gateway", "rdweb", "jump",
    "jumphost", "jumpbox", "bastion", "ztna",
    "securedc", "securedr", "secureportal",

    # ── Mail Infrastructure ───────────────────────────────────────────
    "mail", "mail2", "mail3", "email", "webmail", "owa",
    "outlook", "exchange", "smtp", "smtp2", "smtpout",
    "pop", "pop3", "imap", "mx", "mx1", "mx2", "mxbackup",
    "relay", "mailrelay", "mailin", "mailout", "mailgw",
    "spam", "antispam", "filter", "mailfilter",
    "newsletter", "marketing", "bulk", "transactional",
    "mosmtp", "autodiscover",

    # ── CDN / Static / Media ──────────────────────────────────────────
    "cdn", "cdn2", "static", "static2", "assets", "asset",
    "media", "images", "img", "files", "downloads", "upload",
    "content", "resources", "res", "js", "css", "fonts",

    # ── Developer / Staging ───────────────────────────────────────────
    "dev", "dev2", "develop", "development",
    "staging", "stage", "stg", "uat", "qa", "test", "testing",
    "preprod", "pre-prod", "sandbox", "demo", "preview",
    "beta", "alpha", "canary", "pilot", "poc",
    "int", "integration", "lab", "labs",

    # ── Admin / Management ────────────────────────────────────────────
    "admin", "admin2", "administration", "manage", "management",
    "panel", "control", "controlpanel", "cp", "cpanel",
    "dashboard", "console", "backoffice", "back-office",
    "manager", "webadmin", "sysadmin", "ops", "operations",
    "helpdesk", "support", "crm", "erp", "cms",
    "intranet", "internal", "staff", "employee",
    "mdm", "mdcportal", "share",

    # ── Monitoring / Status ───────────────────────────────────────────
    "monitor", "monitoring", "status", "health", "healthcheck",
    "metrics", "grafana", "kibana", "elastic", "splunk",
    "prometheus", "logs", "logging", "log", "apm",

    # ── Security / PKI ────────────────────────────────────────────────
    "cert", "certs", "certificate", "pki", "ca", "rootca",
    "ocsp", "crl", "waf", "proxy", "proxy2", "firewall",
    "ids", "ips", "siem", "soc", "security", "sec",

    # ── Infrastructure / Cloud ────────────────────────────────────────
    "ns", "ns1", "ns2", "ns3", "ns4", "nameserver",
    "dns", "dns1", "dns2", "rdns",
    "ntp", "ldap", "ad", "dc", "dc1", "dc2",
    "db", "db1", "db2", "database", "sql", "cache",
    "storage", "backup", "archive", "dr",
    "k8s", "docker", "registry", "git", "gitlab",
    "ci", "cd", "jenkins", "build", "deploy",
    "soa", "tab", "kc",

    # ── Partner / Open API ────────────────────────────────────────────
    "partner", "partners", "vendor", "b2b", "b2c",
    "open", "openapi", "developer", "developers", "dev-portal",
    "webhook", "callback", "notify",
    "reporting", "report", "reports", "analytics", "bi",
    "data", "etl", "pipeline",

    # ── Regional ─────────────────────────────────────────────────────
    "us", "eu", "ap", "in", "uk", "sg", "au",
    "region1", "region2", "zone1", "zone2",
    "onboarding", "mypnb", "udaan",
]

# ══════════════════════════════════════════════════════════════════════
# SPF / DMARC REGEX PATTERNS
# ══════════════════════════════════════════════════════════════════════

SPF_PATTERNS = [
    r'include:([\w\.\-]+)',
    r'(?<!\w)a:([\w\.\-]+)',
    r'mx:([\w\.\-]+)',
    r'redirect=([\w\.\-]+)',
    r'ptr:([\w\.\-]+)',
]

DMARC_PATTERNS = [
    r'rua=mailto:[^@]+@([\w\.\-]+)',
    r'ruf=mailto:[^@]+@([\w\.\-]+)',
]

SRV_PREFIXES = [
    "_https._tcp", "_http._tcp", "_sip._tcp", "_sip._udp",
    "_ldap._tcp", "_kerberos._tcp", "_imaps._tcp",
    "_submission._tcp", "_autodiscover._tcp",
]


# ══════════════════════════════════════════════════════════════════════
# CORE RESOLUTION — A + AAAA + CNAME
# ══════════════════════════════════════════════════════════════════════

def resolve_subdomain(
    subdomain: str,
    domain: str
) -> tuple[str, list[str], Optional[str]]:
    """
    Resolve a single subdomain. Checks A → AAAA → CNAME in order.

    Returns
    -------
    tuple[hostname, ip_list, cname_or_none]
    """
    # Cached definitive answers only — see scanner/dns_cache.py. This is
    # what makes a rescan cheap AND repeatable: the second scan of a domain
    # does not re-interrogate an already-saturated resolver.
    cached = dns_cache.get(f"sub:{subdomain}")
    if cached is not dns_cache.MISS:
        ips, cname = cached
        return subdomain, list(ips), cname, False

    ips: list[str] = []
    cname: Optional[str] = None
    # True when the resolver never gave a definitive answer. Distinct from
    # "no IPs": one means "this name does not exist", the other means "we
    # could not find out". Reported by the caller instead of vanishing.
    inconclusive = False

    if DNSPYTHON_AVAILABLE:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        # A record (IPv4). NXDOMAIN/NoAnswer are the resolver telling us the
        # name is not there — a real answer. Timeout/SERVFAIL/NoNameservers
        # are the resolver failing to answer at all, which used to land in
        # the same `pass` and silently drop the candidate. At 100 concurrent
        # workers the resolver saturates and produces exactly those, which
        # is why brute-force yield drifted run to run on identical input.
        for attempt in range(2):
            try:
                answers = resolver.resolve(subdomain, "A")
                ips = [str(r) for r in answers]
                break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break  # Definitive: this name has no A record.
            except (dns.exception.Timeout,
                    dns.resolver.NoNameservers,
                    dns.resolver.LifetimeTimeout):
                inconclusive = True
                if attempt == 0:
                    time.sleep(0.2)
                    continue
            except Exception:
                inconclusive = True
                break

        # AAAA fallback (IPv6) — catches IPv6-only cloud hosts
        if not ips:
            try:
                answers = resolver.resolve(subdomain, "AAAA")
                ips = [str(r) for r in answers]
                inconclusive = False
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception:
                inconclusive = True

        # CNAME — catches CDN-fronted subdomains
        try:
            cname_ans = resolver.resolve(subdomain, "CNAME")
            cname = str(cname_ans[0].target).rstrip(".").lower()
        except Exception:
            pass

    else:
        # Fallback: socket if dnspython unavailable
        try:
            info = socket.getaddrinfo(
                subdomain, None,
                socket.AF_INET, socket.SOCK_STREAM
            )
            ips = list({i[4][0] for i in info})
        except socket.gaierror as exc:
            # Same NXDOMAIN-vs-resolver-failure split as the ghost filter;
            # see _DEFINITIVE_NXDOMAIN in scanner/domain_discovery.py.
            if exc.errno not in _DEFINITIVE_NXDOMAIN:
                inconclusive = True
        except Exception:
            inconclusive = True
        try:
            info6 = socket.getaddrinfo(
                subdomain, None,
                socket.AF_INET6, socket.SOCK_STREAM
            )
            if not ips:
                ips = list({i[4][0] for i in info6})
                inconclusive = False
        except socket.gaierror as exc:
            if exc.errno not in _DEFINITIVE_NXDOMAIN:
                inconclusive = True
        except Exception:
            inconclusive = True

    # Store only when the resolver actually answered. An inconclusive result
    # must stay uncached so the next attempt gets a real chance.
    if not inconclusive:
        dns_cache.put(f"sub:{subdomain}", (tuple(ips), cname))

    return subdomain, ips, cname, inconclusive


def extract_hosts_from_txt(txt_value: str, domain: str) -> list[str]:
    """Extract hostnames from SPF / DKIM / DMARC TXT record values."""
    hosts: list[str] = []
    for pattern in SPF_PATTERNS + DMARC_PATTERNS:
        for match in re.findall(pattern, txt_value, re.IGNORECASE):
            clean = match.lower().rstrip(".")
            if clean.endswith(domain) and not clean.startswith("*"):
                hosts.append(clean)
    return hosts


# ══════════════════════════════════════════════════════════════════════
# TECHNIQUE 1 — DNS BRUTE FORCE (Concurrent, with CNAME following)
# ══════════════════════════════════════════════════════════════════════

def dns_bruteforce(domain: str,
                   max_workers: int = DNS_BRUTEFORCE_CONCURRENCY) -> list[str]:
    """
    Concurrent DNS brute force with CNAME chain following.
    Uses 100 workers (up from previous sequential implementation).

    Parameters
    ----------
    domain : str
        The parent domain to scan.
    max_workers : int
        Number of concurrent DNS resolution threads.

    Returns
    -------
    list[str]
        All discovered hostnames including CNAME follow-up targets.
    """
    candidates = {f"{word}.{domain}" for word in WORDLIST}
    discovered: set[str] = set()
    cname_followups: set[str] = set()
    # Candidates the resolver never gave a verdict on. Unlike the ghost
    # filter these are NOT kept — a wordlist guess has no evidence behind
    # it, so failing open would inject hundreds of nonexistent hosts. They
    # are counted and reported instead of disappearing silently.
    unresolved: set[str] = set()

    print(f"  [dns_enum] Brute forcing {len(candidates)} candidates "
          f"with {max_workers} workers...", flush=True)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
        futures = {
            executor.submit(resolve_subdomain, candidate, domain): candidate
            for candidate in candidates
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                hostname, ips, cname, inconclusive = future.result()
                if ips:
                    discovered.add(hostname)
                    # Follow CNAME if within same domain
                    if (cname
                            and cname.endswith(f".{domain}")
                            and cname not in candidates
                            and cname not in discovered):
                        cname_followups.add(cname)
                elif inconclusive:
                    unresolved.add(hostname)
            except Exception:
                pass

    # Second pass — resolve CNAME targets
    if cname_followups:
        print(f"  [dns_enum] Following {len(cname_followups)} "
              f"CNAME targets...", flush=True)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=DNS_BRUTEFORCE_CONCURRENCY
        ) as executor:
            futures = {
                executor.submit(resolve_subdomain, host, domain): host
                for host in cname_followups
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    hostname, ips, _, inconclusive = future.result()
                    if ips:
                        discovered.add(hostname)
                    elif inconclusive:
                        unresolved.add(hostname)
                except Exception:
                    pass

    print(f"  [dns_enum] Brute force discovered {len(discovered)} "
          f"live hosts", flush=True)
    if unresolved:
        # Visible rather than silent: this is the number that explains why
        # brute-force yield differs between two runs over identical input.
        print(f"  [dns_enum] ⚠ {len(unresolved)} candidate(s) inconclusive "
              f"(resolver timeout/SERVFAIL, not NXDOMAIN) — brute-force yield "
              f"is a lower bound for this run", flush=True)
    return sorted(discovered)


# ══════════════════════════════════════════════════════════════════════
# TECHNIQUE 2 — DNS RECORD MINING
# ══════════════════════════════════════════════════════════════════════

def dns_records(domain: str) -> list[str]:
    """
    Mine MX, NS, TXT, SOA, SRV DNS records for hostnames.
    Extracts SPF / DKIM / DMARC directives from TXT records.
    Scans SRV prefixes for service endpoints.

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

    if not DNSPYTHON_AVAILABLE:
        print("  [dns_enum] Skipping DNS record mining "
              "(dnspython not installed)", flush=True)
        return []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3

    # ── Standard record types + SOA ───────────────────────────────────
    for rtype in ["MX", "NS", "TXT", "SOA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                rdata_str = str(rdata).lower()

                if rtype == "MX":
                    parts = rdata_str.split()
                    if len(parts) >= 2:
                        host = parts[1].rstrip(".")
                        if host.endswith(domain):
                            hosts.add(host)

                elif rtype == "NS":
                    host = rdata_str.rstrip(".")
                    if host.endswith(domain):
                        hosts.add(host)

                elif rtype == "SOA":
                    # First token is the primary nameserver
                    host = rdata_str.split()[0].rstrip(".")
                    if host.endswith(domain):
                        hosts.add(host)

                elif rtype == "TXT":
                    clean = rdata_str.strip('"')
                    # Basic include: extraction (backward compat)
                    for token in clean.split():
                        if token.startswith("include:"):
                            h = token.split(":", 1)[1].strip('"')
                            if h and h.endswith(domain):
                                hosts.add(h)
                    # Full SPF/DMARC regex extraction
                    for h in extract_hosts_from_txt(clean, domain):
                        hosts.add(h)

        except (dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout):
            pass
        except Exception as e:
            print(f"  [dns_enum] {rtype} query failed: {e}", flush=True)

    # ── SRV record mining ─────────────────────────────────────────────
    for prefix in SRV_PREFIXES:
        try:
            answers = resolver.resolve(f"{prefix}.{domain}", "SRV")
            for rdata in answers:
                parts = str(rdata).lower().split()
                if len(parts) >= 4:
                    host = parts[3].rstrip(".")
                    if host.endswith(domain):
                        hosts.add(host)
        except Exception:
            pass

    # ── Domain-level SRV ──────────────────────────────────────────────
    try:
        answers = resolver.resolve(domain, "SRV")
        for rdata in answers:
            parts = str(rdata).lower().split()
            if len(parts) >= 4:
                host = parts[3].rstrip(".")
                if host.endswith(domain):
                    hosts.add(host)
    except Exception:
        pass

    print(f"  [dns_enum] DNS record mining found "
          f"{len(hosts)} hosts", flush=True)
    return sorted(hosts)
