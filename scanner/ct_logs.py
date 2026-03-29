"""
Certificate Transparency log discovery.
Queries the crt.sh public API to find subdomains from issued certificates.
"""

import urllib.request
import json
import re


def discover_from_ct(domain: str) -> list[str]:
    """
    Query crt.sh for certificates matching ``*.domain`` and extract hostnames.

    Parameters
    ----------
    domain : str
        The parent domain to search (e.g. ``example.com``).

    Returns
    -------
    list[str]
        Deduplicated list of discovered hostnames.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    hosts: set[str] = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "QuantumCryptoPlatform/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        for entry in data:
            # name_value can contain multiple hostnames separated by newlines
            for field in ("name_value", "common_name"):
                raw = entry.get(field, "")
                for name in raw.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and name.endswith(domain) and _is_valid_hostname(name):
                        hosts.add(name)

    except Exception as exc:
        print(f"  [ct_logs] Warning: crt.sh query failed: {exc}")

    return sorted(hosts)


def _is_valid_hostname(name: str) -> bool:
    """Basic check that a string looks like a hostname."""
    return bool(re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", name))
