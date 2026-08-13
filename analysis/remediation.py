"""
Per-host remediation recommendations — one source of truth shared by the
GET /asset/{id} JSON endpoint and the per-host remediation PDF export, so
the two can never drift into disagreeing about what a host should fix.

Extracted unchanged from backend/server.py's former inline logic: driven
by which of THIS host's score components are actually elevated, ordered by
weighted impact (key exchange and signature — the two heaviest-weighted,
most Shor-breakable components — first), not a fixed list shown identically
for every asset regardless of its real weaknesses.
"""


def build_recommendations(b: dict, tls_row) -> list[str]:
    """
    Parameters
    ----------
    b : dict
        The ``breakdown`` dict from ``calculate_quantum_risk(...)["breakdown"]``
        (raw 0-100 per-component scores).
    tls_row : sqlite3.Row | dict
        The ``tls_results`` row for this host — needs ``is_expired``,
        ``days_until_expiry``, ``is_self_signed``, ``hostname_mismatch``.
    """
    recommendations: list[str] = []
    if b["key_exchange"] >= 60:
        recommendations.append("Migrate key exchange to ML-KEM-768 (hybrid) — classical-only key exchange in use")
    if b["signature"] >= 60:
        recommendations.append("Migrate certificate signature to ML-DSA-65 — classical-only signature algorithm in use")
    if b["key_size"] >= 60:
        recommendations.append("Increase key size — current key length is below recommended strength")
    if b["forward_secrecy"] >= 60:
        recommendations.append("Enable forward secrecy (ECDHE) — without it one recovered key decrypts all captured sessions")
    if b["tls_version"] >= 50:
        recommendations.append("Upgrade to TLS 1.3 — outdated protocol version in use")
    if b["cipher"] >= 40:
        recommendations.append("Move bulk encryption to AES-256 or ChaCha20 — Grover halves symmetric key strength")
    if b["cipher_mode"] >= 60:
        recommendations.append("Switch to an AEAD cipher mode (GCM/ChaCha20-Poly1305) — CBC/CTR modes are padding-oracle prone")
    if b["hash"] >= 60:
        recommendations.append("Replace SHA-1/MD5 hashing — collision attacks are practical today, no quantum computer required")
    if tls_row["is_expired"]:
        recommendations.append("Renew certificate immediately — it has already expired")
    elif tls_row["days_until_expiry"] is not None and tls_row["days_until_expiry"] < 30:
        recommendations.append(f"Renew certificate soon — expires in {tls_row['days_until_expiry']} days")
    elif b["certificate"] >= 55:
        recommendations.append("Shorten certificate lifetime toward the 398-day maximum — long-lived certs slow PQC rotation")
    if tls_row["is_self_signed"]:
        recommendations.append("Replace self-signed certificate with one from a trusted CA")
    if tls_row["hostname_mismatch"]:
        recommendations.append("Investigate hostname/certificate mismatch — may indicate misconfiguration or shadow IT")
    if not recommendations:
        recommendations.append("No immediate action required — this asset's cryptographic posture is within acceptable bounds")
    return recommendations
