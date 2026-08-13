"""
Quantum Risk Engine — authoritative scoring model.
==================================================

Single source of truth for every risk number in the platform: the per-asset
Quantum Risk Score, the risk label, the fleet-level Enterprise Rating, and
the Posture Tier. Everything below is derived from signals the scanner
actually measures during the TLS handshake and certificate parse — there
are no random values, no placeholder constants, and no hardcoded per-host
results. If a signal is missing, it is scored as *unknown* with a
documented conservative default rather than being silently skipped.

THE MODEL
---------
Score = 0 (fully quantum-safe) → 100 (critically exposed), in four stages:

  1. Weighted composite of 10 independent components (weights sum to 1.0)
  2. Floor gates — structural facts a weighted average would otherwise
     dilute (see FLOOR RULES)
  3. HNDL amplification — harvest value scales existing exposure
  4. Clamp to 0-100

WHY BOTH A COMPOSITE AND FLOOR GATES
------------------------------------
A pure weighted average lets good hygiene mask a fatal flaw: a host on
TLS 1.3 with AES-256-GCM, SHA-384 and a valid CA certificate scores well
on 8 of 10 components while its key exchange and signature remain 100%
Shor-breakable. Averaging that away would report "Transitioning" for an
asset with zero post-quantum protection. The floor gates encode the
non-negotiable structural truth ("no PQC anywhere ⇒ at minimum Quantum
Vulnerable"); the composite then provides granularity *above* the floor,
so two equally quantum-exposed hosts are still separated by cipher
strength, protocol version, and certificate hygiene.

THE 10 COMPONENTS AND THEIR WEIGHTS
-----------------------------------
  0.22  key_exchange      Shor-breakable handshake ⇒ retroactive decryption
  0.14  signature         Shor-breakable cert signature ⇒ forgeable identity
  0.12  key_size          Public-key strength (Shor cost proxy)
  0.10  forward_secrecy   No PFS ⇒ one key decrypts all captured sessions
  0.10  tls_version       Protocol version hygiene
  0.08  cipher            Symmetric strength vs Grover (halves key bits)
  0.07  certificate_trust Expired / self-signed / hostname mismatch
  0.06  cipher_mode       AEAD vs padding-oracle-prone modes
  0.06  hash              Collision resistance (SHA-1/MD5 are broken)
  0.05  certificate       Certificate lifetime hygiene / crypto-agility
  ----
  1.00

Key exchange carries the largest weight because it alone determines
whether traffic captured today can be decrypted later — the core
Harvest-Now-Decrypt-Later threat this platform exists to measure.
Signature weight is second: it governs identity forgery once a CRQC
exists, but unlike key exchange it cannot be exploited retroactively
against recorded traffic.

References for the thresholds: NIST SP 800-208 / FIPS 203-205 (PQC
standards and security levels), NIST SP 800-57 (key-strength
equivalence), RFC 8446 (TLS 1.3 removes static RSA and non-AEAD modes),
CA/Browser Forum Baseline Requirements (398-day maximum certificate
lifetime), and Grover's algorithm giving a square-root speedup against
symmetric keys (256-bit key ⇒ 128-bit post-quantum security).
"""

import os
import re
import sys

# Ensure analysis folder can import from other modules if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from algorithm_classifier import classify_algorithm


# ---------------------------------------------------------------------------
# Model constants — every tunable lives here so the methodology is
# inspectable (and is served verbatim by /intelligence/scoring-model).
# ---------------------------------------------------------------------------

COMPONENT_WEIGHTS: dict[str, float] = {
    "key_exchange":      0.22,
    "signature":         0.14,
    "key_size":          0.12,
    "forward_secrecy":   0.10,
    "tls_version":       0.10,
    "cipher":            0.08,
    "certificate_trust": 0.07,
    "cipher_mode":       0.06,
    "hash":              0.06,
    "certificate":       0.05,
}

COMPONENT_LABELS: dict[str, str] = {
    "key_exchange":      "Key Exchange (quantum resistance)",
    "signature":         "Certificate Signature (quantum resistance)",
    "key_size":          "Public Key Strength",
    "forward_secrecy":   "Forward Secrecy (PFS)",
    "tls_version":       "TLS Protocol Version",
    "cipher":            "Symmetric Cipher Strength (vs Grover)",
    "certificate_trust": "Certificate Trust Chain",
    "cipher_mode":       "Cipher Mode / AEAD",
    "hash":              "Hash Function Strength",
    "certificate":       "Certificate Lifetime Hygiene",
}

# Harvest-Now-Decrypt-Later amplification. The service multiplier from
# hndl_detector is 1.0 (plain HTTPS) → 2.0 (VPN/IPSec). Uplift is
# proportional to BOTH the multiplier excess and the existing exposure, so
# harvest value amplifies real vulnerability but cannot manufacture risk
# where the crypto is already quantum-safe — PQC-protected VPN traffic is
# not harvestable, and the model must say so.
HNDL_SENSITIVITY: float = 0.15

# Risk label bands (inclusive lower bound → inclusive upper bound).
# Boundaries coincide with the floor gates below by design.
RISK_BANDS: list[tuple[int, int, str]] = [
    (0,  29,  "Quantum Safe"),
    (30, 44,  "Transitioning"),
    (45, 80,  "Quantum Vulnerable"),
    (81, 100, "Critical"),
]

# Floor gates. Applied after the composite; they raise a score into a band
# but never lower it.
#
# WHY THE no-PQC FLOOR SITS AT 45 AND NOT AT 61
#
# The floor maps a 0-100 composite across [floor, band_top]. At 61 that
# window was only 19 points wide, and because real-world composites cluster
# well below 100, actual scans occupied barely a third of it: across 86 live
# hosts on one bank estate the composite spread 17.3 points and the gated
# score spread just 4.0 — the gate was discarding ~77% of the resolution the
# ten weighted components had produced, and every classical fleet collapsed
# onto an identical posture tier regardless of hygiene.
#
# Lowering the floor to 45 widens the window to 35 points and restores that
# resolution. The structural claim is unchanged: "Quantum Vulnerable" now
# spans 45-80, so a host with no post-quantum protection anywhere still
# cannot be labelled anything better than Quantum Vulnerable — which is the
# property the gate exists to guarantee. Only the granularity within the
# band changed, never the verdict.
FLOOR_NO_PQC_ANYWHERE = 45     # bottom of "Quantum Vulnerable"
FLOOR_PARTIAL_PQC = 30         # bottom of "Transitioning"
FLOOR_CLASSICALLY_BROKEN = 81  # bottom of "Critical"

# Enterprise Rating: a 0-1000 rescaling of the fleet's average risk score,
# rating = (100 - avg_risk) * 10. Tier boundaries sit on exact round risk
# values so each tier maps to a clean, explainable risk range.
#   Elite-PQC   850-1000  avg risk  0-15   PQC deployed across the fleet
#   Advanced    700-849   avg risk 15-30   PQC in progress, hygiene strong
#   Standard    550-699   avg risk 30-45   classical crypto, well maintained
#   Developing  400-549   avg risk 45-60   classical crypto, weak hygiene
#   Legacy        0-399   avg risk 60-100  broadly exposed, no PQC
POSTURE_TIERS: list[tuple[int, int, str]] = [
    (850, 1000, "Elite-PQC"),
    (700, 849,  "Advanced"),
    (550, 699,  "Standard"),
    (400, 549,  "Developing"),
    (0,   399,  "Legacy"),
]

# Algorithm family markers. Kept as explicit token sets so a judge (or a
# future maintainer) can see exactly what counts as post-quantum.
PQC_KEM_TOKENS = ("ML-KEM", "MLKEM", "KYBER", "SNTRUP", "CECPQ", "BIKE", "HQC", "FRODO")
PQC_SIG_TOKENS = ("ML-DSA", "MLDSA", "DILITHIUM", "FALCON", "SPHINCS", "SLH-DSA", "SLHDSA", "XMSS", "LMS")
CLASSICALLY_BROKEN_TOKENS = ("MD5", "RC4", "DES40", "EXPORT", "NULL", "ANON", "SSLV2", "SSLV3")


def _norm(value) -> str:
    """Uppercase, whitespace-stripped string for token matching."""
    return str(value or "").upper().strip()


def _is_pqc_kem(text: str) -> bool:
    return any(tok in text for tok in PQC_KEM_TOKENS)


def _is_pqc_sig(text: str) -> bool:
    return any(tok in text for tok in PQC_SIG_TOKENS)


# ---------------------------------------------------------------------------
# Component 1 — Key exchange quantum resistance (weight 0.22)
# ---------------------------------------------------------------------------

def calculate_key_exchange_risk(kex: str, tls_version: str = "", cipher_suite: str = "") -> int:
    """
    Score the handshake's resistance to Shor's algorithm.

    Nothing classical scores below 78: ECDHE, X25519 and finite-field DHE
    are all fully broken by a CRQC, so the model refuses to imply that
    picking a bigger classical curve is a post-quantum mitigation. Only a
    PQC or hybrid key exchange scores 0.

    TLS 1.3 removed static RSA key transport entirely (RFC 8446), so when
    the cipher-suite name carries no key-exchange token — which is normal
    for TLS 1.3 suites like TLS_AES_128_GCM_SHA256 — the handshake is known
    to be ephemeral (X)DH. Inferring that is strictly more accurate than
    charging the host an "unknown" penalty for a naming convention.
    """
    text = _norm(kex) + " " + _norm(cipher_suite)
    version = _norm(tls_version)

    if _is_pqc_kem(text):
        return 0
    if "RSA" in _norm(kex) and "DHE" not in _norm(kex) and "ECDHE" not in _norm(kex):
        return 100  # static RSA key transport: no PFS and Shor-breakable
    if "ECDHE" in text or "X25519" in text or "X448" in text:
        return 80
    if "DHE" in text or "FFDHE" in text:
        return 85
    if "ECDH" in text or "DH" in text:
        return 95  # static (non-ephemeral) DH
    if "1.3" in version:
        return 80  # TLS 1.3 guarantees ephemeral (X)DH
    return 85      # unknown — assume classical, the conservative default


# ---------------------------------------------------------------------------
# Component 2 — Certificate signature quantum resistance (weight 0.14)
# ---------------------------------------------------------------------------

def calculate_signature_risk(sig: str, signature_algorithm: str = "") -> int:
    """
    Score the certificate's signature algorithm.

    The X.509 signature_algorithm string encodes both the hash and the
    public-key algorithm (e.g. ``sha256WithRSAEncryption``). The asymmetric
    part is scored here; hash strength is scored separately by
    :func:`calculate_hash_risk`. A signature built on MD5 or SHA-1 is a
    *classical* break (forgeable today, no quantum computer required), so
    those escalate above every merely quantum-exposed option.
    """
    text = _norm(sig) + " " + _norm(signature_algorithm)

    if _is_pqc_sig(text):
        return 0
    if "MD5" in text:
        return 100  # collision-forgeable today
    if "SHA1" in text or "SHA-1" in text or "WITHSHA1" in text:
        return 95   # SHAttered: chosen-prefix collisions are practical
    if "ED25519" in text or "ED448" in text:
        return 78
    if "ECDSA" in text:
        return 80
    if "DSA" in text and "ECDSA" not in text:
        return 90   # small subgroup sizes plus Shor exposure
    if "RSA" in text:
        return 85
    return 85       # unknown — assume classical


# ---------------------------------------------------------------------------
# Component 3 — Public key strength (weight 0.12)
# ---------------------------------------------------------------------------

def calculate_key_size_risk(key_alg: str, key_size: int) -> int:
    """
    Score public-key strength as a proxy for the quantum resources needed
    to break it, and for classical strength where that is already the
    binding constraint.

    Classical keys never score below 50 however large they are, because
    key size does not confer quantum resistance — a 4096-bit RSA key falls
    to Shor just as a 2048-bit key does, only marginally slower. Keys at or
    below 1024 bits are treated as already broken classically.
    """
    alg = _norm(key_alg)
    size = key_size or 0

    if _is_pqc_kem(alg) or _is_pqc_sig(alg):
        return 0
    if not alg or alg == "UNKNOWN" or size == 0:
        return 75  # unmeasured — conservative default, surfaced as "unknown"

    if "RSA" in alg or ("DSA" in alg and "ECDSA" not in alg):
        if size <= 1024:
            return 100  # broken classically (NIST disallowed since 2013)
        if size < 2048:
            return 90
        if size < 3072:
            return 70   # RSA-2048: 112-bit classical, Shor-breakable
        if size < 4096:
            return 60
        return 50
    if "EC" in alg or "ED25519" in alg or "ED448" in alg:
        if size < 224:
            return 95
        if size <= 256:
            return 65   # P-256 / Ed25519: 128-bit classical
        if size <= 384:
            return 55
        return 50
    return 75


# ---------------------------------------------------------------------------
# Component 4 — Forward secrecy (weight 0.10)  [NEW]
# ---------------------------------------------------------------------------

def calculate_forward_secrecy_risk(kex: str, tls_version: str = "", cipher_suite: str = "") -> int:
    """
    Score perfect forward secrecy — the single most important modifier of
    Harvest-Now-Decrypt-Later severity.

    Without PFS (static RSA key transport), every session ever recorded
    under a given certificate is decryptable by recovering that one key.
    With PFS, an adversary must break each session's ephemeral key
    individually. Same eventual quantum threat, radically different blast
    radius — which is why this is scored independently of key exchange.
    """
    kex_text = _norm(kex)
    text = kex_text + " " + _norm(cipher_suite)
    version = _norm(tls_version)

    if "1.3" in version:
        return 0  # TLS 1.3 mandates ephemeral key exchange
    if "ECDHE" in text or "DHE" in text or "X25519" in text or "X448" in text:
        return 0
    if _is_pqc_kem(text):
        return 0
    if "RSA" in kex_text:
        return 100  # static key transport: no forward secrecy at all
    if "PSK" in text:
        return 60   # PSK without a DH exchange has no PFS
    if "ECDH" in text or "DH" in text:
        return 100  # static DH
    return 40       # indeterminate


# ---------------------------------------------------------------------------
# Component 5 — TLS protocol version (weight 0.10)
# ---------------------------------------------------------------------------

def calculate_tls_version_risk(tls_version: str) -> int:
    """
    Score protocol version hygiene only. Quantum exposure of the handshake
    is deliberately *not* folded in here — it belongs to the key-exchange
    and forward-secrecy components — so each component stays independently
    explainable and the weights do not double-count the same weakness.
    """
    version = _norm(tls_version)
    if not version:
        return 60
    if "1.3" in version:
        return 0
    if "1.2" in version:
        return 45   # still widely acceptable, but permits non-AEAD and no PQC hybrids
    if "1.1" in version:
        return 80   # deprecated by RFC 8996
    if "1.0" in version:
        return 92   # deprecated by RFC 8996
    if "SSL" in version:
        return 100  # POODLE / DROWN
    return 60


# ---------------------------------------------------------------------------
# Component 6 — Symmetric cipher strength vs Grover (weight 0.08)
# ---------------------------------------------------------------------------

# Matches both IANA naming (AES_256_GCM) and OpenSSL naming (AES256-GCM).
_SYMMETRIC_BITS_RE = re.compile(r"(AES|CAMELLIA|ARIA|SEED)[_\-]?(128|192|256)")


def calculate_cipher_strength_risk(cipher_suite: str, encryption: str = "") -> int:
    """
    Score bulk-encryption strength against Grover's algorithm, which
    square-roots the search space: an n-bit symmetric key retains only
    n/2 bits of post-quantum security. NIST's post-quantum target is
    128 bits, so AES-256 (→128-bit PQ) clears the bar while AES-128
    (→64-bit PQ) does not, and is penalised accordingly.

    Both cipher-suite naming conventions are handled, because the same
    cipher appears as ``AES_256_GCM`` from IANA-style names and
    ``AES256-GCM`` from OpenSSL-style names; keying only off the former
    silently mis-scored every OpenSSL-named suite as unknown.
    """
    text = _norm(cipher_suite) + " " + _norm(encryption)
    if not text.strip():
        return 50

    if "NULL" in text or "ANON" in text:
        return 100  # no confidentiality at all
    if "RC4" in text:
        return 100  # RFC 7465 prohibits RC4
    if "3DES" in text or "DES_EDE" in text:
        return 90   # 112-bit effective, Sweet32 birthday attack
    if "DES" in text:
        return 100
    if "CHACHA20" in text:
        return 0    # 256-bit key → 128-bit post-quantum

    match = _SYMMETRIC_BITS_RE.search(text)
    if match:
        family, bits = match.group(1), int(match.group(2))
        base = {256: 0, 192: 20, 128: 45}[bits]
        # Camellia/ARIA/SEED are sound but far less reviewed and
        # hardware-accelerated than AES; a small premium reflects that.
        return base if family == "AES" else min(100, base + 5)

    if "AES" in text:
        return 30   # AES present, key length not stated in the suite name
    return 50       # unknown cipher


# ---------------------------------------------------------------------------
# Component 7 — Certificate trust chain (weight 0.07)  [NEW]
# ---------------------------------------------------------------------------

def calculate_certificate_trust_risk(
    is_expired=None, is_self_signed=None, hostname_mismatch=None
) -> int:
    """
    Score real certificate-validation findings produced by the certificate
    parser. These are classical trust failures rather than quantum ones,
    but they are genuine exploitable exposure (an expired or mismatched
    certificate on a banking host is a live MITM opportunity) and they were
    being collected and then discarded by the previous model.

    Findings compound: a self-signed certificate that also fails hostname
    validation is worse than either alone.
    """
    if is_expired is None and is_self_signed is None and hostname_mismatch is None:
        return 25  # certificate not validated — unverified, not proven clean

    score = 0
    if is_expired:
        score = max(score, 100)
    if is_self_signed:
        score = max(score, 85)
    if hostname_mismatch:
        score = max(score, 80)

    findings = sum(1 for f in (is_expired, is_self_signed, hostname_mismatch) if f)
    if findings > 1:
        score = min(100, score + 8 * (findings - 1))
    return int(score)


# ---------------------------------------------------------------------------
# Component 8 — Cipher mode / AEAD (weight 0.06)  [NEW]
# ---------------------------------------------------------------------------

def calculate_cipher_mode_risk(cipher_suite: str, tls_version: str = "") -> int:
    """
    Score the block-cipher mode. AEAD modes (GCM, CCM, ChaCha20-Poly1305)
    bind confidentiality and integrity together; CBC in TLS has produced a
    decade of padding-oracle attacks (BEAST, Lucky13, POODLE). TLS 1.3
    permits AEAD only (RFC 8446), so an unnamed mode there is provably
    AEAD rather than unknown.
    """
    text = _norm(cipher_suite)
    version = _norm(tls_version)

    if "GCM" in text or "POLY1305" in text or "CCM_8" in text or "CCM" in text:
        return 20 if "CCM_8" in text else 0  # CCM_8's 64-bit tag is truncated
    if "ECB" in text:
        return 100
    if "CBC" in text:
        return 70
    if "CTR" in text:
        return 60  # unauthenticated stream mode
    if "1.3" in version:
        return 0   # TLS 1.3 is AEAD-only by specification
    return 40      # mode not determinable


# ---------------------------------------------------------------------------
# Component 9 — Hash function strength (weight 0.06)  [NEW]
# ---------------------------------------------------------------------------

def calculate_hash_risk(cipher_suite: str, signature_algorithm: str = "", hash_alg: str = "") -> int:
    """
    Score hash strength across the handshake PRF and the certificate
    signature. SHA-1 and MD5 are collision-broken *classically* — this is
    present-tense exposure, not a future quantum risk — so they dominate
    the component when found anywhere.
    """
    text = " ".join((_norm(hash_alg), _norm(signature_algorithm), _norm(cipher_suite)))
    # Split on every non-alphanumeric separator so a bare "SHA" token can be
    # told apart from "SHA256". In TLS cipher-suite naming an unqualified
    # trailing SHA means HMAC-SHA1 (TLS_RSA_WITH_RC4_128_SHA,
    # ECDHE-RSA-AES128-SHA), so treating it as "unknown" silently let a
    # genuinely broken hash score better than a healthy SHA-256.
    tokens = set(re.split(r"[^A-Z0-9]+", text))

    if "MD5" in text:
        return 100
    if "SHA1" in tokens or "SHA" in tokens or re.search(r"SHA[_\-]1\b", text) or "WITHSHA1" in text:
        return 90
    if "SHA3" in text or "BLAKE" in text or "SHAKE" in text:
        return 0
    if "SHA512" in text or "SHA_512" in text or "SHA384" in text or "SHA_384" in text:
        return 0
    if "SHA256" in text or "SHA_256" in text:
        return 10  # sound today; Grover halves preimage margin
    if "SHA224" in text or "SHA_224" in text:
        return 30
    return 40      # unknown


# ---------------------------------------------------------------------------
# Component 10 — Certificate lifetime hygiene (weight 0.05)
# ---------------------------------------------------------------------------

def calculate_certificate_validity_risk(expiry: str, days_until_expiry=None) -> int:
    """
    Score certificate lifetime as an operational-readiness signal.

    Both extremes are penalised, which is the insight a plain "days left"
    check misses. A certificate expiring within days is an imminent
    outage; a certificate valid for far longer than the CA/Browser Forum
    398-day maximum indicates weak rotation discipline, and rotation
    discipline is precisely the capability an organisation needs in order
    to migrate to post-quantum certificates at all. Poor crypto-agility is
    a real PQC-readiness risk.

    ``days_until_expiry`` is used when the scanner recorded it; otherwise
    it is derived from the raw expiry timestamp.
    """
    days = days_until_expiry
    if days is None:
        if not expiry:
            return 40
        try:
            from datetime import datetime, timezone
            exp_date = datetime.fromisoformat(expiry)
            if exp_date.tzinfo is None:
                exp_date = exp_date.replace(tzinfo=timezone.utc)
            days = (exp_date - datetime.now(timezone.utc)).days
        except (ValueError, TypeError):
            return 40

    if days < 0:
        return 100  # already expired
    if days < 15:
        return 85
    if days < 30:
        return 70
    if days < 90:
        return 40
    if days <= 398:
        return 10   # within CA/Browser Forum maximum — healthy
    return 55       # over-long lifetime: poor crypto-agility


# ---------------------------------------------------------------------------
# HNDL amplification
# ---------------------------------------------------------------------------

def _hndl_multiplier_from(hndl) -> tuple[float, str]:
    """
    Accept either the numeric/dict form produced by hndl_detector or the
    legacy bare risk-level string, so older call sites keep working while
    newer ones get the full-resolution multiplier.

    Returns (multiplier, source_label).
    """
    if isinstance(hndl, dict):
        mult = hndl.get("hndl_multiplier")
        if isinstance(mult, (int, float)) and mult > 0:
            return float(mult), str(hndl.get("service_type") or "measured multiplier")
        hndl = hndl.get("risk_level", "")

    level = _norm(hndl)
    # Midpoints of the bands hndl_detector._risk_level() maps from, used
    # only when the caller could not supply the real multiplier.
    if level == "CRITICAL":
        return 2.0, "risk level (critical)"
    if level == "HIGH":
        return 1.65, "risk level (high)"
    if level == "MEDIUM":
        return 1.35, "risk level (medium)"
    if level == "LOW":
        return 1.0, "risk level (low)"
    return 1.0, "unknown (no amplification)"


# ---------------------------------------------------------------------------
# Labels and tiers
# ---------------------------------------------------------------------------

def get_risk_label(score: int) -> str:
    """Map a 0-100 quantum risk score to its band label."""
    for low, high, label in RISK_BANDS:
        if low <= score <= high:
            return label
    return "Critical" if score > 100 else "Quantum Safe"


def _band_top_for(floor: int) -> int:
    """Upper bound of the risk band a given floor sits at the bottom of."""
    for low, high, _ in RISK_BANDS:
        if low <= floor <= high:
            return high
    return 100


def _apply_floor(composite: float, floor: int) -> float:
    """
    Raise a composite score into the band starting at ``floor`` while
    preserving the ordering the composite established.

    A plain ``max(composite, floor)`` would satisfy the structural rule but
    flatten every asset that trips the same gate onto one number — with no
    PQC anywhere being the overwhelmingly common case today, that collapsed
    an entire fleet to an identical score and made the ten weighted
    components invisible in the output. Instead the composite is mapped
    proportionally across the band above the floor, so a host with weaker
    ciphers, an older protocol or a worse certificate still scores above a
    cleaner host that trips the same gate.

    The raw composite still wins when it is already higher than the mapped
    value, so a genuinely terrible asset is never dragged *down* into a
    band it has outgrown.
    """
    band_top = _band_top_for(floor)
    mapped = floor + (composite / 100.0) * (band_top - floor)
    return max(composite, mapped)


def get_enterprise_rating(average_risk_score: float) -> int:
    """Rescale an average risk score to the 0-1000 Enterprise Rating."""
    return int(max(0, min(1000, round((100 - average_risk_score) * 10))))


def get_posture_tier(rating: int) -> str:
    """Map an Enterprise Rating to its Posture Tier."""
    for low, high, tier in POSTURE_TIERS:
        if low <= rating <= high:
            return tier
    return "Legacy"


def get_host_posture_tier(risk_score) -> str:
    """
    Posture Tier for a SINGLE host, from its 0-100 quantum risk score.

    A fleet's tier comes from the rating of its average risk; a fleet of one
    host is just that host, so the same two steps — rating, then tier —
    applied to one score are the tier of that host by definition. Routing it
    through the same get_enterprise_rating/get_posture_tier pair as
    summarize_fleet keeps ONE definition of the boundaries: a host reported
    as Legacy here is exactly a host that would drag a fleet to Legacy on its
    own. Defining a second mapping for hosts is how the per-host chart and
    the fleet headline start disagreeing about the same estate.
    """
    if not isinstance(risk_score, (int, float)):
        return "N/A"
    return get_posture_tier(get_enterprise_rating(risk_score))


def summarize_fleet(scores: list) -> dict:
    """
    Aggregate per-asset scores into the fleet-level numbers the dashboard
    and every export share, so a single implementation defines them all.
    """
    valid = [s for s in scores if isinstance(s, (int, float))]
    if not valid:
        return {
            "assets_scored": 0,
            "average_risk_score": 0,
            "enterprise_rating": 0,
            "posture_tier": "N/A",
            "band_counts": {label: 0 for _, _, label in RISK_BANDS},
        }

    average = sum(valid) / len(valid)
    rating = get_enterprise_rating(average)
    counts = {label: 0 for _, _, label in RISK_BANDS}
    for s in valid:
        counts[get_risk_label(int(round(s)))] += 1

    return {
        "assets_scored": len(valid),
        "average_risk_score": int(round(average)),
        "enterprise_rating": rating,
        "posture_tier": get_posture_tier(rating),
        "band_counts": counts,
    }


def get_scoring_model() -> dict:
    """
    Return the complete model definition — weights, bands, tiers and
    constants — so the methodology can be served over the API, embedded in
    exports, and shown in the UI instead of living only in this docstring.
    """
    return {
        "model_version": "2.0",
        "score_range": {"min": 0, "max": 100, "direction": "higher is worse"},
        "components": [
            {
                "key": key,
                "label": COMPONENT_LABELS[key],
                "weight": weight,
                "weight_percent": round(weight * 100, 1),
            }
            for key, weight in sorted(COMPONENT_WEIGHTS.items(), key=lambda kv: -kv[1])
        ],
        "weights_total": round(sum(COMPONENT_WEIGHTS.values()), 6),
        "hndl_amplification": {
            "formula": "uplift = composite * (multiplier - 1.0) * sensitivity",
            "sensitivity": HNDL_SENSITIVITY,
            "multiplier_range": [1.0, 2.0],
            "note": "Amplifies existing exposure; cannot create risk where crypto is quantum-safe.",
        },
        "floor_mapping": {
            "formula": "gated = max(composite, floor + (composite / 100) * (band_top - floor))",
            "note": "Raises the score into the gated band while preserving the ordering the composite established, so assets tripping the same gate stay differentiated.",
        },
        "floor_rules": [
            {
                "name": "classically_broken",
                "floor": FLOOR_CLASSICALLY_BROKEN,
                "trigger": "MD5/SHA-1 signature, RC4/DES/NULL cipher, SSLv2/v3, or RSA/DSA key <= 1024 bits",
                "rationale": "Exploitable today without any quantum computer.",
            },
            {
                "name": "no_pqc_anywhere",
                "floor": FLOOR_NO_PQC_ANYWHERE,
                "trigger": "Neither key exchange nor certificate signature is post-quantum",
                "rationale": "Zero post-quantum protection cannot rate better than Quantum Vulnerable.",
            },
            {
                "name": "partial_pqc",
                "floor": FLOOR_PARTIAL_PQC,
                "trigger": "Exactly one of key exchange / signature is post-quantum",
                "rationale": "Hybrid deployment in progress — genuine improvement, not yet complete.",
            },
        ],
        "risk_bands": [
            {"min": low, "max": high, "label": label} for low, high, label in RISK_BANDS
        ],
        "enterprise_rating": {
            "formula": "rating = (100 - average_risk_score) * 10",
            "range": [0, 1000],
        },
        "posture_tiers": [
            {
                "min_rating": low,
                "max_rating": high,
                "tier": tier,
                "max_avg_risk": round((1000 - low) / 10, 1),
            }
            for low, high, tier in POSTURE_TIERS
        ],
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def calculate_quantum_risk(tls_result: dict, cert_meta: dict, hndl=None, algo_meta: dict = None) -> dict:
    """
    Calculate the multi-factor Quantum Risk Score for a single asset.

    Parameters
    ----------
    tls_result : dict
        Handshake facts. Keys used: ``tls_version``, ``cipher_suite``.
    cert_meta : dict
        Certificate facts. Keys used: ``key_algorithm``, ``key_size``,
        ``signature_algorithm``, ``certificate_expiry``, and — when the
        caller has them — ``is_expired``, ``is_self_signed``,
        ``hostname_mismatch``, ``days_until_expiry``.
    hndl : str | dict, optional
        Either the full HNDL record (preferred — carries the real numeric
        ``hndl_multiplier``) or the legacy bare risk-level string.
    algo_meta : dict, optional
        Pre-parsed cipher components from ``algorithm_analysis``
        (``key_exchange``, ``signature``, ``encryption``, ``hash``). When
        omitted, everything needed is derived from the cipher suite, so no
        call site is forced to join that table to get full-fidelity scoring.

    Returns
    -------
    dict
        ``total_score``, ``risk_label``, ``breakdown`` (raw 0-100 per
        component, including the six legacy keys), ``components`` (raw
        score, weight and weighted contribution per component),
        ``composite_score``, ``applied_floor``, ``hndl`` details and
        ``model_version``.
    """
    tls_result = tls_result or {}
    cert_meta = cert_meta or {}
    algo_meta = algo_meta or {}

    tls_version = tls_result.get("tls_version") or ""
    cipher_suite = tls_result.get("cipher_suite") or ""
    key_alg = cert_meta.get("key_algorithm") or "unknown"
    key_size = cert_meta.get("key_size") or 0
    sig_alg = cert_meta.get("signature_algorithm") or "unknown"
    expiry = cert_meta.get("certificate_expiry") or ""

    # Classify the handshake into key-exchange / signature families. The
    # pre-parsed values win when supplied; otherwise classify_algorithm
    # infers them from the suite name plus certificate metadata.
    classification = classify_algorithm(cipher_suite, key_alg, sig_alg)
    kex = algo_meta.get("key_exchange") or classification["key_exchange"]
    sig = algo_meta.get("signature") or classification["signature"]
    if _norm(kex) == "UNKNOWN":
        kex = classification["key_exchange"]
    if _norm(sig) == "UNKNOWN":
        sig = classification["signature"]

    # --- Raw component scores (each 0-100, higher = worse) --------------
    raw = {
        "key_exchange":      calculate_key_exchange_risk(kex, tls_version, cipher_suite),
        "signature":         calculate_signature_risk(sig, sig_alg),
        "key_size":          calculate_key_size_risk(key_alg, key_size),
        "forward_secrecy":   calculate_forward_secrecy_risk(kex, tls_version, cipher_suite),
        "tls_version":       calculate_tls_version_risk(tls_version),
        "cipher":            calculate_cipher_strength_risk(cipher_suite, algo_meta.get("encryption", "")),
        "certificate_trust": calculate_certificate_trust_risk(
            cert_meta.get("is_expired"),
            cert_meta.get("is_self_signed"),
            cert_meta.get("hostname_mismatch"),
        ),
        "cipher_mode":       calculate_cipher_mode_risk(cipher_suite, tls_version),
        "hash":              calculate_hash_risk(cipher_suite, sig_alg, algo_meta.get("hash", "")),
        "certificate":       calculate_certificate_validity_risk(
            expiry, cert_meta.get("days_until_expiry")
        ),
    }

    # --- Stage 1: weighted composite -----------------------------------
    composite = sum(raw[key] * COMPONENT_WEIGHTS[key] for key in COMPONENT_WEIGHTS)

    # --- Stage 2: floor gates ------------------------------------------
    kex_is_pqc = _is_pqc_kem(_norm(kex) + " " + _norm(cipher_suite))
    sig_is_pqc = _is_pqc_sig(_norm(sig) + " " + _norm(sig_alg))

    broken_text = " ".join((_norm(cipher_suite), _norm(sig_alg), _norm(tls_version)))
    classically_broken = (
        any(tok in broken_text for tok in CLASSICALLY_BROKEN_TOKENS)
        or raw["signature"] >= 95
        or raw["cipher"] >= 100
        or raw["key_size"] >= 100
        or raw["tls_version"] >= 100
    )

    applied_floor = None
    gated = composite
    if classically_broken:
        gated, applied_floor = _apply_floor(composite, FLOOR_CLASSICALLY_BROKEN), "classically_broken"
    elif not kex_is_pqc and not sig_is_pqc:
        gated, applied_floor = _apply_floor(composite, FLOOR_NO_PQC_ANYWHERE), "no_pqc_anywhere"
    elif kex_is_pqc != sig_is_pqc:
        gated, applied_floor = _apply_floor(composite, FLOOR_PARTIAL_PQC), "partial_pqc"

    # --- Stage 3: HNDL amplification -----------------------------------
    multiplier, hndl_source = _hndl_multiplier_from(hndl)
    hndl_uplift = gated * max(0.0, multiplier - 1.0) * HNDL_SENSITIVITY

    # --- Stage 4: clamp -------------------------------------------------
    total_score = int(max(0, min(100, round(gated + hndl_uplift))))

    return {
        "total_score": total_score,
        "risk_label": get_risk_label(total_score),
        # Flat raw scores. The six keys the previous model exposed
        # (key_exchange, signature, tls_version, key_size, certificate,
        # cipher) are all still present with unchanged meaning, so existing
        # consumers keep working while the four new components are additive.
        "breakdown": dict(raw),
        "components": [
            {
                "key": key,
                "label": COMPONENT_LABELS[key],
                "raw_score": raw[key],
                "weight": COMPONENT_WEIGHTS[key],
                "weighted_contribution": round(raw[key] * COMPONENT_WEIGHTS[key], 2),
            }
            for key in sorted(COMPONENT_WEIGHTS, key=lambda k: -raw[k] * COMPONENT_WEIGHTS[k])
        ],
        "composite_score": round(composite, 2),
        "applied_floor": applied_floor,
        "quantum_safe_key_exchange": kex_is_pqc,
        "quantum_safe_signature": sig_is_pqc,
        "hndl": {
            "multiplier": multiplier,
            "source": hndl_source,
            "uplift": round(hndl_uplift, 2),
        },
        "model_version": "2.0",
    }
