"""
End-to-end system validation.

Exercises the core quantum-risk-scoring path directly (no server/network
required) so it can run in any environment, including a fresh clone with
only requirements.txt installed. Each check asserts a specific, real claim
made about the engine rather than just "it doesn't crash".

Run: python test_system.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "analysis"))

from service_classifier import classify_service  # noqa: E402
from hndl_detector import detect_hndl_risk  # noqa: E402
from quantum_risk_engine import (  # noqa: E402
    calculate_quantum_risk, get_risk_label, get_posture_tier,
    get_enterprise_rating, summarize_fleet, get_scoring_model,
    COMPONENT_WEIGHTS, POSTURE_TIERS,
)

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}")
    if not condition:
        FAILURES.append(f"{label}: {detail}")


def section(title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))


PQC_TLS = {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}
PQC_CERT = {
    "key_algorithm": "ML-DSA-65",
    "key_size": 3168,
    "signature_algorithm": "ML-DSA-65",
    "certificate_expiry": "2030-01-01T00:00:00+00:00",
}

LEGACY_TLS = {"tls_version": "TLSv1.0", "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA"}
LEGACY_CERT = {
    "key_algorithm": "RSA",
    "key_size": 1024,
    "signature_algorithm": "RSA",
    "certificate_expiry": "2020-01-01T00:00:00+00:00",  # already expired
}


def test_determinism() -> None:
    section("Determinism (same input -> same score, every run)")
    results = [calculate_quantum_risk(LEGACY_TLS, LEGACY_CERT, "HIGH") for _ in range(20)]
    scores = {r["total_score"] for r in results}
    check(
        "20 repeated calls with identical input produce one score",
        len(scores) == 1,
        f"got {len(scores)} distinct scores: {sorted(scores)}",
    )


def test_pqc_signature_detected() -> None:
    section("PQC signature algorithm is detected and scored as safe")
    result = calculate_quantum_risk(PQC_TLS, PQC_CERT, "LOW")
    check(
        f"breakdown.signature is 0 for an ML-DSA certificate (got {result['breakdown']['signature']})",
        result["breakdown"]["signature"] == 0,
        f"breakdown: {result['breakdown']}",
    )


def test_pqc_key_exchange_detection_and_gap() -> None:
    section("PQC key exchange: detected when named, undetectable via negotiated group")
    # A hybrid group that appears in the cipher-suite name IS detected.
    named = calculate_quantum_risk(
        {"tls_version": "TLSv1.3", "cipher_suite": "TLS_X25519MLKEM768_AES_256_GCM_SHA384"},
        PQC_CERT, "LOW",
    )
    check(
        f"hybrid ML-KEM named in the suite scores key_exchange 0 "
        f"(got {named['breakdown']['key_exchange']})",
        named["breakdown"]["key_exchange"] == 0,
        f"breakdown: {named['breakdown']}",
    )

    # KNOWN GAP: when the hybrid group is negotiated via supported_groups and
    # is NOT in the suite name (the normal TLS 1.3 case), it is invisible.
    # Python's ssl module exposes no group()/curve accessor in this build, so
    # the scanner cannot record it. The model therefore assumes ephemeral
    # classical (X)DH - risk 80 - which is the conservative, honest default.
    #
    # This test documents the gap rather than hiding it. If it starts failing,
    # the scanner has begun capturing the negotiated group: rewrite this as a
    # positive assertion and update the README's Known Limitations section
    # rather than deleting it.
    unnamed = calculate_quantum_risk(PQC_TLS, PQC_CERT, "LOW")
    check(
        f"unnamed group on TLS 1.3 falls back to ECDHE-assumed 80, not 0 "
        f"(got {unnamed['breakdown']['key_exchange']})",
        unnamed["breakdown"]["key_exchange"] == 80,
        f"breakdown: {unnamed['breakdown']}",
    )


def test_weights_are_normalized() -> None:
    section("Component weights are normalized (sum to exactly 1.0)")
    total = sum(COMPONENT_WEIGHTS.values())
    check(
        f"{len(COMPONENT_WEIGHTS)} component weights sum to 1.0 (got {total})",
        abs(total - 1.0) < 1e-9,
        f"weights: {COMPONENT_WEIGHTS}",
    )
    model = get_scoring_model()
    check(
        f"/scoring-model reports the same total (got {model['weights_total']})",
        abs(model["weights_total"] - 1.0) < 1e-9,
    )
    check(
        f"model exposes all {len(COMPONENT_WEIGHTS)} components (got {len(model['components'])})",
        len(model["components"]) == len(COMPONENT_WEIGHTS),
    )


def test_all_components_scored() -> None:
    section("Every weighted component is actually produced by the engine")
    result = calculate_quantum_risk(LEGACY_TLS, LEGACY_CERT, "HIGH")
    for key in COMPONENT_WEIGHTS:
        check(
            f"breakdown contains '{key}'",
            key in result["breakdown"] and isinstance(result["breakdown"][key], int),
            f"breakdown: {result['breakdown']}",
        )
    check(
        f"components list is fully populated (got {len(result['components'])})",
        len(result["components"]) == len(COMPONENT_WEIGHTS),
    )


def test_new_components_detect_real_findings() -> None:
    section("The four v2 components detect real, measurable findings")
    base_cert = {
        "key_algorithm": "RSA", "key_size": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "certificate_expiry": "", "days_until_expiry": 200,
        "is_expired": False, "is_self_signed": False, "hostname_mismatch": False,
    }

    # Forward secrecy: static RSA key transport has none.
    no_pfs = calculate_quantum_risk(
        {"tls_version": "TLSv1.2", "cipher_suite": "TLS_RSA_WITH_AES_256_GCM_SHA384"},
        base_cert, "LOW")
    check(f"static RSA key transport scores forward_secrecy 100 "
          f"(got {no_pfs['breakdown']['forward_secrecy']})",
          no_pfs["breakdown"]["forward_secrecy"] == 100)

    pfs = calculate_quantum_risk(
        {"tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384"},
        base_cert, "LOW")
    check(f"ECDHE scores forward_secrecy 0 (got {pfs['breakdown']['forward_secrecy']})",
          pfs["breakdown"]["forward_secrecy"] == 0)

    # Cipher mode: CBC is penalised, GCM is not.
    cbc = calculate_quantum_risk(
        {"tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES128-CBC-SHA256"},
        base_cert, "LOW")
    check(f"CBC mode is penalised (got {cbc['breakdown']['cipher_mode']})",
          cbc["breakdown"]["cipher_mode"] >= 60)
    check(f"GCM mode is not penalised (got {pfs['breakdown']['cipher_mode']})",
          pfs["breakdown"]["cipher_mode"] == 0)

    # Hash: bare trailing SHA in a suite name means SHA-1 and must be caught.
    sha1 = calculate_quantum_risk(
        {"tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES128-SHA"},
        base_cert, "LOW")
    check(f"bare 'SHA' suffix is detected as SHA-1 (got {sha1['breakdown']['hash']})",
          sha1["breakdown"]["hash"] == 90)
    check(f"SHA-384 scores 0 (got {pfs['breakdown']['hash']})",
          pfs["breakdown"]["hash"] == 0)

    # Certificate trust: real validation flags drive the component.
    bad_trust = calculate_quantum_risk(
        {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
        dict(base_cert, is_self_signed=True, hostname_mismatch=True), "LOW")
    check(f"self-signed + hostname mismatch compound above either alone "
          f"(got {bad_trust['breakdown']['certificate_trust']})",
          bad_trust["breakdown"]["certificate_trust"] > 85)
    check(f"a clean chain scores 0 (got {pfs['breakdown']['certificate_trust']})",
          pfs["breakdown"]["certificate_trust"] == 0)


def test_floor_gates() -> None:
    section("Floor gates enforce structural truth without flattening ordering")
    clean = {"is_expired": False, "is_self_signed": False, "hostname_mismatch": False,
             "days_until_expiry": 200, "certificate_expiry": ""}

    # Best possible classical posture still cannot beat the band floor.
    best_classical = calculate_quantum_risk(
        {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
        dict(clean, key_algorithm="RSA", key_size=4096,
             signature_algorithm="sha384WithRSAEncryption"), "LOW")
    check(
        f"no PQC anywhere is floored into Quantum Vulnerable "
        f"(got {best_classical['total_score']} / {best_classical['risk_label']})",
        best_classical["risk_label"] == "Quantum Vulnerable",
        f"composite was {best_classical['composite_score']}",
    )
    check("the floor is reported, not hidden",
          best_classical["applied_floor"] == "no_pqc_anywhere")

    # Ordering must survive the gate: a weaker asset tripping the same gate
    # must still score strictly higher than a stronger one.
    weaker = calculate_quantum_risk(
        {"tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES128-CBC-SHA"},
        dict(clean, key_algorithm="RSA", key_size=2048,
             signature_algorithm="sha256WithRSAEncryption"), "LOW")
    check(
        f"weaker asset outranks stronger one under the same floor "
        f"({weaker['total_score']} > {best_classical['total_score']})",
        weaker["total_score"] > best_classical["total_score"],
        "floor mapping collapsed both onto the same score",
    )

    # Partial PQC lands in Transitioning, not Quantum Safe.
    partial = calculate_quantum_risk(
        {"tls_version": "TLSv1.3", "cipher_suite": "TLS_X25519MLKEM768_AES_256_GCM_SHA384"},
        dict(clean, key_algorithm="RSA", key_size=3072,
             signature_algorithm="sha384WithRSAEncryption"), "LOW")
    check(
        f"PQC key exchange with a classical certificate is Transitioning "
        f"(got {partial['total_score']} / {partial['risk_label']})",
        partial["risk_label"] == "Transitioning",
    )

    # Full PQC reaches Quantum Safe — the top of the scale must be reachable.
    full = calculate_quantum_risk(
        {"tls_version": "TLSv1.3", "cipher_suite": "TLS_X25519MLKEM768_AES_256_GCM_SHA384"},
        dict(clean, key_algorithm="ML-DSA-65", key_size=0,
             signature_algorithm="ML-DSA-65"), "LOW")
    check(
        f"full PQC reaches Quantum Safe (got {full['total_score']} / {full['risk_label']})",
        full["risk_label"] == "Quantum Safe" and full["applied_floor"] is None,
    )


def test_hndl_amplification() -> None:
    section("HNDL amplifies real exposure but cannot manufacture it")
    clean = {"is_expired": False, "is_self_signed": False, "hostname_mismatch": False,
             "days_until_expiry": 200, "certificate_expiry": ""}
    classical_tls = {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}
    classical_cert = dict(clean, key_algorithm="RSA", key_size=4096,
                          signature_algorithm="sha384WithRSAEncryption")

    low = calculate_quantum_risk(classical_tls, classical_cert, {"hndl_multiplier": 1.0})
    high = calculate_quantum_risk(classical_tls, classical_cert, {"hndl_multiplier": 2.0})
    check(
        f"a VPN (x2.0) scores above plain HTTPS (x1.0) on identical crypto "
        f"({high['total_score']} > {low['total_score']})",
        high["total_score"] > low["total_score"],
    )
    check(f"multiplier 1.0 produces zero uplift (got {low['hndl']['uplift']})",
          low["hndl"]["uplift"] == 0)

    # On fully quantum-safe crypto there is nothing to harvest, so even the
    # maximum multiplier must not push the asset out of Quantum Safe.
    safe_vpn = calculate_quantum_risk(
        {"tls_version": "TLSv1.3", "cipher_suite": "TLS_X25519MLKEM768_AES_256_GCM_SHA384"},
        dict(clean, key_algorithm="ML-DSA-65", key_size=0, signature_algorithm="ML-DSA-65"),
        {"hndl_multiplier": 2.0})
    check(
        f"max HNDL on full PQC stays Quantum Safe "
        f"(got {safe_vpn['total_score']} / {safe_vpn['risk_label']})",
        safe_vpn["risk_label"] == "Quantum Safe",
    )

    # The legacy bare-string form must still work for older call sites.
    legacy_form = calculate_quantum_risk(classical_tls, classical_cert, "HIGH")
    check(f"legacy risk-level string still amplifies (got x{legacy_form['hndl']['multiplier']})",
          legacy_form["hndl"]["multiplier"] > 1.0)


def test_monotonicity() -> None:
    section("Degrading any single parameter never lowers the score")
    clean = {"is_expired": False, "is_self_signed": False, "hostname_mismatch": False,
             "days_until_expiry": 200, "certificate_expiry": ""}
    baseline_tls = {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}
    baseline_cert = dict(clean, key_algorithm="RSA", key_size=4096,
                         signature_algorithm="sha384WithRSAEncryption")
    baseline = calculate_quantum_risk(baseline_tls, baseline_cert, {"hndl_multiplier": 1.0})["total_score"]

    degradations = [
        ("AES-128 instead of AES-256",
         {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"}, baseline_cert),
        ("TLS 1.2 instead of 1.3", {"tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384"}, baseline_cert),
        ("RSA-2048 instead of RSA-4096", baseline_tls,
         dict(baseline_cert, key_size=2048, signature_algorithm="sha256WithRSAEncryption")),
        ("expired certificate", baseline_tls,
         dict(baseline_cert, is_expired=True, days_until_expiry=-3)),
        ("self-signed certificate", baseline_tls, dict(baseline_cert, is_self_signed=True)),
        ("hostname mismatch", baseline_tls, dict(baseline_cert, hostname_mismatch=True)),
        ("certificate expiring in 5 days", baseline_tls, dict(baseline_cert, days_until_expiry=5)),
    ]
    for label, tls, cert in degradations:
        score = calculate_quantum_risk(tls, cert, {"hndl_multiplier": 1.0})["total_score"]
        check(f"{label}: {score} >= baseline {baseline}", score >= baseline,
              f"degrading a parameter lowered the score ({score} < {baseline})")


def test_posture_tiers() -> None:
    section("Posture tiers divide the 0-1000 rating without gaps or overlap")
    ordered = sorted(POSTURE_TIERS, key=lambda t: t[0])
    check(f"lowest tier starts at 0 (got {ordered[0][0]})", ordered[0][0] == 0)
    check(f"highest tier ends at 1000 (got {ordered[-1][1]})", ordered[-1][1] == 1000)
    for (_, prev_high, prev_name), (next_low, _, next_name) in zip(ordered, ordered[1:]):
        check(f"{prev_name} ends at {prev_high}, {next_name} starts at {next_low} (contiguous)",
              next_low == prev_high + 1,
              f"gap or overlap between {prev_name} and {next_name}")

    # Every rating in range must resolve to exactly one tier.
    unmapped = [r for r in range(0, 1001) if not get_posture_tier(r)]
    check(f"all 1001 rating values map to a tier ({len(unmapped)} unmapped)", not unmapped)

    boundaries = [(0, "Legacy"), (399, "Legacy"), (400, "Developing"), (549, "Developing"),
                  (550, "Standard"), (699, "Standard"), (700, "Advanced"), (849, "Advanced"),
                  (850, "Elite-PQC"), (1000, "Elite-PQC")]
    for rating, expected in boundaries:
        got = get_posture_tier(rating)
        check(f"rating={rating} -> \"{expected}\"", got == expected, f"got \"{got}\"")


def test_fleet_aggregation() -> None:
    section("Fleet aggregation is consistent and shared")
    check("empty fleet yields rating 0 / tier N/A",
          summarize_fleet([])["posture_tier"] == "N/A"
          and summarize_fleet([])["enterprise_rating"] == 0)

    fleet = summarize_fleet([67, 67, 77, 77])
    check(f"average of [67,67,77,77] is 72 (got {fleet['average_risk_score']})",
          fleet["average_risk_score"] == 72)
    check(f"rating = (100-72)*10 = 280 (got {fleet['enterprise_rating']})",
          fleet["enterprise_rating"] == 280)
    check(f"280 -> Legacy (got {fleet['posture_tier']})", fleet["posture_tier"] == "Legacy")
    check(f"band counts total the fleet size (got {sum(fleet['band_counts'].values())})",
          sum(fleet["band_counts"].values()) == 4)

    # rating and tier must agree with the standalone helpers.
    check("summarize_fleet agrees with get_enterprise_rating/get_posture_tier",
          fleet["enterprise_rating"] == get_enterprise_rating(72)
          and fleet["posture_tier"] == get_posture_tier(get_enterprise_rating(72)))


def test_legacy_scores_high_risk() -> None:
    section("Legacy/expired crypto scores as high risk")
    result = calculate_quantum_risk(LEGACY_TLS, LEGACY_CERT, "HIGH")
    check(
        f"RSA-1024/TLS1.0/expired-cert total_score is high (got {result['total_score']})",
        result["total_score"] >= 70,
        f"full result: {result}",
    )
    check(
        f'label is "Critical" (got "{result["risk_label"]}")',
        result["risk_label"] == "Critical",
    )


def test_risk_label_boundaries() -> None:
    section("Risk label thresholds match documented bands")
    cases = [(0, "Quantum Safe"), (29, "Quantum Safe"), (30, "Transitioning"),
             (44, "Transitioning"), (45, "Quantum Vulnerable"), (80, "Quantum Vulnerable"),
             (81, "Critical"), (100, "Critical")]
    for score, expected in cases:
        got = get_risk_label(score)
        check(f"score={score} -> \"{expected}\"", got == expected, f"got \"{got}\"")


def test_score_bounds() -> None:
    section("Score is always clamped to 0-100")
    for tls, cert, hndl in ((PQC_TLS, PQC_CERT, "LOW"), (LEGACY_TLS, LEGACY_CERT, "CRITICAL")):
        result = calculate_quantum_risk(tls, cert, hndl)
        s = result["total_score"]
        check(f"0 <= {s} <= 100", 0 <= s <= 100)


def test_service_classification_ignores_the_apex() -> None:
    """
    The HNDL multiplier must be a property of the endpoint, not of the
    customer's brand. Keyword matching therefore runs on the subdomain
    labels only: scanning "pnb.bank.in" once classified all 101 discovered
    hosts as Financial-API because the apex contains "bank", which applied a
    1.7x multiplier fleet-wide and moved the whole estate a posture tier.
    """
    section("Service classification is scoped to subdomain labels")

    # The apex must never drive the verdict, however financial it reads.
    for host in ("pnb.bank.in", "images.pnb.bank.in", "locate.pnb.bank.in"):
        got = classify_service(host, 443, "pnb.bank.in")
        check(f'apex keyword does not classify {host} (got "{got}")', got == "HTTPS")
    check('a non-service label under a bank apex stays HTTPS',
          classify_service("careers.hdfcbank.com", 443, "hdfcbank.com") == "HTTPS")

    # Real service labels must still be detected.
    for host, expected in (
        ("ibanking.pnb.bank.in", "Financial-API"),
        ("upi.pnb.bank.in", "Financial-API"),
        ("epayment.pnb.bank.in", "Financial-API"),
        ("netbanking.hdfcbank.com", "Financial-API"),
        ("api-gateway.example.com", "Financial-API"),
    ):
        got = classify_service(host, 443, host.split(".", 1)[1])
        check(f'{host} -> "{expected}" (got "{got}")', got == expected)

    # Substrings of unrelated words must not fire.
    for host, apex in (("rapid.example.com", "example.com"),
                       ("wgateway.example.com", "example.com"),
                       ("assorted.example.com", "example.com")):
        got = classify_service(host, 443, apex)
        check(f'incidental substring does not classify {host} (got "{got}")',
              got == "HTTPS")

    # Longest keyword wins, so a specific service beats a substring of itself.
    check('openvpn beats the shorter "vpn" key '
          f'(got "{classify_service("openvpn.example.com", 443, "example.com")}")',
          classify_service("openvpn.example.com", 443, "example.com") == "OpenVPN")

    # Multiplier consequence: the two ends of the range are actually reached.
    plain = detect_hndl_risk("images.pnb.bank.in", 443,
                             classify_service("images.pnb.bank.in", 443, "pnb.bank.in"))
    fin = detect_hndl_risk("ibanking.pnb.bank.in", 443,
                           classify_service("ibanking.pnb.bank.in", 443, "pnb.bank.in"))
    check(f"a static host carries no HNDL uplift (got {plain['hndl_multiplier']})",
          plain["hndl_multiplier"] == 1.0)
    check(f"a banking host does carry uplift (got {fin['hndl_multiplier']})",
          fin["hndl_multiplier"] > 1.0)


def main() -> int:
    print("=" * 60)
    print("QUBITSENSE SYSTEM VALIDATION")
    print("=" * 60)

    test_determinism()
    test_weights_are_normalized()
    test_all_components_scored()
    test_pqc_signature_detected()
    test_pqc_key_exchange_detection_and_gap()
    test_new_components_detect_real_findings()
    test_floor_gates()
    test_hndl_amplification()
    test_monotonicity()
    test_legacy_scores_high_risk()
    test_risk_label_boundaries()
    test_posture_tiers()
    test_fleet_aggregation()
    test_score_bounds()
    test_service_classification_ignores_the_apex()

    print("\n" + "=" * 60)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} FAILURE(S)")
        for f in FAILURES:
            print(f"  - {f}")
        print("=" * 60)
        return 1

    print("RESULT: ALL CHECKS PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
