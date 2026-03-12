"""
Quantum Estimator module.
Estimates quantum vulnerability based on algorithm family classifications.

Rules:
    factoring     → broken by Shor's algorithm   → critical (90)
    elliptic_curve→ broken by Shor's algorithm   → critical (90)
    discrete_log  → broken by Shor's algorithm   → critical (90)
    symmetric     → weakened by Grover's          → medium  (50)
    hash          → weakened by Grover's          → medium  (50)
    lattice       → quantum resistant             → low     (10)
    hash_based_sig→ quantum resistant             → low     (10)
    unknown       → cannot verify safety          → high    (70)
"""


# ---- Family → risk mapping ----

FAMILY_RISK: dict[str, tuple[str, int]] = {
    "factoring":       ("critical", 90),
    "elliptic_curve":  ("critical", 90),
    "discrete_log":    ("critical", 90),
    "symmetric":       ("medium",   50),
    "hash":            ("medium",   50),
    "lattice":         ("low",      10),
    "hash_based_sig":  ("low",      10),
    "unknown":         ("high",     70),
}


def estimate_quantum_risk(classification: dict) -> dict:
    """
    Estimate quantum vulnerability from algorithm family classifications.

    Parameters
    ----------
    classification : dict
        Output of ``classify_family()`` with keys
        ``key_exchange_family``, ``signature_family``,
        ``encryption_family``, ``hash_family``.

    Returns
    -------
    dict
        Keys:
        - ``quantum_risk_estimate`` — weighted composite score (0-100)
        - ``risk_label`` — human-readable label
        - ``component_risks`` — per-component breakdown
    """
    components = {
        "key_exchange": classification.get("key_exchange_family", "unknown"),
        "signature":    classification.get("signature_family", "unknown"),
        "encryption":   classification.get("encryption_family", "unknown"),
        "hash":         classification.get("hash_family", "unknown"),
    }

    # Weights: key exchange (40%), signature (30%), encryption (20%), hash (10%)
    weights = {
        "key_exchange": 0.40,
        "signature":    0.30,
        "encryption":   0.20,
        "hash":         0.10,
    }

    component_risks = {}
    weighted_score = 0.0

    for component, family in components.items():
        label, score = FAMILY_RISK.get(family, FAMILY_RISK["unknown"])
        component_risks[component] = {"family": family, "risk": label, "score": score}
        weighted_score += score * weights[component]

    total = round(weighted_score)

    # Overall label
    if total >= 80:
        overall_label = "Critical"
    elif total >= 60:
        overall_label = "High"
    elif total >= 40:
        overall_label = "Medium"
    else:
        overall_label = "Low"

    return {
        "quantum_risk_estimate": total,
        "risk_label": overall_label,
        "component_risks": component_risks,
    }
