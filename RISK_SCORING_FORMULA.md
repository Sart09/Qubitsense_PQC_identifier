# Quantum Risk Scoring — Formula Reference

One page, the whole model. Implemented in `analysis/quantum_risk_engine.py`; every number below is served live at `GET /scoring-model` and embedded in every exported report, so any score on the platform can be traced back to this exact formula.

Every input is measured from the real TLS handshake and certificate — no random values, no hardcoded results.

## Stage 1 — Weighted composite (10 components, 0–100 each, higher = worse)

| Weight | Component | What it measures |
|-------:|-----------|-------------------|
| 22% | Key Exchange | Shor-breakability of the handshake — the core Harvest-Now-Decrypt-Later risk |
| 14% | Certificate Signature | Shor-breakability of the cert signature (identity forgery) |
| 12% | Public Key Strength | Key size vs. Shor's algorithm cost |
| 10% | Forward Secrecy | Without PFS, one recovered key decrypts every past session |
| 10% | TLS Protocol Version | Handshake/protocol hygiene (1.3 best, SSL worst) |
| 8% | Symmetric Cipher Strength | Grover's algorithm halves effective key strength |
| 7% | Certificate Trust Chain | Expired / self-signed / hostname-mismatch findings |
| 6% | Cipher Mode (AEAD) | GCM/ChaCha20-Poly1305 vs. padding-oracle-prone CBC/ECB |
| 6% | Hash Function Strength | Collision resistance (SHA-1/MD5 already broken today) |
| 5% | Certificate Lifetime Hygiene | Rotation discipline — the capability PQC migration needs |

```
composite = Σ (raw_component_score × weight)        // 0–100, weights sum to 1.00
```

## Stage 2 — Floor gates

A pure weighted average lets good hygiene mask a fatal flaw (e.g. TLS 1.3 + AES-256 scores well on 8 of 10 components while its key exchange stays 100% Shor-breakable). The floors encode the non-negotiable structural facts a weighted average would otherwise dilute — they only ever raise a score, never lower it:

| Floor | Trigger |
|------:|---------|
| **81** | Classically broken *today*: MD5/SHA-1 signature, RC4/DES/NULL cipher, SSLv2/v3, or key ≤1024 bits |
| **45** | No post-quantum algorithm anywhere (neither key exchange nor signature) |
| **30** | Partial PQC — exactly one of key exchange / signature is post-quantum |

Floors **map** the composite across the band above them rather than clamping to a single number, so two hosts tripping the same gate stay ordered by their real hygiene differences instead of collapsing onto one score:

```
mapped = floor + (composite / 100) × (band_top − floor)
gated  = max(composite, mapped)
```

## Stage 3 — HNDL amplification

Harvest value scales existing exposure — it can never manufacture risk where the crypto is already quantum-safe:

```
uplift = gated × (service_multiplier − 1.0) × 0.15
```
`service_multiplier` is the measured harvest-value multiplier from `analysis/hndl_detector.py`: **1.0** (plain HTTPS) up to **2.0** (VPN/IPSec/financial APIs — long-lived, high-value traffic).

## Stage 4 — Clamp and classify

```
final_score = clamp( round(gated + uplift), 0, 100 )
```

| Score | Label |
|------:|-------|
| 0–29 | Quantum Safe |
| 30–44 | Transitioning |
| 45–80 | Quantum Vulnerable |
| 81–100 | Critical |

## Fleet level — Enterprise Rating & Posture Tier

```
enterprise_rating = (100 − average_risk_score) × 10        // 0–1000
```

| Rating | Tier | Avg. risk |
|-------:|------|----------:|
| 850–1000 | Elite-PQC | 0–15 |
| 700–849 | Advanced | 15–30 |
| 550–699 | Standard | 30–45 |
| 400–549 | Developing | 45–60 |
| 0–399 | Legacy | 60–100 |

A single host's own tier uses the same two-step formula on its own score, so a host and the fleet it belongs to are never scored by two different definitions of the same boundary.
