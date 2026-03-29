"""
Quantum Risk Engine module.
Calculates quantum vulnerability scores based on TLS analysis.
"""

from datetime import datetime, timezone
import os
import sys

# Ensure analysis folder can import from other modules if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from algorithm_classifier import classify_algorithm


import random

def calculate_key_exchange_risk(kex: str) -> int:
    kex_upper = kex.upper()
    if not kex_upper or kex_upper == 'UNKNOWN':
        return 90
    if "KYBER" in kex_upper or "ML-KEM" in kex_upper or "PQ" in kex_upper:
        return 0
    if "X25519" in kex_upper:
        return 60
    if "ECDHE" in kex_upper:
        return 80
    if "DHE" in kex_upper or "RSA" in kex_upper:
        return 90
    return 90

def calculate_signature_risk(sig: str) -> int:
    sig_upper = sig.upper()
    if not sig_upper or sig_upper == 'UNKNOWN':
        return 80
    if "DILITHIUM" in sig_upper or "FALCON" in sig_upper or "ML-DSA" in sig_upper or "SPHINCS" in sig_upper or "SLH-DSA" in sig_upper:
        return 0
    if "ED25519" in sig_upper:
        return 60
    if "ECDSA" in sig_upper:
        return 70
    if "RSA" in sig_upper or "DSA" in sig_upper:
        return 80
    return 80

def calculate_tls_version_risk(tls_version: str) -> int:
    if not tls_version:
        return 100
    if "1.3" in tls_version:
        return 20
    if "1.2" in tls_version:
        return 50
    if "1.1" in tls_version:
        return 80
    if "1.0" in tls_version or "SSL" in tls_version.upper():
        return 100
    return 100

def calculate_key_size_risk(key_alg: str, key_size: int) -> int:
    if not key_alg or not key_size:
        return 90
    alg_upper = key_alg.upper()
    if "RSA" in alg_upper:
        if key_size <= 1024:
            return 90
        if key_size <= 2048:
            return 60
        if key_size <= 3072:
            return 40
        return 30
    elif "EC" in alg_upper:
        if key_size <= 256:
            return 60
        if key_size <= 384:
            return 40
        return 30
    return 50

def calculate_certificate_validity_risk(expiry: str) -> int:
    if not expiry:
        return 30
    try:
        exp_date = datetime.fromisoformat(expiry)
        if exp_date.tzinfo is None:
            exp_date = exp_date.replace(tzinfo=timezone.utc)
        days_left = (exp_date - datetime.now(timezone.utc)).days
        if days_left < 30:
            return 30
        if days_left < 90:
            return 20
        if days_left < 180:
            return 10
        return 0
    except ValueError:
        return 30

def calculate_cipher_strength_risk(cipher_suite: str) -> int:
    if not cipher_suite:
        return 20
    cipher_upper = cipher_suite.upper()
    if "AES_256" in cipher_upper or "AES256" in cipher_upper:
        return 5
    if "CHACHA20" in cipher_upper:
        return 10
    if "AES_128" in cipher_upper or "AES128" in cipher_upper:
        return 15
    return 20

def calculate_hndl_risk(hndl_level: str) -> int:
    hndl_upper = (hndl_level or "").upper()
    if hndl_upper == "HIGH" or hndl_upper == "CRITICAL":
        return 10
    if hndl_upper == "MEDIUM":
        return 5
    if hndl_upper == "LOW":
        return 0
    return 0

def get_risk_label(score: int) -> str:
    if score < 30:
        return "Quantum Safe"
    elif score <= 60:
        return "Transitioning"
    elif score <= 80:
        return "Quantum Vulnerable"
    else:
        return "Critical"

def calculate_quantum_risk(tls_result: dict, cert_meta: dict, hndl_level: str = "") -> dict:
    """
    Calculate a multi-factor Quantum Risk Score based on normalized weights.
    """
    tls_version = tls_result.get("tls_version", "")
    cipher_suite = tls_result.get("cipher_suite", "")
    key_alg = cert_meta.get("key_algorithm", "unknown")
    key_size = cert_meta.get("key_size", 0)
    sig_alg = cert_meta.get("signature_algorithm", "unknown")
    expiry = cert_meta.get("certificate_expiry", "")

    # 1. Classify algorithms to extract KEX and SIG families
    classification = classify_algorithm(cipher_suite, key_alg, sig_alg)
    kex = classification["key_exchange"]
    sig = classification["signature"]

    # 2. Get individual raw component scores (each 0 - 100)
    raw_kex = calculate_key_exchange_risk(kex)
    raw_sig = calculate_signature_risk(sig)
    raw_tls = calculate_tls_version_risk(tls_version)
    raw_key = calculate_key_size_risk(key_alg, key_size)
    raw_cert = calculate_certificate_validity_risk(expiry)
    raw_cipher = calculate_cipher_strength_risk(cipher_suite)

    # 3. Define normalized weights
    weights = {
        "key_exchange": 0.30,
        "signature": 0.20,
        "tls_version": 0.15,
        "key_size": 0.15,
        "certificate": 0.10,
        "cipher": 0.10
    }

    # 4. Calculate weighted total score
    score = (
        raw_kex * weights["key_exchange"] +
        raw_sig * weights["signature"] +
        raw_tls * weights["tls_version"] +
        raw_key * weights["key_size"] +
        raw_cert * weights["certificate"] +
        raw_cipher * weights["cipher"]
    )

    # 5. Add HNDL penalty and random variation
    hndl_penalty = calculate_hndl_risk(hndl_level)
    noise = random.uniform(-2, 2)
    score += hndl_penalty + noise
    
    # 6. Clamp between 0 and 100
    total_score = int(max(0, min(100, round(score))))

    return {
        "total_score": total_score,
        "risk_label": get_risk_label(total_score),
        "breakdown": {
            "key_exchange": raw_kex,
            "signature": raw_sig,
            "tls_version": raw_tls,
            "key_size": raw_key,
            "certificate": raw_cert,
            "cipher": raw_cipher
        }
    }
