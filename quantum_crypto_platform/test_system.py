"""
Quantum Crypto Intelligence Platform -- Complete System Validation
==================================================================
Tests Parts 1-12 using neilpatel.com as the target domain.
Requires server on port 8000 and worker running.
"""

import time
import json
import sys
import urllib.request
import urllib.error

BASE = "http://localhost:8000"
PASS = 0
FAIL = 0
TOKEN = None
SCAN_ID = None


def api(method, path, data=None, auth=False):
    url = BASE + path
    req = urllib.request.Request(url, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    if auth and TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode()), resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body), e.code
        except Exception:
            return {"_body": body}, e.code
    except Exception as e:
        return {"_error": str(e)}, 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}" + (f" -- {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))
    return condition


print("=" * 70)
print("  QUANTUM CRYPTO INTELLIGENCE -- COMPLETE SYSTEM VALIDATION")
print("  Target: neilpatel.com")
print("=" * 70)

# === STEP 1: Server ===
print("\n-- STEP 1: Server Startup --")
data, code = api("GET", "/openapi.json")
check("Server responds", code == 200)
check("OpenAPI schema available", "openapi" in str(data))

# === STEP 3: Register ===
print("\n-- STEP 3: Register User --")
data, code = api("POST", "/auth/register", {"email": "tester@example.com", "password": "testpassword123"})
if code == 409:
    check("User already exists (OK)", True, "skipping to login")
else:
    check("Registration successful", code == 200, f"code={code}")
    check("Token returned", data.get("token") is not None)
    TOKEN = data.get("token")

# === STEP 4: Login ===
print("\n-- STEP 4: Login --")
data, code = api("POST", "/auth/login", {"email": "tester@example.com", "password": "testpassword123"})
check("Login successful", code == 200)
check("JWT token returned", data.get("token") is not None)
TOKEN = data.get("token")
USER_ID = data.get("user_id")
check("User ID returned", USER_ID is not None, f"user_id={USER_ID}")

# Verify /auth/me
data, code = api("GET", "/auth/me", auth=True)
check("GET /auth/me works", code == 200 and data.get("email") == "tester@example.com")

# === STEP 5: Scan neilpatel.com ===
print("\n-- STEP 5: Scan neilpatel.com (authenticated) --")
data, code = api("POST", "/scan", {"target": "neilpatel.com"}, auth=True)
SCAN_ID = data.get("scan_id")
status = data.get("status")
check("Scan created", SCAN_ID is not None, f"scan_id={SCAN_ID}, status={status}")
check("Status is queued", status == "queued")

# Wait for completion
print("\n  Waiting for scan to complete...")
completed = False
for i in range(45):
    time.sleep(2)
    data, _ = api("GET", f"/scan/{SCAN_ID}")
    pstatus = data.get("status", "unknown")
    if pstatus == "completed":
        completed = True
        print(f"  Scan completed after ~{(i+1)*2}s")
        break
    elif pstatus == "failed":
        print(f"  Scan FAILED after ~{(i+1)*2}s")
        break
    else:
        sys.stdout.write(f"\r  ... status={pstatus} ({(i+1)*2}s)   ")
        sys.stdout.flush()
print()
check("Scan completed successfully", completed)

if not completed:
    print("  WARNING: Scan did not complete. Some tests may fail.\n")

# === STEP 6: Cache Test ===
print("\n-- STEP 6: Cache Test --")
data, code = api("POST", "/scan", {"target": "neilpatel.com"}, auth=True)
check("Second scan returns cached", data.get("status") == "cached", f"status={data.get('status')}")
check("Same scan_id", data.get("scan_id") == SCAN_ID)

data, code = api("POST", "/scan?force=true", {"target": "neilpatel.com"}, auth=True)
check("Force scan bypasses cache", data.get("status") == "queued")

data, code = api("GET", "/cache/status/neilpatel.com")
check("Cache status endpoint", data.get("cached") == True)

# === STEP 2: Worker Validation ===
print("\n-- STEP 2: Worker Validation --")
check("Worker processed job", completed, "scan completed = worker works")

# === STEP 7: Domain Discovery ===
print("\n-- STEP 7: Domain Discovery --")
data, code = api("GET", f"/scan/{SCAN_ID}/assets")
assets = data.get("assets", [])
check("Assets returned", len(assets) > 0, f"{len(assets)} assets")
check("neilpatel.com in assets", "neilpatel.com" in assets)

# === STEP 8: TLS Scanner ===
print("\n-- STEP 8: TLS Scanner --")
data, code = api("GET", f"/scan/{SCAN_ID}/tls")
tls = data.get("results", [])
check("TLS results returned", len(tls) > 0, f"{len(tls)} results")
if tls:
    t = tls[0]
    check("  Has hostname", t.get("hostname") is not None, t.get("hostname", ""))
    check("  Has tls_version", t.get("tls_version") is not None, t.get("tls_version", ""))
    check("  Has cipher_suite", t.get("cipher_suite") is not None, str(t.get("cipher_suite", ""))[:50])

# === STEP 9: Algorithm Intelligence ===
print("\n-- STEP 9: Algorithm Intelligence --")
data, code = api("GET", f"/scan/{SCAN_ID}/algorithm-analysis")
algo = data.get("results", [])
check("Algorithm analysis returned", len(algo) > 0, f"{len(algo)} results")
if algo:
    a = algo[0]
    check("  Has key_exchange", a.get("key_exchange") is not None, a.get("key_exchange", ""))
    check("  Has encryption", a.get("encryption") is not None, a.get("encryption", ""))
    check("  Has quantum_risk_estimate", a.get("quantum_risk_estimate") is not None, str(a.get("quantum_risk_estimate")))

# === STEP 10: Quantum Risk ===
print("\n-- STEP 10: Quantum Risk Engine --")
data, code = api("GET", f"/scan/{SCAN_ID}/quantum-risk")
qr = data.get("results", [])
check("Quantum risk returned", len(qr) > 0, f"{len(qr)} results")
if qr:
    q = qr[0]
    check("  Has risk_score", q.get("risk_score") is not None, str(q.get("risk_score")))
    check("  Has risk_label", q.get("risk_label") is not None, q.get("risk_label", ""))
    check("  Score 0-100", 0 <= q.get("risk_score", -1) <= 100)

# === STEP 11: HNDL Detection ===
print("\n-- STEP 11: HNDL Detection --")
data, code = api("GET", f"/scan/{SCAN_ID}/hndl")
hndl = data.get("targets", [])
check("HNDL results returned", len(hndl) > 0, f"{len(hndl)} targets")
if hndl:
    h = hndl[0]
    check("  Has service type", h.get("service") is not None, h.get("service", ""))
    check("  Has multiplier", h.get("multiplier") is not None, str(h.get("multiplier")))

# === STEP 12: Report ===
print("\n-- STEP 12: Report / Graph Data --")
data, code = api("GET", f"/scan/{SCAN_ID}/report")
check("Report endpoint works", data.get("scan_id") is not None)
check("  Has assets", len(data.get("assets", [])) > 0)
check("  Has tls_results", len(data.get("tls_results", [])) > 0)
check("  Has quantum_risk", len(data.get("quantum_risk", [])) > 0)
check("  Has hndl_results", len(data.get("hndl_results", [])) > 0)
check("  Has algorithm_analysis", len(data.get("algorithm_analysis", [])) > 0)

# === STEP 13: Dashboard APIs ===
print("\n-- STEP 13: Dashboard API Verification --")
endpoints = [
    f"/scan/{SCAN_ID}", f"/scan/{SCAN_ID}/assets", f"/scan/{SCAN_ID}/tls",
    f"/scan/{SCAN_ID}/quantum-risk", f"/scan/{SCAN_ID}/hndl",
    f"/scan/{SCAN_ID}/algorithm-analysis", f"/scan/{SCAN_ID}/report",
    "/intelligence/registry", "/cache/status/neilpatel.com",
]
for ep in endpoints:
    data, code = api("GET", ep)
    check(f"  GET {ep}", code == 200)

# === STEP 15: User Dashboard API ===
print("\n-- STEP 15: User Dashboard API --")
data, code = api("GET", "/user/scans", auth=True)
check("GET /user/scans works", code == 200)
scans = data.get("scans", [])
check("User has scans", len(scans) > 0, f"{len(scans)} scans")
has_neilpatel = any(s.get("domain") == "neilpatel.com" for s in scans)
check("neilpatel.com in user scans", has_neilpatel)
if scans:
    check("  Scan has risk_score", scans[0].get("risk_score") is not None, str(scans[0].get("risk_score")))

# === Threat Intel Registry ===
print("\n-- Threat Intelligence Registry --")
data, code = api("GET", "/intelligence/registry")
algos = data.get("algorithms", [])
check("Registry has algorithms", len(algos) > 0, f"{len(algos)} algorithms")

# === STEP 16: Error Handling ===
print("\n-- STEP 16: Error Handling --")
data, code = api("POST", "/scan", {"target": "not valid domain!!!"})
check("Invalid domain rejected", code == 400, f"code={code}")

data, code = api("GET", "/user/scans")
check("Unauthenticated /user/scans rejected", code == 401)

data, code = api("POST", "/auth/login", {"email": "wrong@example.com", "password": "wrong"})
check("Bad login rejected", code == 401)

# === SUMMARY ===
print("\n" + "=" * 70)
print(f"  RESULTS: {PASS} PASSED  |  {FAIL} FAILED  |  {PASS + FAIL} TOTAL")
print("=" * 70)

if FAIL == 0:
    print("\n  ALL TESTS PASSED -- System is fully operational!\n")
else:
    print(f"\n  WARNING: {FAIL} test(s) failed. Review output above.\n")

sys.exit(0 if FAIL == 0 else 1)
