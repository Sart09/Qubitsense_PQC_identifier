# Qubitsense — Post-Quantum Cryptography Identifier

A full-stack enterprise security platform that scans domains for **post-quantum cryptographic risk**, evaluating TLS configurations, cipher suites, certificate health, and **Harvest Now, Decrypt Later (HNDL)** exposure across entire subdomain estates.

Built for **Indian banking infrastructure** — tested on enterprise domains with 200+ subdomains.

---

## Features

### 🔍 Domain Discovery Engine
- **Multi-source Subdomain Discovery** — CT logs, AlienVault OTX (with API key support), DNS brute-force (200+ categorized wordlist), and passive DNS record mining
- **Dual-Stack Resolution** — A + AAAA record resolution catches IPv6-only hosts
- **CNAME Chain Following** — Discovers CDN-hosted subdomains missed by basic lookups
- **SOA + SRV Record Mining** — Extracts service endpoints from DNS infrastructure
- **SPF/DKIM/DMARC Extraction** — Regex-based extraction from TXT records
- **Ghost Filtering** — Automatically removes subdomains with no DNS A record before scanning
- **100 Concurrent DNS Workers** — High-throughput brute-force enumeration

### 🔒 TLS & Certificate Analysis
- **Async Concurrent TLS Scanner** — 50 parallel TLS handshakes with 12s timeout
- **Full Certificate Inspection** — TLS version, cipher suite, key algorithm, key size, signature algorithm, certificate expiry
- **Failure Classification** — TCP_TIMEOUT, TCP_REFUSED, TLS_HANDSHAKE_FAIL, CERT_MISMATCH categorized separately

### ⚛️ Quantum Risk Engine
- **Per-Host Quantum Risk Scores** — 0–100 composite from **10 independently weighted components** (weights sum to exactly 1.00), plus structural floor gates and HNDL amplification. Full model in [Scoring Methodology](#-scoring-methodology)
- **Inspectable Methodology** — every weight, band and threshold is served live at `GET /scoring-model`, rendered in the dashboard's *Scoring Methodology* panel, and embedded in every exported report
- **HNDL Detection** — Identifies which subdomains are highest-value harvest targets, and amplifies their score using the real measured service multiplier
- **Algorithm Intelligence** — Classifies cipher components and maps them to quantum vulnerability estimates
- **Cryptographic Bill of Materials (CBOM)** — Full inventory of every algorithm in use

### 🤖 AI Assistant "Qubit"
- **Groq (Llama 3.3 70B) Powered** — Natural language scanning and risk intelligence, via a server-side proxy that never exposes the API key to the browser
- **Report Analysis** — On a scan's dashboard page, ask Qubit to summarize or analyze the findings and it answers from that scan's real numbers (risk scores, failure breakdown, highest-risk hosts) — not generic platform knowledge
- **Voice-Driven Operation** — Speak a domain name, agent scans it automatically
- **Available on Every Page, No Login Required** — Persistent floating widget across the entire platform, usable by anonymous visitors like the rest of the app

### 🔐 Authentication, MFA & Admin Console
- **Two-Factor Authentication (TOTP)** — real, working authenticator-app 2FA (`pyotp` + QR enrollment), independent of any external identity provider so it works out of the box. Login becomes a two-step challenge for accounts with it enabled; manage enrollment from **Security** (`/security`)
- **Supabase Auth — ready to connect** — the identity backend is fully wired to route through Supabase Auth (`auth/supabase_client.py`) the moment `SUPABASE_URL`/`SUPABASE_ANON_KEY`/`SUPABASE_SERVICE_ROLE_KEY` are set in `.env`; with them blank, the app runs on local bcrypt auth exactly as before — same endpoints, same responses. See [Configuration](#configuration)
- **Role-Based Admin Console** (`/admin`) — a real user directory (email, role, MFA status, scan count, last login), a platform-wide activity feed built from an actual login/MFA audit table (not sampled), promote/demote and activate/deactivate controls, and fleet-wide analytics across every user's scans. Guarded server-side (`backend/admin_routes.py`'s `require_admin`) independent of any client-side check
- **Account Lockout Takes Effect Immediately** — deactivating a user is enforced inside the shared `get_current_user` dependency every protected route already passes through, so it doesn't wait out an existing session's 24h token life

### 🗑️ Scan Lifecycle & Integrity
- **Delete a Scan Everywhere at Once** — One action removes a scan from history, analytics, the domain leaderboard, trends, the 24-hour result cache and scheduler run history. Owner-scoped and auth-gated; confirmation names the exact scan before anything is destroyed. Refuses to delete a queued/running scan (the worker would recreate orphan rows), and clears the `scheduled_scans.last_scan_id` pointer so no schedule dangles
- **Zero-Host Scans Fail Honestly** — A scan of a non-existent or parked domain used to be marked `completed`, render a dashboard of zeroes, and export a fully-formed but entirely empty report indistinguishable from a catastrophic real estate. Such scans are now marked **failed** with the reason recorded, are **not cached**, show an explanatory banner on the dashboard with report downloads disabled, and all three report endpoints return **409** rather than producing an empty document

### 📋 Scan Queue Management
- **Scan Now** — Priority scan that pauses the entire queue and runs immediately
- **Add to Queue** — Standard FIFO queuing for batch scanning
- **Stop Running Scans** — Cancel any running, queued, or paused scan from the History panel
- **Auto-Resume** — Paused jobs automatically resume after a priority scan completes

### 🗓️ Automated Scheduling
- **Recurring Scans** — Daily, weekly, monthly, or custom interval scheduling per domain
- **Risk Trend Tracking** — Compares quantum risk scores across scan history
- **Run-Now Override** — Trigger any scheduled scan instantly out of band
- **Execution History** — Full run log with risk deltas and failure tracking

### 📊 Dashboard & Reporting
- **Persistent Sidebar Navigation** — One shared component (`components/sidebar.js`) across every app page: **Home** (`/home` — your scanned-domain card grid), **Schedule Scan**, **Scan History & Analytics**. Collapsible to an icon rail, off-canvas on mobile, with active-section highlighting. Home is the domain inventory, not the scan-entry page — `/` remains the anonymous landing page and is reached via **+ New Scan**
- **Scan History & Analytics** — Cross-scan intelligence for your whole estate: domain posture leaderboard by tier, riskiest subdomains with the weighted component driving each score, per-domain trend with improved/regressed verdicts, and a fleet-wide crypto rollup (TLS/key/kex/hash distributions, weakest-component clustering, certificate findings). Replaces the former My Scans page
- **Live Risk Dashboard** — Risk scores, HNDL exposure, cipher breakdowns, network graph
- **Live Scan Progress** — Terminal log stream with phase-by-phase progress bars, polled every 2s
- **Scan History** — Full timestamped history per domain with TLS counts and failure stats
- **PDF Export** — One-click whole-scan report generation
- **Per-Host Remediation PDF** — Every asset in the drill-down modal has its own **Download Remediation PDF** button (`GET /asset/{id}/report/pdf`): that host's full 10-component score derivation, certificate findings, HNDL exposure, and a prioritized fix checklist — generated from the same shared recommendation logic (`analysis/remediation.py`) the on-screen panel uses, so the two can never disagree
- **JSON Export** — Full aggregated report for programmatic consumption
- **Contrast-Audited Theme** — Every page shares one design system (`frontend/components/pnb-theme.css`): text/background pairs are verified ≥ 4.5:1 (WCAG AA) via computed relative-luminance contrast, not eyeballed. This replaced an earlier per-page `tailwind.config` color-remap layered under `!important` CSS overrides — two inconsistent layers that had already produced real invisible-text bugs before this rewrite

---

## Architecture

```
├── backend/                    # FastAPI server, database, models
│   ├── server.py               # Main entry-point + all REST API routes
│   ├── database.py             # SQLite schema + WAL connection management
│   ├── models.py                # Pydantic request/response models
│   ├── admin_routes.py         # Admin console API (users, activity, stats)
│   ├── report_export.py        # JSON/PDF/CycloneDX report builders (whole-scan + per-host)
│   ├── job_manager.py          # Scan job creation
│   ├── result_manager.py       # TLS/HNDL/algorithm result storage
│   ├── domain_parser.py        # URL normalization
│   └── upload_parser.py        # QR/barcode document parsing
│
├── scanner/                    # Network scanning modules
│   ├── tls_scanner_async_concurrent.py  # Async 50-worker TLS scanner
│   ├── dns_enum.py             # 200+ wordlist brute-force + CNAME/SRV/SOA
│   ├── domain_discovery.py     # Multi-source orchestrator (CT + OTX + DNS)
│   ├── ct_logs.py              # Certificate Transparency log lookup
│   └── certificate_parser.py  # DER certificate parsing
│
├── analysis/                   # Risk analysis & classification
│   ├── quantum_risk_engine.py  # Composite quantum risk scoring
│   ├── remediation.py          # Shared per-host recommendation logic (JSON + PDF)
│   ├── cipher_parser.py        # Cipher suite component extraction
│   ├── algorithm_classifier.py # Cryptographic family classification
│   ├── quantum_estimator.py    # Per-algorithm quantum risk estimates
│   ├── service_classifier.py   # Subdomain service type detection
│   └── hndl_detector.py        # HNDL risk multiplier calculation
│
├── intelligence/               # Threat intelligence & PQC registry
│   ├── registry_updater.py     # Algorithm registry seeding & lookup
│   └── threat_feed.py          # Live threat intelligence updates
│
├── auth/                       # Authentication system
│   ├── auth_routes.py          # Register / Login / MFA / Me endpoints
│   ├── jwt_handler.py          # JWT token generation & validation
│   ├── password_utils.py       # bcrypt hashing
│   ├── mfa.py                  # TOTP secret generation, QR codes, code verification
│   └── supabase_client.py      # Supabase Auth REST client (inert until configured)
│
├── workers/                    # Background processing
│   ├── scan_worker.py          # Main scan pipeline (Discovery → TLS → Storage)
│   ├── job_fetcher.py          # Priority-aware job queue (FIFO + priority override)
│   └── scheduler.py            # Recurring scan scheduler
│
├── frontend/                   # Web UI
│   ├── index.html              # Scanner landing — Scan Now + Add to Queue
│   ├── login.html              # Login / Register / MFA challenge
│   ├── security.html           # Two-factor authentication setup & management
│   ├── admin.html               # Admin console — users, roles, activity, stats
│   ├── dashboard.html          # Full scan results dashboard
│   ├── scan_progress.html      # Live progress tracker (2s poll)
│   ├── user_dashboard.html     # Per-user scan history + stop controls
│   ├── schedules.html          # Schedule management UI
│   ├── css/ai-agent.css        # AI agent widget styles (WCAG AA)
│   └── components/             # Shared theme (pnb-theme.css), sidebar, charts, graph viewer
│
├── start.bat                   # Windows one-command stack launcher
├── start.sh                    # Linux/Mac one-command stack launcher
└── test_system.py              # End-to-end system validation
```

---

## Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/Sart09/Qubitsense_PQC_identifier.git
cd Qubitsense_PQC_identifier

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Configure environment
cp .env.example .env
```

Edit `.env` and set your Groq API key (see `.env.example` for the full list of variables):
```env
GROQ_API_KEY=your_key_here
JWT_SECRET=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
```

> [!IMPORTANT]
> The AI Assistant (Qubit) requires a valid Groq API key in `.env`.
> Without it, the rest of the app runs normally — only the chat widget shows an error.
> Get a free key at https://console.groq.com/keys

A default admin account is seeded automatically on first startup — no setup step needed:
```
email:    nick@gmail.com
password: Hero44@55
```
It's idempotent (only created once; a password you change later is never reset by a restart) and is promoted to `role=admin` even if it already exists as a regular account. Any other email listed in `ADMIN_EMAILS` (`.env`) is auto-promoted to admin on registration too.

#### Connecting Supabase Auth (optional)

Authentication works fully today on local bcrypt — this step is only needed if you want login/registration backed by a real Supabase project instead:

1. Create a free project at https://supabase.com (a couple of minutes, no card required).
2. In the project dashboard, go to **Settings → API** and copy the **Project URL**, **anon public key**, and **service_role key**.
3. Paste them into `.env`:
   ```env
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_ANON_KEY=your_anon_key
   SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
   ```
4. Restart the server. New registrations are now mirrored into Supabase Auth and logins are verified against it, with automatic fallback to the local password hash if Supabase is unreachable. No other code change is required. Two-factor authentication (`auth/mfa.py`) is unaffected either way — it's this app's own TOTP implementation, not Supabase's, so it works identically before and after connecting.

### Running

```bash
# Windows — starts all 3 processes at once
.\start.bat

# Linux/Mac
./start.sh
```

Or run each process manually:

```bash
# 1. API Server (http://localhost:8000)
python backend/server.py

# 2. Scan Worker
python workers/scan_worker.py

# 3. Scheduler
python workers/scheduler.py
```

---

## API Reference

### Scan Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Submit domain to queue |
| `POST` | `/scan/priority` | **Priority scan** — pauses queue, runs immediately |
| `POST` | `/scan/{id}/stop` | **Stop** a running/queued scan |
| `GET`  | `/scan/{id}` | Poll scan status |
| `GET`  | `/scan/{id}/logs` | Live execution log stream |
| `GET`  | `/scan/{id}/assets` | Discovered subdomains |
| `GET`  | `/scan/{id}/tls` | TLS scan results |
| `GET`  | `/scan/{id}/quantum-risk` | Quantum risk scores |
| `GET`  | `/scan/{id}/hndl` | HNDL detection results |
| `GET`  | `/scan/{id}/algorithm-analysis` | Cipher & algorithm breakdown |
| `GET`  | `/scan/{id}/failures` | Categorized scan failures |
| `DELETE` | `/scan/{id}` | **Delete a scan permanently** (auth, owner-scoped) — removes it from history, analytics, leaderboards, trends, the result cache and scheduler history in one operation. Returns 409 if the scan is still queued/running |
| `GET`  | `/scan/{id}/report` | Full aggregated JSON report (includes the scoring model). **409 if the scan scanned 0 hosts** |
| `GET`  | `/scan/{id}/report/pdf` | Printable PDF report, generated server-side |
| `GET`  | `/scan/{id}/report/cyclonedx` | CycloneDX 1.6 CBOM export |
| `POST` | `/scan/upload` | Upload QR/barcode document |

### Scoring Model

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/scoring-model` | Complete scoring methodology — component weights, floor rules, risk bands, posture tiers |

### Cross-Scan Analytics

All analytics endpoints require auth and are scoped to the caller's own scans
(via `user_scans`). Scan status is read from `scans`, never from the stale
`user_scans.status` column.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/analytics/overview` | Fleet totals, rating, tier, risk-band spread, PQC adoption |
| `GET`  | `/analytics/history` | Every scan with per-scan posture (replaces the old My Scans page) |
| `GET`  | `/analytics/domains` | Per-domain posture leaderboard, worst first |
| `GET`  | `/analytics/domains/{domain}/trend` | Rating movement across repeat scans + improved/regressed verdict |
| `GET`  | `/analytics/assets/risky?limit=N` | Riskiest hosts estate-wide, deduped to each host's latest scan |
| `GET`  | `/analytics/crypto` | Fleet algorithm inventory, weakest-component clustering, cert findings |

### Domain History

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/domains` | List all scanned domains |
| `GET`  | `/domain/{domain}/scans` | Scan history for a domain |
| `GET`  | `/asset/{id}` | Per-asset drill-down details |
| `GET`  | `/asset/{id}/report/pdf` | Per-host remediation PDF — score derivation, cert/HNDL findings, prioritized fix checklist |

### Scheduling

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/schedules/create` | Create recurring scan schedule |
| `GET`  | `/api/schedules/list` | List user's schedules |
| `PATCH`| `/api/schedules/{id}/pause` | Pause a schedule |
| `PATCH`| `/api/schedules/{id}/resume` | Resume a schedule |
| `POST` | `/api/schedules/{id}/run-now` | Trigger immediate scan |
| `GET`  | `/api/schedules/{id}/history` | Run history with risk deltas |
| `DELETE`| `/api/schedules/{id}` | Delete a schedule |

### Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register new user (mirrored into Supabase Auth if configured) |
| `POST` | `/auth/login` | Login. Returns a JWT, or `{mfa_required: true, challenge_token}` if the account has 2FA enabled |
| `POST` | `/auth/mfa/verify` | Complete an MFA-challenged login with a 6-digit code |
| `POST` | `/auth/mfa/enroll` | Start 2FA setup — returns a TOTP secret + QR code (requires an existing session) |
| `POST` | `/auth/mfa/activate` | Confirm enrollment with one valid code; only then does the account require 2FA |
| `POST` | `/auth/mfa/disable` | Turn off 2FA (requires current password) |
| `GET`  | `/auth/me` | Current user info — email, role, MFA status |
| `GET`  | `/user/scans` | User's scan history |

### Admin

Every route below requires an active admin account (`backend/admin_routes.py`'s `require_admin`), independent of whatever the frontend shows or hides.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/admin/users` | Every account — role, status, MFA, scan count, last login |
| `GET`  | `/admin/users/{id}` | One user's profile, scans, and real login/MFA activity trail |
| `PATCH`| `/admin/users/{id}/role` | Promote/demote (blocked if it would leave zero active admins) |
| `PATCH`| `/admin/users/{id}/status` | Activate/deactivate an account (same last-admin protection) |
| `GET`  | `/admin/activity` | Platform-wide feed: real login/MFA events + scan creation, newest first |
| `GET`  | `/admin/stats` | Fleet totals: users, scans, admins, MFA adoption, 7-day active users |
| `GET`  | `/admin/analytics/*` | Same analytics as `/analytics/*` (below), fleet-wide or for one `?user_id=` |

---

## 🧮 Scoring Methodology

Every risk number the platform reports comes from one module —
`analysis/quantum_risk_engine.py` — and is derived from signals actually
measured during the TLS handshake and certificate parse. There are no random
values, no placeholder constants, and no per-host hardcoded results. When a
signal cannot be measured it is scored as *unknown* with a documented
conservative default rather than silently skipped.

The model is **inspectable at runtime**: `GET /scoring-model` serves the
constants below verbatim from the engine, the dashboard renders them in its
*Scoring Methodology* panel, and every exported report (JSON, PDF, CycloneDX)
embeds them — so any score can be audited against the exact model that
produced it.

### Stage 1 — Weighted composite (10 components)

Each component returns a raw 0–100 score (higher = worse). Weights sum to
exactly **1.00**, so the composite is itself on a 0–100 scale.

| Weight | Component | What it measures |
|-------:|-----------|------------------|
| **22%** | Key Exchange | Shor-breakability of the handshake. Nothing classical scores below 78 — ECDHE, X25519 and DHE are all fully broken by a CRQC. Only ML-KEM / Kyber hybrid scores 0. |
| **14%** | Certificate Signature | Shor-breakability of the cert signature. MD5 (100) and SHA-1 (95) signatures escalate above merely quantum-exposed options because they are forgeable *today*. |
| **12%** | Public Key Strength | Shor cost proxy. Classical keys never score below 50 — a 4096-bit RSA key falls to Shor just as a 2048-bit one does. Keys ≤ 1024 bits are treated as already broken. |
| **10%** | Forward Secrecy | Without PFS, one recovered key decrypts *every* recorded session. Same eventual quantum threat, radically different blast radius — so it is weighted independently of key exchange. |
| **10%** | TLS Protocol Version | Protocol hygiene only (1.3 → 0, 1.2 → 45, 1.1 → 80, 1.0 → 92, SSL → 100). Handshake quantum exposure lives in the two components above, so weights never double-count. |
| **8%** | Symmetric Cipher Strength | Grover square-roots the search space, so an *n*-bit key retains *n*/2 bits of post-quantum security. AES-256 → 0 (clears NIST's 128-bit PQ bar); AES-128 → 45 (only 64-bit); 3DES → 90; RC4/DES → 100. |
| **7%** | Certificate Trust Chain | Real validation findings: expired (100), self-signed (85), hostname mismatch (80). Findings compound. Unvalidated → 25, never "clean". |
| **6%** | Cipher Mode / AEAD | GCM / CCM / ChaCha20-Poly1305 → 0; CBC → 70 (BEAST, Lucky13, POODLE); CTR → 60; ECB → 100. TLS 1.3 is AEAD-only by spec, so an unnamed mode there is provably AEAD. |
| **6%** | Hash Function Strength | SHA-384/512 → 0, SHA-256 → 10, SHA-1 → 90, MD5 → 100. A bare trailing `SHA` in a suite name (e.g. `ECDHE-RSA-AES128-SHA`) means HMAC-SHA1 and is detected as such. |
| **5%** | Certificate Lifetime Hygiene | Penalises **both** extremes: imminent expiry is an outage risk, and a lifetime beyond the CA/Browser Forum 398-day maximum signals weak rotation discipline — and rotation discipline is exactly the capability needed to migrate to PQC certificates. |

### Stage 2 — Floor gates

A pure weighted average lets good hygiene mask a fatal flaw. A host on TLS 1.3
with AES-256-GCM, SHA-384 and a valid CA certificate scores well on 8 of 10
components while its key exchange and signature remain 100% Shor-breakable —
averaging that away would report "Transitioning" for an asset with *zero*
post-quantum protection. The floor gates encode that structural truth:

| Floor | Rule | Trigger |
|------:|------|---------|
| **81** | `classically_broken` | MD5/SHA-1 signature, RC4/DES/NULL cipher, SSLv2/v3, or RSA/DSA key ≤ 1024 bits — exploitable today, no quantum computer required |
| **45** | `no_pqc_anywhere` | Neither key exchange nor signature is post-quantum ⇒ cannot rate better than Quantum Vulnerable |
| **30** | `partial_pqc` | Exactly one of the two is post-quantum — hybrid migration genuinely in progress |

Floors **map** rather than clamp:

```
gated = max(composite, floor + (composite / 100) × (band_top − floor))
```

A plain `max(composite, floor)` would satisfy the rule but flatten every asset
tripping the same gate onto one number — and with no PQC anywhere being the
common case today, that collapsed whole fleets to an identical score and made
the ten components invisible. Mapping preserves the ordering the composite
established, so a host with weaker ciphers or a worse certificate still ranks
above a cleaner host behind the same gate.

**Why the `no_pqc_anywhere` floor sits at 45.** It was originally 61, which
made the mapping window only 19 points wide. Because real-world composites
cluster well below 100, live scans occupied barely a third of that window: on
a measured 86-host bank estate the composite spread 17.3 points while the
gated score spread just 4.0 — the gate was discarding roughly 77% of the
resolution the ten weighted components had produced, and every classical
fleet collapsed onto the same posture tier regardless of hygiene. At 45 the
window is 35 points wide and that resolution is restored. **The structural
claim is unchanged:** the Quantum Vulnerable band now spans 45–80, so a host
with no post-quantum protection anywhere still cannot be labelled anything
better than Quantum Vulnerable. Only the granularity within the band moved,
never the verdict.

### Stage 3 — HNDL amplification

```
uplift = gated × (service_multiplier − 1.0) × 0.15      # multiplier 1.0 – 2.0
```

The multiplier is the real measured value from `analysis/hndl_detector.py`
(plain HTTPS 1.0 → OpenVPN/IPSec 2.0). Uplift is proportional to *both* the
multiplier excess and the existing exposure, so harvest value amplifies real
vulnerability but **cannot manufacture risk where the crypto is already
quantum-safe** — PQC-protected VPN traffic is not harvestable, and the model
says so.

### Stage 4 — Clamp, then classify

Final score is bounded to 0–100 and mapped to one of four per-asset bands:

| Score | Risk Label |
|------:|-----------|
| 0–29 | Quantum Safe |
| 30–44 | Transitioning |
| 45–80 | Quantum Vulnerable |
| 81–100 | Critical |

### Fleet rating and posture tiers

```
Enterprise Rating = (100 − average_risk_score) × 10       # 0 – 1000
```

Five tiers, contiguous with no gaps or overlaps, each boundary landing on a
round average-risk value:

| Rating | Tier | Average risk |
|-------:|------|-------------:|
| 850–1000 | **Elite-PQC** | ≤ 15 |
| 700–849 | **Advanced** | ≤ 30 |
| 550–699 | **Standard** | ≤ 45 |
| 400–549 | **Developing** | ≤ 60 |
| 0–399 | **Legacy** | > 60 |

Rating and tier are computed by `summarize_fleet()` in the engine and reused by
the dashboard, the scan-history list, the scheduler's trend tracking and every
export — so a scan's score is identical wherever it appears.

### Reference standards

NIST FIPS 203/204/205 and SP 800-208 (PQC standards and security levels),
NIST SP 800-57 (key-strength equivalence), RFC 8446 (TLS 1.3 removes static RSA
and non-AEAD modes), RFC 8996 (TLS 1.0/1.1 deprecation), RFC 7465 (RC4
prohibition), and CA/Browser Forum Baseline Requirements (398-day maximum
certificate lifetime).

### Validation

`python test_system.py` runs 77 assertions against the engine, including:
weights sum to exactly 1.0; all 10 components are produced; each floor gate
fires on the right trigger; floor mapping preserves ordering; degrading any
single parameter never lowers the score (monotonicity); HNDL cannot push
quantum-safe crypto out of the Quantum Safe band; posture tiers tile 0–1000
with no gaps; and scores are always clamped to 0–100.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI, Uvicorn, SQLite (WAL mode) |
| **AI Agent** | Groq (Llama 3.3 70B), server-side proxy — API key never reaches the browser |
| **Auth** | JWT (PyJWT), bcrypt, TOTP (`pyotp`), Supabase Auth (optional, ready-to-connect) |
| **TLS Scanning** | Python `ssl`, `socket`, `asyncio`, `pyOpenSSL` |
| **DNS Discovery** | `dnspython`, CT logs API, AlienVault OTX |
| **Frontend** | HTML5, Tailwind CSS, Vanilla JS, Chart.js, Cytoscape.js |
| **Risk Engine** | Custom quantum scoring, HNDL multiplier, CBOM analysis |

---

## Known Limitations

- **PQC key exchange is only detected when the cipher suite names it.** A hybrid
  group carried in the suite name (e.g. `TLS_X25519MLKEM768_AES_256_GCM_SHA384`)
  **is** detected and scores 0. But in the normal TLS 1.3 case the negotiated
  group lives in the handshake's `supported_groups`/`key_share` extension, and
  Python's `ssl` module exposes no `group()`/curve accessor in this build
  (verified: absent from both `ssl.SSLSocket` and `ssl.SSLObject` on CPython
  3.14 / OpenSSL 3.5) — so the scanner cannot record it. In that case the model
  assumes ephemeral classical (X)DH and scores the key exchange 80, the
  conservative default. **PQC *signature* algorithms (ML-DSA/Dilithium,
  SLH-DSA/SPHINCS+) are detected reliably** from certificate metadata, so a
  PQC-signed host is scored correctly on that component. Regression-tested in
  `test_system.py` (`test_pqc_key_exchange_detection_and_gap`), which asserts
  both the working path and the gap.
- **Stored `algorithm_analysis` rows are not re-parsed retroactively.** The
  cipher parser now handles OpenSSL-style concatenated names (`AES256-GCM`)
  as well as IANA-style (`AES_256_GCM`), but rows written by earlier scans keep
  whatever they were stored with, so their CBOM `encryption` field may still
  read `unknown`. Re-scan a domain to refresh it. Risk *scoring* is unaffected —
  the engine re-derives cipher strength and mode from the raw cipher suite on
  every request rather than trusting the stored parse.
- **No test coverage beyond the core risk-scoring path.** `test_system.py`
  validates the quantum risk engine directly (77 assertions); scanner, DNS
  discovery, and API routes are not yet covered by automated tests.
- **Supabase Auth is code-complete but inactive until a project is connected.**
  With `SUPABASE_URL`/`SUPABASE_ANON_KEY`/`SUPABASE_SERVICE_ROLE_KEY` blank
  (the shipped default), registration and login run entirely on local bcrypt —
  this is a deliberate fallback, not a stub: the same code path is exercised
  either way, only the identity backend differs. See
  [Connecting Supabase Auth](#connecting-supabase-auth-optional).
- **Two-factor authentication is this app's own TOTP implementation**
  (`auth/mfa.py`), not Supabase's native MFA — it works identically whether or
  not Supabase is connected, and was built this way specifically so 2FA is
  real and demoable without depending on an external account being set up.
- **`GET /asset/{id}` and `GET /asset/{id}/report/pdf` are unauthenticated**,
  consistent with the existing `GET /scan/{id}/report/pdf` — asset/scan IDs
  are sequential integers, so this is enumerable. Acceptable for a
  single-tenant hackathon deployment; a production deployment should scope
  these to the owning user the same way `/user/scans` and the analytics
  endpoints already are.
- **The local mirror password hash can go stale for Supabase-linked accounts.**
  If a user's password is changed directly in Supabase (outside this app),
  the local bcrypt fallback and `/auth/mfa/disable`'s password check won't
  reflect that change until they log in again through this app. No
  password-reset flow exists yet.

---

## License

This project is proprietary. All rights reserved.
