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
- **Per-Host Quantum Risk Scores** — 0–100 composite score based on key exchange, encryption, TLS version, key size, and certificate validity
- **HNDL Detection** — Identifies which subdomains are highest-value harvest targets
- **Algorithm Intelligence** — Classifies cipher components and maps them to quantum vulnerability estimates
- **Cryptographic Bill of Materials (CBOM)** — Full inventory of every algorithm in use

### 🤖 AI Assistant "Qubit"
- **Gemini 2.5 Flash Powered** — Natural language scanning and risk intelligence
- **Voice-Driven Operation** — Speak a domain name, agent scans it automatically
- **Context-Aware Analysis** — Agent understands your current scan and answers questions about it
- **Available on Every Page** — Persistent floating widget across the entire platform

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
- **Live Risk Dashboard** — Risk scores, HNDL exposure, cipher breakdowns, network graph
- **Real-time Scan Progress** — Live terminal log stream with phase-by-phase progress bars
- **Scan History** — Full timestamped history per domain with TLS counts and failure stats
- **PDF Export** — One-click compliance-ready report generation
- **JSON Export** — Full aggregated report for programmatic consumption
- **WCAG AA Compliant UI** — All text elements meet 4.5:1 contrast ratio minimum

---

## Architecture

```
├── backend/                    # FastAPI server, database, models
│   ├── server.py               # Main entry-point + all REST API routes
│   ├── database.py             # SQLite schema + WAL connection management
│   ├── models.py               # Pydantic request/response models
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
│   ├── auth_routes.py          # Register / Login / Me endpoints
│   ├── jwt_handler.py          # JWT token generation & validation
│   └── password_utils.py       # bcrypt hashing
│
├── workers/                    # Background processing
│   ├── scan_worker.py          # Main scan pipeline (Discovery → TLS → Storage)
│   ├── job_fetcher.py          # Priority-aware job queue (FIFO + priority override)
│   └── scheduler.py            # Recurring scan scheduler
│
├── frontend/                   # Web UI
│   ├── index.html              # Scanner landing — Scan Now + Add to Queue
│   ├── login.html              # Login / Register
│   ├── dashboard.html          # Full scan results dashboard
│   ├── scan_progress.html      # Real-time progress tracker
│   ├── user_dashboard.html     # Per-user scan history + stop controls
│   ├── schedules.html          # Schedule management UI
│   ├── css/ai-agent.css        # AI agent widget styles (WCAG AA)
│   └── components/             # Shared theme, charts, graph viewer
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
pip install fastapi uvicorn pyjwt bcrypt cryptography python-dotenv \
            python-multipart aiodns pycares dnspython Pillow pyzbar \
            pymupdf pyOpenSSL requests
```

### Configuration

```bash
# Configure environment
cp .env.example .env
```

Edit `.env` and set your Gemini API key:
```env
GEMINI_API_KEY=AIzaSy...your_key_here
JWT_SECRET=your_secret_here
```

> [!IMPORTANT]
> The AI Assistant (Qubit) requires a valid Google Gemini API key in `.env`.
> Without it, the agent displays an error and cannot trigger scans or analysis.
> Get a free key at https://aistudio.google.com/apikey

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
| `GET`  | `/scan/{id}/report` | Full aggregated JSON report |
| `POST` | `/scan/upload` | Upload QR/barcode document |

### Domain History

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/domains` | List all scanned domains |
| `GET`  | `/domain/{domain}/scans` | Scan history for a domain |
| `GET`  | `/asset/{id}` | Per-asset drill-down details |

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
| `POST` | `/auth/register` | Register new user |
| `POST` | `/auth/login` | Login, returns JWT |
| `GET`  | `/auth/me` | Current user info |
| `GET`  | `/user/scans` | User's scan history |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI, Uvicorn, SQLite (WAL mode) |
| **AI Agent** | Google Gemini 2.5 Flash (secure backend proxy) |
| **Auth** | JWT (PyJWT), bcrypt |
| **TLS Scanning** | Python `ssl`, `socket`, `asyncio`, `pyOpenSSL` |
| **DNS Discovery** | `dnspython`, CT logs API, AlienVault OTX |
| **Frontend** | HTML5, Tailwind CSS, Vanilla JS, Chart.js, Cytoscape.js |
| **Risk Engine** | Custom quantum scoring, HNDL multiplier, CBOM analysis |

---

## License

This project is proprietary. All rights reserved.
