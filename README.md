# Qubitsense — Post-Quantum Cryptography Identifier

A full-stack security platform that scans websites and domains for **post-quantum cryptographic risk**, evaluating TLS configurations, cipher suites, and **Harvest Now, Decrypt Later (HNDL)** exposure.

Built with **FastAPI** (Python) on the backend and a modern HTML/JS frontend.

---

## Features

- **Domain Scanning** — Submit any domain or URL for automated security analysis
- **AI Assistant "Qubit"** — Integrated floating AI agent (Gemini 2.5 Flash) for chat-based scanning and risk intelligence
- **Scan Scheduling** — Automated surveillance with recurring daily/weekly/monthly scans and risk delta tracking
- **Discovery Intelligence** — Massive 500+ prefix brute-force engine for enterprise-grade subdomain mining
- **TLS Deep Analysis** — Inspect TLS versions, cipher suites, key algorithms, and certificate expiry
- **Quantum Risk Scoring** — Dynamically calculated risk scores (0–100) based on cryptographic posture
- **HNDL Detection** — Identify assets vulnerable to "Harvest Now, Decrypt Later" attacks
- **Algorithm Intelligence** — Classify cipher components (key exchange, signature, encryption, hash) and estimate quantum vulnerability
- **Scan Caching** — 24-hour result cache with strictly controlled "No-Cache" UI headers
- **QR/Barcode Upload** — Extract target URLs from uploaded images or PDFs
- **Export Reports** — Aggregated JSON reports covering all scan dimensions
- **Real-time Scan Logs** — Live progress tracking during scan execution

---

## Architecture

```
├── backend/          # FastAPI server, database, models, job management
│   ├── server.py     # Main entry-point (FastAPI app + all API routes)
│   ├── database.py   # SQLite database initialization & connection
│   ├── models.py     # Pydantic request/response models
│   ├── job_manager.py
│   ├── result_manager.py
│   ├── domain_parser.py
│   └── upload_parser.py
│
├── scanner/          # Network scanning modules
│   ├── tls_scanner.py
│   ├── certificate_parser.py
│   ├── dns_enum.py
│   ├── domain_discovery.py
│   └── ct_logs.py
│
├── analysis/         # Risk analysis & classification
│   ├── quantum_risk_engine.py
│   ├── algorithm_classifier.py
│   ├── cipher_parser.py
│   ├── quantum_estimator.py
│   ├── service_classifier.py
│   └── hndl_detector.py
│
├── intelligence/     # Threat intelligence & PQC registry
│   ├── pqc_registry.py
│   ├── attack_registry.py
│   ├── registry_updater.py
│   └── threat_feed.py
│
├── auth/             # Authentication system
│   ├── auth_routes.py
│   ├── jwt_handler.py
│   └── password_utils.py
│
├── workers/          # Background scan worker
│   ├── scan_worker.py
│   └── job_fetcher.py
│
├── frontend/         # Web UI
│   ├── index.html         # Scanner landing page
│   ├── login.html         # Login / Register
│   ├── dashboard.html     # Scan results dashboard
│   ├── scan_progress.html # Real-time scan progress
│   ├── user_dashboard.html
│   └── components/        # Shared JS/CSS components
│
└── test_system.py    # End-to-end system validation script
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
# Core: fastapi, uvicorn, pyjwt, bcrypt, cryptography, python-dotenv, python-multipart
# Scanning: aiodns, pycares, dnspython
# Document Analysis: Pillow, pyzbar, pymupdf
pip install fastapi uvicorn pyjwt bcrypt cryptography python-dotenv python-multipart aiodns pycares dnspython Pillow pyzbar pymupdf

# Configure the environment
cp .env.example .env
# Edit .env and supply your Gemini API Key for the AI Agent (Qubit)
# GEMINI_API_KEY=AIzaSy...
```

### Running

### Running

You need **three processes** running simultaneously to leverage the full pipeline:

**1. API Server**

```bash
python backend/server.py
```

The server starts on `http://localhost:8000`. It serves the frontend pages and exposes all REST API endpoints.

**2. Main Scan Worker**

```bash
python workers/scan_worker.py
```

The worker polls the database `scans` table to execute the domain discovery, TLS scan, and risk engine pipelines.

**3. Scan Scheduler Worker**

```bash
python workers/scheduler.py
```

The scheduler wakes up every 60 seconds, reads the `scheduled_scans` configurations, computes offsets, and triggers background `scan_worker.py` jobs.

> **Tip:** You can use the provided `start.bat` (Windows) or `start.sh` (Linux/Mac) to boot all three processes at once.

---

## API Endpoints

| Method | Endpoint                          | Description                              |
|--------|-----------------------------------|------------------------------------------|
| POST   | `/scan`                           | Submit a domain for scanning             |
| GET    | `/scan/{id}`                      | Poll scan status                         |
| GET    | `/scan/{id}/assets`               | Discovered subdomains/assets             |
| GET    | `/scan/{id}/tls`                  | TLS scan results                         |
| GET    | `/scan/{id}/quantum-risk`         | Quantum risk scores                      |
| GET    | `/scan/{id}/hndl`                 | HNDL detection results                   |
| GET    | `/scan/{id}/report`               | Full aggregated JSON report              |
| GET    | `/scan/{id}/logs`                 | Real-time scan execution logs            |
| POST   | `/api/schedules/create`           | Register a new recurring task            |
| GET    | `/api/schedules/list`             | List currently authenticated user schedules|
| PATCH  | `/api/schedules/{id}/pause`       | Suspend active recurring schedule        |
| PATCH  | `/api/schedules/{id}/resume`      | Reactivate a suspended schedule          |
| PATCH  | `/api/schedules/{id}/update`      | Modify existing schedule configuration   |
| POST   | `/api/schedules/{id}/run-now`     | Trigger scan out of band instantly       |
| GET    | `/api/schedules/{id}/history`     | Execution history with risk deltas       |
| DELETE | `/api/schedules/{id}`             | Unregister an existing schedule target   |
| GET    | `/api/config/agent-key`           | Fetch secure AI agent key (Authenticated)|
| POST   | `/auth/register`                  | Register a new user                      |
| POST   | `/auth/login`                     | Login and receive JWT token              |
| GET    | `/auth/me`                        | Get current user info                    |
| GET    | `/user/scans`                     | List authenticated user's scan history   |

---

## Testing

Run the full end-to-end validation suite (requires both server and worker to be running):

```bash
python test_system.py
```

This validates all 16 system components including authentication, scanning, caching, risk analysis, and error handling.

---

## Tech Stack

- **Backend**: FastAPI, Uvicorn, SQLite
- **AI Agent**: Google Gemini 2.5 Flash (via secure backend proxy)
- **Auth**: JWT (PyJWT), bcrypt
- **Scanning**: Python `ssl`, `socket`, `dns.resolver`, Certificate Transparency logs
- **Frontend**: HTML5, Vanilla CSS (Glassmorphism), Vanilla JS
- **Discovery**: Custom multi-source engine (CT Logs, 500+ Wordlist, Passive DNS)
- **Analysis**: Custom quantum risk engine, cipher classification, HNDL detection

---

## License

This project is proprietary. All rights reserved.
