# Qubitsense: Quantum-Proof Systems Scanner (QPSS)

![Quantum Cyber Security](https://img.shields.io/badge/Security-Quantum--Proof-blueviolet)
![Hackathon](https://img.shields.io/badge/Hackathon-Cyber%20Security-orange)

**Qubitsense** is a cutting-edge software scanner designed to help organizations secure their public-facing applications against the looming threat of cryptanalytically relevant quantum computers (CRQCs). It creates a comprehensive **Cryptographic Bill of Materials (CBOM)** and evaluates existing deployments for "Harvest Now, Decrypt Later" (HNDL) vulnerabilities.

---

## 🚀 Main Functions

The primary objective of Qubitsense is to provide a unified visibility layer into an organization's cryptographic health:

1.  **Crypto Inventory Discovery**: Automatically discovers and catalogs public-facing assets (Web Servers, APIs, VPNs) and their associated TLS certificates.
2.  **Cryptographic Control Validation**: Validates the cipher suites, key exchange algorithms, and signature algorithms in use.
3.  **PQC Readiness Assessment**: Cross-references identified algorithms against NIST-standardized Post-Quantum Cryptography (PQC) standards.
4.  **Quantum-Safe Labeling**: Automatically issues "Post Quantum Cryptography (PQC) Ready" or "Fully Quantum Safe" digital labels for systems meeting modern standards.

---

## ✨ Additional Features (Beyond Hackathon Requirements)

While the hackathon required baseline discovery and assessment, Qubitsense expands on these with enterprise-grade features:

*   **Dynamic Normalized Risk Scoring**: Implements a weighted 0-100 scoring model that evaluates TLS versions, key exchange protocols, and signature algorithms. Risk is recalculated in real-time as threat intelligence updates.
*   **HNDL Exposure Analysis**: Specifically identifies assets vulnerable to "Harvest Now, Decrypt Later" attacks by identifying long-life certificate signatures and classical asymmetric encryption.
*   **Multi-Domain Dashboard**: A centralized user interface to track security posture across dozens of domains simultaneously.
*   **User Authentication & Secure History**: Integrated JWT-based authentication to store and manage scan histories securely for different organizations.
*   **Domain Monitoring**: Proactive monitoring toggle to alert users when a previously "Safe" domain degrades due to updated security standards.
*   **Automated Intelligence Feed**: A self-updating registry of classical vs. quantum-safe algorithms.

---

## 🛠️ How It Works

1.  **Scanning Engine**: Utilizes custom TLS handshake parsers to extract certificate metadata and supported cipher suites without performing invasive attacks.
2.  **Quantum Risk Engine**: A mathematical model that applies penalties for legacy protocols (RSA < 3072, ECC < 256, TLS < 1.3) and rewards for PQC candidates (ML-KEM, SLH-DSA).
3.  **Intelligence Registry**: Maintains a mapping of cryptographic primitives to their quantum-resistance status.

---

## 📋 Software Requirements

### System Pre-requisites
*   **Python 3.9+**
*   **SQLite 3** (Included with Python)

### Python Libraries
*   `fastapi`: For the high-performance API backend.
*   `uvicorn`: ASGI server implementation.
*   `cryptography`: For certificate parsing and crypto-intelligence.
*   `PyJWT`: For secure user session management.
*   `bcrypt`: For secure password hashing.
*   `requests`: For domain discovery and external lookups.
*   `python-multipart`: For handling form data.

---

## ⚙️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/Sart09/Qubitsense_PQC_identifier.git
cd Qubitsense_PQC_identifier
```

### 2. Install Dependencies
It is recommended to use a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install fastapi uvicorn cryptography PyJWT bcrypt requests python-multipart
```

### 3. Initialize the Database
The system automatically initializes its SQLite database (`platform.db`) on the first run.

### 4. Start the Server
Run the FastAPI application using Uvicorn:
```bash
python quantum_crypto_platform/backend/server.py
```
Wait for the console message: `[startup] Seeded algorithms into crypto_registry`.

### 5. Access the Platform
*   **Frontend**: Open `http://localhost:8000` in your browser.
*   **API Docs**: Open `http://localhost:8000/docs` for the interactive Swagger documentation.

---

**"Quantum-Ready Cybersecurity for Future-Safe Banking"**
