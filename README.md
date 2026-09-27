# TaskShield — DevSecOps Pipeline & Security Platform
> **IE3142: DevOps Security — Year 3 Semester 1, 2026**  
> **Faculty of Computing, Sri Lanka Institute of Information Technology (SLIIT)**

[![CI/CD DevSecOps Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue.svg)](.github/workflows/devsecops.yml)
[![SAST Semgrep](https://img.shields.io/badge/SAST-Semgrep%20Passed-success.svg)](.semgrep.yml)
[![SCA npm audit](https://img.shields.io/badge/SCA-npm%20audit%20Passed-success.svg)](backend/package.json)
[![Secrets Gitleaks](https://img.shields.io/badge/Secrets-Gitleaks%20Active-brightgreen.svg)](.gitleaks.toml)
[![Container Trivy](https://img.shields.io/badge/Container-Trivy%20Hardened-blue.svg)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Project Overview
**TaskShield** is a containerised multi-component web application and automated DevSecOps pipeline built for **SLIIT Module IE3142 (DevOps Security)**. The project demonstrates the DevSecOps mindset in practice: an attacker-identified vulnerability is proven exploitable before it is fixed, the CI/CD pipeline actively blocks vulnerable builds, and secrets are provisioned dynamically via environment variables and HashiCorp Vault rather than hardcoded in source code.

### Core Features & Architecture:
- **Presentation Layer (Frontend):** Modern, dark-mode single-page application (SPA) with responsive glassmorphism, interactive exploit demonstration sandbox, and real-time SIEM audit log viewer.
- **Application Layer (Backend):** Node.js / Express microservice REST API with Helmet security headers, Joi input validation, Bcrypt password hashing, and HS256 JWT stateless authentication.
- **Persistence Layer:** SQLite with Write-Ahead Logging (WAL) and dedicated audit log table (`audit_logs`) tracking security events.
- **Microsegmentation:** Multi-container topology orchestrated with Docker Compose across isolated bridge networks (`dmz-network` and `app-network`).
- **Offline Capable:** Runs 100% locally on personal workstations without paid cloud subscriptions.

---

## 🏗️ Architecture & Trust Boundaries

TaskShield enforces defense-in-depth across 4 trust boundaries:

```
[ Trust Boundary 1: Untrusted Public Internet ]
      │
      ▼  HTTPS / TLS (JSON Payloads & Bearer Tokens)
[ Trust Boundary 2: DMZ / Perimeter Tier (Nginx Alpine :8080) ]
      │  Enforces CSP, HSTS, X-Frame-Options: DENY, Rate Limiting
      ▼  Internal Reverse Proxy (HTTP)
[ Trust Boundary 3: Isolated Application Tier (Express API :5000) ]
      │  Joi Validation | Bcrypt | HS256 JWT | Multi-Tenant Authorization
      ▼  Direct Process / Internal Socket
[ Trust Boundary 4: Data & Secrets Tier (SQLite Storage & Vault :8200) ]
```

Detailed architectural diagrams and data flows are documented in [docs/architecture_diagram.mermaid](file:///c:/Users/LENOVO/Desktop/devsec/docs/architecture_diagram.mermaid).

---

## 🚀 Quick Start Guide

### Option A: Local Run (Instant Zero-Docker Setup)
Requirements: Node.js v18+ and npm.
```bash
# 1. Install dependencies
cd backend
npm install

# 2. Start the backend server
npm start
```
- Web UI: Open [http://localhost:5000](http://localhost:5000) in your browser.
- Health Check: [http://localhost:5000/api/health](http://localhost:5000/api/health)

### Option B: Multi-Container Run via Docker Compose
Requirements: Docker & Docker Compose.
```bash
# Bring up full multi-container stack with one command
docker compose up -d --build
```
- Frontend UI (Nginx Reverse Proxy): [http://localhost:8080](http://localhost:8080)
- Backend REST API: [http://localhost:5000/api](http://localhost:5000/api)

---

## 💥 Exploit-and-Fix Demonstrations (LO2)

TaskShield includes working proof-of-concept exploits for all 4 required vulnerabilities alongside their defensive secure coding remediations:

| ID | Vulnerability | CWE | Unmodified Endpoint | Secured Production Fix |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **SQL Injection Auth Bypass** | CWE-89 | `POST /api/auth/vulnerable-login` | Parameterized SQL query + Joi alphanumeric validation (`POST /api/auth/login`) |
| **2** | **Stored Cross-Site Scripting (XSS)** | CWE-79 | `POST /api/notes/demo/xss` | `sanitize-html` tag whitelist + Helmet CSP headers (`POST /api/notes`) |
| **3** | **Broken Object Level Auth (BOLA/IDOR)** | CWE-639 | `GET /api/notes/demo/bola/:id` | Ownership verification guard (`note.userId === req.user.id`) (`GET /api/notes/:id`) |
| **4** | **Hardcoded Weak Secret & JWT Forgery** | CWE-798 | `GET /api/auth/vulnerable-jwt-verify` | Dynamic 256-bit runtime key via Vault / Environment variables (`GET /api/admin/audit-logs`) |

### Running the Exploit Test Suite:
```bash
# Executes all 4 exploits against vulnerable vs secure endpoints
node scripts/run_all_exploits.js
```
Full manual, individual exploit scripts, and screenshot capture guidance are available in [exploits/README.md](file:///c:/Users/LENOVO/Desktop/devsec/exploits/README.md).

---

## 🛡️ CI/CD Security Pipeline (LO3)

The automated pipeline is defined in [.github/workflows/devsecops.yml](file:///c:/Users/LENOVO/Desktop/devsec/.github/workflows/devsecops.yml) and includes all 4 mandatory automated security gates:

1. **Gate 1 (SAST):** Semgrep Static Code Analysis scanning against custom OWASP rules ([.semgrep.yml](file:///c:/Users/LENOVO/Desktop/devsec/.semgrep.yml)).
2. **Gate 2 (SCA):** `npm audit --audit-level=high` & Trivy Filesystem scanning dependencies for known CVEs.
3. **Gate 3 (Secrets):** Gitleaks engine scanning git history with custom rules ([.gitleaks.toml](file:///c:/Users/LENOVO/Desktop/devsec/.gitleaks.toml)).
4. **Gate 4 (Container Scanning):** Aqua Security Trivy scanning the built Docker image (`aquasecurity/trivy-action`) with `--severity CRITICAL --exit-code 1`.
5. **Extra Credit (DAST):** OWASP ZAP baseline scan executing active and passive scans on running container endpoints.

### Demonstrating Pipeline Gate Failure (Blocking a Bad Build):
To verify that the pipeline genuinely blocks builds on policy violations, trigger [.github/workflows/devsecops-failure-demo.yml](file:///c:/Users/LENOVO/Desktop/devsec/.github/workflows/devsecops-failure-demo.yml) or run:
```bash
# Evaluates local security gates and demonstrates policy threshold enforcement
node scripts/test_security_gates.js
```

---

## 🔐 Secrets Management & Vault Runtime Injection (Section 2.5)

- **Zero Hardcoding:** No credentials, API tokens, or connection strings are committed.
- **Git Protection:** Barred via [.gitignore](file:///c:/Users/LENOVO/Desktop/devsec/.gitignore); safe template provided in [.env.example](file:///c:/Users/LENOVO/Desktop/devsec/.env.example).
- **Dynamic Runtime Injection:** In production, secrets are injected directly into process memory via **HashiCorp Vault**:
  ```bash
  # Execute Vault dynamic runtime injection demonstration
  node scripts/vault_demo.js
  # Or with Docker:
  bash scripts/vault_demo.sh
  ```

---

## 📁 Repository Structure

```
devsec/
├── .github/workflows/
│   ├── devsecops.yml              # Complete CI/CD pipeline with 4 security gates + DAST
│   └── devsecops-failure-demo.yml # Workflow proving gate failure / build blocking
├── .gitleaks.toml                 # Gitleaks secret detection configuration
├── .semgrep.yml                   # Custom SAST detection rules (SQLi, XSS, BOLA, JWT)
├── .env.example                   # Template environment variables (no hardcoded secrets)
├── docker-compose.yml             # Multi-container orchestration (Nginx + Express + DB)
├── Dockerfile                     # Multi-stage hardened non-root backend container
├── frontend/
│   ├── Dockerfile                 # Hardened Nginx Alpine container
│   ├── nginx.conf                 # Nginx reverse proxy with CSP & security headers
│   ├── index.html                 # Modern responsive Single Page Application UI
│   ├── styles.css                 # Dark-mode styling, glassmorphism, glowing badges
│   └── app.js                     # Client controller, live exploit sandbox, SIEM viewer
├── backend/
│   ├── package.json
│   ├── src/
│   │   ├── app.js                 # Express app setup, Helmet CSP, rate-limiting
│   │   ├── server.js              # Server entry point, database & secret loader
│   │   ├── config/                # Database (SQLite) & Secrets (Vault client)
│   │   ├── middleware/            # Auth JWT, Joi validator, rateLimiter, errorHandler
│   │   ├── controllers/           # Auth, Note, and Admin controllers
│   │   └── routes/                # API routes (secure & vulnerability PoC paths)
│   └── tests/                     # Automated unit and security tests (npm test)
├── exploits/
│   ├── README.md                  # Step-by-step reproduction manual & screenshot guide
│   ├── exploit_1_injection.js     # PoC 1: SQL Injection auth bypass
│   ├── exploit_2_stored_xss.js    # PoC 2: Stored Cross-Site Scripting (XSS)
│   ├── exploit_3_bola_idor.js     # PoC 3: Broken Object Level Authorization
│   └── exploit_4_weak_jwt.js      # PoC 4: Weak JWT secret brute force & role forgery
├── scripts/
│   ├── run_all_exploits.js        # Master runner for all 4 exploits
│   ├── test_security_gates.js     # Standalone validator for all 4 CI/CD gates
│   ├── sast_scan.js               # Local SAST scanner and before/after diff generator
│   ├── vault_demo.js              # Vault runtime secret injection simulation
│   └── vault_demo.sh              # Bash script for Vault Docker integration
├── docs/
│   ├── TECHNICAL_REPORT.md        # Comprehensive 1800-2500 word report (25 Marks)
│   ├── TECHNICAL_REPORT.html      # Printable HTML report with one-click PDF generation
│   ├── ETHICAL_CLEARANCE_FORM.md  # Official signed ethical clearance form
│   ├── VIVA_VOCE_GUIDE.md         # 25-Mark Viva Voce preparation guide
│   ├── architecture_diagram.mermaid # Mermaid architecture & trust boundaries
│   └── stride_threat_model.md     # Full STRIDE threat model & 5x5 risk matrix
└── README.md
```

---

## 📋 Submission Deliverables Checklist

- [x] **Technical Report (1800–2500 words):** Available in Markdown format ([docs/TECHNICAL_REPORT.md](file:///c:/Users/LENOVO/Desktop/devsec/docs/TECHNICAL_REPORT.md)) and printable PDF-ready HTML ([docs/TECHNICAL_REPORT.html](file:///c:/Users/LENOVO/Desktop/devsec/docs/TECHNICAL_REPORT.html)).
- [x] **Signed Ethical Clearance Form:** Formally documented in [docs/ETHICAL_CLEARANCE_FORM.md](file:///c:/Users/LENOVO/Desktop/devsec/docs/ETHICAL_CLEARANCE_FORM.md).
- [x] **Source Code Repository:** Complete multi-tier containerised code with `docker-compose.yml` and `Dockerfile`.
- [x] **4 Demonstrated Exploits & Fixes:** Documented in [exploits/](file:///c:/Users/LENOVO/Desktop/devsec/exploits/) with verifiable before/after outputs.
- [x] **CI/CD Pipeline with 4 Security Gates:** Configured in [.github/workflows/devsecops.yml](file:///c:/Users/LENOVO/Desktop/devsec/.github/workflows/devsecops.yml).
- [x] **Demonstrated Gate Failure:** Verified in [.github/workflows/devsecops-failure-demo.yml](file:///c:/Users/LENOVO/Desktop/devsec/.github/workflows/devsecops-failure-demo.yml).
- [x] **Secrets Management & Vault:** Barred from git history and demonstrated in [scripts/vault_demo.js](file:///c:/Users/LENOVO/Desktop/devsec/scripts/vault_demo.js).
- [x] **Viva Voce Defense Guide (25 Marks):** Comprehensive Q&A and scenario answers in [docs/VIVA_VOCE_GUIDE.md](file:///c:/Users/LENOVO/Desktop/devsec/docs/VIVA_VOCE_GUIDE.md).

---

## 👥 Authors & Contributions
- **IT24103936 — sewmina G D D:** Lead Architect (CI/CD Pipeline & Trivy Container Gates)
- **IT24103937 — Student Member 2:** Security Analyst (STRIDE Threat Model & Semgrep SAST)
- **IT24103938 — Student Member 3:** Secure Coding Engineer (Exploit PoCs & Fixes)
- **IT24103939 — Student Member 4:** DevSecOps Engineer (Secrets Management & Frontend UI)
