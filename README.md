# OWASP NodeGoat — DevSecOps Pipeline & Security Platform
> **IE3142: DevOps Security — Year 3 Semester 1, 2026**  
> **Faculty of Computing, Sri Lanka Institute of Information Technology (SLIIT)**

[![CI/CD DevSecOps Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue.svg)](https://github.com/ashendilantha/nodegoat-devsecops/actions)
[![SAST Semgrep](https://img.shields.io/badge/SAST-Semgrep%20Passed-success.svg)](https://semgrep.dev)
[![SCA npm audit](https://img.shields.io/badge/SCA-npm%20audit%20Passed-success.svg)](package.json)
[![Secrets Gitleaks](https://img.shields.io/badge/Secrets-Gitleaks%20Active-brightgreen.svg)](https://github.com/gitleaks/gitleaks)
[![Container Trivy](https://img.shields.io/badge/Container-Trivy%20Hardened-blue.svg)](https://github.com/aquasecurity/trivy)

---

## 📌 Project Overview
This repository contains the complete DevSecOps pipeline implementation, threat model, exploit demonstrations, and secure coding fixes for **OWASP NodeGoat**, pre-vetted and recommended under **Appendix A.1 (Intentionally Vulnerable Applications)** of the **IE3142 DevOps Security module brief**.

- **Repository:** [https://github.com/ashendilantha/nodegoat-devsecops](https://github.com/ashendilantha/nodegoat-devsecops)
- **Selected Stack:** Node.js (Express.js) Web Tier + MongoDB 4.4 NoSQL Database Tier
- **Orchestration:** Multi-container Docker Compose (`web` + `db`)
- **Offline Capable:** 100% executable and testable on local developer workstations without cloud accounts.

---

## 🏛️ System Architecture & Trust Boundaries

```
[ Trust Boundary 1: Untrusted Public Ingress (Port 4000) ]
       │
       ▼  HTTP / REST (Employee Browser / Attacker Payloads)
[ Trust Boundary 2: Web Application Container (Node.js / Express) ]
       │  Controllers: contributions, allocations, memos, profile, session
       ▼  TCP Socket over isolated Docker network (nodegoat-net:27017)
[ Trust Boundary 3: Database Container (MongoDB 4.4 Persistence Tier) ]
       │  Collections: users (salted bcrypt), allocations, memos, counters
[ Trust Boundary 4: CI/CD Pipeline & Secrets Automation (GitHub Actions) ]
```

Detailed architectural diagrams and trust boundaries are available in:
- [architecture_diagram.mermaid](file:///c:/Users/LENOVO/Desktop/devsec/docs/architecture_diagram.mermaid)
- [stride_threat_model.md](file:///c:/Users/LENOVO/Desktop/devsec/docs/stride_threat_model.md)

---

## 🛡️ Four Core Vulnerabilities (Exploit-and-Fix)

| # | Vulnerability Class | CWE / OWASP | Vulnerable Code File | Implemented Remediation | SAST Result |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **1** | **SSJS Injection** | CWE-94 / A1:2017 | `app/routes/contributions.js` | Removed `eval()`; enforced `parseInt(..., 10)` (Commit `22574e5`) | **0 findings** (Fixed) |
| **2** | **NoSQL Injection** | CWE-943 / A1:2017 | `app/data/allocations-dao.js` | Replaced `$where` JS concatenation with native MongoDB `{$gt: ...}` | **0 findings** (Fixed) |
| **3** | **Stored XSS** | CWE-79 / A7:2017 | `app/views/memos.html` | Enabled sanitization and HTML escaping in `marked` markdown engine | **0 findings** (Fixed) |
| **4** | **Broken Auth & Plaintext Passwords** | CWE-256 / A2:2017 | `app/data/user-dao.js` | Applied salted Bcrypt hashing (10 rounds); externalized session secret | **0 findings** (Fixed) |

---

## ⚙️ CI/CD Pipeline & Automated Security Gates

The GitHub Actions workflow (`.github/workflows/devsecops-pipeline.yml`) enforces four mandatory security quality gates on every push:
1. **Gate 1: SAST (Static Analysis):** Semgrep scanning `app/` using `p/owasp-top-ten`, `p/nodejs`, and `p/security-audit`. Fails if critical errors exceed threshold.
2. **Gate 2: SCA (Software Composition Analysis):** `npm audit` scanning third-party dependencies in `package-lock.json`.
3. **Gate 3: Secrets Scanning:** `gitleaks/gitleaks-action@v2` scanning commit diffs and history for credentials.
4. **Gate 4: Container Security:** Aqua Security Trivy scanning the built `nodegoat:latest` image for OS and package CVEs.

---

## 🚀 How to Run Locally

### Using Docker Compose (Recommended)
```bash
# 1. Clone the repository
git clone https://github.com/ashendilantha/nodegoat-devsecops.git
cd nodegoat-devsecops

# 2. Build and start containers
docker compose up --build

# 3. Open in browser
http://localhost:4000
```

### Default Credentials
- **Admin:** `admin` / `Admin_123`
- **User 1:** `user1` / `User1_123`
- **User 2:** `user2` / `User2_123`

---

## 📑 Documentation Index

- 📘 [Technical Report (Markdown)](file:///c:/Users/LENOVO/Desktop/devsec/docs/TECHNICAL_REPORT.md)
- 🌐 [Technical Report (HTML Printable View)](file:///c:/Users/LENOVO/Desktop/devsec/docs/TECHNICAL_REPORT.html)
- 🎯 [STRIDE Threat Model & Risk Matrix](file:///c:/Users/LENOVO/Desktop/devsec/docs/stride_threat_model.md)
- 🏛️ [Architecture Diagram (Mermaid)](file:///c:/Users/LENOVO/Desktop/devsec/docs/architecture_diagram.mermaid)
- 📝 [Ethical Clearance Form](file:///c:/Users/LENOVO/Desktop/devsec/docs/ETHICAL_CLEARANCE_FORM.md)
- 🎤 [Viva Voce Preparation Guide](file:///c:/Users/LENOVO/Desktop/devsec/docs/VIVA_VOCE_GUIDE.md)

---

## 👥 Group Identification

| Student ID | Full Name | Primary Project Role & Domain |
| :--- | :--- | :--- |
| **IT24103936** | sewmina G D D | Lead Architect: CI/CD Pipeline & Trivy Container Gates |
| **IT24103937** | Ashen Dilantha | Security Analyst & Developer: Secure Coding & SSJS/NoSQLi Fixes |
| **IT24103938** | Student Member 3 | Threat Modelling Lead: STRIDE Risk Assessment & Semgrep SAST |
| **IT24103939** | Student Member 4 | DevSecOps Engineer: Gitleaks Secrets Management & SCA Gates |
