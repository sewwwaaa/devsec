# STRIDE Threat Model & Risk Assessment
**Module:** IE3142 - DevOps Security  
**Project:** TaskShield DevSecOps Platform  
**Target Architecture:** Multi-Component Containerised REST API & Single Page Application (SPA)

---

## 1. System Decomposition & Data Flow Mapping

The TaskShield architecture comprises four distinct trust domains separated by explicit network and software boundaries:

1. **Trust Boundary 1: Untrusted Public Internet (User/Attacker Client)**
   - External clients interact with the system via HTTP/S requests carrying JSON payloads and Bearer tokens.
   - Attack vectors originating here include credential stuffing, injection payloads, unauthenticated resource enumeration, and malicious script injection.

2. **Trust Boundary 2: Perimeter / DMZ (Nginx Reverse Proxy)**
   - Nginx handles ingress traffic, terminates TLS, enforces Content-Security-Policy (CSP) and HTTP security headers, and reverse-proxies API requests to the application layer.

3. **Trust Boundary 3: Internal Application Network (Node.js/Express Backend)**
   - Node.js runtime isolated on an internal bridge network (`app-network`).
   - Contains authentication verification, input validation middleware, business logic, and security event generation.

4. **Trust Boundary 4: Data & Secrets Storage (Database & Vault)**
   - Persistent SQLite/PostgreSQL storage and HashiCorp Vault key-value secrets storage.
   - Accessible strictly by the backend container using non-root least-privilege permissions.

---

## 2. STRIDE Threat Catalogue

| Threat ID | STRIDE Category | Threat Description & Attack Scenario | Impacted Component | Vulnerability Class |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Spoofing** | **Counterfeit JWT Generation via Weak Secret:** An adversary identifies a hardcoded fallback or weak dictionary signing key (`secret123`), offline-mints an arbitrary JWT claiming administrative role, and bypasses authentication. | `backend/src/middleware/auth.js` | CWE-798 / CWE-287 |
| **TH-02** | **Tampering** | **Stored Cross-Site Scripting (XSS) in Task Content:** A malicious authenticated user submits persistent `<script>` tags or malicious event handlers (`<img onerror=...>`) in task descriptions, executing arbitrary JS in other users' browsers to hijack cookies. | `backend/src/controllers/noteController.js` | CWE-79 |
| **TH-03** | **Repudiation** | **Unlogged Administrative Actions:** An administrator or compromised account deletes records or elevates user permissions without persistent, tamper-evident audit trails, making forensic attribution impossible. | `backend/src/config/db.js` | CWE-778 |
| **TH-04** | **Information Disclosure** | **SQL Injection Authentication Bypass & Schema Dump:** An unauthenticated adversary inputs SQL metacharacters (`' OR '1'='1`) into the login endpoint, bypassing password verification and leaking confidential tenant records. | `backend/src/controllers/authController.js` | CWE-89 |
| **TH-05** | **Denial of Service** | **Brute-Force & Resource Exhaustion Attack:** An attacker floods `/api/auth/login` with high-frequency password guessing or submits oversized JSON payloads, consuming memory and starving legitimate requests. | `backend/src/middleware/rateLimiter.js` | CWE-400 / CWE-307 |
| **TH-06** | **Elevation of Privilege** | **Broken Object Level Authorization (BOLA/IDOR):** An authenticated standard user modifies the request parameter (`GET /api/notes/:id` or `DELETE /api/notes/:id`) to read or delete private records belonging to another tenant. | `backend/src/controllers/noteController.js` | CWE-639 / OWASP API1:2023 |

---

## 3. Risk Assessment Matrix (5x5 Qualitative Scale)

### Rating Methodology
- **Likelihood (1–5):** 1: Rare, 2: Unlikely, 3: Possible, 4: Likely, 5: Almost Certain.
- **Impact (1–5):** 1: Insignificant, 2: Minor, 3: Moderate, 4: Major, 5: Catastrophic.
- **Overall Risk Score = Likelihood × Impact:**
  - **1–6:** Low (Green)
  - **7–14:** Medium (Blue/Yellow)
  - **15–19:** High (Orange)
  - **20–25:** Critical (Red)

### Risk Evaluation & Justification Table

| Threat ID | Threat Title | Likelihood (1–5) | Impact (1–5) | Risk Score | Risk Category | Detailed Justification |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **TH-01** | JWT Weak Secret Forgery | 3 | 5 | **15** | **High** | Token tampering tools (e.g. `jwt_tool`, Hashcat) routinely crack weak secrets in seconds, immediately granting complete administrative access. |
| **TH-02** | Stored XSS Scripting | 4 | 4 | **16** | **High** | Web applications with markdown/note inputs frequently suffer from unescaped rendering; execution can hijack administrative sessions. |
| **TH-03** | Missing Audit Logging | 2 | 4 | **8** | **Medium** | Does not directly breach data on its own, but severely impairs incident response, insider threat tracking, and legal compliance. |
| **TH-04** | SQL Injection Bypass | 4 | 5 | **20** | **Critical** | SQL injection is among the most catastrophic web vulnerabilities, yielding full database exfiltration, credential loss, and authentication bypass. |
| **TH-05** | Credential Brute-Force DoS | 4 | 3 | **12** | **High** | Automated botnets routinely target authentication endpoints; without rate-limiting, system responsiveness degrades rapidly. |
| **TH-06** | BOLA / IDOR Tenant Breach | 4 | 4 | **16** | **High** | Sequential resource identifiers are trivial to enumerate; unvalidated queries allow total violation of multi-tenant confidentiality. |

---

## 4. Threat-to-Control Mapping

| Threat ID | Mitigating Security Control | Control Type | Exact Codebase / Pipeline Location | Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | 256-bit dynamic JWT key injection via Vault / Environment variables; strict HS256 signature check; zero hardcoding. | Preventative | `backend/src/config/secrets.js`<br/>`backend/src/middleware/auth.js` | Exploit 4 PoC (`exploits/exploit_4_weak_jwt.js`); Gitleaks CI Gate. |
| **TH-02** | Context-aware HTML sanitization using `sanitize-html` allowing only safe tags; strict Helmet Content-Security-Policy (CSP). | Preventative | `backend/src/controllers/noteController.js`<br/>`backend/src/app.js` | Exploit 2 PoC (`exploits/exploit_2_stored_xss.js`); Semgrep XSS rules. |
| **TH-03** | Immutable database audit table logging user ID, action, timestamp, IP address, and status. | Detective | `backend/src/config/db.js` (`audit_logs`)<br/>`backend/src/controllers/adminController.js` | Admin SIEM UI; Unit tests in `backend/tests/security.test.js`. |
| **TH-04** | Parameterized SQL queries using SQLite/Postgres bindings (`?`); strict schema validation using Joi (`alphanum` rules). | Preventative | `backend/src/controllers/authController.js`<br/>`backend/src/middleware/validator.js` | Exploit 1 PoC (`exploits/exploit_1_injection.js`); Semgrep SQLi rules. |
| **TH-05** | `express-rate-limit` windowing (20 auth attempts / 15 min; 120 API requests / min); request payload size limits (50kb). | Preventative | `backend/src/middleware/rateLimiter.js`<br/>`backend/src/app.js` | Automated rapid-fire curl test; integration testing. |
| **TH-06** | Explicit tenant ownership enforcement (`WHERE id = ? AND userId = ?`) and RBAC privilege checks. | Preventative | `backend/src/controllers/noteController.js`<br/>`backend/src/middleware/auth.js` | Exploit 3 PoC (`exploits/exploit_3_bola_idor.js`); Multi-tenant security tests. |
