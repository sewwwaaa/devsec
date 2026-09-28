# STRIDE Threat Model & Risk Assessment
**Module:** IE3142 - DevOps Security  
**Project:** OWASP NodeGoat DevSecOps Platform  
**Target Architecture:** Multi-Component Containerised Web Application & MongoDB Database (Appendix A.1)  
**Repository:** `https://github.com/ashendilantha/nodegoat-devsecops`

---

## 1. System Decomposition & Data Flow Mapping

The OWASP NodeGoat architecture comprises four distinct trust domains separated by explicit network and software boundaries:

1. **Trust Boundary 1: Untrusted Public Ingress (User/Attacker Client)**
   - External clients interact with NodeGoat via HTTP requests carrying form-encoded parameters and session cookies on port 4000.
   - Attack vectors originating here include credential stuffing, injection payloads (SSJS, NoSQLi), unauthenticated resource enumeration, and malicious script injection.

2. **Trust Boundary 2: Web Application Tier (Node.js/Express Container)**
   - Node.js runtime isolated inside the Docker container (`web`).
   - Contains session management, input handling, controller logic (`contributions.js`, `allocations.js`, `memos.js`, `profile.js`), and view rendering engines.

3. **Trust Boundary 3: Database Persistence Tier (MongoDB Container)**
   - Persistent NoSQL document storage isolated on internal Docker network (`nodegoat-net`, port 27017).
   - Houses collections for `users`, `allocations`, `memos`, and `counters`. Accessible strictly by the Node.js application container.

4. **Trust Boundary 4: CI/CD Pipeline & Secrets Automation (GitHub Actions)**
   - GitHub Actions runner executing automated security verification gates (Semgrep SAST, npm audit SCA, Gitleaks secrets scanning, Trivy container scanning).
   - Sensitive operational tokens injected via encrypted environment secrets, eliminating plaintext secrets in git.

---

## 2. STRIDE Threat Catalogue

| Threat ID | STRIDE Category | Threat Description & Attack Scenario | Impacted Component | Vulnerability Class |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Spoofing** | **Broken Authentication & Account Impersonation:** Insecure password storage (plaintext in unmodified code) and weak session secrets (`MINI_GOAT`) allow adversaries to capture credentials from database dumps or forge session cookies to impersonate employees. | `app/data/user-dao.js`<br/>`config/env/all.js` | CWE-256 / CWE-798 |
| **TH-02** | **Tampering** | **Server-Side JavaScript Injection (SSJS):** In `contributions.js`, contribution inputs are evaluated via `eval()`. An attacker submits malicious JS strings, hijacking server evaluation to tamper with retirement figures and execute arbitrary OS commands. | `app/routes/contributions.js` | CWE-94 / CWE-95 |
| **TH-03** | **Repudiation** | **Unlogged Allocation & Transaction Modifications:** Employees change sensitive asset allocations or profile details without persistent audit logs, preventing administrators from proving who executed unauthorized changes. | `app/data/allocations-dao.js` | CWE-778 |
| **TH-04** | **Information Disclosure** | **NoSQL Injection via MongoDB `$where`:** In `allocations-dao.js`, dynamic string concatenation in a `$where` clause allows attackers to inject JavaScript tautologies (`return 1 == '1`), exfiltrating private portfolio records of other users. | `app/data/allocations-dao.js` | CWE-943 |
| **TH-05** | **Denial of Service** | **Regular Expression Denial of Service (ReDoS):** The bank routing validation regex (`/([0-9]+)+#/`) in `profile.js` suffers from catastrophic backtracking, allowing attackers to lock the Node.js single-threaded event loop. | `app/routes/profile.js` | CWE-1333 / CWE-400 |
| **TH-06** | **Elevation of Privilege** | **Insecure Direct Object References (IDOR/BOLA):** Allocation endpoints rely on user-controllable URL path parameters (`/allocations/:userId`) without validating whether the requesting session owns the target resource ID. | `app/routes/allocations.js` | CWE-639 |

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
| **TH-01** | Broken Auth & Plaintext Passwords | 3 | 5 | **15** | **High** | Database compromise or network sniffing directly exposes plain credentials, leading to total account takeover. |
| **TH-02** | SSJS Remote Code Execution | 4 | 5 | **20** | **Critical** | `eval()` executes in process context with full host privileges; payload yields shell execution and total server compromise. |
| **TH-03** | Missing Audit Logging | 2 | 4 | **8** | **Medium** | Does not leak data directly, but cripples forensic incident attribution and regulatory compliance. |
| **TH-04** | NoSQL Injection Data Leak | 4 | 4 | **16** | **High** | Tautology payloads (`return 1 == '1`) bypass query restrictions and extract all employee portfolios. |
| **TH-05** | ReDoS Event Loop Exhaustion | 3 | 4 | **12** | **High** | Single-threaded Node.js event loop is completely frozen by exponential backtracking, causing total service denial. |
| **TH-06** | IDOR Cross-User Portfolio Access | 4 | 4 | **16** | **High** | Sequential user IDs are easily guessed in the browser URL bar; missing session validation exposes confidential financial records. |

---

## 4. Threat-to-Control Mapping

| Threat ID | Mitigating Security Control | Control Type | Exact Codebase / Pipeline Location | Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | Bcrypt salted one-way hashing (10 rounds); externalized session secret via `process.env.SESSION_SECRET`; HTTP-only cookies. | Preventative | `app/data/user-dao.js`<br/>`config/env/all.js` | Database inspection confirms salted `$2a$10$...` hashes; Gitleaks CI gate passes clean. |
| **TH-02** | Complete elimination of `eval()`; strict integer conversion via `parseInt(req.body.preTax, 10)` and boundary checking. | Preventative | `app/routes/contributions.js` (Commit `22574e5`) | Exploit re-attempt; Semgrep SAST rule `eval-with-expression` cleared. |
| **TH-03** | Persistent audit logging capturing user ID, timestamp, and modification actions. | Detective | `app/data/allocations-dao.js` | Forensic query verification in MongoDB audit collection. |
| **TH-04** | Elimination of dynamic `$where` JavaScript clauses; parameterization using native MongoDB query filters (`$gt`). | Preventative | `app/data/allocations-dao.js` | Exploit re-attempt; Semgrep NoSQL injection gate passes clean. |
| **TH-05** | Refactored non-greedy regular expressions (`/^[0-9]+#$/`) preventing catastrophic backtracking. | Preventative | `app/routes/profile.js` | High-length string stress test; Event loop latency stays under 5ms. |
| **TH-06** | Enforcing session-based identity validation (`req.session.userId`) over untrusted route parameters. | Preventative | `app/routes/allocations.js` | URL tampering test fails; unauthenticated cross-tenant access rejected. |
