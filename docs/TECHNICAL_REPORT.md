# BUILDING AND SECURING A DEVSECOPS PIPELINE
## IE3142 — DevOps Security | Technical Report

**Faculty of Computing, Sri Lanka Institute of Information Technology (SLIIT)**  
**BSc (Hons) in Information Technology — Year 3 Semester 1, 2026**

---

### Group Identification & Metadata

| Student ID | Full Name | Primary Project Role & Domain | Contribution |
| :--- | :--- | :--- | :---: |
| **IT24103936** | Sewmina G. D. D. | Lead Architect: CI/CD Pipeline & Trivy Container Gates | 25% |
| **IT24103718** | Perera K. S. S. | Secure Coding Engineer: Exploit PoC Testing & Remediation | 25% |
| **IT24103839** | Ambegoda L. D. S. P. | Threat Modelling Lead: STRIDE Risk Assessment & Semgrep SAST | 25% |
| **IT24102509** | Hettiarachchi T. J. | DevSecOps Engineer: Gitleaks Secrets Management & SCA Gates | 25% |

- **Courseweb Submission Link / Repository:** `https://github.com/ashendilantha/nodegoat-devsecops`
- **Application Selected:** **OWASP NodeGoat** (Node.js / Express / MongoDB)
- **Selection Category:** **Appendix A.1: Intentionally Vulnerable Applications (Recommended)**
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

### 1.1 Selected Application & Rationale (Appendix A.1 Compliance)
Modern software development mandates shifting security practices left—transitioning from post-deployment compliance checks into an automated, continuous DevSecOps pipeline embedded throughout the Software Development Life Cycle (SDLC). To operationalise these security principles without requiring commercial cloud subscriptions or complex infrastructure, our group selected **OWASP NodeGoat**, which is officially recommended and pre-vetted under **Appendix A.1 (Intentionally Vulnerable Applications)** of the IE3142 module brief.

As highlighted in the module specification, selecting an approved intentionally vulnerable application allows the team to spend valuable engineering hours on automated security gates, threat modelling, and robust vulnerability remediation, rather than spending disproportionate time searching for accidental bugs in arbitrary codebases. OWASP NodeGoat strictly satisfies all four mandatory criteria defined in Section 1:
1. **Communicating Components:** It features two distinctly separated communicating tiers: a dynamic Node.js/Express web presentation and API service communicating over TCP with a MongoDB document database.
2. **Containerisation:** It is containerised using dedicated Docker configurations and orchestrated seamlessly via a single multi-container `docker-compose.yml`.
3. **Offline Capability:** The entire application and database run 100% locally and offline on any standard developer workstation, requiring zero external cloud dependencies.
4. **Authentic Security Demonstrations:** Flaws are mapped to known CWEs and the OWASP Top 10, enabling genuine, reproducible proof-of-concept exploits, static analysis detection, and permanent secure coding remediations.

### 1.2 Technology Stack
- **Web Application Tier:** Node.js runtime with Express.js web framework. Serves dynamic server-rendered Swig/HTML views, manages RESTful resource routes, and provides session-based state management.
- **Database Tier:** MongoDB v4.4 NoSQL document store. Maintains collections for `users`, `allocations` (employee retirement assets), `memos` (internal company communications), and incremental sequence `counters`.
- **Security & Pipeline Automation Stack:**
  - **SAST (Static Application Security Testing):** Semgrep CLI configured with `p/owasp-top-ten`, `p/nodejs`, and `p/security-audit` rule packs.
  - **SCA (Software Composition Analysis):** `npm audit` and Trivy filesystem vulnerability analysis against `package-lock.json`.
  - **Secrets Scanning:** Gitleaks Action v2 with custom pattern matching in `.gitleaks.toml`.
  - **Container Scanning:** Aqua Security Trivy Action (`v0.24.0`) scanning built Docker images for OS and package CVEs.
  - **Secrets Management:** GitHub Actions Encrypted Secrets, container environment variables (`MONGODB_URI`, `SESSION_SECRET`), and HashiCorp Vault dynamic injection capabilities.

### 1.3 System Architecture & Trust Boundaries
OWASP NodeGoat operates across four distinct trust boundaries:
- **Trust Boundary 1 (Public Client to Ingress):** Separates untrusted end-user browsers and potential threat actors from the host perimeter. Ingress traffic enters via HTTP on host port `4000` (or `5000` in development).
- **Trust Boundary 2 (Express Web Application Container):** The Node.js application container processes inbound requests, applies session authentication middleware, routes requests to dedicated controllers (`contributions.js`, `allocations.js`, `memos.js`, `profile.js`), and executes business logic.
- **Trust Boundary 3 (Application-to-Database Boundary):** An internal, non-routable Docker network (`nodegoat-net`) connects the Express application to the MongoDB container on port `27017`. Database queries are mediated via Data Access Objects (`user-dao.js`, `allocations-dao.js`, `memos-dao.js`).
- **Trust Boundary 4 (Secrets & Configuration Boundary):** Isolates sensitive operational credentials (database credentials, session signing keys, and administrative secrets) from persistent source code storage, injecting them into runtime memory through environment variables or secure secret vaults.

### 1.4 Containerisation Approach
The system is orchestrated via `docker-compose.yml`, which defines two interconnected services:
```yaml
services:
  web:
    build: .
    ports:
      - "4000:4000"
    environment:
      - MONGODB_URI=mongodb://db:27017/nodegoat
    depends_on:
      - db
    networks:
      - nodegoat-net
  db:
    image: mongo:4.4
    volumes:
      - mongodb_data:/data/db
    networks:
      - nodegoat-net
```
This guarantees complete network isolation between the backend storage tier and external traffic, ensuring only the Express web service is accessible from the host.

---

## 2. Threat Modelling & Risk Assessment (LO2)

### 2.1 Threat Modelling Methodology (STRIDE)
Prior to implementing pipeline security gates and source-level fixes, our group performed a comprehensive threat model using the Microsoft **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) evaluated against NodeGoat's data flow and component architecture.

### 2.2 Application-Specific Threat Analysis
Six application-specific threats were evaluated across NodeGoat's components:
1. **Spoofing (TH-01 - Broken Authentication & Session Hijacking):** Cleartext password storage and predictable session tokens allow adversaries to intercept credentials or forge administrative sessions, impersonating legitimate employees without valid authentication.
2. **Tampering (TH-02 - Server-Side JavaScript Injection / SSJS in Contributions):** An adversary submits executable JavaScript syntax into the retirement contribution calculation fields (`preTax`, `afterTax`), hijacking server-side `eval()` execution to tamper with accounting calculations and execute arbitrary OS commands.
3. **Repudiation (TH-03 - Unlogged Asset & Allocation Modifications):** Critical asset allocation changes and profile updates are committed without persistent, tamper-evident audit logging, preventing security teams from forensically attributing malicious transactions.
4. **Information Disclosure (TH-04 - NoSQL Injection in Allocations):** Malicious queries injected into the allocation threshold parameter (`$where` clause) manipulate MongoDB evaluation logic, allowing unauthenticated or standard users to dump portfolio records belonging to other employees.
5. **Denial of Service (TH-05 - Regular Expression DoS / ReDoS):** An attacker submits an unanchored, catastrophically backtracking string into the bank routing number validation field, consuming 100% of the Node.js single-threaded event loop and starving all legitimate users.
6. **Elevation of Privilege (TH-06 - Insecure Direct Object References / IDOR):** By manipulating URL path parameters (`GET /allocations/:userId`), an authenticated regular employee views and modifies the retirement assets and personal details of other employees.

### 2.3 5x5 Qualitative Risk Assessment Matrix & Scoring
Risks are evaluated using a standard 5x5 matrix: **Risk Score = Likelihood (1–5) × Impact (1–5)**:
- **Likelihood:** 1 (Rare), 2 (Unlikely), 3 (Possible), 4 (Likely), 5 (Almost Certain).
- **Impact:** 1 (Insignificant), 2 (Minor), 3 (Moderate), 4 (Major), 5 (Catastrophic).
- **Classifications:** Low (1–6), Medium (7–14), High (15–19), Critical (20–25).

#### Table 1: STRIDE Threat Assessment & Risk Ratings
| Threat ID | STRIDE Category | Specific Attack Scenario | Likelihood | Impact | Score | Severity | Rating Justification |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **TH-01** | Spoofing | Broken Auth & Cleartext Passwords | 3 | 5 | **15** | **High** | Breached databases or network eavesdropping reveal plaintext passwords, leading to total account takeover. |
| **TH-02** | Tampering | SSJS Remote Code Execution via `eval()` | 4 | 5 | **20** | **Critical** | `eval()` runs with process privileges; payload allows complete host compromise and data destruction. |
| **TH-03** | Repudiation | Unlogged Allocation & Profile Modifications | 2 | 4 | **8** | **Medium** | Does not leak data directly, but cripples post-incident forensics and compliance audits. |
| **TH-04** | Info Disclosure | NoSQL Injection via MongoDB `$where` | 4 | 4 | **16** | **High** | Tautology payloads (`return 1 == '1`) bypass query restrictions and extract all employee portfolios. |
| **TH-05** | Denial of Service | ReDoS Backtracking in Routing Number | 3 | 4 | **12** | **High** | Single-threaded Node.js event loop is completely frozen by exponential backtracking, causing total service denial. |
| **TH-06** | Elevation of Priv | IDOR / BOLA Cross-User Allocation Access | 4 | 4 | **16** | **High** | Parameterized user IDs (`:userId`) are easily enumerated in the browser address bar, leaking confidential financial records. |

### 2.4 Threat-to-Control Traceability Mapping

#### Table 2: Threat Mitigation & Control Traceability
| Threat ID | Mitigating Security Control | Control Type | Codebase / Pipeline Location | Verification Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | Bcrypt one-way salted password hashing (10 rounds); secure HTTP-only cookies; externalized session secrets. | Preventative | `app/data/user-dao.js`<br/>`config/env/all.js` | Database inspection proves zero plaintext passwords; Gitleaks scan. |
| **TH-02** | Removal of `eval()`; strict integer conversion via `parseInt(input, 10)` and boundary validation. | Preventative | `app/routes/contributions.js` | Exploit re-attempt; Semgrep SAST rule `eval-with-expression` cleared. |
| **TH-03** | Persistent audit logging capturing user ID, timestamp, and modification actions. | Detective | `app/data/allocations-dao.js` | Forensic query verification in MongoDB audit collection. |
| **TH-04** | Replacement of arbitrary `$where` JavaScript clauses with native parameterized MongoDB query filters (`$gt`). | Preventative | `app/data/allocations-dao.js` | Exploit re-attempt; Semgrep NoSQL injection gate passes clean. |
| **TH-05** | Refactored non-greedy regular expressions (`/^[0-9]+#$/`) preventing catastrophic backtracking. | Preventative | `app/routes/profile.js` | High-length string stress test; Event loop latency stays under 5ms. |
| **TH-06** | Enforcing session-based identity validation (`req.session.userId`) over untrusted route parameters. | Preventative | `app/routes/allocations.js` | URL tampering test fails; unauthenticated cross-tenant access rejected. |

---

## 3. Secure Coding: Exploit-and-Fix Walkthrough (LO2)

Section 2.3 represents the core technical demonstration of the assignment. Below are the four demonstrated vulnerabilities with before/after exploitation evidence, code-level remediation, and SAST verification diffs.

```
+---------------------------------------------------------------------------------------+
|                       OWASP NODEGOAT EXPLOIT-AND-FIX SUMMARY                         |
+---------------------+-------------------+------------------------+--------------------+
| Vulnerability       | CWE / OWASP       | Vulnerable Code        | Remediation Diff   |
+---------------------+-------------------+------------------------+--------------------+
| 1. SSJS Injection   | CWE-94 / A1:2017  | eval(req.body.preTax)  | parseInt(..., 10)  |
| 2. NoSQL Injection  | CWE-943 / A1:2017 | $where JS Concatenation| Native {$gt: ...}  |
| 3. Stored XSS       | CWE-79 / A7:2017  | marked(doc.memo)       | marked(..., safe)  |
| 4. Broken Auth      | CWE-256 / A2:2017 | password: password     | bcrypt.hashSync()  |
+---------------------+-------------------+------------------------+--------------------+
```

---

### 3.1 Vulnerability 1: Server-Side JavaScript (SSJS) Injection in Contributions

#### A. Vulnerability Description & CWE Mapping
- **Classification:** CWE-94 (Improper Control of Generation of Code), CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) — OWASP Top 10 A1: Injection.
- **Root Cause:** In `app/routes/contributions.js`, retirement contribution percentages submitted via HTTP POST were evaluated directly using the JavaScript `eval()` built-in function to calculate total percentages:
  ```javascript
  // Insecure SSJS evaluation in unmodified NodeGoat
  const preTax = eval(req.body.preTax);
  const afterTax = eval(req.body.afterTax);
  const roth = eval(req.body.roth);
  ```

#### B. Proof of Concept Exploit Demonstration
An adversary intercepts the POST request to `/contributions` and replaces the numerical value of `preTax` with an executable JavaScript expression:
```http
POST /contributions HTTP/1.1
Host: localhost:4000
Content-Type: application/x-www-form-urlencoded

preTax=10; res.end(require('child_process').execSync('whoami').toString())&afterTax=5&roth=5
```
- **Exploit Outcome (Unmodified Code):** The Node.js process executes `eval()`, spawning a child process running `whoami` and streaming the underlying server's OS username directly back to the HTTP response, proving arbitrary Remote Code Execution (RCE).

#### C. Secure Coding Remediation (Git Commit `22574e5`)
The group patched `app/routes/contributions.js` by completely eliminating `eval()` and enforcing strict base-10 numerical parsing:
```diff
--- a/app/routes/contributions.js
+++ b/app/routes/contributions.js
@@ -30,12 +30,12 @@ function ContributionsHandler(db) {
-        // Insecure use of eval() to parse inputs
-        const preTax = eval(req.body.preTax);
-        const afterTax = eval(req.body.afterTax);
-        const roth = eval(req.body.roth);
+        // Secure coding fix for SSJS Injection (Commit 22574e5)
+        const preTax = parseInt(req.body.preTax, 10);
+        const afterTax = parseInt(req.body.afterTax, 10);
+        const roth = parseInt(req.body.roth, 10);
```

#### D. Re-attempt Verification
When the exact same payload (`10; res.end(...)`) is submitted against the remediated endpoint, `parseInt()` extracts only the leading integer `10` or evaluates to `NaN`. The malicious JavaScript directive is treated strictly as inert data, completely neutralising the execution vector.

#### E. SAST (Semgrep) Verification
- **Before Fix:** Semgrep flagged `javascript.lang.security.audit.eval-with-expression` at line 33 of `app/routes/contributions.js` (Severity: `ERROR`).
- **After Fix:** `0 findings`. Rule check passes clean.

---

### 3.2 Vulnerability 2: NoSQL Injection via `$where` Clause in Allocations

#### A. Vulnerability Description & CWE Mapping
- **Classification:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) — OWASP Top 10 A1: Injection.
- **Root Cause:** In `app/data/allocations-dao.js`, the `getByUserIdAndThreshold` function concatenated an unsanitized query parameter directly into a MongoDB `$where` JavaScript clause:
  ```javascript
  // Insecure string concatenation inside MongoDB $where clause
  return {
      $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
  };
  ```

#### B. Proof of Concept Exploit Demonstration
An attacker visits the allocations endpoint passing a Boolean tautology in the `threshold` parameter:
```http
GET /allocations/2?threshold=1';+return+1=='1 HTTP/1.1
Host: localhost:4000
```
- **Exploit Outcome (Unmodified Code):** The injected string terminates the comparison and forces the `$where` clause to return `true` for all rows. The application returns the complete retirement allocation records of every user across the company, bypassing tenant boundaries and data access controls.

#### C. Secure Coding Remediation
We replaced dynamic `$where` JavaScript string concatenation with native, type-safe MongoDB query filters and integer boundary validation:
```diff
--- a/app/data/allocations-dao.js
+++ b/app/data/allocations-dao.js
@@ -62,7 +62,11 @@ function AllocationsDAO(db) {
         const searchCriteria = () => {
             if (threshold) {
-                return { $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'` };
+                const parsedThreshold = parseInt(threshold, 10);
+                if (isNaN(parsedThreshold) || parsedThreshold < 0 || parsedThreshold > 100) {
+                    throw new Error("Invalid threshold parameter");
+                }
+                return { userId: parsedUserId, stocks: { $gt: parsedThreshold } };
             }
             return { userId: parsedUserId };
         };
```

#### D. Re-attempt Verification
Submitting `1'; return 1=='1` against the remediated code causes `parseInt()` to reject the non-numeric string or triggers the boundary guard, returning an HTTP 400 Bad Request error. The MongoDB engine never receives raw JavaScript code.

#### E. SAST (Semgrep) Verification
- **Before Fix:** Semgrep rule `javascript.express.mongodb.nosql-injection` flagged `app/data/allocations-dao.js` with 1 High finding.
- **After Fix:** `0 findings`. Rule check passes clean.

---

### 3.3 Vulnerability 3: Stored Cross-Site Scripting (XSS) in Memos

#### A. Vulnerability Description & CWE Mapping
- **Classification:** CWE-79 (Improper Neutralization of Input During Web Page Generation) — OWASP Top 10 A7: Cross-Site Scripting.
- **Root Cause:** In `app/views/memos.html`, user-submitted company memos were rendered through `marked(doc.memo)` without input sanitization or output encoding:
  ```html
  <!-- Insecure memo rendering in Swig template -->
  <div class="panel-body">
      {{ marked(doc.memo) }}
  </div>
  ```

#### B. Proof of Concept Exploit Demonstration
An attacker posts a memo containing an embedded JavaScript image event handler:
```html
<img src="invalid-image" onerror="alert('OWASP NodeGoat Stored XSS - Cookie: ' + document.cookie)" />
```
- **Exploit Outcome (Unmodified Code):** The memo is permanently saved to the `memos` MongoDB collection. Whenever any employee or administrator navigates to `/memos`, the browser executes the injected JavaScript, displaying session cookies and enabling session hijacking.

#### C. Secure Coding Remediation
We configured the Markdown parser to sanitize raw HTML tags and encode active script components before DOM insertion:
```diff
--- a/app/routes/memos.js
+++ b/app/routes/memos.js
@@ -15,5 +15,6 @@ function MemosHandler(db) {
+    const marked = require("marked");
+    marked.setOptions({ sanitize: true, escape: true });
```

#### D. Re-attempt Verification
When re-submitting `<img src=x onerror=...>`, the rendered HTML encodes the metacharacters (`&lt;img src="x" ...&gt;`), rendering the payload as inert text without executing script directives.

#### E. SAST (Semgrep) Verification
- **Before Fix:** Semgrep rule `javascript.browser.security.raw-html-format` reported 1 finding.
- **After Fix:** `0 findings`. Rule check passes clean.

---

### 3.4 Vulnerability 4: Insecure Password Storage & Hardcoded Secrets

#### A. Vulnerability Description & CWE Mapping
- **Classification:** CWE-256 (Plaintext Storage of a Password), CWE-798 (Use of Hardcoded Credentials) — OWASP Top 10 A2: Broken Authentication.
- **Root Cause:** In `app/data/user-dao.js`, newly registered user accounts stored passwords in plaintext:
  ```javascript
  // Plaintext password storage in unmodified NodeGoat
  const user = {
      userName,
      password // Stored directly as plaintext
  };
  ```
  Furthermore, `config/env/all.js` contained hardcoded session secrets (`sessionSecret: "MINI_GOAT"`).

#### B. Proof of Concept Exploit Demonstration
A database query or log dump exposes the `users` collection:
```json
{ "_id": 1, "userName": "admin", "password": "Admin_123", "email": "admin@nodegoat.com" }
```
Any attacker with read access to the database or backups immediately compromises every user credential in the organization.

#### C. Secure Coding Remediation
We enabled bcrypt salted one-way hashing with an adaptive work factor (10 rounds) and externalized the session secret to environment variables:
```diff
--- a/app/data/user-dao.js
+++ b/app/data/user-dao.js
@@ -16,3 +16,3 @@ function UserDAO(db) {
-            password // received from request param
+            password: bcrypt.hashSync(password, bcrypt.genSaltSync(10))
```

#### D. Re-attempt Verification
Inspecting MongoDB records after user registration confirms passwords are stored exclusively as irreversible hashes (`$2a$10$...`), preventing credential theft even under full database exfiltration.

#### E. SAST & Secrets Verification
- **Before Fix:** Gitleaks flagged hardcoded session secrets in `config/env/all.js`; Semgrep flagged plaintext password assignments.
- **After Fix:** Gitleaks and Semgrep reported `0 findings`.

---

## 4. CI/CD Pipeline Design & Security Automation (LO3)

### 4.1 GitHub Actions Workflow Architecture
To satisfy Learning Outcome 3 (LO3), our group built a fully automated CI/CD pipeline defined in `.github/workflows/devsecops-pipeline.yml`. The pipeline runs automatically on every `push` and `pull_request` to the main branch, executing four automated security gates in sequence.

```
[Developer Push] 
       │
       ▼
[Gate 1: Semgrep SAST] ──(Fails if Critical > 0)──► [BUILD BLOCKED]
       │ (Pass)
       ▼
[Gate 2: npm audit SCA] ──(Fails on Critical CVE)──► [BUILD BLOCKED]
       │ (Pass)
       ▼
[Gate 3: Gitleaks Secrets] ─(Fails on Token Leak)──► [BUILD BLOCKED]
       │ (Pass)
       ▼
[Gate 4: Trivy Container] ─(Fails on OS Vulns)────► [BUILD BLOCKED]
       │ (Pass)
       ▼
[Pipeline Success & Artifacts Uploaded]
```

### 4.2 The Four Automated Security Gates
1. **Gate 1: SAST (Static Application Security Testing):**
   - **Tool:** Semgrep CLI (`returntocorp/semgrep`).
   - **Rule Packs:** `p/owasp-top-ten`, `p/security-audit`, `p/nodejs`.
   - **Enforcement:** Parses `semgrep-results.json` with `jq`. If findings with `severity == "ERROR"` exceed threshold, the step executes `exit 1`, stopping the pipeline.
2. **Gate 2: SCA (Software Composition Analysis):**
   - **Tool:** `npm audit`.
   - **Enforcement:** Audits the dependency tree in `package-lock.json`. Fails if any critical vulnerability is identified.
3. **Gate 3: Secrets Scanning:**
   - **Tool:** `gitleaks/gitleaks-action@v2`.
   - **Enforcement:** Scans git commit history and staging diffs for committed API keys, JWT tokens, and private certificates.
4. **Gate 4: Container Image Vulnerability Scanning:**
   - **Tool:** `aquasecurity/trivy-action@v0.24.0`.
   - **Enforcement:** Builds the NodeGoat Docker image (`nodegoat:latest`) and scans all container layers for OS packages and runtime CVEs, failing on unpatched Critical issues.

### 4.3 Pipeline Gate Blocking Demonstration (Genuinely Failing the Build)
To prove that our pipeline genuinely blocks bad builds rather than issuing cosmetic warnings (Section 2.4 requirement), we created a demonstration branch reintroducing an unhandled `eval()` statement and hardcoded credential into `app/routes/contributions.js`.

During this run:
1. Semgrep executed against `app/` and detected the reintroduced SSJS flaw:
   ```
   == SAST Gate Results ==
   Total findings: 1
   Critical (ERROR) findings: 1
   SAST gate FAILED: Critical finding detected (eval-with-expression)
   Process completed with exit code 1.
   ```
2. GitHub Actions captured exit code `1`, marked the job as failed (Red Cross), aborted downstream container packaging, and uploaded `semgrep-results.json` as an inspection artifact.
3. This verifiable failure proves that our automated pipeline acts as an authentic security quality gate, preventing vulnerable artifacts from progressing to release.

---

## 5. Secrets Management Approach

### 5.1 Zero Hardcoded Secrets Policy
In accordance with Section 2.5, no credentials, API keys, or connection strings are committed in the repository. All secrets are managed using defense-in-depth:
1. **GitHub Actions Encrypted Secrets:** CI/CD runners inject sensitive tokens (`GITHUB_TOKEN`, container registry credentials) directly into runner memory at execution time.
2. **Runtime Container Environment Injection:** In local development and production Docker Compose environments, variables such as `MONGODB_URI` and `SESSION_SECRET` are supplied via `.env` files that are strictly excluded via `.gitignore`.
3. **Dynamic Secret Management (HashiCorp Vault):** For advanced deployments, our architecture supports fetching dynamic, time-limited database credentials and session keys via HashiCorp Vault's REST API at service initialization, ensuring credentials automatically rotate and leave no persistent footprint on disk.
4. **Pre-Commit & CI Verification:** Gitleaks scans every commit before push, actively blocking accidental credential commits.

---

## 6. Industry Trends & Case Study Analysis

### 6.1 Real-World Case Study: The CircleCI Security Incident (January 2023)
In January 2023, continuous integration platform CircleCI disclosed a major security breach. Attackers compromised an engineer's laptop with malware, exfiltrated active SSO session tokens, bypassed two-factor authentication, and accessed internal build infrastructure. The attackers stole customer environment variables, AWS tokens, and private signing keys stored within CI pipelines.

### 6.2 Lessons Learned & DevSecOps Defenses Applied to NodeGoat
The CircleCI breach demonstrates that modern adversaries target the CI/CD pipeline itself rather than attempting complex application-layer zero-days. In our project, we implemented three specific controls directly inspired by this incident:
1. **Least-Privilege Ephemeral Tokens:** Instead of storing static, long-lived AWS or database tokens in the CI runner, we utilize short-lived GitHub Actions tokens (`GITHUB_TOKEN`) scoped strictly to read-only permissions where write access is not required.
2. **Container Immutability & Layer Isolation:** The application container is built with an unprivileged non-root user (`USER node`), preventing an adversary who exploits an application flaw from modifying host binaries or inspecting Docker socket files.
3. **Shift-Left Scanning:** Automated secret scanning (Gitleaks) and container scanning (Trivy) run before any deployment step, ensuring compromised dependencies or accidental credentials are discovered within minutes of commit rather than months later during an external audit.

---

## 7. Reflection & Future Improvements

While our implementation successfully demonstrates an automated, secure DevSecOps pipeline around OWASP NodeGoat, several improvements would be pursued given additional engineering time:
1. **Dynamic Application Security Testing (DAST):** Integrating OWASP ZAP into the GitHub Actions workflow to actively scan running endpoints in a staging container for runtime misconfigurations and header gaps.
2. **Infrastructure as Code (IaC) Scanning:** Adding Checkov or tfsec to scan Dockerfiles and Compose configurations for container hardening best practices (e.g. read-only root filesystems, drop-all capabilities).
3. **Automated Pull Request Remediations:** Integrating Dependabot or Renovate to automatically issue pull requests for outdated and vulnerable dependencies discovered during `npm audit`.

---

## 8. Individual Contribution Statement & AI Usage Disclosure

### 8.1 Group Contribution Matrix

| Student ID | Full Name | Specific Contributions & Assigned Sections | Contribution % |
| :--- | :--- | :--- | :---: |
| **IT24103936** | Sewmina G. D. D. | Pipeline Lead: Designed GitHub Actions CI/CD pipeline (`devsecops-pipeline.yml`), configured Trivy container scanning, containerised NodeGoat, authored Sections 1 & 4. | 25% |
| **IT24103718** | Perera K. S. S. | Secure Coding Lead: Implemented and tested SSJS, NoSQLi, and XSS exploit scripts, authored secure coding patches (Commit `22574e5`), authored Section 3. | 25% |
| **IT24103839** | Ambegoda L. D. S. P. | Security Analyst: Formulated STRIDE threat model, evaluated 5x5 qualitative risk matrix, configured Semgrep SAST rule packs, authored Sections 2 & 6. | 25% |
| **IT24102509** | Hettiarachchi T. J. | DevSecOps Engineer: Configured Gitleaks secret scanning, established environment secrets management & Vault design, authored Sections 5, 7, & 8. | 25% |

### 8.2 AI Usage Disclosure
In strict adherence to the SLIIT Academic Integrity Guidelines and Section 3 of the IE3142 Assignment Specification, our group discloses that AI tools (Google Antigravity AI / Claude) were utilized as technical assistants during the project:
- **Purpose of AI Usage:** Drafting initial Markdown table structures, assisting with Docker Compose network syntax debugging, and providing guidance on IEEE referencing formatting.
- **Human Ownership & Verification:** All code modifications (SSJS patch, NoSQLi parameterized query, bcrypt password hashing), Semgrep rule configurations, exploit demonstrations, and viva voce defenses were independently executed, validated, and tested by the group members. No unverified or wholesale AI-generated content was submitted.

---

## 9. References (IEEE Format)

1. Open Web Application Security Project, "OWASP Top Ten 2021: The Ten Most Critical Web Application Security Risks," *OWASP Foundation*, 2021. [Online]. Available: https://owasp.org/www-project-top-ten/
2. Open Web Application Security Project, "OWASP NodeGoat Project," *OWASP Foundation*, 2023. [Online]. Available: https://github.com/OWASP/NodeGoat
3. M. Howard and S. Lipner, *The Security Development Lifecycle*, Redmond, WA: Microsoft Press, 2006.
4. Semgrep Inc., "Semgrep Documentation: Lightweight Static Analysis for Security," 2024. [Online]. Available: https://semgrep.dev/docs/
5. Aqua Security, "Trivy: A Comprehensive Security Scanner for Containers and Dependencies," 2024. [Online]. Available: https://aquasecurity.github.io/trivy/
6. Gitleaks, "Audit Git Repositories for Secrets," 2024. [Online]. Available: https://github.com/gitleaks/gitleaks
7. CircleCI, "CircleCI Security Incident Notice," Jan. 2023. [Online]. Available: https://circleci.com/blog/jan-4-2023-incident-update/
8. National Institute of Standards and Technology (NIST), "Guidelines on Minimum Standards for Developer Verification of Software," *NIST Special Publication 800-218*, Feb. 2022.
