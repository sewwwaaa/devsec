# IE3142: DevOps Security — Viva Voce Preparation Guide (25 Marks)
**Academic Year:** 2026 | **Year 3 Semester 1** | **Faculty of Computing, SLIIT**  
**Project:** TaskShield DevSecOps Platform  

This preparation manual is structured directly around the **Viva Voce Assessment Rubric (Pages 10–11 of the Assignment Specification)**. Every team member must master these core questions and scenario defenses.

---

## Criterion 1: Understanding of Application & Architecture (3 Marks)

### Expected Questions & Model Answers:
**Q1: Walk me through your application architecture and explain how components communicate.**
> **Answer:**  
> TaskShield uses a three-tier containerised architecture comprising:
> 1. **Presentation Tier (Frontend & Reverse Proxy):** An Nginx Alpine container serving a single-page application and acting as a reverse proxy. It listens on host port 8080 and sets mandatory HTTP security headers (Helmet CSP, HSTS, X-Frame-Options: DENY).
> 2. **Application Tier (Backend Microservice):** A Node.js and Express REST API running on port 5000 in an isolated internal bridge network (`app-network`). It processes authentication, executes business logic, enforces Joi schema validation, and issues/verifies HS256 JWTs.
> 3. **Persistence Tier:** Relational database storage (SQLite persistent volume or PostgreSQL) maintaining isolated user, note, and immutable audit log tables.
> Ingress traffic flows from the browser to Nginx via HTTPS/TLS, which proxies API calls internally over HTTP to the backend.

**Q2: What trust boundaries exist in your architecture?**
> **Answer:**  
> We have mapped four explicit trust boundaries:
> - **Boundary 1 (Public Internet vs DMZ):** Separates untrusted end-users and attackers from our perimeter.
> - **Boundary 2 (DMZ vs Internal Network):** Nginx terminates outside traffic and passes sanitized reverse-proxy traffic to the internal container network.
> - **Boundary 3 (API Controller vs Business Logic):** Input validation middleware (Joi) and rate limiting guard internal route handlers against malformed input and brute-forcing.
> - **Boundary 4 (Application vs Database/Secrets):** Database queries are isolated behind parameterized database drivers; runtime secrets are injected directly into process memory from HashiCorp Vault or environment variables, completely absent from public storage.

---

## Criterion 2: Threat Modelling & Risk Assessment (4 Marks)

### Expected Questions & Model Answers:
**Q1: How did you apply STRIDE to your architecture? Can you give an example of a threat for 'T' (Tampering) and 'E' (Elevation of Privilege)?**
> **Answer:**  
> - **Tampering (T):** Stored Cross-Site Scripting (XSS) in task descriptions. An authenticated user inputs persistent `<script>` or `<img onerror=...>` payloads into the database. When other users view the note, the script executes in their browser context. We mitigated this by integrating `sanitize-html` to whitelist safe markup and enforcing a strict Content-Security-Policy (CSP) via Helmet.
> - **Elevation of Privilege (E):** Broken Object Level Authorization (BOLA/IDOR). User Bob could modify the URL parameter from `/api/notes/2` to `/api/notes/1` to access Alice's confidential budget. We mitigated this by implementing an object ownership guard in `noteController.js` requiring `note.userId === req.user.id || req.user.role === 'admin'`.

**Q2: How did you calculate your risk scores in the 5x5 matrix?**
> **Answer:**  
> Risk Score = Likelihood (1–5) × Impact (1–5).  
> For SQL Injection (TH-04):
> - Likelihood is **4 (Likely)** because authentication endpoints are public and attackers routinely automate credential attacks.
> - Impact is **5 (Catastrophic)** because a successful SQL tautology bypasses authentication and allows full schema exfiltration.
> - Total Score: 20 (Critical Risk), demanding immediate preventative controls (parameterized queries).

---

## Criterion 3: Vulnerability Assessment & Secure Coding Fixes (5 Marks)

### Expected Questions & Model Answers:
**Q1: Demonstrate and explain your SQL Injection vulnerability and how you remediated it.**
> **Answer:**  
> - **The Flaw:** In `authController.vulnerableLogin`, raw SQL concatenation was used:
>   `SELECT * FROM users WHERE username = '${username}'`.
> - **The Exploit:** We passed `admin' OR '1'='1` in the username. The SQL engine evaluates the condition as true for all rows, returning the first record (admin) without checking the password.
> - **The Fix:** In `authController.login`, we implemented parameterized queries with SQLite placeholders (`SELECT * FROM users WHERE username = ?`, `[username]`) alongside Joi alphanumeric input validation.
> - **Verification:** When re-running the exact same exploit payload, the server returns HTTP 400 Validation Error (`username must only contain alpha-numeric characters`), stopping execution before the database is ever touched.

**Q2: What were your Semgrep SAST results before and after fixing the 4 vulnerabilities?**
> **Answer:**  
> - **Before Fix:** Semgrep identified 4 Critical/Error findings:
>   1. `devsec-sql-nosql-injection` (CWE-89) in `authController.js`
>   2. `devsec-hardcoded-jwt-secret` (CWE-798) in `authController.js`
>   3. `devsec-stored-xss-raw-storage` (CWE-79) in `noteController.js`
>   4. `devsec-missing-authorization-check` (CWE-639) in `noteController.js`
> - **After Fix:** On all production routes (`/api/auth/login`, `/api/notes`), SAST findings dropped to **0 findings**, representing a **100% reduction** in exploitable vulnerabilities.

---

## Criterion 4: CI/CD Pipeline & Security Automation (5 Marks)

### Expected Questions & Model Answers:
**Q1: What are your four automated security gates in GitHub Actions?**
> **Answer:**  
> 1. **Gate 1 (SAST):** Semgrep scanning for coding flaws and OWASP Top 10 patterns.
> 2. **Gate 2 (SCA):** `npm audit --audit-level=high` and Trivy Filesystem scanning third-party dependencies for known CVEs.
> 3. **Gate 3 (Secrets):** Gitleaks scanning commits and git history using `.gitleaks.toml` to prevent committed credentials.
> 4. **Gate 4 (Container Security):** Trivy scanning the built Docker image (`aquasecurity/trivy-action`) with `--severity CRITICAL --exit-code 1`.
> 5. **Extra Credit (DAST):** OWASP ZAP baseline scan executing active and passive scans against the running container endpoints.

**Q2: How does your pipeline block a bad build? Prove that it genuinely fails rather than just warns.**
> **Answer:**  
> In `.github/workflows/devsecops-failure-demo.yml` and Gate 2 of our CI/CD pipeline, we configure `npm audit --audit-level=high` and Trivy with `--exit-code 1`. When a high-severity transitive vulnerability or leaked credential is introduced, the command returns exit code 1. GitHub Actions detects the non-zero exit status, immediately aborts subsequent deployment stages, and marks the workflow run as failed with a red badge, preventing vulnerable code from reaching production.

---

## Criterion 5: Industry Trends & Case Study Analysis (2 Marks)

### Expected Questions & Model Answers:
**Q1: Relate your project practices to a recent major supply-chain security breach (e.g. SolarWinds or CircleCI).**
> **Answer:**  
> In the **CircleCI security incident (January 2023)**, an engineer's laptop was compromised with malware that stole session tokens, allowing attackers to access internal build systems and customer-encrypted environment variables.
> **Lessons applied to TaskShield:**
> 1. **Shift-Left Secrets Management:** Instead of storing persistent plaintext credentials in CI runners or repos, we use ephemeral tokens and HashiCorp Vault dynamic runtime injection.
> 2. **Short-lived Tokens:** Our JWTs and pipeline tokens expire within 15 minutes (`JWT_EXPIRES_IN=15m`), severely narrowing the window of opportunity for stolen session tokens.
> 3. **Container Immutability & SBOM:** We scan container base images with Trivy to guarantee no malicious upstream dependencies are packaged into our release artifacts.

---

## Criterion 6 & 7: Technical Problem-Solving & Defense Tips

1. **Be Specific:** Always reference the actual file names:
   - `backend/src/controllers/authController.js`
   - `backend/src/middleware/validator.js`
   - `.github/workflows/devsecops.yml`
   - `.gitleaks.toml`
2. **Demonstrate Working Evidence:** Be ready to show `node scripts/run_all_exploits.js` and open the local UI at `http://localhost:5000` to execute live attacks and fixes right in front of the assessor.
3. **Emphasize the Mindset:** Emphasize that DevSecOps is not an afterthought checklist, but an automated, shift-left pipeline with enforced quality gates.
