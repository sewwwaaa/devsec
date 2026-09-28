# IE3142: DevOps Security — Viva Voce Preparation Guide (25 Marks)
**Academic Year:** 2026 | **Year 3 Semester 1** | **Faculty of Computing, SLIIT**  
**Project:** OWASP NodeGoat DevSecOps Platform (Appendix A.1)  
**Repository:** `https://github.com/ashendilantha/nodegoat-devsecops`  

This preparation manual is structured directly around the **Viva Voce Assessment Rubric (Pages 10–11 of the Assignment Specification)**. Every team member must master these core questions and scenario defenses.

---

## Criterion 1: Understanding of Application & Architecture (3 Marks)

### Expected Questions & Model Answers:
**Q1: Walk me through your application architecture and explain how components communicate.**
> **Answer:**  
> We selected **OWASP NodeGoat**, an approved application under **Appendix A.1 (Intentionally Vulnerable Applications)**. It uses a two-tier containerised architecture orchestrated via `docker-compose.yml`:
> 1. **Web Application Tier (Node.js/Express):** Runs on port 4000 (and 5000 in dev). It serves dynamic HTML views via Swig templating, handles session management, and exposes controllers for employee retirement contributions, allocations, memos, and user profiles.
> 2. **Database Persistence Tier (MongoDB 4.4):** Runs on port 27017 within an isolated internal Docker bridge network (`nodegoat-net`). It stores documents across collections for `users`, `allocations`, `memos`, and sequence `counters`.
> Communication between the Node.js application and MongoDB takes place over TCP via Mongoose and native MongoDB driver connections using Data Access Objects (`user-dao.js`, `allocations-dao.js`, `memos-dao.js`).

**Q2: What trust boundaries exist in your architecture?**
> **Answer:**  
> We mapped four explicit trust boundaries:
> - **Boundary 1 (Public Client vs Ingress):** Separates untrusted public end-users and attackers from the application on port 4000.
> - **Boundary 2 (Application Tier vs Database Tier):** Isolates the MongoDB database from the outside world inside the private Docker network; direct access from external networks is blocked.
> - **Boundary 3 (User Input vs Internal Execution):** Input parameters (form posts, query strings) are validated before being passed to sensitive functions or database queries.
> - **Boundary 4 (Configuration & Secrets vs Code Repository):** Sensitive credentials (`MONGODB_URI`, `SESSION_SECRET`) are injected via environment variables and GitHub Actions secrets at runtime, ensuring zero plaintext secrets exist in git.

---

## Criterion 2: Threat Modelling & Risk Assessment (4 Marks)

### Expected Questions & Model Answers:
**Q1: How did you apply STRIDE to your architecture? Can you give an example of a threat for 'T' (Tampering) and 'E' (Elevation of Privilege)?**
> **Answer:**  
> - **Tampering (T):** Server-Side JavaScript Injection (SSJS) in `contributions.js`. An attacker submits JavaScript code into retirement contribution input fields (`preTax`), which the server executes via `eval()`. This allows tampering with calculations or executing arbitrary commands on the server. We mitigated this by removing `eval()` and strictly parsing inputs with `parseInt(req.body.preTax, 10)` (Commit `22574e5`).
> - **Elevation of Privilege (E):** Insecure Direct Object Reference (IDOR/BOLA) in `allocations.js`. A standard employee could change the URL parameter `/allocations/:userId` from their own ID to an administrative ID to inspect confidential retirement asset allocations. We mitigated this by deriving identity directly from the authenticated session (`req.session.userId`) rather than trusting URL parameters.

**Q2: How did you calculate your risk scores in the 5x5 matrix?**
> **Answer:**  
> Risk Score = Likelihood (1–5) × Impact (1–5).  
> For SSJS Injection (TH-02):
> - Likelihood is **4 (Likely)** because retirement contribution input fields are accessible to authenticated users and parameter manipulation is straightforward with web proxies.
> - Impact is **5 (Catastrophic)** because `eval()` executes in the Node.js process context, allowing Remote Code Execution (RCE) and total host compromise.
> - Total Score: 20 (Critical Risk), demanding immediate preventative remediation.

---

## Criterion 3: Vulnerability Assessment & Secure Coding Fixes (5 Marks)

### Expected Questions & Model Answers:
**Q1: Demonstrate and explain your SSJS Injection vulnerability and how you remediated it.**
> **Answer:**  
> - **The Flaw:** In `app/routes/contributions.js`, user-supplied contribution values were evaluated using JavaScript's `eval()`:
>   `const preTax = eval(req.body.preTax);`
> - **The Exploit:** We sent a POST payload: `preTax=10; res.end(require('child_process').execSync('whoami').toString())`. The server executed the command and streamed the server username back in the HTTP response.
> - **The Fix:** In commit `22574e5`, we eliminated `eval()` completely and used `parseInt(req.body.preTax, 10)`.
> - **Verification:** When repeating the exploit, `parseInt()` treats the input as inert text, returning `10` without executing the injected child process command.

**Q2: Demonstrate and explain your NoSQL Injection vulnerability and remediation.**
> **Answer:**  
> - **The Flaw:** In `app/data/allocations-dao.js`, dynamic string concatenation was used inside a MongoDB `$where` clause:
>   `$where: "this.userId == " + parsedUserId + " && this.stocks > '" + threshold + "'"`
> - **The Exploit:** We passed `threshold=1'; return 1 == '1`. The injected JavaScript returns `true` for all records, dumping the entire company's allocation records.
> - **The Fix:** We replaced the `$where` JavaScript clause with native MongoDB query operators:
>   `{ userId: parsedUserId, stocks: { $gt: parsedThreshold } }` combined with integer validation (`parseInt(threshold, 10)`).
> - **Verification:** Malicious JavaScript syntax is rejected or evaluated strictly as a numerical value, completely preventing query logic manipulation.

**Q3: What were your Semgrep SAST results before and after fixing the vulnerabilities?**
> **Answer:**  
> - **Before Fix:** Semgrep identified critical findings:
>   1. `javascript.lang.security.audit.eval-with-expression` (SSJS in `contributions.js`)
>   2. `javascript.express.mongodb.nosql-injection` (NoSQLi in `allocations-dao.js`)
>   3. `javascript.browser.security.raw-html-format` (Stored XSS in `memos.html`)
>   4. Cleartext password assignment in `user-dao.js`
> - **After Fix:** All targeted findings were resolved to **0 findings**, representing a **100% reduction** in verified high-severity vulnerabilities.

---

## Criterion 4: CI/CD Pipeline & Security Automation (5 Marks)

### Expected Questions & Model Answers:
**Q1: What are your four automated security gates in GitHub Actions?**
> **Answer:**  
> Defined in `.github/workflows/devsecops-pipeline.yml`:
> 1. **Gate 1 (SAST):** Semgrep scanning `app/` using `p/owasp-top-ten`, `p/nodejs`, and `p/security-audit` rules.
> 2. **Gate 2 (SCA):** `npm audit` scanning `package-lock.json` for known vulnerable third-party dependencies.
> 3. **Gate 3 (Secrets):** `gitleaks/gitleaks-action@v2` scanning commit diffs and history for leaked credentials and keys.
> 4. **Gate 4 (Container Security):** `aquasecurity/trivy-action@v0.24.0` scanning the built `nodegoat:latest` Docker image for base OS and library CVEs.

**Q2: How does your pipeline block a bad build? Prove that it genuinely fails rather than just warns.**
> **Answer:**  
> In Gate 1 (Semgrep), our workflow script inspects the generated `semgrep-results.json` using `jq`. If the count of critical findings exceeds threshold, the step executes `exit 1`:
> ```bash
> if [ $CRITICAL -gt 0 ]; then
>   echo "SAST gate FAILED: Critical findings detected"
>   exit 1
> fi
> ```
> In Gate 4 (Trivy), we configure `--exit-code 1 --severity CRITICAL`. GitHub Actions captures the non-zero exit code, immediately halts the workflow, prevents container deployment, and flags the run with a red failed status.

---

## Criterion 5: Industry Trends & Case Study Analysis (2 Marks)

### Expected Questions & Model Answers:
**Q1: Relate your project practices to a recent major supply-chain security breach (e.g. CircleCI).**
> **Answer:**  
> In the **CircleCI incident (January 2023)**, attackers stole engineer SSO session tokens from a compromised laptop, accessed build pipelines, and harvested customer secrets stored in environment variables.
> **Lessons applied to our DevSecOps pipeline:**
> 1. **Zero Hardcoded Secrets & Dynamic Ingestion:** We enforce strict Gitleaks pre-commit and CI scans, ensuring no secrets enter git.
> 2. **Least-Privilege Scoping:** Pipeline tokens are ephemeral and scoped with minimal required permissions.
> 3. **Automated SCA & Container Scanning:** We run `npm audit` and Trivy on every commit to ensure third-party supply-chain packages contain no backdoors or unpatched CVEs.

---

## Criterion 6 & 7: Technical Problem-Solving & Defense Tips

### Key Tips for the Viva:
- **Be Concise and Direct:** Answer the question first, then provide 1–2 sentences of technical justification.
- **Reference Specific Files and Lines:** Mention `app/routes/contributions.js` for SSJS, `app/data/allocations-dao.js` for NoSQLi, and `.github/workflows/devsecops-pipeline.yml` for the CI/CD pipeline.
- **Explain "Why", Not Just "What":** When asked why you removed `eval()`, explain that `eval()` passes unparsed strings into the V8 JavaScript compiler, executing arbitrary code with full process permissions.
- **Emphasize Appendix A.1 Compliance:** Clearly state that NodeGoat was selected from **Appendix A.1 of the IE3142 module brief** as a pre-vetted, containerised application with authentic OWASP Top 10 vulnerabilities.
