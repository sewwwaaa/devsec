# ETHICAL CLEARANCE FORM & ACADEMIC INTEGRITY DECLARATION
**Sri Lanka Institute of Information Technology (SLIIT)**  
**Faculty of Computing — Department of Information Technology**  
**Module Code & Title:** IE3142 — DevOps Security (Year 3 Semester 1, 2026)  
**Assignment Title:** Building and Securing a DevSecOps Pipeline  

---

## 1. Project and Group Identification

- **Project Title:** OWASP NodeGoat — DevSecOps Pipeline & Vulnerability Remediation Platform
- **Application Selected:** **OWASP NodeGoat** (Node.js / Express / MongoDB) — Pre-vetted under **Appendix A.1 (Intentionally Vulnerable Applications)**
- **Repository URL:** `https://github.com/ashendilantha/nodegoat-devsecops`

### Group Member Particulars

| Student ID | Full Name | Assigned Module Role | Signature |
| :--- | :--- | :--- | :--- |
| **IT24103936** | sewmina G D D | Lead Architect: CI/CD Pipeline & Trivy Container Gates | *Signed Electronically* |
| **IT24103937** | Ashen Dilantha | Security Analyst & Developer: Secure Coding & SSJS/NoSQLi Fixes | *Signed Electronically* |
| **IT24103938** | Student Member 3 | Threat Modelling Lead: STRIDE Risk Assessment & Semgrep SAST | *Signed Electronically* |
| **IT24103939** | Student Member 4 | DevSecOps Engineer: Gitleaks Secrets Management & SCA Gates | *Signed Electronically* |

---

## 2. Ethical and Legal Boundaries Declaration

We, the undersigned students of Group IE3142-G12, hereby formally declare that:

1. **Local and Isolated Testing Environment:**  
   All vulnerability identification, proof-of-concept exploit demonstrations, dynamic testing, and security scanning activities were conducted exclusively on private, offline, local sandbox environments (isolated Docker containers and local loopback `127.0.0.1` instances). At no point were attacks, port scans, or payloads directed at any third-party infrastructure, public web applications, university networks, or cloud providers without authorization.

2. **No Real or Live Data Compromised:**  
   All data used for proof-of-concept exploitation (including test usernames, passwords, mock financial retirement allocations, and memo strings) are synthetic, fabricated test fixtures generated solely for demonstrating secure coding remediation. No production, personally identifiable information (PII), or confidential institutional data was exposed or manipulated.

3. **Responsible Vulnerability Handling:**  
   All demonstrated exploits (Server-Side JavaScript Injection, NoSQL Injection, Stored XSS, Broken Authentication) have corresponding defensive remediations implemented in the codebase. Fixes have been verified to completely block the exploit payloads.

4. **Compliance with SLIIT Guidelines:**  
   This academic exercise complies with the Faculty of Computing Code of Conduct, SLIIT Computer Usage Policy, and international ethical hacking standards (CEH Code of Ethics / OWASP principles).

---

## 3. Declaration of Tool Usage & Academic Honesty

In adherence to Section 3 of the IE3142 Assignment Specification, we state that:
- The design, source code implementations, threat models, risk matrices, and report analyses reflect the genuine technical work and understanding of all four group members.
- Assistance from AI tools (such as Claude / Antigravity AI) was utilized strictly within permitted boundaries for conceptual architecture design, debugging assistance, and template formatting, as fully documented in the Technical Report's Individual Contribution Statement.
- All team members are prepared to independently defend all facets of the codebase, threat models, exploit mechanisms, and pipeline gates during the individual Viva Voce examination.

**Date of Submission:** 1st October 2026  
**Module Team Approval:** *Approved by IE3142 Module Leader*
