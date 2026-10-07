# DNS Security Auditor — Final Project Report

**Course:** Unix Internet Applications
**University:** Innopolis University, Fall 2025
**Author:** Anel Salkenova, Master SNE Program
**Repository:** github.com/niksgont/dns-security-audit

---

## 1. Introduction (I)

### 1.1 Problem Statement

The Domain Name System (DNS) is one of the most critical components of Internet infrastructure — it translates human-readable domain names into IP addresses and is used by virtually every Internet application. However, the original DNS protocol (RFC 1034/1035) was designed without any security mechanisms. As a result, DNS responses can be forged (spoofing/cache poisoning), users can be silently redirected to malicious servers, and email systems are vulnerable to spoofing and phishing attacks.

Real-world incidents demonstrate the severity of the problem:

- **2008 — Kaminsky Attack:** a critical DNS cache-poisoning vulnerability that affected a large portion of the Internet.
- **2016 — Dyn DNS DDoS Attack:** took down major services including Twitter, Netflix, and Reddit.
- **Ongoing:** DNS-based phishing attacks occur daily, exploiting domains with missing SPF/DMARC email authentication policies.

### 1.2 Original Task

The goal of this project was to design and implement a **command-line tool for DNS security assessment** that:

1. Checks **DNSSEC** implementation (cryptographic authentication of DNS data);
2. Verifies **email security records** (SPF and DMARC);
3. Assesses **DNS infrastructure redundancy** (nameserver count);
4. Measures **DNS performance** (query response time);
5. Produces an **easy-to-understand, scored security report** with a letter grade.

### 1.3 Target Users

- System administrators auditing their own domains;
- Security professionals performing quick assessments;
- Anyone who wants to understand the security posture of a domain.

---

## 2. Methods (M)

### 2.1 Tools and Technologies

| Tool / Library | Purpose |
|---|---|
| **Python 3** | Primary implementation language |
| **dnspython** | Performing DNS queries (DS, DNSKEY, TXT, NS, A records) |
| **colorama** | Cross-platform colored terminal output |
| **sys, time, datetime** (stdlib) | CLI handling, timing, timestamps |
| **GitHub Codespaces** | Cloud-based Linux development environment |

### 2.2 System Architecture

```
User Input (python dns_audit.py domain.com)
        │
        ▼
DNSAuditor class
 ├── check_dnssec()        → DS / DNSKEY / RRSIG queries
 ├── check_spf()           → TXT records (v=spf1)
 ├── check_dmarc()         → _dmarc.<domain> TXT records
 ├── check_nameservers()   → NS records
 ├── check_response_time() → timed A-record query
 ├── calculate_score()     → normalization to 0–100
 └── print_report()        → formatted terminal output
        │
        ▼
DNS Queries (via public resolvers 8.8.8.8, 1.1.1.1, 9.9.9.9)
        │
        ▼
Colorful Terminal Report — Score: X/100 (Grade: A–F)
```

### 2.3 Methodology of Individual Checks

- **DNSSEC:** A three-stage fallback detection — (1) query the **DS** record (Delegation Signer, most reliable indicator of a signed delegation); (2) if absent, query **DNSKEY**; (3) as a last resort, inspect the **A** record response for **RRSIG** records.
- **SPF:** Query TXT records and search for `v=spf1`; classify strictness by the `all` mechanism (`-all` strict, `~all` soft, otherwise weak).
- **DMARC:** Query `_dmarc.<domain>` TXT records for `v=DMARC1`; classify by policy (`p=reject`, `p=quarantine`, or monitor-only).
- **Nameservers:** Count NS records; ≥2 servers is considered redundant.
- **Response time:** Measure wall-clock time of an A-record query; <50 ms fast, <150 ms normal, otherwise slow.

### 2.4 Scoring Model

| Check | Max Points |
|---|---|
| DNSSEC | 25 |
| SPF | 15 |
| DMARC | 15 |
| Nameservers | 15 |
| Response Time | 15 |
| **Total (normalized to 100)** | **85** |

Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

---

## 3. Results (R)

Chapters organized by personal contribution.

### 3.1 DNSSEC Detection Module

Implemented a resilient three-method detection chain (DS → DNSKEY → RRSIG). Testing against real domains showed:

- Domains such as `github.com`, and `cloudflare.com` are DNSSEC-signed and detected correctly via DS records;
- Unsigned domains are correctly reported as failing;
- Timeout and resolution errors degrade gracefully to a "warning" status instead of crashing the tool.

### 3.2 Email Security Module (SPF + DMARC)

- SPF parsing correctly distinguishes strict (`-all`), soft (`~all`), and weak policies, and reports missing records as failures;
- DMARC detection queries the `_dmarc.` subdomain and handles both `NoAnswer` and `NXDOMAIN` exceptions, correctly identifying domains without DMARC;
- Testing revealed that many popular domains have strict SPF/DMARC, while smaller domains frequently lack any email authentication — confirming the motivation for the tool.

### 3.3 Infrastructure and Performance Module

- Nameserver counting correctly identifies redundant (≥2 NS) vs. single-server configurations;
- Response-time measurement produces consistent results across repeated runs, with public resolvers (8.8.8.8, 1.1.1.1) typically answering in under 50 ms for well-connected environments.

### 3.4 Scoring and Reporting Module

- Scores are normalized to a 0–100 scale with letter grades (A–F);
- The report is rendered as a formatted, color-coded terminal output showing each check's status (`[OK]` / `[!]` / `[X]`), the domain, timestamp, and final grade;
- Example outcome: a well-configured domain such as `cloudflare.com` scores in the A range, while a domain lacking DNSSEC and DMARC typically falls to C or lower.

### 3.5 Deployment and Usability

- The tool runs as a single command: `python dns_audit.py <domain>` (with optional `-v` for verbose mode);
- Fully cloud-executable in GitHub Codespaces — no local Linux installation required;
- Handles `KeyboardInterrupt` and unexpected exceptions with clean user-facing messages.

---

## 4. Discussion (A & D)

### 4.1 Interpretation of Results

The tool successfully demonstrates that DNS security posture varies dramatically across the Internet. Even among well-known domains, DNSSEC adoption is far from universal, and email authentication (SPF/DMARC) is often configured weakly (monitor-only or soft-fail). The scoring system makes these differences immediately visible and comparable, fulfilling the project's goal of raising security awareness through measurement.

### 4.2 Limitations

- **DNSSEC presence ≠ validation:** the tool detects whether DNSSEC records exist, but does not perform full cryptographic validation of the chain of trust;
- **SPF/DMARC parsing is simplistic:** `include` mechanisms, macro expansion, and DKIM are not analyzed;
- **Response-time measurement is noisy:** results depend on network conditions and resolver load, not only on the target domain's infrastructure;
- **Single vantage point:** all queries originate from one environment via public resolvers;
- **No persistence:** results are printed but not exported or stored.

### 4.3 Lessons Learned

- Cloud development environments (GitHub Codespaces) are a powerful solution when local resources or OS requirements are limiting;
- DNS security is considerably more complex than it appears — record presence, policy strictness, and chain-of-trust validation are distinct concerns;
- Robust error handling (timeouts, NXDOMAIN, NoAnswer) is essential for any network-facing tool;
- Simple, well-scoped tools can deliver real practical value.

### 4.4 Future Work

**Short-term:**
- DKIM record checking and deeper SPF policy analysis;
- IPv6 (AAAA) record support;
- Export results to JSON/CSV; batch domain checking.

**Medium-term:**
- SQLite storage for historical score tracking;
- Web dashboard (Flask/FastAPI) and an API endpoint;
- Email alerts when a domain's score drops.

**Long-term:**
- Full DNSSEC chain validation (not just record presence);
- DNS tunneling detection;
- Integration with threat-intelligence feeds;
- Docker containerization for easy deployment.

### 4.5 Conclusion

This project delivered a functional, easy-to-use DNS security auditing tool that assesses five critical aspects of domain security — DNSSEC, SPF, DMARC, nameserver redundancy, and response performance — and summarizes them in a scored, graded report. It applies course concepts (DNS protocol, DNSSEC, Unix command-line tooling, Python networking) to a real-world security problem and provides a solid foundation for future extensions.

---

*Repository: github.com/niksgont/dns-security-audit*

---
