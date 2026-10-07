# DNS Security Auditor

---

## Slide 1: Title Slide

```
        DNS SECURITY AUDITOR
 A Command-Line Tool for DNS Security Assessment

 SNE Industrial Project
 Innopolis University, Fall 2025

 Anel Salkenova — Master SNE Program
```

---

## Slide 2: Why DNS Security Matters

```
DNS is the "Phonebook of the Internet"
• Translates domain names → IP addresses
• Used by EVERY internet application
• Critical infrastructure component

The Problem:
✗ Original DNS (RFC 1034/1035) has NO security features
✗ DNS responses can be forged (spoofing / cache poisoning)
✗ Users can be redirected to malicious sites
✗ Email spoofing and phishing attacks
```


---

## Slide 3: Real-World Impact

```
2008 — Kaminsky Attack
  Critical DNS cache-poisoning vulnerability
  Affected a large portion of the Internet

2016 — Dyn DNS Attack
  DDoS on DNS provider Dyn
  Took down Twitter, Netflix, Reddit, Spotify

Daily — DNS-based phishing
  Domains without SPF/DMARC are spoofed every day
```
---

## Slide 4: Project Objectives

```
Main Goal: Create a tool to assess DNS security posture

1. Check DNSSEC implementation
   (cryptographic authentication)
2. Verify email security records (SPF, DMARC)
3. Assess DNS infrastructure redundancy
4. Measure DNS performance
5. Generate an easy-to-understand security report

Target Users:
• System administrators
• Security professionals
• Anyone concerned about domain security
```
---

## Slide 5: Technical Background — DNSSEC

```
DNSSEC (DNS Security Extensions)

• Adds cryptographic signatures to DNS records
• Provides data origin authentication
• Ensures data integrity
• Chain of trust: Root → TLD → Domain

Key Records:
┌────────┬──────────────────────────────────┐
│ DNSKEY │ Public key for verification       │
│ RRSIG  │ Cryptographic signature           │
│ DS     │ Delegation Signer (chain of trust)│
└────────┴──────────────────────────────────┘
```
---

## Slide 6: Technical Background — Email Security

```
Email Spoofing Attack:
  Attacker sends email "from: ceo@company.com"
  → Without SPF/DMARC, receivers can't verify it
  → Phishing succeeds

SPF (Sender Policy Framework)
  TXT record listing AUTHORIZED mail servers

DMARC (Domain-based Message Authentication)
  Policy telling receivers what to do on failure:
  p=none (monitor) → p=quarantine → p=reject
```
---

## Slide 7: System Architecture

```
User Input (python dns_audit.py domain.com)
              │
              ▼
      ┌───────────────────────┐
      │    DNSAuditor class   │
      │  check_dnssec()       │──→ DS / DNSKEY / RRSIG
      │  check_spf()          │──→ TXT (v=spf1)
      │  check_dmarc()        │──→ _dmarc.<domain> TXT
      │  check_nameservers()  │──→ NS records
      │  check_response_time()│──→ timed A query
      │  calculate_score()    │
      │  print_report()       │
      └───────────────────────┘
              │
              ▼
   Score: X/100 (Grade: A–F)
```
---

## Slide 8: The Five Checks & Scoring

```
┌────────────────┬─────────────────────────────┬────────┐
│ Check          │ What It Tests               │ Points │
├────────────────┼─────────────────────────────┼────────┤
│ DNSSEC         │ Cryptographic DNS auth      │  25    │
│ SPF            │ Sender verification policy  │  15    │
│ DMARC          │ Email enforcement policy    │  15    │
│ Nameservers    │ Redundancy (2+ servers)     │  15    │
│ Response Time  │ Query performance           │  15    │
└────────────────┴─────────────────────────────┴────────┘

Grades: A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60
```
---

## Slide 9: Live Demo

```
LIVE DEMO

$ python dns_audit.py cloudflare.com
$ python dns_audit.py innopolis.university

Questions to watch for:
• Which domains have DNSSEC?
• Which have strict email policies (p=reject)?
• How do response times differ?
```
---

## Slide 10: Demo Output

```
```

---

## Slide 11: Challenges & Solutions

```
┌─────────────────────┬────────────────────────────────────┐
│ Challenge           │ Solution                           │
├─────────────────────┼────────────────────────────────────┤
│ No local Linux OS   │ GitHub Codespaces (free cloud      │
│                     │ Linux environment)                 │
│ Weak local machine  │ All computation in the cloud,      │
│                     │ zero local load                    │
│ DNS timeouts        │ Timeout handling + graceful        │
│                     │ degradation to "warning" status    │
└─────────────────────┴────────────────────────────────────┘

Lessons Learned:
• Cloud dev environments are powerful
• DNS security is more complex than it seems
• Many domains still lack basic security
```

---

## Slide 12: Future Work 

```
Short-term:
• DKIM record checking
• IPv6 (AAAA) support
• Export to JSON/CSV, batch checking

Medium-term:
• SQLite historical tracking
• Web dashboard (Flask/FastAPI) + API
• Email alerts for score drops

Long-term:
• Full DNSSEC chain validation
• DNS tunneling detection
• Threat-intelligence integration
• Docker deployment
```
---

## Slide 13: Conclusion

```
What Was Built:
✓ Functional DNS security auditing tool
✓ 5 critical security checks
✓ Scoring system for easy comparison
✓ Single command, cloud-executable

Why It Matters:
• DNS is critical infrastructure
• Many domains still lack basic security
• Awareness drives improvement

"Security should be measured and monitored."
```
---

## Slide 14: Q&A

```
Questions?

Demo Repository:
github.com/niksgont/dns-security-audit
```
---
