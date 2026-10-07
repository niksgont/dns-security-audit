# DNS Security Auditor

A command-line tool that audits domain DNS security configuration.

## Features

- ✅ DNSSEC validation check
- ✅ SPF/DMARC/DKIM email security records
- ✅ Nameserver redundancy check
- ✅ DNS response time measurement
- ✅ Security score calculation
- ✅ Colorful terminal output

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run audit on a domain
python dns_audit.py google.com

# Run with verbose output
python dns_audit.py github.com -v

# Check multiple domains
python dns_audit.py google.com github.com cloudflare.com
```
─────────────────────────────────────────┘
```

## Requirements

- Python 3.7+
- Linux/macOS/WSL
- Internet connection
