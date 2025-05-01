# RedTeam Toolkit Suite

[![AGPL License](https://img.shields.io/badge/license-AGPL--3.0-green)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen)](https://opensource.org/)

A comprehensive suite of ethical hacking tools for vulnerability scanning and compliance verification.

---

## Table of Contents
1. [Tools Overview](#tools-overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Legal & Ethical Requirements](#legal-and-ethical-requirements)
6. [Contributing](#contributing)
7. [License](#license)
8. [Support](#support)

---

## Tools Overview

### 1. RedMapper - Advanced Vulnerability Scanner
**OWASP Top 10 Focused Security Auditor**  
```bash
python3 redmapper.py -u http://target.com --consent
```

### 2. Compliance Scanner - Regulatory Verification Tool
**GDPR/HIPAA/PCI-DSS/CCPA Compliance Checker**  
```bash
python3 compliancescanner.py -u https://target.com --gdpr --hipaa --consent
```

---

## Features

### RedMapper
- Subdomain Enumeration (1000+ patterns)
- Directory/File Brute-Forcing
- SQL Injection & XSS Detection
- JWT Token Analysis
- API Endpoint Discovery
- Multi-threaded Scanning (50+ threads)
- JSON/HTML Reporting

### Compliance Scanner
- GDPR Cookie Consent Verification
- HIPAA PHI Pattern Detection
- PCI-DSS Payment Security Checks
- CCPA Opt-Out Mechanism Testing
- DSAR Request Validation
- TLS 1.2+ Enforcement Checks
- Automated Compliance Reporting

---

## Installation

### Requirements
- Python 3.10+
- 4GB RAM (8GB recommended)
- Linux/macOS (Windows WSL2 supported)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/ssecgroup/RedTeam-Toolkit-Suite.git
   cd redteam-tools
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Download default wordlists:
   ```bash
   python3 redmapper.py --download-wordlists
   ```

### Required Packages
- `requests==2.31.0`
- `beautifulsoup4==4.12.3`
- `colorama==0.4.6`
- `pyOpenSSL==23.3.0`
- `tqdm==4.66.1`

---

## Usage

### RedMapper Basic Scan
```bash
python3 redmapper.py -u http://target.com \
  -s ./wordlists/subdomains.txt \
  -d ./wordlists/directories.txt \
  --threads 20 \
  --rate-limit 0.5 \
  --json \
  --consent
```

### Compliance Full Audit
```bash
python3 compliance.py -u https://target.com \
  --gdpr \
  --hipaa \
  --pci \
  --ccpa \
  --dsar \
  --consent
```

### Command Options

#### RedMapper
| Flag           | Description               | Default                  |
|----------------|---------------------------|--------------------------|
| `-u URL`       | Target URL                | Required                 |
| `-s PATH`      | Subdomain wordlist        | `wordlists/subdomains.txt` |
| `-d PATH`      | Directory wordlist        | `wordlists/directories.txt` |
| `--threads NUM`| Concurrent threads        | 10                       |
| `--rate-limit SEC` | Request delay          | 0.5s                     |
| `--json`       | JSON report output        | Disabled                 |

#### Compliance Scanner
| Flag           | Description               | Scope                    |
|----------------|---------------------------|--------------------------|
| `--gdpr`       | GDPR compliance checks    | EU                       |
| `--hipaa`      | HIPAA health data checks  | US                       |
| `--pci`        | Payment security checks   | Global                   |
| `--dsar`       | Data subject access tests | CCPA/GDPR                |

---

## Legal & Ethical Requirements

### Mandatory Practices
- Obtain written consent before scanning.
- Never test production systems without authorization.
- Delete all scan data within 7 days.
- Follow responsible disclosure procedures.

### Restricted Targets
- `.gov` domains - National infrastructure
- `.bank`/`.financial` - Banking institutions
- `.health`/`.med` - Healthcare providers

---

## Contributing

### Development Process
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feat/new-feature
   ```
3. Submit a pull request with:
   - Unit tests
   - Updated documentation
   - Security impact analysis

### Vulnerability Reporting
- **Email:** ssecgroup08@gmail.com  
- **PGP Key:** `0xABCDEF123456`  
- **Response SLA:** 72h for critical issues

---

## License

This project is licensed under the GNU Affero GPL v3.0:
- All modifications must be open-sourced.
- Commercial use requires written permission.
- Includes strict ethical use clauses.

**Copyright (C) 2025 SSECGROUP**  
Ethical use only. Unauthorized scanning prohibited.

---

## Support

For assistance, 
contact: **ssecgroup08@gmail.com**


donation link: 0x3d18a0941AF65df7cA2CB0D7d7E57DA1093E1044
