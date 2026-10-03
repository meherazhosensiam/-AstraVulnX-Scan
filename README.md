# 🔮 AstraVulnX

**An asynchronous, rule-based web vulnerability scanner written in Python.**

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-yellow)
![License](https://img.shields.io/badge/license-MIT-red)
![Status](https://img.shields.io/badge/status-beta%20%2F%20learning%20project-orange)

**Author:** [Meheraz Hosen Siam](https://github.com/meherazhosensiam),
**Repository:** https://github.com/meherazhosensiam/-AstraVulnX-Scan

> ⚠️ **Legal disclaimer:** Use this tool only on systems you own or have **explicit written permission** to test. Unauthorized scanning may be illegal. The author is not responsible for misuse.

---

## 📖 About

AstraVulnX scans a single target URL, checks its HTTP security headers, and sends a small set of safe test payloads to look for common web vulnerabilities. Each finding includes a severity, CVSS-style score, OWASP Top 10 (2021) category, CWE ID, and evidence.

It is built with `asyncio` and `aiohttp`, and is designed as a learning project with a modular structure that can grow into a fuller scanner.

> **Honest scope:** Detection is based on signatures and heuristics (regex, reflection, response markers). It produces *potential* findings that must be **verified manually**. It is not a replacement for tools like Burp Suite, OWASP ZAP, or Nikto.

---

## ✅ What works today

| Check | How it detects | OWASP (2021) | CWE |
|---|---|---|---|
| **Security headers** | HEAD request; flags missing X-Frame-Options, CSP, HSTS, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy | A05 / A02 | various |
| **SQL injection** (error-based) | Injects payloads into URL parameters and form inputs; matches database error signatures (MySQL, PostgreSQL, Oracle, MSSQL, SQLite) | A03 | CWE-89 |
| **Reflected XSS** | Injects script/event payloads; flags unencoded reflection | A03 | CWE-79 |
| **SSRF** (heuristic) | Tries common parameters (`url`, `dest`, ...) with internal addresses; looks for internal-response markers | A10 | CWE-918 |
| **Open redirect** | Sends external URLs in redirect parameters; checks the `Location` header | A01 | CWE-601 |
| **Directory traversal** | Sends `../` payloads (plain and encoded); looks for file-content markers | A01 | CWE-22 |
| **CORS misconfiguration** | OPTIONS request with a forged `Origin`; checks `Access-Control-Allow-Origin` | A05 | CWE-942 |
| **Sensitive data exposure** | Regex on page source for API keys, private keys, secrets, emails, phone numbers, card-like numbers | A02 | CWE-200 |

Other working features:
- Async HTTP requests with configurable timeout and custom headers
- Form and URL-parameter discovery from the target page (regex-based)
- Findings sorted by severity with colored terminal output
- Scan statistics (by severity, module, OWASP category)
- JSON export (`-o report.json`)
- Python API usable from your own scripts

---

## 🚧 Planned / not implemented yet

These are listed in the code structure but **not functional yet**:

- IDOR, file upload, and dedicated clickjacking modules
- Crawler / multi-page scanning (only the given URL is scanned)
- Blind and time-based SQL injection
- Stored and DOM-based XSS
- HTML / PDF / CSV reports (JSON only for now)
- Working scan profiles (`quick` / `standard` / `deep`) and proxy support
- CVE / CWE online lookups and knowledge-base integration
- ML / LLM-based false-positive reduction (the `ai/` package currently holds design placeholders only)

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for the roadmap.

---

## 🚀 Installation

**Requirements:** Python 3.10+ and pip.

```bash
git clone https://github.com/meherazhosensiam/-AstraVulnX-Scan.git
cd -AstraVulnX-Scan

# Virtual environment (Linux/macOS)
python3 -m venv venv
source venv/bin/activate

# Virtual environment (Windows PowerShell)
# python -m venv venv
# .\venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

---

## 💻 Usage

```bash
# Basic scan
python main.py http://testphp.vulnweb.com

# Save results to JSON
python main.py http://testphp.vulnweb.com -o report.json

# Custom timeout (seconds)
python main.py http://testphp.vulnweb.com -t 15

# Show help
python main.py --help
```

> 💡 For parameter-based tests (SQLi, XSS, traversal), give a URL that already has a query string, e.g. `http://testphp.vulnweb.com/listproducts.php?cat=1`.

### Options

| Option | Description | Status |
|---|---|---|
| `target_url` | URL to scan (must start with `http://` or `https://`) | ✅ |
| `-o, --output` | Save results as JSON | ✅ |
| `-t, --timeout` | Request timeout in seconds (default 30) | ✅ |
| `-p, --profile` | `quick`, `standard`, `deep` | ⚠️ accepted, not applied yet |
| `--proxy` | Proxy URL (e.g. Burp at `http://127.0.0.1:8080`) | ⚠️ accepted, not applied yet |
| `-v, --version` | Show version | ✅ |

### Python API

```python
import asyncio
from astravulnx.core import Scanner, Config

async def main():
    config = Config(target_url="http://testphp.vulnweb.com", timeout=20)
    scanner = Scanner(config)
    result = await scanner.scan("http://testphp.vulnweb.com")
    print(f"Found {len(result.findings)} potential issues")
    result.save_json("report.json")

asyncio.run(main())
```

---

## 📂 Project structure

```
AstraVulnX-Scan/
├── main.py                      # CLI entry point
├── requirements.txt
├── setup.py
├── astravulnx/
│   ├── core/
│   │   ├── scanner.py           # Scanner engine and all working checks
│   │   └── config.py            # Config dataclass
│   ├── modules/                 # Module metadata (OWASP/CWE mapping)
│   ├── data/knowledge_base.json # Static OWASP reference data
│   ├── crawler/                 # Placeholder (planned)
│   ├── reporting/               # Placeholder (planned)
│   ├── intelligence/            # Placeholder (planned)
│   ├── ai/                      # Placeholder (planned)
│   └── utils/                   # URL helpers
```

### Scan flow

1. **Reconnaissance:** GET the target, extract forms and parameters
2. **Header analysis:** HEAD request, report missing security headers
3. **Vulnerability detection:** run enabled modules
4. **Report:** terminal summary and optional JSON

---

## 📊 Example JSON output

```json
{
  "scanner": "AstraVulnX v3.0.0",
  "target": "http://testphp.vulnweb.com",
  "duration": "8.31s",
  "total_findings": 8,
  "statistics": {
    "findings_by_severity": {"High": 1, "Medium": 3, "Low": 4}
  },
  "findings": [
    {
      "module": "security_headers",
      "vulnerability_type": "Missing Content-Security-Policy",
      "severity": "Medium",
      "owasp": "A05 - Security Misconfiguration",
      "evidence": "Header not present in response"
    }
  ]
}
```

---

## ⚠️ Known limitations

- Scans only the single URL provided (no crawling)
- Findings are heuristic and can include **false positives** (for example, SSRF markers like "nginx" or the email regex) and **false negatives**
- Only error-based SQL injection is detected
- Requests run sequentially, so large scans will be slow
- Form tests POST to the page URL rather than the form's `action`

---

## 🧪 Safe practice targets

- [DVWA](https://github.com/digininja/DVWA), run locally
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), run locally
- [testphp.vulnweb.com](http://testphp.vulnweb.com), a public demo site intended for scanner testing

---

## 🤝 Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit and push your changes
4. Open a Pull Request

---

## 📄 License

MIT License. See [LICENSE](LICENSE).

## 🙏 Acknowledgments

- OWASP Foundation and the CWE project
- The wider security community
- Built with AI assistance (z.ai); testing, debugging, and maintenance by the author

---

<p align="center"><b>Made by Meheraz Hosen Siam</b></p>
