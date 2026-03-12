<p align="center">
  <img src="https://img.shields.io/badge/AstraVulnX-v3.0.0-blue?style=for-the-badge&logo=security" alt="AstraVulnX Version">
  <img src="https://img.shields.io/badge/Author-Meheraz%20Hosen%20Siam-green?style=for-the-badge" alt="Author">
  <img src="https://img.shields.io/badge/Python-3.10+-yellow?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge" alt="License">
</p>
  
<p align="center">
  <img src="https://img.shields.io/badge/OWASP-Top%2010%202024-purple?style=flat-square" alt="OWASP">
  <img src="https://img.shields.io/badge/AI%2FML-Integrated-orange?style=flat-square" alt="AI/ML">
  <img src="https://img.shields.io/badge/CVE-Database-black?style=flat-square" alt="CVE">
  <img src="https://img.shields.io/badge/CWE-Mapped-blue?style=flat-square" alt="CWE">
</p>

<h1 align="center">🔮 AstraVulnX v3.0.0</h1>
<h1 align="center"> Build with the help of z.ai And the bugs and problems are solved by meheraz hosen siam</h5>

<h3 align="center">AI-Powered Web Vulnerability Scanner</h3>

<p align="center">
  <b>Author:</b> <a href="https://github.com/meherazhosensiam">Meheraz Hosen Siam</a><br>
  <b>Role:</b> Penetration Testing Learner<br>
  <b>Repository:</b> <a href="https://github.com/meherazhosensiam/-AstraVulnX-Scan">https://github.com/meherazhosensiam/-AstraVulnX-Scan</a>
</p>

---

## ❤️ Made with Love

<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-❤️-red?style=for-the-badge" alt="Made with Love">
  <img src="https://img.shields.io/badge/By-Meheraz%20Hosen%20Siam-brightgreen?style=for-the-badge" alt="By Meheraz">
</p>

---

## 📖 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Detection Modules](#-detection-modules)
- [OWASP Top 10 Coverage](#-owasp-top-10-coverage)
- [AI/ML Features](#-aiml-features)
- [Examples](#-examples)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## 🎯 About

**AstraVulnX** is a comprehensive, AI-powered web vulnerability scanner designed to detect OWASP Top 10 2024 vulnerabilities. Built by a penetration testing learner, for penetration testing learners.

### Key Highlights:
- 🔍 **11 Detection Modules** covering all OWASP Top 10 categories
- 🤖 **AI/ML Integration** for intelligent vulnerability detection
- 📊 **Professional PDF Reports** generated automatically
- 🌐 **Online Updates** for latest CVE and vulnerability data
- 📚 **Knowledge Base** with OWASP, CWE, and CVE mappings

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **SQL Injection Detection** | Error-based, Blind, UNION-based detection |
| 🎭 **XSS Detection** | Reflected, Stored, DOM-based XSS |
| 🌐 **SSRF Detection** | Cloud metadata, Internal network scanning |
| 🔑 **IDOR Detection** | Insecure Direct Object References |
| 🔀 **Open Redirect** | URL redirect vulnerability detection |
| 📁 **Directory Traversal** | Path traversal with encoding bypass |
| 📤 **File Upload** | Unrestricted upload detection |
| 🛡️ **Security Headers** | CSP, HSTS, X-Frame-Options analysis |
| 🌍 **CORS Misconfiguration** | Cross-origin security issues |
| 🖼️ **Clickjacking** | Frame embedding vulnerabilities |
| 🔒 **Sensitive Data** | API keys, credentials, PII detection |

---

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Install from GitHub

```bash
# Clone the repository
git clone https://github.com/meherazhosensiam/-AstraVulnX-Scan.git

# Navigate to directory
cd -AstraVulnX-Scan

#Make a virtual environment (linux/macos)
python3 -m venv venv
source venv/bin/activate
#Make a virtual environment (windows)
venv\Scripts\activate
#PowerShell:
.\ venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python main.py <target_url>
```

### Quick Install

```bash
pip install astravulnx
```

---

## 💻 Usage

### Basic Scan

```bash
python main.py http://testphp.vulnweb.com
```

### Advanced Options

```bash
# Deep scan
python main.py http://example.com --profile deep

# With proxy
python main.py http://example.com --proxy http://127.0.0.1:8080

# Output to file
python main.py http://example.com --output report.json
```

### Python API

```python
from astravulnx.core import Scanner, Config

config = Config(
    target_url="http://testphp.vulnweb.com",
    scan_profile="quick"
)

scanner = Scanner(config)
result = await scanner.scan("http://testphp.vulnweb.com")

print(f"Found {len(result.findings)} vulnerabilities!")
```

---

## 🔧 Detection Modules

| Module | OWASP | CWE | Severity |
|--------|-------|-----|----------|
| SQLInjectionModule | A03 - Injection | CWE-89 | Critical |
| XSSModule | A03 - Injection | CWE-79 | High |
| SSRFModule | A10 - SSRF | CWE-918 | High |
| IDORModule | A01 - Broken Access | CWE-639 | High |
| OpenRedirectModule | A01 - Broken Access | CWE-601 | Medium |
| DirectoryTraversalModule | A01 - Broken Access | CWE-22 | High |
| FileUploadModule | A04 - Insecure Design | CWE-434 | High |
| SecurityHeadersModule | A05 - Misconfiguration | CWE-693 | Medium |
| CORSModule | A05 - Misconfiguration | CWE-942 | Medium |
| ClickjackingModule | A05 - Misconfiguration | CWE-1021 | Medium |
| SensitiveDataModule | A02 - Crypto Failures | CWE-200 | High |

---

## 🛡️ OWASP Top 10 Coverage

| OWASP 2024 | Detection Coverage |
|------------|-------------------|
| A01 - Broken Access Control | ✅ IDOR, Open Redirect, Directory Traversal |
| A02 - Cryptographic Failures | ✅ Sensitive Data, Security Headers |
| A03 - Injection | ✅ SQL Injection, XSS |
| A04 - Insecure Design | ✅ File Upload |
| A05 - Security Misconfiguration | ✅ Headers, CORS, Clickjacking |
| A06 - Vulnerable Components | ✅ CVE Database Integration |
| A07 - Auth Failures | ✅ Credential Exposure Detection |
| A08 - Integrity Failures | ✅ File Upload Validation |
| A09 - Logging Failures | ✅ Built-in Logging |
| A10 - SSRF | ✅ Dedicated SSRF Module |

---

## 🤖 AI/ML Features

AstraVulnX integrates AI/ML for enhanced detection:

- **VulnerabilityClassifier** - ML-based vulnerability classification
- **PayloadIntelligence** - Smart payload generation
- **AnomalyDetector** - Response anomaly detection
- **ResponseAnalyzer** - Pattern analysis
- **FalsePositiveReducer** - AI-powered FP reduction
- **LLMIntegration** - Large Language Model analysis

---

## 📊 Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║            AstraVulnX v3.0.0 - Vulnerability Scanner          ║
║              Author: Meheraz Hosen Siam                       ║
╚═══════════════════════════════════════════════════════════════╝

Target: http://testphp.vulnweb.com
Duration: 8.31 seconds
Total Findings: 8

Findings by Severity:
  [HIGH] 1 findings
  [MEDIUM] 3 findings
  [LOW] 4 findings
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Contact

**Meheraz Hosen Siam**

- GitHub: [@meherazhosensiam](https://github.com/meherazhosensiam)
- Repository: [AstraVulnX-Scan](https://github.com/meherazhosensiam/-AstraVulnX-Scan)

---

## 🙏 Acknowledgments

- OWASP Foundation for Top 10 guidelines
- Security research community
- All contributors and supporters

---

<p align="center">
  <b>Made with ❤️ by Meheraz Hosen Siam</b><br>
  <a href="https://github.com/meherazhosensiam/-AstraVulnX-Scan">
    <img src="https://img.shields.io/github/stars/meherazhosensiam/-AstraVulnX-Scan?style=social" alt="GitHub stars">
  </a>
</p>
