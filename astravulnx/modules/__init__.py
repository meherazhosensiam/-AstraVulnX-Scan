"""
AstraVulnX v3.0.0 Detection Modules
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan

All 11 vulnerability detection modules for OWASP Top 10 coverage.
"""

# Module names and their OWASP mappings
DETECTION_MODULES = {
    "sql_injection": {
        "name": "SQL Injection Detection",
        "owasp": "A03 - Injection",
        "cwe": "CWE-89",
        "severity": "Critical",
        "description": "Detects SQL injection vulnerabilities including error-based, blind, and UNION-based"
    },
    "xss": {
        "name": "Cross-Site Scripting Detection",
        "owasp": "A03 - Injection",
        "cwe": "CWE-79",
        "severity": "High",
        "description": "Detects reflected, stored, and DOM-based XSS vulnerabilities"
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "owasp": "A10 - SSRF",
        "cwe": "CWE-918",
        "severity": "High",
        "description": "Detects SSRF with cloud metadata and internal network testing"
    },
    "idor": {
        "name": "Insecure Direct Object Reference",
        "owasp": "A01 - Broken Access Control",
        "cwe": "CWE-639",
        "severity": "High",
        "description": "Detects IDOR vulnerabilities through parameter manipulation"
    },
    "open_redirect": {
        "name": "Open URL Redirect",
        "owasp": "A01 - Broken Access Control",
        "cwe": "CWE-601",
        "severity": "Medium",
        "description": "Detects open redirect vulnerabilities with various bypass techniques"
    },
    "directory_traversal": {
        "name": "Directory Traversal",
        "owasp": "A01 - Broken Access Control",
        "cwe": "CWE-22",
        "severity": "High",
        "description": "Detects path traversal with encoding bypass techniques"
    },
    "file_upload": {
        "name": "Unrestricted File Upload",
        "owasp": "A04 - Insecure Design",
        "cwe": "CWE-434",
        "severity": "High",
        "description": "Detects file upload vulnerabilities with extension and MIME bypass"
    },
    "security_headers": {
        "name": "Security Headers Analysis",
        "owasp": "A05 - Security Misconfiguration",
        "cwe": "CWE-693",
        "severity": "Medium",
        "description": "Analyzes security headers including CSP, HSTS, X-Frame-Options"
    },
    "cors": {
        "name": "CORS Misconfiguration",
        "owasp": "A05 - Security Misconfiguration",
        "cwe": "CWE-942",
        "severity": "Medium",
        "description": "Detects CORS misconfigurations and origin validation issues"
    },
    "clickjacking": {
        "name": "Clickjacking Detection",
        "owasp": "A05 - Security Misconfiguration",
        "cwe": "CWE-1021",
        "severity": "Medium",
        "description": "Detects clickjacking vulnerabilities through frame embedding tests"
    },
    "sensitive_data": {
        "name": "Sensitive Data Exposure",
        "owasp": "A02 - Cryptographic Failures",
        "cwe": "CWE-200",
        "severity": "High",
        "description": "Detects sensitive data exposure including API keys, credentials, PII"
    }
}

def get_module_info(module_name: str) -> dict:
    """Get information about a specific module"""
    return DETECTION_MODULES.get(module_name, {})

def get_all_modules() -> list:
    """Get list of all available modules"""
    return list(DETECTION_MODULES.keys())

def get_modules_by_owasp(owasp_category: str) -> list:
    """Get modules that detect a specific OWASP category"""
    return [
        name for name, info in DETECTION_MODULES.items()
        if owasp_category in info.get("owasp", "")
    ]

__all__ = ["DETECTION_MODULES", "get_module_info", "get_all_modules", "get_modules_by_owasp"]
