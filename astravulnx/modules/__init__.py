"""
AstraVulnX v3.0.0 Detection Modules
Author: Meheraz Hosen Siam

All 11 vulnerability detection modules for OWASP Top 10 coverage.
"""

# Module names and their OWASP mappings
DETECTION_MODULES = {
    "sql_injection": {"name": "SQL Injection", "owasp": "A03", "cwe": "CWE-89", "severity": "Critical"},
    "xss": {"name": "Cross-Site Scripting", "owasp": "A03", "cwe": "CWE-79", "severity": "High"},
    "ssrf": {"name": "Server-Side Request Forgery", "owasp": "A10", "cwe": "CWE-918", "severity": "High"},
    "idor": {"name": "Insecure Direct Object Reference", "owasp": "A01", "cwe": "CWE-639", "severity": "High"},
    "open_redirect": {"name": "Open Redirect", "owasp": "A01", "cwe": "CWE-601", "severity": "Medium"},
    "directory_traversal": {"name": "Directory Traversal", "owasp": "A01", "cwe": "CWE-22", "severity": "High"},
    "file_upload": {"name": "Unrestricted File Upload", "owasp": "A04", "cwe": "CWE-434", "severity": "High"},
    "security_headers": {"name": "Security Headers", "owasp": "A05", "cwe": "CWE-693", "severity": "Medium"},
    "cors": {"name": "CORS Misconfiguration", "owasp": "A05", "cwe": "CWE-942", "severity": "Medium"},
    "clickjacking": {"name": "Clickjacking", "owasp": "A05", "cwe": "CWE-1021", "severity": "Medium"},
    "sensitive_data": {"name": "Sensitive Data Exposure", "owasp": "A02", "cwe": "CWE-200", "severity": "High"},
}

__all__ = ["DETECTION_MODULES"]
