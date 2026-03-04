"""
AstraVulnX v3.0.0 - AI-Powered Web Vulnerability Scanner
=========================================================

Author: Meheraz Hosen Siam
Role: Penetration Testing Learner
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan
License: MIT

A comprehensive web vulnerability scanner with AI/ML integration
for detecting OWASP Top 10 2024 vulnerabilities.
"""

__version__ = "3.0.0"
__author__ = "Meheraz Hosen Siam"
__email__ = "meheraz.siam@example.com"
__license__ = "MIT"
__repository__ = "https://github.com/meherazhosensiam/-AstraVulnX-Scan"

from astravulnx.core.scanner import Scanner, ScanResult, VulnerabilityFinding
from astravulnx.core.config import Config

__all__ = [
    "Scanner",
    "ScanResult", 
    "VulnerabilityFinding",
    "Config",
    "__version__",
    "__author__",
    "__repository__"
]
