"""
AstraVulnX v3.0.0 Utils Module
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan

Utility functions and helpers.
"""

import re
from urllib.parse import urlparse, urljoin

def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def normalize_url(url: str) -> str:
    """Normalize URL format"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.netloc

def is_internal_url(base_url: str, test_url: str) -> bool:
    """Check if test_url is internal to base_url"""
    base_domain = extract_domain(base_url)
    test_domain = extract_domain(test_url)
    return base_domain == test_domain

def get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        "Critical": "\033[91m",  # Red
        "High": "\033[93m",     # Yellow
        "Medium": "\033[94m",   # Blue
        "Low": "\033[92m",     # Green
        "Info": "\033[90m"      # Gray
    }
    return colors.get(severity, "\033[0m")

__all__ = [
    "is_valid_url",
    "normalize_url", 
    "extract_domain",
    "is_internal_url",
    "get_severity_color"
]
