"""
AstraVulnX v3.0.0 Intelligence Module
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan

Intelligence features: self-learning, online updates, CVE integration.
"""

INTELLIGENCE_FEATURES = {
    "self_learning": {
        "description": "Learns from scan results to improve accuracy",
        "enabled": True
    },
    "online_updates": {
        "description": "Fetches latest vulnerability data from online sources",
        "enabled": True,
        "sources": ["OWASP", "CVE Database", "Exploit-DB"]
    },
    "cve_integration": {
        "description": "Connects to CVE database for vulnerability information",
        "enabled": True
    },
    "pattern_sharing": {
        "description": "Share and import detection patterns",
        "enabled": False
    }
}

__all__ = ["INTELLIGENCE_FEATURES"]
