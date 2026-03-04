"""
AstraVulnX v3.0.0 Crawler Module
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan

Web crawling and parameter discovery.
"""

CRAWLER_FEATURES = {
    "spider": {
        "description": "Crawl website to discover pages and endpoints",
        "max_depth": 3,
        "max_pages": 100
    },
    "parameter_discovery": {
        "description": "Discover URL and form parameters",
        "enabled": True
    },
    "form_extraction": {
        "description": "Extract forms and input fields",
        "enabled": True
    },
    "link_extraction": {
        "description": "Extract all links from pages",
        "enabled": True
    }
}

__all__ = ["CRAWLER_FEATURES"]
