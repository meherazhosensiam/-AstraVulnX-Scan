"""
AstraVulnX v3.0.0 Reporting Module
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan

Professional PDF and HTML report generation.
"""

REPORT_FORMATS = {
    "pdf": {
        "description": "Professional PDF report with executive summary",
        "available": True
    },
    "html": {
        "description": "Interactive HTML report",
        "available": True
    },
    "json": {
        "description": "JSON export for CI/CD integration",
        "available": True
    },
    "csv": {
        "description": "CSV export for spreadsheet analysis",
        "available": True
    }
}

__all__ = ["REPORT_FORMATS"]
