"""
Configuration module for AstraVulnX v3.0.0
Author: Meheraz Hosen Siam
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class Config:
    """Scanner configuration"""
    target_url: str = ""
    timeout: int = 30
    max_pages: int = 100
    concurrent_requests: int = 10
    delay: float = 0.1
    user_agent: str = "AstraVulnX/3.0.0 (Meheraz Hosen Siam)"
    proxy: Optional[str] = None
    headers: Dict = field(default_factory=dict)
    cookies: Dict = field(default_factory=dict)
    verbose: bool = True
    output_dir: str = "./reports"
    
    # Scan profiles
    scan_profile: str = "quick"  # quick, standard, deep
    
    # Module settings
    enabled_modules: List[str] = field(default_factory=lambda: [
        "sql_injection", "xss", "ssrf", "idor", "open_redirect",
        "directory_traversal", "file_upload", "security_headers",
        "cors", "clickjacking", "sensitive_data"
    ])
