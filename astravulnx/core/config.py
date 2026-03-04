"""
Configuration module for AstraVulnX v3.0.0
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json


@dataclass
class Config:
    """
    Scanner configuration for AstraVulnX v3.0.0
    
    Author: Meheraz Hosen Siam
    """
    
    # Target settings
    target_url: str = ""
    timeout: int = 30
    max_pages: int = 100
    concurrent_requests: int = 10
    delay: float = 0.1
    
    # Request settings
    user_agent: str = "AstraVulnX/3.0.0 (Meheraz Hosen Siam)"
    proxy: Optional[str] = None
    headers: Dict = field(default_factory=dict)
    cookies: Dict = field(default_factory=dict)
    
    # Output settings
    verbose: bool = True
    output_dir: str = "./reports"
    output_format: str = "json"  # json, pdf, html
    
    # Scan profiles
    scan_profile: str = "quick"  # quick, standard, deep
    
    # Module settings
    enabled_modules: List[str] = field(default_factory=lambda: [
        "sql_injection", "xss", "ssrf", "idor", "open_redirect",
        "directory_traversal", "file_upload", "security_headers",
        "cors", "clickjacking", "sensitive_data"
    ])
    
    # AI settings
    ai_enabled: bool = True
    false_positive_threshold: float = 0.7
    
    def __post_init__(self):
        """Initialize headers if empty"""
        if not self.headers:
            self.headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            }
    
    @classmethod
    def from_file(cls, config_path: str) -> 'Config':
        """Load configuration from JSON file"""
        with open(config_path, 'r') as f:
            data = json.load(f)
        return cls(**data)
    
    def to_file(self, config_path: str):
        """Save configuration to JSON file"""
        os.makedirs(os.path.dirname(config_path) or '.', exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(self.__dict__, f, indent=2)
    
    def get_scan_profiles(self) -> Dict:
        """Get available scan profiles"""
        return {
            "quick": {
                "timeout": 15,
                "max_pages": 20,
                "delay": 0.05,
                "payloads_per_param": 3
            },
            "standard": {
                "timeout": 30,
                "max_pages": 50,
                "delay": 0.1,
                "payloads_per_param": 10
            },
            "deep": {
                "timeout": 60,
                "max_pages": 200,
                "delay": 0.2,
                "payloads_per_param": 25
            }
        }


# Global configuration instance
DEFAULT_CONFIG = Config()
