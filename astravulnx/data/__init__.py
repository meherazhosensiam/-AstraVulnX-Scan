"""
AstraVulnX v3.0.0 Data Module
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan
"""

import json
import os

# Path to knowledge base
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_BASE_PATH = os.path.join(DATA_DIR, 'knowledge_base.json')

def load_knowledge_base() -> dict:
    """Load the knowledge base from JSON file"""
    try:
        with open(KNOWLEDGE_BASE_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading knowledge base: {e}")
        return {}

# Load on import
KNOWLEDGE_BASE = load_knowledge_base()

__all__ = ["KNOWLEDGE_BASE", "load_knowledge_base"]
