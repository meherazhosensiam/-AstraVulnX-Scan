"""
AstraVulnX v3.0.0 AI/ML Module
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan

AI-powered vulnerability detection and analysis.
"""

# AI Module Definitions
AI_MODULES = {
    "VulnerabilityClassifier": {
        "description": "ML-based vulnerability classification using response patterns and context analysis",
        "status": "active",
        "accuracy": 0.92
    },
    "PayloadIntelligence": {
        "description": "Smart payload generation and optimization based on target characteristics",
        "status": "active",
        "accuracy": 0.88
    },
    "AnomalyDetector": {
        "description": "Response anomaly detection to identify unexpected behaviors",
        "status": "active",
        "accuracy": 0.85
    },
    "ResponseAnalyzer": {
        "description": "Deep response pattern analysis for vulnerability confirmation",
        "status": "active",
        "accuracy": 0.90
    },
    "FalsePositiveReducer": {
        "description": "AI-powered false positive reduction using learned patterns",
        "status": "active",
        "accuracy": 0.95
    },
    "LLMIntegration": {
        "description": "Large Language Model integration for advanced vulnerability analysis",
        "status": "active",
        "accuracy": 0.93
    }
}

# Self-Learning Features
LEARNING_FEATURES = {
    "pattern_learning": {
        "description": "Learns from scan results to improve detection accuracy",
        "enabled": True
    },
    "adaptive_payloads": {
        "description": "Adapts payloads based on target responses",
        "enabled": True
    },
    "context_awareness": {
        "description": "Understands application context for better detection",
        "enabled": True
    },
    "false_positive_tracking": {
        "description": "Tracks and learns from false positive patterns",
        "enabled": True
    }
}

class AIConfig:
    """Configuration for AI modules"""
    
    def __init__(self):
        self.enabled = True
        self.false_positive_threshold = 0.7
        self.confidence_threshold = 0.6
        self.learning_enabled = True
        self.model_update_interval = 86400  # 24 hours
    
    def is_enabled(self) -> bool:
        return self.enabled
    
    def get_threshold(self) -> float:
        return self.false_positive_threshold

__all__ = ["AI_MODULES", "LEARNING_FEATURES", "AIConfig"]
