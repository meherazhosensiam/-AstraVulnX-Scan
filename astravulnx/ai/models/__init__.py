"""
AstraVulnX v3.0.0 AI Models
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan
"""

# Model configurations
MODEL_CONFIGS = {
    "classifier": {
        "type": "neural_network",
        "input_size": 128,
        "hidden_layers": [64, 32],
        "output_classes": ["safe", "vulnerable", "suspicious"]
    },
    "anomaly_detector": {
        "type": "autoencoder",
        "encoding_dim": 32,
        "threshold": 0.1
    }
}

__all__ = ["MODEL_CONFIGS"]
