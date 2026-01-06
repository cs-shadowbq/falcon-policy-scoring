"""
Falcon Policy Scoring - CrowdStrike Falcon policy analysis and grading tool.

This package provides functionality for fetching, analyzing, and grading
CrowdStrike Falcon policies against minimum security standards.
"""

import importlib.metadata

try:
    __version__ = importlib.metadata.version("falcon-policy-scoring")
except importlib.metadata.PackageNotFoundError:
    # Fallback for development environments where package isn't installed
    __version__ = "0.0.0-dev"

# Expose commonly used modules
from falcon_policy_scoring import grading
from falcon_policy_scoring import falconapi
from falcon_policy_scoring import utils

__all__ = ['grading', 'falconapi', 'utils', '__version__']
