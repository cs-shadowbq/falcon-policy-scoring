"""Constants and configuration for policy-audit CLI.

NOTE: Shared constants (APP_VERSION, POLICY_TYPE_REGISTRY, RecordType, PolicyStatus, etc.)
have been moved to falcon_policy_scoring.utils.constants for reuse across CLI and daemon.
This module now re-exports them for backward compatibility and contains CLI-specific constants.
"""
from enum import Enum
from typing import Dict

# Import version from package __init__.py
from falcon_policy_scoring import __version__ as APP_VERSION

# Import shared constants from utils
from falcon_policy_scoring.utils.constants import (
    DEFAULT_BATCH_SIZE,
    API_COMMAND_GET_DEVICE_DETAILS,
    RecordType,
    PolicyStatus,
    POLICY_TYPE_REGISTRY,
    get_policy_type_info
)

# CLI-specific default values
DEFAULT_POLICY_TTL_SECONDS = 600
DEFAULT_HOSTS_TTL_SECONDS = 300
DEFAULT_PROGRESS_THRESHOLD = 500

# Rich styles (CLI-specific)
class Style:
    """Rich markup style constants."""
    GREEN = "green"
    RED = "red"
    YELLOW = "yellow"
    DIM = "dim"
    CYAN = "cyan"
    BOLD = "bold"
