"""Constants and configuration for policy-audit CLI.

NOTE: Shared constants (APP_VERSION, POLICY_TYPE_REGISTRY, RecordType, PolicyStatus, etc.)
have been moved to falcon_policy_scoring.utils.constants for reuse across CLI and daemon.
This module now re-exports them for backward compatibility and contains CLI-specific constants.
"""
# Import version from package __init__.py
from falcon_policy_scoring import __version__ as APP_VERSION

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
