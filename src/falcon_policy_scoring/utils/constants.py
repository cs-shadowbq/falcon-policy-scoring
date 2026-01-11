"""Shared constants for policy-audit application.

Constants used across CLI, daemon, and utils modules.
"""
from enum import Enum
from typing import Dict


# Default values
DEFAULT_POLICY_TTL_SECONDS = 600
DEFAULT_HOSTS_TTL_SECONDS = 300
DEFAULT_BATCH_SIZE = 100
DEFAULT_PROGRESS_THRESHOLD = 500

# API constants
API_COMMAND_GET_DEVICE_DETAILS = 'GetDeviceDetailsV2'


# Rich styles (used by CLI formatters and output strategies)
class Style:  # pylint: disable=too-few-public-methods
    """Rich markup style constants."""
    GREEN = "green"
    RED = "red"
    YELLOW = "yellow"
    DIM = "dim"
    CYAN = "cyan"
    BOLD = "bold"


# Database record types
class RecordType(Enum):
    """Database record type enumeration."""
    HOST_DETAILS = 4


# Policy status
class PolicyStatus(Enum):
    """Policy grading status enumeration."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_GRADED = "NOT GRADED"
    NO_POLICY_ASSIGNED = "NO POLICY ASSIGNED"


# Policy type registry
POLICY_TYPE_REGISTRY = {
    'prevention': {
        'db_key': 'prevention_policies',
        'api_key': 'prevention',
        'display_name': 'Prevention',
        'cli_name': 'prevention'
    },
    'sensor_update': {
        'db_key': 'sensor_update_policies',
        'api_key': 'sensor_update',
        'display_name': 'Sensor Update',
        'cli_name': 'sensor-update'
    },
    'content_update': {
        'db_key': 'content_update_policies',
        'api_key': 'content-update',
        'display_name': 'Content Update',
        'cli_name': 'content-update'
    },
    'firewall': {
        'db_key': 'firewall_policies',
        'api_key': 'firewall',
        'display_name': 'Firewall',
        'cli_name': 'firewall'
    },
    'device_control': {
        'db_key': 'device_control_policies',
        'api_key': 'device_control',
        'display_name': 'Device Control',
        'cli_name': 'device-control'
    },
    'it_automation': {
        'db_key': 'it_automation_policies',
        'api_key': 'it-automation',
        'display_name': 'IT Automation',
        'cli_name': 'it-automation'
    }
}


def get_policy_type_info(policy_type: str) -> Dict:
    """Get policy type information from registry.

    Args:
        policy_type: The policy type key

    Returns:
        Dictionary containing policy type metadata
    """
    return POLICY_TYPE_REGISTRY.get(policy_type, {})
