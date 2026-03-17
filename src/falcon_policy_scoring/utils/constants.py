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


# Policy type registry — single source of truth for all policy metadata.
# Fields:
#   db_key          : database table/record key
#   api_key         : internal API identifier
#   display_name    : human-readable name used in titles and verbose output
#   cli_name        : CLI argument form (hyphenated)
#   gradable        : False for fetch-only types (e.g. response/RTR)
#   narrow_header   : abbreviated column header for compact host tables
#   table_header    : column header for wide host tables
#   status_key      : key used in host row dicts for this policy's status
#   ttl_config_key  : key used in config file ttl.policies dict (backward-compat names)
#   api_command     : FalconPy SDK command name for fetching
#   api_limit       : page-size limit for API fetch
#   api_weblink     : FalconPy documentation URL
#   is_shim         : True when api_command is a custom shim, not a direct SDK method
POLICY_TYPE_REGISTRY = {
    'prevention': {
        'db_key': 'prevention_policies',
        'api_key': 'prevention',
        'display_name': 'Prevention',
        'cli_name': 'prevention',
        'gradable': True,
        'narrow_header': 'AV',
        'table_header': 'Prevention',
        'status_key': 'prevention_status',
        'ttl_config_key': 'prevention_policy',
        'api_command': 'queryCombinedPreventionPolicies',
        'api_limit': 5000,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/Prevention-Policies.html#querycombinedpreventionpolicies',
        'is_shim': False,
    },
    'sensor_update': {
        'db_key': 'sensor_update_policies',
        'api_key': 'sensor_update',
        'display_name': 'Sensor Update',
        'cli_name': 'sensor-update',
        'gradable': True,
        'narrow_header': 'SU',
        'table_header': 'Sensor Update',
        'status_key': 'sensor_update_status',
        'ttl_config_key': 'sensor_update_policy',
        'api_command': 'queryCombinedSensorUpdatePolicies',
        'api_limit': 5000,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/Sensor-Update-Policies.html#querycombinedsensorupdatepolicies',
        'is_shim': False,
    },
    'content_update': {
        'db_key': 'content_update_policies',
        'api_key': 'content-update',
        'display_name': 'Content Update',
        'cli_name': 'content-update',
        'gradable': True,
        'narrow_header': 'CU',
        'table_header': 'Content Update',
        'status_key': 'content_update_status',
        'ttl_config_key': 'content_policy',
        'api_command': 'queryCombinedContentUpdatePolicies',
        'api_limit': 5000,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/Content-Update-Policies.html#querycombinedcontentupdatepolicies',
        'is_shim': False,
    },
    'firewall': {
        'db_key': 'firewall_policies',
        'api_key': 'firewall',
        'display_name': 'Firewall',
        'cli_name': 'firewall',
        'gradable': True,
        'narrow_header': 'FW',
        'table_header': 'Firewall',
        'status_key': 'firewall_status',
        'ttl_config_key': 'firewall_policy',
        'api_command': 'queryCombinedFirewallPolicies',
        'api_limit': 5000,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/Firewall-Policies.html#querycombinedfirewallpolicies',
        'is_shim': False,
    },
    'device_control': {
        'db_key': 'device_control_policies',
        'api_key': 'device_control',
        'display_name': 'Device Control',
        'cli_name': 'device-control',
        'gradable': True,
        'narrow_header': 'DC',
        'table_header': 'Device Control',
        'status_key': 'device_control_status',
        'ttl_config_key': 'devicecontrol_policy',
        'api_command': 'queryCombinedDeviceControlPolicies',
        'api_limit': 5000,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/Device-Control-Policies.html#querycombineddevicecontrolpolicies',
        'is_shim': False,
    },
    'it_automation': {
        'db_key': 'it_automation_policies',
        'api_key': 'it-automation',
        'display_name': 'IT Automation',
        'cli_name': 'it-automation',
        'gradable': True,
        'narrow_header': 'IT',
        'table_header': 'IT Automation',
        'status_key': 'it_automation_status',
        'ttl_config_key': 'it_automation_policy',
        'api_command': 'query_combined_it_automation_policies',
        'api_limit': 500,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/IT-Automation.html#itautomationgetpolicies',
        'is_shim': True,
    },
    'ods_scheduled_scan': {
        'db_key': 'ods_scheduled_scan_policies',
        'api_key': 'ods-scheduled-scan',
        'display_name': 'ODS Scheduled Scan',
        'cli_name': 'ods-scheduled-scan',
        'gradable': True,
        'narrow_header': 'ODS',
        'table_header': 'ODS Scan',
        'status_key': 'ods_scheduled_scan_status',
        'ttl_config_key': 'ods_scheduled_scan_policy',
        'api_command': 'QueryScheduledScans',
        'api_limit': 500,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/ODS.html#queryscheduledscans',
        'is_shim': True,
    },
    'response': {
        'db_key': 'response_policies',
        'api_key': 'response',
        'display_name': 'Response (RTR)',
        'cli_name': 'response',
        'gradable': True,
        'narrow_header': 'RTR',
        'table_header': 'Response (RTR)',
        'status_key': 'response_status',
        'ttl_config_key': 'rtr_policy',
        'api_command': 'queryCombinedRTResponsePolicies',
        'api_limit': 5000,
        'api_weblink': 'https://www.falconpy.io/Service-Collections/Response-Policies.html#querycombinedrtresponsepolicies',
        'is_shim': False,
    },
}


def get_policy_type_info(policy_type: str) -> Dict:
    """Get policy type information from registry.

    Args:
        policy_type: The policy type key

    Returns:
        Dictionary containing policy type metadata
    """
    return POLICY_TYPE_REGISTRY.get(policy_type, {})
