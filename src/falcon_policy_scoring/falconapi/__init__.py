"""FalconAPI module for CrowdStrike Falcon API interactions."""

from falcon_policy_scoring.falconapi.cid import get_cid, get_cid_hash
from falcon_policy_scoring.falconapi.hosts import Hosts
from falcon_policy_scoring.falconapi.host_group import HostGroup
from falcon_policy_scoring.falconapi.policies import (
    get_policies,
    get_policy_table_name,
    get_all_policy_types,
    fetch_and_store_policy,
    fetch_and_store_all_policies,
    check_scope_permission_error
)
from falcon_policy_scoring.falconapi.zero_trust import (
    fetch_zero_trust_assessments,
    query_assessments_by_score,
    get_audit_report
)
from falcon_policy_scoring.falconapi.firewall import fetch_policy_containers
from falcon_policy_scoring.falconapi.device_control import fetch_policy_settings
from falcon_policy_scoring.falconapi.it_automation import (
    query_combined_it_automation_policies,
    fetch_it_automation_policies
)

__all__ = [
    # CID functions
    'get_cid',
    'get_cid_hash',
    # Host classes
    'Hosts',
    'HostGroup',
    # Policy functions
    'get_policies',
    'get_policy_table_name',
    'get_all_policy_types',
    'fetch_and_store_policy',
    'fetch_and_store_all_policies',
    'check_scope_permission_error',
    # Zero Trust
    'fetch_zero_trust_assessments',
    'query_assessments_by_score',
    'get_audit_report',
    # Firewall
    'fetch_policy_containers',
    # Device Control
    'fetch_policy_settings',
    # IT Automation
    'query_combined_it_automation_policies',
    'fetch_it_automation_policies'
]
