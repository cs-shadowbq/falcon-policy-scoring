"""Policy helper utilities.

Pure business logic for policy operations. No UI dependencies.
Shared between CLI and daemon modules.
"""
from typing import Dict, Optional, List


def calculate_score_percentage(checks: int, failures: int) -> float:
    """Calculate policy score percentage.

    Args:
        checks: Total number of checks
        failures: Number of failed checks

    Returns:
        Score as percentage (0-100)
    """
    return ((checks - failures) / checks * 100) if checks > 0 else 0


def calculate_policy_stats(policies: List[Dict]) -> Dict:
    """Calculate statistics for a list of policies.

    Args:
        policies: List of policy dictionaries

    Returns:
        Dictionary with stats (passed_count, failed_count, total_checks, total_failures, displayed_count)
    """
    passed_count = 0
    failed_count = 0
    total_checks = 0
    total_failures = 0

    for policy in policies:
        if policy.get('passed', False):
            passed_count += 1
        else:
            failed_count += 1

        total_checks += policy.get('checks_count', 0)
        total_failures += policy.get('failures_count', 0)

    return {
        'passed_count': passed_count,
        'failed_count': failed_count,
        'total_checks': total_checks,
        'total_failures': total_failures,
        'displayed_count': len(policies)
    }


def fetch_all_graded_policies(adapter, cid: str, policy_type_registry: Dict) -> Dict[str, Optional[Dict]]:
    """Fetch all graded policy records from database.

    Args:
        adapter: Database adapter instance
        cid: Customer ID
        policy_type_registry: Registry mapping policy types to database keys

    Returns:
        Dictionary mapping policy type to graded record
    """
    result = {}
    for policy_type, info in policy_type_registry.items():
        result[policy_type] = adapter.get_graded_policies(info['db_key'], cid)
    return result


def get_policy_status(policy_id: Optional[str], graded_record: Optional[Dict]) -> str:
    """Get the grading status for a specific policy ID.

    Args:
        policy_id: Policy ID to check
        graded_record: Graded policies record

    Returns:
        Status string: PASSED, FAILED, NOT GRADED, or NO POLICY ASSIGNED
    """
    if not policy_id:
        return "NO POLICY ASSIGNED"

    if not graded_record or 'graded_policies' not in graded_record:
        return "NOT GRADED"

    for policy_result in graded_record['graded_policies']:
        if policy_result['policy_id'] == policy_id:
            return "PASSED" if policy_result['passed'] else "FAILED"

    return "NOT GRADED"


def determine_policy_types_to_display(policy_type_arg: str) -> List[str]:
    """Determine which policy types to display based on CLI argument.

    Supports 'all' or comma-separated list of policy types.

    Args:
        policy_type_arg: CLI argument for policy type (single or comma-separated)

    Returns:
        List of policy type keys to display
    """
    if policy_type_arg == 'all':
        return ['prevention', 'sensor_update', 'content_update', 'firewall', 'device_control', 'it_automation']

    # Handle comma-separated list
    policy_types = [t.strip() for t in policy_type_arg.split(',')]

    # Map from CLI format (with hyphens) to internal format (with underscores)
    type_mapping = {
        'prevention': 'prevention',
        'sensor-update': 'sensor_update',
        'content-update': 'content_update',
        'firewall': 'firewall',
        'device-control': 'device_control',
        'it-automation': 'it_automation'
    }

    result = []
    for policy_type in policy_types:
        if policy_type in type_mapping:
            result.append(type_mapping[policy_type])

    return result


def get_platform_name(policy_result: Dict) -> str:
    """Extract platform name handling both 'platform_name' and 'target' fields.

    Args:
        policy_result: Policy result dictionary

    Returns:
        Platform name string
    """
    return policy_result.get('platform_name') or policy_result.get('target', 'Unknown')


def matches_status_filter(passed: bool, status_filter: Optional[str]) -> bool:
    """Check if policy matches status filter.

    Args:
        passed: Whether the policy passed grading
        status_filter: Filter string ('passed', 'failed', or None)

    Returns:
        True if matches filter, False otherwise
    """
    if not status_filter:
        return True
    return (status_filter == 'passed' and passed) or (status_filter == 'failed' and not passed)
