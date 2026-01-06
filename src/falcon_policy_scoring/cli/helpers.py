"""Helper functions for policy-audit CLI."""
from typing import Dict, Optional, Tuple, List
from falcon_policy_scoring.utils.constants import POLICY_TYPE_REGISTRY
from falcon_policy_scoring.utils import policy_helpers as policy_helpers_utils
from falcon_policy_scoring.utils.cache_helpers import calculate_cache_age as _calculate_cache_age


def format_cache_age(epoch: int) -> Tuple[int, str]:
    """Calculate and format cache age from epoch timestamp.

    Wrapper for utils function to maintain backward compatibility.

    Args:
        epoch: Unix timestamp

    Returns:
        Tuple of (age_in_seconds, formatted_display_string)
    """
    return _calculate_cache_age(epoch)


def calculate_score_percentage(checks: int, failures: int) -> float:
    """Calculate policy score percentage.

    Wrapper for utils function to maintain backward compatibility.
    """
    return policy_helpers_utils.calculate_score_percentage(checks, failures)


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


def fetch_all_graded_policies(adapter, cid: str) -> Dict[str, Optional[Dict]]:
    """Fetch all graded policy records from database.

    Wrapper for utils function to maintain backward compatibility.
    """
    return policy_helpers_utils.fetch_all_graded_policies(adapter, cid, POLICY_TYPE_REGISTRY)


def get_policy_status(policy_id: Optional[str], graded_record: Optional[Dict]) -> str:
    """Get the grading status for a specific policy ID.

    Wrapper for utils function to maintain backward compatibility.
    """
    return policy_helpers_utils.get_policy_status(policy_id, graded_record)


def determine_policy_types_to_display(policy_type_arg: str) -> List[str]:
    """Determine which policy types to display based on CLI argument.

    Wrapper for utils function to maintain backward compatibility.
    """
    return policy_helpers_utils.determine_policy_types_to_display(policy_type_arg)


def parse_host_groups(host_groups_arg: Optional[str]) -> Optional[List[str]]:
    """Parse comma-separated host group names from CLI argument.

    Args:
        host_groups_arg: Comma-separated string of host group names, or None

    Returns:
        List of host group names (stripped), or None if not provided
    """
    if not host_groups_arg:
        return None

    # Split by comma and strip whitespace
    groups = [group.strip() for group in host_groups_arg.split(',') if group.strip()]

    return groups if groups else None
