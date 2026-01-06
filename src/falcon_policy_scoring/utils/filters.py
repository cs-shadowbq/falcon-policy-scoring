"""Filtering logic for policies and hosts.

Pure business logic for filtering data. No UI dependencies.
Shared between CLI and daemon modules.
"""
from typing import List, Dict, Optional


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


def get_platform_name(policy_result: Dict) -> str:
    """Extract platform name handling both 'platform_name' and 'target' fields.

    Args:
        policy_result: Policy result dictionary

    Returns:
        Platform name string
    """
    return policy_result.get('platform_name') or policy_result.get('target', 'Unknown')


def filter_policies(
    policies: List[Dict],
    platform_filter: Optional[str] = None,
    status_filter: Optional[str] = None
) -> List[Dict]:
    """Filter policies by platform and status.

    Args:
        policies: List of policy dictionaries
        platform_filter: Optional platform filter (Windows, Mac, Linux)
        status_filter: Optional status filter ('passed' or 'failed')

    Returns:
        Filtered list of policies
    """
    filtered = []

    for policy in policies:
        # Get platform name
        platform_name = get_platform_name(policy)

        # Apply platform filter
        if platform_filter and platform_name.lower() != platform_filter.lower():
            continue

        # Apply status filter
        if status_filter and not matches_status_filter(policy.get('passed', False), status_filter):
            continue

        filtered.append(policy)

    return filtered


def filter_hosts(
    hosts: List[Dict],
    platform_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    hostname_filter: Optional[str] = None
) -> List[Dict]:
    """Filter hosts by platform, status, and hostname.

    Args:
        hosts: List of host dictionaries
        platform_filter: Optional platform filter (Windows, Mac, Linux)
        status_filter: Optional status filter ('all-passed' or 'any-failed')
        hostname_filter: Optional hostname filter (exact match, case-insensitive)

    Returns:
        Filtered list of hosts
    """
    filtered = []

    for host in hosts:
        # Apply platform filter
        if platform_filter and host.get('platform', '').lower() != platform_filter.lower():
            continue

        # Apply hostname filter
        if hostname_filter and host.get('hostname', '').lower() != hostname_filter.lower():
            continue

        # Apply status filter
        if status_filter:
            if status_filter == 'all-passed' and not host.get('all_passed', False):
                continue
            if status_filter == 'any-failed' and not host.get('any_failed', False):
                continue

        filtered.append(host)

    return filtered
