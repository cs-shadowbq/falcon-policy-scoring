"""Sorting logic for policies and hosts."""
from typing import List, Dict
from .helpers import get_platform_name


def sort_policies(policies: List[Dict], sort_by: str = 'platform') -> List[Dict]:
    """Sort policies by specified criteria.

    Args:
        policies: List of policy dictionaries
        sort_by: Sort order - 'platform', 'name', or 'score'

    Returns:
        Sorted list of policies
    """
    if sort_by == 'platform':
        # Sort by platform, then policy name
        def key_func(p):
            return (get_platform_name(p).lower(), p.get('policy_name', '').lower())
    elif sort_by == 'name':
        # Sort by policy name, then platform
        def key_func(p):
            return (p.get('policy_name', '').lower(), get_platform_name(p).lower())
    elif sort_by == 'score':
        # Sort by score (failed first, then by failure count descending), then platform, then name
        def key_func(p):
            checks = p.get('checks_count', 0)
            failures = p.get('failures_count', 0)
            # Calculate score (lower is worse)
            score = ((checks - failures) / checks * 100) if checks > 0 else 100
            return (score, -failures, get_platform_name(p).lower(), p.get('policy_name', '').lower())
    else:
        # Default to platform sort
        def key_func(p):
            return (get_platform_name(p).lower(), p.get('policy_name', '').lower())

    return sorted(policies, key=key_func)


def sort_hosts(hosts: List[Dict], sort_by: str = 'platform') -> List[Dict]:
    """Sort hosts by specified criteria.

    Args:
        hosts: List of host dictionaries
        sort_by: Sort order - 'platform', 'hostname', or 'status'

    Returns:
        Sorted list of hosts
    """
    if sort_by == 'platform':
        # Sort by platform, then hostname
        def key_func(h):
            return (h.get('platform', '').lower(), h.get('hostname', '').lower())
    elif sort_by == 'hostname':
        # Sort by hostname only
        def key_func(h):
            return h.get('hostname', '').lower()
    elif sort_by == 'status':
        # Sort by status (failed first), then platform, then hostname
        def key_func(h):
            return (not h.get('any_failed', False), h.get('platform', '').lower(), h.get('hostname', '').lower())
    else:
        # Default to platform sort
        def key_func(h):
            return (h.get('platform', '').lower(), h.get('hostname', '').lower())

    return sorted(hosts, key=key_func)
