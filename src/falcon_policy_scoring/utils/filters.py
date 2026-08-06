"""Filtering logic for policies and hosts.

Pure business logic for filtering data. No UI dependencies.
Shared between CLI and daemon modules.
"""
from typing import List, Dict, Optional

from .constants import DEFAULT_TAG_PREFIX, VALID_TAG_PREFIXES


def parse_host_group_ids(host_group_ids_arg: Optional[str]) -> Optional[List[str]]:
    """Parse comma-separated host group IDs from a CLI argument.

    These values are host group IDs used directly in the FQL ``groups:`` clause
    (server-side) or matched against cached ``groups`` (client-side); no name
    lookup is performed.

    Args:
        host_group_ids_arg: Comma-separated string of host group IDs, or None

    Returns:
        List of host group IDs (stripped), or None if not provided
    """
    if not host_group_ids_arg:
        return None

    ids = [gid.strip() for gid in host_group_ids_arg.split(',') if gid.strip()]

    return ids if ids else None


def normalize_tag(tag: str) -> str:
    """Normalize a single Falcon tag value, applying the default prefix.

    A tag already carrying a valid prefix (``FalconGroupingTags/`` or
    ``SensorGroupingTags/``, matched case-insensitively) is preserved with the
    canonical prefix casing. A bare tag has the default Falcon grouping tag
    prefix applied.

    Args:
        tag: Raw tag value

    Returns:
        Normalized tag string with a canonical prefix
    """
    tag = tag.strip()
    for prefix in VALID_TAG_PREFIXES:
        if tag.lower().startswith(prefix.lower()):
            # Preserve the suffix as supplied, canonicalize the prefix casing.
            return prefix + tag[len(prefix):]

    return f"{DEFAULT_TAG_PREFIX}{tag}"


def parse_tags(tags_arg: Optional[str]) -> Optional[List[str]]:
    """Parse comma-separated Falcon tags from a CLI argument.

    Each value is normalized via :func:`normalize_tag`: bare values default to
    the ``FalconGroupingTags/`` prefix, while values already prefixed with a
    valid tag type are preserved.

    Args:
        tags_arg: Comma-separated string of tags, or None

    Returns:
        List of normalized tags, or None if not provided
    """
    if not tags_arg:
        return None

    tags = [normalize_tag(tag) for tag in tags_arg.split(',') if tag.strip()]

    return tags if tags else None


def matches_status_filter(policy: Dict, status_filter: Optional[str]) -> bool:
    """Check if policy matches status filter.

    Args:
        policy: Policy dictionary with grading_status and passed fields
        status_filter: Filter string ('passed', 'failed', 'ungradable', or None)

    Returns:
        True if matches filter, False otherwise
    """
    if not status_filter:
        return True

    grading_status = policy.get('grading_status', 'graded')

    # Handle ungradable filter
    if status_filter == 'ungradable':
        return grading_status == 'ungradable'

    # For passed/failed filters, only consider graded policies
    if grading_status != 'graded':
        return False

    passed = policy.get('passed', False)
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
        if status_filter and not matches_status_filter(policy, status_filter):
            continue

        filtered.append(policy)

    return filtered


def filter_hosts(
    hosts: List[Dict],
    platform_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    hostname_filter: Optional[str] = None,
    group_ids: Optional[List[str]] = None,
    tags: Optional[List[str]] = None
) -> List[Dict]:
    """Filter hosts by platform, status, hostname, host group, and tags.

    Host group and tag filters are client-side (applied over cached host rows).
    Values within a category combine with OR (a host in ANY listed group, or with
    ANY listed tag), and the group and tag categories combine with AND — matching
    the server-side FQL semantics used at fetch time.

    Args:
        hosts: List of host dictionaries
        platform_filter: Optional platform filter (Windows, Mac, Linux)
        status_filter: Optional status filter ('all-passed' or 'any-failed')
        hostname_filter: Optional hostname filter (exact match, case-insensitive)
        group_ids: Optional list of host group IDs; keep hosts in any listed group
        tags: Optional list of normalized Falcon tags; keep hosts with any listed tag

    Returns:
        Filtered list of hosts
    """
    filtered = []

    group_id_set = set(group_ids) if group_ids else None
    # Match tags case-insensitively (the prefix is canonical; suffixes may vary)
    tag_set = {t.lower() for t in tags} if tags else None

    for host in hosts:
        # Apply platform filter
        if platform_filter and host.get('platform', '').lower() != platform_filter.lower():
            continue

        # Apply hostname filter
        if hostname_filter and host.get('hostname', '').lower() != hostname_filter.lower():
            continue

        # Apply host group filter (OR across group IDs)
        if group_id_set is not None:
            host_groups = set(host.get('groups', []) or [])
            if host_groups.isdisjoint(group_id_set):
                continue

        # Apply tag filter (OR across tags)
        if tag_set is not None:
            host_tags = {t.lower() for t in (host.get('tags', []) or [])}
            if host_tags.isdisjoint(tag_set):
                continue

        # Apply status filter
        if status_filter:
            if status_filter == 'all-passed' and not host.get('all_passed', False):
                continue
            if status_filter == 'any-failed' and not host.get('any_failed', False):
                continue

        filtered.append(host)

    return filtered
