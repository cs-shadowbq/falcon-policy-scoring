"""Helper functions for policy-audit CLI."""
from typing import Dict, Optional, Tuple, List
from falcon_policy_scoring.utils.constants import POLICY_TYPE_REGISTRY
from falcon_policy_scoring.utils import policy_helpers as policy_helpers_utils
from falcon_policy_scoring.utils.cache_helpers import calculate_cache_age as _calculate_cache_age
# Pure tag/group parsing lives in utils.filters (no UI deps); re-exported here
# for the CLI layer and backward compatibility.
from falcon_policy_scoring.utils.filters import (
    parse_host_group_ids,
    parse_tags,
)


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


def resolve_display_host_filters(args, ctx) -> Tuple[Optional[List[str]], Optional[List[str]]]:
    """Compute client-side host group ID and tag filters from CLI args.

    Used by the display path (e.g. the ``hosts`` command) where filtering is
    applied over cached rows. ``--host-group-ids`` and ``--tags`` need no API.
    ``--host-groups`` names require a name-to-ID lookup; if an API client is
    available (``ctx.falcon``) the names are resolved, otherwise a warning is
    emitted and the names are ignored (cached records store group IDs, not names).

    Args:
        args: Parsed CLI arguments
        ctx: CLI context (provides ``falcon`` client, if any, and console)

    Returns:
        Tuple of (group_ids, tags), each a list or None
    """
    from falcon_policy_scoring.falconapi.host_group import HostGroup
    from falcon_policy_scoring.utils.constants import Style

    group_ids = parse_host_group_ids(getattr(args, 'host_group_ids', None)) or []
    tags = parse_tags(getattr(args, 'tags', None))

    host_group_names = parse_host_groups(getattr(args, 'host_groups', None))
    if host_group_names:
        falcon = getattr(ctx, 'falcon', None)
        if falcon is not None:
            try:
                name_to_id = HostGroup(falcon).resolve_group_names_to_ids(host_group_names)
                group_ids.extend(name_to_id.values())
            except ValueError as e:
                ctx.console.print(
                    f"[{Style.YELLOW}]⚠ Could not resolve host group names: {e}[/{Style.YELLOW}]"
                )
        else:
            ctx.console.print(
                f"[{Style.YELLOW}]⚠ --host-groups by name needs an API connection and is "
                f"unavailable for cached display. Use --host-group-ids here, or apply "
                f"--host-groups on the 'fetch' command.[/{Style.YELLOW}]"
            )

    # De-duplicate while preserving order
    group_ids = list(dict.fromkeys(group_ids)) if group_ids else None

    return group_ids, tags
