"""Formatters for displaying policy audit results."""
from rich.table import Table
from typing import Dict, List, Optional
from .constants import Style
from falcon_policy_scoring.utils.constants import PolicyStatus
from .helpers import calculate_score_percentage, get_platform_name
from falcon_policy_scoring.utils.policy_helpers import calculate_policy_stats
from falcon_policy_scoring.utils.cache_helpers import (
    calculate_cache_age, get_policy_ttl, is_cache_expired, format_cache_display_with_ttl
)
from falcon_policy_scoring.utils.models import CacheInfo


def format_status_cell(status: str) -> str:
    """Format status with Rich markup.

    Args:
        status: Status string

    Returns:
        Formatted string with Rich color markup
    """
    if status == PolicyStatus.PASSED.value:
        return f"[{Style.GREEN}]✓ PASSED[/{Style.GREEN}]"
    elif status == PolicyStatus.FAILED.value:
        return f"[{Style.RED}]✗ FAILED[/{Style.RED}]"
    elif status == PolicyStatus.NOT_GRADED.value:
        return f"[{Style.YELLOW}]NOT GRADED[/{Style.YELLOW}]"
    else:  # NO POLICY ASSIGNED
        return f"[{Style.DIM}]NO POLICY[/{Style.DIM}]"


def calculate_cache_info(graded_record: Dict, config: Dict, policy_type: str) -> CacheInfo:
    """Calculate cache information for a graded policy record.

    Args:
        graded_record: Graded policies record
        config: Configuration dictionary
        policy_type: Type of policy

    Returns:
        CacheInfo object with age and TTL information
    """
    cache_age_seconds = 0
    cache_age_display = "Unknown"

    if 'epoch' in graded_record:
        cache_age_seconds, cache_age_display = calculate_cache_age(graded_record['epoch'])

    # Get TTL for this policy type
    ttl_seconds = get_policy_ttl(config, policy_type)
    cache_age_display = format_cache_display_with_ttl(cache_age_display, ttl_seconds)

    expired = is_cache_expired(cache_age_seconds, ttl_seconds)

    return CacheInfo(
        age_seconds=cache_age_seconds,
        age_display=cache_age_display,
        ttl_seconds=ttl_seconds,
        expired=expired
    )


def format_policy_table_row(policy: Dict) -> tuple:
    """Format a single policy as a table row.

    Args:
        policy: Policy dictionary

    Returns:
        Tuple of (status_icon, policy_name, platform, checks_display, score_display)
    """
    platform_name = get_platform_name(policy)
    checks_count = policy.get('checks_count', 0)
    failures_count = policy.get('failures_count', 0)

    # Determine status
    if policy.get('passed', False):
        status_icon = "✓"
        status_color = Style.GREEN
    else:
        status_icon = "✗"
        status_color = Style.RED

    # Calculate score
    if checks_count > 0:
        score_pct = calculate_score_percentage(checks_count, failures_count)
        score_display = f"{score_pct:.1f}%"

        if score_pct == 100:
            score_style = Style.GREEN
        elif score_pct >= 80:
            score_style = Style.YELLOW
        else:
            score_style = Style.RED
    else:
        score_display = "N/A"
        score_style = Style.DIM

    # Format checks display
    checks_display = f"{failures_count}/{checks_count}"
    if failures_count == 0:
        checks_style = Style.GREEN
    else:
        checks_style = Style.RED

    return (
        f"[{status_color}]{status_icon}[/{status_color}]",
        policy.get('policy_name', 'Unknown'),
        platform_name,
        f"[{checks_style}]{checks_display}[/{checks_style}] failed",
        f"[{score_style}]{score_display}[/{score_style}]"
    )


def print_policy_table(graded_record: Dict, policy_type: str, config: Dict, policies: List[Dict], ctx):
    """Print a Rich table of graded policies.

    Args:
        graded_record: Graded policies record from database
        policy_type: Type of policy
        config: Configuration dict
        policies: Filtered and sorted list of policies
        ctx: CLI context
    """
    if not policies:
        ctx.console.print(f"[{Style.YELLOW}]No policies match the specified filters[/{Style.YELLOW}]\n")
        return

    # Create table
    table = Table(title=f"{policy_type.replace('_', ' ').title()} Policies", show_lines=True)

    table.add_column("Status", justify="center", style="bold", width=8)
    table.add_column("Policy Name", style=Style.CYAN)
    table.add_column("Platform", justify="center", width=12)
    table.add_column("Checks", justify="center", width=12)
    table.add_column("Score", justify="center", width=8)

    # Add rows
    for policy in policies:
        table.add_row(*format_policy_table_row(policy))

    # Print table
    ctx.console.print(table)

    # Calculate stats
    stats = calculate_policy_stats(policies)

    # Calculate cache info
    cache_info = calculate_cache_info(graded_record, config, policy_type)

    # Print summary
    ctx.console.print(f"\n[{Style.BOLD}]Summary:[/{Style.BOLD}]")
    ctx.console.print(f"  ✅ Passed: [{Style.GREEN}]{stats['passed_count']}[/{Style.GREEN}]")
    ctx.console.print(f"  ❌ Failed: [{Style.RED}]{stats['failed_count']}[/{Style.RED}]")
    if stats['total_checks'] > 0:
        overall_score = calculate_score_percentage(stats['total_checks'], stats['total_failures'])
        ctx.console.print(f"  📊 Overall Score: {overall_score:.1f}%")
    ctx.console.print(f"  🕒 Cache Age: [{Style.DIM}]{cache_info.age_display}[/{Style.DIM}]")

    # Print cache warning if expired
    if cache_info.expired:
        print_cache_warning(cache_info, ctx)

    ctx.console.print()


def print_cache_warning(cache_info: CacheInfo, ctx):
    """Print cache expiration warning.

    Args:
        cache_info: Cache information
        ctx: CLI context
    """
    ctx.console.print(f"  [{Style.YELLOW}]⚠ Cache exceeded TTL. Consider using --fetch to refresh[/{Style.YELLOW}]")


def format_failure_details(setting_results, ctx):
    """Format and print failure details.

    Args:
        setting_results: Setting results (list or dict)
        ctx: CLI context
    """
    if isinstance(setting_results, list):
        # List format (sensor_update, prevention, etc.)
        for setting_result in setting_results:
            if not setting_result.get('passed', True):
                ctx.console.print(f"  [{Style.YELLOW}]• {setting_result['setting_name']}[/{Style.YELLOW}] ({setting_result['setting_id']})")
                for failure in setting_result.get('failures', []):
                    if failure.get('field') == 'ring_points':
                        ctx.console.print(f"    [{Style.RED}]✗[/{Style.RED}] {failure['field']}: {failure['actual']} > {failure['minimum']} (maximum)")
                    else:
                        ctx.console.print(f"    [{Style.RED}]✗[/{Style.RED}] {failure['field']}: {failure['actual']} < {failure['minimum']} (minimum)")
    elif isinstance(setting_results, dict):
        # Dict format (firewall, device_control, etc.)
        if 'failures' in setting_results:
            for failure in setting_results['failures']:
                field_name = failure.get('field', '').replace('class.', '')
                ctx.console.print(f"  [{Style.YELLOW}]• {field_name}[/{Style.YELLOW}]")
                expected = failure.get('minimum', failure.get('expected', 'expected'))
                ctx.console.print(f"    [{Style.RED}]✗[/{Style.RED}] {failure['actual']} != {expected}")


def print_policy_details(graded_record: Dict, policy_type: str, ctx):
    """Print detailed failure information for policies.

    Args:
        graded_record: Graded policies record from database
        policy_type: Type of policy
        ctx: CLI context
    """
    if not graded_record or 'graded_policies' not in graded_record:
        return

    failed_policies = [p for p in graded_record['graded_policies'] if not p.get('passed', True)]

    if not failed_policies:
        ctx.console.print(f"[{Style.GREEN}]All {policy_type.replace('_', ' ').title()} policies passed! ✓[/{Style.GREEN}]\n")
        return

    ctx.console.print(f"\n[{Style.BOLD}] [{Style.RED}]Failed {policy_type.replace('_', ' ').title()} Policies - Detailed Results:[/{Style.RED}][/{Style.BOLD}]\n")

    for policy_result in failed_policies:
        platform_name = get_platform_name(policy_result)

        ctx.console.print(f"[{Style.BOLD}]Policy:[/{Style.BOLD}] {policy_result.get('policy_name', 'Unknown')} ({platform_name})")
        ctx.console.print(f"[{Style.BOLD}]Status:[/{Style.BOLD}] [{Style.RED}]FAILED[/{Style.RED}]")
        ctx.console.print(f"[{Style.BOLD}]Failed Checks:[/{Style.BOLD}] {policy_result.get('failures_count', 0)}/{policy_result.get('checks_count', 0)}\n")

        ctx.console.print(f"[{Style.BOLD}]Failures:[/{Style.BOLD}]")

        format_failure_details(policy_result.get('setting_results', []), ctx)

        ctx.console.print()


def build_host_table(host_rows: List[Dict], ctx, config: Dict = None, policy_types: List[str] = None) -> Table:
    """Build a Rich table for host policy status.

    Args:
        host_rows: List of host data dictionaries
        ctx: CLI context
        config: Configuration dictionary (optional)
        policy_types: List of policy types to display (optional, defaults to all)

    Returns:
        Rich Table object
    """
    # Default to all policy types if not specified
    if policy_types is None:
        policy_types = ['prevention', 'sensor_update', 'content_update', 'firewall', 'device_control', 'it_automation']

    table = Table(title="Host Policy Status", show_lines=True)
    table.add_column("Hostname", style=Style.CYAN, width=30)
    table.add_column("Platform", justify="center", width=12)

    # Define policy column mappings
    policy_columns = [
        ('prevention', 'Prevention', 'prevention_status'),
        ('sensor_update', 'Sensor Update', 'sensor_update_status'),
        ('content_update', 'Content Update', 'content_update_status'),
        ('firewall', 'Firewall', 'firewall_status'),
        ('device_control', 'Device Control', 'device_control_status'),
        ('it_automation', 'IT Automation', 'it_automation_status')
    ]

    # Add only the requested policy columns
    active_columns = []
    for policy_type, column_name, status_key in policy_columns:
        if policy_type in policy_types:
            table.add_column(column_name, justify="center", width=15)
            active_columns.append(status_key)

    # Add Zero Trust column if enabled
    include_zta = config.get('host_fetching', {}).get('include_zta', True) if config else True
    if include_zta:
        table.add_column("Zero Trust", justify="center", width=18)

    for row in host_rows:
        row_data = [
            row['hostname'],
            row['platform']
        ]

        # Add only the active policy columns
        for status_key in active_columns:
            row_data.append(format_status_cell(row[status_key]))

        if include_zta:
            row_data.append(format_zta_cell(row.get('zta_assessment')))

        table.add_row(*row_data)

    return table


def format_zta_cell(zta_assessment: Optional[Dict]) -> str:
    """Format Zero Trust Assessment cell with aligned scores.

    Args:
        zta_assessment: Zero Trust Assessment dictionary containing sensor_config, os, and overall scores

    Returns:
        Formatted string with Rich markup showing (sensor_config/os) overall or N/A
    """
    if not zta_assessment:
        return "[dim]N/A[/dim]"

    sensor_config = zta_assessment.get('sensor_config', 0)
    os_score = zta_assessment.get('os', 0)
    overall = zta_assessment.get('overall', 0)

    # Format each number with 3-character width, right-aligned
    sensor_str = f"{sensor_config:>3}" if isinstance(sensor_config, int) else "  -"
    os_str = f"{os_score:>3}" if isinstance(os_score, int) else "  -"
    overall_str = f"{overall:>3}" if isinstance(overall, int) else "  -"

    # Format: dim (XXX/XXX) then bold XXX
    return f"[dim]({sensor_str}/{os_str})[/dim] [bold]{overall_str}[/bold]"


def print_host_stats(stats: Dict, cache_info: CacheInfo, ctx):
    """Print host summary statistics.

    Args:
        stats: Statistics dictionary
        cache_info: Cache information
        ctx: CLI context
    """
    ctx.console.print(f"\n[{Style.BOLD}]Host Summary:[/{Style.BOLD}]")
    ctx.console.print(f"  Total Hosts: {stats['total']}")
    ctx.console.print(f"  ✅ All Policies Passed: [{Style.GREEN}]{stats['all_passed']}[/{Style.GREEN}]")
    ctx.console.print(f"  ❌ Any Policy Failed: [{Style.RED}]{stats['any_failed']}[/{Style.RED}]")
    ctx.console.print(f"  🕒 Cache Age: [{Style.DIM}]{cache_info.age_display}[/{Style.DIM}]")

    if cache_info.expired:
        print_cache_warning(cache_info, ctx)

    ctx.console.print()
