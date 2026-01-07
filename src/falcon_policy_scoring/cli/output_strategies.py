"""Output strategies for different display formats."""
from abc import ABC, abstractmethod
from typing import Dict, Any
import json


class OutputStrategy(ABC):
    """Abstract base class for output strategies."""

    @abstractmethod
    def output(self, data: Dict[str, Any], context) -> None:
        """Output data in specific format.

        Args:
            data: Data dictionary to output
            context: CLI context
        """
        pass


class TextOutputStrategy(OutputStrategy):
    """Strategy for text/table output."""

    def output(self, data: Dict[str, Any], context) -> None:
        """Display data as Rich tables.

        Args:
            data: Data dictionary containing adapter, cid, config, args
            context: CLI context
        """
        # Import here to avoid circular dependencies
        from .filters import filter_policies, filter_hosts
        from .sorters import sort_policies, sort_hosts
        from .formatters import (
            print_policy_table, print_policy_details,
            build_host_table, print_host_stats
        )
        from .data_fetcher import collect_host_data, calculate_host_stats, find_host_by_name
        from .helpers import fetch_all_graded_policies, determine_policy_types_to_display, get_policy_status
        from .constants import Style
        from falcon_policy_scoring.utils.cache_helpers import (
            calculate_cache_age, get_hosts_ttl, is_cache_expired, format_cache_display_with_ttl
        )
        from falcon_policy_scoring.utils.models import CacheInfo

        adapter = data['adapter']
        cid = data['cid']
        config = data['config']
        args = data['args']

        # Get all graded policies
        policy_records = fetch_all_graded_policies(adapter, cid)

        # Handle host-specific views
        if args.show_hosts and args.hostname and getattr(args, 'details', False):
            # Show host summary table for specific host, then details
            host_data = collect_host_data(adapter, cid, policy_records, config)
            filtered_hosts = filter_hosts(host_data, args.platform, args.host_status, args.hostname)

            if filtered_hosts:
                sorted_hosts = sort_hosts(filtered_hosts, args.sort_hosts)
                # Determine which policy types to display in the table
                policy_types_to_display = determine_policy_types_to_display(args.policy_type)
                table = build_host_table(sorted_hosts, context, config, policy_types_to_display)
                context.console.print(table)

                # Calculate stats and cache info
                stats = calculate_host_stats(sorted_hosts)
                hosts_in_db = adapter.get_hosts(cid)

                if hosts_in_db and 'epoch' in hosts_in_db:
                    cache_age_seconds, cache_age_display = calculate_cache_age(hosts_in_db['epoch'])
                    hosts_ttl_seconds = get_hosts_ttl(config)
                    cache_age_display = format_cache_display_with_ttl(cache_age_display, hosts_ttl_seconds)
                    cache_info = CacheInfo(
                        age_seconds=cache_age_seconds,
                        age_display=cache_age_display,
                        ttl_seconds=hosts_ttl_seconds,
                        expired=is_cache_expired(cache_age_seconds, hosts_ttl_seconds)
                    )
                    print_host_stats(stats, cache_info, context)

            # Print host policy details
            host_info = find_host_by_name(adapter, cid, args.hostname)
            if host_info:
                device_data = host_info['device_data']
                device_policies = device_data.get('device_policies', {})

                context.console.print(f"\n[bold cyan]Policy Details for Host: {device_data.get('hostname', 'Unknown')}[/bold cyan]")
                context.console.print(f"[dim]Device ID: {host_info['device_id']}[/dim]")
                context.console.print(f"[dim]Platform: {device_data.get('platform_name', 'Unknown')}[/dim]\n")

                # Determine which policy types to display based on -t flag
                policy_types_to_display = determine_policy_types_to_display(args.policy_type)

                # Build policy ID to name lookup maps for each policy type
                policy_id_to_name = {}
                for policy_type in policy_types_to_display:
                    graded_record = policy_records.get(policy_type)
                    if graded_record and 'graded_policies' in graded_record:
                        for policy in graded_record['graded_policies']:
                            policy_id = policy.get('policy_id')
                            policy_name = policy.get('policy_name')
                            if policy_id and policy_name:
                                policy_id_to_name[policy_id] = policy_name

                # Helper to locate policy info with hyphen/underscore variants
                def _find_policy_info(policy_map, key):
                    # try exact key, underscore, hyphen variants
                    candidates = [key, key.replace('_', '-'), key.replace('-', '_')]
                    for k in candidates:
                        info = policy_map.get(k)
                        if info:
                            return info
                    return {}

                # Print each policy type - only those filtered by -t flag
                all_policy_mappings = [
                    ('prevention', 'Prevention', policy_records.get('prevention')),
                    ('sensor_update', 'Sensor Update', policy_records.get('sensor_update')),
                    ('content_update', 'Content Update', policy_records.get('content_update')),
                    ('firewall', 'Firewall', policy_records.get('firewall')),
                    ('device_control', 'Device Control', policy_records.get('device_control')),
                    ('it_automation', 'IT Automation', policy_records.get('it_automation'))
                ]

                # Filter to only show the requested policy types
                policy_mappings = [(key, name, record) for key, name, record in all_policy_mappings if key in policy_types_to_display]

                for policy_key, policy_display_name, graded_record in policy_mappings:
                    policy_info = _find_policy_info(device_policies, policy_key)
                    policy_id = policy_info.get('policy_id')
                    # Look up policy name from graded policies, fall back to device_policies, then 'Not Assigned'
                    policy_name = policy_id_to_name.get(policy_id) if policy_id else None
                    if not policy_name:
                        policy_name = policy_info.get('policy_name', 'Not Assigned')

                    status = get_policy_status(policy_id, graded_record)

                    context.console.print(f"[{Style.BOLD}]{policy_display_name} Policy:[/{Style.BOLD}] {policy_name}")

                    if status == "PASSED":
                        context.console.print(f"  Status: [{Style.GREEN}]✓ PASSED[/{Style.GREEN}]")
                    elif status == "FAILED":
                        context.console.print(f"  Status: [{Style.RED}]✗ FAILED[/{Style.RED}]")

                        # Show failure details
                        if graded_record and 'graded_policies' in graded_record:
                            for policy_result in graded_record['graded_policies']:
                                if policy_result.get('policy_id') == policy_id:
                                    context.console.print(f"  Failed Checks: {policy_result.get('failures_count', 0)}/{policy_result.get('checks_count', 0)}")
                                    break
                    else:
                        context.console.print(f"  Status: [{Style.YELLOW}]{status}[/{Style.YELLOW}]")

                    context.console.print()
            else:
                context.console.print(f"[{Style.YELLOW}]Host '{args.hostname}' not found in database[/{Style.YELLOW}]")

        elif args.show_hosts and args.hostname:
            # Just show the host summary table for the specific host
            host_data = collect_host_data(adapter, cid, policy_records, config)
            filtered_hosts = filter_hosts(host_data, args.platform, args.host_status, args.hostname)

            if filtered_hosts:
                sorted_hosts = sort_hosts(filtered_hosts, args.sort_hosts)
                # Determine which policy types to display in the table
                policy_types_to_display = determine_policy_types_to_display(args.policy_type)
                table = build_host_table(sorted_hosts, context, config, policy_types_to_display)
                context.console.print(table)

                # Calculate stats and cache info
                stats = calculate_host_stats(sorted_hosts)
                hosts_in_db = adapter.get_hosts(cid)

                if hosts_in_db and 'epoch' in hosts_in_db:
                    cache_age_seconds, cache_age_display = calculate_cache_age(hosts_in_db['epoch'])
                    hosts_ttl_seconds = get_hosts_ttl(config)
                    cache_age_display = format_cache_display_with_ttl(cache_age_display, hosts_ttl_seconds)
                    cache_info = CacheInfo(
                        age_seconds=cache_age_seconds,
                        age_display=cache_age_display,
                        ttl_seconds=hosts_ttl_seconds,
                        expired=is_cache_expired(cache_age_seconds, hosts_ttl_seconds)
                    )
                    print_host_stats(stats, cache_info, context)
            else:
                context.console.print(f"[{Style.YELLOW}]No hosts match the specified filters[/{Style.YELLOW}]\n")

        else:
            # Show policy tables if explicitly requested or if filters are applied
            # Use hasattr to safely check for status attribute (policies subcommand has 'status', hosts/host have 'host_status')
            policy_status = getattr(args, 'status', None)
            show_policy_tables = args.show_policies or (getattr(args, 'details', False) and not args.show_hosts) or (policy_status and not args.show_hosts)

            if show_policy_tables:
                # Display policy tables
                policy_types_to_display = determine_policy_types_to_display(args.policy_type)

                for policy_type in policy_types_to_display:
                    graded_record = policy_records.get(policy_type)

                    if graded_record and 'graded_policies' in graded_record:
                        # Filter and sort policies
                        policies = graded_record['graded_policies']
                        filtered_policies = filter_policies(policies, args.platform, policy_status)
                        sorted_policies = sort_policies(filtered_policies, args.sort_policies)

                        print_policy_table(graded_record, policy_type, config, sorted_policies, context)

                        if getattr(args, 'details', False):
                            print_policy_details(graded_record, policy_type, context)

            # Show host summary if requested (without hostname filter)
            if args.show_hosts:
                host_data = collect_host_data(adapter, cid, policy_records, config)
                filtered_hosts = filter_hosts(host_data, args.platform, args.host_status, args.hostname)

                if filtered_hosts:
                    sorted_hosts = sort_hosts(filtered_hosts, args.sort_hosts)
                    # Determine which policy types to display in the table
                    policy_types_to_display = determine_policy_types_to_display(args.policy_type)
                    table = build_host_table(sorted_hosts, context, config, policy_types_to_display)
                    context.console.print(table)

                    # Calculate stats and cache info
                    stats = calculate_host_stats(sorted_hosts)
                    hosts_in_db = adapter.get_hosts(cid)

                    if hosts_in_db and 'epoch' in hosts_in_db:
                        cache_age_seconds, cache_age_display = calculate_cache_age(hosts_in_db['epoch'])
                        hosts_ttl_seconds = get_hosts_ttl(config)
                        cache_age_display = format_cache_display_with_ttl(cache_age_display, hosts_ttl_seconds)
                        cache_info = CacheInfo(
                            age_seconds=cache_age_seconds,
                            age_display=cache_age_display,
                            ttl_seconds=hosts_ttl_seconds,
                            expired=is_cache_expired(cache_age_seconds, hosts_ttl_seconds)
                        )
                        print_host_stats(stats, cache_info, context)
                else:
                    context.console.print(f"[{Style.YELLOW}]No hosts match the specified filters[/{Style.YELLOW}]\n")

            # Print helpful tips if minimal output
            if not args.show_policies and not args.show_hosts:
                context.console.print(f"\n[{Style.YELLOW}]Use --help to show all available commands and options[/{Style.YELLOW}]")
                context.console.print("[dim]Tip: Use --fetch to retrieve fresh data from CrowdStrike API[/dim]")
                context.console.print("[dim]Tip: Use --show-policies to see policy grading tables[/dim]")
                context.console.print("[dim]Tip: Use --show-hosts to see host-level policy status[/dim]")
                context.console.print("[dim]Tip: Use --details to see detailed failure information[/dim]")
                context.console.print("[dim]Tip: Use --output-format json to get machine-readable output[/dim]\n")


class JsonOutputStrategy(OutputStrategy):
    """Strategy for JSON output."""

    def output(self, data: Dict[str, Any], context) -> None:
        """Display data as JSON.

        Args:
            data: Data dictionary containing adapter, cid, config, args
            context: CLI context
        """
        # Import build_json_output function
        from falcon_policy_scoring.utils.json_builder import build_json_output

        adapter = data['adapter']
        cid = data['cid']
        config = data['config']
        args = data['args']

        json_data = build_json_output(adapter, cid, config, args)
        json_str = json.dumps(json_data, indent=2)

        output_file = args.output_file

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_str)
            if context.verbose:
                context.console.print(f"[green]JSON output written to: {output_file}[/green]")
        else:
            print(json_str)


def get_output_strategy(format_type: str) -> OutputStrategy:
    """Factory function to get output strategy.

    Args:
        format_type: Output format type ('text' or 'json')

    Returns:
        OutputStrategy instance
    """
    strategies = {
        'text': TextOutputStrategy(),
        'json': JsonOutputStrategy()
    }
    return strategies.get(format_type, TextOutputStrategy())
