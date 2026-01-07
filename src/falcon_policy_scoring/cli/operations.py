"""Operations for fetching and grading policies and hosts."""
from falcon_policy_scoring.falconapi.hosts import Hosts
from falcon_policy_scoring.falconapi.host_group import HostGroup
from falcon_policy_scoring.falconapi.zero_trust import fetch_zero_trust_assessments
from falcon_policy_scoring.utils.policy_registry import get_policy_registry
from falcon_policy_scoring.grading.engine import load_grading_config, POLICY_GRADERS, DEFAULT_GRADING_CONFIGS
from falcon_policy_scoring.falconapi.policies import get_policy_table_name
from .constants import Style, DEFAULT_PROGRESS_THRESHOLD
from falcon_policy_scoring.utils.constants import DEFAULT_BATCH_SIZE
from .helpers import parse_host_groups


def parse_product_types(product_types_arg):
    """Parse product types argument.

    Args:
        product_types_arg: Product types argument string

    Returns:
        List of product types or empty list for all
    """
    if product_types_arg:
        if product_types_arg.lower() == 'all':
            return []  # Empty list means no filtering
        else:
            return [pt.strip() for pt in product_types_arg.split(',')]
    else:
        # Default: only include these device types
        return ['Workstation', 'Domain Controller', 'Server']


def fetch_and_store_hosts(falcon, adapter, cid: str, product_types, config, ctx, host_group_names=None, last_seen_filter=None):
    """Fetch and store hosts from CrowdStrike API.

    Args:
        falcon: FalconPy API client
        adapter: Database adapter
        cid: Customer ID
        product_types: List of product types to filter
        config: Configuration dictionary
        ctx: CLI context
        host_group_names: Optional list of host group names to filter by
        last_seen_filter: Optional FQL filter for last_seen time period

    Returns:
        Results dictionary with counts
    """
    from .data_fetcher import fetch_hosts_with_progress, fetch_hosts_simple

    ctx.log_verbose("Fetching hosts...")

    # Handle host group filtering
    device_ids_filter = None
    if host_group_names:
        ctx.log_verbose(f"Filtering by host groups: {', '.join(host_group_names)}")

        try:
            host_group_api = HostGroup(falcon)
            device_ids_filter = host_group_api.get_device_ids_from_groups(host_group_names)

            if not device_ids_filter:
                ctx.console.print(f"[{Style.YELLOW}]⚠ No devices found in specified host groups[/{Style.YELLOW}]")
                return {'fetched': 0, 'total_hosts': 0, 'errors': 0}

            ctx.log_verbose(f"Found {len(device_ids_filter)} unique devices in host groups")

        except ValueError as e:
            ctx.console.print(f"[{Style.RED}]✗ Error resolving host groups: {e}[/{Style.RED}]")
            raise

    # Get host list
    hosts_api = Hosts(cid, falcon, filter=last_seen_filter, product_types=product_types, device_ids=device_ids_filter)
    hosts_list = hosts_api.get_devices()
    adapter.put_hosts(hosts_list)

    host_ids = hosts_list.get('hosts', [])
    total_hosts = len(host_ids)

    # Get batch settings
    batch_size = config.get('host_fetching', {}).get('batch_size', DEFAULT_BATCH_SIZE)
    progress_threshold = config.get('host_fetching', {}).get('progress_threshold', DEFAULT_PROGRESS_THRESHOLD)

    # Fetch host details
    if total_hosts > progress_threshold:
        results = fetch_hosts_with_progress(falcon, adapter, host_ids, batch_size, ctx)
    else:
        results = fetch_hosts_simple(falcon, adapter, host_ids, batch_size, ctx)

    return results


def fetch_and_store_zta(falcon, adapter, host_ids: list, ctx):
    """Fetch and store Zero Trust Assessment data for hosts.

    Args:
        falcon: FalconPy API client
        adapter: Database adapter
        host_ids: List of device IDs to fetch ZTA data for
        ctx: CLI context

    Returns:
        Results dictionary with counts
    """
    if not host_ids:
        ctx.log_verbose("No host IDs to fetch ZTA data for")
        return {'fetched': 0, 'errors': 0}

    ctx.log_verbose(f"Fetching Zero Trust Assessments for {len(host_ids)} hosts...")

    with ctx.console.status(f"[{Style.BOLD}][{Style.GREEN}]Fetching Zero Trust Assessments...[/{Style.GREEN}][/{Style.BOLD}]"):
        result = fetch_zero_trust_assessments(falcon, host_ids)

    # Store each assessment
    for device_id, assessment_data in result['assessments'].items():
        adapter.put_host_zta(device_id, assessment_data)

    ctx.log_verbose(f"Stored {result['count']} ZTA assessments")

    return {
        'fetched': result['count'],
        'errors': len(result.get('errors', []))
    }


def fetch_and_grade_all_policies(falcon, adapter, cid: str, policy_types: list, ctx):
    """Fetch and grade all specified policy types.

    Args:
        falcon: FalconPy API client
        adapter: Database adapter
        cid: Customer ID
        policy_types: List of policy types to fetch ('all' or specific types)
        ctx: CLI context
    """
    # Get the policy registry
    policy_registry = get_policy_registry()

    # Determine which policies to fetch
    if 'all' in policy_types:
        policies_to_fetch = policy_registry.get_all_types()
    else:
        # Convert CLI names to internal names
        policies_to_fetch = []
        for policy_type in policy_types:
            # Try direct lookup first (e.g., 'prevention')
            if policy_registry.get(policy_type):
                policies_to_fetch.append(policy_type)
            else:
                # Try by CLI name (e.g., 'sensor-update' -> 'sensor_update')
                for key, info in policy_registry.get_all().items():
                    if info.cli_name == policy_type:
                        policies_to_fetch.append(key)
                        break

    ctx.log_verbose(f"Fetching and grading {len(policies_to_fetch)} policy types...")

    # Fetch and grade each policy type
    for policy_type in policies_to_fetch:
        policy_info = policy_registry.get(policy_type)
        if policy_info and policy_info.grader_func:
            ctx.log_verbose(f"Fetching and grading {policy_info.display_name} policies...")

            with ctx.console.status(f"[{Style.BOLD}][{Style.GREEN}]Fetching {policy_info.display_name} policies...[/{Style.GREEN}][/{Style.BOLD}]"):
                result = policy_info.grader_func(falcon, adapter, cid)

            # Show results
            if not ctx.json_output_mode:
                if result.get('permission_error'):
                    # Show permission error with assist message
                    ctx.console.print(
                        f"[{Style.YELLOW}]⚠ Failed to fetch {policy_info.display_name} policies[/{Style.YELLOW}]"
                    )
                    assist_msg = result.get('assist_message')
                    if assist_msg:
                        ctx.console.print(f"[{Style.YELLOW}]{assist_msg}[/{Style.YELLOW}]")
                elif result.get('grade_success'):
                    passed = result.get('passed_policies', 0)
                    failed = result.get('failed_policies', 0)
                    total = result.get('policies_count', 0)

                    ctx.console.print(
                        f"[{Style.BOLD}][{Style.GREEN}]✓ {policy_info.display_name} Policies: "
                        f"{passed}/{total} passed, {failed} failed[/{Style.GREEN}][/{Style.BOLD}]"
                    )
                elif result.get('fetch_success'):
                    ctx.console.print(
                        f"[{Style.YELLOW}]⚠ {policy_info.display_name} policies fetched but not graded[/{Style.YELLOW}]"
                    )
                else:
                    ctx.console.print(
                        f"[{Style.YELLOW}]⚠ Failed to fetch {policy_info.display_name} policies[/{Style.YELLOW}]"
                    )
        else:
            ctx.log_verbose(f"No grader function for policy type: {policy_type}")

    if not ctx.json_output_mode:
        ctx.console.print()


def handle_fetch_operations(falcon, adapter, cid: str, args, config, ctx):
    """Handle fetch operations if requested.

    Args:
        falcon: FalconPy API client (must not be None for fetch operations)
        adapter: Database adapter
        cid: Customer ID
        args: Command line arguments
        config: Configuration dictionary
        ctx: CLI context

    Raises:
        ValueError: If falcon is None
    """
    if falcon is None:
        raise ValueError("API connection required for fetch operations")

    # Parse product types
    product_types = parse_product_types(args.product_types)

    # Parse host groups if provided
    host_group_names = parse_host_groups(getattr(args, 'host_groups', None))

    # Get last_seen filter if provided
    last_seen_filter = getattr(args, 'last_seen', None)

    # Fetch hosts (with optional host group filtering)
    host_results = fetch_and_store_hosts(falcon, adapter, cid, product_types, config, ctx, host_group_names, last_seen_filter)

    # Show summary in text mode
    if not ctx.json_output_mode:
        ctx.console.print(f"\n[{Style.BOLD}][{Style.GREEN}]✓ Fetched {host_results['fetched']:,} of {host_results['total_hosts']:,} hosts[/{Style.GREEN}][/{Style.BOLD}]")
        if host_results['errors'] > 0:
            ctx.console.print(f"[{Style.YELLOW}]⚠ {host_results['errors']:,} hosts had errors[/{Style.YELLOW}]")
        ctx.console.print()

    # Fetch Zero Trust Assessments for hosts (if enabled)
    include_zta = config.get('host_fetching', {}).get('include_zta', True)
    if include_zta:
        hosts_list = adapter.get_hosts(cid)
        host_ids = hosts_list.get('hosts', []) if hosts_list else []
        if host_ids:
            zta_results = fetch_and_store_zta(falcon, adapter, host_ids, ctx)
            if not ctx.json_output_mode:
                ctx.console.print(f"[{Style.BOLD}][{Style.GREEN}]✓ Fetched {zta_results['fetched']:,} Zero Trust Assessments[/{Style.GREEN}][/{Style.BOLD}]")
                if zta_results['errors'] > 0:
                    ctx.console.print(f"[{Style.YELLOW}]⚠ {zta_results['errors']:,} ZTA errors[/{Style.YELLOW}]")
                ctx.console.print()

    # Fetch and grade policies
    if args.policy_type == 'all':
        policy_types = ['all']
    else:
        # Split comma-separated values
        policy_types = [t.strip() for t in args.policy_type.split(',')]

    fetch_and_grade_all_policies(falcon, adapter, cid, policy_types, ctx)

    # Print completion message
    if not ctx.json_output_mode:
        ctx.console.print(f"[{Style.BOLD}][{Style.GREEN}]Fetch and Grade Complete![/{Style.GREEN}][/{Style.BOLD}]\n")


def regrade_policies(adapter, cid: str, policy_types: list, ctx):
    """Re-grade existing policies from the database with current grading criteria.

    Args:
        adapter: Database adapter
        cid: Customer ID
        policy_types: List of policy types to regrade ('all' or specific types)
        ctx: CLI context
    """
    # Get the policy registry
    policy_registry = get_policy_registry()

    # Determine which policies to regrade
    if 'all' in policy_types:
        policies_to_regrade = policy_registry.get_all_types()
    else:
        # Convert CLI names to internal names
        policies_to_regrade = []
        for policy_type in policy_types:
            # Try direct lookup first (e.g., 'prevention')
            if policy_registry.get(policy_type):
                policies_to_regrade.append(policy_type)
            else:
                # Try by CLI name (e.g., 'sensor-update' -> 'sensor_update')
                for key, info in policy_registry.get_all().items():
                    if info.cli_name == policy_type:
                        policies_to_regrade.append(key)
                        break

    ctx.log_verbose(f"Re-grading {len(policies_to_regrade)} policy types with current criteria...")

    total_passed = 0
    total_failed = 0
    total_policies = 0

    # Regrade each policy type
    for policy_type in policies_to_regrade:
        policy_info = policy_registry.get(policy_type)
        if not policy_info:
            ctx.log_verbose(f"Unknown policy type: {policy_type}")
            continue

        # Check if grader exists
        if policy_type not in POLICY_GRADERS:
            ctx.log_verbose(f"No grader available for policy type: {policy_type}")
            continue

        ctx.log_verbose(f"Re-grading {policy_info.display_name} policies...")

        with ctx.console.status(f"[{Style.BOLD}][{Style.GREEN}]Re-grading {policy_info.display_name} policies...[/{Style.GREEN}][/{Style.BOLD}]"):
            # Retrieve stored policies from database
            table_name = get_policy_table_name(policy_type)
            policies_record = adapter.get_policies(table_name, cid)

            if not policies_record or 'error' in policies_record:
                if not ctx.json_output_mode:
                    ctx.console.print(
                        f"[{Style.YELLOW}]⚠ No {policy_info.display_name} policies found in database[/{Style.YELLOW}]"
                    )
                continue

            policies_data = policies_record.get('policies', [])
            if not policies_data:
                if not ctx.json_output_mode:
                    ctx.console.print(
                        f"[{Style.YELLOW}]⚠ No {policy_info.display_name} policies in database[/{Style.YELLOW}]"
                    )
                continue

            # Load grading configuration
            default_config = DEFAULT_GRADING_CONFIGS.get(policy_type)
            grading_config = load_grading_config(default_config)

            if not grading_config:
                if not ctx.json_output_mode:
                    ctx.console.print(
                        f"[{Style.RED}]✗ Failed to load grading configuration for {policy_info.display_name}[/{Style.RED}]"
                    )
                continue

            # Grade the policies using the appropriate grader
            grader_func = POLICY_GRADERS[policy_type]

            # Handle special cases that need additional metadata
            if policy_type == 'firewall':
                # Firewall grader needs policy_containers_map
                policy_containers_map = policies_record.get('policy_containers', {})
                graded_results = grader_func(policies_data, policy_containers_map, grading_config)
            elif policy_type == 'device_control':
                # Device control grader needs policy_settings_map
                policy_settings_map = policies_record.get('policy_settings', {})
                graded_results = grader_func(policies_data, policy_settings_map, grading_config)
            else:
                # Simple graders (prevention, sensor_update, content_update, it_automation)
                graded_results = grader_func(policies_data, grading_config)

            if graded_results is None:
                if not ctx.json_output_mode:
                    ctx.console.print(
                        f"[{Style.RED}]✗ Grading failed for {policy_info.display_name}[/{Style.RED}]"
                    )
                continue

            # Store graded results
            adapter.put_graded_policies(f'{policy_type}_policies', cid, graded_results)

            # Calculate summary
            passed = sum(1 for r in graded_results if r.get('passed', False))
            failed = len(graded_results) - passed
            total = len(graded_results)

            total_passed += passed
            total_failed += failed
            total_policies += total

            # Show results
            if not ctx.json_output_mode:
                ctx.console.print(
                    f"[{Style.BOLD}][{Style.GREEN}]✓ {policy_info.display_name} Policies: "
                    f"{passed}/{total} passed, {failed} failed[/{Style.GREEN}][/{Style.BOLD}]"
                )

    # Print summary
    if not ctx.json_output_mode:
        ctx.console.print()
        ctx.console.print(f"[{Style.BOLD}][{Style.GREEN}]Re-grade Complete![/{Style.GREEN}][/{Style.BOLD}]")
        ctx.console.print(f"Total: {total_passed}/{total_policies} policies passed, {total_failed} failed\n")


def handle_regrade_operations(adapter, cid: str, args, ctx):
    """Handle regrade operations.

    Args:
        adapter: Database adapter
        cid: Customer ID
        args: Command line arguments
        ctx: CLI context
    """
    # Parse policy types - handle 'all' or comma-separated list
    if args.policy_type == 'all':
        policy_types = ['all']
    else:
        # Split comma-separated values
        policy_types = [t.strip() for t in args.policy_type.split(',')]

    # Regrade policies
    regrade_policies(adapter, cid, policy_types, ctx)
