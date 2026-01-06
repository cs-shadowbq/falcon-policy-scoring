"""JSON output builder utilities.

Pure business logic for building JSON reports. No UI dependencies.
Shared between CLI and daemon modules.
"""
import sys
from typing import Dict, List
from falcon_policy_scoring import __version__ as APP_VERSION
from .constants import POLICY_TYPE_REGISTRY
from .metadata_builder import build_report_metadata
from .datetime_utils import get_utc_iso_timestamp
from .policy_helpers import (
    determine_policy_types_to_display,
    fetch_all_graded_policies,
    calculate_policy_stats
)
from .filters import filter_policies
from .host_data import collect_host_data
from .cache_helpers import calculate_cache_age, get_policy_ttl, is_cache_expired


def redact_sensitive_args(args: List[str]) -> List[str]:
    """Redact sensitive command-line arguments.

    Args:
        args: List of command-line arguments

    Returns:
        List with sensitive values redacted
    """
    sensitive_args = [
        '--client-id',
        '--client-secret',
        '--base-url'
    ]

    redacted_args = []
    skip_next = False

    for i, arg in enumerate(args):
        if skip_next:
            redacted_args.append('<redacted>')
            skip_next = False
            continue

        # Check if this argument contains sensitive data
        is_sensitive = False
        for sensitive_arg in sensitive_args:
            # Check for --key=value format
            if arg.startswith(f'{sensitive_arg}='):
                redacted_args.append(f'{sensitive_arg}=<redacted>')
                is_sensitive = True
                break
            # Check for --key value format (value is in next argument)
            elif arg == sensitive_arg:
                redacted_args.append(arg)
                skip_next = True
                is_sensitive = True
                break

        if not is_sensitive:
            redacted_args.append(arg)

    return redacted_args


def build_json_output(adapter, cid: str, config: Dict, args) -> Dict:
    """Build structured JSON output matching the schema.

    Args:
        adapter: Database adapter
        cid: CrowdStrike CID
        config: Configuration dict
        args: Arguments object with attributes: show_hosts, policy_type, platform,
              status, hostname, host_status, product_types (optional)

    Returns:
        Dict containing structured output
    """
    output = {
        "metadata": {
            "version": APP_VERSION,
            "timestamp": get_utc_iso_timestamp(),
            "report_type": "host-details" if args.show_hosts else "policy-audit",
            "cid": cid,
            "database_type": config.get('db', {}).get('type', 'tiny_db'),
            "filters": {}
        },
        "summary": {
            "total_policies": 0,
            "passed_policies": 0,
            "failed_policies": 0
        },
        "policies": {}
    }

    # Add command line to metadata with sensitive args redacted
    redacted_args = redact_sensitive_args(sys.argv)
    output["metadata"]["command"] = ' '.join(redacted_args)

    # Add optional metadata based on config settings
    optional_metadata = build_report_metadata(config)
    output["metadata"].update(optional_metadata)

    # Add filters to metadata
    if args.policy_type != 'all':
        # Handle comma-separated list of policy types
        policy_types = [t.strip().replace('-', '_') for t in args.policy_type.split(',')]
        output["metadata"]["filters"]["policy_types"] = policy_types
    else:
        output["metadata"]["filters"]["policy_types"] = ["prevention", "sensor_update", "content_update", "firewall", "device_control", "it_automation"]

    output["metadata"]["filters"]["platform"] = args.platform
    # Use getattr to safely get status - policies subcommand has 'status', hosts/host have 'host_status'
    output["metadata"]["filters"]["status"] = getattr(args, 'status', None)

    # product_types is only available in the fetch subcommand
    product_types = getattr(args, 'product_types', None)
    if product_types:
        if product_types.lower() == 'all':
            output["metadata"]["filters"]["product_types"] = None
        else:
            output["metadata"]["filters"]["product_types"] = [pt.strip() for pt in product_types.split(',')]
    else:
        output["metadata"]["filters"]["product_types"] = ['Workstation', 'Domain Controller', 'Server']

    # Determine which policy types to include
    policy_types_to_include = determine_policy_types_to_display(args.policy_type)

    # Build policy results
    total_checks = 0
    total_failures = 0

    policy_records = fetch_all_graded_policies(adapter, cid, POLICY_TYPE_REGISTRY)

    for policy_type in policy_types_to_include:
        graded_record = policy_records.get(policy_type)

        if not graded_record:
            continue

        # Calculate cache info using shared utilities
        cache_age_seconds = 0
        if 'epoch' in graded_record:
            cache_age_seconds, _ = calculate_cache_age(graded_record['epoch'])

        ttl_seconds = get_policy_ttl(config, policy_type)
        cache_expired = is_cache_expired(cache_age_seconds, ttl_seconds)

        # Filter policies
        policies = graded_record.get('graded_policies', [])
        # Use getattr to safely get status - policies subcommand has 'status', hosts/host have 'host_status'
        policy_status = getattr(args, 'status', None)
        filtered_policies = filter_policies(policies, args.platform, policy_status)

        # Build policy list and calculate inline stats for building output
        policy_list = []

        for policy in filtered_policies:
            checks_count = policy.get('checks_count', 0)
            failures_count = policy.get('failures_count', 0)
            total_checks += checks_count
            total_failures += failures_count

            policy_list.append({
                "policy_id": policy.get('policy_id'),
                "policy_name": policy.get('policy_name'),
                "platform_name": policy.get('platform_name') or policy.get('target', 'Unknown'),
                "passed": policy.get('passed', False),
                "checks_count": checks_count,
                "failures_count": failures_count,
                "score_percentage": round(((checks_count - failures_count) / checks_count * 100), 2) if checks_count > 0 else 0,
                "setting_results": policy.get('setting_results', [])
            })

        # Use shared function to calculate stats
        stats = calculate_policy_stats(policy_list)
        passed_count = stats['passed_count']
        failed_count = stats['failed_count']

        # Calculate score for this policy type
        type_checks = sum(p['checks_count'] for p in policy_list)
        type_failures = sum(p['failures_count'] for p in policy_list)
        score_percentage = round(((type_checks - type_failures) / type_checks * 100), 2) if type_checks > 0 else 0

        output["policies"][policy_type] = {
            "cache_age_seconds": cache_age_seconds,
            "cache_ttl_seconds": ttl_seconds,
            "cache_expired": cache_expired,
            "total_policies": len(policy_list),
            "passed_policies": passed_count,
            "failed_policies": failed_count,
            "score_percentage": score_percentage,
            "graded_policies": policy_list
        }

        output["summary"]["total_policies"] += len(policy_list)
        output["summary"]["passed_policies"] += passed_count
        output["summary"]["failed_policies"] += failed_count

    # Calculate overall score
    if total_checks > 0:
        output["summary"]["overall_score"] = round(((total_checks - total_failures) / total_checks) * 100, 2)
    else:
        output["summary"]["overall_score"] = 0

    # Add host information if requested
    if args.show_hosts:
        output["hosts"] = []

        # Import get_policy_status here to avoid circular dependency
        from .policy_helpers import get_policy_status
        host_data = collect_host_data(adapter, cid, policy_records, get_policy_status, config)

        # Build policy ID to name lookup maps for each policy type
        policy_id_to_name = {}
        for policy_type in ['prevention', 'sensor_update', 'content_update', 'firewall', 'device_control', 'it_automation']:
            graded_record = policy_records.get(policy_type)
            if graded_record and 'graded_policies' in graded_record:
                for policy in graded_record['graded_policies']:
                    policy_id = policy.get('policy_id')
                    policy_name = policy.get('policy_name')
                    if policy_id and policy_name:
                        policy_id_to_name[policy_id] = policy_name

        all_passed_count = 0
        any_failed_count = 0

        for host in host_data:
            # Apply filters
            if args.platform and host.get('platform', '').lower() != args.platform.lower():
                continue

            if args.hostname and host.get('hostname', '').lower() != args.hostname.lower():
                continue

            if args.host_status:
                if args.host_status == 'all-passed' and not host.get('all_passed', False):
                    continue
                if args.host_status == 'any-failed' and not host.get('any_failed', False):
                    continue

            if host.get('all_passed', False):
                all_passed_count += 1
            if host.get('any_failed', False):
                any_failed_count += 1

            # Try to fetch the stored host record to extract assigned policy ids/names
            host_record = adapter.get_host(host['device_id']) if hasattr(adapter, 'get_host') else None
            device_policies = {}
            if host_record and 'data' in host_record:
                device_policies = host_record['data'].get('device_policies', {}) or {}

            # Helper to locate policy info with hyphen/underscore variants
            def _find_policy_info(policy_map, key):
                # try exact key, underscore, hyphen variants
                candidates = [key, key.replace('_', '-'), key.replace('-', '_')]
                for k in candidates:
                    info = policy_map.get(k)
                    if info:
                        return info
                return {}

            prevention_info = _find_policy_info(device_policies, 'prevention')
            sensor_update_info = _find_policy_info(device_policies, 'sensor_update')
            content_update_info = _find_policy_info(device_policies, 'content_update')
            firewall_info = _find_policy_info(device_policies, 'firewall')
            device_control_info = _find_policy_info(device_policies, 'device_control')
            it_automation_info = _find_policy_info(device_policies, 'it_automation')

            # Helper to get policy name from ID
            def _get_policy_name(policy_id):
                return policy_id_to_name.get(policy_id) if policy_id else None

            # Build host output including policy ids/names when available
            host_output = {
                "device_id": host['device_id'],
                "hostname": host['hostname'],
                "platform": host['platform'],
                "policy_status": {
                    "prevention": {
                        "status": host['prevention_status'],
                        "policy_id": prevention_info.get('policy_id') or prevention_info.get('policy') or None,
                        "policy_name": _get_policy_name(prevention_info.get('policy_id'))
                    },
                    "sensor_update": {
                        "status": host['sensor_update_status'],
                        "policy_id": sensor_update_info.get('policy_id') or sensor_update_info.get('policy') or None,
                        "policy_name": _get_policy_name(sensor_update_info.get('policy_id'))
                    },
                    "content_update": {
                        "status": host['content_update_status'],
                        "policy_id": content_update_info.get('policy_id') or content_update_info.get('policy') or None,
                        "policy_name": _get_policy_name(content_update_info.get('policy_id'))
                    },
                    "firewall": {
                        "status": host['firewall_status'],
                        "policy_id": firewall_info.get('policy_id') or firewall_info.get('policy') or None,
                        "policy_name": _get_policy_name(firewall_info.get('policy_id'))
                    },
                    "device_control": {
                        "status": host['device_control_status'],
                        "policy_id": device_control_info.get('policy_id') or device_control_info.get('policy') or None,
                        "policy_name": _get_policy_name(device_control_info.get('policy_id'))
                    },
                    "it_automation": {
                        "status": host['it_automation_status'],
                        "policy_id": it_automation_info.get('policy_id') or it_automation_info.get('policy') or None,
                        "policy_name": _get_policy_name(it_automation_info.get('policy_id'))
                    }
                },
                "all_policies_passed": host['all_passed'],
                "any_policy_failed": host['any_failed']
            }

            # Include the full host_record data if available
            if host_record and 'data' in host_record:
                host_output["host_record"] = host_record['data']

            # Include Zero Trust Assessment data if enabled and available
            include_zta = config.get('host_fetching', {}).get('include_zta', True)
            if include_zta:
                zta_data = adapter.get_host_zta(host['device_id']) if hasattr(adapter, 'get_host_zta') else None
                if zta_data:
                    host_output["zero_trust"] = zta_data

            output["hosts"].append(host_output)

        output["summary"]["total_hosts"] = len(output["hosts"])
        output["summary"]["hosts_all_passed"] = all_passed_count
        output["summary"]["hosts_any_failed"] = any_failed_count

    return output
