"""Host data processing utilities.

Pure business logic for processing host data. No UI dependencies.
Shared between CLI and daemon modules.
"""
from typing import Dict, List, Optional


def find_host_by_name(adapter, cid: str, hostname: str) -> Optional[Dict]:
    """Search for a host by hostname.

    Args:
        adapter: Database adapter
        cid: Customer ID
        hostname: Hostname to search for

    Returns:
        Host data dictionary or None if not found
    """
    hosts_in_db = adapter.get_hosts(cid)
    if not hosts_in_db or 'hosts' not in hosts_in_db:
        return None

    for host in hosts_in_db['hosts']:
        device_id = host
        host_record = adapter.get_host(device_id)
        if not host_record:
            continue

        device_data = host_record.get('data', {})
        host_hostname = device_data.get('hostname', 'Unknown')

        if host_hostname.lower() == hostname.lower():
            return {'device_id': device_id, 'host_record': host_record, 'device_data': device_data}

    return None


def collect_host_data(adapter, cid: str, policy_records: Dict,
                      get_policy_status_func, config: Dict = None) -> List[Dict]:
    """Collect host data with policy status.

    Args:
        adapter: Database adapter
        cid: Customer ID
        policy_records: Dictionary of policy records by type
        get_policy_status_func: Function to get policy status
        config: Configuration dictionary (optional)

    Returns:
        List of host data dictionaries
    """
    hosts_in_db = adapter.get_hosts(cid)
    if not hosts_in_db or 'hosts' not in hosts_in_db:
        return []

    host_rows = []

    for host in hosts_in_db['hosts']:
        device_id = host
        host_record = adapter.get_host(device_id)
        if not host_record:
            continue

        device_data = host_record.get('data', {})
        hostname = device_data.get('hostname', 'Unknown')
        platform = device_data.get('platform_name', 'Unknown')
        device_policies = device_data.get('device_policies', {})

        # Get policy status for each type
        prevention_policy_info = device_policies.get('prevention', {})
        prevention_status = get_policy_status_func(prevention_policy_info.get('policy_id'), policy_records.get('prevention'))

        sensor_update_policy_info = device_policies.get('sensor_update', {})
        sensor_update_status = get_policy_status_func(sensor_update_policy_info.get('policy_id'), policy_records.get('sensor_update'))

        content_update_policy_info = device_policies.get('content-update', {})
        content_update_status = get_policy_status_func(content_update_policy_info.get('policy_id'), policy_records.get('content_update'))

        firewall_policy_info = device_policies.get('firewall', {})
        firewall_status = get_policy_status_func(firewall_policy_info.get('policy_id'), policy_records.get('firewall'))

        device_control_policy_info = device_policies.get('device_control', {})
        device_control_status = get_policy_status_func(device_control_policy_info.get('policy_id'), policy_records.get('device_control'))

        it_automation_policy_info = device_policies.get('it-automation', {})
        it_automation_status = get_policy_status_func(it_automation_policy_info.get('policy_id'), policy_records.get('it_automation'))

        # Fetch Zero Trust Assessment data (if enabled)
        zta_assessment = None
        include_zta = config.get('host_fetching', {}).get('include_zta', True) if config else True
        if include_zta:
            zta_data = adapter.get_host_zta(device_id)
            if zta_data and 'assessment' in zta_data:
                zta_assessment = {
                    'sensor_config': zta_data['assessment'].get('sensor_config', 0),
                    'os': zta_data['assessment'].get('os', 0),
                    'overall': zta_data['assessment'].get('overall', 0)
                }

        # Determine overall status
        statuses = [prevention_status, sensor_update_status, content_update_status,
                    firewall_status, device_control_status, it_automation_status]
        has_any_failed = any(s == "FAILED" for s in statuses)
        has_any_ungradable = any(s == "UNGRADABLE" for s in statuses)
        all_policies_passed = all(s == "PASSED" for s in statuses)

        host_rows.append({
            'device_id': device_id,
            'hostname': hostname,
            'platform': platform,
            'prevention_status': prevention_status,
            'sensor_update_status': sensor_update_status,
            'content_update_status': content_update_status,
            'firewall_status': firewall_status,
            'device_control_status': device_control_status,
            'it_automation_status': it_automation_status,
            'zta_assessment': zta_assessment,
            'all_passed': all_policies_passed,
            'any_failed': has_any_failed,
            'has_ungradable': has_any_ungradable
        })

    return host_rows


def calculate_host_stats(host_rows: List[Dict]) -> Dict:
    """Calculate statistics for hosts.

    Args:
        host_rows: List of host data dictionaries

    Returns:
        Statistics dictionary
    """
    total = len(host_rows)
    all_passed = sum(1 for h in host_rows if h.get('all_passed', False))
    any_failed = sum(1 for h in host_rows if h.get('any_failed', False))

    return {
        'total': total,
        'all_passed': all_passed,
        'any_failed': any_failed
    }


def process_host_batch(falcon, adapter, batch: List[str]) -> tuple:
    """Process a batch of host IDs and fetch their details.

    Args:
        falcon: FalconPy API client
        adapter: Database adapter
        batch: List of host IDs to process

    Returns:
        Tuple of (fetched_count, error_count)
    """
    from .constants import API_COMMAND_GET_DEVICE_DETAILS

    fetched_count = 0
    error_count = 0

    # Fetch host details
    response = falcon.command(API_COMMAND_GET_DEVICE_DETAILS, ids=batch)

    if response['status_code'] == 200:
        resources = response['body'].get('resources', [])
        for host_data in resources:
            device_id = host_data.get('device_id')
            if device_id:
                adapter.put_host(host_data)
                fetched_count += 1
    else:
        error_count = len(batch)

    return fetched_count, error_count
