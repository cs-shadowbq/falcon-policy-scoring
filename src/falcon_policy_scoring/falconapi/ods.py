"""
ODS (On Demand Scan) API utilities.

Handles fetching scheduled scans using the two-step query + get pattern.
Scheduled scans are Windows-only and require the 'ods:read' API scope.
"""

import logging
from typing import Dict, List, Tuple


def _query_all_scan_ids(falcon, limit: int = 500) -> Tuple[List[str], bool, str]:
    """
    Query for all scheduled scan IDs with pagination.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        limit: Maximum number of records per API request

    Returns:
        Tuple of (scan_ids, permission_error, assist_message)
    """
    from falcon_policy_scoring.falconapi.policies import check_scope_permission_error

    all_ids = []
    offset = 0
    weblink = 'https://www.falconpy.io/Service-Collections/ODS.html#queryscheduledscans'

    while True:
        logging.debug("Querying scheduled scan IDs (offset: %s, limit: %s)...", offset, limit)
        response = falcon.command('query_scheduled_scans', limit=limit, offset=offset)

        is_permission_error, assist_msg = check_scope_permission_error(
            response, 'query_scheduled_scans', weblink
        )
        if is_permission_error:
            logging.warning("Permission error querying scheduled scans: %s", response.get('body', {}))
            logging.warning(assist_msg)
            return [], True, assist_msg

        if response.get('status_code') != 200:
            logging.warning("Failed to query scheduled scan IDs: %s", response.get('body', {}))
            break

        batch_ids = response['body'].get('resources', [])
        all_ids.extend(batch_ids)

        meta = response['body'].get('meta', {})
        pagination = meta.get('pagination', {})
        total = pagination.get('total', 0)

        logging.debug("Retrieved %d scan IDs so far (total: %d)", len(all_ids), total)

        if len(batch_ids) == 0 or offset + limit >= total:
            break

        offset += limit

    return all_ids, False, None


def _fetch_scans_by_ids(falcon, scan_ids: List[str], batch_size: int = 100) -> List[Dict]:
    """
    Fetch full scan details for the given scan IDs in batches.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        scan_ids: List of scan IDs to fetch
        batch_size: Maximum number of IDs per GetScheduledScansScanIds call

    Returns:
        List of scheduled scan objects
    """
    all_scans = []

    for i in range(0, len(scan_ids), batch_size):
        batch = scan_ids[i:i + batch_size]
        logging.debug(
            "Fetching scheduled scans batch %d (%d IDs)...", i // batch_size + 1, len(batch)
        )

        response = falcon.command('get_scheduled_scans_by_scan_ids', ids=batch)

        if response.get('status_code') != 200:
            logging.warning(
                "Failed to fetch scheduled scan batch: %s", response.get('body', {})
            )
            continue

        scans = response['body'].get('resources', [])
        all_scans.extend(scans)
        logging.debug(
            "Fetched %d scans in batch (total so far: %d)", len(scans), len(all_scans)
        )

    return all_scans


def fetch_all_scheduled_scans(falcon, db_adapter, cid: str) -> Dict:
    """
    Fetch all scheduled scans for a CID and store raw results.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        db_adapter: Database adapter instance
        cid: Customer ID

    Returns:
        Dict with structure:
            {
                'policies': [scan_obj, ...],
                'total': int,
                'permission_error': bool  (only if error),
                'assist_message': str     (only if error)
            }
    """
    logging.info("Fetching all scheduled scans...")

    scan_ids, permission_error, assist_message = _query_all_scan_ids(falcon)

    if permission_error:
        return {
            'policies': [],
            'total': 0,
            'permission_error': True,
            'assist_message': assist_message
        }

    if not scan_ids:
        logging.info("No scheduled scan IDs found")
        result = {'policies': [], 'total': 0}
        db_adapter.put_policies('ods_scheduled_scan_policies', cid, result)
        return result

    logging.info("Found %d scheduled scan IDs, fetching details...", len(scan_ids))
    scans = _fetch_scans_by_ids(falcon, scan_ids)

    # Filter out deleted scans
    active_scans = [s for s in scans if not s.get('deleted', False)]
    logging.info(
        "Fetched %d scheduled scans (%d active after filtering deleted)",
        len(scans), len(active_scans)
    )

    result = {'policies': active_scans, 'total': len(active_scans)}
    db_adapter.put_policies('ods_scheduled_scan_policies', cid, result)
    return result


def build_host_coverage_index(falcon, scans: List[Dict]) -> Dict[str, List[str]]:
    """
    Build an index mapping device_id -> [scan_id, ...] by expanding host groups.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        scans: List of scheduled scan objects

    Returns:
        Dict mapping device_id to list of scan IDs that cover that device
    """
    from falcon_policy_scoring.falconapi.host_group import HostGroup

    hg = HostGroup(falcon)
    coverage_index = {}  # device_id -> [scan_id, ...]

    for scan in scans:
        scan_id = scan.get('id')
        host_groups = scan.get('host_groups', [])

        if not scan_id:
            continue

        if not host_groups:
            logging.debug("Scan %s has no host groups, skipping coverage expansion.", scan_id)
            continue

        for group_id in host_groups:
            logging.debug("Expanding host group %s for scan %s...", group_id, scan_id)
            member_ids = hg.get_all_group_members(group_id)
            logging.debug("Group %s has %d members", group_id, len(member_ids))

            for device_id in member_ids:
                if device_id not in coverage_index:
                    coverage_index[device_id] = []
                if scan_id not in coverage_index[device_id]:
                    coverage_index[device_id].append(scan_id)

    logging.info(
        "ODS coverage index built: %d devices covered across %d scans",
        len(coverage_index), len(scans)
    )
    return coverage_index
