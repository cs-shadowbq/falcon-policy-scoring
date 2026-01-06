"""
IT Automation Policy API utilities.

Handles fetching IT automation policies using the two-step query + get pattern.
"""

import logging
from typing import Dict, List, Optional


def _query_all_policy_ids(falcon, platforms: List[str] = None, limit: int = 500,
                          log_level: str = 'debug') -> tuple:
    """
    Query for all IT automation policy IDs across platforms with pagination.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        platforms: List of platforms to query (defaults to Windows, Linux, Mac)
        limit: Maximum number of records to return per API request
        log_level: Logging level to use ('debug' or 'info')

    Returns:
        Tuple of (policy_ids, permission_error, assist_message)
        - policy_ids: List of all policy IDs across all platforms
        - permission_error: Boolean indicating if a permission error occurred
        - assist_message: String with ASSIST message if permission error, None otherwise
    """
    if platforms is None:
        platforms = ['Windows', 'Linux', 'Mac']

    all_policy_ids = []
    log_func = logging.debug if log_level == 'debug' else logging.info
    permission_error_detected = False
    assist_message = None

    for platform in platforms:
        platform_offset = 0

        while True:
            log_func(f"Querying {platform} IT automation policies (offset: {platform_offset}, limit: {limit})...")
            query_response = falcon.command('ITAutomationQueryPolicies',
                                            platform=platform,
                                            limit=limit,
                                            offset=platform_offset)

            # Check for scope permission errors
            from falcon_policy_scoring.falconapi.policies import check_scope_permission_error
            weblink = "https://www.falconpy.io/Service-Collections/IT-Automation.html#itautomationquerypolicies"
            is_permission_error, assist_msg = check_scope_permission_error(query_response, 'ITAutomationQueryPolicies', weblink)
            if is_permission_error:
                error_msg = f"Failed to query {platform} IT automation policies: {query_response.get('body', {})}"
                logging.warning(error_msg)
                logging.warning(assist_msg)
                permission_error_detected = True
                assist_message = assist_msg
                break

            if query_response['status_code'] != 200:
                logging.warning(f"Failed to query {platform} IT automation policies: {query_response.get('body', {})}")
                break

            platform_ids = query_response['body'].get('resources', [])
            all_policy_ids.extend(platform_ids)

            # Check pagination info
            meta = query_response['body'].get('meta', {})
            pagination = meta.get('pagination', {})
            platform_total = pagination.get('total', 0)

            log_func(f"Found {len(platform_ids)} {platform} IT automation policy IDs in this batch")

            # Stop if we've fetched all policies for this platform
            if len(platform_ids) == 0 or platform_offset + limit >= platform_total:
                break

            platform_offset += limit

        if log_level == 'info':
            logging.info(f"Completed fetching all {platform} IT automation policy IDs")

        # If permission error detected, stop processing other platforms
        if permission_error_detected:
            break

    return all_policy_ids, permission_error_detected, assist_message


def _fetch_policies_by_ids(falcon, policy_ids: List[str], batch_size: int = 100,
                           log_level: str = 'debug') -> List[Dict]:
    """
    Fetch full policy details for the given policy IDs in batches.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        policy_ids: List of policy IDs to fetch
        batch_size: Maximum number of IDs per ITAutomationGetPolicies call
        log_level: Logging level to use ('debug' or 'info')

    Returns:
        List of policy objects
    """
    all_policies = []
    log_func = logging.debug if log_level == 'debug' else logging.info

    for i in range(0, len(policy_ids), batch_size):
        batch_ids = policy_ids[i:i + batch_size]
        log_func(f"Fetching IT automation policies batch {i // batch_size + 1} ({len(batch_ids)} policies)...")

        get_response = falcon.command('ITAutomationGetPolicies', ids=batch_ids)

        # Check for scope permission errors
        from falcon_policy_scoring.falconapi.policies import check_scope_permission_error
        weblink = "https://www.falconpy.io/Service-Collections/IT-Automation.html#itautomationgetpolicies"
        is_permission_error, assist_msg = check_scope_permission_error(get_response, 'ITAutomationGetPolicies', weblink)
        if is_permission_error:
            error_msg = f"Failed to fetch IT automation policies batch: {get_response.get('body', {})}"
            logging.error(error_msg)
            logging.warning(assist_msg)
            continue

        if get_response['status_code'] == 200:
            batch_policies = get_response['body'].get('resources', [])
            all_policies.extend(batch_policies)
            if log_level == 'info':
                logging.info(f"Fetched {len(batch_policies)} policies in this batch")
        else:
            logging.error(f"Failed to fetch IT automation policies batch: {get_response.get('body', {})}")

    return all_policies


def query_combined_it_automation_policies(falcon, limit: int = 500, offset: int = 0) -> Dict:
    """
    Shim function to mimic queryCombined*Policies pattern for IT Automation.

    IT Automation doesn't have a true queryCombined endpoint, so this function
    combines the query + get pattern to return full policy objects with pagination.

    Args:
        falcon: FalconPy APIHarnessV2 instance
        limit: Maximum number of records to return per request
        offset: Starting index for record retrieval

    Returns:
        dict: API response in the same format as other queryCombined endpoints:
            {
                'status_code': int,
                'body': {
                    'resources': [policy objects],
                    'meta': {
                        'pagination': {
                            'total': int
                        }
                    }
                },
                'permission_error': bool (optional),
                'assist_message': str (optional)
            }
    """
    # Step 1: Query for all policy IDs across all platforms
    all_policy_ids, permission_error, assist_message = _query_all_policy_ids(falcon, limit=limit, log_level='debug')

    # If permission error occurred, return error response
    if permission_error:
        return {
            'status_code': 403,
            'body': {},
            'permission_error': True,
            'assist_message': assist_message
        }

    if not all_policy_ids:
        # Return empty response in expected format
        return {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {
                    'pagination': {
                        'total': 0
                    }
                }
            }
        }

    # Apply offset/limit to the combined policy IDs
    paginated_ids = all_policy_ids[offset:offset + limit]

    # Step 2: Fetch full policy details for the paginated IDs
    all_policies = _fetch_policies_by_ids(falcon, paginated_ids, batch_size=100, log_level='debug')

    # Return in the expected queryCombined format
    return {
        'status_code': 200,
        'body': {
            'resources': all_policies,
            'meta': {
                'pagination': {
                    'total': len(all_policy_ids)  # Total across all platforms
                }
            }
        }
    }


def fetch_it_automation_policies(falcon, db_adapter, cid: str, force_refresh: bool = False) -> Dict:
    """
    Fetch IT automation policies for all platforms (Windows, Linux, Mac).

    IT Automation policies must be queried per platform, then details fetched by IDs.
    Uses the two-step pattern:
      1. ITAutomationQueryPolicies (with platform parameter) -> get policy IDs
      2. ITAutomationGetPolicies (with ids parameter) -> get full policy details

    Policy structure includes:
    - is_enabled: boolean (top-level)
    - config.execution.enable_script_execution: boolean (nested)
    - config.execution.enable_python_execution: boolean
    - config.execution.enable_os_query: boolean
    - target: Windows, Linux, or Mac

    Args:
        falcon: FalconPy APIHarnessV2 instance
        db_adapter: Database adapter instance
        cid: Customer ID
        force_refresh: If True, bypass cache and fetch fresh data

    Returns:
        dict: {
            'policies': [list of policy objects],
            'count': int,
            'cid': str,
            'epoch': int
        }
    """
    # Check cache unless force refresh
    if not force_refresh:
        cached = db_adapter.get_policies('it_automation_policies', cid)
        if cached and cached.get('policies'):
            logging.info(f"Using cached IT automation policies: {len(cached['policies'])} policies")
            return cached

    logging.info("Fetching IT automation policies...")

    try:
        # Step 1: Query for all policy IDs across all platforms with pagination
        all_policy_ids, permission_error, assist_message = _query_all_policy_ids(falcon, limit=500, log_level='info')

        # If permission error occurred, return error info immediately (don't store)
        if permission_error:
            logging.warning("Permission error detected while fetching IT automation policies")
            return {
                'cid': cid,
                'epoch': int(__import__('time').time()),
                'policies': [],
                'total': 0,
                'permission_error': True,
                'assist_message': assist_message
            }

        if not all_policy_ids:
            logging.info("No IT automation policies found")
            result = {
                'cid': cid,
                'epoch': int(__import__('time').time()),
                'policies': [],
                'total': 0
            }
            db_adapter.put_policies('it_automation_policies', cid, result)
            return result

        logging.info(f"Total IT automation policy IDs found: {len(all_policy_ids)}")

        # Step 2: Fetch detailed policy information by IDs
        all_policies = _fetch_policies_by_ids(falcon, all_policy_ids, batch_size=100, log_level='info')

        logging.info(f"Total IT automation policies fetched: {len(all_policies)}")

        # Store in cache using the format expected by SQLite adapter
        result = {
            'body': {
                'resources': all_policies
            }
        }
        db_adapter.put_policies('it_automation_policies', cid, result)

        # Return in the standard format for internal use
        return {
            'cid': cid,
            'epoch': int(__import__('time').time()),
            'policies': all_policies,
            'total': len(all_policies)
        }

    except Exception as e:
        logging.error(f"Exception fetching IT automation policies: {e}")
        import traceback
        traceback.print_exc()
        return {
            'cid': cid,
            'epoch': int(__import__('time').time()),
            'policies': [],
            'total': 0
        }


def get_policy_by_id(policies_data: Dict, policy_id: str) -> Optional[Dict]:
    """
    Get a specific IT automation policy by ID from fetched policies data.

    Args:
        policies_data: Result from fetch_it_automation_policies
        policy_id: Policy ID to retrieve

    Returns:
        Policy object if found, None otherwise
    """
    if not policies_data or not policies_data.get('policies'):
        return None

    for policy in policies_data['policies']:
        if policy.get('id') == policy_id:
            return policy

    return None
