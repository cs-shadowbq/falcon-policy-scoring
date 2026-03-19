"""
Module for fetching CrowdStrike Falcon policies.
Provides a generic interface for fetching different policy types.
"""

import logging
from falcon_policy_scoring import grading
from falcon_policy_scoring.utils.constants import POLICY_TYPE_REGISTRY

# Policy type configuration — derived from the central registry.
# 'sca' (Secure Configuration Assessment) is retained as a placeholder; it
# reuses the sensor_update API command but is not part of the graded registry.
POLICY_TYPES = {
    k: {
        'command': v['api_command'],
        'table_name': v['db_key'],
        'limit': v['api_limit'],
        'weblink': v['api_weblink'],
        **({'is_shim': True} if v['is_shim'] else {}),
    }
    for k, v in POLICY_TYPE_REGISTRY.items()
}


def check_scope_permission_error(response, command_name: str = None, weblink: str = None):
    """
    Check if an API response indicates a scope permission error (403 with 'access denied, scope not permitted').

    Args:
        response: API response dictionary
        command_name: Optional name of the API command that was called
        weblink: Optional FalconPy documentation link

    Returns:
        tuple: (is_permission_error: bool, assist_message: str or None)
               Returns assist_message if command_name and weblink provided, otherwise None
    """
    if response.get('status_code') != 403:
        return False, None

    body = response.get('body', {})
    errors = body.get('errors', [])

    for error in errors:
        error_code = error.get('code')
        error_message = error.get('message', '').lower()

        if error_code == 403 and 'access denied' in error_message and 'scope not permitted' in error_message:
            if command_name and weblink:
                assist_msg = (f"ASSIST: Your API key does not include the proper scope for the method '{command_name}', or licensed product SKU. \n"
                              f"See FalconPy documentation for details: {weblink}")
                return True, assist_msg
            return True, None

    return False, None


def get_policies(falcon, policy_type):
    """
    Fetch policies from CrowdStrike Falcon API with pagination support.

    Args:
        falcon: The FalconPy API client instance
        policy_type: Type of policy to fetch (e.g., 'prevention', 'firewall', 'sca', 'sensor_update', 'response')

    Returns:
        dict: The API response containing policy data, or a dict with 'error' key if failed

    Raises:
        ValueError: If policy_type is not supported
    """
    if policy_type not in POLICY_TYPES:
        raise ValueError(
            f"Unsupported policy type: {policy_type}. "
            f"Supported types: {', '.join(POLICY_TYPES.keys())}"
        )

    config = POLICY_TYPES[policy_type]
    command = config['command']
    limit = config.get('limit', 500)  # Use configured limit or default to 500
    is_shim = config.get('is_shim', False)  # Check if this is a custom shim function

    logging.info("Fetching %s policies using command: %s (limit: %s)", policy_type, command, limit)

    # Fetch all policies with pagination support
    all_policies = []
    offset = 0

    while True:
        # Fetch a batch of policies
        if is_shim:
            # For IT Automation, use the custom shim function
            if policy_type == 'it_automation':
                from falcon_policy_scoring.falconapi import it_automation
                response = it_automation.query_combined_it_automation_policies(falcon, limit=limit, offset=offset)
            elif policy_type == 'sca':
                from falcon_policy_scoring.falconapi import sca
                response = sca.query_combined_sca_policies(falcon, limit=limit, offset=offset)
            else:
                logging.error("Unknown shim function for policy type: %s", policy_type)
                return {'error': 500, 'status_code': 500, 'body': {}}
        else:
            # Normal API command
            response = falcon.command(command, limit=limit, offset=offset)

        # Check for scope permission errors first
        is_permission_error, assist_msg = check_scope_permission_error(response, command, config.get('weblink', ''))
        if is_permission_error:
            weblink = config.get('weblink', '')
            error_msg = f"Access denied (403) for {policy_type} policies - access denied, scope not permitted"

            logging.warning(error_msg)
            logging.warning(assist_msg)

            return {
                'error': 403,
                'status_code': 403,
                'body': response.get('body', {}),
                'permission_error': True,
                'assist_message': assist_msg,
                'weblink': weblink
            }

        if response['status_code'] == 403:
            logging.warning("Access denied (403) for %s policies", policy_type)
            return {'error': 403, 'status_code': 403, 'body': {}}
        if response['status_code'] != 200:
            logging.error("Failed to fetch %s policies: %s", policy_type, response)
            return {'error': response['status_code'], 'status_code': response['status_code'], 'body': {}}

        # Get resources from this batch
        resources = response.get('body', {}).get('resources', [])
        all_policies.extend(resources)

        # Check if there are more results
        meta = response.get('body', {}).get('meta', {})
        pagination = meta.get('pagination', {})
        total = pagination.get('total', 0)

        logging.info("Fetched %s %s policies in this batch (total so far: %s/%s)", len(resources), policy_type, len(all_policies), total)

        # Stop if we've fetched all policies
        if len(all_policies) >= total or len(resources) == 0:
            break

        # Move to next batch
        offset += limit

    logging.info("Successfully fetched all %s %s policies", len(all_policies), policy_type)

    # Return response in the same format as original
    final_response = response.copy()
    final_response['body']['resources'] = all_policies

    return final_response


def get_policy_table_name(policy_type):
    """
    Get the database table name for a given policy type.

    Args:
        policy_type: Type of policy

    Returns:
        str: The table name for storing this policy type

    Raises:
        ValueError: If policy_type is not supported
    """
    if policy_type not in POLICY_TYPES:
        raise ValueError(
            f"Unsupported policy type: {policy_type}. "
            f"Supported types: {', '.join(POLICY_TYPES.keys())}"
        )

    return POLICY_TYPES[policy_type]['table_name']


def get_all_policy_types():
    """
    Get a list of all supported policy types.

    Returns:
        list: List of supported policy type names
    """
    return list(POLICY_TYPES.keys())


def fetch_and_store_policy(falcon, db_adapter, cid, policy_type):
    """
    Fetch and store a specific policy type.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        policy_type: Type of policy to fetch ('prevention', 'firewall', 'sca', etc.)

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Fetch policies from API
        response = get_policies(falcon, policy_type)

        if response:
            # Get the table name for this policy type
            table_name = get_policy_table_name(policy_type)

            # Store in database (including errors like 403)
            db_adapter.put_policies(table_name, cid, response)

            if 'error' in response:
                logging.warning("Stored %s policies error (%s) for CID %s", policy_type, response['error'], cid)

            logging.info("Stored %s policies for CID %s", policy_type, cid)
            return True

        logging.error("Failed to fetch %s policies", policy_type)
        return False
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Exception while fetching %s policies: %s", policy_type, e)
        return False


def fetch_and_store_all_policies(falcon, db_adapter, cid):
    """
    Fetch and store all policy types.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID

    Returns:
        dict: Dictionary with policy types as keys and success status as values
    """
    # Get all supported policy types
    policy_types = get_all_policy_types()

    logging.info("Fetching %s policy types...", len(policy_types))
    results = {}

    for policy_type in policy_types:
        try:
            success = fetch_and_store_policy(falcon, db_adapter, cid, policy_type)
            results[policy_type] = success
        except Exception as e:  # pylint: disable=broad-exception-caught
            logging.error("Error fetching %s policies: %s", policy_type, e)
            results[policy_type] = False

    return results


def fetch_grade_and_store_prevention_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch prevention policies, grade them against minimums, and store both.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'data/prevention_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    return grading.fetch_grade_and_store_policies(
        falcon, db_adapter, cid, 'prevention', grading_config_file
    )


def fetch_grade_and_store_sensor_update_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch sensor update policies, grade them against minimums, and store both.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'data/sensor_update_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    return grading.fetch_grade_and_store_policies(
        falcon, db_adapter, cid, 'sensor_update', grading_config_file
    )


def fetch_grade_and_store_content_update_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch content update policies, grade them against minimums, and store both.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'data/content_update_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    return grading.fetch_grade_and_store_policies(
        falcon, db_adapter, cid, 'content_update', grading_config_file
    )


def fetch_grade_and_store_firewall_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch firewall policies and policy containers, then grade and store results.

    Firewall policies are graded based on policy container settings:
    - default_inbound: Should be DENY
    - enforce: Should be true
    - test_mode: Should be false

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'config/grading/firewall_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    from falcon_policy_scoring.falconapi import firewall as firewall_module
    from falcon_policy_scoring.grading import engine as grading_engine

    result = {
        'fetch_success': False,
        'grade_success': False,
        'policies_count': 0,
        'containers_count': 0,
        'passed_policies': 0,
        'failed_policies': 0,
        'permission_error': False,
        'assist_message': None
    }

    try:
        # Step 1: Fetch firewall policies
        logging.info("Step 1: Fetching firewall policies...")
        response = get_policies(falcon, 'firewall')

        # Check for permission error in response before storing
        if response and response.get('permission_error'):
            result['permission_error'] = True
            result['assist_message'] = response.get('assist_message')
            logging.warning("Permission error for firewall policies")
            return result

        # Store the response
        if response:
            table_name = get_policy_table_name('firewall')
            db_adapter.put_policies(table_name, cid, response)

        policies_record = db_adapter.get_policies('firewall_policies', cid)

        if not policies_record or 'policies' not in policies_record:
            logging.warning("No firewall policies found")
            return result

        policies_data = policies_record['policies']
        result['policies_count'] = len(policies_data)
        logging.info("Found %s firewall policies", len(policies_data))

        # Step 2: Fetch policy containers for all policies
        logging.info("Step 2: Fetching policy containers...")
        policy_ids = [p['id'] for p in policies_data]
        containers_result = firewall_module.fetch_policy_containers(falcon, db_adapter, policy_ids, cid)
        policy_containers_map = containers_result['policy_containers']
        result['containers_count'] = len(policy_containers_map)
        logging.info("Fetched %s policy containers", len(policy_containers_map))

        result['fetch_success'] = True

        # Step 3: Load grading config
        logging.info("Step 3: Loading grading configuration...")
        if grading_config_file:
            logging.info("Loading grading configuration from %s", grading_config_file)
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default firewall policies grading configuration")
            grading_config = grading_engine.load_grading_config('firewall_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 4: Grade policies with their containers
        logging.info("Step 4: Grading %s firewall policies...", len(policies_data))
        graded_results = grading_engine.grade_all_firewall_policies(
            policies_data, policy_containers_map, grading_config
        )

        if graded_results is None:
            logging.error("Grading returned None")
            return result

        # Step 5: Store graded results
        logging.info("Step 5: Storing graded results...")
        db_adapter.put_graded_policies('firewall_policies', cid, graded_results)

        # Calculate summary
        result['grade_success'] = True
        result['passed_policies'] = sum(1 for r in graded_results if r.get('passed', False))
        result['failed_policies'] = len(graded_results) - result['passed_policies']

        logging.info(
            "Firewall grading complete: %s/%s policies passed, %s policy containers",
            result['passed_policies'], result['policies_count'], result['containers_count']
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Error during fetch_grade_and_store_firewall_policies: %s", e)
        import traceback
        logging.error(traceback.format_exc())

    return result


def fetch_grade_and_store_device_control_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch device control policies and their settings, then grade and store results.

    Device control policies are graded based on:
    - enabled: Should be true
    - enforcement_mode: Should match configured requirement
    - Device class actions: Classes like MASS_STORAGE, IMAGING, etc. should be BLOCK_ALL

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'config/grading/device_control_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    from falcon_policy_scoring.falconapi import device_control as device_control_module
    from falcon_policy_scoring.grading import engine as grading_engine

    result = {
        'fetch_success': False,
        'grade_success': False,
        'policies_count': 0,
        'settings_count': 0,
        'passed_policies': 0,
        'failed_policies': 0,
        'permission_error': False,
        'assist_message': None
    }

    try:
        # Step 1: Fetch device control policies
        logging.info("Step 1: Fetching device control policies...")
        response = get_policies(falcon, 'device_control')

        # Check for permission error in response before storing
        if response and response.get('permission_error'):
            result['permission_error'] = True
            result['assist_message'] = response.get('assist_message')
            logging.warning("Permission error for device control policies")
            return result

        # Store the response
        if response:
            table_name = get_policy_table_name('device_control')
            db_adapter.put_policies(table_name, cid, response)

        policies_record = db_adapter.get_policies('device_control_policies', cid)

        if not policies_record or 'policies' not in policies_record:
            logging.warning("No device control policies found")
            return result

        policies_data = policies_record['policies']
        result['policies_count'] = len(policies_data)
        logging.info("Found %s device control policies", len(policies_data))
        # Step 1: Fetch device control policies
        logging.info("Step 1: Fetching device control policies...")
        fetch_and_store_policy(falcon, db_adapter, cid, 'device_control')

        policies_record = db_adapter.get_policies('device_control_policies', cid)
        if not policies_record or 'policies' not in policies_record:
            logging.warning("No device control policies found")
            return result

        policies_data = policies_record['policies']
        result['policies_count'] = len(policies_data)
        logging.info("Found %s device control policies", len(policies_data))

        # Step 2: Fetch policy settings for all policies
        logging.info("Step 2: Fetching policy settings...")
        policy_ids = [p['id'] for p in policies_data]
        settings_result = device_control_module.fetch_policy_settings(falcon, db_adapter, policy_ids, cid)
        policy_settings_map = settings_result['policy_settings']
        result['settings_count'] = len(policy_settings_map)
        logging.info("Fetched %s policy settings", len(policy_settings_map))

        result['fetch_success'] = True

        # Step 3: Load grading config
        logging.info("Step 3: Loading grading configuration...")
        if grading_config_file:
            logging.info("Loading grading configuration from %s", grading_config_file)
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default device control policies grading configuration")
            grading_config = grading_engine.load_grading_config('device_control_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 4: Grade policies with their settings
        logging.info("Step 4: Grading %s device control policies...", len(policies_data))
        graded_results = grading_engine.grade_all_device_control_policies(
            policies_data, policy_settings_map, grading_config
        )

        if graded_results is None:
            logging.error("Grading returned None")
            return result

        # Step 5: Store graded results
        logging.info("Step 5: Storing graded results...")
        db_adapter.put_graded_policies('device_control_policies', cid, graded_results)

        # Calculate summary
        result['grade_success'] = True
        result['passed_policies'] = sum(1 for r in graded_results if r.get('passed', False))
        result['failed_policies'] = len(graded_results) - result['passed_policies']

        logging.info(
            "Device control grading complete: %s/%s policies passed, %s policy settings",
            result['passed_policies'], result['policies_count'], result['settings_count']
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Error during fetch_grade_and_store_device_control_policies: %s", e)
        import traceback
        logging.error(traceback.format_exc())

    return result


def fetch_grade_and_store_it_automation_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch IT automation policies, then grade and store results.

    IT Automation policies are graded based on:
    - is_enabled: Should be true (top-level)
    - config.execution.enable_script_execution: Should be true (nested)

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'config/grading/it_automation_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    from falcon_policy_scoring.falconapi import it_automation
    from falcon_policy_scoring.grading import engine as grading_engine

    result = {
        'fetch_success': False,
        'grade_success': False,
        'policies_count': 0,
        'passed_policies': 0,
        'failed_policies': 0,
        'permission_error': False,
        'assist_message': None
    }

    try:
        # Step 1: Fetch IT automation policies
        logging.info("Step 1: Fetching IT automation policies...")
        policies_data = it_automation.fetch_it_automation_policies(falcon, db_adapter, cid, force_refresh=True)

        # Check if there's a permission error in the returned data
        if policies_data and policies_data.get('permission_error'):
            result['permission_error'] = True
            result['assist_message'] = policies_data.get('assist_message')
            logging.warning("Permission error for IT automation policies")
            return result

        if not policies_data or not policies_data.get('policies'):
            logging.warning("No IT automation policies found")
            return result

        result['policies_count'] = len(policies_data['policies'])
        logging.info("Found %s IT automation policies", result['policies_count'])
        result['fetch_success'] = True

        # Step 2: Load grading config
        logging.info("Step 2: Loading grading configuration...")
        if grading_config_file:
            logging.info("Loading grading configuration from %s", grading_config_file)
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default IT automation policies grading configuration")
            grading_config = grading_engine.load_grading_config('it_automation_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 3: Grade policies
        logging.info("Step 3: Grading %s IT automation policies...", result['policies_count'])
        graded_results = grading_engine.grade_all_it_automation_policies(
            policies_data, grading_config
        )

        if graded_results is None:
            logging.error("Grading returned None")
            return result

        # Step 4: Store graded results
        logging.info("Step 4: Storing graded results...")
        db_adapter.put_graded_policies('it_automation_policies', cid, graded_results)

        # Calculate summary
        result['grade_success'] = True
        result['passed_policies'] = sum(1 for r in graded_results if r.get('passed', False))
        result['failed_policies'] = len(graded_results) - result['passed_policies']

        logging.info(
            "IT automation grading complete: %s/%s policies passed",
            result['passed_policies'], result['policies_count']
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Error during fetch_grade_and_store_it_automation_policies: %s", e)
        import traceback
        logging.error(traceback.format_exc())

    return result


def fetch_grade_and_store_ods_scheduled_scan_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch ODS scheduled scans, build host coverage index, then grade and store results.

    ODS scheduled scans are graded based on:
    - status: Must be 'scheduled'
    - schedule.interval: Must not exceed maximum days (e.g., 7)
    - cloud_ml_level_detection: Must meet minimum level (0-3 scale)
    - sensor_ml_level_detection: Must meet minimum level (0-3 scale)

    Scheduled scans are Windows-only. Host coverage is stored separately so
    that collect_host_data() can determine per-host ODS status.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'config/grading/ods_scheduled_scan_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    from falcon_policy_scoring.falconapi import ods as ods_module
    from falcon_policy_scoring.grading import engine as grading_engine

    result = {
        'fetch_success': False,
        'grade_success': False,
        'policies_count': 0,
        'passed_policies': 0,
        'failed_policies': 0,
        'permission_error': False,
        'assist_message': None
    }

    try:
        # Step 1: Fetch all scheduled scans
        logging.info("Step 1: Fetching ODS scheduled scans...")
        scans_data = ods_module.fetch_all_scheduled_scans(falcon, db_adapter, cid)

        if scans_data.get('permission_error'):
            result['permission_error'] = True
            result['assist_message'] = scans_data.get('assist_message')
            logging.warning("Permission error for ODS scheduled scans")
            return result

        scans_list = scans_data.get('policies', [])
        if not scans_list:
            logging.warning("No ODS scheduled scans found")
            result['fetch_success'] = True
            return result

        result['policies_count'] = len(scans_list)
        logging.info("Found %s ODS scheduled scans", result['policies_count'])

        # Step 2: Build and store host coverage index
        logging.info("Step 2: Building host coverage index from host groups...")
        coverage_index = ods_module.build_host_coverage_index(falcon, scans_list)
        db_adapter.put_ods_scan_coverage(cid, coverage_index)
        logging.info("Coverage index stored: %d devices covered", len(coverage_index))

        result['fetch_success'] = True

        # Step 3: Load grading config
        logging.info("Step 3: Loading grading configuration...")
        if grading_config_file:
            logging.info("Loading grading configuration from %s", grading_config_file)
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default ODS scheduled scan grading configuration")
            grading_config = grading_engine.load_grading_config('ods_scheduled_scan_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 4: Grade scans
        logging.info("Step 4: Grading %s ODS scheduled scans...", result['policies_count'])
        graded_results = grading_engine.grade_all_ods_scheduled_scans(scans_data, grading_config)

        if graded_results is None:
            logging.error("Grading returned None")
            return result

        # Step 5: Store graded results
        logging.info("Step 5: Storing graded results...")
        db_adapter.put_graded_policies('ods_scheduled_scan_policies', cid, graded_results)

        # Calculate summary
        result['grade_success'] = True
        result['passed_policies'] = sum(1 for r in graded_results if r.get('passed', False))
        result['failed_policies'] = len(graded_results) - result['passed_policies']

        # Step 6: Build per-host last compliant scan timestamps from scan run history.
        # Scheduled scan metadata always stays 'scheduled' (next-run state only).
        # Actual completion timestamps live in scan run objects, linked to the
        # source scheduled scan via run['profile_id'].
        logging.info("Step 6: Fetching scan run history for compliant scan timestamps...")
        passing_scan_ids = {
            r['policy_id'] for r in graded_results
            if r.get('passed', False) and r.get('policy_id')
        }
        last_compliant_scan_times = ods_module.fetch_last_compliant_scan_times(
            falcon, passing_scan_ids
        )

        db_adapter.put_ods_scan_coverage(cid, coverage_index, last_compliant_scan_times)
        logging.info(
            "ODS grading complete: %s/%s scans passed, %d devices covered, %d with compliant scan timestamp",
            result['passed_policies'], result['policies_count'],
            len(coverage_index), len(last_compliant_scan_times)
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Error during fetch_grade_and_store_ods_scheduled_scan_policies: %s", e)
        import traceback
        logging.error(traceback.format_exc())

    return result


def fetch_grade_and_store_sca_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch SCA virtual policies (derived from findings), then grade and store results.

    SCA grading is findings-based: the public getCombinedAssessmentsQuery API
    is used to detect which hosts have SCA findings.  The presence of findings
    for a host confirms its policy is both enabled and has rule groups defined.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'config/grading/sca_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    from falcon_policy_scoring.falconapi import sca as sca_module
    from falcon_policy_scoring.grading import engine as grading_engine

    result = {
        'fetch_success': False,
        'grade_success': False,
        'policies_count': 0,
        'passed_policies': 0,
        'failed_policies': 0,
        'permission_error': False,
        'assist_message': None
    }

    try:
        # Step 1: Fetch SCA findings and build virtual policies + coverage index
        logging.info("Step 1: Fetching SCA findings and building virtual policies...")
        policies_data = sca_module.fetch_sca_policies(falcon, db_adapter, cid, force_refresh=True)

        if policies_data and policies_data.get('permission_error'):
            result['permission_error'] = True
            result['assist_message'] = policies_data.get('assist_message')
            logging.warning("Permission error for SCA policies")
            return result

        result['policies_count'] = len(policies_data.get('policies', []) if policies_data else [])
        if result['policies_count'] == 0:
            logging.info("No SCA virtual policies found (no findings returned for this CID)")
        else:
            logging.info("Found %s virtual SCA policies", result['policies_count'])
        result['fetch_success'] = True

        # Step 2: Load grading config
        logging.info("Step 2: Loading grading configuration...")
        if grading_config_file:
            logging.info("Loading grading configuration from %s", grading_config_file)
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default SCA policies grading configuration")
            grading_config = grading_engine.load_grading_config('sca_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 3: Grade virtual policies
        logging.info("Step 3: Grading %s virtual SCA policies...", result['policies_count'])
        graded_results = grading_engine.grade_all_sca_policies(policies_data, grading_config)

        if graded_results is None:
            logging.error("Grading returned None")
            return result

        # Step 4: Store graded results
        logging.info("Step 4: Storing graded results...")
        db_adapter.put_graded_policies('sca_policies', cid, graded_results)

        result['grade_success'] = True
        result['passed_policies'] = sum(1 for r in graded_results if r.get('passed', False))
        result['failed_policies'] = len(graded_results) - result['passed_policies']

        logging.info(
            "SCA grading complete: %s/%s policies passed",
            result['passed_policies'], result['policies_count']
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Error during fetch_grade_and_store_sca_policies: %s", e)
        import traceback
        logging.error(traceback.format_exc())

    return result


def fetch_grade_and_store_response_policies(falcon, db_adapter, cid, grading_config_file=None):
    """
    Fetch Response (RTR) policies, grade them against minimums, and store both.

    RTR policies are graded based on toggle settings:
    - enabled: Policy must be active
    - RealTimeFunctionality: Core RTR toggle must be enabled
    - CustomScripts: Custom scripts toggle must be enabled
    - GetCommand, PutCommand, ExecCommand: High-risk command toggles
    - PutAndRunCommand: Put-and-run command (Windows only)

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        grading_config_file: Optional path to grading config file.
                            Defaults to 'config/grading/response_policies_grading.json'

    Returns:
        dict: Results including fetch status and grading summary
    """
    return grading.fetch_grade_and_store_policies(
        falcon, db_adapter, cid, 'response', grading_config_file
    )
