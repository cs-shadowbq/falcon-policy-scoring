"""
Module for fetching CrowdStrike Falcon policies.
Provides a generic interface for fetching different policy types.
"""

import logging
from falcon_policy_scoring import grading

# Policy type configuration mapping
POLICY_TYPES = {
    'prevention': {
        'command': 'queryCombinedPreventionPolicies',
        'table_name': 'prevention_policies',
        'limit': 5000,
        'weblink': 'https://www.falconpy.io/Service-Collections/Prevention-Policies.html#querycombinedpreventionpolicies'
    },
    'firewall': {
        'command': 'queryCombinedFirewallPolicies',
        'table_name': 'firewall_policies',
        'limit': 5000,
        'weblink': 'https://www.falconpy.io/Service-Collections/Firewall-Policies.html#querycombinedfirewallpolicies'
    },
    'sca': {
        'command': 'queryCombinedSensorUpdatePolicies',  # Secure Configuration Assessment - Placeholder TBD
        'table_name': 'sca_policies',
        'limit': 5000,
        'weblink': 'https://www.falconpy.io/Service-Collections/Sensor-Update-Policies.html#querycombinedsensorupdatepolicies'
    },
    'sensor_update': {
        'command': 'queryCombinedSensorUpdatePolicies',
        'table_name': 'sensor_update_policies',
        'limit': 5000,
        'weblink': 'https://www.falconpy.io/Service-Collections/Sensor-Update-Policies.html#querycombinedsensorupdatepolicies'
    },
    'response': {
        'command': 'queryCombinedRTResponsePolicies',   # Not Graded at this Time
        'table_name': 'response_policies',
        'limit': 5000,
        'weblink': 'https://www.falconpy.io/Service-Collections/Response-Policies.html#querycombinedrtresponsepolicies'
    },
    'content_update': {
        'command': 'queryCombinedContentUpdatePolicies',
        'table_name': 'content_update_policies',
        'limit': 5000,
        'weblink': 'https://www.falconpy.io/Service-Collections/Content-Update-Policies.html#querycombinedcontentupdatepolicies'
    },
    'device_control': {
        'command': 'queryCombinedDeviceControlPolicies',
        'table_name': 'device_control_policies',
        'limit': 5000,
        'weblink': 'https://www.falconpy.io/Service-Collections/Device-Control-Policies.html#querycombineddevicecontrolpolicies'
    },
    'it_automation': {
        'command': 'query_combined_it_automation_policies',  # Custom shim function
        'table_name': 'it_automation_policies',
        'limit': 500,
        'is_shim': True,  # Flag to indicate this is a custom function, not a direct API command
        'weblink': 'https://www.falconpy.io/Service-Collections/IT-Automation.html#itautomationgetpolicies'
    },
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

    logging.info(f"Fetching {policy_type} policies using command: {command} (limit: {limit})")

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
            else:
                logging.error(f"Unknown shim function for policy type: {policy_type}")
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
            logging.warning(f"Access denied (403) for {policy_type} policies")
            return {'error': 403, 'status_code': 403, 'body': {}}
        elif response['status_code'] != 200:
            logging.error(f"Failed to fetch {policy_type} policies: {response}")
            return {'error': response['status_code'], 'status_code': response['status_code'], 'body': {}}

        # Get resources from this batch
        resources = response.get('body', {}).get('resources', [])
        all_policies.extend(resources)

        # Check if there are more results
        meta = response.get('body', {}).get('meta', {})
        pagination = meta.get('pagination', {})
        total = pagination.get('total', 0)

        logging.info(f"Fetched {len(resources)} {policy_type} policies in this batch (total so far: {len(all_policies)}/{total})")

        # Stop if we've fetched all policies
        if len(all_policies) >= total or len(resources) == 0:
            break

        # Move to next batch
        offset += limit

    logging.info(f"Successfully fetched all {len(all_policies)} {policy_type} policies")

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
                logging.warning(f"Stored {policy_type} policies error ({response['error']}) for CID {cid}")
            else:
                logging.info(f"Stored {policy_type} policies for CID {cid}")
            return True
        else:
            logging.error(f"Failed to fetch {policy_type} policies")
            return False
    except Exception as e:
        logging.error(f"Exception while fetching {policy_type} policies: {e}")
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

    logging.info(f"Fetching {len(policy_types)} policy types...")
    results = {}

    for policy_type in policy_types:
        try:
            success = fetch_and_store_policy(falcon, db_adapter, cid, policy_type)
            results[policy_type] = success
        except Exception as e:
            logging.error(f"Error fetching {policy_type} policies: {e}")
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
    import logging

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
        logging.info(f"Found {len(policies_data)} firewall policies")

        # Step 2: Fetch policy containers for all policies
        logging.info("Step 2: Fetching policy containers...")
        policy_ids = [p['id'] for p in policies_data]
        containers_result = firewall_module.fetch_policy_containers(falcon, db_adapter, policy_ids, cid)
        policy_containers_map = containers_result['policy_containers']
        result['containers_count'] = len(policy_containers_map)
        logging.info(f"Fetched {len(policy_containers_map)} policy containers")

        result['fetch_success'] = True

        # Step 3: Load grading config
        logging.info("Step 3: Loading grading configuration...")
        if grading_config_file:
            logging.info(f"Loading grading configuration from {grading_config_file}")
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default firewall policies grading configuration")
            grading_config = grading_engine.load_grading_config('firewall_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 4: Grade policies with their containers
        logging.info(f"Step 4: Grading {len(policies_data)} firewall policies...")
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
            f"Firewall grading complete: {result['passed_policies']}/{result['policies_count']} policies passed, "
            f"{result['containers_count']} policy containers"
        )

    except Exception as e:
        logging.error(f"Error during fetch_grade_and_store_firewall_policies: {e}")
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
    import logging

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
        logging.info(f"Found {len(policies_data)} device control policies")
        # Step 1: Fetch device control policies
        logging.info("Step 1: Fetching device control policies...")
        fetch_and_store_policy(falcon, db_adapter, cid, 'device_control')

        policies_record = db_adapter.get_policies('device_control_policies', cid)
        if not policies_record or 'policies' not in policies_record:
            logging.warning("No device control policies found")
            return result

        policies_data = policies_record['policies']
        result['policies_count'] = len(policies_data)
        logging.info(f"Found {len(policies_data)} device control policies")

        # Step 2: Fetch policy settings for all policies
        logging.info("Step 2: Fetching policy settings...")
        policy_ids = [p['id'] for p in policies_data]
        settings_result = device_control_module.fetch_policy_settings(falcon, db_adapter, policy_ids, cid)
        policy_settings_map = settings_result['policy_settings']
        result['settings_count'] = len(policy_settings_map)
        logging.info(f"Fetched {len(policy_settings_map)} policy settings")

        result['fetch_success'] = True

        # Step 3: Load grading config
        logging.info("Step 3: Loading grading configuration...")
        if grading_config_file:
            logging.info(f"Loading grading configuration from {grading_config_file}")
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default device control policies grading configuration")
            grading_config = grading_engine.load_grading_config('device_control_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 4: Grade policies with their settings
        logging.info(f"Step 4: Grading {len(policies_data)} device control policies...")
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
            f"Device control grading complete: {result['passed_policies']}/{result['policies_count']} policies passed, "
            f"{result['settings_count']} policy settings"
        )

    except Exception as e:
        logging.error(f"Error during fetch_grade_and_store_device_control_policies: {e}")
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
    import logging

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
        logging.info(f"Found {result['policies_count']} IT automation policies")
        result['fetch_success'] = True

        # Step 2: Load grading config
        logging.info("Step 2: Loading grading configuration...")
        if grading_config_file:
            logging.info(f"Loading grading configuration from {grading_config_file}")
            grading_config = grading_engine.load_grading_config(config_file=grading_config_file)
        else:
            logging.info("Loading default IT automation policies grading configuration")
            grading_config = grading_engine.load_grading_config('it_automation_policies')

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Step 3: Grade policies
        logging.info(f"Step 3: Grading {result['policies_count']} IT automation policies...")
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
            f"IT automation grading complete: {result['passed_policies']}/{result['policies_count']} policies passed"
        )

    except Exception as e:
        logging.error(f"Error during fetch_grade_and_store_it_automation_policies: {e}")
        import traceback
        logging.error(traceback.format_exc())

    return result
