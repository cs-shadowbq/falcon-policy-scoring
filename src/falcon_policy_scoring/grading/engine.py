"""
Module for grading CrowdStrike Falcon policies against minimum standards.
"""

import logging
import json
from falcon_policy_scoring.grading.utils import (
    compare_mlslider, compare_toggle, compare_n_level,
    parse_sensor_build_value, compare_ring_points, calculate_ring_points,
    compare_firewall_policy_container, compare_device_control_policy,
    compare_it_automation_policy
)


def load_grading_config(policy_type='prevention_policies', config_file=None):
    """
    Load grading configuration from JSON file.

    Args:
        policy_type: Type of policy (e.g., 'prevention_policies', 'sensor_update_policies')
        config_file: Optional explicit path to config file. If not provided,
                     uses 'config/grading/{policy_type}_grading.json'

    Returns:
        dict: Grading configuration
    """
    if config_file is None:
        config_file = f'config/grading/{policy_type}_grading.json'

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error("Failed to load grading config from %s: %s", config_file, e)
        return {}


def grade_setting(setting, minimum_setting):
    """
    Grade a single policy setting against minimum requirements.

    Args:
        setting: The actual setting dict from the policy
        minimum_setting: The minimum requirement setting dict from grading config

    Returns:
        dict: Grading result with pass/fail status and details
    """
    setting_id = setting.get('id')
    setting_type = setting.get('type', 'unknown')
    setting_value = setting.get('value', {})
    minimum_value = minimum_setting.get('value', {})

    result = {
        'setting_id': setting_id,
        'setting_name': setting.get('name', setting_id),
        'type': setting_type,
        'actual_value': setting_value,
        'minimum_value': minimum_value,
        'passed': False,
        'failures': []
    }

    # Handle mlslider type (has detection and prevention sub-values)
    if setting_type == 'mlslider':
        detection_passed = True
        prevention_passed = True

        if 'detection' in minimum_value:
            actual_detection = setting_value.get('detection', 'DISABLED')
            minimum_detection = minimum_value['detection']
            detection_passed = compare_mlslider(actual_detection, minimum_detection)
            if not detection_passed:
                result['failures'].append({
                    'field': 'detection',
                    'actual': actual_detection,
                    'minimum': minimum_detection
                })

        if 'prevention' in minimum_value:
            actual_prevention = setting_value.get('prevention', 'DISABLED')
            minimum_prevention = minimum_value['prevention']
            prevention_passed = compare_mlslider(actual_prevention, minimum_prevention)
            if not prevention_passed:
                result['failures'].append({
                    'field': 'prevention',
                    'actual': actual_prevention,
                    'minimum': minimum_prevention
                })

        result['passed'] = detection_passed and prevention_passed

    # Handle toggle type
    elif setting_type == 'toggle':
        actual_enabled = setting_value.get('enabled', False) if isinstance(setting_value, dict) else setting_value
        minimum_enabled = minimum_value.get('enabled', False) if isinstance(minimum_value, dict) else minimum_value

        result['passed'] = compare_toggle(actual_enabled, minimum_enabled)
        if not result['passed']:
            result['failures'].append({
                'field': 'enabled',
                'actual': actual_enabled,
                'minimum': minimum_enabled
            })

    else:
        # Unknown type, mark as passed but log warning
        logging.warning("Unknown setting type '%s' for setting %s", setting_type, setting_id)
        result['passed'] = True

    return result


def _create_empty_policy_result(policy_id='unknown', policy_name='unknown', platform_name='unknown'):
    """
    Create an empty/failed policy grading result structure.

    Args:
        policy_id: Policy ID
        policy_name: Policy name
        platform_name: Platform name

    Returns:
        dict: Empty result structure
    """
    return {
        'policy_id': policy_id,
        'policy_name': policy_name,
        'platform_name': platform_name,
        'passed': False,
        'setting_results': [],
        'failures_count': 0,
        'checks_count': 0
    }


def grade_prevention_policy(policy, grading_config):
    """
    Grade a prevention policy against minimum requirements.

    Args:
        policy: The policy dict to grade
        grading_config: The grading configuration dict (from prevention_policies_grading.json)

    Returns:
        dict: Grading result with overall pass/fail and individual setting results
    """
    if policy is None:
        logging.error("Cannot grade policy: policy is None")
        return _create_empty_policy_result()

    policy_id = policy.get('id')
    policy_name = policy.get('name')
    platform_name = policy.get('platform_name')
    policy_enabled = policy.get('enabled', False)

    result = _create_empty_policy_result(policy_id, policy_name, platform_name)
    result['passed'] = True  # Will be set to False if any setting fails

    # Get the grading requirements for prevention policies
    prevention_policies_list = grading_config.get('prevention_policies', [])

    # Find the platform-specific grading configuration
    platform_config = None
    for platform_entry in prevention_policies_list:
        if platform_entry.get('platform_name') == platform_name:
            platform_config = platform_entry
            break

    # If no platform-specific config found, log warning and return passed
    if not platform_config:
        logging.warning("No grading configuration found for platform '%s'", platform_name)
        result['passed'] = True
        return result

    # Check if policy should be enabled
    minimum_enabled = platform_config.get('enabled', False)
    if minimum_enabled is not False:  # Only check if explicitly set in config
        result['checks_count'] += 1

        if minimum_enabled and not policy_enabled:
            result['failures_count'] += 1
            result['passed'] = False
            result['setting_results'].append({
                'setting_id': 'enabled',
                'setting_name': 'Policy Enabled',
                'type': 'toggle',
                'actual_value': policy_enabled,
                'minimum_value': minimum_enabled,
                'passed': False,
                'failures': [{
                    'field': 'enabled',
                    'actual': policy_enabled,
                    'minimum': minimum_enabled
                }]
            })

    prevention_settings_config = platform_config.get('prevention_settings', [])

    # Create a lookup dict for minimum settings by ID
    minimum_settings_by_id = {}
    for category in prevention_settings_config:
        for min_setting in category.get('settings', []):
            minimum_settings_by_id[min_setting['id']] = min_setting

    # Grade each setting in the policy
    for category in policy.get('prevention_settings', []):
        for setting in category.get('settings', []):
            setting_id = setting.get('id')

            # Check if this setting has a minimum requirement
            if setting_id in minimum_settings_by_id:
                result['checks_count'] += 1
                minimum_setting = minimum_settings_by_id[setting_id]
                setting_result = grade_setting(setting, minimum_setting)
                result['setting_results'].append(setting_result)

                if not setting_result['passed']:
                    result['failures_count'] += 1
                    result['passed'] = False

    return result


def grade_all_policies(policies_data, grading_config, policy_grader_func, policy_type_name="policy"):
    """
    Generic function to grade all policies of a given type.

    Args:
        policies_data: List of policy dicts
        grading_config: The grading configuration dict
        policy_grader_func: Function to grade a single policy
        policy_type_name: Name of policy type for logging (e.g., "prevention", "sensor update")

    Returns:
        list: List of grading results for each policy
    """
    results = []

    for i, policy in enumerate(policies_data):
        if policy is None:
            logging.warning("Skipping None policy at index %s", i)
            continue

        result = policy_grader_func(policy, grading_config)
        results.append(result)

        # Log the result
        status = "PASSED" if result['passed'] else "FAILED"
        logging.info(
            "Policy '%s' (%s): %s - %s/%s checks failed",
            result['policy_name'], result['platform_name'], status,
            result['failures_count'], result['checks_count']
        )

    return results


def grade_all_prevention_policies(policies_data, grading_config):
    """
    Grade all prevention policies in the dataset.

    Args:
        policies_data: List of policy dicts
        grading_config: The grading configuration dict

    Returns:
        list: List of grading results for each policy
    """
    return grade_all_policies(policies_data, grading_config, grade_prevention_policy, "prevention")


def grade_sensor_update_policy(policy, grading_config):
    """
    Grade a sensor update policy against minimum requirements.

    Args:
        policy: The policy dict to grade
        grading_config: The grading configuration dict (from sensor_update_policies_grading.json)

    Returns:
        dict: Grading result with overall pass/fail and individual setting results
    """
    if policy is None:
        logging.error("Cannot grade policy: policy is None")
        return _create_empty_policy_result()

    policy_id = policy.get('id')
    policy_name = policy.get('name')
    platform_name = policy.get('platform_name')
    policy_enabled = policy.get('enabled', False)

    result = _create_empty_policy_result(policy_id, policy_name, platform_name)
    result['passed'] = True

    # Get the grading requirements for sensor update policies
    policies_list = grading_config.get('policies', [])

    # Find the platform-specific grading configuration
    platform_config = None
    for platform_entry in policies_list:
        if platform_entry.get('platform_name') == platform_name:
            platform_config = platform_entry
            break

    # If no platform-specific config found, log warning and return passed
    if not platform_config:
        logging.warning("No grading configuration found for platform '%s'", platform_name)
        result['passed'] = True
        return result

    # Check if policy should be enabled
    minimum_enabled = platform_config.get('enabled', False)
    result['checks_count'] += 1

    if minimum_enabled and not policy_enabled:
        result['failures_count'] += 1
        result['passed'] = False
        result['setting_results'].append({
            'setting_id': 'enabled',
            'setting_name': 'Policy Enabled',
            'type': 'toggle',
            'actual_value': policy_enabled,
            'minimum_value': minimum_enabled,
            'passed': False,
            'failures': [{
                'field': 'enabled',
                'actual': policy_enabled,
                'minimum': minimum_enabled
            }]
        })

    # Grade the build setting
    policy_settings = policy.get('settings', {})
    minimum_settings = platform_config.get('settings', {})

    if 'build' in minimum_settings:
        result['checks_count'] += 1

        # Parse both actual and minimum build values
        actual_n_value = parse_sensor_build_value(policy_settings)
        minimum_build = minimum_settings['build']

        # Minimum is just the string like "n-2", so compare directly
        build_passed = compare_n_level(actual_n_value, minimum_build)

        if not build_passed:
            result['failures_count'] += 1
            result['passed'] = False

        result['setting_results'].append({
            'setting_id': 'build',
            'setting_name': 'Sensor Build Version',
            'type': 'n_level',
            'actual_value': actual_n_value,
            'minimum_value': minimum_build,
            'passed': build_passed,
            'failures': [] if build_passed else [{
                'field': 'build',
                'actual': actual_n_value,
                'minimum': minimum_build
            }]
        })

    return result


def grade_all_sensor_update_policies(policies_data, grading_config):
    """
    Grade all sensor update policies in the dataset.

    Args:
        policies_data: List of policy dicts
        grading_config: The grading configuration dict

    Returns:
        list: List of grading results for each policy
    """
    return grade_all_policies(policies_data, grading_config, grade_sensor_update_policy, "sensor update")


def grade_content_update_policy(policy, grading_config):
    """
    Grade a content update policy against minimum requirements.

    Args:
        policy: The policy dict to grade
        grading_config: The grading configuration dict (from content_update_policies_grading.json)

    Returns:
        dict: Grading result with overall pass/fail and individual setting results
    """
    if policy is None:
        logging.error("Cannot grade policy: policy is None")
        return _create_empty_policy_result()

    policy_id = policy.get('id')
    policy_name = policy.get('name')
    platform_name = policy.get('platform_name')
    policy_enabled = policy.get('enabled', False)

    result = _create_empty_policy_result(policy_id, policy_name, platform_name)
    result['passed'] = True

    # Get the grading requirements for content update policies
    policies_list = grading_config.get('policies', [])

    # Find the platform-specific grading configuration (or 'all' platform)
    platform_config = None
    for platform_entry in policies_list:
        entry_platform = platform_entry.get('platform_name')
        if entry_platform == platform_name or entry_platform == 'all':
            platform_config = platform_entry
            break

    # If no platform-specific config found, log warning and return passed
    if not platform_config:
        logging.warning("No grading configuration found for platform '%s'", platform_name)
        result['passed'] = True
        return result

    # Check if policy should be enabled
    minimum_enabled = platform_config.get('enabled', False)
    result['checks_count'] += 1

    if minimum_enabled and not policy_enabled:
        result['failures_count'] += 1
        result['passed'] = False
        result['setting_results'].append({
            'setting_id': 'enabled',
            'setting_name': 'Policy Enabled',
            'type': 'toggle',
            'actual_value': policy_enabled,
            'minimum_value': minimum_enabled,
            'passed': False,
            'failures': [{
                'field': 'enabled',
                'actual': policy_enabled,
                'minimum': minimum_enabled
            }]
        })

    # Get ring assignment settings from policy
    policy_settings = policy.get('settings', {})
    ring_assignments = policy_settings.get('ring_assignment_settings', [])

    # Get minimum ring points requirements from config
    minimum_settings = platform_config.get('settings', {})
    min_ring_settings = minimum_settings.get('ring_assignment_settings', [])

    # Create lookup dict for minimum ring points by setting ID
    min_ring_points_by_id = {s['id']: s['ring_points'] for s in min_ring_settings}

    # Grade each ring assignment setting
    for ring_setting in ring_assignments:
        setting_id = ring_setting.get('id')

        # Check if this setting has a minimum requirement
        if setting_id not in min_ring_points_by_id:
            continue

        result['checks_count'] += 1

        # Check pinned_content_version - should be empty or "None"
        pinned_version = ring_setting.get('pinned_content_version', '')
        pinned_passed = pinned_version == '' or pinned_version == 'None'

        # Check ring points
        ring_assignment = ring_setting.get('ring_assignment', 'ea')
        delay_hours = ring_setting.get('delay_hours', 0)
        max_ring_points = min_ring_points_by_id[setting_id]

        ring_points_passed = compare_ring_points(ring_assignment, delay_hours, max_ring_points)

        # Overall setting pass if both checks pass
        setting_passed = pinned_passed and ring_points_passed

        if not setting_passed:
            result['failures_count'] += 1
            result['passed'] = False

        # Build failure details
        failures = []
        if not pinned_passed:
            failures.append({
                'field': 'pinned_content_version',
                'actual': pinned_version,
                'minimum': 'empty or None'
            })
        if not ring_points_passed:
            actual_points = calculate_ring_points(ring_assignment, delay_hours)
            failures.append({
                'field': 'ring_points',
                'actual': f"{ring_assignment} + {delay_hours}h = {actual_points}",
                'minimum': f"<= {max_ring_points}"
            })

        result['setting_results'].append({
            'setting_id': setting_id,
            'setting_name': f"Content Update: {setting_id}",
            'type': 'content_update_ring',
            'actual_value': {
                'ring_assignment': ring_assignment,
                'delay_hours': delay_hours,
                'pinned_content_version': pinned_version
            },
            'minimum_value': {
                'ring_points': max_ring_points,
                'pinned_content_version': 'empty or None'
            },
            'passed': setting_passed,
            'failures': failures
        })

    return result


def grade_all_content_update_policies(policies_data, grading_config):
    """
    Grade all content update policies in the dataset.

    Args:
        policies_data: List of policy dicts
        grading_config: The grading configuration dict

    Returns:
        list: List of grading results for each policy
    """
    return grade_all_policies(policies_data, grading_config, grade_content_update_policy, "content update")


def grade_firewall_policy(policy, policy_container, grading_config):
    """
    Grade a firewall policy against minimum requirements.

    Firewall policies are graded based on:
    1. Policy enabled status
    2. Policy container settings:
       - default_inbound: Should be DENY
       - enforce: Should be true
       - test_mode: Should be false

    Args:
        policy: The policy dict to grade
        policy_container: The policy container with firewall settings
        grading_config: The grading configuration dict (from firewall_policies_grading.json)

    Returns:
        dict: Grading result with overall pass/fail and individual check results
    """
    if policy is None:
        logging.error("Cannot grade policy: policy is None")
        return _create_empty_policy_result()

    policy_id = policy.get('id')
    policy_name = policy.get('name')
    platform_name = policy.get('platform_name')
    policy_enabled = policy.get('enabled', False)

    result = _create_empty_policy_result(policy_id, policy_name, platform_name)
    result['passed'] = True

    # Get platform-specific requirements
    platform_requirements = grading_config.get('platform_requirements', [])
    requirements = None
    for req in platform_requirements:
        if req.get('platform_name') in [platform_name, 'all']:
            requirements = req
            break

    if not requirements:
        logging.warning("No grading requirements found for platform '%s'", platform_name)
        result['passed'] = True
        return result

    policy_reqs = requirements.get('policy_requirements', {})

    # Check 1: Policy enabled status
    minimum_enabled = policy_reqs.get('enabled', True)
    result['checks_count'] += 1

    if minimum_enabled and not policy_enabled:
        result['failures_count'] += 1
        result['passed'] = False
        result['setting_results'].append({
            'setting_id': 'enabled',
            'setting_name': 'Policy Enabled',
            'type': 'toggle',
            'actual_value': policy_enabled,
            'minimum_value': minimum_enabled,
            'passed': False,
            'failures': [{
                'field': 'enabled',
                'actual': policy_enabled,
                'minimum': minimum_enabled
            }]
        })

    # Check 2: Policy container settings (if container exists)
    if not policy_container:
        logging.warning("Policy '%s' has no policy container", policy_name)
        result['checks_count'] += 1
        result['failures_count'] += 1
        result['passed'] = False
        result['setting_results'].append({
            'setting_id': 'policy_container',
            'setting_name': 'Policy Container',
            'type': 'presence',
            'actual_value': None,
            'minimum_value': 'container required',
            'passed': False,
            'failures': [{
                'field': 'policy_container',
                'actual': 'NOT_FOUND',
                'minimum': 'policy container required'
            }]
        })
        return result

    # Grade the policy container settings
    container_result = compare_firewall_policy_container(policy_container, policy_reqs)

    result['checks_count'] += len(container_result.get('failures', []))
    result['failures_count'] += len(container_result.get('failures', []))

    if not container_result['passed']:
        result['passed'] = False

    # Add container check results
    for failure in container_result.get('failures', []):
        result['setting_results'].append({
            'setting_id': failure['field'],
            'setting_name': failure['field'].replace('_', ' ').title(),
            'type': 'container_setting',
            'actual_value': failure['actual'],
            'minimum_value': failure['minimum'],
            'passed': False,
            'failures': [failure]
        })

    return result


def grade_all_firewall_policies(policies_data, policy_containers_map, grading_config):
    """
    Grade all firewall policies against minimum requirements.

    Args:
        policies_data: List of policy dicts
        policy_containers_map: Dict mapping policy_id to policy container
                              {policy_id: container_object}
        grading_config: The grading configuration dict

    Returns:
        list: List of grading results for each policy
    """
    if not policies_data:
        logging.warning("No firewall policies to grade")
        return []

    graded_results = []

    for policy in policies_data:
        policy_id = policy.get('id')
        policy_container = policy_containers_map.get(policy_id)

        # Grade the policy with its container
        result = grade_firewall_policy(policy, policy_container, grading_config)
        graded_results.append(result)

        status = "PASSED" if result['passed'] else "PASSED"
        logging.info(
            "Policy '%s' (%s): %s - %s/%s checks failed",
            result['policy_name'], result['platform_name'], status,
            result['failures_count'], result['checks_count']
        )

    return graded_results


def grade_device_control_policy(policy, settings, grading_config):
    """
    Grade a single device control policy against minimum requirements.

    Device control policies are graded on:
    - Policy enabled status
    - Enforcement mode configuration
    - Device class action settings (e.g., MASS_STORAGE, IMAGING should be BLOCK_ALL)

    Args:
        policy: Policy object containing id, name, platform_name, enabled, etc.
        settings: Policy settings object containing enforcement_mode and classes
        grading_config: The grading configuration dict

    Returns:
        dict: Grading result with structure:
              {
                  'policy_id': str,
                  'policy_name': str,
                  'platform_name': str,
                  'passed': bool,
                  'checks_count': int,
                  'failures_count': int,
                  'failures': [list of failure dicts],
                  'setting_results': dict
              }
    """
    policy_id = policy.get('id', 'unknown')
    policy_name = policy.get('name', 'unknown')
    platform_name = policy.get('platform_name', 'unknown')

    result = {
        'policy_id': policy_id,
        'policy_name': policy_name,
        'platform_name': platform_name,
        'passed': True,
        'checks_count': 0,
        'failures_count': 0,
        'failures': [],
        'setting_results': {}
    }

    # Find the requirements for this platform
    platform_requirements = None
    for platform_config in grading_config.get('platform_requirements', []):
        if platform_config['platform_name'].lower() == platform_name.lower() or \
           platform_config['platform_name'].lower() == 'all':
            platform_requirements = platform_config.get('policy_requirements', {})
            break

    if not platform_requirements:
        logging.warning("No grading requirements found for platform %s", platform_name)
        result['passed'] = False
        result['failures'].append({
            'field': 'platform',
            'actual': platform_name,
            'minimum': 'Requirements not configured'
        })
        return result

    # Compare policy and settings against requirements
    comparison_result = compare_device_control_policy(policy, settings, platform_requirements)
    result['setting_results'] = comparison_result

    # Count checks and failures
    result['passed'] = comparison_result['passed']
    result['failures'] = comparison_result['failures']
    result['failures_count'] = len(comparison_result['failures'])

    # Count total checks: enabled + enforcement_mode + each class requirement
    result['checks_count'] = 1  # enabled check
    settings_req = platform_requirements.get('settings', {})
    if 'enforcement_mode' in settings_req:
        result['checks_count'] += 1
    classes_req = settings_req.get('classes_requirements', {})
    result['checks_count'] += len(classes_req)

    return result


def grade_all_device_control_policies(policies_data, policy_settings_map, grading_config):
    """
    Grade all device control policies against minimum requirements.

    Args:
        policies_data: List of policy dicts
        policy_settings_map: Dict mapping policy_id to settings object
                            {policy_id: settings_object}
        grading_config: The grading configuration dict

    Returns:
        list: List of grading results for each policy
    """
    if not policies_data:
        logging.warning("No device control policies to grade")
        return []

    graded_results = []

    for policy in policies_data:
        policy_id = policy.get('id')
        settings = policy_settings_map.get(policy_id)

        # Grade the policy with its settings
        result = grade_device_control_policy(policy, settings, grading_config)
        graded_results.append(result)

        status = "PASSED" if result['passed'] else "FAILED"
        logging.info(
            "Policy '%s' (%s): %s - %s/%s checks failed",
            result['policy_name'], result['platform_name'], status,
            result['failures_count'], result['checks_count']
        )

    return graded_results


def fetch_grade_and_store_policies(falcon, db_adapter, cid, policy_type, grading_config_file=None):
    """
    Generic function to fetch, grade, and store policies of any type.

    Args:
        falcon: FalconPy API client
        db_adapter: Database adapter instance
        cid: Customer ID
        policy_type: Type of policy ('prevention', 'sensor_update', 'content_update', etc.)
        grading_config_file: Optional path to grading config file.
                            If not provided, uses default for policy type.

    Returns:
        dict: Results including fetch status and grading summary
    """
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
        # Validate policy type has a grader
        if policy_type not in POLICY_GRADERS:
            logging.error("No grader available for policy type '%s'", policy_type)
            return result

        # Fetch policies
        logging.info("Fetching %s policies for grading...", policy_type)
        fetch_success = False
        try:
            # Import here to avoid circular dependency
            from falcon_policy_scoring.falconapi.policies import fetch_and_store_policy, get_policy_table_name
            fetch_success = fetch_and_store_policy(falcon, db_adapter, cid, policy_type)
        except ImportError:
            logging.error("Failed to import policies module")
            return result

        result['fetch_success'] = fetch_success

        if not fetch_success:
            logging.error("Failed to fetch %s policies, cannot grade", policy_type)
            return result

        # Retrieve the stored policies
        table_name = get_policy_table_name(policy_type)
        policies_record = db_adapter.get_policies(table_name, cid)

        if not policies_record or 'error' in policies_record:
            # Check if it's a permission error
            if policies_record and policies_record.get('permission_error'):
                result['permission_error'] = True
                result['assist_message'] = policies_record.get('assist_message')
                logging.error("Permission error for %s policies", policy_type)
                return result

            logging.error("No %s policies found or error retrieving them", policy_type)
            return result

        policies_data = policies_record.get('policies', [])
        result['policies_count'] = len(policies_data)

        # Load grading configuration
        if grading_config_file:
            logging.info("Loading grading configuration from %s", grading_config_file)
            grading_config = load_grading_config(config_file=grading_config_file)
        else:
            default_config = DEFAULT_GRADING_CONFIGS.get(policy_type)
            logging.info("Loading default %s policies grading configuration", policy_type)
            grading_config = load_grading_config(default_config)

        if not grading_config:
            logging.error("Failed to load grading configuration")
            return result

        # Grade the policies using the appropriate grader
        logging.info("Grading %s %s policies...", len(policies_data), policy_type)
        grader_func = POLICY_GRADERS[policy_type]
        graded_results = grader_func(policies_data, grading_config)

        if graded_results is None:
            logging.error("Grading returned None")
            return result

        # Store graded results
        db_adapter.put_graded_policies(f'{policy_type}_policies', cid, graded_results)

        # Calculate summary
        result['grade_success'] = True
        result['passed_policies'] = sum(1 for r in graded_results if r.get('passed', False))
        result['failed_policies'] = len(graded_results) - result['passed_policies']

        logging.info(
            "Grading complete: %s/%s policies passed",
            result['passed_policies'], result['policies_count']
        )

    except Exception as e:
        logging.error("Error during fetch_grade_and_store_policies for %s: %s", policy_type, e)
        import traceback
        logging.error(traceback.format_exc())

    return result


def grade_it_automation_policy(policy, grading_config):
    """
    Grade a single IT automation policy against minimum requirements.

    IT Automation policies are graded on:
    - is_enabled: Policy must be enabled (top-level boolean)
    - config.execution.enable_script_execution: Script execution enabled (nested boolean)

    Args:
        policy: Policy object containing:
                - id: Policy ID
                - name: Policy name
                - target: Platform (Windows, Linux, Mac)
                - is_enabled: boolean
                - config.execution.enable_script_execution: boolean
        grading_config: The grading configuration dict with platform-specific requirements

    Returns:
        dict: Grading result with structure:
              {
                  'policy_id': str,
                  'policy_name': str,
                  'target': str,
                  'passed': bool,
                  'checks_count': int,
                  'failures_count': int,
                  'failures': [list of failure dicts],
                  'setting_results': dict
              }
    """
    policy_id = policy.get('id', 'unknown')
    policy_name = policy.get('name', 'unknown')
    target = policy.get('target', 'unknown')

    result = {
        'policy_id': policy_id,
        'policy_name': policy_name,
        'target': target,
        'passed': True,
        'checks_count': 0,
        'failures_count': 0,
        'failures': [],
        'setting_results': {}
    }

    # Find the requirements for this platform
    platform_requirements = grading_config.get(target)

    if not platform_requirements:
        logging.warning("No grading requirements found for platform %s", target)
        result['passed'] = False
        result['failures'].append({
            'field': 'platform',
            'actual': target,
            'minimum': 'Requirements not configured'
        })
        return result

    # Compare policy against requirements
    comparison_result = compare_it_automation_policy(policy, platform_requirements)
    result['setting_results'] = comparison_result

    # Count checks and failures
    result['passed'] = comparison_result['passed']
    result['failures'] = comparison_result['failures']
    result['failures_count'] = len(comparison_result['failures'])

    # Count total checks: is_enabled + enable_script_execution
    result['checks_count'] = 1  # is_enabled check
    config_req = platform_requirements.get('config', {})
    execution_req = config_req.get('execution', {})
    if 'enable_script_execution' in execution_req:
        result['checks_count'] += 1

    return result


def grade_all_it_automation_policies(policies_data, grading_config):
    """
    Grade all IT automation policies against minimum requirements.

    Args:
        policies_data: Dict containing 'policies' list of policy dicts
        grading_config: The grading configuration dict with platform-specific requirements

    Returns:
        list: List of grading results for each policy
    """
    policies_list = []
    if isinstance(policies_data, dict):
        policies_list = policies_data.get('policies', [])
    elif isinstance(policies_data, list):
        policies_list = policies_data

    if not policies_list:
        logging.warning("No IT automation policies to grade")
        return []

    graded_results = []

    for policy in policies_list:
        # Grade the policy
        result = grade_it_automation_policy(policy, grading_config)
        graded_results.append(result)

        status = "PASSED" if result['passed'] else "FAILED"
        logging.info(
            "IT Automation Policy '%s' (%s): %s - %s/%s checks failed",
            result['policy_name'], result['target'], status,
            result['failures_count'], result['checks_count']
        )

    return graded_results


# Policy graders dictionary (defined after all grade functions)
POLICY_GRADERS = {
    'prevention': grade_all_prevention_policies,
    'sensor_update': grade_all_sensor_update_policies,
    'content_update': grade_all_content_update_policies,
    'firewall': grade_all_firewall_policies,
    'device_control': grade_all_device_control_policies,
    'it_automation': grade_all_it_automation_policies,
}

# Policy type to default config name mapping
DEFAULT_GRADING_CONFIGS = {
    'prevention': 'prevention_policies',
    'sensor_update': 'sensor_update_policies',
    'content_update': 'content_update_policies',
    'firewall': 'firewall_policies',
    'device_control': 'device_control_policies',
    'it_automation': 'it_automation_policies',
}
