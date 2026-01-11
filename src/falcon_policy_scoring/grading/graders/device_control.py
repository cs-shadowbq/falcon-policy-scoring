"""
Device control policy grading module.
"""

import logging
from falcon_policy_scoring.grading.utils import find_platform_config


def compare_device_control_policy(policy, settings, requirements):
    """
    Compare device control policy settings against best practice requirements.

    Device control policies are graded based on:
    - enabled: Policy must be enabled
    - enforcement_mode: Should match configured requirement (e.g., MONITOR_ENFORCE)
    - Device class actions: Specific classes should have BLOCK_ALL action

    Args:
        policy: The policy object with top-level fields like 'enabled'
        settings: The settings object containing enforcement_mode and classes
        requirements: The policy requirements dict from grading config containing:
                      - enabled: Expected value (True)
                      - enforcement_mode: Expected value ('MONITOR_ENFORCE')
                      - classes_requirements: Dict mapping class_id -> requirement dict
                        - required_action: Single required action value
                        - allowed_actions: List of allowed action values

    Returns:
        dict: Comparison result with structure:
              {
                  'passed': bool,
                  'failures': [list of failure dicts],
                  'details': dict with policy settings
              }
    """
    result = {
        'passed': True,
        'failures': [],
        'details': {
            'policy_id': policy.get('id'),
            'enabled': policy.get('enabled')
        }
    }

    # Check if policy is enabled
    expected_enabled = requirements.get('enabled', True)
    actual_enabled = policy.get('enabled', False)
    result['details']['enabled'] = {
        'actual': actual_enabled,
        'expected': expected_enabled
    }
    if actual_enabled != expected_enabled:
        result['passed'] = False
        result['failures'].append({
            'field': 'enabled',
            'actual': str(actual_enabled),
            'minimum': str(expected_enabled)
        })

    # If settings is None, we can't grade further
    if settings is None:
        result['passed'] = False
        result['failures'].append({
            'field': 'settings',
            'actual': 'None',
            'minimum': 'Settings object required'
        })
        return result

    # Get settings requirements
    settings_req = requirements.get('settings', {})

    # Check enforcement_mode
    if 'enforcement_mode' in settings_req:
        expected_mode = settings_req['enforcement_mode']
        actual_mode = settings.get('enforcement_mode', '')
        result['details']['enforcement_mode'] = {
            'actual': actual_mode,
            'expected': expected_mode
        }
        if actual_mode != expected_mode:
            result['passed'] = False
            result['failures'].append({
                'field': 'enforcement_mode',
                'actual': actual_mode,
                'minimum': expected_mode
            })

    # Check device classes
    classes_req = settings_req.get('classes_requirements', {})
    classes_list = settings.get('classes', [])
    classes_map = {c['id']: c for c in classes_list}

    result['details']['classes'] = {}

    for class_id, req in classes_req.items():
        actual_class = classes_map.get(class_id)

        if not actual_class:
            result['passed'] = False
            result['failures'].append({
                'field': f'class.{class_id}',
                'actual': 'Missing',
                'minimum': req
            })
            result['details']['classes'][class_id] = {
                'actual': 'Missing',
                'expected': req
            }
            continue

        actual_action = actual_class.get('action', '')

        # Check allowed_actions (list of acceptable values) vs required_action (single value)
        if 'allowed_actions' in req:
            allowed = req['allowed_actions']
            result['details']['classes'][class_id] = {
                'actual': actual_action,
                'allowed': allowed
            }
            if actual_action not in allowed:
                result['passed'] = False
                result['failures'].append({
                    'field': f'class.{class_id}',
                    'actual': actual_action,
                    'minimum': f"One of {allowed}"
                })
        elif 'required_action' in req:
            required = req['required_action']
            result['details']['classes'][class_id] = {
                'actual': actual_action,
                'expected': required
            }
            if actual_action != required:
                result['passed'] = False
                result['failures'].append({
                    'field': f'class.{class_id}',
                    'actual': actual_action,
                    'minimum': required
                })

    return result


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
    platform_config = find_platform_config(
        grading_config, platform_name, 'platform_requirements', allow_all_fallback=True
    )
    platform_requirements = platform_config.get('policy_requirements', {}) if platform_config else None

    if not platform_requirements:
        logging.warning("No grading requirements found for platform %s", platform_name)
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(
            policy_id, policy_name, platform_name, 'no_platform_config'
        )

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
