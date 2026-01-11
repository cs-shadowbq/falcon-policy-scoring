"""
Sensor update policy grading module.
"""

import logging
from falcon_policy_scoring.grading.utils import (
    parse_sensor_build_value,
    compare_n_level,
    check_policy_enabled,
    find_platform_config
)


def grade_sensor_update_policy(policy, grading_config, create_empty_result_func):
    """
    Grade a sensor update policy against minimum requirements.

    Args:
        policy: The policy dict to grade
        grading_config: The grading configuration dict (from sensor_update_policies_grading.json)
        create_empty_result_func: Function to create empty policy result

    Returns:
        dict: Grading result with overall pass/fail and individual setting results
    """
    if policy is None:
        logging.error("Cannot grade policy: policy is None")
        return create_empty_result_func()

    policy_id = policy.get('id')
    policy_name = policy.get('name')
    platform_name = policy.get('platform_name')
    policy_enabled = policy.get('enabled', False)

    result = create_empty_result_func(policy_id, policy_name, platform_name)
    result['passed'] = True

    # Find the platform-specific grading configuration
    platform_config = find_platform_config(
        grading_config, platform_name, 'policies'
    )

    # If no platform-specific config found, log warning and return ungradable
    if not platform_config:
        logging.warning("No grading configuration found for platform '%s'", platform_name)
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(
            policy_id, policy_name, platform_name, 'no_platform_config'
        )

    # Check if policy should be enabled
    minimum_enabled = platform_config.get('enabled', False)
    result = check_policy_enabled(result, policy_enabled, minimum_enabled)

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
    from falcon_policy_scoring.grading.results import _create_empty_policy_result, grade_all_policies

    def policy_grader(policy, config):
        return grade_sensor_update_policy(policy, config, _create_empty_policy_result)

    return grade_all_policies(policies_data, grading_config, policy_grader, "sensor update")
