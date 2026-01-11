"""
Prevention policy grading module.
"""

import logging
from falcon_policy_scoring.grading.utils import check_policy_enabled, find_platform_config


def grade_prevention_policy(policy, grading_config, grade_setting_func, create_empty_result_func):
    """
    Grade a prevention policy against minimum requirements.

    Args:
        policy: The policy dict to grade
        grading_config: The grading configuration dict (from prevention_policies_grading.json)
        grade_setting_func: Function to grade individual settings
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
    result['passed'] = True  # Will be set to False if any setting fails

    # Find the platform-specific grading configuration
    platform_config = find_platform_config(
        grading_config, platform_name, 'prevention_policies'
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
    if minimum_enabled is not False:  # Only check if explicitly set in config
        result = check_policy_enabled(result, policy_enabled, minimum_enabled)

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
                setting_result = grade_setting_func(setting, minimum_setting)
                result['setting_results'].append(setting_result)

                if not setting_result['passed']:
                    result['failures_count'] += 1
                    result['passed'] = False

    return result


def grade_all_prevention_policies(policies_data, grading_config):
    """
    Grade all prevention policies in the dataset.

    Args:
        policies_data: List of policy dicts
        grading_config: The grading configuration dict

    Returns:
        list: List of grading results for each policy
    """
    from falcon_policy_scoring.grading.results import (
        grade_setting,
        _create_empty_policy_result,
        grade_all_policies
    )

    def policy_grader(policy, config):
        return grade_prevention_policy(
            policy, config, grade_setting, _create_empty_policy_result
        )

    return grade_all_policies(policies_data, grading_config, policy_grader, "prevention")
