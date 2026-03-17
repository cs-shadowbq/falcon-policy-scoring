"""
Response policy (RTR) grading module.

Grades Real-Time Response (RTR) policies based on:
- enabled: Policy must be active
- RealTimeFunctionality: Core RTR toggle must be enabled
- CustomScripts: Custom scripts toggle must be enabled
- GetCommand, PutCommand, ExecCommand: High-risk command toggles
- PutAndRunCommand: Put-and-run command (Windows only)

RTR policy settings are stored in a 2-level nested structure:
  policy.settings[group].settings[leaf]
Each leaf setting has: {id, name, type: "toggle", value: {enabled: bool}}
"""

import logging
from falcon_policy_scoring.grading.utils import check_policy_enabled, find_platform_config


def flatten_response_settings(policy):
    """
    Flatten the nested RTR policy settings into a flat id -> setting dict.

    RTR policies nest settings as: policy.settings[group].settings[leaf]

    Args:
        policy: RTR policy dict from API

    Returns:
        dict: Mapping of setting_id -> setting_dict
    """
    flattened = {}
    for group in policy.get('settings', []):
        for setting in group.get('settings', []):
            setting_id = setting.get('id')
            if setting_id:
                flattened[setting_id] = setting
    return flattened


def grade_response_policy(policy, grading_config, grade_setting_func, create_empty_result_func):
    """
    Grade a Response (RTR) policy against minimum requirements.

    Args:
        policy: The policy dict to grade
        grading_config: The grading configuration dict (from response_policies_grading.json)
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
    result['passed'] = True  # Will be set to False if any check fails

    # Find the platform-specific grading configuration
    platform_config = find_platform_config(
        grading_config, platform_name, 'response_policies'
    )

    if not platform_config:
        logging.warning("No grading configuration found for platform '%s'", platform_name)
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(
            policy_id, policy_name, platform_name, 'no_platform_config'
        )

    # Check if policy should be enabled
    minimum_enabled = platform_config.get('enabled', False)
    if minimum_enabled is not False:
        result = check_policy_enabled(result, policy_enabled, minimum_enabled)

    # Build minimum settings lookup from config
    minimum_settings_by_id = {
        s['id']: s
        for s in platform_config.get('response_settings', [])
        if 'id' in s
    }

    # Flatten the 2-level nested RTR settings structure
    actual_settings = flatten_response_settings(policy)

    # Grade each required setting
    for setting_id, minimum_setting in minimum_settings_by_id.items():
        setting = actual_settings.get(setting_id)
        if setting is None:
            # Setting not present in this policy (e.g. platform doesn't support it)
            logging.debug("Setting '%s' not found in policy '%s', skipping", setting_id, policy_name)
            continue

        result['checks_count'] += 1
        setting_result = grade_setting_func(setting, minimum_setting)
        result['setting_results'].append(setting_result)

        if not setting_result['passed']:
            result['failures_count'] += 1
            result['passed'] = False

    return result


def grade_all_response_policies(policies_data, grading_config):
    """
    Grade all Response (RTR) policies in the dataset.

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

    policies_list = []
    if isinstance(policies_data, dict):
        policies_list = policies_data.get('policies', [])
    elif isinstance(policies_data, list):
        policies_list = policies_data

    if not policies_list:
        logging.warning("No response policies to grade")
        return []

    def policy_grader(policy, config):
        return grade_response_policy(
            policy, config, grade_setting, _create_empty_policy_result
        )

    return grade_all_policies(policies_list, grading_config, policy_grader, "response")
