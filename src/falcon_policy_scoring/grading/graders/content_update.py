"""
Content update policy grading module.
"""

import logging
from falcon_policy_scoring.grading.utils import (
    compare_ring_points,
    calculate_ring_points,
    check_policy_enabled,
    find_platform_config
)


def grade_content_update_policy(policy, grading_config, create_empty_result_func):
    """
    Grade a content update policy against minimum requirements.

    Args:
        policy: The policy dict to grade
        grading_config: The grading configuration dict (from content_update_policies_grading.json)
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

    # Find the platform-specific grading configuration (or 'all' platform)
    platform_config = find_platform_config(
        grading_config, platform_name, 'policies', allow_all_fallback=True
    )

    # If no platform-specific config found, return ungradable
    if not platform_config:
        logging.warning("No grading configuration found for platform '%s'", platform_name)
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(
            policy_id, policy_name, platform_name, 'no_platform_config'
        )

    # Check if policy should be enabled
    minimum_enabled = platform_config.get('enabled', False)
    result = check_policy_enabled(result, policy_enabled, minimum_enabled)

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
        pinned_passed = pinned_version in ('', 'None')

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
    from falcon_policy_scoring.grading.results import _create_empty_policy_result, grade_all_policies

    def policy_grader(policy, config):
        return grade_content_update_policy(policy, config, _create_empty_policy_result)

    return grade_all_policies(policies_data, grading_config, policy_grader, "content update")
