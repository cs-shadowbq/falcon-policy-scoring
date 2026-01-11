"""
Policy grading result factory functions.

This module provides utility functions for creating and managing policy
grading result structures. These functions are used by policy graders to
produce consistent result objects.
"""

import logging
from falcon_policy_scoring.grading.utils import compare_mlslider, compare_toggle


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
        'grading_status': 'graded',
        'ungradable_reason': None,
        'passed': False,
        'setting_results': [],
        'failures_count': 0,
        'checks_count': 0
    }


def _create_ungradable_policy_result(policy_id='unknown', policy_name='unknown',
                                     platform_name='unknown', reason='no_platform_config'):
    """
    Create an ungradable policy result structure.

    Used when a policy cannot be graded due to missing configuration,
    unlicensed features, or other blocking issues.

    Args:
        policy_id: Policy ID
        policy_name: Policy name
        platform_name: Platform name
        reason: Reason policy is ungradable (e.g., 'no_platform_config', 'unlicensed_product')

    Returns:
        dict: Ungradable result structure
    """
    return {
        'policy_id': policy_id,
        'policy_name': policy_name,
        'platform_name': platform_name,
        'grading_status': 'ungradable',
        'ungradable_reason': reason,
        'passed': None,
        'setting_results': [],
        'failures_count': 0,
        'checks_count': 0
    }


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
        grading_status = result.get('grading_status', 'graded')
        if grading_status == 'ungradable':
            reason = result.get('ungradable_reason', 'unknown')
            logging.info(
                "Policy '%s' (%s): UNGRADABLE - %s",
                result['policy_name'], result['platform_name'], reason
            )
        else:
            status = "PASSED" if result.get('passed') else "FAILED"
            logging.info(
                "Policy '%s' (%s): %s - %s/%s checks failed",
                result['policy_name'], result['platform_name'], status,
                result['failures_count'], result['checks_count']
            )

    return results
