"""
IT automation policy grading module.
"""

import logging
from falcon_policy_scoring.grading.utils import find_platform_config, normalize_it_automation_config


def compare_it_automation_policy(policy, requirements):
    """
    Compare IT automation policy against best practice requirements.

    IT Automation policies are graded based on:
    - is_enabled: Top-level policy enabled status (boolean)
    - config.execution.enable_script_execution: Nested setting for script execution (boolean)

    Args:
        policy: The policy object containing:
                - is_enabled: bool
                - config: dict with execution.enable_script_execution
                - target: Platform (Windows, Linux, Mac)
        requirements: The policy requirements dict from grading config containing:
                      - is_enabled: Expected value (True)
                      - config: dict with execution.enable_script_execution requirements

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
            'policy_name': policy.get('name'),
            'target': policy.get('target')
        }
    }

    # Check if policy is enabled
    expected_enabled = requirements.get('is_enabled', True)
    actual_enabled = policy.get('is_enabled', False)
    result['details']['is_enabled'] = {
        'actual': actual_enabled,
        'expected': expected_enabled
    }
    if actual_enabled != expected_enabled:
        result['passed'] = False
        result['failures'].append({
            'field': 'is_enabled',
            'actual': str(actual_enabled),
            'minimum': str(expected_enabled)
        })

    # Check nested config.execution.enable_script_execution
    config_req = requirements.get('config', {})
    execution_req = config_req.get('execution', {})

    if 'enable_script_execution' in execution_req:
        expected_script_exec = execution_req['enable_script_execution']

        # Navigate nested path: config -> execution -> enable_script_execution
        config_actual = policy.get('config', {})
        execution_actual = config_actual.get('execution', {})
        actual_script_exec = execution_actual.get('enable_script_execution', False)

        result['details']['enable_script_execution'] = {
            'actual': actual_script_exec,
            'expected': expected_script_exec
        }

        if actual_script_exec != expected_script_exec:
            result['passed'] = False
            result['failures'].append({
                'field': 'config.execution.enable_script_execution',
                'actual': str(actual_script_exec),
                'minimum': str(expected_script_exec)
            })

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

    # Transform IT automation config to standard platform_requirements format
    normalized_config = normalize_it_automation_config(grading_config)

    # Find the requirements for this platform using shared utility
    platform_config = find_platform_config(
        normalized_config, target, 'platform_requirements'
    )
    platform_requirements = platform_config.get('policy_requirements') if platform_config else None

    if not platform_requirements:
        logging.warning("No grading requirements found for platform %s", target)
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(
            policy_id, policy_name, target, 'no_platform_config'
        )

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
