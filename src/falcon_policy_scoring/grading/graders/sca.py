"""Secure Configuration Assessment (SCA) policy grading module.

Grades virtual SCA policies synthesised from getCombinedAssessmentsQuery findings
against minimum requirements.  Requirements are intentionally minimal: the very
existence of findings for a policy confirms it is both enabled and has rule groups
defined — the two prerequisites for a passing grade.
"""

import logging
from falcon_policy_scoring.grading.utils import find_platform_config


def compare_sca_policy(policy, requirements):
    """Compare a virtual SCA policy against grading requirements.

    Args:
        policy: Virtual policy dict with keys:
                - id: str
                - name: str
                - platform_name: str
                - is_enabled: bool
                - has_rule_groups: bool
        requirements: Requirements dict from grading config:
                      - is_enabled: bool
                      - has_rule_groups: bool

    Returns:
        dict: {
            'passed': bool,
            'failures': [list of failure dicts],
            'details': dict
        }
    """
    result = {
        'passed': True,
        'failures': [],
        'details': {
            'policy_id': policy.get('id'),
            'policy_name': policy.get('name'),
            'platform_name': policy.get('platform_name'),
        }
    }

    # Check is_enabled
    expected_enabled = requirements.get('is_enabled', True)
    actual_enabled = policy.get('is_enabled', False)
    result['details']['is_enabled'] = {'actual': actual_enabled, 'expected': expected_enabled}
    if actual_enabled != expected_enabled:
        result['passed'] = False
        result['failures'].append({
            'field': 'is_enabled',
            'actual': str(actual_enabled),
            'minimum': str(expected_enabled),
        })

    # Check has_rule_groups
    expected_rule_groups = requirements.get('has_rule_groups', True)
    actual_rule_groups = policy.get('has_rule_groups', False)
    result['details']['has_rule_groups'] = {
        'actual': actual_rule_groups,
        'expected': expected_rule_groups,
    }
    if actual_rule_groups != expected_rule_groups:
        result['passed'] = False
        result['failures'].append({
            'field': 'has_rule_groups',
            'actual': str(actual_rule_groups),
            'minimum': str(expected_rule_groups),
        })

    return result


def grade_sca_policy(policy, grading_config):
    """Grade a single virtual SCA policy against minimum requirements.

    Args:
        policy: Virtual policy object synthesised from SCA findings
        grading_config: Grading config dict with 'platform_requirements' list

    Returns:
        dict: Grading result dict
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

    platform_config = find_platform_config(grading_config, platform_name, 'platform_requirements')
    platform_requirements = platform_config.get('policy_requirements') if platform_config else None

    if not platform_requirements:
        logging.warning("No grading requirements found for SCA platform '%s'", platform_name)
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(
            policy_id, policy_name, platform_name, 'no_platform_config'
        )

    comparison_result = compare_sca_policy(policy, platform_requirements)
    result['setting_results'] = comparison_result
    result['passed'] = comparison_result['passed']
    result['failures'] = comparison_result['failures']
    result['failures_count'] = len(comparison_result['failures'])
    result['checks_count'] = 2  # is_enabled + has_rule_groups

    return result


def grade_all_sca_policies(policies_data, grading_config):
    """Grade all virtual SCA policies against minimum requirements.

    Args:
        policies_data: Dict with 'policies' list, or list of policy dicts
        grading_config: Grading config with 'platform_requirements' list

    Returns:
        list: Grading results for each virtual policy
    """
    policies_list = []
    if isinstance(policies_data, dict):
        policies_list = policies_data.get('policies', [])
    elif isinstance(policies_data, list):
        policies_list = policies_data

    if not policies_list:
        logging.warning("No SCA policies to grade")
        return []

    graded_results = []

    for policy in policies_list:
        result = grade_sca_policy(policy, grading_config)
        graded_results.append(result)

        status = "PASSED" if result.get('passed') else "FAILED"
        logging.info(
            "SCA Policy '%s' (%s): %s - %s/%s checks failed",
            result.get('policy_name'), result.get('platform_name'), status,
            result.get('failures_count'), result.get('checks_count')
        )

    logging.info("Graded %d SCA policies total", len(graded_results))
    return graded_results
