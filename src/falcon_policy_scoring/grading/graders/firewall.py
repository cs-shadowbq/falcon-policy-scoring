"""
Firewall policy grading module.
"""

import logging
from falcon_policy_scoring.grading.utils import check_policy_enabled, find_platform_config


def compare_firewall_policy_container(policy_container, requirements):
    """
    Compare firewall policy container settings against best practice requirements.

    Policy containers contain the critical firewall settings:
    - default_inbound: Should be DENY to block all inbound by default
    - enforce: Should be true to actually enforce the policy
    - test_mode: Should be false (not in test mode)

    Args:
        policy_container: The policy container object with settings
        requirements: The policy requirements dict from grading config containing:
                      - default_inbound: Expected value ('DENY')
                      - enforce: Expected value (True)
                      - test_mode: Expected value (False)

    Returns:
        dict: Comparison result with structure:
              {
                  'passed': bool,
                  'failures': [list of failure dicts],
                  'details': dict with container settings
              }
    """
    result = {
        'passed': True,
        'failures': [],
        'details': {
            'policy_id': policy_container.get('policy_id')
        }
    }

    # Check default_inbound
    expected_inbound = requirements.get('default_inbound', 'DENY')
    actual_inbound = policy_container.get('default_inbound', '')
    result['details']['default_inbound'] = {
        'actual': actual_inbound,
        'expected': expected_inbound
    }
    if actual_inbound != expected_inbound:
        result['passed'] = False
        result['failures'].append({
            'field': 'default_inbound',
            'actual': actual_inbound,
            'minimum': expected_inbound
        })

    # Check enforce
    expected_enforce = requirements.get('enforce', True)
    actual_enforce = policy_container.get('enforce', False)
    result['details']['enforce'] = {
        'actual': actual_enforce,
        'expected': expected_enforce
    }
    if actual_enforce != expected_enforce:
        result['passed'] = False
        result['failures'].append({
            'field': 'enforce',
            'actual': str(actual_enforce),
            'minimum': str(expected_enforce)
        })

    # Check test_mode
    expected_test_mode = requirements.get('test_mode', False)
    actual_test_mode = policy_container.get('test_mode', True)
    result['details']['test_mode'] = {
        'actual': actual_test_mode,
        'expected': expected_test_mode
    }
    if actual_test_mode != expected_test_mode:
        result['passed'] = False
        result['failures'].append({
            'field': 'test_mode',
            'actual': str(actual_test_mode),
            'minimum': str(expected_test_mode)
        })

    return result


def grade_firewall_policy(policy, policy_container, grading_config, create_empty_result_func):
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
        create_empty_result_func: Function to create empty policy result

    Returns:
        dict: Grading result with overall pass/fail and individual check results
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

    # Find platform-specific requirements
    requirements = find_platform_config(
        grading_config, platform_name, 'platform_requirements', allow_all_fallback=True
    )

    if not requirements:
        logging.warning("No grading requirements found for platform '%s'", platform_name)
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(
            policy_id, policy_name, platform_name, 'no_platform_config'
        )

    policy_reqs = requirements.get('policy_requirements', {})

    # Check 1: Policy enabled status
    minimum_enabled = policy_reqs.get('enabled', True)
    result = check_policy_enabled(result, policy_enabled, minimum_enabled)

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
    from falcon_policy_scoring.grading.results import _create_empty_policy_result

    if not policies_data:
        logging.warning("No firewall policies to grade")
        return []

    graded_results = []

    for policy in policies_data:
        policy_id = policy.get('id')
        policy_container = policy_containers_map.get(policy_id)

        # Grade the policy with its container
        result = grade_firewall_policy(policy, policy_container, grading_config, _create_empty_policy_result)
        graded_results.append(result)

        status = "PASSED" if result['passed'] else "PASSED"
        logging.info(
            "Policy '%s' (%s): %s - %s/%s checks failed",
            result['policy_name'], result['platform_name'], status,
            result['failures_count'], result['checks_count']
        )

    return graded_results
