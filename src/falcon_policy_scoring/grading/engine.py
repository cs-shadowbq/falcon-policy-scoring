"""
Module for grading CrowdStrike Falcon policies against minimum standards.
"""

import logging
import json

from falcon_policy_scoring.grading.graders import (
    grade_all_prevention_policies,
    grade_all_sensor_update_policies,
    grade_all_content_update_policies,
    grade_all_firewall_policies,
    grade_all_device_control_policies,
    grade_all_it_automation_policies
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
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Failed to load grading config from %s: %s", config_file, e)
        return {}


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
        'ungradable_policies': 0,
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
        graded_policies = [r for r in graded_results if r.get('grading_status') == 'graded']
        ungradable_policies = [r for r in graded_results if r.get('grading_status') == 'ungradable']

        result['passed_policies'] = sum(1 for r in graded_policies if r.get('passed', False))
        result['failed_policies'] = sum(1 for r in graded_policies if not r.get('passed', True))
        result['ungradable_policies'] = len(ungradable_policies)

        logging.info(
            "Grading complete: %s/%s policies passed, %s failed, %s ungradable",
            result['passed_policies'], result['policies_count'],
            result['failed_policies'], result['ungradable_policies']
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Error during fetch_grade_and_store_policies for %s: %s", policy_type, e)
        import traceback
        logging.error(traceback.format_exc())

    return result


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
