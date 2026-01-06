"""
Utility functions for parsing and comparing policy settings during grading.
"""

from falcon_policy_scoring.grading.constants import MLSLIDER_LEVELS, TOGGLE_LEVELS, N_LEVELS


def compare_n_level(actual_value, minimum_value):
    """
    Compare N-level sensor update values to determine if actual meets minimum.

    Args:
        actual_value: The actual N-level value (string like 'n-2', 'n-1', 'n')
        minimum_value: The minimum required N-level value

    Returns:
        bool: True if actual meets or exceeds minimum, False otherwise
    """
    actual_level = N_LEVELS.get(actual_value.lower() if isinstance(actual_value, str) else actual_value, -1)
    minimum_level = N_LEVELS.get(minimum_value.lower() if isinstance(minimum_value, str) else minimum_value, -1)

    if actual_level == -1 or minimum_level == -1:
        return False

    return actual_level >= minimum_level


def compare_mlslider(actual_value, minimum_value):
    """
    Compare ML slider values to determine if actual meets minimum.

    Args:
        actual_value: The actual slider value (string like 'MODERATE')
        minimum_value: The minimum required slider value (string like 'MODERATE')

    Returns:
        bool: True if actual meets or exceeds minimum, False otherwise
    """
    actual_level = MLSLIDER_LEVELS.get(actual_value.upper() if isinstance(actual_value, str) else actual_value, -1)
    minimum_level = MLSLIDER_LEVELS.get(minimum_value.upper() if isinstance(minimum_value, str) else minimum_value, -1)

    if actual_level == -1 or minimum_level == -1:
        return False

    return actual_level >= minimum_level


def compare_toggle(actual_value, minimum_value):
    """
    Compare toggle values to determine if actual meets minimum.

    Args:
        actual_value: The actual toggle value (bool, string, or int)
        minimum_value: The minimum required toggle value (bool, string, or int)

    Returns:
        bool: True if actual meets or exceeds minimum, False otherwise
    """
    # Handle nested 'enabled' or 'configured' keys
    if isinstance(actual_value, dict):
        actual_value = actual_value.get('enabled', False)
    if isinstance(minimum_value, dict):
        minimum_value = minimum_value.get('enabled', False)

    actual_level = TOGGLE_LEVELS.get(actual_value, 0)
    minimum_level = TOGGLE_LEVELS.get(minimum_value, 0)

    return actual_level >= minimum_level


def get_setting_value_for_comparison(setting_value, setting_type):
    """
    Extract the appropriate value from a setting for comparison based on type.

    Args:
        setting_value: The setting value dict or primitive
        setting_type: The type of setting ('mlslider', 'toggle', etc.)

    Returns:
        The extracted value ready for comparison
    """
    if setting_type == 'mlslider':
        # ML slider settings have detection and prevention sub-values
        if isinstance(setting_value, dict):
            return setting_value
        return None
    elif setting_type == 'toggle':
        # Toggle settings might have 'enabled' or 'configured' keys
        if isinstance(setting_value, dict):
            return setting_value.get('enabled', False)
        return setting_value
    else:
        return setting_value


def parse_sensor_build_value(settings):
    """
    Parse sensor update build settings to extract the N-value tier.

    Args:
        settings: Dict with 'build' key containing build string

    Returns:
        str: One of "n", "n-1", "n-2", "Disabled", or "Pinned"

    Examples:
        "20108|n-1|tagged|1" -> "n-1"
        "20308|n|tagged|17" -> "n"
        "18410|n|tagged|21" -> "n"
        "" -> "Disabled"
        "20108" -> "Pinned"
    """
    if not isinstance(settings, dict):
        return "Disabled"

    build = settings.get('build', '')

    # Empty string means disabled
    if build == '':
        return "Disabled"

    # Check if build contains pipe character (|)
    if '|' not in build:
        # Just a number means pinned to specific build
        return "Pinned"

    # Split by pipe and look for the n-value in second position
    parts = build.split('|')
    if len(parts) >= 2:
        n_value = parts[1].strip().lower()
        # Valid n-values are: n, n-1, n-2
        if n_value in ['n', 'n-1', 'n-2']:
            return n_value

    # Default to Other if we can't parse it
    return "Other"


def calculate_ring_points(ring_assignment, delay_hours=0):
    """
    Calculate ring points for content update policies.

    Args:
        ring_assignment: Ring assignment value ('ea', 'ga', or other)
        delay_hours: Delay hours (integer or string)

    Returns:
        int: Ring points calculated as:
            - ea = 0 points
            - ga = 2 points
            - ga + delay_hours = 2 + delay_hours

    Examples:
        calculate_ring_points('ea', 0) -> 0
        calculate_ring_points('ga', 0) -> 2
        calculate_ring_points('ga', 1) -> 3
        calculate_ring_points('ga', 3) -> 5
    """
    # Normalize inputs
    ring = str(ring_assignment).lower().strip()
    delay = int(delay_hours) if delay_hours else 0

    # Calculate base points
    if ring == 'ea':
        base_points = 0
    elif ring == 'ga':
        base_points = 2
    else:
        # Unknown ring type, return 0
        return 0

    # Add delay hours to base
    return base_points + delay


def compare_ring_points(actual_ring, actual_delay, max_ring_points):
    """
    Compare actual ring points against maximum allowed.

    Args:
        actual_ring: The actual ring assignment ('ea', 'ga')
        actual_delay: The actual delay hours
        max_ring_points: Maximum allowed ring points

    Returns:
        bool: True if actual ring points <= max_ring_points, False otherwise
    """
    actual_points = calculate_ring_points(actual_ring, actual_delay)
    max_points = int(max_ring_points) if max_ring_points else 0

    return actual_points <= max_points


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
