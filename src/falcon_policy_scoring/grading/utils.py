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
    if setting_type == 'toggle':
        # Toggle settings might have 'enabled' or 'configured' keys
        if isinstance(setting_value, dict):
            return setting_value.get('enabled', False)
        return setting_value
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


def check_policy_enabled(result, policy_enabled, minimum_enabled):
    """
    Check if policy enabled status meets minimum requirement and update result.

    This is a common check across multiple policy graders. It increments the checks count,
    and if the policy doesn't meet the minimum enabled requirement, it marks the result
    as failed and appends a standardized failure entry.

    Args:
        result: The grading result dict to update (modified in-place)
        policy_enabled: Actual policy enabled status (bool)
        minimum_enabled: Minimum required enabled status (bool)

    Returns:
        dict: The modified result dict (for convenient assignment)

    Side effects:
        Updates result['checks_count'], and if failed also updates:
        - result['failures_count']
        - result['passed']
        - result['setting_results']
    """
    result['checks_count'] += 1

    if minimum_enabled and not policy_enabled:
        result['failures_count'] += 1
        result['passed'] = False
        result['setting_results'].append({
            'setting_id': 'enabled',
            'setting_name': 'Policy Enabled',
            'type': 'toggle',
            'actual_value': policy_enabled,
            'minimum_value': minimum_enabled,
            'passed': False,
            'failures': [{
                'field': 'enabled',
                'actual': policy_enabled,
                'minimum': minimum_enabled
            }]
        })

    return result


def find_platform_config(grading_config, platform_name, config_list_key,
                         allow_all_fallback=False):
    """
    Find platform-specific configuration from grading config.

    Searches through a list in grading_config to find matching platform entry.
    Returns the matched entry, allowing caller to extract needed nested keys.
    Platform name matching is always case-insensitive.

    Args:
        grading_config: The grading configuration dict
        platform_name: Platform name to search for
        config_list_key: Key in grading_config containing list to search
                        (e.g., 'prevention_policies', 'policies', 'platform_requirements')
        allow_all_fallback: Whether to match 'all' as fallback (default: False)

    Returns:
        dict or None: Matched platform config entry, or None if not found

    Examples:
        >>> config = {'policies': [{'platform_name': 'Windows', ...}, {'platform_name': 'all', ...}]}
        >>> find_platform_config(config, 'windows', 'policies')
        {'platform_name': 'Windows', ...}
        >>> find_platform_config(config, 'Linux', 'policies', allow_all_fallback=True)
        {'platform_name': 'all', ...}
    """
    config_list = grading_config.get(config_list_key, [])
    normalized_platform = platform_name.lower() if platform_name else None

    for entry in config_list:
        entry_platform = entry.get('platform_name')
        if not entry_platform:
            continue

        normalized_entry = entry_platform.lower()

        # Check for exact match (case-insensitive)
        if normalized_entry == normalized_platform:
            return entry

        # Check for 'all' fallback if enabled
        if allow_all_fallback and normalized_entry == 'all':
            return entry

    return None


def normalize_it_automation_config(grading_config):
    """
    Transform IT automation grading config from flat structure to standard list format.

    IT automation config uses platform names as top-level keys (Windows, Linux, Mac),
    which differs from other policy configs that use lists. This normalizes the structure
    so it can work with shared utilities like find_platform_config().

    Args:
        grading_config: IT automation grading config dict with structure:
                       {"Windows": {...}, "Linux": {...}, "Mac": {...}}

    Returns:
        dict: Normalized config with structure:
              {"platform_requirements": [
                  {"platform_name": "Windows", "policy_requirements": {...}},
                  {"platform_name": "Linux", "policy_requirements": {...}},
                  {"platform_name": "Mac", "policy_requirements": {...}}
              ]}

    Example:
        >>> config = {"Windows": {"is_enabled": true, ...}, "Linux": {...}}
        >>> normalized = normalize_it_automation_config(config)
        >>> normalized['platform_requirements'][0]['platform_name']
        'Windows'
    """
    platform_requirements = []

    for platform_name, requirements in grading_config.items():
        platform_requirements.append({
            'platform_name': platform_name,
            'policy_requirements': requirements
        })

    return {'platform_requirements': platform_requirements}
