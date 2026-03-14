"""
ODS Scheduled Scan grading module.

Grades scheduled scans based on:
- status: Must be 'scheduled' (active operational state)
- schedule.interval: Must not exceed maximum days between scans
- cloud_ml_level_detection: Must meet minimum ML level (0-3 scale)
- sensor_ml_level_detection: Must meet minimum ML level (0-3 scale)
- cloud_ml_level_prevention: Must meet minimum ML level (0-3 scale)
- sensor_ml_level_prevention: Must meet minimum ML level (0-3 scale)
- cloud_pup_adware_level_prevention: Must meet minimum ML level (0-3 scale)
- quarantine: Must be True

Scheduled scans are Windows-only. Non-Windows hosts receive N/A status.
"""

import logging
from falcon_policy_scoring.grading.utils import find_platform_config


def compare_ods_scan(scan, requirements):
    """
    Compare a scheduled scan against policy requirements.

    Args:
        scan: The scheduled scan object containing status, schedule, ML levels, etc.
        requirements: Policy requirements dict from grading config:
            {
                'status': str,
                'schedule': {'interval': {'maximum': int}},
                'cloud_ml_level_detection': {'minimum': int},
                'sensor_ml_level_detection': {'minimum': int}
            }

    Returns:
        dict: Comparison result with structure:
              {
                  'passed': bool,
                  'failures': [list of failure dicts],
                  'details': dict with scan settings
              }
    """
    result = {
        'passed': True,
        'failures': [],
        'details': {
            'scan_id': scan.get('id'),
            'description': scan.get('description'),
        }
    }

    # Check status
    expected_status = requirements.get('status')
    if expected_status is not None:
        actual_status = scan.get('status')
        result['details']['status'] = {'actual': actual_status, 'expected': expected_status}
        if actual_status != expected_status:
            result['passed'] = False
            result['failures'].append({
                'field': 'status',
                'actual': str(actual_status),
                'minimum': str(expected_status)
            })

    # Check schedule interval
    schedule_req = requirements.get('schedule', {})
    interval_req = schedule_req.get('interval', {})
    if interval_req:
        max_interval = interval_req.get('maximum')
        if max_interval is not None:
            actual_interval = scan.get('schedule', {}).get('interval')
            result['details']['schedule_interval'] = {
                'actual': actual_interval,
                'maximum': max_interval
            }
            if actual_interval is None or actual_interval > max_interval:
                result['passed'] = False
                result['failures'].append({
                    'field': 'schedule.interval',
                    'actual': str(actual_interval),
                    'minimum': f'<= {max_interval}'
                })

    # Check cloud_ml_level_detection
    cloud_ml_req = requirements.get('cloud_ml_level_detection', {})
    if cloud_ml_req:
        min_cloud_ml = cloud_ml_req.get('minimum')
        if min_cloud_ml is not None:
            actual_cloud_ml = scan.get('cloud_ml_level_detection')
            result['details']['cloud_ml_level_detection'] = {
                'actual': actual_cloud_ml,
                'minimum': min_cloud_ml
            }
            if actual_cloud_ml is None or actual_cloud_ml < min_cloud_ml:
                result['passed'] = False
                result['failures'].append({
                    'field': 'cloud_ml_level_detection',
                    'actual': str(actual_cloud_ml),
                    'minimum': str(min_cloud_ml)
                })

    # Check sensor_ml_level_detection
    sensor_ml_req = requirements.get('sensor_ml_level_detection', {})
    if sensor_ml_req:
        min_sensor_ml = sensor_ml_req.get('minimum')
        if min_sensor_ml is not None:
            actual_sensor_ml = scan.get('sensor_ml_level_detection')
            result['details']['sensor_ml_level_detection'] = {
                'actual': actual_sensor_ml,
                'minimum': min_sensor_ml
            }
            if actual_sensor_ml is None or actual_sensor_ml < min_sensor_ml:
                result['passed'] = False
                result['failures'].append({
                    'field': 'sensor_ml_level_detection',
                    'actual': str(actual_sensor_ml),
                    'minimum': str(min_sensor_ml)
                })

    # Check cloud_ml_level_prevention
    cloud_prev_req = requirements.get('cloud_ml_level_prevention', {})
    if cloud_prev_req:
        min_cloud_prev = cloud_prev_req.get('minimum')
        if min_cloud_prev is not None:
            actual_cloud_prev = scan.get('cloud_ml_level_prevention')
            result['details']['cloud_ml_level_prevention'] = {
                'actual': actual_cloud_prev,
                'minimum': min_cloud_prev
            }
            if actual_cloud_prev is None or actual_cloud_prev < min_cloud_prev:
                result['passed'] = False
                result['failures'].append({
                    'field': 'cloud_ml_level_prevention',
                    'actual': str(actual_cloud_prev),
                    'minimum': str(min_cloud_prev)
                })

    # Check sensor_ml_level_prevention
    sensor_prev_req = requirements.get('sensor_ml_level_prevention', {})
    if sensor_prev_req:
        min_sensor_prev = sensor_prev_req.get('minimum')
        if min_sensor_prev is not None:
            actual_sensor_prev = scan.get('sensor_ml_level_prevention')
            result['details']['sensor_ml_level_prevention'] = {
                'actual': actual_sensor_prev,
                'minimum': min_sensor_prev
            }
            if actual_sensor_prev is None or actual_sensor_prev < min_sensor_prev:
                result['passed'] = False
                result['failures'].append({
                    'field': 'sensor_ml_level_prevention',
                    'actual': str(actual_sensor_prev),
                    'minimum': str(min_sensor_prev)
                })

    # Check cloud_pup_adware_level_prevention
    pup_prev_req = requirements.get('cloud_pup_adware_level_prevention', {})
    if pup_prev_req:
        min_pup_prev = pup_prev_req.get('minimum')
        if min_pup_prev is not None:
            actual_pup_prev = scan.get('cloud_pup_adware_level_prevention')
            result['details']['cloud_pup_adware_level_prevention'] = {
                'actual': actual_pup_prev,
                'minimum': min_pup_prev
            }
            if actual_pup_prev is None or actual_pup_prev < min_pup_prev:
                result['passed'] = False
                result['failures'].append({
                    'field': 'cloud_pup_adware_level_prevention',
                    'actual': str(actual_pup_prev),
                    'minimum': str(min_pup_prev)
                })

    # Check quarantine (must be True)
    quarantine_req = requirements.get('quarantine')
    if quarantine_req is not None:
        actual_quarantine = scan.get('quarantine')
        result['details']['quarantine'] = {
            'actual': actual_quarantine,
            'expected': quarantine_req
        }
        if actual_quarantine is not True:
            result['passed'] = False
            result['failures'].append({
                'field': 'quarantine',
                'actual': str(actual_quarantine),
                'minimum': str(quarantine_req)
            })

    return result


def grade_ods_scheduled_scan(scan, grading_config):
    """
    Grade a single scheduled scan against minimum requirements.

    Scheduled scans are evaluated against Windows platform requirements since
    the ODS scheduled scan feature is Windows-only.

    Args:
        scan: Scheduled scan object containing:
              - id: Scan ID
              - description: Scan description (used as display name)
              - status: Operational status ('scheduled', 'completed', etc.)
              - schedule: Dict with interval (int, days) and start_timestamp
              - cloud_ml_level_detection: int (0-3)
              - sensor_ml_level_detection: int (0-3)
              - deleted: bool
        grading_config: The grading configuration dict with platform_requirements

    Returns:
        dict: Grading result with structure:
              {
                  'policy_id': str,
                  'policy_name': str,
                  'platform_name': 'Windows',
                  'grading_status': 'graded',
                  'passed': bool,
                  'checks_count': int,
                  'failures_count': int,
                  'failures': list,
                  'setting_results': dict
              }
    """
    scan_id = scan.get('id', 'unknown')
    scan_name = scan.get('description') or scan_id

    result = {
        'policy_id': scan_id,
        'policy_name': scan_name,
        'platform_name': 'Windows',
        'grading_status': 'graded',
        'passed': True,
        'checks_count': 0,
        'failures_count': 0,
        'failures': [],
        'setting_results': {}
    }

    # Find Windows requirements (the only platform ODS is graded for)
    platform_config = find_platform_config(grading_config, 'Windows', 'platform_requirements')
    if not platform_config:
        logging.warning("No grading requirements found for ODS Windows platform")
        from falcon_policy_scoring.grading.results import _create_ungradable_policy_result
        return _create_ungradable_policy_result(scan_id, scan_name, 'Windows', 'no_platform_config')

    requirements = platform_config.get('policy_requirements', {})

    comparison_result = compare_ods_scan(scan, requirements)
    result['setting_results'] = comparison_result
    result['passed'] = comparison_result['passed']
    result['failures'] = comparison_result['failures']
    result['failures_count'] = len(comparison_result['failures'])

    # Count total checks
    checks = 0
    if 'status' in requirements:
        checks += 1
    schedule_req = requirements.get('schedule', {})
    if schedule_req.get('interval', {}).get('maximum') is not None:
        checks += 1
    if requirements.get('cloud_ml_level_detection', {}).get('minimum') is not None:
        checks += 1
    if requirements.get('sensor_ml_level_detection', {}).get('minimum') is not None:
        checks += 1
    if requirements.get('cloud_ml_level_prevention', {}).get('minimum') is not None:
        checks += 1
    if requirements.get('sensor_ml_level_prevention', {}).get('minimum') is not None:
        checks += 1
    if requirements.get('cloud_pup_adware_level_prevention', {}).get('minimum') is not None:
        checks += 1
    if requirements.get('quarantine') is not None:
        checks += 1
    result['checks_count'] = checks

    return result


def grade_all_ods_scheduled_scans(scans_data, grading_config):
    """
    Grade all scheduled scans against minimum requirements.

    Args:
        scans_data: Dict containing 'policies' list of scan dicts,
                    or a list of scan dicts directly
        grading_config: The grading configuration dict with platform_requirements

    Returns:
        list: List of grading results for each scan
    """
    scans_list = []
    if isinstance(scans_data, dict):
        scans_list = scans_data.get('policies', [])
    elif isinstance(scans_data, list):
        scans_list = scans_data

    if not scans_list:
        logging.warning("No ODS scheduled scans to grade")
        return []

    graded_results = []

    for scan in scans_list:
        result = grade_ods_scheduled_scan(scan, grading_config)
        graded_results.append(result)

        grading_status = result.get('grading_status', 'graded')
        if grading_status == 'ungradable':
            logging.info(
                "ODS Scan '%s': UNGRADABLE - %s",
                result['policy_name'], result.get('ungradable_reason', 'unknown')
            )
        else:
            status = "PASSED" if result['passed'] else "FAILED"
            logging.info(
                "ODS Scan '%s': %s - %s/%s checks failed",
                result['policy_name'], status,
                result['failures_count'], result['checks_count']
            )

    return graded_results
