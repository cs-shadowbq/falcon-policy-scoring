"""
Device Control Policy API utilities.

Handles fetching device control policies and their settings which contain
the critical grading information: enforcement_mode, device class actions, etc.
"""

import logging
from typing import Dict, List


def fetch_policy_settings(falcon, db_adapter, policy_ids: List[str], cid: str) -> Dict:
    """
    Fetch device control policy settings for the given policy IDs.

    Device control policy settings contain:
    - enforcement_mode: MONITOR_ENFORCE, ENFORCE, etc.
    - end_user_notification: SILENT, etc.
    - classes: Array of device class configurations with actions and exceptions
    - enhanced_file_metadata: true/false

    Args:
        falcon: FalconPy APIHarnessV2 instance
        db_adapter: Database adapter instance
        policy_ids: List of device control policy IDs
        cid: Customer ID

    Returns:
        dict: {
            'policy_settings': {policy_id: settings_object},
            'count': int
        }
    """
    if not policy_ids:
        return {'policy_settings': {}, 'count': 0}

    # Check cache
    cached = db_adapter.get_device_control_policy_settings(cid)
    if cached and cached.get('policy_settings'):
        settings_map = cached['policy_settings']
        # Check if we have all requested policy IDs
        if all(pid in settings_map for pid in policy_ids):
            logging.info("Using cached device control policy settings: %s settings", len(policy_ids))
            return {
                'policy_settings': {pid: settings_map[pid] for pid in policy_ids},
                'count': len(policy_ids)
            }

    logging.info("Fetching device control policy settings for %s policies...", len(policy_ids))

    try:
        # Fetch policy settings - the API returns full policy details including settings
        # We already have this from queryCombinedDeviceControlPolicies,
        # but we need to extract just the settings portion for grading

        # For device control, the settings are already part of the policy object
        # from queryCombinedDeviceControlPolicies, so we just need to map policy_id -> settings

        # However, if we need to re-fetch or get detailed settings, we can use:
        # getDeviceControlPolicies with ids parameter

        all_settings = []
        batch_size = 100

        for i in range(0, len(policy_ids), batch_size):
            batch_ids = policy_ids[i:i + batch_size]
            logging.info("Fetching device control settings batch %s (%s policies)...", i // batch_size + 1, len(batch_ids))

            # Fetch detailed policy info including settings
            response = falcon.command("getDeviceControlPolicies", ids=batch_ids)

            if response["status_code"] == 200:
                batch_policies = response["body"]["resources"]
                # Extract settings from each policy
                for policy in batch_policies:
                    if 'settings' in policy:
                        all_settings.append({
                            'policy_id': policy['id'],
                            'settings': policy['settings']
                        })
                logging.info("Fetched %s policy settings in this batch", len(batch_policies))
            else:
                logging.error("Failed to fetch device control settings batch: %s", response.get('body', {}))

        logging.info("Total device control policy settings fetched: %s", len(all_settings))

        # Build map: policy_id -> settings
        settings_map = {item['policy_id']: item['settings'] for item in all_settings}

        # Store in cache
        db_adapter.put_device_control_policy_settings(cid, settings_map)

        return {
            'policy_settings': settings_map,
            'count': len(settings_map)
        }

    except Exception as e:
        logging.error("Exception fetching device control policy settings: %s", e)
        import traceback
        logging.error(traceback.format_exc())
        return {'policy_settings': {}, 'count': 0}
