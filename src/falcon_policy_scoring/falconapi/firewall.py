"""
Firewall Management API utilities.

Handles fetching firewall policies and their policy containers which contain
the critical grading settings: default_inbound, default_outbound, enforce, test_mode.
"""

import logging
from typing import Dict, List


def fetch_policy_containers(falcon, db_adapter, policy_ids: List[str], cid: str) -> Dict:
    """
    Fetch policy containers for the given policy IDs.

    Policy containers contain the actual firewall settings:
    - default_inbound: ALLOW/DENY
    - default_outbound: ALLOW/DENY
    - enforce: true/false
    - test_mode: true/false
    - rule_group_ids: list of assigned rule groups

    Args:
        falcon: FalconPy APIHarnessV2 instance
        db_adapter: Database adapter instance
        policy_ids: List of firewall policy IDs
        cid: Customer ID

    Returns:
        dict: {
            'policy_containers': {policy_id: container_object},
            'count': int
        }
    """
    if not policy_ids:
        return {'policy_containers': {}, 'count': 0}

    # Check cache
    cached = db_adapter.get_firewall_policy_containers(cid)
    if cached and cached.get('policy_containers'):
        containers_map = cached['policy_containers']
        # Check if we have all requested policy IDs
        if all(pid in containers_map for pid in policy_ids):
            logging.info("Using cached policy containers: %s containers", len(policy_ids))
            return {
                'policy_containers': {pid: containers_map[pid] for pid in policy_ids},
                'count': len(policy_ids)
            }

    logging.info("Fetching policy containers for %s policies...", len(policy_ids))

    try:
        # Fetch policy containers in batches (API limit typically 100-500)
        all_containers = []
        batch_size = 100

        for i in range(0, len(policy_ids), batch_size):
            batch_ids = policy_ids[i:i + batch_size]
            logging.info("Fetching policy container batch %s (%s containers)...", i // batch_size + 1, len(batch_ids))

            response = falcon.command("get_policy_containers", ids=batch_ids)

            if response["status_code"] == 200:
                batch_containers = response["body"]["resources"]
                all_containers.extend(batch_containers)
                logging.info("Fetched %s policy containers in this batch", len(batch_containers))
            else:
                logging.error("Failed to fetch policy container batch: %s", response.get('body', {}))

        logging.info("Total policy containers fetched: %s", len(all_containers))

        # Build map: policy_id -> container
        containers_map = {c['policy_id']: c for c in all_containers}

        # Store in cache
        db_adapter.put_firewall_policy_containers(cid, containers_map)

        return {
            'policy_containers': containers_map,
            'count': len(containers_map)
        }

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Exception fetching policy containers: %s", e)
        return {'policy_containers': {}, 'count': 0}
