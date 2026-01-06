"""
Host Group API utilities.

Handles fetching host group information and member device IDs.
Optimized for large host groups (20K+ members).
"""

import logging
from typing import Dict, List, Optional


class HostGroup:
    """
    HostGroup class for fetching CrowdStrike Falcon host group information.

    Provides methods to:
    - Resolve host group names to IDs
    - Fetch all member device IDs from host groups with pagination
    """

    def __init__(self, falcon):
        """
        Initialize HostGroup instance.

        Args:
            falcon: APIHarnessV2 instance
        """
        self.falcon = falcon

    def resolve_group_names_to_ids(self, group_names: List[str]) -> Dict[str, str]:
        """
        Resolve host group names to their IDs.

        Args:
            group_names: List of host group names to resolve (case-insensitive)

        Returns:
            Dict mapping group_name -> group_id

        Raises:
            ValueError: If any group names cannot be resolved
        """
        if not group_names:
            return {}

        logging.info(f"Resolving {len(group_names)} host group names to IDs...")

        # Build filter for all group names (case-insensitive)
        # FQL requires lowercase for string filtering
        name_conditions = ','.join([f"'{name.lower()}'" for name in group_names])
        filter_str = f"name:[{name_conditions}]"

        # Query for host groups matching the names
        response = self.falcon.command("queryHostGroups",
                                       filter=filter_str,
                                       limit=500)  # Max limit for queryHostGroups is 500

        if response['status_code'] != 200:
            error_msg = response.get('body', {}).get('errors', [])
            raise ValueError(f"Failed to query host groups: {error_msg}")

        group_ids = response['body'].get('resources', [])

        if not group_ids:
            raise ValueError(f"No host groups found matching names: {', '.join(group_names)}")

        # Fetch full group details to get names
        if group_ids:
            details_response = self.falcon.command("getHostGroups", ids=group_ids)

            if details_response['status_code'] != 200:
                error_msg = details_response.get('body', {}).get('errors', [])
                raise ValueError(f"Failed to get host group details: {error_msg}")

            groups = details_response['body'].get('resources', [])

            # Build name -> ID mapping (case-insensitive)
            name_to_id = {}
            for group in groups:
                group_name = group.get('name', '')
                group_id = group.get('id', '')
                if group_name and group_id:
                    name_to_id[group_name.lower()] = group_id

            # Verify all requested names were found
            missing_names = []
            result = {}
            for requested_name in group_names:
                requested_lower = requested_name.lower()
                if requested_lower in name_to_id:
                    result[requested_name] = name_to_id[requested_lower]
                else:
                    missing_names.append(requested_name)

            if missing_names:
                raise ValueError(f"Host groups not found: {', '.join(missing_names)}")

            logging.info(f"Successfully resolved {len(result)} host group names to IDs")
            return result

        return {}

    def get_all_group_members(self, group_id: str) -> List[str]:
        """
        Fetch all member device IDs from a host group with pagination.

        Optimized for large groups (20K+ members). Uses queryGroupMembers
        to fetch device IDs only (not full host details) for efficiency.

        Args:
            group_id: The host group ID

        Returns:
            List of device IDs (AIDs) that are members of the group
        """
        logging.info(f"Fetching members for host group {group_id}...")

        all_device_ids = []
        offset = 0
        limit = 5000  # Max limit for queryGroupMembers

        while True:
            response = self.falcon.command("queryGroupMembers",
                                           id=group_id,
                                           offset=offset,
                                           limit=limit)

            if response['status_code'] != 200:
                error_msg = response.get('body', {}).get('errors', [])
                logging.error(f"Failed to fetch group members: {error_msg}")
                break

            device_ids = response['body'].get('resources', [])
            all_device_ids.extend(device_ids)

            # Check pagination
            meta = response['body'].get('meta', {})
            pagination = meta.get('pagination', {})
            total = pagination.get('total', 0)

            logging.debug(f"Fetched {len(device_ids)} device IDs (offset={offset}, total={total})")

            # Check if we've fetched all members
            if offset + len(device_ids) >= total or len(device_ids) == 0:
                break

            offset += limit

        logging.info(f"Fetched {len(all_device_ids)} device IDs from group {group_id}")
        return all_device_ids

    def get_device_ids_from_groups(self, group_names: List[str]) -> List[str]:
        """
        Get all unique device IDs from multiple host groups (union).

        Args:
            group_names: List of host group names

        Returns:
            List of unique device IDs across all groups
        """
        if not group_names:
            return []

        # Resolve names to IDs
        name_to_id = self.resolve_group_names_to_ids(group_names)

        # Collect all device IDs from all groups
        all_device_ids = []
        for group_name, group_id in name_to_id.items():
            logging.info(f"Fetching members from group '{group_name}' ({group_id})...")
            device_ids = self.get_all_group_members(group_id)
            all_device_ids.extend(device_ids)
            logging.info(f"  Found {len(device_ids)} devices in '{group_name}'")

        # Return unique device IDs (union of all groups)
        unique_ids = list(set(all_device_ids))
        logging.info(f"Total unique devices across {len(group_names)} groups: {len(unique_ids)}")

        return unique_ids
