import logging
from falcon_policy_scoring.utils.core import epoch_now


class Hosts:
    """
    Hosts class for fetching CrowdStrike Falcon host information.

    Uses QueryDevicesByFilterScroll for improved pagination with large datasets.
    """

    def __init__(self, cid, falcon, filter=None, product_types=None, device_ids=None):
        """
        Initialize Hosts instance.

        Args:
            cid: CrowdStrike Customer ID
            falcon: APIHarnessV2 instance
            filter: Optional FQL filter string (will be combined with other filters)
            product_types: List of product types to include, or empty list/None for no filtering
            device_ids: Optional list of device IDs to filter by (for host group filtering)
        """
        self.cid = cid
        self.falcon = falcon
        self.limit = 10000  # QueryDevicesByFilterScroll supports up to 10000

        # Store device_ids for post-filtering if needed
        self.device_ids_filter = set(device_ids) if device_ids else None

        # Determine if we should apply device_ids in FQL or post-filter
        # If we have other filters (like last_seen) with a large device_ids list,
        # it's better to query with other filters and post-filter by device_ids
        use_device_ids_in_fql = True
        if device_ids and (filter or product_types):
            # If the device list is large, don't include in FQL
            if len(device_ids) > 100:  # Arbitrary threshold
                use_device_ids_in_fql = False
                logging.info("Large device list (%s devices) with additional filters. Will apply device_id filter client-side.", len(device_ids))

        # Build the filter with or without device IDs in FQL
        device_ids_for_fql = device_ids if use_device_ids_in_fql else None
        self.filter = self._build_filter(filter, product_types, device_ids_for_fql)
        self.total = self.device_count()

    def _build_filter(self, custom_filter=None, product_types=None, device_ids=None):
        """
        Build FQL filter string combining custom filter with product type and device ID filtering.

        Args:
            custom_filter: Optional custom FQL filter string
            product_types: List of product types to include, or None/empty for no filtering
            device_ids: Optional list of device IDs to filter by

        Returns:
            Combined FQL filter string
        """
        filters = []

        # Add device ID filter if specified (for host group filtering)
        if device_ids:
            # Build FQL: device_id:['id1','id2','id3']
            # For very large lists, we rely on the scroll API to handle them
            device_id_conditions = ','.join([f"'{did}'" for did in device_ids])
            filters.append(f"device_id:[{device_id_conditions}]")

        # Add product type filter if product types are specified
        if product_types:
            # Build FQL: product_type_desc:'Workstation','Domain Controller','Server'
            product_type_conditions = ','.join([f"'{pt}'" for pt in product_types])
            filters.append(f"product_type_desc:[{product_type_conditions}]")

        # Add custom filter if provided
        if custom_filter:
            filters.append(custom_filter)

        # Combine filters with + (AND operator in FQL)
        if filters:
            return '+'.join(filters)

        return None

    def device_count(self):
        """
        Get the total count of devices matching the filter.

        Note: For scroll API, we use a small limit just to get the total count.
        """
        r = self.falcon.command("QueryDevicesByFilterScroll",
                                limit=1,
                                sort="device_id.desc",
                                filter=self.filter)

        if r['status_code'] != 200:
            errors = r.get('body', {}).get('errors', [])
            logging.error("Failed to query device count. Status: %s, Errors: %s", r['status_code'], errors)
            logging.error("Filter used: %s", self.filter)
            raise RuntimeError(f"Failed to query devices: {errors}")

        total = r['body']['meta']['pagination']['total']
        return total

    def get_devices(self):
        """
        Fetch all devices using scroll-based pagination.

        QueryDevicesByFilterScroll uses string offset tokens that expire after 2 minutes.
        Supports up to 10,000 records per request for improved performance.
        """
        logging.info("Fetching %s devices from Falcon API using scroll pagination (filter: %s)...", self.total, self.filter)

        all_devices = []
        offset_token = None  # Start with no offset for first request
        page = 0

        while True:
            page += 1

            # Build request parameters
            params = {
                "limit": self.limit,
                "sort": "device_id.desc",
                "filter": self.filter
            }

            # Add offset token for subsequent pages
            if offset_token:
                params["offset"] = offset_token

            r = self.falcon.command("QueryDevicesByFilterScroll", **params)

            if r['status_code'] != 200:
                logging.error("Failed to fetch devices: %s", r.get('body', {}).get('errors', []))
                break

            device_ids = r['body'].get('resources', [])
            all_devices.extend(device_ids)

            logging.debug("Page %s: Fetched %s device IDs (total so far: %s/%s)", page, len(device_ids), len(all_devices), self.total)

            # Check if there are more pages
            meta = r['body'].get('meta', {})
            pagination = meta.get('pagination', {})
            offset_token = pagination.get('offset')  # Get next page token

            # Stop if no more results or no offset token for next page
            if not device_ids or not offset_token:
                break

        # Apply client-side device_id filtering if needed
        if self.device_ids_filter:
            original_count = len(all_devices)
            all_devices = [did for did in all_devices if did in self.device_ids_filter]
            logging.info("Applied client-side device_id filter: %s of %s devices matched", len(all_devices), original_count)

        logging.info("Fetched %s device IDs from Falcon API.", len(all_devices))

        hosts_dict = {'epoch': epoch_now(),
                      'cid': self.cid,
                      'base_url': self.falcon.base_url,
                      'total': len(all_devices),  # Update total to reflect filtered count
                      'hosts': all_devices
                      }
        return hosts_dict
