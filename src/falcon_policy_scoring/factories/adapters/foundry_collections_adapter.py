import json
import logging
from falcon_policy_scoring.factories.adapters.database_adapter import DatabaseAdapter
from falcon_policy_scoring.utils.core import epoch_now
from falconpy import APIHarnessV2


# Names of all Foundry Collections this adapter expects to exist.
# Collections must be pre-created via the Foundry CLI before use.
_COLLECTION_NAMES = [
    'hosts', 'host_records', 'host_zta', 'policies', 'graded_policies', 'firewall_policy_containers', 'device_control_policy_settings', 'ods_scan_coverage', 'sca_scan_coverage', 'cid_cache',
]


class FoundryCollectionsAdapter(DatabaseAdapter):
    """CrowdStrike Foundry Collections adapter (Custom Storage API via falconpy).

    Uses the falconpy APIHarnessV2 to store and retrieve JSON objects in
    pre-created Foundry Collections.  Inside a Foundry runtime, no credentials
    are required — the platform injects them automatically.  For external
    access pass falcon_credentials in the config dict.
    """

    def __init__(self):
        self.falcon = None
        self._app_id = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self, config):
        """Connect to Foundry Collections.

        Args:
            config: dict with keys:
                - app_id (str, required): Value for X-CS-APP-ID header
                - client_id (str, optional): Falcon OAuth2 client ID
                - client_secret (str, optional): Falcon OAuth2 client secret
                - base_url (str, optional): Falcon API base URL
        """
        self._app_id = config['app_id']

        creds_kwargs = {}
        if config.get('client_id'):
            creds_kwargs['client_id'] = config['client_id']
            creds_kwargs['client_secret'] = config.get('client_secret', '')
        if config.get('base_url'):
            creds_kwargs['base_url'] = config['base_url']

        self.falcon = APIHarnessV2(**creds_kwargs)
        self._verify_collections()
        logging.info("FoundryCollectionsAdapter connected (app_id=%s)", self._app_id)

    def close(self):
        """Release the Falcon API handle."""
        self.falcon = None
        self._app_id = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self):
        return {'X-CS-APP-ID': self._app_id}

    def _verify_collections(self):
        """Warn for any collections that are not yet created."""
        missing = []
        for name in _COLLECTION_NAMES:
            resp = self.falcon.command(
                'DescribeCollection', collection_name=name, parameters={'X-CS-APP-ID': self._app_id}, )
            if isinstance(resp, dict) and resp.get('status_code', 200) == 404:
                logging.warning(
                    "Foundry collection '%s' does not exist. "
                    "Create it with: foundry collections create --name %s", name, name, )
                missing.append(name)
        if len(missing) == len(_COLLECTION_NAMES):
            raise RuntimeError(
                "None of the required Foundry Collections exist. "
                "Have you run 'foundry collections create' for this app?"
            )

    def _put_object(self, collection, object_key, payload):
        """Serialize payload to JSON bytes and store it."""
        body = json.dumps(payload).encode('utf-8')
        resp = self.falcon.command(
            'PutObject', collection_name=collection, object_key=object_key, body=body, parameters={'X-CS-APP-ID': self._app_id}, )
        if isinstance(resp, dict) and resp.get('status_code', 200) not in (200, 201):
            logging.error(
                "FoundryCollections PutObject failed for %s/%s: %s", collection, object_key, resp, )

    def _get_object(self, collection, object_key):
        """Retrieve and deserialize a stored JSON object, or None if not found."""
        resp = self.falcon.command(
            'GetObject', collection_name=collection, object_key=object_key, parameters={'X-CS-APP-ID': self._app_id}, )
        if isinstance(resp, bytes):
            return json.loads(resp.decode('utf-8'))
        if isinstance(resp, dict):
            status = resp.get('status_code', 200)
            if status == 404:
                return None
            logging.error(
                "FoundryCollections GetObject failed for %s/%s: %s", collection, object_key, resp, )
        return None

    def _list_object_keys(self, collection):
        """Return a list of object keys in a collection."""
        resp = self.falcon.command(
            'ListObjects', collection_name=collection, parameters={'X-CS-APP-ID': self._app_id}, )
        if isinstance(resp, dict) and resp.get('status_code', 200) == 200:
            return resp.get('body', {}).get('resources', [])
        return []

    # ------------------------------------------------------------------
    # Collection / record helpers (not used in this adapter)
    # ------------------------------------------------------------------

    def get_hosts_collection(self):
        return None

    def get_host_records_collection(self):
        return None

    def create_record(self, collection, newvalue_set):
        pass

    def update_record(self, collection, resource, newvalue_set):
        pass

    def update_or_create_record(self, collection, resource, data=None):
        pass

    # ------------------------------------------------------------------
    # 'hosts' collection
    # ------------------------------------------------------------------

    def put_hosts(self, list_of_devices):
        """Store the host list record for a CID."""
        cid = list_of_devices['cid']
        payload = {
            'cid': cid, 'base_url': list_of_devices.get('base_url', ''), 'epoch': list_of_devices.get('epoch', epoch_now()), 'hosts': list_of_devices['hosts'], 'total': list_of_devices['total'], }
        self._put_object('hosts', cid, payload)
        logging.info("FoundryCollections hosts record stored for CID %s", cid)

    def get_hosts(self, cid):
        """Retrieve the hosts record for a CID, or None."""
        result = self._get_object('hosts', cid)
        if result is None:
            logging.info("FoundryCollections hosts record for CID %s NOT Found.", cid)
        return result

    # ------------------------------------------------------------------
    # 'host_records' collection
    # ------------------------------------------------------------------

    def put_host(self, device_details, record_type=4):
        """Store detailed device information."""
        aid = device_details.get('device_id', 'unknown_aid')
        key = f"{aid}#{record_type}"
        payload = dict(device_details)
        payload['epoch'] = epoch_now()
        payload['record_type'] = record_type
        self._put_object('host_records', key, payload)
        logging.info("FoundryCollections host_record stored for aid=%s record_type=%s", aid, record_type)

    def get_host(self, device_id, record_type=4):
        """Retrieve detailed device information, or None."""
        key = f"{device_id}#{record_type}"
        result = self._get_object('host_records', key)
        if result is None:
            logging.info(
                "FoundryCollections host_record for device_id=%s record_type=%s NOT Found.", device_id, record_type, )
        return result

    # ------------------------------------------------------------------
    # 'host_zta' collection
    # ------------------------------------------------------------------

    def put_host_zta(self, device_id, zta_data):
        """Store Zero Trust Assessment data for a host."""
        payload = {'device_id': device_id, 'epoch': epoch_now(), 'data': zta_data}
        self._put_object('host_zta', device_id, payload)
        logging.info("FoundryCollections ZTA record stored for device_id=%s", device_id)

    def get_host_zta(self, device_id):
        """Get Zero Trust Assessment data for a host, or None."""
        result = self._get_object('host_zta', device_id)
        if result is None:
            logging.debug("FoundryCollections ZTA for device_id=%s NOT Found.", device_id)
            return None
        return result.get('data')

    # ------------------------------------------------------------------
    # 'policies' collection
    # ------------------------------------------------------------------

    def put_policies(self, policy_type, cid, policies_data):
        """Store policies for a given policy_type and CID."""
        key = f"{policy_type}#{cid}"
        epoch = epoch_now()

        if 'error' in policies_data:
            payload = {
                'cid': cid, 'epoch': epoch, 'policies': [], 'total': -1, 'error': str(policies_data['error']), }
        else:
            resources = policies_data.get('body', {}).get('resources', [])
            payload = {
                'cid': cid, 'epoch': epoch, 'policies': resources, 'total': len(resources), }
        self._put_object('policies', key, payload)
        logging.info("FoundryCollections %s policies stored for CID %s", policy_type, cid)

    def get_policies(self, policy_type, cid):
        """Get policies for a given policy_type and CID, or None."""
        key = f"{policy_type}#{cid}"
        result = self._get_object('policies', key)
        if result is None:
            logging.info("FoundryCollections %s policies for CID %s NOT Found.", policy_type, cid)
        return result

    # ------------------------------------------------------------------
    # 'graded_policies' collection
    # ------------------------------------------------------------------

    def put_graded_policies(self, policy_type, cid, graded_results):
        """Store graded policy results for a given policy_type and CID."""
        if graded_results is None:
            logging.error("Cannot store graded policies: graded_results is None")
            return

        key = f"{policy_type}#{cid}"
        total_policies = len(graded_results)
        passed_policies = sum(1 for r in graded_results if r.get('passed', False))
        payload = {
            'cid': cid, 'epoch': epoch_now(), 'graded_policies': graded_results, 'total_policies': total_policies, 'passed_policies': passed_policies, 'failed_policies': total_policies - passed_policies, }
        self._put_object('graded_policies', key, payload)
        logging.info(
            "FoundryCollections graded_%s stored for CID %s (%s/%s passed)", policy_type, cid, passed_policies, total_policies, )

    def get_graded_policies(self, policy_type, cid):
        """Get graded policy results for a given policy_type and CID, or None."""
        key = f"{policy_type}#{cid}"
        result = self._get_object('graded_policies', key)
        if result is None:
            logging.info("FoundryCollections graded_%s for CID %s NOT Found.", policy_type, cid)
        return result

    # ------------------------------------------------------------------
    # 'firewall_policy_containers' collection
    # ------------------------------------------------------------------

    def put_firewall_policy_containers(self, cid, containers_map):
        """Store firewall policy containers for a CID."""
        payload = {
            'cid': cid, 'epoch': epoch_now(), 'policy_containers': containers_map, 'count': len(containers_map), }
        self._put_object('firewall_policy_containers', cid, payload)
        logging.info("FoundryCollections firewall_policy_containers stored for CID %s", cid)

    def get_firewall_policy_containers(self, cid):
        """Get firewall policy containers for a CID, or None."""
        result = self._get_object('firewall_policy_containers', cid)
        if result is None:
            logging.info("FoundryCollections firewall_policy_containers for CID %s NOT Found.", cid)
        return result

    # ------------------------------------------------------------------
    # 'device_control_policy_settings' collection
    # ------------------------------------------------------------------

    def put_device_control_policy_settings(self, cid, settings_map):
        """Store device control policy settings for a CID."""
        payload = {
            'cid': cid, 'epoch': epoch_now(), 'policy_settings': settings_map, 'count': len(settings_map), }
        self._put_object('device_control_policy_settings', cid, payload)
        logging.info("FoundryCollections device_control_policy_settings stored for CID %s", cid)

    def get_device_control_policy_settings(self, cid):
        """Get device control policy settings for a CID, or None."""
        result = self._get_object('device_control_policy_settings', cid)
        if result is None:
            logging.info("FoundryCollections device_control_policy_settings for CID %s NOT Found.", cid)
        return result

    # ------------------------------------------------------------------
    # 'ods_scan_coverage' collection
    # ------------------------------------------------------------------

    def put_ods_scan_coverage(self, cid, coverage_index, last_compliant_scan_times=None):
        """Store ODS scan coverage index for a CID."""
        payload = {
            'cid': cid, 'epoch': epoch_now(), 'coverage_index': coverage_index, 'count': len(coverage_index), 'last_compliant_scan_times': last_compliant_scan_times or {}, }
        self._put_object('ods_scan_coverage', cid, payload)
        logging.info("FoundryCollections ods_scan_coverage stored for CID %s", cid)

    def get_ods_scan_coverage(self, cid):
        """Get ODS scan coverage index for a CID, or None."""
        result = self._get_object('ods_scan_coverage', cid)
        if result is None:
            logging.info("FoundryCollections ods_scan_coverage for CID %s NOT Found.", cid)
        return result

    # ------------------------------------------------------------------
    # 'sca_scan_coverage' collection
    # ------------------------------------------------------------------

    def put_sca_coverage(self, cid, coverage_index):
        """Store SCA coverage index for a CID."""
        payload = {
            'cid': cid, 'epoch': epoch_now(), 'coverage_index': coverage_index, 'count': len(coverage_index), }
        self._put_object('sca_scan_coverage', cid, payload)
        logging.info("FoundryCollections sca_scan_coverage stored for CID %s", cid)

    def get_sca_coverage(self, cid):
        """Get SCA coverage index for a CID, or None."""
        result = self._get_object('sca_scan_coverage', cid)
        if result is None:
            logging.info("FoundryCollections sca_scan_coverage for CID %s NOT Found.", cid)
        return result

    # ------------------------------------------------------------------
    # CID caching  ('cid_cache' collection)
    # ------------------------------------------------------------------

    def put_cid(self, cid, base_url):
        """Cache CID for a given base_url."""
        payload = {'base_url': base_url, 'cid': cid, 'epoch': epoch_now()}
        self._put_object('cid_cache', base_url, payload)
        logging.info("FoundryCollections CID %s cached for base_url %s", cid, base_url)

    def get_cid(self, base_url):
        """Get cached CID for a base_url, or None."""
        result = self._get_object('cid_cache', base_url)
        if result:
            cid = result.get('cid')
            logging.info("FoundryCollections CID %s retrieved for base_url %s", cid, base_url)
            return cid
        logging.info("FoundryCollections no cached CID found for base_url %s", base_url)
        return None

    def get_cached_cid_info(self):
        """Return the most recently cached CID info dict, or None."""
        keys = self._list_object_keys('cid_cache')
        if not keys:
            logging.info("FoundryCollections cid_cache is empty.")
            return None

        # Retrieve all entries and return the one with the highest epoch
        best = None
        for key in keys:
            item = self._get_object('cid_cache', key)
            if item is None:
                continue
            if best is None or item.get('epoch', 0) > best.get('epoch', 0):
                best = item

        if best:
            return {'cid': best['cid'], 'base_url': best['base_url']}
        return None
