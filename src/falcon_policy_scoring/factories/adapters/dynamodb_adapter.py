import json
import logging
import zlib
from decimal import Decimal
from falcon_policy_scoring.factories.adapters.database_adapter import DatabaseAdapter
from falcon_policy_scoring.utils.core import epoch_now

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError as _boto3_import_error:  # pragma: no cover
    raise ImportError(
        "boto3 is required for DynamoDBAdapter. "
        "Install it with: pip install 'falcon-policy-scoring[dynamodb]'"
    ) from _boto3_import_error


def _pack(obj):
    """Serialize + zlib-compress obj to bytes for DynamoDB Binary storage."""
    return zlib.compress(json.dumps(obj).encode('utf-8'))


def _unpack(data):
    """Decompress + deserialize a DynamoDB Binary field.

    Falls back to plain JSON string decoding for backward compatibility.
    ``bytes(data)`` works for plain bytes, bytearray, and boto3 Binary objects.
    """
    if isinstance(data, str):
        return json.loads(data)  # legacy uncompressed string
    return json.loads(zlib.decompress(bytes(data)).decode('utf-8'))


# Max compressed bytes stored per DynamoDB item — well below the 400 KB hard limit.
_CHUNK_SIZE = 300_000

# DynamoDB table definitions: (table_name, partition_key, sort_key_or_None)
_TABLE_DEFINITIONS = [
    ('hosts', 'cid', None), ('host_records', 'aid', ('record_type', 'N')), ('host_zta', 'device_id', None), ('policies', 'pk', None), ('graded_policies', 'pk', None), ('firewall_policy_containers', 'cid', None), ('device_control_policy_settings', 'cid', None), ('ods_scan_coverage', 'cid', None), ('sca_scan_coverage', 'cid', None), ('cid_cache', 'base_url', None),
]


class DynamoDBAdapter(DatabaseAdapter):
    """DynamoDB adapter — works with real AWS DynamoDB and with a local Dynalite server."""

    def __init__(self):
        self.dynamodb = None
        self._tables = {}

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self, config):
        """Connect to DynamoDB (AWS or local Dynalite) and ensure all tables exist.

        Args:
            config: dict with optional keys:
                - region (str): AWS region, default 'us-east-1'
                - endpoint_url (str): Override endpoint (required for Dynalite)
                - aws_access_key_id (str): Optional; injected automatically for local endpoints
                - aws_secret_access_key (str): Optional; injected automatically for local endpoints
        """
        kwargs = {
            'region_name': config.get('region', 'us-east-1'), }
        endpoint_url = config.get('endpoint_url')
        if endpoint_url:
            kwargs['endpoint_url'] = endpoint_url
            # Dynalite / local DynamoDB requires non-empty credentials even if ignored
            kwargs.setdefault('aws_access_key_id', config.get('aws_access_key_id', 'local'))
            kwargs.setdefault('aws_secret_access_key', config.get('aws_secret_access_key', 'local'))

        if 'aws_access_key_id' in config and not endpoint_url:
            kwargs['aws_access_key_id'] = config['aws_access_key_id']
            kwargs['aws_secret_access_key'] = config.get('aws_secret_access_key', '')

        self.dynamodb = boto3.resource('dynamodb', **kwargs)
        self._tables = {}
        self._ensure_tables()
        logging.info("DynamoDB connected (endpoint=%s)", endpoint_url or 'AWS')

    def close(self):
        """Release DynamoDB resource handle."""
        self.dynamodb = None
        self._tables = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _table(self, name):
        """Return (cached) Table resource."""
        if name not in self._tables:
            self._tables[name] = self.dynamodb.Table(name)
        return self._tables[name]

    def _ensure_tables(self):
        """Create tables that do not yet exist (idempotent)."""
        existing = {t.name for t in self.dynamodb.tables.all()}
        for table_name, pk, sk in _TABLE_DEFINITIONS:
            if table_name in existing:
                continue
            key_schema = [{'AttributeName': pk, 'KeyType': 'HASH'}]
            attr_definitions = [{'AttributeName': pk, 'AttributeType': 'S'}]
            if sk:
                sk_name, sk_type = sk
                key_schema.append({'AttributeName': sk_name, 'KeyType': 'RANGE'})
                attr_definitions.append({'AttributeName': sk_name, 'AttributeType': sk_type})
            try:
                self.dynamodb.create_table(
                    TableName=table_name, KeySchema=key_schema, AttributeDefinitions=attr_definitions, BillingMode='PAY_PER_REQUEST', )
                logging.info("DynamoDB table created: %s", table_name)
            except ClientError as exc:
                if exc.response['Error']['Code'] == 'ResourceInUseException':
                    logging.debug("DynamoDB table already exists: %s", table_name)
                else:
                    raise

    # ------------------------------------------------------------------
    # Chunked-binary helpers (transparent 300 KB chunking for large blobs)
    # ------------------------------------------------------------------

    def _put_chunked(self, table_name, pk_field, main_item, blob_field, blob_bytes):
        """Store main_item, splitting blob_bytes into ≤300 KB chunks if needed.

        Extra chunks are stored as sibling items with pk ``{pk_value}#chunk#{i}``.
        The main item carries ``_chunk_count`` when more than one chunk is needed.
        """
        chunks = [blob_bytes[i:i + _CHUNK_SIZE] for i in range(0, len(blob_bytes) or 1, _CHUNK_SIZE)]
        pk_value = main_item[pk_field]
        main_item[blob_field] = chunks[0]
        if len(chunks) > 1:
            main_item['_chunk_count'] = len(chunks)
        self._table(table_name).put_item(Item=main_item)
        for idx, chunk in enumerate(chunks[1:], start=1):
            self._table(table_name).put_item(Item={pk_field: f"{pk_value}#chunk#{idx}", blob_field: chunk})
        if len(chunks) > 1:
            logging.debug("DynamoDB %s: stored %s chunk(s) for pk=%s", table_name, len(chunks), pk_value)

    def _get_chunked(self, table_name, pk_field, item, blob_field):
        """Return the reassembled bytes for a potentially-chunked blob."""
        n_chunks = int(item.get('_chunk_count', 1))
        parts = [bytes(item[blob_field])]
        if n_chunks > 1:
            pk_value = item[pk_field]
            for idx in range(1, n_chunks):
                resp = self._table(table_name).get_item(Key={pk_field: f"{pk_value}#chunk#{idx}"})
                chunk_item = resp.get('Item', {})
                parts.append(bytes(chunk_item[blob_field]))
        return b''.join(parts)

    # ------------------------------------------------------------------
    # Collection / record helpers (not used in DynamoDB adapter)
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
    # 'hosts' table
    # ------------------------------------------------------------------

    def put_hosts(self, list_of_devices):
        """Store the host list record for a CID."""
        cid = list_of_devices['cid']
        base_url = list_of_devices.get('base_url', '')
        epoch = list_of_devices.get('epoch', epoch_now())
        hosts = _pack(list_of_devices['hosts'])
        total = list_of_devices['total']

        self._table('hosts').put_item(Item={
            'cid': cid, 'base_url': base_url, 'epoch': epoch, 'hosts': hosts, 'total': total, })
        logging.info("DynamoDB hosts record stored for CID %s", cid)

    def get_hosts(self, cid):
        """Retrieve the hosts record for a CID, or None."""
        response = self._table('hosts').get_item(Key={'cid': cid})
        item = response.get('Item')
        if item:
            return {
                'cid': item['cid'], 'base_url': item.get('base_url', ''), 'epoch': int(item['epoch']), 'hosts': _unpack(item['hosts']), 'total': int(item['total']), }
        logging.info("DynamoDB hosts record for CID %s NOT Found.", cid)
        return None

    # ------------------------------------------------------------------
    # 'host_records' table
    # ------------------------------------------------------------------

    def put_host(self, device_details, record_type=4):
        """Store detailed device information."""
        cid = device_details.get('cid', 'unknown_cid')
        aid = device_details.get('device_id', 'unknown_aid')
        data = _pack(device_details)

        self._table('host_records').put_item(Item={
            'aid': aid, 'record_type': Decimal(record_type), 'cid': cid, 'epoch': epoch_now(), 'data': data, })
        logging.info("DynamoDB host_record stored for aid=%s record_type=%s", aid, record_type)

    def get_host(self, device_id, record_type=4):
        """Retrieve detailed device information, or None."""
        response = self._table('host_records').get_item(
            Key={'aid': device_id, 'record_type': Decimal(record_type)}
        )
        item = response.get('Item')
        if item:
            return {
                'aid': item['aid'], 'cid': item.get('cid', ''), 'record_type': int(item['record_type']), 'epoch': int(item['epoch']), 'data': _unpack(item['data']), }
        logging.info("DynamoDB host_record for device_id=%s record_type=%s NOT Found.", device_id, record_type)
        return None

    # ------------------------------------------------------------------
    # 'host_zta' table
    # ------------------------------------------------------------------

    def put_host_zta(self, device_id, zta_data):
        """Store Zero Trust Assessment data for a host."""
        self._table('host_zta').put_item(Item={
            'device_id': device_id, 'epoch': epoch_now(), 'data': _pack(zta_data), })
        logging.info("DynamoDB ZTA record stored for device_id=%s", device_id)

    def get_host_zta(self, device_id):
        """Get Zero Trust Assessment data for a host, or None."""
        response = self._table('host_zta').get_item(Key={'device_id': device_id})
        item = response.get('Item')
        if item:
            return _unpack(item['data'])
        logging.debug("DynamoDB ZTA for device_id=%s NOT Found.", device_id)
        return None

    # ------------------------------------------------------------------
    # 'policies' table
    # ------------------------------------------------------------------

    def put_policies(self, policy_type, cid, policies_data):
        """Store policies for a given policy_type and CID."""
        epoch = epoch_now()
        pk = f"{policy_type}#{cid}"

        if 'error' in policies_data:
            packed = _pack([])
            total = -1
            error = str(policies_data['error'])
        else:
            resources = policies_data.get('body', {}).get('resources', [])
            packed = _pack(resources)
            total = len(resources)
            error = None

        item = {'pk': pk, 'epoch': epoch, 'total': total}
        if error:
            item['error'] = error

        self._put_chunked('policies', 'pk', item, 'policies', packed)
        logging.info("DynamoDB %s policies stored for CID %s (total=%s)", policy_type, cid, total)

    def get_policies(self, policy_type, cid):
        """Get policies for a given policy_type and CID, or None."""
        pk = f"{policy_type}#{cid}"
        response = self._table('policies').get_item(Key={'pk': pk})
        item = response.get('Item')
        if item:
            packed = self._get_chunked('policies', 'pk', item, 'policies')
            result = {
                'cid': cid, 'epoch': int(item['epoch']), 'policies': _unpack(packed), 'total': int(item['total']), }
            if 'error' in item:
                result['error'] = item['error']
            return result
        logging.info("DynamoDB %s policies for CID %s NOT Found.", policy_type, cid)
        return None

    # ------------------------------------------------------------------
    # 'graded_policies' table
    # ------------------------------------------------------------------

    def put_graded_policies(self, policy_type, cid, graded_results):
        """Store graded policy results for a given policy_type and CID."""
        if graded_results is None:
            logging.error("Cannot store graded policies: graded_results is None")
            return

        epoch = epoch_now()
        pk = f"{policy_type}#{cid}"
        total_policies = len(graded_results)
        passed_policies = sum(1 for r in graded_results if r.get('passed', False))
        failed_policies = total_policies - passed_policies

        item = {
            'pk': pk, 'epoch': epoch,
            'total_policies': total_policies, 'passed_policies': passed_policies, 'failed_policies': failed_policies,
        }
        self._put_chunked('graded_policies', 'pk', item, 'graded_policies', _pack(graded_results))
        logging.info(
            "DynamoDB graded_%s stored for CID %s (%s/%s passed)", policy_type, cid, passed_policies, total_policies, )

    def get_graded_policies(self, policy_type, cid):
        """Get graded policy results for a given policy_type and CID, or None."""
        pk = f"{policy_type}#{cid}"
        response = self._table('graded_policies').get_item(Key={'pk': pk})
        item = response.get('Item')
        if item:
            packed = self._get_chunked('graded_policies', 'pk', item, 'graded_policies')
            return {
                'cid': cid, 'epoch': int(item['epoch']), 'graded_policies': _unpack(packed), 'total_policies': int(item['total_policies']), 'passed_policies': int(item['passed_policies']), 'failed_policies': int(item['failed_policies']), }
        logging.info("DynamoDB graded_%s for CID %s NOT Found.", policy_type, cid)
        return None

    # ------------------------------------------------------------------
    # 'firewall_policy_containers' table
    # ------------------------------------------------------------------

    def put_firewall_policy_containers(self, cid, containers_map):
        """Store firewall policy containers for a CID."""
        self._table('firewall_policy_containers').put_item(Item={
            'cid': cid, 'epoch': epoch_now(), 'policy_containers': _pack(containers_map), 'count': len(containers_map), })
        logging.info("DynamoDB firewall_policy_containers stored for CID %s (%s items)", cid, len(containers_map))

    def get_firewall_policy_containers(self, cid):
        """Get firewall policy containers for a CID, or None."""
        response = self._table('firewall_policy_containers').get_item(Key={'cid': cid})
        item = response.get('Item')
        if item:
            return {
                'cid': item['cid'], 'epoch': int(item['epoch']), 'policy_containers': _unpack(item['policy_containers']), 'count': int(item['count']), }
        logging.info("DynamoDB firewall_policy_containers for CID %s NOT Found.", cid)
        return None

    # ------------------------------------------------------------------
    # 'device_control_policy_settings' table
    # ------------------------------------------------------------------

    def put_device_control_policy_settings(self, cid, settings_map):
        """Store device control policy settings for a CID."""
        self._table('device_control_policy_settings').put_item(Item={
            'cid': cid, 'epoch': epoch_now(), 'policy_settings': _pack(settings_map), 'count': len(settings_map), })
        logging.info("DynamoDB device_control_policy_settings stored for CID %s (%s items)", cid, len(settings_map))

    def get_device_control_policy_settings(self, cid):
        """Get device control policy settings for a CID, or None."""
        response = self._table('device_control_policy_settings').get_item(Key={'cid': cid})
        item = response.get('Item')
        if item:
            return {
                'cid': item['cid'], 'epoch': int(item['epoch']), 'policy_settings': _unpack(item['policy_settings']), 'count': int(item['count']), }
        logging.info("DynamoDB device_control_policy_settings for CID %s NOT Found.", cid)
        return None

    # ------------------------------------------------------------------
    # 'ods_scan_coverage' table
    # ------------------------------------------------------------------

    def put_ods_scan_coverage(self, cid, coverage_index, last_compliant_scan_times=None):
        """Store ODS scan coverage index for a CID."""
        self._table('ods_scan_coverage').put_item(Item={
            'cid': cid, 'epoch': epoch_now(), 'coverage_index': _pack(coverage_index), 'count': len(coverage_index), 'last_compliant_scan_times': _pack(last_compliant_scan_times or {}), })
        logging.info("DynamoDB ods_scan_coverage stored for CID %s (%s devices)", cid, len(coverage_index))

    def get_ods_scan_coverage(self, cid):
        """Get ODS scan coverage index for a CID, or None."""
        response = self._table('ods_scan_coverage').get_item(Key={'cid': cid})
        item = response.get('Item')
        if item:
            return {
                'cid': item['cid'], 'epoch': int(item['epoch']), 'coverage_index': _unpack(item['coverage_index']), 'count': int(item['count']), 'last_compliant_scan_times': _unpack(item['last_compliant_scan_times']) if 'last_compliant_scan_times' in item else {}, }
        logging.info("DynamoDB ods_scan_coverage for CID %s NOT Found.", cid)
        return None

    # ------------------------------------------------------------------
    # 'sca_scan_coverage' table
    # ------------------------------------------------------------------

    def put_sca_coverage(self, cid, coverage_index):
        """Store SCA coverage index for a CID."""
        self._table('sca_scan_coverage').put_item(Item={
            'cid': cid, 'epoch': epoch_now(), 'coverage_index': _pack(coverage_index), 'count': len(coverage_index), })
        logging.info("DynamoDB sca_scan_coverage stored for CID %s (%s devices)", cid, len(coverage_index))

    def get_sca_coverage(self, cid):
        """Get SCA coverage index for a CID, or None."""
        response = self._table('sca_scan_coverage').get_item(Key={'cid': cid})
        item = response.get('Item')
        if item:
            return {
                'cid': item['cid'], 'epoch': int(item['epoch']), 'coverage_index': _unpack(item['coverage_index']), 'count': int(item['count']), }
        logging.info("DynamoDB sca_scan_coverage for CID %s NOT Found.", cid)
        return None

    # ------------------------------------------------------------------
    # CID caching  ('cid_cache' table)
    # ------------------------------------------------------------------

    def put_cid(self, cid, base_url):
        """Cache CID for a given base_url."""
        self._table('cid_cache').put_item(Item={
            'base_url': base_url, 'cid': cid, 'epoch': epoch_now(), })
        logging.info("DynamoDB CID %s cached for base_url %s", cid, base_url)

    def get_cid(self, base_url):
        """Get cached CID for a base_url, or None."""
        response = self._table('cid_cache').get_item(Key={'base_url': base_url})
        item = response.get('Item')
        if item:
            cid = item['cid']
            logging.info("DynamoDB CID %s retrieved for base_url %s", cid, base_url)
            return cid
        logging.info("DynamoDB no cached CID found for base_url %s", base_url)
        return None

    def get_cached_cid_info(self):
        """Return the most recently cached CID info dict, or None."""
        response = self._table('cid_cache').scan()
        items = response.get('Items', [])
        if not items:
            logging.info("DynamoDB cid_cache is empty.")
            return None
        latest = max(items, key=lambda x: int(x.get('epoch', 0)))
        return {'cid': latest['cid'], 'base_url': latest['base_url']}
