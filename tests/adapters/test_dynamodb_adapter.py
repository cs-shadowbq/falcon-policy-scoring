"""
DynamoDB adapter tests (moto-backed, no live server required).

Tests use moto's mock_aws context to intercept all boto3 calls.
All 10 tables and the full adapter interface are covered.
"""

import pytest
from unittest.mock import patch

try:
    import boto3
    from moto import mock_aws
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not BOTO3_AVAILABLE,
    reason="boto3 and moto are required for DynamoDB adapter tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def dynamodb_adapter():
    """DynamoDB adapter backed by moto's in-process mock."""
    from falcon_policy_scoring.factories.adapters.dynamodb_adapter import DynamoDBAdapter
    with mock_aws():
        adapter = DynamoDBAdapter()
        adapter.connect({'region': 'us-east-1'})
        yield adapter
        adapter.close()


# ---------------------------------------------------------------------------
# Table creation
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBTables:
    """Verify that all 10 tables are created on connect."""

    EXPECTED_TABLES = [
        'hosts',
        'host_records',
        'host_zta',
        'policies',
        'graded_policies',
        'firewall_policy_containers',
        'device_control_policy_settings',
        'ods_scan_coverage',
        'sca_scan_coverage',
        'cid_cache',
    ]

    def test_all_tables_created(self, dynamodb_adapter):
        with mock_aws():
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            existing = {t.name for t in dynamodb.tables.all()}
            for table_name in self.EXPECTED_TABLES:
                assert table_name in existing, f"Table '{table_name}' was not created"

    def test_host_records_has_sort_key(self, dynamodb_adapter):
        """host_records must have record_type as its sort key (RANGE)."""
        with mock_aws():
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            table = dynamodb.Table('host_records')
            keys = {k['AttributeName']: k['KeyType'] for k in table.key_schema}
            assert keys.get('aid') == 'HASH'
            assert keys.get('record_type') == 'RANGE'


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBHosts:
    def test_put_and_get_hosts(self, dynamodb_adapter):
        payload = {
            'cid': 'CID001',
            'base_url': 'https://api.us2.crowdstrike.com',
            'epoch': 1700000000,
            'hosts': ['aid1', 'aid2'],
            'total': 2,
        }
        dynamodb_adapter.put_hosts(payload)
        result = dynamodb_adapter.get_hosts('CID001')
        assert result is not None
        assert result['cid'] == 'CID001'
        assert result['hosts'] == ['aid1', 'aid2']
        assert result['total'] == 2

    def test_get_hosts_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_hosts('NONEXISTENT') is None

    def test_put_hosts_overwrites_existing(self, dynamodb_adapter):
        payload = {'cid': 'CID001', 'base_url': '', 'epoch': 1, 'hosts': ['aid1'], 'total': 1}
        dynamodb_adapter.put_hosts(payload)
        payload2 = {'cid': 'CID001', 'base_url': '', 'epoch': 2, 'hosts': ['aid1', 'aid2'], 'total': 2}
        dynamodb_adapter.put_hosts(payload2)
        result = dynamodb_adapter.get_hosts('CID001')
        assert result['total'] == 2
        assert len(result['hosts']) == 2


# ---------------------------------------------------------------------------
# Host records
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBHostRecords:
    def test_put_and_get_host(self, dynamodb_adapter):
        device = {'device_id': 'aid-abc', 'cid': 'CID001', 'hostname': 'host1'}
        dynamodb_adapter.put_host(device, record_type=4)
        result = dynamodb_adapter.get_host('aid-abc', record_type=4)
        assert result is not None
        assert result['aid'] == 'aid-abc'
        assert result['record_type'] == 4

    def test_get_host_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_host('no-such-aid') is None

    def test_put_host_upsert(self, dynamodb_adapter):
        device = {'device_id': 'aid-abc', 'cid': 'CID001', 'hostname': 'host1'}
        dynamodb_adapter.put_host(device, record_type=4)
        device2 = {'device_id': 'aid-abc', 'cid': 'CID001', 'hostname': 'host1-renamed'}
        dynamodb_adapter.put_host(device2, record_type=4)
        result = dynamodb_adapter.get_host('aid-abc', record_type=4)
        assert result['data']['hostname'] == 'host1-renamed'


# ---------------------------------------------------------------------------
# ZTA
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBHostZTA:
    def test_put_and_get_zta(self, dynamodb_adapter):
        zta = {'score': 85, 'assessment': 'good'}
        dynamodb_adapter.put_host_zta('aid-zta', zta)
        result = dynamodb_adapter.get_host_zta('aid-zta')
        assert result == zta

    def test_get_zta_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_host_zta('no-such-aid') is None


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBPolicies:
    def test_put_and_get_policies(self, dynamodb_adapter):
        data = {'body': {'resources': [{'id': 'pol1', 'name': 'Default'}]}}
        dynamodb_adapter.put_policies('prevention_policy', 'CID001', data)
        result = dynamodb_adapter.get_policies('prevention_policy', 'CID001')
        assert result is not None
        assert result['total'] == 1
        assert result['policies'][0]['id'] == 'pol1'

    def test_get_policies_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_policies('prevention_policy', 'NOPE') is None

    def test_put_policies_handles_error_response(self, dynamodb_adapter):
        error_data = {'error': 403}
        dynamodb_adapter.put_policies('prevention_policy', 'CID001', error_data)
        result = dynamodb_adapter.get_policies('prevention_policy', 'CID001')
        assert result is not None
        assert result['total'] == -1
        assert 'error' in result

    def test_put_and_get_policies_chunked(self, dynamodb_adapter):
        """Policies larger than _CHUNK_SIZE (300 KB compressed) must round-trip correctly."""
        from falcon_policy_scoring.factories.adapters.dynamodb_adapter import _CHUNK_SIZE
        # Build a resource list whose compressed size will exceed one chunk
        large_resource = {'id': 'x', 'data': 'A' * 1000}
        # Each compressed chunk is ~300 KB; ~400 resources * 1 KB each easily exceeds 300 KB
        resources = [dict(large_resource, id=f'pol{i}') for i in range(400)]
        dynamodb_adapter.put_policies('sca_raw_findings', 'CID_LARGE', {'body': {'resources': resources}})
        result = dynamodb_adapter.get_policies('sca_raw_findings', 'CID_LARGE')
        assert result is not None
        assert result['total'] == 400
        assert result['policies'][0]['id'] == 'pol0'
        assert result['policies'][399]['id'] == 'pol399'


# ---------------------------------------------------------------------------
# Graded policies
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBGradedPolicies:
    def test_put_and_get_graded_policies(self, dynamodb_adapter):
        graded = [
            {'id': 'pol1', 'passed': True},
            {'id': 'pol2', 'passed': False},
        ]
        dynamodb_adapter.put_graded_policies('prevention_policy', 'CID001', graded)
        result = dynamodb_adapter.get_graded_policies('prevention_policy', 'CID001')
        assert result is not None
        assert result['total_policies'] == 2
        assert result['passed_policies'] == 1
        assert result['failed_policies'] == 1

    def test_get_graded_policies_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_graded_policies('prevention_policy', 'NOPE') is None

    def test_put_graded_policies_noop_on_none(self, dynamodb_adapter):
        dynamodb_adapter.put_graded_policies('prevention_policy', 'CID001', None)
        assert dynamodb_adapter.get_graded_policies('prevention_policy', 'CID001') is None


# ---------------------------------------------------------------------------
# Firewall containers
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBFirewallContainers:
    def test_put_and_get(self, dynamodb_adapter):
        containers = {'pol1': {'id': 'pol1', 'rules': []}}
        dynamodb_adapter.put_firewall_policy_containers('CID001', containers)
        result = dynamodb_adapter.get_firewall_policy_containers('CID001')
        assert result is not None
        assert result['count'] == 1
        assert 'pol1' in result['policy_containers']

    def test_get_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_firewall_policy_containers('NOPE') is None


# ---------------------------------------------------------------------------
# Device control policy settings
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBDeviceControlSettings:
    def test_put_and_get(self, dynamodb_adapter):
        settings = {'pol1': {'id': 'pol1', 'classes': []}}
        dynamodb_adapter.put_device_control_policy_settings('CID001', settings)
        result = dynamodb_adapter.get_device_control_policy_settings('CID001')
        assert result is not None
        assert result['count'] == 1

    def test_get_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_device_control_policy_settings('NOPE') is None


# ---------------------------------------------------------------------------
# ODS scan coverage
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBODSCoverage:
    def test_put_and_get(self, dynamodb_adapter):
        cov = {'aid1': ['scan1', 'scan2'], 'aid2': ['scan3']}
        times = {'aid1': '2024-01-01T00:00:00Z'}
        dynamodb_adapter.put_ods_scan_coverage('CID001', cov, times)
        result = dynamodb_adapter.get_ods_scan_coverage('CID001')
        assert result is not None
        assert result['count'] == 2
        assert result['last_compliant_scan_times']['aid1'] == '2024-01-01T00:00:00Z'

    def test_put_without_scan_times(self, dynamodb_adapter):
        cov = {'aid1': ['scan1']}
        dynamodb_adapter.put_ods_scan_coverage('CID002', cov)
        result = dynamodb_adapter.get_ods_scan_coverage('CID002')
        assert result['last_compliant_scan_times'] == {}

    def test_get_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_ods_scan_coverage('NOPE') is None


# ---------------------------------------------------------------------------
# SCA coverage
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBSCACoverage:
    def test_put_and_get(self, dynamodb_adapter):
        cov = {'aid1': {'finding': 'low'}, 'aid2': {'finding': 'high'}}
        dynamodb_adapter.put_sca_coverage('CID001', cov)
        result = dynamodb_adapter.get_sca_coverage('CID001')
        assert result is not None
        assert result['count'] == 2

    def test_get_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_sca_coverage('NOPE') is None


# ---------------------------------------------------------------------------
# CID cache
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBCIDCache:
    def test_put_and_get_cid(self, dynamodb_adapter):
        dynamodb_adapter.put_cid('CID001', 'https://api.us2.crowdstrike.com')
        result = dynamodb_adapter.get_cid('https://api.us2.crowdstrike.com')
        assert result == 'CID001'

    def test_get_cid_returns_none_for_missing(self, dynamodb_adapter):
        assert dynamodb_adapter.get_cid('https://nowhere.example.com') is None

    def test_get_cached_cid_info(self, dynamodb_adapter):
        dynamodb_adapter.put_cid('CID001', 'https://api.us2.crowdstrike.com')
        result = dynamodb_adapter.get_cached_cid_info()
        assert result is not None
        assert result['cid'] == 'CID001'
        assert result['base_url'] == 'https://api.us2.crowdstrike.com'

    def test_get_cached_cid_info_returns_none_when_empty(self, dynamodb_adapter):
        assert dynamodb_adapter.get_cached_cid_info() is None

    def test_get_cached_cid_info_returns_most_recent(self, dynamodb_adapter):
        """When multiple entries exist, the one with the highest epoch is returned."""
        with patch('falcon_policy_scoring.factories.adapters.dynamodb_adapter.epoch_now', return_value=1000):
            dynamodb_adapter.put_cid('CID_OLD', 'https://api.us1.crowdstrike.com')
        with patch('falcon_policy_scoring.factories.adapters.dynamodb_adapter.epoch_now', return_value=9999):
            dynamodb_adapter.put_cid('CID_NEW', 'https://api.us2.crowdstrike.com')
        result = dynamodb_adapter.get_cached_cid_info()
        assert result['cid'] == 'CID_NEW'


# ---------------------------------------------------------------------------
# Factory integration
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDynamoDBFactory:
    def test_factory_creates_dynamodb_adapter_for_dynamodb_type(self):
        from falcon_policy_scoring.factories.database_factory import DatabaseFactory
        from falcon_policy_scoring.factories.adapters.dynamodb_adapter import DynamoDBAdapter
        with mock_aws():
            adapter = DatabaseFactory.create_adapter('dynamodb')
            assert isinstance(adapter, DynamoDBAdapter)

    def test_factory_creates_dynamodb_adapter_for_dynalite_type(self):
        from falcon_policy_scoring.factories.database_factory import DatabaseFactory
        from falcon_policy_scoring.factories.adapters.dynamodb_adapter import DynamoDBAdapter
        adapter = DatabaseFactory.create_adapter('dynalite')
        assert isinstance(adapter, DynamoDBAdapter)

    def test_factory_get_config_key_dynalite(self):
        from falcon_policy_scoring.factories.database_factory import DatabaseFactory
        assert DatabaseFactory.get_config_key('dynalite') == 'dynalite'

    def test_factory_get_config_key_dynamodb(self):
        from falcon_policy_scoring.factories.database_factory import DatabaseFactory
        assert DatabaseFactory.get_config_key('dynamodb') == 'dynamodb'

    def test_factory_get_config_key_passthrough(self):
        from falcon_policy_scoring.factories.database_factory import DatabaseFactory
        assert DatabaseFactory.get_config_key('sqlite') == 'sqlite'
        assert DatabaseFactory.get_config_key('tiny_db') == 'tiny_db'
