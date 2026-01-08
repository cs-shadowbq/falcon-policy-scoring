"""
Tests for database adapter compliance and interface requirements.

Parametrized tests across SQLite and TinyDB adapters ensuring:
- Interface compliance with DatabaseAdapter base class
- CRUD operations for all data types (hosts, policies, ZTA, etc.)
- Cache behavior and epoch tracking
- Data integrity and idempotency
- Future MariaDB compatibility

These tests validate adapter behavior without external dependencies.
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from typing import Dict, Any

from falcon_policy_scoring.factories.adapters.sqlite_adapter import SQLiteAdapter
from falcon_policy_scoring.factories.adapters.tinydb_adapter import TinyDBAdapter
from falcon_policy_scoring.utils.core import epoch_now


# Parametrize across both adapters
@pytest.fixture(params=['sqlite', 'tinydb'])
def adapter(request, tmp_path):
    """Create adapter instance for testing.

    Parametrized to run all tests against both SQLite and TinyDB.
    Future: Add 'mariadb' to params when MariaDB adapter is implemented.
    """
    adapter_type = request.param

    if adapter_type == 'sqlite':
        db_path = tmp_path / "test.db"
        config = {'path': str(db_path)}
        adapter_instance = SQLiteAdapter()
    elif adapter_type == 'tinydb':
        db_path = tmp_path / "test.json"
        config = {'path': str(db_path)}
        adapter_instance = TinyDBAdapter()
    # elif adapter_type == 'mariadb':
    #     # Future: MariaDB adapter config
    #     config = {
    #         'host': 'localhost',
    #         'port': 3306,
    #         'database': 'test_db',
    #         'user': 'test_user',
    #         'password': 'test_pass'
    #     }
    #     adapter_instance = MariaDBAdapter()
    else:
        raise ValueError(f"Unknown adapter type: {adapter_type}")

    adapter_instance.connect(config)
    yield adapter_instance
    adapter_instance.close()


@pytest.mark.unit
class TestAdapterInterface:
    """Test that all adapters implement the required interface."""

    def test_adapter_has_required_methods(self, adapter):
        """Test that adapter implements all abstract methods."""
        required_methods = [
            'connect', 'close',
            'get_hosts_collection', 'get_host_records_collection',
            'create_record', 'update_record', 'update_or_create_record',
            'put_hosts', 'get_hosts',
            'put_host', 'get_host',
            'put_host_zta', 'get_host_zta',
            'put_policies', 'get_policies',
            'put_graded_policies', 'get_graded_policies',
            'put_firewall_policy_containers', 'get_firewall_policy_containers',
            'put_device_control_policy_settings', 'get_device_control_policy_settings',
            'put_cid', 'get_cid', 'get_cached_cid_info'
        ]

        for method in required_methods:
            assert hasattr(adapter, method), f"Adapter missing method: {method}"
            assert callable(getattr(adapter, method)), f"Method not callable: {method}"


@pytest.mark.unit
class TestHostsOperations:
    """Test hosts table CRUD operations."""

    def test_put_and_get_hosts(self, adapter):
        """Test storing and retrieving hosts list."""
        hosts_data = {
            'cid': 'test-cid-123',
            'base_url': 'https://api.crowdstrike.com',
            'epoch': epoch_now(),
            'hosts': ['host-1', 'host-2', 'host-3'],
            'total': 3
        }

        # Store hosts
        result = adapter.put_hosts(hosts_data)
        assert result is not None

        # Retrieve hosts
        retrieved = adapter.get_hosts('test-cid-123')
        assert retrieved is not None
        assert retrieved['cid'] == 'test-cid-123'
        assert retrieved['total'] == 3
        assert len(retrieved['hosts']) == 3
        assert 'host-1' in retrieved['hosts']

    def test_get_hosts_not_found(self, adapter):
        """Test retrieving non-existent hosts."""
        result = adapter.get_hosts('nonexistent-cid')
        assert result is None

    def test_put_hosts_replaces_existing(self, adapter):
        """Test that put_hosts replaces existing record."""
        hosts_data_v1 = {
            'cid': 'test-cid',
            'base_url': 'https://api.crowdstrike.com',
            'epoch': epoch_now(),
            'hosts': ['host-1'],
            'total': 1
        }

        hosts_data_v2 = {
            'cid': 'test-cid',
            'base_url': 'https://api.crowdstrike.com',
            'epoch': epoch_now() + 100,
            'hosts': ['host-1', 'host-2', 'host-3'],
            'total': 3
        }

        adapter.put_hosts(hosts_data_v1)
        adapter.put_hosts(hosts_data_v2)

        # Should retrieve the v2 data
        retrieved = adapter.get_hosts('test-cid')
        assert retrieved['total'] == 3
        assert len(retrieved['hosts']) == 3


@pytest.mark.unit
class TestHostRecordsOperations:
    """Test host_records table CRUD operations."""

    def test_put_and_get_host(self, adapter):
        """Test storing and retrieving individual host details."""
        device_details = {
            'cid': 'test-cid',
            'device_id': 'device-123',
            'hostname': 'test-host',
            'platform_name': 'Windows',
            'device_policies': {
                'prevention': {'policy_id': 'prev-1'},
                'sensor_update': {'policy_id': 'sensor-1'}
            }
        }

        adapter.put_host(device_details, record_type=4)

        retrieved = adapter.get_host('device-123', record_type=4)
        assert retrieved is not None
        assert retrieved['aid'] == 'device-123'
        assert retrieved['cid'] == 'test-cid'
        assert retrieved['data']['hostname'] == 'test-host'
        assert retrieved['data']['platform_name'] == 'Windows'

    def test_get_host_not_found(self, adapter):
        """Test retrieving non-existent host."""
        result = adapter.get_host('nonexistent-device')
        assert result is None

    def test_put_host_updates_existing(self, adapter):
        """Test that put_host updates existing record."""
        device_v1 = {
            'cid': 'test-cid',
            'device_id': 'device-123',
            'hostname': 'old-hostname'
        }

        device_v2 = {
            'cid': 'test-cid',
            'device_id': 'device-123',
            'hostname': 'new-hostname',
            'platform_name': 'Linux'
        }

        adapter.put_host(device_v1)
        adapter.put_host(device_v2)

        retrieved = adapter.get_host('device-123')
        assert retrieved['data']['hostname'] == 'new-hostname'
        assert retrieved['data']['platform_name'] == 'Linux'

    def test_put_host_tracks_epoch(self, adapter):
        """Test that host records track epoch timestamps."""
        device_details = {
            'cid': 'test-cid',
            'device_id': 'device-123',
            'hostname': 'test-host'
        }

        before_epoch = epoch_now()
        adapter.put_host(device_details)
        after_epoch = epoch_now()

        retrieved = adapter.get_host('device-123')
        assert 'epoch' in retrieved
        assert before_epoch <= retrieved['epoch'] <= after_epoch


@pytest.mark.unit
class TestZTAOperations:
    """Test Zero Trust Assessment data operations."""

    def test_put_and_get_host_zta(self, adapter):
        """Test storing and retrieving ZTA data."""
        zta_data = {
            'aid': 'device-123',
            'cid': 'test-cid',
            'assessment': {
                'sensor_config': 85,
                'os': 90,
                'overall': 87,
                'version': '1.0'
            }
        }

        adapter.put_host_zta('device-123', zta_data)

        retrieved = adapter.get_host_zta('device-123')
        assert retrieved is not None
        assert retrieved['aid'] == 'device-123'
        assert retrieved['assessment']['sensor_config'] == 85
        assert retrieved['assessment']['overall'] == 87

    def test_get_host_zta_not_found(self, adapter):
        """Test retrieving non-existent ZTA data."""
        result = adapter.get_host_zta('nonexistent-device')
        assert result is None

    def test_put_host_zta_replaces_existing(self, adapter):
        """Test that ZTA data is replaced on update."""
        zta_v1 = {
            'aid': 'device-123',
            'assessment': {'overall': 70}
        }

        zta_v2 = {
            'aid': 'device-123',
            'assessment': {'overall': 95}
        }

        adapter.put_host_zta('device-123', zta_v1)
        adapter.put_host_zta('device-123', zta_v2)

        retrieved = adapter.get_host_zta('device-123')
        assert retrieved['assessment']['overall'] == 95


@pytest.mark.unit
class TestPoliciesOperations:
    """Test policies table operations."""

    def test_put_and_get_policies(self, adapter):
        """Test storing and retrieving policies."""
        # Policies are stored with API response format (body.resources)
        policies_data = {
            'body': {
                'resources': [
                    {
                        'id': 'policy-1',
                        'name': 'Test Policy',
                        'platform_name': 'Windows',
                        'enabled': True
                    },
                    {
                        'id': 'policy-2',
                        'name': 'Another Policy',
                        'platform_name': 'Linux',
                        'enabled': False
                    }
                ]
            }
        }

        adapter.put_policies('prevention_policies', 'test-cid', policies_data)

        retrieved = adapter.get_policies('prevention_policies', 'test-cid')
        assert retrieved is not None
        assert 'policies' in retrieved
        assert len(retrieved['policies']) == 2
        assert retrieved['policies'][0]['id'] == 'policy-1'

    def test_get_policies_not_found(self, adapter):
        """Test retrieving non-existent policies."""
        result = adapter.get_policies('prevention_policies', 'nonexistent-cid')
        assert result is None

    def test_put_policies_replaces_existing(self, adapter):
        """Test that policies are replaced on update."""
        policies_v1 = {'body': {'resources': [{'id': 'policy-1'}]}}
        policies_v2 = {'body': {'resources': [{'id': 'policy-1'}, {'id': 'policy-2'}]}}

        adapter.put_policies('prevention_policies', 'test-cid', policies_v1)
        adapter.put_policies('prevention_policies', 'test-cid', policies_v2)

        retrieved = adapter.get_policies('prevention_policies', 'test-cid')
        assert len(retrieved['policies']) == 2


@pytest.mark.unit
class TestGradedPoliciesOperations:
    """Test graded policies table operations."""

    def test_put_and_get_graded_policies(self, adapter):
        """Test storing and retrieving graded policy results."""
        graded_results = [
            {
                'policy_id': 'policy-1',
                'policy_name': 'Test Policy',
                'passed': True,
                'failures_count': 0,
                'checks_count': 5
            },
            {
                'policy_id': 'policy-2',
                'policy_name': 'Another Policy',
                'passed': False,
                'failures_count': 2,
                'checks_count': 5
            }
        ]

        adapter.put_graded_policies('prevention_policies', 'test-cid', graded_results)

        retrieved = adapter.get_graded_policies('prevention_policies', 'test-cid')
        assert retrieved is not None
        assert 'graded_policies' in retrieved
        assert len(retrieved['graded_policies']) == 2
        assert retrieved['graded_policies'][0]['passed'] is True
        assert retrieved['graded_policies'][1]['passed'] is False

    def test_get_graded_policies_not_found(self, adapter):
        """Test retrieving non-existent graded policies."""
        result = adapter.get_graded_policies('prevention_policies', 'nonexistent-cid')
        assert result is None

    def test_graded_policies_tracks_epoch(self, adapter):
        """Test that graded policies track epoch timestamps."""
        graded_results = [
            {'policy_id': 'policy-1', 'passed': True}
        ]

        before_epoch = epoch_now()
        adapter.put_graded_policies('prevention_policies', 'test-cid', graded_results)
        after_epoch = epoch_now()

        retrieved = adapter.get_graded_policies('prevention_policies', 'test-cid')
        assert 'epoch' in retrieved
        assert before_epoch <= retrieved['epoch'] <= after_epoch


@pytest.mark.unit
class TestFirewallContainersOperations:
    """Test firewall policy containers operations."""

    def test_put_and_get_firewall_containers(self, adapter):
        """Test storing and retrieving firewall containers."""
        containers_map = {
            'policy-1': {
                'default_inbound': 'DENY',
                'enforce': True,
                'test_mode': False
            },
            'policy-2': {
                'default_inbound': 'ALLOW',
                'enforce': False,
                'test_mode': True
            }
        }

        adapter.put_firewall_policy_containers('test-cid', containers_map)

        retrieved = adapter.get_firewall_policy_containers('test-cid')
        assert retrieved is not None
        # Data is stored in 'policy_containers' key
        assert 'policy_containers' in retrieved
        assert 'policy-1' in retrieved['policy_containers']
        assert retrieved['policy_containers']['policy-1']['default_inbound'] == 'DENY'
        assert retrieved['policy_containers']['policy-2']['test_mode'] is True

    def test_get_firewall_containers_not_found(self, adapter):
        """Test retrieving non-existent firewall containers."""
        result = adapter.get_firewall_policy_containers('nonexistent-cid')
        assert result is None


@pytest.mark.unit
class TestDeviceControlSettingsOperations:
    """Test device control policy settings operations."""

    def test_put_and_get_device_control_settings(self, adapter):
        """Test storing and retrieving device control settings."""
        settings_map = {
            'policy-1': {
                'settings': {
                    'usb_storage': 'block',
                    'bluetooth': 'allow'
                }
            },
            'policy-2': {
                'settings': {
                    'usb_storage': 'allow',
                    'bluetooth': 'block'
                }
            }
        }

        adapter.put_device_control_policy_settings('test-cid', settings_map)
        retrieved = adapter.get_device_control_policy_settings('test-cid')

        # Data is stored in 'policy_settings' key
        assert 'policy_settings' in retrieved
        assert 'policy-1' in retrieved['policy_settings']
        assert retrieved['policy_settings']['policy-1']['settings']['usb_storage'] == 'block'
        assert 'policy-2' in retrieved['policy_settings']
        assert retrieved['policy_settings']['policy-2']['settings']['bluetooth'] == 'block'

    def test_get_device_control_settings_not_found(self, adapter):
        """Test retrieving non-existent device control settings."""
        result = adapter.get_device_control_policy_settings('nonexistent-cid')
        assert result is None


@pytest.mark.unit
class TestCIDCaching:
    """Test CID caching operations."""

    def test_put_and_get_cid(self, adapter):
        """Test storing and retrieving cached CID."""
        adapter.put_cid('test-cid-123', 'https://api.crowdstrike.com')

        retrieved_cid = adapter.get_cid('https://api.crowdstrike.com')
        assert retrieved_cid == 'test-cid-123'

    def test_get_cid_not_found(self, adapter):
        """Test retrieving non-existent CID."""
        result = adapter.get_cid('https://nonexistent.com')
        assert result is None

    def test_put_cid_replaces_existing(self, adapter):
        """Test that CID cache is replaced on update."""
        adapter.put_cid('old-cid', 'https://api.crowdstrike.com')
        adapter.put_cid('new-cid', 'https://api.crowdstrike.com')

        retrieved = adapter.get_cid('https://api.crowdstrike.com')
        assert retrieved == 'new-cid'

    def test_get_cached_cid_info(self, adapter):
        """Test retrieving most recent CID info."""
        adapter.put_cid('test-cid', 'https://api.crowdstrike.com')

        cid_info = adapter.get_cached_cid_info()
        assert cid_info is not None
        assert cid_info['cid'] == 'test-cid'
        assert cid_info['base_url'] == 'https://api.crowdstrike.com'

    def test_get_cached_cid_info_empty(self, adapter):
        """Test retrieving CID info when cache is empty."""
        result = adapter.get_cached_cid_info()
        # Should return None or empty dict
        assert result is None or result == {}


@pytest.mark.unit
class TestDataIntegrity:
    """Test data integrity and consistency."""

    def test_json_serialization_complex_types(self, adapter):
        """Test that complex data types are properly serialized/deserialized."""
        complex_data = {
            'cid': 'test-cid',
            'device_id': 'device-123',
            'nested': {
                'list': [1, 2, 3],
                'dict': {'key': 'value'},
                'bool': True,
                'null': None
            },
            'array': [
                {'item': 1},
                {'item': 2}
            ]
        }

        adapter.put_host(complex_data)
        retrieved = adapter.get_host('device-123')

        assert retrieved['data']['nested']['list'] == [1, 2, 3]
        assert retrieved['data']['nested']['bool'] is True
        assert retrieved['data']['nested']['null'] is None
        assert len(retrieved['data']['array']) == 2

    def test_unicode_handling(self, adapter):
        """Test that Unicode characters are handled correctly."""
        unicode_data = {
            'cid': 'test-cid',
            'device_id': 'device-123',
            'hostname': 'test-机器-🖥️',
            'description': 'Système français, Gerät, システム'
        }

        adapter.put_host(unicode_data)
        retrieved = adapter.get_host('device-123')

        assert retrieved['data']['hostname'] == 'test-机器-🖥️'
        assert retrieved['data']['description'] == 'Système français, Gerät, システム'

    def test_empty_lists_and_dicts(self, adapter):
        """Test handling of empty lists and dictionaries."""
        empty_data = {
            'cid': 'test-cid',
            'device_id': 'device-123',
            'empty_list': [],
            'empty_dict': {},
            'nested': {
                'also_empty': []
            }
        }

        adapter.put_host(empty_data)
        retrieved = adapter.get_host('device-123')

        assert retrieved['data']['empty_list'] == []
        assert retrieved['data']['empty_dict'] == {}
        assert retrieved['data']['nested']['also_empty'] == []


@pytest.mark.unit
class TestIdempotency:
    """Test idempotent operations."""

    def test_put_hosts_idempotent(self, adapter):
        """Test that putting same hosts multiple times is idempotent."""
        hosts_data = {
            'cid': 'test-cid',
            'base_url': 'https://api.crowdstrike.com',
            'epoch': 12345,
            'hosts': ['host-1', 'host-2'],
            'total': 2
        }

        adapter.put_hosts(hosts_data)
        adapter.put_hosts(hosts_data)
        adapter.put_hosts(hosts_data)

        retrieved = adapter.get_hosts('test-cid')
        assert retrieved['total'] == 2
        assert len(retrieved['hosts']) == 2

    def test_put_graded_policies_idempotent(self, adapter):
        """Test that grading results can be stored multiple times."""
        graded_results = [
            {'policy_id': 'policy-1', 'passed': True}
        ]

        adapter.put_graded_policies('prevention_policies', 'test-cid', graded_results)
        adapter.put_graded_policies('prevention_policies', 'test-cid', graded_results)

        retrieved = adapter.get_graded_policies('prevention_policies', 'test-cid')
        assert len(retrieved['graded_policies']) == 1


@pytest.mark.unit
class TestMultiplePolicyTypes:
    """Test operations across multiple policy types."""

    def test_multiple_policy_types_independent(self, adapter):
        """Test that different policy types are stored independently."""
        prevention_data = {'body': {'resources': [{'id': 'prev-1'}]}}
        sensor_data = {'body': {'resources': [{'id': 'sensor-1'}]}}
        firewall_data = {'body': {'resources': [{'id': 'fw-1'}]}}

        adapter.put_policies('prevention_policies', 'test-cid', prevention_data)
        adapter.put_policies('sensor_update_policies', 'test-cid', sensor_data)
        adapter.put_policies('firewall_policies', 'test-cid', firewall_data)

        # Each should be retrievable independently
        prev = adapter.get_policies('prevention_policies', 'test-cid')
        sensor = adapter.get_policies('sensor_update_policies', 'test-cid')
        firewall = adapter.get_policies('firewall_policies', 'test-cid')

        assert prev['policies'][0]['id'] == 'prev-1'
        assert sensor['policies'][0]['id'] == 'sensor-1'
        assert firewall['policies'][0]['id'] == 'fw-1'

    def test_graded_policies_multiple_types(self, adapter):
        """Test graded policies for multiple types."""
        prevention_graded = [{'policy_id': 'prev-1', 'passed': True}]
        sensor_graded = [{'policy_id': 'sensor-1', 'passed': False}]

        adapter.put_graded_policies('prevention_policies', 'test-cid', prevention_graded)
        adapter.put_graded_policies('sensor_update_policies', 'test-cid', sensor_graded)

        prev_retrieved = adapter.get_graded_policies('prevention_policies', 'test-cid')
        sensor_retrieved = adapter.get_graded_policies('sensor_update_policies', 'test-cid')

        assert prev_retrieved['graded_policies'][0]['passed'] is True
        assert sensor_retrieved['graded_policies'][0]['passed'] is False


@pytest.mark.unit
class TestMultipleCIDs:
    """Test operations across multiple CIDs."""

    def test_hosts_per_cid_isolation(self, adapter):
        """Test that hosts are isolated per CID."""
        hosts_cid1 = {
            'cid': 'cid-1',
            'base_url': 'https://api.crowdstrike.com',
            'epoch': epoch_now(),
            'hosts': ['host-1', 'host-2'],
            'total': 2
        }

        hosts_cid2 = {
            'cid': 'cid-2',
            'base_url': 'https://api.crowdstrike.com',
            'epoch': epoch_now(),
            'hosts': ['host-3', 'host-4', 'host-5'],
            'total': 3
        }

        adapter.put_hosts(hosts_cid1)
        adapter.put_hosts(hosts_cid2)

        retrieved_cid1 = adapter.get_hosts('cid-1')
        retrieved_cid2 = adapter.get_hosts('cid-2')

        assert retrieved_cid1['total'] == 2
        assert retrieved_cid2['total'] == 3
        assert 'host-1' in retrieved_cid1['hosts']
        assert 'host-3' in retrieved_cid2['hosts']
        assert 'host-3' not in retrieved_cid1['hosts']

    def test_policies_per_cid_isolation(self, adapter):
        """Test that policies are isolated per CID."""
        policies_cid1 = {'body': {'resources': [{'id': 'policy-cid1'}]}}
        policies_cid2 = {'body': {'resources': [{'id': 'policy-cid2'}]}}

        adapter.put_policies('prevention_policies', 'cid-1', policies_cid1)
        adapter.put_policies('prevention_policies', 'cid-2', policies_cid2)

        retrieved_cid1 = adapter.get_policies('prevention_policies', 'cid-1')
        retrieved_cid2 = adapter.get_policies('prevention_policies', 'cid-2')

        assert retrieved_cid1['policies'][0]['id'] == 'policy-cid1'
        assert retrieved_cid2['policies'][0]['id'] == 'policy-cid2'


@pytest.mark.unit
class TestCloseOperation:
    """Test database connection closing."""

    def test_close_adapter(self, tmp_path):
        """Test that adapters can be closed cleanly."""
        # Test with SQLite
        sqlite_adapter = SQLiteAdapter()
        sqlite_config = {'path': str(tmp_path / "test_close.db")}
        sqlite_adapter.connect(sqlite_config)
        sqlite_adapter.put_cid('test-cid', 'https://test.com')
        sqlite_adapter.close()

        # Test with TinyDB
        tinydb_adapter = TinyDBAdapter()
        tinydb_config = {'path': str(tmp_path / "test_close.json")}
        tinydb_adapter.connect(tinydb_config)
        tinydb_adapter.put_cid('test-cid', 'https://test.com')
        tinydb_adapter.close()

        # Both should complete without error
        assert True
