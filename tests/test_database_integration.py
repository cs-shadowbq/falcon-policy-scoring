"""Database integration tests.

These tests verify database adapter operations with real (temp) databases.
They test CRUD operations, persistence, and data isolation across multiple
data types (hosts, policies, graded policies, ZTA, etc).

These are integration tests because they test the database layer with real
database operations, but they don't test workflows across multiple application
layers (CLI → operations → data_fetcher → adapter).

Mark: @pytest.mark.integration
"""
import pytest
import tempfile
import shutil
from pathlib import Path

from falcon_policy_scoring.factories.database_factory import DatabaseFactory


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


@pytest.fixture
def temp_db_dir():
    """Create a temporary directory for test databases."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def test_config(temp_db_dir):
    """Create test configuration."""
    return {
        'database': {
            'type': 'sqlite',
            'path': str(Path(temp_db_dir) / 'test.db')
        },
        'batch_size': 100,
        'progress_threshold': 500
    }


@pytest.fixture
def test_adapter(test_config):
    """Create and connect a test database adapter."""
    adapter = DatabaseFactory.create_adapter(test_config['database']['type'])
    adapter.connect(test_config['database'])
    return adapter


class TestDatabaseIntegration:
    """Test database adapter integration with persistence."""

    def test_hosts_list_persistence(self, test_adapter):
        """Test storing and retrieving hosts list."""
        # Store hosts list
        test_adapter.put_hosts({
            'cid': 'test-cid',
            'base_url': 'US1',
            'hosts': ['aid1', 'aid2', 'aid3'],
            'total': 3
        })

        # Retrieve and verify
        hosts_list = test_adapter.get_hosts('test-cid')
        assert hosts_list is not None
        assert hosts_list['total'] == 3
        assert len(hosts_list['hosts']) == 3
        assert 'aid1' in hosts_list['hosts']

    def test_host_details_persistence(self, test_adapter):
        """Test storing and retrieving host details."""
        device_details = {
            'device_id': 'test-aid',
            'hostname': 'test-host',
            'platform_name': 'Windows',
            'cid': 'test-cid'
        }

        # Store host details
        test_adapter.put_host(device_details)

        # Retrieve and verify
        retrieved = test_adapter.get_host('test-aid')
        assert retrieved is not None
        assert retrieved['aid'] == 'test-aid'
        assert retrieved['data']['hostname'] == 'test-host'

    def test_policy_storage_and_retrieval(self, test_adapter):
        """Test storing and retrieving policies."""
        policy_data = {
            'body': {
                'resources': [
                    {'id': 'p1', 'name': 'Policy 1', 'enabled': True},
                    {'id': 'p2', 'name': 'Policy 2', 'enabled': False}
                ]
            }
        }

        # Store policies
        test_adapter.put_policies('prevention', 'test-cid', policy_data)

        # Retrieve and verify
        retrieved = test_adapter.get_policies('prevention', 'test-cid')
        assert retrieved is not None
        assert retrieved['total'] == 2
        assert len(retrieved['policies']) == 2
        assert retrieved['policies'][0]['id'] == 'p1'

    def test_graded_policies_persistence(self, test_adapter):
        """Test storing and retrieving graded policies."""
        graded_results = [
            {'id': 'p1', 'name': 'Policy 1', 'passed': True, 'score': 100},
            {'id': 'p2', 'name': 'Policy 2', 'passed': False, 'score': 60}
        ]

        # Store graded policies
        test_adapter.put_graded_policies('prevention', 'test-cid', graded_results)

        # Retrieve and verify
        retrieved = test_adapter.get_graded_policies('prevention', 'test-cid')
        assert retrieved is not None
        assert retrieved['total_policies'] == 2
        assert retrieved['passed_policies'] == 1
        assert retrieved['failed_policies'] == 1

    def test_multiple_policy_types(self, test_adapter):
        """Test storing multiple policy types for same CID."""
        prevention_data = {
            'body': {
                'resources': [{'id': 'prev1', 'name': 'Prevention Policy'}]
            }
        }
        firewall_data = {
            'body': {
                'resources': [{'id': 'fw1', 'name': 'Firewall Policy'}]
            }
        }

        # Store different policy types
        test_adapter.put_policies('prevention', 'test-cid', prevention_data)
        test_adapter.put_policies('firewall', 'test-cid', firewall_data)

        # Retrieve and verify both
        prev_retrieved = test_adapter.get_policies('prevention', 'test-cid')
        fw_retrieved = test_adapter.get_policies('firewall', 'test-cid')

        assert prev_retrieved['policies'][0]['id'] == 'prev1'
        assert fw_retrieved['policies'][0]['id'] == 'fw1'

    def test_cid_storage_and_retrieval(self, test_adapter):
        """Test CID storage and retrieval."""
        # Store CID
        test_adapter.put_cid('test-cid-123', 'US1')

        # Retrieve and verify
        retrieved_cid = test_adapter.get_cid('US1')
        assert retrieved_cid == 'test-cid-123'

    def test_zta_data_persistence(self, test_adapter):
        """Test Zero Trust Assessment data persistence."""
        zta_data = {
            'aid': 'test-aid',
            'cid': 'test-cid',
            'assessment': {
                'sensor_config': 85,
                'os': 90,
                'overall': 87
            },
            'modified_time': '2024-01-01T00:00:00Z'
        }

        # Store ZTA data
        test_adapter.put_host_zta('test-aid', zta_data)

        # Retrieve and verify
        retrieved = test_adapter.get_host_zta('test-aid')
        assert retrieved is not None
        assert retrieved['aid'] == 'test-aid'
        assert retrieved['assessment']['overall'] == 87


class TestDataAdapterOperations:
    """Test database adapter operations."""

    def test_update_existing_host(self, test_adapter):
        """Test updating existing host details."""
        initial_data = {
            'device_id': 'test-aid',
            'hostname': 'old-hostname',
            'platform_name': 'Windows',
            'cid': 'test-cid'
        }

        updated_data = {
            'device_id': 'test-aid',
            'hostname': 'new-hostname',
            'platform_name': 'Windows',
            'cid': 'test-cid'
        }

        # Store initial
        test_adapter.put_host(initial_data)

        # Update
        test_adapter.put_host(updated_data)

        # Retrieve and verify update
        retrieved = test_adapter.get_host('test-aid')
        assert retrieved['data']['hostname'] == 'new-hostname'

    def test_update_existing_policies(self, test_adapter):
        """Test updating existing policies."""
        initial_data = {
            'body': {
                'resources': [{'id': 'p1', 'name': 'Policy 1'}]
            }
        }

        updated_data = {
            'body': {
                'resources': [
                    {'id': 'p1', 'name': 'Policy 1 Updated'},
                    {'id': 'p2', 'name': 'Policy 2 New'}
                ]
            }
        }

        # Store initial
        test_adapter.put_policies('prevention', 'test-cid', initial_data)

        # Update
        test_adapter.put_policies('prevention', 'test-cid', updated_data)

        # Retrieve and verify update
        retrieved = test_adapter.get_policies('prevention', 'test-cid')
        assert retrieved['total'] == 2
        assert retrieved['policies'][0]['name'] == 'Policy 1 Updated'

    def test_query_nonexistent_data(self, test_adapter):
        """Test querying data that doesn't exist."""
        # Query non-existent hosts list
        hosts_list = test_adapter.get_hosts('nonexistent-cid')
        assert hosts_list is None

        # Query non-existent host details
        host_details = test_adapter.get_host('nonexistent-aid')
        assert host_details is None

        # Query non-existent policies
        policies = test_adapter.get_policies('prevention', 'nonexistent-cid')
        assert policies is None

    def test_multiple_cids_isolation(self, test_adapter):
        """Test that data for different CIDs is isolated."""
        # Store hosts for two different CIDs
        test_adapter.put_hosts({
            'cid': 'cid-1',
            'base_url': 'US1',
            'hosts': ['aid1', 'aid2'],
            'total': 2
        })

        test_adapter.put_hosts({
            'cid': 'cid-2',
            'base_url': 'EU1',
            'hosts': ['aid3', 'aid4', 'aid5'],
            'total': 3
        })

        # Retrieve and verify isolation
        cid1_hosts = test_adapter.get_hosts('cid-1')
        cid2_hosts = test_adapter.get_hosts('cid-2')

        assert cid1_hosts['total'] == 2
        assert cid2_hosts['total'] == 3
        assert cid1_hosts['hosts'] != cid2_hosts['hosts']


class TestFirewallPolicyContainers:
    """Test firewall policy container persistence."""

    def test_store_and_retrieve_firewall_containers(self, test_adapter):
        """Test storing and retrieving firewall policy containers."""
        containers_map = {
            'policy-1': [
                {'id': 'rule-1', 'name': 'Container 1', 'type': 'firewall'}
            ],
            'policy-2': [
                {'id': 'rule-2', 'name': 'Container 2', 'type': 'firewall'}
            ]
        }

        # Store containers
        test_adapter.put_firewall_policy_containers('test-cid', containers_map)

        # Retrieve and verify
        retrieved = test_adapter.get_firewall_policy_containers('test-cid')
        assert retrieved is not None
        assert 'policy-1' in retrieved['policy_containers']
        assert 'policy-2' in retrieved['policy_containers']
        assert len(retrieved['policy_containers']['policy-1']) == 1
        assert retrieved['policy_containers']['policy-1'][0]['name'] == 'Container 1'


class TestDeviceControlSettings:
    """Test device control policy settings persistence."""

    def test_store_and_retrieve_device_control_settings(self, test_adapter):
        """Test storing and retrieving device control settings."""
        settings_map = {
            'policy-1': {
                'id': 'settings-1',
                'custom_notifications': {
                    'enabled': True,
                    'message': 'Access denied'
                }
            },
            'policy-2': {
                'id': 'settings-2',
                'custom_notifications': {
                    'enabled': False,
                    'message': ''
                }
            }
        }

        # Store settings
        test_adapter.put_device_control_policy_settings('test-cid', settings_map)

        # Retrieve and verify
        retrieved = test_adapter.get_device_control_policy_settings('test-cid')
        assert retrieved is not None
        assert 'policy-1' in retrieved['policy_settings']
        assert 'policy-2' in retrieved['policy_settings']
        assert retrieved['policy_settings']['policy-1']['custom_notifications']['enabled'] is True
        assert retrieved['policy_settings']['policy-2']['custom_notifications']['enabled'] is False
