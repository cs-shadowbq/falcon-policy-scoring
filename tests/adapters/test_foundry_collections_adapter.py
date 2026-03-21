"""
Foundry Collections adapter tests (fully mocked, no live Falcon API required).

All falconpy APIHarnessV2.command() calls are intercepted via unittest.mock.
"""

import json
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers to build mock falconpy responses
# ---------------------------------------------------------------------------

def _ok_list(keys):
    """Simulate ListObjects 200 response."""
    return {'status_code': 200, 'body': {'resources': keys}}


def _ok_put():
    """Simulate PutObject 200 response."""
    return {'status_code': 200, 'body': {}}


def _not_found():
    """Simulate GetObject / Describe 404 response."""
    return {'status_code': 404, 'body': {'errors': [{'message': 'Not found'}]}}


def _bytes_response(payload):
    """Simulate GetObject returning raw JSON bytes (success path)."""
    return json.dumps(payload).encode('utf-8')


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_falcon():
    """Return a MagicMock that replaces APIHarnessV2."""
    return MagicMock()


@pytest.fixture
def foundry_adapter(mock_falcon):
    """FoundryCollectionsAdapter connected with all collections present."""
    from falcon_policy_scoring.factories.adapters.foundry_collections_adapter import FoundryCollectionsAdapter

    # _verify_collections: every DescribeCollection returns 200
    mock_falcon.command.return_value = {'status_code': 200, 'body': {}}

    with patch(
        'falcon_policy_scoring.factories.adapters.foundry_collections_adapter.APIHarnessV2',
        return_value=mock_falcon,
    ):
        adapter = FoundryCollectionsAdapter()
        adapter.connect({'app_id': 'test-app'})
        # Reset mock after connect so only test-specific calls are tracked
        mock_falcon.command.reset_mock()
        yield adapter, mock_falcon
        adapter.close()


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsConnection:
    def test_connect_sets_app_id(self, mock_falcon):
        from falcon_policy_scoring.factories.adapters.foundry_collections_adapter import FoundryCollectionsAdapter
        mock_falcon.command.return_value = {'status_code': 200, 'body': {}}
        with patch(
            'falcon_policy_scoring.factories.adapters.foundry_collections_adapter.APIHarnessV2',
            return_value=mock_falcon,
        ):
            adapter = FoundryCollectionsAdapter()
            adapter.connect({'app_id': 'my-app'})
            assert adapter._app_id == 'my-app'

    def test_connect_warns_on_missing_collection(self, mock_falcon, caplog):
        from falcon_policy_scoring.factories.adapters.foundry_collections_adapter import (
            FoundryCollectionsAdapter,
            _COLLECTION_NAMES,
        )
        import logging

        # Only the first collection returns 404; the rest return 200
        def side_effect(action, **kwargs):
            if action == 'DescribeCollection' and kwargs.get('collection_name') == _COLLECTION_NAMES[0]:
                return _not_found()
            return {'status_code': 200, 'body': {}}

        mock_falcon.command.side_effect = side_effect

        with patch(
            'falcon_policy_scoring.factories.adapters.foundry_collections_adapter.APIHarnessV2',
            return_value=mock_falcon,
        ):
            with caplog.at_level(logging.WARNING):
                adapter = FoundryCollectionsAdapter()
                adapter.connect({'app_id': 'test-app'})
            assert _COLLECTION_NAMES[0] in caplog.text

    def test_connect_raises_when_all_collections_missing(self, mock_falcon):
        from falcon_policy_scoring.factories.adapters.foundry_collections_adapter import FoundryCollectionsAdapter
        mock_falcon.command.return_value = _not_found()

        with patch(
            'falcon_policy_scoring.factories.adapters.foundry_collections_adapter.APIHarnessV2',
            return_value=mock_falcon,
        ):
            adapter = FoundryCollectionsAdapter()
            with pytest.raises(RuntimeError, match="None of the required Foundry Collections"):
                adapter.connect({'app_id': 'test-app'})

    def test_close_resets_state(self, foundry_adapter):
        adapter, _ = foundry_adapter
        adapter.close()
        assert adapter.falcon is None
        assert adapter._app_id is None


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsHosts:
    def test_put_and_get_hosts(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        payload = {
            'cid': 'CID001',
            'base_url': 'https://api.us2.crowdstrike.com',
            'epoch': 1700000000,
            'hosts': ['aid1', 'aid2'],
            'total': 2,
        }
        falcon.command.return_value = _ok_put()
        adapter.put_hosts(payload)

        expected = dict(payload)
        falcon.command.return_value = _bytes_response(expected)
        result = adapter.get_hosts('CID001')
        assert result is not None
        assert result['cid'] == 'CID001'
        assert result['hosts'] == ['aid1', 'aid2']

    def test_get_hosts_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_hosts('NOSUCHCID') is None


# ---------------------------------------------------------------------------
# Host records
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsHostRecords:
    def test_put_and_get_host(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        device = {'device_id': 'aid-abc', 'cid': 'CID001'}
        falcon.command.return_value = _ok_put()
        adapter.put_host(device, record_type=4)

        stored = dict(device, record_type=4, epoch=1234)
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_host('aid-abc', record_type=4)
        assert result is not None
        assert result['device_id'] == 'aid-abc'

    def test_get_host_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_host('no-such-aid') is None


# ---------------------------------------------------------------------------
# ZTA
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsZTA:
    def test_put_and_get_zta(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        zta = {'score': 90}
        falcon.command.return_value = _ok_put()
        adapter.put_host_zta('aid-zta', zta)

        stored = {'device_id': 'aid-zta', 'epoch': 1234, 'data': zta}
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_host_zta('aid-zta')
        assert result == zta

    def test_get_zta_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_host_zta('no-such-aid') is None


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsPolicies:
    def test_put_and_get_policies(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        data = {'body': {'resources': [{'id': 'pol1'}]}}
        falcon.command.return_value = _ok_put()
        adapter.put_policies('prevention_policy', 'CID001', data)

        stored = {'cid': 'CID001', 'epoch': 1, 'policies': [{'id': 'pol1'}], 'total': 1}
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_policies('prevention_policy', 'CID001')
        assert result is not None
        assert result['total'] == 1

    def test_put_policies_stores_error_response(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _ok_put()
        adapter.put_policies('prevention_policy', 'CID001', {'error': 403})

        stored = {'cid': 'CID001', 'epoch': 1, 'policies': [], 'total': -1, 'error': '403'}
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_policies('prevention_policy', 'CID001')
        assert result['total'] == -1
        assert 'error' in result

    def test_get_policies_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_policies('prevention_policy', 'NOPE') is None


# ---------------------------------------------------------------------------
# Graded policies
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsGradedPolicies:
    def test_put_and_get_graded_policies(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        graded = [{'id': 'pol1', 'passed': True}, {'id': 'pol2', 'passed': False}]
        falcon.command.return_value = _ok_put()
        adapter.put_graded_policies('prevention_policy', 'CID001', graded)

        stored = {
            'cid': 'CID001', 'epoch': 1,
            'graded_policies': graded,
            'total_policies': 2, 'passed_policies': 1, 'failed_policies': 1,
        }
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_graded_policies('prevention_policy', 'CID001')
        assert result['total_policies'] == 2
        assert result['passed_policies'] == 1

    def test_put_graded_policies_noop_on_none(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        adapter.put_graded_policies('prevention_policy', 'CID001', None)
        # PutObject should NOT have been called
        for c in falcon.command.call_args_list:
            assert c.args[0] != 'PutObject'


# ---------------------------------------------------------------------------
# Firewall containers
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsFirewallContainers:
    def test_put_and_get(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        containers = {'pol1': {'id': 'pol1'}}
        falcon.command.return_value = _ok_put()
        adapter.put_firewall_policy_containers('CID001', containers)

        stored = {'cid': 'CID001', 'epoch': 1, 'policy_containers': containers, 'count': 1}
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_firewall_policy_containers('CID001')
        assert result['count'] == 1

    def test_get_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_firewall_policy_containers('NOPE') is None


# ---------------------------------------------------------------------------
# Device control settings
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsDeviceControl:
    def test_put_and_get(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        settings = {'pol1': {'id': 'pol1', 'classes': []}}
        falcon.command.return_value = _ok_put()
        adapter.put_device_control_policy_settings('CID001', settings)

        stored = {'cid': 'CID001', 'epoch': 1, 'policy_settings': settings, 'count': 1}
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_device_control_policy_settings('CID001')
        assert result['count'] == 1

    def test_get_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_device_control_policy_settings('NOPE') is None


# ---------------------------------------------------------------------------
# ODS coverage
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsODSCoverage:
    def test_put_and_get(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        cov = {'aid1': ['s1'], 'aid2': ['s2']}
        times = {'aid1': '2024-01-01T00:00:00Z'}
        falcon.command.return_value = _ok_put()
        adapter.put_ods_scan_coverage('CID001', cov, times)

        stored = {
            'cid': 'CID001', 'epoch': 1,
            'coverage_index': cov, 'count': 2,
            'last_compliant_scan_times': times,
        }
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_ods_scan_coverage('CID001')
        assert result['count'] == 2
        assert result['last_compliant_scan_times']['aid1'] == '2024-01-01T00:00:00Z'

    def test_get_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_ods_scan_coverage('NOPE') is None


# ---------------------------------------------------------------------------
# SCA coverage
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsSCACoverage:
    def test_put_and_get(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        cov = {'aid1': {'finding': 'low'}}
        falcon.command.return_value = _ok_put()
        adapter.put_sca_coverage('CID001', cov)

        stored = {'cid': 'CID001', 'epoch': 1, 'coverage_index': cov, 'count': 1}
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_sca_coverage('CID001')
        assert result['count'] == 1

    def test_get_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_sca_coverage('NOPE') is None


# ---------------------------------------------------------------------------
# CID cache
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsCIDCache:
    def test_put_and_get_cid(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _ok_put()
        adapter.put_cid('CID001', 'https://api.us2.crowdstrike.com')

        stored = {'base_url': 'https://api.us2.crowdstrike.com', 'cid': 'CID001', 'epoch': 1}
        falcon.command.return_value = _bytes_response(stored)
        result = adapter.get_cid('https://api.us2.crowdstrike.com')
        assert result == 'CID001'

    def test_get_cid_returns_none_on_404(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _not_found()
        assert adapter.get_cid('https://nowhere.example.com') is None

    def test_get_cached_cid_info(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        keys = ['https://api.us2.crowdstrike.com']
        record = {'base_url': 'https://api.us2.crowdstrike.com', 'cid': 'CID001', 'epoch': 1000}

        def command_side_effect(action, **kwargs):
            if action == 'ListObjects':
                return _ok_list(keys)
            if action == 'GetObject':
                return _bytes_response(record)
            return _ok_put()

        falcon.command.side_effect = command_side_effect
        result = adapter.get_cached_cid_info()
        assert result == {'cid': 'CID001', 'base_url': 'https://api.us2.crowdstrike.com'}

    def test_get_cached_cid_info_returns_none_when_empty(self, foundry_adapter):
        adapter, falcon = foundry_adapter
        falcon.command.return_value = _ok_list([])
        assert adapter.get_cached_cid_info() is None


# ---------------------------------------------------------------------------
# Factory integration
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFoundryCollectionsFactory:
    def test_factory_creates_foundry_adapter(self):
        from falcon_policy_scoring.factories.database_factory import DatabaseFactory
        from falcon_policy_scoring.factories.adapters.foundry_collections_adapter import FoundryCollectionsAdapter
        adapter = DatabaseFactory.create_adapter('foundry_collections')
        assert isinstance(adapter, FoundryCollectionsAdapter)

    def test_factory_get_config_key_foundry(self):
        from falcon_policy_scoring.factories.database_factory import DatabaseFactory
        assert DatabaseFactory.get_config_key('foundry_collections') == 'foundry_collections'
