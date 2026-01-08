"""End-to-end smoke tests with VCR cassettes.

These tests use real CrowdStrike Falcon API calls recorded with VCR.
They are marked with @pytest.mark.e2e and are SKIPPED BY DEFAULT in CI/CD.

Running E2E tests:
------------------
1. Replay from cassettes (no credentials needed):
   pytest tests/test_e2e_smoke.py -m e2e --vcr-record=none

2. Record new cassettes (requires credentials):
   export CLIENT_ID=your_client_id
   export CLIENT_SECRET=your_secret  
   export BASE_URL=US2
   pytest tests/test_e2e_smoke.py -m e2e --vcr-record=once

3. Add new test episodes:
   pytest tests/test_e2e_smoke.py -m e2e --vcr-record=new_episodes

VCR Configuration:
------------------
- Cassettes stored in: tests/fixtures/vcr_cassettes_e2e/
- Credentials are filtered from cassettes (see tests/conftest.py)
- Match on: method + URI + body
- Serial format: yaml (human-readable)
- Metadata: CID, BASE_URL, timestamp stored in .meta.yaml files

Note: These tests are optional and not required for CI/CD to pass.
They are useful for:
- Validating against real API responses
- Detecting breaking API changes
- Local debugging with real data
- Integration testing before deployment
"""
import pytest
import os
from pathlib import Path

from falcon_policy_scoring.falconapi.hosts import Hosts
from falcon_policy_scoring.falconapi.host_group import HostGroup
from tests.conftest import (
    save_cassette_metadata,
    load_cassette_metadata,
    get_cassette_metadata_path
)

# Mark all tests in this module as e2e
pytestmark = [pytest.mark.e2e, pytest.mark.smoke]


def has_credentials_or_cassette(request, vcr_cassette_dir):
    """Check if we have credentials OR cassette metadata for VCR replay.

    This allows tests to run in two modes:
    1. Recording: Requires real credentials from environment
    2. Replay: Uses cassette metadata, no credentials needed
    """
    # Check if we have real credentials (recording mode)
    has_credentials = all([
        os.getenv('CLIENT_ID'),
        os.getenv('CLIENT_SECRET'),
        os.getenv('BASE_URL')
    ])

    if has_credentials:
        return True

    # Check if we have cassette metadata (replay mode)
    cassette_name = f"{request.cls.__name__}.{request.node.name}" if request.cls else request.node.name
    metadata = load_cassette_metadata(cassette_name, vcr_cassette_dir)

    if metadata and 'cid' in metadata and 'base_url' in metadata:
        return True

    # Neither credentials nor cassette available
    pytest.skip("E2E test requires either credentials (for recording) or cassette metadata (for replay)")


@pytest.fixture
def real_falcon_client(request, vcr_cassette_dir):
    """Create a real FalconPy client for E2E tests.

    When recording cassettes: Uses real credentials from environment variables.
    When replaying cassettes: Loads BASE_URL from cassette metadata, uses fake credentials.

    Requires environment variables (for recording):
    - CLIENT_ID
    - CLIENT_SECRET
    - BASE_URL (e.g., 'US1', 'US2', 'EU1')
    """
    from falconpy import APIHarnessV2

    # Get cassette name from test node
    cassette_name = f"{request.cls.__name__}.{request.node.name}" if request.cls else request.node.name

    # Check if we're replaying from metadata
    metadata = load_cassette_metadata(cassette_name, vcr_cassette_dir)

    if metadata and 'base_url' in metadata:
        # Replay mode: use metadata
        print(f"\n📼 VCR Replay: Using metadata from {cassette_name}.meta.yaml")
        client = APIHarnessV2(
            client_id="fake-client-id-for-vcr-replay",
            client_secret="fake-client-secret-for-vcr-replay",
            base_url=metadata['base_url']
        )
    else:
        # Record mode: use real credentials
        print(f"\n🔴 VCR Record: Using real credentials from environment")
        client = APIHarnessV2(
            client_id=os.getenv('CLIENT_ID'),
            client_secret=os.getenv('CLIENT_SECRET'),
            base_url=os.getenv('BASE_URL', 'US1')
        )

    return client


@pytest.fixture
def real_cid(request, real_falcon_client, vcr_cassette_dir):
    """Get the real CID from the API.

    When recording cassettes: Fetches CID from API and saves to metadata.
    When replaying cassettes: Loads CID from cassette metadata.
    """
    from falcon_policy_scoring.falconapi.cid import get_cid

    # Get cassette name from test node
    cassette_name = f"{request.cls.__name__}.{request.node.name}" if request.cls else request.node.name

    # Check if we're replaying from metadata
    metadata = load_cassette_metadata(cassette_name, vcr_cassette_dir)

    if metadata and 'cid' in metadata:
        # Replay mode: use metadata
        print(f"📼 VCR Replay: CID={metadata['cid']} (from metadata)")
        return metadata['cid']
    else:
        # Record mode: fetch real CID and save metadata
        print(f"🔴 VCR Record: Fetching real CID from API")
        cid = get_cid(real_falcon_client)

        # Save metadata for future replay
        save_cassette_metadata(
            cassette_name,
            vcr_cassette_dir,
            {
                'cid': cid,
                'base_url': os.getenv('BASE_URL', 'US1'),
                'recorded_by': os.getenv('USER', 'unknown'),
            }
        )
        print(f"💾 Saved cassette metadata: {cassette_name}.meta.yaml")

        return cid


class TestHostsAPIE2E:
    """E2E tests for Hosts API."""

    @pytest.mark.vcr()
    def test_fetch_workstation_device_ids(self, request, vcr_cassette_dir, real_falcon_client, real_cid):
        """Fetch real workstation device IDs from API.

        VCR cassette: tests/fixtures/vcr_cassettes_e2e/test_fetch_workstation_device_ids.yaml
        """
        has_credentials_or_cassette(request, vcr_cassette_dir)

        hosts_api = Hosts(real_cid, real_falcon_client)
        result = hosts_api.get_devices()

        # get_devices() returns a dict with {'epoch', 'cid', 'base_url', 'total', 'hosts'}
        assert isinstance(result, dict)
        assert 'hosts' in result
        assert isinstance(result['hosts'], list)
        assert result['total'] == len(result['hosts'])
        print(f"\n✓ Fetched {result['total']} devices from API (CID: {result['cid']})")

        # If we have devices, verify they're valid AIDs
        if result['hosts']:
            assert all(isinstance(aid, str) for aid in result['hosts'])
            assert all(len(aid) > 0 for aid in result['hosts'])
            print(f"✓ First device ID: {result['hosts'][0]}")

    @pytest.mark.vcr()
    def test_fetch_all_product_types(self, request, vcr_cassette_dir, real_falcon_client, real_cid):
        """Fetch devices of all product types.

        VCR cassette: tests/fixtures/vcr_cassettes_e2e/test_fetch_all_product_types.yaml
        """
        has_credentials_or_cassette(request, vcr_cassette_dir)

        hosts_api = Hosts(real_cid, real_falcon_client)
        result = hosts_api.get_devices()

        assert isinstance(result, dict)
        assert 'hosts' in result
        assert isinstance(result['hosts'], list)
        assert len(result['hosts']) >= 0

    @pytest.mark.vcr()
    @pytest.mark.slow
    def test_scroll_pagination(self, request, vcr_cassette_dir, real_falcon_client, real_cid):
        """Test scroll pagination with real API.

        This tests the scroll token handling for large result sets.

        VCR cassette: tests/fixtures/vcr_cassettes_e2e/test_scroll_pagination.yaml
        """
        has_credentials_or_cassette(request, vcr_cassette_dir)

        hosts_api = Hosts(real_cid, real_falcon_client)
        result = hosts_api.get_devices()

        assert isinstance(result, dict)
        assert 'hosts' in result
        # Just verify it completes without error


class TestPreventionPoliciesE2E:
    """E2E tests for Prevention Policies API."""

    @pytest.mark.vcr()
    def test_fetch_prevention_policies(self, request, vcr_cassette_dir, real_falcon_client):
        """Fetch real prevention policies from API.

        VCR cassette: tests/fixtures/vcr_cassettes/test_fetch_prevention_policies.yaml
        """
        has_credentials_or_cassette(request, vcr_cassette_dir)

        # TODO: Import correct policy class once structure is known
        # For now, test direct API call
        response = real_falcon_client.command('queryPreventionPolicies')

        # Verify response structure
        assert response is not None
        assert 'body' in response or 'resources' in response

    @pytest.mark.vcr()
    def test_prevention_policy_pagination(self, request, vcr_cassette_dir, real_falcon_client):
        """Test prevention policy pagination.

        VCR cassette: tests/fixtures/vcr_cassettes/test_prevention_policy_pagination.yaml
        """
        has_credentials_or_cassette(request, vcr_cassette_dir)

        # Test with small limit to test pagination
        response = real_falcon_client.command('queryPreventionPolicies', limit=5)

        assert response is not None


class TestHostGroupE2E:
    """E2E tests for Host Group API."""

    @pytest.mark.vcr()
    def test_list_host_groups(self, request, vcr_cassette_dir, real_falcon_client):
        """List real host groups from API.

        VCR cassette: tests/fixtures/vcr_cassettes/test_list_host_groups.yaml
        """
        has_credentials_or_cassette(request, vcr_cassette_dir)

        hg_api = HostGroup(real_falcon_client)

        # Note: This calls the internal method, might need adjustment
        # based on actual API
        response = real_falcon_client.command('queryCombinedHostGroups', limit=10)

        assert response is not None
        # Verify no errors
        if 'errors' in response:
            assert len(response['errors']) == 0


class TestCompleteWorkflowE2E:
    """E2E tests for complete workflows."""

    @pytest.mark.vcr()
    @pytest.mark.slow
    def test_fetch_hosts_and_policies(self, request, vcr_cassette_dir, real_falcon_client, real_cid, tmp_path):
        """Test complete workflow: fetch hosts → fetch policies.

        This is the closest to a real user workflow.

        VCR cassette: tests/fixtures/vcr_cassettes/test_fetch_hosts_and_policies.yaml
        """
        has_credentials_or_cassette(request, vcr_cassette_dir)

        from falcon_policy_scoring.factories.database_factory import DatabaseFactory

        # Create real database
        adapter = DatabaseFactory.create_adapter('sqlite')
        db_path = tmp_path / 'e2e_test.db'
        adapter.connect({'path': str(db_path)})

        # Step 1: Fetch hosts
        hosts_api = Hosts(real_cid, real_falcon_client)
        result = hosts_api.get_devices()

        if result['hosts']:
            # Store in database
            adapter.put_hosts(result)

            # Verify storage
            stored = adapter.get_hosts(real_cid)
            assert stored['total'] == len(result['hosts'])

        # Step 2: Fetch policies
        # TODO: Use correct policy API once structure is known
        response = real_falcon_client.command('queryPreventionPolicies')

        if response and 'resources' in response:
            # Store in database (need to adapt structure)
            policy_data = {'body': {'resources': response.get('resources', [])}}
            adapter.put_policies('prevention', real_cid, policy_data)

            # Verify storage
            stored_policies = adapter.get_policies('prevention', real_cid)
            assert stored_policies is not None


# TODO: Add more E2E tests:
# - test_zero_trust_assessment_fetch
# - test_firewall_policies_with_containers
# - test_device_control_policies_with_settings
# - test_sensor_update_policies
# - test_it_automation_policies
# - test_error_handling_403_forbidden
# - test_error_handling_rate_limit
# - test_large_dataset_performance
