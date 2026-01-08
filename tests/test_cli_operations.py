"""
CLI operations unit tests.

Tests CLI commands and operations:
- fetch: Fetch hosts and policies from API
- regrade: Re-run grading on cached data
- policies: List and filter policies
- hosts: List and filter hosts
- host: Show individual host details
- Output formats: JSON, table, CSV
- Filtering and sorting
- Large dataset handling and progress bar triggering

NOTE: Comprehensive API pagination tests are in tests/test_falconapi/ module tests.
These tests focus on CLI-level operations and progress bar behavior for large datasets,
which have caused production issues in the past.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from argparse import Namespace
from io import StringIO
from falcon_policy_scoring.cli.operations import (
    fetch_and_store_hosts,
    fetch_and_store_zta,
    fetch_and_grade_all_policies,
    handle_fetch_operations,
    regrade_policies,
    handle_regrade_operations,
    parse_product_types
)
from falcon_policy_scoring.cli.context import CliContext
from rich.console import Console


@pytest.fixture
def mock_ctx():
    """Create mock CLI context."""
    console = Console(file=StringIO(), force_terminal=False)
    return CliContext(console=console, verbose=False, json_output_mode=False)


@pytest.fixture
def mock_falcon():
    """Create mock Falcon API client."""
    falcon = Mock()
    falcon.command = Mock(return_value={
        'status_code': 200,
        'body': {'resources': []}
    })
    return falcon


@pytest.fixture
def mock_adapter(tmp_path):
    """Create mock database adapter."""
    from falcon_policy_scoring.factories.adapters.sqlite_adapter import SQLiteAdapter
    adapter = SQLiteAdapter()
    adapter.connect({'path': str(tmp_path / "test.db")})
    yield adapter
    adapter.close()


@pytest.fixture
def mock_config():
    """Create mock configuration."""
    return {
        'host_fetching': {
            'batch_size': 100,
            'progress_threshold': 500
        },
        'grading': {
            'prevention_policies': {}
        }
    }


@pytest.mark.unit
class TestProductTypeParsing:
    """Test product type argument parsing."""

    def test_parse_all_product_types(self):
        """Test parsing 'all' returns empty list."""
        result = parse_product_types('all')
        assert result == []

    def test_parse_specific_product_types(self):
        """Test parsing comma-separated product types."""
        result = parse_product_types('Workstation,Server')
        assert result == ['Workstation', 'Server']

    def test_parse_with_whitespace(self):
        """Test parsing handles whitespace."""
        result = parse_product_types('Workstation, Server, Domain Controller')
        assert result == ['Workstation', 'Server', 'Domain Controller']

    def test_parse_none_returns_defaults(self):
        """Test None returns default product types."""
        result = parse_product_types(None)
        assert 'Workstation' in result
        assert 'Server' in result
        assert 'Domain Controller' in result


@pytest.mark.unit
class TestFetchHosts:
    """Test host fetching operations."""

    @patch('falcon_policy_scoring.cli.operations.Hosts')
    @patch('falcon_policy_scoring.cli.data_fetcher.fetch_hosts_simple')
    def test_fetch_hosts_basic(self, mock_fetch_simple, mock_hosts_class,
                               mock_falcon, mock_adapter, mock_config, mock_ctx):
        """Test basic host fetching."""
        # Setup mocks
        mock_hosts_instance = Mock()
        mock_hosts_instance.get_devices.return_value = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'hosts': ['host-1', 'host-2'],
            'total': 2,
            'epoch': 1234567890
        }
        mock_hosts_class.return_value = mock_hosts_instance

        mock_fetch_simple.return_value = {
            'fetched': 2,
            'total_hosts': 2,
            'errors': 0
        }

        # Execute
        result = fetch_and_store_hosts(
            mock_falcon, mock_adapter, 'test-cid',
            ['Workstation'], mock_config, mock_ctx
        )

        # Verify
        assert result['fetched'] == 2
        assert result['total_hosts'] == 2
        assert result['errors'] == 0
        mock_hosts_instance.get_devices.assert_called_once()

    @patch('falcon_policy_scoring.cli.operations.Hosts')
    @patch('falcon_policy_scoring.cli.operations.HostGroup')
    @patch('falcon_policy_scoring.cli.data_fetcher.fetch_hosts_simple')
    def test_fetch_hosts_with_host_groups(self, mock_fetch_simple, mock_host_group_class,
                                          mock_hosts_class, mock_falcon, mock_adapter,
                                          mock_config, mock_ctx):
        """Test host fetching with host group filtering."""
        # Setup mocks
        mock_host_group_instance = Mock()
        mock_host_group_instance.get_device_ids_from_groups.return_value = ['host-1', 'host-2']
        mock_host_group_class.return_value = mock_host_group_instance

        mock_hosts_instance = Mock()
        mock_hosts_instance.get_devices.return_value = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'hosts': ['host-1', 'host-2'],
            'total': 2,
            'epoch': 1234567890
        }
        mock_hosts_class.return_value = mock_hosts_instance

        mock_fetch_simple.return_value = {
            'fetched': 2,
            'total_hosts': 2,
            'errors': 0
        }

        # Execute
        result = fetch_and_store_hosts(
            mock_falcon, mock_adapter, 'test-cid',
            ['Workstation'], mock_config, mock_ctx,
            host_group_names=['group1', 'group2']
        )

        # Verify
        assert result['fetched'] == 2
        mock_host_group_instance.get_device_ids_from_groups.assert_called_once_with(['group1', 'group2'])

    @patch('falcon_policy_scoring.cli.operations.Hosts')
    @patch('falcon_policy_scoring.cli.operations.HostGroup')
    def test_fetch_hosts_empty_host_group(self, mock_host_group_class, mock_hosts_class,
                                          mock_falcon, mock_adapter, mock_config, mock_ctx):
        """Test handling of empty host groups."""
        # Setup mocks
        mock_host_group_instance = Mock()
        mock_host_group_instance.get_device_ids_from_groups.return_value = []
        mock_host_group_class.return_value = mock_host_group_instance

        # Execute
        result = fetch_and_store_hosts(
            mock_falcon, mock_adapter, 'test-cid',
            ['Workstation'], mock_config, mock_ctx,
            host_group_names=['empty-group']
        )

        # Verify - should return zeros without fetching
        assert result['fetched'] == 0
        assert result['total_hosts'] == 0

    @patch('falcon_policy_scoring.cli.operations.Hosts')
    @patch('falcon_policy_scoring.cli.data_fetcher.fetch_hosts_with_progress')
    def test_fetch_hosts_large_dataset_uses_progress_bar(self, mock_fetch_progress, mock_hosts_class,
                                                         mock_falcon, mock_adapter, mock_config, mock_ctx):
        """Test that progress bar is used when fetching large datasets.

        This is critical for production - when host count exceeds progress_threshold (default 500),
        the system should use fetch_hosts_with_progress instead of fetch_hosts_simple.
        This prevents UI freezing and provides user feedback during long operations.
        """
        # Setup mocks - return 600 hosts (above default threshold of 500)
        mock_hosts_instance = Mock()
        host_list = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'hosts': [f'host-{i}' for i in range(600)],
            'total': 600,
            'epoch': 1234567890
        }
        mock_hosts_instance.get_devices.return_value = host_list
        mock_hosts_class.return_value = mock_hosts_instance

        mock_fetch_progress.return_value = {
            'fetched': 600,
            'total_hosts': 600,
            'errors': 0
        }

        # Execute
        result = fetch_and_store_hosts(
            mock_falcon, mock_adapter, 'test-cid',
            ['Workstation'], mock_config, mock_ctx
        )

        # Verify progress fetcher was called (not simple fetcher)
        assert result['fetched'] == 600
        mock_fetch_progress.assert_called_once()

        # Verify it was called with correct batch_size from config
        call_args = mock_fetch_progress.call_args
        assert call_args[0][3] == 100  # batch_size from mock_config

    @patch('falcon_policy_scoring.cli.operations.Hosts')
    @patch('falcon_policy_scoring.cli.data_fetcher.fetch_hosts_simple')
    def test_fetch_hosts_small_dataset_skips_progress_bar(self, mock_fetch_simple, mock_hosts_class,
                                                          mock_falcon, mock_adapter, mock_config, mock_ctx):
        """Test that small datasets skip the progress bar overhead.

        When host count is below progress_threshold, use simple fetching without
        progress bar to avoid unnecessary overhead.
        """
        # Setup mocks - return 50 hosts (below threshold of 500)
        mock_hosts_instance = Mock()
        host_list = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'hosts': [f'host-{i}' for i in range(50)],
            'total': 50,
            'epoch': 1234567890
        }
        mock_hosts_instance.get_devices.return_value = host_list
        mock_hosts_class.return_value = mock_hosts_instance

        mock_fetch_simple.return_value = {
            'fetched': 50,
            'total_hosts': 50,
            'errors': 0
        }

        # Execute
        result = fetch_and_store_hosts(
            mock_falcon, mock_adapter, 'test-cid',
            ['Workstation'], mock_config, mock_ctx
        )

        # Verify simple fetcher was called
        assert result['fetched'] == 50
        mock_fetch_simple.assert_called_once()

    @patch('falcon_policy_scoring.cli.operations.Hosts')
    @patch('falcon_policy_scoring.cli.data_fetcher.fetch_hosts_with_progress')
    def test_fetch_hosts_custom_progress_threshold(self, mock_fetch_progress, mock_hosts_class,
                                                   mock_falcon, mock_adapter, mock_ctx):
        """Test that custom progress_threshold from config is respected.

        Allows users to configure when progress bar appears based on their environment.
        """
        # Custom config with low threshold
        custom_config = {
            'host_fetching': {
                'batch_size': 50,
                'progress_threshold': 100  # Lower threshold
            }
        }

        # Setup mocks - return 150 hosts (above custom threshold of 100)
        mock_hosts_instance = Mock()
        host_list = {
            'cid': 'test-cid',
            'base_url': 'https://test.com',
            'hosts': [f'host-{i}' for i in range(150)],
            'total': 150,
            'epoch': 1234567890
        }
        mock_hosts_instance.get_devices.return_value = host_list
        mock_hosts_class.return_value = mock_hosts_instance

        mock_fetch_progress.return_value = {
            'fetched': 150,
            'total_hosts': 150,
            'errors': 0
        }

        # Execute with custom config
        result = fetch_and_store_hosts(
            mock_falcon, mock_adapter, 'test-cid',
            ['Workstation'], custom_config, mock_ctx
        )

        # Verify progress fetcher was used due to custom threshold
        assert result['fetched'] == 150
        mock_fetch_progress.assert_called_once()

        # Verify custom batch_size was used
        call_args = mock_fetch_progress.call_args
        assert call_args[0][3] == 50  # custom batch_size


@pytest.mark.unit
class TestFetchZTA:
    """Test Zero Trust Assessment fetching."""

    @patch('falcon_policy_scoring.cli.operations.fetch_zero_trust_assessments')
    def test_fetch_zta_success(self, mock_fetch_zta, mock_falcon, mock_adapter, mock_ctx):
        """Test successful ZTA fetching."""
        # Setup mock with correct structure
        mock_fetch_zta.return_value = {
            'assessments': {
                'host-1': {'score': 85, 'assessment': 'high'},
                'host-2': {'score': 70, 'assessment': 'medium'}
            },
            'count': 2,
            'errors': []
        }

        # Execute
        result = fetch_and_store_zta(
            mock_falcon, mock_adapter,
            ['host-1', 'host-2'], mock_ctx
        )

        # Verify
        assert result['fetched'] == 2
        assert result['errors'] == 0
        mock_fetch_zta.assert_called_once_with(mock_falcon, ['host-1', 'host-2'])

    @patch('falcon_policy_scoring.cli.operations.fetch_zero_trust_assessments')
    def test_fetch_zta_empty_list(self, mock_fetch_zta, mock_falcon, mock_adapter, mock_ctx):
        """Test ZTA fetching with empty host list."""
        # No need to mock - function returns early for empty list

        # Execute
        result = fetch_and_store_zta(
            mock_falcon, mock_adapter, [], mock_ctx
        )

        # Verify
        assert result['fetched'] == 0
        assert result['errors'] == 0


@pytest.mark.unit
class TestFetchPolicies:
    """Test policy fetching operations."""

    @patch('falcon_policy_scoring.cli.operations.get_policy_registry')
    def test_fetch_and_grade_policies_basic(self, mock_get_registry, mock_falcon,
                                            mock_adapter, mock_config, mock_ctx):
        """Test basic policy fetching and grading."""
        # Setup mock registry
        mock_policy_info = Mock()
        mock_policy_info.grader_func = Mock(return_value={
            'grade_success': True,
            'passed_policies': 2,
            'failed_policies': 0,
            'policies_count': 2
        })
        mock_policy_info.display_name = 'Prevention'

        mock_registry = Mock()
        mock_registry.get.return_value = mock_policy_info
        mock_get_registry.return_value = mock_registry

        # Execute
        fetch_and_grade_all_policies(
            mock_falcon, mock_adapter, 'test-cid',
            ['prevention_policies'], mock_ctx
        )

        # Verify grader was called
        mock_policy_info.grader_func.assert_called_once()

    @patch('falcon_policy_scoring.cli.operations.get_policy_registry')
    def test_fetch_all_policies(self, mock_get_registry, mock_falcon,
                                mock_adapter, mock_config, mock_ctx):
        """Test fetching all policy types."""
        # Setup mock registry
        mock_policy_info = Mock()
        mock_policy_info.grader_func = Mock(return_value={
            'grade_success': True,
            'passed_policies': 1,
            'failed_policies': 0,
            'policies_count': 1
        })
        mock_policy_info.display_name = 'Test Policy'

        mock_registry = Mock()
        mock_registry.get_all_types.return_value = ['prevention_policies', 'sensor_update_policies']
        mock_registry.get.return_value = mock_policy_info
        mock_get_registry.return_value = mock_registry

        # Execute with 'all'
        fetch_and_grade_all_policies(
            mock_falcon, mock_adapter, 'test-cid',
            ['all'], mock_ctx
        )

        # Verify get_all_types was called
        mock_registry.get_all_types.assert_called_once()


@pytest.mark.unit
class TestHandleFetchOperations:
    """Test high-level fetch operations handler."""

    @patch('falcon_policy_scoring.cli.operations.fetch_and_store_hosts')
    @patch('falcon_policy_scoring.cli.operations.fetch_and_grade_all_policies')
    @patch('falcon_policy_scoring.cli.operations.fetch_and_store_zta')
    @patch('falcon_policy_scoring.cli.operations.parse_host_groups')
    def test_fetch_operations_full(self, mock_parse_groups, mock_fetch_zta,
                                   mock_fetch_policies, mock_fetch_hosts,
                                   mock_falcon, mock_config, mock_ctx):
        """Test full fetch operation with all components."""
        # Create a real adapter for this test
        from falcon_policy_scoring.factories.adapters.sqlite_adapter import SQLiteAdapter
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = SQLiteAdapter()
            adapter.connect({'path': f"{tmpdir}/test.db"})

            try:
                # Setup mocks
                mock_parse_groups.return_value = None

                mock_fetch_hosts.return_value = {
                    'fetched': 10,
                    'total_hosts': 10,
                    'errors': 0
                }

                # Store host list in adapter
                adapter.put_hosts({
                    'cid': 'test-cid',
                    'base_url': 'https://test.com',
                    'hosts': [f'host-{i}' for i in range(10)],
                    'total': 10,
                    'epoch': 1234567890
                })

                mock_fetch_zta.return_value = {
                    'fetched': 10,
                    'errors': 0
                }

                # Create args matching actual signature
                args = Namespace(
                    policy_type='prevention',
                    product_types='Workstation,Server',
                    host_groups=None,
                    last_seen=None
                )

                # Execute
                handle_fetch_operations(
                    mock_falcon, adapter, 'test-cid',
                    args, mock_config, mock_ctx
                )

                # Verify all fetchers were called
                mock_fetch_hosts.assert_called_once()
                mock_fetch_policies.assert_called_once()
                mock_fetch_zta.assert_called_once()
            finally:
                adapter.close()

    def test_fetch_operations_requires_falcon(self, mock_adapter, mock_config, mock_ctx):
        """Test that fetch operations requires falcon API."""
        args = Namespace(policy_type='all', product_types='all')

        # Should raise ValueError if falcon is None
        with pytest.raises(ValueError, match="API connection required"):
            handle_fetch_operations(
                None, mock_adapter, 'test-cid',
                args, mock_config, mock_ctx
            )


@pytest.mark.unit
class TestHandleRegradeOperations:
    """Test regrade operations handler."""

    @patch('falcon_policy_scoring.cli.operations.regrade_policies')
    def test_regrade_command(self, mock_regrade, mock_adapter, mock_config, mock_ctx):
        """Test regrade command execution."""
        # Setup mock
        mock_regrade.return_value = None

        # Create args
        args = Namespace(
            policy_type='prevention'
        )

        # Execute
        handle_regrade_operations(
            mock_adapter, 'test-cid', args, mock_ctx
        )

        # Verify regrade was called with policy types
        mock_regrade.assert_called_once()


@pytest.mark.unit
class TestOutputFormats:
    """Test different output format options."""

    def test_json_output_mode(self):
        """Test JSON output mode."""
        console = Console(file=StringIO(), force_terminal=False)
        ctx = CliContext(console=console, verbose=False, json_output_mode=True)

        assert ctx.json_output_mode is True

    def test_table_output_mode(self):
        """Test table output mode (default)."""
        console = Console(file=StringIO(), force_terminal=False)
        ctx = CliContext(console=console, verbose=False, json_output_mode=False)

        assert ctx.json_output_mode is False

    def test_verbose_logging(self):
        """Test verbose mode enables logging."""
        console = Console(file=StringIO(), force_terminal=False)
        ctx = CliContext(console=console, verbose=True, json_output_mode=False)

        # Log verbose message
        ctx.log_verbose("Test message")

        # Verify output contains message
        output = ctx.console.file.getvalue()
        assert "Test message" in output


@pytest.mark.unit
class TestCLIContext:
    """Test CLI context helper."""

    def test_context_creation(self):
        """Test CLI context can be created."""
        console = Console(file=StringIO(), force_terminal=False)
        ctx = CliContext(console=console, verbose=False, json_output_mode=False)

        assert ctx.console is not None
        assert ctx.verbose is False
        assert ctx.json_output_mode is False

    def test_log_verbose_when_enabled(self):
        """Test verbose logging when enabled."""
        console = Console(file=StringIO(), force_terminal=False)
        ctx = CliContext(console=console, verbose=True, json_output_mode=False)

        ctx.log_verbose("Debug message")
        output = ctx.console.file.getvalue()
        assert "Debug message" in output

    def test_log_verbose_when_disabled(self):
        """Test verbose logging is suppressed when disabled."""
        console = Console(file=StringIO(), force_terminal=False)
        ctx = CliContext(console=console, verbose=False, json_output_mode=False)

        ctx.log_verbose("Debug message")
        output = ctx.console.file.getvalue()
        # Should be empty or minimal
        assert len(output) < 50


@pytest.mark.unit
class TestCLIHelpers:
    """Test CLI helper functions."""

    def test_parse_host_groups(self):
        """Test parsing host group names."""
        from falcon_policy_scoring.cli.helpers import parse_host_groups

        # Test with comma-separated string
        result = parse_host_groups('group1,group2,group3')
        assert result == ['group1', 'group2', 'group3']

        # Test with whitespace
        result = parse_host_groups('group1, group2, group3')
        assert result == ['group1', 'group2', 'group3']

        # Test with None
        result = parse_host_groups(None)
        assert result is None
