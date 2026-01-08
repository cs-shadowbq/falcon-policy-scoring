"""
Tests for FalconAPI Hosts module.

Critical focus on pagination testing due to production bugs.
Tests cover: scroll-based pagination, large datasets, token handling,
rate limiting, mid-pagination errors, and filter handling.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from falcon_policy_scoring.falconapi.hosts import Hosts


class TestHostsInitialization:
    """Test Hosts class initialization and filter building."""

    def test_hosts_init_no_filters(self):
        """Test initialization with no filters."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 100}}}
        }

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)

        assert hosts.cid == 'test-cid'
        assert hosts.falcon == mock_falcon
        assert hosts.limit == 10000
        assert hosts.filter is None
        assert hosts.total == 100

    def test_hosts_init_with_product_types(self):
        """Test initialization with product type filtering."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 50}}}
        }

        hosts = Hosts(
            cid='test-cid',
            falcon=mock_falcon,
            product_types=['Workstation', 'Server']
        )

        assert "product_type_desc:['Workstation','Server']" in hosts.filter
        assert hosts.total == 50

    def test_hosts_init_with_custom_filter(self):
        """Test initialization with custom FQL filter."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 75}}}
        }

        hosts = Hosts(
            cid='test-cid',
            falcon=mock_falcon,
            filter="last_seen:>'2024-01-01'"
        )

        assert "last_seen:>'2024-01-01'" in hosts.filter
        assert hosts.total == 75

    def test_hosts_init_with_small_device_id_list(self):
        """Test initialization with small device ID list (uses FQL)."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 10}}}
        }

        device_ids = [f'device-{i}' for i in range(10)]
        hosts = Hosts(
            cid='test-cid',
            falcon=mock_falcon,
            device_ids=device_ids
        )

        # Small list should be in FQL filter
        assert 'device_id:[' in hosts.filter
        assert hosts.device_ids_filter is not None

    def test_hosts_init_with_large_device_id_list(self):
        """Test initialization with large device ID list (uses post-filter)."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 500}}}
        }

        # Large list > 100 devices with additional filter
        device_ids = [f'device-{i}' for i in range(150)]
        hosts = Hosts(
            cid='test-cid',
            falcon=mock_falcon,
            device_ids=device_ids,
            filter="last_seen:>'2024-01-01'"
        )

        # Large list with other filters should NOT be in FQL
        # (will be post-filtered client-side)
        assert 'device_id:[' not in hosts.filter
        assert hosts.device_ids_filter is not None
        assert len(hosts.device_ids_filter) == 150

    def test_hosts_init_combined_filters(self):
        """Test initialization with multiple filter types combined."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 25}}}
        }

        hosts = Hosts(
            cid='test-cid',
            falcon=mock_falcon,
            filter="last_seen:>'2024-01-01'",
            product_types=['Workstation']
        )

        # Both filters should be combined with +
        assert "product_type_desc:['Workstation']" in hosts.filter
        assert "last_seen:>'2024-01-01'" in hosts.filter
        assert '+' in hosts.filter


class TestHostsDeviceCount:
    """Test device count queries."""

    def test_device_count_success(self):
        """Test successful device count query."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 500}}}
        }

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        count = hosts.device_count()

        assert count == 500
        mock_falcon.command.assert_called_with(
            "QueryDevicesByFilterScroll",
            limit=1,
            sort="device_id.desc",
            filter=None
        )

    def test_device_count_with_filter(self):
        """Test device count with FQL filter."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'meta': {'pagination': {'total': 150}}}
        }

        hosts = Hosts(
            cid='test-cid',
            falcon=mock_falcon,
            product_types=['Workstation']
        )

        # Check that filter was applied in count query
        call_args = mock_falcon.command.call_args_list[0]
        assert call_args[1]['filter'] is not None
        assert 'Workstation' in call_args[1]['filter']

    def test_device_count_api_error(self):
        """Test device count with API error."""
        mock_falcon = Mock()
        mock_falcon.command.return_value = {
            'status_code': 500,
            'body': {'errors': [{'code': 500, 'message': 'Internal server error'}]}
        }

        with pytest.raises(RuntimeError, match="Failed to query devices"):
            Hosts(cid='test-cid', falcon=mock_falcon)


class TestHostsPaginationSinglePage:
    """Test single-page response scenarios."""

    def test_get_devices_single_page(self):
        """Test fetching devices when all fit in a single page."""
        mock_falcon = Mock()

        # Mock device count
        mock_falcon.command.side_effect = [
            # First call: device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 50}}}
            },
            # Second call: get_devices() - single page
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(50)],
                    'meta': {'pagination': {'offset': None}}  # No more pages
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        assert result['total'] == 50
        assert len(result['hosts']) == 50
        assert result['cid'] == 'test-cid'
        assert 'epoch' in result
        assert 'base_url' in result

        # Verify only 2 API calls: 1 for count, 1 for data
        assert mock_falcon.command.call_count == 2

    def test_get_devices_empty_result(self):
        """Test fetching devices when no devices match filter."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 0}}}
            },
            # get_devices() - empty
            {
                'status_code': 200,
                'body': {
                    'resources': [],
                    'meta': {'pagination': {'offset': None}}
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        assert result['total'] == 0
        assert len(result['hosts']) == 0


class TestHostsPaginationMultiplePages:
    """Test multi-page pagination scenarios - CRITICAL for production."""

    def test_get_devices_two_pages(self):
        """Test fetching devices across 2 pages."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 150}}}
            },
            # Page 1
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100)],
                    'meta': {'pagination': {'offset': 'token-page-2'}}
                }
            },
            # Page 2 (final)
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100, 150)],
                    'meta': {'pagination': {'offset': None}}  # No more pages
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        assert result['total'] == 150
        assert len(result['hosts']) == 150
        assert mock_falcon.command.call_count == 3  # count + 2 pages

        # Verify second page used offset token
        second_page_call = mock_falcon.command.call_args_list[2]
        assert second_page_call[1]['offset'] == 'token-page-2'

    def test_get_devices_multiple_pages(self):
        """Test fetching devices across 5 pages."""
        mock_falcon = Mock()

        # Simulate 5 pages of 1000 devices each
        total_devices = 5000
        page_size = 1000

        responses = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': total_devices}}}
            }
        ]

        # Add 5 pages
        for page_num in range(5):
            start = page_num * page_size
            end = start + page_size
            has_next = page_num < 4  # Last page has no next token

            responses.append({
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(start, end)],
                    'meta': {
                        'pagination': {
                            'offset': f'token-page-{page_num + 2}' if has_next else None
                        }
                    }
                }
            })

        mock_falcon.command.side_effect = responses

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        assert result['total'] == 5000
        assert len(result['hosts']) == 5000
        assert mock_falcon.command.call_count == 6  # 1 count + 5 pages

    def test_get_devices_large_dataset_100_pages(self):
        """Test fetching 100+ pages - stress test for production scale."""
        mock_falcon = Mock()

        # Simulate 100 pages of 10000 devices each (max limit)
        total_devices = 1_000_000
        page_size = 10000
        num_pages = 100

        responses = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': total_devices}}}
            }
        ]

        # Add 100 pages
        for page_num in range(num_pages):
            start = page_num * page_size
            end = start + page_size
            has_next = page_num < (num_pages - 1)

            responses.append({
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(start, end)],
                    'meta': {
                        'pagination': {
                            'offset': f'token-page-{page_num + 2}' if has_next else None
                        }
                    }
                }
            })

        mock_falcon.command.side_effect = responses

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        assert result['total'] == 1_000_000
        assert len(result['hosts']) == 1_000_000
        assert mock_falcon.command.call_count == 101  # 1 count + 100 pages


class TestHostsPaginationTokenHandling:
    """Test pagination token handling edge cases."""

    def test_get_devices_token_expires_mid_pagination(self):
        """Test handling of expired scroll token during pagination."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 200}}}
            },
            # Page 1
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100)],
                    'meta': {'pagination': {'offset': 'token-page-2'}}
                }
            },
            # Page 2 - token expired error
            {
                'status_code': 400,
                'body': {
                    'errors': [{'code': 400, 'message': 'Invalid offset token'}]
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Should return partial results before error
        assert len(result['hosts']) == 100
        assert result['total'] == 100  # Updated to reflect what was fetched

    def test_get_devices_missing_offset_in_response(self):
        """Test handling of missing offset field in pagination response."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 100}}}
            },
            # Page with malformed response (missing offset)
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100)],
                    'meta': {'pagination': {}}  # Missing 'offset' key
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Should handle gracefully and stop
        assert result['total'] == 100
        assert len(result['hosts']) == 100

    def test_get_devices_empty_page_mid_pagination(self):
        """Test handling of unexpected empty page during pagination."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 200}}}
            },
            # Page 1
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100)],
                    'meta': {'pagination': {'offset': 'token-page-2'}}
                }
            },
            # Page 2 - empty resources (API bug?)
            {
                'status_code': 200,
                'body': {
                    'resources': [],  # Empty!
                    'meta': {'pagination': {'offset': 'token-page-3'}}
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Should stop on empty page
        assert len(result['hosts']) == 100


class TestHostsErrorHandling:
    """Test error handling scenarios."""

    def test_get_devices_api_error_first_page(self):
        """Test handling of API error on first page."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 100}}}
            },
            # First page - error
            {
                'status_code': 500,
                'body': {'errors': [{'code': 500, 'message': 'Internal server error'}]}
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Should return empty results after error
        assert result['total'] == 0
        assert len(result['hosts']) == 0

    def test_get_devices_network_error_mid_pagination(self):
        """Test handling of network error during pagination."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 200}}}
            },
            # Page 1
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100)],
                    'meta': {'pagination': {'offset': 'token-page-2'}}
                }
            },
            # Page 2 - network error
            {
                'status_code': 503,
                'body': {'errors': [{'code': 503, 'message': 'Service unavailable'}]}
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Should return partial results
        assert len(result['hosts']) == 100
        assert result['total'] == 100

    def test_get_devices_rate_limit_error(self):
        """Test handling of rate limit (429) error."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 100}}}
            },
            # First page - rate limited
            {
                'status_code': 429,
                'body': {
                    'errors': [{
                        'code': 429,
                        'message': 'Rate limit exceeded'
                    }]
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Should return empty results
        assert len(result['hosts']) == 0


class TestHostsClientSideFiltering:
    """Test client-side device ID filtering."""

    def test_client_side_filtering_applied(self):
        """Test that client-side device ID filtering works correctly."""
        mock_falcon = Mock()

        device_ids_filter = {f'device-{i}' for i in range(50)}  # Only want 0-49

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 100}}}
            },
            # get_devices() - returns 100 devices
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100)],  # 0-99
                    'meta': {'pagination': {'offset': None}}
                }
            }
        ]

        # Large list with other filters triggers client-side filtering
        hosts = Hosts(
            cid='test-cid',
            falcon=mock_falcon,
            device_ids=list(device_ids_filter),
            filter="last_seen:>'2024-01-01'"
        )

        result = hosts.get_devices()

        # Should be filtered to only the 50 devices in filter set
        assert result['total'] == 50
        assert len(result['hosts']) == 50
        for device_id in result['hosts']:
            assert device_id in device_ids_filter

    def test_no_client_side_filtering_when_not_needed(self):
        """Test that client-side filtering is skipped when not configured."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 100}}}
            },
            # get_devices()
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(100)],
                    'meta': {'pagination': {'offset': None}}
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # No filtering should occur
        assert result['total'] == 100
        assert len(result['hosts']) == 100


class TestHostsResponseStructure:
    """Test response structure validation."""

    def test_get_devices_response_structure(self):
        """Test that get_devices returns correct structure."""
        mock_falcon = Mock()
        mock_falcon.base_url = 'https://api.crowdstrike.com'

        mock_falcon.command.side_effect = [
            # device_count()
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 50}}}
            },
            # get_devices()
            {
                'status_code': 200,
                'body': {
                    'resources': [f'device-{i}' for i in range(50)],
                    'meta': {'pagination': {'offset': None}}
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Verify all required keys present
        assert 'epoch' in result
        assert 'cid' in result
        assert 'base_url' in result
        assert 'total' in result
        assert 'hosts' in result

        # Verify types
        assert isinstance(result['epoch'], int)
        assert isinstance(result['cid'], str)
        assert isinstance(result['base_url'], str)
        assert isinstance(result['total'], int)
        assert isinstance(result['hosts'], list)

        # Verify values
        assert result['cid'] == 'test-cid'
        assert result['base_url'] == 'https://api.crowdstrike.com'
        assert result['total'] == 50
        assert len(result['hosts']) == 50

    def test_get_devices_epoch_timestamp(self):
        """Test that epoch timestamp is current."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            {
                'status_code': 200,
                'body': {'meta': {'pagination': {'total': 0}}}
            },
            {
                'status_code': 200,
                'body': {
                    'resources': [],
                    'meta': {'pagination': {'offset': None}}
                }
            }
        ]

        hosts = Hosts(cid='test-cid', falcon=mock_falcon)
        result = hosts.get_devices()

        # Epoch should be recent (within last minute)
        import time
        current_epoch = int(time.time())
        assert abs(result['epoch'] - current_epoch) < 60
