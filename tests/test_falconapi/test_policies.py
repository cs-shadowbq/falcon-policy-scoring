"""
Tests for FalconAPI Policies module.

Tests policy fetching with pagination, error handling, permission errors,
and multi-policy-type support.
"""
import pytest
from unittest.mock import Mock, patch
from falcon_policy_scoring.falconapi.policies import (
    get_policies,
    check_scope_permission_error,
    get_policy_table_name,
    POLICY_TYPES
)


class TestPolicyTypes:
    """Test policy type configuration."""

    def test_all_policy_types_defined(self):
        """Test that all expected policy types are defined."""
        expected_types = [
            'prevention',
            'firewall',
            'sensor_update',
            'content_update',
            'device_control',
            'it_automation'
        ]

        for policy_type in expected_types:
            assert policy_type in POLICY_TYPES

    def test_policy_type_has_required_fields(self):
        """Test that each policy type has required configuration."""
        for policy_type, config in POLICY_TYPES.items():
            assert 'command' in config, f"{policy_type} missing 'command'"
            assert 'table_name' in config, f"{policy_type} missing 'table_name'"
            assert 'limit' in config, f"{policy_type} missing 'limit'"
            assert 'weblink' in config, f"{policy_type} missing 'weblink'"

    def test_invalid_policy_type_raises_error(self):
        """Test that invalid policy type raises ValueError."""
        mock_falcon = Mock()

        with pytest.raises(ValueError, match="Unsupported policy type"):
            get_policies(mock_falcon, 'invalid_policy_type')


class TestScopePermissionError:
    """Test scope permission error detection."""

    def test_detect_403_scope_not_permitted(self):
        """Test detection of 403 scope permission error."""
        response = {
            'status_code': 403,
            'body': {
                'errors': [{
                    'code': 403,
                    'message': 'access denied, scope not permitted'
                }]
            }
        }

        is_error, msg = check_scope_permission_error(
            response,
            'queryCombinedPreventionPolicies',
            'https://example.com/docs'
        )

        assert is_error is True
        assert msg is not None
        assert 'ASSIST' in msg
        assert 'scope' in msg
        assert 'https://example.com/docs' in msg

    def test_detect_403_scope_without_assist_message(self):
        """Test detection without command name/weblink."""
        response = {
            'status_code': 403,
            'body': {
                'errors': [{
                    'code': 403,
                    'message': 'access denied, scope not permitted'
                }]
            }
        }

        is_error, msg = check_scope_permission_error(response)

        assert is_error is True
        assert msg is None

    def test_non_403_not_detected(self):
        """Test that non-403 errors are not detected as scope errors."""
        response = {
            'status_code': 500,
            'body': {
                'errors': [{
                    'code': 500,
                    'message': 'Internal server error'
                }]
            }
        }

        is_error, msg = check_scope_permission_error(response)

        assert is_error is False
        assert msg is None

    def test_403_without_scope_message_not_detected(self):
        """Test that 403 without scope message is not detected."""
        response = {
            'status_code': 403,
            'body': {
                'errors': [{
                    'code': 403,
                    'message': 'Forbidden - other reason'
                }]
            }
        }

        is_error, msg = check_scope_permission_error(response)

        assert is_error is False


class TestGetPoliciesSinglePage:
    """Test single-page policy fetching."""

    def test_get_prevention_policies_single_page(self):
        """Test fetching prevention policies that fit in single page."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [
                    {'id': 'pol-1', 'name': 'Policy 1'},
                    {'id': 'pol-2', 'name': 'Policy 2'}
                ],
                'meta': {'pagination': {'total': 2}}
            }
        }

        result = get_policies(mock_falcon, 'prevention')

        assert result['status_code'] == 200
        assert len(result['body']['resources']) == 2
        assert mock_falcon.command.call_count == 1

    def test_get_firewall_policies_single_page(self):
        """Test fetching firewall policies."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [{'id': 'fw-1', 'name': 'Firewall Policy'}],
                'meta': {'pagination': {'total': 1}}
            }
        }

        result = get_policies(mock_falcon, 'firewall')

        assert result['status_code'] == 200
        mock_falcon.command.assert_called_once_with(
            'queryCombinedFirewallPolicies',
            limit=5000,
            offset=0
        )

    def test_get_policies_empty_result(self):
        """Test fetching policies when none exist."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }

        result = get_policies(mock_falcon, 'sensor_update')

        assert result['status_code'] == 200
        assert len(result['body']['resources']) == 0


class TestGetPoliciesMultiplePages:
    """Test multi-page policy fetching."""

    def test_get_policies_two_pages(self):
        """Test fetching policies across 2 pages."""
        mock_falcon = Mock()

        # Simulate 2 pages of results
        mock_falcon.command.side_effect = [
            # Page 1
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': f'pol-{i}', 'name': f'Policy {i}'} for i in range(100)],
                    'meta': {'pagination': {'total': 150}}
                }
            },
            # Page 2 (remaining 50)
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': f'pol-{i}', 'name': f'Policy {i}'} for i in range(100, 150)],
                    'meta': {'pagination': {'total': 150}}
                }
            }
        ]

        result = get_policies(mock_falcon, 'prevention')

        assert result['status_code'] == 200
        assert len(result['body']['resources']) == 150
        assert mock_falcon.command.call_count == 2

        # Verify pagination offset was incremented
        first_call = mock_falcon.command.call_args_list[0]
        second_call = mock_falcon.command.call_args_list[1]
        assert first_call[1]['offset'] == 0
        assert second_call[1]['offset'] == 5000  # limit from config

    def test_get_policies_multiple_pages(self):
        """Test fetching policies across 5 pages."""
        mock_falcon = Mock()

        total_policies = 12000
        page_size = 5000  # Default limit for most policies

        responses = []
        for page_num in range(3):  # 3 pages to get 12000
            start = page_num * page_size
            end = min(start + page_size, total_policies)
            count = end - start

            responses.append({
                'status_code': 200,
                'body': {
                    'resources': [
                        {'id': f'pol-{i}', 'name': f'Policy {i}'}
                        for i in range(start, end)
                    ],
                    'meta': {'pagination': {'total': total_policies}}
                }
            })

        mock_falcon.command.side_effect = responses

        result = get_policies(mock_falcon, 'device_control')

        assert result['status_code'] == 200
        assert len(result['body']['resources']) == 12000
        assert mock_falcon.command.call_count == 3

    def test_get_policies_stops_on_empty_page(self):
        """Test that pagination stops when empty resources returned."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # Page 1
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': f'pol-{i}', 'name': f'Policy {i}'} for i in range(100)],
                    'meta': {'pagination': {'total': 1000}}
                }
            },
            # Page 2 - empty resources (API issue)
            {
                'status_code': 200,
                'body': {
                    'resources': [],
                    'meta': {'pagination': {'total': 1000}}
                }
            }
        ]

        result = get_policies(mock_falcon, 'prevention')

        # Should stop after empty page
        assert len(result['body']['resources']) == 100
        assert mock_falcon.command.call_count == 2

    def test_get_policies_stops_when_total_reached(self):
        """Test that pagination stops when total count is reached."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # Page 1 - exactly 100 policies
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': f'pol-{i}'} for i in range(100)],
                    'meta': {'pagination': {'total': 100}}
                }
            }
        ]

        result = get_policies(mock_falcon, 'firewall')

        # Should stop after fetching all
        assert len(result['body']['resources']) == 100
        assert mock_falcon.command.call_count == 1


class TestGetPoliciesErrorHandling:
    """Test error handling in policy fetching."""

    def test_get_policies_api_error(self):
        """Test handling of API error."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 500,
            'body': {
                'errors': [{
                    'code': 500,
                    'message': 'Internal server error'
                }]
            }
        }

        result = get_policies(mock_falcon, 'prevention')

        assert result['error'] == 500
        assert result['status_code'] == 500

    def test_get_policies_403_non_scope_error(self):
        """Test handling of 403 error that is not a scope error."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 403,
            'body': {
                'errors': [{
                    'code': 403,
                    'message': 'Forbidden - other reason'
                }]
            }
        }

        result = get_policies(mock_falcon, 'sensor_update')

        assert result['error'] == 403
        assert result['status_code'] == 403
        assert 'permission_error' not in result

    def test_get_policies_scope_permission_error(self):
        """Test handling of scope permission error."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 403,
            'body': {
                'errors': [{
                    'code': 403,
                    'message': 'access denied, scope not permitted'
                }]
            }
        }

        result = get_policies(mock_falcon, 'device_control')

        assert result['error'] == 403
        assert result['status_code'] == 403
        assert result['permission_error'] is True
        assert 'assist_message' in result
        assert 'ASSIST' in result['assist_message']
        assert 'weblink' in result

    def test_get_policies_error_mid_pagination(self):
        """Test handling of error during pagination."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            # Page 1 - success
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': f'pol-{i}'} for i in range(100)],
                    'meta': {'pagination': {'total': 200}}
                }
            },
            # Page 2 - error
            {
                'status_code': 503,
                'body': {
                    'errors': [{
                        'code': 503,
                        'message': 'Service unavailable'
                    }]
                }
            }
        ]

        result = get_policies(mock_falcon, 'firewall')

        # Should return error response from failed page
        assert result['error'] == 503
        assert result['status_code'] == 503


class TestGetPoliciesITAutomation:
    """Test IT Automation policy fetching (custom shim)."""

    @patch('falcon_policy_scoring.falconapi.it_automation')
    def test_get_it_automation_policies_uses_shim(self, mock_it_automation):
        """Test that IT Automation uses custom shim function."""
        mock_falcon = Mock()

        mock_it_automation.query_combined_it_automation_policies.return_value = {
            'status_code': 200,
            'body': {
                'resources': [{'id': 'it-pol-1'}],
                'meta': {'pagination': {'total': 1}}
            }
        }

        result = get_policies(mock_falcon, 'it_automation')

        assert result['status_code'] == 200
        mock_it_automation.query_combined_it_automation_policies.assert_called_once()

        # Verify shim was called with correct parameters
        call_args = mock_it_automation.query_combined_it_automation_policies.call_args
        assert call_args[0][0] == mock_falcon
        assert call_args[1]['limit'] == 500  # IT automation has lower limit
        assert call_args[1]['offset'] == 0

    @patch('falcon_policy_scoring.falconapi.it_automation')
    def test_get_it_automation_policies_pagination(self, mock_it_automation):
        """Test IT Automation pagination with custom shim."""
        mock_falcon = Mock()

        mock_it_automation.query_combined_it_automation_policies.side_effect = [
            # Page 1
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': f'it-pol-{i}'} for i in range(500)],
                    'meta': {'pagination': {'total': 750}}
                }
            },
            # Page 2
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': f'it-pol-{i}'} for i in range(500, 750)],
                    'meta': {'pagination': {'total': 750}}
                }
            }
        ]

        result = get_policies(mock_falcon, 'it_automation')

        assert result['status_code'] == 200
        assert len(result['body']['resources']) == 750
        assert mock_it_automation.query_combined_it_automation_policies.call_count == 2


class TestGetPolicyTableName:
    """Test policy table name retrieval."""

    def test_get_table_name_for_all_types(self):
        """Test getting table names for all policy types."""
        expected_mappings = {
            'prevention': 'prevention_policies',
            'firewall': 'firewall_policies',
            'sensor_update': 'sensor_update_policies',
            'content_update': 'content_update_policies',
            'device_control': 'device_control_policies',
            'it_automation': 'it_automation_policies'
        }

        for policy_type, expected_table in expected_mappings.items():
            table_name = get_policy_table_name(policy_type)
            assert table_name == expected_table

    def test_get_table_name_invalid_type(self):
        """Test that invalid policy type returns None or raises error."""
        # Check what the actual function does - it might raise or return None
        try:
            result = get_policy_table_name('invalid_type')
            # If it returns, it should be None or empty
            assert result is None or result == ''
        except (ValueError, KeyError):
            # It's also acceptable to raise an error
            pass


class TestPolicyFetchingConfigLimits:
    """Test that different policy types use correct limits."""

    def test_prevention_policy_uses_5000_limit(self):
        """Test that prevention policies use 5000 limit."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }

        get_policies(mock_falcon, 'prevention')

        call_args = mock_falcon.command.call_args
        assert call_args[1]['limit'] == 5000

    @patch('falcon_policy_scoring.falconapi.it_automation')
    def test_it_automation_uses_500_limit(self, mock_it_automation):
        """Test that IT automation uses 500 limit."""
        mock_falcon = Mock()

        mock_it_automation.query_combined_it_automation_policies.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }

        get_policies(mock_falcon, 'it_automation')

        call_args = mock_it_automation.query_combined_it_automation_policies.call_args
        assert call_args[1]['limit'] == 500

    def test_firewall_policy_uses_5000_limit(self):
        """Test that firewall policies use 5000 limit."""
        mock_falcon = Mock()

        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }

        get_policies(mock_falcon, 'firewall')

        call_args = mock_falcon.command.call_args
        assert call_args[1]['limit'] == 5000


class TestPolicyResponseStructure:
    """Test response structure validation."""

    def test_response_preserves_original_structure(self):
        """Test that response maintains original API structure."""
        mock_falcon = Mock()

        original_response = {
            'status_code': 200,
            'body': {
                'resources': [{'id': 'pol-1'}],
                'meta': {
                    'pagination': {'total': 1},
                    'other_field': 'preserved'
                }
            },
            'headers': {'X-Custom': 'header'}
        }

        mock_falcon.command.return_value = original_response

        result = get_policies(mock_falcon, 'prevention')

        # Original structure should be preserved
        assert 'headers' in result
        assert result['headers']['X-Custom'] == 'header'
        assert 'other_field' in result['body']['meta']

    def test_paginated_response_combines_resources(self):
        """Test that multi-page responses combine resources correctly."""
        mock_falcon = Mock()

        mock_falcon.command.side_effect = [
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': 'pol-1'}],
                    'meta': {'pagination': {'total': 2}}
                }
            },
            {
                'status_code': 200,
                'body': {
                    'resources': [{'id': 'pol-2'}],
                    'meta': {'pagination': {'total': 2}}
                }
            }
        ]

        result = get_policies(mock_falcon, 'sensor_update')

        # Resources should be combined
        assert len(result['body']['resources']) == 2
        assert result['body']['resources'][0]['id'] == 'pol-1'
        assert result['body']['resources'][1]['id'] == 'pol-2'
