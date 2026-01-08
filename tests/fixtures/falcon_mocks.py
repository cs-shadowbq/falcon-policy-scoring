"""
Mock FalconPy SDK responses for testing.

Provides mock APIHarnessV2.command() responses that match the structure
returned by CrowdStrike FalconPy SDK, including:
- Success responses with pagination
- 403 scope permission errors
- 429 rate limit errors
- Network failures
- Various API command responses

Covers all falcon.command() calls in the codebase:
- Host/Device APIs: QueryDevicesByFilterScroll, GetDeviceDetailsV2
- Policy APIs: queryCombined*Policies, getDeviceControlPolicies
- Host Group APIs: queryCombinedHostGroups, queryHostGroups, getHostGroups, 
  queryCombinedGroupMembers, queryGroupMembers
- Zero Trust Assessment: getAssessmentV1, getAssessmentsByScoreV1, getAuditV1
- Firewall: get_policy_containers
- IT Automation: ITAutomationQueryPolicies, ITAutomationGetPolicies
- CID lookup: GetSensorInstallersCCIDByQuery

Based on FalconPy test patterns: https://github.com/CrowdStrike/falconpy/tree/main/tests
"""

from typing import Dict, Any, List, Optional
from unittest.mock import Mock
from datetime import datetime
from tests.fixtures.sample_data import (
    SAMPLE_HOSTS,
    SAMPLE_PREVENTION_POLICIES,
    SAMPLE_SENSOR_UPDATE_POLICIES,
    SAMPLE_FIREWALL_POLICIES,
    generate_host_detail,
    generate_prevention_policy,
    generate_sensor_update_policy,
    generate_firewall_policy,
    generate_device_control_policy,
    generate_content_update_policy,
    generate_zta_assessment,
    generate_firewall_container,
    generate_it_automation_policy,
    generate_host_group
)


class MockFalconResponse:
    """Container for mock Falcon API responses matching FalconPy structure."""

    @staticmethod
    def success(body: Dict[str, Any], status_code: int = 200) -> Dict[str, Any]:
        """Generate a successful API response.

        Args:
            body: Response body content
            status_code: HTTP status code (default: 200)

        Returns:
            Dict matching FalconPy response structure
        """
        return {
            'status_code': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'X-Ratelimit-Limit': '10000',
                'X-Ratelimit-Remaining': '9999'
            },
            'body': body
        }

    @staticmethod
    def error_403_scope(command: str = "QueryDevicesByFilterScroll") -> Dict[str, Any]:
        """Generate a 403 scope permission error response.

        Args:
            command: API command that failed

        Returns:
            Dict matching FalconPy 403 error structure
        """
        return {
            'status_code': 403,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': {
                'errors': [
                    {
                        'code': 403,
                        'message': 'access denied, scope not permitted',
                        'id': 'test-request-id-12345'
                    }
                ],
                'meta': {
                    'query_time': 0.001,
                    'powered_by': 'crowdstrike-api-gateway',
                    'trace_id': 'test-trace-id-67890'
                }
            }
        }

    @staticmethod
    def error_429_rate_limit() -> Dict[str, Any]:
        """Generate a 429 rate limit error response.

        Returns:
            Dict matching FalconPy 429 error structure
        """
        return {
            'status_code': 429,
            'headers': {
                'Content-Type': 'application/json',
                'X-Ratelimit-Limit': '10000',
                'X-Ratelimit-Remaining': '0',
                'X-Ratelimit-Retryafter': '60'
            },
            'body': {
                'errors': [
                    {
                        'code': 429,
                        'message': 'Too Many Requests',
                        'id': 'test-request-id-rate-limit'
                    }
                ],
                'meta': {
                    'query_time': 0.001,
                    'powered_by': 'crowdstrike-api-gateway',
                    'trace_id': 'test-trace-id-rate-limit'
                }
            }
        }

    @staticmethod
    def error_network() -> Dict[str, Any]:
        """Generate a network/connection error response.

        Returns:
            Dict representing network failure
        """
        return {
            'status_code': 0,
            'headers': {},
            'body': {
                'errors': [
                    {
                        'code': 0,
                        'message': 'Connection error',
                        'id': 'network-error'
                    }
                ]
            }
        }

    @staticmethod
    def query_devices_scroll(
        device_ids: List[str],
        total: int = None,
        offset: str = None,
        has_more: bool = False
    ) -> Dict[str, Any]:
        """Generate QueryDevicesByFilterScroll response.

        Args:
            device_ids: List of device IDs to return
            total: Total count of devices (defaults to len(device_ids))
            offset: Next page offset token (for pagination)
            has_more: Whether there are more pages

        Returns:
            Dict matching QueryDevicesByFilterScroll response structure
        """
        if total is None:
            total = len(device_ids)

        body = {
            'resources': device_ids,
            'meta': {
                'pagination': {
                    'total': total,
                    'limit': len(device_ids)
                },
                'query_time': 0.123,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-scroll'
            }
        }

        # Add offset token if more pages exist
        if has_more and offset:
            body['meta']['pagination']['offset'] = offset

        return MockFalconResponse.success(body)

    @staticmethod
    def get_device_details(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate GetDeviceDetailsV2 response.

        Args:
            devices: List of device detail dictionaries

        Returns:
            Dict matching GetDeviceDetailsV2 response structure
        """
        body = {
            'resources': devices,
            'errors': [],
            'meta': {
                'query_time': 0.234,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-details'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def query_combined_policies(
        policies: List[Dict[str, Any]],
        total: int = None,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Generate queryCombined*Policies response (generic for all policy types).

        Args:
            policies: List of policy dictionaries
            total: Total count of policies (defaults to len(policies))
            offset: Current offset for pagination

        Returns:
            Dict matching queryCombined*Policies response structure
        """
        if total is None:
            total = len(policies)

        body = {
            'resources': policies,
            'meta': {
                'pagination': {
                    'total': total,
                    'offset': offset,
                    'limit': len(policies)
                },
                'query_time': 0.156,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-policies'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def query_host_groups(groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate queryCombinedHostGroups response.

        Args:
            groups: List of host group dictionaries

        Returns:
            Dict matching queryCombinedHostGroups response structure
        """
        body = {
            'resources': groups,
            'meta': {
                'pagination': {
                    'total': len(groups),
                    'offset': 0,
                    'limit': len(groups)
                },
                'query_time': 0.089,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-groups'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def query_group_members(device_ids: List[str]) -> Dict[str, Any]:
        """Generate queryCombinedGroupMembers response.

        Args:
            device_ids: List of device IDs in the group

        Returns:
            Dict matching queryCombinedGroupMembers response structure
        """
        body = {
            'resources': device_ids,
            'meta': {
                'pagination': {
                    'total': len(device_ids),
                    'offset': 0,
                    'limit': len(device_ids)
                },
                'query_time': 0.045,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-group-members'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_cid(cid: str = "test-cid-1234567890abcdef") -> Dict[str, Any]:
        """Generate GetSensorInstallersCCIDByQuery response.

        Args:
            cid: Customer ID to return

        Returns:
            Dict matching GetSensorInstallersCCIDByQuery response structure
        """
        body = {
            'resources': [cid],
            'meta': {
                'query_time': 0.023,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-cid'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_zta_assessment(assessments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate GetAssessmentV1 response for Zero Trust Assessment.

        Args:
            assessments: List of ZTA assessment dictionaries

        Returns:
            Dict matching GetAssessmentV1 response structure
        """
        body = {
            'resources': assessments,
            'meta': {
                'query_time': 0.178,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-zta'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_zta_by_score(assessments: List[Dict[str, Any]], score_filter: str = None) -> Dict[str, Any]:
        """Generate getAssessmentsByScoreV1 response.

        Args:
            assessments: List of ZTA assessment dictionaries
            score_filter: Optional score filter (e.g., 'gte:80')

        Returns:
            Dict matching getAssessmentsByScoreV1 response structure
        """
        # Filter by score if provided
        if score_filter:
            filtered = []
            for assessment in assessments:
                overall_score = assessment.get('assessment', {}).get('overall', 0)
                if score_filter.startswith('gte:'):
                    threshold = int(score_filter.split(':')[1])
                    if overall_score >= threshold:
                        filtered.append(assessment)
                elif score_filter.startswith('lte:'):
                    threshold = int(score_filter.split(':')[1])
                    if overall_score <= threshold:
                        filtered.append(assessment)
            assessments = filtered

        body = {
            'resources': assessments,
            'meta': {
                'query_time': 0.189,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-zta-score'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_zta_audit() -> Dict[str, Any]:
        """Generate getAuditV1 response for ZTA audit log.

        Returns:
            Dict matching getAuditV1 response structure
        """
        body = {
            'resources': [{
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'action': 'assessment_updated',
                'user': 'system'
            }],
            'meta': {
                'query_time': 0.067,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-zta-audit'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_firewall_containers(containers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate get_policy_containers response.

        Args:
            containers: List of firewall policy container dictionaries

        Returns:
            Dict matching get_policy_containers response structure
        """
        body = {
            'resources': containers,
            'meta': {
                'query_time': 0.145,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-firewall-containers'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def query_it_automation_policies(policy_ids: List[str], total: int = None) -> Dict[str, Any]:
        """Generate ITAutomationQueryPolicies response.

        Args:
            policy_ids: List of IT automation policy IDs
            total: Total count (defaults to len(policy_ids))

        Returns:
            Dict matching ITAutomationQueryPolicies response structure
        """
        if total is None:
            total = len(policy_ids)

        body = {
            'resources': policy_ids,
            'meta': {
                'pagination': {
                    'total': total,
                    'offset': 0,
                    'limit': len(policy_ids)
                },
                'query_time': 0.098,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-it-automation-query'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_it_automation_policies(policies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate ITAutomationGetPolicies response.

        Args:
            policies: List of IT automation policy dictionaries

        Returns:
            Dict matching ITAutomationGetPolicies response structure
        """
        body = {
            'resources': policies,
            'meta': {
                'query_time': 0.134,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-it-automation-get'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def query_host_groups_ids(group_ids: List[str]) -> Dict[str, Any]:
        """Generate queryHostGroups response (returns IDs only).

        Args:
            group_ids: List of host group IDs

        Returns:
            Dict matching queryHostGroups response structure
        """
        body = {
            'resources': group_ids,
            'meta': {
                'pagination': {
                    'total': len(group_ids),
                    'offset': 0,
                    'limit': len(group_ids)
                },
                'query_time': 0.056,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-host-groups-query'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_host_groups_details(groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate getHostGroups response (returns full details).

        Args:
            groups: List of host group dictionaries

        Returns:
            Dict matching getHostGroups response structure
        """
        body = {
            'resources': groups,
            'meta': {
                'query_time': 0.089,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-host-groups-get'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def query_group_members_ids(device_ids: List[str]) -> Dict[str, Any]:
        """Generate queryGroupMembers response (returns device IDs).

        Args:
            device_ids: List of device IDs in the group

        Returns:
            Dict matching queryGroupMembers response structure
        """
        body = {
            'resources': device_ids,
            'meta': {
                'pagination': {
                    'total': len(device_ids),
                    'offset': 0,
                    'limit': len(device_ids)
                },
                'query_time': 0.045,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-group-members-query'
            }
        }

        return MockFalconResponse.success(body)

    @staticmethod
    def get_device_control_policies_details(policies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate getDeviceControlPolicies response.

        Args:
            policies: List of device control policy dictionaries

        Returns:
            Dict matching getDeviceControlPolicies response structure
        """
        body = {
            'resources': policies,
            'meta': {
                'query_time': 0.112,
                'powered_by': 'crowdstrike-api-gateway',
                'trace_id': 'test-trace-id-device-control-get'
            }
        }

        return MockFalconResponse.success(body)


class MockAPIHarness:
    """Mock APIHarnessV2 for testing without real API calls.

    Provides command() method that returns pre-configured responses
    based on command name and parameters.
    """

    def __init__(self):
        """Initialize mock API harness with default responses."""
        self.call_history: List[Dict[str, Any]] = []
        self.response_overrides: Dict[str, Any] = {}
        self.call_count: Dict[str, int] = {}

    def command(self, action: str, **kwargs) -> Dict[str, Any]:
        """Mock the APIHarnessV2.command() method.

        Args:
            action: API action/command name
            **kwargs: Command parameters

        Returns:
            Dict matching FalconPy response structure
        """
        # Record the call
        call_info = {'action': action, 'kwargs': kwargs}
        self.call_history.append(call_info)
        self.call_count[action] = self.call_count.get(action, 0) + 1

        # Check for override responses
        if action in self.response_overrides:
            override = self.response_overrides[action]
            if callable(override):
                return override(**kwargs)
            return override

        # Default responses based on action
        return self._default_response(action, **kwargs)

    def _default_response(self, action: str, **kwargs) -> Dict[str, Any]:
        """Generate default response for an action.

        Args:
            action: API action/command name
            **kwargs: Command parameters

        Returns:
            Dict matching FalconPy response structure
        """
        # Host/Device APIs
        if action == "QueryDevicesByFilterScroll":
            # Return sample device IDs
            device_ids = [h['device_id'] for h in SAMPLE_HOSTS[:kwargs.get('limit', 5)]]
            return MockFalconResponse.query_devices_scroll(device_ids)

        elif action == "GetDeviceDetailsV2":
            # Return sample device details
            ids = kwargs.get('ids', [])
            devices = [generate_host_detail(device_id=did) for did in ids]
            return MockFalconResponse.get_device_details(devices)

        # Policy APIs - Combined queries
        elif action == "queryCombinedPreventionPolicies":
            return MockFalconResponse.query_combined_policies(SAMPLE_PREVENTION_POLICIES)

        elif action == "queryCombinedSensorUpdatePolicies":
            return MockFalconResponse.query_combined_policies(SAMPLE_SENSOR_UPDATE_POLICIES)

        elif action == "queryCombinedFirewallPolicies":
            return MockFalconResponse.query_combined_policies(SAMPLE_FIREWALL_POLICIES)

        elif action == "queryCombinedDeviceControlPolicies":
            policies = [generate_device_control_policy()]
            return MockFalconResponse.query_combined_policies(policies)

        elif action == "queryCombinedContentUpdatePolicies":
            policies = [generate_content_update_policy()]
            return MockFalconResponse.query_combined_policies(policies)

        # Device Control - Get policies by IDs
        elif action == "getDeviceControlPolicies":
            ids = kwargs.get('ids', [])
            policies = [generate_device_control_policy(policy_id=pid) for pid in ids]
            return MockFalconResponse.get_device_control_policies_details(policies)

        # CID lookup
        elif action == "GetSensorInstallersCCIDByQuery":
            return MockFalconResponse.get_cid()

        # Host Group APIs
        elif action == "queryCombinedHostGroups":
            groups = [generate_host_group()]
            return MockFalconResponse.query_host_groups(groups)

        elif action == "queryHostGroups":
            # Returns IDs only, not full objects
            group_ids = ['test-group-id-1', 'test-group-id-2']
            return MockFalconResponse.query_host_groups_ids(group_ids)

        elif action == "getHostGroups":
            # Returns full host group details
            ids = kwargs.get('ids', ['test-group-id-1'])
            groups = [generate_host_group(group_id=gid) for gid in ids]
            return MockFalconResponse.get_host_groups_details(groups)

        elif action == "queryCombinedGroupMembers":
            device_ids = [h['device_id'] for h in SAMPLE_HOSTS[:3]]
            return MockFalconResponse.query_group_members(device_ids)

        elif action == "queryGroupMembers":
            # Returns device IDs only
            device_ids = [h['device_id'] for h in SAMPLE_HOSTS[:3]]
            return MockFalconResponse.query_group_members_ids(device_ids)

        # Zero Trust Assessment APIs
        elif action == "getAssessmentV1":
            ids = kwargs.get('ids', [])
            assessments = [generate_zta_assessment(device_id=did) for did in ids]
            return MockFalconResponse.get_zta_assessment(assessments)

        elif action == "getAssessmentsByScoreV1":
            # Mock some sample assessments with varying scores
            assessments = [
                generate_zta_assessment(device_id=SAMPLE_HOSTS[0]['device_id'], overall_score=85),
                generate_zta_assessment(device_id=SAMPLE_HOSTS[1]['device_id'], overall_score=65),
                generate_zta_assessment(device_id=SAMPLE_HOSTS[2]['device_id'], overall_score=90)
            ]
            score_filter = kwargs.get('score')
            return MockFalconResponse.get_zta_by_score(assessments, score_filter)

        elif action == "getAuditV1":
            return MockFalconResponse.get_zta_audit()

        # Firewall APIs
        elif action == "get_policy_containers":
            ids = kwargs.get('ids', [])
            containers = [generate_firewall_container(policy_id=pid) for pid in ids]
            return MockFalconResponse.get_firewall_containers(containers)

        # IT Automation APIs
        elif action == "ITAutomationQueryPolicies":
            # Return policy IDs
            policy_ids = ['it-auto-policy-1', 'it-auto-policy-2', 'it-auto-policy-3']
            return MockFalconResponse.query_it_automation_policies(policy_ids)

        elif action == "ITAutomationGetPolicies":
            ids = kwargs.get('ids', [])
            platform = kwargs.get('platform', 'Windows')
            policies = [generate_it_automation_policy(policy_id=pid, platform=platform) for pid in ids]
            return MockFalconResponse.get_it_automation_policies(policies)

        else:
            # Unknown command - return generic success
            return MockFalconResponse.success({'resources': []})

    def set_response(self, action: str, response: Any):
        """Set a custom response for a specific action.

        Args:
            action: API action/command name
            response: Response dict or callable that returns response dict
        """
        self.response_overrides[action] = response

    def clear_overrides(self):
        """Clear all custom response overrides."""
        self.response_overrides.clear()

    def reset(self):
        """Reset all state including call history and overrides."""
        self.call_history.clear()
        self.call_count.clear()
        self.response_overrides.clear()

    def get_calls(self, action: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get call history, optionally filtered by action.

        Args:
            action: Optional action name to filter by

        Returns:
            List of call info dictionaries
        """
        if action:
            return [c for c in self.call_history if c['action'] == action]
        return self.call_history
