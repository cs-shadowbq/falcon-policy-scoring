"""
Tests for grading rollup/propagation logic.

Tests the critical failure propagation chain:
1. Setting level: Individual setting fails comparison
2. Policy level: Single failed setting → entire policy fails
3. Host level: Single failed policy → entire host fails

This ensures that security misconfigurations propagate correctly
through the grading hierarchy.
"""

from falcon_policy_scoring.utils.host_data import collect_host_data, calculate_host_stats
from falcon_policy_scoring.utils.policy_helpers import get_policy_status
import pytest
from typing import Dict, List

from falcon_policy_scoring.grading.results import (
    grade_setting,
    _create_empty_policy_result
)
from falcon_policy_scoring.grading.graders.prevention import (
    grade_prevention_policy as _grade_prevention_policy
)
from falcon_policy_scoring.grading.graders.sensor_update import (
    grade_sensor_update_policy as _grade_sensor_update_policy
)
from falcon_policy_scoring.grading.graders.firewall import (
    grade_firewall_policy as _grade_firewall_policy
)
from falcon_policy_scoring.grading.graders.device_control import (
    grade_device_control_policy
)
from falcon_policy_scoring.grading.graders.content_update import (
    grade_content_update_policy as _grade_content_update_policy
)
from falcon_policy_scoring.grading.graders.it_automation import (
    grade_it_automation_policy
)

# Wrappers for backward compatibility with test signatures
def grade_prevention_policy(policy, grading_config):
    return _grade_prevention_policy(
        policy, grading_config, grade_setting, _create_empty_policy_result
    )

def grade_sensor_update_policy(policy, grading_config):
    return _grade_sensor_update_policy(policy, grading_config, _create_empty_policy_result)

def grade_firewall_policy(policy, policy_container, grading_config):
    return _grade_firewall_policy(
        policy, policy_container, grading_config, _create_empty_policy_result
    )

def grade_content_update_policy(policy, grading_config):
    return _grade_content_update_policy(policy, grading_config, _create_empty_policy_result)


@pytest.mark.unit
class TestSettingToPolicyRollup:
    """Test that a single failed setting fails the entire policy."""

    def test_prevention_policy_one_setting_fails_all_others_pass(self):
        """Test prevention policy with one failing setting among many passing ones."""
        policy = {
            'id': 'test-policy-id',
            'name': 'Test Prevention Policy',
            'platform_name': 'Windows',
            'enabled': True,
            'prevention_settings': [
                {
                    'settings': [
                        {
                            'id': 'CloudAntiMalware',
                            'name': 'Cloud Machine Learning',
                            'type': 'mlslider',
                            'value': {
                                'detection': 'AGGRESSIVE',
                                'prevention': 'AGGRESSIVE'
                            }
                        },
                        {
                            'id': 'AdwarePUP',
                            'name': 'Adware & PUP',
                            'type': 'mlslider',
                            'value': {
                                'detection': 'DISABLED',  # FAILS - too low
                                'prevention': 'DISABLED'
                            }
                        },
                        {
                            'id': 'Quarantine',
                            'name': 'Quarantine',
                            'type': 'toggle',
                            'value': {'enabled': True}
                        }
                    ]
                }
            ]
        }

        grading_config = {
            'prevention_policies': [
                {
                    'platform_name': 'Windows',
                    'enabled': True,
                    'prevention_settings': [
                        {
                            'settings': [
                                {
                                    'id': 'CloudAntiMalware',
                                    'value': {
                                        'detection': 'MODERATE',
                                        'prevention': 'MODERATE'
                                    }
                                },
                                {
                                    'id': 'AdwarePUP',
                                    'value': {
                                        'detection': 'MODERATE',  # Minimum requirement
                                        'prevention': 'MODERATE'
                                    }
                                },
                                {
                                    'id': 'Quarantine',
                                    'value': {'enabled': True}
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        result = grade_prevention_policy(policy, grading_config)

        # Policy should fail overall
        assert result['passed'] is False, "Policy should fail when any setting fails"

        # Should have exactly 1 failure
        assert result['failures_count'] == 1

        # Should have checked 4 items (enabled check + 3 settings: CloudAntiMalware, AdwarePUP, Quarantine)
        assert result['checks_count'] == 4

        # Verify the specific failing setting
        failed_settings = [s for s in result['setting_results'] if not s['passed']]
        assert len(failed_settings) == 1
        assert failed_settings[0]['setting_id'] == 'AdwarePUP'

    def test_prevention_policy_all_settings_pass(self):
        """Test prevention policy with all settings passing."""
        policy = {
            'id': 'test-policy-id',
            'name': 'Test Prevention Policy',
            'platform_name': 'Windows',
            'enabled': True,
            'prevention_settings': [
                {
                    'settings': [
                        {
                            'id': 'CloudAntiMalware',
                            'type': 'mlslider',
                            'value': {
                                'detection': 'EXTRA_AGGRESSIVE',
                                'prevention': 'EXTRA_AGGRESSIVE'
                            }
                        },
                        {
                            'id': 'Quarantine',
                            'type': 'toggle',
                            'value': {'enabled': True}
                        }
                    ]
                }
            ]
        }

        grading_config = {
            'prevention_policies': [
                {
                    'platform_name': 'Windows',
                    'enabled': True,
                    'prevention_settings': [
                        {
                            'settings': [
                                {
                                    'id': 'CloudAntiMalware',
                                    'value': {
                                        'detection': 'MODERATE',
                                        'prevention': 'MODERATE'
                                    }
                                },
                                {
                                    'id': 'Quarantine',
                                    'value': {'enabled': True}
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        result = grade_prevention_policy(policy, grading_config)

        # Policy should pass
        assert result['passed'] is True
        assert result['failures_count'] == 0
        # Should have checked 3 items (enabled check + 2 settings)
        assert result['checks_count'] == 3

    def test_sensor_update_policy_single_failure(self):
        """Test sensor update policy fails when build setting is too low."""
        policy = {
            'id': 'sensor-policy-id',
            'name': 'Sensor Update Policy',
            'platform_name': 'Windows',
            'enabled': True,
            'settings': {
                'build': 'n-2'  # Minimum is 'n' - this fails
            }
        }

        grading_config = {
            'policies': [
                {
                    'platform_name': 'Windows',
                    'enabled': True,
                    'settings': {
                        'build': 'n'
                    }
                }
            ]
        }

        result = grade_sensor_update_policy(policy, grading_config)

        # Policy should fail
        assert result['passed'] is False
        assert result['failures_count'] >= 1

    def test_firewall_policy_container_setting_failure(self):
        """Test firewall policy fails when container setting is wrong."""
        policy = {
            'id': 'firewall-policy-id',
            'name': 'Firewall Policy',
            'platform_name': 'Windows',
            'enabled': True
        }

        policy_container = {
            'default_inbound': 'ALLOW',  # Should be DENY - FAILS
            'enforce': True,
            'test_mode': False
        }

        grading_config = {
            'platform_requirements': [
                {
                    'platform_name': 'all',
                    'policy_requirements': {
                        'enabled': True,
                        'default_inbound': 'DENY',
                        'enforce': True,
                        'test_mode': False
                    }
                }
            ]
        }

        result = grade_firewall_policy(policy, policy_container, grading_config)

        # Policy should fail due to container setting
        assert result['passed'] is False
        assert result['failures_count'] >= 1

    def test_multiple_settings_fail_all_counted(self):
        """Test that all failed settings are counted."""
        policy = {
            'id': 'test-policy-id',
            'name': 'Test Prevention Policy',
            'platform_name': 'Windows',
            'enabled': True,
            'prevention_settings': [
                {
                    'settings': [
                        {
                            'id': 'CloudAntiMalware',
                            'type': 'mlslider',
                            'value': {
                                'detection': 'DISABLED',  # FAILS
                                'prevention': 'CAUTIOUS'  # FAILS
                            }
                        },
                        {
                            'id': 'Quarantine',
                            'type': 'toggle',
                            'value': {'enabled': False}  # FAILS
                        }
                    ]
                }
            ]
        }

        grading_config = {
            'prevention_policies': [
                {
                    'platform_name': 'Windows',
                    'enabled': True,
                    'prevention_settings': [
                        {
                            'settings': [
                                {
                                    'id': 'CloudAntiMalware',
                                    'value': {
                                        'detection': 'AGGRESSIVE',
                                        'prevention': 'AGGRESSIVE'
                                    }
                                },
                                {
                                    'id': 'Quarantine',
                                    'value': {'enabled': True}
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        result = grade_prevention_policy(policy, grading_config)

        # Policy should fail
        assert result['passed'] is False

        # Should have 2 failures (CloudAntiMalware and Quarantine)
        assert result['failures_count'] == 2

        # Verify both settings failed
        failed_settings = [s for s in result['setting_results'] if not s['passed']]
        assert len(failed_settings) == 2
        failed_ids = {s['setting_id'] for s in failed_settings}
        assert 'CloudAntiMalware' in failed_ids
        assert 'Quarantine' in failed_ids


@pytest.mark.unit
class TestPolicyToHostRollup:
    """Test that a single failed policy fails the entire host."""

    def test_host_with_one_failed_policy_fails(self):
        """Test host fails when one policy fails, even if others pass."""
        # Mock database adapter
        class MockAdapter:
            def get_hosts(self, cid):
                return {'hosts': ['device-1']}

            def get_host(self, device_id):
                return {
                    'data': {
                        'device_id': device_id,
                        'hostname': 'test-host',
                        'platform_name': 'Windows',
                        'device_policies': {
                            'prevention': {'policy_id': 'prev-1'},
                            'sensor_update': {'policy_id': 'sensor-1'},
                            'content-update': {'policy_id': 'content-1'},
                            'firewall': {'policy_id': 'fw-1'},
                            'device_control': {'policy_id': 'dc-1'},
                            'it-automation': {'policy_id': 'it-1'}
                        }
                    }
                }

            def get_host_zta(self, device_id):
                return None

        # Policy records - prevention FAILED, all others PASSED
        policy_records = {
            'prevention': {
                'graded_policies': [
                    {'policy_id': 'prev-1', 'passed': False}  # FAILED
                ]
            },
            'sensor_update': {
                'graded_policies': [
                    {'policy_id': 'sensor-1', 'passed': True}
                ]
            },
            'content_update': {
                'graded_policies': [
                    {'policy_id': 'content-1', 'passed': True}
                ]
            },
            'firewall': {
                'graded_policies': [
                    {'policy_id': 'fw-1', 'passed': True}
                ]
            },
            'device_control': {
                'graded_policies': [
                    {'policy_id': 'dc-1', 'passed': True}
                ]
            },
            'it_automation': {
                'graded_policies': [
                    {'policy_id': 'it-1', 'passed': True}
                ]
            }
        }

        adapter = MockAdapter()
        host_data = collect_host_data(
            adapter,
            'test-cid',
            policy_records,
            get_policy_status,
            config={'host_fetching': {'include_zta': False}}
        )

        assert len(host_data) == 1
        host = host_data[0]

        # Host should fail due to prevention policy failure
        assert host['any_failed'] is True
        assert host['all_passed'] is False

        # Verify individual statuses
        assert host['prevention_status'] == 'FAILED'
        assert host['sensor_update_status'] == 'PASSED'
        assert host['content_update_status'] == 'PASSED'
        assert host['firewall_status'] == 'PASSED'
        assert host['device_control_status'] == 'PASSED'
        assert host['it_automation_status'] == 'PASSED'

    def test_host_with_all_policies_passed(self):
        """Test host passes when all policies pass."""
        class MockAdapter:
            def get_hosts(self, cid):
                return {'hosts': ['device-1']}

            def get_host(self, device_id):
                return {
                    'data': {
                        'device_id': device_id,
                        'hostname': 'test-host',
                        'platform_name': 'Windows',
                        'device_policies': {
                            'prevention': {'policy_id': 'prev-1'},
                            'sensor_update': {'policy_id': 'sensor-1'},
                            'content-update': {'policy_id': 'content-1'},
                            'firewall': {'policy_id': 'fw-1'},
                            'device_control': {'policy_id': 'dc-1'},
                            'it-automation': {'policy_id': 'it-1'}
                        }
                    }
                }

            def get_host_zta(self, device_id):
                return None

        # All policies PASSED
        policy_records = {
            'prevention': {'graded_policies': [{'policy_id': 'prev-1', 'passed': True}]},
            'sensor_update': {'graded_policies': [{'policy_id': 'sensor-1', 'passed': True}]},
            'content_update': {'graded_policies': [{'policy_id': 'content-1', 'passed': True}]},
            'firewall': {'graded_policies': [{'policy_id': 'fw-1', 'passed': True}]},
            'device_control': {'graded_policies': [{'policy_id': 'dc-1', 'passed': True}]},
            'it_automation': {'graded_policies': [{'policy_id': 'it-1', 'passed': True}]}
        }

        adapter = MockAdapter()
        host_data = collect_host_data(
            adapter,
            'test-cid',
            policy_records,
            get_policy_status,
            config={'host_fetching': {'include_zta': False}}
        )

        assert len(host_data) == 1
        host = host_data[0]

        # Host should pass
        assert host['any_failed'] is False
        assert host['all_passed'] is True

        # All policies should show PASSED
        assert host['prevention_status'] == 'PASSED'
        assert host['sensor_update_status'] == 'PASSED'

    def test_host_with_multiple_failed_policies(self):
        """Test host fails when multiple policies fail."""
        class MockAdapter:
            def get_hosts(self, cid):
                return {'hosts': ['device-1']}

            def get_host(self, device_id):
                return {
                    'data': {
                        'device_id': device_id,
                        'hostname': 'test-host',
                        'platform_name': 'Windows',
                        'device_policies': {
                            'prevention': {'policy_id': 'prev-1'},
                            'sensor_update': {'policy_id': 'sensor-1'},
                            'content-update': {'policy_id': 'content-1'},
                            'firewall': {'policy_id': 'fw-1'},
                            'device_control': {'policy_id': 'dc-1'},
                            'it-automation': {'policy_id': 'it-1'}
                        }
                    }
                }

            def get_host_zta(self, device_id):
                return None

        # Multiple policies FAILED
        policy_records = {
            'prevention': {'graded_policies': [{'policy_id': 'prev-1', 'passed': False}]},  # FAILED
            'sensor_update': {'graded_policies': [{'policy_id': 'sensor-1', 'passed': True}]},
            'content_update': {'graded_policies': [{'policy_id': 'content-1', 'passed': True}]},
            'firewall': {'graded_policies': [{'policy_id': 'fw-1', 'passed': False}]},  # FAILED
            'device_control': {'graded_policies': [{'policy_id': 'dc-1', 'passed': True}]},
            'it_automation': {'graded_policies': [{'policy_id': 'it-1', 'passed': False}]}  # FAILED
        }

        adapter = MockAdapter()
        host_data = collect_host_data(
            adapter,
            'test-cid',
            policy_records,
            get_policy_status,
            config={'host_fetching': {'include_zta': False}}
        )

        assert len(host_data) == 1
        host = host_data[0]

        # Host should fail
        assert host['any_failed'] is True
        assert host['all_passed'] is False

        # Verify failed policies
        assert host['prevention_status'] == 'FAILED'
        assert host['firewall_status'] == 'FAILED'
        assert host['it_automation_status'] == 'FAILED'

        # Verify passed policies
        assert host['sensor_update_status'] == 'PASSED'


@pytest.mark.unit
class TestHostStatsAggregation:
    """Test host-level statistics aggregation."""

    def test_calculate_host_stats_mixed(self):
        """Test calculating stats for mix of passed/failed hosts."""
        host_data = [
            {'device_id': '1', 'all_passed': True, 'any_failed': False},
            {'device_id': '2', 'all_passed': True, 'any_failed': False},
            {'device_id': '3', 'all_passed': False, 'any_failed': True},
            {'device_id': '4', 'all_passed': True, 'any_failed': False},
            {'device_id': '5', 'all_passed': False, 'any_failed': True},
        ]

        stats = calculate_host_stats(host_data)

        assert stats['total'] == 5
        assert stats['all_passed'] == 3
        assert stats['any_failed'] == 2

    def test_calculate_host_stats_all_passed(self):
        """Test stats when all hosts pass."""
        host_data = [
            {'device_id': '1', 'all_passed': True, 'any_failed': False},
            {'device_id': '2', 'all_passed': True, 'any_failed': False},
        ]

        stats = calculate_host_stats(host_data)

        assert stats['total'] == 2
        assert stats['all_passed'] == 2
        assert stats['any_failed'] == 0

    def test_calculate_host_stats_all_failed(self):
        """Test stats when all hosts fail."""
        host_data = [
            {'device_id': '1', 'all_passed': False, 'any_failed': True},
            {'device_id': '2', 'all_passed': False, 'any_failed': True},
            {'device_id': '3', 'all_passed': False, 'any_failed': True},
        ]

        stats = calculate_host_stats(host_data)

        assert stats['total'] == 3
        assert stats['all_passed'] == 0
        assert stats['any_failed'] == 3

    def test_calculate_host_stats_empty(self):
        """Test stats with no hosts."""
        stats = calculate_host_stats([])

        assert stats['total'] == 0
        assert stats['all_passed'] == 0
        assert stats['any_failed'] == 0


@pytest.mark.unit
class TestCompleteRollupChain:
    """Test the complete setting → policy → host rollup chain."""

    def test_single_setting_failure_propagates_to_host(self):
        """Test that a single setting failure cascades all the way to host failure.

        This is the critical business logic test:
        - One slider is set to MODERATE when minimum is EXTRA_AGGRESSIVE
        - This fails the setting
        - The setting failure fails the entire prevention policy
        - The prevention policy failure fails the entire host
        """
        # Step 1: Setting failure
        policy = {
            'id': 'critical-policy',
            'name': 'Critical Prevention Policy',
            'platform_name': 'Windows',
            'enabled': True,
            'prevention_settings': [
                {
                    'settings': [
                        {
                            'id': 'CloudAntiMalware',
                            'type': 'mlslider',
                            'value': {
                                'detection': 'MODERATE',  # TOO LOW!
                                'prevention': 'EXTRA_AGGRESSIVE'
                            }
                        }
                    ]
                }
            ]
        }

        grading_config = {
            'prevention_policies': [
                {
                    'platform_name': 'Windows',
                    'prevention_settings': [
                        {
                            'settings': [
                                {
                                    'id': 'CloudAntiMalware',
                                    'value': {
                                        'detection': 'EXTRA_AGGRESSIVE',
                                        'prevention': 'EXTRA_AGGRESSIVE'
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        # Grade the policy
        policy_result = grade_prevention_policy(policy, grading_config)

        # Step 2: Policy fails due to setting
        assert policy_result['passed'] is False, "Policy should fail due to setting"
        assert policy_result['failures_count'] == 1

        # Step 3: Host inherits policy failure
        class MockAdapter:
            def get_hosts(self, cid):
                return {'hosts': ['critical-host']}

            def get_host(self, device_id):
                return {
                    'data': {
                        'device_id': device_id,
                        'hostname': 'production-server',
                        'platform_name': 'Windows',
                        'device_policies': {
                            'prevention': {'policy_id': 'critical-policy'},
                            'sensor_update': {'policy_id': None},
                            'content-update': {'policy_id': None},
                            'firewall': {'policy_id': None},
                            'device_control': {'policy_id': None},
                            'it-automation': {'policy_id': None}
                        }
                    }
                }

            def get_host_zta(self, device_id):
                return None

        policy_records = {
            'prevention': {
                'graded_policies': [policy_result]
            },
            'sensor_update': None,
            'content_update': None,
            'firewall': None,
            'device_control': None,
            'it_automation': None
        }

        adapter = MockAdapter()
        host_data = collect_host_data(
            adapter,
            'test-cid',
            policy_records,
            get_policy_status,
            config={'host_fetching': {'include_zta': False}}
        )

        # Host should fail due to the cascaded failure
        assert len(host_data) == 1
        host = host_data[0]
        assert host['any_failed'] is True, "Host should fail due to policy failure"
        assert host['all_passed'] is False, "Host cannot pass with failed policy"
        assert host['prevention_status'] == 'FAILED'

        # Verify stats aggregation
        stats = calculate_host_stats(host_data)
        assert stats['any_failed'] == 1, "Should count 1 failed host"
        assert stats['all_passed'] == 0, "Should count 0 passed hosts"

    def test_one_bad_policy_affects_multiple_hosts(self):
        """Test that one failing policy causes all hosts using it to fail.

        This reflects the documentation:
        'If a failed policy applies to two hundred hosts, fixing that one policy 
        causes all two hundred hosts to show as passing on the next assessment.'
        """
        # Create a policy that fails
        policy_result = {
            'policy_id': 'shared-policy',
            'policy_name': 'Shared Policy',
            'platform_name': 'Windows',
            'passed': False,  # Policy fails
            'failures_count': 1,
            'checks_count': 1
        }

        class MockAdapter:
            def __init__(self, host_count):
                self.host_count = host_count

            def get_hosts(self, cid):
                return {'hosts': [f'host-{i}' for i in range(self.host_count)]}

            def get_host(self, device_id):
                return {
                    'data': {
                        'device_id': device_id,
                        'hostname': f'server-{device_id}',
                        'platform_name': 'Windows',
                        'device_policies': {
                            'prevention': {'policy_id': 'shared-policy'},  # All use same policy
                            'sensor_update': {'policy_id': None},
                            'content-update': {'policy_id': None},
                            'firewall': {'policy_id': None},
                            'device_control': {'policy_id': None},
                            'it-automation': {'policy_id': None}
                        }
                    }
                }

            def get_host_zta(self, device_id):
                return None

        policy_records = {
            'prevention': {'graded_policies': [policy_result]},
            'sensor_update': None,
            'content_update': None,
            'firewall': None,
            'device_control': None,
            'it_automation': None
        }

        # Test with 200 hosts
        adapter = MockAdapter(host_count=200)
        host_data = collect_host_data(
            adapter,
            'test-cid',
            policy_records,
            get_policy_status,
            config={'host_fetching': {'include_zta': False}}
        )

        # All 200 hosts should fail
        assert len(host_data) == 200
        for host in host_data:
            assert host['any_failed'] is True
            assert host['all_passed'] is False
            assert host['prevention_status'] == 'FAILED'

        # Stats should reflect mass failure
        stats = calculate_host_stats(host_data)
        assert stats['total'] == 200
        assert stats['any_failed'] == 200
        assert stats['all_passed'] == 0
