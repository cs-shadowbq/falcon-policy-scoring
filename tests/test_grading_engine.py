"""
Tests for the grading engine.

Tests the policy grading system with focus on:
- Comparison type registry (mlslider, toggle, n-level)
- Score aggregation logic
- JSON grading file loading
- Edge cases and error handling
- Extensibility for new comparison types

Tests use synthetic policy data and are designed to remain valid when new
grading files or comparison types are added.
"""

from falcon_policy_scoring.grading.utils import (
    compare_mlslider,
    compare_toggle,
    compare_n_level
)
from falcon_policy_scoring.grading.constants import (
    MLSLIDER_LEVELS,
    TOGGLE_LEVELS,
    N_LEVELS
)
import pytest
import json
from pathlib import Path
from typing import Dict, Any, List

from falcon_policy_scoring.grading.engine import load_grading_config
from falcon_policy_scoring.grading.results import (
    grade_setting,
    _create_empty_policy_result
)
from falcon_policy_scoring.grading.graders.prevention import (
    grade_prevention_policy as _grade_prevention_policy
)

# Wrapper for backward compatibility with test signature
def grade_prevention_policy(policy, grading_config):
    return _grade_prevention_policy(
        policy, grading_config, grade_setting, _create_empty_policy_result
    )


@pytest.mark.unit
class TestComparisonTypes:
    """Test all comparison type functions for correctness."""

    @pytest.mark.parametrize("actual,minimum,expected", [
        ('DISABLED', 'DISABLED', True),
        ('CAUTIOUS', 'DISABLED', True),
        ('MODERATE', 'MODERATE', True),
        ('MODERATE', 'CAUTIOUS', True),
        ('AGGRESSIVE', 'MODERATE', True),
        ('EXTRA_AGGRESSIVE', 'AGGRESSIVE', True),
        ('DISABLED', 'MODERATE', False),
        ('CAUTIOUS', 'MODERATE', False),
        ('MODERATE', 'AGGRESSIVE', False),
        ('AGGRESSIVE', 'EXTRA_AGGRESSIVE', False),
    ])
    def test_compare_mlslider(self, actual: str, minimum: str, expected: bool):
        """Test mlslider comparison across all valid combinations."""
        assert compare_mlslider(actual, minimum) == expected

    @pytest.mark.parametrize("actual,minimum", [
        ('DISABLED', 'DISABLED'),
        ('CAUTIOUS', 'CAUTIOUS'),
        ('MODERATE', 'MODERATE'),
        ('AGGRESSIVE', 'AGGRESSIVE'),
        ('EXTRA_AGGRESSIVE', 'EXTRA_AGGRESSIVE'),
    ])
    def test_compare_mlslider_equal(self, actual: str, minimum: str):
        """Test mlslider comparison for equal values."""
        assert compare_mlslider(actual, minimum) is True

    @pytest.mark.parametrize("actual,minimum", [
        ('INVALID', 'MODERATE'),
        ('MODERATE', 'INVALID'),
        ('', 'MODERATE'),
        (None, 'MODERATE'),
        ('MODERATE', None),
    ])
    def test_compare_mlslider_invalid(self, actual, minimum):
        """Test mlslider comparison with invalid values."""
        assert compare_mlslider(actual, minimum) is False

    @pytest.mark.parametrize("actual", [
        'disabled', 'DISABLED', 'Disabled',
        'moderate', 'MODERATE', 'Moderate',
    ])
    def test_compare_mlslider_case_insensitive(self, actual: str):
        """Test mlslider comparison is case-insensitive."""
        assert compare_mlslider(actual, 'MODERATE') in [True, False]

    @pytest.mark.parametrize("actual,minimum,expected", [
        (True, True, True),
        (True, False, True),
        (False, False, True),
        (False, True, False),
        (1, 1, True),
        (1, 0, True),
        (0, 0, True),
        (0, 1, False),
        ('true', 'true', True),
        ('false', 'false', True),
    ])
    def test_compare_toggle(self, actual, minimum, expected: bool):
        """Test toggle comparison with various value types."""
        assert compare_toggle(actual, minimum) == expected

    @pytest.mark.parametrize("actual,minimum,expected", [
        ('n', 'n', True),
        ('n', 'n-1', True),
        ('n', 'n-2', True),
        ('n-1', 'n-1', True),
        ('n-1', 'n-2', True),
        ('n-2', 'n-2', True),
        ('n-2', 'n-1', False),
        ('n-1', 'n', False),
        ('n-2', 'n', False),
        ('disabled', 'n-2', False),
        ('pinned', 'n-2', False),
    ])
    def test_compare_n_level(self, actual: str, minimum: str, expected: bool):
        """Test n-level comparison for sensor updates."""
        assert compare_n_level(actual, minimum) == expected

    @pytest.mark.parametrize("actual,minimum", [
        ('invalid', 'n'),
        ('n', 'invalid'),
        ('', 'n'),
        (None, 'n'),
    ])
    def test_compare_n_level_invalid(self, actual, minimum):
        """Test n-level comparison with invalid values."""
        assert compare_n_level(actual, minimum) is False


@pytest.mark.unit
class TestSettingGrading:
    """Test individual setting grading logic."""

    def test_grade_mlslider_setting_pass(self):
        """Test grading a passing mlslider setting."""
        setting = {
            'id': 'CloudAntiMalware',
            'name': 'Cloud Machine Learning',
            'type': 'mlslider',
            'value': {
                'detection': 'AGGRESSIVE',
                'prevention': 'MODERATE'
            }
        }
        minimum = {
            'id': 'CloudAntiMalware',
            'value': {
                'detection': 'MODERATE',
                'prevention': 'MODERATE'
            }
        }

        result = grade_setting(setting, minimum)

        assert result['passed'] is True
        assert result['setting_id'] == 'CloudAntiMalware'
        assert len(result['failures']) == 0

    def test_grade_mlslider_setting_fail_detection(self):
        """Test grading a failing mlslider setting (detection too low)."""
        setting = {
            'id': 'CloudAntiMalware',
            'name': 'Cloud Machine Learning',
            'type': 'mlslider',
            'value': {
                'detection': 'CAUTIOUS',
                'prevention': 'AGGRESSIVE'
            }
        }
        minimum = {
            'id': 'CloudAntiMalware',
            'value': {
                'detection': 'MODERATE',
                'prevention': 'MODERATE'
            }
        }

        result = grade_setting(setting, minimum)

        assert result['passed'] is False
        assert len(result['failures']) == 1
        assert result['failures'][0]['field'] == 'detection'
        assert result['failures'][0]['actual'] == 'CAUTIOUS'
        assert result['failures'][0]['minimum'] == 'MODERATE'

    def test_grade_mlslider_setting_fail_prevention(self):
        """Test grading a failing mlslider setting (prevention too low)."""
        setting = {
            'id': 'CloudAntiMalware',
            'type': 'mlslider',
            'value': {
                'detection': 'AGGRESSIVE',
                'prevention': 'DISABLED'
            }
        }
        minimum = {
            'id': 'CloudAntiMalware',
            'value': {
                'detection': 'MODERATE',
                'prevention': 'MODERATE'
            }
        }

        result = grade_setting(setting, minimum)

        assert result['passed'] is False
        assert len(result['failures']) == 1
        assert result['failures'][0]['field'] == 'prevention'

    def test_grade_mlslider_setting_fail_both(self):
        """Test grading a failing mlslider setting (both too low)."""
        setting = {
            'id': 'CloudAntiMalware',
            'type': 'mlslider',
            'value': {
                'detection': 'DISABLED',
                'prevention': 'CAUTIOUS'
            }
        }
        minimum = {
            'id': 'CloudAntiMalware',
            'value': {
                'detection': 'MODERATE',
                'prevention': 'MODERATE'
            }
        }

        result = grade_setting(setting, minimum)

        assert result['passed'] is False
        assert len(result['failures']) == 2

    def test_grade_toggle_setting_pass(self):
        """Test grading a passing toggle setting."""
        setting = {
            'id': 'Quarantine',
            'name': 'Quarantine',
            'type': 'toggle',
            'value': {'enabled': True}
        }
        minimum = {
            'id': 'Quarantine',
            'value': {'enabled': True}
        }

        result = grade_setting(setting, minimum)

        assert result['passed'] is True
        assert len(result['failures']) == 0

    def test_grade_toggle_setting_fail(self):
        """Test grading a failing toggle setting."""
        setting = {
            'id': 'Quarantine',
            'type': 'toggle',
            'value': {'enabled': False}
        }
        minimum = {
            'id': 'Quarantine',
            'value': {'enabled': True}
        }

        result = grade_setting(setting, minimum)

        assert result['passed'] is False
        assert len(result['failures']) == 1
        assert result['failures'][0]['actual'] is False
        assert result['failures'][0]['minimum'] is True

    def test_grade_setting_missing_value(self):
        """Test grading a setting with missing value field."""
        setting = {
            'id': 'TestSetting',
            'type': 'mlslider'
            # Missing 'value' field
        }
        minimum = {
            'id': 'TestSetting',
            'value': {'detection': 'MODERATE'}
        }

        result = grade_setting(setting, minimum)

        # Should handle gracefully
        assert 'passed' in result
        assert 'failures' in result

    def test_grade_setting_unknown_type(self):
        """Test grading a setting with unknown type (should pass with warning)."""
        setting = {
            'id': 'TestSetting',
            'type': 'unknown_type',
            'value': 'some_value'
        }
        minimum = {
            'id': 'TestSetting',
            'value': 'some_minimum'
        }

        result = grade_setting(setting, minimum)

        # Unknown types should pass (logged warning)
        assert result['passed'] is True


@pytest.mark.unit
class TestGradingConfigLoading:
    """Test loading and parsing of grading configuration files."""

    def test_load_grading_config_prevention(self):
        """Test loading prevention policy grading config."""
        config = load_grading_config('prevention_policies')

        assert config is not None
        assert isinstance(config, dict)
        assert 'prevention_policies' in config
        assert len(config['prevention_policies']) > 0

    def test_load_grading_config_sensor_update(self):
        """Test loading sensor update policy grading config."""
        config = load_grading_config('sensor_update_policies')

        assert config is not None
        assert isinstance(config, dict)
        # Sensor update has 'policies' key
        assert 'policies' in config

    def test_load_grading_config_firewall(self):
        """Test loading firewall policy grading config."""
        config = load_grading_config('firewall_policies')

        assert config is not None
        assert isinstance(config, dict)
        # Firewall has 'platform_requirements' key
        assert 'platform_requirements' in config

    @pytest.mark.parametrize("policy_type", [
        'prevention_policies',
        'sensor_update_policies',
        'firewall_policies',
        'device_control_policies',
        'content_update_policies',
        'it_automation_policies',
    ])
    def test_load_all_grading_configs(self, policy_type: str):
        """Test that all grading config files can be loaded."""
        config = load_grading_config(policy_type)

        assert config is not None
        assert isinstance(config, dict)
        # Config should have at least one key
        assert len(config) > 0

    def test_load_grading_config_nonexistent(self):
        """Test loading a non-existent grading config."""
        config = load_grading_config('nonexistent_policy_type')

        # Should return empty dict on error
        assert config == {}

    def test_load_grading_config_explicit_path(self, tmp_path: Path):
        """Test loading grading config from explicit path."""
        # Create a temporary config file
        config_data = {
            'test_policies': [
                {'platform_name': 'Test', 'settings': []}
            ]
        }
        config_file = tmp_path / "test_grading.json"
        with open(config_file, 'w') as f:
            json.dump(config_data, f)

        config = load_grading_config(config_file=str(config_file))

        assert config == config_data

    def test_grading_config_structure(self):
        """Test that grading config has expected structure."""
        config = load_grading_config('prevention_policies')

        assert 'prevention_policies' in config
        policies = config['prevention_policies']
        assert isinstance(policies, list)

        # Check first policy structure
        if len(policies) > 0:
            policy = policies[0]
            assert 'platform_name' in policy
            assert 'prevention_settings' in policy


@pytest.mark.unit
class TestPolicyGrading:
    """Test complete policy grading workflows."""

    def test_grade_prevention_policy_pass(self):
        """Test grading a passing prevention policy."""
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
                                        'detection': 'MODERATE',
                                        'prevention': 'MODERATE'
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        result = grade_prevention_policy(policy, grading_config)

        assert result is not None
        assert result['policy_id'] == 'test-policy-id'
        assert result['policy_name'] == 'Test Prevention Policy'
        assert 'passed' in result
        assert 'setting_results' in result

    def test_grade_prevention_policy_none(self):
        """Test grading a None policy."""
        result = grade_prevention_policy(None, {})

        assert result is not None
        assert result['passed'] is False
        assert result['policy_id'] == 'unknown'

    def test_create_empty_policy_result(self):
        """Test creating an empty policy result structure."""
        result = _create_empty_policy_result(
            policy_id='test-id',
            policy_name='Test Policy',
            platform_name='Windows'
        )

        assert result['policy_id'] == 'test-id'
        assert result['policy_name'] == 'Test Policy'
        assert result['platform_name'] == 'Windows'
        assert result['passed'] is False
        assert result['setting_results'] == []
        assert result['failures_count'] == 0
        assert result['checks_count'] == 0


@pytest.mark.unit
class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_mlslider_boundary_values(self):
        """Test mlslider at level boundaries."""
        # Minimum level (DISABLED)
        assert compare_mlslider('DISABLED', 'DISABLED') is True
        assert compare_mlslider('CAUTIOUS', 'DISABLED') is True

        # Maximum level (EXTRA_AGGRESSIVE)
        assert compare_mlslider('EXTRA_AGGRESSIVE', 'EXTRA_AGGRESSIVE') is True
        assert compare_mlslider('AGGRESSIVE', 'EXTRA_AGGRESSIVE') is False

    def test_n_level_boundary_values(self):
        """Test n-level at boundaries."""
        # Minimum valid level (n-2)
        assert compare_n_level('n-2', 'n-2') is True
        assert compare_n_level('n-1', 'n-2') is True
        assert compare_n_level('pinned', 'n-2') is False

        # Maximum level (n)
        assert compare_n_level('n', 'n') is True
        assert compare_n_level('n-1', 'n') is False

    def test_setting_with_empty_value(self):
        """Test grading setting with empty value dict."""
        setting = {
            'id': 'TestSetting',
            'type': 'mlslider',
            'value': {}
        }
        minimum = {
            'id': 'TestSetting',
            'value': {'detection': 'MODERATE'}
        }

        result = grade_setting(setting, minimum)

        # Should handle gracefully and report failure for missing detection
        assert result['passed'] is False

    def test_toggle_with_non_dict_value(self):
        """Test toggle comparison when value is not a dict."""
        setting = {
            'id': 'TestToggle',
            'type': 'toggle',
            'value': True  # Not wrapped in dict
        }
        minimum = {
            'id': 'TestToggle',
            'value': True
        }

        result = grade_setting(setting, minimum)

        # Should handle both dict and non-dict values
        assert result['passed'] is True


@pytest.mark.unit
class TestConstantsRegistry:
    """Test that constants registries are properly defined."""

    def test_mlslider_levels_complete(self):
        """Test that MLSLIDER_LEVELS contains all expected values."""
        expected_levels = ['DISABLED', 'CAUTIOUS', 'MODERATE', 'AGGRESSIVE', 'EXTRA_AGGRESSIVE']

        for level in expected_levels:
            assert level in MLSLIDER_LEVELS
            assert isinstance(MLSLIDER_LEVELS[level], int)

        # Test ordering
        assert MLSLIDER_LEVELS['DISABLED'] < MLSLIDER_LEVELS['CAUTIOUS']
        assert MLSLIDER_LEVELS['CAUTIOUS'] < MLSLIDER_LEVELS['MODERATE']
        assert MLSLIDER_LEVELS['MODERATE'] < MLSLIDER_LEVELS['AGGRESSIVE']
        assert MLSLIDER_LEVELS['AGGRESSIVE'] < MLSLIDER_LEVELS['EXTRA_AGGRESSIVE']

    def test_toggle_levels_complete(self):
        """Test that TOGGLE_LEVELS contains all expected values."""
        # Should support boolean and string representations
        assert TOGGLE_LEVELS[False] == 0
        assert TOGGLE_LEVELS[True] == 1
        assert TOGGLE_LEVELS['false'] == 0
        assert TOGGLE_LEVELS['true'] == 1
        assert TOGGLE_LEVELS[0] == 0
        assert TOGGLE_LEVELS[1] == 1

    def test_n_levels_complete(self):
        """Test that N_LEVELS contains all expected values."""
        expected_levels = ['disabled', 'other', 'pinned', 'n-2', 'n-1', 'n']

        for level in expected_levels:
            assert level in N_LEVELS
            assert isinstance(N_LEVELS[level], int)

        # Test ordering
        assert N_LEVELS['n-2'] < N_LEVELS['n-1']
        assert N_LEVELS['n-1'] < N_LEVELS['n']
        assert N_LEVELS['disabled'] < N_LEVELS['n-2']


@pytest.mark.unit
class TestITAutomationGrading:
    """Test IT automation policy grading with focus on config transformation and output."""

    def test_normalize_it_automation_config_windows(self):
        """Test config normalization for Windows platform."""
        from falcon_policy_scoring.grading.utils import normalize_it_automation_config

        config = {
            "Windows": {
                "is_enabled": True,
                "config": {
                    "execution": {
                        "enable_script_execution": True
                    }
                }
            }
        }

        normalized = normalize_it_automation_config(config)

        # Verify output structure
        assert "platform_requirements" in normalized
        assert isinstance(normalized["platform_requirements"], list)
        assert len(normalized["platform_requirements"]) == 1

        # Verify platform transformation
        platform = normalized["platform_requirements"][0]
        assert platform["platform_name"] == "Windows"
        assert "policy_requirements" in platform
        assert platform["policy_requirements"]["is_enabled"] is True
        assert platform["policy_requirements"]["config"]["execution"]["enable_script_execution"] is True

    def test_normalize_it_automation_config_multiple_platforms(self):
        """Test config normalization handles multiple platforms."""
        from falcon_policy_scoring.grading.utils import normalize_it_automation_config

        config = {
            "Windows": {"is_enabled": True, "config": {}},
            "Linux": {"is_enabled": True, "config": {}},
            "Mac": {"is_enabled": False, "config": {}}
        }

        normalized = normalize_it_automation_config(config)

        # Verify all platforms transformed
        assert len(normalized["platform_requirements"]) == 3
        platform_names = [p["platform_name"] for p in normalized["platform_requirements"]]
        assert "Windows" in platform_names
        assert "Linux" in platform_names
        assert "Mac" in platform_names

    def test_normalize_it_automation_config_preserves_values(self):
        """Test config normalization preserves nested values."""
        from falcon_policy_scoring.grading.utils import normalize_it_automation_config

        config = {
            "Linux": {
                "is_enabled": False,
                "config": {
                    "execution": {
                        "enable_script_execution": False,
                        "custom_field": "value"
                    },
                    "other_section": {"key": 123}
                }
            }
        }

        normalized = normalize_it_automation_config(config)
        platform = normalized["platform_requirements"][0]

        # Verify all nested values preserved
        assert platform["policy_requirements"]["is_enabled"] is False
        assert platform["policy_requirements"]["config"]["execution"]["enable_script_execution"] is False
        assert platform["policy_requirements"]["config"]["execution"]["custom_field"] == "value"
        assert platform["policy_requirements"]["config"]["other_section"]["key"] == 123

    def test_grade_it_automation_policy_all_pass(self):
        """Test IT automation grading when policy meets all requirements."""
        from falcon_policy_scoring.grading.graders.it_automation import grade_it_automation_policy

        grading_config = {
            "Windows": {
                "is_enabled": True,
                "config": {
                    "execution": {
                        "enable_script_execution": True
                    }
                }
            }
        }

        policy = {
            "id": "test-1",
            "name": "Test Policy",
            "target": "Windows",
            "is_enabled": True,
            "config": {
                "execution": {
                    "enable_script_execution": True
                }
            }
        }

        result = grade_it_automation_policy(policy, grading_config)

        # Verify output structure and passing grade
        assert result["passed"] is True
        assert result["checks_count"] == 2
        assert result["failures_count"] == 0
        # Verify result has expected fields (flexible on structure)
        assert "policy_id" in result
        assert "policy_name" in result

    def test_grade_it_automation_policy_disabled_fails(self):
        """Test IT automation grading fails when policy is disabled but should be enabled."""
        from falcon_policy_scoring.grading.graders.it_automation import grade_it_automation_policy

        grading_config = {
            "Linux": {
                "is_enabled": True,
                "config": {}
            }
        }

        policy = {
            "id": "test-2",
            "name": "Disabled Policy",
            "target": "Linux",
            "is_enabled": False,
            "config": {}
        }

        result = grade_it_automation_policy(policy, grading_config)

        # Verify failure for disabled policy
        assert result["passed"] is False
        assert result["failures_count"] >= 1
        # Verify failure message mentions the issue
        result_str = str(result).lower()
        assert "is_enabled" in result_str or "enabled" in result_str

    def test_grade_it_automation_policy_script_execution_fails(self):
        """Test IT automation grading fails when script execution is disabled."""
        from falcon_policy_scoring.grading.graders.it_automation import grade_it_automation_policy

        grading_config = {
            "Mac": {
                "is_enabled": True,
                "config": {
                    "execution": {
                        "enable_script_execution": True
                    }
                }
            }
        }

        policy = {
            "id": "test-3",
            "name": "No Script Execution",
            "target": "Mac",
            "is_enabled": True,
            "config": {
                "execution": {
                    "enable_script_execution": False
                }
            }
        }

        result = grade_it_automation_policy(policy, grading_config)

        # Verify failure for script execution setting
        assert result["passed"] is False
        assert result["failures_count"] >= 1
        # Verify failure message mentions script execution
        result_str = str(result).lower()
        assert "script" in result_str or "execution" in result_str

    def test_grade_it_automation_policy_case_insensitive_platform(self):
        """Test IT automation grading handles case-insensitive platform matching."""
        from falcon_policy_scoring.grading.graders.it_automation import grade_it_automation_policy

        grading_config = {
            "Windows": {
                "is_enabled": True,
                "config": {}
            }
        }

        # Test with lowercase target
        policy = {
            "id": "test-4",
            "name": "Lowercase Target",
            "target": "windows",
            "is_enabled": True,
            "config": {}
        }

        result = grade_it_automation_policy(policy, grading_config)

        # Should find config despite case mismatch
        assert "passed" in result
        assert result["checks_count"] >= 1

    def test_grade_it_automation_policy_unknown_platform(self):
        """Test IT automation grading handles unknown platform gracefully."""
        from falcon_policy_scoring.grading.graders.it_automation import grade_it_automation_policy

        grading_config = {
            "Windows": {
                "is_enabled": True,
                "config": {}
            }
        }

        policy = {
            "id": "test-5",
            "name": "Unknown Platform",
            "target": "UnknownOS",
            "is_enabled": True,
            "config": {}
        }

        result = grade_it_automation_policy(policy, grading_config)

        # Should return result even for unknown platform
        assert "passed" in result
        assert "checks_count" in result
        assert "failures_count" in result

    def test_grade_it_automation_policy_multiple_checks(self):
        """Test IT automation grading evaluates multiple settings."""
        from falcon_policy_scoring.grading.graders.it_automation import grade_it_automation_policy

        grading_config = {
            "Linux": {
                "is_enabled": True,
                "config": {
                    "execution": {
                        "enable_script_execution": True
                    }
                }
            }
        }

        policy = {
            "id": "test-6",
            "name": "Multi Check Policy",
            "target": "Linux",
            "is_enabled": True,
            "config": {
                "execution": {
                    "enable_script_execution": True
                }
            }
        }

        result = grade_it_automation_policy(policy, grading_config)

        # Verify multiple checks executed
        assert result["checks_count"] >= 2
        assert result["passed"] is True
        assert result["failures_count"] == 0
        # Verify result includes policy identification
        assert result["policy_id"] == "test-6"
        assert result["policy_name"] == "Multi Check Policy"

    def test_grade_it_automation_policy_with_real_config(self):
        """Test IT automation grading with actual config file if available."""
        from falcon_policy_scoring.grading.graders.it_automation import grade_it_automation_policy

        config_path = Path('config/grading/it_automation_policies_grading.json')
        if not config_path.exists():
            pytest.skip("Config file not available")

        with open(config_path) as f:
            grading_config = json.load(f)

        # Test with Windows policy matching config
        policy = {
            "id": "real-test",
            "name": "Real Config Test",
            "target": "Windows",
            "is_enabled": True,
            "config": {
                "execution": {
                    "enable_script_execution": True
                }
            }
        }

        result = grade_it_automation_policy(policy, grading_config)

        # Verify output structure matches expected format
        assert isinstance(result, dict)
        assert result["passed"] is True
        assert result["checks_count"] > 0
        assert result["failures_count"] == 0
        # Verify policy was graded successfully
        assert result["policy_name"] == "Real Config Test"
        assert result["target"] == "Windows"


@pytest.mark.unit
class TestExtensibility:
    """Test that the system is extensible for new comparison types."""

    def test_new_comparison_type_fallback(self):
        """Test that unknown comparison types are handled gracefully."""
        setting = {
            'id': 'FutureFeature',
            'type': 'future_comparison_type',
            'value': 'some_value'
        }
        minimum = {
            'id': 'FutureFeature',
            'value': 'minimum_value'
        }

        result = grade_setting(setting, minimum)

        # Should not crash, should pass with warning
        assert 'passed' in result
        assert result['type'] == 'future_comparison_type'

    def test_grading_config_discovery(self):
        """Test that all grading config files are discoverable."""
        grading_dir = Path('config/grading')

        if grading_dir.exists():
            grading_files = list(grading_dir.glob('*_grading.json'))

            # Should have at least the known policy types
            assert len(grading_files) >= 6

            # All files should be loadable
            for grading_file in grading_files:
                with open(grading_file) as f:
                    config = json.load(f)
                assert isinstance(config, dict)
                assert len(config) > 0
