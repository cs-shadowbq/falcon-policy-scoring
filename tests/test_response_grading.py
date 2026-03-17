"""
Tests for Response (RTR) policy grading logic.

Tests the toggle-based grading for Real-Time Response policies without
requiring live API connections.
"""

import pytest
from falcon_policy_scoring.grading.graders.response import (
    flatten_response_settings,
    grade_response_policy,
    grade_all_response_policies,
)
from falcon_policy_scoring.grading.results import grade_setting, _create_empty_policy_result


# ---------------------------------------------------------------------------
# Minimal passing grading config (mirrors response_policies_grading.json)
# ---------------------------------------------------------------------------

GRADING_CONFIG = {
    "response_policies": [
        {
            "platform_name": "Windows",
            "enabled": True,
            "response_settings": [
                {"id": "RealTimeFunctionality", "value": {"enabled": True}},
                {"id": "CustomScripts", "value": {"enabled": True}},
                {"id": "GetCommand", "value": {"enabled": True}},
                {"id": "PutCommand", "value": {"enabled": True}},
                {"id": "ExecCommand", "value": {"enabled": True}},
                {"id": "PutAndRunCommand", "value": {"enabled": True}},
            ],
        },
        {
            "platform_name": "Linux",
            "enabled": True,
            "response_settings": [
                {"id": "RealTimeFunctionality", "value": {"enabled": True}},
                {"id": "CustomScripts", "value": {"enabled": True}},
                {"id": "GetCommand", "value": {"enabled": True}},
                {"id": "PutCommand", "value": {"enabled": True}},
                {"id": "ExecCommand", "value": {"enabled": True}},
            ],
        },
        {
            "platform_name": "Mac",
            "enabled": True,
            "response_settings": [
                {"id": "RealTimeFunctionality", "value": {"enabled": True}},
                {"id": "CustomScripts", "value": {"enabled": True}},
                {"id": "GetCommand", "value": {"enabled": True}},
                {"id": "PutCommand", "value": {"enabled": True}},
                {"id": "ExecCommand", "value": {"enabled": True}},
            ],
        },
    ]
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_setting(setting_id, enabled=True):
    """Build a minimal RTR policy setting (leaf node)."""
    return {
        "id": setting_id,
        "name": setting_id,
        "type": "toggle",
        "value": {"enabled": enabled},
    }


def make_group(group_id, settings):
    """Build a settings group containing the given leaf settings."""
    return {"id": group_id, "name": group_id, "settings": settings}


def make_windows_policy(
    policy_id="pol-win-1",
    policy_name="Full RTR Windows",
    enabled=True,
    rtf=True,
    custom_scripts=True,
    get_cmd=True,
    put_cmd=True,
    exec_cmd=True,
    put_and_run=True,
):
    """Build a minimal Windows RTR policy dict matching the 2-level API structure."""
    group1_settings = [
        make_setting("RealTimeFunctionality", rtf),
        make_setting("CustomScripts", custom_scripts),
    ]
    group2_settings = [
        make_setting("GetCommand", get_cmd),
        make_setting("PutCommand", put_cmd),
        make_setting("ExecCommand", exec_cmd),
        make_setting("PutAndRunCommand", put_and_run),
    ]
    return {
        "id": policy_id,
        "name": policy_name,
        "platform_name": "Windows",
        "enabled": enabled,
        "settings": [
            make_group("response_basic", group1_settings),
            make_group("response_advanced", group2_settings),
        ],
    }


def make_linux_policy(
    policy_id="pol-lin-1",
    policy_name="Full RTR Linux",
    enabled=True,
    rtf=True,
    custom_scripts=True,
    get_cmd=True,
    put_cmd=True,
    exec_cmd=True,
):
    """Build a minimal Linux RTR policy dict (no PutAndRunCommand)."""
    group_settings = [
        make_setting("RealTimeFunctionality", rtf),
        make_setting("CustomScripts", custom_scripts),
        make_setting("GetCommand", get_cmd),
        make_setting("PutCommand", put_cmd),
        make_setting("ExecCommand", exec_cmd),
    ]
    return {
        "id": policy_id,
        "name": policy_name,
        "platform_name": "Linux",
        "enabled": enabled,
        "settings": [make_group("response_basic", group_settings)],
    }


# ---------------------------------------------------------------------------
# flatten_response_settings
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFlattenResponseSettings:
    """Tests for flatten_response_settings helper."""

    def test_single_group_single_setting(self):
        policy = {
            "settings": [make_group("g1", [make_setting("RealTimeFunctionality")])]
        }
        result = flatten_response_settings(policy)
        assert "RealTimeFunctionality" in result
        assert result["RealTimeFunctionality"]["type"] == "toggle"

    def test_multiple_groups_no_collisions(self):
        policy = {
            "settings": [
                make_group("g1", [make_setting("GetCommand"), make_setting("PutCommand")]),
                make_group("g2", [make_setting("ExecCommand")]),
            ]
        }
        result = flatten_response_settings(policy)
        assert set(result.keys()) == {"GetCommand", "PutCommand", "ExecCommand"}

    def test_empty_settings_returns_empty_dict(self):
        result = flatten_response_settings({"settings": []})
        assert result == {}

    def test_missing_settings_key_returns_empty_dict(self):
        result = flatten_response_settings({})
        assert result == {}

    def test_setting_without_id_is_skipped(self):
        policy = {"settings": [{"id": "g1", "settings": [{"type": "toggle"}]}]}
        result = flatten_response_settings(policy)
        assert result == {}

    def test_full_windows_policy(self):
        policy = make_windows_policy()
        result = flatten_response_settings(policy)
        expected_keys = {
            "RealTimeFunctionality", "CustomScripts",
            "GetCommand", "PutCommand", "ExecCommand", "PutAndRunCommand",
        }
        assert set(result.keys()) == expected_keys


# ---------------------------------------------------------------------------
# grade_response_policy
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestGradeResponsePolicy:
    """Tests for grade_response_policy function."""

    def test_fully_passing_windows_policy(self):
        policy = make_windows_policy()
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["passed"] is True
        assert result["failures_count"] == 0
        assert result["checks_count"] == 7  # 1 enabled check + 6 required settings for Windows

    def test_fully_passing_linux_policy(self):
        policy = make_linux_policy()
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["passed"] is True
        assert result["failures_count"] == 0
        assert result["checks_count"] == 6  # 1 enabled check + 5 required settings (no PutAndRunCommand)

    def test_disabled_policy_fails(self):
        policy = make_windows_policy(enabled=False)
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["passed"] is False

    def test_rtf_disabled_fails(self):
        policy = make_windows_policy(rtf=False)
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["passed"] is False
        assert result["failures_count"] == 1

    def test_put_and_run_disabled_on_windows_fails(self):
        policy = make_windows_policy(put_and_run=False)
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["passed"] is False
        failure_ids = [fr["setting_id"] for fr in result["setting_results"] if not fr["passed"]]
        assert "PutAndRunCommand" in failure_ids

    def test_multiple_settings_disabled_accumulates_failures(self):
        policy = make_windows_policy(get_cmd=False, put_cmd=False, exec_cmd=False)
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["passed"] is False
        assert result["failures_count"] == 3

    def test_unknown_platform_returns_ungradable(self):
        policy = {
            "id": "pol-unknown",
            "name": "Unknown Platform Policy",
            "platform_name": "ChromeOS",
            "enabled": True,
            "settings": [],
        }
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["grading_status"] == "ungradable"
        assert result["ungradable_reason"] == "no_platform_config"

    def test_none_policy_returns_empty_result(self):
        result = grade_response_policy(None, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        # Should not raise; should return some result dict
        assert isinstance(result, dict)

    def test_policy_without_put_and_run_linux_still_passes(self):
        """Linux policy must pass even though it has no PutAndRunCommand setting.
        The grader should skip unknown settings rather than fail."""
        policy = make_linux_policy()
        # Confirm PutAndRunCommand is not present
        flat = flatten_response_settings(policy)
        assert "PutAndRunCommand" not in flat

        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        assert result["passed"] is True

    def test_result_fields_present(self):
        policy = make_windows_policy()
        result = grade_response_policy(policy, GRADING_CONFIG, grade_setting, _create_empty_policy_result)
        for field in ("policy_id", "policy_name", "platform_name", "passed",
                      "checks_count", "failures_count", "setting_results"):
            assert field in result, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# grade_all_response_policies
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestGradeAllResponsePolicies:
    """Tests for grade_all_response_policies function."""

    def test_grades_list_of_policies(self):
        policies_data = [make_windows_policy(policy_id="w1"), make_linux_policy(policy_id="l1")]
        results = grade_all_response_policies(policies_data, GRADING_CONFIG)
        assert len(results) == 2
        assert all(r["passed"] is True for r in results)

    def test_grades_mixed_pass_fail(self):
        policies_data = [
            make_windows_policy(policy_id="w1"),
            make_windows_policy(policy_id="w2", put_and_run=False),
        ]
        results = grade_all_response_policies(policies_data, GRADING_CONFIG)
        assert len(results) == 2
        statuses = {r["policy_id"]: r["passed"] for r in results}
        assert statuses["w1"] is True
        assert statuses["w2"] is False

    def test_accepts_dict_with_policies_key(self):
        policies_data = {"policies": [make_windows_policy()]}
        results = grade_all_response_policies(policies_data, GRADING_CONFIG)
        assert len(results) == 1
        assert results[0]["passed"] is True

    def test_empty_list_returns_empty_list(self):
        results = grade_all_response_policies([], GRADING_CONFIG)
        assert results == []

    def test_empty_dict_returns_empty_list(self):
        results = grade_all_response_policies({}, GRADING_CONFIG)
        assert results == []

    def test_failing_windows_policy_in_batch(self):
        policies_data = [
            make_windows_policy(policy_id="w1", rtf=False),
            make_linux_policy(policy_id="l1"),
        ]
        results = grade_all_response_policies(policies_data, GRADING_CONFIG)
        windows_result = next(r for r in results if r["policy_id"] == "w1")
        linux_result = next(r for r in results if r["policy_id"] == "l1")
        assert windows_result["passed"] is False
        assert linux_result["passed"] is True
