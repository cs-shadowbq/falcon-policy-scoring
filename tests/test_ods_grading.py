"""
Tests for ODS scheduled scan grading logic.

Tests the scan-level grading (status, interval, ML levels) without requiring
live API connections.
"""

import pytest
from falcon_policy_scoring.grading.graders.ods_scheduled_scan import (
    compare_ods_scan,
    grade_ods_scheduled_scan,
    grade_all_ods_scheduled_scans
)


# Minimal passing grading config
GRADING_CONFIG = {
    "platform_requirements": [
        {
            "platform_name": "Windows",
            "policy_requirements": {
                "status": "scheduled",
                "schedule": {
                    "interval": {
                        "maximum": 7
                    }
                },
                "cloud_ml_level_detection": {
                    "minimum": 2
                },
                "sensor_ml_level_detection": {
                    "minimum": 2
                },
                "cloud_ml_level_prevention": {
                    "minimum": 2
                },
                "sensor_ml_level_prevention": {
                    "minimum": 2
                },
                "cloud_pup_adware_level_prevention": {
                    "minimum": 2
                },
                "quarantine": True
            }
        }
    ]
}


def make_scan(**kwargs):
    """Build a minimal scheduled scan dict. Override fields via kwargs."""
    defaults = {
        "id": "scan-001",
        "description": "Test Scan",
        "status": "scheduled",
        "deleted": False,
        "schedule": {"start_timestamp": "2026-03-13T17:00", "interval": 1},
        "cloud_ml_level_detection": 3,
        "sensor_ml_level_detection": 3,
        "cloud_ml_level_prevention": 2,
        "sensor_ml_level_prevention": 2,
        "cloud_pup_adware_level_prevention": 2,
        "quarantine": True,
        "host_groups": ["group-001"]
    }
    defaults.update(kwargs)
    return defaults


@pytest.mark.unit
class TestCompareOdsScan:
    """Unit tests for compare_ods_scan comparison function."""

    def test_passing_scan(self):
        scan = make_scan()
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is True
        assert result["failures"] == []

    def test_wrong_status_fails(self):
        scan = make_scan(status="completed")
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "status" in fields

    def test_interval_at_maximum_passes(self):
        scan = make_scan(schedule={"interval": 7, "start_timestamp": "2026-03-13T17:00"})
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is True

    def test_interval_exceeds_maximum_fails(self):
        scan = make_scan(schedule={"interval": 8, "start_timestamp": "2026-03-13T17:00"})
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "schedule.interval" in fields

    def test_null_interval_fails(self):
        scan = make_scan(schedule={"start_timestamp": "2026-03-13T17:00"})
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "schedule.interval" in fields

    def test_cloud_ml_at_minimum_passes(self):
        scan = make_scan(cloud_ml_level_detection=2)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is True

    def test_cloud_ml_below_minimum_fails(self):
        scan = make_scan(cloud_ml_level_detection=1)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "cloud_ml_level_detection" in fields

    def test_sensor_ml_below_minimum_fails(self):
        scan = make_scan(sensor_ml_level_detection=0)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "sensor_ml_level_detection" in fields

    def test_cloud_ml_prevention_below_minimum_fails(self):
        scan = make_scan(cloud_ml_level_prevention=1)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "cloud_ml_level_prevention" in fields

    def test_cloud_ml_prevention_at_minimum_passes(self):
        scan = make_scan(cloud_ml_level_prevention=2)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is True

    def test_sensor_ml_prevention_below_minimum_fails(self):
        scan = make_scan(sensor_ml_level_prevention=1)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "sensor_ml_level_prevention" in fields

    def test_null_sensor_ml_prevention_fails(self):
        scan = make_scan(sensor_ml_level_prevention=None)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "sensor_ml_level_prevention" in fields

    def test_cloud_pup_adware_prevention_below_minimum_fails(self):
        scan = make_scan(cloud_pup_adware_level_prevention=0)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "cloud_pup_adware_level_prevention" in fields

    def test_quarantine_false_fails(self):
        scan = make_scan(quarantine=False)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "quarantine" in fields

    def test_quarantine_none_fails(self):
        scan = make_scan(quarantine=None)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        fields = [f["field"] for f in result["failures"]]
        assert "quarantine" in fields

    def test_quarantine_true_passes(self):
        scan = make_scan(quarantine=True)
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is True

    def test_multiple_failures_accumulated(self):
        scan = make_scan(
            status="completed",
            cloud_ml_level_detection=0,
            sensor_ml_level_detection=0
        )
        requirements = GRADING_CONFIG["platform_requirements"][0]["policy_requirements"]
        result = compare_ods_scan(scan, requirements)
        assert result["passed"] is False
        assert len(result["failures"]) == 3


@pytest.mark.unit
class TestGradeOdsScheduledScan:
    """Unit tests for grade_ods_scheduled_scan function."""

    def test_passing_scan_grade(self):
        scan = make_scan()
        result = grade_ods_scheduled_scan(scan, GRADING_CONFIG)
        assert result["passed"] is True
        assert result["policy_id"] == "scan-001"
        assert result["policy_name"] == "Test Scan"
        assert result["platform_name"] == "Windows"
        assert result["grading_status"] == "graded"
        assert result["failures_count"] == 0
        assert result["checks_count"] == 8  # status + interval + cloud_det + sensor_det + cloud_prev + sensor_prev + pup_prev + quarantine

    def test_failing_scan_grade(self):
        scan = make_scan(status="pending", cloud_ml_level_detection=1)
        result = grade_ods_scheduled_scan(scan, GRADING_CONFIG)
        assert result["passed"] is False
        assert result["failures_count"] == 2

    def test_ungradable_when_no_platform_config(self):
        config = {"platform_requirements": []}
        scan = make_scan()
        result = grade_ods_scheduled_scan(scan, config)
        assert result["grading_status"] == "ungradable"
        assert result["ungradable_reason"] == "no_platform_config"

    def test_scan_id_used_as_name_when_no_description(self):
        scan = make_scan(description=None)
        result = grade_ods_scheduled_scan(scan, GRADING_CONFIG)
        assert result["policy_name"] == "scan-001"

    def test_empty_description_falls_back_to_id(self):
        scan = make_scan(description="")
        result = grade_ods_scheduled_scan(scan, GRADING_CONFIG)
        assert result["policy_name"] == "scan-001"


@pytest.mark.unit
class TestGradeAllOdsScheduledScans:
    """Unit tests for grade_all_ods_scheduled_scans function."""

    def test_grades_all_scans(self):
        scans_data = {
            "policies": [
                make_scan(id="scan-1", description="Scan A"),
                make_scan(id="scan-2", description="Scan B", cloud_ml_level_detection=1),
            ]
        }
        results = grade_all_ods_scheduled_scans(scans_data, GRADING_CONFIG)
        assert len(results) == 2
        assert results[0]["passed"] is True
        assert results[1]["passed"] is False

    def test_accepts_list_input(self):
        scans_list = [make_scan(id="scan-1"), make_scan(id="scan-2")]
        results = grade_all_ods_scheduled_scans(scans_list, GRADING_CONFIG)
        assert len(results) == 2

    def test_empty_scans_returns_empty_list(self):
        results = grade_all_ods_scheduled_scans({"policies": []}, GRADING_CONFIG)
        assert results == []

    def test_empty_dict_returns_empty_list(self):
        results = grade_all_ods_scheduled_scans({}, GRADING_CONFIG)
        assert results == []
