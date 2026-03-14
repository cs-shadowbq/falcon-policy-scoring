"""
Tests for ODS host coverage lookup logic.

Tests the per-host ODS status determination using the coverage index,
without requiring live API connections or a real database.
"""

import pytest
from falcon_policy_scoring.utils.host_data import _get_ods_status


def make_graded_record(scans):
    """Build a graded_policies record dict from a list of (scan_id, passed) tuples."""
    return {
        "graded_policies": [
            {
                "policy_id": scan_id,
                "policy_name": f"Scan {scan_id}",
                "platform_name": "Windows",
                "grading_status": "graded",
                "passed": passed
            }
            for scan_id, passed in scans
        ]
    }


@pytest.mark.unit
class TestGetOdsStatus:
    """Unit tests for _get_ods_status helper function."""

    def test_non_windows_returns_na(self):
        assert _get_ods_status("device-1", "Linux", None, {}) == "N/A"
        assert _get_ods_status("device-1", "Mac", None, {}) == "N/A"
        assert _get_ods_status("device-1", "Unknown", None, {}) == "N/A"

    def test_windows_no_graded_record_returns_not_graded(self):
        assert _get_ods_status("device-1", "Windows", None, {}) == "NOT GRADED"

    def test_windows_empty_graded_record_returns_not_graded(self):
        empty_record = {}
        assert _get_ods_status("device-1", "Windows", empty_record, {}) == "NOT GRADED"

    def test_windows_no_coverage_returns_failed(self):
        graded = make_graded_record([("scan-1", True)])
        coverage = {}  # device not in any scan's group
        assert _get_ods_status("device-1", "Windows", graded, coverage) == "FAILED"

    def test_windows_covered_by_passing_scan_returns_passed(self):
        graded = make_graded_record([("scan-1", True)])
        coverage = {"device-1": ["scan-1"]}
        assert _get_ods_status("device-1", "Windows", graded, coverage) == "PASSED"

    def test_windows_covered_by_failing_scan_returns_failed(self):
        graded = make_graded_record([("scan-1", False)])
        coverage = {"device-1": ["scan-1"]}
        assert _get_ods_status("device-1", "Windows", graded, coverage) == "FAILED"

    def test_windows_covered_by_multiple_scans_passes_if_any_pass(self):
        graded = make_graded_record([("scan-1", False), ("scan-2", True)])
        coverage = {"device-1": ["scan-1", "scan-2"]}
        assert _get_ods_status("device-1", "Windows", graded, coverage) == "PASSED"

    def test_windows_covered_by_multiple_all_failing(self):
        graded = make_graded_record([("scan-1", False), ("scan-2", False)])
        coverage = {"device-1": ["scan-1", "scan-2"]}
        assert _get_ods_status("device-1", "Windows", graded, coverage) == "FAILED"

    def test_coverage_scan_id_not_in_graded_record_returns_failed(self):
        graded = make_graded_record([("scan-other", True)])
        coverage = {"device-1": ["scan-1"]}
        assert _get_ods_status("device-1", "Windows", graded, coverage) == "FAILED"

    def test_different_devices_get_independent_status(self):
        graded = make_graded_record([("scan-1", True), ("scan-2", False)])
        coverage = {
            "device-win-1": ["scan-1"],  # covered by passing scan
            "device-win-2": ["scan-2"],  # covered by failing scan
            # device-win-3 has no coverage
        }
        assert _get_ods_status("device-win-1", "Windows", graded, coverage) == "PASSED"
        assert _get_ods_status("device-win-2", "Windows", graded, coverage) == "FAILED"
        assert _get_ods_status("device-win-3", "Windows", graded, coverage) == "FAILED"
        assert _get_ods_status("device-linux-1", "Linux", graded, coverage) == "N/A"
