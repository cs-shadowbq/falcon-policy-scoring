"""
Policy-specific grading modules for CrowdStrike Falcon policies.
"""

from falcon_policy_scoring.grading.graders.prevention import (
    grade_prevention_policy,
    grade_all_prevention_policies
)
from falcon_policy_scoring.grading.graders.sensor_update import (
    grade_sensor_update_policy,
    grade_all_sensor_update_policies
)
from falcon_policy_scoring.grading.graders.content_update import (
    grade_content_update_policy,
    grade_all_content_update_policies
)
from falcon_policy_scoring.grading.graders.firewall import (
    grade_firewall_policy,
    grade_all_firewall_policies
)
from falcon_policy_scoring.grading.graders.device_control import (
    grade_device_control_policy,
    grade_all_device_control_policies
)
from falcon_policy_scoring.grading.graders.it_automation import (
    grade_it_automation_policy,
    grade_all_it_automation_policies
)

__all__ = [
    'grade_prevention_policy',
    'grade_all_prevention_policies',
    'grade_sensor_update_policy',
    'grade_all_sensor_update_policies',
    'grade_content_update_policy',
    'grade_all_content_update_policies',
    'grade_firewall_policy',
    'grade_all_firewall_policies',
    'grade_device_control_policy',
    'grade_all_device_control_policies',
    'grade_it_automation_policy',
    'grade_all_it_automation_policies',
]
