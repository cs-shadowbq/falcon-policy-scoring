"""Policy type registry for centralized policy metadata."""
from typing import Dict, List, Optional
from .models import PolicyTypeInfo
from .constants import POLICY_TYPE_REGISTRY


class PolicyTypeRegistry:
    """Registry for policy type metadata."""

    def __init__(self):
        """Initialize the policy type registry.

        Builds PolicyTypeInfo objects from POLICY_TYPE_REGISTRY (Layer 1 constants)
        and attaches grader_func callables via a deferred import to avoid the
        circular dependency: policy_registry -> falconapi.policies -> grading -> engine.
        """
        from falcon_policy_scoring.falconapi.policies import (
            fetch_grade_and_store_prevention_policies,
            fetch_grade_and_store_sensor_update_policies,
            fetch_grade_and_store_content_update_policies,
            fetch_grade_and_store_firewall_policies,
            fetch_grade_and_store_device_control_policies,
            fetch_grade_and_store_it_automation_policies,
            fetch_grade_and_store_ods_scheduled_scan_policies,
            fetch_grade_and_store_response_policies,
            fetch_grade_and_store_sca_policies,
        )

        # Map internal key -> fetch+grade+store callable.
        _grader_funcs = {
            'prevention': fetch_grade_and_store_prevention_policies,
            'sensor_update': fetch_grade_and_store_sensor_update_policies,
            'content_update': fetch_grade_and_store_content_update_policies,
            'firewall': fetch_grade_and_store_firewall_policies,
            'device_control': fetch_grade_and_store_device_control_policies,
            'it_automation': fetch_grade_and_store_it_automation_policies,
            'ods_scheduled_scan': fetch_grade_and_store_ods_scheduled_scan_policies,
            'response': fetch_grade_and_store_response_policies,
            'sca': fetch_grade_and_store_sca_policies,
        }

        self._registry = {
            key: PolicyTypeInfo(**data, grader_func=_grader_funcs.get(key))
            for key, data in POLICY_TYPE_REGISTRY.items()
        }

    def get(self, policy_type: str) -> Optional[PolicyTypeInfo]:
        """Get policy type information.

        Args:
            policy_type: Policy type key

        Returns:
            PolicyTypeInfo or None if not found
        """
        return self._registry.get(policy_type)

    def get_all(self) -> Dict[str, PolicyTypeInfo]:
        """Get all policy types.

        Returns:
            Dictionary of all policy types
        """
        return self._registry.copy()

    def get_by_cli_name(self, cli_name: str) -> Optional[PolicyTypeInfo]:
        """Get policy type by CLI argument name.

        Args:
            cli_name: CLI argument name (e.g., 'sensor-update')

        Returns:
            PolicyTypeInfo or None if not found
        """
        for info in self._registry.values():
            if info.cli_name == cli_name:
                return info
        return None

    def get_all_types(self) -> List[str]:
        """Get list of all policy type keys.

        Returns:
            List of policy type keys
        """
        return list(self._registry.keys())

    def get_gradable_types(self) -> List[str]:
        """Get list of policy type keys that are graded (excludes fetch-only types).

        Returns:
            List of gradable policy type keys
        """
        return [k for k, v in self._registry.items() if v.gradable]


# Global registry instance
_REGISTRY = PolicyTypeRegistry()


def get_policy_registry() -> PolicyTypeRegistry:
    """Get the global policy registry.

    Returns:
        Singleton PolicyTypeRegistry instance
    """
    return _REGISTRY
