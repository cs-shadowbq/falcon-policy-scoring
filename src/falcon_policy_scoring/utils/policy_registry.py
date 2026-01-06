"""Policy type registry for centralized policy metadata."""
from typing import Dict, List, Optional
from .models import PolicyTypeInfo


class PolicyTypeRegistry:
    """Registry for policy type metadata."""

    def __init__(self):
        """Initialize the policy type registry."""
        from falcon_policy_scoring.falconapi.policies import (
            fetch_grade_and_store_prevention_policies,
            fetch_grade_and_store_sensor_update_policies,
            fetch_grade_and_store_content_update_policies,
            fetch_grade_and_store_firewall_policies,
            fetch_grade_and_store_device_control_policies,
            fetch_grade_and_store_it_automation_policies,
        )

        self._registry = {
            'prevention': PolicyTypeInfo(
                db_key='prevention_policies',
                api_key='prevention',
                display_name='Prevention',
                cli_name='prevention',
                grader_func=fetch_grade_and_store_prevention_policies
            ),
            'sensor_update': PolicyTypeInfo(
                db_key='sensor_update_policies',
                api_key='sensor_update',
                display_name='Sensor Update',
                cli_name='sensor-update',
                grader_func=fetch_grade_and_store_sensor_update_policies
            ),
            'content_update': PolicyTypeInfo(
                db_key='content_update_policies',
                api_key='content-update',
                display_name='Content Update',
                cli_name='content-update',
                grader_func=fetch_grade_and_store_content_update_policies
            ),
            'firewall': PolicyTypeInfo(
                db_key='firewall_policies',
                api_key='firewall',
                display_name='Firewall',
                cli_name='firewall',
                grader_func=fetch_grade_and_store_firewall_policies
            ),
            'device_control': PolicyTypeInfo(
                db_key='device_control_policies',
                api_key='device_control',
                display_name='Device Control',
                cli_name='device-control',
                grader_func=fetch_grade_and_store_device_control_policies
            ),
            'it_automation': PolicyTypeInfo(
                db_key='it_automation_policies',
                api_key='it-automation',
                display_name='IT Automation',
                cli_name='it-automation',
                grader_func=fetch_grade_and_store_it_automation_policies
            )
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


# Global registry instance
_registry = None


def get_policy_registry() -> PolicyTypeRegistry:
    """Get the global policy registry.

    Returns:
        Singleton PolicyTypeRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = PolicyTypeRegistry()
    return _registry
