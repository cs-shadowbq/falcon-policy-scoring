"""
Sample data fixtures for testing.

Provides hand-crafted test data matching real CrowdStrike API response structures:
- Host device details
- Policy configurations (prevention, firewall, sensor-update, etc.)
- Grading results
- API error responses
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any


def generate_host_detail(
    device_id: str = "test-device-id-12345",
    hostname: str = "test-host-01",
    platform_name: str = "Windows",
    product_type_desc: str = "Workstation",
    os_version: str = "Windows 10",
    agent_version: str = "7.10.12345",
    last_seen: str = None
) -> Dict[str, Any]:
    """Generate a sample host device detail matching CrowdStrike API structure."""
    if last_seen is None:
        last_seen = datetime.utcnow().isoformat() + "Z"

    return {
        "device_id": device_id,
        "cid": "test-cid-1234567890abcdef",
        "hostname": hostname,
        "platform_name": platform_name,
        "product_type_desc": product_type_desc,
        "os_version": os_version,
        "agent_version": agent_version,
        "last_seen": last_seen,
        "first_seen": (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "mac_address": "00-11-22-33-44-55",
        "local_ip": "192.168.1.100",
        "external_ip": "203.0.113.100",
        "status": "normal",
        "system_manufacturer": "Test Manufacturer",
        "system_product_name": "Test Product",
        "tags": ["test", "development"],
        "groups": [],
        "policies": {
            "prevention": {
                "policy_id": "test-prevention-policy-id",
                "policy_type": "prevention",
                "applied": True,
                "applied_date": datetime.utcnow().isoformat() + "Z"
            },
            "sensor_update": {
                "policy_id": "test-sensor-update-policy-id",
                "policy_type": "sensor-update",
                "applied": True,
                "applied_date": datetime.utcnow().isoformat() + "Z"
            }
        }
    }


def generate_prevention_policy(
    policy_id: str = "test-prevention-policy-id",
    name: str = "Test Prevention Policy",
    enabled: bool = True,
    prevention_settings: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Generate a sample prevention policy matching CrowdStrike API structure."""
    if prevention_settings is None:
        prevention_settings = {
            "AdwarePUP": {
                "detection": "MODERATE",
                "prevention": "MODERATE"
            },
            "CloudAntiMalware": {
                "detection": "AGGRESSIVE",
                "prevention": "AGGRESSIVE"
            },
            "SensorAntiMalware": {
                "detection": "AGGRESSIVE",
                "prevention": "AGGRESSIVE"
            },
            "Quarantine": {
                "enabled": True
            },
            "UnknownDetectionRelatedExecutables": {
                "detection": "AGGRESSIVE"
            },
            "UnknownExecutables": {
                "detection": "MODERATE"
            }
        }

    return {
        "id": policy_id,
        "name": name,
        "description": "Test prevention policy for unit testing",
        "platform_name": "Windows",
        "enabled": enabled,
        "created_by": "test-user",
        "created_timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat() + "Z",
        "modified_by": "test-user",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "prevention_settings": prevention_settings,
        "groups": []
    }


def generate_sensor_update_policy(
    policy_id: str = "test-sensor-update-policy-id",
    name: str = "Test Sensor Update Policy",
    enabled: bool = True,
    sensor_version: str = "7.10"
) -> Dict[str, Any]:
    """Generate a sample sensor update policy matching CrowdStrike API structure."""
    return {
        "id": policy_id,
        "name": name,
        "description": "Test sensor update policy for unit testing",
        "platform_name": "Windows",
        "enabled": enabled,
        "created_by": "test-user",
        "created_timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat() + "Z",
        "modified_by": "test-user",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "settings": {
            "build": sensor_version,
            "scheduler": {
                "enabled": True,
                "timezone": "UTC"
            },
            "uninstall_protection": "ENABLED",
            "variants": []
        },
        "groups": []
    }


def generate_firewall_policy(
    policy_id: str = "test-firewall-policy-id",
    name: str = "Test Firewall Policy",
    enabled: bool = True,
    enforce: bool = True
) -> Dict[str, Any]:
    """Generate a sample firewall policy matching CrowdStrike API structure."""
    return {
        "id": policy_id,
        "name": name,
        "description": "Test firewall policy for unit testing",
        "platform_name": "Windows",
        "enabled": enabled,
        "created_by": "test-user",
        "created_timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat() + "Z",
        "modified_by": "test-user",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "rule_group_ids": ["test-rule-group-id-1"],
        "settings": {
            "enforce": enforce,
            "default_inbound": "DENY",
            "default_outbound": "ALLOW",
            "test_mode": False,
            "local_logging": "DISABLED"
        },
        "groups": []
    }


def generate_device_control_policy(
    policy_id: str = "test-device-control-policy-id",
    name: str = "Test Device Control Policy",
    enabled: bool = True
) -> Dict[str, Any]:
    """Generate a sample device control policy matching CrowdStrike API structure."""
    return {
        "id": policy_id,
        "name": name,
        "description": "Test device control policy for unit testing",
        "platform_name": "Windows",
        "enabled": enabled,
        "created_by": "test-user",
        "created_timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat() + "Z",
        "modified_by": "test-user",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "settings": {
            "classes": {
                "exceptions": [],
                "usb_storage": {
                    "action": "FULL_ACCESS"
                },
                "bluetooth": {
                    "action": "MONITOR_ONLY"
                }
            },
            "end_user_notification": "ENABLED",
            "enforcement_mode": "MONITOR_ONLY"
        },
        "groups": []
    }


def generate_content_update_policy(
    policy_id: str = "test-content-update-policy-id",
    name: str = "Test Content Update Policy",
    enabled: bool = True
) -> Dict[str, Any]:
    """Generate a sample content update policy matching CrowdStrike API structure."""
    return {
        "id": policy_id,
        "name": name,
        "description": "Test content update policy for unit testing",
        "platform_name": "Windows",
        "enabled": enabled,
        "created_by": "test-user",
        "created_timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat() + "Z",
        "modified_by": "test-user",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "settings": {
            "content_update_interval": 3600,
            "auto_update": True
        },
        "groups": []
    }


def generate_graded_policy_result(
    policy_id: str = "test-prevention-policy-id",
    policy_name: str = "Test Prevention Policy",
    policy_type: str = "prevention",
    score: int = 85,
    failures: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate a sample graded policy result."""
    if failures is None:
        failures = []

    return {
        "policy_id": policy_id,
        "policy_name": policy_name,
        "policy_type": policy_type,
        "platform": "Windows",
        "enabled": True,
        "score": score,
        "total_checks": 10,
        "passed_checks": 8,
        "failed_checks": 2,
        "failures": failures,
        "graded_at": datetime.utcnow().isoformat() + "Z"
    }


def generate_zta_assessment(
    device_id: str = "test-device-id-12345",
    sensor_config_score: int = 85,
    os_score: int = 75,
    overall_score: int = 80
) -> Dict[str, Any]:
    """Generate a sample Zero Trust Assessment result."""
    return {
        "aid": device_id,
        "cid": "test-cid-1234567890abcdef",
        "assessment": {
            "sensor_config": sensor_config_score,
            "os": os_score,
            "overall": overall_score
        },
        "assessment_items": {
            "os_signals": [
                {
                    "criteria": "firewall_enabled",
                    "meets_criteria": "YES" if os_score > 50 else "NO"
                },
                {
                    "criteria": "disk_encryption",
                    "meets_criteria": "YES" if os_score > 70 else "NO"
                }
            ],
            "sensor_signals": [
                {
                    "criteria": "sensor_version_supported",
                    "meets_criteria": "YES" if sensor_config_score > 50 else "NO"
                },
                {
                    "criteria": "prevention_policy_applied",
                    "meets_criteria": "YES" if sensor_config_score > 70 else "NO"
                }
            ]
        },
        "modified_time": datetime.utcnow().isoformat() + "Z",
        "sensor_file_status": "active"
    }


def generate_firewall_container(
    policy_id: str = "test-firewall-policy-id",
    default_inbound: str = "DENY",
    default_outbound: str = "ALLOW",
    enforce: bool = True,
    test_mode: bool = False
) -> Dict[str, Any]:
    """Generate a sample firewall policy container with settings."""
    return {
        "policy_id": policy_id,
        "name": "Test Firewall Container",
        "description": "Test firewall policy container",
        "platform_name": "Windows",
        "default_inbound": default_inbound,
        "default_outbound": default_outbound,
        "enforce": enforce,
        "test_mode": test_mode,
        "local_logging": "DISABLED",
        "rule_group_ids": ["test-rule-group-id-1", "test-rule-group-id-2"],
        "created_timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat() + "Z",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z"
    }


def generate_it_automation_policy(
    policy_id: str = "test-it-automation-policy-id",
    name: str = "Test IT Automation Policy",
    platform: str = "Windows",
    enabled: bool = True
) -> Dict[str, Any]:
    """Generate a sample IT automation policy."""
    return {
        "id": policy_id,
        "name": name,
        "description": "Test IT automation policy for unit testing",
        "platform_name": platform,
        "enabled": enabled,
        "created_by": "test-user",
        "created_timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat() + "Z",
        "modified_by": "test-user",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "settings": {
            "custom_run_interval": {
                "enabled": True,
                "interval": 3600
            }
        },
        "groups": []
    }


def generate_host_group(
    group_id: str = "test-group-id-1",
    name: str = "Test Host Group",
    group_type: str = "static"
) -> Dict[str, Any]:
    """Generate a sample host group."""
    return {
        "id": group_id,
        "name": name,
        "description": "Test host group for unit testing",
        "group_type": group_type,
        "created_by": "test-user",
        "created_timestamp": (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z",
        "modified_by": "test-user",
        "modified_timestamp": datetime.utcnow().isoformat() + "Z",
        "assignment_rule": None if group_type == "static" else "platform_name:'Windows'"
    }


# Sample host lists for batch testing
SAMPLE_HOSTS = [
    generate_host_detail(
        device_id=f"device-{i:05d}",
        hostname=f"test-host-{i:02d}",
        platform_name=platform,
        product_type_desc=product_type
    )
    for i, (platform, product_type) in enumerate([
        ("Windows", "Workstation"),
        ("Windows", "Server"),
        ("Linux", "Server"),
        ("Mac", "Workstation"),
        ("Windows", "Workstation")
    ], start=1)
]

# Sample policy lists for batch testing
SAMPLE_PREVENTION_POLICIES = [
    generate_prevention_policy(
        policy_id=f"prevention-policy-{i}",
        name=f"Prevention Policy {i}",
        enabled=True
    )
    for i in range(1, 4)
]

SAMPLE_SENSOR_UPDATE_POLICIES = [
    generate_sensor_update_policy(
        policy_id=f"sensor-update-policy-{i}",
        name=f"Sensor Update Policy {i}",
        enabled=True,
        sensor_version=version
    )
    for i, version in enumerate(["7.10", "7.09", "7.11"], start=1)
]

SAMPLE_FIREWALL_POLICIES = [
    generate_firewall_policy(
        policy_id=f"firewall-policy-{i}",
        name=f"Firewall Policy {i}",
        enabled=True,
        enforce=enforce
    )
    for i, enforce in enumerate([True, True, False], start=1)
]
