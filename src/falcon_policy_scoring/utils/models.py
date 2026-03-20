"""Domain models for business logic."""
from dataclasses import dataclass
from typing import Optional, Callable


@dataclass
class CacheInfo:
    """Cache information for a dataset.

    Attributes:
        age_seconds: Age of cache in seconds
        age_display: Human-readable cache age string
        ttl_seconds: TTL (time to live) in seconds
        expired: Whether the cache has expired
    """
    age_seconds: int
    age_display: str
    ttl_seconds: int
    expired: bool


@dataclass
class PolicyTypeInfo:
    """Information about a policy type.

    Attributes:
        db_key: Database key for policy storage
        api_key: API key for policy retrieval
        display_name: Human-readable display name
        cli_name: CLI argument name
        gradable: Whether this policy type is graded (False for fetch-only types)
        narrow_header: Abbreviated column header for compact host tables
        table_header: Column header for wide host tables
        status_key: Key used in host row dicts for this policy's status
        device_policies_key: Key used in host device_policies dict (None = coverage-index based)
        ttl_config_key: Key used in config TTL policies dict
        api_command: FalconPy command name for fetching policies
        api_limit: API fetch page size limit
        api_weblink: FalconPy documentation URL
        is_shim: Whether the api_command is a custom shim rather than a direct SDK method
        grader_func: Function to fetch, grade, and store this policy type
    """
    db_key: str
    api_key: str
    display_name: str
    cli_name: str
    gradable: bool = True
    narrow_header: str = ''
    table_header: str = ''
    status_key: str = ''
    device_policies_key: Optional[str] = None
    ttl_config_key: str = ''
    api_command: str = ''
    api_limit: int = 5000
    api_weblink: str = ''
    is_shim: bool = False
    grader_func: Optional[Callable] = None


# Unused models - defined for future use but not currently implemented
# These would be useful for replacing dict-based data passing with typed dataclasses

# @dataclass
# class PolicyResult:
#     """Result of a single policy evaluation.
#
#     Attributes:
#         policy_id: Unique policy identifier
#         policy_name: Human-readable policy name
#         platform_name: Target platform (Windows, Mac, Linux)
#         passed: Whether policy passed grading
#         checks_count: Total number of checks performed
#         failures_count: Number of failed checks
#         score_percentage: Score as percentage (0-100)
#         setting_results: Detailed results for each setting
#     """
#     policy_id: str
#     policy_name: str
#     platform_name: str
#     passed: bool
#     checks_count: int
#     failures_count: int
#     score_percentage: float
#     setting_results: List[Dict]


# @dataclass
# class HostPolicyStatus:
#     """Policy status for a single host.
#
#     Attributes:
#         device_id: Unique device identifier
#         hostname: Host name
#         platform: Operating system platform
#         prevention_status: Prevention policy status
#         sensor_update_status: Sensor update policy status
#         content_update_status: Content update policy status
#         firewall_status: Firewall policy status
#         device_control_status: Device control policy status
#         it_automation_status: IT automation policy status
#         all_passed: Whether all policies passed
#         any_failed: Whether any policy failed
#     """
#     device_id: str
#     hostname: str
#     platform: str
#     prevention_status: str
#     sensor_update_status: str
#     content_update_status: str
#     firewall_status: str
#     device_control_status: str
#     it_automation_status: str
#     all_passed: bool
#     any_failed: bool


# @dataclass
# class SummaryStats:
#     """Summary statistics for policies or hosts.
#
#     Attributes:
#         total: Total count
#         passed: Number that passed
#         failed: Number that failed
#         score_percentage: Overall score as percentage
#     """
#     total: int
#     passed: int
#     failed: int
#     score_percentage: float
