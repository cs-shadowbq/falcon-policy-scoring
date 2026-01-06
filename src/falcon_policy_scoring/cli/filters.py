"""Filtering logic for policies and hosts.

NOTE: This module now serves as a wrapper to falcon_policy_scoring.utils.filters.
For backward compatibility, it re-exports all filtering functions from utils.
"""
from falcon_policy_scoring.utils.filters import (
    filter_policies,
    filter_hosts,
    matches_status_filter,
    get_platform_name
)

__all__ = ['filter_policies', 'filter_hosts', 'matches_status_filter', 'get_platform_name']
