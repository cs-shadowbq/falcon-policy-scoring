"""Cache-related utility functions."""
from datetime import datetime, timezone
from typing import Dict, Tuple


def calculate_cache_age(epoch_timestamp: int) -> Tuple[int, str]:
    """Calculate cache age from epoch timestamp.

    Args:
        epoch_timestamp: Unix epoch timestamp

    Returns:
        Tuple of (age_in_seconds, human_readable_string)
    """
    now = datetime.now(timezone.utc)
    cache_time = datetime.fromtimestamp(epoch_timestamp, tz=timezone.utc)
    age_seconds = int((now - cache_time).total_seconds())

    # Format human-readable string
    if age_seconds < 60:
        age_display = f"{age_seconds} seconds"
    elif age_seconds < 3600:
        minutes = age_seconds // 60
        age_display = f"{minutes} minute{'s' if minutes != 1 else ''}"
    else:
        hours = age_seconds // 3600
        minutes = (age_seconds % 3600) // 60
        if minutes > 0:
            age_display = f"{hours} hour{'s' if hours != 1 else ''} {minutes} minute{'s' if minutes != 1 else ''}"
        else:
            age_display = f"{hours} hour{'s' if hours != 1 else ''}"

    return age_seconds, age_display


def get_policy_ttl(config: Dict, policy_type: str) -> int:
    """Get TTL for a specific policy type from config.

    Args:
        config: Configuration dictionary
        policy_type: Type of policy (e.g., 'prevention', 'firewall')

    Returns:
        TTL in seconds (default: 600)
    """
    return config.get('ttl', {}).get('policies', {}).get(f"{policy_type}_policy", 600)


def get_hosts_ttl(config: Dict) -> int:
    """Get TTL for hosts cache from config.

    Args:
        config: Configuration dictionary

    Returns:
        TTL in seconds (default: 300)
    """
    return config.get('ttl', {}).get('hosts', 300)


def is_cache_expired(age_seconds: int, ttl_seconds: int) -> bool:
    """Check if cache has expired.

    Args:
        age_seconds: Age of cache in seconds
        ttl_seconds: TTL threshold in seconds

    Returns:
        True if cache is expired, False otherwise
    """
    return age_seconds > ttl_seconds


def format_cache_display_with_ttl(age_display: str, ttl_seconds: int) -> str:
    """Format cache age display with TTL information.

    Args:
        age_display: Human-readable cache age
        ttl_seconds: TTL in seconds

    Returns:
        Formatted string with age and TTL
    """
    ttl_minutes = ttl_seconds // 60
    return f"{age_display} / {ttl_minutes} minutes max"
