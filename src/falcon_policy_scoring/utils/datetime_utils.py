"""Standardized datetime utilities for consistent timestamp formatting."""
from datetime import datetime, timezone


def get_filename_timestamp() -> str:
    """Get formatted timestamp for filenames with timezone.

    Format: YYYY-MM-DD_HH-MM-SS_TZ (e.g., 2025-12-08_14-30-45_EST)

    Returns:
        Formatted timestamp string suitable for filenames
    """
    return datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S_%Z")


def get_utc_iso_timestamp() -> str:
    """Get UTC timestamp in ISO 8601 format with 'Z' suffix.

    Format: YYYY-MM-DDTHH:MM:SS.ffffffZ (e.g., 2025-12-08T19:30:45.123456Z)
    Used for metadata and API responses requiring standard UTC time.

    Returns:
        ISO 8601 formatted UTC timestamp string with 'Z' suffix
    """
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def get_local_iso_timestamp() -> str:
    """Get local timestamp in ISO 8601 format with timezone offset.

    Format: YYYY-MM-DDTHH:MM:SS.ffffff±HH:MM (e.g., 2025-12-08T14:30:45.123456-05:00)
    Used for logging and local time references.

    Returns:
        ISO 8601 formatted local timestamp string with timezone offset
    """
    return datetime.now().astimezone().isoformat()
