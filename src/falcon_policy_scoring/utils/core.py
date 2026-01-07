"""Core helper utility functions for the application."""
import time


def ttl_expired(latest_ttl, ttl_maximum, epoch=int(time.time())):
    """Check if TTL (time-to-live) has expired.
    
    Args:
        latest_ttl: Timestamp of the last update
        ttl_maximum: Maximum TTL duration in seconds
        epoch: Current epoch time (default: current time)
        
    Returns:
        bool: True if TTL has expired, False otherwise
    """
    try:
        return epoch - latest_ttl > ttl_maximum
    except Exception:
        return True

def epoch_now():
    """Return the current epoch time as an integer."""
    return int(time.time())
