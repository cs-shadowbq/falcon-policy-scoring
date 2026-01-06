# Description: Core helper utility functions for the application
import time


def ttl_expired(latest_ttl, ttl_maximum, epoch=int(time.time())):
    try:
        return epoch - latest_ttl > ttl_maximum
    except Exception:
        return True

def epoch_now():
    """Return the current epoch time as an integer."""
    return int(time.time())
