"""Customer ID (CID) utilities for CrowdStrike Falcon API."""


def get_cid(falcon):
    """Get the customer ID without the hash suffix.

    Args:
        falcon: FalconAPI instance with valid credentials

    Returns:
        str: Customer ID (first part before the dash)
    """
    r = falcon.command("GetSensorInstallersCCIDByQuery")
    cid = r['body']['resources'][0]
    return cid.split('-')[0]


def get_cid_hash(falcon):
    """Get the full customer ID with hash suffix.

    Args:
        falcon: FalconAPI instance with valid credentials

    Returns:
        str: Full customer ID including hash (CID-HASH format)
    """
    r = falcon.command("GetSensorInstallersCCIDByQuery")
    cid_hash = r['body']['resources'][0]
    return cid_hash
