"""Host data class for CrowdStrike Falcon host information."""


class Host:
    """Represents a single Falcon host with its CID and API connection.
    
    Attributes:
        cid: Customer ID for the Falcon environment
        falcon: FalconAPI instance for making API calls
    """

    def __init__(self, cid, falcon):
        self.cid = cid
        self.falcon = falcon
