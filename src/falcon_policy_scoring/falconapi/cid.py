

def get_cid(falcon):
    r = falcon.command("GetSensorInstallersCCIDByQuery")
    cid = r['body']['resources'][0]
    return cid.split('-')[0]


def get_cid_hash(falcon):
    r = falcon.command("GetSensorInstallersCCIDByQuery")
    cid_hash = r['body']['resources'][0]
    return cid_hash
