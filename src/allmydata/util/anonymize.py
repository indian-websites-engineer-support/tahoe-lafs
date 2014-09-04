import re
from foolscap.referenceable import decode_furl_endpoints

AFTER_ENDPOINT_TYPE_RE=re.compile(r"^.+?:(.+)$")
FURL_RE=re.compile(r"^pb://([^@]+)@([^/]*)/(.+)$")
ANONYMITY_TYPES=["i2p","onion"]

def tor_only_rewrite(furl):
    (encrypted, tubID, hints, swissnum) = decode_furl_endpoints(furl)
    new_hints = []
    for hint in hints:
        if not hint.startswith('tor:'):
            mo = AFTER_ENDPOINT_TYPE_RE.match(hint)
            h = mo.group(1)
            new_hints.append("tor:" + mo.group(1))
        else:
            new_hints.append(hint)
    new_furl = "pb://%s@%s/%s" % (tubID, ','.join(new_hints), swissnum)
    return new_furl

def is_anonymous(location):
    locations = location.split(',')
    for location in locations:
        fields = location.split(':')
        if fields[0] not in ANONYMITY_TYPES:
            return False
    return True
