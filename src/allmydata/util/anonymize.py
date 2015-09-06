ANONYMITY_TYPES=["i2p","onion"]

def is_anonymous(location):
    if "AUTO" in location:
        return False
    locations = location.split(',')
    for location in locations:
        fields = location.split(':')
        if fields[0] not in ANONYMITY_TYPES:
            return False
    return True
