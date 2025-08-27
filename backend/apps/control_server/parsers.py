import json
from hashlib import sha256


def hash_dict(d: dict):
    return sha256(
        json.dumps(
            d, sort_keys=True, separators=None, ensure_ascii=True, default=str
        ).encode("utf8")
    ).hexdigest()
