import base64
from typing import Optional


def safe_get(d: dict, path: str, default=None):
    cur = d
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def try_decode_base64_unicode(s: str) -> Optional[str]:
    try:
        raw = base64.b64decode(s)
        return raw.decode('utf-16le')
    except Exception:
        try:
            return base64.b64decode(s).decode('utf-8', errors='ignore')
        except Exception:
            return None
