from typing import Dict, Any
import re


def normalize_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    msg = evt.get('message') or ''
    cmd = evt.get('command') or ''
    ip = None
    # Extract simple IP
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg)
    if m:
        ip = m.group(1)
    evt['ip'] = evt.get('ip') or ip
    # Extract PowerShell command from message if present
    if not cmd and 'powershell' in msg.lower():
        evt['command'] = msg
    return evt
