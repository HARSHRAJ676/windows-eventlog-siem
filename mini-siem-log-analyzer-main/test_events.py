import os
import json
from datetime import datetime

# Writes a small set of synthetic events to latest_events.json for pipeline testing
BASE_DIR = os.path.dirname(__file__)
OUT = os.path.join(BASE_DIR, 'data', 'latest_events.json')

SAMPLE = [
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Security", "event_id": 4625, "user": "user1", "ip": "10.0.0.5", "command": None, "message": "An account failed to log on from 10.0.0.5"},
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Windows PowerShell", "event_id": 4104, "user": "user1", "ip": None, "command": "powershell -EncodedCommand SQAAABEAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIgAgACIAVABlAHMAdABBAH"},
    {"timestamp": datetime.utcnow().isoformat(), "channel": "System", "event_id": 2003, "user": None, "ip": None, "command": None, "message": "Kernel-PnP: Device configured (USB\\VID_XXXX)"},
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Security", "event_id": 4688, "user": "user1", "ip": None, "command": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -W Hidden", "message": None}
]


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(SAMPLE, f, indent=2)
    print(f"Wrote sample events to {OUT}")


if __name__ == '__main__':
    main()
