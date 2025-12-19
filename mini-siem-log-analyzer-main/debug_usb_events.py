import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

import win32evtlog
from datetime import datetime

TARGET_SOURCE = "Kernel-PnP"
MAX = 120

def main():
    handle = win32evtlog.OpenEventLog(None, "System")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    collected = 0
    printed = 0
    seen_ids = {}
    while collected < MAX:
        batch = win32evtlog.ReadEventLog(handle, flags, 0)
        if not batch:
            break
        for evt in batch:
            if collected >= MAX:
                break
            collected += 1
            eid = evt.EventID & 0xFFFF
            source = evt.SourceName
            if source == TARGET_SOURCE:
                msg = ' '.join(evt.StringInserts) if evt.StringInserts else ''
                print(f"[{printed+1}] ID={eid} Time={evt.TimeGenerated.isoformat()} MsgFirst={msg[:110]}")
                printed += 1
                seen_ids[eid] = seen_ids.get(eid, 0) + 1
    win32evtlog.CloseEventLog(handle)
    print("\nSummary IDs:")
    for k,v in sorted(seen_ids.items()):
        print(f"  {k}: {v}")
    if printed == 0:
        print("No Kernel-PnP events found in last System batch. Plug/unplug USB and rerun.")

if __name__ == '__main__':
    main()