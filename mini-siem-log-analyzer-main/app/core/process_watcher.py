from collections import deque
from datetime import datetime
from typing import Dict, Any

try:
    import wmi
except Exception:
    wmi = None

_queue = deque(maxlen=1000)
_started = False

def start():
    global _started
    if _started or not wmi:
        return
    _started = True
    import threading
    def _run():
        c = wmi.WMI()
        watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_Process")
        while True:
            try:
                proc = watcher()
                cmdline = proc.CommandLine or proc.Name or ''
                _queue.append({
                    'timestamp': datetime.utcnow().isoformat(),
                    'channel': 'ProcessWatcherRT',
                    'event_id': 4688,
                    'user': None,
                    'ip': None,
                    'command': cmdline,
                    'message': cmdline,
                })
            except Exception:
                # short sleep to avoid tight loop in case of errors
                import time
                time.sleep(0.2)
    t = threading.Thread(target=_run, daemon=True)
    t.start()

def drain(max_items: int = 250):
    items = []
    while _queue and len(items) < max_items:
        items.append(_queue.popleft())
    return items
