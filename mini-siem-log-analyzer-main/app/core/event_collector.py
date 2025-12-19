import win32evtlog
import win32evtlogutil
import win32con
import json
import os
from datetime import datetime
from typing import List, Dict, Any
from utils.logging import setup_logger
import subprocess
try:
    import wmi
except Exception:
    wmi = None

logger = setup_logger("event_collector")

# Fallback process tracking when Security log (4688) not accessible
_seen_pids: Dict[int, datetime] = {}
_PROCESS_MAX_AGE_SECONDS = 300  # prune old pids to keep memory small


def collect_latest_events(channels: List[str], max_records: int = 250) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for channel in channels:
        channel_count = 0
        try:
            # Classic logs via OpenEventLog
            if True:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                # Loop until we reach max_records or no more events returned
                while channel_count < max_records:
                    evt_batch = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not evt_batch:
                        break
                    for evt in evt_batch:
                        if channel_count >= max_records:
                            break
                        events.append({
                            'timestamp': evt.TimeGenerated.isoformat() if evt.TimeGenerated else datetime.utcnow().isoformat(),
                            'channel': channel,
                            'event_id': evt.EventID & 0xFFFF,
                            'user': evt.StringInserts[0] if evt.StringInserts else None,
                            'ip': None,
                            'command': None,
                            'message': ' '.join(evt.StringInserts) if evt.StringInserts else ''
                        })
                        channel_count += 1
                win32evtlog.CloseEventLog(handle)
                logger.info(f"Channel {channel}: collected {channel_count} events")
        except Exception as e:
            logger.error(f"Failed to read {channel}: {e}")

    # Fallback: if Security log failed (no 4688 events) and WMI available, synthesize new process events
    security_requested = any(ch.lower() == 'security' for ch in channels)
    have_security_events = any(ev.get('channel') == 'Security' for ev in events)
    if security_requested and not have_security_events and wmi:
        try:
            c = wmi.WMI()
            current_time = datetime.utcnow()
            # prune old pids
            for pid, ts in list(_seen_pids.items()):
                if (current_time - ts).total_seconds() > _PROCESS_MAX_AGE_SECONDS:
                    del _seen_pids[pid]
            for proc in c.Win32_Process():
                pid = int(proc.ProcessId)
                if pid not in _seen_pids:
                    _seen_pids[pid] = current_time
                    cmdline = proc.CommandLine or proc.Name or ''
                    events.append({
                        'timestamp': current_time.isoformat(),
                        'channel': 'ProcessWatcher',
                        'event_id': 4688,  # synthetic new process creation
                        'user': None,
                        'ip': None,
                        'command': cmdline,
                        'message': cmdline,
                    })
            logger.info(f"ProcessWatcher: synthesized {sum(1 for e in events if e.get('channel')=='ProcessWatcher')} process events")
        except Exception as e:
            logger.error(f"ProcessWatcher fallback failed: {e}")

    # PowerShell Operational (4104) ingestion via PowerShell command (works without admin)
    if any(ch.lower() == 'microsoft-windows-powershell/operational' for ch in channels):
        try:
            ps_cmd = (
                "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 50 "
                "| Where-Object {$_.Id -eq 4104} "
                "| Select-Object TimeCreated, Id, Message | ConvertTo-Json -Compress"
            )
            result = subprocess.run([
                'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd
            ], capture_output=True, text=True, timeout=8)
            if result.returncode == 0 and result.stdout:
                import json
                try:
                    items = json.loads(result.stdout)
                    if isinstance(items, dict):
                        items = [items]
                    for it in items[:50]:
                        msg = it.get('Message') or ''
                        ts = it.get('TimeCreated') or datetime.utcnow().isoformat()
                        events.append({
                            'timestamp': ts,
                            'channel': 'Microsoft-Windows-PowerShell/Operational',
                            'event_id': 4104,
                            'user': None,
                            'ip': None,
                            'command': msg,
                            'message': msg,
                        })
                    logger.info(f"PowerShell Operational: collected {len([e for e in events if e.get('event_id')==4104])} events")
                except Exception as je:
                    snippet = (result.stdout or '')[:200]
                    logger.error(f"Failed to parse 4104 JSON: {je} | Snippet: {snippet}")
            else:
                logger.error(f"Get-WinEvent 4104 failed: {result.stderr.strip()}")
        except Exception as e:
            logger.error(f"PowerShell Operational ingestion error: {e}")
    logger.info(f"Total collected {len(events)} events")
    return events


def export_latest_events(events: List[Dict[str, Any]], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(events, f, indent=2)
