from typing import List, Dict, Any
from utils.helpers import try_decode_base64_unicode


def format_powershell_alert(alert_type: str, command: str, decoded: str = None, user: str = None) -> str:
    """
    Format PowerShell abuse alert in professional SOC style.
    """
    if alert_type == "encoded":
        alert = [
            "⚠️ Suspicious Encoded PowerShell Detected",
            "",
            f"Command: {command[:100]}...",
        ]
        if decoded:
            alert.extend([
                "",
                "Decoded Content:",
                f"{decoded[:200]}..."
            ])
        if user:
            alert.insert(2, f"User: {user}")
        alert.extend([
            "",
            "Risk Level: High 🔴",
            "MITRE ATT&CK: T1059.001 - PowerShell",
            "",
            "Recommended Actions:",
            "• Isolate affected system",
            "• Analyze decoded command for malicious intent",
            "• Check for additional persistence mechanisms"
        ])
    else:  # suspicious keywords
        alert = [
            "⚠️ Suspicious PowerShell Command Detected",
            "",
            f"Command: {command[:150]}...",
        ]
        if user:
            alert.insert(2, f"User: {user}")
        alert.extend([
            "",
            "Risk Level: Medium ⚠️",
            "MITRE ATT&CK: T1059.001 - PowerShell",
            "Indicators: IEX, DownloadString, or Web Client detected",
            "",
            "Recommended Actions:",
            "• Review full command context",
            "• Check network connections from this host",
            "• Verify if download occurred"
        ])
    return "\n".join(alert)


def detect_powershell_abuse(events: List[Dict[str, Any]], thresholds: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    min_len = thresholds.get('powershell_min_base64_len', 24)
    for e in events:
        # Event ID 4104 = PowerShell Script Block Logging (if enabled)
        # Event ID 4688 = Process Creation (fallback for PowerShell commands)
        if e.get('event_id') == 4104:
            cmd = e.get('command') or e.get('message') or ''
            user = e.get('user')
            s = cmd.lower()
            if '-enc' in s or '-encodedcommand' in s:
                parts = cmd.split()
                b64 = parts[-1] if parts else ''
                if len(b64) >= min_len:
                    decoded = try_decode_base64_unicode(b64)
                    alerts.append({
                        'severity': 'HIGH',
                        'title': f'[HIGH] Suspicious Encoded PowerShell - {user or "Unknown"}',
                        'description': format_powershell_alert('encoded', cmd, decoded, user)
                    })
            elif any(x in s for x in ['iex', 'invoke-expression', 'downloadstring', 'new-object net.webclient']):
                alerts.append({
                    'severity': 'MEDIUM',
                    'title': f'[MEDIUM] Suspicious PowerShell Keywords - {user or "Unknown"}',
                    'description': format_powershell_alert('keywords', cmd, None, user)
                })
        # Also detect from process creation events (Event ID 4688)
        elif e.get('event_id') == 4688:
            cmd = e.get('command') or e.get('message') or ''
            if 'powershell' not in cmd.lower():
                continue
            user = e.get('user')
            s = cmd.lower()
            if '-enc' in s or '-encodedcommand' in s:
                parts = cmd.split()
                b64 = parts[-1] if parts else ''
                if len(b64) >= min_len:
                    decoded = try_decode_base64_unicode(b64)
                    alerts.append({
                        'severity': 'HIGH',
                        'title': f'[HIGH] Suspicious Encoded PowerShell - {user or "Unknown"}',
                        'description': format_powershell_alert('encoded', cmd, decoded, user)
                    })
            elif any(x in s for x in ['iex', 'invoke-expression', 'downloadstring', 'new-object net.webclient']):
                alerts.append({
                    'severity': 'MEDIUM',
                    'title': f'[MEDIUM] Suspicious PowerShell Keywords - {user or "Unknown"}',
                    'description': format_powershell_alert('keywords', cmd, None, user)
                })
    return alerts
