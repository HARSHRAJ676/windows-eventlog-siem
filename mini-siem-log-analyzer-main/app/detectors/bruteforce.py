from collections import deque
from datetime import datetime, timedelta
from typing import List, Dict, Any


def format_bruteforce_alert(ip: str, count: int, window_minutes: int, username: str = None) -> str:
    """
    Format brute force alert in professional SOC style.
    """
    alert = [
        "🚨 Brute Force Attack Detected",
        "",
        f"Source IP: {ip}",
        f"Failed Attempts: {count}",
        f"Time Window: {window_minutes} minutes",
    ]
    if username:
        alert.insert(3, f"Target User: {username}")
    
    alert.extend([
        "",
        "Risk Level: High 🔴",
        "MITRE ATT&CK: T1110 - Brute Force",
        "",
        "Recommended Actions:",
        "• Block source IP immediately",
        "• Review account for compromise",
        "• Enable account lockout policy"
    ])
    return "\n".join(alert)


def detect_bruteforce(events: List[Dict[str, Any]], thresholds: Dict[str, Any]) -> List[Dict[str, Any]]:
    window_minutes = thresholds.get('brute_force_window_minutes', 10)
    fail_threshold = thresholds.get('brute_force_failures', 2)  # Default 2 attempts
    window = timedelta(minutes=window_minutes)

    attempts: Dict[str, deque] = {}
    user_map: Dict[str, str] = {}  # Track username per IP
    alerted: set = set()  # Track already alerted IPs to prevent duplicates
    alerts: List[Dict[str, Any]] = []

    for e in events:
        if e.get('event_id') == 4625:
            ip = e.get('ip') or 'localhost'
            user = e.get('user') or 'unknown'
            ts = datetime.fromisoformat(e.get('timestamp')) if e.get('timestamp') else datetime.utcnow()
            dq = attempts.setdefault(ip, deque())
            dq.append(ts)
            user_map[ip] = user
            # prune old attempts outside window
            while dq and ts - dq[0] > window:
                dq.popleft()
            # Only alert once when threshold is FIRST reached, not every time
            if len(dq) >= fail_threshold and ip not in alerted:
                alerted.add(ip)
                alerts.append({
                    'severity': 'HIGH',
                    'title': f'[HIGH] Brute Force Attack - {user}',
                    'description': format_bruteforce_alert(ip, len(dq), window_minutes, user_map.get(ip))
                })
    return alerts
