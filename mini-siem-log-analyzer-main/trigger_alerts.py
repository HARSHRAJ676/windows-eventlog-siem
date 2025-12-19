import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime
from app.core.config_loader import AppConfig
from app.core.db import Database
from app.core.rules_engine import run_detectors
from app.alerts.alert_engine import dispatch_alerts

CONFIG_PATH = 'config.json'

# Create fake events to trigger detectors
FAKE_EVENTS = [
    # Brute force - 3 failed logins from same IP
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Security", "event_id": 4625, "user": "admin", "ip": "192.168.1.100", "command": None, "message": "Failed login from 192.168.1.100"},
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Security", "event_id": 4625, "user": "admin", "ip": "192.168.1.100", "command": None, "message": "Failed login from 192.168.1.100"},
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Security", "event_id": 4625, "user": "admin", "ip": "192.168.1.100", "command": None, "message": "Failed login from 192.168.1.100"},
    
    # PowerShell abuse - EncodedCommand
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Windows PowerShell", "event_id": 4104, "user": "user1", "ip": None, "command": "powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAZQBzAHQAIgA=", "message": "ScriptBlock with encoded command"},
    
    # USB device
    {"timestamp": datetime.utcnow().isoformat(), "channel": "System", "event_id": 2003, "user": None, "ip": None, "command": None, "message": "Kernel-PnP: Device configured (USB\\VID_1234&PID_5678)"},
    
    # Suspicious process
    {"timestamp": datetime.utcnow().isoformat(), "channel": "Security", "event_id": 4688, "user": "user1", "ip": None, "command": "C:\\Windows\\Temp\\malware.exe", "message": "Process created from suspicious location"},
]

def main():
    print("🔍 Triggering SIEM detectors with fake events...\n")
    
    cfg = AppConfig.load(CONFIG_PATH)
    db = Database(cfg.database.get('path', 'data/siem.db'))
    
    # Save events to DB
    db.insert_events(FAKE_EVENTS)
    print(f"✅ Saved {len(FAKE_EVENTS)} fake events to database")
    
    # Run detectors
    alerts = run_detectors(FAKE_EVENTS, cfg.thresholds)
    print(f"✅ Generated {len(alerts)} alerts:")
    for a in alerts:
        print(f"   [{a['severity']}] {a['title']}: {a['description'][:60]}...")
    
    # Send to Telegram
    if alerts:
        print(f"\n📤 Sending {len(alerts)} alerts to Telegram...")
        dispatch_alerts(alerts, cfg.alerts.__dict__ if hasattr(cfg.alerts, '__dict__') else cfg.alerts, db)
        print("✅ Done! Check your Telegram for alerts.")
    else:
        print("⚠️ No alerts were generated. Try adjusting thresholds.")

if __name__ == '__main__':
    main()
