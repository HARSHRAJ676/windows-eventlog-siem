import threading
import time
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from app.core.config_loader import AppConfig
from app.core.db import Database
from app.core.event_collector import collect_latest_events, export_latest_events
from app.core.event_parser import normalize_event
from app.core.rules_engine import run_detectors
from app.alerts.alert_engine import dispatch_alerts
from utils.logging import setup_logger
from app.dashboard.dashboard import app as dashboard_app
from app.core.usb_wmi_watcher import USBWMIWatcher

logger = setup_logger("siem_runner")

BASE_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')


def run_siem():
    cfg = AppConfig.load(CONFIG_PATH)
    db = Database(cfg.database.get('path', os.path.join(BASE_DIR, 'data', 'siem.db')))
    logger.info("Starting SIEM loop")

    # In-memory synthetic events from WMI watcher
    synthetic_events = []

    def _on_usb(evt: dict):
        synthetic_events.append(evt)

    # Start USB WMI watcher
    watcher = USBWMIWatcher(on_event=_on_usb)
    watcher.start()
    while True:
        events = collect_latest_events(cfg.channels, max_records=250)
        # merge synthetic USB events then clear buffer
        if synthetic_events:
            events.extend(synthetic_events)
            synthetic_events.clear()
        events = [normalize_event(e) for e in events]
        db.insert_events(events)
        export_latest_events(events, cfg.export.get('latest_events_json', os.path.join(BASE_DIR, 'data', 'latest_events.json')))
        alerts = run_detectors(events, cfg.thresholds)
        dispatch_alerts(alerts, cfg.alerts.__dict__ if hasattr(cfg.alerts, '__dict__') else cfg.alerts, db)
        time.sleep(cfg.interval_seconds)


def start_dashboard():
    dashboard_app.run(host='127.0.0.1', port=5000)


def main():
    t = threading.Thread(target=run_siem, daemon=True)
    t.start()
    time.sleep(2)
    start_dashboard()


if __name__ == '__main__':
    main()
