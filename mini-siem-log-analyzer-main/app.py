import os
import time
from app.core.config_loader import AppConfig
from app.core.db import Database
from app.core.event_collector import collect_latest_events, export_latest_events
from app.core.event_parser import normalize_event
from app.core.rules_engine import run_detectors
from app.alerts.alert_engine import dispatch_alerts
from utils.logging import setup_logger

logger = setup_logger("app")

BASE_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')


def main():
    cfg = AppConfig.load(CONFIG_PATH)
    db = Database(cfg.database.get('path', os.path.join(BASE_DIR, 'data', 'siem.db')))

    logger.info("Starting SIEM loop")
    while True:
        events = collect_latest_events(cfg.channels, max_records=250)
        # Normalize/enrich
        events = [normalize_event(e) for e in events]
        # Persist
        db.insert_events(events)
        # Export
        export_latest_events(events, cfg.export.get('latest_events_json', os.path.join(BASE_DIR, 'data', 'latest_events.json')))
        # Detect
        alerts = run_detectors(events, cfg.thresholds)
        # Alert
        dispatch_alerts(alerts, cfg.alerts.__dict__ if hasattr(cfg.alerts, '__dict__') else cfg.alerts, db)
        time.sleep(cfg.interval_seconds)


if __name__ == '__main__':
    main()
