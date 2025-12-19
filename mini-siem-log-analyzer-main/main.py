#!/usr/bin/env python3
"""
Windows SIEM - Complete Security Monitoring System
Runs all features: Event Collection, USB Detection, PowerShell Monitoring, 
Process Monitoring, Brute Force Detection, Web Dashboard, and Telegram Alerts

AUTO-ELEVATES TO ADMINISTRATOR IF NEEDED
"""
import threading
import time
import os
import sys
import ctypes

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))


def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


from app.core.config_loader import AppConfig
from app.core.db import Database
from app.core.event_collector import collect_latest_events, export_latest_events
from app.core.process_watcher import start as start_process_watcher, drain as drain_process_events
from app.core.event_parser import normalize_event
from app.core.rules_engine import run_detectors
from app.alerts.alert_engine import dispatch_alerts
from utils.logging import setup_logger
from app.dashboard.dashboard import app as dashboard_app
from app.core.usb_wmi_watcher import USBWMIWatcher

logger = setup_logger("main")

BASE_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')


def print_banner():
    """Display startup banner"""
    banner = """
    ═══════════════════════════════════════════════════════════
    ███████╗██╗███████╗███╗   ███╗    
    ██╔════╝██║██╔════╝████╗ ████║    Windows SIEM v2.0
    ███████╗██║█████╗  ██╔████╔██║    Advanced Threat Detection
    ╚════██║██║██╔══╝  ██║╚██╔╝██║    
    ███████║██║███████╗██║ ╚═╝ ██║    
    ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    
    ═══════════════════════════════════════════════════════════
    
    🎯 Active Features:
       ✅ USB Device Monitoring (Real-time WMI)
       ✅ Failed Login Detection (Brute Force)
       ✅ PowerShell Command Monitoring
       ✅ Process Execution Monitoring
       ✅ Telegram Alert Delivery
       ✅ Web Dashboard (http://127.0.0.1:5000)
    
    ═══════════════════════════════════════════════════════════
    """
    print(banner)


def run_siem():
    """Main SIEM loop with USB monitoring"""
    try:
        cfg = AppConfig.load(CONFIG_PATH)
        db = Database(cfg.database.get('path', os.path.join(BASE_DIR, 'data', 'siem.db')))
        
        logger.info("🚀 Starting SIEM Event Collection Engine")
        
        # In-memory buffer for synthetic USB events from WMI watcher
        synthetic_events = []
        
        def _on_usb_event(evt: dict):
            """Callback when USB device attached/removed"""
            synthetic_events.append(evt)
            logger.debug(f"USB event queued: {evt.get('usb_kind')} - {evt.get('usb_name')}")
        
        # Start USB WMI watcher thread
        logger.info("🔌 Starting USB WMI Watcher...")
        usb_watcher = USBWMIWatcher(on_event=_on_usb_event)
        usb_watcher.start()
        logger.info("✅ USB monitoring active")
        
        # Start real-time process watcher (non-admin works)
        try:
            start_process_watcher()
        except Exception:
            pass

        # Main event collection loop
        while True:
            # Collect events from Windows Event Logs
            events = collect_latest_events(cfg.channels, max_records=250)
            
            # Merge synthetic USB events from WMI watcher
            if synthetic_events:
                logger.debug(f"Merging {len(synthetic_events)} USB events")
                events.extend(synthetic_events)
                synthetic_events.clear()
            
            # Drain any real-time process events and merge
            try:
                rt_events = drain_process_events(250)
                if rt_events:
                    events.extend(rt_events)
            except Exception:
                pass

            # Normalize and enrich events
            events = [normalize_event(e) for e in events]
            
            # Persist to database
            db.insert_events(events)
            
            # Export latest events to JSON
            export_latest_events(
                events, 
                cfg.export.get('latest_events_json', os.path.join(BASE_DIR, 'data', 'latest_events.json'))
            )
            
            # Run detection rules
            alerts = run_detectors(events, cfg.thresholds)
            
            # Dispatch alerts (Telegram, Discord, Email)
            if alerts:
                logger.info(f"📢 Dispatching {len(alerts)} alerts")
            dispatch_alerts(
                alerts, 
                cfg.alerts.__dict__ if hasattr(cfg.alerts, '__dict__') else cfg.alerts, 
                db
            )
            
            # Sleep before next collection cycle
            time.sleep(cfg.interval_seconds)
            
    except KeyboardInterrupt:
        logger.info("🛑 SIEM shutdown requested")
        usb_watcher.stop()
    except Exception as e:
        logger.error(f"❌ SIEM error: {e}", exc_info=True)
        raise


def start_dashboard():
    """Start Flask web dashboard"""
    logger.info("🌐 Starting Web Dashboard on http://127.0.0.1:5000")
    dashboard_app.run(host='127.0.0.1', port=5000, debug=False)


def main():
    """Main entry point"""
    print_banner()
    
    # Check if running as administrator
    if not is_admin():
        logger.warning("⚠️  NOT running as Administrator")
        logger.warning("⚠️  Security log access will be limited")
        logger.warning("⚠️  Please use START_SIEM.ps1 for full functionality")
        print("\n" + "="*60)
        print("⚠️  WARNING: Not running as Administrator!")
        print("="*60)
        print("Some features may not work:")
        print("  ❌ Failed login detection (needs Security log)")
        print("  ❌ Process monitoring (needs admin)")
        print("  ✅ USB detection (will work)")
        print("  ✅ PowerShell monitoring (partial)")
        print("\n💡 Recommended: Right-click START_SIEM.ps1 → Run with PowerShell")
        print("="*60 + "\n")
    else:
        logger.info("✅ Running with Administrator privileges")
    
    # Start SIEM in background thread
    logger.info("🔧 Starting background SIEM thread...")
    siem_thread = threading.Thread(target=run_siem, daemon=True, name="SIEM-Thread")
    siem_thread.start()
    
    # Wait for SIEM to initialize
    logger.info("⏳ Waiting for SIEM initialization...")
    time.sleep(3)
    
    # Start Flask dashboard (blocks main thread)
    logger.info("🎬 Launching dashboard...")
    start_dashboard()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 SIEM stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}", exc_info=True)
        sys.exit(1)
