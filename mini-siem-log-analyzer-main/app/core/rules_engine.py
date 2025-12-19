from typing import List, Dict, Any

from app.detectors.bruteforce import detect_bruteforce
from app.detectors.powershell_abuse import detect_powershell_abuse
from app.detectors.usb_monitor import detect_usb_activity
from app.detectors.malware_exec import detect_malware_exec
from utils.logging import setup_logger

logger = setup_logger("rules_engine")


def run_detectors(events: List[Dict[str, Any]], thresholds: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    alerts += detect_bruteforce(events, thresholds)
    alerts += detect_powershell_abuse(events, thresholds)
    alerts += detect_usb_activity(events, thresholds)
    alerts += detect_malware_exec(events, thresholds)
    logger.info(f"Detectors produced {len(alerts)} alerts")
    return alerts
