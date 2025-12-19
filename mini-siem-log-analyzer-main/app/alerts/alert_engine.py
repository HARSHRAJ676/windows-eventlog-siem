from typing import List, Dict, Any
from datetime import datetime, timedelta

from utils.logging import setup_logger
from app.alerts.telegram_alert import send_telegram
from app.alerts.discord_alert import send_discord
from app.alerts.email_alert import send_email

logger = setup_logger("alert_engine")

# Global alert deduplication cache (title -> timestamp)
_alert_cache: Dict[str, datetime] = {}
_ALERT_COOLDOWN_MINUTES = 5  # Don't send same alert within 5 minutes


def dispatch_alerts(alerts: List[Dict[str, Any]], config: Dict[str, Any], db):
    enabled = config.get('enabled_channels', [])
    now = datetime.utcnow()
    
    for a in alerts:
        title = a.get('title', 'Alert')
        severity = a.get('severity', 'LOW')
        desc = a.get('description', '')
        
        # Deduplicate: Skip if same alert sent recently
        if title in _alert_cache:
            last_sent = _alert_cache[title]
            if now - last_sent < timedelta(minutes=_ALERT_COOLDOWN_MINUTES):
                logger.debug(f"Skipping duplicate alert: {title}")
                continue
        
        # Update cache
        _alert_cache[title] = now
        
        # Clean old cache entries (older than cooldown period)
        expired = [k for k, v in _alert_cache.items() if now - v > timedelta(minutes=_ALERT_COOLDOWN_MINUTES)]
        for k in expired:
            del _alert_cache[k]
        
        # Record in DB
        db.insert_alert(severity, title, desc, now.isoformat())
        
        # Send alerts
        message = f"{title}\n{desc}"  # Title already includes [SEVERITY] prefix
        if 'telegram' in enabled:
            send_telegram(config.get('telegram', {}), message)
        if 'discord' in enabled:
            send_discord(config.get('discord', {}), message)
        if 'email' in enabled:
            send_email(config.get('email', {}), title, desc)
