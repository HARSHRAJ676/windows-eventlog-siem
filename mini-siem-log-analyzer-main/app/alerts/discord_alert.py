import requests
from utils.logging import setup_logger

logger = setup_logger("discord_alert")


def send_discord(cfg, text: str):
    url = cfg.get('webhook_url')
    if not url:
        logger.warning("Discord not configured; skipping")
        return
    try:
        r = requests.post(url, json={"content": text}, timeout=10)
        if r.status_code >= 300:
            logger.error(f"Discord error {r.status_code}: {r.text}")
    except Exception as e:
        logger.error(f"Discord send failed: {e}")
