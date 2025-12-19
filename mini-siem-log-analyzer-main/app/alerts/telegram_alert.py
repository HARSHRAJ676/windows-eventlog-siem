import requests
from utils.logging import setup_logger
import time

logger = setup_logger("telegram_alert")


def send_telegram(cfg, text: str):
    token = cfg.get('token')
    chat_id = cfg.get('chat_id')
    if not token or not chat_id:
        logger.warning("Telegram not configured; skipping")
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    
    # Retry up to 3 times
    for attempt in range(3):
        try:
            r = requests.post(url, json=payload, timeout=15)
            if r.status_code == 200:
                logger.info(f"Telegram alert sent successfully")
                return
            else:
                logger.error(f"Telegram error {r.status_code}: {r.text}")
                if attempt < 2:
                    time.sleep(1)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Telegram connection error (attempt {attempt+1}/3): {e}")
            if attempt < 2:
                time.sleep(2)
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            break
