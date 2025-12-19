import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.core.config_loader import AppConfig
from app.alerts.telegram_alert import send_telegram

CONFIG_PATH = 'config.json'

def main():
    cfg = AppConfig.load(CONFIG_PATH)
    print(f"Testing Telegram with token: {cfg.alerts.telegram.get('token')[:20]}...")
    print(f"Chat ID: {cfg.alerts.telegram.get('chat_id')}")
    
    send_telegram(cfg.alerts.telegram, "🚨 Test Alert from Windows SIEM\n\nIf you see this, Telegram alerts are working!")
    print("\n✅ Alert sent! Check your Telegram.")

if __name__ == '__main__':
    main()
