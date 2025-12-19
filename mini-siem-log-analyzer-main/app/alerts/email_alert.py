import smtplib
from email.message import EmailMessage
from utils.logging import setup_logger

logger = setup_logger("email_alert")


def send_email(cfg, subject: str, body: str):
    server = cfg.get('smtp_server')
    port = cfg.get('smtp_port', 587)
    username = cfg.get('username')
    password = cfg.get('password')
    to_addr = cfg.get('to')
    if not (server and username and password and to_addr):
        logger.warning("Email not configured; skipping")
        return
    try:
        msg = EmailMessage()
        msg["From"] = username
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(server, port) as s:
            s.starttls()
            s.login(username, password)
            s.send_message(msg)
    except Exception as e:
        logger.error(f"Email send failed: {e}")
