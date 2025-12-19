# Advanced Windows SIEM & Threat Detection System

Windows-only mini SIEM pipeline: collect Windows Event Logs, normalize events, detect threats, store to SQLite, export recent events to JSON, and send alerts (Telegram/Discord/Email). Includes a minimal Flask dashboard.

The runnable code lives in `mini-siem-log-analyzer-main/`.

## Requirements

- Windows 10/11 or Windows Server 2016+
- Python 3.8+
- Administrator terminal (recommended) for Security log access

## Quick start

```powershell
cd "mini-siem-log-analyzer-main"
python install.py
python run.py
```

Dashboard: `http://127.0.0.1:5000`

## Configuration

- `mini-siem-log-analyzer-main/config.json` is intentionally **gitignored** (contains secrets).
- Copy from the committed template:

```powershell
cd "mini-siem-log-analyzer-main"
Copy-Item config.example.json config.json
```

Then edit `config.json`:
- Enable channels: `alerts.enabled_channels` (e.g. `["telegram"]`)
- Telegram: `alerts.telegram.token`, `alerts.telegram.chat_id`

## Tests / utilities

```powershell
cd "mini-siem-log-analyzer-main"
python test_events.py
python test_usb_watcher.py
python test_telegram.py
python trigger_alerts.py
```

## Notes

- Runtime artifacts (logs, SQLite DB, latest_events.json) are not committed to GitHub.
- Detection logic lives under `mini-siem-log-analyzer-main/app/detectors/` and correlation/rules under `mini-siem-log-analyzer-main/app/core/`.

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- Email: your.email@example.com

## 🙏 Acknowledgments

- Windows Event Log API documentation
- Python win32evtlog library
- Flask framework
- SQLite database
- Telegram Bot API

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Contact via email: your.email@example.com

## 🔄 Version History

- **v1.0.0** (2024-12-19)
  - Initial release
  - Core SIEM functionality
  - Web dashboard
  - Multi-channel alerting
  - USB device monitoring

## 🎓 Academic Project

This project was developed as part of an academic assignment for distributed security systems. It demonstrates practical implementation of security monitoring, threat detection, and incident response concepts.

---

**⚠️ Disclaimer**: This tool is for educational and authorized security monitoring purposes only. Ensure you have proper authorization before monitoring any systems.
