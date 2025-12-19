# Mini SIEM Log Analyzer (Standardized)

Windows-only SIEM pipeline: collect Windows Event Logs (pywin32), normalize, detect threats, persist to SQLite, export JSON, and send alerts (Telegram/Discord/Email). Includes a minimal dashboard API.

## Structure
- `app.py`: SIEM loop (ingest → parse → detect → store → alert)
- `run.py`: Starts SIEM loop + Flask dashboard
- `install.py`: Installs dependencies, verifies pywin32, creates folders
- `config.json`: Config (interval, channels, alerts, thresholds, DB)
- `app/core`: `config_loader.py`, `db.py`, `event_collector.py`, `event_parser.py`, `rules_engine.py`
- `app/alerts`: `alert_engine.py`, `telegram_alert.py`, `discord_alert.py`, `email_alert.py`
- `app/detectors`: `bruteforce.py`, `powershell_abuse.py`, `usb_monitor.py`, `malware_exec.py`
- `app/dashboard`: `dashboard.py` (Flask API)
- `utils`: `logging.py`, `helpers.py`
- `data`: SQLite DB and latest JSON events
- `logs`: Rotating log files

## Install
```powershell
cd "C:\project\Advanced Windows SIEM & Threat Detection System\mini-siem-log-analyzer-main"
python install.py
```
If `pywin32` check fails:
```powershell
pip install pywin32
python -c "import win32evtlog; print('pywin32 OK')"
```

## Configure Telegram
Edit `config.json`:
- `alerts.enabled_channels`: `["telegram"]`
- `alerts.telegram.token`: `<bot token>`
- `alerts.telegram.chat_id`: `<chat id>`

## Run
```powershell
cd "C:\project\Advanced Windows SIEM & Threat Detection System\mini-siem-log-analyzer-main"
python run.py
```
SIEM runs at the configured interval and serves dashboard at `http://127.0.0.1:5000`.

## Trigger Alerts Manually
- PowerShell ScriptBlock logging (4104) — enable (Admin):
```powershell
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -Force | Out-Null
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force | Out-Null
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
```
- Security auditing (4625, 4688):
```powershell
auditpol /set /subcategory:"Logon" /success:disable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Force | Out-Null
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
```
- Test PowerShell event (4104 or 4688 path):
```powershell
$cmd = 'Write-Output "TestAlert"'; $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)); powershell -EncodedCommand $b64
```
- USB insert/remove: Plug/unplug a device; detector looks for Kernel-PnP `2003/2100`.
- Synthetic sample:
```powershell
python test_events.py
```

## Notes
- Run terminal as Administrator for Security log access.
- If USB alerts don't trigger, check Event Viewer for the actual Kernel-PnP IDs and update `app/detectors/usb_monitor.py` accordingly.


