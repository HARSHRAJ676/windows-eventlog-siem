from typing import List, Dict, Any, Set
import time

USB_EVENT_IDS: Set[int] = {2003, 2100, 2102, 400, 410, 9999}
USB_SIGNATURES = ["USB\\VID_", "USB VID", "Device configured (USB\\VID", "USB attach:", "USB remove:"]

# In-memory dedupe per physical device (serial extracted from PNP ID)
_recent_usb: Dict[str, float] = {}
_USB_DEDUPE_SECONDS = 8  # window to collapse Volume/HARSHRAJ/Mass Storage into one alert


def _looks_usb(message: str) -> bool:
    m = (message or '').lower()
    return any(sig.lower() in m for sig in USB_SIGNATURES)


def _extract_label(pnp: str, name: str) -> str:
    """Extract volume label from device name or path."""
    if name and name not in ['Volume', 'USB Mass Storage Device', 'SanDisk Ultra Fit USB Device']:
        if '\\' not in name and '_??' not in name:
            return name
    return ""


def _shorten_path(path: str, max_len: int = 40) -> str:
    """Truncate long paths."""
    if not path or len(path) <= max_len:
        return path
    return path[:max_len] + "…"


def _extract_vendor(model: str) -> str:
    """Extract vendor/manufacturer from model string."""
    if not model:
        return "Unknown"
    parts = model.split()
    if parts:
        vendor = parts[0]
        if vendor.lower() in ['usb', 'mass', 'storage', 'device']:
            return model
        return vendor
    return model


def _get_risk_emoji(severity: str) -> str:
    if severity == 'HIGH':
        return '🔴'
    elif severity == 'MEDIUM':
        return '⚠️'
    else:
        return '🟢'


def _extract_serial(pnp: str) -> str:
    if not pnp:
        return "unknown"
    # USBSTOR\DISK&VEN_...\SERIAL
    parts = pnp.split("\\")
    if len(parts) >= 2:
        return parts[-1]
    return pnp[-32:]


def format_usb_alert(e: Dict[str, Any]) -> tuple:
    """
    Format USB event into clean SOC-style alert.
    Returns: (severity, title, description)
    """
    kind = e.get('usb_kind', 'activity').lower()
    name = e.get('usb_name', 'USB Device')
    model = e.get('usb_model') or ''
    cap = e.get('usb_capacity_gb')
    pnp = e.get('usb_pnp_id') or ''
    
    # Determine friendly device name
    device_name = model if model else name
    if 'USB Mass Storage Device' in device_name and model:
        device_name = model
    
    # Extract vendor for cleaner display
    vendor = _extract_vendor(device_name)
    
    # Extract label (volume name)
    label = _extract_label(pnp, name)
    
    # Determine severity
    severity = 'MEDIUM' if kind == 'attach' and cap else 'LOW'
    if kind == 'remove':
        severity = 'LOW'
    
    # Build icon
    icon = '🔌'
    risk_icon = _get_risk_emoji(severity)
    
    # Format action
    action = 'Attached' if kind == 'attach' else 'Removed'
    
    # Build alert
    lines = [f"{icon} USB Device {action}"]
    lines.append(f"Device Name: {device_name}")
    if label:
        lines.append(f"Label: {label}")
    if cap is not None:
        try:
            lines.append(f"Capacity: {float(cap):.2f} GB")
        except Exception:
            pass
    
    device_type = "Mass Storage" if "storage" in name.lower() or "disk" in pnp.lower() else "USB Device"
    lines.append(f"Device Type: {device_type}")
    lines.append(f"Risk Level: {severity.title()} {risk_icon}")
    
    if kind == 'attach' and pnp:
        short_path = _shorten_path(pnp, 60)
        lines.append(f"Device Path: {short_path}")
    
    description = "\n".join(lines)
    serial = _extract_serial(pnp)
    title = f"USB Device {action}: {serial[:8]}"  # include serial fragment for better dedupe discrimination
    
    return (severity, title, description)


def detect_usb_activity(events: List[Dict[str, Any]], thresholds: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    now = time.time()
    # Clean old dedupe entries
    for k, ts in list(_recent_usb.items()):
        if now - ts > _USB_DEDUPE_SECONDS:
            del _recent_usb[k]

    for e in events:
        if e.get('channel') != 'System':
            continue
        eid = e.get('event_id')
        msg = e.get('message') or ''
        if not (eid in USB_EVENT_IDS or _looks_usb(msg)):
            continue

        if eid == 9999:  # synthetic enriched
            pnp = e.get('usb_pnp_id') or ''
            serial = _extract_serial(pnp)
            kind = e.get('usb_kind', '')
            # Collapse multiple entity events (Volume / label / device) into single per kind+serial
            dedupe_key = f"{kind}:{serial}"
            if dedupe_key in _recent_usb:
                # skip duplicate within window
                continue
            _recent_usb[dedupe_key] = now
            severity, title, desc = format_usb_alert(e)
        else:
            # Legacy USB logs (rare); low severity generic alert
            desc = msg[:400]
            severity = 'LOW'
            title = 'USB Activity'

        alerts.append({
            'severity': severity,
            'title': title,
            'description': desc
        })
    return alerts
