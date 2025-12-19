import threading
import time
from typing import Callable, Dict, Set

import wmi
from utils.logging import setup_logger

logger = setup_logger("usb_wmi_watcher")


class USBWMIWatcher:
    def __init__(self, on_event: Callable[[dict], None]):
        self._on_event = on_event
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._cache: Dict[str, Dict[str, str]] = {}
        self._recent_events: Set[str] = set()  # deduplicate within 2 seconds

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)

    def _emit(self, kind: str, name: str, pnp: str, model: str = None, capacity_gb: float = None):
        # Filter: Only alert on USB storage devices
        # Accept: USBSTOR\DISK (actual USB storage device)
        # Reject: HID\, USB\VID (non-storage like keyboard/mouse), STORAGE\VOLUME (volume without disk)
        pnp_upper = pnp.upper()
        
        # Only allow USBSTOR devices (the actual USB storage hardware)
        if not ("USBSTOR" in pnp_upper and "DISK" in pnp_upper):
            logger.debug(f"Skipping non-storage device: {name} ({pnp[:60]}...)")
            return
        
        # Deduplicate: only emit if we haven't seen this exact PNP ID+kind in last 2 seconds
        dedup_key = f"{kind}:{pnp}"
        if dedup_key in self._recent_events:
            logger.debug(f"Skipping duplicate USB {kind}: {name}")
            return
        self._recent_events.add(dedup_key)
        # Clear after 2 seconds
        def _clear():
            time.sleep(2)
            self._recent_events.discard(dedup_key)
        threading.Thread(target=_clear, daemon=True).start()
        
        # Build a richer structured event consumed by usb detector.
        msg_lines = [f"USB {kind}: {name}"]
        if model:
            msg_lines.append(f"Model: {model}")
        if capacity_gb is not None:
            msg_lines.append(f"Capacity: {capacity_gb} GB")
        if pnp:
            msg_lines.append(pnp)
        message = "\n".join(msg_lines)
        evt = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "channel": "System",
            "event_id": 9999,  # synthetic
            "user": None,
            "ip": None,
            "command": None,
            "message": message,
            "usb_name": name,
            "usb_model": model,
            "usb_capacity_gb": capacity_gb,
            "usb_pnp_id": pnp,
            "usb_kind": kind
        }
        self._on_event(evt)

    def _run(self):
        try:
            c = wmi.WMI()
            watcher_add = c.watch_for(notification_type="Creation", wmi_class="Win32_PnPEntity")
            watcher_del = c.watch_for(notification_type="Deletion", wmi_class="Win32_PnPEntity")
            logger.info("USB WMI watcher started (synthetic event_id 9999)")
            while not self._stop.is_set():
                # Attach handling
                try:
                    add_evt = watcher_add(timeout_ms=500)
                    if add_evt:
                        name = getattr(add_evt, "Name", "USB device") or "USB device"
                        pnp = getattr(add_evt, "PNPDeviceID", "") or ""
                        model = None
                        capacity_gb = None
                        try:
                            for d in c.Win32_DiskDrive(InterfaceType='USB'):
                                d_pnp = getattr(d, 'PNPDeviceID', '')
                                if pnp and d_pnp == pnp:
                                    model = getattr(d, 'Model', None)
                                    size = getattr(d, 'Size', None)
                                    if size:
                                        capacity_gb = round(int(size)/(1024**3), 2)
                                    break
                            # fallback if specific match not found
                            if model is None:
                                drives = c.Win32_DiskDrive(InterfaceType='USB')
                                if drives:
                                    model = getattr(drives[0], 'Model', None)
                                    size = getattr(drives[0], 'Size', None)
                                    if size and capacity_gb is None:
                                        capacity_gb = round(int(size)/(1024**3), 2)
                        except Exception as e:
                            logger.debug(f"Disk drive enrichment failed: {e}")
                        self._cache[pnp] = {"model": model or "", "capacity_gb": str(capacity_gb) if capacity_gb is not None else ""}
                        self._emit("attach", name, pnp, model, capacity_gb)
                        logger.info(f"USB attach: name={name} model={model} capacity={capacity_gb}GB")
                except wmi.x_wmi_timed_out:
                    pass
                except Exception as e:
                    logger.error(f"USB attach watcher error: {e}")

                # Removal handling
                try:
                    del_evt = watcher_del(timeout_ms=500)
                    if del_evt:
                        name = getattr(del_evt, "Name", "USB device") or "USB device"
                        pnp = getattr(del_evt, "PNPDeviceID", "") or ""
                        cached = self._cache.get(pnp, {})
                        model = cached.get("model") or None
                        capacity_gb = None
                        cap_str = cached.get("capacity_gb")
                        if cap_str:
                            try:
                                capacity_gb = float(cap_str)
                            except ValueError:
                                capacity_gb = None
                        self._emit("remove", name, pnp, model, capacity_gb)
                        logger.info(f"USB remove: name={name} model={model}")
                        if pnp in self._cache:
                            del self._cache[pnp]
                except wmi.x_wmi_timed_out:
                    pass
                except Exception as e:
                    logger.error(f"USB remove watcher error: {e}")
        except Exception as e:
            logger.error(f"Failed to start WMI watcher: {e}")
