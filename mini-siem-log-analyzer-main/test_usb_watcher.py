"""
Test USB WMI Watcher - Run this to verify USB detection is working
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.core.usb_wmi_watcher import USBWMIWatcher
import time

print("=" * 50)
print("USB WMI Watcher Test")
print("=" * 50)
print("\nMonitoring USB devices...")
print("Please plug/unplug your USB drive now.")
print("Press Ctrl+C to stop.")
print("=" * 50)

events_detected = []

def on_event(evt):
    events_detected.append(evt)
    print(f"\n✅ USB Event Detected!")
    print(f"  Kind: {evt.get('usb_kind')}")
    print(f"  Name: {evt.get('usb_name')}")
    print(f"  Model: {evt.get('usb_model')}")
    print(f"  Capacity: {evt.get('usb_capacity_gb')} GB")
    print(f"  PNP ID: {evt.get('usb_pnp_id')[:80]}...")
    print("-" * 50)

watcher = USBWMIWatcher(on_event=on_event)
watcher.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\n\n{'=' * 50}")
    print(f"Test Complete!")
    print(f"Total events detected: {len(events_detected)}")
    print(f"{'=' * 50}")
    watcher.stop()
