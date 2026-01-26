
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from collectors.clipboard.clipboard import ClipboardCollector
    print("[OK] ClipboardCollector imported successfully")

    collector = ClipboardCollector()
    print("[OK] ClipboardCollector instantiated successfully")

    is_admin = collector._is_admin()
    print(f"[OK] Admin privileges: {'Yes' if is_admin else 'No'}")

    events = collector.collect()
    print(f"[OK] Clipboard collection completed, got {len(events)} events")

    current_events = [e for e in events if "Historical" not in e.object]
    historical_events = [e for e in events if "Historical" in e.object]

    print(f"  - Current clipboard events: {len(current_events)}")
    print(f"  - Historical clipboard events: {len(historical_events)}")

    if events:
        print("[OK] Clipboard event details:")
        for event in events:
            print(f"  - {event}")
            print(f"    Raw time_start: {event.time_start}")
            print(f"    Current datetime.now(): {datetime.now()}")
    else:
        print("[WARN] No clipboard events collected (clipboard may be empty or pywin32 unavailable)")

    if is_admin and not historical_events:
        print("[INFO] Admin privileges available but no historical data found (database may not exist or be empty)")

except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
