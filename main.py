import csv
import ctypes
from datetime import datetime

from collectors.recent_files import RecentFilesCollector
from collectors.registry_mru import RegistryMRUCollector
from collectors.userassist import UserAssistCollector
from collectors.prefetch import PrefetchCollector
from collectors.file_metadata import FileMetadataCollector
from collectors.browser_downloads import BrowserDownloadsCollector
from collectors.firefox_downloads import FirefoxDownloadsCollector

from core.correlator import correlate_events
from core.event import EventType


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def parse_datetime(value: str):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M")
    except ValueError:
        return None


def export_to_csv(events):
    filename = "forensic_timeline.csv"

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Timestamp',
            'Event_Type',
            'Subject',
            'Object',
            'Description',
            'Source',
            'Confidence',
            'Correlated',
            'Correlation_Notes'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for event in events:
            writer.writerow({
                'Timestamp': event.sort_time.isoformat() if event.sort_time else 'UNKNOWN',
                'Event_Type': event.event_type.value if event.event_type else 'UNKNOWN',
                'Subject': event.subject,
                'Object': event.object,
                'Description': event.description,
                'Source': event.source,
                'Confidence': event.confidence.value,
                'Correlated': 'Yes' if event.correlated else 'No',
                'Correlation_Notes': event.correlation_notes or ''
            })


def main():
    print("Digital Forensic Timeline Reconstructor")
    print("=" * 50)
    print()
    print("Select operation mode:")
    print("1. Standard Mode (No admin privileges required)")
    print("   - Collects user-accessible artifacts")
    print("   - Recent Files, Registry MRU, UserAssist, File Metadata, Browser Downloads")
    print()
    print("2. Enhanced Mode (Requires administrator privileges)")
    print("   - Includes all Standard Mode artifacts")
    print("   - Plus system-level artifacts (Prefetch)")
    print()

    while True:
        mode_input = input("Enter choice (1/2): ").strip()
        if mode_input in ['1', '2']:
            break
        print("Invalid choice. Please enter 1 or 2.")

    enable_prefetch = False
    mode_name = ""

    if mode_input == "2":
        if not is_admin():
            print("\n[!] Enhanced mode selected, but administrator privileges not detected.")
            print("   Please re-run the tool as administrator (Right-click → Run as administrator)")
            return
        else:
            print("\n[+] Running in Enhanced (Administrator) Mode")
            enable_prefetch = True
            mode_name = "Enhanced Mode"
    else:
        print("\n[+] Running in Standard (User) Mode")
        mode_name = "Standard Mode"

    print(f"Features: Cross-artifact correlation, confidence scoring, user/system activity detection")
    print(f"Mode: {mode_name}")

    collectors = [
        RecentFilesCollector(),
        RegistryMRUCollector(),
        UserAssistCollector(),
        FileMetadataCollector(),
        BrowserDownloadsCollector(),
        FirefoxDownloadsCollector()
    ]

    if enable_prefetch:
        collectors.append(PrefetchCollector())

    collector_names = [type(c).__name__.replace('Collector', '') for c in collectors]
    print(f"Collecting from: {', '.join(collector_names)}")

    all_events = []
    for collector in collectors:
        all_events.extend(collector.collect())

    print(f"\nCollected {len(all_events)} total events")

    all_events = correlate_events(all_events)

    display_events = list(all_events)

    print("\nFilter timeline by time range (optional)")

    from datetime import timedelta
    default_start = datetime.now() - timedelta(days=7)

    start_input = input(f"Start time (YYYY-MM-DD HH:MM) or Enter for last 7 days: ").strip()
    end_input = input("End time (YYYY-MM-DD HH:MM) or Enter to skip: ").strip()
    include_unknown = input("Include events with UNKNOWN time? (y/n): ").lower() == "y"

    if not start_input:
        start_time = default_start
        print(f"Using default start time: {start_time.strftime('%Y-%m-%d %H:%M')}")
    else:
        start_time = parse_datetime(start_input)

    end_time = parse_datetime(end_input) if end_input else None

    filtered_events = []

    for event in display_events:
        t = event.sort_time

        if t is None:
            if include_unknown:
                filtered_events.append(event)
            continue

        if start_time and t < start_time:
            continue

        if end_time and t > end_time:
            continue

        filtered_events.append(event)

    display_events = filtered_events

    print("\nApplied time filter:")
    print(f"  Start: {start_time if start_time else 'Not set'}")
    print(f"  End:   {end_time if end_time else 'Not set'}")
    print(f"  Include UNKNOWN times: {include_unknown}")
    print(f"  Events after filtering: {len(display_events)}\n")

    display_events.sort(key=lambda e: e.sort_time or datetime.min, reverse=True)

    MAX_TERMINAL_EVENTS = 10
    print("Timeline preview (most recent events):\n")

    for event in display_events[:MAX_TERMINAL_EVENTS]:
        print(event)

    remaining = len(display_events) - MAX_TERMINAL_EVENTS
    if remaining > 0:
        print(f"\n... {remaining} more events filtered.")
        print("Use CSV export for complete forensic timeline.")

    csv_export = input("\nExport filtered timeline to CSV? (y/n): ").lower().strip() == 'y'

    if csv_export:
        export_to_csv(display_events)
        print(f"Filtered timeline exported to 'forensic_timeline.csv' ({len(display_events)} events)")
        print("Note: Use unfiltered export for complete forensic evidence.")


if __name__ == "__main__":
    main()
