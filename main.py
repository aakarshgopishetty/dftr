import csv
import ctypes
from datetime import datetime

from collectors.recent_files.recent_files import RecentFilesCollector
from collectors.app_usage.registry_mru import RegistryMRUCollector
from collectors.app_usage.userassist import UserAssistCollector
from collectors.app_usage.prefetch import PrefetchCollector

from collectors.usb_logs.usb import USBCollector
from collectors.file_metadata.file_metadata import FileMetadataCollector
from collectors.downloads.browser_downloads import BrowserDownloadsCollector
from collectors.recent_files.jump_lists import JumpListsCollector
from collectors.browser_history.browser_history import BrowserHistoryCollector
from collectors.clipboard.clipboard import ClipboardCollector
from collectors.startup_shutdown_logs.startup_shutdown_logs import StartupShutdownLogsCollector
from collectors.temp_files.temp_files import TempFilesCollector

from collectors.downloads.non_browser_downloads import NonBrowserDownloadAnalyzer

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
    print("   - Recent Files, Registry MRU, UserAssist, File Metadata, Browser Downloads, Jump Lists, Browser History, Clipboard, Startup/Shutdown Logs, Temp Files")
    print()
    print("2. Enhanced Mode (Requires administrator privileges)")
    print("   - Includes all Standard Mode artifacts")
    print("   - Plus system-level artifacts (Prefetch) and historical clipboard data")
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
            print("   Please re-run the tool as administrator (Right-click -> Run as administrator)")
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

    collectors = []
    failed_collectors = []

    # Initialize collectors with error handling
    collector_classes = [
        (RecentFilesCollector, "Recent Files"),
        (RegistryMRUCollector, "Registry MRU"),
        (UserAssistCollector, "UserAssist"),
        (FileMetadataCollector, "File Metadata"),
        (BrowserDownloadsCollector, "Browser Downloads"),
        (JumpListsCollector, "Jump Lists"),
        (BrowserHistoryCollector, "Browser History"),
        (ClipboardCollector, "Clipboard"),
        (USBCollector, "USB"),
        (StartupShutdownLogsCollector, "Startup/Shutdown Logs"),
        (TempFilesCollector, "Temp Files")
    ]

    for collector_class, name in collector_classes:
        try:
            collector = collector_class()
            collectors.append(collector)
            print(f"✓ {name} collector initialized")
        except Exception as e:
            print(f"⚠ Failed to initialize {name} collector: {e}")
            failed_collectors.append(name)
            continue

    if enable_prefetch:
        try:
            collectors.append(PrefetchCollector())
            print("✓ Prefetch collector initialized")
        except Exception as e:
            print(f"⚠ Failed to initialize Prefetch collector: {e}")
            failed_collectors.append("Prefetch")

    if failed_collectors:
        print(f"\n⚠ Warning: {len(failed_collectors)} collectors failed to initialize: {', '.join(failed_collectors)}")
        print("   The tool will continue with available collectors.")

    collector_names = [type(c).__name__.replace('Collector', '') for c in collectors]
    print(f"\nCollecting from: {', '.join(collector_names)}")

    all_events = []
    collection_errors = []

    for collector in collectors:
        collector_name = type(collector).__name__.replace('Collector', '')
        try:
            events = collector.collect()
            all_events.extend(events)
            print(f"✓ {collector_name}: {len(events)} events collected")
        except Exception as e:
            error_msg = f"Failed to collect from {collector_name}: {e}"
            print(f"✗ {error_msg}")
            collection_errors.append(error_msg)
            continue

    if collection_errors:
        print(f"\n⚠ Warning: {len(collection_errors)} collection errors occurred.")
        print("   Check the error messages above for details.")
        print("   The tool will continue with successfully collected events.")

    print(f"\nCollected {len(all_events)} total events")

    valid_events = [event for event in all_events if event.is_temporally_valid()]
    future_events_count = len(all_events) - len(valid_events)

    if future_events_count > 0:
        print(f"Filtered out {future_events_count} future events (maintaining forensic integrity)")

    all_events = valid_events

    # Correlation with error handling
    try:
        all_events = correlate_events(all_events)
        print("✓ Event correlation completed")
    except Exception as e:
        print(f"⚠ Warning: Event correlation failed: {e}")
        print("   Continuing without correlation...")

    print("\nFilter timeline by time range (optional)")

    from datetime import timedelta
    # Use current system time for default filtering
    reasonable_current_time = datetime.now()
    default_start = reasonable_current_time - timedelta(days=7)

    # Input validation with error handling
    try:
        start_input = input(f"Start time (YYYY-MM-DD HH:MM) or Enter for last 7 days: ").strip()
        end_input = input("End time (YYYY-MM-DD HH:MM) or Enter to skip: ").strip()
        include_unknown_input = input("Include events with UNKNOWN time? (y/n): ").strip().lower()

        # Validate include_unknown input
        if include_unknown_input not in ['y', 'n', 'yes', 'no']:
            print("⚠ Invalid input for UNKNOWN times. Defaulting to 'yes'.")
            include_unknown = True
        else:
            include_unknown = include_unknown_input.startswith('y')

    except KeyboardInterrupt:
        print("\n\n⚠ Operation cancelled by user.")
        return
    except Exception as e:
        print(f"⚠ Error during input: {e}")
        print("   Using default values...")
        start_input = ""
        end_input = ""
        include_unknown = True

    if not start_input:
        start_time = default_start
        print(f"Using default start time: {start_time.strftime('%Y-%m-%d %H:%M')}")
    else:
        start_time = parse_datetime(start_input)
        if start_time is None:
            print(f"⚠ Invalid start time format. Using default.")
            start_time = default_start

    end_time = parse_datetime(end_input) if end_input else None
    if end_input and end_time is None:
        print(f"⚠ Invalid end time format. Ignoring end time.")

    # Non-browser download analysis with error handling
    try:
        analyzer = NonBrowserDownloadAnalyzer()
        inferred_events = analyzer.analyze(all_events, start_time, end_time)
        if inferred_events:
            all_events.extend(inferred_events)
            print(f"✓ Added {len(inferred_events)} inferred non-browser download events")
        else:
            print("✓ Non-browser download analysis completed (no new events)")
    except Exception as e:
        print(f"⚠ Warning: Non-browser download analysis failed: {e}")
        print("   Continuing without inferred events...")

    display_events = list(all_events)

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

    # Option to include/exclude temp files from output
    try:
        include_temp_files_input = input("Include temporary files in timeline output? (y/n): ").strip().lower()
        if include_temp_files_input not in ['y', 'n', 'yes', 'no']:
            print("⚠ Invalid input. Defaulting to 'yes'.")
            include_temp_files = True
        else:
            include_temp_files = include_temp_files_input.startswith('y')
    except KeyboardInterrupt:
        print("\n\n⚠ Operation cancelled by user.")
        return
    except Exception as e:
        print(f"⚠ Error during input: {e}")
        print("   Defaulting to include temp files...")
        include_temp_files = True

    if not include_temp_files:
        display_events = [event for event in display_events if event.source != "Temporary Files"]
        print(f"Excluded temporary files. Events after filtering: {len(display_events)}\n")
    else:
        print("Including temporary files in output.\n")

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
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Program interrupted by user.")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        print("   Please report this error for debugging.")
        import traceback
        traceback.print_exc()
