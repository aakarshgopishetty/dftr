from datetime import datetime

from collectors.recent_files import RecentFilesCollector
from collectors.registry_mru import RegistryMRUCollector
from collectors.userassist import UserAssistCollector
from collectors.prefetch import PrefetchCollector

from core.correlator import correlate_events
from core.event import EventType


def parse_datetime(value: str):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M")
    except ValueError:
        return None


def main():
    events = []

    print("Digital Forensic Timeline Reconstructor")
    print("Collecting from: Recent Files, Registry MRU, UserAssist, Prefetch")
    print("Features: Cross-artifact correlation, confidence scoring, user/system activity detection")

    recent_collector = RecentFilesCollector()
    mru_collector = RegistryMRUCollector()
    userassist_collector = UserAssistCollector()
    prefetch_collector = PrefetchCollector()

    events.extend(recent_collector.collect())
    events.extend(mru_collector.collect())
    events.extend(userassist_collector.collect())
    events.extend(prefetch_collector.collect())

    print(f"\nCollected {len(events)} total events")

    events = correlate_events(events)

    print("\nFilter timeline by time range (optional)")

    # Default to last 7 days if no input
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

    for event in events:
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

    events = filtered_events

    print("\nApplied time filter:")
    print(f"  Start: {start_time if start_time else 'Not set'}")
    print(f"  End:   {end_time if end_time else 'Not set'}")
    print(f"  Include UNKNOWN times: {include_unknown}")
    print(f"  Events after filtering: {len(events)}\n")

    print("Timeline events shown using best-known timestamps (sort_time):\n")

    events.sort(key=lambda e: e.sort_time or datetime.min, reverse=True)

    # Show first 10 events as sample
    for event in events[:10]:
        print(event)

    if len(events) > 10:
        print(f"\n... and {len(events) - 10} more events")


if __name__ == "__main__":
    main()
