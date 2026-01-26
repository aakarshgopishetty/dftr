"""
Script to clean existing forensic_timeline.csv by removing future events
"""

import csv
from datetime import datetime
from core.event import Event, EventType, Confidence
from core.config import TIME_VALIDATION_CONFIG

def clean_csv_file():
    """Clean the CSV file by removing future events"""
    input_file = "forensic_timeline.csv"
    output_file = "forensic_timeline_cleaned.csv"

    valid_events = []
    future_events_count = 0

    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)

            for row in reader:
                timestamp_str = row.get('Timestamp', '')
                if timestamp_str and timestamp_str != 'UNKNOWN':
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str)

                        temp_event = Event(time_start=timestamp)
                        if temp_event.is_temporally_valid():
                            valid_events.append(row)
                        else:
                            future_events_count += 1
                            print(f"Removed future event: {timestamp_str} - {row.get('Description', '')[:50]}...")
                    except ValueError:
                        valid_events.append(row)
                        print(f"Kept event with unparseable timestamp: {timestamp_str}")
                else:
                    valid_events.append(row)

        if valid_events:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = valid_events[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(valid_events)

        print(f"CSV cleaning completed:")
        print(f"  - Original events: {len(valid_events) + future_events_count}")
        print(f"  - Valid events: {len(valid_events)}")
        print(f"  - Future events removed: {future_events_count}")
        print(f"  - Cleaned file saved as: {output_file}")

        import os
        if os.path.exists(output_file):
            os.replace(output_file, input_file)
            print(f"  - Original file replaced with cleaned version")

    except FileNotFoundError:
        print(f"Error: {input_file} not found")
    except Exception as e:
        print(f"Error cleaning CSV: {e}")

if __name__ == "__main__":
    clean_csv_file()
