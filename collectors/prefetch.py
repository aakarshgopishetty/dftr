import os
import struct
import logging
from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, ConfidenceLevel

class PrefetchCollector:
    def __init__(self):
        self.source = "Windows Prefetch"

    def collect(self) -> List[Event]:
        events = []

        try:
            prefetch_dir = os.path.expandvars(r"%SystemRoot%\Prefetch")

            if not os.path.exists(prefetch_dir):
                logging.warning(f"Prefetch directory not found: {prefetch_dir}")
                return events

            for filename in os.listdir(prefetch_dir):
                if not filename.lower().endswith('.pf'):
                    continue

                prefetch_path = os.path.join(prefetch_dir, filename)

                try:
                    with open(prefetch_path, 'rb') as f:
                        # Read prefetch file header
                        header = f.read(8)
                        if len(header) < 8:
                            continue

                        # Check for prefetch file signature (0x53434341)
                        signature = struct.unpack('<I', header[4:8])[0]
                        if signature != 0x41434353:  # "SCCA" in little endian
                            continue

                        # Read version (offset 0)
                        f.seek(0)
                        version = struct.unpack('<I', f.read(4))[0]

                        if version == 17:  # Windows XP/2003
                            # Parse XP format
                            f.seek(0x78)  # Last run time offset
                            last_run_filetime = struct.unpack('<Q', f.read(8))[0]
                            run_count = struct.unpack('<I', f.read(4))[0]

                        elif version == 23:  # Windows Vista/7
                            # Parse Vista/7 format
                            f.seek(0x80)  # Last run time offset
                            last_run_filetime = struct.unpack('<Q', f.read(8))[0]
                            f.seek(0x90)  # Run count offset
                            run_count = struct.unpack('<I', f.read(4))[0]

                        elif version == 26:  # Windows 8+
                            # Parse Windows 8+ format
                            f.seek(0x80)  # Last run time offset
                            last_run_filetime = struct.unpack('<Q', f.read(8))[0]
                            f.seek(0x98)  # Run count offset
                            run_count = struct.unpack('<I', f.read(4))[0]

                        else:
                            continue  # Unsupported version

                        if last_run_filetime > 0:
                            # Convert Windows FILETIME to datetime
                            last_run_time = datetime(1601, 1, 1) + timedelta(microseconds=last_run_filetime / 10)

                            # Extract program name from filename (remove .pf extension)
                            program_name = filename[:-3]  # Remove .pf

                            # Create event
                            event = Event(
                                time_start=None,
                                time_end=last_run_time,
                                event_type=EventType.PROGRAM_EXECUTION,
                                subject="User",
                                object=program_name,
                                description=f"Program executed {run_count} times, last at {last_run_time} (Prefetch)",
                                source=self.source,
                                confidence=ConfidenceLevel.HIGH  # Prefetch is strong evidence
                            )

                            events.append(event)

                except (OSError, struct.error, ValueError) as e:
                    logging.debug(f"Failed to parse prefetch file {filename}: {e}")
                    continue

            if events:
                logging.info(f"Collected {len(events)} Prefetch events")

        except PermissionError:
            logging.info("Prefetch collection skipped: Administrator privileges required to access C:\\Windows\\Prefetch")
            return []
        except Exception as e:
            logging.warning(f"Failed to collect Prefetch artifacts: {e}")
            return []

        return events
