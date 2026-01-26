import os
import logging
from datetime import datetime
from typing import List

from core.event import Event, EventType, Confidence


class TempFilesCollector:

    def __init__(self):
        self.source = "Temporary Files"

    def collect(self) -> List[Event]:
        events = []

        # Common temporary directories to scan
        temp_dirs = [
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%TMP%"),
            os.path.join(os.path.expandvars(r"%WINDIR%"), "Temp"),
            os.path.join(os.path.expandvars(r"%SYSTEMROOT%"), "Temp")
        ]

        for temp_dir in temp_dirs:
            if not os.path.exists(temp_dir):
                continue

            try:
                for root, dirs, files in os.walk(temp_dir):
                    # Skip subdirectories that are likely not user-relevant
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d.lower() not in ['cache', 'logs']]

                    for filename in files:
                        file_path = os.path.join(root, filename)

                        try:
                            # Get file metadata
                            stat_info = os.stat(file_path)
                            last_modified = datetime.fromtimestamp(stat_info.st_mtime)
                            file_size = stat_info.st_size

                            # Create event for temporary file
                            event = Event(
                                time_start=None,
                                time_end=last_modified,
                                event_type=EventType.FILE_REFERENCE,
                                subject="System/User",
                                object=file_path,
                                description=f"Temporary file: {filename} ({file_size} bytes)",
                                source=self.source,
                                confidence=Confidence.MEDIUM
                            )

                            events.append(event)

                        except (OSError, PermissionError) as e:
                            # Skip files we can't access
                            logging.debug(f"Cannot access temp file {file_path}: {e}")
                            continue
                        except Exception as e:
                            logging.warning(f"Error processing temp file {filename}: {e}")
                            continue

            except (OSError, PermissionError) as e:
                logging.debug(f"Cannot access temp directory {temp_dir}: {e}")
                continue
            except Exception as e:
                logging.warning(f"Error scanning temp directory {temp_dir}: {e}")
                continue

        return events
