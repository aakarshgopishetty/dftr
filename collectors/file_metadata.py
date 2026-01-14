import os
import logging
from datetime import datetime
from typing import List

from core.event import Event, EventType, Confidence


class FileMetadataCollector:
    def __init__(self):
        self.source = "NTFS Metadata"

    def collect(self) -> List[Event]:
        events = []

        try:
            user_home = os.path.expanduser("~")

            target_folders = ["Desktop", "Documents", "Downloads", "Pictures"]

            for folder_name in target_folders:
                folder_path = os.path.join(user_home, folder_name)

                if not os.path.exists(folder_path):
                    continue

                for root, dirs, files in os.walk(folder_path):
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d.lower() not in ['temp', 'cache']]

                    for file_name in files:
                        if file_name.lower().endswith(('.tmp', '.log', '.dat')):
                            continue

                        file_path = os.path.join(root, file_name)

                        try:
                            stat = os.stat(file_path)

                            created = datetime.fromtimestamp(stat.st_ctime)
                            modified = datetime.fromtimestamp(stat.st_mtime)
                            accessed = datetime.fromtimestamp(stat.st_atime)

                            event_time = max(created, modified, accessed)
                            file_size = stat.st_size

                            event = Event(
                                time_start=event_time,
                                time_end=None,
                                event_type=EventType.FILE_REFERENCE,
                                subject="USER",
                                object=file_path,
                                description=f"File activity detected ({file_size} bytes) - Created: {created.strftime('%Y-%m-%d %H:%M:%S')}, Modified: {modified.strftime('%Y-%m-%d %H:%M:%S')}, Accessed: {accessed.strftime('%Y-%m-%d %H:%M:%S')}",
                                source=self.source,
                                confidence=Confidence.MEDIUM
                            )

                            events.append(event)

                        except (OSError, PermissionError) as e:
                            logging.debug(f"Cannot access file {file_path}: {e}")
                            continue
                        except Exception as e:
                            logging.debug(f"Error processing file {file_path}: {e}")
                            continue

            if events:
                logging.info(f"Collected {len(events)} file metadata events from user directories")

        except Exception as e:
            logging.error(f"Failed to collect file metadata: {e}")

        return events
