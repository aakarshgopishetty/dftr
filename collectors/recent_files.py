import os
import logging
from datetime import datetime
from typing import List

from core.event import Event, EventType, ConfidenceLevel

class RecentFilesCollector:

    def __init__(self):
        self.source = "Recent Files (.lnk)"
    
    def collect(self) -> List[Event]:
        events = []

        recent_folder = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")

        if not os.path.exists(recent_folder):
            return events
        for filename in os.listdir(recent_folder):
            if not filename.lower().endswith(".lnk"):
                continue

            shortcut_path = os.path.join(recent_folder, filename)
            try:
                last_modified = datetime.fromtimestamp(
                    os.path.getmtime(shortcut_path)
                )
                event = Event(
                    time_start=None,
                    time_end=last_modified,
                    event_type=EventType.FILE_REFERENCE,
                    subject="User",
                    object=filename,
                    description=f"Recent file reference: {filename}",
                    source=self.source,
                    confidence=ConfidenceLevel.LOW
                )

                events.append(event)
            except Exception as e:
                logging.warning(
                    f"Failed to process shortcut {filename}: {e}"
                )

        return events
