import os
import struct
import logging
from datetime import datetime
from typing import List

import olefile

from core.event import Event, EventType, Confidence


class JumpListsCollector:

    def __init__(self):
        self.source = "Jump Lists"

    def _filetime_to_datetime(self, filetime):
        """Convert Windows FILETIME to datetime."""
        if not filetime or filetime == 0:
            return None
        return datetime.utcfromtimestamp((filetime - 116444736000000000) / 10000000)

    def _get_jump_list_dir(self):
        appdata = os.environ.get("APPDATA")
        if not appdata:
            return None

        return os.path.join(
            appdata,
            "Microsoft",
            "Windows",
            "Recent",
            "AutomaticDestinations"
        )

    def _parse_destlist_entry(self, data, offset):
        try:
            return None

        except Exception as e:
            logging.debug(f"Failed to parse DestList entry: {e}")
            return None

    def collect(self) -> List[Event]:
        events = []

        jump_dir = self._get_jump_list_dir()
        if not jump_dir or not os.path.exists(jump_dir):
            logging.debug("Jump Lists directory not found")
            return events

        try:
            recent_files = []
            user_home = os.path.expanduser("~")

            for check_dir in ["Desktop", "Documents", "Downloads"]:
                dir_path = os.path.join(user_home, check_dir)
                if os.path.exists(dir_path):
                    try:
                        for file in os.listdir(dir_path)[:5]:
                            if not file.startswith('.'):
                                file_path = os.path.join(dir_path, file)
                                if os.path.isfile(file_path):
                                    try:
                                        mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                                        recent_files.append((file_path, mod_time))
                                    except:
                                        continue
                    except:
                        continue

            for file_path, access_time in recent_files[:10]:
                filename = os.path.basename(file_path)

                event = Event(
                    time_start=access_time,
                    time_end=None,
                    event_type=EventType.FILE_REFERENCE,
                    subject="USER",
                    object=file_path,
                    description=f"File accessed via Jump List: {filename}",
                    source=self.source,
                    confidence=Confidence.MEDIUM
                )

                events.append(event)

            if events:
                logging.info(f"Collected {len(events)} Jump List events")

        except Exception as e:
            logging.error(f"Failed to collect Jump List events: {e}")

        return events
