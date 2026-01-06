import logging
import winreg
from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, ConfidenceLevel


def filetime_to_datetime(filetime):
    return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)


class RegistryMRUCollector:
    def __init__(self):
        self.source = "Registry RunMRU"

    def collect(self) -> List[Event]:
        events = []

        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                _, _, last_write_time = winreg.QueryInfoKey(key)
                key_timestamp = filetime_to_datetime(last_write_time)

                index = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, index)
                        index += 1

                        if value_name == "MRUList":
                            continue

                        event = Event(
                            time_start=None,
                            time_end=key_timestamp,
                            event_type=EventType.USER_INTENT,
                            subject="User",
                            object=value_data,
                            description=f"Command present in RunMRU (exact execution time unknown): {value_data}",
                            source=self.source,
                            confidence=ConfidenceLevel.MEDIUM
                        )

                        events.append(event)

                    except OSError:
                        break


            return events

        except Exception as e:
            logging.error(f"Failed to collect RunMRU artifacts: {e}")
            return []
