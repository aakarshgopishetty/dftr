import logging
import winreg
from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, Confidence


def filetime_to_datetime(filetime):
    return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)


def rot13_decode(s):
    result = []
    for char in s:
        if 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        elif 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)


class UserAssistCollector:
    def __init__(self):
        self.source = "UserAssist Registry"

    def collect(self) -> List[Event]:
        events = []

        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as userassist_key:
                value_index = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(userassist_key, value_index)
                        value_index += 1

                        if value_type != winreg.REG_BINARY or not isinstance(value_data, bytes) or len(value_data) < 16:
                            continue

                        if len(value_data) >= 16:
                            execution_count = int.from_bytes(value_data[4:8], byteorder='little')
                            last_execution_filetime = int.from_bytes(value_data[8:16], byteorder='little')

                            if last_execution_filetime > 0:
                                last_execution_time = filetime_to_datetime(last_execution_filetime)
                                decoded_name = rot13_decode(value_name)

                                event = Event(
                                    time_start=None,
                                    time_end=last_execution_time,
                                    event_type=EventType.PROGRAM_EXECUTION,
                                    subject="User",
                                    object=decoded_name,
                                    description=f"Program executed {execution_count} times, last at {last_execution_time}",
                                    source=self.source,
                                    confidence=Confidence.HIGH
                                )
                                events.append(event)

                    except OSError:
                        break

                subkey_index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(userassist_key, subkey_index)
                        subkey_index += 1

                        subkey_path = f"{key_path}\\{subkey_name}"
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey_path) as subkey:
                            value_index = 0
                            while True:
                                try:
                                    value_name, value_data, value_type = winreg.EnumValue(subkey, value_index)
                                    value_index += 1

                                    if value_name.lower() in ['version', 'count']:
                                        continue

                                    if value_type != winreg.REG_BINARY or not isinstance(value_data, bytes) or len(value_data) < 16:
                                        continue

                                    execution_count = int.from_bytes(value_data[4:8], byteorder='little')
                                    last_execution_filetime = int.from_bytes(value_data[8:16], byteorder='little')

                                    if last_execution_filetime == 0:
                                        continue

                                    last_execution_time = filetime_to_datetime(last_execution_filetime)

                                    decoded_name = rot13_decode(value_name)

                                    event = Event(
                                        time_start=None,
                                        time_end=last_execution_time,
                                        event_type=EventType.PROGRAM_EXECUTION,
                                        subject="User",
                                        object=decoded_name,
                                        description=f"Program executed {execution_count} times, last at {last_execution_time}",
                                        source=self.source,
                                        confidence=Confidence.HIGH
                                    )

                                    events.append(event)

                                except OSError:
                                    break

                    except OSError:
                        break

            if events:
                logging.info(f"Collected {len(events)} UserAssist events")
            return events

        except Exception as e:
            logging.error(f"Failed to collect UserAssist artifacts: {e}")
            return []
