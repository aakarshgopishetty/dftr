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

    def _categorize_application(self, app_name):
        """Categorize application based on executable name."""
        app_lower = app_name.lower()

        # Browser applications
        browsers = ['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'iexplore.exe']
        if any(browser in app_lower for browser in browsers):
            return "Browser"

        # Messaging applications
        messaging = ['whatsapp.exe', 'telegram.exe', 'skype.exe', 'teams.exe', 'discord.exe', 'slack.exe', 'zoom.exe']
        if any(msg in app_lower for msg in messaging):
            return "Messaging"

        # Cloud storage applications
        cloud = ['onedrive.exe', 'dropbox.exe', 'googledrive.exe', 'icloud.exe']
        if any(cld in app_lower for cld in cloud):
            return "Cloud"

        # Office applications
        office = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'wordpad.exe', 'notepad.exe']
        if any(off in app_lower for off in office):
            return "Office"

        # Media applications
        media = ['vlc.exe', 'wmplayer.exe', 'photos.exe', 'mspaint.exe', 'snippingtool.exe']
        if any(med in app_lower for med in media):
            return "Media"

        # System applications
        system = ['explorer.exe', 'cmd.exe', 'powershell.exe', 'taskmgr.exe', 'control.exe']
        if any(sys in app_lower for sys in system):
            return "System"

        # Development tools
        dev = ['code.exe', 'devenv.exe', 'python.exe', 'java.exe', 'node.exe']
        if any(d in app_lower for d in dev):
            return "Development"

        return "Other"

    def _generate_smart_description(self, app_name, category, execution_count, last_execution_time):
        """Generate context-aware description based on application category."""
        base_desc = f"{app_name} executed {execution_count} times, last at {last_execution_time}"

        category_descriptions = {
            "Browser": f"Web browser {app_name} accessed (possible web activity or downloads)",
            "Messaging": f"Messaging application {app_name} used (possible media/file reception)",
            "Cloud": f"Cloud storage client {app_name} active (possible file synchronization)",
            "Office": f"Office application {app_name} launched (document creation/editing)",
            "Media": f"Media application {app_name} opened (image/video/audio processing)",
            "System": f"System utility {app_name} executed (file management or system tasks)",
            "Development": f"Development tool {app_name} used (code editing or compilation)",
            "Other": f"Application {app_name} executed"
        }

        context_desc = category_descriptions.get(category, f"Application {app_name} executed")

        if execution_count > 1:
            context_desc += f" - {execution_count} total executions"
        else:
            context_desc += " - First execution in tracking period"

        return context_desc

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

                                category = self._categorize_application(decoded_name)
                                smart_description = self._generate_smart_description(
                                    decoded_name, category, execution_count, last_execution_time
                                )

                                event = Event(
                                    time_start=None,
                                    time_end=last_execution_time,
                                    event_type=EventType.PROGRAM_EXECUTION,
                                    subject="User",
                                    object=decoded_name,
                                    description=smart_description,
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

                                    category = self._categorize_application(decoded_name)
                                    smart_description = self._generate_smart_description(
                                        decoded_name, category, execution_count, last_execution_time
                                    )

                                    event = Event(
                                        time_start=None,
                                        time_end=last_execution_time,
                                        event_type=EventType.PROGRAM_EXECUTION,
                                        subject="User",
                                        object=decoded_name,
                                        description=smart_description,
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
