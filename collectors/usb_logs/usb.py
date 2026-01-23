import winreg
from datetime import datetime, timezone
from typing import List

from core.event import Event, EventType, Confidence


class USBCollector:
    REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

    def _is_removable(self, name: str) -> bool:
        name = name.lower()
        return ":" in name or "usb" in name or "removable" in name

    def _get_last_write_time(self, key) -> datetime:
        ts = winreg.QueryInfoKey(key)[2]
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    def collect(self) -> List[Event]:
        events: List[Event] = []

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_PATH) as root:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, index)
                        index += 1
                        if not self._is_removable(subkey_name):
                            continue
                        with winreg.OpenKey(root, subkey_name) as subkey:
                            last_write = self._get_last_write_time(subkey)
                            events.append(
                                Event(
                                    time_end=last_write,
                                    event_type=EventType.USB_DEVICE_MOUNT,
                                    subject="User",
                                    object=subkey_name,
                                    description="Removable storage device mounted by user",
                                    source="Registry: MountPoints2 (HKCU)",
                                    confidence=Confidence.MEDIUM,
                                )
                            )
                    except OSError:
                        break
        except FileNotFoundError:
            pass

        return events
