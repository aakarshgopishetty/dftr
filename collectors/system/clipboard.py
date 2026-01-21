import pyperclip
import hashlib
from datetime import datetime
from typing import List, Optional

from core.event import Event, EventType, Confidence


class ClipboardCollector:
    """
    Collects current clipboard content (non-admin).
    Note: This captures live clipboard data only, not historical clipboard logs.
    """

    def __init__(self):
        self.source = "Clipboard"

    def collect(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> List[Event]:
        events = []

        try:
            content = pyperclip.paste()

            if not content or not isinstance(content, str):
                return events

            content = content.strip()
            if not content:
                return events

            content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            timestamp = datetime.now()

            # Time filter (optional)
            if start_time and timestamp < start_time:
                return events
            if end_time and timestamp > end_time:
                return events

            description = (
                f"Clipboard text captured (length={len(content)}, "
                f"sha256={content_hash[:12]}...)"
            )

            event = Event(
                time_start=timestamp,
                event_type=EventType.CLIPBOARD_ACTIVITY,
                subject="User",
                object="Clipboard",
                description=description,
                source=self.source,
                confidence=Confidence.MEDIUM
            )

            events.append(event)

        except Exception as e:
            # Silent fail – clipboard access is best-effort
            pass

        return events
