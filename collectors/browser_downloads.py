import os
import sqlite3
import shutil
import tempfile
import logging
from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, Confidence


class BrowserDownloadsCollector:
    def __init__(self):
        self.source = "Browser Downloads"

    def _chrome_time_to_datetime(self, chrome_time):
        if chrome_time is None or chrome_time == 0:
            return None
        base_time = datetime(1601, 1, 1)
        return base_time + timedelta(microseconds=chrome_time)

    def _get_browser_paths(self):
        local_appdata = os.environ.get('LOCALAPPDATA')
        if not local_appdata:
            return []

        return [
            ("Chrome", os.path.join(local_appdata, 'Google', 'Chrome', 'User Data', 'Default', 'History')),
            ("Edge", os.path.join(local_appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'History')),
            ("Brave", os.path.join(local_appdata, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History')),
        ]

    def collect(self) -> List[Event]:
        events = []

        for browser_name, history_path in self._get_browser_paths():
            if not os.path.exists(history_path):
                continue

            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    shutil.copy2(history_path, tmp.name)
                    db_path = tmp.name

                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT
                        target_path,
                        start_time,
                        end_time,
                        received_bytes,
                        total_bytes,
                        url,
                        state
                    FROM downloads
                    ORDER BY end_time DESC
                """)

                browser_events = 0
                for row in cursor.fetchall():
                    target_path, start, end, recv, total, url, state = row

                    if state != 1 or not target_path or not end:
                        continue

                    start_dt = self._chrome_time_to_datetime(start)
                    end_dt = self._chrome_time_to_datetime(end)
                    event_time = end_dt or start_dt

                    if not event_time:
                        continue

                    filename = os.path.basename(target_path)

                    event = Event(
                        time_start=start_dt,
                        time_end=end_dt,
                        event_type=EventType.FILE_REFERENCE,
                        subject="USER",
                        object=target_path,
                        description=f"Downloaded via {browser_name}: '{filename}' from {url}",
                        source=f"{browser_name} Downloads",
                        confidence=Confidence.HIGH
                    )

                    events.append(event)
                    browser_events += 1

                conn.close()
                os.remove(db_path)

                if browser_events > 0:
                    logging.info(f"{browser_name}: collected {browser_events} download events")

            except Exception as e:
                logging.debug(f"{browser_name} download collection failed: {e}")

        return events
