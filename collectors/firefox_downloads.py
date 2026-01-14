import os
import sqlite3
import shutil
import tempfile
import logging
from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, Confidence


class FirefoxDownloadsCollector:
    def __init__(self):
        self.source = "Firefox Downloads"

    def _prtime_to_datetime(self, prtime):
        if prtime is None or prtime == 0:
            return None
        base_time = datetime(1970, 1, 1)
        return base_time + timedelta(microseconds=prtime)

    def _get_firefox_profile_path(self):
        appdata = os.environ.get('APPDATA')
        if not appdata:
            return None

        firefox_profiles = os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')

        if not os.path.exists(firefox_profiles):
            return None

        for profile_dir in os.listdir(firefox_profiles):
            profile_path = os.path.join(firefox_profiles, profile_dir)
            if os.path.isdir(profile_path) and ('default' in profile_dir.lower()):
                places_db = os.path.join(profile_path, 'places.sqlite')
                if os.path.exists(places_db):
                    return places_db

        return None

    def collect(self) -> List[Event]:
        events = []

        places_path = self._get_firefox_profile_path()
        if not places_path:
            logging.debug("Firefox places.sqlite not found")
            return events

        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                shutil.copy2(places_path, tmp.name)
                db_path = tmp.name

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    SELECT
                        source,
                        target,
                        startTime,
                        endTime,
                        state
                    FROM moz_downloads
                    ORDER BY endTime DESC
                """)

                for row in cursor.fetchall():
                    source_url, target_path, start_time, end_time, state = row

                    if state != 1:
                        continue

                    if not target_path or not end_time:
                        continue

                    start_dt = self._prtime_to_datetime(start_time)
                    end_dt = self._prtime_to_datetime(end_time)
                    event_time = end_dt or start_dt

                    if not event_time:
                        continue

                    filename = os.path.basename(target_path) if target_path else "Unknown"

                    event = Event(
                        time_start=start_dt,
                        time_end=end_dt,
                        event_type=EventType.FILE_REFERENCE,
                        subject="USER",
                        object=target_path,
                        description=f"Downloaded via Firefox: '{filename}' from {source_url}",
                        source="Firefox Downloads",
                        confidence=Confidence.HIGH
                    )

                    events.append(event)

            except sqlite3.OperationalError:
                logging.debug("moz_downloads table not found, trying moz_annos approach")
                logging.debug("Firefox newer version download detection not yet implemented")

            conn.close()
            os.remove(db_path)

            if events:
                logging.info(f"Firefox: collected {len(events)} download events")

        except Exception as e:
            logging.error(f"Failed to collect Firefox downloads: {e}")

        return events
