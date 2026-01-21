import os
import sqlite3
import shutil
import tempfile
import logging
from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, Confidence


class BrowserHistoryCollector:
    """
    Forensic collector for browser history (visited URLs).

    Extracts URL visit history from browser databases to show:
    - Websites visited by the user
    - Visit timestamps and frequencies
    - Page titles and metadata

    This provides evidence of user browsing activity and helps
    correlate with file downloads and other user actions.

    Non-admin access: Reads user profile browser data.
    High forensic value: Shows intentional user browsing behavior.
    """

    def __init__(self):
        self.source = "Browser History"

    def _chrome_time_to_datetime(self, chrome_time):
        """Convert Chrome timestamp (microseconds since 1601-01-01) to datetime."""
        if chrome_time is None or chrome_time == 0:
            return None
        # Chrome uses microseconds since 1601-01-01 UTC
        base_time = datetime(1601, 1, 1)
        return base_time + timedelta(microseconds=chrome_time)

    def _firefox_time_to_datetime(self, firefox_time):
        """Convert Firefox timestamp (microseconds since 1970-01-01) to datetime."""
        if firefox_time is None or firefox_time == 0:
            return None
        # Firefox uses microseconds since 1970-01-01 UTC
        base_time = datetime(1970, 1, 1)
        return base_time + timedelta(microseconds=firefox_time)

    def _get_chromium_browsers(self):
        """Get paths to supported Chromium-based browser History databases."""
        local_appdata = os.environ.get('LOCALAPPDATA')
        appdata = os.environ.get('APPDATA')
        if not local_appdata or not appdata:
            return []

        browsers = []

        # Check each browser and all profiles
        browser_configs = [
            ("Chrome", os.path.join(local_appdata, 'Google', 'Chrome', 'User Data')),
            ("Edge", os.path.join(local_appdata, 'Microsoft', 'Edge', 'User Data')),
            ("Brave", os.path.join(local_appdata, 'BraveSoftware', 'Brave-Browser', 'User Data')),
        ]

        for browser_name, base_path in browser_configs:
            if not os.path.exists(base_path):
                continue

            # Check all profiles (Default, Profile 1, Profile 2, etc.)
            for item in os.listdir(base_path):
                if item == "Default" or item.startswith("Profile"):
                    profile_path = os.path.join(base_path, item)
                    if os.path.isdir(profile_path):
                        history_path = os.path.join(profile_path, 'History')
                        if os.path.exists(history_path):
                            browsers.append((f"{browser_name} ({item})", history_path))

        # Opera (different structure)
        opera_history = os.path.join(appdata, 'Opera Software', 'Opera Stable', 'History')
        if os.path.exists(opera_history):
            browsers.append(("Opera", opera_history))

        return browsers

    def _get_firefox_profiles(self):
        """Get paths to Firefox profile databases."""
        appdata = os.environ.get('APPDATA')
        if not appdata:
            return []

        firefox_profiles = os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')
        if not os.path.exists(firefox_profiles):
            return []

        profiles = []
        for profile_dir in os.listdir(firefox_profiles):
            profile_path = os.path.join(firefox_profiles, profile_dir)
            if os.path.isdir(profile_path) and ('default' in profile_dir.lower()):
                places_db = os.path.join(profile_path, 'places.sqlite')
                if os.path.exists(places_db):
                    profiles.append((f"Firefox ({profile_dir})", places_db))

        return profiles

    def collect(self) -> List[Event]:
        """
        Collect browser history from all supported browsers.

        Returns:
            List[Event]: Browser history events with visit data
        """
        events = []

        # Collect from Chromium-based browsers
        for browser_name, history_path in self._get_chromium_browsers():
            if not os.path.exists(history_path):
                continue

            try:
                # Copy database (forensic-safe)
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    shutil.copy2(history_path, tmp.name)
                    db_path = tmp.name

                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                # Query URLs table for visit history
                cursor.execute("""
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                    ORDER BY last_visit_time DESC
                """)

                browser_events = 0
                for url, title, visit_count, last_visit_time in cursor.fetchall():
                    visit_dt = self._chrome_time_to_datetime(last_visit_time)
                    if not visit_dt:
                        continue

                    # Create event for browser visit
                    event = Event(
                        time_start=visit_dt,
                        time_end=None,
                        event_type=EventType.USER_INTENT,  # Intentional browsing activity
                        subject="USER",
                        object=url,
                        description=f"Browsed '{title or 'Untitled'}' - {visit_count} visits",
                        source=f"{browser_name} History",
                        confidence=Confidence.HIGH  # High confidence - direct browser evidence
                    )

                    events.append(event)
                    browser_events += 1

                conn.close()
                os.remove(db_path)

                if browser_events > 0:
                    logging.info(f"{browser_name}: collected {browser_events} history events")

            except Exception as e:
                logging.debug(f"{browser_name} history collection failed: {e}")

        # Collect from Firefox
        for profile_name, places_path in self._get_firefox_profiles():
            try:
                # Copy database (forensic-safe)
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    shutil.copy2(places_path, tmp.name)
                    db_path = tmp.name

                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                # Query Firefox history
                cursor.execute("""
                    SELECT p.url, p.title, h.visit_date
                    FROM moz_places p
                    JOIN moz_historyvisits h ON p.id = h.place_id
                    ORDER BY h.visit_date DESC
                """)

                firefox_events = 0
                for url, title, visit_date in cursor.fetchall():
                    visit_dt = self._firefox_time_to_datetime(visit_date)
                    if not visit_dt:
                        continue

                    # Create event for Firefox visit
                    event = Event(
                        time_start=visit_dt,
                        time_end=None,
                        event_type=EventType.USER_INTENT,  # Intentional browsing activity
                        subject="USER",
                        object=url,
                        description=f"Browsed '{title or 'Untitled'}' (Firefox)",
                        source=f"{profile_name} History",
                        confidence=Confidence.HIGH  # High confidence - direct browser evidence
                    )

                    events.append(event)
                    firefox_events += 1

                conn.close()
                os.remove(db_path)

                if firefox_events > 0:
                    logging.info(f"{profile_name}: collected {firefox_events} history events")

            except Exception as e:
                logging.debug(f"{profile_name} history collection failed: {e}")

        return events
