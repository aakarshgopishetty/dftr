import os
import sqlite3
import shutil
import tempfile
import logging
import time
from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, Confidence


class BrowserHistoryCollector:

    def _is_relevant_url(self, url):
        """Filter out browser internal and irrelevant URLs."""
        if not url:
            return False

        url_lower = url.lower()

        # Filter out browser internal URLs
        irrelevant_prefixes = [
            'chrome://', 'edge://', 'about:', 'data:', 'blob:', 'file://',
            'chrome-extension://', 'moz-extension://', 'opera://'
        ]

        for prefix in irrelevant_prefixes:
            if url_lower.startswith(prefix):
                return False

        # Filter out common tracking/analytics domains that don't provide user intent
        tracking_domains = [
            'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
            'facebook.com/tr', 'connect.facebook.net', 'googlesyndication.com'
        ]

        for domain in tracking_domains:
            if domain in url_lower:
                return False

        return True

    def __init__(self):
        self.source = "Browser History"

    def _chrome_time_to_datetime(self, chrome_time):
        """Convert Chrome timestamp to datetime with multiple format support."""
        if chrome_time is None or chrome_time == 0:
            return None

        try:
            chrome_time = float(chrome_time)

            # Try different timestamp formats in order of likelihood

            # 1. Unix timestamp in milliseconds (most common for some Chrome versions)
            if 1000000000000 < chrome_time < 2000000000000:  # 2001-2033 in milliseconds
                # Browser timestamps are typically in UTC, convert to system local time
                utc_dt = datetime.utcfromtimestamp(chrome_time / 1000.0)
                # Convert UTC to local time using proper timezone handling
                is_dst = time.daylight and time.localtime().tm_isdst
                local_offset = time.altzone if is_dst else time.timezone
                return utc_dt + timedelta(seconds=-local_offset)

            # 2. Unix timestamp in seconds (rare but possible)
            elif 1577836800 < chrome_time < 2147483647:  # 2020-2038 in seconds
                utc_dt = datetime.utcfromtimestamp(chrome_time)
                is_dst = time.daylight and time.localtime().tm_isdst
                local_offset = time.altzone if is_dst else time.timezone
                return utc_dt + timedelta(seconds=-local_offset)

            # 3. Chrome's standard format: microseconds since 1601-01-01
            elif chrome_time > 10000000000000:  # Very large numbers
                seconds_since_1601 = chrome_time / 1000000.0
                base_time = datetime(1601, 1, 1)
                result = base_time + timedelta(seconds=seconds_since_1601)

                # Validate result is reasonable (not in far future)
                if result < datetime.now() + timedelta(days=1):
                    return result

            # 4. Windows FILETIME: 100-nanosecond intervals since 1601-01-01
            elif chrome_time > 116444736000000000:  # FILETIME starts around year 2000
                seconds_since_1601 = chrome_time / 10000000.0
                base_time = datetime(1601, 1, 1)
                result = base_time + timedelta(seconds=seconds_since_1601)

                if result < datetime.now() + timedelta(days=1):
                    return result

            return None
        except (ValueError, OverflowError, OSError):
            return None

    def _firefox_time_to_datetime(self, firefox_time):
        """Convert Firefox timestamp (microseconds since 1970-01-01) to datetime."""
        if firefox_time is None or firefox_time == 0:
            return None
        base_time = datetime(1970, 1, 1)
        return base_time + timedelta(microseconds=firefox_time)

    def _get_chromium_browsers(self):
        """Get paths to supported Chromium-based browser History databases."""
        local_appdata = os.environ.get('LOCALAPPDATA')
        appdata = os.environ.get('APPDATA')
        if not local_appdata or not appdata:
            return []

        browsers = []

        browser_configs = [
            ("Chrome", os.path.join(local_appdata, 'Google', 'Chrome', 'User Data')),
            ("Edge", os.path.join(local_appdata, 'Microsoft', 'Edge', 'User Data')),
            ("Brave", os.path.join(local_appdata, 'BraveSoftware', 'Brave-Browser', 'User Data')),
        ]

        for browser_name, base_path in browser_configs:
            if not os.path.exists(base_path):
                continue

            for item in os.listdir(base_path):
                if item == "Default" or item.startswith("Profile"):
                    profile_path = os.path.join(base_path, item)
                    if os.path.isdir(profile_path):
                        history_path = os.path.join(profile_path, 'History')
                        if os.path.exists(history_path):
                            browsers.append((f"{browser_name} ({item})", history_path))

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
        events = []

        for browser_name, history_path in self._get_chromium_browsers():
            if not os.path.exists(history_path):
                continue

            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    shutil.copy2(history_path, tmp.name)
                    db_path = tmp.name

                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                    ORDER BY last_visit_time DESC
                """)

                browser_events = 0
                for url, title, visit_count, last_visit_time in cursor.fetchall():
                    if not self._is_relevant_url(url):
                        continue

                    # Debug: log the raw timestamp for YouTube URLs
                    if 'youtube.com' in url.lower():
                        logging.debug(f"YouTube timestamp: {last_visit_time} (type: {type(last_visit_time)})")

                    visit_dt = self._chrome_time_to_datetime(last_visit_time)
                    if not visit_dt:
                        logging.debug(f"Invalid timestamp for {url}: {last_visit_time}")
                        continue

                    # Debug: log the converted time for YouTube URLs
                    if 'youtube.com' in url.lower():
                        logging.debug(f"YouTube converted time: {visit_dt}")
                        logging.debug(f"YouTube raw timestamp value: {last_visit_time}")

                    event = Event(
                        time_start=visit_dt,
                        time_end=None,
                        event_type=EventType.USER_INTENT,
                        subject="USER",
                        object=url,
                        description=f"Browsed '{title or 'Untitled'}' - {visit_count} visits",
                        source=f"{browser_name} History",
                        confidence=Confidence.HIGH
                    )

                    events.append(event)
                    browser_events += 1

                conn.close()
                os.remove(db_path)

                if browser_events > 0:
                    logging.info(f"{browser_name}: collected {browser_events} history events")

            except Exception as e:
                logging.debug(f"{browser_name} history collection failed: {e}")

        for profile_name, places_path in self._get_firefox_profiles():
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    shutil.copy2(places_path, tmp.name)
                    db_path = tmp.name

                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT p.url, p.title, h.visit_date
                    FROM moz_places p
                    JOIN moz_historyvisits h ON p.id = h.place_id
                    ORDER BY h.visit_date DESC
                """)

                firefox_events = 0
                for url, title, visit_date in cursor.fetchall():
                    if not self._is_relevant_url(url):
                        continue

                    visit_dt = self._firefox_time_to_datetime(visit_date)
                    if not visit_dt:
                        continue

                    event = Event(
                        time_start=visit_dt,
                        time_end=None,
                        event_type=EventType.USER_INTENT,
                        subject="USER",
                        object=url,
                        description=f"Browsed '{title or 'Untitled'}' (Firefox)",
                        source=f"{profile_name} History",
                        confidence=Confidence.HIGH
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
