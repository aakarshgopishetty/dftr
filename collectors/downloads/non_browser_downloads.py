from datetime import datetime, timedelta
from typing import List

from core.event import Event, EventType, Confidence


class NonBrowserDownloadAnalyzer:
    """
    Forensic analyzer for inferring non-browser file acquisitions.

    Analyzes existing events to identify files that were likely acquired
    through non-browser means (messaging apps, cloud services, etc.)
    by correlating file creation metadata with application usage.

    Non-admin analysis: Uses only existing collected events.
    Medium forensic confidence: Based on inference, not direct evidence.
    """

    def __init__(self):
        self.source = "Non-Browser Download Inference"
        self.time_window = timedelta(minutes=5)  # 5-minute correlation window

    def _is_candidate_file(self, event: Event) -> bool:
        """Check if a file event represents a potential non-browser download."""
        if event.event_type != EventType.FILE_REFERENCE:
            return False

        if event.source != "NTFS Metadata":
            return False

        file_path = event.object.lower()

        # Check for common download locations
        candidate_paths = [
            "\\downloads\\",
            "\\desktop\\"
        ]

        return any(path in file_path for path in candidate_paths)

    def _is_browser_download(self, file_path: str, browser_events: List[Event]) -> bool:
        """Check if file was already identified as a browser download."""
        for event in browser_events:
            if event.event_type in [EventType.FILE_REFERENCE] and event.source in [
                "Chrome Downloads", "Edge Downloads", "Brave Downloads", "Firefox Downloads"
            ]:
                if event.object.lower() == file_path.lower():
                    return True
        return False

    def _find_correlated_app(self, file_time: datetime, app_events: List[Event]) -> str:
        """Find messaging/cloud app that executed near file creation time."""
        for event in app_events:
            if event.event_type != EventType.PROGRAM_EXECUTION:
                continue

            # Check if it's a messaging or cloud app
            app_name = event.object.lower()
            if not any(keyword in app_name for keyword in [
                'whatsapp', 'telegram', 'skype', 'teams', 'discord', 'slack', 'zoom',
                'onedrive', 'dropbox', 'googledrive', 'icloud'
            ]):
                continue

            # Check time correlation
            app_time = event.time_end or event.time_start
            if app_time and abs(app_time - file_time) <= self.time_window:
                return event.object  # Return the app name

        return None

    def analyze(self, events: List[Event], start_time: datetime = None, end_time: datetime = None) -> List[Event]:
        """
        Analyze events to infer non-browser file acquisitions.

        Args:
            events: All collected events
            start_time: Analysis start time (optional)
            end_time: Analysis end time (optional)

        Returns:
            List of inferred file acquisition events
        """
        inferred_events = []

        # Separate events by type for efficient lookup
        file_events = [e for e in events if e.event_type == EventType.FILE_REFERENCE and e.source == "NTFS Metadata"]
        browser_download_events = [e for e in events if e.event_type == EventType.FILE_REFERENCE and
                                 e.source in ["Chrome Downloads", "Edge Downloads", "Brave Downloads", "Firefox Downloads"]]
        app_events = [e for e in events if e.event_type == EventType.PROGRAM_EXECUTION]

        # Process each candidate file
        for file_event in file_events:
            if not self._is_candidate_file(file_event):
                continue

            file_path = file_event.object
            file_time = file_event.time_start  # File creation time

            if not file_time:
                continue

            # Apply time filter if specified
            if start_time and file_time < start_time:
                continue
            if end_time and file_time > end_time:
                continue

            # Skip if already identified as browser download
            if self._is_browser_download(file_path, browser_download_events):
                continue

            # Look for correlated app execution
            correlated_app = self._find_correlated_app(file_time, app_events)

            if correlated_app:
                # Create inferred acquisition event
                inferred_event = Event(
                    time_start=file_time,
                    time_end=None,
                    event_type=EventType.FILE_ACQUISITION_INFERRED,
                    subject="User",
                    object=file_path,
                    description=f"File likely received via {correlated_app} (non-browser download inferred)",
                    source=self.source,
                    confidence=Confidence.MEDIUM
                )

                inferred_events.append(inferred_event)

        return inferred_events
