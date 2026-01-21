import win32evtlog
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from core.event import Event, EventType, Confidence

EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class USBCollector:
    """
    Collects USB device connection and removal events from Windows Event Logs.
    Requires administrator privileges to access event logs.
    """

    def __init__(self):
        self.source = "Windows Event Logs - USB"
        self.requires_admin = True

    def _query_events(self, log, xpath):
        """Query Windows Event Log with XPath filter."""
        handle = win32evtlog.EvtQuery(
            log,
            win32evtlog.EvtQueryChannelPath,
            xpath
        )
        try:
            while True:
                events = win32evtlog.EvtNext(handle, 50)
                if not events:
                    break
                for evt in events:
                    yield evt
        finally:
            pass

    def _parse_event(self, evt):
        """Parse event XML into structured data."""
        xml = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
        root = ET.fromstring(xml)

        system = root.find("e:System", EVENT_NS)
        if system is None:
            return None

        eid = int(system.find("e:EventID", EVENT_NS).text)
        provider = system.find("e:Provider", EVENT_NS).attrib.get("Name", "")

        ts_raw = system.find("e:TimeCreated", EVENT_NS).attrib["SystemTime"]
        timestamp = datetime.fromisoformat(ts_raw.rstrip("Z")).replace(tzinfo=timezone.utc)

        data = {}
        ed = root.find("e:EventData", EVENT_NS)
        if ed is not None:
            for d in ed.findall("e:Data", EVENT_NS):
                data[d.attrib.get("Name", "")] = d.text or ""

        return eid, provider, timestamp, data

    def collect(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> List[Event]:
        events = []

        # Default to last 30 days if no time range specified
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(days=30)

        since = start_time.isoformat() + "Z"
        xpath = f"*[System[TimeCreated[@SystemTime>='{since}']]]"

        try:
            for evt in self._query_events(
                "Microsoft-Windows-DriverFrameworks-UserMode/Operational", xpath
            ):
                parsed = self._parse_event(evt)
                if not parsed:
                    continue

                eid, _, ts, data = parsed

                # Filter by end_time if specified
                if end_time and ts > end_time:
                    continue

                event_type = None
                description = ""
                confidence = Confidence.MEDIUM

                if eid in (2003, 2100, 2101):
                    event_type = EventType.SYSTEM_EVENT
                    device_instance = data.get('DeviceInstance', 'Unknown Device')
                    description = f"USB device connected: {device_instance}"
                    confidence = Confidence.HIGH
                elif eid in (2004, 2102, 2106):
                    event_type = EventType.SYSTEM_EVENT
                    device_instance = data.get('DeviceInstance', 'Unknown Device')
                    description = f"USB device removed: {device_instance}"
                    confidence = Confidence.HIGH
                else:
                    continue

                event = Event(
                    time_start=ts,
                    event_type=event_type,
                    subject="System",
                    object=device_instance,
                    description=description,
                    source=self.source,
                    confidence=confidence
                )

                events.append(event)

        except Exception as e:
            # Create a warning event if USB event log access fails
            warning_event = Event(
                time_start=datetime.now(timezone.utc),
                event_type=EventType.SYSTEM_EVENT,
                subject="System",
                object="USB Collector",
                description=f"USB event collection failed: {str(e)}. DriverFrameworks-UserMode/Operational log may be disabled.",
                source=self.source,
                confidence=Confidence.LOW
            )
            events.append(warning_event)

        return events
