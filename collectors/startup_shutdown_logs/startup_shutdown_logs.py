import logging
import os
from datetime import datetime, timedelta
from typing import List

try:
    import win32evtlog
    import win32evtlogutil
    import pywintypes
    EVENT_LOG_AVAILABLE = True
except ImportError:
    EVENT_LOG_AVAILABLE = False
    logging.warning("pywin32 not available - startup/shutdown log collection disabled")

from core.event import Event, EventType, Confidence


class StartupShutdownLogsCollector:

    def __init__(self):
        self.source = "Windows Event Log"

    def _evt_time_to_datetime(self, evt_time):
        """Safely convert Windows event time to datetime with high precision."""
        try:
            if evt_time is None:
                return None

            # Already datetime - return as-is (most accurate)
            if isinstance(evt_time, datetime):
                return evt_time

            # pywintypes.Time - use direct conversion
            try:
                # pywintypes.Time objects can be converted directly to datetime
                if hasattr(evt_time, 'Format'):
                    # Try to get the datetime representation
                    dt_str = str(evt_time)
                    # Parse the string representation if it's in a standard format
                    try:
                        return datetime.strptime(dt_str, '%a %b %d %H:%M:%S %Y')
                    except:
                        pass
                # Alternative: use the underlying time tuple
                if hasattr(evt_time, 'timetuple'):
                    return datetime(*evt_time.timetuple()[:6])
            except:
                pass

            # Try as Unix timestamp (most common for recent events)
            try:
                timestamp = float(evt_time)
                # Check if it's a reasonable Unix timestamp (after 2000, before 2030)
                if 946684800 < timestamp < 1893456000:  # 2000-01-01 to 2030-01-01
                    return datetime.fromtimestamp(timestamp)
            except:
                pass

            # Try as Windows FILETIME (100-nanosecond intervals since 1601-01-01)
            try:
                filetime = int(evt_time)
                # FILETIME values are typically very large numbers
                if filetime > 116444736000000000:  # Roughly year 2000 in FILETIME
                    base_time = datetime(1601, 1, 1)
                    # FILETIME is in 100-nanosecond intervals
                    seconds = filetime / 10000000.0
                    result = base_time + timedelta(seconds=seconds)
                    # Validate the result is reasonable (not in future)
                    if result < datetime.now() + timedelta(hours=1):
                        return result
            except:
                pass

            return None
        except Exception:
            return None

    def _collect_system_events(self):
        """Collect startup and shutdown events from Windows Event Log."""
        events = []

        if not EVENT_LOG_AVAILABLE:
            logging.warning("Event log collection skipped - pywin32 not available")
            return events

        try:
            # Open System event log
            log_handle = win32evtlog.OpenEventLog(None, "System")

            if log_handle:
                try:
                    # Event IDs for startup/shutdown events
                    startup_events = [12, 6005, 6009]  # System start events
                    shutdown_events = [13, 6006, 6008]  # System shutdown events

                    # Read events from the last 30 days
                    start_time = datetime.now() - timedelta(days=30)
                    start_time_pywintypes = pywintypes.Time(start_time)

                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                    total_events = win32evtlog.GetNumberOfEventLogRecords(log_handle)
                    events_read = 0
                    max_events = min(1000, total_events)  # Limit to prevent excessive processing

                    while events_read < max_events:
                        records = win32evtlog.ReadEventLog(log_handle, flags, 0)

                        if not records:
                            break

                        for record in records:
                            try:
                                event_time = self._evt_time_to_datetime(record.TimeGenerated)

                                if event_time and event_time >= start_time:
                                    event_id = record.EventID & 0xFFFF  # Mask to get actual event ID

                                    if event_id in startup_events:
                                        event_type = EventType.SYSTEM_STARTUP
                                        description = "System startup event"
                                        confidence = Confidence.HIGH

                                        # Try to get more details from event message
                                        try:
                                            msg = win32evtlogutil.FormatMessage(record, "System")
                                            if msg and len(msg.strip()) > 0:
                                                description = f"System startup: {msg.strip()[:100]}"
                                        except:
                                            pass

                                        event = Event(
                                            time_start=event_time,
                                            time_end=None,
                                            event_type=event_type,
                                            subject="System",
                                            object=f"Event ID {event_id}",
                                            description=description,
                                            source=self.source,
                                            confidence=confidence
                                        )
                                        events.append(event)

                                    elif event_id in shutdown_events:
                                        event_type = EventType.SYSTEM_SHUTDOWN
                                        if event_id == 6008:
                                            description = "Unexpected system shutdown (possible crash or power loss)"
                                            confidence = Confidence.MEDIUM
                                        else:
                                            description = "System shutdown event"
                                            confidence = Confidence.HIGH

                                        # Try to get more details from event message
                                        try:
                                            msg = win32evtlogutil.FormatMessage(record, "System")
                                            if msg and len(msg.strip()) > 0:
                                                description = f"System shutdown: {msg.strip()[:100]}"
                                        except:
                                            pass

                                        event = Event(
                                            time_start=event_time,
                                            time_end=None,
                                            event_type=event_type,
                                            subject="System",
                                            object=f"Event ID {event_id}",
                                            description=description,
                                            source=self.source,
                                            confidence=confidence
                                        )
                                        events.append(event)

                            except Exception as e:
                                logging.debug(f"Error processing event record: {e}")
                                continue

                        events_read += len(records)

                        # Break if we've gone back far enough
                        last_time = self._evt_time_to_datetime(records[-1].TimeGenerated)
                        if last_time and last_time < start_time:
                            break

                    logging.info(f"Collected {len(events)} startup/shutdown events from event log")

                finally:
                    win32evtlog.CloseEventLog(log_handle)

        except Exception as e:
            logging.warning(f"Failed to collect startup/shutdown events from event log: {e}")

        return events

    def collect(self) -> List[Event]:
        """Collect startup and shutdown events."""
        events = []

        if not EVENT_LOG_AVAILABLE:
            logging.warning("Startup/shutdown log collection skipped - pywin32 not available")
            return events

        try:
            events = self._collect_system_events()
            logging.info(f"Startup/shutdown collection completed: {len(events)} events")
        except Exception as e:
            logging.error(f"Startup/shutdown collection failed: {e}")

        return events
