import logging
import os
import sqlite3
import shutil
import tempfile
from datetime import datetime, timedelta
from typing import List

try:
    import win32clipboard
    import win32con
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False
    logging.warning("pywin32 not available - clipboard collection disabled")

from core.event import Event, EventType, Confidence


class ClipboardCollector:

    def __init__(self):
        self.source = "Clipboard"

    def _is_admin(self):
        """Check if running with administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def _windows_ticks_to_datetime(self, windows_ticks):
        """Convert Windows FILETIME ticks to datetime."""
        if windows_ticks is None or windows_ticks == 0:
            return None
        # Windows FILETIME is 100-nanosecond intervals since 1601-01-01
        base_time = datetime(1601, 1, 1)
        # Convert ticks to seconds (divide by 10,000,000)
        seconds = windows_ticks / 10000000.0
        return base_time + timedelta(seconds=seconds)

    def _get_clipboard_content(self):
        """Get current clipboard content in a safe way."""
        if not CLIPBOARD_AVAILABLE:
            return None, "pywin32 not available"

        try:
            win32clipboard.OpenClipboard()
            try:
                # Try to get text content first
                if win32clipboard.IsClipboardFormatAvailable(win32con.CF_TEXT):
                    data = win32clipboard.GetClipboardData(win32con.CF_TEXT)
                    try:
                        # Decode bytes to string
                        text = data.decode('utf-8', errors='replace')
                        return text, "text"
                    except:
                        return str(data), "text"

                # Try Unicode text
                elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                    data = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                    return data, "unicode_text"

                # Try HTML format
                elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.RegisterClipboardFormat("HTML Format")):
                    data = win32clipboard.GetClipboardData(win32clipboard.RegisterClipboardFormat("HTML Format"))
                    try:
                        html = data.decode('utf-8', errors='replace')
                        return html[:200] + "..." if len(html) > 200 else html, "html"
                    except:
                        return str(data)[:200] + "..." if len(str(data)) > 200 else str(data), "html"

                # Try bitmap/image
                elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_BITMAP):
                    return "[Bitmap/Image content]", "bitmap"

                # Try file list
                elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                    data = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                    files = []
                    for file_path in data:
                        files.append(file_path)
                    return f"Files: {', '.join(files)}", "files"

                else:
                    # Check what formats are available
                    available_formats = []
                    format_id = 0
                    while True:
                        format_id = win32clipboard.EnumClipboardFormats(format_id)
                        if format_id == 0:
                            break
                        try:
                            format_name = win32clipboard.GetClipboardFormatName(format_id)
                            available_formats.append(format_name or f"Format_{format_id}")
                        except:
                            available_formats.append(f"Format_{format_id}")

                    if available_formats:
                        return f"[Clipboard contains: {', '.join(available_formats[:3])}]", "unknown"
                    else:
                        return "[Empty clipboard]", "empty"

            finally:
                win32clipboard.CloseClipboard()

        except Exception as e:
            logging.debug(f"Clipboard access failed: {e}")
            return None, f"access_error: {str(e)}"

    def _collect_historical_clipboard(self):
        """Collect historical clipboard data from Windows clipboard database (requires admin)."""
        events = []

        if not self._is_admin():
            return events

        # Path to clipboard history database
        local_appdata = os.environ.get('LOCALAPPDATA')
        if not local_appdata:
            return events

        clipboard_db_path = os.path.join(local_appdata, 'Microsoft', 'Windows', 'Clipboard', 'Clipboard.db')

        if not os.path.exists(clipboard_db_path):
            logging.debug("Clipboard history database not found")
            return events

        try:
            # Create a temporary copy of the database
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                shutil.copy2(clipboard_db_path, tmp.name)
                db_path = tmp.name

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Query clipboard history - the exact schema may vary by Windows version
            # Common tables: ClipboardContent, Content
            try:
                # Try different possible table/column names
                queries = [
                    "SELECT Id, Content, Timestamp FROM ClipboardContent ORDER BY Timestamp DESC",
                    "SELECT Id, Content, AddedTime FROM Content ORDER BY AddedTime DESC",
                    "SELECT * FROM ClipboardContent ORDER BY Timestamp DESC",
                    "SELECT * FROM Content ORDER BY AddedTime DESC"
                ]

                historical_events = 0
                for query in queries:
                    try:
                        cursor.execute(query)
                        rows = cursor.fetchall()

                        if rows:
                            # Get column names
                            column_names = [desc[0] for desc in cursor.description]

                            for row in rows:
                                row_dict = dict(zip(column_names, row))

                                # Extract content and timestamp
                                content = None
                                timestamp = None

                                # Try different column names for content
                                for content_col in ['Content', 'Data', 'Text']:
                                    if content_col in row_dict and row_dict[content_col]:
                                        content = row_dict[content_col]
                                        break

                                # Try different column names for timestamp
                                for time_col in ['Timestamp', 'AddedTime', 'CreatedTime']:
                                    if time_col in row_dict and row_dict[time_col]:
                                        timestamp = row_dict[time_col]
                                        break

                                if content and timestamp:
                                    # Convert timestamp if it's Windows FILETIME
                                    if isinstance(timestamp, int) and timestamp > 1000000000000000:  # Likely FILETIME
                                        event_time = self._windows_ticks_to_datetime(timestamp)
                                    else:
                                        # Assume Unix timestamp or try to parse
                                        try:
                                            event_time = datetime.fromtimestamp(timestamp)
                                        except:
                                            event_time = None

                                    if event_time:
                                        # Decode content if it's bytes
                                        if isinstance(content, bytes):
                                            try:
                                                content_str = content.decode('utf-8', errors='replace')
                                            except:
                                                content_str = str(content)
                                        else:
                                            content_str = str(content)

                                        # Create preview
                                        preview = content_str.replace('\n', ' ').replace('\r', ' ').strip()
                                        if len(preview) > 100:
                                            preview = preview[:97] + "..."

                                        event = Event(
                                            time_start=event_time,
                                            time_end=None,
                                            event_type=EventType.CLIPBOARD_ACTIVITY,
                                            subject="User",
                                            object=f"Historical Clipboard (ID: {row_dict.get('Id', 'Unknown')})",
                                            description=f"Historical clipboard: {preview}",
                                            source="Clipboard History",
                                            confidence=Confidence.HIGH  # Historical data has higher forensic value
                                        )

                                        events.append(event)
                                        historical_events += 1

                            break  # Stop trying other queries if we found data

                    except sqlite3.OperationalError:
                        continue  # Try next query

                conn.close()
                os.remove(db_path)

                if historical_events > 0:
                    logging.info(f"Clipboard history collected: {historical_events} historical entries")

            except Exception as e:
                logging.debug(f"Clipboard history collection failed: {e}")
                conn.close()
                os.remove(db_path)

        except Exception as e:
            logging.debug(f"Failed to access clipboard history database: {e}")

        return events

    def collect(self) -> List[Event]:
        events = []

        if not CLIPBOARD_AVAILABLE:
            logging.warning("Clipboard collection skipped - pywin32 not available")
            return events

        # Always collect current clipboard content (works without admin)
        content, content_type = self._get_clipboard_content()

        if content is not None:
            # Create preview for description (truncate if too long)
            preview = content.replace('\n', ' ').replace('\r', ' ').strip()
            if len(preview) > 100:
                preview = preview[:97] + "..."

            # Determine confidence based on content type
            confidence = Confidence.LOW  # Current clipboard has limited forensic value
            if content_type in ["text", "unicode_text"] and len(content.strip()) > 0:
                confidence = Confidence.MEDIUM

            event = Event(
                time_start=datetime.now(),  # Current time since we capture current state
                time_end=None,
                event_type=EventType.CLIPBOARD_ACTIVITY,
                subject="User",
                object=f"Clipboard ({content_type})",
                description=f"Clipboard content: {preview}",
                source=self.source,
                confidence=confidence
            )

            events.append(event)
            logging.info(f"Current clipboard collected: {content_type} content ({len(content) if content else 0} chars)")
        else:
            logging.debug("Failed to access current clipboard content")

        # Collect historical clipboard data if running with admin privileges
        if self._is_admin():
            logging.info("Admin privileges detected - collecting historical clipboard data")
            historical_events = self._collect_historical_clipboard()
            events.extend(historical_events)
            logging.info(f"Total clipboard events collected: {len(events)} (including {len(historical_events)} historical)")
        else:
            logging.debug("No admin privileges - skipping historical clipboard collection")

        return events
