from enum import Enum
from datetime import datetime
from typing import Optional


class EventType(Enum):
    FILE_REFERENCE = "FILE_REFERENCE"
    PROGRAM_EXECUTION = "PROGRAM_EXECUTION"
    USER_INTENT = "USER_INTENT"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    FILE_ACQUISITION_INFERRED = "FILE_ACQUISITION_INFERRED"
    CLIPBOARD_ACTIVITY = "CLIPBOARD_ACTIVITY"
    USB_DEVICE_MOUNT = "USB_DEVICE_MOUNT"


class Confidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Event:
    def __init__(
        self,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        event_type: Optional[EventType] = None,
        subject: str = "User",
        object: str = "",
        description: str = "",
        source: str = "",
        confidence: Confidence = Confidence.LOW,
        correlated: bool = False,
        correlation_notes: Optional[str] = None
    ):
        self.time_start = time_start
        self.time_end = time_end
        self.event_type = event_type
        self.subject = subject
        self.object = object
        self.description = description
        self.source = source
        self.confidence = confidence
        self.correlated = correlated
        self.correlation_notes = correlation_notes

    @property
    def sort_time(self) -> Optional[datetime]:
        return self.time_end or self.time_start

    def __str__(self):
        start = (
            self.time_start.isoformat()
            if self.time_start else "UNKNOWN"
        )
        end = (
            self.time_end.isoformat()
            if self.time_end else "UNKNOWN"
        )

        correlation_score = ""
        if self.correlation_notes and "Corroborated by:" in self.correlation_notes:
            sources_part = self.correlation_notes.split("Corroborated by:")[1].strip()
            sources = [s.strip() for s in sources_part.split(",")]
            correlation_score = f" | Correlation: {len(sources)}/4 artifacts"
        elif self.correlated:
            correlation_score = " | Correlation: 2/4 artifacts"
        else:
            correlation_score = " | Correlation: 1/4 artifacts"

        corr = ""
        if self.correlated:
            corr = f" | CORRELATED"
            if self.correlation_notes and "Corroborated by:" not in self.correlation_notes:
                corr += f" ({self.correlation_notes})"

        return (
            f"[{start} -> {end}] | "
            f"{self.event_type.value if self.event_type else 'UNKNOWN'} | "
            f"{self.description} | "
            f"{self.source} | "
            f"{self.confidence.value}"
            f"{correlation_score}"
            f"{corr}"
        )
