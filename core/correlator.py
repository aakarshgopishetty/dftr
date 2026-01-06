from datetime import datetime, timedelta
from collections import defaultdict
from core.event import EventType, ConfidenceLevel

TIME_WINDOW = timedelta(minutes=5)

def normalize_program_name(name):
    if not name:
        return ""

    name = name.lower()
    name = name.replace('.exe', '').replace('.lnk', '')

    name_map = {
        'microsoftedge': 'msedge',
        'microsoft.windows.explorer': 'explorer',
        'code': 'visual studio code',
        'chrome': 'google chrome',
        'firefox': 'mozilla firefox'
    }

    for key, value in name_map.items():
        if key in name:
            return value

    return name

def is_system_activity(event):
    system_paths = [
        'system32', 'syswow64', 'windows\\system',
        'windowsapps', 'program files\\windowsapps',
        'windows\\winsxs', 'windows\\servicing'
    ]

    system_programs = [
        'svchost', 'services', 'lsass', 'winlogon', 'csrss',
        'smss', 'system', 'idle', 'system idle process'
    ]

    subject_lower = (event.subject or '').lower()
    object_lower = (event.object or '').lower()
    description_lower = (event.description or '').lower()

    for path in system_paths:
        if path in object_lower or path in description_lower:
            return True

    for prog in system_programs:
        if prog in object_lower:
            return True

    return False

def calculate_confidence(event, related_events):
    sources = set()
    time_agreements = 0

    event_time = event.sort_time
    if not event_time:
        return ConfidenceLevel.LOW

    for related_event in related_events:
        if related_event.source != event.source:
            sources.add(related_event.source)

        related_time = related_event.sort_time
        if related_time and abs(related_time - event_time) <= TIME_WINDOW:
            time_agreements += 1

    if len(sources) >= 2 and time_agreements >= 1:
        return ConfidenceLevel.HIGH
    elif len(sources) >= 1 or time_agreements >= 1:
        return ConfidenceLevel.MEDIUM
    else:
        return ConfidenceLevel.LOW

def correlate_events(events):
    name_groups = defaultdict(list)
    time_groups = defaultdict(list)

    for event in events:
        if hasattr(event, '_processed'):
            continue

        if event.event_type == EventType.PROGRAM_EXECUTION:
            normalized = normalize_program_name(event.object)
        elif event.event_type == EventType.FILE_REFERENCE:
            normalized = normalize_program_name(event.object)
        else:
            normalized = normalize_program_name(event.object)

        if normalized:
            name_groups[normalized].append(event)

        event_time = event.sort_time
        if event_time:
            time_key = event_time.replace(minute=event_time.minute // 5 * 5, second=0, microsecond=0)
            time_groups[time_key].append(event)

        event._processed = True

    for program_name, program_events in name_groups.items():
        if len(program_events) < 2:
            continue

        program_events.sort(key=lambda e: e.sort_time or datetime.min)

        for i, event in enumerate(program_events):
            related_events = [e for e in program_events if e != event]
            new_confidence = calculate_confidence(event, related_events)

            if (event.confidence == ConfidenceLevel.LOW and new_confidence in [ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH]) or \
               (event.confidence == ConfidenceLevel.MEDIUM and new_confidence == ConfidenceLevel.HIGH):
                event.confidence = new_confidence

            if len(set(e.source for e in program_events)) > 1:
                event.correlated = True
                sources = list(set(e.source for e in program_events))
                event.correlation_notes = f"Corroborated by: {', '.join(sources)}"

    for time_window, time_events in time_groups.items():
        if len(time_events) < 2:
            continue

        executions = [e for e in time_events if e.event_type == EventType.PROGRAM_EXECUTION]
        file_refs = [e for e in time_events if e.event_type == EventType.FILE_REFERENCE]

        for exec_event in executions:
            exec_time = exec_event.sort_time
            if not exec_time:
                continue

            for file_event in file_refs:
                file_time = file_event.sort_time
                if not file_time:
                    continue

                if abs(file_time - exec_time) <= TIME_WINDOW:
                    file_event.correlated = True
                    if not file_event.correlation_notes:
                        file_event.correlation_notes = f"Associated with {exec_event.object} execution"
                    else:
                        file_event.correlation_notes += f" | Associated with {exec_event.object} execution"

                    exec_event.correlated = True
                    if not exec_event.correlation_notes:
                        exec_event.correlation_notes = f"Associated with file access: {file_event.object}"
                    else:
                        exec_event.correlation_notes += f" | Associated with file access: {file_event.object}"

    for event in events:
        if is_system_activity(event):
            event.subject = "System"
            event.correlation_notes = (event.correlation_notes or "") + " | System Activity"
        else:
            event.subject = "User"

    return events
