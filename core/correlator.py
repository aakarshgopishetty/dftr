from datetime import timedelta
from core.event import EventType, ConfidenceLevel

EXECUTION_APPS = ["Chrome", "Brave", "MSEdge", "Microsoft.Windows.Explorer", "Visual Studio Code"]
TIME_WINDOW = timedelta(minutes=5)

def correlate_events(events):
    executions = [
        e for e in events if e.event_type == EventType.PROGRAM_EXECUTION
    ]
    file_refs = [
        e for e in events if e.event_type == EventType.FILE_REFERENCE
    ]

    for exec_event in executions:
        exec_time = exec_event.sort_time
        if not exec_time:
            continue

        for file_event in file_refs:
            file_time = file_event.sort_time
            if not file_time:
                continue

            if abs(file_time - exec_time) <= TIME_WINDOW:
                for app in EXECUTION_APPS:
                    if app.lower() in exec_event.object.lower():

                        file_event.correlated = True
                        file_event.confidence = ConfidenceLevel.MEDIUM
                        file_event.correlation_notes = (
                            f"File likely accessed via {exec_event.object}"
                        )

                        exec_event.correlated = True
                        break

    return events
