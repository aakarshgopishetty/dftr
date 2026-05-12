from flask import Flask, request, jsonify, Response
import os
from datetime import datetime

app = Flask(__name__, template_folder="templates")

collected_events = []


@app.route("/")
def index():
    html_path = os.path.join(app.template_folder, "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    return Response(content, mimetype="text/html")


@app.route("/api/collect", methods=["POST"])
def collect():
    global collected_events
    
    data = request.get_json() or {}
    mode = data.get("mode", "standard")
    selected_sources = data.get("sources", [])
    selected_confidences = data.get("confidences", [])
    start_date = data.get("start_date")
    end_date = data.get("end_date")
    
    print(f"Starting collection in {mode} mode...")
    print(f"Selected sources: {selected_sources}")
    print(f"Selected confidences: {selected_confidences}")
    print(f"Date range: {start_date} to {end_date}")
    
    # Clear previous events
    collected_events = []
    
    # Define source to collector mapping
    collectors_map = {
        'recent_files': ('collectors.recent_files.recent_files', 'RecentFilesCollector'),
        'browser_history': ('collectors.browser_history.browser_history', 'BrowserHistoryCollector'),
        'file_metadata': ('collectors.file_metadata.file_metadata', 'FileMetadataCollector'),
        'downloads': ('collectors.downloads.browser_downloads', 'BrowserDownloadsCollector'),
        'clipboard': ('collectors.clipboard.clipboard', 'ClipboardCollector'),
        'usb': ('collectors.usb_logs.usb', 'USBCollector'),
        'app_usage': ('collectors.app_usage.registry_mru', 'RegistryMRUCollector'),
        'startup_shutdown': ('collectors.startup_shutdown_logs.startup_shutdown_logs', 'StartupShutdownLogsCollector'),
        'temp_files': ('collectors.temp_files.temp_files', 'TempFilesCollector')
    }
    
    # If no sources selected, use all
    if not selected_sources:
        selected_sources = list(collectors_map.keys())
    
    # Import and run selected collectors
    for source_name in selected_sources:
        if source_name in collectors_map:
            module_name, class_name = collectors_map[source_name]
            try:
                module = __import__(module_name, fromlist=[class_name])
                collector_class = getattr(module, class_name)
                collector = collector_class()
                events = collector.collect()
                if events:
                    collected_events.extend(events)
                    print(f"[API] {class_name}: {len(events)} events collected")
            except Exception as e:
                print(f"[API] Error with {class_name}: {e}")

    # Always include Jump Lists (supplementary collector)
    try:
        from collectors.recent_files.jump_lists import JumpListsCollector
        collector = JumpListsCollector()
        events = collector.collect()
        if events:
            collected_events.extend(events)
            print(f"[API] Jump Lists: {len(events)} events collected")
    except Exception as e:
        print(f"[API] Error with JumpListsCollector: {e}")

    # Always include UserAssist (supplementary collector)
    try:
        from collectors.app_usage.userassist import UserAssistCollector
        collector = UserAssistCollector()
        events = collector.collect()
        if events:
            collected_events.extend(events)
            print(f"[API] UserAssist: {len(events)} events collected")
    except Exception as e:
        print(f"[API] Error with UserAssistCollector: {e}")

    # Prefetch collector - only for admin/advanced mode
    if mode == "advanced":
        try:
            from collectors.app_usage.prefetch import PrefetchCollector
            collector = PrefetchCollector()
            events = collector.collect()
            if events:
                collected_events.extend(events)
                print(f"[API] Prefetch: {len(events)} events collected")
        except Exception as e:
            print(f"[API] Error with PrefetchCollector: {e}")

    print(f"[API] Total events collected: {len(collected_events)}")
    
    return jsonify({
        'status': 'success',
        'events_collected': len(collected_events),
        'mode': mode
    })


@app.route("/api/events", methods=["GET"])
def get_events():
    from datetime import datetime
    
    # Get filters - but don't filter if not provided
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    sources = request.args.get('sources', '')
    eventtypes = request.args.get('eventtypes', '')
    confidences = request.args.get('confidences', '')

    print(f"[API] Fetching events - total collected: {len(collected_events)}")
    print(f"[API] Filters - start: '{start_date}', end: '{end_date}', sources: '{sources}', confidences: '{confidences}'")

    # Convert all collected events to dictionary format
    filtered = []
    
    for event in collected_events:
        try:
            # Get timestamp - try sort_time property first
            ts = None
            if hasattr(event, 'sort_time'):
                ts = event.sort_time
            elif hasattr(event, 'time_end') and event.time_end:
                ts = event.time_end
            elif hasattr(event, 'time_start') and event.time_start:
                ts = event.time_start
            
            # Date filtering
            if start_date and ts:
                try:
                    filter_start = datetime.strptime(start_date, '%Y-%m-%d')
                    if ts < filter_start:
                        continue
                except:
                    pass
                    
            if end_date and ts:
                try:
                    filter_end = datetime.strptime(end_date, '%Y-%m-%d')
                    filter_end = filter_end.replace(hour=23, minute=59, second=59)
                    if ts > filter_end:
                        continue
                except:
                    pass
            
            # Source filtering
            if sources:
                source_list = [s.strip() for s in sources.split(',') if s.strip()]
                if source_list:
                    event_source = ''
                    if hasattr(event, 'source'):
                        event_source = event.source or ''
                    
                    matched = False
                    for s in source_list:
                        if s.lower() in event_source.lower() or event_source.lower() in s.lower():
                            matched = True
                            break
                    if not matched:
                        continue
            
            # Get event type
            etype_val = None
            if hasattr(event, 'event_type') and event.event_type:
                if hasattr(event.event_type, 'value'):
                    etype_val = event.event_type.value
                else:
                    etype_val = str(event.event_type)
            
            # Get confidence
            conf_val = 'LOW'
            if hasattr(event, 'confidence') and event.confidence:
                if hasattr(event.confidence, 'value'):
                    conf_val = event.confidence.value
                else:
                    conf_val = str(event.confidence)
            
            # Convert to dictionary
            ts_str = None
            if ts:
                ts_str = ts.isoformat()
            
            evt = {
                "timestamp": ts_str,
                "event_type": etype_val,
                "subject": getattr(event, 'subject', ''),
                "object": getattr(event, 'object', ''),
                "description": getattr(event, 'description', ''),
                "source": getattr(event, 'source', ''),
                "confidence": conf_val,
                "correlated": getattr(event, 'correlated', False)
            }
            
            filtered.append(evt)
        except Exception as e2:
            print(f"Error processing event: {e2}")

    print(f"[API] Returning {len(filtered)} events")
    return jsonify({'events': filtered, 'total': len(filtered)})


@app.route("/api/debug", methods=["GET"])
def debug_events():
    """Debug endpoint to see collected events"""
    result = []
    for event in collected_events:
        result.append({
            'sort_time': str(getattr(event, 'sort_time', None)),
            'source': getattr(event, 'source', ''),
            'description': getattr(event, 'description', '')[:100],
            'object': getattr(event, 'object', '')[:100]
        })
    return jsonify({
        'total_collected': len(collected_events),
        'events': result[:10]  # First 10 events
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)

