"""
Configuration settings for the Digital Forensic Timeline Reconstructor
"""

TIME_VALIDATION_CONFIG = {
    'strict_mode': True,  
    'max_future_drift_minutes': 5,  
    'log_filtered_events': True  
}

APP_CONFIG = {
    'max_terminal_events': 10,  
    'default_time_range_days': 7,  
}
