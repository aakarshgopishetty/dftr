"""
Configuration settings for the Digital Forensic Timeline Reconstructor
"""

TIME_VALIDATION_CONFIG = {
    'strict_mode': False,  # Allow some future drift since system clock is in 2026
    'max_future_drift_minutes': 525600,  # Allow events up to ~1 year in the future (60*24*365)
    'log_filtered_events': True
}

APP_CONFIG = {
    'max_terminal_events': 10,  
    'default_time_range_days': 7,  
}
