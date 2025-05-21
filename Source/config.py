import os
from utils import get_local_interfaces

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
DATABASE_ENABLED = True if DATABASE_URL else False
PACKET_STORAGE_LIMIT = 5000  # Maximum number of packets to store in the database per session
ENABLE_PACKET_STORAGE = True  # Whether to store full packet data
ENABLE_TRAFFIC_STATS_STORAGE = True  # Whether to store traffic statistics
LOG_RETENTION_DAYS = 30  # Number of days to retain logs in database

# Default interface to capture packets from
# Try to auto-detect, but fall back to "any" as a last resort
INTERFACES = get_local_interfaces()
INTERFACE = "any"  # Default to "any" if no interfaces found

if INTERFACES:
    if "eth0" in INTERFACES:
        INTERFACE = "eth0"
    elif "en0" in INTERFACES:
        INTERFACE = "en0"
    elif "wlan0" in INTERFACES:
        INTERFACE = "wlan0"
    else:
        INTERFACE = INTERFACES[0]

# Packet capture settings
CAPTURE_TIMEOUT = 2  # Timeout in seconds for packet capture
CAPTURE_COUNT = 100  # Maximum number of packets to capture in each cycle

# Analysis settings
ANALYSIS_WINDOW = 300  # Analysis window in seconds (5 minutes)
MIN_PACKETS_FOR_ANALYSIS = 10  # Minimum packets needed for meaningful analysis

# Anomaly detection settings
ANOMALY_THRESHOLD = 95  # Percentile threshold for anomaly detection
ANOMALY_WINDOW = 300  # Window for anomaly detection in seconds (5 minutes)

# Alert settings
MAX_ALERTS = 1000  # Maximum number of alerts to store in memory
ALERT_LOG_FILE = "alerts.log"  # File to log alerts to

# Logging settings
LOG_LEVEL = "INFO"  # Default log level
LOG_FILE = "nids.log"  # Log file path

# Rule engine settings
RULES_FILE = "data/rules.json"  # Path to rules file

# UI settings
REFRESH_INTERVAL = 5  # Refresh interval for UI in seconds
MAX_PACKETS_DISPLAY = 100  # Maximum number of packets to display in UI
