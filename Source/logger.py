import logging
import os
from datetime import datetime
import sys

def setup_logger(log_level=logging.INFO, log_file=None):
    """
    Setup a logger for the application
    
    Args:
        log_level (int): Logging level
        log_file (str): Path to log file (if None, logs to console only)
        
    Returns:
        logging.Logger: Configured logger
    """
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create handlers
    console_handler = logging.StreamHandler(sys.stdout)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    
    # Add file handler if log_file is specified
    if log_file:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def log_exception(logger, exc_info=None):
    """
    Log an exception with traceback
    
    Args:
        logger (logging.Logger): Logger to use
        exc_info (tuple): Exception info from sys.exc_info() (if None, gets current exception)
    """
    if exc_info is None:
        exc_info = sys.exc_info()
        
    logger.error("Exception occurred", exc_info=exc_info)

class LogCapture:
    """
    Class to capture log messages for display in the UI
    """
    
    def __init__(self, max_entries=1000):
        """
        Initialize the log capture
        
        Args:
            max_entries (int): Maximum number of log entries to store
        """
        self.log_entries = []
        self.max_entries = max_entries
        
        # Setup handler
        self.handler = LogCaptureHandler(self)
        self.handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)
    
    def add_entry(self, record):
        """
        Add a log entry
        
        Args:
            record (logging.LogRecord): Log record
        """
        # Convert log record to dictionary
        entry = {
            'timestamp': datetime.fromtimestamp(record.created),
            'level': record.levelname,
            'message': record.getMessage(),
            'source': record.name
        }
        
        # Add to entries
        self.log_entries.append(entry)
        
        # Trim if exceeding max entries
        if len(self.log_entries) > self.max_entries:
            self.log_entries = self.log_entries[-self.max_entries:]
    
    def get_entries(self, count=None, level=None):
        """
        Get log entries
        
        Args:
            count (int): Number of entries to return (newest first)
            level (str): Filter by log level
            
        Returns:
            list: Log entries
        """
        filtered = self.log_entries
        
        # Filter by level
        if level:
            filtered = [entry for entry in filtered if entry['level'] == level]
        
        # Sort by timestamp (newest first)
        filtered = sorted(filtered, key=lambda x: x['timestamp'], reverse=True)
        
        # Limit count if specified
        if count is not None:
            filtered = filtered[:count]
        
        return filtered

class LogCaptureHandler(logging.Handler):
    """
    Custom logging handler that sends log records to a LogCapture instance
    """
    
    def __init__(self, log_capture):
        """
        Initialize the handler
        
        Args:
            log_capture (LogCapture): LogCapture instance
        """
        super().__init__()
        self.log_capture = log_capture
    
    def emit(self, record):
        """
        Emit a log record
        
        Args:
            record (logging.LogRecord): Log record
        """
        self.log_capture.add_entry(record)
