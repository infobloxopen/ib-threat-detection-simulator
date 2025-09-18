"""
Logging Utilities for Sales Demo

Provides logging configuration and utilities for the sales demo script.
"""

import logging
import sys
import os

def configure_logging(log_level=logging.INFO):
    """
    Configure logging for the sales demo script.
    
    Args:
        log_level: Logging level (default: INFO)
    """
    handlers = []
    
    # Always add console handler
    handlers.append(logging.StreamHandler(sys.stdout))
    
    # Try to add file handler, but gracefully handle permission errors
    try:
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Try to create file handler
        file_handler = logging.FileHandler(os.path.join(log_dir, "threat_detection_simulator.log"), encoding='utf-8')
        handlers.append(file_handler)
        print(f"✅ Logging to file: {os.path.join(log_dir, 'threat_detection_simulator.log')}")
        
    except (PermissionError, OSError) as e:
        # If we can't write to the logs directory, try alternative locations
        alternative_paths = [
            os.path.expanduser("~/category_analysis.log"),  # User home directory
            "/tmp/category_analysis.log",                   # Temporary directory
        ]
        
        file_handler_created = False
        for alt_path in alternative_paths:
            try:
                file_handler = logging.FileHandler(alt_path, encoding='utf-8')
                handlers.append(file_handler)
                print(f"⚠️  Could not write to logs directory, using alternative: {alt_path}")
                file_handler_created = True
                break
            except (PermissionError, OSError):
                continue
        
        if not file_handler_created:
            print(f"⚠️  Could not create log file anywhere, logging to console only")
            print(f"    Original error: {e}")
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers,
        force=True  # Force reconfiguration if logging was already configured
    )
    
    # Set specific logger levels
    logging.getLogger('google').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

def get_logger(name):
    """
    Get a configured logger instance.
    
    Args:
        name (str): Logger name
        
    Returns:
        logging.Logger: Configured logger
    """
    return logging.getLogger(name)

def flush_logs():
    """Manually flush all logging handlers"""
    for handler in logging.root.handlers:
        handler.flush()
    sys.stdout.flush()
    sys.stderr.flush()
