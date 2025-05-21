import socket
import struct
import logging
import time
import re
import os
import platform
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)

def get_local_interfaces():
    """
    Get a list of local network interfaces
    
    Returns:
        list: List of interface names
    """
    interfaces = []
    
    try:
        # Different approaches based on platform
        if platform.system() == "Windows":
            # Use ipconfig on Windows
            output = subprocess.check_output("ipconfig", shell=True).decode('utf-8')
            # Extract adapter names
            for line in output.split('\n'):
                if "adapter" in line and ":" in line:
                    interfaces.append(line.split(':')[0].strip())
                    
        elif platform.system() == "Linux":
            # Use /sys/class/net on Linux
            for iface in os.listdir('/sys/class/net'):
                interfaces.append(iface)
                
        elif platform.system() == "Darwin":  # macOS
            # Use ifconfig on macOS
            output = subprocess.check_output("ifconfig", shell=True).decode('utf-8')
            pattern = re.compile(r'^([a-zA-Z0-9]+):')
            for line in output.split('\n'):
                match = pattern.match(line)
                if match:
                    interfaces.append(match.group(1))
        
        if not interfaces:
            interfaces = ["eth0", "wlan0", "en0", "lo"]  # Default fallback
            
    except Exception as e:
        logger.error(f"Error getting network interfaces: {str(e)}")
        interfaces = ["eth0", "wlan0", "en0", "lo"]  # Default fallback
    
    return interfaces

def ip_to_int(ip_address):
    """
    Convert an IP address to an integer
    
    Args:
        ip_address (str): IP address
        
    Returns:
        int: Integer representation of the IP
    """
    try:
        return struct.unpack("!I", socket.inet_aton(ip_address))[0]
    except Exception:
        return 0

def int_to_ip(ip_int):
    """
    Convert an integer to an IP address
    
    Args:
        ip_int (int): Integer representation of the IP
        
    Returns:
        str: IP address
    """
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except Exception:
        return "0.0.0.0"

def is_private_ip(ip_address):
    """
    Check if an IP address is private
    
    Args:
        ip_address (str): IP address
        
    Returns:
        bool: True if private, False otherwise
    """
    # Check if IP is in private ranges
    ip_int = ip_to_int(ip_address)
    
    # 10.0.0.0/8
    if (ip_int & 0xFF000000) == 0x0A000000:
        return True
    # 172.16.0.0/12
    if (ip_int & 0xFFF00000) == 0xAC100000:
        return True
    # 192.168.0.0/16
    if (ip_int & 0xFFFF0000) == 0xC0A80000:
        return True
    # 127.0.0.0/8 (localhost)
    if (ip_int & 0xFF000000) == 0x7F000000:
        return True
    
    return False

def format_bytes(size):
    """
    Format a byte size into a human-readable string
    
    Args:
        size (int): Size in bytes
        
    Returns:
        str: Formatted size
    """
    power = 2 ** 10  # 1024
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    
    while size > power and n < 4:
        size /= power
        n += 1
    
    return f"{size:.2f} {power_labels[n]}"

def get_timestamp():
    """
    Get current timestamp in a consistent format
    
    Returns:
        str: Formatted timestamp
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def calculate_rate(count, time_period):
    """
    Calculate a rate (events per second)
    
    Args:
        count (int): Number of events
        time_period (float): Time period in seconds
        
    Returns:
        float: Rate per second
    """
    if time_period <= 0:
        return 0
    return count / time_period

def parse_timestamp(timestamp_str):
    """
    Parse a timestamp string into a datetime object
    
    Args:
        timestamp_str (str): Timestamp string
        
    Returns:
        datetime: Datetime object
    """
    try:
        return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            # Try without milliseconds
            return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            logger.error(f"Error parsing timestamp: {timestamp_str}")
            return datetime.now()

def safe_div(a, b):
    """
    Safe division (avoids division by zero)
    
    Args:
        a (float): Numerator
        b (float): Denominator
        
    Returns:
        float: Result of division, or 0 if denominator is 0
    """
    return a / b if b != 0 else 0

def get_protocol_name(proto_num):
    """
    Get protocol name from protocol number
    
    Args:
        proto_num (int): Protocol number
        
    Returns:
        str: Protocol name
    """
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'IPv6-ICMP',
        132: 'SCTP'
    }
    
    return protocols.get(proto_num, f'Unknown({proto_num})')
