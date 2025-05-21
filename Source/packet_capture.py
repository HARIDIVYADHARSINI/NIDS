import scapy.all as scapy
from scapy.all import sniff
import threading
import logging
from collections import deque
import time

logger = logging.getLogger(__name__)

class PacketCapture:
    """
    Class for capturing network packets using Scapy
    """
    
    def __init__(self, interface="any"):
        """
        Initialize the packet capture module
        
        Args:
            interface (str): Network interface to capture packets from
        """
        self.interface = interface
        self.packet_buffer = deque(maxlen=10000)  # Store last 10k packets
        self.packet_lock = threading.Lock()
        logger.info(f"Packet capture initialized on interface: {interface}")
    
    def capture(self, count=10, timeout=1, filter_str=None):
        """
        Capture packets from the network
        
        Args:
            count (int): Maximum number of packets to capture
            timeout (int): Timeout in seconds
            filter_str (str): BPF filter string
            
        Returns:
            list: Captured packets
        """
        try:
            packets = sniff(
                iface=self.interface,
                count=count,
                timeout=timeout,
                filter=filter_str,
                store=True
            )
            
            # Store packets in buffer
            with self.packet_lock:
                for packet in packets:
                    self.packet_buffer.append(packet)
            
            if packets:
                logger.debug(f"Captured {len(packets)} packets")
            
            return packets
        except Exception as e:
            logger.error(f"Error capturing packets: {str(e)}")
            return []
    
    def capture_continuous(self, callback=None, stop_event=None, filter_str=None):
        """
        Continuously capture packets in a separate thread
        
        Args:
            callback (function): Callback function to process captured packets
            stop_event (Event): Threading event to signal when to stop
            filter_str (str): BPF filter string
        """
        if stop_event is None:
            stop_event = threading.Event()
            
        def packet_handler(packet):
            with self.packet_lock:
                self.packet_buffer.append(packet)
            
            if callback:
                callback(packet)
            
            if stop_event.is_set():
                return True  # Signal to stop sniffing
        
        try:
            logger.info(f"Starting continuous packet capture on {self.interface}")
            sniff(
                iface=self.interface,
                prn=packet_handler,
                filter=filter_str,
                store=False,
                stop_filter=lambda p: stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Error in continuous packet capture: {str(e)}")
    
    def get_packets(self, count=None):
        """
        Get packets from the buffer
        
        Args:
            count (int): Number of packets to retrieve
            
        Returns:
            list: Packets from the buffer
        """
        with self.packet_lock:
            if count is None:
                return list(self.packet_buffer)
            else:
                return list(self.packet_buffer)[-count:]
    
    def clear_buffer(self):
        """Clear the packet buffer"""
        with self.packet_lock:
            self.packet_buffer.clear()
        logger.debug("Packet buffer cleared")

    def get_packet_count(self):
        """
        Get the number of packets in the buffer
        
        Returns:
            int: Number of packets
        """
        with self.packet_lock:
            return len(self.packet_buffer)
            
    def get_interface(self):
        """Get the current interface"""
        return self.interface
    
    def set_interface(self, interface):
        """Set the interface for packet capture"""
        self.interface = interface
        logger.info(f"Packet capture interface set to: {interface}")
