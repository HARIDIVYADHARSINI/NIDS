import logging
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
import socket
import struct
from datetime import datetime

logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    """
    Analyzes network traffic for patterns and statistics
    """
    
    def __init__(self):
        """Initialize the traffic analyzer"""
        self.protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            58: 'IPv6-ICMP',
            132: 'SCTP'
        }
        
        # Historical data for trend analysis
        self.history = {
            'protocol_counts': [],
            'source_ips': defaultdict(list),
            'destination_ips': defaultdict(list),
            'packet_lengths': [],
            'timestamps': []
        }
        
        # Time window for analysis (in seconds)
        self.time_window = 300  # 5 minutes
        logger.info("Traffic analyzer initialized")
    
    def analyze(self, packets):
        """
        Analyze a set of packets
        
        Args:
            packets (list): List of scapy packets
            
        Returns:
            dict: Analysis results
        """
        if not packets:
            logger.debug("No packets to analyze")
            return {
                'protocol_counts': {},
                'source_ips': [],
                'destination_ips': [],
                'packet_lengths': [],
                'port_activity': {},
                'connections': [],
                'timestamp': datetime.now()
            }
        
        # Initialize analysis results
        result = {
            'protocol_counts': {},
            'source_ips': [],
            'destination_ips': [],
            'packet_lengths': [],
            'port_activity': defaultdict(int),
            'connections': [],
            'timestamp': datetime.now()
        }
        
        # Analyze each packet
        for packet in packets:
            try:
                # Extract IP layer if it exists
                if 'IP' in packet:
                    ip_layer = packet['IP']
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    proto = ip_layer.proto
                    
                    # Add to source and destination IP lists
                    result['source_ips'].append(src_ip)
                    result['destination_ips'].append(dst_ip)
                    
                    # Protocol counting
                    proto_name = self.protocols.get(proto, f'UNKNOWN({proto})')
                    result['protocol_counts'][proto_name] = result['protocol_counts'].get(proto_name, 0) + 1
                    
                    # Packet length
                    if hasattr(packet, 'len'):
                        result['packet_lengths'].append(packet.len)
                    
                    # Port activity analysis
                    if proto == 6 and 'TCP' in packet:  # TCP
                        tcp = packet['TCP']
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        result['port_activity'][dst_port] += 1
                        result['connections'].append((src_ip, src_port, dst_ip, dst_port, 'TCP'))
                        
                    elif proto == 17 and 'UDP' in packet:  # UDP
                        udp = packet['UDP']
                        src_port = udp.sport
                        dst_port = udp.dport
                        result['port_activity'][dst_port] += 1
                        result['connections'].append((src_ip, src_port, dst_ip, dst_port, 'UDP'))
                
                # Handle other protocol types
                elif 'IPv6' in packet:
                    ipv6_layer = packet['IPv6']
                    src_ip = ipv6_layer.src
                    dst_ip = ipv6_layer.dst
                    
                    result['source_ips'].append(src_ip)
                    result['destination_ips'].append(dst_ip)
                    
                    proto_name = 'IPv6'
                    result['protocol_counts'][proto_name] = result['protocol_counts'].get(proto_name, 0) + 1
                
                elif 'ARP' in packet:
                    proto_name = 'ARP'
                    result['protocol_counts'][proto_name] = result['protocol_counts'].get(proto_name, 0) + 1
                
                else:
                    # Unknown protocol, try to get a name if available
                    proto_name = getattr(packet, 'name', 'UNKNOWN')
                    result['protocol_counts'][proto_name] = result['protocol_counts'].get(proto_name, 0) + 1
            
            except Exception as e:
                logger.error(f"Error analyzing packet: {str(e)}")
        
        # Update historical data
        timestamp = datetime.now()
        self.history['timestamps'].append(timestamp)
        self.history['protocol_counts'].append(result['protocol_counts'])
        self.history['packet_lengths'].extend(result['packet_lengths'])
        
        for ip in result['source_ips']:
            self.history['source_ips'][ip].append(timestamp)
        
        for ip in result['destination_ips']:
            self.history['destination_ips'][ip].append(timestamp)
        
        # Clean up old historical data
        self._clean_history()
        
        return result
    
    def _clean_history(self):
        """Remove data older than the time window"""
        current_time = datetime.now()
        cutoff_time = current_time.timestamp() - self.time_window
        
        # Filter timestamps
        new_timestamps = []
        for timestamp in self.history['timestamps']:
            if timestamp.timestamp() >= cutoff_time:
                new_timestamps.append(timestamp)
        
        # Update timestamps list
        self.history['timestamps'] = new_timestamps
        
        # If all timestamps were removed, clear all history
        if not new_timestamps:
            self.history['protocol_counts'] = []
            self.history['source_ips'] = defaultdict(list)
            self.history['destination_ips'] = defaultdict(list)
            self.history['packet_lengths'] = []
            return
        
        # Clean protocol counts
        self.history['protocol_counts'] = self.history['protocol_counts'][-len(new_timestamps):]
        
        # Clean source IPs
        for ip in list(self.history['source_ips'].keys()):
            self.history['source_ips'][ip] = [
                ts for ts in self.history['source_ips'][ip] 
                if ts.timestamp() >= cutoff_time
            ]
            if not self.history['source_ips'][ip]:
                del self.history['source_ips'][ip]
        
        # Clean destination IPs
        for ip in list(self.history['destination_ips'].keys()):
            self.history['destination_ips'][ip] = [
                ts for ts in self.history['destination_ips'][ip] 
                if ts.timestamp() >= cutoff_time
            ]
            if not self.history['destination_ips'][ip]:
                del self.history['destination_ips'][ip]
    
    def get_ip_frequency(self, top_n=10):
        """
        Get the most frequent IP addresses
        
        Args:
            top_n (int): Number of top IPs to return
            
        Returns:
            dict: Top source and destination IPs with counts
        """
        src_ip_counts = {ip: len(timestamps) for ip, timestamps in self.history['source_ips'].items()}
        dst_ip_counts = {ip: len(timestamps) for ip, timestamps in self.history['destination_ips'].items()}
        
        # Sort by count, get top N
        top_sources = dict(sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n])
        top_destinations = dict(sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n])
        
        return {
            'top_sources': top_sources,
            'top_destinations': top_destinations
        }
    
    def get_protocol_distribution(self):
        """
        Get the distribution of protocols
        
        Returns:
            dict: Protocol distribution
        """
        if not self.history['protocol_counts']:
            return {}
        
        # Combine all protocol counts
        combined = defaultdict(int)
        for counts in self.history['protocol_counts']:
            for proto, count in counts.items():
                combined[proto] += count
        
        return combined
    
    def get_packet_statistics(self):
        """
        Get statistics about packet sizes
        
        Returns:
            dict: Packet statistics
        """
        if not self.history['packet_lengths']:
            return {
                'min': 0,
                'max': 0,
                'mean': 0,
                'median': 0,
                'std': 0
            }
        
        lengths = np.array(self.history['packet_lengths'])
        
        return {
            'min': int(np.min(lengths)),
            'max': int(np.max(lengths)),
            'mean': float(np.mean(lengths)),
            'median': float(np.median(lengths)),
            'std': float(np.std(lengths))
        }
    
    def detect_port_scanning(self, threshold=5):
        """
        Detect potential port scanning activity
        
        Args:
            threshold (int): Threshold for unique ports from same source IP
            
        Returns:
            list: Potential port scanners
        """
        # Group connections by source IP and count unique destination ports
        ip_port_groups = defaultdict(set)
        
        for src_ip, src_port, dst_ip, dst_port, proto in [
            conn for result in self.history.get('connections', []) 
            for conn in result
        ]:
            ip_port_groups[src_ip].add((dst_ip, dst_port))
        
        # Find IPs accessing many different ports
        potential_scanners = []
        for ip, port_set in ip_port_groups.items():
            if len(port_set) >= threshold:
                dest_ips = set(dst_ip for dst_ip, _ in port_set)
                dest_ports = set(dst_port for _, dst_port in port_set)
                
                potential_scanners.append({
                    'source_ip': ip,
                    'unique_destinations': len(dest_ips),
                    'unique_ports': len(dest_ports),
                    'total_connections': len(port_set)
                })
        
        return sorted(potential_scanners, key=lambda x: x['unique_ports'], reverse=True)
