import json
import os
import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class RuleEngine:
    """
    Rule-based detection engine for network traffic
    """
    
    def __init__(self, rules_file):
        """
        Initialize the rule engine
        
        Args:
            rules_file (str): Path to the JSON rules file
        """
        self.rules_file = rules_file
        self.rules = []
        
        # Create default rules if file doesn't exist
        if not os.path.exists(rules_file):
            self._create_default_rules()
        
        # Load rules from file
        self.load_rules()
        logger.info(f"Rule engine initialized with {len(self.rules)} rules")
    
    def load_rules(self):
        """Load rules from the rules file"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    self.rules = json.load(f)
                logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file}")
            else:
                logger.warning(f"Rules file {self.rules_file} not found")
                self._create_default_rules()
        except Exception as e:
            logger.error(f"Error loading rules: {str(e)}")
            self._create_default_rules()
    
    def save_rules(self):
        """Save rules to the rules file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
            
            with open(self.rules_file, 'w') as f:
                json.dump(self.rules, f, indent=2)
            logger.info(f"Saved {len(self.rules)} rules to {self.rules_file}")
        except Exception as e:
            logger.error(f"Error saving rules: {str(e)}")
    
    def _create_default_rules(self):
        """Create default rules"""
        self.rules = [
            {
                "name": "TCP SYN Flood",
                "description": "Detects potential TCP SYN flood attacks",
                "condition": "packet.haslayer('TCP') and packet['TCP'].flags & 0x02 and not packet['TCP'].flags & 0x10",
                "count_threshold": 100,
                "time_window": 60,
                "severity": "High",
                "enabled": True
            },
            {
                "name": "ICMP Flood",
                "description": "Detects ICMP flood attacks",
                "condition": "packet.haslayer('ICMP')",
                "count_threshold": 50,
                "time_window": 60,
                "severity": "Medium",
                "enabled": True
            },
            {
                "name": "Port Scan Detection",
                "description": "Detects potential port scanning activity",
                "condition": "packet.haslayer('TCP') and packet['TCP'].flags & 0x02",
                "unique_ports_threshold": 15,
                "time_window": 120,
                "severity": "Medium",
                "enabled": True
            },
            {
                "name": "DNS Amplification",
                "description": "Detects potential DNS amplification attacks",
                "condition": "packet.haslayer('UDP') and packet.haslayer('DNS') and packet['UDP'].dport == 53",
                "count_threshold": 30,
                "time_window": 60,
                "severity": "High",
                "enabled": True
            },
            {
                "name": "HTTP Flooding",
                "description": "Detects HTTP flooding attacks",
                "condition": "packet.haslayer('TCP') and (packet['TCP'].dport == 80 or packet['TCP'].dport == 443)",
                "count_threshold": 200,
                "time_window": 60,
                "severity": "Medium",
                "enabled": True
            },
            {
                "name": "ARP Spoofing",
                "description": "Detects potential ARP spoofing attacks",
                "condition": "packet.haslayer('ARP') and packet['ARP'].op == 2",  # ARP reply
                "count_threshold": 10,
                "time_window": 30,
                "severity": "Critical",
                "enabled": True
            },
            {
                "name": "SSH Brute Force",
                "description": "Detects potential SSH brute force attacks",
                "condition": "packet.haslayer('TCP') and packet['TCP'].dport == 22",
                "count_threshold": 10,
                "time_window": 60,
                "severity": "High",
                "enabled": True
            }
        ]
        
        self.save_rules()
    
    def check_rules(self, packets, analysis_results=None):
        """
        Check packets against all rules
        
        Args:
            packets (list): List of packets to check
            analysis_results (dict): Results from traffic analyzer (optional)
            
        Returns:
            list: Rule violations detected
        """
        violations = []
        
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            try:
                # Different rule types require different checking logic
                if 'condition' in rule:
                    # Evaluate rule condition on each packet
                    matching_packets = self._check_packet_condition(packets, rule)
                    
                    # Check if the number of matching packets exceeds the threshold
                    if 'count_threshold' in rule and len(matching_packets) >= rule['count_threshold']:
                        violations.append({
                            'rule_name': rule['name'],
                            'description': rule['description'],
                            'severity': rule['severity'],
                            'matching_packets': len(matching_packets),
                            'threshold': rule['count_threshold']
                        })
                
                # Special handling for port scan detection
                if rule['name'] == "Port Scan Detection" and analysis_results:
                    port_scan_violations = self._check_port_scan(packets, rule, analysis_results)
                    violations.extend(port_scan_violations)
                    
            except Exception as e:
                logger.error(f"Error checking rule '{rule['name']}': {str(e)}")
        
        if violations:
            logger.warning(f"Detected {len(violations)} rule violations")
            
        return violations
    
    def _check_packet_condition(self, packets, rule):
        """
        Check if packets match a rule condition
        
        Args:
            packets (list): List of packets to check
            rule (dict): Rule definition
            
        Returns:
            list: Matching packets
        """
        matching_packets = []
        condition = rule['condition']
        
        for packet in packets:
            try:
                # Use eval to evaluate the rule condition
                # This is safe because we control the rule conditions
                if eval(condition, {'packet': packet}):
                    matching_packets.append(packet)
            except Exception as e:
                # Skip packets that cause evaluation errors
                logger.debug(f"Error evaluating rule condition: {str(e)}")
                continue
        
        return matching_packets
    
    def _check_port_scan(self, packets, rule, analysis_results):
        """
        Check for port scanning activity
        
        Args:
            packets (list): List of packets
            rule (dict): Rule definition
            analysis_results (dict): Traffic analysis results
            
        Returns:
            list: Rule violations
        """
        violations = []
        
        # Get all TCP SYN packets
        syn_packets = self._check_packet_condition(packets, rule)
        if not syn_packets:
            return []
        
        # Group by source IP and count unique destination ports
        src_ip_dst_ports = {}
        
        for packet in syn_packets:
            if 'IP' in packet and 'TCP' in packet:
                src_ip = packet['IP'].src
                dst_port = packet['TCP'].dport
                
                if src_ip not in src_ip_dst_ports:
                    src_ip_dst_ports[src_ip] = set()
                    
                src_ip_dst_ports[src_ip].add(dst_port)
        
        # Check if any source IP is scanning multiple ports
        threshold = rule.get('unique_ports_threshold', 15)
        
        for src_ip, dst_ports in src_ip_dst_ports.items():
            if len(dst_ports) >= threshold:
                violations.append({
                    'rule_name': rule['name'],
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'source_ip': src_ip,
                    'unique_ports': len(dst_ports),
                    'threshold': threshold
                })
        
        return violations
    
    def add_rule(self, rule):
        """
        Add a new rule
        
        Args:
            rule (dict): Rule definition
        """
        if not self._validate_rule(rule):
            logger.error("Invalid rule definition")
            return False
            
        self.rules.append(rule)
        self.save_rules()
        logger.info(f"Added new rule: {rule['name']}")
        return True
    
    def update_rule(self, index, rule):
        """
        Update an existing rule
        
        Args:
            index (int): Rule index
            rule (dict): Updated rule definition
        """
        if not self._validate_rule(rule):
            logger.error("Invalid rule definition")
            return False
            
        if 0 <= index < len(self.rules):
            self.rules[index] = rule
            self.save_rules()
            logger.info(f"Updated rule: {rule['name']}")
            return True
        else:
            logger.error(f"Invalid rule index: {index}")
            return False
    
    def delete_rule(self, index):
        """
        Delete a rule
        
        Args:
            index (int): Rule index
        """
        if 0 <= index < len(self.rules):
            rule_name = self.rules[index]['name']
            del self.rules[index]
            self.save_rules()
            logger.info(f"Deleted rule: {rule_name}")
            return True
        else:
            logger.error(f"Invalid rule index: {index}")
            return False
    
    def get_rules(self):
        """
        Get all rules
        
        Returns:
            list: All rules
        """
        return self.rules
    
    def _validate_rule(self, rule):
        """
        Validate a rule definition
        
        Args:
            rule (dict): Rule definition
            
        Returns:
            bool: True if valid, False otherwise
        """
        required_fields = ['name', 'description', 'severity']
        
        # Check required fields
        for field in required_fields:
            if field not in rule:
                logger.error(f"Missing required field in rule: {field}")
                return False
        
        # Check rule has either a condition or other detection mechanism
        if 'condition' not in rule:
            logger.error("Rule must have a condition")
            return False
        
        # Validate severity
        valid_severities = ['Low', 'Medium', 'High', 'Critical']
        if rule['severity'] not in valid_severities:
            logger.error(f"Invalid severity: {rule['severity']}")
            return False
        
        return True
