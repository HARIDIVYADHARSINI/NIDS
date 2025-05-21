import logging
from datetime import datetime
import json
import os

logger = logging.getLogger(__name__)

class AlertSystem:
    """
    System for generating and managing alerts
    """
    
    def __init__(self, max_alerts=1000):
        """
        Initialize the alert system
        
        Args:
            max_alerts (int): Maximum number of alerts to store
        """
        self.max_alerts = max_alerts
        self.alerts = []
        logger.info("Alert system initialized")
    
    def generate_alerts(self, anomalies=None, rule_violations=None, timestamp=None):
        """
        Generate alerts from anomalies and rule violations
        
        Args:
            anomalies (list): List of detected anomalies
            rule_violations (list): List of rule violations
            timestamp (datetime): Timestamp for the alerts (default: current time)
            
        Returns:
            list: Generated alerts
        """
        if timestamp is None:
            timestamp = datetime.now()
            
        new_alerts = []
        
        # Process anomalies
        if anomalies:
            for anomaly in anomalies:
                alert = {
                    'type': 'Anomaly',
                    'subtype': anomaly.get('type', 'Unknown'),
                    'message': self._format_anomaly_message(anomaly),
                    'severity': anomaly.get('severity', 'Medium'),
                    'details': anomaly,
                    'timestamp': timestamp
                }
                new_alerts.append(alert)
        
        # Process rule violations
        if rule_violations:
            for violation in rule_violations:
                alert = {
                    'type': 'Rule Violation',
                    'subtype': violation.get('rule_name', 'Unknown'),
                    'message': self._format_rule_violation_message(violation),
                    'severity': violation.get('severity', 'Medium'),
                    'details': violation,
                    'timestamp': timestamp
                }
                new_alerts.append(alert)
        
        # Add to alert storage
        self.alerts.extend(new_alerts)
        
        # Trim if we exceed max alerts
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
        
        # Log the alerts
        for alert in new_alerts:
            log_level = logging.WARNING
            if alert['severity'] == 'Critical':
                log_level = logging.CRITICAL
            elif alert['severity'] == 'High':
                log_level = logging.ERROR
                
            logger.log(log_level, f"ALERT: {alert['type']}: {alert['message']}")
        
        return new_alerts
    
    def _format_anomaly_message(self, anomaly):
        """
        Format an anomaly into a human-readable message
        
        Args:
            anomaly (dict): Anomaly details
            
        Returns:
            str: Formatted message
        """
        anomaly_type = anomaly.get('type', 'Unknown')
        
        if 'Traffic Spike' in anomaly_type:
            return f"Traffic spike detected - {anomaly.get('value', 0):.1f} packets/sec, {anomaly.get('deviation', 0):.1f}x normal"
            
        elif 'Unusual IP Count' in anomaly_type:
            return f"Unusual number of IP addresses - {anomaly.get('value', 0)} unique IPs, {anomaly.get('deviation', 0):.1f}x normal"
            
        elif 'Port Activity' in anomaly_type:
            return f"Unusual activity on port {anomaly.get('port', 'unknown')} - {anomaly.get('value', 0)} packets, {anomaly.get('deviation', 0):.1f}x normal"
            
        elif 'Protocol Distribution' in anomaly_type:
            return f"Unusual {anomaly.get('protocol', 'unknown')} protocol activity - {anomaly.get('deviation', 0):.1f}x normal"
            
        elif 'ML-Detected' in anomaly_type:
            return f"Machine learning detected unusual network behavior - score: {anomaly.get('value', 0):.2f}"
            
        else:
            return f"{anomaly_type} detected - {anomaly.get('metric', 'unknown')}: {anomaly.get('value', 0)}"
    
    def _format_rule_violation_message(self, violation):
        """
        Format a rule violation into a human-readable message
        
        Args:
            violation (dict): Rule violation details
            
        Returns:
            str: Formatted message
        """
        rule_name = violation.get('rule_name', 'Unknown rule')
        
        if 'Port Scan' in rule_name:
            return f"Potential port scan from {violation.get('source_ip', 'unknown IP')} - {violation.get('unique_ports', 0)} ports scanned"
            
        elif 'TCP SYN Flood' in rule_name:
            return f"Potential TCP SYN flood attack - {violation.get('matching_packets', 0)} SYN packets detected"
            
        elif 'ICMP Flood' in rule_name:
            return f"Potential ICMP flood attack - {violation.get('matching_packets', 0)} ICMP packets detected"
            
        elif 'ARP Spoofing' in rule_name:
            return f"Potential ARP spoofing attack - {violation.get('matching_packets', 0)} suspicious ARP replies"
            
        elif 'SSH Brute Force' in rule_name:
            return f"Potential SSH brute force attack - {violation.get('matching_packets', 0)} SSH connection attempts"
            
        else:
            return f"{rule_name}: {violation.get('description', 'No description')}"
    
    def get_alerts(self, count=None, severity=None, alert_type=None, start_time=None, end_time=None):
        """
        Get filtered alerts
        
        Args:
            count (int): Maximum number of alerts to return
            severity (str/list): Filter by severity
            alert_type (str/list): Filter by alert type
            start_time (datetime): Filter by start time
            end_time (datetime): Filter by end time
            
        Returns:
            list: Filtered alerts
        """
        filtered = self.alerts
        
        # Filter by severity
        if severity:
            if isinstance(severity, str):
                severity = [severity]
            filtered = [alert for alert in filtered if alert['severity'] in severity]
        
        # Filter by type
        if alert_type:
            if isinstance(alert_type, str):
                alert_type = [alert_type]
            filtered = [alert for alert in filtered if alert['type'] in alert_type]
        
        # Filter by time range
        if start_time:
            filtered = [alert for alert in filtered if alert['timestamp'] >= start_time]
        if end_time:
            filtered = [alert for alert in filtered if alert['timestamp'] <= end_time]
        
        # Sort by timestamp (newest first)
        filtered = sorted(filtered, key=lambda x: x['timestamp'], reverse=True)
        
        # Limit count if specified
        if count is not None:
            filtered = filtered[:count]
        
        return filtered
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts = []
        logger.info("All alerts cleared")
    
    def export_alerts(self, filename):
        """
        Export alerts to a JSON file
        
        Args:
            filename (str): Path to export file
            
        Returns:
            bool: Success or failure
        """
        try:
            # Prepare alerts for serialization (convert datetime objects)
            export_data = []
            for alert in self.alerts:
                alert_copy = alert.copy()
                alert_copy['timestamp'] = alert_copy['timestamp'].isoformat()
                export_data.append(alert_copy)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
                
            logger.info(f"Exported {len(export_data)} alerts to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting alerts: {str(e)}")
            return False
    
    def import_alerts(self, filename):
        """
        Import alerts from a JSON file
        
        Args:
            filename (str): Path to import file
            
        Returns:
            bool: Success or failure
        """
        try:
            with open(filename, 'r') as f:
                import_data = json.load(f)
            
            # Convert string timestamps to datetime objects
            for alert in import_data:
                alert['timestamp'] = datetime.fromisoformat(alert['timestamp'])
            
            self.alerts = import_data
            logger.info(f"Imported {len(import_data)} alerts from {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error importing alerts: {str(e)}")
            return False
