import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from collections import defaultdict, Counter
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Detect anomalies in network traffic using statistical and machine learning methods
    """
    
    def __init__(self, threshold=95):
        """
        Initialize the anomaly detector
        
        Args:
            threshold (int): Detection threshold (percentile)
        """
        self.threshold = threshold
        
        # Historical data storage
        self.history = {
            'traffic_volumes': [],
            'unique_ips': [],
            'packet_rates': [],
            'port_activity': defaultdict(list),
            'protocol_ratios': [],
            'timestamps': []
        }
        
        # Window size for historical data (in seconds)
        self.window_size = 300  # 5 minutes
        
        # Initialize the anomaly detection model
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.05,  # Expect about 5% of traffic to be anomalous
            random_state=42
        )
        
        # Baseline values
        self.baselines = {
            'avg_packet_rate': None,
            'avg_unique_ips': None,
            'common_ports': Counter(),
            'protocol_distribution': Counter()
        }
        
        self.is_trained = False
        logger.info("Anomaly detector initialized")
    
    def detect(self, analysis_results):
        """
        Detect anomalies in the current traffic
        
        Args:
            analysis_results (dict): Results from traffic analyzer
            
        Returns:
            list: Detected anomalies
        """
        if not analysis_results:
            return []
        
        # Update history
        timestamp = analysis_results.get('timestamp', datetime.now())
        self.history['timestamps'].append(timestamp)
        
        # Traffic volume (number of packets)
        total_packets = sum(analysis_results['protocol_counts'].values())
        self.history['traffic_volumes'].append(total_packets)
        
        # Unique IPs
        unique_ips = len(set(analysis_results['source_ips']).union(set(analysis_results['destination_ips'])))
        self.history['unique_ips'].append(unique_ips)
        
        # Packet rate (if we have more than one data point)
        if len(self.history['timestamps']) > 1:
            time_diff = (timestamp - self.history['timestamps'][-2]).total_seconds()
            if time_diff > 0:
                packet_rate = total_packets / time_diff
            else:
                packet_rate = 0
            self.history['packet_rates'].append(packet_rate)
        else:
            self.history['packet_rates'].append(0)
        
        # Port activity
        for port, count in analysis_results.get('port_activity', {}).items():
            self.history['port_activity'][port].append(count)
        
        # Protocol ratios
        protocol_counts = analysis_results['protocol_counts']
        if total_packets > 0:
            protocol_ratios = {proto: count / total_packets for proto, count in protocol_counts.items()}
        else:
            protocol_ratios = {proto: 0 for proto in protocol_counts}
        self.history['protocol_ratios'].append(protocol_ratios)
        
        # Clean up old history
        self._clean_history()
        
        # Train model if we have enough data and haven't trained yet
        if len(self.history['timestamps']) >= 10 and not self.is_trained:
            self._train_model()
        
        # Establish baseline if not set
        if self.baselines['avg_packet_rate'] is None and len(self.history['packet_rates']) >= 5:
            self._establish_baseline()
        
        # Detect anomalies
        detected_anomalies = []
        
        # Only perform detection if we have enough history
        if len(self.history['timestamps']) < 5:
            return []
        
        # 1. Check for traffic volume spikes
        if self.baselines['avg_packet_rate'] is not None:
            current_rate = self.history['packet_rates'][-1]
            if current_rate > self.baselines['avg_packet_rate'] * 3:  # Traffic 3x normal
                anomaly = {
                    'type': 'Traffic Spike',
                    'metric': 'packet_rate',
                    'value': current_rate,
                    'baseline': self.baselines['avg_packet_rate'],
                    'deviation': current_rate / self.baselines['avg_packet_rate'],
                    'severity': 'Medium' if current_rate < self.baselines['avg_packet_rate'] * 5 else 'High'
                }
                detected_anomalies.append(anomaly)
        
        # 2. Check for unusual number of unique IPs
        if self.baselines['avg_unique_ips'] is not None:
            current_unique_ips = self.history['unique_ips'][-1]
            if current_unique_ips > self.baselines['avg_unique_ips'] * 2:  # 2x normal
                anomaly = {
                    'type': 'Unusual IP Count',
                    'metric': 'unique_ips',
                    'value': current_unique_ips,
                    'baseline': self.baselines['avg_unique_ips'],
                    'deviation': current_unique_ips / self.baselines['avg_unique_ips'],
                    'severity': 'Medium'
                }
                detected_anomalies.append(anomaly)
        
        # 3. Check for unusual port activity
        for port, counts in self.history['port_activity'].items():
            if len(counts) < 3:
                continue
                
            port_baseline = np.mean(counts[:-1])
            current_count = counts[-1]
            
            # Skip if baseline is very low (avoid false positives)
            if port_baseline < 2:
                continue
                
            # Check if current activity is significantly higher than baseline
            if current_count > port_baseline * 3:
                # Check if this is a common port
                is_common_port = port in self.baselines['common_ports']
                
                anomaly = {
                    'type': 'Port Activity Spike',
                    'metric': f'port_{port}',
                    'value': current_count,
                    'baseline': port_baseline,
                    'deviation': current_count / port_baseline,
                    'port': port,
                    'severity': 'Low' if is_common_port else 'Medium'
                }
                detected_anomalies.append(anomaly)
        
        # 4. Check for unusual protocol distribution
        if len(self.history['protocol_ratios']) >= 3:
            current_ratios = self.history['protocol_ratios'][-1]
            
            for proto, ratio in current_ratios.items():
                # Skip protocols we haven't seen enough to establish baseline
                prev_ratios = [prev.get(proto, 0) for prev in self.history['protocol_ratios'][:-1]]
                if len([r for r in prev_ratios if r > 0]) < 2:
                    continue
                
                baseline_ratio = np.mean([r for r in prev_ratios if r > 0])
                
                # Skip if baseline is very low (avoid false positives)
                if baseline_ratio < 0.05:
                    continue
                
                # Check if current ratio is significantly different
                if ratio > 0 and (ratio > baseline_ratio * 3 or ratio < baseline_ratio * 0.2):
                    anomaly = {
                        'type': 'Protocol Distribution Shift',
                        'metric': f'protocol_{proto}',
                        'value': ratio,
                        'baseline': baseline_ratio,
                        'deviation': ratio / baseline_ratio if baseline_ratio > 0 else float('inf'),
                        'protocol': proto,
                        'severity': 'Low'
                    }
                    detected_anomalies.append(anomaly)
        
        # 5. Use ML model for advanced detection if trained
        if self.is_trained and len(self.history['packet_rates']) >= 5:
            # Create feature vector
            features = self._create_feature_vector()
            
            # Get anomaly score from model
            anomaly_scores = self.model.decision_function(features)
            
            # Lower scores indicate more anomalous behavior
            if anomaly_scores[-1] < -0.5:  # Threshold for anomaly detection
                anomaly = {
                    'type': 'ML-Detected Anomaly',
                    'metric': 'anomaly_score',
                    'value': float(anomaly_scores[-1]),
                    'baseline': 0,
                    'deviation': abs(anomaly_scores[-1]),
                    'severity': 'High' if anomaly_scores[-1] < -0.8 else 'Medium'
                }
                detected_anomalies.append(anomaly)
        
        # Log detected anomalies
        if detected_anomalies:
            logger.warning(f"Detected {len(detected_anomalies)} anomalies: {[a['type'] for a in detected_anomalies]}")
        
        return detected_anomalies
    
    def _clean_history(self):
        """Remove data points older than the window size"""
        if not self.history['timestamps']:
            return
            
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.window_size)
        
        # Find the index where we should start keeping data
        cutoff_index = 0
        for i, ts in enumerate(self.history['timestamps']):
            if ts >= cutoff_time:
                cutoff_index = i
                break
        
        # Remove old data
        if cutoff_index > 0:
            self.history['timestamps'] = self.history['timestamps'][cutoff_index:]
            self.history['traffic_volumes'] = self.history['traffic_volumes'][cutoff_index:]
            self.history['unique_ips'] = self.history['unique_ips'][cutoff_index:]
            self.history['packet_rates'] = self.history['packet_rates'][cutoff_index:]
            self.history['protocol_ratios'] = self.history['protocol_ratios'][cutoff_index:]
            
            # Clean port activity history
            for port in self.history['port_activity']:
                self.history['port_activity'][port] = self.history['port_activity'][port][cutoff_index:]
    
    def _establish_baseline(self):
        """Establish baseline values for anomaly detection"""
        if len(self.history['packet_rates']) < 5:
            return
            
        # Average packet rate
        self.baselines['avg_packet_rate'] = np.mean(self.history['packet_rates'])
        
        # Average unique IPs
        self.baselines['avg_unique_ips'] = np.mean(self.history['unique_ips'])
        
        # Common ports (from port activity history)
        port_counts = Counter()
        for port, counts in self.history['port_activity'].items():
            port_counts[port] = sum(counts)
        
        # Keep top 10 ports as "common"
        self.baselines['common_ports'] = Counter(dict(port_counts.most_common(10)))
        
        # Protocol distribution
        proto_counts = Counter()
        for ratios in self.history['protocol_ratios']:
            for proto, ratio in ratios.items():
                proto_counts[proto] += ratio
        
        self.baselines['protocol_distribution'] = proto_counts
        
        logger.info("Established baseline values for anomaly detection")
    
    def _create_feature_vector(self):
        """
        Create a feature vector for ML-based anomaly detection
        
        Returns:
            numpy.ndarray: Feature matrix
        """
        # Number of recent observations to use
        n_obs = min(len(self.history['packet_rates']), 100)
        
        # Features:
        # 1. Packet rate
        packet_rates = np.array(self.history['packet_rates'][-n_obs:]).reshape(-1, 1)
        
        # 2. Unique IPs
        unique_ips = np.array(self.history['unique_ips'][-n_obs:]).reshape(-1, 1)
        
        # 3. Protocol ratios (use most common protocols)
        protocols = set()
        for ratios in self.history['protocol_ratios'][-n_obs:]:
            protocols.update(ratios.keys())
        
        # Create array for protocol ratios
        proto_features = np.zeros((n_obs, len(protocols)))
        
        for i, ratios in enumerate(self.history['protocol_ratios'][-n_obs:]):
            for j, proto in enumerate(protocols):
                proto_features[i, j] = ratios.get(proto, 0)
        
        # Combine features
        features = np.hstack((packet_rates, unique_ips, proto_features))
        
        return features
    
    def _train_model(self):
        """Train the ML model on historical data"""
        if len(self.history['packet_rates']) < 10:
            return
            
        try:
            # Create feature matrix
            features = self._create_feature_vector()
            
            # Train model
            self.model.fit(features)
            self.is_trained = True
            logger.info("Trained anomaly detection model")
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {str(e)}")
    
    def reset_baseline(self):
        """Reset baseline values"""
        self.baselines = {
            'avg_packet_rate': None,
            'avg_unique_ips': None,
            'common_ports': Counter(),
            'protocol_distribution': Counter()
        }
        logger.info("Reset anomaly detection baselines")
    
    def set_threshold(self, threshold):
        """
        Set the anomaly detection threshold
        
        Args:
            threshold (int): Detection threshold (0-100)
        """
        self.threshold = max(0, min(100, threshold))
        logger.info(f"Set anomaly detection threshold to {self.threshold}")
