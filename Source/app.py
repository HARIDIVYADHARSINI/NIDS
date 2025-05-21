import streamlit as st
import time
import threading
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import logging
import json
from datetime import datetime, timedelta

from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from anomaly_detector import AnomalyDetector
from rule_engine import RuleEngine
from alert_system import AlertSystem
from visualization import (
    create_traffic_volume_chart,
    create_protocol_distribution_chart,
    create_geo_map,
    create_alerts_table,
    create_packet_stats_chart
)
from logger import setup_logger
from config import INTERFACE, CAPTURE_TIMEOUT

# Setup logger
logger = setup_logger()

# Global variables for packet capture
PACKET_LIMIT = 100

# Initialize app state - moved to the beginning to avoid session state issues
if 'initialized' not in st.session_state:
    st.session_state.running = False
    st.session_state.alerts = []
    st.session_state.packets = []
    st.session_state.start_time = None
    st.session_state.stats = {
        'total_packets': 0,
        'packets_per_protocol': {},
        'source_ips': {},
        'destination_ips': {},
        'traffic_volume': [],
        'packet_sizes': [],
        'timestamps': []
    }
    st.session_state.log_entries = []
    st.session_state.packet_limit = PACKET_LIMIT
    st.session_state.bpf_filter = ""
    st.session_state.initialized = True

# Initialize components
packet_capture = PacketCapture(INTERFACE)
traffic_analyzer = TrafficAnalyzer()
anomaly_detector = AnomalyDetector()
rule_engine = RuleEngine('data/rules.json')
alert_system = AlertSystem()

def monitoring_thread():
    """Background thread for continuous packet capture and analysis"""
    st.session_state.start_time = datetime.now()
    
    # Limit the size of historical data
    MAX_TRAFFIC_HISTORY = 100
    MAX_PACKET_HISTORY = 10000
    
    while st.session_state.running:
        try:
            # Capture packets with configured limit and optional filter
            new_packets = packet_capture.capture(
                count=st.session_state.packet_limit,
                timeout=CAPTURE_TIMEOUT,
                filter_str=st.session_state.bpf_filter if st.session_state.bpf_filter else None
            )
            if new_packets:
                # Update stats
                st.session_state.packets.extend(new_packets)
                if len(st.session_state.packets) > MAX_PACKET_HISTORY:
                    st.session_state.packets = st.session_state.packets[-MAX_PACKET_HISTORY:]
                
                st.session_state.stats['total_packets'] += len(new_packets)
                
                # Analyze traffic
                analysis_results = traffic_analyzer.analyze(new_packets)
                
                # Update protocol statistics
                for protocol, count in analysis_results['protocol_counts'].items():
                    if protocol in st.session_state.stats['packets_per_protocol']:
                        st.session_state.stats['packets_per_protocol'][protocol] += count
                    else:
                        st.session_state.stats['packets_per_protocol'][protocol] = count
                
                # Update source IP statistics
                for ip in analysis_results['source_ips']:
                    if ip in st.session_state.stats['source_ips']:
                        st.session_state.stats['source_ips'][ip] += 1
                    else:
                        st.session_state.stats['source_ips'][ip] = 1
                
                # Update destination IP statistics        
                for ip in analysis_results['destination_ips']:
                    if ip in st.session_state.stats['destination_ips']:
                        st.session_state.stats['destination_ips'][ip] += 1
                    else:
                        st.session_state.stats['destination_ips'][ip] = 1
                
                # Record traffic volume with timestamp
                current_time = datetime.now()
                st.session_state.stats['traffic_volume'].append({
                    'timestamp': current_time,
                    'count': len(new_packets)
                })
                
                # Limit traffic volume history
                if len(st.session_state.stats['traffic_volume']) > MAX_TRAFFIC_HISTORY:
                    st.session_state.stats['traffic_volume'] = st.session_state.stats['traffic_volume'][-MAX_TRAFFIC_HISTORY:]
                
                # Record packet sizes and timestamps
                for packet in new_packets:
                    if hasattr(packet, 'len'):
                        st.session_state.stats['packet_sizes'].append(packet.len)
                        st.session_state.stats['timestamps'].append(current_time)
                
                # Limit packet size history
                if len(st.session_state.stats['packet_sizes']) > MAX_TRAFFIC_HISTORY:
                    st.session_state.stats['packet_sizes'] = st.session_state.stats['packet_sizes'][-MAX_TRAFFIC_HISTORY:]
                    st.session_state.stats['timestamps'] = st.session_state.stats['timestamps'][-MAX_TRAFFIC_HISTORY:]
                
                # Check for anomalies
                anomalies = anomaly_detector.detect(analysis_results)
                
                # Check rule violations
                rule_violations = rule_engine.check_rules(new_packets, analysis_results)
                
                # Generate alerts for any detected anomalies or rule violations
                if anomalies or rule_violations:
                    new_alerts = alert_system.generate_alerts(
                        anomalies=anomalies,
                        rule_violations=rule_violations,
                        timestamp=current_time
                    )
                    st.session_state.alerts.extend(new_alerts)
                    
                    # Log alerts to the system logger
                    for alert in new_alerts:
                        alert_message = f"ALERT: {alert['type']} - {alert['message']} - Severity: {alert['severity']}"
                        logger.warning(alert_message)
                        
                        # Also add to session state log entries for display in UI
                        st.session_state.log_entries.append({
                            'timestamp': current_time,
                            'level': alert['severity'],
                            'message': alert_message
                        })
        
        except Exception as e:
            error_msg = f"Error in monitoring thread: {str(e)}"
            logger.error(error_msg)
            
            # Add to session state log entries
            st.session_state.log_entries.append({
                'timestamp': datetime.now(),
                'level': 'ERROR',
                'message': error_msg
            })
            
        time.sleep(0.5)  # Brief pause to prevent excessive CPU usage

    logger.info("Monitoring stopped")

def start_monitoring():
    """Start the monitoring process"""
    if not st.session_state.running:
        st.session_state.running = True
        thread = threading.Thread(target=monitoring_thread)
        thread.daemon = True
        thread.start()
        logger.info("Network monitoring started")

def stop_monitoring():
    """Stop the monitoring process"""
    if st.session_state.running:
        st.session_state.running = False
        logger.info("Network monitoring stopped")

# UI Layout
st.title("Network Intrusion Detection System")

# Sidebar
with st.sidebar:
    st.header("Controls")
    
    if not st.session_state.running:
        start_col, reset_col = st.columns([2, 1])
        with start_col:
            if st.button("▶️ Start Monitoring", use_container_width=True):
                start_monitoring()
        with reset_col:
            if st.button("🔄 Reset", use_container_width=True):
                st.session_state.alerts = []
                st.session_state.packets = []
                st.session_state.stats = {
                    'total_packets': 0,
                    'packets_per_protocol': {},
                    'source_ips': {},
                    'destination_ips': {},
                    'traffic_volume': [],
                    'packet_sizes': [],
                    'timestamps': []
                }
                st.session_state.log_entries = []
                st.rerun()
    else:
        if st.button("⏹️ Stop Monitoring", use_container_width=True):
            stop_monitoring()
    
    st.divider()
    
    # Settings section with more options
    st.header("Settings")
    
    # Get available interfaces from utils.py
    from utils import get_local_interfaces
    available_interfaces = get_local_interfaces()
    
    # Add 'any' option
    if 'any' not in available_interfaces:
        available_interfaces = ['any'] + available_interfaces
    
    # Get current interface
    current_interface = packet_capture.get_interface()
    
    # Find index
    if current_interface in available_interfaces:
        default_index = available_interfaces.index(current_interface)
    else:
        default_index = 0
    
    selected_interface = st.selectbox(
        "Network Interface",
        options=available_interfaces,
        index=default_index
    )
    
    # Apply interface change if needed
    if selected_interface != current_interface:
        packet_capture.set_interface(selected_interface)
        st.success(f"Interface changed to {selected_interface}")
    
    # Add filters section
    st.subheader("Capture Filters")
    
    # BPF filter for packet capture
    bpf_filter = st.text_input("BPF Filter", 
                               value=st.session_state.bpf_filter,
                               placeholder="e.g. tcp port 80",
                               help="Berkeley Packet Filter syntax")
    
    # Packet limit slider
    packet_limit = st.slider("Max Packets per Capture", 
                            min_value=10, 
                            max_value=500, 
                            value=st.session_state.packet_limit,
                            step=10)
    
    # Apply button for filters
    if st.button("Apply Filters"):
        # Update session state
        st.session_state.bpf_filter = bpf_filter
        st.session_state.packet_limit = packet_limit
        
        if st.session_state.running:
            # Restart monitoring to apply new settings
            stop_monitoring()
            start_monitoring()
            st.success("Applied new filter settings")
        else:
            st.success("Filter settings saved")
    
    st.divider()
    
    # System status with improved styling
    st.header("System Status")
    
    # Status with colored pill
    status_color = "green" if st.session_state.running else "red"
    status_text = "Running" if st.session_state.running else "Stopped"
    st.markdown(f"""
    <div style="background-color: {status_color}; 
                color: white; 
                padding: 8px 12px; 
                border-radius: 20px;
                display: inline-block;
                font-weight: bold;">
        ⚫ {status_text}
    </div>
    """, unsafe_allow_html=True)
    
    # Display uptime
    if st.session_state.start_time:
        elapsed = datetime.now() - st.session_state.start_time
        st.metric("Uptime", str(elapsed).split('.')[0])
    
    # Display packet metrics
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Packets", st.session_state.stats['total_packets'])
    with col2:
        st.metric("Active Alerts", len(st.session_state.alerts))

# Main content area with added Logs tab
tab1, tab2, tab3, tab4, tab5 = st.tabs(["Dashboard", "Alerts", "Packet Analysis", "Logs", "Settings"])

with tab1:
    st.header("Network Traffic Overview")
    
    # Add refresh button and monitoring status
    status_col, refresh_col = st.columns([3, 1])
    with refresh_col:
        if st.button("🔄 Refresh Dashboard"):
            st.rerun()
    
    with status_col:
        if st.session_state.running:
            st.success("Monitoring is active - Dashboard updates in real-time")
        else:
            st.warning("Monitoring is inactive - Start monitoring to collect data")
    
    # Traffic metrics with improved styling
    col1, col2, col3 = st.columns(3)
    with col1:
        current_packets = len(st.session_state.packets[-100:]) if st.session_state.packets else 0
        st.metric(
            label="Packets Captured", 
            value=st.session_state.stats['total_packets'],
            delta=current_packets,
            delta_color="normal",
            help="Total number of packets captured since monitoring started"
        )
    with col2:
        recent_alerts = len([a for a in st.session_state.alerts if datetime.now() - a['timestamp'] < timedelta(minutes=5)])
        st.metric(
            label="Active Alerts", 
            value=len(st.session_state.alerts),
            delta=recent_alerts,
            delta_color="inverse",  # Red is bad (more alerts)
            help="Total number of security alerts detected"
        )
    with col3:
        unique_ips = len(set(st.session_state.stats['source_ips'].keys()).union(
            set(st.session_state.stats['destination_ips'].keys())))
        st.metric(
            label="Unique IPs", 
            value=unique_ips,
            help="Number of unique IP addresses observed"
        )
    
    # Add network activity summary
    if st.session_state.stats['traffic_volume']:
        # Calculate current traffic rate
        if len(st.session_state.stats['traffic_volume']) > 1:
            last_minute_traffic = [v for v in st.session_state.stats['traffic_volume'] 
                                 if datetime.now() - v['timestamp'] < timedelta(minutes=1)]
            packets_last_minute = sum(v['count'] for v in last_minute_traffic)
            
            # Display traffic statistics
            st.subheader("Current Network Activity")
            activity_cols = st.columns(3)
            with activity_cols[0]:
                st.metric("Packets/Minute", f"{packets_last_minute}")
            
            with activity_cols[1]:
                # Calculate bytes/sec if we have packet sizes
                if st.session_state.stats['packet_sizes']:
                    avg_packet_size = sum(st.session_state.stats['packet_sizes']) / len(st.session_state.stats['packet_sizes'])
                    bytes_per_min = packets_last_minute * avg_packet_size
                    if bytes_per_min > 1024*1024:
                        st.metric("Data Rate", f"{bytes_per_min/(1024*1024):.2f} MB/min")
                    elif bytes_per_min > 1024:
                        st.metric("Data Rate", f"{bytes_per_min/1024:.2f} KB/min")
                    else:
                        st.metric("Data Rate", f"{bytes_per_min:.0f} B/min")
                else:
                    st.metric("Data Rate", "N/A")
            
            with activity_cols[2]:
                # Calculate average packet size
                if st.session_state.stats['packet_sizes']:
                    avg_size = sum(st.session_state.stats['packet_sizes']) / len(st.session_state.stats['packet_sizes'])
                    st.metric("Avg Packet Size", f"{avg_size:.0f} bytes")
                else:
                    st.metric("Avg Packet Size", "N/A")
    
    # Traffic volume chart
    st.subheader("Traffic Volume Over Time")
    if st.session_state.stats['traffic_volume']:
        traffic_chart = create_traffic_volume_chart(st.session_state.stats['traffic_volume'])
        st.plotly_chart(traffic_chart, use_container_width=True)
    else:
        st.info("No traffic data available yet. Start monitoring to collect data.")
    
    # IP and Protocol section with tabs for better organization
    traffic_tabs = st.tabs(["Protocol Distribution", "Top IPs", "Connection Map"])
    
    with traffic_tabs[0]:
        # Protocol distribution
        if st.session_state.stats['packets_per_protocol']:
            protocol_chart = create_protocol_distribution_chart(
                st.session_state.stats['packets_per_protocol']
            )
            st.plotly_chart(protocol_chart, use_container_width=True)
            
            # Add a table showing protocol count details
            protocols_sorted = dict(sorted(
                st.session_state.stats['packets_per_protocol'].items(),
                key=lambda item: item[1],
                reverse=True
            ))
            
            protocol_df = pd.DataFrame({
                "Protocol": list(protocols_sorted.keys()),
                "Packet Count": list(protocols_sorted.values()),
                "Percentage": [f"{(count / st.session_state.stats['total_packets'] * 100):.1f}%" 
                               if st.session_state.stats['total_packets'] > 0 else "0%" 
                               for count in protocols_sorted.values()]
            })
            
            st.dataframe(protocol_df, use_container_width=True, hide_index=True)
        else:
            st.info("No protocol data available yet.")
    
    with traffic_tabs[1]:
        if st.session_state.stats['source_ips'] or st.session_state.stats['destination_ips']:
            # Create two columns for source and destination IPs
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Top Source IPs")
                if st.session_state.stats['source_ips']:
                    source_ips_sorted = dict(sorted(
                        st.session_state.stats['source_ips'].items(),
                        key=lambda item: item[1],
                        reverse=True
                    )[:10])
                    
                    source_df = pd.DataFrame({
                        "IP Address": list(source_ips_sorted.keys()),
                        "Packet Count": list(source_ips_sorted.values())
                    })
                    
                    st.dataframe(source_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No source IP data available yet.")
            
            with col2:
                st.subheader("Top Destination IPs")
                if st.session_state.stats['destination_ips']:
                    dest_ips_sorted = dict(sorted(
                        st.session_state.stats['destination_ips'].items(),
                        key=lambda item: item[1],
                        reverse=True
                    )[:10])
                    
                    dest_df = pd.DataFrame({
                        "IP Address": list(dest_ips_sorted.keys()),
                        "Packet Count": list(dest_ips_sorted.values())
                    })
                    
                    st.dataframe(dest_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No destination IP data available yet.")
        else:
            st.info("No IP data available yet. Start monitoring to collect data.")
    
    with traffic_tabs[2]:
        st.subheader("Network Connection Map")
        
        if st.session_state.packets:
            # Create a placeholder for the network map
            st.info("Network connection mapping is in development. This feature will visualize traffic flows between hosts.")
            
            # Add a simple connection table as a placeholder
            if st.session_state.stats['source_ips'] and st.session_state.stats['destination_ips']:
                # Create a sample of connections from our data
                connections = []
                src_ips = list(st.session_state.stats['source_ips'].keys())[:5]
                dst_ips = list(st.session_state.stats['destination_ips'].keys())[:5]
                
                # Create connections data
                for i, src in enumerate(src_ips):
                    for j, dst in enumerate(dst_ips):
                        if i != j:  # Avoid self connections
                            connections.append({
                                "Source": src,
                                "Destination": dst,
                                "Protocol": list(st.session_state.stats['packets_per_protocol'].keys())[0] 
                                           if st.session_state.stats['packets_per_protocol'] else "Unknown",
                                "Packets": min(st.session_state.stats['source_ips'][src], 
                                              st.session_state.stats['destination_ips'][dst]) 
                                          if src in st.session_state.stats['source_ips'] and 
                                             dst in st.session_state.stats['destination_ips'] else 0
                            })
                
                # Display connections table
                if connections:
                    connections_df = pd.DataFrame(connections)
                    st.dataframe(connections_df, use_container_width=True, hide_index=True)
        else:
            st.info("No connection data available yet. Start monitoring to collect data.")
    
    # Recent alerts with improved styling
    st.subheader("Recent Security Alerts")
    if st.session_state.alerts:
        recent_alerts = st.session_state.alerts[-5:]
        
        # Create custom alert display with colors based on severity
        for alert in recent_alerts:
            severity = alert['severity']
            alert_color = "red" if severity == "Critical" else \
                          "orange" if severity == "High" else \
                          "yellow" if severity == "Medium" else "blue"
            
            st.markdown(f"""
            <div style="border-left: 4px solid {alert_color}; padding-left: 10px; margin-bottom: 10px;">
                <p style="margin: 0; font-weight: bold; color: {alert_color};">
                    {severity} Alert: {alert['subtype']}
                </p>
                <p style="margin: 0; font-size: 0.9em;">{alert['message']}</p>
                <p style="margin: 0; font-size: 0.8em; color: gray;">
                    {alert['timestamp'].strftime('%H:%M:%S')}
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        # Add a link to view all alerts
        st.markdown("[View all alerts in the Alerts tab](#Alerts)")
    else:
        st.info("No alerts generated yet. This section will display security incidents when detected.")

with tab2:
    st.header("Alert Management")
    
    # Add refresh and clear buttons
    alert_action_col1, alert_action_col2, alert_action_col3 = st.columns([1, 1, 2])
    with alert_action_col1:
        if st.button("🔄 Refresh Alerts"):
            st.rerun()
    
    with alert_action_col2:
        if st.button("🧹 Clear All Alerts") and st.session_state.alerts:
            alert_system.clear_alerts()
            st.session_state.alerts = []
            st.success("All alerts have been cleared")
            st.rerun()
    
    # Alert statistics panel
    if st.session_state.alerts:
        with alert_action_col3:
            total_alerts = len(st.session_state.alerts)
            critical_alerts = sum(1 for a in st.session_state.alerts if a['severity'] == 'Critical')
            high_alerts = sum(1 for a in st.session_state.alerts if a['severity'] == 'High')
            
            # Show alert statistics with color coding
            st.markdown(f"""
            <div style="text-align: right;">
                <span style="color: gray; font-size: 0.9em;">Total: <b>{total_alerts}</b></span> &nbsp;
                <span style="color: red; font-size: 0.9em;">Critical: <b>{critical_alerts}</b></span> &nbsp;
                <span style="color: orange; font-size: 0.9em;">High: <b>{high_alerts}</b></span>
            </div>
            """, unsafe_allow_html=True)
    
    # Filter controls with improved layout
    st.subheader("Filter Alerts")
    
    filter_cols = st.columns([2, 2, 3])
    with filter_cols[0]:
        severity_filter = st.multiselect(
            "Severity",
            options=["Low", "Medium", "High", "Critical"],
            default=["Medium", "High", "Critical"],
            help="Filter alerts by severity level"
        )
    
    with filter_cols[1]:
        # Get unique alert types
        alert_types = set([alert['type'] for alert in st.session_state.alerts]) if st.session_state.alerts else []
        # Add default options if no alerts yet
        if not alert_types:
            alert_types = ["Anomaly", "Rule Violation"]
            
        type_filter = st.multiselect(
            "Alert Type",
            options=list(alert_types),
            default=list(alert_types),
            help="Filter alerts by type (anomaly or rule violation)"
        )
    
    with filter_cols[2]:
        # Time range with more options
        time_options = ["Last 15 minutes", "Last hour", "Last 6 hours", "Last 24 hours", "All time"]
        time_filter = st.select_slider(
            "Time Range", 
            options=time_options, 
            value="All time",
            help="Filter alerts by time range"
        )
    
    # Apply filters
    filtered_alerts = st.session_state.alerts
    
    if severity_filter:
        filtered_alerts = [alert for alert in filtered_alerts if alert['severity'] in severity_filter]
    
    if type_filter:
        filtered_alerts = [alert for alert in filtered_alerts if alert['type'] in type_filter]
    
    if time_filter != "All time":
        now = datetime.now()
        minutes = 15 if time_filter == "Last 15 minutes" else \
                 60 if time_filter == "Last hour" else \
                 360 if time_filter == "Last 6 hours" else 1440  # 24 hours
        filtered_alerts = [
            alert for alert in filtered_alerts 
            if now - alert['timestamp'] < timedelta(minutes=minutes)
        ]
    
    # Display alerts with count and improved styling
    if filtered_alerts:
        st.subheader(f"Alerts ({len(filtered_alerts)} of {len(st.session_state.alerts)} total)")
        
        # Add visualization of alert distribution if we have enough alerts
        if len(filtered_alerts) >= 3:
            alert_viz_tabs = st.tabs(["Timeline", "By Severity", "By Type"])
            
            with alert_viz_tabs[0]:
                # Create timeline chart of alerts
                timeline_data = []
                for alert in filtered_alerts:
                    timeline_data.append({
                        'timestamp': alert['timestamp'],
                        'severity': alert['severity'],
                        'type': alert['type']
                    })
                
                timeline_df = pd.DataFrame(timeline_data)
                
                # Group by hour and count
                timeline_df['hour'] = timeline_df['timestamp'].apply(lambda x: x.strftime('%Y-%m-%d %H:00'))
                # Use a safer approach to groupby
                hour_severity_groups = timeline_df.groupby(['hour', 'severity'])
                hourly_counts = pd.DataFrame({
                    'count': hour_severity_groups.size()
                }).reset_index()
                
                fig = px.bar(
                    hourly_counts, 
                    x='hour', 
                    y='count', 
                    color='severity',
                    color_discrete_map={
                        'Critical': 'red',
                        'High': 'orange',
                        'Medium': 'yellow',
                        'Low': 'blue'
                    },
                    title="Alert Timeline",
                    labels={'hour': 'Time', 'count': 'Number of Alerts'}
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with alert_viz_tabs[1]:
                # Create pie chart by severity
                severity_counts = {}
                for alert in filtered_alerts:
                    severity = alert['severity']
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    else:
                        severity_counts[severity] = 1
                
                fig = px.pie(
                    names=list(severity_counts.keys()),
                    values=list(severity_counts.values()),
                    title="Alerts by Severity",
                    color=list(severity_counts.keys()),
                    color_discrete_map={
                        'Critical': 'red',
                        'High': 'orange',
                        'Medium': 'yellow',
                        'Low': 'blue'
                    }
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig, use_container_width=True)
            
            with alert_viz_tabs[2]:
                # Create pie chart by type
                type_counts = {}
                for alert in filtered_alerts:
                    alert_type = alert['type']
                    if alert_type in type_counts:
                        type_counts[alert_type] += 1
                    else:
                        type_counts[alert_type] = 1
                
                fig = px.pie(
                    names=list(type_counts.keys()),
                    values=list(type_counts.values()),
                    title="Alerts by Type"
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig, use_container_width=True)
        
        # Create a more detailed table with formatted data
        alert_table_data = []
        for alert in filtered_alerts:
            alert_table_data.append({
                "Time": alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                "Severity": alert['severity'],
                "Type": alert['type'],
                "Subtype": alert.get('subtype', ''),
                "Message": alert['message']
            })
        
        alerts_df = pd.DataFrame(alert_table_data)
        
        # Apply color coding based on severity
        def highlight_severity(s):
            return ['background-color: #ffcccc' if x == 'Critical' 
                    else 'background-color: #ffd6a5' if x == 'High' 
                    else 'background-color: #ffffcc' if x == 'Medium' 
                    else 'background-color: #e6f3ff' 
                    for x in s]
        
        # Display as styled dataframe
        st.dataframe(
            alerts_df.style.apply(highlight_severity, subset=['Severity']),
            use_container_width=True,
            hide_index=True
        )
        
        # Add alert details section
        st.subheader("Alert Details")
        alert_index = st.selectbox(
            "Select an alert to view details",
            options=range(len(filtered_alerts)),
            format_func=lambda i: f"{filtered_alerts[i]['timestamp'].strftime('%H:%M:%S')} - {filtered_alerts[i]['severity']} - {filtered_alerts[i]['subtype']}"
        )
        
        # Display detailed alert information
        selected_alert = filtered_alerts[alert_index]
        
        # Create columns for details
        col1, col2 = st.columns(2)
        
        with col1:
            severity = selected_alert['severity']
            alert_color = "red" if severity == "Critical" else \
                        "orange" if severity == "High" else \
                        "yellow" if severity == "Medium" else "blue"
            
            st.markdown(f"""
            <div style="border-left: 4px solid {alert_color}; padding-left: 10px; padding-top: 5px; padding-bottom: 5px;">
                <h3 style="margin: 0; color: {alert_color};">{severity}</h3>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown(f"**Alert Type:** {selected_alert['type']}")
            st.markdown(f"**Subtype:** {selected_alert.get('subtype', 'N/A')}")
            st.markdown(f"**Time:** {selected_alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        
        with col2:
            st.markdown("**Description:**")
            st.info(selected_alert['message'])
            
            if 'details' in selected_alert:
                # Format and display additional details
                details = selected_alert['details']
                if isinstance(details, dict):
                    # Exclude some fields for cleaner display
                    exclude_keys = ['type', 'severity', 'message']
                    detail_text = "\n".join([f"**{k}:** {v}" for k, v in details.items() 
                                           if k not in exclude_keys and v is not None])
                    
                    if detail_text:
                        st.markdown("**Technical Details:**")
                        st.markdown(detail_text)
    else:
        if st.session_state.alerts:
            st.warning("No alerts match the current filters. Try adjusting your filter criteria.")
        else:
            st.info("No alerts have been generated yet. This section will display security incidents when detected.")

with tab3:
    st.header("Packet Analysis")
    
    # Add a refresh button at the top
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔄 Refresh Data", key="refresh_packet_analysis"):
            st.rerun()
    
    # Add packet count indicator
    with col1:
        if st.session_state.packets:
            st.info(f"Currently analyzing {len(st.session_state.packets)} packets")
    
    # Packet statistics
    if st.session_state.stats['packet_sizes'] and st.session_state.stats['timestamps']:
        st.subheader("Packet Size Distribution")
        packet_stats_chart = create_packet_stats_chart(
            st.session_state.stats['packet_sizes'],
            st.session_state.stats['timestamps']
        )
        st.plotly_chart(packet_stats_chart, use_container_width=True)
    
    # Top talkers section with tabs for different views
    talker_tabs = st.tabs(["Top Source IPs", "Top Destination IPs", "Protocol Distribution"])
    
    with talker_tabs[0]:
        if st.session_state.stats['source_ips']:
            source_ips_sorted = dict(sorted(
                st.session_state.stats['source_ips'].items(),
                key=lambda item: item[1],
                reverse=True
            )[:10])
            
            # Add a pie chart option
            view_type = st.radio("View as", ["Bar Chart", "Pie Chart"], horizontal=True, key="source_view")
            
            if view_type == "Bar Chart":
                fig = px.bar(
                    x=list(source_ips_sorted.keys()),
                    y=list(source_ips_sorted.values()),
                    labels={'x': 'IP Address', 'y': 'Packet Count'},
                    title="Top Source IPs"
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                fig = px.pie(
                    names=list(source_ips_sorted.keys()),
                    values=list(source_ips_sorted.values()),
                    title="Top Source IPs"
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig, use_container_width=True)
                
            # Show as table also
            st.dataframe(
                pd.DataFrame({
                    "IP Address": list(source_ips_sorted.keys()),
                    "Packet Count": list(source_ips_sorted.values())
                }),
                use_container_width=True
            )
        else:
            st.info("No source IP data available yet.")
    
    with talker_tabs[1]:
        if st.session_state.stats['destination_ips']:
            dest_ips_sorted = dict(sorted(
                st.session_state.stats['destination_ips'].items(),
                key=lambda item: item[1],
                reverse=True
            )[:10])
            
            # Add a pie chart option
            view_type = st.radio("View as", ["Bar Chart", "Pie Chart"], horizontal=True, key="dest_view")
            
            if view_type == "Bar Chart":
                fig = px.bar(
                    x=list(dest_ips_sorted.keys()),
                    y=list(dest_ips_sorted.values()),
                    labels={'x': 'IP Address', 'y': 'Packet Count'},
                    title="Top Destination IPs"
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                fig = px.pie(
                    names=list(dest_ips_sorted.keys()),
                    values=list(dest_ips_sorted.values()),
                    title="Top Destination IPs"
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig, use_container_width=True)
                
            # Show as table also
            st.dataframe(
                pd.DataFrame({
                    "IP Address": list(dest_ips_sorted.keys()),
                    "Packet Count": list(dest_ips_sorted.values())
                }),
                use_container_width=True
            )
        else:
            st.info("No destination IP data available yet.")
    
    with talker_tabs[2]:
        if st.session_state.stats['packets_per_protocol']:
            protocol_chart = create_protocol_distribution_chart(
                st.session_state.stats['packets_per_protocol']
            )
            st.plotly_chart(protocol_chart, use_container_width=True)
            
            # Show as table also
            protocols_sorted = dict(sorted(
                st.session_state.stats['packets_per_protocol'].items(),
                key=lambda item: item[1],
                reverse=True
            ))
            
            st.dataframe(
                pd.DataFrame({
                    "Protocol": list(protocols_sorted.keys()),
                    "Packet Count": list(protocols_sorted.values())
                }),
                use_container_width=True
            )
        else:
            st.info("No protocol data available yet.")
    
    # Raw packet data with improved display
    st.subheader("Recent Packets")
    
    # Controls for packet display
    col1, col2 = st.columns([2, 1])
    with col1:
        show_raw = st.checkbox("Show raw packet data", value=False)
    with col2:
        if st.session_state.packets:
            packet_count = st.number_input("Packets to show", min_value=5, max_value=100, value=20, step=5)
        else:
            packet_count = 20
    
    # Display packet data
    if st.session_state.packets:
        recent_packets = st.session_state.packets[-packet_count:]
        packet_summaries = []
        
        for i, packet in enumerate(recent_packets):
            try:
                if hasattr(packet, 'summary'):
                    summary = packet.summary()
                else:
                    # Fallback for packets without summary method
                    protocol = packet.name if hasattr(packet, 'name') else "Unknown"
                    src = packet.src if hasattr(packet, 'src') else "Unknown"
                    dst = packet.dst if hasattr(packet, 'dst') else "Unknown"
                    summary = f"{protocol}: {src} -> {dst}"
                
                timestamp = st.session_state.stats['timestamps'][-(packet_count-i)] if i < len(st.session_state.stats['timestamps']) else datetime.now()
                time_str = timestamp.strftime("%H:%M:%S") if isinstance(timestamp, datetime) else "Unknown"
                
                packet_summaries.append({
                    "Time": time_str,
                    "Index": i+1,
                    "Summary": summary,
                    "Length": getattr(packet, 'len', 0)
                })
            except Exception as e:
                packet_summaries.append({
                    "Time": "Error",
                    "Index": i+1,
                    "Summary": f"Error parsing packet: {str(e)}",
                    "Length": 0
                })
        
        # Create a dataframe with packets
        packet_df = pd.DataFrame(packet_summaries)
        
        # Apply styling to highlight unusual packet sizes
        if 'Length' in packet_df.columns and len(packet_df) > 0:
            mean_size = packet_df['Length'].mean()
            std_size = packet_df['Length'].std() if len(packet_df) > 1 else 0
            
            # Color coding based on deviation from mean
            def highlight_size(val):
                if val > mean_size + 2*std_size:
                    return 'background-color: #ffcccc'  # Red for very large
                elif val > mean_size + std_size:
                    return 'background-color: #ffffcc'  # Yellow for large
                else:
                    return ''
            
            # Apply styling
            styled_df = packet_df.style.applymap(highlight_size, subset=['Length'])
            st.dataframe(styled_df, use_container_width=True)
        else:
            st.dataframe(packet_df, use_container_width=True)
        
        # Raw packet display
        if show_raw and recent_packets:
            st.subheader("Raw Packet Data")
            packet_idx = st.slider("Select packet", 1, len(recent_packets), 1) - 1
            selected_packet = recent_packets[packet_idx]
            
            # Parse and show key packet details in a more readable format
            st.markdown("#### Packet Details")
            col1, col2 = st.columns(2)
            
            with col1:
                if hasattr(selected_packet, 'name'):
                    st.markdown(f"**Protocol:** {selected_packet.name}")
                if hasattr(selected_packet, 'len'):
                    st.markdown(f"**Length:** {selected_packet.len} bytes")
                if 'IP' in selected_packet:
                    st.markdown(f"**Source IP:** {selected_packet['IP'].src}")
                    st.markdown(f"**Destination IP:** {selected_packet['IP'].dst}")
            
            with col2:
                if 'TCP' in selected_packet:
                    st.markdown(f"**Source Port:** {selected_packet['TCP'].sport}")
                    st.markdown(f"**Destination Port:** {selected_packet['TCP'].dport}")
                    flags = selected_packet['TCP'].flags
                    st.markdown(f"**TCP Flags:** {flags} ({format(flags, '08b')})")
                elif 'UDP' in selected_packet:
                    st.markdown(f"**Source Port:** {selected_packet['UDP'].sport}")
                    st.markdown(f"**Destination Port:** {selected_packet['UDP'].dport}")
            
            # Display full raw packet
            st.markdown("#### Raw Packet Content")
            st.code(str(selected_packet), language="text")
    else:
        st.info("No packets captured yet. Start monitoring to collect packet data.")

with tab4:
    st.header("System Logs")
    
    # Add refresh button
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🔄 Refresh Logs", key="refresh_logs"):
            st.rerun()
    
    # Add log filtering options
    with col1:
        # Create filter options
        log_levels = ["All Levels", "ERROR", "WARNING", "INFO", "DEBUG"]
        selected_level = st.selectbox("Filter by level", log_levels)
    
    # Display log entries with time filtering
    st.subheader("Event Log")
    
    time_options = ["Last 5 minutes", "Last 15 minutes", "Last hour", "All time"]
    time_filter = st.select_slider("Time Range", options=time_options, value="All time")
    
    # Convert time filter to timedelta
    time_delta = None
    if time_filter == "Last 5 minutes":
        time_delta = timedelta(minutes=5)
    elif time_filter == "Last 15 minutes":
        time_delta = timedelta(minutes=15)
    elif time_filter == "Last hour":
        time_delta = timedelta(hours=1)
    
    # Filter and display log entries
    if st.session_state.log_entries:
        filtered_logs = st.session_state.log_entries
        
        # Apply time filter
        if time_delta:
            current_time = datetime.now()
            filtered_logs = [
                log for log in filtered_logs 
                if current_time - log['timestamp'] <= time_delta
            ]
        
        # Apply level filter
        if selected_level != "All Levels":
            filtered_logs = [log for log in filtered_logs if log['level'] == selected_level]
        
        # Sort by timestamp (newest first)
        filtered_logs = sorted(filtered_logs, key=lambda x: x['timestamp'], reverse=True)
        
        # Convert to DataFrame for display
        if filtered_logs:
            log_df = pd.DataFrame([
                {
                    "Time": log['timestamp'].strftime('%H:%M:%S'),
                    "Level": log['level'],
                    "Message": log['message']
                } for log in filtered_logs
            ])
            
            # Apply styling based on log level
            def highlight_level(s):
                if s == 'ERROR':
                    return 'background-color: #ffcccc'
                elif s == 'WARNING':
                    return 'background-color: #ffffcc'
                elif s == 'CRITICAL':
                    return 'background-color: #ff9999'
                return ''
            
            styled_df = log_df.style.applymap(highlight_level, subset=['Level'])
            st.dataframe(styled_df, use_container_width=True)
        else:
            st.info("No log entries match the current filters.")
    else:
        st.info("No log entries available yet.")
    
    # Add log statistics
    if st.session_state.log_entries:
        st.subheader("Log Statistics")
        
        # Count entries by level
        level_counts = {}
        for log in st.session_state.log_entries:
            level = log['level']
            if level in level_counts:
                level_counts[level] += 1
            else:
                level_counts[level] = 1
        
        # Display as bar chart
        fig = px.bar(
            x=list(level_counts.keys()),
            y=list(level_counts.values()),
            labels={'x': 'Log Level', 'y': 'Count'},
            title="Log Entries by Level",
            color=list(level_counts.keys()),
            color_discrete_map={
                'ERROR': 'red',
                'WARNING': 'orange',
                'INFO': 'blue',
                'DEBUG': 'gray',
                'CRITICAL': 'darkred'
            }
        )
        st.plotly_chart(fig, use_container_width=True)

with tab5:
    st.header("System Settings")
    
    # Create tabs for different settings categories
    settings_tabs = st.tabs(["Detection Rules", "Anomaly Detection", "System Configuration", "Export/Import"])
    
    with settings_tabs[0]:
        st.header("Detection Rules")
        
        # Rule management actions
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            if st.button("Reload Default Rules", key="reload_rules"):
                rule_engine._create_default_rules()
                rule_engine.save_rules()
                st.success("Default rules reloaded")
                st.rerun()
        
        with col2:
            if st.button("Save Rules", key="save_rules"):
                rule_engine.save_rules()
                st.success("Rules saved successfully")
        
        with col3:
            if st.button("Refresh", key="refresh_rules"):
                rule_engine.load_rules()
                st.success("Rules refreshed")
                st.rerun()
                
        # Get and display rules
        rules = rule_engine.get_rules()
        
        if rules:
            # Display rules statistics
            active_rules = sum(1 for rule in rules if rule.get('enabled', True))
            st.info(f"Found {len(rules)} rules ({active_rules} active, {len(rules) - active_rules} disabled)")
            
            # Display rules in a table first for overview
            rule_data = []
            for i, rule in enumerate(rules):
                rule_data.append({
                    "ID": i+1,
                    "Name": rule['name'],
                    "Severity": rule['severity'],
                    "Status": "✅ Active" if rule.get('enabled', True) else "⚪ Disabled"
                })
            
            rule_df = pd.DataFrame(rule_data)
            st.dataframe(rule_df, use_container_width=True)
            
            # Detailed rule view with editing capabilities
            st.subheader("Edit Rules")
            for i, rule in enumerate(rules):
                with st.expander(f"Rule {i+1}: {rule['name']}"):
                    # Create columns for the rule details
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.markdown(f"**Description:** {rule['description']}")
                        st.markdown(f"**Severity:** {rule['severity']}")
                        
                        # Show condition with syntax highlighting
                        st.markdown("**Condition:**")
                        st.code(rule['condition'], language="python")
                        
                        # Show additional parameters if they exist
                        if 'count_threshold' in rule:
                            st.markdown(f"**Count Threshold:** {rule['count_threshold']}")
                        if 'time_window' in rule:
                            st.markdown(f"**Time Window:** {rule['time_window']} seconds")
                        if 'unique_ports_threshold' in rule:
                            st.markdown(f"**Unique Ports Threshold:** {rule['unique_ports_threshold']}")
                    
                    with col2:
                        # Toggle for enabling/disabling
                        enabled = st.toggle("Enabled", value=rule.get('enabled', True), key=f"rule_{i}")
                        if enabled != rule.get('enabled', True):
                            rule['enabled'] = enabled
                            rule_engine.update_rule(i, rule)
                            st.success(f"Rule '{rule['name']}' {'enabled' if enabled else 'disabled'}")
                        
                        # Delete button
                        if st.button("Delete Rule", key=f"delete_rule_{i}"):
                            if rule_engine.delete_rule(i):
                                st.success(f"Rule '{rule['name']}' deleted")
                                st.rerun()
                            else:
                                st.error("Failed to delete rule")
        else:
            st.warning("No detection rules found. Default rules will be loaded.")
            if st.button("Load Default Rules"):
                rule_engine._create_default_rules()
                rule_engine.save_rules()
                st.success("Default rules loaded")
                st.rerun()
        
        # Add new rule UI
        st.subheader("Add New Rule")
        with st.form("new_rule_form"):
            rule_name = st.text_input("Rule Name")
            rule_description = st.text_area("Description")
            rule_condition = st.text_area("Condition (Python expression)", 
                                         placeholder="packet.haslayer('TCP') and packet['TCP'].flags & 0x02")
            
            col1, col2 = st.columns(2)
            with col1:
                rule_severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
            with col2:
                has_threshold = st.checkbox("Add Threshold Parameters")
            
            # Initialize variables with default values to avoid unbound variables
            count_threshold = 50
            time_window = 60
            
            # Conditional threshold parameters
            if has_threshold:
                threshold_col1, threshold_col2 = st.columns(2)
                with threshold_col1:
                    count_threshold = st.number_input("Count Threshold", min_value=1, value=50)
                with threshold_col2:
                    time_window = st.number_input("Time Window (seconds)", min_value=1, value=60)
            
            submitted = st.form_submit_button("Add Rule")
            if submitted and rule_name and rule_condition:
                # Create the rule dict with required fields
                new_rule = {
                    "name": rule_name,
                    "description": rule_description,
                    "condition": rule_condition,
                    "severity": rule_severity,
                    "enabled": True
                }
                
                # Add threshold parameters if specified
                if has_threshold:
                    new_rule["count_threshold"] = count_threshold
                    new_rule["time_window"] = time_window
                
                # Add the rule
                if rule_engine.add_rule(new_rule):
                    st.success(f"Rule '{rule_name}' added successfully")
                    st.rerun()
                else:
                    st.error("Failed to add rule. Check the rule format.")
    
    with settings_tabs[1]:
        st.header("Anomaly Detection Settings")
        
        # Display current settings
        st.subheader("Current Configuration")
        
        col1, col2 = st.columns(2)
        with col1:
            # Threshold slider
            current_threshold = anomaly_detector.threshold
            new_threshold = st.slider(
                "Detection Threshold",
                min_value=50,
                max_value=99,
                value=current_threshold,
                help="Higher values are more permissive (fewer anomalies detected)"
            )
            
            if new_threshold != current_threshold:
                anomaly_detector.set_threshold(new_threshold)
                st.success(f"Threshold updated to {new_threshold}")
        
        with col2:
            # Reset baselines
            if st.button("Reset Baselines"):
                anomaly_detector.reset_baseline()
                st.success("Anomaly detection baselines reset")
        
        # Add explanation of anomaly detection
        st.subheader("About Anomaly Detection")
        st.markdown("""
        The anomaly detection system monitors network traffic patterns and identifies unusual behavior. 
        It uses both statistical methods and machine learning to detect deviations from normal patterns.
        
        **Detection methods include:**
        - Traffic volume spikes
        - Unusual numbers of unique IP addresses
        - Abnormal port activity
        - Changes in protocol distribution
        - Advanced machine learning detection
        
        Adjusting the threshold changes the sensitivity of the detection. A higher threshold means fewer 
        anomalies will be detected but with higher confidence.
        """)
        
    with settings_tabs[2]:
        st.header("System Configuration")
        
        # Interface settings (duplicated from sidebar for convenience)
        st.subheader("Network Interface")
        
        from utils import get_local_interfaces
        available_interfaces = get_local_interfaces()
        
        if 'any' not in available_interfaces:
            available_interfaces = ['any'] + available_interfaces
        
        current_interface = packet_capture.get_interface()
        
        # Create interface selection with radio buttons for better UX
        selected_interface = st.radio(
            "Select Network Interface",
            options=available_interfaces,
            index=available_interfaces.index(current_interface) if current_interface in available_interfaces else 0,
            horizontal=True
        )
        
        if selected_interface != current_interface:
            packet_capture.set_interface(selected_interface)
            st.success(f"Interface changed to {selected_interface}")
        
        # Logging settings
        st.subheader("Logging Configuration")
        
        log_level_options = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING, 
            "ERROR": logging.ERROR
        }
        
        selected_log_level = st.selectbox(
            "Log Level",
            options=list(log_level_options.keys()),
            index=1  # Default to INFO
        )
        
        if st.button("Apply Log Settings"):
            logger.setLevel(log_level_options[selected_log_level])
            st.success(f"Log level set to {selected_log_level}")
            
            # Add to log entries
            st.session_state.log_entries.append({
                'timestamp': datetime.now(),
                'level': "INFO",
                'message': f"Log level changed to {selected_log_level}"
            })
        
        # UI settings
        st.subheader("User Interface Settings")
        
        # Theme settings
        st.markdown("**Note:** Theme settings require app restart to take full effect")
        theme_cols = st.columns(2)
        with theme_cols[0]:
            primary_color = st.color_picker("Primary Color", "#1E88E5")
        with theme_cols[1]:
            background_color = st.color_picker("Background Color", "#FFFFFF")
        
        if st.button("Apply Theme"):
            # Update config.toml file
            with open('.streamlit/config.toml', 'w') as f:
                f.write(f"""[server]
headless = true
address = "0.0.0.0"
port = 5000

[theme]
primaryColor = "{primary_color}"
backgroundColor = "{background_color}"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#262730"
""")
            st.success("Theme settings updated. Restart the app for changes to take effect.")
        
    with settings_tabs[3]:
        st.header("Export / Import")
        
        # Export alerts to file
        st.subheader("Export Data")
        
        export_options = st.columns(2)
        with export_options[0]:
            if st.button("Export Alerts to JSON"):
                try:
                    filename = f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    if alert_system.export_alerts(filename):
                        st.success(f"Alerts exported to {filename}")
                    else:
                        st.error("Error exporting alerts")
                except Exception as e:
                    st.error(f"Export error: {str(e)}")
        
        with export_options[1]:
            if st.button("Export Rules to JSON"):
                try:
                    filename = f"rules_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    # Create a copy of rules for export
                    with open(filename, 'w') as f:
                        json.dump(rule_engine.get_rules(), f, indent=2)
                    st.success(f"Rules exported to {filename}")
                except Exception as e:
                    st.error(f"Export error: {str(e)}")
        
        # Import data
        st.subheader("Import Data")
        
        import_option = st.radio("Select Import Type", ["Alerts", "Rules"], horizontal=True)
        import_file = st.text_input("Enter filename to import from:", placeholder="alerts_export_20250515.json")
        
        if st.button("Import Data") and import_file:
            try:
                if import_option == "Alerts":
                    if alert_system.import_alerts(import_file):
                        st.success(f"Alerts imported from {import_file}")
                    else:
                        st.error("Error importing alerts")
                else:  # Rules
                    # Import rules from file
                    try:
                        with open(import_file, 'r') as f:
                            imported_rules = json.load(f)
                        
                        # Validate the imported rules format
                        if not isinstance(imported_rules, list):
                            st.error("Invalid rules file format. Expected a list of rules.")
                        else:
                            # Clear current rules and add imported ones
                            rule_engine.rules = []
                            import_success = True
                            
                            # Add each rule individually
                            for imported_rule in imported_rules:
                                # Ensure each rule has the required fields
                                if not all(key in imported_rule for key in ['name', 'description', 'condition', 'severity']):
                                    st.error(f"Rule missing required fields: {imported_rule.get('name', 'Unknown')}")
                                    import_success = False
                                    continue
                                    
                                # Add the rule to the engine
                                if not rule_engine.add_rule(imported_rule):
                                    st.error(f"Failed to add rule: {imported_rule.get('name', 'Unknown')}")
                                    import_success = False
                            
                            # Save the rules if all imports succeeded
                            if import_success:
                                rule_engine.save_rules()
                                st.success(f"Rules imported from {import_file}")
                    except Exception as e:
                        st.error(f"Error importing rules: {str(e)}")
            except Exception as e:
                st.error(f"Import error: {str(e)}")
    
    # System configuration
    st.subheader("System Configuration")
    
    # Packet capture settings
    st.text_input("Interface", value=INTERFACE, disabled=True, 
                help="To change the interface, modify the config.py file")
    
    capture_timeout = st.slider(
        "Capture Timeout (seconds)",
        min_value=1,
        max_value=10,
        value=CAPTURE_TIMEOUT,
        help="Time to wait for packets in each capture cycle"
    )
    
    # Alert settings
    st.subheader("Alert Settings")
    
    alert_threshold = st.number_input(
        "Alert Threshold",
        min_value=1,
        max_value=100,
        value=anomaly_detector.threshold,
        help="Threshold for anomaly detection (lower values are more sensitive)"
    )
    
    if alert_threshold != anomaly_detector.threshold:
        anomaly_detector.threshold = alert_threshold
        st.success(f"Anomaly detection threshold updated to {alert_threshold}")
    
    # Logging settings
    st.subheader("Logging Settings")
    log_level = st.selectbox(
        "Log Level",
        options=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        index=1  # INFO
    )
    
    # Save settings button
    if st.button("Save Settings"):
        # In a real application, this would save to a config file
        st.success("Settings saved successfully!")

# Footer
st.markdown("---")
st.caption("Network Intrusion Detection System | v1.0.0")
