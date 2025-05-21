import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import numpy as np

def create_traffic_volume_chart(traffic_data):
    """
    Create a line chart of traffic volume over time
    
    Args:
        traffic_data (list): List of dictionaries with timestamp and count
        
    Returns:
        plotly.graph_objects.Figure: Traffic volume chart
    """
    if not traffic_data:
        df = pd.DataFrame({
            'timestamp': [datetime.now()],
            'count': [0]
        })
    else:
        df = pd.DataFrame(traffic_data)
    
    # Convert timestamps to strings for better display
    df['time_str'] = df['timestamp'].apply(lambda x: x.strftime('%H:%M:%S'))
    
    fig = px.line(
        df, 
        x='time_str', 
        y='count',
        labels={'time_str': 'Time', 'count': 'Packet Count'},
        title='Traffic Volume Over Time'
    )
    
    fig.update_traces(mode='lines+markers')
    fig.update_layout(
        xaxis_title='Time',
        yaxis_title='Packet Count',
        height=400
    )
    
    return fig

def create_protocol_distribution_chart(protocol_counts):
    """
    Create a pie chart of protocol distribution
    
    Args:
        protocol_counts (dict): Dictionary mapping protocols to counts
        
    Returns:
        plotly.graph_objects.Figure: Protocol distribution chart
    """
    if not protocol_counts:
        return go.Figure()
    
    # Convert to lists for plotting
    labels = list(protocol_counts.keys())
    values = list(protocol_counts.values())
    
    fig = px.pie(
        names=labels,
        values=values,
        title='Protocol Distribution'
    )
    
    fig.update_traces(
        textposition='inside',
        textinfo='percent+label'
    )
    
    return fig

def create_geo_map(ip_locations):
    """
    Create a geographic map of IP addresses
    
    Args:
        ip_locations (list): List of dictionaries with ip, lat, lon, and count
        
    Returns:
        plotly.graph_objects.Figure: Geographic map
    """
    if not ip_locations:
        return go.Figure()
    
    df = pd.DataFrame(ip_locations)
    
    fig = px.scatter_geo(
        df,
        lat='lat',
        lon='lon',
        size='count',
        hover_name='ip',
        projection='natural earth',
        title='IP Address Locations'
    )
    
    return fig

def create_alerts_table(alerts):
    """
    Create a dataframe for alerts table
    
    Args:
        alerts (list): List of alert dictionaries
        
    Returns:
        pandas.DataFrame: Alerts table
    """
    if not alerts:
        return pd.DataFrame()
    
    # Create a simplified dataframe for display
    data = []
    for alert in alerts:
        data.append({
            'Time': alert['timestamp'].strftime('%H:%M:%S'),
            'Type': alert['type'],
            'Subtype': alert.get('subtype', ''),
            'Severity': alert['severity'],
            'Message': alert['message']
        })
    
    return pd.DataFrame(data)

def create_packet_stats_chart(packet_sizes, timestamps):
    """
    Create a chart showing packet size distribution over time
    
    Args:
        packet_sizes (list): List of packet sizes
        timestamps (list): List of corresponding timestamps
        
    Returns:
        plotly.graph_objects.Figure: Packet statistics chart
    """
    if not packet_sizes or not timestamps:
        return go.Figure()
    
    df = pd.DataFrame({
        'size': packet_sizes,
        'timestamp': timestamps
    })
    
    # Add time string for better display
    df['time_str'] = df['timestamp'].apply(lambda x: x.strftime('%H:%M:%S'))
    
    # Create a scatter plot of packet sizes
    fig = px.scatter(
        df,
        x='time_str',
        y='size',
        title='Packet Size Distribution Over Time',
        labels={'time_str': 'Time', 'size': 'Packet Size (bytes)'}
    )
    
    # Calculate moving average for trend line
    window_size = min(20, len(df))
    if window_size > 2:
        df['size_ma'] = df['size'].rolling(window=window_size).mean()
        
        # Add trend line
        fig.add_trace(
            go.Scatter(
                x=df['time_str'],
                y=df['size_ma'],
                mode='lines',
                line=dict(color='red', width=2),
                name='Moving Average'
            )
        )
    
    fig.update_layout(
        xaxis_title='Time',
        yaxis_title='Packet Size (bytes)',
        height=400
    )
    
    return fig

def create_histogram(data, title, x_label, bins=20):
    """
    Create a histogram
    
    Args:
        data (list): Data for histogram
        title (str): Chart title
        x_label (str): Label for x-axis
        bins (int): Number of bins
        
    Returns:
        plotly.graph_objects.Figure: Histogram
    """
    if not data:
        return go.Figure()
    
    fig = px.histogram(
        x=data,
        nbins=bins,
        title=title,
        labels={'x': x_label}
    )
    
    fig.update_layout(
        xaxis_title=x_label,
        yaxis_title='Count',
        height=400
    )
    
    return fig

def create_heatmap(x_labels, y_labels, z_values, title, x_title, y_title):
    """
    Create a heatmap
    
    Args:
        x_labels (list): Labels for x-axis
        y_labels (list): Labels for y-axis
        z_values (list): 2D array of values
        title (str): Chart title
        x_title (str): Title for x-axis
        y_title (str): Title for y-axis
        
    Returns:
        plotly.graph_objects.Figure: Heatmap
    """
    fig = go.Figure(data=go.Heatmap(
        z=z_values,
        x=x_labels,
        y=y_labels,
        colorscale='Viridis'
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title=x_title,
        yaxis_title=y_title,
        height=500
    )
    
    return fig

def create_bar_chart(x, y, title, x_label, y_label):
    """
    Create a bar chart
    
    Args:
        x (list): X-axis values
        y (list): Y-axis values
        title (str): Chart title
        x_label (str): Label for x-axis
        y_label (str): Label for y-axis
        
    Returns:
        plotly.graph_objects.Figure: Bar chart
    """
    if not x or not y:
        return go.Figure()
    
    fig = px.bar(
        x=x,
        y=y,
        title=title,
        labels={'x': x_label, 'y': y_label}
    )
    
    fig.update_layout(
        xaxis_title=x_label,
        yaxis_title=y_label,
        height=400
    )
    
    return fig
