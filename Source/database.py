import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from datetime import datetime
import traceback

logger = logging.getLogger(__name__)

class Database:
    """
    Database handler for storing and retrieving NIDS data
    """
    def __init__(self, connection_string=None):
        """
        Initialize database connection
        
        Args:
            connection_string (str): Database connection string (defaults to DATABASE_URL env var)
        """
        self.connection_string = connection_string or os.environ.get('DATABASE_URL')
        self.conn = None
        self.cursor = None
        self.connected = False
        
        # Try to establish connection and initialize schema
        if self.connection_string:
            if self._connect():
                if self._initialize_schema():
                    self.connected = True
                    logger.info("Database initialized successfully")
                else:
                    logger.error("Failed to initialize database schema")
            else:
                logger.warning("Database connection failed, running in memory-only mode")
        else:
            logger.warning("No database connection string provided, running in memory-only mode")
            
    def _connect(self):
        """Establish database connection"""
        try:
            if not self.connection_string:
                logger.error("No database connection string provided")
                return False
                
            self.conn = psycopg2.connect(self.connection_string)
            self.conn.autocommit = True
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            logger.info("Database connection established")
            return True
        except Exception as e:
            logger.error(f"Database connection error: {str(e)}")
            self.conn = None
            self.cursor = None
            return False

    def _initialize_schema(self):
        """Create database tables if they don't exist"""
        if not self.cursor:
            logger.error("Cannot initialize schema: no database connection")
            return False
            
        try:
            # Create packets table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip VARCHAR(45) NOT NULL,
                    dst_ip VARCHAR(45) NOT NULL,
                    protocol INTEGER,
                    src_port INTEGER,
                    dst_port INTEGER,
                    length INTEGER,
                    payload TEXT,
                    metadata JSONB
                )
            ''')
            
            # Create alerts table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    alert_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    message TEXT NOT NULL,
                    source_ip VARCHAR(45),
                    dest_ip VARCHAR(45),
                    metadata JSONB
                )
            ''')
            
            # Create traffic_stats table for aggregated statistics
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    stat_type VARCHAR(50) NOT NULL,
                    stat_value JSONB NOT NULL
                )
            ''')
            
            # Create logs table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    level VARCHAR(10) NOT NULL,
                    module VARCHAR(50),
                    message TEXT NOT NULL
                )
            ''')
            
            # Create index for packet timestamp
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_packets_timestamp
                ON packets (timestamp)
            ''')
            
            # Create index for alert timestamp and severity
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts (timestamp)
            ''')
            self.cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alerts_severity
                ON alerts (severity)
            ''')
            
            logger.info("Database schema initialized")
            return True
        except Exception as e:
            logger.error(f"Schema initialization error: {str(e)}")
            return False

    def store_packet(self, packet_data):
        """
        Store packet information in the database
        
        Args:
            packet_data (dict): Packet data dictionary with fields matching the table schema
            
        Returns:
            bool: Success status
        """
        try:
            metadata = packet_data.pop('metadata', {})
            if metadata and not isinstance(metadata, str):
                metadata = json.dumps(metadata)
            
            self.cursor.execute('''
                INSERT INTO packets 
                (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, payload, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                packet_data.get('timestamp', datetime.now()),
                packet_data.get('src_ip', ''),
                packet_data.get('dst_ip', ''),
                packet_data.get('protocol'),
                packet_data.get('src_port'),
                packet_data.get('dst_port'),
                packet_data.get('length'),
                packet_data.get('payload', ''),
                metadata
            ))
            return True
        except Exception as e:
            logger.error(f"Error storing packet: {str(e)}")
            return False

    def store_alert(self, alert_data):
        """
        Store alert information in the database
        
        Args:
            alert_data (dict): Alert data dictionary with fields matching the table schema
            
        Returns:
            bool: Success status
        """
        try:
            metadata = alert_data.pop('metadata', {})
            if metadata and not isinstance(metadata, str):
                metadata = json.dumps(metadata)
                
            self.cursor.execute('''
                INSERT INTO alerts 
                (timestamp, alert_type, severity, message, source_ip, dest_ip, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                alert_data.get('timestamp', datetime.now()),
                alert_data.get('alert_type', 'unknown'),
                alert_data.get('severity', 'low'),
                alert_data.get('message', ''),
                alert_data.get('source_ip'),
                alert_data.get('dest_ip'),
                metadata
            ))
            return True
        except Exception as e:
            logger.error(f"Error storing alert: {str(e)}")
            return False

    def store_traffic_stat(self, stat_type, stat_value):
        """
        Store traffic statistics in the database
        
        Args:
            stat_type (str): Type of statistic (e.g., 'protocol_distribution', 'ip_frequency')
            stat_value (dict): Statistic value as a dictionary
            
        Returns:
            bool: Success status
        """
        try:
            if not isinstance(stat_value, str):
                stat_value = json.dumps(stat_value)
                
            self.cursor.execute('''
                INSERT INTO traffic_stats (stat_type, stat_value)
                VALUES (%s, %s)
            ''', (stat_type, stat_value))
            return True
        except Exception as e:
            logger.error(f"Error storing traffic stat: {str(e)}")
            return False

    def store_log(self, log_data):
        """
        Store log information in the database
        
        Args:
            log_data (dict): Log data dictionary with fields matching the table schema
            
        Returns:
            bool: Success status
        """
        try:
            self.cursor.execute('''
                INSERT INTO logs (timestamp, level, module, message)
                VALUES (%s, %s, %s, %s)
            ''', (
                log_data.get('timestamp', datetime.now()),
                log_data.get('level', 'INFO'),
                log_data.get('module', ''),
                log_data.get('message', '')
            ))
            return True
        except Exception as e:
            logger.error(f"Error storing log: {str(e)}")
            return False

    def get_packets(self, limit=100, offset=0, filters=None):
        """
        Retrieve packets from the database with optional filtering
        
        Args:
            limit (int): Maximum number of packets to retrieve
            offset (int): Offset for pagination
            filters (dict): Filtering criteria
            
        Returns:
            list: Retrieved packet records
        """
        try:
            query = "SELECT * FROM packets"
            params = []
            
            if filters:
                where_clauses = []
                if 'start_time' in filters:
                    where_clauses.append("timestamp >= %s")
                    params.append(filters['start_time'])
                if 'end_time' in filters:
                    where_clauses.append("timestamp <= %s")
                    params.append(filters['end_time'])
                if 'src_ip' in filters:
                    where_clauses.append("src_ip = %s")
                    params.append(filters['src_ip'])
                if 'dst_ip' in filters:
                    where_clauses.append("dst_ip = %s")
                    params.append(filters['dst_ip'])
                if 'protocol' in filters:
                    where_clauses.append("protocol = %s")
                    params.append(filters['protocol'])
                
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
            
            query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving packets: {str(e)}")
            return []

    def get_alerts(self, limit=100, offset=0, filters=None):
        """
        Retrieve alerts from the database with optional filtering
        
        Args:
            limit (int): Maximum number of alerts to retrieve
            offset (int): Offset for pagination
            filters (dict): Filtering criteria
            
        Returns:
            list: Retrieved alert records
        """
        try:
            query = "SELECT * FROM alerts"
            params = []
            
            if filters:
                where_clauses = []
                if 'start_time' in filters:
                    where_clauses.append("timestamp >= %s")
                    params.append(filters['start_time'])
                if 'end_time' in filters:
                    where_clauses.append("timestamp <= %s")
                    params.append(filters['end_time'])
                if 'alert_type' in filters:
                    where_clauses.append("alert_type = %s")
                    params.append(filters['alert_type'])
                if 'severity' in filters:
                    where_clauses.append("severity = %s")
                    params.append(filters['severity'])
                if 'source_ip' in filters:
                    where_clauses.append("source_ip = %s")
                    params.append(filters['source_ip'])
                
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
            
            query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving alerts: {str(e)}")
            return []

    def get_traffic_stats(self, stat_type=None, limit=24):
        """
        Retrieve traffic statistics from the database
        
        Args:
            stat_type (str): Type of statistic to retrieve (None for all)
            limit (int): Maximum number of records to retrieve
            
        Returns:
            list: Retrieved statistic records
        """
        try:
            query = "SELECT * FROM traffic_stats"
            params = []
            
            if stat_type:
                query += " WHERE stat_type = %s"
                params.append(stat_type)
                
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving traffic stats: {str(e)}")
            return []

    def get_logs(self, limit=100, offset=0, level=None, module=None):
        """
        Retrieve logs from the database with optional filtering
        
        Args:
            limit (int): Maximum number of logs to retrieve
            offset (int): Offset for pagination
            level (str): Filter by log level
            module (str): Filter by module name
            
        Returns:
            list: Retrieved log records
        """
        try:
            query = "SELECT * FROM logs"
            params = []
            where_clauses = []
            
            if level:
                where_clauses.append("level = %s")
                params.append(level)
            if module:
                where_clauses.append("module = %s")
                params.append(module)
                
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
                
            query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving logs: {str(e)}")
            return []

    def get_packet_count_by_time(self, interval='hour', start_time=None, end_time=None):
        """
        Get packet count grouped by time interval
        
        Args:
            interval (str): Time interval ('hour', 'day', 'week', 'month')
            start_time (datetime): Start time for the query
            end_time (datetime): End time for the query
            
        Returns:
            list: Records with time interval and count
        """
        try:
            # Define the time format based on the interval
            if interval == 'hour':
                time_format = "YYYY-MM-DD HH24:00:00"
            elif interval == 'day':
                time_format = "YYYY-MM-DD 00:00:00"
            elif interval == 'week':
                time_format = "YYYY-IW"  # ISO week
            elif interval == 'month':
                time_format = "YYYY-MM-01"
            else:
                time_format = "YYYY-MM-DD HH24:00:00"  # default to hour
                
            query = f"""
                SELECT 
                    TO_CHAR(timestamp, %s) as time_interval, 
                    COUNT(*) as packet_count
                FROM packets
            """
            params = [time_format]
            where_clauses = []
            
            if start_time:
                where_clauses.append("timestamp >= %s")
                params.append(start_time)
            if end_time:
                where_clauses.append("timestamp <= %s")
                params.append(end_time)
                
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
                
            query += " GROUP BY time_interval ORDER BY time_interval"
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving packet count by time: {str(e)}")
            return []

    def get_alert_count_by_time(self, interval='hour', start_time=None, end_time=None, severity=None):
        """
        Get alert count grouped by time interval and optionally by severity
        
        Args:
            interval (str): Time interval ('hour', 'day', 'week', 'month')
            start_time (datetime): Start time for the query
            end_time (datetime): End time for the query
            severity (str): Filter by severity
            
        Returns:
            list: Records with time interval, severity, and count
        """
        try:
            # Define the time format based on the interval
            if interval == 'hour':
                time_format = "YYYY-MM-DD HH24:00:00"
            elif interval == 'day':
                time_format = "YYYY-MM-DD 00:00:00"
            elif interval == 'week':
                time_format = "YYYY-IW"  # ISO week
            elif interval == 'month':
                time_format = "YYYY-MM-01"
            else:
                time_format = "YYYY-MM-DD HH24:00:00"  # default to hour
                
            query = f"""
                SELECT 
                    TO_CHAR(timestamp, %s) as time_interval,
                    severity,
                    COUNT(*) as alert_count
                FROM alerts
            """
            params = [time_format]
            where_clauses = []
            
            if start_time:
                where_clauses.append("timestamp >= %s")
                params.append(start_time)
            if end_time:
                where_clauses.append("timestamp <= %s")
                params.append(end_time)
            if severity:
                where_clauses.append("severity = %s")
                params.append(severity)
                
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
                
            query += " GROUP BY time_interval, severity ORDER BY time_interval, severity"
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving alert count by time: {str(e)}")
            return []

    def get_top_source_ips(self, limit=10, start_time=None, end_time=None):
        """
        Get the top source IP addresses by packet count
        
        Args:
            limit (int): Maximum number of results to return
            start_time (datetime): Start time for the query
            end_time (datetime): End time for the query
            
        Returns:
            list: Records with source IP and count
        """
        try:
            query = """
                SELECT src_ip, COUNT(*) as packet_count
                FROM packets
            """
            params = []
            where_clauses = []
            
            if start_time:
                where_clauses.append("timestamp >= %s")
                params.append(start_time)
            if end_time:
                where_clauses.append("timestamp <= %s")
                params.append(end_time)
                
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
                
            query += " GROUP BY src_ip ORDER BY packet_count DESC LIMIT %s"
            params.append(limit)
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving top source IPs: {str(e)}")
            return []

    def get_protocol_distribution(self, start_time=None, end_time=None):
        """
        Get the distribution of protocols
        
        Args:
            start_time (datetime): Start time for the query
            end_time (datetime): End time for the query
            
        Returns:
            list: Records with protocol and count
        """
        try:
            query = """
                SELECT protocol, COUNT(*) as packet_count
                FROM packets
            """
            params = []
            where_clauses = []
            
            if start_time:
                where_clauses.append("timestamp >= %s")
                params.append(start_time)
            if end_time:
                where_clauses.append("timestamp <= %s")
                params.append(end_time)
                
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
                
            query += " GROUP BY protocol ORDER BY packet_count DESC"
            
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except Exception as e:
            logger.error(f"Error retrieving protocol distribution: {str(e)}")
            return []

    def close(self):
        """Close the database connection"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

# Create a singleton instance
db = Database()