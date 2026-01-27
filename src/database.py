"""
Database module for storing flow data
Uses SQLite for simplicity
"""

import sqlite3
import json
import logging
from datetime import datetime

logger = logging.getLogger('database')


class FlowDatabase:
    """SQLite database for flow storage"""

    def __init__(self, db_path='/app/data/flows.db'):
        """Initialize database connection"""
        self.db_path = db_path
        self.conn = None
        self.connect()
        self.create_tables()

    def connect(self):
        """Connect to database"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to database: {self.db_path}")
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise

    def create_tables(self):
        """Create database tables if they don't exist"""
        try:
            cursor = self.conn.cursor()

            # Flows table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packets_forward INTEGER,
                    packets_reverse INTEGER,
                    bytes_forward INTEGER,
                    bytes_reverse INTEGER,
                    unidirectional_ratio REAL,
                    avg_entropy REAL,
                    has_user_agent BOOLEAN,
                    is_websocket BOOLEAN,
                    duration REAL,
                    risk_score INTEGER,
                    flags TEXT,
                    UNIQUE(flow_id, timestamp)
                )
            ''')

            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    score INTEGER,
                    src TEXT,
                    dst TEXT,
                    protocol TEXT,
                    indicators TEXT,
                    details TEXT
                )
            ''')

            # Create indices
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_score ON flows(risk_score)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_id ON flows(flow_id)')

            self.conn.commit()
            logger.info("Database tables created/verified")

        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            raise

    def insert_flow(self, features, risk_score):
        """Insert flow record"""
        try:
            cursor = self.conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO flows (
                    timestamp, flow_id, src_ip, dst_ip, src_port, dst_port,
                    protocol, packets_forward, packets_reverse,
                    bytes_forward, bytes_reverse, unidirectional_ratio,
                    avg_entropy, has_user_agent, is_websocket,
                    duration, risk_score, flags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                features.get('flow_id', ''),
                features.get('src_ip', ''),
                features.get('dst_ip', ''),
                features.get('src_port', 0),
                features.get('dst_port', 0),
                features.get('protocol', ''),
                features.get('packets_forward', 0),
                features.get('packets_reverse', 0),
                features.get('bytes_forward', 0),
                features.get('bytes_reverse', 0),
                features.get('unidirectional_ratio', 0.0),
                features.get('avg_entropy', 0.0),
                features.get('has_user_agent', False),
                features.get('is_websocket', False),
                features.get('duration', 0.0),
                risk_score,
                json.dumps(features.get('flags', []))
            ))

            self.conn.commit()

        except Exception as e:
            logger.error(f"Error inserting flow: {e}")

    def insert_alert(self, alert):
        """Insert alert record"""
        try:
            cursor = self.conn.cursor()

            cursor.execute('''
                INSERT INTO alerts (
                    timestamp, level, flow_id, score, src, dst,
                    protocol, indicators, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert['level'],
                alert['flow_id'],
                alert['score'],
                alert['src'],
                alert['dst'],
                alert['protocol'],
                json.dumps(alert['indicators']),
                json.dumps(alert['details'])
            ))

            self.conn.commit()

        except Exception as e:
            logger.error(f"Error inserting alert: {e}")

    def get_recent_flows(self, limit=100):
        """Get recent flows"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM flows
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Error getting recent flows: {e}")
            return []

    def get_high_risk_flows(self, threshold=70, limit=100):
        """Get high-risk flows"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM flows
                WHERE risk_score >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (threshold, limit))

            return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Error getting high-risk flows: {e}")
            return []

    def get_statistics(self):
        """Get overall statistics"""
        try:
            cursor = self.conn.cursor()

            # Total flows
            cursor.execute('SELECT COUNT(*) as count FROM flows')
            total_flows = cursor.fetchone()['count']

            # High-risk flows
            cursor.execute('SELECT COUNT(*) as count FROM flows WHERE risk_score >= 70')
            high_risk = cursor.fetchone()['count']

            # Suspicious flows
            cursor.execute('SELECT COUNT(*) as count FROM flows WHERE risk_score >= 40 AND risk_score < 70')
            suspicious = cursor.fetchone()['count']

            # Total alerts
            cursor.execute('SELECT COUNT(*) as count FROM alerts')
            total_alerts = cursor.fetchone()['count']

            return {
                'total_flows': total_flows,
                'high_risk_flows': high_risk,
                'suspicious_flows': suspicious,
                'total_alerts': total_alerts
            }

        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def clear_all_data(self):
        """Clear all data from database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM flows')
            cursor.execute('DELETE FROM alerts')
            self.conn.commit()
            logger.info("All data cleared from database")
        except Exception as e:
            logger.error(f"Error clearing data: {e}")

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
