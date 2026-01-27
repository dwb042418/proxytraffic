#!/usr/bin/env python3
"""
V2Ray Detection Engine - Real-time Network Traffic Analyzer
Detects V2Ray, Shadowsocks, Trojan, and other proxy bypass techniques
"""

import os
import sys
import time
import logging
import yaml
import json
import socket
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.dns import DNS

# Import local modules
from scoring import calculate_risk_score
from database import FlowDatabase
from parsers import parse_packet, extract_flow_features

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('detector')


class V2RayDetector:
    """Real-time V2Ray/Proxy Detection Engine"""

    def __init__(self, config_path='/app/config.yaml'):
        """Initialize detector with configuration"""
        logger.info("Initializing V2Ray Detection Engine...")

        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        # Initialize database
        self.db = FlowDatabase(self.config['detector']['db_path'])

        # Flow tracking
        self.flows = defaultdict(lambda: {
            'packets_forward': 0,
            'packets_reverse': 0,
            'bytes_forward': 0,
            'bytes_reverse': 0,
            'start_time': None,
            'last_seen': None,
            'has_user_agent': False,
            'is_gtp': False,
            'is_websocket': False,
            'destination': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'entropy_samples': [],
            'dns_sizes': [],
            'flags': set()
        })

        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'suspicious_flows': 0,
            'high_risk_flows': 0,
            'alerts': []
        }

        # Alert thresholds
        self.alert_threshold = self.config['detector']['alert_threshold']
        self.suspicious_threshold = self.config['detector']['suspicious_threshold']

        logger.info(f"Detection thresholds - Alert: {self.alert_threshold}, Suspicious: {self.suspicious_threshold}")

    def get_flow_id(self, packet):
        """Generate unique flow identifier from packet"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                return None

            proto = None
            src_port = 0
            dst_port = 0

            if TCP in packet:
                proto = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                proto = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                proto = 'OTHER'

            # Create bidirectional flow ID (sort by IP to group both directions)
            if src_ip < dst_ip:
                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            else:
                flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"

            return flow_id

        except Exception as e:
            logger.error(f"Error generating flow ID: {e}")
            return None

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        try:
            from collections import Counter
            import math

            # Convert to bytes if needed
            if isinstance(data, str):
                data = data.encode()

            # Count byte frequencies
            counter = Counter(data)
            length = len(data)

            # Calculate entropy
            entropy = 0.0
            for count in counter.values():
                p = count / length
                entropy -= p * math.log2(p)

            return entropy

        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0.0

    def analyze_packet(self, packet):
        """Analyze individual packet for V2Ray indicators"""
        try:
            self.stats['total_packets'] += 1

            # Get flow ID
            flow_id = self.get_flow_id(packet)
            if not flow_id:
                return

            flow = self.flows[flow_id]

            # Update flow metadata
            if flow['start_time'] is None:
                flow['start_time'] = time.time()
                self.stats['total_flows'] += 1

            flow['last_seen'] = time.time()

            # Extract packet info
            if IP in packet:
                flow['src_ip'] = packet[IP].src
                flow['dst_ip'] = packet[IP].dst
            elif IPv6 in packet:
                flow['src_ip'] = packet[IPv6].src
                flow['dst_ip'] = packet[IPv6].dst

            if TCP in packet:
                flow['protocol'] = 'TCP'
                flow['src_port'] = packet[TCP].sport
                flow['dst_port'] = packet[TCP].dport
                flow['bytes_forward'] += len(packet)
                flow['packets_forward'] += 1
            elif UDP in packet:
                flow['protocol'] = 'UDP'
                flow['src_port'] = packet[UDP].sport
                flow['dst_port'] = packet[UDP].dport
                flow['bytes_forward'] += len(packet)
                flow['packets_forward'] += 1

            # Check for HTTP/WebSocket
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)

                # Check for HTTP request
                if b'GET ' in payload or b'POST ' in payload:
                    # Check for User-Agent
                    if b'User-Agent:' in payload:
                        flow['has_user_agent'] = True
                    else:
                        flow['flags'].add('missing_user_agent')
                        logger.debug(f"Missing User-Agent in flow {flow_id}")

                    # Check for WebSocket upgrade
                    if b'Upgrade: websocket' in payload or b'upgrade: websocket' in payload:
                        flow['is_websocket'] = True
                        flow['flags'].add('websocket')
                        logger.debug(f"WebSocket detected in flow {flow_id}")

                # Calculate entropy
                entropy = self.calculate_entropy(payload)
                flow['entropy_samples'].append(entropy)

                if entropy > 7.5:
                    flow['flags'].add('high_entropy')

            # Check for DNS
            if packet.haslayer(DNS):
                dns_size = len(packet)
                flow['dns_sizes'].append(dns_size)

                if dns_size > 150:
                    flow['flags'].add('dns_tunneling')
                    logger.debug(f"Large DNS packet ({dns_size} bytes) in flow {flow_id}")

            # Analyze flow periodically
            if flow['packets_forward'] % 50 == 0:
                self.analyze_flow(flow_id, flow)

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")

    def analyze_flow(self, flow_id, flow):
        """Analyze flow for V2Ray patterns"""
        try:
            # Calculate unidirectional ratio
            total_packets = flow['packets_forward'] + flow['packets_reverse']
            if total_packets == 0:
                return

            unidirectional_ratio = (flow['packets_forward'] / total_packets) * 100

            # Calculate average entropy
            avg_entropy = sum(flow['entropy_samples']) / len(flow['entropy_samples']) if flow['entropy_samples'] else 0

            # Build features dictionary
            features = {
                'flow_id': flow_id,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'packets_forward': flow['packets_forward'],
                'packets_reverse': flow['packets_reverse'],
                'bytes_forward': flow['bytes_forward'],
                'bytes_reverse': flow['bytes_reverse'],
                'unidirectional_ratio': unidirectional_ratio,
                'avg_entropy': avg_entropy,
                'has_user_agent': flow['has_user_agent'],
                'is_websocket': flow['is_websocket'],
                'flags': list(flow['flags']),
                'duration': time.time() - flow['start_time'] if flow['start_time'] else 0
            }

            # Calculate risk score
            score = calculate_risk_score(features, self.config)

            # Update flow with score
            flow['risk_score'] = score

            # Generate alerts based on score
            if score >= self.alert_threshold:
                self.generate_alert('HIGH_RISK', flow_id, flow, score, features)
                self.stats['high_risk_flows'] += 1
            elif score >= self.suspicious_threshold:
                self.generate_alert('SUSPICIOUS', flow_id, flow, score, features)
                self.stats['suspicious_flows'] += 1

            # Store in database
            self.db.insert_flow(features, score)

        except Exception as e:
            logger.error(f"Error analyzing flow {flow_id}: {e}")

    def generate_alert(self, level, flow_id, flow, score, features):
        """Generate detection alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'flow_id': flow_id,
            'score': score,
            'src': f"{flow['src_ip']}:{flow['src_port']}",
            'dst': f"{flow['dst_ip']}:{flow['dst_port']}",
            'protocol': flow['protocol'],
            'indicators': list(flow['flags']),
            'details': {
                'unidirectional_ratio': features['unidirectional_ratio'],
                'avg_entropy': features['avg_entropy'],
                'has_user_agent': features['has_user_agent'],
                'is_websocket': features['is_websocket']
            }
        }

        self.stats['alerts'].append(alert)

        # Log alert
        logger.warning(f"[{level}] V2Ray Detected - Score: {score}/100")
        logger.warning(f"  Flow: {alert['src']} -> {alert['dst']}")
        logger.warning(f"  Indicators: {', '.join(alert['indicators'])}")

        # Write to alert file for dashboard
        self.write_alert_to_file(alert)

    def write_alert_to_file(self, alert):
        """Write alert to file for dashboard consumption"""
        try:
            alerts_file = '/app/data/alerts.json'
            alerts = []

            # Load existing alerts
            if os.path.exists(alerts_file):
                with open(alerts_file, 'r') as f:
                    try:
                        alerts = json.load(f)
                    except:
                        alerts = []

            # Add new alert
            alerts.append(alert)

            # Keep only last 1000 alerts
            alerts = alerts[-1000:]

            # Write back
            with open(alerts_file, 'w') as f:
                json.dump(alerts, f, indent=2)

        except Exception as e:
            logger.error(f"Error writing alert to file: {e}")

    def write_stats(self):
        """Write statistics to file for dashboard"""
        try:
            stats_file = '/app/data/stats.json'
            stats = {
                'timestamp': datetime.now().isoformat(),
                'total_packets': self.stats['total_packets'],
                'total_flows': self.stats['total_flows'],
                'suspicious_flows': self.stats['suspicious_flows'],
                'high_risk_flows': self.stats['high_risk_flows'],
                'alerts_count': len(self.stats['alerts'])
            }

            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)

        except Exception as e:
            logger.error(f"Error writing stats: {e}")

    def start(self):
        """Start real-time detection"""
        logger.info("Starting real-time packet capture...")
        logger.info(f"Interface: {self.config['detector']['interface']}")
        logger.info(f"Filter: {self.config['detector']['capture_filter']}")

        try:
            # Create data directory if needed
            os.makedirs('/app/data', exist_ok=True)

            # Start stats writer thread
            import threading
            def write_stats_loop():
                while True:
                    time.sleep(1)
                    self.write_stats()

            stats_thread = threading.Thread(target=write_stats_loop, daemon=True)
            stats_thread.start()

            # Start packet capture
            logger.info("Packet capture started. Waiting for traffic...")

            sniff(
                iface=self.config['detector']['interface'],
                filter=self.config['detector']['capture_filter'],
                prn=self.analyze_packet,
                store=False
            )

        except KeyboardInterrupt:
            logger.info("Shutting down detector...")
            self.cleanup()
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            raise

    def cleanup(self):
        """Cleanup on shutdown"""
        logger.info(f"Total packets analyzed: {self.stats['total_packets']}")
        logger.info(f"Total flows: {self.stats['total_flows']}")
        logger.info(f"Suspicious flows: {self.stats['suspicious_flows']}")
        logger.info(f"High-risk flows: {self.stats['high_risk_flows']}")
        self.db.close()


if __name__ == '__main__':
    detector = V2RayDetector()
    detector.start()
