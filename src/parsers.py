"""
Packet parsers for various protocols
"""

import logging

logger = logging.getLogger('parsers')


def parse_packet(packet):
    """
    Parse packet and extract relevant information

    Args:
        packet: Scapy packet object

    Returns:
        dict: Parsed packet information
    """
    info = {
        'timestamp': packet.time if hasattr(packet, 'time') else None,
        'length': len(packet),
        'protocol': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'payload': None
    }

    try:
        from scapy.all import IP, IPv6, TCP, UDP, Raw

        # IP layer
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
        elif packet.haslayer(IPv6):
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst

        # Transport layer
        if packet.haslayer(TCP):
            info['protocol'] = 'TCP'
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
        elif packet.haslayer(UDP):
            info['protocol'] = 'UDP'
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport

        # Payload
        if packet.haslayer(Raw):
            info['payload'] = bytes(packet[Raw].load)

    except Exception as e:
        logger.error(f"Error parsing packet: {e}")

    return info


def extract_flow_features(flow_data):
    """
    Extract features from flow for ML/analysis

    Args:
        flow_data: Flow dictionary

    Returns:
        dict: Feature vector
    """
    features = {}

    try:
        # Basic flow statistics
        features['packets_forward'] = flow_data.get('packets_forward', 0)
        features['packets_reverse'] = flow_data.get('packets_reverse', 0)
        features['bytes_forward'] = flow_data.get('bytes_forward', 0)
        features['bytes_reverse'] = flow_data.get('bytes_reverse', 0)

        # Derived features
        total_packets = features['packets_forward'] + features['packets_reverse']
        total_bytes = features['bytes_forward'] + features['bytes_reverse']

        if total_packets > 0:
            features['bidirectional_ratio'] = features['packets_reverse'] / total_packets
        else:
            features['bidirectional_ratio'] = 0.0

        if total_bytes > 0:
            features['avg_packet_size'] = total_bytes / total_packets
        else:
            features['avg_packet_size'] = 0.0

        # Duration
        start_time = flow_data.get('start_time')
        last_seen = flow_data.get('last_seen')
        if start_time and last_seen:
            features['duration'] = last_seen - start_time
        else:
            features['duration'] = 0.0

        # Entropy
        entropy_samples = flow_data.get('entropy_samples', [])
        if entropy_samples:
            features['avg_entropy'] = sum(entropy_samples) / len(entropy_samples)
            features['max_entropy'] = max(entropy_samples)
        else:
            features['avg_entropy'] = 0.0
            features['max_entropy'] = 0.0

        # Boolean features
        features['has_user_agent'] = 1 if flow_data.get('has_user_agent', False) else 0
        features['is_websocket'] = 1 if flow_data.get('is_websocket', False) else 0
        features['is_gtp'] = 1 if flow_data.get('is_gtp', False) else 0

        # DNS features
        dns_sizes = flow_data.get('dns_sizes', [])
        if dns_sizes:
            features['dns_avg_size'] = sum(dns_sizes) / len(dns_sizes)
            features['dns_max_size'] = max(dns_sizes)
        else:
            features['dns_avg_size'] = 0.0
            features['dns_max_size'] = 0.0

        # Port features
        dst_port = flow_data.get('dst_port', 0)
        features['is_common_port'] = 1 if dst_port in [80, 443, 8080, 8443] else 0

    except Exception as e:
        logger.error(f"Error extracting features: {e}")

    return features


def is_v2ray_pattern(payload):
    """
    Check if payload contains V2Ray-specific patterns

    Args:
        payload: Bytes payload

    Returns:
        bool: True if V2Ray patterns detected
    """
    if not payload:
        return False

    try:
        # Common V2Ray/proxy indicators
        v2ray_patterns = [
            b'vmess://',
            b'vless://',
            b'trojan://',
            b'shadowsocks://',
            b'ss://'
        ]

        for pattern in v2ray_patterns:
            if pattern in payload:
                return True

        # Check for custom headers
        custom_headers = [
            b'x-v2ray',
            b'x-trojan',
            b'x-shadowsocks'
        ]

        for header in custom_headers:
            if header in payload.lower():
                return True

    except Exception as e:
        logger.error(f"Error checking V2Ray pattern: {e}")

    return False
