"""
Risk Scoring Engine for V2Ray Detection
Implements multi-factor scoring system
"""

import logging

logger = logging.getLogger('scoring')


def calculate_risk_score(features, config):
    """
    Calculate risk score for a flow based on multiple indicators

    Args:
        features: Dict containing flow features
        config: Configuration dict with scoring weights

    Returns:
        int: Risk score (0-100)
    """
    score = 0
    weights = config['scoring']['weights']

    # Factor 1: Missing User-Agent (medium signal)
    if not features.get('has_user_agent', True) and features.get('is_websocket', False):
        score += weights['missing_user_agent']
        logger.debug(f"Missing User-Agent: +{weights['missing_user_agent']}")

    # Factor 2: Unidirectional traffic (strong signal)
    unidirectional_ratio = features.get('unidirectional_ratio', 0)
    if unidirectional_ratio > 90:
        score += weights['unidirectional_high']
        logger.debug(f"High unidirectional ratio ({unidirectional_ratio:.1f}%): +{weights['unidirectional_high']}")
    elif unidirectional_ratio > 75:
        score += weights['unidirectional_low']
        logger.debug(f"Low unidirectional ratio ({unidirectional_ratio:.1f}%): +{weights['unidirectional_low']}")

    # Factor 3: High entropy (strong signal for encrypted proxy)
    avg_entropy = features.get('avg_entropy', 0)
    if avg_entropy > 7.5:
        score += weights['high_entropy']
        logger.debug(f"High entropy ({avg_entropy:.2f}): +{weights['high_entropy']}")

    # Factor 4: Check flags
    flags = set(features.get('flags', []))

    if 'dns_tunneling' in flags:
        score += weights['dns_tunneling']
        logger.debug(f"DNS tunneling detected: +{weights['dns_tunneling']}")

    if 'websocket' in flags and 'missing_user_agent' in flags:
        score += weights['websocket_opcode']
        logger.debug(f"WebSocket abuse: +{weights['websocket_opcode']}")

    if 'high_entropy' in flags:
        # Already counted above
        pass

    # Factor 5: Sustained connection (weak signal)
    duration = features.get('duration', 0)
    if duration > 3600:  # 1 hour+
        score += weights['sustained_connection']
        logger.debug(f"Sustained connection ({duration}s): +{weights['sustained_connection']}")

    # Factor 6: Check destination against whitelist
    dst_ip = features.get('dst_ip', '')
    if is_whitelisted(dst_ip, config):
        score = max(0, score - 30)  # Reduce score for whitelisted destinations
        logger.debug(f"Whitelisted destination, reducing score by 30")

    # Cap score at 100
    score = min(100, score)

    return score


def is_whitelisted(ip_or_domain, config):
    """Check if IP/domain is whitelisted"""
    whitelist_ips = config['scoring'].get('whitelist_ips', [])
    whitelist_domains = config['scoring'].get('whitelist_domains', [])

    # Check IP
    if ip_or_domain in whitelist_ips:
        return True

    # Check domain (would need DNS resolution in real implementation)
    for domain in whitelist_domains:
        if domain in ip_or_domain:
            return True

    return False


def get_risk_level(score):
    """Convert score to risk level"""
    if score >= 80:
        return 'CRITICAL'
    elif score >= 70:
        return 'HIGH'
    elif score >= 40:
        return 'SUSPICIOUS'
    else:
        return 'LOW'
