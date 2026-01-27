#!/usr/bin/env python3
"""
V2Ray Real Traffic Generator - Using v2ray2proxy Library
Generates ACTUAL V2Ray protocol traffic (VMess, VLESS, Shadowsocks, Trojan)
"""

import os
import sys
import time
import random
import logging
import yaml
import requests
import threading
from datetime import datetime

# Import v2ray2proxy for real V2Ray traffic
try:
    from v2ray2proxy import V2RayProxy
    V2RAY_AVAILABLE = True
    logging.info("v2ray2proxy library loaded successfully")
except ImportError:
    V2RAY_AVAILABLE = False
    logging.error("v2ray2proxy not installed. Install with: pip install v2ray2proxy")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('attacker')


class RealV2RayTrafficGenerator:
    """Generates REAL V2Ray traffic using v2ray2proxy library"""

    def __init__(self, config_path='/app/config.yaml'):
        """Initialize real V2Ray traffic generator"""
        logger.info("=" * 60)
        logger.info("REAL V2RAY TRAFFIC GENERATOR")
        logger.info("=" * 60)

        if not V2RAY_AVAILABLE:
            logger.error("v2ray2proxy library not available!")
            logger.error("Install with: pip install v2ray2proxy")
            sys.exit(1)

        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        # Get V2Ray server configurations
        self.v2ray_servers = self.config['attacker'].get('v2ray_servers', [])

        if not self.v2ray_servers:
            logger.error("No V2Ray servers configured!")
            logger.error("Add V2Ray server URLs in config.yaml under attacker.v2ray_servers")
            logger.error("Example: vmess://base64config or vless://... or ss://... or trojan://...")
            sys.exit(1)

        self.intensity = self.config['attacker']['intensity']
        self.duration = self.config['attacker']['duration']

        # Calculate requests per second based on intensity
        intensity_map = {
            'light': 2,      # 2 requests/sec
            'medium': 10,    # 10 requests/sec
            'aggressive': 30 # 30 requests/sec
        }
        self.rps = intensity_map.get(self.intensity, 10)

        # Target websites to access through V2Ray
        self.target_urls = self.config['attacker'].get('target_urls', [
            'http://httpbin.org/ip',
            'http://httpbin.org/user-agent',
            'http://httpbin.org/headers',
            'http://example.com',
            'http://ifconfig.me',
        ])

        self.running = False
        self.active_proxies = []
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'bytes_transferred': 0,
            'active_servers': 0,
            'start_time': None
        }

        logger.info(f"Loaded {len(self.v2ray_servers)} V2Ray server(s)")
        logger.info(f"Intensity: {self.intensity} ({self.rps} requests/sec)")
        logger.info(f"Duration: {'Infinite' if self.duration == 0 else f'{self.duration}s'}")

    def initialize_v2ray_proxies(self):
        """Initialize V2Ray proxy connections"""
        logger.info("Initializing V2Ray proxies...")

        for idx, server_url in enumerate(self.v2ray_servers):
            try:
                # Extract protocol type
                protocol = server_url.split('://')[0] if '://' in server_url else 'unknown'
                logger.info(f"[{idx+1}/{len(self.v2ray_servers)}] Connecting to {protocol.upper()} server...")

                # Initialize V2Ray proxy
                proxy = V2RayProxy(server_url)

                # Test connection
                proxies = {
                    'http': proxy.http_proxy_url,
                    'https': proxy.http_proxy_url
                }

                # Quick connection test
                test_response = requests.get(
                    'http://httpbin.org/ip',
                    proxies=proxies,
                    timeout=10
                )

                if test_response.status_code == 200:
                    self.active_proxies.append({
                        'proxy': proxy,
                        'proxies': proxies,
                        'protocol': protocol,
                        'url': server_url,
                        'working': True
                    })
                    logger.info(f"  ✓ {protocol.upper()} proxy connected successfully")
                    logger.info(f"  ✓ External IP: {test_response.json().get('origin', 'unknown')}")
                else:
                    logger.warning(f"  ✗ {protocol.upper()} proxy test failed")
                    proxy.stop()

            except Exception as e:
                logger.error(f"  ✗ Failed to connect to server {idx+1}: {e}")
                continue

        self.stats['active_servers'] = len(self.active_proxies)

        if not self.active_proxies:
            logger.error("No working V2Ray proxies available!")
            logger.error("Please check your V2Ray server URLs in config.yaml")
            sys.exit(1)

        logger.info(f"Successfully connected to {len(self.active_proxies)} V2Ray server(s)")

    def generate_real_v2ray_traffic(self):
        """Generate real V2Ray traffic through proxies"""
        logger.info("Starting real V2Ray traffic generation...")

        request_count = 0
        start_time = time.time()
        self.stats['start_time'] = start_time

        try:
            while self.running:
                # Check duration limit
                if self.duration > 0 and (time.time() - start_time) >= self.duration:
                    logger.info(f"Duration limit reached ({self.duration}s)")
                    break

                # Select random proxy
                proxy_config = random.choice(self.active_proxies)
                proxies = proxy_config['proxies']
                protocol = proxy_config['protocol']

                # Select random target URL
                target_url = random.choice(self.target_urls)

                try:
                    # Make REAL HTTP request through V2Ray
                    response = requests.get(
                        target_url,
                        proxies=proxies,
                        timeout=15,
                        headers={
                            'User-Agent': self._get_random_user_agent()
                        }
                    )

                    # Update statistics
                    self.stats['total_requests'] += 1
                    self.stats['successful_requests'] += 1
                    self.stats['bytes_transferred'] += len(response.content)

                    request_count += 1

                    # Log progress every 10 requests
                    if request_count % 10 == 0:
                        elapsed = time.time() - start_time
                        actual_rps = request_count / elapsed if elapsed > 0 else 0
                        logger.info(
                            f"Progress: {request_count} requests | "
                            f"{actual_rps:.1f} req/s | "
                            f"{self.stats['bytes_transferred']/1024:.1f} KB | "
                            f"Protocol: {protocol.upper()}"
                        )

                except requests.exceptions.RequestException as e:
                    self.stats['total_requests'] += 1
                    self.stats['failed_requests'] += 1
                    logger.debug(f"Request failed: {e}")

                # Rate limiting
                time.sleep(1.0 / self.rps)

        except KeyboardInterrupt:
            logger.info("Traffic generation interrupted by user")

    def _get_random_user_agent(self):
        """Get random User-Agent string"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
        ]
        return random.choice(user_agents)

    def start(self):
        """Start real V2Ray traffic generation"""
        logger.info("=" * 60)
        logger.info("STARTING REAL V2RAY TRAFFIC GENERATION")
        logger.info("=" * 60)

        # Initialize proxies
        self.initialize_v2ray_proxies()

        # Start traffic generation
        self.running = True

        try:
            self.generate_real_v2ray_traffic()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.cleanup()

    def cleanup(self):
        """Cleanup and close all proxy connections"""
        logger.info("Cleaning up...")

        # Stop all proxies
        for proxy_config in self.active_proxies:
            try:
                proxy_config['proxy'].stop()
            except:
                pass

        # Print final statistics
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0

        logger.info("=" * 60)
        logger.info("FINAL STATISTICS")
        logger.info("=" * 60)
        logger.info(f"Total Requests: {self.stats['total_requests']}")
        logger.info(f"Successful: {self.stats['successful_requests']}")
        logger.info(f"Failed: {self.stats['failed_requests']}")
        logger.info(f"Success Rate: {(self.stats['successful_requests']/self.stats['total_requests']*100):.1f}%" if self.stats['total_requests'] > 0 else "N/A")
        logger.info(f"Data Transferred: {self.stats['bytes_transferred']/1024/1024:.2f} MB")
        logger.info(f"Duration: {elapsed:.1f}s")
        logger.info(f"Average Rate: {(self.stats['total_requests']/elapsed):.1f} req/s" if elapsed > 0 else "N/A")
        logger.info(f"Active V2Ray Servers: {self.stats['active_servers']}")
        logger.info("=" * 60)


if __name__ == '__main__':
    logger.info("Starting Real V2Ray Traffic Generator...")

    generator = RealV2RayTrafficGenerator()
    generator.start()
