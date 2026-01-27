#!/usr/bin/env python3
"""
V2Ray Server URL Fetcher
Automatically fetches fresh V2Ray server URLs from TelegramV2rayCollector repository
"""

import requests
import yaml
import random
import sys
from datetime import datetime

# GitHub repository URLs
REPO_BASE = "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks"
URLS = {
    'vmess': f"{REPO_BASE}/vmess.txt",
    'vless': f"{REPO_BASE}/vless.txt",
    'ss': f"{REPO_BASE}/ss.txt",
    'trojan': f"{REPO_BASE}/trojan.txt",
}

def fetch_servers(protocol):
    """Fetch server URLs for a specific protocol"""
    try:
        print(f"Fetching {protocol.upper()} servers...")
        response = requests.get(URLS[protocol], timeout=10)
        response.raise_for_status()

        # Split by lines and filter empty lines
        servers = [line.strip() for line in response.text.split('\n') if line.strip()]

        # Filter to only valid URLs
        servers = [s for s in servers if s.startswith(f"{protocol}://")]

        print(f"  Found {len(servers)} {protocol.upper()} servers")
        return servers

    except Exception as e:
        print(f"  Error fetching {protocol} servers: {e}")
        return []


def get_all_servers(max_per_protocol=5):
    """Fetch servers from all protocols"""
    all_servers = []

    for protocol in ['vless', 'vmess', 'ss', 'trojan']:
        servers = fetch_servers(protocol)

        if servers:
            # Randomly select up to max_per_protocol servers
            selected = random.sample(servers, min(max_per_protocol, len(servers)))
            all_servers.extend(selected)
            print(f"  Selected {len(selected)} {protocol.upper()} servers")

    return all_servers


def update_config_yaml(servers, config_path='../config.yaml'):
    """Update config.yaml with fetched servers"""
    try:
        print(f"\nUpdating {config_path}...")

        # Read existing config
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Update v2ray_servers
        config['attacker']['v2ray_servers'] = servers

        # Write back
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

        print(f"  ✓ Updated config.yaml with {len(servers)} servers")
        return True

    except Exception as e:
        print(f"  ✗ Error updating config: {e}")
        return False


def display_servers(servers):
    """Display fetched servers"""
    print("\n" + "="*70)
    print(f"FETCHED V2RAY SERVERS ({len(servers)} total)")
    print("="*70)

    protocols = {}
    for server in servers:
        protocol = server.split('://')[0]
        protocols[protocol] = protocols.get(protocol, 0) + 1

    print(f"\nProtocol Distribution:")
    for protocol, count in protocols.items():
        print(f"  {protocol.upper()}: {count} servers")

    print(f"\nSample URLs (first 3):")
    for i, server in enumerate(servers[:3], 1):
        # Truncate long URLs for display
        display_url = server[:100] + "..." if len(server) > 100 else server
        print(f"  {i}. {display_url}")

    print("="*70)


def main():
    """Main function"""
    print("="*70)
    print("V2RAY SERVER URL FETCHER")
    print("="*70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Source: {REPO_BASE}")
    print("="*70 + "\n")

    # Fetch servers (up to 5 per protocol)
    servers = get_all_servers(max_per_protocol=5)

    if not servers:
        print("\n✗ No servers found! Check your internet connection.")
        sys.exit(1)

    # Display servers
    display_servers(servers)

    # Ask user if they want to update config
    print("\nOptions:")
    print("  1. Update config.yaml automatically")
    print("  2. Display servers only (no update)")
    print("  3. Export to file")

    try:
        choice = input("\nEnter choice (1/2/3) [default: 1]: ").strip() or "1"

        if choice == "1":
            # Determine config path
            import os
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(script_dir, '..', 'config.yaml')

            if update_config_yaml(servers, config_path):
                print("\n✓ Config updated successfully!")
                print("  Next steps:")
                print("    1. Rebuild containers: docker-compose build --no-cache")
                print("    2. Start system: ./demo.sh start")
                print("    3. Launch attack: ./demo.sh attack")
            else:
                print("\n✗ Failed to update config")

        elif choice == "2":
            print("\nServers displayed. No changes made.")

        elif choice == "3":
            output_file = f"v2ray_servers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(output_file, 'w') as f:
                f.write('\n'.join(servers))
            print(f"\n✓ Servers exported to: {output_file}")

        else:
            print("\nInvalid choice. No changes made.")

    except KeyboardInterrupt:
        print("\n\nCancelled by user.")
        sys.exit(0)


if __name__ == '__main__':
    main()
