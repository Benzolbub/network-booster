#!/usr/bin/env python3
"""
Network Speed Booster Script
Requires: Python 3.x, root privileges
Tested on: Ubuntu/Debian, Fedora, CentOS
"""

import os
import subprocess
import sys
import argparse

# Configuration parameters
TCP_SETTINGS = {
    # TCP buffer sizes
    "net.core.rmem_max": "12582912",
    "net.core.wmem_max": "12582912",
    "net.ipv4.tcp_rmem": "4096 12582912 16777216",
    "net.ipv4.tcp_wmem": "4096 12582912 16777216",
    
    # TCP algorithm settings
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_sack": "1",
    "net.ipv4.tcp_fastopen": "3",
    
    # Queue management
    "net.core.default_qdisc": "fq",
    
    # Connection tracking
    "net.netfilter.nf_conntrack_max": "1000000"
}

def check_root():
    """Verify script is run as root"""
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root/sudo")
        sys.exit(1)

def apply_sysctl_settings():
    """Apply TCP/IP stack optimizations"""
    print("\n⚙️ Applying kernel network optimizations")
    for key, value in TCP_SETTINGS.items():
        try:
            subprocess.run(["sysctl", "-w", f"{key}={value}"], check=True)
            print(f"  ✓ {key} = {value}")
        except subprocess.CalledProcessError:
            print(f"  ✗ Failed to set {key} (unsupported?)")

def disable_powersave(interface):
    """Disable power saving features on network interface"""
    print(f"\n⚡ Disabling power saving for {interface}")
    try:
        subprocess.run(["ethtool", "-s", interface, "wol", "d", "autoneg", "on", "speed", "auto", "duplex", "full"], check=True)
        subprocess.run(["iw", interface, "set", "power_save", "off"], check=True)
        print("  ✓ Power management disabled")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("  ✗ ethtool/iw not available or failed (check interface name)")

def configure_irq_balance():
    """Optimize IRQ balancing configuration"""
    print("\n🎚️ Configuring IRQ balancing")
    try:
        with open("/etc/default/irqbalance", "a") as f:
            f.write('\n# Optimized by network booster\nOPTIONS="--policyscript=/etc/irqbalance.policy"')
        print("  ✓ IRQ balance configured")
    except Exception as e:
        print(f"  ✗ Configuration failed: {str(e)}")

def restart_services():
    """Restart network services"""
    print("\n🔄 Restarting networking services")
    services = ["irqbalance", "systemd-networkd", "NetworkManager"]
    for service in services:network_boost.py
        try:
            subprocess.run(["systemctl", "restart", service], stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            continue

def main():
    parser = argparse.ArgumentParser(description='Network Speed Booster')
    parser.add_argument('-i', '--interface', help='Network interface (e.g., eth0)')
    args = parser.parse_args()

    check_root()
    print("🔧 Starting network optimization")
    
    apply_sysctl_settings()
    
    if args.interface:
        disable_powersave(args.interface)
    else:
        print("\n⚠️ No interface specified - skipping NIC optimizations")
    
    configure_irq_balance()
    restart_services()
    
    print("\n✅ Optimizations applied!")
    print("Note: Some changes are temporary. To make persistent:")
    print("1. Save current settings: sysctl -p > /etc/sysctl.d/99-network.conf")
    print("2. Re-run after reboots")

if __name__ == "__main__":
    main()
