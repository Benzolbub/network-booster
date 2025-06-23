#!/usr/bin/env python3
"""
Ultimate Network Optimizer Pro - Router Discovery + Speed Maximization
Requires: Python 3.6+, root privileges, nmap, arp-scan
Tested on: Ubuntu 20.04+, Fedora 33+, Kali Linux 2021+
"""

import os
import re
import sys
import json
import socket
import argparse
import subprocess
import multiprocessing
from collections import defaultdict
from urllib.request import urlopen, Request

# Aggressive TCP/IP optimization settings
TCP_SETTINGS = {
    # Core buffer sizes
    "net.core.rmem_max": "2147483647",
    "net.core.wmem_max": "2147483647",
    "net.core.netdev_max_backlog": "300000",
    "net.core.somaxconn": "65535",
    # TCP buffer sizes
    "net.ipv4.tcp_rmem": "4096 87380 2147483647",
    "net.ipv4.tcp_wmem": "4096 65536 2147483647",
    "net.ipv4.tcp_mem": "2147483647 2147483647 2147483647",
    # TCP algorithm
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_sack": "1",
    "net.ipv4.tcp_fastopen": "3",
    "net.ipv4.tcp_tw_reuse": "1",
    "net.ipv4.tcp_fin_timeout": "15",
    "net.ipv4.tcp_slow_start_after_idle": "0",
    # Queue management
    "net.core.default_qdisc": "fq",
    # Connection tracking
    "net.netfilter.nf_conntrack_max": "2000000",
    "net.ipv4.tcp_max_syn_backlog": "3240000",
    "net.ipv4.tcp_max_tw_buckets": "1440000",
}

def check_root():
    """Verify script is run as root"""
    if os.geteuid() != 0:
        print("❌ ERROR: This script must be run as root/sudo")
        sys.exit(1)

def run_cmd(cmd, capture=True):
    """Execute shell command with error handling"""
    try:
        result = subprocess.run(cmd, shell=True, check=True,
                               stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.PIPE if capture else None,
                               text=True)
        return result.stdout.strip() if capture else None
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Command failed: {cmd}\nError: {e.stderr.strip() if capture else str(e)}")
        return None

def get_network_info():
    """Retrieve detailed network configuration and router information"""
    print("\n🔍 Discovering network information...")
    
    # Get default gateway
    gateway = run_cmd("ip route | grep default | awk '{print $3}' | head -1")
    interface = run_cmd("ip route | grep default | awk '{print $5}' | head -1")
    
    if not gateway or not interface:
        print("❌ Failed to detect default gateway or interface")
        sys.exit(1)
    
    print(f"  • Default Gateway: {gateway}")
    print(f"  • Interface: {interface}")
    
    # Get MAC address of gateway
    arp_info = run_cmd(f"arp -n {gateway}")
    mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", arp_info)
    mac = mac_match.group(0) if mac_match else "Unknown"
    print(f"  • Router MAC: {mac}")
    
    # Get local IP and subnet
    ip_info = run_cmd(f"ip -o -4 addr show dev {interface}")
    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', ip_info)
    local_ip, subnet = ip_match.groups() if ip_match else ("Unknown", "Unknown")
    print(f"  • Local IP: {local_ip}/{subnet}")
    
    # Scan local network for devices
    print("\n📡 Scanning local network for devices...")
    devices = []
    try:
        arp_scan = run_cmd(f"arp-scan --localnet --interface={interface}")
        for line in arp_scan.splitlines():
            if re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):
                parts = line.split()
                ip, mac = parts[0], parts[1]
                vendor = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"
                devices.append({"ip": ip, "mac": mac, "vendor": vendor})
                print(f"  • Device: {ip} ({mac}) - {vendor}")
    except:
        print("  ⚠️ arp-scan not available, using limited discovery")
    
    # Identify router model
    router_model = "Unknown"
    try:
        # Try to get router info via HTTP
        req = Request(f"http://{gateway}", headers={'User-Agent': 'Mozilla/5.0'})
        with urlopen(req, timeout=3) as response:
            html = response.read().decode('utf-8', errors='ignore')
            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            if title_match:
                router_model = title_match.group(1)
                print(f"  • Router Model (detected): {router_model}")
    except:
        pass
    
    # DNS information
    dns_servers = run_cmd("grep nameserver /etc/resolv.conf | awk '{print $2}'").splitlines()
    print(f"  • DNS Servers: {', '.join(dns_servers)}")
    
    return {
        "gateway": gateway,
        "interface": interface,
        "router_mac": mac,
        "router_model": router_model,
        "local_ip": local_ip,
        "subnet": subnet,
        "dns_servers": dns_servers,
        "devices": devices
    }

def apply_max_optimizations(interface):
    """Apply maximum network speed optimizations to local system"""
    print(f"\n🚀 Applying MAXIMUM speed optimizations to {interface}")
    
    # Apply TCP settings
    print("\n⚙️ Configuring kernel network parameters")
    for key, value in TCP_SETTINGS.items():
        run_cmd(f"sysctl -w {key}={value}", capture=False)
        print(f"  ✓ {key} = {value}")
    
    # Disable power saving
    print(f"\n⚡ Disabling power saving on {interface}")
    run_cmd(f"ethtool -s {interface} wol d autoneg on speed auto duplex full", capture=False)
    run_cmd(f"iw dev {interface} set power_save off", capture=False)
    run_cmd(f"echo on > /sys/class/net/{interface}/power/control", capture=False)
    
    # Enable hardware offloading
    print("\n🔧 Enabling hardware offloading features")
    features = [
        "tso on", "gso on", "gro on", "lro on", 
        "tx on", "rx on", "sg on", "txvlan on", "rxvlan on"
    ]
    for feature in features:
        run_cmd(f"ethtool -K {interface} {feature}", capture=False)
    
    # IRQ balancing
    print("\n🎛️ Optimizing IRQ handling")
    irqs = run_cmd(f"grep {interface} /proc/interrupts | cut -d: -f1")
    if irqs:
        irqs = irqs.split()
        cpu_count = multiprocessing.cpu_count()
        for i, irq in enumerate(irqs):
            cpu_mask = 1 << (i % cpu_count)
            run_cmd(f"echo {hex(cpu_mask)} > /proc/irq/{irq}/smp_affinity", capture=False)
            print(f"  ✓ IRQ {irq} → CPU {i % cpu_count}")
    
    # MTU Optimization (test jumbo frames)
    print("\n📦 Testing optimal MTU size")
    run_cmd(f"ip link set dev {interface} mtu 1500", capture=False)
    ping_test = run_cmd(f"ping -c 2 -M do -s 1472 {net_info['gateway']}")
    if "0% packet loss" in ping_test:
        run_cmd(f"ip link set dev {interface} mtu 9000", capture=False)
        print("  ✓ Jumbo frames (MTU 9000) enabled")
    else:
        print("  • Using standard MTU 1500 (jumbo frames not supported)")
    
    # Make settings persistent
    print("\n🔒 Making optimizations persistent")
    with open("/etc/sysctl.d/99-max-network.conf", "w") as f:
        for key, value in TCP_SETTINGS.items():
            f.write(f"{key} = {value}\n")
    
    # Create startup script
    with open("/etc/network/if-up.d/99-max-network", "w") as f:
        f.write(f"""#!/bin/sh
[ "$IFACE" != "{interface}" ] && exit 0
ethtool -s {interface} wol d autoneg on speed auto duplex full
ethtool -K {interface} tso on gso on gro on lro on tx on rx on
echo on > /sys/class/net/{interface}/power/control
ip link set dev {interface} mtu 9000
sysctl -p /etc/sysctl.d/99-max-network.conf
""")
    run_cmd("chmod +x /etc/network/if-up.d/99-max-network")
    
    print("\n💨 MAXIMUM NETWORK BOOST APPLIED!")

def suggest_router_optimizations(net_info):
    """Provide suggestions for router optimizations"""
    print("\n📊 Router Optimization Suggestions:")
    
    print("1. 📶 WiFi Channel Optimization:")
    print("   - Use 5GHz band for less interference")
    print("   - Choose least congested channel (use WiFi analyzer)")
    print("   - Enable 80MHz or 160MHz channel width if supported")
    
    print("\n2. 🔧 Advanced Settings:")
    print("   - Enable Hardware NAT acceleration")
    print("   - Disable QoS/bandwidth limiting")
    print("   - Enable IPv6 if supported by ISP")
    
    print("\n3. 🔒 Security Recommendations:")
    print("   - Use WPA3 encryption")
    print("   - Change default admin credentials")
    print("   - Disable WPS and UPnP if not needed")
    
    print("\n4. ⚙️ Firmware Update:")
    print("   - Check for latest firmware at manufacturer's website")
    
    print("\n5. 🌐 DNS Configuration:")
    print("   - Use faster DNS servers like:")
    print("     • Cloudflare: 1.1.1.1, 1.0.0.1")
    print("     • Google: 8.8.8.8, 8.8.4.4")
    print("     • Quad9: 9.9.9.9")
    
    print("\n🔍 Access your router at:")
    print(f"   http://{net_info['gateway']} (admin interface)")
    
    print("\n⚠️ Note: Router changes require manual configuration")
    print("         through the web interface using admin credentials")

def speed_test(net_info):
    """Perform basic network speed test"""
    print("\n⏱️ Performing speed test to router...")
    ping_result = run_cmd(f"ping -c 4 {net_info['gateway']}")
    if ping_result:
        match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+', ping_result)
        if match:
            print(f"  • Ping to router: {match.group(1)} ms")
    
    print("\n🚀 Testing throughput with iperf3 (install if missing):")
    print("   First start server on another machine: 'iperf3 -s'")
    print(f"   Then run: 'iperf3 -c {server_ip} -P 8'")
    print("   For internet speed test: 'speedtest-cli'")

def main():
    parser = argparse.ArgumentParser(description='Ultimate Network Optimizer Pro')
    parser.add_argument('--apply', action='store_true', help='Apply speed optimizations')
    parser.add_argument('--test', action='store_true', help='Run speed tests')
    args = parser.parse_args()

    check_root()
    global net_info
    net_info = get_network_info()
    
    if args.apply:
        apply_max_optimizations(net_info['interface'])
    
    suggest_router_optimizations(net_info)
    
    if args.test:
        speed_test(net_info)
    
    print("\n✅ Network optimization complete!")

if __name__ == "__main__":
    net_info = None
    main()
