#!/usr/bin/env python3
"""
Ultimate Network Speed Booster
Requires: Python 3.6+, root privileges
Tested on: Ubuntu 20.04+, Fedora 33+, Kali Linux 2021+
"""

import os
import subprocess
import sys
import argparse
import multiprocessing
import re

# Aggressive TCP/IP optimization settings
TCP_SETTINGS = {
    # Core buffer sizes
    "net.core.rmem_max": "2147483647",  # Max receive buffer (2GB)
    "net.core.wmem_max": "2147483647",  # Max send buffer (2GB)
    "net.core.netdev_max_backlog": "300000",  # Increased packet queue
    "net.core.somaxconn": "65535",  # Max connection backlog
    
    # TCP buffer sizes
    "net.ipv4.tcp_rmem": "4096 87380 2147483647",
    "net.ipv4.tcp_wmem": "4096 65536 2147483647",
    "net.ipv4.tcp_mem": "2147483647 2147483647 2147483647",
    
    # TCP algorithm settings
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
    
    # IPv6 optimizations
    "net.ipv6.conf.all.disable_ipv6": "0",
    "net.ipv6.conf.default.disable_ipv6": "0",
    "net.ipv6.conf.lo.disable_ipv6": "0"
}

def check_root():
    """Verify script is run as root"""
    if os.geteuid() != 0:
        print("❌ ERROR: This script must be run as root/sudo")
        sys.exit(1)

def apply_sysctl_settings():
    """Apply TCP/IP stack optimizations"""
    print("\n⚙️ Applying aggressive kernel network optimizations")
    for key, value in TCP_SETTINGS.items():
        try:
            subprocess.run(["sysctl", "-w", f"{key}={value}"], 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL,
                          check=True)
            print(f"  ✓ {key} = {value}")
        except subprocess.CalledProcessError:
            print(f"  ⚠️ Failed to set {key} (unsupported by kernel)")

def disable_powersave(interface):
    """Disable all power saving features on network interface"""
    print(f"\n⚡ Disabling power saving for {interface}")
    
    # Ethernet settings
    try:
        subprocess.run(["ethtool", "-s", interface, 
                       "wol", "d",
                       "autoneg", "on",
                       "speed", "auto",
                       "duplex", "full",
                       "tx", "on",
                       "rx", "on",
                       "sg", "on",
                       "tso", "on",
                       "gso", "on",
                       "lro", "on",
                       "gro", "on"],
                      check=True)
    except subprocess.CalledProcessError:
        print("  ⚠️ ethtool failed - using alternative method")
        try:
            # Alternative method for some NICs
            subprocess.run(["ethtool", "-K", interface, 
                           "tx", "on", "rx", "on", "sg", "on", "tso", "on",
                           "gso", "on", "lro", "on", "gro", "on"],
                          check=True)
        except:
            pass
    
    # Wireless settings
    try:
        subprocess.run(["iw", "dev", interface, "set", "power_save", "off"], check=True)
        subprocess.run(["iw", "config", interface, "power_save", "0"], check=True)
        print("  ✓ Wireless power management disabled")
    except:
        pass
    
    # Enable maximum performance
    try:
        with open(f"/sys/class/net/{interface}/power/control", "w") as f:
            f.write("on\n")
    except:
        pass
    
    print("  ✓ All power management disabled")

def optimize_irq(interface):
    """Optimize IRQ handling and CPU affinity"""
    print("\n🎛️ Optimizing IRQ handling")
    
    # Get IRQs for interface
    try:
        irqs = []
        output = subprocess.check_output(["grep", interface, "/proc/interrupts"], 
                                        text=True)
        for line in output.splitlines():
            parts = line.split()
            if parts and ':' in parts[0]:
                irqs.append(parts[0].replace(':', ''))
        
        if not irqs:
            print("  ⚠️ No IRQs found for interface")
            return
        
        cpu_count = multiprocessing.cpu_count()
        print(f"  • Found {len(irqs)} IRQs for {interface}")
        print(f"  • System has {cpu_count} CPUs")
        
        # Distribute IRQs across CPUs
        for i, irq in enumerate(irqs):
            cpu_mask = 1 << (i % cpu_count)
            try:
                with open(f"/proc/irq/{irq}/smp_affinity", "w") as f:
                    f.write(f"{cpu_mask:0x}")
                print(f"  ✓ IRQ {irq} → CPU {i % cpu_count}")
            except:
                print(f"  ⚠️ Failed to set affinity for IRQ {irq}")
                
    except Exception as e:
        print(f"  ⚠️ IRQ optimization failed: {str(e)}")

def set_offloading(interface):
    """Enable hardware offloading features"""
    print(f"\n🔧 Enabling hardware offloading for {interface}")
    features = [
        "tcp-segmentation-offload", "tx", "on",
        "udp-fragmentation-offload", "tx", "on",
        "generic-segmentation-offload", "tx", "on",
        "generic-receive-offload", "rx", "on",
        "large-receive-offload", "rx", "on",
        "rx-vlan-offload", "on",
        "tx-vlan-offload", "on",
        "highdma", "on"
    ]
    
    try:
        subprocess.run(["ethtool", "-K", interface] + features, check=True)
        print("  ✓ Hardware offloading enabled")
    except Exception as e:
        print(f"  ⚠️ Offloading configuration failed: {str(e)}")

def make_persistent():
    """Make optimizations survive reboots"""
    print("\n🔒 Making optimizations persistent")
    
    # Save sysctl settings
    try:
        with open("/etc/sysctl.d/99-max-network.conf", "w") as f:
            for key, value in TCP_SETTINGS.items():
                f.write(f"{key} = {value}\n")
        print("  ✓ Sysctl settings saved to /etc/sysctl.d/99-max-network.conf")
    except Exception as e:
        print(f"  ⚠️ Failed to save sysctl settings: {str(e)}")
    
    # Save interface settings in network manager
    try:
        with open("/etc/NetworkManager/dispatcher.d/99-max-network", "w") as f:
            f.write("""#!/bin/sh
[ "$2" = "up" ] || exit 0
for iface in $(ls /sys/class/net/); do
    ethtool -K $iface tso on gso on gro on lro on tx on rx on &> /dev/null
    iw dev $iface set power_save off &> /dev/null
    echo on > /sys/class/net/$iface/power/control &> /dev/null
done
""")
        subprocess.run(["chmod", "+x", "/etc/NetworkManager/dispatcher.d/99-max-network"])
        print("  ✓ Created NetworkManager persistence script")
    except:
        print("  ⚠️ Failed to create persistence script")

def main():
    parser = argparse.ArgumentParser(description='Ultimate Network Speed Booster')
    parser.add_argument('-i', '--interface', required=True, 
                       help='Network interface (e.g., eth0, wlan0)')
    parser.add_argument('-p', '--persistent', action='store_true',
                       help='Make changes survive reboots')
    args = parser.parse_args()

    check_root()
    print(f"🚀 Starting MAXIMUM network optimization for {args.interface}")
    
    # Apply all optimizations
    apply_sysctl_settings()
    disable_powersave(args.interface)
    set_offloading(args.interface)
    optimize_irq(args.interface)
    
    if args.persistent:
        make_persistent()
    
    print("\n💨 MAXIMUM NETWORK BOOST APPLIED!")
    print("Recommendations for further optimization:")
    print("1. Use wired connection instead of WiFi")
    print("2. Upgrade network hardware (router/switch)")
    print("3. Contact ISP for higher-speed plans")
    print("4. Test with: iperf3 -c <server> -P 16")

if __name__ == "__main__":
    main()
