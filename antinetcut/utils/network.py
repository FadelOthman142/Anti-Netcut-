"""
Network utility functions
"""

import os
import subprocess
import logging

logger = logging.getLogger("antinetcut")

def run_command(command, timeout=8):
    """Execute shell command and return output"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            logger.debug("Command failed: %s - %s", command, result.stderr)
            return ""
    except subprocess.TimeoutExpired:
        logger.debug("Command timed out: %s", command)
        return ""
    except Exception as e:
        logger.debug("Command error: %s - %s", command, e)
        return ""

def get_gateway_ip(iface=None):
    """Get default gateway IP address"""
    # Try ip route
    gateway = run_command("ip route | awk '/default/ {print $3}'")
    if gateway:
        return gateway.split('\n')[0].strip()
    
    # Fallback to netstat
    gateway = run_command("netstat -rn | awk '/^0.0.0.0/ {print $2}'")
    return gateway.split('\n')[0].strip() if gateway else None

def get_interface_for_gateway():
    """Get interface used for default gateway"""
    iface = run_command("ip route | awk '/default/ {print $5}'")
    return iface.strip() if iface else None

def read_arp_table():
    """Read system ARP table"""
    entries = []
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip, hw_type, flags, mac, mask, device = parts[:6]
                    if mac != "00:00:00:00:00:00":
                        entries.append({
                            "ip": ip,
                            "mac": mac.lower(),
                            "iface": device
                        })
    except Exception as e:
        logger.debug("Failed to read ARP table: %s", e)
    
    return entries

def get_arp_mac_for_ip(ip_address):
    """Get MAC address for IP from ARP table"""
    entries = read_arp_table()
    for entry in entries:
        if entry["ip"] == ip_address:
            return entry["mac"]
    return None

def ping_host(host, count=3, timeout=1):
    """Ping host and return statistics"""
    try:
        output = run_command(f"ping -c {count} -W {timeout} {host}")
        
        # Parse RTT from ping output
        for line in output.split('\n'):
            if "rtt min/avg/max/mdev" in line:
                parts = line.split('=')[1].split('/')
                return {
                    "min": float(parts[0]),
                    "avg": float(parts[1]),
                    "max": float(parts[2]),
                    "mdev": float(parts[3])
                }
            elif "round-trip" in line:
                parts = line.split('=')[1].split('/')
                return {
                    "min": float(parts[0]),
                    "avg": float(parts[1]),
                    "max": float(parts[2]),
                    "mdev": float(parts[3])
                }
    except Exception as e:
        logger.debug("Ping failed: %s", e)
    
    return {"min": None, "avg": None, "max": None, "mdev": None}

def ping_stats(host, count=3, timeout=1):
    """Ping host and return statistics - compatibility version"""
    result = ping_host(host, count, timeout)
    # Return in the format expected by the original code
    return {"avg": result.get("avg")}

def arp_scan(subnet, iface):
    """Perform ARP scan of subnet"""
    try:
        from scapy.all import ARP, Ether, srp
        
        # Create ARP request packet
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send packets and get responses
        answered = srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)[0]
        
        # Parse responses
        devices = []
        for sent, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc.lower(),
                "iface": iface
            })
        
        return devices
        
    except ImportError:
        logger.warning("Scapy not available for ARP scanning")
        return read_arp_table()
    except Exception as e:
        logger.debug("ARP scan failed: %s", e)
        return read_arp_table()  # Fallback to ARP table

def get_network_interfaces():
    """Get list of available network interfaces"""
    interfaces = []
    try:
        # Use ip command
        output = run_command("ip link show | awk -F: '/^[0-9]+:/ {print $2}'")
        interfaces = [iface.strip() for iface in output.split('\n') if iface.strip()]
    except Exception:
        pass
    
    return interfaces