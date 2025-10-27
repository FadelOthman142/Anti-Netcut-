"""
ARP spoofing detection and mitigation
"""

import time
import logging
from collections import defaultdict, deque

from ..utils.network import get_arp_mac_for_ip

logger = logging.getLogger("antinetcut")

class ArpGuard:
    def __init__(self, cfg, queue, executor):
        self.cfg = cfg
        self.queue = queue
        self.executor = executor
        self.history = defaultdict(lambda: deque(maxlen=cfg["arp_window_s"]))
        self.trusted_mappings = {}  # ip -> trusted mac
        self.whitelist = self._load_whitelist()

    def _load_whitelist(self):
        """Load MAC whitelist from file"""
        import json
        try:
            with open(self.cfg["whitelist_file"], "r") as f:
                return json.load(f)
        except Exception:
            logger.warning("Could not load whitelist file")
            return {}

    def is_whitelisted(self, ip, mac):
        """Check if IP/MAC pair is whitelisted"""
        return self.whitelist.get(ip) == mac

    def learn_trusted_mapping(self, ip, mac):
        """Learn trusted IP-MAC mapping from consistent observations"""
        self.history[ip].append((mac, time.time()))
        
        # Count occurrences of each MAC
        mac_counts = defaultdict(int)
        for observed_mac, _ in self.history[ip]:
            mac_counts[observed_mac] += 1
        
        # Find most frequent MAC
        if mac_counts:
            most_common_mac = max(mac_counts.items(), key=lambda x: x[1])
            if (most_common_mac[1] >= self.cfg["arp_trigger_count"] and 
                ip not in self.trusted_mappings):
                self.trusted_mappings[ip] = most_common_mac[0]
                logger.info("Learned trusted mapping: %s -> %s", ip, most_common_mac[0])

    def check_arp_entry(self, entry):
        """Check ARP table entry for anomalies"""
        ip = entry["ip"]
        mac = entry["mac"].lower()
        
        # Skip invalid entries
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        
        # Learn from this observation
        self.learn_trusted_mapping(ip, mac)
        
        # Check against trusted mapping
        trusted_mac = self.trusted_mappings.get(ip)
        if trusted_mac and mac != trusted_mac and not self.is_whitelisted(ip, mac):
            logger.warning("ARP spoofing detected: %s claimed by %s (expected %s)", 
                         ip, mac, trusted_mac)
            
            # Send corrective ARP if enabled
            if self.cfg.get("auto_remediate"):
                self._send_gratuitous_arp(ip, trusted_mac)
                self.executor.mitigate_arp_spoof(mac, ip, trusted_mac)
            else:
                self.queue.add(
                    "ARP Spoofing Detected",
                    f"IP {ip} claimed by {mac} (expected {trusted_mac})",
                    {"attacker_mac": mac, "victim_ip": ip, "expected_mac": trusted_mac}
                )

    def handle_packet(self, pkt):
        """Handle incoming ARP packets"""
        try:
            from scapy.all import ARP
            
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if arp.op in (1, 2):  # who-has or is-at
                    entry = {
                        "ip": arp.psrc,
                        "mac": arp.hwsrc.lower(),
                        "iface": self.cfg["iface"]
                    }
                    self.check_arp_entry(entry)
        except Exception as e:
            logger.debug("ARP packet handling error: %s", e)

    def _send_gratuitous_arp(self, ip, mac):
        """Send gratuitous ARP to correct poisoning"""
        try:
            from scapy.all import Ether, ARP, send
            
            logger.info("Sending corrective ARP for %s -> %s", ip, mac)
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2,  # is-at
                psrc=ip,
                hwsrc=mac,
                pdst=ip,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            
            for _ in range(self.cfg.get("grat_arp_repeat", 3)):
                send(pkt, iface=self.cfg["iface"], verbose=False)
                time.sleep(self.cfg.get("grat_arp_interval", 1))
                
        except Exception as e:
            logger.error("Failed to send gratuitous ARP: %s", e)