"""
Mitigation command execution
"""

import os
import time
import subprocess
import logging

logger = logging.getLogger("antinetcut")

class MitigationExecutor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.mitigated_entries = {}
        self.default_commands = [
            "iptables -I INPUT -m mac --mac-source {attacker_mac} -j DROP",
            "ebtables -I FORWARD -s {attacker_mac} -j DROP", 
            "ip neigh replace {victim_ip} lladdr {correct_mac} dev {iface} nud permanent"
        ]

    def has_root_privileges(self):
        """Check if running with root privileges"""
        return os.geteuid() == 0

    def mitigate_arp_spoof(self, attacker_mac, victim_ip, correct_mac):
        """Execute ARP spoofing mitigation"""
        if not self.has_root_privileges():
            logger.warning("Root required for ARP spoof mitigation")
            return False

        commands = self.cfg.get("mitigation_commands", self.default_commands)
        success = False

        for command_template in commands:
            try:
                command = command_template.format(
                    attacker_mac=attacker_mac,
                    victim_ip=victim_ip,
                    correct_mac=correct_mac,
                    iface=self.cfg["iface"]
                )
                logger.info("Executing: %s", command)
                
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    logger.info("Mitigation successful: %s", command)
                    success = True
                else:
                    logger.warning("Mitigation failed (code %d): %s", 
                                 result.returncode, result.stderr)
                    
            except subprocess.TimeoutExpired:
                logger.error("Mitigation command timed out: %s", command)
            except Exception as e:
                logger.error("Mitigation command failed: %s - %s", command, e)

        return success

    def execute_from_queue_entry(self, queue_entry):
        """Execute mitigation from queue entry"""
        meta = queue_entry.get("meta", {})
        attacker_mac = meta.get("attacker_mac") or meta.get("attacker")
        victim_ip = meta.get("victim_ip")
        correct_mac = meta.get("expected_mac") or meta.get("victim_mac")
        
        if not attacker_mac:
            logger.error("No attacker MAC in queue entry")
            return False
            
        if queue_entry["title"] == "ARP Spoofing Detected" and victim_ip and correct_mac:
            return self.mitigate_arp_spoof(attacker_mac, victim_ip, correct_mac)
        else:
            # Generic MAC blocking for other attack types
            return self.block_mac_address(attacker_mac)

    def block_mac_address(self, mac_address):
        """Block MAC address using iptables/ebtables"""
        if not self.has_root_privileges():
            logger.warning("Root required for MAC blocking")
            return False

        commands = [
            f"iptables -I INPUT -m mac --mac-source {mac_address} -j DROP",
            f"ebtables -I FORWARD -s {mac_address} -j DROP"
        ]

        success = False
        for command in commands:
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    logger.info("MAC block successful: %s", command)
                    success = True
            except Exception as e:
                logger.error("MAC block failed: %s - %s", command, e)

        return success

    def flush_mitigations(self):
        """Remove all mitigation rules (cleanup)"""
        if not self.has_root_privileges():
            return False

        commands = [
            "iptables -F",
            "ebtables -F"
        ]

        for command in commands:
            try:
                subprocess.run(command, shell=True, timeout=10)
                logger.info("Flushed mitigation rules: %s", command)
            except Exception as e:
                logger.error("Failed to flush rules: %s - %s", command, e)