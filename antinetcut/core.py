"""
Main orchestrator for Anti-Netcut
"""

import time
import threading
import logging

from .detectors.arp_guard import ArpGuard
from .detectors.dhcp_guard import DhcpGuard
from .detectors.dns_guard import DnsGuard
from .detectors.fakeap_guard import FakeAPGuard
from .detectors.deauth_guard import DeauthGuard
from .mitigation.queue import MitigationQueue
from .mitigation.commands import MitigationExecutor
from .utils.network import get_gateway_ip, read_arp_table, arp_scan, ping_stats

logger = logging.getLogger("antinetcut")

class AntiNetCut:
    def __init__(self, cfg):
        self.cfg = cfg
        self.queue = MitigationQueue(cfg["queue_file"])
        self.executor = MitigationExecutor(cfg)
        
        # Initialize detectors
        self.arp_guard = ArpGuard(cfg, self.queue, self.executor)
        self.dhcp_guard = DhcpGuard(cfg, self.queue)
        self.dns_guard = DnsGuard(cfg, self.queue)
        self.fakeap_guard = FakeAPGuard(cfg, self.queue)
        self.deauth_guard = DeauthGuard(cfg, self.queue)
        
        self.stop_event = threading.Event()
        self.threads = []

    def start(self):
        """Start all monitoring threads"""
        logger.info("AntiNetCut starting on interface %s", self.cfg["iface"])
        
        # Start background monitoring threads
        threads_config = [
            (self._arp_table_loop, 2, "ARP Table Monitor"),
            (self._fakeap_loop, 8, "Fake AP Monitor"),
            (self._dns_loop, 15, "DNS Monitor"),
            (self._device_scan_loop, 30, "Device Scanner"),
            (self._gateway_integrity_loop, 20, "Gateway Monitor"),
        ]
        
        for target, interval, name in threads_config:
            thread = threading.Thread(
                target=self._run_monitoring_loop,
                args=(target, interval, name),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
        
        # Start packet sniffing if available
        self._start_packet_sniffing()
        
        # Main loop
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop all monitoring threads"""
        logger.info("Stopping AntiNetCut...")
        self.stop_event.set()
        
        # Wait for threads to complete
        for thread in self.threads:
            thread.join(timeout=5)

    def _run_monitoring_loop(self, target, interval, name):
        """Generic monitoring loop runner"""
        logger.debug("Starting %s", name)
        while not self.stop_event.is_set():
            try:
                target()
            except Exception as e:
                logger.error("%s error: %s", name, e)
            time.sleep(interval)

    def _arp_table_loop(self):
        """Monitor ARP table for anomalies"""
        entries = read_arp_table()
        for entry in entries:
            self.arp_guard.check_arp_entry(entry)

    def _fakeap_loop(self):
        """Check for fake access points"""
        self.fakeap_guard.check_current_ap()

    def _dns_loop(self):
        """Check for DNS poisoning"""
        self.dns_guard.check_dns_integrity()

    def _device_scan_loop(self):
        """Scan network for devices and duplicates"""
        cidr = self.cfg.get("arp_scan_cidr")
        if not cidr:
            gateway = get_gateway_ip(self.cfg["iface"])
            if gateway:
                cidr = gateway.rsplit(".", 1)[0] + ".0/24"
        
        if cidr:
            devices = arp_scan(cidr, self.cfg["iface"])
            # Check for duplicate IPs
            ip_counts = {}
            for device in devices:
                ip_counts[device["ip"]] = ip_counts.get(device["ip"], 0) + 1
            
            duplicates = [ip for ip, count in ip_counts.items() if count > 1]
            if duplicates:
                logger.warning("Duplicate IP addresses detected: %s", duplicates)
                self.queue.add(
                    "Duplicate IP Addresses",
                    f"Multiple devices responding to: {', '.join(duplicates)}",
                    {"duplicate_ips": duplicates}
                )

    def _gateway_integrity_loop(self):
        """Monitor gateway health"""
        gateway = get_gateway_ip(self.cfg["iface"])
        if gateway:
            stats = ping_stats(gateway, count=3, timeout=1)
            avg_rtt = stats.get("avg")
            
            if avg_rtt and avg_rtt > 500:  # 500ms threshold
                logger.warning("High gateway latency: %.1f ms", avg_rtt)
                self.queue.add(
                    "High Gateway Latency",
                    f"Gateway {gateway} responding slowly: {avg_rtt:.1f} ms",
                    {"gateway": gateway, "rtt": avg_rtt}
                )

    def _start_packet_sniffing(self):
        """Start packet sniffing threads"""
        try:
            from scapy.all import sniff
            
            def packet_handler(pkt):
                """Handle incoming packets for various detectors"""
                try:
                    self.arp_guard.handle_packet(pkt)
                    self.dhcp_guard.handle_packet(pkt)
                    self.deauth_guard.handle_packet(pkt)
                except Exception as e:
                    logger.debug("Packet handling error: %s", e)
            
            # Start sniffing thread
            sniff_thread = threading.Thread(
                target=lambda: sniff(
                    iface=self.cfg["iface"],
                    prn=packet_handler,
                    store=0,
                    filter="arp or (udp and (port 67 or 68))"
                ),
                daemon=True
            )
            sniff_thread.start()
            self.threads.append(sniff_thread)
            
        except ImportError:
            logger.warning("Scapy not available, packet sniffing disabled")
        except Exception as e:
            logger.error("Failed to start packet sniffing: %s", e)