"""
DHCP spoofing detection
"""

import logging
from ..utils.network import get_gateway_ip

logger = logging.getLogger("antinetcut")

class DhcpGuard:
    def __init__(self, cfg, queue):
        self.cfg = cfg
        self.queue = queue
        self.known_servers = set()

    def handle_packet(self, pkt):
        """Handle DHCP packets"""
        try:
            from scapy.all import DHCP, IP
            
            if pkt.haslayer(DHCP):
                dhcp = pkt[DHCP]
                
                # Look for DHCP Offer or ACK
                if dhcp.options:
                    message_type = None
                    server_ip = None
                    
                    for opt in dhcp.options:
                        if isinstance(opt, tuple):
                            if opt[0] == 'message-type':  # DHCP message type
                                message_type = opt[1]
                            elif opt[0] == 'server_id':  # DHCP server identifier
                                server_ip = opt[1]
                    
                    # Check DHCP Offer from unauthorized server
                    if message_type == 2 and server_ip:  # DHCP Offer
                        self._check_dhcp_server(server_ip, pkt[IP].src)
                        
        except Exception as e:
            logger.debug("DHCP packet handling error: %s", e)

    def _check_dhcp_server(self, server_ip, packet_src):
        """Verify DHCP server legitimacy"""
        gateway_ip = get_gateway_ip(self.cfg["iface"])
        
        # First time seeing this server
        if server_ip not in self.known_servers:
            self.known_servers.add(server_ip)
            logger.info("Discovered DHCP server: %s", server_ip)
        
        # Check if server IP matches gateway (typical home networks)
        # or if server IP matches packet source (should be the same)
        if server_ip != packet_src:
            logger.warning("DHCP server IP mismatch: announced %s from %s", 
                         server_ip, packet_src)
            self.queue.add(
                "Suspicious DHCP Server",
                f"Server {server_ip} announced from {packet_src}",
                {"server_ip": server_ip, "packet_src": packet_src}
            )
        
        # Check against gateway (common in rogue DHCP scenarios)
        if gateway_ip and server_ip != gateway_ip:
            logger.warning("Rogue DHCP server detected: %s (gateway: %s)", 
                         server_ip, gateway_ip)
            self.queue.add(
                "Rogue DHCP Server",
                f"Unauthorized DHCP server {server_ip} (gateway: {gateway_ip})",
                {"rogue_server": server_ip, "gateway": gateway_ip}
            )