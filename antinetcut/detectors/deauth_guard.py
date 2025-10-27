"""
Deauthentication attack detection
"""

import time
import logging
from collections import defaultdict, deque

logger = logging.getLogger("antinetcut")

class DeauthGuard:
    def __init__(self, cfg, queue):
        self.cfg = cfg
        self.queue = queue
        self.deauth_counts = defaultdict(lambda: deque(maxlen=100))
        self.detected_attacks = set()

    def handle_packet(self, pkt):
        """Handle 802.11 deauthentication packets"""
        try:
            from scapy.all import Dot11, Dot11Deauth
            
            if pkt.haslayer(Dot11Deauth):
                dot11 = pkt[Dot11]
                victim = dot11.addr1
                attacker = dot11.addr2
                
                # Skip broadcast deauths
                if victim.lower() == "ff:ff:ff:ff:ff:ff":
                    return
                
                current_time = time.time()
                self.deauth_counts[victim].append(current_time)
                
                # Check for deauth flood (5+ in 10 seconds)
                recent_count = sum(1 for ts in self.deauth_counts[victim] 
                                 if ts > current_time - 10)
                
                if recent_count >= 5:
                    attack_key = f"{attacker}-{victim}"
                    if attack_key not in self.detected_attacks:
                        self.detected_attacks.add(attack_key)
                        logger.warning("Deauth flood attack: %s -> %s (%d packets)",
                                     attacker, victim, recent_count)
                        self.queue.add(
                            "Deauthentication Attack",
                            f"Attacker: {attacker}\nVictim: {victim}\nPackets: {recent_count}",
                            {"attacker": attacker, "victim": victim, "packet_count": recent_count}
                        )
                        
        except Exception as e:
            logger.debug("Deauth packet handling error: %s", e)