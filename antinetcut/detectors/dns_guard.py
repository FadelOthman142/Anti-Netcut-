"""
DNS poisoning detection
"""

import time
import logging
import subprocess

logger = logging.getLogger("antinetcut")

class DnsGuard:
    def __init__(self, cfg, queue):
        self.cfg = cfg
        self.queue = queue
        self.last_check = 0
        self.check_interval = 60  #seconds

    def check_dns_integrity(self):
        """Compare system DNS with DoH providers"""
        current_time = time.time()
        if current_time - self.last_check < self.check_interval:
            return
            
        self.last_check = current_time
        
        # Test domains
        test_domains = [
            "google.com",
            "cloudflare.com", 
            "example.com",
            "one.one.one.one"
        ]
        
        for domain in test_domains:
            system_ip = self._resolve_system(domain)
            doh_ip = self._resolve_doh(domain)
            
            if system_ip and doh_ip and system_ip != doh_ip:
                logger.warning("DNS poisoning detected for %s: system=%s, doh=%s", 
                             domain, system_ip, doh_ip)
                self.queue.add(
                    "DNS Poisoning Detected",
                    f"Domain {domain}: system={system_ip}, doh={doh_ip}",
                    {"domain": domain, "system_ip": system_ip, "doh_ip": doh_ip}
                )
                break  # One detection is enough

    def _resolve_system(self, domain):
        """Resolve domain using system DNS"""
        try:
            # Try getent first
            result = subprocess.run(
                ["getent", "hosts", domain],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                return result.stdout.split()[0]
            
            # Fallback to socket
            import socket
            return socket.gethostbyname(domain)
            
        except Exception:
            return None

    def _resolve_doh(self, domain):
        """Resolve domain using DNS-over-HTTPS"""
        try:
            import requests
            
            if self.cfg.get("doh_provider", "cloudflare") == "google":
                url = f"https://dns.google/resolve?name={domain}&type=A"
            else:
                url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
            
            headers = {"accept": "application/dns-json"}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if "Answer" in data and data["Answer"]:
                    return data["Answer"][0]["data"]
                    
        except Exception as e:
            logger.debug("DoH resolution failed: %s", e)
            
        return None