"""
Fake Access Point detection
"""

import logging
import os
from ..utils.network import run_command

logger = logging.getLogger("antinetcut")

class FakeAPGuard:
    def __init__(self, cfg, queue):
        self.cfg = cfg
        self.queue = queue
        self.known_networks = {}
        self.preferences_file = os.path.expanduser("~/.antinetcut_wifi_prefs.json")

    def check_current_ap(self):
        """Check current connected AP for evil twin"""
        try:
            current_bssid = self._get_current_bssid()
            current_ssid = self._get_current_ssid()
            
            if not current_ssid or not current_bssid:
                return
                
            # Load or create trusted BSSID record
            trusted_bssid = self._get_trusted_bssid(current_ssid)
            
            if not trusted_bssid:
                # First time seeing this network, save it
                self._save_trusted_bssid(current_ssid, current_bssid)
                logger.info("Saved trusted BSSID for %s: %s", current_ssid, current_bssid)
            elif trusted_bssid != current_bssid:
                # BSSID changed - possible evil twin
                logger.warning("Evil twin detected: SSID %s, expected BSSID %s, got %s",
                             current_ssid, trusted_bssid, current_bssid)
                self.queue.add(
                    "Evil Twin Access Point",
                    f"SSID: {current_ssid}\nExpected BSSID: {trusted_bssid}\nCurrent BSSID: {current_bssid}",
                    {"ssid": current_ssid, "expected_bssid": trusted_bssid, "current_bssid": current_bssid}
                )

        except Exception as e:
            logger.error("Fake AP check failed: %s", e)

    def _get_current_bssid(self):
        """Get current connected BSSID"""
        # Try iwgetid first
        bssid = run_command("iwgetid -r -a 2>/dev/null")
        if bssid:
            return bssid.strip()
        
        # Try nmcli
        bssid = run_command("nmcli -t -f ACTIVE,BSSID dev wifi | awk -F: '$1==\"yes\" {print $2}'")
        if bssid:
            return bssid.strip()
        
        # Try iwconfig
        bssid = run_command("iwconfig 2>/dev/null | grep 'Access Point' | awk '{print $6}'")
        return bssid.strip() if bssid else None

    def _get_current_ssid(self):
        """Get current connected SSID"""
        ssid = run_command("iwgetid -r 2>/dev/null")
        if ssid:
            return ssid.strip()
        
        ssid = run_command("nmcli -t -f ACTIVE,SSID dev wifi | awk -F: '$1==\"yes\" {print $2}'")
        return ssid.strip() if ssid else None

    def _get_trusted_bssid(self, ssid):
        """Get trusted BSSID for SSID from preferences"""
        import json
        
        try:
            if os.path.exists(self.preferences_file):
                with open(self.preferences_file, 'r') as f:
                    prefs = json.load(f)
                    return prefs.get(ssid)
        except Exception:
            pass
            
        return None

    def _save_trusted_bssid(self, ssid, bssid):
        """Save trusted BSSID to preferences"""
        import json
        
        try:
            prefs = {}
            if os.path.exists(self.preferences_file):
                with open(self.preferences_file, 'r') as f:
                    prefs = json.load(f)
            
            prefs[ssid] = bssid
            
            with open(self.preferences_file, 'w') as f:
                json.dump(prefs, f, indent=2)
                
        except Exception as e:
            logger.error("Failed to save WiFi preferences: %s", e)