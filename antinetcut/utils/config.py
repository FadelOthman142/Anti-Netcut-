"""
Configuration management
"""

import os
import json
import logging

logger = logging.getLogger("antinetcut")

DEFAULT_CONFIG = {
    "iface": "eth0",
    "auto_remediate": False,
    "detect_only": False,
    "arp_window_s": 30,
    "arp_trigger_count": 2,
    "grat_arp_repeat": 3,
    "grat_arp_interval": 1,
    "mitigated_ttl_s": 300,
    "mitigation_commands": [
        "iptables -I INPUT -m mac --mac-source {attacker_mac} -j DROP",
        "ebtables -I FORWARD -s {attacker_mac} -j DROP",
        "ip neigh replace {victim_ip} lladdr {correct_mac} dev {iface} nud permanent"
    ],
    "whitelist_file": "/etc/antinetcut/whitelist.json",
    "queue_file": "/var/lib/antinetcut/queue.json",
    "log_file": "/var/log/antinetcut.log",
    "doh_provider": "cloudflare",
    "arp_scan_cidr": None,
    "deauth_iface": None
}

def load_config(config_path=None):
    """Load configuration from file or use defaults"""
    config = DEFAULT_CONFIG.copy()
    
    # Try to load user config
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                config.update(user_config)
            logger.info("Loaded configuration from %s", config_path)
        except Exception as e:
            logger.error("Failed to load config file: %s", e)
    
    # Set default interface if not specified
    if not config.get("iface"):
        from .network import get_interface_for_gateway
        config["iface"] = get_interface_for_gateway() or "eth0"
    
    # Create necessary directories
    _ensure_directories(config)
    
    return config

def save_config(config, config_path):
    """Save configuration to file"""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info("Configuration saved to %s", config_path)
        return True
    except Exception as e:
        logger.error("Failed to save config: %s", e)
        return False

def _ensure_directories(config):
    """Ensure necessary directories exist"""
    directories = [
        os.path.dirname(config["queue_file"]),
        os.path.dirname(config["log_file"]),
        "/etc/antinetcut"
    ]
    
    for directory in directories:
        if directory:
            os.makedirs(directory, exist_ok=True)

def create_default_config(config_path):
    """Create default configuration file"""
    return save_config(DEFAULT_CONFIG, config_path)