Anti-Netcut for Linux & Windows
https://img.shields.io/badge/python-3.6%252B-blue
https://img.shields.io/badge/platform-linux%2520%257C%2520windows-lightgrey
https://img.shields.io/badge/license-MIT-green

A comprehensive defensive security tool for detecting and mitigating network attacks on both Linux and Windows systems. Anti-Netcut provides real-time monitoring, threat detection, and automated remediation for common network-based attacks.

🛡️ Features
Detection Capabilities
ARP Spoofing Detection: Monitors ARP tables and detects MAC address conflicts

DHCP Spoofing Detection: Identifies rogue DHCP servers on the network

DNS Poisoning Detection: Compares system DNS with DoH providers (Cloudflare, Google)

Fake AP Detection: Detects evil twin access points via BSSID fingerprinting

Deauthentication Attack Detection: Monitors for 802.11 deauthentication floods

Device Discovery: ARP scanning for network mapping and duplicate IP detection

Gateway Integrity Monitoring: Continuous ping monitoring for gateway health

Mitigation & Response
Manual Approval Queue: Review and approve mitigations before execution

Auto-Remediation: Automatic attack blocking (optional)

Multiple Block Methods: iptables, ebtables, and ARP table corrections

Whitelist Support: Trusted IP-MAC pairs to prevent false positives

Comprehensive Logging: Detailed activity and threat logs

Cross-Platform Support
Linux: Full functionality with all detection and mitigation features

Windows: Basic detection capabilities with Windows-compatible networking

📋 Requirements
Python Dependencies
bash
# Core dependencies
scapy>=2.4.5
netaddr>=0.8.0
requests>=2.25.1
System Requirements
Python 3.6 or higher

Linux: Root privileges for full functionality

Windows: Administrator privileges for some features

Network Interface with promiscuous mode support (for packet capture)

🚀 Quick Start
Method 1: Direct Execution (No Installation)
bash
# Clone the repository
git clone https://github.com/yourusername/anti-netcut-linux.git
cd anti-netcut-linux

# Install Python dependencies
pip install -r requirements.txt

# Run basic detection (Linux)
sudo python -m antinetcut.cli --iface wlan0 --detect-only

# Run basic detection (Windows)
python run_windows.py --detect-only
Method 2: Development Installation
bash
# Install in development mode
pip install -e .

# Now run from anywhere
sudo antinetcut --iface wlan0 --detect-only
Method 3: Full Installation (Linux)
bash
# Run the installation script (Linux)
sudo ./scripts/install.sh

# The tool will be installed system-wide
sudo antinetcut --iface wlan0
📖 Usage Examples
Basic Detection (Safe Mode)
bash
# Linux - Detection only, no remediation
sudo antinetcut --iface eth0 --detect-only

# Windows - Detection only
python run_windows.py --iface "Ethernet" --detect-only

# With verbose output
sudo antinetcut --iface wlan0 --detect-only --verbose
Auto-Remediation Mode
bash
# Linux - Automatic blocking of detected threats
sudo antinetcut --iface wlan0 --auto-remediate

# Windows - Limited auto-remediation
python run_windows.py --iface "Wi-Fi" --auto-remediate
Queue Management
bash
# List pending mitigation actions
antinetcut --list-queue

# Approve and execute a specific mitigation
sudo antinetcut --approve 0

# Clear the mitigation queue
antinetcut --clear-queue
Custom Configuration
bash
# Use custom config file
sudo antinetcut --config /path/to/config.json

# Specify network interface
sudo antinetcut --iface wlan0

# Different DoH provider
sudo antinetcut --iface eth0 --detect-only
⚙️ Configuration
Configuration File Structure
Create a config.json file:

json
{
    "iface": "wlan0",
    "auto_remediate": false,
    "detect_only": true,
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
    "arp_scan_cidr": "192.168.1.0/24",
    "deauth_iface": null
}
Windows Configuration
For Windows, use config_windows.json:

json
{
    "iface": "Wi-Fi",
    "auto_remediate": false,
    "detect_only": true,
    "whitelist_file": "whitelist.json",
    "queue_file": "queue.json",
    "log_file": "antinetcut.log",
    "doh_provider": "cloudflare"
}
Whitelist Configuration
Create whitelist.json to prevent false positives:

json
{
    "192.168.1.1": "aa:bb:cc:dd:ee:ff",
    "192.168.1.100": "11:22:33:44:55:66",
    "192.168.1.101": "66:55:44:33:22:11"
}
🎯 Detection Scenarios
ARP Spoofing Attack
text
[WARNING] ARP spoofing detected: 192.168.1.50 claimed by aa:bb:cc:dd:ee:ff (expected 11:22:33:44:55:66)
Rogue DHCP Server
text
[WARNING] Rogue DHCP server detected: 192.168.1.200 (gateway: 192.168.1.1)
DNS Poisoning
text
[WARNING] DNS poisoning detected for google.com: system=192.168.1.200, doh=142.251.32.110
Evil Twin Access Point
text
[WARNING] Evil twin detected: SSID HomeWiFi, expected BSSID aa:bb:cc:dd:ee:ff, got 11:22:33:44:55:66
Deauthentication Attack
text
[WARNING] Deauth flood attack: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 (15 packets)
🛠️ Advanced Usage
Running as a Service (Linux)
bash
# Install systemd service (via install.sh)
sudo systemctl enable antinetcut
sudo systemctl start antinetcut
sudo systemctl status antinetcut
Custom Mitigation Commands
Modify mitigation_commands in your config:

json
"mitigation_commands": [
    "iptables -I INPUT -m mac --mac-source {attacker_mac} -j DROP",
    "ip neigh del {victim_ip} dev {iface}",
    "ip neigh add {victim_ip} lladdr {correct_mac} dev {iface} nud permanent"
]
Network Interface Setup
bash
# Put interface in monitor mode (for deauth detection)
sudo ./scripts/setup_monitor_mode.sh wlan0

# Check available interfaces
ip link show
# or on Windows
Get-NetAdapter
📊 Logging and Monitoring
Log Files
Linux: /var/log/antinetcut.log

Windows: antinetcut.log (in current directory)

Log Format
text
2024-01-01 12:00:00 [INFO] Starting AntiNetCut on interface wlan0
2024-01-01 12:00:05 [WARNING] ARP spoofing detected: 192.168.1.50 claimed by aa:bb:cc:dd:ee:ff
2024-01-01 12:00:10 [INFO] Queued mitigation: ARP Spoofing Detected
Queue Management
bash
# View mitigation queue
antinetcut --list-queue

# Output:
[0] ARP Spoofing Detected -- 2024-01-01T12:00:10
  IP 192.168.1.50 claimed by aa:bb:cc:dd:ee:ff (expected 11:22:33:44:55:66)
  meta={'attacker_mac': 'aa:bb:cc:dd:ee:ff', 'victim_ip': '192.168.1.50', 'expected_mac': '11:22:33:44:55:66'}
🔧 Troubleshooting
Common Issues
"ImportError: cannot import name ..."

bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
"No such file or directory" (Linux paths on Windows)

bash
# Use Windows runner script
python run_windows.py --detect-only
"Permission denied" for packet capture

bash
# Run with appropriate privileges
sudo antinetcut --iface wlan0 --detect-only
Scapy WinPcap warning on Windows

bash
# Install Npcap for better Windows support
# Download from: https://nmap.org/npcap/
Interface not found

bash
# List available interfaces (Linux)
ip link show

# List available interfaces (Windows)
Get-NetAdapter
Performance Tips
Use wired connections for more reliable detection

Whitelist trusted devices to reduce false positives

Adjust detection thresholds in config for your network size

Use --detect-only mode initially to test without blocking

🏗️ Architecture
Module Structure
text
antinetcut/
├── cli.py              # Command-line interface
├── core.py             # Main orchestrator
├── detectors/          # Detection modules
│   ├── arp_guard.py
│   ├── dhcp_guard.py
│   ├── dns_guard.py
│   ├── fakeap_guard.py
│   └── deauth_guard.py
├── mitigation/         # Response modules
│   ├── queue.py
│   └── commands.py
└── utils/              # Utilities
    ├── network.py
    └── config.py
Detection Workflow
Packet Capture: Scapy-based sniffing for ARP, DHCP, and 802.11 frames

Anomaly Detection: Statistical analysis and pattern matching

Verification: Cross-referencing with trusted sources (DoH, gateway)

Queueing: Suspicious events added to mitigation queue

Response: Manual approval or auto-remediation

🤝 Contributing
We welcome contributions! Please see our Contributing Guide for details.

Development Setup
bash
# Fork and clone the repository
git clone https://github.com/yourusername/anti-netcut-linux.git
cd anti-netcut-linux

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
python -m pytest tests/
Reporting Issues
Please report bugs and feature requests on the GitHub Issues page.

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer
This tool is designed for defensive security purposes only. Use responsibly and only on networks you own or have explicit permission to monitor. The developers are not responsible for any misuse or damage caused by this software.

🙏 Acknowledgments
Scapy community for the powerful packet manipulation library

Cloudflare & Google for providing free DoH services

Security researchers who contributed ideas and testing

📞 Support
Documentation: GitHub Wiki

Issues: GitHub Issues

Discussions: GitHub Discussions

Happy defending! 🛡️

If you find this tool useful, please consider giving it a ⭐ on GitHub!

🎯 Quick Command Reference
Linux Commands
bash
# Basic detection
sudo python -m antinetcut.cli --iface wlan0 --detect-only

# Auto-remediation
sudo python -m antinetcut.cli --iface wlan0 --auto-remediate

# With custom config
sudo python -m antinetcut.cli --config config.json

# Queue management
python -m antinetcut.cli --list-queue
sudo python -m antinetcut.cli --approve 0
Windows Commands
bash
# Basic detection
python run_windows.py --detect-only

# Specific interface
python run_windows.py --iface "Wi-Fi" --detect-only

# Queue management
python run_windows.py --list-queue
python run_windows.py --approve 0
Common Network Interfaces
Linux: eth0, wlan0, enp0s3

Windows: "Ethernet", "Wi-Fi", "Local Area Connection"

Need Help? Check the troubleshooting section above or create an issue on GitHub!