Here’s a **cleaned up and professional version** of your `README.md` — properly formatted in Markdown with badges, clear sections, and visually appealing structure.

---

# 🛡️ Anti-Netcut for Linux & Windows

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> A comprehensive defensive security tool for detecting and mitigating network attacks on both **Linux** and **Windows** systems.
> Anti-Netcut provides **real-time monitoring**, **threat detection**, and **automated remediation** for common network-based attacks.

---

## ✨ Features

### 🔍 Detection Capabilities

* **ARP Spoofing Detection** – Monitors ARP tables for MAC conflicts
* **DHCP Spoofing Detection** – Identifies rogue DHCP servers
* **DNS Poisoning Detection** – Cross-checks DNS with DoH providers (Cloudflare, Google)
* **Fake AP Detection** – Detects evil twin access points via BSSID fingerprinting
* **Deauthentication Attack Detection** – Monitors for 802.11 deauth floods
* **Device Discovery** – ARP scanning for network mapping and duplicate IPs
* **Gateway Integrity Monitoring** – Continuous ping checks for gateway health

### 🧰 Mitigation & Response

* **Manual Approval Queue** – Review mitigations before execution
* **Auto-Remediation** – Automatically block detected threats (optional)
* **Multiple Block Methods** – Supports `iptables`, `ebtables`, and ARP corrections
* **Whitelist Support** – Trusted IP–MAC pairs to prevent false positives
* **Comprehensive Logging** – Detailed event and activity logs

### 💻 Cross-Platform Support

| Platform    | Capabilities                             |
| ----------- | ---------------------------------------- |
| **Linux**   | Full detection & mitigation support      |
| **Windows** | Basic detection with limited remediation |

---

## ⚙️ Requirements

### 🐍 Python Dependencies

```bash
scapy>=2.4.5
netaddr>=0.8.0
requests>=2.25.1
```

### 💾 System Requirements

* Python **3.6+**
* **Root** privileges (Linux) or **Administrator** (Windows)
* Network interface with **promiscuous mode** support

---

## 🚀 Quick Start

### **Method 1: Direct Execution (No Installation)**

```bash
# Clone repository
git clone https://github.com/yourusername/anti-netcut-linux.git
cd anti-netcut-linux

# Install dependencies
pip install -r requirements.txt

# Run detection (Linux)
sudo python -m antinetcut.cli --iface wlan0 --detect-only

# Run detection (Windows)
python run_windows.py --detect-only
```

### **Method 2: Development Mode**

```bash
pip install -e .
sudo antinetcut --iface wlan0 --detect-only
```

### **Method 3: Full Linux Installation**

```bash
sudo ./scripts/install.sh
sudo antinetcut --iface wlan0
```

---

## 💡 Usage Examples

### **Basic Detection**

```bash
sudo antinetcut --iface eth0 --detect-only
python run_windows.py --iface "Ethernet" --detect-only
```

### **Auto-Remediation**

```bash
sudo antinetcut --iface wlan0 --auto-remediate
python run_windows.py --iface "Wi-Fi" --auto-remediate
```

### **Queue Management**

```bash
antinetcut --list-queue
sudo antinetcut --approve 0
antinetcut --clear-queue
```

---

## 🧩 Configuration

### **Example (Linux)**

```json
{
  "iface": "wlan0",
  "auto_remediate": false,
  "detect_only": true,
  "arp_window_s": 30,
  "arp_trigger_count": 2,
  "mitigation_commands": [
    "iptables -I INPUT -m mac --mac-source {attacker_mac} -j DROP",
    "ebtables -I FORWARD -s {attacker_mac} -j DROP"
  ],
  "whitelist_file": "/etc/antinetcut/whitelist.json",
  "log_file": "/var/log/antinetcut.log"
}
```

### **Whitelist Example**

```json
{
  "192.168.1.1": "aa:bb:cc:dd:ee:ff",
  "192.168.1.100": "11:22:33:44:55:66"
}
```

---

## 🔬 Detection Scenarios

| Attack Type       | Example Log                                                                  |
| ----------------- | ---------------------------------------------------------------------------- |
| **ARP Spoofing**  | `[WARNING] ARP spoofing detected: 192.168.1.50 claimed by aa:bb:cc:dd:ee:ff` |
| **Rogue DHCP**    | `[WARNING] Rogue DHCP server detected: 192.168.1.200`                        |
| **DNS Poisoning** | `[WARNING] DNS poisoning detected for google.com: system=192.168.1.200`      |
| **Evil Twin**     | `[WARNING] Evil twin detected: SSID HomeWiFi, expected BSSID ...`            |
| **Deauth Attack** | `[WARNING] Deauth flood detected: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66`    |

---

## 🛠️ Advanced Usage

### **Running as a Service (Linux)**

```bash
sudo systemctl enable antinetcut
sudo systemctl start antinetcut
sudo systemctl status antinetcut
```

### **Monitor Mode Setup**

```bash
sudo ./scripts/setup_monitor_mode.sh wlan0
ip link show
```

---

## 📊 Logging

| OS          | Log Location                       |
| ----------- | ---------------------------------- |
| **Linux**   | `/var/log/antinetcut.log`          |
| **Windows** | `antinetcut.log` (local directory) |

**Example Log:**

```
2024-01-01 12:00:00 [INFO] Starting AntiNetCut on interface wlan0
2024-01-01 12:00:05 [WARNING] ARP spoofing detected: 192.168.1.50 claimed by aa:bb:cc:dd:ee:ff
```

---

## 🧱 Architecture

```
antinetcut/
├── cli.py              # Command-line interface
├── core.py             # Core orchestration
├── detectors/          # Detection modules
│   ├── arp_guard.py
│   ├── dhcp_guard.py
│   ├── dns_guard.py
│   ├── fakeap_guard.py
│   └── deauth_guard.py
├── mitigation/
│   ├── queue.py
│   └── commands.py
└── utils/
    ├── network.py
    └── config.py
```

---

## 🤝 Contributing

Contributions are welcome!
Please fork the repo, create a feature branch, and submit a PR.

### Development Setup

```bash
git clone https://github.com/yourusername/anti-netcut-linux.git
cd anti-netcut-linux
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install -e .
pytest
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).

---

## ⚠️ Disclaimer

> This tool is for **defensive security** use only.
> Use only on networks you own or have explicit permission to monitor.
> The developers assume **no responsibility** for misuse or damage.

---

## 🙏 Acknowledgments

* 🐍 [Scapy](https://scapy.net) – for powerful packet manipulation
* ☁️ Cloudflare & Google – for public DoH services
* 👩‍💻 Security researchers & testers

---

## ⭐ Support


* 🐛 Issues: GitHub Issues


If you find this tool useful, **give it a ⭐ on GitHub!**

---

## 🎯 Quick Command Reference

### Linux

```bash
sudo python -m antinetcut.cli --iface wlan0 --detect-only
sudo python -m antinetcut.cli --iface wlan0 --auto-remediate
sudo python -m antinetcut.cli --config config.json
python -m antinetcut.cli --list-queue
```

### Windows

```bash
python run_windows.py --detect-only
python run_windows.py --iface "Wi-Fi" --detect-only
python run_windows.py --list-queue
```




