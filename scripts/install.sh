#!/bin/bash
#
# Anti-Netcut Installation Script
#

set -e

echo "Installing Anti-Netcut for Linux..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required"
    exit 1
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root for full installation"
    exit 1
fi

# Install directory
INSTALL_DIR="/opt/antinetcut"
CONFIG_DIR="/etc/antinetcut"
LOG_DIR="/var/log/antinetcut"
DATA_DIR="/var/lib/antinetcut"

# Create directories
echo "Creating directories..."
mkdir -p $INSTALL_DIR $CONFIG_DIR $LOG_DIR $DATA_DIR

# Copy files
echo "Copying files..."
cp -r ./* $INSTALL_DIR/

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r $INSTALL_DIR/requirements.txt

# Install package
echo "Installing package..."
cd $INSTALL_DIR && python3 setup.py install

# Create default config
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    echo "Creating default configuration..."
    cat > $CONFIG_DIR/config.json << EOF
{
    "iface": "eth0",
    "auto_remediate": false,
    "detect_only": false,
    "whitelist_file": "$CONFIG_DIR/whitelist.json",
    "queue_file": "$DATA_DIR/queue.json",
    "log_file": "$LOG_DIR/antinetcut.log"
}
EOF
fi

# Create whitelist
if [ ! -f "$CONFIG_DIR/whitelist.json" ]; then
    echo "Creating default whitelist..."
    echo "{}" > $CONFIG_DIR/whitelist.json
fi

# Create systemd service
if command -v systemctl &> /dev/null; then
    echo "Creating systemd service..."
    cat > /etc/systemd/system/antinetcut.service << EOF
[Unit]
Description=Anti-Netcut Network Security Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/antinetcut --config /etc/antinetcut/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "Systemd service created"
fi

# Set permissions
chmod +x $INSTALL_DIR/scripts/*.sh

echo ""
echo "Installation complete!"
echo ""
echo "Quick start:"
echo "  sudo antinetcut --iface eth0"
echo ""
echo "Configuration: /etc/antinetcut/config.json"
echo "Logs: /var/log/antinetcut/antinetcut.log"
echo ""