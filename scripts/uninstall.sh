#!/bin/bash
#
# Anti-Netcut Uninstallation Script
#

set -e

echo "Uninstalling Anti-Netcut..."

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Stop service if running
if systemctl is-active --quiet antinetcut; then
    echo "Stopping antinetcut service..."
    systemctl stop antinetcut
    systemctl disable antinetcut
fi

# Remove systemd service
if [ -f "/etc/systemd/system/antinetcut.service" ]; then
    echo "Removing systemd service..."
    rm -f /etc/systemd/system/antinetcut.service
    systemctl daemon-reload
fi

# Remove installation
if [ -d "/opt/antinetcut" ]; then
    echo "Removing installation directory..."
    rm -rf /opt/antinetcut
fi

# Remove binary
if [ -f "/usr/local/bin/antinetcut" ]; then
    echo "Removing binary..."
    rm -f /usr/local/bin/antinetcut
fi

echo "Uninstallation complete!"