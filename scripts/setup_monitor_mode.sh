#!/bin/bash
#
# Monitor Mode Setup for Wireless Interface
#

set -e

IFACE=${1:-wlan0}
MON_IFACE="${IFACE}mon"

echo "Setting up monitor mode on $IFACE..."

# Check if interface exists
if ! ip link show "$IFACE" &> /dev/null; then
    echo "Error: Interface $IFACE not found"
    exit 1
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Bring interface down
echo "Bringing down $IFACE..."
ip link set "$IFACE" down

# Set monitor mode
echo "Setting monitor mode..."
iwconfig "$IFACE" mode monitor

# Bring interface up
echo "Bringing up $IFACE..."
ip link set "$IFACE" up

# Check if monitor mode was set
if iwconfig "$IFACE" | grep -q "Mode:Monitor"; then
    echo "Monitor mode successfully enabled on $IFACE"
    echo "You can now use: sudo antinetcut --iface $IFACE"
else
    echo "Failed to enable monitor mode on $IFACE"
    echo "Trying alternative method..."
    
    # Try using airmon-ng
    if command -v airmon-ng &> /dev/null; then
        airmon-ng start "$IFACE"
        echo "Monitor mode started with airmon-ng"
    else
        echo "Please install aircrack-ng for airmon-ng"
        exit 1
    fi
fi