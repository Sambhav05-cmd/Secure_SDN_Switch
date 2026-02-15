#!/usr/bin/env bash
set -e

VM=debian13
VLAN=100

# Find the vnet connected to Control-Bridge
VNET=$(virsh domiflist "$VM" | awk '$2=="bridge" && $3=="Control-Bridge"{print $1}')

if [ -z "$VNET" ]; then
    echo "No vnet attached to Control-Bridge for VM $VM"
    exit 1
fi

# Remove default VLAN 1
bridge vlan del dev "$VNET" vid 1 2>/dev/null || true

# Set VLAN 100 as access VLAN
bridge vlan add dev "$VNET" vid "$VLAN" pvid untagged

echo "$VNET is now in VLAN $VLAN"

