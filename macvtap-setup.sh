#!/usr/bin/env bash
set -e

VM=debian13
CONTAINER=c1
IP=10.10.0.10/24

# Resolve ethernet dataplane NICs
ETH_IFS=$(virsh domiflist "$VM" | awk '$2=="ethernet"{print $1}')

if [ -z "$ETH_IFS" ]; then
    echo "No ethernet dataplane NIC found on VM"
    exit 1
fi

# Pick newest one
VNET=$(echo "$ETH_IFS" | sort -V | tail -n 1)
echo "Using dataplane interface: $VNET"

# Create macvtap if missing
if ! ip link show macvtap-c1 &>/dev/null; then
    ip link add macvtap-c1 link "$VNET" type macvtap mode bridge
fi

ip link set macvtap-c1 up

# Get container PID
PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")

# Move macvtap into container namespace
ip link set macvtap-c1 netns "$PID"

# Configure interface inside container
nsenter -t "$PID" -n sh -c "
ip link set macvtap-c1 name eth0
ip link set eth0 up
ip addr add $IP dev eth0 2>/dev/null || true
"

