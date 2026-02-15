#!/bin/bash
set -e

BR=br0

systemctl start openvswitch-switch || true

ovs-vsctl --if-exists del-br $BR
ovs-vsctl add-br $BR

ip link set ovs-system up
ip link set $BR up

for IF in $(ls /sys/class/net); do
    [[ "$IF" == "lo" ]] && continue
    [[ "$IF" == "ovs-system" ]] && continue
    [[ "$IF" == "$BR" ]] && continue

    [[ ! -e "/sys/class/net/$IF/device" ]] && continue

    ip addr flush dev $IF || true
    ip link set $IF up

    ovs-vsctl --may-exist add-port $BR $IF
done

