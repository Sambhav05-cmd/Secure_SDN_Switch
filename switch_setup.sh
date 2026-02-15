#!/bin/bash
set -e

BR=br0
BR_IP=10.0.0.1/24
CONTROLLER_IP=10.100.0.1
OF_PORT=6653

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

ip addr flush dev $BR || true
ip addr add $BR_IP dev $BR

ovs-vsctl set bridge $BR protocols=OpenFlow13
ovs-vsctl set bridge $BR fail-mode=secure
ovs-vsctl set-controller $BR tcp:$CONTROLLER_IP:$OF_PORT

ovs-ofctl del-flows $BR

