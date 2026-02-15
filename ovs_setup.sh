#!/bin/bash

set -e

NIC=enp1s0
BR=br0
IPADDR=10.100.0.1/24
SUBNET=10.100.0.0/24

systemctl start openvswitch-switch || true

ovs-vsctl --if-exists del-br $BR
ovs-vsctl add-br $BR

ovs-vsctl add-port $BR $NIC

ip link set ovs-system up
ip link set $NIC up
ip link set $BR up

ip addr flush dev $NIC
ip addr flush dev $BR

ip addr add $IPADDR dev $BR
ip route replace $SUBNET dev $BR

ip neigh flush all

