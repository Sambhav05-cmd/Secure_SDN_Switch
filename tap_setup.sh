#!/bin/bash
set -e

VM=debian13
CONT=c1

VETH_HOST=veth-c1-host
VETH_CONT=veth-c1-cont
TAP=tap-c1
BR=br-wire
XML=/tmp/tap-c1.xml

ip link del $VETH_HOST 2>/dev/null || true
ip tuntap del dev $TAP mode tap 2>/dev/null || true
ip link del $BR 2>/dev/null || true

ip link add $VETH_HOST type veth peer name $VETH_CONT

ip tuntap add dev $TAP mode tap
ip link set $TAP up

ip link add name $BR type bridge
ip link set $BR up

ip link set $VETH_HOST up
ip link set $VETH_HOST master $BR
ip link set $TAP master $BR

PID=$(docker inspect -f '{{.State.Pid}}' $CONT)
ip link set $VETH_CONT netns $PID
nsenter -t $PID -n ip link set $VETH_CONT name eth1
nsenter -t $PID -n ip link set eth1 up

rm -f $XML
cat > $XML <<EOF
<interface type='ethernet'>
  <target dev='$TAP'/>
  <model type='virtio'/>
</interface>
EOF

virsh attach-device $VM $XML --live --config

