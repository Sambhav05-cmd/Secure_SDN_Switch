mount -t 9p -o trans=virtio,version=9p2000.L shared /mnt
systemctl start openvswitch-switch
systemctl status openvswitch-switch
modprobe openvswitch
ovs-vsctl del-port br0 eth0
ovs-vsctl set-controller br0 tcp:10.0.0.3:6653
ovs-vsctl set bridge br0 protocols=OpenFlow13
ovs-vsctl set bridge br0 fail-mode=secure

