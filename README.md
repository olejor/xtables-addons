xtables-addons
==============

A fork of xtables-addons for the development of grekey target

grekey target modifies the "key" if present in the GRE header
of a packet. This is useful for terminating ERSPAN traffic
from vSphere 5.1 on the same gre tunnel interface:

iptables -t mangle -A PREROUTING -s <vsphere ip> -p gre -j grekey
ip link add foo type gretap local <ip> remote <vsphere ip> key 123456
ip link set foo up
tcpdump -i foo

vSphere 5.x will set 0x00000000 as key on ingress captured traffic,
and 0x0020000 on egress captured traffic. So instead of setting up
two interfaces (gretap), you rewrite the key in the packets and 
therefore only need one interface per VMWare host.
