#!/bin/bash

#https://medium.com/@bjnandi/linux-network-namespace-with-bridge-d68831d5e8a1

set euxo -pipefail
ip netns add dev
ip netns add prod
#show namespace
ip netns show
ip link add v-net-0 type bridge
ip link set dev v-net-0 up
ip link add veth-dev type veth peer name veth-dev-br
ip link add veth-prod type veth peer name veth-prod-br
ip link set veth-dev netns dev
ip link set veth-dev-br master v-net-0
ip link set veth-prod netns prod
ip link set veth-prod-br master v-net-0
ip -n dev addr add 192.168.10.1/24 dev veth-dev
ip -n prod addr add 192.168.10.2/24 dev veth-prod
ip -n dev link set veth-dev up
ip -n prod link set veth-prod up
ip link set veth-dev-br up
ip link set veth-prod-br up

## Execute below to set the gateway on the linux bridge
ip addr add 192.168.10.10/24 dev v-net-0
# lets add the route to namespace dev
ip -n dev route add default via 192.168.10.10

iptables --table nat -A POSTROUTING -s 192.168.10.0/24 -j MASQUERADE
## Note. make sure the ipv4 forwarding is enabled
echo 1 > /proc/sys/net/ipv4/ip_forward

# set dns server
ip netns exec dev mkdir -p /etc/netns/dev
ip netns exec dev echo "nameserver 8.8.8.8" > /etc/netns/dev/resolv.conf
ip netns exec dev echo "nameserver 8.8.4.4" >> /etc/netns/dev/resolv.conf