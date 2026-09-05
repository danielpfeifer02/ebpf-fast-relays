#!/bin/bash
# Tutorial-style two-namespace bridge (dev/prod). Not used by the main ser/rel/cli setup.
# https://medium.com/@bjnandi/linux-network-namespace-with-bridge-d68831d5e8a1

set -euxo pipefail

ip netns add dev
ip netns add prod
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

ip addr add 192.168.10.10/24 dev v-net-0
ip -n dev route add default via 192.168.10.10

iptables --table nat -A POSTROUTING -s 192.168.10.0/24 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

# Host-side /etc/netns/<ns>/resolv.conf is bind-mounted into the namespace.
mkdir -p /etc/netns/dev
printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\n' > /etc/netns/dev/resolv.conf
