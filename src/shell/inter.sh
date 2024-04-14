#!/usr/bin/env bash

# inspired by https://gist.github.com/brauner/49e462a5d2af63705a74b215da4d20bb
#             https://www.gilesthomas.com/2021/03/fun-with-network-namespaces

set -x

NS="test_server"
PEERNS="test_relay"
VETH="veth0"
VPEER="veth1"
VETH_ADDR="192.168.1.1"
VPEER_ADDR="192.168.1.2"
NON_NS_ADDR="192.168.1.3"
MAINETH="enp1s0f0"

SERVER_VETH="veth2"
SERVER_VGLOBAL="veth3"
SERVER_VETH_ADDR="192.168.1.4"
SERVER_VGLOBAL_ADDR="192.168.1.5"


if [[ $EUID -ne 0 ]]; then
    echo "You must be root to run this script"
    exit 1
fi

# Remove namespace if it exists.
ip netns del ${NS} &>/dev/null
ip netns del ${PEERNS} &>/dev/null

# Create namespace
ip netns add ${NS}
ip netns add ${PEERNS}

# Create veth link.
ip link add ${VETH} type veth peer name ${VPEER}

# Create veth link to connect server to main ethernet interface
ip link add ${SERVER_VETH} type veth peer name ${SERVER_VGLOBAL}

# Add to NS.
ip link set ${SERVER_VETH} netns ${NS}

# Add to NS.
ip link set ${VETH} netns ${NS}
ip link set ${VPEER} netns ${PEERNS}

# Add the NON_NS_ADDR to the main interface
ip addr add ${NON_NS_ADDR}/24 dev ${MAINETH}

# Add addresses to server and main ethernet inferface connection
ip netns exec ${NS} ip addr add ${SERVER_VETH_ADDR}/24 dev ${SERVER_VETH}
ip netns exec ${NS} ip link set ${SERVER_VETH} up

ip addr add ${SERVER_VGLOBAL_ADDR}/24 dev ${SERVER_VGLOBAL}
ip link set ${SERVER_VGLOBAL} up

# Setup IP address of ${VETH}.
ip netns exec ${NS} ip addr add ${VETH_ADDR}/24 dev ${VETH}
ip netns exec ${NS} ip link set ${VETH} up
ip netns exec ${NS} ip link set lo up
ip netns exec ${NS} ip route add default via ${SERVER_VETH_ADDR} dev ${SERVER_VETH}

# Setup IP ${VPEER}.
ip netns exec ${PEERNS} ip addr add ${VPEER_ADDR}/24 dev ${VPEER}
ip netns exec ${PEERNS} ip link set ${VPEER} up
ip netns exec ${PEERNS} ip link set lo up
ip netns exec ${PEERNS} ip route add default via ${NON_NS_ADDR} dev ${VPEER} # TODO

# Enable IP-forwarding.
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush forward rules.
iptables -P FORWARD DROP
iptables -F FORWARD
 
# Flush nat rules.
iptables -t nat -F


# # Enable masquerading for internet connection
# iptables -t nat -A POSTROUTING -s ${SERVER_VGLOBAL}/24 -j MASQUERADE



# Enable masquerading
iptables -t nat -A POSTROUTING -s ${VETH_ADDR}/24 -o ${MAINETH} -j MASQUERADE
iptables -t nat -A POSTROUTING -s ${VPEER_ADDR}/24 -o ${MAINETH} -j MASQUERADE
 
iptables -A FORWARD -i ${MAINETH} -o ${VETH} -j ACCEPT
iptables -A FORWARD -o ${MAINETH} -i ${VETH} -j ACCEPT
iptables -A FORWARD -i ${MAINETH} -o ${VPEER} -j ACCEPT
iptables -A FORWARD -o ${MAINETH} -i ${VPEER} -j ACCEPT


ip netns exec ${NS} mkdir -p /etc/netns/${NS}
ip netns exec ${NS} echo "nameserver 8.8.8.8" > /etc/netns/${NS}/resolv.conf
ip netns exec ${NS} echo "nameserver 8.8.4.4" >> /etc/netns/${NS}/resolv.conf

ip netns exec ${PEERNS} mkdir -p /etc/netns/${PEERNS}
ip netns exec ${PEERNS} echo "nameserver 8.8.8.8" > /etc/netns/${PEERNS}/resolv.conf
ip netns exec ${PEERNS} echo "nameserver 8.8.4.4" >> /etc/netns/${PEERNS}/resolv.conf
