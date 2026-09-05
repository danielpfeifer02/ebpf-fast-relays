#!/bin/bash
# Attach client_ns to existing relay_ns via bridge v-net-1 (192.168.11.0/24).
# Run after ser-rel-bridge.sh so relay_ns already exists.

set -euxo pipefail

CLIENT_NS="client_ns"
RELAY_NS="relay_ns"

CLIENT_VETH="veth3"
RELAY_VETH="veth2"
CLIENT_VETH_PEER="veth3-br"
RELAY_VETH_PEER="veth2-br"

CLIENT_VETH_ADDR="192.168.11.1"
RELAY_VETH_ADDR="192.168.11.2"
BRIDGE_IP="192.168.11.10"
BRIDGE_NET_ADDR="192.168.11.0"

BRIDGE_INTERFACE="v-net-1"
BRIDGE_VETH_TO_CLI="veth3-br"

if [[ $EUID -ne 0 ]]; then
	echo "You must be root to run this script"
	exit 1
fi

if ip netns list | grep -q "$CLIENT_NS"; then
	echo "deleting $CLIENT_NS"
	ip netns del "$CLIENT_NS"
fi
if ip link show | grep -q "$BRIDGE_INTERFACE"; then
	echo "deleting $BRIDGE_INTERFACE"
	ip link set dev "$BRIDGE_INTERFACE" down
	brctl delbr "$BRIDGE_INTERFACE"
fi
if ip link show | grep -q "$CLIENT_VETH_PEER"; then
	echo "deleting $CLIENT_VETH_PEER"
	ip link set dev "$CLIENT_VETH_PEER" down
	ip link del "$CLIENT_VETH_PEER"
fi
if ip link show | grep -q "$RELAY_VETH_PEER"; then
	echo "deleting $RELAY_VETH_PEER"
	ip link set dev "$RELAY_VETH_PEER" down
	ip link del "$RELAY_VETH_PEER"
fi

ip netns add "$CLIENT_NS"

if ! ip netns list | grep -q "$RELAY_NS"; then
	echo "Relay namespace not existing"
	exit 1
fi

ip netns show

ip link add "$BRIDGE_INTERFACE" type bridge
ip link set dev "$BRIDGE_INTERFACE" up

ip link add "$CLIENT_VETH" type veth peer name "$CLIENT_VETH_PEER"
ip link add "$RELAY_VETH" type veth peer name "$RELAY_VETH_PEER"

ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip link set "$CLIENT_VETH_PEER" master "$BRIDGE_INTERFACE"
ip link set "$RELAY_VETH" netns "$RELAY_NS"
ip link set "$RELAY_VETH_PEER" master "$BRIDGE_INTERFACE"

ip -n "$CLIENT_NS" addr add "${CLIENT_VETH_ADDR}/24" dev "$CLIENT_VETH"
ip -n "$RELAY_NS" addr add "${RELAY_VETH_ADDR}/24" dev "$RELAY_VETH"

ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
ip -n "$RELAY_NS" link set "$RELAY_VETH" up
ip link set "$CLIENT_VETH_PEER" up
ip link set "$RELAY_VETH_PEER" up

ip -n "$CLIENT_NS" link set lo up
ip -n "$RELAY_NS" link set lo up

ip addr add "${BRIDGE_IP}/24" dev "$BRIDGE_INTERFACE"
ip -n "$CLIENT_NS" route add default via "$BRIDGE_IP"

iptables --table nat -A POSTROUTING -s "${BRIDGE_NET_ADDR}/24" -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

mkdir -p "/etc/netns/${CLIENT_NS}"
printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\n' > "/etc/netns/${CLIENT_NS}/resolv.conf"

tc qdisc add dev "$BRIDGE_VETH_TO_CLI" root netem delay 5ms
