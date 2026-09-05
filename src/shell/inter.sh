#!/usr/bin/env bash
# Early netns experiment (test_server / test_relay). Prefer ser-rel-bridge.sh + rel-cli-bridge.sh.
# Inspired by:
#   https://gist.github.com/brauner/49e462a5d2af63705a74b215da4d20bb
#   https://www.gilesthomas.com/2021/03/fun-with-network-namespaces

set -euxo pipefail

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

ip netns del "$NS" &>/dev/null || true
ip netns del "$PEERNS" &>/dev/null || true

ip netns add "$NS"
ip netns add "$PEERNS"

ip link add "$VETH" type veth peer name "$VPEER"
ip link add "$SERVER_VETH" type veth peer name "$SERVER_VGLOBAL"

ip link set "$SERVER_VETH" netns "$NS"
ip link set "$VETH" netns "$NS"
ip link set "$VPEER" netns "$PEERNS"

ip addr add "${NON_NS_ADDR}/24" dev "$MAINETH"

ip netns exec "$NS" ip addr add "${SERVER_VETH_ADDR}/24" dev "$SERVER_VETH"
ip netns exec "$NS" ip link set "$SERVER_VETH" up

ip addr add "${SERVER_VGLOBAL_ADDR}/24" dev "$SERVER_VGLOBAL"
ip link set "$SERVER_VGLOBAL" up

ip netns exec "$NS" ip addr add "${VETH_ADDR}/24" dev "$VETH"
ip netns exec "$NS" ip link set "$VETH" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$SERVER_VETH_ADDR" dev "$SERVER_VETH"

ip netns exec "$PEERNS" ip addr add "${VPEER_ADDR}/24" dev "$VPEER"
ip netns exec "$PEERNS" ip link set "$VPEER" up
ip netns exec "$PEERNS" ip link set lo up
ip netns exec "$PEERNS" ip route add default via "$NON_NS_ADDR" dev "$VPEER"

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -P FORWARD DROP
iptables -F FORWARD
iptables -t nat -F

iptables -t nat -A POSTROUTING -s "${VETH_ADDR}/24" -o "$MAINETH" -j MASQUERADE
iptables -t nat -A POSTROUTING -s "${VPEER_ADDR}/24" -o "$MAINETH" -j MASQUERADE

iptables -A FORWARD -i "$MAINETH" -o "$VETH" -j ACCEPT
iptables -A FORWARD -o "$MAINETH" -i "$VETH" -j ACCEPT
iptables -A FORWARD -i "$MAINETH" -o "$VPEER" -j ACCEPT
iptables -A FORWARD -o "$MAINETH" -i "$VPEER" -j ACCEPT

mkdir -p "/etc/netns/${NS}" "/etc/netns/${PEERNS}"
printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\n' > "/etc/netns/${NS}/resolv.conf"
printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\n' > "/etc/netns/${PEERNS}/resolv.conf"
