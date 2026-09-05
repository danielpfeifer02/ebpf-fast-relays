#!/bin/bash
set -euxo pipefail

SERVER_NS="server_ns"
RELAY_NS="relay_ns"
CLIENT_NS="client_ns"

SERVER_VETH_ADDR="192.168.10.1"
RELAY_VETH_ADDR_S="192.168.10.2"
RELAY_VETH_ADDR_C="192.168.11.2"
CLIENT_VETH_ADDR="192.168.11.1"

PUBLIC_IP="1.1.1.1"

# Connectivity checks: every namespace can reach every other, plus the public internet.
for ns in "$SERVER_NS" "$RELAY_NS" "$CLIENT_NS"; do
	for addr in "$SERVER_VETH_ADDR" "$RELAY_VETH_ADDR_S" "$RELAY_VETH_ADDR_C" "$CLIENT_VETH_ADDR"; do
		ip netns exec "$ns" ping -c 1 "$addr"
	done
done

for ns in "$SERVER_NS" "$RELAY_NS" "$CLIENT_NS"; do
	ip netns exec "$ns" ping -c 1 "$PUBLIC_IP"
done

printf '\n\n\t\tAll tests passed.\n\t\tSetup complete!\n\n'
