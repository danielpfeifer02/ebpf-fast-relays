#!/bin/bash

set -e
set -x
set -o errexit

SERVER_NS="server_ns"
RELAY_NS="relay_ns"
CLIENT_NS="client_ns"

SERVER_VETH_ADDR="192.168.10.1"
RELAY_VETH_ADDR_S="192.168.10.2"
RELAY_VETH_ADDR_C="192.168.11.2"
CLIENT_VETH_ADDR="192.168.11.1"

PUBLIC_IP="1.1.1.1"

# Test the connectivity

# Every ns should be able to ping every other ns
ip netns exec ${SERVER_NS} ping -c 1 ${SERVER_VETH_ADDR}
ip netns exec ${SERVER_NS} ping -c 1 ${RELAY_VETH_ADDR_S}
ip netns exec ${SERVER_NS} ping -c 1 ${RELAY_VETH_ADDR_C}
ip netns exec ${SERVER_NS} ping -c 1 ${CLIENT_VETH_ADDR}

ip netns exec ${RELAY_NS} ping -c 1 ${SERVER_VETH_ADDR}
ip netns exec ${RELAY_NS} ping -c 1 ${RELAY_VETH_ADDR_S}
ip netns exec ${RELAY_NS} ping -c 1 ${RELAY_VETH_ADDR_C}
ip netns exec ${RELAY_NS} ping -c 1 ${CLIENT_VETH_ADDR}

ip netns exec ${CLIENT_NS} ping -c 1 ${SERVER_VETH_ADDR}
ip netns exec ${CLIENT_NS} ping -c 1 ${RELAY_VETH_ADDR_S}
ip netns exec ${CLIENT_NS} ping -c 1 ${RELAY_VETH_ADDR_C}
ip netns exec ${CLIENT_NS} ping -c 1 ${CLIENT_VETH_ADDR}

# Every ns should be able to access the internet (i.e. ping any public IP like 1.1.1.1)
ip netns exec ${SERVER_NS} ping -c 1 ${PUBLIC_IP}
ip netns exec ${RELAY_NS} ping -c 1 ${PUBLIC_IP}
ip netns exec ${CLIENT_NS} ping -c 1 ${PUBLIC_IP}

echo "\n\n\t\tAll tests passed.\n\t\tSetup complete!\n\n"