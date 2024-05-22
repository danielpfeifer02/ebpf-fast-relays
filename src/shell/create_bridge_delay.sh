BRIDGE_VETH_TO_REL="veth1-br"
BRIDGE_VETH_TO_CLI="veth3-br"

# Add a delay to the bridge connecting relay and client
tc qdisc add dev ${BRIDGE_VETH_TO_CLI} root netem delay 100ms

# Add a delay to the bridge connecting relay and client
tc qdisc add dev ${BRIDGE_VETH_TO_REL} root netem delay 100ms