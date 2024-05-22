BRIDGE_VETH_TO_REL="veth1-br"
BRIDGE_VETH_TO_CLI="veth3-br"

# Clean the bridge delay
tc qdisc del dev ${BRIDGE_VETH_TO_REL} root netem delay 100ms
tc qdisc del dev ${BRIDGE_VETH_TO_CLI} root netem delay 100ms
