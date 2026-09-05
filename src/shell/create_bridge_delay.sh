#!/bin/bash
set -euo pipefail

BRIDGE_VETH_TO_REL="veth1-br"
BRIDGE_VETH_TO_CLI="veth3-br"

# 5ms netem delay on both bridge veths facing the relay/client path.
tc qdisc add dev "$BRIDGE_VETH_TO_CLI" root netem delay 5ms
tc qdisc add dev "$BRIDGE_VETH_TO_REL" root netem delay 5ms
