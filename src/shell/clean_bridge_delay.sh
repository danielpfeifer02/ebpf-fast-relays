#!/bin/bash
set -euo pipefail

BRIDGE_VETH_TO_REL="veth1-br"
BRIDGE_VETH_TO_CLI="veth3-br"

tc qdisc del dev "$BRIDGE_VETH_TO_REL" root netem delay 5ms
tc qdisc del dev "$BRIDGE_VETH_TO_CLI" root netem delay 5ms
