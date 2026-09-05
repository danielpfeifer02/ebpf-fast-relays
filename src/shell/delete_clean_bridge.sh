#!/bin/bash
set -euo pipefail

# Tear down the tutorial bridge from bridge.sh (and any leftover v-net-1).
ip netns delete dev || true
ip netns delete prod || true

ip link set dev v-net-0 down || true
brctl delbr v-net-0 || true

ip link set dev v-net-1 down || true
brctl delbr v-net-1 || true
