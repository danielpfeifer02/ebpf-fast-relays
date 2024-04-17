#!/usr/bin/env bash

set -x

clear

RELAY_NS="relay_ns"

export PATH=${PATH}:/usr/local/go/bin
cd ..
ip netns exec ${RELAY_NS} go run *.go relay
