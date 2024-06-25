#!/bin/bash

CURRENT_NAMESPACE=$(ip netns identify)

clear
if [ -z "$CURRENT_NAMESPACE" ]; then
    echo "No namespace found. Please change into a namespace before running this script."
    exit 1
fi

echo "Current namespace: $CURRENT_NAMESPACE"

if [ "$CURRENT_NAMESPACE" == "relay_ns" ]; then
    cd ../../bpf/ && make clean && cd ../go/performance_analysis/
elif [ "$CURRENT_NAMESPACE" == "server_ns" ]; then
    cd ../../bpf/ && make clean && cd ../go/performance_analysis/
elif [ "$CURRENT_NAMESPACE" == "client_ns" ]; then
    cd ../../bpf/ && make clean && cd ../go/performance_analysis/
else
    echo "Unknown namespace."
    exit 1
fi