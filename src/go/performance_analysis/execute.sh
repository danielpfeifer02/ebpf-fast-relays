#!/bin/bash

CURRENT_NAMESPACE=$(ip netns identify)

clear
if [ -z "$CURRENT_NAMESPACE" ]; then
    echo "No namespace found. Please change into a namespace before running this script."
    exit 1
fi

echo "Current namespace: $CURRENT_NAMESPACE"

run_type="diff"
if [ -z "$1" ]; then
    echo "No run type specified. Defaulting to diff."
elif [ "$1" == "diff" ] || [ "$1" == "cpu" ]; then
    run_type=$1
else
    echo "Invalid run type. Defaulting to diff."
fi

echo "Running $run_type analysis..."

if [ "$CURRENT_NAMESPACE" == "relay_ns" ]; then
    cd ../../bpf/ && make clean && make && cd ../go/performance_analysis/ && go run *.go $run_type relay
elif [ "$CURRENT_NAMESPACE" == "server_ns" ]; then
    cd ../../bpf/ && make clean && make tc_ts_eg && cd ../go/performance_analysis/ && go run *.go $run_type server
elif [ "$CURRENT_NAMESPACE" == "client_ns" ]; then
    cd ../../bpf/ && make clean && make tc_ts_in && cd ../go/performance_analysis/ && go run *.go $run_type client
else
    echo "Unknown namespace."
    exit 1
fi