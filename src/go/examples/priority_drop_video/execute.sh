#!/bin/bash

CURRENT_NAMESPACE=$(ip netns identify)

clear
if [ -z "$CURRENT_NAMESPACE" ]; then
    echo "No namespace found. Please change into a namespace before running this script."
    exit 1
fi

echo "Current namespace: $CURRENT_NAMESPACE"

# -e trace=bpf 
if [ "$CURRENT_NAMESPACE" == "relay_ns" ]; then
#    cd ../../../bpf/ && make clean && make && cd ../go/examples/priority_drop_video/ && strace -f -c go run *.go relay
    cd ../../../bpf/ && make clean && make && cd ../go/examples/priority_drop_video/ && go run *.go relay
elif [ "$CURRENT_NAMESPACE" == "server_ns" ]; then
    go run *.go server
elif [ "$CURRENT_NAMESPACE" == "client_ns" ]; then
    go run *.go client
else
    echo "Unknown namespace."
    exit 1
fi
