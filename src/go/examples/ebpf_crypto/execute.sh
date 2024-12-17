#!/bin/bash

CURRENT_NAMESPACE=$(ip netns identify)

clear
if [ -z "$CURRENT_NAMESPACE" ]; then
    echo "No namespace found. Please change into a namespace before running this script."
    exit 1
fi

echo "Current namespace: $CURRENT_NAMESPACE"

# QUIC_GO_DISABLE_GSO=true
# QUIC_GO_LOG_LEVEL=debug QLOGDIR=.

# -e trace=bpf 
if [ "$CURRENT_NAMESPACE" == "relay_ns" ]; then
    cd ../../../bpf/ && make clean && make tc_crypto_eg && make tc_crypto_ig && cd ../go/examples/ebpf_crypto/ && QUIC_GO_DISABLE_GSO=true go run *.go relay
elif [ "$CURRENT_NAMESPACE" == "server_ns" ]; then
    QUIC_GO_DISABLE_GSO=true go run *.go server
elif [ "$CURRENT_NAMESPACE" == "client_ns" ]; then
    echo "Nothing to do for client namespace" 
else
    echo "Unknown namespace."
    exit 1
fi
