#!/usr/bin/env bash

set -x

clear

CLIENT_NS="client_ns"

export PATH=${PATH}:/usr/local/go/bin
cd ..
ip netns exec ${CLIENT_NS} go run *.go client
