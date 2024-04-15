#!/usr/bin/env bash

set -x

clear

SERVER_NS="server_ns"

export PATH=${PATH}:/usr/local/go/bin
cd ..
ip netns exec ${SERVER_NS} go run *.go server
