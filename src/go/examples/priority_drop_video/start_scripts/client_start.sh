#!/usr/bin/env bash

set -x

clear

sudo ip netns exec client_ns sh -c 'export PATH=$PATH:/usr/local/go/bin && exec bash'
