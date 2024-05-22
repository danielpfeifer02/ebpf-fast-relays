#!/usr/bin/env bash

set -x

clear

sudo ip netns exec relay_ns sh -c 'export PATH=$PATH:/usr/local/go/bin && exec bash'
