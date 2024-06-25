#!/bin/bash

clear && cd ../../../bpf/ && make clean && make && cd ../go/examples/priority_drop_chat/ && go run *.go relay