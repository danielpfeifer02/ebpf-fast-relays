#!/bin/bash

clear && cd ../../bpf/ && make clean && make && cd ../go/performance_analysis/ && go run *.go relay