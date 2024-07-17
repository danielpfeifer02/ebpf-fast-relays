#!/bin/bash

# All errors or warnings are fatal and cause the script to stop
set -e

python plotting_pprof.py
cp output/tables/* ../../../../tum-thesis-bsc-fast-relays/chapters/04_subchapters/cpu_usage_tables/