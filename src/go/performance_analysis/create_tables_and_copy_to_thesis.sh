#!/bin/bash

# All errors or warnings are fatal and cause the script to stop
# set -e

python plotting_pprof.py cpu-setup-turned-on.prof cpu_setup_turned_on
python plotting_pprof.py cpu-setup-turned-off.prof cpu_setup_turned_off
cp output/tables/* ../../../../tum-thesis-bsc-fast-relays/chapters/04_subchapters/cpu_usage_tables/