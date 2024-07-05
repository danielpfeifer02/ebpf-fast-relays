#!/bin/bash

if [ -z "$1" ]; then
    echo "No namespace found. Please specify a namespace before running this script."
    return
fi

CPU_NAMESPACE=$1

echo "Namespace of the tracked processes and their CPU usage: $CPU_NAMESPACE"

# Get the list of network namespaces
netns_list=$(ip netns list)

# Convert the output into an array
IFS=$'\n' read -r -d '' -a netns_array <<< "$netns_list"

# Check if the namespace exists
exists=false
for ns in "${netns_array[@]}"; do
    name=$(echo "$ns" | awk '{print $1}')
    if [ "$name" == "$CPU_NAMESPACE" ]; then
        exists=true
        break
    fi
done

if [ "$exists" = false ]; then
    echo "Namespace $CPU_NAMESPACE does not exist."
    return
fi

if [ -z "$2" ]; then
    echo "No mode found. Please specify a mode before running this script."
    return
fi

MODE=$2

if [ "$MODE" != "kernel" ] && [ "$MODE" != "user" ]; then
    echo "Invalid mode. Mode can be 'kernel' or 'user'."
    return
fi

go_program_started=false

while [ "$go_program_started" = false ]; do
    # Get the PID of the processes in the namespace
    pids=$(sudo ip netns exec "$CPU_NAMESPACE" ip netns pids "$CPU_NAMESPACE")

    # Convert the output into an array
    IFS=$'\n' read -r -d '' -a pid_array <<< "$pids"

    go_usage_indicators=("go run" "/tmp/go-build")
    go_pids=()

    # Iterate over the PIDs
    for pid in "${pid_array[@]}"; do
        # Get the CPU usage of the process
        # echo "pid: $pid"
        ax_out=$(ps ax | grep $pid)
        # echo "$ax_out"
        is_go_process=false
        for indicator in "${go_usage_indicators[@]}"; do
            if [[ "$ax_out" == *"$indicator"* ]]; then
                echo "Match with \"$indicator\" ($ax_out)"
                go_pids+=("$pid")
                go_program_started=true
                break
            fi
        done
    done
done

output_file="output/cpu_usage_pids_$CPU_NAMESPACE-$MODE.csv"
echo "pid,cpu,ts" > $output_file

while true; do
    clear
    echo "Output file: $output_file"
    ts_ns=$(date +%s%N)
    for go_pid in "${go_pids[@]}"; do
        cpu_info=$(ps -p $go_pid -o %cpu | tail -n 1) # TODO: this can show >100% cpu usage since one core is 100%.
        # top -H -n 1 -p $go_pid | awk 'NR > 7 {print $10}' # TODO: maybe use this and look up how to get correct cpu usage.
        if [ "$cpu_info" == "%CPU" ]; then
            continue
        fi
        echo "pid $go_pid uses $cpu_info% of cpu at ($ts_ns)."
        echo "$go_pid,$cpu_info,$ts_ns" >> $output_file
    done
    sleep 1
    
    # Get the PID of the processes in the namespace
    pids=$(sudo ip netns exec "$CPU_NAMESPACE" ip netns pids "$CPU_NAMESPACE")

    # Convert the output into an array
    IFS=$'\n' read -r -d '' -a pid_array <<< "$pids"

    # Update the list of PIDs
    go_pids=()

    # Iterate over the PIDs
    for pid in "${pid_array[@]}"; do
        # Get the CPU usage of the process
        # echo "pid: $pid"
        ax_out=$(ps ax | grep $pid)
        # echo "$ax_out"
        is_go_process=false
        for indicator in "${go_usage_indicators[@]}"; do
            if [[ "$ax_out" == *"$indicator"* ]]; then
                go_pids+=("$pid")
                break
            fi
        done
    done
    if [ ${#go_pids[@]} -eq 0 ]; then
        echo "No Go processes found in the namespace."
        break
    fi
done
