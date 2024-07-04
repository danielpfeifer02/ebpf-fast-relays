#!/bin/bash

if [ -z "$1" ]; then
    echo "No namespace found. Please specify a namespace before running this script."
    exit 1
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
    exit 1
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
                is_go_process=true
                go_program_started=true
                break
            fi
        done
        if [ "$is_go_process" = true ]; then
            go_pids+=("$pid")
        fi
    done

    for go_pid in "${go_pids[@]}"; do
        echo "pid: $go_pid"
        cpu_info=$(ps -p $go_pid -o %cpu,%mem)
        echo "$cpu_info"
    done
done

