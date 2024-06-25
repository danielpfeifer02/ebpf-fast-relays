#!/bin/bash

INTERFACE="enp1s0f0"

# This IP address has to match the one in the code, database bindings and grafana setup!
IP="172.16.254.134/24"

# Temporary file to store stderr
TEMPFILE=$(mktemp)

# Try to add the IP address to the interface
# Redirect stderr to the temporary file
sudo ip addr add ${IP} dev ${INTERFACE} 2>$TEMPFILE

# Check if the error is "RTNETLINK answers: File exists"
if grep -q "RTNETLINK answers: File exists" $TEMPFILE; then
    echo "IP address already exists on the interface, ignoring error."
else
    # If there was any other error, print it
    if [ -s $TEMPFILE ]; then
        echo "An error occurred:"
        cat $TEMPFILE
    fi
fi

# Clean up the temporary file
rm $TEMPFILE
