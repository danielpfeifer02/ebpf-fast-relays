#!/bin/bash
set -euo pipefail

INTERFACE="enp1s0f0"

# Must match the address used in application code, DB bindings, and Grafana.
IP="172.16.254.134/24"

TEMPFILE="$(mktemp)"
trap 'rm -f "$TEMPFILE"' EXIT

# Ignore "File exists"; surface any other error from ip(8).
if ! sudo ip addr add "$IP" dev "$INTERFACE" 2>"$TEMPFILE"; then
	if grep -q "RTNETLINK answers: File exists" "$TEMPFILE"; then
		echo "IP address already exists on the interface, ignoring error."
	elif [[ -s "$TEMPFILE" ]]; then
		echo "An error occurred:"
		cat "$TEMPFILE"
		exit 1
	fi
fi
