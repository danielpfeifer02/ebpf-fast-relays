#!/bin/bash
set -euo pipefail

# Spawn an xfce4-terminal that reads shell commands from a FIFO (manual test helper).
SERVER_PIPE="/tmp/xfce_terminal_pipe_server"
mkfifo "$SERVER_PIPE"

dbus-launch xfce4-terminal --hold -e "bash -c 'while true; do if read line < $SERVER_PIPE; then eval \"\$line\"; fi; done'"

echo "cd ../go/examples/priority_drop_video/" > "$SERVER_PIPE"
echo "ls" > "$SERVER_PIPE"
echo "sudo sh start_scripts/server_start.sh" > "$SERVER_PIPE"

rm -f "$SERVER_PIPE"
