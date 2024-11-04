#!/bin/bash

# Create a named pipe (FIFO) to send commands to the new terminal
SERVER_PIPE="/tmp/xfce_terminal_pipe_server"
mkfifo "$SERVER_PIPE"

# Spawn a new xfce4-terminal and have it continuously read from the pipe
dbus-launch xfce4-terminal --hold -e "bash -c 'while true; do if read line < $SERVER_PIPE; then eval \"\$line\"; fi; done'"

# Enter the server namespace
echo "cd ../go/examples/priority_drop_video/" > "$SERVER_PIPE"
echo "ls" > "$SERVER_PIPE"
echo "sudo sh start_scripts/server_start.sh" > "$SERVER_PIPE"


# Clean up the pipe (optional, if you want the pipe to persist)
rm "$SERVER_PIPE"
