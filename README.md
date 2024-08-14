# eBPF-Assisted Relays for Media-Streaming
This repository contains eBPF programs that allow kernel-space
forwarding of packets for a decrease in forwarding delay.
This approach avoids immediate user-space processing and delays 
it until after a packet was forwarded.
For this we use the TC hook point for BPF both on ingress and 
egress side.

## Contents ##
The repository contains, aside from the eBPF programs, also
application level implementations of server, relay and client side
(within src/go/examples), as well as shell scripts that allow for 
easy setup, testing and analysis.
The examples contain a chat example where messages are kernel-forwarded
and a video example where a video stream is created using gstreamer and
kernel-forwarded.
There is also a "proof of concept" example that just shows that forwarding 
from ingress to egress still triggers the egress eBPF program.
A special performance analysis implementation of the application layer
is also provided such that there is no need to actually transmit video
data but mock-data is sent instead.

## Set up the namespaces ##
- Go into the directory ``src/shell/''
- Run the following commands to set up the bridges and namespaces:
    ``sudo sh ser-rel-bridge.sh''
    ``sudo sh rel-cli-bridge.sh''
- After the bridges and namespaces have been set up you can test the setup 
by executing the following command:
    ``sudo sh test-setup.sh''
- In case you want to use grafana for the same ip that is used in our code
you need to run:
    ``sudo sh add_db_ip.sh''

## Enter a namespace and run the corresponding application layer program ##
- To enter a certain namespace you need to execute the following command from within the directory src/go/examples/priority_drop_video:
    ``sudo sh start_scripts/(server|relay|client)_start.sh''
- After that you can run the program using:
    ``source execute.sh''

## After program is done running clean up potential left-overs ##
- To clean up potential left-overs after running an application layer
program that used kernel-forwarding run:
    ``source delete.sh''

This, for example, removes all used eBPF programs that have been hooked to TC
