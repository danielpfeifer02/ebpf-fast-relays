# Adaptive_MoQ
Adaptive media streaming implementation ideas using AF_XDP, TC, eBPF and potentially NIC offload

## Add an ingress packet handler based on eBPF using XDP hook ##
Execute 'sudo make ingress' inside of the directory 'loopback_quic/'

## Add an egress packet handler based on eBPF using TC hook ##
Execute 'sudo make egress' inside of the directory 'loopback_quic/'

## Remove all packet handlers ##
Execute 'sudo make clean' inside of the directory 'loopback_quic/'

## Run the example of adaptive packet handling ##
0)  Navigate inside the 'loopback_quic' folder
1)  Execute 'sudo make ingress' to build and hook the eBPF program inside the kernel
2)  Execute 'sudo make manage' to build the c program that will handle the eBPF-map access that is used to enable/disable the packet dropping
3)  Execute 'go run *.go' to run the main program loop of the example
4)  Execute 'sudo make clean' to remrove all the files and unhook the eBPF program from the kernel
