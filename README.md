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
1)  Execute 'sudo make ingress' to build and run the eBPF program inside the kernel
2)  Execute 'go run quic_traffic.go' to create some quic traffic on the system
    (you should see both high and low priority messages being transmitted)
3)  Change ...
