# Adaptive_MoQ
Adaptive media streaming implementation ideas using AF_XDP, TC, eBPF and potentially NIC offload

## Add an ingress packet handler based on eBPF using XDP hook ##
Execute 'sudo make ingress' inside of the directory 'loopback_quic/'

## Add an egress packet handler based on eBPF using TC hook ##
Execute 'sudo make egress' inside of the directory 'loopback_quic/'

## Remove all packet handlers ##
Execute 'sudo make clean' inside of the directory 'loopback_quic/'
