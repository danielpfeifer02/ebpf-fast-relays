#Cleanup
ip netns delete dev
ip netns delete prod
ip link set dev v-net-0 down
brctl delbr v-net-0
ip link set dev v-net-1 down
brctl delbr v-net-1