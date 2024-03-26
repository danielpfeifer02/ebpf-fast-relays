TC = tc_t # tc_poc
TC_PATH = tc
BPF_TC = ${TC_PATH}/${TC:=_handling}
BPF_TC_C = ${BPF_TC:=.c}
BPF_TC_OBJ = ${BPF_TC_C:.c=.o}

BPF_TC_PINNED_PATH := /sys/fs/bpf/$(TC)
DEV_IN := veth1
DEV_EG := veth2

export PATH := $(PATH):/usr/local/go/bin

.PHONY: all clean tc

all: $(BPF_TC_OBJ) tc
	
	go build -o example/ example/main.go

tc: $(BPF_TC_OBJ)
	tc qdisc add dev ${DEV_IN} clsact
	tc qdisc add dev ${DEV_EG} clsact
	tc filter add dev ${DEV_IN} ingress bpf da obj ${BPF_TC_OBJ} sec ingress
	tc filter add dev ${DEV_EG} egress bpf da obj ${BPF_TC_OBJ} sec egress
	tc filter add dev ${DEV_EG} ingress bpf da obj ${BPF_TC_OBJ} sec ingress_startup
	tc filter show dev ${DEV_IN} ingress
	tc filter show dev ${DEV_EG} egress

# TODO add -Werror flag 
$(BPF_TC_OBJ): ${TC_PATH}/%.o: ${TC_PATH}/%.c
	clang -S \
		-g \
		-target bpf \
	  -I../libbpf/src\
	  -I../iproute2/include\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}

# not needed after ns setup
# interface:
# 	sudo ip link add veth0 type veth peer name veth1
# 	sudo ip addr add 192.168.1.1/24 dev veth0
# 	sudo ip addr add 192.168.1.2/24 dev veth1
# 	sudo ip link set dev veth0 up
# 	sudo ip link set dev veth1 up

# 	sudo ip link add veth2 type veth peer name veth3
# 	sudo ip addr add 192.168.1.3/24 dev veth2
# 	sudo ip addr add 192.168.1.4/24 dev veth3
# 	sudo ip link set dev veth2 up
# 	sudo ip link set dev veth3 up

# 	@echo "\n\n PLEASE SET ALL INTERFACE INDICES CORRECTLY IN ${BPF_TC_C}\n\n"

# 	@ip link show veth0 | awk '/^[0-9]/ {split($$0, fields, ":"); print fields[1] ":" fields[2]}'
# 	@ip link show veth1 | awk '/^[0-9]/ {split($$0, fields, ":"); print fields[1] ":" fields[2]}'
# 	@ip link show veth2 | awk '/^[0-9]/ {split($$0, fields, ":"); print fields[1] ":" fields[2]}'
# 	@ip link show veth3 | awk '/^[0-9]/ {split($$0, fields, ":"); print fields[1] ":" fields[2]}'

clean:
	sudo rm -f $(BPF_TC_PINNED_PATH)

	@if [ -e "$(BPF_TC_OBJ)" ]; then \
		echo "Deleting egress TC rules"; \
		tc filter del dev ${DEV_EG} egress; \
		tc filter del dev ${DEV_IN} ingress; \
		tc qdisc del dev ${DEV_EG} clsact; \
		tc qdisc del dev ${DEV_IN} clsact; \
		rm -f /sys/fs/bpf/tc/globals/id_counter; \
		rm -f /sys/fs/bpf/tc/globals/client_data; \
		rm -f /sys/fs/bpf/tc/globals/number_of_clients; \
		rm -f /sys/fs/bpf/tc/globals/client_id; \
	fi

	rm -f $(BPF_TC_OBJ)
	rm -f ${BPF_TC_OBJ:.o=.ll}
	rm -f example/main
