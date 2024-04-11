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
	tc filter add dev ${DEV_EG} ingress bpf da obj ${BPF_TC_OBJ} sec ingress_from_client
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
		rm -f /sys/fs/bpf/tc/globals/packet_counter; \
		rm -f /sys/fs/bpf/tc/globals/connection_established; \
		rm -f /sys/fs/bpf/tc/globals/client_pn; \
		rm -f /sys/fs/bpf/tc/globals/connection_current_pn; \
		rm -f /sys/fs/bpf/tc/globals/connection_pn_translation; \
		rm -f /sys/fs/bpf/tc/globals/client_stream_offset; \
	fi

	rm -f $(BPF_TC_OBJ)
	rm -f ${BPF_TC_OBJ:.o=.ll}
	rm -f example/main
