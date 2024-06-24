TC = tc_t # tc_poc
TC_PATH = tc/main
BPF_TC = ${TC_PATH}/${TC:=_handling}
# BPF_TC_OBJ = ${BPF_TC:=.o}
TC_C_FILES := $(wildcard ${TC_PATH}/*.c)
BPF_TC_OBJ := $(patsubst ${TC_PATH}/%.c,${TC_PATH}/%.o,$(TC_C_FILES))

# TODO: make more resilient to changes?
BPF_TC_OBJ_ING_CLIENT := ${TC_PATH}/tc_ingress_client_side.o
BPF_TC_OBJ_ING_SERVER := ${TC_PATH}/tc_ingress_server_side.o
BPF_TC_OBJ_EG_CLIENT := ${TC_PATH}/tc_egress_client_side.o


BPF_TC_PINNED_PATH := /sys/fs/bpf/$(TC)

# This is for the proof of concept of redirecting ingress packets to egress.
TC_IN_TO_EG = tc_poc
TC_IN_TO_EG_PATH = tc/proof_of_concept_redirection
BPF_TC_IN_TO_EG = ${TC_IN_TO_EG_PATH}/${TC_IN_TO_EG:=_handling}
BPF_TC_IN_TO_EG_C = ${BPF_TC_IN_TO_EG:=.c}
BPF_TC_IN_TO_EG_OBJ = ${BPF_TC_IN_TO_EG_C:.c=.o}

BPF_TC_IN_TO_EG_PINNED_PATH := /sys/fs/bpf/$(TC_IN_TO_EG)

DEV_IN := veth1
DEV_EG := veth2

DEV_EG_INDEX := $(shell ip link show $(DEV_EG) | awk '/^[0-9]/ {print $$1}' | sed 's/://')

ifeq ($(strip $(DEV_EG_INDEX)),)
	DEV_EG_INDEX := 0
endif

# This is for the timestamp programs for the performance evaluation.
TS_DEV_IN := veth0
TS_DEV_EG := veth0

TC_TS = tc_ts
BPF_TC_TS_PINNED_PATH := /sys/fs/bpf/$(TC_TS)

TC_TS_PATH = tc/performance_analysis
BPF_TC_OBJ_TS_ING = ${TC_TS_PATH}/tc_ts_handling_ingress.o
BPF_TC_OBJ_TS_EG = ${TC_TS_PATH}/tc_ts_handling_egress.o


CUR_NS := $(shell ip netns identify)

# TODO: other way to export PATH
export PATH := $(PATH):/usr/local/go/bin

PRIO_DROP_PATH_VIDEO := ../go/examples/priority_drop_video
PRIO_DROP_PATH_CHAT := ../go/examples/priority_drop_chat
INGRESS_TO_EGRESS_PATH := ../go/examples/ingress_to_egress

.PHONY: clean all tc_main tc_poc tc_ts chat

all: $(BPF_TC_OBJ) tc_main
	@echo "ifindex for $(DEV_EG): $(DEV_EG_INDEX)"
#	TODO: better practice to work with compiled go code?
#	go build -o ${PRIO_DROP_PATH_VIDEO}/build/main ${PRIO_DROP_PATH_VIDEO}/*.go

chat: $(BPF_TC_OBJ) tc_main
	go build -o ${PRIO_DROP_PATH_CHAT}/build/main ${PRIO_DROP_PATH_CHAT}/*.go

poc: $(BPF_TC_IN_TO_EG_OBJ) tc_poc
	@if [ ! -e "/sys/kernel/tracing/trace_pipe" ]; then \
		echo "Mounting tracefs"; \
		sudo mount -t tracefs tracefs /sys/kernel/tracing; \
	fi
	go build -o ${INGRESS_TO_EGRESS_PATH}/build ${INGRESS_TO_EGRESS_PATH}/main.go

tc_main:
	tc qdisc add dev ${DEV_IN} clsact
	tc qdisc add dev ${DEV_EG} clsact
	tc filter add dev ${DEV_IN} ingress bpf da obj ${BPF_TC_OBJ_ING_SERVER} sec ingress
	tc filter add dev ${DEV_EG} egress bpf da obj ${BPF_TC_OBJ_EG_CLIENT} sec egress
	tc filter add dev ${DEV_EG} ingress bpf da obj ${BPF_TC_OBJ_ING_CLIENT} sec ingress_from_client
	tc filter show dev ${DEV_IN} ingress
	tc filter show dev ${DEV_EG} egress

tc_poc: $(BPF_TC_IN_TO_EG_OBJ)
	tc qdisc add dev ${DEV_IN} clsact
	tc qdisc add dev ${DEV_EG} clsact
	tc filter add dev ${DEV_IN} ingress bpf da obj ${BPF_TC_IN_TO_EG_OBJ} sec ingress
	tc filter add dev ${DEV_EG} egress bpf da obj ${BPF_TC_IN_TO_EG_OBJ} sec egress
	tc filter show dev ${DEV_IN} ingress
	tc filter show dev ${DEV_EG} egress

tc_ts: $(BPF_TC_OBJ_TS_ING) $(BPF_TC_OBJ_TS_EG)
	tc qdisc add dev ${TS_DEV_IN} clsact
#	tc qdisc add dev ${TS_DEV_EG} clsact // TODO: only needed if TS_DEV_EG and TS_DEV_IN are different
	tc filter add dev ${TS_DEV_IN} ingress bpf da obj ${BPF_TC_OBJ_TS_ING} sec ts_ingress
	tc filter add dev ${TS_DEV_EG} egress bpf da obj ${BPF_TC_OBJ_TS_EG} sec ts_egress
	tc filter show dev ${TS_DEV_IN} ingress
	tc filter show dev ${TS_DEV_EG} egress

# Main tc program compilation
# TODO add -Werror flag 
$(BPF_TC_OBJ): ${TC_PATH}/%.o: ${TC_PATH}/%.c
	clang -S \
		-Dveth2_egress_ifindex=${DEV_EG_INDEX} \
		-g \
		-target bpf \
	  -I../../libbpf/src\
	  -I../../iproute2/include\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}

# Proof of concept of redirecting compilation
# TODO add -Werror flag 
$(BPF_TC_IN_TO_EG_OBJ): ${TC_IN_TO_EG_PATH}/%.o: ${TC_IN_TO_EG_PATH}/%.c
	clang -S \
		-Dveth2_egress_ifindex=${DEV_EG_INDEX} \
		-g \
		-target bpf \
	  -I../../libbpf/src\
	  -I../../iproute2/include\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}	

# Timestamp programs compilation
$(BPF_TC_OBJ_TS_ING): ${TC_TS_PATH}/%.o: ${TC_TS_PATH}/%.c
	clang -S \
		-g \
		-target bpf \
	  -I../../libbpf/src\
	  -I../../iproute2/include\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}

$(BPF_TC_OBJ_TS_EG): ${TC_TS_PATH}/%.o: ${TC_TS_PATH}/%.c
	clang -S \
		-g \
		-target bpf \
	  -I../../libbpf/src\
	  -I../../iproute2/include\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}

clean:

	echo $(CUR_NS)

	@if [ "$(CUR_NS)" = "relay_ns" ]; then \
		sudo rm -f $(BPF_TC_PINNED_PATH); \
		if [ -e "$(BPF_TC_OBJ_ING_SERVER)" ]; then \
			echo "Deleting TC filters and maps"; \
			rm -f $(BPF_TC_OBJ); \
			rm -f ${BPF_TC_OBJ:.o=.ll}; \
			rm -f /sys/fs/bpf/tc/globals/id_counter; \
			rm -f /sys/fs/bpf/tc/globals/client_data; \
			rm -f /sys/fs/bpf/tc/globals/number_of_clients; \
			rm -f /sys/fs/bpf/tc/globals/client_id; \
			rm -f /sys/fs/bpf/tc/globals/connection_established; \
			rm -f /sys/fs/bpf/tc/globals/client_pn; \
			rm -f /sys/fs/bpf/tc/globals/connection_current_pn; \
			rm -f /sys/fs/bpf/tc/globals/connection_pn_translation; \
			rm -f /sys/fs/bpf/tc/globals/connection_unistream_id_translation; \
			rm -f /sys/fs/bpf/tc/globals/client_stream_offset; \
			rm -f /sys/fs/bpf/tc/globals/packets_to_register; \
			rm -f /sys/fs/bpf/tc/globals/index_packets_to_register; \
			rm -f /sys/fs/bpf/tc/globals/pn_ts_storage; \
			rm -f /sys/fs/bpf/tc/globals/index_pn_ts_storage; \
			tc filter del dev ${DEV_EG} egress; \
			tc filter del dev ${DEV_IN} ingress; \
			tc qdisc del dev ${DEV_EG} clsact; \
			tc qdisc del dev ${DEV_IN} clsact; \
		fi; \
		sudo rm -f $(BPF_TC_IN_TO_EG_PINNED_PATH); \
	fi

	@if [ "$(CUR_NS)" = "relay_ns" ]; then \
		if [ -e "$(BPF_TC_IN_TO_EG_OBJ)" ]; then \
			echo "Deleting TC filters for redirection proof of concept"; \
			rm -f $(BPF_TC_IN_TO_EG_OBJ); \
			rm -f ${BPF_TC_IN_TO_EG_OBJ:.o=.ll}; \
			tc filter del dev ${DEV_EG} egress; \
			tc filter del dev ${DEV_IN} ingress; \
			tc qdisc del dev ${DEV_EG} clsact; \
			tc qdisc del dev ${DEV_IN} clsact; \
		fi; \
		sudo rm -f $(BPF_TC_TS_PINNED_PATH); \
	fi

	@if [ "$(CUR_NS)" = "server_ns" ]; then \
		if [ -e "$(BPF_TC_OBJ_TS_ING)" ]; then \
			echo "Deleting TC filters for timestamping (ingress)"; \
			rm -f $(BPF_TC_OBJ_TS_ING); \
			rm -f ${BPF_TC_OBJ_TS_ING:.o=.ll}; \
			tc filter del dev ${TS_DEV_IN} ingress; \
			tc qdisc del dev ${TS_DEV_IN} clsact; \
		fi; \
		if [ -e "$(BPF_TC_OBJ_TS_EG)" ]; then \
			echo "Deleting TC filters for timestamping (egress)"; \
			rm -f $(BPF_TC_OBJ_TS_EG); \
			rm -f ${BPF_TC_OBJ_TS_EG:.o=.ll}; \
		fi; \
	fi
# 	tc filter del dev ${TS_DEV_EG} egress; \ // TODO: only if TS_DEV_EG and TS_DEV_IN are different
# 	tc qdisc del dev ${TS_DEV_EG} clsact; \


	rm -f ${PRIO_DROP_PATH_VIDEO}/build/main
	rm -f ${PRIO_DROP_PATH_CHAT}/build/main
	rm -f ${INGRESS_TO_EGRESS_PATH}/build/main
