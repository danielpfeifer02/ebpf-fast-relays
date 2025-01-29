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
TS_DEV_IN := veth3
TS_DEV_EG := veth0

TC_TS = tc_ts
BPF_TC_TS_PINNED_PATH := /sys/fs/bpf/$(TC_TS)

TC_TS_PATH = tc/performance_analysis
BPF_TC_OBJ_TS_ING = ${TC_TS_PATH}/tc_ts_handling_ingress.o
BPF_TC_OBJ_TS_EG = ${TC_TS_PATH}/tc_ts_handling_egress.o


# This is for the proof of concept that the relay can en- and decrypt on the ebpf level.
# Devices are the same as for the main tc program.
CRYPTO_DEV_IN := veth1
CRYPTO_DEV_EG := veth2
TC_CRYPTO_PATH := tc/crypto
BPF_TC_OBJ_CRYPTO_ING_SERVER := ${TC_CRYPTO_PATH}/tc_ingress_server_side_crypto.o
BPF_TC_OBJ_CRYPTO_EG_CLIENT := ${TC_CRYPTO_PATH}/tc_egress_client_side_crypto.o

XDP_CRYPTO_PATH := xdp
BPF_XDP_OBJ_CRYPTO_ING_SERVER := ${XDP_CRYPTO_PATH}/xdp_ingress_server_side_crypto.o


CUR_NS := $(shell ip netns identify)

# TODO: other way to export PATH
export PATH := $(PATH):/usr/local/go/bin

PRIO_DROP_PATH_VIDEO := ../go/examples/priority_drop_video
PRIO_DROP_PATH_CHAT := ../go/examples/priority_drop_chat
INGRESS_TO_EGRESS_PATH := ../go/examples/ingress_to_egress

.PHONY: clean all tc_main tc_poc tc_ts_in tc_ts_eg chat

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

tc_ts_in: $(BPF_TC_OBJ_TS_ING)
	tc qdisc add dev ${TS_DEV_IN} clsact
	tc filter add dev ${TS_DEV_IN} ingress bpf da obj ${BPF_TC_OBJ_TS_ING} sec ts_ingress
	tc filter show dev ${TS_DEV_IN} ingress

tc_ts_eg: $(BPF_TC_OBJ_TS_EG)
	tc qdisc add dev ${TS_DEV_EG} clsact
	tc filter add dev ${TS_DEV_EG} egress bpf da obj ${BPF_TC_OBJ_TS_EG} sec ts_egress
	tc filter show dev ${TS_DEV_EG} egress

tc_crypto_ig: $(BPF_TC_OBJ_CRYPTO_ING_SERVER)
	tc qdisc add dev ${CRYPTO_DEV_IN} clsact
	tc filter add dev ${CRYPTO_DEV_IN} ingress bpf da obj ${BPF_TC_OBJ_CRYPTO_ING_SERVER} sec crypto_ingress
	tc filter show dev ${CRYPTO_DEV_IN} ingress
	@echo "Added ingress crypto ebpf program"

tc_crypto_eg: $(BPF_TC_OBJ_CRYPTO_EG_CLIENT)
	tc qdisc add dev ${CRYPTO_DEV_EG} clsact
	tc filter add dev ${CRYPTO_DEV_EG} egress bpf da obj ${BPF_TC_OBJ_CRYPTO_EG_CLIENT} sec crypto_egress
	tc filter show dev ${CRYPTO_DEV_EG} egress
	@echo "Added egress crypto ebpf program"

xdp_tag_ig: $(BPF_XDP_OBJ_CRYPTO_ING_SERVER)
	ip link set dev ${CRYPTO_DEV_IN} xdp off
	ip link set dev ${CRYPTO_DEV_IN} xdp obj ${BPF_XDP_OBJ_CRYPTO_ING_SERVER} sec xdp_crypto	
	@echo "Added ingress crypto ebpf program"

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

# Crypto programs compilation
$(BPF_TC_OBJ_CRYPTO_ING_SERVER): ${TC_CRYPTO_PATH}/%.o: ${TC_CRYPTO_PATH}/%.c
	clang -S \
		-Dveth2_egress_ifindex=${DEV_EG_INDEX} \
		-g \
		-target bpf \
	  -I../../libbpf/src\
	  -I../../iproute2/include\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}

$(BPF_TC_OBJ_CRYPTO_EG_CLIENT): ${TC_CRYPTO_PATH}/%.o: ${TC_CRYPTO_PATH}/%.c
	clang -S \
		-g \
		-target bpf \
	  -I../../libbpf/src\
	  -I../../iproute2/include\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}

# XDP version to see if that helps with verifier issues
$(BPF_XDP_OBJ_CRYPTO_ING_SERVER): ${XDP_CRYPTO_PATH}/%.o: ${XDP_CRYPTO_PATH}/%.c
	clang -H -S \
		-Dveth2_egress_ifindex=${DEV_EG_INDEX} \
		-g \
		-target bpf \
	  -I../../libbpf/src\
	  -I../../iproute2/include\
	  -I./vmlinux.h\
		-Wall \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -O2 -o $@ ${@:.o=.ll}

clean:

	@echo $(CUR_NS)
#	TODO: actually not needed to delete all maps individually, just clear the folder
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
			rm -f /sys/fs/bpf/tc/globals/connection_unistream_id_counter; \
			rm -f /sys/fs/bpf/tc/globals/connection_unistream_id_translation; \
			rm -f /sys/fs/bpf/tc/globals/client_stream_offset; \
			rm -f /sys/fs/bpf/tc/globals/packets_to_register; \
			rm -f /sys/fs/bpf/tc/globals/index_packets_to_register; \
			rm -f /sys/fs/bpf/tc/globals/pn_ts_storage; \
			rm -f /sys/fs/bpf/tc/globals/index_pn_ts_storage; \
			rm -f /sys/fs/bpf/tc/globals/unistream_id_is_retransmission; \
			rm -f /sys/fs/bpf/tc/globals/packet_events; \
			rm -f /sys/fs/bpf/tc/globals/*; \
			tc filter del dev ${DEV_EG} egress; \
			tc filter del dev ${DEV_IN} ingress; \
			tc qdisc del dev ${DEV_EG} clsact; \
			tc qdisc del dev ${DEV_IN} clsact; \
		fi; \
		sudo rm -f $(BPF_TC_IN_TO_EG_PINNED_PATH); \
		if [ -e "$(BPF_TC_OBJ_CRYPTO_ING_SERVER)" ]; then \
			echo "Deleting TC filters for crypto"; \
			rm -f $(BPF_TC_OBJ_CRYPTO_ING_SERVER); \
			rm -f ${BPF_TC_OBJ_CRYPTO_ING_SERVER:.o=.ll}; \
			rm -f /sys/fs/bpf/tc/globals/*; \
			tc filter del dev ${CRYPTO_DEV_IN} ingress; \
			tc qdisc del dev ${CRYPTO_DEV_IN} clsact; \
		fi; \
		if [ -e "$(BPF_TC_OBJ_CRYPTO_EG_CLIENT)" ]; then \
			echo "Deleting TC filters for crypto"; \
			rm -f $(BPF_TC_OBJ_CRYPTO_EG_CLIENT); \
			rm -f ${BPF_TC_OBJ_CRYPTO_EG_CLIENT:.o=.ll}; \
			rm -f /sys/fs/bpf/tc/globals/*; \
			tc filter del dev ${CRYPTO_DEV_EG} egress; \
			tc qdisc del dev ${CRYPTO_DEV_EG} clsact; \
		fi; \
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

	@if [ "$(CUR_NS)" = "client_ns" ]; then \
		if [ -e "$(BPF_TC_OBJ_TS_ING)" ]; then \
			echo "Deleting TC filters for timestamping (ingress)"; \
			rm -f $(BPF_TC_OBJ_TS_ING); \
			rm -f ${BPF_TC_OBJ_TS_ING:.o=.ll}; \
			tc filter del dev ${TS_DEV_IN} ingress; \
			tc qdisc del dev ${TS_DEV_IN} clsact; \
		fi; \
		rm -f /sys/fs/bpf/tc/globals/*; \
	fi
#	TODO: make a more general way of deleting them independently of the namespace
	@if [ "$(CUR_NS)" = "server_ns" ]; then \
		if [ -e "$(BPF_TC_OBJ_TS_EG)" ]; then \
			echo "Deleting TC filters for timestamping (egress)"; \
			rm -f $(BPF_TC_OBJ_TS_EG); \
			rm -f ${BPF_TC_OBJ_TS_EG:.o=.ll}; \
			tc filter del dev ${TS_DEV_EG} egress; \
			tc qdisc del dev ${TS_DEV_EG} clsact; \
		fi; \
		rm -f /sys/fs/bpf/tc/globals/*; \
	fi


#	Potentially add to avoid problems with using same interfaces for different purposes
# 	if [ "$(TS_DEV_IN)" != "$(TS_DEV_EG)" ]; then \
# 		tc filter del dev ${TS_DEV_EG} egress; \
# 		tc qdisc del dev ${TS_DEV_EG} clsact; \
# 	fi; \


	rm -f ${PRIO_DROP_PATH_VIDEO}/build/main
	rm -f ${PRIO_DROP_PATH_CHAT}/build/main
	rm -f ${INGRESS_TO_EGRESS_PATH}/build/main

	rm -f ${XDP_CRYPTO_PATH}/*.ll
	rm -f ${XDP_CRYPTO_PATH}/*.o
