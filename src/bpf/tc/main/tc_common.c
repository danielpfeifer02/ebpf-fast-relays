#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include "tc_frame_length_lut.c"

// In case the checksum should be recomputed when using
// bpf_skb_store_bytes(...) the flag BPF_F_RECOMPUTE_CSUM
// can be used.

// Definition of BPF section
#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

// This is just to suppress the IDE warnings about the
// missing symbol of veth2_egress_ifindex.
// The symbol is defined in the Makefile
// so this case should never be reached.
#ifndef veth2_egress_ifindex
# define veth2_egress_ifindex 0
#endif

// ++++++++++++++++++ CONFIG DEFINITIONS ++++++++++++++++++ //

// The ingress to egress redirection happens from the veth1 interface to the veth2 interface.
// For that the program needs to know the ifindex of the veth2 interface. 
// This will be defined in the Makefile
// since the ifindex can change and has
// to be read from the system.
// #define veth2_egress_ifindex ??

// The connection id length will always be 16 bytes since the underlying QUIC library
// is expected to use a fixed length connection id. This is just for convenience since
// otherwise the bpf program would need to keep state on how long the connection id is.
#define CONN_ID_LEN 16

// The MAC length is always 6 bytes.
#define MAC_LEN 6

// Restrictions regarding number of clients as well as the number of streams per client
// and number of storable packet number translations.
// These have been arbitrarily chosen and can be adjusted.
#define MAX_CLIENTS 1024
#define MAX_STREAMS_PER_CLIENT 1024
// Since the packet number translations are deleted by the userspace program
// 1024 might not even be necessary and this could be lowered.
#define MAX_PN_TRANSLATIONS 1 << 15 // 32768 // TODO: what size is sufficient?
// The same goes for the unistream id translations.
// This is necessary since the IDs also have to be unique even if
// the relay and the forwarding mechanism open streams at the same time.
// Therefore translate in the relay.
#define MAX_UNISTREAM_ID_TRANSLATIONS 1<<15 // 32768 // TODO: what size is sufficient?
// This stores the maximum number of ids stores at the same
// time to identify them as being part of a retransmission.
#define MAX_RETRANSMISSION_IDS_STORED 1<<15 // 32768 // TODO: what size is sufficient? (why are the entries not properly deleted?)
// The maximum number of frames that are expected to be in a packet.
// For now this is just an arbitrary number and can be adjusted.
// Not sure if there is any limit defined in the QUIC standard.
#define MAX_FRAMES_PER_PACKET 16
// The maximum number of packets in the queue that have to be registered
#define MAX_REGISTER_QUEUE_SIZE 1<<15 // 32768 // TODO: what size is sufficient?
// The maximum number of pairs of packet number and timestamp that can be stored
// for RTT calculations.
#define MAX_PN_TS_PAIRS 1<<15 // 32768 // TODO: what size is sufficient?

// Ports are used to identify the QUIC connection. The relay will always use the same port
// which is also used in the userspace program (i.e. should be changed with care).
#define RELAY_PORT htons(4242)
#define SERVER_PORT htons(4242)
#define PORT_MARKER htons(6969)

// These markers tell if a unistream originates from the relay or the media server.
#define RELAY_ORIGIN 1
#define MEDIA_SERVER_ORIGIN 2

// For now only stream and datagram frames are supported.
#define IS_STREAM_FRAME(x) ((x) >= 0x08 && (x) <= 0x0f)
#define IS_DATAGRAM_FRAME(x) ((x) >= 0x30 && (x) <= 0x31)
#define SUPPORTED_FRAME(x) (IS_STREAM_FRAME(x) || IS_DATAGRAM_FRAME(x))

// The IP header checksum offset is always the same.
// We need this to adapt the checksum when changing the packet
// since otherwise the client would discard the packet.
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

// These define the offsets of the timestamps inside a performance analysis
// payload used to measure the impact of direct forwarding at the relay.
// This offset is relative TO THE START OF THE STREAM DATA!
// Something else is not possible since there are variable length integers
// ahead of the timestamp.
#define TS_OFF_EGRESS 5
#define TS_OFF_INGRESS 13

// When reading variable length integers we can provide info if the value 
// is needed or not. This can provide a small performance improvement.
#define NO_VALUE_NEEDED 0
#define VALUE_NEEDED 1

// These definitions are mostly used for development purposes.
#define TURNOFF 0
#define TURNOFF_INGRESS_FORWARDING 0
#define PRIO_DROP 1
#define MOQ_PAYLOAD 1
#define VP8_VIDEO_PAYLOAD 1
#define SINGLE_STREAM_USAGE 0

// A definition to avoid having to check the return value of a probe read
// manually all the time. This cannot be a wrapper since in case of an error
// we want to return TC_ACT_OK.
#define CONCAT(a, b) a##b
#define LINE_EXPAND(a, b) CONCAT(a, b)
#define UNQ_NAME(name) LINE_EXPAND(name, __LINE__)

#define SAVE_BPF_PROBE_READ_KERNEL(dest, size, ptr)                     \
        long UNQ_NAME(unq_) = bpf_probe_read_kernel(dest, size, ptr);   \
        if (UNQ_NAME(unq_) < 0) {                                       \
                bpf_printk("Failed to read memory!\n");                 \
                return TC_ACT_OK;                                       \
        }                                                           


// ++++++++++++++++++ STRUCT DEFINITIONS ++++++++++++++++++ //

// This key is used to make sure that we can check if a client is already in the map
// it is not meant to be known for fan-out purposes since there we will just go over
// all map entries in a linear fashion.
struct client_info_key_t {
        uint32_t ip_addr;
        uint16_t port;
        uint8_t padding[2];
};

// This struct is used to store the client information in the map.
// The priority drop limit will be the smallest priority that the
// client is **still accepting**. 
struct client_info_t {
        uint8_t src_mac[MAC_LEN];
        uint8_t dst_mac[MAC_LEN];
        uint32_t src_ip_addr;
        uint32_t dst_ip_addr;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t connection_id[CONN_ID_LEN];
        uint8_t priority_drop_limit;
};

// This struct is used to resemble a packet number value.
// TODO: Adapt packet_number to be a larger integer type
// TODO: since the standard allows values > 16 bit.
struct pn_value_t {
        uint16_t packet_number;
        uint8_t changed;
        uint8_t padding[3];
};

// This struct is used to store the value of a variable length integer
// as well as the **minimum** length (in bytes) it needs within the QUIC
// packet to be stores correctly (i.e. with the variable length integer
// encoding).
struct var_int {
        uint64_t value;
        uint8_t len; 
};

// Struct that represents the key for the map
// containing the packet number translations.
struct client_pn_map_key_t {
        struct client_info_key_t key;
        uint32_t packet_number;
};

// This struct servers for the retransmission check of unidirectional stream ids.
struct client_unistream_id_pair_t {
        struct client_info_key_t key;
        uint64_t unistream_id;
};

// Struct that represents the key for the map
// containing the unistream id translations.
struct client_unistream_id_lookup_key_t {
        struct client_unistream_id_pair_t key;
        uint8_t unistream_origin;
        uint8_t padding[7];
};

// Struct that represents the key for the map
// containing the stream offsets.
struct client_stream_offset_key_t {
        struct client_info_key_t key;
        uint32_t stream_id;
};

// Struct that represents a packet that has to be registered
// by the userspace program.
struct register_packet_t { // TODO: what fields are necessary?
        uint64_t packet_number;
        uint64_t timestamp;
        uint64_t length;

        uint32_t server_pn;

        uint8_t valid;
        uint8_t non_userspace;
        uint8_t padding[2];
};

// This struct represents an entry in the ring buffer storing
// packet-number / timestamp pairs.
struct ps_ts_pair_t {
        uint32_t packet_number;
        uint32_t ip_addr;
        uint64_t timestamp;
        uint16_t port;
        uint8_t valid;
        uint8_t padding[5];
}; 

// ++++++++++++++++++ BPF MAP DEFINITIONS ++++++++++++++++++ //

// Map for storing client information
// (e.g. mac, ip, port, connection id).
// The key will be an integer id so that
// we can easily iterate over all clients
// within the egress bpf program (since we
// do not know the client id at this point).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, struct client_info_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_data SEC(".maps");

// This map is used to get the client id
// based on the client_info_key_t.
// TODO: how to handle deletion of clients?
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, uint32_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_id SEC(".maps");

// This map will be used to update the packet
// number of a client after the bpf program
// sent out packets which are unknown to the
// user-space program.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, struct pn_value_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_pn SEC(".maps");

// This map is used to get the number of clients
// this will only be changed by the userspace program
// since handling connection establishment in bpf
// is more complex. 
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} number_of_clients SEC(".maps");

// This map is used to get the next client id
// that will identify a client in the client_data.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} id_counter SEC(".maps");

// This map can be used to delay the start of the bpf
// program considering a new client. This can be useful
// in case some setup would need to be done before the
// client is fully operational.
// TODO: might now be needed because of "number of clients"?
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, uint8_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_established SEC(".maps");

// This map saves the first packet number that is
// free to use for a new packet. 
// This is used when doing packet number translations. 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, uint32_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_current_pn SEC(".maps");

// This map is storing how a packet number was translated.
// The userspace program will use this to retranslate the
// packet number. It will also delete any entries that are
// not needed anymore to keep the map from overflowing.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_pn_map_key_t);
    __type(value, uint32_t);
    __uint(max_entries, MAX_PN_TRANSLATIONS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_pn_translation SEC(".maps");

// This map acts as the counter for the next unidirectional stream id.
// This is needed since the Media Server and the Relay both might open
// uni-directional streams and the stream ids have to be unique.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, uint64_t);
    __uint(max_entries, MAX_UNISTREAM_ID_TRANSLATIONS); // TODO: separate size?
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_unistream_id_counter SEC(".maps");

// This map is used to be able to lookup if a unidirectional stream id
// already has been translated.
// This is needed to avoid translating the same stream id multiple times.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_unistream_id_lookup_key_t);
    __type(value, uint64_t);
    __uint(max_entries, MAX_UNISTREAM_ID_TRANSLATIONS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_unistream_id_translation SEC(".maps");

// This map is used to store the current offset within a stream.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_stream_offset_key_t);
    __type(value, struct var_int);
    __uint(max_entries, MAX_CLIENTS * MAX_STREAMS_PER_CLIENT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_stream_offset SEC(".maps");

// This map is used to store the packets that have to be registered
// by the userspace program. This is necessary to allow the congestion
// control to work correctly.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct register_packet_t);
    __uint(max_entries, MAX_REGISTER_QUEUE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packets_to_register SEC(".maps");

// This map is used to store the index of the next packet that has to be registered.
// The "packet_to_register" map is a used as a ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} index_packets_to_register SEC(".maps");

// This map can be used to get RTT info.
// It can store a packet-number and a timestamp.
// The packet-number is used to identify the packet
// and the timestamp tells when it was sent/received.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct ps_ts_pair_t);
    __uint(max_entries, MAX_PN_TS_PAIRS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pn_ts_storage SEC(".maps");

// This map stores an index to the next free slot in the
// "pn_ts_storage" map.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} index_pn_ts_storage SEC(".maps");

// This map stores if the unirectional stream id is part of a retransmission 
// by the relay. This is needed when updating the stream id to make sure that 
// retransmission do not get a new stream id when they should reuse the old one
// (they would potentially get a new one since the origin of the stream differs).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_unistream_id_pair_t);
    __type(value, uint8_t);
    __uint(max_entries, MAX_RETRANSMISSION_IDS_STORED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} unistream_id_is_retransmission SEC(".maps");

// This is used to signal events (mainly arrival of a new packet to register) to 
// the userspace program.
struct {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, (1 << 15));
__uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_events SEC(".maps");
// const char* packet_events_pin_path = "/sys/fs/bpf/tc/packet_events";


// ++++++++++++++++++ FUNCTION DEFINITIONS ++++++++++++++++++ //


// Storing a packet to register in the ring buffer which allows for more efficient 
// communication with the userspace program.
__attribute__((always_inline)) int32_t store_packet_to_register_rb(struct register_packet_t packet) {

        // TODO: how to signal to packet_events 
        struct register_packet_t *data = bpf_ringbuf_reserve(&packet_events, sizeof(struct register_packet_t), 0); // TODO: check flags for waking up / not waking up
        if (!data)
                return 0;
        *data = packet;
        bpf_ringbuf_submit(data, 0); // TODO: check correct flags for wake up 8https://stackoverflow.com/questions/74092376/regarding-the-ebpf-question-bpf-ringbuf-submit-is-not-in-effect)
        return 0;
}

// Update the stream id of a packet.
__attribute__((always_inline)) int32_t update_stream_id(struct var_int stream_id, void *skb, uint32_t stream_id_off, struct client_info_key_t *key, uint8_t unistream_origin) {

        // return 0;
        if (skb==NULL || key==NULL) {
                bpf_printk("Invalid arguments for update_stream_id\n");
                return 1;
        }

        struct client_unistream_id_pair_t stream_id_key = {
                .key = *key,
                .unistream_id = stream_id.value
        };

        // uint64_t ts = bpf_ktime_get_tai_ns();
        // if (unistream_origin == RELAY_ORIGIN) {
        //         bpf_printk("Relay origin for %d %lu\n", stream_id.value, ts);
        // } else {
        //         bpf_printk("Media server origin for %d %lu\n", stream_id.value, ts);
        // }

        // In case the origin is the relay userspace we need to check if it is a retransmission of a packet.
        // If it is a retransmission we can find out by checking the translation map with the origin set to
        // the media server. If there is an entry with it we know the media server has snet out on a unidirectional
        // stream with the same stream id. This does not necessarly mean that the relay is not just coincidentally
        // at the same stream id counter though. That's why we need to use a different map where the relay sets the 
        // stream id to be a retransmission explicitly. That way we can rule out accidental reusage of the same stream id.
        if (unistream_origin == RELAY_ORIGIN) {

                uint8_t *is_retransmission = bpf_map_lookup_elem(&unistream_id_is_retransmission, &stream_id_key);
                if (is_retransmission != NULL && *is_retransmission == 1) {
                        bpf_printk("Retransmission detected\n");
                        unistream_origin = MEDIA_SERVER_ORIGIN;
                        bpf_map_delete_elem(&unistream_id_is_retransmission, &stream_id.value); // TODO: seems to not work?
                } else {
                        bpf_printk("Nothing detected for %d %d %d\n", key->ip_addr, key->port, stream_id.value);
                }


                // TODO: isn't the stream id already correct in case of a retransmission?
                // TODO: is the packet registering process working properly regarding stream id (i.e. not, for exmple, storing before adapting stream id)?
                // TODO: check with caching to make sure that the stream id in the wire.frame matches the one we actually want.
                // TODO:        StoreServerPacket(...) in cache_common.go (A_MoQ code) is called in connection.go (prio-packs code)
                // TODO:        and does store the raw short header data the relay gets from the server. 
                // TODO:        -> the stream_id should be set correctly by just changing the origin.
        }

        struct client_unistream_id_lookup_key_t unistream_key = {
                .key = stream_id_key,
                // TODO: how to handle retranmissions that come from the relay but should be sent with a stream id of the media server?
                .unistream_origin = unistream_origin
        };

        // TODO: maybe egress does not identify relay- / server-sent packets correctly 

        uint64_t *translation = bpf_map_lookup_elem(&connection_unistream_id_translation, &unistream_key);
        
        // These are only needed if the stream id is not already translated.
        // They need to be out here to avoid problems with out of scope variables.
        uint64_t *new_stream_id;
        uint64_t initial = 0b11; // 0b11 == unidirectional and server initiated.

        // If not already translated, translate it.
        if (translation == NULL) {
                new_stream_id = bpf_map_lookup_elem(&connection_unistream_id_counter, key);
                
                if (new_stream_id == NULL) {
                        bpf_printk("No unidirectional stream id found\n");
                        bpf_map_update_elem(&connection_unistream_id_counter, key, &initial, BPF_ANY);
                        new_stream_id = &initial;
                }

                // TODO: this map needs to be cleaned at some point?
                int unistr_ret = bpf_map_update_elem(&connection_unistream_id_translation, &unistream_key, new_stream_id, BPF_ANY); 
                // TODO: In case the map update is actually to slow -> maybe use the return value + BPF_NOEXIST to avoid the problem?

                // Do not touch the two least significant bits since they inicate stream type.
                uint64_t next_stream_id = *new_stream_id + 0b100;
                bpf_map_update_elem(&connection_unistream_id_counter, key, &next_stream_id, BPF_ANY);

                translation = new_stream_id;

                // TODO: somehow the video does not play correcty is this print is not there. I assume this is because of the map update
                // TODO: takes until the next packet is already being processed and this one then accesses old data?
                // TODO: using 5 * "%d" seems to be necessary since for 4 * "%d" it still does not work.
                bpf_printk("Unidirectional stream id mapping registered from %d to %d (%d %d %d)\n", stream_id.value, *new_stream_id, key->ip_addr, key->port, unistream_origin); 

        } 

        // Store new_stream_id in the packet.
        // TODO: for now userspace is expected to always use 8 byte stream ids
        uint8_t new_stream_id_bytes[8] = {0};
        for (int i=0; i<8; i++) {
                new_stream_id_bytes[i] = (*translation >> (56 - 8 * i)) & 0xff;
        }
        // Check that only 62 bits are used.
        if (new_stream_id_bytes[0] & 0xc0) {
                bpf_printk("Stream id too large\n");
                return 1;
        }
        // Set length.
        new_stream_id_bytes[0] |= 0xc0;
        // TODO: make size 8 a constant in config.
        bpf_skb_store_bytes(skb, stream_id_off, new_stream_id_bytes, 8, 0);
        bpf_printk("Unidirectional stream id updated from %d to %d (%d)\n", stream_id.value, *translation, unistream_origin);

        return 0;
}

// Store packet-number and timestamp for potential RTT calculation.
__attribute__((always_inline)) int32_t store_pn_and_ts(uint32_t packet_number, uint64_t timestamp, uint32_t ip_addr, uint16_t port) {

        uint32_t zero = 0;
        uint32_t *index = bpf_map_lookup_elem(&index_pn_ts_storage, &zero);
        if (index == NULL) {
                bpf_printk("Failed to get index for pn-ts storage\n");
                return 1;
        }
        struct ps_ts_pair_t pair = {
                .packet_number = packet_number,
                .ip_addr = ip_addr,
                .timestamp = timestamp,
                .port = port,
                .valid = 1
        };
        bpf_map_update_elem(&pn_ts_storage, index, &pair, BPF_ANY);

        *index = *index + 1;
        if (*index == MAX_PN_TS_PAIRS) { // TODO: why modulo not working?
                *index = 0;
        }
        bpf_map_update_elem(&index_pn_ts_storage, &zero, index, BPF_ANY);

        return 0;
}

// This function is used to store a packet that has to be registered
// by the userspace program.
__attribute__((always_inline)) int32_t store_packet_to_register(struct register_packet_t packet) { // TODO: need to consider ip and port to support multiple clients

        bpf_printk("Storing packet to register with pn %d\n", packet.packet_number);
        // TODO: just for testing
        store_packet_to_register_rb(packet);
        return 0;

        // TODO: remove usage of normal map
        uint32_t zero = 0;
        uint32_t *index = bpf_map_lookup_elem(&index_packets_to_register, &zero);
        if (index == NULL) {
                bpf_printk("Failed to get index for packets to register\n");
                return 1;
        }
        bpf_map_update_elem(&packets_to_register, index, &packet, BPF_ANY);

        // bpf_printk("Storing packet to register with pn %d at index %d\n", packet.packet_number, *index);

        *index = *index + 1;
        if (*index == MAX_REGISTER_QUEUE_SIZE) { // TODO: why modulo not working?
                *index = 0;
        }
        bpf_map_update_elem(&index_packets_to_register, &zero, index, BPF_ANY);

        return 0;
}

// This function is necessary to satisfy the verifier as it does treat
// the lengths saved in the variable integer struct as unbounded.
__attribute__((always_inline)) uint8_t bounded_var_int_len(uint8_t var_int_len) {
        if (var_int_len == 1) {
                return 1;
        }
        if (var_int_len == 2) {
                return 2;
        }
        if (var_int_len == 4) {
                return 4;
        }
        if (var_int_len == 8) {
                return 8;
        }
        return 0;
}

// This function is used to read a variable length integer from a buffer.
// The variable length integer is expected to use the encoding described in 
// RFC9000:
// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
__attribute__((always_inline)) int read_var_int(void *start, struct var_int *res, uint8_t need_value) {

        uint8_t len;
        SAVE_BPF_PROBE_READ_KERNEL(&len, sizeof(len), start);
        len = 1 << (len >> 6);

        res->len = bounded_var_int_len(len);

        if (need_value == NO_VALUE_NEEDED) {
                return 0;
        }

        uint8_t byte;

        if (len >= 1) {
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start);
                res->value = byte & 0x3f;
        }
        if (len >= 2) {
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start + 1);
                res->value = (res->value << 8) | byte;
        }
        if (len >= 4) {
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start + 2);
                res->value = (res->value << 8) | byte;
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start + 3);
                res->value = (res->value << 8) | byte;
        }
        if (len >= 8) {
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start + 4);
                res->value = (res->value << 8) | byte;
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start + 5);
                res->value = (res->value << 8) | byte;
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start + 6);
                res->value = (res->value << 8) | byte;
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), start + 7);
                res->value = (res->value << 8) | byte;
        }
        return 0;
}

// This function determines the minimal number of bytes needed to encode
// a variable length integer as described in RFC9000:
// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
// The return value is already given in the encoding specified above.
__attribute__((always_inline)) uint8_t determine_minimal_length_encoded(uint64_t value) {
        if (value <= 63) {
                return 0b00;
        }
        if (value <= 16383) {
                return 0b01;
        }
        if (value <= 1073741823) {
                return 0b10;
        }
        if (value <= 4611686018427387903) {
                return 0b11;
        }
        return 0b100;
}

// This function returns the start of the QUIC stream frame
// or NULL if the payload of the packet does not contain
// a QUIC stream frame.
// This would be the optimal way to handle packets from the bpf
// program but this approach seems to be too complex for the verifier.
// Therefore the underlying QUIC library is expected to send supported
// frams in separate packets for easy handling within bpf.
__attribute__((always_inline)) int32_t get_stream_frame_start(void *payload, uint32_t payload_length, void **stream_frame_start) {

        // Normally this would be a while loop but one could assume that
        // a frame does not have a huge amount of different frame within
        // it.
        for (int frame_ctr=0; frame_ctr<MAX_FRAMES_PER_PACKET; frame_ctr++) {
                // TODO: special cases e.g. NEW_TOKEN_FRAME with skipping token
                // TODO: still not considered.
                uint8_t byte;
                SAVE_BPF_PROBE_READ_KERNEL(&byte, sizeof(byte), payload);

                if (IS_STREAM_FRAME(byte)) {
                        *stream_frame_start = payload;
                        return 1;
                }

                payload++;

                // Read how many var ints are in the frame.
                uint8_t var_ints = get_number_of_var_ints_of_frame(byte);
                if (var_ints == INVALID_FRAME) {
                        *stream_frame_start = NULL;
                        return 0;
                }

                // Starting at 1 since the type is also a var int
                // but already read at this point.
                for (int i=1; i<var_ints; i++) {
                        if (i == var_ints) {
                                break;
                        }
                        struct var_int res;
                        if (i != 3 || (byte != ACK_FRAME && byte != ACK_ECN_FRAME)) {
                                read_var_int(payload, &res, NO_VALUE_NEEDED);
                        } else {
                                // In case the frame is an ACK frame we need to 
                                // find out how many ACK ranges there are (fourth var int
                                // is the number of ACK ranges) and add 2 var ints for each
                                // ACK range present.
                                read_var_int(payload, &res, VALUE_NEEDED);
                                var_ints += 2 * res.value;
                        }
                        payload += bounded_var_int_len(res.len);
                }

        } // while (payload < payload + payload_length);

        *stream_frame_start = NULL;
        return 0;
}

char __license[] __section("license") = "GPL";