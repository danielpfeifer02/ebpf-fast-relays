#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>

// https://github.com/iproute2/iproute2.git

// bpf_skb_store_bytes flag for CSUM: BPF_F_RECOMPUTE_CSUM


#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#define veth2_egress_ifindex 13 // ! TODO: how to handle better and avoid manual configuration?
#define CONN_ID_LEN 16
#define MAC_LEN 6
#define MAX_CLIENTS 1024
#define MAX_STREAMS_PER_CLIENT 16
#define MAX_PN_TRANSLATIONS 1024 //1<<16 // TODO: what size? how to delete entries?

// TODO: why is 4242 observable in WireShark and 6969 not?
#define RELAY_PORT htons(4242)
#define SERVER_PORT htons(4242)
#define PORT_MARKER htons(6969)

#define IS_STREAM_FRAME(x) ((x) >= 0x08 && (x) <= 0x0f)
#define IS_DATAGRAM_FRAME(x) ((x) >= 0x30 && (x) <= 0x31)
#define SUPPORTED_FRAME(x) (IS_STREAM_FRAME(x) || IS_DATAGRAM_FRAME(x))

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

#define NO_VALUE_NEEDED 0
#define VALUE_NEEDED 1

#define TURNOFF 0
#define PRIO_DROP 0
#define MOQ_PAYLOAD 1
#define VP8_VIDEO_PAYLOAD 1
#define SINGLE_STREAM_USAGE 0

// this key is used to make sure that we can check if a client is already in the map
// it is not meant to be known for fan-out purposes since there we will just go over
// all map entries
struct client_info_key_t {
        uint32_t ip_addr;
        uint16_t port;
        uint8_t padding[2];
};

struct client_info_t {
        uint8_t src_mac[MAC_LEN];
        uint8_t dst_mac[MAC_LEN];
        uint32_t src_ip_addr;
        uint32_t dst_ip_addr;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t connection_id[CONN_ID_LEN];
        uint8_t priority_drop_limit; // this is the smallest priority that is still accepted
};

struct pn_value_t {
        // TODO: assume only 16 bit pn for now
        uint16_t packet_number;
        uint8_t changed;
        uint8_t padding[3];
};

// map for storing client information
// i.e. mac, ip, port, connection id
// key will be an integer id so that
// we can easily iterate over all clients
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, struct client_info_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_data SEC(".maps");

// this map is used to get the client id
// based on the client_info_key_t
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, uint32_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_id SEC(".maps");

// this map will be used to update the packet
// number of a client after the bpf program
// sent out packets which are unknown to the
// user-space program
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, struct pn_value_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_pn SEC(".maps");

// this map is used to get the number of clients
// this will be set mainly from userspace
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} number_of_clients SEC(".maps");

// this map is used to get the next client id
// TODO: keeping this consistent will likely happen
// TODO: in userspace
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} id_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, uint8_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_established SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_info_key_t);
    __type(value, uint32_t);
    __uint(max_entries, MAX_CLIENTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_current_pn SEC(".maps");

struct client_pn_map_key_t {
        struct client_info_key_t key;
        uint32_t packet_number;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_pn_map_key_t);
    __type(value, uint32_t);
    __uint(max_entries, MAX_PN_TRANSLATIONS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_pn_translation SEC(".maps");

struct client_stream_offset_key_t {
        struct client_info_key_t key;
        uint32_t stream_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_stream_offset_key_t);
    __type(value, struct var_int);
    __uint(max_entries, MAX_CLIENTS * MAX_STREAMS_PER_CLIENT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_stream_offset SEC(".maps");

struct var_int {
        uint64_t value;
        // len for saved values in the stream offset map provide the MINIMAL length of value in bytes
        uint8_t len; 
};

// to satisfy the verifier
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


// TODO: not working -> fix
__attribute__((always_inline)) int read_var_int(void *start, struct var_int *res, uint8_t need_value) {

        // uint64_t result = 0;
        // uint8_t byte;
        // bpf_probe_read_kernel(&byte, sizeof(byte), start);
        // uint8_t len = 1 << (byte >> 6);
        // bpf_printk("Stream %d %d", len, byte >> 6);
        // result = byte & 0x3f; 

        // if (need_value == NO_VALUE_NEEDED) {
        //         res->value = 0;
        //         res->len = len;
        //         return;
        // }

        // for (int i=1; i<8; i++) {
        //         if (i >= len) {
        //                 break;
        //         }
        //         result = result << 8;
        //         bpf_probe_read_kernel(&byte, sizeof(byte), start + i);
        //         result = result | byte;
        // }
        // res->value = result;
        // res->len = len;

        uint8_t len;
        bpf_probe_read_kernel(&len, sizeof(len), start);
        len = 1 << (len >> 6);

        res->len = bounded_var_int_len(len);

        uint8_t byte;

        if (len >= 1) {
                bpf_probe_read_kernel(&byte, sizeof(byte), start);
                res->value = byte & 0x3f;
        }
        if (len >= 2) {
                bpf_probe_read_kernel(&byte, sizeof(byte), start + 1);
                res->value = (res->value << 8) | byte;
        }
        if (len >= 4) {
                bpf_probe_read_kernel(&byte, sizeof(byte), start + 2);
                res->value = (res->value << 8) | byte;
                bpf_probe_read_kernel(&byte, sizeof(byte), start + 3);
                res->value = (res->value << 8) | byte;
        }
        if (len >= 8) {
                bpf_probe_read_kernel(&byte, sizeof(byte), start + 4);
                res->value = (res->value << 8) | byte;
                bpf_probe_read_kernel(&byte, sizeof(byte), start + 5);
                res->value = (res->value << 8) | byte;
                bpf_probe_read_kernel(&byte, sizeof(byte), start + 6);
                res->value = (res->value << 8) | byte;
                bpf_probe_read_kernel(&byte, sizeof(byte), start + 7);
                res->value = (res->value << 8) | byte;
        }
        return 0;
}

// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
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


#define PADDING_FRAME 0x00
#define PING_FRAME 0x01
#define ACK_FRAME 0x02
#define ACK_ECN_FRAME 0x03
#define RESET_STREAM_FRAME 0x04
#define STOP_SENDING_FRAME 0x05
#define CRYPTO_FRAME 0x06
#define NEW_TOKEN_FRAME 0x07

#define STREAM_FRAME 0x08
#define OFF_BIT 0x04
#define LEN_BIT 0x02
#define FIN_BIT 0x01
#define STREAM_WITH_OFF (STREAM_FRAME | OFF_BIT)
#define STREAM_WITH_LEN (STREAM_FRAME | LEN_BIT)
#define STREAM_WITH_FIN (STREAM_FRAME | FIN_BIT)
#define STREAM_WITH_OFF_LEN (STREAM_FRAME | OFF_BIT | LEN_BIT)
#define STREAM_WITH_OFF_FIN (STREAM_FRAME | OFF_BIT | FIN_BIT)
#define STREAM_WITH_LEN_FIN (STREAM_FRAME | LEN_BIT | FIN_BIT)
#define STREAM_WITH_OFF_LEN_FIN (STREAM_FRAME | OFF_BIT | LEN_BIT | FIN_BIT)

#define MAX_DATA_FRAME 0x10
#define MAX_STREAM_DATA_FRAME 0x11
#define DATA_BLOCKED_FRAME 0x14
#define STREAM_DATA_BLOCKED_FRAME 0x15
#define NEW_CONNECTION_ID_FRAME 0x18
#define RETIRE_CONNECTION_ID_FRAME 0x19
#define PATH_CHALLENGE_FRAME 0x1a
#define PATH_RESPONSE_FRAME 0x1b
#define HANDSHAKE_DONE_FRAME 0x1e

#define INVALID_FRAME 0xff

// https://datatracker.ietf.org/doc/html/rfc9000#frames
uint8_t get_number_of_var_ints_of_frame(uint64_t frame_id) {
        switch (frame_id) {
                /*
                PADDING Frame {
                  Type (i) = 0x00,
                }
                */
                case PADDING_FRAME:
                        return 1;

                /*
                PING Frame {
                  Type (i) = 0x01,
                }
                */
                case PING_FRAME:
                        return 1;

                /*
                ACK Frame {
                  Type (i) = 0x02..0x03,
                  Largest Acknowledged (i),
                  ACK Delay (i),
                  ACK Range Count (i),
                  First ACK Range (i),
                  ACK Range (..) ...,
                  [ECN Counts (..)],
                }
                ACK Range {
                  Gap (i),
                  ACK Range Length (i),
                }
                ECN Counts {
                  ECT0 Count (i),
                  ECT1 Count (i),
                  ECN-CE Count (i),
                }
                */
                case ACK_FRAME:
                        return 5;
                case ACK_ECN_FRAME: 
                        return 8; //TODO: ACK Range (has two varints) and ECN Counts (has three varints???
                
                /*
                RESET_STREAM Frame {
                  Type (i) = 0x04,
                  Stream ID (i),
                  Application Protocol Error Code (i),
                  Final Size (i),
                }
                */
                case RESET_STREAM_FRAME:
                        return 4;
                
                /*
                STOP_SENDING Frame {
                  Type (i) = 0x05,
                  Stream ID (i),
                  Application Protocol Error Code (i),
                }
                */
                case STOP_SENDING_FRAME:
                        return 3;
                
                /*
                CRYPTO Frame {
                  Type (i) = 0x06,
                  Offset (i),
                  Length (i),
                  Crypto Data (..),
                }
                */
                case CRYPTO_FRAME:
                        return 3; //TODO: plus crypto data
                
                /*
                NEW_TOKEN Frame {
                  Type (i) = 0x07,
                  Token Length (i),
                  Token (..),
                }
                */
                case NEW_TOKEN_FRAME:
                        return 2; //TODO: second one is token length

                /*
                STREAM Frame {
                  Type (i) = 0x08..0x0f,
                  Stream ID (i),
                  [Offset (i)],
                  [Length (i)],
                  Stream Data (..),
                }
                */
                case STREAM_FRAME:
                case STREAM_WITH_FIN:
                        return 2;
                case STREAM_WITH_LEN:
                case STREAM_WITH_OFF:
                case STREAM_WITH_LEN_FIN:
                case STREAM_WITH_OFF_FIN:
                        return 3;
                case STREAM_WITH_OFF_LEN:
                case STREAM_WITH_OFF_LEN_FIN:
                        return 4;
                
                /*
                MAX_DATA Frame {
                  Type (i) = 0x10,
                  Maximum Data (i),
                }
                */
                case MAX_DATA_FRAME:
                        return 2;
                
                /*
                MAX_STREAM_DATA Frame {
                  Type (i) = 0x11,
                  Stream ID (i),
                  Maximum Stream Data (i),
                }
                */
                case MAX_STREAM_DATA_FRAME:
                        return 3;
                
                /*
                MAX_STREAMS Frame {
                  Type (i) = 0x12..0x13,
                  Maximum Streams (i),
                }
                */
                case 0x12: // MAX_STREAMS
                case 0x13:
                        return 2;
                
                /*
                DATA_BLOCKED Frame {
                  Type (i) = 0x14,
                  Maximum Data (i),
                }
                */
                case DATA_BLOCKED_FRAME:
                        return 2;
                
                /*
                STREAM_DATA_BLOCKED Frame {
                  Type (i) = 0x15,
                  Stream ID (i),
                  Maximum Stream Data (i),
                }
                */
                case STREAM_DATA_BLOCKED_FRAME: 
                        return 3;
                
                /*
                STREAMS_BLOCKED Frame {
                  Type (i) = 0x16..0x17,
                  Maximum Streams (i),
                }
                */
                case 0x16: // STREAMS_BLOCKED
                case 0x17:
                        return 2;
                
                /*
                NEW_CONNECTION_ID Frame {
                  Type (i) = 0x18,
                  Sequence Number (i),
                  Retire Prior To (i),
                  Length (8),
                  Connection ID (8..160),
                  Stateless Reset Token (128),
                }
                */
                case NEW_CONNECTION_ID_FRAME:
                        return 3;
                
                /*
                RETIRE_CONNECTION_ID Frame {
                  Type (i) = 0x19,
                  Sequence Number (i),
                }
                */
                case RETIRE_CONNECTION_ID_FRAME:
                        return 2;
                
                /*
                PATH_CHALLENGE Frame {
                  Type (i) = 0x1a,
                  Data (64),
                }
                */
                case PATH_CHALLENGE_FRAME:
                        return 1;
                
                /*
                PATH_RESPONSE Frame {
                  Type (i) = 0x1b,
                  Data (64),
                }
                */
                case PATH_RESPONSE_FRAME:
                        return 1;
                
                /*
                CONNECTION_CLOSE Frame {
                  Type (i) = 0x1c..0x1d,
                  Error Code (i),
                  [Frame Type (i)],
                  Reason Phrase Length (i),
                  Reason Phrase (..),
                }
                */
                case 0x1c: // CONNECTION_CLOSE
                case 0x1d:
                        return 3; //TODO: when is frame type there?
                
                /*
                HANDSHAKE_DONE Frame {
                  Type (i) = 0x1e,
                }       
                */
                case HANDSHAKE_DONE_FRAME:
                        return 1;       
                
                /*
                  In this case the frame read is not valid
                */
                default: // unknown frame
                        return INVALID_FRAME;
        }
}

// This function returns the start of the QUIC stream frame
// or NULL if the payload of the packet does not contain
// a QUIC stream frame
__attribute__((always_inline)) int32_t get_stream_frame_start(void *payload, uint32_t payload_length, void **stream_frame_start) {

        for (int frame_ctr=0; frame_ctr<10; frame_ctr++) { // TODO: change to while loop possible?
                // TODO: handle special cases like NEW_TOKEN_FRAME with skipping token
                uint8_t byte;
                bpf_probe_read_kernel(&byte, sizeof(byte), payload);

                if (IS_STREAM_FRAME(byte)) {
                        *stream_frame_start = payload;
                        return 1;
                }

                payload++;

                // read how many var ints are in the frame
                uint8_t var_ints = get_number_of_var_ints_of_frame(byte);
                if (var_ints == INVALID_FRAME) {
                        *stream_frame_start = NULL;
                        return 0;
                }

                // starting at 1 since the type is also a var int
                // but already read at this point
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
                                // ACK range present
                                read_var_int(payload, &res, VALUE_NEEDED);
                                var_ints += 2 * res.value;
                        }
                        payload += bounded_var_int_len(res.len);
                }

        } //while (payload < payload + payload_length);

        *stream_frame_start = NULL;
        return 0;
}

char __license[] __section("license") = "GPL";