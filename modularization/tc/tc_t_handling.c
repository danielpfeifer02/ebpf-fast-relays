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

#define veth2_egress_ifindex 14
#define CONN_ID_LEN 16
#define MAC_LEN 6
#define MAX_CLIENTS 1024
#define RELAY_PORT 4242
#define SERVER_PORT 4242
#define PORT_MARKER 6969
#define SKB_FLAGS BPF_F_RECOMPUTE_CSUM

// this key is used to make sure that we can check if a client is already in the map
// it is not meant to be known for fan-out purposes since there we will just go over
// all map entries
struct client_info_key_t {
        uint32_t ip_addr;
        uint16_t port;
};

struct client_info_t {
        uint8_t src_mac[MAC_LEN];
        uint8_t dst_mac[MAC_LEN];
        uint32_t src_ip_addr;
        uint32_t dst_ip_addr;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t connection_id[CONN_ID_LEN];
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
// in userspace
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint8_t);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_established SEC(".maps");

__section("ingress_startup")
int tc_ingress_startup(struct __sk_buff *skb)
{

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                return TC_ACT_OK; // Not enough data
        }

        // Load ethernet header
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check if the packet is UDP
        if (ip->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
        }

        // Load UDP header
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // Check if the packet is QUIC
        if (udp->dest != htons(RELAY_PORT)) {
                return TC_ACT_OK;
        }

        // Load UDP payload
        void *payload = (void *)(udp + 1);
        uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

        if ((void *)payload + payload_size > data_end) {

                bpf_printk("[ingress startup tc] payload is not in the buffer");

                // We need to use bpf_skb_pull_data() to get the rest of the packet
                if(bpf_skb_pull_data(skb, (data_end-data)+payload_size) < 0) {
                        bpf_printk("[ingress startup tc] failed to pull data");
                        return TC_ACT_OK;
                }
                data_end = (void *)(long)skb->data_end;
                data = (void *)(long)skb->data;
        
        }

        uint8_t quic_flags;
        bpf_probe_read_kernel(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        if (header_form == 1) {
                // Long header
                bpf_printk("Long header\n");

                uint8_t packet_type = (quic_flags & 0x30) >> 4;

                bpf_printk("Packet type: %02x\n", packet_type);

                // Packet types are:
                // 0x00 - Initial
                // 0x01 - 0-RTT
                // 0x02 - Handshake
                // 0x03 - Retry

                // Load connection id
                uint8_t dst_connection_id_offset = 6;
                uint8_t src_connection_id_offset = 6 + CONN_ID_LEN + 1;

                uint8_t dst_connection_id[CONN_ID_LEN];
                uint8_t src_connection_id[CONN_ID_LEN];

                bpf_probe_read_kernel(dst_connection_id, sizeof(dst_connection_id), payload + dst_connection_id_offset);
                bpf_probe_read_kernel(src_connection_id, sizeof(src_connection_id), payload + src_connection_id_offset);

                uint8_t src_mac[MAC_LEN]; // mac address of the client
                bpf_probe_read_kernel(src_mac, sizeof(src_mac), eth->h_source);
                uint8_t dst_mac[MAC_LEN]; // mac address of the relay
                bpf_probe_read_kernel(dst_mac, sizeof(dst_mac), eth->h_dest);
                uint32_t src_ip_addr; // ip address of the client
                bpf_probe_read_kernel(&src_ip_addr, sizeof(src_ip_addr), &ip->saddr);
                uint32_t dst_ip_addr; // ip address of the relay
                bpf_probe_read_kernel(&dst_ip_addr, sizeof(dst_ip_addr), &ip->daddr);
                uint16_t src_port; // port of the client
                bpf_probe_read_kernel(&src_port, sizeof(src_port), &udp->source);
                uint16_t dst_port; // port of the relay
                bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &udp->dest);

                struct client_info_key_t key = {
                        .ip_addr = src_ip_addr, // identifying will be the ip of the client
                        .port = src_port,       // and the port of the client
                };

                struct client_info_t value = {
                        .src_mac = {0},
                        .dst_mac = {0},
                        .src_ip_addr = dst_ip_addr, // the source ip will be the ip of the relay
                        .dst_ip_addr = src_ip_addr, // the destination ip will be the ip of the client
                        .src_port = dst_port, // the source port will be the port of the relay
                        .dst_port = src_port, // the destination port will be the port of the client
                        .connection_id = {0},
                };

                for (int i = 0; i < MAC_LEN; i++) {
                        value.src_mac[i] = dst_mac[i]; // the source mac will be the mac of the relay
                }
                for (int i = 0; i < MAC_LEN; i++) {
                        value.dst_mac[i] = src_mac[i]; // the destination mac will be the mac of the client
                }
                for (int i = 0; i < CONN_ID_LEN; i++) {
                        value.connection_id[i] = src_connection_id[i];
                }

                // Look up the client id
                uint32_t *cid = bpf_map_lookup_elem(&client_id, &key);
                if (cid == NULL) {
                        bpf_printk("First occurence of key\n");
                        // Get the next client id
                        uint32_t zero = 0;
                        uint32_t *next_client_id = bpf_map_lookup_elem(&id_counter, &zero);
                        if (next_client_id == NULL) {
                                bpf_printk("No next client id found\n");
                                return TC_ACT_OK;
                        }
                        uint32_t new_counter = (*next_client_id + 1) % MAX_CLIENTS;
                        bpf_printk("New client id: %d\n", new_counter);
                        bpf_map_update_elem(&id_counter, &zero, &new_counter, BPF_ANY);
                        bpf_map_update_elem(&client_id, &key, next_client_id, BPF_ANY);
                        cid = next_client_id;
                }

                bpf_printk("Client id: %d\n", *cid);

                // Update the client data map
                bpf_map_update_elem(&client_data, cid, &value, BPF_ANY);

        } else {
                // Short header
                // bpf_printk("Short header\n");
        }

        // bpf_printk("[ingress startup tc]\n");
        return TC_ACT_OK;
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{

        // load connection_established map
        uint32_t zero = 0;
        uint8_t *conn_est = bpf_map_lookup_elem(&connection_established, &zero);
        if (conn_est == NULL) {
                bpf_printk("No connection established found\n");
                return TC_ACT_OK;
        }
        if (*conn_est == 0) {
                bpf_printk("Connection not established\n");
                return TC_ACT_OK;
        }

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        // TODO hacky for now since i know the payload / packet size
        uint32_t sz = skb->data_end - skb->data;
        if (sz > 100) {
                return TC_ACT_OK;
        }

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                return TC_ACT_OK; // Not enough data
        }

        // Load ethernet header
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check if the packet is UDP
        if (ip->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
        }

        // Load UDP header
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // Check if the packet is QUIC
        if (udp->source != htons(SERVER_PORT)) {
                return TC_ACT_OK;
        }

        // Load UDP payload
        void *payload = (void *)(udp + 1);
        uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

        if ((void *)payload + payload_size > data_end) {

                bpf_printk("[ingress startup tc] payload is not in the buffer");

                // We need to use bpf_skb_pull_data() to get the rest of the packet
                if(bpf_skb_pull_data(skb, (data_end-data)+payload_size) < 0) {
                        bpf_printk("[ingress startup tc] failed to pull data");
                        return TC_ACT_OK;
                }
                data_end = (void *)(long)skb->data_end;
                data = (void *)(long)skb->data;
        
        }

        uint8_t quic_flags;
        bpf_probe_read_kernel(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        // redirecting short header packets
        if (header_form == 0) {

                // get number of clients
                uint32_t zero = 0;
                uint32_t *num_clients = bpf_map_lookup_elem(&number_of_clients, &zero);
                if (num_clients == NULL) {
                        bpf_printk("No number of clients found\n");
                        return TC_ACT_OK;
                }

                bpf_printk("Short header - redirecting for %d clients\n", *num_clients);

                // set packet_counter to 1 // ARGH TODO probably not working bc of concurrency (maybe some hash map to look up ctr value for a packet?)
                uint32_t pack_ctr = 1;
                bpf_map_update_elem(&packet_counter, &zero, &pack_ctr, BPF_ANY);

                // TODO this might be better approach than zero checksum
                // // set src_port to PORT_MARKER
                // uint16_t src_port = htons(PORT_MARKER);
                // // get offset of src_port
                // uint32_t src_port_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
                // bpf_skb_store_bytes(skb, src_port_off, &src_port, sizeof(src_port), SKB_FLAGS);
                // // bpf_probe_write(&udp->source, &src_port, sizeof(src_port));

                // set ip checksum to 0
                uint16_t zero_ip_checksum = 0;
                uint32_t ip_checksum_off = sizeof(struct ethhdr) + 10 /* Everything before checksum */;
                bpf_skb_store_bytes(skb, ip_checksum_off, &zero_ip_checksum, sizeof(zero_ip_checksum), SKB_FLAGS);

                // set udp checksum to 0
                uint16_t zero_checksum = 0;
                uint32_t checksum_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 6 /* Everything before checksum */;
                bpf_skb_store_bytes(skb, checksum_off, &zero_checksum, sizeof(zero_checksum), SKB_FLAGS);

                // { //ARGH TODO remove (only for checking that checksums are 0)
                //         void *data = (void *)(long)skb->data;
                //         void *data_end = (void *)(long)skb->data_end;

                //         // TODO hacky for now since i know the payload / packet size
                //         uint32_t sz = skb->data_end - skb->data;
                //         if (sz > 100) {
                //                 return TC_ACT_OK;
                //         }

                //         if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                //                 return TC_ACT_OK; // Not enough data
                //         }

                //         // Load ethernet header
                //         struct ethhdr *eth = (struct ethhdr *)data;

                //         // Load IP header
                //         struct iphdr *ip = (struct iphdr *)(eth + 1);

                //         // Check if the packet is UDP
                //         if (ip->protocol != IPPROTO_UDP) {
                //                 return TC_ACT_OK;
                //         }

                //         // Load UDP header
                //         struct udphdr *udp = (struct udphdr *)(ip + 1);
                //         bpf_printk("redirected: %d %d\n", udp->check, ip->check);
                // }


                for (int i=0; i<MAX_CLIENTS; i++) {
                        if (i >= *num_clients) {
                                break;
                        }
                        bpf_clone_redirect(skb, veth2_egress_ifindex, 0); // TODO: bpf_redirect or bpf_clone_redirect?
                }

                return TC_ACT_SHOT;
        
        }

        // bpf_printk("[ingress tc]\n");
        return TC_ACT_OK;

}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{

        // Before redirecting we need to: 

        //      1) change src ethernet 
        //      2) change dst ethernet
        //      3) change src ip
        //      4) change dst ip
        //      5) change dst port (or set it in code)
        //      6) change connection id (setup maps for that)

        // TODO: also filter for direction so that connection establishment from client is not affected

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                bpf_printk("Not enough data\n");
                return TC_ACT_OK; // Not enough data
        }

        // Load ethernet header
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check if the packet is UDP
        if (ip->protocol != IPPROTO_UDP) {
                bpf_printk("Not UDP\n");
                return TC_ACT_OK;
        }

        // Load UDP header
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // Check if the packet is QUIC
        if (udp->source != htons(RELAY_PORT) && udp->source != htons(PORT_MARKER)) { // TODO change to SERVER_PORT or PORT_MARKER once it is sent?
                bpf_printk("Not QUIC\n");
                return TC_ACT_OK;
        }

        // TODO: this might be better than zero checksum
        // // check src_port for PORT_MARKER
        // uint16_t src_port;
        // bpf_probe_read_kernel(&src_port, sizeof(src_port), &udp->source);
        // if (src_port != htons(PORT_MARKER)) {
        //         return TC_ACT_OK;
        // }

        // check if ip checksum is 0
        if (ip->check != 0) {
                bpf_printk("IP checksum not 0\n");
                return TC_ACT_OK;
        }

        // check if udp checksum is 0
        if (udp->check != 0) {
                bpf_printk("UDP checksum not 0\n");
                return TC_ACT_OK;
        }


        // Load UDP payload
        void *payload = (void *)(udp + 1);
        uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

        if ((void *)payload + payload_size > data_end) {

                bpf_printk("[ingress startup tc] payload is not in the buffer");

                // We need to use bpf_skb_pull_data() to get the rest of the packet
                if(bpf_skb_pull_data(skb, (data_end-data)+payload_size) < 0) {
                        bpf_printk("[ingress startup tc] failed to pull data");
                        return TC_ACT_OK;
                }
                data_end = (void *)(long)skb->data_end;
                data = (void *)(long)skb->data;
        
        }

        uint8_t quic_flags;
        bpf_probe_read_kernel(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        // redirecting short header packets
        if (header_form == 0) {

                bpf_printk("Received redirected short header!\n");

                // get packet_counter
                uint32_t zero = 0;
                uint32_t *pack_ctr = bpf_map_lookup_elem(&packet_counter, &zero);

                if (pack_ctr == NULL) {
                        bpf_printk("No packet counter found\n");
                        return TC_ACT_OK;
                }


                // get pack_ctr-th client data
                struct client_info_t *value;

                // TODO this assumes that they are linear in the map (verify)
                value = bpf_map_lookup_elem(&client_data, pack_ctr);

                if (value == NULL) {
                        bpf_printk("No client data found\n");
                        return TC_ACT_SHOT;
                }

                // set src_mac to value->src_mac
                uint32_t src_mac_off = 6 /* DST MAC */;
                bpf_skb_store_bytes(skb, src_mac_off, value->src_mac, MAC_LEN, SKB_FLAGS);
                // bpf_probe_write(eth->h_source, value->src_mac, MAC_LEN);

                // TODO wrong? not the mac from the bridge inside the map?
                // set dst_mac to value->dst_mac
                uint32_t dst_mac_off = 0;
                value->dst_mac[0] = 0xd6; // TODO: remove hardcode (mac of client)
                value->dst_mac[1] = 0x06;
                value->dst_mac[2] = 0xcb;
                value->dst_mac[3] = 0x05;
                value->dst_mac[4] = 0x65;
                value->dst_mac[5] = 0x62;
                bpf_skb_store_bytes(skb, dst_mac_off, value->dst_mac, MAC_LEN, SKB_FLAGS);
                // bpf_probe_write(eth->h_dest, value->dst_mac, MAC_LEN);

                // set src_ip to value->src_ip_addr
                uint32_t src_ip_off = sizeof(struct ethhdr) + 12 /* Everything before SRC IP */;
                bpf_skb_store_bytes(skb, src_ip_off, &value->src_ip_addr, sizeof(value->src_ip_addr), SKB_FLAGS);
                // bpf_probe_write(&ip->saddr, &value->src_ip_addr, sizeof(value->src_ip_addr));

                // set dst_ip to value->dst_ip_addr
                uint32_t dst_ip_off = sizeof(struct ethhdr) + 12 /* Everything before SRC IP */ +  4 /* SRC IP */;
                bpf_skb_store_bytes(skb, dst_ip_off, &value->dst_ip_addr, sizeof(value->dst_ip_addr), SKB_FLAGS);
                // bpf_probe_write(&ip->daddr, &value->dst_ip_addr, sizeof(value->dst_ip_addr));

                // set src_port to value->src_port
                uint16_t src_port_tmp = value->src_port;
                uint32_t src_port_tmp_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
                bpf_skb_store_bytes(skb, src_port_tmp_off, &src_port_tmp, sizeof(src_port_tmp), SKB_FLAGS);
                // bpf_probe_write(&udp->source, &src_port_tmp, sizeof(src_port_tmp));

                // set dst_port to value->dst_port
                uint16_t dst_port_tmp = value->dst_port;
                uint32_t dst_port_tmp_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 2 /* SRC PORT */;
                bpf_skb_store_bytes(skb, dst_port_tmp_off, &dst_port_tmp, sizeof(dst_port_tmp), SKB_FLAGS);
                // bpf_probe_write(&udp->dest, &dst_port_tmp, sizeof(dst_port_tmp));

                // set connection_id to value->connection_id
                uint32_t conn_id_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 /* Short header flags */;
                bpf_skb_store_bytes(skb, conn_id_off, value->connection_id, CONN_ID_LEN, SKB_FLAGS);
                // bpf_probe_write(payload + 1, value->connection_id, CONN_ID_LEN);

                // set pack_ctr to pack_ctr + 1 and write it back
                *pack_ctr = *pack_ctr + 1;
                bpf_map_update_elem(&packet_counter, &zero, pack_ctr, BPF_ANY);

                bpf_printk("Done editing packet\n");
        
        }

        bpf_printk("Long header\n");
        return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";


/*
        Basic setup how the ingress-to-egress redirection should work:

        First we get a packet we have not seen before (i.e. we don't know how to forward it yet).
        
        We determine such a packet by checking the connection id map, which maps ingress quic 
        connection id to egress quic connection id. (TODO feels like this might get weird)
        
        At egress we also check a map based on the connection id as a key and if there is no 
        entry, we create a new one that stores all the information we need at the ingress hook
        (i.e. MAC addresses, IP addresses, ports, etc.)

        Once this map is set every packet at ingress will have access to these values and can
        directly modify the packet and forward it to the egress interface.
*/