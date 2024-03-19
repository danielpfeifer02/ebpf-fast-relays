#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
// https://github.com/iproute2/iproute2.git


#define DEST_PORT 4242 // see loopback_quic/quic_traffic.go

// TODO: use this to differentiate between template and actual packet
#define DUMMY_DEST_PORT 4243 // port to differentiate between tempalte and actual packet
#define MAX_FAN_OUT 16

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map acc_map __section("maps") = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
};

/*
struct in_addr {
    unsigned long s_addr;  // load with inet_aton()
};
*/
struct destination {
        uint8_t eh_dest[ETH_ALEN];
        struct in_addr iph_dest;
        uint16_t uh_dport;
        uint8_t valid;
};

struct bpf_elf_map destinations_map __section("maps") = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(struct destination),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = MAX_FAN_OUT,
};

static __inline int account_data(struct __sk_buff *skb, uint32_t dir)
{
        uint32_t *bytes;

        bytes = map_lookup_elem(&acc_map, &dir);
        if (bytes)
                lock_xadd(bytes, skb->len);

        return TC_ACT_OK;
}

// NOT CONSIDERED IN MAKEFILE!
__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{
        bpf_printk("[ingress tc] packet is entering");
        return account_data(skb, 0);
}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{

        void *data_end = (void *)(long)skb->data_end;
        void *data = (void *)(long)skb->data;

        unsigned int payload_size;
        struct ethhdr *eth = data;
        unsigned char *payload;
        struct udphdr *udp;
        struct iphdr *ip;

        // Too small to contain an Ethernet header
        if ((void *)eth + sizeof(*eth) > data_end) {
                return TC_ACT_OK;
        }

        // Too small to contain an IP header
        ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end) {
                return TC_ACT_OK;
        }

        int ip_version = ip->version;
        // For now only support IPv4
        if (ip_version != 4) {
                bpf_printk("[ingress xdp] dropping something that is not IPv4\n");
                return TC_ACT_OK;
        }

        // Not a UDP packet
        if (ip->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
        }

        // Too small to contain a UDP header (TODO: check if this is necessary)
        udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end) {
                return TC_ACT_OK;
        }

        // Wrong destination port
        if (udp->source != ntohs(DEST_PORT)) { //udp->dest != ntohs(DEST_PORT) && 
                return TC_ACT_OK;
        }

        // Point to start of payload.
        payload = (unsigned char *)udp + sizeof(*udp);
        payload_size = ntohs(udp->len) - sizeof(*udp);
        if ((void *)payload + payload_size > data_end) {
                return TC_ACT_OK;
        }


        // // fan out the packet to all destinations that are valid
        // struct destination *dest;
        // for (int i = 0; i < MAX_FAN_OUT; i++) {
        //         dest = map_lookup_elem(&destinations_map, &i);
        //         if (dest && dest->valid) {
        //                 bpf_printk("[egress tc] packet is leaving to %d", i);
                        
        //                 udp->dest = htons(dest->uh_dport);
        //                 ip->daddr = dest->iph_dest.s_addr;
        //                 memcpy(eth->h_dest, dest->eh_dest, ETH_ALEN);
        //                 // TODO setup ifindex so that packet does not need to 
        //                 // go through bpf program again
        //                 bpf_clone_redirect(skb, 0, 0);
        //         }
        // }


        if (udp->source == ntohs(DUMMY_DEST_PORT)) {
                udp->source = ntohs(DEST_PORT);
                bpf_printk("[egress tc] packet is leaving (duplicate)");
                return TC_ACT_OK;
        }

        // if we are here then the packet is not a dummy packet
        // so we double it and send it to the same interface again
        udp->source = ntohs(DUMMY_DEST_PORT);
        uint32_t ifindex = skb->ifindex;
        uint64_t flags = 0;
        bpf_clone_redirect(skb, ifindex, flags);
        // bpf_clone_redirect(skb, ifindex, flags);




        bpf_printk("[egress tc] real packet is dropped");
        // return account_data(skb, 1);
        // TODO change to TC_ACT_SHOT so that the dummy packet used as a
        // template does not actually get sent
        return TC_ACT_SHOT;
}

char __license[] __section("license") = "GPL";


// clang -g -O2 -Wall -target bpf -I ~/iproute2/include/ -c tc-example.c -o tc-example.o
// clang -g -O2 -Wall -target bpf -I ./iproute2/include/ -c tc-example.c -o tc-example.o
// clang -g -O2 -Wall -target bpf -I ./iproute2/include/ -I ../libbpf/src/ -c tc-example.c -o tc-example.o