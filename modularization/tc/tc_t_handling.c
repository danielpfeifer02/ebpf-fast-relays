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


#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#define veth0_veth1 6
#define veth1_veth0 7
#define veth2_veth3 8
#define veth3_veth2 9

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{

        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                return TC_ACT_OK; // Not enough data
        }

        // Load ethernet header
        struct ethhdr *eth = (struct ethhdr *)data;

        // Since ping packets start with an ARP packet and 
        // we don't really car about the exact type of the
        // packet here, we can just use ARP to show how the
        // redirection would work.
        if (eth->h_proto == htons(ETH_P_ARP)) {
                bpf_printk("[ingress tc] packet entered ingress and will be redirected to egress!\n");
                return bpf_redirect(veth2_veth3, 0);
        }

        return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{

        bpf_printk("[egress tc] packet entered egress and will be dropped!\n");
        return TC_ACT_SHOT;
}

char __license[] __section("license") = "GPL";