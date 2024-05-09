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

#define veth2 13 // ! TODO: how to handle better and avoid manual configuration?

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

        // We redirect the response of the ICMP packets
        if (eth->h_proto != 0x08) {
                return TC_ACT_OK;
        }

        // Load IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if (ip->protocol != IPPROTO_ICMP) {
                return TC_ACT_OK;
        }

        bpf_printk("[ingress tc] packet entered ingress and will be redirected to egress!\n");
        bpf_clone_redirect(skb, veth2, 0);

        return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{

        bpf_printk("[egress tc] packet entered egress and will be dropped!\n");
        return TC_ACT_SHOT;
}

char __license[] __section("license") = "GPL";