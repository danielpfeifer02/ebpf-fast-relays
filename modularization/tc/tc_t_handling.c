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

#define veth2_egress_ifindex 187

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{

        // void *data = (void *)(long)skb->data;
        // void *data_end = (void *)(long)skb->data_end;

        // if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
        //         return TC_ACT_OK; // Not enough data
        // }

        // // Load ethernet header
        // struct ethhdr *eth = (struct ethhdr *)data;

        // Before redirecting we need to: 

        //      1) change src ethernet 
        //      2) change dst ethernet
        //      3) change src ip
        //      4) change dst ip
        //      5) change dst port (or set it in code)
        //      6) change connection id (setup maps for that)

        // TODO: also filter for direction so that connection establishment from client is not affected

        bpf_printk("[ingress tc] packet entered ingress and will be redirected to egress!\n");
        return bpf_redirect(veth2_egress_ifindex, 0);

}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{

        bpf_printk("[egress tc] packet entered egress and will be dropped!\n");
        return TC_ACT_SHOT;
}

char __license[] __section("license") = "GPL";