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
        return TC_ACT_OK;
        return bpf_redirect(veth2_egress_ifindex, 0);

}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{
        bpf_printk("[egress tc] packet entered egress and will not be dropped!\n");
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