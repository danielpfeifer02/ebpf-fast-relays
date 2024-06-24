#include "../main/tc_common.c"

/*
 - This program is intercepting incoming packets from the client side
 - and makes sure that new clients are "registered" in the client_data map
 - as well as separate maps that allow iteration over the clients in the
 - egress program.
 - Here only long headers are considered, since they are used primarily
 - in the initial handshake phase and that way we can avoid looking at
 - short headers containing ACKs once the connection is established.
 */

__section("ts_ingress")
int tc_ts_ingress(struct __sk_buff *skb)
{

    bpf_printk("Hello from tc_ts_ingress\n");
    return TC_ACT_OK;

        // Get data pointers from the buffer.
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        // If the packet is too small to contain the headers we expect
        // we can directly pass it through.
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                return TC_ACT_OK;
        }

        // Load ethernet header.
        struct ethhdr *eth = (struct ethhdr *)data;

        // Load IP header.
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // If the packet is not a UDP packet we can pass it through
        // since QUIC is built on top of UDP.
        if (ip->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
        }

        // Load UDP header.
        struct udphdr *udp = (struct udphdr *)(ip + 1);

        // If the packet is not addressed to the port where our relay is
        // listening we can pass it through since the packet is from a 
        // different program.
        if (udp->dest != RELAY_PORT) {
                return TC_ACT_OK;
        }

        // Load UDP payload as well as UDP payload size.
        void *payload = (void *)(udp + 1);
        uint32_t payload_size = ntohs(udp->len) - sizeof(*udp);

        // If the payload is not in the buffer we need to pull it in.
        if ((void *)payload + payload_size > data_end) {

                // We need to use bpf_skb_pull_data() to get the rest of the packet.
                // If the pull fails we can pass the packet through.
                if(bpf_skb_pull_data(skb, (data_end-data)+payload_size) < 0) {
                        bpf_printk("[tc_ts_handling_ingress] Failed to pull data");
                        return TC_ACT_OK;
                }

                // Once we have pulled the data we need to update the pointers.
                data_end = (void *)(long)skb->data_end;
                data = (void *)(long)skb->data;
                eth = (struct ethhdr *)data;
                ip = (struct iphdr *)(eth + 1);
                udp = (struct udphdr *)(ip + 1);
                payload = (void *)(udp + 1);
        }      

        // We load the first byte of the QUIC payload to determine the header form.
        uint8_t quic_flags;
        SAVE_BPF_PROBE_READ_KERNEL(&quic_flags, sizeof(quic_flags), payload);
        uint8_t header_form = (quic_flags & 0x80) >> 7;

        // We only consider long headers here.
        if (header_form == 1) {

                // Only thing to change is the timetamp.

        }

        return TC_ACT_OK;
}
