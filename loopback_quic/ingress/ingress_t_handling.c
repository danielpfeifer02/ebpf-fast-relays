#include <linux/bpf.h>
#include <bpf_helpers.h>

// to read trace: sudo cat /sys/kernel/tracing/trace_pipe

SEC("xdp")
int handle_ingress(struct xdp_md *ctx)
{
    bpf_printk("[ingress xdp] packet is entering\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";