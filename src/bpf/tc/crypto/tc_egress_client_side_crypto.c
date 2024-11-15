#include "../main/tc_common.c"
#include "tc_crypto_common.c"

__section("crypto_egress")
int tc_egress(struct __sk_buff *skb)
{
    bpf_printk("Hello from crypto_egress\n");
    return TC_ACT_OK;
}
