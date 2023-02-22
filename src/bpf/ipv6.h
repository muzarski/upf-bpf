#if !defined(PROTOCOLS_IP6_H)
#define PROTOCOLS_IP6_H

#include <linux/ipv6.h>
#include <types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

static u32 ipv6_handle(struct xdp_md *ctx, struct ipv6hdr *iph);
static u8 ip_inner_check_ipv6(struct xdp_md *ctx, struct ipv6hdr *iph);

#endif // PROTOCOLS_IP6_H
