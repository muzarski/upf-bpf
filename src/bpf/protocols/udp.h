#if !defined(PROTOCOLS_UDP_H)
#define PROTOCOLS_UDP_H

#include <linux/udp.h>
#include <types.h>

static u32 udp_handle(struct xdp_md *p_ctx, struct udphdr *udph, const u32 src_ip[4], const u32 dest_ip[4], u8 is_ip6);


#endif // PROTOCOLS_UDP_H
