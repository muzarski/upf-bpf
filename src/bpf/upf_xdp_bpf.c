#define KBUILD_MODNAME upf_xdp_bpf

// clang-format off
#include <types.h>
// clang-format on
#include <bpf_helpers.h>
#include <endian.h>
#include <lib/crc16.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <protocols/eth.h>
#include <protocols/gtpu.h>
#include <protocols/ip.h>
#include <protocols/udp.h>
#include <protocols/ipv6.h>
#include <upf_xdp_bpf_maps.h>
#include <utils/logger.h>
#include <utils/utils.h>
#include <next_prog_rule_key.h>
#include <string.h>
#include "ip_key.h"

#ifdef KERNEL_SPACE
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

/* Defines xdp_stats_map */
#include "xdp_stats_kern.h"
#include "xdp_stats_kern_user.h"

void ipv6_to_string(const u8 *ipv6, u8* buffer) {
  const int num_blocks = 8;
  const int block_size = 2;
  u8 *buf_ptr = buffer;
  uint16_t block;
  int i, j;

  for (i = 0; i < num_blocks; i++) {
    block = 0;
    for (j = 0; j < block_size; j++) {
      block = (block << 8) | ipv6[i*block_size+j];
    }

    block = ntohs(block);
    __builtin_memcpy(buf_ptr, &block, sizeof (uint16_t));
    buf_ptr += 2;

    if (i < num_blocks - 1) {
      *buf_ptr++ = ':';
    }
  }

  *buf_ptr = '\0';
}

static u32 tail_call_next_prog(struct xdp_md *p_ctx, teid_t_ teid, u8 source_value, struct ip_key* ipKey)
{
  struct next_rule_prog_index_key map_key;
  u32 *index_prog;

  __builtin_memset(&map_key, 0, sizeof(struct next_rule_prog_index_key));
  
  
  map_key.teid = teid;
  map_key.source_value = source_value;

  __builtin_memcpy(&map_key.ip_address, &ipKey->ip_address, sizeof(u32) * 4);

  map_key.ip_is_ipv6_flag = ipKey->ip_is_ipv6_flag;

  index_prog = bpf_map_lookup_elem(&m_next_rule_prog_index, &map_key);

  if(index_prog){
    bpf_debug("BPF tail call to %d key\n", *index_prog);
    bpf_tail_call(p_ctx, &m_next_rule_prog, *index_prog);
    bpf_debug("BPF tail call was not executed!\n");
  }
  return 0;
}
/**
 * GTP SECTION.
 */

/**
 * @brief Check if GTP packet is a GPDU. If so, process the next block chain.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param p_gtpuh The GTP header.
 * @return u32 The XDP action.
 */
static u32 gtp_handle(struct xdp_md *p_ctx, struct gtpuhdr *p_gtpuh, struct ip_key* ipKey)
{
  void *p_data_end = (void *)(long)p_ctx->data_end;

  if((void *)p_gtpuh + sizeof(*p_gtpuh) > p_data_end) {
    bpf_debug("Invalid GTPU packet");
    return XDP_DROP;
  }

  // TODO navarrothiago - handle other PDU.
  if(p_gtpuh->message_type != GTPU_G_PDU) {
    bpf_debug("Message type 0x%x is not GTPU GPDU(0x%x)", p_gtpuh->message_type, GTPU_G_PDU);
    return XDP_PASS;
  }

  bpf_debug("GTP GPDU received");

  if(ip_inner_check_ipv6(p_ctx, (struct  ipv6hdr *)(p_gtpuh + 1))) {
    bpf_debug("No fars implemented for IPv6 packets yet. Dropping the packet...");
    return XDP_DROP;
  } else if(!ip_inner_check_ipv4(p_ctx, (struct iphdr *)(p_gtpuh + 1))) {
    bpf_debug("Invalid IPv4 inner");
    return XDP_DROP;
  }

  // Jump to session context.
  tail_call_next_prog(p_ctx, p_gtpuh->teid, INTERFACE_VALUE_ACCESS, ipKey);
  bpf_debug("BPF tail call was not executed! teid %d\n", htonl(p_gtpuh->teid));

  return XDP_PASS;
}

/**
 * UDP SECTION.
 */

/**
 * @brief Handle UDP header.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param udph The UDP header.
 * @return u32 The XDP action.
 */
static u32 udp_handle(struct xdp_md *p_ctx, struct udphdr *udph, struct ip_key* ip_src, struct ip_key* ip_dst)
{
  void *p_data_end = (void *)(long)p_ctx->data_end;
  struct next_rule_prog_index_key map_key;
  u32 index_prog;
  u32 dport;

  /* Hint: +1 is sizeof(struct udphdr) */
  if((void *)udph + sizeof(*udph) > p_data_end) {
    bpf_debug("Invalid UDP packet");
    return XDP_ABORTED;
  }

  bpf_debug("UDP packet validated");
  dport = ntohs(udph->dest);

  switch(dport) {
  case GTP_UDP_PORT:
    // The source IP is the UE IP address (uplink).
    return gtp_handle(p_ctx, (struct gtpuhdr *)(udph + 1), ip_src);
  default:
    // The destination IP is the UE IP address (donwlink).
    tail_call_next_prog(p_ctx, 0, INTERFACE_VALUE_CORE, ip_dst);

    return XDP_PASS;
  }
}

/**
 * IP SECTION.
 */

/**
 * @brief Handle IPv4 header.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param iph The IP header.
 * @return u32 The XDP action.
 */
static u32 ipv4_handle(struct xdp_md *p_ctx, struct iphdr *iph)
{
  void *p_data_end = (void *)(long)p_ctx->data_end;
  // Type need to match map.

  // Hint: +1 is sizeof(struct iphdr)
  if((void *)iph + sizeof(*iph) > p_data_end) {
    bpf_debug("Invalid IPv4 packet");
    return XDP_ABORTED;
  }
  
  u8 *ip_src_ptr = (u8 *)&iph->saddr;
  u8 *ip_dst_ptr = (u8 *)&iph->daddr;

  bpf_debug("IPv4 src address: ");

  for(int i = 3; i >= 0; --i) {
    bpf_debug("%u: ", ntohs(ip_src_ptr[i]));
  }

  bpf_debug("IPv4 dst address: ");

  for(int i = 3; i >= 0; --i) {
    bpf_debug("%u: ", ntohs(ip_dst_ptr[i]));
  }



  struct ip_key ip_src;
  struct ip_key ip_dst;


  __builtin_memset(&ip_src, 0, sizeof(ip_src));
  __builtin_memset(&ip_dst, 0, sizeof(ip_dst));
  ip_src.ip_address[0] = iph->saddr;
  ip_dst.ip_address[0] = iph->daddr;
  
  
  switch(iph->protocol) {
  case IPPROTO_UDP:
    bpf_debug("UDP DETECTED FROM IPv4 handle");
    return udp_handle(p_ctx, (struct udphdr *)(iph + 1), &ip_src, &ip_dst);
  case IPPROTO_TCP:
  default:
    bpf_debug("TCP protocol L4");
    return XDP_PASS;
  }
}

static u32 ipv6_handle(struct xdp_md *p_ctx, struct ipv6hdr *ipv6h)
{

  void *p_data_end = (void *)(long)p_ctx->data_end;


  if ((void *)ipv6h + sizeof(*ipv6h) > p_data_end) {
    bpf_debug("Invalid IPv6 packet");
    return XDP_ABORTED;
  }
  bpf_debug("Valid IPv6 packet.\n");
  
//  u8 buffer[40];
//  ipv6_to_string(ipv6h->saddr.in6_u.u6_addr8, buffer);

//  bpf_debug("IPv6 src address: %s\n", buffer);

//  ipv6_to_string(ipv6h->daddr.in6_u.u6_addr8, buffer);

//  bpf_debug("IPv6 dst address: %s\n", buffer);

  bpf_debug("IPv6 src address: ");

  for(int i = 0; i < 8; ++i) {
    bpf_debug("%x: ", ntohs(ipv6h->saddr.in6_u.u6_addr16[i]));
  }

  bpf_debug("IPv6 dst address: ");

  for(int i = 0; i < 8; ++i) {
    bpf_debug("%x: ", ntohs(ipv6h->daddr.in6_u.u6_addr16[i]));
  }

  //  bpf_debug("IPv6 src address: %x:%x:%x:%x:%x:%x:%x:%x\n", ntohl(ipv6h->saddr.in6_u.u6_addr16[0]),
//            ntohl(ipv6h->saddr.in6_u.u6_addr16[1]),
//            ntohl(ipv6h->saddr.in6_u.u6_addr16[2]),
//            ntohl(ipv6h->saddr.in6_u.u6_addr16[3]),
//            ntohl(ipv6h->saddr.in6_u.u6_addr16[4]),
//            ntohl(ipv6h->saddr.in6_u.u6_addr16[5]),
//            ntohl(ipv6h->saddr.in6_u.u6_addr16[6]),
//            ntohl(ipv6h->saddr.in6_u.u6_addr16[7]));
//  bpf_debug("IPv6 dst address: %x:%x:%x:%x:%x:%x:%x:%x\n", ntohl(ipv6h->daddr.in6_u.u6_addr16[0]),
//            ntohl(ipv6h->daddr.in6_u.u6_addr16[1]),
//            ntohl(ipv6h->daddr.in6_u.u6_addr16[2]),
//            ntohl(ipv6h->daddr.in6_u.u6_addr16[3]),
//            ntohl(ipv6h->daddr.in6_u.u6_addr16[4]),
//            ntohl(ipv6h->daddr.in6_u.u6_addr16[5]),
//            ntohl(ipv6h->daddr.in6_u.u6_addr16[6]),
//            ntohl(ipv6h->daddr.in6_u.u6_addr16[7]));

  struct ip_key ip_src;
  struct ip_key ip_dst;

  __builtin_memcpy(&ip_src.ip_address, ipv6h->saddr.in6_u.u6_addr32, 4 * sizeof(u32));
  __builtin_memcpy(&ip_dst.ip_address, ipv6h->daddr.in6_u.u6_addr32, 4 * sizeof(u32));

  ip_src.ip_is_ipv6_flag = 1;
  ip_dst.ip_is_ipv6_flag = 1;

  switch(ipv6h->nexthdr) {
  case IPPROTO_UDP:
    bpf_debug("UPD DETECTED FROM IPv6 handle");
    return udp_handle(p_ctx, (struct udphdr *)(ipv6h + 1), &ip_src, &ip_dst);
    return XDP_PASS;
  case IPPROTO_TCP:
  default:
    bpf_debug("TCP protocol L4");
    return XDP_PASS;
  }

  return XDP_PASS;
}

/**
 * @brief Check if inner IP header is IPv4.
 *
 * @param p_ctx The user accessible metadata for xdp packet hook.
 * @param iph The IP header.
 * @return u8 The XDP action.
 */
static u8 ip_inner_check_ipv4(struct xdp_md *p_ctx, struct iphdr *iph)
{
  void *p_data_end = (void *)(long)p_ctx->data_end;

  // Hint: +1 is sizeof(struct iphdr)
  if((void *)iph + sizeof(*iph) > p_data_end) {
    bpf_debug("Invalid IPv4 packet");
    return XDP_ABORTED;
  }

  return iph->version == 4;
}

static u8 ip_inner_check_ipv6(struct xdp_md *p_ctx, struct ipv6hdr *iph)
{
  void *p_data_end = (void *)(long)p_ctx->data_end;

  // Hint: +1 is sizeof(struct iphdr)
  if((void *)iph + sizeof(*iph) > p_data_end) {
    bpf_debug("Invalid IPv6 packet");
    return XDP_ABORTED;
  }

  return iph->version == 6;
}

/**
 * ETHERNET SECTION.
 */

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

/**
 *
 * @brief Parse Ethernet layer 2, extract network layer 3 offset and protocol
 * Call next protocol handler (e.g. ipv4).
 *
 * @param p_ctx
 * @param ethh
 * @return u32 The XDP action.
 */
static u32 eth_handle(struct xdp_md *p_ctx, struct ethhdr *ethh)
{
  void *p_data_end = (void *)(long)p_ctx->data_end;
  u16 eth_type;
  u64 offset;
  struct vlan_hdr *vlan_hdr;

  offset = sizeof(*ethh);
  if((void *)ethh + offset > p_data_end) {
    bpf_debug("Cannot parse L2");
    return XDP_PASS;
  }

  eth_type = htons(ethh->h_proto);
  bpf_debug("Debug: eth_type:0x%x", eth_type);

  switch(eth_type) {
  case ETH_P_8021Q:
  case ETH_P_8021AD:
    bpf_debug("VLAN!! Changing the offset");
    vlan_hdr = (void *)ethh + offset;
    offset += sizeof(*vlan_hdr);
    if(!((void *)ethh + offset > p_data_end))
      eth_type = htons(vlan_hdr->h_vlan_encapsulated_proto);
    // Enter in next case.
  case ETH_P_IP:
    return ipv4_handle(p_ctx, (struct iphdr *)((void *)ethh + offset));
  case ETH_P_IPV6:
    return ipv6_handle(p_ctx, (struct ipv6hdr *)((void *)ethh + offset));
  // Skip non 802.3 Ethertypes
  case ETH_P_ARP:
  // Skip non 802.3 Ethertypes
  // Fall-through
  default:
    bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x", offset, eth_type);
    return XDP_PASS;
  }
}

SEC("xdp_entry_point")
int entry_point(struct xdp_md *p_ctx)
{
  void *p_data = (void *)(long)p_ctx->data;
  struct ethhdr *eth = p_data;

  bpf_debug("XDP ENTRY POINT");

  // Start to handle the ethernet header.
  u32 action = xdp_stats_record_action(p_ctx, eth_handle(p_ctx, eth));
  bpf_debug("Action %d", action);

  return action;
}

char _license[] SEC("license") = "GPL";
