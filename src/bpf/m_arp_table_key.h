//
// Created by andrzej on 27.02.23.
//

#ifndef UPFBPF_M_ARP_TABLE_KEY_H
#define UPFBPF_M_ARP_TABLE_KEY_H

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>

struct m_arp_table_key {
  u32 ip_address[4];
  u8 ip_is_ipv6_flag;
};

#endif // UPFBPF_M_ARP_TABLE_KEY_H