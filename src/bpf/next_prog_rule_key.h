#ifndef __NEXT_PROG_RULE_KEY_H__
#define __NEXT_PROG_RULE_KEY_H__

#include <ie/teid.h>
#include <types.h>

struct next_rule_prog_index_key {
  teid_t_ teid;
  u8 source_value;
  u32 ip_address[4];
  u8 ip_is_ipv6_flag;
};

#endif // __NEXT_PROG_RULE_KEY_H__
