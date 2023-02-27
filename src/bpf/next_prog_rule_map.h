#ifndef __NEXT_PROG_RULE_MAP_H__
#define __NEXT_PROG_RULE_MAP_H__

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <types.h>
#include "next_prog_rule_key.h"

struct bpf_map_def SEC("maps") m_next_rule_prog = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(struct next_rule_prog_index_key),
    .value_size = sizeof(s32),
    .max_entries = 10,
};

//BPF_ANNOTATE_KV_PAIR(m_next_rule_prog, u32, s32);

#endif // __NEXT_PROG_RULE_MAP_H__
