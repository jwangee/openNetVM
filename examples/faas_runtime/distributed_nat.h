
#ifndef L4_NAT_H_
#define L4_NAT_H_

#include <limits.h>
#include <stdbool.h> 
#include <string.h>
#include <stdint.h>

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_thash.h>
#include <rte_hash_crc.h>

#include "onvm_flow_dir.h"
#include "onvm_flow_table.h"

#define NAT_ENTRIES 4096

struct onvm_nat_table {
        struct rte_hash *hash;
        char *data;
        int cnt;
        int entry_size;
};
extern struct onvm_ft *nat_table;

/*
struct onvm_ft_ipv4_5tuple {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t proto;
};
struct Address {
    uint32_t ip;
    uint16_t port;
}
*/

struct Entry {
    uint32_t ip;
    uint16_t port;
    bool active;
    uint64_t last_refresh;
};

bool is_internal_traffic(uint32_t target_ip);

void onvm_nat_fill_key(struct onvm_ft_ipv4_5tuple *key, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, int dir);

int onvm_nat_dir_init();

struct onvm_ft * onvm_natt_create(int cnt, int entry_size);

int onvm_natt_add_key(struct onvm_ft *table, struct onvm_ft_ipv4_5tuple *key, char **data);

int onvm_natt_lookup_key(struct onvm_ft *table, struct onvm_ft_ipv4_5tuple *key, char **data);

int32_t onvm_natt_remove_key(struct onvm_ft *table, struct onvm_ft_ipv4_5tuple *key);

void onvm_natt_free(struct onvm_ft *table);

#endif // L4_NAT_H_
