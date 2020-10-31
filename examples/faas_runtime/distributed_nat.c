
#include "distributed_nat.h"

struct onvm_ft *nat_table = NULL;

// Internal IP range: 10.0.0.0/8
bool is_internal_traffic(uint32_t target_ip) {
    uint32_t mask = 0xF000;
    return target_ip & mask == 0xA000;
}

void onvm_nat_fill_key(struct onvm_ft_ipv4_5tuple *key, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, int dir) {
    if (dir == 0) {
        key->src_addr = sip;
        key->src_port = sport;
        key->dst_addr = 0;
        key->dst_port = 0;
        key->proto = 0;
    } else {
        key->src_addr = dip;
        key->src_port = dport;
        key->dst_addr = 0;
        key->dst_port = 0;
        key->proto = 0;
    }
}

int onvm_nat_dir_init() {
        const struct rte_memzone *mz_ftp;

        nat_table = onvm_natt_create(NAT_ENTRIES, sizeof(struct Entry));
        if (nat_table == NULL) {
                rte_exit(EXIT_FAILURE, "Unable to create flow table\n");
        }
        return 0;
}

/*software caculate RSS for NAT table*/
static inline uint32_t
onvm_nat_softrss(struct onvm_ft_ipv4_5tuple *key) {
        union rte_thash_tuple tuple;
        uint8_t rss_key_be[RTE_DIM(rss_symmetric_key)];
        uint32_t rss_l3l4 = 0;

        rte_convert_rss_key((uint32_t *)rss_symmetric_key, (uint32_t *)rss_key_be, RTE_DIM(rss_symmetric_key));

        tuple.v4.src_addr = rte_be_to_cpu_32(key->src_addr);
        tuple.v4.dst_addr = rte_be_to_cpu_32(key->dst_addr);
        tuple.v4.sport = rte_be_to_cpu_16(key->src_port);
        tuple.v4.dport = rte_be_to_cpu_16(key->dst_port);

        rss_l3l4 = rte_softrss_be((uint32_t *)&tuple, RTE_THASH_V4_L4_LEN, rss_key_be);
        return rss_l3l4;
}

struct onvm_ft *
onvm_natt_create(int cnt, int entry_size) {
        struct rte_hash *hash;
        struct rte_hash_parameters *ipv4_hash_params;
        struct onvm_ft *ft;
        int status;

        ipv4_hash_params = (struct rte_hash_parameters *) rte_malloc(NULL, sizeof(struct rte_hash_parameters), 0);
        if (!ipv4_hash_params) {
                return NULL;
        }

        char *name = rte_malloc(NULL, 64, 0);
        /* create ipv4 hash table. use core number and cycle counter to get a unique name. */
        ipv4_hash_params->entries = cnt;
        ipv4_hash_params->key_len = sizeof(struct onvm_ft_ipv4_5tuple);
        ipv4_hash_params->hash_func = &onvm_ft_faas_hash_crc;
        ipv4_hash_params->hash_func_init_val = 0;
        ipv4_hash_params->name = name;
        ipv4_hash_params->socket_id = rte_socket_id();

        hash = rte_hash_create(ipv4_hash_params);

        if (!hash) {
                return NULL;
        }
        ft = (struct onvm_ft *) rte_calloc("table", 1, sizeof(struct onvm_ft), 0);
        if (!ft) {
                rte_hash_free(hash);
                return NULL;
        }
        ft->hash = hash;
        ft->cnt = cnt;
        ft->entry_size = entry_size;
        /* Create data array for storing values */
        ft->data = rte_calloc("entry", cnt, entry_size, 0);
        if (!ft->data) {
                rte_hash_free(hash);
                rte_free(ft);
                return NULL;
        }
        return ft;
}

int
onvm_natt_add_key(struct onvm_ft *table, struct onvm_ft_ipv4_5tuple *key, char **data) {
        int32_t tbl_index;
        uint32_t softrss;

        softrss = onvm_nat_softrss(key);

        tbl_index = rte_hash_add_key_with_hash(table->hash, (const void *)key, softrss);
        if (tbl_index >= 0) {
                *data = onvm_ft_get_data(table, tbl_index);
        }

        return tbl_index;
}

int
onvm_natt_lookup_key(struct onvm_ft *table, struct onvm_ft_ipv4_5tuple *key, char **data) {
        int32_t tbl_index;
        uint32_t softrss;

        softrss = onvm_nat_softrss(key);

        tbl_index = rte_hash_lookup_with_hash(table->hash, (const void *)key, softrss);
        if (tbl_index >= 0) {
                *data = onvm_ft_get_data(table, tbl_index);
        }

        return tbl_index;
}

int32_t
onvm_natt_remove_key(struct onvm_ft *table, struct onvm_ft_ipv4_5tuple *key) {
        uint32_t softrss;

        softrss = onvm_nat_softrss(key);
        return rte_hash_del_key_with_hash(table->hash, (const void *)key, softrss);
}

void
onvm_natt_free(struct onvm_ft *table) {
        rte_hash_reset(table->hash);
        rte_hash_free(table->hash);
        rte_free(table->data);
        rte_free(table);
        table = NULL;
}
