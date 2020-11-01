/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * onvm_flow_dir.c - flow director APIs
 ********************************************************************/

#include "onvm_flow_dir.h"
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "onvm_common.h"
#include "onvm_flow_table.h"

#define NO_FLAGS 0

struct onvm_ft *sdn_ft;
struct onvm_ft **sdn_ft_p;

int
onvm_flow_dir_init(void) {
        const struct rte_memzone *mz_ftp;

        sdn_ft = onvm_ft_create(SDN_FT_ENTRIES, sizeof(struct onvm_flow_entry));
        if (sdn_ft == NULL) {
                rte_exit(EXIT_FAILURE, "Unable to create flow table\n");
        }
        mz_ftp = rte_memzone_reserve(MZ_FTP_INFO, sizeof(struct onvm_ft *), rte_socket_id(), NO_FLAGS);
        if (mz_ftp == NULL) {
                rte_exit(EXIT_FAILURE, "Canot reserve memory zone for flow table pointer\n");
        }
        memset(mz_ftp->addr, 0, sizeof(struct onvm_ft *));
        sdn_ft_p = mz_ftp->addr;
        *sdn_ft_p = sdn_ft;

        return 0;
}

int
onvm_flow_dir_nf_init(void) {
        const struct rte_memzone *mz_ftp;
        struct onvm_ft **ftp;

        mz_ftp = rte_memzone_lookup(MZ_FTP_INFO);
        if (mz_ftp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get table pointer\n");
        ftp = mz_ftp->addr;
        sdn_ft = *ftp;

        return 0;
}

int
onvm_flow_dir_get_pkt(struct rte_mbuf *pkt, struct onvm_flow_entry **flow_entry) {
        int ret;
        ret = onvm_ft_lookup_pkt(sdn_ft, pkt, (char **)flow_entry);

        return ret;
}

int
onvm_flow_dir_add_pkt(struct rte_mbuf *pkt, struct onvm_flow_entry **flow_entry) {
        int ret;
        ret = onvm_ft_add_pkt(sdn_ft, pkt, (char **)flow_entry);

        return ret;
}

int
onvm_flow_dir_del_pkt(struct rte_mbuf *pkt) {
        int ret;
        struct onvm_flow_entry *flow_entry;
        int ref_cnt;

        ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (ret >= 0) {
                ref_cnt = flow_entry->sc->ref_cnt--;
                if (ref_cnt <= 0) {
                        ret = onvm_flow_dir_del_and_free_pkt(pkt);
                }
        }

        return ret;
}

int
onvm_flow_dir_del_and_free_pkt(struct rte_mbuf *pkt) {
        int ret;
        struct onvm_flow_entry *flow_entry;

        ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (ret >= 0) {
                rte_free(flow_entry->sc);
                rte_free(flow_entry->key);
                ret = onvm_ft_remove_pkt(sdn_ft, pkt);
        }

        return ret;
}

int
onvm_flow_dir_get_key(struct onvm_ft_ipv4_5tuple *key, struct onvm_flow_entry **flow_entry) {
        int ret;
        ret = onvm_ft_lookup_key(sdn_ft, key, (char **)flow_entry);

        return ret;
}

int
onvm_flow_dir_add_key(struct onvm_ft_ipv4_5tuple *key, struct onvm_flow_entry **flow_entry) {
        int ret;
        ret = onvm_ft_add_key(sdn_ft, key, (char **)flow_entry);

        return ret;
}

int
onvm_flow_dir_del_key(struct onvm_ft_ipv4_5tuple *key) {
        int ret;
        struct onvm_flow_entry *flow_entry;
        int ref_cnt;

        ret = onvm_flow_dir_get_key(key, &flow_entry);
        if (ret >= 0) {
                ref_cnt = flow_entry->sc->ref_cnt--;
                if (ref_cnt <= 0) {
                        ret = onvm_flow_dir_del_and_free_key(key);
                }
        }

        return ret;
}

int
onvm_flow_dir_del_and_free_key(struct onvm_ft_ipv4_5tuple *key) {
        int ret;
        struct onvm_flow_entry *flow_entry;

        ret = onvm_flow_dir_get_key(key, &flow_entry);
        if (ret >= 0) {
                rte_free(flow_entry->sc);
                rte_free(flow_entry->key);
                ret = onvm_ft_remove_key(sdn_ft, key);
        }

        return ret;
}

// NFVNice functions
static inline uint32_t get_index_of_sc(struct onvm_service_chain *sc, sc_entries_list *c_list) {
        uint32_t free_index = SDN_FT_ENTRIES;
        uint32_t i = 0;
        for (i=0; i<SDN_FT_ENTRIES; i++) {
                if (c_list[i].sc) {
                        if(c_list[i].sc == sc) {
                                return i;
                        }
                }
                else {
                        free_index = ((i < free_index)? (i):(free_index));
                }
        }
        return free_index;
}

uint32_t dump_sdn_ft(void) {
    uint32_t cnt_flow_entries = 0;
    uint32_t cnt_valid_flow_entries = 0;
    int32_t tbl_index = 0;
    for (; tbl_index < SDN_FT_ENTRIES; tbl_index++) {
        struct onvm_flow_entry *flow_entry = (struct onvm_flow_entry *)&sdn_ft->data[tbl_index*sdn_ft->entry_size];
        if (flow_entry && flow_entry->sc) {
            ++cnt_flow_entries;
            if (flow_entry->sc->chain_length) {
                ++cnt_valid_flow_entries;
                //fprintf(stdout, "chain len: %d, highest down: %d\n", flow_entry->sc->chain_length, flow_entry->sc->highest_downstream_nf_index_id);
            }
        }
    }

    //fprintf(stdout, "sdn_ft: %d entries, %d valid entries\n", cnt_flow_entries, cnt_valid_flow_entries);
    return cnt_flow_entries;
}

uint32_t
extract_sc_list(uint32_t *bft_count, sc_entries_list *c_list) {
        uint32_t active_fts = 0, bneck_fts=0;
        if(!c_list) return -1;
        if(sdn_ft) {
                int32_t tbl_index = 0;
                uint32_t s_inx = SDN_FT_ENTRIES;

                memset(c_list,0,sizeof(*c_list));

                for (; tbl_index < SDN_FT_ENTRIES; tbl_index++) {
                        s_inx = SDN_FT_ENTRIES;
                        struct onvm_flow_entry *flow_entry = (struct onvm_flow_entry *)&sdn_ft->data[tbl_index*sdn_ft->entry_size];
                        if (flow_entry && flow_entry->sc && flow_entry->sc->chain_length) {
                                active_fts+=1;
                                s_inx = get_index_of_sc(flow_entry->sc, c_list);
                                if(s_inx < SDN_FT_ENTRIES) {
                                        c_list[s_inx].sc = flow_entry->sc;
                                        c_list[s_inx].sc_count+=1;
                                        if(1 == c_list[s_inx].sc_count) c_list[s_inx].bneck_flag=0;
                                }
                        }
                        else continue;

                        #ifdef ENABLE_NF_BACKPRESSURE
                        if (flow_entry->sc->highest_downstream_nf_index_id) {
                                bneck_fts++;
                                if(s_inx < SDN_FT_ENTRIES) {
                                        c_list[s_inx].bneck_flag+=1;
                                }
                                #define LIST_FLOW_ENTRIES
                                #ifdef LIST_FLOW_ENTRIES
                                int i =0;
                                fprintf(stdout, "OverflowStatus [(binx=%d, %d),(nfid=%d),(scl=%d)::", flow_entry->sc->highest_downstream_nf_index_id, flow_entry->idle_timeout, flow_entry->sc->ref_cnt, flow_entry->sc->chain_length );
                                for(i=1;i<=flow_entry->sc->chain_length;++i)printf("[%d], ",flow_entry->sc->sc[i].destination);
                                if(flow_entry->key)
                                        fprintf(stdout, "Tuple:[SRC(%d:%d),DST(%d:%d), PROTO(%d)], \t", flow_entry->key->src_addr, rte_be_to_cpu_16(flow_entry->key->src_port), flow_entry->key->dst_addr, rte_be_to_cpu_16(flow_entry->key->dst_port), flow_entry->key->proto);
                                fprintf(stdout, "\n");
                                #endif
                        }
                        #endif  //ENABLE_NF_BACKPRESSURE
                }
        }
        if(bft_count)*bft_count = bneck_fts;

        return active_fts;
}
