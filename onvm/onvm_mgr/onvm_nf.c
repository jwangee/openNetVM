/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *            2010-2019 Intel Corporation. All rights reserved.
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
 ********************************************************************/

/******************************************************************************

                              onvm_nf.c

       This file contains all functions related to NF management.

******************************************************************************/

#include "onvm_nf.h"
#include "onvm_mgr.h"
#include "onvm_stats.h"
#include <rte_lpm.h>

/* ID 0 is reserved */
uint16_t next_instance_id = 1;
uint16_t starting_instance_id = 1;

nf_schedule_info_t nf_sched_param;


/************************Internal functions prototypes************************/

/*
 * Function starting a NF.
 *
 * Input  : a pointer to the NF's informations
 * Output : an error code
 *
 */
inline static int
onvm_nf_start(struct onvm_nf_init_cfg *nf_init_cfg);

/*
 * Function to mark a NF as ready.
 *
 * Input  : a pointer to the NF's informations
 * Output : an error code
 *
 */
inline static int
onvm_nf_ready(struct onvm_nf *nf);

/*
 * Function stopping a NF.
 *
 * Input  : a pointer to the NF's informations
 * Output : an error code
 *
 */
inline static int
onvm_nf_stop(struct onvm_nf *nf);

/*
 * Function to move a NF to another core.
 *
 * Input  : instance id of the NF that needs to be moved
 *          new_core value of where the NF should be moved
 * Output : an error code
 *
 */
inline int
onvm_nf_relocate_nf(uint16_t nf, uint16_t new_core);

/*
 * Function that initializes an LPM object
 *
 * Input  : the address of an lpm_request struct
 * Output : a return code based on initialization of the LPM object
 *
 */
static void
onvm_nf_init_lpm_region(struct lpm_request *req_lpm);

/*
 * Function that initializes a hashtable for a flow_table struct
 *
 * Input : the address of a ft_request struct
 * Output : a return code based on initialization of a FT object (similar to LPM request)
 */
static void
onvm_nf_init_ft(struct ft_request *ft);

/*
 *  Set up the DPDK rings which will be used to pass packets, via
 *  pointers, between the multi-process server and NF processes.
 *  Each NF needs one RX queue.
 *
 *  Input: An nf struct
 *  Output: rte_exit if failed, none otherwise
 */
static void
onvm_nf_init_rings(struct onvm_nf *nf);

/********************************Interfaces***********************************/

uint16_t
onvm_nf_next_instance_id(void) {
        struct onvm_nf *nf;
        uint16_t instance_id;

        if (num_nfs >= MAX_NFS)
                return MAX_NFS;

        /* Do a first pass for NF IDs bigger than current next_instance_id */
        while (next_instance_id < MAX_NFS) {
                instance_id = next_instance_id++;
                /* Check if this id is occupied by another NF */
                nf = &nfs[instance_id];
                if (!onvm_nf_is_valid(nf))
                        return instance_id;
        }

        /* Reset to starting position */
        next_instance_id = starting_instance_id;

        /* Do a second pass for other NF IDs */
        while (next_instance_id < MAX_NFS) {
                instance_id = next_instance_id++;
                /* Check if this id is occupied by another NF */
                nf = &nfs[instance_id];
                if (!onvm_nf_is_valid(nf))
                        return instance_id;
        }

        /* This should never happen, means our num_nfs counter is wrong */
        RTE_LOG(ERR, APP, "Tried to allocated a next instance ID but num_nfs is corrupted\n");
        return MAX_NFS;
}

void
onvm_nf_check_status(void) {
        int i;
        void *msgs[MAX_NFS];
        struct onvm_nf *nf;
        struct onvm_nf_msg *msg;
        struct onvm_nf_init_cfg *nf_init_cfg;
        struct lpm_request *req_lpm;
        struct ft_request *ft;
        uint16_t stop_nf_id;
        int num_msgs = rte_ring_count(incoming_msg_queue);

        if (num_msgs == 0)
                return;

        if (rte_ring_dequeue_bulk(incoming_msg_queue, msgs, num_msgs, NULL) == 0)
                return;

        for (i = 0; i < num_msgs; i++) {
                msg = (struct onvm_nf_msg *)msgs[i];

                switch (msg->msg_type) {
                        case MSG_REQUEST_LPM_REGION:
                                // TODO: Add stats event handler here
                                req_lpm = (struct lpm_request *)msg->msg_data;
                                onvm_nf_init_lpm_region(req_lpm);
                                break;
                        case MSG_REQUEST_FT:
                                ft = (struct ft_request *) msg->msg_data;
                                onvm_nf_init_ft(ft);
                                break;
                        case MSG_NF_STARTING:
                                nf_init_cfg = (struct onvm_nf_init_cfg *)msg->msg_data;
                                if (onvm_nf_start(nf_init_cfg) == 0) {
                                        onvm_stats_gen_event_nf_info("NF Starting", &nfs[nf_init_cfg->instance_id]);
                                }
                                break;
                        case MSG_NF_READY:
                                nf = (struct onvm_nf *)msg->msg_data;
                                if (onvm_nf_ready(nf) == 0) {
                                        onvm_stats_gen_event_nf_info("NF Ready", nf);
                                }
                                break;
                        case MSG_NF_STOPPING:
                                nf = (struct onvm_nf *)msg->msg_data;
                                if (nf == NULL)
                                        break;

                                /* Saved as onvm_nf_stop frees the memory */
                                stop_nf_id = nf->instance_id;
                                if (onvm_nf_stop(nf) == 0) {
                                        onvm_stats_gen_event_info("NF Stopping", ONVM_EVENT_NF_STOP, &stop_nf_id);
                                }
                                break;
                }

                rte_mempool_put(nf_msg_pool, (void *)msg);
        }
}

int
onvm_nf_send_msg(uint16_t dest, uint8_t msg_type, void *msg_data) {
        int ret;
        struct onvm_nf_msg *msg;

        ret = rte_mempool_get(nf_msg_pool, (void **)(&msg));
        if (ret != 0) {
                RTE_LOG(INFO, APP, "Oh the huge manatee! Unable to allocate msg from pool :(\n");
                return ret;
        }

        msg->msg_type = msg_type;
        msg->msg_data = msg_data;

        return rte_ring_enqueue(nfs[dest].msg_q, (void *)msg);
}

/******************************Internal functions*****************************/

inline static int
onvm_nf_start(struct onvm_nf_init_cfg *nf_init_cfg) {
        struct onvm_nf *spawned_nf;
        uint16_t nf_id;
        int ret;

        if (nf_init_cfg == NULL || nf_init_cfg->status != NF_WAITING_FOR_ID)
                return 1;

        // if NF passed its own id on the command line, don't assign here
        // assume user is smart enough to avoid duplicates
        nf_id = nf_init_cfg->instance_id == (uint16_t)NF_NO_ID ? onvm_nf_next_instance_id() : nf_init_cfg->instance_id;
        spawned_nf = &nfs[nf_id];

        if (nf_id >= MAX_NFS) {
                // There are no more available IDs for this NF
                nf_init_cfg->status = NF_NO_IDS;
                return 1;
        }

        if (nf_init_cfg->service_id >= MAX_SERVICES) {
                // Service ID must be less than MAX_SERVICES and greater than 0
                nf_init_cfg->status = NF_SERVICE_MAX;
                return 1;
        }

        if (nf_per_service_count[nf_init_cfg->service_id] >= MAX_NFS_PER_SERVICE) {
                // Maximum amount of NF's per service spawned
                nf_init_cfg->status = NF_SERVICE_COUNT_MAX;
                return 1;
        }

        if (onvm_nf_is_valid(spawned_nf)) {
                // This NF is trying to declare an ID already in use
                nf_init_cfg->status = NF_ID_CONFLICT;
                return 1;
        }

        // Keep reference to this NF in the manager
        nf_init_cfg->instance_id = nf_id;

        /* If not successful return will contain the error code */
        ret = onvm_threading_get_core(&nf_init_cfg->core, nf_init_cfg->init_options, cores);
        if (ret != 0) {
                nf_init_cfg->status = ret;
                return 1;
        }

        spawned_nf->instance_id = nf_id;
        spawned_nf->service_id = nf_init_cfg->service_id;
        spawned_nf->status = NF_STARTING;
        spawned_nf->tag = nf_init_cfg->tag;
        spawned_nf->thread_info.core = nf_init_cfg->core;
        spawned_nf->flags.time_to_live = nf_init_cfg->time_to_live;
        spawned_nf->flags.pkt_limit = nf_init_cfg->pkt_limit;
        onvm_nf_init_rings(spawned_nf);

        // Let the NF continue its init process
        nf_init_cfg->status = NF_STARTING;
        return 0;
}

inline static int
onvm_nf_ready(struct onvm_nf *nf) {
        // Ensure we've already called nf_start for this NF
        if (nf->status != NF_STARTING)
                return -1;

        uint16_t service_count = nf_per_service_count[nf->service_id]++;
        services[nf->service_id][service_count] = nf->instance_id;
        num_nfs++;
        // Register this NF running within its service
        nf->status = NF_RUNNING;
        return 0;
}

inline static int
onvm_nf_stop(struct onvm_nf *nf) {
        uint16_t nf_id;
        uint16_t nf_status;
        uint16_t service_id;
        uint16_t nb_pkts, i;
        struct onvm_nf_msg *msg;
        struct rte_mempool *nf_info_mp;
        struct rte_mbuf *pkts[PACKET_READ_SIZE];
        uint16_t candidate_nf_id, candidate_core;
        int mapIndex;

        if (nf == NULL)
                return 1;

        nf_id = nf->instance_id;
        service_id = nf->service_id;
        nf_status = nf->status;
        candidate_core = nf->thread_info.core;

        /* Cleanup the allocated tag */
        if (nf->tag) {
                rte_free(nf->tag);
                nf->tag = NULL;
        }

        /* Cleanup should only happen if NF was starting or running */
        if (nf_status != NF_STARTING && nf_status != NF_RUNNING && nf_status != NF_PAUSED)
                return 1;

        nf->status = NF_STOPPED;
        nfs[nf->instance_id].status = NF_STOPPED;

        /* Tell parent we stopped running */
        if (nfs[nf_id].thread_info.parent != 0)
                rte_atomic16_dec(&nfs[nfs[nf_id].thread_info.parent].thread_info.children_cnt);

        /* Remove the NF from the core it was running on */
        cores[nf->thread_info.core].nf_count--;
        cores[nf->thread_info.core].is_dedicated_core = 0;

        /* Clean up possible left over objects in rings */
        while ((nb_pkts = rte_ring_dequeue_burst(nfs[nf_id].rx_q, (void **)pkts, PACKET_READ_SIZE, NULL)) > 0) {
                for (i = 0; i < nb_pkts; i++)
                        rte_pktmbuf_free(pkts[i]);
        }
        while ((nb_pkts = rte_ring_dequeue_burst(nfs[nf_id].tx_q, (void **)pkts, PACKET_READ_SIZE, NULL)) > 0) {
                for (i = 0; i < nb_pkts; i++)
                        rte_pktmbuf_free(pkts[i]);
        }
        nf_msg_pool = rte_mempool_lookup(_NF_MSG_POOL_NAME);
        while (rte_ring_dequeue(nfs[nf_id].msg_q, (void**)(&msg)) == 0) {
                rte_mempool_put(nf_msg_pool, (void*)msg);
        }

        /* Free info struct */
        /* Lookup mempool for nf struct */
        nf_info_mp = rte_mempool_lookup(_NF_MEMPOOL_NAME);
        if (nf_info_mp == NULL)
                return 1;

        rte_mempool_put(nf_info_mp, (void*)nf);

        /* Further cleanup is only required if NF was succesfully started */
        if (nf_status != NF_RUNNING && nf_status != NF_PAUSED)
                return 0;

        /* Decrease the total number of RUNNING NFs */
        num_nfs--;

        /* Reset stats */
        onvm_stats_clear_nf(nf_id);

        /* Remove this NF from the service map.
         * Need to shift all elements past it in the array left to avoid gaps */
        nf_per_service_count[service_id]--;
        for (mapIndex = 0; mapIndex < MAX_NFS_PER_SERVICE; mapIndex++) {
                if (services[service_id][mapIndex] == nf_id) {
                        break;
                }
        }

        if (mapIndex < MAX_NFS_PER_SERVICE) {  // sanity error check
                services[service_id][mapIndex] = 0;
                for (; mapIndex < MAX_NFS_PER_SERVICE - 1; mapIndex++) {
                        // Shift the NULL to the end of the array
                        if (services[service_id][mapIndex + 1] == 0) {
                                // Short circuit when we reach the end of this service's list
                                break;
                        }
                        services[service_id][mapIndex] = services[service_id][mapIndex + 1];
                        services[service_id][mapIndex + 1] = 0;
                }
        }

        /* As this NF stopped we can reevaluate core mappings */
        if (ONVM_NF_SHUTDOWN_CORE_REASSIGNMENT) {
                /* As this NF stopped we can reevaluate core mappings */
                candidate_nf_id = onvm_threading_find_nf_to_reassign_core(candidate_core, cores);
                if (candidate_nf_id > 0) {
                        onvm_nf_relocate_nf(candidate_nf_id, candidate_core);
                }
        }

        return 0;
}

static void
onvm_nf_init_lpm_region(struct lpm_request *req_lpm) {
        struct rte_lpm_config conf;
        struct rte_lpm* lpm_region;

        conf.max_rules = req_lpm->max_num_rules;
        conf.number_tbl8s = req_lpm->num_tbl8s;

        lpm_region = rte_lpm_create(req_lpm->name, req_lpm->socket_id, &conf);
        if (lpm_region) {
                req_lpm->status = 0;
        } else {
                req_lpm->status = -1;
        }
}

static void
onvm_nf_init_ft(struct ft_request *ft) {
        struct rte_hash *hash;

        hash = rte_hash_create(ft->ipv4_hash_params);
        if (hash) {
                ft->status = 0;
        } else {
                ft->status = -1;
        }
}

inline int
onvm_nf_relocate_nf(uint16_t dest, uint16_t new_core) {
        uint16_t *msg_data;

        msg_data = rte_malloc("Change core msg data", sizeof(uint16_t), 0);
        *msg_data = new_core;

        cores[nfs[dest].thread_info.core].nf_count--;

        onvm_nf_send_msg(dest, MSG_CHANGE_CORE, msg_data);

        /* We probably need logic that handles if everything is successful */

        /* TODO Add core number */
        onvm_stats_gen_event_nf_info("NF Ready", &nfs[dest]);

        cores[new_core].nf_count++;
        return 0;
}

static void
onvm_nf_init_rings(struct onvm_nf *nf) {
        unsigned instance_id;
        unsigned socket_id;
        const char *rq_name;
        const char *tq_name;
        const char *msg_q_name;
        const unsigned ringsize = NF_QUEUE_RINGSIZE;
        const unsigned msgringsize = NF_MSG_QUEUE_SIZE;

        instance_id = nf->instance_id;
        socket_id = rte_socket_id();
        rq_name = get_rx_queue_name(instance_id);
        tq_name = get_tx_queue_name(instance_id);
        msg_q_name = get_msg_queue_name(instance_id);
        nf->rx_q =
                rte_ring_create(rq_name, ringsize, socket_id, RING_F_SC_DEQ); /* multi prod, single cons */
        nf->tx_q =
                rte_ring_create(tq_name, ringsize, socket_id, RING_F_SC_DEQ); /* multi prod, single cons */
        nf->msg_q =
                rte_ring_create(msg_q_name, msgringsize, socket_id,
                                RING_F_SC_DEQ); /* multi prod, single cons */

        if (nf->rx_q == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create rx ring queue for NF %u\n", instance_id);

        if (nf->tx_q == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create tx ring queue for NF %u\n", instance_id);

        if (nf->msg_q == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create msg queue for NF %u\n", instance_id);
}

// NFVNice functions
/*
// Each entry tells whether a service chain is considered as the bottleneck.
typedef struct sc_entries {
        struct onvm_service_chain *sc;
        uint16_t sc_count;
        uint16_t bneck_flag;
}sc_entries_list;
*/
//Local Data structure to compute nf_load and comp_cost contention on each core
typedef struct nf_core_and_cc_info {
        uint64_t total_comp_cost;       //total computation cost on the core (sum of all NFs computation cost)
        uint32_t total_nf_count;        //total count of the NFs on the core (sum of all NFs)
        uint64_t total_pkts_served;     //total pkts processed on the core (sum of all NFs packet processed).
        uint64_t total_load;            //total pkts (avergae) queued up on the core for processing.
        uint64_t total_load_cost_fct;   //total product of current load and computation cost on core (aggregate demand in total cycles)
}nf_core_and_cc_info_t;

static sc_entries_list sc_list[SDN_FT_ENTRIES];
//bottlenec_nf_info_t bottleneck_nf_list;

int
onvm_mark_all_entries_for_bottleneck(uint16_t nf_id) {
        int ret = 0;
        uint32_t ttl_chains = extract_sc_list(NULL, sc_list);

        //There must be valid chains
        if(ttl_chains) {
                uint32_t s_inx = 0;
                for(s_inx=0; s_inx <SDN_FT_ENTRIES; s_inx++) {
                        if(sc_list[s_inx].sc) {
                                int i =0;
                                for(i=1;i<=sc_list[s_inx].sc->chain_length;++i) {
                                        if(nf_id == sc_list[s_inx].sc->nf_instance_id[i]) {
                                                //mark this sc with this index;;
                                                if(!(TEST_BIT(sc_list[s_inx].sc->highest_downstream_nf_index_id, i))) {
                                                        SET_BIT(sc_list[s_inx].sc->highest_downstream_nf_index_id, i);
                                                        break;
                                                }
                                        }
                                }
                                #ifdef NF_BACKPRESSURE_APPROACH_2
                                uint32_t index = (i-1);
                                //for(; index < meta->chain_index; index++ ) {
                                for(; index >=1 ; index-- ) {
                                        nfs[sc_list[s_inx].sc->nf_instance_id[index]].throttle_this_upstream_nf=1;
                                }
                                #endif  //NF_BACKPRESSURE_APPROACH_2

                        }
                        else {
                                break;  //reached end of schains list;
                        }
                }
        }
        return ret;
}

int
onvm_clear_all_entries_for_bottleneck(uint16_t nf_id) {
        int ret = 0;
        uint32_t bneck_chains = 0;
        uint32_t ttl_chains = extract_sc_list(&bneck_chains, sc_list);

        //There must be chains with bottleneck indications
        if(ttl_chains && bneck_chains) {
                uint32_t s_inx = 0;
                for(s_inx=0; s_inx < SDN_FT_ENTRIES; s_inx++) {
                        if(NULL == sc_list[s_inx].sc) break;    //reached end of chains list
                        if(sc_list[s_inx].bneck_flag) {
                                int i =0;
                                for(i=1;i<=sc_list[s_inx].sc->chain_length;++i) {
                                        if(nf_id == sc_list[s_inx].sc->nf_instance_id[i]) {
                                                //clear this sc with this index;;
                                                if((TEST_BIT(sc_list[s_inx].sc->highest_downstream_nf_index_id, i))) {
                                                        CLEAR_BIT(sc_list[s_inx].sc->highest_downstream_nf_index_id, i);
                                                        //break;
                                                }
                                        }
                                }

                                #ifdef NF_BACKPRESSURE_APPROACH_2
                                // detect the start nf_index based on new val of highest_downstream_nf_index_id
                                int nf_index=(sc_list[s_inx].sc->highest_downstream_nf_index_id == 0)? (1): (get_index_of_highest_set_bit(sc_list[s_inx].sc->highest_downstream_nf_index_id));
                                for(; nf_index < i; nf_index++) {
                                       nfs[sc_list[s_inx].sc->nf_instance_id[nf_index]].throttle_this_upstream_nf=0;
                                }
                                #endif  //NF_BACKPRESSURE_APPROACH_2
                        }
                }
        }

        return ret;
}

int enqueu_nf_to_bottleneck_watch_list(uint16_t nf_id) {
        if(bottleneck_nf_list.nf[nf_id].enqueue_status) return 1;

        bottleneck_nf_list.nf[nf_id].enqueue_status = BOTTLENECK_NF_STATUS_WAIT_ENQUEUED;
        bottleneck_nf_list.nf[nf_id].nf_id = nf_id;
        get_current_time(&bottleneck_nf_list.nf[nf_id].s_time);
        bottleneck_nf_list.nf[nf_id].enqueued_ctr+=1;
        bottleneck_nf_list.entires++;
        return 0;
}

int dequeue_nf_from_bottleneck_watch_list(uint16_t nf_id) {
        if(!bottleneck_nf_list.nf[nf_id].enqueue_status) return 1;

        bottleneck_nf_list.nf[nf_id].enqueue_status = BOTTLENECK_NF_STATUS_RESET;
        bottleneck_nf_list.nf[nf_id].nf_id = nf_id;
        get_current_time(&bottleneck_nf_list.nf[nf_id].s_time);
        bottleneck_nf_list.entires--;
        return 0;
}

int check_and_enqueue_or_dequeue_nfs_from_bottleneck_watch_list(void) {
        dump_sdn_ft();

        int ret = 0;
        uint16_t nf_id = 0;
        struct timespec now;
        get_current_time(&now);
        for(; nf_id < MAX_NFS; nf_id++) {

                if(BOTTLENECK_NF_STATUS_RESET == bottleneck_nf_list.nf[nf_id].enqueue_status) continue;
                //is in enqueue list and marked
                else if (BOTTLENECK_NF_STATUS_DROP_MARKED & bottleneck_nf_list.nf[nf_id].enqueue_status) {
                        if(rte_ring_count(nfs[nf_id].rx_q) < CLIENT_QUEUE_RING_LOW_WATER_MARK_SIZE) {
                                onvm_clear_all_entries_for_bottleneck(nf_id);
                                dequeue_nf_from_bottleneck_watch_list(nf_id);
                                bottleneck_nf_list.nf[nf_id].enqueue_status = BOTTLENECK_NF_STATUS_RESET;
                                nfs[nf_id].is_bottleneck = 0;
                        }
                        //else keep as marked.
                }
                //is in enqueue list but not marked
                else if(BOTTLENECK_NF_STATUS_WAIT_ENQUEUED & bottleneck_nf_list.nf[nf_id].enqueue_status) {
                        //ring count is still beyond the water mark threshold
                        if(rte_ring_count(nfs[nf_id].rx_q) >= CLIENT_QUEUE_RING_WATER_MARK_SIZE) {
                                if((0 == WAIT_TIME_BEFORE_MARKING_OVERFLOW_IN_US)||((WAIT_TIME_BEFORE_MARKING_OVERFLOW_IN_US) + 1 <= get_difftime_us(&bottleneck_nf_list.nf[nf_id].s_time, &now))) {
                                        bottleneck_nf_list.nf[nf_id].enqueue_status = BOTTLENECK_NF_STATUS_DROP_MARKED;
                                        onvm_mark_all_entries_for_bottleneck(nf_id);
                                        bottleneck_nf_list.nf[nf_id].marked_ctr+=1;
                                        nfs[nf_id].stats.bkpr_count++;
                                }
                                //else //time has not expired.. continue to monitor..
                        }
                        //ring count has dropped
                        else  if(rte_ring_count(nfs[nf_id].rx_q) < CLIENT_QUEUE_RING_LOW_WATER_MARK_SIZE) {
                                if((0 == WAIT_TIME_BEFORE_MARKING_OVERFLOW_IN_US)||((WAIT_TIME_BEFORE_MARKING_OVERFLOW_IN_US) + 1 <= get_difftime_us(&bottleneck_nf_list.nf[nf_id].s_time, &now))) {
                                        dequeue_nf_from_bottleneck_watch_list(nf_id);
                                        bottleneck_nf_list.nf[nf_id].enqueue_status = BOTTLENECK_NF_STATUS_RESET;
                                        nfs[nf_id].is_bottleneck = 0;
                                }
                                //else //time has not expired.. continue to monitor..
                        }
                }

        }
        return ret;
}

// NFVNice functions - cgroup
#define DEFAULT_NF_CPU_SHARE    (1024)

/*
 * This function computes and assigns weights to each nfs cgroup based on its contention and requirements
 * PRerequisite: nfs[]->info->comp_cost and  nfs[]->info->load should be already updated.  -- updated by extract_nf_load_and_svc_rate_info()
 */
static inline void assign_nf_cgroup_weight(uint16_t nf_id) {
        if ((onvm_nf_is_valid(&nfs[nf_id])) && (nfs[nf_id].info && nfs[nf_id].info->comp_cost)) {
                set_cgroup_nf_cpu_share_from_onvm_mgr(nfs[nf_id].info->instance_id, nfs[nf_id].info->cpu_share);
        }
}

static inline void assign_all_nf_cgroup_weight(void) {
        uint16_t nf_id = 0;
        for (nf_id=0; nf_id < MAX_NFS; nf_id++) {
                assign_nf_cgroup_weight(nf_id);
        }
}

void compute_nf_exec_period_and_cgroup_weight(void) {

#if defined (USE_CGROUPS_PER_NF_INSTANCE)

        const uint64_t total_cycles_in_epoch = ARBITER_PERIOD_IN_US *(rte_get_timer_hz()/1000000);
        static nf_core_and_cc_info_t nfs_on_core[MAX_CORES_ON_NODE];

        uint16_t nf_id = 0;
        memset(nfs_on_core, 0, sizeof(nfs_on_core));

        //First build the total cost and contention info per core
        for (nf_id=0; nf_id < MAX_NFS; nf_id++) {
                if (onvm_nf_is_valid(&nfs[nf_id])){
                        nfs_on_core[nfs[nf_id].info->core_id].total_comp_cost += nfs[nf_id].info->comp_cost;
                        nfs_on_core[nfs[nf_id].info->core_id].total_nf_count++;
                        nfs_on_core[nfs[nf_id].info->core_id].total_load += nfs[nf_id].info->load;            //nfs[nf_id].info->avg_load;
                        nfs_on_core[nfs[nf_id].info->core_id].total_pkts_served += nfs[nf_id].info->svc_rate; //nfs[nf_id].info->avg_svc;
                        nfs_on_core[nfs[nf_id].info->core_id].total_load_cost_fct += (nfs[nf_id].info->comp_cost*nfs[nf_id].info->load);
                }
        }

        //evaluate and assign the cost of each NF
        // Any one of them is not working properly. Do not update cgroup info.
        for (nf_id=0; nf_id < MAX_NFS; nf_id++) {
                if ((onvm_nf_is_valid(&nfs[nf_id])) && (!nfs[nf_id].info->comp_cost)) {
                    return;
                }
        }

        for (nf_id=0; nf_id < MAX_NFS; nf_id++) {
                if ((onvm_nf_is_valid(&nfs[nf_id])) && (nfs[nf_id].info->comp_cost)) {

                        // share of NF = 1024* NF_comp_cost/Total_comp_cost
                        //Note: ideal share of NF is 100%(1024) so for N NFs sharing core => N*100 or (N*1024) then divide the cost proportionally
#ifndef USE_DYNAMIC_LOAD_FACTOR_FOR_CPU_SHARE
                        //Static accounting based on computation_cost_only
                        if(nfs_on_core[nfs[nf_id].info->core_id].total_comp_cost) {
                                nfs[nf_id].info->cpu_share = (uint32_t) ((DEFAULT_NF_CPU_SHARE*nfs_on_core[nfs[nf_id].info->core_id].total_nf_count)*(nfs[nf_id].info->comp_cost))
                                                /((nfs_on_core[nfs[nf_id].info->core_id].total_comp_cost));

                                nfs[nf_id].info->exec_period = ((nfs[nf_id].info->comp_cost)*total_cycles_in_epoch)/nfs_on_core[nfs[nf_id].info->core_id].total_comp_cost; //(total_cycles_in_epoch)*(total_load_on_core)/(load_of_nf)
                        }
                        else {
                                nfs[nf_id].info->cpu_share = (uint32_t)DEFAULT_NF_CPU_SHARE;
                                nfs[nf_id].info->exec_period = 0;

                        }

                        #ifdef __DEBUG_LOGS__
                        printf("\n ***** Client [%d] with cost [%d] on core [%d] with total_demand [%d] shared by [%d] NFs, got cpu share [%d]***** \n ", nfs[nf_id].info->instance_id, nfs[nf_id].info->comp_cost, nfs[nf_id].info->core_id,
                                                                                                                                                   nfs_on_core[nfs[nf_id].info->core_id].total_comp_cost,
                                                                                                                                                   nfs_on_core[nfs[nf_id].info->core_id].total_nf_count,
                                                                                                                                                   nfs[nf_id].info->cpu_share);
                        #endif //__DEBUG_LOGS__

#else
                        uint64_t num = 0;
                        //Dynamic: Based on accounting the product of Load*comp_cost factors. We can define the weights Alpha(\u03b1) and Beta(\u03b2) for apportioning Load and Comp_Costs: (\u03b1*nfs[nf_id].info->load)*(\u03b2*nfs[nf_id].info->comp_cost) | \u03b2*\u03b1 = 1.
                        if (nfs_on_core[nfs[nf_id].info->core_id].total_load_cost_fct) {

                                num = (uint64_t)(nfs_on_core[nfs[nf_id].info->core_id].total_nf_count)*(DEFAULT_NF_CPU_SHARE)*(nfs[nf_id].info->comp_cost)*(nfs[nf_id].info->load);
                                nfs[nf_id].info->cpu_share = (uint32_t) (num/nfs_on_core[nfs[nf_id].info->core_id].total_load_cost_fct);
                                //nfs[nf_id].info->cpu_share = ((uint64_t)(((DEFAULT_NF_CPU_SHARE*nfs_on_core[nfs[nf_id].info->core_id].total_nf_count)*(nfs[nf_id].info->comp_cost*nfs[nf_id].info->load)))
                                //                /((nfs_on_core[nfs[nf_id].info->core_id].total_load_cost_fct)));
                                nfs[nf_id].info->exec_period = ((nfs[nf_id].info->comp_cost)*(nfs[nf_id].info->load)*total_cycles_in_epoch)/nfs_on_core[nfs[nf_id].info->core_id].total_load_cost_fct; //(total_cycles_in_epoch)*(total_load_on_core)/(load_of_nf)
                        }
                        else {
                                nfs[nf_id].info->cpu_share = (uint32_t)DEFAULT_NF_CPU_SHARE;
                                nfs[nf_id].info->exec_period = 0;
                        }
                        #ifdef __DEBUG_LOGS__
                        printf("\n ***** Client [%d] with cost [%d] and load [%d] on core [%d] with total_demand_comp_cost=%"PRIu64", shared by [%d] NFs, got num=%"PRIu64", cpu share [%d]***** \n ", nfs[nf_id].info->instance_id, nfs[nf_id].info->comp_cost, nfs[nf_id].info->load, nfs[nf_id].info->core_id,
                                                                                                                                                   nfs_on_core[nfs[nf_id].info->core_id].total_load_cost_fct,
                                                                                                                                                   nfs_on_core[nfs[nf_id].info->core_id].total_nf_count,
                                                                                                                                                   num, nfs[nf_id].info->cpu_share);
                        #endif //__DEBUG_LOGS__
#endif //USE_DYNAMIC_LOAD_FACTOR_FOR_CPU_SHARE

                }
        }
#endif // #if defined (USE_CGROUPS_PER_NF_INSTANCE)
}

void
onvm_nf_stats_update(__attribute__((unused)) unsigned long interval) {
    assign_all_nf_cgroup_weight();
}

static inline void extract_nf_load_and_svc_rate_info(__attribute__((unused)) unsigned long interval) {
#if defined (USE_CGROUPS_PER_NF_INSTANCE)
        uint16_t nf_id = 0;
        for (; nf_id < MAX_NFS; nf_id++) {
                struct onvm_nf *cl = &nfs[nf_id];
                if (onvm_nf_is_valid(cl)){
                        static onvm_stats_snapshot_t st;
                        get_onvm_nf_stats_snapshot_v2(nf_id, &st, 500000);
                        cl->info->load      =  (st.rx_delta + st.rx_drop_delta);//(cl->stats.rx - cl->stats.prev_rx + cl->stats.rx_drop - cl->stats.prev_rx_drop); //rte_ring_count(cl->rx_q);
                        cl->info->avg_load  =  ((cl->info->avg_load == 0) ? (cl->info->load):((cl->info->avg_load + cl->info->load) /2));   // (((1-EWMA_LOAD_ADECAY)*cl->info->avg_load) + (EWMA_LOAD_ADECAY*cl->info->load))
                        cl->info->svc_rate  =  (st.tx_delta); //(nfs_stats->tx[nf_id] -  nfs_stats->prev_tx[nf_id]);
                        cl->info->avg_svc   =  ((cl->info->avg_svc == 0) ? (cl->info->svc_rate):((cl->info->avg_svc + cl->info->svc_rate) /2));
                        cl->info->drop_rate =  (st.rx_drop_rate);

#ifdef STORE_HISTOGRAM_OF_NF_COMPUTATION_COST
                        //Get the Median Computation cost, instead of running average; else running average is expected to be set already.
                        cl->info->comp_cost = hist_extract_v2(&cl->info->ht2, VAL_TYPE_MEDIAN);
#else
                        cl->info->comp_cost = cl->info->comp_cost;
#endif //STORE_HISTOGRAM_OF_NF_COMPUTATION_COST
                }
                else if (cl && cl->info) {
                        cl->info->load      = 0;
                        cl->info->avg_load  = 0;
                        cl->info->svc_rate  = 0;
                        cl->info->avg_svc   = 0;
                }
        }

        //compute the execution_period_and_cgroup_weight    -- better to separate the two??
        compute_nf_exec_period_and_cgroup_weight();

        //sort and prepare the list of nfs_per_core_per_pool in the decreasing order of priority; use this list to wake up the NFs
        setup_nfs_priority_per_core_list(interval);
#endif
}

void setup_nfs_priority_per_core_list(__attribute__((unused)) unsigned long interval) {
#ifdef USE_CGROUPS_PER_NF_INSTANCE
        memset(&nf_sched_param, 0, sizeof(nf_sched_param));
        uint16_t nf_id = 0;
        for (nf_id=0; nf_id < MAX_NFS; nf_id++) {
                if ((onvm_nf_is_valid(&nfs[nf_id])) /* && (nfs[nf_id].info->comp_cost)*/) {
                        nf_sched_param.nf_list_per_core[nfs[nf_id].info->core_id].nf_ids[nf_sched_param.nf_list_per_core[nfs[nf_id].info->core_id].count++] = nf_id;
                        nf_sched_param.nf_list_per_core[nfs[nf_id].info->core_id].run_time[nf_id] = nfs[nf_id].info->exec_period;
                }
        }
        uint16_t core_id = 0;
        for(core_id=0; core_id < MAX_CORES_ON_NODE; core_id++) {
                if(!nf_sched_param.nf_list_per_core[core_id].count) continue;
                //onvm_sort_generic(nf_sched_param.nf_list_per_core[core_id].nf_ids, ONVM_SORT_TYPE_CUSTOM, SORT_DESCENDING, nf_sched_param.nf_list_per_core[core_id].count, sizeof(nf_sched_param.nf_list_per_core[core_id].nf_ids[0]), nf_sort_func);
                nf_sched_param.nf_list_per_core[core_id].sorted=1;
#if 0
                {
                        unsigned x = 0;
                        printf("\n********** Sorted NFs on Core [%d]: ", core_id);
                        for (x=0; x< nf_sched_param.nf_list_per_core[core_id].count; x++) {
                                printf("[%d],", nf_sched_param.nf_list_per_core[core_id].nf_ids[x]);
                        }
                }
#endif
        }
        nf_sched_param.sorted=1;
        #endif //USE_CGROUPS_PER_NF_INSTANCE
}

void compute_and_order_nf_wake_priority(void) {
        //Decouple The evaluation and wakee-up logic : move the code to main thread, which can perform this periodically;
        /* Firs:t extract load charactersitics in this epoch
         * Second: sort and prioritize NFs based on the demand matrix in this epoch
         * Finally: wake up the tasks in the identified priority
         * */
#if defined (USE_CGROUPS_PER_NF_INSTANCE)
        extract_nf_load_and_svc_rate_info(0);   //setup_nfs_priority_per_core_list(0);
#endif  //USE_CGROUPS_PER_NF_INSTANCE
        return;
}

void monitor_nf_node_liveliness_via_pid_monitoring(void) {
        uint16_t nf_id = 0;

        for (; nf_id < MAX_NFS; nf_id++) {
                if (onvm_nf_is_valid(&nfs[nf_id])){
                        if (kill(nfs[nf_id].info->pid, 0)) {
                                printf("\n\n******* Moving NF with InstanceID:%d state %d to STOPPED\n\n",nfs[nf_id].info->instance_id, nfs[nf_id].info->status);
                                nfs[nf_id].info->status = NF_STOPPED;
                                //**** TO DO: Take necessary actions here: It still doesn't clean-up until the new_nf_pool is populated by adding/killing another NF instance.
                                rte_ring_enqueue(nf_info_queue, nfs[nf_id].info);
                                rte_mempool_put(nf_info_pool, nfs[nf_id].info);
                                // Still the IDs are not recycled.. missing some additional changes:: found bug in the way the IDs are recycled-- fixed change in onvm_nf_next_instance_id()
                        }
                }
        }
}

int nf_sort_func(const void * a, const void *b) {
        uint32_t nfid1 = *(const uint32_t*)a;
        uint32_t nfid2 = *(const uint32_t*)b;
        struct onvm_nf *cl1 = &nfs[nfid1];
        struct onvm_nf *cl2 = &nfs[nfid2];

        if(!cl1 || !cl2) return 0;

#if defined (USE_CGROUPS_PER_NF_INSTANCE)
        if(cl1->info->load < cl2->info->load) return 1;
        else if (cl1->info->load > cl2->info->load) return (-1);
#endif //USE_CGROUPS_PER_NF_INSTANCE

        return 0;
}
