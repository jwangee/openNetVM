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
                                 onvm_pkt.c

            This file contains all functions related to receiving or
            transmitting packets.

******************************************************************************/

#include "onvm_mgr.h"

#include "onvm_nf.h"
#include "onvm_pkt.h"

/**********************************Interfaces*********************************/

void
onvm_pkt_process_rx_batch(struct queue_mgr *rx_mgr, struct rte_mbuf *pkts[], uint16_t rx_count) {
        uint16_t i;
        struct onvm_pkt_meta *meta;
#ifdef FLOW_LOOKUP
        struct onvm_flow_entry *flow_entry;
        struct onvm_service_chain *sc;
        int ret;
#endif

        if (rx_mgr == NULL || pkts == NULL)
                return;

        for (i = 0; i < rx_count; i++) {
                meta = (struct onvm_pkt_meta *)&(((struct rte_mbuf *)pkts[i])->udata64);
                meta->src = 0;
                meta->chain_index = 0;

#ifdef FAAS_HASH
                struct rte_ipv4_hdr *ipv4_hdr = onvm_pkt_ipv4_hdr(pkts[i]);
                struct rte_tcp_hdr *tcp_hdr;
                struct rte_udp_hdr *udp_hdr;
                if (ipv4_hdr->next_proto_id == IP_PROTOCOL_TCP) {
                    tcp_hdr = onvm_pkt_tcp_hdr(pkts[i]);
                    pkts[i]->hash.rss = tcp_hdr->dst_port;
                } else if (ipv4_hdr->next_proto_id == IP_PROTOCOL_UDP) {
                    udp_hdr = onvm_pkt_udp_hdr(pkts[i]);
                    pkts[i]->hash.rss = udp_hdr->dst_port;
                }
#endif

#ifdef FLOW_LOOKUP
                ret = onvm_flow_dir_get_pkt(pkts[i], &flow_entry);
                if (ret >= 0) {
                        sc = flow_entry->sc;
                        meta->action = onvm_sc_next_action(sc, pkts[i]);
                        meta->destination = onvm_sc_next_destination(sc, pkts[i]);
                } else {
#endif
                        meta->action = onvm_sc_next_action(default_chain, pkts[i]);
                        meta->destination = onvm_sc_next_destination(default_chain, pkts[i]);
#ifdef FLOW_LOOKUP
                }
#endif
                /* PERF: this might hurt performance since it will cause cache
                 * invalidations. Ideally the data modified by the NF manager
                 * would be a different line than that modified/read by NFs.
                 * That may not be possible.
                 */

                (meta->chain_index)++;
                onvm_pkt_enqueue_nf(rx_mgr, meta->destination, pkts[i], NULL);
        }

        onvm_pkt_flush_all_nfs(rx_mgr, NULL);
}

void
onvm_pkt_flush_all_ports(struct queue_mgr *tx_mgr) {
        uint16_t i;

        if (tx_mgr == NULL)
                return;

        for (i = 0; i < ports->num_ports; i++)
                onvm_pkt_flush_port_queue(tx_mgr, ports->id[i]);
}

void
onvm_pkt_drop_batch(struct rte_mbuf **pkts, uint16_t size) {
        uint16_t i;

        if (pkts == NULL)
                return;

        for (i = 0; i < size; i++)
                rte_pktmbuf_free(pkts[i]);
}

// NFVNice functions
void onvm_detect_and_set_back_pressure_v2(struct onvm_nf *cl) {
        if(!cl || cl->is_bottleneck) return ;
        cl->is_bottleneck = 1;
        enqueu_nf_to_bottleneck_watch_list(cl->instance_id);
}

void
onvm_detect_and_set_back_pressure(__attribute__((unused)) struct rte_mbuf *pkts[], __attribute__((unused)) uint16_t count, __attribute__((unused)) struct onvm_nf *cl) {
        /*** Make sure this function is called only on error status on rx_enqueue() ***/
        /*** Detect the NF Rx Buffer overflow and signal this NF instance in the service chain as bottlenecked -- source of back-pressure -- all NFs prior to this in chain must throttle (either not scheduler or drop packets). ***/

#ifdef ENABLE_NF_BACKPRESSURE
        struct onvm_pkt_meta *meta = NULL;
        uint16_t i;
        struct onvm_flow_entry *flow_entry = NULL;
        //unsigned rx_q_count = rte_ring_count(cl->rx_q);

        unsigned rx_q_count = rte_ring_count(cl->rx_q);
        cl->stats.max_rx_q_len =  (rx_q_count>cl->stats.max_rx_q_len)?(rx_q_count):(cl->stats.max_rx_q_len);
        unsigned tx_q_count = rte_ring_count(cl->tx_q);
        cl->stats.max_tx_q_len =  (tx_q_count>cl->stats.max_tx_q_len)?(tx_q_count):(cl->stats.max_tx_q_len);

        //Inside this function indicates NFs Rx buffer has exceeded water-mark

        /** Flow Entry based/Per Service Chain classification scenario **/

        for(i = 0; i < count; i++) {
                int ret = get_flow_entry(pkts[i], &flow_entry);
                if (ret < 0)
                    continue;

                if (flow_entry && flow_entry->sc) {
                        meta = onvm_get_pkt_meta(pkts[i]);
                        // Enable below line to skip the 1st NF in the chain Note: <=1 => skip Flow_rule_installer and the First NF in the chain; <1 => skip only the Flow_rule_installer NF
                        if(meta->chain_index < 1) continue;

                        //Check the Flow Entry mark status and Add mark if not already done!
                        if(!(TEST_BIT(flow_entry->sc->highest_downstream_nf_index_id, meta->chain_index))) {
                                SET_BIT(flow_entry->sc->highest_downstream_nf_index_id, meta->chain_index);

                                #ifdef NF_BACKPRESSURE_APPROACH_2
                                uint8_t index = 1;
                                //for(; index < meta->chain_index; index++ ) {
                                for(index=(meta->chain_index -1); index >=1 ; index-- ) {
                                        nfs[flow_entry->sc->nf_instance_id[index]].throttle_this_upstream_nf=1;
                                        #ifdef HOP_BY_HOP_BACKPRESSURE
                                        break;
                                        #endif //HOP_BY_HOP_BACKPRESSURE
                                }
                                #endif  //NF_BACKPRESSURE_APPROACH_2
                                //approach: extend the service chain to keep track of client_nf_ids that service the chain, in-order to know which NFs to throttle in the wakeup thread..?
                                //Test and Set

                                //reset flow_entry and meta
                                flow_entry = NULL;
                                meta = NULL;
                        }
                }
        }

        cl->stats.bkpr_count++;
#endif //ENABLE_NF_BACKPRESSURE
        return;
}

void
onvm_check_and_reset_back_pressure_v2(__attribute__((unused)) struct rte_mbuf *pkts[], __attribute__((unused)) uint16_t count, __attribute__((unused)) struct onvm_nf *cl) {

#ifdef ENABLE_NF_BACKPRESSURE
        unsigned rx_q_count = rte_ring_count(cl->rx_q);
        // check if rx_q_size has decreased to acceptable level
        if (rx_q_count >= CLIENT_QUEUE_RING_LOW_WATER_MARK_SIZE) {
                if(rx_q_count >=CLIENT_QUEUE_RING_WATER_MARK_SIZE) {
                        onvm_detect_and_set_back_pressure_v2(cl);
                }
                return;
        }
#endif //ENABLE_NF_BACKPRESSURE
        return;
}

void
onvm_check_and_reset_back_pressure(struct rte_mbuf *pkts[], uint16_t count, struct onvm_nf *cl) {

#ifdef ENABLE_NF_BACKPRESSURE
        struct onvm_pkt_meta *meta = NULL;
        struct onvm_flow_entry *flow_entry = NULL;
        uint16_t i;
        unsigned rx_q_count = rte_ring_count(cl->rx_q);

        // check if rx_q_size has decreased to acceptable level
        if (rx_q_count >= CLIENT_QUEUE_RING_LOW_WATER_MARK_SIZE) {
                if(rx_q_count >=CLIENT_QUEUE_RING_WATER_MARK_SIZE) {
                        onvm_detect_and_set_back_pressure(pkts,count,cl);
                }
                return;
        }

        //Inside here indicates NFs Rx buffer has resumed to acceptable level (watermark - hysterisis)

        for(i = 0; i < count; i++) {
                int ret = get_flow_entry(pkts[i], &flow_entry);
                if (ret >= 0 && flow_entry && flow_entry->sc) {
                        if(flow_entry->sc->highest_downstream_nf_index_id ) {
                                meta = onvm_get_pkt_meta(pkts[i]);
                                if(TEST_BIT(flow_entry->sc->highest_downstream_nf_index_id, meta->chain_index )) {
                                        // also reset the chain's downstream NFs cl->downstream_nf_overflow and cl->highest_downstream_nf_index_id=0. But How?? <track the nf_instance_id in the service chain.
                                        CLEAR_BIT(flow_entry->sc->highest_downstream_nf_index_id, meta->chain_index);

#ifdef NF_BACKPRESSURE_APPROACH_2
                                        // detect the start nf_index based on new val of highest_downstream_nf_index_id
                                        unsigned nf_index=(flow_entry->sc->highest_downstream_nf_index_id == 0)? (1): (get_index_of_highest_set_bit(flow_entry->sc->highest_downstream_nf_index_id));
                                        for(; nf_index < meta->chain_index; nf_index++) {
                                                nfs[flow_entry->sc->nf_instance_id[nf_index]].throttle_this_upstream_nf=0;
                                        }
#endif //NF_BACKPRESSURE_APPROACH_2
                                }
                        }
                        flow_entry = NULL;
                        meta = NULL;
                }
        }
#endif //ENABLE_NF_BACKPRESSURE
}
