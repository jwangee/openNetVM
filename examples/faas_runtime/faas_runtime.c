
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <libgen.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include "cJSON.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#include "onvm_flow_dir.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_config_common.h"

// Customized NFs
#include "acl.h"
#include "chacha.h"
#include "distributed_nat.h"

#define NF_TAG "faas_runtime"

#define MAX_RULES 256
#define NUM_TBLS 8

static int nf_idx = 0;
static int faas_tcp_port = 0;
static int faas_chain_length = 1;
bool is_ingress = false;
bool is_egress = false;
int faas_per_packet_cycle = 0;
int bypass_per_packet_cycle = 100;

// destination specifies the next NF instance
static uint16_t destination;
static int debug = 0;
char *rule_file = NULL;

/* The per-NF packet counter */
static struct faas_runtime_pkt_stats stats;

/* Number of packets between each print */
static uint32_t print_delay = 10000000;

/* Shared data structure containing host port info */
extern struct port_info *ports;

/* Struct for printing stats */
struct faas_runtime_pkt_stats {
        uint64_t pkt_drop;
        uint64_t pkt_accept;
        uint64_t pkt_not_ipv4;
        uint64_t pkt_not_tcp_udp;
        uint64_t pkt_total;
};

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -p <print_delay> -f <rules file> [-b]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-t TCP_PORT`: Packets with dst tcp port will be forwarded to this module\n");
        printf(" - `-d DST`: Destination Service ID to forward to\n");
        printf(" - `-p PRINT_DELAY`: Number of packets between each print, e.g. `-p 1` prints every packets.\n");
        printf(" - `-b`: Debug mode: Print each incoming packets source/destination"
               " IP address as well as its drop/forward status\n");
        printf(" - `-f`: Path to a JSON file containing firewall rules; See README for example usage\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0, rules_init = 1;

        while ((c = getopt(argc, argv, "t:n:i:l:e:c:d:f:p:b")) != -1) {
                switch (c) {
                        case 't':
                                faas_tcp_port = strtoul(optarg, NULL, 10);
                                break;
                        case 'n':
                                nf_idx = strtoul(optarg, NULL, 10);
                                break;
                        case 'i':
                                if (strtoul(optarg, NULL, 10) > 0)
                                    is_ingress = true;
                                else
                                    is_ingress = false;
                                break;
                        case 'l':
                                faas_chain_length = strtoul(optarg, NULL, 10);
                                break;
                        case 'e':
                                if (strtoul(optarg, NULL, 10) > 0)
                                    is_egress = true;
                                else
                                    is_egress = false;
                                break;
                        case 'c':
                                faas_per_packet_cycle = strtoul(optarg, NULL, 10);
                                break;
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                dst_flag = 1;
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                RTE_LOG(INFO, APP, "Print delay = %d\n", print_delay);
                                break;
                        case 'f':
                                rule_file = strdup(optarg);
                                rules_init = 1;
                                break;
                        case 'b':
                                RTE_LOG(INFO, APP, "Debug mode enabled; printing the source IP addresses"
                                                   " of each incoming packet as well as drop/forward status\n");
                                debug = 1;
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                if (optopt == 'f')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Firewall NF requires a destination NF with the -d flag.\n");
                return -1;
        }
        if (!debug) {
                RTE_LOG(INFO, APP, "Running normal mode, use -b flag to enable debug mode\n");
        }
        if (!rules_init) {
                RTE_LOG(INFO, APP, "Please specify a rules JSON file with -f FILE_NAME\n");
                return -1;
        }
        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(void) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);
        printf("Packets Dropped: %lu\n", stats.pkt_drop);
        printf("Packets not IPv4: %lu\n", stats.pkt_not_ipv4);
        printf("Packets Accepted: %lu\n", stats.pkt_accept);
        printf("Packets Total: %lu", stats.pkt_total);

        printf("\n\n");
}

/* The code prints the SDN flow table at the ingress.
struct onvm_flow_entry *flow_entry;
struct onvm_ft_ipv4_5tuple fk;
int ret = onvm_ft_lookup_pkt(sdn_ft, pkt, &flow_entry);
onvm_ft_fill_key(&fk, pkt);
RTE_LOG(INFO, APP, "flowkey: [%x:%u:, %x:%u, %u]\n", fk.src_addr, fk.src_port, fk.dst_addr, fk.dst_port, fk.proto);
int tbl_index = rte_hash_lookup_with_hash(sdn_ft->hash, (const void *)&fk, pkt->hash.rss);
RTE_LOG(INFO, APP, "rss %d, idx %d, idx %d\n", pkt->hash.rss, ret, tbl_index);
*/

void faas_handle_egress(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta) {
    struct rte_ether_hdr *eth;
    struct rte_ether_addr tmp;
    eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    rte_ether_addr_copy(&(eth->d_addr), &tmp);
    rte_ether_addr_copy(&(eth->s_addr), &(eth->d_addr));
    rte_ether_addr_copy(&tmp, &(eth->s_addr));

    meta->action = ONVM_NF_ACTION_OUT;
    meta->destination = 1;
    if (debug) RTE_LOG(INFO, APP, "egress to port: %d \n", meta->destination);
}

// Bypass
static int
bypass_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        // Waits every 10 packets.
        uint64_t end = rte_rdtsc() + 10 * bypass_per_packet_cycle;
        while (rte_rdtsc() < end) {
            _mm_pause();
        }

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;
        stats.pkt_accept++;
        if (debug) RTE_LOG(INFO, APP, "Per-packet bypass %d. To next: %d\n", bypass_per_packet_cycle, meta->destination);

        if (is_egress) faas_handle_egress(pkt, meta);
        return 0;
}

// CHACHA
static int
chacha_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        int udp_pkt, tcp_pkt;
        int payload_size = 0;
        size_t hdr_length;
        struct rte_ipv4_hdr *ip = NULL;
        struct rte_tcp_hdr *tcp = NULL;
        struct rte_udp_hdr *udp = NULL;

        stats.pkt_total++;

        /* Check if we have a valid IP header */
        if (!onvm_pkt_is_ipv4(pkt)) {
                meta->action = ONVM_NF_ACTION_DROP;
                stats.pkt_not_ipv4++;
                return 0;
        }

        ip = onvm_pkt_ipv4_hdr(pkt);
        size_t ip_hdr_len = ((uint16_t)(rte_be_to_cpu_16(ip->total_length))) << 2;
        udp_pkt = onvm_pkt_is_udp(pkt);
        tcp_pkt = onvm_pkt_is_tcp(pkt);
        uint8_t *payload = NULL;

        /* Check if we have a valid TCP/UDP header */
        if (!udp_pkt && !tcp_pkt) {
                meta->action = ONVM_NF_ACTION_DROP;
                stats.pkt_not_tcp_udp++;
                return 0;
        }

        if (udp_pkt) {
                hdr_length = 10 + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
                payload = rte_pktmbuf_mtod_offset(pkt, uint8_t *,
                            hdr_length + chacha_payload_offset);
                payload_size = pkt->pkt_len - hdr_length - chacha_payload_offset;
        } else {
                hdr_length = 10 + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
                payload = rte_pktmbuf_mtod_offset(pkt, uint8_t * ,
                            hdr_length + chacha_payload_offset);
                payload_size = pkt->pkt_len - hdr_length - chacha_payload_offset;
        }

        if (debug) RTE_LOG(INFO, APP, "pkt: %d==%d, chacha offset: %d, header length %ld, payload: %d \n", pkt->pkt_len, pkt->data_len, chacha_payload_offset, hdr_length, payload_size);

        chacha_process_packet(payload, payload_size);

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;
        stats.pkt_accept++;
        if (debug) RTE_LOG(INFO, APP, "CHACHA to next: %d\n", meta->destination);

        if (is_egress) faas_handle_egress(pkt, meta);
        return 0;
}

// ACL
static int
acl_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        struct rte_ipv4_hdr *ipv4_hdr;
        static uint32_t counter = 0;
        int ret;
        uint32_t rule = 0;
        uint32_t track_ip = 0;
        char ip_string[16];

        if (++counter == print_delay) {
                do_stats_display();
                counter = 0;
        }

        stats.pkt_total++;

        if (!onvm_pkt_is_ipv4(pkt)) {
                stats.pkt_not_ipv4++;
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
        uint32_t src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
        uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
        ret = onvm_acl_hit_rule(src_ip, dst_ip, 0, 0, &rule);
        ret = 1501;
        rule = 0;

        if (debug) onvm_pkt_parse_char_ip(ip_string, rte_be_to_cpu_32(ipv4_hdr->src_addr));

        if (ret < 0) {
                meta->action = ONVM_NF_ACTION_DROP;
                stats.pkt_drop++;
                if (debug) RTE_LOG(INFO, APP, "Packet from source IP %s has been dropped\n", ip_string);
                return 0;
        }

        switch (rule) {
                case 0:
                        meta->action = ONVM_NF_ACTION_TONF;
                        meta->destination = destination;
                        stats.pkt_accept++;
                        if (debug) RTE_LOG(INFO, APP, "Packet from source IP %s has been accepted\n", ip_string);
                        break;
                default:
                        meta->action = ONVM_NF_ACTION_DROP;
                        stats.pkt_drop++;
                        if (debug) RTE_LOG(INFO, APP, "Packet from source IP %s has been dropped\n", ip_string);
                        break;
        }

        if (is_egress) faas_handle_egress(pkt, meta);
        return 0;
}

// Distributed NAT
static int
l4nat_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    struct rte_tcp_hdr *tcp = NULL;
    struct rte_udp_hdr *udp = NULL;
    int tcp_pkt, udp_pkt;
    static uint32_t counter = 0;
    int ret;
    int dir = 0;
    uint32_t track_ip = 0;
    char ip_string[16];

    if (++counter == print_delay) {
            do_stats_display();
            counter = 0;
    }

    stats.pkt_total++;

    if (!onvm_pkt_is_ipv4(pkt)) {
            stats.pkt_not_ipv4++;
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
    }

    ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
    uint32_t src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

    // dir=0 (forward traffic); dir=1 (reverse traffic)
    if (is_internal_traffic(src_ip)) {
            dir = 0;
    } else if (is_internal_traffic(dst_ip)) {
            dir = 1;
    } else {
            stats.pkt_drop++;
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
    }

    udp_pkt = onvm_pkt_is_udp(pkt);
    tcp_pkt = onvm_pkt_is_tcp(pkt);

    /* Check if we have a valid TCP/UDP header */
    if (!udp_pkt && !tcp_pkt) {
            stats.pkt_not_tcp_udp++;
            meta->action = ONVM_NF_ACTION_DROP;
            return 0;
    }

    struct onvm_ft_ipv4_5tuple nat_key;
    struct Entry* nat_entry = NULL;

    if (udp_pkt) {
            uint16_t sport = rte_be_to_cpu_16(udp->src_port);
            uint16_t dport = rte_be_to_cpu_16(udp->dst_port);
            onvm_nat_fill_key(&nat_key, src_ip, dst_ip, sport, dport, dir);
    } else {
            uint16_t sport = rte_be_to_cpu_16(tcp->src_port);
            uint16_t dport = rte_be_to_cpu_16(tcp->dst_port);
            onvm_nat_fill_key(&nat_key, src_ip, dst_ip, sport, dport, dir);
    }

    ret = onvm_natt_lookup_key(nat_table, &nat_key, (char **)&nat_entry);

    if (ret < 0) {
        // Add a new entry;
        ret = onvm_natt_add_key(nat_table, &nat_key, (char **)&nat_entry);
        if (nat_entry != NULL) {
            nat_entry->ip = rte_be_to_cpu_32(get_ipv4_value("10.10.10.10"));
            nat_entry->port = 8081;
            nat_entry->active = true;
            nat_entry->last_refresh = rte_rdtsc();
        }
    }

    if (dir == 0) {
        // refresh the key-entry pair.
        nat_entry->last_refresh = rte_rdtsc();
    }

    if (udp_pkt) {
        if (dir == 0) {
            ipv4_hdr->src_addr = rte_cpu_to_be_32(nat_entry->ip);
            udp->src_port = rte_cpu_to_be_16(nat_entry->port);
        } else {
            ipv4_hdr->dst_addr = rte_cpu_to_be_32(nat_entry->ip);
            udp->dst_port = rte_cpu_to_be_16(nat_entry->port);
        }
    } else {
        if (dir == 0) {
            ipv4_hdr->src_addr = rte_cpu_to_be_32(nat_entry->ip);
            tcp->src_port = rte_cpu_to_be_16(nat_entry->port);
        } else {
            ipv4_hdr->dst_addr = rte_cpu_to_be_32(nat_entry->ip);
            tcp->dst_port = rte_cpu_to_be_16(nat_entry->port);
        }
    }

    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = destination;
    stats.pkt_accept++;

    if (is_egress) faas_handle_egress(pkt, meta);
    return 0;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    switch (nf_idx) {
    case 1:
        return bypass_packet_handler(pkt, meta, nf_local_ctx);
    case 2:
        return acl_packet_handler(pkt, meta, nf_local_ctx);
    case 3:
        return acl_packet_handler(pkt, meta, nf_local_ctx);
    case 4:
        return chacha_packet_handler(pkt, meta, nf_local_ctx);
    case 5:
        return l4nat_packet_handler(pkt, meta, nf_local_ctx);
    default:
        return 0;
    };
}

int main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        struct onvm_fw_rule **rules;
        int arg_offset;
        int ret;

        const char *progname = argv[0];
        stats.pkt_drop = 0;
        stats.pkt_accept = 0;

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }
        uint16_t curr_service_id = nf_local_ctx->nf->service_id;
        printf("curr service_id = %d\n", curr_service_id);

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        // Decides the corresponding packet_handler function pointer
        printf("NF Index = %d\n", nf_idx);
        switch (nf_idx) {
        case 1:
            if (faas_per_packet_cycle > 0) {
                bypass_per_packet_cycle = faas_per_packet_cycle;
            }
            nf_function_table->pkt_handler = &bypass_packet_handler;
            printf("NF = Bypass %d\n", bypass_per_packet_cycle);
            break;
        case 2:
            nf_function_table->pkt_handler = &acl_packet_handler;
            printf("NF = ACL\n");
            break;
        case 3:
            nf_function_table->pkt_handler = &acl_packet_handler;
            printf("NF = BPF\n");
            break;
        case 4:
            chacha_module_init();
            nf_function_table->pkt_handler = &chacha_packet_handler;
            printf("NF = CHACHA\n");
            break;
        case 5:
            onvm_nat_dir_init();
            assert(nat_table != NULL);
            nf_function_table->pkt_handler = &l4nat_packet_handler;
            printf("NF = L4NAT\n");
            break;
        default:
            nf_function_table->pkt_handler = &bypass_packet_handler;
            break;
        };

        if (rule_file != NULL) {
                rules = setup_rules_from_file(&acl_num_rules, rule_file);
                lpm_setup(rules, acl_num_rules);
        } else if (nf_idx == 2) {
                rules = setup_rules(&acl_num_rules);
        } else if (nf_idx == 3) {
                rules = bpf_setup_rules(&acl_num_rules);
        }

        /* Map the sdn_ft table */
        printf("Target traffic = %d\n", faas_tcp_port);
        onvm_flow_dir_nf_init();

        if (is_ingress && faas_tcp_port != 0) {

            struct onvm_flow_entry *flow_entry = NULL;
            struct onvm_ft_ipv4_5tuple *fk = NULL;
            struct onvm_ft_ipv4_5tuple ipv4_5tuple;

            struct onvm_service_chain *schain = NULL;
            schain = onvm_sc_create();
            if (schain == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for SC Entry\n");
            }

            onvm_sc_append_entry(schain, ONVM_NF_ACTION_TONF, curr_service_id);
            if (faas_chain_length > 1) {
                // Link other NFs to this service chain.
                for (int idx = 1; idx < faas_chain_length - 1; ++idx) {
                    onvm_sc_append_entry(schain, ONVM_NF_ACTION_OUT, curr_service_id + idx);
                }
                onvm_sc_append_entry(schain, ONVM_NF_ACTION_OUT, curr_service_id + faas_chain_length - 1);
            }

            ipv4_5tuple.src_addr = get_ipv4_value("10.0.0.1");
            ipv4_5tuple.dst_addr = get_ipv4_value("10.0.0.1");
            ipv4_5tuple.src_port = (uint16_t)faas_tcp_port;
            ipv4_5tuple.dst_port = (uint16_t)faas_tcp_port;
            ipv4_5tuple.proto = 0;

            //RTE_CACHE_LINE_SIZE
            fk = rte_calloc("flow_key",1, sizeof(struct onvm_ft_ipv4_5tuple), 0);
            fk->src_addr = 0;
            fk->dst_addr = 0;
            fk->src_port = 0;
            fk->dst_port = rte_cpu_to_be_16(ipv4_5tuple.dst_port);
            fk->proto = ipv4_5tuple.proto;
            printf("Flow entry key = [%x:%u:, %x:%u, %u]\n", fk->src_addr, fk->src_port, fk->dst_addr, fk->dst_port, fk->proto);

            // Check if the entry has existed.
            ret = onvm_flow_dir_get_key(fk, &flow_entry);
            if (ret == -ENOENT) {
                flow_entry = NULL;
                ret = onvm_flow_dir_add_key(fk, &flow_entry);
                printf("Adding fresh Key [%x]\n", fk->src_addr);
            }
            else if (ret >= 0) {
                // Entry already exists
                rte_free(flow_entry->key);
                printf("Flow entry has already existed. Override it..\n");
            }
            else {
                rte_free(fk);
                printf("Unknown Failure in get_key()!\n");
                return ret;
            }

            if (flow_entry == NULL) {
                printf("Failed flow_entry Allocations!!\n" );
                return -ENOMEM;
            }

            //(void)onvm_flow_dir_reset_entry(flow_entry);
            flow_entry->key = fk;
            flow_entry->sc = schain;
            printf("%d %d\n", fk->dst_port, onvm_softrss(fk));
        }

        onvm_nflib_run(nf_local_ctx);

        if (rule_file != NULL) {
            lpm_teardown(rules, acl_num_rules);
            free(rule_file);
        }

        if (nat_table != NULL) {
            onvm_natt_free(nat_table);
        }

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
