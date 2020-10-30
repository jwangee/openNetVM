
#include <unistd.h>
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
#include "cJSON.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#include <rte_lpm.h>

#include "onvm_flow_dir.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_config_common.h"

#define NF_TAG "faas_runtime"

#define MAX_RULES 256
#define NUM_TBLS 8

static int nf_idx = 0;
static int faas_tcp_port = 0;
int bypass_per_packet_cycle = 10000;

static uint16_t destination;
static int debug = 0;
char *rule_file = NULL;

/* Structs that contain information to setup LPM and its rules */
struct lpm_request *firewall_req;
static struct firewall_pkt_stats stats;
struct rte_lpm *lpm_tbl;
struct onvm_fw_rule **rules;

/* Number of packets between each print */
static uint32_t print_delay = 10000000;

/* Shared data structure containing host port info */
extern struct port_info *ports;

/* Struct for the firewall LPM rules */
struct onvm_fw_rule {
        uint32_t src_ip;
        uint8_t depth;
        uint8_t action;
};

/* Struct for printing stats */
struct firewall_pkt_stats {
        uint64_t pkt_drop;
        uint64_t pkt_accept;
        uint64_t pkt_not_ipv4;
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

        while ((c = getopt(argc, argv, "t:i:d:f:p:b")) != -1) {
                switch (c) {
                        case 't':
                                faas_tcp_port = strtoul(optarg, NULL, 10);
                                break;
                        case 'i':
                                nf_idx = strtoul(optarg, NULL, 10);
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

// Distributed NAT
static int
l4nat_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    return 0;
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

// Bypass
static int
bypass_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        // Waits every 10 packets.
        if (stats.pkt_accept % 10) {
            uint64_t end = rte_rdtsc() + 10 * bypass_per_packet_cycle;
            while (rte_rdtsc() < end) {
                _mm_pause();
            }
        }

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;
        stats.pkt_accept++;
        if (debug) RTE_LOG(INFO, APP, "Per-packet bypass %d \n", bypass_per_packet_cycle);
        return 0;
}

// CHACHA
static int
chacha_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
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
                if (debug) RTE_LOG(INFO, APP, "Packet received not ipv4\n");
                stats.pkt_not_ipv4++;
                meta->action = ONVM_NF_ACTION_DROP;
                return 0;
        }

        ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
        ret = rte_lpm_lookup(lpm_tbl, rte_be_to_cpu_32(ipv4_hdr->src_addr), &rule);

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
        return chacha_packet_handler(pkt, meta, nf_local_ctx);
    case 4:
        return l4nat_packet_handler(pkt, meta, nf_local_ctx);
    default:
        return 0;
    };
}

static int
lpm_setup(struct onvm_fw_rule **rules, int num_rules) {
        int i, status, ret;
        uint32_t ip;
        char name[64];
        char ip_string[16];

        firewall_req = (struct lpm_request *) rte_malloc(NULL, sizeof(struct lpm_request), 0);

        if (!firewall_req) return 0;

        snprintf(name, sizeof(name), "fw%d-%"PRIu64, rte_lcore_id(), rte_get_tsc_cycles());
        firewall_req->max_num_rules = 1024;
        firewall_req->num_tbl8s = 24;
        firewall_req->socket_id = rte_socket_id();
        snprintf(firewall_req->name, sizeof(name), "%s", name);
        status = onvm_nflib_request_lpm(firewall_req);

        if (status < 0) {
                rte_exit(EXIT_FAILURE, "Cannot get lpm region for firewall\n");
        }

        lpm_tbl = rte_lpm_find_existing(name);

        if (lpm_tbl == NULL) {
                printf("No existing LPM_TBL\n");
        }

        for (i = 0; i < num_rules; ++i) {
                ip = rules[i]->src_ip;
                onvm_pkt_parse_char_ip(ip_string, ip);
                printf("RULE %d: { ip: %s, depth: %d, action: %d }\n", i, ip_string, rules[i]->depth, rules[i]->action);
                ret = rte_lpm_add(lpm_tbl, rules[i]->src_ip, rules[i]->depth, rules[i]->action);
                if (ret < 0) {
                        printf("ERROR ADDING RULE %d\n", ret);
                        return 1;
                }
        }
        rte_free(firewall_req);

        return 0;
}

static void
lpm_teardown(struct onvm_fw_rule **rules, int num_rules) {
        int i;

        if (rules) {
                for (i = 0; i < num_rules; ++i) {
                        if (rules[i]) free(rules[i]);
                }
                free(rules);
        }

        if (lpm_tbl) {
                rte_lpm_free(lpm_tbl);
        }

        if (rule_file) {
                free(rule_file);
        }
}

struct onvm_fw_rule
**setup_rules(int *total_rules, char *rules_file) {
        int ip[4];
        int num_rules, ret;
        int i = 0;

        cJSON *rules_json = onvm_config_parse_file(rules_file);
        cJSON *rules_ip = NULL;
        cJSON *depth = NULL;
        cJSON *action = NULL;

        if (rules_json == NULL) {
                rte_exit(EXIT_FAILURE, "%s file could not be parsed/not found. Assure rules file"
                                       " the directory to the rules file is being specified.\n", rules_file);
        }

        num_rules = onvm_config_get_item_count(rules_json);
        *total_rules = num_rules;
        rules = (struct onvm_fw_rule **) malloc(num_rules * sizeof(struct onvm_fw_rule *));
        rules_json = rules_json->child;

        while (rules_json != NULL) {
                rules_ip = cJSON_GetObjectItem(rules_json, "ip");
                depth = cJSON_GetObjectItem(rules_json, "depth");
                action = cJSON_GetObjectItem(rules_json, "action");

                if (rules_ip == NULL) rte_exit(EXIT_FAILURE, "IP not found/invalid\n");
                if (depth == NULL) rte_exit(EXIT_FAILURE, "Depth not found/invalid\n");
                if (action == NULL) rte_exit(EXIT_FAILURE, "Action not found/invalid\n");

                rules[i] = (struct onvm_fw_rule *) malloc(sizeof(struct onvm_fw_rule));
                onvm_pkt_parse_ip(rules_ip->valuestring, &rules[i]->src_ip);
                rules[i]->depth = depth->valueint;
                rules[i]->action = action->valueint;
                rules_json = rules_json->next;
                i++;
        }
        cJSON_Delete(rules_json);

        return rules;
}

static uint32_t get_ipv4_value(const char *ip_addr){
        if (NULL == ip_addr) {
                return 0;
        }

        struct sockaddr_in antelope;
        inet_aton(ip_addr, &antelope.sin_addr);
        return rte_be_to_cpu_32(antelope.sin_addr.s_addr);
}

int main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        struct onvm_fw_rule **rules;
        int arg_offset, num_rules;
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
            nf_function_table->pkt_handler = &bypass_packet_handler;
            break;
        case 2:
            nf_function_table->pkt_handler = &acl_packet_handler;
            break;
        case 3:
            nf_function_table->pkt_handler = &chacha_packet_handler;
            break;
        case 4:
            nf_function_table->pkt_handler = &l4nat_packet_handler;
            break;
        default:
            nf_function_table->pkt_handler = &bypass_packet_handler;
            break;
        };

        if (rule_file != NULL) {
                rules = setup_rules(&num_rules, rule_file);
                lpm_setup(rules, num_rules);
        }

        /* Map the sdn_ft table */
        printf("Target traffic = %d\n", faas_tcp_port);
        if (faas_tcp_port != 0) {
            onvm_flow_dir_nf_init();

            struct onvm_flow_entry *flow_entry = NULL;
            struct onvm_ft_ipv4_5tuple *fk = NULL;
            struct onvm_ft_ipv4_5tuple ipv4_5tuple;

            struct onvm_service_chain *schain = NULL;
            schain = onvm_sc_create();
            if (schain == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot allocate memory for SC Entry\n");
            }
            onvm_sc_append_entry(schain, ONVM_NF_ACTION_TONF, curr_service_id);

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
            lpm_teardown(rules, num_rules);
        }

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
