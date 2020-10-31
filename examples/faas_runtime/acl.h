
#ifndef FAAS_ACL_
#define FAAS_ACL_

#include <limits.h>
#include <stdbool.h> 
#include <string.h>
#include <stdint.h>
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

/* Struct for the firewall LPM rules */
struct onvm_fw_rule {
    	uint32_t src_ip;
        uint8_t depth;
        uint8_t action;

        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
};

/* Structs that contain information to setup LPM and its rules */
struct lpm_request *firewall_req;
struct rte_lpm *lpm_tbl;
struct onvm_fw_rule **rules;

extern int acl_num_rules;

// Export functions.
int onvm_acl_hit_rule(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, int* rule);

struct onvm_fw_rule **setup_rules(int *total_rules);

struct onvm_fw_rule **setup_rules_from_file(int *total_rules, char *rules_file);

int lpm_setup(struct onvm_fw_rule **rules, int num_rules);

void lpm_teardown(struct onvm_fw_rule **rules, int num_rules);

uint32_t get_ipv4_value(const char *ip_addr);

#endif // FAAS_ACL_
