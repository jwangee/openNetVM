
#include "acl.h"

int acl_num_rules = 0;

bool Match(struct onvm_fw_rule *rule, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    uint32_t mask = 0xFFFF;
    if (rule->depth == 0) {
        mask = 0;
    }

    return (rule->src_ip & mask == sip & mask) && 
         (rule->dst_ip & mask == dip & mask) &&
         (rule->src_port == 0 || rule->src_port == sport) &&
         (rule->dst_port == 0 || rule->dst_port == dport);
}

int onvm_acl_hit_rule(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, int* rule) {
    int i;
    for (i = 0; i < acl_num_rules; ++i) {
        if (Match(rules[i], sip, dip, sport, dport)) {
            *rule = rules[i]->action;
            return i;
        }
    }

    return -2;
}

int lpm_setup(struct onvm_fw_rule **rules, int num_rules) {
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

void lpm_teardown(struct onvm_fw_rule **rules, int num_rules) {
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
}

struct onvm_fw_rule **setup_rules(int *total_rules) {
        int ip_range_1 = 30;
        int ip_range_2 = 50;
        int num_rules = ip_range_1 * ip_range_2 + 1;
        *total_rules = num_rules;

        rules = (struct onvm_fw_rule **) malloc(num_rules * sizeof(struct onvm_fw_rule *));

        for (int i = 0; i < ip_range_1; ++i) {
            for (int j = 0; j < ip_range_2; ++i) {
                rules[i]->src_ip = get_ipv4_value("172.12.0.1");
                rules[i]->dst_ip = get_ipv4_value("172.13.0.1");
                rules[i]->depth = 32;
                rules[i]->src_port = 12345;
                rules[i]->dst_port = 54321;
            }
        }
        rules[num_rules]->src_ip = 0;
        rules[num_rules]->dst_ip = 0;
        rules[num_rules]->depth = 0;
        rules[num_rules]->src_port = 0;
        rules[num_rules]->dst_port = 0;

        return rules;
}

struct onvm_fw_rule
**setup_rules_from_file(int *total_rules, char *rules_file) {
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

uint32_t get_ipv4_value(const char *ip_addr) {
        if (NULL == ip_addr) {
                return 0;
        }

        struct sockaddr_in antelope;
        inet_aton(ip_addr, &antelope.sin_addr);
        return rte_be_to_cpu_32(antelope.sin_addr.s_addr);
}
