#ifndef CONFIG_UTILS_H
#define CONFIG_UTILS_H

#include <openssl/evp.h>
#include "parser.h"
#include "key_generation.h"

void generate_keys(struct config *cfg); // make static
struct config *load_and_process_config(const char *input_yaml);
int load_config_manager_keys(EVP_PKEY **priv_key, EVP_PKEY **pub_key);
int is_hmi(unsigned client_id, struct config *cfg);
struct host *find_host_by_name(const struct config *cfg, const char *name);
int get_spines_ips_for_replica(const struct config *cfg, int instance_id,
                               const char **int_ip_out, const char **ext_ip_out);

const char *get_spines_ip_for_client(const struct config *cfg, int client_id, int is_hmi);
#endif // CONFIG_UTILS_H
