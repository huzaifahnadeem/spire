
#include "config_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "tc_wrapper.h"
#include "../OpenTC-1.1/TC-lib-1.0/TC.h"

#define SM_TC_DIR "tc_keys/sm/"
#define PRIME_TC_DIR "tc_keys/prime/"

static char *read_file_as_string(const char *filepath);                                                 // make static
static void generate_all_site_tc_keys(int req_shares, int faults, int rej_servers);                     // make static
static void load_threshold_pubkeys(struct config *cfg);                                                 // make static
static void generate_keys_for_host(struct host *host);                                                  // make static
static void generate_keys_for_replica(struct replica *replica, struct host *host, unsigned site_index); // make static
static void generate_keys_for_client(struct client *client, struct host *host);                         // make static

/**
 * Reads the entire contents of a file into a null-terminated string.
 */
static char *read_file_as_string(const char *filepath)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp)
        return NULL;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    char *buffer = malloc(size + 1);
    if (!buffer)
    {
        fclose(fp);
        return NULL;
    }

    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}

/**
 * Generates threshold cryptography key shares for all sites.
 */
static void generate_all_site_tc_keys(int req_shares, int faults, int rej_servers)
{
    int n = 3 * faults + 2 * rej_servers + 1;
    int k = req_shares;
    int keysize = 1024;

    TC_DEALER *dealer_sm = TC_generate(keysize / 2, n, k, 17);
    TC_write_shares(dealer_sm, "tc_keys/sm", 1);
    TC_DEALER_free(dealer_sm);

    TC_DEALER *dealer_prime = TC_generate(keysize / 2, n, k, 17);
    TC_write_shares(dealer_prime, "tc_keys/prime", 1);
    TC_DEALER_free(dealer_prime);
}

/**
 * Loads threshold public keys for Scada Master and Prime into config.
 */
static void load_threshold_pubkeys(struct config *cfg)
{
    char sm_pubkey_path[256];
    char prime_pubkey_path[256];

    snprintf(sm_pubkey_path, sizeof(sm_pubkey_path), "%spubkey_1.pem", SM_TC_DIR);
    snprintf(prime_pubkey_path, sizeof(prime_pubkey_path), "%spubkey_1.pem", PRIME_TC_DIR);

    cfg->service_keys.sm_threshold_public_key = read_file_as_string(sm_pubkey_path);
    cfg->service_keys.prime_threshold_public_key = read_file_as_string(prime_pubkey_path);

    if (!cfg->service_keys.sm_threshold_public_key || !cfg->service_keys.prime_threshold_public_key)
    {
        fprintf(stderr, "Error: Failed to read SM or Prime threshold public keys.\n");
        free_yaml_config(&cfg);
        exit(EXIT_FAILURE);
    }
}

/**
 * Generates and encrypts internal and external RSA key pairs for a host.
 */
static void generate_keys_for_host(struct host *host)
{
    if (!host->permanent_public_key)
    {
        fprintf(stderr, "Error: TPM public key missing for host %s\n", host->name);
        return;
    }

    EVP_PKEY *tpm_pubkey = load_public_key_from_pem(host->permanent_public_key);
    if (!tpm_pubkey)
    {
        fprintf(stderr, "Error: Failed to load TPM public key for host %s\n", host->name);
        return;
    }

    // === Internal Key ===
    EVP_PKEY *internal_key = generate_rsa_key(1024);
    if (!internal_key)
    {
        fprintf(stderr, "Failed to generate internal RSA key\n");
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    host->spines_internal_public_key = get_public_key(internal_key);
    char *internal_private_pem = get_private_key(internal_key);

    struct HybridEncrypted internal_enc = hybrid_encrypt(
        (unsigned char *)internal_private_pem,
        strlen(internal_private_pem),
        tpm_pubkey);

    host->encrypted_spines_internal_private_key = hybrid_pack(&internal_enc);

    // Cleanup
    free(internal_enc.ciphertext_hex);
    free(internal_enc.enc_key_hex);
    free(internal_private_pem);
    free_rsa_key(internal_key);

    // === External Key ===
    EVP_PKEY *external_key = generate_rsa_key(1024);
    if (!external_key)
    {
        fprintf(stderr, "Failed to generate external RSA key\n");
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    host->spines_external_public_key = get_public_key(external_key);
    char *external_private_pem = get_private_key(external_key);

    struct HybridEncrypted external_enc = hybrid_encrypt(
        (unsigned char *)external_private_pem,
        strlen(external_private_pem),
        tpm_pubkey);

    host->encrypted_spines_external_private_key = hybrid_pack(&external_enc);

    // Cleanup
    free(external_enc.ciphertext_hex);
    free(external_enc.enc_key_hex);
    free(external_private_pem);
    free_rsa_key(external_key);

    EVP_PKEY_free(tpm_pubkey);
}

/**
 * Generates and encrypts keys and threshold shares for a replica.
 */
static void generate_keys_for_replica(struct replica *replica, struct host *host, unsigned site_index)
{
    if (!host->permanent_public_key)
    {
        fprintf(stderr, "Error: TPM public key missing for host %s (replica %d)\n", host->name, replica->instance_id);
        return;
    }

    // Load the host's public key from PEM
    EVP_PKEY *tpm_pubkey = load_public_key_from_pem(host->permanent_public_key);
    if (!tpm_pubkey)
    {
        fprintf(stderr, "Error: Failed to load TPM public key for host %s (replica %d)\n", host->name, replica->instance_id);
        return;
    }

    // Generate instance key pair
    EVP_PKEY *instance_key = generate_rsa_key(1024);
    if (!instance_key)
    {
        fprintf(stderr, "Error: Failed to generate RSA key for replica %d\n", replica->instance_id);
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    replica->instance_public_key = get_public_key(instance_key);
    char *instance_private_pem = get_private_key(instance_key);

    struct HybridEncrypted inst_enc = hybrid_encrypt(
        (unsigned char *)instance_private_pem,
        strlen(instance_private_pem),
        tpm_pubkey);
    replica->encrypted_instance_private_key = hybrid_pack(&inst_enc);

    free(instance_private_pem);
    free(inst_enc.ciphertext_hex);
    free(inst_enc.enc_key_hex);
    free_rsa_key(instance_key);

    // Encrypt Threshold Shares

    char prime_share_path[512];
    snprintf(prime_share_path, sizeof(prime_share_path), PRIME_TC_DIR "share%d_1.pem", replica->instance_id - 1);

    char sm_share_path[512];
    snprintf(sm_share_path, sizeof(sm_share_path), SM_TC_DIR "share%d_1.pem", replica->instance_id - 1);

    char *prime_plain = read_file_as_string(prime_share_path);
    char *sm_plain = read_file_as_string(sm_share_path);

    if (!prime_plain || !sm_plain)
    {
        fprintf(stderr, "Error: Failed to read threshold shares for replica %d\n", replica->instance_id);
        free(prime_plain);
        free(sm_plain);
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    struct HybridEncrypted prime_enc = hybrid_encrypt(
        (unsigned char *)prime_plain,
        strlen(prime_plain),
        tpm_pubkey);
    replica->encrypted_prime_threshold_key_share = hybrid_pack(&prime_enc);

    struct HybridEncrypted sm_enc = hybrid_encrypt(
        (unsigned char *)sm_plain,
        strlen(sm_plain),
        tpm_pubkey);
    replica->encrypted_sm_threshold_key_share = hybrid_pack(&sm_enc);

    // Cleanup
    free(prime_plain);
    free(sm_plain);

    free(prime_enc.ciphertext_hex);
    free(prime_enc.enc_key_hex);

    free(sm_enc.ciphertext_hex);
    free(sm_enc.enc_key_hex);

    EVP_PKEY_free(tpm_pubkey);
}

/**
 * Generates an RSA key pair for a client and encrypts the private key using the host's TPM public key.
 */
static void generate_keys_for_client(struct client *client, struct host *host)
{
    if (!host || !host->permanent_public_key)
    {
        fprintf(stderr, "Error: TPM public key missing for host %s (client %u)\n", host ? host->name : "NULL", client->client_id);
        return;
    }

    EVP_PKEY *tpm_pubkey = load_public_key_from_pem(host->permanent_public_key);
    if (!tpm_pubkey)
    {
        fprintf(stderr, "Error: Failed to load TPM public key for host %s (client %u)\n", host->name, client->client_id);
        return;
    }

    EVP_PKEY *client_key = generate_rsa_key(1024);
    if (!client_key)
    {
        fprintf(stderr, "Error: Failed to generate RSA key for client %u\n", client->client_id);
        EVP_PKEY_free(tpm_pubkey);
        return;
    }

    client->instance_public_key = get_public_key(client_key);
    char *client_priv_pem = get_private_key(client_key);

    struct HybridEncrypted enc = hybrid_encrypt(
        (unsigned char *)client_priv_pem,
        strlen(client_priv_pem),
        tpm_pubkey);

    client->encrypted_instance_private_key = hybrid_pack(&enc);

    // Cleanup
    free(client_priv_pem);
    free(enc.ciphertext_hex);
    free(enc.enc_key_hex);
    free_rsa_key(client_key);
    EVP_PKEY_free(tpm_pubkey);
}

/**
 * Generates and encrypts all internal, external, and replica-specific keys.
 */
void generate_keys(struct config *cfg)
{
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        // Handle hosts
        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            generate_keys_for_host(&site->hosts[j]);
        }

        // Handle replicas
        for (unsigned j = 0; j < site->replicas_count; j++)
        {
            struct replica *replica = &site->replicas[j];
            struct host *replica_host = find_host_by_name(cfg, replica->host);

            if (replica_host)
            {
                generate_keys_for_replica(replica, replica_host, i);
            }
            else
            {
                fprintf(stderr, "Error: Replica %d has no matching host %s!\n", replica->instance_id, replica->host);
            }
        }

        // Handle clients
        for (unsigned j = 0; j < site->clients_count; j++)
        {
            struct client *client = &site->clients[j];
            struct host *client_host = find_host_by_name(cfg, client->host);

            if (client_host)
            {
                generate_keys_for_client(client, client_host);
            }
            else
            {
                fprintf(stderr, "Error: Client %u references unknown host %s\n", client->client_id, client->host);
            }
        }
    }
}

/**
 * Loads the raw YAML configuration processes it, performing all key generation and processing steps.
 */
struct config *load_and_process_config(const char *input_yaml)
{
    struct config *cfg = load_yaml_config(input_yaml);
    if (!cfg)
        return NULL;

    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];
        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            struct host *host = &site->hosts[j];
            EVP_PKEY *priv = load_key_from_file(host->permanent_key_location, 1);
            if (!priv)
            {
                fprintf(stderr, "Error: Failed to load TPM private key from %s for host %s\n",
                        host->permanent_key_location, host->name);
                free_yaml_config(&cfg);
                return NULL;
            }

            char *pub_str = get_public_key(priv);
            EVP_PKEY_free(priv);

            if (!pub_str)
            {
                fprintf(stderr, "Error: Failed to extract TPM public key from %s for host %s\n",
                        host->permanent_key_location, host->name);
                free_yaml_config(&cfg);
                return NULL;
            }

            host->permanent_public_key = pub_str;
        }
    }

    int faults = cfg->tolerated_byzantine_faults;
    int rej_servers = cfg->tolerated_unavailable_replicas;
    int req_shares = faults + 1;
    generate_all_site_tc_keys(req_shares, faults, rej_servers);

    load_threshold_pubkeys(cfg);
    generate_keys(cfg);

    return cfg;
}

/**
 * Loads the Config Manager's RSA key pair from disk.
 */
int load_config_manager_keys(EVP_PKEY **priv_key, EVP_PKEY **pub_key)
{
    *priv_key = load_key_from_file("cm_keys/private_key.pem", 1);
    *pub_key = load_key_from_file("cm_keys/public_key.pem", 0);
    return (*priv_key && *pub_key) ? 0 : -1;
}

/**
 * Determines if a given client ID corresponds to an HMI based on its type and ID.
 */
int is_hmi(unsigned client_id, struct config *cfg)
{
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->clients_count; j++)
        {
            struct client *client = &site->clients[j];

            if (client->client_id != client_id)
                continue;

            if ((strcmp(client->type, "JHU") == 0 && client_id == 1) ||
                (strcmp(client->type, "PNNL") == 0 && client_id == 2) ||
                (strcmp(client->type, "EMS") == 0 && client_id == 3))
            {
                return 1;
            }

            return 0; 
        }
    }

    return 0; 
}

/**
 * Finds and returns a pointer to the host struct with the given name.
 * Searches all hosts across all sites in the configuration.
 */
struct host *find_host_by_name(const struct config *cfg, const char *name)
{
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];
        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            if (strcmp(site->hosts[j].name, name) == 0)
                return &site->hosts[j];
        }
    }
    return NULL;
}

/**
 * Finds the IP address of the host running the external Spines daemon
 * for a given client_id.
 */
const char *get_spines_ip_for_client(const struct config *cfg, int client_id, int is_hmi)
{

    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        if (site->type != CLIENT)
            continue;


        for (unsigned j = 0; j < site->clients_count; j++)
        {
            struct client *c = &site->clients[j];

            if ((is_hmi && c->type &&
                 (strcmp(c->type, "EMS") == 0 || strcmp(c->type, "PNNL") == 0 || strcmp(c->type, "JHU") == 0)) ||
                !is_hmi)
            {
                if (c->client_id == (unsigned)client_id)
                {

                    struct host *spines_host = find_host_by_name(cfg, c->spines_external_daemon);

                    if (spines_host != NULL)
                    {
                        return spines_host->ip;
                    }
                }
            }
        }
    }

    return NULL;
}

/**
 * Given a replica instance ID, retrieves the internal and external Spines daemon IPs.
 * Returns 0 on success, -1 on failure.
 */
int get_spines_ips_for_replica(const struct config *cfg, int instance_id,
                               const char **int_ip_out, const char **ext_ip_out)
{
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->replicas_count; j++)
        {
            struct replica *rep = &site->replicas[j];
            if (rep->instance_id != instance_id)
                continue;

            if (rep->spines_internal_daemon)
            {
                struct host *int_host = find_host_by_name(cfg, rep->spines_internal_daemon);
                if (!int_host)
                {
                    fprintf(stderr, "Internal Spines host not found for replica %d\n", instance_id);
                    return -1;
                }
                *int_ip_out = int_host->ip;
            }
            if (rep->spines_external_daemon)
            {
                struct host *ext_host = find_host_by_name(cfg, rep->spines_external_daemon);
                if (!ext_host)
                {
                    fprintf(stderr, "External Spines host not found for replica %d\n", instance_id);
                    return -1;
                }
                *ext_ip_out = ext_host->ip;
            }

            return 0;
        }
    }

    fprintf(stderr, "Replica with instance ID %d not found\n", instance_id);
    return -1;
}