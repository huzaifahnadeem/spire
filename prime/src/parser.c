#include <stdio.h>
#include <stdlib.h>
#include "parser.h"
#include <string.h>

/**
 * Host Schema Declaration
 */

static const cyaml_schema_field_t host_schema_fields[] = {
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct host, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct host, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("permanent_key_location", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, permanent_key_location, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("permanent_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, permanent_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("runs_spines_internal", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct host, runs_spines_internal),
    CYAML_FIELD_UINT("runs_spines_external", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct host, runs_spines_external),
    // Future fields (currently required but can be empty for now)
    CYAML_FIELD_STRING_PTR("spines_internal_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, spines_internal_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_spines_internal_private_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, encrypted_spines_internal_private_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("spines_external_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, spines_external_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_spines_external_private_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, encrypted_spines_external_private_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t host_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct host, host_schema_fields),
};

/**
 * Replica Schema Declaration
 */

static const cyaml_schema_field_t replica_schema_fields[] = {
    CYAML_FIELD_UINT("instance_id", CYAML_FLAG_DEFAULT, struct replica, instance_id),
    CYAML_FIELD_STRING_PTR("host", CYAML_FLAG_POINTER, struct replica, host, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("spines_internal_daemon", CYAML_FLAG_POINTER, struct replica, spines_internal_daemon, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("spines_external_daemon", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, spines_external_daemon, 0, CYAML_UNLIMITED),
    // Future fields (currently required but can be empty initially)
    CYAML_FIELD_STRING_PTR("instance_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, instance_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_instance_private_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, encrypted_instance_private_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_prime_threshold_key_share", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, encrypted_prime_threshold_key_share, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_sm_threshold_key_share", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, encrypted_sm_threshold_key_share, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t replica_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct replica, replica_schema_fields),
};

/**
 * Client Schema Declaration
 */

static const cyaml_schema_field_t client_schema_fields[] = {
    CYAML_FIELD_UINT("client_id", CYAML_FLAG_DEFAULT, struct client, client_id),
    CYAML_FIELD_STRING_PTR("host", CYAML_FLAG_POINTER, struct client, host, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("spines_external_daemon", CYAML_FLAG_POINTER, struct client, spines_external_daemon, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER, struct client, type, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("instance_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct client, instance_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_instance_private_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct client, encrypted_instance_private_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t client_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct client, client_schema_fields),
};

/**
 * Site Schema Declaration
 */

static const cyaml_strval_t site_type_strings[] = {
    {"CONTROL_CENTER", CONTROL_CENTER},
    {"DATA_CENTER", DATA_CENTER},
    {"CLIENT", CLIENT},
};

static const cyaml_schema_field_t site_schema_fields[] = {
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct site, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_ENUM("type", CYAML_FLAG_DEFAULT, struct site, type, site_type_strings, CYAML_ARRAY_LEN(site_type_strings)),
    CYAML_FIELD_SEQUENCE_COUNT("hosts", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct site, hosts, hosts_count, &host_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("replicas", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct site, replicas, replicas_count, &replica_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("clients", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct site, clients, clients_count, &client_schema, 0, CYAML_UNLIMITED),

    CYAML_FIELD_END};

static const cyaml_schema_value_t site_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct site, site_schema_fields),
};

/**
 * Service Keys Schema Declaration
 */

static const cyaml_schema_field_t service_keys_schema_fields[] = {
    CYAML_FIELD_STRING_PTR("sm_threshold_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct service_keys, sm_threshold_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("prime_threshold_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct service_keys, prime_threshold_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

/**
 * Config Message Schema Declaration
 */

static const cyaml_schema_field_t config_schema_fields[] = {
    CYAML_FIELD_UINT("configuration_id", CYAML_FLAG_DEFAULT, struct config, configuration_id),
    CYAML_FIELD_UINT("tolerated_byzantine_faults", CYAML_FLAG_DEFAULT, struct config, tolerated_byzantine_faults),
    CYAML_FIELD_UINT("tolerated_unavailable_replicas", CYAML_FLAG_DEFAULT, struct config, tolerated_unavailable_replicas),
    CYAML_FIELD_MAPPING("service_keys", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct config, service_keys, service_keys_schema_fields),
    CYAML_FIELD_SEQUENCE_COUNT("sites", CYAML_FLAG_POINTER, struct config, sites, sites_count, &site_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t config_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct config, config_schema_fields),
};

static const cyaml_config_t cyaml_config = {
    // .log_level = CYAML_LOG_DEBUG,
    .log_level = CYAML_LOG_WARNING,
    .log_fn = cyaml_log,
    .mem_fn = cyaml_mem,
};

// Function to load YAML config
struct config *load_yaml_config(const char *yaml_file)
{
    cyaml_err_t err;
    struct config *buff = NULL;

    err = cyaml_load_file(yaml_file, &cyaml_config, &config_schema, (cyaml_data_t **)&buff, NULL);

    if (err != CYAML_OK || buff == NULL)
    {
        fprintf(stderr, "Error loading YAML file '%s': %s\n", yaml_file, cyaml_strerror(err));
        return NULL;
    }

    return buff;
}

char *serialize_yaml_config_to_string(const struct config *cfg, size_t *out_len)
{
    if (!cfg || !out_len)
        return NULL;

    unsigned char *yaml_data = NULL;
    cyaml_err_t err = cyaml_save_data(
        &yaml_data, out_len, &cyaml_config, &config_schema, cfg, 0);

    if (err != CYAML_OK)
    {
        fprintf(stderr, "Error serializing YAML: %s\n", cyaml_strerror(err));
        return NULL;
    }

    // yaml_data is a pointer to malloc'd buffer (not null-terminated!)
    char *yaml_str = malloc(*out_len + 1);
    if (!yaml_str)
    {
        fprintf(stderr, "Memory allocation failed for YAML string\n");
        free(yaml_data);
        return NULL;
    }

    memcpy(yaml_str, yaml_data, *out_len);
    yaml_str[*out_len] = '\0';

    free(yaml_data); // free the original buffer allocated by cyaml
    return yaml_str; // caller must free
}

struct config *load_yaml_config_from_string(const char *yaml_str, size_t yaml_len)
{
    if (!yaml_str || yaml_len == 0)
    {
        fprintf(stderr, "Invalid YAML input string or length\n");
        return NULL;
    }

    struct config *cfg = NULL;
    cyaml_err_t err = cyaml_load_data(
        (const unsigned char *)yaml_str, yaml_len,
        &cyaml_config, &config_schema,
        (void **)&cfg, NULL);

    if (err != CYAML_OK)
    {
        fprintf(stderr, "Error loading YAML from string: %s\n", cyaml_strerror(err));
        return NULL;
    }

    return cfg;
}

void free_yaml_config(struct config **cfg)
{
    if (cfg == NULL || *cfg == NULL)
        return;

    cyaml_err_t err = cyaml_free(&cyaml_config, &config_schema, *cfg, 0);
    if (err != CYAML_OK)
    {
        fprintf(stderr, "Failed to free YAML data: %s\n", cyaml_strerror(err));
    }
}
