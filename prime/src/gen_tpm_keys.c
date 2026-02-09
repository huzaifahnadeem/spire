#include <stdio.h>
#include <stdlib.h>
#include "parser.h"         // For load_yaml_config(), free_yaml_config()
#include "key_generation.h" // For generate_simulated_tpm_key_for_host()
#include <sys/stat.h>

#define TPM_KEY_DIR "tpm_keys/"

/**
 * Create the directory at the given path if it doesn't exist.
 *
 * Checks if the specified directory exists. If not, attempts to create it.
 *
 * @param path Path to the directory.
 */
void ensure_directory(const char *path)
{
    struct stat st = {0};
    if (stat(path, &st) == -1)
    {
        if (mkdir(path, 0755) < 0)
        {
            perror(path);
        }
    }
}

void generate_simulated_tpm_key_for_host(struct host *host)
{
    char private_key_filepath[512];
    snprintf(private_key_filepath, sizeof(private_key_filepath),
             "%s%s_tpm_private.pem", TPM_KEY_DIR, host->name);

    ensure_directory(TPM_KEY_DIR);

    // Set permanent key path
    host->permanent_key_location = strdup(private_key_filepath);

    EVP_PKEY *tpm_key = NULL;

    // Check if the private key file exists
    FILE *fp = fopen(private_key_filepath, "r");
    if (fp) {
        // Load existing private key
        tpm_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);

        if (!tpm_key) {
            fprintf(stderr, "Error: Failed to load existing TPM key for host %s\n", host->name);
            return;
        }
    } else {
        // Generate new key
        tpm_key = generate_rsa_key(3072);
        if (!tpm_key) {
            fprintf(stderr, "Error: Failed to generate simulated TPM key for host %s\n", host->name);
            return;
        }

        // Extract and write private key
        char *tpm_private = get_private_key(tpm_key);
        if (!tpm_private) {
            fprintf(stderr, "Error: Failed to extract TPM private key for host %s\n", host->name);
            free_rsa_key(tpm_key);
            return;
        }

        if (write_key_to_file(private_key_filepath, tpm_private) != 0) {
            fprintf(stderr, "Error: Failed to write TPM key to %s\n", private_key_filepath);
            free(tpm_private);
            free_rsa_key(tpm_key);
            return;
        }

        free(tpm_private);
    }

    // Extract public key
    char *tpm_public = get_public_key(tpm_key);
    if (!tpm_public) {
        fprintf(stderr, "Error: Failed to extract TPM public key for host %s\n", host->name);
        free_rsa_key(tpm_key);
        return;
    }

    host->permanent_public_key = tpm_public;
    free_rsa_key(tpm_key);
}


/**
 * Performs the first pass of config generation:
 * - Loads the YAML config
 * - Generates simulated TPM keys for each host
 * - Updates the config in memory (in-place)
 *
 * @param cfg Pointer to the parsed config structure
 */
void first_pass_generate_tpm_keys(struct config *cfg)
{
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];
        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            generate_simulated_tpm_key_for_host(&site->hosts[j]);
        }
    }
}

static void print_usage(void)
{
    fprintf(stderr, "Usage: ./gen_tpm_keys <input_yaml>\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        print_usage();
    }

    const char *input_path = argv[1];
    struct config *cfg = load_yaml_config(input_path);
    if (!cfg)
    {
        fprintf(stderr, "Failed to parse YAML config: %s\n", input_path);
        return EXIT_FAILURE;
    }

    printf("[INFO] Generating simulated TPM keys...\n");
    first_pass_generate_tpm_keys(cfg);

    // Serialize and overwrite the updated YAML config
    size_t yaml_len = 0;
    char *updated_yaml = serialize_yaml_config_to_string(cfg, &yaml_len);
    if (!updated_yaml)
    {
        fprintf(stderr, "Failed to serialize updated YAML config.\n");
        free_yaml_config(&cfg);
        return EXIT_FAILURE;
    }

    FILE *fp = fopen(input_path, "w");
    if (!fp)
    {
        perror("Failed to open config file for writing");
        free(updated_yaml);
        free_yaml_config(&cfg);
        return EXIT_FAILURE;
    }

    fwrite(updated_yaml, 1, yaml_len, fp);
    fclose(fp);

    printf("[INFO] Done. Updated config written to %s\n", input_path);

    free(updated_yaml);
    free_yaml_config(&cfg);
    return EXIT_SUCCESS;
}

