#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "tc_wrapper.h"
#include "parser.h"
#include "key_generation.h"
#include "../OpenTC-1.1/TC-lib-1.0/TC.h"
#include "config_utils.h"

static void Print_Usage(void)
{
    fprintf(stderr,
            "Usage:\n"
            "  ./config_generator -i <input_yaml> [-o <output_yaml>]\n\n"
            "Arguments:\n"
            "  -i <input_yaml>      Path to input YAML config file (required)\n"
            "  -o <output_yaml>     Path to output signed config file (optional)\n"
            "                       If omitted, defaults to post_configs/<input_basename>\n");
    exit(EXIT_FAILURE);
}

static void Usage(int argc, char **argv, const char **input_yaml, const char **output_yaml)
{
    static char local_output_path[512]; 

    *input_yaml = NULL;
    *output_yaml = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            *input_yaml = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            *output_yaml = argv[++i];
        } else {
            Print_Usage();
        }
    }

    if (*input_yaml == NULL) {
        Print_Usage();
    }

    // If -o not provided, set default path based on -i basename
    if (*output_yaml == NULL) {
        char *input_copy = strdup(*input_yaml);
        if (!input_copy) {
            perror("strdup");
            exit(EXIT_FAILURE);
        }
        char *base = basename(input_copy);
        static char output_path[512];
        snprintf(local_output_path, sizeof(local_output_path), "post_configs/%s", base);
        *output_yaml = local_output_path;
        free(input_copy);
    }
}

int main(int argc, char *argv[])
{
    int simulate_tpm = 0;
    const char *input_path = NULL;
    const char *output_path = NULL;

    Usage(argc, argv, &input_path, &output_path);

    EVP_PKEY *cm_priv = NULL, *cm_pub = NULL;
    char *serialized_config = NULL;
    Signature sig = {0};
    FILE *out_fp = NULL;
    int status = EXIT_SUCCESS;

    // Load and process YAML config
    struct config *cfg = load_and_process_config(input_path);
    if (!cfg)
    {
        fprintf(stderr, "Failed to load or process config\n");
        status = EXIT_FAILURE;
        goto out;
    }

    // Load CM keys
    if (load_config_manager_keys(&cm_priv, &cm_pub) < 0)
    {
        fprintf(stderr, "Failed to load config manager keys\n");
        status = EXIT_FAILURE;
        goto out;
    }

    // Serialize YAML
    size_t serialized_config_len = 0;
    serialized_config = serialize_yaml_config_to_string(cfg, &serialized_config_len);
    if (!serialized_config)
    {
        fprintf(stderr, "Failed to serialize config\n");
        status = EXIT_FAILURE;
        goto out;
    }

    // Sign serialized config
    sig = sign_buffer((unsigned char *)serialized_config, serialized_config_len, cm_priv);
    if (!sig.signature)
    {
        fprintf(stderr, "Failed to sign configuration\n");
        status = EXIT_FAILURE;
        goto out;
    }

    // Write output file
    out_fp = fopen(output_path, "wb");
    if (!out_fp)
    {
        perror("Failed to open output file");
        status = EXIT_FAILURE;
        goto out;
    }

    uint32_t sig_len_u32 = (uint32_t)sig.length;
    fwrite(&sig_len_u32, sizeof(uint32_t), 1, out_fp);
    fwrite(sig.signature, 1, sig.length, out_fp);
    fwrite(serialized_config, 1, serialized_config_len, out_fp);

out:
    if (out_fp)
        fclose(out_fp);
    if (cfg)
        free_yaml_config(&cfg);
    if (serialized_config)
        free(serialized_config);
    free_signature(&sig);
    if (cm_priv)
        EVP_PKEY_free(cm_priv);
    if (cm_pub)
        EVP_PKEY_free(cm_pub);

    return status;
}