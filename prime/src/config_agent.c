#define _GNU_SOURCE
#define __USE_MISC

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <time.h>
#include <ifaddrs.h>
#include <dirent.h>

#include "spu_alarm.h"
#include "spu_events.h"
#include "net_wrapper.h"
#include "spines_lib.h"
// #include "parser.h"
// #include "key_generation.h"
#include "config_utils.h"
#include "def.h"

#define MAX_DAEMONS 256
#define BASE_SPINES_CONFIG "base_spines.conf"
#define SPINES_INT_FILE "../../spines/daemon/spines_int.conf"
#define SPINES_EXT_FILE "../../spines/daemon/spines_ext.conf"
#define DEFAULT_SPINES_ADDR "127.0.0.1"
#define DEFAULT_SPINES_PORT 8200
const char spines_internal_key_dir[] = "../../spines/daemon/internal_keys";
const char spines_external_key_dir[] = "../../spines/daemon/external_keys";

typedef struct
{
    int spines_int;
    int spines_ext;
    int prime;
    int scada_master;
    int jhu_hmi;
    int pnnl_hmi;
    int ems_hmi;
    int proxy;
    int benchmark;
} ComponentFlags;

typedef struct
{
    const char *ip;
    unsigned id;
} DaemonEntry;

// Fragmentation and message size constants
#define MAX_FRAGMENT_SIZE (MAX_SPINES_CLIENT_MSG - 12)
#define MAX_TOTAL_SIZE (10 * 1024 * 1024) // 10 MB max config

// Structure for each configuration message fragment header
typedef struct dummy_conf_fragment
{
    int32u conf_id;
    int32u total_fragments;
    int32u fragment_index;
} conf_fragment;

// Global state variables
static int Ctrl_Spines = -1;
static int32u Conf_ID = 1;

// Buffers for fragment data and lengths
static char **fragment_data = NULL;
static size_t *fragment_lens = NULL;

// Fragment tracking
static int received_fragments = 0;
static int expected_fragments = -1;

static int32u Last_Seen_Conf_ID = 0;
static char latest_config_path[512] = "received_configs/latest.yaml";

static char Spines_Addr[32] = DEFAULT_SPINES_ADDR;
static int Spines_Port = DEFAULT_SPINES_PORT;
static char Host_Name[128] = {0}; // Empty string by default

int log_to_file = 0;

static void Init_Network(void);
static void Handle_Conf_Message(int s, int source, void *dummy);
static void Usage(int argc, char **argv);
static void Print_Usage(void);

int Assemble_Config_Buffer(char **out_buf, size_t *out_len);
int Verify_Config_Signature(const char *buf, size_t len);
int Handle_Verified_Config(const char *yaml_data, size_t yaml_len);
void Cleanup_Fragments(void);

void start_components_from_config(const struct config *cfg, const struct host *me, ComponentFlags *restarted);
int kill_all_components(ComponentFlags *flags);
void pad_killed_logs(const ComponentFlags *killed, const ComponentFlags *restarted);
void generate_spines_topologies(const struct config *cfg);

int main(int argc, char **argv)
{
    Alarm_set_types(PRINT);

    Usage(argc, argv);

    // set up multicast socket for receiving config messages
    Init_Network();

    // Initialize Spines events
    E_init();

    // attach a handler to the Spines socket for READ events
    E_attach_fd(Ctrl_Spines, READ_FD, Handle_Conf_Message, 0, NULL, HIGH_PRIORITY);

    // Start the event loop
    E_handle_events();
    return 0;
}

static void Init_Network(void)
{
    struct ip_mreq mreq;

    // create a spines socket to receive the messsages
    Ctrl_Spines = Spines_Sock(Spines_Addr, Spines_Port, SPINES_PRIORITY, CONF_SPINES_MCAST_PORT);
    if (Ctrl_Spines < 0)
    {
        Alarm(EXIT, "Config_Agent: Error setting up Spines socket\n");
    }

    // join the multicast group on any interface
    mreq.imr_multiaddr.s_addr = inet_addr(CONF_SPINES_MCAST_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    // add multicast group membership for spines socket
    if (spines_setsockopt(Ctrl_Spines, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0)
    {
        Alarm(EXIT, "Config_Agent: Failed to join multicast group\n");
    }

    Alarm(PRINT, "Config_Agent: Ready!\n");
}

static void Handle_Conf_Message(int s, int source, void *dummy)
{
    char buffer[MAX_FRAGMENT_SIZE + sizeof(conf_fragment)];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    // receive frag from spines socket
    int ret = spines_recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr *)&from_addr, &from_len);
    if (ret <= 0)
        return;

    // ignore if fragments too small
    if (ret < sizeof(conf_fragment))
    {
        Alarm(DEBUG, "Config_Agent: Received fragment too small\n");
        return;
    }

    conf_fragment *hdr = (conf_fragment *)buffer;
    char *payload = buffer + sizeof(conf_fragment);
    size_t payload_len = ret - sizeof(conf_fragment);

    // ignore duplicate and older config ids
    if (hdr->conf_id <= Last_Seen_Conf_ID)
    {
        Alarm(DEBUG, "Config_Agent: Ignoring duplicate or older conf_id %u (last seen: %u)\n", hdr->conf_id, Last_Seen_Conf_ID);
        return;
    }

    // if its the first time seeing this config id, or its a new config id
    if (expected_fragments == -1 || hdr->conf_id != Conf_ID)
    {
        // clean up if there are existing fragments
        if (fragment_data != NULL)
        {
            for (int i = 0; i < expected_fragments; i++)
            {
                free(fragment_data[i]);
            }
            free(fragment_data);
            free(fragment_lens);
            fragment_data = NULL;
            fragment_lens = NULL;
        }

        // update state for new config
        expected_fragments = hdr->total_fragments;
        received_fragments = 0;
        Conf_ID = hdr->conf_id;

        fragment_data = calloc(expected_fragments, sizeof(char *));
        fragment_lens = calloc(expected_fragments, sizeof(size_t));

        Alarm(DEBUG, "Config_Agent: Resetting to expect %d fragments for new conf ID %u\n", expected_fragments, Conf_ID);
    }

    // drop unexpected fragments
    if (hdr->conf_id < Conf_ID || hdr->fragment_index >= expected_fragments)
    {
        Alarm(DEBUG, "Config_Agent: Unexpected conf_id or fragment index\n");
        return;
    }

    // drop duplicate f ragments
    if (fragment_data[hdr->fragment_index] != NULL)
    {
        Alarm(DEBUG, "Config_Agent: Duplicate fragment %d ignored\n", hdr->fragment_index);
        return;
    }

    // store fragment
    fragment_data[hdr->fragment_index] = malloc(payload_len);
    memcpy(fragment_data[hdr->fragment_index], payload, payload_len);
    fragment_lens[hdr->fragment_index] = payload_len;
    received_fragments++;

    Alarm(DEBUG, "Config_Agent: Got fragment %d/%d (len=%lu)\n", hdr->fragment_index + 1, expected_fragments, payload_len);

    // if all fragments received, assemble and process the config
    if (received_fragments == expected_fragments)
    {
        Alarm(PRINT, "Config_Agent: All %d fragments received. Assembling config...\n", expected_fragments);

        char *assembled = NULL;
        size_t assembled_len = 0;

        // combine frags into a full buffer
        if (Assemble_Config_Buffer(&assembled, &assembled_len) != 0)
        {
            Alarm(PRINT, "Config_Agent: Failed to assemble config buffer\n");
            Cleanup_Fragments();
            return;
        }

        // verify the signature
        if (Verify_Config_Signature(assembled, assembled_len) != 0)
        {
            Alarm(PRINT, "Config_Agent: Signature is INVALID\n");
            free(assembled);
            Conf_ID = 0;
            Cleanup_Fragments();
            return;
        }

        // parse the yaml and process the config
        if (Handle_Verified_Config(assembled, assembled_len) != 0)
        {
            Alarm(PRINT, "Config_Agent: Failed to handle verified config\n");
        }
        else
        {
            Last_Seen_Conf_ID = Conf_ID;
            Conf_ID = 0;
        }

        free(assembled);
        Cleanup_Fragments();
    }
}

/**
 * Reassembles received configuration fragments into a single contiguous buffer.
 */
int Assemble_Config_Buffer(char **out_buf, size_t *out_len)
{
    if (!fragment_data || !fragment_lens || expected_fragments <= 0)
        return -1;

    size_t total_len = 0;
    for (int i = 0; i < expected_fragments; i++)
    {
        if (!fragment_data[i])
            return -2;
        total_len += fragment_lens[i];
    }

    char *assembled = malloc(total_len);
    if (!assembled)
        return -3;

    size_t offset = 0;
    for (int i = 0; i < expected_fragments; i++)
    {
        memcpy(assembled + offset, fragment_data[i], fragment_lens[i]);
        offset += fragment_lens[i];
    }

    *out_buf = assembled;
    *out_len = total_len;
    return 0;
}

/**
 * Verifies the signature on a received configuration buffer.
 */
int Verify_Config_Signature(const char *buf, size_t len)
{
    if (len < sizeof(uint32_t))
        return -1;

    uint32_t sig_len;
    memcpy(&sig_len, buf, sizeof(uint32_t));
    if (len < sizeof(uint32_t) + sig_len)
        return -2;

    unsigned char *signature = (unsigned char *)(buf + sizeof(uint32_t));
    const char *yaml_data = buf + sizeof(uint32_t) + sig_len;
    size_t yaml_len = len - (sizeof(uint32_t) + sig_len);

    EVP_PKEY *pubkey = load_key_from_file("cm_keys/public_key.pem", 0);
    if (!pubkey)
        return -3;

    int valid = verify_buffer((unsigned char *)yaml_data, yaml_len, signature, sig_len, pubkey);
    EVP_PKEY_free(pubkey);

    return valid == 0 ? 0 : -4;
}

/**
 * Parses, processes, and saves a verified YAML configuration buffer.
 */
int Handle_Verified_Config(const char *buf, size_t len)
{
    uint32_t sig_len;
    memcpy(&sig_len, buf, sizeof(uint32_t));
    const char *yaml_data = buf + sizeof(uint32_t) + sig_len;
    size_t yaml_len = len - (sizeof(uint32_t) + sig_len);

    struct config *cfg = load_yaml_config_from_string(yaml_data, yaml_len);
    if (!cfg)
        return -1;

    if (cfg->configuration_id != Conf_ID || cfg->configuration_id <= Last_Seen_Conf_ID)
    {
        Alarm(PRINT, "Config_Agent: Ignoring config with id %u (expected: %u, last seen: %u)\n",
              cfg->configuration_id, Conf_ID, Last_Seen_Conf_ID);
        free_yaml_config(&cfg);
        return 0;
    }
    ComponentFlags killed = {0};
    ComponentFlags restarted = {0};
    kill_all_components(&killed);
    generate_spines_topologies(cfg);
    struct host *me = find_host_by_name(cfg, Host_Name);
    if (!me)
    {
        Alarm(PRINT, "Host '%s' not found in config. Skipping component startup.\n", Host_Name);
        pad_killed_logs(&killed, &restarted);
        free_yaml_config(&cfg);
        return 0;
    }

    sleep(5);

    const char *dir = "received_configs";
    struct stat st = {0};
    if (stat(dir, &st) == -1)
    {
        mkdir(dir, 0755);
    }

    // write the file out, include timestamp
    // config_<config id>_<timestamp>.yaml
    char filename[512];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(filename, sizeof(filename),
             "%s/config_%u_%04d%02d%02d_%02d%02d%02d.yaml",
             dir,
             Conf_ID,
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    FILE *fp = fopen(filename, "w");
    if (!fp)
    {
        Alarm(PRINT, "Config_Agent: Failed to write config file to %s\n", filename);
    }
    else
    {
        fwrite(yaml_data, 1, yaml_len, fp);
        fclose(fp);
        Alarm(PRINT, "Config_Agent: Saved config to %s\n", filename);
    }

    // Also save a consistent copy as latest.yaml
    FILE *latest_fp = fopen(latest_config_path, "w");
    if (!latest_fp)
    {
        Alarm(PRINT, "Config_Agent: Failed to write latest config to %s\n", latest_config_path);
    }
    else
    {
        fwrite(yaml_data, 1, yaml_len, latest_fp);
        fclose(latest_fp);
        Alarm(PRINT, "Config_Agent: Updated %s with latest config\n", latest_config_path);
    }

    start_components_from_config(cfg, me, &restarted);
    pad_killed_logs(&killed, &restarted);

    free_yaml_config(&cfg);
    return 0;
}

void Cleanup_Fragments(void)
{
    if (fragment_data)
    {
        for (int i = 0; i < expected_fragments; i++)
        {
            free(fragment_data[i]);
        }
        free(fragment_data);
        fragment_data = NULL;
    }

    free(fragment_lens);
    fragment_lens = NULL;

    received_fragments = 0;
    expected_fragments = -1;
}

static void Usage(int argc, char **argv)
{
    int ret;
    int got_host_name = 0;

    while (--argc > 0)
    {
        argv++;
        if ((argc > 1) && (!strncmp(*argv, "-a", 2)))
        {
            ret = snprintf(Spines_Addr, sizeof(Spines_Addr), "%s", argv[1]);
            if (ret < 0 || ret >= sizeof(Spines_Addr))
            {
                Alarm(PRINT, "Invalid Spines IP address: %s\n", argv[1]);
                Print_Usage();
            }
            argc--;
            argv++;
        }
        else if ((argc > 1) && (!strncmp(*argv, "-p", 2)))
        {
            ret = sscanf(argv[1], "%d", &Spines_Port);
            if (ret != 1)
            {
                Alarm(PRINT, "Invalid Spines port: %s\n", argv[1]);
                Print_Usage();
            }
            argc--;
            argv++;
        }
        else if ((argc > 1) && (!strncmp(*argv, "-h", 2)))
        {
            ret = snprintf(Host_Name, sizeof(Host_Name), "%s", argv[1]);
            if (ret < 0 || ret >= sizeof(Host_Name))
            {
                Alarm(PRINT, "Invalid host name: %s\n", argv[1]);
                Print_Usage();
            }
            got_host_name = 1;
            argc--;
            argv++;
        }
        else if ((argc > 1) && (!strncmp(*argv, "-l", 2)))
        {
            ret = sscanf(argv[1], "%d", &log_to_file);
            if (ret != 1 || (log_to_file != 0 && log_to_file != 1))
            {
                Alarm(PRINT, "Invalid log setting: %s (must be 0 or 1)\n", argv[1]);
                Print_Usage();
            }
            argc--;
            argv++;
        }
        else
        {
            Print_Usage();
        }
    }

    if (!got_host_name)
    {
        Alarm(PRINT, "Missing required argument: -h host_name\n");
        Print_Usage();
    }
}

static void Print_Usage(void)
{
    Alarm(EXIT, "Usage: ./config_agent -h host_name\n"
                "    [-a spines_addr] : IP address of Spines daemon to connect to. Default: %s\n"
                "    [-p spines_port] : Port for Spines configuration network. Default: %d\n"
                "    [-l log_mode]    : Log destination (0 = console, 1 = file). Default: 0\n"
                "    -h host_name     : REQUIRED. Host name to match in config.\n",
          DEFAULT_SPINES_ADDR, DEFAULT_SPINES_PORT);
}

/**
 * Checks if an IP address already exists in a list of DaemonEntry structs.
 * Iterates through the list and compares the given IP against each entry.
 */
static int ip_in_list(const char *ip, DaemonEntry *list, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        if (strcmp(list[i].ip, ip) == 0)
            return 1;
    }
    return 0;
}

/**
 * Appends a new DaemonEntry to the list if the IP is not already present.
 * Assigns a new ID based on the current count and increments the count.
 */
static void append_daemon(DaemonEntry *list, size_t *count, const char *ip)
{
    if (!ip_in_list(ip, list, *count))
    {
        list[*count].ip = ip;
        list[*count].id = (unsigned)(*count + 1);
        (*count)++;
    }
}

/**
 * Writes a Spines topology file with host and edge definitions.
 */
static void write_topology_file(const char *output_path, DaemonEntry *hosts, size_t host_count, FILE *base_fp)
{
    FILE *out = fopen(output_path, "w");
    if (!out)
    {
        perror("Failed to open output file");
        return;
    }

    // Copy base config from base_spines.conf to output
    fseek(base_fp, 0, SEEK_SET);
    char line[1024];
    while (fgets(line, sizeof(line), base_fp))
    {
        fputs(line, out);
    }

    // Write Hosts section
    fprintf(out, "\nHosts {\n");
    for (size_t i = 0; i < host_count; i++)
    {
        fprintf(out, "    %u %s\n", hosts[i].id, hosts[i].ip);
    }
    fprintf(out, "}\n\n");

    // Write full mesh Edges section
    fprintf(out, "Edges {\n");
    for (size_t i = 0; i < host_count; i++)
    {
        for (size_t j = i + 1; j < host_count; j++)
        {
            fprintf(out, "    %u %u 100\n", hosts[i].id, hosts[j].id);
        }
    }
    fprintf(out, "}\n");

    fclose(out);
}

/**
 * Writes Spines public and (if applicable) private key files for a given daemon.
 */
static void write_spines_keys(const char *key_dir, int id,
                              const char *public_key,
                              const char *encrypted_private_key,
                              const char *perm_key_loc,
                              bool is_local_host)
{
    char path[512];
    FILE *fp;

    // Write public key
    snprintf(path, sizeof(path), "%s/public%d.pem", key_dir, id);
    if ((fp = fopen(path, "w")))
    {
        fputs(public_key, fp);
        fclose(fp);
    }
    else
    {
        perror("fopen public key");
    }

    // Write private key only if on local host and encrypted key is present
    if (is_local_host && encrypted_private_key)
    {
        EVP_PKEY *rsa_privkey = load_key_from_file(perm_key_loc, 1);
        if (!rsa_privkey)
        {
            fprintf(stderr, "[ERROR] Could not load TPM key from %s\n", perm_key_loc);
            return;
        }

        EVP_PKEY *decrypted_key = load_decrypted_key(encrypted_private_key, rsa_privkey);
        EVP_PKEY_free(rsa_privkey);

        if (!decrypted_key)
        {
            fprintf(stderr, "[ERROR] Failed to decrypt private key for id %d\n", id);
            return;
        }

        char *pem = get_private_key(decrypted_key);
        EVP_PKEY_free(decrypted_key);

        if (!pem)
        {
            fprintf(stderr, "[ERROR] Failed to serialize decrypted private key for id %d\n", id);
            return;
        }

        snprintf(path, sizeof(path), "%s/private%d.pem", key_dir, id);
        if ((fp = fopen(path, "w")))
        {
            fputs(pem, fp);
            fclose(fp);
        }
        else
        {
            perror("fopen private key");
        }

        free(pem);
    }
}

void generate_spines_topologies(const struct config *cfg)
{
    DaemonEntry internal_daemons[MAX_DAEMONS];
    DaemonEntry external_core[MAX_DAEMONS];
    DaemonEntry external_clients[MAX_DAEMONS];
    size_t internal_count = 0, core_count = 0, client_count = 0;

    int internal_id = 0;
    int external_id = 0;

    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            struct host *h = &site->hosts[j];
            int is_local = (strcmp(h->name, Host_Name) == 0);

            // ---- Internal Daemon Handling ----
            if (h->runs_spines_internal)
            {
                append_daemon(internal_daemons, &internal_count, h->ip);
                internal_id = internal_count;

                write_spines_keys(spines_internal_key_dir, internal_id,
                                  h->spines_internal_public_key,
                                  h->encrypted_spines_internal_private_key,
                                  h->permanent_key_location,
                                  is_local);
            }

            // ---- External Daemon Handling ----
            if (h->runs_spines_external)
            {
                if (site->type == CLIENT)
                {
                    append_daemon(external_clients, &client_count, h->ip);
                    external_id = core_count + client_count;
                }
                else
                {
                    append_daemon(external_core, &core_count, h->ip);
                    external_id = core_count;
                }

                write_spines_keys(spines_external_key_dir, external_id,
                                  h->spines_external_public_key,
                                  h->encrypted_spines_external_private_key,
                                  h->permanent_key_location,
                                  is_local);
            }
        }
    }

    // ----- INTERNAL TOPOLOGY -----
    FILE *base_fp = fopen(BASE_SPINES_CONFIG, "r");
    if (!base_fp)
    {
        perror("Failed to open base config");
        return;
    }

    write_topology_file(SPINES_INT_FILE, internal_daemons, internal_count, base_fp);
    fclose(base_fp);

    // ----- EXTERNAL TOPOLOGY -----
    FILE *out = fopen(SPINES_EXT_FILE, "w");
    if (!out)
    {
        perror("Failed to open spines_ext.conf");
        return;
    }

    base_fp = fopen(BASE_SPINES_CONFIG, "r");
    if (!base_fp)
    {
        perror("Failed to reopen base config");
        fclose(out);
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), base_fp))
        fputs(line, out);
    fclose(base_fp);

    fprintf(out, "\nHosts {\n");
    for (size_t i = 0; i < core_count; i++)
        fprintf(out, "    %zu %s\n", i + 1, external_core[i].ip);
    for (size_t i = 0; i < client_count; i++)
        fprintf(out, "    %zu %s\n", core_count + i + 1, external_clients[i].ip);
    fprintf(out, "}\n\n");

    fprintf(out, "Edges {\n");
    // Full mesh among core
    for (size_t i = 0; i < core_count; i++)
    {
        for (size_t j = i + 1; j < core_count; j++)
            fprintf(out, "    %zu %zu 100\n", i + 1, j + 1);
    }

    // Core → client connections
    for (size_t i = 0; i < core_count; i++)
    {
        for (size_t j = 0; j < client_count; j++)
            fprintf(out, "    %zu %zu 100\n", i + 1, core_count + j + 1);
    }

    fprintf(out, "}\n");
    fclose(out);
}

/**
 * Checks if a process name matches a known component (spines, prime, or scada_master).
 */
int is_target_process(const char *name)
{
    const char *targets[] = {"spines", "prime", "scada_master", "pnnl_hmi", "ems_hmi", "jhu_hmi", "proxy", "benchmark"};
    const int num_targets = sizeof(targets) / sizeof(targets[0]);
    for (int i = 0; i < num_targets; i++)
    {
        if (strcmp(name, targets[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * Appends 50 blank lines and a "killed" marker to the specified log file.
 * Used to visibly separate log output from a component that was terminated.
 */
void pad_log(const char *path, const char *name)
{
    if (access(path, F_OK) != 0)
        return; // file does not exist, skip

    FILE *fp = fopen(path, "a");
    if (!fp)
    {
        return; // could not open for append, skip
    }

    setvbuf(fp, NULL, _IONBF, 0);

    for (int i = 0; i < 50; i++)
        fputc('\n', fp);

    fprintf(fp, "[KILLED BY CONFIG AGENT] %s\n", name);
    fclose(fp);
}

/*
 * Pads the logs of any components that were killed but not restarted.
 * This provides a clear visual delimiter in their log files indicating termination.
 */
void pad_killed_logs(const ComponentFlags *killed, const ComponentFlags *restarted)
{
    if (killed->prime && !restarted->prime)
        pad_log("/app/spire/prime/bin/logs/prime.log", "prime");
    if (killed->scada_master && !restarted->scada_master)
        pad_log("/app/spire/prime/bin/logs/sm.log", "scada_master");
    if (killed->jhu_hmi && !restarted->jhu_hmi)
        pad_log("/app/spire/prime/bin/logs/jhu_hmi.log", "jhu_hmi");
    if (killed->pnnl_hmi && !restarted->pnnl_hmi)
        pad_log("/app/spire/prime/bin/logs/pnnl_hmi.log", "pnnl_hmi");
    if (killed->ems_hmi && !restarted->ems_hmi)
        pad_log("/app/spire/prime/bin/logs/ems_hmi.log", "ems_hmi");
    if (killed->proxy && !restarted->proxy)
        pad_log("/app/spire/prime/bin/logs/proxy.log", "proxy");
    if (killed->benchmark && !restarted->benchmark)
        pad_log("/app/spire/prime/bin/logs/benchmark.log", "benchmark");
}

/**
 * Scans all running processes and forcibly terminates known system components with the exception of any spines control daemons.
 */
int kill_all_components(ComponentFlags *flags)
{
    DIR *proc_dir = opendir("/proc");
    struct dirent *entry;
    int killed = 0;

    if (!proc_dir)
    {
        perror("opendir /proc");
        return -1;
    }

    // iterate through all of proc
    while ((entry = readdir(proc_dir)) != NULL)
    {
        // considering only directories (pids are dirs)
        if (entry->d_type != DT_DIR)
            continue;

        // dir name to pid
        pid_t pid = atoi(entry->d_name);
        if (pid <= 0)
            continue;

        // construct a path
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);

        // open the file to read the process name
        FILE *comm_file = fopen(comm_path, "r");
        if (!comm_file)
            continue; // couldnt open

        char comm[256];
        if (fgets(comm, sizeof(comm), comm_file))
        {
            // rm newline
            comm[strcspn(comm, "\n")] = 0;

            // if is a target process
            if (is_target_process(comm))
            {
                int skip = 0;

                // Special case: only skip spines if it's running spines_ctrl.conf
                if (strcmp(comm, "spines") == 0)
                {
                    char cmdline_path[64];
                    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
                    FILE *cmdline_file = fopen(cmdline_path, "r");
                    if (cmdline_file)
                    {
                        char cmdline[1024];
                        size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file);
                        fclose(cmdline_file);

                        if (len > 0)
                        {
                            cmdline[len] = '\0';

                            // Replace nulls with spaces to log clearly
                            for (size_t i = 0; i < len; i++)
                            {
                                if (cmdline[i] == '\0')
                                    cmdline[i] = ' ';
                            }

                            if (strstr(cmdline, "spines_ctrl") != NULL)
                            {
                                skip = 1;
                            }
                        }
                    }
                }

                if (skip)
                {
                    // printf("Skipping %s (PID %d) — spines_ctrl.conf detected\n", comm, pid);
                    continue;
                }

                if (kill(pid, SIGTERM) == 0)
                {
                    printf("Killed %s (PID %d)\n", comm, pid);
                    killed++;

                    if (strcmp(comm, "prime") == 0)
                        flags->prime = 1;
                    else if (strcmp(comm, "scada_master") == 0)
                        flags->scada_master = 1;
                    else if (strcmp(comm, "jhu_hmi") == 0)
                        flags->jhu_hmi = 1;
                    else if (strcmp(comm, "pnnl_hmi") == 0)
                        flags->pnnl_hmi = 1;
                    else if (strcmp(comm, "ems_hmi") == 0)
                        flags->ems_hmi = 1;
                    else if (strcmp(comm, "proxy") == 0)
                        flags->proxy = 1;
                    else if (strcmp(comm, "benchmark") == 0)
                        flags->benchmark = 1;
                }
                else
                {
                    perror("kill");
                }
            }
        }

        fclose(comm_file); // close file
    }

    closedir(proc_dir); // close proc
    return killed;      // return number of killed processes
}

void start_components_from_config(const struct config *cfg, const struct host *me, ComponentFlags *restarted)
{
    char cmd[1024];

    if (me->runs_spines_internal)
    {
        Alarm(PRINT, "Starting internal Spines on %s:%d\n", me->ip, SPINES_PORT);
        snprintf(cmd, sizeof(cmd),
                 "cd ../../spines/daemon && ./spines -p %d -c spines_int.conf -I %s -kd %s > ../../prime/bin/logs/spines_int.log 2>/dev/null &",
                 SPINES_PORT, me->ip, spines_internal_key_dir);
        system(cmd);
        restarted->spines_int = 1;
    }

    if (me->runs_spines_external)
    {
        Alarm(PRINT, "Starting external Spines on %s:%d\n", me->ip, SPINES_EXT_PORT);
        snprintf(cmd, sizeof(cmd),
                 "cd ../../spines/daemon && ./spines -p %d -c spines_ext.conf -I %s -kd %s > ../../prime/bin/logs/spines_ext.log 2>/dev/null &",
                 SPINES_EXT_PORT, me->ip, spines_external_key_dir);
        system(cmd);
        restarted->spines_ext = 1;
    }

    // give spines time to start
    if (restarted->spines_ext || restarted->spines_int)
    {
        sleep(3);
    }

    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->replicas_count; j++)
        {
            struct replica *r = &site->replicas[j];
            struct host *rep_host = find_host_by_name(cfg, r->host);

            if (rep_host == me)
            {
                snprintf(cmd, sizeof(cmd),
                         "./prime -i %u -g %u %s &",
                         r->instance_id, r->instance_id,
                         log_to_file ? "> logs/prime.log 2>/dev/null" : "2>/dev/null");
                system(cmd);
                Alarm(PRINT, "Starting replica (site %u, instance %u)\n", i, r->instance_id);
                snprintf(cmd, sizeof(cmd),
                         "cd ../../scada_master && ./scada_master %u %u %s &",
                         r->instance_id, r->instance_id,
                         //  log_to_file ? "> ../prime/bin/logs/sm.log" : "");
                         log_to_file ? "> ../prime/bin/logs/sm.log 2>/dev/null" : "2>/dev/null");
                system(cmd);
                restarted->prime = 1;
                restarted->scada_master = 1;
            }
        }

        if (site->type == CLIENT)
        {
            for (unsigned j = 0; j < site->clients_count; j++)
            {
                struct client *c = &site->clients[j];
                struct host *client_host = find_host_by_name(cfg, c->host);

                if (client_host == me && c->type)
                {
                    if (strcmp(c->type, "JHU") == 0)
                    {
                        Alarm(PRINT, "Starting JHU HMI client (id %u)\n", c->client_id);
                        restarted->jhu_hmi = 1;
                    }
                    else if (strcmp(c->type, "PNNL") == 0)
                    {
                        Alarm(PRINT, "Starting PNNL HMI client (id %u)\n", c->client_id);
                        restarted->pnnl_hmi = 1;
                    }
                    else if (strcmp(c->type, "EMS") == 0)
                    {
                        Alarm(PRINT, "Starting EMS HMI client (id %u)\n", c->client_id);
                        restarted->ems_hmi = 1;
                    }
                    else if (strcmp(c->type, "proxy") == 0)
                    {
                        Alarm(PRINT, "Starting proxy client (id %u)\n", c->client_id);
                        restarted->proxy = 1;
                    }
                    else if (strcmp(c->type, "benchmark") == 0)
                    {
                        Alarm(PRINT, "Starting benchmark client (id %u)\n", c->client_id);
                        restarted->benchmark = 1;
                    }
                    else
                    {
                        Alarm(PRINT, "Unknown client type '%s' for client %u — skipping\n", c->type, c->client_id);
                        continue;
                    }

                    if (strcmp(c->type, "JHU") == 0)
                        snprintf(cmd, sizeof(cmd), "cd ../../hmis/jhu_hmi/ && ./jhu_hmi %s &",
                                 log_to_file ? "> ../../prime/bin/logs/jhu_hmi.log 2>/dev/null" : "2>/dev/null");
                    else if (strcmp(c->type, "PNNL") == 0)
                        snprintf(cmd, sizeof(cmd), "cd ../../hmis/pnnl_hmi/ && ./pnnl_hmi %s &",
                                 log_to_file ? "> ../../prime/bin/logs/pnnl_hmi.log 2>/dev/null" : "2>/dev/null");
                                //  log_to_file ? "> ../../prime/bin/logs/pnnl_hmi.log" : "");
                    else if (strcmp(c->type, "EMS") == 0)
                        snprintf(cmd, sizeof(cmd), "cd ../../hmis/ems_hmi/ && ./ems_hmi %s &",
                                 log_to_file ? "> ../../prime/bin/logs/ems_hmi.log 2>/dev/null" : "2>/dev/null");
                    else if (strcmp(c->type, "proxy") == 0)
                        snprintf(cmd, sizeof(cmd), "cd ../../proxy/ && ./proxy %u 1 %s &",
                                 c->client_id, log_to_file ? "> ../prime/bin/logs/proxy.log 2>/dev/null" : "2>/dev/null");
                                //  c->client_id, log_to_file ? "> ../prime/bin/logs/proxy.log" : "");
                    else if (strcmp(c->type, "benchmark") == 0)
                        snprintf(cmd, sizeof(cmd), "cd ../../benchmark/ && ./benchmark %u 1000000 100 %s &",
                                 c->client_id, log_to_file ? "> ../prime/bin/logs/benchmark.log 2>/dev/null" : "2>/dev/null");

                    system(cmd);
                }
            }
        }
    }
}