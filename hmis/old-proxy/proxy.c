/* HMI-side Proxy implementation */
#include <stdio.h>

extern "C" {
    #include "../common/itrc.h"
}

itrc_data hmi_comm_data, itrc_thread_data;
pthread_t hmi_thread, itrc_thread;
char *ip_ptr;

// void itrc_init() {
//     // get my IP
//     // get prime client id
//     // set type, id etc

//     // Set IPC for what was previously HMI main thread

//     // Set up IPC for what was previously the worker thread (iprc client) on the HMI
// } 

int main(int argc, char *argv[])
{
    /* Parse args */
    if (argc != 2) {
        printf("HELP: proxy spinesAddr:spinesPort\n");
        return 0;
    }

    // Setup IPC for the Worker Thread (running the ITRC Client) (to talk to prime via spines)
    memset(&itrc_thread_data, 0, sizeof(itrc_data));
    sprintf(itrc_thread_data.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS); // TODO: update the last params
    sprintf(itrc_thread_data.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    sprintf(itrc_thread_data.ipc_local, "%s%d", (char *)RTU_IPC_ITRC, My_ID);
    sprintf(itrc_thread_data.ipc_remote, "%s%d", (char *)RTU_IPC_MAIN, My_ID);
    ip_ptr = strtok(argv[2], ":");
    sprintf(itrc_thread_data.spines_ext_addr, "%s", ip_ptr);
    ip_ptr = strtok(NULL, ":");
    sscanf(ip_ptr, "%d", &itrc_thread_data.spines_ext_port);

    printf("HMI-PROXY: Setting up ITRC Client thread\n");
    pthread_create(&itrc_thread, NULL, &ITRC_Client, (void *)&itrc_thread_data);
    fflush(stdout);

    // TODO: FDSET and a loop for select below
}