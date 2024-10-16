
//Include headers for socket management
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>

#include <pthread.h>
#include <cstring> // for memset

extern "C" {
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
    #include "../common/itrc.h"
    #include "spu_events.h"
    #include "stdutil/stdcarr.h"
}

int ipc_sock_hmi;
// itrc_data proxy_data;
itrc_data mainthread_to_itrcthread_data;
itrc_data itr_client_data;
int ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;

void setup_ipc_for_hmi()
{   
    // // My_ID = PNNL;
    // // memset(&proxy_data, 0, sizeof(itrc_data));
    // // sprintf(proxy_data.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
    // // sprintf(proxy_data.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
    // // sprintf(proxy_data.ipc_local, "%s%d", (char *)HMIPROXY_IPC_HMI, My_ID);
    // // sprintf(proxy_data.ipc_remote, "%s%d", (char *)HMI_IPC_MAIN, My_ID);
    
    // // ipc_sock_hmi = IPC_DGram_Sock(proxy_data.ipc_local);
    ipc_sock_hmi = IPC_DGram_Sock("/tmp/hmi-to-proxy-ipc-sock");
}

void *listen_on_hmi_sock(void *arg){
    UNUSED(arg);

    int ret; 
    char buf[MAX_LEN];
    signed_message *mess;
    int nbytes;

    for (;;) {
        perror("waiting to recv smth on hmi sock (perror)");
        ret = IPC_Recv(ipc_sock_hmi, buf, MAX_LEN);
        if (ret < 0) {
            printf("HMI-proxy: IPC_Rev failed\n");
        }
        else {
            perror("received something (perror)\n");
            printf("received something (printf)\n");
            // perror(buf);
            mess = (signed_message *)buf;
            nbytes = sizeof(signed_message) + mess->len;
            // IPC_Send(ipc_sock_main_to_itrcthread, (void *)mess, nbytes, mainthread_to_itrcthread_data.ipc_remote);
            // IPC_Send(ipc_sock_main_to_itrcthread, (void *)mess, nbytes, "/tmp/hmiproxy_ipc_itrc");
            IPC_Send(ipc_sock_main_to_itrcthread, (void *)mess, nbytes, "/tmp/hmiproxy_ipc_itrc4");
            perror("mess forwarded to itrc thread\n");
            printf("mess forwarded to itrc thread (printf)\n");
        }
    }
    // return NULL;
}

void itrc_init(char **av) 
{   
    char *ip;
    struct timeval now;

    My_Global_Configuration_Number = 0;
    Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    Seq_Num = 1;
    Type = HMI_TYPE;
    // My_ID = PROXY_FOR_PNNL;
    My_ID = 4; // PROXY_FOR_PNNL = 4. getting a 'PROXY_FOR_PNNL' was not declared in this scope error. TODO: figure out.
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU + My_ID;
    My_IP = getIP();

    // Setup IPC for HMI main thread
    memset(&mainthread_to_itrcthread_data, 0, sizeof(itrc_data));
    sprintf(mainthread_to_itrcthread_data.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
    sprintf(mainthread_to_itrcthread_data.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
    // sprintf(mainthread_to_itrcthread_data.ipc_local, "%s%d", (char *)HMIPROXY_IPC_MAIN, My_ID);
    // sprintf(mainthread_to_itrcthread_data.ipc_remote, "%s%d", (char *)HMIPROXY_IPC_ITRC, My_ID);
    // getting a 'HMIPROXY_IPC_MAIN' was not declared in this scope error. TODO: figure out.
    // getting a 'HMIPROXY_IPC_ITRC' was not declared in this scope error. TODO: figure out.
    sprintf(mainthread_to_itrcthread_data.ipc_local, "%s%d", (char *)"/tmp/hmiproxy_ipc_main", My_ID);
    sprintf(mainthread_to_itrcthread_data.ipc_remote, "%s%d", (char *)"/tmp/hmiproxy_ipc_itrc", My_ID);
    // ipc_sock_main_to_itrcthread = IPC_DGram_Sock(mainthread_to_itrcthread_data.ipc_local);
    // ipc_sock_main_to_itrcthread = IPC_DGram_Sock("/tmp/hmiproxy_ipc_main");
    ipc_sock_main_to_itrcthread = IPC_DGram_Sock("/tmp/hmiproxy_ipc_main4");

    // Setup IPC for Worker thread (itrc client)
    memset(&itr_client_data, 0, sizeof(itrc_data));
    sprintf(itr_client_data.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
    sprintf(itr_client_data.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
    // sprintf(itr_client_data.ipc_local, "%s%d", (char *)HMIPROXY_IPC_ITRC, My_ID);
    // sprintf(itr_client_data.ipc_remote, "%s%d", (char *)HMIPROXY_IPC_MAIN, My_ID);
    // getting a 'HMIPROXY_IPC_ITRC' was not declared in this scope error. TODO: figure out.
    // getting a 'HMIPROXY_IPC_MAIN' was not declared in this scope error. TODO: figure out.
    sprintf(itr_client_data.ipc_local, "%s%d", (char *)"/tmp/hmiproxy_ipc_itrc", My_ID);
    sprintf(itr_client_data.ipc_remote, "%s%d", (char *)"/tmp/hmiproxy_ipc_main", My_ID);
    ip = strtok(av[1], ":");
    sprintf(itr_client_data.spines_ext_addr, "%s", ip);
    ip = strtok(NULL, ":");
    sscanf(ip, "%d", &itr_client_data.spines_ext_port);
}

int main(int ac, char **av){
    // Usage check
    if (ac < 2 || ac > 3) {
        printf("Invalid args\n");
        printf("Usage: %s spinesAddr:spinesPort [-port=PORT]\n", av[0]);
        exit(EXIT_FAILURE);
    }

    pthread_t hmi_listen_thread;
    pthread_t itrc_thread;

    setup_ipc_for_hmi();
    itrc_init(av);

    pthread_create(&hmi_listen_thread, NULL, &listen_on_hmi_sock, NULL);
    pthread_create(&itrc_thread, NULL, &ITRC_Client, (void *)&itr_client_data);
    
    pthread_join(hmi_listen_thread, NULL);
    pthread_join(itrc_thread, NULL);

    // printf("hello\n");
    return 0;
}