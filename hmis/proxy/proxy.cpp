
//Include headers for socket management
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <cstring> // for memset
#include <string>

extern "C" {
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
    #include "../common/itrc.h"
    #include "spu_events.h"
    #include "stdutil/stdcarr.h"
    #include "spines_lib.h"
}

#define DATA_COLLECTOR_SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines

int ipc_sock_hmi;
// itrc_data proxy_data;
itrc_data mainthread_to_itrcthread_data;
itrc_data itr_client_data;
int ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;

// for comm. with data collector:
int dc_spines_sock; // spines socket to be used for communicating with the data collector
struct sockaddr_in dc_addr; // data collector's address (contains ip addr and port)

void usage_check(int ac, char **av);
void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, std::string &dc_ip_addr, int &dc_port);
void setup_ipc_for_hmi();
void itrc_init(std::string spinesd_ip_addr, int spinesd_port);
void setup_datacoll_spines_sock(std::string spinesd_ip_addr, int spinesd_port, std::string dc_ip_addr, int dc_port);
void *listen_on_hmi_sock(void *arg);

int main(int ac, char **av){
    std::string spinesd_ip_addr; // for spines daemon
    int spinesd_port;
    std::string dc_ip_addr; // for data collector
    int dc_port;

    parse_args(ac, av, spinesd_ip_addr, spinesd_port, dc_ip_addr, dc_port);

    pthread_t hmi_listen_thread;
    pthread_t itrc_thread;

    setup_ipc_for_hmi();
    itrc_init(spinesd_ip_addr, spinesd_port);
    setup_datacoll_spines_sock(spinesd_ip_addr, spinesd_port, dc_ip_addr, dc_port);

    pthread_create(&hmi_listen_thread, NULL, &listen_on_hmi_sock, NULL);
    pthread_create(&itrc_thread, NULL, &ITRC_Client, (void *)&itr_client_data);
    
    pthread_join(hmi_listen_thread, NULL);
    pthread_join(itrc_thread, NULL);

    return 0;
}

void usage_check(int ac, char **av) {
    // Usage check
    if (ac != 3) {
        printf("Invalid args\n");
        printf("Usage: %s spinesAddr:spinesPort dataCollectorAddr:dataCollectorPort\n", av[0]);
        exit(EXIT_FAILURE);
    }
}

void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, std::string &dc_ip_addr, int &dc_port) {
    usage_check(ac, av);

    int colon_pos;
    std::string spinesd_arg = av[1];
    std::string dc_arg = av[2];

    colon_pos = -1;
    colon_pos = spinesd_arg.find(':');
    spinesd_ip_addr = spinesd_arg.substr(0, colon_pos);
    spinesd_port = std::stoi(spinesd_arg.substr(colon_pos + 1));

    colon_pos = -1;
    colon_pos = dc_arg.find(':');
    dc_ip_addr = dc_arg.substr(0, colon_pos);
    dc_port = std::stoi(dc_arg.substr(colon_pos + 1));
}

void setup_datacoll_spines_sock(std::string spinesd_ip_addr, int spinesd_port, std::string dc_ip_addr, int dc_port) {
    int proto;//, num, ret;
    int spines_timeout;
    // char* spinesd_ip_addr = strtok(strdup(av[1]), ":");
    // int spinesd_port = atoi(strtok(NULL, ":"));

    // char* dc_ip_addr = strtok(strdup(av[2]), ":");
    // int dc_port = atoi(strtok(NULL, ":"));
    
    // proto = SPINES_PRIORITY;
    proto = SPINES_RELIABLE;
    
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
     *  this often */
    spines_timeout = DATA_COLLECTOR_SPINES_CONNECT_SEC;

    dc_spines_sock = -1; // -1 is not a real socket so init to that
    while (1)
    {
        dc_spines_sock = Spines_SendOnly_Sock(spinesd_ip_addr.c_str(), spinesd_port, proto);
        if (dc_spines_sock < 0) {
            std::cout << "setup_datacoll_spines_sock(): Unable to connect to Spines, trying again soon\n";
            sleep(spines_timeout);
        }
        else {
            std::cout << "setup_datacoll_spines_sock(): Connected to Spines\n";
            break;
        }
    }

    dc_addr.sin_family = AF_INET;
    dc_addr.sin_port = htons(dc_port);
    dc_addr.sin_addr.s_addr = inet_addr(dc_ip_addr.c_str());
    
    // int i = 64; // 'A' is 65
    // while (1) {
    //     i++;
    //     char msg;
    //     msg = char(i);
    //     std::cout << "sending\n";
    //     ret = spines_sendto(dc_spines_sock, &msg, sizeof(char), 0, (struct sockaddr *)&dc_addr, sizeof(struct sockaddr));
    //     std::cout << "sent with return code ret =" << ret << "\n";
    //     sleep(5);
    // }
}

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

void itrc_init(std::string spinesd_ip_addr, int spinesd_port) 
{   
    // char *ip;
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
    // ip = strtok(av[1], ":");
    // sprintf(itr_client_data.spines_ext_addr, "%s", ip);
    sprintf(itr_client_data.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    // ip = strtok(NULL, ":");
    // sscanf(ip, "%d", &itr_client_data.spines_ext_port);
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itr_client_data.spines_ext_port);
}

void *listen_on_hmi_sock(void *arg){
    UNUSED(arg);

    int ret, dc_ret; 
    char buf[MAX_LEN];
    signed_message *mess;
    int nbytes;


    // <tmp>
    int dc_i = 64; // 'A' is 65
    char dc_msg;
    // </tmp>

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

            std::cout << "sending to data collector\n";
            dc_i++;
            dc_msg = char(dc_i);
            dc_ret = spines_sendto(dc_spines_sock, &dc_msg, sizeof(char), 0, (struct sockaddr *)&dc_addr, sizeof(struct sockaddr));
            std::cout << "sent to data collector with return code ret =" << dc_ret << "\n";
        }
    }
    // return NULL;
}