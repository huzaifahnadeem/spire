
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

bool data_collector_isinsystem = false;
bool shadow_isinsystem = false;

int ipc_sock_hmi;
// itrc_data proxy_data;
itrc_data mainthread_to_itrcthread_data;
itrc_data itr_client_data;
int ipc_sock_main_to_itrcthread;
int shadow_ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;

// for comm. with data collector:
int dc_spines_sock; // spines socket to be used for communicating with the data collector
struct sockaddr_in dc_addr; // data collector's address (contains ip addr and port)

void usage_check(int ac, char **av);
void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, std::string &dc_ip_addr, int &dc_port, std::string &shadow_spinesd_ip_addr, int &shadow_spinesd_port);
void setup_ipc_for_hmi();
void itrc_init(std::string spinesd_ip_addr, int spinesd_port);
void setup_datacoll_spines_sock(std::string spinesd_ip_addr, int spinesd_port, std::string dc_ip_addr, int dc_port);
void recv_then_fw_to_hmi_and_dc(int s, int dummy1, void *dummy2);
void *handler_msg_from_itrc(void *arg);
void *listen_on_hmi_sock(void *arg);
void send_to_data_collector(signed_message *msg, nbytes, int nbytes);
void itrc_init_shadow(std::string spinesd_ip_addr, int spinesd_port);

int main(int ac, char **av){
    std::string spinesd_ip_addr; // for spines daemon (main system)
    int spinesd_port;
    std::string dc_ip_addr; // for data collector
    int dc_port;
    std::string shadow_spinesd_ip_addr; // for spines daemon (shadow system)
    int shadow_spinesd_port;

    parse_args(ac, av, spinesd_ip_addr, spinesd_port, dc_ip_addr, dc_port, spinesd_ip_addr, spinesd_port);

    pthread_t hmi_listen_thread;
    pthread_t itrc_thread;
    pthread_t handle_msg_from_itrc_thread;

    setup_ipc_for_hmi();
    itrc_init(spinesd_ip_addr, spinesd_port);
    if (shadow_isinsystem) {
        itrc_init_shadow(shadow_spinesd_ip_addr, shadow_spinesd_port);
    }
    if (data_collector_isinsystem) {
        setup_datacoll_spines_sock(spinesd_ip_addr, spinesd_port, dc_ip_addr, dc_port);
    }

    pthread_create(&handle_msg_from_itrc_thread, NULL, &handler_msg_from_itrc, NULL); // receives messages from itrc client
    pthread_create(&hmi_listen_thread, NULL, &listen_on_hmi_sock, NULL); // listens for command messages coming from the HMI and forwards it to the ITRC client and the data collector
    pthread_create(&itrc_thread, NULL, &ITRC_Client, (void *)&itr_client_data); // ITRC_Client thread will take care of any forwarding/receving the replicas via spines
    
    pthread_join(hmi_listen_thread, NULL);
    pthread_join(itrc_thread, NULL);

    return 0;
}

void usage_check(int ac, char **av) {
    // Usage check
    if (ac == 2) { // running with just the main system
        data_collector_isinsystem = false;
        shadow_isinsystem = false;
    }
    else if (ac == 3) { // running with the main system and the data collector
        data_collector_isinsystem = true;
        shadow_isinsystem = false;
    }
    else if (ac == 4) { // running with the main system, the data collector, and the shadow system
        data_collector_isinsystem = true;
        shadow_isinsystem = true;
    }
    else {
        printf("Invalid args\n");
        printf("Usage: %s spinesAddr:spinesPort dataCollectorAddr:dataCollectorPort\n", av[0]);
        exit(EXIT_FAILURE);
    }
}

void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, std::string &dc_ip_addr, int &dc_port, std::string &shadow_spinesd_ip_addr, int &shadow_spinesd_port) {
    usage_check(ac, av);

    int colon_pos;
    
    std::string spinesd_arg = av[1];
    colon_pos = -1;
    colon_pos = spinesd_arg.find(':');
    spinesd_ip_addr = spinesd_arg.substr(0, colon_pos);
    spinesd_port = std::stoi(spinesd_arg.substr(colon_pos + 1));

    if (data_collector_isinsystem) {
        std::string dc_arg = av[2];
        colon_pos = -1;
        colon_pos = dc_arg.find(':');
        dc_ip_addr = dc_arg.substr(0, colon_pos);
        dc_port = std::stoi(dc_arg.substr(colon_pos + 1));
    }

    if (shadow_isinsystem) {
        std::string shadow_spinesd_arg = av[3];
        colon_pos = -1;
        colon_pos = spinesd_arg.find(':');
        shadow_spinesd_ip_addr = shadow_spinesd_arg.substr(0, colon_pos);
        shadow_spinesd_port = std::stoi(shadow_spinesd_arg.substr(colon_pos + 1));

    }
}

void setup_datacoll_spines_sock(std::string spinesd_ip_addr, int spinesd_port, std::string dc_ip_addr, int dc_port) {
    int proto;//, num, ret;
    int spines_timeout;
    
    proto = SPINES_RELIABLE; // need to use SPINES_RELIABLE and not SPINES_PRIORITY. This is because we need to be sure the message is delivered. SPINES_PRIORITY can drop messages. might need to think more though (but thats for later)
    
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

void recv_then_fw_to_hmi_and_dc(int s, int dummy1, void *dummy2) // called by handler_msg_from_itrc
{   
    int ret; 
    int nbytes;
    char buf[MAX_LEN];
    signed_message *mess;

    UNUSED(dummy1);
    UNUSED(dummy2);

    // Receive from ITRC Client"
    std::cout << "There is a message from the ITRC Client\n";
    ret = IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("recv_msg_from_itrc(): IPC_Rev failed\n");
    
    // Forward to HMI
    mess = (signed_message *)buf;
    nbytes = sizeof(signed_message) + mess->len;
    IPC_Send(ipc_sock_hmi, (void *)mess, nbytes, "/tmp/hmi-to-proxy-ipc-sock"); // TODO: change static string
    std::cout << "The message has been forwarded to the HMI\n";

    if (data_collector_isinsystem) {
        // Forward to the Data Collector:
        send_to_data_collector(mess, nbytes);
    }
}

void *handler_msg_from_itrc(void *arg)
{
    UNUSED(arg);

    E_init();
    E_attach_fd(ipc_sock_main_to_itrcthread, READ_FD, recv_then_fw_to_hmi_and_dc, 0, NULL, MEDIUM_PRIORITY); // recv_then_fw_to_hmi_and_dc called when there is a message to be received from the proxy
    if (shadow_isinsystem){
        E_attach_fd(shadow_ipc_sock_main_to_itrcthread, READ_FD, recv_then_fw_to_hmi_and_dc, 0, NULL, MEDIUM_PRIORITY); // recv_then_fw_to_hmi_and_dc called when there is a message to be received from the proxy
    }
    E_handle_events();

    return NULL;
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

            if (data_collector_isinsystem) {
                dc_i++;
                dc_msg = char(dc_i);
                send_to_data_collector(mess, nbytes);
            }
            if (shadow_isinsystem) {
                IPC_Send(shadow_ipc_sock_main_to_itrcthread, (void *)mess, nbytes, "/tmp/shadow_hmiproxy_ipc_itrc4");
                perror("mess forwarded to itrc thread\n");
                printf("mess forwarded to itrc thread (printf)\n");
            }
        }
    }
    return NULL;
}

void send_to_data_collector(signed_message *msg, nbytes, int nbytes) { // TODO: adjust param to signed mess or something
    int ret;
    std::cout << "sending to data collector\n";
    ret = spines_sendto(dc_spines_sock, (void *)msg, nbytes, 0, (struct sockaddr *)&dc_addr, sizeof(struct sockaddr));
    std::cout << "sent to data collector with return code ret =" << ret << "\n";
}

void itrc_init_shadow(std::string spinesd_ip_addr, int spinesd_port) // TODO: its largely the same fn as itrc_init, combine the two
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
    sprintf(mainthread_to_itrcthread_data.ipc_local, "%s%d", (char *)"/tmp/shadow_hmiproxy_ipc_main", My_ID);
    sprintf(mainthread_to_itrcthread_data.ipc_remote, "%s%d", (char *)"/tmp/shadow_hmiproxy_ipc_itrc", My_ID);
    // ipc_sock_main_to_itrcthread = IPC_DGram_Sock(mainthread_to_itrcthread_data.ipc_local);
    // ipc_sock_main_to_itrcthread = IPC_DGram_Sock("/tmp/hmiproxy_ipc_main");
    shadow_ipc_sock_main_to_itrcthread = IPC_DGram_Sock("/tmp/shadow_hmiproxy_ipc_main4");

    // Setup IPC for Worker thread (itrc client)
    memset(&itr_client_data, 0, sizeof(itrc_data));
    sprintf(itr_client_data.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
    sprintf(itr_client_data.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
    // sprintf(itr_client_data.ipc_local, "%s%d", (char *)HMIPROXY_IPC_ITRC, My_ID);
    // sprintf(itr_client_data.ipc_remote, "%s%d", (char *)HMIPROXY_IPC_MAIN, My_ID);
    // getting a 'HMIPROXY_IPC_ITRC' was not declared in this scope error. TODO: figure out.
    // getting a 'HMIPROXY_IPC_MAIN' was not declared in this scope error. TODO: figure out.
    sprintf(itr_client_data.ipc_local, "%s%d", (char *)"/tmp/shadow_hmiproxy_ipc_itrc", My_ID);
    sprintf(itr_client_data.ipc_remote, "%s%d", (char *)"/tmp/shadow_hmiproxy_ipc_main", My_ID);
    // ip = strtok(av[1], ":");
    // sprintf(itr_client_data.spines_ext_addr, "%s", ip);
    sprintf(itr_client_data.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    // ip = strtok(NULL, ":");
    // sscanf(ip, "%d", &itr_client_data.spines_ext_port);
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itr_client_data.spines_ext_port);
}