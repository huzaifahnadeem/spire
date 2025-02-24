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

#include <sys/prctl.h> // required for prctl() (used to kill this proc if the parents gets a sighup)
#include <signal.h> // has the declaration for SIGHUP

// TODO: assumed directory "shadow-spire". fix in here and makefile too. use some compiler directives or something
namespace ns_shadow {
    extern "C" {
        #include "shadow-spire/common/net_wrapper.h"  // needs: -I$(SPIRE)/common
        #include "shadow-spire/common/def.h"          // needs: -I$(SPIRE)/common
        #include "shadow-spire/common/itrc.h"         // needs: -I$(SPIRE)/common
        #include "shadow-spire/prime/libspread-util/include/spu_events.h"             // needs: -I$(PRIME)/libspread-util/include
        #include "shadow-spire/prime/stdutil/include/stdutil/stdcarr.h"        // needs: -I$(PRIME)/stdutil/include
        #include "shadow-spire/spines/libspines/spines_lib.h"             // needs: -I$(SPINES)/libspines/ 
    }
}

#define IPC_TO_PARENT "/tmp/ssproxy_ipc_shadowio_to_proxy"
#define IPC_FROM_PARENT "/tmp/ssproxy_ipc_proxy_to_shadowio"

void parse_args(int ac, char **av, std::string &shadow_spinesd_ip_addr, int &shadow_spinesd_port, std::string &shadow_spire_dir);
void itrc_init_shadow(std::string shadow_spinesd_ip_addr, int shadow_spinesd_port, std::string shadow_spire_dir);
void setup_ipc_with_parent();
void *handler_msg_from_itrc(void *arg);
void *listen_on_parent_sock(void *arg);

int shadow_ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;
int ipc_sock_to_parent, ipc_sock_from_parent;
ns_shadow::itrc_data shadow_mainthread_to_itrcthread_data, shadow_itr_client_data;
int my_id_for_itrc;

int main(int ac, char **av) {
    std::cout << "shadow_io starts \n";
    // this kills this process if the parent gets a SIGHUP:
    prctl(PR_SET_PDEATHSIG, SIGHUP); // TODO: this might not be the best way to do this. check the second answer in the following (answer by Schof): https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/17589555
    
    std::string shadow_spinesd_ip_addr;
    int shadow_spinesd_port;
    std::string shadow_spire_dir = "./"; // if the user doesn't provide the shadow spire directory, then just default to using the same keys as the main ones. (note that the directory structure is exactly the same for the main and shadow since the shadow is supposed to the exact same version of the code just compiled with different config files).

    parse_args(ac, av, shadow_spinesd_ip_addr, shadow_spinesd_port, shadow_spire_dir);
    setup_ipc_with_parent();
    
    pthread_t parent_listen_thread, itrc_thread, handle_msg_from_itrc_thread;
    
    itrc_init_shadow(shadow_spinesd_ip_addr, shadow_spinesd_port, shadow_spire_dir);

    pthread_create(&handle_msg_from_itrc_thread, NULL, &handler_msg_from_itrc, NULL); // receives messages from itrc client (shadow)
    pthread_create(&parent_listen_thread, NULL, &listen_on_parent_sock, NULL); // listens for command messages coming from the parent proc
    pthread_create(&itrc_thread, NULL, &ns_shadow::ITRC_Client, (void *)&shadow_itr_client_data); // ITRC_Client thread will take care of any forwarding/receving the replicas via spines
    
    pthread_join(handle_msg_from_itrc_thread, NULL);
    pthread_join(parent_listen_thread, NULL);
    pthread_join(itrc_thread, NULL);

    return 0;
}

void parse_args(int ac, char **av, std::string &shadow_spinesd_ip_addr, int &shadow_spinesd_port, std::string &shadow_spire_dir) {
    if (ac != 5) {
        printf("Invalid args\n");
        printf("Usage: ./shadow_io spinesIPAddr spinesPort shadowSpireDirectoryBase My_ID_for_ITRC\n");
        exit(EXIT_FAILURE);
    }
    // by convention av[0] is just the prog name
    shadow_spinesd_ip_addr = av[1];
    shadow_spinesd_port = atoi(av[2]);
    shadow_spire_dir = av[3];
    my_id_for_itrc = atoi(av[4]);
}

void _itrc_init(std::string spinesd_ip_addr, int spinesd_port, ns_shadow::itrc_data &itrc_data_main, ns_shadow::itrc_data &itrc_data_itrcclient, int &sock_main_to_itrc_thread, std::string proxy_prime_keys_dir, std::string proxy_sm_keys_dir, std::string ssproxy_ipc_main_procfile, std::string ssproxy_ipc_itrc_procfile)
{   
    struct timeval now;
    ns_shadow::My_Global_Configuration_Number = 0;
    ns_shadow::Init_SM_Replicas();

    // // NET Setup
    gettimeofday(&now, NULL);
    ns_shadow::My_Incarnation = now.tv_sec;
    // Seq_Num = 1;
    
    ns_shadow::Type = RTU_TYPE;
    ns_shadow::Prime_Client_ID = MAX_NUM_SERVER_SLOTS + ns_shadow::My_ID;
    ns_shadow::My_IP = ns_shadow::getIP();
    ns_shadow::My_ID = my_id_for_itrc;

    // Setup IPC for the RTU Proxy main thread
    printf("PROXY: Setting up IPC for RTU proxy thread (For Shadow)\n");
    memset(&itrc_data_main, 0, sizeof(ns_shadow::itrc_data));
    sprintf(itrc_data_main.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_main.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_main.ipc_local, "%s%d", ssproxy_ipc_main_procfile.c_str(), ns_shadow::My_ID);
    sprintf(itrc_data_main.ipc_remote, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), ns_shadow::My_ID);
    sock_main_to_itrc_thread = ns_shadow::IPC_DGram_Sock(itrc_data_main.ipc_local);

    // Setup IPC for the Worker Thread (running the ITRC Client)
    memset(&itrc_data_itrcclient, 0, sizeof(ns_shadow::itrc_data));
    sprintf(itrc_data_itrcclient.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.ipc_local, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), ns_shadow::My_ID);
    sprintf(itrc_data_itrcclient.ipc_remote, "%s%d", ssproxy_ipc_main_procfile.c_str(), ns_shadow::My_ID);
    sprintf(itrc_data_itrcclient.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itrc_data_itrcclient.spines_ext_port);   
}

void itrc_init_shadow(std::string shadow_spinesd_ip_addr, int shadow_spinesd_port, std::string shadow_spire_dir) {
    _itrc_init( shadow_spinesd_ip_addr, 
                shadow_spinesd_port, 
                shadow_mainthread_to_itrcthread_data, 
                shadow_itr_client_data, 
                shadow_ipc_sock_main_to_itrcthread, 
                shadow_spire_dir == "./" ? shadow_spire_dir + PROXY_PRIME_KEYS : shadow_spire_dir + "/hmis/proxy/" + PROXY_PRIME_KEYS, // there is nothing complicated going on here. just checking whether or not the user provided a directory and adjusting accordingly
                shadow_spire_dir == "./" ? shadow_spire_dir + PROXY_SM_KEYS : shadow_spire_dir + "/hmis/proxy/" + PROXY_SM_KEYS, 
                RTU_IPC_MAIN_IOPROC, 
                RTU_IPC_ITRC_IOPROC );
    // TODO: ? ns_shadow::PROXY_PRIME_KEYS ?
}

void setup_ipc_with_parent() {
    ipc_sock_to_parent = ns_shadow::IPC_DGram_SendOnly_Sock(); // for sending something TO the parent
    ipc_sock_from_parent = ns_shadow::IPC_DGram_Sock(IPC_FROM_PARENT); // for receiving something FROM the parent
}

void recv_then_fw_to_parent(int s, void *dummy1, void *dummy2) // called by handler_msg_from_itrc
{   
    int ret; 
    int nbytes;
    char buf[MAX_LEN];
    ns_shadow::signed_message *mess;

    UNUSED(dummy1);
    UNUSED(dummy2);

    std::cout << "shadow_io: recv_then_fw_to_parent():\n";

    // Receive from ITRC Client:
    std::cout << "shadow_io: There is a message from the ITRC Client (shadow) \n";
    ret = ns_shadow::IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("shadow_io: recv_msg_from_itrc(): IPC_Rev failed\n");
    mess = (ns_shadow::signed_message *)buf;
    nbytes = sizeof(ns_shadow::signed_message) + mess->len;
    // Forward to parent:
    ns_shadow::IPC_Send(ipc_sock_to_parent, (void *)mess, nbytes, IPC_TO_PARENT);
    std::cout << "shadow_io: The message has been forwarded to the parent proc.\n";
}

void *handler_msg_from_itrc(void *arg)
{   
    UNUSED(arg);
    
    std::cout << "shadow_io: initialized handler_msg_from_itrc() \n";

    fd_set active_fd_set, read_fd_set;
    int num;
    // Init data structures for select()
    FD_ZERO(&active_fd_set);
    FD_SET(shadow_ipc_sock_main_to_itrcthread, &active_fd_set);
    
    while(1) {
        read_fd_set = active_fd_set;
        num = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
        if (num > 0) {
            if(FD_ISSET(shadow_ipc_sock_main_to_itrcthread, &read_fd_set)) { // if there is a message from itrc client (main)
                recv_then_fw_to_parent(shadow_ipc_sock_main_to_itrcthread, 0, NULL);
            }
        }
    }

    return NULL;
}

void *listen_on_parent_sock(void *arg) {
    UNUSED(arg);

    int ret; 
    char buf[MAX_LEN];
    ns_shadow::signed_message *mess;
    int nbytes;

    for (;;) {
        std::cout << "shadow_io: Waiting to receive something on the parent socket\n";
        ret = ns_shadow::IPC_Recv(ipc_sock_from_parent, buf, MAX_LEN);
        if (ret < 0) {
            std::cout << "shadow_io: IPC_Rev failed. ret = " << ret << "\n";
        }
        else {
            std::cout << "shadow_io: Received a message from the parent. ret = " << ret << "\n";
            mess = (ns_shadow::signed_message *)buf;
            nbytes = sizeof(ns_shadow::signed_message) + mess->len;
            ret = ns_shadow::IPC_Send(shadow_ipc_sock_main_to_itrcthread, (void *)mess, nbytes, shadow_mainthread_to_itrcthread_data.ipc_remote);
            if (ret < 0) {
                std::cout << "shadow_io: Failed to sent message to the IRTC thread. ret = " << ret << "\n";
            }
            std::cout << "shadow_io: The message has been forwarded to the IRTC thread. ret = " << ret << "\n";

        }
    }
    return NULL;
}