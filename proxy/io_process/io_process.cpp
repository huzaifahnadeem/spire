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

// NOTE: in the Makefile, we have $SPIRE_DIR. Set that to the right spire directory if you do not want to use the default path
namespace system_ns {
    extern "C" {
        #include "common/net_wrapper.h"  
        #include "common/def.h"          
        #include "common/itrc.h"         
        #include "prime/libspread-util/include/spu_events.h"
        #include "prime/stdutil/include/stdutil/stdcarr.h"
        #include "spines/libspines/spines_lib.h"
    }
}

#define IPC_TO_PARENT_RTUPLCCLIENT "/tmp/ssproxy_ipc_ioproc_to_proxy"
#define IPC_FROM_PARENT_RTUPLCCLIENT "/tmp/ssproxy_ipc_proxy_to_ioproc"
#define IPC_TO_PARENT_HMICLIENT "/tmp/hmiproxy_ipc_ioproc_to_proxy"
#define IPC_FROM_PARENT_HMICLIENT "/tmp/hmiproxy_ipc_proxy_to_ioproc"

void parse_args(int ac, char **av, std::string &ioproc_spinesd_ip_addr, int &ioproc_spinesd_port);
void itrc_init_ioproc(std::string ioproc_spinesd_ip_addr, int ioproc_spinesd_port);
void setup_ipc_with_parent();
void *handler_msg_from_itrc(void *arg);
void *listen_on_parent_sock(void *arg);

int ioproc_ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;
int ipc_sock_to_parent, ipc_sock_from_parent;
system_ns::itrc_data ioproc_mainthread_to_itrcthread_data, ioproc_itr_client_data;
std::string ipc_path_suffix;
int proxy_id_for_itrc = 1; // only used for RTU/PLC clients
bool client_is_hmi;

int main(int ac, char **av) {
    // this kills this process if the parent gets a SIGHUP:
    prctl(PR_SET_PDEATHSIG, SIGHUP); // TODO: this might not be the best way to do this. check the second answer in the following (answer by Schof): https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/17589555
    
    std::string ioproc_spinesd_ip_addr;
    int ioproc_spinesd_port;

    parse_args(ac, av, ioproc_spinesd_ip_addr, ioproc_spinesd_port);

    std::cout << "io_process (" << ipc_path_suffix << ") starts (with suffix: " + ipc_path_suffix + ")\n";

    setup_ipc_with_parent();
    
    pthread_t parent_listen_thread, itrc_thread, handle_msg_from_itrc_thread;
    
    itrc_init_ioproc(ioproc_spinesd_ip_addr, ioproc_spinesd_port);

    pthread_create(&handle_msg_from_itrc_thread, NULL, &handler_msg_from_itrc, NULL); // receives messages from itrc client (ioproc)
    pthread_create(&parent_listen_thread, NULL, &listen_on_parent_sock, NULL); // listens for command messages coming from the parent proc
    pthread_create(&itrc_thread, NULL, &system_ns::ITRC_Client, (void *)&ioproc_itr_client_data); // ITRC_Client thread will take care of any forwarding/receving the replicas via spines
    
    pthread_join(handle_msg_from_itrc_thread, NULL);
    pthread_join(parent_listen_thread, NULL);
    pthread_join(itrc_thread, NULL);

    return 0;
}

void parse_args(int ac, char **av, std::string &ioproc_spinesd_ip_addr, int &ioproc_spinesd_port) {
    if (ac != 6) {
        printf("Invalid args\n");
        printf("Usage (run as a child process): ./path/to/io_process spinesIPAddr spinesPort ipc_path_suffix proxy_id_for_itrc client_is_hmi\n");
        exit(EXIT_FAILURE);
    }
    // by convention av[0] is just the prog name
    ioproc_spinesd_ip_addr = av[1];
    ioproc_spinesd_port = atoi(av[2]);
    ipc_path_suffix = av[3];
    proxy_id_for_itrc = atoi(av[4]);

    std::string client_type_arg = av[5];
    if (client_type_arg == "1")
        client_is_hmi = true;
    else
        client_is_hmi = false;
}

void _itrc_init_plcrtu(std::string spinesd_ip_addr, int spinesd_port, system_ns::itrc_data &itrc_data_main, system_ns::itrc_data &itrc_data_itrcclient, int &sock_main_to_itrc_thread, std::string proxy_prime_keys_dir, std::string proxy_sm_keys_dir, std::string ssproxy_ipc_main_procfile, std::string ssproxy_ipc_itrc_procfile)
{   
    struct timeval now;
    system_ns::My_Global_Configuration_Number = 0;
    system_ns::Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    system_ns::My_Incarnation = now.tv_sec;
    // Seq_Num = 1;
    
    system_ns::Type = RTU_TYPE;
    system_ns::Prime_Client_ID = MAX_NUM_SERVER_SLOTS + system_ns::My_ID;
    system_ns::My_IP = system_ns::getIP();
    system_ns::My_ID = proxy_id_for_itrc;

    // Setup IPC for the RTU Proxy main thread
    printf("PROXY: Setting up IPC for RTU proxy thread (in io_proc)\n");
    memset(&itrc_data_main, 0, sizeof(system_ns::itrc_data));
    sprintf(itrc_data_main.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_main.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_main.ipc_local, "%s%d", ssproxy_ipc_main_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_main.ipc_remote, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), system_ns::My_ID);
    sock_main_to_itrc_thread = system_ns::IPC_DGram_Sock(itrc_data_main.ipc_local);

    // Setup IPC for the Worker Thread (running the ITRC Client)
    memset(&itrc_data_itrcclient, 0, sizeof(system_ns::itrc_data));
    sprintf(itrc_data_itrcclient.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.ipc_local, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_itrcclient.ipc_remote, "%s%d", ssproxy_ipc_main_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_itrcclient.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itrc_data_itrcclient.spines_ext_port);   
}

void _itrc_init_hmi(std::string spinesd_ip_addr, int spinesd_port, system_ns::itrc_data &itrc_data_main, system_ns::itrc_data &itrc_data_itrcclient, int &sock_main_to_itrc_thread, std::string hmi_prime_keys_dir, std::string hmi_sm_keys_dir, std::string hmiproxy_ipc_main_procfile, std::string hmiproxy_ipc_itrc_procfile)
{   
    struct timeval now;
    system_ns::My_Global_Configuration_Number = 0;
    system_ns::Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    system_ns::My_Incarnation = now.tv_sec;
    Seq_Num = 1;
    system_ns::Type = HMI_TYPE;
    system_ns::My_ID = PNNL; // TODO: might want to change this to PNNL_W_PROXY or PROXY_FOR_PNNL to differentiate from plain old PNNL if someone wants to run them together
    system_ns::Prime_Client_ID = MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU + system_ns::My_ID;
    system_ns::My_IP = system_ns::getIP();

    // Setup IPC for HMI main thread
    memset(&itrc_data_main, 0, sizeof(system_ns::itrc_data));
    sprintf(itrc_data_main.prime_keys_dir, "%s", hmi_prime_keys_dir.c_str());
    sprintf(itrc_data_main.sm_keys_dir, "%s", hmi_sm_keys_dir.c_str());
    sprintf(itrc_data_main.ipc_local, "%s%d", hmiproxy_ipc_main_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_main.ipc_remote, "%s%d", hmiproxy_ipc_itrc_procfile.c_str(), system_ns::My_ID);
    
    sock_main_to_itrc_thread = system_ns::IPC_DGram_Sock(itrc_data_main.ipc_local);

    // Setup IPC for Worker thread (itrc client)
    memset(&itrc_data_itrcclient, 0, sizeof(system_ns::itrc_data));
    sprintf(itrc_data_itrcclient.prime_keys_dir, "%s", hmi_prime_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.sm_keys_dir, "%s", hmi_sm_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.ipc_local, "%s%d", hmiproxy_ipc_itrc_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_itrcclient.ipc_remote, "%s%d", hmiproxy_ipc_main_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_itrcclient.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itrc_data_itrcclient.spines_ext_port);
}

void itrc_init_ioproc(std::string ioproc_spinesd_ip_addr, int ioproc_spinesd_port) {
    if (client_is_hmi) {
        std::string prime_keys = ""; 
        prime_keys = prime_keys + HMI_PRIME_KEYS;
        std::string sm_keys = "";
        sm_keys = sm_keys + HMI_SM_KEYS;
        _itrc_init_hmi( ioproc_spinesd_ip_addr, 
                    ioproc_spinesd_port, 
                    ioproc_mainthread_to_itrcthread_data, 
                    ioproc_itr_client_data, 
                    ioproc_ipc_sock_main_to_itrcthread, 
                    prime_keys,
                    sm_keys, 
                    HMIPROXY_IPC_MAIN_IOPROC, 
                    HMIPROXY_IPC_ITRC_IOPROC
        );
    }
    else { // client is PLC/RTU
        std::string prime_keys = ""; 
        prime_keys = prime_keys + PROXY_PRIME_KEYS;
        std::string sm_keys = "";
        sm_keys = sm_keys + PROXY_SM_KEYS;
        _itrc_init_plcrtu( ioproc_spinesd_ip_addr, 
            ioproc_spinesd_port, 
            ioproc_mainthread_to_itrcthread_data, 
            ioproc_itr_client_data, 
            ioproc_ipc_sock_main_to_itrcthread, 
            prime_keys,
            sm_keys,
            RTU_IPC_MAIN_IOPROC, 
            RTU_IPC_ITRC_IOPROC 
        );
    }
}

void setup_ipc_with_parent() {
    ipc_sock_to_parent = system_ns::IPC_DGram_SendOnly_Sock(); // for sending something TO the parent
    
    std::string ipc_from_parent;
    if (client_is_hmi)
        ipc_from_parent = IPC_FROM_PARENT_HMICLIENT;
    else
        ipc_from_parent = IPC_FROM_PARENT_RTUPLCCLIENT;
    ipc_sock_from_parent = system_ns::IPC_DGram_Sock((ipc_from_parent + ipc_path_suffix).c_str()); // for receiving something FROM the parent
}

void recv_then_fw_to_parent(int s, void *dummy1, void *dummy2) // called by handler_msg_from_itrc
{   
    int ret; 
    int nbytes;
    char buf[MAX_LEN];
    system_ns::signed_message *mess;

    UNUSED(dummy1);
    UNUSED(dummy2);

    std::cout << "io_process (" << ipc_path_suffix << "): recv_then_fw_to_parent():\n";

    // Receive from ITRC Client:
    std::cout << "io_process (" << ipc_path_suffix << "): There is a message from the ITRC Client (ioproc) \n";
    ret = system_ns::IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("io_process: recv_msg_from_itrc(): IPC_Rev failed\n");
    mess = (system_ns::signed_message *)buf;
    nbytes = sizeof(system_ns::signed_message) + mess->len;
    // Forward to parent:
    std::string ipc_to_parent;
    if (client_is_hmi)
        ipc_to_parent = IPC_TO_PARENT_HMICLIENT;
    else
        ipc_to_parent = IPC_TO_PARENT_RTUPLCCLIENT;
    system_ns::IPC_Send(ipc_sock_to_parent, (void *)mess, nbytes, (ipc_to_parent + ipc_path_suffix).c_str());
    std::cout << "io_process (" << ipc_path_suffix << "): The message has been forwarded to the parent proc.\n";
}

void *handler_msg_from_itrc(void *arg)
{   
    UNUSED(arg);
    
    std::cout << "io_process (" << ipc_path_suffix << "): initialized handler_msg_from_itrc() \n";

    fd_set active_fd_set, read_fd_set;
    int num;
    // Init data structures for select()
    FD_ZERO(&active_fd_set);
    FD_SET(ioproc_ipc_sock_main_to_itrcthread, &active_fd_set);
    
    while(1) {
        read_fd_set = active_fd_set;
        num = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
        if (num > 0) {
            if(FD_ISSET(ioproc_ipc_sock_main_to_itrcthread, &read_fd_set)) { // if there is a message from itrc client (main)
                recv_then_fw_to_parent(ioproc_ipc_sock_main_to_itrcthread, 0, NULL);
            }
        }
    }

    return NULL;
}

void *listen_on_parent_sock(void *arg) {
    UNUSED(arg);

    int ret; 
    char buf[MAX_LEN];
    system_ns::signed_message *mess;
    int nbytes;

    for (;;) {
        std::cout << "io_process (" << ipc_path_suffix << "): Waiting to receive something on the parent socket\n";
        ret = system_ns::IPC_Recv(ipc_sock_from_parent, buf, MAX_LEN);
        if (ret < 0) {
            std::cout << "io_process (" << ipc_path_suffix << "): IPC_Rev failed. ret = " << ret << "\n";
        }
        else {
            std::cout << "io_process (" << ipc_path_suffix << "): Received a message from the parent. ret = " << ret << "\n";
            mess = (system_ns::signed_message *)buf;
            nbytes = sizeof(system_ns::signed_message) + mess->len;
            ret = system_ns::IPC_Send(ioproc_ipc_sock_main_to_itrcthread, (void *)mess, nbytes, ioproc_mainthread_to_itrcthread_data.ipc_remote);
            if (ret < 0) {
                std::cout << "io_process (" << ipc_path_suffix << "): Failed to sent message to the IRTC thread. ret = " << ret << "\n";
            }
            std::cout << "io_process (" << ipc_path_suffix << "): The message has been forwarded to the IRTC thread. ret = " << ret << "\n";

        }
    }
    return NULL;
}