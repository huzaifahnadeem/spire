
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

#include <sys/wait.h> // for forking io_process process
#include <sys/types.h>

namespace ns_main {
    extern "C" {
        #include "common/net_wrapper.h"  // needs: -I$(SPIRE)/common
        #include "common/def.h"          // needs: -I$(SPIRE)/common
        #include "common/itrc.h"         // needs: -I$(SPIRE)/common
        #include "prime/libspread-util/include/spu_events.h"             // needs: -I$(PRIME)/libspread-util/include
        #include "prime/stdutil/include/stdutil/stdcarr.h"        // needs: -I$(PRIME)/stdutil/include
        #include "spines/libspines/spines_lib.h"             // needs: -I$(SPINES)/libspines/ 
    }
}

#define DATA_COLLECTOR_SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines

#define IPC_FROM_IOPROC_CHILD "/tmp/hmiproxy_ipc_ioproc_to_proxy"
#define IPC_TO_IOPROC_CHILD "/tmp/hmiproxy_ipc_proxy_to_ioproc"

// TODO: Move these somewhere common to proxy.c, proxy.cpp, data_collector
#define RTU_PROXY_MAIN_MSG      10  // message from main, received at the RTU proxy
#define RTU_PROXY_SHADOW_MSG    11  // message from shadow, received at the RTU proxy
#define RTU_PROXY_RTU_DATA      12  // message from RTU/PLC (contains RTU_DATA) received at the RTU proxy
#define HMI_PROXY_MAIN_MSG      20  // message from main, received at the HMI proxy
#define HMI_PROXY_SHADOW_MSG    21  // message from shadow, received at the HMI proxy
#define HMI_PROXY_HMI_CMD       22  // message from HMI (contains HMI_COMMAND), received at the HMI proxy
struct data_collector_packet {
    int data_stream;
    int nbytes_mess;
    int nbytes_struct;
    ns_main::signed_message system_message;
}; // TODO: this struct (identical versions) is in 3 different files (hmiproxy, data_collector, ss-side proxy). move this to some common file maybe scada_packets

bool data_collector_isinsystem = false;
bool shadow_isinsystem = false;

int ipc_sock_to_hmi, ipc_sock_from_hmi;
ns_main::itrc_data mainthread_to_itrcthread_data;
ns_main::itrc_data itr_client_data;
int ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;
std::string shadow_spire_dir = "./"; // if the user doesn't provide the shadow spire directory, then just default to using the same keys as the main ones. (note that the directory structure is exactly the same for the main and shadow since the shadow is supposed to the exact same version of the code just compiled with different config files).
std::string shadow_io_path = "./io_process/io_process";
int ipc_sock_to_child, ipc_sock_from_child;

// for comm. with data collector:
int dc_spines_sock; // spines socket to be used for communicating with the data collector
struct sockaddr_in dc_addr; // data collector's address (contains ip addr and port)

void usage_check(int ac);
void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, std::string &dc_ip_addr, int &dc_port, std::string &shadow_spinesd_ip_addr, int &shadow_spinesd_port);
void setup_ipc_for_hmi();
void itrc_init(std::string spinesd_ip_addr, int spinesd_port);
void setup_datacoll_spines_sock(std::string spinesd_ip_addr, int spinesd_port, std::string dc_ip_addr, int dc_port);
void recv_then_fw_to_hmi_and_dc(int s, int dummy1, void *dummy2);
void *handler_msg_from_itrc(void *arg);
void *listen_on_hmi_sock(void *arg);
void send_to_data_collector(ns_main::signed_message *msg, int nbytes, int stream);
void setup_ipc_with_shadow_io();

int main(int ac, char **av) {
    std::string spinesd_ip_addr; // for spines daemon (main system)
    int spinesd_port;
    std::string dc_ip_addr; // for data collector
    int dc_port;
    std::string shadow_spinesd_ip_addr; // for spines daemon (shadow system)
    int shadow_spinesd_port;

    parse_args(ac, av, spinesd_ip_addr, spinesd_port, dc_ip_addr, dc_port, shadow_spinesd_ip_addr, shadow_spinesd_port);
    
    pthread_t hmi_listen_thread;
    pthread_t itrc_thread;
    pthread_t handle_msg_from_itrc_thread;

    setup_ipc_for_hmi();
    itrc_init(spinesd_ip_addr, spinesd_port);
    
    if (shadow_isinsystem) {
        setup_ipc_with_shadow_io();
    }

    if (data_collector_isinsystem) {
        setup_datacoll_spines_sock(spinesd_ip_addr, spinesd_port, dc_ip_addr, dc_port);
    }

    pthread_create(&handle_msg_from_itrc_thread, NULL, &handler_msg_from_itrc, NULL); // receives messages from itrc client (and from itrc client for shadow too)
    pthread_create(&hmi_listen_thread, NULL, &listen_on_hmi_sock, NULL); // listens for command messages coming from the HMI and forwards it to the ITRC client and the data collector
    pthread_create(&itrc_thread, NULL, &ns_main::ITRC_Client, (void *)&itr_client_data); // ITRC_Client thread will take care of any forwarding/receving the replicas via spines
    
    if (shadow_isinsystem) {
        /* Start shadow_io proc */
        printf("Starting io_process (shadow)\n");
        pid_t pid;
        //child -- run program on path
        // Note 1: by convention, arg 0 is the prog name. Note 2: execv required this array to be NULL terminated.
        char* child_proc_cmd[5] = {const_cast<char*>(shadow_io_path.c_str()), const_cast<char*>(shadow_spinesd_ip_addr.c_str()), const_cast<char*>(std::to_string(shadow_spinesd_port).c_str()), const_cast<char*>(shadow_spire_dir.c_str()), NULL};

        if ((pid = fork()) < 0) { // error case
            std::cout << "Error: fork returned pid < 0\n";
            exit(1);
        }
        else if(pid == 0) { 
            // only child proc will run this. parent moves to the very next line after the end of 'if (shadow_isinsystem)' if statement
            printf("The child proc's pid is: %d\n", getpid());
            if (execv(child_proc_cmd[0], child_proc_cmd) < 0) {
                std::cout << "error starting shadow_io. errorno = "<< errno << "\n";
                exit(1); // exit child
            }
        }
        // no need to separately make a thread to listen for updates from shadow_io. the itrc handler checks for that too
    }

    pthread_join(hmi_listen_thread, NULL);
    pthread_join(itrc_thread, NULL);
    pthread_join(handle_msg_from_itrc_thread, NULL);
    
    // if (shadow_isinsystem) {
    //     pthread_join(shadow_itrc_thread, NULL);
    // }
    
    return 0;
}

void usage_check(int ac) {
    // Usage check
    if (ac == 2) { // running with just the main system
        data_collector_isinsystem = false;
        shadow_isinsystem = false;
    }
    else if (ac == 3) { // running with the main system and the data collector
        data_collector_isinsystem = true;
        shadow_isinsystem = false;
    }
    else if (ac == 4 || ac == 5) { // running with the main system, the data collector, and the shadow system (if running with shadow, the user can optionally provide the directory where the the shadow binaries of spire are. That is useful to find keys if the shadow is running in a different configuration and/or using different keys)
        data_collector_isinsystem = true;
        shadow_isinsystem = true;
    }
    else {
        printf("Invalid args\n");
        // printf("Usage: ./proxy spinesAddr:spinesPort [dataCollectorAddr:dataCollectorPort] [shadowAddr:shadowPort] [shadowSpireDirectory]\n");
        printf("Usage: ./proxy spinesAddr:spinesPort [dataCollectorAddr:dataCollectorPort] [shadowAddr:shadowPort] [shadowSpireDirectory]\n");
        exit(EXIT_FAILURE);
    }
}

void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, std::string &dc_ip_addr, int &dc_port, std::string &shadow_spinesd_ip_addr, int &shadow_spinesd_port) {
    usage_check(ac);

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
        if (ac == 5) {
            shadow_spire_dir = av[4];
        }
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
        dc_spines_sock = ns_main::Spines_SendOnly_Sock(spinesd_ip_addr.c_str(), spinesd_port, proto);
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
}

void setup_ipc_for_hmi()
{   
    ipc_sock_from_hmi = ns_main::IPC_DGram_Sock(HMI_IPC_HMIPROXY); // for HMI to HMIproxy communication
    ipc_sock_to_hmi = ns_main::IPC_DGram_SendOnly_Sock(); // for HMIproxy to HMI communication
}

void recv_then_fw_to_hmi_and_dc(int s, int main_or_shadow, void *dummy2) // called by handler_msg_from_itrc
{   
    int ret; 
    int nbytes;
    char buf[MAX_LEN];
    ns_main::signed_message *mess;

    // UNUSED(dummy1);
    UNUSED(dummy2);

    std::cout << "recv_then_fw_to_hmi_and_dc():\n";

    // Receive from ITRC Client"
    if (main_or_shadow == 0) std::cout << "There is a message from the ITRC Client (main) \n";      // (main_or_shadow == 0) => main
    if (main_or_shadow == 1) std::cout << "There is a message from the ITRC Client (shadow) \n";    // (main_or_shadow == 1) => shadow
    ret = ns_main::IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("recv_msg_from_itrc(): IPC_Rev failed\n");
    
    mess = (ns_main::signed_message *)buf;
    nbytes = sizeof(ns_main::signed_message) + mess->len;
    // Forward to HMI (only forward messages that are coming from the main system (shadow's messages are only fw to data collector, thats it))
    if (main_or_shadow == 0) {
        ns_main::IPC_Send(ipc_sock_to_hmi, (void *)mess, nbytes, HMIPROXY_IPC_HMI);
        std::cout << "The message has been forwarded to the HMI\n";
    }

    if (data_collector_isinsystem) {
        // Forward to the Data Collector:
        send_to_data_collector(mess, nbytes, main_or_shadow == 0? HMI_PROXY_MAIN_MSG: HMI_PROXY_SHADOW_MSG);
    }
}

void *handler_msg_from_itrc(void *arg)
{   
    UNUSED(arg);
    
    std::cout << "initialized handler_msg_from_itrc() \n";

    ns_main::E_init();
    ns_main::E_attach_fd(ipc_sock_main_to_itrcthread, READ_FD, recv_then_fw_to_hmi_and_dc, 0, NULL, MEDIUM_PRIORITY); // recv_then_fw_to_hmi_and_dc called when there is a message to be received from the proxy
    if (shadow_isinsystem){
        ns_main::E_attach_fd(ipc_sock_from_child, READ_FD, recv_then_fw_to_hmi_and_dc, 1, NULL, MEDIUM_PRIORITY); // recv_then_fw_to_hmi_and_dc called when there is a message to be received from the shadow (via shadow_io child proc)
    }
    ns_main::E_handle_events();

    return NULL;
}

void *listen_on_hmi_sock(void *arg){
    UNUSED(arg);

    int ret; 
    char buf[MAX_LEN];
    ns_main::signed_message *mess;
    int nbytes;

    for (;;) {
        std::cout << "Waiting to receive something on the HMI socket\n";
        ret = ns_main::IPC_Recv(ipc_sock_from_hmi, buf, MAX_LEN);
        if (ret < 0) {
            std::cout << "HMI-proxy: IPC_Rev failed. ret = " << ret << "\n";
        }
        else {
            std::cout << "Received a message from the HMI. ret = " << ret << "\n";
            mess = (ns_main::signed_message *)buf;
            nbytes = sizeof(ns_main::signed_message) + mess->len;
            ret = ns_main::IPC_Send(ipc_sock_main_to_itrcthread, (void *)mess, nbytes, mainthread_to_itrcthread_data.ipc_remote);
            if (ret < 0) {
                std::cout << "Failed to sent message to the IRTC thread. ret = " << ret << "\n";
            }
            std::cout << "The message has been forwarded to the IRTC thread. ret = " << ret << "\n";

            if (data_collector_isinsystem) {
                send_to_data_collector(mess, nbytes, HMI_PROXY_HMI_CMD);
            }
            if (shadow_isinsystem) {
                ret = ns_main::IPC_Send(ipc_sock_to_child, (void *)mess, nbytes, IPC_TO_IOPROC_CHILD);
                if (ret < 0) {
                    std::cout << "Failed to sent message to the shadow IRTC thread. ret = " << ret << "\n";
                }
                else {
                    std::cout << "The message has been forwarded to the itrc thread (shadow) \n";
                }
            }
        }
    }
    return NULL;
}

void send_to_data_collector(ns_main::signed_message *msg, int nbytes, int stream) {
    int ret;
    std::cout << "Sending to data collector\n";
    // ret = spines_sendto(dc_spines_sock, (void *)msg, nbytes, 0, (struct sockaddr *)&dc_addr, sizeof(struct sockaddr));
    struct data_collector_packet data_packet;
    data_packet.data_stream = stream;
    data_packet.system_message = *msg;
    data_packet.nbytes_mess = nbytes;
    data_packet.nbytes_struct = sizeof(ns_main::signed_message) + msg->len + 3*sizeof(int);
    ret = ns_main::spines_sendto(dc_spines_sock, (void *)&data_packet, data_packet.nbytes_struct, 0, (struct sockaddr *)&dc_addr, sizeof(struct sockaddr));
    std::cout << "Sent to data collector with return code ret = " << ret << "\n";
}

void _itrc_init(std::string spinesd_ip_addr, int spinesd_port, ns_main::itrc_data &itrc_data_main, ns_main::itrc_data &itrc_data_itrcclient, int &sock_main_to_itrc_thread, std::string hmi_prime_keys_dir, std::string hmi_sm_keys_dir, std::string hmiproxy_ipc_main_procfile, std::string hmiproxy_ipc_itrc_procfile)
{   
    struct timeval now;
    ns_main::My_Global_Configuration_Number = 0;
    ns_main::Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    ns_main::My_Incarnation = now.tv_sec;
    Seq_Num = 1;
    ns_main::Type = HMI_TYPE;
    ns_main::My_ID = PNNL; // TODO: might want to change this to PNNL_W_PROXY or PROXY_FOR_PNNL to differentiate from plain old PNNL if someone wants to run them together
    ns_main::Prime_Client_ID = MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU + ns_main::My_ID;
    ns_main::My_IP = ns_main::getIP();

    // Setup IPC for HMI main thread
    memset(&itrc_data_main, 0, sizeof(ns_main::itrc_data));
    sprintf(itrc_data_main.prime_keys_dir, "%s", hmi_prime_keys_dir.c_str());
    sprintf(itrc_data_main.sm_keys_dir, "%s", hmi_sm_keys_dir.c_str());
    sprintf(itrc_data_main.ipc_local, "%s%d", hmiproxy_ipc_main_procfile.c_str(), ns_main::My_ID);
    sprintf(itrc_data_main.ipc_remote, "%s%d", hmiproxy_ipc_itrc_procfile.c_str(), ns_main::My_ID);
    
    sock_main_to_itrc_thread = ns_main::IPC_DGram_Sock(itrc_data_main.ipc_local);

    // Setup IPC for Worker thread (itrc client)
    memset(&itrc_data_itrcclient, 0, sizeof(ns_main::itrc_data));
    sprintf(itrc_data_itrcclient.prime_keys_dir, "%s", hmi_prime_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.sm_keys_dir, "%s", hmi_sm_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.ipc_local, "%s%d", hmiproxy_ipc_itrc_procfile.c_str(), ns_main::My_ID);
    sprintf(itrc_data_itrcclient.ipc_remote, "%s%d", hmiproxy_ipc_main_procfile.c_str(), ns_main::My_ID);
    sprintf(itrc_data_itrcclient.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itrc_data_itrcclient.spines_ext_port);
}

void itrc_init(std::string spinesd_ip_addr, int spinesd_port) {
    _itrc_init( spinesd_ip_addr, 
                spinesd_port, 
                mainthread_to_itrcthread_data, 
                itr_client_data, 
                ipc_sock_main_to_itrcthread, 
                HMI_PRIME_KEYS, 
                HMI_SM_KEYS, 
                HMIPROXY_IPC_MAIN, 
                HMIPROXY_IPC_ITRC );
}

void setup_ipc_with_shadow_io() {
    // shadow_io is the child:
    ipc_sock_to_child = ns_main::IPC_DGram_SendOnly_Sock(); // for sending something TO the parent
    ipc_sock_from_child = ns_main::IPC_DGram_Sock(IPC_FROM_IOPROC_CHILD); // for receiving something FROM the parent
}