#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h> // for sleep()
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <sys/wait.h> // for forking io_process process
#include <sys/types.h>
#include <sys/time.h>
#include <vector> 
#include <fstream>
#include <sstream>
#include <unordered_map>

extern "C" {
    #include "common/net_wrapper.h" 
    #include "common/def.h"
    #include "common/openssl_rsa.h"
    #include "common/tc_wrapper.h"
    #include "common/itrc.h"
    #include "common/scada_packets.h"
    #include "common/key_value.h"
    #include "config/cJSON.h"
    #include "config/config_helpers.h"
    #include "spines/libspines/spines_lib.h" // for spines functions e.g. spines_sendto()
    #include "prime/libspread-util/include/spu_events.h" // import libspread. for its event handler functions
}

// macro defines:
#define DEFAULT_IO_PROCESS_PATH "./io_process/io_process"
#define IPC_FROM_IOPROC_CHILD "/tmp/ssproxy_ipc_ioproc_to_proxy"
#define IPC_TO_IOPROC_CHILD "/tmp/ssproxy_ipc_proxy_to_ioproc"

// TODO: Move these somewhere common to proxy.c, proxy.cpp, data_collector
#define RTU_PROXY_MAIN_MSG      10  // message from main, received at the RTU proxy
#define RTU_PROXY_SHADOW_MSG    11  // message from shadow, received at the RTU proxy
#define RTU_PROXY_RTU_DATA      12  // message from RTU/PLC (contains RTU_DATA) received at the RTU proxy
#define HMI_PROXY_MAIN_MSG      20  // message from main, received at the HMI proxy
#define HMI_PROXY_SHADOW_MSG    21  // message from shadow, received at the HMI proxy
#define HMI_PROXY_HMI_CMD       22  // message from HMI (contains HMI_COMMAND), received at the HMI proxy

struct DataCollectorPacket {
    int data_stream;
    int nbytes_mess;
    int nbytes_struct;
    signed_message system_message;
}; // TODO: this struct (identical versions) is in 3 different files (hmiproxy, data_collector, ss-side proxy). move this to some common file maybe scada_packets

struct Switcher_Message {
    std::string new_active_system_id;
}; // TODO: put this somewhere common to the proxies and the switcher

struct SocketAddress {
    std::string ip_addr = "";
    int port = -1;
};

// Declaring these classes here first because they have properties refering to each other.
class RTUsPLCsMessageBrokerManager;
class IOProcManager;

class InputArgs {
    private:
        struct SystemsData {
            std::string binary_path;
            SocketAddress spinesd_sock_addr;
            std::string id;
        };
        struct PipeData {
            std::string active_sys_id = "";
            SocketAddress data_collector_sock_addr;
            SocketAddress switcher_sock_addr;
            std::vector<SystemsData> systems_data;
        };

        void print_usage();
        void parse_args(int ac, char **av);
        void read_named_pipe(std::string pipe_name);
    
    public:
        InputArgs(int ac, char **av);
        SocketAddress spinesd_sock_addr;
        std::string proxy_id;
        int num_of_plc_rtus;
        std::string pipe_name;
        PipeData pipe_data;
};

class DataCollectorManager {
    private:
        bool no_data_collector = true;
        SocketAddress dc_sockaddr;
        sockaddr_in dc_sockaddr_in;
        SocketAddress spinesd_sock_addr;
        int spines_protocol = -1; // the spines protocol to use. options: SPINES_RELIABLE, SPINES_PRIORITY. set in the constructor
        int SPINES_RECONNECT_SEC = 2; // for timeout if unable to connect to spines
        int spinesd_socket = -1;
        void setup_spines_socket(); 

    public:
        DataCollectorManager(SocketAddress data_collector_sockaddr, SocketAddress spined_sockaddr);
        void send_to_dc(signed_message *msg, int nbytes, int stream_id);
};

class IOProcManager {
    private:
        struct IPCSocket {
            int to = -1; // socket that is used when sending something to the IO Process
            int from = -1; // socket that is used when receiving something from the IO Process
        };
        struct IOProcess {
            std::string io_binary_path = "";
            SocketAddress spines_addr;
            pid_t pid;
            IPCSocket sockets;
        };

        std::unordered_map<std::string, IOProcess> io_procs;
        std::string active_sys_id = "";
        std::string proxy_id = ""; // used by the IO processes to tell the system about the proxy's role (client etc)
        DataCollectorManager * data_collector_manager;
        RTUsPLCsMessageBrokerManager * rtuplc_manager;

        void fork_io_proc(IOProcess &io_proc, std::string id);
        static void io_proc_message_handler(int sock, int code, void *data);
        
        public:
        IOProcManager(InputArgs args, DataCollectorManager * data_collector_manager, RTUsPLCsMessageBrokerManager * rtuplc_man);
        void add_io_proc(std::string id, std::string bin_path, SocketAddress spines_addr);
        void start_io_proc(std::string id);
        void start_all_io_procs();
        void kill_io_proc(std::string id);
        void send_msg_to_all_procs(signed_message *msg, int nbytes);
        void update_active_system_id(std::string new_sys_id);
};

class RTUsPLCsMessageBrokerManager {
    private:
        std::string proxy_id;
        std::vector<pid_t*> mb_procs_pids; // message broker processes' pids
        bool ipc_index_used_for_message_broker[NUM_PROTOCOLS];
        int num_of_plc_rtus;
        SocketAddress spinesd_addr; // the daemon that is not specific to any system. used by data collector, here, etc
        IOProcManager * io_proc_manager;
        DataCollectorManager * dc_manager;

        void init_message_broker_processes_and_sockets();
        static void * listen_on_rtus_plcs_sock(void *arg);
        
    public:
        itrc_data protocol_data[NUM_PROTOCOLS];
        int sockets_to_from_rtus_plcs_via_ipc[NUM_PROTOCOLS];

        RTUsPLCsMessageBrokerManager(InputArgs args);
        void init_listen_thread(pthread_t &thread);
        void set_io_proc_man_ref(IOProcManager * io_proc_man);
        void set_data_collector_man_ref(DataCollectorManager * dc_man);
};

class SwitcherManager {
    private:
        const int switch_message_max_size = MAX_SPINES_CLIENT_MSG;

        SocketAddress mcast_addr;
        SocketAddress spinesd_addr;
        int switcher_socket = -1;
        struct ip_mreq mcast_membership;
        IOProcManager * io_proc_manager;
        
        void setup_switcher_connection();
        static void handle_switcher_message(int sock, int code, void* data);
    
    public:
        SwitcherManager(InputArgs args, IOProcManager * io_proc_man);
        
};

void parse_socket_address(char* socket_address, std::string &ipaddr, int &port);
void parse_socket_address(std::string socket_address, std::string &ipaddr, int &port);
void parse_socket_address(char* socket_address, SocketAddress &sock_addr);
void parse_socket_address(std::string socket_address, SocketAddress &sock_addr);
SocketAddress parse_socket_address(std::string socket_address);
SocketAddress parse_socket_address(char* socket_address);

void process_config_msg(signed_message * conf_mess,int mess_size);
int string_to_protocol(char * prot);