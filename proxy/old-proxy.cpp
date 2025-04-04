//Include headers for socket management
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

// defines:
#define DEFAULT_IO_PROCESS_PATH "./io_process/io_process"
#define IPC_FROM_IOPROC_CHILD "/tmp/ssproxy_ipc_ioproc_to_proxy"
#define IPC_TO_IOPROC_CHILD "/tmp/ssproxy_ipc_proxy_to_ioproc"
#define DATA_COLLECTOR_SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines
// TODO: Move these somewhere common to proxy.c, proxy.cpp, data_collector
#define RTU_PROXY_MAIN_MSG      10  // message from main, received at the RTU proxy
#define RTU_PROXY_SHADOW_MSG    11  // message from shadow, received at the RTU proxy
#define RTU_PROXY_RTU_DATA      12  // message from RTU/PLC (contains RTU_DATA) received at the RTU proxy
#define HMI_PROXY_MAIN_MSG      20  // message from main, received at the HMI proxy
#define HMI_PROXY_SHADOW_MSG    21  // message from shadow, received at the HMI proxy
#define HMI_PROXY_HMI_CMD       22  // message from HMI (contains HMI_COMMAND), received at the HMI proxy

// structs:
struct io_process_data_struct {
    std::string io_binary_path;
    std::string spines_ip;
    int spines_port;
    std::string ipc_path_suffix;
    bool is_alive; // this is set to true when the io_proc is first started. set to false when the process is killed
};
struct data_collector_addr_struct {
    std::string dc_ip;
    int dc_port;
    std::string spines_ip;
    int spines_port;
    sockaddr_in dc_sockaddr_in;
};
struct sockets_struct {
    std::vector<int> from_ioproc_via_ipc; // for messages coming from the I/O processes
    std::vector<int> to_ioproc_via_ipc; // for sending messages to the I/O processes
    int to_data_collector_via_spines;
    int to_from_rtus_plcs_via_ipc[NUM_PROTOCOLS];
    int switcher_socket;
};

struct switcher_addr_struct {
    std::string mcast_ipaddr;
    int mcast_port;
    std::string spines_ip;
    int spines_port;
    struct ip_mreq mreq;
};

struct Switch_Message {
    int new_system_index;
}; // TODO: put this somewhere common to the proxies and the switcher

struct data_collector_packet {
    int data_stream;
    int nbytes_mess;
    int nbytes_struct;
    signed_message system_message;
}; // TODO: this struct (identical versions) is in 3 different files (hmiproxy, data_collector, ss-side proxy). move this to some common file maybe scada_packets

// // global variables:
bool data_collector_isinsystem = false;
int num_of_systems = 0;
int active_system_index = -1;
sockets_struct sockets;
std::vector<io_process_data_struct> io_processes_data;
data_collector_addr_struct data_collector_addr = {.dc_ip="", .dc_port=-1, .spines_ip="", .spines_port=-1, .dc_sockaddr_in={}}; // initialize
// vars relevant to PLCs/RTUs
int num_of_plc_rtus = -1;
itrc_data protocol_data[NUM_PROTOCOLS];
bool ipc_index_used_for_message_broker[NUM_PROTOCOLS];
std::string proxy_id;
bool switcher_isinsystem = false;
switcher_addr_struct switcher_addr;
const int switch_message_max_size = MAX_SPINES_CLIENT_MSG; // TODO: put this somewhere common to the proxies and the switcher? MAX_SPINES_CLIENT_MSG = 50000 bytes
std::vector<pid_t> io_procs_pids; // keeps track of each IO Process' pid. it is used when a process needs to be killed

// // function declarations:
void parse_args(int ac, char **av, std::vector<io_process_data_struct> &io_process_data, data_collector_addr_struct &data_collector_addr);
void read_named_pipe(std::string pipe_name);
void init_rtus_plcs_listen_thread(pthread_t &thread);
void setup_data_collector_spines_sock();
void send_to_data_collector(signed_message *msg, int nbytes, int stream);
void setup_ipc_sockets_for_io_proc(int system_index);
void init_io_procs();
void init_io_proc_message_handlers(pthread_t &message_events_thread);
void init_message_broker_processes_and_sockets();
int string_to_protocol(char * prot);
void Process_Config_Msg(signed_message * conf_mess,int mess_size);
void setup_switcher_connection();
pid_t new_io_proc(io_process_data_struct &io_proc_data);

// function definitions:
int main(int ac, char **av) {
    // read input args and store the data in the data structures:
    parse_args(ac, av, io_processes_data, data_collector_addr);
    
    // set up for communication with the Data Collector
    if (data_collector_isinsystem) {
        setup_data_collector_spines_sock();
    }


    // initializes and fork the message broker processes. also set up for communication with the:
    init_message_broker_processes_and_sockets();

    // set up the IPC connection using which we will talk to the child process:
    // note that this is being done here and not inside init_io_procs() because init_rtus_plcs_listen_thread() reads the sockets set up by this function
    for (int i=0; i < num_of_systems; i++) {
        setup_ipc_sockets_for_io_proc(i);
    }

    // initialize and set up the thread that listens for messages from the PLCs/RTUs:
    pthread_t rtus_plcs_listen_thread;
    init_rtus_plcs_listen_thread(rtus_plcs_listen_thread);

    // initialize and fork the I/O processes:
    init_io_procs();

    // initialize and set up the threads for the message handler for the messages from the I/O processes:
    pthread_t io_procs_message_events_thread;
    init_io_proc_message_handlers(io_procs_message_events_thread);

    // set up socket and a libspread events handler to listen for any switcher messages:
    setup_switcher_connection();

    // wait for the threads before exiting
    pthread_join(rtus_plcs_listen_thread, NULL);
    pthread_join(io_procs_message_events_thread, NULL);

    // TODO: set up dc connection and send messages there too

    return 0;
}

void parse_ipaddr_colon_port(std::string ipaddr_colon_port, std::string &ipaddr, int &port) {
    int colon_pos = -1;
    colon_pos = ipaddr_colon_port.find(':');
    ipaddr = ipaddr_colon_port.substr(0, colon_pos);
    port = std::stoi(ipaddr_colon_port.substr(colon_pos + 1));
}

void parse_ipaddr_colon_port(char* ipaddr_colon_port, std::string &ipaddr, int &port) {
    std::string std_string_ipaddr_colon_port = ipaddr_colon_port;
    parse_ipaddr_colon_port(std_string_ipaddr_colon_port, ipaddr, port);
}

void parse_args(int ac, char **av, std::vector<io_process_data_struct> &io_process_data, data_collector_addr_struct &data_collector_addr) {
    bool one_default_sys = false;
    bool case_named_pipe = false;

    if (ac == 4) { // running with just the one active system
        one_default_sys = true;
        data_collector_isinsystem = false;
        case_named_pipe = false;
    }
    else if (ac == 5) {  
        // running with the main system, the data collector, and shadow system(s).
        // check the else statement for details on how it is expected to work
        
        case_named_pipe =  true;
        data_collector_isinsystem = false;  // to be determined by reading the named pipe/file. will change to true if have a data collector otherwise keeping it at false
        one_default_sys = false;
    }
    else { // TODO: what if different active sys index is given at start (as compared to the other proxy)?
        std::cout 
        << "Invalid args\n" 
        << "Usage: ./proxy proxyID spinesAddr:spinesPort Num_PLC_RTU [named pipe name or file name to use multiple systems]\n" 
        << "If you want to run with shadow/twin systems: for the last (optional) argument, provide the name of a named pipe or a text file to read on for the details of the other systems and information about the data collector.\n" 
        << "For the named pipe/file, this program will expect the first line to be: \n"
        << "`active_system_index`<space>`dataCollectorAddr:dataCollectorPort`<space>`switcherIPaddr:switcherPort`\n"
        << "active_system_index starts at 0 which is the system specified in the very next line (line #2 overall). The system in the line after that (the 3rd line overall) is considered index 1 and so on.\n"
        << "the next argument in the first line is `dataCollectorAddr:dataCollectorPort`. Use this to specify the data collector's IP address and port. If for some reason you do not want to use a data collector you can put a colon in this argument's place i.e. `:`.\n"
        << "The next argument in the first line `switcherIPaddr:switcherPort` is used to specify the Multicast IP address and the port that the switcher will be using. If, for some reason, you do not need the switcher, put a colon in this argument's place i.e. `:`.\n"
        << "2nd line and onwards are expected to be like: \n"
        << "/path/to/io_process_to_use SpinesDaemonIPAddr:SpinesDaemonPort suffixNumForIPCPath\n" 
        << "The IP address and port are of the spines daemon that is to be used for communication with this system.\n"
        << "Lastly, note that if the named pipe/file argument is provided, then the ip address and port provided in the command line arguments are going to be used as IP address and port for the spines daemon that is to be used for the communication with the data collector and the switcher.\n";
             
        exit(EXIT_FAILURE);
    }

    if (one_default_sys) {
        num_of_systems = 1;
        active_system_index = 0;

        std::string spinesd_ip_addr;
        int spinesd_port;
        parse_ipaddr_colon_port(av[2], spinesd_ip_addr, spinesd_port);

        io_process_data_struct this_io_proc;
        this_io_proc.io_binary_path = DEFAULT_IO_PROCESS_PATH;
        this_io_proc.spines_ip = spinesd_ip_addr;
        this_io_proc.spines_port = spinesd_port;
        this_io_proc.ipc_path_suffix = "0";
        
        io_process_data.push_back(this_io_proc);
        
        proxy_id = av[1];
        num_of_plc_rtus = atoi(av[3]);
    }

    if (case_named_pipe) {
        std::string pipe_name = av[4];
        read_named_pipe(pipe_name);
    }

    // if we have a data collector and/or switcher in the system then we need to know the spines daemon addr that will comm. with the these two components
    if (data_collector_isinsystem || switcher_isinsystem) {
        // spines ip, port to use for comm. with the data collector and/or switcher
        std::string spinesd_arg = av[2];
        std::string spinesd_ipaddr;
        int spinesd_port;
        parse_ipaddr_colon_port(spinesd_arg, spinesd_ipaddr, spinesd_port);
        
        if (data_collector_isinsystem) {
            data_collector_addr.spines_ip = spinesd_ipaddr;
            data_collector_addr.spines_port = spinesd_port;
        }

        if (switcher_isinsystem) {
            switcher_addr.spines_ip = spinesd_ipaddr;
            switcher_addr.spines_port = spinesd_port;
        }
    }
}

void read_named_pipe(std::string pipe_name) {
    std::ifstream pipe_file(pipe_name);
    if(pipe_file.fail()){
        std::cout << "Unable to access the file \"" << pipe_name << "\". Exiting.\n";
        exit(EXIT_FAILURE);
    }
    std::string line;
    bool is_first_line = true;
    int num_sys_count = 0;
    while (std::getline(pipe_file, line)) {
        char *line_cstr = strdup(line.c_str());
        io_process_data_struct this_io_proc;
        if (is_first_line) {  
            is_first_line = false;
            // active system index:
            active_system_index = atoi(strtok(line_cstr, " "));
            
            // data collector addr:
            std::string dc_addr = strtok(NULL, " ");
            if (dc_addr == ":") {
                data_collector_isinsystem = false;
            }
            else {
                data_collector_isinsystem = true;
                std::string dc_ipaddr;
                int dc_port;
                parse_ipaddr_colon_port(dc_addr, dc_ipaddr, dc_port);
                data_collector_addr.dc_ip = dc_ipaddr;
                data_collector_addr.dc_port = dc_port;
                // set up the sockaddr_in data struct:
                data_collector_addr.dc_sockaddr_in.sin_family = AF_INET;
                data_collector_addr.dc_sockaddr_in.sin_port = htons(data_collector_addr.dc_port);
                data_collector_addr.dc_sockaddr_in.sin_addr.s_addr = inet_addr(data_collector_addr.dc_ip.c_str());
            }

            // switcher mcast address:
            std::string switcher_ipaddr_and_port = strtok(NULL, " ");
            if (switcher_ipaddr_and_port == ":") {
                switcher_isinsystem = false;
            }
            else {
                switcher_isinsystem = true;
                std::string switcher_ipaddr;
                int switcher_port;
                parse_ipaddr_colon_port(switcher_ipaddr_and_port, switcher_ipaddr, switcher_port);
                switcher_addr.mcast_ipaddr = switcher_ipaddr;
                switcher_addr.mcast_port = switcher_port;
            }
        }
        else {
            num_sys_count++;

            // io_proc binary to use:
            this_io_proc.io_binary_path = strtok(line_cstr, " ");

            // spines ip addr and port to use with this io_process:
            int colon_pos = -1;
            std::string ip_and_port = strtok(NULL, " ");
            colon_pos = ip_and_port.find(':');
            std::string ip_addr = ip_and_port.substr(0, colon_pos);
            int port = std::stoi(ip_and_port.substr(colon_pos + 1));
            this_io_proc.spines_ip = ip_addr;
            this_io_proc.spines_port = port;
            this_io_proc.is_alive = false; // will set to true when it is actually forked
            
            // suffix for the ipc path
            this_io_proc.ipc_path_suffix = strtok(NULL, " ");

            // save:
            io_processes_data.push_back(this_io_proc);
        }
        num_of_systems = num_sys_count;

        free(line_cstr);
    }
}

void *listen_on_rtus_plcs_sock(void *arg) {
    // Receives any messages. Send them to all I/O processes
    UNUSED(arg);

    fd_set mask, tmask;
    int num;
    int nBytes;
    int ret;
    signed_message *mess;
    char buff[MAX_LEN];
    rtu_data_msg *rtud;
    seq_pair *ps;

    FD_ZERO(&mask);
    for(int i = 0; i < NUM_PROTOCOLS; i++) {
        if(ipc_index_used_for_message_broker[i]){
            FD_SET(sockets.to_from_rtus_plcs_via_ipc[i], &mask);
            std::cout << "FD_SET on ipc_s["<< i << "]\n";
        }
    }

    while (1) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, NULL);
        if (num > 0) {
            for(int i = 0; i < NUM_PROTOCOLS; i++) {
                if (ipc_index_used_for_message_broker[i] != true) {
                    continue;
                }
                /* Message from a message broker */
                if (FD_ISSET(sockets.to_from_rtus_plcs_via_ipc[i], &tmask)) {
                    nBytes = IPC_Recv(sockets.to_from_rtus_plcs_via_ipc[i], buff, MAX_LEN);
                    mess = (signed_message *)buff;
                    mess->global_configuration_number = My_Global_Configuration_Number;
                    rtud = (rtu_data_msg *)(mess + 1);
                    ps = (seq_pair *)&rtud->seq;
                    ps->incarnation = My_Incarnation;
                    
                    for (int j = 0; j < num_of_systems; j++) {
                        std::string system_info = (num_of_systems == 1)? ".": " # "+ std::to_string(j) + "/" + std::to_string(num_of_systems) + ".";
                        std::cout << "PROXY: message from plc, sending data to SM" << system_info << "\n";
                        int this_sock = sockets.to_ioproc_via_ipc[j];
                        std::string this_path_suffix = io_processes_data[j].ipc_path_suffix;
                        ret = IPC_Send(this_sock, (void *)mess, nBytes, (IPC_TO_IOPROC_CHILD + this_path_suffix).c_str());
                        if(ret != nBytes){
                            std::cout << "PROXY: error sending to SM. ret = " << ret << "\n";
                        }
                        else {
                            std::cout << "PROXY: message sent successfully. ret = " << ret << "\n";
                        }
                    }

                    // send to data collector (if it is in the system)
                    if (data_collector_isinsystem) {
                        // sending to data collector (this is a message that this proxy received from a rtu/plc and it is sending to SMs (via itrc client)):
                        std::cout << "sending message to data collector\n";
                        send_to_data_collector(mess, nBytes, RTU_PROXY_RTU_DATA);
                    }
                }
            }
        }
    }

    return NULL;
}

void init_rtus_plcs_listen_thread(pthread_t &thread) {
    // The thread listens for command messages coming from the RTUs/PLCs and forwards it to the the io_processes (which then send it to their ITRC_Client). The thread also forwards it to the data collector
    pthread_create(&thread, NULL, &listen_on_rtus_plcs_sock, NULL);
}

void setup_data_collector_spines_sock() {
    int proto;//, num, ret;
    int spines_timeout;
    
    proto = SPINES_RELIABLE; // need to use SPINES_RELIABLE and not SPINES_PRIORITY. This is because we need to be sure the message is delivered. SPINES_PRIORITY can drop messages. might need to think more though (but thats for later)
    
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
     *  this often */
    spines_timeout = DATA_COLLECTOR_SPINES_CONNECT_SEC;

    sockets.to_data_collector_via_spines = -1; // -1 is not a real socket so init to that
    while (1)
    {   
        sockets.to_data_collector_via_spines = Spines_SendOnly_Sock(data_collector_addr.spines_ip.c_str(), data_collector_addr.spines_port, proto);
        if (sockets.to_data_collector_via_spines < 0) {
            std::cout << "setup_data_collector_spines_sock(): Unable to connect to Spines, trying again soon\n";
            sleep(spines_timeout);
        }
        else {
            std::cout << "setup_data_collector_spines_sock(): Connected to Spines\n";
            break;
        }
    }
}

void send_to_data_collector(signed_message *msg, int nbytes, int stream) {
    int ret;
    std::cout << "Forwarding a message to the data collector\n";
    
    data_collector_packet data_packet;
    data_packet.data_stream = stream;
    data_packet.system_message = *msg;
    data_packet.nbytes_mess = nbytes;
    data_packet.nbytes_struct = sizeof(signed_message) + msg->len + 3*sizeof(int);

    ret = spines_sendto(sockets.to_data_collector_via_spines, (void *)&data_packet, data_packet.nbytes_struct, 0, (struct sockaddr *)&data_collector_addr.dc_sockaddr_in, sizeof(struct sockaddr));
    std::cout <<"Sent to data collector with return code ret = " << ret << "\n";
}

void setup_ipc_sockets_for_io_proc(int system_index) {
    sockets.to_ioproc_via_ipc.insert(sockets.to_ioproc_via_ipc.begin() + system_index, IPC_DGram_SendOnly_Sock()); // for sending something TO the child process
    sockets.from_ioproc_via_ipc.insert(sockets.from_ioproc_via_ipc.begin() + system_index, IPC_DGram_Sock((IPC_FROM_IOPROC_CHILD + io_processes_data[system_index].ipc_path_suffix).c_str())); // for receiving something FROM the child process
}

void init_io_procs() {
    for (int i=0; i < num_of_systems; i++) {
        std::cout << "Starting io_process";
        if (num_of_systems > 1) {
            std::cout << " # " << i+1 << "/" << num_of_systems;
        }
        std::cout << "\n";
        
        io_procs_pids.push_back(new_io_proc(io_processes_data[i]));
    }
}

void io_proc_message_handler(int socket_to_use, int code, void *data)
{   
    // This function runs for each message that is received. First it received the message on the socker. Then, if the message is from the active system, it is sent to the RTUs/PLCs. Finally, if there is a data collector in the system, it forwards the message to the data collector. 
    // It is called by listen_for_messages_from_ioproc()

    UNUSED(data);
    int message_is_from = code;

    int ret; 
    int nbytes;
    char buffer[MAX_LEN];
    signed_message *mess;

    std::cout << "There is a message from system #" << message_is_from << ":\n";

    // Receive the message on the socket
    ret = IPC_Recv(socket_to_use, buffer, MAX_LEN);
    if (ret < 0) std::cout << "I/O process message handler for process # " << message_is_from << ": IPC_Rev failed.\n";
    mess = (signed_message *)buffer;
    nbytes = sizeof(signed_message) + mess->len;

    // Special Processing for reconfiguration message
    if(mess->type ==  PRIME_OOB_CONFIG_MSG){
        std::cout << "PROXY: processing OOB CONFIG MESSAGE\n";
        Process_Config_Msg((signed_message *)buffer, ret);
    }
    
    // If the message is from the active system, send to the the message broker (modbus/dnp3 process) for sending further down to the RTUs/PLCs:
    if (message_is_from == active_system_index) {
        int in_list, rtu_dst, channel, ret2;

        rtu_dst = ((rtu_feedback_msg *)(mess + 1))->rtu;
        /* enqueue in correct ipc */
        in_list = key_value_get(rtu_dst, &channel);
        if(in_list) {
            std::cout << "PROXY: Delivering msg to RTU channel " << channel << "at " << sockets.to_from_rtus_plcs_via_ipc[channel] << "at path: " << protocol_data[channel].ipc_remote << "\n";
            ret2 = IPC_Send(sockets.to_from_rtus_plcs_via_ipc[channel], buffer, nbytes, 
                        protocol_data[channel].ipc_remote);
            if(ret2 != nbytes) {
                std::cout << "PROXY: error delivering to RTU\n";
            }
            else{
                std::cout << "PROXY: delivered to RTU\n";
            }
        }
        else {
            std::cout << "Error: Message from spines for rtu: " << rtu_dst << ", not my problem\n";
        }

        std::cout << "I/O process message handler for process # " << message_is_from << ": " << "The message has been forwarded to the RTUs/PLCs\n";
    }

    if (data_collector_isinsystem) {
        // Forward to the Data Collector:
        send_to_data_collector(mess, nbytes, message_is_from == active_system_index? RTU_PROXY_MAIN_MSG: RTU_PROXY_SHADOW_MSG);
    }
}

void *listen_for_messages_from_ioproc(void *arg) {
    // sets up events handler. This events handler is triggered when a message is received from an I/O process

    UNUSED(arg);

    E_init(); // initialize libspread event handler
        
    for (int i=0; i < num_of_systems; i++) {
        // Listen on the socket for this I/O process and run 
        E_attach_fd(sockets.from_ioproc_via_ipc[i], READ_FD, io_proc_message_handler, i, NULL, MEDIUM_PRIORITY);
    }
    
    E_handle_events();

    return NULL;
}

void init_io_proc_message_handlers(pthread_t &thread) {
    // create a thread that sets up events handler. This events handler is triggered when a message is received from an I/O process
    pthread_create(&thread, NULL, &listen_for_messages_from_ioproc, NULL);
}

void init_message_broker_processes_and_sockets() {
    std::vector<pid_t> pids;

    /* initialize ipc_index_used_for_message_broker */
    for(int i=0; i < NUM_PROTOCOLS; i++) {
        ipc_index_used_for_message_broker[i] = false;
    }
    
    struct timeval now;
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    My_ID = std::stoi(proxy_id);
    std::cout << "scanning json\n";

    // parse config into string and then parse json
    char *buffer;
    buffer = config_into_buffer();
    cJSON * root = cJSON_Parse(buffer);
    free(buffer);

    std::cout << "finding location in json\n";
    // find my location in the json file
    cJSON * my_loc = NULL;
    cJSON * locations = cJSON_GetObjectItem(root, "locations");
    int num_locations;
    num_locations = cJSON_GetArraySize(locations);
    int i;
    for(i = 0; i < num_locations; i++) {
        cJSON * loc = cJSON_GetArrayItem(locations, i);
        if(My_ID == cJSON_GetObjectItem(loc, "ID")->valueint) {
            std::cout << "Found my loc: " << My_ID << "\n";
            my_loc = loc;
            break;
        }
    }
    if (i == num_locations) {
        std::cout << "My id is not in config.json file!\n";
        exit(EXIT_FAILURE);
    }

    std::cout << "PROXY: finding what protocols I support\n";
    // figure out which protocols I support, set up those sockets
    cJSON * protocols = cJSON_GetObjectItem(my_loc, "protocols");
    for(i = 0; i < cJSON_GetArraySize(protocols); i++) {
        char * prot = cJSON_GetArrayItem(protocols, i)->valuestring;
        int p_n = string_to_protocol(prot);
        printf("PROXY: Creating Socket for protocol: %s and p_n=%d\n", prot,p_n);
        memset(&protocol_data[p_n], 0, sizeof(itrc_data));
        sprintf(protocol_data[p_n].prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
        sprintf(protocol_data[p_n].sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
        sprintf(protocol_data[p_n].ipc_local, "%s%s%d", (char *)RTU_IPC_ITRC, prot, My_ID);
        sprintf(protocol_data[p_n].ipc_remote, "%s%s%d", (char *)RTU_IPC_MAIN, prot, My_ID);
        ipc_index_used_for_message_broker[p_n] = true;
        sockets.to_from_rtus_plcs_via_ipc[p_n] = IPC_DGram_Sock(protocol_data[p_n].ipc_local);
        std::cout << "Create IPC_DGram_Sock sockets.to_from_rtus_plcs_via_ipc[" << p_n << "]=" << sockets.to_from_rtus_plcs_via_ipc[p_n] << "\n";
    
        // Start the child process:
        pid_t pid;
        pids.push_back(pid);
        std::stringstream process_path_strstream;
        process_path_strstream << "../" << prot << "/" << prot << "_master";
        std::string process_path = process_path_strstream.str();
        
        std::cout << "Starting message broker process";
        if (num_of_systems > 1) {
            std::cout << "# " << i << "/" << cJSON_GetArraySize(protocols);
        }
        std::cout << "\n";
        
        // child -- run program on path
        // Note 1: by convention, arg 0 is the prog name. Note 2: execv required this array to be NULL terminated.
        std::string caller = "proxy";
        std::string id = proxy_id;
        std::string spines_ip_port = "";
        spines_ip_port = spines_ip_port + data_collector_addr.spines_ip + std::to_string(data_collector_addr.spines_port); // ip:port for main/peripheries spines daemon
        std::string Num_RTU_Emulated = std::to_string(num_of_plc_rtus);
        char* child_proc_cmd[5] = { 
            const_cast<char*>(caller.c_str()), 
            const_cast<char*>(id.c_str()), 
            const_cast<char*>(spines_ip_port.c_str()),
            const_cast<char*>(Num_RTU_Emulated.c_str()),
            NULL
        };
        
        if ((pid = fork()) < 0) { // error case
            std::cout << "Error: fork returned pid < 0\n";
            exit(EXIT_FAILURE);
        }
        else if(pid == 0) { 
            // only child proc will run this. parent process will move on to to the very next line of code (which is going back to the start of the loop or finishing running the function).
            std::cout << "The child process' pid is: " << getpid() << "\n";
            if (execv(process_path.c_str(), child_proc_cmd) < 0) {
                std::cout << "Error in starting the process. errorno = "<< errno << "\n";
                exit(EXIT_FAILURE); // exit child
            }
        }
    }
    
    sleep(2); // TODO: this is carried over from the old codebase. Not sure why this is needed. If this is for sync purposes, there are better ways for that.
    std::cout << "PROXY: filling in key value data structure\n";
    fflush(stdout);
    // Figure out what RTU's I have to send to and place map the
    // id to a protocol
    key_value_init();
    cJSON * rtus = cJSON_GetObjectItem(my_loc, "rtus");
    for(i = 0; i < cJSON_GetArraySize(rtus); i++) { 
        cJSON * rtu = cJSON_GetArrayItem(rtus, i);
        char * prot_str = cJSON_GetObjectItem(rtu, "protocol")->valuestring;
        int rtu_id = cJSON_GetObjectItem(rtu, "ID")->valueint;
        int rtu_protocol = string_to_protocol(prot_str);
        key_value_insert(rtu_id, rtu_protocol);
        std::cout << "key value insert id=" << rtu_id << ", protocol " << rtu_protocol << "\n";
    } 

    // Delete CJSON reference
    cJSON_Delete(root);
}

int string_to_protocol(char * prot) {
    // conver string to protocol enum
    int p_n;
    if(strcmp(prot, "modbus") == 0) {
        p_n = MODBUS;
    }
    else if(strcmp(prot, "dnp3") ==0) {
        p_n = DNP3;
    }
    else {
        fprintf(stderr, "Protocol: %s not supported\n", prot);
        exit(EXIT_FAILURE);
    }
    return p_n;

}

void Process_Config_Msg(signed_message * conf_mess,int mess_size) {
    std::cout << "TODO\n";
    exit(EXIT_FAILURE);
}

void handle_switcher_message(int sock, int code, void* data) {
    UNUSED(code);
    UNUSED(data);
    
    int ret;
    byte buff[switch_message_max_size];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    Switch_Message * message;
    
    ret = spines_recvfrom(sock, buff, switch_message_max_size, 0, (struct sockaddr *) &from_addr, &from_len);
    if (ret < 0) {
        std::cout << "Switcher Message Handler: Error receving the message\n";
    }
    else {
        if ((unsigned long) ret < sizeof(Switch_Message)){
            std::cout << "Switcher Message Handler: Error - The received message is smaller than expected\n";
            return;
        }
        message = (Switch_Message*) buff;
        active_system_index = message->new_system_index; // TODO: do i need to do more here?
    }
    return;
}

void setup_switcher_connection() {
    // TODO: look at all the changes in this proxy file and apply the changes to the other proxy
    // set up the mcast socket:
    int retry_wait_sec = 2;
    int proto = SPINES_RELIABLE; // options: SPINES_RELIABLE and SPINES_PRIORITY
    while (true) {
        sockets.switcher_socket = Spines_Sock(switcher_addr.spines_ip.c_str(), switcher_addr.spines_port, proto, switcher_addr.mcast_port);
        if (sockets.switcher_socket < 0 ) {
            std::cout << "Error setting the socket for the switcher. Trying again in " << retry_wait_sec << "sec\n";
            sleep(retry_wait_sec);
        }
        else {
            break;
        }
    }
    switcher_addr.mreq.imr_multiaddr.s_addr = inet_addr(switcher_addr.mcast_ipaddr.c_str());
    switcher_addr.mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if(spines_setsockopt(sockets.switcher_socket, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&switcher_addr.mreq, sizeof(switcher_addr.mreq)) < 0) {
        std::cout << "Mcast: problem in setsockopt to join multicast address";
      }
    std::cout << "Mcast setup done\n";

    // set up an event handler for the switcher's messages
    E_init();
    E_attach_fd(sockets.switcher_socket, READ_FD, handle_switcher_message, 0, NULL, HIGH_PRIORITY);
    E_handle_events();
}

void kill_io_proc(io_process_data_struct io_proc_data) {
    kill(io_procs_pids[sys_index], SIGTERM); // TODO: what kind of signal should i send?
    io_proc_data.is_alive = false;
}

pid_t new_io_proc(io_process_data_struct &io_proc_data) {
    pid_t pid;
    // child -- run program on path
    // Note 1: by convention, arg 0 is the prog name. Note 2: execv required this array to be NULL terminated.
    char* child_proc_cmd[6] = { 
        const_cast<char*>(io_proc_data.io_binary_path.c_str()), 
        const_cast<char*>(io_proc_data.spines_ip.c_str()), 
        const_cast<char*>(std::to_string(io_proc_data.spines_port).c_str()),
        const_cast<char*>(io_proc_data.ipc_path_suffix.c_str()),
        const_cast<char*>(proxy_id.c_str()),
        NULL
    };

    if ((pid = fork()) < 0) { // error case
        std::cout << "Error: fork returned pid < 0\n";
        exit(EXIT_FAILURE);
    }
    else if(pid == 0) { 
        // only child proc will run this. parent process will move on to to the very next line of code (which is going back to the start of the loop or finishing running the function).
        std::cout << "The child process' pid is: " << getpid() << "\n";
        if (execv(child_proc_cmd[0], child_proc_cmd) < 0) {
            std::cout << "Error in starting the process. errorno = "<< errno << "\n";
            exit(EXIT_FAILURE); // exit child
        }
    }
    
    io_proc_data.is_alive = true;
    return pid;
}