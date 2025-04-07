//Include headers for socket management
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
// #include <errno.h>
#include <unistd.h> // for sleep()
#include <netdb.h>
// #include <sys/socket.h>
// #include <sys/time.h>
// #include <signal.h>
#include <arpa/inet.h>
// #include <pthread.h>
#include <cstring>
#include <string>
#include <sys/wait.h> // for forking io_process process
#include <sys/types.h>
#include <vector> 
#include <fstream>

extern "C" {
    #include "common/def.h" // used for MAX_LEN, etc.
    #include "common/scada_packets.h" // used for signed_message, etc.
    #include "common/net_wrapper.h" // for IPC_DGram_Sock(), etc
    #include "spines/libspines/spines_lib.h" // for spines functions e.g. spines_sendto()
    #include "prime/libspread-util/include/spu_events.h" // import libspread. for its event handler functions
}

// defines:
#define DEFAULT_IO_PROCESS_PATH "./io_process/io_process"
#define IPC_FROM_IOPROC_CHILD "/tmp/hmiproxy_ipc_ioproc_to_proxy"
#define IPC_TO_IOPROC_CHILD "/tmp/hmiproxy_ipc_proxy_to_ioproc"
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
};
struct data_collector_addr_struct {
    std::string dc_ip;
    int dc_port;
    std::string spines_ip;
    int spines_port;
    sockaddr_in dc_sockaddr_in;
};
struct sockets_struct {
    int from_hmi_via_ipc; // for messages coming from the HMI
    int to_hmi_via_ipc; // for sending messages to the HMI
    std::vector<int> from_ioproc_via_ipc; // for messages coming from the I/O processes
    std::vector<int> to_ioproc_via_ipc; // for sending messages to the I/O processes
    int to_data_collector_via_spines;
};
struct data_collector_packet {
    int data_stream;
    int nbytes_mess;
    int nbytes_struct;
    signed_message system_message;
}; // TODO: this struct (identical versions) is in 3 different files (hmiproxy, data_collector, ss-side proxy). move this to some common file maybe scada_packets

// global variables:
bool data_collector_isinsystem = false;
int num_of_systems = 0;
int active_system_index = -1;
sockets_struct sockets;
std::vector<io_process_data_struct> io_processes_data;
data_collector_addr_struct data_collector_addr = {.dc_ip="", .dc_port=-1, .spines_ip="", .spines_port=-1, .dc_sockaddr_in={}}; // initialize

// function declarations:
void parse_args(int ac, char **av, std::vector<io_process_data_struct> &io_process_data, data_collector_addr_struct &data_collector_addr);
void read_named_pipe(std::string pipe_name, std::vector<io_process_data_struct> &io_processes_data, bool &data_collector_isinsystem);
void setup_ipc_for_hmi(sockets_struct &sockets);
void init_hmi_listen_thread(pthread_t &thread);
void setup_data_collector_spines_sock();
void send_to_data_collector(signed_message *msg, int nbytes, int stream);
void init_io_procs();
void init_io_proc_message_handlers(pthread_t &message_events_thread);

// function definitions:
int main(int ac, char **av) {
    // read input args and store the data in the data structures:
    parse_args(ac, av, io_processes_data, data_collector_addr);
    
    // set up for communication with the Data Collector
    if (data_collector_isinsystem) {
        setup_data_collector_spines_sock();
    }

    // set up for communication with the HMI
    setup_ipc_for_hmi(sockets);

    // initialize and set up the thread that listens for messages from the HMI:
    pthread_t hmi_listen_thread;
    init_hmi_listen_thread(hmi_listen_thread);

    // initialize and fork the I/O processes:
    init_io_procs();

    // initialize and set up the threads for the message handler for the messages from the I/O processes:
    pthread_t io_procs_message_events_thread;
    init_io_proc_message_handlers(io_procs_message_events_thread);

    // wait for the threads before exiting
    pthread_join(hmi_listen_thread, NULL);
    pthread_join(io_procs_message_events_thread, NULL);

    return 0;
}

void parse_args(int ac, char **av, std::vector<io_process_data_struct> &io_process_data, data_collector_addr_struct &data_collector_addr) {
    bool one_default_sys = false;
    bool case_named_pipe = false;

    if (ac == 2) { // running with just the one active system
        one_default_sys = true;
        data_collector_isinsystem = false;
    }
    else if (ac == 3) { // running with the one active system and the data collector
        one_default_sys = true;
        data_collector_isinsystem = true;
    }
    else if (ac == 4) {  
        // running with the main system, the data collector, and shadow system(s).
        // check the else statement for details on how it is expected to work
        
        case_named_pipe =  true;
        data_collector_isinsystem = false;  // to be determined by reading the named pipe/file. will change to true if have a data collector otherwise keeping it at false
    }
    else {
        std::cout 
        << "Invalid args\n" 
        << "Usage: ./proxy spinesAddr:spinesPort [dataCollectorAddr:dataCollectorPort] [named pipe name or file name to use multiple systems]\n" 
        << "If you want to run with shadow/twin systems: for the last argument, provide the name of a named pipe or a text file to read on for the details of the other systems\n" 
        << "For the named pipe/file, this program will expect the first line to be: `active_system_index data_collector_is_in_system`. active_system_index starts at 0 which is the system specified in the the very next line. The system in the line after the next one is at index 1 and so on. `data_collector_is_in_system` can be set to 0 (false) and 1 (true) to specify whether or not there is going to be a data collector in the system. Note that there is a single space between these two.\n" 
        << "2nd line and onwards are expected to be like: /path/to/io_process_to_use SpinesIPAddr:SpinesPort suffixNumForIPCPath\n" 
        << "If this arg is provided:\n\tIf is is specified that we will have a data collector, then the first argument will be used for the IP address and port of the spines daemon that is to be used for communication with the data collector.\n\tOtherwise, if is is specified that we will NOT have a data collector, then the first two arguments are ignored.\n";
             
        exit(EXIT_FAILURE);
    }

    if (one_default_sys) {
        num_of_systems = 1;
        active_system_index = 0;

        int colon_pos = -1;
        std::string spinesd_arg = av[1];
        colon_pos = spinesd_arg.find(':');
        std::string spinesd_ip_addr = spinesd_arg.substr(0, colon_pos);
        int spinesd_port = std::stoi(spinesd_arg.substr(colon_pos + 1));

        io_process_data_struct this_io_proc;
        this_io_proc.io_binary_path = DEFAULT_IO_PROCESS_PATH;
        this_io_proc.spines_ip = spinesd_ip_addr;
        this_io_proc.spines_port = spinesd_port;
        this_io_proc.ipc_path_suffix = "0";
        
        io_process_data.push_back(this_io_proc);
    }

    if (case_named_pipe) {
        std::string pipe_name = av[3];
        read_named_pipe(pipe_name, io_process_data, data_collector_isinsystem);
    }

    if (data_collector_isinsystem) {
        // ip and port for the data collector process
        std::string dc_arg = av[2];
        int colon_pos = -1;
        colon_pos = dc_arg.find(':');
        std::string dc_ip_addr = dc_arg.substr(0, colon_pos);
        int dc_port = std::stoi(dc_arg.substr(colon_pos + 1));
        data_collector_addr.dc_ip = dc_ip_addr;
        data_collector_addr.dc_port = dc_port;

        // spines ip, port to use for comm. with the data collector
        colon_pos = -1;
        std::string spinesd_arg = av[1];
        colon_pos = spinesd_arg.find(':');
        std::string spinesd_ip_addr = spinesd_arg.substr(0, colon_pos);
        int spinesd_port = std::stoi(spinesd_arg.substr(colon_pos + 1));
        data_collector_addr.spines_ip = spinesd_ip_addr;
        data_collector_addr.spines_port = spinesd_port;

        // set up the sockaddr_in data struct:
        data_collector_addr.dc_sockaddr_in.sin_family = AF_INET;
        data_collector_addr.dc_sockaddr_in.sin_port = htons(data_collector_addr.dc_port);
        data_collector_addr.dc_sockaddr_in.sin_addr.s_addr = inet_addr(data_collector_addr.dc_ip.c_str());
    }
}

void read_named_pipe(std::string pipe_name, std::vector<io_process_data_struct> &io_processes_data, bool &data_collector_isinsystem) {
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
            active_system_index = atoi(strtok(line_cstr, " "));
            int dc_isinsystem_int = atoi(strtok(NULL, " "));
            if (!(dc_isinsystem_int == 0 || dc_isinsystem_int == 1)) {
                std::cout << "Invalid value for `data_collector_isinsystem` in the named pipe/file\n";
                exit(EXIT_FAILURE);
            }
            data_collector_isinsystem = dc_isinsystem_int == 1? true: false;
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
            
            // suffix for the ipc path
            this_io_proc.ipc_path_suffix = strtok(NULL, " ");

            // save:
            io_processes_data.push_back(this_io_proc);
        }
        num_of_systems = num_sys_count;

        free(line_cstr);
    }
}

void setup_ipc_for_hmi(sockets_struct &sockets)
{   
    sockets.from_hmi_via_ipc = IPC_DGram_Sock(HMI_IPC_HMIPROXY); // for HMI to HMI-side-proxy communication
    sockets.to_hmi_via_ipc = IPC_DGram_SendOnly_Sock(); // for HMI-side-proxy to HMI communication
}

void *listen_on_hmi_sock(void *arg) {
    // sockets_struct * sockets = (sockets_struct*) (arg);
    UNUSED(arg);

    int ret; 
    char buf[MAX_LEN];
    signed_message *mess;
    int nbytes;

    for (;;) {
        std::cout << "Waiting to receive something on the HMI socket\n";
        ret = IPC_Recv(sockets.from_hmi_via_ipc, buf, MAX_LEN);
        if (ret < 0) {
            std::cout << "HMI-proxy: IPC_Rev failed. ret = " << ret << "\n";
        }
        else {
            std::cout << "Received a message from the HMI. ret = " << ret << "\n";
            mess = (signed_message *)buf;
            nbytes = sizeof(signed_message) + mess->len;
            for (int i=0; i < num_of_systems; i++) {
                ret = IPC_Send(sockets.to_ioproc_via_ipc[i], (void *)mess, nbytes, (IPC_TO_IOPROC_CHILD + io_processes_data[i].ipc_path_suffix).c_str());
                if (ret < 0) {
                    std::cout << "Failed to sent message to the IRTC thread. ret = " << ret << "\n";
                }
                std::cout << "The message has been forwarded to the IRTC thread. ret = " << ret << "\n";
            }

            if (data_collector_isinsystem) {
                send_to_data_collector(mess, nbytes, HMI_PROXY_HMI_CMD);
            }
        }
    }
    return NULL;
}

void init_hmi_listen_thread(pthread_t &thread) {
    // The thread listens for command messages coming from the HMI and forwards it to the the io_processes (which then send it to their ITRC_Client). The thread also forwards it to the data collector
    pthread_create(&thread, NULL, &listen_on_hmi_sock, NULL);
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
    std::cout << "Sent to data collector with return code ret = " << ret << "\n";
}

void setup_ipc_sockets_for_io_proc(int system_index) {
    sockets.to_ioproc_via_ipc.insert(sockets.to_ioproc_via_ipc.begin() + system_index, IPC_DGram_SendOnly_Sock()); // for sending something TO the child process
    sockets.from_ioproc_via_ipc.insert(sockets.from_ioproc_via_ipc.begin() + system_index, IPC_DGram_Sock((IPC_FROM_IOPROC_CHILD + io_processes_data[system_index].ipc_path_suffix).c_str())); // for receiving something FROM the child process
}

void init_io_procs() {
    std::vector<pid_t> pids;
    
    for (int i=0; i < num_of_systems; i++) {
        // set up the IPC connection using which we will talk to the child process:
        setup_ipc_sockets_for_io_proc(i);

        // Start the child process:
        pid_t pid;
        pids.push_back(pid);

        std::cout << "Starting io_process";
        if (num_of_systems > 1) {
            std::cout << " # " << i+1 << "/" << num_of_systems;
        }
        std::cout << "\n";
        
        // child -- run program on path
        // Note 1: by convention, arg 0 is the prog name. Note 2: execv required this array to be NULL terminated.
        char* child_proc_cmd[5] = { 
            const_cast<char*>(io_processes_data[i].io_binary_path.c_str()), 
            const_cast<char*>(io_processes_data[i].spines_ip.c_str()), 
            const_cast<char*>(std::to_string(io_processes_data[i].spines_port).c_str()),
            const_cast<char*>(io_processes_data[i].ipc_path_suffix.c_str()),
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
    }
}

void io_proc_message_handler(int socket_to_use, int code, void *data)
{   
    // This function runs for each message that is received. First it received the message on the socker. Then, if the message is from the active system, it is sent to the HMI. Finally, if there is a data collector in the system, it forwards the message to the data collector. 
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

    // TODO: check for PRIME_OOB_CONFIG_MSG ?
    
    // If the message is from the active system, send to the HMI:
    if (message_is_from == active_system_index) {
        IPC_Send(sockets.to_hmi_via_ipc, (void *)mess, nbytes, HMIPROXY_IPC_HMI);
        std::cout << "I/O process message handler for process # " << message_is_from << ": " << "The message has been forwarded to the HMI\n";
    }

    if (data_collector_isinsystem) {
        // Forward to the Data Collector:
        send_to_data_collector(mess, nbytes, message_is_from == active_system_index? HMI_PROXY_MAIN_MSG: HMI_PROXY_SHADOW_MSG);
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