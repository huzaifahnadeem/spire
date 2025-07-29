#include "proxy.h"

// TODO remove (used by temp_test_switcher_msgs)
#include <fstream> // for file operations
#include <chrono> // for time
#include <ctime> // for time

int main(int ac, char **av) {
    E_init(); // initialize libspread events handler

    // the constructor reads input args and store the data in the data structures:
    InputArgs args(ac, av);

    // set up the data collector manager
    DataCollectorManager data_collector_manager(args.pipe_data.data_collector_sock_addr, args.spinesd_sock_addr);
    
    // Initialize client manager
    ClientManager client_manager(args);   

    // set up I/O Processes Manager
    IOProcManager io_proc_manager(args, &data_collector_manager, &client_manager);

    // start client manager
    pthread_t client_listen_thread;
    client_manager.set_io_proc_man_ref(&io_proc_manager); // so that the client manager can send messages to the IO processes
    client_manager.set_data_collector_man_ref(&data_collector_manager); // so that the client manager can send messages to the data collector
    client_manager.init_listen_thread(client_listen_thread); // Initialize the thread that listens to the incoming messages from the clients

    // fork all the io processes
    io_proc_manager.start_all_io_procs();

    // sets up socket for the switcher messages and handle events:
    pthread_t switcher_listen_thread;
    SwitcherManager switcher_manager(args, &io_proc_manager, switcher_listen_thread);
    temp_test_switcher_msgs("main(): before E_handle_events");
    E_handle_events(); // signal libspread events handler to start handling all the events for which fds were set by the objects above
    temp_test_switcher_msgs("main(): after E_handle_events");

    // wait for any threads before exiting
    pthread_join(client_listen_thread, NULL);
    pthread_join(switcher_listen_thread, NULL);
    return EXIT_SUCCESS;
}

InputArgs::InputArgs(int ac, char **av) {
    this->parse_args(ac, av);
}
void InputArgs::print_usage() {
    std::cout 
        << "Invalid args\n" 
        << "Usage: ./proxy -c client_type -sd spinesAddr:spinesPort [-id proxyID] [-n Num_PLC_RTU] [-dt <named pipe name or file name to use multiple systems>]\n" 
        << "use `-c` to specify the client's type. Valid options: `hmi`, `rtus_plcs`.\n"
        << "use `-id` to specify the Proxy ID for the RTUs/PLCs clients. Ignored for HMI clients.\n"
        << "use `-sd` to specify the Spines daemon's Socket Address (IPaddress:Port). If not using the -dt option (see below), then this daemon is used for all communication by this proxy.\n"
        << "use `-n` to the number of RTUs/PLCs. Ignored for RTU/PLC clients.\n"
        << "You may use the arguments in any order. Specify the argument followed by a space and then the value. e.g. `-c hmi`.\n"
        << "\nIf you want to run with digital twin systems: for the last (optional) -dt argument, provide the name of a named pipe or a text file to read on for the details of the other systems and information about the data collector.\n" 
        << "For this named pipe/file, this program will expect the first line to be: \n"
        << "`active_system_id`<space>`dataCollectorIPAddr:dataCollectorPort`<space>`switcherIPAddr:switcherPort`\n"
        << "active_system_id is a string that is specified for each system (see below).\n"
        << "The next argument in the first line is `dataCollectorIPAddr:dataCollectorPort`. Use this to specify the data collector's IP address and port. If for some reason you do not want to use a data collector you skip this by putting a colon in this argument's place i.e. `:`.\n"
        << "The next argument in the first line `switcherIPAddr:switcherPort` is used to specify the Multicast IP address and the port that the switcher will be using. If, for some reason, you do not need the switcher, put a colon in this argument's place i.e. `:`.\n"
        << "2nd line and onwards are expected to be like: \n"
        << "System_ID /path/to/io_process_to_use SpinesDaemonIPAddr:SpinesDaemonPort\n" 
        << "Use `System_ID` to specify the system's unique ID/label. This will be used refer to the system.\n" 
        << "Use `/path/to/io_process_to_use` to specify where the I/O Process' binary file is.\n" 
        << "The IP address and port are of the spines daemon that is to be used for communication with this system.\n"
        << "Finally, note that if the named pipe/file argument is provided, then the ip address and port provided in the command line arguments are going to be used as IP address and port for the spines daemon that is to be used for the communication with the data collector and the switcher.\n";
             
        exit(EXIT_FAILURE);
}
void InputArgs::parse_args(int argc, char **argv) {
    // TODO: right now we only have one kind of HMI (pnnl). But in the future we might want to have an option of having multiple?
    while (--argc > 0) {
        argv++;
    
        /* [-c client_type] */
        if ((argc > 1) && (!strncmp(*argv, "-c", 2))) {
            std::string this_arg = argv[1];
            if ((this_arg != "hmi") && (this_arg != "rtus_plcs")) {
                std::cout << "Invalid value provided for -c argument. Exiting.\n";
                exit(EXIT_FAILURE);
            }
            this->client_type = this_arg;
            argc--; argv++;
        }
        /* [-id proxyID] */
        else if ((argc > 1) && (!strncmp(*argv, "-id", 3))) {
            std::string this_arg = argv[1];
            this->proxy_id = this_arg;
            argc--; argv++;
        }
        /* [-sd spinesAddr:spinesPort] */
        else if ((argc > 1) && (!strncmp(*argv, "-sd", 3))) {
            std::string this_arg = argv[1];
            this->spinesd_sock_addr = parse_socket_address(this_arg);
            argc--; argv++;
        }
        /* [-n Num_PLC_RTU] */
        else if ((argc > 1) && (!strncmp(*argv, "-n", 2))) {
            std::string this_arg = argv[1];
            this->num_of_plc_rtus = std::stoi(this_arg);
            argc--; argv++;
        }
        /* [-dt named_pipe] */
        else if ((argc > 1) && (!strncmp(*argv, "-dt", 3))) {
            std::string this_arg = argv[1];
            this->pipe_name = this_arg;
            this->read_named_pipe(this->pipe_name);
            argc--; argv++;
        }
        else {
            this->print_usage();
        }
    }
}
void InputArgs::read_named_pipe(std::string pipe_name) {
    std::ifstream pipe_file(pipe_name);
    if(pipe_file.fail()){
        std::cout << "Unable to access the file \"" << pipe_name << "\". Exiting.\n";
        exit(EXIT_FAILURE);
    }

    std::string line;
    bool is_first_line = true;
    while (std::getline(pipe_file, line)) {
        char *line_cstr = strdup(line.c_str());
        if (is_first_line) {  
            is_first_line = false;
            
            this->pipe_data.active_sys_id = strtok(line_cstr, " ");
            
            // data collector socket addr:
            std::string dc_addr = strtok(NULL, " ");
            this->pipe_data.data_collector_sock_addr = parse_socket_address(dc_addr);

            // switcher mcast address:
            std::string switcher_addr = strtok(NULL, " ");
            this->pipe_data.switcher_sock_addr = parse_socket_address(switcher_addr);
        }
        else {
            SystemsData this_systems_data;
            
            // id for this system
            this_systems_data.id = strtok(line_cstr, " ");

            // io_proc binary to use:
            this_systems_data.binary_path = strtok(NULL, " ");

            // spines ip addr and port to use with this io_process:
            std::string sp_addr = strtok(NULL, " ");
            this_systems_data.spinesd_sock_addr = parse_socket_address(sp_addr);
                        
            // save:
            this->pipe_data.systems_data.push_back(this_systems_data);
        }

        free(line_cstr);
    }
}

IOProcManager::IOProcManager(InputArgs args, DataCollectorManager * data_collector_manager, ClientManager* client_man) {
    this->proxy_id = args.proxy_id;
    this->data_collector_manager = data_collector_manager;
    this->client_manager = client_man;
    this->client_type = args.client_type;

    // add IO Procs
    if (args.pipe_name == "" && args.pipe_data.systems_data.size() == 0) {
        // this means running with just a single system (no twins)
        std::string sys_id = "0"; // arbitrary
        this->active_sys_id = sys_id;
        std::string path = DEFAULT_IO_PROCESS_PATH;
        this->add_io_proc(sys_id, path, args.spinesd_sock_addr);
    }
    else {
        // running with twins
        this->active_sys_id = args.pipe_data.active_sys_id;

        for (auto & this_system : args.pipe_data.systems_data) {
            this->add_io_proc(this_system.id, this_system.binary_path, this_system.spinesd_sock_addr);
        }
    } 
}
void IOProcManager::add_io_proc(std::string id, std::string bin_path, SocketAddress spines_address) {
    // add the data for a new io_proc (but don't fork the process here (that has its own fork_io_proc function))
    IOProcess this_io_proc;
    this_io_proc.io_binary_path = bin_path;
    this_io_proc.spines_addr = spines_address;
    
    this_io_proc.sockets.to = IPC_DGram_SendOnly_Sock(); // for sending something TO the child process (child being the IO Process)
    std::string ipc_path = (this->client_type == "hmi"? IPC_FROM_IOPROC_CHILD_CLIENTHMI: IPC_FROM_IOPROC_CHILD_CLIENTRTUPLC);
    this_io_proc.sockets.from = IPC_DGram_Sock((ipc_path + id).c_str()); // for receiving something FROM the child process (child being the IO Process)

    this->io_procs[id] = this_io_proc;
}
void IOProcManager::start_io_proc(std::string id) {
    // for the given id, this function forks a process to run that. It also sets up the message handler for any messages received from this process
    this->fork_io_proc(this->io_procs[id], id);

    // Note that you cannot pass a non-static class memberfunction to E_attach_fd or to pthread_create.
    // and since this function that I am passing (io_proc_message_handler) uses non-static class member properties, it cannot be simply made static as is
    // So, I have made the function static and removed all direct references to 'this' object. Instead, to access object specific member properies, a reference to a specific object is passed
    // since we have a few args to pass to this function, I have made a simple struct 'this_fn_args_struct' to use to send the args. Inside the function I have the same struct and I cast the void * data to this struct and use the object inside instead of 'this'
    
    Args_io_proc_message_handler args_to_pass = {.id = id, .class_obj = this};
    this->args_for_io_proc_message_handler[id] = args_to_pass;
    Args_io_proc_message_handler* args_to_pass_ptr = &(this->args_for_io_proc_message_handler[id]);
    E_attach_fd(io_procs[id].sockets.from, READ_FD, IOProcManager::io_proc_message_handler, 0, (void*)args_to_pass_ptr, MEDIUM_PRIORITY); 
}
void IOProcManager::fork_io_proc(IOProcess &io_proc, std::string id) {
    // child -- run program on path
    // Note 1: by convention, arg 0 is the prog name. Note 2: execv required this array to be NULL terminated.
    std::string client_is_hmi= (this->client_type == "hmi"? "1": "0");
    std::string ipc_path_suffix = id; 
    char* child_proc_cmd[7] = { 
        const_cast<char*>(io_proc.io_binary_path.c_str()), 
        const_cast<char*>(io_proc.spines_addr.ip_addr.c_str()), 
        const_cast<char*>(std::to_string(io_proc.spines_addr.port).c_str()),
        const_cast<char*>(ipc_path_suffix.c_str()),
        const_cast<char*>(this->proxy_id.c_str()), // proxy id for rtu/plc
        const_cast<char*>(client_is_hmi.c_str()),
        NULL
    };

    if ((io_proc.pid = fork()) < 0) { // error case
        std::cout << "Error: fork returned pid < 0\n";
        exit(EXIT_FAILURE);
    }
    else if(io_proc.pid == 0) { 
        // only child proc will run this. parent process will move on to to the very next line of code (which is going back to the start of the loop or finishing running the function).
        std::cout << "The child process' pid is: " << getpid() << "\n";
        if (execv(child_proc_cmd[0], child_proc_cmd) < 0) {
            std::cout << "Error in starting the process. errorno = "<< errno << "\n";
            exit(EXIT_FAILURE); // exit child
        }
    }
}
void IOProcManager::kill_io_proc(std::string id) {
    // ignore if the active system is requested to be killed
    if (id == this->get_active_sys_id()) {
        std::cout << "IOProcManager::kill_io_proc: ignoring request to kill the active io process\n";
        return;
    }
    // kills the process and lets the event handler know it should no longer listen for any messages
    IOProcess this_io_proc = io_procs[id];
    kill(this_io_proc.pid, SIGTERM); // TODO: what kind of signal should i send?
    E_detach_fd(this->io_procs[id].sockets.from, READ_FD); // tell the event handler that it no longer needs to handle for this socket
    this->args_for_io_proc_message_handler.erase(id);
}
void IOProcManager::start_all_io_procs() {
    for (auto & [id, this_io_proc]: this->io_procs) {
        this->start_io_proc(id);
    }
}
void IOProcManager::io_proc_message_handler(int sock, int code, void *data) {
    // handles the messages that are received from the io_process
    
    // This function runs for each message that is received. First it received the message on the socker. Then, if the message is from the active system, it is sent to the RTUs/PLCs. Finally, if there is a data collector in the system, it forwards the message to the data collector. 
    // It is called by listen_for_messages_from_ioproc()

    UNUSED(code);
    Args_io_proc_message_handler* this_fn_args = (Args_io_proc_message_handler *) data;
    std::string message_is_from = this_fn_args->id;
    IOProcManager* this_class_obj = this_fn_args->class_obj; // since this is a static function, I cannot use 'this'. Instead a reference to a class object is passes as an argument (which is of this specific struct's type)

    int ret; 
    int nbytes;
    char buffer[MAX_LEN];
    signed_message *mess;

    std::cout << "There is a message from system with ID: " << message_is_from << "\n";

    // Receive the message on the socket
    ret = IPC_Recv(sock, buffer, MAX_LEN);
    if (ret < 0) std::cout << "I/O process message handler for system " << message_is_from << ": IPC_Rev failed.\n";
    mess = (signed_message *)buffer;
    nbytes = sizeof(signed_message) + mess->len;

    if (this_class_obj->client_type == "rtus_plcs") {
        // Special Processing for reconfiguration message
        if(mess->type ==  PRIME_OOB_CONFIG_MSG) {
            std::cout << "PROXY: processing OOB CONFIG MESSAGE\n";
            process_config_msg((signed_message *)buffer, ret);
        }
        
        // If the message is from the active system, send to the the message broker (modbus/dnp3 process) for sending further down to the RTUs/PLCs:
        if (message_is_from == this_class_obj->active_sys_id) {
            this_class_obj->client_manager->send(mess, nbytes);
            std::cout << "I/O process message handler for process # " << message_is_from << ": " << "The message has been forwarded to the RTUs/PLCs\n";
        }
        
        // Forward to the Data Collector: (the dc manager will figure out whether or there is a data collector to send to or not)
        this_class_obj->data_collector_manager->send_to_dc(mess, nbytes, message_is_from == this_class_obj->active_sys_id? RTU_PROXY_MAIN_MSG: RTU_PROXY_SHADOW_MSG, message_is_from);
    }
    
    else if (this_class_obj->client_type == "hmi") {
        // TODO: check for PRIME_OOB_CONFIG_MSG ?
    
        // If the message is from the active system, send to the HMI:
        if (message_is_from == this_class_obj->active_sys_id) {
            this_class_obj->client_manager->send(mess, nbytes);
            std::cout << "I/O process message handler for process # " << message_is_from << ": " << "The message has been forwarded to the HMI\n";
        }

        // Forward to the Data Collector:
        this_class_obj->data_collector_manager->send_to_dc(mess, nbytes, message_is_from == this_class_obj->active_sys_id? HMI_PROXY_MAIN_MSG: HMI_PROXY_SHADOW_MSG, message_is_from);
    }    
}
void IOProcManager::send_msg_to_all_procs(signed_message *msg, int nbytes) {
    int ret;
    for (auto & [id, this_io_proc]: this->io_procs) {
        std::cout << "PROXY: message from proxy, sending to SM (via IO Process with system ID " << id << ")\n";
        int this_sock = this_io_proc.sockets.to;
        std::string ipc_path = (this->client_type == "hmi"? IPC_TO_IOPROC_CHILD_CLIENTHMI: IPC_TO_IOPROC_CHILD_CLIENTRTUPLC);
        std::string this_path_suffix = id;
        ret = IPC_Send(this_sock, (void *)msg, nbytes, (ipc_path + this_path_suffix).c_str());
        if(ret != nbytes) {
            std::cout << "PROXY: error sending to SM (via IO Process with system ID "<< id << "). ret = " << ret << "\n";
        }
        else {
            std::cout << "PROXY: message sent successfully to SM (via IO Process with system ID "<< id << "). ret = " << ret << "\n";
        }
    }
}
void IOProcManager::update_active_system_id(std::string new_sys_id) {
    auto found_val = this->io_procs.find(new_sys_id);
    if (found_val != this->io_procs.end()) {
        // key (id) exists. so valid system ID was provided
        this->active_sys_id = new_sys_id;
    } 
    else {
       std::cout << "Switcher sent an invalid key for the new active system. Sent ID = " << new_sys_id << ". Request was ignored\n";
    }
}
std::string IOProcManager::get_active_sys_id() {
    return this->active_sys_id;
}

void parse_socket_address(std::string ipaddr_colon_port, std::string &ipaddr, int &port) {
    if (ipaddr_colon_port == ":") {
        ipaddr = "";
        port = -1;
        return;
    }
    int colon_pos = -1;
    colon_pos = ipaddr_colon_port.find(':');
    ipaddr = ipaddr_colon_port.substr(0, colon_pos);
    port = std::stoi(ipaddr_colon_port.substr(colon_pos + 1));
}
void parse_socket_address(char* ipaddr_colon_port, std::string &ipaddr, int &port) {
    std::string std_string_ipaddr_colon_port = ipaddr_colon_port;
    parse_socket_address(std_string_ipaddr_colon_port, ipaddr, port);
}
void parse_socket_address(char* socket_address, SocketAddress &sock_addr) {
    parse_socket_address(socket_address, sock_addr.ip_addr, sock_addr.port);
}
void parse_socket_address(std::string socket_address, SocketAddress &sock_addr) {
    parse_socket_address(socket_address, sock_addr.ip_addr, sock_addr.port);
}
SocketAddress parse_socket_address(std::string socket_address) {
    SocketAddress sock_addr;
    parse_socket_address(socket_address, sock_addr.ip_addr, sock_addr.port);
    return sock_addr;
}
SocketAddress parse_socket_address(char* socket_address) {
    SocketAddress sock_addr;
    parse_socket_address(socket_address, sock_addr.ip_addr, sock_addr.port);
    return sock_addr;
}

DataCollectorManager::DataCollectorManager(SocketAddress data_collector_sockaddr, SocketAddress spined_sockaddr) {
    // check if the data collector args were provided
    if (data_collector_sockaddr.ip_addr == "" && data_collector_sockaddr.port == -1) {
        // no data collector
        this->no_data_collector = true;
    }
    else {
        this->no_data_collector = false;
        this->dc_sockaddr = data_collector_sockaddr;
        this->spinesd_sock_addr = spined_sockaddr;
        this->dc_sockaddr_in.sin_family = AF_INET;
        this->dc_sockaddr_in.sin_port = htons(dc_sockaddr.port);
        this->dc_sockaddr_in.sin_addr.s_addr = inet_addr(dc_sockaddr.ip_addr.c_str());
        
        this->spines_protocol = SPINES_RELIABLE; // need to use SPINES_RELIABLE and not SPINES_PRIORITY. This is because we need to be sure the message is delivered. SPINES_PRIORITY can drop messages. might need to think more though (but thats for later)

        this->setup_spines_socket();
    }
}
void DataCollectorManager::setup_spines_socket() {
    int spines_timeout = this->SPINES_RECONNECT_SEC; // Setup the spines timeout frequency - if disconnected, will try to reconnect this often

    this->spinesd_socket = -1; // -1 is not a real socket so init to that
    while (true) {   
        this->spinesd_socket = Spines_SendOnly_Sock(this->spinesd_sock_addr.ip_addr.c_str(), this->spinesd_sock_addr.port, this->spines_protocol);
        if (this->spinesd_socket < 0) {
            std::cout << "Data Collector Manager: Unable to connect to Spines, trying again soon\n";
            sleep(spines_timeout);
        }
        else {
            std::cout << "Data Collector Manager: Connected to Spines\n";
            break;
        }
    }
}

void DataCollectorManager::send_to_dc(signed_message *msg, int nbytes, int data_stream_id)  {
    this->send_to_dc(msg, nbytes, data_stream_id, "");
}

void DataCollectorManager::send_to_dc(signed_message *msg, int nbytes, int data_stream_id, std::string sys_id) {
    if (this->no_data_collector)
        return;

    int ret;
    std::cout << "Forwarding a message to the data collector\n";
    
    DataCollectorPacket data_packet;
    data_packet.data_stream = data_stream_id;
    data_packet.system_message = *msg;
    data_packet.nbytes_mess = nbytes;
    data_packet.sys_id = sys_id;
    data_packet.nbytes_struct = sizeof(signed_message) + msg->len + 3*sizeof(int) + data_packet.sys_id.size();

    ret = spines_sendto(this->spinesd_socket, (void *)&data_packet, data_packet.nbytes_struct, 0, (struct sockaddr *)&this->dc_sockaddr_in, sizeof(struct sockaddr));
    std::cout << "Sent to data collector with return code ret = " << ret << "\n";
}

ClientManager::ClientManager(InputArgs args) {
    this->client_type = args.client_type;
    if (this->client_type == "hmi") {
        this->hmi_manager.init();
    }
    else if (this->client_type == "rtus_plcs") {
        this->rtu_manager.init(args);
    }
    else {
        std::cout << "Invalid client type " << args.client_type << ". Exiting. \n";
        exit(EXIT_FAILURE);
    }
}
void ClientManager::set_io_proc_man_ref(IOProcManager * io_proc_man) {
    this->io_proc_manager = io_proc_man;
    if (this->client_type == "hmi") {
        this->hmi_manager.set_io_proc_man_ref(this->io_proc_manager);
    }
    else if (this->client_type == "rtus_plcs") {
        this->rtu_manager.set_io_proc_man_ref(this->io_proc_manager);
    }
    else {
        std::cout << "Invalid client type " << this->client_type << ". Exiting. \n";
        exit(EXIT_FAILURE);
    }
}
void ClientManager::set_data_collector_man_ref(DataCollectorManager * dc_man) {
    this->dc_manager = dc_man;
    if (this->client_type == "hmi") {
        this->hmi_manager.set_data_collector_man_ref(this->dc_manager);
    }
    else if (this->client_type == "rtus_plcs") {
        this->rtu_manager.set_data_collector_man_ref(this->dc_manager);
    }
    else {
        std::cout << "Invalid client type " << this->client_type << ". Exiting. \n";
        exit(EXIT_FAILURE);
    }
}
void ClientManager::init_listen_thread(pthread_t &thread) {
    if (this->client_type == "hmi") {
        this->hmi_manager.init_listen_thread();
    }
    else if (this->client_type == "rtus_plcs") {
        this->rtu_manager.init_listen_thread(thread);
    }
    else {
        std::cout << "Invalid client type " << this->client_type << ". Exiting. \n";
        exit(EXIT_FAILURE);
    }
}
int ClientManager::send(signed_message* mess, int nbytes) {
    int ret = -1;
    if (this->client_type == "hmi") {
        ret = this->hmi_manager.send(mess, nbytes);
    }
    else if (this->client_type == "rtus_plcs") {
        ret = this->rtu_manager.send(mess, nbytes);
    }
    else {
        std::cout << "Invalid client type " << this->client_type << ". Exiting. \n";
        exit(EXIT_FAILURE);
    }

    return ret;
}

RTUsPLCsMessageBrokerManager::RTUsPLCsMessageBrokerManager() {
    // nothing here. initialized with `init` fn
    // doing it like this because ClientManager has a property for both RTUsPLCsMessageBrokerManager and HMIManager
    // but in a given proxy instance only one of them is used so this way we only run `init` for the one we are using
}
void RTUsPLCsMessageBrokerManager::init(InputArgs args) {
    this->proxy_id = args.proxy_id;
    this->num_of_plc_rtus = args.num_of_plc_rtus;
    this->spinesd_addr = args.spinesd_sock_addr;
    this->init_message_broker_processes_and_sockets();
}
void RTUsPLCsMessageBrokerManager::init_message_broker_processes_and_sockets() {
    /* initialize ipc_index_used_for_message_broker */
    for(int i=0; i < NUM_PROTOCOLS; i++) {
        this->ipc_index_used_for_message_broker[i] = false;
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
        memset(&this->protocol_data[p_n], 0, sizeof(itrc_data));
        sprintf(this->protocol_data[p_n].prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
        sprintf(this->protocol_data[p_n].sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
        sprintf(this->protocol_data[p_n].ipc_local, "%s%s%d", (char *)RTU_IPC_ITRC, prot, My_ID);
        sprintf(this->protocol_data[p_n].ipc_remote, "%s%s%d", (char *)RTU_IPC_MAIN, prot, My_ID);
        ipc_index_used_for_message_broker[p_n] = true;
        this->sockets_to_from_rtus_plcs_via_ipc[p_n] = IPC_DGram_Sock(this->protocol_data[p_n].ipc_local);
        std::cout << "Create IPC_DGram_Sock sockets_to_from_rtus_plcs_via_ipc[" << p_n << "]=" << this->sockets_to_from_rtus_plcs_via_ipc[p_n] << "\n";
    
        // Start the child process:
        std::stringstream process_path_strstream;
        process_path_strstream << "../" << prot << "/" << prot << "_master";
        std::string process_path = process_path_strstream.str();
        
        std::cout << "Starting message broker process"
                    << "# " << i << "/" << cJSON_GetArraySize(protocols)
                    << "\n";
        
        // child -- run program on path
        // Note 1: by convention, arg 0 is the prog name. Note 2: execv required this array to be NULL terminated.
        std::string caller = "proxy";
        std::string id = this->proxy_id;
        std::string spines_ip_port = "";
        spines_ip_port = spines_ip_port + this->spinesd_addr.ip_addr + std::to_string(this->spinesd_addr.port); // ip:port for spines daemon to use here (if we have multiple systems then there is one that is not used by those systems (its the one used by data collector etc). if we only have one system then it may be the same)
        std::string Num_RTU_Emulated = std::to_string(num_of_plc_rtus);
        char* child_proc_cmd[5] = { 
            const_cast<char*>(caller.c_str()), 
            const_cast<char*>(id.c_str()), 
            const_cast<char*>(spines_ip_port.c_str()),
            const_cast<char*>(Num_RTU_Emulated.c_str()),
            NULL
        };
        
        pid_t pid;
        this->mb_procs_pids.push_back(&pid);
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
void RTUsPLCsMessageBrokerManager::init_listen_thread(pthread_t &thread) {
    // The thread listens for command messages coming from the RTUs/PLCs and forwards it to the the io_processes (which then send it to their ITRC_Client). The thread also forwards it to the data collector

    // for pthread_create, we need a static member function. That adds some extra work (which is below). See IOProcManager::start_io_proc for more details on a similar case

    pthread_create(&thread, NULL, &RTUsPLCsMessageBrokerManager::listen_on_rtus_plcs_sock, (void *)this);
}
void* RTUsPLCsMessageBrokerManager::listen_on_rtus_plcs_sock(void *arg) {
    // Receives any messages. Send them to all I/O processes and the data collector
    RTUsPLCsMessageBrokerManager* this_class_object = (RTUsPLCsMessageBrokerManager*) arg;

    fd_set mask, tmask;
    int num;
    int nBytes;
    signed_message *mess;
    char buff[MAX_LEN];
    rtu_data_msg *rtud;
    seq_pair *ps;

    FD_ZERO(&mask);
    for(int i = 0; i < NUM_PROTOCOLS; i++) {
        if(this_class_object->ipc_index_used_for_message_broker[i]) {
            FD_SET(this_class_object->sockets_to_from_rtus_plcs_via_ipc[i], &mask);
            std::cout << "FD_SET on ipc_s["<< i << "]\n";
        }
    }

    while (true) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, NULL);
        if (num > 0) {
            for(int i = 0; i < NUM_PROTOCOLS; i++) {
                if (this_class_object->ipc_index_used_for_message_broker[i] != true) {
                    continue;
                }
                /* Message from a message broker */
                if (FD_ISSET(this_class_object->sockets_to_from_rtus_plcs_via_ipc[i], &tmask)) {
                    nBytes = IPC_Recv(this_class_object->sockets_to_from_rtus_plcs_via_ipc[i], buff, MAX_LEN);
                    mess = (signed_message *)buff;
                    mess->global_configuration_number = My_Global_Configuration_Number;
                    rtud = (rtu_data_msg *)(mess + 1);
                    ps = (seq_pair *)&rtud->seq;
                    ps->incarnation = My_Incarnation;

                    this_class_object->io_proc_manager->send_msg_to_all_procs(mess, nBytes);

                    // sending to data collector (this is a message that this proxy received from a rtu/plc and it is sending to SMs (via itrc client)):
                    this_class_object->dc_manager->send_to_dc(mess, nBytes, RTU_PROXY_RTU_DATA);
                }
            }
        }
    }

    return NULL;
}
int RTUsPLCsMessageBrokerManager::send(signed_message* mess, int nbytes) {
    int in_list, rtu_dst, channel;
    // char buffer[MAX_LEN];
    int ret = -1;

    rtu_dst = ((rtu_feedback_msg *)(mess + 1))->rtu;
    /* enqueue in correct ipc */
    in_list = key_value_get(rtu_dst, &channel);
    if(in_list) {
        int this_socket = this->sockets_to_from_rtus_plcs_via_ipc[channel];
        std::cout << "PROXY: Delivering msg to RTU channel " << channel << "at " << this_socket << "at path: " << this->protocol_data[channel].ipc_remote << "\n";
        ret = IPC_Send(this_socket, (void *)mess, nbytes, 
            this->protocol_data[channel].ipc_remote);
        if(ret != nbytes) {
            std::cout << "PROXY: error delivering to RTU\n";
        }
        else {
            std::cout << "PROXY: delivered to RTU\n";
        }
    }
    else {
        std::cout << "Error: Message from spines for rtu: " << rtu_dst << ", not my problem\n";
    }
    
    return ret;
}
void RTUsPLCsMessageBrokerManager::set_io_proc_man_ref(IOProcManager * io_proc_man) {
    this->io_proc_manager = io_proc_man;
    
}
void RTUsPLCsMessageBrokerManager::set_data_collector_man_ref(DataCollectorManager * dc_man) {
    this->dc_manager = dc_man;
}

// TODO remove. also remove the 3 relevant headers
void temp_test_switcher_msgs(std::string proxy_output) {
    // std::string data_file_path = "./switcher.txt";
    // std::time_t timestamp;
    // std::ofstream datafile;

    // datafile.open(data_file_path.c_str(), std::ios_base::app); // open in append mode
    // timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    // datafile << "=== New Entry ===\n";
    // datafile << "Time: " << std::ctime(&timestamp); 
    // datafile << "PROXY OUTPUT: " << proxy_output << "\n";    
    // datafile << "=== End Entry ===\n\n";
    // datafile.close();

    return;
}

SwitcherManager::SwitcherManager(InputArgs args, IOProcManager * io_proc_man, pthread_t &thread) {
    // check if there is a switcher in the system (if switcher addr is set to default vals then assume no)
    if (args.pipe_data.switcher_sock_addr.ip_addr == "" && args.pipe_data.switcher_sock_addr.port == -1) {
        this->no_switcher = true;
        return;
    }
    else {
        this->no_switcher = false;
    }

    this->mcast_addr = args.pipe_data.switcher_sock_addr;
    this->spinesd_addr = args.spinesd_sock_addr;
    this->io_proc_manager = io_proc_man;
    this->setup_switcher_socket();
    // pthread_create(&thread, NULL, &SwitcherManager::init_events_handler, (void *)this);
    SwitcherManager::init_events_handler((void *)this);
}
void SwitcherManager::setup_switcher_socket() {
    if (this->no_switcher)
        return;
    
    // set up the mcast socket:
    int retry_wait_sec = 2;
    int proto = SPINES_PRIORITY; // note that even though the option are `SPINES_RELIABLE` and `SPINES_PRIORITY`. Only `SPINES_PRIORITY` is compatible with mcast. the other one wont work
    while (true) {
        this->switcher_socket = Spines_Sock(this->spinesd_addr.ip_addr.c_str(), this->spinesd_addr.port, proto, this->mcast_addr.port);
        if (this->switcher_socket < 0 ) {
            std::cout << "Error setting the socket for the switcher. Trying again in " << retry_wait_sec << "sec\n";
            temp_test_switcher_msgs("Error setting the socket for the switcher. Trying again in ...");
            sleep(retry_wait_sec);
        }
        else {
            break;
        }
    }
    this->mcast_membership.imr_multiaddr.s_addr = inet_addr(this->mcast_addr.ip_addr.c_str());
    this->mcast_membership.imr_interface.s_addr = htonl(INADDR_ANY);
    if(spines_setsockopt(this->switcher_socket, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&this->mcast_membership, sizeof(this->mcast_membership)) < 0) {
        std::cout << "Mcast: problem in setsockopt to join multicast address";
        temp_test_switcher_msgs("Mcast: problem in setsockopt to join multicast address");
      }
    std::cout << "Mcast setup done\n";
    temp_test_switcher_msgs("Mcast setup done");
}
void* SwitcherManager::init_events_handler(void* arg) {
    SwitcherManager* this_class_object = (SwitcherManager*) arg;
    if (this_class_object->no_switcher)
        return NULL;

    // for E_attach_fd, we need a static member function. That adds some extra work (basically need to pass a refence to a specific class object which in this case since there is only one object of this class, 'this' should work just fine). See IOProcManager::start_io_proc for more details on a similar case
    temp_test_switcher_msgs("SwitcherManager::init_events_handler: before E_attach_fd");
    E_attach_fd(this_class_object->switcher_socket, READ_FD, SwitcherManager::handle_switcher_message, 0, (void *)this_class_object, MEDIUM_PRIORITY);
    temp_test_switcher_msgs("SwitcherManager::init_events_handler: after E_attach_fd");
    return NULL;
}
void SwitcherManager::handle_switcher_message(int sock, int code, void* data) {
    temp_test_switcher_msgs("SwitcherManager::handle_switcher_message: called");
    UNUSED(code);
    SwitcherManager * this_class_object = (SwitcherManager *) data;
    if (this_class_object->no_switcher)
        return;
    
    int ret;
    byte buff[this_class_object->switch_message_max_size];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    Switcher_Message * message;
    
    temp_test_switcher_msgs("SwitcherManager::handle_switcher_message: before spines_recvfrom()");
    ret = spines_recvfrom(sock, buff, this_class_object->switch_message_max_size, 0, (struct sockaddr *) &from_addr, &from_len);
    temp_test_switcher_msgs("SwitcherManager::handle_switcher_message: after spines_recvfrom()");
    if (ret < 0) {
        std::cout << "Switcher Message Handler: Error receving the message\n";
        temp_test_switcher_msgs("Switcher Message Handler: Error receving the message");
    }
    else {
        if ((unsigned long) ret < sizeof(Switcher_Message)){
            std::cout << "Switcher Message Handler: Error - The received message is smaller than expected\n";
            temp_test_switcher_msgs("Switcher Message Handler: Error - The received message is smaller than expected");
            return;
        }
        message = (Switcher_Message*) buff;
        std::cout << "Switcher Message Handler: Received a message.\n";    
        temp_test_switcher_msgs("Switcher Message Handler: Received a message.");
        // TODO: check that the message has correct values (i.e. ignore if e.g. is asks you to remove an io proc with an id that doesnt exist)
        // ignore if empty message
        if (message->new_active_system_id == "" && message->add_io_proc_path == "" && message->add_io_proc_spinesd_addr == "" && message->add_io_proc_id == "" && message->remove_io_proc_id == "") {
            std::cout << "Switcher Message Handler: message was empty. Ignored.\n";  
            temp_test_switcher_msgs("Switcher Message Handler: message was empty. Ignored.");  
            return;
        }

        // add a new io proc, if message has that info:
        // int ans = strcmp(str1, str2, ans); ans = 0 if str1==str.
        if (strcmp(message->add_io_proc_path, "") != 0 && strcmp(message->add_io_proc_spinesd_addr, "") != 0) {
            // if add_io_proc_id not provided then just use the path as the id
            std::string new_io_proc_id = (message->add_io_proc_id == ""? message->add_io_proc_path: message->add_io_proc_id);
            this_class_object->io_proc_manager->add_io_proc(new_io_proc_id, message->add_io_proc_path, parse_socket_address(message->add_io_proc_spinesd_addr));
            std::cout << "Switcher Message Handler: added a new I/O process. ID=" << new_io_proc_id << ", binary path=" << message->add_io_proc_path << "\n";  
            temp_test_switcher_msgs("Switcher Message Handler: added a new I/O process...");
        }
        
        // update the active system id, if message has that info:
        if (strcmp(message->new_active_system_id, "") != 0) {
            std::string new_id = message->new_active_system_id;
            this_class_object->io_proc_manager->update_active_system_id(new_id);
            std::cout << "Switcher Message Handler: Updated active system ID from `" << this_class_object->io_proc_manager->get_active_sys_id() << "` to `" << message->new_active_system_id << "`\n";
            temp_test_switcher_msgs("Switcher Message Handler: Updated active system ID from ...");
        }

        // remove an io proc, if message has that info:
        if (strcmp(message->remove_io_proc_id, "") != 0) {
            // this fn ignores the request if removing the currently active io proc:
            this_class_object->io_proc_manager->kill_io_proc(message->remove_io_proc_id);
            std::cout << "Switcher Message Handler: Killed I/O process with id `" << message->remove_io_proc_id << "`\n";
            temp_test_switcher_msgs("Switcher Message Handler: Killed I/O process with id ...");
        }
    }
    // TODO: forward received messages to the DC
    temp_test_switcher_msgs("SwitcherManager::handle_switcher_message: about to return.");
    return;
}

HMIManager::HMIManager() {
    // nothing here. initialized with `init` fn
    // doing it like this because ClientManager has a property for both RTUsPLCsMessageBrokerManager and HMIManager
    // but in a given proxy instance only one of them is used so this way we only run `init` for the one we are using
}
void HMIManager::init() {
    this->setup_ipc_for_hmi();
}
void HMIManager::setup_ipc_for_hmi() {
    this->sockets.from = IPC_DGram_Sock(HMI_IPC_HMIPROXY); // for HMI to HMI-side-proxy communication
    this->sockets.to = IPC_DGram_SendOnly_Sock(); // for HMI-side-proxy to HMI communication
}
void HMIManager::init_listen_thread() {
    // The thread listens for command messages coming from the HMI and forwards it to the the io_processes (which then send it to their ITRC_Client). The thread also forwards it to the data collector
    
    // for E_attach_fd, we need a static member function. That adds some extra work (basically need to pass a refence to a specific class object which in this case since there is only one object of this class, 'this' should work just fine). See IOProcManager::start_io_proc for more details on a similar case
    E_attach_fd(this->sockets.from, READ_FD, HMIManager::listen_on_hmi_sock, 0, (void *)this, MEDIUM_PRIORITY);
}
void HMIManager::listen_on_hmi_sock(int sock, int code, void *data) {
    // Receives any messages. Send them to all I/O processes and the data collector
    HMIManager* this_class_object = (HMIManager*) data;
    UNUSED(code);

    int ret; 
    char buf[MAX_LEN];
    signed_message *mess;
    int nbytes;

    std::cout << "Receiving something on the HMI socket\n";
    ret = IPC_Recv(sock, buf, MAX_LEN);
    if (ret < 0) {
        std::cout << "HMI-proxy: IPC_Rev failed. ret = " << ret << "\n";
    }
    else {
        std::cout << "Received a message from the HMI. ret = " << ret << "\n";
        mess = (signed_message *)buf;
        nbytes = sizeof(signed_message) + mess->len;
        
        this_class_object->io_proc_manager->send_msg_to_all_procs(mess, nbytes);

        this_class_object->dc_manager->send_to_dc(mess, nbytes, HMI_PROXY_HMI_CMD);
    }
}
int HMIManager::send(signed_message* mess, int nbytes) {
    return IPC_Send(this->sockets.to, (void*) mess, nbytes, HMIPROXY_IPC_HMI);
}
void HMIManager::set_io_proc_man_ref(IOProcManager * io_proc_man) {
    this->io_proc_manager = io_proc_man;
}
void HMIManager::set_data_collector_man_ref(DataCollectorManager * dc_man) {
    this->dc_manager = dc_man;
}

void process_config_msg(signed_message * conf_mess, int mess_size) {
    std::cout << "TODO\n";
    exit(EXIT_FAILURE);
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


// // used by my_Spines_Sock (defined right below this fn)
// int my_Spines_SendOnly_Sock(const char *sp_addr, int sp_port, int proto) 
// {
//     int sk, ret, protocol;
//     struct sockaddr_in spines_addr;
//     struct sockaddr_un spines_uaddr;
//     int16u prio, kpaths;
//     spines_nettime exp;

//     memset(&spines_addr, 0, sizeof(spines_addr));

//     printf("Initiating Spines connection: %s:%d\n", sp_addr, sp_port);
//     spines_addr.sin_family = AF_INET;
//     spines_addr.sin_port   = htons(sp_port);
//     spines_addr.sin_addr.s_addr = inet_addr(sp_addr);

//     spines_uaddr.sun_family = AF_UNIX;
//     sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", sp_port);

//     protocol = 8 | (proto << 8);

//     /* printf("Creating IPC spines_socket\n");
//     sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr); */
   
//     if ((int)inet_addr(sp_addr) == My_IP) {
//         printf("Creating default spines_socket\n");
//         sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr);
//     }
//     else {
//         printf("Creating inet spines_socket\n");
//         sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
//                 (struct sockaddr *)&spines_addr);
//     }
//     if (sk < 0) {
//         perror("Spines_Sock: error creating spines socket!");
//         return sk;
//     }

//     /* setup kpaths = 1 */
//     kpaths = 1;
//     if ((ret = spines_setsockopt(sk, 0, SPINES_DISJOINT_PATHS, (void *)&kpaths, sizeof(int16u))) < 0) {
//         printf("Spines_Sock: spines_setsockopt failed for disjoint paths = %u\n", kpaths);
//         return ret;
//     }

//     /* setup priority level and garbage collection settings for Priority Messaging */
//     prio = SCADA_PRIORITY;
//     exp.sec  = 5;
//     exp.usec = 0;

//     if (proto == SPINES_PRIORITY) {
//         if ((ret = spines_setsockopt(sk, 0, SPINES_SET_EXPIRATION, (void *)&exp, sizeof(spines_nettime))) < 0) {
//             printf("Spines_Sock: error setting expiration time to %u sec %u usec\n", exp.sec, exp.usec);
//             return ret;
//         }

//         if ((ret = spines_setsockopt(sk, 0, SPINES_SET_PRIORITY, (void *)&prio, sizeof(int16u))) < 0) {
//             printf("Spines_Sock: error setting priority to %u\n", prio);
//             return ret;
//         }
//     }

//     return sk;
// }

// // the `Spines_Sock` function from net_wrapper.c uses some spire-specific macro defines (SPINES_INT_PORT & SPINES_EXT_PORT) and i would need to make some changes there or somewhere else to allow having a management network. so i adapt the function here
// int my_Spines_Sock(const char *sp_addr, int sp_port, int proto, int my_port) 
// {
//     int sk, ret;
//     struct sockaddr_in my_addr;
    
//     sk = my_Spines_SendOnly_Sock(sp_addr, sp_port, proto);
//     if (sk < 0) {
//         perror("Spines_Sock: failure to connect to spines");
//         return sk;
//     }

//     memset(&my_addr, 0, sizeof(my_addr));
//     my_addr.sin_family = AF_INET;
//     my_addr.sin_addr.s_addr = My_IP;
//     my_addr.sin_port = htons(my_port);

//     ret = spines_bind(sk, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in));
//     if (ret < 0) {
//         perror("Spines_Sock: bind error!");
//         return ret;
//     }

//     return sk;
// }