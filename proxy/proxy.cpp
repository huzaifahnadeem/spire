#include "proxy.h"

int main(int ac, char **av) {
    // the constructor reads input args and store the data in the data structures:
    InputArgs args(ac, av);

    // set up the data collector manager
    DataCollectorManager data_collector_manager(args.pipe_data.data_collector_sock_addr, args.spinesd_sock_addr);
    
    // Initializes message broker processes and sets up sockets
    RTUsPLCsMessageBrokerManager rtuplc_manager(args);

    // set up I/O Processes Manager
    IOProcManager io_proc_manager(args, &data_collector_manager, &rtuplc_manager);

    // Initialize the thread that listens to the incoming messages from the RTUs/PLCs
    pthread_t rtus_plcs_listen_thread;
    rtuplc_manager.set_io_proc_man_ref(&io_proc_manager); // so that the rtu/plc manager can send messages to the IO processes
    rtuplc_manager.set_data_collector_man_ref(&data_collector_manager); // so that the rtu/plc manager can send messages to the data collector
    rtuplc_manager.init_listen_thread(rtus_plcs_listen_thread);

    // fork all the io processes
    io_proc_manager.start_all_io_procs();

    // sets up socket for the switcher messages and handle events:
    SwitcherManager switcher_manager(args, &io_proc_manager);

    // wait for any threads before exiting
    pthread_join(rtus_plcs_listen_thread, NULL);
    return EXIT_SUCCESS;
}

IOProcManager::IOProcManager(InputArgs args, DataCollectorManager * data_collector_manager, RTUsPLCsMessageBrokerManager * rtuplc_man) {
    // TODO: maybe this needs to be done in a thread
    this->proxy_id = args.proxy_id;
    this->data_collector_manager = data_collector_manager;
    this->rtuplc_manager = rtuplc_man;

    // add IO Procs
    if (args.pipe_name == "" && args.pipe_data.systems_data.size() == 0) {
        // this means running with just a single system (no twins)
        std::string sys_id = "0"; // arbitrary
        std::string path = DEFAULT_IO_PROCESS_PATH;
        this->add_io_proc(sys_id, path, args.spinesd_sock_addr);
    }
    else {
        // running with twins
        for (auto & this_system : args.pipe_data.systems_data) {
            this->add_io_proc(this_system.id, this_system.binary_path, this_system.spinesd_sock_addr);
        }
    }

    E_init(); // initialize libspread events handler
    E_handle_events(); // will attach events later when IO processes are started
}
void IOProcManager::add_io_proc(std::string id, std::string bin_path, SocketAddress spines_address) {
    // add the data for a new io_proc (doesn't fork the process, though)
    IOProcess this_io_proc;
    this_io_proc.io_binary_path = bin_path;
    this_io_proc.spines_addr = spines_address;
    
    this_io_proc.sockets.to = IPC_DGram_SendOnly_Sock(); // for sending something TO the child process (child being the IO Process)
    this_io_proc.sockets.from = IPC_DGram_Sock((IPC_FROM_IOPROC_CHILD + id).c_str()); // for receiving something FROM the child process (child being the IO Process)

    this->io_procs.insert({id, this_io_proc});
}
void IOProcManager::start_io_proc(std::string id) {
    // for the given id, this function forks a process to run that. It also sets up the message handler for any messages received from this process
    this->fork_io_proc(io_procs[id], id);
    E_attach_fd(io_procs[id].sockets.from, READ_FD, this->io_proc_message_handler, 0, (void*)&id, MEDIUM_PRIORITY); 
    // E_handle_events(); // confirm if this needs to be called again
}
void IOProcManager::fork_io_proc(IOProcess &io_proc, std::string id) {
    // child -- run program on path
    // Note 1: by convention, arg 0 is the prog name. Note 2: execv required this array to be NULL terminated.
    char* child_proc_cmd[6] = { 
        const_cast<char*>(io_proc.io_binary_path.c_str()), 
        const_cast<char*>(io_proc.spines_addr.ip_addr.c_str()), 
        const_cast<char*>(std::to_string(io_proc.spines_addr.port).c_str()),
        const_cast<char*>(id.c_str()),
        const_cast<char*>(this->proxy_id.c_str()),
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
void IOProcManager::kill_io_proc(std::string id) { // TODO: what if the active system is killed?
    // kills the process and lets the event handler know it should no longer listen for any messages
    IOProcess this_io_proc = io_procs[id];
    kill(this_io_proc.pid, SIGTERM); // TODO: what kind of signal should i send?
    E_detach_fd(this->io_procs[id].sockets.from, READ_FD); // tell the event handler that it no longer needs to handle for this socket
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
    std::string message_is_from = * (std::string *) data;

    int ret; 
    int nbytes;
    char buffer[MAX_LEN];
    signed_message *mess;

    std::cout << "There is a message from system " << message_is_from << ":\n";

    // Receive the message on the socket
    ret = IPC_Recv(sock, buffer, MAX_LEN);
    if (ret < 0) std::cout << "I/O process message handler for system " << message_is_from << ": IPC_Rev failed.\n";
    mess = (signed_message *)buffer;
    nbytes = sizeof(signed_message) + mess->len;

    // Special Processing for reconfiguration message
    if(mess->type ==  PRIME_OOB_CONFIG_MSG) {
        std::cout << "PROXY: processing OOB CONFIG MESSAGE\n";
        process_config_msg((signed_message *)buffer, ret);
    }
    
    // If the message is from the active system, send to the the message broker (modbus/dnp3 process) for sending further down to the RTUs/PLCs:
    if (message_is_from == this->active_sys_id) {
        int in_list, rtu_dst, channel, ret2;

        rtu_dst = ((rtu_feedback_msg *)(mess + 1))->rtu;
        /* enqueue in correct ipc */
        in_list = key_value_get(rtu_dst, &channel);
        if(in_list) {
            int this_socket = this->rtuplc_manager->sockets_to_from_rtus_plcs_via_ipc[channel];
            std::cout << "PROXY: Delivering msg to RTU channel " << channel << "at " << this_socket << "at path: " << this->rtuplc_manager->protocol_data[channel].ipc_remote << "\n";
            ret2 = IPC_Send(this_socket, buffer, nbytes, 
                        this->rtuplc_manager->protocol_data[channel].ipc_remote);
            if(ret2 != nbytes) {
                std::cout << "PROXY: error delivering to RTU\n";
            }
            else {
                std::cout << "PROXY: delivered to RTU\n";
            }
        }
        else {
            std::cout << "Error: Message from spines for rtu: " << rtu_dst << ", not my problem\n";
        }

        std::cout << "I/O process message handler for process # " << message_is_from << ": " << "The message has been forwarded to the RTUs/PLCs\n";
    }

    
    // Forward to the Data Collector: (the dc manager will figure out whether or there is a data collector to send to or not)
    this->data_collector_manager->send_to_dc(mess, nbytes, message_is_from == this->active_sys_id? RTU_PROXY_MAIN_MSG: RTU_PROXY_SHADOW_MSG);
}
void IOProcManager::send_msg_to_all_procs(signed_message *msg, int nbytes) {
    int ret;
    for (auto & [id, this_io_proc]: this->io_procs) {
        std::cout << "PROXY: message from plc, sending data to SM with system ID " << id << "\n";
        int this_sock = this_io_proc.sockets.to;
        std::string this_path_suffix = id;
        ret = IPC_Send(this_sock, (void *)msg, nbytes, (IPC_TO_IOPROC_CHILD + this_path_suffix).c_str());
        if(ret != nbytes) {
            std::cout << "PROXY: error sending to SM with system ID "<< id << ". ret = " << ret << "\n";
        }
        else {
            std::cout << "PROXY: message sent successfully to SM with system ID "<< id << ". ret = " << ret << "\n";
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

InputArgs::InputArgs(int ac, char **av) {
    this->parse_args(ac, av);
}
void InputArgs::print_usage() {
    std::cout 
        << "Invalid args\n" 
        << "Usage: ./proxy proxyID spinesAddr:spinesPort Num_PLC_RTU [named pipe name or file name to use multiple systems]\n" 
        << "\nIf you want to run with shadow/twin systems: for the last (optional) argument, provide the name of a named pipe or a text file to read on for the details of the other systems and information about the data collector.\n" 
        << "For this named pipe/file, this program will expect the first line to be: \n"
        << "`active_system_id`<space>`dataCollectorIPAddr:dataCollectorPort`<space>`switcherIPAddr:switcherPort`\n"
        << "active_system_id is a string that is specified for each system (see below).\n"
        << "The next argument in the first line is `dataCollectorIPAddr:dataCollectorPort`. Use this to specify the data collector's IP address and port. If for some reason you do not want to use a data collector you skip this by putting a colon in this argument's place i.e. `:`.\n"
        << "The next argument in the first line `switcherIPAddr:switcherPort` is used to specify the Multicast IP address and the port that the switcher will be using. If, for some reason, you do not need the switcher, put a colon in this argument's place i.e. `:`.\n"
        << "2nd line and onwards are expected to be like: \n"
        << "/path/to/io_process_to_use SpinesDaemonIPAddr:SpinesDaemonPort System_ID\n" 
        << "The IP address and port are of the spines daemon that is to be used for communication with this system.\n"
        << "Lastly, note that if the named pipe/file argument is provided, then the ip address and port provided in the command line arguments are going to be used as IP address and port for the spines daemon that is to be used for the communication with the data collector and the switcher.\n";
             
        exit(EXIT_FAILURE);
}
void InputArgs::parse_args(int ac, char **av) {
    // TODO make a better parse fn

    if (!(ac == 4 || ac == 5)) {
        this->print_usage();
    }

    this->proxy_id = av[1];
    this->spinesd_sock_addr = parse_socket_address(av[2]);
    this->num_of_plc_rtus = atoi(av[3]);

    if (ac == 5) {
        // optional arg (i.e named pipe for twins, etc) provided
        this->pipe_name = av[4];
        this->read_named_pipe(pipe_name);
    }
    else {
        this->pipe_name = "";
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
            if (dc_addr != ":")
                this->pipe_data.data_collector_sock_addr = parse_socket_address(dc_addr);

            // switcher mcast address:
            std::string switcher_addr = strtok(NULL, " ");
            if (switcher_addr != ":")
                this->pipe_data.switcher_sock_addr = parse_socket_address(switcher_addr);
        }
        else {
            SystemsData this_systems_data;
            
            // io_proc binary to use:
            this_systems_data.binary_path = strtok(line_cstr, " ");

            // spines ip addr and port to use with this io_process:
            std::string sp_addr = strtok(NULL, " ");
            this_systems_data.spinesd_sock_addr = parse_socket_address(sp_addr);
                        
            // id for this system
            this_systems_data.id = strtok(NULL, " ");

            // save:
            this->pipe_data.systems_data.push_back(this_systems_data);
        }

        free(line_cstr);
    }
}

void parse_socket_address(std::string ipaddr_colon_port, std::string &ipaddr, int &port) {
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
void DataCollectorManager::send_to_dc(signed_message *msg, int nbytes, int data_stream_id) {
    if (this->no_data_collector)
        return;

    int ret;
    std::cout << "Forwarding a message to the data collector\n";
    
    DataCollectorPacket data_packet;
    data_packet.data_stream = data_stream_id;
    data_packet.system_message = *msg;
    data_packet.nbytes_mess = nbytes;
    data_packet.nbytes_struct = sizeof(signed_message) + msg->len + 3*sizeof(int);

    ret = spines_sendto(this->spinesd_socket, (void *)&data_packet, data_packet.nbytes_struct, 0, (struct sockaddr *)&this->dc_sockaddr_in, sizeof(struct sockaddr));
    std::cout << "Sent to data collector with return code ret = " << ret << "\n";
}

RTUsPLCsMessageBrokerManager::RTUsPLCsMessageBrokerManager(InputArgs args) {
    this->proxy_id = args.proxy_id;
    this->num_of_plc_rtus = args.num_of_plc_rtus;
    this->spinesd_addr = args.spinesd_sock_addr;
    this->init_message_broker_processes_and_sockets();
}
void RTUsPLCsMessageBrokerManager::set_io_proc_man_ref(IOProcManager * io_proc_man) {
    this->io_proc_manager = io_proc_man;
}
void RTUsPLCsMessageBrokerManager::set_data_collector_man_ref(DataCollectorManager * dc_man) {
    this->dc_manager = dc_man;
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
    pthread_create(&thread, NULL, this->listen_on_rtus_plcs_sock, NULL);
}
void * RTUsPLCsMessageBrokerManager::listen_on_rtus_plcs_sock(void *arg) {
    // Receives any messages. Send them to all I/O processes
    UNUSED(arg);

    fd_set mask, tmask;
    int num;
    int nBytes;
    signed_message *mess;
    char buff[MAX_LEN];
    rtu_data_msg *rtud;
    seq_pair *ps;

    FD_ZERO(&mask);
    for(int i = 0; i < NUM_PROTOCOLS; i++) {
        if(this->ipc_index_used_for_message_broker[i]) {
            FD_SET(this->sockets_to_from_rtus_plcs_via_ipc[i], &mask);
            std::cout << "FD_SET on ipc_s["<< i << "]\n";
        }
    }

    while (true) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, NULL);
        if (num > 0) {
            for(int i = 0; i < NUM_PROTOCOLS; i++) {
                if (this->ipc_index_used_for_message_broker[i] != true) {
                    continue;
                }
                /* Message from a message broker */
                if (FD_ISSET(this->sockets_to_from_rtus_plcs_via_ipc[i], &tmask)) {
                    nBytes = IPC_Recv(this->sockets_to_from_rtus_plcs_via_ipc[i], buff, MAX_LEN);
                    mess = (signed_message *)buff;
                    mess->global_configuration_number = My_Global_Configuration_Number;
                    rtud = (rtu_data_msg *)(mess + 1);
                    ps = (seq_pair *)&rtud->seq;
                    ps->incarnation = My_Incarnation;

                    this->io_proc_manager->send_msg_to_all_procs(mess, nBytes);

                    // sending to data collector (this is a message that this proxy received from a rtu/plc and it is sending to SMs (via itrc client)):
                    this->dc_manager->send_to_dc(mess, nBytes, RTU_PROXY_RTU_DATA);
                }
            }
        }
    }

    return NULL;
}

SwitcherManager::SwitcherManager(InputArgs args, IOProcManager * io_proc_man) {
    this->mcast_addr = args.pipe_data.switcher_sock_addr;
    this->spinesd_addr = args.spinesd_sock_addr;
    this->io_proc_manager = io_proc_man;
    this->setup_switcher_connection();
}
void SwitcherManager::setup_switcher_connection() {
    // set up the mcast socket:
    int retry_wait_sec = 2;
    int proto = SPINES_RELIABLE; // options: SPINES_RELIABLE and SPINES_PRIORITY
    while (true) {
        this->switcher_socket = Spines_Sock(this->spinesd_addr.ip_addr.c_str(), this->spinesd_addr.port, proto, this->mcast_addr.port);
        if (this->switcher_socket < 0 ) {
            std::cout << "Error setting the socket for the switcher. Trying again in " << retry_wait_sec << "sec\n";
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
      }
    std::cout << "Mcast setup done\n";

    // set up an event handler for the switcher's messages
    E_init();
    E_attach_fd(this->switcher_socket, READ_FD, this->handle_switcher_message, 0, NULL, HIGH_PRIORITY);
    E_handle_events();
}
void SwitcherManager::handle_switcher_message(int sock, int code, void* data) {
    UNUSED(code);
    UNUSED(data);
    
    int ret;
    byte buff[this->switch_message_max_size];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    Switcher_Message * message;
    
    ret = spines_recvfrom(sock, buff, this->switch_message_max_size, 0, (struct sockaddr *) &from_addr, &from_len);
    if (ret < 0) {
        std::cout << "Switcher Message Handler: Error receving the message\n";
    }
    else {
        if ((unsigned long) ret < sizeof(Switcher_Message)){
            std::cout << "Switcher Message Handler: Error - The received message is smaller than expected\n";
            return;
        }
        message = (Switcher_Message*) buff;
        this->io_proc_manager->update_active_system_id(message->new_active_system_id);
    }
    // TODO: forward received messages to the DC
    return;
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
