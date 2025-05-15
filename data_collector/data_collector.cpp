#include "data_collector.h"

const std::string default_logs_path = "./logs/";
std::string log_files_dir;
std::unordered_map<std::string, std::string> log_files_map;

int main(int ac, char **av) {
    std::string spinesd_ip_addr; // for spines daemon
    int spinesd_port;
    int my_port; // the port this data collector receives messages on
    std::string mcast_sock_addr;

    parse_args(ac, av, spinesd_ip_addr, spinesd_port, my_port, log_files_dir, mcast_sock_addr);

    struct mcast_connection mcast_conn;
    set_up_mcast_sock(spinesd_ip_addr, spinesd_port, mcast_sock_addr, mcast_conn);
    pthread_t mcast_handler_thread;
    pthread_create(&mcast_handler_thread, NULL, &listen_on_mcast_sock, (void *) &mcast_conn);

    // set up spines sock for proxy messages:
    int proto, spines_sock, num, ret;
    struct timeval spines_timeout, *t;
    fd_set mask, tmask;
    char buff[MAX_LEN];

    FD_ZERO(&mask);
    proto = SPINES_RELIABLE; // need to use SPINES_RELIABLE and not SPINES_PRIORITY. This is because we need to be sure the message is delivered. SPINES_PRIORITY can drop messages. might need to think more though (but thats for later)
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
     *  this often */
    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;

    spines_sock = -1; // -1 is not a real socket so init to that
    spines_sock = Spines_Sock(spinesd_ip_addr.c_str(), spinesd_port, proto, my_port);
    if (spines_sock < 0) {
        std::cout << "data_collector: Unable to connect to Spines, trying again soon\n";
        t = &spines_timeout; 
    }
    else {
        std::cout << "data_collector: Connected to Spines\n";
        FD_SET(spines_sock, &mask);
        t = NULL;
    }

    // handle proxy messages:
    while (1) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);
        if (num > 0) {
            /* Message from Spines */
            if (spines_sock >= 0 && FD_ISSET(spines_sock, &tmask)) {
                // spines_recv does not give a way to find out the sender's address
                // ret = spines_recv(spines_sock, buff, MAX_LEN, 0);
                // so, instead we are using spines_recvfrom:
                struct sockaddr_in sender_addr;
                socklen_t sender_addr_structlen = sizeof(sender_addr); 
                ret = spines_recvfrom(spines_sock, buff, MAX_LEN, 0, (struct sockaddr *) &sender_addr, &sender_addr_structlen);
                if (ret <= 0) {
                    std::cout << "data_collector: Error in spines_recvfrom with spines_sock>0 and : ret = " << ret << "dropping!\n";
                    spines_close(spines_sock);
                    FD_CLR(spines_sock, &mask);
                    spines_sock = -1;
                    t = &spines_timeout; 
                    continue;
                }
                std::cout << "data_collector: Received some data from spines daemon\n";

                std::string sender_ipaddr;
                int sender_port;
                sockaddr_in_to_str(&sender_addr, &sender_addr_structlen, sender_ipaddr, sender_port);
                // write_data(log_files_dir, (signed_message *)buff, sender_ipaddr, sender_port);
                write_data(log_files_dir, (DataCollectorPacket *)buff, sender_ipaddr, sender_port);
                std::cout << "data_collector: Data has been written to disk\n";
            }
        }
        else {
            // this happens when we havent connected to spire. so try again: // TODO: does this actually happen?
            spines_sock = Spines_Sock(spinesd_ip_addr.c_str(), spinesd_port, proto, my_port);
            if (spines_sock < 0) {
                std::cout << "data_collector: Unable to connect to Spines, trying again soon\n";
                spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                t = &spines_timeout; 
            }
            else {
                std::cout << "data_collector: Connected to Spines\n";
                FD_SET(spines_sock, &mask);
                t = NULL;
            }
        }
    }

    pthread_join(mcast_handler_thread, NULL);
    return EXIT_SUCCESS;
}

void usage_check(int ac, char **av) {
    if (ac != 5) {
        printf("Invalid args\n");
        printf("Usage: %s spinesAddr:spinesPort dataCollectorPort mcastAddr:mcastPort logs_directory\nTo ignore mcastAddr:mcastPort arg, just enter ':' in its place. To use the default logs_directory (./logs/), enter '%' in its place\n", av[0]);
        exit(EXIT_FAILURE);
    }
}

void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, int &my_port, std::string &log_files_dir, std::string &mcast_sock_addr) {
    usage_check(ac, av);

    int colon_pos;
    std::string spinesd_arg = av[1];
    std::string my_port_arg = av[2];
    
    // spines daemon address and port:
    colon_pos = -1;
    colon_pos = spinesd_arg.find(':');
    spinesd_ip_addr = spinesd_arg.substr(0, colon_pos);
    spinesd_port = std::stoi(spinesd_arg.substr(colon_pos + 1));

    // data collector (my) port:
    my_port = std::stoi(my_port_arg);

    // mcast address (to receive the switcher's messages on):
    mcast_sock_addr = av[3];

    // data file:
    log_files_dir = av[4];
    if (log_files_dir == "%") {
        // use the default path
        log_files_dir = default_logs_path;
    }
    else {
        log_files_dir = log_files_dir + "/"; // just to make sure the forward slash is there at the end of the path (note that >1 slashes is fine, system ignores those)
    }
    // create directory (including parent directories) if they do not exist
    std::error_code err;
    if (!CreateDirectoryRecursive(log_files_dir, err))
    {
        std::cout << "Error creating the directory '" << log_files_dir <<"'\n";
        std::cout << "CreateDirectoryRecursive FAILED, err: " << err.message() << std::endl;
        exit(EXIT_FAILURE);
    }
}

bool CreateDirectoryRecursive(std::string const & dirName, std::error_code & err) // source: https://stackoverflow.com/questions/71658440/c17-create-directories-automatically-given-a-file-path/71659205
// Returns:
//   true upon success.
//   false upon failure, and set the std::error_code & err accordingly.
{
    err.clear();
    if (!std::filesystem::create_directories(dirName, err))
    {
        if (std::filesystem::exists(dirName))
        {
            // The folder already exists:
            err.clear();
            return true;    
        }
        return false;
    }
    return true;
}

void write_data_yaml(std::string log_files_dir, struct DataCollectorPacket * data_packet, std::string sender_ipaddr, int sender_port) {
    // note that log_files_dir can have whatever file extension. It doesnt matter. We are writing a text file that can be interpretted as a yaml file (and yaml files are easier to read for humans too so should also serve as a decent text file)
    
    const std::string ind = "  "; // Indentation for the yaml file structure. using 2 spaces which i believe is the recommeded indentation for yaml (however, any number should be fine as long as we are consistent) (note that yaml hates tabs so use this everywhere)

    std::string system_id = data_packet->sys_id;
    signed_message *data = &data_packet->system_message;
    
    // time related stuff for file names and keys in the yaml file.
    auto now = std::chrono::system_clock::now();
    auto time_since_epoch = now.time_since_epoch();
    auto microsec_since_epoch = std::chrono::duration_cast<std::chrono::microseconds>(time_since_epoch).count();
    std::time_t timestamp;
    timestamp = std::chrono::system_clock::to_time_t(now);
    std::string ts = std::ctime(&timestamp);
    std::string ts_wo_newline = ts.substr(0, ts.find('\n'));    
    
    // find the file for this system_id if it was previously created. otherwise create it and put it in log_files_map to keep track of it
    std::string file_name;
    auto found_val = log_files_map.find(system_id);
    if (found_val != log_files_map.end()) {
        // key (id) exists. so a file for this system id was previously created. use that
        file_name = log_files_map[system_id];
    } 
    else {
        std::stringstream strstream_file_name;
        strstream_file_name << system_id << "_" << microsec_since_epoch << ".yaml";
        file_name = strstream_file_name.str();
        log_files_map[system_id] = file_name;
    }
    std::ofstream datafile;
    datafile.open((log_files_dir + file_name).c_str(), std::ios_base::app); // open in append mode
    datafile << "# === New Entry ===\n"; // a yaml comment

    datafile << microsec_since_epoch << ":\n"; // each new entry is a dict with timestamp (when the data collector writes this entry) as the root key. timestamp is microseconds since epoch (if we use seconds then the keys are occasionally not unique. with microseconds they are oftern 2-3 microsec apart so just to be safe, this microsec should definitely give us unique keys. if not we can add a usleep() at the end of this function to force some time between entries)

    datafile << ind << "Timestamp: '"<< ts_wo_newline << "'\n"; // human-readable timestamp
    
    datafile << ind << "from:\n";
    datafile << ind << ind << "IP_address: " << sender_ipaddr << "\n";
    datafile << ind << ind << "port: " << sender_port << "\n";

    std::string data_stream_str;
    switch (data_packet->data_stream) {
        case RTU_PROXY_MAIN_MSG:
            data_stream_str = "RTU_PROXY_MAIN_MSG";
            break;
        case RTU_PROXY_SHADOW_MSG:
            data_stream_str = "RTU_PROXY_SHADOW_MSG";
            break;
        case RTU_PROXY_RTU_DATA:
            data_stream_str = "RTU_PROXY_RTU_DATA";
            break;
        case HMI_PROXY_MAIN_MSG:
            data_stream_str = "HMI_PROXY_MAIN_MSG";
            break;
        case HMI_PROXY_SHADOW_MSG:
            data_stream_str = "HMI_PROXY_SHADOW_MSG";
            break;
        case HMI_PROXY_HMI_CMD:
            data_stream_str = "HMI_PROXY_HMI_CMD";
            break;
        default:
            "unknown_data_stream";
    }
    datafile << ind << "data_stream: " << data_stream_str << "\n";

    std::string msg_type_str;
    switch (data->type) {
    case HMI_COMMAND:
        msg_type_str = "HMI_COMMAND";
        break;
    case HMI_UPDATE:
        msg_type_str = "HMI_UPDATE";
        break;
    case PRIME_OOB_CONFIG_MSG:
        msg_type_str = "PRIME_OOB_CONFIG_MSG";
        break;
    case RTU_FEEDBACK:
        msg_type_str = "RTU_FEEDBACK";
        break;
    case RTU_DATA:
        msg_type_str = "RTU_DATA";
        break;
    default:
        "unknown_type";
    }

    datafile << ind << "data: \n";
    datafile << ind << ind << "sig: '<";
    for (int i = 0; i < SIGNATURE_SIZE; i++) {
        datafile << (int)data->sig[i] << "";
    }
    datafile << ">'\n";

    datafile << ind << ind << "mt_num: "                      << data->mt_num << "\n";
    datafile << ind << ind << "mt_index: "                    << data->mt_index << "\n";
    datafile << ind << ind << "site_id: "                     << data->site_id << "\n";
    datafile << ind << ind << "machine_id: "                  << data->machine_id << "\n";
    datafile << ind << ind << "len: "                         << data->len << "\n";
    datafile << ind << ind << "type_(enum_val): "             << data->type << "\n";
    datafile << ind << ind << "type_(enum_str): "             << msg_type_str << "\n";
    datafile << ind << ind << "incarnation: "                 << data->incarnation << "\n";
    datafile << ind << ind << "monotonic_counter: "           << data->monotonic_counter << "\n";
    datafile << ind << ind << "global_configuration_number: " << data->global_configuration_number << "\n";

    datafile << ind << ind << "message_content:\n";

    if (data->type == HMI_COMMAND) { // This type is SENT BY the HMI
        hmi_command_msg * msg_content = NULL;
        msg_content = (hmi_command_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << ind << ind << ind << "seq:\n";
        datafile << ind << ind << ind << ind << "incarnation: " << msg_content_seq.incarnation << "\n";
        datafile << ind << ind << ind << ind << "seq_num: "     << msg_content_seq.seq_num << "\n";
        datafile << ind << ind << ind << "hmi_id: "             << msg_content->hmi_id << "\n";
        datafile << ind << ind << ind << "scen_type: "          << msg_content->scen_type << "\n";
        datafile << ind << ind << ind << "type: "               << msg_content->type << "\n";
        datafile << ind << ind << ind << "ttip_pos: "           << msg_content->ttip_pos << "\n";
    }
    else if (data->type == HMI_UPDATE) { // This type is RECEIVED BY the HMI-side Proxy
        hmi_update_msg * msg_content = NULL;
        msg_content = (hmi_update_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << ind << ind << ind << "seq:\n";
        datafile << ind << ind << ind << ind << "incarnation: " << msg_content_seq.incarnation << "\n";
        datafile << ind << ind << ind << ind << "seq_num: "     << msg_content_seq.seq_num << "\n";
        datafile << ind << ind << ind << "scen_type: "          << msg_content->scen_type << "\n";
        datafile << ind << ind << ind << "sec: "                << msg_content->sec << "\n";
        datafile << ind << ind << ind << "usec: "               << msg_content->usec << "\n";
        datafile << ind << ind << ind << "len: "                << msg_content->len << "\n";
    }
    else if (data->type == PRIME_OOB_CONFIG_MSG) { // This type is RECEIVED BY the HMI-side Proxy & the RTU/PLC-side Proxy (from ITRC)
        config_message * msg_content = NULL;
        msg_content = (config_message *)(data + 1);
        datafile << ind << ind << ind << "N: "                    << msg_content->N << "\n";
        datafile << ind << ind << ind << "f: "                    << msg_content->f << "\n";
        datafile << ind << ind << ind << "k: "                    << msg_content->k << "\n";
        datafile << ind << ind << ind << "num_sites: "            << msg_content->num_sites << "\n";
        datafile << ind << ind << ind << "num_cc: "               << msg_content->num_cc << "\n";
        datafile << ind << ind << ind << "num_dc: "               << msg_content->num_dc << "\n";
        datafile << ind << ind << ind << "num_cc_replicas: "      << msg_content->num_cc_replicas << "\n";
        datafile << ind << ind << ind << "num_dc_replicas: "      << msg_content->num_dc_replicas << "\n";
        datafile << ind << ind << ind << "tpm_based_id: "         << msg_content->tpm_based_id << "\n";
        datafile << ind << ind << ind << "replica_flag: "         << msg_content->replica_flag << "\n";
        datafile << ind << ind << ind << "sm_addresses: "         << msg_content->sm_addresses << "\n";
        datafile << ind << ind << ind << "spines_ext_addresses: " << msg_content->spines_ext_addresses << "\n";
        datafile << ind << ind << ind << "spines_ext_port: "      << msg_content->spines_ext_port << "\n";
        datafile << ind << ind << ind << "spines_int_addresses: " << msg_content->spines_int_addresses << "\n";
        datafile << ind << ind << ind << "spines_int_port: "      << msg_content->spines_int_port << "\n";
        datafile << ind << ind << ind << "prime_addresses: "      << msg_content->prime_addresses << "\n";
        datafile << ind << ind << ind << "initial_state: "        << msg_content->initial_state << "\n";
        datafile << ind << ind << ind << "initial_state_digest: " << msg_content->initial_state_digest << "\n";
        datafile << ind << ind << ind << "frag_num: "             << msg_content->frag_num << "\n";
    }
    else if (data->type == RTU_FEEDBACK) { // This type is RECEIVED BY the RTU/PLC-side Proxy (from ITRC)
        rtu_feedback_msg * msg_content = NULL;
        msg_content = (rtu_feedback_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << ind << ind << ind << "seq:\n";
        datafile << ind << ind << ind << ind << "incarnation: " << msg_content_seq.incarnation << "\n";
        datafile << ind << ind << ind << ind << "seq_num: "     << msg_content_seq.seq_num << "\n";
        datafile << ind << ind << ind << "scen_type: "          << msg_content->scen_type << "\n";
        datafile << ind << ind << ind << "type: "               << msg_content->type << "\n";
        datafile << ind << ind << ind << "sub: "                << msg_content->sub << "\n";
        datafile << ind << ind << ind << "rtu: "                << msg_content->rtu << "\n";
        datafile << ind << ind << ind << "offset: "             << msg_content->offset << "\n";
        datafile << ind << ind << ind << "val: "                << msg_content->val << "\n";
    }
    else if (data->type == RTU_DATA) { // This type is RECEIVED BY the RTU/PLC-side Proxy (from RTUs/PLCs)
        rtu_data_msg * msg_content = NULL;
        msg_content = (rtu_data_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << ind << ind << ind << "seq:\n";
        datafile << ind << ind << ind << ind << "incarnation: " << msg_content_seq.incarnation << "\n";
        datafile << ind << ind << ind << ind << "seq_num: "     << msg_content_seq.seq_num << "\n";
        datafile << ind << ind << ind << "rtu_id: "             << msg_content->rtu_id << "\n";
        datafile << ind << ind << ind << "scen_type: "          << msg_content->scen_type << "\n";
        datafile << ind << ind << ind << "sec: "                << msg_content->sec << "\n";
        datafile << ind << ind << ind << "usec: "               << msg_content->usec << "\n";
        datafile << ind << ind << ind << "data_(aka_payload):\n";
        pnnl_fields * payload = (pnnl_fields *)msg_content->data; // since msg_content->data is of type struct pnnl_fields, it cant be printed directly and we need to separately write its fields
        datafile << ind << ind << ind << ind << "padd1: "<< payload->padd1 << "\n";
        datafile << ind << ind << ind << ind << "point: [";
        for (int i = 0; i < NUM_POINT; i++) {
            datafile << payload->point[i] << ((i < NUM_POINT-1) ? ", " : ""); // adding a comma to make it a proper list. dont print comma for the last element
        }
        datafile << "]\n";
        datafile << ind << ind << ind << ind << "breaker_read: [";
        for (int i = 0; i < NUM_BREAKER; i++) {
            datafile << +payload->breaker_read[i] << ((i < NUM_BREAKER-1) ? ", " : ""); // the '+' makes it print as a number. Im not sure what the value exactly means but it seems its binary value is manipulated somehow when it is actually used. so i just save the numerical equivalent value for the element
        }
        datafile << "]\n";
        datafile << ind << ind << ind << ind << "breaker_write: [";
        for (int i = 0; i < NUM_BREAKER; i++) {
            datafile << +payload->breaker_write[i] << ((i < NUM_BREAKER-1) ? ", " : "");
        }
        datafile << "]\n";
    }
    // else case: if unknown data type then nothing to print.
    
    datafile << "# === End Entry ===\n\n"; // a yaml comment
    datafile.close();
}

void write_data(std::string log_files_dir, struct DataCollectorPacket * data_packet, std::string sender_ipaddr, int sender_port) {
    write_data_yaml(log_files_dir, data_packet, sender_ipaddr, sender_port);
}

void sockaddr_in_to_str(struct sockaddr_in *sa, socklen_t *sa_len, std::string &ipaddr, int &port){
    char * ip = inet_ntoa(sa->sin_addr);
    int sender_port = sa->sin_port;
    ipaddr = ip;
    port = sender_port;
}

void set_up_mcast_sock(std::string spinesd_ipaddr, int spinesd_port, std::string mcast_sock_addr, struct mcast_connection &mcast_conn) {
    if (mcast_sock_addr == ":") { // ":" implies no mcast addr so ignore
        mcast_conn.sock = -1;
        return;
    }

    // parse mcast sock address (mcastIPaddr:mcastPort -> mcastIP, mcastPort)
    int colon_pos = -1;
    colon_pos = mcast_sock_addr.find(':');
    mcast_conn.ipaddr = mcast_sock_addr.substr(0, colon_pos);
    mcast_conn.port = std::stoi(mcast_sock_addr.substr(colon_pos + 1));

    // set up the mcast socket:
    int retry_wait_sec = 2;
    int proto = SPINES_PRIORITY; // note that even though the option are `SPINES_RELIABLE` and `SPINES_PRIORITY`. Only `SPINES_PRIORITY` is compatible with mcast. the other one wont work
    while (true) {
        mcast_conn.sock = Spines_Sock(spinesd_ipaddr.c_str(), spinesd_port, proto, mcast_conn.port);
        if (mcast_conn.sock < 0 ) {
            std::cout << "Error setting the multicast socket for the switcher. Trying again in " << retry_wait_sec << "sec\n";
            sleep(retry_wait_sec);
        }
        else {
            break;
        }
    }
    mcast_conn.membership.imr_multiaddr.s_addr = inet_addr(mcast_conn.ipaddr.c_str());
    mcast_conn.membership.imr_interface.s_addr = htonl(INADDR_ANY);
    if (spines_setsockopt(mcast_conn.sock, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mcast_conn.membership, sizeof(mcast_conn.membership)) < 0) {
        std::cout << "Mcast: problem in setsockopt to join multicast address";
      }
    std::cout << "Mcast setup done\n";
}

void handle_mcast_message(int sock, int code, void *data) {
    struct mcast_connection mcast_conn = *((struct mcast_connection*) data);
    
    int ret;
    byte buff[switcher_message_max_size];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    Switcher_Message * message;
    
    while (true) {
        ret = spines_recvfrom(sock, buff, switcher_message_max_size, 0, (struct sockaddr *) &from_addr, &from_len);
        if (ret < 0) {
            std::cout << "Switcher Message Handler: Error receving the message\n";
        }
        else {
            if ((unsigned long) ret < sizeof(Switcher_Message)){
                std::cout << "Switcher Message Handler: Error - The received message is smaller than expected\n";
                continue;
            }
            message = (Switcher_Message*) buff;
            std::cout << "a message was received from the switcher. \n";
            // TODO: confirm, sometimes seg faults on non-empty messages (maybe line breaks ?)
            write_data(log_files_dir, message, mcast_conn.ipaddr, mcast_conn.port);
        }
    }
}

void* listen_on_mcast_sock(void* fn_args) {
    struct mcast_connection mcast_conn = *((struct mcast_connection*) fn_args);
    if (mcast_conn.sock == -1) // if there was no mcast addr provided
        return NULL;

    E_init();
    E_attach_fd(mcast_conn.sock, READ_FD, handle_mcast_message, 0, (void *) &mcast_conn, HIGH_PRIORITY);
    E_handle_events();
    
    return NULL;
}

void write_data(std::string log_files_dir_og, Switcher_Message * switcher_message, std::string sender_ipaddr, int sender_port) { // for switcher messages
    // initially, just keeping it simple so our 'database' is just a file
    // later on we can have something better like a proper database or whatever is needed.

    std::time_t timestamp;
    std::ofstream datafile;
    
    std::string log_files_dir = log_files_dir_og + ".switcher.txt";
    datafile.open(log_files_dir.c_str(), std::ios_base::app); // open in append mode
    timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    datafile << "=== New Entry ===\n";
    datafile << "Time: " << std::ctime(&timestamp); 
    datafile << "From: " << sender_ipaddr << ":" << sender_port <<"\n";    

    std::string data_stream_str;
    data_stream_str = "SWITCHER_MSG";

    datafile << "Data Stream: " << data_stream_str << "\n";
    
    std::string msg_type_str;
    msg_type_str = " [== SWITCHER_MSG]";

    datafile << "Data: \n";
    datafile << "\tnew_active_system_id: " << switcher_message->new_active_system_id << "\n";
    datafile << "\tadd_io_proc_path: " << switcher_message->add_io_proc_path << "\n";
    datafile << "\tadd_io_proc_id: " << switcher_message->add_io_proc_id << "\n";
    datafile << "\tremove_io_proc_id: " << switcher_message->remove_io_proc_id << "\n";

    datafile << "=== End Entry ===\n\n";
    datafile.close();
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