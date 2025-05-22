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

    // set up spines sock for proxy messages:
    int proto, spines_sock, num, ret;
    struct timeval spines_timeout, *t;
    fd_set mask, tmask;
    char buff[MAX_LEN];

    FD_ZERO(&mask);
    if (mcast_conn.sock != -1) // implies that there is not switcher in the system, we ensure that we connect to it otherwise
        FD_SET(mcast_conn.sock, &mask);

    proto = SPINES_RELIABLE; // need to use SPINES_RELIABLE and not SPINES_PRIORITY. This is because we need to be sure the message is delivered. SPINES_PRIORITY can drop messages. might need to think more though (but thats for later)
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
     *  this often */
    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;

    spines_sock = -1; // -1 is not a real socket so init to that
    while (spines_sock < 0) {
        spines_sock = Spines_Sock(spinesd_ip_addr.c_str(), spinesd_port, proto, my_port);
        std::cout << "data_collector: Unable to connect to Spines, trying again soon\n";
    }
    t = &spines_timeout; 
    std::cout << "data_collector: Connected to Spines\n";
    FD_SET(spines_sock, &mask);

    // handle proxy messages:
    while (1) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);
        if (num > 0) {
            // message from a proxy
            if (spines_sock >= 0 && FD_ISSET(spines_sock, &tmask)) {
                // spines_recv does not give a way to find out the sender's address
                // ret = spines_recv(spines_sock, buff, MAX_LEN, 0);
                // so, instead we are using spines_recvfrom:
                struct sockaddr_in sender_addr;
                socklen_t sender_addr_structlen = sizeof(sender_addr); 
                ret = spines_recvfrom(spines_sock, buff, MAX_LEN, 0, (struct sockaddr *) &sender_addr, &sender_addr_structlen);
                if (ret <= 0) {
                    std::cout << "data_collector: Error in spines_recvfrom with spines_sock>0 and : ret = " << ret << " .dropping!\n";
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
            // mcast message from the switcher
            else if (mcast_conn.sock >= 0 && FD_ISSET(mcast_conn.sock, &tmask)) {
                handle_mcast_message(mcast_conn);
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

void write_sys_data_yaml(std::string log_file_path, struct DataCollectorPacket * data_packet, std::string sender_ipaddr, int sender_port, const std::string ind, std::chrono::system_clock::rep microsec_since_epoch, std::string timestamp) {
    // note that log_files_dir can have whatever file extension. It doesnt matter. We are writing a text file that can be interpretted as a yaml file (and yaml files are easier to read for humans too so should also serve as a decent text file)
    std::string system_id = data_packet->sys_id;
    signed_message *data = &data_packet->system_message;
  
    std::ofstream datafile;
    datafile.open(log_file_path.c_str(), std::ios_base::app); // open in append mode
    datafile << "# === New Entry ===\n"; // a yaml comment

    datafile << microsec_since_epoch << ":\n"; // each new entry is a dict with timestamp (when the data collector writes this entry) as the root key. timestamp is microseconds since epoch (if we use seconds then the keys are occasionally not unique. with microseconds they are oftern 2-3 microsec apart so just to be safe, this microsec should definitely give us unique keys. if not we can add a usleep() at the end of this function to force some time between entries)

    datafile << ind << "Timestamp: '"<< timestamp << "'\n"; // human-readable timestamp
    
    datafile << ind << "from:\n";
    datafile << ind << ind << "system_ID: " << system_id << "\n";
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

void write_switcher_data_yaml(std::string log_file_path, struct Switcher_Message * switcher_message, std::string sender_ipaddr, int sender_port, const std::string ind, std::chrono::system_clock::rep microsec_since_epoch, std::string timestamp) {
    std::ofstream datafile;
    datafile.open(log_file_path.c_str(), std::ios_base::app); // open in append mode
    
    datafile << "# === New Entry ===\n"; // a yaml comment
    datafile << microsec_since_epoch << ":\n"; // each new entry is a dict with timestamp (when the data collector writes this entry) as the root key. timestamp is microseconds since epoch (if we use seconds then the keys are occasionally not unique. with microseconds they are oftern 2-3 microsec apart so just to be safe, this microsec should definitely give us unique keys. if not we can add a usleep() at the end of this function to force some time between entries)
    datafile << ind << "Timestamp: '"<< timestamp << "'\n"; // human-readable timestamp
    
    datafile << ind << "from:\n";
    datafile << ind << ind << "IP_address: " << sender_ipaddr << "\n";
    datafile << ind << ind << "port: " << sender_port << "\n";

    datafile << ind << "data_stream: " << "SWITCHER_MSG" << "\n";

    datafile << ind << "data: \n";
    
    datafile << ind << ind << "new_active_system_id: " << switcher_message->new_active_system_id << "\n";
    datafile << ind << ind << "add_io_proc_path: "     << switcher_message->add_io_proc_path << "\n";
    datafile << ind << ind << "add_io_proc_id: "       << switcher_message->add_io_proc_id << "\n";
    datafile << ind << ind << "remove_io_proc_id: "    << switcher_message->remove_io_proc_id << "\n";

    datafile << "# === End Entry ===\n\n"; // a yaml comment
    datafile.close();
}

void gen_timestamps(std::chrono::system_clock::rep &microsec_since_epoch, std::string &ts_wo_newline) {
    // time related stuff for file names and keys in the yaml file.
    auto now = std::chrono::system_clock::now();
    auto time_since_epoch = now.time_since_epoch();
    microsec_since_epoch = std::chrono::duration_cast<std::chrono::microseconds>(time_since_epoch).count();
    std::time_t timestamp;
    timestamp = std::chrono::system_clock::to_time_t(now);
    std::string ts = std::ctime(&timestamp);
    ts_wo_newline = ts.substr(0, ts.find('\n'));    
}

void get_log_filename(std::string &file_name, const std::string system_id, const std::chrono::system_clock::rep microsec_since_epoch) {
    // find the file for this system_id if it was previously created. otherwise create it and put it in log_files_map to keep track of it
    // switcher follows the same file name conventions with system_id being "switcher"
    auto found_val = log_files_map.find(system_id);
    if (found_val != log_files_map.end()) {
        // key (id) exists. so a file for this system id was previously created. use that
        file_name = log_files_map[system_id];
    } 
    else {
        std::stringstream strstream_file_name;
        strstream_file_name << system_id << "." << microsec_since_epoch << ".yaml";
        file_name = strstream_file_name.str();
        log_files_map[system_id] = file_name;
    }
}

std::string get_yaml_indentation() {
    const std::string ind = "  "; // Indentation for the yaml file structure. using 2 spaces which i believe is the recommeded indentation for yaml (however, any number should be fine as long as we are consistent) (note that yaml hates tabs so use this everywhere)
    return ind;
}

// for data collector packets (from proxies)
void write_data(std::string log_files_dir, struct DataCollectorPacket * data_packet, std::string sender_ipaddr, int sender_port) {
    std::string ind = get_yaml_indentation();
    
    std::chrono::system_clock::rep microsec_since_epoch;
    std::string timestamp;
    gen_timestamps(microsec_since_epoch, timestamp);
    
    std::string file_name;
    get_log_filename(file_name, data_packet->sys_id, microsec_since_epoch);
    
    write_sys_data_yaml((log_files_dir + file_name), data_packet, sender_ipaddr, sender_port, ind, microsec_since_epoch, timestamp);
}

// for switcher packets
void write_data(std::string log_files_dir, struct Switcher_Message * switcher_message, std::string sender_ipaddr, int sender_port) {
    std::string ind = get_yaml_indentation();
    
    std::chrono::system_clock::rep microsec_since_epoch;
    std::string timestamp;
    gen_timestamps(microsec_since_epoch, timestamp);
    
    std::string file_name;
    get_log_filename(file_name, "switcher", microsec_since_epoch);
    
    write_switcher_data_yaml((log_files_dir + file_name), switcher_message, sender_ipaddr, sender_port, ind, microsec_since_epoch, timestamp);
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

void handle_mcast_message(mcast_connection mcast_conn) {
    int sock = mcast_conn.sock;
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