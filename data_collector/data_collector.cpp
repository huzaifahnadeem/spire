#include "data_collector.h"

std::string data_file_path;
int main(int ac, char **av) {
    std::string spinesd_ip_addr; // for spines daemon
    int spinesd_port;
    int my_port; // the port this data collector receives messages on
    std::string mcast_sock_addr;

    parse_args(ac, av, spinesd_ip_addr, spinesd_port, my_port, data_file_path, mcast_sock_addr);

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
                // write_data(data_file_path, (signed_message *)buff, sender_ipaddr, sender_port);
                write_data(data_file_path, (DataCollectorPacket *)buff, sender_ipaddr, sender_port);
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
        printf("Usage: %s spinesAddr:spinesPort dataCollectorPort mcastAddr:mcastPort dataLogFilePath\nTo ignore mcastAddr:mcastPort arg, just enter ':' in its place\n", av[0]);
        exit(EXIT_FAILURE);
    }
}

void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, int &my_port, std::string &data_file_path, std::string &mcast_sock_addr) {
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
    data_file_path = av[4];
}

// void write_data(std::string data_file_path, signed_message *data, std::string sender_ipaddr, int sender_port) {
void write_data(std::string data_file_path, struct DataCollectorPacket * data_packet, std::string sender_ipaddr, int sender_port) {
    // initially, just keeping it simple so our 'database' is just a file
    // later on we can have something better like a proper database or whatever is needed.
    signed_message *data = &data_packet->system_message;

    std::time_t timestamp;
    std::ofstream datafile;
    
    datafile.open(data_file_path.c_str(), std::ios_base::app); // open in append mode
    timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    datafile << "=== New Entry ===\n";
    datafile << "Time: " << std::ctime(&timestamp); 
    datafile << "From: " << sender_ipaddr << ":" << sender_port <<"\n";    

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
            "<unknown data stream>";
    }
    datafile << "Data Stream: " << data_stream_str << "\n";
    
    std::string msg_type_str;
    switch (data->type) {
    case HMI_COMMAND:
        msg_type_str = " [== HMI_COMMAND]";
        break;
    case HMI_UPDATE:
        msg_type_str = " [== HMI_UPDATE]";
        break;
    case PRIME_OOB_CONFIG_MSG:
        msg_type_str = " [== PRIME_OOB_CONFIG_MSG]";
        break;
    case RTU_FEEDBACK:
        msg_type_str = " [== RTU_FEEDBACK]";
        break;
    case RTU_DATA:
        msg_type_str = " [== RTU_DATA]";
        break;
    default:
        " [<unknown type>]";
    }

    datafile << "Data: \n";
    // datafile << "\t" << "->sig:\t\t"                          << data->sig << "\n";
    datafile << "\t" << "->sig:\t\t< ";
    
    for (int i = 0; i < SIGNATURE_SIZE; i++) {
        datafile << (int)data->sig[i] << "";
    }
    datafile << " >\n";
    
    datafile << "\t" << "->mt_num:\t\t"                       << data->mt_num << "\n";
    datafile << "\t" << "->mt_index:\t\t"                     << data->mt_index << "\n";
    datafile << "\t" << "->site_id:\t\t"                      << data->site_id << "\n";
    datafile << "\t" << "->machine_id:\t\t"                   << data->machine_id << "\n";
    datafile << "\t" << "->len:\t\t"                          << data->len << "\n";
    datafile << "\t" << "->type:\t\t"                         << data->type << msg_type_str << "\n";
    datafile << "\t" << "->incarnation:\t\t"                  << data->incarnation << "\n";
    datafile << "\t" << "->monotonic_counter:\t\t"            << data->monotonic_counter << "\n";
    datafile << "\t" << "->global_configuration_number:\t\t"  << data->global_configuration_number << "\n";
    datafile << "\t" << "->message content follows:\n";

    if (data->type == HMI_COMMAND) { // This type is SENT BY the HMI
        hmi_command_msg * msg_content = NULL;
        msg_content = (hmi_command_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << "->seq.incarnation:\t\t"  << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << "->seq.seq_num:\t\t"      << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << "->hmi_id:\t\t"           << msg_content->hmi_id << "\n";
        datafile << "\t\t" << "->scen_type:\t\t"        << msg_content->scen_type << "\n";
        datafile << "\t\t" << "->type:\t\t"             << msg_content->type << "\n";
        datafile << "\t\t" << "->ttip_pos:\t\t"         << msg_content->ttip_pos << "\n";
    }
    else if (data->type == HMI_UPDATE) { // This type is RECEIVED BY the HMI-side Proxy
        hmi_update_msg * msg_content = NULL;
        msg_content = (hmi_update_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << "->seq.incarnation:\t\t"     << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << "->seq.seq_num:\t\t"         << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << "->scen_type:\t\t"           << msg_content->scen_type << "\n";
        datafile << "\t\t" << "->sec:\t\t"                 << msg_content->sec << "\n";
        datafile << "\t\t" << "->usec:\t\t"                << msg_content->usec << "\n";
        datafile << "\t\t" << "->len:\t\t"                 << msg_content->len << "\n";
    }
    else if (data->type == PRIME_OOB_CONFIG_MSG) { // This type is RECEIVED BY the HMI-side Proxy & the RTU/PLC-side Proxy (from ITRC)
        config_message * msg_content = NULL;
        msg_content = (config_message *)(data + 1);
        datafile << "\t\t" << "->N:\t\t"                        << msg_content->N << "\n";
        datafile << "\t\t" << "->f:\t\t"                        << msg_content->f << "\n";
        datafile << "\t\t" << "->k:\t\t"                        << msg_content->k << "\n";
        datafile << "\t\t" << "->num_sites:\t\t"                << msg_content->num_sites << "\n";
        datafile << "\t\t" << "->num_cc:\t\t"                   << msg_content->num_cc << "\n";
        datafile << "\t\t" << "->num_dc:\t\t"                   << msg_content->num_dc << "\n";
        datafile << "\t\t" << "->num_cc_replicas:\t\t"          << msg_content->num_cc_replicas << "\n";
        datafile << "\t\t" << "->num_dc_replicas:\t\t"          << msg_content->num_dc_replicas << "\n";
        datafile << "\t\t" << "->tpm_based_id:\t\t"             << msg_content->tpm_based_id << "\n";
        datafile << "\t\t" << "->replica_flag:\t\t"             << msg_content->replica_flag << "\n";
        datafile << "\t\t" << "->sm_addresses:\t\t"             << msg_content->sm_addresses << "\n";
        datafile << "\t\t" << "->spines_ext_addresses:\t\t"     << msg_content->spines_ext_addresses << "\n";
        datafile << "\t\t" << "->spines_ext_port:\t\t"          << msg_content->spines_ext_port << "\n";
        datafile << "\t\t" << "->spines_int_addresses:\t\t"     << msg_content->spines_int_addresses << "\n";
        datafile << "\t\t" << "->spines_int_port:\t\t"          << msg_content->spines_int_port << "\n";
        datafile << "\t\t" << "->prime_addresses:\t\t"          << msg_content->prime_addresses << "\n";
        datafile << "\t\t" << "->initial_state:\t\t"            << msg_content->initial_state << "\n";
        datafile << "\t\t" << "->initial_state_digest:\t\t"     << msg_content->initial_state_digest << "\n";
        datafile << "\t\t" << "->frag_num:\t\t"                 << msg_content->frag_num << "\n";
    }
    else if (data->type == RTU_FEEDBACK) { // This type is RECEIVED BY the RTU/PLC-side Proxy (from ITRC)
        rtu_feedback_msg * msg_content = NULL;
        msg_content = (rtu_feedback_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << "->seq.incarnation:\t\t"          << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << "->seq.seq_num:\t\t"              << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << "->scen_type:\t\t"                << msg_content->scen_type << "\n";
        datafile << "\t\t" << "->type:\t\t"                     << msg_content->type << "\n";
        datafile << "\t\t" << "->sub:\t\t"                      << msg_content->sub << "\n";
        datafile << "\t\t" << "->rtu:\t\t"                      << msg_content->rtu << "\n";
        datafile << "\t\t" << "->offset:\t\t"                   << msg_content->offset << "\n";
        datafile << "\t\t" << "->val:\t\t"                      << msg_content->val << "\n";
    }
    else if (data->type == RTU_DATA) { // This type is RECEIVED BY the RTU/PLC-side Proxy (from RTUs/PLCs)
        rtu_data_msg * msg_content = NULL;
        msg_content = (rtu_data_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << "->seq.incarnation:\t\t"      << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << "->seq.seq_num:\t\t"          << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << "->rtu_id:\t\t"               << msg_content->rtu_id << "\n";
        datafile << "\t\t" << "->scen_type:\t\t"            << msg_content->scen_type << "\n";
        datafile << "\t\t" << "->sec:\t\t"                  << msg_content->sec << "\n";
        datafile << "\t\t" << "->usec:\t\t"                 << msg_content->usec << "\n";
        datafile << "\t\t" << "->data (payload):\n";
        pnnl_fields * payload = (pnnl_fields *)msg_content->data; // since msg_content->data is of type struct pnnl_fields, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t\t->padd1:"<< payload->padd1 << "\n";
        datafile << "\t\t\t->point: [";
        for (int i = 0; i < NUM_POINT; i++) {
            datafile << payload->point[i] << ((i < NUM_POINT-1) ? ", " : ""); // adding a comma to make it print nicer. dont print comma for the last element
        }
        datafile << "]\n";
        datafile << "\t\t\t->breaker_read: [";
        for (int i = 0; i < NUM_BREAKER; i++) {
            datafile << +payload->breaker_read[i] << ((i < NUM_BREAKER-1) ? ", " : ""); // the '+' makes it print as a number. Im not sure what the value exactly means but it seems its binary value is manipulated somehow when it is actually used. so i just save the numerical equivalent value for the element
        }
        datafile << "]\n";
        datafile << "\t\t\t->breaker_write: [";
        for (int i = 0; i < NUM_BREAKER; i++) {
            datafile << +payload->breaker_write[i] << ((i < NUM_BREAKER-1) ? ", " : "");
        }
        datafile << "]\n";
    }
    else {
        std::cout << "Received a message of an unknown type. Type = " << data->type << ".\n";
        datafile << "\t\t" << "<Unknown Type = "<< data->type << ">\n";
    }

    datafile << "=== End Entry ===\n\n";
    datafile.close();
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
            write_data(data_file_path, message, mcast_conn.ipaddr, mcast_conn.port);
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

void write_data(std::string data_file_path_og, Switcher_Message * switcher_message, std::string sender_ipaddr, int sender_port) { // for switcher messages
    // initially, just keeping it simple so our 'database' is just a file
    // later on we can have something better like a proper database or whatever is needed.

    std::time_t timestamp;
    std::ofstream datafile;
    
    std::string data_file_path = data_file_path_og + ".switcher.txt";
    datafile.open(data_file_path.c_str(), std::ios_base::app); // open in append mode
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