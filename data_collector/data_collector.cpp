#include <stdio.h>
#include <stdlib.h>

// for file operations
#include <iostream>
#include <fstream>

// for time
#include <chrono>
#include <ctime>

// string operations
#include <string.h>

// select statement
#include <sys/select.h>


#include <arpa/inet.h>

// for spines
extern "C" {
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
    #include "../common/itrc.h"
    #include "spines_lib.h"
}

#define SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines
#define SPINES_CONNECT_USEC 0

void write_data(std::string data_file_path, signed_message* data, std::string sender_ipaddr, int sender_port);
void usage_check(int ac, char **av);
void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, int &my_port, std::string &data_file_path);
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
void sockaddr_to_str(struct sockaddr *sa, socklen_t *sa_len, std::string &ipaddr, int &port);

int main(int ac, char **av){
    std::string spinesd_ip_addr; // for spines daemon
    int spinesd_port;
    int my_port; // the port this data collector receives messages on
    std::string data_file_path;

    parse_args(ac, av, spinesd_ip_addr, spinesd_port, my_port, data_file_path);

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

    while (1) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);
        if (num > 0) {
            /* Message from Spines */
            if (spines_sock >= 0 && FD_ISSET(spines_sock, &tmask)) {
                // spines_recv does not give a way to find out the sender's address
                // ret = spines_recv(spines_sock, buff, MAX_LEN, 0);
                // so, instead we are using spines_recvfrom
                struct sockaddr sender_addr;
                socklen_t sender_addr_structlen;
                ret = spines_recvfrom(spines_sock, buff, MAX_LEN, 0, &sender_addr, &sender_addr_structlen);
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
                sockaddr_to_str(&sender_addr, &sender_addr_structlen, sender_ipaddr, sender_port);
                write_data(data_file_path, (signed_message *)buff, sender_ipaddr, sender_port);
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

    return 0;
}

void usage_check(int ac, char **av) {
    if (ac != 4) {
        printf("Invalid args\n");
        printf("Usage: %s spinesAddr:spinesPort dataCollectorPort dataLogFilePath\n", av[0]);
        exit(EXIT_FAILURE);
    }
}

void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, int &my_port, std::string &data_file_path) {
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

    // data file:
    data_file_path = av[3];
}

void write_data(std::string data_file_path, signed_message *data, std::string sender_ipaddr, int sender_port) {
    // initially, just keeping it simple so our 'database' is just a file
    // later on we can have something better like a proper database or whatever is needed.

    std::time_t timestamp;
    std::ofstream datafile;
    
    datafile.open(data_file_path.c_str(), std::ios_base::app); // open in append mode
    timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    datafile << "=== New Entry ===\n";
    datafile << "Time: " << std::ctime(&timestamp); 
    datafile << "From: " << sender_ipaddr << ":" << sender_port <<"\n";
    
    std::string msg_type_str;
    switch (data->type) {
    case HMI_COMMAND:
        msg_type_str = "[== HMI_COMMAND]";
        break;
    case HMI_UPDATE:
        msg_type_str = "[== HMI_UPDATE]";
        break;
    case PRIME_OOB_CONFIG_MSG:
        msg_type_str = "[== PRIME_OOB_CONFIG_MSG]";
        break;
    case RTU_FEEDBACK:
        msg_type_str = "[== RTU_FEEDBACK]";
        break;
    case RTU_DATA:
        msg_type_str = "[== RTU_DATA]";
        break;
    default:
        "[ <unknown type>]";
    }

    datafile << "Data: \n";
    datafile << "\t" << "->sig:\t\t"                          << data->sig << "\n";
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
        datafile << "\t\t" << "->data:\t\t"                 << msg_content->data << "\n";
    }
    else {
        std::cout << "Received a message of an unknown type. Type = " << data->type << ".\n";
        datafile << "\t\t" << "<Unknown Type = "<< data->type << ">\n";
    }

    datafile << "=== End Entry ===\n\n";
    datafile.close();
}

// Convert a struct sockaddr address to a string, IPv4 and IPv6:
// from https://gist.github.com/jkomyno/45bee6e79451453c7bbdc22d033a282e
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{   
    // std::cout << "here01\n";
    switch(sa->sa_family) {
        case AF_INET:
            // std::cout << "here02\n";
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            // std::cout << "here03\n";
            break;

        case AF_INET6:
            // std::cout << "here04\n";
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            // std::cout << "here05\n";
            break;

        default:
            // std::cout << "here06\n";
            strncpy(s, "Unknown AF", maxlen);
            // std::cout << "here07\n";
            return NULL;
    }

    return s;
}

void sockaddr_to_str(struct sockaddr *sa, socklen_t *sa_len, std::string &ipaddr, int &port){
    char * tmp;
    // std::cout << "here100\n";
    struct sockaddr_in *addr_in = (struct sockaddr_in *)sa;
    std::string sender_ipaddr = get_ip_str(sa, tmp, sizeof(sa));
    // std::cout << "here200\n";
    // std::string sender_ipaddr = inet_ntoa(addr_in->sin_addr);
    // std::cout << "here300\n";
    int sender_port = addr_in->sin_port;
    // int sender_port = 99;
    // ;std::cout << "here400\n";


    // sender_port = ((struct sockaddr_in*)sender_addr)->sin_port;

    // ipaddr = "?";
    // port = -1;
    ipaddr = sender_ipaddr;
    port = sender_port;
}