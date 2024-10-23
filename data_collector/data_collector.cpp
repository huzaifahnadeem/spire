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

void write_data(signed_message* data, std::string data_file_path);
void usage_check(int ac, char **av);
void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, int &my_port, std::string &data_file_path);

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
                ret = spines_recv(spines_sock, buff, MAX_LEN, 0);
                if (ret <= 0) {
                    std::cout << "data_collector: Error in spines_recvfrom with spines_sock>0 and : ret = " << ret << "dropping!\n";
                    spines_close(spines_sock);
                    FD_CLR(spines_sock, &mask);
                    spines_sock = -1;
                    t = &spines_timeout; 
                    continue;
                }
                std::cout << "data_collector: Received some data from spines daemon\n";
                write_data((signed_message *)buff, data_file_path);
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

void write_data(signed_message *data, std::string data_file_path) {
    // initially, just keeping it simple so our 'database' is just a file
    // later on we can have something better like a proper database or whatever is needed.

    std::time_t timestamp;
    std::ofstream datafile;
    
    datafile.open(data_file_path.c_str(), std::ios_base::app); // open in append mode
    timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    datafile << "=== New Entry ===\n";
    datafile << "Time: " << std::ctime(&timestamp) << "From: " << "<from>\n";
    datafile << "Data: \n";

    datafile << "\t" << data->sig << "\n";
    datafile << "\t" << data->mt_num << "\n";
    datafile << "\t" << data->mt_index << "\n";
    datafile << "\t" << data->site_id << "\n";
    datafile << "\t" << data->machine_id << "\n";
    datafile << "\t" << data->len << "\n";
    datafile << "\t" << data->type << "\n";
    datafile << "\t" << data->incarnation << "\n";
    datafile << "\t" << data->monotonic_counter << "\n";
    datafile << "\t" << data->global_configuration_number << "\n";

    if (data->type == HMI_COMMAND) { // This type is SENT BY the HMI
        hmi_command_msg * msg_content = NULL;
        msg_content = (hmi_command_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << msg_content->hmi_id << "\n";
        datafile << "\t\t" << msg_content->scen_type << "\n";
        datafile << "\t\t" << msg_content->type << "\n";
        datafile << "\t\t" << msg_content->ttip_pos << "\n";
    }
    else if (data->type == HMI_UPDATE) { // This type is RECEIVED BY the HMI-side Proxy
        hmi_update_msg * msg_content = NULL;
        msg_content = (hmi_update_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << msg_content->scen_type << "\n";
        datafile << "\t\t" << msg_content->sec << "\n";
        datafile << "\t\t" << msg_content->usec << "\n";
        datafile << "\t\t" << msg_content->len << "\n";
    }
    else if (data->type == PRIME_OOB_CONFIG_MSG) { // This type is RECEIVED BY the HMI-side Proxy & the RTU/PLC-side Proxy (from ITRC)
        config_message * msg_content = NULL;
        msg_content = (config_message *)(data + 1);
        datafile << "\t\t" << msg_content->N << "\n";
        datafile << "\t\t" << msg_content->f << "\n";
        datafile << "\t\t" << msg_content->k << "\n";
        datafile << "\t\t" << msg_content->num_sites << "\n";
        datafile << "\t\t" << msg_content->num_cc << "\n";
        datafile << "\t\t" << msg_content->num_dc << "\n";
        datafile << "\t\t" << msg_content->num_cc_replicas << "\n";
        datafile << "\t\t" << msg_content->num_dc_replicas << "\n";
        datafile << "\t\t" << msg_content->tpm_based_id << "\n";
        datafile << "\t\t" << msg_content->replica_flag << "\n";
        datafile << "\t\t" << msg_content->sm_addresses << "\n";
        datafile << "\t\t" << msg_content->spines_ext_addresses << "\n";
        datafile << "\t\t" << msg_content->spines_ext_port << "\n";
        datafile << "\t\t" << msg_content->spines_int_addresses << "\n";
        datafile << "\t\t" << msg_content->spines_int_port << "\n";
        datafile << "\t\t" << msg_content->prime_addresses << "\n";
        datafile << "\t\t" << msg_content->initial_state << "\n";
        datafile << "\t\t" << msg_content->initial_state_digest << "\n";
        datafile << "\t\t" << msg_content->frag_num << "\n";
    }
    else if (data->type == RTU_FEEDBACK) { // This type is RECEIVED BY the RTU/PLC-side Proxy (from ITRC)
        rtu_feedback_msg * msg_content = NULL;
        msg_content = (rtu_feedback_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << msg_content->scen_type << "\n";
        datafile << "\t\t" << msg_content->type << "\n";
        datafile << "\t\t" << msg_content->sub << "\n";
        datafile << "\t\t" << msg_content->rtu << "\n";
        datafile << "\t\t" << msg_content->offset << "\n";
        datafile << "\t\t" << msg_content->val << "\n";
    }
    else if (data->type == RTU_DATA) { // This type is RECEIVED BY the RTU/PLC-side Proxy (from RTUs/PLCs)
        rtu_data_msg * msg_content = NULL;
        msg_content = (rtu_data_msg *)(data + 1);
        seq_pair msg_content_seq = msg_content->seq; // since msg_content->seq is of type struct seq_pair, it cant be printed directly and we need to separately write its fields
        datafile << "\t\t" << msg_content_seq.incarnation << "\n";
        datafile << "\t\t" << msg_content_seq.seq_num << "\n";
        datafile << "\t\t" << msg_content->rtu_id << "\n";
        datafile << "\t\t" << msg_content->scen_type << "\n";
        datafile << "\t\t" << msg_content->sec << "\n";
        datafile << "\t\t" << msg_content->usec << "\n";
        datafile << "\t\t" << msg_content->data << "\n";
    }
    else {
        std::cout << "Received a message of an unknown type. Type = " << data->type << ".\n";
        datafile << "\t\t" << "<Unknown Type = "<< data->type << ">\n";
    }

    datafile << "=== End Entry ===\n\n";
    datafile.close();
}