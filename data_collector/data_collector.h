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

#include "data_collector_packets.h"

// for spines
extern "C" {
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
    #include "../common/itrc.h"
    #include "spines_lib.h"
}

#define SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines
#define SPINES_CONNECT_USEC 0

void write_data(std::string data_file_path, struct DataCollectorPacket * data_packet, std::string sender_ipaddr, int sender_port);
void usage_check(int ac, char **av);
void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, int &my_port, std::string &data_file_path);
void sockaddr_in_to_str(struct sockaddr_in *sa, socklen_t *sa_len, std::string &ipaddr, int &port);