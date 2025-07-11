#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for sleep()
#include <iostream> 
#include <fstream> // for file operations
#include <chrono> // for time
#include <ctime> // for time
#include <string.h> // string operations
#include <sys/select.h> // select statement
#include <arpa/inet.h>
#include <sys/un.h>
#include <sstream>
#include <unordered_map>
#include <filesystem> // available since c++-17

#include "data_collector_packets.h"
#include "../switcher/switcher_packets.h"

// for spines
extern "C" {
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
    #include "../common/itrc.h"
    #include "spines_lib.h"
    #include "../prime/libspread-util/include/spu_events.h" // import libspread. for its event handler functions
}

#define SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines
#define SPINES_CONNECT_USEC 0

struct mcast_connection {
    std::string ipaddr;
    int port;
    struct ip_mreq membership;
    int sock = -1;
};

const int switcher_message_max_size = MAX_SPINES_CLIENT_MSG; // TODO: maybe this should go in ../switcher/switcher_packets.h

void write_data(std::string log_files_dir, struct DataCollectorPacket * data_packet, std::string sender_ipaddr, int sender_port); // for proxy messages
void usage_check(int ac, char **av);
void parse_args(int ac, char **av, std::string &spinesd_ip_addr, int &spinesd_port, int &my_port, std::string &data_file_path, std::string &mcast_sock_addr);
void sockaddr_in_to_str(struct sockaddr_in *sa, socklen_t *sa_len, std::string &ipaddr, int &port);
void set_up_mcast_sock(std::string spinesd_ipaddr, int spinesd_port, std::string mcast_sock_addr, struct mcast_connection &mcast_conn);
void write_data(std::string log_files_dir, struct Switcher_Message * switcher_message, std::string sender_ipaddr, int sender_port); // for switcher messages
bool CreateDirectoryRecursive(std::string const & dirName, std::error_code & err);
void* mcast_listen(void* fn_arg);
void handle_mcast_message(int sock, int code, void *data);

// // specifically for management network (avoids using SPINES_INT_PORT & SPINES_EXT_PORT)
// int my_Spines_Sock(const char *sp_addr, int sp_port, int proto, int my_port);