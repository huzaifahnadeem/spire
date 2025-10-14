#include <string>
#include <sstream>
#include <unistd.h> // for sleep()
#include <queue>
#include <fstream> // file/pipe reading
#include <arpa/inet.h>
#include <netdb.h> // for struct hostent
#include <cstring> // for memcpy
#include <sys/un.h>
#include <chrono>
#include <filesystem>

#include "./switcher_packets.h"
#include "../data_collector/data_collector_packets.h"

extern "C" {
    #include "../spines/libspines/spines_lib.h"
}

#define SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines
#define SPINES_CONNECT_USEC 0

struct Args {
    std::string spinesd_ipaddr;
    int spinesd_port;
    std::string mcast_ipaddr;
    int mcast_port;
    // std::string input_pipe_name;
    int switcher_msg_recv_port;
};

struct Spines_Connection {
    int socket;
    sockaddr_in dest;
};

struct Proxy_Messages_Thread_Args {
    Spines_Connection spines_conn;
};

// TODO to-send message queue. read input pipe thread will put stuff in there for the other socket managment thread to read on and send

void parse_args(int ac, char **av);
void* read_input_pipe(void* fn_arg);
Spines_Connection setup_spines_multicast_sending_socket();
void* setup_and_handle_spines_receiving_socket(void* fn_arg);
void write_into_log(std::string output);
void sockaddr_in_to_str(struct sockaddr_in *sa, socklen_t *sa_len, std::string &ipaddr, int &port);