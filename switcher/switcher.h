#include <string>
#include <sstream>
#include <unistd.h> // for sleep()
#include <queue>
#include <fstream> // file/pipe reading
#include <arpa/inet.h>
#include <netdb.h> // for struct hostent
#include <cstring> // for memcpy
#include <sys/un.h>
// #include <chrono>

#include "./switcher_packets.h"
#include "../data_collector/data_collector_packets.h"

extern "C" {
    #include "../spines/libspines/spines_lib.h"
}

struct Args {
    std::string spinesd_ipaddr;
    int spinesd_port;
    std::string mcast_ipaddr;
    int mcast_port;
    std::string input_pipe_name;
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
Spines_Connection setup_spines_multicast_socket();
void* send_pending_messages_to_mcast_group(void* fn_args);