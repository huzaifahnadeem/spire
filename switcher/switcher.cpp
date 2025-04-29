
#include "switcher.h"

#include <iostream>

extern "C" {
    #include "common/net_wrapper.h" 
    #include "spines/libspines/spines_lib.h" // for spines functions e.g. spines_sendto()
}

Args args;
std::queue <Switcher_Message> pending_messages;
const int Switcher_Message_max_size = MAX_SPINES_CLIENT_MSG; // TODO: put this somewhere common to the proxies and the switcher? MAX_SPINES_CLIENT_MSG = 50000 bytes

int main(int ac, char **av) {
    parse_args(ac, av);

    // set up a spines multicast socket
    Spines_Connection spines_connection = setup_spines_multicast_socket();

    // run a thread that checks for and reads and input coming in on the named input pipe
    pthread_t read_input_pipe_thread;
    pthread_create(&read_input_pipe_thread, NULL, &read_input_pipe, NULL);

    // run a thread that sends out any messages to the proxies
    pthread_t proxy_messages_thread;
    Proxy_Messages_Thread_Args message_thread_args = {.spines_conn = spines_connection};
    pthread_create(&proxy_messages_thread, NULL, &send_pending_messages_to_mcast_group, (void*) &message_thread_args);

    // wait for the threads before exiting
    pthread_join(read_input_pipe_thread, NULL);
    pthread_join(proxy_messages_thread, NULL);

    return EXIT_SUCCESS;
}

void parse_args(int argc, char **argv) {
    std::stringstream usage_stream;
    usage_stream << "Usage: ./switcher spinesIP:port mcastIP:port input_pipe_name\n";
    std::string usage = usage_stream.str();


    int expected_argc = 4;
    if (argc != expected_argc) {
        std::cout << usage;
        exit(EXIT_FAILURE);
    }

    // parse the spines daemon address arg
    std::string spinesd_arg = argv[1];
    int colon_pos = -1;
    colon_pos = spinesd_arg.find(':');
    std::string spinesd_ipaddr = spinesd_arg.substr(0, colon_pos);
    int spinesd_port = std::stoi(spinesd_arg.substr(colon_pos + 1));
    args.spinesd_ipaddr = spinesd_ipaddr;
    args.spinesd_port = spinesd_port;

    // parse the arg for IP addr and the port for MCAST
    std::string mcast_arg = argv[2];
    colon_pos = -1;
    colon_pos = mcast_arg.find(':');
    std::string mcast_ipaddr = mcast_arg.substr(0, colon_pos);
    int mcast_port = std::stoi(mcast_arg.substr(colon_pos + 1));
    args.mcast_ipaddr = mcast_ipaddr;
    args.mcast_port = mcast_port;

    // input pipe name arg:
    args.input_pipe_name = argv[3];
}

void* read_input_pipe(void* fn_arg) {
    UNUSED(fn_arg);
    // for now just read standard input. will come back to add the whole pipe reading thing
    std::string input;
    while (true) {
        std::cin >> input;

        Switcher_Message message_to_send = {.new_active_system_id = input};
        pending_messages.push(message_to_send);
    }

    
    // int retry_wait_time_sec = 2; // if we cant access the file (e.g. if it doesnt exist, then wait for this many seconds before attempting again)

    // // read the input pipe if there is something to read. if not, wait for something.
    // while (true) {
    //     std::ifstream pipe_file(args.input_pipe_name);
    //     if(pipe_file.fail()) {
    //         std::cout << "Unable to access the file \"" << args.input_pipe_name << "\". Trying again in " << retry_wait_time_sec << " seconds\n";
    //         sleep(retry_wait_time_sec);
    //     }
    //     else {
    //         break;
    //     }
    // }

    // // create the message based on what was read on the input pipe
    // Switcher_Message message_to_send;
    // pending_messages.push(message_to_send);

    return NULL;
}

Spines_Connection setup_spines_multicast_socket() {
    int proto, socket, reconnect_wait_time_sec, ttl;
    proto = SPINES_RELIABLE; // options: SPINES_RELIABLE and SPINES_PRIORITY
    reconnect_wait_time_sec = 2;
    ttl = 255; // not sure what is the purpose. copied from the config_manager's code
    socket = -1;
    while (socket < 0) {
        socket = Spines_Mcast_SendOnly_Sock(args.spinesd_ipaddr.c_str(), args.spinesd_port, proto);
        if (socket >= 0) break;
        
        // otherwise, try reconnecting
        std::cout << "Error setting up the spines socket, Trying again in " << reconnect_wait_time_sec << " seconds\n";
        sleep(reconnect_wait_time_sec);
    }

    Spines_Connection connection;
    connection.socket = socket;
    connection.dest.sin_port = htons(args.mcast_port);
    connection.dest.sin_family = AF_INET;
    hostent h_ent;
    memcpy(&h_ent, gethostbyname(args.mcast_ipaddr.c_str()), sizeof(h_ent));
    memcpy(&connection.dest.sin_addr, h_ent.h_addr, sizeof(connection.dest.sin_addr));
    if (spines_setsockopt(connection.socket, IPPROTO_IP, SPINES_IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0) {
        std::cout << "MCAST: Spines setsockopt error\n";
      }
    std::cout << "MCAST set up done\n";

    return connection;
}

void* send_pending_messages_to_mcast_group(void* fn_args) {
    Spines_Connection spines_connection = ((struct Proxy_Messages_Thread_Args*)fn_args)->spines_conn;
    int ret, num_bytes;
    while (true) {
        if (!pending_messages.empty()) {
            Switcher_Message next_mesage = pending_messages.front();
            pending_messages.pop();
            
            // TODO think about how to use Switcher_Message_max_size here. the proxies need a max length when receiving messages
            num_bytes = sizeof(Switcher_Message);
            ret = spines_sendto(spines_connection.socket, (void *)&next_mesage, num_bytes, 0, (struct sockaddr *)&spines_connection.dest, sizeof(struct sockaddr)); 
            if(ret != num_bytes){
                std::cout << "Error: Spines sendto ret != num_bytes\n";
            }
        }
    }
}