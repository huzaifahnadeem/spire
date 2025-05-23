
#include "switcher.h"

#include <iostream>

extern "C" {
    #include "common/net_wrapper.h" 
    #include "spines/libspines/spines_lib.h" // for spines functions e.g. spines_sendto()
}

Args args;
std::queue <Switcher_Message> pending_messages;
const int Switcher_Message_max_size = MAX_SPINES_CLIENT_MSG; // TODO: put this somewhere common to the proxies and the switcher? MAX_SPINES_CLIENT_MSG = 50000 bytes

Spines_Connection* spines_connection_global = NULL;
int main(int ac, char **av) {
    parse_args(ac, av);

    // set up a spines multicast socket
    Spines_Connection spines_connection = setup_spines_multicast_socket();
    spines_connection_global = &spines_connection;

    // run a thread that checks for and reads and input coming in on the named input pipe
    pthread_t read_input_pipe_thread;
    pthread_create(&read_input_pipe_thread, NULL, &read_input_pipe, NULL);

    // run a thread that sends out any messages to the proxies
    // pthread_t proxy_messages_thread;
    // Proxy_Messages_Thread_Args message_thread_args = {.spines_conn = spines_connection};
    // pthread_create(&proxy_messages_thread, NULL, &send_pending_messages_to_mcast_group, (void*) &message_thread_args);

    // wait for the threads before exiting
    pthread_join(read_input_pipe_thread, NULL);
    // pthread_join(proxy_messages_thread, NULL);

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
    char empty[5] = "";
    while (true) {
        // the idea is that empty strings will be ignored
        // so using different combinations of empty and non empty strings
        // the following commands can be sent:
        // 1. change active system id (other vals are "")
        // 2. add new io proc with given path and optional id (if id not given then path will be the id).
        // 3. #2 but also change the active id to something else. id will be changed after adding an io proc so that only a single command is needed to add a new io proc then change to it
        // 4. remove an io proc that is not active
        // 5. remove an io proc that is currently active then change to the new given active id (if you try to remove currently active sys without giving a new active sys id, then command ignored)
        
        Switcher_Message message_to_send;
        std::cout << "\nnew_active_system_id: ";
        std::cin >> input;
        // message_to_send.new_active_system_id = (input == "."? empty: input.c_str()); // treat "." as an empty string
        strcpy(message_to_send.new_active_system_id, (input == "."? empty: input.c_str()));
        
        std::cout << "\nadd_io_proc_path: ";
        std::cin >> input;
        // message_to_send.add_io_proc_path = (input == "."? empty: input.c_str());
        strcpy(message_to_send.add_io_proc_path, (input == "."? empty: input.c_str()));
        
        std::cout << "\nadd_io_proc_spinesd_addr: ";
        std::cin >> input;
        // message_to_send.add_io_proc_spinesd_addr = (input == "."? empty: input.c_str());
        strcpy(message_to_send.add_io_proc_spinesd_addr, (input == "."? empty: input.c_str()));
        
        std::cout << "\nadd_io_proc_id: ";
        std::cin >> input;
        // message_to_send.add_io_proc_id = (input == "."? empty: input.c_str());
        strcpy(message_to_send.add_io_proc_id, (input == "."? empty: input.c_str()));
        
        std::cout << "\nremove_io_proc_id: ";
        std::cin >> input;
        // message_to_send.remove_io_proc_id = (input == "."? empty: input.c_str());
        strcpy(message_to_send.remove_io_proc_id, (input == "."? empty: input.c_str()));

        // pending_messages.push(message_to_send); // having a queue will be useful when we are reading inputs from a file/pipe as it will help avoid thread sync issues.

        int num_bytes = sizeof(Switcher_Message);
        int ret = spines_sendto(spines_connection_global->socket, (void *)&message_to_send, num_bytes, 0, (struct sockaddr *)&(spines_connection_global->dest), sizeof(struct sockaddr)); 
        if(ret != num_bytes) {
            std::cout << "Error: Spines sendto ret != num_bytes\n";
        }
        else {
            std::cout << "Messages passed to spines successfully\n";
        }
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

// // the `Spines_Mcast_SendOnly_Sock` function from net_wrapper.c uses some spire-specific macro defines (SPINES_INT_PORT & SPINES_EXT_PORT) and i would need to make some changes there or somewhere else to allow having a management network. so i adapt the function here
// int my_Spines_Mcast_SendOnly_Sock(const char *sp_addr, int sp_port, int proto) 
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
//     kpaths = 0;
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


Spines_Connection setup_spines_multicast_socket() {
    int proto, socket, reconnect_wait_time_sec, ttl;
    proto = SPINES_PRIORITY; // note that even though the option are `SPINES_RELIABLE` and `SPINES_PRIORITY`. Only `SPINES_PRIORITY` is compatible with mcast. the other one wont work
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
            if(ret != num_bytes) {
                std::cout << "Error: Spines sendto ret != num_bytes\n";
            }
            else {
                std::cout << "Messages passed to spines successfully\n";
            }
        }
    }
}