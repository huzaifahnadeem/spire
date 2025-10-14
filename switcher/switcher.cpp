
#include "switcher.h"

#include <iostream>

extern "C" {
    #include "common/net_wrapper.h" 
    #include "spines/libspines/spines_lib.h" // for spines functions e.g. spines_sendto()
}


Args args;
const int Switcher_Message_max_size = MAX_SPINES_CLIENT_MSG; // TODO: put this somewhere common to the proxies and the switcher? MAX_SPINES_CLIENT_MSG = 50000 bytes

Spines_Connection* spines_connection_global = NULL;

int main(int ac, char **av) {
    parse_args(ac, av);

    // set up a spines multicast socket
    Spines_Connection spines_connection = setup_spines_multicast_sending_socket();
    spines_connection_global = &spines_connection;
    
    // this threads receives messages coming from the proxies (to let the switcher/operator know that it has applied the switch command -- not strictly necessary. also sets up the relavant socket for this)
    pthread_t handle_proxy_messages_thread;
    pthread_create(&handle_proxy_messages_thread, NULL, &setup_and_handle_spines_receiving_socket, NULL);
    sleep(1); // helps with output alignment (otherwise, prev thread's fn's outputs something in the middle of the output of the next thread's fn)

    // run a thread that checks for and reads and input coming in on the named input pipe
    pthread_t read_input_pipe_thread;
    pthread_create(&read_input_pipe_thread, NULL, &read_input_pipe, NULL);

    // wait for the threads before exiting
    pthread_join(read_input_pipe_thread, NULL);
    pthread_join(handle_proxy_messages_thread, NULL);

    return EXIT_SUCCESS;
}

void parse_args(int argc, char **argv) {
    std::stringstream usage_stream;
    usage_stream << "Usage: ./switcher spinesIP:port mcastIP:port recv_port\n";
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

    // port num to receive messages back from the proxies on
    args.switcher_msg_recv_port = std::stoi(argv[3]);
}

void* read_input_pipe(void* fn_arg) {
    UNUSED(fn_arg);
    // for now just read standard input. will come back to add the whole pipe reading thing
    std::string input;
    char empty[50] = "";
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
            auto now = std::chrono::high_resolution_clock::now();
            auto duration_since_epoch = now.time_since_epoch();
            std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration_since_epoch);
            std::chrono::microseconds us = std::chrono::duration_cast<std::chrono::microseconds>(duration_since_epoch);
            std::stringstream output;
            output << "Messages passed to spines successfully. [Timestamp: " << ns.count() << "ns. " << us.count() << "µs." << "]\n";
            std::cout << output.str();
            write_into_log(output.str());
        }
    }

    return NULL;
}

Spines_Connection setup_spines_multicast_sending_socket() {
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

void* setup_and_handle_spines_receiving_socket(void* fn_arg) {
    int recv_sock;
    fd_set mask, tmask;
    char buff[MAX_LEN];

    FD_ZERO(&mask);
    int proto = SPINES_RELIABLE; // need to use SPINES_RELIABLE and not SPINES_PRIORITY. This is because we need to be sure the message is delivered. SPINES_PRIORITY can drop messages. might need to think more though (but thats for later)
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
    *  this often */
    struct timeval spines_timeout, *t;
    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;

    recv_sock = -1; // -1 is not a real socket so init to that
    recv_sock = Spines_Sock(args.spinesd_ipaddr.c_str(), args.spinesd_port, proto, args.switcher_msg_recv_port);
    if (recv_sock < 0) {
        std::cout << "switcher: Unable to connect to Spines (for recv_sock), trying again soon\n";
        t = &spines_timeout; 
    }
    else {
        std::cout << "switcher: Connected to Spines (for recv_sock)\n";
        FD_SET(recv_sock, &mask);
        t = NULL;
    }

    // handle messages:
    int num, ret;
    while (1) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);
        if (num > 0) {
            // message from a proxy
            if (recv_sock >= 0 && FD_ISSET(recv_sock, &tmask)) {
                // spines_recv does not give a way to find out the sender's address
                // ret = spines_recv(spines_sock, buff, MAX_LEN, 0);
                // so, instead we are using spines_recvfrom:
                struct sockaddr_in sender_addr;
                socklen_t sender_addr_structlen = sizeof(sender_addr); 
                ret = spines_recvfrom(recv_sock, buff, MAX_LEN, 0, (struct sockaddr *) &sender_addr, &sender_addr_structlen);
                if (ret <= 0) {
                    write_into_log("switcher: Error in spines_recvfrom with spines_sock>0 and : ret = " + std::to_string(ret) + " .dropping!\n");
                    spines_close(recv_sock);
                    FD_CLR(recv_sock, &mask);
                    recv_sock = -1;
                    t = &spines_timeout; 
                    continue;
                }
                else {
                    auto now = std::chrono::high_resolution_clock::now();
                    auto duration_since_epoch = now.time_since_epoch();
                    std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration_since_epoch);
                    std::chrono::microseconds us = std::chrono::duration_cast<std::chrono::microseconds>(duration_since_epoch);
                    
                    std::string sender_ipaddr;
                    int sender_port;
                    sockaddr_in_to_str(&sender_addr, &sender_addr_structlen, sender_ipaddr, sender_port);

                    std::stringstream output;
                    output << "Received a message from a proxy. (Address: " << sender_ipaddr << ":" << sender_port << "). [Timestamp: " << ns.count() << "ns. " << us.count() << "µs." << "]\n";
                    write_into_log(output.str());
                }
            }
        }
        else {
            // this happens when we havent connected to spire. so try again:
            recv_sock = Spines_Sock(args.spinesd_ipaddr.c_str(), args.spinesd_port, proto, args.switcher_msg_recv_port);
            if (recv_sock < 0) {
                std::cout << "switcher: Unable to connect to Spines (for recv_sock), trying again soon\n";
                spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                t = &spines_timeout; 
            }
            else {
                std::cout << "switcher: Connected to Spines (for recv_sock)\n";
                FD_SET(recv_sock, &mask);
                t = NULL;
            }
        }
    }

    return NULL;
}

void sockaddr_in_to_str(struct sockaddr_in *sa, socklen_t *sa_len, std::string &ipaddr, int &port){
    char * ip = inet_ntoa(sa->sin_addr);
    int sender_port = sa->sin_port;
    ipaddr = ip;
    port = sender_port;
}

void write_into_log(std::string output) {
    std::string data_file_path = "./switch_log.txt";
    std::ofstream datafile;

    if (std::filesystem::exists(data_file_path)) {
        datafile.open(data_file_path.c_str(), std::ios_base::app); // open in append mode
    } else {
        datafile.open(data_file_path.c_str(), std::ios_base::out); // creates new file (append mode does not)
    }
    
    if (datafile.is_open()) {
        datafile << "=== New Entry ===\n";
        datafile << output << "\n";    
        datafile << "=== End Entry ===\n\n";
        datafile.close();
    } else {
        std::cerr << "Error: Unable to open the log file (" << data_file_path << ")\n";
    }

    return;
}