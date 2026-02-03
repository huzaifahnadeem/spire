#define TESTING 1

// TODO Ovation: review all the #include statements, probably dont need some of them (like common/itrc.h)

// prior (spire io proc #includes)
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string>

// child process related #includes
#include <sys/prctl.h> // required for prctl() (used to kill this proc if the parents gets a sighup)
#include <signal.h> // has the declaration for SIGHUP

// libmodbus related #includes
#include <modbus/modbus.h> // sudo yum install libmodbus-devel; # or `sudo apt-get install libmodbus-dev;`
#include <iostream>
#include <cerrno>
#include <cstring>
#include <unistd.h>

// for printing hex
#include <iomanip>

// prior (spire io proc #includes)
// NOTE: in the Makefile, we have $SPIRE_DIR. Set that to the right spire directory if you do not want to use the default path

namespace system_ns {
    extern "C" {
        #include "common/net_wrapper.h"  
        // #include "common/def.h"       // x   
        #include "common/itrc.h"         
        // #include "prime/libspread-util/include/spu_events.h" // x 
        // #include "prime/stdutil/include/stdutil/stdcarr.h" // x
        // #include "spines/libspines/spines_lib.h" // x
    }
}
#define IPC_TO_PARENT_RTUPLCCLIENT "/tmp/ssproxy_ipc_ioproc_to_proxy"
#define IPC_FROM_PARENT_RTUPLCCLIENT "/tmp/ssproxy_ipc_proxy_to_ioproc"
// #define IPC_TO_PARENT_HMICLIENT "/tmp/hmiproxy_ipc_ioproc_to_proxy"
// #define IPC_FROM_PARENT_HMICLIENT "/tmp/hmiproxy_ipc_proxy_to_ioproc"

int HMI_scenario = PNNL;
// int HMI_scenario = JHU;

#if !(TESTING)
void parse_args(int ac, char **av, std::string &ovation_ip_addr, int &ovation_port);
void ovation_setup(std::string ip_addr, int port);
#endif
void setup_ipc_with_parent();
void send_to_parent(system_ns::signed_message * mess);
#if !(TESTING)
void *handler_msg_from_itrc(void *arg);
void *listen_on_parent_sock(void *arg);

int ioproc_ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;
#endif

int ipc_sock_to_parent, ipc_sock_from_parent;
std::string ipc_path_suffix;
#if !(TESTING)
int proxy_id_for_itrc = -1; // only used for RTU/PLC clients
// bool client_is_hmi;
#endif

// void print_hex(const uint8_t* data, int length) {
//     // Set the stream to hexadecimal format and fill with zeros
//     std::cout << std::hex << std::setfill('0');

//     for (size_t i = 0; i < length; ++i) {
//         // Cast to unsigned int to print as a number (not a character)
//         // std::setw(2) ensures two characters are used for each byte
//         std::cout << std::setw(2) << static_cast<unsigned int>(data[i]) << " ";
//     }
//     std::cout << std::endl;

//     // Reset stream formatters if needed elsewhere in the program
//     std::cout << std::dec << std::setfill(' ');
// }
std::string uint8_t_array_to_hex_string(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');

    for (size_t i = 0; i < length; ++i) {
        // Cast uint8_t to int to ensure correct output with iomanipulators
        ss << std::setw(2) << static_cast<int>(data[i]);
    }

    return ss.str();
}

void * modbus_tcp_server_loop(void * arg) {
    UNUSED(arg);

    // Create a new Modbus TCP context
    // We listen on all interfaces ("0.0.0.0") on port 502 (default Modbus port)
    // Note: using port 502 usually requires root privileges. Change to 1502 or 5020 for non-root testing.
    int port = 5020;
    modbus_t *ctx = modbus_new_tcp("0.0.0.0", port);

    if (ctx == nullptr) {
        std::cerr << "Unable to create the libmodbus context" << std::endl;
        return NULL;
    }

    // Set Debug mode (optional, prints raw bytes to console)
    modbus_set_debug(ctx, TRUE);

    // Allocate Memory Map (The "Database" of the server) // TODO Ovation: This will be more complicated and need to match spire's. This is where we keep track of the state too, i think.
    // We allocate 14 (output) bits, 14 input bits, 16 (output/holding, word) registers, and 0 input (word) registers. Registers are 16 bits in modbus
    int NUM_POINT_ACTUAL = 16; // in PNNL plc, there are actually 16 output registers but only NUM_POINT = 8 are used
    int NUM_INPUT_REGISTERS = 0; // input registers are not used in the pnnl scenario
    
    // #if (TESTING)
    // int NUM_BREAKER = 14;
    // #endif 

    modbus_mapping_t *mb_mapping = modbus_mapping_new(NUM_BREAKER, NUM_BREAKER, NUM_POINT_ACTUAL, NUM_INPUT_REGISTERS);
    if (mb_mapping == nullptr) {
        std::cerr << "Failed to allocate the mapping: " << modbus_strerror(errno) << std::endl;
        modbus_free(ctx);
        return NULL;
    }

    // Initialize some values for testing (setting it to the initial values the same as PNNL PLC)
    mb_mapping->tab_registers[0]  = 138; // Holding Register 0.
    mb_mapping->tab_registers[1]  = 0;   // Holding Register 1
    mb_mapping->tab_registers[2]  = 138;
    mb_mapping->tab_registers[3]  = 0;
    mb_mapping->tab_registers[4]  = 138;
    mb_mapping->tab_registers[5]  = 0;
    mb_mapping->tab_registers[6]  = 138;
    mb_mapping->tab_registers[7]  = 0;
    mb_mapping->tab_registers[8]  = 0;
    mb_mapping->tab_registers[9]  = 0;
    mb_mapping->tab_registers[10] = 0;
    mb_mapping->tab_registers[11] = 0;
    mb_mapping->tab_registers[12] = 0;
    mb_mapping->tab_registers[13] = 0;
    mb_mapping->tab_registers[14] = 0;
    mb_mapping->tab_registers[15] = 32767; // for fun

    mb_mapping->tab_bits[0]  = 0;    // Coil 0.
    mb_mapping->tab_bits[1]  = 0;    // Coil 1
    mb_mapping->tab_bits[2]  = 0;
    mb_mapping->tab_bits[3]  = 0;
    mb_mapping->tab_bits[4]  = 0;
    mb_mapping->tab_bits[5]  = 0;
    mb_mapping->tab_bits[6]  = 0;
    mb_mapping->tab_bits[7]  = 0;
    mb_mapping->tab_bits[8]  = 0;
    mb_mapping->tab_bits[9]  = 0;
    mb_mapping->tab_bits[10] = 0;
    mb_mapping->tab_bits[11] = 0;
    mb_mapping->tab_bits[12] = 0;
    mb_mapping->tab_bits[13] = 0;

    mb_mapping->tab_input_bits[0]  = 0;    // Input Status Bit 0.
    mb_mapping->tab_input_bits[1]  = 1;    // Input Status Bit 1
    mb_mapping->tab_input_bits[2]  = 0;
    mb_mapping->tab_input_bits[3]  = 1;
    mb_mapping->tab_input_bits[4]  = 1;
    mb_mapping->tab_input_bits[5]  = 0;
    mb_mapping->tab_input_bits[6]  = 0;
    mb_mapping->tab_input_bits[7]  = 1;
    mb_mapping->tab_input_bits[8]  = 0;
    mb_mapping->tab_input_bits[9]  = 1;
    mb_mapping->tab_input_bits[10] = 0;
    mb_mapping->tab_input_bits[11] = 1;
    mb_mapping->tab_input_bits[12] = 0;
    mb_mapping->tab_input_bits[13] = 1;

    // Listen for incoming connections
    // This creates the socket and binds it
    int server_socket = modbus_tcp_listen(ctx, 1);
    if (server_socket == -1) {
        std::cerr << "Unable to listen: " << modbus_strerror(errno) << std::endl;
        modbus_free(ctx);
        return NULL;
    }
    
    std::cout << "Server listening on port " << port << "..." << std::endl;

    // Main Server Loop
    while (true) {
        // Accept a client connection
        int rc = modbus_tcp_accept(ctx, &server_socket);
        if (rc == -1) {
            std::cerr << "Error accepting connection: " << modbus_strerror(errno) << std::endl;
            break;
        }

        // TODO Ovation: The following shows an example of how client messages are processed in general. In our case, we need to check if its a read or a write kind of message. Reads can be replied like this (if our state is stored in mb_mapping), but writes are sent down to proxy and we MAY require some message encapsulation or processing to make it compatible with proxy/message broker.
        // Loop to handle requests from the connected client
        // buffer to store raw query
        uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
        
        while (true) {
            // Receive a query
            int query_len = modbus_receive(ctx, query);
            
            if (query_len > 0) {
                // Determine what the request is and reply automatically
                // This function updates the mb_mapping if it's a Write, 
                // and reads from it if it's a Read.

                std::cout << "Query: ";
                std::string query_hex = uint8_t_array_to_hex_string(query, query_len);
                // std::cout << query_hex << " -- ";
                // print_hex(query, query_len);
                std::cout << query_hex << "\n";
                std::string transaction_id = query_hex.substr(0, 4);
                // std::stoi can be used with hex like std::stoi(str, nullptr, 16)
                std::cout << "Transaction ID: 0x" << std::hex << std::setfill('0') << std::setw(4) << std::stoi("0x" + transaction_id, nullptr, 16) << std::dec << std::setfill(' ') << std::endl; // first 2 bytes e.g. 0x 00 01. uniquely identifies each request. responses repeat this.
                std::string protocol_id = query_hex.substr(4, 4);
                std::cout << "Protocol ID: 0x" << std::hex << std::setfill('0') << std::setw(4) << std::stoi("0x" + protocol_id, nullptr, 16) << std::dec << std::setfill(' ') << std::endl; // second 2 bytes e.g. 0x __ __ 00 00. will always be 00 00 for modbus
                std::string length = query_hex.substr(8, 4);
                std::cout << "Length: 0x" << std::hex << std::setfill('0') << std::setw(4) << std::stoi("0x" + length, nullptr, 16) << std::dec << std::setfill(' ') << std::endl; // following 2 bytes e.g. 0x __ __ __ __ 00 06. identifies the number of bytes in the message that follow. It is counted from Unit Identifier (next) to the end of the message
                std::string unit_id = query_hex.substr(12, 2);
                std::cout << "Unit ID: 0x" << std::hex << std::setfill('0') << std::setw(2) << std::stoi("0x" + unit_id, nullptr, 16) << std::dec << std::setfill(' ') << std::endl; // following 1 byte e.g. 0x __ __ __ __ __ __ ff. identifies the modbus server unit. repeated by the server in its messages.
                std::string mb_fn_code = query_hex.substr(14, 2); // following 1 byte is the function code e.g. 0x __ __ __ __ __ __ __ 05. 
                std::cout << "Modbus function code: 0x" << std::hex << std::setfill('0') << std::setw(2) << std::stoi("0x" + mb_fn_code, nullptr, 16) << std::dec << std::setfill(' ');
                if (mb_fn_code == "01") {
                    std::cout << " = read coil status" << "\n";
                }
                else if (mb_fn_code == "02") {
                    std::cout << " = read input status" << "\n";
                }
                else if (mb_fn_code == "03") {
                    std::cout << " = read holding registers" << "\n";
                }
                else if (mb_fn_code == "05") {
                    std::cout << " = force single coil" << "\n";
                }
                else if (mb_fn_code == "06") { // not used in pnnl scenario
                    std::cout << " = preset single register" << "\n";
                }
                else {
                    std::cout << "\n";
                }
                std::string data = query_hex.substr(16);
                std::cout << "Data: 0x" << std::hex << std::setfill('0') << std::setw(data.length()) << std::stoi("0x" + data, nullptr, 16) << std::dec << std::setfill(' ') << std::endl; // remaining bytes. variable length. 

                if (mb_fn_code == "05" || mb_fn_code == "06") { // i.e. a write command 
                    // send these commands to the parent process (proxy)
                    // proxy expects these messages in spire format to need to encapsulate it properly
                    std::string data_dot_addr = query_hex.substr(16, 4);
                    std::cout << "\t.addr: 0x" << std::hex << std::setfill('0') << std::setw(4) << std::stoi("0x" + data_dot_addr, nullptr, 16) << std::dec << std::setfill(' ') << std::endl; // first 2 bytes in data
                    std::string data_dot_val = query_hex.substr(20, 4);
                    std::cout << "\t.val: 0x" << std::hex << std::setfill('0') << std::setw(4) << std::stoi("0x" + data_dot_val, nullptr, 16) << std::dec << std::setfill(' ') << std::endl; // second 2 bytes in data. 0x0000 means OFF state. 0xFF00 means ON state

                    int32_t breaker_pos;
                    int data_dot_addr_int = std::stoi("0x" + data_dot_addr, nullptr, 16);
                    if (data_dot_addr_int >= 0 && data_dot_addr_int < NUM_BREAKER) { 
                        breaker_pos = data_dot_addr_int;
                    }
                    else {
                        std::cout << "ERROR. Invalid data.addr = 0x" << data_dot_addr << "\n";
                    }
                    int val;
                    if (data_dot_val == "FF00") { // i.e. ON state
                        val = 1;
                    }
                    else if (data_dot_val == "0000") {
                        val = 0;
                    }
                    else {
                        std::cout << "ERROR. Invalid data.val = 0x" << data_dot_val << "\n";
                    }
                    system_ns::seq_pair seq = {.incarnation = system_ns::My_Incarnation, .seq_num = std::stoi(transaction_id)};
                    system_ns::signed_message * mess_to_send;
                    mess_to_send = system_ns::PKT_Construct_RTU_Feedback_Msg( // calling this fn similar to how SM.read_from_hmi calls it
                        seq,                        // = seq_pair seq
                        HMI_scenario,               // = int32u scen_type
                        system_ns::BREAKER,         // = int32u type
                        PNNL_RTU_ID,                // = int32u sub
                        PNNL_RTU_ID,                // = int32u rtu
                        breaker_pos,                // = int32u offset
                        val                         // = int32_t val
                    );
                    send_to_parent(mess_to_send);
                }
                else {
                    // reads can be directly replied to from here
                    modbus_reply(ctx, query, query_len, mb_mapping);
                }
            } else if (query_len == -1) {
                // Connection closed by the client or error
                break; 
            }
        }
        
        std::cout << "Client disconnected." << std::endl;
    }

    // Cleanup
    std::cout << "Cleaning up..." << std::endl;
    modbus_mapping_free(mb_mapping);
    close(server_socket);
    modbus_free(ctx);
    
    return NULL;
}

int main(int ac, char **av) {
    #if !(TESTING)
    // this kills this process if the parent gets a SIGHUP:
    prctl(PR_SET_PDEATHSIG, SIGHUP); // TODO: this might not be the best way to do this. check the second answer in the following (answer by Schof): https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/17589555
    
    std::string ovation_ip_addr;
    int ovation_port;

    parse_args(ac, av, ovation_ip_addr, ovation_port); // TODO Ovation: may need to adjust this for ovation

    std::cout << "io_process for ovation (" << ipc_path_suffix << ") starts (with suffix: " + ipc_path_suffix + ")\n";
    #endif
    
    setup_ipc_with_parent();
    
    #if !(TESTING)
    pthread_t parent_listen_thread, handle_msg_from_ovation_thread;
    
    ovation_setup(ovation_ip_addr, ovation_port); // TODO Ovation: this is one of the major places where we need to adjust logic. we do not have an ITRC client thread like we used to. Instead there is some other cusom thread that needs to send messages to the Ovation system instance as well as receive messages from it (and potentially forwarding these received messages to a diff function to unwrap it or smth like that. messages are expected to be in modbus protocol).

    pthread_create(&handle_msg_from_ovation_thread, NULL, &handler_msg_from_ovation, NULL); // receives messages from itrc client (ioproc)
    pthread_create(&parent_listen_thread, NULL, &listen_on_parent_sock, NULL); // listens for command messages coming from the parent proc
    
    pthread_join(handle_msg_from_ovation_thread, NULL);
    pthread_join(parent_listen_thread, NULL);

    return 0;

    #endif
    
    struct timeval now;
    gettimeofday(&now, NULL);
    system_ns::My_Incarnation = now.tv_sec; // happens in itrc init fn in spire io proc
    pthread_t modbus_tcp_server_loop_thread; 
    pthread_create(&modbus_tcp_server_loop_thread, NULL, &modbus_tcp_server_loop, NULL);


    
    pthread_join(modbus_tcp_server_loop_thread, NULL);
    return 0;
}

#if !(TESTING)
void parse_args(int ac, char **av, std::string &ovation_ip_addr, int &ovation_port) {
    if (ac != 6) {
        printf("Invalid args\n");
        printf("Usage (run as a child process): ./path/to/io_process spinesIPAddr spinesPort ipc_path_suffix proxy_id_for_itrc client_is_hmi\n");
        exit(EXIT_FAILURE);
    }
    // by convention av[0] is just the prog name
    ovation_ip_addr = av[1];
    ovation_port = atoi(av[2]);
    ipc_path_suffix = av[3];
    proxy_id_for_itrc = atoi(av[4]);

    std::string client_type_arg = av[5];
    if (client_type_arg == "1")
        client_is_hmi = true;
    else
        client_is_hmi = false;
}

void _init_plcrtu(std::string spinesd_ip_addr, int spinesd_port, system_ns::itrc_data &itrc_data_main, system_ns::itrc_data &itrc_data_itrcclient, int &sock_main_to_itrc_thread, std::string proxy_prime_keys_dir, std::string proxy_sm_keys_dir, std::string ssproxy_ipc_main_procfile, std::string ssproxy_ipc_itrc_procfile)
{   
    struct timeval now;
    system_ns::My_Global_Configuration_Number = 0;
    system_ns::Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    system_ns::My_Incarnation = now.tv_sec;
    // Seq_Num = 1;
    
    system_ns::Type = RTU_TYPE;
    system_ns::Prime_Client_ID = MAX_NUM_SERVER_SLOTS + system_ns::My_ID;
    system_ns::My_IP = system_ns::getIP();
    system_ns::My_ID = proxy_id_for_itrc;

    // Setup IPC for the RTU Proxy main thread
    printf("PROXY: Setting up IPC for RTU proxy thread (in io_proc)\n");
    memset(&itrc_data_main, 0, sizeof(system_ns::itrc_data));
    sprintf(itrc_data_main.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_main.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_main.ipc_local, "%s%d", ssproxy_ipc_main_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_main.ipc_remote, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), system_ns::My_ID);
    sock_main_to_itrc_thread = system_ns::IPC_DGram_Sock(itrc_data_main.ipc_local);

    // Setup IPC for the Worker Thread (running the ITRC Client)
    memset(&itrc_data_itrcclient, 0, sizeof(system_ns::itrc_data));
    sprintf(itrc_data_itrcclient.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.ipc_local, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_itrcclient.ipc_remote, "%s%d", ssproxy_ipc_main_procfile.c_str(), system_ns::My_ID);
    sprintf(itrc_data_itrcclient.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itrc_data_itrcclient.spines_ext_port);   
}

void ovation_setup(std::string ip_addr, int port) {
	// TODO Ovation will probably have a separate HMI for ovation (which is synched up with the spire hmi. synched up as in shows the same stuff and is identical)
	// if (client_is_hmi) { 
    //     // TODO Ovation
    // }
    // else { // client is PLC/RTU
    //     // TODO Ovation
    // }

	// go with plc only for now


}

#endif

void setup_ipc_with_parent() {
    ipc_sock_to_parent = system_ns::IPC_DGram_SendOnly_Sock(); // for sending something TO the parent
    std::string ipc_from_parent;
    ipc_from_parent = IPC_FROM_PARENT_RTUPLCCLIENT;
    ipc_sock_from_parent = system_ns::IPC_DGram_Sock((ipc_from_parent + ipc_path_suffix).c_str()); // for receiving something FROM the parent
}

void send_to_parent(system_ns::signed_message * mess)
{   
    std::string ipc_to_parent = IPC_TO_PARENT_RTUPLCCLIENT;
    int nbytes = sizeof(system_ns::signed_message) + sizeof(system_ns::rtu_feedback_msg);
    system_ns::IPC_Send(ipc_sock_to_parent, (void *)mess, nbytes, (ipc_to_parent + ipc_path_suffix).c_str());
    std::cout << "io_process for ovation (" << ipc_path_suffix << "): The message has been forwarded to the parent proc.\n";
}

#if !(TESTING)

void *handler_msg_from_ovation(void *arg)
{   // TODO Ovation: should use modbus_tcp_server_loop() here or with this fn
    UNUSED(arg);
    
    std::cout << "io_process for ovation (" << ipc_path_suffix << "): initialized handler_msg_from_itrc() \n";

    fd_set active_fd_set, read_fd_set;
    int num;
    // Init data structures for select()
    FD_ZERO(&active_fd_set);
    FD_SET(ioproc_ipc_sock_main_to_itrcthread, &active_fd_set);
    
    while(1) {
        read_fd_set = active_fd_set;
        num = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
        if (num > 0) {
            if(FD_ISSET(ioproc_ipc_sock_main_to_itrcthread, &read_fd_set)) { // if there is a message from itrc client (main)
                recv_then_fw_to_parent(ioproc_ipc_sock_main_to_itrcthread, 0, NULL); // TODO Ovation: do not need to always send the system instance message to the parent (i.e the Proxy) in the case of Ovation. Message needs to be sent to the parent (after some potential message unwrapping/wrapping) if the client's state is to be updated like e.g. close breaker type messages. But if the message is a client state polling message then do not forward to parent. Instead, need to use the state stored locally here to create a reply message and send that back to system instance (i.e. Ovation).
            }
        }
    }

    return NULL;
}

void *listen_on_parent_sock(void *arg) {
    UNUSED(arg);

    int ret; 
    char buf[MAX_LEN];
    system_ns::signed_message *mess;
    int nbytes;

    for (;;) {
        std::cout << "io_process for ovation (" << ipc_path_suffix << "): Waiting to receive something on the parent socket\n";
        ret = system_ns::IPC_Recv(ipc_sock_from_parent, buf, MAX_LEN);
        if (ret < 0) {
            std::cout << "io_process for ovation (" << ipc_path_suffix << "): IPC_Rev failed. ret = " << ret << "\n";
        }
        else {
            std::cout << "io_process for ovation (" << ipc_path_suffix << "): Received a message from the parent. ret = " << ret << "\n";
            mess = (system_ns::signed_message *)buf;
            nbytes = sizeof(system_ns::signed_message) + mess->len;
            ret = system_ns::IPC_Send(ioproc_ipc_sock_main_to_itrcthread, (void *)mess, nbytes, ioproc_mainthread_to_itrcthread_data.ipc_remote); // TODO Ovation: instead of sending it to ITRC thread, need to instead use it to keep track of current state. 
            if (ret < 0) {
                std::cout << "io_process for ovation (" << ipc_path_suffix << "): Failed to sent message to the IRTC thread. ret = " << ret << "\n";
            }
            std::cout << "io_process for ovation (" << ipc_path_suffix << "): The message has been forwarded to the IRTC thread. ret = " << ret << "\n";

        }
    }
    return NULL;
}
#endif