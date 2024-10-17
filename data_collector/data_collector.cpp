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

#define DATAFILE "./data_log.txt"
#define SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines
#define SPINES_CONNECT_USEC 0



// TODO: i should probably use spines_socket() in /Users/huzaifahnadeem/spire/spines/libspines/spines_lib.c  instead of Spines_Sock()




void write_data(char* data_buff, size_t data_buff_len);
void usage_check(int ac, char **av);

int main(int ac, char **av){
    usage_check(ac, av);

    int proto, my_port, spines_sock, num, ret;
    char* spinesd_ip_addr = strtok(strdup(av[1]), ":");
    int spinesd_port = atoi(strtok(NULL, ":"));
    struct timeval spines_timeout, *t;
    fd_set mask, tmask;
    char buff[MAX_LEN];

    FD_ZERO(&mask);
    // proto = SPINES_PRIORITY;
    proto = SPINES_RELIABLE;
    my_port = 9999; // TODO: figure out proper way

    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
     *  this often */
    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;

    spines_sock = -1; // -1 is not a real socket so init to that
    spines_sock = Spines_Sock(spinesd_ip_addr, spinesd_port, proto, my_port);
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
                // ret = spines_recvfrom(spines_sock, buff, MAX_LEN, 0, NULL, 0);
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
                write_data(buff, MAX_LEN);
                std::cout << "data_collector: Data has been written to disk\n";
            }
        }
        else {
            // this happens when we havent connected to spire. so try again:
            spines_sock = Spines_Sock(spinesd_ip_addr, spinesd_port, proto, my_port);
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
    if (ac < 2 || ac > 3) {
        printf("Invalid args\n");
        printf("Usage: %s spinesAddr:spinesPort [-port=PORT]\n", av[0]);
        // will need the address/port of the spines daemon that will run alongside this data_collector. it receives from the the two proxies through that
        exit(EXIT_FAILURE);
    }
}

void write_data(char* data_buff, size_t data_buff_len) {
    // initially, just keeping it simple so our 'database' is just a file
    // later on we can have something better like a proper database or whatever is needed.

    std::time_t timestamp;
    std::ofstream datafile;
    
    datafile.open(DATAFILE, std::ios_base::app); // open in append mode
    timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    // datafile << "Time: " << std::ctime(&timestamp) << "From: " << "<from>\n" << "Data: " <<"<some data here>.\n\n";
    datafile << "Time: " << std::ctime(&timestamp) << "From: " << "<from>\n" << "Data: " << data_buff << "\n\n";
    datafile.close();
}