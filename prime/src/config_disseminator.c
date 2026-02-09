/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design
 *   Daniel Qian          Contributions to Trip Master and IDS
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2023 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE.
 *
 */

#define _GNU_SOURCE
#define __USE_MISC

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>

#include "net_wrapper.h"

#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "spines_lib.h"

#define MAX_FILENAME_LEN  100
//#define MAX_FRAGMENT_SIZE MAX_SPINES_CLIENT_MSG
#define MAX_FRAGMENT_SIZE (MAX_SPINES_CLIENT_MSG - 12) // 12 == size of conf_fragment

#define DEFAULT_CONF_ID     1
#define DEFAULT_SPINES_PORT 8200
#define DEFAULT_CONF_FILE   "post_config.yaml"

typedef struct dummy_conf_fragment {
    int32u conf_id;
    int32u total_fragments;
    int32u fragment_index;
} conf_fragment;

static const sp_time      Repeat_Timeout    = {1, 0};

static char   Spines_IP_Addr[16]              = "";
static int16u Spines_Port                     = DEFAULT_SPINES_PORT;
static char   Conf_Filename[MAX_FILENAME_LEN] = DEFAULT_CONF_FILE;
static int32u Conf_ID                         = DEFAULT_CONF_ID;

static int                Ctrl_Spines       = -1; /* Spines configuration/control network socket */
static struct sockaddr_in Spines_Conf_Addr;

static void Usage(int argc, char **argv);
static void Print_Usage(void);
static void Init_Network(void);
static int Init_Spines_Sock(const char *sp_addr, int sp_port);
static void Broadcast_Conf(int code, void *dummy);

int main(int argc, char **argv)
{
    Alarm_set_types(DEBUG);

    Usage(argc,argv);

    Alarm(DEBUG, "Conf_ID: %d\n", Conf_ID);
    Alarm(DEBUG, "Conf_Filename: %s\n", Conf_Filename);
    Alarm(DEBUG, "Spines_IP_Addr: %s\n", Spines_IP_Addr);
    Alarm(DEBUG, "Spines_Port: %hu\n", Spines_Port);

    Init_Network();

    E_init();
    E_queue(Broadcast_Conf, 0, NULL, Repeat_Timeout);

    E_handle_events(); 
}

static void Usage(int argc, char**argv)
{
    int ret; 

    while(--argc > 0) {
        argv++;

        if ( (argc > 1) && (!strncmp(*argv, "-i", 2)) ) {
            ret = sscanf(argv[1], "%u", &Conf_ID);
            if (ret != 1) {
                Alarm(PRINT, "Invalid configuration ID: %s\n", argv[1]);
                Print_Usage();
            }
            argc--; argv++;
        }
        else if ( (argc > 1) && (!strncmp(*argv, "-c", 2)) ) {
            ret = snprintf(Conf_Filename, sizeof(Conf_Filename), "%s", argv[1]);
            if (ret < 0 || ret >= sizeof(Conf_Filename)) {
                Alarm(PRINT, "Invalid configuration filename (ret = %d): %s\n", ret, argv[1]);
                Print_Usage();
            }
            argc--; argv++;
        }
        else if ( (argc > 1) && (!strncmp(*argv, "-a", 2)) ) {
            ret = snprintf(Spines_IP_Addr, sizeof(Spines_IP_Addr), "%s", argv[1]);
            if (ret < 0 || ret >= sizeof(Spines_IP_Addr)) {
                Alarm(PRINT, "Invalid Spines IP address: %s\n", argv[1]);
                Print_Usage();
            }
            argc--; argv++;
        }
        else if ( (argc > 1) && (!strncmp(*argv, "-p", 2)) ) {
            ret = sscanf(argv[1], "%hu", &Spines_Port);
            if (ret != 1) {
                Alarm(PRINT, "Invalid Spines port: %s\n", argv[1]);
                Print_Usage();
            }
            argc--; argv++;
        }
        else {
            Print_Usage();
        }
    }
}

static void Print_Usage(void)
{
  Alarm(EXIT, "Usage: ./config_disseminator \n"
              "    [-i config_id]   : Global configuration ID (must match ID in config_file). Default: %d\n"
              "    [-c config_file] : Default: %s\n"
              "    [-a spines_addr] : IP address of Spines daemon to connect to. Default: IPC on localhost)\n"
              "    [-p spines_port] : Port for Spines configuration network. Default: %hu\n",
              DEFAULT_CONF_ID, DEFAULT_CONF_FILE, DEFAULT_SPINES_PORT);
}

static void Init_Network(void)
{
    struct hostent h_ent;

    /* Create Spines socket */
    Ctrl_Spines = Init_Spines_Sock(Spines_IP_Addr, Spines_Port);
    if (Ctrl_Spines < 0 ) {
        /* TODO try reconnecting? */
        Alarm(EXIT, "Error setting up control spines network, exiting\n");
    }

    /* Initialize Spines multicast address */
    memcpy(&h_ent, gethostbyname(CONF_SPINES_MCAST_ADDR), sizeof(h_ent));
    memcpy(&Spines_Conf_Addr.sin_addr, h_ent.h_addr, sizeof(Spines_Conf_Addr.sin_addr));
    
    Spines_Conf_Addr.sin_family = AF_INET;
    Spines_Conf_Addr.sin_port   = htons(CONF_SPINES_MCAST_PORT);
}

/* Connect to Spines at specified IP and port */
static int Init_Spines_Sock(const char *sp_addr, int sp_port)
{
    int sk, ret, protocol, proto;
    struct sockaddr_in spines_addr;
    struct sockaddr_un spines_uaddr;
    int16u prio, kpaths;
    spines_nettime exp;

    Alarm(DEBUG, "Initiating Spines connection: %s:%d\n", sp_addr, sp_port);

    proto = SPINES_PRIORITY;
    protocol = 8 | (proto << 8);

    if (!strcmp(sp_addr, "")) {
        /* Address not specified, connect to my local daemon via IPC */
        spines_uaddr.sun_family = AF_UNIX;
        sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", sp_port);
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr); 
    } else {
        /* Address specified, connect via TCP */
        memset(&spines_addr, 0, sizeof(spines_addr));
        spines_addr.sin_family      = AF_INET;
        spines_addr.sin_port        = htons(sp_port);
        spines_addr.sin_addr.s_addr = inet_addr(sp_addr);
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_addr);
    }

    if (sk < 0) {
        perror("Spines_Sock: error creating spines socket!");
        return sk;
    }

    /* setup kpaths = 0 (flooding) */
    kpaths = 0;
    if ((ret = spines_setsockopt(sk, 0, SPINES_DISJOINT_PATHS, (void *)&kpaths, sizeof(int16u))) < 0) {
        printf("Spines_Sock: spines_setsockopt failed for disjoint paths = %u\n", kpaths);
        return ret;
    }

    /* setup intrusion-tolerant priority dissem */
    exp.sec  = SPINES_EXP_TIME_SEC;
    exp.usec = SPINES_EXP_TIME_USEC;
    
    if ((ret = spines_setsockopt(sk, 0, SPINES_SET_EXPIRATION, (void *)&exp, sizeof(spines_nettime))) < 0) {
        printf("Spines_Sock: error setting expiration time to %u sec %u usec\n", exp.sec, exp.usec);
        return ret;
    }

    /* set priority */
    prio = 10; /* somewhat arbitrary choice */
    if ((ret = spines_setsockopt(sk, 0, SPINES_SET_PRIORITY, (void *)&prio, sizeof(int16u))) < 0) {
        printf("Spines_Sock: error setting priority to %u\n", prio);
        return ret;
    }

    return sk;
}

static void Broadcast_Conf(int code, void *dummy)
{
    FILE *file;
    long file_size;
    int total_fragments;
    char buffer[sizeof(conf_fragment)+MAX_FRAGMENT_SIZE];
    conf_fragment *header;
    char *payload;
    int i;
    size_t bytes_to_read, bytes_read;
    int ret;

    header = (conf_fragment *)buffer;
    payload = &buffer[sizeof(conf_fragment)];

    /* Open file */
    file = fopen(Conf_Filename, "rb");
    if (file == NULL) {
        Alarm(EXIT, "Failed to open file: %s", Conf_Filename);
    }

    /* Get the total file size */
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Calculate the total number of fragments */
    total_fragments = (file_size + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;

    for (i = 0; i < total_fragments; i++) {
        /* Set the fragment header */
        header->fragment_index = i;
        header->total_fragments = total_fragments;
        header->conf_id = Conf_ID;

        /* Read the next chunk of the file */
        bytes_to_read = (i == total_fragments - 1) ? (file_size - i * MAX_FRAGMENT_SIZE) : MAX_FRAGMENT_SIZE;
        bytes_read = fread(payload, 1, bytes_to_read, file);
        if (bytes_read == 0) {
            break;  // No more data to read
        }

        // Send the data chunk
        ret = spines_sendto(Ctrl_Spines, buffer, sizeof(conf_fragment) +
                            bytes_read, 0, (struct sockaddr *)&Spines_Conf_Addr,
                            sizeof(struct sockaddr));
        if (ret != sizeof(conf_fragment) + bytes_read) {
            Alarm(PRINT, "Failed to send fragment %d/%d\n", i+1, total_fragments);
            fclose(file);
            Alarm(EXIT, "Exiting...\n");
        }

        Alarm(DEBUG, "Sent fragment %d/%d\n", i + 1, total_fragments);
    }

    fclose(file);
    
    /* Schedule this function to be called again after Repeat_Timeout */
    E_queue(Broadcast_Conf, 0, NULL, Repeat_Timeout);
}
