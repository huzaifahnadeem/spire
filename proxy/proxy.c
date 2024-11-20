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
 * Copyright (c) 2017-2024 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>


#include "../common/net_wrapper.h" 
#include "../common/def.h"
#include "../common/openssl_rsa.h"
#include "../common/tc_wrapper.h"
#include "../common/itrc.h"
#include "../common/scada_packets.h"
#include "../common/key_value.h"
#include "../config/cJSON.h"
#include "../config/config_helpers.h"

#define MAX_PATH 1000

// TODO: Move these somewhere common to proxy.c, proxy.cpp, data_collector
#define RTU_PROXY_MAIN_MSG      10  // message from main, received at the RTU proxy
#define RTU_PROXY_SHADOW_MSG    11  // message from shadow, received at the RTU proxy
#define RTU_PROXY_RTU_DATA      12  // message from RTU/PLC (contains RTU_DATA) received at the RTU proxy
#define HMI_PROXY_MAIN_MSG      20  // message from main, received at the HMI proxy
#define HMI_PROXY_SHADOW_MSG    21  // message from shadow, received at the HMI proxy
#define HMI_PROXY_HMI_CMD       22  // message from HMI (contains HMI_COMMAND), received at the HMI proxy
struct data_collector_packet {
    int data_stream;
    int nbytes_mess;
    int nbytes_struct;
    signed_message system_message;
}; // TODO: this struct (identical versions) is in 3 different files (hmiproxy, data_collector, ss-side proxy). move this to some common file maybe scada_packets

int data_collector_isinsystem = 0; // bool
int shadow_isinsystem = 0; // bool
char* spinesd_ip_addr; // spines daemon addr
int spinesd_port;    // spines daemon port
char* dc_spinesd_ip_addr; // data collector addr
int dc_spinesd_port;    // data collector port
char* shadow_spinesd_ip_addr; // data collector addr
int shadow_spinesd_port;    // data collector port
itrc_data shadow_itrc_main, shadow_itrc_thread;
pthread_t shadow_itrc_thread_tid;
int shadow_ipc_sock;
int dc_proto, dc_spines_sock, dc_ret;
struct timeval dc_spines_timeout, *dc_t;
int dc_conn_successful = 0;
struct sockaddr_in dc_dest;

extern int32u My_Global_Configuration_Number;

void Process_Config_Msg(signed_message * conf_mess,int mess_size);

void Process_Config_Msg(signed_message * conf_mess,int mess_size){
    config_message *c_mess;

    if (mess_size!= sizeof(signed_message)+sizeof(config_message)){
        printf("Config message is %d ,not expected size of %d\n",mess_size, sizeof(signed_message)+sizeof(config_message));
        return;
    }

    if(!OPENSSL_RSA_Verify((unsigned char*)conf_mess+SIGNATURE_SIZE,
                sizeof(signed_message)+conf_mess->len-SIGNATURE_SIZE,
                (unsigned char*)conf_mess,conf_mess->machine_id,RSA_CONFIG_MNGR)){
        printf("Benchmark: Config message signature verification failed\n");

        return;
    }
    printf("Verified Config Message\n");
    if(conf_mess->global_configuration_number<=My_Global_Configuration_Number){
        printf("Got config=%u and I am already in %u config\n",conf_mess->global_configuration_number,My_Global_Configuration_Number);
        return;
    }
    My_Global_Configuration_Number=conf_mess->global_configuration_number;
    c_mess=(config_message *)(conf_mess+1);
    //Reset SM
    Reset_SM_def_vars(c_mess->N,c_mess->f,c_mess->k,c_mess->num_cc_replicas, c_mess->num_cc,c_mess->num_dc);
    Reset_SM_Replicas(c_mess->tpm_based_id,c_mess->replica_flag,c_mess->spines_ext_addresses,c_mess->spines_int_addresses);
    printf("Reconf done \n");
}

int usage_check(int ac);
int parse_args(int ac, char **av);
int send_to_data_collector(signed_message *msg, int nbytes, int stream);
void setup_connection_to_data_collector();

// conver string to protocol enum
int string_to_protocol(char * prot) {
    int p_n;
    if(strcmp(prot, "modbus") == 0) {
        p_n = MODBUS;
    }
    else if(strcmp(prot, "dnp3") ==0) {
        p_n = DNP3;
    }
    else {
        fprintf(stderr, "Protocol: %s not supported\n", prot);
        exit(1);
    }
    return p_n;

}

/* RTU Proxy implementation */
int main(int argc, char *argv[])
{
    int i, num, ret, nBytes, sub,ret2;
    int ipc_sock;
    struct timeval now;
    // struct sockaddr_in;
    fd_set mask, tmask;
    char buff[MAX_LEN];
    signed_message *mess;
    rtu_data_msg *rtud;
    itrc_data protocol_data[NUM_PROTOCOLS];
    itrc_data itrc_main, itrc_thread;
    int ipc_used[NUM_PROTOCOLS];
    int ipc_s[NUM_PROTOCOLS];
    seq_pair *ps;
    char *ip_ptr;
    int pid;
    char *buffer;
    char path[MAX_PATH];
    pthread_t tid;
    int num_locations;

    setlinebuf(stdout);
    
    // parse args. if parse_args returns 0 then invalid args were provided and so return (i.e. exit)
    if (parse_args(argc, argv) == 0) {
        return 0;
    }

    // set up socket for data collector connection
    if (data_collector_isinsystem == 1) { // init these only if there is a data_collector in the system
        setup_connection_to_data_collector();
    }
    
    My_Global_Configuration_Number=0;
    Init_SM_Replicas();

    /* zero ipc_used */
    for(i=0; i < NUM_PROTOCOLS; i++) {
        ipc_used[i] = 0;
    }

    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    sub = atoi(argv[1]);
    My_ID = sub;
    printf("scanning json\n");

    // parse config into string and then parse json
    buffer = config_into_buffer();
    cJSON * root = cJSON_Parse(buffer);
    free(buffer);

    printf("finding location in json\n");
    // find my location in the json file
    cJSON * my_loc;
    cJSON * locations = cJSON_GetObjectItem(root, "locations");
    num_locations = cJSON_GetArraySize(locations);
    for(i = 0 ; i < num_locations ; i++) {
        cJSON * loc = cJSON_GetArrayItem(locations, i);
        if(My_ID == cJSON_GetObjectItem(loc, "ID")->valueint) {
            printf("Found my loc: %d\n",My_ID);
            my_loc = loc;
            break;
        }
    }
    if (i == num_locations) {
        printf("My id is not in config.json file!\n");
        exit(0);
    }

    printf("PROXY: finding what protocols I support\n");
    // figure out which protocols I support, set up those sockets
    cJSON * protocols = cJSON_GetObjectItem(my_loc, "protocols");
    for(i = 0; i < cJSON_GetArraySize(protocols); i++) {
        char * prot = cJSON_GetArrayItem(protocols, i)->valuestring;
        int p_n = string_to_protocol(prot);
        printf("PROXY: Creating Socket for protocol: %s and p_n=%d\n", prot,p_n);
        memset(&protocol_data[p_n], 0, sizeof(itrc_data));
        sprintf(protocol_data[p_n].prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
        sprintf(protocol_data[p_n].sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
        sprintf(protocol_data[p_n].ipc_local, "%s%s%d", (char *)RTU_IPC_ITRC, 
                prot, My_ID);
        sprintf(protocol_data[p_n].ipc_remote, "%s%s%d", (char *)RTU_IPC_MAIN,
                prot, My_ID);
        ipc_used[p_n] = 1;
        ipc_s[p_n] = IPC_DGram_Sock(protocol_data[p_n].ipc_local);
        printf("Create IPC_DGram_Sock ipc_s[%d]=%d\n",p_n,ipc_s[p_n]);

        /* Start protocol threads */
        sprintf(path, "../%s/%s_master", prot, prot);
        printf("PROXY: Starting program at path: %s\n", path);
        pid = fork();
        //child -- run program on path
        char* args_for_modbus[4] = {argv[0], argv[1], argv[2], argv[3]};
        if(pid == 0) {
            // execv(path, &argv[0]);
            execv(path, &args_for_modbus[0]);
        } 
        else if(pid < 0) {
            perror("Fork returned below 0 pid");
            exit(1);
        }

    }

    sleep(2);
    printf("PROXY: filling in key value data structure\n");
    fflush(stdout);
    // Figure out what RTU's I have to send to and place map the
    // id to a protocol
    key_value_init();
    cJSON * rtus = cJSON_GetObjectItem(my_loc, "rtus");
    for(i = 0; i < cJSON_GetArraySize(rtus); i++) { 
        cJSON * rtu = cJSON_GetArrayItem(rtus, i);
        char * prot_str = cJSON_GetObjectItem(rtu, "protocol")->valuestring;
        int rtu_id = cJSON_GetObjectItem(rtu, "ID")->valueint;
        int rtu_protocol = string_to_protocol(prot_str);
        key_value_insert(rtu_id, rtu_protocol);
        printf("key value insert id=%d, protocol %d\n",rtu_id,rtu_protocol);
    } 

    // Delete CJSON reference
    cJSON_Delete(root);

    // Net Setup
    Type = RTU_TYPE;
    //Prime_Client_ID = (NUM_SM + 1) + My_ID;
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + My_ID;
    My_IP = getIP();

    // Setup IPC for the RTU Proxy main thread
    printf("PROXY: Setting up IPC for RTU proxy thread\n");
    memset(&itrc_main, 0, sizeof(itrc_data));
    sprintf(itrc_main.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_main.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    sprintf(itrc_main.ipc_local, "%s%d", (char *)RTU_IPC_MAIN, My_ID);
    sprintf(itrc_main.ipc_remote, "%s%d", (char *)RTU_IPC_ITRC, My_ID);
    ipc_sock = IPC_DGram_Sock(itrc_main.ipc_local);

    // Setup IPC for the Worker Thread (running the ITRC Client)
    memset(&itrc_thread, 0, sizeof(itrc_data));
    sprintf(itrc_thread.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_thread.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    sprintf(itrc_thread.ipc_local, "%s%d", (char *)RTU_IPC_ITRC, My_ID);
    sprintf(itrc_thread.ipc_remote, "%s%d", (char *)RTU_IPC_MAIN, My_ID);
    ip_ptr = spinesd_ip_addr;
    sprintf(itrc_thread.spines_ext_addr, "%s", ip_ptr);
    sprintf(ip_ptr, "%d", spinesd_port); // essentially equal to ip_ptr = to_char_ptr(spinesd_port);
    sscanf(ip_ptr, "%d", &itrc_thread.spines_ext_port);

    
    
    ///////////////////////////
    if (shadow_isinsystem == 1) {
        // Setup IPC for the RTU Proxy main thread
        printf("PROXY: Setting up IPC for RTU proxy thread (For Shadow)\n");
        memset(&shadow_itrc_main, 0, sizeof(itrc_data));
        sprintf(shadow_itrc_main.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
        sprintf(shadow_itrc_main.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
        sprintf(shadow_itrc_main.ipc_local, "%s%d", (char *)RTU_IPC_MAIN_SHADOW, My_ID);
        sprintf(shadow_itrc_main.ipc_remote, "%s%d", (char *)RTU_IPC_ITRC_SHADOW, My_ID);
        shadow_ipc_sock = IPC_DGram_Sock(shadow_itrc_main.ipc_local);

        // Setup IPC for the Worker Thread (running the ITRC Client)
        memset(&shadow_itrc_thread, 0, sizeof(itrc_data));
        sprintf(shadow_itrc_thread.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
        sprintf(shadow_itrc_thread.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
        sprintf(shadow_itrc_thread.ipc_local, "%s%d", (char *)RTU_IPC_ITRC_SHADOW, My_ID);
        sprintf(shadow_itrc_thread.ipc_remote, "%s%d", (char *)RTU_IPC_MAIN_SHADOW, My_ID);
        // ip_ptr = strtok(argv[2], ":");
        ip_ptr = shadow_spinesd_ip_addr; // TODO: do i need a diff ip_ptr for shadow?
        sprintf(shadow_itrc_thread.spines_ext_addr, "%s", ip_ptr);
        // ip_ptr = strtok(NULL, ":");
        sprintf(ip_ptr, "%d", shadow_spinesd_port); // essentially equal to ip_ptr = to_char_ptr(shadow_spinesd_port);
        sscanf(ip_ptr, "%d", &shadow_itrc_thread.spines_ext_port);
        
    }

    ///////////////////////////



    printf("PROXY: Setting up ITRC Client thread\n");
    pthread_create(&tid, NULL, &ITRC_Client, (void *)&itrc_thread);
    // fflush(stdout);

    FD_ZERO(&mask);
    for(i = 0; i < NUM_PROTOCOLS; i++) 
        if(ipc_used[i] == 1){
            FD_SET(ipc_s[i], &mask);
            printf("FD_SET on ipc_s[%d]\n",i);
        }
    FD_SET(ipc_sock, &mask);



    if (shadow_isinsystem == 1) {
        printf("PROXY: Setting up ITRC Client thread (For Shadow)\n");
        pthread_create(&shadow_itrc_thread_tid, NULL, &ITRC_Client, (void *)&shadow_itrc_thread);
        FD_SET(shadow_ipc_sock, &mask); // shadow
    }

    while (1) {

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, NULL);

        if (num > 0) {
            
            /* Message from ITRC */
            if (FD_ISSET(ipc_sock, &tmask)) {
                int in_list;
                int channel;
                int rtu_dst;
                ret = IPC_Recv(ipc_sock, buff, MAX_LEN);
                if (ret <= 0) {
                    printf("Error in IPC_Recv: ret = %d, dropping!\n", ret);
                    continue;
                }
                mess = (signed_message *)buff;
                nBytes = sizeof(signed_message) + (int)mess->len;
                
                if (data_collector_isinsystem == 1) {
                    // sending to data collector (this is a message that this proxy received from SMs (via itrc client) and it is sending to an rtu/plc:
                    printf("sending main's message to data collector\n");
                    // dc_ret = spines_sendto(dc_spines_sock, (void *)mess, nBytes, 0, (struct sockaddr *)&dc_dest, sizeof(struct sockaddr));
                    dc_ret = send_to_data_collector(mess, nBytes, RTU_PROXY_MAIN_MSG);
                    if (dc_ret < 0) {
                        printf("Failed to send message to data collector.  ret = ");
                    }
                    else {
                        printf("message sent to data collector. ret = ");
                    }
                    printf("%d\n", dc_ret);
                }

                if(mess->type ==  PRIME_OOB_CONFIG_MSG){
                    printf("PROXY: processing OOB CONFIG MESSAGE\n");
                    Process_Config_Msg((signed_message *)buff,ret);
                    continue;
                }
                rtu_dst = ((rtu_feedback_msg *)(mess + 1))->rtu;
                /* enqueue in correct ipc */
                in_list = key_value_get(rtu_dst, &channel);
                if(in_list) {
                    printf("PROXY: Delivering msg to RTU channel %d at %d at path:%s\n",channel,ipc_s[channel],protocol_data[channel].ipc_remote);
                    ret2=IPC_Send(ipc_s[channel], buff, nBytes, 
                             protocol_data[channel].ipc_remote);
                    if(ret2!=nBytes){
                        printf("PROXY: error delivering to RTU\n");
                    }
                    else{
                        printf("PROXY: delivered to RTU\n");
                    }
                }
                else {
                    fprintf(stderr, 
                            "Message from spines for rtu: %d, not my problem\n",
                             rtu_dst);
                    continue;
                }
            }
            
            if (shadow_isinsystem == 1) {
                /* Message from ITRC (Shadow) */
                if (FD_ISSET(shadow_ipc_sock, &tmask)) {
                    int in_list;
                    int channel;
                    int rtu_dst;
                    ret = IPC_Recv(shadow_ipc_sock, buff, MAX_LEN);
                    if (ret <= 0) {
                        printf("Error in IPC_Recv (for shadow): ret = %d, dropping!\n", ret);
                        continue;
                    }
                    mess = (signed_message *)buff;
                    nBytes = sizeof(signed_message) + (int)mess->len;
                    
                    if (data_collector_isinsystem == 1) {
                        // sending to data collector (this is a message that this proxy received from SMs (via itrc client) and it is sending to an rtu/plc:
                        printf("sending shadow's message to data collector\n");
                        // dc_ret = spines_sendto(dc_spines_sock, (void *)mess, nBytes, 0, (struct sockaddr *)&dc_dest, sizeof(struct sockaddr));
                        dc_ret = send_to_data_collector(mess, nBytes, RTU_PROXY_SHADOW_MSG);
                        if (dc_ret < 0) {
                            printf("Failed to send message to data collector.  ret = ");
                        }
                        else {
                            printf("message sent to data collector. ret = ");
                        }
                        printf("%d\n", dc_ret);
                    }
                    // dont need to do anything else with it as this message is from the shadow (only main's messages are sent to rtus/plcs)
                }
            }
            
            for(i = 0; i < NUM_PROTOCOLS; i++) {
                if(ipc_used[i] != 1) 
                    continue;
                /* Message from a proxy */
                if (FD_ISSET(ipc_s[i], &tmask)) {
                    nBytes = IPC_Recv(ipc_s[i], buff, MAX_LEN);
                    mess = (signed_message *)buff;
                    mess->global_configuration_number = My_Global_Configuration_Number;
                    rtud = (rtu_data_msg *)(mess + 1);
                    ps = (seq_pair *)&rtud->seq;
                    ps->incarnation = My_Incarnation;
                    printf("PROXY: message from plc, sending data to sm.\n");
                    ret = IPC_Send(ipc_sock, (void *)buff, nBytes, itrc_main.ipc_remote);
                    if(ret!=nBytes){
                        printf("PROXY: error sending to SM. ret = ");
                    }
                    else {
                        printf("message sent successfully. ret = ");
                    }
                    printf("%d\n", ret);
                    
                    // send to shadow (if it is in the system)
                    if (shadow_isinsystem == 1) {
                        printf("PROXY: message from plc, sending data to sm (shadow) \n");
                        ret = IPC_Send(shadow_ipc_sock, (void *)buff, nBytes, shadow_itrc_main.ipc_remote);
                        if(ret!=nBytes){
                            printf("PROXY: error sending to SM (shadow). ret = ");
                        }
                        else {
                            printf("message sent successfully. ret = ");
                        }
                        printf("%d\n", ret);
                    }

                    // send to data collector (if it is in the system)
                    if (data_collector_isinsystem == 1) {
                        // sending to data collector (this is a message that this proxy received from a rtu/plc and it is sending to SMs (via itrc client)):
                        printf("sending message to data collector\n");
                        // dc_ret = spines_sendto(dc_spines_sock, (void *)mess, nBytes, 0, (struct sockaddr *)&dc_dest, sizeof(struct sockaddr));
                        dc_ret = send_to_data_collector(mess, nBytes, RTU_PROXY_RTU_DATA);
                        if (dc_ret < 0) {
                            printf("Failed to send message to data collector.  ret = ");
                        }
                        else {
                            printf("message sent to data collector. ret = ");
                        }
                        printf("%d\n", dc_ret);
                    }
                }
            }
        }
    }
    pthread_exit(NULL);
    return 0;
}

int usage_check(int ac) {
    if (ac == 4) { // running with just the main system
        data_collector_isinsystem = 0; // == false
        shadow_isinsystem = 0;  // == false
    }
    else if (ac == 5) { // running with the main system and the data collector
        data_collector_isinsystem = 1; // == true
        shadow_isinsystem = 0;  // == false
    }
    else if (ac == 6) { // running with the main system, the data collector, and the shadow
        data_collector_isinsystem = 1; // == true
        shadow_isinsystem = 1;  // == true
    }
    else { // running with just the main system
        printf("HELP: proxy sub spinesAddr:spinesPort Num_RTU_Emulated [dataCollectorAddr:dataCollectorPort] [shadowAddr:shadowPort]\n");
        return 0;
    }
    
    return 1;
}

int parse_args(int ac, char **av) {
    // if usage_check returns 0 then invalid args were provided and so return 0 (i.e. exit)
    if (usage_check(ac) == 0) {
        return 0;
    }

    spinesd_ip_addr = strtok(strdup(av[2]), ":"); // spines daemon addr (global var)
    spinesd_port = atoi(strtok(NULL, ":"));         // spines daemon port (global var)

    if (data_collector_isinsystem == 1) { // if data collector is in the system
        dc_spinesd_ip_addr = strtok(strdup(av[4]), ":");  // data collector addr (global var)
        dc_spinesd_port = atoi(strtok(NULL, ":"));          // data collector port (global var)
    }
    if (shadow_isinsystem == 1) { // if shadow is in the system
        shadow_spinesd_ip_addr = strtok(strdup(av[5]), ":"); // shadow addr (global var)
        shadow_spinesd_port = atoi(strtok(NULL, ":"));         // shadow port (global var)
    }

    return 1;
}

int send_to_data_collector(signed_message *msg, int nbytes, int stream) {
    // check if data collector connection was successful. if not, try to establish it first
    if (dc_conn_successful == 0) {
        setup_connection_to_data_collector(); // TODO Should set up a timer of something. currently spines_timeout dont seem to be used anywhere (including in ITRC client?)
    }

    int ret;
    // ret = spines_sendto(dc_spines_sock, (void *)msg, nbytes, 0, (struct sockaddr *)&dc_dest, sizeof(struct sockaddr));
    struct data_collector_packet data_packet;
    data_packet.data_stream = stream;
    data_packet.system_message = *msg;
    data_packet.nbytes_mess = nbytes;
    data_packet.nbytes_struct = sizeof(signed_message) + msg->len + 3*sizeof(int);
    ret = spines_sendto(dc_spines_sock, (void *)&data_packet, data_packet.nbytes_struct, 0, (struct sockaddr *)&dc_dest, sizeof(struct sockaddr));

    return ret;
}

void setup_connection_to_data_collector() {
    dc_proto = SPINES_RELIABLE; // need to use SPINES_RELIABLE and not SPINES_PRIORITY. This is because we need to be sure the message is delivered. SPINES_PRIORITY can drop messages. might need to think more though (but thats for later)
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
    *  this often */
    // #define DATA_COLLECTOR_SPINES_CONNECT_SEC  2 // for timeout if unable to connect to spines
    // #define DATA_COLLECTOR_SPINES_CONNECT_USEC 0
    dc_spines_timeout.tv_sec  = 2; // DATA_COLLECTOR_SPINES_CONNECT_SEC;
    dc_spines_timeout.tv_usec = 0; // DATA_COLLECTOR_SPINES_CONNECT_USEC;
    dc_spines_sock = -1; // -1 is not a real socket so init to that
    dc_spines_sock = Spines_SendOnly_Sock(spinesd_ip_addr, spinesd_port, dc_proto);
    if (dc_spines_sock < 0) {
        printf("setting up data collector conn.: Unable to connect to Spines, trying again soon\n");
        // dc_t = &dc_spines_timeout; 
        dc_conn_successful = 0;
    }
    else {
        printf("setting up data collector conn.: Connected to Spines\n");
        // dc_t = NULL;
        dc_conn_successful = 1;
    }
    
    dc_dest.sin_family = AF_INET;
    dc_dest.sin_port = htons(dc_spinesd_port);
    dc_dest.sin_addr.s_addr = inet_addr(dc_spinesd_ip_addr);
}