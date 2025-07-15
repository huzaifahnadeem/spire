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
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>

#include <arpa/inet.h>

#include "../common/scada_packets.h"
#include "../common/openssl_rsa.h"
#include "../common/net_wrapper.h"
#include "../common/def.h"
#include "../common/itrc.h"
#include "structs.h"
#include "queue.h"

#include "spines_lib.h"
#include "../config/cJSON.h"
#include "../config/config_helpers.h"

// These are the stages used for state collection
// copied from itrc.c
#define FROM_CLIENT   1
#define FROM_EXTERNAL 2
#define FROM_PRIME    3
#define FROM_SM_MAIN  4
#define FROM_INTERNAL 5
#define TO_CLIENT     6
#define SPINES_CONNECT_SEC  2
#define SPINES_CONNECT_USEC 0

int ipc_sock;
itrc_data itrc_main, itrc_thread;

//Arrays
char * stat;
p_switch * sw_arr;
p_link * pl_arr;
sub * sub_arr;
p_tx * tx_arr;

// Storage for PNNL
pnnl_fields pnnl_data;

// Storage for EMS
ems_fields ems_data[EMS_NUM_GENERATORS];

//size info
int stat_len;
int sw_arr_len;
int pl_arr_len;
int sub_arr_len;
int tx_arr_len;
int32u num_jhu_sub;

// used by spines_comm_handler
seq_pair _progress[MAX_EMU_RTU + NUM_HMI + 1];
// update_history up_hist[MAX_EMU_RTU + NUM_HMI + 1];

/*Functions*/
void Usage(int, char **);
void init();
void err_check_read(char * ret);
void process();
int read_from_rtu(signed_message *, struct timeval *);
void read_from_hmi(signed_message *);
void print_state();

void *spines_comm_handler(void *data);

int main(int argc, char **argv)
{   
    
    int nbytes, id, i, ret,debug_ret,debug_ret2;
    char buf[MAX_LEN];
    char *ip;
    struct timeval t, now;
    signed_message *mess;
    fd_set mask, tmask;
    rtu_data_msg *rtud;
    benchmark_msg *ben;
    pthread_t m_tid, pi_tid;
    /*int remove_me;*/

    setlinebuf(stdout);
    Init_SM_Replicas(); // call before usage to check that we get the right args for our type

    Usage(argc, argv);

    printf("INIT demo sm for config 1\n");
    init();

    // NET Setup
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    Prime_Client_ID = My_ID;
    if (Is_CC_Replica(My_ID))
        Type = CC_TYPE;
    else
        Type = DC_TYPE;
    My_IP = getIP();

    // Setup the signal handler for ITRC_Master
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    ret = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
    if (ret != 0) {
        printf("SM_main: error in pthread_sigmask\n");
        return EXIT_FAILURE;
    }

    // initalize the IPC communication with the ITRC
    memset(&itrc_main, 0, sizeof(itrc_data));
    sprintf(itrc_main.prime_keys_dir, "%s", (char *)SM_PRIME_KEYS);
    sprintf(itrc_main.sm_keys_dir, "%s", (char *)SM_SM_KEYS);
    sprintf(itrc_main.ipc_config, "%s%d", (char *)CONFIG_AGENT, My_Global_ID);
    sprintf(itrc_main.ipc_local, "%s%d", (char *)SM_IPC_MAIN, My_Global_ID);
    sprintf(itrc_main.ipc_remote, "%s%d", (char *)SM_IPC_ITRC, My_Global_ID);
    ipc_sock = IPC_DGram_Sock(itrc_main.ipc_local);

    memset(&itrc_thread, 0, sizeof(itrc_data));
    sprintf(itrc_thread.prime_keys_dir, "%s", (char *)SM_PRIME_KEYS);
    sprintf(itrc_thread.sm_keys_dir, "%s", (char *)SM_SM_KEYS);
    sprintf(itrc_thread.ipc_config, "%s%d", (char *)CONFIG_AGENT, My_Global_ID);
    sprintf(itrc_thread.ipc_local, "%s%d", (char *)SM_IPC_ITRC, My_Global_ID);
    sprintf(itrc_thread.ipc_remote, "%s%d", (char *)SM_IPC_MAIN, My_Global_ID);
    // ip = strtok(argv[3], ":");
    // sprintf(itrc_thread.spines_int_addr, "%s", ip);
    // ip = strtok(NULL, ":");
    // sscanf(ip, "%d", &itrc_thread.spines_int_port);
    // if (Type == CC_TYPE) {
    ip = strtok(argv[1], ":");
    sprintf(itrc_thread.spines_ext_addr, "%s", ip);
    ip = strtok(NULL, ":");
    sscanf(ip, "%d", &itrc_thread.spines_ext_port);
    // }

    // Setup and spawn the main itrc thread
    pthread_create(&m_tid, NULL, &spines_comm_handler, (void *)&itrc_thread);

    // Setup the FD_SET
    FD_ZERO(&mask);
    FD_SET(ipc_sock, &mask);

    while(1) {

        tmask = mask;
        debug_ret=select(FD_SETSIZE, &tmask, NULL, NULL, NULL);
        if (FD_ISSET(ipc_sock, &tmask)) { // message from spines_comm_handler to scada_master
            ret = IPC_Recv(ipc_sock, buf, MAX_LEN);
            mess = (signed_message *)buf;

            if (mess->type == RTU_DATA) {
                // printf("demo_sm_conf1: `mess->type == RTU_DATA`\n");
                id = read_from_rtu(mess, &t);

                /* Separate sending correct HMI update for each scenario */
                rtud = (rtu_data_msg *)(mess + 1);
                if (rtud->scen_type == JHU) {
                    mess = PKT_Construct_HMI_Update_Msg(rtud->seq, rtud->scen_type,
                                    stat_len, stat, t.tv_sec, t.tv_usec);
                }
                else if (rtud->scen_type == PNNL) {
                    mess = PKT_Construct_HMI_Update_Msg(rtud->seq, rtud->scen_type,
                                RTU_DATA_PAYLOAD_LEN - PNNL_DATA_PADDING,
                                (char *)(((char *)&pnnl_data) + PNNL_DATA_PADDING),
                                t.tv_sec, t.tv_usec);
                }
                else if (rtud->scen_type == EMS) {
                    mess = PKT_Construct_HMI_Update_Msg(rtud->seq, rtud->scen_type,
                                RTU_DATA_PAYLOAD_LEN,
                                (char *)((char *)&ems_data[id]),
                                t.tv_sec, t.tv_usec);
                    /*for(remove_me = 0; remove_me < EMS_NUM_GENERATORS; ++remove_me) {
                        printf("ID: %d Current: %d Target: %d Max: %d\n", remove_me, ems_data[remove_me].curr_generation, ems_data[remove_me].target_generation, ems_data[remove_me].max_generation);
                    }*/
                }
                nbytes = sizeof(signed_message) + mess->len;
                IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_main.ipc_remote); // send to spines_comm_handler to send to the clients
                free(mess);
            }
            else if (mess->type == HMI_COMMAND) {
                // printf("demo_sm_conf1: `mess->type == HMI_COMMAND`\n");
                read_from_hmi(mess);
            }
            else if (mess->type == BENCHMARK) {
                // printf("demo_sm_conf1: `mess->type == BENCHMARK`\n");
                ben = (benchmark_msg *)(mess + 1);
                gettimeofday(&now, NULL);
                ben->pong_sec = 0; //now.tv_sec;
                ben->pong_usec = 0; //now.tv_usec;
                //printf("MS2022: In scada_master: RECEIVED BENCHMARK MESSAGE\n");
                IPC_Send(ipc_sock, (void *)mess, ret, itrc_main.ipc_remote); // send to spines_comm_handler to send to the clients
            }
            else {
                printf("SM_MAIN: invalid message type %d\n", mess->type);
            }
        }
    }

    pthread_exit(NULL);
}

// Usage
void Usage(int argc, char **argv)
{
    My_ID = 0;
    My_Global_Configuration_Number=0;
    PartOfConfig=1;

    if (argc != 2) {
        printf("Usage: %s spinesExtAddr:spinesExtPort\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* while (--argc > 0) {
        argv++;

        if ((argc > 1) && (!strncmp(*argv, "-i", 2))) {
            sscanf(argv[1], "%d", &My_ID);
            if (My_ID < 1 || My_ID > NUM_SM) {
                printf("Invalid My_ID: %d\n", My_ID);
                exit(EXIT_FAILURE);
            }
            argc--; argv++;
        }
        else {
            printf("Usage: ./scada_master\n"
                    "\t-i id, indexed base 1\n");
            exit(EXIT_FAILURE);
        }
    }

    if (My_ID == 0) {
        printf("No Server ID. Please specify the ID using -i\n");
        exit(EXIT_FAILURE);
    } */
}

// Set everything up
void init()
{
    FILE *fp;
    int line_size = 100;
    char line[100];
    int sw_cur = 0;
    int pl_cur = 0;
    int tx_cur = 0;
    int i, j, num_switches, num_lines;

    fp = fopen("../init/ini", "r");
    if(fp == NULL) {
        fprintf(stderr, "problems opening file. abort");
        exit(1);
    }
    //find size of tooltip array
    err_check_read(fgets(line, line_size, fp)); //ignore this line (comment #SIZE OF TOOLTIP ARRAY)
    err_check_read(fgets(line, line_size, fp));
    stat_len = atoi(line);

    // get lengths
    sw_arr_len = 0;
    pl_arr_len = 0;
    sub_arr_len = 0;
    tx_arr_len = 0;

    err_check_read(fgets(line, line_size, fp)); //ignore this line (comment #TOOLTIP ARRAY)
    for(i = 0; i < stat_len; i++) {
        err_check_read(fgets(line, line_size, fp));
        switch(line[0]) {
            case '0': {
                sub_arr_len++;
                break;
            }
            case '1': {
                tx_arr_len++;
                break;
            }
            case '2': {
                sw_arr_len++;
                break;
            }
            case '3': {
                pl_arr_len++;
                break;
            }
        }
    }
    stat = malloc(sizeof(char) * stat_len);
    sw_arr = malloc(sizeof(p_switch) * sw_arr_len);
    pl_arr = malloc(sizeof(p_link) * pl_arr_len);
    sub_arr = malloc(sizeof(sub) * sub_arr_len);
    tx_arr = malloc(sizeof(p_tx) * tx_arr_len);

    memset(sub_arr, 0, sizeof(sub) * sub_arr_len);
    num_jhu_sub = sub_arr_len;

    //start filling arrays
    err_check_read(fgets(line, line_size, fp)); //ignore (comment #_____________________)
    err_check_read(fgets(line, line_size, fp)); //ignore (10?)
    for(i = 0; i < sub_arr_len; i++) {
        err_check_read(fgets(line, line_size, fp)); //ignore (comment #SUB ID)
        err_check_read(fgets(line, line_size, fp));
        sub_arr[i].id = atoi(line);
        //set up tx
        err_check_read(fgets(line, line_size, fp)); //ignore (comment #TX ID)
        err_check_read(fgets(line, line_size, fp));
        tx_arr[tx_cur].id = atoi(line);
        sub_arr[i].tx = tx_arr + tx_cur;
        tx_cur++;
        //set up switches
        err_check_read(fgets(line, line_size, fp)); //ignore (#NUMBER OF SWITCHES)
        err_check_read(fgets(line, line_size, fp));
        num_switches = atoi(line);
        sub_arr[i].num_switches = num_switches;
        err_check_read(fgets(line, line_size, fp)); //ignore (#SWITCH_IDS)
        for(j = 0; j < num_switches; j++) {
            err_check_read(fgets(line, line_size, fp));
            sw_arr[sw_cur].id = atoi(line);
            sub_arr[i].sw_list[j] = sw_arr + sw_cur;
            sw_cur++;
        }
        //set up lines
        err_check_read(fgets(line, line_size, fp)); //ignore (#NUMBER OF LINES)
        err_check_read(fgets(line, line_size, fp));
        num_lines = atoi(line);
        sub_arr[i].num_lines = num_lines;
        for(j = 0; j < num_lines; j++) {
            err_check_read(fgets(line, line_size, fp)); //ignore (#LINE INFO)
            // line id, src switch id, dest switch id, dest sub id
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].id = atoi(line);
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].src_sw_id = atoi(line);
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].dest_sw_id = atoi(line);
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].dest_sub = atoi(line);
            pl_arr[pl_cur].src_sub = i;
            sub_arr[i].out_lines[j] = pl_arr + pl_cur;
            //to support bi directional links between substations only
            int dest_sub = pl_arr[pl_cur].dest_sub;
            if( i >= 1 && i <= 4 && dest_sub >=1 && dest_sub <= 4) {
                int cur_lines;
                //printf("Reverse Line\n");
                //printf("Src Sub: %d, Dest Sub: %d\n", i, dest_sub);
                cur_lines = sub_arr[dest_sub].num_in_lines;
                sub_arr[dest_sub].in_lines[cur_lines] = pl_arr + pl_cur;
                sub_arr[dest_sub].num_in_lines ++;
            }
            pl_cur++;
        }
    }
    fclose(fp);
    //finish up setting up lines
    for(i = 0; i < pl_arr_len; i++) {
        for(j = 0; j < sw_arr_len; j++) {
            if(sw_arr[j].id == pl_arr[i].src_sw_id)
                pl_arr[i].src_sw = sw_arr + j;
            if(sw_arr[j].id == pl_arr[i].dest_sw_id)
                pl_arr[i].dest_sw = sw_arr + j;
        }
    }

    for(i = 0; i < sw_arr_len; i++) {
        sw_arr[i].status = 1;
    }
    for(i = 0; i < tx_arr_len; i++) {
        tx_arr[i].status = 1;
    }
    for(i = 0; i < sub_arr_len; i++){
        sub_arr[i].status = 1;
    }
    for(i = 0; i < pl_arr_len; i++){
        pl_arr[i].status = 1;
    }
    for(i = 0; i < stat_len; i++) {
        stat[i] = 1;
    }

    /* Initialize PNNL Scenario */
    memset(&pnnl_data, 0, sizeof(pnnl_fields));
}

void err_check_read(char * ret)
{
    if(ret == NULL) {
        fprintf(stderr, "read issue");
        exit(1);
    }
}

//Figure out which substations have power
void process()
{
    int i, j;

    /*initialize data*/
    queue_init();
    sub_arr[0].status = 1;
    for(j = 1; j < sub_arr_len; j++)
        sub_arr[j].status = 0;
    for(j = 0; j < pl_arr_len; j++)
        pl_arr[j].status = 0;
    enqueue(0);

    //run bfs
    while(!queue_is_empty()) {
        sub * c_sub = sub_arr + dequeue();
        if(c_sub->tx->status == 0)
            continue;
        for(i = 0; i < c_sub->num_lines; i++){
            p_link * c_link = c_sub->out_lines[i];
            if(c_link->src_sw->status == 1 && c_link->dest_sw->status == 1) {
                c_link->status = 1;
                if(sub_arr[c_link->dest_sub].status == 0) {
                    sub_arr[c_link->dest_sub].status = 1;
                    enqueue(c_link->dest_sub);
                }
            }
        }
        for(i = 0; i < c_sub->num_in_lines; i++){
            p_link * c_link = c_sub->in_lines[i];
            if(c_link->src_sw->status == 1 && c_link->dest_sw->status == 1) {
                c_link->status = 1;
                if(sub_arr[c_link->src_sub].status == 0) {
                    sub_arr[c_link->src_sub].status = 1;
                    enqueue(c_link->src_sub);
                }
            }
        }
    }

    //check if links are broken
    for(i = 0; i < pl_arr_len; i++){
        if(pl_arr[i].src_sw->status == 2) {
            //tripped line, raise alarm
            pl_arr[i].status=2;
        }
    }

    //put new data into status array
    for(i = 0; i < sw_arr_len; i++)
        stat[sw_arr[i].id] = sw_arr[i].status;
    for(i = 0; i < pl_arr_len; i++)
        stat[pl_arr[i].id] = pl_arr[i].status;
    for(i = 0; i < sub_arr_len; i++)
        stat[sub_arr[i].id] = sub_arr[i].status;
    for(i = 0; i < tx_arr_len; i++)
        stat[tx_arr[i].id] = tx_arr[i].status;
    queue_del();
}

//Read from RTU, and update data structures
int read_from_rtu(signed_message *mess, struct timeval *t)
{
    int i;
    rtu_data_msg *payload;
    jhu_fields *jhf;
    pnnl_fields *pf;
    ems_fields *ems;

    payload = (rtu_data_msg *)(mess + 1);

    // Only send updates from Real RTUs (ID = 0 to NUM_RTU - 1) to HMI
    // We don't actually check this return value anywhere...should move to itrc
    // validate_message function?
    if (payload->rtu_id >= NUM_RTU || payload->seq.seq_num == 0)
        return -1;

    t->tv_sec  = payload->sec;
    t->tv_usec = payload->usec;

    if (payload->scen_type == JHU) {
        /* If we got an invalid id, we don't want to try to use it to update
         * the sub_arr. Note that we will still send an HMI update (keeping all
         * of the ordinal accounting happy), but it won't actually reflect any
         * state change. It would be better to be able to identify this message
         * as invalid at the itrc level, but we don't know how many substation
         * we have until we read the configuration file at the SCADA Master
         * level today */
        if (payload->rtu_id >= num_jhu_sub) return 0;

        jhf = (jhu_fields *)(payload->data);

        for(i = 0; i < sub_arr[payload->rtu_id].num_switches; i++) {
            if(jhf->sw_status[i] == 1 || jhf->sw_status[i] == 0 ||
                    jhf->sw_status[i] == 2) {
                sub_arr[payload->rtu_id].sw_list[i]->status = jhf->sw_status[i];
            }
        }

        if(jhf->tx_status == 1 || jhf->tx_status == 0)
            sub_arr[payload->rtu_id].tx->status = jhf->tx_status;
        process();
    }
    else if (payload->scen_type == PNNL) {
        pf = (pnnl_fields *)(payload->data);
        memcpy(&pnnl_data, pf, sizeof(pnnl_data));
    }
    else if (payload->scen_type == EMS) {
        ems = (ems_fields *)(payload->data);
        memcpy(&ems_data[ems->id], ems, sizeof(ems_fields));
        return ems->id;
    }
    return 0;
}

//Read PVS message, send message to DAD saying what to write
void read_from_hmi(signed_message *mess)
{
    //printf("READ FROM HMI\n");
    //char buf[MAX_LEN];
    int val = 0;
    int found = 0;
    int nbytes = 0;
    int i, z;
    //signed_message *mess;
    //client_response_message *res;
    //update_message *up;
    hmi_command_msg *payload;
    signed_message *dad_mess = NULL;

    //IPC_Recv(ipc_hmi_sock, buf, MAX_LEN);
    //mess = ((signed_message *) buf);
    //res = (client_response_message *)(mess + 1);
    //up = (update_message *)(mess + 1);
    //payload = (hmi_command_msg *)(res + 1);
    payload = (hmi_command_msg *)(mess + 1);

    if (payload->scen_type == JHU) {
        switch(payload->type){
            case TRANSFORMER: {
                //figure out what substation the transformer belongs to
                for(i = 0; i < sub_arr_len; i++) {
                    if(payload->ttip_pos == sub_arr[i].tx->id) {
                        found = 1;
                        val = (sub_arr[i].tx->status == 0)? 1:0;
                        dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq,
                                    payload->scen_type, TRANSFORMER, i, i, 0, val);
                        break;
                    }
                }
                break;
            }
            case SWITCH: {
                for(i = 0; i < sub_arr_len; i++) {
                    for(z = 0; z < sub_arr[i].num_switches; z++) {
                        if(payload->ttip_pos == sub_arr[i].sw_list[z]->id) {
                            found = 1;
                            //dont change anything if tripped
                            if(sub_arr[i].sw_list[z]->status == 2)
                                return;
                                //return 1;
                            val = (sub_arr[i].sw_list[z]->status==0)?1:0;
                            dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq,
                                        payload->scen_type, SWITCH, i, i, z, val);
                            break;
                        }
                    }
                    if(found == 1)
                        break;
                }
                break;
            }
        }
        if(found == 0) {
            perror("ID from PVS not found\n");
            // Are we still required to create some kind of feedback message in
            // this case?
        }
    }
    else if (payload->scen_type == PNNL) {
        // We should probably make sure the validate function is actually
        // ensuring this before asserting it
        assert(payload->ttip_pos >= 0 && payload->ttip_pos < NUM_BREAKER);

        if (payload->type == BREAKER_FLIP) {
            val = (pnnl_data.breaker_write[payload->ttip_pos]==0)?1:0;
        }
        else if (payload->type == BREAKER_ON) {
            val = 1;
        }
        else if (payload->type == BREAKER_OFF) {
            val = 0;
        }

        dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq, payload->scen_type,
                        BREAKER, PNNL_RTU_ID, PNNL_RTU_ID, payload->ttip_pos, val);
    }
    else if (payload->scen_type == EMS) {
        /* payload->type is the updated Target value
         * payload->ttip_pos is the generator ID*/
        // Need to validate payload0>ttip_pos < NUM_EMS_GENERATORS
        ems_data[payload->ttip_pos].target_generation = payload->type;
        printf("EMS message, gen: %d target: %d\n", payload->ttip_pos, payload->type);

        dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq,
                        payload->scen_type,
                        EMS_TARGET_SET,
                        (EMS_RTU_ID_BASE+payload->ttip_pos),
                        (EMS_RTU_ID_BASE+payload->ttip_pos),
                        0, // Hardcode to 0 b/c we always write to the target, which is the first R/W Int
                        ems_data[payload->ttip_pos].target_generation);
    }

    /* With the message constructed (from either scenario), send it on */
    if(dad_mess != NULL){
        nbytes = sizeof(signed_message) + sizeof(rtu_feedback_msg);
        IPC_Send(ipc_sock, (void *)dad_mess, nbytes, itrc_main.ipc_remote); // send to spines_comm_handler to send to the clients
        free(dad_mess);
    }
}

void print_state()
{
    int32u i;
    int j;
    pnnl_fields *pf;

    printf("=== SM STATE ===\n");

    /* Print out JHU state */
    printf("   JHU SCENARIO   \n");
    for (i = 0; i < num_jhu_sub; i++) {
        printf("    [%u]: tx=%d sw=[", i, sub_arr[i].tx->status);
        for (j = 0; j < sub_arr[i].num_switches; j++)
            printf("%d ", sub_arr[i].sw_list[j]->status);
        printf("]\n");
    }

    /* print out PNNL State */
    printf("   PNNL SCENARIO   \n");
    pf = (pnnl_fields *)(&pnnl_data);
    printf("Latest Values:\n");
    printf("  IR: ");
    for (i = 0; i < NUM_POINT; i++)
        printf("%d ", pf->point[i]);
    printf("\n");
    printf("  IS: ");
    for (i = 0; i < NUM_BREAKER; i++)
        printf("%d ", pf->breaker_read[i]);
    printf("\n");
    printf("  CS: ");
    for (i = 0; i < NUM_BREAKER; i++)
        printf("%d ", pf->breaker_write[i]);
    printf("\n");

    /* print out EMS State */
    for (i = 0; i < EMS_NUM_GENERATORS; ++i) {
        printf("EMS Generator #%d, id: %d\n", i, ems_data[i].id);
        printf("    Max Generation: %d\n", ems_data[i].max_generation);
        printf("    Current Generation: %d\n", ems_data[i].curr_generation);
        printf("    Target Generation: %d\n", ems_data[i].target_generation);
    }
}

// adapted from ITRC_Send_TC_Final
int send_to_client(int sp_ext_sk, signed_message *mess_to_send)
{
    int ret, loc, in_list;
    struct sockaddr_in dest;
    signed_message *scada_mess;
    // tc_final_msg *tcf;
    rtu_feedback_msg *rtuf;
    hmi_update_msg *hmiu;
    benchmark_msg *ben;

    // tcf = (tc_final_msg *)(mess + 1);
    // scada_mess = (signed_message *)(tcf->payload);
    scada_mess = mess_to_send;

    /* Toward RTU Proxy */
    if (scada_mess->type == RTU_FEEDBACK) { 
        rtuf = (rtu_feedback_msg *)(scada_mess + 1);
        in_list = key_value_get(rtuf->sub, &loc); 
        if(!in_list) {
            printf("\nrtu:%d has no loc, dropping msg\n", rtuf->sub);
            return 0;
        }
        dest.sin_port = htons(RTU_BASE_PORT + loc);
        dest.sin_addr.s_addr = inet_addr(SPINES_RTU_ADDR);
        dest.sin_family = AF_INET;
    }
    /* Toward HMI */
    else if (scada_mess->type == HMI_UPDATE) {
        hmiu = (hmi_update_msg *)(scada_mess + 1);
        dest.sin_family = AF_INET;
        dest.sin_port = htons(HMI_BASE_PORT + hmiu->scen_type);
        dest.sin_addr.s_addr = inet_addr(SPINES_HMI_ADDR);
    }
    /* BENCHMARK */
    else if (scada_mess->type == BENCHMARK) {
        ben = (benchmark_msg *)(scada_mess + 1);
        dest.sin_family = AF_INET;
        dest.sin_port = htons(RTU_BASE_PORT + ben->sender);
        dest.sin_addr.s_addr = inet_addr(SPINES_RTU_ADDR);
        //printf("\nSENT benchmark response on %s \n",SPINES_RTU_ADDR);
    }
    else {
        printf("Invalid mess type = %d\n", mess_to_send->type);
        return 0;
    }
    ret = spines_sendto(sp_ext_sk, mess_to_send, sizeof(signed_message) + mess_to_send->len,        
                0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
    if ((int32u)ret != (sizeof(signed_message) + mess_to_send->len)) {
        printf("send_to_client: spines_sendto error!\n");
        return -1;
    }
     //printf("\nSENT response of %d on ext spines \n",ret);

    return 1;
}

void *spines_comm_handler(void *data)
// adapted from ITRC_Master and external spines handling code from ITRC_Prime_Inject
{
    int i, j, num, ret, nBytes;
    seq_pair zero_ps = {0, 0};
    net_sock ns;
    int16u val;
    fd_set mask, tmask;
    char buff[MAX_LEN], prime_client_path[128],prime_path[128];
    struct sockaddr_in dest;
    signed_message *mess, *scada_mess, *tc_final;
    client_response_message *res;
    itrc_data *itrcd;
    tc_share_msg *tc_mess;
    state_xfer_msg *st_mess;
    // stdit it;
    ordinal ord_save;
    int32u recvd_first_ordinal;
    struct timeval spines_timeout, *t;

    /* Parse JSON to make ds for corresponding sub for rtu */
    key_value_init();
    char * buffer = config_into_buffer();
    cJSON * root = cJSON_Parse(buffer);
    free(buffer);
    cJSON * locations = cJSON_GetObjectItem(root, "locations");
    for(i = 0; i < cJSON_GetArraySize(locations); i++) {
        cJSON * loc = cJSON_GetArrayItem(locations, i);
        int loc_num = cJSON_GetObjectItem(loc, "ID")->valueint;
        cJSON * rtus = cJSON_GetObjectItem(loc, "rtus");
        for(j = 0; j < cJSON_GetArraySize(rtus); j++) {
            cJSON * rtu = cJSON_GetArrayItem(rtus, j);
            int rtu_id = cJSON_GetObjectItem(rtu, "ID")->valueint;
            //printf("Adding %d, %d to KEY_VALUE STORE\n", rtu_id, loc_num);
            key_value_insert(rtu_id, loc_num);
        }
    }

    FD_ZERO(&mask);

    /* Grab IPC info */
    itrcd = (itrc_data *)data;

    // set up ext spines sock (this is adapted from ITRC_Prime_Inject)
        ns.sp_ext_s = ret = -1;
    while (ns.sp_ext_s < 0 || ret < 0) {

        ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                    SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
        if (ns.sp_ext_s < 0) {
            sleep(SPINES_CONNECT_SEC);
            continue;
        }

        val = 2;
        ret = spines_setsockopt(ns.sp_ext_s, 0, SPINES_SET_DELIVERY, (void *)&val, sizeof(val));
        if (ret < 0) {
            spines_close(ns.sp_ext_s);
            ns.sp_ext_s = -1;
            sleep(SPINES_CONNECT_SEC);
            continue;
        }
    }
    FD_SET(ns.sp_ext_s, &mask);

    // set up ipc sock for comm. with main thread
    ns.ipc_s = IPC_DGram_Sock(itrcd->ipc_local);
    memcpy(ns.ipc_remote, itrcd->ipc_remote, sizeof(ns.ipc_remote));
    FD_SET(ns.ipc_s, &mask);

    /* Read Keys */ // TODO: temp: no keys or verification for first version
    // OPENSSL_RSA_Init();
    // OPENSSL_RSA_Read_Keys(My_ID, RSA_SERVER, itrcd->prime_keys_dir);
    // TC_Read_Public_Key(itrcd->sm_keys_dir);
    // TC_Read_Partial_Key(My_ID, 1, itrcd->sm_keys_dir); /* only "1" site */

    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;
    t = NULL;

    // no internal network for conf 1 as there are is no consensus protocol running
    ns.sp_int_s = -1;

    /* Setup RTUs/HMIs/Benchmarks */
    for (i = 0; i <= MAX_EMU_RTU + NUM_HMI; i++) {
        _progress[i] = zero_ps;
        //dup_bench[i] = 0;
    }

    // ITRC_Reset_Master_Data_Structures(1);
    recvd_first_ordinal = 0;

    while (1) {

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);

        if (num > 0) {
            /* Incoming NET message External spines network */
            if (ns.sp_ext_s >= 0 && FD_ISSET(ns.sp_ext_s, &tmask)) {
                // this if statement is a combination of ITRC_Prime_Inject code where it receives messages from ext spines and from ITRC_Master where it receives messages from prime post-ordering
                nBytes = spines_recvfrom(ns.sp_ext_s, buff, MAX_LEN, 0, NULL, 0);
                if (nBytes <= 0) {
                    printf("Disconnected from Spines?\n");
                    FD_CLR(ns.sp_ext_s, &mask);
                    spines_close(ns.sp_ext_s);
                    /* Reconnect to spines external network if CC */
                    ns.sp_ext_s = ret = -1;
                    while (ns.sp_ext_s < 0 || ret < 0) {
                        printf("Ext_Spines_handler: Trying to reconnect to external spines\n");
                        ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                                    SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
                        if (ns.sp_ext_s < 0) {
                            sleep(SPINES_CONNECT_SEC);
                            continue;
                        }

                        val = 2;
                        ret = spines_setsockopt(ns.sp_ext_s, 0, SPINES_SET_DELIVERY, (void *)&val, sizeof(val));
                        if (ret < 0) {
                            spines_close(ns.sp_ext_s);
                            ns.sp_ext_s = -1;
                            sleep(SPINES_CONNECT_SEC);
                            continue;
                        }
                    }
                    FD_SET(ns.sp_ext_s, &mask);
                    printf("Ext_Spines_handler: Connected to ext spines\n");
                    continue;
                }

                /* VERIFY Client signature on message */
                mess = (signed_message *)buff; // this is a hmi/rtu client's signed_update_message
                
                /* Validate Message */
                if (!ITRC_Valid_Type(mess, FROM_EXTERNAL)) {
                    printf("Ext_Spines_handler: invalid message type (%d) from client\n", mess->type);
                    continue;
                }
                // TODO: temp: no keys or verification for first version
                // ret = OPENSSL_RSA_Verify((unsigned char*)mess + SIGNATURE_SIZE,
                //             sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                //             (unsigned char *)mess, mess->machine_id, RSA_CLIENT);
                // if (!ret) {
                //     printf("Ext_Spines_handler: RSA_Verify Failed for Client Update from %d with message type (%d)\n", mess->machine_id, mess->type);
                //     continue;
                // }

                // originally, in ITRC_Prime_Inject, the function would send the message to prime (as is). ITRC_Master would then receive it post-ordering from prime.
                // for conf1 sm, we dont have prime inject so process it here

                /* Message from Prime (Post Ordering) */
                // res = (client_response_message *)(mess + 1);
                // scada_mess = (signed_message *)(res + 1);
                
                // scada_mess = (signed_message *)(mess + 1); // gives type 0
                // scada_mess = mess; // gives type 46 (UPDATE)
                
                signed_update_message *u;
                u = (signed_update_message *)mess;
                scada_mess = u->update_contents;

                // in the normal ITRC_Master, here we check for scada_mess->type \in {PRIME_SYSTEM_RESET, PRIME_SYSTEM_RECONF, ...}. that is of course not needed as there is no prime
                recvd_first_ordinal = 1; // this var is used to check for the case where the SM is behind others. not applicable here so set to 1 to say we are good

                // originally this part is towards the end of `ITRC_Process_Prime_Ordinal` once we check ordinal sequence vals etc
                /* Store the latest update from this client, update progress, and send to the SM's main function */
                seq_pair *ps;
                int32u *idx;
                ps = (seq_pair *)(scada_mess + 1);
                idx = (int32u *)(ps + 1);
                _progress[*idx] = *ps;
            
                nBytes = sizeof(signed_message) + scada_mess->len;
                // memcpy(up_hist[*idx].buff, scada_mess, nBytes);
                // up_hist[*idx].ord = o;
                IPC_Send(ns.ipc_s, (void *)scada_mess, nBytes, ns.ipc_remote);

                // just in case we are disconnected from spines ext, set the timeout val for next round of while loop
                if (ns.sp_ext_s == -1) {
			        t = &spines_timeout;
                }
            }

            /* Incoming IPC message from SM's main function */
            if (FD_ISSET(ns.ipc_s, &tmask)) {
                nBytes = IPC_Recv(ns.ipc_s, buff, MAX_LEN);
                scada_mess = (signed_message *)buff;
                
                if (!ITRC_Valid_Type(scada_mess, FROM_SM_MAIN)) {
                    printf("ITRC_Master: invalid type %d from SM_MAIN\n", scada_mess->type);
                    continue;
                }

                // TODO: temp: no keys or verification for first version
                // /* Get the saved ordinal from the queue */
                // assert(stddll_size(&ord_queue) > 0);
                // stddll_begin(&ord_queue, &it);
                // ord_save = *(ordinal *)stdit_val(&it);
                // stddll_pop_front(&ord_queue);

                // mess = PKT_Construct_TC_Share_Msg(ord_save, (char *)scada_mess, nBytes);
                // tc_mess = (tc_share_msg *)(mess + 1);
                // /* SIGN TC Share Message */
                // OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                //         sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                //         (byte*)mess);

                /* If a CC, store your own share, possibly delivering afterwards if you
                 *  have enough matching TC shares to create a final signature */
                // if (Type == CC_TYPE) {
                //     ITRC_Insert_TC_ID(tc_mess, My_ID, NORMAL_ORD);
                //     while (ITRC_TC_Ready_Deliver(&tc_final)) {
                //         if (send_to_client(ns.sp_ext_s, tc_final) < 0) {
                //             printf("ITRC_Master: External spines error, try to reconnect soon\n");
                //             free(tc_final);
                //             spines_close(ns.sp_ext_s);
                //             ns.sp_ext_s = -1;
                //             t = &spines_timeout;
                //             break;
                //         }
                //         //printf("1. ITRC Master: ITRC_Send_TC_Final sent\n");
                //         free(tc_final);
                //     }
                // }
                // free(mess);

                if (send_to_client(ns.sp_ext_s, scada_mess) < 0) {
                    printf("spines_comm_handler: External spines error, try to reconnect soon\n");
                    spines_close(ns.sp_ext_s);
                    ns.sp_ext_s = -1;
                    t = &spines_timeout;
                    break;
                }

            }
            
        }// if num >0
        else {

            if (FD_ISSET(ns.ipc_s, &tmask)) {
                printf("num=%d and ipc_s is set\n",num);
            }
            
            t = NULL;
            		
            if (ns.sp_ext_s == -1) {
                ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                    SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
                if (ns.sp_ext_s < 0) {
                    sleep(SPINES_CONNECT_SEC);
                    continue;
                }

                val = 2;
                ret = spines_setsockopt(ns.sp_ext_s, 0, SPINES_SET_DELIVERY, (void *)&val, sizeof(val));
                if (ret < 0) {
                    spines_close(ns.sp_ext_s);
                    ns.sp_ext_s = -1;
                    sleep(SPINES_CONNECT_SEC);
                    continue;
                }
            }
		
        }//while else i.e., num<=0
    }//while

    return NULL;
}