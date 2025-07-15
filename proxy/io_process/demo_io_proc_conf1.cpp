#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <cstring> // for memset
#include <string>

#include <sys/prctl.h> // required for prctl() (used to kill this proc if the parents gets a sighup)
#include <signal.h> // has the declaration for SIGHUP

// NOTE: in the Makefile, we have $SPIRE_DIR. Set that to the right spire directory if you do not want to use the default path

extern "C" {
    #include "common/net_wrapper.h"  
    #include "common/def.h"          
    #include "common/itrc.h"         
    #include "prime/libspread-util/include/spu_events.h"
    #include "prime/stdutil/include/stdutil/stdcarr.h"
    #include "spines/libspines/spines_lib.h"
}

#define IPC_TO_PARENT_RTUPLCCLIENT "/tmp/ssproxy_ipc_ioproc_to_proxy"
#define IPC_FROM_PARENT_RTUPLCCLIENT "/tmp/ssproxy_ipc_proxy_to_ioproc"
#define IPC_TO_PARENT_HMICLIENT "/tmp/hmiproxy_ipc_ioproc_to_proxy"
#define IPC_FROM_PARENT_HMICLIENT "/tmp/hmiproxy_ipc_proxy_to_ioproc"

// for conf1_client/ITRC_Valid_Type/ITRC_Validate_Message
#define SPINES_CONNECT_SEC  2
#define SPINES_CONNECT_USEC 0
#define FROM_CLIENT   1
#define FROM_EXTERNAL 2
#define FROM_PRIME    3
#define FROM_SM_MAIN  4
#define FROM_INTERNAL 5
#define TO_CLIENT     6

void parse_args(int ac, char **av, std::string &ioproc_spinesd_ip_addr, int &ioproc_spinesd_port);
void itrc_init_ioproc(std::string ioproc_spinesd_ip_addr, int ioproc_spinesd_port);
void setup_ipc_with_parent();
void *handler_msg_from_itrc(void *arg);
void *listen_on_parent_sock(void *arg);

int ioproc_ipc_sock_main_to_itrcthread;
unsigned int Seq_Num;
int ipc_sock_to_parent, ipc_sock_from_parent;
itrc_data ioproc_mainthread_to_itrcthread_data, ioproc_itr_client_data;
std::string ipc_path_suffix;
int proxy_id_for_itrc = -1; // only used for RTU/PLC clients
bool client_is_hmi;

int ITRC_Validate_Message(signed_message *mess);
int ITRC_Valid_Type(signed_message *mess, int32u stage);
extern int Curr_num_f;
extern int Curr_num_k;

/* Adapted from itrc.c: ITRC_Client */
void *conf1_client(void *data)
{
    int i, num, ret, nBytes, rep;
    int proto, my_port;
    struct sockaddr_in dest;
    fd_set mask, tmask;
    char buff[MAX_LEN];
    signed_message *mess; //, *tcf;
    // tc_final_msg *tcf_specific;
    update_message *up;
    net_sock ns;
    itrc_data *itrcd;
    seq_pair *ps;
    // ordinal applied, *ord;
    byte digest[DIGEST_SIZE];
    struct timeval spines_timeout, *t;

    /* Initialize the receiving data structures */
    // memset(&applied, 0, sizeof(ordinal));
    //msgq.head.next = NULL;
    //msgq.tail = &msgq.head;
    /* for (i = 0; i <= MAX_EMU_RTU; i++) {
        applied[i] = 0;
    } */
    
    FD_ZERO(&mask);
    
    /* Grab the IPC information and NET information from data */
    itrcd = (itrc_data *)data;
    printf("local = %s, remote = %s, spines_ext_addr = %s, spines_ext_port = %d\n", 
            itrcd->ipc_local, itrcd->ipc_remote, itrcd->spines_ext_addr, itrcd->spines_ext_port);
    ns.ipc_s = IPC_DGram_Sock(itrcd->ipc_local);
    memcpy(ns.ipc_remote, itrcd->ipc_remote, sizeof(ns.ipc_remote));
    FD_SET(ns.ipc_s, &mask);
    
    // TODO: temp: no keys or verification for first version
    // /* Setup Keys. For TC, only Public here for verification of TC Signed Messages */
    // OPENSSL_RSA_Init();
    // OPENSSL_RSA_Read_Keys(Prime_Client_ID, RSA_CLIENT, itrcd->prime_keys_dir);
    // TC_Read_Public_Key(itrcd->sm_keys_dir);
   
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
     *  this often */
    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;

    /* Connect to spines */
    ns.sp_ext_s = -1;
    if (Type == RTU_TYPE) {
        proto = SPINES_PRIORITY;
        my_port = RTU_BASE_PORT + My_ID;
    }
    else {
        proto = SPINES_PRIORITY;
        my_port = HMI_BASE_PORT + My_ID;
    }
    ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port, 
                    proto, my_port);
    if (ns.sp_ext_s < 0) {
        printf("conf1_client: Unable to connect to Spines, trying again soon\n");
        t = &spines_timeout; 
    }
    else {
        printf("conf1_client: Connected to Spines\n");
        FD_SET(ns.sp_ext_s, &mask);
        t = NULL;
    }

    while (1) {

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);

        if (num > 0) {
            
            /* Message from Spines */
            if (ns.sp_ext_s >= 0 && FD_ISSET(ns.sp_ext_s, &tmask)) {
                printf("conf1_client: message from spines\n");
                ret = spines_recvfrom(ns.sp_ext_s, buff, MAX_LEN, 0, NULL, 0);
                if (ret <= 0) {
                    printf("MS2022 Error in spines_recvfrom with ns.sp_ext_s>0 and : ret = %d, dropping!\n", ret);
                    spines_close(ns.sp_ext_s);
                    FD_CLR(ns.sp_ext_s, &mask);
                    ns.sp_ext_s = -1;
                    t = &spines_timeout; 
                    continue;
                }
		//printf("Received %d on ext_spines\n",ret);
               
                // tcf          = (signed_message *)buff;
                // tcf_specific = (tc_final_msg *)(tcf + 1);

                // /* VERIFY RSA Signature over whole message */
                // ret = OPENSSL_RSA_Verify((unsigned char*)tcf + SIGNATURE_SIZE,
                //             sizeof(signed_message) + tcf->len - SIGNATURE_SIZE,
                //             (unsigned char *)tcf, tcf->machine_id, RSA_SERVER);
                // if (!ret) {
                //     printf("RSA_Verify Failed of Client Update from %d\n", tcf->machine_id);
                //     continue;
                // }

                // /* Verify TC Signature */
                // OPENSSL_RSA_Make_Digest(tcf_specific, 
                //     sizeof(tcf_specific->ord) + sizeof(tcf_specific->payload), digest);
                // if (!TC_Verify_Signature(1, tcf_specific->thresh_sig, digest)) {
                //     printf("ITRC_Client: TC verify failed from CC replica %d\n", tcf->machine_id);
                //     continue;
                // }

                /* Extract SCADA Message */
                // mess = (signed_message *)(tcf_specific->payload);
                mess = (signed_message *)buff;
                if (!ITRC_Valid_Type(mess, TO_CLIENT)) {
                    printf("ITRC_Client: Invalid message type received from CCs, type = %d\n", mess->type);
                    continue;
                }
                ps = (seq_pair *)(mess + 1);
		//printf("verified scada mess seq=%lu\n",ps->seq_num);
                nBytes = sizeof(signed_message) + (int)mess->len;
                //ITRC_Enqueue(*seq_no, (char *)mess, nBytes, ns.ipc_s, itrcd->ipc_remote);
                /* if (*seq_no <= applied[*idx])
                    continue;
                applied[*idx] = *seq_no; */
                
                /* TODO: Another sanity check on the the message type being 
                 *  appropriate for the type of client I am */
               
                // ord = (ordinal *)&tcf_specific->ord;
                // if (ITRC_Ord_Compare(*ord, applied) <= 0){
                //         //printf("Continue called\n");
			    //     continue;
		        // }
                // applied = *ord;
                //printf("Applying [%u, %u of %u]\n", ord->ord_num, ord->event_idx, ord->event_tot);
                IPC_Send(ns.ipc_s, (char *)mess, nBytes, ns.ipc_remote);
            }

            /* Message from IPC Client */
            if (FD_ISSET(ns.ipc_s, &tmask)) {
                printf("conf1_client: message from io_proc's main fn\n");
                nBytes = IPC_Recv(ns.ipc_s, buff, MAX_LEN);
                signed_message *test_config=(signed_message*)buff;
                if (nBytes > UPDATE_SIZE) {
                    printf("conf1_client: error! client message too large %d\n", nBytes);
                    continue;
                }

                if (ns.sp_ext_s == -1){
                        printf("Spines not connected , so not sending benchmark\n");
                        continue;
                }

                ps = (seq_pair *)&buff[sizeof(signed_message)];
                mess = PKT_Construct_Signed_Message(sizeof(signed_update_message) 
                            - sizeof(signed_message));
                mess->machine_id = Prime_Client_ID;
                mess->len = sizeof(signed_update_message) - sizeof(signed_message);
                mess->type = UPDATE;
                mess->incarnation = ps->incarnation;
                mess->global_configuration_number=My_Global_Configuration_Number;
                up = (update_message *)(mess + 1);
                up->server_id = Prime_Client_ID;
                up->seq_num = ps->seq_num;
                //up->seq = *ps;
                memcpy((unsigned char*)(up + 1), buff, nBytes);
                //printf("Sending Update[%u]: [%u, %u]\n", mess->global_configuration_number,mess->incarnation, up->seq_num); 

                /* SIGN Message */
                // OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                //         sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                //         (byte*)mess );

                // rep = MIN(Curr_num_f + Curr_num_k + 1, 2 * (Curr_num_f + 2)); 
                // for (i = 1; i <= rep; i++) {
                // no loop for conf 1 because there is only 1 server which uses SM_EXT_BASE_PORT for spines port
                dest.sin_family = AF_INET;
                dest.sin_port = htons(SM_EXT_BASE_PORT); // + Curr_CC_Replicas[i-1]);
                dest.sin_addr.s_addr = inet_addr("192.168.54.11"); // TODO: temp hardcodded // Curr_Ext_Site_Addrs[Curr_CC_Sites[i-1]]);
                //printf("dest port=%d, dest addr=%s\n",SM_EXT_BASE_PORT + Curr_CC_Replicas[i-1],Curr_Ext_Site_Addrs[Curr_CC_Sites[i-1]]);
                //dest.sin_port = htons(SM_EXT_BASE_PORT + CC_Replicas[i-1]);
                //dest.sin_addr.s_addr = inet_addr(Ext_Site_Addrs[CC_Sites[i-1]]);
                ret = spines_sendto(ns.sp_ext_s, mess, sizeof(signed_update_message),
                        0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                if(ret != sizeof(signed_update_message)) {
                    printf("******* conf1_client: spines_sendto error!\n");
                    spines_close(ns.sp_ext_s);
                    FD_CLR(ns.sp_ext_s, &mask);
                    ns.sp_ext_s = -1;
                    t = &spines_timeout; 
                    break;
                    

                //printf("dest port=%d, dest addr=%s\n",SM_EXT_BASE_PORT + Curr_CC_Replicas[i-1],Curr_Ext_Site_Addrs[Curr_CC_Sites[i-1]]);
                }
                else {
                    printf("conf1_client: message passed to spines\n");
                }
                // }
                free(mess);
            }
        }
        else {
                        ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port, proto, my_port);
            if (ns.sp_ext_s < 0) {
                //printf("MS2022 ITRC_Client: Unable to connect to Spines, trying again soon\n");
                spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                t = &spines_timeout; 
            }
            else {
                //printf("$$$$$$$$$MS2022 ITRC_Client: Reconnected to ext spines\n");
                FD_SET(ns.sp_ext_s, &mask);
                t = NULL;
            }
        }
    }
    return NULL;
}

int main(int ac, char **av) {
    // this kills this process if the parent gets a SIGHUP:
    prctl(PR_SET_PDEATHSIG, SIGHUP); // TODO: this might not be the best way to do this. check the second answer in the following (answer by Schof): https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/17589555
    
    std::string ioproc_spinesd_ip_addr;
    int ioproc_spinesd_port;

    parse_args(ac, av, ioproc_spinesd_ip_addr, ioproc_spinesd_port);

    std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << ") starts (with suffix: " + ipc_path_suffix + ")\n";

    setup_ipc_with_parent();
    
    pthread_t parent_listen_thread, itrc_thread, handle_msg_from_itrc_thread;
    
    itrc_init_ioproc(ioproc_spinesd_ip_addr, ioproc_spinesd_port);

    pthread_create(&handle_msg_from_itrc_thread, NULL, &handler_msg_from_itrc, NULL); // receives messages from itrc client (ioproc)
    pthread_create(&parent_listen_thread, NULL, &listen_on_parent_sock, NULL); // listens for command messages coming from the parent proc
    pthread_create(&itrc_thread, NULL, &conf1_client, (void *)&ioproc_itr_client_data); // ITRC_Client thread will take care of any forwarding/receving the replicas via spines
    
    pthread_join(handle_msg_from_itrc_thread, NULL);
    pthread_join(parent_listen_thread, NULL);
    pthread_join(itrc_thread, NULL);

    return 0;
}

void parse_args(int ac, char **av, std::string &ioproc_spinesd_ip_addr, int &ioproc_spinesd_port) {
    if (ac != 6) {
        printf("Invalid args\n");
        printf("Usage (run as a child process): ./path/to/io_process spinesIPAddr spinesPort ipc_path_suffix proxy_id_for_itrc client_is_hmi\n");
        exit(EXIT_FAILURE);
    }
    // by convention av[0] is just the prog name
    ioproc_spinesd_ip_addr = av[1];
    ioproc_spinesd_port = atoi(av[2]);
    ipc_path_suffix = av[3];
    proxy_id_for_itrc = atoi(av[4]);

    std::string client_type_arg = av[5];
    if (client_type_arg == "1")
        client_is_hmi = true;
    else
        client_is_hmi = false;
}

void _itrc_init_plcrtu(std::string spinesd_ip_addr, int spinesd_port, itrc_data &itrc_data_main, itrc_data &itrc_data_itrcclient, int &sock_main_to_itrc_thread, std::string proxy_prime_keys_dir, std::string proxy_sm_keys_dir, std::string ssproxy_ipc_main_procfile, std::string ssproxy_ipc_itrc_procfile)
{   
    struct timeval now;
    My_Global_Configuration_Number = 0;
    Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    // Seq_Num = 1;
    
    Type = RTU_TYPE;
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + My_ID;
    My_IP = getIP();
    My_ID = proxy_id_for_itrc;

    // Setup IPC for the RTU Proxy main thread
    printf("PROXY: Setting up IPC for RTU proxy thread (in io_proc)\n");
    memset(&itrc_data_main, 0, sizeof(itrc_data));
    sprintf(itrc_data_main.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_main.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_main.ipc_local, "%s%d", ssproxy_ipc_main_procfile.c_str(), My_ID);
    sprintf(itrc_data_main.ipc_remote, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), My_ID);
    sock_main_to_itrc_thread = IPC_DGram_Sock(itrc_data_main.ipc_local);

    // Setup IPC for the Worker Thread (running the ITRC Client)
    memset(&itrc_data_itrcclient, 0, sizeof(itrc_data));
    sprintf(itrc_data_itrcclient.prime_keys_dir, "%s", proxy_prime_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.sm_keys_dir, "%s", proxy_sm_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.ipc_local, "%s%d", ssproxy_ipc_itrc_procfile.c_str(), My_ID);
    sprintf(itrc_data_itrcclient.ipc_remote, "%s%d", ssproxy_ipc_main_procfile.c_str(), My_ID);
    sprintf(itrc_data_itrcclient.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itrc_data_itrcclient.spines_ext_port);   
}

void _itrc_init_hmi(std::string spinesd_ip_addr, int spinesd_port, itrc_data &itrc_data_main, itrc_data &itrc_data_itrcclient, int &sock_main_to_itrc_thread, std::string hmi_prime_keys_dir, std::string hmi_sm_keys_dir, std::string hmiproxy_ipc_main_procfile, std::string hmiproxy_ipc_itrc_procfile)
{   
    struct timeval now;
    My_Global_Configuration_Number = 0;
    Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    Seq_Num = 1;
    Type = HMI_TYPE;
    My_ID = PNNL; // TODO: might want to change this to PNNL_W_PROXY or PROXY_FOR_PNNL to differentiate from plain old PNNL if someone wants to run them together
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU + My_ID;
    My_IP = getIP();

    // Setup IPC for HMI main thread
    memset(&itrc_data_main, 0, sizeof(itrc_data));
    sprintf(itrc_data_main.prime_keys_dir, "%s", hmi_prime_keys_dir.c_str());
    sprintf(itrc_data_main.sm_keys_dir, "%s", hmi_sm_keys_dir.c_str());
    sprintf(itrc_data_main.ipc_local, "%s%d", hmiproxy_ipc_main_procfile.c_str(), My_ID);
    sprintf(itrc_data_main.ipc_remote, "%s%d", hmiproxy_ipc_itrc_procfile.c_str(), My_ID);
    
    sock_main_to_itrc_thread = IPC_DGram_Sock(itrc_data_main.ipc_local);

    // Setup IPC for Worker thread (itrc client)
    memset(&itrc_data_itrcclient, 0, sizeof(itrc_data));
    sprintf(itrc_data_itrcclient.prime_keys_dir, "%s", hmi_prime_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.sm_keys_dir, "%s", hmi_sm_keys_dir.c_str());
    sprintf(itrc_data_itrcclient.ipc_local, "%s%d", hmiproxy_ipc_itrc_procfile.c_str(), My_ID);
    sprintf(itrc_data_itrcclient.ipc_remote, "%s%d", hmiproxy_ipc_main_procfile.c_str(), My_ID);
    sprintf(itrc_data_itrcclient.spines_ext_addr, "%s", spinesd_ip_addr.c_str());
    sscanf(std::to_string(spinesd_port).c_str(), "%d", &itrc_data_itrcclient.spines_ext_port);
}

void itrc_init_ioproc(std::string ioproc_spinesd_ip_addr, int ioproc_spinesd_port) {
    if (client_is_hmi) {
        // std::string prime_keys = HMI_PRIME_KEYS; 
        // std::string sm_keys = HMI_SM_KEYS;
        // the above macro defines dont have the right relative path. so using the following: // TODO add/fix a macro defines
        std::string prime_keys = "../prime/bin/keys"; 
        std::string sm_keys = "../scada_master/sm_keys";
        _itrc_init_hmi( ioproc_spinesd_ip_addr, 
                    ioproc_spinesd_port, 
                    ioproc_mainthread_to_itrcthread_data, 
                    ioproc_itr_client_data, 
                    ioproc_ipc_sock_main_to_itrcthread, 
                    prime_keys,
                    sm_keys, 
                    HMIPROXY_IPC_MAIN_IOPROC, 
                    HMIPROXY_IPC_ITRC_IOPROC
        );
    }
    else { // client is PLC/RTU
        std::string prime_keys = PROXY_PRIME_KEYS; 
        std::string sm_keys = PROXY_SM_KEYS;
        _itrc_init_plcrtu( ioproc_spinesd_ip_addr, 
            ioproc_spinesd_port, 
            ioproc_mainthread_to_itrcthread_data, 
            ioproc_itr_client_data, 
            ioproc_ipc_sock_main_to_itrcthread, 
            prime_keys,
            sm_keys,
            RTU_IPC_MAIN_IOPROC, 
            RTU_IPC_ITRC_IOPROC 
        );
    }
}

void setup_ipc_with_parent() {
    ipc_sock_to_parent = IPC_DGram_SendOnly_Sock(); // for sending something TO the parent
    
    std::string ipc_from_parent;
    if (client_is_hmi)
        ipc_from_parent = IPC_FROM_PARENT_HMICLIENT;
    else
        ipc_from_parent = IPC_FROM_PARENT_RTUPLCCLIENT;
    ipc_sock_from_parent = IPC_DGram_Sock((ipc_from_parent + ipc_path_suffix).c_str()); // for receiving something FROM the parent
}

void recv_then_fw_to_parent(int s, void *dummy1, void *dummy2) // called by handler_msg_from_itrc
{   
    int ret; 
    int nbytes;
    char buf[MAX_LEN];
    signed_message *mess;

    UNUSED(dummy1);
    UNUSED(dummy2);

    std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): recv_then_fw_to_parent():\n";

    // Receive from ITRC Client:
    std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): There is a message from the ITRC Client (ioproc) \n";
    ret = IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("io_process: recv_msg_from_itrc(): IPC_Rev failed\n");
    mess = (signed_message *)buf;
    nbytes = sizeof(signed_message) + mess->len;
    // Forward to parent:
    std::string ipc_to_parent;
    if (client_is_hmi)
        ipc_to_parent = IPC_TO_PARENT_HMICLIENT;
    else
        ipc_to_parent = IPC_TO_PARENT_RTUPLCCLIENT;
    IPC_Send(ipc_sock_to_parent, (void *)mess, nbytes, (ipc_to_parent + ipc_path_suffix).c_str());
    std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): The message has been forwarded to the parent proc.\n";
}

void *handler_msg_from_itrc(void *arg)
{   
    UNUSED(arg);
    
    std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): initialized handler_msg_from_itrc() \n";

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
                recv_then_fw_to_parent(ioproc_ipc_sock_main_to_itrcthread, 0, NULL);
            }
        }
    }

    return NULL;
}

void *listen_on_parent_sock(void *arg) {
    UNUSED(arg);

    int ret; 
    char buf[MAX_LEN];
    signed_message *mess;
    int nbytes;

    for (;;) {
        std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): Waiting to receive something on the parent socket\n";
        ret = IPC_Recv(ipc_sock_from_parent, buf, MAX_LEN);
        if (ret < 0) {
            std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): IPC_Rev failed. ret = " << ret << "\n";
        }
        else {
            std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): Received a message from the parent. ret = " << ret << "\n";
            mess = (signed_message *)buf;
            nbytes = sizeof(signed_message) + mess->len;
            ret = IPC_Send(ioproc_ipc_sock_main_to_itrcthread, (void *)mess, nbytes, ioproc_mainthread_to_itrcthread_data.ipc_remote);
            if (ret < 0) {
                std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): Failed to sent message to the IRTC thread. ret = " << ret << "\n";
            }
            std::cout << "demo_io_proc_conf1 (" << ipc_path_suffix << "): The message has been forwarded to the IRTC thread. ret = " << ret << "\n";

        }
    }
    return NULL;
}


// identical to the one in itrc.c
int ITRC_Validate_Message(signed_message *mess)
{
    rtu_data_msg *rtu_mess;
    ems_fields *ems_data;

    switch (mess->type) {
        case RTU_DATA:
            // TODO: Validate message should take in received bytes so we can
            // check length
            // rtu_bytes = recvd_bytes - sizeof(signed_message);
            // if (rtu_bytes < sizeof(rtu_data_msg)) return 0;
            rtu_mess = (rtu_data_msg *)(mess + 1);
            if (rtu_mess->rtu_id >= NUM_RTU || rtu_mess->seq.seq_num == 0)
                return 0;

            switch (rtu_mess->scen_type) {
                case JHU:
                case PNNL:
                    break;
                case EMS:
                    ems_data = (ems_fields *)&rtu_mess->data;
                    if (ems_data->id >= EMS_NUM_GENERATORS) return 0;
                    break;
                default:
                    return 0;
            }
            break;

        case RTU_FEEDBACK:
        case HMI_UPDATE:
        case HMI_COMMAND:
        case TC_SHARE:
        case TC_FINAL:
        case STATE_XFER:
        case BENCHMARK:
        case PRIME_OOB_CONFIG_MSG:
            break;

        case PRIME_NO_OP:
            //printf("  PRIME_NO_OP\n");
            if (mess->machine_id != (int32u)My_ID) {
                printf("Prime No_Op not from my own Prime (instead from %u)!\n", 
                            mess->machine_id);
                return 0;
            }
            break;

        case PRIME_STATE_TRANSFER:
            printf("  PRIME_STATE_TRANSFER for %d\n", mess->machine_id);
            if (mess->machine_id > Curr_num_SM) {
                printf("Prime State Xfer from non-Prime replica (instead from %u)\n",
                            mess->machine_id);
                return 0;
            }
            break;
        
        case PRIME_SYSTEM_RESET:
            printf("  PRIME_SYSTEM_RESET\n");
            if (mess->machine_id != (int32u)My_ID) {
                printf("Prime System Reset not from my own Prime (instead from %u)\n",
                            mess->machine_id);
                return 0;
            }
            break;

        default:
            return 0;
    }

    return 1;
}

// identical to the one in itrc.c
int ITRC_Valid_Type(signed_message *mess, int32u stage)
{
    switch(stage) {

        case FROM_CLIENT:
        case FROM_EXTERNAL:
            switch(mess->type) {
                case UPDATE:
                    return 1;
                /* case HMI_COMMAND:
                case RTU_DATA:
                case BENCHMARK:
                    return ITRC_Validate_Message(mess); */
                default:
                    return 0;
            }
            break;

        case FROM_PRIME:
            switch(mess->type) {
                case PRIME_NO_OP:
                case PRIME_STATE_TRANSFER:
                case PRIME_SYSTEM_RESET:
                case HMI_COMMAND:
                case RTU_DATA:
                case BENCHMARK:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;

        case FROM_SM_MAIN:
            switch(mess->type) {
                case HMI_UPDATE:
                case RTU_FEEDBACK:
                case BENCHMARK:
                case STATE_XFER:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;

        case TO_CLIENT:
            switch(mess->type) {
                case HMI_UPDATE:
                case RTU_FEEDBACK:
                case BENCHMARK:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;
        
        case FROM_INTERNAL:
            switch(mess->type) {
                case TC_SHARE:
                case STATE_XFER:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;

        default:
            return 0;
    }

    return 1;
}
