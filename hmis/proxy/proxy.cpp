
//Include headers for socket management
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>

#include <pthread.h>
#include <cstring> // for memset

extern "C" {
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
    #include "../common/itrc.h"
    #include "spu_events.h"
    #include "stdutil/stdcarr.h"
}

// todo: comment me out. you can insert these objects as extern in your masks.
//rlModbusClient     modbus(modbusdaemon_MAILBOX,modbusdaemon_SHARED_MEMORY,modbusdaemon_SHARED_MEMORY_SIZE);
//rlSiemensTCPClient siemensTCP(siemensdaemon_MAILBOX,siemensdaemon_SHARED_MEMORY,siemensdaemon_SHARED_MEMORY_SIZE);
//rlPPIClient        ppi(ppidaemon_MAILBOX,ppidaemon_SHARED_MEMORY,ppidaemon_SHARED_MEMORY_SIZE);

// unsigned int Seq_Num;
// int ipc_sock;
// itrc_data itrc_in, itrc_out;
// struct timeval min_wait;
// int Script_Running;
// int Script_Button_Pushed;
// int Script_Pipe[2];
// stdcarr Script_History = STDCARR_STATIC_CONSTRUCT(80,0);
// int Script_History_Seq;
// int Script_Breaker_Index;
// int Script_Breaker_Val;
// sp_time Next_Button, Button_Pressed_Duration;

// extern int32u My_Global_Configuration_Number;

// void itrc_init(int ac, char **av) 
// {
//     char *ip;
//     struct timeval now;
    
//     // Usage check
//     if (ac < 2 || ac > 3) {
//         printf("Usage: %s spinesAddr:spinesPort [-port=PORT]\n", av[0]);
//         exit(EXIT_FAILURE);
//     }

//     My_Global_Configuration_Number = 0;
//     Init_SM_Replicas();

//     // NET Setup
//     gettimeofday(&now, NULL);
//     My_Incarnation = now.tv_sec;
//     Seq_Num = 1;
//     Type = HMI_TYPE;
//     My_ID = PNNL;
//     //Prime_Client_ID = (NUM_SM + 1) + MAX_EMU_RTU + My_ID;
//     Prime_Client_ID = MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU + My_ID;
//     My_IP = getIP();
//     // Setup IPC for HMI main thread
//     memset(&itrc_in, 0, sizeof(itrc_data));
//     sprintf(itrc_in.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
//     sprintf(itrc_in.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
//     sprintf(itrc_in.ipc_local, "%s%d", (char *)HMI_IPC_MAIN, My_ID);
//     sprintf(itrc_in.ipc_remote, "%s%d", (char *)HMI_IPC_ITRC, My_ID);
//     ipc_sock = IPC_DGram_Sock(itrc_in.ipc_local);

//     // Setup IPC for Worker thread (itrc client)
//     memset(&itrc_out, 0, sizeof(itrc_data));
//     sprintf(itrc_out.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
//     sprintf(itrc_out.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
//     sprintf(itrc_out.ipc_local, "%s%d", (char *)HMI_IPC_ITRC, My_ID);
//     sprintf(itrc_out.ipc_remote, "%s%d", (char *)HMI_IPC_MAIN, My_ID);
//     ip = strtok(av[1], ":");
//     sprintf(itrc_out.spines_ext_addr, "%s", ip);
//     ip = strtok(NULL, ":");
//     sscanf(ip, "%d", &itrc_out.spines_ext_port);
// }

// void *master_connection(void *arg) 
// {
//     UNUSED(arg);

//     // E_init();
//     // //fd_set active_fd_set, read_fd_set;

//     // // Init data structures for select()
//     // //FD_ZERO(&active_fd_set);
//     // //FD_SET(ipc_sock, &active_fd_set);

//     // E_attach_fd(ipc_sock, READ_FD, Read_From_Master, 0, NULL, MEDIUM_PRIORITY);
//     // E_attach_fd(Script_Pipe[0], READ_FD, Execute_Script, 0, NULL, MEDIUM_PRIORITY);

//     // E_handle_events();

//     // /* while(1) {

//     //     read_fd_set = active_fd_set;
//     //     select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
        
//     //     if(FD_ISSET(ipc_sock, &read_fd_set)) {
//     //         Read_From_Master(ipc_sock);
//     //     }
//     // } */

//     return NULL;
// }

// int main(int ac, char **av)
// {
//     int s;
//     pthread_t tid, itid;

//     signal(SIGPIPE, SIG_IGN);

//     itrc_init(ac, av);
//     pthread_create(&itid, NULL, &ITRC_Client, (void *)&itrc_out);
//     pthread_create(&tid, NULL, &master_connection, NULL);

//     return 0;
// }

int ipc_sock_hmi;
itrc_data proxy_data;

void setup_ipc_for_hmi()
{   
    // // My_ID = PNNL;
    // // memset(&proxy_data, 0, sizeof(itrc_data));
    // // sprintf(proxy_data.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
    // // sprintf(proxy_data.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
    // // sprintf(proxy_data.ipc_local, "%s%d", (char *)HMIPROXY_IPC_HMI, My_ID);
    // // sprintf(proxy_data.ipc_remote, "%s%d", (char *)HMI_IPC_MAIN, My_ID);
    
    // // ipc_sock_hmi = IPC_DGram_Sock(proxy_data.ipc_local);
    ipc_sock_hmi = IPC_DGram_Sock("/tmp/huzaifah");
}

void *listen_on_hmi_sock(void *arg){
    UNUSED(arg);

    int ret, nbytes; 
    // char buf[MAX_LEN];
    // nbytes = sizeof(buf);
    // ret = IPC_Recv(ipc_sock_hmi, (void *)buf, nbytes);


    // char* mess = "Empty message";
    // nbytes = sizeof(mess);
    // char buf[sizeof(mess)];
    // ret = IPC_Recv(ipc_sock_hmi, (void *)buf, nbytes);

    for (;;) {
        nbytes = sizeof('c');
        char buf[1];
        ret = IPC_Recv(ipc_sock_hmi, (void *)buf, nbytes);

        if (ret < 0) {
            perror("IPC_recv: error\n");
        }
        else {
            perror("received something (perror)");
            printf("received something (printf)");
            perror(buf);
        }
    }
    // return NULL;

}

int main(int ac, char **av){
    pthread_t hmi_listen_thread;

    setup_ipc_for_hmi();
    pthread_create(&hmi_listen_thread, NULL, &listen_on_hmi_sock, NULL);
    pthread_join(hmi_listen_thread, NULL);

    // printf("hello\n");
    return 0;
}