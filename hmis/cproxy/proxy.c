// TODO: figure out which ones are actually needed and remove the rest:
//Include headers for socket management
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>

// extern "C" {
//     #include "../common/net_wrapper.h"
//     #include "../common/def.h"
//     #include "../common/itrc.h"
//     // #include "spu_events.h"
//     // #include "stdutil/stdcarr.h"
// }

#include "common/net_wrapper.h"
#include "common/def.h"
#include "common/itrc.h"
#include "common/scada_packets.h"

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

void listen_on_hmi_sock(void *arg){
    UNUSED(arg);

    int ret, nbytes; 
    char buf[MAX_LEN];
    nbytes = sizeof(buf);
    ret = IPC_Recv(ipc_sock_hmi, (void *)buf, nbytes);
    if (ret < 0) {
        perror("IPC_recv: error\n");
    }
    else {
        perror("received something");
    }

}

int main(int ac, char **av){
    pthread_t hmi_listen_thread;

    // setup_ipc_for_hmi();
    // pthread_create(&hmi_listen_thread, NULL, &listen_on_hmi_sock, NULL);
    printf("hello\n");
    return 0;
}