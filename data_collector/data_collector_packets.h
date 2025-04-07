extern "C" {
    #include "../common/scada_packets.h"
}

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
};

struct DataCollectorPacket {
    int data_stream;
    int nbytes_mess;
    int nbytes_struct;
    signed_message system_message;
};