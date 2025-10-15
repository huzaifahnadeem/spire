extern "C" {
    #include "../common/scada_packets.h"
}
#include <string.h> // string operations

#define SWITCHER_MSG            00  // message from a switcher
#define RTU_PROXY_MAIN_MSG      10  // message from the active system, received at the RTU proxy
#define RTU_PROXY_SHADOW_MSG    11  // message from a shadow system, received at the RTU proxy
#define RTU_PROXY_RTU_DATA      12  // message from RTU/PLC (contains RTU_DATA) received at the RTU proxy
#define HMI_PROXY_MAIN_MSG      20  // message from the active system, received at the HMI proxy
#define HMI_PROXY_SHADOW_MSG    21  // message from a shadow system, received at the HMI proxy
#define HMI_PROXY_HMI_CMD       22  // message from HMI (contains HMI_COMMAND), received at the HMI proxy

struct DataCollectorPacket {
    int data_stream;
    int nbytes_mess;
    int nbytes_struct;
    char sys_id[20]     = ""; // used to specify the sys if for RTU_PROXY_MAIN_MSG, RTU_PROXY_SHADOW_MSG, HMI_PROXY_MAIN_MSG, HMI_PROXY_SHADOW_MSG. "hmi" or ""rtu-plc" otherwise
    signed_message system_message;
};