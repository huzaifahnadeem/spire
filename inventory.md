# Definition
# Constants that are originally defined via #define 
- ./common/def.h:79:#define NUM_K            1
- ./common/def.h:65: * 3*NUM_F + 2*NUM_K + 1 */
- ./common/def.h:70:#define NUM_F            1
- ./common/def.h:73: * simultaneously (in addition to the NUM_F compromises). A replica may be
- ./common/def.h:219:/* Total number of relays, should equal (2 * NUM_F + NUM_K + 1) */
- ./common/def.h:222:#define SS_NUM_F 1
- ./prime/src/def.h:55:#define NUM_F 1
- ./prime/src/def.h:65:#define NUM_SERVERS (3*NUM_F + 2*NUM_K + 1)
- ./prime/src/def.h:411:#define MAX_ACK_PARTS  (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - sizeof(po_certificate_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE) - sizeof(signed_message) - sizeof(po_request_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE) - ((2*NUM_F + NUM_K + 1) * (sizeof(signed_message) + sizeof(po_ack_message) + (MAX_MERKLE_DIGESTS * DIGEST_SIZE)))) / ((2*NUM_F + NUM_K + 1) * sizeof(po_ack_part))
- ./common/def.h:224:#define SS_NUM_K 1
- ./prime/src/def.h:59:#define NUM_K 1
- ./prime/src/def.h:48:#define MAX_NUM_SERVERS 30
- ./prime/src/def.h:49:#define MAX_NUM_SERVER_SLOTS           (MAX_NUM_SERVERS+1)
- ./prime/src/def.h:65:#define NUM_SERVERS (3*NUM_F + 2*NUM_K + 1)
- ./common/def.h:66:#define NUM_SM           6
- ./common/def.h:85:#define NUM_CC_REPLICA   6
- ./common/def.h:88:#define NUM_SITES       6
- ./common/def.h:110:#define SPINES_EXT_SITE_ADDRS {"192.168.101.101", \
- ./common/def.h:120:#define SPINES_INT_SITE_ADDRS {"192.168.101.101", \
- ./prime/src/tc_wrapper.c:55:#define NUM_SITES 1 //JCS: don't want to modify whole thing, so just defined this here...

# Static Allocation
### Constants used to define the fixed sizes of arrays, buffers, or data structures at compile time.

- ./prime/src/order.c:259:    memset(cum_acks[VAR.My_Server_ID - 1].cum_ack.ack_for_server, 0, sizeof(po_seq_pair) * MAX_NUM_SERVERS);
- ./prime/src/data_structs.h:414:  po_seq_pair made_eligible[MAX_NUM_SERVERS];
- ./prime/src/packets.h:202:  int32u preinstalled_incarnations[MAX_NUM_SERVERS]; 
- ./prime/src/packets.h:211:  po_seq_pair ack_for_server[MAX_NUM_SERVERS];
- ./prime/src/packets.h:246:  po_seq_pair last_executed[MAX_NUM_SERVERS];
- ./prime/src/packets.h:259:  int32u preinstalled_incarnations[MAX_NUM_SERVERS]; 
- ./prime/src/packets.h:267:  int32u preinstalled_incarnations[MAX_NUM_SERVERS]; 
- ./prime/src/packets.h:275:  po_seq_pair last_executed[MAX_NUM_SERVERS];
- ./prime/src/packets.h:276:  po_aru_signed_message cum_acks[MAX_NUM_SERVERS];
- ./prime/src/packets.h:404:  po_seq_pair po_aru[MAX_NUM_SERVERS];
- ./prime/src/packets.h:426:  int32u installed_incarn[MAX_NUM_SERVERS];
- ./common/conf_scada_packets.h:469:    char recvd[NUM_SM + 1];
- ./common/conf_scada_packets.h:470:    char checkpoint_messages[NUM_SM + 1][sizeof(signed_message)+sizeof-(checkpoint_msg)];
- ./common/conf_scada_packets.h:501:    char recvd[NUM_SM + 1];
- ./common/conf_scada_packets.h:502:    update_transfer_msg update_transfer_messages[NUM_SM + 1];
- ./common/conf_net_wrapper.c:70:int All_Sites[NUM_SM];
- ./common/net_wrapper.c:79:int All_Sites[NUM_SM];
- ./common/conf_net_wrapper.h:80:extern int All_Sites[NUM_SM];
- ./common/net_wrapper.h:83:extern int All_Sites[NUM_SM];
- ./common/conf_net_wrapper.c:71:int CC_Replicas[NUM_CC_REPLICA];
- ./common/conf_net_wrapper.c:72:int CC_Sites[NUM_CC_REPLICA];
- ./common/net_wrapper.c:80:int CC_Replicas[NUM_CC_REPLICA];
- ./common/net_wrapper.c:81:int CC_Sites[NUM_CC_REPLICA];
- ./common/net_wrapper.c:94:int Curr_num_CC_Replica = NUM_CC_REPLICA;
- ./common/conf_net_wrapper.h:81:extern int CC_Replicas[NUM_CC_REPLICA];
- ./common/conf_net_wrapper.h:82:extern int CC_Sites[NUM_CC_REPLICA];
- ./common/net_wrapper.h:84:extern int CC_Replicas[NUM_CC_REPLICA];
- ./common/net_wrapper.h:85:extern int CC_Sites[NUM_CC_REPLICA];
- ./common/conf_net_wrapper.c:74:char* Int_Site_Addrs[NUM_SITES] = SPINES_INT_SITE_ADDRS;
- ./common/net_wrapper.c:83:char* Int_Site_Addrs[NUM_SITES] = SPINES_INT_SITE_ADDRS;
- ./common/conf_net_wrapper.h:84:extern char* Int_Site_Addrs[NUM_SITES];
- ./prime/src/conf_tc_wrapper.c:58:TC_PK *tc_public_key[NUM_SITES+1];   /* Public Key of Site */
- ./prime/src/conf_tc_wrapper.c:59:TC_PK *tc_sm_public_key[NUM_SITES+1];   /* MK: Public Key of SM Site */
- ./prime/src/tc_wrapper.c:58:TC_PK *tc_public_key[NUM_SITES+1];   /* Public Key of Site */
- ./prime/src/tc_wrapper.c:59:TC_PK *tc_sm_public_key[NUM_SITES+1];   /* MK: Public Key of SM Site */


./common/net_wrapper.c:79:int All_Sites[NUM_SM];
- ./common/net_wrapper.h:83:extern int All_Sites[NUM_SM];
- ./common/net_wrapper.c:80:int CC_Replicas[NUM_CC_REPLICA];
- ./common/net_wrapper.c:81:int CC_Sites[NUM_CC_REPLICA];

- ./common/net_wrapper.h:84:extern int CC_Replicas[NUM_CC_REPLICA];
- ./common/net_wrapper.h:85:extern int CC_Sites[NUM_CC_REPLICA];
- ./common/net_wrapper.c:83:char* Int_Site_Addrs[NUM_SITES] = SPINES_INT_SITE_ADDRS;
- ./prime/src/tc_wrapper.c:58:TC_PK *tc_public_key[NUM_SITES+1];   /* Public Key of Site */
- ./prime/src/tc_wrapper.c:59:TC_PK *tc_sm_public_key[NUM_SITES+1];   /* MK: Public Key of SM Site */

# Initialization
### Constants used to assign values to global or local variables during startup

- ./common/net_wrapper.c:85     // int Curr_num_f = NUM_F;
- ./common/net_wrapper.c:86     // int Curr_num_k = NUM_K;
- ./prime/src/prime.c:181:  VAR.F                    = NUM_F;
- ./common/net_wrapper.c:86:int Curr_num_k = NUM_K;
- ./prime/src/prime.c:182:  VAR.K                    = NUM_K;
- ./common/net_wrapper.c:93:int Curr_num_SM =NUM_SM;
- ./modbus/modbus_master.cpp:417:    Prime_Client_ID = (NUM_SM + 1) + My_ID;
- ./common/conf_itrc.c:331:                rep = NUM_CC_REPLICA;
- ./common/conf_net_wrapper.c:112:                site = NUM_SITES - 1;
- ./common/conf_net_wrapper.c:119:            site = (site + 1) % NUM_SITES;
- ./common/conf_net_wrapper.c:127:            site = NUM_CC + ((site + 1) % (NUM_SITES - NUM_CC)) ;
- ./common/net_wrapper.c:96:int Curr_num_sites=NUM_SITES;
- ./common/conf_net_wrapper.c:73:char* Ext_Site_Addrs[NUM_CC]    = SPINES_EXT_SITE_ADDRS;
- ./common/net_wrapper.c:82:char* Ext_Site_Addrs[NUM_CC]    = SPINES_EXT_SITE_ADDRS;
- ./common/conf_net_wrapper.c:74:char* Int_Site_Addrs[NUM_SITES] = SPINES_INT_SITE_ADDRS;
- ./common/net_wrapper.c:83:char* Int_Site_Addrs[NUM_SITES] = SPINES_INT_SITE_ADDRS;
- ./common/net_wrapper.c:118:        site = (site + 1) % NUM_SITES;
- ./common/tc_wrapper.c:365:    num_sites = TC_NUM_SITES;
- ./prime/src/conf_tc_wrapper.c:334:    num_sites = NUM_SITES;
- ./prime/src/tc_wrapper.c:311:	num_sites = NUM_SITES;
- ./common/ss_tc_wrapper.c:286  // k = NUM_F + 1;
- ./common/conf_tc_wrapper.c:294  // faults = NUM_F;
- ./common/tc_wrapper.c:360       // faults = NUM_F;
- ./prime/src/conf_tc_wrapper.c:329:    faults = NUM_F;
- ./prime/src/conf_tc_wrapper.c:329:    faults = NUM_F;
- ./prime/src/tc_wrapper.c:306:	faults = NUM_F;
- ./common/conf_tc_wrapper.c:295:    rej_servers = NUM_K;
- ./common/tc_wrapper.c:361:    rej_servers = NUM_K;
- ./prime/src/conf_tc_wrapper.c:330:    rej_servers = NUM_K;
- ./prime/src/tc_wrapper.c:307:    	rej_servers = NUM_K;

# Control Logic
### Constants used in conditional statements, loops, or other branching things
- ./common/conf_itrc.c:2675     if(match_count >= ((2*NUM_F) + NUM_K + 1))
- ./trip_master/utility.c:242   if (sh_arr[dts_index].count <= SS_NUM_F)
- ./trip_master/utility.c:293   if (count + 1 == SS_NUM_F)
- ./proxy_iec61850/counting_brkr_proxy.c:530  // if (msg_count1 == SS_NUM_F + 1)
- ./proxy_iec61850/counting_brkr_proxy.c:537  // if (msg_count2 == SS_NUM_F + 1)
- ./prime/src/order.c:944:      for (i = 1; i <= MAX_NUM_SERVERS; i++) {
- ./prime/src/order.c:949:      for (i = 0; i < MAX_NUM_SERVERS; i++) {
- ./prime/src/driver.c:374:    for(i = 1; i <= MAX_NUM_SERVERS; i++) {
- ./common/conf_itrc.c:1316:                    for (i = 1; i <= NUM_SM; i++) {
- ./common/conf_itrc.c:2180:        for (i = 1; i <= NUM_SM; i++) {
- ./common/conf_itrc.c:2582:        for (j = 1; j <= NUM_SM-1; j++) 
- ./common/conf_itrc.c:2593:            for (i = j; i <= NUM_SM; i++) {
- ./common/conf_itrc.c:2642:                    for (i = 1; i <= NUM_SM; i++) {
- ./common/conf_itrc.c:2895:        for (i = 1; i <= NUM_SM; i++) {
- ./common/conf_net_wrapper.c:89:    for (id = 1; id <= NUM_SM; id++)
- ./common/net_wrapper.c:109:    for (id = 1; id <= NUM_SM; id++)
- ./common/conf_scada_packets.c:219:    for (i = 1; i <= NUM_SM; i++) {
- ./common/conf_scada_packets.c:321:    for (i = 1; i <= NUM_SM; i++) {
- ./common/conf_itrc.c:670:                    for (i = 1; i <= NUM_CC_REPLICA; i++) {
- ./common/conf_itrc.c:1368:                for (i = 1; i <= NUM_CC_REPLICA; i++) {
- ./common/conf_net_wrapper.c:148:    for (i = 0; i < NUM_CC_REPLICA; i++)
- ./common/itrc.c:1257:                for (i = 1; i <= NUM_CC_REPLICA; i++) {
- ./prime/src/prime.c:175:  if(MAX_NUM_SERVERS < (3*NUM_F + 2*NUM_K + 1)) {
- ./prime/src/prime.c:185:  if(VAR.Num_Servers < (3*NUM_F + 2*NUM_K + 1)) {
- ./prime/src/prime.c:175:  if(MAX_NUM_SERVERS < (3*NUM_F + 2*NUM_K + 1)) {
- ./prime/src/prime.c:185:  if(VAR.Num_Servers < (3*NUM_F + 2*NUM_K + 1)) {
- ./prime/src/prime.c:175:  if(MAX_NUM_SERVERS < (3*NUM_F + 2*NUM_K + 1)) {
- ./prime/src/prime.c:248:        if (tmp < 1 || tmp > MAX_NUM_SERVERS){
- ./prime/src/driver.c:244:      if(My_Server_ID > MAX_NUM_SERVERS || My_Server_ID <= 0) {
- ./prime/src/driver.c:245:	Alarm(PRINT, "Server ID must be between 1 and %d\n", MAX_NUM_SERVERS);
- ./prime/src/conf_validate.c:709:    if (sender_id >= 1 && sender_id <= NUM_SERVERS) {
- ./prime/src/conf_validate.c:816:      && sender_id <= NUM_SERVERS) {
- ./prime/src/conf_validate.c:1057:    if (part[p].originator < 1 || part[p].originator > NUM_SERVERS) {
- ./prime/src/conf_validate.c:1422:  if (report->rb_tag.machine_id < 1 || report->rb_tag.machine_id > NUM_SERVERS) {
- ./prime/src/conf_validate.c:1444:  if (pc->rb_tag.machine_id < 1 || pc->rb_tag.machine_id > NUM_SERVERS) {
- ./prime/src/conf_validate.c:1815:                   sizeof(int32u) * NUM_SERVERS) != 0) {
- ./prime/src/conf_validate.c:2144:  if (reset_proposal->num_shares > NUM_SERVERS) {
- ./common/conf_itrc.c:2675:                if((match_count >= ((2*NUM_F) + NUM_K + 1)) && (ptr->recvd[My_ID] == 1))
- ./common/conf_itrc.c:3497:            if (mess->machine_id > NUM_SM) {
- ./common/conf_net_wrapper.c:110:            if(dc_rep == (NUM_SM - NUM_CC_REPLICA))
- ./common/conf_net_wrapper.c:117:        if(cc_rep < NUM_CC_REPLICA && dc_rep < (NUM_SM - NUM_CC_REPLICA))
- ./scada_master/conf_scada_master.c:277:    if (My_ID < 1 || My_ID > NUM_SM) {
- ./scada_master/scada_master.c:311:    if (My_ID < 1 || My_ID > NUM_SM) {
- ./scada_master/scada_master.c:738:    assert(sr_specific->target > 0 && sr_specific->target <= NUM_SM);
- ./common/conf_net_wrapper.c:100:            if(cc_rep == (NUM_CC_REPLICA))
- ./common/conf_net_wrapper.c:110:            if(dc_rep == (NUM_SM - NUM_CC_REPLICA))
- ./common/conf_net_wrapper.c:117:        if(cc_rep < NUM_CC_REPLICA && dc_rep < (NUM_SM - NUM_CC_REPLICA))
- ./common/conf_net_wrapper.c:121:        else if(cc_rep < NUM_CC_REPLICA)
- ./scada_master/conf_scada_master.c:287:    else if (Is_CC_Replica(My_ID) > NUM_CC_REPLICA && argc != 3) {
- ./scada_master/scada_master.c:321:    else if (Is_CC_Replica(My_ID) > NUM_CC_REPLICA && argc != 4) {
- ./prime/src/tc_wrapper.c:97:    for ( nsite = 1; nsite <= NUM_SITES; nsite++ ) {
- ./prime/src/tc_wrapper.c:270:    if ( site == 0 || site > NUM_SITES ) {
- ./prime/src/tc_wrapper.c:338:    if ( site == 0 || site > NUM_SITES ) {
- ./prime/src/conf_tc_wrapper.c:97:    for ( nsite = 1; nsite <= NUM_SITES; nsite++ ) {
- ./prime/src/conf_tc_wrapper.c:268:    if ( site == 0 || site > NUM_SITES ) {
- ./prime/src/conf_tc_wrapper.c:293:    if ( site == 0 || site > NUM_SITES ) {
- ./prime/src/generate_keys.c:63:  TC_Generate(2*NUM_F + NUM_K + 1, "./keys");
- ./prime/src/generate_keys.c:63:  TC_Generate(2*NUM_F + NUM_K + 1, "./keys");
- ./prime/src/generate_keys.c:63:  TC_Generate(2*NUM_F + NUM_K + 1, "./keys");
- ./common/conf_scada_packets.c:215:    TC_Initialize_Combine_Phase(NUM_SM + 1, TC_MODE_POST_PRIME);
- ./common/conf_scada_packets.c:254:    TC_Destruct_Combine_Phase(NUM_SM + 1, TC_MODE_POST_PRIME);
- ./common/conf_scada_packets.c:312:    TC_Initialize_Combine_Phase(NUM_SM + 1, TC_MODE_PRE_PRIME); //MK TODO: Should this be F?
- ./common/conf_scada_packets.c:369:    TC_Destruct_Combine_Phase(NUM_SM + 1, TC_MODE_PRE_PRIME);

# Derived Constant
### Constants that are computed expressions of other constants
- ./common/conf_scada_packets.h:393  // #define MAX_SHARES (3*NUM_F + 2*NUM_K + 1)
- ./common/scada_packets.h:398       // #define MAX_SHARES (3*NUM_F + 2*NUM_K + 1)
- ./common/conf_scada_packets.h:394  // #define REQ_SHARES (NUM_F + 1)
- ./common/scada_packets.h:399       // #define REQ_SHARES (NUM_F + 1)
- ./common/conf_scada_packets.h:393:#define MAX_SHARES (3*NUM_F + 2*NUM_K + 1)
- ./common/scada_packets.h:398:#define MAX_SHARES (3*NUM_F + 2*NUM_K + 1)
- ./prime/src/def.h:65:#define NUM_SERVERS (3*NUM_F + 2*NUM_K + 1)
- ./prime/src/def.h:411:#define MAX_ACK_PARTS  (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - sizeof(po_certificate_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE) - sizeof(signed_message) - sizeof(po_request_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE) - ((2*NUM_F + NUM_K + 1) * (sizeof(signed_message) + sizeof(po_ack_message) + (MAX_MERKLE_DIGESTS * DIGEST_SIZE)))) / ((2*NUM_F + NUM_K + 1) * sizeof(po_ack_part))
- ./prime/src/conf_tc_wrapper.c:55:#define NUM_SITES 1 //JCS: don't want to modify whole thing, so just defined this here...

# Unused

- ./prime/src/openssl_rsa.c:83:RSA *public_rsa_by_server[MAX_NUM_SERVERS + 1];
- ./prime/src/openssl_rsa.c:274:    for ( s = 1; s <= MAX_NUM_SERVERS; s++ ) {
-./common/openssl_rsa.c:69:#define NUMBER_OF_SERVERS        NUM_SM
- ./common/conf_openssl_rsa.c:70:#define NUMBER_OF_SERVERS        NUM_SM