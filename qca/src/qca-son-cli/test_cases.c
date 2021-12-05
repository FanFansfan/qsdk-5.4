/*
 * @File: test_cases.c
 *
 * @Abstract: Son CLI Application UNIT-TEST FRAME-WORK File
 *
 * @Notes:
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#include <qcatools_lib.h>
#include <unistd.h>
#include <bufrd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <signal.h>
#include <ieee80211_external.h>
#include <wlan_son_band_steering_api.h>
#include <linux/wireless.h>

#define TEST_SEC 20
#define MAX_EVENTS 19
#define IPERF_COUNT 10
#define TX_VALUE 20
#define TX_VALUE1 10
#define SON_CLI_CMD_MAX_LEN 128

typedef enum def_error{
    EINVALIDBANDCAP = 132,
    EINVALIDUTIL = 133,
    EPINGFAIL = 134,
    EPERFFAIL = 135,
    EACTFAIL = 136,
    MAX_ERROR,
}son_error_t;

struct event_info {
    char *name;
    int state;
};

int er_code;
int tx_val;
unsigned long tx_byte,rx_byte;
int tx_pac,rx_pac;

static char *err_codes[MAX_ERROR] = {"INVALID RET VALUE","EPERM","ENOENT","ESRCH","EINTR","EIO","ENXIO","E2BIG","ENOEXEC","EBADF","ECHILD","EAGAIN","ENOMEM","EACCES","EFAULT","ENOTBLK","EBUSY","EEXIST","EXDEV","ENODEV","ENOTDIR","EISDIR","EINVAL","ENFILE","EMFILE","ENOTTY","ETXTBSY","EFBIG","ENOSPC","ESPIPE","EROFS","EMLINK","EPIPE","EDOM","ERANGE","EDEADLK","ENAMETOOLONG","ENOLCK","ENOSYS","ENOTEMPTY","ELOOP","","ENOMSG","EIDRM","ECHRNG","EL2NSYNC","EL3HLT","EL3RST","ELNRNG","EUNATCH","ENOCSI","EL2HLT","EBADE","EBADR","EXFULL","ENOANO","EBADRQC","EBADSLT","","EBFONT","ENOSTR","ENODATA","ETIME","ENOSR","ENONET","ENOPKG","EREMOTE","ENOLINK","EADV","ESRMNT","ECOMM","EPROTO","EMULTIHOP","EDOTDOT","EBADMSG","EOVERFLOW","ENOTUNIQ","EBADFD","EREMCHG","ELIBACC","ELIBBAD","ELIBSCN","ELIBMAX","ELIBEXEC","EILSEQ","ERESTART","ESTRPIPE","EUSERS","ENOTSOCK","EDESTADDRREQ","EMSGSIZE","EPROTOTYPE","ENOPROTOOPT","EPROTONOSUPPORT","ESOCKTNOSUPPORT","EOPNOTSUPP","EPFNOSUPPORT","EAFNOSUPPORT","EADDRINUSE","EADDRNOTAVAIL","ENETDOWN","ENETUNREACH","ENETRESET","ECONNABORTED","ECONNRESET","ENOBUFS","EISCONN","ENOTCONN","ESHUTDOWN","ETOOMANYREFS","ETIMEDOUT","ECONNREFUSED","EHOSTDOWN","EHOSTUNREACH","EALREADY","EINPROGRESS","ESTALE","EUCLEAN","ENOTNAM","ENAVAIL","EISNAM","EREMOTEIO","EDQUOT","ENOMEDIUM","EMEDIUMTYPE","ECANCELED","ENOKEY","EKEYEXPIRED","EKEYREVOKED","EKEYREJECTED","EOWNERDEAD","ENOTRECOVERABLE", "EINVALIDBANDCAP", "EINVALIDUTIL", "EPINGFAIL", "EPERFFAIL", "EACTFAIL" };

static struct event_info evt_info[MAX_EVENTS] = {{"SON-TEST-CASE",1},
                                         {"ATH_EVENT_BSTEERING_CHAN_UTIL",1},
                                         {"ATH_EVENT_BSTEERING_PROBE_REQ",1},
                                         {"ATH_EVENT_BSTEERING_NODE_ASSOCIATED",1},
                                         {"ATH_EVENT_BSTEERING_TX_AUTH_FAIL",1},
                                         {"ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE",1},
                                         {"ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING",1},
                                         {"ATH_EVENT_BSTEERING_CLIENT_RSSI_MEASUREMENT",1},
                                         {"ATH_EVENT_BSTEERING_RRM_REPORT",1},
                                         {"ATH_EVENT_BSTEERING_WNM_EVENT",1},
                                         {"ATH_EVENT_BSTEERING_CLIENT_TX_RATE_CROSSING",1},
                                         {"ATH_EVENT_BSTEERING_DBG_TX_RATE",1},
                                         {"ATH_EVENT_BSTEERING_TX_POWER_CHANGE",1},
                                         {"ATH_EVENT_BSTEERING_STA_STATS",1},
                                         {"ATH_EVENT_BSTEERING_SMPS_UPDATE",1},
                                         {"ATH_EVENT_BSTEERING_OPMODE_UPDATE",1},
                                         {"NA",1},
                                         {"ATH_EVENT_BSTEERING_MAP_CLIENT_RSSI_CROSSING",1},
                                         {"IEEE80211_ALD_ALL",1},
                                         };

#define soncli_print_if_err(ret,data,val) { \
    if ( ret != 0 ) { \
        er_code = abs(ret); \
        printf("\t\t\tTEST: [%s] ERR: [%d] REASON: [%s] VAL: [%d] <FAIL>\n", data, ret, err_codes[er_code], val); \
    } \
    else { \
        printf ("\t\t\t%s :\t OKAY\n", data); \
    } \
}

#define soncli_print_test_stat(ret,type) { \
    printf("\n"); \
    evt_info[type].state = ret; \
    printf("EVENT: [%s] ID: [%d]\n", evt_info[type].name, (int)type); \
    printf("\t\t\t\t\t\t\t\t\t"); \
    if ( ret == 0 ) { \
        printf("***PASS***\n"); \
    } \
    else if ( ret < 0 ) { \
        printf("***FAIL***\n"); \
    } \
    else { \
        printf("***NOT-STARTED***\n"); \
    } \
}

#define soncli_print_event(type) { \
    printf("\n\n"); \
    printf("**************************************************************\n"); \
    printf("%s - STARTED\n", evt_info[type].name); \
    printf("**************************************************************\n"); \
    sleep(1); \
}

typedef enum soncli_band_e {
    soncli_band_24g,   ///< 2.4 GHz
    soncli_band_5g,    ///< 5 GHz
    soncli_band_6g,
    soncli_band_invalid,  ///< band is not known or is invalid
} soncli_band_e;

int son_evt_sock=-1;
int util_val=0;
int rssi_val = 0;
int rssi_flag = 0;
int bs_enabled = 0;
int client_rssi = 0;
int activity = 1;
int iperf_flag = 0;
static int count;
soncli_band_e band=soncli_band_invalid;

struct bufrd readBuf;
struct socket_context sock_ctx;
struct evloopTimeout timer_soncli;
pthread_t soncli_th=NULL;

struct event_host_info {
    ath_netlink_bsteering_event_t bsevent;
    char ifname[32];
};

struct event_host_info evth = {0};

extern void convert_ifindex_to_ifname(int sys_index, char *ifname);
extern int convert_ifname_to_ifindex(const char *ifname);
extern int soncli_enable_events(const char *ifname);
extern int send_generic_command_cfg80211(struct socket_context *sock_ctx, const char *ifname, int maincmd, int cmd, char *data, int data_len);
extern int send_command_get_cfg80211( struct socket_context *sock_ctx, const char *ifname, int op, int *data);
static int soncli_sock_destroy(void)
{
    int son_ret=0;
    int ret = 0;

    if ((ret=close(son_evt_sock)) != 0) {
        fprintf(stdout, "%s:%d> <FAILED> socket close err:%d\n", __func__, __LINE__, ret);
        son_ret = ret;
    }
    son_evt_sock = -1;
    bs_enabled = 0;

    bufrdDestroy(&readBuf);
    fprintf(stdout, "%s:%d> <INFO> Event data destroyed successfully\n", __func__, __LINE__);
    return son_ret;

}

static void soncli_final_result(void)
{
    int i=1;
    printf("\n\n\t\t\tFINAL RESULT\n");
    printf("**************************************************************\n");
    while ( i < MAX_EVENTS ) {
        soncli_print_test_stat(evt_info[i].state,i);
        ++i;
    }
    printf("**************************************************************\n");
}

int is_mac_valid ( u_int8_t *mac )
{
    struct ether_addr zeroAddr = {0};

    if (memcmp(&zeroAddr.ether_addr_octet, mac, 6) == 0 ) {
        return -1;
    }
    return 0;
}

static int event_bsteering_node_associated( ath_netlink_bsteering_event_t *event )
{
   int ret,i=0;
   //ath_netlink_bsteering_event_t *event = (ath_netlink_bsteering_event_t *)&(evth->bsevent);
   soncli_print_event(ATH_EVENT_BSTEERING_NODE_ASSOCIATED);
   if ((ret = is_mac_valid(event->data.bs_node_associated.client_addr)) == 0) {
        while ( i < TEST_SEC ) {
            ret = system("/lib/functions/commands.sh start ping_test");
            if (ret == 0) {
                break;
            }
            else {
                printf("\t\t\t[PING-FAILING] :\t RETRYING:%d\n", i);
                ret = -EPINGFAIL;
            }
            ++i;
        }
        soncli_print_if_err(ret, "[PING-TEST]\t", 0);
        if (ret != 0) {
            printf("\t\t\tASSOCIATED IN SECS:\t %d\n", i+1);
            soncli_print_test_stat(ret,ATH_EVENT_BSTEERING_NODE_ASSOCIATED);
            return -1;
       }
        if (!(event->data.bs_node_associated.band_cap & (1 << band))) {
            ret = -EINVALIDBANDCAP;
        }
        soncli_print_if_err(ret, "[BAND-CAP-TEST]:", event->data.bs_node_associated.band_cap);
    }
    else if (ret == -1) {
        printf("\t\t\tTEST: ATH_EVENT_BSTEERING_NODE_ASSOCIATED  ERR: [%d] REASON: INVALID MAC ADDRESS VAL: [00:00:00:00:00:00] <FAIL>\n", ret);
    }
    soncli_print_test_stat(ret,ATH_EVENT_BSTEERING_NODE_ASSOCIATED);
    return 0;
}

static void event_bsteering_chan_util(ath_netlink_bsteering_event_t *event)
{
    char cmd[SON_CLI_CMD_MAX_LEN];
    int ret,i=0;
    soncli_print_event(ATH_EVENT_BSTEERING_CHAN_UTIL);
    memset(cmd, 0, SON_CLI_CMD_MAX_LEN);
    snprintf(cmd, SON_CLI_CMD_MAX_LEN, "/lib/functions/commands.sh start iperf_test %d", IPERF_COUNT);
    ret = system(cmd);
    soncli_print_if_err(ret,"[IPERF-TEST]:",0);
    printf("\t\t\t<IPERF TRAFFIC IS RUNNING FOR SECS :\t %d>\n", IPERF_COUNT);
    i=IPERF_COUNT;
    while ( i > 0 ) {
        printf("\t\t\tIPERF TRAFFIC IS RUNNING.. WAIT FOR:%d SECS\n", i);
        sleep(1);
        --i;
        }
    if (ret == 0) {
        if ( util_val < 80 ) {
            ret = -EINVALIDUTIL;
        }
    }
    soncli_print_if_err(ret, "[UTILITY-TEST]:", util_val);
    soncli_print_test_stat(ret,ATH_EVENT_BSTEERING_CHAN_UTIL);
}

static void event_bsteering_client_activity_change(ath_netlink_bsteering_event_t *event)
{
    int ret,i=0;
    soncli_print_event(ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE);
    if ((ret = is_mac_valid(event->data.bs_activity_change.client_addr)) == 0) {
        printf("\t\t\tNO TRAFFIC RUNNING.. ACTIVITY STATE CHECKING..\n");
        sleep(30);
        if (activity == 0) {
            i=0;
            ret=0;
            while ( i < TEST_SEC ) {
                ret = system("/lib/functions/commands.sh start ping_test");
                if (activity == 1) {
                    ret = 0;
                    break;
                }
                else {
                    printf("\t\t\t[ACTIVITY-FAILING] :\t RETRYING:%d\n", i+1);
                    ret = -EPINGFAIL;
                    sleep(1);
                }
                ++i;
            }
            if (activity != 1 ) {
                ret = -EACTFAIL;
            }
        }
        else {
            ret = -1;
        }
        soncli_print_if_err(ret, "[ACTIVITY-TEST]:", activity);
    }
    else if (ret == -1)
    {
        printf("\t\t\tTEST: ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE  ERR: [%d] REASON: INVALID MAC ADDRESS VAL: [00:00:00:00:00:00] <FAIL>\n", ret);
    }
    soncli_print_test_stat(ret, ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE);
}

static void event_bsteering_probe_req(ath_netlink_bsteering_event_t *event)
{
    int ret = 0;
    soncli_print_event(ATH_EVENT_BSTEERING_PROBE_REQ);
    if ((ret = is_mac_valid(event->data.bs_probe.sender_addr)) == 0)
    {
        if (rssi_val<=0) {
            ret=-1;
        }
        soncli_print_if_err(ret, "[PROBEREQ-TEST]:", rssi_val);
    }
    else if (ret == -1)
    {
        printf("\t\t\tTEST: ATH_EVENT_BSTEERING_PROBE_REQ  ERR: [%d] REASON: INVALID MAC ADDRESS VAL: [00:00:00:00:00:00] <FAIL>\n", ret);
    }
    soncli_print_test_stat(ret,ATH_EVENT_BSTEERING_PROBE_REQ);
}

static void event_bsteering_tx_power_change (struct event_host_info *evth,ath_netlink_bsteering_event_t *event)
{
    char cmd[SON_CLI_CMD_MAX_LEN];
    int ret;
    soncli_print_event(ATH_EVENT_BSTEERING_TX_POWER_CHANGE);
    memset(cmd, 0, SON_CLI_CMD_MAX_LEN);
    snprintf(cmd, SON_CLI_CMD_MAX_LEN, "/lib/functions/commands.sh start txpow_test %s %d", evth->ifname, TX_VALUE);
    ret = system(cmd);
    sleep(10);
    if (ret==0) {
        snprintf(cmd, SON_CLI_CMD_MAX_LEN, "/lib/functions/commands.sh start txpow_test %s %d", evth->ifname, TX_VALUE1);
        ret = system(cmd);
        if (ret == 0)
        {
            sleep(10);
            if (tx_val == TX_VALUE)
            {
                ret = 0;
            }
            else
            {
                ret = -1;
            }
        }
    }
    else
    {
        ret = -1;
    }
    soncli_print_if_err(ret, "[TX_POWERCHANGE-TEST]:", tx_val);
    soncli_print_test_stat(ret,ATH_EVENT_BSTEERING_TX_POWER_CHANGE);
}

static void event_bsteering_sta_stats(ath_netlink_bsteering_event_t *event)
{
    int ret,i=0;
    soncli_print_event(ATH_EVENT_BSTEERING_STA_STATS);
    iperf_flag = 1;
    while ( i < TEST_SEC ) {
        ret = system("/lib/functions/commands.sh start ping_test");
        ++i;
    }
    iperf_flag = 0;
    if ((ret = is_mac_valid(event->data.bs_sta_stats.peer_stats[0].client_addr)) == 0)
    {
        if ( count>=6 && count <=12 )
        {
            ret = 0;
        }
        else
        {
            ret = -1;
        }
        soncli_print_if_err(ret, "[STA_STATUS-TEST]:", count);
    }
    else if (ret == -1)
    {
        printf("\t\t\tTEST: ATH_EVENT_BSTEERING_STA_STATS  ERR: [%d] REASON: INVALID MAC ADDRESS VAL: [00:00:00:00:00:00] <FAIL>\n", ret);
    }
    soncli_print_test_stat(ret,ATH_EVENT_BSTEERING_STA_STATS);
}

static void event_bsteering_client_rssi_crossing(ath_netlink_bsteering_event_t *event)
{
    int ret;
    soncli_print_event(ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING);
    if ((ret = is_mac_valid(event->data.bs_rssi_xing.client_addr)) == 0)
    {
        if( client_rssi <= 0 )
        {
            ret = -1;
        }
        else {
            ret = 0;
        }
        soncli_print_if_err(ret, "[CLIENT_RSSI_CROSSING-TEST]:", client_rssi);
    }
    else if (ret == -1)
    {
        printf("\t\t\tTEST: ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING  ERR: [%d] REASON: INVALID MAC ADDRESS VAL: [00:00:00:00:00:00] <FAIL>\n", ret);
    }
    soncli_print_test_stat(ret,ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING);
}

static void *soncli_thread( void *data)
{
   struct event_host_info *evth = (struct event_host_info *)data;
   ath_netlink_bsteering_event_t *event = (ath_netlink_bsteering_event_t *)&(evth->bsevent);
   switch ( event->type ) {
       case ATH_EVENT_BSTEERING_NODE_ASSOCIATED:
          printf("\t\t\t[EVENT-RECEIVED] :\t OKAY\n");
//TEST-CASE: 1
          event_bsteering_node_associated(event);
//TEST-CASE: 2
          event_bsteering_chan_util(event);
//TEST-CASE: 3
          event_bsteering_client_activity_change(event);
//TEST-CASE: 4
	  event_bsteering_probe_req(event);
//TEST-CASE: 5
          event_bsteering_tx_power_change(evth,event);
//TEST-CASE: 6
          event_bsteering_sta_stats(event); 
//TEST-CASE: 7
          event_bsteering_client_rssi_crossing(event);
//FINAL-RESULT
           soncli_final_result();
           break;
   }
   soncli_th = NULL;
//   pthread_exit((void *)0);
   return NULL;
}

int soncli_pthread_create( pthread_t *thread, void * (*thread_cb)(void *data), void *arg )
{
    pthread_attr_t custom_sched_attr;
    struct sched_param param;
    int min_prio;
    int ret=0;

    pthread_attr_init(&custom_sched_attr);
    pthread_attr_setinheritsched(&custom_sched_attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&custom_sched_attr, SCHED_RR);
    min_prio = sched_get_priority_min(SCHED_RR);
    param.sched_priority = min_prio;
    pthread_attr_setschedparam(&custom_sched_attr, &param);
    ret = pthread_create( thread, NULL, thread_cb, arg);
    return ret;
}

int close_if_running( pthread_t *thread )
{
    int ret=0;
    if ( *thread != NULL  ) {
        printf("%s:%d> <WARNING> THREAD IS RUNNING ALREADY\n ", __func__, __LINE__ );
        ret = pthread_kill(*thread, SIGTERM);
        soncli_print_if_err(ret, "PTHREAD-KILL",0);
        *thread=NULL;
    }
    return ret;
}

void soncli_event_cb ( char *ifname, const ath_netlink_bsteering_event_t *event )
{
    int ret;
    convert_ifindex_to_ifname(event->sys_index, ifname);

    switch ( event->type ) {

        case ATH_EVENT_BSTEERING_NODE_ASSOCIATED:
//                ret = close_if_running(&soncli_th);
//                soncli_print_if_err(ret,"ATH_EVENT_BSTEERING_NODE_ASSOCIATED",0);
            if ( soncli_th == NULL ) {
                memcpy(&(evth.bsevent), event, sizeof(evth.bsevent));
                strlcpy(evth.ifname, ifname, 32);
                ret = soncli_pthread_create(&soncli_th, soncli_thread, (void*)&evth);
                soncli_print_if_err(ret, "PTHREAD_CREATE",0);
            }
            break;

        case ATH_EVENT_BSTEERING_CLIENT_DISCONNECTED:
            break;

        case  ATH_EVENT_BSTEERING_CHAN_UTIL:
            if ( util_val < event->data.bs_chan_util.utilization ) {
                util_val = event->data.bs_chan_util.utilization;
            }
            break;

        case ATH_EVENT_BSTEERING_PROBE_REQ:
            if (rssi_val < event->data.bs_probe.rssi) {
                rssi_val = event->data.bs_probe.rssi;
            }
            if (rssi_val != 0 && rssi_flag !=1) {
                rssi_flag=1;
            }

            break;

        case ATH_EVENT_BSTEERING_TX_AUTH_FAIL:
            fprintf(stdout, "\nClient MAC Address : [%x:%x:%x:%x:%x:%x] \nRSSI Value : %d , Blocked : %d, Rejected : %d, Reason: %d",
            event->data.bs_auth.client_addr[0], event->data.bs_auth.client_addr[1], event->data.bs_auth.client_addr[2], event->data.bs_auth.client_addr[3],
            event->data.bs_auth.client_addr[4], event->data.bs_auth.client_addr[5], event->data.bs_auth.rssi, event->data.bs_auth.bs_blocked,
            event->data.bs_auth.bs_rejected, event->data.bs_auth.reason);
            break;

        case ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE:
            activity=event->data.bs_activity_change.activity;
            break;

        case ATH_EVENT_BSTEERING_CLIENT_RSSI_MEASUREMENT:
            printf("\nRSSI Measurement Check");
            fprintf(stdout, "\nMAC : [%x:%x:%x:%x:%x:%x] \nRSSI Value : %d", event->data.bs_rssi_measurement.client_addr[0],
            event->data.bs_rssi_measurement.client_addr[1], event->data.bs_rssi_measurement.client_addr[2], event->data.bs_rssi_measurement.client_addr[3],
            event->data.bs_rssi_measurement.client_addr[4], event->data.bs_rssi_measurement.client_addr[5], event->data.bs_rssi_measurement.rssi);
            break;

        case ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING:
            client_rssi = event->data.bs_rssi_xing.rssi;
            break;

        case ATH_EVENT_BSTEERING_RRM_REPORT:
            printf("\nATH_EVENT_BSTEERING_RRM_REPORT - CALLED");
            break;

        case ATH_EVENT_BSTEERING_WNM_EVENT:
            printf("\nATH_EVENT_BSTEERING_WNM_EVENT - CALLED");
            break;

        case ATH_EVENT_BSTEERING_CLIENT_TX_RATE_CROSSING:
            /*printf("\nATH_EVENT_BSTEERING_CLIENT_TX_RATE_CROSSING - CALLED");
            fprintf(stdout, "\nMAC : [%x:%x:%x:%x:%x:%x] \nTX-RATE : %d \nXING DIRECTION : %d", event->data.bs_tx_rate_xing.client_addr[0],
            event->data.bs_tx_rate_xing.client_addr[1], event->data.bs_tx_rate_xing.client_addr[2], event->data.bs_tx_rate_xing.client_addr[3],
            event->data.bs_tx_rate_xing.client_addr[4], event->data.bs_tx_rate_xing.client_addr[5], event->data.bs_tx_rate_xing.tx_rate,
            event->data.bs_tx_rate_xing.xing);*/
            break;

        case ATH_EVENT_BSTEERING_DBG_TX_RATE:
            printf("\nATH_EVENT_BSTEERING_DBG_TX_RATE - CALLED");
            break;

        case ATH_EVENT_BSTEERING_TX_POWER_CHANGE:
            //fprintf(stdout, "\n TX-POWER : %d", event->data.bs_tx_power_change.tx_power);
            tx_val = event->data.bs_tx_power_change.tx_power;
            break;

        case ATH_EVENT_BSTEERING_SMPS_UPDATE:
           /* printf("\nATH_EVENT_BSTEERING_SMPS_UPDATE - CALLED");
            fprintf(stdout, "\nMAC : [%x:%x:%x:%x:%x:%x] \nSTATIC : %d", event->data.smps_update.client_addr[0],event->data.smps_update.client_addr[1],
            event->data.smps_update.client_addr[2], event->data.smps_update.client_addr[3],event->data.smps_update.client_addr[4],
            event->data.smps_update.client_addr[5], event->data.smps_update.is_static);
            break;*/

        case ATH_EVENT_BSTEERING_OPMODE_UPDATE:
            printf("\nATH_EVENT_BSTEERING_OPMODE_UPDATE - CALLED");
            break;

        case ATH_EVENT_BSTEERING_MAP_CLIENT_RSSI_CROSSING:
            printf("\nATH_EVENT_BSTEERING_MAP_CLIENT_RSSI_CROSSING - CALLED");
            break;

        case ATH_EVENT_BSTEERING_STA_STATS:
            if ( iperf_flag ) {
                if ( tx_byte <= event->data.bs_sta_stats.peer_stats[0].tx_byte_count &&
                     rx_byte <= event->data.bs_sta_stats.peer_stats[0].rx_byte_count &&
                     rx_pac < event->data.bs_sta_stats.peer_stats[0].rx_packet_count &&
                     tx_pac < event->data.bs_sta_stats.peer_stats[0].tx_packet_count &&
                     event->data.bs_sta_stats.peer_stats[0].rssi != 0)
                {
                    ++count;
                    tx_byte = event->data.bs_sta_stats.peer_stats[0].tx_byte_count;
                    rx_byte = event->data.bs_sta_stats.peer_stats[0].rx_byte_count;
                    rx_pac = event->data.bs_sta_stats.peer_stats[0].rx_packet_count;
                    tx_pac = event->data.bs_sta_stats.peer_stats[0].tx_packet_count;
                   // printf("\n PEER 1 PER : %d",event->data.bs_sta_stats.peer_stats[0].per);
                   // printf("\n PEER 1 TX RATE : %d", event->data.bs_sta_stats.peer_stats[0].tx_rate);
                }
            }
            break;

       /* case IEEE80211_ALD_ALL:
            printf("IEEE80211_ALD_ALL - CALLED");
            break;*/

        default:
            break;

    }
}

void soncli_event_cb_main( void *data)
{
    const struct nlmsghdr *hdr = NULL;
    const ath_netlink_bsteering_event_t *event = NULL;
    char *ifname = (char *)data;
    u_int32_t numBytes;
    const u_int8_t *msg;

    numBytes = bufrdNBytesGet(&readBuf);
    msg = bufrdBufGet(&readBuf);
    do {
        if (bufrdErrorGet(&readBuf)) {
            fprintf(stdout, "%s:%d> <FAILED> Read Error, numBytes:%d\n", __func__, __LINE__, numBytes );
            if (-1 == son_evt_sock  ) {
                fprintf(stdout, "%s:%d> <FAILED> socket creation!!!\n", __func__, __LINE__);
                exit(1);
            }
            return;
        }
        if (!numBytes) {
            return;
        }
        hdr = (const struct nlmsghdr *) msg;
        if (numBytes < sizeof(struct nlmsghdr) + sizeof(ath_netlink_bsteering_event_t) ||
            hdr->nlmsg_len < sizeof(ath_netlink_bsteering_event_t)) {
            fprintf(stdout, "%s:%d> <FAILED> Invalid message len: %u bytes", __func__, __LINE__, numBytes);
            break;
        }
        event = NLMSG_DATA(hdr);
        soncli_event_cb(ifname, event);
    }while(0);
    bufrdConsume(&readBuf, numBytes);
}

int soncli_enable_events( const char *ifname)
{
    struct sockaddr_nl destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.nl_family = AF_NETLINK;
    destAddr.nl_pid = 0;
    destAddr.nl_groups = 0;

    struct nlmsghdr hdr;
    hdr.nlmsg_len = NLMSG_SPACE(0);
    hdr.nlmsg_flags = convert_ifname_to_ifindex(ifname);
    hdr.nlmsg_type = 0;
    hdr.nlmsg_pid = getpid();

    if (sendto(son_evt_sock, &hdr, hdr.nlmsg_len, 0,
               (const struct sockaddr *) &destAddr, sizeof(destAddr)) < 0) {
        fprintf(stdout, "%s:%d> Failed to send netlink trigger", __func__, __LINE__ );
        return -1;
    }
    return 0;
}

int soncli_enable_bs(const char *ifname)
{
    struct ieee80211req_athdbg req = { 0 };
    int ret, i=0;

    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_PARAMS;

    req.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_check_period = 1;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.utilization_sample_period = 40;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.utilization_average_num_samples = 1;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.low_rssi_crossing_threshold = 10;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.low_rate_rssi_crossing_threshold = 0;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_overload = 10;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.low_tx_rate_crossing_threshold = 0;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.interference_detection_enable = 0;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.delay_24g_probe_rssi_threshold = 35;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.delay_24g_probe_time_window = 0;
    while(i<BSTEERING_MAX_CLIENT_CLASS_GROUP) {
       req.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_normal[i]=10;
       req.data.mesh_dbg_req.mesh_data.bsteering_param.high_tx_rate_crossing_threshold[i]=50000;
       req.data.mesh_dbg_req.mesh_data.bsteering_param.inactive_rssi_xing_high_threshold[i]=35;
       req.data.mesh_dbg_req.mesh_data.bsteering_param.inactive_rssi_xing_low_threshold[i]=0;
       req.data.mesh_dbg_req.mesh_data.bsteering_param.high_rate_rssi_crossing_threshold[i]=30;
       req.data.mesh_dbg_req.mesh_data.bsteering_param.ap_steer_rssi_xing_low_threshold[i]=20;

        ++i;
    }
//    req.data.bsteering_param.low_rate_rssi_crossing_threshold = ;
 //   req.data.bsteering_param.interference_detection_enable = ;

    req.needs_reply = DBGREQ_REPLY_IS_NOT_REQUIRED;
    ret = send_generic_command_cfg80211(&sock_ctx, ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (char *)&req, sizeof(req));
    if (ret < 0) {
        soncli_print_if_err(ret,"ENABLE-BS",0);
        if ( ret != -EBUSY ) {
            return -1;
        }
    }

    req.data.mesh_dbg_req.mesh_data.value = 1;
    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE;
    req.needs_reply = DBGREQ_REPLY_IS_NOT_REQUIRED;
    ret = send_generic_command_cfg80211(&sock_ctx, ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (char *)&req, sizeof(req));
    if (ret < 0) {
        soncli_print_if_err(ret,"ENABLE-BS",0);
        if ( ret != -EALREADY)
        return -1;
    }
    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE_EVENTS;
    //ret = send_command((struct socket_context *)de_event_socket, ifname, &req, sizeof(req), NULL, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_DBGREQ );
    ret = send_generic_command_cfg80211(&sock_ctx, ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (char *)&req, sizeof(req));
    if (ret < 0) {
        soncli_print_if_err(ret,"ENABLE-BS",0);
        if ( ret != -EALREADY)
        return -1;
    }
    ret = soncli_enable_events(ifname);
    soncli_print_if_err(ret,"ENABLE-BS",0);
   return ret;
}

int soncli_event_create(const char *ifname)
{

    if ( bs_enabled ) {
        fprintf(stdout, "%s:%d> <INFO> %s: Band-Steer already enabled\n", __func__, __LINE__, ifname);
        return 0;
    }

    if ( soncli_enable_bs(ifname) != 0) {
        close(son_evt_sock);
        son_evt_sock = -1;
        fprintf(stdout, "%s:%d> %s: <FAILED> BS ENABLE\n", __func__, __LINE__, ifname );
        return -1;
    }
    bs_enabled = 1;
    //fprintf(stdout, "%s:%d> <INFO> %s: BandSteering Init Successfully\n", __func__, __LINE__, ifname );
    return 0;
}

int soncli_init_event(char *ifname)
{

    struct sockaddr_nl addr={0};
    u_int32_t bufferSize;

    son_evt_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_BAND_STEERING_EVENT);
    if (-1 == son_evt_sock) {
        fprintf(stdout, "%s:%d> <FAILED> socket creation!!!\n", __func__, __LINE__);
        return -1;
    }
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;
    if (-1 == bind(son_evt_sock, (const struct sockaddr *) &addr, sizeof(addr))) {
        fprintf(stdout, "%s:%d> <FAILED> bind netlink socket\n", __func__, __LINE__ );
        close(son_evt_sock);
        son_evt_sock = -1;
        return -1;
    }

    bufferSize = NLMSG_SPACE(sizeof(struct nlmsghdr) + sizeof(struct ath_netlink_bsteering_event));
    bufrdCreate(&readBuf, "son_event", son_evt_sock, bufferSize, soncli_event_cb_main, ifname);

    return 0;
}

int get_bssid(const char * ifname)
{
    int ret=0;
    u_int8_t bssid[6];
    memset(bssid, 0, 6);

    ret = send_command(&sock_ctx, ifname, bssid, sizeof(bssid), NULL, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION, QCA_NL80211_VENDORSUBCMD_BSSID);
    if (ret < 0)
    {
        soncli_print_if_err(ret, "ASSOC",0);
        return ret;
    }
    if ( (ret = is_mac_valid(bssid)) != 0 ) {
        printf("\t\t\t%s BRINGING UP WAIT..\n", ifname);
    }
    return ret;
}

soncli_band_e get_band(const char *ifname)
{
    int ret = 0;
    unsigned int freq;

    ret = send_command_get_cfg80211(&sock_ctx, ifname, IEEE80211_PARAM_GET_FREQUENCY, (void *)&freq);
    if ( ret != 0 ) {
        soncli_print_if_err(ret, "GETFREQ",0);
        return soncli_band_invalid;
    }
   // printf("freq: %d\n", freq);
    if (freq <= 1000) {
        if (freq < 27) {
            return soncli_band_24g;
        } else {
            return soncli_band_5g;
        }
    } else {
        // Value is a raw frequency (seems to be in 10s of Hz).
        if (freq >= 5945)
            return soncli_band_6g;
        else if (freq / 1000 >= 5) {
            return soncli_band_5g;
        } else {
            return soncli_band_24g;
        }
   }
   ret = -1;
   soncli_print_if_err(ret, "GETBAND",0);
   return soncli_band_invalid;
}

int is_vap_ready( char *ifname )
{
    int ret = -1;
    int loop = 0;

    while(loop<TEST_SEC)
    {
        if ((ret=get_bssid(ifname))!=0) {
            sleep(1);
        }
        else {
            printf("\t\t\t<%s> BROUGHT UP IN SECS :\t %d\n", ifname, loop+1);
            break;
        }
        loop++;
    }
    soncli_print_if_err(ret, "BRINGUP",0);
    return ret;
}


void init_config(void)
{
    system("/lib/functions/commands.sh start init");
    system("/lib/functions/commands.sh start config");
    system("/lib/functions/commands.sh start wifi");
}

void son_run( void )
{
   evloopRunPrepare();
   evloopRun();
}

void SON_TestCases(char *ifname)
{
    int ret;
    init_config();

    soncli_print_event(0);
    ret = is_vap_ready(ifname);
    if ( ret < 0 ) {
        printf("<FAILED>: BASIC - BRINGUP: Test Case Failed\n");
        soncli_print_if_err(ret, ifname,0);
        return;
    }
    band = get_band(ifname);
    if ( band == soncli_band_invalid ) {
        ret = -1;
        printf("<FAILED>: BASIC - GET-BAND: Test Case Failed\n");
        soncli_print_if_err(ret,"INBALID-BAND",0);
        return;
    }
    ret = soncli_init_event(ifname);
    soncli_print_if_err(ret, "SOCKET-INIT",0);
    ret = soncli_event_create(ifname);
    soncli_print_if_err(ret, "EVENT-INIT",0);
    printf("\t\t\tWAITING FOR CLIENT...\n");
    son_run();
    soncli_sock_destroy();
}



