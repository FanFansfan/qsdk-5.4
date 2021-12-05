/*
 * @File: son_cli.c
 *
 * @Abstract: Son CLI Application Main File
 *
 * @Notes:
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#include <qcatools_lib.h>         /* library for common headerfiles */
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <time.h>
#include <glob.h>                 /* Including glob.h for glob() function used in find_pid() */
#include <sys/queue.h>
#include <pthread.h>
#include <bufrd.h>
#include <dbg.h>
#ifndef BUILD_X86
#include <netlink/attr.h>
#endif
//#include <ath_ald_external.h>
#include <ieee80211_external.h>
#include <wlan_son_band_steering_api.h>
#include <linux/wireless.h>
#include <unistd.h>
#include <evloop.h>
#include "son_cli.h"

#ifdef SON_MEMORY_DEBUG
#include "meminfo.h"
extern int enable_debug;
#endif

extern int de_event_socket;
struct evloopTimeout timer_soncli;
struct socket_context sock_ctx;

user_input_data_t in_data;

int init_socket_context (struct socket_context *sock_ctx,
        int cmd_sock_id, int event_sock_id)
{
    int err = 0;
#if UMAC_SUPPORT_CFG80211
    if (sock_ctx->cfg80211) {
        sock_ctx->cfg80211_ctxt.pvt_cmd_sock_id = cmd_sock_id;
        sock_ctx->cfg80211_ctxt.pvt_event_sock_id = event_sock_id;

        err = wifi_init_nl80211(&(sock_ctx->cfg80211_ctxt));
        if (err) {
            errx(1, "unable to create NL socket");
            return -EIO;
        }
    }
#endif
    return 0;
}


int send_generic_command_cfg80211(struct socket_context *sock_ctx, const char *ifname, int maincmd, int cmd, char *data, int data_len)
{
    int res;
    struct cfg80211_data buffer;
    buffer.data = (void *)data;
    buffer.length = data_len;
    buffer.callback = NULL;
    buffer.parse_data = 0;

    res = wifi_cfg80211_send_generic_command(&(sock_ctx->cfg80211_ctxt), maincmd, cmd, ifname, (char *)&buffer, data_len);
    if (res < 0) {
        fprintf( stdout, " %s : send NL command failed \n",__func__);
        return res;
    }

    return 0;
}

int send_command_get_cfg80211( struct socket_context *sock_ctx, const char *ifname, int op, int *data)
{
    int ret;
    struct cfg80211_data buffer;
    buffer.data = data;
    buffer.length = sizeof(int);
    buffer.parse_data = 0;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    if((ret=wifi_cfg80211_send_getparam_command(&(sock_ctx->cfg80211_ctxt), QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, op, ifname, (char *)&buffer, sizeof(int))) < 0)
    {
        return -EIO;
    }
    return 0;
}


int send_command (struct socket_context *sock_ctx, const char *ifname, void *buf,
        size_t buflen, void (*callback) (struct cfg80211_data *arg), int cmd, int ioctl_cmd)
{
#if UMAC_SUPPORT_CFG80211
    int msg;
    struct cfg80211_data buffer;
#endif

    if (sock_ctx->cfg80211) {
#if UMAC_SUPPORT_CFG80211
        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = callback;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_generic_command(&(sock_ctx->cfg80211_ctxt),
                cmd,
                ioctl_cmd, ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            printf("Could not send NL command\n");
            return -EIO;
        }
        return buffer.length;
#endif
    }

    return 0;
}

void destroy_socket_context (struct socket_context *sock_ctx)
{
#if UMAC_SUPPORT_CFG80211
    if (sock_ctx->cfg80211) {
        wifi_destroy_nl80211(&(sock_ctx->cfg80211_ctxt));
    }
#endif
    return;
}

void process_user_input(int argc, char **argv, struct user_input_data *input)
{
    int c;
#ifdef SON_MEMORY_DEBUG
    int port_num;
    char procname[APP_CONFIG_LEN];
    memset(procname, 0, APP_CONFIG_LEN);
#endif

    for (;;) {
#ifdef SON_MEMORY_DEBUG
        c = getopt(argc, argv, "i:m:p:r:dvh" );
#else
        c = getopt(argc, argv, "i:vh" );
#endif

        if (c < 0)
            break;

        switch (c) {
            case 'i':
                strlcpy(input->ifname, optarg, IFNAME_LEN);
                break;

#ifdef SON_MEMORY_DEBUG
            case 'm':
                strlcpy(procname, optarg, APP_CONFIG_LEN);
                debug_print("%s: config[%s]", __func__, procname);
                if (strcmp(procname, "hyd-lan") == 0 || strcmp(procname, "hyd") == 0)
                    port_num = SON_CLI_HYD_LAN_PORT;
                else if (strcmp(procname, "hyd-Guest") == 0 || strcmp(procname, "hyd-guest") == 0)
                    port_num = SON_CLI_HYD_GUEST_PORT;
                else if (strcmp(procname, "wsplcd-lan") == 0 || strcmp(procname, "wsplcd") == 0)
                    port_num = SON_CLI_WSPLCD_LAN_PORT;
                else if (strcmp(procname, "wsplcd-Guest") == 0 || strcmp(procname, "wsplcd-guest") == 0)
                    port_num = SON_CLI_WSPLCD_GUEST_PORT;
                else if (strcmp(procname, "lbd") == 0)
                    port_num = SON_CLI_LBD_PORT;
                else
                    port_num = INVALID_PORT_NUM;
                input->memdbg_cli_port = port_num;
                break;
            case 'p':
                input->memdbg_report_interval = atoi(optarg);
                break;
            case 't':
                input->memdbg_repeat_count = atoi(optarg);
                break;
            case 'd':
                enable_debug = 1;
                break;
#endif
            case 'v':
                printf("son_cli: version %s\n", SON_CLI_VERSION);
                exit(0);
                break;
            case 'h':
                printf("usage: son_cli [option]\n\n");
                printf("-i <athX>  : Specify interface name to run UnitTest\n");
#ifdef SON_MEMORY_DEBUG
                printf("-m arg  :   print memory usage informaton of selected SON application\n");
                printf("            (arg: wsplcd|wsplcd-lan, wsplcd-guest, hyd|hyd-lan, hyd-guest, lbd)\n");
                printf("-p n    :   repeat every n seconds, if repeat option '-r' is specified, then default report interval is 10 seconds \n");
                printf("-t n    :   repeat n times for configured report interval using '-p' option \n");
                printf("-d      :   print memory info debug information\n\n");
                printf("-h      :   print this usage and exit\n");
                printf("-v      :   print version information and exit\n");
                printf("\nExample : \n");
                printf("    'son_cli -m wsplcd-lan' - print WSPLCD memory usage information one time and exit\n");
                printf("    'son_cli -m wsplcd-lan -t 20' - print WSPLCD memory usage information repeatedly for 20 times, for every 10 seconds, \n");
                printf("    'son_cli -m wsplcd-lan -p 60 -t 10' - print WSPLCD memory usage information for every 60 seconds, repeatedly for 10 times\n\n");
#endif
                exit(0);
                break;
        }
    }
#ifdef SON_MEMORY_DEBUG
    // set default report interval to 10 seconds
    if (input->memdbg_report_interval == 0 && input->memdbg_repeat_count > 1)
        input->memdbg_report_interval = 10;
    debug_print("Configuration Settings:\nPort Number:[%d]\nReport Interval:[%d]\nRepeat Count:%d\n", input->memdbg_cli_port, input->memdbg_report_interval, input->memdbg_repeat_count);
#endif
}

/* Initialize memory debug parameters */
void initialize_input_parameter(user_input_data_t *input)
{
#ifdef SON_MEMORY_DEBUG
    input->memdbg_cli_port = 0;
    input->memdbg_report_interval = 0;
    input->memdbg_repeat_count = 1;
#endif
   // input->ifname = NULL;
    memset(input->ifname, 0, IFNAME_LEN);
}

extern void  SON_TestCases(char *ifname);

int main(int argc, char *argv[])
{
    // Initialize memory debug parameters
    initialize_input_parameter(&in_data);

    // Read User input options
    process_user_input(argc, argv, &in_data);

#ifdef SON_MEMORY_DEBUG
    if (in_data.memdbg_cli_port) {

        // Retrieve memory usage information
        retrieve_mem_info(&in_data);
    }
#endif

    if (strlen(in_data.ifname) > 0) {
        sock_ctx.cfg80211 = 1;
        init_socket_context(&sock_ctx, DEFAULT_NL80211_CMD_SOCK_ID, DEFAULT_NL80211_EVENT_SOCK_ID);
        SON_TestCases(in_data.ifname);

        destroy_socket_context(&sock_ctx);
    }

    return 0;
}
#if 0
static void help()
{
    printf("Wrong Query\n");
    printf(" Format :: son_cli athX <option> \n");
    printf("\n___________________________________________________________________________\n The following are the options \n ___________________________________________________________________________");
    printf("\nOption             \t\tEVENT ");
    printf("\ninst_rssi            \t\tATH_EVENT_BSTEERING_PROBE_REQ");
    printf("\nchan_util          \t\tATH_EVENT_BSTEERING_CHAN_UTIL");
    printf("\npeer_info          \t\tATH_EVENT_BSTEERING_NODE_ASSOCIATED");
    printf("\ntx_auth_rejec      \t\tATH_EVENT_BSTEERING_TX_AUTH_FAIL");
    printf("\nactivity_change_alert  \t\tATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE");
    printf("\nrssi_threshold_crossed \t\tATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING");
    printf("\nrssi_measurement       \t\tATH_EVENT_BSTEERING_CLIENT_RSSI_MEASUREMENT");
    printf("\nbeacon_frame_report    \t\tATH_EVENT_BSTEERING_RRM_REPORT");
    printf("\nwnm_report             \t\tATH_EVENT_BSTEERING_WNM_EVENT");
    printf("\ntx_rate_threshold      \t\tATH_EVENT_BSTEERING_CLIENT_TX_RATE_CROSSING");
    printf("\ntx_rate_meas_rpt       \t\tATH_EVENT_BSTEERING_DBG_TX_RATE");
    printf("\ntx_power_change        \t\tATH_EVENT_BSTEERING_TX_POWER_CHANGE");
    printf("\nsmps_node_update       \t\tATH_EVENT_BSTEERING_SMPS_UPDATE");
    printf("\nopmode_update          \t\tATH_EVENT_BSTEERING_OPMODE_UPDATE");
    printf("\nrssi_thresh_map        \t\tATH_EVENT_BSTEERING_MAP_CLIENT_RSSI_CROSSING");
    printf("\nsta_stats              \t\tATH_EVENT_BSTEERING_STA_STATS");
    printf("\nhyd_assoc              \t\tIEEE80211_ALD_ASSOCIATE");
    printf("\nhyd_buffull            \t\tIEEE80211_ALD_BUFFULL_WRN");
    printf("\nbsteering_params       \t\tIEEE80211_DBGREQ_BSTEERING_GET_PARAMS");
    printf("\ndatarate_info          \t\tIEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO");
    printf("\ncac_state              \t\tIEEE80211_PARAM_GET_CAC");
    printf("\nacs_state              \t\tIEEE80211_PARAM_GET_ACS");
    printf("\nsecond_center_freq     \t\tIEEE80211_PARAM_SECOND_CENTER_FREQ");
    printf("\nbandwidth              \t\tIEEE80211_PARAM_BANDWIDTH");
    printf("\nchextoffset            \t\tIEEE80211_PARAM_CHEXTOFFSET");
    printf("\nchwidth                \t\tIEEE80211_PARAM_CHWIDTH");
    printf("\nmixedbh_ulrate         \t\tIEEE80211_PARAM_WHC_MIXEDBH_ULRATE");
    printf("\nsmart_monitor          \t\tIEEE80211_PARAM_RX_FILTER_SMART_MONITOR");
    printf("\nssid                   \t\tSIOCGIWESSID");
    printf("\nwap                    \t\tSIOCGIWAP");
    printf("\nfreq                   \t\tSIOCGIWFREQ");
    printf("\nchan_info              \t\tIEEE80211_IOCTL_GETCHANINFO");
    printf("\nchan160_info           \t\tIEEE80211_WLANCONFIG_GETCHANINFO_160");
    printf("\ncfg_sta_stats          \t\tIEEE80211_IOCTL_STA_STATS");
    printf("\nsta_stats_info         \t\tIEEE80211_IOCTL_STA_INFO");
    printf("\nnetif_carrier_status   \t\tIEEE80211_IOCTL_");
    printf("\nFor cfg_sta_stats and sta_stats_info please enter MAC of the station as the 4th argument\n");
}
#endif

