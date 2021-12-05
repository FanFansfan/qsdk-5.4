/*
 * =====================================================================================
 *
 *       Filename:  ath_ssd.c
 *
 *    Description:  Spectral daemon for Atheros UI
 *
 *        Version:  1.0
 *        Created:  12/13/2011 03:58:28 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan ()
 *        Company:  Qualcomm Atheros
 *
 *        Copyright (c) 2012-2021 Qualcomm Technologies, Inc.
 *
 *        All Rights Reserved.
 *        Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 *        2012-2016 Qualcomm Atheros, Inc.
 *
 *        All Rights Reserved.
 *        Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>

#include "classifier.h"
#include "ath_ssd_defs.h"
#include "spectral_data.h"
#include "spec_msg_proto.h"
#include "ath_classifier.h"
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#include "spectral_ioctl.h"

int dot11g_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
int dot11a_channels[] = {36, 40, 44, 48, 149, 153, 157, 161, 165}; // Only Non-DFS channels

static ath_ssd_info_t   ath_ssdinfo;
static ath_ssd_info_t*  pinfo = &ath_ssdinfo;

static char * band2string[WLAN_BAND_MAX] = {"INVALID", "2.4 GHz", "5 GHz", "6 GHz"};
/* Netlink timeout specification (second and microsecond components) */
#define QCA_ATHSSDTOOL_NL_TIMEOUT_SEC         (2)
#define QCA_ATHSSDTOOL_NL_TIMEOUT_USEC        (0)

/* if debug is enabled or not */
int debug   = FALSE;

#ifdef SPECTRAL_SUPPORT_CFG80211
static int init_cfg80211_socket(ath_ssd_info_t *pinfo);
static void destroy_cfg80211_socket(ath_ssd_info_t *pinfo);
static int init_sparams_to_cfg80211_attrs_mapping(ath_ssd_info_t *pinfo);

/*
 * Function     : init_cfg80211_socket
 * Description  : initialize cfg80211 socket
 * Input params : pointer to ath_ssdinfo
 * Return       : SUCCESS or FAILURE
 *
 */
static int init_cfg80211_socket(ath_ssd_info_t *pinfo)
{
    wifi_cfg80211_context *pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
    int status = SUCCESS;

    if (wifi_init_nl80211(pcfg80211_sock_ctx) != 0) {
        status = FAILURE;
    }
    return status;
}

/*
 * Function     : destroy_cfg80211_socket
 * Description  : destroy cfg80211 socket
 * Input params : pointer to ath_ssdinfo
 * Return       : void
 *
 */
static void destroy_cfg80211_socket(ath_ssd_info_t *pinfo)
{
    wifi_destroy_nl80211(GET_ADDR_OF_CFGSOCKINFO(pinfo));
}

/*
 * Helper macro to convert a given Spectral internal parameter to the equivalent
 * cfg80211 attribute. It is the responsibility of the caller to ensure that the
 * correct arguments are passed.
 */
#define ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, param) \
        ((pinfo)->sparams_to_cfg80211_attrs[SPECTRAL_PARAM_##param] = \
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_##param)

/*
 * init_sparams_to_cfg80211_attrs_mapping() - Initialize mapping of Spectral
 * internal parameters to cfg80211 attributes
 * @pinfo: Pointer to ath_ssd_info_t structure
 *
 * Return: SUCCESS/FAILURE
 */
static int init_sparams_to_cfg80211_attrs_mapping(ath_ssd_info_t *pinfo)
{
    ATHSSD_ASSERT(pinfo != NULL);

    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, FFT_PERIOD);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, SCAN_PERIOD);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, SCAN_COUNT);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, SHORT_REPORT);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, FFT_SIZE);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, GC_ENA);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, RESTART_ENA);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, NOISE_FLOOR_REF);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, INIT_DELAY);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, NB_TONE_THR);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, STR_BIN_THR);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, WB_RPT_MODE);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, RSSI_RPT_MODE);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, RSSI_THR);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, PWR_FORMAT);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, RPT_MODE);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, BIN_SCALE);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, DBM_ADJ);
    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, CHN_MASK);

    pinfo->sparams_to_cfg80211_attrs[SPECTRAL_PARAM_SPECT_PRI] =
        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY;

    ATHSSD_CONVERT_SPARAM_TO_CFG80211ATTR(pinfo, FREQUENCY);

    return SUCCESS;
}
#endif /* SPECTRAL_SUPPORT_CFG80211 */


/*
 * Function     : print_usage
 * Description  : print the athssd usage
 * Input params : void
 * Return       : void
 *
 */
void print_usage(void)
{
    printf("athssd - usage\n");
    line();
    printf("a : Enable Agile mode (if available on chipset). \n"
           "    Available only in cfg80211 mode.\n");
    printf("b : Specifies the band in which standalone scan is to be done"
           "    (1 - 2.4 GHz, 2 - 5 GHz, 3 - 6 GHz).\n"
           "    This is optional and defaults to 2.4 GHz or 5 GHz depending on\n"
           "    the channel in which standalone scan is requested.\n"
           "    This field is applicable only when standalone scan is requested\n"
           "    in a channel other than operating channel.\n");
    printf("d : Enable debug prints\n");
    printf("f : Spectral frequency - Currently applicable only \n"
           "    for Agile mode. Center frequency (in MHz) of the \n"
           "    span of interest, or for convenience, center \n"
           "    frequency (in MHz) of any channel in the span \n"
           "    of interest. Indicates primary 80 MHz span \n"
           "    for 80p80 Agile Spectral scan. The value \n"
           "    configured currently serves as the initial value \n"
           "    with which to start operation.\n"
           "    Available only in cfg80211 mode.\n");
    printf("g : Spectral frequency - Currently applicable only \n"
           "    for 80p80 Agile mode. Center frequency (in MHz) of the \n"
           "    secondary 80 MHz span of interest, or for convenience, \n"
           "    center frequency (in MHz) of any channel in the \n"
           "    secondary 80 MHz span of interest. The value \n"
           "    configured currently serves as the initial value \n"
           "    with which to start operation.\n"
           "    Available only in cfg80211 mode.\n");
    printf("h : Print this help message\n");
    printf("i : Radio interface name <wifiX>\n");
    printf("j : Interface name <athX>\n");
    printf("p : Play from file <filename>\n");
    printf("s : Stand alone Spectral scan on operational channel <channel>\n"
           "    In normal mode: <channel> can be 0 in which case the current \n"
           "    operating channel is used.\n"
           "    In Agile mode: The -s option need not be provided since \n"
           "    Agile mode forces stand alone Spectral scan on Spectral \n"
           "    frequency configured using '-f' instead of operational \n"
           "    channel. However if this option is specified, <channel> \n"
           "    must be 0 and this indicates that the operational channel \n"
           "    is inapplicable.\n"
           "    Multiple instances of athssd can be started with stand \n"
           "    alone Spectral operation. This is intended to allow parallel\n"
           "    classification on different radios, or different modes \n"
           "    (Normal vs. Agile) on the same radio. (However currently \n"
           "    parallel classification on the same radio with the same mode \n"
           "    is not prohibited if the user chooses to invoke athssd in \n"
           "    this manner so that some potential debug use cases are \n"
           "    enabled, but there might be limitations in this scenario \n"
           "    such as higher than necessary CPU utilization, restoration \n"
           "    of old configs to those being used by older instance of \n"
           "    athssd rather than other applications, timeout experienced \n"
           "    by other instances on a radio with a given mode if one of \n"
           "    the instances on that radio with that mode is stopped, etc. \n"
           "    Hence this should be used only for debug). \n"
           "    Only a single instance of athssd can be started without stand\n"
           "    alone Spectral operation, though this does not prevent other\n"
           "    instances with stand alone Spectral operation from being \n"
           "    started. Also note that athssd without stand alone Spectral \n"
           "    operation is not supported in production currently and is \n"
           "    present only for some limited debug purposes requiring \n"
           "    additional changes. Invoking athssd without standalone \n"
           "    Spectral operation may currently interfere with other \n"
           "    parallel instances on the same radio.\n");
    printf("u : Use udp socket\n");
    printf("c : Capture None:0 MWO:1 CW:2 WiFi:3 FHSS:4 ALL:5\n");
    printf("x : Enable(1)/disable(0) generation III linear bin\n"
           "    format scaling (default: %s). Will be ignored\n"
           "    for other generations.\n",
           (ATH_SSD_ENAB_GEN3_LINEAR_SCALING_DEFAULT) ? "enabled":"disabled");
    printf("z : Spectral scan priority, 0 - low priority, 1 - High priority\n");
    line();
    exit(0);
}

/*
 * Function     : issue_start_spectral_cmd
 * Description  : starts spectral scan command
 * Input params : void
 * Return       : SUCCESS/FAILURE
 */
int issue_start_spectral_cmd(void)
{
    enum ieee80211_cwm_width ch_width;
    ch_width = get_channel_width(pinfo);
    struct spectral_param param = {0};

    /* Save configuration to restore it back after stop scan */
    if (save_spectral_configuration() != SUCCESS) {
        return FAILURE;
    }

    param.id = SPECTRAL_PARAM_FFT_SIZE;
    switch (ch_width) {
        case IEEE80211_CWM_WIDTH20:
          param.value = 7 - (pinfo->caps.num_detectors_20mhz - 1);
          break;
        case IEEE80211_CWM_WIDTH40:
          param.value = 8 - (pinfo->caps.num_detectors_40mhz - 1);
          break;
        case IEEE80211_CWM_WIDTH80:
         param.value  = 9 - (pinfo->caps.num_detectors_80mhz - 1);
          break;
        case IEEE80211_CWM_WIDTH160:
          param.value = 10 - (pinfo->caps.num_detectors_160mhz - 1);
          break;
        case IEEE80211_CWM_WIDTH80_80:
          param.value = 10 - (pinfo->caps.num_detectors_80p80mhz - 1);
          break;
        case IEEE80211_CWM_WIDTHINVALID:
        default:
          fprintf(stderr, "Invalid channel width\n");
          return FAILURE;
    }

    if (ath_ssd_set_spectral_param(pinfo, &param) != SUCCESS) {
        return FAILURE;
    }

    param.id = SPECTRAL_PARAM_SPECT_PRI;
    param.value = pinfo->spectral_scan_priority;
    if (ath_ssd_set_spectral_param(pinfo, &param) != SUCCESS) {
            goto fail_with_restore;
    }

    if (pinfo->spectral_mode == SPECTRAL_SCAN_MODE_AGILE) {
        ATHSSD_ASSERT(pinfo->spectral_frequency.cfreq1 != 0);
        param.id = SPECTRAL_PARAM_FREQUENCY;
        param.value1 = pinfo->spectral_frequency.cfreq1;
        param.value2 = pinfo->spectral_frequency.cfreq2;
        if (ath_ssd_set_spectral_param(pinfo, &param) != SUCCESS) {
                goto fail_with_restore;
        }
    }

    param.id = SPECTRAL_PARAM_RPT_MODE;
    param.value = 2;
    if (ath_ssd_set_spectral_param(pinfo, &param) != SUCCESS) {
        goto fail_with_restore;
    }

    param.id = SPECTRAL_PARAM_PWR_FORMAT;
    param.value = 0;
    if (ath_ssd_set_spectral_param(pinfo, &param) != SUCCESS) {
        goto fail_with_restore;
    }

    param.id = SPECTRAL_PARAM_BIN_SCALE;
    param.value = 1;
    if (ath_ssd_set_spectral_param(pinfo, &param) != SUCCESS) {
        goto fail_with_restore;
    }

    param.id = SPECTRAL_PARAM_SCAN_COUNT;
    param.value = 0;
    if (ath_ssd_set_spectral_param(pinfo, &param) != SUCCESS) {
        goto fail_with_restore;
    }

    if (ath_ssd_start_spectral_scan(pinfo) != SUCCESS) {
        goto fail_with_restore;
    }

    return SUCCESS;

fail_with_restore:
    restore_spectral_configuration();

    return FAILURE;
}

/*
 * Function     : save_spectral_configuration
 * Description  : Save the values of Spectral parameters
 * Input params : void
 * Return       : SUCCESS/FAILURE
 */
int save_spectral_configuration(void)
{
    if (ath_ssd_get_spectral_param(pinfo, &pinfo->prev_spectral_params)
            != SUCCESS) {
            return FAILURE;
    }

    pinfo->prev_spectral_params_valid = true;

    return SUCCESS;
}

/*
 * Function     : restore_spectral_configuration
 * Description  : Restore the previous values of Spectral parameters. This is
 *                done on a best effort basis - even if there are errors in
 *                restoring some of the parameters, we continue and try to cover
 *                all the remaining parameters. This function is intended to be
 *                called as part of application clean up.
 * Input params : void
 * Return       : void
 */
void restore_spectral_configuration(void)
{
    struct spectral_param param = {0};

    if (!pinfo->prev_spectral_params_valid)
        return;

    /* Only the following parameters have been modifed by athssd, write them back */

    param.id = SPECTRAL_PARAM_SPECT_PRI;
    param.value = pinfo->prev_spectral_params.ss_spectral_pri;
    ath_ssd_set_spectral_param(pinfo, &param);

    param.id = SPECTRAL_PARAM_FFT_SIZE;
    param.value = pinfo->prev_spectral_params.ss_fft_size;
    ath_ssd_set_spectral_param(pinfo, &param);

    param.id = SPECTRAL_PARAM_RPT_MODE;
    param.value = pinfo->prev_spectral_params.ss_rpt_mode;
    ath_ssd_set_spectral_param(pinfo, &param);

    param.id = SPECTRAL_PARAM_PWR_FORMAT;
    param.value = pinfo->prev_spectral_params.ss_pwr_format;
    ath_ssd_set_spectral_param(pinfo, &param);

    param.id = SPECTRAL_PARAM_BIN_SCALE;
    param.value = pinfo->prev_spectral_params.ss_bin_scale;
    ath_ssd_set_spectral_param(pinfo, &param);

    param.id = SPECTRAL_PARAM_SCAN_COUNT;
    param.value = pinfo->prev_spectral_params.ss_count;
    ath_ssd_set_spectral_param(pinfo, &param);
}

/*
 * Function     : issue_stop_spectral_cmd
 * Description  : starts spectral scan command
 * Input params : void
 * Return       : void
 *
 */
void issue_stop_spectral_cmd(void)
{
    ath_ssd_stop_spectral_scan(pinfo);
    restore_spectral_configuration();
}

/*
 * Function     : init_inet_sockinfo
 * Description  : initializes inet socket info
 * Input params : pointer to ath_ssdinfo
 * Return       : SUCCESS or FAILURE
 *
 */
int init_inet_sockinfo(ath_ssd_info_t *pinfo)
{
    int status = SUCCESS;
    ath_ssd_inet_t      *pinet = GET_ADDR_OF_INETINFO(pinfo);

    /* init socket interface */
    pinet->listener = socket(PF_INET, SOCK_STREAM, 0);

    /* validate */
    if (pinet->listener < 0) {
        perror("unable to open socket\n");
        status = FAILURE;
    }

    /* set socket option : Reuse */
    if (setsockopt(pinet->listener, SOL_SOCKET, SO_REUSEADDR, &pinet->on, sizeof(pinet->on)) < 0) {
        perror("socket option failed\n");
        close(pinet->listener);
        status = FAILURE;
    }

    /* initialize ..... */
    memset(&pinet->server_addr, 0, sizeof(pinet->server_addr));
    pinet->server_addr.sin_family  = AF_INET;
    pinet->server_addr.sin_port    = htons(ATHPORT);
    pinet->server_addr.sin_addr.s_addr = INADDR_ANY;
    pinet->type = SOCK_TYPE_TCP;

    /* bind the listener socket */
    if (bind(pinet->listener, (struct sockaddr*)&pinet->server_addr, sizeof(pinet->server_addr)) < 0) {
        perror("bind error\n");
        close(pinet->listener);
        status = FAILURE;
    }

    /* start listening */
    if (listen(pinet->listener, BACKLOG) == -1) {
        perror("listen error\n");
        close(pinet->listener);
        status = FAILURE;
    }

    if (status) {
        info("socket init done");
    } else {
        info("socket init fail");
    }

    return status;
}

/*
 * Function     : init_inet_dgram_sockinfo
 * Description  : initializes inet datagram socket info
 * Input params : pointer to ath_ssdinfo
 * Return       : SUCCESS or FAILURE
 *
 */
int init_inet_dgram_sockinfo(ath_ssd_info_t *pinfo)
{
    int status = SUCCESS;
    ath_ssd_inet_t  *pinet = GET_ADDR_OF_INETINFO(pinfo);

    /* init socket interface */
    pinet->listener = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (pinet->listener < 0) {
        perror("unable to open socket\n");
        status = FAILURE;
    }

    /* initialize..... */
    memset(&pinet->server_addr, 0, sizeof(pinet->server_addr));
    pinet->server_addr.sin_family   = AF_INET;
    pinet->server_addr.sin_port     = htons(ATHPORT);
    pinet->server_addr.sin_addr.s_addr = INADDR_ANY;

    pinet->type = SOCK_TYPE_UDP;
    pinet->client_fd = INVALID_FD;

    /* bind the listener socket */
    if (bind(pinet->listener, (struct sockaddr*)&pinet->server_addr, sizeof(pinet->server_addr)) < 0) {
        perror("bind error\n");
        close(pinet->listener);
        status = FAILURE;
    }

    if (status) {
        info("udp socket init done");
    } else {
        info("udp socket init fail");
    }

    return status;
}

/*
 * Function    : ath_ssd_get_free_mem
 * Description : Get amount of free physical memory, in bytes.
 * Input       : Pointer into which the value for free physical memory in bytes
 *               should be populated - value is valid only on success.
 * Output      : SUCCESS or FAILURE
 */
static int ath_ssd_get_free_mem(size_t *free_mem_bytes)
{
    FILE* fp = NULL;
    char line[256];
    size_t free_mem_kibibytes = 0;
    bool entry_found = false;

    ATHSSD_ASSERT(free_mem_bytes != NULL);

    fp = fopen("/proc/meminfo", "r");

    if (NULL == fp) {
        perror("fopen");
        return FAILURE;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemFree: %zu kB", &free_mem_kibibytes) == 1) {
            entry_found = true;
            break;
        }
    }

    fclose(fp);

    if (entry_found) {
        *free_mem_bytes = free_mem_kibibytes * 1024;
        return SUCCESS;
    } else {
        return FAILURE;
    }
}

/*
 * Function     : ath_ssd_init_sock_rx_buffer_size
 * Description  : On some platforms and under some circumstances, our netlink
 *                message receive rate may not be able to keep up with the
 *                driver's send rate. This can result in receive buffer errors.
 *                To mitigate this, we try to increase the socket receive buffer
 *                size from its default.
 * Input params : Pointer to ath_ssd_info_t and socket file descriptor
 * Return       : SUCCESS/FAILURE
 */
int ath_ssd_init_sock_rx_buffer_size(ath_ssd_info_t *pinfo, int sock_fd)
{
    int ret = FAILURE;
    unsigned long long limit_temp = 0;
    unsigned long long req_temp = 0;
    /* Note: SO_RCVBUF/SO_RCVBUFFORCE expect receive buffer sizes as integer
     * values. Hence the corresponding variables below are integers.
     */
    /* Receive buffer size to be requested */
    int rbuff_sz_req = 0;
    /* Upper limit on receive buffer size to be requested */
    int rbuff_sz_req_limit = 0;
    /* Current receive buffer size */
    int rbuff_sz_curr = 0;
    /* Length of current receive buffer size datatype */
    socklen_t rbuff_sz_curr_len = 0;
    /* Free physical memory */
    size_t free_mem = 0;

    /* Get current receive buffer size */
    rbuff_sz_curr_len = sizeof(rbuff_sz_curr);
    if (getsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF,
                   (void *)&rbuff_sz_curr,
                   &rbuff_sz_curr_len) < 0) {
        perror("getsockopt\n");
        goto fail;
    }

    /* The value returned is double the actual size, for book-keeping reasons.
     * So divide by 2.
     */
    rbuff_sz_curr /= 2;

    pinfo->rbuff_sz_def = rbuff_sz_curr;
    if (0 == pinfo->rbuff_sz_def) {
        fprintf(stderr, "Default effective receive buffer size is unexpectedly zero\n");
        goto fail;
    }

    /* Calculate upper limit on receive buffer size we'd like to request */
    if (ath_ssd_get_free_mem(&free_mem) != SUCCESS) {
        fprintf(stderr, "Could not determine amount of free physical memory\n");
        goto fail;
    }

    ATHSSD_ASSERT(ATHSSD_MAX_FREEMEM_UTIL_PERCENT <= 100);

    limit_temp = ((unsigned long long)free_mem *
                        ATHSSD_MAX_FREEMEM_UTIL_PERCENT)/100;

    /* Since the kernel will double the size for book-keeping reasons, keep the
     * limit at half of INT_MAX.
     */
    if (limit_temp > INT_MAX/2)
        limit_temp = INT_MAX/2;

    rbuff_sz_req_limit = limit_temp;

    /* Determine the receive buffer size to be requested */
    req_temp = rbuff_sz_curr * ATHSSD_SPECTRAL_SOCK_RX_BUFF_MULTIPLICATION_FACTOR;

    if (req_temp > INT_MAX/2)
        req_temp = INT_MAX/2;

    rbuff_sz_req = req_temp;

    if (rbuff_sz_req > rbuff_sz_req_limit)
        rbuff_sz_req = rbuff_sz_req_limit;

    if (rbuff_sz_req > rbuff_sz_curr) {
        /* We first try SO_RCVBUFFORCE. This is available since Linux 2.6.14,
         * and if we have CAP_NET_ADMIN privileges.
         *
         * In case we are not entitled to use it, then an error will be returned
         * and we can fall back to SO_RCVBUF. If we use SO_RCVBUF, the kernel
         * will cap our requested value as per rmem_max. We will have to survive
         * with the possibility of a few netlink messages being lost under some
         * circumstances.
         */
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                            (void *)&rbuff_sz_req, sizeof(rbuff_sz_req)) < 0) {
            if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF,
                             (void *)&rbuff_sz_req, sizeof(rbuff_sz_req)) < 0) {
                perror("setsockopt\n");
                goto fail;
            }
        }
    }
    /* Else if rbuff_sz_req < rbuff_sz_curr, we go with the default configured
     * into the kernel. We will have to survive with the possibility of a few
     * netlink messages being lost under some circumstances in case rbuff_sz_req
     * has been capped to below what we would ideally have desired.
     */
    ret = SUCCESS;

fail:
    return ret;
}

/*
 * Function     : ath_ssd_deinit_sock_rx_buffer_size
 * Description  : Restore default socket receive buffer size for Spectral netlink
 *                socket.
 * Input params : Pointer to ath_ssd_info_t structure and socket file descriptor
 * Return       : SUCCESS/FAILURE
 */
int ath_ssd_deinit_sock_rx_buffer_size(ath_ssd_info_t *pinfo, int sock_fd)
{
    int ret = FAILURE;

    if (0 == pinfo->rbuff_sz_def) {
        goto fail;
    }

    /* We first try SO_RCVBUFFORCE so that we have a better chance of restoring
     * the default, even for corner cases if any. This is available since Linux
     * 2.6.14, and if we have CAP_NET_ADMIN privileges.
     *
     * In case we are not entitled to use it, then an error will be returned
     * and we can fall back to SO_RCVBUF.
     */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                        (void *)&pinfo->rbuff_sz_def,
                        sizeof(pinfo->rbuff_sz_def)) < 0) {
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF,
                         (void *)&pinfo->rbuff_sz_def,
                         sizeof(pinfo->rbuff_sz_def)) < 0) {
            perror("setsockopt\n");
            goto fail;
        }
    }

    ret = SUCCESS;

fail:
    return ret;
}

/*
 * Function     : init_nl_sockinfo
 * Description  : initializes netlink socket info
 * Input params : pointer to ath_ssdinfo
 * Return       : SUCCESS or FAILURE
 *
 */
int init_nl_sockinfo(ath_ssd_info_t *pinfo)
{
    int status = FAILURE;
    ath_ssd_nlsock_t *pnl = GET_ADDR_OF_NLSOCKINFO(pinfo);

    /* init netlink connection to spectral driver */
    pnl->spectral_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ATHEROS);

    /* validate ..... */
    if (pnl->spectral_fd < 0) {
        perror("netlink error\n");
        goto fail;
    }

    if (ath_ssd_init_sock_rx_buffer_size(pinfo, pnl->spectral_fd) != SUCCESS) {
        fprintf(stderr, "Failed to initialize the socket rx buffer size\n");
        goto fail;
    }

    /* init netlink socket */
    memset(&pnl->src_addr, 0, sizeof(pnl->src_addr));
    pnl->src_addr.nl_family  = PF_NETLINK;
    pnl->src_addr.nl_pid     = getpid();
    pnl->src_addr.nl_groups  = 1;

    /* bind to the kernel sockets */
    if (bind(pnl->spectral_fd, (struct sockaddr*)&pnl->src_addr, sizeof(pnl->src_addr)) < 0) {
        perror("netlink bind error\n");
        close(pnl->spectral_fd);
        goto fail;
    }

    status = SUCCESS;

fail:
    if (status) {
        info("netlink socket init done");
    } else {
        info("netlink socket init fail");
    }

    return status;
}

/*
 * Function     : accept_new_connection
 * Description  : accepts new client connections
 * Input params : pointer to ath_ssdinfo
 * Return       : SUCCESS or FAILURE
 *
 */
int accept_new_connection(ath_ssd_info_t *pinfo)
{
    int status = SUCCESS;
    ath_ssd_inet_t *pinet = GET_ADDR_OF_INETINFO(pinfo);

    pinet->addrlen = sizeof(pinet->client_addr);

    if ((pinet->client_fd = accept(pinet->listener, (struct sockaddr*)&pinet->client_addr, &pinet->addrlen)) == -1) {
            perror("unable to accept connection\n");
            status = FAILURE;
    }

    if (status) {
      info("new connection from %s on socket %d\n",\
            inet_ntoa(pinet->client_addr.sin_addr), pinet->client_fd);
    }

    return status;
}

/*
 * Function     : get_iface_macaddr
 * Description  : get MAC address of interface
 * Input params : interface name
 * Output params: MAC address filled into pointer to buffer
 *                passed, on success
 * Return       : SUCCESS/FAILURE
 *
 */
int get_iface_macaddr(char *ifname, u_int8_t *macaddr)
{
    struct ifreq  ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (ifname == NULL || macaddr == NULL) {
        close(fd);
        return FAILURE;
    }

    if (strlcpy(ifr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        fprintf(stderr, "ifname too long: %s\n", ifname);
        close(fd);
        return FAILURE;
    }

    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("SIOCGIFHWADDR");
        close(fd);
        return FAILURE;
    }

    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);

    return SUCCESS;
}

/*
 * Function     : new_process_spectral_msg
 * Description  : send data to client
 * Input params : pointer to ath_ssd_info_t, pointer to msg, msg length
 * Return       : SUCCESS or FAILURE
 *
 */
void new_process_spectral_msg(ath_ssd_info_t *pinfo, struct spectral_samp_msg* msg,
                              bool enable_gen3_linear_scaling)
{
    int count = 0;
    struct interf_src_rsp   *rsp    = NULL;
    struct interf_rsp*interf_rsp    = NULL ;
    CLASSIFER_DATA_STRUCT *pclas    = NULL;
    struct spectral_samp_data *ss_data     = NULL;


    /* validate */
    if (msg->signature != SPECTRAL_SIGNATURE) {
        return;
    }

    if (memcmp(pinfo->radio_macaddr, msg->macaddr,
                MIN(sizeof(pinfo->radio_macaddr), sizeof(msg->macaddr)))) {
        return;
    }

    if (msg->samp_data.spectral_mode != pinfo->spectral_mode) {
        return;
    }

    ss_data     = &msg->samp_data;
    rsp         = &ss_data->interf_list;
    interf_rsp  = &rsp->interf[0];
    pclas       = get_classifier_data(msg->macaddr);

    classifier_process_spectral_msg(msg, pclas, pinfo->log_mode,
            enable_gen3_linear_scaling);

    if (IS_MWO_DETECTED(pclas)) {
        interf_rsp->interf_type = INTERF_MW;
        interf_rsp++;
        count++;
    }


    if (IS_CW_DETECTED(pclas)) {
        interf_rsp->interf_type = INTERF_TONE;
        interf_rsp++;
        count++;
    }

    if (IS_WiFi_DETECTED(pclas)) {
        interf_rsp->interf_type = INTERF_WIFI;
        interf_rsp++;
        count++;
    }

    if (IS_CORDLESS_24_DETECTED(pclas)) {
        interf_rsp->interf_type = INTERF_CORDLESS_2GHZ;
        interf_rsp++;
        count++;
    }

    if (IS_CORDLESS_5_DETECTED(pclas)) {
        interf_rsp->interf_type = INTERF_CORDLESS_5GHZ;
        interf_rsp++;
        count++;
    }

    if (IS_BT_DETECTED(pclas)) {
        interf_rsp->interf_type = INTERF_BT;
        interf_rsp++;
        count++;
    }

    if (IS_FHSS_DETECTED(pclas)) {
        interf_rsp->interf_type = INTERF_FHSS;
        interf_rsp++;
        count++;
    }

    /* update the interference count */
    rsp->count = htons(count);

}



/*
 * Function     : send_to_client
 * Description  : send data to client
 * Input params : pointer to ath_ssd_info_t, pointer to msg, msg length
 * Return       : SUCCESS or FAILURE
 *
 */
int send_to_client(ath_ssd_info_t *pinfo, struct spectral_samp_msg* ss_msg, int len)
{
    int err = -1;
    ath_ssd_inet_t *pinet = GET_ADDR_OF_INETINFO(pinfo);

    if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_UDP) {

          err = sendto(pinet->listener, ss_msg, len, 0,
                     (struct sockaddr*)&pinet->peer_addr,
                     pinet->peer_addr_len );

    } else if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_TCP) {

          err = send(pinet->client_fd, ss_msg, len, 0);

    }

    return err;
}
/*
 * Function     : handle_spectral_data
 * Description  : receive data from spectral driver
 * Input params : pointer to ath_ssdinfo
 * Return       : SUCCESS or FAILURE
 *
 */
int handle_spectral_data(ath_ssd_info_t *pinfo)
{

    ath_ssd_nlsock_t *pnl = GET_ADDR_OF_NLSOCKINFO(pinfo);
    ath_ssd_stats_t *pstats = GET_ADDR_OF_STATS(pinfo);
    struct nlmsghdr  *nlh = NULL;
    struct msghdr     msg;
    struct iovec      iov;
    int status = SUCCESS;
    int err = SUCCESS;
    int sockerr = 0;
    static int msg_pace_rate = 0;

    struct spectral_samp_msg *ss_msg = NULL;
    struct spectral_samp_data  *ss_data = NULL;

    if (!(nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(sizeof(struct spectral_samp_msg))))) {
        perror("no memory");
        status = FAILURE;
        return status;
    }

    memset(nlh, 0, NLMSG_SPACE(sizeof(struct spectral_samp_msg)));
    nlh->nlmsg_len  = NLMSG_SPACE(sizeof(struct spectral_samp_msg));
    nlh->nlmsg_pid  = getpid();
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len  = nlh->nlmsg_len;

    memset(&pnl->dst_addr, 0, sizeof(pnl->dst_addr));

    pnl->dst_addr.nl_family = PF_NETLINK;
    pnl->dst_addr.nl_pid    = 0;
    pnl->dst_addr.nl_groups = 1;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void*)&pnl->dst_addr;
    msg.msg_namelen = sizeof(pnl->dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* receive spectral data from spectral driver */
    sockerr = recvmsg(pnl->spectral_fd, &msg, MSG_WAITALL);

    ss_msg = (struct spectral_samp_msg*)NLMSG_DATA(nlh);
    ss_data = &ss_msg->samp_data;

    /* mute compiler number */
    ss_data = ss_data;


    if (sockerr >= 0) {
        if (nlh->nlmsg_len) {
            new_process_spectral_msg(pinfo, ss_msg, pinfo->enable_gen3_linear_scaling);
            if (pinfo->do_standalone_scan == FALSE) {
                msg_pace_rate++;
                if (msg_pace_rate == MSG_PACE_THRESHOLD) {
                    send_to_client(pinfo, ss_msg,
                            sizeof(struct spectral_samp_msg));
                    pstats->ch[pinfo->current_channel].sent_msg++;
                    msg_pace_rate = 0;
                }
            }
        }

        if (err == -1) {
            perror("send err");
            status = FAILURE;
        }
    } else if (ENOBUFS == errno) {
         pinfo->num_rbuff_errors++;
    }

    /* free the resource */
    free(nlh);

    return status;
}

/*
 * Function     : init_inet_sockinfo
 * Description  : initializes inet socket info
 * Input params : pointer to ath_ssdinfo
 * Return       : SUCCESS or FAILURE
 *
 */
int handle_client_data(ath_ssd_info_t *pinfo, int fd)
{
    int recvd_bytes = 0;
    int err = 0;

    ath_ssd_inet_t *pinet = GET_ADDR_OF_INETINFO(pinfo);

    struct TLV *tlv              = NULL;
    int buf[MAX_PAYLOAD] = {'\0'};
    int tlv_len = 0;

    if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_UDP) {
        char host[NI_MAXHOST];
        char service[NI_MAXSERV];
        pinet->peer_addr_len = sizeof(pinet->peer_addr);
        recvd_bytes = recvfrom(fd, buf, sizeof(buf), 0,
            (struct sockaddr*)&pinet->peer_addr, &pinet->peer_addr_len);

        getnameinfo((struct sockaddr*)&pinet->peer_addr,
            pinet->peer_addr_len, host, NI_MAXHOST, service,
            NI_MAXSERV, NI_NUMERICSERV);

        if (recvd_bytes == -1) {
            /* ignore failed attempts */
            return 0;
        }
     } else if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_TCP) {
        if ((recvd_bytes = recv(fd, buf, sizeof(buf), 0)) <= 0) {
            perror("recv error");
            err = -1;
        }
     }

    tlv = (struct TLV*)buf;
    tlv_len = htons(tlv->len);

    /* mute compiler warning */
    tlv_len = tlv_len;

    switch (tlv->tag) {
        case START_SCAN:
            start_spectral_scan(pinfo);
            break;
        case STOP_SCAN:
            stop_spectral_scan(pinfo);
            break;
        case START_CLASSIFY_SCAN:
            start_classifiy_spectral_scan(pinfo);
            break;
        default:
            printf("Tag (%d) Not supported\n", tlv->tag);
            break;
    }

    return err;
}

/*
 * Function     : update_next_channel
 * Description  : switch to next channel; while doing the scan
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void update_next_channel(ath_ssd_info_t *pinfo)
{
    if ((pinfo->channel_index >= pinfo->max_channels)) {
        pinfo->channel_index = 0;
    }
    pinfo->current_channel = pinfo->channel_list[pinfo->channel_index++];
}

/*
 * Function     : stop_spectral_scan
 * Description  : stop the ongoing spectral scan
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void stop_spectral_scan(ath_ssd_info_t *pinfo)
{
    pinfo->channel_index = 0;
    ath_ssd_stop_spectral_scan(pinfo);
    restore_spectral_configuration();
    alarm(0);
}

/*
 * Function     : switch_channel
 * Description  : swith channel; do necessary initialization
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void switch_channel(ath_ssd_info_t *pinfo)
{
    char cmd[CMD_BUF_SIZE] = {'\0'};

    /* disable timer */
    alarm(0);

    /* get the next channel to scan */
    update_next_channel(pinfo);


    /* change the channel */
    info("current channel = %d\n", pinfo->current_channel);
    snprintf(cmd, sizeof(cmd), "%s %s %s %1d", "iwconfig", pinfo->dev_ifname, "channel", pinfo->current_channel);
    system(cmd);

    pinfo->init_classifier = TRUE;
}

/*
 * Function     : start_spectral_scan
 * Description  : start the spectral scan
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void start_spectral_scan(ath_ssd_info_t *pinfo)
{
    pinfo->channel_index   = 0;
    pinfo->dwell_interval  = CHANNEL_NORMAL_DWELL_INTERVAL;
    switch_channel(pinfo);
    issue_start_spectral_cmd();
    alarm(pinfo->dwell_interval);
}

/*
 * Function     : start_classifiy_spectral_scan
 * Description  : start the classify spectral scan
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void start_classifiy_spectral_scan(ath_ssd_info_t *pinfo)
{
    pinfo->channel_index   = 0;
    pinfo->dwell_interval  = CHANNEL_CLASSIFY_DWELL_INTERVAL;
    switch_channel(pinfo);
    issue_start_spectral_cmd();
    alarm(pinfo->dwell_interval);
}

/*
 * Function     : print_interf_details
 * Description  : prints interference info for give type
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
char interf_name[6][32] = {
    "None",
    "Microwave",
    "Bluetooth",
    "DECT phone",
    "Tone",
    "Other",
};
void print_interf_details(ath_ssd_info_t *pinfo, eINTERF_TYPE type)
{
    ath_ssd_interf_info_t *p = &pinfo->interf_info;
    struct interf_rsp *interf_rsp = NULL;

    if ((type < INTERF_NONE) || (type > INTERF_OTHER)) {
        return;
    }

    interf_rsp = &p->interf_rsp[type];

    line();
    printf("Interference Type       = %s\n", interf_name[type]);
    printf("Interference min freq   = %d\n", interf_rsp->interf_min_freq);
    printf("Interference max freq   = %d\n", interf_rsp->interf_max_freq);
    line();
}


/*
 * Function     : print_ssd_stats
 * Description  : prints stats info
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void print_ssd_stats(ath_ssd_info_t *pinfo)
{
    ath_ssd_stats_t *pstats = GET_ADDR_OF_STATS(pinfo);
    int i = 1;

    line();
    printf("Channel/Message Stats\n");
    line();
    for (i = 1; i < MAX_CHANNELS; i++) {
        printf("channel = %2d  sent msg = %llu\n", i, pstats->ch[i].sent_msg);
    }
    line();

}

/*
 * Function     : cleanup
 * Description  : release all socket, memory and others before exiting
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void cleanup(ath_ssd_info_t *pinfo)
{
    ath_ssd_inet_t *pinet = GET_ADDR_OF_INETINFO(pinfo);
    ath_ssd_nlsock_t *pnl = GET_ADDR_OF_NLSOCKINFO(pinfo);

    if (!pinfo->replay)
    	stop_spectral_scan(pinfo);

    if (pinfo->do_standalone_scan == FALSE) {
        close(pinet->listener);
        close(pinet->client_fd);
    }

    close(pnl->spectral_fd);
#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        destroy_cfg80211_socket(pinfo);
    }
#endif /* SPECTRAL_SUPPORT_CFG80211 */

    /* print debug info */
    if (IS_DBG_ENABLED()) {
        if (pinfo->num_rbuff_errors)
        {
            printf("Warning: %hu receive buffer errors. Some samples were lost due "
                   "to receive-rate constraints\n", pinfo->num_rbuff_errors);
        }
    }
    print_spect_int_stats();
    exit(0);
}

/*
 * Function     : alarm_handler
 * Description  : alarm signal handler, used to switch channel
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void alarm_handler(ath_ssd_info_t *pinfo)
{
    /* disable the timer */
    alarm(0);
    /* stop any active spectral scan */
    issue_stop_spectral_cmd();

    /* print debug info */
    if (IS_DBG_ENABLED()) {
        print_ssd_stats(pinfo);
    }

    /* switch to new channel */
    switch_channel(pinfo);

    /* enable the timer handler */
    alarm(pinfo->dwell_interval);

    /* start spectral scan */
    issue_start_spectral_cmd();
}

/*
 * Function     : signal_handler
 * Description  : signal handler
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void signal_handler(int signal)
{
    switch (signal) {
        case SIGHUP:
        case SIGTERM:
        case SIGINT:
            cleanup(pinfo);
            break;
        case SIGALRM:
            alarm_handler(pinfo);
            break;
    }
}

/*
 * Function     : print_spectral_SAMP_msg
 * Description  : print spectral message info
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void print_spectral_SAMP_msg(struct spectral_samp_msg* ss_msg)
{
    int i = 0;

    struct spectral_samp_data *p = &ss_msg->samp_data;
    struct spectral_classifier_params *pc = &p->classifier_params;
    struct interf_src_rsp  *pi = &p->interf_list;

    line();
    printf("Spectral Message\n");
    line();
    printf("Signature   :   0x%x\n", ss_msg->signature);
    printf("Freq        :   %d\n", ss_msg->freq);
    printf("Agile freq1 :   %u\n", ss_msg->agile_freq1);
    printf("Agile freq2 :   %u\n", ss_msg->agile_freq2);
    printf("Freq load   :   %d\n", ss_msg->freq_loading);
    printf("Inter type  :   %d\n", ss_msg->int_type);
    line();
    printf("Spectral Data info\n");
    line();
    printf("data length     :   %d\n", p->spectral_data_len);
    printf("rssi            :   %d\n", p->spectral_rssi);
    printf("combined rssi   :   %d\n", p->spectral_combined_rssi);
    printf("upper rssi      :   %d\n", p->spectral_upper_rssi);
    printf("lower rssi      :   %d\n", p->spectral_lower_rssi);
    printf("bw info         :   %d\n", p->spectral_bwinfo);
    printf("timestamp       :   %d\n", p->spectral_tstamp);
    printf("max index       :   %d\n", p->spectral_max_index);
    printf("max exp         :   %d\n", p->spectral_max_exp);
    printf("max mag         :   %d\n", p->spectral_max_mag);
    printf("last timstamp   :   %d\n", p->spectral_last_tstamp);
    printf("upper max idx   :   %d\n", p->spectral_upper_max_index);
    printf("lower max idx   :   %d\n", p->spectral_lower_max_index);
    printf("bin power count :   %d\n", p->bin_pwr_count);
    line();
    printf("Classifier info\n");
    line();
    printf("20/40 Mode      :   %d\n", pc->spectral_20_40_mode);
    printf("dc index        :   %d\n", pc->spectral_dc_index);
    printf("dc in MHz       :   %d\n", pc->spectral_dc_in_mhz);
    printf("upper channel   :   %d\n", pc->upper_chan_in_mhz);
    printf("lower channel   :   %d\n", pc->lower_chan_in_mhz);
    line();
    printf("Interference info\n");
    line();
    printf("inter count     :   %d\n", pi->count);

    for (i = 0; i < pi->count; i++) {
        printf("inter type  :   %d\n", pi->interf[i].interf_type);
        printf("min freq    :   %d\n", pi->interf[i].interf_min_freq);
        printf("max freq    :   %d\n", pi->interf[i].interf_max_freq);
    }

}

/*
 * Function     : clear_interference_info
 * Description  : clear interference related info
 * Input params : pointer to ath_ssd_info_t
 * Return       : void
 *
 */
void clear_interference_info(ath_ssd_info_t *pinfo)
{
    ath_ssd_interf_info_t *p = &pinfo->interf_info;
    p->count = 0;
    memset(p, 0, sizeof(ath_ssd_interf_info_t));
}

/*
 * Function     : update_interf_info
 * Description  : update cumulative interference report
 * Input params : pointer to ath_ssd_info_t, pointer to classifier data
 * Return       : void
 *
 */
int update_interf_info(ath_ssd_info_t *pinfo, struct ss *bd)
{
    int interf_count = 0;
    int num_types_detected = 0;
    ath_ssd_interf_info_t *p = &pinfo->interf_info;
    struct interf_rsp *interf_rsp = NULL;

    if (bd->count_mwo) {
        interf_rsp = &p->interf_rsp[INTERF_MW];
        interf_rsp->interf_min_freq = (bd->mwo_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->mwo_max_freq/1000);
        interf_rsp->interf_type = INTERF_MW;
        num_types_detected++;
    }

    if (bd->count_bts) {
        interf_rsp = &p->interf_rsp[INTERF_BT];
        interf_rsp->interf_min_freq = (bd->bts_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->bts_max_freq/1000);
        interf_rsp->interf_type = INTERF_BT;
        num_types_detected++;
    }

    if(bd->count_cph) {
        interf_rsp = &p->interf_rsp[INTERF_DECT];
        interf_rsp->interf_min_freq = (bd->cph_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->cph_max_freq/1000);
        interf_rsp->interf_type = INTERF_DECT;
        num_types_detected++;
    }

    if(bd->count_cwa){
        interf_rsp = &p->interf_rsp[INTERF_TONE];
        interf_rsp->interf_min_freq = (bd->cwa_min_freq/1000);
        interf_rsp->interf_max_freq = (bd->cwa_max_freq/1000);
        interf_rsp->interf_type = INTERF_TONE;
        num_types_detected++;
    }


    interf_count = bd->count_mwo + bd->count_bts + bd->count_bth + bd->count_cwa + bd->count_cph;

    if (interf_count)
        p->count = interf_count;

    return num_types_detected;

}

/*
 * Function     : add_interference_report
 * Description  : add interference related information to SAMP message
 * Input params : pointer to ath_ssd_info_t, pointer to interference response frame
 * Return       : void
 *
 */
void add_interference_report(ath_ssd_info_t *pinfo, struct interf_src_rsp *rsp)
{
    int i = 0;
    int count = 0;
    struct interf_rsp *interf_rsp = NULL;
    ath_ssd_interf_info_t *p = &pinfo->interf_info;

    interf_rsp = &rsp->interf[0];

    for (i = 0; i < MAX_INTERF_COUNT; i++) {
        if (p->interf_rsp[i].interf_type != INTERF_NONE) {
            count++;
            interf_rsp->interf_min_freq = htons(p->interf_rsp[i].interf_min_freq);
            interf_rsp->interf_max_freq = htons(p->interf_rsp[i].interf_max_freq);
            interf_rsp->interf_type     = p->interf_rsp[i].interf_type;
            interf_rsp++;
            /* debug print */
            //print_interf_details(pinfo, i);
        }
    }
    rsp->count = htons(count);
}

/*
 * Function     : start_standalone_spectral_scan
 * Description  : starts standalone spectral scan
 * Input params : pinfo, channel and band
 *
 * Start standalone Spectral scan on the specified channel and band.
 *
 * Return       : SUCCESS/FAILURE
 */
int start_standalone_spectral_scan(ath_ssd_info_t *pinfo, int channel, enum wlan_band_id band)
{
    int ret = -1;

    if (channel != 0) {
        pinfo->current_channel = channel;

        ret = athssd_set_channel(pinfo, pinfo->dev_ifname, channel, band);
        if (ret < 0) {
            fprintf(stderr, "failed to set channel = %u, band = %u for %s\n",
                    channel, band, pinfo->dev_ifname);
            return FAILURE;
        }
    }

    pinfo->dwell_interval  = CHANNEL_CLASSIFY_DWELL_INTERVAL;

    /* disable alarm */
    alarm(0);

    /* start spectral scan */
    if (issue_start_spectral_cmd() != SUCCESS) {
        return FAILURE;
    }

    /* debug print */
    printf("starting a stand alone spectral scan\n");

    return SUCCESS;

}
/*
 * Function     : get_next_word
 * Description  : Get next value from SAMP file
 *
 */
#define MAX_WORD_LEN 64


char word[MAX_WORD_LEN] = {'\0'};

char* get_next_word(FILE *file, int *is_eof)
{
    int c;
    int i = 0;

    /* Initialize the word area */
    memset(word, '\0', sizeof(word));

    /* Discard leading spaces or newlines */
    do {
        c = fgetc(file);
    } while (c == ' ' || c == '\n');

    /* Extract the word */
    while ((c != ' ') && (c != '\n') && (c != EOF)) {
        word[i++] = c;
        c = fgetc(file);
    }

    /* Mark EOF */
    if (c == EOF) {
        *is_eof = 1;
    }

    /* null terminate string */
    word[i] = '\0';
    return word;
}


/*
 * Function     : convert_addrstr_to_byte
 * Description  : Convert Address String to Macddr
 *
 */
char separator = ':';
char * convert_addrstr_to_byte(char* addr, char* dst)
{

    int i = 0;

    for (i = 0; i < 6; ++i)
    {
        unsigned int inum = 0;
        char ch;

        ch = tolower(*addr++);

        if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
            return NULL;

        inum = isdigit (ch)?(ch - '0'):(ch - 'a' + 10);
        ch = tolower(*addr);

        if ((i < 5 && ch != separator) ||
            (i == 5 && ch != '\0' && !isspace(ch)))
            {
                ++addr;
                if ((ch < '0' || ch > '9') &&
                    (ch < 'a' || ch > 'f'))
                        return NULL;

                inum <<= 4;
                inum += isdigit(ch) ? (ch - '0') : (ch - 'a' + 10);
                ch = *addr;

                if (i < 5 && ch != separator)
                    return NULL;
        }

        dst[i] = (unsigned char)inum;
        ++addr;
    }
    return dst;
}

/*
 * Function     : get_spectral_caps_from_outfile
 * Description  : get spectral capability form outfile
 * Input params : pointer to file, pointer to spectral_caps
 * Return       : SUCCESS or FAILURE
 */
static
int get_spectral_caps_from_outfile(FILE* pfile, struct spectral_caps *caps) {
    int i;
    int is_eof = FALSE;

    /* data is expected to be in the standard order */
    for (i = SPECTRAL_OUTFILE_SPECTRAL_CAPS_START_POS;
         i <= SPECTRAL_OUTFILE_SPECTRAL_CAPS_END_POS; i++) {
        int value;
        char *value_str;
        char *endptr = NULL;

        /* Ignore the key */
        get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            return FAILURE;
        }
        value_str = get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            return FAILURE;
        }

        /* To distinguish success/failure after call */
        errno = 0;
        value = strtol(value_str, &endptr, 10);
        if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                || (errno != 0 && value == 0)) {
            perror("strtol");
            return FAILURE;
        }
        if (endptr == value_str) {
            fprintf(stderr, "No digits were found\n");
            return FAILURE;
        }
        if (*endptr) {
            printf("Extra characters after number: %s\n", endptr);
            return FAILURE;
        }

        switch(i) {
        case SPECTRAL_OUTFILE_PHYDIAG_CAP_POS:
            caps->phydiag_cap = value;
            break;
        case SPECTRAL_OUTFILE_RADAR_CAP_POS:
            caps->radar_cap = value;
            break;
        case SPECTRAL_OUTFILE_SPECTRAL_CAP_POS:
            caps->spectral_cap = value;
            break;
        case SPECTRAL_OUTFILE_ADV_SPECTRAL_CAP_POS:
            caps->advncd_spectral_cap = value;
            break;
        case SPECTRAL_OUTFILE_HW_GENERATION_POS:
            caps->hw_gen = value;
            break;
        case SPECTRAL_OUTFILE_SCALING_PARAMS_VALID_POS:
            caps->is_scaling_params_populated = (bool)value;
            break;
        case SPECTRAL_OUTFILE_SCALING_FORMULA_ID_POS:
            caps->formula_id = value;
            break;
        case SPECTRAL_OUTFILE_LOW_LEVEL_OFFSET_POS:
            caps->low_level_offset = value;
            break;
        case SPECTRAL_OUTFILE_HIGH_LEVEL_OFFSET_POS:
            caps->high_level_offset = value;
            break;
        case SPECTRAL_OUTFILE_RSSI_THRSH_POS:
            caps->rssi_thr = value;
            break;
        case SPECTRAL_OUTFILE_DEFAULT_AGC_MAX_GAIN_POS:
            caps->default_agc_max_gain = value;
            break;
        case SPECTRAL_OUTFILE_AGILE_SPECTRAL_CAP_POS:
            caps->agile_spectral_cap = (bool)value;
            break;
        case SPECTRAL_OUTFILE_AGILE_SPECTRAL_CAP_160_POS:
            caps->agile_spectral_cap_160 = (bool)value;
            break;
        case SPECTRAL_OUTFILE_AGILE_SPECTRAL_CAP_80P80_POS:
            caps->agile_spectral_cap_80p80 = (bool)value;
            break;
        case SPECTRAL_OUTFILE_NUM_DETECTORS_20_MHZ_POS:
            caps->num_detectors_20mhz = value;
            break;
        case SPECTRAL_OUTFILE_NUM_DETECTORS_40_MHZ_POS:
            caps->num_detectors_40mhz = value;
            break;
        case SPECTRAL_OUTFILE_NUM_DETECTORS_80_MHZ_POS:
            caps->num_detectors_80mhz = value;
            break;
        case SPECTRAL_OUTFILE_NUM_DETECTORS_160_MHZ_POS:
            caps->num_detectors_160mhz = value;
            break;
        case SPECTRAL_OUTFILE_NUM_DETECTORS_80P80_MHZ_POS:
            caps->num_detectors_80p80mhz = value;
            break;
        default:
            fprintf(stderr, "Error in processing spectral caps\n");
            return FAILURE;
            break;
        }
    }

    return SUCCESS;
}

/*
 * get_spectral_mode_str() - Get string for Spectral mode
 * @spectral_mode: Spectral mode
 *
 * Return: String for Spectral mode on success, NULL on failure
 */
static const char* get_spectral_mode_str(enum spectral_scan_mode spectral_mode)
{
    const char *spectral_mode_str = NULL;

    switch(spectral_mode)
    {
        case SPECTRAL_SCAN_MODE_NORMAL:
            spectral_mode_str = "Normal";
            break;
        case SPECTRAL_SCAN_MODE_AGILE:
            spectral_mode_str = "Agile";
            break;
        default:
            break;
    }

    return spectral_mode_str;
}

/*
 * Function     : get_outfile_version
 * Description  : get outfile version
 * Input params : pointer to file, pointer to version
 * Return       : SUCCESS or FAILURE
 */
static
int get_outfile_version(FILE* pfile, int *version) {
    char *first_word;
    char *file_version;
    int is_eof = FALSE;
    char *endptr = NULL;

    first_word = get_next_word(pfile, &is_eof);
    if (is_eof) {
        fprintf(stderr, "Unexpected end of file\n");
        return FAILURE;
    }

    if (streq(first_word, "version:")) {
        file_version = get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            return FAILURE;
        }
    } else {
        file_version = first_word;
    }
    /* To distinguish success/failure after call */
    errno = 0;
    /* fill version */
    *version = strtol(file_version, &endptr, 10);
    if ((errno == ERANGE && (*version == LONG_MAX || *version == LONG_MIN))
            || (errno != 0 && *version == 0)) {
        perror("strtol");
        return FAILURE;
    }
    if (endptr == file_version) {
        fprintf(stderr, "No digits were found\n");
        return FAILURE;
    }
    if (*endptr) {
        printf("Extra characters after number: %s\n", endptr);
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : get_num_spectral_params
 * Description  : extract number of spectral parameters
 * Input params : pointer to file, pointer to num_spectral_params
 * Return       : SUCCESS or FAILURE
 */
static
int get_num_spectral_params(FILE* pfile, int *num_spectral_params) {
    char *num_params;
    int is_eof = FALSE;
    char *endptr = NULL;

    get_next_word(pfile, &is_eof);
    if (is_eof) {
        fprintf(stderr, "Unexpected end of file\n");
        return FAILURE;
    }

    num_params = get_next_word(pfile, &is_eof);
    if (is_eof) {
        fprintf(stderr, "Unexpected end of file\n");
        return FAILURE;
    }
    /* To distinguish success/failure after call */
    errno = 0;
    *num_spectral_params = strtol(num_params, &endptr, 10);
    if ((errno == ERANGE && (*num_spectral_params == LONG_MAX || *num_spectral_params == LONG_MIN))
            || (errno != 0 && *num_spectral_params == 0)) {
        perror("strtol");
        return FAILURE;
    }
    if (endptr == num_params) {
        fprintf(stderr, "No digits were found\n");
        return FAILURE;
    }
    if (*endptr) {
        printf("Extra characters after number: %s\n", endptr);
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Function     : get_spectral_advanced_params
 * Description  : extract advanced spectral parameters
 * Input params : pointer to file, pointer to spectral params
 * Return       : SUCCESS or FAILURE
 */
static
int get_spectral_advanced_params(FILE* pfile, struct spectral_config *params) {
    int i;
    int is_eof = FALSE;

    /* data is expected to be in the standard order */
    for (i = SPECTRAL_ADVANCED_PARAM_START;
         i < SPECTRAL_ADVANCED_PARAM_MAX; i++) {
        int value;
        char *value_str;
        char *endptr = NULL;

        /* Ignore the key */
        get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            return FAILURE;
        }

        value_str = get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            return FAILURE;
        }

        /* To distinguish success/failure after call */
        errno = 0;
        value = strtol(value_str, &endptr, 10);
        if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                || (errno != 0 && value == 0)) {
            perror("strtol");
            return FAILURE;
        }
        if (endptr == value_str) {
            fprintf(stderr, "No digits were found\n");
            return FAILURE;
        }
        if (*endptr) {
            printf("Extra characters after number: %s\n", endptr);
            return FAILURE;
        }

        switch(i) {
        case SPECTRAL_ADVANCED_PARAM_SCAN_PERIOD_POS:
            params->ss_period = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_SCAN_COUNT_POS:
            params->ss_count = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_SPECT_PRI_POS:
            params->ss_spectral_pri = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_FFT_SIZE_POS:
            params->ss_fft_size = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_GC_ENA_POS:
            params->ss_gc_ena = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_RESTART_ENA_POS:
            params->ss_restart_ena = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_NOISE_FLOOR_REF_POS:
            params->ss_noise_floor_ref = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_INIT_DELAY_POS:
            params->ss_init_delay = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_NB_TONE_THR_POS:
            params->ss_nb_tone_thr = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_STR_BIN_THR_POS:
            params->ss_str_bin_thr = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_WB_RPT_MODE_POS:
            params->ss_wb_rpt_mode = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_RSSI_RPT_MODE_POS:
            params->ss_rssi_rpt_mode = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_RSSI_THR_POS:
            params->ss_rssi_thr = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_PWR_FORMAT_POS:
            params->ss_pwr_format = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_RPT_MODE_POS:
            params->ss_rpt_mode = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_BIN_SCALE_POS:
            params->ss_bin_scale = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_DBM_ADJ_POS:
            params->ss_dbm_adj = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_CHN_MASK_POS:
            params->ss_chn_mask = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_FREQUENCY1_POS:
            params->ss_frequency.cfreq1 = value;
            break;

        case SPECTRAL_ADVANCED_PARAM_FREQUENCY2_POS:
            params->ss_frequency.cfreq2 = value;
            break;

        default:
            fprintf(stderr, "Error in processing spectral advanced paramaters\n");
            return FAILURE;
            break;
        }
    }

    return SUCCESS;
}

/*
 * Function     : get_spectral_non_advanced_params
 * Description  : extract non advanced spectral parameters
 * Input params : pointer to file, pointer to spectral params
 * Return       : SUCCESS or FAILURE
 */
static
int get_spectral_non_advanced_params(FILE* pfile, struct spectral_config *params) {
    int i;
    int is_eof = FALSE;

    /* data is expected to be in the standard order */
    for (i = SPECTRAL_NON_ADVANCED_PARAM_START;
         i < SPECTRAL_NON_ADVANCED_PARAM_MAX; i++) {
        int value;
        char *value_str;
        char *endptr = NULL;

        /* Ignore the key */
        get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            return FAILURE;
        }

        value_str = get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            return FAILURE;
        }

        /* To distinguish success/failure after call */
        errno = 0;
        value = strtol(value_str, &endptr, 10);
        if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                || (errno != 0 && value == 0)) {
            perror("strtol");
            return FAILURE;
        }
        if (endptr == value_str) {
            fprintf(stderr, "No digits were found\n");
            return FAILURE;
        }
        if (*endptr) {
            printf("Extra characters after number: %s\n", endptr);
            return FAILURE;
        }

        switch(i) {
        case SPECTRAL_NON_ADVANCED_PARAM_FFT_PERIOD_POS:
            pinfo->cur_spectral_params.ss_fft_period = value;
            break;

        case SPECTRAL_NON_ADVANCED_PARAM_SCAN_PERIOD_POS:
            pinfo->cur_spectral_params.ss_period = value;
            break;

        case SPECTRAL_NON_ADVANCED_PARAM_SCAN_COUNT_POS:
            pinfo->cur_spectral_params.ss_count = value;
            break;

        case SPECTRAL_NON_ADVANCED_PARAM_SHORT_REPORT_POS:
            pinfo->cur_spectral_params.ss_short_report = value;
            break;

        case SPECTRAL_NON_ADVANCED_PARAM_SPECT_PRI_POS:
            pinfo->cur_spectral_params.ss_spectral_pri = value;
            break;

        default:
            fprintf(stderr, "Error in processing spectral non-advanced paramaters\n");
            return FAILURE;
            break;
        }
    }

    return SUCCESS;
}

/*
 * Function     : skip_chars_till_newline
 * Description  : skip characters till new line
 * Input params : pointer to file
 * Return       : void
 */
static void skip_chars_till_newline(FILE *filep) {
    char c;

    do {
        c = fgetc(filep);
    } while (c != '\n');
}

/*
 * Function     : replay_from_file
 * Description  : Feed SAMP Messages from a file and Classifiy the signal
 * Input params : Pointer to Info and Filename
 * Return       : void
 *

 SAMP FIlE FORMAT :
 ----------------

 Version = SPECTRAL_LOG_VERSION_ID1
 ----------------------------------
 Line 1 : Version number | MAC Address | Channel Width | Operating Frequency
 Line 2 : Sample 1 related info for primary 80Mhz segment
 Line 3 : Sample 1 related info for secondary 80Mhz segment
 Line 4 : Sample 2 related info for primary 80Mhz segment
 Line 5 : Sample 2 related info for secondary 80Mhz segment
 :
 Line n : Sample n related info

 Version = SPECTRAL_LOG_VERSION_ID2
 ----------------------------------
 Line 1 : Version number | MAC Address | Channel Width | Operating Frequency
 Line 2 : Sample 1 related info for primary 80Mhz segment (AGC total gain and gain change bit at the end)
 Line 3 : Sample 1 related info for secondary 80Mhz segment (AGC total gain and gain change bit at the end)
 Line 4 : Sample 2 related info for primary 80Mhz segment  (AGC total gain and gain change bit at the end)
 Line 5 : Sample 2 related info for secondary 80Mhz segment (AGC total gain and gain change bit at the end)
 :
 Line n : Sample n related info
 */
int replay_from_file(ath_ssd_info_t *pinfo)
{
    FILE* pfile = NULL;
    int is_eof = FALSE;
    struct spectral_samp_msg msg = {0};
    struct spectral_samp_data *pdata = NULL;
    int i = 0;
    int file_version = 0;
    char macaddr[64] = {'\0'};
    size_t line_cnt = 0;
    size_t num_lines_per_sample = 1;
    bool enable_gen3_linear_scaling = false;
    bool enable_gen3_linear_scaling_outfile = false;
    int ret = FAILURE;
    char *next_word;
    const char *spectral_mode_str = NULL;
    bool operation_165mhz = false;
    enum wlan_band_id current_band;

    pfile = fopen(pinfo->filename, "rt");

    if (!pfile) {
        fprintf(stderr, "Unable to open %s\n", pinfo->filename);
        return FAILURE;
    }

    /* skip the first line describing the file banner */
    skip_chars_till_newline(pfile);
    if (get_outfile_version(pfile, &file_version) != SUCCESS) {
        fprintf(stderr, "Failed to get outfile version\n");
        goto error;
    }

    if ((file_version != SPECTRAL_LOG_VERSION_ID1) &&
                    (file_version != SPECTRAL_LOG_VERSION_ID2) &&
                    (file_version != SPECTRAL_LOG_VERSION_ID3) &&
                    (file_version != SPECTRAL_LOG_VERSION_ID4)) {
        fprintf(stderr, "SAMP File version (%d) not supported\n", file_version);
        goto error;
    }

    /* Get the Mac address from file */
    memset(macaddr, 0, sizeof(macaddr));
    /* Add Signature */
    msg.signature = SPECTRAL_SIGNATURE;
    pdata = &msg.samp_data;

    if (file_version == SPECTRAL_LOG_VERSION_ID3 || file_version == SPECTRAL_LOG_VERSION_ID4) {
        int num_params;

        /* data is expected to be in the standard order */
        /* extract info from header */
        for (i = SPECTRAL_OUTFILE_HEADER_START_POS + 1;
             i <= SPECTRAL_OUTFILE_HEADER_END_POS;i++) {
            int value;
            char *value_str;
            char *endptr = NULL;

            /* Ignore the key */
            get_next_word(pfile, &is_eof);
            if (is_eof) {
                fprintf(stderr, "Unexpected end of file\n");
                goto error;
            }

            switch (i) {
            case SPECTRAL_OUTFILE_MAC_ADDRESS_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                memcpy(macaddr, value_str, sizeof(macaddr));
                break;
            case SPECTRAL_OUTFILE_CHANNEL_WIDTH_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                msg.samp_data.ch_width = value;
                break;
            case SPECTRAL_OUTFILE_AGILE_CHANNEL_WIDTH_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                msg.samp_data.agile_ch_width = value;
                break;
            case SPECTRAL_OUTFILE_MODE_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }

                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if (((errno == ERANGE) &&
                            (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }

                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }

                if (*endptr) {
                    printf("Extra characters after number\n");
                    return FAILURE;
                }

                msg.samp_data.spectral_mode = value;
                break;
            case SPECTRAL_OUTFILE_PRIMARY_FREQUENCY_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                msg.freq = (u_int16_t)value;
                break;
            case SPECTRAL_OUTFILE_CFREQ1_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                msg.vhtop_ch_freq_seg1 = value;
                break;
            case SPECTRAL_OUTFILE_CFREQ2_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                msg.vhtop_ch_freq_seg2 = value;
                break;
            case SPECTRAL_OUTFILE_AGILE_FREQUENCY1_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }

                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);

                if ((errno == ERANGE &&
                            (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }

                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }

                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }

                msg.agile_freq1 = (u_int16_t)value;
                break;
            case SPECTRAL_OUTFILE_AGILE_FREQUENCY2_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }

                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);

                if ((errno == ERANGE &&
                            (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }

                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }

                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }

                msg.agile_freq2 = (u_int16_t)value;
                break;
            case SPECTRAL_OUTFILE_GEN3_LINEAR_SCALING_EN_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                enable_gen3_linear_scaling_outfile = (bool)value;
                break;
                case SPECTRAL_OUTFILE_165MHZ_OPERATION_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                operation_165mhz = (bool)value;
                break;
            case SPECTRAL_OUTFILE_LB_EXTRA_EDGEBINS_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                msg.samp_data.lb_edge_extrabins = value;
                break;
            case SPECTRAL_OUTFILE_RB_EXTRA_EDGEBINS_POS:
                value_str = get_next_word(pfile, &is_eof);
                if (is_eof) {
                    fprintf(stderr, "Unexpected end of file\n");
                    goto error;
                }
                /* To distinguish success/failure after call */
                errno = 0;
                value = strtol(value_str, &endptr, 10);
                if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                        || (errno != 0 && value == 0)) {
                    perror("strtol");
                    return FAILURE;
                }
                if (endptr == value_str) {
                    fprintf(stderr, "No digits were found\n");
                    return FAILURE;
                }
                if (*endptr) {
                    printf("Extra characters after number: %s\n", endptr);
                    return FAILURE;
                }
                msg.samp_data.rb_edge_extrabins = value;
                break;
            }
        }

        /* -------------------------------------------
         * | command line | outfile | combined result|
         * -------------------------------------------
         * |      0       |   0     |       0        |
         * |      0       |   1     |    invalid     |
         * |      1       |   0     |       1        |
         * |      1       |   1     |       0        |
         * ------------------------------------------- */
        if (pinfo->enable_gen3_linear_scaling) {
            enable_gen3_linear_scaling = !enable_gen3_linear_scaling_outfile;
        } else if (!enable_gen3_linear_scaling_outfile) {
            enable_gen3_linear_scaling = false;
        } else {
            fprintf(stderr, "Outfile is already scaled, use an unscaled outfile\n");
            goto error;
        }

        next_word = get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            goto error;
        }
        if (!streq(next_word, "spectral_caps")) {
            fprintf(stderr, "Error in outfile format, spectral_caps not found\n");
            goto error;
        }

        if (get_spectral_caps_from_outfile(pfile, &pinfo->caps) != SUCCESS) {
            fprintf(stderr, "Failed to get spectral caps\n");
            goto error;
        }

        next_word = get_next_word(pfile, &is_eof);
        if (is_eof) {
            fprintf(stderr, "Unexpected end of file\n");
            goto error;
        }
        if (!streq(next_word, "spectral_params")) {
            fprintf(stderr, "Error in outfile format, spectral_params not found\n");
            goto error;
        }

        if (get_num_spectral_params(pfile, &num_params) != SUCCESS) {
            fprintf(stderr, "Failed to get number of spectral params\n");
            goto error;
        }
        /* Extract spectral parameters */
        if (pinfo->caps.advncd_spectral_cap) {
            if (num_params != SPECTRAL_ADVANCED_PARAM_MAX) {
                fprintf(stderr, "Mismatch in number of spectral params\n");
                goto error;
            }
            if (get_spectral_advanced_params(pfile, &pinfo->cur_spectral_params) != SUCCESS) {
                fprintf(stderr, "Failed to get advanced spectral params\n");
                goto error;
            }
        } else {
            if (num_params != SPECTRAL_NON_ADVANCED_PARAM_MAX) {
                fprintf(stderr, "Mismatch in number of spectral params\n");
                goto error;
            }
            if (get_spectral_non_advanced_params(pfile, &pinfo->cur_spectral_params) != SUCCESS) {
                fprintf(stderr, "Failed to get advanced spectral params\n");
                goto error;
            }
        }

        /* skip a new line char */
        skip_chars_till_newline(pfile);
        /* skip a line containing legends */
        skip_chars_till_newline(pfile);
        /* Copy the Macaddress */
        convert_addrstr_to_byte((char*)macaddr, (char*)&msg.macaddr);

        memcpy(pinfo->radio_macaddr, &msg.macaddr,
                MIN(sizeof(pinfo->radio_macaddr), sizeof(msg.macaddr)));

        pinfo->spectral_mode = msg.samp_data.spectral_mode;

        if (pinfo->caps.advncd_spectral_cap) {
            pinfo->spectral_frequency = pinfo->cur_spectral_params.ss_frequency;

            if ((pinfo->spectral_mode == SPECTRAL_SCAN_MODE_AGILE) &&
                    (pinfo->spectral_frequency.cfreq1 == 0)) {
                fprintf(stderr, "Spectral mode is Agile but no Agile "
                                "frequency configured\n");
                goto error;
            }
            if (pinfo->spectral_mode == SPECTRAL_SCAN_MODE_AGILE &&
                msg.samp_data.agile_ch_width == IEEE80211_CWM_WIDTH80_80 &&
                pinfo->spectral_frequency.cfreq2 == 0) {
                fprintf(stderr, "Spectral mode is Agile 80+80 but no Agile "
                                 "center frequency 2 configured\n");
                goto error;
            }
        }

        /* Do classifier data init once caps and mac address is available */
        init_classifier_data(msg.macaddr, &pinfo->caps, sizeof(pinfo->caps));
    } else {
        memcpy(macaddr, get_next_word(pfile, &is_eof), sizeof(macaddr));
        /* Get the channel width */
        msg.samp_data.ch_width = atoi(get_next_word(pfile, &is_eof));
        /* Get the operating frequency */
        msg.freq = (u_int16_t)atoi(get_next_word(pfile, &is_eof));
        /* Copy the Macaddress */
        convert_addrstr_to_byte((char*)macaddr, (char*)&msg.macaddr);
        enable_gen3_linear_scaling = pinfo->enable_gen3_linear_scaling;
    }

    current_band = ath_ssd_get_band_from_freq(msg.freq);
    if (current_band == WLAN_BAND_UNSPECIFIED) {
        fprintf(stderr, "Invalid band corresponding to freq %u MHz\n", msg.freq);
        goto error;
    }

    info("server (built at %s %s )", __DATE__, __TIME__);
    info("current band       : %s", band2string[current_band]);
    info("logging            : %s (%d)", (pinfo->log_mode)?"Enabled":"Disabled", pinfo->log_mode);
    if (pinfo->caps.hw_gen == SPECTRAL_CAP_HW_GEN_3) {
        info("gen3 linear scaling: %s (%d)",
                (enable_gen3_linear_scaling) ? "Enabled" : "Disabled",
                 enable_gen3_linear_scaling);
    }

    if ((spectral_mode_str = get_spectral_mode_str(pinfo->spectral_mode))
            == NULL) {
        fprintf(stderr,
                "Failed to get Spectral mode string for mode value %d\n",
                pinfo->spectral_mode);
        goto error;
    }
    info("Mode               : %s", spectral_mode_str);

    if (pinfo->spectral_mode == SPECTRAL_SCAN_MODE_AGILE) {
        if (pinfo->spectral_frequency.cfreq2) {
            info("Center frequency 1 (for Agile)   : %u MHz", pinfo->spectral_frequency.cfreq1);
            info("Center frequency 2 (for Agile)   : %u MHz", pinfo->spectral_frequency.cfreq2);
        } else {
            info("Center frequency (for Agile)   : %u MHz", pinfo->spectral_frequency.cfreq1);
        }
    }

    if (IS_CHAN_WIDTH_160_OR_80P80(msg.samp_data.ch_width))
         if(operation_165mhz)
            num_lines_per_sample = SPECTRAL_SAMPLE_5MHZ_OFFSET + 1;
         else
            num_lines_per_sample = SPECTRAL_SAMPLE_SEC80_OFFSET + 1;
    else
        num_lines_per_sample = SPECTRAL_SAMPLE_PRI80_OFFSET + 1;

    while(TRUE) {
        /* ignore the line number */
        (void)atoi(get_next_word(pfile, &is_eof));
        if (!is_eof) {

            switch(line_cnt % num_lines_per_sample) {
            case SPECTRAL_SAMPLE_PRI80_OFFSET:
                /* Populating primary 80MHz segment related info */
                pdata->bin_pwr_count = (u_int16_t)atoi(get_next_word(pfile, &is_eof));

                for (i = 0; i < pdata->bin_pwr_count; i++) {
                    pdata->bin_pwr[i] = (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                }

                /* populate TS,RSSI and NF */
                pdata->spectral_tstamp = (int)atoi(get_next_word(pfile, &is_eof));
                pdata->spectral_rssi = abs((int16_t)atoi(get_next_word(pfile, &is_eof)));
                pdata->noise_floor = (int16_t)atoi(get_next_word(pfile, &is_eof));
                if (file_version == SPECTRAL_LOG_VERSION_ID2 ||
                                file_version == SPECTRAL_LOG_VERSION_ID3 ||
                                file_version == SPECTRAL_LOG_VERSION_ID4) {
                        pdata->spectral_agc_total_gain =
                                (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                        pdata->spectral_gainchange =
                                (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                        pdata->spectral_pri80ind =
                                (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                        pdata->raw_timestamp = (int)atoi(get_next_word(pfile, &is_eof));
                        pdata->timestamp_war_offset =
                                (int)atoi(get_next_word(pfile, &is_eof));
                        pdata->last_raw_timestamp = (int)atoi(get_next_word(pfile, &is_eof));
                        pdata->reset_delay = (int)atoi(get_next_word(pfile, &is_eof));
                        pdata->target_reset_count = (int)atoi(get_next_word(pfile, &is_eof));
                        if (file_version == SPECTRAL_LOG_VERSION_ID4) {
                            /* Ignore, this is detection state of the sample */
                            get_next_word(pfile, &is_eof);
                        }
                }
                break;

            case SPECTRAL_SAMPLE_SEC80_OFFSET:
                /* Populating secondary 80MHz segment related info */
                pdata->bin_pwr_count_sec80 = (u_int16_t)atoi(get_next_word(pfile, &is_eof));

                for (i = 0; i < pdata->bin_pwr_count_sec80; i++) {
                    pdata->bin_pwr_sec80[i] = (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                }

                /* populate TS,RSSI and NF */
                pdata->spectral_tstamp = (int)atoi(get_next_word(pfile, &is_eof));
                pdata->spectral_rssi_sec80 = abs((int16_t)atoi(get_next_word(pfile, &is_eof)));
                pdata->noise_floor_sec80 = (int16_t)atoi(get_next_word(pfile, &is_eof));
                if (file_version == SPECTRAL_LOG_VERSION_ID2 ||
                                file_version == SPECTRAL_LOG_VERSION_ID3 ||
                                file_version == SPECTRAL_LOG_VERSION_ID4) {
                    pdata->spectral_agc_total_gain_sec80 =
                        (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                    pdata->spectral_gainchange_sec80 =
                        (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                    pdata->spectral_pri80ind_sec80 =
                        (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                    pdata->raw_timestamp_sec80 = (int)atoi(get_next_word(pfile, &is_eof));
                    pdata->timestamp_war_offset =
                            (int)atoi(get_next_word(pfile, &is_eof));
                    pdata->last_raw_timestamp = (int)atoi(get_next_word(pfile, &is_eof));
                    pdata->reset_delay = (int)atoi(get_next_word(pfile, &is_eof));
                    pdata->target_reset_count = (int)atoi(get_next_word(pfile, &is_eof));
                    if (file_version == SPECTRAL_LOG_VERSION_ID4) {
                        /* Ignore, this is detection state of the sample */
                        get_next_word(pfile, &is_eof);
                    }

                }
                break;

            case SPECTRAL_SAMPLE_5MHZ_OFFSET:
                pdata->bin_pwr_count_5mhz = (u_int16_t)atoi(get_next_word(pfile, &is_eof));

                if (pdata->bin_pwr_count_5mhz > ARRAY_LEN(pdata->bin_pwr_5mhz)) {
                    fprintf(stderr, "Number of bins in 5 MHz %u greater than max\n",
                            pdata->bin_pwr_count_5mhz);
                    goto error;
                }
                for (i = 0; i < pdata->bin_pwr_count_5mhz; i++) {
                    pdata->bin_pwr_5mhz[i] = (u_int8_t)atoi(get_next_word(pfile, &is_eof));
                }
                break;

            default:
                SPECTRAL_CLASSIFIER_ASSERT(0);
            }

            line_cnt++;
	    if (line_cnt % num_lines_per_sample == 0)
                /* Process incoming SAMP Message */
                new_process_spectral_msg(pinfo, &msg, enable_gen3_linear_scaling);
        } else {
            break;
        }
    }

    ret = SUCCESS;

error:
    fclose(pfile);
    cleanup(pinfo);
    return ret;
}

#define FILE_NAME_LENGTH 64
#define MAX_WIPHY 3

#ifdef SPECTRAL_SUPPORT_CFG80211
/*
* get_config_mode_type: Function that detects current config type
* and returns corresponding enum value.
*/
static config_mode_type get_config_mode_type()
{
    FILE *fp;
    char filename[FILE_NAME_LENGTH];
    int radio;
    config_mode_type ret = CONFIG_IOCTL;

    for (radio = 0; radio < MAX_WIPHY; radio++) {
        snprintf(filename, sizeof(filename),"/sys/class/net/wifi%d/phy80211/",radio);
        fp = fopen(filename, "r");
        if (fp != NULL){
            fclose(fp);
            ret = CONFIG_CFG80211;
            break;
        }
    }

    return ret;
}
#endif /* SPECTRAL_SUPPORT_CFG80211 */

/*
 * Function     : is_radio_ifname_valid
 * Description  : Checks whether the Radio ifname given by user is valid
 * Input params : String containing Radio name
 * Return       : 0 for invalid or 1 for valid
 *
 */

int is_radio_ifname_valid(char *radioname)
{
   DIR *dir = NULL;
   int i;
   int wifistr_len = strlen(WIFI_STR);

   if (radioname == NULL)
       return 0;

   /* To validate Radio name, check if it starts with "wifi" and
    * fifth character exists and is a digit.
    */
   if (strncmp(radioname, WIFI_STR, wifistr_len) != 0)
       return 0;

   if (!radioname[wifistr_len] || !isdigit(radioname[wifistr_len]))
       return 0;

   /* No assumptions are made on max no. of radio interfaces,
    * so checking radioname string till IFNAMSIZ
    */
   for (i = wifistr_len + 1; i < IFNAMSIZ; i++)
   {
       if (!radioname[i])
            break;

       if (!isdigit(radioname[i]))
            return 0;
   }

   /* We check whether a directory for given radioname exists
    * in /sys/class/net/. This will help to detect wrong input
    * name of radio interfaces that do not exist.
    */
   dir = opendir(PATH_SYSNET_DEV);
   if (!dir) {
       perror(PATH_SYSNET_DEV);
       return 0;
   }

   while (1)
   {
       struct dirent *dir_entry;
       const char *dir_name;

       dir_entry = readdir(dir);
       if (!dir_entry) {
            /* There are no more entries in this directory, so break
             * out of the while loop.
             */
            break;
       }
       dir_name = dir_entry->d_name;

       if ((dir_entry->d_type & DT_DIR) || (dir_entry->d_type & DT_LNK)) {
            if (strncmp(radioname, dir_name, IFNAMSIZ) == 0) {
                /* Directory for radioname found */
                closedir(dir);
                return 1;
            }
       }
   }

   closedir(dir);
   return 0;
}

/*
 * Function     : is_vap_ifname_valid
 * Description  : Checks whether the VAP ifname given by user is valid
 * Input params : Strings containing radio name and VAP name
 * Return       : 0 for invalid or 1 for valid
 *
 */
int is_vap_ifname_valid(char *radioname, char *devname)
{
   char path[MAX_PATH_LEN];
   FILE *fp;
   char parent_radio[IFNAMSIZ];

   if (radioname == NULL || devname == NULL)
       return 0;

   /* To validate VAP name, check if VAP with given dev ifname
    * is the child of Radio with radio ifname. This is checked
    * by comparing radio ifname entry with parent entry for
    * dev ifname in /sys/class/net/<dev_ifname> path.
    */
   if ((strlcpy(path, PATH_SYSNET_DEV, MAX_PATH_LEN) >= MAX_PATH_LEN)
       || (strlcat(path, devname, MAX_PATH_LEN) >= MAX_PATH_LEN)
       || (strlcat(path, "/parent", MAX_PATH_LEN) >= MAX_PATH_LEN)) {
       fprintf(stderr, "%s(): %d Error creating pathname \n",
               __func__, __LINE__);
       return 0;
   }

   fp = fopen(path, "r");

   /* If entry doesn't exist, it means VAP name is incorrect */
   if (fp == NULL)
       return 0;

   fgets(parent_radio, IFNAMSIZ, fp);
   fclose(fp);
   /* The fgets() issue is it retains a newline character at the end of input
    * which is not required here. So, strcspn() is used to find posiion of
    * newline character and replace by NULL character.
    */
   parent_radio[strcspn(parent_radio,"\n")] = '\0';

   if (strncmp(parent_radio, radioname, IFNAMSIZ) == 0)
       return 1;

   return 0;
}

/*
 * Function     : main
 * Description  : entry point
 * Input params : argc, argv
 * Return       : void
 *
 */

int main(int argc, char* argv[])
{
    int fdmax;
    int fd = 0;
    int ret = 0;
    int channel = INVALID_CHANNEL;
    enum wlan_band_id band = WLAN_BAND_UNSPECIFIED;
    enum ieee80211_cwm_width rchwidth = IEEE80211_CWM_WIDTHINVALID;

    pinfo->replay = FALSE;
    pinfo->enable_gen3_linear_scaling =
        ATH_SSD_ENAB_GEN3_LINEAR_SCALING_DEFAULT;
    /*  Normal Spectral scan is the default mode */
    pinfo->spectral_mode = SPECTRAL_SCAN_MODE_NORMAL;
    memset(&pinfo->spectral_frequency, 0, sizeof(pinfo->spectral_frequency));
    pinfo->do_standalone_scan = FALSE;
    pinfo->spectral_scan_priority = SPECTRAL_SCAN_PRIORITY_HIGH;

    int optc;
    char *radio_ifname  = NULL;
    char *dev_ifname    = NULL;
    char *filename      = NULL;
    struct timeval tv_timeout;
    u_int8_t radio_mac_addr[6];
    const char *spectral_mode_str = NULL;

    fd_set  master;
    fd_set  read_fds;

    ath_ssd_inet_t *pinet = GET_ADDR_OF_INETINFO(pinfo);
    ath_ssd_nlsock_t *pnl = GET_ADDR_OF_NLSOCKINFO(pinfo);

    /* use TCP by default */
    sock_type_t sock_type = SOCK_TYPE_UDP;

#ifdef SPECTRAL_SUPPORT_CFG80211
    /*
     * Based on the driver config mode (cfg80211/wext), application also runs
     * in same mode (wext/cfg80211)
     */
    pinfo->cfg_flag = get_config_mode_type();
#endif /* SPECTRAL_SUPPORT_CFG80211 */

    while ((optc = getopt(argc, argv, "ab:dc:f:g:Hhi:j:p:Tts:nx:z:")) != -1) {
        /* getopt() detects a missing argument only for the last option on
         * the command line. To detect a missing argument for an option in
         * between, the following if condition needs to be included,
         * otherwise it takes the next option as an argument for itself.
         */
        if ((optc == 'b') || (optc == 'c') || (optc == 'f') || (optc == 'g') ||
            (optc == 'i') || (optc == 'j') || (optc == 'p') || (optc == 's') ||
            (optc == 'x') || (optc == 'z')) {
            if (*optarg == '-') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optc);
                    exit(EXIT_FAILURE);
            }
        }
        switch (optc) {
            case 'a':
#ifdef SPECTRAL_SUPPORT_CFG80211
                if (IS_CFG80211_ENABLED(pinfo)) {
                    pinfo->spectral_mode = SPECTRAL_SCAN_MODE_AGILE;
                } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
                {
                    info("Option -%c is available only in cfg80211 mode", optc);
                }
                break;
            case 'c':
                pinfo->log_mode = atoi(optarg);
                break;
            case 'd':
                debug = TRUE;
                break;
            case 'f':
#ifdef SPECTRAL_SUPPORT_CFG80211
                if (IS_CFG80211_ENABLED(pinfo)) {
                    pinfo->spectral_frequency.cfreq1 = atoi(optarg);
                } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
                {
                    info("Option -%c is available only in cfg80211 mode", optc);
                }
                break;
            case 'g':
#ifdef SPECTRAL_SUPPORT_CFG80211
                if (IS_CFG80211_ENABLED(pinfo)) {
                    pinfo->spectral_frequency.cfreq2 = atoi(optarg);
                } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
                {
                    info("Option -%c is available only in cfg80211 mode", optc);
                }
                break;
            case 'T':
            case 't':
                sock_type = SOCK_TYPE_TCP;
                break;
            case 'h':
            case 'H':
                print_usage();
                break;
            case 's':
                channel = atoi(optarg);
                pinfo->do_standalone_scan = TRUE;
                break;
            case 'b':
                band = atoi(optarg);
                break;
            case 'i':
                radio_ifname = optarg;
                break;
            case 'j':
                dev_ifname = optarg;
                break;
            case 'p':
                filename = optarg;
                pinfo->replay = TRUE;
                break;
#ifdef SPECTRAL_SUPPORT_CFG80211
            case 'n':
                if (!pinfo->cfg_flag)
                {
                    fprintf(stderr, "Invalid tag '-n' for wext mode.\n");
                    exit(EXIT_FAILURE);
                }
                break;
#endif /* SPECTRAL_SUPPORT_CFG80211 */
            case 'x':
                pinfo->enable_gen3_linear_scaling = !!atoi(optarg);
                break;
            case 'z':
                pinfo->spectral_scan_priority = atoi(optarg);
                if (pinfo->spectral_scan_priority != SPECTRAL_SCAN_PRIORITY_LOW &&
                    pinfo->spectral_scan_priority != SPECTRAL_SCAN_PRIORITY_HIGH) {
                    fprintf(stderr, "Invalid Spectral scan priority %d\n",
                            pinfo->spectral_scan_priority);
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
                if ((optopt == 's') || (optopt == 'i') || (optopt == 'j') ||
                        (optopt == 'c') || (optopt == 'p') || (optopt == 'x') ||
                        (optopt == 'f') || (optopt == 'z')) {
                    fprintf(stderr, "Option -%c requries an argument.\n",
                                optopt);
                } else {
                    fprintf(stderr, "Unknown option '-%c'.\n", optopt);
                }
                exit(EXIT_FAILURE);
            default:
                break;
        }
    }

    /* init the socket type */
    pinfo->sock_type = sock_type;

    /* init the dwell interval */
    pinfo->dwell_interval = CHANNEL_NORMAL_DWELL_INTERVAL;

    /* init the current channel list */
    if (IS_BAND_5GHZ(pinfo)) {
        pinfo->channel_list = dot11a_channels;
        pinfo->max_channels = ARRAY_LEN(dot11a_channels);
    } else {
        pinfo->channel_list = dot11g_channels;
        pinfo->max_channels = ARRAY_LEN(dot11g_channels);
    }

    /* save the interface name */
    if (radio_ifname) {
        if (strlcpy(pinfo->radio_ifname, radio_ifname, IFNAMSIZ) >= IFNAMSIZ) {
            fprintf(stderr, "Error : Radio ifname more than IFNAMSIZ.\n");
            exit(EXIT_FAILURE);
        }
        if (!is_radio_ifname_valid(pinfo->radio_ifname)) {
            fprintf(stderr, "Radio interface name is incorrect. \n");
            exit(EXIT_FAILURE);
        }
    } else if (!pinfo->replay) {
        fprintf(stderr, "Radio Interface name required. \n");
        exit(EXIT_FAILURE);
    }

    if (dev_ifname) {
        if (strlcpy(pinfo->dev_ifname, dev_ifname, IFNAMSIZ) >= IFNAMSIZ) {
            fprintf(stderr, "Error : VAP ifname more than IFNAMSIZ.\n");
            exit(EXIT_FAILURE);
        }
        if (!is_vap_ifname_valid(pinfo->radio_ifname, pinfo->dev_ifname)) {
            fprintf(stderr, "VAP interface name is incorrect. \n");
            exit(EXIT_FAILURE);
        }
    } else if (!pinfo->replay) {
        fprintf(stderr, "VAP Interface name required. \n");
        exit(EXIT_FAILURE);
    }

    if (ath_ssd_init_spectral(pinfo) != SUCCESS) {
        exit(EXIT_FAILURE);
    }

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        /* init cfg80211 socket */
        if (init_cfg80211_socket(pinfo) == FAILURE) {
            info("unable to create cfg80211 socket");
            exit(EXIT_FAILURE);
        }

         /*
          * Initialize mapping of Spectral internal parameters to cfg80211
          * attributes.
          */
        if (init_sparams_to_cfg80211_attrs_mapping(pinfo) == FAILURE) {
            info("Unable to initialize mapping of Spectral internal parameters "
                 "to cfg80211 attributes");
            exit(EXIT_FAILURE);
        }
    }

#endif /* SPECTRAL_SUPPORT_CFG80211 */

    memset(radio_mac_addr, 0, sizeof(radio_mac_addr));

    memset(&pinfo->caps, 0, sizeof(pinfo->caps));

    /* No need of netlink socket initialization in replay mode */
    if (!pinfo->replay) {
        if (ath_ssd_get_spectral_capabilities(pinfo, &pinfo->caps) != SUCCESS) {
            exit(EXIT_FAILURE);
        }

        if (init_nl_sockinfo(pinfo) == FAILURE) {
            exit(EXIT_FAILURE);
        }

        if (get_iface_macaddr(pinfo->radio_ifname, radio_mac_addr)
                != SUCCESS) {
            exit(EXIT_FAILURE);
        }

        memcpy(pinfo->radio_macaddr, radio_mac_addr,
                MIN(sizeof(pinfo->radio_macaddr), sizeof(radio_mac_addr)));

        if (pinfo->spectral_mode != SPECTRAL_SCAN_MODE_AGILE) {
            if (pinfo->spectral_frequency.cfreq1 != 0 || pinfo->spectral_frequency.cfreq2 != 0) {
                info("Spectral frequency is provided but is currently applicable only for Agile mode");
                exit(EXIT_FAILURE);
            }
        } else {
            if (!pinfo->caps.agile_spectral_cap && !pinfo->caps.agile_spectral_cap_160) {
                info("Agile mode requested but radio interface is not capable of Agile Spectral for any width");
                exit(EXIT_FAILURE);
            }

            if ((rchwidth = get_channel_width(pinfo))
                    == IEEE80211_CWM_WIDTHINVALID) {
                exit(EXIT_FAILURE);
            }

           /* Currently, IEEE80211_CWM_WIDTH160 is applicable for both 160 and
            * 80+80 MHz. Similarly, agile_spectral_cap_160 is applicable for
            * both 160 and 80+80 MHz. Future changes in this respect if any to
            * be reflected here. We assert in case of a width value greater than
            * IEEE80211_CWM_WIDTH160.
            */
            ATHSSD_ASSERT(rchwidth <= IEEE80211_CWM_WIDTH160);

            if (IEEE80211_CWM_WIDTH160 == rchwidth) {
                if (!pinfo->caps.agile_spectral_cap_160) {
                    info("Agile mode requested but radio interface is not capable of Agile Spectral for 160/80+80 MHz");
                    exit(EXIT_FAILURE);
                }
            } else {
                if (!pinfo->caps.agile_spectral_cap) {
                    info("Agile mode requested but radio interface is not capable of Agile Spectral for <=80 MHz");
                    exit(EXIT_FAILURE);
                }
            }

            if (!pinfo->spectral_frequency.cfreq1) {
                info("Agile mode requested but frequency for Agile is not provided.");
                exit(EXIT_FAILURE);
            }

            if (pinfo->do_standalone_scan == TRUE) {
                if (channel != 0) {
                    info("Agile mode requested but non-zero operational channel for stand alone scan provided.");
                    exit(EXIT_FAILURE);
                }
            } else {
                pinfo->do_standalone_scan = TRUE;
                /* Set operational channel to 0 to mark it as inapplicable. */
                channel = 0;
            }
            info("Agile mode: Stand alone scan configured");
        }
    }

    if (pinfo->do_standalone_scan == FALSE) {
        if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_TCP) {
            /* Init TCP socket interface */
            if (init_inet_sockinfo(pinfo) == FAILURE) {
                exit(EXIT_FAILURE);
            }
        }
        else if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_UDP) {
            /* Init UDP socket interface */
            if (init_inet_dgram_sockinfo(pinfo) == FAILURE) {
                exit(EXIT_FAILURE);
            }
        } else {
            info("invalid socket type");
            exit(EXIT_FAILURE);
        }
    }

    init_classifier_lookup_tables();
    init_classifier_data(radio_mac_addr, &pinfo->caps, sizeof(pinfo->caps));

    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(pnl->spectral_fd, &master);

    if (pinfo->do_standalone_scan == FALSE) {
        FD_SET(pinet->listener, &master);

        fdmax = (pinet->listener > pnl->spectral_fd) ?
            pinet->listener : pnl->spectral_fd;
    } else {
        fdmax = pnl->spectral_fd;
    }

    signal(SIGINT, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGCHLD, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    /* Replay SAMP messages from a File */
    if (pinfo->replay) {
        info("Replay Mode   : %s", (pinfo->replay == TRUE)?"YES":"NO");
        pinfo->filename = filename;
        if (replay_from_file(pinfo) != SUCCESS) {
            fprintf(stderr, "Failed to replay from file\n");
            exit(EXIT_FAILURE);
        }
        return 0;
    }

    if ((spectral_mode_str = get_spectral_mode_str(pinfo->spectral_mode))
            == NULL) {
        fprintf(stderr,
                "Failed to get Spectral mode string for mode value %d\n",
                pinfo->spectral_mode);
        exit(EXIT_FAILURE);
    }

    if (pinfo->spectral_mode == SPECTRAL_SCAN_MODE_AGILE) {
        if (pinfo->spectral_frequency.cfreq2) {
            info("Center frequency 1 (for Agile)   : %u MHz", pinfo->spectral_frequency.cfreq1);
            info("Center frequency 2 (for Agile)   : %u MHz", pinfo->spectral_frequency.cfreq2);
        } else {
            info("Center frequency (for Agile)   : %u MHz", pinfo->spectral_frequency.cfreq1);
        }
    }

    if (pinfo->do_standalone_scan == TRUE) {
        if (start_standalone_spectral_scan(pinfo, channel, band) != SUCCESS) {
            fprintf(stderr, "Failed to start standalone Spectral scan\n");
            exit(EXIT_FAILURE);
        }
    }

    ret = ath_sssd_get_current_band(pinfo, pinfo->dev_ifname, &(pinfo->current_band));
    if (ret != SUCCESS) {
        info("Unable to get current band");
        exit(EXIT_FAILURE);
    }

    info("server (built at %s %s )", __DATE__, __TIME__);
    info("Mode               : %s", spectral_mode_str);
    info("interface          : %s", pinfo->radio_ifname);
    info("current band       : %s", band2string[pinfo->current_band]);
    info("logging            : %s (%d)", (pinfo->log_mode)?"Enabled":"Disabled", pinfo->log_mode);
    if (pinfo->caps.hw_gen == SPECTRAL_CAP_HW_GEN_3) {
        info("gen3 linear scaling: %s (%d)",
                (pinfo->enable_gen3_linear_scaling) ? "Enabled" : "Disabled",
                pinfo->enable_gen3_linear_scaling);
    }

    for (;;) {

        read_fds = master;
        tv_timeout.tv_sec = QCA_ATHSSDTOOL_NL_TIMEOUT_SEC;
        tv_timeout.tv_usec = QCA_ATHSSDTOOL_NL_TIMEOUT_USEC;

        ret = select(fdmax + 1, &read_fds, NULL, NULL, &tv_timeout);

        if (ret == -1) {
            continue;
        }
        else if(ret == 0){
            printf("Timed out waiting for spectral message.\n");
            cleanup(pinfo);
            break;
        }

        for (fd = 0; fd <= fdmax; fd++) {
            if (FD_ISSET(fd, &read_fds)) {
                if ((pinfo->do_standalone_scan == FALSE) &&
                    (fd == pinet->listener)) {
                    if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_UDP) {
                        if (handle_client_data(pinfo, fd) == -1) {
                            cleanup(pinfo);
                            exit(EXIT_FAILURE);
                        }
                    } else if (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_TCP) {
                        if (accept_new_connection(pinfo)) {
                            FD_SET(pinet->client_fd, &master);
                            fdmax = (pinet->client_fd > fdmax)?pinet->client_fd:fdmax;
                        }
                    }
                }
                else if (fd ==  pnl->spectral_fd) {
                        if (handle_spectral_data(pinfo) == FAILURE) {
                            cleanup(pinfo);
                            exit(EXIT_FAILURE);
                        }
                }
                else if ((pinfo->do_standalone_scan == FALSE) &&
                         (fd == pinet->client_fd) &&
                         (CONFIGURED_SOCK_TYPE(pinfo) == SOCK_TYPE_TCP)) {
                        if (handle_client_data(pinfo, fd ) == -1) {
                            cleanup(pinfo);
                            exit(EXIT_FAILURE);
                        }
                }
            }
        }
    }
    return 0;
}

