/*
 * Copyright (c) 2014, 2017-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2014 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 *
 *       Filename:  ath_ssd_cmds.c
 *
 *    Description:  Spectral Scan commands (IOCTLs)
 *
 *        Version:  1.0
 *       Revision:  none
 *       Compiler:  gcc
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <net/if.h>

#include "if_athioctl.h"
#define  _LINUX_TYPES_H
#define __bool_already_defined__
#include "ath_classifier.h"
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#include "spectral_ioctl.h"
#include "ath_ssd_defs.h"
#include "spectral_data.h"
#include "spec_msg_proto.h"
#include "spectral.h"
#include "nl80211_copy.h"
#include "cfg80211_nlwrapper_api.h"
#include "wireless_copy.h"
#include <ieee80211_external.h>
#include <cdp_txrx_stats_struct.h>
#include <ol_ath_ucfg.h>

#ifndef ATH_DEFAULT
#define ATH_DEFAULT "wifi0"
#endif

static int send_ioctl_command (const char *ifname, void *buf, int sock_fd);
#ifdef SPECTRAL_SUPPORT_CFG80211
static int convert_to_cfg80211_spectral_mode(enum spectral_scan_mode mode,
        enum qca_wlan_vendor_spectral_scan_mode *nlmode);
#endif /* SPECTRAL_SUPPORT_CFG80211 */

/**
 * send_ioctl_command() - Function to send Spectral ioctl command
 * @ifname: Interface name
 * @buf: Buffer containing command data
 * @sock_fd: Socket file descriptor to use
 *
 * Return: SUCCESS or FAILURE
 */
static int send_ioctl_command (const char *ifname, void *buf, int sock_fd)
{
    struct ifreq ifr;

    ATHSSD_ASSERT(ifname != NULL);
    ATHSSD_ASSERT(buf != NULL);

    memset((void *)&ifr, 0, sizeof(ifr));

    if (strlcpy(ifr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
        fprintf(stderr, "ifname too long\n");
        return FAILURE;
    }

    ifr.ifr_data = buf;

    if (ioctl(sock_fd, SIOCGATHPHYERR, &ifr) < 0) {
        perror("ioctl failed");
        return FAILURE;
    }

    return SUCCESS;
}

#ifdef SPECTRAL_SUPPORT_CFG80211
/**
 * convert_to_cfg80211_spectral_mode() - Function to convert
 * spectral_scan_mode to qca_wlan_vendor_spectral_scan_mode
 * @mode: enum spectral_scan_mode value
 * @nlmode Pointer to enum qca_wlan_vendor_spectral_scan_mode. The converted
 * value will be written to this location on success. The caller should ignore
 * this on error.
 *
 * Return: SUCCESS/FAILURE
 */
static int convert_to_cfg80211_spectral_mode(enum spectral_scan_mode mode,
        enum qca_wlan_vendor_spectral_scan_mode *nlmode) {
    int status = FAILURE;

    ATHSSD_ASSERT(nlmode != NULL);

    switch (mode) {
        case SPECTRAL_SCAN_MODE_NORMAL:
            *nlmode = QCA_WLAN_VENDOR_SPECTRAL_SCAN_MODE_NORMAL;
            status = SUCCESS;
            break;

        case SPECTRAL_SCAN_MODE_AGILE:
            *nlmode = QCA_WLAN_VENDOR_SPECTRAL_SCAN_MODE_AGILE;
            status = SUCCESS;
            break;

        default:
            fprintf(stderr, "%s Unhandled mode %d\n", __func__, mode);
            status = FAILURE;
            break;
    }

    return status;
}
#endif

/**
 * get_vap_priv_int_param() - Get private integer parameter for VAP
 * @pinfo: Pointer to ath_ssd_info_t
 * @ifname: VAP interface name
 * @param: IEEE80211_PARAM specifier for parameter
 * @value: Pointer to integer value which is to be populated (should be ignored
 * by caller on error)
 *
 * Return: 0 on success, negative value on error
 */
int get_vap_priv_int_param(ath_ssd_info_t* pinfo, const char *ifname, int param,
        int *value)
{
#if SPECTRAL_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
    int ret;

    ATHSSD_ASSERT(pinfo != NULL);
    ATHSSD_ASSERT(ifname != NULL);
    ATHSSD_ASSERT(value != NULL);

    if (IS_CFG80211_ENABLED(pinfo)) {
        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void*)&buffer, 0, sizeof(buffer));
        buffer.data = value;
        buffer.length = sizeof(*value);
        buffer.parse_data = 0;
        buffer.callback = NULL;
        buffer.parse_data = 0;
        ret = wifi_cfg80211_send_getparam_command(pcfg80211_sock_ctx,
                QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, param, ifname,
                (char *)&buffer, sizeof(uint32_t));
        /* We need to pass subcommand as well */
        if (ret < 0) {
            fprintf(stderr,"Couldn't send NL command\n");
            return -EIO;
        }
        return 0;
    }
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    return -EINVAL;
}

/**
 * athssd_set_channel() - Set channel and band for a vap
 * @pinfo: Pointer to ath_ssd_info_t
 * @ifname: VAP interface name
 * @channel: Channel number
 * @band: Band
 *
 * Return: 0 on success, negative value on error
 */
int athssd_set_channel(ath_ssd_info_t* pinfo, const char *ifname, int channel, enum wlan_band_id band)
{
#ifdef SPECTRAL_SUPPORT_CFG80211
    struct nl_msg *nlmsg = NULL;
    struct nlattr *nl_venData = NULL;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
    struct cfg80211_data buffer;

    ATHSSD_ASSERT(pinfo != NULL);
    ATHSSD_ASSERT(ifname != NULL);

    if (IS_CFG80211_ENABLED(pinfo)) {
        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void*)&buffer, 0, sizeof(buffer));
        buffer.data = NULL;
        buffer.length = 0;
        buffer.parse_data = 0;
        buffer.callback = NULL;
        buffer.parse_data = 0;

        nlmsg = wifi_cfg80211_prepare_command(pcfg80211_sock_ctx,
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                ifname);

        if (nlmsg) {
            nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
            if (!nl_venData) {
                fprintf(stderr, "failed to start vendor data\n");
                nlmsg_free(nlmsg);
                return -EIO;
            }

            if (nla_put_u32(nlmsg,
                QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND,
                QCA_NL80211_VENDORSUBCMD_CHANNEL_CONFIG)) {
                nlmsg_free(nlmsg);
                return -EIO;
            }

            if (nla_put_u32(nlmsg,
                QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, channel)) {
                nlmsg_free(nlmsg);
                return -EIO;
            }

            if (nla_put_u32(nlmsg,
                QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_LENGTH, band)) {
                nlmsg_free(nlmsg);
                return -EIO;
            }

            if (nl_venData) {
                end_vendor_data(nlmsg, nl_venData);
            }
            return send_nlmsg(pcfg80211_sock_ctx, nlmsg, &buffer);
        }
    }
#endif /* SPECTRAL_SUPPORT_CFG80211 */

    return -EINVAL;
}

/**
 * get_radio_priv_int_param() - Get private integer parameter for radio
 * @pinfo: Pointer to ath_ssd_info_t
 * @ifname: Radio interface name
 * @param: _ol_ath_param_t enum value for parameter
 * @value: Pointer to integer value which is to be populated (should be ignored
 * by caller on error)
 *
 * Return: 0 on success, negative value on error
 */
int get_radio_priv_int_param(ath_ssd_info_t* pinfo, const char *ifname,
        int param, int *value)
{
#ifdef SPECTRAL_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    ath_ssd_nlsock_t *pnlinfo = NULL;
    struct iwreq iwr;
    int ret = 0;

    ATHSSD_ASSERT(pinfo != NULL);
    ATHSSD_ASSERT(ifname != NULL);
    ATHSSD_ASSERT(value != NULL);

#if !ATH_PERF_PWR_OFFLOAD
    if (param == OL_ATH_PARAM_GET_IF_ID) {
        return 0;
    }
#endif /* ATH_PERF_PWR_OFFLOAD */

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void *)&buffer, 0, sizeof(buffer));
        buffer.data = value;
        buffer.length = sizeof(*value);
        buffer.parse_data = 0;
        buffer.callback = NULL;
        buffer.parse_data = 0;

        ret = wifi_cfg80211_send_getparam_command(pcfg80211_sock_ctx,
                QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, param | ATH_PARAM_SHIFT,
                ifname, (char *)&buffer, sizeof(uint32_t));
        if (ret < 0) {
            fprintf(stderr,"Couldn't send NL command\n");
            return -EIO;
        }

        return 0;
    } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    {
        pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
        ATHSSD_ASSERT(pnlinfo != NULL);

        memset((void *)&iwr, 0, sizeof(iwr));

        iwr.u.mode = param | ATH_PARAM_SHIFT;

        memset(iwr.ifr_name, '\0', IFNAMSIZ);
        if (strlcpy(iwr.ifr_name, ifname, IFNAMSIZ) >= IFNAMSIZ) {
            fprintf(stderr,"ifname is too long\n");
            return -EINVAL;
        }

        ret = ioctl(pnlinfo->spectral_fd, IEEE80211_IOCTL_GETPARAM, &iwr);
        if (ret < 0) {
            /*
             * We return an error in all cases, including if
             * param=OL_ATH_PARAM_GET_IF_ID. This is for clarity and uniformity.
             * Exceptions for param=OL_ATH_PARAM_GET_IF_ID can be added in the
             * future if needed.
             */
            fprintf(stderr,"Unable to send WEXT ioctl command\n");
            return -EIO;
        }

        *value = iwr.u.param.value;
        return 0;
    }

    return -EINVAL;
}

/*
 * Function     : ath_ssd_init_spectral
 * Description  : initialize spectral related info
 * Input params : pointer to ath_ssd_info_t info structrue
 * Return       : success/failure
 *
 */
int ath_ssd_init_spectral(ath_ssd_info_t* pinfo)
{
    int err = SUCCESS;
    ath_ssd_spectral_info_t* psinfo = &pinfo->sinfo;

    if (pinfo->radio_ifname == NULL)
        return -EINVAL;

    if (strlcpy(psinfo->atd.ad_name, pinfo->radio_ifname, sizeof(psinfo->atd.ad_name)) >= sizeof(psinfo->atd.ad_name)) {
        fprintf(stderr, "radio_ifname too long: %s\n", pinfo->radio_ifname);
        return FAILURE;
    }

    return err;
}

#ifdef SPECTRAL_SUPPORT_CFG80211
/*
 * print_spectral_error_code() - Helper for printing to stderr the description
 * of Spectral error as per Spectral error code passed
 * @spectral_err: Spectral error code
 */
static inline void print_spectral_error_description(
        enum qca_wlan_vendor_spectral_scan_error_code spectral_err) {
    switch(spectral_err) {
        case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_PARAM_UNSUPPORTED:
            fprintf(stderr, "Spectral scan parameter unsupported\n");
            break;

        case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_MODE_UNSUPPORTED:
            fprintf(stderr, "Spectral scan mode unsupported\n");
            break;

        case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_PARAM_INVALID_VALUE:
            fprintf(stderr, "Invalid Spectral scan parameter value\n");
            break;

        case QCA_WLAN_VENDOR_SPECTRAL_SCAN_ERR_PARAM_NOT_INITIALIZED:
            fprintf(stderr, "A Spectral scan parameter is not initialized\n");
            break;

        default:
            fprintf(stderr, "Invalid Spectral scan error code %d\n",
                    spectral_err);
            break;
    }

    return;
}

/*
 * ath_ssd_spectral_cfg_error_handler_helper() - Helper for handling cfg80211
 * Spectral configuration error indication
 * @cfgdata: Pointer to struct cfg80211_data
 *
 * This is a common helper for populating cfg80211 Spectral configuration error
 * indication and setting the corresponding flag in the error context to true.
 * This should be used by Spectral configuration handlers which only need to
 * parse for the error indication. Handlers which need any differing or
 * additional functionality should not call this helper.
 */
static void ath_ssd_spectral_cfg_error_handler_helper(
        struct cfg80211_data *cfgdata)
{
    struct nlattr *attr_vendor[\
        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX + 1];
    ath_ssd_spectral_err_ctx_t *spectral_err_ctx = NULL;
    size_t expected_spectral_err_ctx_len = 0;

    if (!cfgdata) {
        fprintf(stderr,"%s: NULL cfgdata received. Investigate.\n", __func__);
        return;
    }

    if (!cfgdata->nl_vendordata) {
        fprintf(stderr,
                "%s: NULL nl_vendordata received in cfgdata. Investigate.",
                __func__);
        return;
    }

    if (!cfgdata->nl_vendordata_len) {
        fprintf(stderr,
                "%s: nl_vendordata_len=0 received in cfgdata. Investigate.",
                __func__);
        return;
    }

    if (!cfgdata->data) {
        fprintf(stderr,
                "%s: NULL data buffer received in cfgdata. Investigate.",
                __func__);
        return;
    }

    expected_spectral_err_ctx_len = sizeof(ath_ssd_spectral_err_ctx_t);
    if (cfgdata->length != expected_spectral_err_ctx_len) {
        fprintf(stderr,
                "%s: Unexpected data buffer length received in cfgdata. Expected=%zu Received=%u. Investigate.",
                __func__, expected_spectral_err_ctx_len, cfgdata->length);
        return;
    }

    if (nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX,
            cfgdata->nl_vendordata, cfgdata->nl_vendordata_len, NULL) < 0) {
        fprintf(stderr, "%s Error parsing NL vendor attributes.", __func__);
        return;
    }

    spectral_err_ctx = (ath_ssd_spectral_err_ctx_t *)cfgdata->data;
    memset(spectral_err_ctx, 0, sizeof(*spectral_err_ctx));

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]) {
            spectral_err_ctx->spectral_err = nla_get_u32(attr_vendor
                    [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_ERROR_CODE]);

            spectral_err_ctx->is_spectral_err_valid = true;
    }
}

/*
 * ath_ssd_start_spectral_scan_handler() - cfg80211 handler for start Spectral
 * scan request
 * @cfgdata: Pointer to struct cfg80211_data
 */
static void ath_ssd_start_spectral_scan_handler(struct cfg80211_data *cfgdata)
{
    ath_ssd_spectral_cfg_error_handler_helper(cfgdata);
}
#endif /* SPECTRAL_SUPPORT_CFG80211 */

/*
 * ath_ssd_start_spectral_scan() - Start Spectral scan on current channel
 * @pinfo: Pointer to ath_ssd_info_t structure
 *
 * Return: SUCCESS/FAILURE
 */
int ath_ssd_start_spectral_scan(ath_ssd_info_t *pinfo)
{
#ifdef SPECTRAL_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
    struct nl_msg *nlmsg = NULL;
    struct nlattr *nl_venData = NULL;
    enum qca_wlan_vendor_spectral_scan_mode nlmode;
    ath_ssd_spectral_err_ctx_t spectral_err_ctx = {0};
    int cfgret = 0;
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    ath_ssd_nlsock_t *pnlinfo = NULL;
    ath_ssd_spectral_info_t *psinfo = NULL;
    u_int32_t status = FAILURE;

    ATHSSD_ASSERT(pinfo != NULL);

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        ATHSSD_ASSERT(pinfo->radio_ifname != NULL);

        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void *)&buffer, 0, sizeof(buffer));
        buffer.data = (void *)(&spectral_err_ctx);
        buffer.length = sizeof(spectral_err_ctx);
        buffer.callback = ath_ssd_start_spectral_scan_handler;
        buffer.parse_data = 1;

        nlmsg = wifi_cfg80211_prepare_command(pcfg80211_sock_ctx,
                    QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START,
                    pinfo->radio_ifname);
        if (!nlmsg) {
            fprintf(stderr, "%s: Failed to prepare NL message\n", __func__);
            status = FAILURE;
            goto out;
        }

        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData) {
            fprintf(stderr, "%s: Failed to start NL vendor data\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        cfgret = convert_to_cfg80211_spectral_mode(pinfo->spectral_mode,
                        &nlmode);
        if (cfgret != SUCCESS) {
            fprintf(stderr, "%s: Failed to convert mode to cfg80211 "
                            "equivalent\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        if (nla_put_u32(nlmsg,
                    QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
                    nlmode)) {
            fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                            "mode\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        if (nla_put_u32(nlmsg,
                        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE,
                        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE_SCAN)) {
            fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                            "type of request\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        end_vendor_data(nlmsg, nl_venData);

        cfgret = send_nlmsg(pcfg80211_sock_ctx, nlmsg, &buffer);
        if (cfgret < 0) {
            fprintf(stderr, "%s: Failed to send NL vendor data\n", __func__);
            status = FAILURE;
            goto out;
        }

        if (spectral_err_ctx.is_spectral_err_valid) {
            fprintf(stderr, "%s: Error on trying to start Spectral\n",
                    __func__);
            print_spectral_error_description(spectral_err_ctx.spectral_err);
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    {
        pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
        ATHSSD_ASSERT(pnlinfo != NULL);

        psinfo = &pinfo->sinfo;

        psinfo->atd.ad_id = SPECTRAL_ACTIVATE_SCAN | ATH_DIAG_DYN;
        psinfo->atd.ad_in_data = NULL;
        psinfo->atd.ad_in_size = 0;
        psinfo->atd.ad_out_data = (void*)&status;
        psinfo->atd.ad_out_size = sizeof(u_int32_t);

        if (send_ioctl_command(psinfo->atd.ad_name, (caddr_t)&psinfo->atd,
                    pnlinfo->spectral_fd) != SUCCESS) {
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    }

out:
    return status;
}


#ifdef SPECTRAL_SUPPORT_CFG80211
/*
 * ath_ssd_stop_spectral_scan_handler() - cfg80211 handler for stop Spectral
 * scan request
 * @cfgdata: Pointer to struct cfg80211_data
 */
static void ath_ssd_stop_spectral_scan_handler(struct cfg80211_data *cfgdata)
{
    ath_ssd_spectral_cfg_error_handler_helper(cfgdata);
}
#endif /* SPECTRAL_SUPPORT_CFG80211 */

/*
 * ath_ssd_stop_spectral_scan() - Stop Spectral scan
 * @pinfo: Pointer to ath_ssd_info_t structure
 *
 * Return: SUCCESS/FAILURE
 */
int ath_ssd_stop_spectral_scan(ath_ssd_info_t *pinfo)
{
#ifdef SPECTRAL_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
    struct nl_msg *nlmsg = NULL;
    struct nlattr *nl_venData = NULL;
    enum qca_wlan_vendor_spectral_scan_mode nlmode;
    ath_ssd_spectral_err_ctx_t spectral_err_ctx = {0};
    int cfgret = 0;
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    ath_ssd_nlsock_t *pnlinfo = NULL;
    ath_ssd_spectral_info_t *psinfo = NULL;
    u_int32_t status = FAILURE;

    ATHSSD_ASSERT(pinfo != NULL);

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        ATHSSD_ASSERT(pinfo->radio_ifname != NULL);

        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void *)&buffer, 0, sizeof(buffer));
        buffer.data = (void *)(&spectral_err_ctx);
        buffer.length = sizeof(spectral_err_ctx);
        buffer.callback = ath_ssd_stop_spectral_scan_handler;
        buffer.parse_data = 1;

        nlmsg = wifi_cfg80211_prepare_command(pcfg80211_sock_ctx,
                    QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_STOP,
                    pinfo->radio_ifname);
        if (!nlmsg) {
            fprintf(stderr, "%s: Failed to prepare NL message\n", __func__);
            status = FAILURE;
            goto out;
        }

        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData) {
            fprintf(stderr, "%s: Failed to start NL vendor data\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        cfgret = convert_to_cfg80211_spectral_mode(pinfo->spectral_mode,
                        &nlmode);
        if (cfgret != SUCCESS) {
            fprintf(stderr, "%s: Failed to convert mode to cfg80211 "
                            "equivalent\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        if (nla_put_u32(nlmsg,
                    QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
                    nlmode)) {
            fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                            "mode\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        end_vendor_data(nlmsg, nl_venData);

        cfgret = send_nlmsg(pcfg80211_sock_ctx, nlmsg, &buffer);
        if (cfgret < 0) {
            fprintf(stderr, "%s: Failed to send NL vendor data\n", __func__);
            status = FAILURE;
            goto out;
        }

        if (spectral_err_ctx.is_spectral_err_valid) {
            fprintf(stderr, "%s: Error on trying to stop Spectral\n",
                    __func__);
            print_spectral_error_description(spectral_err_ctx.spectral_err);
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    {
        pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
        ATHSSD_ASSERT(pnlinfo != NULL);

        psinfo = &pinfo->sinfo;

        psinfo->atd.ad_id = SPECTRAL_STOP_SCAN | ATH_DIAG_DYN;
        psinfo->atd.ad_in_data = NULL;
        psinfo->atd.ad_in_size = 0;
        psinfo->atd.ad_out_data = (void*)&status;
        psinfo->atd.ad_out_size = sizeof(u_int32_t);

        if (send_ioctl_command(psinfo->atd.ad_name, (caddr_t)&psinfo->atd,
                    pnlinfo->spectral_fd) != SUCCESS) {
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    }

out:
    return status;
}

#ifdef SPECTRAL_SUPPORT_CFG80211
/*
 * ath_ssd_set_spectral_param_handler() - cfg80211 handler for set Spectral
 * parameter request
 * @cfgdata: Pointer to struct cfg80211_data
 */
static void ath_ssd_set_spectral_param_handler(struct cfg80211_data *cfgdata)
{
    ath_ssd_spectral_cfg_error_handler_helper(cfgdata);
}
#endif /* SPECTRAL_SUPPORT_CFG80211 */

/*
 * ath_ssd_set_spectral_param() - Set Spectral configuration parameter
 * @pinfo: Pointer to ath_ssd_info_t
 * @param: Spectral parameter id and value
 *
 * Return: SUCCESS/FAILURE
 */
int ath_ssd_set_spectral_param(ath_ssd_info_t *pinfo, struct spectral_param *param)
{
#ifdef SPECTRAL_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
    struct nl_msg *nlmsg = NULL;
    struct nlattr *nl_venData = NULL;
    enum qca_wlan_vendor_spectral_scan_mode nlmode;
    ath_ssd_spectral_err_ctx_t spectral_err_ctx = {0};
    int cfgret = 0;
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    struct spectral_config sp;
    ath_ssd_nlsock_t *pnlinfo = NULL;
    ath_ssd_spectral_info_t *psinfo = NULL;
    int status = FAILURE;

    ATHSSD_ASSERT(pinfo != NULL);

    memset((void *)&sp, 0, sizeof(sp));
    if (ath_ssd_get_spectral_param(pinfo, &sp) != SUCCESS) {
        status = FAILURE;
        goto out;
    }

    switch(param->id) {
        case SPECTRAL_PARAM_FFT_PERIOD:
            sp.ss_fft_period = param->value;
            break;

        case SPECTRAL_PARAM_SCAN_PERIOD:
            sp.ss_period = param->value;
            break;

        case SPECTRAL_PARAM_SHORT_REPORT:
            {
                if (param->value) {
                    sp.ss_short_report = 1;
                } else {
                    sp.ss_short_report = 0;
                }
            }
            break;

        case SPECTRAL_PARAM_SCAN_COUNT:
            sp.ss_count = param->value;
            break;

        case SPECTRAL_PARAM_SPECT_PRI:
            sp.ss_spectral_pri = (!!param->value) ? true:false;
            break;

        case SPECTRAL_PARAM_FFT_SIZE:
            sp.ss_fft_size = param->value;
            break;

        case SPECTRAL_PARAM_GC_ENA:
            sp.ss_gc_ena = !!param->value;
            break;

        case SPECTRAL_PARAM_RESTART_ENA:
            sp.ss_restart_ena = !!param->value;
            break;

        case SPECTRAL_PARAM_NOISE_FLOOR_REF:
            sp.ss_noise_floor_ref = param->value;
            break;

        case SPECTRAL_PARAM_INIT_DELAY:
            sp.ss_init_delay = param->value;
            break;

        case SPECTRAL_PARAM_NB_TONE_THR:
            sp.ss_nb_tone_thr = param->value;
            break;

        case SPECTRAL_PARAM_STR_BIN_THR:
            sp.ss_str_bin_thr = param->value;
            break;

        case SPECTRAL_PARAM_WB_RPT_MODE:
            sp.ss_wb_rpt_mode = !!param->value;
            break;

        case SPECTRAL_PARAM_RSSI_RPT_MODE:
            sp.ss_rssi_rpt_mode = !!param->value;
            break;

        case SPECTRAL_PARAM_RSSI_THR:
            sp.ss_rssi_thr = param->value;
            break;

        case SPECTRAL_PARAM_PWR_FORMAT:
            sp.ss_pwr_format = !!param->value;
            break;

        case SPECTRAL_PARAM_RPT_MODE:
            sp.ss_rpt_mode = param->value;
            break;

        case SPECTRAL_PARAM_BIN_SCALE:
            sp.ss_bin_scale = param->value;
            break;

        case SPECTRAL_PARAM_DBM_ADJ:
            sp.ss_dbm_adj = !!param->value;
            break;

        case SPECTRAL_PARAM_CHN_MASK:
            sp.ss_chn_mask = param->value;
            break;

        case SPECTRAL_PARAM_FREQUENCY:
            sp.ss_frequency.cfreq1 =  param->value1;
            sp.ss_frequency.cfreq2 =  param->value2;
            break;
    }

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        ATHSSD_ASSERT(pinfo->radio_ifname != NULL);

        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void *)&buffer, 0, sizeof(buffer));
        buffer.data = (void *)(&spectral_err_ctx);
        buffer.length = sizeof(spectral_err_ctx);
        buffer.callback = ath_ssd_set_spectral_param_handler;
        buffer.parse_data = 1;

        nlmsg = wifi_cfg80211_prepare_command(pcfg80211_sock_ctx,
                    QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_START,
                    pinfo->radio_ifname);
        if (!nlmsg) {
            fprintf(stderr, "%s: Failed to prepare NL message\n", __func__);
            status = FAILURE;
            goto out;
        }

        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData) {
            fprintf(stderr, "%s: Failed to start NL vendor data\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        cfgret = convert_to_cfg80211_spectral_mode(pinfo->spectral_mode,
                        &nlmode);
        if (cfgret != SUCCESS) {
            fprintf(stderr, "%s: Failed to convert mode to cfg80211 "
                            "equivalent\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        if (nla_put_u32(nlmsg,
                    QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
                    nlmode)) {
            fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                            "mode\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        if (nla_put_u32(nlmsg,
                    QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE,
                    QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_REQUEST_TYPE_CONFIG)) {
            fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                            "type of request\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        if (param->id == SPECTRAL_PARAM_FREQUENCY) {
            if (nla_put_u32(nlmsg,
                        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY,
                        param->value1)) {
                fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                                "Spectral parameter value\n", __func__);
                nlmsg_free(nlmsg);
                status = FAILURE;
                goto out;
            }

            if (nla_put_u32(nlmsg,
                        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY_2,
                        param->value2)) {
                fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                                "Spectral parameter value\n", __func__);
                nlmsg_free(nlmsg);
                status = FAILURE;
                goto out;
            }
        } else {
            if (nla_put_u32(nlmsg,
                        pinfo->sparams_to_cfg80211_attrs[param->id], param->value)) {
                fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                                "Spectral parameter value\n", __func__);
                nlmsg_free(nlmsg);
                status = FAILURE;
                goto out;
            }
        }
        end_vendor_data(nlmsg, nl_venData);

        cfgret = send_nlmsg(pcfg80211_sock_ctx, nlmsg, &buffer);
        if (cfgret < 0) {
            fprintf(stderr, "%s: Failed to send NL vendor data\n", __func__);
            status = FAILURE;
            goto out;
        }

        if (spectral_err_ctx.is_spectral_err_valid) {
            if (param->id == SPECTRAL_PARAM_FREQUENCY) {
                fprintf(stderr,
                        "%s: Error on trying to configure Spectral param %d with value %d %d\n",
                        __func__, param->id, param->value1, param->value2);
            } else {
                fprintf(stderr,
                        "%s: Error on trying to configure Spectral param %d with value %d\n",
                        __func__, param->id, param->value);
            }
            print_spectral_error_description(spectral_err_ctx.spectral_err);
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    {
        pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
        ATHSSD_ASSERT(pnlinfo != NULL);

        psinfo = &pinfo->sinfo;

        psinfo->atd.ad_id = SPECTRAL_SET_CONFIG | ATH_DIAG_IN;
        psinfo->atd.ad_out_data = NULL;
        psinfo->atd.ad_out_size = 0;
        psinfo->atd.ad_in_data = (void *) &sp;
        psinfo->atd.ad_in_size = sizeof(struct spectral_config);

        if (send_ioctl_command(psinfo->atd.ad_name, (caddr_t)&psinfo->atd,
                    pnlinfo->spectral_fd) != SUCCESS) {
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    }

out:
    return status;
}

#ifdef SPECTRAL_SUPPORT_CFG80211
/*
 * ath_ssd_init_spectral_config() - Initialize Spectral configuration structure
 * @sp: Pointer to struct spectral_config which is to be initialized
 */
static void ath_ssd_init_spectral_config(struct spectral_config *sp)
{
    ATHSSD_ASSERT(sp != NULL);

    memset(sp, 0, sizeof(*sp));

    sp->ss_count = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_period = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_spectral_pri = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_fft_size = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_gc_ena = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_restart_ena = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_noise_floor_ref = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_init_delay = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_nb_tone_thr = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_str_bin_thr = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_wb_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_rssi_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_rssi_thr = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_pwr_format = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_bin_scale = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_dbm_adj = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_chn_mask = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_fft_period = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_short_report = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_frequency.cfreq1 = HAL_PHYERR_PARAM_NOVAL;
    sp->ss_frequency.cfreq2 = HAL_PHYERR_PARAM_NOVAL;
}

/*
 * ath_ssd_get_spectral_param_handler() - cfg80211 handler for spectral
 * configuration get request
 * @msg: Pointer to struct cfg80211_data
 */
static void ath_ssd_get_spectral_param_handler(struct cfg80211_data *cfgdata)
{
    struct nlattr *attr_vendor[\
        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX + 1];
    struct spectral_config *sp = NULL;
    size_t expected_sp_len = 0;

    if (cfgdata == NULL) {
        fprintf(stderr,"%s: NULL cfgdata received. Investigate.\n", __func__);
        return;
    }

    if (cfgdata->nl_vendordata == NULL) {
        fprintf(stderr, "%s: NULL nl_vendordata received in cfgdata. "
                        "Investigate.", __func__);
        return;
    }

    if (cfgdata->nl_vendordata_len == 0) {
        fprintf(stderr, "%s: nl_vendordata_len=0 received in cfgdata. "
                        "Investigate.", __func__);
        return;
    }

    if (cfgdata->data == NULL) {
        fprintf(stderr, "%s: NULL data buffer received in cfgdata. "
                        "Investigate.", __func__);
        return;
    }

    expected_sp_len = sizeof(struct spectral_config);
    if (cfgdata->length != expected_sp_len) {
        fprintf(stderr, "%s: Unexpected data buffer length received in "
                        "cfgdata. Expected=%zu Received=%u. Investigate.",
                        __func__, expected_sp_len, cfgdata->length);
        return;
    }

    if (nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_MAX,
            cfgdata->nl_vendordata, cfgdata->nl_vendordata_len, NULL) < 0) {
        fprintf(stderr, "%s Error parsing NL vendor attributes.",__func__);
        return;
    }

    sp = (struct spectral_config *)cfgdata->data;

    ath_ssd_init_spectral_config(sp);

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_COUNT]) {
        sp->ss_count = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_COUNT]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_PERIOD]) {
        sp->ss_period = nla_get_u32(attr_vendor
        [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SCAN_PERIOD]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY]) {
        sp->ss_spectral_pri = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PRIORITY]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_SIZE]) {
        sp->ss_fft_size = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_SIZE]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_GC_ENA]) {
        sp->ss_gc_ena = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_GC_ENA]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RESTART_ENA]) {
        sp->ss_restart_ena = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RESTART_ENA]);
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NOISE_FLOOR_REF]) {
        sp->ss_noise_floor_ref = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NOISE_FLOOR_REF]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_INIT_DELAY]) {
        sp->ss_init_delay = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_INIT_DELAY]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NB_TONE_THR]) {
        sp->ss_nb_tone_thr = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_NB_TONE_THR]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_STR_BIN_THR]) {
        sp->ss_str_bin_thr = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_STR_BIN_THR]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_WB_RPT_MODE]) {
        sp->ss_wb_rpt_mode = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_WB_RPT_MODE]);
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_RPT_MODE]) {
        sp->ss_rssi_rpt_mode = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_RPT_MODE]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_THR]) {
        sp->ss_rssi_thr = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RSSI_THR]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PWR_FORMAT]) {
        sp->ss_pwr_format = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_PWR_FORMAT]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RPT_MODE]) {
        sp->ss_rpt_mode = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_RPT_MODE]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_BIN_SCALE]) {
        sp->ss_bin_scale = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_BIN_SCALE]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DBM_ADJ]) {
        sp->ss_dbm_adj = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_DBM_ADJ]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_CHN_MASK]) {
        sp->ss_chn_mask = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_CHN_MASK]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_PERIOD]) {
        sp->ss_fft_period = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FFT_PERIOD]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SHORT_REPORT]) {
        sp->ss_short_report = nla_get_u32(attr_vendor
           [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_SHORT_REPORT]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY]) {
        sp->ss_frequency.cfreq1 = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY_2]) {
        sp->ss_frequency.cfreq2 = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CONFIG_FREQUENCY_2]);
    }
}
#endif /* SPECTRAL_SUPPORT_CFG80211 */

/*
 * ath_ssd_get_spectral_param() - Get Spectral configuration parameters
 * @pinfo: Pointer to ath_ssd_info_t
 * @sp: Pointer to struct spectral_config to be populated
 *
 * Return: SUCCESS/FAILURE
 */
int ath_ssd_get_spectral_param(ath_ssd_info_t *pinfo,
        struct spectral_config *sp)
{
#ifdef SPECTRAL_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
    struct nl_msg *nlmsg = NULL;
    struct nlattr *nl_venData = NULL;
    enum qca_wlan_vendor_spectral_scan_mode nlmode;
    int cfgret = 0;
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    ath_ssd_nlsock_t *pnlinfo = NULL;
    ath_ssd_spectral_info_t *psinfo = NULL;
    int status = FAILURE;

    ATHSSD_ASSERT(pinfo != NULL);
    ATHSSD_ASSERT(sp != NULL);

    memset(sp, 0, sizeof(*sp));

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        ATHSSD_ASSERT(pinfo->radio_ifname != NULL);

        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void *)&buffer, 0, sizeof(buffer));
        buffer.data = (void *)sp;
        buffer.length = sizeof(*sp);
        buffer.callback = ath_ssd_get_spectral_param_handler;
        buffer.parse_data = 1;

        nlmsg = wifi_cfg80211_prepare_command(pcfg80211_sock_ctx,
                    QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_CONFIG,
                    pinfo->radio_ifname);
        if (!nlmsg) {
            fprintf(stderr, "%s: Failed to prepare NL message\n", __func__);
            status = FAILURE;
            goto out;
        }

        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData) {
            fprintf(stderr, "%s: Failed to start NL vendor data\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        cfgret = convert_to_cfg80211_spectral_mode(pinfo->spectral_mode,
                        &nlmode);
        if (cfgret != SUCCESS) {
            fprintf(stderr, "%s: Failed to convert mode to cfg80211 "
                            "equivalent\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        if (nla_put_u32(nlmsg,
                    QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_MODE,
                    nlmode)) {
            fprintf(stderr, "%s: Failed to add NL vendor attribute data for "
                            "mode\n", __func__);
            nlmsg_free(nlmsg);
            status = FAILURE;
            goto out;
        }

        end_vendor_data(nlmsg, nl_venData);

        cfgret = send_nlmsg(pcfg80211_sock_ctx, nlmsg, &buffer);
        if (cfgret < 0) {
            fprintf(stderr, "%s: Failed to send NL vendor data\n", __func__);
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    {
        pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
        ATHSSD_ASSERT(pnlinfo != NULL);

        psinfo = &pinfo->sinfo;

        psinfo->atd.ad_id = SPECTRAL_GET_CONFIG | ATH_DIAG_DYN;
        psinfo->atd.ad_out_data = (void *)sp;
        psinfo->atd.ad_out_size = sizeof(*sp);

        if (send_ioctl_command(psinfo->atd.ad_name, (caddr_t)&psinfo->atd,
                    pnlinfo->spectral_fd) != SUCCESS) {
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    }

out:
    return status;
}

/*
 * Function     : get_channel_width
 * Description  : Get current radio level channel width from driver
 * Input params : pointer to ath_ssd_info_t structure
 * Return       : IEEE80211_CWM_WIDTHINVALID on failure, a valid
 *                IEEE80211_CWM_* entry on success
 */
int get_channel_width(ath_ssd_info_t* pinfo)
{
    int ch_width = IEEE80211_CWM_WIDTHINVALID;
    int ret = 0;

    ATHSSD_ASSERT(pinfo != NULL);
    ATHSSD_ASSERT(pinfo->radio_ifname != NULL);

    ret = get_radio_priv_int_param(pinfo, pinfo->radio_ifname,
                        OL_ATH_PARAM_RCHWIDTH, &ch_width);
    if (ret < 0) {
        fprintf(stderr,"Unable to get radio width\n");
        return IEEE80211_CWM_WIDTHINVALID;
    }

    return ch_width;
}

#ifdef SPECTRAL_SUPPORT_CFG80211
/*
 * ath_ssd_get_spectral_capabilities_handler() - cfg80211 handler for Spectral
 * capabilities get request
 * @msg: Pointer to struct cfg80211_data
 */
static void ath_ssd_get_spectral_capabilities_handler(
        struct cfg80211_data *cfgdata)
{
    struct nlattr *attr_vendor[\
        QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_MAX + 1];
    struct spectral_caps *caps = NULL;
    size_t expected_caps_len = 0;

    if (cfgdata == NULL) {
        fprintf(stderr,"%s: NULL cfgdata received. Investigate.\n", __func__);
        return;
    }

    if (cfgdata->nl_vendordata == NULL) {
        fprintf(stderr, "%s: NULL nl_vendordata received in cfgdata. "
                        "Investigate.", __func__);
        return;
    }

    if (cfgdata->nl_vendordata_len == 0) {
        fprintf(stderr, "%s: nl_vendordata_len=0 received in cfgdata. "
                        "Investigate.", __func__);
        return;
    }

    if (cfgdata->data == NULL) {
        fprintf(stderr, "%s: NULL data buffer received in cfgdata. "
                        "Investigate.", __func__);
        return;
    }

    expected_caps_len = sizeof(struct spectral_caps);
    if (cfgdata->length != expected_caps_len) {
        fprintf(stderr, "%s: Unexpected data buffer length received in "
                        "cfgdata. Expected=%zu Received=%u. Investigate.",
                        __func__, expected_caps_len, cfgdata->length);
        return;
    }

    if (nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_MAX,
            cfgdata->nl_vendordata, cfgdata->nl_vendordata_len, NULL) < 0) {
        fprintf(stderr, "%s Error parsing NL vendor attributes.",__func__);
        return;
    }

    caps = (struct spectral_caps *)cfgdata->data;

    memset(caps, 0, sizeof(*caps));

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_PHYDIAG]) {
        caps->phydiag_cap = 1;
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_RADAR]) {
        caps->radar_cap = 1;
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_SPECTRAL]) {
        caps->spectral_cap = 1;
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_ADVANCED_SPECTRAL]) {
        caps->advncd_spectral_cap = 1;
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HW_GEN]) {
        caps->hw_gen = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HW_GEN]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_FORMULA_ID]) {
        caps->is_scaling_params_populated = true;
        caps->formula_id = nla_get_u16(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_FORMULA_ID]);
    } else {
        caps->is_scaling_params_populated = false;
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_LOW_LEVEL_OFFSET]) {
        caps->low_level_offset = nla_get_u16(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_LOW_LEVEL_OFFSET]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HIGH_LEVEL_OFFSET]) {
        caps->high_level_offset = nla_get_u16(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_HIGH_LEVEL_OFFSET]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_RSSI_THR]) {
        caps->rssi_thr = nla_get_u16(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_RSSI_THR]);
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_DEFAULT_AGC_MAX_GAIN]) {
        caps->default_agc_max_gain = nla_get_u8(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_DEFAULT_AGC_MAX_GAIN]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_AGILE_SPECTRAL]) {
        caps->agile_spectral_cap = 1;
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_AGILE_SPECTRAL_160]) {
        caps->agile_spectral_cap_160 = 1;
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_AGILE_SPECTRAL_80_80]) {
        caps->agile_spectral_cap_80p80 = 1;
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_20_MHZ]) {
        caps->num_detectors_20mhz = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_20_MHZ]);
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_40_MHZ]) {
        caps->num_detectors_40mhz = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_40_MHZ]);
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80_MHZ]) {
        caps->num_detectors_80mhz = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80_MHZ]);
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_160_MHZ]) {
        caps->num_detectors_160mhz = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_160_MHZ]);
    }

    if (attr_vendor[\
            QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80P80_MHZ]) {
        caps->num_detectors_80p80mhz = nla_get_u32(attr_vendor
            [QCA_WLAN_VENDOR_ATTR_SPECTRAL_SCAN_CAP_NUM_DETECTORS_80P80_MHZ]);
    }
}
#endif /* SPECTRAL_SUPPORT_CFG80211 */

/*
 * ath_ssd_get_spectral_capabilities() - Get Spectral capabilities
 * @pinfo: Pointer to ath_ssd_info_t
 * @caps: Pointer to struct spectral_caps to be populated
 *
 * Return: SUCCESS/FAILURE
 */
int ath_ssd_get_spectral_capabilities(ath_ssd_info_t *pinfo,
        struct spectral_caps *caps)
{
#ifdef SPECTRAL_SUPPORT_CFG80211
    struct cfg80211_data buffer;
    wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
    struct nl_msg *nlmsg = NULL;
    int cfgret = 0;
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    ath_ssd_nlsock_t *pnlinfo = NULL;
    ath_ssd_spectral_info_t *psinfo = NULL;
    int status = FAILURE;

    ATHSSD_ASSERT(pinfo != NULL);
    ATHSSD_ASSERT(caps != NULL);

    memset(caps, 0, sizeof(*caps));

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        ATHSSD_ASSERT(pinfo->radio_ifname != NULL);

        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        memset((void *)&buffer, 0, sizeof(buffer));
        buffer.data = (void *)caps;
        buffer.length = sizeof(*caps);
        buffer.callback = ath_ssd_get_spectral_capabilities_handler;
        buffer.parse_data = 1;

        nlmsg = wifi_cfg80211_prepare_command(pcfg80211_sock_ctx,
                    QCA_NL80211_VENDOR_SUBCMD_SPECTRAL_SCAN_GET_CAP_INFO,
                    pinfo->radio_ifname);
        if (!nlmsg) {
            fprintf(stderr, "%s: Failed to prepare NL message\n", __func__);
            status = FAILURE;
            goto out;
        }

        cfgret = send_nlmsg(pcfg80211_sock_ctx, nlmsg, &buffer);
        if (cfgret < 0) {
            if (cfgret == -EPERM) {
                fprintf(stderr, "Spectral scan feature is disabled\n");
            }
            fprintf(stderr, "%s: Failed to send NL vendor data\n", __func__);
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    {
        pnlinfo = GET_ADDR_OF_NLSOCKINFO(pinfo);
        ATHSSD_ASSERT(pnlinfo != NULL);

        psinfo = &pinfo->sinfo;

        psinfo->atd.ad_id = SPECTRAL_GET_CAPABILITY_INFO | ATH_DIAG_DYN;
        psinfo->atd.ad_out_data = (void *)caps;
        psinfo->atd.ad_out_size = sizeof(*caps);

        if (send_ioctl_command(psinfo->atd.ad_name, (caddr_t)&psinfo->atd,
                    pnlinfo->spectral_fd) != SUCCESS) {
            status = FAILURE;
            goto out;
        }

        status = SUCCESS;
    }

out:
    return status;
}

/*
 * ath_ssd_get_band_from_freq() - Get band from frequency in MHz.
 * @freq: Frequency in MHz
 *
 * Return: enum wlan_band_id
 */
enum wlan_band_id ath_ssd_get_band_from_freq(u_int32_t freq)
{
    if ((freq >= BAND_2_4GHZ_FREQ_MIN) && (freq <= BAND_2_4GHZ_FREQ_MAX))
        return WLAN_BAND_2GHZ;

    if ((freq >= BAND_5GHZ_FREQ_MIN) && (freq <= BAND_5GHZ_FREQ_MAX))
        return WLAN_BAND_5GHZ;

    if ((freq >= BAND_6GHZ_FREQ_MIN) && (freq <= BAND_6GHZ_FREQ_MAX))
        return WLAN_BAND_6GHZ;

    return WLAN_BAND_UNSPECIFIED;
}

/*
 * ath_ssd_interface_info_handler() - Handler to process the response of
 * NL80211_CMD_GET_INTERFACE command.
 * @msg: NL message
 * @arg: Pointer to the argument
 *
 * Return: success/failure
 */
static int ath_ssd_interface_info_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *nl_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    uint32_t *cur_freq = arg;

    nla_parse(nl_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (nl_msg[NL80211_ATTR_WIPHY_FREQ])
    {
        *cur_freq = nla_get_u32(nl_msg[NL80211_ATTR_WIPHY_FREQ]);
    } else {
        fprintf(stderr, "NL80211_ATTR_WIPHY_FREQ not found\n");
        return -EINVAL;
    }

    return NL_SKIP;
}
/*
 * ath_sssd_get_current_freq() - Get current frequency of an interface
 * @pinfo: Pointer to ath_ssd_info_t structure
 * @ifname: Interface name
 * @cur_freq: pointer to current frequency
 *
 * Return: SUCCESS/FAILURE
 */
static int ath_sssd_get_current_freq(ath_ssd_info_t *pinfo, const char *ifname, uint32_t *cur_freq)
{
    u_int32_t status = FAILURE;
    struct nl_msg *nlmsg = NULL;
    struct nl_cb *cb = NULL;

    ATHSSD_ASSERT(pinfo != NULL);

#ifdef SPECTRAL_SUPPORT_CFG80211
    if (IS_CFG80211_ENABLED(pinfo)) {
        wifi_cfg80211_context *pcfg80211_sock_ctx = NULL;
        int ret;
        int err = 1;

        ATHSSD_ASSERT(ifname != NULL);

        pcfg80211_sock_ctx = GET_ADDR_OF_CFGSOCKINFO(pinfo);
        ATHSSD_ASSERT(pcfg80211_sock_ctx != NULL);

        nlmsg = nlmsg_alloc();
        if (!nlmsg) {
            fprintf(stderr, "Failed to allocate nl message\n");
            goto out;
        }

        cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!cb) {
            fprintf(stderr, "Failed to allocate netlink callbacks\n");
            goto out;
        }

        /* Prepare nlmsg get the Interface attributes */
        genlmsg_put(nlmsg, 0, 0, pcfg80211_sock_ctx->nl80211_family_id , 0, 0, NL80211_CMD_GET_INTERFACE, 0);
        nla_put_u32(nlmsg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname));

        nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, ath_ssd_interface_info_handler, cur_freq);

        /* send message */
        ret = nl_send_auto_complete(pcfg80211_sock_ctx->cmd_sock, nlmsg);
        if (ret < 0) {
            fprintf(stderr, "nl message sending failed\n");
            goto out;
        }

        /*   wait for reply */
        while (err > 0) {  /* error will be set by callbacks */
            ret = nl_recvmsgs(pcfg80211_sock_ctx->cmd_sock, cb);
            if (ret) {
                fprintf(stderr, "nl receive message failed\n");
                goto out;
            }
        }

        status = SUCCESS;
    } else
#endif /* SPECTRAL_SUPPORT_CFG80211 */
    {
        fprintf(stderr, "WEXT is unsupported\n");
        status = FAILURE;
    }

out:
    if (cb) {
        nl_cb_put(cb);
    }
    if (nlmsg) {
        nlmsg_free(nlmsg);
    }

    return status;
}

/*
 * ath_sssd_get_current_band() - Get current band of operation of an interface
 * @pinfo: Pointer to ath_ssd_info_t structure
 * @ifname: Interface name
 * @cur_band: pointer to current band
 *
 * Return: SUCCESS/FAILURE
 */
int ath_sssd_get_current_band(ath_ssd_info_t *pinfo, const char *ifname, enum wlan_band_id *cur_band)
{
    int ret;
    uint32_t cur_freq;

    ret = ath_sssd_get_current_freq(pinfo, ifname, &cur_freq);
    if (ret != SUCCESS) {
        fprintf(stderr, "Unable to get current frequency\n");
        return ret;
    }

    *cur_band = ath_ssd_get_band_from_freq(cur_freq);
    if (*cur_band == WLAN_BAND_UNSPECIFIED) {
        fprintf(stderr, "Invalid band corresponding to freq %u MHz\n", cur_freq);
        return FAILURE;
    }

    return SUCCESS;
}
