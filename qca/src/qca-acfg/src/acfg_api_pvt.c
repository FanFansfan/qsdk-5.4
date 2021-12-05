/*
 * Copyright (c) 2018-2021 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2008-2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <net/if_arp.h>
#include <math.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <acfg_types.h>
#include <stdint.h>
#include <acfg_api_pvt.h>
#include <acfg_security.h>
#include <acfg_misc.h>
#include <acfg_api_event.h>
#include <linux/un.h>
#include <linux/netlink.h>
#include <stdarg.h>

#include <appbr_if.h>
#include <acfg_wireless.h>
bool g_str_truncated = 0;
uint8_t g_acfg_standard;

//#define LINUX_PVT_WIOCTL  (SIOCDEVPRIVATE + 1)
#define SIOCWANDEV  0x894A
#define LINUX_PVT_WIOCTL  (SIOCWANDEV)

#define ACFG_MAX_PHYMODE_STRLEN 30

extern appbr_status_t appbr_if_send_cmd_remote(uint32_t app_id, void *buf,
        uint32_t size);

extern appbr_status_t appbr_if_wait_for_response(void *buf, uint32_t size,
        uint32_t timeout);

extern uint32_t acfg_wpa_supplicant_get(acfg_wlan_profile_vap_params_t *vap_params);

extern uint32_t acfg_hostapd_get(acfg_wlan_profile_vap_params_t *vap_params);

extern void acfg_send_interface_event(char *event, int len);

uint32_t acfg_set_radio_profile(acfg_wlan_profile_radio_params_t
        *radio_params, acfg_wlan_profile_radio_params_t *cur_radio_params);

extern int compare_string(char *str1, char *str2);

extern int get_uint32(char *str, uint32_t *val);

struct socket_context g_sock_ctx;

uint32_t
acfg_get_err_status(void)
{
    switch (errno)  {
        case ENOENT:        return QDF_STATUS_E_NOENT;
        case ENOMEM:        return QDF_STATUS_E_NOMEM;
        case EINVAL:        return QDF_STATUS_E_INVAL;
        case EINPROGRESS:   return QDF_STATUS_E_ALREADY;
        case EBUSY:         return QDF_STATUS_E_BUSY;
        case E2BIG:         return QDF_STATUS_E_E2BIG;
        case ENXIO:         return QDF_STATUS_E_ENXIO;
        case EFAULT:        return QDF_STATUS_E_FAULT;
        case EIO:           return QDF_STATUS_E_IO;
        case EEXIST:        return QDF_STATUS_E_EXISTS;
        case ENETDOWN:      return QDF_STATUS_E_NETDOWN;
        case EADDRNOTAVAIL: return QDF_STATUS_E_ADDRNOTAVAIL;
        case ENETRESET:     return QDF_STATUS_E_NETRESET;
        case EOPNOTSUPP:    return QDF_STATUS_E_NOSUPPORT;
        default:            return QDF_STATUS_E_FAILURE;
    }
}

int acfg_convert_mode_to_str(uint8_t mode, char *mode_str)
{

    char *phymode_strings[] = {
        [ACFG_PHYMODE_AUTO]             = (char *)"AUTO",
        [ACFG_PHYMODE_11A]              = (char *)"11A",
        [ACFG_PHYMODE_11B]              = (char *)"11B",
        [ACFG_PHYMODE_11G]              = (char *)"11G" ,
        [ACFG_PHYMODE_FH]               = (char *)"FH" ,
        [ACFG_PHYMODE_TURBO_A]               = (char *)"TA" ,
        [ACFG_PHYMODE_TURBO_G]               = (char *)"TG" ,
        [ACFG_PHYMODE_11NA_HT20]        = (char *)"11NAHT20" ,
        [ACFG_PHYMODE_11NG_HT20]        = (char *)"11NGHT20" ,
        [ACFG_PHYMODE_11NA_HT40PLUS]    = (char *)"11NAHT40PLUS" ,
        [ACFG_PHYMODE_11NA_HT40MINUS]   = (char *)"11NAHT40MINUS" ,
        [ACFG_PHYMODE_11NG_HT40PLUS]    = (char *)"11NGHT40PLUS" ,
        [ACFG_PHYMODE_11NG_HT40MINUS]   = (char *)"11NGHT40MINUS" ,
        [ACFG_PHYMODE_11NG_HT40]   = (char *)"11NGHT40" ,
        [ACFG_PHYMODE_11NA_HT40]   = (char *)"11NAHT40" ,
        [ACFG_PHYMODE_11AC_VHT20]  = (char *)"11ACVHT20" ,
        [ACFG_PHYMODE_11AC_VHT40PLUS]  = (char *)"11ACVHT40PLUS" ,
        [ACFG_PHYMODE_11AC_VHT40MINUS]  = (char *)"11ACVHT40MINUS" ,
        [ACFG_PHYMODE_11AC_VHT40]  = (char *)"11ACVHT40" ,
        [ACFG_PHYMODE_11AC_VHT80]  = (char *)"11ACVHT80" ,
        [ACFG_PHYMODE_11AC_VHT160]  = (char *)"11ACVHT160" ,
        [ACFG_PHYMODE_11AC_VHT80_80]  = (char *)"11ACVHT80_80" ,
        [ACFG_PHYMODE_11AXA_HE20] = (char *) "11AHE20" ,
        [ACFG_PHYMODE_11AXG_HE20] = (char *) "11GHE20" ,
        [ACFG_PHYMODE_11AXA_HE40PLUS] = (char *) "11AHE40PLUS" ,
        [ACFG_PHYMODE_11AXA_HE40MINUS] = (char *) "11AHE40MINUS" ,
        [ACFG_PHYMODE_11AXG_HE40PLUS] = (char *) "11GHE40PLUS" ,
        [ACFG_PHYMODE_11AXG_HE40MINUS]   = (char *) "11GHE40MINUS" ,
        [ACFG_PHYMODE_11AXA_HE40] = (char *) "11AHE40" ,
        [ACFG_PHYMODE_11AXG_HE40] = (char *) "11GHE40" ,
        [ACFG_PHYMODE_11AXA_HE80] = (char *) "11AHE80" ,
        [ACFG_PHYMODE_11AXA_HE160] = (char *) "11AHE160" ,
        [ACFG_PHYMODE_11AXA_HE80_80] = (char *) "11AHE80_80" ,

        [ACFG_PHYMODE_INVALID]          = NULL ,
    };

    if (mode >= ACFG_PHYMODE_INVALID)
        return QDF_STATUS_E_FAILURE;
    strlcpy(mode_str, phymode_strings[mode], ACFG_MAX_PHYMODE_STRLEN);
    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_os_send_req(uint8_t *ifname, acfg_os_req_t  *req)
{
    int ret = QDF_STATUS_E_FAILURE;
    int value = 0;
    size_t len = 0;
    enum qca_nl80211_vendor_subcmds subcmd;
    enum qca_nl80211_vendor_subcmds_internal cmd;
    struct cfg80211_data cmd_data;

    memset(&cmd_data, 0, sizeof(struct cfg80211_data));

    if (g_acfg_standard && g_sock_ctx.cfg80211) {
        switch (req->cmd) {
            case ACFG_REQ_SET_RADIO_PARAM:
            case ACFG_REQ_SET_VAP_PARAM:
            {
                 acfg_param_req_t *ptr = (acfg_param_req_t *)req->data;

                 subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                 cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
                 value = ptr->param;

                 if ((value == ACFG_PARAM_AUTHMODE) || (value == ACFG_PARAM_DROPUNENCRYPTED)) {
                     acfg_log_errstr("%s: param:%d deprecated\n", __FUNCTION__, value);
                     return QDF_STATUS_SUCCESS;
                 }

                 len = sizeof(ptr->val);
                 cmd_data.length = sizeof(ptr->val);
                 cmd_data.data = &(ptr->val);
            }
            break;
            case ACFG_REQ_GET_RADIO_PARAM:
            case ACFG_REQ_GET_VAP_PARAM:
            {
                 acfg_param_req_t *ptr = (acfg_param_req_t *)req->data;

                 subcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
                 cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
                 value = ptr->param;
                 len = sizeof(ptr->val);
                 cmd_data.length = sizeof(ptr->val);
                 cmd_data.data = &(ptr->val);
            }
            break;
            case ACFG_REQ_SET_SSID:
            {
                 acfg_ssid_t *ptr = (acfg_ssid_t *)req->data;

                 subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                 cmd = QCA_NL80211_VENDORSUBCMD_SSID_CONFIG;
                 len = ptr->len;
                 cmd_data.length = ptr->len;
                 cmd_data.data = ptr->ssid;
            }
            break;
            case ACFG_REQ_SET_CHANNEL:
            {
                 acfg_chan_t *ptr = (acfg_chan_t *)req->data;
                 uint32_t chan_num = *ptr;
                 uint32_t chan_band;

                 ptr++;
                 chan_band = *ptr;
                 subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                 cmd = QCA_NL80211_VENDORSUBCMD_CHANNEL_CONFIG;
                 value = chan_num;
                 len = chan_band;  //Driver expects band info in len filed
            }
            break;
            case ACFG_REQ_GET_CHANNEL:
            {
                 subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                 cmd = QCA_NL80211_VENDORSUBCMD_GET_CHANNEL;
                 cmd_data.data = req->data;
                 cmd_data.length = 2; //1byte for chan_num, 1byte for band.
                 len = 2;
            }
            break;
            case ACFG_REQ_ACL_ADDMAC:
            {
                acfg_macaddr_t *ptr = (acfg_macaddr_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDORSUBCMD_ADDMAC;
                len = ACFG_MACADDR_LEN;
                cmd_data.length = ACFG_MACADDR_LEN;
                cmd_data.data = ptr->addr;
            }
            break;
            case ACFG_REQ_ACL_DELMAC:
            {
                acfg_macaddr_t *ptr = (acfg_macaddr_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDORSUBCMD_DELMAC;
                len = ACFG_MACADDR_LEN;
                cmd_data.length = ACFG_MACADDR_LEN;
                cmd_data.data = ptr->addr;
            }
            break;
            case ACFG_REQ_ACL_ADDMAC_SEC:
            {
                acfg_macaddr_t *ptr = (acfg_macaddr_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDORSUBCMD_ADDMAC_SEC;
                len = ACFG_MACADDR_LEN;
                cmd_data.length = ACFG_MACADDR_LEN;
                cmd_data.data = ptr->addr;
            }
            break;
            case ACFG_REQ_ACL_DELMAC_SEC:
            {
                acfg_macaddr_t *ptr = (acfg_macaddr_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDORSUBCMD_DELMAC_SEC;
                len = ACFG_MACADDR_LEN;
                cmd_data.length = ACFG_MACADDR_LEN;
                cmd_data.data = ptr->addr;
            }
            break;
            case ACFG_REQ_SET_HW_ADDR:
            {
                acfg_macaddr_t *ptr = (acfg_macaddr_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDORSUBCMD_HWADDR_CONFIG;
                len = ACFG_MACADDR_LEN;
                cmd_data.length = ACFG_MACADDR_LEN;
                cmd_data.data = ptr->addr;
            }
            break;
            case ACFG_REQ_SET_ATF_ADDSSID:
            {
                acfg_atf_ssid_val_t *ptr = (acfg_atf_ssid_val_t *)req->data;

                ptr->id_type = IEEE80211_IOCTL_ATF_ADDSSID;
                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDOR_SUBCMD_ATF;
                len = sizeof(acfg_atf_ssid_val_t);
                cmd_data.length = sizeof(acfg_atf_ssid_val_t);
                cmd_data.data = ptr;
            }
            break;
            case ACFG_REQ_SET_ATF_DELSSID:
            {
                acfg_atf_ssid_val_t *ptr = (acfg_atf_ssid_val_t *)req->data;

                ptr->id_type = IEEE80211_IOCTL_ATF_DELSSID;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDOR_SUBCMD_ATF;
                len = sizeof(acfg_atf_ssid_val_t);
                cmd_data.length = sizeof(acfg_atf_ssid_val_t);
                cmd_data.data = ptr;
	    }
            break;
            case ACFG_REQ_SET_ATF_ADDSTA:
            {
                acfg_atf_sta_val_t *ptr = (acfg_atf_sta_val_t *)req->data;

                ptr->id_type = IEEE80211_IOCTL_ATF_ADDSTA;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDOR_SUBCMD_ATF;
                len = sizeof(acfg_atf_sta_val_t);
                cmd_data.length = sizeof(acfg_atf_sta_val_t);
                cmd_data.data = ptr;
            }
            break;
            case ACFG_REQ_SET_ATF_DELSTA:
            {
                acfg_atf_sta_val_t *ptr = (acfg_atf_sta_val_t *)req->data;

                ptr->id_type = IEEE80211_IOCTL_ATF_DELSTA;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDOR_SUBCMD_ATF;
                len = sizeof(acfg_atf_sta_val_t);
                cmd_data.length = sizeof(acfg_atf_sta_val_t);
                cmd_data.data = ptr;
            }
            break;
            case ACFG_REQ_SET_AP:
            {
                acfg_macaddr_t *ptr = (acfg_macaddr_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDOR_SUBCMD_SET_AP;
                len = ACFG_MACADDR_LEN;
                cmd_data.length = ACFG_MACADDR_LEN;
                cmd_data.data = ptr->addr;
            }
            break;
            case ACFG_REQ_GET_AP:
            {
                acfg_macaddr_t *ptr = (acfg_macaddr_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDORSUBCMD_BSSID;
                len = ACFG_MACADDR_LEN;
                cmd_data.length = ACFG_MACADDR_LEN;
                cmd_data.data = ptr->addr;
            }
            break;
            case ACFG_REQ_SET_VAP_VENDOR_PARAM:
            {
                acfg_vendor_param_req_t *ptr = (acfg_vendor_param_req_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDOR_SUBCMD_VAP_VENDOR_PARAM;
                len = sizeof(*ptr);
                cmd_data.length = sizeof(*ptr);
                cmd_data.data = ptr;
            }
            break;
            case ACFG_REQ_GET_ASSOC_STA_INFO:
            {
                acfg_sta_info_req_t *ptr = (acfg_sta_info_req_t *)req->data;

                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDOR_SUBCMD_LIST_STA;
                len = sizeof(*ptr);
                cmd_data.length = sizeof(*ptr);
                cmd_data.data = ptr;
                cmd_data.flags = NO_CHUNKS_COPY;
            }
            break;
            case ACFG_REQ_SET_TXPOW:
            {
                 acfg_txpow_t *txpow = (acfg_txpow_t *)req->data;

                 subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                 cmd = QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS;
                 value = ACFG_PARAM_TXPOW;
                 len = *txpow;
                 cmd_data.length = sizeof(uint32_t);
                 cmd_data.data = ++txpow;
            }
            break;
            case ACFG_REQ_SET_PHYMODE:
            {
                acfg_phymode_t *ptr = (acfg_phymode_t *)req->data;
                char mode_str[ACFG_MAX_PHYMODE_STRLEN];
                if (QDF_STATUS_E_FAILURE == acfg_convert_mode_to_str(*ptr, mode_str)) {
                    acfg_log_errstr("%s: invalid phymode %d\n",
                                  __FUNCTION__, *ptr);
                  return QDF_STATUS_E_FAILURE;
                }
                subcmd = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
                cmd = QCA_NL80211_VENDORSUBCMD_WIRELESS_MODE;
                len = strlen(mode_str);
                cmd_data.length = strlen(mode_str);
                cmd_data.data = mode_str;
            }
            break;
            case ACFG_REQ_SET_ENCODE:
            {
                acfg_log_errstr("%s: cmd:%d deprecated\n", __FUNCTION__, req->cmd);
                return QDF_STATUS_SUCCESS;
            }
            default:
                  acfg_log_errstr("%s: cmd:%d not available\n",
                                  __FUNCTION__, req->cmd);
                  return QDF_STATUS_E_FAILURE;
        }
        ret = wifi_cfg80211_user_send_generic_command(&(g_sock_ctx.cfg80211_ctxt),
                                                      subcmd, cmd, value,
                                                      (const char *)ifname,
                                                      (char *)&cmd_data, len);
    } else {
        ret = send_command(&g_sock_ctx, (const char *)ifname, req,
                           sizeof(acfg_os_req_t), NULL,
                           QCA_NL80211_VENDOR_SUBCMD_ACFG,
                           LINUX_PVT_WIOCTL);
    }

    if (ret < 0) {
        acfg_log_errstr("%s failed, ret=%d!\n",__FUNCTION__,ret);
        return QDF_STATUS_E_FAILURE;
    } else {
        return QDF_STATUS_SUCCESS;
    }
}

/**
 * @brief  Initialize interface for device-less configurations
 *
 * @return
 */
uint32_t acfg_dl_init()
{

    uint32_t ret_status = QDF_STATUS_E_FAILURE;

    ret_status = appbr_if_open_dl_conn(APPBR_ACFG);
    if(ret_status != QDF_STATUS_SUCCESS)
        goto out;

    ret_status = appbr_if_open_ul_conn(APPBR_ACFG);
    if(ret_status != QDF_STATUS_SUCCESS)
        goto out;

out:
    return  ret_status;
}

/**
 * @brief Check whether string crossed max limit
 *
 * @param src
 * @param maxlen
 *
 * @return
 */
uint32_t
acfg_os_check_str(uint8_t *src, uint32_t maxlen)
{
    return(strnlen((const char *)src, maxlen) >= maxlen);
}

/**
 * @brief Compare two strings
 *
 * @param str1
 * @param str2
 * @param maxlen
 *
 * @return 0 if strings are same.
 *         Non zero otherwise.
 */
uint32_t
acfg_os_cmp_str(uint8_t *str1, uint8_t *str2, uint32_t maxlen)
{
    return(strncmp((const char *)str1, (const char *)str2, maxlen));
}


/**
 * @brief Copy the dst string into the src
 *
 * @param src (the source string)
 * @param dst (destination string)
 * @param maxlen (the maximum length of dest buf)
 *
 * @note It's assumed that the destination string is
 *       zero'ed
 */
uint32_t
acfg_os_strcpy(char  *dst, const char *src, uint32_t  maxlen)
{
    uint32_t  len;
    len = strlcpy(dst, src, maxlen);
    if(len >= maxlen) {
        g_str_truncated = 1;
        acfg_log_errstr("%s: String truncated\n", __func__);
    }
    return len;
}

/**
 * @brief Concatenate the dst and src strings.
 *
 * @param src (the source string)
 * @param dst (destination string)
 * @param maxlen (the maximum length of dest buf)
 *
 */
uint32_t
acfg_os_strlcat(char  *dst, const char *src, uint32_t  maxlen)
{
    uint32_t  len;
    len = strlcat(dst, src, maxlen);
    if(len >= maxlen){
        g_str_truncated = 1;
        acfg_log_errstr("%s: String truncated\n", __func__);
    }
    return len;
}

/**
 * @brief write the formated character string to str buffer.
 *
 * @param str (the buffer to place result into)
 * @param size (The size of the buffer, including 
 *              the trailing null space)
 * @param fmt (The format string to use)
 * @args (Arguments for the format string)
 *
 */
uint32_t
acfg_os_snprintf(char  *str, uint32_t size, const char *fmt, ...)
{
    va_list args;
    uint32_t  len;
    va_start(args, fmt);
    len = vsnprintf(str, size, fmt, args);
    va_end(args);
    if(len >= size){
        g_str_truncated = 1;
        acfg_log_errstr("%s: String truncated\n", __func__);
    }
    return len;
}

uint32_t
acfg_set_chainmask(uint8_t *radio_name, enum acfg_chainmask_type type, uint16_t mask)
{
    uint32_t   status = QDF_STATUS_SUCCESS;

    switch (type) {
    case ACFG_TX_CHAINMASK:
        status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_TXCHAINMASK, mask);
        break;
    case ACFG_RX_CHAINMASK:
        status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_RXCHAINMASK, mask);
        break;
    default:
        break;
    }

    return status;
}

/*
 *  Public API's
 */


/**
 * @brief Create VAP
 *
 * @param wifi_name
 * @param vap_name
 * @param mode
 *
 * @return
 */
uint32_t
acfg_create_vap(uint8_t             *wifi_name,
        uint8_t             *vap_name,
        acfg_opmode_t          mode,
        int32_t              vapid,
        uint32_t             flags)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    struct ieee80211_clone_params cp;

    int msg=0;
    struct cfg80211_data buffer;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_CREATE_VAP};
    acfg_vapinfo_t    *ptr;
    ptr     = (acfg_vapinfo_t *)req.data;
    struct nlwrapper_data wdata = {0};

    if (acfg_os_check_str(wifi_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;
    if (!g_sock_ctx.cfg80211) {
        acfg_os_strcpy((char *)ptr->icp_name, (char *)vap_name, ACFG_MAX_IFNAME);

        ptr->icp_opmode    = mode;
        ptr->icp_flags     = flags;
        ptr->icp_vapid     = vapid;

        status = acfg_os_send_req(wifi_name, &req);
        return status;
    } else {
        memset(&cp, 0, sizeof(cp));
        acfg_os_strcpy((char *)cp.icp_name, (char *)vap_name, ACFG_MAX_IFNAME);
        cp.icp_name[IFNAMSIZ - 1] = '\0';
        cp.icp_opmode = mode;
        cp.icp_flags = flags;
        cp.icp_vapid = vapid;

        buffer.data = (char *)&cp;
        buffer.length = sizeof(cp);
        buffer.callback = NULL;
        msg = wifi_cfg80211_send_generic_command(&(g_sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_CLONEPARAMS, (char *)wifi_name, (char *)&buffer, buffer.length);
        if (msg < 0) {
            printf("Couldn't send NL command\n");
            return msg;
        }

        if (mode == ACFG_OPMODE_HOSTAP) {
            wdata.value = NL80211_IFTYPE_AP;
        } else if (mode == ACFG_OPMODE_STA) {
            wdata.value = NL80211_IFTYPE_STATION;
        }

        wdata.cmd = NL80211_CMD_NEW_INTERFACE;

        msg = wifi_cfg80211_send_nl80211_standard_command(&(g_sock_ctx.cfg80211_ctxt), wifi_name,
                vap_name, (char *)&wdata);
        if (msg != 0) {
            printf("Couldn't send standard NL command - vap create\n");
            return msg;
        }

        memset(&wdata, 0, sizeof(wdata));

        if (mode == ACFG_OPMODE_STA) {
            wdata.value |= NL80211_ATTR_4ADDR;

            wdata.cmd = NL80211_CMD_SET_INTERFACE;

            msg = wifi_cfg80211_send_nl80211_standard_command(&(g_sock_ctx.cfg80211_ctxt), wifi_name,
                    vap_name, (char *)&wdata);
            if (msg != 0) {
                printf("Couldn't send standard NL command - set vap param\n");
                return msg;
            }
        }
    }
    return QDF_STATUS_SUCCESS;
}


/**
 * @brief Delete VAP
 *
 * @param wifi_name
 * @param vap_name
 *
 * @return
 */
uint32_t
acfg_delete_vap(uint8_t *wifi_name,
        uint8_t *vap_name)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_DELETE_VAP};
    acfg_vapinfo_t    *ptr;
    int msg=0;
    struct nlwrapper_data wdata = {0};

    if (acfg_os_check_str(wifi_name, ACFG_MAX_IFNAME)
            || acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    ptr     = (acfg_vapinfo_t *)req.data;

    if (!g_sock_ctx.cfg80211) {
        acfg_os_strcpy((char *)ptr->icp_name, (char *)vap_name, ACFG_MAX_IFNAME);

        status = acfg_os_send_req(vap_name, &req);

        return status ;
    } else {
        wdata.cmd = NL80211_CMD_DEL_INTERFACE;

        msg = wifi_cfg80211_send_nl80211_standard_command(&(g_sock_ctx.cfg80211_ctxt), wifi_name,
                vap_name, (char *)&wdata);
        if (msg != 0) {
            printf("Couldn't send standard NL command - vap delete\n");
            return msg;
        }
        return QDF_STATUS_SUCCESS;
    }
}

/**
 * @brief Set the SSID
 *
 * @param vap_name
 * @param ssid
 *
 * @return
 */
uint32_t
acfg_set_ssid(uint8_t     *vap_name, acfg_ssid_t  *ssid)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_SSID};
    acfg_ssid_t        *ptr;

    ptr     = (acfg_ssid_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    ptr->len = acfg_os_strcpy((char *)ptr->ssid, (char *)ssid->ssid, ACFG_MAX_SSID_LEN + 1);

    status = acfg_os_send_req(vap_name, &req);
    return status;
}

/**
 * @brief Set the channel numbers
 *
 * @param wifi_name (Radio interface)
 * @param chan_num (IEEE Channel number)
 * @param chan_band (Channel band)
 *
 * @return
 */
uint32_t
acfg_set_channel(uint8_t  *wifi_name, uint8_t  chan_num, uint8_t chan_band)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_CHANNEL};
    acfg_chan_t        *ptr;

    ptr = (acfg_chan_t *)req.data;

    if (acfg_os_check_str(wifi_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    *ptr = chan_num;
    ptr++;
    *ptr = chan_band; /* set channel band */

    status = acfg_os_send_req(wifi_name, &req);

    return status;

}

/**
 * @brief Set the opmode
 *
 * @param vap_name (VAP interface)
 * @param opmode
 *
 * @return
 */
uint32_t
acfg_set_opmode(uint8_t *vap_name, acfg_opmode_t opmode)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_opmode_t * p_opmode = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_OPMODE};

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    p_opmode = (acfg_opmode_t *)req.data;
    *p_opmode = opmode;

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

acfg_opmode_t
acfg_convert_opmode(uint32_t opmode)
{
    switch(opmode) {
        case IW_MODE_ADHOC:
            return ACFG_OPMODE_IBSS;
            break;
        case IW_MODE_INFRA:
            return ACFG_OPMODE_STA;
            break;
        case IW_MODE_MASTER:
            return ACFG_OPMODE_HOSTAP;
            break;
        case IW_MODE_REPEAT:
            return ACFG_OPMODE_WDS;
            break;
        case IW_MODE_MONITOR:
            return ACFG_OPMODE_MONITOR;
            break;
        default:
            return -1;
            break;
    }
}

/**
 * @brief Get Vap param
 *
 * @param vap_name
 * @param param
 * @param val
 *
 * @return
 */
uint32_t
acfg_get_vap_param(uint8_t *vap_name, \
        acfg_param_vap_t param, uint32_t *val)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_VAP_PARAM};
    acfg_param_req_t *ptr;

    ptr = (acfg_param_req_t *)req.data;
    ptr->param = param ;

    status = acfg_os_send_req(vap_name, &req);

    *val = ptr->val ;

    return status ;
}


/**
 * @brief Get the opmode
 *
 * @param vap_name (VAP interface)
 * @param opmode
 *
 * @return
 */
uint32_t
acfg_get_opmode(uint8_t *vap_name, acfg_opmode_t *opmode)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_OPMODE};

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    if (g_acfg_standard && g_sock_ctx.cfg80211) {
        status = acfg_get_vap_param(vap_name, ACFG_PARAM_GET_OPMODE, (uint32_t *)opmode);
    }
    else {
        status = acfg_os_send_req(vap_name, &req);

        if(status == QDF_STATUS_SUCCESS)
        {
            *opmode = acfg_convert_opmode(*(req.data));
            if(*opmode == (acfg_opmode_t)-1) {
                acfg_log_errstr("%s: Failed to convert opmode (vap=%s, opmode=%d)\n",
                        __func__,
                        vap_name,
                        (acfg_opmode_t)req.data);
                status = QDF_STATUS_E_FAILURE;
            }
        }
    }

    return status ;
}

/**
 * @brief Set RTS threshold
 *
 * @param vap_name
 * @param rts value
 * @param rts flags
 * @return
 */
uint32_t
acfg_set_rts(uint8_t *vap_name, acfg_rts_t *rts)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_rts_t *   p_rts = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_RTS};
    struct nlwrapper_data wdata = {0};

    p_rts = (acfg_rts_t *)req.data;
    *p_rts = *rts;

    if (g_acfg_standard && g_sock_ctx.cfg80211) {
        wdata.cmd = NL80211_CMD_SET_WIPHY;
        wdata.attr = NL80211_ATTR_WIPHY_RTS_THRESHOLD;
        wdata.value = *rts;
        wdata.flags |= NL80211_ATTR_32BIT;
        status = wifi_cfg80211_send_nl80211_standard_command(&(g_sock_ctx.cfg80211_ctxt), NULL, vap_name, (char *)&wdata);
    } else
        status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief Set frag threshold
 *
 * @param vap_name
 * @param frag
 *
 * @return
 */
uint32_t
acfg_set_frag(uint8_t *vap_name, acfg_frag_t *frag)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_frag_t *  p_frag = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_FRAG};
    struct nlwrapper_data wdata = {0};

    p_frag = (acfg_frag_t *)req.data;
    *p_frag = *frag;

    if (g_acfg_standard && g_sock_ctx.cfg80211) {
        wdata.cmd = NL80211_CMD_SET_WIPHY;
        wdata.attr = NL80211_ATTR_WIPHY_FRAG_THRESHOLD;
        wdata.value = *frag;
        wdata.flags |= NL80211_ATTR_32BIT;
        status = wifi_cfg80211_send_nl80211_standard_command(&(g_sock_ctx.cfg80211_ctxt), NULL, vap_name, (char *)&wdata);
    } else
        status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief Set txpower
 *
 * @param vap_name
 * @param txpower
 * @param flags
 * @return
 */
uint32_t
acfg_set_txpow(uint8_t *vap_name, acfg_txpow_t *txpow, uint32_t fstype)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_txpow_t *p_txpow = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_TXPOW};

    p_txpow = (acfg_txpow_t *)req.data;
    *p_txpow = *txpow;

    if (g_acfg_standard && g_sock_ctx.cfg80211) {

       /* fill frame subtype after txpower*/
        *((uint32_t *)(++p_txpow)) = fstype;
	}
    status = acfg_os_send_req(vap_name, &req);

    return status ;
}

/**
 * @brief Get Access Point Mac Address
 *
 * @param vap_name
 * @param iwparam
 *
 * @return
 */
uint32_t
acfg_get_ap(uint8_t *vap_name, acfg_macaddr_t *mac)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_AP};
    acfg_macaddr_t *ptr;

    ptr = (acfg_macaddr_t *)req.data;

    status = acfg_os_send_req(vap_name, &req);

    acfg_os_strcpy((char *)mac->addr, (char *)ptr->addr , ACFG_MACADDR_LEN) ;

    return status ;
}


/**
 * @brief Set the encode
 *
 * @param wifi_name
 * @param enc - encode string
 *
 * @return
 */
uint32_t
acfg_set_enc(uint8_t *wifi_name, acfg_encode_flags_t flag, char *enc)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_ENCODE};
    acfg_encode_t      *ptr;
    const char *p;
    int dlen;
    unsigned char out[ACFG_ENCODING_TOKEN_MAX] = {0};
    unsigned char key[ACFG_ENCODING_TOKEN_MAX];
    int keylen = 0;

    ptr = (acfg_encode_t *)req.data;

    p = (const char *)enc;
    dlen = -1;

    if(!(flag & ACFG_ENCODE_DISABLED) && (enc != NULL)) {
        while(*p != '\0') {
            unsigned int temph;
            unsigned int templ;
            int count;
            if(dlen <= 0) {
                if(dlen == 0)
                    p++;
                dlen = strcspn(p, "-:;.,");
            }
            count = sscanf(p, "%1X%1X", &temph, &templ);
            if(count < 1)
                return -1;
            if(dlen % 2)
                count = 1;
            if(count == 2)
                templ |= temph << 4;
            else
                templ = temph;
            out[keylen++] = (unsigned char) (templ & 0xFF);

            if(keylen >= ACFG_ENCODING_TOKEN_MAX )
                break;

            p += count;
            dlen -= count;
        }

        memcpy(key, out, keylen);
        ptr->buff = key;
        ptr->len = keylen;
    }
    else {
        ptr->buff = NULL;
        ptr->len = 0;
    }
    ptr->flags = flag;

    if(ptr->buff == NULL)
        ptr->flags |= ACFG_ENCODE_NOKEY;

    status = acfg_os_send_req(wifi_name, &req);

    return status;
}


/**
 * @brief Set Vap param
 *
 * @param vap_name
 * @param param
 * @param val
 *
 * @return
 */
uint32_t
acfg_set_vap_param(uint8_t *vap_name, \
        acfg_param_vap_t param, uint32_t val)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_VAP_PARAM};
    acfg_param_req_t *ptr;
    ptr = (acfg_param_req_t *)req.data;

    ptr->param = param ;
    ptr->val = val ;

    status = acfg_os_send_req(vap_name, &req);

    return status ;
}

/**
 * @brief set Vap vendor param
 *
 * @param vap_name
 * @param param
 * @param data
 * @param len
 *
 * @return
 */
uint32_t
acfg_set_vap_vendor_param(uint8_t *vap_name, \
        acfg_vendor_param_vap_t param, uint8_t *data,
        uint32_t len, uint32_t type, acfg_vendor_param_init_flag_t reinit)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_VAP_VENDOR_PARAM};
    acfg_vendor_param_req_t *ptr;

    ptr = (acfg_vendor_param_req_t *)req.data;
    ptr->param = param ;
    ptr->type = type;

    if(len <= sizeof(acfg_vendor_param_data_t))
        memcpy(&ptr->data, data, len);
    else
    {
        acfg_log_errstr("Vendor param size greater than max allowed by ACFG!\n");
        return status;
    }

    status = acfg_os_send_req(vap_name, &req);

    if(reinit == RESTART_SECURITY && status == QDF_STATUS_SUCCESS)
    {
        acfg_opmode_t opmode;
        char cmd[15], replybuf[255];
        uint32_t len;

        memset(replybuf, 0, sizeof(replybuf));
        status = acfg_get_opmode(vap_name, &opmode);
        if(status != QDF_STATUS_SUCCESS){
            return status;
        }
        acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd,
                ctrl_wpasupp);
        if(opmode == ACFG_OPMODE_HOSTAP)
            acfg_os_strcpy(cmd, "RELOAD", sizeof(cmd));
        else
            acfg_os_strcpy(cmd, "RECONNECT", sizeof(cmd));
        /* reload the security */
        if((acfg_ctrl_req (vap_name,
                        cmd,
                        strlen(cmd),
                        replybuf, &len,
                        opmode) < 0) ||
                strncmp(replybuf, "OK", strlen("OK"))){
            acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                    cmd,
                    vap_name);
            return QDF_STATUS_E_FAILURE;
        }
    }

    return status ;
}




/**
 * @brief Set Radio param
 *
 * @param radio_name
 * @param param
 * @param val
 *
 * @return
 */
uint32_t
acfg_set_radio_param(uint8_t *radio_name, \
        acfg_param_radio_t param, uint32_t val)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_RADIO_PARAM};
    acfg_param_req_t *ptr;
    ptr = (acfg_param_req_t *)req.data;

    ptr->param = param ;
    ptr->val = val ;

    if(acfg_os_cmp_str(radio_name,(uint8_t *)"wifi",4)){
        acfg_log_errstr("Should use wifiX to set radio param.\n");
        return status ;
    }

    status = acfg_os_send_req(radio_name, &req);

    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: failed (param=0x%x status=%d)\n", __func__, param, status);
    }
    return status ;
}

static int legacy_rate_to_index(unsigned int *rate)
{
    int i;
    /* convert rate to index */
    const unsigned int legacy_rate_idx[][2] = { {1000, 0x1b}, {2000, 0x1a},
                                                {5500, 0x19}, {6000, 0xb},
                                                {9000, 0xf},  {11000, 0x18},
                                                {12000, 0xa}, {18000, 0xe},
                                                {24000, 0x9}, {36000, 0xd},
                                                {48000, 0x8}, {54000, 0xc},
                                              };
    int array_size = sizeof(legacy_rate_idx)/sizeof(legacy_rate_idx[0]);
    *rate /= 1000;
    for (i = 0; i < array_size; i++) {
        if (*rate == legacy_rate_idx[i][0]) {
            *rate = legacy_rate_idx[i][1];
            break;
        }
    }

    if (i == array_size)
        return -EINVAL;
    else
        return 0;
}

/**
 * @Set bit rate
 *
 * @param vap_name
 * @param rate val
 * @param rate fixed
 * @return
 */
uint32_t
acfg_set_rate(uint8_t *vap_name, acfg_rate_t *rate)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_rate_t *  p_rate = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_RATE};

    p_rate = (acfg_rate_t *)req.data;
    *p_rate = *rate;

    if (g_acfg_standard && g_sock_ctx.cfg80211) {
        int value, retv;

        if (*rate) {
            unsigned int rval = *rate;

            if (rval >= 1000) {
                retv = legacy_rate_to_index(&rval);
                if (retv)
                    return -EINVAL;
            }

            value = rval;
        } else {
            value = IEEE80211_FIXED_RATE_NONE;
        }

        retv = acfg_set_vap_param(vap_name, ACFG_PARAM_11N_RATE, value);

        if (!retv) {
            if (value != IEEE80211_FIXED_RATE_NONE) {
             /* set default retries when setting fixed rate */
                retv = acfg_set_vap_param(vap_name, ACFG_PARAM_11N_RETRIES, 4);
            } else {
                retv = acfg_set_vap_param(vap_name, ACFG_PARAM_11N_RETRIES, 0);
            }
        }
        status = retv;

    } else
        status = acfg_os_send_req(vap_name, &req);

    return status ;
}

/**
 * @brief Set the phymode
 *
 * @param vap_name
 * @param mode
 *
 * @return
 */
uint32_t
acfg_set_phymode(uint8_t *vap_name, acfg_phymode_t mode)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t req = {.cmd = ACFG_REQ_SET_PHYMODE};
    acfg_phymode_t *ptr;

    ptr = (acfg_phymode_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    *ptr = mode ;
    status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief acl addmac
 *
 * @param vap name
 * @param mac addr
 *
 *
 * @return
 */
uint32_t
acfg_acl_addmac(uint8_t *vap_name, uint8_t *addr)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_ACL_ADDMAC};
    acfg_macaddr_t *mac;
    struct sockaddr sa;

    //acfg_str_to_ether(addr, &sa);
    memcpy(sa.sa_data, addr, ACFG_MACADDR_LEN);

    mac = (acfg_macaddr_t *)req.data;

    memcpy(mac->addr, sa.sa_data, ACFG_MACADDR_LEN);

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief acl delmac
 *
 * @param vap_name
 * @param macaddr
 * @
 *
 * @return
 */
uint32_t
acfg_acl_delmac(uint8_t *vap_name, uint8_t *addr)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_ACL_DELMAC};
    acfg_macaddr_t *mac;
    struct sockaddr sa;

    memcpy(sa.sa_data, addr, ACFG_MACADDR_LEN);
    mac = (acfg_macaddr_t *)req.data;
    memcpy(mac->addr, sa.sa_data, ACFG_MACADDR_LEN);

    status = acfg_os_send_req(vap_name, &req);

    return status;

}

/* Secondary ACL list implementation */
/**
 * @brief acl addmac_secondary
 *
 * @param vap name
 * @param mac addr
 *
 *
 * @return
 */
uint32_t
acfg_acl_addmac_secondary(uint8_t *vap_name, uint8_t *addr)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_ACL_ADDMAC_SEC};
    acfg_macaddr_t *mac;
    struct sockaddr sa;

    memcpy(sa.sa_data, addr, ACFG_MACADDR_LEN);

    mac = (acfg_macaddr_t *)req.data;

    memcpy(mac->addr, sa.sa_data, ACFG_MACADDR_LEN);

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief acl delmac_secondary
 *
 * @param vap_name
 * @param macaddr
 *
 * @return
 */
uint32_t
acfg_acl_delmac_secondary(uint8_t *vap_name, uint8_t *addr)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_ACL_DELMAC_SEC};
    acfg_macaddr_t *mac;
    struct sockaddr sa;

    memcpy(sa.sa_data, addr, ACFG_MACADDR_LEN);
    mac = (acfg_macaddr_t *)req.data;
    memcpy(mac->addr, sa.sa_data, ACFG_MACADDR_LEN);

    status = acfg_os_send_req(vap_name, &req);

    return status;

}

uint32_t
acfg_set_ap(uint8_t *vap_name, uint8_t *addr)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_AP};
    acfg_macaddr_t *mac;
    struct sockaddr sa;

    memcpy(sa.sa_data, addr, ACFG_MACADDR_LEN);

    mac = (acfg_macaddr_t *)req.data;

    memcpy(mac->addr, sa.sa_data, ACFG_MACADDR_LEN);

    status = acfg_os_send_req(vap_name, &req);

    return status;
}


uint32_t
acfg_wlan_iface_present(char *ifname)
{
    struct ifreq ifr;
    int s;
    uint32_t   status = QDF_STATUS_SUCCESS;

    memset(&ifr, 0, sizeof(struct ifreq));
    acfg_os_strcpy(ifr.ifr_name, (char *)ifname, ACFG_MAX_IFNAME);

    ifr.ifr_data = (__caddr_t)NULL;

    s = socket(AF_INET, SOCK_DGRAM, 0);

    if(s < 0) {
        status = QDF_STATUS_E_BUSY;
        acfg_log_errstr("Unable to open the socket\n");
        goto fail;
    }

    if (ioctl (s, SIOCGIFFLAGS, &ifr) < 0) {
        acfg_log_errstr("Interface %s Not Present\n", ifname);
        status = acfg_get_err_status();
        //acfg_log_errstr("%s: IOCTL failed (status=%d)\n", __func__, status);
    }

    close(s);

fail:
    return status;
}

static int
acfg_str_to_ether(char *bufp, struct sockaddr *sap)
{
#define ETH_ALEN    6
    unsigned char *ptr;
    int i, j;
    unsigned char val;
    unsigned char c;

    ptr = (unsigned char *) sap->sa_data;

    i = 0;

    do {
        j = val = 0;

        /* We might get a semicolon here - not required. */
        if (i && (*bufp == ':')) {
            bufp++;
        }

        do {
            c = *bufp;
            if (((unsigned char)(c - '0')) <= 9) {
                c -= '0';
            } else if (((unsigned char)((c|0x20) - 'a')) <= 5) {
                c = (c|0x20) - ('a'-10);
            } else if (j && (c == ':' || c == 0)) {
                break;
            } else {
                return -1;
            }
            ++bufp;
            val <<= 4;
            val += c;
        } while (++j < 2);
        *ptr++ = val;
    } while (++i < ETH_ALEN);
    return (int) (*bufp);   /* Error if we don't end at end of string. */
#undef ETH_ALEN
}

void
acfg_mac_str_to_octet(uint8_t *mac_str, uint8_t *mac)
{
    char val[3], *str, *str1;
    int i = 0;
    if((str1 = strtok((char *)mac_str, ":")) != NULL){
        acfg_os_strcpy(val, str1, sizeof(val));
	mac[i] = (uint8_t)strtol(val, NULL, 16);
	i++;
	while (((str = strtok(0, ":")) != NULL) && (i < ACFG_MACADDR_LEN)) {
	   acfg_os_strcpy(val, str, sizeof(val));
	    mac[i] = (uint8_t)strtol(val, NULL, 16);
	    i++;
        }
    }
}


uint32_t
acfg_set_ifmac (char *ifname, char *buf, int arphdr)
{
    struct sockaddr sa;
    uint32_t   status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_HW_ADDR};
    acfg_macaddr_t  *ptr = NULL;
    u_int8_t *wifi_name = (u_int8_t *) ifname;

    if(!ifname) {
        return status;
    }

    if (acfg_str_to_ether(buf, &sa) == 0) {
        sa.sa_family = arphdr;
        ptr = (acfg_macaddr_t *)req.data;

        if (acfg_os_check_str(wifi_name, ACFG_MAX_IFNAME))
            return QDF_STATUS_E_NOENT;

        memcpy(&ptr->addr, &sa.sa_data, ACFG_MACADDR_LEN);
        status = acfg_os_send_req(wifi_name, &req);
    }

    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: IOCTL failed (status=%d)\n", __func__, status);
    }

    return status;
}

static uint32_t
acfg_wlan_app_iface_up(acfg_wlan_profile_vap_params_t *vap_params)
{
    char cmd[512];
    char reply[255];
    uint32_t len = sizeof (reply);

    if (vap_params == NULL) {
        return QDF_STATUS_E_FAILURE;
    }

    memset(reply, 0, sizeof(reply));
        /* Enable the network at hostapd or supplicant level first */
        if (vap_params->opmode == ACFG_OPMODE_STA) {
            /* For supplicant */
            memset(cmd, '\0', sizeof (cmd));
            acfg_os_snprintf(cmd, sizeof(cmd), "%s %d", WPA_ENABLE_NETWORK_CMD_PREFIX, 0);
            if((acfg_ctrl_req(vap_params->vap_name, cmd, strlen(cmd), reply,
                              &len, ACFG_OPMODE_STA) < 0) ||
                              strncmp (reply, "OK", strlen("OK"))){
                acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                                cmd, vap_params->vap_name);
                return QDF_STATUS_E_FAILURE;
            }
        } else {
            /* For hostapd */
            memset(cmd, '\0', sizeof (cmd));
            acfg_os_snprintf(cmd, sizeof(cmd), "%s", "STATUS");
            if(acfg_ctrl_req (vap_params->vap_name, cmd, strlen(cmd), reply, &len,
                              vap_params->opmode) < 0) {
                acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                                cmd, vap_params->vap_name);
                return QDF_STATUS_E_FAILURE;
            }
            if(!strncmp (reply, "state=ENABLED", strlen("state=ENABLED"))){
                /* Already Enabled, nothing to do */
                return QDF_STATUS_SUCCESS;
            } else {
                memset(cmd, '\0', sizeof (cmd));
                acfg_os_snprintf(cmd, sizeof(cmd), "%s", "ENABLE");
                if((acfg_ctrl_req (vap_params->vap_name, cmd, strlen(cmd), reply,
                                   &len, vap_params->opmode) < 0) ||
                                   strncmp (reply, "OK", strlen("OK"))){
                    acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                                    cmd, vap_params->vap_name);
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }

    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_wlan_iface_up(uint8_t  *ifname, acfg_wlan_profile_vap_params_t *vap_params)
{
    struct ifreq ifr;
    int s;
    uint32_t   status = QDF_STATUS_SUCCESS;

    /* Check if hostapd/supplicant iface needs to be brought up */
    if (vap_params != NULL) {
        if (acfg_wlan_app_iface_up(vap_params) != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }

        if ((vap_params->opmode == ACFG_OPMODE_HOSTAP)) {
            /* Hostapd also brings up the VAP, so return here */
            return QDF_STATUS_SUCCESS;
        }
    }
    memset(&ifr, 0, sizeof(struct ifreq));

    if(!ifname)
        return QDF_STATUS_E_FAILURE;

    acfg_os_strcpy(ifr.ifr_name, (char *)ifname, ACFG_MAX_IFNAME);

    ifr.ifr_data = (__caddr_t)NULL;
    ifr.ifr_flags = (IFF_UP | IFF_RUNNING);

    s = socket(AF_INET, SOCK_DGRAM, 0);

    if(s < 0) {
        status = QDF_STATUS_E_BUSY;
        goto fail;
    }

    if (ioctl (s, SIOCSIFFLAGS, &ifr) < 0) {
        status = acfg_get_err_status();
        acfg_log_errstr("%s: IOCTL failed (status=%d)\n", __func__, status);
    }

    close(s);

fail:
    return status;
}

uint32_t
acfg_wlan_app_iface_down(acfg_wlan_profile_vap_params_t *vap_params)
{
    char cmd[512];
    char reply[255];
    uint32_t len = sizeof (reply);
    uint32_t   status = QDF_STATUS_SUCCESS;

    if (vap_params == NULL) {
        return QDF_STATUS_E_FAILURE;
    }

    memset(reply, 0, sizeof(reply));
        /* Disable the network at hostapd or supplicant level first */
        if (vap_params->opmode == ACFG_OPMODE_STA) {
            /* For supplicant */
            memset(cmd, '\0', sizeof (cmd));
            acfg_os_snprintf(cmd, sizeof(cmd), "%s", "STATUS");
            status = acfg_ctrl_req (vap_params->vap_name, cmd, strlen(cmd), reply,
                                    &len, vap_params->opmode);
            if((status > 0)) {
                /* No iface at supplicant */
                return QDF_STATUS_SUCCESS;
            } else {
                memset(cmd, '\0', sizeof (cmd));
                acfg_os_snprintf(cmd, sizeof(cmd), "%s %d", WPA_DISABLE_NETWORK_CMD_PREFIX, 0);
                if((acfg_ctrl_req(vap_params->vap_name, cmd, strlen(cmd), reply,
                                  &len, ACFG_OPMODE_STA) < 0) ||
                                  strncmp (reply, "OK", strlen("OK"))){
                    acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                                    cmd, vap_params->vap_name);
                    return QDF_STATUS_E_FAILURE;
                }
            }
        } else {
            /* For hostapd */
            memset(cmd, '\0', sizeof (cmd));
            acfg_os_snprintf(cmd, sizeof(cmd), "%s", "STATUS");
            status = acfg_ctrl_req (vap_params->vap_name, cmd, strlen(cmd), reply,
                                    &len, vap_params->opmode);
            if((status > 0) ||
               !strncmp (reply, "state=DISABLED", strlen("state=DISABLED")) ||
               !strncmp (reply, "state=UNINITIALIZED", strlen("state=UNINITIALIZED"))){
                /* No iface at hostapd or Already Disabled or un-initialized,
                 * nothing to do */
                return QDF_STATUS_SUCCESS;
            } else {
                memset(cmd, '\0', sizeof (cmd));
                acfg_os_snprintf(cmd, sizeof(cmd), "%s", "DISABLE");
                if((acfg_ctrl_req (vap_params->vap_name, cmd, strlen(cmd), reply,
                                   &len, vap_params->opmode) < 0) ||
                                   strncmp (reply, "OK", strlen("OK"))){
                    acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                                    cmd, vap_params->vap_name);
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }

    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_wlan_iface_down(uint8_t *ifname, acfg_wlan_profile_vap_params_t *vap_params)
{
    struct ifreq ifr;
    int s;
    uint32_t   status = QDF_STATUS_SUCCESS;

    /* Check if hostapd/supplicant iface needs to be brought down */
    if (vap_params != NULL) {
        if (acfg_wlan_app_iface_down(vap_params) != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
        if (vap_params->opmode == ACFG_OPMODE_HOSTAP) {
            /* Hostapd also brings down the VAP, so return here */
            return QDF_STATUS_SUCCESS;
        }
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    if(!ifname)
        return -QDF_STATUS_E_FAILURE;

    acfg_os_strcpy(ifr.ifr_name, (char *)ifname, ACFG_MAX_IFNAME);
    ifr.ifr_data = (__caddr_t)NULL;
    ifr.ifr_flags = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);

    if(s < 0) {
        status = QDF_STATUS_E_BUSY;
        goto fail;
    }

    if (ioctl (s, SIOCSIFFLAGS, &ifr) < 0) {
        status = acfg_get_err_status();
        acfg_log_errstr("%s: IOCTL failed (status=%d)\n", __func__, status);
    }

    close(s);

fail:
    return status;
}

uint32_t
acfg_set_acl_policy(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_vap_params_t *cur_vap_params)
{
    acfg_wlan_profile_node_params_t node_params, cur_node_params;
    uint32_t status = QDF_STATUS_SUCCESS;

    node_params = vap_params->node_params;
    if (cur_vap_params != NULL) {
        cur_node_params = cur_vap_params->node_params;
        if (node_params.node_acl != cur_node_params.node_acl) {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_MACCMD,
                    node_params.node_acl);
            if (status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
    } else {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_MACCMD,
                node_params.node_acl);
    }
    return status;
}

uint32_t
acfg_set_acl_policy_secondary(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_vap_params_t *cur_vap_params)
{
    acfg_wlan_profile_node_params_t node_params, cur_node_params;
    uint32_t status = QDF_STATUS_SUCCESS;
    node_params = vap_params->node_params;
    if (cur_vap_params != NULL) {
        cur_node_params = cur_vap_params->node_params;
        if (node_params.node_acl_sec != cur_node_params.node_acl_sec) {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_MACCMD_SEC,
                    node_params.node_acl_sec);
            if (status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
    } else {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_MACCMD_SEC,
                node_params.node_acl_sec);
    }
    return status;
}

uint32_t
acfg_set_node_list_secondary(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_vap_params_t *cur_vap_params)
{
    acfg_wlan_profile_node_params_t node_params, cur_node_params;
    uint8_t *mac;
    uint8_t new_index, cur_index, found ;
    uint32_t status = QDF_STATUS_SUCCESS;

    node_params = vap_params->node_params;
    if (cur_vap_params != NULL) {
        cur_node_params = cur_vap_params->node_params;
        for (new_index = 0; new_index < node_params.num_node_sec; new_index++) {
            mac = node_params.acfg_acl_node_list_sec[new_index];
            found = 0;
            for (cur_index = 0; cur_index < cur_node_params.num_node_sec;
                    cur_index++)
            {
                if (memcmp(mac,
                            cur_node_params.acfg_acl_node_list_sec[cur_index],
                            ACFG_MACADDR_LEN) == 0)
                {
                    found = 1;
                    break;
                }

            }
            if (found == 0) {
                status = acfg_acl_addmac_secondary((uint8_t *)vap_params->vap_name,
                        mac);
                if(status != QDF_STATUS_SUCCESS) {
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }
        for (cur_index = 0; cur_index < cur_node_params.num_node_sec;
                cur_index++)
        {
            mac = cur_node_params.acfg_acl_node_list_sec[cur_index];
            found = 0;
            for (new_index = 0; new_index < node_params.num_node_sec;
                    new_index++)
            {
                if (memcmp(mac,
                            node_params.acfg_acl_node_list_sec[new_index],
                            ACFG_MACADDR_LEN) == 0)
                {
                    found = 1;
                    break;
                }

            }
            if (found == 0) {
                status = acfg_acl_delmac_secondary((uint8_t *)cur_vap_params->vap_name,
                        mac);
                if(status != QDF_STATUS_SUCCESS) {
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }
    } else {
        for (new_index = 0; new_index < node_params.num_node_sec; new_index++) {
            mac = node_params.acfg_acl_node_list_sec[new_index];
            status = acfg_acl_addmac_secondary((uint8_t *)vap_params->vap_name,
                    mac);
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    return status;
}


uint32_t
acfg_set_node_list(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_vap_params_t *cur_vap_params)
{
    acfg_wlan_profile_node_params_t node_params, cur_node_params;
    uint8_t *mac;
    uint8_t new_index, cur_index, found ;
    uint32_t status = QDF_STATUS_SUCCESS;

    node_params = vap_params->node_params;
    if (cur_vap_params != NULL) {
        cur_node_params = cur_vap_params->node_params;
        for (new_index = 0; new_index < node_params.num_node; new_index++) {
            mac = node_params.acfg_acl_node_list[new_index];
            found = 0;
            for (cur_index = 0; cur_index < cur_node_params.num_node;
                    cur_index++)
            {
                if (memcmp(mac,
                            cur_node_params.acfg_acl_node_list[cur_index],
                            ACFG_MACADDR_LEN) == 0)
                {
                    found = 1;
                    break;
                }

            }
            if (found == 0) {
                status = acfg_acl_addmac((uint8_t *)vap_params->vap_name,
                        mac);
                if(status != QDF_STATUS_SUCCESS) {
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }
        for (cur_index = 0; cur_index < cur_node_params.num_node;
                cur_index++)
        {
            mac = cur_node_params.acfg_acl_node_list[cur_index];
            found = 0;
            for (new_index = 0; new_index < node_params.num_node;
                    new_index++)
            {
                if (memcmp(mac,
                            node_params.acfg_acl_node_list[new_index],
                            ACFG_MACADDR_LEN) == 0)
                {
                    found = 1;
                    break;
                }

            }
            if (found == 0) {
                status = acfg_acl_delmac((uint8_t *)cur_vap_params->vap_name,
                        mac);
                if(status != QDF_STATUS_SUCCESS) {
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }
    } else {
        for (new_index = 0; new_index < node_params.num_node; new_index++) {
            mac = node_params.acfg_acl_node_list[new_index];
            status = acfg_acl_addmac((uint8_t *)vap_params->vap_name,
                    mac);
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    return status;
}

void
acfg_rem_wps_config_file(uint8_t *ifname)
{
    char filename[32];
    FILE *fp;

    acfg_os_snprintf(filename, sizeof(filename), "/etc/%s_%s.conf",
             ACFG_WPS_CONFIG_PREFIX, (char *)ifname);
    fp = fopen(filename, "r");
    if (fp != NULL) {
        unlink(filename);
        fclose(fp);
    }
}

uint32_t
acfg_set_wps_vap_params(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wps_cred_t *wps_cred)
{
    acfg_opmode_t opmode;
    uint32_t status = QDF_STATUS_SUCCESS;

    status = acfg_get_opmode(vap_params->vap_name, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail for %s\n", __func__,
                vap_params->vap_name);
        return QDF_STATUS_E_FAILURE;
    }
    acfg_os_strcpy(vap_params->ssid, wps_cred->ssid, sizeof(vap_params->ssid));
    if ( wps_cred->wpa == 1) {
        vap_params->security_params.sec_method =
            IEEE80211_AUTH_WPA;
    } else if ((wps_cred->wpa == 2)) {
        vap_params->security_params.sec_method =
            IEEE80211_AUTH_RSNA;
    } else if ((wps_cred->wpa == 3)) {
        vap_params->security_params.sec_method =
            ACFG_WLAN_PROFILE_SEC_METH_WPAWPA2;
    } else if (wps_cred->wpa == 0) {
        if (wps_cred->auth_alg == 1) {
            vap_params->security_params.sec_method =
                ACFG_WLAN_PROFILE_SEC_METH_OPEN;
        } else if (wps_cred->auth_alg == 2) {
            vap_params->security_params.sec_method =
                ACFG_WLAN_PROFILE_SEC_METH_SHARED;
        }
        if (strlen(wps_cred->wep_key)) {
            if (wps_cred->wep_key_idx == 0) {
                acfg_os_strcpy(vap_params->security_params.wep_key0,
                               wps_cred->wep_key,
                               sizeof(vap_params->security_params.wep_key0));
            } else if (wps_cred->wep_key_idx == 1) {
                acfg_os_strcpy(vap_params->security_params.wep_key1,
                               wps_cred->wep_key,
                               sizeof(vap_params->security_params.wep_key1));
            } else if (wps_cred->wep_key_idx == 2) {
                acfg_os_strcpy(vap_params->security_params.wep_key2,
                               wps_cred->wep_key,
                               sizeof(vap_params->security_params.wep_key2));
            } else if (wps_cred->wep_key_idx == 3) {
                acfg_os_strcpy(vap_params->security_params.wep_key3,
                               wps_cred->wep_key,
                               sizeof(vap_params->security_params.wep_key3));
            }
            vap_params->security_params.wep_key_defidx = wps_cred->wep_key_idx;
            vap_params->security_params.cipher_method =
                ACFG_WLAN_PROFILE_CIPHER_METH_WEP;
        } else {
            vap_params->security_params.sec_method =
                ACFG_WLAN_PROFILE_SEC_METH_OPEN;
        }
    }

    if (wps_cred->key_mgmt == 2) {
        acfg_os_strcpy(vap_params->security_params.psk, wps_cred->key, sizeof(vap_params->security_params.psk));
    }
    if (wps_cred->enc_type) {
        vap_params->security_params.cipher_method = wps_cred->enc_type;
    }
    /*Overide Cipher*/
    if ((vap_params->security_params.sec_method ==
                ACFG_WLAN_PROFILE_SEC_METH_OPEN) ||
            (vap_params->security_params.sec_method ==
             ACFG_WLAN_PROFILE_SEC_METH_SHARED))
    {
        if (strlen(wps_cred->wep_key)) {
            vap_params->security_params.cipher_method =
                ACFG_WLAN_PROFILE_CIPHER_METH_WEP;
        } else {
            vap_params->security_params.cipher_method =
                ACFG_WLAN_PROFILE_CIPHER_METH_NONE;
        }
    }

    if (opmode == ACFG_OPMODE_HOSTAP) {
        vap_params->security_params.wps_flag = WPS_FLAG_CONFIGURED;
    }

    return status;
}

uint32_t
acfg_wps_config(uint8_t *ifname, char *ssid,
        char *auth, char *encr, char *key)
{
    char cmd[255];
    char buf[255];
    char replybuf[255];
    uint32_t len = sizeof(replybuf), i;
    acfg_opmode_t opmode;
    uint32_t status = QDF_STATUS_SUCCESS;
    char ssid_hex[2 * 32 + 1];
    char key_hex[2 * 64 + 1];

    memset(replybuf, 0, sizeof(replybuf));
    status = acfg_get_opmode(ifname,
            &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail for %s\n", __func__, ifname);
        return status;
    }
    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd,
            ctrl_wpasupp);
    acfg_os_snprintf(cmd, sizeof(cmd), "WPS_CONFIG");
    if (strcmp(ssid, "0")) {
        ssid_hex[0] = '\0';
        for (i = 0; i < 32; i++) {
            if (ssid[i] == '\0') {
                break;
            }
            acfg_os_snprintf(&ssid_hex[i * 2], 3, "%02x", ssid[i]);
        }
        acfg_os_strlcat(cmd, " ", sizeof(cmd));
        acfg_os_strlcat(cmd, ssid_hex, sizeof(cmd));
    }
    if (strcmp(auth, "0")) {
        acfg_os_snprintf(buf, sizeof(buf), " %s", auth);
        acfg_os_strlcat(cmd, buf, sizeof(cmd));
    }
    if (strcmp(encr, "0")) {
        acfg_os_snprintf(buf, sizeof(buf), " %s", encr);
        acfg_os_strlcat(cmd, buf, sizeof(cmd));
    }
    if (strcmp(key, "0")) {
        key_hex[0] = '\0';
        for (i = 0; i < 64; i++) {
            if (key[i] == '\0') {
                break;
            }
            acfg_os_snprintf(&key_hex[i * 2], 3, "%02x",
                    key[i]);
        }
        acfg_os_strlcat(cmd, " ", sizeof(cmd));
        acfg_os_strlcat(cmd, key_hex, sizeof(cmd));
    }

    if((acfg_ctrl_req(ifname, cmd, strlen(cmd),
                    replybuf, &len, opmode) < 0) ||
            strncmp(replybuf, "OK", strlen("OK"))){
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

void
acfg_open_dpp_config_file(uint8_t *ifname)
{
    char filename[32];
    FILE *fp;

    snprintf(filename, sizeof(filename), "/etc/%s_%s.conf",
             ACFG_DPP_CONFIG_PREFIX, (char *)ifname);
    fp = fopen(filename, "r");
    if (fp != NULL) {
        unlink(filename);
        fclose(fp);
    }

    fp = fopen(filename, "w");
    if (fp == NULL){
        return;
    }
    fclose(fp);
}

void
acfg_write_dpp_config_file(uint8_t *ifname, char *data)
{
    char filename[32];
    FILE *fp;

    snprintf(filename, sizeof(filename), "/etc/%s_%s.conf",
             ACFG_DPP_CONFIG_PREFIX, (char *)ifname);
    fp = fopen(filename, "a");
    if (fp == NULL){
        return;
    }
    fprintf(fp,"%s", data);
    fclose(fp);
}

int acfg_get_legacy_rate(int rate)
{
    unsigned int i = 0;
    int legacy_rate_idx[][2] = {
        {1, 0x1b},
        {2, 0x1a},
        {5, 0x19},
        {6, 0xb},
        {9, 0xf},
        {11, 0x18},
        {12, 0xa},
        {18, 0xe},
        {24, 0x9},
        {36, 0xd},
        {48, 0x8},
        {54, 0xc},
    };
    for (i = 0; i < (sizeof(legacy_rate_idx)/sizeof(legacy_rate_idx[0])); i++)
    {
        if (legacy_rate_idx[i][0] == rate) {
            return legacy_rate_idx[i][1];
        }
    }
    return 0;
}

int acfg_get_mcs_rate(int val)
{
    unsigned int i = 0;
    int mcs_rate_idx[][2] = {
        {0, 0x80},
        {1, 0x81},
        {2, 0x82},
        {3, 0x83},
        {4, 0x84},
        {5, 0x85},
        {6, 0x86},
        {7, 0x87},
        {8, 0x88},
        {9, 0x89},
        {10, 0x8a},
        {11, 0x8b},
        {12, 0x8c},
        {13, 0x8d},
        {14, 0x8e},
        {15, 0x8f},
        {16, 0x90},
        {17, 0x91},
        {18, 0x92},
        {19, 0x93},
        {20, 0x94},
        {21, 0x95},
        {22, 0x96},
        {23, 0x97},
    };

    if (val >= (int)(sizeof(mcs_rate_idx)/sizeof(mcs_rate_idx[0]))) {
        return 0;
    }
    for (i = 0; i < sizeof(mcs_rate_idx)/sizeof(mcs_rate_idx[0]); i++)
    {
        if (mcs_rate_idx[i][0] == val) {
            return mcs_rate_idx[i][1];
        }
    }
    return 0;
}

void
acfg_parse_rate(uint8_t *rate_str, int *val)
{
    char *pos = NULL, *start;
    char buf[16];
    int rate = 0;
    int ratecode, i;
    int maxlen = 0;

    start = (char *)rate_str;
    pos = strchr((char *)rate_str, 'M');
    if (pos) {
        if((unsigned int)(pos - start) >= sizeof(buf))
            maxlen = sizeof(buf);
        else
            maxlen = pos - start + 1;
        acfg_os_strcpy(buf, start, maxlen);
        rate = atoi(buf);
        ratecode = acfg_get_legacy_rate(rate);
    } else {
        acfg_os_strcpy(buf, start, sizeof(buf));
        rate = atoi(buf);
        rate = rate - 1;
        if (rate < 0) {
            *val = 0;
            return;
        }
        ratecode = acfg_get_mcs_rate(rate);
    }
    *val = 0;
    for (i = 0; i < 4; i++) {
        *val |= ratecode << (i * 8);
    }
}

uint32_t
acfg_wlan_vap_profile_vlan_add(acfg_wlan_profile_vap_params_t *vap_params)
{
    char str[60];
    char iface_name[ACFG_MAX_IFNAME];
    char vlan_bridge[ACFG_MAX_IFNAME];
    uint32_t status = QDF_STATUS_SUCCESS;
    int ret = 0;

    status = acfg_wlan_iface_present("eth0");
    if (status == QDF_STATUS_SUCCESS) {
        acfg_os_snprintf(str, sizeof(str), "brctl delif br0 eth0");
        ret = system(str);
    }

    status = acfg_wlan_iface_present("eth1");
    if (status == QDF_STATUS_SUCCESS) {
        acfg_os_snprintf(str, sizeof(str), "brctl delif br0 eth1");
        ret = system(str);
    }

    status = acfg_wlan_iface_present((char *)vap_params->vap_name);
    if (status == QDF_STATUS_SUCCESS) {
        acfg_os_snprintf(str, sizeof(str), "brctl delif br0 %s", vap_params->vap_name);
        ret = system(str);
    }

    acfg_os_snprintf(vlan_bridge, sizeof(vlan_bridge), "br%d", vap_params->vlanid);
    status = acfg_wlan_iface_present(vlan_bridge);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_os_snprintf(str, sizeof(str), "brctl addbr %s", vlan_bridge);
        ret = system(str);
    }

    acfg_os_snprintf(str, sizeof(str), "brctl delif br%d %s",
             vap_params->vlanid, vap_params->vap_name);
    ret = system(str);

    acfg_os_snprintf(str, sizeof(str), "vconfig add %s %d", vap_params->vap_name,
             vap_params->vlanid);
    ret = system(str);

    acfg_os_snprintf(str, sizeof(str), "vconfig add eth0 %d", vap_params->vlanid);
    ret = system(str);

    acfg_os_snprintf(str, sizeof(str), "vconfig add eth1 %d", vap_params->vlanid);
    ret = system(str);

    acfg_os_snprintf(str, sizeof(str), "brctl addif %s %s.%d", vlan_bridge,
            vap_params->vap_name, vap_params->vlanid);
    ret = system(str);
    acfg_os_snprintf(str, sizeof(str), "brctl addif %s eth0.%d", vlan_bridge,
            vap_params->vlanid);
    ret = system(str);
    acfg_os_snprintf(str, sizeof(str), "brctl addif %s eth1.%d", vlan_bridge,
            vap_params->vlanid);
    ret = system(str);

    if (ret) {
        status = ret;
        return status;
    }

    ret = acfg_os_snprintf(iface_name, sizeof(iface_name), "%s.%d", vap_params->vap_name, vap_params->vlanid);
    if ((ret < 0) || (ret >= (int)sizeof(iface_name))) {
        acfg_log_errstr("%s:%d Failed snprintf\n",__func__,__LINE__);
        return QDF_STATUS_E_FAILURE;
    }
    status = acfg_wlan_iface_up((uint8_t *)iface_name, NULL);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("Failed to bring vap UP\n");
        return status;
    }
    acfg_os_snprintf(iface_name, sizeof(iface_name), "eth0.%d", vap_params->vlanid);
    status = acfg_wlan_iface_up((uint8_t *)iface_name, NULL);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("Failed to bring %s UP\n", str);
        return status;
    }
    acfg_os_snprintf(iface_name, sizeof(iface_name), "eth1.%d", vap_params->vlanid);
    status = acfg_wlan_iface_up((uint8_t *)iface_name, NULL);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("Failed to bring %s UP\n", str);
        return status;
    }
    return status;
}

void acfg_wlan_vap_profile_vlan_remove(acfg_wlan_profile_vap_params_t *cur_vap_params)
{
    char str[60];
    char iface_name[ACFG_MAX_IFNAME];
    char vlan_bridge[ACFG_MAX_IFNAME];
    uint32_t status = QDF_STATUS_SUCCESS;
    int ret = 0;

    acfg_os_snprintf(vlan_bridge, sizeof(vlan_bridge), "br%d", cur_vap_params->vlanid);

    ret = acfg_os_snprintf(iface_name, sizeof(iface_name), "%s.%d", cur_vap_params->vap_name, cur_vap_params->vlanid);
    if ((ret < 0) || (ret >= (int)sizeof(iface_name))) {
        acfg_log_errstr("%s:%d Failed snprintf\n",__func__,__LINE__);
        return;
    }
    status = acfg_wlan_iface_present(iface_name);
    if (status == QDF_STATUS_SUCCESS) {
        acfg_wlan_iface_down((uint8_t *)iface_name, NULL);
        acfg_os_snprintf(str,sizeof(str), "brctl delif %s %s", vlan_bridge, iface_name);
        ret = system(str);
    }

    acfg_os_snprintf(str, sizeof(str), "vconfig rem %s.%d", cur_vap_params->vap_name,
            cur_vap_params->vlanid);
    ret = system(str);
    if (ret)
        printf("system call failed.\n");
    return;
}

uint32_t
acfg_percent_str_to_octet(char *tmp_new, char end_chr, uint32_t *percent)
{
    char *str = tmp_new;
    int8_t cnt = 0;

    while((*str != end_chr) && (*str != '\0') && (cnt < 4))
    {
        cnt++;
        str++;
    }

    if(cnt == 4)
    {
        acfg_log_errstr("Percent value invalid\n");
        return QDF_STATUS_E_FAILURE;
    }

    str = tmp_new;
    *percent = 0;

    while(cnt--)
    {
        if((*str >= '0')&&(*str <= '9'))
        {
            *percent = (*percent * 10) + (*str - '0');
            str++;
        }
        else{
            acfg_log_errstr("Percent range should be in decimal, but %c \n", *str);
            return QDF_STATUS_E_FAILURE;
        }
    }
    if(*percent > 100)
    {
        acfg_log_errstr("Percent range should be btw 0 ~ 100, but %d\n", *percent);
        return QDF_STATUS_E_FAILURE;
    }
    else
        return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_vap_atf_addssid(uint8_t *vap_name,
        char *ssid,
        uint32_t percent)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_os_req_t req = {.cmd = ACFG_REQ_SET_ATF_ADDSSID};
    acfg_atf_ssid_val_t *ptr = (acfg_atf_ssid_val_t *)req.data;

    memset(ptr, 0, sizeof(acfg_atf_ssid_val_t));

    acfg_os_strcpy((char *)ptr->ssid, ssid, ACFG_MAX_SSID_LEN + 1);
    ptr->value = percent * 10;

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

uint32_t
acfg_vap_atf_delssid(uint8_t *vap_name,
        char *ssid)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_os_req_t req = {.cmd = ACFG_REQ_SET_ATF_DELSSID};
    acfg_atf_ssid_val_t *ptr = (acfg_atf_ssid_val_t *)req.data;

    memset(ptr, 0, sizeof(acfg_atf_ssid_val_t));

    acfg_os_strcpy((char *)ptr->ssid, ssid, ACFG_MAX_SSID_LEN + 1);

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

uint32_t
acfg_vap_atf_addsta(uint8_t *vap_name,
        uint8_t *mac,
        uint32_t percent, char *ssid)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_os_req_t req = {.cmd = ACFG_REQ_SET_ATF_ADDSTA};
    acfg_atf_sta_val_t *ptr = (acfg_atf_sta_val_t *)req.data;

    memset(ptr, 0, sizeof(acfg_atf_sta_val_t));

    memcpy(ptr->sta_mac, mac, ACFG_MACADDR_LEN);
    ptr->value = percent * 10;

    acfg_os_strcpy((char *)ptr->ssid, ssid, ACFG_MAX_SSID_LEN + 1);

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

uint32_t
acfg_vap_atf_delsta(uint8_t *vap_name,
        uint8_t *mac)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_os_req_t req = {.cmd = ACFG_REQ_SET_ATF_DELSTA};
    acfg_atf_sta_val_t *ptr = (acfg_atf_sta_val_t *)req.data;

    memset(ptr, 0, sizeof(acfg_atf_sta_val_t));

    memcpy(ptr->sta_mac, mac, ACFG_MACADDR_LEN);

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

#if QCA_AIRTIME_FAIRNESS
uint32_t
acfg_vap_atf_commit(uint8_t *vap_name)
{
    uint32_t status = QDF_STATUS_SUCCESS;

    status = acfg_set_vap_param(vap_name,
            ACFG_PARAM_ATF_OPT,
            1);
    if (status != QDF_STATUS_SUCCESS)
    {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_vap_configure_atf(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_vap_params_t *cur_vap_params)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    uint8_t update = 0;

    if(strncmp(vap_params->atf.atf_percent,
                cur_vap_params->atf.atf_percent,
                ACFG_MAX_PERCENT_SIZE))
    {
        /* NULL, Remove the ssid from the ATF table */
        if(vap_params->atf.atf_percent[0] == '\0')
        {
            status = acfg_vap_atf_delssid(vap_params->vap_name, vap_params->ssid);
            if(status != QDF_STATUS_SUCCESS)
            {
                acfg_log_errstr("ATF delssid failed %s\n", vap_params->vap_name);
                return QDF_STATUS_E_FAILURE;
            }
        }
        /* Add the new percent to ATF table */
        else
        {
            uint32_t percent;

            status = acfg_percent_str_to_octet(vap_params->atf.atf_percent,
                    '\0', &percent);
            if(status != QDF_STATUS_SUCCESS)
            {
                acfg_log_errstr("Invalid VAP ATF percent\n");
                return QDF_STATUS_E_FAILURE;
            }
            status = acfg_vap_atf_addssid(vap_params->vap_name,
                    vap_params->ssid,
                    percent);
            if(status != QDF_STATUS_SUCCESS)
            {
                acfg_log_errstr("ATF addssid failed %s\n", vap_params->vap_name);
                return QDF_STATUS_E_FAILURE;
            }
        }
        update = 1;
    }
    if(strncmp(vap_params->atf.atf_stalist,
                cur_vap_params->atf.atf_stalist,
                ACFG_MAX_ATF_STALIST_SIZE))
    {
        uint8_t mac[ACFG_MACADDR_LEN];
        char  mac_str[18] = {0};

        if(strchr(cur_vap_params->atf.atf_stalist, ':'))
        {
            char *old = cur_vap_params->atf.atf_stalist;

            /* Remove old entries from the ATF table */
            for(;;)
            {
                uint8_t mac[ACFG_MACADDR_LEN];

                memcpy(mac_str, old, 17);
                acfg_mac_str_to_octet((uint8_t *)mac_str, mac);

                status = acfg_vap_atf_delsta(vap_params->vap_name, mac);
                if(status != QDF_STATUS_SUCCESS)
                {
                    acfg_log_errstr("ATF delsta failed\n");
                    return QDF_STATUS_E_FAILURE;
                }

                /* Point to the next old entry */
                old = strchr(old, ';');
                if(old == NULL)
                    break;
                old++;

            }
        }

        /* Add new entries to the ATF table */
        if(strchr(vap_params->atf.atf_stalist, ':'))
        {
            char *new = vap_params->atf.atf_stalist;
            char *percent_str;
            uint32_t percent;

            for(;;)
            {
                memcpy(mac_str, new, 17);
                acfg_mac_str_to_octet((uint8_t *)mac_str, mac);

                percent_str = strchr(new, ',');
                if(percent_str == NULL)
                {
                    acfg_log_errstr("No STA ATF percent provided\n");
                    return QDF_STATUS_E_FAILURE;
                }
                percent_str++;

                status = acfg_percent_str_to_octet(percent_str, ';', &percent);
                if(status != QDF_STATUS_SUCCESS)
                {
                    acfg_log_errstr("Invalid STA ATF percent\n");
                    return QDF_STATUS_E_FAILURE;
                }
                status  = acfg_vap_atf_addsta(vap_params->vap_name, mac, percent, vap_params->ssid);
                if(status != QDF_STATUS_SUCCESS)
                {
                    acfg_log_errstr("ATF addsta failed\n");
                    return QDF_STATUS_E_FAILURE;
                }
                /* Point to the next new entry */
                new = strchr(new, ';');
                if(new == NULL)
                    break;
                new++;
            }
        }
        update = 1;
    }
    if(update)
    {
        /* Now commit the ATF change */
        status = acfg_vap_atf_commit(vap_params->vap_name);
        if(status != QDF_STATUS_SUCCESS)
        {
            acfg_log_errstr("ATF commit failed\n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    return QDF_STATUS_SUCCESS;
}
#endif

uint32_t
acfg_wlan_vap_create(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_radio_params_t radio_params)
{
    uint32_t status = QDF_STATUS_SUCCESS;

    status = acfg_wlan_iface_present((char *)vap_params->vap_name);
    if(status == QDF_STATUS_SUCCESS) {
        acfg_log_errstr("Interface Already present\n");
        return QDF_STATUS_E_INVAL;
    }
    if ((vap_params->opmode == ACFG_OPMODE_STA) &&
            (vap_params->wds_params.wds_flags != ACFG_FLAG_VAP_ENHIND))
    {
        if((vap_params->vapid == VAP_ID_AUTO) || (radio_params.macreq_enabled != 1))
            status = acfg_create_vap(radio_params.radio_name,
                    vap_params->vap_name,
                    vap_params->opmode,
                    vap_params->vapid,
                    IEEE80211_CLONE_BSSID | IEEE80211_CLONE_NOBEACONS);
        else
            status = acfg_create_vap(radio_params.radio_name,
                    vap_params->vap_name,
                    vap_params->opmode,
                    vap_params->vapid,
                    IEEE80211_CLONE_NOBEACONS);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to Create Vap %s\n", vap_params->vap_name);
            return QDF_STATUS_E_FAILURE;
        }
    }
    else
    {
        if((vap_params->vapid == VAP_ID_AUTO) || (radio_params.macreq_enabled != 1))
            status = acfg_create_vap(radio_params.radio_name,
                    vap_params->vap_name,
                    vap_params->opmode,
                    vap_params->vapid,
                    IEEE80211_CLONE_BSSID);
        else
            status = acfg_create_vap(radio_params.radio_name,
                    vap_params->vap_name,
                    vap_params->opmode,
                    vap_params->vapid,
                    0);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to Create Vap %s\n", vap_params->vap_name);
            return QDF_STATUS_E_FAILURE;
        }
    }
    return status;
}

uint32_t
acfg_wlan_vap_profile_modify(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_vap_params_t *cur_vap_params,
        acfg_wlan_profile_radio_params_t radio_params)
{
    acfg_ssid_t ssid;
    acfg_rate_t rate;
    int8_t sec = 0;
    int if_down = 0, setssid = 0, enablewep = 0, set_open = 0,
        set_wep = 0, wps_state = 0;
    uint32_t status = QDF_STATUS_SUCCESS;
    uint8_t mac[ACFG_MACADDR_LEN];
    char str[60];
    int rate_val = 0, retries = 0, i;
    int ret = 0;

    int index = 0, k =0;
    char replybuf[255] = {0};
    uint32_t len = sizeof (replybuf);
    char acfg_hapd_param_list[ACFG_MAX_HAPD_CONFIG_PARAM+1][1051];//changed 1024 to 1051

    (void) radio_params;
    if(vap_params->opmode != cur_vap_params->opmode) {
        acfg_log_errstr("Operating Mode cannot be modified\n");
        return QDF_STATUS_E_FAILURE;
    }

    if ((vap_params->vlanid) && (vap_params->vlanid != ACFG_WLAN_PROFILE_VLAN_INVALID)) {
        acfg_os_snprintf((char *)vap_params->bridge,
                 sizeof(vap_params->bridge), "br%d", vap_params->vlanid);
     }
    if ((cur_vap_params->vlanid) && (vap_params->vlanid != ACFG_WLAN_PROFILE_VLAN_INVALID)) {
        acfg_os_snprintf((char *)cur_vap_params->bridge,
                 sizeof(cur_vap_params->bridge), "br%d", cur_vap_params->vlanid);
    }

    if (!ACFG_STR_MATCH(vap_params->ssid, cur_vap_params->ssid)) {
        memcpy(ssid.ssid, vap_params->ssid, (ACFG_MAX_SSID_LEN + 1));
        if(strlen((char *)ssid.ssid) > 0) {
            if (!if_down) {
                status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
                if_down = 1;
                setssid = 1;
                if(status != QDF_STATUS_SUCCESS) {
                    return QDF_STATUS_E_FAILURE;
                }
            }
            status = acfg_set_ssid(vap_params->vap_name, &ssid);
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
    }

    if (!ACFG_STR_MATCH(vap_params->bridge, cur_vap_params->bridge)) {
        if (vap_params->bridge[0] == 0) {
            status = acfg_wlan_iface_present(cur_vap_params->bridge);

            if (status == QDF_STATUS_SUCCESS) {
                acfg_os_snprintf(str, sizeof(str),
                         "brctl delif %s %s", cur_vap_params->bridge,
                         vap_params->vap_name);
                ret = system(str);
            }
        } else if (!cur_vap_params->bridge[0] && vap_params->bridge[0]) {
            status = acfg_wlan_iface_present(vap_params->bridge);

            if (status != QDF_STATUS_SUCCESS) {
                acfg_os_snprintf(str, sizeof(str), "brctl addbr %s", vap_params->bridge);
                ret = system(str);
            }

            status = acfg_wlan_iface_up((uint8_t *)vap_params->bridge, NULL);

            acfg_os_snprintf(str, sizeof(str), "brctl addif %s %s", vap_params->bridge,
                    vap_params->vap_name);
            ret = system(str);
            acfg_os_snprintf(str, sizeof(str), "brctl setfd %s 0", vap_params->bridge);
            ret = system(str);
        } else if (cur_vap_params->bridge[0] && vap_params->bridge[0]) {
            status = acfg_wlan_iface_present(cur_vap_params->bridge);
            if (status == QDF_STATUS_SUCCESS) {
                acfg_os_snprintf(str, sizeof(str),
                         "brctl delif %s %s", cur_vap_params->bridge,
                         vap_params->vap_name);
                ret = system(str);
            }
            status = acfg_wlan_iface_present(vap_params->bridge);

            if (status != QDF_STATUS_SUCCESS) {
                acfg_os_snprintf(str, sizeof(str), "brctl addbr %s",
                         vap_params->bridge);
                ret = system(str);
            }
            acfg_os_snprintf(str, sizeof(str), "brctl addif %s %s", vap_params->bridge,
                    vap_params->vap_name);
            status = acfg_wlan_iface_up((uint8_t *)vap_params->bridge, NULL);
            ret = system(str);
            acfg_os_snprintf(str, sizeof(str), "brctl setfd %s 0", vap_params->bridge);
            ret = system(str);
        }
    }
    if (ret) {
        printf("some system call failed\n");
        return QDF_STATUS_E_FAILURE;
    }
    if (vap_params->wds_params.enabled != cur_vap_params->wds_params.enabled) {
        if (!if_down) {
            status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
            if_down = 1;
            setssid = 1;
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_WDS,
                vap_params->wds_params.enabled);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to enbale wds\n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (vap_params->wds_params.wds_flags !=
            cur_vap_params->wds_params.wds_flags)
    {
        if (!if_down) {
            status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
            if_down = 1;
            setssid = 1;
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }


        if ((vap_params->wds_params.wds_flags & ACFG_FLAG_VAP_ENHIND) ==
                ACFG_FLAG_VAP_ENHIND)
        {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_VAP_ENHIND, 1);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set wds repeater Enhanced independent flag\n");
                return QDF_STATUS_E_FAILURE;
            }
        }
        else
        {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_VAP_ENHIND, 0);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set wds repeater Enhanced independent flag\n");
                return QDF_STATUS_E_FAILURE;
            }
        }

        if (vap_params->opmode == ACFG_OPMODE_STA) {
            if ((vap_params->wds_params.wds_flags & ACFG_FLAG_EXTAP) ==
                    ACFG_FLAG_EXTAP)
            {
                status = acfg_set_vap_param(vap_params->vap_name,
                        ACFG_PARAM_EXTAP, 1);
                if (status != QDF_STATUS_SUCCESS) {
                    acfg_log_errstr("Failed to set wds extension flag\n");
                    return QDF_STATUS_E_FAILURE;
                }
            }
            else
            {
                status = acfg_set_vap_param(vap_params->vap_name,
                        ACFG_PARAM_EXTAP, 0);
                if (status != QDF_STATUS_SUCCESS) {
                    acfg_log_errstr("Failed to set wds extension flag\n");
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }
    }

    if (vap_params->phymode != cur_vap_params->phymode) {
        if (!if_down) {
            status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
            if_down = 1;
            setssid = 1;
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
        status = acfg_set_phymode(vap_params->vap_name,
                vap_params->phymode);
        if(status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }

    if(vap_params->opmode == ACFG_OPMODE_HOSTAP) {
        if (vap_params->primary_vap && (vap_params->beacon_interval != cur_vap_params->beacon_interval))
        {
            acfg_os_snprintf(acfg_hapd_param_list[index], sizeof(acfg_hapd_param_list[index]),
                    "SET beacon_int %d", vap_params->beacon_interval);
            index++;
            if (!if_down) {
                status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
                if_down = 1;
                setssid = 1;
                if(status != QDF_STATUS_SUCCESS) {
                    return QDF_STATUS_E_FAILURE;
                }
            }
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_BEACON_INTERVAL,
                    vap_params->beacon_interval);
            if(status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set beacon interval\n");
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    if(vap_params->opmode == ACFG_OPMODE_HOSTAP) {
        if (vap_params->dtim_period == 0) {
            /*Default DTIM period is 1 on driver and 2 on hostapd
              so, set same default value on hostapd also*/
            acfg_os_snprintf(acfg_hapd_param_list[index], sizeof(acfg_hapd_param_list[index]),
                    "SET dtim_period 1");
            index++;
            }
        if (vap_params->dtim_period != cur_vap_params->dtim_period)
        {
            acfg_os_snprintf(acfg_hapd_param_list[index], sizeof(acfg_hapd_param_list[index]),
                    "SET dtim_period %d", vap_params->dtim_period);
            index++;
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_DTIM_PERIOD,
                    vap_params->dtim_period);
            if(status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set dtim period\n");
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    if (vap_params->he_rx_mcsmap != cur_vap_params->he_rx_mcsmap)
    {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_RX_MCSMAP,
                vap_params->he_rx_mcsmap);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set HE RX MCS MAP\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->he_tx_mcsmap != cur_vap_params->he_tx_mcsmap)
    {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_TX_MCSMAP,
                vap_params->he_tx_mcsmap);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set HE TX MCS MAP\n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    if(vap_params->bitrate != cur_vap_params->bitrate) {
        if (!if_down) {
            status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
            if_down = 1;
            setssid = 1;
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
        rate = vap_params->bitrate;
        status = acfg_set_rate(vap_params->vap_name, &rate);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set rate\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (!ACFG_STR_MATCH(vap_params->rate, cur_vap_params->rate)) {
        acfg_parse_rate(vap_params->rate, &rate_val);
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_11N_RATE,
                rate_val);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set rate\n");
        }
    }
    if (vap_params->retries != cur_vap_params->retries) {
        for (i = 0; i < 4; i++) {
            retries |= vap_params->retries << (i * 8);
        }
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_11N_RETRIES,
                retries);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set retries\n");
        }
    }
    if(vap_params->frag_thresh !=
            cur_vap_params->frag_thresh)
    {

        if((vap_params->frag_thresh >= IEEE80211_FRAGMT_THRESHOLD_MAX) ||
                (vap_params->frag_thresh == 0))
        {
            vap_params->frag_thresh = IEEE80211_FRAGMT_THRESHOLD_MAX;
        }

        if (!if_down) {
            status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
            if_down = 1;
            setssid = 1;
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
        status = acfg_set_frag(vap_params->vap_name,
                &vap_params->frag_thresh);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set fragmentation Threshold\n");
        }
    }
    if(vap_params->rts_thresh !=
            cur_vap_params->rts_thresh)
    {

        if((vap_params->rts_thresh >= IEEE80211_RTS_MAX) ||
                (vap_params->rts_thresh == 0))
        {
            vap_params->rts_thresh = IEEE80211_RTS_MAX;
        }
        if (!if_down) {
            status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
            if_down = 1;
            setssid = 1;
            if(status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
        status = acfg_set_rts(vap_params->vap_name,
                &vap_params->rts_thresh);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set rts threshold\n");
        }
    }
    status = acfg_set_node_list(vap_params, cur_vap_params);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Failed to set node list (vap=%s status=%d)!\n",
                __func__, vap_params->vap_name, status);
        return QDF_STATUS_E_FAILURE;
    }
    status = acfg_set_acl_policy(vap_params, cur_vap_params);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Failed to set ACL policy (vap=%s status=%d)!\n",
                __func__, vap_params->vap_name, status);
        return QDF_STATUS_E_FAILURE;
    }
    /* For Second ACL list */
    status = acfg_set_node_list_secondary(vap_params, cur_vap_params);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Failed to set node list (vap=%s status=%d)!\n",
                __func__, vap_params->vap_name, status);
        return QDF_STATUS_E_FAILURE;
    }
    status = acfg_set_acl_policy_secondary(vap_params, cur_vap_params);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Failed to set ACL policy (vap=%s status=%d)!\n",
                __func__, vap_params->vap_name, status);
        return QDF_STATUS_E_FAILURE;
    }

    if ((vap_params->opmode == ACFG_OPMODE_HOSTAP) &&
            (vap_params->pureg != cur_vap_params->pureg))
    {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_PUREG,
                vap_params->pureg);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set pureg\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if ((vap_params->opmode == ACFG_OPMODE_HOSTAP) &&
            (vap_params->puren != cur_vap_params->puren))
    {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_PUREN,
                vap_params->puren);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set puren\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if ((vap_params->opmode == ACFG_OPMODE_HOSTAP) &&
            (vap_params->hide_ssid !=
             cur_vap_params->hide_ssid))
    {
            acfg_os_snprintf(acfg_hapd_param_list[index], sizeof(acfg_hapd_param_list[index]),
                    "SET ignore_broadcast_ssid %d", vap_params->hide_ssid);
            index++;
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_HIDE_SSID,
                vap_params->hide_ssid);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set hide ssid param\n");
            return QDF_STATUS_E_FAILURE;
        }

    }
    if ((vap_params->opmode == ACFG_OPMODE_HOSTAP) &&
            (vap_params->acs_6g_only_psc !=
             cur_vap_params->acs_6g_only_psc))
    {
            acfg_os_snprintf(acfg_hapd_param_list[index], sizeof(acfg_hapd_param_list[index]),
                    "SET acs_exclude_6ghz_non_psc %d", vap_params->acs_6g_only_psc);
            index++;
    }
    if ((vap_params->opmode == ACFG_OPMODE_HOSTAP) &&
        (!ACFG_STR_MATCH(vap_params->acs_freq_list, cur_vap_params->acs_freq_list)))
    {
            acfg_os_snprintf(acfg_hapd_param_list[index], sizeof(acfg_hapd_param_list[index]),
                    "SET freqlist %s", vap_params->acs_freq_list);
            index++;
    }
    if (vap_params->implicitbf != cur_vap_params->implicitbf) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_IMPLICITBF,
                vap_params->implicitbf);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set implicitbf param\n");
            return QDF_STATUS_E_FAILURE;
        }

    }
    if (vap_params->wnm != cur_vap_params->wnm) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_WNM_ENABLE,
                vap_params->wnm);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set wnm param\n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (vap_params->rrm != cur_vap_params->rrm) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_RRM_CAP,
                vap_params->rrm);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set rrm param\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->primary_vap && (vap_params->doth != cur_vap_params->doth)) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_DOTH,
                vap_params->doth);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set hide doth param\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->primary_vap && (vap_params->coext != cur_vap_params->coext)) {
        status = acfg_set_vap_param(vap_params->vap_name,
                        ACFG_PARAM_COEXT_DISABLE,
                        !vap_params->coext);
        if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set coext param\n");
                return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->client_isolation != cur_vap_params->client_isolation) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_APBRIDGE,
                !vap_params->client_isolation);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set ap bridge param\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->ampdu != cur_vap_params->ampdu) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_VAP_AMPDU,
                vap_params->ampdu);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set ampdu param\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->uapsd != cur_vap_params->uapsd) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_UAPSD,
                vap_params->uapsd);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set uapsd\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->shortgi != cur_vap_params->shortgi) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_VAP_SHORT_GI,
                vap_params->shortgi);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set shortgi\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->amsdu != cur_vap_params->amsdu) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_AMSDU,
                vap_params->amsdu);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set amsdu\n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (vap_params->vap_doth != cur_vap_params->vap_doth) {
        status = acfg_set_vap_param(vap_params->vap_name,
                                    IEEE80211_PARAM_VAP_DOTH,
                                    vap_params->vap_doth);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set vap_doth\n");
            return QDF_STATUS_E_FAILURE;
        }
    }


    if (vap_params->max_clients != cur_vap_params->max_clients) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_MAXSTA,
                vap_params->max_clients);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set max_clients\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (vap_params->atf_options != cur_vap_params->atf_options) {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_ATF_MAX_CLIENT,
                vap_params->atf_options);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set max_clients\n");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if(vap_params->opmode == ACFG_OPMODE_HOSTAP) {
        if (vap_params->primary_vap && (vap_params->greenap_ps_enable != cur_vap_params->greenap_ps_enable))
        {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_GREEN_AP_PS_ENABLE,
                    vap_params->greenap_ps_enable);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to enable GreenAP\n");
                return QDF_STATUS_E_FAILURE;
            }
        }
    }

    if(vap_params->opmode == ACFG_OPMODE_HOSTAP) {
        if (vap_params->primary_vap && (vap_params->greenap_ps_trans_time != cur_vap_params->greenap_ps_trans_time))
        {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_GREEN_AP_PS_TIMEOUT,
                    vap_params->greenap_ps_trans_time);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set GreenAP timeout\n");
                return QDF_STATUS_E_FAILURE;
            }
        }
    }

    if((vap_params->security_params.hs_iw_param.hs_enabled == 1) &&
            (vap_params->security_params.hs_iw_param.iw_enabled == 1))
    {
        acfg_set_hs_iw_vap_param(vap_params);
    }

    //Set security parameters
    if (vap_params->security_params.wps_flag == 0) {
        acfg_rem_wps_config_file(vap_params->vap_name);
    } else if (ACFG_SEC_CMP(vap_params, cur_vap_params)) {
        acfg_rem_wps_config_file(vap_params->vap_name);
    } else {
        acfg_wps_cred_t wps_cred;
        memset(&wps_cred, 0x00, sizeof(wps_cred));
        /* Check & Set default WPS dev params */
        acfg_set_wps_default_config(vap_params);
        /* Update/create the WPS config file*/
        acfg_update_wps_dev_config_file(vap_params, 0);

        wps_state = acfg_get_wps_config(vap_params->vap_name, &wps_cred);
        if (wps_state == 1) {
            status = acfg_set_wps_vap_params(vap_params, &wps_cred);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("%s: Failed to set WPS VAP params (vap=%s status=%d)!\n",
                        __func__, vap_params->vap_name, status);
                return QDF_STATUS_E_FAILURE;
            }
        }
    }

    if(vap_params->num_vendor_params != 0)
    {
        int i, j, configure;
        for(i = 0; i < vap_params->num_vendor_params; i++)
        {
            configure = 1;

            for(j = 0; j < cur_vap_params->num_vendor_params; j++)
            {
                if(vap_params->vendor_param[i].cmd ==
                        cur_vap_params->vendor_param[j].cmd)
                {
                    int len = 0;

                    if(vap_params->vendor_param[i].len == cur_vap_params->vendor_param[j].len)
                    {
                        /* Length is equal, check data */
                        len = vap_params->vendor_param[i].len;
                        if(0 == memcmp((void *)&vap_params->vendor_param[i].data,
                                    (void *)&cur_vap_params->vendor_param[j].data,
                                    len))
                        {
                            /* Data is same, No need to configure again */
                            configure = 0;
                        }
                        else
                        {
                            /* Data is different, Need to configure again */
                            configure = 1;
                        }
                    }
                }
            }
            if(configure == 1)
            {
                status = acfg_set_vap_vendor_param(vap_params->vap_name,
                        vap_params->vendor_param[i].cmd,
                        (uint8_t *)&vap_params->vendor_param[i].data,
                        vap_params->vendor_param[i].len,
                        vap_params->vendor_param[i].type,
                        0);
                if (status != QDF_STATUS_SUCCESS)
                {
                    acfg_log_errstr("Failed to set vendor param: status %d\n", status);
                    return QDF_STATUS_E_FAILURE;
                }
            }
        }
    }
    if(QDF_STATUS_SUCCESS != acfg_set_security(vap_params, cur_vap_params,
                PROFILE_MODIFY, &sec)){
        acfg_log_errstr("%s: Failed to set %s security params\n", __func__,
                vap_params->vap_name);
        return QDF_STATUS_E_FAILURE;
    }
    if (vap_params->security_params.sec_method !=
            cur_vap_params->security_params.sec_method && (sec != 1))
    {
        if (vap_params->security_params.sec_method ==
                ACFG_WLAN_PROFILE_SEC_METH_SHARED)
        {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_AUTHMODE, 2);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed Set vap param\n");
                return QDF_STATUS_E_FAILURE;
            }
            enablewep = 1;
        } else if (vap_params->security_params.sec_method ==
                ACFG_WLAN_PROFILE_SEC_METH_AUTO)
        {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_AUTHMODE, 4);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed Set vap param\n");
                return QDF_STATUS_E_FAILURE;
            }
            enablewep = 1;
        } else if (vap_params->security_params.sec_method ==
                ACFG_WLAN_PROFILE_SEC_METH_OPEN)
        {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_AUTHMODE, 1);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed Set vap param\n");
                return QDF_STATUS_E_FAILURE;
            }
            enablewep = 1;
        } else if (vap_params->security_params.sec_method >=
                ACFG_WLAN_PROFILE_SEC_METH_INVALID)
        {
            acfg_log_errstr("Invalid Security Method \n\r");
            return QDF_STATUS_E_FAILURE;
        }
    }
    set_wep = ((vap_params->security_params.cipher_method ==
                ACFG_WLAN_PROFILE_CIPHER_METH_WEP) &&
            ((vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_OPEN) ||
             (vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_SHARED) ||
             (vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_AUTO)));
    if (set_wep)
    {
        int flag = 0;
        if (vap_params->security_params.cipher_method !=
                cur_vap_params->security_params.cipher_method)
        {
            enablewep = 1;
            setssid = 1;
        }

        if (!ACFG_STR_MATCH(vap_params->security_params.wep_key0,
                    cur_vap_params->security_params.wep_key0) ||
                enablewep)
        {
            if (vap_params->security_params.wep_key0[0] != '\0') {
                flag = 1;
                status = acfg_set_enc(vap_params->vap_name, flag,
                                        vap_params->security_params.wep_key0);
                if (status != QDF_STATUS_SUCCESS) {
                    acfg_log_errstr("Failed to set enc\n");
                    return QDF_STATUS_E_FAILURE;
                }
            }
            setssid = 1;
        }
        if (!ACFG_STR_MATCH(vap_params->security_params.wep_key1,
                    cur_vap_params->security_params.wep_key1) ||
                enablewep)
        {
            if(vap_params->security_params.wep_key1[0] != '\0') {
                flag = 2;
                status = acfg_set_enc(vap_params->vap_name, flag,
                                        vap_params->security_params.wep_key1);
                if (status != QDF_STATUS_SUCCESS) {
                    acfg_log_errstr("Failed to set enc\n");
                    return QDF_STATUS_E_FAILURE;
                }
            }
            setssid = 1;
        }
        if (!ACFG_STR_MATCH(vap_params->security_params.wep_key2,
                    cur_vap_params->security_params.wep_key2) ||
                enablewep)
        {
            if(vap_params->security_params.wep_key2[0] != '\0') {
                flag = 3;
                status = acfg_set_enc(vap_params->vap_name, flag,
                                        vap_params->security_params.wep_key2);
                if (status != QDF_STATUS_SUCCESS) {
                    acfg_log_errstr("Failed to set enc\n");
                    return QDF_STATUS_E_FAILURE;
                }
            }
            setssid = 1;
        }
        if (!ACFG_STR_MATCH(vap_params->security_params.wep_key3,
                    cur_vap_params->security_params.wep_key3) ||
                enablewep)
        {
            if(vap_params->security_params.wep_key3[0] != '\0') {
                flag = 4;
                status = acfg_set_enc(vap_params->vap_name, flag,
                                        vap_params->security_params.wep_key3);
                if (status != QDF_STATUS_SUCCESS) {
                    acfg_log_errstr("Failed to set enc\n");
                    return QDF_STATUS_E_FAILURE;
                }
            }
            setssid = 1;
        }
        //Set default key idx
        if ((vap_params->security_params.wep_key_defidx != 0)) {
            if ((vap_params->security_params.wep_key_defidx !=
                        cur_vap_params->security_params.wep_key_defidx) ||
                    enablewep)
            {
                flag = vap_params->security_params.wep_key_defidx;
                status = acfg_set_enc(vap_params->vap_name, flag, 0);
                if (status != QDF_STATUS_SUCCESS) {
                    acfg_log_errstr("Failed to set enc\n");
                    return QDF_STATUS_E_FAILURE;
                }
                setssid = 1;
            }
        }
    }
    if((vap_params->security_params.sec_method ==
                ACFG_WLAN_PROFILE_SEC_METH_OPEN) && (sec != 1))
    {
        if (vap_params->security_params.sec_method !=
                cur_vap_params->security_params.sec_method)
        {
            if (vap_params->security_params.cipher_method ==
                    ACFG_WLAN_PROFILE_CIPHER_METH_NONE)
            {
                set_open = 1;
            }
        }
        if (vap_params->security_params.cipher_method !=
                cur_vap_params->security_params.cipher_method)
        {
            if (vap_params->security_params.cipher_method ==
                    ACFG_WLAN_PROFILE_CIPHER_METH_NONE)
            {
                set_open = 1;
            }
        }
        if (set_open) {
            status = acfg_set_auth_open(vap_params, ACFG_SEC_DISABLE_SECURITY);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("%s: Failed to set auth to open (vap=%s status=%d)!\n",
                        __func__, vap_params->vap_name, status);
                return QDF_STATUS_E_FAILURE;
            }
        }
        if (vap_params->security_params.sec_method !=
                cur_vap_params->security_params.sec_method)
        {
            setssid = 1;
        }
        if(strlen (vap_params->security_params.owe_transition_ssid)) {
           if (strlen (vap_params->security_params.owe_transition_ssid) <= ACFG_MAX_SSID_LEN) {
               uint8_t vendorie_buf[45];
               uint8_t vendorie_len = 6;
               vendorie_buf[0] = 0xdd;
               /* buf[1]=11 (4 - OUI + 6 - BSSID + 1 - owe_transition ssid len) */
               vendorie_buf[1] = 11;
               /* Wifi Alliance OUI 0x506f9a1c */
               vendorie_buf[2] = 0x50;
               vendorie_buf[3] = 0x6f;
               vendorie_buf[4] = 0x9a;
               vendorie_buf[5] = 0x1c;
               acfg_mac_str_to_octet((uint8_t*)vap_params->security_params.owe_transition_bssid, (uint8_t*)(vendorie_buf + 6));
               vendorie_buf[12] = strlen (vap_params->security_params.owe_transition_ssid);
               memcpy((uint8_t *)(vendorie_buf+13), vap_params->security_params.owe_transition_ssid, vendorie_buf[12]);
               vendorie_buf[1] += vendorie_buf[12];
               vendorie_len = vendorie_buf[1] + 2;
               acfg_add_app_ie(vap_params->vap_name, vendorie_buf, vendorie_len);
           }
           else {
               acfg_log_errstr("%s: Exceeded max SSID length\n", __func__);
               return QDF_STATUS_E_FAILURE;
           }
        }
    }
    if ((vap_params->opmode == ACFG_OPMODE_STA) &&
            ((vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_OPEN) ||
             (vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_SHARED) ||
             (vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_AUTO)) &&
            (vap_params->wds_params.enabled == 1))
    {
        if ((!ACFG_STR_MATCH(vap_params->wds_params.wds_addr,
                        cur_vap_params->wds_params.wds_addr)) && \
                (vap_params->wds_params.wds_addr[0] != 0))
        {
            acfg_mac_str_to_octet(vap_params->wds_params.wds_addr, mac);

            status = acfg_set_ap(vap_params->vap_name, mac);

            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set ROOTAP MAC\n");
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    if(((vap_params->txpow != cur_vap_params->txpow) ||
        (vap_params->fstype != cur_vap_params->fstype)) &&
        (vap_params->opmode == ACFG_OPMODE_HOSTAP)) {

        if (vap_params->txpow == (uint32_t)-1) {
            acfg_log_errstr("Failed to set txpower.txpower is unspec\n");
            return QDF_STATUS_E_FAILURE;
        }

        if (vap_params->fstype == (uint32_t)-1) {
            acfg_log_errstr("Failed to set txpower.fstype is unspec\n");
            return QDF_STATUS_E_FAILURE;
        }
        status = acfg_set_txpow(vap_params->vap_name,
                &vap_params->txpow, vap_params->fstype);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set txpower\n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (vap_params->vlanid != cur_vap_params->vlanid) {
        if ((cur_vap_params->vlanid == 0) && (vap_params->vlanid != 0)) {
            status = acfg_wlan_vap_profile_vlan_add(vap_params);
            if(status != QDF_STATUS_SUCCESS){
                acfg_log_errstr("Failed to add %s to vlan\n", vap_params->vap_name);
                return QDF_STATUS_E_FAILURE;
            }
        } else if ((cur_vap_params->vlanid != 0) && (vap_params->vlanid == 0)) {
            acfg_wlan_vap_profile_vlan_remove(cur_vap_params);
        } else {
            acfg_wlan_vap_profile_vlan_remove(cur_vap_params);
            status = acfg_wlan_vap_profile_vlan_add(vap_params);
            if(status != QDF_STATUS_SUCCESS){
                acfg_log_errstr("Failed to add %s to vlan\n", vap_params->vap_name);
                return QDF_STATUS_E_FAILURE;
            }
        }
    }

    /* 6GHz Security Compliance */
    if (vap_params->sec_comp_6g != cur_vap_params->sec_comp_6g)
    {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_6G_SECURITY_COMP,
                vap_params->sec_comp_6g);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set en_6g_sec_comp \n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (!vap_params->sec_comp_6g && (vap_params->keymgmt_mask_6g != cur_vap_params->keymgmt_mask_6g))
    {
        status = acfg_set_vap_param(vap_params->vap_name,
                ACFG_PARAM_6G_KEYMGMT_MASK,
                vap_params->keymgmt_mask_6g);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set keymgmt_mask_6g \n");
            return QDF_STATUS_E_FAILURE;
        }
    }

    //Set the ssid if in Station mode and security mode is open or wep
    if ((vap_params->opmode == ACFG_OPMODE_STA) && (setssid) &&
            ((vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_OPEN) ||
             (vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_SHARED) ||
             (vap_params->security_params.sec_method ==
              ACFG_WLAN_PROFILE_SEC_METH_AUTO)))
    {
        acfg_os_strcpy((char *)ssid.ssid, vap_params->ssid,
                       (ACFG_MAX_SSID_LEN + 1));
        status = acfg_set_ssid(vap_params->vap_name, &ssid);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to set the SSID\n");
            return QDF_STATUS_E_FAILURE;
        }
    }

#if QCA_AIRTIME_FAIRNESS
    status = acfg_vap_configure_atf(vap_params, cur_vap_params);
#endif
    if (vap_params->opmode == ACFG_OPMODE_HOSTAP) {
        for (k = 0; k < index; k++) {
            if((acfg_ctrl_req (vap_params->vap_name,
                            acfg_hapd_param_list[k],
                            strlen(acfg_hapd_param_list[k]),
                            replybuf, &len,
                            ACFG_OPMODE_HOSTAP) < 0) ||
                    strncmp (replybuf, "OK", strlen("OK"))){
                acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                        acfg_hapd_param_list[k],
                        vap_params->vap_name);
                return QDF_STATUS_E_FAILURE;
            }
        }
    }

    return status;
}

uint32_t
acfg_wlan_vap_profile_delete(acfg_wlan_profile_vap_params_t *vap_params)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    uint8_t *vapname = vap_params->vap_name;
    char *radioname = vap_params->radio_name;
    int8_t sec;

    status = acfg_get_opmode(vap_params->vap_name,
            &vap_params->opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", vap_params->vap_name);
    }

    if(acfg_set_security(vap_params, NULL,
                PROFILE_DELETE, &sec) != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Failed to delete %s security params\n", __func__,
                vap_params->vap_name);
        return QDF_STATUS_E_INVAL;
    }

    if( (*vapname) && (*radioname)) {

        status = acfg_wlan_iface_present(radioname);

        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Radio Interface not present %d \n",  status);
            return QDF_STATUS_E_INVAL;
        }

        status = acfg_wlan_iface_present((char *)vapname);

        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Vap is Not Present!!\n");
            return QDF_STATUS_E_FAILURE;
        }

        status = acfg_delete_vap((uint8_t *)radioname, vapname);

        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("Failed to delete vap!\n\a\a");
        }
    }
    return status;
}

void
acfg_mac_to_str(uint8_t *addr, char *str, uint16_t str_max_len)
{
    acfg_os_snprintf(str, str_max_len, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0],
             addr[1],
             addr[2],
             addr[3],
             addr[4],
             addr[5]);
}

void acfg_set_vap_list(acfg_wlan_profile_t *new_profile,
        acfg_wlan_profile_t *cur_profile,
        acfg_wlan_profile_vap_list_t *create_list,
        acfg_wlan_profile_vap_list_t *delete_list,
        acfg_wlan_profile_vap_list_t *modify_list)
{
    uint8_t num_new_vap = 0, num_cur_vap = 0;
    acfg_wlan_profile_vap_params_t *vap_param;
    uint8_t vap_matched = 0;

    if (cur_profile == NULL) {
        acfg_log_errstr("%s()- Error !!Current profile cannot be NULL \n\r",__func__);
        return;
    }
    for (num_new_vap = 0; num_new_vap < new_profile->num_vaps;
            num_new_vap++)
    {
        vap_param = &new_profile->vap_params[num_new_vap];
        vap_matched = 0;
        for (num_cur_vap = 0; num_cur_vap < cur_profile->num_vaps;
                num_cur_vap++)
        {
            if (ACFG_STR_MATCH(vap_param->vap_name,
                        cur_profile->vap_params[num_cur_vap].vap_name))
            {
                //put it to modify list
                modify_list->new_vap_idx[modify_list->num_vaps] = num_new_vap;
                modify_list->cur_vap_idx[modify_list->num_vaps] = num_cur_vap;
                modify_list->num_vaps++;
                vap_matched = 1;
                break;
            }
        }
        if (vap_matched == 0) {
            if(vap_param->vap_name[0] == '\0')
                continue;
            //put it to create list
            create_list->new_vap_idx[create_list->num_vaps] = num_new_vap;
            create_list->num_vaps++;
            modify_list->new_vap_idx[modify_list->num_vaps] = num_new_vap;
            modify_list->cur_vap_idx[modify_list->num_vaps] = num_new_vap;
            modify_list->num_vaps++;
        }
    }
    //Check if any vap has to be deleted
    for (num_cur_vap = 0; num_cur_vap < cur_profile->num_vaps;
            num_cur_vap++)
    {
        vap_param = &cur_profile->vap_params[num_cur_vap];
        vap_matched = 0;
        for (num_new_vap = 0; num_new_vap < new_profile->num_vaps;
                num_new_vap++)
        {
            if (ACFG_STR_MATCH(vap_param->vap_name, new_profile->vap_params[num_new_vap].vap_name))
            {
                vap_matched = 1;
                break;
            }

        }
        if (vap_matched == 0) {
            //put it to delete list
            delete_list->cur_vap_idx[delete_list->num_vaps] = num_cur_vap;
            delete_list->num_vaps++;
        }
    }
}

uint32_t
acfg_create_vaps(acfg_wlan_profile_vap_list_t *create_list, acfg_wlan_profile_t *new_profile)
{
    uint8_t i, vap_index;
    acfg_wlan_profile_vap_params_t *vap_profile;
    uint32_t status = QDF_STATUS_SUCCESS;

    /* Create STA vaps first */
    for (i = 0; i < create_list->num_vaps; i++) {
        vap_index = create_list->new_vap_idx[i];
        vap_profile = &new_profile->vap_params[vap_index];
        if(vap_profile->opmode == ACFG_OPMODE_STA)
        {
            status = acfg_wlan_vap_create(vap_profile,
                    new_profile->radio_params);

            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("%s: Failed to create STA VAP (vap=%s status=%d)!\n",
                        __func__, vap_profile->vap_name, status);
                break;
            }
        }
    }
    /* Create AP vaps now */
    for (i = 0; i < create_list->num_vaps; i++) {
        vap_index = create_list->new_vap_idx[i];
        vap_profile = &new_profile->vap_params[vap_index];
        if(vap_profile->opmode != ACFG_OPMODE_STA)
        {
            status = acfg_wlan_vap_create(vap_profile,
                    new_profile->radio_params);

            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("%s: Failed to create AP VAP (vap=%s status=%d)!\n",
                        __func__, vap_profile->vap_name, status);
                break;
            }
        }
    }
    return status;
}

/* Function common to modify and restore operation.
 * (*num_vaps_modified) should be set to a value > 0
 * by caller for restore operation.
 * (*num_vaps_modified) returns num vaps successfully
 * modified on normal modify operation. */

static uint32_t
acfg_iterate_vap_list_and_modify(acfg_wlan_profile_vap_list_t *modify_list,
        acfg_wlan_profile_t *new_profile,
        acfg_wlan_profile_t *cur_profile,
        acfg_opmode_t opmode,
        uint8_t *num_vaps_modified)
{
    uint32_t restore_status = QDF_STATUS_SUCCESS, status = QDF_STATUS_SUCCESS;
    uint8_t restore_requested = 0;
    uint8_t num_vaps_to_restore = 0;
    uint8_t vap_index;
    uint8_t new_vap_index, cur_vap_index;
    acfg_wlan_profile_vap_params_t *new_vap_profile, *cur_vap_profile;

    if(*num_vaps_modified)
    {
        restore_requested = 1;
        num_vaps_to_restore = *num_vaps_modified;
        *num_vaps_modified = 0;
    }

    for (vap_index = 0; vap_index < modify_list->num_vaps; vap_index++) {
        new_vap_index = modify_list->new_vap_idx[vap_index];
        cur_vap_index = modify_list->cur_vap_idx[vap_index];

        if(restore_requested) {
            new_vap_profile = &cur_profile->vap_params[cur_vap_index];
            cur_vap_profile = &new_profile->vap_params[new_vap_index];
        }
        else {
            new_vap_profile = &new_profile->vap_params[new_vap_index];
            cur_vap_profile = &cur_profile->vap_params[cur_vap_index];
        }

        if(new_vap_profile->opmode == opmode) {
            status = acfg_wlan_vap_profile_modify(new_vap_profile, cur_vap_profile,
                    new_profile->radio_params);
            if (status != QDF_STATUS_SUCCESS)
            {
                acfg_log_errstr("%s: Failed to modify VAP profile (vap=%s status=%d)!\n",
                        __func__, new_vap_profile->vap_name, status);
                if(restore_requested)
                    restore_status = QDF_STATUS_E_FAILURE;
                else
                    return status;
            }

            (*num_vaps_modified)++;

            if((num_vaps_to_restore == (vap_index + 1)) && restore_requested)
            {
                status = restore_status;
                break;
            }
        }
    }

    return status;
}

uint32_t
acfg_modify_profile(acfg_wlan_profile_vap_list_t *modify_list, acfg_wlan_profile_t *new_profile,
        acfg_wlan_profile_t *cur_profile, int *sec)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    uint8_t num_ap_vaps = 0, num_sta_vaps = 0;

    *sec = 0;

    /* Bring up STA vaps first */
    status = acfg_iterate_vap_list_and_modify(modify_list,
            new_profile,
            cur_profile,
            ACFG_OPMODE_STA,
            &num_sta_vaps);
    if(status != QDF_STATUS_SUCCESS)
    {
        /* There is no need of restore operation here,
         * as this is the first vap modified */
        acfg_log_errstr("%s: Failed to modify STA VAP!\n", __func__);
        return status;
    }

    /* Bring up AP vaps now */
    status = acfg_iterate_vap_list_and_modify(modify_list,
            new_profile,
            cur_profile,
            ACFG_OPMODE_HOSTAP,
            &num_ap_vaps);
    if(status != QDF_STATUS_SUCCESS)
    {
        acfg_log_errstr("%s: Failed to modify AP VAP!\n", __func__);
        /* Restore any VAPs which are modified,
         * This is done to be in sync with config file*/
        if(num_sta_vaps)
        {
            status = acfg_iterate_vap_list_and_modify(modify_list,
                    new_profile,
                    cur_profile,
                    ACFG_OPMODE_STA,
                    &num_sta_vaps);
            if(status !=QDF_STATUS_SUCCESS) {
                acfg_log_errstr("***** Restoring STA vap: failed \n");
            }
            else {
                acfg_log_errstr("***** Restoring STA vap: success\n");
            }
        }
        if(num_ap_vaps)
        {
            status = acfg_iterate_vap_list_and_modify(modify_list,
                    new_profile,
                    cur_profile,
                    ACFG_OPMODE_HOSTAP,
                    &num_ap_vaps);
            if(status !=QDF_STATUS_SUCCESS) {
                acfg_log_errstr("***** Restoring AP vaps: failed \n");
            }
            else {
                acfg_log_errstr("***** Restoring AP vaps: success\n");
            }
        }
        status = QDF_STATUS_E_FAILURE;
        return status;
    }

    *sec = 1;
    return status;
}

uint32_t
acfg_set_vap_profile(acfg_wlan_profile_t *new_profile,
        acfg_wlan_profile_t *cur_profile,
        acfg_wlan_profile_vap_list_t *create_list,
        acfg_wlan_profile_vap_list_t *delete_list,
        acfg_wlan_profile_vap_list_t *modify_list)
{
    uint8_t i, vap_index;
    uint32_t send_wps_event = 0;
    acfg_wlan_profile_vap_params_t *vap_profile;
    acfg_wlan_profile_vap_params_t *cur_vap_params, *new_vap_params;
    uint32_t status = QDF_STATUS_SUCCESS;
    int sec;

    //Delete Vaps
    for (i = 0; i < delete_list->num_vaps; i++) {
        vap_index = delete_list->cur_vap_idx[i];
        vap_profile = &cur_profile->vap_params[vap_index];
        status = acfg_wlan_vap_profile_delete(vap_profile);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("%s: Failed to delete profile (status=%d)!\n", __func__, status);
            return status;
        }
        new_profile->num_vaps--;
        if (ACFG_IS_VALID_WPS(vap_profile->security_params)) {
            send_wps_event = 1;
        }
        if (ACFG_IS_SEC_ENABLED(vap_profile->security_params.sec_method)) {
            send_wps_event = 1;
        }
    }

    if (cur_profile == NULL) {
        goto done;
    }

    if (cur_profile->num_vaps == delete_list->num_vaps) {
        if (create_list->num_vaps > 0) {
            /*
             * If number of vaps to be deleted is equal to number of current vaps
             * then reset the radio profile params only if there are some vaps to
             * be created.
             */

            acfg_init_radio_params(&cur_profile->radio_params);
            status = acfg_set_radio_profile(&new_profile->radio_params,
                                            &cur_profile->radio_params);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("%s: Failed to set radio profile (status=%d)!\n", __func__, status);
                return status;
            }
        } else {
            /* If the number of vaps to be created is 0, reset the new_profile so
             * that the radio params are reseted next time when the new vap is created.
             */
            acfg_init_radio_params(&new_profile->radio_params);
        }
    }

    /*Enable radio before creating VAPs*/
    status = acfg_set_radio_enable((uint8_t *)new_profile->radio_params.radio_name);
    if(status != QDF_STATUS_SUCCESS) {
        acfg_print("%s: Failed to bring Radio-%s up (status=%d)!\n",
                __func__, new_profile->radio_params.radio_name, status);
        return QDF_STATUS_E_FAILURE;
    }

    //Create vaps
    status = acfg_create_vaps(create_list, new_profile);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Failed to create profile (status=%d)!\n", __func__, status);
        return status;
    }

    for (i = 0; i < create_list->num_vaps; i++) {
        if(i <ACFG_MAX_VAPS){
            vap_index = create_list->new_vap_idx[i];
            cur_vap_params = &cur_profile->vap_params[vap_index];
            new_vap_params = &new_profile->vap_params[vap_index];
            cur_vap_params->opmode = new_vap_params->opmode;
            cur_vap_params->default_params_set = 1;
        } else{
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (cur_profile == NULL) {
        goto done;
    }

    //modify vaps
    status = acfg_modify_profile(modify_list, new_profile, cur_profile, &sec);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Failed to create/modify profile (status=%d)!\n", __func__, status);
        return status;
    }
    if (sec == 1) {
        send_wps_event =1;
    }
done:
    if (send_wps_event) {
        acfg_send_interface_event(ACFG_APP_EVENT_INTERFACE_MOD,
                strlen(ACFG_APP_EVENT_INTERFACE_MOD));
    }
    return status;
}

uint32_t acfg_bringup_vaps(acfg_wlan_profile_t *profile,
                             acfg_opmode_t opmode)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    uint8_t i;
    acfg_wlan_profile_vap_params_t *vap_params;

    for (i = 0; i < profile->num_vaps; i++) {
        vap_params = &profile->vap_params[i];
        if ((vap_params->opmode != opmode) ||
                (*vap_params->vap_name == '\0')) {
            continue;
        }
        /*Set phymode before bringing up VAP, in order to get correct
         * phymode from cfg80211_start_ap*/
        status = acfg_set_phymode(vap_params->vap_name,
                vap_params->phymode);
        if(status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
        status = acfg_wlan_iface_up(vap_params->vap_name, vap_params);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("%s: Failed to bring VAP up (vap=%s status=%d)!\n",
                            __func__, vap_params->vap_name, status);
            return QDF_STATUS_E_FAILURE;
        }
    }

    return status;
}

uint32_t acfg_bringdown_vaps(acfg_wlan_profile_t *profile,
        acfg_opmode_t opmode)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    uint8_t i;
    acfg_wlan_profile_vap_params_t *vap_params;

    for (i = 0; i < profile->num_vaps; i++) {
        vap_params = &profile->vap_params[i];
        if ((vap_params->opmode != opmode) ||
                (*vap_params->vap_name == '\0')) {
            continue;
        }
        status = acfg_wlan_iface_down(vap_params->vap_name, vap_params);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("%s: Failed to bring VAP down (vap=%s status=%d)!\n",
                    __func__, vap_params->vap_name, status);
            return QDF_STATUS_E_FAILURE;
        }
    }

    return status;
}

uint32_t acfg_set_radio_profile_chan(acfg_wlan_profile_radio_params_t
        *radio_params,
        acfg_wlan_profile_radio_params_t
        *cur_radio_params,
        acfg_wlan_profile_t *profile,
        acfg_wlan_profile_t *cur_profile)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    uint8_t i;
    acfg_wlan_profile_vap_params_t *vap_params;

    if ((radio_params->beacon_burst_mode != cur_radio_params->beacon_burst_mode) ||
         (radio_params->chan != cur_radio_params->chan) ||
         (radio_params->chan_band != cur_radio_params->chan_band) ||
         (radio_params->preCAC != cur_radio_params->preCAC) ||
         (profile->num_vaps > 0 && cur_profile->num_vaps == 0)) {

        for (i = 0; i < profile->num_vaps; i++) {
            vap_params = &profile->vap_params[i];
            if (vap_params->vap_name[0] == '\0')
                continue;

            if (vap_params->opmode == ACFG_OPMODE_STA)
                continue;

            if (!vap_params->radio_params->chan)
                continue;

            status = acfg_set_channel(vap_params->vap_name,
                                      vap_params->radio_params->chan,
                                      vap_params->radio_params->chan_band);
            if (status != QDF_STATUS_SUCCESS)
                return QDF_STATUS_E_FAILURE;
            break;
        }

        /*
         * Introduce delay before disabling hostapd to get response
         * from driver(if any) for previouly sent cmds
         */
        sleep(1);
        status = acfg_bringdown_vaps(profile, ACFG_OPMODE_HOSTAP);
        if(status != QDF_STATUS_SUCCESS) {
            acfg_log_errstr("%s: Failed to bring AP VAPs down (status=%d)!\n",
                    __func__, status);
            return QDF_STATUS_E_FAILURE;
        }
    }

    for (i = 0; i < profile->num_vaps; i++) {
        acfg_wlan_profile_vap_params_t *cur_vap_params;

        vap_params = &profile->vap_params[i];
        cur_vap_params = &cur_profile->vap_params[i];

        if (vap_params->vap_name[0] == '\0')
                continue;

        if ((vap_params->opmode == ACFG_OPMODE_HOSTAP) &&
                (vap_params->bcn_rate != cur_vap_params->bcn_rate )) {
            status = acfg_set_vap_param(vap_params->vap_name,
                    ACFG_PARAM_MODIFY_BEACON_RATE,
                    vap_params->bcn_rate);
            if (status != QDF_STATUS_SUCCESS) {
                acfg_log_errstr("Failed to set bcn_rate param\n");
                return QDF_STATUS_E_FAILURE;
            }
        }
    }

    /* First bring STA VAP up */
    status = acfg_bringup_vaps(profile, ACFG_OPMODE_STA);
    if(status != QDF_STATUS_SUCCESS) {
      acfg_log_errstr("%s: Failed to bring STA VAPs up (status=%d)!\n",
                      __func__, status);
      return QDF_STATUS_E_FAILURE;
    }
    /* Bring AP VAPs up */
    status = acfg_bringup_vaps(profile, ACFG_OPMODE_HOSTAP);
    if(status != QDF_STATUS_SUCCESS) {
      acfg_log_errstr("%s: Failed to bring AP VAPs up (status=%d)!\n",
                      __func__, status);
      return QDF_STATUS_E_FAILURE;

    }

    return status;
}

uint32_t acfg_set_radio_profile(acfg_wlan_profile_radio_params_t
        *radio_params,
        acfg_wlan_profile_radio_params_t
        *cur_radio_params)
{
    uint32_t status = QDF_STATUS_SUCCESS;

    status = acfg_wlan_iface_present((char *)radio_params->radio_name);
    if(status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("Radio not present\n");
        return QDF_STATUS_E_INVAL;
    }
    if (!ACFG_STR_MATCH((char *)radio_params->radio_mac,
                (char *)cur_radio_params->radio_mac)) {
        status = acfg_set_ifmac ((char *)radio_params->radio_name,
                (char *)radio_params->radio_mac,
                ARPHRD_IEEE80211);
        if (status != QDF_STATUS_SUCCESS) {
            //return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->country_code != cur_radio_params->country_code) {
        if(radio_params->country_code != 0) {
            status = acfg_set_radio_param(radio_params->radio_name,
                    ACFG_PARAM_RADIO_COUNTRYID,
                    radio_params->country_code);
            if (status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    if (radio_params->tpscale != cur_radio_params->tpscale) {
            status = acfg_set_radio_param(radio_params->radio_name,
                    (OL_ATH_PARAM_SHIFT | OL_ATH_PARAM_TXPOWER_SCALE),
                    radio_params->tpscale);
            if (status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
    }
    if (radio_params->ampdu != cur_radio_params->ampdu) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_AMPDU,
                !!radio_params->ampdu);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->ampdu_limit_bytes !=
            cur_radio_params->ampdu_limit_bytes)
    {
        if (radio_params->ampdu_limit_bytes) {
            status = acfg_set_radio_param(radio_params->radio_name,
                    ACFG_PARAM_RADIO_AMPDU_LIMIT,
                    radio_params->ampdu_limit_bytes);
            if (status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
        else {
            acfg_log_errstr("Invalid value for ampdu limit \n\r");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->ampdu_subframes != cur_radio_params->ampdu_subframes)
    {
        if (radio_params->ampdu_subframes) {
            status = acfg_set_radio_param(radio_params->radio_name,
                    ACFG_PARAM_RADIO_AMPDU_SUBFRAMES,
                    radio_params->ampdu_subframes);
            if (status != QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
        }
        else {
            acfg_log_errstr("Invalid value for ampdu subframes \n\r");
            return QDF_STATUS_E_FAILURE;
        }
    }
    if(radio_params->macreq_enabled != cur_radio_params->macreq_enabled)
    {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_ENABLE_MAC_REQ,
                radio_params->macreq_enabled);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->aggr_burst != cur_radio_params->aggr_burst) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_AGGR_BURST,
                radio_params->aggr_burst);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->aggr_burst_dur != cur_radio_params->aggr_burst_dur) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_AGGR_BURST_DUR,
                radio_params->aggr_burst_dur);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->ccathena != cur_radio_params->ccathena) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_HAL_CONFIG_ENABLEADAPTIVECCATHRES,
                radio_params->ccathena);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->cca_det_level != cur_radio_params->cca_det_level) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_HAL_CONFIG_CCA_DETECTION_LEVEL,
                radio_params->cca_det_level);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->cca_det_margin != cur_radio_params->cca_det_margin) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_HAL_CONFIG_CCA_DETECTION_MARGIN,
                radio_params->cca_det_margin);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->beacon_burst_mode != cur_radio_params->beacon_burst_mode) {
        status = acfg_set_radio_param( radio_params->radio_name,
                ACFG_PARAM_RADIO_BEACON_BURST_MODE,
                radio_params->beacon_burst_mode );
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->sta_dfs_enable != cur_radio_params->sta_dfs_enable) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_STADFS_ENABLE,
                radio_params->sta_dfs_enable);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->atf_strict_sched != cur_radio_params->atf_strict_sched) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_ATF_STRICT_SCHED,
                !!(radio_params->atf_strict_sched & ACFG_FLAG_ATF_STRICT_SCHED));
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_ATF_OBSS_SCHED,
                !!(radio_params->atf_strict_sched & ACFG_FLAG_ATF_OBSS_SCHED));
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->preCAC != cur_radio_params->preCAC) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_PRECAC_ENABLE,
                radio_params->preCAC);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->interCACChan != cur_radio_params->interCACChan) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_PRECAC_INTER_CHANNEL,
                radio_params->interCACChan);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->preCACtimeout != cur_radio_params->preCACtimeout) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_PRECAC_TIMEOUT,
                radio_params->preCACtimeout);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    if (radio_params->dbdc_enable != cur_radio_params->dbdc_enable) {
        status = acfg_set_radio_param(radio_params->radio_name,
                ACFG_PARAM_RADIO_DBDC_ENABLE,
                radio_params->dbdc_enable);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }

    if (radio_params->rpt_max_phy != cur_radio_params->rpt_max_phy) {
        status = acfg_set_radio_param(radio_params->radio_name,
                                      (OL_ATH_PARAM_SHIFT |
                                      OL_ATH_PARAM_RPT_MAX_PHY),
                                      radio_params->rpt_max_phy);
        if (status != QDF_STATUS_SUCCESS)
            return QDF_STATUS_E_FAILURE;
    }

    if (radio_params->scan_over_cac != cur_radio_params->scan_over_cac) {
        status = acfg_set_radio_param(radio_params->radio_name,
                                      (OL_ATH_PARAM_SHIFT |
                                      OL_ATH_SCAN_OVER_CAC),
                                      radio_params->scan_over_cac);
        if (status != QDF_STATUS_SUCCESS)
            return QDF_STATUS_E_FAILURE;
    }

    if (radio_params->acs_pcaconly != cur_radio_params->acs_pcaconly) {
        status = acfg_set_radio_param(radio_params->radio_name,
                                      (OL_ATH_PARAM_SHIFT |
                                      OL_ATH_PARAM_ACS_PRECAC_SUPPORT),
                                      radio_params->acs_pcaconly);
        if (status != QDF_STATUS_SUCCESS)
            return QDF_STATUS_E_FAILURE;
    }

    if (radio_params->dcs_enable != cur_radio_params->dcs_enable) {
        status = acfg_set_radio_param(radio_params->radio_name,
                                      ACFG_PARAM_RADIO_DCS_ENABLE,
                                      radio_params->dcs_enable);
    if (status != QDF_STATUS_SUCCESS)
        return QDF_STATUS_E_FAILURE;
    }

    return status;
}

void
acfg_init_profile(acfg_wlan_profile_t *profile)
{
    acfg_wlan_profile_radio_params_t *radio_params;
    acfg_wlan_profile_vap_params_t *vap_params;
    int i;

    profile->acfg_standard = 1;
    radio_params = &profile->radio_params;
    acfg_init_radio_params (radio_params);
    for(i = 0; i < ACFG_MAX_VAPS; i++) {
        vap_params = &profile->vap_params[i];
        acfg_init_vap_params (vap_params);
   }
}

void
acfg_init_radio_params (acfg_wlan_profile_radio_params_t *unspec_radio_params)
{
    unspec_radio_params->chan = 0;
    unspec_radio_params->chan_band = 0;
    unspec_radio_params->freq = 0;
    unspec_radio_params->country_code = 0;
    unspec_radio_params->tpscale = 0;
    memset(unspec_radio_params->radio_mac, 0, ACFG_MACSTR_LEN);
    unspec_radio_params->macreq_enabled = 0xff;
    unspec_radio_params->ampdu = -1;
    unspec_radio_params->ampdu_limit_bytes = 0;
    unspec_radio_params->ampdu_subframes = 0;
    unspec_radio_params->aggr_burst = -1;
    unspec_radio_params->aggr_burst_dur = 0;
    unspec_radio_params->sta_dfs_enable = 0;
    unspec_radio_params->atf_strict_sched = -1;
    unspec_radio_params->ccathena = 0;
    unspec_radio_params->cca_det_level = -70;
    unspec_radio_params->cca_det_margin = 3;
    unspec_radio_params->preCAC = 0;
    unspec_radio_params->interCACChan = 0;
    unspec_radio_params->preCACtimeout = 60;
    unspec_radio_params->dbdc_enable = 1;
    unspec_radio_params->acs_pcaconly = 0;
    unspec_radio_params->rpt_max_phy = 0;
    unspec_radio_params->scan_over_cac = -1;
    unspec_radio_params->dcs_enable = 0;
}

void
acfg_init_vap_params (acfg_wlan_profile_vap_params_t *unspec_vap_params)
{
    acfg_wlan_profile_node_params_t *unspec_node_params;
    acfg_wds_params_t *unspec_wds_params;
    acfg_wlan_profile_security_params_t *unspec_security_params;
    acfg_wlan_profile_sec_eap_params_t *unspec_eap_params;
    acfg_wlan_profile_sec_radius_params_t *unspec_radius_params;
    acfg_wlan_profile_sec_acct_server_params_t *unspec_acct_params;
    acfg_wlan_profile_sec_hs_iw_param_t *unspec_hs_params;
    int j;
    memset(unspec_vap_params->vap_name, 0, ACFG_MAX_IFNAME);
    unspec_vap_params->vap_name[0]='\0';
    memset(unspec_vap_params->radio_name, 0, ACFG_MAX_IFNAME);
    unspec_vap_params->opmode = ACFG_OPMODE_INVALID;
    unspec_vap_params->vapid = 0xffffffff;
    unspec_vap_params->phymode = ACFG_PHYMODE_INVALID;
    unspec_vap_params->ampdu = -1;
    memset(unspec_vap_params->ssid, 0, (ACFG_MAX_SSID_LEN + 1));
    unspec_vap_params->bitrate = -1;
    for(j = 0; j < 16; j++)
        unspec_vap_params->rate[0] = -1;
    unspec_vap_params->retries = -1;
    unspec_vap_params->txpow = -1;
    unspec_vap_params->fstype = -1;
    unspec_vap_params->beacon_interval = 0;
    unspec_vap_params->acs_6g_only_psc = 0;
    memset(unspec_vap_params->acs_freq_list, 0, MAX_LIST_LEN);
    unspec_vap_params->dtim_period = 0;
    unspec_vap_params->atf_options = -1;
    unspec_vap_params->rts_thresh = ACFG_RTS_INVALID;
    unspec_vap_params->frag_thresh = ACFG_FRAG_INVALID;
    memset(unspec_vap_params->vap_mac, 0, ACFG_MACSTR_LEN);
    unspec_node_params = &unspec_vap_params->node_params;
    for(j = 0; j < ACFG_MAX_ACL_NODE; j++) {
        memset(unspec_node_params->acfg_acl_node_list[j], 0, ACFG_MACADDR_LEN);
    }
    unspec_node_params->num_node = 0;
    unspec_node_params->node_acl = ACFG_WLAN_PROFILE_NODE_ACL_INVALID;

    for(j = 0; j < ACFG_MAX_ACL_NODE; j++) {
        memset(unspec_node_params->acfg_acl_node_list_sec[j], 0, ACFG_MACADDR_LEN);
    }
    unspec_node_params->num_node_sec = 0;
    unspec_node_params->node_acl_sec = ACFG_WLAN_PROFILE_NODE_ACL_INVALID;

    unspec_wds_params = &unspec_vap_params->wds_params;
    unspec_wds_params->enabled = -1;
    memset(unspec_wds_params->wds_addr, 0, ACFG_MACSTR_LEN);
    unspec_wds_params->wds_flags = ACFG_FLAG_INVALID;
    unspec_vap_params->vlanid = ACFG_WLAN_PROFILE_VLAN_INVALID;
    memset(unspec_vap_params->bridge, 0 , ACFG_MAX_IFNAME);
    unspec_vap_params->pureg = -1;
    unspec_vap_params->puren = -1;
    unspec_vap_params->hide_ssid = -1;
    unspec_vap_params->doth = -1;
    unspec_vap_params->client_isolation = -1;
    unspec_vap_params->coext = -1;
    unspec_vap_params->uapsd = -1;
    unspec_vap_params->shortgi = -1;
    unspec_vap_params->amsdu = -1;
    unspec_vap_params->max_clients = 0;
    unspec_security_params = &unspec_vap_params->security_params;
    unspec_security_params->sec_method = ACFG_WLAN_PROFILE_SEC_METH_INVALID;
    unspec_security_params->cipher_method = ACFG_WLAN_PROFILE_CIPHER_METH_INVALID;
    unspec_security_params->g_cipher_method = ACFG_WLAN_PROFILE_CIPHER_METH_INVALID;
    unspec_security_params->sha256 = 0;
    unspec_security_params->ieee80211w = 0;
    memset(unspec_security_params->owe_transition_ifname, 0, ACFG_MAX_IFNAME);
    memset(unspec_security_params->owe_transition_ssid, 0, ACFG_MAX_SSID_LEN + 1);
    memset(unspec_security_params->owe_transition_bssid, 0, ACFG_MACADDR_LEN);
    memset(unspec_security_params->owe_groups, 0, ACFG_MAX_SAE_OWE_GROUPS);
    memset(unspec_security_params->sae_groups, 0, ACFG_MAX_SAE_OWE_GROUPS);
    memset(unspec_security_params->sae_password, 0, ACFG_MAX_PSK_LEN);
    unspec_security_params->group_mgmt_cipher = ACFG_WLAN_PROFILE_GRP_MGMT_CIPHER_INVALID;
    unspec_security_params->assoc_sa_query_max_timeout = 0;
    unspec_security_params->assoc_sa_query_retry_timeout = 0;
    memset(unspec_security_params->psk, 0, ACFG_MAX_PSK_LEN);
    memset(unspec_security_params->wep_key0, 0, ACFG_MAX_WEP_KEY_LEN);
    memset(unspec_security_params->wep_key1, 0, ACFG_MAX_WEP_KEY_LEN);
    memset(unspec_security_params->wep_key2, 0, ACFG_MAX_WEP_KEY_LEN);
    memset(unspec_security_params->wep_key3, 0, ACFG_MAX_WEP_KEY_LEN);
    unspec_security_params->wep_key_defidx = 0;
    unspec_security_params->wps_pin = 0;
    unspec_security_params->wps_flag = 0;
    memset(unspec_security_params->wps_manufacturer, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_model_name, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_model_number, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_serial_number, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_device_type, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_config_methods, 0, ACFG_WPS_CONFIG_METHODS_LEN);
    memset(unspec_security_params->wps_upnp_iface, 0, ACFG_MAX_IFNAME);
    memset(unspec_security_params->wps_friendly_name, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_man_url, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_model_desc, 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_upc, 0, ACFG_WSUPP_PARAM_LEN);
    unspec_security_params->wps_pbc_in_m1 = 0;
    memset(unspec_security_params->wps_device_name , 0, ACFG_WSUPP_PARAM_LEN);
    memset(unspec_security_params->wps_rf_bands, 0, ACFG_WPS_RF_BANDS_LEN);
    memset(unspec_security_params->dpp_connector, 0, ACFG_MAX_DPP_CONNECTOR_LEN);
    memset(unspec_security_params->dpp_csign, 0, ACFG_MAX_DPP_CONNECTOR_LEN);
    memset(unspec_security_params->dpp_netaccesskey, 0, ACFG_MAX_DPP_CONNECTOR_LEN);
    unspec_eap_params = &unspec_security_params->eap_param;
    unspec_eap_params->eap_type = 0;
    memset(unspec_eap_params->identity , 0, EAP_IDENTITY_LEN);
    memset(unspec_eap_params->password , 0, EAP_PASSWD_LEN);
    memset(unspec_eap_params->ca_cert , 0, EAP_FILE_NAME_LEN);
    memset(unspec_eap_params->client_cert , 0, EAP_FILE_NAME_LEN);
    memset(unspec_eap_params->private_key , 0, EAP_FILE_NAME_LEN);
    memset(unspec_eap_params->private_key_passwd , 0, EAP_PVT_KEY_PASSWD_LEN);
    unspec_security_params->radius_retry_primary_interval = 0;
    unspec_radius_params = &unspec_security_params->pri_radius_param;
    memset(unspec_radius_params->radius_ip, 0, IP_ADDR_LEN);
    unspec_radius_params->radius_port = 0;
    memset(unspec_radius_params->shared_secret, 0 , RADIUS_SHARED_SECRET_LEN);
    unspec_radius_params = &unspec_security_params->sec1_radius_param;
    memset(unspec_radius_params->radius_ip, 0, IP_ADDR_LEN);
    unspec_radius_params->radius_port = 0;
    memset(unspec_radius_params->shared_secret, 0 , RADIUS_SHARED_SECRET_LEN);
    unspec_radius_params = &unspec_security_params->sec2_radius_param;
    memset(unspec_radius_params->radius_ip, 0, IP_ADDR_LEN);
    unspec_radius_params->radius_port = 0;
    memset(unspec_radius_params->shared_secret, 0 , RADIUS_SHARED_SECRET_LEN);
    unspec_acct_params = &unspec_security_params->pri_acct_server_param;
    memset(unspec_acct_params->acct_ip, 0, IP_ADDR_LEN);
    unspec_acct_params->acct_port = 0;
    memset(unspec_acct_params->shared_secret, 0 , ACCT_SHARED_SECRET_LEN);
    unspec_acct_params = &unspec_security_params->sec1_acct_server_param;
    memset(unspec_acct_params->acct_ip, 0, IP_ADDR_LEN);
    unspec_acct_params->acct_port = 0;
    memset(unspec_acct_params->shared_secret, 0 , ACCT_SHARED_SECRET_LEN);
    unspec_acct_params = &unspec_security_params->sec2_acct_server_param;
    memset(unspec_acct_params->acct_ip, 0, IP_ADDR_LEN);
    unspec_acct_params->acct_port = 0;
    memset(unspec_acct_params->shared_secret, 0 , ACCT_SHARED_SECRET_LEN);
    unspec_hs_params = &unspec_security_params->hs_iw_param;
    unspec_hs_params->hs_enabled = 0;
    unspec_hs_params->iw_enabled = 0;
    unspec_vap_params->primary_vap = 0;
    unspec_vap_params->bcn_rate = 0;
    unspec_vap_params->implicitbf = -1;
    unspec_vap_params->rrm = -1;
    unspec_vap_params->wnm = -1;
    unspec_vap_params->he_rx_mcsmap = 0xFFFFFFFF;
    unspec_vap_params->he_tx_mcsmap = 0xFFFFFFFF;
    unspec_vap_params->greenap_ps_enable = 0;
    unspec_vap_params->greenap_ps_trans_time = 20;
    unspec_vap_params->vap_doth = -1;
    unspec_security_params->sae_pwe = 0;
    unspec_vap_params->sec_comp_6g = 0;
    unspec_vap_params->keymgmt_mask_6g = 0xFFFFFFFF;
}

uint32_t acfg_alloc_profile(acfg_wlan_profile_t **new_profile, acfg_wlan_profile_t **curr_profile)
{
    *new_profile = *curr_profile = NULL;

    *new_profile = malloc(sizeof(acfg_wlan_profile_t));
    if (*new_profile == NULL) {
        acfg_log_errstr("%s: mem alloc failure\n", __FUNCTION__);
        return QDF_STATUS_E_FAILURE;
    }
    *curr_profile = malloc(sizeof(acfg_wlan_profile_t));
    if (*curr_profile == NULL) {
        acfg_log_errstr("%s: mem alloc failure\n", __FUNCTION__);
        free(*new_profile);
        *new_profile = NULL;
        return QDF_STATUS_E_FAILURE;
    }
    memset(*new_profile, 0, sizeof(acfg_wlan_profile_t));
    memset(*curr_profile, 0, sizeof(acfg_wlan_profile_t));

    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_populate_profile(acfg_wlan_profile_t *curr_profile, char *radioname)
{
    char curr_profile_file[64];
    FILE *fp;
    int ret = 0;

    acfg_os_snprintf(curr_profile_file, sizeof(curr_profile_file),
                "/etc/acfg_curr_profile_%s.conf.bin", radioname);
    fp =  fopen (curr_profile_file,"rb");
    if(fp == NULL) {
        acfg_log_errstr(" %s not found. Initializing profile \n\r",curr_profile_file);
        return QDF_STATUS_E_INVAL;
    } else {
        ret = fread(curr_profile ,1,sizeof(acfg_wlan_profile_t),fp);
        if(!ret) {
            acfg_log_errstr("ERROR !! %s could not be read!!\n\r",curr_profile_file);
            fclose(fp);
            return QDF_STATUS_E_FAILURE;
        }
        fclose(fp);
    }
    return QDF_STATUS_SUCCESS;
}

acfg_wlan_profile_t * acfg_get_profile(char *radioname)
{
    acfg_wlan_profile_t *new_profile, *curr_profile;
    int i = 0;

    acfg_reset_errstr();

    if (acfg_alloc_profile(&new_profile, &curr_profile) != QDF_STATUS_SUCCESS)
        return NULL;

    if (acfg_populate_profile(curr_profile, radioname) != QDF_STATUS_SUCCESS) {
        acfg_init_profile(curr_profile);

        /* This change is needed because beacon burst default value on driver is 1
         * and this value is not reset during FW reload */
        curr_profile->radio_params.beacon_burst_mode = 1;
        curr_profile->default_params_set = 1;
    } else {
        curr_profile->default_params_set = 0;
    }

    memcpy(new_profile, curr_profile, sizeof(acfg_wlan_profile_t));
    new_profile->priv = (void*)curr_profile;
    new_profile->default_params_set = 0;

    for (i = 0; i < ACFG_MAX_VAPS; i++) {
        new_profile->vap_params[i].radio_params = &new_profile->radio_params;
        new_profile->vap_params[i].default_params_set = 0;
        curr_profile->vap_params[i].radio_params = &curr_profile->radio_params;
        if (curr_profile->default_params_set == 1) {
            curr_profile->vap_params[i].default_params_set = 1;
        } else {
            curr_profile->vap_params[i].default_params_set = 0;
        }
    }
    return new_profile;
}

void acfg_free_profile(acfg_wlan_profile_t * profile)
{
    free(profile->priv);
    free(profile);
}

uint32_t
acfg_set_profile(acfg_wlan_profile_t *new_profile,
        acfg_wlan_profile_t *cur_profile)
{
    uint32_t   status = QDF_STATUS_SUCCESS;
    acfg_wlan_profile_vap_list_t create_list, modify_list, delete_list;

    memset(&create_list, 0, sizeof (acfg_wlan_profile_vap_list_t));
    memset(&delete_list, 0, sizeof (acfg_wlan_profile_vap_list_t));
    memset(&modify_list, 0, sizeof (acfg_wlan_profile_vap_list_t));
    g_str_truncated = 0;

    acfg_set_vap_list(new_profile, cur_profile,
            &create_list, &delete_list,
            &modify_list);
    if ((cur_profile == NULL) || (g_str_truncated == 1)) {
        return QDF_STATUS_E_FAILURE;
    } else {
        status = acfg_set_radio_profile(&new_profile->radio_params,
                &cur_profile->radio_params);
    }
    if ((status != QDF_STATUS_SUCCESS) || (g_str_truncated == 1)) {
        if ((status == QDF_STATUS_SUCCESS) && (g_str_truncated == 1))
            status = QDF_STATUS_E_FAILURE;
        acfg_log_errstr("%s: Failed to set radio profile (radio=%s status=%d)!\n",
                __func__, new_profile->radio_params.radio_name, status);
        return status;
    }
   if(cur_profile != NULL) {
       status = acfg_set_vap_profile(new_profile, cur_profile,
         	   &create_list, &delete_list,
		   &modify_list);
       if ((status != QDF_STATUS_SUCCESS) || (g_str_truncated == 1)) {
           if ((status == QDF_STATUS_SUCCESS) && (g_str_truncated == 1))
               status = QDF_STATUS_E_FAILURE;
	   acfg_log_errstr("%s: Failed to set VAP profile (vap=%s status=%d)!\n",
			   __func__, new_profile->vap_params->vap_name, status);
	   return status;
       }
    }

    if (cur_profile != NULL) {
        status = acfg_set_radio_profile_chan(&new_profile->radio_params,
                &cur_profile->radio_params,
                new_profile, cur_profile);
        if ((status != QDF_STATUS_SUCCESS) || (g_str_truncated == 1))  {
            if ((status == QDF_STATUS_SUCCESS) && (g_str_truncated == 1))
                status = QDF_STATUS_E_FAILURE;
            acfg_log_errstr("%s: Failed to set radio profile channel (vap=%s status=%d)!\n",
                    __func__, new_profile->radio_params.radio_name, status);
            return status;
        }
    }
    return status;
}

uint32_t
acfg_write_file(acfg_wlan_profile_t *new_profile)
{
    int i=0, ret=0;
    FILE *fp;
    char curr_profile_file[64];
    uint32_t status = QDF_STATUS_SUCCESS;

    acfg_os_snprintf(curr_profile_file, sizeof(curr_profile_file),
             "/etc/acfg_curr_profile_%s.conf.bin",
             new_profile->radio_params.radio_name);
    fp =  fopen (curr_profile_file,"wb");
    if(fp != NULL) {
        int valid_vaps = 0;

        acfg_print("%s: INFO: '%s' VAP cnt is %u\n", __func__, new_profile->radio_params.radio_name, new_profile->num_vaps);
        /* move valid VAPs to the front, clear all other */
        for(i=0; i < ACFG_MAX_VAPS; i++)
        {
            if (new_profile->vap_params[i].vap_name[0] == '\0')
            {
                acfg_print("%s: INFO: '%s' clearing VAP index %d\n", __func__, new_profile->radio_params.radio_name, i);
                acfg_init_vap_params(&new_profile->vap_params[i]);
                continue;
            }
            acfg_print("%s: INFO: '%s' valid VAP index %d\n", __func__, new_profile->radio_params.radio_name, i);
            if (i > valid_vaps)
            {
                acfg_print("%s: INFO: '%s' moving VAP '%s' to index %d\n", __func__,
                    new_profile->radio_params.radio_name, new_profile->vap_params[i].vap_name, valid_vaps);
                memcpy(&new_profile->vap_params[valid_vaps], &new_profile->vap_params[i], sizeof(acfg_wlan_profile_vap_params_t));
                acfg_init_vap_params(&new_profile->vap_params[i]);
            }
            valid_vaps++;
        }
        acfg_print("%s: INFO: '%s' VAP cnt is %u\n", __func__, new_profile->radio_params.radio_name, new_profile->num_vaps);
        ret = fwrite(new_profile, 1, sizeof(acfg_wlan_profile_t), fp);
        if(!ret)
            status = QDF_STATUS_E_FAILURE;
        fclose(fp);
    } else {
        acfg_log_errstr("%s could not be opened for writing \n\r",curr_profile_file);
        status = QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_reset_cur_profile(char *radio_name)
{
    char curr_profile_file[64];
    uint32_t status = QDF_STATUS_SUCCESS;

    acfg_os_snprintf(curr_profile_file, sizeof(curr_profile_file),
             "/etc/acfg_curr_profile_%s.conf.bin", radio_name);

    /* Do not return failure, if current profile file doesn't exist */
    errno = 0;
    if((unlink(curr_profile_file) < 0) && (errno != ENOENT)) {
        status = QDF_STATUS_E_FAILURE;
    }

    return status;
}

uint32_t
acfg_apply_profile(acfg_wlan_profile_t *new_profile)
{
    uint32_t  status = QDF_STATUS_SUCCESS;
    acfg_wlan_profile_t * curr_profile = NULL;

    if (new_profile == NULL)
        return QDF_STATUS_E_FAILURE;

    curr_profile = (acfg_wlan_profile_t *)new_profile->priv;
    status = acfg_set_profile(new_profile, curr_profile);
    if (status == QDF_STATUS_SUCCESS) {
        acfg_write_file(new_profile);
    }
    return status;
}

uint32_t acfg_set_radio_enable(uint8_t *ifname)
{
    return acfg_wlan_iface_up(ifname, NULL);
}

uint32_t acfg_set_radio_disable(uint8_t *ifname)
{
    return acfg_wlan_iface_down(ifname, NULL);
}

void
acfg_get_wep_str(char *str, uint8_t *key, uint8_t key_len, uint16_t str_max_len)
{
    if (key_len == 5) {
        acfg_os_snprintf(str, str_max_len, "%02x%02x%02x%02x%02x", key[0],
                 key[1],
                 key[2],
                 key[3],
                 key[4]);
    }
    if (key_len == 13) {
        acfg_os_snprintf(str, str_max_len,
                 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 key[0], key[1], key[2],
                 key[3], key[4], key[5],
                 key[6], key[7], key[8],
                 key[9], key[10], key[11],
                 key[12]);
    }
    if (key_len == 16) {
        acfg_os_snprintf(str, str_max_len,
                 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 key[0], key[1], key[2],
                 key[3], key[4], key[5],
                 key[6], key[7], key[8],
                 key[9], key[10], key[11],
                 key[12], key[13], key[14],
                 key[15]);
    }
}

uint32_t
acfg_get_wps_cred(uint8_t *ifname, acfg_opmode_t opmode,
        char *buffer, int *buflen)
{
    char cmd[255], replybuf[4096];
    uint32_t len;

    len = sizeof(replybuf);

    memset(cmd, '\0', sizeof(cmd));
    memset(replybuf, '\0', sizeof(replybuf));
    acfg_os_snprintf(cmd, sizeof(cmd), "%s", "WPS_GET_CONFIG");
    if(acfg_ctrl_req(ifname, cmd, strlen(cmd),
                replybuf, &len, opmode) < 0){
        acfg_log_errstr("%s: cmd --> %s failed for %s\n", __func__,
                cmd,
                ifname);
        return QDF_STATUS_E_FAILURE;
    }
    *buflen = len;
    acfg_os_strcpy(buffer, replybuf, ACFG_MAX_WPS_FILE_SIZE);

    return QDF_STATUS_SUCCESS;
}

void
acfg_parse_cipher(char *value, acfg_wps_cred_t *wps_cred)
{
    int last;
    char *start, *end, buf[255];

    acfg_os_snprintf(buf, sizeof(buf), "%s", value);
    start = buf;
    while (*start != '\0') {
        while (*start == ' ' || *start == '\t')
            start++;
        if (*start == '\0')
            break;
        end = start;
        while (*end != ' ' && *end != '\t' && *end != '\0' && *end != '\n')
            end++;
        last = *end == '\0';
        *end = '\0';
        if (strcmp(start, "CCMP") == 0) {
            wps_cred->enc_type |=
                ACFG_WLAN_PROFILE_CIPHER_METH_AES;
        }
        else if (strcmp(start, "TKIP") == 0) {
            wps_cred->enc_type |=
                ACFG_WLAN_PROFILE_CIPHER_METH_TKIP;
        }
        if (last) {
            break;
        }
        start = end + 1;
    }
}

uint32_t
acfg_parse_wpa_key_mgmt(char *value,
        acfg_wps_cred_t *wps_cred)
{
    int last;
    char *start, *end, *buf;

    buf = strdup(value);
    if (buf == NULL)
        return QDF_STATUS_E_FAILURE;
    start = buf;
    while (*start != '\0') {
        while (*start == ' ' || *start == '\t')
            start++;
        if (*start == '\0')
            break;
        end = start;
        while (*end != ' ' && *end != '\t' && *end != '\0' && *end != '\n')
            end++;
        last = *end == '\0';
        *end = '\0';
        if (strcmp(start, "WPA-PSK") == 0) {
            wps_cred->key_mgmt = 2;
        }
        else if (strcmp(start, "WPA-EAP") == 0) {
            wps_cred->key_mgmt = 1;
        }
        if (last) {
            break;
        }
        start = end + 1;
    }
    free(buf);
    return QDF_STATUS_SUCCESS;
}

int
acfg_get_wps_config(uint8_t *ifname, acfg_wps_cred_t *wps_cred)
{
    char filename[32];
    FILE *fp;
    char *pos;
    int val = 0, ret = 1, len = 0, buflen = 0;
    char buf[255];

    buflen = sizeof(buf);
    acfg_os_snprintf(filename, sizeof(filename), "/etc/%s_%s.conf",
             ACFG_WPS_CONFIG_PREFIX, ifname);
    fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    while(fgets(buf, buflen, fp)) {
        pos = buf;
        if (strncmp(pos, "wps_state=", 10) == 0) {
            pos = strchr(buf, '=');
            pos++;
            val = atoi(pos);
            if (val == 2) {
                wps_cred->wps_state = val;
                ret = 1;
            }
        } else if (strncmp(pos, "ssid=", 5) == 0) {
            pos = strchr(buf, '=');
            pos++;
            memset(wps_cred->ssid, '\0', sizeof(wps_cred->ssid));
            acfg_os_snprintf(wps_cred->ssid, sizeof(wps_cred->ssid), "%s", pos);
        } else if (strncmp(pos, "wpa_key_mgmt=", 13) == 0) {
            pos = strchr(buf, '=');
            pos++;
            acfg_parse_wpa_key_mgmt(pos, wps_cred);
        } else if (strncmp(pos, "wpa_pairwise=", 13) == 0) {
            pos = strchr(buf, '=');
            pos++;
            acfg_parse_cipher(pos, wps_cred);
        } else if (strncmp(pos, "wpa_passphrase=", 15) == 0) {
            pos = strchr(buf, '=');
            pos++;
            len = strlen(pos);
            if (pos[len - 1] == '\n') {
                pos[len - 1] = '\0';
                len--;
            }
            memset(wps_cred->key, '\0', sizeof(wps_cred->key));
            acfg_os_strcpy(wps_cred->key, pos, sizeof(wps_cred->key));
        } else if (strncmp(pos, "wpa_psk=", 7) == 0) {
            pos = strchr(buf, '=');
            pos++;
            len = strlen(pos);
            if (pos[len - 1] == '\n') {
                pos[len - 1] = '\0';
                len--;
            }
            memset(wps_cred->key, '\0', sizeof(wps_cred->key));
            acfg_os_strcpy(wps_cred->key, pos, sizeof(wps_cred->key));
        } else if (strncmp(pos, "wpa=", 4) == 0) {
            pos = strchr(buf, '=');
            pos++;
            wps_cred->wpa = atoi(pos);
        } else if (strncmp(pos, "key_mgmt=", 9) == 0) {
            pos = strchr(buf, '=');
            pos++;
            wps_cred->key_mgmt = atoi(pos);
        } else if (strncmp(pos, "auth_alg=", 9) == 0) {
            pos = strchr(buf, '=');
            pos++;
            wps_cred->auth_alg = atoi(pos);
        } else if (strncmp(pos, "proto=", 6) == 0) {
            pos = strchr(buf, '=');
            pos++;
            wps_cred->wpa = atoi(pos);
        } else if (strncmp(pos, "wep_key=", 8) == 0) {
            pos = strchr(buf, '=');
            pos++;
            len = strlen(pos);
            if (pos[len - 1] == '\n') {
                pos[len - 1] = '\0';
                len--;
            }
            memset(wps_cred->wep_key, '\0', sizeof(wps_cred->wep_key));
            acfg_os_strcpy(wps_cred->wep_key, pos, sizeof(wps_cred->wep_key));
        } else if (strncmp(pos, "wep_default_key=", 16) == 0) {
            pos = strchr(buf, '=');
            pos++;
            wps_cred->wep_key_idx = atoi(pos);
        }
    }
    fclose(fp);
    return ret;
}

void acfg_set_hs_iw_vap_param(acfg_wlan_profile_vap_params_t *vap_params)
{
    acfg_opmode_t opmode;
    acfg_macaddr_t mac_addr;

    memset(&mac_addr.addr, 0, sizeof(mac_addr.addr));
    acfg_get_opmode(vap_params->vap_name, &opmode);
    acfg_get_ap(vap_params->vap_name,&mac_addr);
    if(opmode == ACFG_OPMODE_HOSTAP)
    {
        if(vap_params->security_params.hs_iw_param.hessid[0] == 0)
	    acfg_os_snprintf(vap_params->security_params.hs_iw_param.hessid, ACFG_MACSTR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",mac_addr.addr[0], mac_addr.addr[1], mac_addr.addr[2], mac_addr.addr[3], mac_addr.addr[4], mac_addr.addr[5]);
        if(vap_params->security_params.hs_iw_param.network_type > 15)
            vap_params->security_params.hs_iw_param.network_type = DEFAULT_NETWORK_TYPE;
        if(vap_params->security_params.hs_iw_param.internet > 1)
            vap_params->security_params.hs_iw_param.internet = DEFAULT_INTERNET;
        if(vap_params->security_params.hs_iw_param.asra > 1)
            vap_params->security_params.hs_iw_param.asra = DEFAULT_ASRA;
        if(vap_params->security_params.hs_iw_param.esr > 1)
            vap_params->security_params.hs_iw_param.esr = DEFAULT_ESR;
        if(vap_params->security_params.hs_iw_param.uesa > 1)
            vap_params->security_params.hs_iw_param.uesa = DEFAULT_UESA;
        if(vap_params->security_params.hs_iw_param.venue_group >= VENUE_GROUP_RESERVED_START)
            vap_params->security_params.hs_iw_param.venue_group = DEFAULT_VENUE_GROUP;
        if(vap_params->security_params.hs_iw_param.roaming_consortium[0] == 0)
            vap_params->security_params.hs_iw_param.roaming_consortium[0] = '\0';
        if(vap_params->security_params.hs_iw_param.roaming_consortium2[0] == 0)
            vap_params->security_params.hs_iw_param.roaming_consortium2[0] = '\0';
        if(vap_params->security_params.hs_iw_param.venue_name[0] == 0)
            acfg_os_strcpy(vap_params->security_params.hs_iw_param.venue_name,
                           "venue_name=eng:Wi-Fi Alliance Labs\x0a 2989 Copper Road\x0aSanta Clara, CA 95051, USA",
                           sizeof(vap_params->security_params.hs_iw_param.venue_name));
    }
}

#define OFFSET(a,b) ((long )&((a *) 0)->b)

struct acfg_wps_params {
    uint8_t name[32];
    uint32_t offset;
    uint32_t size;
};

struct acfg_wps_params wps_device_info[] =
{
    {"wps_device_name",  OFFSET(acfg_wlan_profile_security_params_t, wps_device_name), ACFG_WSUPP_PARAM_LEN},
    {"wps_device_type",  OFFSET(acfg_wlan_profile_security_params_t, wps_device_type), ACFG_WSUPP_PARAM_LEN},
    {"wps_model_name",  OFFSET(acfg_wlan_profile_security_params_t, wps_model_name), ACFG_WSUPP_PARAM_LEN},
    {"wps_model_number",  OFFSET(acfg_wlan_profile_security_params_t, wps_model_number), ACFG_WSUPP_PARAM_LEN},
    {"wps_serial_number",  OFFSET(acfg_wlan_profile_security_params_t, wps_serial_number), ACFG_WSUPP_PARAM_LEN},
    {"wps_manufacturer",  OFFSET(acfg_wlan_profile_security_params_t, wps_manufacturer), ACFG_WSUPP_PARAM_LEN},
    {"wps_config_methods",  OFFSET(acfg_wlan_profile_security_params_t, wps_config_methods), ACFG_WPS_CONFIG_METHODS_LEN},
};

void acfg_set_wps_default_config(acfg_wlan_profile_vap_params_t *vap_params)
{
    acfg_opmode_t opmode;

    acfg_get_opmode(vap_params->vap_name, &opmode);
    if(opmode == ACFG_OPMODE_STA)
    {
        if(vap_params->security_params.wps_config_methods[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_config_methods,
                           "\"ethernet label push_button\"",
                           sizeof(vap_params->security_params.wps_config_methods));
        if(vap_params->security_params.wps_device_type[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_device_type, "1-0050F204-1",
                           sizeof(vap_params->security_params.wps_device_type));
        if(vap_params->security_params.wps_manufacturer[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_manufacturer, "Atheros",
                           sizeof(vap_params->security_params.wps_manufacturer));
        if(vap_params->security_params.wps_model_name[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_model_name, "cmodel",
                           sizeof(vap_params->security_params.wps_model_name));
        if(vap_params->security_params.wps_model_number[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_model_number, "123",
                           sizeof(vap_params->security_params.wps_model_number));
        if(vap_params->security_params.wps_serial_number[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_serial_number, "12345",
                           sizeof(vap_params->security_params.wps_serial_number));
        if(vap_params->security_params.wps_device_name[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_device_name, "WirelessClient",
                           sizeof(vap_params->security_params.wps_device_name));
    }
    else
    {
        if(vap_params->security_params.wps_config_methods[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_config_methods,
                           "push_button label virtual_display virtual_push_button physical_push_button",
                           sizeof(vap_params->security_params.wps_config_methods));
        if(vap_params->security_params.wps_device_type[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_device_type, "6-0050F204-1",
                           sizeof(vap_params->security_params.wps_device_type));
        if(vap_params->security_params.wps_manufacturer[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_manufacturer, "Atheros Communications, Inc.",
                           sizeof(vap_params->security_params.wps_manufacturer));
        if(vap_params->security_params.wps_model_name[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_model_name, "APxx",
                           sizeof(vap_params->security_params.wps_model_name));
        if(vap_params->security_params.wps_model_number[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_model_number, "APxx-xxx",
                           sizeof(vap_params->security_params.wps_model_number));
        if(vap_params->security_params.wps_serial_number[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_serial_number, "87654321",
                           sizeof(vap_params->security_params.wps_serial_number));
        if(vap_params->security_params.wps_device_name[0] == 0)
            acfg_os_strcpy(vap_params->security_params.wps_device_name, "AtherosAP",
                           sizeof(vap_params->security_params.wps_device_name));
    }
}

void acfg_get_wps_dev_config(acfg_wlan_profile_vap_params_t *vap_params)
{
    FILE *fp;
    unsigned int i, offset;
    char buf[255], *pos;
    char filename[60];

    acfg_os_snprintf(filename,sizeof(filename),"/etc/%s_%s.conf", ACFG_WPS_DEV_CONFIG_PREFIX, vap_params->vap_name);

    fp = fopen(filename, "r");
    if(fp == NULL)
        return;

    while(fgets(buf, sizeof(buf), fp))
    {
        if(buf[0] == '#') {
            continue;
        }
        pos = buf;
        while (*pos != '\0') {
            if (*pos == '\n') {
                *pos = '\0';
                break;
            }
            pos++;
        }
        pos = strchr(buf, '=');
        if (pos == NULL) {
            continue;
        }
        *pos = '\0';
        pos++;
        for (i = 0; i < (sizeof (wps_device_info) /
                    sizeof (struct acfg_wps_params)); i++) {
            if (strcmp(buf, (char *)wps_device_info[i].name) == 0) {
                offset = wps_device_info[i].offset;
                acfg_os_strcpy((char *)(&vap_params->security_params) + offset, (char *)pos, wps_device_info[i].size);
                break;
            }
        }
    }
    fclose(fp);
}

void
acfg_update_wps_dev_config_file(acfg_wlan_profile_vap_params_t *vap_params, int force_update)
{
    char filename[60];
    FILE *fp;
    acfg_wlan_profile_security_params_t security_params;
    unsigned int i;

    acfg_os_snprintf(filename,sizeof(filename),"/etc/%s_%s.conf", ACFG_WPS_DEV_CONFIG_PREFIX, vap_params->vap_name);

    /* Try to open the file for reading */
    fp = fopen(filename, "r");
    if(fp == NULL)
    {
        /* Create file if it doesn't exist*/
        force_update = 1;
    }
    else
    {
        char buf[255];
        char *pos;
        int offset;

        /* make a copy of initial security_params, so that it can be used for later comparision */
        memcpy(&security_params, &vap_params->security_params, sizeof(acfg_wlan_profile_security_params_t));
        /* Read the contents and get the WPS device info */
        while(fgets(buf, sizeof(buf), fp))
        {
            if(buf[0] == '#') {
                continue;
            }
            pos = buf;
            while (*pos != '\0') {
                if (*pos == '\n') {
                    *pos = '\0';
                    break;
                }
                pos++;
            }
            pos =  strchr(buf, '=');
            if (pos == NULL) {
                continue;
            }
            *pos = '\0';
            pos++;
            for (i = 0; i < (sizeof (wps_device_info) /
                        sizeof (struct acfg_wps_params)); i++) {
                if (strcmp(buf, (char *)wps_device_info[i].name) == 0) {
                    offset = wps_device_info[i].offset;
                    acfg_os_strcpy((char *)(&security_params) + offset, pos, wps_device_info[i].size);
                    break;
                }
            }
        }
        if(memcmp(&security_params, &vap_params->security_params, sizeof(acfg_wlan_profile_security_params_t)))
        {
            /* Profile is updated, so update the WPS dev file too */
            force_update = 1;
        }
    }
    if(force_update == 1)
    {
        int ret, buflen;
        char str[255], data[ACFG_MAX_WPS_FILE_SIZE];
        int len = 0;

        if(fp){
            fclose(fp);
	    fp = NULL;
	}
	memset(data, '\0',ACFG_MAX_WPS_FILE_SIZE);
        buflen = sizeof(data);

        for(i = 0; i < (sizeof (wps_device_info) /
                    sizeof (struct acfg_wps_params)); i++)
        {
            ret = acfg_os_snprintf(str,sizeof(str), "\n%s=%s", wps_device_info[i].name,
                    (((uint8_t *)&(vap_params->security_params)) + wps_device_info[i].offset));
            if (ret >= 0 && buflen > ret)
            {
                acfg_os_strlcat(data, str, sizeof(data));
                buflen -= ret;
                len += ret;
            }
        }
        acfg_update_wps_config_file(vap_params->vap_name, ACFG_WPS_DEV_CONFIG_PREFIX, data, len);
    }
    if(fp)
	fclose(fp);
}

void
acfg_update_wps_config_file(uint8_t *ifname, char *prefix, char *data, int len)
{
    char filename[32];
    FILE *fp;
    char *pos, *start;
    int ret = 0;

    acfg_os_snprintf(filename, sizeof(filename), "/etc/%s_%s.conf", prefix, ifname);
    fp = fopen(filename, "w");
    if (fp == NULL){
	return;
    }
    pos = start = data;
    while (len) {
        start = pos;
        while ((*pos != '\n') && *pos != '\0') {
            pos++;
            len--;
        }
        if (*pos == '\0') {
            ret = 1;
        }
        *pos = '\0';
        fprintf(fp, "%s\n", start);
        if (ret == 1) {
            fclose(fp);
            return;
        }
        pos++;
        len--;
        while(*pos == '\n') {
            pos++;
            len--;
        }
    }
    fclose(fp);
}

uint32_t
acfg_wps_success_cb(uint8_t *ifname)
{
    char data[ACFG_MAX_WPS_FILE_SIZE];
    int datalen =  0;
    acfg_wps_cred_t wps_cred;
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_opmode_t opmode;
    acfg_wlan_profile_vap_params_t vap_params;

    status = acfg_get_opmode(ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail for %s\n", __func__, ifname);
        return QDF_STATUS_E_FAILURE;
    }
    memset(&vap_params, 0, sizeof(acfg_wlan_profile_vap_params_t));
    memset(data, '\0', sizeof(data));
    status = acfg_get_wps_cred(ifname, opmode, data, &datalen);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Get WPS credentials failed for %s\n", __func__, ifname);
        return QDF_STATUS_E_FAILURE;
    }
    acfg_update_wps_config_file(ifname, ACFG_WPS_CONFIG_PREFIX, data, datalen);
    acfg_os_strcpy((char *)vap_params.vap_name, (char *)ifname,
                   sizeof(vap_params.vap_name));
    if (opmode == ACFG_OPMODE_STA) {
        return QDF_STATUS_SUCCESS;
    }
    acfg_get_wps_config(ifname, &wps_cred);
    acfg_get_wps_dev_config(&vap_params);
    if (wps_cred.wps_state == WPS_FLAG_CONFIGURED) {
        acfg_os_strcpy((char *)vap_params.vap_name,(char *)ifname,
                       sizeof(vap_params.vap_name));
        status = acfg_set_wps_vap_params(&vap_params, &wps_cred);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
        status = acfg_config_security(&vap_params);
        if (status != QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }
    }
    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_handle_wps_event(uint8_t *ifname, enum acfg_event_handler_type event)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_opmode_t opmode;

    status = acfg_get_opmode(ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        return status;
    }
    switch (event) {
        case ACFG_EVENT_WPS_NEW_AP_SETTINGS:
            if (opmode == ACFG_OPMODE_HOSTAP) {
                status = acfg_wps_success_cb(ifname);
            }
            break;
        case ACFG_EVENT_WPS_SUCCESS:
            if (opmode == ACFG_OPMODE_STA) {
                status = acfg_wps_success_cb(ifname);
            }
            break;
        default:
            return QDF_STATUS_E_NOSUPPORT;
    }
    return status;
}

uint32_t
acfg_set_wps_pin(char *ifname, int action, char *pin, char *pin_txt,
        char *bssid)
{
    char cmd[255];
    char replybuf[255];
    uint32_t len = 0;
    acfg_opmode_t opmode;
    acfg_vap_list_t vap_list;

    memset(replybuf, 0, sizeof(replybuf));
    if (acfg_get_opmode((uint8_t *)ifname, &opmode) != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("Opmode get failed\n");
        return -1;
    }
    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd,
            ctrl_wpasupp);
    acfg_os_strcpy(vap_list.iface[0], ifname, ACFG_MAX_IFNAME);
    vap_list.num_iface = 1;
    if (opmode == ACFG_OPMODE_HOSTAP) {
        if (action == ACFG_WPS_PIN_SET) {
            memset(replybuf, '\0', sizeof (replybuf));
            len = sizeof (replybuf);
            acfg_os_snprintf(cmd, sizeof(cmd), "%s %s %s %d", WPA_WPS_PIN_CMD_PREFIX,  "any",
                     pin, WPS_TIMEOUT);
            if(acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                        ACFG_OPMODE_HOSTAP) < 0){
                return QDF_STATUS_E_FAILURE;
            }
            acfg_os_strcpy(pin_txt, replybuf, 10);

            memset(replybuf, '\0', sizeof (replybuf));
            len = sizeof (replybuf);
            acfg_os_snprintf(cmd, sizeof(cmd), "%s %s %s %d",
                     WPA_WPS_AP_PIN_CMD_PREFIX,  "set",
                     pin, WPS_TIMEOUT);
            if(acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                        ACFG_OPMODE_HOSTAP) < 0){
                return QDF_STATUS_E_FAILURE;
            }
            acfg_os_strcpy(pin_txt, replybuf, 10);
        } else if (action == ACFG_WPS_PIN_RANDOM) {
            memset(replybuf, '\0', sizeof (replybuf));
            len = sizeof (replybuf);
            acfg_os_snprintf(cmd, sizeof(cmd), "%s %s %d",
                     WPA_WPS_AP_PIN_CMD_PREFIX,  "random",
                     WPS_TIMEOUT);
            if(acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                        ACFG_OPMODE_HOSTAP) < 0){
                return QDF_STATUS_E_FAILURE;
            }
            acfg_log_errstr("PIN: %s\n", replybuf);
            acfg_os_strcpy(pin_txt, replybuf, 10);
        }
    } else if (opmode == ACFG_OPMODE_STA) {
        char bssid_str[20];
        uint8_t macaddr[6];

        if (action == ACFG_WPS_PIN_SET) {
            if (hwaddr_aton(bssid, macaddr) == -1) {
                acfg_os_snprintf(bssid_str, sizeof(bssid_str), "any");
            } else {
                acfg_os_snprintf(bssid_str, sizeof(bssid_str), "%s", bssid);
            }
            acfg_os_snprintf(cmd, sizeof(cmd), "%s %s %s", WPA_WPS_PIN_CMD_PREFIX,
                    bssid_str, pin);
            if(acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                        ACFG_OPMODE_STA) < 0){
                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    return QDF_STATUS_SUCCESS;
}

/**
 * @brief add Beacon app IE, add inidividual IEs into Beacon/Probe Response frames (AP)
 *
 * @param
 * @vap_name VAP interface
 * @ie: Information element
 * @ie_len: Length of the IE buffer in octets
 *
 * @return
 */
uint32_t
acfg_add_app_ie(uint8_t  *vap_name, const uint8_t *ie, uint32_t ie_len)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   *req = NULL;
    acfg_appie_t    *ptr;

    req = malloc(sizeof(acfg_os_req_t) + ie_len);
    if (req == NULL) {
        acfg_log_errstr("%s: mem alloc failure\n", __FUNCTION__);
        return status;
    }
    memset(req, 0, sizeof(acfg_os_req_t) + ie_len);
    req->cmd = ACFG_REQ_SET_APPIEBUF;
    ptr = (acfg_appie_t *)req->data;

    memcpy(ptr->buf, ie, ie_len);
    ptr->buflen = ie_len;

    ptr->frmtype = ACFG_FRAME_BEACON;
    status = acfg_os_send_req(vap_name, req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: add app ie(type: ACFG_FRAME_BEACON) failed! \n", vap_name);
        return QDF_STATUS_E_FAILURE;
    }

    ptr->frmtype = ACFG_FRAME_PROBE_RESP;
    status = acfg_os_send_req(vap_name, req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: add app ie(type: ACFG_FRAME_PROBE_RESP) failed! \n", vap_name);
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t acfg_get_vap_iface_names(acfg_vap_list_t *list, int *count)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t	req = {.cmd = ACFG_REQ_GET_VAP_NAMES};
    struct acfg_vap_iface_names *ptr;
    uint8_t wifi_iface[ACFG_MAX_RADIO][ACFG_MAX_IFNAME] = {"wifi0", "wifi1",
                                                           "wifi2", "wifi3"};
    unsigned int n;
    int num_iface = 0, i;

    for (n = 0; n < sizeof (wifi_iface) / sizeof(wifi_iface[0]); n++) {
        status = acfg_wlan_iface_present((char *)wifi_iface[n]);
        if(status != QDF_STATUS_SUCCESS) {
            continue;
        }
        ptr = (struct acfg_vap_iface_names *)req.data;
        memset(ptr, 0 , sizeof(struct acfg_vap_iface_names));

        if (acfg_os_check_str(wifi_iface[n], ACFG_MAX_IFNAME))
            return QDF_STATUS_E_NOENT;

        status = acfg_os_send_req(wifi_iface[n], &req);

        if (status == QDF_STATUS_SUCCESS) {
            for (i = 0; i <  ptr->vap_count; i++) {
                acfg_os_strcpy((char *)list->iface[i + num_iface],
                               (char *)ptr->name[i], ACFG_MAX_IFNAME);
            }
            num_iface += i;
        }
    }
    *count = num_iface;
    return QDF_STATUS_SUCCESS;
}

/**
 * @brief Send a generic buffer to kernel space
 *
 * @param
 * @radio_name radio interface
 * @buf  buffer to send
 * @len  buffer length
 * @buf_type type of buffer
 * @return
 */
uint32_t
acfg_add_generic_buf(uint8_t  *radio_name, const uint8_t *buf,
                     uint32_t len, enum acfg_buf_type buf_type)
{
    uint32_t  status = QDF_STATUS_SUCCESS;
    acfg_os_req_t   *req = NULL;
    acfg_generic_buf_t    *ptr;

    req = malloc(sizeof(acfg_os_req_t) + len);
    if (req == NULL) {
        acfg_log_errstr("%s: mem alloc failure\n", __FUNCTION__);
        return status;
    }
    memset(req, 0, sizeof(acfg_os_req_t) + len);
    req->cmd = ACFG_REQ_ADD_GENERIC_BUF;
    ptr = (acfg_generic_buf_t *)req->data;
    if (buf != NULL && len > 0)
        memcpy(ptr->buf, buf, len);
    ptr->buf_len = len;
    ptr->buf_type = buf_type;

    status = acfg_os_send_req(radio_name, req);
    free(req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: send buffer failed! \n", radio_name);
        return QDF_STATUS_E_FAILURE;
    }

    return status;
}

/**
 * @brief Add a user RNR info entry to driver
 *
 * @radio_name radio interface
 * @buf  buffer to send (struct user_rnr_data, uid and struct ieee80211_rnr_nbr_ap_info)
 * @len  buffer length
 * @return
 */
uint32_t
acfg_add_rnr_entry(uint8_t *radio_name, const uint8_t *buf, uint32_t len)
{
    if (len == 0 || len > sizeof(acfg_user_rnr_data_t))
        return 1;
    return acfg_add_generic_buf(radio_name, buf, len, ACFG_USER_RNR_ENTRY_ADD);
}

/**
 * @brief Delete a user RNR info entry
 *
 * @radio_name radio interface
 * @buf  buffer to send (struct user_rnr_data, only uid field needed)
 * @len  buffer length
 * @return
 */
uint32_t
acfg_del_rnr_entry(uint8_t *radio_name, const uint8_t *buf, uint32_t len)
{
    return acfg_add_generic_buf(radio_name, buf, len, ACFG_USER_RNR_ENTRY_DEL);
}

/**
 * @brief Dump all user RNR info entries
 *
 * @radio_name radio interface
 * @uid  unique ID for RNR entry
 * @return
 */
uint32_t
acfg_dump_rnr_entries(uint8_t *radio_name)
{
    return acfg_add_generic_buf(radio_name, NULL, 0, ACFG_USER_RNR_ENTRY_DUMP);
}


uint32_t
acfg_dpp_bootstrap_gen(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[255];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_BOOTSTRAP_GEN_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "FAIL", 4)) {
        printf("dpp bootstrap ID is: %s\n", replybuf);
        return status;
    } else {
        return QDF_STATUS_E_FAILURE;
    }
}

uint32_t
acfg_dpp_bootstrap_remove(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[255];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }
    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_BOOTSTRAP_REMOVE_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_bootstrap_info(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[255];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_BOOTSTRAP_INFO_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "FAIL", 4)) {
        printf("dpp bootstrap info is: %s\n", replybuf);
        return status;
    } else {
        return QDF_STATUS_E_FAILURE;
    }
}

uint32_t
acfg_dpp_configurator_add(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[500], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_CONFIGURATOR_ADD_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "FAIL", 4)) {
        printf("dpp configurator ID: %s\n", replybuf);
        return status;
    } else {
        return QDF_STATUS_E_FAILURE;
    }
}

uint32_t
acfg_dpp_configurator_remove(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[500], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_CONFIGURATOR_REMOVE_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_configurator_sign(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[500], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_CONFIGURATOR_SIGN_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_configurator_get_key(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[255];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_CONFIGURATOR_GETKEY_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "FAIL", 4)) {
        printf("dpp configurator key is: %s\n", replybuf);
        return status;
    } else {
        return QDF_STATUS_E_FAILURE;
    }
}

uint32_t
acfg_dpp_bootstrap_get_uri(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[255];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_BOOTSTRAP_GET_URI_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "FAIL", 4)) {
        printf("dpp bootstrap is: %s\n", replybuf);
        return status;
    } else {
        return QDF_STATUS_E_FAILURE;
    }
}

uint32_t
acfg_dpp_qr_code(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[500], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_QR_CODE_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "FAIL", 4)) {
        printf("dpp qr code ID: %s\n", replybuf);
        return status;
    } else {
        return QDF_STATUS_E_FAILURE;
    }
}

uint32_t
acfg_dpp_bootstrap_set(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[500], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_BOOTSTRAP_SET_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_configurator_params(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s %s", WPA_SET_CMD_PREFIX, "dpp_configurator_params", params);

    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_auth_init(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_AUTH_INIT_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_listen(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_LISTEN_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_stop_listen(char *ifname)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s", WPA_DPP_STOP_LISTEN_PREFIX);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_chirp(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_CHIRP_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_stop_chirp(char *ifname)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s", WPA_DPP_STOP_CHIRP_PREFIX);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_controller_start(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_CONTROLLER_START_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_controller_stop(char *ifname)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s", WPA_DPP_CONTROLLER_STOP_PREFIX);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_pkex_add(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_PKEX_ADD_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "FAIL", 4)) {
        printf("dpp pkex ID: %s\n", replybuf);
        return status;
    } else {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_pkex_remove(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_DPP_PKEX_REMOVE_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_mud_url_set(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_SET_CMD_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_pfs_set(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_SET_CMD_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_dpp_controller_set(char *ifname, char *params)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[10];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd, ctrl_wpasupp);
    memset(replybuf, '\0', sizeof (replybuf));
    len = sizeof (replybuf);
    snprintf(cmd, sizeof(cmd), "%s %s", WPA_SET_CMD_PREFIX, params);
    if (acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd), replybuf, &len,
                     opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }

    if (strncmp(replybuf, "OK", 2)) {
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

uint32_t
acfg_set_dpp_vap_params(acfg_wlan_profile_vap_params_t *vap_params,
                        acfg_dpp_conf_t *configs)
{
    acfg_opmode_t opmode;
    uint32_t status = QDF_STATUS_SUCCESS;

    status = acfg_get_opmode(vap_params->vap_name, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail for %s\n", __func__,
                vap_params->vap_name);
        return QDF_STATUS_E_FAILURE;
    }
    acfg_os_strcpy((char *)vap_params->ssid, (char *)configs->ssid, strlen(configs->ssid));

    if ((strncmp(configs->akm, "dpp+psk+sae", strlen("dpp+psk+sae")) == 0) ||
        (strncmp(configs->akm, "dpp+sae+psk", strlen("dpp+psk+sae")) == 0)) {
        vap_params->security_params.sec_method =
            ACFG_WLAN_PROFILE_SEC_METH_DPP_WPA2WPA3;
        vap_params->security_params.ieee80211w = 1;
    } else if ((strncmp(configs->akm, "dpp+sae", strlen("dpp+sae")) == 0)) {
        vap_params->security_params.sec_method =
            ACFG_WLAN_PROFILE_SEC_METH_DPP_WPA3;
        vap_params->security_params.ieee80211w = 1;
    } else if ((strncmp(configs->akm, "dpp", strlen("dpp")) == 0)) {
        vap_params->security_params.sec_method =
            ACFG_WLAN_PROFILE_SEC_METH_DPP;
        vap_params->security_params.ieee80211w = 1;
    } else if ((strncmp(configs->akm, "sae", strlen("sae")) == 0)) {
        vap_params->security_params.sec_method =
            ACFG_WLAN_PROFILE_SEC_METH_WPA3;
        vap_params->security_params.ieee80211w = 2;
    } else if ((strncmp(configs->akm, "psk+sae", strlen("psk+sae")) == 0)) {
        vap_params->security_params.sec_method =
            ACFG_WLAN_PROFILE_SEC_METH_WPA2WPA3;
        vap_params->security_params.ieee80211w = 1;
    } else if ((strncmp(configs->akm, "psk", strlen("psk")) == 0)) {
        vap_params->security_params.sec_method =
            ACFG_WLAN_PROFILE_SEC_METH_WPA2;
        vap_params->security_params.ieee80211w = 1;
    }

    if (configs->pass != NULL)
        strlcpy(vap_params->security_params.psk, configs->pass, strlen(configs->pass));

    vap_params->security_params.cipher_method = ACFG_WLAN_PROFILE_CIPHER_METH_AES;
    vap_params->security_params.g_cipher_method = ACFG_WLAN_PROFILE_CIPHER_METH_AES;

    if (configs->dpp_connector != NULL)
        strlcpy(vap_params->security_params.dpp_connector, configs->dpp_connector, strlen(configs->dpp_connector));
    if (configs->dpp_csign != NULL)
        strlcpy(vap_params->security_params.dpp_csign, configs->dpp_csign, strlen(configs->dpp_csign));
    if (configs->dpp_netaccesskey != NULL)
        strlcpy(vap_params->security_params.dpp_netaccesskey, configs->dpp_netaccesskey, strlen(configs->dpp_netaccesskey));

    return status;
}

int
acfg_get_dpp_config(uint8_t *ifname, acfg_dpp_conf_t *configs)
{
    char filename[32];
    FILE *fp;
    char *pos;
    int buflen = 0;
    char buf[1000];

    buflen = sizeof(buf);
    snprintf(filename, sizeof(filename), "/etc/%s_%s.conf",
             ACFG_DPP_CONFIG_PREFIX, ifname);
    fp = fopen(filename, "r");
    if (fp == NULL) {
        return QDF_STATUS_E_FAILURE;
    }

    while(fgets(buf, buflen, fp)) {
        pos = buf;
        if (strncmp(pos, "akm=", 4) == 0) {
            pos = strchr(buf, '=');
            pos++;
            memset(configs->akm, '\0', sizeof(configs->akm));
            snprintf(configs->akm, sizeof(configs->akm), "%s", pos);
        } else if (strncmp(pos, "ssid=", 5) == 0) {
            pos = strchr(buf, '=');
            pos++;
            memset(configs->ssid, '\0', sizeof(configs->ssid));
            snprintf(configs->ssid, sizeof(configs->ssid), "%s", pos);
        } else if (strncmp(pos, "pass=", 5) == 0) {
            pos = strchr(buf, '=');
            pos++;
            memset(configs->pass, '\0', sizeof(configs->pass));
            snprintf(configs->pass, sizeof(configs->pass), "%s", pos);
        } else if (strncmp(pos, "connector=", 10) == 0) {
            pos = strchr(buf, '=');
            pos++;
            memset(configs->dpp_connector, '\0', sizeof(configs->dpp_connector));
            snprintf(configs->dpp_connector,  sizeof(configs->dpp_connector), "%s", pos);
        } else if (strncmp(pos, "csign=", 6) == 0) {
            pos = strchr(buf, '=');
            pos++;
            memset(configs->dpp_csign, '\0', sizeof(configs->dpp_csign));
            snprintf(configs->dpp_csign, sizeof(configs->dpp_csign), "%s", pos);
        } else if (strncmp(pos, "netaccesskey=", 13) == 0) {
            pos = strchr(buf, '=');
            pos++;
            memset(configs->dpp_netaccesskey, '\0', sizeof(configs->dpp_netaccesskey));
            snprintf(configs->dpp_netaccesskey, sizeof(configs->dpp_netaccesskey), "%s", pos);
        }
    }
    fclose(fp);
    return 0;
}


uint32_t
acfg_dpp_update_vap(uint8_t *ifname)
{
    acfg_dpp_conf_t configs;
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_opmode_t opmode;
    acfg_wlan_profile_vap_params_t vap_params;
    acfg_wlan_profile_t *curr_profile, *new_profile;
    uint8_t wifi_iface[ACFG_MAX_RADIO][ACFG_MAX_IFNAME] = {"wifi0", "wifi1",
                                                           "wifi2", "wifi3"};
    unsigned int n;
    int i;

    status = acfg_get_opmode(ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail for %s\n", __func__, ifname);
        return QDF_STATUS_E_FAILURE;
    }
    if (opmode == ACFG_OPMODE_STA) {
        return status;
    }

    memset(&vap_params, 0, sizeof(acfg_wlan_profile_vap_params_t));
    for (n = 0; n < sizeof (wifi_iface) / sizeof(wifi_iface[0]); n++) {
        status = acfg_wlan_iface_present((char *)wifi_iface[n]);
        if(status != QDF_STATUS_SUCCESS) {
            continue;
        }
        if (acfg_alloc_profile(&new_profile, &curr_profile) != QDF_STATUS_SUCCESS)
            return QDF_STATUS_E_FAILURE;

        if (acfg_populate_profile(new_profile, (char*)wifi_iface[n]) == QDF_STATUS_E_INVAL) {
            /* no ACFG config found, try uci */
		printf("no ACFG config found\n");
            free(new_profile);
            free(curr_profile);
            return QDF_STATUS_E_FAILURE;
        }
        acfg_init_profile(curr_profile);

        for (i = 0; i < new_profile->num_vaps; i++) {
            strlcpy((char *)curr_profile->vap_params[i].vap_name,
                    (char *)new_profile->vap_params[i].vap_name, sizeof(curr_profile->vap_params[i].vap_name));
       curr_profile->vap_params[i].opmode = new_profile->vap_params[i].opmode;
        }
        curr_profile->num_vaps = new_profile->num_vaps;

        new_profile->priv = (void*)curr_profile;

        for (i = 0; i < ACFG_MAX_VAPS; i++) {
            new_profile->vap_params[i].radio_params = &new_profile->radio_params;
            curr_profile->vap_params[i].radio_params = &curr_profile->radio_params;
        }
        /* Apply the new profile */
        status = acfg_apply_profile(new_profile);

        for (i = 0; i < new_profile->num_vaps; i++) {
            if (strcmp((char *)ifname, (char *)curr_profile->vap_params[i].vap_name) == 0) {
                vap_params.phymode = new_profile->vap_params[i].phymode;
                vap_params.radio_params = new_profile->vap_params[i].radio_params;
                n = ACFG_MAX_RADIO;
            }
        }

        acfg_os_strcpy((char *)vap_params.vap_name, (char *)ifname,
                    sizeof(vap_params.vap_name));

        acfg_get_dpp_config(ifname, &configs);
        status = acfg_set_dpp_vap_params(&vap_params, &configs);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_free_profile(new_profile);
            return QDF_STATUS_E_FAILURE;
        }

        status = acfg_config_security(&vap_params);
        if (status != QDF_STATUS_SUCCESS) {
            acfg_free_profile(new_profile);
            return QDF_STATUS_E_FAILURE;
        }
        acfg_free_profile(new_profile);
    }

    return status;
}
