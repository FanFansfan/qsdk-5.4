/*
 * Copyright (c) 2018-2020 Qualcomm Technologies, Inc.
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

#include <appbr_if.h>
#include <acfg_wireless.h>
#include <acfg_api_cmds.h>

struct nlmsghdr *nlh = NULL;


uint32_t
acfg_wlan_vap_profile_get (acfg_wlan_profile_vap_params_t *vap_params)
{
    (void)vap_params;
    uint32_t status = QDF_STATUS_SUCCESS;

    return status;
}


uint32_t
acfg_hostapd_getconfig(uint8_t *vap_name, char *reply_buf)
{
    uint32_t       status = QDF_STATUS_SUCCESS;
    char buffer[4096];
    uint32_t len = 0;

    acfg_os_strcpy(buffer, "GET_CONFIG", sizeof(buffer));

    len = sizeof (reply_buf);
    if(acfg_ctrl_req (vap_name, buffer, strlen(buffer),
                reply_buf, &len, ACFG_OPMODE_HOSTAP) < 0){
        status = QDF_STATUS_E_FAILURE;
    }

    return status;
}

uint32_t
acfg_wlan_profile_get(acfg_wlan_profile_t *profile)
{
    int i;
    uint32_t status = QDF_STATUS_SUCCESS;

    status = acfg_wlan_iface_present((char *)profile->radio_params.radio_name);
    if(status != QDF_STATUS_SUCCESS) {
        return QDF_STATUS_E_INVAL;
    }

    status = acfg_get_current_profile(profile);
    if(status != QDF_STATUS_SUCCESS){
        acfg_log_errstr("%s: Failed to get driver profile for one or more vaps\n",
                __func__);
        return status;
    }

    for (i = 0; i < profile->num_vaps; i++) {
        if (profile->vap_params[i].opmode == IEEE80211_M_STA) {
            status = acfg_wpa_supplicant_get(&(profile->vap_params[i]));
            if(status != QDF_STATUS_SUCCESS)
            {
                acfg_log_errstr("%s: Failed to get security profile for %s\n",
                        __func__,
                        profile->vap_params[i].vap_name);
                return status;
            }
        }
        if (profile->vap_params[i].opmode == ACFG_OPMODE_HOSTAP) {
            status = acfg_hostapd_get(&(profile->vap_params[i]));
            if(status != QDF_STATUS_SUCCESS)
            {
                acfg_log_errstr("%s: Failed to get security profile for %s\n",
                        __func__,
                        profile->vap_params[i].vap_name);
                return status;
            }
        }
    }

    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_get_ifmac (char *ifname, char *buf)
{
    struct ifreq ifr;
    uint32_t   status = QDF_STATUS_SUCCESS;
    int s;
    int i = 0;
    uint8_t *ptr;

    memset(&ifr, 0, sizeof(struct ifreq));

    if(!ifname) {
        return QDF_STATUS_E_FAILURE;
    }

    acfg_os_strcpy(ifr.ifr_name, ifname, ACFG_MAX_IFNAME);

    s = socket(AF_INET, SOCK_DGRAM, 0);

    if(s < 0) {
        status = QDF_STATUS_E_BUSY;
        goto fail;
    }

    if ((i = ioctl (s, SIOCGIFHWADDR, &ifr)) < 0) {
        status = acfg_get_err_status();
        acfg_log_errstr("%s: IOCTL failed (status=%d)\n", __func__, status);
        close(s);
        goto fail;
    }

    ptr = (uint8_t *) ifr.ifr_hwaddr.sa_data;
    snprintf(buf, ACFG_MACSTR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
            (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
            (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

    close(s);

fail:
    return status;
}


/**
 * @brief
 *
 * @param vap_name
 * @param sinfo
 *
 * @return
 */
uint32_t
acfg_assoc_sta_info(uint8_t *vap_name, acfg_sta_info_req_t *sinfo)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t req = {.cmd = ACFG_REQ_GET_ASSOC_STA_INFO};
    acfg_sta_info_req_t *ptr ;

    ptr = (acfg_sta_info_req_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    ptr->len = sinfo->len ;
    ptr->info = sinfo->info ;

    status = acfg_os_send_req(vap_name, &req);

    sinfo->len = ptr->len ;

    return status;
}


/**
 * @brief Get the phymode
 *
 * @param vap_name
 * @param mode
 *
 * @return
 */
uint32_t
acfg_get_phymode(uint8_t *vap_name, acfg_phymode_t *mode)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    acfg_phymode_t * p_mode = NULL;
    acfg_os_req_t req = {.cmd = ACFG_REQ_GET_PHYMODE};

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_os_send_req(vap_name, &req);

    if (status == QDF_STATUS_SUCCESS) {
        p_mode = (acfg_phymode_t *)req.data;
        *mode = *p_mode;
    }

    return status;
}


/**
 * @brief Get Vap vendor param
 *
 * @param vap_name
 * @param param
 * @param val
 * @param type
 *
 * @return
 */
uint32_t
acfg_get_vap_vendor_param(uint8_t *vap_name, \
        acfg_param_vap_t param, uint8_t *data, uint32_t *type)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_VAP_VENDOR_PARAM};
    acfg_vendor_param_req_t *ptr;

    ptr = (acfg_vendor_param_req_t *)req.data;
    ptr->param = param ;

    status = acfg_os_send_req(vap_name, &req);

    if(status == QDF_STATUS_SUCCESS){
        memcpy(data, &ptr->data, sizeof(acfg_vendor_param_data_t));
        *type = ptr->type;
    }

    return status ;
}


uint32_t
acfg_get_chainmask(uint8_t *radio_name, enum acfg_chainmask_type type, uint32_t *mask)
{
    uint32_t   status = QDF_STATUS_SUCCESS;
    uint32_t   val;

    switch (type) {
    case ACFG_TX_CHAINMASK:
        status = acfg_get_radio_param(radio_name, ACFG_PARAM_RADIO_TXCHAINMASK, &val);
        break;
    case ACFG_RX_CHAINMASK:
        status = acfg_get_radio_param(radio_name, ACFG_PARAM_RADIO_RXCHAINMASK, &val);
        break;
    default:
        break;
    }

    if (status == QDF_STATUS_SUCCESS) {
        *mask = val;
    }

    return status;
}

/**
 * @brief Set ratemask of the VAP
 *
 * @param
 * @vap_name VAP interface
 * @preamble: 0 - legacy, 1 - HT, 2 - VHT
 * @mask_lower32: lower 32-bit mask
 * @mask_higher32: higher 32-bit mask
 * @mask_lower32: lower_2 32-bit mask
 *
 * @return
 */
uint32_t
acfg_set_ratemask(uint8_t  *vap_name, uint32_t preamble, uint32_t mask_lower32,
                  uint32_t mask_higher32, uint32_t mask_lower32_2)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_RATEMASK};
    acfg_ratemask_t   *ptr;

    ptr = (acfg_ratemask_t *)req.data;
    ptr->preamble = (uint8_t)(preamble & 0xFF);
    ptr->mask_lower32 = mask_lower32;
    ptr->mask_higher32 = mask_higher32;
    ptr->mask_lower32_2 = mask_lower32_2;

    status = acfg_os_send_req(vap_name, &req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: set ratemask failed! \n", vap_name);
        return QDF_STATUS_E_FAILURE;
    }

    return status;
}


/**
 * @brief Get the channel number
 *
 * @param wifi_name (Radio interface)
 * @param chan_num
 * @param chan_band
 *
 * @return
 */
uint32_t
acfg_get_channel(uint8_t *wifi_name, uint8_t *chan_num, uint8_t *chan_band)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_CHANNEL};

    if (acfg_os_check_str(wifi_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_os_send_req(wifi_name, &req);

    if(status == QDF_STATUS_SUCCESS) {
        *chan_num = req.data[0];
        *chan_band = req.data[1];
    }

    return status;
}



uint32_t
acfg_get_tx_antenna(uint8_t *radio_name,  uint32_t *mask)
{
    return acfg_get_chainmask(radio_name, ACFG_TX_CHAINMASK, mask);
}

uint32_t
acfg_get_rx_antenna(uint8_t *radio_name,  uint32_t *mask)
{
    return acfg_get_chainmask(radio_name, ACFG_RX_CHAINMASK, mask);
}

/**
 * @brief set basic & supported rates in beacon,
 * and use lowest basic rate as mgmt mgmt/bcast/mcast rates by default.
 * target_rates: an array of supported rates with bit7 set for basic rates.
 * num_of_rates: number of rates in the array
*/
uint32_t
acfg_set_op_support_rates(uint8_t  *radio_name, uint8_t *target_rates, uint32_t num_of_rates)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_SET_OP_SUPPORT_RATES};
    acfg_rateset_t  *rs;
    uint32_t      i = 0, j = 0;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    rs = (acfg_rateset_t *)req.data;
    if(num_of_rates > ACFG_MAX_RATE_SIZE){
        num_of_rates = ACFG_MAX_RATE_SIZE;
    }

    /* Check if any two rates are same */
    for(i=0;i<num_of_rates;i++){
        for(j=i+1;j<num_of_rates;j++){
            if(j == num_of_rates){
                break;
            }
            if((target_rates[i]&ACFG_RATE_VAL) == (target_rates[j]&ACFG_RATE_VAL)){
                acfg_log_errstr("%s failed! Same rates found: %d,%d !\n",__FUNCTION__, target_rates[i], target_rates[j]);
                return status;
            }
        }
    }

    rs->rs_nrates = num_of_rates;
    memcpy(rs->rs_rates, target_rates, num_of_rates);

    status = acfg_os_send_req(radio_name, &req);

    return status;
}

/**
 * @brief get supported legacy rates of the specified phymode for the radio
 * target_rates: return an array of supported rates with bit7 set for basic rates.
 * phymode : phymode
*/
uint32_t
acfg_get_radio_supported_rates(uint8_t  *radio_name, acfg_rateset_t *target_rates, acfg_phymode_t phymode)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_RADIO_SUPPORTED_RATES};
    acfg_rateset_phymode_t  *rs_phymode;
    acfg_rateset_t  *rs;
    uint8_t i=0;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    rs_phymode = (acfg_rateset_phymode_t *)req.data;
    rs_phymode->phymode = phymode;
    rs = &(rs_phymode->rs);
    if(rs->rs_nrates > ACFG_MAX_RATE_SIZE){
        rs->rs_nrates = ACFG_MAX_RATE_SIZE;
    }

    status = acfg_os_send_req(radio_name, &req);
    if(status!=QDF_STATUS_SUCCESS || rs->rs_nrates==0){
        acfg_log_errstr("%s failed!\n",__FUNCTION__);
        return QDF_STATUS_E_FAILURE;
    }

    for(i=0;i<rs->rs_nrates;i++){
        target_rates->rs_rates[i] = rs->rs_rates[i];
    }
    target_rates->rs_nrates = rs->rs_nrates;

    return QDF_STATUS_SUCCESS;
}

/**
 * @brief get supported legacy rates from BEACON IE
 * target_rates: return an array of supported rates with bit7 set for basic rates.
*/
uint32_t
acfg_get_beacon_supported_rates(uint8_t  *vap_name, acfg_rateset_t *target_rates)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_BEACON_SUPPORTED_RATES};
    acfg_rateset_t  *rs;
    uint8_t i=0;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    rs = (acfg_rateset_t *)req.data;
    rs->rs_nrates = sizeof(rs->rs_rates)/sizeof(uint8_t);
    if(rs->rs_nrates > ACFG_MAX_RATE_SIZE){
        rs->rs_nrates = ACFG_MAX_RATE_SIZE;
    }

    status = acfg_os_send_req(vap_name, &req);
    if(status!=QDF_STATUS_SUCCESS || rs->rs_nrates==0){
        acfg_log_errstr("%s failed, status=%d!\n",__FUNCTION__,status);
        return QDF_STATUS_E_FAILURE;
    }

    for(i=0;i<rs->rs_nrates;i++){
        target_rates->rs_rates[i] = rs->rs_rates[i];
    }
    target_rates->rs_nrates = rs->rs_nrates;

    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_del_key(uint8_t *vap_name, uint8_t *mac, uint16_t keyidx)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_DEL_KEY};
    acfg_del_key_t    *ptr;

    ptr     = (acfg_del_key_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    memcpy(ptr->macaddr, mac, ACFG_MACADDR_LEN);
    ptr->keyix = keyidx;

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

uint32_t
acfg_set_key(uint8_t *vap_name, uint8_t *mac, CIPHER_METH cipher, uint16_t keyidx,
             uint32_t keylen, uint8_t *keydata)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_SET_KEY};
    acfg_set_key_t    *ptr;

    ptr     = (acfg_set_key_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    memcpy(ptr->macaddr, mac, ACFG_MACADDR_LEN);
    ptr->cipher = cipher;
    ptr->keylen = keylen;
    ptr->keyix = keyidx;
    memcpy(ptr->keydata, keydata, sizeof(ptr->keydata));

    status = acfg_os_send_req(vap_name, &req);

    return status;
}




/**
 * @brief CLT table set command
 *
 * @param
 * @wifi_name physical radio interface name
 * @mode: 0 for 5G and 1 for 2G
 * @len: length of the table
 * @ctl_table: pointer to CTL table
 *
 * @return
 */

uint32_t
acfg_set_ctl_table(uint8_t  *wifi_name, uint32_t band, uint32_t len, uint8_t  *ctl_table)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    acfg_ctl_table_t     *ptr;
    acfg_os_req_t req = {.cmd = ACFG_REQ_SET_CTL_TABLE};

    ptr = (acfg_ctl_table_t *)req.data;
    ptr->band = band;
    ptr->len  = len;

    if(band != 0 && band != 1)
    {
        acfg_log_errstr("Invalid band. It can only be 0 or 1\n");
        return QDF_STATUS_E_FAILURE;
    }

    memcpy(&ptr->ctl_tbl[0], ctl_table, len);
    status = acfg_os_send_req(wifi_name, &req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: CTL Table set failed! \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }

    return status;
}


/**
 * @brief Enable amsdu per TID
 *
 * @param radio_name
 * @param amsdutidmask
 *
 * @return
 */
uint32_t
acfg_enable_amsdu(uint8_t             *radio_name,
        uint16_t            amsdutidmask
)
{
    uint32_t   status = QDF_STATUS_SUCCESS;

    status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_ENABLE_AMSDU, amsdutidmask);

    return status;
}

/**
 * @brief Enable ampdu per TID
 *
 * @param radio_name
 * @param ampdutidmask
 *
 * @return
 */
uint32_t
acfg_enable_ampdu(uint8_t             *radio_name,
        uint16_t            ampdutidmask
)
{
    uint32_t   status = QDF_STATUS_SUCCESS;

    status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_ENABLE_AMPDU, ampdutidmask);

    return status;
}

/**
 * @brief get per packet power dBm
 *
 * @param
 * @wifi_name physical radio interface name
 *
 * @return
 */

uint32_t
acfg_get_packet_power_info(uint8_t  *wifi_name, acfg_packet_power_param_t *param)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_PACKET_POWER_INFO};
    acfg_packet_power_param_t *ptr;

    ptr = (acfg_packet_power_param_t *)req.data;
    ptr->chainmask = param->chainmask;
    ptr->chan_width = param->chan_width;
    ptr->rate_flags = param->rate_flags;
    ptr->su_mu_ofdma = param->su_mu_ofdma;
    ptr->nss = param->nss;
    ptr->preamble = param->preamble;
    ptr->hw_rate = param->hw_rate;

    status = acfg_os_send_req(wifi_name, &req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Per packet power info request failed \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}


/**
 * @brief get rssi to dbm conversion factor
 *
 * @param
 * @wifi_name physical radio interface name
 *
 * @return
 */

uint32_t
acfg_get_nf_dbr_dbm_info(uint8_t  *wifi_name)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_NF_DBR_DBM_INFO};
    status = acfg_os_send_req(wifi_name, &req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: NF dbr dbm info request failed \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}


/**
 * @brief CCA Thresh hold set command
 *
 * @param
 * @wifi_name physical radio interface name
 * @cca_threshold: CCA power in dBm
 *
 * @return
 */

#define CCA_THRESHOLD_LIMIT_UPPER  -10
#define CCA_THRESHOLD_LIMIT_LOWER  -95

uint32_t
acfg_set_cca_threshold(uint8_t  *wifi_name, float cca_threshold)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    uint32_t  threshold =(int32_t)cca_threshold;
    acfg_log_errstr("%s[%d] CCA threshold = 0x%x\n", __func__, __LINE__, threshold);

    if((cca_threshold>CCA_THRESHOLD_LIMIT_UPPER) || (cca_threshold<CCA_THRESHOLD_LIMIT_LOWER))
    {
        acfg_log_errstr("Failed cca threshold limit test. Valid range (%d, %d)\n", CCA_THRESHOLD_LIMIT_UPPER, CCA_THRESHOLD_LIMIT_LOWER);
        return QDF_STATUS_E_FAILURE;
    }

    status = acfg_set_radio_param(wifi_name, ACFG_PARAM_RADIO_CCA_THRESHOLD, threshold);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: set cca threshold failed! \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}
#undef CCA_THRESHOLD_LIMIT_UPPER
#undef CCA_THRESHOLD_LIMIT_LOWER


/**
 * @brief Set sensitivity level in dBm
 *
 * @param
 * @wifi_name physical radio interface name
 * @sens_level: Sensitivity level in dBm
 *
 * @return
 */

#define SENS_LIMIT_UPPER    -10
#define SENS_LIMIT_LOWER    -95


uint32_t
acfg_set_sens_level(uint8_t  *wifi_name, float sens_level)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    uint32_t level=(int32_t)sens_level;
    acfg_log_errstr("%s[%d] sens_level = 0x%x\n", __func__, __LINE__, level);

    if((sens_level>SENS_LIMIT_UPPER) || (sens_level<SENS_LIMIT_LOWER))
    {
        acfg_log_errstr("Failed sens limit test. Valid range (%d, %d)\n", SENS_LIMIT_UPPER, SENS_LIMIT_LOWER);
        return QDF_STATUS_E_FAILURE;
    }

    status = acfg_set_radio_param(wifi_name, ACFG_PARAM_RADIO_SENS_LEVEL, level);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: set sens level failed! \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

#undef SENS_LIMIT_UPPER
#undef SENS_LIMIT_LOWER


/**
 * @brief Set mode based transmit power
 *
 * @param
 * @wifi_name physical radio interface name
 * @mode: 0 for 5G, 1 for 2G
 * @power: new transmit power which applies across the band
 *
 * @return
 */

#define POWER_LIMIT_UPPER   50.0
#define POWER_LIMIT_LOWER   -10.0


uint32_t
acfg_set_tx_power(uint8_t  *wifi_name, uint32_t mode, float power)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    uint32_t tx_power;
    tx_power = (int32_t) (2*power);
    acfg_log_errstr("%s[%d] mode = %d, power = %d\n", __func__,__LINE__, mode, tx_power);


    if((power>POWER_LIMIT_UPPER) || (power<POWER_LIMIT_LOWER))
    {
        acfg_log_errstr("Failed power limit test. Valid range (%f, %f)\n", POWER_LIMIT_UPPER, POWER_LIMIT_LOWER);
        return QDF_STATUS_E_FAILURE;
    }


    if(mode == 0)
    {
        status = acfg_set_radio_param(wifi_name, ACFG_PARAM_RADIO_TX_POWER_5G, tx_power);
    }
    else if (mode == 1)
    {
        status = acfg_set_radio_param(wifi_name, ACFG_PARAM_RADIO_TX_POWER_2G, tx_power);
    }
    else
    {
        acfg_log_errstr("%s[%d]:: Incorrect mode = %d\n", __func__,__LINE__,mode);
        status = QDF_STATUS_E_FAILURE;
    }

    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: set power failed! \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}


/**
 * @brief Get management/action frame retry limit
 *
 * @param
 * @radio_name: Physical radio interface
 * @limit:      Management/action frame retry limit
 *
 * @return
 */
uint32_t
acfg_get_mgmt_retry_limit(uint8_t *radio_name, uint8_t *limit)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    uint32_t val;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_get_radio_param(radio_name, ACFG_PARAM_RADIO_MGMT_RETRY_LIMIT, &val);
    if (status == QDF_STATUS_SUCCESS) {
        *limit = (uint8_t)val;
    }

    return status;
}


/**
 * @brief Set management/action frame retry limit
 *
 * @param
 * @radio_name: Physical radio interface
 * @limit:      Management/action frame retry limit
 *
 * @return
 */
uint32_t
acfg_set_mgmt_retry_limit(uint8_t *radio_name, uint8_t limit)
{
    uint32_t   status = QDF_STATUS_SUCCESS;
    status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_MGMT_RETRY_LIMIT, limit);
    return status;
}


#define TOTAL_FRAMES 20
static char buffer[MAX_PAYLOAD];
uint32_t
acfg_send_raw_multi(uint8_t  *vap_name, uint8_t *pkt_buf, uint32_t len, uint8_t type, uint16_t chan, uint8_t chan_band, uint8_t nss, uint8_t preamble, uint8_t mcs, uint8_t retry, uint8_t power, uint16_t scan_dur)
{
    uint32_t  status = QDF_STATUS_SUCCESS;
    int acfg_driver_sock;
    int on = 16*1024 ;
    int return_status;
    struct sockaddr_nl src_addr;
    struct acfg_offchan_hdr *acfg_hdr;
    uint32_t written;
    int32_t recvlen;
    struct acfg_offchan_tx_hdr *acfg_frame;
    int total_len, i;
    uint8_t retry_count = 0;

    total_len = TOTAL_FRAMES * (len + sizeof(struct acfg_offchan_tx_hdr)) + sizeof(struct acfg_offchan_hdr)
                                    + sizeof(struct nlmsghdr);
    if (total_len > MAX_PAYLOAD) {
        acfg_log_errstr("%s: Bad length\n", __FUNCTION__);
        return -1;
    }
    if (strlen((char*)vap_name) >= ACFG_MAX_IFNAME)
        return -1;

    if (QDF_STATUS_SUCCESS != acfg_wlan_iface_present((char *)vap_name))
        return -1;

    /* create a netlink socket */
    acfg_driver_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ACFG);
    if (acfg_driver_sock < 0) {
        acfg_log_errstr("socket errno=%d\n", acfg_driver_sock);
        return acfg_driver_sock;
    }
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 0;

    return_status = setsockopt(acfg_driver_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if(return_status < 0) {
        acfg_log_errstr("nl socket option failed\n");
        close(acfg_driver_sock);
        return return_status;
    }
    return_status = bind(acfg_driver_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(return_status < 0) {
        acfg_log_errstr("BIND errno=%d\n", return_status);
        close(acfg_driver_sock);
        return return_status;
    }

    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(*acfg_hdr) + len);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    acfg_hdr = NLMSG_DATA(nlh);
    acfg_os_strcpy((char *)acfg_hdr->vap_name, (char *)vap_name, ACFG_MAX_IFNAME);

    acfg_hdr->msg_type = type;
    acfg_hdr->msg_length = len;
    acfg_hdr->channel = chan;
    acfg_hdr->channel_band = chan_band;
    acfg_hdr->scan_dur = scan_dur;
    acfg_hdr->num_frames = TOTAL_FRAMES;

    acfg_frame = (struct acfg_offchan_tx_hdr *) (acfg_hdr + 1);

    for (i = 0; i < acfg_hdr->num_frames; i++) {
        acfg_frame->id = 1;
        acfg_frame->type = type;
        acfg_frame->length = len;
        acfg_frame->nss = nss;
        acfg_frame->preamble = preamble;
        acfg_frame->mcs = mcs;
        acfg_frame->retry = retry;
        acfg_frame->power = power;

        memcpy((acfg_frame + 1), pkt_buf, len);

        acfg_frame = (struct acfg_offchan_tx_hdr *) ((char*)(acfg_frame + 1) + len);
    }
    /* Check if buffer size exceed the maximum capacity */
    if(sizeof(struct nlmsghdr) + total_len > sizeof(buffer)) {
        acfg_log_errstr("Memory limit of buffer exceeeded. Closing connection. \n");
        close(acfg_driver_sock);
        return -1;
    }
    /* send the msg buffer to the driver */
    written = write(acfg_driver_sock, ((char *)buffer), sizeof(struct nlmsghdr) + total_len);

    if (written < total_len + sizeof(struct nlmsghdr)) {
        // TBD : Need to write pending data if there is partial write
        acfg_log_errstr("Partial write. Closing connection. Size: %d Written: %d\n", len + sizeof(struct acfg_offchan_hdr), written);
        close(acfg_driver_sock);
        acfg_driver_sock = -1;
    }

 again:
    /* wait for a response from the driver */
    do {
        sleep(1);
        recvlen = recv(acfg_driver_sock, buffer, MAX_PAYLOAD, MSG_DONTWAIT);
        retry_count++;
    } while(((recvlen < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
            && (retry_count < 5));

    if( recvlen <= 0 ) {
        status = QDF_STATUS_E_FAILURE;
        acfg_log_errstr("Nothing to receive! retry=%d\n",retry_count);
    } else {
        struct acfg_offchan_resp * acfg_resp;
        acfg_resp = (struct acfg_offchan_resp *) ((char *)buffer + sizeof(struct nlmsghdr));
        if (acfg_resp->hdr.msg_type == ACFG_CHAN_FOREIGN) {
            acfg_log_errstr("Foreign channel\n");
            goto again;
        } else if (acfg_resp->hdr.msg_type == ACFG_CHAN_HOME) {
            acfg_log_errstr("Home channel\n");
            goto again;
        } else {
            acfg_log_errstr("Tx status: %d\n", acfg_resp->hdr.msg_type);
            if (acfg_resp->hdr.msg_type != ACFG_PKT_STATUS_ERROR) {
                acfg_log_errstr("idx - Status\n");
                for (i = 0; i < acfg_resp->hdr.num_frames; i++)
                    acfg_log_errstr(" %d  -  %d\n", i, acfg_resp->status[i].status);
                acfg_log_errstr("\n");
            }
        }
    }
    return status;
}

uint32_t
acfg_send_raw_pkt(uint8_t  *vap_name, uint8_t *pkt_buf, uint32_t len, uint8_t type, uint16_t chan,
        uint8_t chan_band, uint8_t nss, uint8_t preamble, uint8_t mcs, uint8_t retry, uint8_t power, uint16_t scan_dur)
{
    uint32_t  status = QDF_STATUS_SUCCESS;
    int acfg_driver_sock;
    int on = 16*1024 ;
    int return_status;
    struct sockaddr_nl src_addr;
    struct acfg_offchan_hdr *acfg_hdr;
    uint32_t written;
    int32_t recvlen;
    uint8_t retry_count = 0;
    struct acfg_offchan_tx_hdr *acfg_frame;

    if (len > (MAX_PAYLOAD - sizeof(struct acfg_offchan_hdr) - sizeof(struct nlmsghdr)
                          - sizeof(struct acfg_offchan_tx_hdr))) {
        acfg_log_errstr("%s: Bad length\n", __FUNCTION__);
        return -1;
    }
    if (strlen((char*)vap_name) >= ACFG_MAX_IFNAME)
        return -1;

    if (QDF_STATUS_SUCCESS != acfg_wlan_iface_present((char *)vap_name))
        return -1;

    /* create a netlink socket */
    acfg_driver_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ACFG);
    if (acfg_driver_sock < 0) {
        acfg_log_errstr("socket errno=%d\n", acfg_driver_sock);
        return acfg_driver_sock;
    }
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 0;

    return_status = setsockopt(acfg_driver_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if(return_status < 0) {
        acfg_log_errstr("nl socket option failed\n");
        close(acfg_driver_sock);
        return return_status;
    }
    return_status = bind(acfg_driver_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(return_status < 0) {
        acfg_log_errstr("BIND errno=%d\n", return_status);
        close(acfg_driver_sock);
        return return_status;
    }

    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(*acfg_hdr) + sizeof(*acfg_frame) + len);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    acfg_hdr = NLMSG_DATA(nlh);
    acfg_os_strcpy((char *)acfg_hdr->vap_name, (char *)vap_name, ACFG_MAX_IFNAME);

    acfg_hdr->msg_type = type;
    acfg_hdr->msg_length = len;
    acfg_hdr->channel = chan;
    acfg_hdr->channel_band = chan_band;
    acfg_hdr->scan_dur = scan_dur;
    acfg_hdr->num_frames = 1;

    acfg_log_errstr("\n sending the info to driver with sock no. %d\n",acfg_driver_sock);
    acfg_frame = (struct acfg_offchan_tx_hdr *) (acfg_hdr +1);
    acfg_frame->id = 1;
    acfg_frame->type = type;
    acfg_frame->length = len;
    acfg_frame->nss = nss;
    acfg_frame->preamble = preamble;
    acfg_frame->mcs = mcs;
    acfg_frame->retry = retry;
    acfg_frame->power = power;

    memcpy((acfg_frame + 1), pkt_buf, len);

    /* send the msg buffer to the driver */
    written = write(acfg_driver_sock, ((char *)buffer),
                    sizeof(struct nlmsghdr) + sizeof(struct acfg_offchan_hdr) +
                    sizeof(struct acfg_offchan_tx_hdr) + len);
    if ( written < len + sizeof(struct acfg_offchan_hdr) + sizeof(struct acfg_offchan_tx_hdr)) {
        // TBD : Need to write pending data if there is partial write
        acfg_log_errstr("Partial write. Closing connection. Size: %d Written: %d\n", len + sizeof(struct acfg_offchan_hdr), written);
        close(acfg_driver_sock);
        acfg_driver_sock = -1;
    }

 again:
    /* wait for a response from the driver */
    do {
        sleep(1);
        recvlen = recv(acfg_driver_sock, buffer, MAX_PAYLOAD, MSG_DONTWAIT);
        retry_count++;
    } while(((recvlen < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
            && (retry_count < 5));

    if (recvlen <= 0) {
        status = QDF_STATUS_E_FAILURE;
        acfg_log_errstr("Nothing to receive! retry=%d\n",retry_count);
    } else {
        acfg_hdr = (struct acfg_offchan_hdr *) ((char *)buffer + sizeof(struct nlmsghdr));
        acfg_offchan_stat_t *offchan_stat;
        offchan_stat = (acfg_offchan_stat_t *) ((char *)buffer + sizeof(struct nlmsghdr) + sizeof(struct acfg_offchan_hdr));
        if (acfg_hdr->msg_type == ACFG_CHAN_FOREIGN) {
            acfg_log_errstr("Foreign channel\n");
            goto again;
        } else if (acfg_hdr->msg_type == ACFG_CHAN_HOME) {
            acfg_log_errstr("Home channel\n");
            goto again;
        } else {
            acfg_log_errstr("Tx status: %d\n", acfg_hdr->msg_type);
            printf("Dwell time %dus Home to Foreign switch time %dus Foreign to Home switch time %dus\n",
                   offchan_stat->dwell_time, offchan_stat->chanswitch_time_htof, offchan_stat->chanswitch_time_ftoh);
        }
    }
    return status;
}


uint32_t
acfg_send_raw_cancel(uint8_t  *vap_name)
{
    uint32_t  status = QDF_STATUS_SUCCESS;
    int acfg_driver_sock;
    int on = 16*1024 ;
    int return_status;
    struct sockaddr_nl src_addr;
    struct acfg_offchan_hdr *acfg_hdr;
    uint32_t written;

    if (strlen((char*)vap_name) >= ACFG_MAX_IFNAME)
        return -1;

    /* create a netlink socket */
    acfg_driver_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ACFG);
    if (acfg_driver_sock < 0) {
        acfg_log_errstr("socket errno=%d\n", acfg_driver_sock);
        return acfg_driver_sock;
    }
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 0;

    return_status = setsockopt(acfg_driver_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if(return_status < 0) {
        acfg_log_errstr("nl socket option failed\n");
        close(acfg_driver_sock);
        return return_status;
    }
    return_status = bind(acfg_driver_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(return_status < 0) {
        acfg_log_errstr("BIND errno=%d\n", return_status);
        close(acfg_driver_sock);
        return return_status;
    }

    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(*acfg_hdr));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    acfg_hdr = NLMSG_DATA(nlh);
    acfg_os_strcpy((char *)acfg_hdr->vap_name, (char *)vap_name, ACFG_MAX_IFNAME);

    acfg_hdr->msg_type = ACFG_CMD_CANCEL;

    /* send the msg buffer to the driver */
    written = write(acfg_driver_sock, ((char *)buffer),
                    sizeof(struct nlmsghdr) + sizeof(struct acfg_offchan_hdr));
    if ( written < sizeof(struct acfg_offchan_hdr)) {
        // TBD : Need to write pending data if there is partial write
        acfg_log_errstr("Partial write. Closing connection. Size: %d Written: %d\n", sizeof(struct acfg_offchan_hdr), written);
        close(acfg_driver_sock);
        acfg_driver_sock = -1;
    }

    return status;
}

static int get_bwmode_offset(char *param_str, uint8_t *bw_mode, uint8_t *sec_chan_offset)
{
    uint8_t ret;
    *sec_chan_offset = ACFG_SEC_CHAN_OFFSET_NA;

    if (strcmp ("40-", param_str) == 0) {
        *bw_mode = ACFG_OFFCHAN_BANDWIDTH_40MHZ;
        *sec_chan_offset = ACFG_SEC_CHAN_OFFSET_BELOW;
    } else if (strcmp ("40+", param_str) == 0) {
        *bw_mode = ACFG_OFFCHAN_BANDWIDTH_40MHZ;
        *sec_chan_offset = ACFG_SEC_CHAN_OFFSET_ABOVE;
   } else if (strcmp ("80+80", param_str) == 0) {
        acfg_log_errstr("80+80 bwmode is not supported ");
        return -1;
    } else {
         ret = strtol(param_str, NULL, 10);

         switch(ret) {

             case 20: *bw_mode = ACFG_OFFCHAN_BANDWIDTH_20MHZ;
                       break;
             case 40: *bw_mode = ACFG_OFFCHAN_BANDWIDTH_40MHZ;
                       break;
             case 80: *bw_mode = ACFG_OFFCHAN_BANDWIDTH_80MHZ;
                       break;
             case 160: *bw_mode = ACFG_OFFCHAN_BANDWIDTH_160MHZ;
                       break;
             default:
                       return -1;
          }
    }
    return 0;
}

uint32_t
acfg_offchan_rx(uint8_t  *vap_name, uint16_t chan, uint16_t scan_dur, char* params[])
{
    uint32_t  status = QDF_STATUS_SUCCESS;
    int acfg_driver_sock;
    int on = 16*1024 ;
    int return_status;
    struct sockaddr_nl src_addr;
    struct acfg_offchan_hdr *acfg_hdr;
    int32_t recvlen;
    uint32_t written;
    uint8_t bw_mode = 0;
    uint32_t chan_band = 0;
    uint8_t sec_chan_offset = 0;
    uint8_t retry_count = 0;
    int i = 0;

    if (strlen((char*)vap_name) >= ACFG_MAX_IFNAME)
        return -1;

    if (QDF_STATUS_SUCCESS != acfg_wlan_iface_present((char *)vap_name))
        return -1;

    for (i = 3; params[i] != NULL; i++) {
        if ((compare_string("-band", params[i]) == 0) || (compare_string("--band", params[i]) == 0)) {
            i++;
            if (!params[i]) {
                printf("%s: Please specify chan_band, should be [0, 3] inclusive\n", __func__);
                return -1;
            }
            get_uint32(params[i], (uint32_t *)&chan_band);
            if (chan_band > 3) {
                printf("Invalid chan_band: %d, should be [0, 3] "
                        "inclusive\n", chan_band);
                return -1;
            }
            continue;
        }

        return_status = get_bwmode_offset(params[i], &bw_mode, &sec_chan_offset);
        if (return_status < 0) {
            acfg_log_errstr("Invalid Bandwidth %s\n", params[i]);
            return return_status;
        }
    }
    /* create a netlink socket */
    acfg_driver_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ACFG);
    if (acfg_driver_sock < 0) {
        acfg_log_errstr("socket errno=%d\n", acfg_driver_sock);
        return acfg_driver_sock;
    }
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 0;

    return_status = setsockopt(acfg_driver_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if(return_status < 0) {
        acfg_log_errstr("nl socket option failed\n");
        close(acfg_driver_sock);
        return return_status;
    }
    return_status = bind(acfg_driver_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(return_status < 0) {
        acfg_log_errstr("BIND errno=%d\n", return_status);
        close(acfg_driver_sock);
        return return_status;
    }

    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(*acfg_hdr));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    acfg_hdr = NLMSG_DATA(nlh);
    acfg_os_strcpy((char *)acfg_hdr->vap_name, (char *)vap_name, ACFG_MAX_IFNAME);

    acfg_hdr->msg_type = ACFG_CMD_OFFCHAN_RX;
    acfg_hdr->msg_length = 0;
    acfg_hdr->channel = chan;
    acfg_hdr->channel_band = chan_band;
    acfg_hdr->scan_dur = scan_dur;
    acfg_hdr->bw_mode = bw_mode;
    acfg_hdr->sec_chan_offset =
                sec_chan_offset;

    /* send the msg buffer to the driver */
    written = write(acfg_driver_sock, ((char *)buffer),
                    sizeof(struct nlmsghdr) + sizeof(struct acfg_offchan_hdr));
    if ( written < sizeof(struct acfg_offchan_hdr)) {
        // TBD : Need to write pending data if there is partial write
        acfg_log_errstr("Partial write. Closing connection. Size: %d Written: %d\n", sizeof(struct acfg_offchan_hdr), written);
        close(acfg_driver_sock);
        acfg_driver_sock = -1;
    }

    /* wait for a response from the driver */
    do {
        sleep(1);
        recvlen = recv(acfg_driver_sock, buffer, MAX_PAYLOAD, MSG_DONTWAIT);
        retry_count++;
    } while(((recvlen < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
            && (retry_count < 5));

    if (recvlen <= 0) {
            status = QDF_STATUS_E_FAILURE;
            acfg_log_errstr("Nothing to receive! retry=%d\n",retry_count);
    } else {
        acfg_offchan_stat_t *offchan_stat;
        acfg_hdr = (struct acfg_offchan_hdr *) ((char *)buffer + sizeof(struct nlmsghdr));
        offchan_stat = (acfg_offchan_stat_t *) ((char *)buffer + sizeof(struct nlmsghdr) + sizeof(struct acfg_offchan_hdr));
        printf("status %d noise floor %d\n", acfg_hdr->msg_type, offchan_stat->noise_floor);
        printf("Dwell time %dus Home to Foreign switch time %dus Foreign to Home switch time %dus\n",
                offchan_stat->dwell_time, offchan_stat->chanswitch_time_htof, offchan_stat->chanswitch_time_ftoh);
    }
    return status;
}

#if QCA_SUPPORT_GPR
/**
 * @brief start_gpr on a radio and enable for given vap
 *
 * @param
 * @vap_name VAP interface
 * @ pkt_buf pointer to buffer send from applications
 * @ len length of buffer sent
 * @ period periodicity of GPR packets in msec
 * @ nss nss of GPR packet
 * preamble preamble of GPR packet
 * mcs mcs of GPR packet
 *
 * @return
 */

uint32_t
acfg_start_gpr(uint8_t  *vap_name, uint8_t *pkt_buf, uint32_t len, uint32_t period, uint8_t nss, uint8_t preamble, uint8_t mcs)
{
    struct sockaddr_nl src_addr;
    struct acfg_offchan_hdr *acfg_hdr;
    struct acfg_offchan_tx_hdr *acfg_frame;
    uint32_t  status = QDF_STATUS_SUCCESS;
    uint32_t written;
    int acfg_driver_sock;
    int on = 16*1024 ;
    int return_status;
    int total_len;

    total_len = len + sizeof(struct acfg_offchan_tx_hdr) + sizeof(struct acfg_offchan_hdr)
                                    + sizeof(struct nlmsghdr);

    if (total_len > MAX_PAYLOAD) {
        acfg_log_errstr("%s: Bad length of %d, Max payload size is %d bytes \n", __FUNCTION__, len, MAX_PAYLOAD);
        return -1;
    }
    if (strlen((char*)vap_name) >= ACFG_MAX_IFNAME)
        return -1;

    /* create a netlink socket */
    acfg_driver_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ACFG);
    if (acfg_driver_sock < 0) {
        acfg_log_errstr("socket errno=%d\n", errno);
        return acfg_driver_sock;
    }
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 0;

    return_status = setsockopt(acfg_driver_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if(return_status < 0) {
        acfg_log_errstr("nl socket option failed\n");
        close(acfg_driver_sock);
        return return_status;
    }
    return_status = bind(acfg_driver_sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(return_status < 0) {
        acfg_log_errstr("BIND errno=%d\n", errno);
        close(acfg_driver_sock);
        return return_status;
    }

    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(*acfg_hdr) + sizeof(*acfg_frame) + len);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    acfg_hdr = NLMSG_DATA(nlh);
    acfg_os_strcpy((char *)acfg_hdr->vap_name, (char *)vap_name, ACFG_MAX_IFNAME);

    acfg_hdr->msg_type = ACFG_PKT_TYPE_GPR;
    acfg_hdr->msg_length = len;

    acfg_log_errstr("\n sending the info to driver with sock no. %d\n",acfg_driver_sock);
    acfg_frame = (struct acfg_offchan_tx_hdr *) (acfg_hdr +1);
    acfg_frame->id = 1;
    acfg_frame->type = ACFG_PKT_TYPE_GPR;
    acfg_frame->length = len;
    acfg_frame->nss = nss;
    acfg_frame->preamble = preamble;
    acfg_frame->mcs = mcs;
    acfg_frame->period = period;

    memcpy((acfg_frame + 1), pkt_buf, len);

    /* send the msg buffer to the driver */
    written = write(acfg_driver_sock, ((char *)buffer),
                    sizeof(struct nlmsghdr) + sizeof(struct acfg_offchan_hdr) +
                    sizeof(struct acfg_offchan_tx_hdr) + len);
    if ( written < len + sizeof(struct acfg_offchan_hdr) + sizeof(struct acfg_offchan_tx_hdr)) {
        acfg_log_errstr("Partial write. Closing connection. Size: %d Written: %d\n", len + sizeof(struct acfg_offchan_hdr), written);
        close(acfg_driver_sock);
        acfg_driver_sock = -1;
    }
    close(acfg_driver_sock);
    return status;
}

/**
 * @brief send_gpr_cmd per VAP
 *
 * @param
 * @vap_name VAP interface
 * @command: 0 - disable, 1 - enable, 2 - printstats,3 - clearstats
 *
 * @return
 */
uint32_t
acfg_send_gpr_cmd(uint8_t  *vap_name, uint32_t command)
{
    uint32_t   status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t req = {.cmd = ACFG_REQ_SEND_GPR_CMD};
    acfg_gpr_cmd_param_t   *ptr;
    ptr = (acfg_gpr_cmd_param_t *)req.data;
    ptr->command = command;

    status = acfg_os_send_req(vap_name, &req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: send_gpr_cmd failed! \n", vap_name);
        return QDF_STATUS_E_FAILURE;
    }

    return status;
}
#endif

/**
 * @brief set 11AX MU EDCA param ecwmin
 * ac: AC
 * value: value
*/
uint32_t
acfg_set_muedca_ecwmin(uint8_t *vap, uint32_t ac, uint32_t value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_SET_MUEDCA_ECWMIN};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;
    edca_param->val = value;

    status = acfg_os_send_req(vap, &req);
    return status;
}

/**
 * @brief get 11AX MU EDCA param ecwmin
 * ac: AC
 * value: return value
*/
uint32_t
acfg_get_muedca_ecwmin(uint8_t *vap, uint32_t ac, uint32_t *value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_MUEDCA_ECWMIN};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;

    status = acfg_os_send_req(vap, &req);
    if(status!=QDF_STATUS_SUCCESS){
        acfg_log_errstr("%s failed, status=%d!\n",__FUNCTION__,status);
        return QDF_STATUS_E_FAILURE;
    }
    *value = edca_param->val;

    return status;
}


/**
 * @brief set 11AX MU EDCA param
 * ac: AC
 * value: value
*/
uint32_t
acfg_set_muedca_ecwmax(uint8_t *vap, uint32_t ac, uint32_t value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_SET_MUEDCA_ECWMAX};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;
    edca_param->val = value;

    status = acfg_os_send_req(vap, &req);
    return status;
}

/**
 * @brief get 11AX MU EDCA param
 * ac: AC
 * value: return value
*/
uint32_t
acfg_get_muedca_ecwmax(uint8_t *vap, uint32_t ac, uint32_t *value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_MUEDCA_ECWMAX};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;

    status = acfg_os_send_req(vap, &req);
    if(status!=QDF_STATUS_SUCCESS){
        acfg_log_errstr("%s failed, status=%d!\n",__FUNCTION__,status);
        return QDF_STATUS_E_FAILURE;
    }
    *value = edca_param->val;

    return status;
}


/**
 * @brief set 11AX MU EDCA param
 * ac: AC
 * value: value
*/
uint32_t
acfg_set_muedca_aifsn(uint8_t *vap, uint32_t ac, uint32_t value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_SET_MUEDCA_AIFSN};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;
    edca_param->val = value;

    status = acfg_os_send_req(vap, &req);
    return status;
}

/**
 * @brief get 11AX MU EDCA param
 * ac: AC
 * value: return value
*/
uint32_t
acfg_get_muedca_aifsn(uint8_t *vap, uint32_t ac, uint32_t *value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_MUEDCA_AIFSN};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;

    status = acfg_os_send_req(vap, &req);
    if(status!=QDF_STATUS_SUCCESS){
        acfg_log_errstr("%s failed, status=%d!\n",__FUNCTION__,status);
        return QDF_STATUS_E_FAILURE;
    }
    *value = edca_param->val;

    return status;
}

/**
 * @brief set 11AX MU EDCA param
 * ac: AC
 * value: value
*/
uint32_t
acfg_set_muedca_acm(uint8_t *vap, uint32_t ac, uint32_t value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_SET_MUEDCA_ACM};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;
    edca_param->val = value;

    status = acfg_os_send_req(vap, &req);
    return status;
}

/**
 * @brief get 11AX MU EDCA param
 * ac: AC
 * value: return value
*/
uint32_t
acfg_get_muedca_acm(uint8_t *vap, uint32_t ac, uint32_t *value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_MUEDCA_ACM};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;

    status = acfg_os_send_req(vap, &req);
    if(status!=QDF_STATUS_SUCCESS){
        acfg_log_errstr("%s failed, status=%d!\n",__FUNCTION__,status);
        return QDF_STATUS_E_FAILURE;
    }
    *value = edca_param->val;

    return status;
}

/**
 * @brief set 11AX MU EDCA param
 * ac: AC
 * value: value
*/
uint32_t
acfg_set_muedca_timer(uint8_t *vap, uint32_t ac, uint32_t value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_SET_MUEDCA_TIMER};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;
    edca_param->val = value;

    status = acfg_os_send_req(vap, &req);
    return status;
}

/**
 * @brief get 11AX MU EDCA param
 * ac: AC
 * value: return value
*/
uint32_t
acfg_get_muedca_timer(uint8_t *vap, uint32_t ac, uint32_t *value)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_MUEDCA_TIMER};
    acfg_muedca_param_t *edca_param;

    edca_param = (acfg_muedca_param_t *)req.data;
    edca_param->ac = ac;

    status = acfg_os_send_req(vap, &req);
    if(status!=QDF_STATUS_SUCCESS){
        acfg_log_errstr("%s failed, status=%d!\n",__FUNCTION__,status);
        return QDF_STATUS_E_FAILURE;
    }
    *value = edca_param->val;

    return status;
}


/**
 * @brief get 11AX bss color
 * bsscolor: BSS color value range {0...63}
*/
uint32_t
acfg_get_bss_color(uint8_t *radio_name, uint32_t *bsscolor)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_GET_BSS_COLOR};
    acfg_bss_color_t *bss_color_t;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    status = acfg_os_send_req(radio_name, &req);
    if(status!=QDF_STATUS_SUCCESS){
        acfg_log_errstr("%s failed, status=%d!\n",__FUNCTION__,status);
        return QDF_STATUS_E_FAILURE;
    }

    bss_color_t = (acfg_bss_color_t *)req.data;
    *bsscolor = bss_color_t->bsscolor;

    return QDF_STATUS_SUCCESS;
}


/**
 * @brief set 11AX bss color
 * bsscolor: BSS color value range {0...63}
 * override: to override, value 0/1
*/
uint32_t
acfg_set_bss_color(uint8_t *radio_name, uint32_t bsscolor, uint32_t override)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t   req = {.cmd = ACFG_REQ_SET_BSS_COLOR};
    acfg_bss_color_t *bss_color_t;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    bss_color_t = (acfg_bss_color_t *)req.data;
    bss_color_t->subcmd = ACFG_SET_HE_BSSCOLOR;
    bss_color_t->bsscolor = bsscolor;
    bss_color_t->override = override;

    status = acfg_os_send_req(radio_name, &req);
    return status;
}

uint32_t
acfg_mon_enable_filter(uint8_t *vap_name, uint32_t val)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    uint32_t *     p_val = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_MON_ENABLE_FILTER};

    p_val = (uint32_t *)req.data;
    *p_val = val;
    status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief Enable MU Grouping per tidmask
 *
 * @param vap_name  (Upto ACFG_MAX_IFNAME)
 *        mac
 *        tidmask
 *
 * @return On Success
 *             If : QDF_STATUS_SUCCESS
 *             Else: QDF_STATUS_E_FAILURE
 *         On Error: A_STATUS_EFAULT
 */
uint32_t
acfg_set_mu_whtlist(uint8_t *vap_name, uint8_t *mac, uint16_t tidmask)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_SET_MU_WHTLIST};
    acfg_set_mu_whtlist_t    *ptr;

    ptr     = (acfg_set_mu_whtlist_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    memcpy(ptr->macaddr, mac, ACFG_MACADDR_LEN);
    ptr->tidmask = tidmask;

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

uint32_t
acfg_mon_listmac(uint8_t *vap_name)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_MON_LISTMAC};

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief mon addmac
 *
 * @param vap name
 * @param mac addr
 *
 *
 * @return
 */
uint32_t
acfg_mon_addmac(uint8_t *vap_name, uint8_t *addr)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_MON_ADDMAC};
    acfg_macaddr_t *mac;

    mac = (acfg_macaddr_t *)req.data;

    memcpy(mac->addr, addr, ACFG_MACADDR_LEN);
    status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief mon delmac
 *
 * @param vap name
 * @param mac addr
 *
 *
 * @return
 */
uint32_t
acfg_mon_delmac(uint8_t *vap_name, uint8_t *addr)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_MON_DELMAC};
    acfg_macaddr_t *mac;

    mac = (acfg_macaddr_t *)req.data;

    memcpy(mac->addr, addr, ACFG_MACADDR_LEN);
    status = acfg_os_send_req(vap_name, &req);

    return status;
}

/**
 * @brief GPIO output set command
 *
 * @param
 * @wifi_name physical radio interface name
 * @gpio_num: GPIO pin number
 * @set: 1 for set, 0 for unset
 *
 * @return
 */

uint32_t
acfg_gpio_set(uint8_t  *wifi_name, uint32_t gpio_num, uint32_t set)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GPIO_SET};
    acfg_gpio_set_t     *ptr;

    ptr = (acfg_gpio_set_t *)req.data;
    ptr->gpio_num = gpio_num;
    ptr->set = set;

    status = acfg_os_send_req(wifi_name, &req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: GPIO set failed! \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }

    return status;
}


/**
 * @brief config GPIO command
 *
 * @param
 * @wifi_name physical radio interface name
 * @gpio_num: GPIO pin number
 * @input: 1 for input, 0 for output
 * @pull_type: Pull type
 * @intr_mode: Interrupt mode
 *
 * @return
 */

uint32_t
acfg_gpio_config(uint8_t  *wifi_name, uint32_t gpio_num, uint32_t input, uint32_t pull_type, uint32_t intr_mode, uint32_t mux_config_val, uint32_t drive, uint32_t init_enable)
{
    uint32_t  status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GPIO_CONFIG};
    acfg_gpio_config_t *ptr;

    ptr = (acfg_gpio_config_t *)req.data;
    ptr->gpio_num = gpio_num;
    ptr->input = input;
    ptr->pull_type = pull_type;
    ptr->intr_mode = intr_mode;
    ptr->mux_config_val = mux_config_val;
    ptr->drive = drive;
    ptr->init_enable = init_enable;

    status = acfg_os_send_req(wifi_name, &req);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: GPIO config failed! \n", wifi_name);
        return QDF_STATUS_E_FAILURE;
    }

    return status;
}


/**
 * @brief tx99 wrapper, call the actual tx99 tool
 *
 * @param
 * @wifi_name physical radio interface
 * @tx99_data acfg_tx99_data_t structure
 *
 * @return
 */
uint32_t
acfg_tx99_tool(uint8_t  *wifi_name, acfg_tx99_data_t* tx99_data)
{
    uint32_t  status = QDF_STATUS_SUCCESS;
    char *argv[20];
    char interface_opt[3];
    char interface[6];
    char tx99_cmd[12];
    char tx99_mode_opt[6];
    char tx99_mode[10];
    char freq_opt[10];
    char freq[12];
    char chain_opt[10];
    char chain[12];
    char rate_opt[10];
    char rate[12];
    char mode_opt[8];
    char mode[16];
    char power_opt[8];
    char power[12];
    char pattern_opt[12];
    char pattern[12];
    char shortguard_opt[14] = "";

    snprintf(interface_opt, sizeof(interface_opt), "%s", "-i");
    snprintf(interface, sizeof(interface), "%s", wifi_name);
    snprintf(tx99_cmd, sizeof(tx99_cmd), "%s", "athtestcmd");
    argv[0]= tx99_cmd;
    argv[1]= interface_opt;
    argv[2]= interface;

    if(IS_TX99_TX(tx99_data->flags)){
        //tx99 TX
        if(!IS_TX99_TX_ENABLED(tx99_data->flags)){
            snprintf(tx99_mode_opt, sizeof(tx99_mode_opt), "%s", "--tx");
            snprintf(tx99_mode, sizeof(tx99_mode), "%s", "off");
            argv[3]= tx99_mode_opt;
            argv[4]= tx99_mode;
            argv[5]= (char*)0;
        }else{
            snprintf(tx99_mode_opt, sizeof(tx99_mode_opt), "%s", "--tx");
            snprintf(tx99_mode, sizeof(tx99_mode), "%s", "tx99");
            snprintf(freq_opt, sizeof(freq_opt), "%s", "--txfreq");
            snprintf(freq, sizeof(freq), "%d", tx99_data->freq);
            snprintf(chain_opt, sizeof(chain_opt), "%s", "--txchain");
            snprintf(chain, sizeof(chain), "%d", tx99_data->chain);
            snprintf(rate_opt, sizeof(rate_opt), "%s", "--txrate");
            snprintf(rate,sizeof(rate), "%d", tx99_data->rate);
            snprintf(mode_opt, sizeof(mode_opt), "%s", "--mode");
            snprintf(mode, sizeof(mode), "%s", tx99_data->mode);
            snprintf(power_opt, sizeof(power_opt), "%s", "--txpwr");
            snprintf(power, sizeof(power), "%d", tx99_data->power);
            snprintf(pattern_opt, sizeof(pattern_opt), "%s", "--txpattern");
            snprintf(pattern, sizeof(pattern), "%d", tx99_data->pattern);
            if(tx99_data->shortguard == 1 ){
                snprintf(shortguard_opt, sizeof(shortguard_opt),
                         "%s", "--shortguard");
            }
            argv[3]= tx99_mode_opt;
            argv[4]= tx99_mode;
            argv[5]= freq_opt;
            argv[6]= freq;
            argv[7]= chain_opt;
            argv[8]= chain;
            argv[9]= rate_opt;
            argv[10]= rate;
            argv[11]= mode_opt;
            argv[12]= mode;
            argv[13]= power_opt;
            argv[14]= power;
            argv[15]= pattern_opt;
            argv[16]= pattern;
            argv[17]= shortguard_opt;
            argv[18]= (char *)0;
        }
    }else{
        //tx99 RX
        if(IS_TX99_RX_REPORT(tx99_data->flags)){
            snprintf(tx99_mode_opt, sizeof(tx99_mode_opt), "%s", "--rx");
            snprintf(tx99_mode, sizeof(tx99_mode), "%s", "report");
            argv[3]= tx99_mode_opt;
            argv[4]= tx99_mode;
            argv[5]= (char*)0;
        }else{
            snprintf(tx99_mode_opt, sizeof(tx99_mode_opt), "%s", "--rx");
            snprintf(tx99_mode, sizeof(tx99_mode), "%s", "promis");
            snprintf(freq_opt, sizeof(freq_opt), "%s", "--rxfreq");
            snprintf(freq, sizeof(freq), "%d", tx99_data->freq);
            snprintf(chain_opt, sizeof(chain_opt), "%s", "--rxchain");
            snprintf(chain, sizeof(chain), "%d", tx99_data->chain);
            snprintf(mode_opt, sizeof(mode_opt), "%s", "--mode");
            snprintf(mode, sizeof(mode), "%s", tx99_data->mode);
            argv[3]= tx99_mode_opt;
            argv[4]= tx99_mode;
            argv[5]= freq_opt;
            argv[6]= freq;
            argv[7]= chain_opt;
            argv[8]= chain;
            argv[9]= mode_opt;
            argv[10]= mode;
            argv[11]= (char *)0;
        }
    }
#if QCA_DEBUG_TX99
    printf("###########dumping argv###############\n");
    int i;
    for(i=0; argv[i] != NULL;i++){
        printf("%s ",argv[i]);
    }
    printf("\n");
#endif
    if(fork()==0){
        status = execvp(tx99_cmd, argv);
    }

    return status;
}

uint32_t
acfg_add_client(uint8_t *vap_name, uint8_t *mac, uint32_t aid, uint32_t qos,
                acfg_rateset_t lrates, acfg_rateset_t htrates, acfg_rateset_t vhtrates,
                acfg_rateset_t herates)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_ADD_CLIENT};
    acfg_add_client_t    *ptr;

    ptr     = (acfg_add_client_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    memcpy(ptr->stamac, mac, ACFG_MACADDR_LEN);
    ptr->aid    = aid;
    ptr->qos    = qos;
    memcpy(&ptr->lrates, &lrates, sizeof(acfg_rateset_t));
    memcpy(&ptr->htrates, &htrates, sizeof(acfg_rateset_t));
    memcpy(&ptr->vhtrates, &vhtrates, sizeof(acfg_rateset_t));
    memcpy(&ptr->herates, &herates, sizeof(acfg_rateset_t));

    status = acfg_os_send_req(vap_name, &req);
    return status;
}

uint32_t
acfg_delete_client(uint8_t *vap_name, uint8_t *mac)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_DEL_CLIENT};
    acfg_del_client_t    *ptr;

    ptr     = (acfg_del_client_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    memcpy(ptr->stamac, mac, ACFG_MACADDR_LEN);
    status = acfg_os_send_req(vap_name, &req);

    return status;
}

uint32_t
acfg_forward_client(uint8_t *vap_name, uint8_t *mac)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_AUTHORIZE_CLIENT};
    acfg_authorize_client_t    *ptr;

    ptr     = (acfg_authorize_client_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    memcpy(ptr->mac, mac, ACFG_MACADDR_LEN);
    ptr->authorize = 1;

    status = acfg_os_send_req(vap_name, &req);

    return status;
}

uint32_t
acfg_set_tx_antenna(uint8_t *radio_name,  uint16_t mask)
{
    return acfg_set_chainmask(radio_name, ACFG_TX_CHAINMASK, mask);
}

uint32_t
acfg_set_rx_antenna(uint8_t *radio_name,  uint16_t mask)
{
    return acfg_set_chainmask(radio_name, ACFG_RX_CHAINMASK, mask);
}

uint32_t
acfg_config_radio(uint8_t *radio_name)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;

    /* set all radio defaults here */

    status = acfg_set_chainmask(radio_name, ACFG_TX_CHAINMASK, 0x7);
    if (status != QDF_STATUS_SUCCESS)
        return status;

    status = acfg_set_chainmask(radio_name, ACFG_RX_CHAINMASK, 0x7);
    if (status != QDF_STATUS_SUCCESS)
        return status;

    status = acfg_set_txpower_limit(radio_name, ACFG_BAND_2GHZ, 63);
    if (status != QDF_STATUS_SUCCESS)
        return status;

    status = acfg_set_txpower_limit(radio_name, ACFG_BAND_5GHZ, 63);
    if (status != QDF_STATUS_SUCCESS)
        return status;

    status = acfg_set_country(radio_name, 841);
    return status;
}

/**
 * @brief Is the VAP local or remote
 *
 * @param vap_name
 *
 * @return
 */
uint32_t
acfg_is_offload_vap(uint8_t *vap_name)
{
    uint32_t      status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t      req = {.cmd = ACFG_REQ_IS_OFFLOAD_VAP};
    //acfg_vapinfo_t    *ptr;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_INVAL;

    //ptr     = &req.data.vap_info;

    status = acfg_os_send_req(vap_name, &req);

    return status ;
}

/**
 * @brief Get the SSID
 *
 * @param vap_name
 * @param ssid
 */
uint32_t
acfg_get_ssid(uint8_t  *vap_name, acfg_ssid_t  *ssid)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_SSID};
    acfg_ssid_t        *ptr;

    ptr = (acfg_ssid_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_os_send_req(vap_name, &req);

    if (status == QDF_STATUS_SUCCESS)
        ssid->len = acfg_os_strcpy((char *)ssid->ssid, (char *)ptr->ssid, ACFG_MAX_SSID_LEN + 1);

    return status;
}
/**
 * @brief Get the RSSI
 *
 * @param vap_name
 * @param rssi
 */
uint32_t
acfg_get_rssi(uint8_t  *vap_name, acfg_rssi_t  *rssi)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_RSSI};
    acfg_rssi_t        *ptr;

    ptr = (acfg_rssi_t *)req.data;

    if (acfg_os_check_str(vap_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_os_send_req(vap_name, &req);

    if (status == QDF_STATUS_SUCCESS)
        memcpy(rssi, ptr, sizeof(acfg_rssi_t));

    return status;
}

/**
 * @brief Set the frequency
 *
 * @param wifi_name
 * @param freq - Frequency in MHz
 *
 * @return
 */
uint32_t
acfg_set_freq(uint8_t *wifi_name, uint32_t freq)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    uint32_t *     p_freq = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_SET_FREQUENCY};

    p_freq = (uint32_t *)req.data;
    *p_freq = freq;

    status = acfg_os_send_req(wifi_name, &req);
    return status ;
}

/**
 * @brief Get RTS threshold
 *
 * @param vap_name
 * @param rts
 *
 * @return
 */
uint32_t
acfg_get_rts(uint8_t *vap_name, acfg_rts_t *rts)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_rts_t * p_rts = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_RTS};

    status = acfg_os_send_req(vap_name, &req);

    p_rts = (acfg_rts_t *)req.data;
    *rts = *p_rts;

    return status ;
}

/**
 * @brief Get Fragmentation threshold
 *
 * @param vap_name
 * @param frag
 *
 * @return
 */
uint32_t
acfg_get_frag(uint8_t *vap_name, acfg_frag_t *frag)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_frag_t *  p_frag = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_FRAG};

    status = acfg_os_send_req(vap_name, &req);

    p_frag = (acfg_frag_t *)req.data;
    *frag = *p_frag;

    return status ;
}

/**
 * @brief Get default Tx Power in dBm
 *
 * @param wifi_name
 * @param iwparam
 *
 * @return
 */
uint32_t
acfg_get_txpow(uint8_t *wifi_name, acfg_txpow_t *txpow)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_txpow_t * p_txpow = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_TXPOW};

    status = acfg_os_send_req(wifi_name, &req);

    p_txpow = (acfg_txpow_t *)req.data;
    *txpow = *p_txpow;

    return status ;
}


/**
 * @brief Get Radio param
 *
 * @param radio_name
 * @param param
 * @param val
 *
 * @return
 */
uint32_t
acfg_get_radio_param(uint8_t *radio_name, \
        acfg_param_radio_t param, uint32_t *val)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_RADIO_PARAM};
    acfg_param_req_t *ptr;

    ptr = (acfg_param_req_t *)req.data;
    ptr->param = param;

    if(acfg_os_cmp_str(radio_name,(uint8_t *)"wifi",4)){
        acfg_log_errstr("Should use wifiX to get radio param.\n");
        return status ;
    }

    status = acfg_os_send_req(radio_name, &req);
    ptr = (acfg_param_req_t *)req.data;

    *val = ptr->val;

    return status ;
}

/**
 * @brief Get default bit rate
 *
 * @param vap_name
 * @param rate
 *
 * @return
 */
uint32_t
acfg_get_rate(uint8_t *vap_name, uint32_t *rate)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    uint32_t *     p_rate = NULL;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_RATE};

    status = acfg_os_send_req(vap_name, &req);

    /* Driver returns bitrate in Kbps
     * so coverting back to Bps
     */
    p_rate = (uint32_t *)req.data;
    *rate = *p_rate * 1000;

    return status ;
}

/**
 * @brief acl getmac_secondary
 *
 * @param vap_name
 *
 *
 *
 * @return
 */
uint32_t
acfg_acl_getmac_secondary(uint8_t *vap_name, acfg_macacl_t *maclist)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_ACL_GETMAC_SEC};
    acfg_macacl_t *list;
    uint32_t i = 0;

    list = (acfg_macacl_t *)req.data;

    status = acfg_os_send_req(vap_name, &req);
    if(status == QDF_STATUS_SUCCESS){
        for (i = 0; i < list->num; i++) {
            memcpy(maclist->macaddr[i], list->macaddr[i], ACFG_MACADDR_LEN);
        }
        maclist->num = list->num;
    }

#if 0
    memcpy(maclist, macacllist,
            (sizeof(macacllist->num) + macacllist->num * ACFG_MACADDR_LEN) );
#endif

    return status;
}

/**
 * @brief acl getmac
 *
 * @param vap_name
 *
 *
 *
 * @return
 */
uint32_t
acfg_acl_getmac(uint8_t *vap_name, acfg_macacl_t *maclist)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_GET_MAC_ADDR};
    acfg_macacl_t *list;
    uint32_t i = 0;

    list = (acfg_macacl_t *)req.data;

    status = acfg_os_send_req(vap_name, &req);
    if(status == QDF_STATUS_SUCCESS){
        for (i = 0; i < list->num; i++) {
            memcpy(maclist->macaddr[i], list->macaddr[i], ACFG_MACADDR_LEN);
        }
        maclist->num = list->num;
    }

    return status;
}

uint32_t acfg_recover_profile(char *radioname)
{
    acfg_wlan_profile_t *new_profile, *curr_profile;
    int status = QDF_STATUS_SUCCESS;
    char cmd[32];
    int i;
    int ret = 0;

    acfg_reset_errstr();
    memset(&cmd, '\0', sizeof(cmd));

    if (acfg_alloc_profile(&new_profile, &curr_profile) != QDF_STATUS_SUCCESS)
        return QDF_STATUS_E_FAILURE;

    if (acfg_populate_profile(new_profile, radioname) == QDF_STATUS_E_INVAL) {
        /* no ACFG config found, try uci */
        snprintf(cmd, sizeof(cmd)-1, "/sbin/wifi recover %s", radioname);
        ret = system(cmd);
        return ret;
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

    /* Free cur_profile & new_profile */
    acfg_free_profile(new_profile);

    return status;
}

uint32_t acfg_set_country(uint8_t *radio_name, uint16_t country_code)
{
    uint32_t   status = QDF_STATUS_SUCCESS;

    if(country_code == 0) {
        return QDF_STATUS_E_FAILURE;
    }

    status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_COUNTRYID,
                                  country_code);

    return status;
}

uint32_t
acfg_get_country(uint8_t *radio_name, uint32_t *country_code)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    uint32_t val;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_get_radio_param(radio_name, ACFG_PARAM_RADIO_COUNTRYID, &val);

    if (status == QDF_STATUS_SUCCESS) {
        *country_code = val;
    }

    return status;
}

uint32_t
acfg_get_regdomain(uint8_t *radio_name, uint32_t *regdomain)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    uint32_t val;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_get_radio_param(radio_name, ACFG_PARAM_RADIO_REGDOMAIN, &val);

    if (status == QDF_STATUS_SUCCESS) {
        *regdomain = val;
    }

    return status;
}

uint32_t acfg_set_shpreamble(uint8_t *radio_name, uint16_t shpreamble)
{
    uint32_t   status = QDF_STATUS_SUCCESS;

    status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_ENABLE_SHPREAMBLE,
                                  shpreamble);

    return status;
}

uint32_t
acfg_get_shpreamble(uint8_t *radio_name, uint32_t *shpreamble)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    uint32_t val;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_get_radio_param(radio_name, ACFG_PARAM_RADIO_ENABLE_SHPREAMBLE, &val);

    if (status == QDF_STATUS_SUCCESS) {
        *shpreamble = val;
    }

    return status;
}

uint32_t
acfg_set_shslot(uint8_t *radio_name, uint16_t shslot)
{
    uint32_t   status = QDF_STATUS_SUCCESS;

    status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_ENABLE_SHSLOT,
                                  shslot);

    return status;
}

uint32_t
acfg_get_shslot(uint8_t *radio_name, uint32_t *shslot)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    uint32_t val;

    if (acfg_os_check_str(radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_get_radio_param(radio_name, ACFG_PARAM_RADIO_ENABLE_SHSLOT, &val);

    if (status == QDF_STATUS_SUCCESS) {
        *shslot = val;
    }

    return status;
}

uint32_t
acfg_set_acs_pcaconly(uint8_t *radio_name, uint32_t acs_pcaconly)
{
    uint32_t status = QDF_STATUS_SUCCESS;

    status = acfg_set_radio_param(radio_name,
                                  (OL_ATH_PARAM_ACS_PRECAC_SUPPORT |
                                   OL_ATH_PARAM_SHIFT),
                                  acs_pcaconly);

    return status;
}

uint32_t
acfg_get_acs_pcaconly(uint8_t *radio_name, uint32_t *acs_pcaconly)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    uint32_t val;

    status = acfg_get_radio_param(radio_name,
                                  (OL_ATH_PARAM_ACS_PRECAC_SUPPORT |
                                   OL_ATH_PARAM_SHIFT),
                                  &val);

    if (status == QDF_STATUS_SUCCESS) {
        *acs_pcaconly = val;
    }

    return status;
}


uint32_t
acfg_set_txpower_limit(uint8_t *radio_name, enum acfg_band_type band, uint32_t power)
{
    uint32_t   status = QDF_STATUS_SUCCESS;

    switch (band) {
    case ACFG_BAND_2GHZ:
        status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_TXPOWER_LIMIT2G, power);
        break;
    case ACFG_BAND_5GHZ:
        status = acfg_set_radio_param(radio_name, ACFG_PARAM_RADIO_TXPOWER_LIMIT5G, power);
        break;
    default:
        break;
    }

    return status;
}

uint32_t
acfg_get_vap_info(uint8_t *ifname,
        acfg_wlan_profile_vap_params_t *vap_params)
{
    uint32_t status = QDF_STATUS_SUCCESS;
    acfg_macacl_t maclist;
    uint8_t i = 0;
    uint32_t val;
    acfg_ssid_t ssid;

    status = acfg_get_opmode(ifname, &vap_params->opmode);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    status = acfg_get_ssid(ifname, &ssid);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    acfg_os_strcpy((char *)vap_params->ssid, (char *)ssid.ssid, sizeof(vap_params->ssid));

    status = acfg_get_rate(ifname, &vap_params->bitrate);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    vap_params->bitrate = vap_params->bitrate / 1000000;

    status = acfg_get_txpow(ifname, &vap_params->txpow);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_rssi(ifname, &vap_params->rssi);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_rts(ifname, &vap_params->rts_thresh);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_frag(ifname, &vap_params->frag_thresh);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_acl_getmac(ifname, &maclist);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_acl_getmac_secondary(ifname, &maclist);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_MACCMD,
            &vap_params->node_params.node_acl);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    for (i = 0; i < maclist.num; i++) {
        memcpy(vap_params->node_params.acfg_acl_node_list[i],
                maclist.macaddr[i], ACFG_MACADDR_LEN);
    }
    vap_params->node_params.num_node = maclist.num;

    /* For Seconnd ACL list*/
    status = acfg_get_vap_param(ifname, ACFG_PARAM_MACCMD_SEC,
            &vap_params->node_params.node_acl_sec);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    for (i = 0; i < maclist.num; i++) {
        memcpy(vap_params->node_params.acfg_acl_node_list_sec[i],
                maclist.macaddr[i], ACFG_MACADDR_LEN);
    }
    vap_params->node_params.num_node_sec = maclist.num;

    status = acfg_get_vap_param(ifname, ACFG_PARAM_VAP_SHORT_GI, &val);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_VAP_AMPDU, &val);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    vap_params->ampdu = !!(val); /* double negation */

    status = acfg_get_vap_param(ifname, ACFG_PARAM_HIDESSID, &vap_params->hide_ssid);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_APBRIDGE, &val);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    vap_params->client_isolation = !val;

    status = acfg_get_vap_param(ifname, ACFG_PARAM_BEACON_INTERVAL,
            &vap_params->beacon_interval);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_PUREG, &vap_params->pureg);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_UAPSD, &vap_params->uapsd);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_PUREN, &vap_params->puren);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_EXTAP, &val);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    if (val) {
        vap_params->wds_params.wds_flags |= ACFG_FLAG_EXTAP;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_DISABLECOEXT, &val);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    vap_params->coext = !!(val);

    status = acfg_get_vap_param(ifname, ACFG_PARAM_DOTH, &vap_params->doth);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }

    status = acfg_get_vap_param(ifname, ACFG_PARAM_MODIFY_BEACON_RATE, &val);
    if(status != QDF_STATUS_SUCCESS){
        return status;
    }
    vap_params->bcn_rate = val;

    status = acfg_get_vap_param(ifname, ACFG_PARAM_IMPLICITBF, &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->implicitbf = val;

    status = acfg_get_vap_param(ifname, ACFG_PARAM_WNM_ENABLE, &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->wnm = val;

    status = acfg_get_vap_param(ifname, ACFG_PARAM_RRM_CAP, &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->rrm = val;

    status = acfg_get_vap_param(vap_params->vap_name, ACFG_PARAM_RX_MCSMAP,
            &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->he_rx_mcsmap = val;

    status = acfg_get_vap_param(vap_params->vap_name, ACFG_PARAM_TX_MCSMAP,
            &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->he_tx_mcsmap = val;

    status = acfg_get_vap_param(vap_params->vap_name, ACFG_PARAM_6G_SECURITY_COMP,
            &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->sec_comp_6g = val;

    status = acfg_get_vap_param(vap_params->vap_name, ACFG_PARAM_6G_KEYMGMT_MASK,
            &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->keymgmt_mask_6g = val;

    status = acfg_get_vap_param(vap_params->vap_name, ACFG_PARAM_GREEN_AP_PS_ENABLE,
            &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->greenap_ps_enable = val;

    status = acfg_get_vap_param(vap_params->vap_name, ACFG_PARAM_GREEN_AP_PS_TIMEOUT,
            &val);
    if(status != QDF_STATUS_SUCCESS) {
        return status;
    }
    vap_params->greenap_ps_trans_time = val;

    return status;
}

uint32_t
acfg_get_current_profile(acfg_wlan_profile_t *profile)
{
    uint32_t status = QDF_STATUS_E_FAILURE, final_status = QDF_STATUS_SUCCESS;
    acfg_os_req_t	req = {.cmd = ACFG_REQ_GET_PROFILE};
    acfg_radio_vap_info_t *ptr;
    int i = 0;

    ptr = (acfg_radio_vap_info_t *)req.data;
    if (acfg_os_check_str(profile->radio_params.radio_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    status = acfg_os_send_req(profile->radio_params.radio_name, &req);
    if (status == QDF_STATUS_SUCCESS) {
        acfg_os_strcpy((char *)profile->radio_params.radio_name, (char *)ptr->radio_name, ACFG_MAX_IFNAME);
        memcpy(profile->radio_params.radio_mac,
                ptr->radio_mac,
                ACFG_MACADDR_LEN);
        profile->radio_params.chan = ptr->chan;
        profile->radio_params.chan_band = ptr->chan_band;
        profile->radio_params.freq = ptr->freq;
        profile->radio_params.country_code = ptr->country_code;

        for (i = 0; i <  ptr->num_vaps; i++) {
            status = acfg_get_vap_info(ptr->vap_info[i].vap_name,
                    &profile->vap_params[i]);
            if(status != QDF_STATUS_SUCCESS){
                acfg_log_errstr("%s: Get vap info failed for %s\n", __func__,
                        ptr->vap_info[i].vap_name);
                final_status = QDF_STATUS_E_FAILURE;
                continue;
            }
            acfg_os_strcpy((char *)profile->vap_params[i].vap_name,
                           (char *)ptr->vap_info[i].vap_name,
                            sizeof(profile->vap_params[i].vap_name));
            memcpy(profile->vap_params[i].vap_mac,
                    ptr->vap_info[i].vap_mac,
                    ACFG_MACADDR_LEN);
            profile->vap_params[i].phymode = ptr->vap_info[i].phymode;
            profile->vap_params[i].security_params.sec_method =
                ptr->vap_info[i].sec_method;
            profile->vap_params[i].security_params.cipher_method =
                ptr->vap_info[i].cipher;
            if (ptr->vap_info[i].wep_key_len) {
                if (ptr->vap_info[i].wep_key_idx == 0) {
                    acfg_get_wep_str(profile->vap_params[i].security_params.wep_key0,
                            ptr->vap_info[i].wep_key,
                            ptr->vap_info[i].wep_key_len, ACFG_MAX_WEP_KEY_LEN);
                } else if (ptr->vap_info[i].wep_key_idx == 1) {
                    acfg_get_wep_str(profile->vap_params[i].security_params.wep_key1,
                            ptr->vap_info[i].wep_key,
                            ptr->vap_info[i].wep_key_len, ACFG_MAX_WEP_KEY_LEN);
                } else if (ptr->vap_info[i].wep_key_idx == 2) {
                    acfg_get_wep_str(profile->vap_params[i].security_params.wep_key2,
                            ptr->vap_info[i].wep_key,
                            ptr->vap_info[i].wep_key_len, ACFG_MAX_WEP_KEY_LEN);
                } else if (ptr->vap_info[i].wep_key_idx == 3) {
                    acfg_get_wep_str(profile->vap_params[i].security_params.wep_key3,
                            ptr->vap_info[i].wep_key,
                            ptr->vap_info[i].wep_key_len, ACFG_MAX_WEP_KEY_LEN);
                }
            }
        }
        profile->num_vaps = ptr->num_vaps;
    } else {
        acfg_log_errstr("%s: Error sending cmd\n", __func__);
    }
    return final_status;
}

uint32_t acfg_get_iface_list(acfg_vap_list_t *list, int *count)
{
    uint32_t status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t	req = {.cmd = ACFG_REQ_GET_PROFILE};
    acfg_radio_vap_info_t *ptr;
    uint8_t wifi_iface[ACFG_MAX_RADIO][ACFG_MAX_IFNAME] = {"wifi0", "wifi1", "wifi2", "wifi3"};
    unsigned int n;
    int num_iface = 0, i;

    for (n = 0; n < sizeof (wifi_iface) / sizeof(wifi_iface[0]); n++) {
        status = acfg_wlan_iface_present((char *)wifi_iface[n]);
        if(status != QDF_STATUS_SUCCESS) {
            continue;
        }
        ptr = (acfg_radio_vap_info_t *)req.data;
        memset(ptr, 0 , sizeof(acfg_radio_vap_info_t));
        if (acfg_os_check_str(wifi_iface[n], ACFG_MAX_IFNAME))
            return QDF_STATUS_E_NOENT;
        status = acfg_os_send_req(wifi_iface[n], &req);

        if (status == QDF_STATUS_SUCCESS) {
            for (i = 0; i <  ptr->num_vaps; i++) {

                acfg_os_strcpy((char *)list->iface[i + num_iface], (char *)ptr->vap_info[i].vap_name, ACFG_MAX_IFNAME);
            }
            num_iface += i;
        }
    }
    *count = num_iface;
    return QDF_STATUS_SUCCESS;
}

uint32_t
acfg_set_wps_pbc(char *ifname)
{
    acfg_opmode_t opmode;
    char cmd[255], replybuf[255];
    uint32_t len = 0;
    uint32_t status = QDF_STATUS_SUCCESS;

    memset(replybuf, 0, sizeof(replybuf));
    len = sizeof(replybuf);
    memset(cmd, '\0', sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "%s", WPA_WPS_PBC_CMD_PREFIX);

    status = acfg_get_opmode((uint8_t *)ifname, &opmode);
    if (status != QDF_STATUS_SUCCESS) {
        acfg_log_errstr("%s: Opmode fetch fail\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }

    acfg_get_ctrl_iface_path(ACFG_CONF_FILE, ctrl_hapd,
            ctrl_wpasupp);
    if(acfg_ctrl_req((uint8_t *)ifname, cmd, strlen(cmd),
                replybuf, &len,
                opmode) < 0){
        return QDF_STATUS_E_FAILURE;
    }
    if(strncmp(replybuf, "OK", 2) != 0) {
        acfg_log_errstr("set pbc failed for %s\n", ifname);
        return QDF_STATUS_E_FAILURE;
    }
    return status;
}

/**
 * @brief Set preamble
 *
 * @param vap_name (VAP interface)
 * @param preamble - long or short preamble  0-long preamble 1-short preamble
 *
 * @return
 */
uint32_t
acfg_set_preamble(uint8_t  *vap_name, uint32_t preamble)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    status = acfg_set_vap_param(vap_name, ACFG_PARAM_SHORTPREAMBLE, preamble);
    return status;
}


/**
 * @brief Set slot time
 *
 * @param vap_name (VAP interface)
 * @param shot - long or short slot time  0-long slot 1-short slot
 *
 * @return
 */
uint32_t
acfg_set_slot_time(uint8_t  *vap_name, uint32_t slot)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    status = acfg_set_vap_param(vap_name, ACFG_PARAM_SHORT_SLOT, slot);
    return status;
}

/**
 * @brief Set ERP
 *
 * @param vap_name (VAP interface)
 * @param erp - 0-disable ERP 1-enable ERP
 *
 * @return
 */
uint32_t
acfg_set_erp(uint8_t  *vap_name, uint32_t erp)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    status = acfg_set_vap_param(vap_name, ACFG_PARAM_ERP, erp);
    return status;
}

/**
 * @brief Set regdomain
 *
 * @param wifi_name (physical radio interface name)
 * @param regdomain
 *
 * @return
 */
uint32_t
acfg_set_regdomain(uint8_t  *wifi_name, uint32_t regdomain)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    status = acfg_set_radio_param(wifi_name, ACFG_PARAM_RADIO_REGDOMAIN, regdomain);
    return status;
}

uint32_t
acfg_set_chanswitch(uint8_t  *wifi_name, uint8_t chan_num, uint8_t chan_band)
{
    uint32_t       status = QDF_STATUS_E_FAILURE;
    acfg_os_req_t       req = {.cmd = ACFG_REQ_DOTH_CHSWITCH};
    acfg_chan_t        *ptr;

    ptr = (acfg_chan_t *)req.data;

    if (acfg_os_check_str(wifi_name, ACFG_MAX_IFNAME))
        return QDF_STATUS_E_NOENT;

    *ptr = chan_num;
    ptr++;
    *ptr = chan_band;

    status = acfg_os_send_req(wifi_name, &req);

    return status;

}

int acfg_ifname_index(uint8_t *name) {
    uint8_t *cp;
    int unit;

    for (cp = name; *cp != '\0' && !('0' <= *cp && *cp <= '9'); cp++)
        ;
    if (*cp != '\0')
    {
        unit = 0;
        for (; *cp != '\0'; cp++)
        {
            if (!('0' <= *cp && *cp <= '9'))
                return -1;
            unit = (unit * 10) + (*cp - '0');
        }
    }
    else
        unit = -1;
    return unit;
}

void
acfg_fill_wps_config(char *ifname, char *buf)
{
    char filename[32];
    FILE *fp;

    snprintf(filename, sizeof(filename), "%s_%s.conf",
            ACFG_WPS_CONFIG_PREFIX, ifname);
    fp = fopen(filename, "w");
    if(fp != NULL){
        fprintf(fp, "%s", buf);
        fclose(fp);
    }

}
