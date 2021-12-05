/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <net/if.h>
#include <net/ethernet.h>
#define _LINUX_IF_H /* Avoid redefinition of stuff */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <split.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if_arp.h>

#include "dataElements.h"
#include "dataElementsWlan.h"
#include "dataElementsUtil.h"
#include "dataElementsJson.h"
#include "bufrd.h"

#include <ieee80211_external.h>
#include <qca_vendor.h>

#define TRACE_ENTRY() dbgf(dataElementState.dbgModule, DBGINFO, "%s: Enter \n",__func__)
#define TRACE_EXIT() dbgf(dataElementState.dbgModule, DBGINFO, "%s: Exit \n",__func__)
#define TRACE_EXIT_ERR() dbgf(dataElementState.dbgModule, DBGERR, "%s: Exit with err %d\n",__func__,ret)

/* OL Radio xml parse using the shift and PARAM_BAND_INFO is fixed for cmd */
#define RADIO_PARAM_SHIFT 4096
#define RADIO_PARAM_BAND_INFO 399
#define OL_ATH_PARAM_BAND_INFO  (RADIO_PARAM_SHIFT + RADIO_PARAM_BAND_INFO)
#define ENABLE_OL_STATS_CMD 8205
#define LIST_STATION_CFG_ALLOC_SIZE 3*1024

#define HE_HANDLES_TXRX_MCS_SIZE 3

/**
 * @brief Internal state for Data Elements Msg.
 */
typedef struct {

    /// Init the Module
    DE_BOOL isInit;

    /// Number of radio
    int numOfRadio;

    ///current radio index
    int CurRadioIndex;

    //socket
    int Sock;

    //Current opclass of the radio
    int curOpClass;

    ///structure to maintain the radio information
    struct dataElementWlanRadioInfo RadioInfo[WLANIF_MAX_RADIOS];

    ///structure to maintain the interface information
    struct dataElementWlanRadioInfo *CurRadio;

} dataElementCmdWlanState_t;
static dataElementCmdWlanState_t dataElementCmdWlanState;

/**
 * @brief Struct to store ACS report content
 */
typedef struct dEACSReport_t {
    /// The number of channels reported in chanData
    u_int8_t numChans;

    /// The channel data for each channel
    struct ieee80211_acs_dbg chanData[WLAN_MANAGER_MAX_NUM_CHANS];

    /// The number of neighboring BSSes reported in neighborData
    u_int8_t numNeighbors;

    /// The info for each neighboring BSS
    ieee80211_neighbor_info neighborData[WLAN_MANAGER_MAX_NUM_NEIGHBORS];

    /// The operating channel of each neighboring BSS in the same order as the entries
    /// in neighborData above.
    u_int8_t neighborChans[WLAN_MANAGER_MAX_NUM_NEIGHBORS];

} dEACSReport_t;

wifi_cfg80211_context *cfg80211_ctx;
dataElementsDisassociationEventData_t *disassocData = NULL;

DE_STATUS dataElementsBSEventWlanCreate(char *ifname);
DE_STATUS dataElementsBSEventWlanInit(void);

/* nl handler for IW based ioctl*/
static int wdev_info_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *nl_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct wdev_info *info = arg;

    nla_parse(nl_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (nl_msg[NL80211_ATTR_IFTYPE])
    {
        info->nlmode = nla_get_u32(nl_msg[NL80211_ATTR_IFTYPE]);
    } else {
        dataElementDebug(DBGERR, "NL80211_ATTR_IFTYPE not found\n");
        return -EINVAL;
    }

    if(nl_msg[NL80211_ATTR_IFNAME])
    {
        if ( (nla_len(nl_msg[NL80211_ATTR_IFNAME]) < 0)
                && (nla_len(nl_msg[NL80211_ATTR_IFNAME]) > IFNAMSIZ) ) {
            dataElementDebug(DBGERR, "NL80211_ATTR_IFNAME length invalid\n");
            return -EINVAL;
        }
        memcpy(info->name, nla_data(nl_msg[NL80211_ATTR_IFNAME]), nla_len(nl_msg[NL80211_ATTR_IFNAME]));
        info->name[nla_len(nl_msg[NL80211_ATTR_IFNAME])] = '\0';
    } else {
        dataElementDebug(DBGERR, "NL80211_ATTR_IFNAME not found\n");
        return -EINVAL;
    }

    return NL_SKIP;
}

/*allocate and send nlmsg to handle IW based ioctl*/
int send_nlmsg_wdev_info ( const char *ifname, wifi_cfg80211_context *cfgCtx, struct wdev_info *dev_info)
{
    struct nl_msg *nlmsg;
    struct nl_cb *cb;
    int ret, err;

    nlmsg = nlmsg_alloc();
    if (!nlmsg) {
        dataElementDebug(DBGERR, "ERROR: Failed to allocate netlink message for msg.\n");
        return -ENOMEM;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        dataElementDebug(DBGERR, "ERROR: Failed to allocate netlink callbacks.\n");
        nlmsg_free(nlmsg);
        return -ENOMEM;
    }

    /* Prepare nlmsg get the Interface attributes */
    genlmsg_put(nlmsg, 0, 0, cfgCtx->nl80211_family_id , 0, 0, NL80211_CMD_GET_INTERFACE, 0);
    nla_put_u32(nlmsg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname));

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,wdev_info_handler , dev_info);

    /* send message */
    ret = nl_send_auto_complete(cfgCtx->cmd_sock, nlmsg);
    if (ret < 0) {
        goto out;
        goto out;
    }

    /*   wait for reply */
    while (err > 0) {  /* error will be set by callbacks */
        ret = nl_recvmsgs(cfgCtx->cmd_sock, cb);
        if (ret) {
            dataElementDebug(DBGERR, "nl80211: %s->nl_recvmsgs failed: %d\n", __func__, ret);
        }
    }

out:
    if (cb) {
        nl_cb_put(cb);
    }
    if (nlmsg) {
        nlmsg_free(nlmsg);
    }
    return err;
}

/* Function to check whether the current device is AP */
int isAP(void *ctx, const char * ifname, uint32_t *result)
{
    int ret;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    if ((ret = send_nlmsg_wdev_info(ifname, cfg80211_ctx, &devinfo)) < 0) {
        goto err;
    }

    *result = ( devinfo.nlmode == NL80211_IFTYPE_AP ? 1 : 0 );

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

static struct nla_policy
wlan_cfg80211_get_wireless_mode_policy[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1] = {

    [QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH] = {.type = NLA_U32 },
    [QCA_WLAN_VENDOR_ATTR_PARAM_DATA] = {.type = NLA_STRING },
};

void cfg82011_wificonfiguration_cb(struct cfg80211_data *buffer)
{
    struct nlattr *attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1];

    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_PARAM_MAX,
            (struct nlattr *)buffer->data,
            buffer->length, wlan_cfg80211_get_wireless_mode_policy);
}

/* Function to get BSSID address */
int getBSSID(wifi_cfg80211_context *cfg80211_ctx, const char * ifname, struct ether_addr *BSSID )
{
    int ret;

    TRACE_ENTRY();

    struct cfg80211_data buffer;
    buffer.data = BSSID;
    buffer.length = IEEE80211_ADDR_LEN;
    buffer.parse_data = 0;
    buffer.callback = &cfg82011_wificonfiguration_cb;
    if((ret=wifi_cfg80211_send_getparam_command(cfg80211_ctx, QCA_NL80211_VENDORSUBCMD_BSSID, 0, ifname, (char *)&buffer, IEEE80211_ADDR_LEN)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Funtion to get ESSID info */
int getESSID(wifi_cfg80211_context *cfg80211_ctx, const char * ifname, void *buf, uint32_t *len )
{
    int ret;
    struct cfg80211_data buffer;

    TRACE_ENTRY();

    memset(buf, 0, (IEEE80211_NWID_LEN + 1));
    buffer.data = (void *)buf;
    buffer.length = IEEE80211_NWID_LEN;
    buffer.parse_data = 0; /* Enable callback */
    buffer.callback = &cfg82011_wificonfiguration_cb;

    if((ret=wifi_cfg80211_send_getparam_command(cfg80211_ctx,
                    QCA_NL80211_VENDORSUBCMD_GET_SSID, 0,
                    ifname, (char *)&buffer, IEEE80211_NWID_LEN)) < 0)
    {
        goto err;
    }
    *len = strlen((char *)buf);
    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Cfg80211 command to send genric commands to driver*/
int send_generic_command_cfg80211(wifi_cfg80211_context *cfgCtx, const char *ifname, int maincmd, int cmd, char *data, int data_len)
{
    int res;
    struct cfg80211_data buffer;
    buffer.data = (void *)data;
    buffer.length = data_len;
    buffer.callback = NULL;
    buffer.parse_data = 0;

    res = wifi_cfg80211_send_generic_command(cfgCtx, maincmd, cmd, ifname, (char *)&buffer, data_len);
    if (res < 0) {
        dataElementDebug(DBGERR, " %s : send NL command failed \n",__func__);
        return res;
    }
    if (cmd == QCA_NL80211_VENDOR_SUBCMD_LIST_STA){
        data_len = buffer.length;
    }

    return 0;
}

/* Function to command get param in driver */
int send_command_get_cfg80211( wifi_cfg80211_context *cfgCtx, const char *ifname, int op, int *data)
{
    int ret;
    struct cfg80211_data buffer;
    buffer.data = data;
    buffer.length = sizeof(int);
    buffer.parse_data = 0;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    if((ret=wifi_cfg80211_send_getparam_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, op, ifname, (char *)&buffer, sizeof(int))) < 0)
    {
        return -EIO;
    }
    return 0;
}

/*cfg80211 command to set param in driver*/
int send_command_set_cfg80211(wifi_cfg80211_context *cfgCtx, const char *ifname, int op, int *data, int data_len)
{
    int ret;
    struct cfg80211_data buffer;
    buffer.data = data;
    buffer.length = sizeof(int);
    buffer.parse_data = 0;
    buffer.callback = NULL;
    if((ret=wifi_cfg80211_send_setparam_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, op, ifname, (char *)&buffer, sizeof(int))) < 0)
    {
        return ret;
    }
    return 0;
}

/* Function to setparam in the driver*/
int setParam(wifi_cfg80211_context *cfg80211_ctx, const char *ifname, int cmd, void *data, uint32_t len)
{
    int ret;
    TRACE_ENTRY();

    if((ret = send_command_set_cfg80211(cfg80211_ctx, ifname, cmd, data, len)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

DE_BOOL isBssEnabled(char *ifname) {
    struct iwreq deifr;
    deifr.u.bitrate.value = 0;
    DE_BOOL enabled = DE_FALSE;
    int iwret = 0;
    strlcpy(deifr.ifr_name, ifname, IFNAMSIZ);
    if((iwret = ioctl(dataElementCmdWlanState.Sock, SIOCGIWRATE, &deifr)) < 0) {
        dataElementDebug(DBGERR, "%s: ioctl() SIOCGIWRATE failed, ifname: %s ret %d\n",
             __func__, ifname, iwret);
        perror("ioctl");
        return enabled;
    }
    if(deifr.u.bitrate.value) {
        enabled = DE_TRUE;
        dataElementDebug(DBGDUMP, "%s:ifname: %s is enabled, bitrate=%d(Mbits/s)\n",
                  __func__, ifname, deifr.u.bitrate.value/1000);
    }
    return enabled;
}

/**
 * @brief Get Bss data from the driver
 *
 * @param [in] radioIndex index of the radio
 * @param [in] radiodata
 * @param [in] bssData structure to update the values
 *
 * @return DE_OK for success
 */
DE_STATUS dEGetWlanBssData(u_int8_t radioIndex, dataElementsRadio_t *radioData, dataElementsBSS_t *bssData) {
    radioData->numberOfBSS = dataElementCmdWlanState.CurRadio->numOfVap;
    u_int8_t bssCount;
    for (bssCount = 0; bssCount < radioData->numberOfBSS; bssCount++) {
        uint32_t ret=0,length=0,result=0;
        struct dataElementWlanVapInfo *vaps = &dataElementCmdWlanState.CurRadio->vaps[bssCount];
        ret = isAP(cfg80211_ctx, vaps->ifname, &result);
        if( result ) {
            DE_BOOL bssEnabled = isBssEnabled(vaps->ifname);
            bssData[bssCount].enabled = bssEnabled;
            struct ether_addr bssid = {0};
            ret = getBSSID(cfg80211_ctx, vaps->ifname, &bssid);
            if (ret < 0) {
                dataElementDebug(DBGERR, "%s: failed to get BSSID \n",__func__);
            }
            dataElementDebug(DBGDEBUG, "%s: BSSID " deMACAddFmt(":") "\n",__func__,
                    deMACAddData(&bssid.ether_addr_octet));
             bssData[bssCount].BSSID.ether_addr_octet[0]=bssid.ether_addr_octet[0];
             bssData[bssCount].BSSID.ether_addr_octet[1]=bssid.ether_addr_octet[1];
             bssData[bssCount].BSSID.ether_addr_octet[2]=bssid.ether_addr_octet[2];
             bssData[bssCount].BSSID.ether_addr_octet[3]=bssid.ether_addr_octet[3];
             bssData[bssCount].BSSID.ether_addr_octet[4]=bssid.ether_addr_octet[4];
             bssData[bssCount].BSSID.ether_addr_octet[5]=bssid.ether_addr_octet[5];
            u_int8_t buf[IEEE80211_NWID_LEN + 1];
            length = IEEE80211_NWID_LEN;
            ret = getESSID(cfg80211_ctx, vaps->ifname, &buf, &length);
            if (ret < 0) {
                dataElementDebug(DBGERR, "%s: failed to get ESSID \n",__func__);
            }
            strlcpy((char *)bssData[bssCount].ssid, (char *)buf, sizeof(bssData[bssCount].ssid));
            dataElementDebug(DBGDEBUG, "%s: ssid is %s \n",__func__,buf);
            if (( ret = send_command_get_cfg80211(cfg80211_ctx, vaps->ifname, IEEE80211_PARAM_STA_COUNT, (int *)&bssData[bssCount].NumberOfSTA)) < 0) {
                dataElementDebug(DBGERR, "%s: failed to get staCount \n",__func__);
            }

            dEEspInfo_t espInfo[deEspAC_Max];
            struct ieee80211req_athdbg req = {0};
            struct mesh_dbg_req_t mesh_req = {0};

            req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
            req.data.mesh_dbg_req.mesh_cmd = MESH_MAP_GET_ESP_INFO;
            ret = send_generic_command_cfg80211(cfg80211_ctx, vaps->ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req, (sizeof(struct ieee80211req_athdbg)));
            if (ret < 0) {
                dataElementDebug(DBGERR, "%s: ESP info failed, ifName: %s.\n", __func__, vaps->ifname);
            }

            mesh_req = (struct mesh_dbg_req_t )(req.data.mesh_dbg_req);
            memcpy(espInfo, &mesh_req.mesh_data.map_esp_info, sizeof(*espInfo) * deEspAC_Max);

            u_int8_t deServiceAC = 0;
            for (deServiceAC = 0; deServiceAC < deEspAC_Max; deServiceAC++) {
                if (espInfo[deServiceAC].includeESPInfo) {
                    switch (deServiceAC) {
                        case deEspAC_BK:
                            memcpy(&bssData[bssCount].apMetrics.espInfo[mapServiceAC_BK],
                                    &espInfo[deEspAC_BK],
                                    sizeof(dEEspInfo_t));
                            break;
                        case deEspAC_BE:
                            memcpy(&bssData[bssCount].apMetrics.espInfo[mapServiceAC_BE],
                                    &espInfo[deEspAC_BE],
                                    sizeof(dEEspInfo_t));
                            break;
                        case deEspAC_VI:
                            memcpy(&bssData[bssCount].apMetrics.espInfo[mapServiceAC_VI],
                                    &espInfo[deEspAC_VI],
                                    sizeof(dEEspInfo_t));
                            break;
                        case deEspAC_VO:
                            memcpy(&bssData[bssCount].apMetrics.espInfo[mapServiceAC_VO],
                                    &espInfo[deEspAC_VO],
                                    sizeof(dEEspInfo_t));
                            break;
                        default:
                            break;
                    }
                }
            }


            struct ieee80211_stats *stats;
            struct ieee80211_mac_stats *ucaststats;
            struct ieee80211_mac_stats *mcaststats;
            int    stats_total_len = sizeof(struct ieee80211_stats) +
                (2 * sizeof(struct ieee80211_mac_stats)) +
                4;
            stats = (struct ieee80211_stats *)malloc(stats_total_len);
            if (stats == NULL) {
                dataElementDebug(DBGERR, "%s: malloc failed \n",__func__);
                return -ENOMEM;
            }
            memset(stats, 0, stats_total_len);

            ret = send_generic_command_cfg80211(cfg80211_ctx, vaps->ifname,QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_80211STATS, (void *)stats, stats_total_len);
            if (ret < 0) {
                dataElementDebug(DBGERR, "%s: 80211STATS failed ifname %s \n",__func__, vaps->ifname);
            }
            ucaststats = (struct ieee80211_mac_stats*)
                ((unsigned char *)stats +
                 sizeof(struct ieee80211_stats));
            mcaststats = (struct ieee80211_mac_stats*)
                ((unsigned char *)ucaststats +
                 sizeof(struct ieee80211_mac_stats));
            dataElementDebug(DBGDUMP, "%s:%d> stats:%p\n", __func__, __LINE__, stats);
            dataElementDebug(DBGDUMP, "%s:%d> bssCount:%d ucaststats:%p \n", __func__, __LINE__, bssCount, ucaststats );
            dataElementDebug(DBGDUMP, "%s:%d> unicastBytesSent:%d ims_tx_data_bytes:%"PRIu64" \n", __func__, __LINE__, bssData[bssCount].unicastBytesSent, ucaststats->ims_tx_data_bytes );
            bssData[bssCount].unicastBytesSent = ucaststats->ims_tx_data_bytes;
            bssData[bssCount].unicastBytesReceived = ucaststats->ims_rx_data_bytes;
            bssData[bssCount].multicastBytesSent = mcaststats->ims_tx_data_bytes;
            bssData[bssCount].multicastBytesReceived = mcaststats->ims_rx_data_bytes;
            bssData[bssCount].broadcastBytesSent = mcaststats->ims_tx_bcast_data_bytes;
            bssData[bssCount].broadcastBytesReceived = mcaststats->ims_rx_bcast_data_packets;

            //dataElementDebug(DBGERR, "%s: bssData.unicastBytesSent %d bssData.unicastBytesReceived %d bssData.multicastBytesSent %d bssData.multicastBytesReceived %d bssData.broadcastBytesSent %d bssData.broadcastBytesReceived %d bssData[bssCount].NumberOfSTA %d \n",__func__ ,bssData[bssCount].unicastBytesSent, bssData[bssCount].unicastBytesReceived, bssData[bssCount].multicastBytesSent, bssData[bssCount].multicastBytesReceived, bssData[bssCount].broadcastBytesSent, bssData[bssCount].broadcastBytesReceived,bssData[bssCount].NumberOfSTA);

            //dataElementsBSEventWlanCreate(bssCount);
            fflush(stdout);
            free(stats);
        }
    }
    return DE_OK;
}

/**
 * @brief Get radio capable opclass data
 *
 * @param [in] capable opclass structure to update
 *
 * @return DE_OK on success
 */
DE_STATUS dEGetWlanRadioCapableOpClassData(dataElementsCapableOpClassProfile_t *capOpClassData) {
    ieee1905APRadioBasicCapabilities_t apRadioBasicCap;

    memcpy(&apRadioBasicCap, &dataElementCmdWlanState.CurRadio->radioBasicCapabilities, sizeof(ieee1905APRadioBasicCapabilities_t));
    u_int8_t i;
    int ret;
    struct ieee80211req_athdbg req = {0};
    struct mesh_dbg_req_t mesh_req = {0};

    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_MAP_RADIO_HWCAP;
    req.needs_reply = DBGREQ_REPLY_IS_REQUIRED;
    ret = send_generic_command_cfg80211(cfg80211_ctx, dataElementCmdWlanState.CurRadio->vaps[0].ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req, (sizeof(struct ieee80211req_athdbg)));
    if (ret < 0) {
        dataElementDebug(DBGERR, "%s: Radio Hwcap failed, ifName: %s.\n", __func__, dataElementCmdWlanState.CurRadio->ifname);
        return DE_NOK;
    }

    mesh_req = (struct mesh_dbg_req_t )(req.data.mesh_dbg_req);
    if (mesh_req.mesh_data.mapapcap.map_ap_radio_basic_capabilities_valid) {
        for (i = 0; i < apRadioBasicCap.numSupportedOpClasses; i++) {
            capOpClassData[i].opClass = mesh_req.mesh_data.mapapcap.hwcap.opclasses[i].opclass;
            capOpClassData[i].maxTxPower = ~(mesh_req.mesh_data.mapapcap.hwcap.opclasses[i].max_tx_pwr_dbm) + 1;
            capOpClassData[i].numberOfNonOperChan = mesh_req.mesh_data.mapapcap.hwcap.opclasses[i].num_non_oper_chan;

            u_int8_t j;
            for (j = 0; j < capOpClassData[i].numberOfNonOperChan; j++) {
                capOpClassData[i].nonOperable[j] = mesh_req.mesh_data.mapapcap.hwcap.opclasses[i].non_oper_chan_num[j];
            }
        }
    }
    return DE_OK;
}

/**
 * @brief get radio capabilities data
 *
 * @param [in] radioData
 * @param [in] capabilities structure to update
 *
 * @return DE_OK on success
 */
DE_STATUS dEGetWlanRadioCapsData(dataElementsRadio_t *radioData, dataElementsCapabilities_t *capData) {
    struct ieee80211req_athdbg req = {0};
    struct mesh_dbg_req_t mesh_req = {0};
    int ret;
    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_MAP_RADIO_HWCAP;
    req.needs_reply = DBGREQ_REPLY_IS_REQUIRED;
    ret = send_generic_command_cfg80211(cfg80211_ctx, dataElementCmdWlanState.CurRadio->vaps[0].ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req, (sizeof(struct ieee80211req_athdbg)));
    if (ret < 0) {
        dataElementDebug(DBGERR, "%s: Radio Hwcap failed, ifName: %s.\n", __func__, dataElementCmdWlanState.CurRadio->ifname);
        return DE_NOK;
    }

    mesh_req = (struct mesh_dbg_req_t )(req.data.mesh_dbg_req);
    if (mesh_req.mesh_data.mapapcap.map_ap_radio_basic_capabilities_valid) {
        dataElementCmdWlanState.curOpClass = mesh_req.mesh_data.mapapcap.hwcap.opclasses[0].opclass;
    }

    // Warning:Types are assumed to be identical and thus any change made in the driver,
    // needs to be reflected in the user space type and vice versa.
    if (mesh_req.mesh_data.mapapcap.map_ap_radio_basic_capabilities_valid) {
        memcpy(&dataElementCmdWlanState.CurRadio->radioBasicCapabilities, &mesh_req.mesh_data.mapapcap.hwcap,
                sizeof(ieee1905APRadioBasicCapabilities_t));
        dataElementCmdWlanState.CurRadio->radioBasicCapabilitiesValid = DE_TRUE;
        capData->numberOfOpClass = dataElementCmdWlanState.CurRadio->radioBasicCapabilities.numSupportedOpClasses;
    }
    if (mesh_req.mesh_data.mapapcap.map_ap_ht_capabilities_valid) {
        memcpy(&capData->caps.apHtCap, &mesh_req.mesh_data.mapapcap.htcap,
                sizeof(ieee1905APHtCapabilities_t));
        capData->caps.isHTValid = DE_TRUE;
    }
    if (mesh_req.mesh_data.mapapcap.map_ap_vht_capabilities_valid) {
        capData->caps.isVHTValid = DE_TRUE;
        memcpy(&capData->caps.apVhtCap, &mesh_req.mesh_data.mapapcap.vhtcap,
                sizeof(ieee1905APVhtCapabilities_t));
    }
    if (mesh_req.mesh_data.mapapcap.map_ap_he_capabilities_valid) {
        memcpy(&capData->caps.apHeCap, &mesh_req.mesh_data.mapapcap.hecap,
                sizeof(ieee1905APHeCapabilities_t));
        capData->caps.isHEValid = DE_TRUE;
    }
    return DE_OK;
}

/**
 * @brief get current opclass data
 *
 * @param [in] radioData
 * @param [in] current op class structure to update
 *
 * @return DE_OK on success
 */
DE_STATUS dEGetWlanCurOpClassData(dataElementsRadio_t *radioData,
                                       dataElementsCurrentOpClassProfile_t *cOp) {
    uint8_t num_supp_op_class =0, chan_num = 0;
    int tx_power, ret;

    if((ret = send_generic_command_cfg80211(cfg80211_ctx, dataElementCmdWlanState.CurRadio->vaps[0].ifname, QCA_NL80211_VENDOR_SUBCMD_SON_REG_PARAMS, QCA_NL80211_SON_REG_PARAMS_NUM_OPCLASS, (char *)&num_supp_op_class, sizeof(uint8_t))) < 0 ){
        dataElementDebug(DBGERR, "%s: Failed to get Num Opclass\n",__func__);
        return ret;
    }
    //radioData->numberOfCurrOpClass = 1;
    cOp->numberOfCurrOpClass = 1;
    cOp->opClass = dataElementCmdWlanState.curOpClass;

    if((ret = send_generic_command_cfg80211(cfg80211_ctx, dataElementCmdWlanState.CurRadio->vaps[0].ifname, QCA_NL80211_VENDOR_SUBCMD_SON_REG_PARAMS, QCA_NL80211_SON_REG_PARAMS_CURR_CHAN_NUM, (char *)&chan_num, sizeof(uint8_t))) < 0 ){
        dataElementDebug(DBGERR, "%s: failed to get curr chan number \n",__func__);
        return ret;
    }
    cOp->channel = chan_num;

    if((ret = send_generic_command_cfg80211(cfg80211_ctx, dataElementCmdWlanState.CurRadio->vaps[0].ifname, QCA_NL80211_VENDOR_SUBCMD_SON_REG_PARAMS, QCA_NL80211_SON_REG_PARAMS_CURR_OPCLASS_TXPOWER, (char *)&tx_power, sizeof(int))) < 0 ){
        dataElementDebug(DBGERR, "%s: failed to get opclass tx power\n",__func__);
        return ret;
    }
    cOp->txPower = tx_power;
    return DE_OK;
}

/**
 * @brief get radio data
 *
 * @param [in] radioData structure to update radio info
 * @param [in] radioIndex index of the radio
 *
 * @return DE_OK on success
 */
DE_STATUS dEGetWlanRadioData(dataElementsRadio_t *radioData, int radioIndex) {
    int ret,val=0;
    struct dataElementWlanRadioInfo *Radio=&dataElementCmdWlanState.RadioInfo[radioIndex];
    dataElementCmdWlanState.CurRadio = &dataElementCmdWlanState.RadioInfo[radioIndex];
    val = 1;
    ret = setParam(cfg80211_ctx, Radio->ifname, ENABLE_OL_STATS_CMD, &val, sizeof(val));
    if( ret < 0 ) {
        dataElementDebug(DBGERR,"%s: enable ol stats failed \n",__func__);
    }
    dataElementDebug(DBGDUMP, "%s: Radio_ifname %s \n", __func__, Radio->ifname);
    deCopyMACAddr(Radio->radioAddr.ether_addr_octet, radioData->id.ether_addr_octet);
    struct ol_ath_radiostats ol_stats = {0};
    ret = send_generic_command_cfg80211(cfg80211_ctx, Radio->ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, QCA_NL80211_VENDOR_SUBCMD_PHYSTATS, (char *)&ol_stats, sizeof(struct ol_ath_radiostats)  );
    if (ret < 0) {
        dataElementDebug(DBGERR, "%s: set param failed ifname %s \n",__func__, Radio->vaps[0].ifname);
        return DE_NOK;
    }
    radioData->enabled = DE_TRUE;
    radioData->noise = ol_stats.chan_nf;
    radioData->transmit = ol_stats.ap_tx_util;
    radioData->receiveSelf = ol_stats.ap_rx_util;
    radioData->receiveOther = ol_stats.obss_rx_util;
    //dataElementDebug(DBGDUMP, "radioData->enabled %d radioData->noise %d radioData->transmit %d radioData->receiveSelf %d radioData->receiveOther %d \n",radioData->enabled, radioData->noise, radioData->transmit, radioData->receiveSelf, radioData->receiveOther);
    if (( ret = send_command_get_cfg80211(cfg80211_ctx, Radio->vaps[0].ifname, IEEE80211_PARAM_CHAN_UTIL, (int *)&val)) < 0) {
        dataElementDebug(DBGERR, "%s: failed to get channel utilization \n",__func__);
    }
    radioData->utilization = val;
    return DE_OK;
}

/**
 * @brief get device data
 *
 * @param [in] deviceData structure to update stats
 *
 * @return DE_OK on success
 */
DE_STATUS dEGetWlanDeviceData(dataElementsDevice_t *deviceData) {
    deviceData->numberOfRadios = dataElementCmdWlanState.numOfRadio;
    deCopyMACAddr(dataElementCmdWlanState.RadioInfo[0].radioAddr.ether_addr_octet, deviceData->id.ether_addr_octet);
    return DE_OK;
}

/**
 * @brief Get Network stats
 *
 * @param [in] networkData structure to update stats
 *
 * @return DE_OK on success
 */
DE_STATUS dEGetWlanNetworkData(dataElementsNetwork_t *networkData) {
    networkData->numberOfDevices = 1;

    deCopyMACAddr(dataElementCmdWlanState.RadioInfo[0].radioAddr.ether_addr_octet, networkData->ctrlId.ether_addr_octet);
    return DE_OK;
}

//Function to request scan on all radios
void dESendScanRequest() {
    int i=0,val = 1;
    while (i < WLANIF_MAX_RADIOS) {
        if ( dataElementCmdWlanState.RadioInfo[i].valid &&
                dataElementCmdWlanState.RadioInfo[i].vaps[0].valid){
            int ret = 0;
            ret=setParam(cfg80211_ctx,
                    dataElementCmdWlanState.RadioInfo[i].vaps[0].ifname,
                    IEEE80211_PARAM_START_ACS_REPORT, &val, sizeof(val));
            if( ret < 0 ) {
                dataElementDebug(DBGERR,"%s: Enable ACS report failed for ifname: %s \n",
                        __func__, dataElementCmdWlanState.RadioInfo[i].vaps[0].ifname);
            }
        }
        i++;
    }
}

/*
 * @brief get ACS channel and neghbour report stats
 */
int getACSReport( u_int8_t* numChans,struct ieee80211_acs_dbg *chanData,
        u_int8_t* numNeighbors, ieee80211_neighbor_info *neighborData,
        u_int8_t neighborChans[]) {
    struct ieee80211req_athdbg req;
    struct ieee80211_acs_dbg *acs = NULL;
    struct cfg80211_data buffer;
    int ret=0;
    struct dataElementWlanVapInfo *vaps = &dataElementCmdWlanState.CurRadio->vaps[0];

    acs = (struct ieee80211_acs_dbg *)calloc(1, sizeof(struct ieee80211_acs_dbg));

    if(!acs) {
        ret = -ENOMEM;;
        goto cleanup;
    }

    req.cmd = IEEE80211_DBGREQ_GETACSREPORT;
    req.needs_reply = DBGREQ_REPLY_IS_REQUIRED;
    req.data.acs_rep.data_addr = acs;
    req.data.acs_rep.data_size = sizeof(struct ieee80211_acs_dbg);
    req.data.acs_rep.index = 0;
    acs->entry_id = 0;
    acs->acs_type = ACS_CHAN_STATS;

    buffer.data = &req;
    buffer.length = sizeof(req);
    buffer.callback = NULL;
    buffer.callback = NULL;
    buffer.parse_data = 0;

    ret = wifi_cfg80211_send_generic_command(cfg80211_ctx,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_DBGREQ, vaps->ifname, (char *)&buffer, buffer.length);
    if (ret < 0) {
        TRACE_EXIT_ERR();
        goto cleanup;
    }

    // Loop through each channel data and get the neighbors
    u_int8_t idxChan = 0, idxNeighbor = 0;
    for (idxChan = 0; idxChan < *numChans && idxChan < acs->nchans; ++idxChan) {
        acs->entry_id = idxChan;
        req.cmd = IEEE80211_DBGREQ_GETACSREPORT;

        ret = wifi_cfg80211_send_generic_command(cfg80211_ctx,
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_DBGREQ, vaps->ifname, (char *)&buffer, buffer.length);
        if (ret < 0) {
            TRACE_EXIT_ERR();
            goto cleanup;
        }

        // Copy the channel data
        memcpy(&chanData[idxChan], acs, sizeof(struct ieee80211_acs_dbg));
    }

    // Append the neighbor data
    u_int8_t i,j;
    for (i = 0; i < acs->nchans; i++) {
        acs->entry_id = i;
        acs->acs_type = ACS_NEIGHBOUR_GET_LIST_COUNT;
        req.cmd = IEEE80211_DBGREQ_GETACSREPORT;
        req.needs_reply = DBGREQ_REPLY_IS_NOT_REQUIRED;
        ret = wifi_cfg80211_send_generic_command(cfg80211_ctx,
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_DBGREQ, vaps->ifname, (char *)&buffer, buffer.length);

        if (ret < 0) {
            TRACE_EXIT_ERR();
            goto cleanup;
        }

        if (acs->chan_nbss) {
            acs->neighbor_list = (void *) calloc (acs->chan_nbss,sizeof(ieee80211_neighbor_info));

            if(!acs->neighbor_list) {
                ret = -ENOMEM;
                TRACE_EXIT_ERR();
                goto cleanup;
            }

            acs->neighbor_size = sizeof(ieee80211_neighbor_info) * acs->chan_nbss;
            acs->entry_id = i;
            acs->acs_type = ACS_NEIGHBOUR_GET_LIST;
            req.cmd = IEEE80211_DBGREQ_GETACSREPORT;
            req.needs_reply = DBGREQ_REPLY_IS_NOT_REQUIRED;
            ret = wifi_cfg80211_send_generic_command(cfg80211_ctx,
                    QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                    QCA_NL80211_VENDOR_SUBCMD_DBGREQ, vaps->ifname, (char *)&buffer, buffer.length);

            if (ret < 0) {
                TRACE_EXIT_ERR();
                goto cleanup;
            }

            for (j = 0; j < acs->chan_nbss && idxNeighbor < *numNeighbors; j++) {
                memcpy(&neighborData[idxNeighbor], &acs->neighbor_list[j], sizeof(ieee80211_neighbor_info));
                neighborChans[idxNeighbor] = acs->ieee_chan;
                idxNeighbor++;
            }
            free(acs->neighbor_list);
            acs->neighbor_list = NULL;
        }
    }

    *numChans = idxChan;
    *numNeighbors = idxNeighbor;
    TRACE_EXIT();

cleanup:
    if (acs) {
        if (acs->neighbor_list) {
            free(acs->neighbor_list);
            acs->neighbor_list = NULL;
        }
        free(acs);
        acs = NULL;
    }
    if(ret < 0) {
        return DE_NOK;
    }

    return DE_OK;
}

/**
 * @brief get scanList data
 *
 * @param [in] scanData structure to update stats
 *
 * @return DE_OK on success
 */
DE_STATUS dEGetWlanScanListData(dataElementsScanResult_t *scanData ) {
    int i,opcount = 0,chcount = 0, neighcount = 0, ret = 0;
    dEACSReport_t acsReport = {0};
    acsReport.numChans = WLAN_MANAGER_MAX_NUM_CHANS;
    acsReport.numNeighbors = WLAN_MANAGER_MAX_NUM_NEIGHBORS;
    struct dataElementWlanVapInfo *vaps = &dataElementCmdWlanState.CurRadio->vaps[0];

    ret = getACSReport( &acsReport.numChans, acsReport.chanData,
            &acsReport.numNeighbors, acsReport.neighborData,
            acsReport.neighborChans);
    if (ret == DE_NOK) {
        return DE_NOK;
    }

    for (i = 0; i < acsReport.numChans; i++) {
        dataElementDebug(DBGDUMP,
                "%s:    Chan [%u] Opclass [%d]: nbss=%u, NF=%d, minRSSI=%d, maxRSSI=%d, "
                "chanLoad=%u, acsStatus=%d, chanWidth=%d",
                __func__, acsReport.chanData[i].ieee_chan, acsReport.chanData[i].op_class,
                acsReport.chanData[i].chan_nbss, acsReport.chanData[i].noisefloor,
                acsReport.chanData[i].chan_minrssi, acsReport.chanData[i].chan_maxrssi,
                acsReport.chanData[i].chan_load, acsReport.chanData[i].acs_status,
                acsReport.chanData[i].chan_width);
        if ( scanData->opClassScanList[opcount].operatingClass == 0) {
            scanData->opClassScanList[opcount].operatingClass = acsReport.chanData[i].op_class;
            scanData->opClassScanList[opcount].ScanChanList[chcount].channel = acsReport.chanData[i].ieee_chan;
            scanData->opClassScanList[opcount].ScanChanList[chcount].utilization = acsReport.chanData[i].chan_load;
            scanData->opClassScanList[opcount].ScanChanList[chcount].noise = acsReport.chanData[i].noisefloor;
            chcount++;
        } else if(scanData->opClassScanList[opcount].operatingClass == acsReport.chanData[i].op_class ) {
            scanData->opClassScanList[opcount].ScanChanList[chcount].channel = acsReport.chanData[i].ieee_chan;
            scanData->opClassScanList[opcount].ScanChanList[chcount].utilization = acsReport.chanData[i].chan_load;
            scanData->opClassScanList[opcount].ScanChanList[chcount].noise = acsReport.chanData[i].noisefloor;
            chcount++;
        } else if (scanData->opClassScanList[opcount].operatingClass != acsReport.chanData[i].op_class ) {
            scanData->opClassScanList[opcount].numberOfChannelScans = chcount;
            chcount=0;
            opcount++;
            scanData->opClassScanList[opcount].operatingClass = acsReport.chanData[i].op_class;
            scanData->opClassScanList[opcount].ScanChanList[chcount].channel = acsReport.chanData[i].ieee_chan;
            scanData->opClassScanList[opcount].ScanChanList[chcount].utilization = acsReport.chanData[i].chan_load;
            scanData->opClassScanList[opcount].ScanChanList[chcount].noise = acsReport.chanData[i].noisefloor;
            chcount++;
        }
    }
    scanData->opClassScanList[opcount].numberOfChannelScans = chcount;
    scanData->numberOfOpClassScans = opcount+1;

    dataElementDebug(DBGDUMP,
            "%s: Radio for [%s] has %u neighbors", __func__, vaps->ifname,
            acsReport.numNeighbors);

    int temp = 0,ch_width = IEEE80211_CWM_WIDTHINVALID;
    if (( ret = send_command_get_cfg80211(cfg80211_ctx, vaps->ifname, IEEE80211_PARAM_CHWIDTH, &ch_width)) < 0) {
        dataElementDebug(DBGERR, "%s: failed to ch_width \n",__func__);
    }

    for (i = 0; i < acsReport.numNeighbors; i++) {
        int j=0;
        dataElementDebug(DBGDUMP,
                "%s:%d chan=%u, phyMode=%u, rssi=%d, ssid=%s, qbbsLoadIE=%d, stacount=%d, "
                "chanUtil=%d, bssid=" deMACAddFmt(":")"\n",
                __func__, i + 1, acsReport.neighborChans[i], acsReport.neighborData[i].phymode,
                acsReport.neighborData[i].rssi, acsReport.neighborData[i].ssid,
                acsReport.neighborData[i].qbssload_ie_valid,
                acsReport.neighborData[i].station_count,
                acsReport.neighborData[i].channel_utilization,
                deMACAddData(acsReport.neighborData[i].bssid));

        while (j < scanData->numberOfOpClassScans) {
            int k=0;
            while (k < scanData->opClassScanList[j].numberOfChannelScans) {
                if (scanData->opClassScanList[j].ScanChanList[k].channel == acsReport.neighborChans[i]) {
                    if (j != temp){
                        temp = j;
                        neighcount=0;
                    }
                    memcpy((void *)scanData->opClassScanList[j].neighData[neighcount].BSSID.ether_addr_octet,
                            (void *)acsReport.neighborData[i].bssid, IEEE80211_ADDR_LEN);
                    strlcpy((char *)scanData->opClassScanList[j].neighData[neighcount].ssid,
                            (char *)acsReport.neighborData[i].ssid, DATA_ELEMENT_IEEE80211_NWID_LEN + 1);
                    scanData->opClassScanList[j].neighData[neighcount].signalStrength = acsReport.neighborData[i].rssi;
                    scanData->opClassScanList[j].neighData[neighcount].channelBandwidth = acsReport.neighborData[i].phymode;
                    scanData->opClassScanList[j].neighData[neighcount].channelUtilization = acsReport.neighborData[i].channel_utilization;
                    scanData->opClassScanList[j].neighData[neighcount].stationCount = acsReport.neighborData[i].station_count;
                    scanData->opClassScanList[j].neighData[neighcount].channel = acsReport.neighborChans[i];
                    scanData->opClassScanList[j].ScanChanList[k].numberOfNeighbours++;
                    switch (ch_width)
                    {
                        case IEEE80211_CWM_WIDTH20:
                            scanData->opClassScanList[j].neighData[neighcount].channelBandwidth = 20;
                            break;
                        case IEEE80211_CWM_WIDTH40:
                            scanData->opClassScanList[j].neighData[neighcount].channelBandwidth = 40;
                            break;
                        case IEEE80211_CWM_WIDTH80:
                            scanData->opClassScanList[j].neighData[neighcount].channelBandwidth = 80;
                            break;
                        case IEEE80211_CWM_WIDTH160:
                        case IEEE80211_CWM_WIDTH80_80:
                            scanData->opClassScanList[j].neighData[neighcount].channelBandwidth = 160;
                            break;
                        case IEEE80211_CWM_WIDTHINVALID:
                        case IEEE80211_CWM_WIDTH_MAX:
                            scanData->opClassScanList[j].neighData[neighcount].channelBandwidth = 0;
                            break;
                    }
                    neighcount++;
                    break;
                }
            k++;
            }
        j++;
        }
    }
    return DE_OK;
}

/// Get MCS
// =================================================================================================
DE_STATUS dEGetMcsBitConversion(de_phyCapInfo_t phyCapInfo, u_int16_t *mcs) {
    u_int8_t NO_OF_BITS = 16;
    u_int16_t bitMask = 0, mcsBits = 0, i, mcsMask = 0;

    if (phyCapInfo.maxMCS == 9) {
        bitMask = 2;
    } else if (phyCapInfo.maxMCS == 8) {
        bitMask = 1;
    } else if (phyCapInfo.maxMCS == 7) {
        bitMask = 0;
    }

    for (i = 0; i < NO_OF_BITS - phyCapInfo.numStreams * 2; i++) {
        mcsMask = mcsMask | (1 << i);
    }
    mcsMask = mcsMask << phyCapInfo.numStreams * 2;

    for (i = 0; i < phyCapInfo.numStreams; i++) {
        mcsBits |= bitMask;
        if (i < phyCapInfo.numStreams - 1) {
            mcsBits = mcsBits << 2;
        }
    }
    *mcs = mcsBits | mcsMask;

    return DE_OK;
}

de_chwidth_e dEMapToBandwidth(enum ieee80211_cwm_width chwidth) {
    switch (chwidth) {
        case IEEE80211_CWM_WIDTH20:
            return de_chwidth_20;

        case IEEE80211_CWM_WIDTH40:
            return de_chwidth_40;

        case IEEE80211_CWM_WIDTH80:
            return de_chwidth_80;

        case IEEE80211_CWM_WIDTH160:
            return de_chwidth_160;

        default:
            // Fall through for the error case
            break;
    }

    dataElementDebug(DBGERR, "%s: Invalid bandwidth from driver: %u",
            __func__, chwidth);
    return de_chwidth_invalid;
}

/**
 * @brief function to get the phymode
 *
 * @param [in] phymode
 *
 * @return
 */
de_phymode_e dEMapToPhyMode(enum ieee80211_phymode phymode) {
    switch (phymode) {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_FH:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
            return de_phymode_basic;

        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            return de_phymode_ht;

        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            return de_phymode_vht;

        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXG_HE20:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXG_HE40:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AXA_HE80_80:
            return de_phymode_he;

        default:
            // Fall through for the error case
            break;
    }

    return de_phymode_invalid;
}

u_int8_t dEConvertToSingleStreamMCSIndex(enum ieee80211_phymode phymode,
        u_int8_t driverMCS) {
#define WLANIF_MAX_11N_MCS_INDEX 7
    switch (phymode) {
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_FH:
            // Assumes it can only use the first two data rates. In
            // practice it may be even more limited, but hopefully these
            // clients are not seen in the real world any more.
            //
            // Note that the driver reports in Mbps, so we're just picking
            // an MCS index for 802.11g that roughly corresponds to the
            // maximum rate for 802.11b.
            return 1;

        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
            // 802.11g and 802.11n should share the same max index for a
            // single spatial stream (although 802.11n brings higher
            // efficiency).
            //
            // Note that the driver reports the rate as Mbps. Here we are
            // assuming that all clients will support up to MCS 7.
            return WLANIF_MAX_11N_MCS_INDEX;

        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            // 802.11n uses MCS indices that incorporate the number of
            // spatial streams. We are capturing that separately, so
            // remove the spatial stream component of the value.
            return driverMCS % (WLANIF_MAX_11N_MCS_INDEX + 1);

        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            // 802.11ac just reports the MCS index itself independent of
            // the number of spatial streams.
            return driverMCS;

        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXG_HE20:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXG_HE40:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AXA_HE80_80:
            return driverMCS;

        default:
            // Fall through for the error case
            break;
    }

    dataElementDebug(DBGERR, "%s: Invalid PHY mode from driver: %u",
            __func__, phymode);
    return 0;
#undef WLANIF_MAX_11N_MCS_INDEX
}


/**
 * @brief get station data
 *
 * @param [in] bssCount index of the bss
 * @param [in] no_of_sta station count
 * @param [in] staData structure to update stats
 *
 * @return
 */
DE_STATUS dEGetWlanStaData( u_int32_t bssCount, u_int32_t no_of_sta, dataElementsSTAList_t *staData ) {
    int ret, count=0, len;
    struct ieee80211req_sta_info *station_info=NULL;
    struct ieee80211req_sta_info *sta_info=NULL;
    struct ieee80211req_sta_stats *stats=NULL;
    struct dataElementWlanVapInfo *vaps = &dataElementCmdWlanState.CurRadio->vaps[bssCount];

    len = LIST_STATION_CFG_ALLOC_SIZE;
    dataElementDebug(DBGDUMP, " %s:, no_of_sta:%d len:%d \n",__func__, no_of_sta, len);
    station_info = ( struct ieee80211req_sta_info *)malloc(LIST_STATION_CFG_ALLOC_SIZE);
    if (!station_info) {
        dataElementDebug(DBGERR, "%s: station info malloc failed",__func__);
        return DE_NOK;
    }
    stats =
        (struct ieee80211req_sta_stats *)malloc(no_of_sta * sizeof(struct ieee80211req_sta_stats));
    if ( !stats ){
        dataElementDebug(DBGERR, "%s: stats malloc failed",__func__);
        free(station_info);
        return DE_NOK;
    }

    ret = send_generic_command_cfg80211(cfg80211_ctx, vaps->ifname,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_STA, (void *)station_info, len);
    if (ret < 0) {
        dataElementDebug(DBGERR, "%s: LIST STA failed, ifName: %s, ret:%d\n", __func__, vaps->ifname, ret);
        free(station_info);
        free(stats);
        return DE_NOK;
    }
    uint8_t *stacp = NULL;
    stacp = (uint8_t *)station_info;
    while ( count < no_of_sta ) {
        struct ieee80211req_athdbg req = {0};
        struct mesh_dbg_req_t mesh_req = {0};
        ieee80211_bsteering_datarate_info_t datarateInfo = {0};
        sta_info = (struct ieee80211req_sta_info *)stacp;
        memcpy(staData[count].macAddress.ether_addr_octet, sta_info->isi_macaddr, IEEE80211_ADDR_LEN );
        dataElementDebug(DBGINFO, "%s: STA macaddress " deMACAddFmt(":")"\n",
                __func__, deMACAddData(sta_info->isi_macaddr));
        memcpy(stats[count].is_u.macaddr, sta_info->isi_macaddr, IEEE80211_ADDR_LEN );
        ret = send_generic_command_cfg80211(cfg80211_ctx, vaps->ifname,
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_STA_STATS, (void *)&(stats[count]),
                (sizeof(struct ieee80211req_sta_stats)));
        if (ret < 0) {
            dataElementDebug(DBGERR, "%s: STA STATS failed, ifName: %s ret:%d\n",
                    __func__, vaps->ifname, ret);
            free(station_info);
            free(stats);
            return DE_NOK;
        }
        de_phyCapInfo_t phyCapInfo = {
            DE_FALSE /* valid */, de_chwidth_invalid, 0 /* numStreams */,
            de_phymode_invalid, 0 /* maxMCS */, 0 /* maxTxPower */
        };
        memcpy(req.dstmac, sta_info->isi_macaddr, IEEE80211_ADDR_LEN);
        req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
        req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_GET_DATARATE_INFO;
        req.needs_reply = DBGREQ_REPLY_IS_REQUIRED;
        ret = send_generic_command_cfg80211(cfg80211_ctx, vaps->ifname,
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req,
                sizeof(struct ieee80211req_athdbg));
        if (ret < 0) {
            dataElementDebug(DBGERR, "%s: STA DATARATE Info failed, ifName: %s ret:%d\n",
                    __func__, vaps->ifname, ret);
        } else {
            mesh_req = (struct mesh_dbg_req_t )(req.data.mesh_dbg_req);
            memcpy(&datarateInfo, &mesh_req.mesh_data, sizeof(ieee80211_bsteering_datarate_info_t));
            phyCapInfo.valid = DE_TRUE;
            phyCapInfo.maxChWidth =
                dEMapToBandwidth(
                        (enum ieee80211_cwm_width)(datarateInfo.max_chwidth)),
                phyCapInfo.numStreams = datarateInfo.num_streams,
                phyCapInfo.phyMode =
                    dEMapToPhyMode((enum ieee80211_phymode)datarateInfo.phymode),
                phyCapInfo.maxMCS =
                    dEConvertToSingleStreamMCSIndex(
                            (enum ieee80211_phymode)datarateInfo.phymode,
                            datarateInfo.max_MCS);
            phyCapInfo.maxTxPower = datarateInfo.max_txpower;

        }
        staData[count].lastDataDownlinkRate = stats[count].is_stats.ns_last_rx_rate;
        staData[count].lastDataUplinkRate = stats[count].is_stats.ns_last_tx_rate;
        staData[count].estMACDataRateDownlink = 0;
        staData[count].estMACDataRateUplink = 0;
        staData[count].signalStrength = sta_info->isi_rssi;
        staData[count].lastConnectTime = sta_info->isi_tr069_assoc_time.tv_sec;
        staData[count].stats.txBytes = stats[count].is_stats.ns_tx_bytes;
        staData[count].stats.rxBytes = stats[count].is_stats.ns_rx_bytes;
        staData[count].stats.pktsSent = stats[count].is_stats.ns_tx_data;
        staData[count].stats.pktsRcvd = stats[count].is_stats.ns_rx_data;
        staData[count].stats.txPktErr = stats[count].is_stats.ns_failed_retry_count;
        staData[count].stats.rxPktErr = stats[count].is_stats.ns_rx_decap +
            stats[count].is_stats.ns_rx_decryptcrc + stats[count].is_stats.ns_rx_tkipmic +
            stats[count].is_stats.ns_rx_ccmpmic + stats[count].is_stats.ns_rx_wpimic +
            stats[count].is_stats.ns_rx_tkipicv + stats[count].is_stats.ns_rx_wepfail;
        staData[count].stats.cntRetx = stats[count].is_stats.ns_multiple_retry_count;
        staData[count].numberOfMeasureReports = 0;
        staData[count].measurementReport = 0;

        if ( sta_info->isi_htcap & IEEE80211_HTCAP_C_SHORTGI20 ) {
            staData[count].caps.apHtCap.shortGiSupport20Mhz = 1;
            staData[count].caps.isHTValid=1;
        }
        if ( sta_info->isi_htcap & IEEE80211_HTCAP_C_SHORTGI40 ) {
            staData[count].caps.apHtCap.shortGiSupport40Mhz = 1;
            staData[count].caps.isHTValid=1;
        }
        if ( sta_info->isi_htcap & IEEE80211_HTCAP_C_CHWIDTH40 ) {
             staData[count].caps.apHtCap.htSupport40Mhz = 1;
             staData[count].caps.isHTValid=1;
        }

        if ( sta_info->isi_vhtcap & IEEE80211_VHTCAP_SHORTGI_80 ) {
            staData[count].caps.apVhtCap.shortGiSupport80Mhz = 1;
            staData[count].caps.isVHTValid=1;
        }

        if ( sta_info->isi_vhtcap & IEEE80211_VHTCAP_SHORTGI_160 ) {
            staData[count].caps.apVhtCap.shortGiSupport160Mhz80p80Mhz = 1;
            staData[count].caps.isVHTValid=1;
        }

        if ( sta_info->isi_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 ) {
            staData[count].caps.apVhtCap.support80p80Mhz = 1;
            staData[count].caps.isVHTValid=1;
        }

        if (sta_info->isi_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160) {
            staData[count].caps.apVhtCap.support160Mhz = 1;
            staData[count].caps.isVHTValid=1;
        }

        if (sta_info->isi_vhtcap & IEEE80211_VHTCAP_SU_BFORMER) {
            staData[count].caps.apVhtCap.suBeamformerCapable = 1;
            staData[count].caps.isVHTValid=1;
        }
        if (sta_info->isi_vhtcap & IEEE80211_VHTCAP_MU_BFORMER) {
            staData[count].caps.apVhtCap.muBeamformerCapable = 1;
            staData[count].caps.isVHTValid=1;
        }

        if(sta_info->isi_vhtcap) {
            u_int16_t mcs;
            dEGetMcsBitConversion(phyCapInfo, &mcs);
            staData[count].caps.apVhtCap.supportedTxMCS = mcs;
            staData[count].caps.apVhtCap.supportedRxMCS = mcs;
            staData[count].caps.apVhtCap.maxTxNSS = phyCapInfo.numStreams;
            staData[count].caps.apVhtCap.maxRxNSS = phyCapInfo.numStreams;
        }

        staData[count].caps.apHtCap.maxTxNSS = (sta_info->isi_nss & 0xf0)>>4;
        staData[count].caps.apHtCap.maxRxNSS = (sta_info->isi_nss & 0x0f);

        if(sta_info->isi_is_he) {
            int k;
            u_int32_t *hecap_phy = &sta_info->isi_hecap_phyinfo[HECAP_PHYBYTE_IDX0];
            staData[count].caps.isHEValid=1;
            staData[count].caps.apHeCap.maxTxNSS = (sta_info->isi_nss & 0x0f);
            staData[count].caps.apHeCap.maxRxNSS = (sta_info->isi_nss >> 4) & 0x0f;
            staData[count].caps.apHeCap.numMCSEntries = IEEE1905_MAX_HE_MCS;
            for (k=0; k < HE_HANDLES_TXRX_MCS_SIZE ; k++) {
                staData[count].caps.apHeCap.supportedHeMCS[2*k] = sta_info->isi_hecap_rxmcsnssmap[k];
                staData[count].caps.apHeCap.supportedHeMCS[2*k+1] = sta_info->isi_hecap_txmcsnssmap[k];
            }
            if(sta_info->isi_hecap_phyinfo[HECAP_PHYBYTE_IDX0] &
                    IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) {
                staData[count].caps.apHeCap.support160Mhz = 1;
            }

            if (sta_info->isi_hecap_phyinfo[HECAP_PHYBYTE_IDX0] &
                    IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) {
                staData[count].caps.apHeCap.support80p80Mhz = 1;
            }
            staData[count].caps.apHeCap.suBeamformerCapable =
                HECAP_PHY_SUBFMR_GET_FROM_IC(hecap_phy);
            staData[count].caps.apHeCap.muBeamformerCapable =
                HECAP_PHY_MUBFMR_GET_FROM_IC(hecap_phy);
            staData[count].caps.apHeCap.ulMuMimoCapable =
                HECAP_PHY_UL_MU_MIMO_GET_FROM_IC(hecap_phy);
            staData[count].caps.apHeCap.ulMuMimoOfdmaCapable =
                (!!HECAP_PHY_UL_MU_MIMO_GET_FROM_IC(hecap_phy)) &&
                (!!HECAP_PHY_ULOFDMA_GET_FROM_IC(hecap_phy));
            staData[count].caps.apHeCap.dlMuMimoOfdmaCapable =
                HECAP_PHY_DLMUMIMOPARTIALBW_GET_FROM_IC(hecap_phy);
            staData[count].caps.apHeCap.ulOfdmaCapable =
                HECAP_PHY_ULOFDMA_GET_FROM_IC(hecap_phy);
            staData[count].caps.apHeCap.dlOfdmaCapable =
                HECAP_PHY_DLMUMIMOPARTIALBW_GET_FROM_IC(hecap_phy);

        }

//      staData->ipV4Address
//      staData->ipV6Address
//      staData->hostname
//      staData->caps
        stacp += sta_info->isi_len;
        ++count;
   }
   free(station_info);
   free(stats);
   return DE_OK;
}

/**
 * @brief Function to update the radioInfo and VapInfo structure
 *        The function reads the config file for interface names
 *        and updates the structures
 *
 * @return DE_OK on success
 */
DE_STATUS deWlanInterfaceResolve()
{
    const char *wlanInterfaces;
    int numInterfaces;
    char ifnamePair[MAX_VAP_PER_BAND * WLANIF_MAX_RADIOS][1 + 2 * (IFNAMSIZ + 1)];

    wlanInterfaces = profileGetOpts(WLAN_CONFIG_SECTION,
            "WlanInterfaces", NULL);
    if (!wlanInterfaces) {
        dataElementDebug(DBGERR, "%s:%d Wlan Interface is not enabled, exiting",
                __func__,__LINE__);
        return DE_NOK;
    }

    numInterfaces = splitByToken(wlanInterfaces,
            sizeof(ifnamePair) / sizeof(ifnamePair[0]),
            sizeof(ifnamePair[0]),
            (char *)ifnamePair, ',');

    int i=0;
    for (i = 0; i < numInterfaces; i++) {
        char ifnames[2][IFNAMSIZ + 1];
        splitByToken(ifnamePair[i], sizeof(ifnames) / sizeof(ifnames[0]),
                sizeof(ifnames[0]), (char *) ifnames,':');
        int j=0;
        struct dataElementWlanRadioInfo *tempRadioInfo = NULL;
        for (j=0; j < WLANIF_MAX_RADIOS; j++) {
            if (dataElementCmdWlanState.RadioInfo[j].valid && strcmp(dataElementCmdWlanState.RadioInfo[j].ifname, ifnames[0]) == 0) {
                tempRadioInfo = &dataElementCmdWlanState.RadioInfo[j];
                break;
            } else if (!dataElementCmdWlanState.RadioInfo[j].valid) {
                strlcpy(dataElementCmdWlanState.RadioInfo[j].ifname,ifnames[0],sizeof(dataElementCmdWlanState.RadioInfo[j].ifname));
                dataElementCmdWlanState.numOfRadio++;
                dataElementCmdWlanState.RadioInfo[j].valid = 1;
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strlcpy(ifr.ifr_name, dataElementCmdWlanState.RadioInfo[j].ifname, IFNAMSIZ);
                int ret=0;
                if ((ret=ioctl(dataElementCmdWlanState.Sock, SIOCGIFHWADDR, &ifr)) < 0) {
                    dataElementDebug(DBGERR, "%s: ioctl() SIOCGIFHWADDR failed, ifname: %s ret %d\n",
                            __func__, dataElementCmdWlanState.RadioInfo[j].ifname,ret);
                    perror("ioctl");
                }
                deCopyMACAddr(ifr.ifr_hwaddr.sa_data, dataElementCmdWlanState.RadioInfo[j].radioAddr.ether_addr_octet);
                dataElementDebug(DBGDUMP, "%s: radioAddr is "deMACAddFmt(":")"\n",
                        __func__ ,deMACAddData(dataElementCmdWlanState.RadioInfo[j].radioAddr.ether_addr_octet));
                tempRadioInfo = &dataElementCmdWlanState.RadioInfo[j];
                break;
            }
        }
        int k=0;
        for (k=0; k < MAX_VAP_PER_BAND; k++) {
            if (tempRadioInfo && tempRadioInfo->vaps[k].valid && strcmp(tempRadioInfo->vaps[k].ifname, ifnames[1]) == 0) {
                break;
            } else if (tempRadioInfo && !tempRadioInfo->vaps[k].valid) {
                strlcpy (tempRadioInfo->vaps[k].ifname,ifnames[1],sizeof(tempRadioInfo->vaps[k].ifname));
                tempRadioInfo->vaps[k].valid=1;
                tempRadioInfo->numOfVap++;
                struct ifreq ifr;
                strlcpy(ifr.ifr_name, tempRadioInfo->vaps[k].ifname, IFNAMSIZ);
                int ret=0;
                if ((ret=ioctl(dataElementCmdWlanState.Sock, SIOCGIFHWADDR, &ifr)) < 0) {
                    dataElementDebug(DBGERR, "%s: ioctl() SIOCGIFHWADDR failed, ifname: %s ret %d\n",
                            __func__, tempRadioInfo->vaps[k].ifname, ret);
                    perror("ioctl");
                    return DE_NOK;
                }

                dataElementsBSEventWlanCreate(tempRadioInfo->vaps[k].ifname);
                deCopyMACAddr(ifr.ifr_hwaddr.sa_data, tempRadioInfo->vaps[k].macaddr.ether_addr_octet);
                break;
            }
        }
    }
    return DE_OK;
}

/**
 * @brief wifi socket initialization
 *
 * @param [in] cfg80211_ctx socket context
 *
 * @return
 */
int wifi_init(wifi_cfg80211_context *cfg80211_ctx)
{
    int ret;
    dataElementCmdWlanState.Sock=-1;

    /* Fill the private socket id for command and events */
    cfg80211_ctx->pvt_cmd_sock_id = 962;
    cfg80211_ctx->pvt_event_sock_id = 0;

    /*Initializing event related members to zero for not event supporting module*/
    cfg80211_ctx->event_thread_running = 0;
    cfg80211_ctx->event_sock = NULL;

    ret = wifi_init_nl80211((cfg80211_ctx));
    if (ret) {
        dataElementDebug(DBGERR, "%s : unable to create NL socket\n",__func__) ;
        return -EIO;
    }

    if ((dataElementCmdWlanState.Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dataElementDebug(DBGERR, "%s: Create ioctl socket failed\n", __func__);
    }

    if (fcntl(dataElementCmdWlanState.Sock, F_SETFL, fcntl(dataElementCmdWlanState.Sock, F_GETFL) | O_NONBLOCK)) {
        dataElementDebug(DBGERR, "%s: fcntl() failed\n", __func__);
    }

    return 0;
}

/**
 * @brief wifi socket deinit
 *
 * @param [in] cfg80211 socket context
 *
 * @return
 */
void wifi_deinit(wifi_cfg80211_context *cfg80211_ctx)
{
    wifi_destroy_nl80211((cfg80211_ctx));
    free(cfg80211_ctx);
}

/**
 * @brief singleAP wifi initialization
 *
 * @return DE_OK on success
 */
DE_STATUS dataElementWlanInit(void) {
    int ret=-1;
    dataElementCmdWlanState.isInit = 1;

    cfg80211_ctx = malloc(sizeof(wifi_cfg80211_context));
    if (!cfg80211_ctx) {
        dataElementDebug(DBGERR, "%s: Memmory allocation failed\n",__func__);
        return DE_NOK;
    }
    ret = wifi_init(cfg80211_ctx);
    if (ret != 0) {
        dataElementDebug(DBGERR, "%s: Socket creation failed \n",__func__);
        return DE_NOK;
    }
    if ( dataElementsBSEventWlanInit() != DE_OK) {
        dataElementDebug(DBGERR, "%s:%d> <FAILED> BS Event\n", __func__, __LINE__);
        return DE_NOK;
    }
    if (deWlanInterfaceResolve() != DE_OK) {
        dataElementDebug(DBGERR, "%s:%d Restart DE after enabling wlan interfaces",
                __func__,__LINE__);
        return DE_NOK;
    }
    dataElementDebug(DBGINFO, "%s: dataElementWlan Event successful",__func__);

    return DE_OK;

}

/**
 * @brief wlan deinitialization
 * frees cfg socket context
 *
 * @return
 */
void dataElementsWlanFini(void) {
    wifi_deinit(cfg80211_ctx);
}

int de_event_socket=-1;
struct bufrd readBuf;

/**
 * @brief bandsteering event deinitialization
 *
 * @param [in] vap_index index of the vap
 *
 * @return DE_OK on success
 */
DE_STATUS dataElementsBSEventWlanDestroy(int vap_index) {
    DE_STATUS de_ret=DE_OK;
    int ret = 0;

    if ((ret=close(de_event_socket)) != 0) {
        dataElementDebug(DBGERR, "%s:%d> <FAILED> socket close err:%d\n", __func__, __LINE__, ret);
        de_ret = DE_NOK;
    }
    de_event_socket = -1;

    bufrdDestroy(&readBuf);
    dataElementDebug(DBGERR, "%s:%d> <INFO> Event data destroyed successfully\n", __func__, __LINE__);
    return de_ret;

}

/**
 * @brief Event handling for assoc and disassoc
 *
 * @param [in] event respective event data
 *
 */
static void dataElements_EventData ( const ath_netlink_bsteering_event_t *event ) {
    char *ret, ifname[IF_NAMESIZE+1];

    dataElementsAssociationEventData_t assocData={0};
    struct bs_sta_stats_ind *stats;

    ret = if_indextoname(event->sys_index, ifname);
    switch ( event->type ){
        case ATH_EVENT_BSTEERING_NODE_ASSOCIATED:
            memcpy((void *) &assocData.macAddress, (void *)&event->data.bs_node_associated.client_addr, IEEE80211_ADDR_LEN);
            memcpy((void *) &assocData.BSSID.ether_addr_octet, (void *)&event->data.bs_node_associated.client_bssid, IEEE80211_ADDR_LEN);
            assocData.statusCode = DE_OK;

            int retn, len;
            struct ieee80211req_sta_info *station_info=NULL;
            struct ieee80211req_sta_info *sta_info=NULL;

            len = LIST_STATION_CFG_ALLOC_SIZE;
            station_info = ( struct ieee80211req_sta_info *)malloc(LIST_STATION_CFG_ALLOC_SIZE);
            if (!station_info){
                dataElementDebug(DBGERR, "%s: malloc failed \n",__func__);
                return;
            }

            retn = send_generic_command_cfg80211(cfg80211_ctx, ifname,
                    QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                    QCA_NL80211_VENDOR_SUBCMD_LIST_STA, (void *)station_info, len);
            if (retn < 0) {
                dataElementDebug(DBGERR, "%s: LIST STA failed, ifName: %s, ret:%d\n", __func__, ifname, retn);
                free(station_info);
                return;
            }
            uint8_t *stacp = NULL;
            stacp = (uint8_t *)station_info;
            while ( len >= sizeof(struct ieee80211req_sta_info ) ) {
                struct ieee80211req_athdbg req = {0};
                struct mesh_dbg_req_t mesh_req = {0};
                ieee80211_bsteering_datarate_info_t datarateInfo = {0};
                sta_info = (struct ieee80211req_sta_info *)stacp;
                if (deAreEqualMACAddrs(sta_info->isi_macaddr, &assocData.macAddress)) {
                    dataElementDebug(DBGINFO, "%s: STA macaddress " deMACAddFmt(":")"\n",
                            __func__, deMACAddData(sta_info->isi_macaddr));
                    de_phyCapInfo_t phyCapInfo = {
                        DE_FALSE /* valid */, de_chwidth_invalid, 0 /* numStreams */,
                        de_phymode_invalid, 0 /* maxMCS */, 0 /* maxTxPower */
                    };
                    memcpy(req.dstmac, sta_info->isi_macaddr, IEEE80211_ADDR_LEN);
                    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
                    req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_GET_DATARATE_INFO;
                    req.needs_reply = DBGREQ_REPLY_IS_REQUIRED;
                    retn = send_generic_command_cfg80211(cfg80211_ctx, ifname,
                            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                            QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req,
                            sizeof(struct ieee80211req_athdbg));
                    if (retn < 0) {
                        dataElementDebug(DBGERR, "%s: STA DATARATE Info failed, ifName: %s retn:%d\n",
                                __func__, ifname, retn);
                    } else {
                        mesh_req = (struct mesh_dbg_req_t )(req.data.mesh_dbg_req);
                        memcpy(&datarateInfo, &mesh_req.mesh_data, sizeof(ieee80211_bsteering_datarate_info_t));
                        phyCapInfo.valid = DE_TRUE;
                        dataElementDebug(DBGDUMP,"%s: chwidth %d numstreams:%d phymode %d MCS %d len %d \n",
                                __func__, datarateInfo.max_chwidth, datarateInfo.num_streams,
                                datarateInfo.phymode, datarateInfo.max_MCS, len);
                        phyCapInfo.maxChWidth =
                            dEMapToBandwidth(
                                    (enum ieee80211_cwm_width)(datarateInfo.max_chwidth)),
                            phyCapInfo.numStreams = datarateInfo.num_streams,
                            phyCapInfo.phyMode =
                                dEMapToPhyMode((enum ieee80211_phymode)datarateInfo.phymode),
                            phyCapInfo.maxMCS =
                                dEConvertToSingleStreamMCSIndex(
                                        (enum ieee80211_phymode)datarateInfo.phymode,
                                        datarateInfo.max_MCS);
                        phyCapInfo.maxTxPower = datarateInfo.max_txpower;
                        dataElementDebug(DBGDUMP,"%s: chwidth %d numstreams %d phymode %d  maxMCS %d \n",
                                __func__,phyCapInfo.maxChWidth, phyCapInfo.numStreams,
                                phyCapInfo.phyMode, phyCapInfo.maxMCS);

                    }

                    if ( sta_info->isi_htcap & IEEE80211_HTCAP_C_SHORTGI20 ) {
                        assocData.caps.apHtCap.shortGiSupport20Mhz = 1;
                        assocData.caps.isHTValid=1;
                    }
                    if ( sta_info->isi_htcap & IEEE80211_HTCAP_C_SHORTGI40 ) {
                        assocData.caps.apHtCap.shortGiSupport40Mhz = 1;
                        assocData.caps.isHTValid=1;
                    }
                    if ( sta_info->isi_htcap & IEEE80211_HTCAP_C_CHWIDTH40 ) {
                        assocData.caps.apHtCap.htSupport40Mhz = 1;
                        assocData.caps.isHTValid=1;
                    }

                    if ( sta_info->isi_vhtcap & IEEE80211_VHTCAP_SHORTGI_80 ) {
                        assocData.caps.apVhtCap.shortGiSupport80Mhz = 1;
                        assocData.caps.isVHTValid=1;
                    }

                    if ( sta_info->isi_vhtcap & IEEE80211_VHTCAP_SHORTGI_160 ) {
                        assocData.caps.apVhtCap.shortGiSupport160Mhz80p80Mhz = 1;
                        assocData.caps.isVHTValid=1;
                    }

                    if ( sta_info->isi_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 ) {
                        assocData.caps.apVhtCap.support80p80Mhz = 1;
                        assocData.caps.isVHTValid=1;
                    }

                    if (sta_info->isi_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160) {
                        assocData.caps.apVhtCap.support160Mhz = 1;
                        assocData.caps.isVHTValid=1;
                    }

                    if (sta_info->isi_vhtcap & IEEE80211_VHTCAP_SU_BFORMER) {
                        assocData.caps.apVhtCap.suBeamformerCapable = 1;
                        assocData.caps.isVHTValid=1;
                    }
                    if (sta_info->isi_vhtcap & IEEE80211_VHTCAP_MU_BFORMER) {
                        assocData.caps.apVhtCap.muBeamformerCapable = 1;
                        assocData.caps.isVHTValid=1;
                    }

                    if(sta_info->isi_vhtcap) {
                        u_int16_t mcs;
                        dEGetMcsBitConversion(phyCapInfo, &mcs);
                        assocData.caps.apVhtCap.supportedTxMCS = mcs;
                        assocData.caps.apVhtCap.supportedRxMCS = mcs;
                        assocData.caps.apVhtCap.maxTxNSS = phyCapInfo.numStreams;
                        assocData.caps.apVhtCap.maxRxNSS = phyCapInfo.numStreams;
                    }

                    assocData.caps.apHtCap.maxTxNSS = (sta_info->isi_nss & 0xf0)>>4;
                    assocData.caps.apHtCap.maxRxNSS = (sta_info->isi_nss & 0x0f);
                    break;
                }
                stacp += sta_info->isi_len;
                len -= sta_info->isi_len;
            }
            free(station_info);

            dECreateAssocObject(&assocData);
            dataElementDebug(DBGINFO, "%s:%d> <INFO> ifname:%s,Association Event:%d Received, ret:%s\n",
                    __func__, __LINE__, ifname, event->type, ret);
            break;
        case ATH_EVENT_BSTEERING_CLIENT_DISCONNECTED:
            if (disassocData == NULL) {
                disassocData = ( dataElementsDisassociationEventData_t *)malloc(sizeof(dataElementsDisassociationEventData_t));
            }
            if (!disassocData){
                dataElementDebug(DBGERR, "%s: malloc failed \n",__func__);
                return;
            }
            memcpy(disassocData->macAddress.ether_addr_octet, event->data.bs_disconnect_ind.client_addr,IEEE80211_ADDR_LEN);
            disassocData->reasonCode = event->data.bs_disconnect_ind.reason;
            dataElementDebug(DBGINFO, "%s:%d> <INFO> ifname:%s, Disassociation Event:%d Received, ret:%s\n",
                    __func__, __LINE__, ifname, event->type, ret);
            break;
        case ATH_EVENT_BSTEERING_STA_STATS:
           /* Host has to fisrt send CLIENT_DISCONNECTED event and followed with
              immediately they have to send STA_STATS event with is_disassoc_stats flag set,
              for respective disconnected Client mac-address. */
            if (event->data.bs_sta_stats.peer_stats[0].is_disassoc_stats) {
                if ((disassocData &&
                    deAreEqualMACAddrs(disassocData->macAddress.ether_addr_octet,
                                        event->data.bs_sta_stats.peer_stats[0].client_addr))) {

                    stats = (struct bs_sta_stats_ind *)&event->data.bs_sta_stats;

                    memset((void *)&(disassocData->BSSID), 0, IEEE80211_ADDR_LEN);
                    memcpy(disassocData->BSSID.ether_addr_octet, stats->peer_stats[0].bssid,
                           IEEE80211_ADDR_LEN);

                    disassocData->stats.txBytes  = stats->peer_stats[0].tx_byte_count;
                    disassocData->stats.rxBytes  = stats->peer_stats[0].rx_byte_count;
                    disassocData->stats.pktsSent = stats->peer_stats[0].tx_packet_count;
                    disassocData->stats.pktsRcvd = stats->peer_stats[0].rx_packet_count;
                    disassocData->stats.txPktErr = stats->peer_stats[0].tx_error_packets;
                    disassocData->stats.rxPktErr = stats->peer_stats[0].rx_error_packets;
                    disassocData->stats.cntRetx  = stats->peer_stats[0].tx_retrans;
                    dECreateDisAssocObject(disassocData);
                    free(disassocData);
                    disassocData = NULL;
                } else {
                    dataElementDebug(DBGERR,"%s:Disconnected and Sta stats, events, client mac-address are not equal \n",
                              __func__);
                }

                dataElementDebug(DBGINFO, "%s:%d> <INFO> ifname:%s,Sta Stats Event:%d For Disconnected client Received, ret:%s\n",
                    __func__, __LINE__, ifname, event->type, ret);
                }
            break;
    }
}

/**
 * @brief Event callback
 *
 * @param [in] cookie
 *
 */
static void dataElementsEventCB( void *data){
    const struct nlmsghdr *hdr = NULL;
    const ath_netlink_bsteering_event_t *event = NULL;
    u_int32_t numBytes;
    const u_int8_t *msg;

    numBytes = bufrdNBytesGet(&readBuf);
    msg = bufrdBufGet(&readBuf);
    do {
        if (bufrdErrorGet(&readBuf)) {
            dataElementDebug(DBGERR, "%s:%d> <FAILED> Read Error, numBytes:%d\n", __func__, __LINE__, numBytes );
            if (-1 == de_event_socket  ) {
                dataElementDebug(DBGERR, "%s:%d> <FAILED> socket creation!!!\n", __func__, __LINE__);
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
            dataElementDebug(DBGERR, "%s:%d> <FAILED> Invalid message len: %u bytes", __func__, __LINE__, numBytes);
            break;
        }
        event = NLMSG_DATA(hdr);
        dataElements_EventData(event);
    }while(0);
    bufrdConsume(&readBuf, numBytes);
}

/**
 * @brief enable bandsteering events
 *
 * @param [in] ifname interface name
 *
 * @return DE_OK on success
 */
DE_STATUS Enable_BsEvents( char *ifname){
    struct sockaddr_nl destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.nl_family = AF_NETLINK;
    destAddr.nl_pid = 0;
    destAddr.nl_groups = 0;

    struct nlmsghdr hdr;
    hdr.nlmsg_len = NLMSG_SPACE(0);
    hdr.nlmsg_flags = if_nametoindex(ifname);
    hdr.nlmsg_type = 0;
    hdr.nlmsg_pid = getpid();

    if (sendto(de_event_socket, &hdr, hdr.nlmsg_len, 0,
               (const struct sockaddr *) &destAddr, sizeof(destAddr)) < 0) {
        dataElementDebug(DBGERR, "%s:%d> <FAILED:%s:sendto> sock:%x len:%d \n", __func__, __LINE__, ifname, de_event_socket, hdr.nlmsg_len );
        return DE_NOK;
    }
    return DE_OK;
}

/**
 * @brief enable bandsteering params and event in the driver
 *
 * @param [in] ifname interface name
 *
 * @return DE_OK on success
 */
DE_STATUS Enable_BandSteering(char *ifname){
    struct ieee80211req_athdbg req = { 0 };
    int ret, i=0;

    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_PARAMS;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_check_period = 1;
    /*  Setting utilization_sample interval will start the ACS scan for current channel by SON driver
        and mad application also will start ACS scan during SAP test case.
        mad application needs ACS scan for all the channel in current band and SON driver scans current channel
        which makes ACS report to be changed frequently based on triggering place.
        If ACS is triggered by mad application and then SON driver also triggering the ACS then mad application
        will receive the acsreport for current channel only. To avoid this conflict ACS report is turned off by
        setting utilization_sample_period to 0. */
    req.data.mesh_dbg_req.mesh_data.bsteering_param.utilization_sample_period = 0;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.utilization_average_num_samples = 1;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.low_rssi_crossing_threshold = 10;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_overload = 10;
    req.data.mesh_dbg_req.mesh_data.bsteering_param.low_tx_rate_crossing_threshold = 0;
    while(i<BSTEERING_MAX_CLIENT_CLASS_GROUP){
       req.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_normal[i]=10;
       req.data.mesh_dbg_req.mesh_data.bsteering_param.high_tx_rate_crossing_threshold[i]=30;
        ++i;
    }

    req.needs_reply = DBGREQ_REPLY_IS_NOT_REQUIRED;
    ret = send_generic_command_cfg80211(cfg80211_ctx, ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req, (sizeof(struct ieee80211req_athdbg)));
    if (ret < 0) {
        if (ret != -EBUSY ) {
        dataElementDebug(DBGERR, "%s:%d> %s: <FAILED> BSTEERING_SET_PARAMS, err:%d !!!\n", __func__, __LINE__, ifname, ret);
        return DE_NOK;
        }
    }

    req.data.mesh_dbg_req.mesh_data.value = 1;
    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE;
    req.needs_reply = DBGREQ_REPLY_IS_NOT_REQUIRED;
    ret = send_generic_command_cfg80211(cfg80211_ctx, ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req, (sizeof(struct ieee80211req_athdbg)));
    if (ret < 0) {
        dataElementDebug(DBGERR, "%s:%d> %s: <FAILED> DBGREQ_BSTEERING_ENABLE, err:%d !!!\n", __func__, __LINE__, ifname, ret);
        return DE_NOK;
    }
    req.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    req.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE_EVENTS;
    ret = send_generic_command_cfg80211(cfg80211_ctx, ifname, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,QCA_NL80211_VENDOR_SUBCMD_DBGREQ, (void *)&req, (sizeof(struct ieee80211req_athdbg)));
    if (ret < 0) {
        if (ret != -EALREADY) {
        dataElementDebug(DBGERR, "%s:%d> %s: <FAILED> DBGREQ_BSTEERING_ENABLE_EVENTS, err:%d !!!\n", __func__, __LINE__, ifname, ret);
        return DE_NOK;
        }
    }
    if (Enable_BsEvents(ifname) != DE_OK){
        dataElementDebug(DBGERR, "%s:%d> <FAILED:%s:Enable_BsEvents>\n", __func__, __LINE__, ifname );
        return DE_NOK;
    }
    return DE_OK;
}

/**
 * @brief bandsteering event create
 *
 * @param [in] bss_index index of the bss
 *
 * @return DE_OK on success
 */
DE_STATUS dataElementsBSEventWlanCreate(char *ifname){

    if( Enable_BandSteering(ifname) != DE_OK) {
        close(de_event_socket);
        de_event_socket = -1;
        dataElementDebug(DBGERR, "%s:%d> %s: <FAILED> BS ENABLE\n", __func__, __LINE__, ifname );
        return DE_NOK;
    }
    dataElementDebug(DBGERR, "%s:%d> <INFO> %s: BandSteering Init Successfully\n", __func__, __LINE__, ifname );
    return DE_OK;
}

/**
 * @brief Bandsteering event initialization
 *
 * @return DE_OK on success
 */
DE_STATUS dataElementsBSEventWlanInit(void){

    struct sockaddr_nl addr={0};
    u_int32_t bufferSize;

    de_event_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_BAND_STEERING_EVENT);
    if (-1 == de_event_socket) {
        dataElementDebug(DBGERR, "%s:%d> <FAILED> socket creation!!!\n", __func__, __LINE__);
        return DE_NOK;
    }
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;
    if (-1 == bind(de_event_socket, (const struct sockaddr *) &addr, sizeof(addr))) {
        dataElementDebug(DBGERR, "%s:%d> <FAILED> bind netlink socket\n", __func__, __LINE__ );
        close(de_event_socket);
        de_event_socket = -1;
        return DE_NOK;
    }

    bufferSize = NLMSG_SPACE(sizeof(struct nlmsghdr) + sizeof(struct ath_netlink_bsteering_event));
    bufrdCreate(&readBuf, "deElementsEvent", de_event_socket, bufferSize, dataElementsEventCB, NULL);

    return DE_OK;
}

