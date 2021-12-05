/*
 * Copyright (c) 2017-2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <net/if.h>
#include <net/ethernet.h>
#include <asm/types.h>
#define _LINUX_IF_H /* Avoid redefinition of stuff */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

/*
struct ucred {
    __u32   pid;
    __u32   uid;
    __u32   gid;
};
*/

#include <ieee80211_external.h>
#include <cfg80211_external.h>
#include "wlanif_cfg80211.h"

#define _LINUX_TYPES_H
#include <wlan_dfs_ioctl.h>

#ifdef SON_MEMORY_DEBUG

#include "qca-son-mem-debug.h"
#undef QCA_MOD_INPUT
#define QCA_MOD_INPUT QCA_MOD_LIBWIFISONCFG
#include "son-mem-debug.h"

#endif /* SON_MEMORY_DEBUG */


#define TRACE_ENTRY() dbgf(soncfgDbgS.dbgModule, DBGINFO, "%s: Enter \n",__func__)
#define TRACE_EXIT() dbgf(soncfgDbgS.dbgModule, DBGINFO, "%s: Exit \n",__func__)
#define TRACE_EXIT_ERR() dbgf(soncfgDbgS.dbgModule, DBGERR, "%s: Exit with err %d\n",__func__,ret)

/* OL Radio xml parse using the shift and PARAM_BAND_INFO is fixed for cmd */
#define RADIO_PARAM_SHIFT 4096
#define RADIO_PARAM_BAND_INFO 399
#define RADIO_PARAM_FALLBACK_FREQ 444
#define OL_ATH_PARAM_BAND_INFO  (RADIO_PARAM_SHIFT + RADIO_PARAM_BAND_INFO)
#define OL_ATH_PARAM_NXT_RDR_FREQ  (RADIO_PARAM_SHIFT + RADIO_PARAM_FALLBACK_FREQ)

static struct nla_policy
wlan_cfg80211_get_station_info_policy[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1] = {

  [QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH] = {.type = NLA_U32 }
};

/**
 * @brief Function to send the cfg command or ioctl command.
 *
 * @param [in] radar  pointer to radarhandler
 * @param [in] ifname   interface name
 * @param [in] buf   buffer
 * @param [in] buflen   buffer length
 *
 * @return 0 for success, -1 for failure
 */
int radar_send_command (struct radarhandler *radar, const char *ifname, void *buf, size_t buflen,
                        int ioctl_sock_fd)
{
    struct cfg80211_data buffer;
    int nl_cmd = QCA_NL80211_VENDOR_SUBCMD_PHYERR;
    int msg;
    wifi_cfg80211_context pcfg80211_sock_ctx;

    pcfg80211_sock_ctx = radar->sock_ctx.cfg80211_ctxt;
    buffer.data = buf;
    buffer.length = buflen;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    msg = wifi_cfg80211_sendcmd(&pcfg80211_sock_ctx, nl_cmd, ifname,
                                (char *)&buffer, buflen);
    if (msg < 0) {
        fprintf(stderr, "Couldn't send NL command\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Function to Handle bangradar commands.
 *
 * @param [in] radar  pointer to radar handler
 *
 * @return 0 for success, -1 for failure
 */
int radarBangradar(struct radarhandler *radar)
{
    struct dfs_bangradar_params pe;
    pe.bangradar_type = DFS_BANGRADAR_FOR_ALL_SUBCHANS;
    pe.seg_id = 0;
    pe.is_chirp = 0;
    pe.freq_offset = 0;
    pe.detector_id = 0;

    radar->atd.ad_id = DFS_BANGRADAR | ATH_DIAG_IN;
    radar->atd.ad_out_data = NULL;
    radar->atd.ad_out_size = 0;
    radar->atd.ad_in_data = (void *) &pe;
    radar->atd.ad_in_size = sizeof(struct dfs_bangradar_params);
    if (radar_send_command(radar, radar->atd.ad_name, (caddr_t)&radar->atd,
                           sizeof(struct ath_diag), radar->s) < 0) {
        radar->atd.ad_in_data = NULL;
        return -1;
    }
    radar->atd.ad_in_data = NULL;
    return 0;
}

/**
 * @brief Initialize the context
 *
 * @param [in] sock_ctx socket context
 * @param [in] cmd_sock_id, event_sock_id: If application can run as background
 *                               process/daemon then use unique port numbers
 *                               otherwise default socket id for simple applications.
 *
 * @return 0 for success, -1 for failure
 */
int init_socket_context (struct socket_context *sock_ctx,
        int cmd_sock_id, int event_sock_id)
{
    int err = 0;

    sock_ctx->cfg80211_ctxt.pvt_cmd_sock_id = cmd_sock_id;
    sock_ctx->cfg80211_ctxt.pvt_event_sock_id = event_sock_id;

    err = wifi_init_nl80211(&(sock_ctx->cfg80211_ctxt));
    if (err) {
        return -1;
    }

    return 0;
}

void cfg82011_station_info_cb(struct cfg80211_data *buffer)
{
    /*Parsing the nl msg updates the data and date_len from driver*/
    struct nlattr *attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1];
    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_PARAM_MAX,
	      (struct nlattr *)buffer->data,
	      buffer->length, wlan_cfg80211_get_station_info_policy);
}

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
        dbgf(soncfgDbgS.dbgModule, DBGERR, "NL80211_ATTR_IFTYPE not found\n");
        return -EINVAL;
    }

    if(nl_msg[NL80211_ATTR_IFNAME])
    {
        memcpy(info->name, nla_data(nl_msg[NL80211_ATTR_IFNAME]), nla_len(nl_msg[NL80211_ATTR_IFNAME]));
        info->name[nla_len(nl_msg[NL80211_ATTR_IFNAME])] = '\0';
    } else {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "NL80211_ATTR_IFNAME not found\n");
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
        dbgf(soncfgDbgS.dbgModule, DBGERR, "ERROR: Failed to allocate netlink message for msg.\n");
        return -ENOMEM;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "ERROR: Failed to allocate netlink callbacks.\n");
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
    }

    /*   wait for reply */
    while (err > 0) {  /* error will be set by callbacks */
        ret = nl_recvmsgs(cfgCtx->cmd_sock, cb);
        if (ret) {
            dbgf(soncfgDbgS.dbgModule, DBGERR, "nl80211: %s->nl_recvmsgs failed: %d\n", __func__, ret);
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

//cfg80211 command to get param from driver
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
    buffer.parse_data = 0;
    if((ret=wifi_cfg80211_send_setparam_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, op, ifname, (char *)&buffer, sizeof(int))) < 0)
    {
        return -EIO;
    }
    return 0;
}

int send_mesh_get_cfg80211( wifi_cfg80211_context *cfgCtx, const char *ifname, int op, int *data)
{
    int ret;
    struct cfg80211_data buffer;
    buffer.data = data;
    buffer.length = sizeof(int);
    buffer.parse_data = 0;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    if((ret=wifi_cfg80211_send_getparam_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_MESH_CONFIGURATION, op, ifname, (char *)&buffer, sizeof(int))) < 0)
    {
        return -EIO;
    }
    return 0;
}

/*cfg80211 command to set param in driver*/
int send_mesh_set_cfg80211(wifi_cfg80211_context *cfgCtx, const char *ifname, int op, int *data, int data_len)
{
    int ret;
    struct cfg80211_data buffer;
    buffer.data = data;
    buffer.length = sizeof(int);
    buffer.parse_data = 0;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    if((ret=wifi_cfg80211_send_setparam_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_MESH_CONFIGURATION, op, ifname, (char *)&buffer, sizeof(int))) < 0)
    {
        return -EIO;
    }
    return 0;
}

#if QCA_AIRTIME_FAIRNESS
static void get_atf_table(struct cfg80211_data *buffer)
{
    static uint32_t length = 0;

    length += buffer->length;

    if (length >= sizeof(struct atftable)) {
        length = 0;
    }
}
#endif

/* Cfg80211 command to send genric commands to driver*/
int send_generic_command_cfg80211(wifi_cfg80211_context *cfgCtx, const char *ifname, int cmd, char *data, int data_len)
{
    int res;
    struct cfg80211_data buffer;
    buffer.data = (void *)data;
    buffer.length = data_len;
    buffer.callback = NULL;
#if QCA_AIRTIME_FAIRNESS
    if (cmd == QCA_NL80211_VENDOR_SUBCMD_ATF)
    {
        buffer.callback = &get_atf_table;
        buffer.parse_data = 0;
    }
#endif
    res = wifi_cfg80211_send_generic_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, cmd, ifname, (char *)&buffer, data_len);
    if (res < 0) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, " %s : send NL command failed cmd:%d \n",__func__, cmd);
        return res;
    }

    return 0;
}

/* Function to get name of the dev */
int getName_cfg80211(void *ctx, const char * ifname, char *name )
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_nlmsg_wdev_info(ifname, &(cfgPriv->cfg80211_ctx_qca), &devinfo)) < 0) {
        goto err;
    }

    strlcpy( name, devinfo.name, IFNAMSIZ );

    TRACE_EXIT();

    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int getPhyStats_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);
    if(( ret = send_generic_command_cfg80211 (&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_PHYSTATS, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to check whether the current device is AP */
int isAP_cfg80211(void *ctx, const char * ifname, uint32_t *result)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_nlmsg_wdev_info(ifname, &(cfgPriv->cfg80211_ctx_qca), &devinfo)) < 0) {
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
int getBSSID_cfg80211(void *ctx, const char * ifname, struct ether_addr *BSSID )
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    struct cfg80211_data buffer;
    buffer.data = BSSID;
    buffer.length = IEEE80211_ADDR_LEN;
    buffer.parse_data = 0;
    buffer.callback = &cfg82011_wificonfiguration_cb;
    if((ret=wifi_cfg80211_send_getparam_command(&(cfgPriv->cfg80211_ctx_qca), QCA_NL80211_VENDORSUBCMD_BSSID, 0, ifname, (char *)&buffer, IEEE80211_ADDR_LEN)) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Funtion to get ESSID info */
int getESSID_cfg80211(void *ctx, const char * ifname, void *buf, uint32_t *len )
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct cfg80211_data buffer;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    memset(buf, 0, (IEEE80211_NWID_LEN + 1));
    buffer.data = (void *)buf;
    buffer.length = IEEE80211_NWID_LEN;
    buffer.parse_data = 0; /* Enable callback */
    buffer.callback = &cfg82011_wificonfiguration_cb;

    if((ret=wifi_cfg80211_send_getparam_command(&(cfgPriv->cfg80211_ctx_qca),
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

/* Function to get frequency info*/
/* Devinfo command fails if the interface is not up, so using the vendor command to get frequency */
int getFreq_cfg80211(void *ctx, const char * ifname, int32_t * freq)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_GET_FREQUENCY, freq)) < 0) {
        goto err;
    }

    *freq = (*freq * 100000);

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get wireless extension */
int getRange_cfg80211(void *ctx, const char *ifname, int *we_version)
{
    TRACE_ENTRY();

    /*
     * Since this cfg path does not use wireless extension feature,
     * assigning a constant that always passes.
     */
    *we_version = WIRELESS_EXT;

    //TRACE_EXIT();
    return 0;
}

/* Function to get channel width*/
int getChannelWidth_cfg80211(void *ctx, const char * ifname, int * chwidth)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_CHWIDTH, chwidth)) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get channel extoffset */
int getChannelExtOffset_cfg80211(void *ctx, const char * ifname, int * choffset)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_CHEXTOFFSET, choffset)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/*Function to get ACS info*/
int getAcsState_cfg80211(void *ctx, const char * ifname, int * acsstate)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_GET_ACS, acsstate)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get CAC info*/
int getCacState_cfg80211(void *ctx, const char * ifname, int * cacstate)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_GET_CAC, cacstate)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get ParentIndex info*/
int getParentIfindex_cfg80211(void *ctx, const char * ifname, int * parentIndex)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_PARENT_IFINDEX, parentIndex)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to get smart monitor info*/
int getSmartMonitor_cfg80211(void *ctx, const char * ifname, int * smartmonitor)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_RX_FILTER_SMART_MONITOR, smartmonitor)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to get channel bandwidth*/
int getChannelBandwidth_cfg80211(void *ctx, const char * ifname, int * bandwidth)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_BANDWIDTH, bandwidth)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get Atf related generic info*/
int getGenericInfoAtf_cfg80211(void *ctx, const char * ifname, int cmd ,void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

#if QCA_AIRTIME_FAIRNESS
    if(cmd == IEEE80211_IOCTL_ATF_SHOWATFTBL)
    {
        struct atf_data atfdata;
        memset(&atfdata, 0, sizeof(atfdata));
        atfdata.id_type = IEEE80211_IOCTL_ATF_SHOWATFTBL;
        atfdata.buf = chanInfo;
        atfdata.len = chanInfoSize;
        ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_ATF, (void *)&atfdata, sizeof(atfdata));
    }
    else
#endif
    {
        ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_ATF, chanInfo, chanInfoSize);
    }

    if (ret < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get Ald related generic info*/
int getGenericInfoAld_cfg80211(void *ctx, const char * ifname,void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_ALD_PARAMS, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to hmwds related generic info*/
int getGenericInfoHmwds_cfg80211(void *ctx, const char * ifname,void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_HMWDS_PARAMS, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to Nac related generic info*/
int getGenericNac_cfg80211(void *ctx, const char * ifname,void * config, int configSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_NAC, config, configSize)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get centre frequency*/
int getCfreq2_cfg80211(void *ctx, const char * ifname, int32_t * cfreq2)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_SECOND_CENTER_FREQ,cfreq2)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get channel utilization */
int getChUtil_cfg80211(void *ctx, const char * ifname, int32_t * chutil)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_CHAN_UTIL,chutil)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}


/* Function to setparam in the driver*/
int setParam_cfg80211(void *ctx, const char *ifname, int cmd, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if((ret = send_command_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, cmd, data, len)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to mesh setparam in the driver*/
int setParam_mesh_cfg80211(void *ctx, const char *ifname, int cmd, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if((ret = send_mesh_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, cmd, data, len)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Functin to set maccmd, special case in argument handling*/
int setParamMaccmd_cfg80211(void *ctx, const char *ifname, void *data, uint32_t len)
{
    int ret,temp[2];
    struct wlanif_cfg80211_priv * cfgPriv;
    memcpy(temp, data, len);

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if((ret = send_command_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, temp[0], &temp[1], sizeof(temp[1]))) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/*Functin to set mapvapbeacon, special case in argument handling*/
int setMapVapBeacon_cfg80211(void *ctx, const char *ifname, void *data, uint32_t len)
{
    int ret,temp[2];
    struct wlanif_cfg80211_priv * cfgPriv;
    memcpy(temp, data, len);

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if((ret = send_mesh_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, temp[0], &temp[1], sizeof(temp[1]))) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get channel info*/
int getChannelInfo_cfg80211(void *ctx, const char * ifname, void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }


    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get channel info160*/
int getChannelInfo160_cfg80211(void *ctx, const char * ifname, void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN160, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get station info*/
int getStationInfo_cfg80211(void * ctx , const char *ifname, void *data , int * data_len)
{

#define LIST_STA_MAX_CFG80211_LENGTH (3*1024)
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct cfg80211_data buffer;
    int subCmd = QCA_NL80211_VENDOR_SUBCMD_LIST_STA;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    buffer.data = (void *)data;
    buffer.length = *data_len;
    buffer.parse_data = 0; /* Enable callback */
    buffer.flags = 0;
    buffer.callback = &cfg82011_station_info_cb;

    ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca), QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, subCmd, ifname, (char *)&buffer, *data_len);
    if (ret < 0) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, " %s : send NL command failed \n",__func__);
        goto err;
    }

    *data_len = buffer.length;

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get dbreq info*/
int getDbgreq_cfg80211(void * ctx , const char *ifname, void *data , uint32_t data_len)
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct ieee80211req_athdbg * req;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    req = (struct ieee80211req_athdbg *) data;
    assert(req != NULL);

    if (req->data.mesh_dbg_req.mesh_cmd == MESH_BSTEERING_GET_DATARATE_INFO) {
        req->needs_reply = DBGREQ_REPLY_IS_REQUIRED;
    }
    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, QCA_NL80211_VENDOR_SUBCMD_DBGREQ, data, data_len) < 0))
    {
        goto err;
    }
    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Funtion to get extended subcommands */
int getExtended_cfg80211(void * ctx , const char *ifname, void *data , uint32_t data_len)
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS, data, data_len) < 0))
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Funtion to get station stats*/
int getStaStats_cfg80211(void * ctx , const char *ifname, void *data , uint32_t data_len)
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_generic_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, QCA_NL80211_VENDOR_SUBCMD_STA_STATS, data, data_len)) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Funtion to handle Add/Del/Kick Mac commands*/
int addDelKickMAC_cfg80211(void * ctx , const char *ifname, int operation, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    int cfg_id=-1;
    char *ptr = (char *)data;

    TRACE_ENTRY();

    /* TODO: Check for proper handling */
    /* set len to 6 bytes to be coherent with the driver changes */
    len = ETH_ALEN;
    ptr = ptr + 2; /* Move 2 bytes (sa_family) to get the mac starting address */
    data = (void *)ptr;

    switch (operation)
    {
        case IO_OPERATION_ADDMAC:
            cfg_id = QCA_NL80211_VENDORSUBCMD_ADDMAC;
            break;
        case IO_OPERATION_DELMAC:
            cfg_id = QCA_NL80211_VENDORSUBCMD_DELMAC;
            break;
        case IO_OPERATION_KICKMAC:
            cfg_id = QCA_NL80211_VENDORSUBCMD_KICKMAC;
            break;
        default:
            /*Unsupported operation*/
            return -1;
    }

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if(( ret = send_generic_command_cfg80211 (&(cfgPriv->cfg80211_ctx_qca), ifname, cfg_id, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to set filter command */
int setFilter_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);
    if(( ret = send_generic_command_cfg80211 (&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDORSUBCMD_SETFILTER, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to get Wireless mode from driver*/
int getWirelessMode_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct cfg80211_data buffer;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    buffer.data = (void *)data;
    buffer.length = len;
    buffer.parse_data = 0; /* Enable callback */
    buffer.callback = &cfg82011_wificonfiguration_cb;

    ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca), QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION, QCA_NL80211_VENDORSUBCMD_WIRELESS_MODE, ifname, (char *)&buffer, len);

    if (ret < 0) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "%s :  send NL command failed - error %d\n",__func__,ret);
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to send mgmt packet*/
int sendMgmt_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);
    if(( ret = send_generic_command_cfg80211 (&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDORSUBCMD_SEND_MGMT, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get station count */
int getStaCount_cfg80211(void *ctx, const char * ifname, int32_t * result)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if (( ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, IEEE80211_PARAM_STA_COUNT, result)) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/// @see setIntfMode(const void *, const char *, const char *, u_int8_t);
int setIntfMode_cfg80211(void *ctx, const char * ifname, const char * mode, u_int8_t len)
{
    int ret;
    struct cfg80211_data buffer;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    buffer.data = (void *)mode;
    buffer.length = len;
    buffer.parse_data = 0;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    if((ret=wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca),
                    QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                    QCA_NL80211_VENDORSUBCMD_WIRELESS_MODE,
                    ifname, (char *)&buffer, len)) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get Band Info for the given radio interface*/
int getBandInfo_cfg80211(void *ctx, const char * ifname, uint8_t * band_info)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    int bandType;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if (( ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, OL_ATH_PARAM_BAND_INFO, &bandType)) < 0)
    {
        goto err;
    }
    *band_info = (uint8_t)bandType;

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get fallback for the given radio interface*/
int getFallbackFreq_cfg80211(void *ctx, const char * ifname, int * fallbackFreq)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    int fallbackFreqLocal;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if (( ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, OL_ATH_PARAM_NXT_RDR_FREQ,
          &fallbackFreqLocal)) < 0)
    {
        TRACE_EXIT_ERR();
        return ret;
    }
    *fallbackFreq = fallbackFreqLocal;

    TRACE_EXIT();
    return 0;

}

/* Function to set fallback for the given radio interface*/
int setFallbackFreq_cfg80211(void *ctx, const char * ifname, int fallbackFreq)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if (( ret = send_command_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, OL_ATH_PARAM_NXT_RDR_FREQ,
          &fallbackFreq, sizeof(int))) < 0)
    {
        TRACE_EXIT_ERR();
        return ret;
    }

    TRACE_EXIT();
    return 0;

}

/* Function to get MixedBh_uplink rate */
int getUplinkRate_cfg80211(void *ctx, const char * ifname, uint16_t * ul_rate)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    int upLinkRate;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if (( ret = send_mesh_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, MESH_WHC_MIXEDBH_ULRATE, &upLinkRate)) < 0)
    {
        goto err;
    }

    *ul_rate = (uint16_t)upLinkRate;

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to set MixedBh_uplink rate */
int setUplinkRate_cfg80211(void * ctx, const char *ifname, uint16_t ul_rate)
{
    int ret;
    int upLinkRate;

    upLinkRate = (int)ul_rate;

    TRACE_ENTRY();

    if (( ret = setParam_mesh_cfg80211(ctx, ifname, MESH_WHC_MIXEDBH_ULRATE, &upLinkRate, sizeof(upLinkRate))) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to set the son mode and BackHaul_type */
int setSonBhType_cfg80211(void * ctx, const char *ifname, uint8_t bh_type)
{
    int ret;
    int bhType;

    bhType = (int)bh_type;

    TRACE_ENTRY();

    if (( ret = setParam_mesh_cfg80211(ctx, ifname, MESH_WHC_BACKHAUL_TYPE, &bhType, sizeof(bhType))) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int setParamVapInd_cfg80211(void *ctx, const char *ifname, void *data, uint32_t len)
{
    int ret,temp[2];
    struct wlanif_cfg80211_priv * cfgPriv;
    memcpy(temp, data, len);

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if((ret = send_command_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, temp[0], &temp[1], sizeof(temp[1]))) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int setFreq_cfg80211(void *ctx, const char * ifname, int freq, int band)
{
    int ret;
    struct cfg80211_data buffer;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    buffer.data = &freq;
    buffer.length = sizeof(int);
    buffer.parse_data = 0;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    if((ret=wifi_cfg80211_send_setparam_command(&(cfgPriv->cfg80211_ctx_qca), QCA_NL80211_VENDORSUBCMD_CHANNEL_CONFIG, freq, ifname, (char *)&buffer, band)) < 0)
    {
        return -EIO;
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int setNOLChannel_cfg80211(void *ctx, const char * radioName)
{
    struct radarhandler radar;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);


    memset(&radar, 0, sizeof(radar));
    radar.sock_ctx.cfg80211_ctxt = cfgPriv->cfg80211_ctx_qca;

    strlcpy(radar.atd.ad_name, radioName, sizeof(radar.atd.ad_name));

    if(radarBangradar(&radar) < 0) {
        return -1;
    }

    return 0;
}

int getNOLChannel_cfg80211(void *ctx, const char * radioName, void* nolinfo)
{
    struct radarhandler radar;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    memset(&radar, 0, sizeof(radar));
    radar.sock_ctx.cfg80211_ctxt = cfgPriv->cfg80211_ctx_qca;

    strlcpy(radar.atd.ad_name, radioName, sizeof(radar.atd.ad_name));

    radar.atd.ad_id = DFS_GET_NOL | ATH_DIAG_DYN;
    radar.atd.ad_in_data = NULL;
    radar.atd.ad_in_size = 0;
    radar.atd.ad_out_data = nolinfo;
    radar.atd.ad_out_size = sizeof(struct dfsreq_nolinfo);

    if (radar_send_command(&radar, radar.atd.ad_name,
                (caddr_t)&radar.atd, sizeof(struct ath_diag),
                radar.s) < 0) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "STEVE %s: failed to get nol list %s",__func__, radar.atd.ad_name);
        return -1;
    }

    return 0;
}


/// @see setCFreq2(const void *, const char *, int)
int setCFreq2_cfg80211(void *ctx, const char * ifname, int chan_num)
{
    int ret;

    TRACE_ENTRY();

    if (( ret = setParam_cfg80211(ctx, ifname, IEEE80211_PARAM_SECOND_CENTER_FREQ, &chan_num, sizeof(chan_num))) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}


/// @see getPrivArgs(const void *, const char *, size_t *)
struct iw_priv_args *getPrivArgs_cfg80211(void *ctxt, const char *ifname, size_t *len) {
    TRACE_ENTRY();

    TRACE_EXIT();
    return NULL;
}

/// @see getACSReport(void *, const char *, u_int8_t *, ieee80211_acs_report_t[],
///                   u_int8_t *, ieee80211_neighbor_info_t[], u_int8_t[])
int getACSReport_cfg80211(void *ctx, const char *ifName, u_int8_t* numChans,
                          ieee80211_acs_report_t *chanData, u_int8_t* numNeighbors,
                          ieee80211_neighbor_info_t *neighborData, u_int8_t neighborChans[]) {
    struct ieee80211req_athdbg req;
    struct ieee80211_acs_dbg *acs = NULL;
    struct cfg80211_data buffer;
    struct wlanif_cfg80211_priv * cfgPriv;
    int ret=0;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;

    acs = (struct ieee80211_acs_dbg *)calloc(1, sizeof(struct ieee80211_acs_dbg));

    if(!acs) {
        ret = -ENOMEM;;
        TRACE_EXIT_ERR();
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
    buffer.parse_data = 0;

    ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_DBGREQ, ifName, (char *)&buffer, buffer.length);
    if (ret < 0) {
        TRACE_EXIT_ERR();
        goto cleanup;
    }

    // Loop through each channel data and get the neighbors
    u_int8_t idxChan = 0, idxNeighbor = 0;
    for (idxChan = 0; idxChan < *numChans && idxChan < acs->nchans; ++idxChan) {
        acs->entry_id = idxChan;
        req.cmd = IEEE80211_DBGREQ_GETACSREPORT;

        ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca),
              QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
              QCA_NL80211_VENDOR_SUBCMD_DBGREQ, ifName, (char *)&buffer, buffer.length);
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
        ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_DBGREQ, ifName, (char *)&buffer, buffer.length);

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
            ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca),
                    QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                    QCA_NL80211_VENDOR_SUBCMD_DBGREQ, ifName, (char *)&buffer, buffer.length);

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

    return ret;
}

/* Function to get Country Code*/
int getCountryCode_cfg80211(void *ctx, const char *ifname, size_t size, char *countryCode) {
    int ret;
    struct wlanif_cfg80211_priv *cfgPriv;
    char country[4] = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *)ctx;
    assert(cfgPriv != NULL);

    struct cfg80211_data buffer;
    buffer.data = (void *)country;
    buffer.length = sizeof(country);
    buffer.parse_data = 0;
    buffer.callback = &cfg82011_wificonfiguration_cb;
    if (( ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca),
                                           QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                                           QCA_NL80211_VENDORSUBCMD_COUNTRY_CONFIG, ifname,
                                           (char *) &buffer, sizeof(country))) < 0)
    {
        goto err;
    }

    memcpy(countryCode, country, size);
    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int setAcsChanList_cfg80211(void *ctx, const char *ifName, u_int8_t numChans, u_int8_t *channels) {
    int ret;
    struct ieee80211req_athdbg req;
    struct cfg80211_data buffer;
    struct wlanif_cfg80211_priv *cfgPriv;
    u_int8_t i;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *)ctx;
    assert(cfgPriv != NULL);

    memset(&req, 0, sizeof(struct ieee80211req_athdbg));


    req.cmd = IEEE80211_DBGREQ_SETACSUSERCHANLIST;
    req.needs_reply = DBGREQ_REPLY_IS_NOT_REQUIRED;
    req.data.user_chanlist.n_chan = numChans;

    for (i = 0; i < numChans; i++) {
        req.data.user_chanlist.chans[i].chan = channels[i];
        req.data.user_chanlist.chans[i].band = 0; //TODO: should pass proper band index for 6Ghz support
    }

    buffer.data = &req;
    buffer.length = sizeof(req);
    buffer.callback = NULL;
    buffer.parse_data = 0;

    ret = wifi_cfg80211_send_generic_command(&(cfgPriv->cfg80211_ctx_qca),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_DBGREQ, ifName, (char *)&buffer, buffer.length);

    if (ret < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int getMapBssRole_cfg80211(void *ctx, const char *ifName, u_int8_t *mapBssRole) {
    int ret, result;
    struct wlanif_cfg80211_priv *cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *)ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_mesh_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifName,
                                         MESH_MAP_BSS_TYPE, &result)) < 0) {
        goto err;
    }

    *mapBssRole = (u_int8_t)result;

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int setCACTimeout_cfg80211(void *ctx, const char * ifname, int cac_timeout)
{
    int ret;

    TRACE_ENTRY();

    if (( ret = setParam_cfg80211(ctx, ifname, IEEE80211_PARAM_DFS_CACTIMEOUT, &cac_timeout, sizeof(cac_timeout))) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int setRRMFilter_cfg80211(void *ctx, const char * ifname, u_int8_t rrm_filter)
{
    int ret;

    TRACE_ENTRY();

    if (( ret = setParam_cfg80211(ctx, ifname,  IEEE80211_PARAM_RRM_FILTER, &rrm_filter, sizeof(rrm_filter))) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

int setWNMFilter_cfg80211(void *ctx, const char * ifname, u_int8_t wnm_filter)
{
    int ret;

    TRACE_ENTRY();

    if (( ret = setParam_cfg80211(ctx, ifname, IEEE80211_PARAM_WNM_FILTER, &wnm_filter, sizeof(wnm_filter))) < 0)
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*
 * cfg80211_event_getwifi: Function which fills outputbuf with inputbuf(eventdata)
 * @ifindex: ifindex for a particular interface
 * @cmdid: Event type
 * @inpubuf: Event data
 * @len: length of the data
 * @outputbuf : Filled in format of LBD strcture ath_vendorcfg_event
 * with int cmdid, int ifindex and with Event Data(inputbuf)
 * @return 0 on success, otherwise return 1
 */
u_int8_t cfg80211_event_getwifi(int ifindex, int cmdid, void *inputbuf,
        uint32_t len, void *outbuf)
{
    int *locbuf;

    if (inputbuf == NULL || outbuf == NULL) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "%s: %d ERROR!! Received NULL buffer\n",__func__, __LINE__);
        return 1;
    }

    dbgf(soncfgDbgS.dbgModule, DBGDEBUG, ":%s Received Event with cmdid:%d ifidx:%d len:%d \n",__func__, cmdid, ifindex, len);
    if ((cmdid != QCA_NL80211_VENDOR_SUBCMD_DBGREQ) && (cmdid != QCA_NL80211_VENDOR_SUBCMD_FWD_RRM_RPT)
          && (cmdid != QCA_NL80211_VENDOR_SUBCMD_FWD_BTM_RPT) && (cmdid != QCA_NL80211_VENDOR_SUBCMD_SMPS_UPDATE)
            && (cmdid != QCA_NL80211_VENDOR_SUBCMD_OPMODE_UPDATE)) {

         dbgf(soncfgDbgS.dbgModule, DBGERR, "%s: %d unknown subcmd:%d cannot handle \n", __func__, __LINE__, cmdid);
         return 1;
    }
    locbuf = (int *)outbuf;
    *locbuf = cmdid;
    locbuf++;
    *locbuf = ifindex;
    locbuf++;

    switch (cmdid) {
        case QCA_NL80211_VENDOR_SUBCMD_DBGREQ:
            {
                struct ieee80211req_athdbg_event *dbg_event;
                struct ieee80211_hmwds_ast_add_status *ast_status = (struct ieee80211_hmwds_ast_add_status *) locbuf;
                u_int8_t offset = 0;

                dbg_event = (struct ieee80211req_athdbg_event *)inputbuf;
                if (dbg_event->cmd == IEEE80211_DBGREQ_HMWDS_AST_ADD_STATUS) {
                    ast_status->cmd = dbg_event->cmd;
                    memcpy(ast_status->peer_mac, (u_int8_t *) &(dbg_event->fw_unit_test), IEEE80211_ADDR_LEN);
                    offset+=IEEE80211_ADDR_LEN;
                    memcpy(ast_status->ast_mac, (((u_int8_t *)&dbg_event->fw_unit_test) + offset), IEEE80211_ADDR_LEN);
                    offset+=IEEE80211_ADDR_LEN;
                    ast_status->status = *(int *)(((u_int8_t *)&(dbg_event->fw_unit_test)) + offset);
                }

            }
            break;
        case QCA_NL80211_VENDOR_SUBCMD_FWD_RRM_RPT:
        case QCA_NL80211_VENDOR_SUBCMD_FWD_BTM_RPT:
        case QCA_NL80211_VENDOR_SUBCMD_SMPS_UPDATE:
        case QCA_NL80211_VENDOR_SUBCMD_OPMODE_UPDATE:
            {
               memcpy((u_int8_t *)locbuf, (u_int8_t *)inputbuf, len*sizeof(u_int8_t));
            }
            break;
        default:
            dbgf(soncfgDbgS.dbgModule, DBGERR, "%s:CFG80211 event unknown cmd: %d\n",__func__,cmdid);
            return 1;
            break;
        }
    return 0;
}


/*
 * nl80211_vendor_event_qca_parse_get_wifi: nl80211 vendor event to get wifi configuration
 * @ifname: interface name
 * @data: pointer to data
 * @len: length of the data
 * @return 0 on success, otherwise return 1
 */
u_int8_t nl80211_vendor_event_qca_parse_get_wifi(int ifidx,
        uint8_t *data, size_t len, void *outbuf)
{
    struct nlattr *tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX + 1];
    struct nlattr *tb;
    void *buffer = NULL;
    uint32_t buffer_len = 0;
    uint32_t subcmd;

    if (nla_parse(tb_array, QCA_WLAN_VENDOR_ATTR_CONFIG_MAX,
                (struct nlattr *) data, len, NULL)) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "%s: INVALID EVENT\n",__func__);
        return 1;
    }
    tb = tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND];
    if (!tb) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "ERROR!!!GENERIC CMD not found within get-wifi subcmd\n");
        return 1;
    }
    subcmd = nla_get_u32(tb);

    tb = tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA];
    if (tb) {
        buffer = nla_data(tb);
        buffer_len = nla_len(tb);
        if (cfg80211_event_getwifi(ifidx, subcmd, buffer, buffer_len, outbuf) != 0)
            return 1;
    }
    return 0;
}

/*
 * cfg80211_event_callback: cfg80211 event callback to get wifi configuration
 * @ifname: interface name
 * @subcmd: enum value for sub command
 * @data: pointer to the data
 * @len: length of the data
 */
void cfg80211_event_callback(char *ifname,
        uint32_t subcmd, uint8_t *data, size_t len)
{
    /* Dummy callback function for ceating the event socket */
    return;
}

int get_cfg80211_event_sock(void * ctx)
{
    struct wlanif_cfg80211_priv * cfgPriv = (struct wlanif_cfg80211_priv *)ctx;

    return cfgPriv->cfg80211_ctx_qca.event_sock->s_fd;
}

/*
 * get_nl80211_event_msg: Function to parse the cfg event data
 * @msg: Pointer to netlink event message
 * @outbuf: out put, pointer on whcih parsed data is stored
 * @return 0 on success
 */

int get_nl80211_event_msg(u_int8_t *msg, void * ctx, void *outbuf)
{
    struct genlmsghdr *gnlh = (struct genlmsghdr *)msg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int ifidx = -1;
    char ifname[20] = {0};

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX])
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

    if (ifidx != -1) {
        if_indextoname(ifidx, ifname);
    }

    switch (gnlh->cmd) {
        case NL80211_CMD_VENDOR:
            {
                u_int32_t vendor_id, subcmd;
                u_int8_t *data = NULL;
                size_t len = 0;

                if (!tb[NL80211_ATTR_VENDOR_ID] ||
                        !tb[NL80211_ATTR_VENDOR_SUBCMD])
                    return -1;

                vendor_id = nla_get_u32(tb[NL80211_ATTR_VENDOR_ID]);
                subcmd = nla_get_u32(tb[NL80211_ATTR_VENDOR_SUBCMD]);

                if (tb[NL80211_ATTR_VENDOR_DATA]) {
                    data = nla_data(tb[NL80211_ATTR_VENDOR_DATA]);
                    len = nla_len(tb[NL80211_ATTR_VENDOR_DATA]);
                }
                switch (vendor_id) {
                    case OUI_QCA:
                        switch(subcmd) {
                            case QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION:
                                if (nl80211_vendor_event_qca_parse_get_wifi(ifidx, data, len, outbuf)!= 0)
                                    return 1;
                                break;
                            default:
                                break;
                        }
                        break;
                    default:
                        break;
                }
            }
            break;

        default:
            break;
    }
    return 0;
}

/* Init Fucnction to handle private ioctls*/
int wlanif_cfg80211_init(struct wlanif_config *cfg80211_conf)
{
    struct wlanif_cfg80211_priv * cfgPriv;

    int ret;
    /* Initialize debug module used for logging */
    soncfgDbgS.dbgModule = dbgModuleFind("libsoncfg");
    soncfgDbgS.dbgModule->Level=DBGERR;

    assert(cfg80211_conf != NULL);

    cfg80211_conf->IsCfg80211 = 1;
    cfg80211_conf->ctx = malloc(sizeof(struct wlanif_cfg80211_priv));

    if (cfg80211_conf->ctx == NULL)
    {
        printf("%s: Failed\n",__func__);
        return -ENOMEM;
    }

    cfgPriv = (struct wlanif_cfg80211_priv *) cfg80211_conf->ctx;

    assert(cfgPriv != NULL);

    /* Fill the private socket id for command and events */
    cfgPriv->cfg80211_ctx_qca.pvt_cmd_sock_id = cfg80211_conf->pvt_cmd_sock_id;
    cfgPriv->cfg80211_ctx_qca.pvt_event_sock_id = cfg80211_conf->pvt_event_sock_id;

    cfgPriv->cfg80211_ctx_qca.event_callback = cfg80211_event_callback;
    /*Initializing event related members to zero for not event supporting module*/
    cfgPriv->cfg80211_ctx_qca.event_thread_running = 0;
    cfgPriv->cfg80211_ctx_qca.event_sock = NULL;

    ret = wifi_init_nl80211(&(cfgPriv->cfg80211_ctx_qca));
    if (ret) {
        dbgf(soncfgDbgS.dbgModule, DBGERR, "%s : unable to create NL socket\n",__func__) ;
        return -EIO;
    }

    return 0;
}

/* Destroy the intialized context for cfg80211*/
void wlanif_cfg80211_deinit(struct wlanif_config *cfg80211_conf)
{
    struct wlanif_cfg80211_priv * cfgPriv;

    assert(cfg80211_conf != NULL);

    cfgPriv = (struct wlanif_cfg80211_priv *) cfg80211_conf->ctx;

    wifi_destroy_nl80211(&(cfgPriv->cfg80211_ctx_qca));

    free(cfg80211_conf->ctx);
}

