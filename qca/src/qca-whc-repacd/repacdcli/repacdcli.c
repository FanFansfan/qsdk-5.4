/*
 * Copyright (c) 2019 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <linux/version.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <qcatools_lib.h>

#include <cfg80211_nlwrapper_pvt.h>
#include <ieee80211_external.h>
#include <nl80211_copy.h>
#include <qca_vendor.h>
#include "repacdcli.h"

wifi_cfg80211_context *cfg80211_ctx;

/* The prints in the tool are commented deliberatly
   as the requirement is for repacd script which are
   sensitive to prints.
   The prints are not removed to facilitate easy
   debugging when required */

int wifi_init(wifi_cfg80211_context *cfg80211_ctx)
{
    int ret;

    /* Fill the private socket id for command and events */
    cfg80211_ctx->pvt_cmd_sock_id = 960;
    cfg80211_ctx->pvt_event_sock_id = 0;

    /*Initializing event related members to zero for not event supporting module*/
    cfg80211_ctx->event_thread_running = 0;
    cfg80211_ctx->event_sock = NULL;

    ret = wifi_init_nl80211((cfg80211_ctx));
    if (ret) {
        //printf("%s : unable to create NL socket\n",__func__) ;
        return -EIO;
    }

    return 0;
}

void wifi_deinit(wifi_cfg80211_context *cfg80211_ctx)
{
    wifi_destroy_nl80211((cfg80211_ctx));
}

int response_handler(struct nl_msg *msg, void *data)
{
    struct genlmsghdr *header = NULL;
    struct nlattr *attributes[NL80211_ATTR_MAX_INTERNAL + 1];
    struct nlattr *attr_vendor[NL80211_ATTR_MAX_INTERNAL];
    char *vendata = NULL;
    int datalen = 0;
    size_t response_len = 0;
    int result = 0;
    struct cfg80211_data *cfgdata = (struct cfg80211_data *)data;
    u_int32_t *temp = NULL;

    header = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
    result = nla_parse(attributes, NL80211_ATTR_MAX_INTERNAL, genlmsg_attrdata(header, 0),
            genlmsg_attrlen(header, 0), NULL);

    if (result) {
        //printf ("In %s:  nla_parse() failed with %d value", __func__, result);
        return -EINVAL;
    }

    if (attributes[NL80211_ATTR_VENDOR_DATA]) {
        vendata = ((char *)nla_data(attributes[NL80211_ATTR_VENDOR_DATA]));
        datalen = nla_len(attributes[NL80211_ATTR_VENDOR_DATA]);
        if (!vendata) {
            //fprintf(stderr, "Vendor data not found\n");
            return -EINVAL;
        }
    } else {
        //fprintf(stderr, "NL80211_ATTR_VENDOR_DATA not found\n");
        return -EINVAL;
    }

    if (cfgdata->parse_data)  {
        cfgdata->nl_vendordata = vendata;
        cfgdata->nl_vendordata_len = datalen;
        if (cfgdata->callback) {
            cfgdata->callback(cfgdata);
            return NL_OK;
        }
    }

    /* extract data from NL80211_ATTR_VENDOR_DATA attributes */
    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_PARAM_MAX,
            (struct nlattr *)vendata,
            datalen, NULL);

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]) {
        /* memcpy tb_vendor to data */
        temp = nla_data(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]);
        response_len = nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH]);

        if (response_len <= cfgdata->length) {
            memcpy(cfgdata->data, temp, response_len);
        } else {
            cfgdata->data = temp;
        }

        cfgdata->length = response_len;

        if (cfgdata->callback) {
            cfgdata->callback(cfgdata);
        }
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS]) {
        cfgdata->flags = nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS]);
    }

    return NL_OK;
}


int error_skip_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{

    int *ret = (int *)arg;
    *ret = err->error;
    //printf("Error received: %d \n", err->error);
    if (err->error > 0) {
        *ret = -(err->error);
    }
    return NL_SKIP;
}

int cfg80211_send_nlmsg(wifi_cfg80211_context *ctx, struct nl_msg *nlmsg, void *data)
{
    int err = 0, res = 0;
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);

    if (!cb) {
        err = -1;
        goto out;
    }

    /* send message */
    err = nl_send_auto_complete(ctx->cmd_sock, nlmsg);

    if (err < 0) {
        goto out;
    }
    err = 1;

    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_err(cb, NL_CB_CUSTOM, error_skip_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, response_handler, data);

    /*   wait for reply */
    while (err > 0) {  /* error will be set by callbacks */
        res = nl_recvmsgs(ctx->cmd_sock, cb);
        if (res) {
            //fprintf(stderr, "nl80211: %s->nl_recvmsgs failed: %d\n", __func__, res);
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

struct nl_msg *cfg80211_prepare_command(wifi_cfg80211_context *ctx, int cmdid, const char *ifname)
{
    int res;
    struct nl_msg *nlmsg = nlmsg_alloc();
    if (nlmsg == NULL) {
        //fprintf(stderr, "Out of memory\n");
        return NULL;
    }

    genlmsg_put(nlmsg, 0, 0, ctx->nl80211_family_id,
            0, 0, NL80211_CMD_VENDOR, 0);

    res = put_u32(nlmsg, NL80211_ATTR_VENDOR_ID, QCA_VENDOR_OUI);
    if (res < 0) {
        //fprintf(stderr, "Failed to put vendor id\n");
        nlmsg_free(nlmsg);
        return NULL;
    }
    /* SET_WIFI_CONFIGURATION = 72 */
    res = put_u32(nlmsg, NL80211_ATTR_VENDOR_SUBCMD, cmdid);
    if (res < 0) {
        //fprintf(stderr, "Failed to put vendor sub command\n");
        nlmsg_free(nlmsg);
        return NULL;
    }

    if (put_u32(nlmsg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname))) {
        return NULL;
    }

    return nlmsg;
}

int cfg80211_send_getparam_command(wifi_cfg80211_context *ctx, int cmdid,
        int param, const char *ifname, char *buffer, int len)
{
    struct nl_msg *nlmsg = NULL;
    int res = -EIO;
    struct nlattr *nl_venData = NULL;
    nlmsg = cfg80211_prepare_command(ctx,
            QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
            ifname);

    /* Prepare Actual Payload
       1. nla_put - command ID.
       2. nla_put - data
       3. nla_put length
       QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND,
       QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE,
     */
    if (nlmsg) {
        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData) {
            //fprintf(stderr, "failed to start vendor data\n");
            nlmsg_free(nlmsg);
            return -EIO;
        }

        if (nla_put_u32(nlmsg,
                    QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, cmdid)) {
            nlmsg_free(nlmsg);
            return -EIO;
        }
        if (nla_put_u32(nlmsg,
                    QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, param)) {
            nlmsg_free(nlmsg);
            return -EIO;
        }

        if (nl_venData) {
            end_vendor_data(nlmsg, nl_venData);
        }
        res = cfg80211_send_nlmsg(ctx, nlmsg, buffer);

        if (res < 0) {
            return res;
        }
        return res;
    } else {
        return -EIO;
    }

    return res;
}


/* nl handler for IW based ioctl*/
static int wdev_info_handler_2g(struct nl_msg *msg, void *arg)
{
    struct nlattr *nl_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct wdev_info *info = arg;

    nla_parse(nl_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if(nl_msg[NL80211_ATTR_IFNAME])
    {
        if((nla_len(nl_msg[NL80211_ATTR_IFNAME]) > IFNAMSIZ-1)  || (nla_len(nl_msg[NL80211_ATTR_IFNAME]) < 0))
            return -EINVAL;

        memcpy((void *)info->name, nla_data(nl_msg[NL80211_ATTR_IFNAME]), nla_len(nl_msg[NL80211_ATTR_IFNAME]));
        info->name[nla_len(nl_msg[NL80211_ATTR_IFNAME])] = '\0';
    } else {
        //printf( "NL80211_ATTR_IFNAME not found\n");
        return -EINVAL;
    }

    if (nl_msg[NL80211_ATTR_IFTYPE])
    {
        info->nlmode = nla_get_u32(nl_msg[NL80211_ATTR_IFTYPE]);
    } else {
        //printf("NL80211_ATTR_IFTYPE not found\n");
        return -EINVAL;
    }

    if(nl_msg[NL80211_ATTR_WIPHY_FREQ])
    {
        info->freq = nla_get_u32(nl_msg[NL80211_ATTR_WIPHY_FREQ]);
    }

    if (!memcmp(&info->name, "ath" , 3) && ((info->freq >= 2412) && (info->freq <= 2484)) && (info->nlmode == NL80211_IFTYPE_AP))
        printf("%s\n",info->name);

    return NL_SKIP;
}

/* nl handler for IW based ioctl*/
static int wdev_info_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *nl_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct wdev_info *info = arg;

    nla_parse(nl_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if(nl_msg[NL80211_ATTR_IFNAME])
    {
        if((nla_len(nl_msg[NL80211_ATTR_IFNAME]) > IFNAMSIZ-1) || (nla_len(nl_msg[NL80211_ATTR_IFNAME]) < 0))
            return -EINVAL;

        memcpy((void *)info->name, nla_data(nl_msg[NL80211_ATTR_IFNAME]), nla_len(nl_msg[NL80211_ATTR_IFNAME]));
        info->name[nla_len(nl_msg[NL80211_ATTR_IFNAME])] = '\0';
    } else {
        //printf( "NL80211_ATTR_IFNAME not found\n");
        return -EINVAL;
    }

    if(nl_msg[NL80211_ATTR_WIPHY_FREQ])
    {
        info->freq = nla_get_u32(nl_msg[NL80211_ATTR_WIPHY_FREQ]);
    }

    if (!memcmp(&info->name, "ath" , 3))
    {
        if((info->freq >= 2412) && (info->freq <= 2484))
            printf("2\n");
        else if((info->freq >= 5180) && (info->freq <= 5825))
            printf("5\n");
    }

    return NL_SKIP;
}


/*allocate and send nlmsg to handle IW based ioctl*/
int send_nlmsg_wdev_info (const char *ifname, wifi_cfg80211_context *cfgCtx, struct wdev_info *dev_info)
{
    struct nl_msg *nlmsg;
    struct nl_cb *cb;
    int ret, err;

    nlmsg = nlmsg_alloc();
    if (!nlmsg) {
        //printf("ERROR: Failed to allocate netlink message for msg.\n");
        return -ENOMEM;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        //printf("ERROR: Failed to allocate netlink callbacks.\n");
        nlmsg_free(nlmsg);
        return -ENOMEM;
    }

    /* Prepare nlmsg get the Interface attributes */
    genlmsg_put(nlmsg, 0, 0, cfgCtx->nl80211_family_id , 0, 0, NL80211_CMD_GET_INTERFACE, 0);
    nla_put_u32(nlmsg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname));

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_skip_handler, &err);
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
            //printf("nl80211: %s->nl_recvmsgs failed: %d\n", __func__, ret);
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

/*allocate and send nlmsg to handle IW based ioctl*/
int send_nlmsg_wdev_all_info (wifi_cfg80211_context *cfgCtx, struct wdev_info *dev_info, int mode)
{
    struct nl_msg *nlmsg;
    struct nl_cb *cb;
    int ret, err;

    nlmsg = nlmsg_alloc();
    if (!nlmsg) {
        //printf("ERROR: Failed to allocate netlink message for msg.\n");
        return -ENOMEM;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        //printf("ERROR: Failed to allocate netlink callbacks.\n");
        nlmsg_free(nlmsg);
        return -ENOMEM;
    }

    /* Prepare nlmsg get the Interface attributes */
    genlmsg_put(nlmsg, 0, 0, cfgCtx->nl80211_family_id , 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    if ( mode == GET_ALL_INTERFACE_FREQUENCY)
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wdev_info_handler , dev_info);
    else if (mode == GET_ALL_2G_INTERFACE)
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wdev_info_handler_2g , dev_info);

    /* send message */
    ret = nl_send_auto_complete(cfgCtx->cmd_sock, nlmsg);
    if (ret < 0) {
        goto out;
    }

    /*   wait for reply */
    while (err > 0) {  /* error will be set by callbacks */
        ret = nl_recvmsgs(cfgCtx->cmd_sock, cb);
        if (ret) {
            //printf("nl80211: %s->nl_recvmsgs failed: %d\n", __func__, ret);
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
int send_command_get_cfg80211(wifi_cfg80211_context *cfgCtx, const char *ifname, int op, int *data)
{
    int ret;
    struct cfg80211_data buffer;
    buffer.data = data;
    buffer.length = sizeof(int);
    buffer.parse_data = 0;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    if((ret=cfg80211_send_getparam_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, op, ifname, (char *)&buffer, sizeof(int))) < 0)
    {
        return -EIO;
    }
    return 0;
}

/*
 * Output a bitrate with proper scaling
 */

void print_bitrate(int kbits, int print_mode)
{
    if (print_mode) {
        if (kbits >= MEGA_BITS)
            printf("%0.6g Gb/s\n", (float)kbits/MEGA_BITS);
        else if (kbits >= KILO_BITS)
            printf("%0.6g Mb/s\n", (float)kbits/KILO_BITS);
        else
            printf("%d Kb/s\n", kbits);
    } else {
        if (kbits >= MEGA_BITS)
            printf("%0.6g\n", (float)kbits/MEGA_BITS);
        else if (kbits >= KILO_BITS)
            printf("%0.6g\n", (float)kbits/KILO_BITS);
        else
            printf("%d\n", kbits);
    }
}

int get_bitrate(const char * ifname, int unit)
{
    int ret,bitrate;

    if ((ret = send_command_get_cfg80211((cfg80211_ctx),ifname, IEEE80211_PARAM_GET_MAX_RATE, &bitrate)) < 0) {
        if (unit)
            printf("0 b/s\n");
        else
            printf("0\n");
        return ret;
    }
    print_bitrate(bitrate, unit);
    return 0;

}

int get_signal(const char * ifname)
{
    int ret,signal;

    if ((ret = send_command_get_cfg80211((cfg80211_ctx),ifname, IEEE80211_PARAM_GET_SIGNAL_LEVEL, &signal)) < 0) {
        printf("0\n");
        return ret;
    }
    if(signal >= 64)
        signal -= 0x100;
    printf("%d\n",signal);

    return 0;

}

static struct nla_policy
wlan_cfg80211_get_wireless_mode_policy[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1] = {

    [QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH] = {.type = NLA_U32 },
    [QCA_WLAN_VENDOR_ATTR_PARAM_DATA] = {.type = NLA_STRING },
};

void wificonfiguration_cb(struct cfg80211_data *buffer)
{
    struct nlattr *attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_MAX + 1];

    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_PARAM_MAX,
            (struct nlattr *)buffer->data,
            buffer->length, wlan_cfg80211_get_wireless_mode_policy);
}

/* Funtion to get ESSID info */
int get_essid(const const char * ifname)
{
    int ret;
    struct cfg80211_data buffer;
    u_int8_t buf[IEEE80211_NWID_LEN + 1];

    memset(buf, 0, (IEEE80211_NWID_LEN + 1));
    buffer.data = (void *)&buf;
    buffer.length = IEEE80211_NWID_LEN;
    buffer.parse_data = 0; /* Enable callback */
    buffer.callback = &wificonfiguration_cb;

    if((ret=cfg80211_send_getparam_command((cfg80211_ctx),
                    QCA_NL80211_VENDORSUBCMD_GET_SSID, 0,
                    ifname, (char *)&buffer, IEEE80211_NWID_LEN)) < 0)
    {
        return ret;
    }
    printf("%s\n",buf);

    return 0;
}

/* Function to get BSSID address */
int get_bssid(const char * ifname)
{
    int ret;
    struct ether_addr zeroAddr = {{0,0,0,0,0,0}};
    static const struct ether_addr tempAddr = {{0,0,0,0,0,0}};

    struct cfg80211_data buffer;
    buffer.data = &zeroAddr;
    buffer.length = IEEE80211_ADDR_LEN;
    buffer.parse_data = 0;
    buffer.callback = &wificonfiguration_cb;
    if((ret=cfg80211_send_getparam_command((cfg80211_ctx), QCA_NL80211_VENDORSUBCMD_BSSID, 0, ifname, (char *)&buffer, IEEE80211_ADDR_LEN)) < 0)
    {
        printf("Not-Associated");
        return ret;
    }
    if(IsEqualMACAddrs(&tempAddr.ether_addr_octet, &zeroAddr.ether_addr_octet))
    {
        printf("Not-Associated");
    } else {
        printf(MACAddFmt(":"), MACAddData(&zeroAddr.ether_addr_octet));
    }

    return 0;
}

int is_interface_up(const char * ifname)
{

    int ret;
    char name[ IFNAMSIZ ];
    struct wdev_info devinfo = {0};

    if ((ret = send_nlmsg_wdev_info(ifname, cfg80211_ctx, &devinfo)) < 0) {
        return ret;
    }

    return 0;
}

int getName_all(int mode)
{

    int ret;
    struct wdev_info devinfo = {0};

    if ((ret = send_nlmsg_wdev_all_info(cfg80211_ctx, &devinfo, mode)) < 0) {
        return ret;
    }

    return 0;
}

/* Function to get frequency info*/
/* Devinfo command fails if the interface is not up, so using the vendor command to get frequency */
int get_freq(const char * ifname)
{
    int ret,freq;
    if ((ret = send_command_get_cfg80211((cfg80211_ctx),ifname, IEEE80211_PARAM_GET_FREQUENCY, &freq)) < 0) {
        return ret;
    }

    printf("%d\n",freq);

    return 0;
}


void usage(void)
{
    fprintf(stderr, "Bitrate: usage: repacdcli athX get_bitrate \n");
    fprintf(stderr, "Bitrate with units: usage: repacdcli athX get_bitrate_unit \n");
    fprintf(stderr, "Signal: usage: repacdcli athX get_signal \n");
    fprintf(stderr, "get station status: usage: repacdcli athx get_sta_link \n");
    fprintf(stderr, "Is interface up: usage: repacdcli athx is_interface_up \n");
    fprintf(stderr, "Freq: usage: repacdcli athx get_freq_type \n");
    fprintf(stderr, "Get all interface freq: usage: repacdcli athx get_all_freq\n");
    fprintf(stderr, "Get 2g ap interface name: usage: repacdcli athx get_2g_ap\n");
    fprintf(stderr, "ESSID: usage: repacdcli athx get_essid \n");
}

int main(int argc, char **argv)
{
    int ret;
    const char *ifname, *cmd;

    ifname = argv[1];
    cmd = argv[2];

    if((argc < 3) || (argc > 3))
    {
        usage();
        return 0;
    }

    cfg80211_ctx = malloc(sizeof(wifi_cfg80211_context));
    if (!cfg80211_ctx) {
       // printf("Memmory allocation failed\n");
        return 0;
    }
    ret = wifi_init(cfg80211_ctx);
    if (ret != 0) {
        //printf("Socket creation failed \n");
        return 0;
    }

    if (streq(cmd, "get_bitrate")) {
        get_bitrate(ifname,0);
    } else if (streq(cmd, "get_bitrate_unit")) {
        get_bitrate(ifname,1);
    } else if (streq(cmd, "get_signal")) {
        get_signal(ifname);
    } else if (streq(cmd, "get_sta_link")) {
        get_bssid(ifname);
    } else if (streq(cmd, "is_interface_up")) {
        is_interface_up(ifname);
    } else if (streq(cmd, "get_all_freq")) {
        getName_all(GET_ALL_INTERFACE_FREQUENCY);
    } else if (streq(cmd, "get_2g_ap")) {
        getName_all(GET_ALL_2G_INTERFACE);
    } else if (streq(cmd, "get_freq_type")) {
        get_freq(ifname);
    } else if (streq(cmd, "get_essid")) {
        get_essid(ifname);
    } else {
        usage();
    }

    wifi_deinit(cfg80211_ctx);
    return 0;
}

