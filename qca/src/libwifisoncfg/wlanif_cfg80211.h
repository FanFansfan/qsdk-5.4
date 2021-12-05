/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef _CFG80211_NL_H
#define _CFG80211_NL_H

#include "wlanif_cmn.h"
#include "nl80211_copy.h"
#include "cfg80211_nlwrapper_pvt.h"
#include "qca-vendor.h"
#include "ieee80211_ioctl.h"
#include <dbg.h>

extern int finish_handler(struct nl_msg *msg, void *arg);
extern int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
extern int valid_handler(struct nl_msg *msg, void *arg);
extern int ack_handler(struct nl_msg *msg, void *arg);

#define MAX_CMD_LEN 128
static const unsigned NL80211_ATTR_MAX_INTERNAL = 256;
#define WIRELESS_EXT (22)

struct wdev_info {
    enum nl80211_iftype nlmode;
    char name[IFNAMSIZ];
};

struct wlanif_cfg80211_cmn {
    struct nl_sock *gen_sock;
    int drv_id;
};

/* For debugging support */
struct soncfgDbg_t {
    struct dbgModule *dbgModule;
} soncfgDbgS;

/*Structure for private and public ioctls*/
struct wlanif_cfg80211_priv {
    /* QCA Context for all vendor specfic nl80211 message */
    wifi_cfg80211_context cfg80211_ctx_qca;
    /* Generic nl80211 context */
    struct wlanif_cfg80211_cmn cfg80211_ctx_cmn;
};

struct socket_context {
    u_int8_t cfg80211; /* cfg80211 enable flag */

    wifi_cfg80211_context cfg80211_ctxt; /* cfg80211 context */

    int sock_fd; /* wext socket file descriptor */
};

/**
 * @brief Populated to send radar event to driver.
 */
struct radarhandler {
    int s;
    struct ath_diag atd;
    struct socket_context sock_ctx;
};

typedef enum config_mode_type {
    CONFIG_IOCTL    = 0, /* driver config mode is WEXT */
    CONFIG_CFG80211 = 1, /* driver config mode is cfg80211 */
    CONFIG_INVALID  = 2, /* invalid driver config mode */
} config_mode_type;

#endif
