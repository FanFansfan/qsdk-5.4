/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>

#include "wlanif_cmn.h"

#ifdef SON_MEMORY_DEBUG

#include "qca-son-mem-debug.h"
#define QCA_MOD_INPUT QCA_MOD_LIBWIFISONCFG
#include "son-mem-debug.h"

#endif /* SON_MEMORY_DEBUG */

/* Config init function to allocate and configure cfg80211*/
struct wlanif_config * wlanif_config_init(int pvt_cmd_sock_id,
                                          int pvt_event_sock_id)
{
    struct wlanif_config * wlanif = NULL;

    wlanif = (struct wlanif_config *) malloc(sizeof(struct wlanif_config));
    if(!wlanif)
    {
        fprintf(stderr, "Error: %s malloc failed\n",__func__);
        return NULL;
    }
#ifndef LIBCFG80211_SUPPORT
    fprintf(stderr, "Error: %s Library not compiled with CFG80211 \n",__func__);
#endif

    memset(wlanif, 0, sizeof(struct wlanif_config));

    wlanif->ctx =NULL;

    wlanif->pvt_cmd_sock_id = pvt_cmd_sock_id;
    wlanif->pvt_event_sock_id = pvt_event_sock_id;

    if ( wlanif_cfg80211_init(wlanif))
    {
        fprintf(stderr, "WLAN init ops failed\n");
        goto err;
    }
    return wlanif;
err:
    free(wlanif);
    return NULL;
}

/*Config deinit function*/
void wlanif_config_deinit(struct wlanif_config * wlanif)
{
    if(!wlanif) {
        return;
    }

    wlanif_cfg80211_deinit(wlanif);
    wlanif->ctx =NULL;
    free(wlanif);
}
