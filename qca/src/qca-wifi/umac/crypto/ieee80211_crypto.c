/*
 * Copyright (c) 2018 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 *
 */

#include <osdep.h>

#include <ieee80211_var.h>
#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif


void
ieee80211_notify_replay_failure(struct ieee80211vap *vap,
                                const struct ieee80211_frame *wh,
                                const struct wlan_crypto_key *key, u_int64_t rsc)
{
    IEEE80211_DELIVER_EVENT_REPLAY_FAILURE(vap,(const u_int8_t *)wh, key->keyix);
}


void
ieee80211_notify_michael_failure(struct ieee80211vap *vap,
        const uint8_t *ta_mac_addr, u_int keyix)
{
    IEEE80211_DELIVER_EVENT_MIC_FAILURE(vap, ta_mac_addr, keyix);
}
