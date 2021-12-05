/*
* Copyright (c) 2011, 2018 Qualcomm Innovation Center, Inc.
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/

/*
 * Copyright (c) 2010, Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 *
 * cmac mic calculation function is copied from open source wireless-testing
 * project net/mac80211 tree.
 *
 */

/*
 * IEEE 802.11w PMF crypto support.
 */
#include "aes_gcm.h"
bool
ieee80211_is_pmf_enabled(struct ieee80211vap *vap,struct ieee80211_node *ni)
{

    bool status;
    status = wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj);
    return status;
}

bool
wlan_vap_is_pmf_enabled(wlan_if_t vaphandle)
{
    struct ieee80211vap      *vap = vaphandle;
    bool status;
    status = wlan_crypto_vdev_is_pmf_enabled(vap->vdev_obj);
    return status;
}

bool ieee80211_is_pmf_frame(qdf_nbuf_t wbuf)
{
    int type = -1, subtype = -1;
    struct ieee80211_frame *wh;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if((type == IEEE80211_FC0_TYPE_MGT)
          && ((subtype == IEEE80211_FC0_SUBTYPE_DEAUTH)
             || (subtype == IEEE80211_FC0_SUBTYPE_DISASSOC)
             || ((subtype == IEEE80211_FC0_SUBTYPE_ACTION) &&
             ieee80211_is_robust_action_frame(*((uint8_t *)(wh+1)))))) {
          return true;
   }
   return false;
}

void
wlan_crypto_set_hwmfpQos(struct ieee80211vap *vap, u_int32_t dot11w)
{
    struct ieee80211com *ic = vap->iv_ic;
    ic->ic_set_hwmfpQos(ic->ic_pdev_obj, dot11w);
}

