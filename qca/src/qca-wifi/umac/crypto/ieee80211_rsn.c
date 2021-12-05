/*
 * Copyright (c) 2011-2018, 2020-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c)2008 Atheros Communications Inc.
 * All Rights Reserved.

 */

#include <osdep.h>

#include <ieee80211_var.h>
#include <ieee80211_api.h>
#if UNIFIED_SMARTANTENNA
#include <wlan_sa_api_utils_api.h>
#endif
#include <wlan_son_pub.h>

#include <wlan_cmn.h>
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_objmgr_vdev_obj.h>
#include <wlan_objmgr_peer_obj.h>

#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"
#include <wlan_mlme_dp_dispatcher.h>
#include <wlan_vdev_mlme.h>

#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
extern int wlan_update_rawsim_config(struct ieee80211vap *vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */

bool ieee80211_auth_mode_needs_upper_auth( struct ieee80211vap *vap )
{
    int32_t authmode;

    authmode = IEEE80211_AUTH_OPEN;
    authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
    if ( authmode == -1 ) {
        qdf_err("%s: crypto_err while getting authmode params\n",__func__);
        return -1;
    }

    return ( ( vap->iv_wps_mode )  ||  ( !(authmode & (uint32_t)((1 << IEEE80211_AUTH_OPEN))) && !(authmode & (uint32_t)((1 << IEEE80211_AUTH_NONE)))  && !(authmode & (uint32_t)((1 << IEEE80211_AUTH_SHARED)))) );
}

/*
 * NB: Atheros hw keep the cipher algo in the key cache, so we assoc the cipher
 * algo with each key as it is plumbed.  As a result, we do very little here.
 */
int
wlan_set_ucast_ciphers(wlan_if_t vaphandle, ieee80211_cipher_type types[], u_int len)
{
    struct ieee80211vap *vap = vaphandle;
    int i;
    uint32_t value = 0;
    wlan_crypto_cipher_type cipher;

    for (i = 0; i < len; i++) {
        cipher = (wlan_crypto_cipher_type)types[i];
        if (cipher == WLAN_CRYPTO_CIPHER_NONE) {
            return -EINVAL;
        }
        value |= (1 << cipher);
    }
    wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_UCAST_CIPHER, value);
    IEEE80211_VAP_PRIVACY_ENABLE(vap);
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    return 0;
}

int
wlan_set_mcast_ciphers(wlan_if_t vaphandle, ieee80211_cipher_type types[], u_int len)
{
    struct ieee80211vap *vap = vaphandle;
    int i;
    wlan_crypto_cipher_type cipher;
    uint32_t value = 0;
    for (i = 0; i < len; i++) {
        cipher = (wlan_crypto_cipher_type)types[i];
        if (cipher == WLAN_CRYPTO_CIPHER_NONE) {
            return -EINVAL;
        }
        value |= (1 << cipher);
    }

    wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_MCAST_CIPHER, value);
    return 0;
}


int
wlan_set_key(wlan_if_t vaphandle, u_int16_t keyix, ieee80211_keyval *key)
{
    struct ieee80211vap *vap = vaphandle;
    int status = -1;

    struct wlan_crypto_req_key req_key;

    qdf_mem_zero(&req_key, sizeof(struct wlan_crypto_req_key));
    req_key.type   = key->keytype;
    if(vap->iv_opmode == IEEE80211_M_MONITOR) {
       req_key.flags  = IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV | IEEE80211_KEY_SWCRYPT;
       qdf_mem_copy(vap->mcast_encrypt_addr,key->macaddr,QDF_MAC_ADDR_SIZE);
    }
    else {
       req_key.flags  = IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV;
    }

    req_key.keylen = key->keylen;
    req_key.keyrsc = key->keyrsc;
    req_key.keytsc = key->keytsc;
    req_key.keyix  = keyix;

    if (key->keylen > (sizeof(req_key.keydata)))
        return status;

    qdf_mem_copy(req_key.macaddr, key->macaddr, QDF_MAC_ADDR_SIZE);
    qdf_mem_copy(req_key.keydata, key->keydata, key->keylen);

    if ( req_key.type == IEEE80211_CIPHER_WEP ) {
        int32_t ucast_cipher;
        ucast_cipher = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_UCAST_CIPHER);
        if ( ucast_cipher == -1 ) {
            qdf_err("crypto_err while getting ucast_cipher params\n");
            return -1;
        }

        if ( (ucast_cipher & (1<<WLAN_CRYPTO_CIPHER_NONE)) ) {
            wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_MCAST_CIPHER,(1 << WLAN_CRYPTO_CIPHER_WEP));
            wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_UCAST_CIPHER,(1 << WLAN_CRYPTO_CIPHER_WEP));
	}
    }
    status = ((int)wlan_crypto_setkey(vap->vdev_obj, &req_key));

    /* Zero-out local key variables */
    qdf_mem_zero(&req_key, sizeof(struct wlan_crypto_req_key));
    return status;
}

int
wlan_set_default_keyid(wlan_if_t vaphandle, u_int keyix)
{
    struct ieee80211vap *vap = vaphandle;
    uint8_t macaddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
                      "%s: Default keyID = %d\n", __func__, keyix);

    wlan_crypto_default_key(vap->vdev_obj, macaddr, keyix, 0);
    return 0;
}

u_int16_t
wlan_get_default_keyid(wlan_if_t vaphandle)
{
        return IEEE80211_KEYIX_NONE;
}

int
wlan_get_key(wlan_if_t vaphandle, u_int16_t keyix, u_int8_t *macaddr,
             ieee80211_keyval *kval, u_int16_t keybuf_len,
             u_int8_t get_pn_flag)
{
    struct ieee80211vap *vap = vaphandle;
    int error = 0;
    struct wlan_crypto_req_key req_key;

    if(!kval->keydata)
        return -1;

    qdf_mem_zero((uint8_t*)&req_key, sizeof(req_key));
    req_key.keyix = keyix;
    if (get_pn_flag == GET_PN_ENABLE)
        req_key.flags |= WLAN_CRYPTO_KEY_GET_PN;

    error = wlan_crypto_getkey(vap->vdev_obj, &req_key, macaddr);
    if (error)
        return error;

    if (keybuf_len < req_key.keylen)
	return -1;
    kval->keytype  = req_key.type;
    kval->keydir   = (req_key.flags & (IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV));
    kval->keylen   = req_key.keylen;
    kval->keyrsc   = req_key.keyrsc;
    kval->keytsc   = req_key.keytsc;
    kval->macaddr  = macaddr;
#if ATH_SUPPORT_WAPI
    qdf_mem_copy(kval->txiv, req_key.txiv, IEEE80211_WAPI_IV_SIZE);
    qdf_mem_copy(kval->recviv, req_key.recviv, IEEE80211_WAPI_IV_SIZE);
#endif
    qdf_mem_copy(kval->keydata, req_key.keydata, kval->keylen);

    /* Zero-out local key variables */
    qdf_mem_zero(&req_key, sizeof(struct wlan_crypto_req_key));
    return error;
}

int
wlan_del_key(wlan_if_t vaphandle, u_int16_t keyix, u_int8_t *macaddr)
{
    struct ieee80211vap *vap = vaphandle;
    if (keyix == IEEE80211_KEYIX_NONE)
        keyix = 0;
    return wlan_crypto_delkey(vap->vdev_obj, macaddr, keyix);
}

int
ieee80211_del_key(wlan_if_t vaphandle, int32_t authmode, u_int16_t keyix, u_int8_t *macaddr)
{
    struct ieee80211vap *vap = vaphandle;
    authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
    if ( authmode == -1 ) {
        qdf_err("crypto_err while getting authmode params\n");
        return -1;
    }

    if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_OPEN) | (1 << WLAN_CRYPTO_AUTH_SHARED) | (1 << WLAN_CRYPTO_AUTH_SHARED))) {
        return 0;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"DELETE CRYPTO KEY index %d, addr %s\n",
                    keyix, ether_sprintf(macaddr));
    if (keyix == KEYIX_INVALID) {
        return wlan_del_key(vap,IEEE80211_KEYIX_NONE,macaddr);
    } else {
        return wlan_del_key(vap,keyix,macaddr);
    }
}


int
wlan_set_privacy_filters(wlan_if_t vaphandle, ieee80211_privacy_exemption *filters, u_int32_t num_filters)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int i;

    if (num_filters > IEEE80211_MAX_PRIVACY_FILTERS)
        return -EOVERFLOW;

    /* clear out old list first */
    OS_MEMZERO(vap->iv_privacy_filters,
               IEEE80211_MAX_PRIVACY_FILTERS * sizeof(ieee80211_privacy_exemption));

    for (i = 0; i < num_filters; i++) {
        vap->iv_privacy_filters[i] = filters[i];
    }

    vap->iv_num_privacy_filters = num_filters;

    wlan_vdev_set_privacy_filters(vap->vdev_obj, vap->iv_privacy_filters, vap->iv_num_privacy_filters);

    if (ic && ic->ic_set_privacy_filters) {
        ic->ic_set_privacy_filters(vap);
    }
    return 0;
}

int
wlan_get_privacy_filters(wlan_if_t vaphandle, ieee80211_privacy_exemption *filters, u_int32_t *num_filters, u_int32_t len)
{
    struct ieee80211vap *vap = vaphandle;
    int i;

    if (vap->iv_num_privacy_filters == 0) {
        *num_filters = 0;
        return 0;
    }

    /* check if the passed-in buffer has enough space to hold the entire list. */
    if (len < vap->iv_num_privacy_filters) {
        *num_filters = vap->iv_num_privacy_filters;
        return -EOVERFLOW;
    }

    for (i = 0; i < vap->iv_num_privacy_filters; i++) {
        filters[i] = vap->iv_privacy_filters[i];
    }
    *num_filters = vap->iv_num_privacy_filters;
    return 0;
}

int
wlan_node_authorize(wlan_if_t vaphandle, int authorize, u_int8_t *macaddr)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_node *ni=NULL;
#if QCA_SUPPORT_SON
    struct son_ald_assoc_event_info info;
#endif

    ni = ieee80211_vap_find_node(vap, macaddr, WLAN_MLME_SB_ID);
    if (ni == NULL)
        return -EINVAL;

    if (ni->ni_vap != vaphandle) {
        ieee80211_free_node(ni, WLAN_MLME_SB_ID);
        return -EINVAL;
    }

    if (authorize){
    /* SON events are not expected on the STA VAP,
     * Check if vap is not STA VAP, before notifiying events to SON
     */
    if (vap->iv_opmode == IEEE80211_M_HOSTAP || \
        vap->iv_opmode == IEEE80211_M_BTAMP || \
        vap->iv_opmode == IEEE80211_M_IBSS) {

#if QCA_SUPPORT_SON
	    wlan_acl_apply_node_snr_thresholds(vap, macaddr);
        son_update_mlme_event(vap->vdev_obj, ni->peer_obj, SON_EVENT_BSTEERING_NODE_ASSOCIATED, NULL);
        qdf_mem_zero(&info, sizeof(info));
        qdf_mem_copy(info.macaddr, macaddr, QDF_MAC_ADDR_SIZE);
        info.flag = ALD_ACTION_ASSOC;
        info.reason = ni->ni_assocstatus;
        son_update_mlme_event(vap->vdev_obj, NULL, SON_EVENT_ALD_ASSOC, &info);
#endif

#if ATH_PARAMETER_API
        ieee80211_papi_send_assoc_event(vap, ni, PAPI_STA_ASSOCIATION);
#endif
    }

        ieee80211_node_authorize(ni);
    }
    else {
        ieee80211_node_unauthorize(ni);
    }

    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
    return 0;
}

int
wlan_set_pmkid_list(wlan_if_t vaphandle, ieee80211_pmkid_entry *pmkids, u_int16_t num)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_aplist_config *pconfig = ieee80211_vap_get_aplist_config(vap);
    u_int16_t npmkid = 0;
    int i, j;

    if (num > IEEE80211_MAX_PMKID || num < 1)
        return -EOVERFLOW;

    /* clear out old list first */
    OS_MEMZERO(vap->iv_pmkid_list,
               IEEE80211_MAX_PMKID * sizeof(ieee80211_pmkid_entry));

    for (i = 0; i < num; i++) {
        /*
         * Make sure all BSSID specified in the list are in our desired BSSID list.
         */
        if (!ieee80211_aplist_get_accept_any_bssid(pconfig)) {
            for (j = 0; j < ieee80211_aplist_get_desired_bssid_count(pconfig); j++) {
                u_int8_t *bssid = NULL;

                ieee80211_aplist_get_desired_bssid(pconfig, j, &bssid);

                if ((bssid != NULL) && (IEEE80211_ADDR_EQ(pmkids[i].bssid, bssid)))
                    break;
            }

            if (j == ieee80211_aplist_get_desired_bssid_count(pconfig))
                continue;       /* doesn't match any desired BSSID */
        }

        vap->iv_pmkid_list[npmkid++] = pmkids[i];
    }

    vap->iv_pmkid_count = npmkid;
    return 0;
}

int
wlan_get_pmkid_list(wlan_if_t vaphandle, ieee80211_pmkid_entry *pmkids, u_int16_t *count, u_int16_t len)
{
    struct ieee80211vap *vap = vaphandle;
    int i;

    if (vap->iv_pmkid_count == 0) {
        *count = 0;
        return 0;
    }

    /* check if the passed-in buffer has enough space to hold the entire list. */
    if (len < vap->iv_pmkid_count) {
        *count = vap->iv_pmkid_count;
        return -EOVERFLOW;
    }

    for (i = 0; i < vap->iv_pmkid_count; i++) {
        pmkids[i] = vap->iv_pmkid_list[i];
    }
    *count = vap->iv_pmkid_count;
    return 0;
}

u_int8_t *ieee80211_rsnx_override(u_int8_t *ie, struct ieee80211vap *vap)
{
    struct ieee80211_rsnx_ie *rsnx_ie = (struct ieee80211_rsnx_ie *)ie;
    if (!rsnx_ie)
        return ie;

    rsnx_ie->element_id = IEEE80211_ELEMID_RSNX;
    rsnx_ie->rsnx_list[0] = (uint8_t)vap->iv_rsnx_override;
    rsnx_ie->len = 1;

    return (uint8_t*)(rsnx_ie + 1) + rsnx_ie->len;
}

