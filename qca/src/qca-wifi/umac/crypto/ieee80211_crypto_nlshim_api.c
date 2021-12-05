/*
 * Copyright (c) 2016-2019,2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#if UMAC_SUPPORT_CFG80211

#include <osif_private.h>
#include <ieee80211_defines.h>
#include <ieee80211_var.h>
#include <ol_if_athvar.h>
#include <ol_ath_ucfg.h>
#include <ieee80211_ucfg.h>
#include "ieee80211_crypto_nlshim_api.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#include <osif_nss_wifiol_if.h>
#endif

#define RSNX_H2E_ENABLED 0x20
#define RSNX_SAE_PK_ENABLED 0x40
#define KEYMGMT_6G_MASK 0xFF0E00

/**
 * wlan_cfg80211_get_ie_ptr
 * @ies_ptr:  Pointer to beacon buffer
 * @length: Length of Beacon buffer
 * @eid: Element ID of IE to return
 */

uint8_t *wlan_cfg80211_get_ie_ptr(struct ieee80211vap *vap,const uint8_t *ies_ptr, int tail_len,
	uint8_t eid)
{
    int length = tail_len;
    uint8_t *ptr = (uint8_t *)ies_ptr;
    uint8_t elem_id, elem_len;

    while (length >= 2) {
        elem_id = ptr[0];
        elem_len = ptr[1];
        length -= 2;
        if (elem_len > length) {
            qdf_print("Invalid IEs eid = %d elem_len=%d left=%d",
                    eid, elem_len, length);
            return NULL;
        }
        if (!eid && !is_hostie(ptr,IE_LEN(ptr))) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CFG80211, "%s: Adding elementID: %d \n",
                              __func__, elem_id);
            wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_BEACON,ptr,IE_LEN(ptr), HOSTAPD_IE);
            wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_PROBERESP,ptr,IE_LEN(ptr), HOSTAPD_IE);
            vap->appie_buf_updated = 1;
        } else if  (elem_id == eid) {
            return ptr;
        }

        length -= elem_len;
        ptr += (elem_len + 2);
    }
    return NULL;
}

bool wlan_cfg80211_vap_is_open(struct cfg80211_ap_settings *params,struct net_device *dev) {

    struct cfg80211_crypto_settings *crypto_params = &(params->crypto);

    if ((crypto_params->n_ciphers_pairwise == 0) && (crypto_params->cipher_group == 0) &&
        (crypto_params->n_akm_suites == 0))
            return true;

    return false;
}

int  wlan_cfg80211_crypto_setting(struct net_device *dev,
                                  struct cfg80211_crypto_settings *params,
                                  enum nl80211_auth_type  auth_type)
{
    int error = -ENOTSUPP;
    u_int8_t i =0;
    unsigned int args[10] = {0,0,0};
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int32_t value=0;
    u_int32_t cipher=0;
    u_int32_t authmode=0;
    u_int32_t key_mgmt=0;
    u_int8_t ret_val = 0;

    /* group key cipher  IEEE80211_PARAM_MCASTCIPHER */

    switch (params->cipher_group) {
        case WLAN_CIPHER_SUITE_WEP40:
        case WLAN_CIPHER_SUITE_WEP104:
            cipher = IEEE80211_CIPHER_WEP ;
            break;

        case  WLAN_CIPHER_SUITE_TKIP:
            if (vap->iv_6g_comp &&
                    IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
                qdf_err("WPA (TKIP) not allowed for non-transmitting "
                         "MBSS VAP (id %d)!", vap->iv_unit);
                return error;
            }

            cipher = IEEE80211_CIPHER_TKIP ;
            break;

        case WLAN_CIPHER_SUITE_GCMP:
            cipher = IEEE80211_CIPHER_AES_GCM;
            break;

        case WLAN_CIPHER_SUITE_GCMP_256:
            cipher = IEEE80211_CIPHER_AES_GCM_256;
            break;

        case WLAN_CIPHER_SUITE_CCMP:
            cipher = IEEE80211_CIPHER_AES_CCM;
            break;

        case WLAN_CIPHER_SUITE_CCMP_256:
            cipher = IEEE80211_CIPHER_AES_CCM_256;
            break;

        case WLAN_CIPHER_SUITE_SMS4:
            cipher = IEEE80211_CIPHER_WAPI;
            authmode = IEEE80211_AUTH_WAPI;
            break;

        default :
            cipher  = IEEE80211_CIPHER_NONE;
            authmode = (1 << WLAN_CRYPTO_AUTH_OPEN);
            break;

    }

    if ( auth_type == NL80211_AUTHTYPE_SHARED_KEY )
        authmode = (1 << WLAN_CRYPTO_AUTH_SHARED);
    if ( auth_type == NL80211_AUTHTYPE_AUTOMATIC )
        authmode = ((1 << WLAN_CRYPTO_AUTH_SHARED) | (1 << WLAN_CRYPTO_AUTH_OPEN));
    if ( auth_type == NL80211_AUTHTYPE_OPEN_SYSTEM )
        authmode = (1 << WLAN_CRYPTO_AUTH_OPEN);

    if ( cipher  == IEEE80211_CIPHER_WEP) {
        /* key length is done only for specific ciphers */
        if (params->control_port_no_encrypt)
            authmode = (1 << WLAN_CRYPTO_AUTH_8021X);
        else {
            ieee80211_ucfg_setparam(vap,IEEE80211_PARAM_UCASTCIPHERS,1 << cipher,(char*)args);
            ieee80211_ucfg_setparam(vap,IEEE80211_PARAM_MCASTCIPHER,cipher,(char*)args);
            value = (params->cipher_group == WLAN_CIPHER_SUITE_WEP104 ? 13 : 5);
            error = ieee80211_ucfg_setparam(vap,IEEE80211_PARAM_MCASTKEYLEN,value,(char*)args);
            if (error) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,"Unable to set group key length to %u\n", value);
            }
        }
     } else {
        ieee80211_ucfg_setparam(vap,IEEE80211_PARAM_MCASTCIPHER,cipher,(char*)args);
     }

    value = 0;

/* pairwise key ciphers  IEEE80211_PARAM_UCASTCIPHERS*/
    for( i = 0;i < params->n_ciphers_pairwise ; i++) {
        switch(params->ciphers_pairwise[i]) {
            case WLAN_CIPHER_SUITE_TKIP:
                value |= 1<<IEEE80211_CIPHER_TKIP;
                break;

	    case  WLAN_CIPHER_SUITE_CCMP:
                value |= 1<<IEEE80211_CIPHER_AES_CCM;
                break;

            case WLAN_CIPHER_SUITE_CCMP_256:
                value |= 1<<IEEE80211_CIPHER_AES_CCM_256;
                break;

            case WLAN_CIPHER_SUITE_GCMP:
                value |= 1<<IEEE80211_CIPHER_AES_GCM;
                break;  

            case  WLAN_CIPHER_SUITE_GCMP_256:
                value |= 1<<IEEE80211_CIPHER_AES_GCM_256;
                break;

            case WLAN_CIPHER_SUITE_WEP104:
            case WLAN_CIPHER_SUITE_WEP40:
                value |= 1<<IEEE80211_CIPHER_WEP;
                break;

            case WLAN_CIPHER_SUITE_SMS4:
                value |= 1<<IEEE80211_CIPHER_WAPI;
                break;

            default:
                break;
        }
    }
    if(params->n_ciphers_pairwise)
        ieee80211_ucfg_setparam(vap,IEEE80211_PARAM_UCASTCIPHERS,value,(char*)args);
    else
        ret_val = 1;

/*key management algorithms IEEE80211_PARAM_KEYMGTALGS */

    if (params->n_akm_suites)
        authmode = 0;

    for (i = 0; i < params->n_akm_suites; i++) {
    /* AKM suite selectors */
        switch(params->akm_suites[i] ) {
            case WLAN_AKM_SUITE_PSK:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_PSK);
                 /* set the authmode type to WPA if we use mixed or WPA1 security type
                    and is not required for WPA2 security types */
                 if ((params->wpa_versions == 1) || (params->wpa_versions == 3))
                     authmode |= (1 << WLAN_CRYPTO_AUTH_WPA);
                 if ((params->wpa_versions > 1))
                     authmode |= (1 << WLAN_CRYPTO_AUTH_RSNA);
                 break;
            case WLAN_AKM_SUITE_FT_8021X:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_FT_IEEE8021X);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_8021X);
                 break;
            case WLAN_AKM_SUITE_FT_PSK:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_FT_PSK);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_RSNA);
                 break;
            case WLAN_AKM_SUITE_8021X_SHA256:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_IEEE8021X_SHA256);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_8021X);
                 break;
            case WLAN_AKM_SUITE_PSK_SHA256:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_PSK_SHA256);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_RSNA);
                 break;
            case WLAN_AKM_SUITE_8021X_SUITE_B:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_IEEE8021X_SUITE_B);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_8021X);
                 break;
            case WLAN_AKM_SUITE_8021X_SUITE_B_192:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_IEEE8021X_SUITE_B_192);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_8021X);
                 break;
            case WLAN_AKM_SUITE_CCKM:
            case WLAN_AKM_SUITE_OSEN:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_IEEE8021X);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_8021X);
                 break;
            case WLAN_AKM_SUITE_OWE:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_OWE);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_RSNA);
                 break;
            case WLAN_AKM_SUITE_SAE:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_SAE);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_RSNA);
                 break;
            case WLAN_AKM_SUITE_FT_OVER_SAE:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_FT_SAE);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_RSNA);
                 break;
            case WLAN_AKM_SUITE_DPP:
                 key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_DPP);
                 authmode |= (1 << WLAN_CRYPTO_AUTH_RSNA);
                 break;
            default:
                key_mgmt |= (1 << WLAN_CRYPTO_KEY_MGMT_NONE);
                break;
        }
    }

    if (params->n_akm_suites)
        wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_KEY_MGMT, key_mgmt);

    wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE, authmode);


  return ret_val;
}



int wlan_set_beacon_ies(struct  net_device *dev, struct cfg80211_beacon_data *beacon)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    u_int8_t *rsn_ie = NULL;
    u_int8_t *wpa_ie = NULL;
    u_int8_t *ptr = (u_int8_t *)beacon->tail;
    u_int8_t *xrates_ie = NULL;
    u_int8_t *rates_ie = NULL;
    u_int8_t *rsnxe_ie  = NULL;
    int i = 0;
    struct wlan_crypto_params crypto_params = {0} ;
    int status = IEEE80211_STATUS_SUCCESS;
    unsigned int args[2] = {0,0};
    int ret = EOK;
    vap->iv_sae_pwe = SAE_PWE_LOOP;

    /* Remove previous hostapd IE for dynamic security mode to open mode */
    if (vap->vie_handle) {
         wlan_mlme_app_ie_delete_id(vap->vie_handle,IEEE80211_FRAME_TYPE_BEACON,HOSTAPD_IE);
         wlan_mlme_app_ie_delete_id(vap->vie_handle,IEEE80211_FRAME_TYPE_PROBERESP,HOSTAPD_IE);
         wlan_mlme_app_ie_delete_id(vap->vie_handle,IEEE80211_FRAME_TYPE_ASSOCRESP,HOSTAPD_IE);
         vap->appie_buf_updated = 1;
     }

    if(beacon->tail_len) {
        wlan_cfg80211_get_ie_ptr(vap,beacon->tail, beacon->tail_len,0);
    }
    /*
     * beacon->tail IEs has generic IEs like
     * HTCAP, VHTCAP, WMM etc. for these generic IEs driver will generate
     * them and add to beacons.
     * beacon_ies from Hostpad contains
     * WLAN_EID_EXT_CAPAB
     * WLAN_EID_INTERWORKING
     * WLAN_EID_ADV_PROTO
     * WLAN_EID_ROAMING_CONSORTIUM
     * fst_ies, wps_beacon_ie, hostapd_eid_hs20_indication, vendor_elements
     * we will append these IEs in app_ies.
     *
     */
    if (beacon->beacon_ies_len) {
        ret = wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_BEACON,beacon->beacon_ies,beacon->beacon_ies_len, HOSTAPD_IE);
        if (ret)
            return ret;

        if (beacon->beacon_ies_len && iswpsoui(beacon->beacon_ies)) {
            wlan_set_param(vap,IEEE80211_WPS_MODE,1);
        } else if(( beacon->beacon_ies_len == 0) && vap->iv_wps_mode) {
            wlan_set_param(vap,IEEE80211_WPS_MODE,0);
        }
        vap->appie_buf_updated = 1;
    }

    if (beacon->proberesp_ies_len) {
        ret = wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_PROBERESP,beacon->proberesp_ies,beacon->proberesp_ies_len, HOSTAPD_IE);
        if (ret)
            return ret;

        vap->appie_buf_updated = 1;
    }

    if (beacon->assocresp_ies_len) {
        ret = wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_ASSOCRESP,beacon->assocresp_ies,beacon->assocresp_ies_len, HOSTAPD_IE);
        if (ret)
            return ret;

        vap->appie_buf_updated = 1;
    }

    while (((ptr + 1) < (u_int8_t *)beacon->tail + beacon->tail_len) && (ptr + ptr[1] + 1 < (u_int8_t *)beacon->tail + beacon->tail_len)) {
        if (ptr[0] == WLAN_ELEMID_RSN && ptr[1] >= 20 ){
            rsn_ie = ptr;
        } else if (ptr[0] == WLAN_ELEMID_VENDOR && iswpaoui(ptr) ){
            wpa_ie = ptr;
        } else if (ptr[0] == WLAN_ELEMID_RATES) {
            rates_ie = ptr;
        } else if (ptr[0] == WLAN_ELEMID_XRATES) {
            xrates_ie = ptr;
        } else if (ptr[0] == WLAN_ELEMID_RSNXE) {
            rsnxe_ie = ptr;
        }

        ptr += ptr[1] + 2;
    }

    if (xrates_ie || rates_ie) {
        u_int8_t len = 0;
        if (xrates_ie) {
            len = xrates_ie[1];
            ptr = xrates_ie + 2;
        } else {
            len = rates_ie[1];
            ptr = rates_ie + 2;
        }
        for (i = 0; i < len; i++) {
            if (*ptr == (0x80 | IEEE80211_BSS_MEMBERSHIP_SELECTOR_SAE_H2E_ONLY)) {
                vap->iv_sae_pwe = SAE_PWE_H2E;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,"sae_pwe:  %d \n", vap->iv_sae_pwe);
                break;
            }
            ptr++;
        }
    }

    if (!vap->iv_sae_pwe && rsnxe_ie != NULL) {
        ptr = rsnxe_ie + 2;

        if (*ptr & RSNX_H2E_ENABLED)
            vap->iv_sae_pwe = SAE_PWE_LOOP_H2E;
    }

    if (rsnxe_ie != NULL) {
        ptr = rsnxe_ie + 2;

        if (*ptr & RSNX_SAE_PK_ENABLED)
            vap->iv_sae_pk_en = SAE_PK_ENABLE;
    }

    if (wpa_ie != NULL)
    {
        status = wlan_crypto_wpaie_check((struct wlan_crypto_params *)&crypto_params, wpa_ie);
        if (status != QDF_STATUS_SUCCESS) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,"wpa ie unavailable\n");
        }
    }

    if (rsn_ie != NULL)
    {
        status = wlan_crypto_rsnie_check((struct wlan_crypto_params *)&crypto_params, rsn_ie);
        if (status != QDF_STATUS_SUCCESS) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,"rsn ie unavailable\n");
        }
    }

    if ((!wpa_ie && !rsn_ie) || status != QDF_STATUS_SUCCESS)
        crypto_params.rsn_caps = 0;
    ieee80211_ucfg_setparam(vap,IEEE80211_PARAM_RSNCAPS, crypto_params.rsn_caps ,(char*)args);

    return ret;
}

int wlan_6ghz_security_check(wlan_if_t vap,
                             int key_mgmt, uint16_t rsn_caps)
{
    int ret = EOK;
    int is_set_wps = (vap->iv_keymgmt_6g_mask & (1 << WLAN_CRYPTO_KEY_MGMT_WPS));

    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    bool is_ema_ap_enabled  = wlan_pdev_nif_feat_ext_cap_get(vap->iv_ic->ic_pdev_obj,
                                                   WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    if (vap->iv_6g_comp == 1) {
        if (!(vap->iv_opmode == IEEE80211_M_STA && vap->iv_is_6g_wps)) {
            if ((key_mgmt & KEYMGMT_6G_MASK) != key_mgmt ) {
                ret = -EINVAL;
            }
            /* on 6GHz STA cant Associate to H&P AP, so limiting to H2E usage only*/
            if ((key_mgmt & (1 << WLAN_CRYPTO_KEY_MGMT_SAE)) && (vap->iv_sae_pwe != 1)) {
                ret = -EINVAL;
            }
            if (!(rsn_caps & WLAN_CRYPTO_RSN_CAP_MFP_REQUIRED)) {
                ret = -EINVAL;
            }
        }
    } else {
        /* SON Needs WPS & EMA to co-exist on 6GHz */
        if (is_ema_ap_enabled && vap->iv_is_6g_wps  &&
             !soc->ema_ap_support_wps_6ghz) {
            ret = -EINVAL;
        }

        /* Key Mgmt checks with the static key_mgmt bitmask */
        if (!(vap->iv_opmode == IEEE80211_M_STA && vap->iv_is_6g_wps && is_set_wps)) {
            if ( (key_mgmt & vap->iv_keymgmt_6g_mask) != key_mgmt ) {
                ret = -EINVAL;
            }

            if(!is_set_wps && vap->iv_is_6g_wps) {
                ret = -EINVAL;
            }
        }
    }
    return ret;
}

/**
 * wlan_cfg80211_6ghz_security_check() - Check the security configured for 6Ghz
 * @vap: Pointer to vap
 * Return: zero for success non-zero for failure
 */
int wlan_cfg80211_6ghz_security_check(wlan_if_t vap)
{
    int key_mgmt;
    int rsn_caps;

    key_mgmt = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_KEY_MGMT);
    rsn_caps = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_RSN_CAP);

    return wlan_6ghz_security_check(vap, key_mgmt, rsn_caps);
}

/*
 * wlan_cfg80211_mbssid_security_admission_control_sanity - Check security configuration in wideband channel change
 * @ic: Pointer to ic
 * Return: zero for success non-zero for failure
 */
int wlan_cfg80211_mbssid_security_admission_control_sanity(struct ieee80211com *ic, uint8_t check_6g_comp)
{

    struct ieee80211vap *tmpvap = NULL;
    int32_t tmp_ucast_cipher;
    bool is_wb_ema_ap_enabled = true;
    struct ieee80211vap *tx_vap = NULL;

    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;

    if(!IEEE80211_IS_CHAN_11AXA(ic->ic_curchan)) {
        qdf_err("Wide Band Channel change is only applicable for 11ax phymode");
        return -EINVAL;
    }

    tx_vap = ieee80211_ucfg_get_txvap(ic);
    if (!tx_vap) {
        return -EINVAL;
    }


    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if (ieee80211_mbss_is_beaconing_ap(tmpvap)) {

            /* A Wideband switch will be possible for a limited number of WPS AP's only */
            if(tmpvap->iv_is_6g_wps && is_wb_ema_ap_enabled
               && ( !soc->ema_ap_support_wps_6ghz ||
                   (ieee80211_get_num_beacon_ap_vaps(ic) > soc->ema_ap_num_max_vaps) )) {
                return -EINVAL;
            }

            tmp_ucast_cipher = wlan_crypto_get_param(tmpvap->vdev_obj, WLAN_CRYPTO_PARAM_UCAST_CIPHER);
            if( tmp_ucast_cipher == -1 ) {
                return -EINVAL;
            }

            /* TKIP is not allowed in Mission Mode (6GHz) for Tx/Non-Tx Vap's.
             * TKIP is allowed only in WFA Testbed AP mode for single Tx-vap
             * kind of scenario. In case of Wideband switch if Co-hosted Vap's
             * have TKIP in lower band then Wideband switch is restricted. */
            if(((tmp_ucast_cipher & (1<<WLAN_CRYPTO_CIPHER_TKIP)) && (tmpvap != tx_vap))) {
                qdf_err("In EMA TKIP is allowed only on Tx vap");
                return -EINVAL;
            }

            /* Perform the ieee80211ax Draft6.1 specific security validation for 6GHz*/
            if(check_6g_comp && (wlan_cfg80211_6ghz_security_check(tmpvap) != EOK)) {
                qdf_err("Error in 6GHz security compliance!!");
                return -EINVAL;
            }
        }

    }

    return EOK;
}
qdf_export_symbol(wlan_cfg80211_mbssid_security_admission_control_sanity);

/**
 * wlan_cfg80211_setcurity_init() -  Intialize the security parameters
 * @dev: Pointer to netdev
 * @params: Pointer to start ap configuration parameters
 * struct cfg80211_ap_settings - AP configuration
 * Return: zero for success non-zero for failure
 */
int wlan_cfg80211_security_init(struct cfg80211_ap_settings *params,struct net_device *dev)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    wlan_if_t vap = osifp->os_if;
    int ret = 0;

    ret = wlan_cfg80211_crypto_setting(dev,&(params->crypto), params->auth_type);
    if (ret < 0)
        return ret;

    ret = wlan_set_beacon_ies(dev,&(params->beacon));
    if (ret)
        return ret;

     /*set privacy */
    wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY,params->privacy);

    return ret;
}

static void wlan_cfg80211_set_groupkey_to_dp(wlan_if_t vap, uint16_t vlan_id, uint16_t groupkey)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    ol_txrx_soc_handle soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    if (!soc_txrx_handle)
        return;

    cdp_set_vlan_groupkey(soc_txrx_handle, wlan_vdev_get_id(vap->vdev_obj),
                          vlan_id, groupkey);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops) {
        osif_dev *osifp = (osif_dev *)vap->iv_ifp;
        ic->nss_vops->ic_osif_nss_vdev_set_group_key(osifp, vlan_id, groupkey);
    }
#endif
}

static int add_vlan(wlan_if_t vap,int vlan_id,int key_index)
{
    u16 *iv_vlan_map = vap->iv_vlan_map;
    int found = 0;
    int i=0;
    for (i = 0; i < (2 * MAX_VLAN); ) {
        if( !iv_vlan_map[i] && !iv_vlan_map[i+1]) {
            found =1 ;
            break;
        } else if (( iv_vlan_map[i] == vlan_id ) || ( iv_vlan_map[i+1] == vlan_id )){
            iv_vlan_map[i] = 0 ;
            iv_vlan_map[i+1] = 0 ;
            found =1 ;
            break;
        }
        i = i+2;
    }

    if(found) {
        iv_vlan_map[i+key_index-1] = vlan_id ;
        wlan_cfg80211_set_groupkey_to_dp(vap, vlan_id, i/2 + 1);
        return (i + key_index - 1 + 8);
    } else {
        qdf_err("Error with vlan index\n");
        return -1;
    }
}

/**
 * wlan_cfg80211_add_key() - cfg80211 add key handler function
 * @wiphy: Pointer to wiphy structure.
 * @dev: Pointer to net_device structure.
 * @key_index: key index
 * @pairwise: pairwise
 * @mac_addr: mac address
 * @params: key parameters
 *
 * Return: 0 for success, error number on failure.
 */

int wlan_cfg80211_add_key(struct wiphy *wiphy,
        struct net_device *ndev,
        u8 key_index, bool pairwise,
        const u8 *mac_addr,
        struct key_params *params)
{
    int error = -EOPNOTSUPP;
    osif_dev *osifp = ath_netdev_priv(ndev);
    wlan_if_t vap = osifp->os_if;
    ieee80211_keyval key_val;
    u_int8_t keydata[IEEE80211_KEYBUF_SIZE];

    qdf_mem_zero(&key_val, sizeof(ieee80211_keyval));

    switch (params->cipher) {
        case WLAN_CIPHER_SUITE_WEP40:
        case WLAN_CIPHER_SUITE_WEP104:
            key_val.keytype  = IEEE80211_CIPHER_WEP ;
            break;

        case  WLAN_CIPHER_SUITE_TKIP:
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
                     "%s: init. TKIP PN to 0x%x%x, tsc=0x%x%x.\n", __func__,
                     (u_int32_t)(key_val.keyrsc>>32), (u_int32_t)(key_val.keyrsc),
                     (u_int32_t)(key_val.keytsc>>32), (u_int32_t)(key_val.keytsc));

            key_val.keytype  = IEEE80211_CIPHER_TKIP;
            break;

        case WLAN_CIPHER_SUITE_CCMP:
            key_val.keytype  = IEEE80211_CIPHER_AES_CCM;
            break;

        case WLAN_CIPHER_SUITE_GCMP:
            key_val.keytype  = IEEE80211_CIPHER_AES_GCM;
            break;

        case WLAN_CIPHER_SUITE_CCMP_256:
            key_val.keytype  = IEEE80211_CIPHER_AES_CCM_256;
            break;

        case WLAN_CIPHER_SUITE_GCMP_256:
            key_val.keytype  = IEEE80211_CIPHER_AES_GCM_256;
            break;

        case WLAN_CIPHER_SUITE_AES_CMAC:
            key_val.keytype  = IEEE80211_CIPHER_AES_CMAC;
            break;

        case WLAN_CIPHER_SUITE_BIP_CMAC_256:
            key_val.keytype  = IEEE80211_CIPHER_AES_CMAC_256;
            break;

        case WLAN_CIPHER_SUITE_BIP_GMAC_128:
            key_val.keytype  = IEEE80211_CIPHER_AES_GMAC;
            break;

        case WLAN_CIPHER_SUITE_BIP_GMAC_256:
            key_val.keytype  = IEEE80211_CIPHER_AES_GMAC_256;
            break;
        case WLAN_CIPHER_SUITE_SMS4:
            key_val.keytype  = IEEE80211_CIPHER_WAPI;
            break;

        default :
            key_val.keytype  = IEEE80211_CIPHER_NONE;
            break;
    }


    if (osifp->os_opmode == IEEE80211_M_STA ) {
        /* wapi key type is excluded as it it handled handled in setup_wapi() for wapi*/
        if (params->seq_len > MAX_SEQ_LEN &&  (key_val.keytype  != IEEE80211_CIPHER_WAPI)) {
            return -EINVAL;
        }
#ifndef IEEE80211_KEY_GROUP
#define IEEE80211_KEY_GROUP 0x04
#endif

         if(mac_addr &&  !is_broadcast_ether_addr(mac_addr)) {
             if ( key_val.keytype != IEEE80211_CIPHER_WEP && key_index && !pairwise) {
                 osifp->m_count = 1;
                 osifp->mciphers[0] = key_val.keytype;
                 wlan_set_mcast_ciphers(vap,osifp->mciphers,osifp->m_count);
                 key_val.keyindex = key_index;
             } else  {
                osifp->u_count = 1;
                osifp->uciphers[0] = key_val.keytype;
                wlan_set_ucast_ciphers(vap,osifp->uciphers,osifp->u_count);
                key_val.keyindex = key_index == 0 ? IEEE80211_KEYIX_NONE :  key_index;
             }
            key_val.macaddr = (u_int8_t *) mac_addr ;
         } else {
                 osifp->m_count = 1;
                 osifp->mciphers[0] = key_val.keytype;
                 wlan_set_mcast_ciphers(vap,osifp->mciphers,osifp->m_count);
                 key_val.macaddr = (u_int8_t *)ieee80211broadcastaddr ;
                 key_val.keyindex = key_index;
         }

         if (pairwise)
                 key_val.keydir = IEEE80211_KEY_DIR_BOTH ;
         else
                 key_val.keydir = IEEE80211_KEY_DIR_RX ;

         if( params->seq) {
		   qdf_mem_copy(&key_val.keyrsc, params->seq, params->seq_len);
         }
         key_val.keyindex = key_index;
    } else {

        if (!mac_addr)
        {
            key_val.macaddr = (u_int8_t *)ieee80211broadcastaddr ;
            key_val.keyindex = key_index;
        } else {
            key_val.macaddr = (u_int8_t *) mac_addr ;
            key_val.keyindex = IEEE80211_KEYIX_NONE ;
        }

        key_val.keydir = IEEE80211_KEY_DIR_BOTH;
    }

    key_val.keyrsc  = 0;
    key_val.keytsc  = 0;
    if (params->seq) {
        uint64_t v = 0xFFU;
        if (params->seq_len == 8)
            key_val.keyrsc =
                (((uint64_t)params->seq[0] << 56) & (v << 56)) |
                (((uint64_t)params->seq[1] << 48) & (v << 48)) |
                (((uint64_t)params->seq[2] << 40) & (v << 40)) |
                (((uint64_t)params->seq[3] << 32) & (v << 32)) |
                ((params->seq[4] << 24) & (v << 24)) |
                ((params->seq[5] << 16) & (v << 16)) |
                ((params->seq[6] <<  8) & (v << 8)) |
                (params->seq[7]         & v);

        if (params->seq_len == 6)
            key_val.keyrsc =
                (((uint64_t)params->seq[0] << 40) & (v << 40)) |
                (((uint64_t)params->seq[1] << 32) & (v << 32)) |
                ((params->seq[2] << 24) & (v << 24)) |
                ((params->seq[3] << 16) & (v << 16)) |
                ((params->seq[4] <<  8) & (v << 8)) |
                (params->seq[5]         & v);
    }

    key_val.keylen  =  params->key_len;

    if (key_val.keylen == 0) {
        /* zero length keys will only set default key id if flags are set*/
        if ((!pairwise) && (key_val.keyindex!= IEEE80211_KEYIX_NONE)) {
            /* default xmit key */
            wlan_set_default_keyid(vap, key_val.keyindex);
            return 0;
        }
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,"%s: Zero length key\n", __func__);
        return -EINVAL;
    }


     if (key_val.keyindex == IEEE80211_KEYIX_NONE)
    {

        if (osifp->os_opmode == IEEE80211_M_STA ||
            osifp->os_opmode == IEEE80211_M_P2P_CLIENT)
        {
            int i=0;
            for (i = 0; i < QDF_MAC_ADDR_SIZE; i++) {
                if (mac_addr[i] != 0) {
                    break;
                }
            }
            if (i == QDF_MAC_ADDR_SIZE) {
                key_val.macaddr = (u_int8_t *)ieee80211broadcastaddr ;
            }
        }
     } else {
            if ((key_val.keyindex >= IEEE80211_WEP_NKID)
                && (key_val.keytype != IEEE80211_CIPHER_AES_CMAC)
                && (key_val.keytype != IEEE80211_CIPHER_AES_CMAC_256)
                && (key_val.keytype != IEEE80211_CIPHER_AES_GMAC)
                && (key_val.keytype != IEEE80211_CIPHER_AES_GMAC_256)) {
                return -EINVAL;
            }

            if (!IEEE80211_IS_MULTICAST(key_val.macaddr) &&
                ((key_val.keytype == IEEE80211_CIPHER_TKIP) ||
                (key_val.keytype == IEEE80211_CIPHER_AES_CCM) ||
                (key_val.keytype == IEEE80211_CIPHER_AES_CCM_256) ||
                (key_val.keytype == IEEE80211_CIPHER_AES_GCM) ||
                (key_val.keytype == IEEE80211_CIPHER_AES_GCM_256) )) {
                key_val.keyindex = IEEE80211_KEYIX_NONE;
            }
    }


    if (key_val.keylen > IEEE80211_KEYBUF_SIZE)
        key_val.keylen  = IEEE80211_KEYBUF_SIZE;
    key_val.rxmic_offset = IEEE80211_KEYBUF_SIZE + 8;
    key_val.txmic_offset =  IEEE80211_KEYBUF_SIZE;

    qdf_mem_copy(keydata, params->key, params->key_len);

    key_val.keydata = keydata;

    if(key_val.keytype == IEEE80211_CIPHER_TKIP) {
        key_val.rxmic_offset = TKIP_RXMIC_OFFSET;
        key_val.txmic_offset = TKIP_TXMIC_OFFSET;
    }


   if(key_val.keytype == IEEE80211_CIPHER_WEP
            && vap->iv_wep_keycache) {
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 0);
        /* only static wep keys will allocate index 0-3 in keycache
         *if we are using 802.1x with WEP then it should go to else part
         *to mandate this new iwpriv commnad wepkaycache is used
         */
    }
    else {
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 1);
        /* allow keys to allocate anywhere in key cache */
    }

    if ( params->vlan_id) {
	key_val.keyindex = add_vlan(vap, params->vlan_id, key_index);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,"%s: vlan_id:%d Group keyix:%d \n", __func__, params->vlan_id,key_val.keyindex);
    }

    error = wlan_set_key(vap,key_val.keyindex,&key_val);

    wlan_set_param(vap, IEEE80211_WEP_MBSSID, 0);  /* put it back to default */

    if ( (pairwise) &&(key_val.keyindex != IEEE80211_KEYIX_NONE) &&
        (key_val.keytype != IEEE80211_CIPHER_AES_CMAC) && (key_val.keytype != IEEE80211_CIPHER_AES_CMAC_256) &&
        (key_val.keytype != IEEE80211_CIPHER_AES_GMAC) && (key_val.keytype != IEEE80211_CIPHER_AES_GMAC_256)) {
        /* default xmit key */
        wlan_set_default_keyid(vap,key_val.keyindex);
    }

    /* Zero-out local key variables */
    qdf_mem_zero(keydata, IEEE80211_KEYBUF_SIZE);
    qdf_mem_zero(&key_val, sizeof(ieee80211_keyval));
    key_index = 0;
    return 0;
}

/**
 * wlan_cfg80211_get_key() - cfg80211 get key handler function
 * @wiphy: Pointer to wiphy structure.
 * @ndev: Pointer to net_device structure.
 * @key_index: key index
 * @pairwise: pairwise
 * @mac_addr: mac address
 * @cookie : cookie information
 * @params: key parameters
 *
 * Return: 0 for success, error number on failure.
 */
 
int wlan_cfg80211_get_key(struct wiphy *wiphy,
        struct net_device *ndev,
        u8 key_index, bool pairwise,
        const u8 *mac_addr, void *cookie,
        void (*callback)(void *cookie,
            struct key_params *)
        )
{
    struct key_params params;
    ieee80211_keyval kval;
    u_int8_t keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
    osif_dev *osifp = ath_netdev_priv(ndev);
    u_int8_t  bssid[QDF_MAC_ADDR_SIZE];
    wlan_if_t vap = osifp->os_if;
    u_int8_t seq[8] = {0};

    memset(&params, 0, sizeof(params));

    if(!mac_addr)
    {
         memset(bssid, 0xFF, QDF_MAC_ADDR_SIZE);
    } else {
         memcpy(bssid,mac_addr, QDF_MAC_ADDR_SIZE);
    }

    if (key_index != IEEE80211_KEYIX_NONE)
    {
        if (key_index >= IEEE80211_WEP_NKID)
            return -EINVAL;
    }

    kval.keydata = keydata;

    if (wlan_get_key(vap,key_index,bssid, &kval,
                     IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE,
                     GET_PN_ENABLE) != 0)
    {
        return -EINVAL;
    }

    params.cipher =  kval.keytype;
    params.key_len = kval.keylen;
    params.seq_len = SEQ_LEN_8;
    if (params.cipher != WLAN_CRYPTO_CIPHER_WAPI_SMS4 &&
        params.cipher != WLAN_CRYPTO_CIPHER_WEP)
        params.seq_len = SEQ_LEN_6;
    if(kval.keytsc) {
        memset(seq, 0, sizeof(seq));
        KEYTSC_TO_PN(seq, params.seq_len, kval.keytsc);
        params.seq = seq;
        if (params.seq_len == SEQ_LEN_6)
            params.seq = seq + 2;
    }

    params.key = kval.keydata;
    callback(cookie, &params);
    return 0;
}

/**
 * wlan_del_key() - cfg80211 delete key handler function
 * @wiphy: Pointer to wiphy structure.
 * @dev: Pointer to net_device structure.
 * @key_index: key index
 * @pairwise: pairwise
 * @mac_addr: mac address
 *
 * Return: 0 for success, error number on failure.
 */
int wlan_cfg80211_del_key(struct wiphy *wiphy,
        struct net_device *dev,
        u8 key_index,
        bool pairwise, const u8 *mac_addr)
{
    osif_dev *osifp = ath_netdev_priv(dev);
    u_int8_t  bssid[QDF_MAC_ADDR_SIZE];
    wlan_if_t vap = NULL;

    if (osifp == NULL) {
        return 0;
    }
    vap = osifp->os_if;

    if (vap == NULL) {
        return 0;
    }

    if( vap->iv_ic->recovery_in_progress) {
        qdf_print("%s: FW Crash on vap %d ...check", __func__, vap->iv_unit);
        return 0;
    }

    if(!mac_addr)
    {
         memset(bssid, 0xFF, QDF_MAC_ADDR_SIZE);
    } else {
         IEEE80211_ADDR_COPY(bssid,mac_addr);
    }
    if (key_index == KEYIX_INVALID) {
        ieee80211_del_key(vap,osifp->authmode,IEEE80211_KEYIX_NONE,bssid);
    } else {
        ieee80211_del_key(vap,osifp->authmode,key_index,bssid);
    }
    return 0;
}

/**
 * wlan_cfg80211_set_default_key : Set default key
 * @wiphy: pointer to wiphy structure
 * @ndev: pointer to net_device
 * @key_index: key_index
 * @unicast : unicast key
 * @multicast : multicast key
 *
 * Return; 0 on success, error number otherwise
 */
int wlan_cfg80211_set_default_key(struct wiphy *wiphy,
        struct net_device *ndev,
        u8 key_index,
        bool unicast, bool multicast)
{
    osif_dev *osifp = ath_netdev_priv(ndev);
    wlan_if_t vap = osifp->os_if;

    /* default xmit key */
    wlan_set_default_keyid(vap,key_index);

    return 0;
}

#endif
