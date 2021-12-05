/*
 * Copyright (c) 2011, 2017-2018 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 */

#include <osdep.h>
#include <ieee80211_var.h>
#include "ieee80211_channel.h"
#include <ieee80211_rateset.h>
#include "if_upperproto.h"
#include "wlan_scan.h"
#include <wlan_cmn.h>
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_objmgr_vdev_obj.h>
#include <wlan_objmgr_peer_obj.h>
#include <wlan_mlme_dispatcher.h>
#include <wlan_cm_bss_score_param.h>
#include <ieee80211_objmgr_priv.h>
#include <wlan_cm_blm.h>

#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
#endif
#endif

/** Max number of desired BSSIDs we can handle */
#define IEEE80211_DES_BSSID_MAX_COUNT                  8
/** Maximum number of MAC addresses we support in the excluded list */
#define IEEE80211_EXCLUDED_MAC_ADDRESS_MAX_COUNT       4
/** Typical tx power delta (in dB) between AP and STA */
#define IEEE80211_DEFAULT_TX_POWER_DELTA               6


struct ieee80211_aplist_config {
    /** Desired BSSID list */
    u_int8_t                  des_bssid_list[IEEE80211_DES_BSSID_MAX_COUNT][QDF_MAC_ADDR_SIZE];
    u_int32_t                 des_nbssid;
    bool                      accept_any_bssid;

    /** Desired PHY list */
    enum ieee80211_phymode    active_phy_id;

    /** Desired BSS type */
    enum ieee80211_opmode     des_bss_type;

    /** MAC addresses to be excluded from list of candidate APs */
    u_int8_t                  exc_macaddress[IEEE80211_EXCLUDED_MAC_ADDRESS_MAX_COUNT][QDF_MAC_ADDR_SIZE];
    int                       exc_macaddress_count; /* # excluded mac addresses */
    bool                      ignore_all_mac_addresses;

    /** Miscelaneous parameters used to build list of candidate APs */
    bool                      strict_filtering;
    u_int32_t                 max_age;

    /** Parameters used to rank candidate APs */
    int                       tx_power_delta;

    /* custom security check function */
    ieee80211_aplist_match_security_func match_security_func;
    void                                 *match_security_func_arg;


    /* Bad AP Timeout value in milli seconds 
     * This value is used to clear scan entry's BAD_AP status flag
     * from the moment its marked BAD_AP until
     * expiration of bad ap timeout specified in this field
     */
    u_int32_t                 bad_ap_timeout;

    /* custom candidate compare function */
    ieee80211_candidate_list_compare_func   compare_func;
    void                                   *compare_arg;
};


/*
 * Internal UMAC API
 */

void ieee80211_aplist_config_init(struct ieee80211_aplist_config *pconfig)
{
    pconfig->strict_filtering     = false;
    pconfig->max_age              = IEEE80211_SCAN_ENTRY_EXPIRE_TIME;

    /** PHY list */
    pconfig->active_phy_id        = IEEE80211_MODE_AUTO;

    pconfig->des_bss_type         = IEEE80211_M_STA;

    pconfig->tx_power_delta       = IEEE80211_DEFAULT_TX_POWER_DELTA;

    pconfig->des_bssid_list[0][0] = 0xFF;
    pconfig->des_bssid_list[0][1] = 0xFF;
    pconfig->des_bssid_list[0][2] = 0xFF;
    pconfig->des_bssid_list[0][3] = 0xFF;
    pconfig->des_bssid_list[0][4] = 0xFF;
    pconfig->des_bssid_list[0][5] = 0xFF;
    pconfig->des_nbssid           = 1;
    pconfig->accept_any_bssid     = true;
    pconfig->bad_ap_timeout       = BAD_AP_TIMEOUT;
}

int ieee80211_aplist_set_desired_bssidlist(
    struct ieee80211_aplist_config    *pconfig, 
    u_int16_t                         nbssid, 
    u_int8_t                          (*bssidlist)[QDF_MAC_ADDR_SIZE]
    )
{
    int    i;
    u_int8_t zero_mac[QDF_MAC_ADDR_SIZE] = { 0, 0, 0, 0, 0, 0 };
    u_int8_t bcast_mac[QDF_MAC_ADDR_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    if (nbssid > IEEE80211_DES_BSSID_MAX_COUNT) {
        return EOVERFLOW;
    }

    /* We don't know if the wildcard BSSID will be in the list, so clear flag */
    pconfig->accept_any_bssid = false;

    for (i = 0; i < nbssid; i++) {
        /*
         * All zero MAC address is the indication to clear the pervious set
         * BSSID's. In this case, we convert it to a broadcast MAC address.
         */
        if (OS_MEMCMP(bssidlist[i], zero_mac, QDF_MAC_ADDR_SIZE) == 0) {
            OS_MEMCPY(bssidlist[i], bcast_mac, QDF_MAC_ADDR_SIZE);
        }
        IEEE80211_ADDR_COPY(pconfig->des_bssid_list[i], bssidlist[i]);

        /* Update flag based on whether the Wildcard BSSID appears on the list */
        if (IEEE80211_IS_BROADCAST(bssidlist[i]))
            pconfig->accept_any_bssid = true;
    }

    /* Save number of elements on the list */
    pconfig->des_nbssid = nbssid;

    return EOK; 
} 
                                        
int ieee80211_aplist_get_desired_bssidlist(
    struct ieee80211_aplist_config    *pconfig, 
    u_int8_t                          (*bssidlist)[QDF_MAC_ADDR_SIZE]
    )
{
    int    i;

    for (i = 0; i < pconfig->des_nbssid; i++) {
        IEEE80211_ADDR_COPY(bssidlist[i], pconfig->des_bssid_list[i]);
    }

    return (pconfig->des_nbssid);
}

int ieee80211_aplist_get_desired_bssid_count(
    struct ieee80211_aplist_config    *pconfig
    )
{
    return (pconfig->des_nbssid);
}

int ieee80211_aplist_get_desired_bssid(
    struct ieee80211_aplist_config    *pconfig,
    int                               index, 
    u_int8_t                          **bssid
    )
{
    if (index > pconfig->des_nbssid) {
        return EOVERFLOW;
    }

    *bssid = pconfig->des_bssid_list[index];

    return EOK;
}

bool ieee80211_aplist_get_accept_any_bssid(
    struct ieee80211_aplist_config    *pconfig
    )
{
    return (pconfig->accept_any_bssid);
}

int ieee80211_aplist_set_max_age(
    struct ieee80211_aplist_config    *pconfig, 
    u_int32_t                         max_age
    )
{
    pconfig->max_age = max_age;

    return EOK;
}

u_int32_t ieee80211_aplist_get_max_age(
    struct ieee80211_aplist_config    *pconfig
    )
{
    return (pconfig->max_age);
}

int ieee80211_aplist_set_ignore_all_mac_addresses(
    struct ieee80211_aplist_config    *pconfig, 
    bool                              flag
    )
{
    pconfig->ignore_all_mac_addresses = flag;

    return EOK;
}

bool ieee80211_aplist_get_ignore_all_mac_addresses(
    struct ieee80211_aplist_config    *pconfig
    )
{
    return (pconfig->ignore_all_mac_addresses);
}

int ieee80211_aplist_set_exc_macaddresslist(
    struct ieee80211_aplist_config    *pconfig, 
    u_int16_t                         n_entries, 
    u_int8_t                          (*macaddress)[QDF_MAC_ADDR_SIZE]
    )
{
    int    i;

    if (n_entries > IEEE80211_EXCLUDED_MAC_ADDRESS_MAX_COUNT) {
        return EOVERFLOW;
    }

    for (i = 0; i < n_entries; i++) {
        IEEE80211_ADDR_COPY(pconfig->exc_macaddress[i], macaddress[i]);
    }

    pconfig->exc_macaddress_count = n_entries;

    return EOK; 
} 
                                        
int ieee80211_aplist_get_exc_macaddresslist(
    struct ieee80211_aplist_config    *pconfig, 
    u_int8_t                          (*macaddress)[QDF_MAC_ADDR_SIZE]
    )
{
    int    i;

    for (i = 0; i < pconfig->exc_macaddress_count; i++) {
        IEEE80211_ADDR_COPY(macaddress[i], pconfig->exc_macaddress[i]);
    }

    return (pconfig->exc_macaddress_count);
}

int ieee80211_aplist_get_exc_macaddress_count(
    struct ieee80211_aplist_config    *pconfig
    )
{
    return (pconfig->exc_macaddress_count);
}

int ieee80211_aplist_get_exc_macaddress(
    struct ieee80211_aplist_config    *pconfig, 
    int                               index, 
    u_int8_t                          **pmacaddress
    )
{
    if (index >= pconfig->exc_macaddress_count) {
        return EOVERFLOW;
    }

    *pmacaddress = pconfig->exc_macaddress[index];

    return EOK;
}

int ieee80211_aplist_set_desired_bsstype(
    struct ieee80211_aplist_config    *pconfig, 
    enum ieee80211_opmode             bss_type
    )
{
    pconfig->des_bss_type = bss_type;

    return EOK;
}

enum ieee80211_opmode ieee80211_aplist_get_desired_bsstype(
    struct ieee80211_aplist_config    *pconfig
    )
{
    return (pconfig->des_bss_type);
}


int ieee80211_aplist_set_tx_power_delta(
    struct ieee80211_aplist_config    *pconfig, 
    int                               tx_power_delta
    )
{
    pconfig->tx_power_delta = tx_power_delta;

    return EOK;
}

int ieee80211_aplist_get_tx_power_delta(
    struct ieee80211_aplist_config    *pconfig
    )
{
    return (pconfig->tx_power_delta);
}
void ieee80211_aplist_register_match_security_func(
    struct ieee80211_aplist_config    *pconfig,
    ieee80211_aplist_match_security_func match_security_func,
    void *arg
    )
{
    pconfig->match_security_func = match_security_func;
    pconfig->match_security_func_arg = arg;

}

int ieee80211_aplist_set_bad_ap_timeout(
    struct ieee80211_aplist_config    *pconfig, 
    u_int32_t                         bad_ap_timeout
    )
{
    pconfig->bad_ap_timeout = bad_ap_timeout;

    return EOK;
}

int ieee80211_aplist_config_vattach(
    ieee80211_aplist_config_t    *pconfig, 
    osdev_t                      osdev
    )
{
    if ((*pconfig) != NULL) 
        return EINPROGRESS; /* already attached ? */

    *pconfig = (ieee80211_aplist_config_t) OS_MALLOC(osdev, (sizeof(struct ieee80211_aplist_config)),0);

    if (*pconfig != NULL) {
        OS_MEMZERO((*pconfig), sizeof(struct ieee80211_aplist_config));

        ieee80211_aplist_config_init(*pconfig);

        return EOK;
    }

    return ENOMEM;
}

int ieee80211_aplist_config_vdetach(
    ieee80211_aplist_config_t    *pconfig
    )
{
    if ((*pconfig) == NULL) 
        return EINPROGRESS; /* already detached ? */

    OS_FREE(*pconfig);

    *pconfig = NULL;

    return EOK;
}


/******************************* External API *******************************/

int wlan_aplist_set_desired_bssidlist(
    wlan_if_t    vaphandle, 
    u_int16_t    nbssid, 
    u_int8_t     (*bssidlist)[QDF_MAC_ADDR_SIZE]
    )
{
    return ieee80211_aplist_set_desired_bssidlist(ieee80211_vap_get_aplist_config(vaphandle), nbssid, bssidlist);
}

int wlan_aplist_get_desired_bssidlist(
    wlan_if_t    vaphandle, 
    u_int8_t     (*bssidlist)[QDF_MAC_ADDR_SIZE]
    )
{
    return ieee80211_aplist_get_desired_bssidlist(ieee80211_vap_get_aplist_config(vaphandle), bssidlist);
}

int wlan_aplist_get_desired_bssid_count(
    wlan_if_t    vaphandle
    )
{
    return ieee80211_aplist_get_desired_bssid_count(ieee80211_vap_get_aplist_config(vaphandle));
}

int wlan_aplist_get_desired_bssid(
    wlan_if_t    vaphandle,
    int          index, 
    u_int8_t     **bssid
    )
{
    return ieee80211_aplist_get_desired_bssid(ieee80211_vap_get_aplist_config(vaphandle), index, bssid);
}

bool wlan_aplist_get_accept_any_bssid(
    wlan_if_t vaphandle
    )
{
    return ieee80211_aplist_get_accept_any_bssid(ieee80211_vap_get_aplist_config(vaphandle));
}

int wlan_aplist_set_max_age(
    wlan_if_t    vaphandle, 
    u_int32_t    max_age
    )
{
    return ieee80211_aplist_set_max_age(ieee80211_vap_get_aplist_config(vaphandle), max_age);
}

u_int32_t wlan_aplist_get_max_age(
    wlan_if_t    vaphandle
    )
{
    return ieee80211_aplist_get_max_age(ieee80211_vap_get_aplist_config(vaphandle));
}

int wlan_aplist_set_ignore_all_mac_addresses(
    wlan_if_t    vaphandle, 
    bool         flag
    )
{
    return ieee80211_aplist_set_ignore_all_mac_addresses(ieee80211_vap_get_aplist_config(vaphandle), flag);
}

bool wlan_aplist_get_ignore_all_mac_addresses(
    wlan_if_t    vaphandle
    )
{
    return ieee80211_aplist_get_ignore_all_mac_addresses(ieee80211_vap_get_aplist_config(vaphandle));
}

int wlan_aplist_set_exc_macaddresslist(
    wlan_if_t    vaphandle, 
    u_int16_t    n_entries, 
    u_int8_t     (*macaddress)[QDF_MAC_ADDR_SIZE]
    )
{
    return ieee80211_aplist_set_exc_macaddresslist(ieee80211_vap_get_aplist_config(vaphandle), n_entries, macaddress);
} 
                                        
int wlan_aplist_get_exc_macaddresslist(
    wlan_if_t    vaphandle, 
    u_int8_t     (*macaddress)[QDF_MAC_ADDR_SIZE]
    )
{
    return ieee80211_aplist_get_exc_macaddresslist(ieee80211_vap_get_aplist_config(vaphandle), macaddress);
}

int wlan_aplist_get_exc_macaddress_count(
    wlan_if_t    vaphandle
    )
{
    return ieee80211_aplist_get_exc_macaddress_count(ieee80211_vap_get_aplist_config(vaphandle));
}

int wlan_aplist_get_exc_macaddress(
    wlan_if_t    vaphandle, 
    int          index, 
    u_int8_t     **pmacaddress
    )
{
    return ieee80211_aplist_get_exc_macaddress(ieee80211_vap_get_aplist_config(vaphandle), index, pmacaddress);
}

int wlan_aplist_set_desired_bsstype(
    wlan_if_t                vaphandle, 
    enum ieee80211_opmode    bss_type
    )
{
    return ieee80211_aplist_set_desired_bsstype(ieee80211_vap_get_aplist_config(vaphandle), bss_type);
}

enum ieee80211_opmode wlan_aplist_get_desired_bsstype(
    wlan_if_t    vaphandle
    )
{
    return ieee80211_aplist_get_desired_bsstype(ieee80211_vap_get_aplist_config(vaphandle));
}

int wlan_aplist_set_tx_power_delta(
    wlan_if_t    vaphandle, 
    int          tx_power_delta
    )
{
    return ieee80211_aplist_set_tx_power_delta(ieee80211_vap_get_aplist_config(vaphandle), tx_power_delta);
}

int wlan_aplist_set_bad_ap_timeout(
    wlan_if_t    vaphandle, 
    u_int32_t    bad_ap_timeout
    )
{
    return ieee80211_aplist_set_bad_ap_timeout(ieee80211_vap_get_aplist_config(vaphandle), bad_ap_timeout);
}

void wlan_aplist_init(
    wlan_if_t    vaphandle
    )
{
    ieee80211_aplist_config_init(ieee80211_vap_get_aplist_config(vaphandle));
}

void wlan_aplist_register_match_security_func(wlan_if_t vaphandle, ieee80211_aplist_match_security_func match_security_func, void *arg)
{
    ieee80211_aplist_register_match_security_func(ieee80211_vap_get_aplist_config(vaphandle), match_security_func,arg);
}

/*************************************************************************************/
static QDF_STATUS
ieee80211_aplist_clear_bad_ap_flags(
    void                 *arg, 
    wlan_scan_entry_t    scan_entry)
{
    systime_t  bad_ap_time = wlan_cm_blm_scan_mlme_get_bad_ap_time(scan_entry);
    systime_t current_time = OS_GET_TIMESTAMP();
    wlan_if_t vaphandle = arg;
    struct ieee80211_aplist_config *pconfig = ieee80211_vap_get_aplist_config(vaphandle);

    if (bad_ap_time != 0) {
        if (CONVERT_SYSTEM_TIME_TO_MS(current_time - bad_ap_time) > pconfig->bad_ap_timeout){
            wlan_cm_blm_scan_mlme_set_bad_ap_time(scan_entry, 0);
            wlan_cm_blm_scan_mlme_set_status(scan_entry, AP_STATE_GOOD);
        }
    }
    else {
        wlan_cm_blm_scan_mlme_set_bad_ap_time(scan_entry, 0);
        wlan_cm_blm_scan_mlme_set_status(scan_entry, AP_STATE_GOOD);
    }

    return EOK;
}

static void ieee80211_candidate_list_custom_sort(
                    struct ieee80211_aplist_config *pconfig,
                    qdf_list_t *candidate_list)
{
    qdf_list_node_t *cur_node = NULL;
    qdf_list_node_t *next_node = NULL;
    struct scan_cache_node *cur_ent;
    struct scan_cache_node *next_ent;
    uint8_t swap = 0;
    int status = 0;

    if (!candidate_list || qdf_list_size(candidate_list) <= 1)
        return;

    do {
        swap = 0;
        qdf_list_peek_front(candidate_list, &cur_node);
        while (cur_node) {
            cur_ent = qdf_container_of(cur_node, struct scan_cache_node, node);
            qdf_list_peek_next(candidate_list, cur_node, &next_node);
            if (next_node) {
                next_ent = qdf_container_of(next_node, struct scan_cache_node, node);
                status = pconfig->compare_func(pconfig->compare_arg,
                        cur_ent->entry, next_ent->entry);
                if (status < 0) {
                    qdf_list_insert_before(candidate_list, &next_ent->node,
                            &cur_ent->node);
                    swap = 1;
                }

            }
            cur_node = next_node;
            next_node = NULL;
        }

    }while (swap);
}

static void ieee80211_candidate_list_print(qdf_list_t *candidate_list)
{
    qdf_list_node_t *cur_node = NULL;
    qdf_list_node_t *next_node = NULL;
    struct scan_cache_node *se_node;

    if (!candidate_list || !qdf_list_size(candidate_list))
        return;

    qdf_info("Num of entries: %u", qdf_list_size(candidate_list));

    qdf_list_peek_front(candidate_list, &cur_node);
    while (cur_node) {
        se_node = qdf_container_of(cur_node, struct scan_cache_node, node);

        qdf_info("SSID:%s bssid:%pM score:%d", se_node->entry->ssid.ssid,
                 se_node->entry->bssid.bytes, se_node->entry->bss_score);

        qdf_list_peek_next(candidate_list, cur_node, &next_node);
        cur_node = next_node;
        next_node = NULL;
    }
}

qdf_list_t *ieee80211_candidate_list_build(
    wlan_if_t            vaphandle,
    bool                 strict_filtering,
    wlan_scan_entry_t    active_ap,
    u_int32_t            maximum_age,
    uint8_t              *bssid_hint)
{
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_vdev *vdev;
    struct scan_filter *filter;
    qdf_list_t *candidate_list = NULL;
    ieee80211_ssid *des_ssid;
    struct ieee80211_aplist_config *pconfig;
    uint32_t i = 0;
    uint32_t des_bssid_count;
    u_int8_t *des_bssid;
    bool des_bssid_set = false;
    int32_t authmode;
    int32_t ucastcipher;
    int32_t mcastcipher;
    int32_t keymgmt;
#if ATH_SUPPORT_WRAP
    wlan_if_t stavap = vaphandle->iv_ic->ic_sta_vap;
#endif


    filter = qdf_mem_malloc(sizeof(*filter));
    if (!filter) {
        qdf_err("Unable to alloc mem");
        return NULL;
    }

    vdev = vaphandle->vdev_obj;
    pdev = wlan_vdev_get_pdev(vdev);
    pconfig  = ieee80211_vap_get_aplist_config(vaphandle);

    /* Scan entry age threshold filter */
    filter->age_threshold = maximum_age;

    /* SSID filter */
    ieee80211_get_desired_ssid(vaphandle, 0, &des_ssid);
    if (des_ssid->len != 0) {
        filter->num_of_ssid = 1;
        filter->ssid_list[0].length = des_ssid->len;
        qdf_mem_copy(&filter->ssid_list[0].ssid, des_ssid->ssid, des_ssid->len);
    }

    /* BSSID filter */
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (vaphandle->iv_psta && !vaphandle->iv_mpsta) {
#else
    if (dp_wrap_vdev_is_psta(vaphandle->vdev_obj) && !dp_wrap_vdev_is_mpsta(vaphandle->vdev_obj)) {
#endif
        if (stavap && stavap->iv_bss) {
            /* For PSTA, desired BSSID should be MPSTA BSSID */
            filter->num_of_bssid = 1;
            qdf_mem_copy(&filter->bssid_list[0], stavap->iv_bss->ni_macaddr,
                         QDF_NET_ETH_LEN);
            des_bssid_set = true;
        } else {
            qdf_mem_free(filter);
            qdf_err("WRAP mode, staVap not available");
            return NULL;
        }
    }
#endif

    if (!des_bssid_set && !ieee80211_aplist_get_accept_any_bssid(pconfig)) {
        des_bssid_count = ieee80211_aplist_get_desired_bssid_count(pconfig);
        for (i = 0; i < des_bssid_count; i++) {
            if (ieee80211_aplist_get_desired_bssid(pconfig, i, &des_bssid)
                    != EOK) {
                qdf_err("Failed to retrieve desired SSID");
                continue;
            }
            qdf_mem_copy(&filter->bssid_list[i], des_bssid, QDF_NET_ETH_LEN);
        }
        filter->num_of_bssid = des_bssid_count;
    }

    /* Auth and Enc filter*/
    authmode = wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_AUTH_MODE);

    if ( authmode == -1 ) {
        qdf_err("crypto_error while getting authmode params\n");
        goto end;
    }
    filter->authmodeset = authmode;

    ucastcipher = wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_UCAST_CIPHER);

    if ( ucastcipher == -1 ) {
        qdf_err("crypto_error while getting ucast_cipher params\n");
        goto end;
    }
    filter->ucastcipherset = ucastcipher;

    mcastcipher = wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_MCAST_CIPHER);

    if ( mcastcipher == -1 ) {
       qdf_err("crypto_error while getting mcast_cipher params\n");
       goto end;
    }
    filter->mcastcipherset = mcastcipher;

    keymgmt = wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_KEY_MGMT);

    if ( keymgmt == -1 ) {
       qdf_err("crypto_error while getting key mgmt params\n");
       goto end;
    }
    filter->key_mgmt = keymgmt;

    /* Ignore auth encryption type */
    if (!QDF_HAS_PARAM(filter->authmodeset, WLAN_CRYPTO_AUTH_WAPI) &&
            !QDF_HAS_PARAM(filter->authmodeset, WLAN_CRYPTO_AUTH_RSNA) &&
            !QDF_HAS_PARAM(filter->authmodeset, WLAN_CRYPTO_AUTH_WPA))
        filter->ignore_auth_enc_type = 1;

    /* PMF filter */
    if (wlan_crypto_vdev_is_pmf_required(vdev))
        filter->pmf_cap = WLAN_PMF_REQUIRED;
    else if (!wlan_crypto_vdev_is_pmf_enabled(vdev))
        filter->pmf_cap = WLAN_PMF_DISABLED;
    else
        filter->ignore_pmf_cap = 1;

    /* DFS hit channel filter */
    filter->ignore_nol_chan = 1;

    /* Custom security match filter */
    if (pconfig->match_security_func) {
        filter->match_security_func = pconfig->match_security_func;
        filter->match_security_func_arg = pconfig->match_security_func_arg;
    }

    /* Custom CCX validate bss filter */
    if (vaphandle->iv_ccx_evtable && vaphandle->iv_ccx_evtable->wlan_ccx_validate_bss) {
        filter->ccx_validate_bss =
            (void *)vaphandle->iv_ccx_evtable->wlan_ccx_validate_bss;
        filter->ccx_validate_bss_arg = (void *)vaphandle->iv_ccx_arg;
    }

    /* Get the filtered scan results */
    candidate_list = ucfg_scan_get_result(pdev, filter);
    qdf_mem_free(filter);

    /* Calculate the bss score for the filtered result */
    if (candidate_list && qdf_list_size(candidate_list))
        wlan_cm_calculate_bss_score(pdev, NULL, candidate_list,
                                    (struct qdf_mac_addr *)bssid_hint);

    if (!candidate_list || !qdf_list_size(candidate_list)) {
        qdf_err("No valid candidate found");
        if (candidate_list)
            wlan_scan_purge_results(candidate_list);

        ucfg_scan_db_iterate(wlan_vap_get_pdev(vaphandle),
                             ieee80211_aplist_clear_bad_ap_flags,
                             vaphandle);
        return NULL;
    }

    if (pconfig->compare_func)
        ieee80211_candidate_list_custom_sort(pconfig, candidate_list);

    ieee80211_candidate_list_print(candidate_list);
    return candidate_list;

end:
#ifdef ATH_SUPPORT_WRAP
    if (filter)
        qdf_mem_free(filter);
#endif
    return NULL;
}

wlan_scan_entry_t ieee80211_candidate_list_copy_candidate(
    wlan_scan_entry_t    candidate
    )
{
   return util_scan_copy_cache_entry(candidate);
}

void ieee80211_candidate_list_free_copy_candidate(
    wlan_scan_entry_t    copy_candidate
    )
{
    util_scan_free_cache_entry(copy_candidate);
}

void ieee80211_candidate_list_register_compare_func (
    ieee80211_aplist_config_t       aplist,
    ieee80211_candidate_list_compare_func compare_func,
    void *arg
    )
{
        aplist->compare_func = compare_func;
        aplist->compare_arg =arg;
}

qdf_list_t *wlan_candidate_list_build(
    wlan_if_t            vaphandle,
    bool                 strict_filtering,
    wlan_scan_entry_t    active_ap,
    u_int32_t            maximum_age,
    uint8_t              *bssid_hint)
{
    return ieee80211_candidate_list_build(vaphandle,
                                   strict_filtering,
                                   active_ap,
                                   maximum_age,
                                   bssid_hint);
}

wlan_scan_entry_t wlan_candidate_list_copy_candidate(
    wlan_scan_entry_t    candidate
    )
{
    return ieee80211_candidate_list_copy_candidate(candidate);
}

void wlan_candidate_list_free_copy_candidate(
    wlan_scan_entry_t    copy_candidate
    )
{
    ieee80211_candidate_list_free_copy_candidate(copy_candidate);
}

void wlan_candidate_list_register_compare_func(wlan_if_t vaphandle, ieee80211_candidate_list_compare_func compare_func, void *arg)
{
    ieee80211_candidate_list_register_compare_func(ieee80211_vap_get_aplist_config(vaphandle), compare_func,arg);
}

enum cm_blm_exc_mac_mode wlan_cm_get_exc_mac_addr_list(
        struct wlan_objmgr_vdev *vdev,
        uint8_t (**exc_mac_list)[QDF_MAC_ADDR_SIZE],
        uint8_t *exc_mac_count)
{
    wlan_if_t vap;
    struct ieee80211_aplist_config *pconfig;

    if (!vdev)
        goto end;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        goto end;

    pconfig  = ieee80211_vap_get_aplist_config(vap);
    if (!pconfig)
        goto end;

    if (pconfig->ignore_all_mac_addresses)
        return CM_BLM_EXC_MAC_ALL;

    if (pconfig->exc_macaddress_count > 0) {
        (*exc_mac_list) = pconfig->exc_macaddress;
        *exc_mac_count = pconfig->exc_macaddress_count;
        return CM_BLM_EXC_MAC_FEW;
    }

end:
    return CM_BLM_EXC_MAC_NONE;
}

qdf_time_t wlan_cm_get_bad_ap_timeout(struct wlan_objmgr_vdev *vdev)
{
    wlan_if_t vap;
    struct ieee80211_aplist_config *pconfig;

    if (!vdev)
        return 0;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return 0;

    pconfig  = ieee80211_vap_get_aplist_config(vap);
    if (!pconfig)
        return 0;

    return pconfig->bad_ap_timeout;
}

void wlan_cm_update_advance_filter(struct wlan_objmgr_vdev *vdev,
                                   struct scan_filter *filter)
{
    struct ieee80211_aplist_config *pconfig;
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(vdev);

    if (!vap)
        return;

    qdf_debug("Update custom filter options");

    /* Custom security match filter */
    pconfig  = ieee80211_vap_get_aplist_config(vap);
    if (pconfig && pconfig->match_security_func) {
        filter->match_security_func = pconfig->match_security_func;
        filter->match_security_func_arg = pconfig->match_security_func_arg;
    }

    /* Custom CCX validate bss filter */
    if (vap->iv_ccx_evtable && vap->iv_ccx_evtable->wlan_ccx_validate_bss) {
        filter->ccx_validate_bss =
            (void *)vap->iv_ccx_evtable->wlan_ccx_validate_bss;
        filter->ccx_validate_bss_arg = (void *)vap->iv_ccx_arg;
    }
}

void wlan_cm_candidate_list_custom_sort(struct wlan_objmgr_vdev *vdev,
                                        qdf_list_t *candidate_list)
{
    struct ieee80211_aplist_config *pconfig;
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(vdev);

    if (!vap)
        return;

    qdf_debug("Using custom candidate list sort");

    pconfig  = ieee80211_vap_get_aplist_config(vap);
    if (pconfig && pconfig->compare_func)
        ieee80211_candidate_list_custom_sort(pconfig, candidate_list);
}
