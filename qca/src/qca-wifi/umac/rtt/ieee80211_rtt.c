/*
* Copyright (c) 2016, 2018-2019 Qualcomm Innovation Center, Inc.
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/

/*
 * 2016 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <linux/netlink.h>
#include <ieee80211_var.h>
#include <qdf_types.h> /* qdf_print */
#include "ieee80211_rtt.h"
#include "ol_if_athvar.h"

#if ATH_SUPPORT_LOWI
#include "ath_lowi_if.h"
#include "wifi_pos_api.h"
#endif /* ATH_SUPPORT_LOWI */

#define LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS  2

#if ATH_SUPPORT_LOWI
/* Send Where are you action frame */
/* Function     : ieee80211_lowi_send_wru_frame
 * Arguments    : Pointer to data for WRU frame
 * Functionality: Creates and sends Where are you action frame
 * Return       : Void
 */
void ieee80211_lowi_send_wru_frame (struct wlan_objmgr_psoc *psoc, u_int8_t *data)
{
    struct ieee80211_node *ni = NULL;
    struct ieee80211vap * vap = NULL;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    struct ieee80211com *ic = NULL;
    struct wru_lci_request *wru = (struct wru_lci_request *)data;
    struct ieee80211_ftmrrreq *actionbuf;
    struct wlan_objmgr_peer *peer;

    peer = wlan_objmgr_get_peer_by_mac(psoc, &wru->sta_mac[0], WLAN_RTT_ID);
    if(peer == NULL) {
        qdf_err("%s: Could not find node[%s] in associated nodes table.", __func__, ether_sprintf(&wru->sta_mac[0]));
        return;
    }
    ni = wlan_peer_get_mlme_ext_obj(peer);
    if (!ni)
    {
        qdf_err("Unable to get ni");
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return;
    }
    ic = ni->ni_ic;
    /* Get VAP where this node is associated */
    vap = ni->ni_vap;
    /* Make sure this VAP is active and in AP mode */
    if ((wlan_vdev_chan_config_valid(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        (IEEE80211_M_HOSTAP != vap->iv_opmode)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_WIFIPOS,
             "%s: ERROR: VAP is either not active or not in AP mode. Not sending WRU frame\n", __func__);
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return;
    }
    wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
    if (wbuf == NULL) {
        ieee80211_free_node(ni, WLAN_RTT_ID);
        return;
    }
    actionbuf = (struct ieee80211_ftmrrreq *)frm;
    actionbuf->header.ia_category = IEEE80211_ACTION_CAT_RADIO;
    actionbuf->header.ia_action = IEEE80211_ACTION_MEAS_REQUEST;
    actionbuf->dialogtoken = wru->dialogtoken;
    actionbuf->num_repetitions = htole16(wru->num_repetitions);
    frm = &actionbuf->elem[0];

    OS_MEMCPY(frm, &(wru->id), wru->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS); //include id and len fields while copying
    frm += wru->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS;
    wbuf_set_pktlen(wbuf, (frm - (u_int8_t*)wbuf_header(wbuf)));
    /* If Managment Frame protection is enabled (PMF), set Privacy bit */
    if (ieee80211_vap_mfp_test_is_set(vap) ||
        (wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj) &&
         ieee80211_node_is_authorized(ni))) {
        /* MFP is enabled, so we need to set Privacy bit */
        struct ieee80211_frame *wh;
        wh = (struct ieee80211_frame*)wbuf_header(wbuf);
        wh->i_fc[1] |= IEEE80211_FC1_WEP;
    }
    ieee80211_send_mgmt(vap, ni, wbuf, false);
    qdf_print("Where Are you frame successfully sent for %s", ether_sprintf(&wru->sta_mac[0]));
    ieee80211_free_node(ni, WLAN_RTT_ID);    /* reclaim node */
    return;
}
#endif /* ATH_SUPPORT_LOWI */

/* Send FTMRR action frame */
/* Function     : ieee80211_lowi_send_ftmrr_frame
 * Arguments    : Pointer to data for FTMRR frame
 * Functionality: Creates and sends FTMRR action frame
 * Return       : 0 on success, -1 on failure.
 */
int ieee80211_lowi_send_ftmrr_frame(struct wlan_objmgr_psoc *psoc, u_int8_t *data)
{
    struct ieee80211_node *ni = NULL;
    struct ieee80211vap * vap = NULL;
    wbuf_t wbuf = NULL;
    u_int8_t *frm = NULL;
    struct ieee80211com *ic = NULL;
    struct ftmrr_request *ftmrr = (struct ftmrr_request *)data;
    struct ieee80211_ftmrrreq *actionbuf;
    struct wlan_objmgr_peer *peer;

    peer = wlan_objmgr_get_peer_by_mac(psoc, &ftmrr->sta_mac[0], WLAN_RTT_ID);
    if(peer == NULL) {
        qdf_err("%s: Could not find node[%s] in associated nodes table.", __func__, ether_sprintf(&ftmrr->sta_mac[0]));
        return -1;
    }
    ni = wlan_peer_get_mlme_ext_obj(peer);
    if (!ni)
    {
        qdf_err("Unable to get ni");
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return -1;
    }
    ic = ni->ni_ic;
    /* Get VAP where this node is associated */
    vap = ni->ni_vap;
    /* Make sure vap is active and  in AP mode, else do not FTMRR frame */
    if ((wlan_vdev_chan_config_valid(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        (IEEE80211_M_HOSTAP != vap->iv_opmode)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_WIFIPOS,
            "%s: ERROR: Vap is either not active or not in AP mode. Not sending FTMRR frame\n", __func__);
        wlan_objmgr_peer_release_ref(peer, WLAN_RTT_ID);
        return -1;
    }
    wbuf = ieee80211_getmgtframe(ni, IEEE80211_FC0_SUBTYPE_ACTION, &frm, 0);
    if (wbuf == NULL) {
        ieee80211_free_node(ni, WLAN_RTT_ID);
        return -1;
    }
    actionbuf = (struct ieee80211_ftmrrreq *)frm;
    actionbuf->header.ia_category = IEEE80211_ACTION_CAT_RADIO;
    actionbuf->header.ia_action = IEEE80211_ACTION_MEAS_REQUEST;
    actionbuf->dialogtoken = ftmrr->dialogtoken;
    actionbuf->num_repetitions = htole16(ftmrr->num_repetitions);
    frm = &actionbuf->elem[0];

    OS_MEMCPY(frm, &(ftmrr->id), ftmrr->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS); //include id and len fields while copying
    frm += ftmrr->len + LOWI_MESSAGE_SUBIE_AND_LEN_OCTETS;
    wbuf_set_pktlen(wbuf, (frm - (u_int8_t*)wbuf_header(wbuf)));
    /* If Managment Frame protection is enabled (PMF), set Privacy bit */
    if (ieee80211_vap_mfp_test_is_set(vap) ||
        (wlan_crypto_is_pmf_enabled(vap->vdev_obj, ni->peer_obj) &&
         ieee80211_node_is_authorized(ni))) {
        /* MFP is enabled, so we need to set Privacy bit */
        struct ieee80211_frame *wh;
        wh = (struct ieee80211_frame*)wbuf_header(wbuf);
        wh->i_fc[1] |= IEEE80211_FC1_WEP;
    }
    ieee80211_send_mgmt(vap, ni, wbuf, false);
    qdf_print("FTMRR frame successfully sent for %s", ether_sprintf(&ftmrr->sta_mac[0]));
    ieee80211_free_node(ni, WLAN_RTT_ID);    /* reclaim node */
    return 0;
}

int ieee80211_send_ftmrr_frame(struct wlan_objmgr_pdev *pdev,
                               struct ieee80211_wlanconfig_ftmrr *ftmrr_config)
{
    struct ieee80211_ftmrr ftmrr;
    struct neighbor_report_element_arr *nr;
    struct ieee80211com *ic;
    struct wlan_objmgr_psoc *psoc;
    uint8_t sub_element_len;
    uint8_t wbc_len;
    int i;

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("null ic");
        return -1;
    }

    psoc = wlan_pdev_get_psoc(pdev);

    qdf_mem_zero(&ftmrr, sizeof(struct ieee80211_ftmrr));

    qdf_mem_copy(&ftmrr.sta_mac, ftmrr_config->sta_mac, IEEE80211_ADDR_LEN);
    ftmrr.dialogtoken = ++ic->ic_ftmrr_dialogtoken;
    ftmrr.element_id = RM_MEAS_REQ_ELEM_ID;

    ftmrr.meas_token = ++ic->ic_ftmrr_meas_token;
    ftmrr.meas_type = LOWI_WLAN_FTM_RANGE_REQ_TYPE;
    ftmrr.rand_inter = ftmrr_config->random_interval;
    ftmrr.min_ap_count = ftmrr_config->num_elements;

    ftmrr.len = sizeof(ftmrr.meas_token) + sizeof(ftmrr.meas_req_mode) +
                sizeof(ftmrr.meas_type) + sizeof(ftmrr.rand_inter) +
                sizeof(ftmrr.min_ap_count) +
                ftmrr.min_ap_count * sizeof(struct neighbor_report_element_arr);

    nr = (struct neighbor_report_element_arr *)&ftmrr.elem[0];
    sub_element_len = sizeof(struct neighbor_report_element_arr) -
                      sizeof(nr->sub_element_id) - sizeof(nr->sub_element_len);
    wbc_len = sizeof(nr->wbc_ch_width) + sizeof(nr->wbc_center_ch0) +
              sizeof(nr->wbc_center_ch1);

    for(i = 0; i < ftmrr.min_ap_count; i++) {
        nr = (struct neighbor_report_element_arr *)&ftmrr.elem[i];
        nr->sub_element_id = RM_NEIGHBOR_RPT_ELEM_ID;
        nr->sub_element_len = sub_element_len;
        qdf_mem_copy(nr->bssid, &ftmrr_config->elem[i].bssid,
                     IEEE80211_ADDR_LEN);
        nr->bssid_info = ftmrr_config->elem[i].bssid_info;
        nr->opclass = ftmrr_config->elem[i].opclass;
        nr->channel_num = ftmrr_config->elem[i].chan;
        nr->phytype = ftmrr_config->elem[i].phytype;

        nr->wbc_element_id = RM_WIDE_BW_CHANNEL_ELEM_ID;
        nr->wbc_len = wbc_len;
        nr->wbc_ch_width = ftmrr_config->elem[i].chwidth;
        nr->wbc_center_ch0 = ftmrr_config->elem[i].center_ch1;
        nr->wbc_center_ch1 =ftmrr_config->elem[i].center_ch2;
    }

    return ieee80211_lowi_send_ftmrr_frame(psoc, (uint8_t *)&ftmrr);
}

#if ATH_SUPPORT_LOWI
void wifi_pos_send_action_cb(struct wlan_objmgr_psoc *psoc,
                             uint32_t oem_sub_type, uint8_t *req, uint32_t len)
{
    int req_id;

    switch (oem_sub_type) {
    case TARGET_OEM_CONFIGURE_WRU:
        qdf_info("%s: Received Where Are You frame request from LOWI ", __func__);
        ieee80211_lowi_send_wru_frame(psoc, req + LOWI_MESSAGE_WRU_POSITION); //remove subtype(4),req_id(4)
        req_id = *((u_int8_t *)req+LOWI_MESSAGE_REQ_ID_POSITION);
        wifi_pos_send_report_resp(psoc, req_id, req+LOWI_MESSAGE_WRU_POSITION, LOWI_LCI_REQ_WRU_OK);
        return;

    case TARGET_OEM_CONFIGURE_FTMRR:
        qdf_info("%s: Received FTMRR frame request from LOWI ", __func__);
        ieee80211_lowi_send_ftmrr_frame(psoc, req + LOWI_MESSAGE_FTMRR_POSITION); //remove subtype(4),req_id(4)
        req_id = *((u_int8_t *)req+LOWI_MESSAGE_REQ_ID_POSITION);
        wifi_pos_send_report_resp(psoc, req_id, req+LOWI_MESSAGE_FTMRR_POSITION, LOWI_FTMRR_OK);
        return;
    }
}

QDF_STATUS wifi_pos_get_pdev_id_by_dev_name(char *dev_name, uint8_t *pdev_id,
                                            struct wlan_objmgr_psoc **psoc)
{
    struct net_device *dev = NULL;
    wlan_dev_t devhandle = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;

    dev = dev_get_by_name(&init_net, dev_name);
    if (!dev) {
        qdf_err("device %s not Found", dev_name);
        return QDF_STATUS_E_NULL_VALUE;
    }

    devhandle = ath_netdev_priv(dev);
    if (!devhandle) {
        qdf_err("null devhandle");
        goto out;
    }

    pdev = devhandle->ic_pdev_obj;
    if (!pdev) {
        qdf_err("null pdev");
        goto out;
    }

    *pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
    *psoc = wlan_pdev_get_psoc(pdev);
    if (!*psoc) {
        qdf_err("null psoc");
        goto out;
    }

    dev_put(dev);
    return QDF_STATUS_SUCCESS;

out:
    dev_put(dev);
    return QDF_STATUS_E_NULL_VALUE;
}

void wifi_pos_register_cbs(struct wlan_objmgr_psoc *psoc)
{
    wifi_pos_register_send_action(psoc, wifi_pos_send_action_cb);
    wifi_pos_register_get_pdev_id_by_dev_name(psoc, wifi_pos_get_pdev_id_by_dev_name);
}
qdf_export_symbol(wifi_pos_register_cbs);
#endif /* ATH_SUPPORT_LOWI */
