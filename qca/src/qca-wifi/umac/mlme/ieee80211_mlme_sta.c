/*
 * Copyright (c) 2011-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 */

#include "ieee80211_mlme_priv.h"    /* Private to MLME module */
#include <ieee80211_target.h>
#include <ieee80211_mlme_dfs_dispatcher.h>
#include <ieee80211_regdmn.h>
#include <ieee80211_cfg80211.h>
#include <wlan_son_pub.h>
#include <wlan_utility.h>
#include <wlan_lmac_if_api.h>
#include <ieee80211_ev.h>
#include <wlan_cm_public_struct.h>
#include <wlan_cm_blm.h>
#ifdef OL_ATH_SMART_LOGGING
#include <ol_if_athvar.h>
#endif /* OL_ATH_SMART_LOGGING */
#include <wlan_cm_api.h>
#include <wlan_mlme_if.h>
#include <ieee80211_crypto_nlshim_api.h>

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
extern struct ieee80211vap *wlan_get_vap(struct wlan_objmgr_vdev *vdev);
#endif
#endif

static int mlme_assoc_reassoc_request(wlan_if_t vaphandle,
                                      int       reassoc,
                                      u_int8_t  *prev_bssid,
                                      u_int32_t timeout);
static int mlme_process_asresp_elements(struct ieee80211_node *ni,
                                        u_int8_t              *frm,
                                        u_int32_t             ie_len);
static int mlme_process_authresp_ft_elements(struct ieee80211_node *ni,
                                        u_int8_t              *frm,
                                        u_int32_t             ie_len);

static int mlme_process_timeout_interval_elements(struct ieee80211_node *ni,
                                        u_int8_t              *frm,
                                        u_int32_t             ie_len);

#if defined(CONFIG_WIFI_EMULATION_WIFI_3_0)
#define MAX_TSFSYNC_TIME   60000     /* msec */
#else
#define MAX_TSFSYNC_TIME   1500     /* msec */
#endif

QDF_STATUS wlan_mlme_cm_ext_hdl_create(struct wlan_objmgr_vdev *vdev,
                                       cm_ext_t **ext_cm_ptr)
{
    *ext_cm_ptr = qdf_mem_malloc(sizeof(cm_ext_t));
     if (!(*ext_cm_ptr))
         return QDF_STATUS_E_NOMEM;

      qdf_timer_init(NULL, &(*ext_cm_ptr)->cm_defer_resp,
                     mlme_cm_resp_timer, (void *)(vdev),
                     QDF_TIMER_TYPE_WAKE_APPS);

     return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_cm_ext_hdl_destroy(struct wlan_objmgr_vdev *vdev,
                                        cm_ext_t *ext_cm_ptr)
{
     qdf_timer_free(&ext_cm_ptr->cm_defer_resp);
     qdf_mem_free(ext_cm_ptr);

     return QDF_STATUS_SUCCESS;
}

struct scan_cache_entry *mlme_cm_get_active_scan_entry(struct ieee80211vap *vap)
{
    struct wlan_cm_vdev_connect_req req = {0};
    struct wlan_cm_vdev_reassoc_req reassoc_req = {0};

    if (wlan_cm_get_active_req_type(vap->vdev_obj) == CM_ROAM_ACTIVE) {
        wlan_cm_get_active_reassoc_req(vap->vdev_obj, &reassoc_req);
        if (reassoc_req.bss && reassoc_req.bss->entry)
            return reassoc_req.bss->entry;
    } else {
        wlan_cm_get_active_connect_req(vap->vdev_obj, &req);
        if (req.bss && req.bss->entry)
            return req.bss->entry;
    }
    return NULL;
}

struct ieee80211_ath_channel *mlme_cm_get_chosen_chan(struct ieee80211vap *vap)
{
    struct ieee80211_ath_channel *scan_chan = NULL;
    struct ieee80211_ath_channel *chosen_chan = NULL;
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
    struct wlan_cm_vdev_connect_req req = {0};
    struct wlan_cm_vdev_reassoc_req reassoc_req = {0};

    if (wlan_cm_get_active_req_type(vap->vdev_obj) == CM_ROAM_ACTIVE) {
        wlan_cm_get_active_reassoc_req(vap->vdev_obj, &reassoc_req);
        if (reassoc_req.bss && reassoc_req.bss->entry)
            chosen_chan = scan_chan = wlan_util_scan_entry_channel(
                                                reassoc_req.bss->entry);
    } else {
        wlan_cm_get_active_connect_req(vap->vdev_obj, &req);
        if (req.bss && req.bss->entry)
            chosen_chan = scan_chan = wlan_util_scan_entry_channel(req.bss->entry);
    }

    if (!scan_chan)
        return NULL;

    phymode = ieee80211_chan2mode(chosen_chan);

    if (vap->iv_des_mode != IEEE80211_MODE_AUTO) {
        /* if desired mode is not auto then find if the requested mode
         * is supported by the AP
         */
        phymode = ieee80211_get_phy_mode(vap->iv_ic, chosen_chan, vap->iv_des_mode,phymode);
        if (phymode != IEEE80211_MODE_AUTO) {
            chosen_chan = ieee80211_find_dot11_channel(vap->iv_ic, chosen_chan->ic_freq,
                    chosen_chan->ic_vhtop_freq_seg2, phymode | vap->iv_ic->ic_chanbwflag);
            if ((chosen_chan == NULL) || (chosen_chan == IEEE80211_CHAN_ANYC)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s ,can not find a channel with the desired mode \n", __func__);
                chosen_chan = scan_chan;
            }
        }
    }

    return chosen_chan;
}

enum cm_action_debug {
    CM_EV_UNKNOWN,
    CM_EV_BSS_PEER_CREATE_SUCCESS_RESP,
    CM_EV_BSS_PEER_CREATE_FAILURE_RESP,
    CM_EV_BSS_PEER_DELETE_SUCCESS_RESP,
    CM_EV_BSS_PEER_DELETE_FAILURE_RESP,
    CM_EV_CONNECT_RESP,
    CM_EV_DISCONNECT_RESP,
    CM_EV_BSS_PEER_DELETE_IND,
    CM_EV_BSS_PEER_SELECT_IND,
    CM_EV_BSS_PEER_SELECT_IND_FAILURE,
    CM_CMD_BSS_PEER_SELECT_IND,
    CM_CMD_BSS_PEER_CREATE,
    CM_CMD_JOIN_START,
    CM_CMD_DISCONNECT_ACTIVE,
    CM_CMD_BSS_PEER_DELETE,
    CM_TXCHANSWITCH_START,
    CM_TXCHANSWITCH_COMPLETE,
    CM_REPEATER_CAC_START,
    CM_REPEATER_CAC_COMPLETE,
    CM_EV_MAX,
};

const char *wlan_mlme_cm_action_name[CM_EV_MAX + 1] = {
    "UNKNOWN",
    "BSS_PEER_CREATE_SUCCESS",
    "BSS_PEER_CREATE_FAILURE",
    "BSS_PEER_DELETE_SUCCESS",
    "BSS_PEER_DELETE_FAILURE",
    "CONNECT_RESP",
    "DISCONNECT_RESP",
    "BSS_PEER_DELETE_IND",
    "BSS_PEER_SELECT_IND",
    "BSS_PEER_SELECT_IND_FAILURE",
    "BSS_PEER_SELECT_IND_REQ",
    "BSS_PEER_CREATE_REQ",
    "JOIN_START_REQ",
    "DISCONNECT_ACTIVE",
    "BSS_PEER_DELETE_REQ",
    "TXCHANSWITCH_START",
    "TXCHANSWITCH_COMPLETE",
    "REPEATER_CAC_START",
    "REPEATER_CAC_COMPLETE",
    "EV_MAX"

};

#if SM_ENG_HIST_ENABLE
void wlan_mlme_cm_action_history_init(struct ieee80211vap *vap)
{
    cm_ext_t *cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);

    if (!cm_ext_handle)
        return;

    qdf_spinlock_create(&cm_ext_handle->cm_action_history.cm_history_lock);
    qdf_mem_zero(&cm_ext_handle->cm_action_history, sizeof(struct wlan_cm_action_entry));
}

void wlan_mlme_cm_action_history_deinit(struct ieee80211vap *vap)
{
    cm_ext_t *cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);

    if (!cm_ext_handle)
        return;

    qdf_spinlock_destroy(&cm_ext_handle->cm_action_history.cm_history_lock);
}

static void wlan_mlme_cm_action_save_history(struct ieee80211vap *vap,
                                      uint8_t event, QDF_STATUS status)
{
    cm_ext_t *cm_ext_handle = NULL;
    struct wlan_cm_action_history *cm_action_history = NULL;
    struct wlan_cm_action_entry *data = NULL;

    cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);
    if (!cm_ext_handle)
        return;

    cm_action_history = &cm_ext_handle->cm_action_history;
    data = &cm_action_history->data[cm_action_history->index];

    qdf_spin_lock_bh(&cm_action_history->cm_history_lock);
    cm_action_history->index++;
    cm_action_history->index %= WLAN_CM_EVENT_HISTORY_SIZE;
    qdf_mem_zero(data, sizeof(struct wlan_cm_action_entry));

    data->event = event;
    data->status = status;
    data->time = qdf_get_log_timestamp();
    qdf_spin_unlock_bh(&cm_action_history->cm_history_lock);
}

static inline void
wlan_mlme_cm_print_history_entry(struct wlan_cm_action_entry *data, uint8_t idx)
{
    if (!data->event)
        return;

    wlan_mlme_nofl_err("| 0x%016llx |%6d |%28s |%6d |",
                       data->time, idx, wlan_mlme_cm_action_name[data->event],
                       data->status);
}

void wlan_mlme_cm_action_print_history(struct wlan_cm_action_history *cm_action_history)
{
    uint8_t i, idx;
    qdf_spin_lock_bh(&cm_action_history->cm_history_lock);

    wlan_mlme_nofl_err("|%19s |%6s |%28s |%6s |","Time", "Index", "Event", "Status");

    for (i = 0; i < WLAN_CM_EVENT_HISTORY_SIZE; i++) {
         idx = (cm_action_history->index + i) % WLAN_CM_EVENT_HISTORY_SIZE;
         wlan_mlme_cm_print_history_entry(&cm_action_history->data[idx], idx);
    }
    qdf_spin_unlock_bh(&cm_action_history->cm_history_lock);
}
#else
static inline void wlan_mlme_cm_action_save_history(struct ieee80211vap *vap, uint8_t event,
                                             QDF_STATUS status)
{}
#endif

void mlme_cm_connect_rsp(struct ieee80211vap *vap)
{
     struct ieee80211_ath_channel *chan = NULL;
     enum wlan_cm_active_request_type active_req;
     struct wlan_cm_vdev_connect_req req = {0};
     struct wlan_cm_vdev_reassoc_req reassoc_req = {0};
     cm_ext_t *cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);

     if (!cm_ext_handle)
         return;

     qdf_debug("Connect Resp: vdev: %d, Status: %d, Reason: %d",
               wlan_vdev_get_id(vap->vdev_obj),
               cm_ext_handle->cm_conn_rsp.connect_status,
               cm_ext_handle->cm_conn_rsp.reason);

     cm_ext_handle->cm_conn_rsp.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
     cm_ext_handle->cm_conn_rsp.aid = vap->iv_bss->ni_associd;
     cm_ext_handle->cm_conn_rsp.connect_ies.assoc_req.ptr = NULL;
     cm_ext_handle->cm_conn_rsp.connect_ies.assoc_req.len = 0;
     cm_ext_handle->cm_conn_rsp.connect_ies.assoc_rsp.ptr = vap->iv_sta_assoc_resp_ie;
     cm_ext_handle->cm_conn_rsp.connect_ies.assoc_rsp.len = vap->iv_sta_assoc_resp_len;
     chan = mlme_cm_get_chosen_chan(vap);
     if (chan)
         cm_ext_handle->cm_conn_rsp.freq = chan->ic_freq;

     active_req = wlan_cm_get_active_req_type(vap->vdev_obj);
     if (active_req == CM_ROAM_ACTIVE) {
         wlan_cm_get_active_reassoc_req(vap->vdev_obj, &reassoc_req);
         if (reassoc_req.bss && reassoc_req.bss->entry) {
              qdf_mem_copy(cm_ext_handle->cm_conn_rsp.bssid.bytes,
                           util_scan_entry_macaddr(reassoc_req.bss->entry),
                           sizeof(struct qdf_mac_addr));
         }

         cm_ext_handle->cm_conn_rsp.is_reassoc = true;
         wlan_cm_reassoc_rsp(vap->vdev_obj, &cm_ext_handle->cm_conn_rsp);
     } else {
         wlan_cm_get_active_connect_req(vap->vdev_obj, &req);
         if (req.bss && req.bss->entry) {
             qdf_mem_copy(cm_ext_handle->cm_conn_rsp.bssid.bytes,
                          util_scan_entry_macaddr(req.bss->entry),
                          sizeof(struct qdf_mac_addr));
         }
         wlan_cm_connect_rsp(vap->vdev_obj, &cm_ext_handle->cm_conn_rsp);
     }
}

void mlme_cm_disconnect_rsp(struct ieee80211vap *vap)
{
     cm_ext_t *cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);
     if (!cm_ext_handle)
         return;

     qdf_debug("Disconnect Resp: Vdev: %d, Source: %d, Reason: %d",
               wlan_vdev_get_id(vap->vdev_obj),
               cm_ext_handle->cm_discon_rsp.req.req.source,
               cm_ext_handle->cm_discon_rsp.req.req.reason_code);
     cm_ext_handle->cm_discon_rsp.ap_discon_ie.ptr = NULL;
     cm_ext_handle->cm_discon_rsp.ap_discon_ie.len = 0;
     wlan_cm_disconnect_rsp(vap->vdev_obj, &cm_ext_handle->cm_discon_rsp);
}

void mlme_cm_resp_timer(void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)arg;
    struct ieee80211vap *vap = NULL;
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    cm_ext_t *cm_ext_handle = NULL;

    if (!vdev)
        return;

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return;

    cm_ext_handle = wlan_cm_get_ext_hdl(vdev);
    if (!cm_ext_handle)
        return;

    qdf_debug("CM resp event %d vdev_id %d",cm_ext_handle->cm_evt_id,
              wlan_vdev_get_id(vdev));

    if (cm_ext_handle->cm_evt_id == CM_CONNECT_RESP)
        status = cm_ext_handle->cm_conn_rsp.connect_status;

    wlan_mlme_cm_action_save_history(vap, (cm_ext_handle->cm_evt_id + 1), status);

    switch (cm_ext_handle->cm_evt_id) {
    case CM_BSS_PEER_CREATE_SUCCESS_RESP:
         wlan_cm_bss_peer_create_rsp(vdev, QDF_STATUS_SUCCESS, NULL);
         break;
    case CM_BSS_PEER_CREATE_FAILURE_RESP:
         wlan_cm_bss_peer_create_rsp(vdev, QDF_STATUS_E_FAILURE, NULL);
         break;
    case CM_BSS_PEER_DELETE_SUCCESS_RESP:
         wlan_cm_bss_peer_delete_rsp(vdev, QDF_STATUS_SUCCESS);
         break;
    case CM_CONNECT_RESP:
         mlme_cm_connect_rsp(vap);
         break;
    case CM_DISCONNECT_RESP:
         mlme_cm_disconnect_rsp(vap);
         break;
    case CM_BSS_PEER_SELECT_IND:
         wlan_cm_bss_select_ind_rsp(vdev, QDF_STATUS_SUCCESS);
         break;
    case CM_BSS_PEER_SELECT_IND_FAILURE:
         wlan_cm_bss_select_ind_rsp(vdev, QDF_STATUS_E_FAILURE);
         break;
    case CM_BSS_PEER_DELETE_IND:
         wlan_cm_bss_peer_delete_ind(vdev,
                                     (struct qdf_mac_addr *)vap->iv_bss->ni_macaddr);
         break;
    default:
         break;
    }
}

QDF_STATUS wlan_mlme_cm_join_start(struct wlan_objmgr_vdev *vdev, struct wlan_cm_vdev_connect_req *req)
{
    struct ieee80211vap *vap;
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);

    if (!vap)
        return QDF_STATUS_E_FAILURE;

    if (wlan_mlme_join_infra_continue(vap, req->bss->entry, MAX_TSFSYNC_TIME) != 0 ) {
        IEEE80211_DPRINTF(vap,IEEE80211_MSG_STATE,"%s: join_infra failed \n",__func__);
        /*
         * Since VAP bring up failed, delete the earlier created bss peer
         */
        ieee80211_reset_bss(vap);
        wlan_mlme_cancel(vap);
        status = QDF_STATUS_E_FAILURE;
    }
    wlan_mlme_cm_action_save_history(vap, CM_CMD_JOIN_START,
                              status);
    return status;
}

QDF_STATUS wlan_mlme_cm_reassoc_join_start(
                    struct wlan_objmgr_vdev *vdev,
                    struct wlan_cm_vdev_reassoc_req *req)
{
    struct ieee80211vap *vap = NULL;
    cm_ext_t *cm_ext_handle = NULL;

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    cm_ext_handle = wlan_cm_get_ext_hdl(vdev);
    if (!cm_ext_handle)
        return QDF_STATUS_E_FAILURE;

    cm_ext_handle->cm_conn_rsp.cm_id = req->cm_id;

    if (wlan_mlme_join_infra_continue(vap, req->bss->entry,
                                      MAX_TSFSYNC_TIME) != 0 ) {
        IEEE80211_DPRINTF(vap,IEEE80211_MSG_STATE,
                "%s: join_infra failed \n",__func__);
        ieee80211_reset_bss(vap);
        wlan_mlme_cancel(vap);
        return QDF_STATUS_E_FAILURE;
    }

    return QDF_STATUS_SUCCESS;
}

static void wlan_mlme_join_setting_country_handler(void *osif, IEEE80211_STATUS status)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)osif;

    if (status == IEEE80211_STATUS_SUCCESS) {
        wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_CREATE_SUCCESS_RESP);
    } else {
        wlan_mlme_cancel(vap);
        wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_CREATE_FAILURE_RESP);
    }
}

QDF_STATUS wlan_mlme_cm_ext_bss_peer_create_req(struct wlan_objmgr_vdev *vdev,
                                                struct qdf_mac_addr *peer_mac)
{
    struct ieee80211vap *vap;
    u_int8_t *se_macaddr;
    struct ieee80211_node *ni = NULL;
    struct wlan_objmgr_peer *peer = NULL;
    struct wlan_cm_vdev_connect_req req = {0};
    struct wlan_cm_vdev_reassoc_req reassoc_req = {0};
    struct scan_cache_entry *entry = NULL;
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    if (wlan_cm_get_active_req_type(vdev) == CM_ROAM_ACTIVE) {
        wlan_cm_get_active_reassoc_req(vdev, &reassoc_req);
        if (!reassoc_req.bss || !reassoc_req.bss->entry){
            status = QDF_STATUS_E_FAILURE;
            goto exit;
        }
        entry = reassoc_req.bss->entry;
    } else {
        wlan_cm_get_active_connect_req(vap->vdev_obj, &req);

        if (!req.bss || !req.bss->entry) {
            status = QDF_STATUS_E_FAILURE;
            goto exit;
        }
        entry = req.bss->entry;
    }

    se_macaddr = util_scan_entry_macaddr(entry);
    if (qdf_mem_cmp(se_macaddr, peer_mac, QDF_MAC_ADDR_SIZE)) {
        status = QDF_STATUS_E_FAILURE;
        goto exit;
    }

    peer = ieee80211_lookup_peer_by_mac(vap->iv_ic, se_macaddr);
    if ((peer != NULL) && (WLAN_PEER_STA == wlan_peer_get_peer_type(peer))) {
        /*
         * Node is present on another VAP and possibly on different radio
         * peer with same mac address cannot be created across SoC for HKv1
         *
         */
        qdf_warn("%s:peer with same mac address cannot be created across SoC\n",__func__);
        wlan_objmgr_peer_release_ref(peer, WLAN_MGMT_HANDLER_ID);
        status = QDF_STATUS_E_FAILURE;
        goto exit;
    }

    /* release the refrence taken for peer !WLAN_PEER_STA */
    if (peer != NULL) {
        wlan_objmgr_peer_release_ref(peer, WLAN_MGMT_HANDLER_ID);
    }

    /* assoc sm RUN to JOIN state transition requires to wait
     * for previous peer being deleted and new connection
     * attempt being started once peer delete resonse is received.
     */
    ni = ieee80211_vap_find_node(vap, se_macaddr, WLAN_MLME_SB_ID);
    if (ni) {
        qdf_info("%s: vap:%d(0x%pK), previous node: 0x%pK:%s found."
                 " delete it first", __func__, vap->iv_unit, vap,
                 ni, ether_sprintf(se_macaddr));
        qdf_info("vap->iv_myaddr: %s", ether_sprintf(vap->iv_myaddr));
        /* Free previous peer */
        ieee80211_sta_leave(ni);
        ieee80211_free_node(ni, WLAN_MLME_SB_ID);
        /* Not expected to hit this scenario. Added assert for debug purpose */
        QDF_ASSERT(0);
    }

    ieee80211_reset_bss(vap);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                      "%s: vap:%d(0x%pK), continue to JOIN_COMPLETE\n",
                      __func__, vap->iv_unit, vap);
    if (wlan_mlme_join_infra(vap, entry, MAX_TSFSYNC_TIME) != 0 ) {
        IEEE80211_DPRINTF(vap,IEEE80211_MSG_STATE,"%s: join_infra failed \n",__func__);
        wlan_mlme_join_setting_country_handler((void*)vap, IEEE80211_STATUS_UNSPECIFIED);
    }
exit:
    wlan_mlme_cm_action_save_history(vap, CM_CMD_BSS_PEER_CREATE,
                              status);
    return status;
}

static void wlan_mlme_repeater_cac_handler(void *osif, IEEE80211_STATUS status);

#define MAX_TXCSA_TIME     1000    /* msec */
static void wlan_mlme_txchanswitch_handler(void *osif, IEEE80211_STATUS status)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)osif;
    struct ieee80211_ath_channel *chan = NULL;

    wlan_mlme_cancel_txchanswitch_timer(vap);
    wlan_mlme_cm_action_save_history(vap, CM_TXCHANSWITCH_COMPLETE,
                               status);
    chan = mlme_cm_get_chosen_chan(vap);
    if (!chan) {
        wlan_mlme_cancel(vap);
        wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_SELECT_IND_FAILURE);
        return;
    }

#if ATH_SUPPORT_DFS
    if(wlan_mlme_is_repeater_cac_set(vap) &&
       wlan_mlme_is_scanentry_dfs(chan)) {
       if (wlan_mlme_start_repeater_cac(vap, chan) != 0 ) {
           IEEE80211_DPRINTF(vap,IEEE80211_MSG_STATE,"%s: repeater cac failed \n",__func__);
           wlan_mlme_repeater_cac_handler((void *)vap, IEEE80211_STATUS_UNSPECIFIED);
           return;
       }
    } else
#endif
    {
        wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_SELECT_IND);
    }
    return;
}

static void wlan_mlme_repeater_cac_handler(void *osif, IEEE80211_STATUS status)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)osif;
    struct ieee80211_ath_channel *chan = NULL;
    struct wlan_cm_vdev_connect_req req = {0};

    wlan_mlme_cancel_repeater_cac_timer(vap);
    wlan_mlme_cm_action_save_history(vap, CM_REPEATER_CAC_COMPLETE,
                               status);
    if (status == IEEE80211_STATUS_SUCCESS) {
        /* If AP VAP comes up first, let's say in channel 100, then AP VAP is
         * doing CAC. In the mean time if STA VAP found Root AP in channel 60
         * then STA thinks that AP is doing CAC in channel 60. Since AP VAP is
         * still in DFS_WAIT number of AP VAP running is zero and therefore
         * TXCSA does not happen. If TXCSA does not happen after CAC AP VAP
         * comes up in channel 100 and STA comes up in channel 60. And STA
         * does not detect a beacon miss.
         */
        chan = mlme_cm_get_chosen_chan(vap);
        if (!chan) {
            wlan_mlme_cancel(vap);
            wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_SELECT_IND_FAILURE);
            return;
        }
        /* if STA's target channel and AP channels are different after CAC then go to TXSwitch again */
        if(wlan_mlme_is_chosen_diff_from_curchan(vap, chan)) {
           if (wlan_mlme_start_txchanswitch(vap, chan, MAX_TXCSA_TIME) != 0 ) {
               IEEE80211_DPRINTF(vap,IEEE80211_MSG_STATE,"%s: txchanswitch failed \n",__func__);
               wlan_mlme_txchanswitch_handler((void*)vap, IEEE80211_STATUS_NOT_ASSOCED);//IEEE80211_STATUS_UNSPECIFIED);
               return;
           }
       } else {
               wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_SELECT_IND);
         }
    } else {
        wlan_cm_get_active_connect_req(vap->vdev_obj, &req);
        if (req.bss && req.bss->entry)
            wlan_util_scan_entry_mlme_set_assoc_state(req.bss->entry, AP_ASSOC_STATE_NONE);

        wlan_mlme_cancel(vap);
        wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_SELECT_IND_FAILURE);
    }
    return;
}

QDF_STATUS wlan_mlme_cm_vdev_down(struct wlan_objmgr_vdev *vdev)
{
   wlan_vdev_mlme_sm_deliver_evt(
            vdev, WLAN_VDEV_SM_EV_MLME_DOWN_REQ,
            0, NULL);

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_cm_bss_peer_delete_req(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap;

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    wlan_mlme_cm_action_save_history(vap, CM_CMD_BSS_PEER_DELETE,
                              QDF_STATUS_SUCCESS);
    ieee80211_reset_bss(vap);
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_cm_connect_start(struct wlan_objmgr_vdev *vdev,
                                      struct wlan_cm_connect_req *cm_conn_req)
{
    struct ieee80211vap *vap;

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    if (wlan_reg_is_6ghz_chan_freq(cm_conn_req->chan_freq)) {
        if (wlan_6ghz_security_check(vap, cm_conn_req->crypto.akm_suites,
                    cm_conn_req->crypto.rsn_caps) != EOK) {
            qdf_warn("Error in 6GHz secuirty configured !!");
            return QDF_STATUS_E_FAILURE;
        }
    }

    return QDF_STATUS_SUCCESS;
}

/**
 * wlan_mlme_check_psta_chan - For QWRAP mode compare channel for mpsta and psta
 * @vap: legacy vap handle
 * @chan: pointer to the channel
 *
 * Return: success if chan is same, else return failure
 */
#if ATH_SUPPORT_WRAP
static QDF_STATUS
wlan_mlme_check_psta_chan(struct ieee80211vap *vap,
                          struct ieee80211_ath_channel *chan)
{
    struct ieee80211vap *mpstavap;
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t scan_chan_freq;
    uint32_t mpstavap_chan_freq;

    if (ieee80211_ic_enh_ind_rpt_is_set(ic)){
        /* For QWRAP mode enabled, and non mpsta,
         * check the channel for mpsta and psta is same
         */
#if WLAN_QWRAP_LEGACY
        if (ic->ic_mpsta_vap && !vap->iv_mpsta) {
            mpstavap = ic->ic_mpsta_vap;
#else
        if (dp_wrap_get_mpsta_vdev(ic->ic_pdev_obj) && !dp_wrap_vdev_is_mpsta(vap->vdev_obj)) {
            mpstavap = wlan_get_vap(dp_wrap_get_mpsta_vdev(ic->ic_pdev_obj));
            if (!mpstavap)
                return QDF_STATUS_E_FAILURE;
#endif
            scan_chan_freq = ieee80211_channel_frequency(chan);
            mpstavap_chan_freq = ieee80211_channel_frequency(mpstavap->iv_bsschan);

            if (scan_chan_freq != mpstavap_chan_freq) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE,
                                  "%s: scan_entry chan %u freq %d,"
                                  "ivbss_chan %u freq %d \n", __func__,
                                  chan->ic_ieee,
                                  scan_chan_freq,
                                  mpstavap->iv_bsschan->ic_ieee,
                                  mpstavap_chan_freq);

                return QDF_STATUS_E_FAILURE;
            }
        }
    }
    return QDF_STATUS_SUCCESS;
}
#else
static inline QDF_STATUS
wlan_mlme_check_psta_chan(struct ieee80211vap *vap,
                          struct ieee80211_ath_channel *chan)
{
    return QDF_STATUS_SUCCESS;
}
#endif

QDF_STATUS wlan_mlme_cm_connect_active(struct wlan_objmgr_vdev *vdev,
                                       struct wlan_cm_vdev_connect_req *req)
{
    struct ieee80211vap *vap;
    wlan_scan_entry_t scan_entry;
    struct ieee80211_ath_channel *scan_chan;
    struct ieee80211_ath_channel *chosen_chan = NULL;
    struct wlan_objmgr_pdev *pdev;
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    cm_ext_t *cm_ext_handle = wlan_cm_get_ext_hdl(vdev);

    if (!cm_ext_handle)
        return QDF_STATUS_E_FAILURE;

    scan_entry = req->bss->entry;
    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap || !vap->iv_ic) {
        status = QDF_STATUS_E_FAILURE;
        goto fail;
    }
    qdf_mem_zero(&cm_ext_handle->cm_conn_rsp, sizeof(struct wlan_cm_connect_resp));
    cm_ext_handle->cm_conn_rsp.cm_id = req->cm_id;
    scan_chan = wlan_util_scan_entry_channel(scan_entry);
    if (!scan_chan) {
        status = QDF_STATUS_E_FAILURE;
        goto end;
    }

    status = wlan_mlme_check_psta_chan(vap, scan_chan);
    if (QDF_IS_STATUS_ERROR(status))
         goto end;

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (vap->iv_ic->ic_mpsta_vap && vap->iv_mpsta)
#else
    if (dp_wrap_get_mpsta_vdev(vap->iv_ic->ic_pdev_obj) && dp_wrap_vdev_is_mpsta(vap->vdev_obj))
#endif
        wlan_cm_set_max_connect_attempts(vdev, 1);
#endif

    chosen_chan = mlme_cm_get_chosen_chan(vap);
    if (!chosen_chan) {
        status = QDF_STATUS_E_FAILURE;
        goto end;
    }

    pdev = vap->iv_ic->ic_pdev_obj;
    if(pdev == NULL) {
       qdf_err("%s : pdev is null", __func__);
       status = QDF_STATUS_E_FAILURE;
       goto end;
    }

    /* Go for Tx CSA when all of the following are true:
     * 1)Tx CSA is set by the user.
     * 2)Enhanced Independent Repeater  is set by the user.
     * 3)The STA is the main STA (either regular STA or main proxy STA).
     * 4)There is at least on AP running/beaconing.
     * 5)When the chosen phy channel and current channel is different.
     */
    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
        QDF_STATUS_SUCCESS) {
        status = QDF_STATUS_E_FAILURE;
        goto end;
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
               "%s : TXCSA = %d RepCAC = %d Enh_ind = %d Mainsta = %d apvap = %d chosen_diff = %d apcac = %d\n", __func__,
                wlan_mlme_is_txcsa_set(vap) ,
                wlan_mlme_is_repeater_cac_set(vap),
                wlan_get_param(vap,IEEE80211_FEATURE_VAP_ENHIND) ,
                wlan_mlme_is_vap_main_sta(vap) ,
                wlan_mlme_num_apvap_running(vap),
                wlan_mlme_is_chosen_diff_from_curchan(vap,chosen_chan),
                mlme_dfs_is_ap_cac_timer_running(pdev)
                );
    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    if(wlan_get_param(vap,IEEE80211_FEATURE_VAP_ENHIND) &&
       wlan_mlme_is_vap_main_sta(vap) &&
       wlan_mlme_num_apvap_running(vap) &&
       wlan_mlme_is_chosen_diff_from_curchan(vap,chosen_chan)) {
       if (wlan_mlme_start_txchanswitch(vap, chosen_chan, MAX_TXCSA_TIME) != 0 ) {
           IEEE80211_DPRINTF(vap,IEEE80211_MSG_STATE,"%s: txchanswitch failed \n",__func__);
           wlan_mlme_txchanswitch_handler((void*)vap, IEEE80211_STATUS_CAPINFO);//IEEE80211_STATUS_UNSPECIFIED);
           status = QDF_STATUS_SUCCESS;
           goto end;
       }
    } else {
        /* If it is coming here for second time that is after txcsa is over
         * we need to see if the CAC timer is running then wait for the CAC
         */
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                  QDF_STATUS_SUCCESS) {
            status = QDF_STATUS_E_FAILURE;
            goto end;
        }
        if(wlan_mlme_is_repeater_cac_set(vap) &&
           wlan_mlme_is_scanentry_dfs(chosen_chan) &&
           mlme_dfs_is_ap_cac_timer_running(pdev)) {
           wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
           if (wlan_mlme_start_repeater_cac(vap, chosen_chan) != 0 ) {
               IEEE80211_DPRINTF(vap,IEEE80211_MSG_STATE,"%s: repeater cac failed \n",__func__);
               wlan_mlme_repeater_cac_handler((void*)vap, IEEE80211_STATUS_UNSPECIFIED);
               status = QDF_STATUS_SUCCESS;
               goto end;
           }
        } else {
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_SELECT_IND);
        }
    }
end:
    wlan_mlme_cm_action_save_history(vap, CM_CMD_BSS_PEER_SELECT_IND,
                              status);
fail:
    return status;
}

/**
 * wlan_mlme_smart_log_connection_fail_stop - Stop connection failure smart logging
 * @ic: legacy ic handle
 *
 * Return: void
 */
#ifdef OL_ATH_SMART_LOGGING
static void wlan_mlme_smart_log_connection_fail_stop(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ol_if_offload_ops *ol_if_ops = NULL;

    if (ic != NULL) {
        scn = OL_ATH_SOFTC_NET80211(ic);
    }

    if (scn && scn->soc) {
        ol_if_ops = scn->soc->ol_if_ops;
    }

    if (ol_if_ops && ol_if_ops->smart_log_connection_fail_stop) {
        /*
         * Currently, we will not alter the rest of the state machine flow
         * based on whether we succeeded or failed in stopping connection
         * failure logging. Hence we do not check for failure. We rely on
         * the API to print failure messages if any. Engineering action
         * would have to be taken separately to analyze logging API
         * failures.
         * We also rely on the API to determine whether the logging is
         * required.
         */
	    ol_if_ops->smart_log_connection_fail_stop(scn);
    }
}
#else
static inline
void wlan_mlme_smart_log_connection_fail_stop(struct ieee80211com *ic)
{
}
#endif

QDF_STATUS wlan_mlme_cm_connect_complete(struct wlan_objmgr_vdev *vdev,
                                         struct wlan_cm_connect_resp *resp)
{
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    struct mlme_info mlme_info = {0};
    struct bss_info bss_info;
    struct ieee80211vap *vap;
    struct ieee80211com *ic;

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    ic = vap->iv_ic;

    qdf_copy_macaddr(&bss_info.bssid, &resp->bssid);
    bss_info.freq = resp->freq;
    bss_info.ssid.length = resp->ssid.length;
    qdf_mem_copy(&bss_info.ssid.ssid, resp->ssid.ssid,
                 bss_info.ssid.length);

     if (resp->connect_status == QDF_STATUS_SUCCESS) {
         mlme_info.status = AP_STATE_GOOD;
         wlan_mlme_smart_log_connection_fail_stop(ic);
     } else {
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
              if ((ic != NULL) &&
                  ((ic->ic_mpsta_vap == NULL) ||
                  (ic->ic_mpsta_vap && vap->iv_mpsta)))
#else
              if ((ic != NULL) &&
                  ((dp_wrap_get_mpsta_vdev(ic->ic_pdev_obj) == NULL) ||
                  (dp_wrap_get_mpsta_vdev(ic->ic_pdev_obj) &&
                   dp_wrap_vdev_is_mpsta(vap->vdev_obj))))
#endif
#endif
              {
                  mlme_info.status = AP_STATE_BAD;
                  mlme_info.bad_ap_time = qdf_system_ticks();
              }
     }

     wlan_scan_update_mlme_by_bssinfo(wlan_vdev_get_pdev(vdev),
                                      &bss_info, &mlme_info);
     return status;
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
QDF_STATUS wlan_mlme_cm_disconnect_start(struct wlan_objmgr_vdev *vdev,
                                         struct wlan_cm_disconnect_req *req)
{
    struct ieee80211vap *vap;
    enum wlan_vdev_state state;
    enum wlan_vdev_state substate;

    /* Action on disconnect request to serialization.
     * If STA CAC is enabled and CM is in join_active state, then
     * active command is not flushed. Hence dispatch EV_DOWN to abort
     * connect request.
     */
    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    if ((wlan_cm_get_active_req_type(vdev) == CM_CONNECT_ACTIVE) &&
            mlme_is_stacac_needed(vap)) {
        wlan_mlme_stop_bss(vap, 0);
        state = wlan_vdev_mlme_get_state(vdev);
        substate = wlan_vdev_mlme_get_substate(vdev);
        if ((state == WLAN_VDEV_S_START) &&
                ((substate == WLAN_VDEV_SS_START_RESTART_PROGRESS) ||
                 (substate == WLAN_VDEV_SS_START_START_PROGRESS)))
            wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_DOWN, 0, NULL);
    }

    return QDF_STATUS_SUCCESS;
}
#else
QDF_STATUS wlan_mlme_cm_disconnect_start(struct wlan_objmgr_vdev *vdev,
                                         struct wlan_cm_disconnect_req *req)
{
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    /* Action on disconnect request to serialization */
    return status;
}
#endif

QDF_STATUS wlan_mlme_cm_disconnect_active(struct wlan_objmgr_vdev *vdev,
                                          struct wlan_cm_vdev_discon_req *req)
{
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    struct ieee80211vap *vap;
    cm_ext_t *cm_ext_handle = NULL;
    enum wlan_vdev_state state;
    enum wlan_vdev_state substate;

    /* Action on disconnect request activation*/
    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap)
        return QDF_STATUS_E_FAILURE;

    cm_ext_handle = wlan_cm_get_ext_hdl(vdev);
    if (!cm_ext_handle)
        return QDF_STATUS_E_FAILURE;

    wlan_mlme_cm_action_save_history(vap, CM_CMD_DISCONNECT_ACTIVE,
                              status);
    qdf_mem_zero(&cm_ext_handle->cm_discon_rsp, sizeof(struct wlan_cm_discon_rsp));
    qdf_mem_copy(&cm_ext_handle->cm_discon_rsp.req, req, sizeof(struct wlan_cm_vdev_discon_req));
    wlan_mlme_stop_bss(vap, 0);

    state = wlan_vdev_mlme_get_state(vdev);
    substate = wlan_vdev_mlme_get_substate(vdev);
    if ((state == WLAN_VDEV_S_START) &&
        ((substate == WLAN_VDEV_SS_START_RESTART_PROGRESS) ||
        (substate == WLAN_VDEV_SS_START_START_PROGRESS)))
        wlan_vdev_mlme_sm_deliver_evt(vap->vdev_obj, WLAN_VDEV_SM_EV_DOWN, 0, NULL);
    return status;
}

QDF_STATUS wlan_mlme_cm_disconnect_complete(struct wlan_objmgr_vdev *vdev,
                                            struct wlan_cm_discon_rsp *rsp)
{
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    /* Action on disconnect complete(sucess/failure) */
    return status;
}

enum mlme_req mlme_get_active_req_type(struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    return mlme_priv->im_request_type;
}

static void
wlan_mlme_deauth_indication_sta(void *osif, u_int8_t *macaddr,
                                u_int16_t associd, u_int16_t reason)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)osif;
    struct wlan_objmgr_vdev *vdev;

    vdev = vap->vdev_obj;

    if (wlan_cm_is_vdev_connected(vdev)) {
        wlan_cm_disconnect(vap->vdev_obj, CM_SB_DISCONNECT,
                           REASON_DEAUTH_NETWORK_LEAVING, NULL);
    }
}

static void wlan_mlme_disassoc_indication_sta(void *osif,
                                              u_int8_t *macaddr,
                                              u_int16_t associd,
                                              u_int32_t reason)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)osif;
    struct wlan_objmgr_vdev *vdev;

    vdev = vap->vdev_obj;

    if (wlan_cm_is_vdev_connected(vdev)) {
        wlan_cm_disconnect(vap->vdev_obj, CM_SB_DISCONNECT,
                           REASON_DISASSOC_NETWORK_LEAVING, NULL);
    }
}

static void wlan_mlme_beacon_miss(void *osif)
{
    struct ieee80211vap *vap = (struct ieee80211vap *)osif;
    struct wlan_objmgr_vdev *vdev;

    vdev = vap->vdev_obj;

    if (wlan_cm_is_vdev_connected(vdev)) {
        wlan_cm_disconnect(vap->vdev_obj, CM_SB_DISCONNECT,
                           REASON_BEACON_MISSED, NULL);
    }
}

wlan_mlme_event_handler_table sta_cm_mlme_evt_handler = {
    wlan_mlme_join_setting_country_handler,   /* mlme_join_complete_set_country */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    wlan_mlme_txchanswitch_handler,           /* mlme_txchanswitch_complete */
    wlan_mlme_repeater_cac_handler,           /* mlme_repeater_cac_complete */
    NULL,
    wlan_mlme_deauth_indication_sta,
    NULL,
    NULL,
    wlan_mlme_disassoc_indication_sta,
};

static wlan_misc_event_handler_table sta_cm_misc_evt_handler = {
    NULL,                                     /* wlan_channel_change */
    NULL,                                     /* wlan_country_changed */
    NULL,                                     /* wlan_linkspeed */
    NULL,                                     /* wlan_michael_failure_indication */
    NULL,                                     /* wlan_replay_failure_indication */
    wlan_mlme_beacon_miss,                    /* wlan_beacon_miss_indication */
};

static void wlan_mlme_cm_update_advance_filter(struct wlan_objmgr_vdev *vdev,
                                               struct scan_filter *filter)
{
    wlan_cm_update_advance_filter(vdev, filter);
}

static void wlan_mlme_cm_candidate_list_custom_sort(struct wlan_objmgr_vdev *vdev,
                                                    qdf_list_t *candidate_list)
{
    wlan_cm_candidate_list_custom_sort(vdev, candidate_list);
}

void wlan_mlme_cm_event_init(struct ieee80211vap *vap)
{
    wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)vap,&sta_cm_mlme_evt_handler);
    wlan_vap_register_misc_event_handlers(vap,(os_handle_t)vap,&sta_cm_misc_evt_handler);
    wlan_cm_set_candidate_advance_filter_cb(vap->vdev_obj,
                                            wlan_mlme_cm_update_advance_filter);
    wlan_cm_set_candidate_custom_sort_cb(vap->vdev_obj,
                                         wlan_mlme_cm_candidate_list_custom_sort);
}

void wlan_mlme_cm_event_deinit(struct ieee80211vap *vap)
{
    wlan_vap_register_mlme_event_handlers(vap,(os_handle_t)vap,&sta_cm_mlme_evt_handler);
    wlan_vap_register_misc_event_handlers(vap,(os_handle_t)vap,&sta_cm_misc_evt_handler);
}


static void wlan_mlme_vdev_txcsa_start_notify(struct wlan_objmgr_pdev *pdev,
                                              void *object, void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ieee80211_ath_channel *scan_entry_chan = arg;
    struct ieee80211_ath_channel *new_chan = scan_entry_chan;

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic)
        return;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return;

    if(vap->iv_opmode == IEEE80211_M_HOSTAP ||
       vap->iv_opmode == IEEE80211_M_MONITOR){
       vap->iv_no_cac = 1;

       /*
        * Configure MAX supported phy for rpt AP VAP.
        * For ind_rpt, AP VAP comes up first based on
        * scan_entry_chan. scan_entry_chan has phy mode
        * that root AP can support. Overwriter it with
        * rpt AP VAP's phy mode
        */
        if (ieee80211_ic_enh_ind_rpt_is_set(ic)) {
            new_chan = ieee80211_use_max_phy_for_rep_ap(vap, scan_entry_chan);
            if (!new_chan) {
                new_chan = scan_entry_chan;
            }
        }
        if (wlan_vdev_chan_config_valid(vdev) == QDF_STATUS_SUCCESS) {
            wlan_pdev_mlme_vdev_sm_seamless_chan_change(ic->ic_pdev_obj,
                                                        vap->vdev_obj, new_chan);
        }
    }
}

int wlan_mlme_start_txchanswitch(wlan_if_t vaphandle, struct ieee80211_ath_channel *scan_entry_chan, u_int32_t timeout)
{

    struct ieee80211vap           *vap = vaphandle;
    struct ieee80211com           *ic = vap->iv_ic;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    u_int32_t                     tx_csa_complete_timeout = 0;

    if(!(ic->ic_flags & IEEE80211_F_CHANSWITCH)) {
         wlan_mlme_cm_action_save_history(vap,
                                   CM_TXCHANSWITCH_START,
                                   QDF_STATUS_SUCCESS);
        mlme_priv->im_request_type = MLME_REQ_TXCSA;
        tx_csa_complete_timeout = timeout;
        OS_SET_TIMER(&mlme_priv->im_timeout_timer, tx_csa_complete_timeout);

        if(wlan_mlme_is_txcsa_set(vaphandle)) {
            ic->ic_chanchange_channel = scan_entry_chan;
            ic->ic_chanchange_secoffset =
                ieee80211_sec_chan_offset(ic->ic_chanchange_channel);
            ic->ic_chanchange_chwidth =
                ieee80211_get_chan_width(ic->ic_chanchange_channel);
            ic->ic_chanchange_chan_freq = scan_entry_chan->ic_freq;

            ic->ic_chanchange_tbtt = ic->ic_chan_switch_cnt;
            ieee80211com_set_flags(ic, IEEE80211_F_CHANSWITCH);
            wlan_pdev_beacon_update(ic);
        } else {
            /* Change the channel for the AP vaps when TXCSA is set to 0 by the user.
             * Set IEEE80211_F_CHANSWITCH flag for all the AP vaps and ic_chanchange_tbtt to 0.
             * So that AP vaps will not send CSA to its connected clients.
             */
            wlan_objmgr_pdev_iterate_obj_list(ic->ic_pdev_obj, WLAN_VDEV_OP,
                                              wlan_mlme_vdev_txcsa_start_notify,
                                              scan_entry_chan, 0, WLAN_MLME_SB_ID);

            ic->ic_chanchange_tbtt = 0;
        }

      return 0;
    }
    wlan_mlme_cm_action_save_history(vap, CM_TXCHANSWITCH_START,
                              QDF_STATUS_E_FAILURE);
    return EBUSY;
}

#if ATH_SUPPORT_DFS
int wlan_mlme_start_repeater_cac(wlan_if_t vaphandle, struct ieee80211_ath_channel *bss_chan)
{
    struct ieee80211vap           *vap = vaphandle;
    struct ieee80211com           *ic = vap->iv_ic;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    u_int32_t                     repeater_cac_complete_timeout = 0;

    wlan_mlme_cm_action_save_history(vap, CM_REPEATER_CAC_START,
                              QDF_STATUS_SUCCESS);
    mlme_priv->im_request_type = MLME_REQ_REPEATER_CAC;

    /* Add extra 2000milliseconds so that timeout does not happen before actual CAC timeout */
#define EXTRA_TIME 2000
#define CAC_DELAY 15 /* sec */
    repeater_cac_complete_timeout = 1000*ieee80211_dfs_get_cac_timeout(
            ic, bss_chan)+ EXTRA_TIME;
    OS_SET_TIMER(&mlme_priv->im_timeout_timer, repeater_cac_complete_timeout);

    wlan_cfg80211_dfs_cac_start(vap, ieee80211_dfs_get_cac_timeout(ic, bss_chan)+CAC_DELAY);
#if ATH_SUPPORT_STA_DFS
    IEEE80211_DELIVER_EVENT_CAC_STARTED(vaphandle, bss_chan->ic_freq,
            (ieee80211_dfs_get_cac_timeout(ic, bss_chan)+CAC_DELAY));
#endif
    return 0;
}
#endif

int wlan_mlme_cancel_txchanswitch_timer(wlan_if_t vaphandle)
{
    struct ieee80211vap           *vap = vaphandle;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    mlme_priv->im_request_type = MLME_REQ_NONE;
    OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer);
    return 0;

}
int wlan_mlme_cancel_repeater_cac_timer(wlan_if_t vaphandle)
{
    struct ieee80211vap           *vap = vaphandle;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    mlme_priv->im_request_type = MLME_REQ_NONE;
    OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer);
    return 0;

}


/*
 * Sets that hardware up for joining to the specified
 * infrastructure network. The hardware should
 * set itself up to synchronize to beacons from the specified
 * access point. Once the join has completed, the mlme_join_complete_infra
 * routine should be called.
 *
 * timeout - change from number of beacon intervals to milliseconds to meet win8 requirement
 *           xijin. 2011/05/31
 */
int wlan_mlme_join_infra(wlan_if_t vaphandle, wlan_scan_entry_t bss_entry, u_int32_t timeout)
{
    struct ieee80211vap           *vap = vaphandle;
    ieee80211_scan_entry_t        scan_entry = bss_entry;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    int                           error = 0;
    u_int32_t                     join_timeout_ms;
    bool                          thread_started = false;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;


    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

    /* Initialize join state variables */
    ASSERT(mlme_priv->im_request_type == MLME_REQ_NONE);
    mlme_priv->im_request_type = MLME_REQ_JOIN_INFRA;
    atomic_set(&(mlme_priv->im_join_wait_beacon_to_synchronize), 0);
    mlme_priv->im_connection_up = 0;

    vdev_mlme->mgmt.mbss_11ax.profile_idx = scan_entry->mbssid_info.profile_num;
    vdev_mlme->mgmt.mbss_11ax.profile_num = ilog2(scan_entry->mbssid_info.profile_count);
    qdf_mem_copy(vdev_mlme->mgmt.mbss_11ax.trans_bssid, scan_entry->mbssid_info.trans_bssid, QDF_MAC_ADDR_SIZE);
    error = ieee80211_sta_join(vap, scan_entry, &thread_started);
    if (error) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Error %d (0x%08X) in ieee80211_sta_join\n",
            __func__, error, error);
        goto err;
    }

    if (thread_started) {
        /* Set the timeout timer for Join Failure case. */
        join_timeout_ms = mlme_priv->im_timeout;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Setting Join Timeout timer for %d ms\n", join_timeout_ms);
        OS_SET_TIMER(&mlme_priv->im_timeout_timer, join_timeout_ms);
    }

    return error;

err:
    mlme_priv->im_request_type = MLME_REQ_NONE;
    return error;
}

int wlan_mlme_join_infra_continue(wlan_if_t vaphandle, wlan_scan_entry_t bss_entry, u_int32_t timeout)
{
    struct ieee80211vap           *vap = vaphandle;
    struct ieee80211com           *ic = vap->iv_ic;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211_node         *ni;
    int                           error = 0;
    struct wlan_crypto_params vdev_crypto_params;
    bool restart;

    ic->ic_flags_ext2 &= ~IEEE80211_FEXT2_RESET_PRECACLIST;
    error = ieee80211_set_ctry_code_continue(ic, false);
    if (error) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Error %d (0x%08X) in ieee80211_sta_join\n",
            __func__, error, error);
        mlme_priv->im_request_type = MLME_REQ_NONE;
        return error;
    }
    if (!wlan_scan_entry_rsnparams(vaphandle, bss_entry, &vdev_crypto_params)) {
        vaphandle->mixed_encryption_mode = 0;
        if(wlan_crypto_is_htallowed(vap->vdev_obj, NULL))
            vaphandle->mixed_encryption_mode = 1;
    }


    /* iv_bss is valid only after ieee80211_sta_join */
    ni = vap->iv_bss;
    ni->ni_assocstarttime = OS_GET_TICKS();
    /*
     * issue a vap start request to resource manager.
     * if the function returns EOK (0) then its ok to change the channel synchronously
     * if the function returns EBUSY  then resource manager will
     * switch channel asynchronously and post an event event handler registred by vap and
     * vap handler will intern call the wlan_mlme_join_infra_continue .
     */
    mlme_priv->im_timeout = timeout;
    restart = ieee80211_vap_is_connected(vap);
    if (restart) {
        vap->iv_quick_reconnect = true;
    } else {
        vap->iv_quick_reconnect = false;
    }

     /* In station mode, if rejoin is ongoing, VDEV SM is in SUSPEND_RESTART substate
      * it expects DISCONNECT_COMPLETE to move to START state and sends restart
      * req
      */
    if (restart) {
          wlan_vdev_mlme_sm_deliver_evt(vap->vdev_obj,
                                         WLAN_VDEV_SM_EV_DISCONNECT_COMPLETE, 0, NULL);
    }
    else {
          ieee80211_update_vdev_chan(vap->vdev_obj->vdev_mlme.des_chan, ni->ni_chan);
          error = wlan_vdev_mlme_sm_deliver_evt(vap->vdev_obj,
                                                WLAN_VDEV_SM_EV_START, 0, NULL);
          if (error) {
              qdf_err("vdev:%u EV_START failed",
                      wlan_vdev_get_id(vap->vdev_obj));
              mlme_priv->im_request_type = MLME_REQ_NONE;
          }
    }

    return error;
}

void ieee80211_mlme_join_infra_continue(struct ieee80211vap *vap, int32_t status)
{
    struct ieee80211com           *ic = vap->iv_ic;
    struct ieee80211_node         *ni;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    u_int32_t                     join_timeout_ms;
    cm_ext_t *cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);

    if (!cm_ext_handle)
        return;


    if (mlme_priv->im_request_type != MLME_REQ_JOIN_INFRA) {
        cm_ext_handle->cm_conn_rsp.connect_status = QDF_STATUS_E_FAILURE;
        cm_ext_handle->cm_conn_rsp.reason = CM_JOIN_FAILED;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s : im_request_type != JOIN_INFRA\n",
            __func__);
        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, IEEE80211_STATUS_UNSPECIFIED);
        return;
    }

    if (status != EOK) {
        cm_ext_handle->cm_conn_rsp.connect_status = QDF_STATUS_E_FAILURE;
        cm_ext_handle->cm_conn_rsp.reason = CM_JOIN_FAILED;
        mlme_priv->im_request_type = MLME_REQ_NONE;
        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, IEEE80211_STATUS_UNSPECIFIED);
        return;
     }

    /* iv_bss is valid only after ieee80211_sta_join */
    ni = vap->iv_bss;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s ni=%02X:%02X:%02X:%02X:%02X:%02X\n",
        __func__,
        ni->ni_macaddr[0], ni->ni_macaddr[1], ni->ni_macaddr[2],
        ni->ni_macaddr[3], ni->ni_macaddr[4], ni->ni_macaddr[5]);

    /* Update erp info */
    if (ni->ni_erp & IEEE80211_ERP_USE_PROTECTION)
        ieee80211com_set_flags(ic, IEEE80211_F_USEPROT);
    else
        ieee80211com_clear_flags(ic, IEEE80211_F_USEPROT);
    ieee80211_set_protmode(ic);

    if(ni->ni_erp & IEEE80211_ERP_LONG_PREAMBLE)
        ieee80211com_set_flags(ic, IEEE80211_F_USEBARKER);
    else
        ieee80211com_clear_flags(ic, IEEE80211_F_USEBARKER);

    /* 11AX TODO (Phase II) - Update this for 11ax if required */

    /* Update slot time info */
    ieee80211_set_shortslottime(ic,
                                IEEE80211_IS_CHAN_A(vap->iv_bsschan) ||
                                IEEE80211_IS_CHAN_11NA(vap->iv_bsschan) ||
                                (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME));

    /* In station mode, set init_in_progress to 0 before moving to join state.
     * This is added in corner case where wifi down/detect is issues when
     * vap start is in progress. This is leading to init_in_progess not getting
     * reset and leading to host not sending vap_stop before vap_delete.
     */

    /* update the uplink bssid */
    son_update_uplink_bssid(ic->ic_pdev_obj, ni->ni_bssid);

#ifdef ATH_SUPPORT_TxBF
    ieee80211_init_txbf(ic, ni);
#endif

    if (wlan_reg_is_6ghz_chan_freq(vap->iv_bsschan->ic_freq))
        ieee80211_send_tpc_power_cmd(vap);

    /* When stict_passive scan is enabled, do not send probe request in passive channels.
       Send join success here and transit to authentication state.
       When iv_wps_mode is set, probe request has to be sent as it is required for
       WPS-Push button exchange*/

    if ((ic->ic_strict_pscan_enable && IEEE80211_IS_CHAN_PASSIVE(ic->ic_curchan))
                                                            && !vap->iv_wps_mode) {
        mlme_priv->im_request_type = MLME_REQ_NONE;
        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, IEEE80211_STATUS_SUCCESS);
        return;
    }
    else {
        /* Send a direct probe to increase the odds of receiving a probe response */
        ieee80211_send_probereq(ni, vap->iv_myaddr, ni->ni_bssid,
                ni->ni_bssid, ni->ni_essid, ni->ni_esslen,
                vap->iv_opt_ie.ie, vap->iv_opt_ie.length);
    }
    mlme_priv->im_join_is_timeout = 0;
    /* Set the timeout timer for Join Failure case. */
    join_timeout_ms = mlme_priv->im_timeout;//IEEE80211_TU_TO_MS(mlme_priv->im_timeout * ni->ni_intval);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Setting Join Timeout timer for %d ms\n", join_timeout_ms);
    OS_SET_TIMER(&mlme_priv->im_timeout_timer, join_timeout_ms);
    /* Set the appropriate filtering function and wait for Join Beacon */
    MLME_WAIT_FOR_BSS_JOIN(mlme_priv);
}

int wlan_assoc_external_auth(wlan_if_t vap, u_int16_t action)
{
#if UMAC_SUPPORT_WPA3_STA
#if UMAC_SUPPORT_CFG80211
    struct net_device *dev;
    ieee80211_ssid ssid;

    qdf_debug("action %d", action);
    dev = OSIF_TO_NETDEV(vap->iv_ifp);
    wlan_get_desired_ssidlist(vap, &ssid, 1);

    if (vap->iv_cfg80211_create) {
        struct cfg80211_external_auth_params params;

        if(ssid.len)
           qdf_mem_copy(params.ssid.ssid, ssid.ssid, ssid.len);

        params.ssid.ssid_len = ssid.len;
        if (action == IEEE80211_EXTERNAL_AUTH_START)
            params.action = NL80211_EXTERNAL_AUTH_START;
        else
            params.action = NL80211_EXTERNAL_AUTH_ABORT;

        wlan_vap_get_bssid(vap, params.bssid);

        params.key_mgmt_suite = qdf_cpu_to_be32(WLAN_AKM_SUITE_SAE);

        cfg80211_external_auth_request(dev, &params, GFP_ATOMIC);
    } else {
#ifndef MGMT_FRAM_TAG_SIZE
#define MGMT_FRAM_TAG_SIZE 30
#endif
        struct ev_sta_external_auth_params params;
        union iwreq_data wreq;
        char *buf = NULL, *tag = NULL;
        size_t bufsize = MGMT_FRAM_TAG_SIZE + sizeof(struct ev_sta_external_auth_params);

        buf = (char *)qdf_mem_malloc(bufsize);
        if(buf == NULL)
           return 0;

        qdf_mem_zero(&wreq, sizeof(wreq));
        qdf_mem_zero(&params, sizeof(params));
        wreq.data.length = bufsize;
        wreq.data.flags = 0;
        tag = "EXTERNAL_AUTH_INDICATION";

        snprintf(buf, MGMT_FRAM_TAG_SIZE, "%s", tag);

        if(ssid.len)
            qdf_mem_copy(params.ssid, ssid.ssid, ssid.len);
        params.ssid_len = ssid.len;
        params.action = action;
        wlan_vap_get_bssid(vap, params.bssid);
        params.keymgmt_suite = qdf_cpu_to_be32(WLAN_AKM_SUITE_SAE);
        qdf_mem_copy(buf+MGMT_FRAM_TAG_SIZE, &params, sizeof(struct ev_sta_external_auth_params));
        WIRELESS_SEND_EVENT(dev, IWEVCUSTOM, &wreq, buf);
    }

#else
    /* TODO: WEXT implementation needs to be done */
#endif
#endif
    return 0;
}

int wlan_mlme_auth_request(wlan_if_t vaphandle, u_int32_t timeout)
{
    osif_dev *osifp;
    struct ieee80211vap           *vap = vaphandle;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211_node         *ni = vap->iv_bss; /* bss node */
    int                           error = 0;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

    /* wait for auth seq number 2 (open response or shared challenge) */
    ASSERT(mlme_priv->im_request_type == MLME_REQ_NONE);
    mlme_priv->im_request_type = MLME_REQ_AUTH;

    osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
#if UMAC_SUPPORT_WPA3_STA
    if (vap->iv_sta_external_auth_enabled) {

        wlan_assoc_external_auth(vaphandle, IEEE80211_EXTERNAL_AUTH_START);
        /* Set the timeout timer for authenticate failure case */
        qdf_timer_sync_cancel(&vap->iv_sta_external_auth_timer);
        wlan_assoc_sm_sae_max_auth_retry(wlan_mlme_get_assoc_sm_handle(vap->vdev_obj), true);
        qdf_timer_start(&vap->iv_sta_external_auth_timer,
                        IEEE80211_MLME_EXTERNAL_AUTH_TIMEOUT);
    } else
#endif
    {
        mlme_priv->im_expected_auth_seq_number = IEEE80211_AUTH_OPEN_RESPONSE;

#if UMAC_SUPPORT_WPA3_STA
        wlan_assoc_sm_sae_max_auth_retry(wlan_mlme_get_assoc_sm_handle(vap->vdev_obj), true);
#endif
        /*  Send the authentication packet */
        error = ieee80211_send_auth(ni, IEEE80211_AUTH_SHARED_REQUEST, 0, NULL, 0, NULL);
        if (error) {
            goto err;
        }
        /* Set the timeout timer for authenticate failure case */
        OS_SET_TIMER(&mlme_priv->im_timeout_timer, timeout);
        wlan_node_set_peer_state(ni, WLAN_AUTH_STATE);
    }
    return error;

err:
    mlme_priv->im_request_type = MLME_REQ_NONE;
    OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer);
    return error;
}

int wlan_mlme_assoc_request(wlan_if_t vaphandle, u_int32_t timeout)
{
    IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_MLME, "%s\n", __func__);
    return mlme_assoc_reassoc_request(vaphandle, 0, NULL, timeout);
}

int wlan_mlme_reassoc_request(wlan_if_t vaphandle, u_int8_t *prev_bssid, u_int32_t timeout)
{
    IEEE80211_DPRINTF(vaphandle, IEEE80211_MSG_MLME, "%s\n", __func__);
    return mlme_assoc_reassoc_request(vaphandle, 1, prev_bssid, timeout);
}

/*
 * Private APIs
 *      - private to mlme implementation
 *      - called by mgmt frame processing (ieee80211_mgmt_input.c)
 */

/* Confirmations */
void ieee80211_mlme_join_complete_infra(struct ieee80211_node *ni)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    if ((mlme_priv->im_request_type == MLME_REQ_JOIN_INFRA) && (MLME_STOP_WAITING_FOR_JOIN(mlme_priv) == 1))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

        /* Request complete */
        mlme_priv->im_request_type = MLME_REQ_NONE;

        /*
         * We have received the beacon that synchronises us with the BSS.
         * We don't care whether the Timer got cancelled or not. The macro
         * HW_STOP_WAITING_FOR_JOIN synchronizes us with the cancel operation
         */
        OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer);

        /* Call MLME confirmation handler */
        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, IEEE80211_STATUS_SUCCESS);
    }
    else
    {
        if (mlme_priv->im_request_type != MLME_REQ_NONE) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Failed: im_request_type=%d\n",
                __func__,
                mlme_priv->im_request_type);
        }

    }

    /* start SW bmiss. will be here for every beacon received from our AP  */
    mlme_sta_swbmiss_timer_start(vap);
}

/* Receive assoc/reassoc response
 * - the caller of this routine validates the frame and ensures that the opmode == STA
 */
void ieee80211_mlme_recv_assoc_response(struct ieee80211_node *ni,
                                        int                   subtype,
                                        u_int16_t             capability,
                                        u_int16_t             status_code,
                                        u_int16_t             aid,
                                        u_int8_t              *ie_data,
                                        u_int32_t             ie_length,
                                        wbuf_t                wbuf)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    int                           mlme_request_type = mlme_priv->im_request_type;
    int                           error;
    u_int32_t                     rxlinkspeed, txlinkspeed; /* bits/sec */

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s im_request_type=%d status=%d (0x%08X)\n",
        __func__,
        mlme_priv->im_request_type,
        status_code, status_code);

    /* Ignore if no request in progress */
    if ((mlme_priv->im_request_type != MLME_REQ_ASSOC) &&
        (mlme_priv->im_request_type != MLME_REQ_REASSOC))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Incorrect request type %d\n",
            __func__, mlme_priv->im_request_type);
        return;
    }

    if (!OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Timed-out already\n", __func__);
        return;
    }

    if (status_code != IEEE80211_STATUS_SUCCESS) {
        goto complete;
    }

    /* Validate AID */
    aid  &= ~IEEE80211_FIELD_TYPE_AID;
    if ((aid > 2007) || (aid == 0))
    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Association response contains invalid AID=%d\n", __func__, aid);
        status_code = IEEE80211_STATUS_UNSPECIFIED;
        goto complete;
    }

    error = son_update_mgmt_frame(vap->vdev_obj, ni->peer_obj, subtype, wbuf_header(wbuf), wbuf_get_pktlen(wbuf), NULL);
    if (error) {
	ucfg_son_set_root_dist(vap->vdev_obj, SON_INVALID_ROOT_AP_DISTANCE);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: mlme_process_asresp_elements failed\n", __func__);
        status_code = IEEE80211_STATUS_UNSPECIFIED;
        goto complete;
    }

    error = mlme_process_asresp_elements(ni, ie_data, ie_length);
    if (error) {
	ucfg_son_set_root_dist(vap->vdev_obj, SON_INVALID_ROOT_AP_DISTANCE);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: mlme_process_asresp_elements failed\n", __func__);
        status_code = IEEE80211_STATUS_UNSPECIFIED;
        goto complete;
    }

    /* Association successful */

complete:
    switch (mlme_priv->im_request_type) {
    case MLME_REQ_ASSOC:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: mlme_assoc_complete status %d\n", __func__, status_code);
        if (subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: mlme_assoc_complete status type mismatched %d\n", __func__, subtype);
			return;
        }
        break;

    case MLME_REQ_REASSOC:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: mlme_reassoc_complete status %d\n", __func__, status_code);
        if (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_RESP) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: mlme_assoc_complete status type mismatched %d\n", __func__, subtype);
			return;
        }
        break;

    default:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: mlme_reassoc_complete status %d unexpected request type %d\n",
            __func__, status_code, mlme_priv->im_request_type);
        return;
    }

    /* Request complete */
    mlme_priv->im_request_type = MLME_REQ_NONE;

    if (status_code == IEEE80211_STATUS_SUCCESS) {
        ASSERT(aid != 0);
        ni->ni_associd = aid;
        ni->ni_assoctime = OS_GET_TICKS() - ni->ni_assocstarttime;

        /* Association successful, put underlying H/W into ready state */
        wlan_vdev_mlme_sm_deliver_evt(vap->vdev_obj,
                                      WLAN_VDEV_SM_EV_START_SUCCESS, 0, NULL);

        wlan_node_set_peer_state(ni, WLAN_WAITKEY_STATE);
        if(wlan_vap_is_pmf_enabled(vap)){
            wlan_crypto_set_hwmfpQos(vap, 1);
        }
    }
    if (status_code == IEEE80211_STATUS_REJECT_TEMP) {
        error = mlme_process_timeout_interval_elements(ni, ie_data, ie_length);
    }

    /* indicate linkspeed */
     mlme_get_linkrate(ni, &rxlinkspeed, &txlinkspeed);
     IEEE80211_DELIVER_EVENT_LINK_SPEED(vap, rxlinkspeed, txlinkspeed);

    /* Association complete (success or failure) */
    switch (mlme_request_type) {
    case MLME_REQ_ASSOC:
        IEEE80211_DELIVER_EVENT_MLME_ASSOC_COMPLETE(vap, status_code, aid, wbuf);
        break;

    case MLME_REQ_REASSOC:
        IEEE80211_DELIVER_EVENT_MLME_REASSOC_COMPLETE(vap, status_code, aid, wbuf);
        break;

    default:
        break;
    }
}

/* Send association or reassociation request */
static int mlme_assoc_reassoc_request(wlan_if_t vaphandle, int reassoc, u_int8_t *prev_bssid, u_int32_t timeout)
{
    struct ieee80211vap           *vap = vaphandle;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211_node         *ni = vap->iv_bss; /* bss node */
    int                           error = 0;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

    ASSERT(mlme_priv->im_request_type == MLME_REQ_NONE);
    mlme_priv->im_request_type = reassoc ? MLME_REQ_REASSOC : MLME_REQ_ASSOC;

    /* Set the timeout timer for association failure case */
    OS_SET_TIMER(&mlme_priv->im_timeout_timer, timeout);

    /* Transmit frame */
    error = ieee80211_send_assoc(ni, reassoc, prev_bssid);
    if (error) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: ieee80211_send_assoc error %d (0x%08X)\n",
            __func__, error, error);
        goto err;
    }

    wlan_node_set_peer_state(ni, WLAN_ASSOC_STATE);
    return error;

err:
    mlme_priv->im_request_type = MLME_REQ_NONE;
    OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer);
    return error;
}

QDF_STATUS ieee80211_validate_assoc_info(struct ieee80211_node *ni)
{
    int i;
    uint8_t *hecap_phyinfo;

    if (!ni) {
       qdf_rl_err("Node structure is NULL");
       return QDF_STATUS_E_INVAL;
    }

    /* Drop the assoc response frame only if the chwidth is greater than
     * phymode.
     */
    if (ni->ni_chwidth > get_chwidth_phymode(ni->ni_phymode)) {
        qdf_rl_err("Node Channel width (%d) is greater than the phymode (%d)",
                ni->ni_chwidth, ni->ni_phymode);
        return QDF_STATUS_E_INVAL;
    }

    if (ieee80211_is_phymode_11ng(ni->ni_phymode) ||
        ieee80211_is_phymode_11na(ni->ni_phymode)) {

        if (!(ni->ni_flags & IEEE80211_NODE_HT)) {
             qdf_rl_err("HT flag is not set for HT phymode");
             return QDF_STATUS_E_INVAL;
        }

        if (!ni->ni_htcap) {
             qdf_rl_err("HT CAP is not present for HT phymode");
             return QDF_STATUS_E_INVAL;
       }

    } else if (ieee80211_is_phymode_11ac(ni->ni_phymode)) {

        if (!(ni->ni_flags & IEEE80211_NODE_VHT)) {
             qdf_rl_err("VHT flag is not set for VHT phymode");
             return QDF_STATUS_E_INVAL;
        }

        if (!ni->ni_vhtcap) {
             qdf_rl_err("VHT CAP is not present for VHT phymode");
             return QDF_STATUS_E_INVAL;
        }

    } else if (ieee80211_is_phymode_11ax(ni->ni_phymode)) {

        if (!(ni->ni_ext_flags & IEEE80211_NODE_HE)) {
             qdf_rl_err("HE flag is not set for HE phymode");
             return QDF_STATUS_E_INVAL;
        }

        if (!ni->ni_he.heop_param) {
             qdf_rl_err("HEOP_PARAM is not populated for HE phymode");
             return QDF_STATUS_E_INVAL;
        }

        hecap_phyinfo = (uint8_t *) &(ni->ni_he.hecap_phyinfo[HECAP_PHYBYTE_IDX0]);

        for (i = 0; i < HECAP_PHYINFO_SIZE; i++) {
             if (hecap_phyinfo[i]) {
                 break;
             }
        }
        if (i == HECAP_PHYINFO_SIZE) {
            qdf_rl_err("HECAP_PHYINFO is not populated for HE phymode");
            return QDF_STATUS_E_INVAL;
        }

        if ((ni->ni_chwidth > IEEE80211_CWM_WIDTH20) &&
                 (!(ni->ni_he.hecap_phyinfo[HECAP_PHYBYTE_IDX0] &
                                  IEEE80211_HECAP_LDPC_MASK))) {
              qdf_rl_err("LDPC is not set in HE CAP for bandwidth greater than 20MHz");
              return QDF_STATUS_E_INVAL;
        }

        if (!ieee80211_is_basic_txrx_mcsnss_requirement_met(
                  ni, HECAP_TXRX_MCS_NSS_IDX_80)) {
              qdf_rl_err("Basic HE_MCS_NSS requirement for 20,40,80MHz is not met");
              return QDF_STATUS_E_INVAL;
        }

        if (ieee80211_is_phymode_11axa_he160(ni->ni_phymode) &&
                 !(ni->ni_he.he_basic_txrxmcsnss_req_met_160)) {
              qdf_rl_err("HE_MCS_NSS requirement for 160MHz is not met");
              return QDF_STATUS_E_INVAL;
         }

         if (ieee80211_is_phymode_11axa_he80_80(ni->ni_phymode) &&
                 !(ni->ni_he.he_basic_txrxmcsnss_req_met_80_80)) {
              qdf_rl_err("HE_MCS_NSS requirement for 80_80MHz is not met");
              return QDF_STATUS_E_INVAL;
         }

    }

    return QDF_STATUS_SUCCESS;
}

/*
 * Process information elements from association response frame.
 * This includes rate negociation, wmm parameter updating and etc.
 */
static int mlme_process_asresp_elements(struct ieee80211_node *ni,
                                        u_int8_t              *frm,
                                        u_int32_t             ie_len)
{
    struct ieee80211vap          *vap = ni->ni_vap;
    struct ieee80211com          *ic = ni->ni_ic;
    u_int8_t                     *efrm = frm + ie_len;
    u_int8_t                     *rates, *xrates, *wme, *htcap, *tspecie, *athextcap, *extcap, *whc_apinfo, *vhtcap, *vhtop, *htinfo;
    u_int8_t                     *hecap, *heop, *srpie, *hecap_6g;
    u_int8_t                     *assoc_resp_ie;
#if QCN_IE
    u_int8_t                     *qcn = NULL;
#endif
    u_int8_t                     qosinfo;
    int                          ht_rates_allowed;
    struct ieee80211_ie_vhtop    *ap_vhtop;
    struct ieee80211_ie_vhtcap    *ap_vhtcap = NULL;
    struct ieee80211_ie_htinfo_cmn    *ap_htinfo;
#if OBSS_PD
    struct ieee80211_vap_opmode_count vap_opmode_count;
#endif /* OBSS_PD */
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
    u_int8_t *extenderie = NULL;
#endif
    uint32_t heop_info;

    ASSERT((vap->iv_opmode != IEEE80211_M_STA) || (ni == vap->iv_bss));

    rates = xrates = wme = htcap = tspecie = athextcap = extcap = whc_apinfo = vhtcap = vhtop = htinfo = assoc_resp_ie = NULL;
    ap_vhtop = NULL;
    hecap = heop = srpie = hecap_6g = NULL;
    ap_htinfo = NULL;
    assoc_resp_ie = frm;

    while (frm < efrm) {
        switch (*frm) {
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
        case IEEE80211_ELEMID_XRATES:
            xrates = frm;
            break;
        case IEEE80211_ELEMID_XCAPS:
            extcap = frm;
            break;
        case IEEE80211_ELEMID_HTCAP_ANA:
            htcap = (u_int8_t *)&((struct ieee80211_ie_htcap *)frm)->hc_ie;
            break;
       case IEEE80211_ELEMID_VHTCAP:
            if(vhtcap == NULL) {
                vhtcap = (u_int8_t *)(struct ieee80211_ie_vhtcap *)frm;
            }
            break;
       case IEEE80211_ELEMID_VHTOP:
            if(vhtop == NULL) {
                vhtop = (u_int8_t *)(struct ieee80211_ie_vhtop *)frm;
            }
            break;

        case IEEE80211_ELEMID_OP_MODE_NOTIFY:
            /* We can ignore this because the info we need is available in VHTCAP and VHTOP */
        break;
        case IEEE80211_ELEMID_EXTN:
            if ((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) {
                if (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) ==
                            IEEE80211_ELEMID_EXT_HECAP) {
                    hecap = frm;
                } else if (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) ==
                            IEEE80211_ELEMID_EXT_HEOP) {
                    heop  = frm;
                } else if (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) ==
                            IEEE80211_ELEMID_EXT_SRP) {
		            srpie = frm;
		        } else if(*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) ==
                        IEEE80211_ELEMID_EXT_6G_HECAP) {
                    hecap_6g = frm;
                }
            }
        break;
        case IEEE80211_ELEMID_VENDOR:
            if (iswmeoui(frm, WME_PARAM_OUI_SUBTYPE))
                wme = frm;
            else if (iswmeoui(frm, WME_INFO_OUI_SUBTYPE))
                wme = frm;
            else if (iswmeoui(frm, WME_TSPEC_OUI_SUBTYPE))
                tspecie = frm;
            else if(ishtcap(frm)) {
                if (htcap == NULL) {
                    htcap = (u_int8_t *)&((struct vendor_ie_htcap *)frm)->hc_ie;
                }
            }
            else if (isatheros_extcap_oui(frm))
                 athextcap = frm;
#if DBDC_REPEATER_SUPPORT
            else if (is_extender_oui((uint8_t *)frm)) {
                /* location where Extender IE Present */
                extenderie = frm;
            }
#endif
            else if (isinterop_vht(frm) && !(vhtcap) &&
                        ieee80211vap_11ng_vht_interopallowed(vap)) {
                 /* Vht cap & Op location in Vendor specific Vht IE */
                 vhtcap = (u_int8_t *)(struct ieee80211_ie_vhtcap *) (frm + 7);
                 vhtop = (u_int8_t *)(struct ieee80211_ie_vhtop *) (frm + 21);
                 ieee80211node_set_flag(ni, IEEE80211_NODE_11NG_VHT_INTEROP_AMSDU_DISABLE);
            }
            else if (isbwnss_oui(frm)) {
                 ni->ni_bw160_nss = IEEE80211_GET_BW_NSS_FWCONF_160(*(frm + 8)); /*BW_NSS has sub_type & version, hence read data after version*/
            }
#if QCN_IE
            else if(isqcn_oui(frm)) {
                qcn = frm;
            }
#endif
            break;
#if UMAC_SUPPORT_WNM
        case IEEE80211_ELEMID_BSSMAX_IDLE_PERIOD:
			ieee80211_wnm_parse_bssmax_ie(ni, frm);
            break;
        case IEEE80211_ELEMID_TIM_BCAST_RESPONSE:
            ieee80211_parse_timresp_ie(frm, frm + frm[1] + 2, ni);
            break;
#endif
       case IEEE80211_ELEMID_HTINFO_ANA:
            htinfo = (u_int8_t *)(&((struct ieee80211_ie_htinfo *)frm)->hi_ie);
            break;

        }

        /* elem id + len = 2 bytes */
        frm += frm[1] + 2;
    }

    if (!rates || (rates[1] > IEEE80211_RATE_MAXSIZE)) {
        /* XXX: msg + stats */
        return -EINVAL;
    }

    if (!ieee80211_setup_rates(ni, rates, xrates,
                                 IEEE80211_F_DOSORT | IEEE80211_F_DOFRATE |
                                 IEEE80211_F_DOXSECT)) {
        qdf_nofl_info("%s: association failed (rate set mismatch)\n", __func__);
        return -EINVAL;
    }

    /*
     * U-APSD is enabled/disabled per-association.
     */
    if (wme != NULL) {
        /* Parse IE according to subtype */
        if (iswmeparam(wme)) {
            /* Association is QOS-enabled */
            ieee80211node_set_flag(ni, IEEE80211_NODE_QOS);

            if (vap->iv_opmode != IEEE80211_M_BTAMP &&
                ieee80211_parse_wmeparams(vap, wme, &qosinfo, 1) >= 0) {

                /* Check if association is UAPSD-enabled */
                if (qosinfo & WME_CAPINFO_UAPSD_EN) {
                    ieee80211node_set_flag(ni, IEEE80211_NODE_UAPSD);
                }
                else {
                    ieee80211node_clear_flag(ni, IEEE80211_NODE_UAPSD);
                }

                ieee80211_wme_updateparams(vap);
            }
        }
        else {
            /*** QOS requires WME Param */
            ieee80211node_clear_flag(ni, IEEE80211_NODE_QOS);

            if (ieee80211_parse_wmeinfo(vap, wme, &qosinfo) >= 0) {
                /* Check if association is UAPSD-enabled */
                if (qosinfo & WME_CAPINFO_UAPSD_EN) {
                    ieee80211node_set_flag(ni, IEEE80211_NODE_UAPSD);
                }
                else {
                    ieee80211node_clear_flag(ni, IEEE80211_NODE_UAPSD);
                }

                ieee80211_wme_updateinfo(vap);
            }
        }
    }
    else {
        ieee80211node_clear_flag(ni, IEEE80211_NODE_QOS);
        ieee80211node_clear_flag(ni, IEEE80211_NODE_UAPSD);
    }

    if ((tspecie != NULL) &&
        (ieee80211_parse_tspecparams(vap, tspecie) >= 0)) {
        /* store the tspec */
    }

    if (athextcap != NULL)
        ieee80211_process_athextcap_ie(ni, athextcap);

#if DBDC_REPEATER_SUPPORT
    if (ic_list->same_ssid_support && (extenderie != NULL) && (vap == ic->ic_sta_vap)) {
        ieee80211_process_extender_ie(ni, extenderie, IEEE80211_FRAME_TYPE_ASSOCRESP);
    }
#endif
    /*
     * With WEP and TKIP encryption algorithms:
     * Disable aggregation if IEEE80211_NODE_WEPTKIPAGGR is not set.
     * Disable 11n if IEEE80211_FEXT_WEP_TKIP_HTRATE is not set.
     */
    ht_rates_allowed = (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
                        IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
                        IEEE80211_IS_CHAN_11N(ic->ic_curchan));

    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
	wlan_crypto_is_htallowed(vap->vdev_obj, NULL)) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_WEPTKIP);
        if (ieee80211_ic_wep_tkip_htrate_is_set(ic)) {
            if (!ieee80211_has_weptkipaggr(ni))
                ieee80211node_set_flag(ni, IEEE80211_NODE_NOAMPDU);
        } else {
            ht_rates_allowed = 0;
        }
    }

    if (IEEE80211_IS_CHAN_5GHZ_6GHZ(ic->ic_curchan)) {
        ni->ni_phymode = IEEE80211_MODE_11A;
    } else if (( xrates != NULL)  &&
             IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11G)) {
        ni->ni_phymode = IEEE80211_MODE_11G;
    } else {
        ni->ni_phymode = IEEE80211_MODE_11B;
    }


    /*
     * Channel width and Nss will get adjusted with HT parse and VHT parse
     * if those modes are enabled
     */
    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
    ni->ni_streams = 1;
    /* 11n - HT rates not allowed using WEP and TKIP */
    if ((htcap != NULL) && (ht_rates_allowed)) {
        /* record capabilities, mark node as capable of HT */
        if(!ieee80211_parse_htcap(ni, htcap, NULL)) {
            qdf_nofl_info("%s: association failed (Rx MCS  set mismatch)\n", __func__);
            return -EINVAL;
        }

        if (!ieee80211_setup_ht_rates(ni, htcap,
            IEEE80211_F_DOFRATE | IEEE80211_F_DOXSECT |
            IEEE80211_F_DOBRS)) {
            qdf_nofl_info("%s: association failed (rate set mismatch)\n", __func__);
            return -EINVAL;
        }
#ifdef ATH_SUPPORT_TxBF
        // set keycache for txbf after sta associated successfully.
        if ( ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf){
            struct ieee80211com     *ic = vap->iv_ic;

            ieee80211_set_TxBF_keycache(ic,ni);
            ni->ni_bf_update_cv = 1;
            ni->ni_allow_cv_update = 1;
        }
#endif
    } else {
        /*
         * Flush any state from a previous association.
         */
        ieee80211node_clear_flag(ni, IEEE80211_NODE_HT);
        IEEE80211_NODE_CLEAR_HTCAP(ni);
    }

      /* Add vht cap for 2.4G mode, if 256QAM is enabled */
    if ((IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
                    ieee80211vap_vhtallowed(vap)) {

        if (vhtcap != NULL) {
            /* record capabilities, mark node as capable of VHT */
            ieee80211_parse_vhtcap(ni, vhtcap, NULL);

            if (ni->ni_ext_nss_support && !validate_extnss_vhtcap(&ni->ni_vhtcap)) {
                qdf_print("%s: Association failed invalid vhtcap",__func__);
                return -EINVAL;
            }

            if (vhtop && htinfo) {
                ieee80211_parse_vhtop(ni, vhtop, htinfo);
            }

            if (!ieee80211_setup_vht_rates(ni, vhtcap,
                IEEE80211_F_DOFRATE | IEEE80211_F_DOXSECT | IEEE80211_F_DOBRS)) {
                qdf_nofl_info("%s: association failed (vht rate set mismatch)\n", __func__);
                return -EINVAL;
            }


        } else {
            /*
             * Flush any state from a previous association.
             */
            ieee80211node_clear_flag(ni, IEEE80211_NODE_VHT);
            ni->ni_vhtcap = 0;
        }

    } else {
        /*
         * Flush any state from a previous association.
         */
        ieee80211node_clear_flag(ni, IEEE80211_NODE_VHT);
        ni->ni_vhtcap = 0;
    }

    if(vhtop != NULL) {
        ap_vhtop = (struct ieee80211_ie_vhtop *)vhtop;
    }

    if (hecap != NULL && (IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
                      && ieee80211vap_heallowed(vap))) {
        if(heop) {
            /* Update Basic MCS NSS requirement from AP */
            ieee80211_update_basic_bss_mcs_nss_req(ni, heop);
        }
        /* record HE capabilities */
        ieee80211_parse_hecap(ni, hecap, IEEE80211_FC0_SUBTYPE_ASSOC_RESP);

    } else {
         /*
          * Flush any state from a previous association.
          */
         ni->ni_ext_flags &= ~IEEE80211_NODE_HE;
         qdf_mem_zero(&ni->ni_he, sizeof(struct ieee80211_he_handle));
    }

    if (hecap_6g != NULL && IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
                        && ieee80211vap_heallowed(vap)) {
        ieee80211_parse_he_6g_bandcap(ni, hecap_6g, IEEE80211_FC0_SUBTYPE_ASSOC_RESP);
        ieee80211_get_nss_from_hecap_mcsnssset_6g(ni);

    }

    if (heop != NULL && IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
                      && ieee80211vap_heallowed(vap) ) {
        ieee80211_parse_heop(ni, heop, IEEE80211_FC0_SUBTYPE_ASSOC_RESP, NULL);

        /* Update target with this new HE OP params.
         */
#if SUPPORT_11AX_D3
        heop_info = (ni->ni_he.heop_param |
                     (ni->ni_he.heop_bsscolor_info << HEOP_PARAM_S));
#else
        heop_info = ni->ni_he.heop_param;
#endif
        if(ic->ic_vap_set_param &&
            (ic->ic_vap_set_param(vap,
                      IEEE80211_CONFIG_HE_OP, heop_info) != EOK)) {

            qdf_print("%s WARNING!!! heop set to target failed", __func__);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE,
                    "%s: HEOP update sent to FW. color: %d\n",
                    __func__, ni->ni_he.heop_param & 0x3f);
        }

    }

    if (htinfo != NULL) {
        ap_htinfo = (struct ieee80211_ie_htinfo_cmn *)htinfo;
    }

#if OBSS_PD
    if (srpie != NULL) {
        OS_MEMZERO(&vap_opmode_count, sizeof(struct ieee80211_vap_opmode_count));
        ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);

        ieee80211_parse_srpie(ni, srpie);
        /* Update target with this new SRP IE params.
         */
        if (!vap_opmode_count.ap_count && vap_opmode_count.sta_count) {
            if(ic->ic_spatial_reuse &&
                (ic->ic_spatial_reuse(vap) != EOK)) {
                qdf_print("%s WARNING!!! SRP set to target failed\n", __func__);
            }
        }
    }
#endif

#if QCN_IE
    if (qcn != NULL) {
        ieee80211_parse_qcnie(qcn, NULL, ni, NULL);
    }
#endif
    if (vhtcap != NULL) {
        ap_vhtcap = (struct ieee80211_ie_vhtcap *)vhtcap;
    }
    /*
     * ieee80211_parse_vhtop, ieee80211_parse_hecap would have set the channel
     * width based on APs operating mode/channel. If vap is forced to operate
     * in a different lower mode than what AP is operating in, then set the
     * channel width based on the forced channel/phy mode.
     *
     * Required to be revisited for HE case, as chwidth update and
     * ieee80211_update_ht_vht_he_phymode is taken care in the
     * ieee80211_parse_hecap routine.
     */
    ieee80211_readjust_chwidth(ni, ap_vhtop, ap_htinfo, ap_vhtcap);

    /* Update the PHY mode */
    ieee80211_update_ht_vht_he_phymode(ic, ni);

    ieee80211_update_vap_shortgi(ni);

    if (ieee80211_validate_assoc_info(ni)) {
        qdf_rl_err("Association failed as Assoc params validation failed");
        return -EINVAL;
    }

    return EOK;
}

/*
 * Process Timeout Interval information elements from association response frame.
 * This includes an (re)association is failed with 802.11 reason code 30 .
 */
static int mlme_process_timeout_interval_elements(struct ieee80211_node *ni,
                                        u_int8_t              *frm,
                                        u_int32_t             ie_len)
{
    struct ieee80211vap          *vap = ni->ni_vap;
    u_int8_t                     *efrm = frm + ie_len;
    u_int8_t                     *comebacktiem;

    ASSERT((vap->iv_opmode != IEEE80211_M_STA) || (ni == vap->iv_bss));

    comebacktiem = NULL;

    while (frm < efrm) {
        if (IEEE80211_ELEMID_TIMEOUT_INTERVAL == *frm) {
            comebacktiem = frm;
            break;
        }
        frm += frm[1] + 2;
    }

    if ((comebacktiem != NULL) &&
        (ieee80211_parse_timeieparams(vap, comebacktiem) >= 0)) {
        /* store the tie info */
    }

    return EOK;
}

static u_int32_t get_max_phyrate(struct ieee80211com *ic)
{
    u_int32_t    linkspeed; /* bits/sec */
    u_int8_t     tx_streams = ieee80211_getstreams(ic, ic->ic_tx_chainmask);

    if (tx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        tx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    /* 11n card, report highest supported HT rate. */
    switch (tx_streams) {
    default:
        /* Default to single stream */
    case 1:
        linkspeed = 150000000;
        break;
    case 2:
        linkspeed = 300000000;
        break;
    case 3:
        linkspeed = 450000000;
        break;
    case 4:
        linkspeed = 600000000;
        break;
    }

    return linkspeed;
}
static void mlme_calculate_11n_connection_speed(struct ieee80211_node *ni, u_int32_t* rxlinkspeed, u_int32_t* txlinkspeed)
{
    struct ieee80211com    *ic = ni->ni_ic;
    u_int32_t              linkspeed; /* bits/sec */
    u_int8_t     tx_streams = ieee80211_getstreams(ic, ic->ic_tx_chainmask);
    u_int8_t     rx_streams = ieee80211_getstreams(ic, ic->ic_rx_chainmask);

    if (tx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        tx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    if (rx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        rx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    linkspeed = ic->ic_get_maxphyrate(ic, ni) * 1000;

    if (linkspeed == 0) {
        *txlinkspeed = get_max_phyrate(ic);
        *rxlinkspeed = *txlinkspeed;
    } else {
        *txlinkspeed = linkspeed;

        ASSERT(tx_streams <= rx_streams);

        /*
         * WAR for HB95 (1x1) low DownLink throughput issue. Report higher rx link speed to increase TCP RWIN size.
         * For 1x1 and 1x2, we report the rxlinkspeed as double of the txlinkspeed.
         */

        if((tx_streams == 1) && (rx_streams == 1)) {
            *rxlinkspeed = linkspeed * 2;
        } else {
            *rxlinkspeed = (linkspeed * rx_streams)/tx_streams;
            ASSERT(rx_streams <= 4);
        }
    }
}

void
mlme_get_linkrate(struct ieee80211_node *ni, u_int32_t* rxlinkspeed, u_int32_t* txlinkspeed)
{
    struct ieee80211vap    *vap = ni->ni_vap;
    struct ieee80211com    *ic = ni->ni_ic;
    int                    ht_rates_allowed;
    u_int8_t               rate;

    /* Check if connected to BSS */
    if ((ni->ni_htrates.rs_nrates == 0) && (ni->ni_rates.rs_nrates == 0)) {

        /* Not connected */

        if (ic->ic_caps & IEEE80211_C_HT) {
            *txlinkspeed = get_max_phyrate(ic);
            *rxlinkspeed = *txlinkspeed;
        } else {
            struct ieee80211_rateset *rs;

            /* Legacy card, report highest rate */
            rs = &vap->iv_op_rates[ieee80211_chan2mode(ic->ic_curchan)];
            rate = rs->rs_rates[rs->rs_nrates - 1];
            *txlinkspeed = mlme_dot11rate_to_bps(rate & IEEE80211_RATE_VAL);
            *rxlinkspeed = *txlinkspeed;
        }
    } else {

        /* Connected */
        /*
         * With WEP and TKIP encryption algorithms:
         * Disable 11n if IEEE80211_FEXT_WEP_TKIP_HTRATE is not set.
         */
        ht_rates_allowed = ((IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
                            IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
                            ieee80211vap_htallowed(vap));

        if (ni->ni_htrates.rs_nrates &&
            ht_rates_allowed) {
            mlme_calculate_11n_connection_speed(ni, rxlinkspeed, txlinkspeed);
            if (ic->ic_reg_parm.indicateRxLinkSpeed)    *txlinkspeed = *rxlinkspeed;
        } else {
            /* get maximum rate from node rate set */
            rate = ni->ni_rates.rs_rates[ni->ni_rates.rs_nrates - 1] & IEEE80211_RATE_VAL;
            *txlinkspeed = mlme_dot11rate_to_bps(rate);
            *rxlinkspeed = *txlinkspeed;

        }
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Rx Link speed Data rate: %d, Tx Link speed Data rate: %d\n",
                      __func__, *rxlinkspeed, *txlinkspeed);
}

int mlme_recv_auth_sta(struct ieee80211_node *ni,
                        u_int16_t             algo,
                        u_int16_t             seq,
                        u_int16_t             status_code,
                        u_int8_t              *challenge,
                        u_int8_t              challenge_length,
                        wbuf_t                wbuf)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    int32_t authmode = 0;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

    if (mlme_priv->im_request_type != MLME_REQ_AUTH) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: invalid request type\n",
            __func__,
            mlme_priv->im_request_type);
        return -1;
    }

    /* Validate algo */
#if UMAC_SUPPORT_WPA3_STA
    if ((algo == IEEE80211_AUTH_ALG_SAE) && (vap->iv_sta_external_auth_enabled)) {
#if UMAC_SUPPORT_CFG80211
        struct net_device *dev = OSIF_TO_NETDEV(vap->iv_ifp);

        if (vap->iv_cfg80211_create) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
            if(cfg80211_rx_mgmt(dev->ieee80211_ptr, vap->iv_ic->ic_curchan->ic_freq, 0, qdf_nbuf_data(wbuf), qdf_nbuf_len(wbuf), 0)) {
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0))
            if(cfg80211_rx_mgmt(dev->ieee80211_ptr, vap->iv_ic->ic_curchan->ic_freq, 0, qdf_nbuf_data(wbuf), qdf_nbuf_len(wbuf), 0, GFP_ATOMIC)) {
#endif
               return -1;
            }
        }
        return 0;
#endif
    }
#endif

    authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
    if ( authmode == -1 ) {
        qdf_err("crypto_err while getting authmode params\n");
        return -1;
    }

    /*  If STA is in wep+mixed and AP is in wep+open, Initially it starts with
        shared auth and then fall down to open mode if algo:shared,
        mode:mixed/auto and status code is not success */
    if ((algo == IEEE80211_AUTH_ALG_SHARED) &&
        ((authmode & (1<<WLAN_CRYPTO_AUTH_SHARED)) &&
         (authmode & (1<<WLAN_CRYPTO_AUTH_OPEN))) &&
        (status_code != IEEE80211_STATUS_SUCCESS))
    {
        wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE,
                              1 << WLAN_CRYPTO_AUTH_OPEN);
        ni->ni_authalg = IEEE80211_AUTH_ALG_OPEN;
        return -1;
    }

    /* Validate seq */
    if (seq != mlme_priv->im_expected_auth_seq_number) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Invalid seq %d,%d\n",
            __func__,
            seq, mlme_priv->im_expected_auth_seq_number);
        return -1;
    }
    if ((authmode & (1 << WLAN_CRYPTO_AUTH_SHARED)) &&
        (seq == IEEE80211_AUTH_SHARED_CHALLENGE) &&
        (status_code == IEEE80211_STATUS_SUCCESS))
    {
        /* Send the challenge response authentication packet.
         * We don't care if the send fails. If it does, the timeout routine will do
         * the necessary cleanup.
         */
        ieee80211_send_auth(ni, seq + 1, 0, challenge, challenge_length, NULL);
        mlme_priv->im_expected_auth_seq_number = IEEE80211_AUTH_SHARED_PASS;
        return 0;
    }

    if (!OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Timed-out already\n", __func__);
        return -1;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: mlme_auth_complete\n", __func__);

    if (vap->iv_roam.iv_roaming) {
        if (vap->iv_roam.iv_ft_roam) {
            qdf_mem_copy(vap->iv_roam.iv_ft_params.target_ap, wh->i_addr2, QDF_MAC_ADDR_SIZE);
            if (EOK == mlme_process_authresp_ft_elements(ni, frm, efrm - frm)) {
                int retval = 0;
                retval = vap->iv_ic->ic_vap_set_param(vap, IEEE80211_CONFIG_INDICATE_FT_ROAM, 1);
                /* In case of FT roam in HK we see key install before peer assoc which makes
                 * fw discard key install cmd to avoid this we notify fw about FT roam using
                 * peer set param cmd. For legacy this param is not required and not supported
                 * so we consider it as success. */
                if (retval == QDF_STATUS_SUCCESS || retval == QDF_STATUS_E_NOSUPPORT)
                    vap->iv_roam.iv_wait_for_ftie_update = 1;
                else
                    return -1;
            }
            else
                return -1;
        }
    }

    /* Request complete */
    mlme_priv->im_request_type = MLME_REQ_NONE;

    /* Authentication complete (success or failure) */
    IEEE80211_DELIVER_EVENT_MLME_AUTH_COMPLETE(vap, wh->i_addr3, status_code);
    return 0;
}

static int mlme_process_authresp_ft_elements(struct ieee80211_node *ni,
                                        u_int8_t              *frm,
                                        u_int32_t             ie_len)
{
    struct ieee80211vap          *vap = ni->ni_vap;
    u_int8_t                     *efrm = frm + ie_len;
    u_int8_t                     *ftie, *mdie, *rsnie;
    u_int16_t                    ftie_len, mdie_len, rsnie_len;
    u_int8_t                     *ies;

    ASSERT((vap->iv_opmode != IEEE80211_M_STA) || (ni == vap->iv_bss));

    ftie = mdie = rsnie = NULL;

    /* free any existing ft_params */
    if (vap->iv_roam.iv_ft_params.fties) {
        qdf_mem_free(vap->iv_roam.iv_ft_params.fties);
    }

    vap->iv_roam.iv_ft_params.fties = NULL;
    vap->iv_roam.iv_ft_params.fties_len = 0;
    while (frm < efrm) {
        switch (*frm) {
       case IEEE80211_ELEMID_FT:
            ftie = frm;
            break;

       case IEEE80211_ELEMID_MOBILITY_DOMAIN:
            mdie = frm;
            break;

       case IEEE80211_ELEMID_RSN:
            rsnie = frm;
            break;
        }
        /* elem id + len = 2 bytes */
        frm += frm[1] + 2;
    }

    if (!ftie || !mdie || !rsnie)
        return -1;

    ftie_len = mdie_len = rsnie_len = 0;
    ies = NULL;

    mdie_len = mdie[1];
    if (mdie_len != (MD_IE_LEN - 2))
        return -1;
    mdie_len += 2; /* additional 2bytes for elem id and length field */

    ftie_len = ftie[1];
    if (ftie_len < (MIN_FT_IE_LEN - 2) || ftie_len > (MAX_FT_IE_LEN - 2))
        return -1;
    ftie_len += 2; /*additional 2bytes for elem id and length field*/

    rsnie_len = rsnie[1];
    if (rsnie_len < (MIN_RSN_IE_LEN - 2) || rsnie_len > (MAX_RSN_IE_LEN - 2))
        return -1;
    rsnie_len += 2; /*additional 2bytes for elem id and length field*/

    vap->iv_roam.iv_ft_params.fties_len = mdie_len + ftie_len + rsnie_len;
    vap->iv_roam.iv_ft_params.fties = (u_int8_t *)qdf_mem_malloc(vap->iv_roam.iv_ft_params.fties_len);
    if(!vap->iv_roam.iv_ft_params.fties) {
        vap->iv_roam.iv_ft_params.fties_len = 0;
        qdf_mem_zero(vap->iv_roam.iv_ft_params.target_ap, QDF_MAC_ADDR_SIZE);
        return -1;
    }

    ies = vap->iv_roam.iv_ft_params.fties;
    /* copy MDE */
    qdf_mem_copy(ies, mdie, mdie_len);
    ies += mdie_len;

    /* copy FTE */
    qdf_mem_copy(ies, ftie, ftie_len);
    ies += ftie_len;

    /* copy RSNE */
    qdf_mem_copy(ies, rsnie, rsnie_len);

    return EOK;
}

void mlme_sta_bmiss_ind(wlan_if_t vap)
{
    ieee80211_mlme_event   event;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    /* deliver MLME event */
    event.u.event_bmiss.cur_bmiss_count = vap->iv_bmiss_count;
    event.u.event_bmiss.max_bmiss_count = vap->iv_bmiss_count_for_reset;
    event.type = IEEE80211_MLME_EVENT_BEACON_MISS;
    ieee80211_mlme_deliver_event(mlme_priv, &event);

    /* indicate beacon miss */
    IEEE80211_DELIVER_EVENT_BEACON_MISS(vap);
}

void
ieee80211_vap_iter_beacon_miss(void *arg, wlan_if_t vap)
{
    systime_t              tstamp;
    systime_t              last_link_time;
    systime_t              last_traffic_time;
#ifdef ATH_SWRETRY
    struct ieee80211com    *ic = vap->iv_ic;
#endif
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    ieee80211_mlme_event   event;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
                      "%s: %s iv_bmiss_count=%d reset=%d max=%d arg=%08p swbmiss=%d\n",
                      __func__,
                      (arg != NULL) ? "SW" : "HW",
                      vap->iv_bmiss_count,
                      vap->iv_bmiss_count_for_reset,
                      vap->iv_bmiss_count_max,
                      arg,
                      mlme_sta_swbmiss_active(vap));

    /*
     * Our handling is only meaningful for stations that are
     * associated; any other conditions else will be handled
     * through different means (e.g. the tx timeout on mgt frames).
     */
    if ((vap->iv_opmode != IEEE80211_M_STA) ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
        mlme_sta_swbmiss_timer_print_status(vap); /* print the status of sw bmiss */
        return;
    }

    /*
     * ignore HW beacon miss and completely rely on SW beacon miss
     * if 1. HW beacon processing is _not_ in use AND
     *    2. SW beacon miss is enabled.
     */
    if ((arg == NULL) && (!wlan_is_hwbeaconproc_active(vap) &&
            mlme_sta_swbmiss_active(vap))) {
        return;
    }

    /* When swbmiss comes, we need to ignore it when Hardware Beacon Processing is on */
    if ((arg != NULL) && wlan_is_hwbeaconproc_active(vap))
    {
        return ;
    }

    /*
     * WAR for excessive beacon miss problem on SoC.
     * Consider a beacon miss only when we have two consecutive
     * beacon misses and there are no rx activities in between.
     *
     * Count beacon misses only if we gave the AP a chance by sending a
     * directed Probe Request.
     *
     * Don't do anything if we are scanning a foreign channel.
     * Trying to transmit a frame (Probe Request) during a channel change
     * (which includes a channel reset) can cause a NMI due to invalid HW
     * addresses.
     * Trying to transmit a Probe Request while in a foreign channel
     * wouldn't do us any good either.
     *
     * Query current time only after retrieving LastLinkTime. This avoids
     * possible negative values if this routine is preempted by reception of
     * a beacon or directed frame which would update the fields used to
     * calculate LastLinkTime.
     */

    last_traffic_time = ieee80211_get_directed_frame_timestamp(vap);
    last_link_time = (vap->iv_last_beacon_time > last_traffic_time) ?
        vap->iv_last_beacon_time : last_traffic_time;
    tstamp = OS_GET_TIMESTAMP();

    {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN,
            "%d.%03d | %s: count=%d probe=%d beacon:%lums directed:%lums data:%lums ap_frame:%lums traffic_ind:%lums\n",
            ((u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(tstamp)) / 1000,
            ((u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(tstamp)) % 1000,
            __func__, vap->iv_bmiss_count,
            wlan_scan_can_transmit(wlan_vdev_get_pdev(vap->vdev_obj)),
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(tstamp - vap->iv_last_beacon_time),
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(tstamp - last_traffic_time),
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(tstamp - vap->iv_lastdata),
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(tstamp - ieee80211_get_last_ap_frame_timestamp(vap)),
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(tstamp - vap->iv_last_traffic_indication));
    }

    /*
     * Do not count beacon misses received when we're off-channel, or
     * within IEEE80211_MINIMUM_BMISS_TIME ms of the last valid beacon.
     */
    if ((!wlan_scan_in_home_channel(wlan_vdev_get_pdev(vap->vdev_obj))) ||
        (CONVERT_SYSTEM_TIME_TO_MS(tstamp - last_link_time) < IEEE80211_MINIMUM_BMISS_TIME)) {
        mlme_sta_swbmiss_timer_start(vap); /* restart beacon miss timer */
        return;
    }

#if UMAC_SUPPORT_WNM
    /* Ignore bmiss in WNM-Sleep Mode */
    if (wlan_get_powersave(vap) == IEEE80211_PWRSAVE_WNM) {
        mlme_sta_swbmiss_timer_start(vap); /* restart beacon miss timer */
        return;
    }
#endif

    vap->iv_bmiss_count++;


    event.u.event_bmiss.cur_bmiss_count = vap->iv_bmiss_count;
    event.u.event_bmiss.max_bmiss_count = vap->iv_bmiss_count_for_reset;
    event.type = IEEE80211_MLME_EVENT_BEACON_MISS;

    ieee80211_mlme_deliver_event(mlme_priv,&event);

    if (vap->iv_bmiss_count < vap->iv_bmiss_count_for_reset) {
#ifdef ATH_SWRETRY
        /* Turn off the sw retry mechanism until we receive
         * any data frame or probe response for the BSS we are
         * associated to.
         */
        if (ic->ic_set_swretrystate)
            ic->ic_set_swretrystate(vap->iv_bss, FALSE);
#endif

        /*
         * It is possible that the hardware gets into
         * deaf mode. Reset the hardware to see if it can recover
         * from the condition.
         */

        /* indicate device error */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s: Beacon miss, do internal reset!!\n", __func__);
        IEEE80211_DELIVER_EVENT_DEVICE_ERROR(vap);

        mlme_sta_swbmiss_timer_start(vap); /* restart beacon miss timer */
        return;
    }

    /*  max bmiss count reached */

    vap->iv_bmiss_count = 0;    /* reset bmiss counter */

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Beacon miss, will indicate to OS!!\n", __func__);
    /* indicate beacon miss */
    IEEE80211_DELIVER_EVENT_BEACON_MISS(vap);
}


void mlme_sta_reset_bmiss(struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    ieee80211_mlme_event   event;

    vap->iv_bmiss_count = 0;    /* reset bmiss counter */

    event.type = IEEE80211_MLME_EVENT_BEACON_MISS_CLEAR;
    ieee80211_mlme_deliver_event(mlme_priv,&event);
}

void ieee80211_inact_timeout_sta(struct ieee80211vap *vap)
{

    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    if ((mlme_priv==NULL) || !mlme_priv->im_connection_up ||
        vap->iv_vap_is_down) {
        return;
    }
    /*
     * if there was an activity in the last IEEE80211_INACT_WAIT period.
     * then reset the counter.
     */
    if (CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP() - vap->iv_last_directed_frame) < (IEEE80211_INACT_WAIT * 1000)) {
        vap->iv_inact_count = (vap->iv_keep_alive_timeout + IEEE80211_INACT_WAIT -1)/IEEE80211_INACT_WAIT;
    }
    if (vap->iv_inact_count) {
        --vap->iv_inact_count;
        if ((vap->iv_inact_count == 0) && (vap->iv_pwrsave_sta)) {
            ieee80211_send_nulldata(vap->iv_bss,false);
            if (vap->iv_keep_alive_timeout) {
                vap->iv_inact_count =  (vap->iv_keep_alive_timeout + IEEE80211_INACT_WAIT -1)/IEEE80211_INACT_WAIT;
            }
        }
    }
}

void mlme_sta_vattach(struct ieee80211vap *vap)
{
    mlme_sta_swbmiss_timer_attach(vap);
}

void mlme_sta_vdetach(struct ieee80211vap *vap)
{
    mlme_sta_swbmiss_timer_detach(vap);
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS

void mlme_cancel_stacac_timer(struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv *mlme_priv = vap->iv_mlme_priv;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Canceling STA_CAC timer \n");

	OS_CANCEL_TIMER(&mlme_priv->im_stacac_timeout_timer);
}

bool mlme_is_stacac_running(struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv *mlme_priv = vap->iv_mlme_priv;

    return (mlme_priv->im_is_stacac_running);
}

void mlme_set_stacac_running(struct ieee80211vap *vap, u_int8_t set)
{
    struct ieee80211_mlme_priv *mlme_priv = vap->iv_mlme_priv;

    mlme_priv->im_is_stacac_running = set;
}

bool mlme_is_stacac_valid(struct ieee80211vap *vap)
{
    struct ieee80211com    *ic = vap->iv_ic;

    return IEEE80211_IS_CHAN_CAC_VALID(ic->ic_curchan);
}

void mlme_set_stacac_valid(struct ieee80211vap *vap, u_int8_t set)
{
    struct ieee80211com    *ic = vap->iv_ic;

    if(set) {
        IEEE80211_CHAN_SET_CAC_VALID(ic->ic_curchan);
    } else {
        IEEE80211_CHAN_CLR_CAC_VALID(ic->ic_curchan);
    }
}
void mlme_reset_mlme_req(struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv *mlme_priv = vap->iv_mlme_priv;

    wlan_mlme_cancel(vap);
    mlme_priv->im_request_type = MLME_REQ_NONE;
}
void mlme_stacac_restore_defaults(struct ieee80211vap *vap)
{
        mlme_set_stacac_valid(vap,0);
        mlme_cancel_stacac_timer(vap);
        mlme_reset_mlme_req(vap);
        mlme_set_stacac_running(vap,0);
}
static bool mlme_is_stacac_needed_by_stadfsen(struct ieee80211vap *vap)
{

    struct ieee80211com *ic = vap->iv_ic;
    uint32_t dfs_reg = 0;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;

    pdev = ic->ic_pdev_obj;
    if(!pdev) {
        qdf_err("null pdev");
        return false;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("null psoc");
        return false;
    }

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
    if (!reg_rx_ops) {
        qdf_err("null reg_rx_ops");
        return false;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
            QDF_STATUS_SUCCESS) {
        return false;
    }
    reg_rx_ops->get_dfs_region(pdev, &dfs_reg);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);

    return ((DFS_ETSI_DOMAIN == dfs_reg) &&
            ieee80211com_has_cap_ext(ic,IEEE80211_CEXT_STADFS) &&
            IEEE80211_IS_CHAN_HISTORY_RADAR(ic, ic->ic_curchan)
           );
}
static bool mlme_is_stacac_needed_by_dependent_repeater(struct ieee80211vap *vap)
{
    struct ieee80211com    *ic = vap->iv_ic;

    return (!ieee80211_ic_enh_ind_rpt_is_set(ic) &&
            IEEE80211_IS_CSH_CAC_APUP_BYSTA_ENABLED(ic)
           );
}
static bool mlme_is_stacac_needed_by_independent_repeater(struct ieee80211vap *vap)
{
    struct ieee80211com    *ic = vap->iv_ic;

    return (ieee80211_ic_enh_ind_rpt_is_set(ic) &&
            !(IEEE80211_IS_CSH_CSA_APUP_BYSTA_ENABLED(ic)) &&
            IEEE80211_IS_CSH_CAC_APUP_BYSTA_ENABLED(ic)
           );
}
static bool mlme_is_chandfs_and_stacac_valid(struct ieee80211vap *vap)
{
    struct ieee80211com    *ic = vap->iv_ic;

    return (
            ((IEEE80211_IS_CHAN_DFS(ic->ic_curchan) ||
             ((IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) || IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
             && IEEE80211_IS_CHAN_DFS_CFREQ2(ic->ic_curchan)))
            ) &&
            (!mlme_is_stacac_valid(vap))
           );
}

bool mlme_is_stacac_needed(struct ieee80211vap *vap)
{
    /* Whether STA should do CAC or not
     * if ( (A || B || C) && D) {then do CAC }
     *
     * A:- If sta CAC is needed because of staDFSEn is set
     *     (mlme_is_stacac_needed_by_stadfsen)
     * B:- If sta CAC is needed becuase in Repeater Dependent mode
     *     sta should do CAC
     *     (mlme_is_stacac_needed_by_dependent_repeater)
     * C:- If TXCSA is not set and REPEATER_CAC is set
     *     (mlme_is_stacac_needed_by_independent_repeater)
     * D:- IF the channel is DFS and CAC is invalid
     *     (mlme_is_chandfs_and_stacac_valid)
     */

    return ((mlme_is_stacac_needed_by_stadfsen(vap) ||
             mlme_is_stacac_needed_by_dependent_repeater(vap) ||
             mlme_is_stacac_needed_by_independent_repeater(vap)
            )
            &&
            mlme_is_chandfs_and_stacac_valid(vap)
           );
}

#endif
void ieee80211_indicate_sta_radar_detect(struct ieee80211_node *ni)
{
     ieee80211_mlme_recv_csa(ni, IEEE80211_RADAR_DETECT_DEFAULT_DELAY,true);
}

void filter_ht20_dfs_channels(struct ieee80211_ath_channel_list *oldchan_info, struct ieee80211_ath_channel_list *newchan_info)
{
    int i, j = 0;

    for (i = 0; i < oldchan_info->cl_nchans; i++) {
        if (oldchan_info->cl_channels[i]->ic_flagext & IEEE80211_CHAN_DFS) {
            newchan_info->cl_channels[j++] = oldchan_info->cl_channels[i];
        }
    }
    newchan_info->cl_nchans = j;
}

void ieee80211_add_first_ht20_chan(struct ieee80211com *ic, struct ieee80211_ath_channel_list *chan_list)
{
    if (IEEE80211_IS_FLAG_VHT20(chan_list->cl_channels[0]->ic_flags) ||
        IEEE80211_IS_FLAG_VHT40(chan_list->cl_channels[0]->ic_flags) ||
        IEEE80211_IS_FLAG_HT40(chan_list->cl_channels[0]->ic_flags)) {
        chan_list->cl_channels[0] = ic->ic_find_channel(ic, chan_list->cl_channels[0]->ic_freq, 0,
               (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_HT20));
    }
}

bool is_subset_channel_for_cac(struct ieee80211com *ic, struct ieee80211_ath_channel *curchan,
        struct ieee80211_ath_channel *prevchan)
{
    struct ieee80211_ath_channel_list old_curchan_info = {0};
    struct ieee80211_ath_channel_list old_prevchan_info = {0};
    struct ieee80211_ath_channel_list cur_dfs_subchan_list = old_curchan_info;
    struct ieee80211_ath_channel_list prev_dfs_subchan_list = old_prevchan_info;
    uint8_t i, j;
    bool is_found = false;

    if (!prevchan || !curchan) {
        qdf_err("Channel pointer is NULL!");
        return is_found;
    } else if (!IEEE80211_IS_CHAN_5GHZ(curchan) ||
               !IEEE80211_IS_CHAN_5GHZ(prevchan)) {
        return true;
    }

    /* Get the list of dfs sub-channels in the previous channel */
    ieee80211_get_extchaninfo(ic, prevchan, &old_prevchan_info);
    /* ieee80211_get_extchaninfo returns the original channel into the first index
     * of the sub-channel list in case of all VHT40/VHT20. We need to to convert
     * it to HT20 channel.
     */
    ieee80211_add_first_ht20_chan(ic, &old_prevchan_info);
    filter_ht20_dfs_channels(&old_prevchan_info, &prev_dfs_subchan_list);

    /* Get the list of dfs sub-channels in the current channel */
    ieee80211_get_extchaninfo(ic, curchan, &old_curchan_info);
    ieee80211_add_first_ht20_chan(ic, &old_curchan_info);
    filter_ht20_dfs_channels(&old_curchan_info, &cur_dfs_subchan_list);

    /* Repater AP does CAC if the number of sub-channels in current channel is greater
     * that of previous channel.
     */
    if ((curchan->ic_freq == prevchan->ic_freq) &&
            (cur_dfs_subchan_list.cl_nchans > prev_dfs_subchan_list.cl_nchans)) {
        return false;
    }

    for (i = 0; i < cur_dfs_subchan_list.cl_nchans; i++) {
        is_found = false;
        for (j = 0; j < prev_dfs_subchan_list.cl_nchans; j++) {
            if (cur_dfs_subchan_list.cl_channels[i] == prev_dfs_subchan_list.cl_channels[j]) {
                is_found = true;
                break;
            }
        }

        /* If RootAP channel is not found, skip checking the next channels */
        if (is_found == false) {
            qdf_debug("The sub-channels of RootAP's operating channel are not a subset of the RepeaterAP's operating channel \n");
            break;
        }
    }

    /* If is_found == 0, then Repeater AP has to do CAC */
    qdf_debug("is_found = %d \n", is_found);
    return is_found;
}
