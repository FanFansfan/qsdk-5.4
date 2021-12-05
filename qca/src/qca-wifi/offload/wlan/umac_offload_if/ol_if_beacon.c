/*
 * Copyright (c) 2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */
/*
 * Copyright (c) 2011, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * UMAC beacon specific offload interface functions - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "qdf_mem.h"
#include "ol_cfg.h"
#if UNIFIED_SMARTANTENNA
#include <target_if_sa_api.h>
#endif
#include <wlan_objmgr_peer_obj.h>
#include <wlan_objmgr_vdev_obj.h>
#include <wlan_mgmt_txrx_utils_api.h>
#include <wlan_osif_priv.h>
#include <init_deinit_lmac.h>
#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif
#include <wlan_vdev_mgr_ucfg_api.h>
#include <wlan_vdev_mgr_utils_api.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <wlan_utility.h>
#include <target_if.h>
#include "pld_common.h"
#include <wlan_mlme_dispatcher.h>
#include <wmi_unified_vdev_api.h>

extern ol_ath_soc_softc_t *ol_global_soc[GLOBAL_SOC_SIZE];
extern int ol_num_global_soc;

#if ATH_PERF_PWR_OFFLOAD
/*
 *  WMI API for sending beacons
 */
#define BCN_SEND_BY_REF
void
ol_ath_beacon_send(struct ol_ath_softc_net80211 *scn,
                   int vid,
                   wbuf_t wbuf)
{
    struct beacon_params param;
    struct wlan_objmgr_psoc *psoc = NULL;

    QDF_STATUS status = wlan_objmgr_pdev_try_get_ref(scn->sc_pdev, WLAN_SA_API_ID);
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    if (QDF_IS_STATUS_ERROR(status)) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                  "%s, %d unable to get reference\n", __func__, __LINE__);
        return;
    }

    psoc = wlan_pdev_get_psoc(scn->sc_pdev);


    qdf_mem_set(&param, sizeof(param), 0);
    param.wbuf = wbuf;
    param.vdev_id = vid;
    if (ol_cfg_is_high_latency(NULL)) {
        param.is_high_latency = TRUE;

#ifdef DEBUG_BEACON
        qdf_nofl_info("%s frm length %d \n",__func__,bcn_len);
#endif
        wmi_unified_beacon_send_cmd(pdev_wmi_handle, &param);
    } else {
        A_UINT16  frame_ctrl;
        struct ieee80211_frame *wh;
        struct ieee80211_node *ni;
        struct ieee80211vap *vap;
        struct ol_ath_vap_net80211 *avn;
        struct ieee80211_beacon_offsets *bo;
        struct ieee80211_ath_tim_ie *tim_ie;
        A_UINT32 bcn_txant = 0;
        ni = wlan_wbuf_get_peer_node(wbuf);

        if (!ni) {
            wlan_objmgr_pdev_release_ref(scn->sc_pdev, WLAN_SA_API_ID);
            return;
        }
        vap = ni->ni_vap;
        avn = OL_ATH_VAP_NET80211(vap);
        bo = &avn->av_beacon_offsets;
        tim_ie = (struct ieee80211_ath_tim_ie *)
            bo->bo_tim;
        /* Get the frame ctrl field */
        wh = (struct ieee80211_frame *)wbuf_header(wbuf);
        frame_ctrl = __le16_to_cpu(*((A_UINT16 *)wh->i_fc));

        /* get the DTIM count */

        if (tim_ie->tim_count == 0) {
            param.is_dtim_count_zero = TRUE;
            if (tim_ie->tim_bitctl & 0x01) {
                /* deliver CAB traffic in next DTIM beacon */
                param.is_bitctl_reqd = TRUE;
            }
        }
        /* Map the beacon buffer to DMA region */
        qdf_nbuf_map_single(scn->soc->qdf_dev, wbuf, QDF_DMA_TO_DEVICE);

#if UNIFIED_SMARTANTENNA
        bcn_txant = target_if_sa_api_get_beacon_txantenna(psoc, scn->sc_pdev);
#endif

        param.frame_ctrl = frame_ctrl;
        param.bcn_txant = bcn_txant;
        wmi_unified_beacon_send_cmd(pdev_wmi_handle, &param);
    }
    wlan_objmgr_pdev_release_ref(scn->sc_pdev, WLAN_SA_API_ID);
    return;
}

/*
 * API to be invoked from the southbound infra for beacon-Tx.
 * It invokes the legacy beacon Tx API.
 */
QDF_STATUS
ol_ath_mgmt_beacon_send(struct wlan_objmgr_vdev *vdev,
                        wbuf_t wbuf)
{
    struct wlan_objmgr_pdev *pdev;
    struct ol_ath_softc_net80211 *scn;
    struct pdev_osif_priv *osif_priv;

    if (vdev) {
        pdev = wlan_vdev_get_pdev(vdev);
        if (pdev) {
            osif_priv = wlan_pdev_get_ospriv(pdev);
            scn = (struct ol_ath_softc_net80211 *)
                    osif_priv->legacy_osif_priv;
            ol_ath_beacon_send(scn, wlan_vdev_get_id(vdev), wbuf);
            return QDF_STATUS_SUCCESS;
        }
    }
    return QDF_STATUS_E_FAILURE;
}

/*
 * Function to check if beacon offload is enabled
 */
bool ol_ath_is_beacon_offload_enabled(ol_ath_soc_softc_t *soc)
{
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return false;
    }

    if (wlan_psoc_nif_feat_cap_get(soc->psoc_obj, WLAN_SOC_F_BCN_OFFLOAD) &&
        wmi_service_enabled(wmi_handle, wmi_service_beacon_offload)) {
        return true;
    }
    return false;
}

static bool
ol_ath_update_current_pp(struct ieee80211vap *vap)
{
    struct ieee80211com *ic         = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev   = ic->ic_pdev_obj;
    uint8_t prev_pp                 = ic->ic_mbss.current_pp;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    bool is_mbssid_enabled          = wlan_pdev_nif_feat_cap_get(pdev,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_ema_ap_enabled          = wlan_pdev_nif_feat_ext_cap_get(pdev,
                                            WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    bool is_non_tx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);

    if (is_mbssid_enabled &&
        is_ema_ap_enabled &&
        is_non_tx_vap) {
        /* Derive node_pos using access-strategy of non-tx vap */
        uint8_t node_pos = ieee80211_mbssid_get_non_tx_vap_node_idx(vap,
                                           scn->soc->ema_ap_num_max_vaps);
        struct ieee80211_mbss_ie_cache_node *node;
        uint8_t beacon_pos;

        if (node_pos < scn->soc->ema_ap_num_max_vaps) {
            node = (((struct ieee80211_mbss_ie_cache_node *)
                                 ic->ic_mbss.mbss_cache) + node_pos);
            beacon_pos = node->pos;

            qdf_assert(beacon_pos < ic->ic_mbss.max_pp);

            mbss_debug("vdev_id: %d beacon_pos: %d node_pos: %d",
                            vap->iv_unit, beacon_pos, node_pos);
            mbss_debug("node->vdev_id: %d", node->vdev_id);

            while (beacon_pos >= ic->ic_mbss.current_pp
                    && ic->ic_mbss.current_pp < ic->ic_mbss.max_pp) {
                ic->ic_mbss.current_pp++;
                while (ic->ic_mbss.max_pp % ic->ic_mbss.current_pp)
                    ic->ic_mbss.current_pp++;
            }

            qdf_assert(ic->ic_mbss.current_pp <= ic->ic_mbss.max_pp);
        } else {
            mbss_err("Invalid node_idx: %d", node_pos);
        }
    } /* end mbss enable if check */

    mbss_debug("prev_pp: %d current_pp: %d", prev_pp, ic->ic_mbss.current_pp);
    /* pp shrink is not allowed */
    qdf_assert(prev_pp <= ic->ic_mbss.current_pp);

    return (prev_pp < ic->ic_mbss.current_pp);
}

/* Is the vdev corresponding to this mbss_cache_node up?
 * Returns valid bssid_idx only if the vdev is in up-state
 */
static bool ol_ath_mbss_cache_node_beaconing_vdev_up(
        struct wlan_objmgr_pdev *pdev,
        struct ieee80211_mbss_ie_cache_node *node,
        uint8_t *bssid_idx)
{
    struct wlan_objmgr_vdev *vdev;
    struct ieee80211vap *vap;
    bool is_node_vdev_up = false;
    struct ol_ath_softc_net80211 *scn;

    scn = (struct ol_ath_softc_net80211 *) lmac_get_pdev_feature_ptr(pdev);
    if (!scn)
        goto exit;

    if (!bssid_idx)
        goto exit;

    /* Initialize bssid_idx to invalid idx. Valid range
     * of bssid_idx is 1 <= bssid_idx <= (MBSSID_GROUP_SIZE(ic) - 1)
     */
    *bssid_idx = MBSSID_GROUP_SIZE((struct ieee80211com *) &(scn->sc_ic));

    mbss_debug("vdev_id: %d", node->vdev_id);
    vdev = wlan_objmgr_get_vdev_by_id_from_pdev(
                pdev, node->vdev_id, WLAN_MLME_NB_ID);
    if (!vdev)
        goto exit;

    /* Derive vap */
    vap  = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (vap) {
        if (!node->used) {
            mbss_debug("node not allocated to any vap");
        } else {
            is_node_vdev_up = wlan_mbss_beaconing_vdev_up(vdev);

            /* Assign bssid_idx only if vdev is in up state */
            if (is_node_vdev_up)
                *bssid_idx = vap->vdev_mlme->mgmt.mbss_11ax.profile_idx;

            mbss_debug("vap is %s", is_node_vdev_up ? "UP" : "DOWN");
            mbss_debug("bssid_idx is %d", *bssid_idx);
        }
    } /* if (vap) */

    /* release vdev reference */
    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);

exit:
    return is_node_vdev_up;
}

static void ol_ath_iter_update_mbssie_cache(void *arg, struct ieee80211vap *vap)
{
    ieee80211_mbssid_update_mbssie_cache_entry(vap, MBSS_CACHE_ENTRY_CAP);
}

static bool ol_ath_is_single_bcntmp_update_allowed_for_non_tx_vap(
                                      struct ieee80211vap *vap)
{
    struct ieee80211com *ic       = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    bool is_mbssid_enabled        = wlan_pdev_nif_feat_cap_get(pdev,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_ema_ap_enabled        = wlan_pdev_nif_feat_ext_cap_get(pdev,
                                            WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    bool is_tx_vap = !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
    bool is_single_tmpl_update_allowed = false;
    bool pp_change = ol_ath_update_current_pp(vap);

    mbss_debug(":>");
    mbss_debug("is_mbssid_enabled: %d is_ema_ap_enabled: %d"
                "is_tx_vap: %d pp_change: %d", is_mbssid_enabled,
                is_ema_ap_enabled, is_tx_vap, pp_change);
    if (is_mbssid_enabled) {
        is_single_tmpl_update_allowed = (is_tx_vap || !is_ema_ap_enabled);
        if (!is_single_tmpl_update_allowed) {
            /* beacon template update for non-Tx vap
             * may get triggered in the following cases
             * 1. non-Tx profile change only
             * 2. vap create/delete
             * 3. vap up/down
             * 4. channel switch
             *
             * Note1: tmpl update for beacon common-
             * part change other than in case of CSA
             * for a non-Tx vap is prohibited.
             *
             * Note2: single template update in case
             * of 2 & 3 above can be identified from
             * whether there is a PP change or not.
             * In case 'up/down' no PP change. But in
             * case of 'create' there may be PP change
             * involved. PP shrink in case of 'delete'
             * is prohibited
             */
            mbss_debug("non_tx_profile_change: %d",
                    vap->iv_mbss.non_tx_profile_change);
            is_single_tmpl_update_allowed =
                    vap->iv_mbss.non_tx_profile_change;

            if (is_single_tmpl_update_allowed) {
                bool is_csa = ((ic->ic_flags & IEEE80211_F_CHANSWITCH) &&
                              (ic->ic_chanchange_channel != NULL));

                /* but in case of channel switch multi-tmplate
                 * update will be required even if PP did not
                 * change
                 */
                mbss_debug("is_csa: %d", is_csa);
                if (is_csa)
                    is_single_tmpl_update_allowed = false;
            }

            /* channel change will be allowed ideally
             * if there is no pp change. pp change
             * overrides single_temp_update - it means
             * multi-template update
             */
            if (pp_change)
                is_single_tmpl_update_allowed = false;
        }
    } else {
        is_single_tmpl_update_allowed = true;
    }

    /* retain pp change to check if multi-template
     * update is required when tbbt_update_event
     * is received
     */
    ic->ic_mbss.pp_change = pp_change;
    mbss_debug(":< %d", is_single_tmpl_update_allowed);
    return is_single_tmpl_update_allowed;
}

/*
 * Function to update beacon probe template
 */
static void
ol_ath_vdev_beacon_template_update(struct ieee80211vap *vap)
{
    struct ieee80211com *ic           = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc           = scn->soc;
    struct ol_ath_vap_net80211 *avn   = OL_ATH_VAP_NET80211(vap);
    struct ieee80211vap *transmit_vap = vap;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_pdev *pdev     = ic->ic_pdev_obj;
    bool is_mbssid_enabled            = wlan_pdev_nif_feat_cap_get(pdev,
                                                WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_ema_ap_enabled            = wlan_pdev_nif_feat_ext_cap_get(pdev,
                                                WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    bool is_non_tx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
    struct ieee80211_mbss_ie_cache_node *node = NULL, *saved_node = NULL;
    int error = 0, vdev_id;
    uint8_t nbcn = 0, node_idx;
    /* Initialize node_pos to the tx vap's node_pos */
    /* uint8_t node_pos = scn->soc->ema_ap_num_max_vaps -
                                ic->ic_mbss.rot_factor - 1; */
    uint8_t node_pos = 0;
    /* Allow or disallow single template update
     * for non-Tx vap
     */
    bool allow_ntx_single_tmpl_update = false;
    bool is_csa = ((ic->ic_flags & IEEE80211_F_CHANSWITCH) &&
                      (ic->ic_chanchange_channel != NULL));

    if (vap->iv_special_vap_mode && !vap->iv_smart_monitor_vap) {
        mbss_debug("vdev beacon template update not applicable for special vap!");
        return;
    }

    vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    mbss_debug("mbssid enabled: %d vdev_id: %d",
                        is_mbssid_enabled, vdev_id);

    if (is_mbssid_enabled) {
        mbss_debug("is_ema_ap_enabled: %d is_non_tx_vap: %d",
                               is_ema_ap_enabled, is_non_tx_vap);

        /* Update mbssie cache for capability update */
        wlan_iterate_vap_list(vap->iv_ic,
                    ol_ath_iter_update_mbssie_cache, NULL);

        /* Acquire mbss_cache_lock */
        qdf_spin_lock_bh(&ic->ic_mbss.mbss_cache_lock);

        transmit_vap = ic->ic_mbss.transmit_vap;
        if (!transmit_vap) {
            mbss_warn("Transmitting VAP can't be NULL!");
            goto OUT;
        }
        transmit_vap->iv_mbss.current_bcn_pos = 0;

        /* In MBSS case, avn points to transmitting VAP */
        avn = OL_ATH_VAP_NET80211(transmit_vap);

        if (is_non_tx_vap) {
            if (is_csa) {
                /* Send updated beacon template with CSA IE only for
                 * tx vap as there is only one set of beacons with
                 * PP beacons in case of EMA and only one beacon in
                 * case of non-EMA MBSSID case. In case of EMA, PP
                 * templates with CSA IE included will be sent to
                 * FW when beacon template update is triggered for
                 * CSA
                 */
                mbss_debug("skipping beacon template update in case"
                          " of csa for a non-tx vap");
                goto OUT;
            }

            allow_ntx_single_tmpl_update =
                ol_ath_is_single_bcntmp_update_allowed_for_non_tx_vap(vap);
            mbss_debug("allow_ntx_single_tmpl_update: %d",
                            allow_ntx_single_tmpl_update);

            if (allow_ntx_single_tmpl_update) {
                /* Derive node_pos using access-strategy of non-tx vap */
                node_pos = ieee80211_mbssid_get_non_tx_vap_node_idx(vap,
                                           scn->soc->ema_ap_num_max_vaps);
                if (node_pos >= scn->soc->ema_ap_num_max_vaps) {
                    mbss_err("Invalid node_idx: %d", node_pos);
                    goto OUT;
                }

                /* Retrieve node */
                node = &((struct ieee80211_mbss_ie_cache_node *)
                                        ic->ic_mbss.mbss_cache)[node_pos];
                /* Retrieve vdev_id */
                vdev_id = node->vdev_id;
            }

        } else {
            /* With EMA enabled, when CSA is invoked, channel_switch_state
             * is not set for Tx VAP, but only iv_bcn_csa_tmp_sent is set.
             * In MBSS/EMA case, Dont allow beacon template update in
             * case iv_bcn_csa_tmp_sent is set true for Tx VAP.
             * For Non Tx VAP, below channel_switch_state flag check
             * itself prevents any beacon template update until CSA
             * complete event is received from fw.
             */
            if (vap->iv_bcn_csa_tmp_sent) {
                mbss_warn("Skip bcn template update for Tx VAP in between CSA");
                goto OUT;
            }
        }
        /* Retrieve ref to first node in cache in case of tx-vap with ema
         */
        if (!allow_ntx_single_tmpl_update) {
            node = &((struct ieee80211_mbss_ie_cache_node *)
                                        ic->ic_mbss.mbss_cache)[node_pos];
        }
    } /* is_mbssid_enabled */

    qdf_spin_lock_bh(&avn->avn_lock);

    if (avn->av_wbuf == NULL) {
        qdf_spin_unlock_bh(&avn->avn_lock);
        qdf_debug("beacon buffer av_wbuf is NULL - Ignore Template update");
        goto OUT;
    }

    if (vap->channel_switch_state) {
        /* This condition is relaxed if it is in EMA AP mode and a
         * csa_status_event has already been received. If the
         * VAP is already in channel switch state then
         * iv_bcn_csa_tmp_sent can be false if csa_status_event
         * has been processed and if at all iv_bcn_csa_tmp_sent was
         * set while updating beacon template with CSA IE for
         * the tx-vap. Note that in case of EMA AP iv_bcn_csa_tmp_sent
         * may not be set for the tx-vap if each beacon position in
         * profile periodicity set has a non-tx vap in running state
         */
        if (!(is_ema_ap_enabled && !vap->iv_bcn_csa_tmp_sent)) {
            qdf_spin_unlock_bh(&avn->avn_lock);
            qdf_warn("Channel switch is ON - Ignore Template update");
            goto OUT;
        }
    }

    if (!is_mbssid_enabled ||
        !is_ema_ap_enabled ||
        (is_non_tx_vap     &&
        allow_ntx_single_tmpl_update) ||
        ic->ic_mbss.current_pp == 1) {
        if (allow_ntx_single_tmpl_update)
            mbss_debug("Single template update case for non_tx vap: %d", vdev_id);

        if(vap->iv_bss) {
            error = ieee80211_beacon_update(vap->iv_bss,
                    &avn->av_beacon_offsets,
                    avn->av_wbuf, 0
#if UMAC_SUPPORT_WNM
                    , 0
#endif
                    );

            if (error != -1) {
                ol_ath_bcn_tmpl_send(vdev_id, transmit_vap);
                if (is_mbssid_enabled) {
                    mbss_debug("Send bcn-template update for one vap only."
                               "vdev_id: %d tx_vdev id: %d",
                               vdev_id, transmit_vap->iv_unit);
                }
            }
        }
    } else {
        bool is_node_vdev_up = false;
        uint8_t node_idx_tx_vap = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                                        scn->soc->ema_ap_num_max_vaps);

        /* We must set the iv_bcn_csa_tmp_sent flag of tx vap here.
         * In multi-template case when PP > 1, the call to
         * ieee80211_beacon_update() below will be for the first
         * non-tx vaps that are in up state in each beacon pos.
         * So, ieee80211_add_channel_switch_ie() will set the above
         * flag for those non-tx vaps only and not for the tx vap
         */
        if (is_csa)
            transmit_vap->iv_bcn_csa_tmp_sent = true;

        mbss_debug("Send bcn-template update for %d beacons", ic->ic_mbss.current_pp);

        for (nbcn = 0; nbcn < ic->ic_mbss.current_pp; nbcn++) {
            uint8_t bssid_idx = MBSSID_GROUP_SIZE(ic);
            struct ieee80211_mbss_ie_cache_node *temp_node = NULL;
            uint8_t start_pos = 0;

            mbss_debug("beacon_pos: %d", nbcn);
            node_pos = 0;
            node = &((struct ieee80211_mbss_ie_cache_node *)
                                        ic->ic_mbss.mbss_cache)[node_pos];
            while ((node_pos < soc->ema_ap_num_max_vaps) &&
                   (((node->pos == nbcn) && (node_pos == node_idx_tx_vap)) ||
                   (node->pos != nbcn))) {
                node++;
                node_pos++;
            }

            temp_node = node;
            start_pos = node_pos;
            if (start_pos != 0) {
                while ((node_pos < soc->ema_ap_num_max_vaps) &&
                    !(is_node_vdev_up =
                    ol_ath_mbss_cache_node_beaconing_vdev_up(pdev, node, &bssid_idx))) {
                    node++;
                    node_pos++;

                    if ((node_pos >= soc->ema_ap_num_max_vaps) ||
                            (node->pos > nbcn)) {
                        mbss_debug("no vap in up state found in"
                                    " beacon position %d", nbcn);
                        break;
                    }
                } /* end while */
            } else {
                /* First node in the MBSS cache belongs to the current
                 * beacon-position 'nbcn' of the iteration
                 */
                uint8_t temp_bssid_idx = MBSSID_GROUP_SIZE(ic);
                bool is_temp_node_vdev_up = false;
                is_node_vdev_up =
                    ol_ath_mbss_cache_node_beaconing_vdev_up(pdev, node, &bssid_idx);

                temp_node++;
                node_pos++;
                /* Look for a node in the same beacon position that
                 * could hold a lower bssid_idx than the one in 'node'
                 * currently. Note theat the bssid_idx need to be consi
                 * dered if the vdev corresponding to the target vap is
                 * in up-sate
                 */
                while (node_pos < soc->ema_ap_num_max_vaps) {
                    is_temp_node_vdev_up =
                        ol_ath_mbss_cache_node_beaconing_vdev_up(pdev,
                                temp_node, &temp_bssid_idx);
                    if (is_temp_node_vdev_up && node->pos == temp_node->pos &&
                            temp_bssid_idx < bssid_idx) {
                        mbss_debug("VAP found with lower BSSID IDX in"
                                  " same beacon pos: pos=%d tmp_bssid_idx=%u"
                                  " bssid_idx=%u",
                                  node->pos, temp_bssid_idx, bssid_idx);
                        node = temp_node;
                        is_node_vdev_up = is_temp_node_vdev_up;
                        break;
                    }

                    temp_node++;
                    node_pos++;
                } /* end while */
            } /* end if (start_pos != 0) */

            if (node->pos == nbcn && is_node_vdev_up) {
                /* Retrieve vdev_id and vdev from node */
                vdev_id = node->vdev_id;
                vdev = wlan_objmgr_get_vdev_by_id_from_pdev(
                            pdev, vdev_id, WLAN_MLME_NB_ID);

                /* There is possibility of hitting this conidition
                 * due to node remapping for tx-vap case above along
                 * with possible other race conditions.
                 *
                 * If the node in the ema_ap_num_max_vaps-th pos
                 * is already deleted then vdev in that node will
                 * be null. A recovery attempt must be made to
                 * avoid possible FW assert
                 */
                if (!vdev) {
                    mbss_err("%d vdev is null. Make recovery"
                             " attempt of beacon template update\n"
                             " for this particular beacon position"
                             " by using tx-vdev in place", vdev_id);
                    /* It is ok to bail out if nbcn is 0. not otherwise */
                    if (nbcn == 0) {
                        break;
                    } else {
                        mbss_info("Attempting recovery with tx vap");
                        saved_node = node;
                        /* point it to tx vap */
                        node_idx = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                                        scn->soc->ema_ap_num_max_vaps);

                        if (node_idx < scn->soc->ema_ap_num_max_vaps) {
                            node = &((struct ieee80211_mbss_ie_cache_node *)
                                    ic->ic_mbss.mbss_cache)[node_idx];

                            vdev_id = node->vdev_id;
                            vdev = wlan_objmgr_get_vdev_by_id_from_pdev(
                                        pdev, vdev_id, WLAN_MLME_NB_ID);
                        }
                    }
                } /* if (!vdev) */

                if (vdev) {
                    vap = wlan_vdev_mlme_get_ext_hdl(vdev);

                    if (vap) {
                        if(vap->iv_bss) {
                            vap->iv_mbss.mbssid_update_ie = true;
                            error = ieee80211_beacon_update(vap->iv_bss,
                                    &avn->av_beacon_offsets,
                                    avn->av_wbuf, 0
#if UMAC_SUPPORT_WNM
                                    , 0
#endif
                                    );

                            if (error != -1) {
                                /* Override 'non_tx_profile_change' in case
                                 * of multi-template update
                                 */
                                vap->iv_mbss.current_bcn_pos = nbcn;
                                vap->iv_mbss.non_tx_profile_change = false;
                                ol_ath_bcn_tmpl_send(vdev_id, transmit_vap);
                                mbss_debug("Send bcn-template update for vdev_id: %d"
                                            " beacon position: %d", vdev_id, nbcn);
                            }
                        }
                    } /* end if vap */

                    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
                } /* end if vdev */

                /* Re-instate saved_node */
                if (saved_node) {
                    node = saved_node;
                    saved_node = NULL;
                }
            } else {
                mbss_debug("beacon_pos: %d", nbcn);
                mbss_debug("No vap up in beacon position %d."
                           "Send bcn-template update for tx-vap", nbcn);

                /* Update tx vap as no vap in upstate in current
                 * beacon position */
                transmit_vap->iv_mbss.current_bcn_pos  = nbcn;
                transmit_vap->iv_mbss.mbssid_update_ie = true;
                vdev_id = wlan_vdev_get_id(transmit_vap->vdev_obj);

                if (transmit_vap->iv_bss) {
                    error = ieee80211_beacon_update(transmit_vap->iv_bss,
                            &avn->av_beacon_offsets,
                            avn->av_wbuf, 0
#if UMAC_SUPPORT_WNM
                            , 0
#endif
                            );

                    if (error != -1) {
                        ol_ath_bcn_tmpl_send(vdev_id, transmit_vap);
                        mbss_debug("Send bcn-template update for vdev_id: %d"
                                   " beacon position: %d", vdev_id, nbcn);
                    }
                }
            } /* end if (node->pos == nbcn...*/

            if (error == -1) {
                /* If template send fails for one then give
                 * up for the rest of the templtes too
                 */
                mbss_err("template update failed");
                break;
            }
        } /* end for */
    }

    if (error == -1)
        qdf_err("%s: Failed to update beacon", __func__);

    qdf_spin_unlock_bh(&avn->avn_lock);

OUT:
    if (is_mbssid_enabled) {
        if (transmit_vap)
            transmit_vap->iv_mbss.current_bcn_pos = 0;
        if (vap)
            vap->iv_mbss.non_tx_profile_change = false;
        qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
    }
    return;
}

static void
ol_ath_vdev_prb_rsp_template_update(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    int error = 0;
    struct ieee80211vap *transmit_vap = NULL;
    uint8_t vdev_id = wlan_vdev_get_id(vap->vdev_obj);

    if (vap->iv_special_vap_mode && !vap->iv_smart_monitor_vap) {
        qdf_debug("vdev probe response template update not applicable for special vap!");
        return;
    }

    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        transmit_vap = ic->ic_mbss.transmit_vap;
        if (!transmit_vap) {
            qdf_warn("[MBSSID] Transmitting VAP can't be NULL!");
            return;
        }
        /* In MBSS case, avn points to transmitting VAP */
        avn = OL_ATH_VAP_NET80211(transmit_vap);
        vdev_id = wlan_vdev_get_id(transmit_vap->vdev_obj);
    }

    qdf_spin_lock_bh(&avn->avn_lock);

    if (avn->av_pr_rsp_wbuf == NULL) {
       qdf_spin_unlock_bh(&avn->avn_lock);
       qdf_debug("probe response buffer av_pr_rsp_wbuf is NULL - Ignore Template update");
       return;
    }

#if UMAC_SUPPORT_WNM
    if(vap->iv_bss) {
        error = ieee80211_prb_rsp_update(vap->iv_bss, &avn->av_prb_rsp_offsets,
                avn->av_pr_rsp_wbuf, 0, 0);
    }
#else
    if(vap->iv_bss) {
        error = ieee80211_prb_rsp_update(vap->iv_bss, &avn->av_prb_rsp_offsets,
                avn->av_pr_rsp_wbuf, 0);
    }
#endif

    if (error != -1) {
        if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
            if (!transmit_vap) {
                qdf_spin_unlock_bh(&avn->avn_lock);
                return;
            }
            ol_ath_prb_resp_tmpl_send(vdev_id, transmit_vap);
        } else {
            ol_ath_prb_resp_tmpl_send(vdev_id, vap);
        }
    } else {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
                  "%s: Failed to update beacon\n", __func__);
    }
    qdf_spin_unlock_bh(&avn->avn_lock);
    return;
}

#if UMAC_SUPPORT_QUIET
/*
 *  WMI API for sending cmd to set/unset Quiet Mode
 */
static void ol_ath_set_quiet_mode(struct ieee80211com *ic, uint8_t enable)
{
    struct ieee80211_quiet_param *quiet_ic = ic->ic_quiet;
    struct set_quiet_mode_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&param, sizeof(param), 0);
    param.enabled = enable;
    param.intval = ic->ic_intval;
    param.period = quiet_ic->period*ic->ic_intval;
    param.duration = quiet_ic->duration;
    param.offset = quiet_ic->offset;
    wmi_unified_set_quiet_mode_cmd_send(pdev_wmi_handle, &param);
}
static void
ol_ath_set_quiet_offload_config_params(wlan_if_t vap, struct ieee80211com *ic)
{
    struct ieee80211_quiet_param *quiet_ic = ic->ic_quiet;
    struct set_bcn_offload_quiet_mode_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle) {
        qdf_err("pdev_wmi_handle is NULL");
        return;
    }
    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    param.period = quiet_ic->period;
    param.duration = quiet_ic->duration;
    param.next_start = quiet_ic->offset;
    param.flag = vap->iv_quiet->is_enabled;
    wmi_unified_set_bcn_offload_quiet_mode_cmd_send(pdev_wmi_handle, &param);
}
#endif

int ol_ath_set_beacon_filter(wlan_if_t vap, uint32_t *ie)
{
    /* Issue WMI command to set beacon filter */
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct set_beacon_filter_params param;
    QDF_STATUS status;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev)
        return -EINVAL;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    param.ie = ie;

    status = wmi_unified_set_beacon_filter_cmd_send(pdev_wmi_handle, &param);
    return qdf_status_to_os_return(status);
}

int ol_ath_remove_beacon_filter(wlan_if_t vap)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct remove_beacon_filter_params param;
    QDF_STATUS status;

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev)
        return -EINVAL;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    qdf_mem_set(&param, sizeof(param), 0);
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    status = wmi_unified_remove_beacon_filter_cmd_send(pdev_wmi_handle, &param);
    return qdf_status_to_os_return(status);
}

void
ol_ath_set_probe_filter(void *data)
{
    /* TODO: Issue WMI command to set probe response filter */
    return;
}

static void
ol_ath_beacon_update(struct ieee80211_node *ni, int rssi)
{
    /* Stub for peregrine */
    return;
}

static int
ol_ath_net80211_is_hwbeaconproc_active(struct ieee80211com *ic)
{
    /* Stub for peregrine */
    return 0;
}

static void
ol_ath_net80211_hw_beacon_rssi_threshold_enable(struct ieee80211com *ic,
                                            u_int32_t rssi_threshold)
{
    /* TODO: Issue WMI command to set beacon RSSI filter */
    return;

}

static void
ol_ath_net80211_hw_beacon_rssi_threshold_disable(struct ieee80211com *ic)
{
    /* TODO: Issue WMI command to disable beacon RSSI filter */
    return;
}

struct ol_ath_iter_update_beacon_arg {
    struct ieee80211com *ic;
    int if_id;
};

static void ol_ath_vap_defer_prb_rsp_buf_free (struct ol_ath_vap_net80211 *avn)
{
    struct prb_rsp_entry* buf_entry;

    /* Set up buffer entry for Tx MBSS VAP only, so we return here
     * for a non-transmitting VAP
     */
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(&(avn->av_vap))) {
        return;
    }

    buf_entry = (struct prb_rsp_entry *)qdf_mem_malloc(
                    sizeof(struct prb_rsp_entry));
    if (buf_entry) {
        qdf_spin_lock_bh(&avn->avn_lock);
        if (avn->av_pr_rsp_wbuf == NULL) {
            qdf_spin_unlock_bh(&avn->avn_lock);
            qdf_mem_free(buf_entry);
            return;
        }
#ifdef BCN_SEND_BY_REF
        buf_entry->is_dma_mapped = avn->is_dma_mapped;
        /* clear dma_mapped flag */
        avn->is_dma_mapped = 0;
#endif
        buf_entry->prb_rsp_buf = avn->av_pr_rsp_wbuf;
        TAILQ_INSERT_TAIL(&avn->deferred_prb_rsp_list, buf_entry, deferred_prb_rsp_list_elem);
        avn->av_pr_rsp_wbuf =  NULL;
        qdf_spin_unlock_bh(&avn->avn_lock);
    }
    else {
        qdf_nofl_info("ERROR: qdf_mem_malloc failed %s: %d \n", __func__, __LINE__);
        ASSERT(0);
    }

}

/* Move the beacon buffer to deferred_bcn_list */
static void
ol_ath_vap_defer_beacon_buf_free(struct ol_ath_vap_net80211 *avn)
{
    struct bcn_buf_entry* buf_entry;

    /* Set up buffer entry for Tx MBSS VAP only, so we return here
     * for a non-transmitting VAP
     */
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(&(avn->av_vap))) {
        avn->av_wbuf = NULL;
        return;
    }

    buf_entry = (struct bcn_buf_entry *)qdf_mem_malloc(
	         sizeof(struct bcn_buf_entry));
    if (buf_entry) {
        qdf_spin_lock_bh(&avn->avn_lock);
        if(avn->av_wbuf == NULL){
            qdf_spin_unlock_bh(&avn->avn_lock);
            qdf_mem_free(buf_entry);
            return;
        }
#ifdef BCN_SEND_BY_REF
        buf_entry->is_dma_mapped = avn->is_dma_mapped;
        /* clear dma_mapped flag */
        avn->is_dma_mapped = 0;
#endif
        buf_entry->bcn_buf = avn->av_wbuf;
        TAILQ_INSERT_TAIL(&avn->deferred_bcn_list, buf_entry, deferred_bcn_list_elem);
        avn->av_wbuf =  NULL;
        qdf_spin_unlock_bh(&avn->avn_lock);
    }
    else {
        qdf_nofl_info("ERROR: qdf_mem_malloc failed %s: %d \n", __func__, __LINE__);
        ASSERT(0);
    }
}

static void ol_ath_vap_iter_20tu_prb_rsp_alloc(void *arg, wlan_if_t vap)
{
    struct ol_ath_iter_update_beacon_arg* params =
                            (struct ol_ath_iter_update_beacon_arg *)arg;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_node *ni;

    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        QDF_TRACE(QDF_MODULE_ID_MBSSIE, QDF_TRACE_LEVEL_DEBUG,
                 "20TU prb rsp alloc done for Tx Vap only!\n");
        return;
    }

    if (wlan_vdev_get_id(vap->vdev_obj) == params->if_id) {
        ni = vap->iv_bss;
        avn->av_pr_rsp_wbuf = ieee80211_prb_rsp_alloc_init(ni,
                                                &avn->av_prb_rsp_offsets);
        if (avn->av_pr_rsp_wbuf == NULL) {
            qdf_nofl_info("ERROR ieee80211_prb_rsp_alloc failed in %s:%d\n"
                                                        , __func__, __LINE__);
            A_ASSERT(0);
        }
    }
    return;
}

/* offload Pr Resp APIs */
void ol_ath_20tu_prb_rsp_alloc(struct ieee80211com *ic, int if_id)
{
    struct ol_ath_iter_update_beacon_arg params;
    params.ic = ic;
    params.if_id = if_id;
    wlan_iterate_vap_list(ic, ol_ath_vap_iter_20tu_prb_rsp_alloc,
                                                    (void *) &params);
}

/*
 * Function to allocate beacon in host mode
 */
static void ol_ath_vap_iter_beacon_alloc(void *arg, wlan_if_t vap)
{
    struct ol_ath_iter_update_beacon_arg* params =
                                (struct ol_ath_iter_update_beacon_arg *)arg;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_node *ni;

    if (wlan_vdev_get_id(vap->vdev_obj) == params->if_id) {
        ni = vap->iv_bss;
        /* Beacon buffer is already allocated,
         * Move the beacon buffer to deferred_bcn_list to
         * free the buffer on vap stop
         * and allocate a new beacon buufer
         */
        ol_ath_vap_defer_beacon_buf_free(avn);
        avn->av_wbuf = ieee80211_beacon_alloc(ni, &avn->av_beacon_offsets);
        if (!avn->av_wbuf) {
            qdf_nofl_info("ERROR ieee80211_beacon_alloc failed in %s:%d\n",
                          __func__, __LINE__);
            A_ASSERT(0);
        }
    }
    return;
}

/*
 * Function to free beacon in host mode
 */
static void
ol_ath_vap_iter_beacon_free(void *arg, wlan_if_t vap)
{
    struct ol_ath_iter_update_beacon_arg* params = (struct ol_ath_iter_update_beacon_arg *)arg;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
#ifdef BCN_SEND_BY_REF
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#endif

    if (wlan_vdev_get_id(vap->vdev_obj) == params->if_id) {
            struct bcn_buf_entry* buf_entry,*buf_temp;
            struct ieee80211_tx_status ts;
            ts.ts_flags = 0;
            ts.ts_retries = 0;
            qdf_spin_lock_bh(&avn->avn_lock);
            TAILQ_FOREACH_SAFE(buf_entry, &avn->deferred_bcn_list, deferred_bcn_list_elem,buf_temp) {
                TAILQ_REMOVE(&avn->deferred_bcn_list, buf_entry, deferred_bcn_list_elem);
#ifdef BCN_SEND_BY_REF
                if (buf_entry->is_dma_mapped == 1) {
                    qdf_nbuf_unmap_single(scn->soc->qdf_dev,
                              buf_entry->bcn_buf,
                              QDF_DMA_TO_DEVICE);
                    buf_entry->is_dma_mapped = 0;
                }
#endif
                ieee80211_complete_wbuf(buf_entry->bcn_buf, &ts);
                qdf_mem_free(buf_entry);
            }
            qdf_spin_unlock_bh(&avn->avn_lock);
    }
    return;
}

/*
 * Function to free prb rsp in host mode
 */
static void
ol_ath_vap_iter_prb_rsp_free(void *arg, wlan_if_t vap)
{
    struct ol_ath_iter_update_beacon_arg* params = (struct ol_ath_iter_update_beacon_arg *)arg;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
#ifdef BCN_SEND_BY_REF
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#endif

    if (wlan_vdev_get_id(vap->vdev_obj) == params->if_id) {
            struct prb_rsp_entry* buf_entry,*buf_temp;
            struct ieee80211_tx_status ts;
            ts.ts_flags = 0;
            ts.ts_retries = 0;
            qdf_spin_lock_bh(&avn->avn_lock);
            TAILQ_FOREACH_SAFE(buf_entry, &avn->deferred_prb_rsp_list, deferred_prb_rsp_list_elem,buf_temp) {
                TAILQ_REMOVE(&avn->deferred_prb_rsp_list, buf_entry, deferred_prb_rsp_list_elem);
#ifdef BCN_SEND_BY_REF
                if (buf_entry->is_dma_mapped == 1) {
                    qdf_nbuf_unmap_single(scn->soc->qdf_dev,
                              buf_entry->prb_rsp_buf,
                              QDF_DMA_TO_DEVICE);
                    buf_entry->is_dma_mapped = 0;
                }
#endif
                ieee80211_complete_wbuf(buf_entry->prb_rsp_buf, &ts);
                qdf_mem_free(buf_entry);
            }
            qdf_spin_unlock_bh(&avn->avn_lock);
    }
    return;
}

/*
 * offload beacon APIs for other offload modules
 */
void ol_ath_beacon_alloc(struct ieee80211vap *vap)
{
    struct ol_ath_iter_update_beacon_arg params;

    params.ic = vap->iv_ic;
    params.if_id = (int)wlan_vdev_get_id(vap->vdev_obj);
    wlan_iterate_vap_list(vap->iv_ic, ol_ath_vap_iter_beacon_alloc,
                          (void *) &params);
}

void ol_ath_prb_rsp_stop(struct ol_ath_vap_net80211 *avn)
{
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(&(avn->av_vap))) {
        /*  Beacon buffer is set up for tx VAP only */
        return;
    }

    ol_ath_vap_defer_prb_rsp_buf_free(avn);
}

void ol_ath_beacon_stop(struct ol_ath_vap_net80211 *avn)
{
    struct ieee80211_tx_status ts;

    ts.ts_flags = 0;
    ts.ts_retries = 0;
    /* Move the beacon buffer to deferred_bcn_list
     * and wait for stooped event from Target.
     * beacon buffer in deferred_bcn_list gets freed - on
     * vap stopped event from Target
     */
    ol_ath_vap_defer_beacon_buf_free(avn);
}

void ol_ath_beacon_free(struct ieee80211vap *vap)
{
    struct ol_ath_iter_update_beacon_arg params;

    params.ic = vap->iv_ic;
    params.if_id = (int)wlan_vdev_get_id(vap->vdev_obj);
    wlan_iterate_vap_list(vap->iv_ic, ol_ath_vap_iter_beacon_free,
                          (void *) &params);
}

void ol_ath_prb_rsp_free(struct ieee80211vap *vap)
{
    struct ol_ath_iter_update_beacon_arg params;

    params.ic = vap->iv_ic;
    params.if_id = (int)wlan_vdev_get_id(vap->vdev_obj);
    ol_ath_vap_iter_prb_rsp_free((void *) &params, vap);
}

#if UMAC_SUPPORT_QUIET
/**
 * ol_ath_update_quiet_params() - Updates quiet element in the
 * beacon and the VAP quite params
 * @vap: pointer to ieee80211 vap
 *
 * Return: none
 */
static void ol_ath_update_quiet_params(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_quiet_param *quiet_iv = vap->iv_quiet;
    struct ieee80211_quiet_param *quiet_ic = ic->ic_quiet;
    struct ieee80211vap *quiet_vap = TAILQ_FIRST(&ic->ic_vaps);

    /* Update quiet params for the vap with beacon offset 0 */
    if (quiet_ic->is_enabled) {

        uint64_t tsf_adj;
        ucfg_wlan_vdev_mgr_get_tsf_adjust(vap->vdev_obj, &tsf_adj);
        /* convert tsf adjust in to TU */
        tsf_adj = tsf_adj >> 10;

        /* Compute the beacon_offset from slot 0 */
        if (tsf_adj)
            quiet_iv->beacon_offset = ic->ic_intval - tsf_adj;
        else
            quiet_iv->beacon_offset = 0;

        while (quiet_vap) {
            if (!quiet_vap->iv_vap_is_down)
                    break;
            quiet_vap = TAILQ_NEXT(quiet_vap, iv_next);
        }

        if (quiet_vap && (vap->iv_unit == quiet_vap->iv_unit)) {
            quiet_ic->beacon_offset = quiet_iv->beacon_offset;

            if (quiet_ic->tbttcount == 1)
                quiet_ic->tbttcount = quiet_ic->period;
            else
                quiet_ic->tbttcount--;

            if (quiet_ic->tbttcount == 1)
                ol_ath_set_quiet_mode(ic,1);
            else if (quiet_ic->tbttcount == (quiet_ic->period-1))
                ol_ath_set_quiet_mode(ic,0);
        }
    } else if (quiet_ic->tbttcount != quiet_ic->period) {
        /* quiet support is disabled
         * since tbttcount is not '0', the hw quiet period was set before
         * so just disable the hw quiet period and
         * tbttcount to 0.
         */
         quiet_ic->tbttcount = quiet_ic->period;
         ol_ath_set_quiet_mode(ic,0);
    }
}
#endif /* UMAC_SUPPORT_QUIET */

/* returns the pointer to beacon buffer for the vdev
 * used by pktlog message handler to retrieve the beacon
 * header
 */

void *
ol_ath_get_bcn_header(ol_pdev_handle pdev, A_UINT32 vdev_id)
{
    struct ieee80211vap *vap;
    struct ol_ath_softc_net80211 *scn;
    struct ol_ath_vap_net80211 *avn;

    scn = (struct ol_ath_softc_net80211 *) pdev;
    if (!scn)
	return NULL;

    vap = ol_ath_vap_get(scn, vdev_id);
    if (!vap)
        return NULL;
    avn = OL_ATH_VAP_NET80211(vap);

    if ((avn == NULL) || (avn->av_wbuf == NULL))
    {
        qdf_nofl_info("%s: Invalid buffer pointer\n",__func__);
        ol_ath_release_vap(vap);
        return NULL;
    }
    ol_ath_release_vap(vap);
    return (wbuf_header(avn->av_wbuf));
}
qdf_export_symbol(ol_ath_get_bcn_header);

/* returns the pointer to beacon buffer for the vdev
 * used by pktlog message handler
 */

void *
ol_ath_get_bcn_buffer(ol_pdev_handle pdev, A_UINT32 vdev_id)
{
    struct ieee80211vap *vap;
    struct ol_ath_softc_net80211 *scn;
    struct ol_ath_vap_net80211 *avn;

    scn = (struct ol_ath_softc_net80211 *) pdev;
    if (!scn)
	return NULL;

    vap = ol_ath_vap_get(scn, vdev_id);
    if (!vap)
        return NULL;
    avn = OL_ATH_VAP_NET80211(vap);

    if (!avn || !avn->av_wbuf) {
        ASSERT(avn != NULL);
        ASSERT(avn->av_wbuf != NULL);
        qdf_err("beacon buffer vacant");
        ol_ath_release_vap(vap);
        return NULL;
    }
    ol_ath_release_vap(vap);

    return (avn->av_wbuf);
}
qdf_export_symbol(ol_ath_get_bcn_buffer);

void ieee80211_wnm_timbcast_send(struct ieee80211vap *vap)
{
    struct ieee80211_node *ni = vap->iv_bss;
    struct ieee80211com *ic = vap->iv_ic;
    wbuf_t wbuf_tim_hr = NULL;
    wbuf_t wbuf_tim_lr = NULL;
    struct ol_ath_vap_net80211 *avn;
    int error = 0;

    avn = OL_ATH_VAP_NET80211(vap);
    if (ieee80211_wnm_timbcast_enabled(vap) > 0) {
        if (ieee80211_wnm_timbcast_cansend(vap) > 0) {
            if (ni && ieee80211_timbcast_highrateenable(vap)) {
                ieee80211_ref_node(ni, WLAN_MLME_SB_ID);
                wbuf_tim_hr = ieee80211_timbcast_alloc(ni);
                if (wbuf_tim_hr) {
                    error = ieee80211_timbcast_update(vap->iv_bss,
                                         &avn->av_beacon_offsets, wbuf_tim_hr);
                    if (error) {
                        wbuf_free(wbuf_tim_hr);
                        wbuf_tim_hr = NULL;
                    } else {
                        wbuf_set_tid(wbuf_tim_hr, EXT_TID_NONPAUSE);
                        wbuf_set_tx_rate(wbuf_tim_hr, 0, 0, 1, ic->ic_he_target); //24Mbps
                        ieee80211_send_mgmt(vap, ni, wbuf_tim_hr, true);
                    }
                }
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            }
            if (ni && ieee80211_timbcast_lowrateenable(vap)) {
                ieee80211_ref_node(ni, WLAN_MLME_SB_ID);
                wbuf_tim_lr = ieee80211_timbcast_alloc(ni);
                if (wbuf_tim_lr) {
                    error = ieee80211_timbcast_update(vap->iv_bss,
                                          &avn->av_beacon_offsets, wbuf_tim_lr);
                    if (error) {
                        wbuf_free(wbuf_tim_lr);
                        wbuf_tim_lr = NULL;
                    } else {
                        ieee80211_send_mgmt(vap, ni, wbuf_tim_lr, true);
                    }
                }
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            }
        }
    }
}

/**
 * ol_prepare_send_vap_bcn() - Prepares and sends beacon for a vap
 * @vap: pointer to ieee80211 vap
 * @tim_info: TIM info in SWBA event
 *
 * Return: Return 0 on success, other value on failure
 */
static inline int
ol_prepare_send_vap_bcn(struct ieee80211vap *vap, wmi_host_tim_info *tim_info)
{
    struct ol_ath_vap_net80211 *avn;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211((vap->iv_ic));
    struct ieee80211_node *ni = vap->iv_bss;
    int error = 0, retval = -1;

    /*
     * Update the TIM bitmap. At VAP attach memory will be allocated for TIM
     * based on the iv_max_aid set. Update this field and beacon update will
     * automatically take care of populating the bitmap in the beacon buffer.
     */
    if (vap->iv_tim_bitmap && tim_info->tim_changed) {

        /* The tim bitmap is a byte array that is passed through WMI as a
         * 32bit word array. The CE will correct for endianess which is
         * _not_ what we want here. Un-swap the words so that the byte
         * array is in the correct order.
         */
#ifdef BIG_ENDIAN_HOST
        int j;
        for (j = 0; j < WMI_HOST_TIM_BITMAP_ARRAY_SIZE; j++) {
            tim_info->tim_bitmap[j] = le32_to_cpu(tim_info->tim_bitmap[j]);
        }
#endif
        if (tim_info->tim_len <= MAX_TIM_BITMAP_LENGTH) {
            vap->iv_tim_len = (uint16_t)tim_info->tim_len;
            OS_MEMCPY(vap->iv_tim_bitmap, tim_info->tim_bitmap,
                      vap->iv_tim_len);
            vap->iv_ps_pending = tim_info->tim_num_ps_pending;

            IEEE80211_VAP_TIMUPDATE_ENABLE(vap);
        } else {
            qdf_nofl_info("\n%s : Ignoring TIM Update for the VAP (%d) because "
                          "of INVALID Tim length from the firmware\n",
                          __func__, wlan_vdev_get_id(vap->vdev_obj));
        }
    }

    /* Update quiet params and beacon update will take care of the rest */
    avn = OL_ATH_VAP_NET80211(vap);
    qdf_spin_lock_bh(&avn->avn_lock);

    if (!avn->av_wbuf) {
        qdf_spin_unlock_bh(&avn->avn_lock);
        qdf_err("beacon buffer av_wbuf is NULL - Ignoring SWBA event");
        return retval;
    }

#if UMAC_SUPPORT_QUIET
    ol_ath_update_quiet_params(vap);
#endif /* UMAC_SUPPORT_QUIET */
#if UMAC_SUPPORT_WNM
    if (vap->iv_bss) {
        error = ieee80211_beacon_update(vap->iv_bss, &avn->av_beacon_offsets,
                                        avn->av_wbuf, tim_info->tim_mcast, 0);
    }
#else
    if (vap->iv_bss) {
        error = ieee80211_beacon_update(vap->iv_bss, &avn->av_beacon_offsets,
                                        avn->av_wbuf, tim_info->tim_mcast);
    }
#endif
    if (error != -1) {

#if UMAC_SUPPORT_WNM
        ieee80211_wnm_timbcast_send(vap);
#endif

        if (!vap->iv_bcn_offload_enable && ni) {
        /* Send beacon to target */
#ifdef BCN_SEND_BY_REF
            if (avn->is_dma_mapped) {
                qdf_nbuf_unmap_single(scn->soc->qdf_dev, avn->av_wbuf,
                                      QDF_DMA_TO_DEVICE);
                avn->is_dma_mapped = 0;
            }
#endif
            retval = wlan_mgmt_txrx_beacon_frame_tx(ni->peer_obj,
                                                    avn->av_wbuf,
                                                    WLAN_UMAC_COMP_MLME);
            if (!retval) {
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_tx_bcn_swba_inc(vap->vdev_obj, 1);
#endif

#ifdef BCN_SEND_BY_REF
                avn->is_dma_mapped = 1;
#endif
            } else {
                /*
                 * The caller expects -1 in return for failure.
                 * As the failure returned from mgmt_txrx
                 * is greater than 0, retval should be assigned
                 * appropriately.
                 */
                retval = -1;
            }
        }
    }
    qdf_spin_unlock_bh(&avn->avn_lock);
    return retval;
}

/*
 * Handler for Host SWBA events in host mode
 */
static int ol_ath_beacon_swba_handler(ol_ath_soc_softc_t *soc, uint8_t *data)
{
    struct ieee80211vap *vap = NULL;
    wmi_host_tim_info tim_info = {0};
#if UMAC_SUPPORT_QUIET
    wmi_host_quiet_info quiet_info = {0};
#endif
    uint8_t vdev_id = 0, idx = 0;
    uint32_t num_vdevs = 0;
    struct wlan_objmgr_vdev *vdev;
    bool disable_beacon = false;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_swba_num_vdevs(wmi_handle, data, &num_vdevs)) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                  "%s: Unable to extact num vdevs from swba event\n", __func__);
        return -1;
    }

    /* Generate LP IOT vap beacons first and then send other vap beacons later
    */
    if (soc->soc_lp_iot_vaps_mask) { /* if there LP IOT vaps */
        for (idx = 0; idx < num_vdevs; idx++) {

            if (wmi_extract_swba_tim_info(wmi_handle, data, idx, &tim_info)) {
                return -1;
            }

            /* Proceed only if beacon_offload is disabled */
            if (ol_ath_is_beacon_offload_enabled(soc))
                continue;

            vdev_id = tim_info.vdev_id;
            vdev = wlan_objmgr_get_vdev_by_id_from_psoc(soc->psoc_obj, vdev_id,
                                                        WLAN_MLME_SB_ID);
            if (!vdev) {
                /*should continue if vdev is NULL*/
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                          "%s: Unable to find vdev for %d vdev_id\n",
                          __func__, vdev_id);
                continue;
            }
            if ((vap = wlan_vdev_get_mlme_ext_obj(vdev))) {
                /* Disable beacon if VAP is operating in NAWDS bridge mode */
                if (ieee80211_nawds_disable_beacon(vap)){
                    disable_beacon = true;
                }
            }

            if ((!vap) || (disable_beacon)) {
                /*should continue if current vap is NULL*/
                wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                disable_beacon = false;
                continue;
            }
            if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP)   {
#if ATH_NON_BEACON_AP
                if (IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
                    /*for non-beaconing VAP, don't send beacon*/
                    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                    continue;
                }
#endif
                /* If vap is not active, no need to queue beacons to FW, Ignore SWBA*/
                if (wlan_vdev_is_up(vdev) != QDF_STATUS_SUCCESS) {
                    qdf_info("vap %d: drop SWBA event, since vap is not active",
                             vdev_id);
                    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                    continue;
                }
                if (ol_prepare_send_vap_bcn(vap, &tim_info) < 0) {
                    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                    return -1;
                }
           }
           wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
        }
    }

    /* Generate a beacon for all vaps other than lp_iot vaps specified in the list */
    for (idx = 0; idx < num_vdevs; idx++) {

        if (wmi_extract_swba_tim_info(wmi_handle, data, idx, &tim_info)) {
            qdf_err("Extract tim_info_vid %d for %d vdev_id psoc_id %d",
                    tim_info.vdev_id, vdev_id,
                    soc->psoc_obj->soc_objmgr.psoc_id);
            return -1;
        }
        /* Proceed only if beacon offload is disabled */
        if (ol_ath_is_beacon_offload_enabled(soc))
            continue;

        vdev_id = tim_info.vdev_id;
        vdev = wlan_objmgr_get_vdev_by_id_from_psoc(soc->psoc_obj, vdev_id,
                                                    WLAN_MLME_SB_ID);
        if (!vdev) {
            /*should continue if vdev is NULL*/
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                      "%s: Unable to find vdev for %d vdev_id\n",
                      __func__, vdev_id);
            continue;
        }
        if ((vap = wlan_vdev_get_mlme_ext_obj(vdev))) {
           /* Disable beacon if VAP is operating in NAWDS bridge mode */
           if (ieee80211_nawds_disable_beacon(vap))
               disable_beacon = true;
        }

        if ((!vap) || (disable_beacon)){
            /*should continue if current vap is NULL*/
            wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
            disable_beacon = false;
            qdf_err("Unable to find vap for %d vdev_id\n", vdev_id);
            continue;
        }

        /* Skip LP IOT vaps. They have been sent already */
        if (!(vap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
#if ATH_NON_BEACON_AP
             if (IEEE80211_VAP_IS_NON_BEACON_ENABLED(vap)){
                 wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                 /*for non-beaconing VAP, don't send beacon*/
                 continue;
            }
#endif
            /* If vap is not active, no need to queue beacons to FW, Ignore SWBA*/
            if (wlan_vdev_is_up(vdev) != QDF_STATUS_SUCCESS) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
                    "vap %d: drop SWBA event, since vap is not active",
                    vdev_id);
                wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                continue;
            }
            if (ol_prepare_send_vap_bcn(vap, &tim_info) < 0) {
                wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                qdf_err("[%s]:Prepare_send_vap_bcn failure ",
                          vap->iv_netdev_name );
                return -1;
            }
        }
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
    }

#if UMAC_SUPPORT_QUIET
    for (idx = 0; idx < num_vdevs; idx++) {
        if (wmi_extract_swba_quiet_info(wmi_handle, data, idx, &quiet_info)) {
            return -1;
        }
        if (quiet_info.tbttcount == 0) {
            continue;
        }

        vdev_id = quiet_info.vdev_id;
        vdev = wlan_objmgr_get_vdev_by_id_from_psoc(soc->psoc_obj, vdev_id,
                                                    WLAN_MLME_SB_ID);
        if (!vdev) {
            /*should continue if vdev is NULL*/
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                    "%s: Unable to find vdev for %d vdev_id\n",
                    __func__, vdev_id);
            continue;
        }

        vap = wlan_vdev_get_mlme_ext_obj(vdev);
        if (!vap){
            /*should continue if vap is NULL*/
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                      "%s: Unable to find vap for %d vdev_id\n",
                      __func__, vdev_id);
            wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
            continue;
        }
        if (vap->iv_bcn_offload_enable) {
            /* In beacon offload case, quiet IE is offloaded to FW. So in
             * case if probe response needs it, we need to update it in vap.
             */
            vap->iv_quiet->tbttcount   = quiet_info.tbttcount;
            vap->iv_quiet->period      = quiet_info.period;
            vap->iv_quiet->duration    = quiet_info.duration;
            vap->iv_quiet->offset      = quiet_info.offset;
        }
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
    }
#endif
    return 0;
}

int ol_ath_prb_resp_tmpl_send(uint8_t vdev_id, struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn;
    struct wmi_probe_resp_params prb_rsp_tmpl = {0};
    struct ieee80211_frame *wh;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wmi_unified *pdev_wmi_handle;
    uint32_t tmpl_len;
    QDF_STATUS status;

    avn = OL_ATH_VAP_NET80211(vap);
    if (!avn->av_pr_rsp_wbuf) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
                  "%s: Probe Resp buffer is NULL. "
                  "Skip sending beacon template for vdev %d\n",
                  __func__, vdev_id);
        return -1;
    }

    pdev = wlan_vdev_get_pdev(vap->vdev_obj);
    if (!pdev)
        return -EINVAL;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    tmpl_len = wbuf_get_pktlen(avn->av_pr_rsp_wbuf);
    wh = (struct ieee80211_frame *)wbuf_header(avn->av_pr_rsp_wbuf);
    prb_rsp_tmpl.prb_rsp_template_len = tmpl_len;
    prb_rsp_tmpl.prb_rsp_template_frm = (uint8_t *)wh;

    status = wmi_unified_probe_rsp_tmpl_send_cmd(pdev_wmi_handle, vdev_id,
                                                 &prb_rsp_tmpl);
    if (qdf_status_to_os_return(status) < 0 ) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                  "%s: Failed to send Probe Response template\n", __func__);
    }
    return qdf_status_to_os_return(status);
}

#ifdef WLAN_IOT_SIM_SUPPORT
void ol_ath_iot_sim_bcn_update(struct ieee80211vap *vap,
                               struct beacon_tmpl_params *bcn_tmpl_param)
{
    struct ieee80211com *ic = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct wlan_lmac_if_rx_ops *rx_ops = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    if (!vap || !vap->iv_ic)
        return;

    ic = vap->iv_ic;
    avn = OL_ATH_VAP_NET80211(vap);

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
    if (rx_ops) {
        if (rx_ops->iot_sim_rx_ops.iot_sim_cmd_handler) {
            status = rx_ops->iot_sim_rx_ops.iot_sim_cmd_handler(vap->vdev_obj,
                                                                avn->av_wbuf,
                                                                bcn_tmpl_param,
                                                                true, NULL);
            if (QDF_IS_STATUS_SUCCESS(status))
                QDF_TRACE(QDF_MODULE_ID_IOT_SIM,  QDF_TRACE_LEVEL_DEBUG,
                          "%s:iot_sim:bcn processed at TX\n", __func__);
        }
    }
}
#else
void ol_ath_iot_sim_bcn_update(struct ieee80211vap *vap,
                               struct beacon_tmpl_params *bcn_tmpl_param)
{
    /* Dummy function */
}

#endif

int ol_ath_bcn_tmpl_send(uint8_t vdev_id, struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn;
    uint32_t tmpl_len, tmpl_len_aligned;
    QDF_STATUS status;
    uint64_t adjusted_tsf_le, tsf_adj;
    struct ieee80211_frame *wh;
    struct ieee80211_beacon_offsets *bo;
    struct ieee80211_ath_tim_ie *tim_ie;
    struct ieee80211_ie_muedca *muedca_ie;
    struct beacon_tmpl_params bcn_tmpl_param = {0};
    struct wmi_unified *pdev_wmi_handle;
    osif_dev *osifp = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct wlan_objmgr_vdev *t_vdev = NULL; /* temp vdev */
    bool is_mbssid_enabled =
            wlan_pdev_nif_feat_cap_get(pdev, WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_ema_ap_enabled =
            wlan_pdev_nif_feat_ext_cap_get(pdev, WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *transmit_vap = ic->ic_mbss.transmit_vap;

    avn = OL_ATH_VAP_NET80211(vap);
    osifp = (osif_dev *)vap->iv_ifp;
    if (!avn->av_wbuf) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
                  "%s: Beacon buffer is NULL. "
                  "Skip sending beacon template for vdev %d\n",
                  __func__, vdev_id);
        return -1;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    if (wmi_is_blocked(pdev_wmi_handle) &&
        (scn->soc->hw_mode_ctx.dynamic_hw_mode ==
         WMI_HOST_DYNAMIC_HW_MODE_FAST)) {
        /*
         * Hardware mode switch in progress
         */
        return -EINVAL;
    }

    QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
              "%s: Send beacon template for vdev %d\n", __func__, vdev_id);
    qdf_mem_zero(&bcn_tmpl_param, sizeof(bcn_tmpl_param));
    tmpl_len = wbuf_get_pktlen(avn->av_wbuf);
    tmpl_len_aligned = roundup(tmpl_len, sizeof(A_UINT32));
    ucfg_wlan_vdev_mgr_get_tsf_adjust(vap->vdev_obj, &tsf_adj);
    /** Make the TSF offset negative so beacons in the same staggered
     * batch have the same TSF. */
    adjusted_tsf_le = qdf_cpu_to_le64(0ULL - tsf_adj);
    /* Update the timstamp in the beacon buffer with adjusted TSF */
    wh = (struct ieee80211_frame *)wbuf_header(avn->av_wbuf);
    qdf_mem_copy(&wh[1], &adjusted_tsf_le, sizeof(adjusted_tsf_le));

    bcn_tmpl_param.vdev_id = vdev_id;

    bo = &avn->av_beacon_offsets;
    tim_ie = (struct ieee80211_ath_tim_ie *) bo->bo_tim;

    bcn_tmpl_param.tim_ie_offset = ((uint8_t*)tim_ie -
                                   (uint8_t*) wbuf_header(avn->av_wbuf));
    bcn_tmpl_param.tmpl_len = tmpl_len;
    bcn_tmpl_param.tmpl_len_aligned = tmpl_len_aligned;

    mbss_debug("is_mbssid_enabled: %d is_ema_ap_enabled: %d",
               is_mbssid_enabled, is_ema_ap_enabled);
    mbss_debug("vdev_id: %d", vdev_id);

    if (is_mbssid_enabled) {
        struct ieee80211vap *t_vap = NULL;      /* temp vap */

        bcn_tmpl_param.mbssid_ie_offset = (bo->bo_mbssid_ie -
                                           wbuf_header(avn->av_wbuf));

        if (is_ema_ap_enabled) {
            struct ieee80211_mbss_ie_cache_node *node = NULL;
            bool is_tx_vap      = false;
            bool ema_first_tmpl = false;
            bool ema_last_tmpl  = false;
            uint8_t node_pos    = 0;

            t_vdev = wlan_objmgr_get_vdev_by_id_from_pdev(
                        ic->ic_pdev_obj, vdev_id, WLAN_MLME_NB_ID);

            if (t_vdev) {
                if (!ic->ic_mbss.current_pp) {
                    mbss_err("Current PP is 0 - Invalid");
                    return -EINVAL;
                }

                /* ema_beacon_profile_periodicity */
                bcn_tmpl_param.ema_params = ic->ic_mbss.current_pp & 0xff;

                t_vap = wlan_vdev_mlme_get_ext_hdl(t_vdev);

                if (t_vap) {
                    is_tx_vap =
                        !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(t_vap);
                    mbss_debug("is_tx_vap: %d t_vap vdev_id: %d",
                                                is_tx_vap, t_vap->iv_unit);
                }

                /* ema_beacon_tmpl_idx */
                if (is_tx_vap) {
                    if (wlan_vdev_is_up(t_vap->vdev_obj) == QDF_STATUS_SUCCESS) {
                        if (ic->ic_mbss.current_pp != 1) {
                            /* vap is tx_vap in this fn */
                            bcn_tmpl_param.ema_params |=
                                (vap->iv_mbss.current_bcn_pos << 8);
                            ema_first_tmpl = !vap->iv_mbss.current_bcn_pos;
                            ema_last_tmpl = (vap->iv_mbss.current_bcn_pos ==
                                                (ic->ic_mbss.current_pp - 1));
                        } else {
                            ema_first_tmpl = ema_last_tmpl = 1;
                        }
                    } else {
                        /* tx-vap is not yet in up_complete state -
                         * must override ema_params
                         */
                        bcn_tmpl_param.ema_params      = 1;
                        ema_first_tmpl = ema_last_tmpl = 1;
                    }
                } else {
                    if (t_vap) {
                        /* Retrieve node_pos of non-tx vap */
                        node_pos =
                            ieee80211_mbssid_get_non_tx_vap_node_idx(t_vap,
                                    scn->soc->ema_ap_num_max_vaps);

                        if (node_pos >= scn->soc->ema_ap_num_max_vaps) {
                            mbss_err("Invalid node_idx: %d", node_pos);
                            if (t_vdev)
                                /* release vdev ref */
                                wlan_objmgr_vdev_release_ref(t_vdev, WLAN_MLME_NB_ID);
                            return -EINVAL;
                        }

                        node = &((struct ieee80211_mbss_ie_cache_node *)
                                            ic->ic_mbss.mbss_cache)[node_pos];

                        if ((ic->ic_mbss.current_pp > 1) &&
                                (!t_vap->iv_mbss.non_tx_profile_change)) {
                            ema_first_tmpl = !(node->pos);
                            ema_last_tmpl  =
                                    (node->pos == ic->ic_mbss.current_pp - 1);
                        } else {
                            ema_first_tmpl = ema_last_tmpl = 1;
                        }
                        bcn_tmpl_param.ema_params |= (node->pos << 8);
                    } /* end if (t_vap) */
                } /* end else of if (is_tx_vap) */

                /* ema_first_tmpl */
                bcn_tmpl_param.ema_params |= (ema_first_tmpl << 16);

                /* ema_last_tmpl */
                bcn_tmpl_param.ema_params |= (ema_last_tmpl << 24);

                mbss_debug("ema_params: 0x%x", bcn_tmpl_param.ema_params);
            } /* if (t_vdev) */
        } /* end if (ema) */

        /* Overwrite the vdev_id as the vdev_id sent
         * as an input to this funciton is actually
         * the non-tx vap for which the template
         * update was trigerred. We must overwrite
         * it with the vdev id of the Tx-vap
         */
        bcn_tmpl_param.vdev_id = vap->iv_unit;

        /* in case of ema_ap, we want the chan-switch flag
         * etc. from non-tx vap: so, redirect vap pointer
         */
        if (is_ema_ap_enabled && ic->ic_mbss.current_pp > 1) {
            if (t_vdev && t_vap) {
                vap = t_vap;
            } else {
                mbss_err("Unable to retrieve vap from vdev id");
                if (t_vdev)
                    /* release vdev ref */
                    wlan_objmgr_vdev_release_ref(t_vdev, WLAN_MLME_NB_ID);
                return -EINVAL;
            }
        }
    } /* end if (mbssid) */

    if (transmit_vap) {
        mbss_debug("channel_switch_state: %d"
                   " tx-vap iv_bcn_csa_tmp_sent: %d"
                   " iv_bcn_csa_tmp_sent: %d",
                        vap->channel_switch_state,
                        transmit_vap->iv_bcn_csa_tmp_sent,
                        vap->iv_bcn_csa_tmp_sent);
    }

    if (vap->channel_switch_state && vap->iv_bcn_csa_tmp_sent) {
        struct ieee80211_ath_channelswitch_ie *csa;

        csa = (struct ieee80211_ath_channelswitch_ie *) bo->bo_chanswitch;
        if (csa->ie != IEEE80211_ELEMID_CHANSWITCHANN) {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
                      "%s: CSA IE is not added at the offset\n", __func__);
        }
        bcn_tmpl_param.csa_switch_count_offset = (((uint8_t*)&csa->tbttcount) -
                                           (uint8_t*)wbuf_header(avn->av_wbuf));

        if (vap->iv_enable_ecsaie) {
            struct ieee80211_extendedchannelswitch_ie *ecsa;

            ecsa = (struct ieee80211_extendedchannelswitch_ie *)bo->bo_ecsa;
            if (ecsa->ie != IEEE80211_ELEMID_EXTCHANSWITCHANN) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
                          "%s: ECSA IE is not added at the offset\n", __func__);
            }
            bcn_tmpl_param.ext_csa_switch_count_offset = (((uint8_t*)&(ecsa->tbttcount)) -
                    (uint8_t*)wbuf_header(avn->av_wbuf));
        }

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
                "%s : %d: Add CSA_IE, vap = %d (%s)\n",
                __func__, __LINE__, vap->iv_unit, vap->iv_netdev_name);
        mbss_debug("Add CSA_IE, vap = %d (%s)",
                  vap->iv_unit, vap->iv_netdev_name);
    }

#if QCN_ESP_IE
    if (ic->ic_esp_periodicity) {
        struct ieee80211_est_ie *est_ie;

        est_ie = (struct ieee80211_est_ie *) bo->bo_esp_ie;
        if (est_ie) {
            if ((est_ie->element_id != IEEE80211_ELEMID_EXTN) ||
                (est_ie->element_id_extension != IEEE80211_ELEMID_EXT_ESP_ELEMID_EXTENSION)) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_DEBUG,
                          "%s: ESP IE is not added at the offset\n", __func__);
            }
            bcn_tmpl_param.esp_ie_offset = ((uint8_t*)est_ie -
                                        (uint8_t*) wbuf_header(avn->av_wbuf));
        }
    }
#endif /* QCN_ESP_IE */

    if (ieee80211vap_muedca_is_enabled(vap) && bo->bo_muedca) {
        muedca_ie = (struct ieee80211_ie_muedca *) bo->bo_muedca;
        bcn_tmpl_param.mu_edca_ie_offset = ((uint8_t*)muedca_ie -
                        (uint8_t*) wbuf_header(avn->av_wbuf));
    }

    if (vap->iv_beacon_prot)
        bcn_tmpl_param.enable_bigtk = 1 ;

    bcn_tmpl_param.frm = (uint8_t *)wh;
    ol_ath_iot_sim_bcn_update(vap, &bcn_tmpl_param);

    mbss_debug("bcn_tmpl_param.vdev_id: %d", bcn_tmpl_param.vdev_id);
    status = wmi_unified_beacon_tmpl_send_cmd(pdev_wmi_handle, &bcn_tmpl_param);
    if (qdf_status_to_os_return(status) < 0)
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                  "%s: Failed to send beacon template\n", __func__);

    if (t_vdev) {
        /* release vdev ref */
        wlan_objmgr_vdev_release_ref(t_vdev, WLAN_MLME_NB_ID);
    }

    return qdf_status_to_os_return(status);
}

int ol_ath_offload_bcn_tx_status_event_handler(ol_scn_t sc,
        uint8_t *data, uint32_t datalen) {
    ol_ath_soc_softc_t *soc           = (ol_ath_soc_softc_t *) sc;
    struct ieee80211vap *vap          = NULL;
    struct ieee80211com *ic           = NULL;
    struct ieee80211vap *tempvap;
    struct wlan_objmgr_vdev *vdev;
    struct wmi_unified *wmi_handle;
    struct target_psoc_info *tgt_hdl;
    uint32_t vdev_id, tx_status;
    int temp_vdev_id;

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                                                "%s>>", __func__);

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if ((wmi_handle == NULL)
            || wmi_extract_offload_bcn_tx_status_evt(wmi_handle,
                data, &vdev_id, &tx_status) != QDF_STATUS_SUCCESS) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
            "%s: Extracting offload bcn tx status event failed\n", __func__);

        QDF_TRACE(QDF_MODULE_ID_BSSCOLOR,
                QDF_TRACE_LEVEL_DEBUG, "%s<<", __func__);
        return -EINVAL;
    }

    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(
            soc->psoc_obj, vdev_id, WLAN_MLME_SB_ID);
    if (vdev == NULL) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                "Unable to find vdev for %d vdev_id", vdev_id);

        QDF_TRACE(QDF_MODULE_ID_BSSCOLOR,
                QDF_TRACE_LEVEL_DEBUG, "%s<<", __func__);
        return -EINVAL;
    }

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (vap == NULL) {
        qdf_err("vap is NULL %d vdev_id", vdev_id);
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
        return -EINVAL;
    }
    ic  = vap->iv_ic;

    /* if bcca is complete for all vaps then unregister itself
     */
    if (!(temp_vdev_id = ieee80211_is_bcca_ongoing_for_any_vap(ic))) {
        /* We can unregister offload beacon tx status event
         * handler as bss color change announcemtn has
         * completed for all vaps. But unregister only if
         * BCCA is not ongoing already for other radios in
         * the same psoc
         */

        tgt_hdl = (struct target_psoc_info *)
                    wlan_psoc_get_tgt_if_handle(soc->psoc_obj);
        if (!ieee80211_is_bcca_ongoing_on_any_radio(ic,
                    target_psoc_get_num_radios(tgt_hdl))) {
            ic->ic_register_beacon_tx_status_event_handler(ic, true);
        }
        /* update beacon templates for all
         * vaps so that bcca ie can be removed
         * from any pending vap
         */
        TAILQ_FOREACH(tempvap, &ic->ic_vaps, iv_next) {
            if ((tempvap->iv_opmode == IEEE80211_M_HOSTAP)
                    && wlan_vdev_is_up(tempvap->vdev_obj) == QDF_STATUS_SUCCESS) {
                wlan_vdev_beacon_update(tempvap);
            }
        }
    } else {
        QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
        "cannot unregister bcn_tx_status "
        "event as bcca ongoing. vdev-id: 0x%x",
        temp_vdev_id - 1);
        wlan_vdev_beacon_update(vap);
    }

    if (tx_status) {
        /* if we dont update beacon template on bcn
         * tx fail then we stop getting the tx status
         * event. Need to look into that in future
         */
        QDF_TRACE(QDF_MODULE_ID_BSSCOLOR,  QDF_TRACE_LEVEL_ERROR,
            "%s: beacon tx failed for vdev id: %d", __func__, vdev_id);
    }

    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                                            "%s<<", __func__);
    return 0;
}

/*
 * CSA switch count status event for Beacon Offload
 */
int ol_ath_pdev_csa_status_event_handler(struct wlan_objmgr_psoc *psoc,
        struct pdev_csa_switch_count_status csa_status)
{
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211vap *vap = NULL;
    int i = 0;
    struct ol_ath_vap_net80211 *avn;
    uint8_t vdev_id;
    int error = 0;
    bool vap_restart = true;
    struct wlan_objmgr_pdev *pdev;
    struct ieee80211vap *tmp_vap = NULL;
    bool is_ema_ap_enabled;
    bool is_mbssid_enabled;

    pdev = wlan_objmgr_get_pdev_by_id(psoc,
            PDEV_UNIT(csa_status.pdev_id), WLAN_MLME_SB_ID);
    if (pdev == NULL) {
        qdf_err("pdev object (id: %d) is NULL ",
                    PDEV_UNIT(csa_status.pdev_id));
        return -1;
    }

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (scn == NULL) {
        qdf_err("scn(id: %d) is NULL ",
            PDEV_UNIT(csa_status.pdev_id));
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return -1;
    }

    ic = &scn->sc_ic;
    if (ic == NULL) {
        qdf_err("ic is NULL");
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return -1;
    }

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(pdev,
                            WLAN_PDEV_F_MBSS_IE_ENABLE);
    is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(pdev,
                            WLAN_PDEV_FEXT_EMA_AP_ENABLE);

    if (csa_status.current_switch_count) {
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DOTH,
                "%s : %d : current_switch_count = %d\n",
                __func__, __LINE__, csa_status.current_switch_count);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return -1;
    }

    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DOTH,
            "%s : %d : pdev_id = %d current_switch_count = %d num_vdevs = %d\n",
            __func__, __LINE__, csa_status.pdev_id, csa_status.current_switch_count,
            csa_status.num_vdevs);

    for (i = 0; i < csa_status.num_vdevs; i++) {

        /* Get the VAP corresponding to the vdev id received */
        vap = ol_ath_vap_get(scn, csa_status.vdev_ids[i]);
        if (vap == NULL)
            continue;

        if (!vap->iv_bcn_csa_tmp_sent) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
                    "%s : %d : CSA event is already received for vap = %d (%s)\n",
                    __func__, __LINE__, vap->iv_unit, vap->iv_netdev_name);
            ol_ath_release_vap(vap);
            continue;
        }

        vap->iv_bcn_csa_tmp_sent = false;
        mbss_info("vdev_id: %d", vap->iv_unit);

        /* Set channel change count for VAP to number of CSA beacon counts
         * configured for the radio and update beacon
         */
        vap->iv_chanchange_count = ic->ic_chanchange_tbtt;
        if (ic->ic_csa_num_vdevs < WLAN_UMAC_PDEV_MAX_VDEVS) {
            ic->ic_csa_vdev_ids[ic->ic_csa_num_vdevs] = csa_status.vdev_ids[i];
            ic->ic_csa_num_vdevs++;
        } else {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                    "%s: csa_num_vdevs is equal to WLAN_UMAC_PDEV_MAX_VDEVS\n",
                    __func__);
            qdf_assert(0);
        }

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
                "%s : %d : CSA event is received for vap = %d (%s)\n",
                __func__, __LINE__, vap->iv_unit, vap->iv_netdev_name);

        /* Send multiple vdev restart command to FW if AP switches to new
         * channel. Removing the CSA-IE from the beacon is taken care in
         * ol_ath_vap_up() before sending vdev_up command to FW.
         */
        wlan_vdev_mlme_sm_deliver_evt(vap->vdev_obj,
                WLAN_VDEV_SM_EV_CSA_COMPLETE, 0, NULL);
        ol_ath_release_vap(vap);
    }

    /* Check if CSA event is received for all the vaps */
    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
        if (tmp_vap->iv_bcn_csa_tmp_sent) {
            if (!is_ema_ap_enabled) {
                IEEE80211_DPRINTF(tmp_vap, IEEE80211_MSG_DOTH,
                        "%s : %d : Wait for other vaps to complete the CSA, vap = %d (%s)\n",
                        __func__, __LINE__, tmp_vap->iv_unit, tmp_vap->iv_netdev_name);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
                return -1;
            } else {
                /* for ema ap case we need to send multiple
                 * templates if current_pp > 1 including csa
                 * ie but we will receive only one csa_status_event
                 */
                tmp_vap->iv_bcn_csa_tmp_sent = false;
                tmp_vap->iv_chanchange_count = ic->ic_chanchange_tbtt;
                mbss_debug(">vdev_id: %d", tmp_vap->iv_unit);
            }
        }
    }

    /* Return if all the vaps in down state */
    if (!ic->ic_csa_num_vdevs) {
        IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DOTH,
                "%s : %d : No vaps in active state, return\n",
                __func__, __LINE__);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
        return -1;
    }

    /* Received CSA completion from all the vaps. */
    IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DOTH,
            "%s : %d Received CSA completion for all the vaps\n",
            __func__, __LINE__);

    for (i = 0; i < ic->ic_csa_num_vdevs; i++) {
        tmp_vap = ol_ath_vap_get(scn, ic->ic_csa_vdev_ids[i]);
        if (!tmp_vap) {
            continue;
        }
        avn = OL_ATH_VAP_NET80211(tmp_vap);
        vdev_id = wlan_vdev_get_id(tmp_vap->vdev_obj);

        if (wlan_vdev_chan_config_valid(tmp_vap->vdev_obj) !=
                QDF_STATUS_SUCCESS) {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                    "%s: Vap is not in run state, vdev_id = %d\n",
                    __func__, ic->ic_csa_vdev_ids[i]);
            ol_ath_release_vap(tmp_vap);
            continue;
        }

        qdf_spin_lock_bh(&avn->avn_lock);

        if (avn->av_wbuf == NULL) {
            qdf_spin_unlock_bh(&avn->avn_lock);
            ol_ath_release_vap(tmp_vap);
            continue;
        }

        if (!is_ema_ap_enabled || ic->ic_mbss.current_pp == 1) {
            if(tmp_vap->iv_bss)
                error = ieee80211_beacon_update(tmp_vap->iv_bss,
                        &avn->av_beacon_offsets,
                        avn->av_wbuf, 0
#if UMAC_SUPPORT_WNM
                        , 0
#endif
                        );
        }

        if (error != -1) {
            if (!is_ema_ap_enabled || ic->ic_mbss.current_pp == 1) {
                if (tmp_vap && tmp_vap->iv_remove_csa_ie) {
                    /* When AP detects the RADAR or user changes the channel
                     * using doth_chanswitch command, AP sends the CSA to its
                     * BSS. When Host receives CSA event handler, it removes the
                     * CSA IE from beacon in ieee80211_beacon_update() and sends
                     * beacon template to Firmware.
                     */
                    ol_ath_bcn_tmpl_send(vdev_id, tmp_vap);
                    tmp_vap->iv_remove_csa_ie = false;
                }
            } else {
                qdf_spin_unlock_bh(&avn->avn_lock);
                /* set pp = 1 as it is enough to remove the CSA
                 * IE from one template and update the same to
                 * FW. While recieving restart_response for each
                 * vap the pp will increase again to previous
                 * value as part of restart sequence
                 */
                ic->ic_mbss.current_pp = 1;
                ic->ic_vdev_beacon_template_update(tmp_vap);
                qdf_spin_lock_bh(&avn->avn_lock);
                tmp_vap->iv_remove_csa_ie = false;
            }

            if (tmp_vap->iv_no_restart) {
                /* When usenol is set to 0 and if AP detects the RADAR, it
                 * sends CSA to its BSS, but it does not change the channel.
                 * In this case, host only needs to remove the CSA IE and
                 * send beacon template to FW. Since AP is not changing the
                 * channel, vap restart is not required.
                 */
                tmp_vap->channel_switch_state = 0;
                vap_restart = false;
                tmp_vap->iv_no_restart = false;
            }
        }
        qdf_spin_unlock_bh(&avn->avn_lock);

        ol_ath_release_vap(tmp_vap);
    }

    /* Send multiple vdev restart command to FW if AP switches to new
     * channel. Removing the CSA-IE from the beacon is taken care in
     * ol_ath_vap_up() before sending vdev_up command to FW.
     */
    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
        if ((tmp_vap->iv_opmode == IEEE80211_M_MONITOR)
            || wlan_is_non_beaconing_ap_vap(tmp_vap)) {
            ic->ic_csa_vdev_ids[ic->ic_csa_num_vdevs] = wlan_vdev_get_id(tmp_vap->vdev_obj);
            if (ic->ic_csa_num_vdevs < WLAN_UMAC_PDEV_MAX_VDEVS) {
                ic->ic_csa_num_vdevs++;
                wlan_vdev_mlme_sm_deliver_evt(tmp_vap->vdev_obj,
                        WLAN_VDEV_SM_EV_CSA_COMPLETE,
                        0, NULL);
            }
        }
    }

    qdf_mem_zero(ic->ic_csa_vdev_ids, WLAN_UMAC_PDEV_MAX_VDEVS);
    ic->ic_csa_num_vdevs = 0;

    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    return 0;
}

static INLINE QDF_STATUS
ol_ath_extract_tsf(ol_ath_soc_softc_t *soc,
                   u_int8_t *data, u_int8_t idx,
                   struct tbttoffset_params *tbtt_param,
                   bool is_ext_tbtt)
{
    QDF_STATUS retval;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return QDF_STATUS_E_NULL_VALUE;
    }

    if (is_ext_tbtt) {
        retval = wmi_extract_ext_tbttoffset_update_params(wmi_handle,
                                                          data, idx, tbtt_param);
    } else {
        retval = wmi_extract_tbttoffset_update_params(wmi_handle,
                                                      data, idx, tbtt_param);
    }

    return retval;
}

/*
 * ol_ath_sync_multisoc_tbtt - Sync the tbtt on AP on
 * one SoC with AP on other SoC as they use different
 * clock.
 * Term 'reported' is used for AP being reported in
 * RNR IE.
 * Term 'reporting' is used for AP sending the beacon
 * and carrying the info of reported AP.
 *
 * @reported_soc: SoC of reported AP
 * @reported_ic:Pdev of reported SoC
 */

static void ol_ath_sync_multisoc_tbtt(ol_ath_soc_softc_t *reported_soc, wlan_dev_t reported_ic)
{
    int soc_idx;
    ol_ath_soc_softc_t *soc;
    struct wlan_objmgr_psoc_objmgr *psoc_objmgr;
    struct wlan_objmgr_pdev *pdev = NULL;
    int id = 0;
    wlan_dev_t reporting_ic;
    struct ieee80211vap *reported_vap;
    struct rnr_bss_tbtt_info_param *rnr_buf_ptr;
    struct rnr_bss_tbtt_info_param *rnr_bss_tbtt;
    struct rnr_tbtt_multisoc_sync_param tbtt_sync_param;
    uint16_t chwidth, behav_lim;
    bool global_lookup = false;
    uint8_t op_class, prim_chan;
    struct wmi_unified *pdev_wmi_handle;
    uint64_t beacons_elapsed = 0;
    uint16_t reported_ap_count = 0;

    wlan_get_bw_and_behav_limit(reported_ic->ic_curchan,
                        &chwidth, &behav_lim);
    wlan_reg_freq_width_to_chan_op_class_auto(reported_ic->ic_pdev_obj,
                        reported_ic->ic_curchan->ic_freq, chwidth,
                        global_lookup, behav_lim,
                        &op_class, &prim_chan);


    for (soc_idx = 0; soc_idx < ol_num_global_soc; soc_idx++) {
        soc = ol_global_soc[soc_idx];
        if (soc && ol_target_lithium(soc->psoc_obj)) {
            soc->qtime_val = pld_get_q6_time(soc->sc_osdev->device);
            QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                      "curr-qtime-val-read[soc%d]: %llx", soc_idx, soc->qtime_val);
        }
    }

    TAILQ_FOREACH(reported_vap, &reported_ic->ic_vaps, iv_next) {
        if (reported_vap->iv_opmode == IEEE80211_M_HOSTAP && reported_vap->iv_is_up) {
            /* reported_soc->qtime_val - Current qtime of reported AP's SoC
             * reported_vap->iv_vap_tbtt_qtime - Next tbtt of reported AP wrt
             * reported AP's SoC
             * Find iv_tbtt_multisoc_delta, that is time to next tbtt from
             * current qtime value on this SoC.
             * Add this delta to reporting AP SoC's current qtime to find
             * time to next tbtt on reporting SoC's timeline.
             */
            if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(reported_vap)) {
                if (reported_soc->tbtt_soc_delta == reported_soc->qtime_val) {
                    reported_soc->tbtt_soc_delta = 0;
                }
                /* If the current qtime on the reported SoC is less than reported
                 * Ap's tbtt, then find the delta by straightforward subtraction
                 */
                else if (reported_soc->qtime_val < reported_vap->iv_vap_tbtt_qtime) {
                    reported_soc->tbtt_soc_delta = reported_vap->iv_vap_tbtt_qtime -
                                                       reported_soc->qtime_val;
                } else {
                   /* Steps to calculate delta between reported AP tbtt
                    * and reported SoC current qtime.
                    * 1. Find beacons elapsed between reported SoC curr qtime and
                    * reported AP tbtt, using ceil(a,b) = (a + (b-1))/b
                    * a: reported_soc->qtime_val - reported_vap->iv_vap_tbtt_qtime
                    * b: BI of reported AP
                    * 2. Use the value from 1, to find next tbtt from curr time using
                    * delta (next tbtt after curr time) =
                    * (AP tbtt qtime + (beacons_elapsed * BI)) - curr soc qtime
                    */
                    beacons_elapsed = 0;
                    /* Convert microsec to TU using 1024 factor */
                    beacons_elapsed = qdf_do_div(((reported_soc->qtime_val -
                                         reported_vap->iv_vap_tbtt_qtime) +
                                       ((reported_vap->iv_bss->ni_intval << 10) - 1)),
                                       (reported_vap->iv_bss->ni_intval << 10));

                    reported_soc->tbtt_soc_delta = (reported_vap->iv_vap_tbtt_qtime +
                                     (beacons_elapsed * (reported_vap->iv_bss->ni_intval << 10))) -
                                     reported_soc->qtime_val;
                }
                QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                          "%s:%d Reported vap tbtt: %llx, Tbtt delta from curr Qtime read: %llx"
                          ", Tbtt elapsed = %llx",
                          __func__, __LINE__,
                          reported_vap->iv_vap_tbtt_qtime,
                          reported_soc->tbtt_soc_delta, beacons_elapsed);
            }
            reported_ap_count++;
        } /* End of HOSTAP && vap->iv_is_up check */
    } /* End of TAILQ_FOREACH(vap list) */

    if (!reported_ap_count) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_ERROR,
                  "%s: reported AP count is zero!!", __func__);
        return;
    }
    rnr_buf_ptr = qdf_mem_malloc(reported_ap_count * sizeof(struct rnr_bss_tbtt_info_param));
    if (!rnr_buf_ptr) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_ERROR,
                  "%s: rnr_bss_tbtt_info_param alloc failed", __func__);
        return;
    }
    rnr_bss_tbtt = rnr_buf_ptr;
    /* Loop through all SoCs except reported AP's SoC and
     * calculate new tbtt wrt to this SoC using the delta
     * calculated above.
     * Loop through all Pdevs in these SoCs to find lower band pdev
     * and send wmi cmd with reported AP info.
     */
    for (soc_idx = 0; soc_idx < ol_num_global_soc; soc_idx++) {
        soc = ol_global_soc[soc_idx];
        if (!soc || soc == reported_soc || !ol_target_lithium(soc->psoc_obj))
            continue;
        rnr_buf_ptr = rnr_bss_tbtt;
        qdf_mem_zero(rnr_buf_ptr, reported_ap_count *
                     sizeof(struct rnr_bss_tbtt_info_param));
        TAILQ_FOREACH(reported_vap, &reported_ic->ic_vaps, iv_next) {
            if (reported_vap->iv_opmode == IEEE80211_M_HOSTAP && reported_vap->iv_is_up) {
                qdf_mem_copy(rnr_buf_ptr->bss_mac, reported_vap->iv_myaddr, QDF_MAC_ADDR_SIZE);
                rnr_buf_ptr->beacon_intval = reported_vap->iv_bss->ni_intval;
                rnr_buf_ptr->opclass = op_class;
                rnr_buf_ptr->chan_idx = prim_chan;
                /* Cast the next tbtt time of reported SoC on to
                 * reporting SoCs timeline.
                 */
                rnr_buf_ptr->next_qtime_tbtt_high = (reported_soc->tbtt_soc_delta +
                                                     soc->qtime_val) >> 32;
                rnr_buf_ptr->next_qtime_tbtt_low = (reported_soc->tbtt_soc_delta +
                                                    soc->qtime_val) & 0xffffffff;
                QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                          "%s:%d reported_qtime = %llx "
                          "next_qtime_tbtt_high wrt SoC[%d] = %x "
                          "next_qtime_tbtt_low wrt SoC[%d] = %x\n",
                          __func__, __LINE__,
                          reported_soc->tbtt_soc_delta + soc->qtime_val,
                          soc_idx,
                          rnr_buf_ptr->next_qtime_tbtt_high,
                          soc_idx, rnr_buf_ptr->next_qtime_tbtt_low);
                rnr_buf_ptr++;
            }
        }
        tbtt_sync_param.rnr_bss_tbtt = rnr_bss_tbtt;
        tbtt_sync_param.cmd_type = WMI_HOST_PDEV_SET_TBTT_OFFSET;
        tbtt_sync_param.rnr_vap_count = reported_ap_count;
        psoc_objmgr = &soc->psoc_obj->soc_objmgr;

        for (id=0;id<WLAN_UMAC_MAX_PDEVS;id++) {
            pdev = psoc_objmgr->wlan_pdev_list[id];
            if (pdev) {
                reporting_ic = wlan_pdev_get_mlme_ext_obj(pdev);
                if (reporting_ic && !IEEE80211_IS_CHAN_6GHZ(reporting_ic->ic_curchan) &&
                    ieee80211_get_num_ap_vaps_up(reporting_ic)) {
                    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
                    tbtt_sync_param.pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
                    wmi_unified_multisoc_tbtt_sync_cmd(pdev_wmi_handle, &tbtt_sync_param);
                }
            }
        } /* End of pdev loop */
    } /* End of SoC loop */
    qdf_mem_free(rnr_bss_tbtt);
}

/*
 * TSF Offset event handler
 */
static int ol_ath_tsf_offset_event_handler(ol_ath_soc_softc_t *soc,
                                           uint8_t *data, uint32_t num_vdevs,
                                           bool is_ext_tbtt)
{
    struct ieee80211com *ic = NULL;
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    struct ieee80211_frame *wh;
    uint32_t vdev_id = 0, adjusted_tsf = 0;
    uint64_t adjusted_tsf_le = 0, tx_delay = 0, tsf_adj = 0;
    uint8_t idx;
    struct tbttoffset_params tbtt_param = {0};
    struct wlan_objmgr_vdev *vdev;
    struct wlan_vdev_mgr_cfg mlme_cfg;
    bool disable_beacon = false;

    for (idx = 0; idx < num_vdevs; idx++) {
        mbss_debug("idx: %d num_vdevs: %d", idx, num_vdevs);
        if (ol_ath_extract_tsf(soc, data, idx, &tbtt_param, is_ext_tbtt)) {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                      "%s: Failed to extract tsf offset info\n", __func__);
            return -1;
        }

        vdev_id = tbtt_param.vdev_id;
        adjusted_tsf = tbtt_param.tbttoffset;
        /* Get the beaconing VAP corresponding to the id */
        vdev = wlan_objmgr_get_vdev_by_id_from_psoc(soc->psoc_obj,
                                                    vdev_id, WLAN_MLME_SB_ID);
        if (!vdev) {
            /*should continue if vdev is NULL*/
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                      "%s: Unable to find vdev for %d vdev_id\n",
                      __func__, vdev_id);
            continue;
        }

        if ((vap = wlan_vdev_get_mlme_ext_obj(vdev))) {
            /* Disable beacon if VAP is operating in NAWDS bridge mode */
            if (ieee80211_nawds_disable_beacon(vap)){
                disable_beacon = true;
            }
        }

        if ((!vap) || (disable_beacon)) {
            /*should continue if current vap is NULL*/
            wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
            disable_beacon = false;
            continue;
        }

        /* Update tbtt of the vap */
        vap->iv_vap_tbtt_qtime = (uint64_t)tbtt_param.vdev_tbtt_qtime_hi << 32 |
                                      tbtt_param.vdev_tbtt_qtime_lo;

        avn = OL_ATH_VAP_NET80211(vap);
        pdev = wlan_vdev_get_pdev(vap->vdev_obj);
        psoc = wlan_pdev_get_psoc(pdev);
        ic = vap->iv_ic;

        if (!ic) {
            qdf_debug("Ic is NULL");

            wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
            return -1;
        }

        if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
            QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                      "Lower band AP: %llx", vap->iv_vap_tbtt_qtime);

        /* Update adjusted tsf with tbttoffset only if target
         * sends valid values.
         */
        if (adjusted_tsf != WMI_HOST_TBTT_OFFSET_INVALID) {
            if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
                /* Don't handle TSF event for a non-transmitting MBSS VAP */
                wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                continue;
            }

            qdf_spin_lock_bh(&avn->avn_lock);

            if (!avn->av_wbuf) {
                qdf_spin_unlock_bh(&avn->avn_lock);
                qdf_debug("Beacon buf NULL. Ignoring tsf offset evt");
                wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
                return -1;
            }

            /* Save the adjusted TSF */
            mlme_cfg.tsf = adjusted_tsf;
            vdev_mlme_set_param(vap->vdev_mlme, WLAN_MLME_CFG_TSF_ADJUST,
                                mlme_cfg);

            if (lmac_is_target_ar900b(psoc) || ol_target_lithium(psoc)) {
                if (IEEE80211_IS_CHAN_PUREG(ic->ic_curchan) ||
                    IEEE80211_IS_CHAN_5GHZ_6GHZ(ic->ic_curchan) ||
                    IEEE80211_IS_CHAN_OFDM(ic->ic_curchan)) {
                    /* 6Mbps Beacon: 20(lsig) + 2(service) + 32(6mbps, 24 bytes)
                       = 54us + 2us(MAC/BB DELAY) */
                    tx_delay = 56;
                }
                else if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                    /* 1Mbps Beacon: 144 us (LPREAMBLE) + 48 (PLCP Header) +
                       192 (1Mbps, 24 bytes) = 384 us + 2us(MAC/BB DELAY) */
                    tx_delay = 386;
                }
                /* Save the adjusted TSF */
                mlme_cfg.tsf = adjusted_tsf - tx_delay;
                vdev_mlme_set_param(vap->vdev_mlme, WLAN_MLME_CFG_TSF_ADJUST,
                                    mlme_cfg);
            }

            ucfg_wlan_vdev_mgr_get_tsf_adjust(vdev, &tsf_adj);
            /*
             * Make the TSF offset negative so beacons in the same
             * staggered batch have the same TSF.
             */
            adjusted_tsf_le = qdf_cpu_to_le64(0ULL - tsf_adj);

            /* Update the timstamp in the beacon buffer with adjusted TSF */
            wh = (struct ieee80211_frame *)wbuf_header(avn->av_wbuf);
            OS_MEMCPY(&wh[1], &adjusted_tsf_le, sizeof(adjusted_tsf_le));

            if (vap->iv_bcn_offload_enable && !(vap->iv_bcn_csa_tmp_sent)) {
                bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(
                    ic->ic_pdev_obj, WLAN_PDEV_FEXT_EMA_AP_ENABLE);

                /* In case of ema, we only need to send the template
                 * update for multiple profile once - when the PP changes
                 */
                if (!is_ema_ap_enabled || ic->ic_mbss.current_pp == 1) {
                    ol_ath_bcn_tmpl_send(vdev_id, vap);
                    qdf_spin_unlock_bh(&avn->avn_lock);
                } else {
                    if (ic->ic_mbss.pp_change) {
                        mbss_info("do template update after tsf-sync");
                        qdf_spin_unlock_bh(&avn->avn_lock);
                        ol_ath_vdev_beacon_template_update(vap);
                        ic->ic_mbss.pp_change = false;
                    } else {
                        mbss_debug("template send avoided in case of"
                                   " ema as there is no pp change in"
                                   " last non-tx vdev up");
                        qdf_spin_unlock_bh(&avn->avn_lock);
                    }
                }
            } else {
                qdf_spin_unlock_bh(&avn->avn_lock);
            }
        } /* end of if (adjusted_tsf != WMI_HOST_TBTT_OFFSET_INVALID) */
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
    } /* end of for (idx = 0; idx < num_vdevs; idx++) */

    if (ic && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
        ol_ath_sync_multisoc_tbtt(soc, ic);

    return 0;
}

/* WMI Beacon related Event APIs */
static int
ol_beacon_swba_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;

    return ol_ath_beacon_swba_handler(soc, data);
}

static int
ol_tbttoffset_update_event_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    uint32_t num_vdevs = 0;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if(wmi_extract_tbttoffset_num_vdevs(wmi_handle, data, &num_vdevs)) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                  "%s: Failed to extract num vdevs\n", __func__);
        return -1;
    }
    return ol_ath_tsf_offset_event_handler(soc, data, num_vdevs, false);
}

static int
ol_ext_tbttoffset_update_event_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    uint32_t num_vdevs;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if(wmi_extract_ext_tbttoffset_num_vdevs(wmi_handle, data, &num_vdevs)) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                  "%s: Failed to extract num vdevs\n", __func__);
        return -1;
    }
    return ol_ath_tsf_offset_event_handler(soc, data, num_vdevs, true);
}

static int ol_extract_muedca_params_handler(ol_scn_t sc, uint8_t *data, uint32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wmi_unified *wmi_handle;
    struct muedca_params muedca_param_list;
    struct wlan_objmgr_pdev *pdev_obj;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211vap *tempvap;
    struct ieee80211_wme_state *wme = NULL;
    struct muedcaParams muedca_param;
    int ac_cnt;
    bool update_count = false;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if(wmi_extract_muedca_params_handler(wmi_handle, data,
                                         &muedca_param_list)) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                  "%s: Failed to extract muedca params\n", __func__);
        return -1;
    }

    /* Call new muedca update function that will check params and update count and beacon */
    pdev_obj = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, muedca_param_list.pdev_id, WLAN_MGMT_NB_ID);
    if (!pdev_obj) {
        qdf_err("pdev is NULL");
        return -1;
    }
    scn = lmac_get_pdev_feature_ptr(pdev_obj);
    if (!scn) {
        qdf_err("scn is NULL");
        wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MGMT_NB_ID);
        return -1;
    }
   ic = &scn->sc_ic;
   if (!ic) {
        qdf_err("ic is NULL");
        wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MGMT_NB_ID);
        return -1;
    }

    TAILQ_FOREACH(tempvap, &ic->ic_vaps, iv_next) {
        if (tempvap->iv_opmode == IEEE80211_M_HOSTAP) {

            for (ac_cnt = 0; ac_cnt < MUEDCA_NUM_AC; ac_cnt++) {
                    muedca_param.muedca_aifsn = muedca_param_list.muedca_aifsn[ac_cnt];
                    muedca_param.muedca_ecwmin = muedca_param_list.muedca_ecwmin[ac_cnt];
                    muedca_param.muedca_ecwmax = muedca_param_list.muedca_ecwmax[ac_cnt];
                    muedca_param.muedca_timer = muedca_param_list.muedca_timer[ac_cnt];
                    muedca_param.muedca_acm = tempvap->iv_muedcastate.muedca_paramList[ac_cnt].muedca_acm;
                    if(qdf_mem_cmp(&muedca_param,
                                   &tempvap->iv_muedcastate.muedca_paramList[ac_cnt],
                                   sizeof(muedca_param))){
                        update_count = true;
                        qdf_mem_copy(&tempvap->iv_muedcastate.muedca_paramList[ac_cnt],
                                     &muedca_param,
                                     sizeof(muedca_param));
                    }
            }
            if (update_count) {
                tempvap->iv_muedcastate.muedca_param_update_count =
                        ((tempvap->iv_muedcastate.muedca_param_update_count + 1) &
                         MUEDCA_MAX_UPDATE_CNT);
                wme = &tempvap->iv_wmestate;
                /* cap_info has bits set in WME_QOSINFO_COUNT and WME_QOSINFO_UAPSD.
                 * Rest of the bits are reserved currently.
                 */
                wme->wme_bssChanParams.cap_info = (tempvap->iv_muedcastate.muedca_param_update_count &
                                                   WME_QOSINFO_COUNT) |
                                                  (wme->wme_bssChanParams.cap_info & WME_QOSINFO_UAPSD);
                ieee80211vap_set_flag(tempvap, IEEE80211_F_WMEUPDATE);
                wlan_vdev_beacon_update(tempvap);
                update_count = false;
            }
        }
    }
    wlan_objmgr_pdev_release_ref(pdev_obj, WLAN_MGMT_NB_ID);
    return 0;
}

int ol_ath_beacon_offload_control(struct ieee80211vap *vap, uint32_t bcn_ctrl_op)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    struct bcn_offload_control bcn_ctrl = {0};
    struct wmi_unified *wmi_handle, *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    if (!pdev_wmi_handle)
        return -EINVAL;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if(!wmi_handle) {
        qdf_err("%s: wmi_handle is NULL", __func__);
        return -1;
    }

    if (ol_ath_is_beacon_offload_enabled(scn->soc)) {
        if (!wmi_service_enabled(wmi_handle, wmi_service_bcn_offload_start_stop_support)) {
            qdf_err("Beacon offload start/stop not supported");
            return -1;
        }
    }

    bcn_ctrl.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    switch (bcn_ctrl_op) {
        case IEEE80211_BCN_OFFLD_TX_DISABLE:
            bcn_ctrl.bcn_ctrl_op = BCN_OFFLD_CTRL_TX_DISABLE;
            break;
        case IEEE80211_BCN_OFFLD_TX_ENABLE:
            bcn_ctrl.bcn_ctrl_op = BCN_OFFLD_CTRL_TX_ENABLE;
            break;
        case IEEE80211_BCN_OFFLD_SWBA_DISABLE:
            bcn_ctrl.bcn_ctrl_op = BCN_OFFLD_CTRL_SWBA_DISABLE;
            break;
        case IEEE80211_BCN_OFFLD_SWBA_ENABLE:
            bcn_ctrl.bcn_ctrl_op = BCN_OFFLD_CTRL_SWBA_ENABLE;
            break;
        default:
            qdf_info("Beacon offload unknown ctrl operation %d", bcn_ctrl_op);
            return -1;
    }

    if (wmi_send_bcn_offload_control_cmd(pdev_wmi_handle, &bcn_ctrl) !=
                                                          QDF_STATUS_SUCCESS) {
        qdf_info("Failed to send beacon control command");
        return -1;
    }

    return 0;
}
/*
 * Beacon related attach functions for offload solutions
 */
void
ol_ath_beacon_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if (ol_ath_is_beacon_offload_enabled(scn->soc)) {
        ic->ic_vdev_beacon_template_update = ol_ath_vdev_beacon_template_update;
        ic->ic_beacon_offload_control = ol_ath_beacon_offload_control;
#if UMAC_SUPPORT_QUIET
        ic->ic_set_bcn_offload_quiet_mode = ol_ath_set_quiet_offload_config_params;
#endif
    } else {
        ic->ic_vdev_beacon_template_update = NULL;
        ic->ic_beacon_offload_control = ol_ath_beacon_offload_control;
    }
    ic->ic_beacon_update = ol_ath_beacon_update;
    ic->ic_beacon_free = ol_ath_beacon_free;
    ic->ic_is_hwbeaconproc_active = ol_ath_net80211_is_hwbeaconproc_active;
    ic->ic_hw_beacon_rssi_threshold_enable = ol_ath_net80211_hw_beacon_rssi_threshold_enable;
    ic->ic_hw_beacon_rssi_threshold_disable = ol_ath_net80211_hw_beacon_rssi_threshold_disable;
    ic->ic_prb_rsp_free = ol_ath_prb_rsp_free;
    ic->ic_vdev_prb_rsp_tmpl_update = ol_ath_vdev_prb_rsp_template_update;

}

void
ol_ath_beacon_soc_attach(ol_ath_soc_softc_t *soc)
{
	struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    /* Register WMI event handlers */
    wmi_unified_register_event_handler((void *)wmi_handle, wmi_host_swba_event_id,
                                            ol_beacon_swba_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler((void *)wmi_handle, wmi_tbttoffset_update_event_id,
                                           ol_tbttoffset_update_event_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler((void *)wmi_handle, wmi_ext_tbttoffset_update_event_id,
                                           ol_ext_tbttoffset_update_event_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler((void *)wmi_handle, wmi_muedca_params_config_eventid,
                                       ol_extract_muedca_params_handler, WMI_RX_UMAC_CTX);
}
#endif
