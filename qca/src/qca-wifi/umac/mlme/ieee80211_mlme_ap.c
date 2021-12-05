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
#if UNIFIED_SMARTANTENNA
#include <wlan_sa_api_utils_api.h>
#endif
#include <ieee80211_mlme_dfs_dispatcher.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <ieee80211_regdmn.h>
#if WLAN_SUPPORT_SPLITMAC
#include <wlan_splitmac.h>
#endif

#include <wlan_cmn.h>
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_objmgr_vdev_obj.h>
#include <wlan_objmgr_peer_obj.h>

#include <target_type.h>
#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"
#include "wlan_mlme_dp_dispatcher.h"
#include "wlan_utility.h"
#if ATH_POWERSAVE_WAR
#define IEEE80211_PSPOLL_KICKOUT_THR 30000
#endif
#define RX_DECAP_TYPE_RAW            0
#include <wlan_son_pub.h>
#include <target_type.h>
#include <wlan_utility.h>
#include <wlan_mlme_if.h>
#include <ieee80211_node_priv.h>

/* ieee80211_generic_linear_plot - Retreive output given slope and input coordinate
 *
 * uint8_t lower_bound_y: Min output value
 * uint8_t upper_bound_y: Max output value
 * uint16_t input1: Value to get input ratio
 * uint16_t input2: Value to get input ratio
 *
 */
static inline uint8_t ieee80211_linear_plot(uint8_t lower_bound_y,
                                            uint8_t upper_bound_y,
                                            uint16_t input1,
                                            uint16_t input2)
{

    return (lower_bound_y + ((input1 * (upper_bound_y - lower_bound_y)) / input2));

}

void ieee80211_estimate_dynamic_muedca_params(ieee80211_vap_t vap)
{
    struct ieee80211_muedca_state *muedca = &vap->iv_muedcastate;
    int iter;
    struct ieee80211com *ic = vap->iv_ic;
    enum ieee80211_phymode mode;
    const wmeParamType *pBssPhyParam;

    if (vap->iv_bsschan != IEEE80211_CHAN_ANYC)
        mode = ieee80211_chan2mode(vap->iv_bsschan);
    else
        mode = IEEE80211_MODE_AUTO;

/*
 * MU-EDCA param value (#ax_STAs, #legacy_STAs) = lower_bound + (1-#legacy_STAs/#total_STAs) * (upper_bound – lower_bound)
 */
    if (!vap->iv_sta_assoc) {
        vap->iv_muedcastate.mu_edca_dynamic_state |= MUEDCA_DYNAMIC_ALGO_UPDATE_STATE_MASK;
        qdf_debug("No STA connected");
        return;
    }
    /* Do not update param if only 11ax sta connected/disconnected,
     * resulting in all STAs being 11ax only.
     */
    if (!(vap->iv_muedcastate.mu_edca_dynamic_state & MUEDCA_DYNAMIC_ALGO_UPDATE_STATE_MASK)) {
        qdf_debug("Dynamic muedca state: %d - Change in 11ax client count only",
                  vap->iv_muedcastate.mu_edca_dynamic_state);
        vap->iv_muedcastate.mu_edca_dynamic_state |= MUEDCA_DYNAMIC_ALGO_UPDATE_STATE_MASK;
        return;
    }
    for(iter = 0; iter < MUEDCA_NUM_AC; iter++) {

        switch (iter) {
            case WME_AC_BK:
                pBssPhyParam = &ic->phyParamForAC[WME_AC_BK][mode];
                break;
            case WME_AC_VI:
                pBssPhyParam = &ic->bssPhyParamForAC[WME_AC_VI][mode];
                break;
            case WME_AC_VO:
                pBssPhyParam = &ic->bssPhyParamForAC[WME_AC_VO][mode];
                break;
            case WME_AC_BE:
            default:
                pBssPhyParam = &ic->bssPhyParamForAC[WME_AC_BE][mode];
                break;
    }

    vap->iv_muedcastate.muedca_paramList[iter].muedca_ecwmin =
    ieee80211_linear_plot(pBssPhyParam->logcwmin,
                          ic->ic_muedca_defaultParams[iter].muedca_ecwmin,
                          vap->iv_ax_sta_assoc,
                          vap->iv_sta_assoc);
    vap->iv_muedcastate.muedca_paramList[iter].muedca_aifsn =
    ieee80211_linear_plot(pBssPhyParam->aifsn,
                          ic->ic_muedca_defaultParams[iter].muedca_aifsn,
                          vap->iv_ax_sta_assoc,
                          vap->iv_sta_assoc);
    vap->iv_muedcastate.muedca_paramList[iter].muedca_timer =
    ieee80211_linear_plot(MUEDCA_TIMER_MIN,
                          ic->ic_muedca_defaultParams[iter].muedca_timer,
                          vap->iv_ax_sta_assoc,
                          vap->iv_sta_assoc);
    }

       muedca->muedca_param_update_count =
       ((muedca->muedca_param_update_count + 1) & MUEDCA_MAX_UPDATE_CNT);
       wlan_vdev_beacon_update(vap);

}

void ieee80211_mlme_event_callback(ieee80211_vap_t vap,
                                   ieee80211_mlme_event *event,
                                   void *arg)
{
    switch (event->type) {
        case IEEE80211_MLME_EVENT_STA_JOIN:
        case IEEE80211_MLME_EVENT_STA_LEAVE:
            if (vap->iv_he_muedca == IEEE80211_MUEDCA_STATE_ENABLE &&
                vap->iv_ic->ic_muedca_mode_state == HEMUEDCA_HOST_DYNAMIC_MODE &&
                vap->iv_muedcastate.mu_edca_dynamic_state & MUEDCA_DYNAMIC_ALGO_ENABLE_STATE_MASK) {
                ieee80211_estimate_dynamic_muedca_params(vap);
            }
            break;
        default:
            break;
    }
}

int ieee80211_mlme_recv_assoc_request(struct ieee80211_node *ni,
                                       u_int8_t reassoc,u_int8_t *vendor_ie, wbuf_t wbuf)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211com           *ic = ni->ni_ic;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
#if WLAN_SUPPORT_SPLITMAC
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
    int is_splitmac_enable = splitmac_is_enabled(vdev);
#else
    int is_splitmac_enable = 0;
#endif
    u_int8_t                      newassoc = (ni->ni_associd == 0);
    wbuf_t                        resp_wbuf;
    u_int16_t                     assocstatus;
    ieee80211_mlme_event          event;
    u_int8_t                      flag=0;
    u_int8_t                      node_leave = 0, isvht, ishe;
    int32_t authmode;
    int32_t peer_authmode;
    int                           status = 0;
    int                           join_ret = 0;
#if QCA_SUPPORT_SON
    struct son_ald_assoc_event_info info;
#endif

    /* AP  must be up and running */
     if (!mlme_priv->im_connection_up ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
        return 0;
    }
    IEEE80211_NOTE(vap, IEEE80211_MSG_MLME, ni, "%s", __func__);
    wlan_node_set_peer_state(ni, WLAN_ASSOC_STATE);

    if (is_splitmac_enable && reassoc) {
        /* skip node join */
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "%s", "Skip node join, reassoc=%d \n",reassoc);
    } else {
        join_ret = ieee80211_node_join(ni);
    }
    if (join_ret) {
        /* Association Failure */
        assocstatus = IEEE80211_REASON_ASSOC_TOOMANY;
        if (is_splitmac_enable) {
            /* splitmac has aid assigned from controller
             * clear aid if join failed */
            IEEE80211_AID_CLR(vap, ni->ni_associd);
            ni->ni_associd = 0;
        }
    } else {
        assocstatus = IEEE80211_STATUS_SUCCESS;
        if (!reassoc) {
            ieee80211_admctl_node_leave(vap, ni);
        }

        /* Indicate that a new node has associated */
        event.type = IEEE80211_MLME_EVENT_STA_JOIN;
        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }

    /* clear the last auth seq number */
    ni->ni_last_rxauth_seq = 0xfff;
    ni->ni_last_auth_rx_time = 0;

    /* Clear any previously cached status */
    ni->ni_assocstatus = assocstatus;

    /* Setup association response frame before indication */
    resp_wbuf = ieee80211_setup_assocresp(ni, NULL, reassoc, assocstatus, NULL);
    if (!resp_wbuf)
        assocstatus = IEEE80211_REASON_UNSPECIFIED;

    /* Move this down after sending the Assoc resp, so that the EAPOL
     * frame that is sent as consequence of this event, doesn't go OTA
     * before the Assoc Resp frame on some partial offload platforms. */

    /* Windows Platform have to call indication first to update ni->assocstatus
    * value, Keep original alg for Windows Platform.
    */
    /* Memory allocation failure, no point continuing */
    if (!resp_wbuf)
        return 0;

    /* Association rejection from above */
    if (ni->ni_assocstatus != IEEE80211_STATUS_SUCCESS) {

        /* Update already formed association response and send it out */
        ieee80211_setup_assocresp(ni, resp_wbuf, reassoc, ni->ni_assocstatus, NULL);
        ieee80211_send_mgmt(vap,ni, resp_wbuf,false);

        /* Flag to remove the node from node table */
        node_leave = 1;
        status = -EBUSY;
    } else {
        if(son_has_whc_apinfo_flag(ni->peer_obj, IEEE80211_NODE_WHC_APINFO_SON)) {
            son_update_bss_ie(vap->vdev_obj);
            son_pdev_appie_update(ic);
            wlan_pdev_beacon_update(ic);
        }
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_authorize_attempt_inc(vap->vdev_obj, 1);
#endif

        /* Wait for application to trigger mlme response for assoc */
        if (ieee80211_vap_trigger_mlme_resp_is_set(vap)) {
            wbuf_complete(resp_wbuf);
            resp_wbuf = NULL;
        }
        else {
            flag = TRUE;
        }

        ni->ni_assocuptime = OS_GET_TICKS();
#if UMAC_SUPPORT_WNM
        ni->ni_wnm->last_rcvpkt_tstamp =  ni->ni_assocuptime;
#endif

        /* If null/dummy key plumbing for WEP is configured, set the appropriate
         * flag in key structure and call handler to plumb keys for all
         * 4 key indexes
         */
        if ((vap->iv_cfg_raw_dwep_ind) && (vap->iv_rx_decap_type ==
            RX_DECAP_TYPE_RAW)) {
        }

        isvht = (ni->ni_flags & IEEE80211_NODE_VHT);
        ishe = (ni->ni_ext_flags & IEEE80211_NODE_HE);
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC | IEEE80211_MSG_DEBUG, ni,
            "station %sassociated at aid %d: %s preamble, %s slot time"
            "%s%s%s%s cap 0x%x\n"
            , newassoc ? "" : "re"
            , IEEE80211_NODE_AID(ni)
            , ic->ic_flags & IEEE80211_F_SHPREAMBLE ? "short" : "long"
            , ic->ic_flags & IEEE80211_F_SHSLOT ? "short" : "long"
            , ic->ic_flags & IEEE80211_F_USEPROT ? ", protection" : ""
            , ni->ni_flags & IEEE80211_NODE_QOS ? ", QoS" : ""
            , ishe ? "HE" : (isvht ? "VHT" : (ni->ni_flags & IEEE80211_NODE_HT ? ", HT" : ""))
            , (ni->ni_flags & IEEE80211_NODE_HT)  ?
                       (ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40 ? "40" : "20") : ""
            , ni->ni_capinfo
        );
        wlan_node_set_peer_state(ni, WLAN_WAITKEY_STATE);

        /* give driver a chance to setup state like ni_txrate */
        if ((!(ieee80211_is_pmf_enabled(vap, ni)) ||  !(ni->ni_flags & IEEE80211_NODE_AUTH)) && is_splitmac_enable) {
             if ((ic->ic_newassoc != NULL) && !(ni->is_ft_reassoc)) {
                 ic->ic_newassoc(ni, newassoc);
                 /* In case of OMN in Asoc req, phymode is not updated
                  * and therefore we explicitly send chwidth in OMN
                  * to target. This is confirmed by checking if chan width
                  * obtained from phymode and peer ch width differ.
                  */
                  if (ni->ni_chwidth != get_chwidth_phymode(ni->ni_phymode))
                      ic->ic_chwidth_change(ni);
             }
        }

        if(ieee80211_is_pmf_enabled(vap, ni) &&
            vap->iv_opmode == IEEE80211_M_HOSTAP &&
            (vap->iv_skip_pmf_reassoc_to_hostap > 0) &&
            (ni->ni_flags & IEEE80211_NODE_AUTH))
        {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "[%s] drop assoc resp for pmf client from hostapd\n",
                        __func__);
            wlan_mlme_assoc_resp(vap,ni->ni_macaddr, IEEE80211_STATUS_REJECT_TEMP, 0, NULL);
        }

        if(flag) {
            ieee80211_send_mgmt(vap,ni,resp_wbuf,false);
        }
        if((ni->ni_capinfo & IEEE80211_CAPINFO_RADIOMEAS)
                && ieee80211_vap_rrm_is_set(vap))
        {
            ieee80211_set_node_rrm(ni,TRUE);
        }
        else {
            ieee80211_set_node_rrm(ni,FALSE);
        }

#if QCA_SUPPORT_SON
        if (wbuf) {
            son_update_assoc_frame(ni->peer_obj, wbuf);
        }
#endif

        /* To take care of shared wep condition,
           after challenge text success we are setting node to authorized
           so checking it here should be fine.*/
        if (ieee80211_node_is_authorized(ni)) {
#if QCA_SUPPORT_SON
	        wlan_acl_apply_node_snr_thresholds(vap, ni->ni_macaddr);
            qdf_mem_zero(&info, sizeof(info));
            qdf_mem_copy(info.macaddr, ni->ni_macaddr, QDF_MAC_ADDR_SIZE);
            info.flag = ALD_ACTION_ASSOC;
            info.reason = ni->ni_assocstatus;
            son_update_mlme_event(vap->vdev_obj, NULL, SON_EVENT_ALD_ASSOC, &info);
#endif

#if ATH_PARAMETER_API
            ieee80211_papi_send_assoc_event(vap, ni, PAPI_STA_ASSOCIATION);
#endif
            }
        /*
         * Authorize the node when configured in open mode.
         * Node authorizations for other modes are initiated by hostapd.
         * Security modes configured at node & vap should match.
         */
        authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
        if ( authmode == -1 ) {
            qdf_err("crypto_err while getting authmode params\n");
            return -1;
        }

        peer_authmode = wlan_crypto_get_peer_param(ni->peer_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
        if ( peer_authmode == -1 ) {
            qdf_err("crypto_err while getting peer_authmode params\n");
            return -1;
        }

        if((ni->ni_authmode != IEEE80211_AUTH_8021X) &&
           (!(peer_authmode & ((uint32_t)((1 << WLAN_CRYPTO_AUTH_WPA) | (1 << WLAN_CRYPTO_AUTH_RSNA)
                                     | (1 << WLAN_CRYPTO_AUTH_8021X) | (1 << WLAN_CRYPTO_AUTH_WAPI)))) &&
           (((!(authmode & (1 << WLAN_CRYPTO_AUTH_SHARED))) || (ni->ni_authalg != IEEE80211_AUTH_SHARED)))))
        {
#if QCA_SUPPORT_SON
	        wlan_acl_apply_node_snr_thresholds(vap, ni->ni_macaddr);
            qdf_mem_zero(&info, sizeof(info));
            qdf_mem_copy(info.macaddr, ni->ni_macaddr, QDF_MAC_ADDR_SIZE);
            info.flag = ALD_ACTION_ASSOC;
            info.reason = ni->ni_assocstatus;
            son_update_mlme_event(vap->vdev_obj, NULL, SON_EVENT_ALD_ASSOC, &info);
#endif
        }

        /* Update MIMO powersave flags and node rates */
        if ( !(ni->ni_flags & IEEE80211_NODE_AUTH) && is_splitmac_enable) {
            ieee80211_update_noderates(ni);
        }

        /* need to add a station join notification */

        if (!(ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT)) {
            /* Spectrum managemnt is not supported by this node */
            if (!(ni->ni_ext_flags & IEEE80211_NODE_NON_DOTH_STA)) {
                /* Non spectrum managemnt node associated for forst time */
                ic->ic_non_doth_sta_cnt++;
                ieee80211node_set_extflag(ni, IEEE80211_NODE_NON_DOTH_STA);
            }
        } else {
            /* Spectrum managemnt supported by this node */
            if ((ni->ni_ext_flags & IEEE80211_NODE_NON_DOTH_STA)) {
                /* Already associated sta (without spectrum management
                 * capability) reassociated with spectrum management
                 * capability.
                 * Mark this STA now supports sepectrum managemnet.
                 */
                ieee80211node_clear_extflag(ni, IEEE80211_NODE_NON_DOTH_STA);
                ic->ic_non_doth_sta_cnt--;
            }
        }
    }

    if(!node_leave) {
        /* Now send the notification and remove the node if needed */
        if (reassoc) {
            IEEE80211_DELIVER_EVENT_MLME_REASSOC_INDICATION(vap, ni->ni_macaddr,
                assocstatus, wbuf, resp_wbuf);
        } else {
            IEEE80211_DELIVER_EVENT_MLME_ASSOC_INDICATION(vap, ni->ni_macaddr,
                assocstatus, wbuf, resp_wbuf);
#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)
            if (son_get_ssid_steering_vdev_is_pvt(vap->vdev_obj)){
                IEEE80211_DELIVER_SSID_EVENT(vap, ni->ni_macaddr);
            }
#endif
        }
    }

#if DYNAMIC_BEACON_SUPPORT
    /*
     * STA assoc successfully,
     * resume beacon and trigger suspend beacon timer for iv_dbeacon_timeout.
     */
    if (vap->iv_dbeacon && vap->iv_dbeacon_runtime && assocstatus == IEEE80211_STATUS_SUCCESS) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "STA assoc successfully. Resume beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        if (ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, false);
        }
        OS_SET_TIMER(&vap->iv_dbeacon_suspend_beacon, vap->iv_dbeacon_timeout*1000);
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    }
#endif

    if (node_leave) {
	IEEE80211_NODE_LEAVE(ni);
    } else {
        ieee80211node_set_extflag(ni, IEEE80211_NODE_ASSOC_REQ);
    }

    return status;
}

/*
 *  create a insfra structure network (Host AP mode).
 */

int ieee80211_mlme_create_infra_continue(struct ieee80211vap *vap)
{
    struct ieee80211com         *ic = vap->iv_ic;
    bool skip_dfs_cac = false;
    struct ieee80211_vap_opmode_count    vap_opmode_count;
    struct wlan_objmgr_pdev *pdev;
    int status = 0;
    bool is_target_scan_radio;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_print("%s : pdev is null", __func__);
        return EINVAL;
    }

    /* Update channel and rates of the node */
    ieee80211_node_set_chan(vap->iv_bss);
    vap->iv_cur_mode = ieee80211_chan2mode(vap->iv_bss->ni_chan);

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s \n", __func__);

#ifdef ATH_SUPPORT_DFS
    /*
     * Cancel CAC timer and reset valid bit if prevchan is valid and
     * is not same as current chan or has different flag than current chan
     */
    if (ic->ic_prevchan) {
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
            QDF_STATUS_SUCCESS) {
            return EINVAL;
        }

        mlme_dfs_cac_valid_reset_for_freq(pdev,
                                 ic->ic_prevchan->ic_freq,
                                 ic->ic_prevchan->ic_flags);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    }
#endif

    OS_MEMZERO(&(vap_opmode_count), sizeof(vap_opmode_count));
    /*
     * Get total number of VAPs of each type supported by the IC.
     */
    ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
    /* if station vap is present and in connected state, then skip DFS CAC timer */
    if (ic->ic_sta_vap && wlan_is_connected(ic->ic_sta_vap)
        && mlme_dfs_is_spoof_done(ic->ic_pdev_obj) &&
        !ic->ic_rpt_ap_needs_dfs) {
        skip_dfs_cac = true;
    }

#if ATH_SUPPORT_ZERO_CAC_DFS
    /*
     * If precac required timer expires it does a vdev_restart of all the active vaps
     * so that precac algorithm can pick the next channel. However vdev_restart response
     * also calls this function and tries to start the CAC. We do not want CAC for
     * vdev_restart by precac.
     */
    if(vap->iv_pre_cac_timeout_channel_change == 1) {
        vap->iv_pre_cac_timeout_channel_change = 0;
        IEEE80211_DPRINTF(vap,IEEE80211_MSG_DFS, "%s pre_cac channel change so skip cac\n",__func__);
        skip_dfs_cac = true;
    }
#endif

    if (vap->iv_no_cac) {
        skip_dfs_cac = true;
        vap->iv_no_cac = 0;
    }

    if (ieee80211_ic_enh_ind_rpt_is_set(ic) && ic->ic_rpt_ap_needs_dfs) {
        qdf_debug("don't skip CAC for independent rpt mode with rpt_max_phy");
        skip_dfs_cac = false;
    }

    if(ic->recovery_dfschan && (ic->recovery_dfschan == ic->ic_curchan)) {
        qdf_print("%s: same DFS channel during recovery, skipping CAC", __func__);
        ic->recovery_dfschan = NULL;
        skip_dfs_cac = true;
    }

    if (IEEE80211_IS_CSH_OPT_AVOID_DUAL_CAC_ENABLED(ic)) {
        if ((vap_opmode_count.sta_count >= 1) && ic->ic_prevchan && ic->ic_curchan &&
                IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(ic->ic_curchan)) {
            skip_dfs_cac = is_subset_channel_for_cac(ic, ic->ic_curchan, ic->ic_prevchan);
        }
    }

    is_target_scan_radio =
        wlan_pdev_nif_feat_ext_cap_get(pdev,
                                       WLAN_PDEV_FEXT_SCAN_RADIO);
    if (is_target_scan_radio) {
        bool is_dfs_disabled_for_scan_radio =
            wlan_pdev_nif_feat_ext_cap_get(pdev,
                                           WLAN_PDEV_FEXT_SCAN_RADIO_DFS_DIS);
        if (is_dfs_disabled_for_scan_radio)
            skip_dfs_cac = true;
    }

    if (ic->ic_curchan && wlan_reg_is_6ghz_chan_freq(ic->ic_curchan->ic_freq))
        ieee80211_send_tpc_power_cmd(vap);

    if (vap->restart_txn && ic->ic_is_restart_on_same_chan)
        skip_dfs_cac = true;

    if (skip_dfs_cac || ieee80211_dfs_cac_start(vap)) {

        /* In case skip_dfs_cac is set, reset CSA from chanswitch ioctl flag */
        if (ic->ic_flags_ext2 & IEEE80211_FEXT2_CSA_WAIT)
                ic->ic_flags_ext2 &= ~IEEE80211_FEXT2_CSA_WAIT;

        if (!ic->ic_nl_handle) {
            /* NON DFS channel, Start host ap */
            wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
                                      WLAN_VDEV_SM_EV_START_SUCCESS, 0, NULL);
        }
    } else {
        wlan_mlme_inc_act_cmd_timeout(vap->vdev_obj,
                        WLAN_SER_CMD_VDEV_START_BSS);
        wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
                                  WLAN_VDEV_SM_EV_DFS_CAC_WAIT, 0, NULL);
    }

    return status;
}

enum ieee80211_phymode
ieee80211_derive_max_phy(enum ieee80211_phymode des_mode,
                         struct ieee80211_ath_channel *chan)
{
    enum ieee80211_mode des_phy;
    enum ieee80211_phymode chan_mode;
    enum phy_ch_width chwidth;
    int8_t sec_offset = IEEE80211_SEC_CHAN_OFFSET_SCN;

    chwidth = ieee80211_get_phy_chan_width(chan);
    des_phy = get_mode_from_phymode(des_mode);
    chan_mode = ieee80211_chan2mode(chan);

    if (ieee80211_is_phymode_40plus(chan_mode))
        sec_offset = IEEE80211_SEC_CHAN_OFFSET_SCA;
    else if (ieee80211_is_phymode_40minus(chan_mode))
        sec_offset = IEEE80211_SEC_CHAN_OFFSET_SCB;

    return ieee80211_get_composite_phymode(des_phy,
                                           chwidth,
                                           sec_offset);
}


struct ieee80211_ath_channel*
ieee80211_use_max_phy_for_rep_ap(struct ieee80211vap *vap,
                                 struct ieee80211_ath_channel *new_chan)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_ath_channel *chan = NULL;
    struct ieee80211vap *tmpvap = NULL;
    struct wlan_objmgr_psoc *psoc;
    enum phy_ch_width des_chwidth;
    enum phy_ch_width cur_chwidth;
    enum ieee80211_phymode final_phymode;

    if (!ieee80211_ic_rpt_max_phy_is_set(ic))
        return NULL;

    /*Not a repeatar*/
    if (!ic->ic_sta_vap)
        return NULL;

    /*Change only AP phy mode. STA follows root AP's Phy*/
    if (vap->iv_opmode != IEEE80211_M_HOSTAP)
        return NULL;

    /*
     * Apply mode change only for first 2 VAPs(first AP and STA)
     * Rest of the VAPs can follow cur_chan for mode
     */
    if (!ieee80211_ic_enh_ind_rpt_is_set(ic) &&
        ieee80211_get_num_active_vaps(ic) > 2)
        return NULL;

    /* Not supported for QWRAP and EXTAP */
    if (ieee80211_ic_enh_ind_rpt_is_set(ic)) {
        psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
        if (!psoc || wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_QWRAP_ENABLE))
            return NULL;
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            if (wlan_vdev_mlme_feat_cap_get(vap->vdev_obj, WLAN_VDEV_F_AP) &&
                wlan_vdev_mlme_get_opmode(vap->vdev_obj) == QDF_STA_MODE)
                return NULL;
        }
    }

    if (!new_chan || !vap->iv_des_chan[vap->iv_des_mode] ||
        (vap->iv_des_mode ==  IEEE80211_MODE_AUTO) ||
        (vap->iv_des_chan[vap->iv_des_mode] == IEEE80211_CHAN_ANYC))
        return NULL;

    des_chwidth = ieee80211_get_phy_chan_width(vap->iv_des_chan[vap->iv_des_mode]);
    cur_chwidth = ieee80211_get_phy_chan_width(new_chan);

    qdf_debug("rpt AP VAP's des_chwidth=%d, rpt STA VAP's des_chwidth=%d",
              des_chwidth, cur_chwidth);

    if (des_chwidth > cur_chwidth) {
        chan = ieee80211_find_dot11_channel(ic, new_chan->ic_freq,
                                            new_chan->ic_vhtop_freq_seg2,
                                            vap->iv_des_mode);
        /*
         * Configure chan corresponds to max phy of rpt AP if chan
         * is non-dfs.
         * E.g. Rpt AP VAP's des_chan=36HT80 and Rpt STA VAP's
         * des_chan=36HT20. Configure 36HT80 since it is non-dfs.
         */
        if (chan && !IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(chan)) {
            qdf_debug("CAC not required for rpt_max_phy chan");
            return chan;
        }
        /*
         * Max phy chan is DFS chan here. Rpt AP VAP should perform CAC
         * before coming up in this chan.
         * E.g. Rpt AP VAP's des_chan=100HT160 and rpt STA VAP's
         * des_chan=100HT80. Mark CAC is required here before
         * coming up in 100HT160.
         */
        qdf_debug("CAC required for rpt_max_phy chan");
        ic->ic_rpt_ap_needs_dfs = 1;
    }
    chan = ieee80211_find_dot11_channel(ic, new_chan->ic_freq,
                                        new_chan->ic_vhtop_freq_seg2,
                                        vap->iv_des_mode);
    /*
     * For some cases, it is not possible to set max phymode.
     * E.g: Rpt AP VAP's phymode=HT160, and root is operating in channel
     * 149VHT20. In this case chan will be NULL. Try to configure max phy
     * with Root AP's chanwidth.
     * For above example, if rpt supported phy is 11AX, derive 149HE20.
     */
    if (!chan) {
        final_phymode = ieee80211_derive_max_phy(vap->iv_des_mode, new_chan);
        qdf_debug("Max chwidth for rpt ap not possible. Configure phymode %d",
                  final_phymode);
        chan = ieee80211_find_dot11_channel(ic, new_chan->ic_freq,
                                            new_chan->ic_vhtop_freq_seg2,
                                            final_phymode);
    }
    return chan;
}

struct ieee80211_ath_channel* ieee80211_derive_chan(struct ieee80211vap *vap)
{
    struct ieee80211_ath_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
    struct ieee80211com *ic = vap->iv_ic;
    int coex_enabled;
    wlan_if_t tmpvap;
    struct wlan_channel *iter_vdev_chan = NULL;
    struct ieee80211_ath_channel *max_phy_chan = NULL;

    /* if num active vaps is not 0
     * make the vap to follow the current channel instead of desired
     * channel
     */
    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
       iter_vdev_chan = wlan_vdev_get_active_channel(tmpvap->vdev_obj);
       if (iter_vdev_chan) {
           max_phy_chan = ieee80211_use_max_phy_for_rep_ap(vap,
                                                           ic->ic_curchan);
           break;
       }
    }

    /* Check if max phy mode can be used for AP VAP of rpt.
     * If so derive chan using desired chan's flags */
    if (iter_vdev_chan && !max_phy_chan){
        chan = ieee80211_find_channel(ic, iter_vdev_chan->ch_freq,
                                      iter_vdev_chan->ch_freq_seg2,
                                      iter_vdev_chan->ch_flags);
        if (!chan)
           chan = vap->iv_des_chan[vap->iv_des_mode];
    } else if (max_phy_chan) {
        chan = max_phy_chan;
    }

    if (chan == NULL || chan == IEEE80211_CHAN_ANYC) {
        return NULL;
    }

    coex_enabled = !(ic->ic_flags & IEEE80211_F_COEXT_DISABLE);

    if (coex_enabled) {
        if (IEEE80211_IS_CHAN_BW_40MHZ(chan) &&
                IEEE80211_IS_CHAN_2GHZ(chan)) {
            enum ieee80211_phymode mode;
            /*
             *  If we are in 40+ or 40- mode and if channel intolerant bit
             *  is set then its better to use 20 mode, because 40 PhyMode
             *  would be cause a performance drop as PHY has to monitor Ext
             *  channel too.
             */
            mode = IEEE80211_IS_CHAN_HE(chan) ? IEEE80211_MODE_11AXG_HE20
                                              : IEEE80211_MODE_11NG_HT20;

            if (IEEE80211_IS_CHAN_BW_40INTOL(chan)) {
                struct ieee80211_ath_channel    *chan20 = NULL;

                /* Find the HT20 channel info */
                chan20 = ieee80211_find_dot11_channel(ic, chan->ic_freq, 0,
                        mode);
                if (chan20) {
                    qdf_debug("Overriding HT40 channel with HT20 channel");
                    chan = chan20;
                }
                else {
                    qdf_debug("Unable to find HT20 channel in mode %d",mode);
                }
            }
        }
    }

    if (IEEE80211_IS_CHAN_DISALLOW_HOSTAP(chan)) {
        return NULL;
    }

    /* Enable vap_doth bit for 5 GHz and 6 GHz channel when the current pdev
     * supports 2 GHz and user has not disabled vap_doth.
     */
    if (!vap->iv_user_disabled_vap_doth &&
        ic->ic_pdev_is_2ghz_supported(ic) &&
        (IEEE80211_IS_CHAN_5GHZ(chan) ||
         IEEE80211_IS_CHAN_6GHZ(chan))) {
        ieee80211_vap_doth_set(vap);
    }

    /* Setup BSS color  */
    ieee80211_setup_bsscolor(vap, chan);

    return chan;
}

int
mlme_create_infra_bss(struct ieee80211vap *vap, u_int8_t restart)
{
    struct ieee80211com         *ic = vap->iv_ic;
    ieee80211_ssid              *ssid = NULL;
    int                         n_ssid;
    int                         error = 0;
    u_int8_t acs_report_scan_active = 0;
    bool scan_active = false;
    struct ieee80211_ath_channel *chan = NULL;
    QDF_STATUS sm_ret;

    n_ssid = ieee80211_get_desired_ssid(vap, 0,&ssid);

    if (ssid == NULL)
        return EINVAL;

    /*
     * if there is a scan in progress.
     * then there is a vap currently scanning and the chip
     * is off on a different channel. we can not bring up
     * vap at this point.  Scan can be in progress for
     * independant repeater vaps, since they do not change channels.
     *
     * When the resmgr is active, do not fail vap creation even if a scan is in
     * progress.
     * In repeater dependent mode, if STA vap is not associated do not bring up
     * AP vaps unless the it is a mesh VAP.
     */
    acs_report_scan_active = wlan_get_param(vap, IEEE80211_START_ACS_REPORT);

    if (!ieee80211_resmgr_active(ic) &&
           ((scan_active = wlan_scan_in_progress(vap) &&
             !(ieee80211_ic_offchanscan_is_set(ic) || acs_report_scan_active)) ||
             ieee80211_sta_assoc_in_progress(ic))
#if MESH_MODE_SUPPORT
             && !vap->iv_mesh_vap_mode
#endif
        && !ieee80211_ic_enh_ind_rpt_is_set(ic)) {

        if (scan_active)
            ic->schedule_bringup_vaps = true;

        mlme_nofl_err("vdev:%d: Scan is in progress, return",
                           wlan_vdev_get_id(vap->vdev_obj));
        return EAGAIN;
    }

    /* create BSS node for infra network */
    error = ieee80211_create_infra_bss(vap,ssid->ssid, ssid->len);

    if (error) {
        goto err;
    }
    chan = ieee80211_derive_chan(vap);
    if (!chan) {
        qdf_err("Channel is NULL");
        return EINVAL;
    }

    ieee80211_update_vdev_chan(vap->vdev_obj->vdev_mlme.des_chan, chan);

    sm_ret = wlan_vdev_mlme_sm_deliver_evt(vap->vdev_obj,
                                      WLAN_VDEV_SM_EV_START, 0, NULL);
    if (sm_ret != QDF_STATUS_SUCCESS) {
        qdf_err("SM event delivery failed");
        return EINVAL;
    }

err:
    return error;
}
void ieee80211_mlme_create_infra_continue_async(struct ieee80211vap *vap, int32_t status)
{
    int error = 0;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: status %d\n", __func__,status);
    if (status == EOK) {
        error = ieee80211_mlme_create_infra_continue(vap);
    }

    if (!error) {
        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, (status == EOK) ? IEEE80211_STATUS_SUCCESS : IEEE80211_STATUS_REFUSED);
    } else {
        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, IEEE80211_STATUS_REFUSED);
    }
}

/*
 * function to handle shared auth in HOST AP mode.
 */

u_int16_t
mlme_auth_shared(struct ieee80211_node *ni, u_int16_t seq, u_int16_t status,
                 u_int8_t *challenge,u_int16_t challenge_len)
{
    struct ieee80211vap    *vap = ni->ni_vap;
    struct ieee80211com    *ic = ni->ni_ic;
    u_int16_t              estatus = IEEE80211_STATUS_SUCCESS;

    /*
     * NB: this can happen as we allow pre-shared key
     * authentication to be enabled w/o wep being turned
     * on so that configuration of these can be done
     * in any order.  It may be better to enforce the
     * ordering in which case this check would just be
     * for sanity/consistency.
     */
    estatus = 0;            /* NB: silence compiler */
    if (!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                           ni->ni_macaddr, "shared key auth",
                           "%s", " PRIVACY is disabled");
        estatus = IEEE80211_STATUS_ALG;
    }

    if (estatus == IEEE80211_STATUS_SUCCESS) {
        switch (seq) {
        case IEEE80211_AUTH_SHARED_CHALLENGE:
        case IEEE80211_AUTH_SHARED_RESPONSE:
            if (challenge == NULL) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "%s\n", "shared key auth no challenge");
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_auth_err_inc(vap->vdev_obj, 1);
#endif
                estatus = IEEE80211_STATUS_CHALLENGE;
            } else if (challenge_len != IEEE80211_CHALLENGE_LEN) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                                   "shared key auth bad challenge len %d", challenge_len);
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_auth_err_inc(vap->vdev_obj, 1);
#endif
                estatus = IEEE80211_STATUS_CHALLENGE;
            }
        default:
            break;
        }
    }

    if (estatus == IEEE80211_STATUS_SUCCESS) {
        switch (seq) {
        case IEEE80211_AUTH_SHARED_REQUEST:
            if (ni->ni_challenge == NULL)
                ni->ni_challenge = (u_int32_t *)OS_MALLOC(ic->ic_osdev ,IEEE80211_CHALLENGE_LEN,0);
            if (ni->ni_challenge == NULL) {
                IEEE80211_NOTE(ni->ni_vap,
                               IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "%s", "shared key challenge alloc failed");
                /* XXX statistic */
                estatus = IEEE80211_STATUS_UNSPECIFIED;
            } else {
                /*
                 * get random bytes for challenge text.
                 */

                OS_GET_RANDOM_BYTES(ni->ni_challenge,
                                    IEEE80211_CHALLENGE_LEN);
                IEEE80211_NOTE(vap,
                               IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "%s", "shared key auth request \n");
                ieee80211_send_auth(ni,(seq + 1),0,(u_int8_t *)ni->ni_challenge,IEEE80211_CHALLENGE_LEN,NULL);
            }
            break;
        case IEEE80211_AUTH_SHARED_RESPONSE:
            if (ni->ni_challenge == NULL) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "shared key response",
                                   "%s", "no challenge recorded");
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_auth_err_inc(vap->vdev_obj, 1);
#endif
                estatus = IEEE80211_STATUS_CHALLENGE;
            } else if (memcmp(ni->ni_challenge, challenge,
                              challenge_len) != 0) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "shared key response",
                                   "%s", "challenge mismatch");
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_rx_auth_fail_inc(vap->vdev_obj, 1);
#endif
                estatus = IEEE80211_STATUS_CHALLENGE;
            } else {
                IEEE80211_NOTE(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "station authenticated (%s)\n", "shared key");
                ieee80211_node_authorize(ni);
                /*
                 * shared auth success.
                 */
                ieee80211_send_auth(ni,(seq + 1),0, NULL,0,NULL);
            }
            break;
        default:
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                               ni->ni_macaddr, "shared key auth ",
                               "bad seq %d \n", seq);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_auth_err_inc(vap->vdev_obj, 1);
#endif
            estatus = IEEE80211_STATUS_SEQUENCE;
            break;
        }
    }

    /*
     * Send an error response.
     */
    if (estatus != IEEE80211_STATUS_SUCCESS) {
        ieee80211_send_auth(ni,(seq + 1),estatus, NULL,0,NULL);
    }

    return estatus;
}

static int mlme_recv_auth_ap_handle_duplicate(struct ieee80211_node *ni,
                                            u_int16_t algo, u_int16_t seq, u_int16_t frame_seq,
                                            bool* create_new_node)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    u_int16_t associd = 0;
    /*
     * Check is frame is duplicate frame or not.
     * check the received sequence number and compare previous seq number of auth frame.
     */
    if((ni->ni_last_rxauth_seq == frame_seq) && (algo != IEEE80211_AUTH_ALG_SAE)){
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                    "recv duplicate auth frame seq num %d\n",frame_seq);
        return -1;
    } else if (ni->ni_last_auth_rx_time != 0
        && seq != IEEE80211_AUTH_SHARED_RESPONSE && (algo != IEEE80211_AUTH_ALG_SAE)){
        /*
         * Check is auth frame is recevied before a valid assoc request is given
         * ni_last_auth_rx_time is made as '0' on receving assoc request to node.
         * if ni_last_auth_rx_time is not '0' then already auth is in progress.
         * if frame is recevied within nominal auth + assoc req time,
         * then drop this auth. As already one more frame in progress.
         */
        systime_t now;
        now = OS_GET_TIMESTAMP();
        if(CONVERT_SYSTEM_TIME_TO_MS(now - ni->ni_last_auth_rx_time) < 100){
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                "recv another auth frame when previous is in progress\n");
            return -1;
        }
    }

    ni->ni_last_auth_rx_time = OS_GET_TIMESTAMP();
    ni->ni_last_rxauth_seq = frame_seq;

    if ((seq == IEEE80211_AUTH_OPEN_REQUEST ||
         seq == IEEE80211_AUTH_SHARED_REQUEST) &&
         (algo != IEEE80211_AUTH_ALG_FT) && (algo != IEEE80211_AUTH_ALG_SAE)) {
        /* if receive the re-auth frame without any disassoc check if node is at power save mode
            let the sta leave the power save state. */
        if ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) == IEEE80211_NODE_PWR_MGT)
        {
            ieee80211_mlme_node_pwrsave_ap(ni,0);
        }
        /* Leave the node only if PMF not enabled */
        if (!(ieee80211_is_pmf_enabled(vap, ni) && ieee80211_node_is_authorized(ni)) && ieee80211node_has_extflag(ni, IEEE80211_NODE_ASSOC_REQ)) {
            if(!ieee80211_vap_trigger_mlme_resp_is_set(vap)) {
                if (!ieee80211_try_ref_node(ni, WLAN_MLME_HANDLER_ID))
                    return -1;

                associd = ni->ni_associd;
                if(IEEE80211_NODE_LEAVE(ni)) {
                    IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(vap,
                            ni->ni_macaddr, associd, IEEE80211_REASON_ASSOC_LEAVE);
                }
                ieee80211_free_node(ni, WLAN_MLME_HANDLER_ID);
            } else {
                if (qdf_atomic_read(&(ni->ni_auth_tx_completion_pending))) {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                            "recv auth when AUTH TX completion is pending...\n");
                    return -1;

                } else {
                    ieee80211_try_mark_node_for_delayed_cleanup(ni);
                    wlan_mlme_disassoc_request(vap,ni->ni_macaddr,IEEE80211_REASON_ASSOC_LEAVE);
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                            "recv auth when valid node is present ignore auth and disconnect sta\n");
                    return -1;
                }
            }
        } else {
            /* PMF is enabled so don't create new node */
            *create_new_node = FALSE;
        }
    } else if (seq == IEEE80211_AUTH_SHARED_RESPONSE || algo == IEEE80211_AUTH_ALG_FT
                || algo == IEEE80211_AUTH_ALG_SAE){
        /*
         * Second auth in AUTH_ALG_SHARED or
         * Auth request with FT as algo for roaming
         */
        *create_new_node = FALSE;
    } else {
        /*
         * Invalid auth frame in AP mode.
         */
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr,
                   "Invalid auth frame with algo %d AuthSeq %d \n",algo,seq);
        return -1;
    }

  return 0;
}

struct ieee80211_node* find_logically_deleted_node_on_soc(struct wlan_objmgr_psoc *psoc,
        const uint8_t *macaddr, const uint8_t *bssid, wlan_objmgr_ref_dbgid id)
{
    uint8_t pdev_id;
    struct ieee80211_node* ni_temp = NULL;
    struct wlan_objmgr_pdev *pdev;
    struct ieee80211com    *ic;

    if(psoc == NULL)
        return NULL;

    for (pdev_id = 0; pdev_id < WLAN_UMAC_MAX_PDEVS; pdev_id++) {
        pdev = wlan_objmgr_get_pdev_by_id(psoc, pdev_id, id);
        if (pdev != NULL) {
            ic = wlan_pdev_get_mlme_ext_obj(pdev);
            if (ic != NULL)
                ni_temp = _ieee80211_find_logically_deleted_node(ic,
                        macaddr, bssid, id);

            wlan_objmgr_pdev_release_ref(pdev, id);

            if (ni_temp != NULL)
                break;
        }
    }

    return ni_temp;
}

#ifdef AST_HKV1_WORKAROUND
int mlme_find_and_delete_wds_before_auth(struct ieee80211vap *vap, uint8_t *mac,
                                         struct recv_auth_params_defer *auth_params)
{
    struct ieee80211com *ic = vap->iv_ic;
    wbuf_t cwbuf = NULL;

    if (ic->ic_get_tgt_type(ic) != TARGET_TYPE_QCA8074)
        return -1;

    if (ic->ic_node_lookup_wds_and_del) {
        struct recv_auth_params_defer *auth_cookie = NULL;

        if (auth_params) {
            auth_cookie = qdf_mem_malloc(sizeof(struct recv_auth_params_defer));
            if (!auth_cookie) {
                return -1;
            }
            qdf_mem_copy(auth_cookie, auth_params, sizeof(struct recv_auth_params_defer));
            cwbuf  =  wbuf_clone(vap->iv_ic->ic_osdev, auth_params->wbuf);
            if (!cwbuf) {
                qdf_mem_free(auth_cookie);
                return -1;
            }
            auth_cookie->wbuf = cwbuf;
        }

        if (ic->ic_node_lookup_wds_and_del(vap->iv_ifp, mac, auth_cookie) < 0) {
            if (cwbuf)
                wbuf_free(cwbuf);
            if (auth_cookie)
                qdf_mem_free(auth_cookie);
            return -1;
        }
        /* auth_cookie will be freed in WDS del completion handler */
        return 0;
    }

    return -1;
}
#endif

int mlme_recv_auth_ap(struct ieee80211_node *ni,
                       u_int16_t algo, u_int16_t seq, u_int16_t status_code,
                       u_int8_t *challenge, u_int8_t challenge_length, wbuf_t wbuf,
                       const struct ieee80211_rx_status *rs)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211_frame        *wh;
    u_int16_t                     frame_seq;
    bool create_new_node = TRUE;
    struct recv_auth_params_defer auth_params;
    struct ieee80211_node *ni_temp = NULL; /*to hold logically deleted node */
    struct wlan_objmgr_peer *peer = NULL;
    struct wlan_objmgr_vdev *vdev = NULL;
    systime_t now;
    uint32_t delta;
    int ret = 0;

    peer = ni->peer_obj;
    if (peer)
        vdev = wlan_peer_get_vdev(peer);

    if (!vdev) {
        qdf_print("%s: null vdev", __func__);
        return -1;
    }
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);

    /* AP must be up and running */
    if (!mlme_priv->im_connection_up || 
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
        IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
                        "VAP is not up? im_connection_up=%d, vdev up=%d\n",
                        mlme_priv->im_connection_up, wlan_vdev_is_up(vap->vdev_obj));
        return -1;
    }

    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
                       "recv auth frame with algorithm %d seq %d \n", algo, seq);
    frame_seq = ((le16toh(*(u_int16_t *)wh->i_seq)) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT;

        /* Always remove the old client node. Otherwise, station count can be wrong */
        if (ni != vap->iv_bss)  {
#if WLAN_SUPPORT_SPLITMAC
            if (splitmac_is_enabled(vdev)) {
                if(splitmac_api_get_state(peer) == SPLITMAC_ADDCLIENT_START) {
                    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
                       "recv auth frame when assoc is in progress %d\n",frame_seq);
                    return -1;
                }
            }
#endif
            if(mlme_recv_auth_ap_handle_duplicate(ni, algo, seq, frame_seq, &create_new_node))
                return -1;
        }

        /*
         * 1. If node delete in progress take a refrence for that node.
         * 2. else call defer function immediatly.
         *
         */
        auth_params.algo = algo;
        auth_params.seq = seq;
        auth_params.status_code = status_code;
        auth_params.challenge = challenge;
        auth_params.challenge_length = challenge_length;
        auth_params.wbuf = wbuf;
        auth_params.vdev_id = wlan_vdev_get_id(vdev);
        qdf_mem_copy(&auth_params.rs, rs, sizeof(struct ieee80211_rx_status));

        if (create_new_node) {
            ni_temp = find_logically_deleted_node_pdev_psoc(vap->iv_ic,wh->i_addr2,
                                                            WLAN_MLME_SB_ID);
            if (ni_temp != NULL) {
                now = OS_GET_TIMESTAMP();
                delta = CONVERT_SYSTEM_TIME_TO_MS(now - ni->ss_last_data_time);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_PEER_DELETE,
                        "%s: node 0x%pK, mac:%s logically deleted, delta:%d\n",
                        __func__, ni_temp, ether_sprintf(ni_temp->ni_macaddr), delta);
                if (!qdf_atomic_read(&ni_temp->ni_fw_peer_delete_rsp_pending)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_PEER_DELETE,
                            "delete response pending is ZERO continue AUTH \n");
                    ieee80211_free_node(ni_temp, WLAN_MLME_SB_ID);
                    ret = mlme_recv_auth_ap_defer(ni, create_new_node, &auth_params, 0);
                } else {
                    qdf_nbuf_t cwbuf;

                    /* If another AUTH frame while waiting for peer del response,
                     * free the old one and use new one
                     */
                    if (ni_temp->auth_params.wbuf) {
                        wbuf_free(ni_temp->auth_params.wbuf);
                        ni_temp->auth_params.wbuf = NULL;
                    }

                    cwbuf  =  wbuf_clone(vap->iv_ic->ic_osdev,
                                          auth_params.wbuf);
                    if (!cwbuf) {
                        ni_temp->auth_inprogress = 0;
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_PEER_DELETE,
                                           "wbuf clone failed: %s\n",
                                           ether_sprintf(ni_temp->ni_macaddr));
                        ieee80211_free_node(ni_temp, WLAN_MLME_SB_ID);
                        return -1;
                    }
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_PEER_DELETE,
                                       "defer AUTH for: %s\n",
                                        ether_sprintf(ni_temp->ni_macaddr));
                    /* copy AUTH params */
                    ni_temp->auth_params.algo = auth_params.algo;
                    ni_temp->auth_params.seq = auth_params.seq;
                    ni_temp->auth_params.status_code = auth_params.status_code;
                    ni_temp->auth_params.challenge = auth_params.challenge;
                    ni_temp->auth_params.challenge_length =
                                                   auth_params.challenge_length;
                    ni_temp->auth_params.vdev_id = auth_params.vdev_id;
                    ni_temp->auth_params.wbuf  =  cwbuf;
                    qdf_mem_copy(&ni_temp->auth_params.rs,
                                  &auth_params.rs,
                                  sizeof(struct ieee80211_rx_status));
                    ni_temp->auth_inprogress = 1;
                    /* mlme_recv_auth_ap_defer will be called
                     * from mlme_auth_peer_delete_handler
                     */
                    ieee80211_free_node(ni_temp, WLAN_MLME_SB_ID);
                    ret = -1;
                }
            } else {
#ifdef AST_HKV1_WORKAROUND
                ret = mlme_find_and_delete_wds_before_auth(vap, wh->i_addr2, &auth_params);
                if (ret != 0)
#endif
	            ret = mlme_recv_auth_ap_defer(ni, create_new_node, &auth_params, 0);
            }
        } else {
            ret = mlme_recv_auth_ap_defer(ni, false, &auth_params, 0);
        }

        return ret;
}

#ifdef AST_HKV1_WORKAROUND
int mlme_auth_wds_delete_resp_handler(struct wlan_objmgr_psoc *psoc,
                                      struct recv_auth_params_defer *auth_params)
{
    struct ieee80211_node *tmpni = NULL;
    struct wlan_objmgr_vdev *frm_recv_vdev = NULL;
    struct ieee80211vap *frm_recv_vap = NULL;
    qdf_nbuf_t wbuf = NULL;

    if (auth_params) {
        wbuf = auth_params->wbuf;

        frm_recv_vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc,
                auth_params->vdev_id, WLAN_MLME_NB_ID);
        if (!frm_recv_vdev)
            goto exit;
        frm_recv_vap = wlan_vdev_get_mlme_ext_obj(frm_recv_vdev);
        if (!frm_recv_vap)
            goto exit;

        tmpni = ieee80211_ref_node(frm_recv_vap->iv_bss, WLAN_MLME_HANDLER_ID);
        if (!tmpni)
            goto exit;
        mlme_recv_auth_ap_defer(tmpni, 1, auth_params, 1);
        /* Free reference taken during find_node above */
        ieee80211_free_node(tmpni, WLAN_MLME_HANDLER_ID);
        /* Free reference taken during find_vdev above */
        wlan_objmgr_vdev_release_ref(frm_recv_vdev, WLAN_MLME_NB_ID);
        qdf_mem_free(auth_params);
    }
    return 0;

exit:
    /* Couldn't process this request. Drop frame */
    if (frm_recv_vdev)
        wlan_objmgr_vdev_release_ref(frm_recv_vdev, WLAN_MLME_NB_ID);
    if (wbuf)
        wbuf_free(wbuf);
    if (auth_params)
        qdf_mem_free(auth_params);

    return -1;
}
#endif

int mlme_auth_peer_delete_handler(struct ieee80211vap *vap, struct ieee80211_node *ni)
{
  /* copy back AUTH params
   * Remove refrence for that node ideally it should be freed
   * call mlme_recv_auth_ap_defer with cached params
   */
    struct recv_auth_params_defer auth_params;
    struct ieee80211_node *tmpni = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct wlan_objmgr_vdev *frm_recv_vdev = NULL;
    struct ieee80211vap *frm_recv_vap = NULL;
    qdf_nbuf_t wbuf = NULL;

    if (ni->auth_inprogress) {
        auth_params.algo = ni->auth_params.algo;
        auth_params.seq = ni->auth_params.seq;
        auth_params.status_code = ni->auth_params.status_code;
        auth_params.challenge = ni->auth_params.challenge;
        auth_params.challenge_length = ni->auth_params.challenge_length;
        auth_params.vdev_id = ni->auth_params.vdev_id;
        auth_params.wbuf = ni->auth_params.wbuf;
        ni->auth_params.wbuf = NULL;
        wbuf = auth_params.wbuf;
        qdf_mem_copy(&auth_params.rs, &ni->auth_params.rs, sizeof(struct ieee80211_rx_status));
        /* vap in argument is the VAP on which peer delete happend. But peer can send
         * AUTH on a different vap. Find vap from stored vdev ID.
         */
        psoc = wlan_vdev_get_psoc(vap->vdev_obj);
        if (!psoc)
            goto exit;
        frm_recv_vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc,
                auth_params.vdev_id, WLAN_MLME_NB_ID);
        if (!frm_recv_vdev)
            goto exit;
        frm_recv_vap = wlan_vdev_get_mlme_ext_obj(frm_recv_vdev);
        if (!frm_recv_vap)
            goto exit;

        tmpni = ieee80211_ref_node(frm_recv_vap->iv_bss, WLAN_MLME_HANDLER_ID);
        if (!tmpni)
            goto exit;
        mlme_recv_auth_ap_defer(tmpni, 1, &auth_params, 1);
        /* Free reference taken during find_node above */
        ieee80211_free_node(tmpni, WLAN_MLME_HANDLER_ID);
        /* Free reference taken during find_vdev above */
        wlan_objmgr_vdev_release_ref(frm_recv_vdev, WLAN_MLME_NB_ID);
    }
    return 0;

exit:
    /* Couldn't process this request. Drop frame */
    if (frm_recv_vdev)
        wlan_objmgr_vdev_release_ref(frm_recv_vdev, WLAN_MLME_NB_ID);
    if (wbuf)
        wbuf_free(wbuf);
    return -1;
}

static void ieee80211_notify_deferred_auth(struct ieee80211vap *vap,
                                           struct ieee80211_node *ni,
                                           wbuf_t wbuf,
                                           struct ieee80211_rx_status *rs)
{
    struct ieee80211_frame *wh;
    int subtype, ret;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (ieee80211_vap_registered_is_set(vap) &&
        vap->iv_evtable && vap->iv_evtable->wlan_receive_filter_80211) {
        ret = vap->iv_evtable->wlan_receive_filter_80211(vap->iv_ifp, wbuf,
                                                         IEEE80211_FC0_TYPE_MGT,
                                                         subtype, rs);
        /* If indication to OS fails, remove the node */
        if (ret) {
            if(ni && (ni != vap->iv_bss)) {
                IEEE80211_NODE_LEAVE(ni);
            }
        }
    }
}

static bool wlan_rx_auth_sanity_check(struct ieee80211vap *vap, u_int16_t algo)
{
    int32_t authmode;

    if ((algo != IEEE80211_AUTH_ALG_OPEN) &&
        (algo != IEEE80211_AUTH_ALG_SHARED) &&
        (algo != IEEE80211_AUTH_ALG_FT) &&
        (algo != IEEE80211_AUTH_ALG_FILS_SK) &&
        (algo != IEEE80211_AUTH_ALG_FILS_SK_PFS) &&
        (algo != IEEE80211_AUTH_ALG_FILS_PK) &&
        (algo != IEEE80211_AUTH_ALG_SAE)) {
        return FALSE;
    }

    authmode = wlan_crypto_get_param(vap->vdev_obj,
                             WLAN_CRYPTO_PARAM_AUTH_MODE);
    if (authmode == -1) {
        return FALSE;
    }

    /* Validate algo */
    if (algo == IEEE80211_AUTH_ALG_SHARED &&
        !(authmode & (1 << WLAN_CRYPTO_AUTH_SHARED))) {
        return FALSE;
    }

    if (algo == IEEE80211_AUTH_ALG_OPEN &&
        (authmode & (1 << WLAN_CRYPTO_AUTH_SHARED)) &&
        !(authmode & (1 << WLAN_CRYPTO_AUTH_OPEN))) {
        return FALSE;
    }
    return TRUE;
}

int mlme_recv_auth_ap_defer(struct ieee80211_node *ni, bool create_new_node,
        struct recv_auth_params_defer *auth_params, int peer_delete_inprogress)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211_frame        *wh;
    u_int16_t                     frame_seq = 0;
    u_int16_t                     indication_status = IEEE80211_STATUS_SUCCESS,response_status = IEEE80211_STATUS_SUCCESS ;
    bool                          send_auth_response=true,indicate=true;
    u_int16_t algo, seq, status_code;
    u_int8_t *challenge;
    u_int8_t challenge_length;
    wbuf_t wbuf;
    struct ieee80211_rx_status *rs = &auth_params->rs;
    struct ieee80211_mlme_priv  *mlme_priv = vap->iv_mlme_priv;
    int32_t authmode;
#if QCA_SUPPORT_SON
    struct bs_auth_reject_ind auth_reject_event_data = {0};
    u_int8_t bs_rej_reason;
    bool bs_blocked;
    bool bs_rejected;
#endif
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(vap->iv_ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE);
    uint16_t vap_assoc_limit;

    /*
     * iv_max_aid represents the size of the AID bitmap. For MBSSID/EMA this
     * does not always imply the actual number of clients allowed due to
     * reserved AIDs. Additionally, for MBSSID/EMA, use per-VAP AID limit
     * instead of the global AID limit.
     */
    vap_assoc_limit = is_mbssid_enabled ?
                       (vap->iv_mbss_max_aid-(1 << vap->iv_ic->ic_mbss.max_bssid)-1) :
                       (vap->iv_max_aid-1);

    algo = auth_params->algo;
    seq = auth_params->seq;
    status_code = auth_params->status_code;
    challenge = auth_params->challenge;
    challenge_length = auth_params->challenge_length;
    wbuf = auth_params->wbuf;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);

    /* Max auth fail received check auth sanity, drop instantly if fails */
    if (vap->cont_auth_fail >= vap->max_cont_auth_fail) {
        if (!wlan_rx_auth_sanity_check(vap, algo)) {
            if (peer_delete_inprogress) {
                wbuf_free(auth_params->wbuf);
            }
            return -1;
        }
    }

    /* AP must be up and running */
    if (!mlme_priv->im_connection_up || 
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
        if (peer_delete_inprogress) {
            wbuf_free(auth_params->wbuf);
        }
        qdf_print("%s: vap%d is going down, Drop auth request from %s",
                __func__, vap->iv_unit, ether_sprintf(wh->i_addr2));
        return -1;
    }

#if QCA_SUPPORT_SON
    bs_rej_reason = 0;
    bs_blocked = ieee80211_acl_is_auth_blocked(vap,
                                               wh->i_addr2,
                                               rs->rs_snr,
                                               &bs_rej_reason);
    bs_rejected = (bs_blocked && (bs_rej_reason > 0));

    if (bs_blocked && !bs_rejected) {
        /*
         * This condition will never be true when using Wi-Fi SON applications
         */
        /* Ignore auth frame */
        QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_DEBUG,
                  "[%s] auth: ignored by band steering\n",
                  ether_sprintf(wh->i_addr2));

        qdf_mem_copy(auth_reject_event_data.client_addr, wh->i_addr2, QDF_MAC_ADDR_SIZE);
        auth_reject_event_data.rssi = rs->rs_rssi;
        auth_reject_event_data.reason = 0;
        auth_reject_event_data.bs_blocked = bs_blocked;
        auth_reject_event_data.bs_rejected = bs_rejected;
        son_update_mlme_event(vap->vdev_obj, ni->peer_obj, SON_EVENT_BSTEERING_TX_AUTH_FAIL,
                              &auth_reject_event_data);
        return -1;
    }
#endif /* QCA_SUPPORT_SON */


    do {
        if (create_new_node) {
            /* create a node for the station */

            ni = ieee80211_dup_bss(vap, wh->i_addr2);
            if (ni == NULL) {
                indication_status = IEEE80211_STATUS_OTHER;
                /* free cloned wbuffer */
                if (peer_delete_inprogress) {
                    wbuf_free(auth_params->wbuf);
                }
                return -1;
            }

            ni->auth_inprogress = 0;
            wlan_node_set_peer_state(ni, WLAN_AUTH_STATE);

            /* update the last auth frame sequence number */
            ni->ni_last_rxauth_seq = frame_seq;
            ni->ni_last_auth_rx_time = OS_GET_TIMESTAMP();

            /* override bss authmode for shared auth request algorithm*/
            if (algo  == IEEE80211_AUTH_ALG_SHARED)
                ni->ni_authmode = IEEE80211_AUTH_SHARED;
        } else {
            if (!ieee80211_try_ref_node(ni, WLAN_MLME_HANDLER_ID)) {
                indication_status = IEEE80211_STATUS_OTHER;
                /* free cloned wbuffer */
                if (peer_delete_inprogress) {
                    wbuf_free(auth_params->wbuf);
                }
                return -1;
            }
        }

        authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
        if ( authmode == -1 ) {
            qdf_err("crypto_err while getting authmode params\n");
            return -1;
        }

        /* Validate algo */
        if (algo == IEEE80211_AUTH_ALG_SHARED && !(authmode & (1 << WLAN_CRYPTO_AUTH_SHARED))) {
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
            break;
        }

        if (algo == IEEE80211_AUTH_ALG_OPEN && (authmode & (1 << WLAN_CRYPTO_AUTH_SHARED)) &&
            !(authmode & (1 << WLAN_CRYPTO_AUTH_OPEN))) {
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
            break;
        }

        /*
         * Consult the ACL policy module if setup.
         */
        if (!ieee80211_acl_check(vap, wh->i_addr2)) {
#if QCA_SUPPORT_SON
        if(!(ieee80211_acl_flag_check(vap, wh->i_addr2, IEEE80211_ACL_FLAG_AUTH_ALLOW))) {
#endif /* QCA_SUPPORT_SON */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACL,
                      "[%s] auth: disallowed by ACL \n",ether_sprintf(wh->i_addr2));
            response_status = IEEE80211_STATUS_REFUSED;
            indication_status = IEEE80211_STATUS_REFUSED;
            IEEE80211_DELIVER_EVENT_BLKLST_STA_AUTH_INDICATION(vap, wh->i_addr2, indication_status);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_acl_inc(vap->vdev_obj, 1);
#endif
            break;
#if QCA_SUPPORT_SON
        } else {
        qdf_mem_copy(auth_reject_event_data.client_addr, wh->i_addr2, QDF_MAC_ADDR_SIZE);
        auth_reject_event_data.rssi = rs->rs_rssi;
        son_update_mlme_event(vap->vdev_obj, ni->peer_obj, SON_EVENT_BSTEERING_DBG_TX_AUTH_ALLOW,
                              &auth_reject_event_data);
        }
#endif /* QCA_SUPPORT_SON */
        }
#if QCA_SUPPORT_SON
        if (bs_rejected) {
            QDF_TRACE(QDF_MODULE_ID_MLME, QDF_TRACE_LEVEL_DEBUG,
                      "[%s] auth: rejected by band steering, reason=%u\n",
                      ether_sprintf(wh->i_addr2), bs_rej_reason);
            response_status = bs_rej_reason;
            indication_status = IEEE80211_STATUS_REFUSED;
            break;
        }
#endif /* QCA_SUPPORT_SON */
        if (IEEE80211_VAP_IS_COUNTERM_ENABLED(vap)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
              "[%s] auth: TKIP countermeasures enabled \n",ether_sprintf(wh->i_addr2));
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_auth_countermeasures_inc(vap->vdev_obj, 1);
#endif
	    response_status = IEEE80211_REASON_MIC_FAILURE;
	    indication_status = IEEE80211_STATUS_REFUSED;
	    break;
        }
        /*
         * reject auth if there are too many STAs already associated.
         */
        if (vap->iv_sta_assoc >= vap_assoc_limit) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                    "[%s] num auth'd STAs is %d, max is %d, rejecting "
                    "new auth\n", ether_sprintf(wh->i_addr2),
                    vap->iv_sta_assoc, vap->iv_max_aid);

            response_status = IEEE80211_STATUS_TOOMANY;
            indication_status = IEEE80211_STATUS_TOOMANY;
            break;
        }
        if (algo == IEEE80211_AUTH_ALG_OPEN) {
            if (seq != IEEE80211_AUTH_OPEN_REQUEST) {
                response_status = IEEE80211_STATUS_SEQUENCE;
                indication_status = IEEE80211_STATUS_SEQUENCE;
                break;
            }
        } else if (algo == IEEE80211_AUTH_ALG_SHARED) {
#if UMAC_SUPPORT_CFG80211
          if ( !vap->iv_cfg80211_create ) {
#endif
                response_status = indication_status = mlme_auth_shared(ni,seq,status_code,challenge,challenge_length);
                send_auth_response=false;
                if (seq == IEEE80211_AUTH_SHARED_REQUEST && response_status == IEEE80211_STATUS_SUCCESS)
                    indicate=false;
#if UMAC_SUPPORT_CFG80211
            }
#endif
            break;
        } else if(algo == IEEE80211_AUTH_ALG_FT) {
            ni->is_ft_reauth = 1;
            /* TODO: decide what all need to be done for FT frame */
            /*response_status =;
              indication_status = ;
              send_auth_response=;
              indicate=;
              vap->iv_stats.xxxx++*/
            break;
        }
#if WLAN_SUPPORT_FILS
        else if(algo == IEEE80211_AUTH_ALG_FILS_SK ||
                algo == IEEE80211_AUTH_ALG_FILS_SK_PFS ||
                algo == IEEE80211_AUTH_ALG_FILS_PK) {
            /* Any specific handling required for FILS Auth */
            break;
        }
#endif
        else if(algo == IEEE80211_AUTH_ALG_SAE){
                break;
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
                    "[%s] auth: unsupported algorithm %d \n",ether_sprintf(wh->i_addr2),algo);
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_auth_unsupported_inc(vap->vdev_obj, 1);
#endif
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
            break;
        }
    } while (FALSE);

    if (indicate ) {
        IEEE80211_DELIVER_EVENT_MLME_AUTH_INDICATION(vap, ni->ni_macaddr,
                indication_status);
    }

#if QCA_SUPPORT_SON
    if (response_status != IEEE80211_STATUS_SUCCESS) {
        qdf_mem_copy(auth_reject_event_data.client_addr, wh->i_addr2, QDF_MAC_ADDR_SIZE);
        auth_reject_event_data.rssi = rs->rs_rssi;
        auth_reject_event_data.reason = response_status;
        auth_reject_event_data.bs_blocked = bs_blocked;
        auth_reject_event_data.bs_rejected = bs_rejected;
        son_update_mlme_event(vap->vdev_obj, ni->peer_obj, SON_EVENT_BSTEERING_TX_AUTH_FAIL,
                              &auth_reject_event_data);
    }
#else
    // To silence compiler warning about unused variable.
    (void) rs;
#endif

	if (ieee80211_vap_oce_check(vap)) {
		ni->ni_abs_rssi = rs->rs_abs_rssi;
	}

    ni->ni_authalg = algo;
    ni->ni_authstatus = response_status;
#if UMAC_SUPPORT_CFG80211
    if (ieee80211_vap_trigger_mlme_resp_is_set(vap) || vap->iv_cfg80211_create ) {
#else
    if (ieee80211_vap_trigger_mlme_resp_is_set(vap)) {
#endif
        /* Wait for application to trigger mlme response for auth */
        /*
         * In case of WEXT hostapd calls wlan_mlme_auth and driver handles failures
         * like ACL check, MIC & IEEE80211_STATUS_TOOMANY failures and node will be
         * deauthed.
         * In case of cfg80211 hostpad does not call back driver to handle these
         * failures, so send auth with erro status incase of failures in driver itself.
         *
         */
#if UMAC_SUPPORT_CFG80211
        if ((vap->iv_cfg80211_create) && response_status != IEEE80211_STATUS_SUCCESS)
#else
        if (response_status != IEEE80211_STATUS_SUCCESS)
#endif
        {
            int32_t key_mgmt;

            key_mgmt = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_KEY_MGMT);
            if ( key_mgmt == -1 ) {
                qdf_err("crypto_err while getting key_mgmt params\n");
                return -1;
            }


            if (key_mgmt & (1 << WLAN_CRYPTO_KEY_MGMT_SAE))
                ieee80211_send_auth(ni, seq , response_status, NULL, 0, NULL);
            else
                ieee80211_send_auth(ni, seq + 1, response_status, NULL, 0, NULL);
            /* auth is not success, remove the node from node table */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s auth failed with status %d \n", __func__, ni->ni_authstatus);
            IEEE80211_NODE_LEAVE(ni);
        }
    } else {

        IEEE80211_DELIVER_EVENT_MLME_AUTH_COMPLETE(vap, ni->ni_macaddr, response_status);

        if (send_auth_response) {
            ieee80211_send_auth(ni, seq + 1, response_status, NULL, 0, NULL);
        }

        IEEE80211_DELETE_NODE_TARGET(ni, ni->ni_ic, vap, 0);
        if (indication_status != IEEE80211_STATUS_SUCCESS ){
            /* auth is not success, remove the node from node table*/
            IEEE80211_NODE_LEAVE(ni);
        }
    }

    if ((response_status == IEEE80211_STATUS_REFUSED) && (vap->iv_assoc_denial_notify)){
        IEEE80211_DELIVER_ASSOC_DENIAL_EVENT(vap, ni->ni_macaddr);
    }


    if (peer_delete_inprogress) {
        /* Indidate this frame to OS/upper layer */
        ieee80211_notify_deferred_auth(vap, ni, wbuf, rs);
        /* free cloned wbuffer */
        wbuf_free(auth_params->wbuf);
    }

    /*
     * release the reference created at the begining of the case above
     * either by alloc_node or ref_node.
     */
    if(create_new_node)
        ieee80211_free_node(ni, WLAN_MLME_OBJMGR_ID);
    else
        ieee80211_free_node(ni, WLAN_MLME_HANDLER_ID);

    if (response_status != IEEE80211_STATUS_SUCCESS) {
        vap->cont_auth_fail++;
        return -1;
    } else {
        /* Reset continuous auth_fail counter */
        vap->cont_auth_fail = 0;
        return 0;
    }
}

void
ieee80211_mlme_node_leave_ap(struct ieee80211_node *ni)
{
    struct ieee80211vap         *vap = ni->ni_vap;
    struct ieee80211_mlme_priv  *mlme_priv;
    ieee80211_mlme_event          event;

    ASSERT(vap != NULL);
    ASSERT(vap->iv_opmode != IEEE80211_M_STA);

    mlme_priv = vap->iv_mlme_priv;
    event.u.event_sta.sta_count= vap->iv_sta_assoc;
    event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
    event.u.event_sta.ni = ni;

    event.type = IEEE80211_MLME_EVENT_STA_LEAVE;
    ieee80211_mlme_deliver_event(mlme_priv,&event);

    /* NB: preserve ni_table */
    if (ieee80211node_has_flag(ni, IEEE80211_NODE_PWR_MGT)) {

        vap->iv_ps_sta--;
        ieee80211node_clear_flag(ni, IEEE80211_NODE_PWR_MGT);

        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.type = IEEE80211_MLME_EVENT_STA_EXIT_PS;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }


}

void
ieee80211_mlme_node_pwrsave_ap(struct ieee80211_node *ni, int enable)
{
    struct ieee80211vap *vap = ni->ni_vap;

    struct ieee80211com *ic = ni->ni_ic;

    ieee80211_mlme_event          event;

    if  ( ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) != 0) ^ enable) {
        struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

        if (enable) {
            vap->iv_ps_sta++;
            ieee80211node_set_flag(ni, IEEE80211_NODE_PWR_MGT);
#ifdef ATH_SWRETRY
            if (ic->ic_node_psupdate) {
                ic->ic_node_psupdate(ni, 1, 1);
                IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni, "%s", "pause LMAC node\n");
            }
#endif
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "power save mode on, %u sta's in ps mode\n", vap->iv_ps_sta);
            ieee80211node_pause(ni);
            event.type = IEEE80211_MLME_EVENT_STA_ENTER_PS;
        } else {

            vap->iv_ps_sta--;
            ieee80211node_clear_flag(ni, IEEE80211_NODE_PWR_MGT);
#ifdef ATH_SWRETRY
            if (ic->ic_node_psupdate) {
                ic->ic_node_psupdate(ni, 0, 1);
                IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni, "%s", "unpause LMAC node\n");
            }
#endif
            ieee80211node_unpause(ni);
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "power save mode off, %u sta's in ps mode\n", vap->iv_ps_sta);
            event.type = IEEE80211_MLME_EVENT_STA_EXIT_PS;

			/*
			 * Enable aggregation back after the client exit from power-save
			 */
			if(ni && ni->ni_pspoll) {
#if ATH_POWERSAVE_WAR
#ifdef ATH_SUPPORT_QUICK_KICKOUT
			    systime_t current_time = OS_GET_TIMESTAMP();
			    if (CONVERT_SYSTEM_TIME_TO_MS(current_time - ni->ni_pspoll_time) > (IEEE80211_PSPOLL_KICKOUT_THR)) {
				ni->ni_kickout = true;
			    }
#endif
			    /* Revisit later, this reset of ni_pspoll_time to be moved to inactivity phase */
			    ni->ni_pspoll_time = 0;
#endif
                            ic->ic_node_pspoll(ni, 0);
			}


        }

        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }
}


