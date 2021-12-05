/*
 *
 * Copyright (c) 2011-2018, 2020-2021 Qualcomm Innovation Center, Inc.
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
 */

#include "ieee80211_node_priv.h"
#include "ieee80211_defines.h"
#include "ieee80211_api.h"
#include <wlan_son_pub.h>
#if QCA_AIRTIME_FAIRNESS
#include <wlan_atf_utils_api.h>
#endif
#if WLAN_SUPPORT_SPLITMAC
#include <wlan_splitmac.h>
#endif
#if WLAN_SUPPORT_GREEN_AP
#include <wlan_green_ap_api.h>
#endif
#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif
#include <wlan_vdev_mlme.h>


#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
void iee80211_txbf_loforce_check(struct ieee80211_node *ni, bool nodejoin)
{
#ifdef ATH_SUPPORT_TxBF
    struct ieee80211com *ic = ni->ni_ic;
    if ( ni->ni_explicit_compbf || ni->ni_explicit_noncompbf || ni->ni_implicit_bf){
        if(!nodejoin)
            ic->ic_ht_txbf_sta_assoc--;

        if(ic->ic_ht_txbf_sta_assoc == 0){
            if(ic->ic_txbf_loforceon_update)
                ic->ic_txbf_loforceon_update(ic,nodejoin);
        }
        if(nodejoin)
            ic->ic_ht_txbf_sta_assoc++;
    }
#endif
}
#endif
/*
 * Create a HOSTAP node  on current channel based on ssid.
 */
int
ieee80211_create_infra_bss(struct ieee80211vap *vap,
                      const u_int8_t *essid,
                      const u_int16_t esslen)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni;

    if (vap->iv_bss == NULL) {
        ni = wlan_objmgr_alloc_ap_node(vap, vap->iv_myaddr);
        if (ni == NULL)
            return -ENOMEM;
    } else {
        ni = vap->iv_bss;
        ni->ni_ic = ic;
        ni->ni_vap = vap;
        ieee80211_node_reset(ni);
    }

    IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_myaddr);

    ni->ni_esslen = esslen;
    OS_MEMCPY(ni->ni_essid, essid, ni->ni_esslen);
    wlan_vdev_mlme_set_ssid(vap->vdev_obj, (const uint8_t*)essid, esslen);
    /* update mbss cache entry with ssid */
    ieee80211_mbssid_update_mbssie_cache_entry(vap, MBSS_CACHE_ENTRY_SSID);

    /* Skip re-assigning ni_intval for LP IOT vap */
    if (!(vap->iv_create_flags & IEEE80211_LP_IOT_VAP))   {
        ni->ni_intval = ic->ic_intval;
    }
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
        struct wlan_crypto_params *vdev_crypto_params, *peer_crypto_params = NULL;

	vdev_crypto_params = wlan_crypto_vdev_get_crypto_params(vap->vdev_obj);
        if (!vdev_crypto_params)
            return -1;

	peer_crypto_params = wlan_crypto_peer_get_crypto_params(ni->peer_obj);
        if (!peer_crypto_params)
            return -1;
        qdf_mem_copy(peer_crypto_params, vdev_crypto_params,sizeof(struct wlan_crypto_params));
        ni->ni_capinfo |= IEEE80211_CAPINFO_PRIVACY;
    }
    /* Set the node htcap to be same as ic htcap */
    ni->ni_htcap = ic->ic_htcap;
    IEEE80211_ADD_NODE_TARGET(ni, ni->ni_vap, 1);

    if (!wlan_vap_get_bss_rsp_evt_status(vap) ||
        !wlan_vap_is_bss_created(vap)) {
        qdf_err("BSS peer creation is not complete: %d:%d",
                vap->iv_bss_rsp_evt_status, vap->iv_bss_rsp_status);
        return -1;
    }

    return ieee80211_sta_join_bss(ni);
}

/*
 * Handle a station leaving an 11g network.
 */
void
ieee80211_node_leave_11g(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    bool update_beacon = false;

    KASSERT((IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan)
             || IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)
             || IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan)),
            ("not in 11g, bss %u:0x%llx, curmode %u", vap->iv_bsschan->ic_freq,
             vap->iv_bsschan->ic_flags, ic->ic_curmode));

    KASSERT((ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP ||
             ni->ni_vap->iv_opmode == IEEE80211_M_BTAMP ||
             ni->ni_vap->iv_opmode == IEEE80211_M_IBSS), (" node leave in invalid opmode "));

    /*
     * If a long slot station do the slot time bookkeeping.
     */
    if ((ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME) == 0) {
        if (ic->ic_longslotsta) {
           ic->ic_longslotsta--;
           IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "long slot time station leaves, count now %d\n",
                       ic->ic_longslotsta);
        } else {
           IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                "bogus long slot station count %d", ic->ic_longslotsta);
        }

        if (ic->ic_longslotsta == 0) {
            /*
             * Re-enable use of short slot time if supported
             * and not operating in IBSS mode (per spec).
             */
            if (ic->ic_caps & IEEE80211_C_SHSLOT) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                                  "%s: re-enable use of short slot time\n",
                                  __func__);
                ieee80211_set_shortslottime(ic, 1);
                wlan_pdev_beacon_update(ic);
            }
        }
    }

    /*
     * If a non-ERP station do the protection-related bookkeeping.
     */
    if (((ni->ni_flags & IEEE80211_NODE_ERP) == 0) && (ic->ic_nonerpsta > 0)) {
        KASSERT(ic->ic_nonerpsta > 0, ("bogus non-ERP station count %d", ic->ic_nonerpsta));
        ic->ic_nonerpsta--;
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "non-ERP station leaves, count now %d", ic->ic_nonerpsta);
        if (ic->ic_nonerpsta == 0) {
            struct ieee80211vap *tmpvap;
            ieee80211_update_erp_info(vap);
            /* XXX verify mode? */
            if (ic->ic_caps & IEEE80211_C_SHPREAMBLE) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                                  "%s: re-enable use of short preamble\n",
                                  __func__);
                ieee80211com_set_flags(ic, IEEE80211_F_SHPREAMBLE);
                ieee80211com_clear_flags(ic, IEEE80211_F_USEBARKER);
            }

            TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
                ieee80211_vap_erpupdate_set(tmpvap);

            update_beacon = true;
        }
    }

    /* Trigger beacon template update */
    if (update_beacon == true)
        wlan_vdev_beacon_update(vap);
}

#if MESH_MODE_SUPPORT
static int
ieee80211_clear_scanentry_mesh_flags(void *arg, wlan_scan_entry_t scan_entry);
static int
ieee80211_clear_scanentry_mesh_flags(void *arg, wlan_scan_entry_t scan_entry)
{
#if NOT_YET_MESH_PEER_SUPPORT
    int flags = 0;
    flags = wlan_scan_entry_get_flags(scan_entry);
    flags &= ~IEEE80211_SE_FLAG_IS_MESH;
    flags &= ~IEEE80211_SE_FLAG_INTERSECT_DONE;
    wlan_scan_entry_set_flags(scan_entry, flags);
#endif
    return EOK;
}
#endif

#if WLAN_OBJMGR_REF_ID_TRACE
bool ieee80211_node_leave_debug(struct ieee80211_node *ni, const char *func, int line, const char *file)
#else
bool _ieee80211_node_leave(struct ieee80211_node *ni)
#endif
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    bool   retval = false;
    bool dup_leave = false;
    bool update_pdev_beacon = false;
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
#endif

    IEEE80211_NOTE(vap, IEEE80211_MSG_AUTH | IEEE80211_MSG_ASSOC | IEEE80211_MSG_DEBUG,
            ni, "%s: station with aid %d leaves (refcnt %u) \n", __func__,
            IEEE80211_NODE_AID(ni), ieee80211_node_refcnt(ni));

    IEEE80211_NODE_STATE_LOCK_BH(ni);
    /* If node leave is already started, return. */
    if (ieee80211node_has_flag(ni, IEEE80211_NODE_LEAVE_ONGOING))
        dup_leave = true;
    else
        ieee80211node_set_flag(ni, IEEE80211_NODE_LEAVE_ONGOING);
    IEEE80211_NODE_STATE_UNLOCK_BH(ni);

  if (dup_leave) {
      IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC | IEEE80211_MSG_DEBUG, ni,
              "dup_leave for %s\n", ether_sprintf(ni->ni_macaddr));
      return 1;
  }

    if(ni->ni_node_esc == true) {
        ni->ni_node_esc = false;
        vap->iv_ic->ic_auth_tx_xretry--;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s: ni = 0x%pK ni->ni_macaddr = %s ic_auth_tx_xretry = %d\n",
                __func__, ni, ether_sprintf(ni->ni_macaddr), vap->iv_ic->ic_auth_tx_xretry);
    }
#ifdef ATH_SWRETRY
    if (ic->ic_reset_pause_tid)
        ic->ic_reset_pause_tid(ni->ni_ic, ni);
#endif

    KASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP
            || vap->iv_opmode == IEEE80211_M_WDS ||
            vap->iv_opmode == IEEE80211_M_BTAMP  ||
            vap->iv_opmode == IEEE80211_M_IBSS   ||
            vap->iv_opmode == IEEE80211_M_STA,
            ("unexpected operating mode %u", vap->iv_opmode));

    /*
     * If node wasn't previously associated all
     * we need to do is reclaim the reference.
     */
    /* XXX ibss mode bypasses 11g and notification */

    IEEE80211_NODE_STATE_LOCK_BH(ni);

    /*
     * Prevent _ieee80211_node_leave() from reentry which would mess up the
     * value of iv_sta_assoc. Before AP received the tx ack for "disassoc
     * request", it may have received the "auth (not SUCCESS status)" to do
     * node leave. With the flag, follow-up cleanup wouldn't call
     * _ieee80211_node_leave() again when execuating the tx_complete handler.
     */
    ieee80211node_set_flag(ni, IEEE80211_NODE_LEAVE_ONGOING);
#if MESH_MODE_SUPPORT
    if (ni->ni_ext_flags&IEEE80211_LOCAL_MESH_PEER) {
        util_wlan_scan_db_iterate_macaddr(vap, ni->ni_macaddr,
                (scan_iterator_func)ieee80211_clear_scanentry_mesh_flags, NULL);
    }
#endif

    if (ni->ni_associd) {
        if (vap->iv_sta_assoc > 0) {
            IEEE80211_VAP_LOCK(vap);
            vap->iv_sta_assoc--;
            if (ni->ni_ext_flags & IEEE80211_NODE_HE && vap->iv_ax_sta_assoc > 0) {
                    vap->iv_ax_sta_assoc--;
                    if (vap->iv_ax_sta_assoc == vap->iv_sta_assoc &&
                        ic->ic_muedca_mode_state == HEMUEDCA_HOST_DYNAMIC_MODE)
                        vap->iv_muedcastate.mu_edca_dynamic_state &=
                                ~MUEDCA_DYNAMIC_ALGO_UPDATE_STATE_MASK;
            }
            IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                              "%s, STA left,  decremented iv_sta_assoc(%hu)",
                              __func__,vap->iv_sta_assoc);

            if (ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE) {
                vap->iv_mu_bformee_sta_assoc--;
                /* update extended bss load element in beacon */
                ieee80211_vap_ext_bssload_update_set(vap);
            }
            if (HECAP_PHY_SUBFME_GET_FROM_IC(ni->ni_he.hecap_phyinfo))
                vap->iv_he_su_bformee_sta_assoc--;

            IEEE80211_VAP_UNLOCK(vap);
        }
        else {
            qdf_nofl_info("WARNING:ic=%s,vap=%d,vap->iv_sta_assoc getting decremented below zero"
                "vap->iv_sta_assoc %d,ic->ic_sta_assoc %d,(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                ic->ic_netdev->name, vap->iv_unit, vap->iv_sta_assoc, ic->ic_sta_assoc,
                ni->ni_macaddr[0], ni->ni_macaddr[1],
                ni->ni_macaddr[2],ni->ni_macaddr[3],
                ni->ni_macaddr[4],ni->ni_macaddr[5]);
        }

        if(son_has_whc_apinfo_flag(ni->peer_obj, IEEE80211_NODE_WHC_APINFO_SON)) {
            son_clear_whc_apinfo_flag(ni->peer_obj, IEEE80211_NODE_WHC_APINFO_SON);
            son_repeater_cnt_dec(vap->vdev_obj);
            son_update_bss_ie(vap->vdev_obj);
            son_pdev_appie_update(ic);
            update_pdev_beacon = true;
        }

        IEEE80211_COMM_LOCK(ic);
        ic->ic_sta_assoc--;
        /* Update bss load element in beacon */
        ieee80211_vap_qbssload_update_set(vap);

        if (IEEE80211_NODE_USE_HT(ni)) {
            ic->ic_ht_sta_assoc--;
            if (ni->ni_htcap & IEEE80211_HTCAP_C_GREENFIELD) {
                ASSERT(ic->ic_ht_gf_sta_assoc > 0);
                ic->ic_ht_gf_sta_assoc--;
            }
#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
            iee80211_txbf_loforce_check(ni,0);
#endif
            if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40) || (ni->ni_chwidth == IEEE80211_CWM_WIDTH80) || (ni->ni_chwidth == IEEE80211_CWM_WIDTH160))
	      ic->ic_ht40_sta_assoc--;
	  }

#if DBDC_REPEATER_SUPPORT
        if (ni->is_extender_client == 1) {
            GLOBAL_IC_LOCK_BH(ic_list);
            ic_list->num_rptr_clients--;
            GLOBAL_IC_UNLOCK_BH(ic_list);
            ni->is_extender_client = 0;
        }
#endif

        /* 11AX TODO (Phase II) - Below likely to be required for 11ax as well.
         * Hence, we have added a check for AXG. However, reconfirm based on
         * latest draft.
         */
        if (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan))
            ieee80211_node_leave_11g(ni);

        /* For beacon offload targets, the beacon need to updated in FW */
        if (IEEE80211_IS_CHAN_11N(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AX(vap->iv_bsschan)) {
            if (IEEE80211_IS_HTPROT_ENABLED(ic) &&
                (ic->ic_sta_assoc == ic->ic_ht_sta_assoc)) {
                    update_pdev_beacon = true;
                    IEEE80211_DISABLE_HTPROT(ic);
            }
        }

        ieee80211_admctl_node_leave(vap, ni);

#if DYNAMIC_BEACON_SUPPORT
        /* if no sta associated then cancel the timer and suspend the beacon */
        if (vap->iv_sta_assoc == 0 && vap->iv_dbeacon == 1 && vap->iv_dbeacon_runtime == 1) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Node leave, Suspend beacon \n");
            qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
            OS_CANCEL_TIMER(&vap->iv_dbeacon_suspend_beacon);
            if (!ieee80211_mlme_beacon_suspend_state(vap)) {
                ieee80211_mlme_set_beacon_suspend_state(vap, true);
            }
            qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
        }
#endif

        /*
         * Cleanup station state.  In particular clear various state that
         * might otherwise be reused if the node is reused before the
         * reference count goes to zero (and memory is reclaimed).
         *
         * If ni is not in node table, it has been reclaimed in another thread.
         */
#if QCA_AIRTIME_FAIRNESS
        wlan_atf_peer_join_leave(ni->peer_obj, 0);
#endif // QCA_AIRTIME_FAIRNESS
        if ((vap->watermark_threshold_flag == false) && (ic->ic_sta_assoc < vap->watermark_threshold)) {
                vap->watermark_threshold_flag = true;
            }
#ifdef MU_CAP_WAR_ENABLED
        ieee80211_mu_cap_client_join_leave(ni,0);
#endif
        retval = ieee80211_sta_leave(ni);
        OS_FREE (ni->ni_noise_stats);
        IEEE80211_COMM_UNLOCK(ic);
        IEEE80211_NODE_STATE_UNLOCK_BH(ni);
        IEEE80211_DELETE_NODE_TARGET(ni, ic, vap, 0);
    } else {
        ieee80211_admctl_node_leave(vap, ni);
#ifdef MU_CAP_WAR_ENABLED
        ieee80211_mu_cap_client_join_leave(ni,0);
#endif
        retval = ieee80211_sta_leave(ni);
        IEEE80211_NODE_STATE_UNLOCK_BH(ni);
    }

    /* 11AX TODO: Recheck future 802.11ax drafts (>D1.0) on coex rules */
    if (((ni->ni_flags & IEEE80211_NODE_HT || IEEE80211_NODE_USE_HE(ni)) &&
         (ni->ni_flags & IEEE80211_NODE_40MHZ_INTOLERANT)) &&
          ni->ni_set_40mhz_intol_bw) {
         ieee80211_change_cw(ic);
    }
    if (ieee80211_vap_ext_bssload_is_set(vap) &&
        ieee80211_vap_ext_bssload_update_is_set(vap))
        wlan_vdev_beacon_update(vap);

    if (update_pdev_beacon) {
        wlan_pdev_beacon_update(ic);
    }

    return retval;
}


/*
 * Handle a station joining an 11g network.
 */
static void
ieee80211_node_join_11g(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    bool update_beacon = false;

    KASSERT((IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan)),
            ("not in 11g, bss %u:0x%llx, curmode %u", vap->iv_bsschan->ic_freq,
             vap->iv_bsschan->ic_flags, ic->ic_curmode));

    KASSERT((ni->ni_vap->iv_opmode == IEEE80211_M_HOSTAP ||
             ni->ni_vap->iv_opmode == IEEE80211_M_BTAMP  ||
             ni->ni_vap->iv_opmode == IEEE80211_M_IBSS), (" node join in invalid opmode "));
    /*
     * Station isn't capable of short slot time.  Bump
     * the count of long slot time stations and disable
     * use of short slot time.  Note that the actual switch
     * over to long slot time use may not occur until the
     * next beacon transmission (per sec. 7.3.1.4 of 11g).
     */
    if (ieee80211_is_phymode_11b(ni->ni_phymode) ||
        ((ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_SLOTTIME) == 0)) {
        ic->ic_longslotsta++;
        IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ASSOC, ni,
                       "station needs long slot time, count %d",
                       ic->ic_longslotsta);
        /* XXX vap's w/ conflicting needs won't work */
        if (!IEEE80211_IS_CHAN_108G(vap->iv_bsschan)) {
            /*
             * Don't force slot time when switched to turbo
             * mode as non-ERP stations won't be present; this
             * need only be done when on the normal G channel.
             */
            ieee80211_set_shortslottime(ic, 0);
            wlan_pdev_beacon_update(ic);
        }
    }
    /*
     * If the new station is not an ERP station
     * then bump the counter and enable protection
     * if configured.
     */
    if (!ieee80211_iserp_rateset(ic, &ni->ni_rates)) {
        ic->ic_nonerpsta++;
        IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ASSOC, ni,
                       "station is !ERP, %d non-ERP stations associated\n",
                       ic->ic_nonerpsta);
            /*
             * If protection is configured, enable it.
             */
            if (ic->ic_protmode != IEEE80211_PROT_NONE) {
                IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ASSOC,
                                  "%s: enable use of protection\n", __func__);
                ieee80211com_set_flags(ic, IEEE80211_F_USEPROT);
                ieee80211_set_protmode(ic);
            }
            /*
             * If station does not support short preamble
             * then we must enable use of Barker preamble.
             */
            if ((ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) == 0) {
                IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_ASSOC, ni,
                               "%s", "station needs long preamble");
                ieee80211com_set_flags(ic, IEEE80211_F_USEBARKER);
                ieee80211com_clear_flags(ic, IEEE80211_F_SHPREAMBLE);
            }

            /* Update ERP element if this is first non ERP station */
            if (ic->ic_nonerpsta == 1) {
	          struct ieee80211vap *tmpvap;
	          TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
		    ieee80211_vap_erpupdate_set(tmpvap);
	    }
            update_beacon = true;
    } else
        ieee80211node_set_flag(ni, IEEE80211_NODE_ERP);

    /* Trigger beacon template update */
    if (update_beacon == true)
        wlan_vdev_beacon_update(vap);

}

/*
 * function to handle station joining infrastructure network.
 * used for AP mode vap only.
 */
int ieee80211_node_join(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
#if WLAN_SUPPORT_SPLITMAC
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
#endif
    bool   is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE);
    uint16_t vap_assoc_limit;

    IEEE80211_NODE_STATE_LOCK(ni);

    /*
     * iv_max_aid represents the size of the AID bitmap. For MBSSID/EMA this
     * does not always imply the actual number of clients allowed due to
     * reserved AIDs. Additionally, for MBSSID/EMA, use per-VAP AID limit
     * instead of the global AID limit.
     */
    vap_assoc_limit = is_mbssid_enabled ?
                       (vap->iv_mbss_max_aid-(1 << ic->ic_mbss.max_bssid)-1) :
                       (vap->iv_max_aid-1);

#if WLAN_SUPPORT_SPLITMAC
    /*
     * In splitmac mode, the AID is assigned before the call to
     * ieee80211_node_join.
     */
    if ((splitmac_is_enabled(vdev) && (ni->ni_associd != 0)) ||
        (!splitmac_is_enabled(vdev) && (ni->ni_associd == 0))) {
#else
    if (ni->ni_associd == 0) {
#endif
        u_int16_t aid;

        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "%s: Number of associated STAs: %hu",
                       __func__, vap->iv_sta_assoc);

#if QCA_AIRTIME_FAIRNESS
        if (!wlan_atf_peer_association_allowed(ic->ic_pdev_obj)) {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                  "%s: Per radio Associated STA limit reached!",
                                __func__);
            IEEE80211_NODE_STATE_UNLOCK(ni);
            return -1; /* per radio soft client limit reached */
        }
#endif

        if(ic->ic_sta_assoc >= ic->ic_num_clients) {
          IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                         "%s: Per radio Associated STA limit reached!",
                         __func__);

#ifdef QCA_SUPPORT_CP_STATS
          vdev_cp_stats_sta_xceed_rlim_inc(vap->vdev_obj, 1);
#endif
          IEEE80211_NODE_STATE_UNLOCK(ni);
          return -1; /* Per radio soft client limit reached */
        }

        if (vap->iv_sta_assoc >= vap_assoc_limit) {
          IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                         "%s: Associated STA limit reached!",
                         __func__);

#ifdef QCA_SUPPORT_CP_STATS
          vdev_cp_stats_sta_xceed_vlim_inc(vap->vdev_obj, 1);
#endif
          IEEE80211_NODE_STATE_UNLOCK(ni);
          return -1; /* soft client limit reached */
        }

        if (vap->iv_aid_bitmap == NULL) {
            IEEE80211_NODE_STATE_UNLOCK(ni);
            return -1; /* vap is being deleted */
        }

#if WLAN_SUPPORT_SPLITMAC
        /* AID will come from the mac above us */
        if (splitmac_is_enabled(vdev)) {
          goto skip_aid;
        }
#endif

        /*
         * It would be good to search the bitmap
         * more efficiently, but this will do for now.
         */
        if (is_mbssid_enabled) {
            aid = (1 << ic->ic_mbss.max_bssid);
        } else {
            aid = 1;
        }

        for (; aid < vap->iv_max_aid; aid++)
        {
            if (!IEEE80211_AID_ISSET(vap, aid))
                break;
        }

        if (aid >= vap->iv_max_aid) {
            /*
             * Keep stats on this situation.
             */
            IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni, "aid (%d)"
                    " greater than max aid (%d)", aid,
                    vap->iv_max_aid);
            IEEE80211_NODE_STATE_UNLOCK(ni);
            IEEE80211_NODE_LEAVE(ni);
            return -1;
        }
#if ATH_SUPPORT_MBO
        if (ieee80211_vap_mbo_check(vap) && ieee80211_vap_mbo_assoc_status(vap)) {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni, "MBO association disallowed");
            IEEE80211_NODE_STATE_UNLOCK(ni);
            ieee80211_try_mark_node_for_delayed_cleanup(ni);
            return -1;
        }
#endif
        if (ieee80211_vap_oce_check(vap) && ieee80211_vap_oce_assoc_reject(vap, ni)) {
            IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                           "OCE association rejected due to low RSSI %d",
                           ni->ni_snr);
            IEEE80211_NODE_STATE_UNLOCK(ni);
            ieee80211_try_mark_node_for_delayed_cleanup(ni);
            return -1;
        }

        if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            son_vdev_fext_capablity(vap->vdev_obj,
                                    SON_CAP_GET,
                                    WLAN_VDEV_FEXT_SON_SPL_RPT)) {
            if (!son_get_whc_rept_info(ni->peer_obj)) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni, "WHC "
                                  "AP Rept Special mode - association disallowed");
                IEEE80211_NODE_STATE_UNLOCK(ni);
                ieee80211_try_mark_node_for_delayed_cleanup(ni);
                return -1;
            }
        } else {
            if (son_get_whc_rept_info(ni->peer_obj)) {
                IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni, "WHC "
                                  "STA Rept Special mode - association disallowed");
                IEEE80211_NODE_STATE_UNLOCK(ni);
                ieee80211_try_mark_node_for_delayed_cleanup(ni);
                return -1;
            }
        }

        ni->ni_associd = aid | 0xc000;
        IEEE80211_AID_SET(vap, ni->ni_associd);

#if WLAN_SUPPORT_SPLITMAC
skip_aid:
#endif

        IEEE80211_VAP_LOCK(vap);
        vap->iv_sta_assoc++;
        if (ni->ni_ext_flags & IEEE80211_NODE_HE) {
            vap->iv_ax_sta_assoc++;
            if (ic->ic_muedca_mode_state == HEMUEDCA_HOST_DYNAMIC_MODE &&
                vap->iv_ax_sta_assoc == vap->iv_sta_assoc ) {
                vap->iv_muedcastate.mu_edca_dynamic_state &=
                ~MUEDCA_DYNAMIC_ALGO_UPDATE_STATE_MASK;
            }
        }
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "%s: STA joined, incremented iv_sta_assoc(%hu)",
                       __func__, vap->iv_sta_assoc);

        if (ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE) {
            vap->iv_mu_bformee_sta_assoc++;
            /* update extended bss load element in beacon */
            ieee80211_vap_ext_bssload_update_set(vap);
        }
        if (HECAP_PHY_SUBFME_GET_FROM_IC(ni->ni_he.hecap_phyinfo))
            vap->iv_he_su_bformee_sta_assoc++;

        IEEE80211_VAP_UNLOCK(vap);

        /* Update bss load element in beacon */
        ieee80211_vap_qbssload_update_set(vap);

        /* 11AX : Recheck future 802.11ax drafts (>D1.0) on coex rules */
        if ((ni->ni_flags & IEEE80211_NODE_HT || IEEE80211_NODE_USE_HE(ni)) &&
                (ni->ni_flags & IEEE80211_NODE_40MHZ_INTOLERANT)) {
            /* If RSSI greater than/equal threshold then only do CW change */
            if (ni->ni_snr >= ic->obss_rx_snr_threshold) {
                ni->ni_set_40mhz_intol_bw = 1;
                ieee80211_change_cw(ic);
            } else {
                ni->ni_set_40mhz_intol_bw = 0;
            }
        }
        if (vap->vdev_mlme->mgmt.generic.ampdu != 0) {
            ieee80211node_clear_flag(ni, IEEE80211_NODE_NOAMPDU);
        }
        else {
            ieee80211node_set_flag(ni, IEEE80211_NODE_NOAMPDU);
        }

        IEEE80211_COMM_LOCK(ic);
#ifdef MU_CAP_WAR_ENABLED
        ieee80211_mu_cap_client_join_leave(ni,1);
#endif
#if QCA_AIRTIME_FAIRNESS
        wlan_atf_peer_join_leave(ni->peer_obj, 1);
#endif /* QCA_AIRTIME_FAIRNESS */
        ni->ni_noise_stats = (struct noise_stats *)OS_MALLOC(ic->ic_osdev,ic->traf_bins*sizeof(struct noise_stats),GFP_KERNEL);
        if (ni->ni_noise_stats == NULL) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,"%s: ni_noise_stats is null\n",__func__);
        }
        ic->ic_sta_assoc++;
        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC, ni,
                       "%s: STA joined, incremented iv_sta_assoc(%hu), "
                       "ic_sta_assoc=%d, peer count=%hu",
                       __func__, vap->iv_sta_assoc,
                       ic->ic_sta_assoc,
                       wlan_vdev_get_peer_count(vap->vdev_obj));

        if (ic->ic_sta_assoc >= vap->watermark_threshold)
        {
            if (vap->watermark_threshold_flag == true) {
                vap->watermark_threshold_reached++;
                vap->watermark_threshold_flag = false ;

            }
            if (ic->ic_sta_assoc >= vap->assoc_high_watermark) {
                vap->assoc_high_watermark = ic->ic_sta_assoc;
                vap->assoc_high_watermark_time = OS_GET_TIMESTAMP();
            }
        }
        if (IEEE80211_NODE_USE_HT(ni)) {
            ic->ic_ht_sta_assoc++;
            if (ni->ni_htcap & IEEE80211_HTCAP_C_GREENFIELD)
                ic->ic_ht_gf_sta_assoc++;
#if ATH_TxBF_DYNAMIC_LOF_ON_N_CHAIN_MASK
             iee80211_txbf_loforce_check(ni,1);
#endif
             if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH40 ) || (ni->ni_chwidth == IEEE80211_CWM_WIDTH80) || (ni->ni_chwidth == IEEE80211_CWM_WIDTH160)) {
                  ic->ic_ht40_sta_assoc++;
      	    }
	  }


        /* 11AX TODO (Phase II) - Below likely to be required for 11ax as well.
         * Hence, we have added a check for AXG. However, reconfirm based on
         * latest draft.
         */
        if (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan))
            ieee80211_node_join_11g(ni);

        /* For beacon offload targets, the beacon need to updated in FW */
        if (IEEE80211_IS_CHAN_11N(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
            IEEE80211_IS_CHAN_11AX(vap->iv_bsschan)) {
            if (!IEEE80211_IS_HTPROT_ENABLED(ic) &&
                (ic->ic_sta_assoc > ic->ic_ht_sta_assoc)) {
                    wlan_pdev_beacon_update(ic);
                    IEEE80211_ENABLE_HTPROT(ic);
            }
        }

        IEEE80211_COMM_UNLOCK(ic);
    }
    ni->ni_inact_reload = ni->ni_vap->iv_inact_auth;
    ni->ni_inact = ni->ni_inact_reload;

    if (ieee80211_vap_ext_bssload_is_set(vap) &&
        ieee80211_vap_ext_bssload_update_is_set(vap))
        wlan_vdev_beacon_update(vap);

    IEEE80211_NODE_STATE_UNLOCK(ni);
    IEEE80211_ADD_NODE_TARGET(ni, ni->ni_vap, 0);
	return 0;
}

/*
 * Craft a temporary node suitable for sending a management frame
 * to the specified station.  We craft only as much state as we
 * need to do the work since the node will be immediately reclaimed
 * once the send completes, and the temporary node will NOT be put
 * into node table.
 */
struct ieee80211_node *
ieee80211_tmp_node(struct ieee80211vap *vap, const u_int8_t *macaddr)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni;

    if(!(IEEE80211_ADDR_IS_VALID(macaddr))){
        qdf_nofl_info("INVALID MAC ADDRESS \n");
        return NULL;
    }

    /*
     * if vap is being deleted, do not allow new allocations.
     */
    if (ieee80211_vap_deleted_is_set(vap)) {
        return NULL;
    }
    /* Allocate TEMP peer object */
    ni = wlan_objmgr_alloc_tmp_node(vap, (uint8_t *)macaddr);
    if (ni == NULL) {
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_node_alloc_inc(vap->vdev_obj, 1);
#endif
        return NULL;
    }

#if IEEE80211_DEBUG_NODELEAK
    do {
        rwlock_state_t lock_state;
        OS_RWLOCK_WRITE_LOCK(&ic->ic_nodelock,&lock_state);
        TAILQ_INSERT_TAIL(&ic->ic_nodes, ni, ni_alloc_list);
        OS_RWLOCK_WRITE_UNLOCK(&ic->ic_nodelock,&lock_state);
    } while(0);
#endif
    ieee80211node_set_flag(ni, IEEE80211_NODE_TEMP); /* useful for debugging */

    ni->ni_bss_node = ieee80211_try_ref_bss_node(vap, WLAN_MLME_OBJMGR_ID);
    if (!ni->ni_bss_node) {
        wlan_objmgr_delete_node(ni);
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_node_alloc_dec(vap->vdev_obj, 1);
#endif
        return NULL;
    }
    ni->ni_vap = vap;
    ni->ni_ic = ic;
    ni->ni_table = NULL;
    ni->ni_persta = NULL;

    /* copy some default variables from parent */
    IEEE80211_ADDR_COPY(ni->ni_macaddr, macaddr);
    ni->ni_intval = ic->ic_intval; /* default beacon interval */

    /* set default rate and channel */
    ieee80211_node_set_chan(ni);

    ni->ni_txpower = ic->ic_txpowlimit;	/* max power */

#if 0
    /* in case of temp node we don't need ni_persta keys
     * to be allocated even for IBSS mode.
     */
    {
        int i;
        ieee80211_crypto_resetkey(vap, &ni->ni_persta->nips_hwkey, IEEE80211_KEYIX_NONE);
        for (i = 0; i < IEEE80211_WEP_NKID; i++) {
            ieee80211_crypto_resetkey(vap, &ni->ni_persta->nips_swkey[i], IEEE80211_KEYIX_NONE);
        }
    }
#endif
    ni->ni_ath_defkeyindex = IEEE80211_INVAL_DEFKEY;

    /* 11n  or 11ac */
    ni->ni_chwidth = ic->ic_cwm_get_width(ic);

    IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_bss->ni_bssid);


    return ni;
}

int wlan_add_sta_node(wlan_if_t vap, const u_int8_t *macaddr, u_int16_t auth_alg)
{
    struct ieee80211_node *ni;

    ni = ieee80211_vap_find_node(vap, macaddr, WLAN_MLME_OBJMGR_ID);
    if (ni == NULL) {
        ni = ieee80211_dup_bss(vap, macaddr);
        if(ni != NULL) {
           wlan_node_set_peer_state(ni, WLAN_AUTH_STATE);
        }
    }

    if (ni == NULL) {
        return -ENOMEM;
    }
    /* claim node immediately */
    ieee80211_free_node(ni, WLAN_MLME_OBJMGR_ID);
    return 0;
}

