/*
 * Copyright (c) 2011-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * 2008 Atheros Communications Inc.
 * All Rights Reserved.
 *
 */

#include <wlan_cmn.h>
#include <qdf_status.h>
#include <reg_services_public_struct.h>
#include <ieee80211_regdmn_dispatcher.h>
#include <osdep.h>
#include "ieee80211_mlme_dfs_dispatcher.h"
#include <ieee80211_mbo.h>
#include <ieee80211_var.h>
#include <ieee80211_proto.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include "ieee80211_mlme_priv.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"
#include "ieee80211_ucfg.h"
#include "ieee80211_sme_api.h"
#include <wlan_son_pub.h>
#include <wlan_utility.h>
#include <wlan_rnr.h>
#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"
#include <wlan_vdev_mlme.h>
#include "ol_if_athvar.h"
#include "cfg_ucfg_api.h"
#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_utils_api.h>
#endif

#ifndef NUM_MILLISEC_PER_SEC
#define NUM_MILLISEC_PER_SEC 1000
#endif
/*
 *  XXX: Because OID_DOT11_ENUM_BSS_LIST is queried every 30 seconds,
 *       set the interval of Beacon Store to 30.
 *       This is to make sure the AP(GO)'s own scan_entry always exsits in the scan table.
 *       This is a workaround, a better solution is to add reference counter,
 *       to prevent its own scan_entry been flushed out.
 */
#define INTERVAL_STORE_BEACON 30

#define IEEE80211_TSF_LEN       (8)
/*
 *  XXX: Include an intra-module function from ieee80211_input.c.
 *       When we move regdomain code out to separate .h/.c files
 *       this should go to that .h file.
 */

int ieee80211_check_and_add_tx_cmn_ie(struct ieee80211vap *vap, uint8_t *old_frm,
                                        uint8_t **frm, int32_t *remaining_space,
                                        ieee80211_frame_type ftype);

/*
 * ieee80211_add_rsn_ie: Add RSN IE in the frame
 *
 * @vap : VAP handle
 * @frm : frm pointer to add the IE
 * @bo  : Beacon offsets to mark IEs' start address
 *
 * Return: frm pointer after adding, if RSN IE is added,
 *         NULL elsewhere
 */
static inline uint8_t *ieee80211_add_rsn_ie(struct ieee80211vap *vap,
        uint8_t *frm, struct ieee80211_beacon_offsets **bo)
{
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RSN, -1, &frm,
                TYPE_ALL_BUF, NULL, true)) {

            /* Add RSN IE if not present */
#if ATH_SUPPORT_HS20
            if (!vap->iv_osen) {
#endif

                if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                            (1 << WLAN_CRYPTO_AUTH_RSNA))) {
                    frm = wlan_crypto_build_rsnie(vap->vdev_obj, frm, NULL);
                    if(!frm) {
                        (*bo)->bo_rsn = NULL;
                        return NULL;
                    }
                }

#if ATH_SUPPORT_HS20
            } else {
                (*bo)->bo_rsn = NULL;
            }
#endif
        }
    return frm;
}

/*
 * ieee80211_add_vht_ies: Add VHT cap, op, power envelope, channel switch
 *                        wrapper, and EBSS load IEs in the frame
 *
 * @ni  : Node information handle
 * @frm : frm pointer to add IEs
 * @bo  : Beacon offsets to mark IEs' start address
 *
 * Return: frm pointer after adding IEs
 */
static inline uint8_t *ieee80211_add_vht_ies(struct ieee80211_node *ni,
        uint8_t *frm, struct ieee80211_beacon_offsets **bo)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;

    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap)) {
        /* 57. VHT Capabilities */
        (*bo)->bo_vhtcap = frm;
        frm = ieee80211_add_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL, NULL);
        if (ieee80211_check_driver_tx_cmn_ie(vap, (*bo)->bo_vhtcap, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return NULL;

        /* 58. VHT Operation */
        (*bo)->bo_vhtop = frm;
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL);
        if (ieee80211_check_driver_tx_cmn_ie(vap, (*bo)->bo_vhtop, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return NULL;

        /* 59. Transmit Power Envelope element */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            (*bo)->bo_vhttxpwr = frm;
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic,
                                        IEEE80211_FC0_SUBTYPE_BEACON,
                                        !IEEE80211_TPE_IS_SUB_ELEMENT);
            if (ieee80211_check_driver_tx_cmn_ie(vap, (*bo)->bo_vhttxpwr, &frm,
                        &vap->iv_available_bcn_cmn_space,
                        IEEE80211_FRAME_TYPE_BEACON))
                return NULL;

            /* 60. Channel Switch Wrapper */
            (*bo)->bo_vhtchnsw = frm;
        } else {
            (*bo)->bo_vhttxpwr = NULL;
            (*bo)->bo_vhtchnsw = NULL;
        }

        /* 61. Extended BSS Load element */
        frm = ieee80211_ext_bssload_beacon_setup(vap, ni, *bo, frm);
        if (ieee80211_check_driver_tx_cmn_ie(vap, (*bo)->bo_ext_bssload, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return NULL;

    } else {
        (*bo)->bo_vhtcap = NULL;
        (*bo)->bo_vhtop = NULL;
        (*bo)->bo_vhttxpwr = NULL;
        (*bo)->bo_vhtchnsw = NULL;
        (*bo)->bo_ext_bssload = NULL;
    }
    return frm;
}

#if QCA_SUPPORT_EMA_EXT
/*
 * ieee80211_beacon_adjust_bos_for_context: Put back MBSSID/RNR IE in its position,
 *                                            move other IEs, and adjust bo's
 *
 * @ic  : Common state handle
 * @frm : frm pointer to add IEs
 * @bo  : Beacon offsets to be adjusted
 * @offset          : Length of MBSSID/RNR IE
 * @offset_context  : Context (MBSSID/RNR IE)
 *
 * Return: frm pointer after the put-back of context
 */
static uint8_t *ieee80211_beacon_adjust_bos_for_context(
        struct ieee80211com* ic,
        uint8_t *frm,
        struct ieee80211_beacon_offsets *bo,
        uint16_t offset,
        ieee80211_ie_offset_context_t offset_context)
{
    uint16_t ie_trailer_len = 0;

    /* If incoming IE offset is bigger than the buffer size,
     * silently ignore the IE without offset adjustments
     */
    if (offset > IEEE80211_EMA_TEMP_MBSS_BUFFER_SIZE)
        return frm;

    qdf_mem_zero(ic->ic_mbss.bcn_bo_mbss_ie, sizeof(ic->ic_mbss.bcn_bo_mbss_ie));
    qdf_mem_copy(ic->ic_mbss.bcn_bo_mbss_ie, frm, offset);

    if (offset_context == IEEE80211_IE_OFFSET_CONTEXT_MBSSIE) {
        ie_trailer_len = frm - bo->bo_mbssid_ie;

        /* Adjust the bo's of IEs that appears after MBSSID IE */
        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_rrm, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mob_domain, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_dse_reg_loc, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_ecsa, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_opt_class, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_htcap, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_htinfo, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_2040_coex, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_obss_scan, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_extcap, offset);

#if UMAC_SUPPORT_WNM
        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_fms_desc, offset);
        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_fms_trailer, offset);
#endif /* UMAC_SUPPORT_WNM */

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_qos_traffic, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_time_adv, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_interworking, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_adv_proto, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_roam_consortium, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_emergency_id, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mesh_id, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mesh_conf, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mesh_awake_win, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_beacon_time, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mccaop_adv_ov, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mccaop_adv, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mesh_cs_param, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_qmf_policy, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_qload_rpt, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_hcca_upd_cnt, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_multiband, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_vhtcap, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_vhtop, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_ext_bssload, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_vhttxpwr, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_vhtchnsw, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_quiet_chan, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_opt_mode_note, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_rnr, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_rnr2, offset);
    } else {
        if (bo->bo_rnr) {
            ie_trailer_len = frm - bo->bo_rnr;
        } else if (bo->bo_rnr2) {
            ie_trailer_len = frm - bo->bo_rnr2;
        } else {
            return frm;
        }
    }

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_tvht, offset);

#if QCN_ESP_IE
    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_esp_ie, offset);
#endif /* QCN_ESP_IE */

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_future_chan, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_cag_num, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_fils_ind, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_ap_csn, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_diff_init_lnk, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_service_hint, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_service_hash, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mbssid_config, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_hecap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_heop, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_twt, offset);

#if ATH_SUPPORT_UORA
    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_uora_param, offset);
#endif /* ATH_SUPPORT_UORA */

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_bcca, offset);

#ifdef OBSS_PD
    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_srp_ie, offset);
#endif /* OBSS_PD */

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_muedca, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_ess_rpt, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_ndp_rpt_param, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_he_bss_load, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_he_6g_bandcap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mcst, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_secchanoffset, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_rsnx, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_ath_caps, offset);

#if DBDC_REPEATER_SUPPORT
    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_extender_ie, offset);
#endif /* DBDC_REPEATER_SUPPORT */

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_htinfo_vendor_specific, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_mbo_cap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_apriori_next_channel, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_bwnss_map, offset);

#if QCN_IE
    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_qcn_ie, offset);
#endif /* QCN_IE */

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_xr, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_whc_apinfo, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_interop_vhtcap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_wme, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_software_version_ie, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_generic_vendor_capabilities, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(bo, bo_appie_buf, offset);

    /* Move down the IEs to fit MBSSID/RNR IE */
    if (offset_context == IEEE80211_IE_OFFSET_CONTEXT_MBSSIE) {
        qdf_mem_move(bo->bo_mbssid_ie + offset,
                bo->bo_mbssid_ie, ie_trailer_len);
        qdf_mem_copy(bo->bo_mbssid_ie, ic->ic_mbss.bcn_bo_mbss_ie, offset);
    } else {
        if (bo->bo_rnr) {
            qdf_mem_move(bo->bo_rnr + offset,
                            bo->bo_rnr, ie_trailer_len);
            qdf_mem_copy(bo->bo_rnr, ic->ic_mbss.bcn_bo_mbss_ie, offset);
        } else if (bo->bo_rnr2) {
            qdf_mem_move(bo->bo_rnr2 + offset,
                            bo->bo_rnr2, ie_trailer_len);
            qdf_mem_copy(bo->bo_rnr2, ic->ic_mbss.bcn_bo_mbss_ie, offset);
        }
    }

    frm += offset;
    return frm;
}
#endif

#if QCN_IE
static void
ieee80211_flag_beacon_sent(struct ieee80211vap *vap) {
    struct ieee80211com *ic = vap->iv_ic;
    qdf_hrtimer_data_t *bpr_hrtimer = &vap->bpr_timer;

    /* If there is a beacon to be scheduled within the timer window,
     * drop the response and cancel the timer. If timer is not active,
     * qdf_hrtimer_get_remaining will return a negative value, so the timer
     * expiry will be less than beacon timestamp and timer won't be cancelled.
     * If timer expiry is greater than the beacon timestamp, then timer will
     * be cancelled.
     */

    if (qdf_ktime_to_ns(qdf_ktime_add(qdf_hrtimer_get_remaining(bpr_hrtimer), qdf_ktime_get())) >
        qdf_ktime_to_ns(vap->iv_next_beacon_tstamp) + ic->ic_bcn_latency_comp * QDF_NSEC_PER_MSEC) {

        /* Cancel the timer as beacon is sent instead of a broadcast response */
    if (qdf_hrtimer_cancel(bpr_hrtimer)) {
            vap->iv_bpr_timer_cancel_count++;

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                "Cancel timer: %s| %d | Delay: %d | Current time %lld | Next beacon tstamp: %lld | "
                "beacon interval: %d ms | Timer cb: %d | Enqueued: %d\n", \
                __func__, __LINE__, vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp), \
                ic->ic_intval, qdf_hrtimer_callback_running(bpr_hrtimer), qdf_hrtimer_is_queued(bpr_hrtimer));
        }
    }

    /* Calculate the next beacon timestamp */
    vap->iv_next_beacon_tstamp = qdf_ktime_add_ns(qdf_ktime_get(), ic->ic_intval * QDF_NSEC_PER_MSEC);

}
#endif /* QCN_IE */

static uint8_t *ieee80211_beacon_add_mbss_ie(struct ieee80211_beacon_offsets *bo, uint8_t *frm,
                                        struct ieee80211_node *ni, uint8_t frm_subtype)
{
    /* clear previous contents */
    qdf_mem_zero(frm, bo->bo_mbssid_ie_len);
    bo->bo_mbssid_ie = frm;

    bo->bo_mbssid_ie_len = ieee80211_add_mbss_ie(frm, ni, frm_subtype, 0, NULL);
    return (frm + bo->bo_mbssid_ie_len);
}

/*
 * Delete VAP profile from MBSSID IE
 */
void ieee80211_mbssid_del_profile(struct ieee80211vap *vap)
{
  struct ieee80211com *ic = vap->iv_ic;
  struct ol_ath_vap_net80211 *avn;
  struct ieee80211vap *txvap;

  vap->iv_mbss.mbssid_update_ie = 1;
  ic->ic_vdev_beacon_template_update(vap);

  qdf_atomic_set(&vap->iv_mbss.bcn_ctrl, 0);

  /* re-initiallize probe-response buffer to
   * remove profile
   */

  if (ic->ic_mbss.transmit_vap) {
      txvap = ic->ic_mbss.transmit_vap;
      avn = OL_ATH_VAP_NET80211(ic->ic_mbss.transmit_vap);
      if (avn && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
          /* This function is meant to update Non Tx profile (removal)
           * from beacon/20tu/fils frames. At this point when non Tx vap
           * went down, avn->av_pr_rsp_wbuf is expected to be present. If not,
           * either Tx vap is down and so avn->av_pr_rsp_wbuf is in deferred free
           * list or 20Tu has not been enabled until now.
           */
          if (txvap->iv_he_6g_bcast_prob_rsp && avn->av_pr_rsp_wbuf) {
              avn->av_pr_rsp_wbuf = ieee80211_prb_rsp_alloc_init(txvap->iv_bss,
                  &avn->av_prb_rsp_offsets);
              if (QDF_STATUS_SUCCESS != ic->ic_prb_rsp_tmpl_send(txvap->vdev_obj))
                  qdf_warn("20TU prb rsp send failed");
          }
#ifdef WLAN_SUPPORT_FILS
          if (QDF_STATUS_SUCCESS != ic->ic_fd_tmpl_update(txvap->vdev_obj))
              qdf_debug("FILS template update failed");
#endif
      }
  } else {
      mbss_warn("tx vap is null. Profile for vap id: %d"
                " can not be deleted from probe resonse"
                " buffer", vap->iv_unit);
  }
}

#if OBSS_PD
void ieee80211_sr_ie_reset(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    vap->iv_sr_ie_reset = 1;
    ic->ic_vdev_beacon_template_update(vap);
}
qdf_export_symbol(ieee80211_sr_ie_reset);
#endif /* OBSS PD */

#if QCA_SUPPORT_EMA_EXT
int ieee80211_check_and_add_tx_cmn_ie(struct ieee80211vap *vap, uint8_t *old_frm,
                                        uint8_t **frm, int32_t *remaining_space,
                                        ieee80211_frame_type ftype)
{
    int ie_size = 0;
    int ret = 0;
    uint8_t *iebuf = NULL;

    if (!old_frm || !(*frm))
        goto exit;

    ie_size = *frm - old_frm;

    if (ie_size == 0)
        goto exit;

    /* For beacon, bring-down VAP on VAP UP path, ignore IE otherwise
     * For probe response, ignore IE
     */
    iebuf = old_frm;
    while ((iebuf + 1) < *frm) {
        ie_size = iebuf[1] + 2;
        if (*remaining_space < ie_size) {
            if (ftype == IEEE80211_FRAME_TYPE_BEACON &&
                    vap->iv_vap_up_in_progress) {
                vap->iv_mbss.ie_overflow = true;
                vap->iv_mbss.ie_overflow_stats++;
                ret = -ENOMEM;
                goto exit;
            } else {
                qdf_mem_move(iebuf, iebuf + ie_size, (*frm) - (iebuf + ie_size));
                *frm -= (ie_size);
                continue;
            }
        } else {
            (*remaining_space) -= ie_size;
        }
        iebuf += iebuf[1] + 2;
    }

exit:
    return ret;
}
#endif

static inline int ieee80211_add_tx_ie_from_appie_buffer(struct ieee80211vap *vap,
        ieee80211_frame_type ftype, uint8_t eid_x, uint8_t xtid_x, uint8_t **frm,
        uint8_t **bo_x, int32_t *remaining_space)
{
    int ret = 0;

#if QCA_SUPPORT_EMA_EXT
    *bo_x = *frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, ftype, eid_x,
                xtid_x, frm, TYPE_ALL_BUF, NULL, true)) {
        *bo_x = NULL;
    } else {
        if (ieee80211_check_driver_tx_cmn_ie(vap, *bo_x, frm, remaining_space,
                    ftype))
           ret = -ENOMEM;
    }
#endif

    return ret;
}

static u_int8_t *
ieee80211_beacon_init(struct ieee80211_node *ni, struct ieee80211_beacon_offsets *bo,
                      u_int8_t *frm)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    int enable_htrates;
    struct ieee80211_bwnss_map nssmap;
#if UMAC_SUPPORT_WNM
    u_int8_t *fmsie = NULL;
    u_int32_t fms_counter_mask = 0;
    u_int8_t fmsie_len = 0;
#endif /* UMAC_SUPPORT_WNM */
    enum ieee80211_phymode mode;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
#endif
    struct ieee80211vap *orig_vap;
    struct ieee80211_node *non_transmit_ni = NULL;
    struct ol_ath_vap_net80211 *av;
    uint8_t len = 0;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                                WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    struct ieee80211_ath_tim_ie *tie;
    int32_t available_rnr_space = soc->ema_ap_rnr_field_size_limit;
    uint8_t *temp_bo = NULL;

    orig_vap = vap = ni->ni_vap;

    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        if (!ic->ic_mbss.transmit_vap) {
            return NULL;
        }

        /* We operate on tx vap's beacon buffer */
        vap             = ic->ic_mbss.transmit_vap;
        non_transmit_ni = ni;
        ni              = vap->iv_bss;
    }

    vap->iv_available_bcn_cmn_space = soc->ema_ap_beacon_common_part_size;
    av = OL_ATH_VAP_NET80211(vap);

    mode = wlan_get_desired_phymode(vap);
    if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE)
        rs = &(vap->iv_op_rates[mode]);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    KASSERT(vap->iv_bsschan != IEEE80211_CHAN_ANYC, ("no bss chan"));

    /* ------------- Fixed Fields ------------- */
    /* 1. Timestamp */
    frm += IEEE80211_TSF_LEN; /* Skip TSF field */
    if (IS_MBSSID_EMA_EXT_ENABLED(ic))
        vap->iv_available_bcn_cmn_space -= IEEE80211_TSF_LEN;

    /* 2. Beacon interval */
    *(u_int16_t *)frm = htole16(ieee80211_node_get_beacon_interval(ni));
    frm += 2;
    if (IS_MBSSID_EMA_EXT_ENABLED(ic))
        vap->iv_available_bcn_cmn_space -= 2;

    /* 3. Capability Information */
    ieee80211_add_capability(frm, ni);
    bo->bo_caps = (u_int16_t *)frm;
    frm += 2;
    if (IS_MBSSID_EMA_EXT_ENABLED(ic))
        vap->iv_available_bcn_cmn_space -= 2;

    /* ------------- Regular and Extension IEs ------------- */
    /* 4. Service Set Identifier (SSID) */
    temp_bo = frm;
    *frm++ = IEEE80211_ELEMID_SSID;

    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
        *frm++ = 0;
    } else {
        *frm++ = ni->ni_esslen;
        OS_MEMCPY(frm, ni->ni_essid, ni->ni_esslen);
        frm += ni->ni_esslen;
    }
    if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 5. Supported Rates and BSS Membership Selectors */
    bo->bo_rates = frm;
    frm = ieee80211_add_rates(vap, frm, rs);

    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_rates, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 6. DSSS Parameter Se */
    /* XXX better way to check this? */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            !IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        temp_bo = frm;
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, vap->iv_bsschan);
        if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }

    /* 7. CF Parameter Set */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_CFPARMS, -1, &frm, &bo->bo_cf_params,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    bo->bo_tim = frm;
    /* 8. Traffic indication map (TIM) */
    tie = (struct ieee80211_ath_tim_ie *) frm;
    tie->tim_ie        = IEEE80211_ELEMID_TIM;
    tie->tim_len       = 4;                      /* length */
    tie->tim_count     = 0;                      /* DTIM count */
    tie->tim_period    = vap->vdev_mlme->proto.generic.dtim_period;    /* DTIM period */
    tie->tim_bitctl    = 0;                      /* bitmap control */
    tie->tim_bitmap[0] = 0;                      /* Partial Virtual Bitmap */
    frm               += sizeof(struct ieee80211_ath_tim_ie);
    bo->bo_tim_len     = 1;
    bo->bo_tim_trailer = frm;
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_tim, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 9. Country */
    /* cfg80211_TODO: IEEE80211_FEXT_COUNTRYIE
     * ic_country.iso are we populating ?
     * we are building channel list from ic
     * so we should have proper IE generated
     */
    if (IEEE80211_IS_COUNTRYIE_AND_DOTH_ENABLED(ic, vap)) {
        temp_bo = frm;
        frm = ieee80211_add_country(frm, vap);
        if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }

    /* 10. Power Constraint */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        bo->bo_pwrcnstr = frm;
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_pwrcnstr, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
         bo->bo_pwrcnstr = NULL;
    }

    /* 11. Channel Switch Announcement */
    bo->bo_chanswitch = frm;

    /* 12. Quiet */
    temp_bo = frm;
    frm = ieee80211_quiet_beacon_setup(vap, ic, bo, frm);
    if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 14. TPC Report:
     * Add the TPC Report IE in the beacon if 802.11h or RRM capability
     * is set.
     */
    if ((ieee80211_ic_doth_is_set(ic) &&
         ieee80211_vap_doth_is_set(vap)) ||
         ieee80211_vap_rrm_is_set(vap)) {
        bo->bo_tpcreport = frm;
        frm = ieee80211_add_tpc_ie(frm, vap, IEEE80211_FC0_SUBTYPE_BEACON);
        if (!frm)
            return NULL;
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_tpcreport, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_tpcreport = NULL;
    }

    /* 15. ERP */
    if (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan)) {
        bo->bo_erp = frm;
        frm = ieee80211_add_erp(frm, ic);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_erp, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_erp = NULL;
    }

    /* 16.  Extended Supported Rates and BSS Membership Selectors */
    bo->bo_xrates = frm;
    if (rs->rs_nrates >= IEEE80211_RATE_SIZE) {
        frm = ieee80211_add_xrates(vap, frm, rs);
    }

    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_xrates, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 17. RSN */
    bo->bo_rsn = frm;
    frm = ieee80211_add_rsn_ie(vap, frm, &bo);
    if (!frm) {
        return NULL;
    } else {
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_rsn, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }

    /* 18. QBSS Load */
    bo->bo_qbssload = frm;
    if (ieee80211_vap_qbssload_is_set(vap)) {
        frm = ieee80211_qbssload_beacon_setup(vap, ni, bo, frm);
    } else {
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
              IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QBSS_LOAD, -1, &frm,
              TYPE_ALL_BUF, NULL, true))
            bo->bo_qbssload = NULL;
    }
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_qbssload, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 19. EDCA Parameter Set */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EDCA, -1, &frm, &bo->bo_edca,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 20. QoS Capability */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_QOS_CAP, -1, &frm, &bo->bo_qos_cap,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 21. AP Channel Report */
    if (vap->ap_chan_rpt_enable) {
        bo->bo_ap_chan_rpt = frm;
        frm = ieee80211_add_ap_chan_rpt_ie (frm, vap);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_ap_chan_rpt, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_ap_chan_rpt = NULL;
    }

    /* 22. BSS Average Access Delay */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY, -1, &frm, &bo->bo_bss_avg_delay,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 23. Antenna */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_ANTENNA, -1, &frm, &bo->bo_antenna,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 24. BSS Available Admission Capacity */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1, &frm, &bo->bo_bss_adm_cap,
                &vap->iv_available_bcn_cmn_space))
        return frm;

#if !ATH_SUPPORT_WAPI
    /* 25. BSS AC Access Delay */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1, &frm, &bo->bo_bss_ac_acc_delay,
                &vap->iv_available_bcn_cmn_space))
        return frm;
#endif

    /* 26. Measurement Pilot Transmissions */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1, &frm, &bo->bo_msmt_pilot_tx,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 27. Multiple BSSID */
    if (is_mbssid_enabled) {
        if (ic->ic_mbss.ema_ext_enabled) {
            /* Clear out previous contents */
            qdf_mem_zero(frm, bo->bo_mbssid_ie_len);
            bo->bo_mbssid_ie = frm;
        } else {
            frm = ieee80211_beacon_add_mbss_ie(&av->av_beacon_offsets, frm,
                    (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(orig_vap)) ?
                    non_transmit_ni: ni, IEEE80211_FRAME_TYPE_BEACON);

            if (!frm)
                return NULL;
        }
    }

    /* 28. RM Enabled Capbabilities */
    bo->bo_rrm = frm;
    frm = ieee80211_add_rrm_cap_ie(frm, ni);
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_rrm, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 29. Mobility Domain */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MOBILITY_DOMAIN, -1, &frm, &bo->bo_mob_domain,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 30. DSE Registered Location */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_DSE_REG_LOCATION, -1, &frm, &bo->bo_dse_reg_loc,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 31. Extended Channel Switch Announcement */
    bo->bo_ecsa = frm;

    /* 32. Supported Operating Classes */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_SUPP_OP_CLASS, -1, &frm, &bo->bo_opt_class,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /*
     * check for vap is done in ieee80211vap_htallowed.
     * remove iv_bsschan check to support multiple channel operation.
     */
    enable_htrates = ieee80211vap_htallowed(vap);
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
        enable_htrates) {

        if (!(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))) {
            /* 33. HT Capabilities */
            bo->bo_htcap = frm;
            frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_BEACON);
            if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_htcap, &frm,
                        &vap->iv_available_bcn_cmn_space,
                        IEEE80211_FRAME_TYPE_BEACON))
                return frm;

            /* 34. HT Operation */
            bo->bo_htinfo = frm;
            frm = ieee80211_add_htinfo(frm, ni);
            if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_htinfo, &frm,
                        &vap->iv_available_bcn_cmn_space,
                        IEEE80211_FRAME_TYPE_BEACON))
                return frm;
        }

        /* 35. 20/40 BSS Coexistence */
        if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_2040_COEXT, -1, &frm, &bo->bo_2040_coex,
                    &vap->iv_available_bcn_cmn_space))
            return frm;

        /* 36. Overlapping BSS Scan Parameters */
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            bo->bo_obss_scan = frm;
            frm = ieee80211_add_obss_scan(frm, ni);
            if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_obss_scan, &frm,
                        &vap->iv_available_bcn_cmn_space,
                        IEEE80211_FRAME_TYPE_BEACON))
                return frm;
        } else {
            bo->bo_obss_scan = NULL;
        }
    } else {
        bo->bo_htcap = NULL;
        bo->bo_htinfo = NULL;
        bo->bo_2040_coex = NULL;
        bo->bo_obss_scan = NULL;
    }

    /* 37. Extended Capabilities */
    bo->bo_extcap = frm;
    frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_BEACON);
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_extcap, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

#if UMAC_SUPPORT_WNM
    /* 38. FMS Descriptor */
    if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_fms_is_set(vap->wnm)) {
        bo->bo_fms_desc = frm;
        ieee80211_wnm_setup_fmsdesc_ie(ni, 0, &fmsie, &fmsie_len, &fms_counter_mask);
        if (fmsie_len)
            OS_MEMCPY(frm, fmsie, fmsie_len);
        frm += fmsie_len;
        bo->bo_fms_trailer = frm;
        bo->bo_fms_len = (u_int16_t)(frm - bo->bo_fms_desc);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_fms_desc, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_fms_desc = NULL;
        bo->bo_fms_len = 0;
        bo->bo_fms_trailer = NULL;
    }
#endif /* UMAC_SUPPORT_WNM */

    /* 39. QoS Traffic Capability */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1, &frm, &bo->bo_qos_traffic,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 40. Time Advertisement */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1, &frm, &bo->bo_time_adv,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 41. Interworking (Hotspot 2.0) */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_INTERWORKING, -1, &frm, &bo->bo_interworking,
                &vap->iv_available_bcn_cmn_space))
        return frm;


    /* 42. Advertisement Protocol (Hotspot 2.0) */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_ADVERTISEMENT_PROTO, -1, &frm, &bo->bo_adv_proto,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 43. Roaming Consortium (Hotspot 2.0) */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_ROAMING_CONSORTIUM, -1, &frm, &bo->bo_roam_consortium,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 44. Emergency Alert Identifier */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1, &frm, &bo->bo_emergency_id,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 45. Mesh ID */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MESH_ID, -1, &frm, &bo->bo_mesh_id,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 46. Mesh Configuration */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MESH_CONFIG, -1, &frm, &bo->bo_mesh_conf,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 47. Mesh Awake window */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1, &frm, &bo->bo_mesh_awake_win,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 48. Beacon Timing */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_BEACON_TIMING, -1, &frm, &bo->bo_beacon_time,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 49. MCCAOP Advertisement Overview */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1, &frm, &bo->bo_mccaop_adv_ov,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 50. MCCAOP Advertisement */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MCCAOP_ADV, -1, &frm, &bo->bo_mccaop_adv,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 51. Mesh Channel Switch Parameters */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1, &frm, &bo->bo_mesh_cs_param,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 52. QMF Policy */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_QMF_POLICY, -1, &frm, &bo->bo_qmf_policy,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 53. QLoad Report */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_QLOAD_REPORT, -1, &frm, &bo->bo_qload_rpt,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 54. HCCA TXOP Update Count */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_HCCA_TXOP_UPD_CNT, -1, &frm, &bo->bo_hcca_upd_cnt,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 55. Multi-band */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_MULTIBAND, -1, &frm, &bo->bo_multiband,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /*
     * VHT capable:
     * Add VHT capabilties (56), operation (57), Tx Power envelope (58),
     * Channel Switch Wrapper (59) and Extended BSS Load (60) elements,
     * if device is in 11ac operating mode (or) 256QAM is enabled in 2.4G
     */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        uint8_t *t_frm = frm;
        frm = ieee80211_add_vht_ies(ni, frm, &bo);
        if (!frm)
            return t_frm;
    } else {
        /*
         * Add Tx Power Envelope and Channel switch wrapper IE for 6G
         */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            bo->bo_vhttxpwr = frm;
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic,
                                        IEEE80211_FC0_SUBTYPE_BEACON, 0);
            if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_vhttxpwr, &frm,
                        &vap->iv_available_bcn_cmn_space,
                        IEEE80211_FRAME_TYPE_BEACON))
                return frm;
        } else {
            bo->bo_vhttxpwr = NULL;
        }
        bo->bo_vhtcap = NULL;
        bo->bo_vhtop = NULL;
        bo->bo_ext_bssload = NULL;
        bo->bo_vhttxpwr = NULL;
        bo->bo_vhtchnsw = frm;
    }

    /* 61. Quiet Channel */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_QUIET_CHANNEL, -1, &frm, &bo->bo_quiet_chan,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 62. Operating Mode Notification */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_OP_MODE_NOTIFY, -1, &frm, &bo->bo_opt_mode_note,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 63. Reduced Neighbor Report */
    if (vap->rnr_enable) {
        bo->bo_rnr = frm;
        temp_bo = frm;
        frm = ieee80211_add_rnr_ie(frm, vap,
                vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);

        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_rnr, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_rnr = NULL;
        temp_bo    = NULL;

        if (!is_mbssid_enabled || !ic->ic_mbss.ema_ext_enabled) {
            frm = ieee80211_add_6ghz_rnr_ie(ni, bo, frm,
                    &temp_bo, IEEE80211_FC0_SUBTYPE_BEACON, false);
            if (!frm)
                return NULL;

            if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                        &available_rnr_space,
                        IEEE80211_FRAME_TYPE_BEACON))
                return frm;
        } else {
            bo->bo_rnr = bo->bo_rnr2 = frm;
        }
    }

    /* 64. TVHT Operation */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_TVHT_OP, -1, &frm, &bo->bo_tvht,
                &vap->iv_available_bcn_cmn_space))
        return frm;


#if QCN_ESP_IE
    /* 65. Estimated Service Parameters */
    if(ic->ic_esp_periodicity){
        bo->bo_esp_ie = frm;
        frm = ieee80211_add_esp_info_ie(frm, ic, &bo->bo_esp_ie_len);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_esp_ie, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }
#endif

    /* 66. Future Channel Guidance */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_FUTURE_CHANNEL_GUIDE,
                &frm, &bo->bo_future_chan, &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 67. Common Advertisement Group (CAG) Number */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_CAG_NUMBER, -1, &frm, &bo->bo_cag_num,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 68. FILS Indication */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_FILS_INDICATION, -1, &frm, &bo->bo_fils_ind,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 69. AP-CSN */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_AP_CSN, -1, &frm, &bo->bo_ap_csn,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 70. Differentiated Initial Link Setup */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1, &frm, &bo->bo_diff_init_lnk,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 73. Service Hint */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HINT, &frm,
                &bo->bo_service_hint, &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 74. Service Hash */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HASH, &frm,
                &bo->bo_service_hash, &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 76. MBSSID Config */
    if (is_ema_ap_enabled) {
        bo->bo_mbssid_config = frm;
        frm = ieee80211_add_mbssid_config(vap,
                IEEE80211_FRAME_TYPE_BEACON, frm);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_mbssid_config, &frm,
                    &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_mbssid_config = NULL;
    }

    /*
     * HE capable:
     */
    if (ieee80211_vap_wme_is_set(vap) &&
        IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) && ieee80211vap_heallowed(vap)) {
        /* 77. HE Capabilities */
        bo->bo_hecap = frm;
        frm = ieee80211_add_hecap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_hecap, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;

        /* 78. HE Operation */
        bo->bo_heop = frm;
        frm = ieee80211_add_heop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON, NULL);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_heop, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_hecap = NULL;
        bo->bo_heop  = NULL;
    }

    /* 79. TWT */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_TWT, -1, &frm, &bo->bo_twt,
                &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 80. UORA Parameter Set */
#if ATH_SUPPORT_UORA
    if(ieee80211_vap_wme_is_set(vap) &&
       ieee80211vap_heallowed(vap) &&
       IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
       ieee80211vap_uora_is_enabled(vap)) {
        bo->bo_uora_param = frm;
        frm = ieee80211_add_uora_param(frm, vap->iv_ocw_range);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_uora_param, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_uora_param = NULL;
    }
#endif

    /* 81. BSS Color Change Announcement */
    bo->bo_bcca = frm;

#ifdef OBSS_PD
    /*
     * 82. Spatial Reuse Parameter Set
     * Check if OBSS PD service is enabled and add SRP IE in beacon
     * between BSS Color Change Announcement IE and MU EDCA IE as
     * per section 9.3.3.3 in 11ax draft 3.0
     */
    if(ic->ic_he_sr_enable &&
       IEEE80211_IS_CHAN_11AX(ic->ic_curchan) && ieee80211vap_heallowed(vap)) {
        bo->bo_srp_ie = frm;
        frm = ieee80211_add_srp_ie(vap, frm);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_srp_ie, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }
#endif

    /* 83. MU EDCA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
       ieee80211vap_heallowed(vap) &&
       IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
       ieee80211vap_muedca_is_enabled(vap)) {
        bo->bo_muedca = frm;
        frm = ieee80211_add_muedca_param(frm, &vap->iv_muedcastate);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_muedca, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_muedca = NULL;
    }

    /* 84. ESS Report */
    bo->bo_ess_rpt = frm;
    if (vap->iv_planned_ess) {
        frm = ieee80211_add_ess_rpt_ie(frm, vap);
    } else {
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
                    IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_ESS_REPORT, &frm,
                    TYPE_ALL_BUF, NULL, true))
            bo->bo_ess_rpt = NULL;
    }
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_ess_rpt, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* 85. NDP Feedback Report Parameter Set */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM,
                &frm, &bo->bo_ndp_rpt_param, &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 86. HE BSS Load */
    if (ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_BEACON,
                IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_HE_BSS_LOAD, &frm,
                &bo->bo_he_bss_load, &vap->iv_available_bcn_cmn_space))
        return frm;

    /* 87. HE 6GHz Band Capabilities */
    if (ieee80211_vap_wme_is_set(vap) && IEEE80211_IS_CHAN_11AX(vap->iv_bsschan)
            && ieee80211vap_heallowed(vap)
            && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        bo->bo_he_6g_bandcap = frm;
        frm = ieee80211_add_6g_bandcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_he_6g_bandcap, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_he_6g_bandcap = NULL;
    }

    /* Adding Max Channel Switch Time IE here since no order
     * is mentioned in the specification
     */
    bo->bo_mcst = frm;

    /* Secondary channel offset
     * Added here since no order
     * is mentioned in the specification
     */
    bo->bo_secchanoffset = frm;

    /* Adding RSNX IE here since no order is mentioned in the
     * specification
     */
    bo->bo_rsnx = frm;
    if (vap->iv_rsnx_override) {
        frm = ieee80211_rsnx_override(frm, vap);
    } else {
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
            IEEE80211_ELEMID_RSNX, -1, &frm,
            TYPE_ALL_BUF, NULL, true))
            bo->bo_rsnx = NULL;
    }
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_rsnx, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

#if ATH_SUPPORT_WAPI
    /* WAPI IE, if supported
     * Added here since no order
     * is mentioned in the specification
     */
    if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_WAPI)))
    {
        temp_bo = frm;
        frm = ieee80211_setup_wapi_ie(vap, frm);
        if (!frm) {
            return NULL;
        }
        if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }
#endif

    /* ------------- LAST. Vendor IEs ------------- */
    /* Ath Advertisement capabilities */
    bo->bo_ath_caps = frm;
    if (vap->iv_ena_vendor_ie == 1) {
        if (vap->iv_bss && vap->iv_bss->ni_ath_flags) {
            frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
                    vap->iv_bss->ni_ath_defkeyindex);
        } else {
            frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
        }
        vap->iv_update_vendor_ie = 0;
    }
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_ath_caps, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* Ath Extended Capabilities */
    if (ic->ic_ath_extcap) {
        temp_bo = frm;
        frm = ieee80211_add_athextcap(frm,
                ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);
        if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }

#if DBDC_REPEATER_SUPPORT
    /* Extender */
    if (ic_list->same_ssid_support) {
        bo->bo_extender_ie = frm;
        frm = ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_BEACON, frm);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_extender_ie, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }
#endif

    /* HT Cap and HT Info/Operation Vendor IEs */
    if ((!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
            IEEE80211_IS_HTVIE_ENABLED(ic) && enable_htrates) {
        temp_bo = frm;
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_BEACON);
        if (ieee80211_check_driver_tx_cmn_ie(vap, temp_bo, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;

        bo->bo_htinfo_vendor_specific = frm;
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_htinfo_vendor_specific,
                    &frm, &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_htinfo_vendor_specific = NULL;
    }

    /* MBO */
    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        bo->bo_mbo_cap = frm;
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_BEACON, vap, frm, ni);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_mbo_cap, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_mbo_cap = NULL;
    }

    /* Next Channel */
    if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic)
            && IEEE80211_IS_CHAN_DFS(ic->ic_curchan) && ic->ic_tx_next_ch)
    {
        bo->bo_apriori_next_channel = frm;
        frm = ieee80211_add_next_channel(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_apriori_next_channel,
                    &frm, &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_apriori_next_channel = NULL;
    }

    /* Prop NSS Map IE if EXT NSS is not supported */
    if (!(vap->iv_ext_nss_support) &&
            !(ic->ic_disable_bcn_bwnss_map) &&
            !(ic->ic_disable_bwnss_adv) &&
            !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        bo->bo_bwnss_map = frm;
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_bwnss_map, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_bwnss_map = NULL;
    }

#if QCN_IE
    /* QCN IE for the feature set */
    bo->bo_qcn_ie = frm;
    frm = ieee80211_add_qcn_info_ie(frm, vap, &bo->bo_qcn_ie_len,
                                    QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_qcn_ie, &frm,
                &vap->iv_available_bcn_cmn_space,
                IEEE80211_FRAME_TYPE_BEACON))
        return frm;
#endif

    /* SON mode IE which requires WDS as a prereq */
    bo->bo_xr = frm;

    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        bo->bo_whc_apinfo = frm;
        bo->bo_whc_apinfo_len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_VENDOR, IEEE80211_ELEMID_VENDOR_SON_AP,
                &frm, TYPE_APP_IE_BUF, NULL, true);
        if(!bo->bo_whc_apinfo_len)
            bo->bo_whc_apinfo = NULL;

        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_whc_apinfo, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    }
    /* VHT Vendor IE for 256QAM support in 2.4G Interop */
    if ((ieee80211_vap_wme_is_set(vap) &&
         (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
         IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap) &&
              ieee80211vap_11ng_vht_interopallowed(vap)) {
        /* Add VHT capabilities IE and VHT OP IE in Vendor specific IE*/
        bo->bo_interop_vhtcap = frm;
        frm = ieee80211_add_interop_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_interop_vhtcap, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_interop_vhtcap = NULL;
    }

    /* WME param */
    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP ||
         vap->iv_opmode == IEEE80211_M_BTAMP)) {

        bo->bo_wme = frm;
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
        ieee80211vap_clear_flag(vap, IEEE80211_F_WMEUPDATE);
        if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_wme, &frm,
                    &vap->iv_available_bcn_cmn_space,
                    IEEE80211_FRAME_TYPE_BEACON))
            return frm;
    } else {
        bo->bo_wme = NULL;
    }

    /* WPA
     * Check if os shim has setup WPA IE itself
     */
    if (!vap->iv_rsn_override) {
        len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON,IEEE80211_ELEMID_VENDOR, 1, &frm,
                TYPE_ALL_BUF, NULL, true);
        if (len) {
            /* Remove WPA from frame so that it will be added
             * when other vendor IEs are added
             */
            frm -= len;
            qdf_mem_zero(frm, len);
        } else {

            /* Adding WPA IE if not present in buffers*/
            if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                        (1 << WLAN_CRYPTO_AUTH_WPA))) {
                frm = wlan_crypto_build_wpaie(vap->vdev_obj, frm);
                if(!frm) {
                    return NULL;
                }
            }
        }
    }

    /* Software and Hardware version */
    bo->bo_software_version_ie = frm;
    frm = ieee80211_add_sw_version_ie(frm, ic);
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_software_version_ie, &frm,
                &vap->iv_available_bcn_cmn_space,
                IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    bo->bo_generic_vendor_capabilities = frm;
    frm = ieee80211_add_generic_vendor_capabilities_ie(frm, ic);
    if (!frm) {
        return NULL;
    }
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_generic_vendor_capabilities,
                &frm, &vap->iv_available_bcn_cmn_space,
                IEEE80211_FRAME_TYPE_BEACON))
        return frm;

    /* ------------- LAST. App IE Buffer or list, and Optional IEs ------------- */
    bo->bo_appie_buf = frm;
    bo->bo_appie_buf_len = 0;

    len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_BEACON,
            IEEE80211_ELEMID_VENDOR, 0, &frm, TYPE_ALL_BUF, NULL, false);
    bo->bo_appie_buf_len = len;
    if (ieee80211_check_driver_tx_cmn_ie(vap, bo->bo_appie_buf, &frm,
                &vap->iv_available_bcn_cmn_space, IEEE80211_FRAME_TYPE_BEACON))
        return frm;

#if QCA_SUPPORT_EMA_EXT
    /* Populate MBSSID and RNR IEs */
    if (IS_MBSSID_EMA_EXT_ENABLED(ic)) {
        uint8_t *saved_bo_rnr = NULL;
        uint16_t offset = 0;

        /* Add MBSSID IE */
        bo->bo_mbssid_ie_len = ieee80211_add_mbss_ie(frm,
                (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(orig_vap)) ?
                non_transmit_ni: ni, IEEE80211_FRAME_TYPE_BEACON, 0, NULL);

        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(orig_vap) &&
                orig_vap->iv_mbss.ie_overflow) {
            return frm;
        }

        /* Adjust offsets */
        if (bo->bo_mbssid_ie_len) {
            frm = ieee80211_beacon_adjust_bos_for_context(
                    ic, frm, bo,
                    bo->bo_mbssid_ie_len, IEEE80211_IE_OFFSET_CONTEXT_MBSSIE);
        }

        /* Add RNR IE */
        saved_bo_rnr = bo->bo_rnr;
        temp_bo = NULL;
        frm = ieee80211_add_6ghz_rnr_ie(ni, bo, frm,
                &temp_bo, IEEE80211_FC0_SUBTYPE_BEACON, false);
        if (!frm) {
            return NULL;
        }

        if (bo->bo_rnr) {
            offset = frm - bo->bo_rnr;
        } else if (bo->bo_rnr2) {
            offset = frm - bo->bo_rnr2;
        }

        if (offset) {
            if (bo->bo_rnr2 && bo->bo_rnr2 > bo->bo_rnr)
                bo->bo_rnr2 = saved_bo_rnr + (bo->bo_rnr2 - bo->bo_rnr);
            bo->bo_rnr  = saved_bo_rnr;

            /* Adjust offsets */
            if (temp_bo &&
                    !ieee80211_check_and_add_tx_cmn_ie(vap, temp_bo, &frm,
                        &available_rnr_space, IEEE80211_FRAME_TYPE_BEACON)) {
                frm -= offset;
                frm = ieee80211_beacon_adjust_bos_for_context(
                        ic, frm, bo, offset, IEEE80211_IE_OFFSET_CONTEXT_RNRIE);
            }
        }
    }
#endif

    bo->bo_tim_trailerlen = frm - bo->bo_tim_trailer;
    bo->bo_chanswitch_trailerlen = frm - bo->bo_chanswitch;
    bo->bo_ecsa_trailerlen = frm - bo->bo_ecsa;
    bo->bo_mcst_trailerlen = frm - bo->bo_mcst;
    bo->bo_vhtchnsw_trailerlen = frm - bo->bo_vhtchnsw;
    bo->bo_secchanoffset_trailerlen = frm - bo->bo_secchanoffset;
    bo->bo_bcca_trailerlen          = frm - bo->bo_bcca;
#if UMAC_SUPPORT_WNM
    bo->bo_fms_trailerlen = frm - bo->bo_fms_trailer;
#endif /* UMAC_SUPPORT_WNM */

    return frm;
}

/*
 * Make a copy of the Beacon Frame store for this VAP. NOTE: this copy is not the
 * most recent and is only updated when certain information (listed below) changes.
 *
 * The frame includes the beacon frame header and all the IEs, does not include the 802.11
 * MAC header. Beacon frame format is defined in ISO/IEC 8802-11. The beacon frame
 * should be the up-to-date one used by the driver except that real-time parameters or
 * information elements that vary with data frame flow control or client association status,
 * such as timestamp, radio parameters, TIM, ERP and HT information elements do not
 * need to be accurate.
 *
 */
static void
store_beacon_frame(struct ieee80211vap *vap, u_int8_t *wh, int frame_len)
{

    if (ieee80211_vap_copy_beacon_is_clear(vap)) {
        ASSERT(0);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                "ieee80211_vap_copy_beacon_is_clear is true\n");
        return;
    }

    if (vap->iv_beacon_copy_buf == NULL) {
        /* The beacon copy buffer is not allocated yet. */

        vap->iv_beacon_copy_buf = OS_MALLOC(vap->iv_ic->ic_osdev, IEEE80211_RTS_MAX, GFP_KERNEL);
        if (vap->iv_beacon_copy_buf == NULL) {
            /* Unable to allocate the memory */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc beacon copy buf. Size=%d\n",
                              __func__, IEEE80211_RTS_MAX);
            return;
        }
    }

    ASSERT(frame_len <= IEEE80211_RTS_MAX);
    OS_MEMCPY(vap->iv_beacon_copy_buf, wh, frame_len);
    vap->iv_beacon_copy_len = frame_len;
#if UMAC_SUPPORT_P2P
/*
 *  XXX: When P2P connect, the wireless connection icon will be changed to Red-X,
 *       while the connection is OK.
 *       It is because of the query of OID_DOT11_ENUM_BSS_LIST.
 *       By putting AP(GO)'s own beacon information into the scan table,
 *       that problem can be solved.
 */
    ieee80211_scan_table_update(vap,
                                (struct ieee80211_frame*)wh,
                                frame_len,
                                IEEE80211_FC0_SUBTYPE_BEACON,
                                0,
                                ieee80211_get_current_channel(vap->iv_ic));
#endif
}

wbuf_t ieee80211_prb_rsp_alloc_init(struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211vap *tx_vap = NULL;
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = NULL;
    ol_ath_soc_softc_t *soc = NULL;
    struct ieee80211vap *orig_vap;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int16_t capinfo;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask;
    int enable_htrates;
    struct ieee80211_node *non_transmit_ni = NULL;
    uint8_t len = 0;
    uint8_t chanchange_tbtt = 0;
    uint8_t csmode = IEEE80211_CSA_MODE_STA_TX_ALLOWED;
    bool global_look_up = false;
    uint64_t adjusted_tsf_le = 0, tsf_adj = 0;
    struct ol_ath_vap_net80211 *avn = NULL;
    struct ieee80211_beacon_offsets *po = NULL;
    uint16_t behav_lim = 0;
    uint16_t chan_width;


#if QCN_IE
    u_int16_t ie_len;
#endif
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list;
#endif
#if QCN_ESP_IE
    u_int16_t esp_ie_len;
#endif
    bool is_buffer_preallocated;
    bool is_mbssid_enabled;
    bool is_ema_ap_enabled;
    int32_t available_rnr_space = 0;
    uint8_t *temp_po = NULL;

    qdf_mem_zero(&nssmap, sizeof(nssmap));
    if (!ic) {
        qdf_err("Ic is NULL");
        return NULL;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    soc = scn->soc;
    available_rnr_space = soc->ema_ap_rnr_field_size_limit;
    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                        WLAN_PDEV_F_MBSS_IE_ENABLE);
    is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                        WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    ic->ic_mbss.ema_ap_available_prb_non_tx_space = soc->ema_ap_max_non_tx_size;

    vap = ni->ni_vap;

    if(!vap) {
        qdf_err("Vap is NULL");
        return NULL;
    }

    avn = OL_ATH_VAP_NET80211(vap);
    po = &(avn->av_prb_rsp_offsets);

    if (is_mbssid_enabled) {
        tx_vap = ic->ic_mbss.transmit_vap;
        if (!tx_vap) {
            qdf_err("Tx vap is NULL");
            return NULL;
        }
    }

    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) ||
         (!is_mbssid_enabled && !vap->iv_he_6g_bcast_prob_rsp) ||
         (tx_vap && !tx_vap->iv_he_6g_bcast_prob_rsp)) {
        qdf_debug("20 Tu Prb resp not applicable");
        return NULL;
    }

#if DBDC_REPEATER_SUPPORT
    ic_list = ic->ic_global_list;
#endif
    rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    orig_vap = ni->ni_vap;
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {

        /* We operate on tx vap's beacon buffer */
        vap = ic->ic_mbss.transmit_vap;
        non_transmit_ni = ni;
        ni = vap->iv_bss;
    }

    vap->iv_mbss.ie_overflow = false;
    vap->iv_available_prb_cmn_space = soc->ema_ap_beacon_common_part_size;

    avn = OL_ATH_VAP_NET80211(vap);
    if (avn->av_pr_rsp_wbuf) {
        /* Skip buffer alloc if Probe response buffer is already allocated */
        wbuf = avn->av_pr_rsp_wbuf;
        is_buffer_preallocated = true;
    } else {
        if (ic && ic->ic_osdev) {
            wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
            is_buffer_preallocated = false;
        } else {
            return NULL;
        }
    }

    if (wbuf == NULL)
        return NULL;

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
        IEEE80211_FC0_SUBTYPE_PROBE_RESP;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    *(u_int16_t *)wh->i_dur = 0;
    if(ic->ic_softap_enable){
        IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_myaddr);
    }
    IEEE80211_ADDR_COPY(wh->i_addr1, IEEE80211_GET_BCAST_ADDR(ic));
    IEEE80211_ADDR_COPY(wh->i_addr2, vap->iv_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);
    *(u_int16_t *)wh->i_seq = 0;

    frm = (u_int8_t *)&wh[1];

    /* ------------- Fixed Fields ------------- */
    /* 1. Timestamp */
    /* In staggered mode, TSF correction is done in HW based on
     * adjusted TSF value provided by Host in timestamp field of mgmt
     * frames. This logic is present in beacon but not in probe response.
     * Below applies the logic to probe response frames as well.
     */
    ucfg_wlan_vdev_mgr_get_tsf_adjust(vap->vdev_obj, &tsf_adj);
    adjusted_tsf_le = qdf_cpu_to_le64(0ULL - tsf_adj);
    qdf_mem_copy(frm, &adjusted_tsf_le, sizeof(adjusted_tsf_le));

    frm += 8;
    if (IS_MBSSID_EMA_EXT_ENABLED(ic))
        vap->iv_available_prb_cmn_space -= 8;

    /* 2. Beacon interval */
    *(u_int16_t *)frm = htole16(vap->iv_bss->ni_intval);
    frm += 2;
    if (IS_MBSSID_EMA_EXT_ENABLED(ic))
        vap->iv_available_prb_cmn_space -= 2;

    /* 3. Capability Information */
    capinfo = IEEE80211_CAPINFO_ESS;

    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }

    po->bo_caps = (u_int16_t *)frm;
    *(u_int16_t *)frm = htole16(capinfo);
    frm += 2;
    if (IS_MBSSID_EMA_EXT_ENABLED(ic))
        vap->iv_available_prb_cmn_space -= 2;

    /* ------------- Regular and Extension IEs ------------- */
    /* 4. SSID */
    temp_po = frm;
    frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
                             vap->iv_bss->ni_esslen);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 5. Supported Rates and BSS Membership Selectors */
    po->bo_rates = frm;
    frm = ieee80211_add_rates(vap, frm, &vap->iv_bss->ni_rates);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_rates, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 6. DS Parameter Set */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            !IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        temp_po = frm;
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

    /* 7. CF Parameter Set */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_CFPARMS, -1, &frm, &po->bo_cf_params,
            &vap->iv_available_prb_cmn_space);

    /* 8. Country */
    if (IEEE80211_IS_COUNTRYIE_AND_DOTH_ENABLED(ic, vap)) {
        temp_po = frm;
        frm = ieee80211_add_country(frm, vap);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

    /* 9. Power Constraint */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        po->bo_pwrcnstr = frm;
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_pwrcnstr,
                &frm, &vap->iv_available_prb_cmn_space,
                    IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_pwrcnstr = NULL;
    }

    if (vap->iv_csmode == IEEE80211_CSA_MODE_AUTO) {

        /* No user preference for csmode. Use default behavior.
         * If chan swith is triggered because of radar found
         * ask associated stations to stop transmission by
         * sending csmode as 1 else let them transmit as usual
         * by sending csmode as 0.
         */
        if (ic->ic_flags & IEEE80211_F_DFS_CHANSWITCH_PENDING) {
            /* Request STA's to stop transmission */
            csmode = IEEE80211_CSA_MODE_STA_TX_RESTRICTED;
        }
    } else {
        /* User preference for csmode is configured.
         * Use user preference
         */
        csmode = vap->iv_csmode;
    }

    /* 10. Channel Switch Announcement */
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)) {
        struct ieee80211_ath_channelswitch_ie *csaie = NULL;
        chanchange_tbtt = ic->ic_chanchange_tbtt - vap->iv_chanchange_count;

        temp_po = frm;
        csaie = (struct ieee80211_ath_channelswitch_ie *)frm;
        csaie->ie = IEEE80211_ELEMID_CHANSWITCHANN;
        csaie->len = 3; /* fixed len */
        csaie->switchmode = csmode;
        csaie->newchannel = wlan_reg_freq_to_chan(ic->ic_pdev_obj, ic->ic_chanchange_chan_freq);
        csaie->tbttcount = chanchange_tbtt;
        frm += IEEE80211_CHANSWITCHANN_BYTES;
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

    /* 11. Quiet */
    po->bo_quiet = frm;
    frm = ieee80211_add_quiet(vap, ic, frm);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_quiet, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 13. TPC Report
     * Add the TPC Report IE in the probe response for 5GHz if 802.11h or RRM capability
     * is set.
     */
    if ((ieee80211_ic_doth_is_set(ic) &&
         ieee80211_vap_doth_is_set(vap)) ||
         ieee80211_vap_rrm_is_set(vap)) {
        po->bo_tpcreport = frm;
        frm = ieee80211_add_tpc_ie(frm, vap, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        if (!frm) {
            wbuf_release(ic->ic_osdev, wbuf);
            return NULL;
        }
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_tpcreport,
                &frm, &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_tpcreport = NULL;
    }

    /* 14. ERP */
    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11AXG(ic->ic_curchan)) {
        po->bo_erp = frm;
        frm = ieee80211_add_erp(frm, ic);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_erp, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_erp = NULL;
    }

    /* 15. Extended Support Rates and BSS Membership Selectors */
    po->bo_xrates = frm;
    frm = ieee80211_add_xrates(vap, frm, &vap->iv_bss->ni_rates);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_xrates, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 16. RSN */
    po->bo_rsn = frm;
    frm = ieee80211_prb_add_rsn_ie(vap, frm, &po, NULL);
    if (!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return NULL;
    }
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_rsn, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 17. QBSS Load */
    po->bo_qbssload = frm;
    if (ieee80211_vap_qbssload_is_set(vap)) {
        frm = ieee80211_add_qbssload(frm, ni);
    } else {
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_PROBERESP,
                    IEEE80211_ELEMID_QBSS_LOAD, -1, &frm,
                    TYPE_ALL_BUF, NULL, true))
            po->bo_qbssload = NULL;
    }
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_qbssload, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 18. EDCA Parameter Set */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EDCA, -1, &frm, &po->bo_edca,
            &vap->iv_available_prb_cmn_space);

    /* 19. Measurement Pilot Transmissions */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1, &frm, &po->bo_msmt_pilot_tx,
            &vap->iv_available_prb_cmn_space);

    /* 20. Multiple BSSID */
    if (is_mbssid_enabled) {
        if (ic->ic_mbss.ema_ext_enabled) {
            po->bo_mbssid_ie = frm;
        } else {
            frm = ieee80211_beacon_add_mbss_ie(&avn->av_prb_rsp_offsets, frm,
                    (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(orig_vap)) ?
                    non_transmit_ni: ni, IEEE80211_FRAME_TYPE_PROBERESP);
        }
    } else {
        po->bo_mbssid_ie = NULL;
    }

    /* 21. RM Enabled Capbabilities, if supported */
    po->bo_rrm = frm;
    frm = ieee80211_add_rrm_cap_ie(frm, ni);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_rrm, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 22. AP Channel Report */
    if (vap->ap_chan_rpt_enable) {
        po->bo_ap_chan_rpt = frm;
        frm = ieee80211_add_ap_chan_rpt_ie (frm, vap);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_ap_chan_rpt,
                &frm, &vap->iv_available_prb_cmn_space,
                    IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_ap_chan_rpt = NULL;
    }

    /* 23. BSS Average Access Delay */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY, -1, &frm, &po->bo_bss_avg_delay,
            &vap->iv_available_prb_cmn_space);

    /* 24. Antenna */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_ANTENNA, -1, &frm, &po->bo_antenna,
            &vap->iv_available_prb_cmn_space);

    /* 25. BSS Available Admission Capacity */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1, &frm, &po->bo_bss_adm_cap,
            &vap->iv_available_prb_cmn_space);

#if !ATH_SUPPORT_WAPI
    /* 26. BSS AC Access Delay IE */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1, &frm, &po->bo_bss_ac_acc_delay,
            &vap->iv_available_prb_cmn_space);
#endif

    /* 27. Mobility Domain */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MOBILITY_DOMAIN, -1, &frm, &po->bo_mob_domain,
            &vap->iv_available_prb_cmn_space);

    /* 28. DSE registered location */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_DSE_REG_LOCATION, -1, &frm, &po->bo_dse_reg_loc,
            &vap->iv_available_prb_cmn_space);

    /* 29. Extended Channel Switch Announcement */
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && vap->iv_enable_ecsaie) {
        struct ieee80211_extendedchannelswitch_ie *ecsa_ie = NULL;

        temp_po = frm;
        ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)frm;
        ecsa_ie->ie = IEEE80211_ELEMID_EXTCHANSWITCHANN;
        ecsa_ie->len = 4; /* fixed len */
        ecsa_ie->switchmode = csmode;

        /* If user configured opClass is set, use it else
         * *              * calculate new opClass from destination channel.
         * *                           */
        if (vap->iv_ecsa_opclass) {
            ecsa_ie->newClass = vap->iv_ecsa_opclass;
            ecsa_ie->newchannel =
                    wlan_reg_freq_to_chan(ic->ic_pdev_obj,
                                          ic->ic_chanchange_chan_freq);
        } else {
            /* Channel look-up tables should not change with CSA */
            global_look_up = false;
            wlan_get_bw_and_behav_limit(ic->ic_chanchange_channel,
                                        &chan_width, &behav_lim);

            if (!behav_lim) {
                wbuf_release(ic->ic_osdev, wbuf);
                return NULL;
            }
            /* Get new OpClass and Channel number from regulatory */
            wlan_reg_freq_width_to_chan_op_class_auto(ic->ic_pdev_obj,
                                                      ic->ic_chanchange_chan_freq,
                                                      chan_width,
                                                      global_look_up, behav_lim,
                                                      &ecsa_ie->newClass,
                                                      &ecsa_ie->newchannel);
        }
        ecsa_ie->tbttcount = chanchange_tbtt;
        frm += IEEE80211_EXTCHANSWITCHANN_BYTES;
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

    /* 30. Supported Operating Classes */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_SUPP_OP_CLASS, -1, &frm, &po->bo_opt_class,
            &vap->iv_available_prb_cmn_space);

    /* HT capable */
    enable_htrates = ieee80211vap_htallowed(vap);
    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        enable_htrates) {
        /* 31. HT Capabilities */
        po->bo_htcap = frm;
        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_htcap, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

        /* 32. HT Operation */
        po->bo_htinfo = frm;
        frm = ieee80211_add_htinfo(frm, ni);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_htinfo, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

        /* 33. 20/40 BSS Coexistence */
        (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
                IEEE80211_ELEMID_2040_COEXT, -1, &frm, &po->bo_2040_coex,
                &vap->iv_available_prb_cmn_space);

        /* 34. OBSS Scan */
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            po->bo_obss_scan = frm;
            frm = ieee80211_add_obss_scan(frm, ni);
            (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_obss_scan,
                    &frm, &vap->iv_available_prb_cmn_space,
                        IEEE80211_FRAME_TYPE_PROBERESP);
        } else {
            po->bo_obss_scan = NULL;
        }
    }

    /* 35. Extended Capbabilities, if applicable */
    po->bo_extcap = frm;
    frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_extcap, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 36. QoS Traffic Capability */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1, &frm, &po->bo_qos_traffic,
            &vap->iv_available_prb_cmn_space);

    /* 37. Channel Usage */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_CHANNEL_USAGE, -1, &frm, &po->bo_chan_usage,
            &vap->iv_available_prb_cmn_space);

    /* 38. Time Advertisement */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1, &frm, &po->bo_time_adv,
            &vap->iv_available_prb_cmn_space);

    /* 39. Time Zone */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_TIME_ZONE, -1, &frm, &po->bo_time_zone,
            &vap->iv_available_prb_cmn_space);

    /* 40. Interworking IE (Hotspot 2.0) */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_INTERWORKING, -1, &frm, &po->bo_interworking,
            &vap->iv_available_prb_cmn_space);

    /* 41. Advertisement Protocol IE (Hotspot 2.0) */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_ADVERTISEMENT_PROTO, -1, &frm, &po->bo_adv_proto,
            &vap->iv_available_prb_cmn_space);

    /* 42. Roaming Consortium IE (Hotspot 2.0) */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_ROAMING_CONSORTIUM, -1, &frm, &po->bo_roam_consortium,
            &vap->iv_available_prb_cmn_space);

    /* 43. Emergency Alert Identifier */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1, &frm, &po->bo_emergency_id,
            &vap->iv_available_prb_cmn_space);

    /* 44. Mesh ID */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MESH_ID, -1, &frm, &po->bo_mesh_id,
            &vap->iv_available_prb_cmn_space);

    /* 45. Mesh Configuration */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MESH_CONFIG, -1, &frm, &po->bo_mesh_conf,
            &vap->iv_available_prb_cmn_space);

    /* 46. Mesh Awake Window */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1, &frm, &po->bo_mesh_awake_win,
            &vap->iv_available_prb_cmn_space);

    /* 47. Beacon Timing */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_BEACON_TIMING, -1, &frm, &po->bo_beacon_time,
            &vap->iv_available_prb_cmn_space);

    /* 48. MCCAOP Advertisement Overview */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1, &frm, &po->bo_mccaop_adv_ov,
            &vap->iv_available_prb_cmn_space);

    /* 49. MCCAOP Advertisement */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MCCAOP_ADV, -1, &frm, &po->bo_mccaop_adv,
            &vap->iv_available_prb_cmn_space);

    /* 50. Mesh Channel Switch Parameters */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1, &frm, &po->bo_mesh_cs_param,
            &vap->iv_available_prb_cmn_space);

    /* 51. QMF Policy */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_QMF_POLICY, -1, &frm, &po->bo_qmf_policy,
            &vap->iv_available_prb_cmn_space);

    /* 52. QLoad Report */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_QLOAD_REPORT, -1, &frm, &po->bo_qload_rpt,
            &vap->iv_available_prb_cmn_space);

    /* 53. Multi-band */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MULTIBAND, -1, &frm, &po->bo_multiband,
            &vap->iv_available_prb_cmn_space);

    /* 54. DMG Capabilities */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_DMG_CAP, -1, &frm, &po->bo_dmg_cap,
            &vap->iv_available_prb_cmn_space);

    /* 55. DMG Operation */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_DMG_OPERATION, -1, &frm, &po->bo_dmg_op,
            &vap->iv_available_prb_cmn_space);

    /* 56. Multiple MAC Sublayers */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MULTIPLE_MAC_SUB, -1, &frm, &po->bo_mul_mac_sub,
            &vap->iv_available_prb_cmn_space);

    /* 57. Antenna Sector ID Pattern */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_ANTENNA_SECT_ID_PAT, -1, &frm, &po->bo_ant_sec_id,
            &vap->iv_available_prb_cmn_space);

    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        /* VHT capable
         * Add VHT capabilities (58), operation (59), Tx Power envelope (60),
         * Channel Switch Wrapper (61) and Extended BSS Load (62) elements
         * for 2.4G mode, if 256QAM is enabled
         */
        frm = ieee80211_prb_add_vht_ies(ni, frm, wh->i_addr1, NULL, &po);
    } else {
        po->bo_vhtcap = NULL;
        po->bo_vhtop = NULL;
        po->bo_ext_bssload = NULL;

        /*
         * Add Channel switch wrapper IE and Tx power envelope for 6G band
         * ieee80211_prb_add_vht_ies adds these IEs for 5G band, but not for 6G.
         */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            po->bo_vhttxpwr = frm;
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic,
                                    IEEE80211_FC0_SUBTYPE_PROBE_RESP, 0);
            (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_vhttxpwr,
                    &frm, &vap->iv_available_prb_cmn_space,
                    IEEE80211_FRAME_TYPE_PROBERESP);
        } else {
            po->bo_vhttxpwr = NULL;
        }

        if (ieee80211_vap_wme_is_set(vap) && vap->iv_chanchange_count &&
                (ic->ic_chanchange_channel != NULL)) {
            po->bo_vhtchnsw = frm;
            frm = ieee80211_add_chan_switch_wrp(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                    (!IEEE80211_VHT_EXTCH_SWITCH));
            (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_vhtchnsw,
                    &frm, &vap->iv_available_prb_cmn_space,
                    IEEE80211_FRAME_TYPE_PROBERESP);
        } else {
            po->bo_vhtchnsw = NULL;
        }
    }

    /* 63. Quiet Channel */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_QUIET_CHANNEL, -1, &frm, &po->bo_quiet_chan,
            &vap->iv_available_prb_cmn_space);

    /* 64. Operating Mode Notification */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_OP_MODE_NOTIFY, -1, &frm, &po->bo_opt_mode_note,
            &vap->iv_available_prb_cmn_space);

    /* 65. Reduced Neighbor Report */
    if (vap->rnr_enable) {
        po->bo_rnr = frm;
        temp_po = frm;
        frm = ieee80211_add_rnr_ie(frm, vap,
                vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);

        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_rnr,
                &frm, &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_rnr = NULL;
        temp_po = NULL;

        if (!is_mbssid_enabled || !ic->ic_mbss.ema_ext_enabled) {
            frm = ieee80211_add_6ghz_rnr_ie(ni, bo, frm,
                    &temp_po, IEEE80211_FC0_SUBTYPE_PROBE_RESP, true);
            if (!frm) {
                wbuf_release(ic->ic_osdev, wbuf);
                return NULL;
            }

            (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                    &available_rnr_space, IEEE80211_FRAME_TYPE_PROBERESP);
        } else {
            po->bo_rnr = po->bo_rnr2 = frm;
        }
    }

    /* 66. TVHT Operation */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_TVHT_OP, -1, &frm, &po->bo_tvht,
            &vap->iv_available_prb_cmn_space);

#if QCN_ESP_IE
    /* 67. Estimated Service Parameters */
    if (ic->ic_esp_periodicity){
        po->bo_esp_ie = frm;
        frm = ieee80211_add_esp_info_ie(frm, ic, &esp_ie_len);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_esp_ie, &frm,
                &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);
    }
#endif

    /* 68. Relay Capabilities */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_RELAY_CAP, -1, &frm, &po->bo_relay_cap,
            &vap->iv_available_prb_cmn_space);

    /* 69. Common Advertisement Group (CAG) Number */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_CAG_NUMBER, -1, &frm, &po->bo_cag_num,
            &vap->iv_available_prb_cmn_space);

    /* 70. FILS Indication */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_FILS_INDICATION, -1, &frm, &po->bo_fils_ind,
            &vap->iv_available_prb_cmn_space);

    /* 71. AP-CSN */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_AP_CSN, -1, &frm, &po->bo_ap_csn,
            &vap->iv_available_prb_cmn_space);

    /* 72. Differentiated Initial Link Setup */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1, &frm, &po->bo_diff_init_lnk,
            &vap->iv_available_prb_cmn_space);

    /* 73. RPS */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_RPS, -1, &frm, &po->bo_rps,
            &vap->iv_available_prb_cmn_space);

    /* 74. Page Slice */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_PAGE_SLICE, -1, &frm, &po->bo_page_slice,
            &vap->iv_available_prb_cmn_space);

    /* 75. Change Sequence */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_CHANGE_SEQ, -1, &frm, &po->bo_chan_seq,
            &vap->iv_available_prb_cmn_space);

    /* 76. TSF Timer Accuracy */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_TSF_TIMER_ACC, -1, &frm, &po->bo_tsf_timer_acc,
            &vap->iv_available_prb_cmn_space);

    /* 77. S1G Relay Discovery */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_S1G_RELAY_DISCOVREY, -1, &frm, &po->bo_s1g_relay_disc,
            &vap->iv_available_prb_cmn_space);

    /* 78. S1G Capabilities */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_S1G_CAP, -1, &frm, &po->bo_s1g_cap,
            &vap->iv_available_prb_cmn_space);

    /* 79. S1G Operation */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_S1G_OP, -1, &frm, &po->bo_s1g_op,
            &vap->iv_available_prb_cmn_space);

    /* 80. MAD */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_MAD, -1, &frm, &po->bo_mad,
            &vap->iv_available_prb_cmn_space);

    /* 81. Short Beacon Interval */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_SHORT_BEACON_INTVAL, -1, &frm, &po->bo_short_bcn_int,
            &vap->iv_available_prb_cmn_space);

    /* 82. S1G Open-Loop Link Margin Index */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_S1G_OPENLOOP_LINK_MARGIN, -1, &frm, &po->bo_s1g_openloop_idx,
            &vap->iv_available_prb_cmn_space);

    /* 83. S1G Relay element */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_S1G_RELAY, -1, &frm, &po->bo_s1g_relay,
            &vap->iv_available_prb_cmn_space);

    /* 85. CDMG Capaiblities */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_CDMG_CAP, &frm,
            &po->bo_cdmg_cap, &vap->iv_available_prb_cmn_space);

    /* 86. Extended Cluster Report */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_EXTENDED_CLUSTER_RPT,
            &frm, &po->bo_ext_cluster_rpt, &vap->iv_available_prb_cmn_space);

    /* 87. CMMG Capabilities */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_CMMG_CAP, &frm,
            &po->bo_cmmg_cap, &vap->iv_available_prb_cmn_space);

    /* 88. CMMG Operation */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_CMMG_OP, &frm,
            &po->bo_cmmg_op, &vap->iv_available_prb_cmn_space);

    /* 90. Service Hint */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HINT, &frm,
            &po->bo_service_hint, &vap->iv_available_prb_cmn_space);

    /* 91. Service Hash */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HASH, &frm,
            &po->bo_service_hash, &vap->iv_available_prb_cmn_space);

    /* 93. MBSSID Config */
    if (is_ema_ap_enabled) {
        po->bo_mbssid_config = frm;
        frm = ieee80211_add_mbssid_config(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, frm);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_mbssid_config, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_mbssid_config = NULL;
    }

    if (ieee80211_vap_wme_is_set(vap) &&  IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
         && ieee80211vap_heallowed(vap)) {
        /* 94. HE Capabilities */
        po->bo_hecap = frm;
        frm = ieee80211_add_hecap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_hecap, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

        /* 95. HE Operation */
        po->bo_heop = frm;
        frm = ieee80211_add_heop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, NULL);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_heop, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_hecap = NULL;
        po->bo_heop = NULL;
    }

    /* 96. TWT */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_TWT, -1, &frm, &po->bo_twt,
            &vap->iv_available_prb_cmn_space);

#if ATH_SUPPORT_UORA
    /* 97. UORA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
           ieee80211vap_heallowed(vap) &&
           IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
           ieee80211vap_uora_is_enabled(vap)) {
        po->bo_uora_param = frm;
        frm = ieee80211_add_uora_param(frm, vap->iv_ocw_range);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_uora_param,
                &frm, &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_uora_param = NULL;
    }
#endif

    /* 98. BSS Color Change Announcement */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_BSSCOLOR_CHG, &frm,
            &po->bo_bcca, &vap->iv_available_prb_cmn_space);

#if OBSS_PD
    /* 99. Spatial Reuse Parameters */
    if (ic->ic_he_sr_enable &&
        IEEE80211_IS_CHAN_11AX(ic->ic_curchan) && ieee80211vap_heallowed(vap)) {
        po->bo_srp_ie = frm;
        frm = ieee80211_add_srp_ie(vap, frm);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_srp_ie, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }
#endif

    /* 100. MU EDCA Parameter Set*/
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap)) {
        po->bo_muedca = frm;
        frm = ieee80211_add_muedca_param(frm, &vap->iv_muedcastate);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_muedca, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_muedca = NULL;
    }

    /* 101. ESS Report */
    po->bo_ess_rpt = frm;
    if (vap->iv_planned_ess) {
        frm = ieee80211_add_ess_rpt_ie(frm, vap);
    } else {
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                    IEEE80211_ELEMID_EXT_ESS_REPORT, &frm,
                    TYPE_ALL_BUF, NULL, true))
            po->bo_ess_rpt = NULL;
    }
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_ess_rpt, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

    /* 102. NDP Feedback Report Parameter */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM,
            &frm, &po->bo_ndp_rpt_param, &vap->iv_available_prb_cmn_space);

    /* 103. HE BSS Load */
    (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_HE_BSS_LOAD, &frm,
            &po->bo_he_bss_load, &vap->iv_available_prb_cmn_space);

    /* 104. HE 6GHz Band Capabilities */
    if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        po->bo_he_6g_bandcap = frm;
        frm = ieee80211_add_6g_bandcap(frm, ni, ic,
                        IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_he_6g_bandcap,
                &frm, &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_he_6g_bandcap = NULL;
    }

    /* Adding RSNX element here since no order is mentioned in
     * the specification
     */
    po->bo_rsnx = frm;
    if (vap->iv_sae_pwe != SAE_PWE_LOOP) {
        if (vap->iv_rsnx_override) {
            frm = ieee80211_rsnx_override(frm, vap);
        } else {
            if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                        IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RSNX,
                        -1, &frm, TYPE_ALL_BUF, NULL, true))
                po->bo_rsnx = NULL;
        }
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_rsnx, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

#if ATH_SUPPORT_WAPI
    /* WAPI IE
     * Added here since no order is mentioned in the specififcation */
    if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_WAPI)))
    {
        temp_po = frm;
        frm = ieee80211_setup_wapi_ie(vap, frm);
        if (!frm) {
            wbuf_release(ic->ic_osdev, wbuf);
            return NULL;
        }
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }
#endif

    /* Maximum channel Switch Time (MCST)
     * Added here since no order is mentioned in the specification*/
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && vap->iv_enable_max_ch_sw_time_ie) {
        struct ieee80211_max_chan_switch_time_ie *mcst_ie = NULL;

        temp_po = frm;
        mcst_ie = (struct ieee80211_max_chan_switch_time_ie *)frm;
        ieee80211_add_max_chan_switch_time(vap, (uint8_t *)mcst_ie);
        frm += IEEE80211_MAXCHANSWITCHTIME_BYTES;
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

    /* Secondary Channel Offset
     * Addedhere since no order is mentioned in
     * the specififcation
     */
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && (((IEEE80211_IS_CHAN_11N(vap->iv_bsschan)
                        || IEEE80211_IS_CHAN_11AC(vap->iv_bsschan)
                        || IEEE80211_IS_CHAN_11AX(vap->iv_bsschan))
                    && (ic->ic_chanchange_secoffset)) && ic->ic_sec_offsetie)) {
        struct ieee80211_ie_sec_chan_offset *sec_chan_offset_ie = NULL;

        temp_po = frm;
        sec_chan_offset_ie = (struct ieee80211_ie_sec_chan_offset *)frm;
        sec_chan_offset_ie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;

        /* Element has only one octet of info */
        sec_chan_offset_ie->len = 1;
        sec_chan_offset_ie->sec_chan_offset = ic->ic_chanchange_secoffset;
        frm += IEEE80211_SEC_CHAN_OFFSET_BYTES;
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

    /* ------------- LAST. Vendor IEs ------------- */
    /* Ath Advanced Capabilities */
    po->bo_ath_caps = frm;
    if (vap->iv_ena_vendor_ie == 1) {
        if (vap->iv_bss->ni_ath_flags) {
            frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
                    vap->iv_bss->ni_ath_defkeyindex);
        } else {
            frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
        }
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_ath_caps, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

    /* Ath Extended Capabilities */
    if (ic->ic_ath_extcap) {
        temp_po = frm;
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    }

#if DBDC_REPEATER_SUPPORT
    /* Extender */
    if (ic_list->same_ssid_support) {
        po->bo_extender_ie = frm;
        frm = ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_extender_ie,
                &frm, &vap->iv_available_prb_cmn_space,
                    IEEE80211_FRAME_TYPE_PROBERESP);
    }
#endif

    /* HT Capabilities and HT Info/Operation vendor IEs */
    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        (IEEE80211_IS_HTVIE_ENABLED(ic)) && enable_htrates) {

        temp_po = frm;
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

        po->bo_htinfo_vendor_specific = frm;
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
        (void)ieee80211_check_driver_tx_cmn_ie(vap,
                po->bo_htinfo_vendor_specific, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_htinfo_vendor_specific = NULL;
    }

    /* MBO */
    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        po->bo_mbo_cap = frm;
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_PROBE_RESP, vap, frm, ni);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_mbo_cap, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_mbo_cap = NULL;
    }

    /* Prop NSS IE if external NSS is not supported */
    if (!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv)
            && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask))  {
        po->bo_bwnss_map = frm;
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_bwnss_map,
                &frm, &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_bwnss_map = NULL;
    }

#if QCN_IE
    /* QCN IE for the feature set */
    po->bo_qcn_ie = frm;
    frm = ieee80211_add_qcn_info_ie(frm, vap, &ie_len,
                                    QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_qcn_ie, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
#endif

    /* SON Mode */
    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        (void)ieee80211_add_tx_ie_from_appie_buffer(vap, IEEE80211_FRAME_TYPE_PROBERESP,
                IEEE80211_ELEMID_VENDOR, IEEE80211_ELEMID_VENDOR_SON_AP, &frm,
                &po->bo_whc_apinfo, &vap->iv_available_prb_cmn_space);
    }

    /* WME Param */
    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_BTAMP)) {/* don't support WMM in ad-hoc for now */
        po->bo_wme = frm;
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
        (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_wme, &frm,
                &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        po->bo_wme = NULL;
    }

    /* Check if os shim has setup WPA IE itself */
    if (!vap->iv_rsn_override) {
        len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP,IEEE80211_ELEMID_VENDOR, 1, &frm,
                TYPE_ALL_BUF, NULL, true);
        if (len) {
            /* Remove WPA from frame so that it will be added
             * when other vendor IEs are added
             */
            frm -= len;
            qdf_mem_zero(frm, len);
        } else {

            /* WPA IE if not present in buffers*/
            if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                        (1 << WLAN_CRYPTO_AUTH_WPA))) {
                frm = wlan_crypto_build_wpaie(vap->vdev_obj, frm);
                if(!frm) {
                    wbuf_release(ic->ic_osdev, wbuf);
                    return NULL;
                }
            }
        }
    }

    /* Hardware and Software version */
    po->bo_software_version_ie = frm;
    frm = ieee80211_add_sw_version_ie(frm, ic);
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_software_version_ie,
            &frm, &vap->iv_available_prb_cmn_space,
            IEEE80211_FRAME_TYPE_PROBERESP);

    po->bo_generic_vendor_capabilities = frm;
    frm = ieee80211_add_generic_vendor_capabilities_ie(frm, ic);
    if(!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return NULL;
    }
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_generic_vendor_capabilities,
            &frm, &vap->iv_available_prb_cmn_space,
            IEEE80211_FRAME_TYPE_PROBERESP);

    /* ------------- App IE Buffer or list, and Optional IEs ------------- */
    po->bo_appie_buf = frm;
    po->bo_appie_buf_len = 0;
    len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_VENDOR, 0, &frm, TYPE_ALL_BUF,
            NULL, false);
    po->bo_appie_buf_len = len;
    (void)ieee80211_check_driver_tx_cmn_ie(vap, po->bo_appie_buf, &frm,
            &vap->iv_available_prb_cmn_space, IEEE80211_FRAME_TYPE_PROBERESP);

#if QCA_SUPPORT_EMA_EXT
    /* Populate MBSSID and RNR IEs */
    if (IS_MBSSID_EMA_EXT_ENABLED(ic)) {
        uint8_t *saved_bo_rnr = NULL;
        uint16_t offset = 0;

        /* Add MBSSID IE */
        po->bo_mbssid_ie_len =
            ieee80211_add_mbss_ie(frm, (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(orig_vap)) ?
                non_transmit_ni: ni, IEEE80211_FRAME_TYPE_PROBERESP, 0, NULL);

        /* Adjust offsets */
        if (po->bo_mbssid_ie_len) {
            frm = ieee80211_prb_adjust_pos_for_context(
                    ic, frm, po,
                    po->bo_mbssid_ie_len, IEEE80211_IE_OFFSET_CONTEXT_MBSSIE);
        }

        /* Add RNR IE */
        saved_bo_rnr = po->bo_rnr;
        temp_po = NULL;
        frm = ieee80211_add_6ghz_rnr_ie(ni, po, frm,
                &temp_po, IEEE80211_FC0_SUBTYPE_PROBE_RESP, true);
        if(!frm) {
            wbuf_release(ic->ic_osdev, wbuf);
            return NULL;
        }

        if (po->bo_rnr) {
            offset = frm - po->bo_rnr;
        } else if (po->bo_rnr2) {
            offset = frm - po->bo_rnr2;
        }

        if (offset) {
            if (po->bo_rnr2 && po->bo_rnr2 > po->bo_rnr)
                po->bo_rnr2 = saved_bo_rnr + (po->bo_rnr2 - po->bo_rnr);
            po->bo_rnr = saved_bo_rnr;

            /* Adjust offsets */
            if (temp_po &&
                    !ieee80211_check_driver_tx_cmn_ie(vap, temp_po, &frm,
                        &available_rnr_space, IEEE80211_FRAME_TYPE_PROBERESP)) {
                frm -= offset;
                frm = ieee80211_prb_adjust_pos_for_context(
                        ic, frm, po, offset, IEEE80211_IE_OFFSET_CONTEXT_RNRIE);
            }
        }
    }
#endif

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

    /* If wbuf's peer desc is already set to ni, then below is skipped.
     * If it is not set, then inc ref count and call wlan_wbuf_set_peer_node,
     * this happens first time wbuf is created and ni is set. On succesive
     * calls to ieee80211_prb_rsp_alloc_init, incrementing ref count can be
     * skipped as wlan_wbuf_set_peer_node is already set.
     */
    if (!is_buffer_preallocated) {
        ni = ieee80211_try_ref_node(ni, WLAN_MGMT_TX_ID);
        if (!ni) {
            wbuf_release(ic->ic_osdev, wbuf);
            return NULL;
        } else {
            wlan_wbuf_set_peer_node(wbuf, ni);
        }
    }

    return wbuf;

}

/*
 * Allocate a beacon frame and fillin the appropriate bits.
 */

wbuf_t
ieee80211_beacon_alloc(struct ieee80211_node *ni,
                       struct ieee80211_beacon_offsets *bo)
{
    wbuf_t wbuf;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_frame *wh;
    u_int8_t *frm;

    vap->iv_vap_up_in_progress = true;

    /*
     * For non-tx MBSS VAP, we reinitialize the beacon buffer of tx VAP
     * and return.
     */
    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ic->ic_mbss.transmit_vap);

        vap->iv_mbss.mbssid_update_ie = true;
        vap->iv_mbss.non_tx_profile_change = false;
        ic->ic_vdev_beacon_template_update(vap);
        return avn->av_wbuf;
    }

    if (ic && ic->ic_osdev) {
        wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_BEACON, MAX_TX_RX_PACKET_SIZE);
    } else {
        return NULL;
    }

    if (wbuf == NULL) {
        return NULL;
    }

    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
        IEEE80211_FC0_SUBTYPE_BEACON;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    *(u_int16_t *)wh->i_dur = 0;
    if(ic->ic_softap_enable){
        IEEE80211_ADDR_COPY(ni->ni_bssid, vap->iv_myaddr);
    }
    IEEE80211_ADDR_COPY(wh->i_addr1, IEEE80211_GET_BCAST_ADDR(ic));
    IEEE80211_ADDR_COPY(wh->i_addr2, vap->iv_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);
    *(u_int16_t *)wh->i_seq = 0;

    frm = (u_int8_t *)&wh[1];

    OS_MEMZERO(frm, IEEE80211_TSF_LEN); /* Clear TSF field */
    frm = ieee80211_beacon_init(ni, bo, frm);
    vap->iv_vap_up_in_progress = false;
    if (!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return NULL;
    }

    if (ieee80211_vap_copy_beacon_is_set(vap)) {
        store_beacon_frame(vap, (u_int8_t *)wh, (frm - (u_int8_t *)wh));
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *) wbuf_header(wbuf)));

    ni = ieee80211_try_ref_node(ni, WLAN_MGMT_TX_ID);
    if (!ni) {
        wbuf_release(ic->ic_osdev, wbuf);
        return NULL;
    } else {
        wlan_wbuf_set_peer_node(wbuf, ni);
    }

    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_MLME, vap->iv_myaddr,
                       "%s \n", __func__);

    return wbuf;
}


/*
 * Suspend or Resume the transmission of beacon for this SoftAP VAP.
 * @param vap           : vap pointer.
 * @param en_suspend    : boolean flag to enable or disable suspension.
 * @ returns 0 if success, others if failed.
 */
int
ieee80211_mlme_set_beacon_suspend_state(
    struct ieee80211vap *vap,
    bool en_suspend)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211com *ic = vap->iv_ic;
    int ret = 0;

    ASSERT(mlme_priv != NULL);
    if (en_suspend) {
        mlme_priv->im_beacon_tx_suspend++;
        /* Send beacon control command to disable beacon tx */
        if (ic->ic_beacon_offload_control) {
            ret = ic->ic_beacon_offload_control(vap, IEEE80211_BCN_OFFLD_TX_DISABLE);
        }
    }
    else {
        mlme_priv->im_beacon_tx_suspend--;
        /* Send beacon control command to enable beacon tx */
        if (ic->ic_beacon_offload_control) {
            ret = ic->ic_beacon_offload_control(vap, IEEE80211_BCN_OFFLD_TX_ENABLE);
        }
    }

    if (ret) {
        qdf_print("Failed to send beacon offload control message");
    }

    return ret;
}

bool
ieee80211_mlme_beacon_suspend_state(
    struct ieee80211vap *vap)
{
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

    ASSERT(mlme_priv != NULL);
    return (mlme_priv->im_beacon_tx_suspend != 0);
}

#if DYNAMIC_BEACON_SUPPORT
void ieee80211_mlme_set_dynamic_beacon_suspend(struct ieee80211vap *vap, bool suspend_beacon)
{
    if (vap->iv_dbeacon_runtime != suspend_beacon) {
        wlan_deauth_all_stas(vap); /* dissociating all associated stations */
    }
    if (!suspend_beacon ) { /* DFS channels */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Resume beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        OS_CANCEL_TIMER(&vap->iv_dbeacon_suspend_beacon);
        if (ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, false);
        }
        vap->iv_dbeacon_runtime = suspend_beacon;
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    } else { /* non DFS channels */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Suspend beacon \n");
        qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
        if (!ieee80211_mlme_beacon_suspend_state(vap)) {
            ieee80211_mlme_set_beacon_suspend_state(vap, true);
        }
        vap->iv_dbeacon_runtime = suspend_beacon;
        qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
    }
}
qdf_export_symbol(ieee80211_mlme_set_dynamic_beacon_suspend);
#endif

static void ieee80211_disconnect_sta_vap(struct wlan_objmgr_pdev *pdev,
                                         void *object, void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    QDF_STATUS status;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || vap->iv_opmode != IEEE80211_M_STA)
        return;

    if (mlme_get_active_req_type(vap) == MLME_REQ_TXCSA) {
        /* If Channel change is initiated by STAVAP then do not indicate mlme
         * sta radar detect (in other words do not disconnect the STA) since
         * STA VAP is trying to come up in a different channel and is doing the
         * Channel Switch, STA is yet to do CAC+ send probe req+ AUTH to the
         * Root AP.
         */
    } else {
        ic = vap->iv_ic;
        if (!(ic->ic_repeater_move.state == REPEATER_MOVE_START)) {
            status = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_OSIF_SCAN_ID);
            if (QDF_IS_STATUS_ERROR(status)) {
                scan_info("unable to get reference");
            } else {
                ucfg_scan_flush_results(pdev, NULL);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_OSIF_SCAN_ID);
            }

            /* Disconnect the main sta vap form RootAP, so that in Dependent mode
             * AP vap(s) automatically goes down. Main sta vap scans and connects
             * to the RootAP in the new channel.
             */
            ieee80211_indicate_sta_radar_detect(vap->iv_bss);
        }
    }
}

void ieee80211_send_chanswitch_complete_event(
        struct ieee80211com *ic)
{
    struct ieee80211vap *stavap;

    STA_VAP_DOWNUP_LOCK(ic);
    stavap = ic->ic_sta_vap;
    if(stavap) {
        /* Only for main STA send the chanswitch complete event */
          if (mlme_get_active_req_type(stavap) == MLME_REQ_TXCSA)
              IEEE80211_DELIVER_EVENT_MLME_TXCHANSWITCH_COMPLETE(
                    stavap, IEEE80211_STATUS_SUCCESS);
    }
    STA_VAP_DOWNUP_UNLOCK(ic);
}

static void ieee80211_beacon_change_channel(
        struct ieee80211vap *vap,
        struct ieee80211_ath_channel *c)
{
    struct ieee80211com *ic = vap->iv_ic;
    enum ieee80211_cwm_width ic_cw_width;
    enum ieee80211_cwm_width ic_cw_width_prev = ic->ic_cwm_get_width(ic);
    struct ieee80211vap *tmp_vap = NULL;
    struct ieee80211vap *transmit_vap = NULL;

    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        transmit_vap = ic->ic_mbss.transmit_vap;
    }

    ic_cw_width = ic->ic_cwm_get_width(ic);

    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
        if(tmp_vap->iv_opmode == IEEE80211_M_HOSTAP ||
                tmp_vap->iv_opmode == IEEE80211_M_STA  ||
                tmp_vap->iv_opmode == IEEE80211_M_MONITOR) {

            tmp_vap->iv_bsschan = c;
            tmp_vap->iv_des_chan[tmp_vap->iv_des_mode] = c;
            tmp_vap->iv_cur_mode = ieee80211_chan2mode(c);
            tmp_vap->iv_chanchange_count = 0;
            ieee80211vap_clear_flag(tmp_vap, IEEE80211_F_CHANSWITCH);

            /* When MBSSIE FR is enabled, set iv_remove_csa_ie flag only for
             * transmitting vap. Based on this flag beacon template is sent to
             * FW in CSA event handler. Do not set iv_remove_csa_ie flag for
             * non-transmitting vaps, as Host does not send CSA template to FW
             * for these vaps.
             * When MBSSIE FR is disabled, host sends CSA template for all the
             * vaps to FW. Therefore set iv_remove_csa_ie for all the vaps. In
             * this case transmit_vap is NULL.
             */
            if (!transmit_vap || (tmp_vap == transmit_vap))
                tmp_vap->iv_remove_csa_ie = true;

            tmp_vap->iv_no_restart = false;

            if ((tmp_vap->iv_opmode == IEEE80211_M_STA) &&
                    !(IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(c)))
                ieee80211_node_set_chan(tmp_vap->iv_bss);

            /*
             * If multiple vdev restart is supported,channel_switch_set_channel
             * should not be called in CSA case. Check ic_csa_num_vdevs before
             * calling channel_switch_set_channel.
             *
             *
             * If in Rep Independent mode we get a channel change from
             * CAP, set channel for sta vap's, only if it is not in DFS chan.
             * This prevents a case in which STA vap assoc state machine
             * was going into bad state. The reason being, when sta vap moves
             * to DFS channel it sends disconnet notifiction to supplicant but
             * we were doing vap reset before a proper reply hence causing bad
             * state.
             */
            if (!((IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(c)) &&
                   ieee80211_is_cac_required_in_rep_ap(vap, c) &&
                   tmp_vap->iv_opmode == IEEE80211_M_STA) &&
                   (wlan_vdev_is_up(tmp_vap->vdev_obj) == QDF_STATUS_SUCCESS)) {

                if (tmp_vap->iv_opmode == IEEE80211_M_STA) {
                      wlan_pdev_mlme_vdev_sm_seamless_chan_change(ic->ic_pdev_obj,
                                                         tmp_vap->vdev_obj, c);
                }
                else {
                     wlan_vdev_mlme_sm_deliver_evt(tmp_vap->vdev_obj,
                                        WLAN_VDEV_SM_EV_CSA_COMPLETE, 0, NULL);
                }

                /* In case of MBSSID, channel_switch_set_channel() is called in
                 * the for loop for all the vaps. Before receiving the start
                 * response for a vap(say vap-A) ieee80211_beacon_update() for
                 * vap-B is called and vap-B reinits the beacon and sets
                 * channel_switch_state = 0. Hence the vap-A skips the CAC on
                 * reception of vdev_start response from FW in
                 * ieee80211_dfs_cac_start(). Once vap-A skips the CAC it enters
                 * RUN state and therefore  all other vaps skip the CAC.
                 *
                 * To fix the above problem, after channel change clear
                 * vap_active flag for all the vaps and do not send beacon if
                 * vap_active flag is cleared.
                 */
            }

            if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) &&
                    vap->iv_unit != tmp_vap->iv_unit)
                tmp_vap->channel_change_done = 1;

            /* Channel width changed.
             * Update BSS node with the new channel width.
             */
            if((ic_cw_width_prev != ic_cw_width) && (tmp_vap->iv_bss != NULL) &&
               (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_F_MULTIVDEV_RESTART) ||
                              (ic->ic_csa_num_vdevs == 0))) {
                tmp_vap->iv_bss->ni_chwidth = ic->ic_cwm_get_width(ic);
                ic->ic_chwidth_change(tmp_vap->iv_bss);
            }
        }
    }
}

#define IS_CAC_REQUIRED_FOR_THIS_AP(_pdev, _c, _ic, _is_cac_continuable) \
    mlme_dfs_is_cac_required(_pdev, _c, _ic->ic_curchan, &_is_cac_continuable)
/* **** Channel Switch Algorithm **** *
 * New channel Non-DFS:-
 * 1)Do instant channel change for all vaps.
 *
 * New channel DFS:-
 * 1)Bring down the main STA VAP if present. In dependent mode the STA
 *   brings down the AP VAP(s) and, when re-connected, it brings up AP
 *   VAP(s).
 * 2)If main STA is not present or in independent mode, then
 *   do instant channel change for all VAPs. The channel change
 *   takes care of the CAC automatically.
 *
 * Two types of channel change:-
 * 1)Channel change driven by CSA from root AP
 * 2)Channel change by (A) RADAR or (B) user channel change
 */

/* ieee80211_is_cac_required_in_rep_ap() - Check if CAC is needed on target
 * channel in case of a Repeater VAP.
 * @vap: Pointer to ieee80211_vap structure.
 * @c: Target channel.
 *
 * Change to target channel without CAC if:
 *  A] If root can avoid CAC
 *            and
 *  B] If this AP vap can avoid CAC
 */
bool ieee80211_is_cac_required_in_rep_ap(struct ieee80211vap *vap,
                                         struct ieee80211_ath_channel *c)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    bool is_cac_continuable;

    if (ic->ic_has_rootap_done_cac &&
        !IS_CAC_REQUIRED_FOR_THIS_AP(pdev, c, ic, is_cac_continuable))
        return false;

    return true;
}

static void ieee80211_beacon_channel_change(struct wlan_objmgr_pdev *pdev,
                                            void *object, void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
    struct ieee80211_ath_channel *c = (struct ieee80211_ath_channel *)arg;
    struct ieee80211vap *vap = wlan_vdev_get_mlme_ext_obj(vdev);

    if (!vap)
        return;

    /* If user triggers CSA on Repeater AP and delete for Repeater STA vap, as
     * the CSA restart is ser blocking cmd, the STOP_BSS for STA vap is added
     * in pending queue. The STA vap is removed from ic_vaps list, so the
     * Down/Restart is not triggered from CSA event handler. Deliver Restart
     * event to sta vap which is in up state and has vap_deleted set if cac is
     * not required on rep_ap
     */

    if ((vap->iv_opmode == IEEE80211_M_STA) && ieee80211_vap_deleted_is_set(vap)) {
        if (wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS) {
            vap->iv_bsschan = c;
            vap->iv_des_chan[vap->iv_des_mode] = c;
            vap->iv_cur_mode = ieee80211_chan2mode(c);
            vap->iv_chanchange_count = 0;
            ieee80211vap_clear_flag(vap, IEEE80211_F_CHANSWITCH);

            if (!(IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(c)))
                ieee80211_node_set_chan(vap->iv_bss);

            wlan_pdev_mlme_vdev_sm_seamless_chan_change(pdev, vdev, c);
        }
    }
}

static void inline ieee80211_chan_switch_to_new_chan(
        struct ieee80211vap *vap,
        struct ieee80211_ath_channel *c)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211vap *stavap = NULL;
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vap->vdev_obj);

    if (!pdev)
    {
        qdf_err("Pdev is NULL");
        return;
    }

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"%s: Prev Chan=%u freq %d New Chan=%u freq %d mainsta=%pk enh_ind=%u\n",
            __func__,ic->ic_curchan->ic_ieee,ic->ic_curchan->ic_freq,
            c->ic_ieee,c->ic_freq,ic->ic_sta_vap,
            ieee80211_ic_enh_ind_rpt_is_set(ic));
    if (!ieee80211_is_cac_required_in_rep_ap(vap, c)) {
        /* If CAC need not be started in RE-AP, do instant channel change in both
         * dependent and independent mode.
         */
        ieee80211_beacon_change_channel(vap, c);
        wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
                                          ieee80211_beacon_channel_change,
                                          c, 0, WLAN_MLME_SB_ID);
    } else {
        STA_VAP_DOWNUP_LOCK(ic);
        stavap = ic->ic_sta_vap;        
        wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
                                          ieee80211_disconnect_sta_vap,
                                          NULL, 0, WLAN_MLME_SB_ID);
        if(ieee80211_ic_enh_ind_rpt_is_set(ic) || !stavap ||
           (ic->ic_repeater_move.state == REPEATER_MOVE_START)) {
            STA_VAP_DOWNUP_UNLOCK(ic);
            ieee80211_beacon_change_channel(vap, c);
        } else {
            STA_VAP_DOWNUP_UNLOCK(ic);
        }
    }

    ieee80211_send_chanswitch_complete_event(ic);
}

/* This function adds the Maximum Channel Switch Time IE in the beacon
 *
 * "This element is optionally present in Beacon and Probe Response frames
 * when a Channel Switch Announcement or Extended Channel Switch Announcement
 * element is also present." -- Quote from ieee80211 standard
 *
 * "The Max Channel Switch Time element indicates the time delta between
 * the time the last beacon is transmitted by the AP in the current channel
 * and the expected time of the first beacon transmitted by the AP
 * in the new channel". -- Quote from ieee80211 standard
 *
 *@frm: pointer to the beacon where the IE should be written
 *@max_time: The time delta between  the last beacon TXed in the current
 *           channel and the first beacon in the new channel. In TUs.
 */
static inline void ieee80211_add_max_chan_switch_time_ie(
        uint8_t *frm,
        uint32_t max_time)
{
    struct ieee80211_max_chan_switch_time_ie *max_chan_switch_time_ie;
    uint8_t i;

    max_chan_switch_time_ie = (struct ieee80211_max_chan_switch_time_ie *) frm;
    max_chan_switch_time_ie->elem_id = IEEE80211_ELEMID_EXTN;
    max_chan_switch_time_ie->elem_len = MAX_CHAN_SWITCH_TIME_IE_LEN;
    max_chan_switch_time_ie->elem_id_ext = IEEE80211_ELEMID_EXT_MAX_CHAN_SWITCH_TIME;

    /* Pack the max_time in 3 octets/bytes. Little endian format */
    for(i = 0; i < SIZE_OF_MAX_TIME_INT; i++) {
        max_chan_switch_time_ie->switch_time[i] = (max_time & ONE_BYTE_MASK);
        max_time = (max_time >> BITS_IN_A_BYTE);
    }
}

void ieee80211_add_max_chan_switch_time(struct ieee80211vap *vap, uint8_t *frm)
{
    struct ieee80211com *ic = vap->iv_ic;
    int cac_timeout = 0;
    uint32_t max_switch_time_in_ms = 0;
    uint32_t max_switch_time_in_tu = 0;
    uint32_t cac_in_ms = 0;
    bool is_cac_continuable;
    uint32_t beacon_interval_in_ms = (uint32_t)ieee80211_vap_get_beacon_interval(vap);
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;

    if (!mlme_dfs_is_cac_required(pdev,
                                  ic->ic_chanchange_channel,
                                  ic->ic_curchan,
                                  &is_cac_continuable)) {
        cac_in_ms = 0;
    } else {
        cac_timeout = ieee80211_dfs_get_cac_timeout(ic, ic->ic_chanchange_channel);
        cac_in_ms = cac_timeout * 1000;
    }

    max_switch_time_in_ms = cac_in_ms + beacon_interval_in_ms;
    if(ic->ic_mcst_of_rootap > max_switch_time_in_ms)
    {
        max_switch_time_in_ms = ic->ic_mcst_of_rootap;
    }
    max_switch_time_in_tu = IEEE80211_MS_TO_TU(max_switch_time_in_ms);

    /* Add Maximum Channel Switch Time IE */
    ieee80211_add_max_chan_switch_time_ie(frm, max_switch_time_in_tu);
}

static void inline ieee80211_add_channel_switch_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_extendedchannelswitch_ie *ecsa_ie = NULL;
    struct ieee80211_max_chan_switch_time_ie *mcst_ie = NULL;
    uint8_t *tempbuf;
    uint16_t behav_lim = 0;
    uint16_t chan_width;
    uint8_t *csa_ies = NULL, *t_csa_ies = NULL;
    uint16_t total_len = 0;
    bool global_look_up = false;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
            WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool bcn_size_check = false;

    /* While IEEE80211_F_CHANSWITCH is set, insert chan switch IEs in 2 cases
     * 1) Adding the CSA IE for the first time
     * 2) We haven't sent out all the CSAs, but beacon reinit happens.
     */

    mbss_debug("vap_id: %d iv_chanchange_count: %d"
            " beacon_reinit_done: %d", vap->iv_unit,
            vap->iv_chanchange_count, vap->beacon_reinit_done);

    if (!vap->iv_chanchange_count || vap->beacon_reinit_done) {

        uint8_t csmode;
        uint8_t vhtchnsw_ielen;
        /* the length of csa, ecsa and max chan switch time(mcst),
         * secondary channel offset and channel switch wrapper IEs is represented
         * by csa_ecsa_mcst_len, but it is initialised with 0 and based on
         * the presence of IEs, the length is increased.
         */
        uint8_t csa_ecsa_mcst_len;

        csa_ies = qdf_mem_malloc(IEEE80211_CHANSWITCHANN_BYTES + IEEE80211_EXTCHANSWITCHANN_BYTES +
                IEEE80211_MAX_IE_LEN + IEEE80211_MAXCHANSWITCHTIME_BYTES +
                IEEE80211_SEC_CHAN_OFFSET_BYTES);
        if (!csa_ies) {
            goto exit;
        }

        t_csa_ies = csa_ies;
        csmode = IEEE80211_CSA_MODE_STA_TX_ALLOWED;
        vhtchnsw_ielen = 0;
        csa_ecsa_mcst_len = 0;

        if (vap->iv_csmode == IEEE80211_CSA_MODE_AUTO) {

            /* No user preference for csmode. Use default behavior.
             * If chan swith is triggered because of radar found,
             * ask associated stations to stop transmission by
             * sending csmode as 1 else let them transmit as usual
             * by sending csmode as 0.
             */
            if (ic->ic_flags & IEEE80211_F_DFS_CHANSWITCH_PENDING) {
                /* Request STA's to stop transmission */
                csmode = IEEE80211_CSA_MODE_STA_TX_RESTRICTED;
            }
        } else {
            /* User preference for csmode is configured.
             * Use user preference.
             */
            csmode = vap->iv_csmode;
        }

        /* Channel Switch Announcement IE */
        if (bo->bo_chanswitch[0] != IEEE80211_ELEMID_CHANSWITCHANN) {
            t_csa_ies[0] = IEEE80211_ELEMID_CHANSWITCHANN;
            t_csa_ies[1] = 3; /* fixed length */
            t_csa_ies[2] = csmode;
            t_csa_ies[3] = wlan_reg_freq_to_chan(ic->ic_pdev_obj, ic->ic_chanchange_chan_freq);
            t_csa_ies[4] = ic->ic_chanchange_tbtt - vap->iv_chanchange_count;
            total_len += IEEE80211_CHANSWITCHANN_BYTES;
        }

        /* Extended Channel Switch Announcement IE
         * Check for ecsa_ie pointer instead of ic->ic_ecsaie flag
         * to avoid ic->ic_ecsaie being updated in between from IOCTL
         * ontext
         */
        if (vap->iv_enable_ecsaie) {
            ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)(t_csa_ies + total_len);
            ecsa_ie->ie = IEEE80211_ELEMID_EXTCHANSWITCHANN;
            ecsa_ie->len = 4;
            ecsa_ie->switchmode = csmode;

            /* If user configured opClass is set, use it else
             * calculate new opClass from destination channel.
             */
            if (vap->iv_ecsa_opclass) {
                ecsa_ie->newClass = vap->iv_ecsa_opclass;
                ecsa_ie->newchannel =
                    wlan_reg_freq_to_chan(ic->ic_pdev_obj,
                                          ic->ic_chanchange_chan_freq);
            } else {
                /* Channel look-up tables should not change with CSA */
                global_look_up = false;
                wlan_get_bw_and_behav_limit(ic->ic_chanchange_channel,
                                            &chan_width, &behav_lim);

                if (!behav_lim) {
                    goto free_exit;
                }
                /* Get new OpClass and Channel number from regulatory */
                wlan_reg_freq_width_to_chan_op_class_auto(ic->ic_pdev_obj,
                                                          ic->ic_chanchange_chan_freq,
                                                          chan_width,
                                                          global_look_up, behav_lim,
                                                          &ecsa_ie->newClass,
                                                          &ecsa_ie->newchannel);
            }

            ecsa_ie->tbttcount = ic->ic_chanchange_tbtt;
            total_len += IEEE80211_EXTCHANSWITCHANN_BYTES;
        }

        /* Channel Switch Wrapper IE */
        if ((IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
                IEEE80211_IS_CHAN_11AXA(vap->iv_bsschan)) &&
                ieee80211vap_vht_or_above_allowed(vap)
                && (ic->ic_chanchange_channel != NULL) &&
                (bo->bo_vhtchnsw != NULL)) {

            uint8_t *vhtchnsw_ie;

            /* Adding channel switch wrapper element */
            vhtchnsw_ie = ieee80211_add_chan_switch_wrp(t_csa_ies + total_len,
                    ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                    /* When switching to new country by sending ECSA IE,
                     * new country IE should be also be added.
                     * As of now we dont support switching to new country
                     * without bringing down vaps so new country IE is not
                     * required.
                     */
                    (/*ecsa_ie ? IEEE80211_VHT_EXTCH_SWITCH :*/
                     !IEEE80211_VHT_EXTCH_SWITCH));
            vhtchnsw_ielen = (vhtchnsw_ie - (t_csa_ies + total_len));
            total_len += (vhtchnsw_ie - (t_csa_ies + total_len));
        }

        /* Max Channel Switch Time IE */
        if (vap->iv_enable_max_ch_sw_time_ie) {
            mcst_ie = (struct ieee80211_max_chan_switch_time_ie *)(t_csa_ies + total_len);
            ieee80211_add_max_chan_switch_time(vap, (uint8_t *)mcst_ie);
            total_len += IEEE80211_MAXCHANSWITCHTIME_BYTES;
        }

        /* Secondary Channel Offset IE
         * Add secondary channel offset element if new channel has
         * secondary 20 MHz channel
         */
        if (((IEEE80211_IS_CHAN_11N(vap->iv_bsschan) ||
                        IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
                        IEEE80211_IS_CHAN_11AX(vap->iv_bsschan)) &&
                    (ic->ic_chanchange_secoffset)) &&
                ic->ic_sec_offsetie && bo->bo_secchanoffset) {
            struct ieee80211_ie_sec_chan_offset *sec_chan_offset_ie = NULL;

            sec_chan_offset_ie = (struct ieee80211_ie_sec_chan_offset *)
                                        (t_csa_ies + total_len);
            sec_chan_offset_ie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;

            /* Element has only one octet of info */
            sec_chan_offset_ie->len = 1;
            sec_chan_offset_ie->sec_chan_offset =
                ic->ic_chanchange_secoffset;

            total_len += IEEE80211_SEC_CHAN_OFFSET_BYTES;
        }

        if (IS_MBSSID_EMA_EXT_ENABLED(ic) &&
                !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            if (vap->iv_available_bcn_cmn_space - total_len < 0)
                goto free_exit;
            else
                vap->iv_available_bcn_cmn_space -= total_len;
            bcn_size_check = true;
        }

        /* Add the IEs */
        if (t_csa_ies[0] == IEEE80211_ELEMID_CHANSWITCHANN) {
            ieee80211vap_set_flag(vap, IEEE80211_F_CHANSWITCH);
            vap->channel_switch_state = 1;

            /* Copy out trailer to open up a slot */
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_chanswitch_trailerlen);
            if (!tempbuf) {
                mbss_info(":<");
                qdf_print("%s : tempbuf is NULL", __func__);

                if (bcn_size_check)
                    vap->iv_available_bcn_cmn_space += total_len;

                goto free_exit;
            }
            qdf_mem_zero(tempbuf, bo->bo_chanswitch_trailerlen);
            qdf_mem_copy(tempbuf, bo->bo_chanswitch,
                    bo->bo_chanswitch_trailerlen);
            qdf_mem_copy(bo->bo_chanswitch + IEEE80211_CHANSWITCHANN_BYTES,
                    tempbuf, bo->bo_chanswitch_trailerlen);
            qdf_mem_free(tempbuf);

            qdf_mem_copy(bo->bo_chanswitch, t_csa_ies, IEEE80211_CHANSWITCHANN_BYTES);
            t_csa_ies += IEEE80211_CHANSWITCHANN_BYTES;
            csa_ecsa_mcst_len += IEEE80211_CHANSWITCHANN_BYTES;

            if (is_mbssid_enabled) {
                /* If we set iv_bcn_csa_tmp_sent flag non-transmitting vap,
                 * host will be waiting for CSA complete event for
                 * non-transmitting vap. Since FW sends CSA complete only for
                 * transmitting vap and not for non-transmitting vap, host waits
                 * and does not restart the vaps. This leads to beacon stuck
                 * issue. Therefore set iv_bcn_csa_tmp_sent flag only for
                 * transmitting vap.
                 */
                if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap))
                    vap->iv_bcn_csa_tmp_sent = true;
                else {
                    bool is_ema_ap_enabled =
                        wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_FEXT_EMA_AP_ENABLE);

                    if (is_ema_ap_enabled && ic->ic_mbss.current_pp > 1)
                        vap->iv_bcn_csa_tmp_sent = true;
                    else
                        vap->iv_bcn_csa_tmp_sent = false;
                }
            } else {
                vap->iv_bcn_csa_tmp_sent = true;
            }

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
                    "%s : %d Add CSA IE, iv_bcn_csa_tmp_sent = %d vap = %d (%s) chan freq = %d\n",
                    __func__, __LINE__, vap->iv_bcn_csa_tmp_sent, vap->iv_unit,
                    vap->iv_netdev_name, ic->ic_chanchange_chan_freq);

            if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                        WLAN_PDEV_F_MBSS_IE_ENABLE)) {
                mbss_info(
                    "%s : %d Add CSA IE, iv_bcn_csa_tmp_sent = %d vap = %d (%s) chan freq = %d\n",
                    __func__, __LINE__, vap->iv_bcn_csa_tmp_sent, vap->iv_unit,
                    vap->iv_netdev_name, ic->ic_chanchange_chan_freq);
            }

            /* Adjust trailer, buffer offsets between CSA and ECSA */
            bo->bo_chanswitch_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;
            bo->bo_tim_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;
            bo->bo_bcca_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += IEEE80211_CHANSWITCHANN_BYTES;
#endif /* UMAC_SUPPORT_WNM */
        }

        if (bo->bo_quiet)
            bo->bo_quiet += csa_ecsa_mcst_len;

        if (bo->bo_tpcreport) {
            bo->bo_tpcreport += csa_ecsa_mcst_len;
        }

        if (bo->bo_erp)
            bo->bo_erp += csa_ecsa_mcst_len;

        if (bo->bo_xrates)
            bo->bo_xrates += csa_ecsa_mcst_len;

        if (bo->bo_rsn)
            bo->bo_rsn += csa_ecsa_mcst_len;

        if (bo->bo_qbssload)
            bo->bo_qbssload += csa_ecsa_mcst_len;

        if (bo->bo_edca)
            bo->bo_edca += csa_ecsa_mcst_len;

        if (bo->bo_qos_cap)
            bo->bo_qos_cap += csa_ecsa_mcst_len;

        if (bo->bo_ap_chan_rpt)
            bo->bo_ap_chan_rpt += csa_ecsa_mcst_len;

        if (bo->bo_bss_avg_delay)
            bo->bo_bss_avg_delay += csa_ecsa_mcst_len;

        if (bo->bo_antenna)
            bo->bo_antenna += csa_ecsa_mcst_len;

        if (bo->bo_bss_adm_cap)
            bo->bo_bss_adm_cap += csa_ecsa_mcst_len;

#if !ATH_SUPPORT_WAPI
        if (bo->bo_bss_ac_acc_delay)
            bo->bo_bss_ac_acc_delay += csa_ecsa_mcst_len;
#endif

        if (bo->bo_msmt_pilot_tx)
            bo->bo_msmt_pilot_tx += csa_ecsa_mcst_len;

        if (bo->bo_mbssid_ie)
                bo->bo_mbssid_ie += csa_ecsa_mcst_len;

        if (bo->bo_rrm)
            bo->bo_rrm += csa_ecsa_mcst_len;

        if (bo->bo_mob_domain)
            bo->bo_mob_domain += csa_ecsa_mcst_len;

        if (bo->bo_dse_reg_loc)
            bo->bo_dse_reg_loc += csa_ecsa_mcst_len;

        bo->bo_ecsa += csa_ecsa_mcst_len;

        if (t_csa_ies[0] == IEEE80211_ELEMID_EXTCHANSWITCHANN) {
            /* Copy out trailer to open up a slot */
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_ecsa_trailerlen);
            if (tempbuf) {
                qdf_mem_zero(tempbuf, bo->bo_ecsa_trailerlen);
                ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *) bo->bo_ecsa;
                qdf_mem_copy(tempbuf, bo->bo_ecsa,
                        bo->bo_ecsa_trailerlen);
                qdf_mem_copy(bo->bo_ecsa + IEEE80211_EXTCHANSWITCHANN_BYTES,
                        tempbuf, bo->bo_ecsa_trailerlen);
                qdf_mem_free(tempbuf);

                qdf_mem_copy(bo->bo_ecsa, t_csa_ies, IEEE80211_EXTCHANSWITCHANN_BYTES);
                csa_ecsa_mcst_len += IEEE80211_EXTCHANSWITCHANN_BYTES;

                /* Adjust trailers if ECSA is added */
                bo->bo_chanswitch_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
                bo->bo_tim_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
                bo->bo_ecsa_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
                bo->bo_bcca_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;

#if UMAC_SUPPORT_WNM
                bo->bo_fms_trailerlen += IEEE80211_EXTCHANSWITCHANN_BYTES;
#endif /* UMAC_SUPPORT_WNM */
            } else {
                if (bcn_size_check)
                    vap->iv_available_bcn_cmn_space += IEEE80211_EXTCHANSWITCHANN_BYTES;
            }
            t_csa_ies += IEEE80211_EXTCHANSWITCHANN_BYTES;
        }

        /* Adjust buffer offsets between ECSA and CSA Wrapper */
        if (bo->bo_opt_class)
            bo->bo_opt_class += csa_ecsa_mcst_len;

        if (bo->bo_htcap)
            bo->bo_htcap += csa_ecsa_mcst_len;

        if (bo->bo_htinfo)
            bo->bo_htinfo += csa_ecsa_mcst_len;

        if (bo->bo_2040_coex)
            bo->bo_2040_coex += csa_ecsa_mcst_len;

        if (bo->bo_obss_scan)
            bo->bo_obss_scan += csa_ecsa_mcst_len;

        if (bo->bo_extcap)
            bo->bo_extcap += csa_ecsa_mcst_len;

#if UMAC_SUPPORT_WNM
        if (bo->bo_fms_desc)
            bo->bo_fms_desc += csa_ecsa_mcst_len;

        if (bo->bo_fms_trailer)
            bo->bo_fms_trailer += csa_ecsa_mcst_len;
#endif
        if (bo->bo_qos_traffic)
            bo->bo_qos_traffic += csa_ecsa_mcst_len;

        if (bo->bo_time_adv)
            bo->bo_time_adv += csa_ecsa_mcst_len;

        if (bo->bo_interworking)
            bo->bo_interworking += csa_ecsa_mcst_len;

        if (bo->bo_adv_proto)
            bo->bo_adv_proto += csa_ecsa_mcst_len;

        if (bo->bo_roam_consortium)
            bo->bo_roam_consortium += csa_ecsa_mcst_len;

        if (bo->bo_emergency_id)
            bo->bo_emergency_id  += csa_ecsa_mcst_len;

        if (bo->bo_mesh_id)
            bo->bo_mesh_id += csa_ecsa_mcst_len;

        if (bo->bo_mesh_conf)
            bo->bo_mesh_conf += csa_ecsa_mcst_len;

        if (bo->bo_mesh_awake_win)
            bo->bo_mesh_awake_win += csa_ecsa_mcst_len;

        if (bo->bo_beacon_time)
            bo->bo_beacon_time += csa_ecsa_mcst_len;

        if (bo->bo_mccaop_adv_ov)
            bo->bo_mccaop_adv_ov += csa_ecsa_mcst_len;

        if (bo->bo_mccaop_adv)
            bo->bo_mccaop_adv += csa_ecsa_mcst_len;

        if (bo->bo_mesh_cs_param)
            bo->bo_mesh_cs_param += csa_ecsa_mcst_len;

        if (bo->bo_qmf_policy)
            bo->bo_qmf_policy += csa_ecsa_mcst_len;

        if (bo->bo_qload_rpt)
            bo->bo_qload_rpt += csa_ecsa_mcst_len;

        if (bo->bo_hcca_upd_cnt)
            bo->bo_hcca_upd_cnt += csa_ecsa_mcst_len;

        if (bo->bo_multiband)
            bo->bo_multiband += csa_ecsa_mcst_len;

        if (bo->bo_vhtcap)
            bo->bo_vhtcap += csa_ecsa_mcst_len;

        if (bo->bo_vhtop)
            bo->bo_vhtop += csa_ecsa_mcst_len;

        if (bo->bo_vhttxpwr)
            bo->bo_vhttxpwr += csa_ecsa_mcst_len;

        if (bo->bo_vhtchnsw)
            bo->bo_vhtchnsw += csa_ecsa_mcst_len;

        /* Filling channel switch wrapper element */
        if (t_csa_ies[0] == IEEE80211_ELEMID_CHAN_SWITCH_WRAP) {

            /* Copy out trailer to open up a slot */
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_vhtchnsw_trailerlen);

            if(tempbuf != NULL) {
                qdf_mem_zero(tempbuf, bo->bo_vhtchnsw_trailerlen);
                qdf_mem_copy(tempbuf, bo->bo_vhtchnsw, bo->bo_vhtchnsw_trailerlen);
                qdf_mem_copy(bo->bo_vhtchnsw + vhtchnsw_ielen, tempbuf, bo->bo_vhtchnsw_trailerlen);
                qdf_mem_free(tempbuf);

                qdf_mem_copy(bo->bo_vhtchnsw, t_csa_ies, vhtchnsw_ielen);
                csa_ecsa_mcst_len += vhtchnsw_ielen;

                /* Adjusting trailers */
                bo->bo_tim_trailerlen += vhtchnsw_ielen;
                bo->bo_chanswitch_trailerlen += vhtchnsw_ielen;
                bo->bo_ecsa_trailerlen += vhtchnsw_ielen;
                bo->bo_vhtchnsw_trailerlen += vhtchnsw_ielen;
                bo->bo_bcca_trailerlen += vhtchnsw_ielen;

#if UMAC_SUPPORT_WNM
                bo->bo_fms_trailerlen += vhtchnsw_ielen;
#endif /* UMAC_SUPPORT_WNM */
            } else {
                if (bcn_size_check)
                    vap->iv_available_bcn_cmn_space += vhtchnsw_ielen;
            }
            t_csa_ies += vhtchnsw_ielen;
        }

        /* Adjust buffer offsets between CSA Wrapper and MCST */
        if (bo->bo_ext_bssload)
            bo->bo_ext_bssload += csa_ecsa_mcst_len;

        if (bo->bo_quiet_chan)
            bo->bo_quiet_chan += csa_ecsa_mcst_len;

        if (bo->bo_opt_mode_note)
            bo->bo_opt_mode_note += csa_ecsa_mcst_len;

        if (bo->bo_rnr)
            bo->bo_rnr += csa_ecsa_mcst_len;

        if (bo->bo_rnr2)
            bo->bo_rnr2 += csa_ecsa_mcst_len;

        if (bo->bo_tvht)
            bo->bo_tvht += csa_ecsa_mcst_len;


#if QCN_ESP_IE
        if (bo->bo_esp_ie)
            bo->bo_esp_ie += csa_ecsa_mcst_len;
#endif

        if (bo->bo_future_chan)
            bo->bo_future_chan += csa_ecsa_mcst_len;

        if (bo->bo_cag_num)
            bo->bo_cag_num += csa_ecsa_mcst_len;

        if (bo->bo_fils_ind)
            bo->bo_fils_ind += csa_ecsa_mcst_len;

        if (bo->bo_ap_csn)
            bo->bo_ap_csn += csa_ecsa_mcst_len;

        if (bo->bo_diff_init_lnk)
            bo->bo_diff_init_lnk += csa_ecsa_mcst_len;

        if (bo->bo_service_hint)
            bo->bo_service_hint += csa_ecsa_mcst_len;

        if (bo->bo_service_hash)
            bo->bo_service_hash += csa_ecsa_mcst_len;

        if (bo->bo_hecap)
            bo->bo_hecap += csa_ecsa_mcst_len;

        if (bo->bo_heop)
            bo->bo_heop += csa_ecsa_mcst_len;

        if (bo->bo_twt)
            bo->bo_twt += csa_ecsa_mcst_len;

#if ATH_SUPPORT_UORA
        if (bo->bo_uora_param)
            bo->bo_uora_param += csa_ecsa_mcst_len;
#endif

        if (bo->bo_bcca)
            bo->bo_bcca += csa_ecsa_mcst_len;

#if OBSS_PD
        if(bo->bo_srp_ie)
            bo->bo_srp_ie += csa_ecsa_mcst_len;
#endif

        if (bo->bo_muedca)
            bo->bo_muedca += csa_ecsa_mcst_len;

        if (bo->bo_ess_rpt)
            bo->bo_ess_rpt += csa_ecsa_mcst_len;

        if (bo->bo_ndp_rpt_param)
            bo->bo_ndp_rpt_param += csa_ecsa_mcst_len;

        if (bo->bo_he_bss_load)
            bo->bo_he_bss_load += csa_ecsa_mcst_len;

        if (bo->bo_he_6g_bandcap)
            bo->bo_he_6g_bandcap += csa_ecsa_mcst_len;

        bo->bo_mcst += csa_ecsa_mcst_len;

        /* Check if max chan switch time IE(mcst IE) has to be added.
         * If yes, update csa_ecsa_mcst_len
         */
        if (t_csa_ies[0] == IEEE80211_ELEMID_EXTN &&
                t_csa_ies[2] == IEEE80211_ELEMID_EXT_MAX_CHAN_SWITCH_TIME) {
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_mcst_trailerlen);
            if (tempbuf) {
                qdf_mem_zero(tempbuf, bo->bo_mcst_trailerlen);
                qdf_mem_copy(tempbuf, bo->bo_mcst,
                        bo->bo_mcst_trailerlen);
                qdf_mem_copy(bo->bo_mcst
                        + IEEE80211_MAXCHANSWITCHTIME_BYTES,
                        tempbuf, bo->bo_mcst_trailerlen);
                qdf_mem_free(tempbuf);

                qdf_mem_copy(bo->bo_mcst, t_csa_ies, IEEE80211_MAXCHANSWITCHTIME_BYTES);
                csa_ecsa_mcst_len += IEEE80211_MAXCHANSWITCHTIME_BYTES;

                /* Adjust trailers alone
                 * Buffer offsets will be adjusted after secondary channel offset updation
                 */
                bo->bo_tim_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
                bo->bo_chanswitch_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
                bo->bo_ecsa_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
                bo->bo_vhtchnsw_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
                bo->bo_mcst_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
                bo->bo_bcca_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;

#if UMAC_SUPPORT_WNM
                bo->bo_fms_trailerlen += IEEE80211_MAXCHANSWITCHTIME_BYTES;
#endif /* UMAC_SUPPORT_WNM */
            } else {
                if (bcn_size_check)
                    vap->iv_available_bcn_cmn_space += IEEE80211_MAXCHANSWITCHTIME_BYTES;
            }
            t_csa_ies += IEEE80211_MAXCHANSWITCHTIME_BYTES;
        }

        bo->bo_secchanoffset += csa_ecsa_mcst_len;

        if (t_csa_ies[0] == IEEE80211_ELEMID_SECCHANOFFSET) {
            /* Add secondary channel offset element */
            tempbuf = (uint8_t *)qdf_mem_malloc(bo->bo_secchanoffset_trailerlen);

            if(tempbuf) {
                qdf_mem_zero(tempbuf, bo->bo_secchanoffset_trailerlen);
                qdf_mem_copy(tempbuf, bo->bo_secchanoffset,
                        bo->bo_secchanoffset_trailerlen);
                qdf_mem_copy(bo->bo_secchanoffset
                        + IEEE80211_SEC_CHAN_OFFSET_BYTES,
                        tempbuf, bo->bo_secchanoffset_trailerlen);
                qdf_mem_free(tempbuf);

                qdf_mem_copy(bo->bo_secchanoffset, t_csa_ies, IEEE80211_SEC_CHAN_OFFSET_BYTES);
                csa_ecsa_mcst_len += IEEE80211_SEC_CHAN_OFFSET_BYTES;

                /* Adjust trailers, and buffer offsets between MCST and app ie buf */
                bo->bo_tim_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_chanswitch_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_ecsa_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_vhtchnsw_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_mcst_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_secchanoffset_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
                bo->bo_bcca_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;

#if UMAC_SUPPORT_WNM
                bo->bo_fms_trailerlen += IEEE80211_SEC_CHAN_OFFSET_BYTES;
#endif /* UMAC_SUPPORT_WNM */
            } else {
                if (bcn_size_check)
                    vap->iv_available_bcn_cmn_space += IEEE80211_SEC_CHAN_OFFSET_BYTES;
            }
            t_csa_ies += IEEE80211_SEC_CHAN_OFFSET_BYTES;
        }

        if (bo->bo_rsnx)
            bo->bo_rsnx += csa_ecsa_mcst_len;

        if (bo->bo_ath_caps)
            bo->bo_ath_caps += csa_ecsa_mcst_len;

        if (bo->bo_extender_ie)
            bo->bo_extender_ie += csa_ecsa_mcst_len;

        if (bo->bo_htinfo_vendor_specific)
            bo->bo_htinfo_vendor_specific += csa_ecsa_mcst_len;

        if (bo->bo_mbo_cap )
            bo->bo_mbo_cap  += csa_ecsa_mcst_len;

        if (bo->bo_apriori_next_channel)
            bo->bo_apriori_next_channel += csa_ecsa_mcst_len;

        if (bo->bo_bwnss_map)
            bo->bo_bwnss_map += csa_ecsa_mcst_len;

#if QCN_IE
        if (bo->bo_qcn_ie)
            bo->bo_qcn_ie += csa_ecsa_mcst_len;
#endif

        if (bo->bo_software_version_ie)
            bo->bo_software_version_ie += csa_ecsa_mcst_len;

        if (bo->bo_xr)
            bo->bo_xr += csa_ecsa_mcst_len;

        if (bo->bo_whc_apinfo)
            bo->bo_whc_apinfo += csa_ecsa_mcst_len;

        if (bo->bo_interop_vhtcap)
            bo->bo_interop_vhtcap += csa_ecsa_mcst_len;

        if (bo->bo_wme)
            bo->bo_wme += csa_ecsa_mcst_len;

        if (bo->bo_appie_buf)
            bo->bo_appie_buf += csa_ecsa_mcst_len;

         /* Indicate new beacon length so other layers may manage memory */
         wbuf_append(wbuf, csa_ecsa_mcst_len);
         *len_changed = 1;
    } else {
        bo->bo_chanswitch[4] =
            ic->ic_chanchange_tbtt - vap->iv_chanchange_count;
        /* ECSA IE is added if enabled
         * Update tbtt count in ECSA IE to same as CSA IE.
         */
        ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)bo->bo_ecsa;

        if (ecsa_ie->ie == IEEE80211_ELEMID_EXTCHANSWITCHANN) {
            /* ECSA is inserted, so update tbttcount */
            ecsa_ie->tbttcount = bo->bo_chanswitch[4];
        }
    }

    vap->iv_chanchange_count++;

    /* In case of repeater move, send deauth to old root AP one count
     * before channel switch happens
     */
    if (bo->bo_chanswitch[4] == 1 && ic->ic_repeater_move.state == REPEATER_MOVE_START) {
        struct ieee80211vap *rep_sta_vap = ic->ic_sta_vap;
        struct ieee80211_node *ni = ieee80211_vap_find_node(rep_sta_vap,
                rep_sta_vap->iv_bss->ni_bssid, WLAN_MLME_SB_ID);
        if (ni != NULL) {
            ieee80211_send_deauth(ni, IEEE80211_REASON_AUTH_LEAVE);
            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
        }
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
            "%s: CHANSWITCH IE, change in %d \n",
            __func__, bo->bo_chanswitch[4]);

free_exit:
    if (csa_ies)
        qdf_mem_free(csa_ies);

exit:
    return;
}

static void ieee80211_beacon_reinit(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    uint8_t *frm = NULL;
    struct ieee80211vap *vap = ni->ni_vap;

    frm = (uint8_t *) wbuf_header(wbuf) + sizeof(struct ieee80211_frame);
    frm = ieee80211_beacon_init(ni, bo, frm);
    if (!frm)
        return;

    *update_beacon_copy = true;
    wbuf_set_pktlen(wbuf, (frm - (uint8_t *)wbuf_header(wbuf)));
    *len_changed = 1;
    vap->beacon_reinit_done = true;
}

static void ieee80211_csa_interop_phy_iter_sta(void *arg, wlan_node_t wn)
{
    struct ieee80211_node *bss;
    struct ieee80211_node *ni;
    struct ieee80211vap *vap;
    struct ieee80211com *ic;

    ni = wn;
    bss = arg;

    if (!ni || !bss) {
        return;
    }
    vap = ni->ni_vap;
    ic = vap->iv_ic;

    if (ni == bss) {
        qdf_debug("[%s, %pM] skipping bss node", vap->iv_netdev_name,
                 ni->ni_macaddr);
        return;
    }

    ieee80211_csa_interop_phy_update(ni, -1);
}

static void ieee80211_csa_interop_phy_iter_vap(void *arg, wlan_if_t wif)
{
    struct ieee80211vap *vap;

    vap = wif;
    if (!vap->iv_csa_interop_phy)
        return;

    wlan_iterate_station_list(vap, ieee80211_csa_interop_phy_iter_sta, vap->iv_bss);
}

static void ieee80211_csa_interop_phy(struct ieee80211com *ic)
{
    int err = 0;

    /* Subscribe to ppdu stats to see if STA is transmitting
     * higher bw frames.
     */
    if (ic->ic_subscribe_csa_interop_phy &&
        ieee80211_get_num_csa_interop_phy_vaps(ic)) {
        /* Subscribe only if not subscribed before */
        if (!ic->ic_csa_interop_subscribed)
            err = ic->ic_subscribe_csa_interop_phy(ic, true);

        if (!err) {
            ic->ic_csa_interop_subscribed = true;
            wlan_iterate_vap_list(ic, ieee80211_csa_interop_phy_iter_vap, NULL);
            /* start timer to unsubscrive per ppdu stats */
            qdf_timer_mod(&ic->ic_csa_max_rx_wait_timer, g_csa_max_rx_wait_time);
        }
    }
}

/* ieee80211_change_channel: If all the CSAs have been sent, change the channel
 * and reset the channel switch flags.
 *
 * return 0: Perform channel change and reset channel switch flags.
 * return 1: Not all the CSAs have been sent or usenol is 0, so channel change
 * doesn't happen.
 */
static int ieee80211_change_channel(
        struct ieee80211_node *ni,
        bool *update_beacon_copy,
        int *len_changed,
        wbuf_t wbuf,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_ath_channel *c;
    struct ieee80211vap *tmp_vap = NULL;
    struct ieee80211_vap_opmode_count vap_opmode_count;

    if ((vap->iv_flags & IEEE80211_F_CHANSWITCH) &&
            (vap->iv_chanchange_count == ic->ic_chanchange_tbtt) &&
            IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)) {

        vap->iv_chanchange_count = 0;

        /*
         * NB: iv_bsschan is in the DSPARMS beacon IE, so must set this
         * prior to the beacon re-init, below.
         */
        if (!ic->ic_chanchange_channel) {
            c = ieee80211_doth_findchan(vap, ic->ic_chanchange_chan_freq);
            if (c == NULL) {
                qdf_err("[%s]: find channel failure ic_chanchange_chan_freq = %d\n",
                         vap->iv_netdev_name, ic->ic_chanchange_chan_freq);
                return 0;
            }
        } else {
            c = ic->ic_chanchange_channel;
        }
        vap->iv_bsschan = c;

        /* Clear IEEE80211_F_CHANSWITCH flag */
        ieee80211vap_clear_flag(vap, IEEE80211_F_CHANSWITCH);

        ieee80211com_clear_flags(ic, IEEE80211_F_CHANSWITCH);

        ieee80211_csa_interop_phy(ic);

        if (ic->ic_chanchange_chwidth != 0) {
            /* Wide Bandwidth Channel Switch for VHT/11ax 5 GHz only.
             * In this case need to update phymode.
             */
            uint64_t chan_flag = ic->ic_chanchange_chanflag;
            enum ieee80211_phymode mode = 0;

            /* 11AX TODO: Recheck future 802.11ax drafts (>2.0) on
             * channel switching rules.
             */

            /*Get phymode from chan_flag value */
            mode = ieee80211_get_phymode_from_chan_flag(ic->ic_curchan,
                    chan_flag);

            if(mode != 0 && (ic->ic_opmode == IEEE80211_M_HOSTAP)){
                ieee80211_setmode(ic, mode, IEEE80211_M_HOSTAP);
                OS_MEMZERO(&vap_opmode_count, sizeof(vap_opmode_count));
                ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
                /* Allow phymode override in non-repeater mode */
                if (!vap_opmode_count.sta_count) {
                    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                        wlan_set_desired_phymode(tmp_vap,mode);
                    }
                }

            }
        }

        if (ic->ic_curchan != c) {
            ieee80211_chan_switch_to_new_chan(vap, c);
        } else {
            struct ieee80211vap *transmit_vap = NULL;

            if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                        WLAN_PDEV_F_MBSS_IE_ENABLE)) {
                transmit_vap = ic->ic_mbss.transmit_vap;
            }

            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if(tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) {

                    /* When MBSSIE FR is enabled, set iv_remove_csa_ie flag only
                     * for transmitting vap. Based on this flag beacon template
                     * is sent to FW in CSA event handler. Do not set
                     * iv_remove_csa_ie flag for non-transmitting vaps, as Host
                     * does not send CSA template to FW for these vaps.
                     * When MBSSIE FR is disabled, host sends CSA template for
                     * all the vaps to FW. Therefore set iv_remove_csa_ie for
                     * all the vaps. In this case transmit_vap is NULL.
                     */
                    if (!transmit_vap || (tmp_vap == transmit_vap))
                    {
                        tmp_vap->iv_remove_csa_ie = true;
                        tmp_vap->iv_no_restart = true;
                    }

                    /* When MBSSIE FR is enabled, set iv_no_restart flag only
                     * for transmitting vap.
                     */
                    if (transmit_vap && (tmp_vap == transmit_vap)) {
                        tmp_vap->iv_no_restart = true;
                    }

                    tmp_vap->iv_chanchange_count = 0;
                    ieee80211vap_clear_flag(tmp_vap, IEEE80211_F_CHANSWITCH);
                    wlan_vdev_mlme_sm_deliver_evt(tmp_vap->vdev_obj,
                                        WLAN_VDEV_SM_EV_CSA_COMPLETE, 0, NULL);
                }
            }
        }

        /* Reinitialize the beacon after restart */
        ieee80211_beacon_reinit(ni, bo, wbuf, len_changed, update_beacon_copy);

        /* Resetting VHT channel change variables */
        ic->ic_chanchange_channel = NULL;
        ic->ic_chanchange_chwidth = 0;
        IEEE80211_CHAN_SWITCH_END(ic);

        IEEE80211_CHANCHANGE_STARTED_CLEAR(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_CLEAR(ic);
        if (!vap->iv_bcn_offload_enable) {
            if(mlme_dfs_get_rn_use_nol(ic->ic_pdev_obj))
                return 0;
        }
    }
    return 1;
}

static void inline ieee80211_update_capinfo(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint16_t capinfo;

    if (!bo || !bo->bo_caps)
        return;

    /* XXX faster to recalculate entirely or just changes? */
    capinfo = IEEE80211_CAPINFO_ESS;

    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;

    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
            IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;

    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;

    if (ieee80211_ic_doth_is_set(ic) &&
            ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    if (IEEE80211_VAP_IS_PUREB_ENABLED(vap))
        capinfo &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;

    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;

    *bo->bo_caps = htole16(capinfo);
}

/*
 * Check if channel change due to CW interference needs to be done.
 * Since this is a drastic channel change, we do not wait for the TBTT
 * interval to expair and do not send Channel change flag in beacon.
 */
static void ieee80211_beacon_check_and_reinit_beacon(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic  = vap->iv_ic;

    /* Update APP IE for tx VAP only in case of MBSS,
     * APP IE for a non-tx VAP is added to VAP profile in MBSS IE
     */
    if ((vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE) ||
            vap->iv_update_vendor_ie ||
            vap->channel_change_done ||
            vap->appie_buf_updated   ||
            (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap) &&
                    vap->iv_app_ie_list[IEEE80211_FRAME_TYPE_BEACON].changed) ||
            vap->iv_doth_updated     ||
            (vap->iv_flags_ext2 & IEEE80211_FEXT2_MBO) ||
            vap->iv_remove_csa_ie    ||
            vap->iv_he_bsscolor_remove_ie ||
            vap->iv_mbss.mbssid_update_ie ||
            vap->iv_sr_ie_reset ||
            vap->iv_oob_update ||
            vap->iv_rtt_update)
    {

        ieee80211_beacon_reinit(ni, bo, wbuf, len_changed, update_beacon_copy);

        ieee80211vap_clear_flag_ext2(vap, IEEE80211_FEXT2_MBO);
        ieee80211vap_clear_flag_ext2(vap, IEEE80211_FEXT2_BR_UPDATE);
        vap->iv_update_vendor_ie = 0;
        vap->channel_change_done = 0;
        vap->appie_buf_updated   = 0;

        if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap))
                vap->iv_app_ie_list[IEEE80211_FRAME_TYPE_BEACON].changed = false;

        vap->iv_doth_updated     = 0;
        vap->iv_he_bsscolor_remove_ie = false;
        vap->iv_mbss.mbssid_update_ie = 0;
        vap->iv_sr_ie_reset = 0;
        vap->iv_oob_update = 0;
        vap->iv_rtt_update = false;

        if (!vap->iv_bcn_offload_enable) {
            vap->iv_remove_csa_ie = false;
            vap->channel_switch_state = 0;
        }

        if (ic->cw_inter_found)
            ic->cw_inter_found = 0;
    }
}

static void ieee80211_beacon_add_wme_param(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        bool *update_beacon_copy)
{
    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP)) {
        struct ieee80211_wme_state *wme = &vap->iv_wmestate;

        /* XXX multi-bss */
        if ((vap->iv_flags & IEEE80211_F_WMEUPDATE) && (bo->bo_wme)) {
            ieee80211_add_wme_param(bo->bo_wme, wme,
                    IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
            *update_beacon_copy = true;
            ieee80211vap_clear_flag(vap, IEEE80211_F_WMEUPDATE);
        }
    }
}

static void ieee80211_beacon_update_muedca_param(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        bool *update_beacon_copy)
{
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(vap->iv_ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap) && (bo->bo_muedca)) {
        ieee80211_add_muedca_param(bo->bo_muedca, &vap->iv_muedcastate);
        *update_beacon_copy = true;
    }
}

#if ATH_SUPPORT_UORA
static void ieee80211_beacon_update_uora_param(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        bool *update_beacon_copy)
{
    if( ieee80211vap_heallowed(vap) &&
             IEEE80211_IS_CHAN_11AX(vap->iv_ic->ic_curchan) &&
             ieee80211vap_uora_is_enabled(vap) && (bo->bo_uora_param)) {
        ieee80211_add_uora_param(bo->bo_uora_param, vap->iv_ocw_range);
        *update_beacon_copy = true;
    }
}
#endif

static void  ieee80211_beacon_update_pwrcnstr(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (bo->bo_pwrcnstr &&
            ieee80211_ic_doth_is_set(ic) &&
            ieee80211_vap_doth_is_set(vap)) {
        uint8_t *pwrcnstr = bo->bo_pwrcnstr;

        *pwrcnstr++ = IEEE80211_ELEMID_PWRCNSTR;
        *pwrcnstr++ = 1;
        *pwrcnstr++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }
}

static void ieee80211_update_chan_utilization(
        struct ieee80211vap *vap)
{
#if UMAC_SUPPORT_QBSSLOAD
    ieee80211_beacon_chanutil_update(vap);
#elif UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    if (vap->iv_chanutil_enab) {
        ieee80211_beacon_chanutil_update(vap);
    }
#endif
}

static void inline ieee80211_beacon_add_htcap(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    int enable_htrates;

    enable_htrates = ieee80211vap_htallowed(vap);

    /*
     * HT cap. check for vap is done in ieee80211vap_htallowed.
     * TBD: remove iv_bsschan check to support multiple channel operation.
     */
    if (ieee80211_vap_wme_is_set(vap) &&
            (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
            enable_htrates && (bo->bo_htinfo != NULL) &&
            (bo->bo_htcap != NULL)) {

        struct ieee80211_ie_htinfo_cmn *htinfo;
        struct ieee80211_ie_obss_scan *obss_scan;

#if IEEE80211_BEACON_NOISY
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                "%s: AP: updating HT Info IE (ANA) for %s\n",
                __func__, ether_sprintf(ni->ni_macaddr));

        if (bo->bo_htinfo[0] != IEEE80211_ELEMID_HTINFO_ANA) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                    "%s: AP: HT Info IE (ANA) beacon offset askew %s "
                    "expected 0x%02x, found 0x%02x\n",
                    __func__, ether_sprintf(ni->ni_macaddr),
                    IEEE80211_ELEMID_HTINFO_ANA, bo->bo_htinfo[0]);
        }
#endif
        htinfo = &((struct ieee80211_ie_htinfo *)bo->bo_htinfo)->hi_ie;
        ieee80211_update_htinfo_cmn(htinfo, ni);

        ieee80211_add_htcap(bo->bo_htcap, ni, IEEE80211_FC0_SUBTYPE_BEACON);

        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            obss_scan = (struct ieee80211_ie_obss_scan *)bo->bo_obss_scan;
            if(obss_scan)
                ieee80211_update_obss_scan(obss_scan, ni);
        }

        if (IEEE80211_IS_HTVIE_ENABLED(ic) &&
                bo->bo_htinfo_vendor_specific) {
#if IEEE80211_BEACON_NOISY
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                    "%s: AP: updating HT Info IE (Vendor Specific) for %s\n",
                    __func__, ether_sprintf(ni->ni_macaddr));
            if (bo->bo_htinfo_vendor_specific[5] !=
                    IEEE80211_ELEMID_HTINFO_VENDOR) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_11N,
                        "%s: AP: HT Info IE (Vendor Specific) beacon offset askew %s expected 0x%02x, found 0x%02x\n",
                        __func__, ether_sprintf(ni->ni_macaddr),
                        IEEE80211_ELEMID_HTINFO_ANA,
                        bo->bo_htinfo_vendor_specific[5] );
            }
#endif
            htinfo = &((struct vendor_ie_htinfo *)
                    bo->bo_htinfo_vendor_specific)->hi_ie;
            ieee80211_update_htinfo_cmn(htinfo, ni);
        }
    }
}

static void inline ieee80211_beacon_add_vhtcap(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    /* Add VHT cap if device is in 11ac operating mode (or)
     * 256QAM is enabled in 2.4G.
     */
    if (ieee80211_vap_wme_is_set(vap) &&
            (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap) &&
            (bo->bo_vhtcap != NULL) && (bo->bo_vhtop != NULL)) {

        /* Add VHT capabilities IE */
        ieee80211_add_vhtcap(bo->bo_vhtcap, ni, ic,
                IEEE80211_FC0_SUBTYPE_BEACON, NULL, NULL);

        /* Add VHT Operation IE */
        ieee80211_add_vhtop(bo->bo_vhtop, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                NULL);

        /* Add VHT Tx Power Envelope IE */
        if (bo->bo_vhttxpwr && ieee80211_ic_doth_is_set(ic) &&
                ieee80211_vap_doth_is_set(vap)) {
            ieee80211_add_vht_txpwr_envlp(bo->bo_vhttxpwr, ni, ic,
                    IEEE80211_FC0_SUBTYPE_BEACON,
                    !IEEE80211_TPE_IS_SUB_ELEMENT);
        }
    }

    /* Add VHT Vendor specific IE for 256QAM support in 2.4G Interop */
    if (ieee80211_vap_wme_is_set(vap) &&
            (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) &&
            ieee80211vap_vhtallowed(vap) &&
            ieee80211vap_11ng_vht_interopallowed(vap) &&
            (bo->bo_interop_vhtcap != NULL)) {
        /* Add VHT capabilities IE and VHT OP IE */
        ieee80211_add_interop_vhtcap(bo->bo_interop_vhtcap, ni, ic,
                IEEE80211_FC0_SUBTYPE_BEACON);
    }
}

static void ieee80211_add_he_cap(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic  = ni->ni_ic;

    if (ieee80211_vap_wme_is_set(vap) &&
            IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) &&
            ieee80211vap_heallowed(vap) &&
            (bo->bo_hecap != NULL) &&
            (bo->bo_heop != NULL)) {

        /* Add HE capabilities IE */
        ieee80211_add_hecap(bo->bo_hecap, ni, ic,
                IEEE80211_FC0_SUBTYPE_BEACON);

        /* Add HE Operation IE */
        ieee80211_add_heop(bo->bo_heop, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                NULL);

        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            /* Add HE 6GHz Band Capabilities IE */
            ieee80211_add_6g_bandcap(bo->bo_he_6g_bandcap, ni, ic,
                    IEEE80211_FC0_SUBTYPE_BEACON);
        }
    }
}

static void ieee80211_beacon_add_bsscolor_change_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int  *len_changed)
{
    struct ieee80211vap *vap = ni->ni_vap;
    uint8_t vdev_id = wlan_vdev_get_id(vap->vdev_obj);

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
        "%s>> vdev-id: %d iv_he_bsscolor_change_ongoing: %s",  __func__,
        vdev_id, vap->iv_he_bsscolor_change_ongoing ? "true": "false");

    if (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) &&
                    ieee80211vap_heallowed(vap) &&
                    vap->iv_he_bsscolor_change_ongoing) {
        ieee80211_add_he_bsscolor_change_ie(bo, wbuf, ni,
                IEEE80211_FC0_SUBTYPE_BEACON, len_changed);
        if(vap->iv_bcca_ie_status == BCCA_NA) {
            vap->iv_bcca_ie_status = BCCA_START;
        } else {
            vap->iv_bcca_ie_status = BCCA_ONGOING;
        }
    }
    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                                            "%s<<", __func__);
}

static void ieee80211_find_new_chan(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (ieee80211_ic_doth_is_set(ic) &&
            (ic->ic_flags & IEEE80211_F_CHANSWITCH) &&
            IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)) {
        if (!(ic->ic_chanchange_channel)) {
            ic->ic_chanchange_channel =
                ieee80211_doth_findchan(vap, ic->ic_chanchange_chan_freq);
            if(!(ic->ic_chanchange_channel)) {
                /*
                 * Ideally we should not be here, Only reason is that we have
                 * a corrupt chan.
                 */
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                        "%s : Error chanchange is NULL: VAP = %d "
                        "chan freq = %d cfreq = %d flags = %llu",
                        __func__, vap->iv_unit, ic->ic_chanchange_chan_freq,
                        vap->iv_des_cfreq2,
                        (vap->iv_bsschan->ic_flags & IEEE80211_CHAN_ALL));
            } else {
                /* Find secondary 20 offset to advertise in beacon */
                ic->ic_chanchange_secoffset =
                    ieee80211_sec_chan_offset(ic->ic_chanchange_channel);
                /* Find destination channel width */
                ic->ic_chanchange_chwidth =
                    ieee80211_get_chan_width(ic->ic_chanchange_channel);
            }
        }
    }
}

static void inline ieee80211_beacon_update_tim(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        struct ieee80211_ath_tim_ie **tie,
        wbuf_t wbuf,
        int *len_changed,
        int mcast,
        int *is_dtim)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    if (vap->iv_opmode == IEEE80211_M_HOSTAP &&
            bo->bo_tim) {
        *tie = (struct ieee80211_ath_tim_ie *) bo->bo_tim;

        if (IEEE80211_VAP_IS_TIMUPDATE_ENABLED(vap) &&
                vap->iv_opmode == IEEE80211_M_HOSTAP) {
            u_int timlen = 0;
            u_int timoff = 0;
            u_int i = 0;

            /*
             * ATIM/DTIM needs updating. If it fits in the current space
             * allocated then just copy in the new bits. Otherwise we need to
             * move any trailing data to make room. Note that we know there is
             * contiguous space because ieee80211_beacon_allocate insures there
             * is space in the wbuf to write a maximal-size virtual bitmap
             * (based on ic_max_aid).
             */
            /*
             * Calculate the bitmap size and offset, copy any trailer out of the
             * way, and then copy in the new bitmap and update the information
             * element. Note that the tim bitmap must contain at least one byte
             * and any offset must be even.
             */
            if (vap->iv_ps_pending != 0) {
                timoff = 128;        /* Impossibly large */
                for (i = 0; i < vap->iv_tim_len; i++) {
                    if (vap->iv_tim_bitmap[i]) {
                        timoff = i &~ 1;
                        break;
                    }
                }
                /* Remove the assert and do a recovery */
                /* KASSERT(timoff != 128, ("tim bitmap empty!")); */
                if (timoff == 128) {
                    timoff = 0;
                    timlen = 1;
                    qdf_print("Recover in TIM update");
                } else {
                    for (i = vap->iv_tim_len-1; i >= timoff; i--) {
                        if (vap->iv_tim_bitmap[i])
                            break;
                    }

                    if (i < timoff) {
                        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                                "Corrupted tim ie, recover in TIM update, "
                                "tim_len = %d, i = %d, timoff = %d",
                                vap->iv_tim_len, i, timoff);
                        timoff = 0;
                        timlen = 1;
                    } else {
                        timlen = 1 + (i - timoff);
                        /* Resetting the timlen if it goes beyond 68 limit
                         * (64 + 4 The 64 is to support 512 client 4 is a
                         * gaurd band.
                         */
                        if (timlen > 68) {
                            timoff = 0;
                            timlen = 1;
                            qdf_print("Recover in TIM update Invalid TIM length");
                        }
                    }
                }
            } else {
                timoff = 0;
                timlen = 1;
            }

            (*tie)->tim_bitctl = timoff;
            if (IS_MBSSID_EMA_EXT_ENABLED(ic) &&
                    !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
                if (vap->iv_available_bcn_cmn_space - (timlen - bo->bo_tim_len) < 0) {
                    timlen = 0;
                    vap->iv_available_bcn_cmn_space += bo->bo_tim_len;
                    *tie = NULL;
                } else {
                    vap->iv_available_bcn_cmn_space -= (timlen - bo->bo_tim_len);
                }
            }
            if (timlen != bo->bo_tim_len) {
                int trailer_adjust = 0;

                if (!timlen) {
                    trailer_adjust -= bo->bo_tim_len;
                    qdf_mem_move(bo->bo_tim, bo->bo_tim_trailer, bo->bo_tim_trailerlen);
                    bo->bo_tim_trailer = bo->bo_tim;
                } else {
                    trailer_adjust =
                        ((*tie)->tim_bitmap+timlen) - bo->bo_tim_trailer;

                    /* copy up/down trailer */
                    qdf_mem_move((*tie)->tim_bitmap+timlen, bo->bo_tim_trailer,
                            bo->bo_tim_trailerlen);
                    bo->bo_tim_trailer = (*tie)->tim_bitmap+timlen;
                }

                if (bo->bo_pwrcnstr)
                    bo->bo_pwrcnstr += trailer_adjust;

                if (bo->bo_chanswitch)
                    bo->bo_chanswitch += trailer_adjust;

                if (bo->bo_quiet)
                    bo->bo_quiet += trailer_adjust;

                if (bo->bo_tpcreport) {
                    bo->bo_tpcreport += trailer_adjust;
                }

                if (bo->bo_erp)
                    bo->bo_erp += trailer_adjust;

                if (bo->bo_xrates)
                    bo->bo_xrates += trailer_adjust;

                if (bo->bo_rsn)
                    bo->bo_rsn += trailer_adjust;

                if (bo->bo_qbssload)
                    bo->bo_qbssload += trailer_adjust;

                if (bo->bo_edca)
                    bo->bo_edca += trailer_adjust;

                if (bo->bo_qos_cap)
                    bo->bo_qos_cap += trailer_adjust;

                if (bo->bo_ap_chan_rpt)
                    bo->bo_ap_chan_rpt += trailer_adjust;

                if (bo->bo_bss_avg_delay)
                    bo->bo_bss_avg_delay += trailer_adjust;

                if (bo->bo_antenna)
                    bo->bo_antenna += trailer_adjust;

                if (bo->bo_bss_adm_cap)
                    bo->bo_bss_adm_cap += trailer_adjust;

#if !ATH_SUPPORT_WAPI
                if (bo->bo_bss_ac_acc_delay)
                    bo->bo_bss_ac_acc_delay += trailer_adjust;
#endif

                if (bo->bo_msmt_pilot_tx)
                    bo->bo_msmt_pilot_tx += trailer_adjust;

                if (bo->bo_mbssid_ie)
                        bo->bo_mbssid_ie += trailer_adjust;

                if (bo->bo_rrm)
                    bo->bo_rrm += trailer_adjust;

                if (bo->bo_mob_domain)
                    bo->bo_mob_domain += trailer_adjust;

                if (bo->bo_dse_reg_loc)
                    bo->bo_dse_reg_loc += trailer_adjust;

                if (bo->bo_ecsa)
                    bo->bo_ecsa += trailer_adjust;

                if (bo->bo_opt_class)
                    bo->bo_opt_class += trailer_adjust;

                if (bo->bo_htcap)
                    bo->bo_htcap += trailer_adjust;

                if (bo->bo_htinfo)
                    bo->bo_htinfo += trailer_adjust;

                if (bo->bo_2040_coex)
                    bo->bo_2040_coex += trailer_adjust;

                if (bo->bo_obss_scan)
                    bo->bo_obss_scan += trailer_adjust;

                if (bo->bo_extcap)
                    bo->bo_extcap += trailer_adjust;

                #if UMAC_SUPPORT_WNM
                    if (bo->bo_fms_desc)
                        bo->bo_fms_desc += trailer_adjust;

                    if (bo->bo_fms_trailer)
                        bo->bo_fms_trailer += trailer_adjust;
                #endif

                if (bo->bo_qos_traffic)
                    bo->bo_qos_traffic += trailer_adjust;

                if (bo->bo_time_adv)
                    bo->bo_time_adv += trailer_adjust;

                if (bo->bo_interworking)
                    bo->bo_interworking += trailer_adjust;

                if (bo->bo_adv_proto)
                    bo->bo_adv_proto += trailer_adjust;

                if (bo->bo_roam_consortium)
                    bo->bo_roam_consortium += trailer_adjust;

                if (bo->bo_emergency_id)
                    bo->bo_emergency_id  += trailer_adjust;

                if (bo->bo_mesh_id)
                    bo->bo_mesh_id += trailer_adjust;

                if (bo->bo_mesh_conf)
                    bo->bo_mesh_conf += trailer_adjust;

                if (bo->bo_mesh_awake_win)
                    bo->bo_mesh_awake_win += trailer_adjust;

                if (bo->bo_beacon_time)
                    bo->bo_beacon_time += trailer_adjust;

                if (bo->bo_mccaop_adv_ov)
                    bo->bo_mccaop_adv_ov += trailer_adjust;

                if (bo->bo_mccaop_adv)
                    bo->bo_mccaop_adv += trailer_adjust;

                if (bo->bo_mesh_cs_param)
                    bo->bo_mesh_cs_param += trailer_adjust;

                if (bo->bo_qmf_policy)
                    bo->bo_qmf_policy += trailer_adjust;

                if (bo->bo_qload_rpt)
                    bo->bo_qload_rpt += trailer_adjust;

                if (bo->bo_hcca_upd_cnt)
                    bo->bo_hcca_upd_cnt += trailer_adjust;

                if (bo->bo_multiband)
                    bo->bo_multiband += trailer_adjust;

                if (bo->bo_vhtcap)
                    bo->bo_vhtcap += trailer_adjust;

                if (bo->bo_vhtop)
                    bo->bo_vhtop += trailer_adjust;

                if (bo->bo_vhttxpwr)
                    bo->bo_vhttxpwr += trailer_adjust;

                if (bo->bo_vhtchnsw)
                    bo->bo_vhtchnsw += trailer_adjust;

                if (bo->bo_ext_bssload)
                    bo->bo_ext_bssload += trailer_adjust;

                if (bo->bo_quiet_chan)
                    bo->bo_quiet_chan += trailer_adjust;

                if (bo->bo_opt_mode_note)
                    bo->bo_opt_mode_note += trailer_adjust;

                if (bo->bo_rnr)
                    bo->bo_rnr += trailer_adjust;

                if (bo->bo_rnr2)
                    bo->bo_rnr2 += trailer_adjust;

                if (bo->bo_tvht)
                    bo->bo_tvht += trailer_adjust;

#if QCN_ESP_IE
                if (bo->bo_esp_ie)
                    bo->bo_esp_ie += trailer_adjust;
#endif

                if (bo->bo_future_chan)
                    bo->bo_future_chan += trailer_adjust;

                if (bo->bo_cag_num)
                    bo->bo_cag_num += trailer_adjust;

                if (bo->bo_fils_ind)
                    bo->bo_fils_ind += trailer_adjust;

                if (bo->bo_ap_csn)
                    bo->bo_ap_csn += trailer_adjust;

                if (bo->bo_diff_init_lnk)
                    bo->bo_diff_init_lnk += trailer_adjust;

                if (bo->bo_service_hint)
                    bo->bo_service_hint += trailer_adjust;

                if (bo->bo_service_hash)
                    bo->bo_service_hash += trailer_adjust;

                if (bo->bo_hecap)
                    bo->bo_hecap += trailer_adjust;

                if (bo->bo_heop)
                    bo->bo_heop += trailer_adjust;

                if (bo->bo_twt)
                    bo->bo_twt += trailer_adjust;

#if ATH_SUPPORT_UORA
                if (bo->bo_uora_param)
                    bo->bo_uora_param += trailer_adjust;
#endif

                if (bo->bo_bcca)
                    bo->bo_bcca += trailer_adjust;

#if OBSS_PD
                if(bo->bo_srp_ie)
                    bo->bo_srp_ie += trailer_adjust;
#endif

                if (bo->bo_muedca)
                    bo->bo_muedca += trailer_adjust;

                if (bo->bo_ess_rpt)
                    bo->bo_ess_rpt += trailer_adjust;

                if (bo->bo_ndp_rpt_param)
                    bo->bo_ndp_rpt_param += trailer_adjust;

                if (bo->bo_he_bss_load)
                    bo->bo_he_bss_load += trailer_adjust;

                if (bo->bo_he_6g_bandcap)
                    bo->bo_he_6g_bandcap += trailer_adjust;

                if (bo->bo_mcst)
                    bo->bo_mcst += trailer_adjust;

                if (bo->bo_secchanoffset)
                    bo->bo_secchanoffset += trailer_adjust;

                if (bo->bo_rsnx)
                    bo->bo_rsnx += trailer_adjust;

                if (bo->bo_ath_caps)
                    bo->bo_ath_caps += trailer_adjust;

                if (bo->bo_extender_ie)
                    bo->bo_extender_ie += trailer_adjust;

                if (bo->bo_htinfo_vendor_specific)
                    bo->bo_htinfo_vendor_specific += trailer_adjust;

                if (bo->bo_mbo_cap )
                    bo->bo_mbo_cap  += trailer_adjust;

                if (bo->bo_apriori_next_channel)
                    bo->bo_apriori_next_channel += trailer_adjust;

                if (bo->bo_bwnss_map)
                    bo->bo_bwnss_map += trailer_adjust;

#if QCN_IE
                if (bo->bo_qcn_ie)
                    bo->bo_qcn_ie += trailer_adjust;
#endif

                if (bo->bo_software_version_ie)
                    bo->bo_software_version_ie += trailer_adjust;

                if (bo->bo_xr)
                    bo->bo_xr += trailer_adjust;

                if (bo->bo_whc_apinfo)
                    bo->bo_whc_apinfo += trailer_adjust;

                if (bo->bo_interop_vhtcap)
                    bo->bo_interop_vhtcap += trailer_adjust;

                if (bo->bo_wme)
                    bo->bo_wme += trailer_adjust;

                if (bo->bo_appie_buf)
                    bo->bo_appie_buf += trailer_adjust;

                if (timlen > bo->bo_tim_len)
                    wbuf_append(wbuf, timlen - bo->bo_tim_len);
                else
                    wbuf_trim(wbuf, bo->bo_tim_len - timlen);

                bo->bo_tim_len = timlen;
                *len_changed = 1;

                if (!bo->bo_tim_len) {
                    bo->bo_tim = bo->bo_tim_trailer = NULL;
                    return;
                }
                /* Update information element */
                (*tie)->tim_len = 3 + timlen;
            }

            qdf_mem_copy((*tie)->tim_bitmap, vap->iv_tim_bitmap + timoff,
                    bo->bo_tim_len);

            IEEE80211_VAP_TIMUPDATE_DISABLE(vap);

            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                    "%s: TIM updated, pending %u, off %u, len %u\n",
                    __func__, vap->iv_ps_pending, timoff, timlen);
        }

        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            /* Count down DTIM period */
            if ((*tie)->tim_count == 0)
                (*tie)->tim_count = (*tie)->tim_period - 1;
            else
                (*tie)->tim_count--;

            /* Update state for buffered multicast frames on DTIM */
            if (mcast && ((*tie)->tim_count == 0 || (*tie)->tim_period == 1))
                (*tie)->tim_bitctl |= 1;
            else
                (*tie)->tim_bitctl &= ~1;

        }
#if UMAC_SUPPORT_WNM
        *is_dtim = ((*tie)->tim_count == 0 || (*tie)->tim_period == 1);
#endif
    }
}

static void ieee80211_send_chan_switch_action(struct ieee80211_node *ni)
{
        struct ieee80211vap *vap = ni->ni_vap;
        struct ieee80211_action_mgt_args *actionargs;

        actionargs = OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_action_mgt_args) , GFP_KERNEL);
        if (actionargs == NULL) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Unable to alloc arg buf. Size=%d\n",
                     __func__, sizeof(struct ieee80211_action_mgt_args));
        } else {
            OS_MEMZERO(actionargs, sizeof(struct ieee80211_action_mgt_args));

            actionargs->category = IEEE80211_ACTION_CAT_SPECTRUM;
            actionargs->action   = IEEE80211_ACTION_CHAN_SWITCH;
            ieee80211_send_action(ni, actionargs, NULL);
            OS_FREE(actionargs);
        }
}

static void ieee80211_beacon_add_chan_switch_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {

        /* Find the new channel if it's not known already */
        ieee80211_find_new_chan(vap);

        if (ieee80211_ic_doth_is_set(ic) &&
                (ic->ic_flags & IEEE80211_F_CHANSWITCH) &&
                (ic->ic_chanchange_channel) &&
                IEEE80211_CHANCHANGE_BY_BEACONUPDATE_IS_SET(ic)) {

            ieee80211_add_channel_switch_ie(ni, bo, wbuf, len_changed);
            if (*len_changed == 1)
                ieee80211_send_chan_switch_action(ni);

        }
    }
}

static void ieee80211_beacon_erp_update(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
                (IEEE80211_IS_CHAN_ANYG(vap->iv_bsschan) ||
                 IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
                 IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan)) ) ||
            vap->iv_opmode == IEEE80211_M_BTAMP) { /* No IBSS Support */

        if (ieee80211_vap_erpupdate_is_set(vap) && bo->bo_erp) {
            ieee80211_add_erp(bo->bo_erp, ic);
            ieee80211_vap_erpupdate_clear(vap);
        }
    }
}

#if UMAC_SUPPORT_WNM
static int ieee80211_beacon_add_wnm_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        struct ieee80211_ath_tim_ie *tie,
        wbuf_t wbuf,
        int *is_dtim,
        uint32_t nfmsq_mask)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    uint32_t fms_counter_mask = 0;
    uint8_t *fmsie = NULL;
    uint8_t fmsie_len = 0;

    /* Add WNM specific IEs (like FMS desc...), if supported */
    if (ieee80211_vap_wnm_is_set(vap) &&
            ieee80211_wnm_fms_is_set(vap->wnm) &&
            vap->iv_opmode == IEEE80211_M_HOSTAP &&
            (bo->bo_fms_desc) && (bo->bo_fms_trailer)) {
        ieee80211_wnm_setup_fmsdesc_ie(ni, *is_dtim, &fmsie, &fmsie_len,
                &fms_counter_mask);

        if (IS_MBSSID_EMA_EXT_ENABLED(ic) &&
                !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            if (vap->iv_available_bcn_cmn_space - (fmsie_len - bo->bo_fms_len) < 0) {
                fmsie = NULL;
                fmsie_len = 0;
                vap->iv_available_bcn_cmn_space += bo->bo_fms_len;
            } else {
                vap->iv_available_bcn_cmn_space -= (fmsie_len - bo->bo_fms_len);
            }
        }

        if (fmsie_len != bo->bo_fms_len) {
            uint8_t *new_fms_trailer = (bo->bo_fms_desc + fmsie_len);
            int trailer_adjust =  new_fms_trailer - bo->bo_fms_trailer;

            /* Copy up/down trailer */
            if(trailer_adjust > 0) {
                uint8_t *tempbuf;

                tempbuf = qdf_mem_malloc(bo->bo_fms_trailerlen);
                if (tempbuf == NULL) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                            "%s: Unable to alloc FMS copy buf. Size=%d\n",
                            __func__, bo->bo_fms_trailerlen);
                    return -1;
                }

                qdf_mem_copy(tempbuf, bo->bo_fms_trailer, bo->bo_fms_trailerlen);
                qdf_mem_move(new_fms_trailer, tempbuf, bo->bo_fms_trailerlen);
                qdf_mem_free(tempbuf);
            } else {
                qdf_mem_copy(new_fms_trailer, bo->bo_fms_trailer,
                        bo->bo_fms_trailerlen);
            }

            bo->bo_tim_trailerlen += trailer_adjust;
            bo->bo_chanswitch_trailerlen += trailer_adjust;
            bo->bo_ecsa_trailerlen += trailer_adjust;
            bo->bo_vhtchnsw_trailerlen += trailer_adjust;
            bo->bo_mcst_trailerlen += trailer_adjust;

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += trailer_adjust;
#endif /* UMAC_SUPPORT_WNM */

            bo->bo_fms_trailer = new_fms_trailer;
            if (bo->bo_qos_traffic)
                bo->bo_qos_traffic += trailer_adjust;

            if (bo->bo_time_adv)
                bo->bo_time_adv += trailer_adjust;

            if (bo->bo_interworking)
                bo->bo_interworking += trailer_adjust;

            if (bo->bo_adv_proto)
                bo->bo_adv_proto += trailer_adjust;

            if (bo->bo_roam_consortium)
                bo->bo_roam_consortium += trailer_adjust;

            if (bo->bo_emergency_id)
                bo->bo_emergency_id  += trailer_adjust;

            if (bo->bo_mesh_id)
                bo->bo_mesh_id += trailer_adjust;

            if (bo->bo_mesh_conf)
                bo->bo_mesh_conf += trailer_adjust;

            if (bo->bo_mesh_awake_win)
                bo->bo_mesh_awake_win += trailer_adjust;

            if (bo->bo_beacon_time)
                bo->bo_beacon_time += trailer_adjust;

            if (bo->bo_mccaop_adv_ov)
                bo->bo_mccaop_adv_ov += trailer_adjust;

            if (bo->bo_mccaop_adv)
                bo->bo_mccaop_adv += trailer_adjust;

            if (bo->bo_mesh_cs_param)
                bo->bo_mesh_cs_param += trailer_adjust;

            if (bo->bo_qmf_policy)
                bo->bo_qmf_policy += trailer_adjust;

            if (bo->bo_qload_rpt)
                bo->bo_qload_rpt += trailer_adjust;

            if (bo->bo_hcca_upd_cnt)
                bo->bo_hcca_upd_cnt += trailer_adjust;

            if (bo->bo_multiband)
                bo->bo_multiband += trailer_adjust;

            if (bo->bo_vhtcap)
                bo->bo_vhtcap += trailer_adjust;

            if (bo->bo_vhtop)
                bo->bo_vhtop += trailer_adjust;

            if (bo->bo_vhttxpwr)
                bo->bo_vhttxpwr += trailer_adjust;

            if (bo->bo_vhtchnsw)
                bo->bo_vhtchnsw += trailer_adjust;

            if (bo->bo_ext_bssload)
                bo->bo_ext_bssload += trailer_adjust;

            if (bo->bo_quiet_chan)
                bo->bo_quiet_chan += trailer_adjust;

            if (bo->bo_opt_mode_note)
                bo->bo_opt_mode_note += trailer_adjust;

            if (bo->bo_rnr)
                bo->bo_rnr += trailer_adjust;

            if (bo->bo_rnr2)
                bo->bo_rnr2 += trailer_adjust;

            if (bo->bo_tvht)
                bo->bo_tvht += trailer_adjust;

#if QCN_ESP_IE
            if (bo->bo_esp_ie)
                bo->bo_esp_ie += trailer_adjust;
#endif

            if (bo->bo_future_chan)
                bo->bo_future_chan += trailer_adjust;

            if (bo->bo_cag_num)
                bo->bo_cag_num += trailer_adjust;

            if (bo->bo_fils_ind)
                bo->bo_fils_ind += trailer_adjust;

            if (bo->bo_ap_csn)
                bo->bo_ap_csn += trailer_adjust;

            if (bo->bo_diff_init_lnk)
                bo->bo_diff_init_lnk += trailer_adjust;

            if (bo->bo_service_hint)
                bo->bo_service_hint += trailer_adjust;

            if (bo->bo_service_hash)
                bo->bo_service_hash += trailer_adjust;

            if (bo->bo_hecap)
                bo->bo_hecap += trailer_adjust;

            if (bo->bo_heop)
                bo->bo_heop += trailer_adjust;

            if (bo->bo_twt)
                bo->bo_twt += trailer_adjust;

#if ATH_SUPPORT_UORA
            if (bo->bo_uora_param)
                bo->bo_uora_param += trailer_adjust;
#endif

            if (bo->bo_bcca)
                bo->bo_bcca += trailer_adjust;

#if OBSS_PD
            if(bo->bo_srp_ie)
                bo->bo_srp_ie += trailer_adjust;
#endif

            if (bo->bo_muedca)
                bo->bo_muedca += trailer_adjust;

            if (bo->bo_ess_rpt)
                bo->bo_ess_rpt += trailer_adjust;

            if (bo->bo_ndp_rpt_param)
                bo->bo_ndp_rpt_param += trailer_adjust;

            if (bo->bo_he_bss_load)
                bo->bo_he_bss_load += trailer_adjust;

            if (bo->bo_mcst)
                bo->bo_mcst += trailer_adjust;

            if (bo->bo_secchanoffset)
                bo->bo_secchanoffset += trailer_adjust;

            if (bo->bo_rsnx)
                bo->bo_rsnx += trailer_adjust;

            if (bo->bo_ath_caps)
                bo->bo_ath_caps += trailer_adjust;

            if (bo->bo_extender_ie)
                bo->bo_extender_ie += trailer_adjust;

            if (bo->bo_htinfo_vendor_specific)
                bo->bo_htinfo_vendor_specific += trailer_adjust;

            if (bo->bo_mbo_cap )
                bo->bo_mbo_cap  += trailer_adjust;

            if (bo->bo_apriori_next_channel)
                bo->bo_apriori_next_channel += trailer_adjust;

            if (bo->bo_bwnss_map)
                bo->bo_bwnss_map += trailer_adjust;

#if QCN_IE
            if (bo->bo_qcn_ie)
                bo->bo_qcn_ie += trailer_adjust;
#endif

            if (bo->bo_software_version_ie)
                bo->bo_software_version_ie += trailer_adjust;

            if (bo->bo_xr)
                bo->bo_xr += trailer_adjust;

            if (bo->bo_whc_apinfo)
                bo->bo_whc_apinfo += trailer_adjust;

            if (bo->bo_interop_vhtcap)
                bo->bo_interop_vhtcap += trailer_adjust;

            if (bo->bo_wme)
                bo->bo_wme += trailer_adjust;

            if (bo->bo_appie_buf)
                bo->bo_appie_buf += trailer_adjust;


            if (fmsie_len > bo->bo_fms_len)
                wbuf_append(wbuf, fmsie_len - bo->bo_fms_len);
            else
                wbuf_trim(wbuf, bo->bo_fms_len - fmsie_len);

            bo->bo_fms_len = fmsie_len;
            if (!bo->bo_fms_len) {
                bo->bo_fms_desc = bo->bo_fms_trailer = NULL;
            }
        }

        if (fmsie_len &&  (bo->bo_fms_desc) && (bo->bo_fms_trailer)) {
            qdf_mem_copy(bo->bo_fms_desc, fmsie, fmsie_len);
            bo->bo_fms_trailer = bo->bo_fms_desc + fmsie_len;
            bo->bo_fms_len = fmsie_len;
        }

        if (tie != NULL) {
            /* Update state for buffered multicast frames on DTIM */
            if (nfmsq_mask & fms_counter_mask)
                tie->tim_bitctl |= 1;
        }
    }

    return 0;
}
#endif /* UMAC_SUPPORT_WNM */

static void ieee80211_add_apriori_next_chan(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo)
{
    struct ieee80211com *ic = ni->ni_ic;

    if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic) &&
            IEEE80211_IS_CHAN_DFS(ic->ic_curchan)) {
        if(bo->bo_apriori_next_channel && ic->ic_tx_next_ch)
            ieee80211_add_next_channel(bo->bo_apriori_next_channel, ni, ic,
                    IEEE80211_FC0_SUBTYPE_BEACON);
    }
}

/* Add APP_IE buffer if app updated it */
static void ieee80211_beacon_add_app_ie(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    uint8_t *frm_buf = NULL, *temp = NULL;
    uint8_t len = 0;

    IEEE80211_VAP_LOCK(vap);

    if (IEEE80211_VAP_IS_APPIE_UPDATE_ENABLED(vap)) {
        frm_buf = (uint8_t *)qdf_mem_malloc(IEEE80211_APPIE_MAX);
        if (!frm_buf) {
            IEEE80211_VAP_APPIE_UPDATE_DISABLE(vap);
            IEEE80211_VAP_UNLOCK(vap);
            return;
        }

        temp = frm_buf;
        /* Add the IEs in new memory location */
        len = __ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_VENDOR, false,
                &temp, TYPE_APP_IE_BUF, false);
        if (len != bo->bo_appie_buf_len) {
            int diff_len;

            diff_len = len - bo->bo_appie_buf_len;
            bo->bo_appie_buf_len = (u_int16_t) len;

            /* update the trailer lens */
            bo->bo_chanswitch_trailerlen += diff_len;
            bo->bo_tim_trailerlen += diff_len;
            bo->bo_ecsa_trailerlen += diff_len;
            bo->bo_mcst_trailerlen += diff_len;
            bo->bo_vhtchnsw_trailerlen += diff_len;
            bo->bo_secchanoffset_trailerlen += diff_len;

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += diff_len;
#endif

            /* Append or trim based on diff_len
             * If append, update size, shift extension IEs last to first, copy frm_buf
             * If trim, shift extension IEs first to last, update size, copy frm_buf
             */
            if (diff_len > 0)
                wbuf_append(wbuf, diff_len);
            else
                wbuf_trim(wbuf, -(diff_len));

            *len_changed = 1;
        }

        /* Copy the newly added IEs to frm (bo_appie_buf) */
        qdf_mem_copy(bo->bo_appie_buf, temp-len, len);
        qdf_mem_free(frm_buf);
        IEEE80211_VAP_APPIE_UPDATE_DISABLE(vap);

        *update_beacon_copy = true;
    }

    IEEE80211_VAP_UNLOCK(vap);
}

#if QCA_SUPPORT_SON
static int ieee80211_beacon_add_son_ie(
        struct ieee80211vap *vap,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    uint8_t *frm = NULL;

    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            son_vdev_fext_capablity(vap->vdev_obj,SON_CAP_GET,
                WLAN_VDEV_FEXT_SON_INFO_UPDATE) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        uint16_t newlen;
        uint8_t *tempbuf = NULL;
        uint8_t *buf = NULL;

        tempbuf = OS_MALLOC(vap->iv_ic->ic_osdev,
                sizeof(struct ieee80211_ie_whc_apinfo),
                GFP_KERNEL);
        if(tempbuf == NULL)
            return -1;

        buf = tempbuf;
        newlen = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                        IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_VENDOR, IEEE80211_ELEMID_VENDOR_SON_AP,
                        &buf, TYPE_APP_IE_BUF, NULL, true);

        if(newlen != bo->bo_whc_apinfo_len) {
            int diff_len = newlen - bo->bo_whc_apinfo_len;

            bo->bo_whc_apinfo_len = newlen;

            /* update the trailer lens */
            bo->bo_tim_trailerlen += diff_len;
            bo->bo_chanswitch_trailerlen += diff_len;
            bo->bo_secchanoffset_trailerlen += diff_len;
            bo->bo_ecsa_trailerlen += diff_len;
            bo->bo_mcst_trailerlen += diff_len;
            bo->bo_vhtchnsw_trailerlen += diff_len;
            bo->bo_bcca_trailerlen += diff_len;

#if UMAC_SUPPORT_WNM
            bo->bo_fms_trailerlen += diff_len;
#endif

            if (diff_len > 0)
                wbuf_append(wbuf, diff_len);
            else
                wbuf_trim(wbuf, -(diff_len));

            *len_changed = 1;
        }

        if (bo->bo_whc_apinfo) {
            OS_MEMCPY(bo->bo_whc_apinfo, tempbuf, bo->bo_whc_apinfo_len);
            frm = bo->bo_whc_apinfo + bo->bo_whc_apinfo_len;
            son_vdev_fext_capablity(vap->vdev_obj,SON_CAP_CLEAR,
                    WLAN_VDEV_FEXT_SON_INFO_UPDATE);
        }

        OS_FREE(tempbuf);
        *update_beacon_copy = true;
    }

    return 0;
}
#endif

#if DBDC_REPEATER_SUPPORT
/* Add Extender IE */
static void ieee80211_beacon_add_extender_ie(
        struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int *len_changed,
        bool *update_beacon_copy)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct global_ic_list *ic_list = ic->ic_global_list;

    if (ic_list->same_ssid_support) {
       if (bo->bo_extender_ie) {
            /* Add the Extender IE */
           ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_BEACON, bo->bo_extender_ie);
       } else {
           ieee80211_beacon_reinit(ni, bo, wbuf, len_changed, update_beacon_copy);
       }
    } else {
        bo->bo_extender_ie = NULL;
    }
}
#endif

void
ieee80211_adjust_bos_for_bsscolor_change_ie(
        struct ieee80211_beacon_offsets *bo,
        uint8_t offset) {

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_INFO, "%s>>", __func__);

    /* Update the pointers following this element and also trailer
     * length.
     */
    bo->bo_tim_trailerlen             += offset;
    bo->bo_chanswitch_trailerlen      += offset;
    bo->bo_vhtchnsw_trailerlen        += offset;
    bo->bo_secchanoffset_trailerlen   += offset;
    bo->bo_mcst_trailerlen            += offset;
    bo->bo_ecsa_trailerlen            += offset;
#if UMAC_SUPPORT_WNM
    bo->bo_fms_trailerlen             += offset;
#endif
#if OBSS_PD
    if(bo->bo_srp_ie)
        bo->bo_srp_ie += offset;
#endif

    if(bo->bo_muedca)
        bo->bo_muedca += offset;

    if (bo->bo_ess_rpt)
        bo->bo_ess_rpt += offset;

    if (bo->bo_ndp_rpt_param)
        bo->bo_ndp_rpt_param += offset;

    if (bo->bo_he_bss_load)
        bo->bo_he_bss_load += offset;

    if (bo->bo_he_6g_bandcap) {
        bo->bo_he_6g_bandcap += offset;
    }

    if (bo->bo_mcst)
        bo->bo_mcst += offset;

    if (bo->bo_secchanoffset)
        bo->bo_secchanoffset += offset;

    if (bo->bo_rsnx)
        bo->bo_rsnx += offset;

    if (bo->bo_ath_caps)
        bo->bo_ath_caps += offset;

    if (bo->bo_extender_ie)
        bo->bo_extender_ie += offset;

    if (bo->bo_htinfo_vendor_specific)
        bo->bo_htinfo_vendor_specific += offset;

    if (bo->bo_mbo_cap )
        bo->bo_mbo_cap  += offset;

    if (bo->bo_apriori_next_channel)
        bo->bo_apriori_next_channel += offset;

    if (bo->bo_bwnss_map)
        bo->bo_bwnss_map += offset;

#if QCN_IE
    if (bo->bo_qcn_ie)
        bo->bo_qcn_ie += offset;
#endif

    if (bo->bo_software_version_ie)
        bo->bo_software_version_ie += offset;

    if (bo->bo_xr)
        bo->bo_xr += offset;

    if (bo->bo_whc_apinfo)
        bo->bo_whc_apinfo += offset;

    if (bo->bo_interop_vhtcap)
        bo->bo_interop_vhtcap += offset;

    if (bo->bo_wme)
        bo->bo_wme += offset;

    if (bo->bo_appie_buf)
        bo->bo_appie_buf += offset;

#if ATH_SUPPORT_UORA
    if(bo->bo_uora_param)
        bo->bo_uora_param += offset;
#endif

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_INFO, "%s<<", __func__);
}

static int ieee80211_csa_interop_bss_is_desired(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    int desired = 0;

    ic = vap->iv_ic;

    if (ic->ic_flags & IEEE80211_F_CHANSWITCH) {
        desired = 1;
        if (!vap->iv_csa_interop_bss)
            desired = 0;
    }

    return desired;
}

/*
 * Update the dynamic parts of a beacon frame based on the current state.
 */
#if UMAC_SUPPORT_WNM
int ieee80211_beacon_update(struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int mcast,
        u_int32_t nfmsq_mask)
#else
int ieee80211_beacon_update(struct ieee80211_node *ni,
        struct ieee80211_beacon_offsets *bo,
        wbuf_t wbuf,
        int mcast)
#endif
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic  = NULL;
    int len_changed = 0;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    bool update_beacon_copy = false;
    struct ieee80211_ath_tim_ie *tie = NULL;
    systime_t curr_time = OS_GET_TIMESTAMP();
    static systime_t prev_store_beacon_time;
    int retval;
#if UMAC_SUPPORT_WNM
    int is_dtim = 0;
#endif
    int interop_bss_desired;

    if (!ni) {
        qdf_err("ni is null");
        return -1;
    }
    vap = ni->ni_vap;

    if (!vap) {
        qdf_err("vap is null");
        return -1;
    }
    ic = ni->ni_ic;

    if (!ic) {
        qdf_err("ic is null");
        return -1;
    }

    if((curr_time - prev_store_beacon_time) >=
            INTERVAL_STORE_BEACON * NUM_MILLISEC_PER_SEC){
        update_beacon_copy = true;
        prev_store_beacon_time = curr_time;
    }

#if QCN_IE
    /* If broadcast probe response feature is enabled and beacon offload is not enabled
     * then flag the current beacon as sent and calculate the next beacon timestamp.
     */
    if (vap->iv_bpr_enable && (!vap->iv_bcn_offload_enable)) {
       ieee80211_flag_beacon_sent(vap);
    }
#endif
    vap->iv_estimate_tbtt = qdf_ktime_to_ms(qdf_ktime_get());

    /* Update neighbor APs informations for AP Channel Report IE, RNR IE and MBO_OCE IE */
    if ((CONVERT_SYSTEM_TIME_TO_MS(curr_time) - vap->nbr_scan_ts) >=
        (vap->nbr_scan_period * NUM_MILLISEC_PER_SEC)) {

        if (vap->ap_chan_rpt_enable && !ieee80211_bg_scan_enabled(vap))
            ieee80211_update_ap_chan_rpt(vap);

        if (vap->rnr_enable && !ieee80211_bg_scan_enabled(vap))
            ieee80211_update_rnr(vap);
#if ATH_SUPPORT_MBO
        if (ieee80211_vap_oce_check(vap)) {
            ieee80211_update_non_oce_ap_presence (vap);
            if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
                ieee80211_update_11b_ap_presence (vap);
        }
#endif
        vap->nbr_scan_ts = CONVERT_SYSTEM_TIME_TO_MS(curr_time);
    }
#if QCN_ESP_IE
    if(ic->ic_esp_flag == 1){
        vap->iv_update_vendor_ie = 1;
        ic->ic_esp_flag = 0;
    }
#endif

    /* If Beacon Tx is suspended, then don't send this beacon */
    if (ieee80211_mlme_beacon_suspend_state(vap)) {
        qdf_err("[%s] skip Tx beacon during to suspend.\n", vap->iv_netdev_name);
        return -1;
    }

    /*
     * Use the non-QoS sequence number space for BSS node
     * to avoid sw generated frame sequence the same as H/W generated frame,
     * the value lower than min_sw_seq is reserved for HW generated frame.
     */
    if ((ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] & IEEE80211_SEQ_MASK) <
            MIN_SW_SEQ)
        ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] = MIN_SW_SEQ;

    *(uint16_t *)&wh->i_seq[0] = htole16(
            ni->ni_txseqs[IEEE80211_NON_QOS_SEQ] << IEEE80211_SEQ_SEQ_SHIFT);
    ni->ni_txseqs[IEEE80211_NON_QOS_SEQ]++;

    interop_bss_desired = ieee80211_csa_interop_bss_is_desired(vap);

    vap->beacon_reinit_done = false;

    if (interop_bss_desired != vap->iv_csa_interop_bss_active) {
        qdf_info("csa interop bss %hhu -> %hhu",
                 vap->iv_csa_interop_bss_active, interop_bss_desired);

        vap->iv_csa_interop_bss_active = interop_bss_desired;
        ieee80211_beacon_reinit(ni, bo, wbuf, &len_changed, &update_beacon_copy);
    }

    ieee80211_beacon_check_and_reinit_beacon(ni, bo, wbuf, &len_changed,
            &update_beacon_copy);

    IEEE80211_CHAN_CHANGE_LOCK(ic);
    if (!IEEE80211_CHANCHANGE_STARTED_IS_SET(ic) &&
            (ic->ic_flags & IEEE80211_F_CHANSWITCH)) {
        IEEE80211_CHANCHANGE_STARTED_SET(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_SET(ic);
    }
    IEEE80211_CHAN_CHANGE_UNLOCK(ic);

    retval = ieee80211_change_channel(ni, &update_beacon_copy,
            &len_changed, wbuf, bo);
    if (!retval) {
        qdf_err("%s: channel change failed", vap->iv_netdev_name);
        IEEE80211_CHANCHANGE_STARTED_CLEAR(ic);
        IEEE80211_CHANCHANGE_BY_BEACONUPDATE_CLEAR(ic);
        return -1;
    }

    /* Update cap info. In MBSS IE case, update for tx VAP only */
    if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        ieee80211_update_capinfo(vap, bo);
    }

    /* Update TIM */
    ieee80211_beacon_update_tim(ni, bo, &tie, wbuf, &len_changed, mcast,
            &is_dtim);

    /* Update power constraints */
    ieee80211_beacon_update_pwrcnstr(vap, bo);

    /* Update CSA, ECSA, CSA Wrapper, Secondary Channel Offset and MCST */
    ieee80211_beacon_add_chan_switch_ie(ni, bo, wbuf, &len_changed);

    /* Update quiet param */
    ieee80211_quiet_beacon_update(vap, ic, bo);

    /* Update channel utilization information */
    ieee80211_update_chan_utilization(vap);

    /* Add the TPC Report IE in the beacon */
    if (bo->bo_tpcreport) {
        /* No need to check return value as the fatal conditions
         * (NULL check) has been already checked at the beginning
         * of this function. Ignore non-fatal ones if any
         */
        (void) ieee80211_add_tpc_ie(bo->bo_tpcreport, vap, IEEE80211_FC0_SUBTYPE_BEACON);
    }

    /* Update ERP IE */
    ieee80211_beacon_erp_update(vap, bo);

    /* Update bssload*/
    ieee80211_qbssload_beacon_update(vap, ni, bo);

    /* Update extension bssload */
    ieee80211_ext_bssload_beacon_update(vap, ni, bo);

    /* Add HT capability */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        ieee80211_beacon_add_htcap(ni, bo);
    }

    /* Add VHT capability */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        ieee80211_beacon_add_vhtcap(ni, bo);
    }

    /* Increment the TIM update beacon count to indicate inclusion of BCCA IE */
    if(vap->iv_bcca_ie_status == BCCA_START) {
        update_beacon_copy = true;
    }
    /* Increment the TIM update beacon count to indicate change in HEOP param */
    if(ic->ic_is_heop_param_updated) {
        update_beacon_copy = true;

    }
    /* Add HE BSS Color Change IE */
    ieee80211_beacon_add_bsscolor_change_ie(ni, bo, wbuf, &len_changed);

    /* Add HE capability */
    ieee80211_add_he_cap(ni, bo);

#if OBSS_PD
    if(vap->iv_is_spatial_reuse_updated) {
        ieee80211_add_srp_ie(vap, bo->bo_srp_ie);
        update_beacon_copy = true;
    }
#endif /* OBSS PD */

#if ATH_SUPPORT_UORA
    /* Update UORA param */
    ieee80211_beacon_update_uora_param(vap, bo, &update_beacon_copy);
#endif

    if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        /* Update MU-EDCA param */
        ieee80211_beacon_update_muedca_param(vap, bo, &update_beacon_copy);

        /* Add WME param */
        ieee80211_beacon_add_wme_param(vap, bo, &update_beacon_copy);
    }

    /* Update WNM IE */
#if UMAC_SUPPORT_WNM
    retval = ieee80211_beacon_add_wnm_ie(ni, bo, tie, wbuf,
            &is_dtim, nfmsq_mask) ;
    if (retval == -1)
        return -1;
#endif

    /* Update APRIORI next channel */
    ieee80211_add_apriori_next_chan(ni, bo);

    /* Add SON IE */
#if QCA_SUPPORT_SON
    retval = ieee80211_beacon_add_son_ie(vap, bo, wbuf, &len_changed,
            &update_beacon_copy);
    if (retval == -1)
        return -1;
#endif

#if DBDC_REPEATER_SUPPORT
    /* Update Extender IE */
    ieee80211_beacon_add_extender_ie(ni, bo, wbuf, &len_changed,
            &update_beacon_copy);
#endif

#if UMAC_SUPPORT_WNM
    if (update_beacon_copy) {
        ieee80211_wnm_tim_incr_checkbeacon(vap);
    }
#endif

    if (update_beacon_copy && ieee80211_vap_copy_beacon_is_set(vap)) {
        store_beacon_frame(vap, (uint8_t *)wbuf_header(wbuf),
                wbuf_get_pktlen(wbuf));
    }

    return len_changed;
}

#if UMAC_SUPPORT_WNM
int ieee80211_prb_rsp_update(struct ieee80211_node *ni,
                    struct ieee80211_beacon_offsets *bo, wbuf_t wbuf,
                    int mcast, u_int32_t nfmsq_mask)
#else
int ieee80211_prb_rsp_update(struct ieee80211_node *ni,
                    struct ieee80211_beacon_offsets *bo, wbuf_t wbuf, int mcast)
#endif
{
    struct ieee80211vap *vap = ni->ni_vap;
    bool update_beacon_copy = false;
    int len_changed = 0;

    /* Update cap info */
    ieee80211_update_capinfo(vap, bo);

    /* Update power constraints */
    ieee80211_beacon_update_pwrcnstr(vap, bo);

    /* Update quiet param */
    ieee80211_quiet_beacon_update(vap, ni->ni_ic, bo);

    /* Add the TPC Report IE in 20TU probe response */
    if (bo->bo_tpcreport) {
        if (!ieee80211_add_tpc_ie(bo->bo_tpcreport, vap,
                            IEEE80211_FC0_SUBTYPE_PROBE_RESP))
            return -1;
    }

    /* Update ERP IE */
    ieee80211_beacon_erp_update(vap, bo);

    /* Update bssload*/
    ieee80211_qbssload_beacon_update(vap, ni, bo);

   /* Add HE capability */
    ieee80211_add_he_cap(ni, bo);

#if OBSS_PD
    if(vap->iv_is_spatial_reuse_updated)
        ieee80211_add_srp_ie(vap, bo->bo_srp_ie);

#endif /* OBSS PD */

    /* Update MU-EDCA param */
    ieee80211_beacon_update_muedca_param(vap, bo, &update_beacon_copy);

    /* Add WME param */
    ieee80211_beacon_add_wme_param(vap, bo, &update_beacon_copy);

    /* Add application IE */
    ieee80211_beacon_add_app_ie(vap, bo, wbuf, &len_changed,
            &update_beacon_copy);

    return 0;

}

void wlan_vdev_beacon_update(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    bool is_mbssid_enabled        = wlan_pdev_nif_feat_cap_get(pdev,
                                        WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_tx_vap = !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
    bool is_csa    = ((ic->ic_flags & IEEE80211_F_CHANSWITCH) &&
                     (ic->ic_chanchange_channel != NULL));

    if (vap->iv_bcn_offload_enable &&
            ieee80211_is_vap_state_running(vap) &&
            (vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            /* in case of mbssid allow beacon update
             * through this path only if the update
             * is being triggered for
             * 1. a tx-vap or
             * 2. a non-Tx vap for non-Tx profile related
             * change or
             * 3. a non-Tx vap with CSA
             */
            (!is_mbssid_enabled || is_tx_vap ||
             vap->iv_mbss.non_tx_profile_change ||
             is_csa) &&
            ic->ic_vdev_beacon_template_update) {
        ic->ic_vdev_beacon_template_update(vap);
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
            ic->ic_vdev_prb_rsp_tmpl_update(vap);
    }

    return;
}
qdf_export_symbol(wlan_vdev_beacon_update);

void wlan_pdev_beacon_update(struct ieee80211com *ic)
{
    struct ieee80211vap *vap;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    bool is_mbssid_enabled        = wlan_pdev_nif_feat_cap_get(pdev,
                                        WLAN_PDEV_F_MBSS_IE_ENABLE);

    if (is_mbssid_enabled) {
        vap = ic->ic_mbss.transmit_vap;
        if (vap)
            wlan_vdev_beacon_update(vap);
    } else {
        TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
            if (vap)
                wlan_vdev_beacon_update(vap);
    }

    return;
}

void ieee80211_csa_interop_phy_update(struct ieee80211_node *ni, int rx_bw)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    int chan_bw;

    if (!ni) {
        return;
    }

    vap = ni->ni_vap;
    ic = vap->iv_ic;

    switch (rx_bw) {
        case IEEE80211_CWM_WIDTH20:
        case IEEE80211_CWM_WIDTH40:
        case IEEE80211_CWM_WIDTH80:
        case IEEE80211_CWM_WIDTH160:
            switch (ieee80211_get_chan_width(vap->iv_bsschan)) {
                case 5:
                case 10:
                case 20:
                    chan_bw = IEEE80211_CWM_WIDTH20;
                    break;
                case 40:
                    chan_bw = IEEE80211_CWM_WIDTH40;
                    break;
                case 80:
                    chan_bw = IEEE80211_CWM_WIDTH80;
                    break;
                case 160:
                    chan_bw = IEEE80211_CWM_WIDTH160;
                    break;
                default:
                    chan_bw = IEEE80211_CWM_WIDTH20;
                    break;
            }

            if (rx_bw <= ni->ni_chwidth)
                break;

            if (rx_bw > chan_bw)
                break;

            if (unlikely(WARN_ONCE((unlikely(!(ni->ni_flags & IEEE80211_NODE_HT)) &&
                                    unlikely(rx_bw >= IEEE80211_CWM_WIDTH40)),
                                   "%s: [%s, %pM] ignoring %d -> %d, !ht && cw>=40",
                                   __func__, vap->iv_netdev_name, ni->ni_macaddr,
                                   ni->ni_chwidth, rx_bw)))
                break;

            if (unlikely(WARN_ONCE((unlikely(!(ni->ni_flags & IEEE80211_NODE_VHT)) &&
                                    unlikely(rx_bw >= IEEE80211_CWM_WIDTH80)),
                                   "%s: [%s, %pM] ignoring %d -> %d, !vht && cw>=80",
                                   __func__, vap->iv_netdev_name, ni->ni_macaddr,
                                   ni->ni_chwidth, rx_bw)))
                break;

            if (unlikely(WARN_ONCE((unlikely(!ni->ni_160bw_requested) &&
                                    unlikely(rx_bw >= IEEE80211_CWM_WIDTH160)),
                                   "%s: [%s, %pM] ignoring %d -> %d, !160assoc && cw>=160",
                                   __func__, vap->iv_netdev_name, ni->ni_macaddr,
                                   ni->ni_chwidth, rx_bw)))
                break;

            qdf_debug("[%s, %pM] upgrading CW %d -> %d (chan_bw=%d)",
                     vap->iv_netdev_name, ni->ni_macaddr,
                     ni->ni_chwidth, rx_bw, chan_bw);

            ni->ni_chwidth = rx_bw;
            ic->ic_chwidth_change(ni);
            break;
        case -1:
            qdf_debug("[%s, %pM] downgrading CW %d -> %d",
                     vap->iv_netdev_name, ni->ni_macaddr, ni->ni_chwidth,
                     IEEE80211_CWM_WIDTH20);

            ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            ic->ic_chwidth_change(ni);
            break;
        default:
            qdf_debug("[%s, %pM] unsupported CW %d -> %d, ignoring",
                     vap->iv_netdev_name, ni->ni_macaddr,
                     ni->ni_chwidth, rx_bw);
            break;
    }
}

void ieee80211_csa_interop_update(void *ctrl_pdev, enum WDI_EVENT event,
                                  void *buf, uint16_t id, uint32_t type)
{
    qdf_nbuf_t nbuf;
    struct wlan_objmgr_pdev *pdev;
    struct ieee80211com *ic;
    struct cdp_rx_indication_ppdu *cdp_rx_ppdu;
    uint32_t bw;
    struct ieee80211_node *ni;

    nbuf = buf;
    if (!nbuf) {
        qdf_err("nbuf is null");
        return;
    }

    pdev = (struct wlan_objmgr_pdev *)ctrl_pdev;
    if (!pdev) {
        qdf_err("pdev is null");
        return;
    }

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    cdp_rx_ppdu = (struct cdp_rx_indication_ppdu *)qdf_nbuf_data(nbuf);
    bw = cdp_rx_ppdu->u.bw;

    ni = ieee80211_find_node(ic, cdp_rx_ppdu->mac_addr, WLAN_MLME_HANDLER_ID);
    if (!ni) {
        qdf_err("ni is null");
        return;
    }

    ieee80211_csa_interop_phy_update(ni, bw);
    ieee80211_free_node(ni, WLAN_MLME_HANDLER_ID);
}
qdf_export_symbol(ieee80211_csa_interop_update);
