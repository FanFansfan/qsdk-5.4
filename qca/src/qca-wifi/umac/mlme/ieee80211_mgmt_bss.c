/*
 * Copyright (c) 2011,2018-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 * Qualcomm Innovation Center,Inc. has chosen to take madwifi subject to the BSD license and terms.
 *
 * 2011 Qualcomm Atheros, Inc.
 * Qualcomm Atheros, Inc. has chosen to take madwifi subject to the BSD license and terms.
 *
 * Copyright (c) 2008, Atheros Communications Inc.
 */

#include "ieee80211_mlme_priv.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"
#include "osif_private.h"
#include <ieee80211_mbo.h>

#include "ol_if_athvar.h"
#include "cfg_ucfg_api.h"
#include <wlan_utility.h>
#include <wlan_rnr.h>
#include <wlan_son_pub.h>
/* This macro is copied from FW headers*/
#define HTT_TX_EXT_TID_NONPAUSE_PRIVATE 19

/*
 * ieee80211_prb_add_rsn_ie: Add RSN IE in the frame
 *
 * @vap   : VAP handle
 * @frm   : frm pointer to add the IE
 * @po    : Probe offsets to mark IEs' start address
 * @optie : Optional IE buffer (local buffer)
 *
 * Return: frm pointer after adding, if RSN IE is added,
 *         NULL elsewhere
 */
uint8_t *ieee80211_prb_add_rsn_ie(struct ieee80211vap *vap,
        uint8_t *frm, struct ieee80211_beacon_offsets **po,
        struct ieee80211_app_ie_t *optie)
{
    if (!vap->iv_rsn_override) {
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RSN, -1, &frm,
                TYPE_ALL_BUF, optie, true)) {

            /* Add RSN IE if not present */
#if ATH_SUPPORT_HS20
            if (!vap->iv_osen) {
#endif

                if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj,
                            (1 << WLAN_CRYPTO_AUTH_RSNA))) {
                    frm = wlan_crypto_build_rsnie(vap->vdev_obj, frm, NULL);
                    if(!frm) {
                        (*po)->bo_rsn = NULL;
                        return NULL;
                    }
                }

#if ATH_SUPPORT_HS20
            } else {
                (*po)->bo_rsn = NULL;
            }
#endif
        }
    }

    return frm;
}

/*
 * ieee80211_prb_add_vht_ies: Add VHT cap, op, power envelope, CS Wrapper
 *                        and EBSS load IEs in the frame
 *
 * @ni       : Node information handle
 * @frm      : frm pointer to add IEs
 * @macaddr  : MAC address of the STA
 * @extractx : Extra Context information
 * @po       : Probe offsets to mark IEs' start address
 *
 * Return: frm pointer after adding IEs
 */
uint8_t *ieee80211_prb_add_vht_ies(struct ieee80211_node *ni,
        uint8_t *frm, uint8_t *macaddr,
        struct ieee80211_framing_extractx *extractx,
        struct ieee80211_beacon_offsets **po)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;

    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
        ieee80211vap_vhtallowed(vap)) {

        /* 59. VHT Capabilities */
        (*po)->bo_vhtcap = frm;
        if (ASSOCWAR160_IS_VHT_CAP_CHANGE(vap->iv_cfg_assoc_war_160w))
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx, macaddr);
        else
            frm = ieee80211_add_vhtcap(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP, NULL, macaddr);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, (*po)->bo_vhtcap, &frm,
                &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);

        /* 60. VHT Operation */
        (*po)->bo_vhtop = frm;
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, (*po)->bo_vhtop, &frm,
                &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);

        /* 61. Transmit Power Envelope element */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            (*po)->bo_vhttxpwr = frm;
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                                                         !IEEE80211_TPE_IS_SUB_ELEMENT);
            (void)ieee80211_check_driver_tx_cmn_ie(vap, (*po)->bo_vhttxpwr,
                    &frm, &vap->iv_available_prb_cmn_space,
                    IEEE80211_FRAME_TYPE_PROBERESP);
        } else {
            (*po)->bo_vhttxpwr = NULL;
        }

        /* 62. Channel Switch Wrapper */
        if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
                && (IEEE80211_IS_CHAN_11AC(vap->iv_bsschan)
                    || IEEE80211_IS_CHAN_11AXA(vap->iv_bsschan))
                && ieee80211vap_vhtallowed(vap)
                && (ic->ic_chanchange_channel != NULL)) {

            /* channel switch wrapper element */
            (*po)->bo_vhtchnsw = frm;
            frm = ieee80211_add_chan_switch_wrp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                    /* When switching to new country by sending ECSA IE,
                     * new country IE should be also be added.
                     * As of now we dont support switching to new country
                     * without bringing down vaps so new country IE is not
                     * required.
                     */
                    (/*ecsa_ie ? IEEE80211_VHT_EXTCH_SWITCH :*/
                     !IEEE80211_VHT_EXTCH_SWITCH));
            (void)ieee80211_check_driver_tx_cmn_ie(vap, (*po)->bo_vhtchnsw,
                    &frm, &vap->iv_available_prb_cmn_space,
                    IEEE80211_FRAME_TYPE_PROBERESP);
        } else {
            (*po)->bo_vhtchnsw = NULL;
        }

        /* 63. Extended BSS Load */
        (*po)->bo_ext_bssload = frm;
        frm = ieee80211_add_ext_bssload(frm, ni);
        (void)ieee80211_check_driver_tx_cmn_ie(vap, (*po)->bo_ext_bssload, &frm,
                &vap->iv_available_prb_cmn_space,
                IEEE80211_FRAME_TYPE_PROBERESP);
    } else {
        (*po)->bo_vhtcap = NULL;
        (*po)->bo_vhtop = NULL;
        (*po)->bo_vhttxpwr = NULL;
        (*po)->bo_vhtchnsw = NULL;
        (*po)->bo_ext_bssload = NULL;
    }

    return frm;
}

#if QCA_SUPPORT_EMA_EXT
/*
* ieee80211_prb_adjust_pos_for_context: Put back MBSSID/RNR IE in its position,
*                                            move other IEs, and adjust po's
*
* @ic  : Common state handle
* @frm : frm pointer to add IEs
* @po  : Probe response offsets to be adjusted
* @offset          : Length of MBSSID/RNR IE
* @offset_context  : Context (MBSSID/RNR IE)
*
* Return: frm pointer after the put-back of context
*/

uint8_t *ieee80211_prb_adjust_pos_for_context(
        struct ieee80211com *ic,
        uint8_t *frm,
        struct ieee80211_beacon_offsets *po,
        uint16_t offset,
        ieee80211_ie_offset_context_t offset_context)
{
    uint16_t ie_trailer_len = 0;

    /* If incoming IE offset is bigger than the buffer size,
     * silently ignore the IE without offset adjustments
     */
    if (offset > IEEE80211_EMA_TEMP_MBSS_BUFFER_SIZE)
        return frm;

    qdf_mem_zero(ic->ic_mbss.prb_po_mbss_ie, sizeof(ic->ic_mbss.prb_po_mbss_ie));
    qdf_mem_copy(ic->ic_mbss.prb_po_mbss_ie, frm, offset);

    if (offset_context == IEEE80211_IE_OFFSET_CONTEXT_MBSSIE) {
        ie_trailer_len = frm - po->bo_mbssid_ie;
        /* Adjust the bo's of IEs coming after MBSSID IE */
        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_rrm, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ap_chan_rpt, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_bss_avg_delay, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_antenna, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_bss_adm_cap, offset);

#if !ATH_SUPPORT_WAPI
        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_bss_ac_acc_delay, offset);
#endif /* !ATH_SUPPORT_WAPI */

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mob_domain, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_dse_reg_loc, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_opt_class, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_htcap, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_htinfo, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_2040_coex, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_obss_scan, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_extcap, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_qos_traffic, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_chan_usage, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_time_adv, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_time_zone, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_interworking, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_adv_proto, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_roam_consortium, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_emergency_id, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mesh_id, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mesh_conf, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mesh_awake_win, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_beacon_time, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mccaop_adv_ov, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mccaop_adv, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mesh_cs_param, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_qmf_policy, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_qload_rpt, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_multiband, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_dmg_cap, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_dmg_op, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mul_mac_sub, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ant_sec_id, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_vhtcap, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_vhtop, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ext_bssload, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_vhttxpwr, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_vhtchnsw, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_quiet_chan, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_opt_mode_note, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_rnr, offset);

        IEEE80211_ADJUST_FRAME_OFFSET(po, bo_rnr2, offset);
    } else {
        if (po->bo_rnr) {
            ie_trailer_len = frm - po->bo_rnr;
        } else if (po->bo_rnr2) {
            ie_trailer_len = frm - po->bo_rnr2;
        } else {
            return frm;
        }
    }

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_tvht, offset);

#if QCN_ESP_IE
    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_esp_ie, offset);
#endif /* QCN_ESP_IE */

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_relay_cap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_cag_num, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_fils_ind, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ap_csn, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_diff_init_lnk, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_rps, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_page_slice, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_chan_seq, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_tsf_timer_acc, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_s1g_relay_disc, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_s1g_cap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_s1g_op, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mad, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_short_bcn_int, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_s1g_openloop_idx, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_s1g_relay, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_cdmg_cap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ext_cluster_rpt, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_cmmg_cap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_cmmg_op, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_service_hint, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_service_hash, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_hecap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_heop, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_twt, offset);

#if ATH_SUPPORT_UORA
    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_uora_param, offset);
#endif /* ATH_SUPPORT_UORA */

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_bcca, offset);

#ifdef OBSS_PD
    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_srp_ie, offset);
#endif /* OBSS_PD */

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_muedca, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ess_rpt, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ndp_rpt_param, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_he_bss_load, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_he_6g_bandcap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_rsnx, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mcst, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_secchanoffset, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_ath_caps, offset);

#if DBDC_REPEATER_SUPPORT
    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_extender_ie, offset);
#endif /* DBDC_REPEATER_SUPPORT */

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_htinfo_vendor_specific, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_mbo_cap, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_bwnss_map, offset);

#if QCN_IE
    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_qcn_ie, offset);
#endif /* QCN_IE */

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_whc_apinfo, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_wme, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_software_version_ie, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_generic_vendor_capabilities, offset);

    IEEE80211_ADJUST_FRAME_OFFSET(po, bo_appie_buf, offset);

    /* Move down the IEs to fit MBSSID/RNR IE */
    if (offset_context == IEEE80211_IE_OFFSET_CONTEXT_MBSSIE) {
        qdf_mem_move(po->bo_mbssid_ie + offset,
                po->bo_mbssid_ie, ie_trailer_len);
        qdf_mem_copy(po->bo_mbssid_ie, ic->ic_mbss.prb_po_mbss_ie, offset);
    } else {
        if (po->bo_rnr) {
            qdf_mem_move(po->bo_rnr + offset,
                    po->bo_rnr, ie_trailer_len);
            qdf_mem_copy(po->bo_rnr, ic->ic_mbss.prb_po_mbss_ie, offset);
        } else if (po->bo_rnr2) {
            qdf_mem_move(po->bo_rnr2 + offset,
                    po->bo_rnr2, ie_trailer_len);
            qdf_mem_copy(po->bo_rnr2, ic->ic_mbss.prb_po_mbss_ie, offset);
        }
    }

    frm += offset;
    return frm;
}
#endif

/*
 * Send a probe response frame.
 * NB: for probe response, the node may not represent the peer STA.
 * We could use BSS node to reduce the memory usage from temporary node.
 */
int
ieee80211_send_proberesp(struct ieee80211_node *ni, u_int8_t *macaddr,
                         const void *optie, const size_t  optielen,
                         struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int16_t capinfo;
    int enable_htrates;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
#if QCN_IE
    u_int16_t ie_len;
#endif
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
#endif

#if QCN_ESP_IE
    u_int16_t esp_ie_len;
#endif
    uint8_t len = 0;
    uint8_t chanchange_tbtt = 0;
    uint8_t csmode = IEEE80211_CSA_MODE_STA_TX_ALLOWED;
    bool global_look_up = false;
    uint16_t behav_lim = 0;
    uint16_t chan_width;
    uint64_t adjusted_tsf_le = 0, tsf_adj = 0;
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_beacon_offsets *po = &(avn->av_prb_rsp_offsets);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
            WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
            WLAN_PDEV_FEXT_EMA_AP_ENABLE);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    ASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP ||
           vap->iv_opmode == IEEE80211_M_BTAMP);

    /*
     * XXX : This section needs more testing with P2P
     */
    if (!vap->iv_bss) {
        return 0;
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                          "%s: Error: unable to alloc wbuf of type WBUF_TX_MGMT.\n",
                          __func__);
        return -ENOMEM;
    }

    vap->iv_mbss.ie_overflow = false;
    ic->ic_mbss.ema_ap_available_prb_non_tx_space = soc->ema_ap_max_non_tx_size;

    qdf_mem_zero(qdf_nbuf_data(wbuf), MAX_TX_RX_PACKET_SIZE);

    if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        IEEE80211_ADDR_COPY(macaddr, IEEE80211_GET_BCAST_ADDR(ni->ni_ic));
    }

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                         vap->iv_myaddr, macaddr,
                         ieee80211_node_get_bssid(ni));
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

    /* 2. Beacon interval */
    *(u_int16_t *)frm = htole16(vap->iv_bss->ni_intval);
    frm += 2;

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
    *(u_int16_t *)frm = htole16(capinfo);
    frm += 2;

    /* ------------- Regular and Extension IEs ------------- */
    /* 4. SSID */
    *frm++ = IEEE80211_ELEMID_SSID;
    if (is_mbssid_enabled && IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) &&
        (ic->ic_mbss.prb_req_ssid_match_vap != vap)) {
        *frm++ = 0;
    } else {
        *frm++ = ni->ni_esslen;
        OS_MEMCPY(frm, ni->ni_essid, ni->ni_esslen);
        frm += ni->ni_esslen;
    }

    /* 5. Supported Rates and BSS Membership Selectors */
    po->bo_rates = frm;
    frm = ieee80211_add_rates(vap, frm, &vap->iv_bss->ni_rates);

    /* 6. DS Parameter Set */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            !IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);
    }

    /* 7. CF Parameter Set */
    po->bo_cf_params = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CFPARMS, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_cf_params = NULL;

    /* 8. Country */
    if (IEEE80211_IS_COUNTRYIE_AND_DOTH_ENABLED(ic, vap))
        frm = ieee80211_add_country(frm, vap);

    /* 9. Power Constraint */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        po->bo_pwrcnstr = frm;
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
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
        csaie = (struct ieee80211_ath_channelswitch_ie *)frm;
        csaie->ie = IEEE80211_ELEMID_CHANSWITCHANN;
        csaie->len = 3; /* fixed len */
        csaie->switchmode = csmode;
        csaie->newchannel = wlan_reg_freq_to_chan(ic->ic_pdev_obj, ic->ic_chanchange_chan_freq);
        csaie->tbttcount = chanchange_tbtt;
        frm += IEEE80211_CHANSWITCHANN_BYTES;
    }

    /* 11. Quiet */
    po->bo_quiet = frm;
    frm = ieee80211_add_quiet(vap, ic, frm);

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
            return -EINVAL;
        }
    } else {
        po->bo_tpcreport = NULL;
    }

    /* 14. ERP */
    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11AXG(ic->ic_curchan)) {
        po->bo_erp = frm;
        frm = ieee80211_add_erp(frm, ic);
    } else {
        po->bo_erp = NULL;
    }

    /* 15. Extended Support Rates and BSS Membership Selectors */
    po->bo_xrates = frm;
    frm = ieee80211_add_xrates(vap, frm, &vap->iv_bss->ni_rates);

    /* 16. RSN */
    po->bo_rsn = frm;
    frm = ieee80211_prb_add_rsn_ie(vap, frm, &po, (struct ieee80211_app_ie_t *)optie);
    if (!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return -EINVAL;
    }

    /* 17. QBSS Load */
    po->bo_qbssload = frm;
    if (ieee80211_vap_qbssload_is_set(vap)) {
        frm = ieee80211_add_qbssload(frm, ni);
    } else {
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_PROBERESP,
                    IEEE80211_ELEMID_QBSS_LOAD, -1, &frm,
                    TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
            po->bo_qbssload = NULL;
    }

    /* 18. EDCA Parameter Set */
    po->bo_edca = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EDCA, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_edca = NULL;

    /* 19. Measurement Pilot Transmissions */
    po->bo_msmt_pilot_tx = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
            IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1, &frm,
            TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_msmt_pilot_tx = NULL;

    /* 20. Multiple BSSID */
    if (is_mbssid_enabled) {
        if (ic->ic_mbss.ema_ext_enabled) {
            po->bo_mbssid_ie = frm;
        } else {
            frm += ieee80211_add_mbss_ie(frm, ni, IEEE80211_FRAME_TYPE_PROBERESP,
                    extractx->is_broadcast_req? 1:0, NULL);
        }
    } else {
        po->bo_mbssid_ie = NULL;
    }

    /* 21. RM Enabled Capbabilities, if supported */
    po->bo_rrm = frm;
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    /* 22. AP Channel Report */
    if (vap->ap_chan_rpt_enable) {
        po->bo_ap_chan_rpt = frm;
        frm = ieee80211_add_ap_chan_rpt_ie (frm, vap);
    } else {
        po->bo_ap_chan_rpt = NULL;
    }

    /* 23. BSS Average Access Delay */
    po->bo_bss_avg_delay = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_bss_avg_delay = NULL;

    /* 24. Antenna */
    po->bo_antenna = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ANTENNA, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_antenna = NULL;

    /* 25. BSS Available Admission Capacity */
    po->bo_bss_adm_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_bss_adm_cap = NULL;

#if !ATH_SUPPORT_WAPI
    /* 26. BSS AC Access Delay IE */
    po->bo_bss_ac_acc_delay = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_bss_ac_acc_delay = NULL;
#endif

    /* 27. Mobility Domain */
    po->bo_mob_domain = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MOBILITY_DOMAIN, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mob_domain = NULL;

    /* 28. DSE registered location */
    po->bo_dse_reg_loc = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DSE_REG_LOCATION, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_dse_reg_loc = NULL;


    /* 29. Extended Channel Switch Announcement */
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && vap->iv_enable_ecsaie) {
        struct ieee80211_extendedchannelswitch_ie *ecsa_ie = NULL;
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
                return -EINVAL;
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
    }

    /* 30. Supported Operating Classes */
    po->bo_opt_class = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_SUPP_OP_CLASS, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_opt_class = NULL;


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

        /* 32. HT Operation */
        po->bo_htinfo = frm;
        frm = ieee80211_add_htinfo(frm, ni);

        /* 33. 20/40 BSS Coexistence */
        po->bo_2040_coex = frm;
        if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                    IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_2040_COEXT, -1, &frm,
                    TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
            po->bo_2040_coex = NULL;

        /* 34. OBSS Scan */
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            po->bo_obss_scan = frm;
            frm = ieee80211_add_obss_scan(frm, ni);
        } else {
            po->bo_obss_scan = NULL;
        }
    }

    /* 35. Extended Capbabilities, if applicable */
    po->bo_extcap = frm;
    frm = ieee80211_add_extcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

    /* 36. QoS Traffic Capability */
    po->bo_qos_traffic = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_qos_traffic = NULL;

    /* 37. Channel Usage */
    po->bo_chan_usage = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CHANNEL_USAGE, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_chan_usage = NULL;

    /* 38. Time Advertisement */
    po->bo_time_adv = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_time_adv = NULL;

    /* 39. Time Zone */
    po->bo_time_zone = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TIME_ZONE, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_time_zone = NULL;

    /* 40. Interworking IE (Hotspot 2.0) */
    po->bo_interworking = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_INTERWORKING, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_interworking = NULL;

    /* 41. Advertisement Protocol IE (Hotspot 2.0) */
    po->bo_adv_proto = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ADVERTISEMENT_PROTO, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_adv_proto = NULL;

    /* 42. Roaming Consortium IE (Hotspot 2.0) */
    po->bo_roam_consortium = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ROAMING_CONSORTIUM, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_roam_consortium = NULL;

    /* 43. Emergency Alert Identifier */
    po->bo_emergency_id = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_emergency_id = NULL;

    /* 44. Mesh ID */
    po->bo_mesh_id = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_ID, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mesh_id = NULL;

    /* 45. Mesh Configuration */
    po->bo_mesh_conf = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_CONFIG, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mesh_conf = NULL;

    /* 46. Mesh Awake Window */
    po->bo_mesh_awake_win = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mesh_awake_win = NULL;

    /* 47. Beacon Timing */
    po->bo_beacon_time = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_BEACON_TIMING, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_beacon_time = NULL;

    /* 48. MCCAOP Advertisement Overview */
    po->bo_mccaop_adv_ov = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mccaop_adv_ov = NULL;

    /* 49. MCCAOP Advertisement */
    po->bo_mccaop_adv = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MCCAOP_ADV, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mccaop_adv = NULL;

    /* 50. Mesh Channel Switch Parameters */
    po->bo_mesh_cs_param = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mesh_cs_param = NULL;

    /* 51. QMF Policy */
    po->bo_qmf_policy = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QMF_POLICY, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_qmf_policy = NULL;

    /* 52. QLoad Report */
    po->bo_qload_rpt = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QLOAD_REPORT, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_qload_rpt = NULL;

    /* 53. Multi-band */
    po->bo_multiband = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MULTIBAND, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_multiband = NULL;

    /* 54. DMG Capabilities */
    po->bo_dmg_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DMG_CAP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_dmg_cap = NULL;

    /* 55. DMG Operation */
    po->bo_dmg_op = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DMG_OPERATION, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_dmg_op = NULL;

    /* 56. Multiple MAC Sublayers */
    po->bo_mul_mac_sub = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MULTIPLE_MAC_SUB, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mul_mac_sub = NULL;

    /* 57. Antenna Sector ID Pattern */
    po->bo_ant_sec_id = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_ANTENNA_SECT_ID_PAT, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_ant_sec_id = NULL;


    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        /* VHT capable
         * Add VHT capabilities (58), operation (59), Tx Power envelope (60),
         * Channel Switch Wrapper (61) and Extended BSS Load (62) elements
         * for 2.4G mode, if 256QAM is enabled
         */
        frm = ieee80211_prb_add_vht_ies(ni, frm, macaddr, extractx, &po);
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
        } else {
            po->bo_vhttxpwr = NULL;
        }

        if (ieee80211_vap_wme_is_set(vap) && vap->iv_chanchange_count &&
                (ic->ic_chanchange_channel != NULL)) {
            po->bo_vhtchnsw = frm;
            frm = ieee80211_add_chan_switch_wrp(frm, ni, ic,
                    IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                    (!IEEE80211_VHT_EXTCH_SWITCH));
        } else {
            po->bo_vhtchnsw = NULL;
        }
    }

    /* 63. Quiet Channel */
    po->bo_quiet_chan = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QUIET_CHANNEL, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_quiet_chan = NULL;

    /* 64. Operating Mode Notification */
    po->bo_opt_mode_note = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_OP_MODE_NOTIFY, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_opt_mode_note = NULL;

    /* 65. Reduced Neighbor Report */
    if (vap->rnr_enable) {
        po->bo_rnr = frm;
        if (IEEE80211_IS_BROADCAST(macaddr) || (extractx->oce_sta) || (extractx->fils_sta)) {
            frm = ieee80211_add_rnr_ie(frm, vap, extractx->ssid, extractx->ssid_len);
        }
    } else {
        po->bo_rnr2 = NULL;

        if (!is_mbssid_enabled || !ic->ic_mbss.ema_ext_enabled) {
            uint8_t *temp_po = NULL;

            frm = ieee80211_add_6ghz_rnr_ie(ni, po, frm,
                    &temp_po, IEEE80211_FC0_SUBTYPE_PROBE_RESP, false);
            if (!frm) {
                wbuf_release(ic->ic_osdev, wbuf);
                return -EINVAL;
            }
        } else {
            po->bo_rnr = po->bo_rnr2 = frm;
        }
    }

    /* 66. TVHT Operation */
    po->bo_tvht = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TVHT_OP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_tvht = NULL;

#if QCN_ESP_IE
    /* 67. Estimated Service Parameters */
    if (ic->ic_esp_periodicity){
        po->bo_esp_ie = frm;
        frm = ieee80211_add_esp_info_ie(frm, ic, &esp_ie_len);
    }
#endif

    /* 68. Relay Capabilities */
    po->bo_relay_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RELAY_CAP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_relay_cap = NULL;

    /* 69. Common Advertisement Group (CAG) Number */
    po->bo_cag_num = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CAG_NUMBER, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_cag_num = NULL;

    /* 70. FILS Indication */
    po->bo_fils_ind = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_FILS_INDICATION, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_fils_ind = NULL;

    /* 71. AP-CSN */
    po->bo_ap_csn = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_AP_CSN, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_ap_csn = NULL;

    /* 72. Differentiated Initial Link Setup */
    po->bo_diff_init_lnk = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_diff_init_lnk = NULL;

    /* 73. RPS */
    po->bo_rps = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RPS, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_rps = NULL;

    /* 74. Page Slice */
    po->bo_page_slice = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_PAGE_SLICE, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_page_slice = NULL;

    /* 75. Change Sequence */
    po->bo_chan_seq = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_CHANGE_SEQ, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_chan_seq = NULL;

    /* 76. TSF Timer Accuracy */
    po->bo_tsf_timer_acc = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TSF_TIMER_ACC, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_tsf_timer_acc = NULL;

    /* 77. S1G Relay Discovery */
    po->bo_s1g_relay_disc = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_RELAY_DISCOVREY, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_s1g_relay_disc = NULL;

    /* 78. S1G Capabilities */
    po->bo_s1g_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_CAP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_s1g_cap = NULL;

    /* 79. S1G Operation */
    po->bo_s1g_op = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_OP, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_s1g_op = NULL;

    /* 80. MAD */
    po->bo_mad = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_MAD, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_mad = NULL;

    /* 81. Short Beacon Interval */
    po->bo_short_bcn_int = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_SHORT_BEACON_INTVAL, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_short_bcn_int = NULL;

    /* 82. S1G Open-Loop Link Margin Index */
    po->bo_s1g_openloop_idx = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_OPENLOOP_LINK_MARGIN,
                -1, &frm, TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_s1g_openloop_idx = NULL;

    /* 83. S1G Relay element */
    po->bo_s1g_relay = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_S1G_RELAY, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_s1g_relay = NULL;

    /* 85. CDMG Capaiblities */
    po->bo_cdmg_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_CDMG_CAP, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_cdmg_cap = NULL;

    /* 86. Extended Cluster Report */
    po->bo_ext_cluster_rpt = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_EXTENDED_CLUSTER_RPT, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_ext_cluster_rpt = NULL;

    /* 87. CMMG Capabilities */
    po->bo_cmmg_cap = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_CMMG_CAP, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_cmmg_cap = NULL;

    /* 88. CMMG Operation */
    po->bo_cmmg_op = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_CMMG_OP, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_cmmg_op = NULL;

    /* 90. Service Hint */
    po->bo_service_hint = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_SERVICE_HINT, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_service_hint = NULL;

    /* 91. Service Hash */
    po->bo_service_hash = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_SERVICE_HASH, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_service_hash = NULL;

    /* 93. MBSSID Config */
    if (is_ema_ap_enabled) {
        po->bo_mbssid_config = frm;
        frm = ieee80211_add_mbssid_config(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, frm);
    } else {
        po->bo_mbssid_config = NULL;
    }

    if (ieee80211_vap_wme_is_set(vap) &&  IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
         && ieee80211vap_heallowed(vap)) {
        /* 94. HE Capabilities */
        po->bo_hecap = frm;
        frm = ieee80211_add_hecap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        /* 95. HE Operation */
        po->bo_heop = frm;
        frm = ieee80211_add_heop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx);
    } else {
        po->bo_hecap = NULL;
        po->bo_heop = NULL;
    }

    /* 96. TWT */
    po->bo_twt = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TWT, -1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_twt = NULL;

#if ATH_SUPPORT_UORA
    /* 97. UORA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
           ieee80211vap_heallowed(vap) &&
           IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
           ieee80211vap_uora_is_enabled(vap)) {
        po->bo_uora_param = frm;
        frm = ieee80211_add_uora_param(frm, vap->iv_ocw_range);
    } else {
        po->bo_uora_param = NULL;
    }
#endif

    /* 98. BSS Color Change Announcement */
    po->bo_bcca = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_BSSCOLOR_CHG, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_bcca = NULL;

#if OBSS_PD
    /* 99. Spatial Reuse Parameters */
    if (ic->ic_he_sr_enable &&
        IEEE80211_IS_CHAN_11AX(ic->ic_curchan) && ieee80211vap_heallowed(vap)) {
        po->bo_srp_ie = frm;
        frm = ieee80211_add_srp_ie(vap, frm);
    }
#endif

    /* 100. MU EDCA Parameter Set*/
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap)) {
        po->bo_muedca = frm;
        frm = ieee80211_add_muedca_param(frm, &vap->iv_muedcastate);
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
                    TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
            po->bo_ess_rpt = NULL;
    }

    /* 102. NDP Feedback Report Parameter */
    po->bo_ndp_rpt_param = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_ndp_rpt_param = NULL;

    /* 103. HE BSS Load */
    po->bo_he_bss_load = frm;
    if (!ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_HE_BSS_LOAD, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
        po->bo_he_bss_load = NULL;

    /* 104. HE 6GHz Band Capabilities */
    if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        po->bo_he_6g_bandcap = frm;
        frm = ieee80211_add_6g_bandcap(frm, ni, ic,
                        IEEE80211_FC0_SUBTYPE_PROBE_RESP);
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
                        -1, &frm, TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true))
                po->bo_rsnx = NULL;
        }
    }

#if ATH_SUPPORT_WAPI
    /* WAPI IE
     * Added here since no order is mentioned in the specififcation */
    if (wlan_crypto_vdev_has_auth_mode(vap->vdev_obj, (1 << WLAN_CRYPTO_AUTH_WAPI)))
    {
        frm = ieee80211_setup_wapi_ie(vap, frm);
        if (!frm) {
            wbuf_release(ic->ic_osdev, wbuf);
            return -EINVAL;
        }
    }
#endif

    /* Maximum channel Switch Time (MCST)
     * Added here since no order is mentioned in the specification*/
    if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)
            && vap->iv_enable_max_ch_sw_time_ie) {
        struct ieee80211_max_chan_switch_time_ie *mcst_ie = NULL;
        mcst_ie = (struct ieee80211_max_chan_switch_time_ie *)frm;
        ieee80211_add_max_chan_switch_time(vap, (uint8_t *)mcst_ie);
        frm += IEEE80211_MAXCHANSWITCHTIME_BYTES;
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

        sec_chan_offset_ie = (struct ieee80211_ie_sec_chan_offset *)frm;
        sec_chan_offset_ie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;

        /* Element has only one octet of info */
        sec_chan_offset_ie->len = 1;
        sec_chan_offset_ie->sec_chan_offset = ic->ic_chanchange_secoffset;
        frm += IEEE80211_SEC_CHAN_OFFSET_BYTES;
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
    }

    /* Ath Extended Capabilities */
    if (ic->ic_ath_extcap)
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);

#if DBDC_REPEATER_SUPPORT
    /* Extender */
    if (ic_list->same_ssid_support) {
        po->bo_extender_ie = frm;
        frm = ieee80211_add_extender_ie(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
    }
#endif

    /* HT Capabilities and HT Info/Operation vendor IEs */
    if (ieee80211_vap_wme_is_set(vap) &&
        (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
        (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
         IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        (IEEE80211_IS_HTVIE_ENABLED(ic)) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        po->bo_htinfo_vendor_specific = frm;
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    } else {
        po->bo_htinfo_vendor_specific = NULL;
    }

    /* MBO */
    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        po->bo_mbo_cap = frm;
        frm = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_PROBE_RESP, vap, frm, ni);
    } else {
        po->bo_mbo_cap = NULL;
    }

    /* Prop NSS IE if external NSS is not supported */
    if (!(vap->iv_ext_nss_support) && !(ic->ic_disable_bwnss_adv)
            && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask))  {
        po->bo_bwnss_map = frm;
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    } else {
        po->bo_bwnss_map = NULL;
    }

#if QCN_IE
    /* QCN IE for the feature set */
    po->bo_qcn_ie = frm;
    frm = ieee80211_add_qcn_info_ie(frm, vap, &ie_len,
                                    QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
#endif

    /* SON Mode */
    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_PROBERESP,
                                                      IEEE80211_ELEMID_VENDOR, IEEE80211_ELEMID_VENDOR_SON_AP,
                                                      &frm, TYPE_APP_IE_BUF, NULL, true);
    }
    /* WME Param */
    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_BTAMP)) {/* don't support WMM in ad-hoc for now */
        po->bo_wme = frm;
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
    } else {
        po->bo_wme = NULL;
    }

	/* Check if os shim has setup WPA IE itself */
    if (!vap->iv_rsn_override) {
        len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap,
                IEEE80211_FRAME_TYPE_PROBERESP,IEEE80211_ELEMID_VENDOR, 1, &frm,
                TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);
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
                    return -EINVAL;
                }
            }
        }
    }

    /* Hardware and Software version */
    po->bo_software_version_ie = frm;
    frm = ieee80211_add_sw_version_ie(frm, ic);

    po->bo_generic_vendor_capabilities = frm;
    frm = ieee80211_add_generic_vendor_capabilities_ie(frm, ic);
    if (!frm) {
        wbuf_release(ic->ic_osdev, wbuf);
        return -EINVAL;
    }

    /* ------------- App IE Buffer or list, and Optional IEs ------------- */
    po->bo_appie_buf = frm;
    po->bo_appie_buf_len = 0;
    len = ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, IEEE80211_FRAME_TYPE_PROBERESP,
            IEEE80211_ELEMID_VENDOR, 0, &frm, TYPE_ALL_BUF,
            (struct ieee80211_app_ie_t *)optie, false);
    po->bo_appie_buf_len = len;

#if QCA_SUPPORT_EMA_EXT
    /* Populate MBSSID and RNR IEs */
    if (IS_MBSSID_EMA_EXT_ENABLED(ic)) {
        uint8_t *saved_bo_rnr = NULL;
        uint8_t *temp_po = NULL;
        uint16_t offset = 0;

        /* Add MBSSID IE */
        po->bo_mbssid_ie_len = ieee80211_add_mbss_ie(frm, ni, IEEE80211_FRAME_TYPE_PROBERESP,
                extractx->is_broadcast_req? 1:0, (void *)optie);

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
                &temp_po, IEEE80211_FC0_SUBTYPE_PROBE_RESP, false);
        if (!frm) {
            wbuf_release(ic->ic_osdev, wbuf);
            return -EINVAL;
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
            if (temp_po) {
                frm -= offset;
                frm = ieee80211_prb_adjust_pos_for_context(
                        ic, frm, po, offset, IEEE80211_IE_OFFSET_CONTEXT_RNRIE);
            }
        }
    }
#endif

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));
    if (extractx->retry) {
        wbuf_set_tx_ctrl(wbuf, extractx->retry, ic->ic_curchan->ic_maxregpower, -1);
    }

    if (extractx->datarate) {
        if (extractx->datarate == 6000)       /* 6 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_OFDM, 3, ic->ic_he_target);
        else if (extractx->datarate == 5500)  /* 5.5 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 1, ic->ic_he_target);
        else if (extractx->datarate == 2000)  /* 2 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 2, ic->ic_he_target);
        else                                  /* 1 Mbps */
            wbuf_set_tx_rate(wbuf, 0, RATECODE_PREAM_CCK, 3, ic->ic_he_target);
    }
    if (extractx->retry || extractx->datarate) {
        /* tid should be set to HTT_TX_EXT_TID_NONPAUSE to apply tx_rate */
        wbuf_set_tid(wbuf, HTT_TX_EXT_TID_NONPAUSE_PRIVATE);
    }

    return ieee80211_send_mgmt(vap,ni, wbuf,true);
}

/* Determine whether probe response needs modification towards 160 MHz width
   association WAR.
 */
static bool
is_assocwar160_reqd_proberesp(struct ieee80211vap *vap,
        struct ieee80211_ie_ssid *probereq_ssid_ie,
        struct ieee80211_ie_vhtcap *sta_vhtcap)
{
    int is_sta_any160cap = 0;

    qdf_assert_always(vap != NULL);
    qdf_assert_always(probereq_ssid_ie != NULL);

    /* Since this WAR is deprecated, it will not be made available for 11ax. */

    if ((!ieee80211_is_phymode_11ac_160or8080(vap->iv_cur_mode)) ||
        !vap->iv_cfg_assoc_war_160w) {
        return false;
    }

    /* The WAR is required only for STAs not having any 160/80+80 MHz
     * capability. */
    if (sta_vhtcap == NULL) {
        return true;
    }

    is_sta_any160cap =
        ((sta_vhtcap->vht_cap_info &
            (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 |
             IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
             IEEE80211_VHTCAP_SHORTGI_160)) != 0);

    if (is_sta_any160cap) {
        return false;
    }

    return true;
}

/* ieee80211_6ghz_is_ssid_match: Find a vap in 6Ghz
 * radio that matches the ssid/short_ssid in probe request.
 */
void ieee80211_6ghz_is_ssid_match(struct wlan_objmgr_psoc *psoc,
               void *arg, uint8_t index)
{
    struct wlan_objmgr_psoc_objmgr *objmgr;
    struct wlan_objmgr_pdev *pdev = NULL;
    int id = 0;
    wlan_dev_t ic;
    struct ieee80211vap *tmpvap = NULL;
    struct oob_prb_rsp *oob_prbrsp = (struct oob_prb_rsp*)arg;
    uint32_t self_shortssid;

    objmgr = &psoc->soc_objmgr;
    for (id=0;id<WLAN_UMAC_MAX_PDEVS;id++) {
        pdev = objmgr->wlan_pdev_list[id];
        if (pdev) {
            ic = wlan_pdev_get_mlme_ext_obj(pdev);
            if (ic && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    if (tmpvap->iv_opmode == IEEE80211_M_HOSTAP &&
                        tmpvap->iv_is_up) {
                        if (!oob_prbrsp->is_shortssid) {
                            oob_prbrsp->ssid_match = IEEE80211_MATCH_SSID(tmpvap->iv_bss,
                                                     oob_prbrsp->ssid_info);
                            if (!oob_prbrsp->ssid_match) {
#ifdef QCA_SUPPORT_CP_STATS
                                vdev_cp_stats_oob_probe_req_count_inc(tmpvap->vdev_obj, 1);
#endif
                                break;
                            }
                        } else {
                            self_shortssid = ieee80211_construct_shortssid((tmpvap->iv_bss)->ni_essid,
                                                        (tmpvap->iv_bss)->ni_esslen);
                            oob_prbrsp->ssid_match = IEEE80211_MATCH_SHORT_SSID(tmpvap->iv_bss,
                                            (uint8_t *)&self_shortssid, oob_prbrsp->ssid_info);
                            if (!oob_prbrsp->ssid_match) {
#ifdef QCA_SUPPORT_CP_STATS
                                vdev_cp_stats_oob_probe_req_count_inc(tmpvap->vdev_obj, 1);
#endif
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

/* ieee80211_6ghz_is_ssid_match: Iterate through
 * all psocs and find a 6Ghz pdev to get vaps in
 * 6Ghz band
 */
QDF_STATUS ieee80211_check_6ghz_ssid_match (struct wlan_objmgr_psoc *psoc,
        struct oob_prb_rsp *oob_prbrsp)
{
    wlan_objmgr_iterate_psoc_list(ieee80211_6ghz_is_ssid_match,
                                  oob_prbrsp, WLAN_MLME_NB_ID);
    return QDF_STATUS_SUCCESS;
}

int
ieee80211_recv_probereq(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                        struct ieee80211_rx_status *rs)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    unsigned int found_vap  = 0;
    unsigned int found_null_bssid = 0;
    struct ieee80211vap *tx_vap = NULL;
    struct ieee80211_node *ni_bss_tx_vap = NULL;
    int ret = -EINVAL;
    u_int8_t *frm, *efrm;
    u_int8_t *ssid, *rates, *ven , *short_ssid;
    u_int8_t *ssid_info, *known_bssid = NULL;
#if ATH_SUPPORT_HS20 || QCN_IE
    u_int8_t *xcaps = NULL;
#endif
#if ATH_SUPPORT_HS20
    u_int8_t *iw = NULL;
    uint8_t empty[QDF_MAC_ADDR_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00};
#endif
#if QCA_SUPPORT_SON
    struct bs_probe_req_data probe_data = {0};
    bool blocked;
    bool ssid_null;
#endif
#if QCN_IE
    u_int8_t *qcn = NULL;

    /*
     * Max-ChannelTime parameter represented in units of TUs
     * 255 used to indicate any duration of more than 254 TUs, or an
     * unspecified or unknown duration.
     */
    u_int8_t channel_time = 0;
    /* Index 0 has version and index 1 has subversion of QCN IE*/
    u_int8_t data[2] = {0};
    qdf_ktime_t eff_chan_time, bpr_delay;
    qdf_hrtimer_data_t *bpr_gen_timer = &vap->bpr_timer;
#endif
    u_int8_t *mbo = NULL;
    bool suppress_resp = false;
    u_int8_t nullbssid[QDF_MAC_ADDR_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00};
    int snd_prb_resp = 0;
    struct ieee80211_ie_vhtcap *vhtcap = NULL;
    struct ieee80211_ie_hecap  *hecap  = NULL;
    struct ieee80211_ie_heop   *heop   = NULL;
    struct ieee80211_framing_extractx extractx;
    bool shortssid_flag = false;
    uint32_t self_shortssid = 0;
    uint8_t ssid_match;
    bool special_ssid_case = false;
    u_int8_t dedicated_oui_present = 0;
    bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
					    WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
					    WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_non_tx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);

    OS_MEMZERO(&extractx, sizeof(extractx));
#if ATH_SUPPORT_AP_WDS_COMBO
    if (vap->iv_opmode == IEEE80211_M_STA ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        vap->iv_no_beacon) {
#else
    if (vap->iv_opmode == IEEE80211_M_STA ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
#endif
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
        vdev_cp_stats_prob_req_drops_inc(vap->vdev_obj, 1);
#endif
        return -EINVAL;
    }

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (IEEE80211_IS_MULTICAST(wh->i_addr2)) {
        /* frame must be directed */
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
        vdev_cp_stats_prob_req_drops_inc(vap->vdev_obj, 1);
#endif
        return -EINVAL;
    }

#if UMAC_SUPPORT_NAWDS
    /* Skip probe request if configured as NAWDS bridge */
    if(vap->iv_nawds.mode == IEEE80211_NAWDS_STATIC_BRIDGE
		  || vap->iv_nawds.mode == IEEE80211_NAWDS_LEARNING_BRIDGE) {
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_prob_req_drops_inc(vap->vdev_obj, 1);
#endif
        return -EINVAL;
    }
#endif
    /*Update node if ni->bssid is NULL*/
    if(!OS_MEMCMP(ni->ni_bssid,nullbssid,QDF_MAC_ADDR_SIZE))
    {
        ni = ieee80211_try_ref_bss_node(vap, WLAN_MGMT_HANDLER_ID);
        if(ni == NULL) {
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_prob_req_drops_inc(vap->vdev_obj, 1);
#endif
            return -EINVAL;
        }

        found_null_bssid = 1;
    }
#if ATH_PARAMETER_API
    ieee80211_papi_send_probe_req_event(vap, ni, wbuf, rs);
#endif

    /*
     * prreq frame format
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] extended supported rates
     *  [tlv] Atheros Advanced Capabilities
     */
    ssid = rates = short_ssid =NULL;
    while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
#if ATH_SUPPORT_HS20
        case IEEE80211_ELEMID_XCAPS:
            xcaps = frm;
            break;
        case IEEE80211_ELEMID_INTERWORKING:
            iw = frm;
            break;
#endif
        case IEEE80211_ELEMID_VENDOR:
            if (vap->iv_venie && vap->iv_venie->ven_oui_set) {
                ven = frm;
                if (ven[2] == vap->iv_venie->ven_oui[0] &&
                    ven[3] == vap->iv_venie->ven_oui[1] &&
                    ven[4] == vap->iv_venie->ven_oui[2]) {
                    vap->iv_venie->ven_ie_len = MIN(ven[1] + 2, IEEE80211_MAX_IE_LEN);
                    OS_MEMCPY(vap->iv_venie->ven_ie, ven, vap->iv_venie->ven_ie_len);
                }
            }
            if (isdedicated_cap_oui(frm)) {
                dedicated_oui_present = 1;
            }
            else if ((vhtcap == NULL) &&
                    /*
                     * Standalone-VHT CAP IE outside
                     * of Interop IE
                     * will obviously supercede
                     * VHT CAP inside interop IE
                     */
                    ieee80211vap_11ng_vht_interopallowed(vap) &&
                    isinterop_vht(frm)) {
                /* frm+7 is the location , where 2.4G Interop VHT IE starts */
                vhtcap = (struct ieee80211_ie_vhtcap *) (frm + 7);
            }
#if QCN_IE
            else if(isqcn_oui(frm)) {
                qcn = frm;
            }
#endif
            else if (ismbooui(frm)) {
                mbo = frm;
            }

            if ( snd_prb_resp == 0 ) {
                snd_prb_resp = isorbi_ie(vap, frm);
              }
            break;
        case IEEE80211_ELEMID_VHTCAP:
            vhtcap = (struct ieee80211_ie_vhtcap *)frm;
            break;

        case WLAN_ELEMID_EXTN_ELEM:
            if (((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) &&
                (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT)
                     == IEEE80211_ELEMID_EXT_HECAP)) {
                hecap = (struct ieee80211_ie_hecap *)frm;
            } else if (((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) &&
                    (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT)
                         == IEEE80211_ELEMID_EXT_HEOP)) {
                heop = (struct ieee80211_ie_heop *)frm;
            } else if (((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) &&
                    (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT)
                        == IEEE80211_ELEMID_EXT_SHORT_SSID)) {
                short_ssid = frm;
            } else if (((frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT) < efrm) &&
                    (*(frm + IEEE80211_HE_IE_HDR_OFFSET_TO_ID_EXT)
                        == IEEE80211_ELEMID_EXT_KNOWN_BSSID)) {
                mbss_debug("known_bssid ELEM at %pK", frm);
                known_bssid = frm;
            }

#if QCN_IE
            else if(isfils_req_parm(frm)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS STA found mac[%s] \n",ether_sprintf(wh->i_addr2));
                /* Get the Channel time |IE|LEN|EXT|BITMAP|CHANNEL TIME|..| skip Parameter Control Bitmap */
                if(frm[4]) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS Max channel time : %uTU\n",frm[4]);
                    channel_time = frm[4];
                    eff_chan_time = qdf_ns_to_ktime(QDF_NSEC_PER_MSEC *
                                EFF_CHAN_TIME((channel_time * 1024)/1000, ic->ic_bpr_latency_comp));
                }
                else {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,"FILS STA with invalid IE Ignoring \n");
                }
            }
#endif
            break;
        }

        /* elem id + len = 2 bytes */
        frm += frm[1] + 2;
    }

    if (frm > efrm) {
        ret = -EINVAL;
        goto exit;
    }
#ifdef MU_CAP_WAR_ENABLED
    if (dedicated_oui_present &&
        (vhtcap != NULL) &&
        (le32toh(vhtcap->vht_cap_info) & IEEE80211_VHTCAP_MU_BFORMEE)) {

        ni->dedicated_client = 1;
    }
#endif

    IEEE80211_VERIFY_ELEMENT(rates, rates[1], IEEE80211_RATE_MAXSIZE);

    if(ssid) {
        IEEE80211_VERIFY_ELEMENT(ssid, ssid[1], IEEE80211_NWID_LEN);
        ssid_info = ssid;
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            if(IEEE80211_IS_INVALID_6GHZ_PROBE_REQ(ssid, wh)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Invalid 6GHz Probe Request");
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_wc_probe_req_drops_inc(vap->vdev_obj, 1);
#endif
                return -EINVAL;
            }
            special_ssid_case = IEEE80211_IS_SPECIAL_SSID(ssid_info,
                                                IEEE80211_6GHZ_SPECIAL_SSID);
        }
    } else {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "SSID element not found in probe request!");
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_prob_req_drops_inc(vap->vdev_obj, 1);
#endif
        return -EINVAL;
    }

    if (short_ssid) {
        IEEE80211_VERIFY_ELEMENT(short_ssid, (short_ssid[1] - 1), IEEE80211_SHORT_SSID_LEN);
        self_shortssid = ieee80211_construct_shortssid((vap->iv_bss)->ni_essid,
                                                    (vap->iv_bss)->ni_esslen);
        shortssid_flag = true;
    }

    /* update rate and rssi information */
#ifdef QCA_SUPPORT_CP_STATS
    WLAN_PEER_CP_STAT_SET(ni, rx_mgmt_rate, rs->rs_datarate);
    WLAN_PEER_CP_STAT_SET(ni, rx_mgmt_snr, rs->rs_snr);
#endif

    IEEE80211_DELIVER_EVENT_RECV_PROBE_REQ(vap, wh->i_addr2, ssid_info);

    ssid_match = IEEE80211_MATCH_SSID(vap->iv_bss, ssid_info);
    if((ssid_match || special_ssid_case) && shortssid_flag) {
        /* Process the short SSID information from probe request in case
         * the client uses Special SSID or if the SSID does not match.
         */
        ssid_match = IEEE80211_MATCH_SHORT_SSID(vap->iv_bss,
                                (uint8_t *)&self_shortssid, short_ssid);
    }

    /* In 5/2Ghz AP case, if no ssid match, find a vap in 6Ghz radio that
     * has ssid/shortssid match
     */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        if (ssid_match) //ssid not match
        {
            struct oob_prb_rsp oob_prbrsp;
            qdf_mem_zero(&oob_prbrsp, sizeof(struct oob_prb_rsp));
            if(special_ssid_case && shortssid_flag) {
                oob_prbrsp.is_shortssid = shortssid_flag;
                oob_prbrsp.ssid_info = short_ssid;
            } else {
                oob_prbrsp.ssid_info = ssid_info;
            }
            oob_prbrsp.ssid_match = ssid_match;
            ieee80211_check_6ghz_ssid_match(wlan_pdev_get_psoc(ic->ic_pdev_obj), &oob_prbrsp);
            ssid_match = oob_prbrsp.ssid_match;
        }
    }

    /*
     * XXX bug fix 107944: STA Entry exists in the node table,
     * But the STA want to associate with the other vap,  vap should
     * send the correct proble response to Station.
     *
     */

    if(ssid_match)  //ssid not match
    {
        struct ieee80211vap *tmpvap = NULL;
        if(ni != vap->iv_bss)
        {
            TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
            {
                ssid_match = IEEE80211_MATCH_SSID(tmpvap->iv_bss, ssid_info);
                if((ssid_match || special_ssid_case) && shortssid_flag) {
                    self_shortssid =
                        ieee80211_construct_shortssid((tmpvap->iv_bss)->ni_essid,
                                                    (tmpvap->iv_bss)->ni_esslen);
                    ssid_match = IEEE80211_MATCH_SHORT_SSID(tmpvap->iv_bss,
                                       (uint8_t *)&self_shortssid, short_ssid);
                }
                if((tmpvap->iv_opmode == IEEE80211_M_HOSTAP) && (!ssid_match))
                {
                        found_vap = 1;
                        break;
                }
            }
        }
        if(found_vap  == 1)
        {
            ni = ieee80211_ref_bss_node(tmpvap, WLAN_MGMT_HANDLER_ID);
            if ( ni ) {
                vap = ni->ni_vap;
            }
        }
        else
        {
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_ssid_mismatch_inc(vap->vdev_obj, 1);
#endif
            /* In MBSS IE case, probe req is handled by all VAPs, so don't
             * return error yet _except_ when short ssid is present, request
             * is handled by tx vap and ssid/shortssid don't match
             */
            if (is_mbssid_enabled) {
                if (!(shortssid_flag && !is_non_tx_vap)) {
                    ret = 0;
                    vdev_cp_stats_prob_req_drops_inc(vap->vdev_obj, 1);
                }
            }

            goto exit;
        }

    }

    /* If SSID or Short SSID matches, save the vap info in ic.
     * In MBSSIE case, this vap needs to be added to MBSS IE in probe response.
     */
    if (is_mbssid_enabled) {
        if ( ni ) {
            self_shortssid = ieee80211_construct_shortssid(ni->ni_essid,
                                                            ni->ni_esslen);
        }

        if ((ssid_info[1] != 0 &&
            !qdf_mem_cmp(ni->ni_essid, &ssid_info[2], ssid_info[1])) ||
             (short_ssid && short_ssid[1] != 0 && !qdf_mem_cmp(short_ssid + 3,
                       (uint8_t *)& self_shortssid, (short_ssid[1]-1)) != 0)) {
            ic->ic_mbss.prb_req_ssid_match_vap = vap;
        }
    }

#if ATH_ACL_SOFTBLOCKING
    if (ssid_info[1] != 0) { // directed probe request.
        if (!wlan_acl_check_softblocking(vap, wh->i_addr2)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACL,
                    "Directed Probe Req Frames from %s are softblocked\n",
                    ether_sprintf(wh->i_addr2));
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
            goto exit;
        }
    }
#endif

    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) && (ssid_info[1] == 0) && !(IEEE80211_VAP_IS_BACKHAUL_ENABLED(vap))) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                          subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "no ssid with ssid suppression enabled");
#ifdef QCA_SUPPORT_CP_STATS
        vdev_cp_stats_rx_ssid_mismatch_inc(vap->vdev_obj, 1);
#endif

        /* In MBSS IE case, probe req is handled by all VAPs, so don't
         * return error yet
         */
        if (is_mbssid_enabled)
            ret = 0;

        goto exit;
    }

#if DYNAMIC_BEACON_SUPPORT
    /*
     * If probe req received from non associated STA,
     * check the rssi and send probe resp.
     */
    if (vap->iv_dbeacon == 1 && vap->iv_dbeacon_runtime == 1) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "node(%s): rs_rssi %d, iv_dbeacon_rssi_thr: %d \n",
                ether_sprintf(wh->i_addr2),rs->rs_snr, vap->iv_dbeacon_snr_thr);
        if (rs->rs_snr < vap->iv_dbeacon_snr_thr) {
            /* don't send probe resp if rssi is low. */
#ifdef QCA_SUPPORT_CP_STATS
            vdev_cp_stats_rx_mgmt_discard_inc(vap->vdev_obj, 1);
#endif
            goto exit;
        }
    }
#endif

#if ATH_SUPPORT_HS20
    if (!IEEE80211_ADDR_EQ(vap->iv_hessid, &empty)) {
        if (iw && !xcaps)
            goto exit;
        if (iw && (xcaps[5] & 0x80)) {
            /* hessid match ? */
            if (iw[1] == 9 && !IEEE80211_ADDR_EQ(iw+5, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+5, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            if (iw[1] == 7 && !IEEE80211_ADDR_EQ(iw+3, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+3, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            /* access_network_type match ? */
            if ((iw[2] & 0xF) != vap->iv_access_network_type && (iw[2] & 0xF) != 0xF)
                goto exit;
        }
    }
#endif

#if QCN_IE
    if (xcaps) {
        struct ieee80211_ie_ext_cap *extcaps = (struct ieee80211_ie_ext_cap *) xcaps;

        if ((extcaps->elem_len > 9) && (extcaps->ext_capflags4 & IEEE80211_EXTCAPIE_FILS)) {
            extractx.fils_sta = true;
        }
    }

    if (ssid) {
        extractx.ssid_len = *(ssid + 1);
        OS_MEMCPY(extractx.ssid, ssid + 2, extractx.ssid_len);
    }

    if (qcn && ni) {
        /*
         * Record qcn parameters for station, mark
         * node as using qcn and record information element
         * for applications that require it.
         */
          ieee80211_parse_qcnie(qcn, wh, ni,data);
    }
#endif
    if (mbo && ieee80211_vap_oce_check(vap)) {
        extractx.oce_sta = ieee80211_oce_capable(mbo);
        suppress_resp = ieee80211_oce_suppress_ap(mbo, vap);

        if (suppress_resp) {
            /* Drop the probe response */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Suppress probe response: %d for vap %pK\n", suppress_resp, vap);
            goto exit;
        }
    }

#if QCA_SUPPORT_SON
    /* If band steering is withholding probes (due to steering being in
     * progress), return here so that the response is not sent.
     */
    if(ssid_info) {
        ssid_null = (ssid_info[1] == 0) ? true : false;
        blocked = wlan_vdev_acl_is_probe_wh_set(vap->vdev_obj, wh->i_addr2, rs->rs_rssi);

        probe_data.probe_req.rssi = rs->rs_snr;
        probe_data.probe_req.blocked = blocked;
        probe_data.probe_req.ssid_null = ssid_null;
        qdf_mem_copy(probe_data.probe_req.sender_addr, wh->i_addr2, QDF_MAC_ADDR_SIZE);
	probe_data.is_chan_2G = IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan);
        if (son_update_mgmt_frame(vap->vdev_obj, NULL, IEEE80211_FC0_SUBTYPE_PROBE_REQ, wbuf_header(wbuf), wbuf_get_pktlen(wbuf), &probe_data) > 0) {
            ret = 0;
            goto exit;
        }
        if (blocked) {
            ret = 0;
            goto exit;
        }
    }
#else
    // To silence compiler warning about unused variable.
    (void) rs;
#endif

    /* EMA - known bssid element */
    if (is_ema_ap_enabled && !is_non_tx_vap) {
        if (known_bssid) {

            mbss_debug("found known_bssid element");
            mbss_info("BITMAP in known_bssid:0x%x", known_bssid[3]);
            qdf_mem_copy(&ic->ic_mbss.known_bssid_map, &known_bssid[3],
                         (1 << ic->ic_mbss.max_bssid)/BITS_PER_BYTE);
        }
    }

    /*
     * Skip Probe Requests received while the scan algorithm is setting a new
     * channel, or while in a foreign channel.
     * Trying to transmit a frame (Probe Response) during a channel change
     * (which includes a channel reset) can cause a NMI due to invalid HW
     * addresses.
     * Trying to transmit the Probe Response while in a foreign channel
     * wouldn't do us any good either.
     */
    if (wlan_scan_can_transmit(wlan_vdev_get_pdev(vap->vdev_obj)) && !vap->iv_special_vap_mode) {
        if (likely(ic->ic_curchan == vap->iv_bsschan)) {
            snd_prb_resp = 1;
        }
#if MESH_MODE_SUPPORT
        if (vap->iv_mesh_vap_mode) {
            snd_prb_resp = 0;
        }
#endif
    }
    if (snd_prb_resp) {
        extractx.fectx_assocwar160_reqd = is_assocwar160_reqd_proberesp(vap,
                (struct ieee80211_ie_ssid *)ssid_info, vhtcap);

        if (extractx.fectx_assocwar160_reqd) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                              "%s: Applying 160MHz assoc WAR: probe resp to "
                              "STA %s\n",
                              __func__, ether_sprintf(wh->i_addr2));
        }

        if (ni) {
#if QCN_IE
            /* If channel time is not present then send the unicast response immediately */
            if ((extractx.fils_sta || extractx.oce_sta) && channel_time && vap->iv_bpr_enable &&
                    IEEE80211_IS_BROADCAST(wh->i_addr1) && IEEE80211_IS_BROADCAST(wh->i_addr3)) {

                /* If channel time is bigger than beancon interval, slightly discard the probe-req
                   as beacon will be sent instead */
                if (channel_time > ic->ic_intval) {
                    goto exit;
                }

                if (!extractx.oce_sta) {
                    if (ieee80211_vap_oce_check(vap))
                        extractx.retry = vap->iv_prb_retry;
                    ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);
                    vap->iv_bpr_unicast_resp_count++;
                } else if (!qdf_hrtimer_active(bpr_gen_timer)) {
                    /* If its the first STA sending broadcast probe request, start the timer with
                     * the minimum of user configured delay and the channel time.
                     */
                    bpr_delay = qdf_ns_to_ktime(QDF_NSEC_PER_MSEC * vap->iv_bpr_delay);

                    /* Set the bpr_delay to be the minimum of channel time and user configured value */
                    if (qdf_ktime_to_ns(eff_chan_time) < qdf_ktime_to_ns(bpr_delay)) {
                        bpr_delay = eff_chan_time;
                    }

                    qdf_hrtimer_start(bpr_gen_timer, bpr_delay, QDF_HRTIMER_MODE_REL);
                    vap->iv_bpr_timer_start_count++;

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                        "Start timer: %s | %d | Sequence: %d | Delay: %d | Current time: %lld | Beacon: %lld | effchantime: %lld | "
                        " Timer expires: %lld | Timer cb: %d | Enqueued: %d \n", \
                        __func__, __LINE__, ((le16toh(*(u_int16_t *)wh->i_seq)) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT,
                        vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp),
                        eff_chan_time, qdf_ktime_to_ns(qdf_ktime_add(qdf_ktime_get(),
                        qdf_hrtimer_get_remaining(bpr_gen_timer))),
                        qdf_hrtimer_callback_running(bpr_gen_timer), qdf_hrtimer_is_queued(bpr_gen_timer));
                } else {

                    /* For rest of the STA sending broadcast probe requests, if the
                     * timer callback is not running and channel time is less than the remaining
                     * time in the timer, resize the timer to the channel time. Ignore if timer callback
                     * is running as it will be served by the broadcast probe response.
                     */
                    if(!qdf_hrtimer_callback_running(bpr_gen_timer) &&
                        qdf_ktime_to_ns(qdf_hrtimer_get_remaining(bpr_gen_timer)) > qdf_ktime_to_ns(eff_chan_time)) {

                        qdf_hrtimer_forward(bpr_gen_timer, qdf_hrtimer_cb_get_time(bpr_gen_timer), eff_chan_time);
                        vap->iv_bpr_timer_resize_count++;

                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                            "Resize timer: %s| %d | Sequence: %d | Delay: %d | Current time: %lld | Next beacon tstamp: %lld | effchantime: %lld | "
                            "Timer expires in: %lld | Timer cb: %d | Enqueued: %d\n", \
                            __func__, __LINE__, ((le16toh(*(u_int16_t *)wh->i_seq)) & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT,
                            vap->iv_bpr_delay, qdf_ktime_to_ns(qdf_ktime_get()), qdf_ktime_to_ns(vap->iv_next_beacon_tstamp),
                            eff_chan_time, qdf_ktime_to_ns(qdf_ktime_add(qdf_ktime_get(),qdf_hrtimer_get_remaining(bpr_gen_timer))),
                            qdf_hrtimer_callback_running(bpr_gen_timer), qdf_hrtimer_is_queued(bpr_gen_timer));
                    }

                }

            } else if ((extractx.fils_sta || extractx.oce_sta) && channel_time && vap->iv_bpr_enable &&
                       (IEEE80211_ADDR_EQ(wh->i_addr1, vap->iv_myaddr) || IEEE80211_ADDR_EQ(wh->i_addr3, vap->iv_myaddr))) {

                /* If channel time is bigger than beancon interval, slightly discard the probe-req
                    as beacon will be sent instead */
                if (channel_time > ic->ic_intval) {
                    goto exit;
                }

                /* If STA sends a probe request to the VAP with some channel time, then send unicast
                 * response only if there is no beacon to be scheduled before the channel time expires.
                 * Otherwise, the beacon will be sent.
                 */
                if ((qdf_ktime_to_ns(vap->iv_next_beacon_tstamp) - QDF_NSEC_PER_MSEC * ic->ic_bcn_latency_comp) >  ktime_to_ns(eff_chan_time)) {
                    if (ieee80211_vap_oce_check(vap)) {
                        if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan) && extractx.oce_sta) {
                            if (rs->rs_datarate < vap->iv_prb_rate)
                                extractx.datarate = rs->rs_datarate;
                            else
                                extractx.datarate = vap->iv_prb_rate;
                        }
                        extractx.retry = vap->iv_prb_retry;
                    }
                    ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);
                    vap->iv_bpr_unicast_resp_count++;

                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                                      "Unicast response sent: %s | %d | "
                                      "Sequence: %d | Delay: %d | Current time:"
                                      " %lld | Next beacon tstamp: %lld | "
                                      "effchantime: %lld | beacon interval: "
                                      "%d ms | Timer expires in: %lld | "
                                      "Timer cb running: %d\n", __func__,
                                      __LINE__,
                                      ((le16toh(*(u_int16_t *)wh->i_seq))
                                      & IEEE80211_SEQ_SEQ_MASK) >>
                                      IEEE80211_SEQ_SEQ_SHIFT,
                                      vap->iv_bpr_delay,
                                      qdf_ktime_to_ns(qdf_ktime_get()),
                                      qdf_ktime_to_ns(
                                          vap->iv_next_beacon_tstamp),
                                      eff_chan_time, ic->ic_intval,
                                      qdf_ktime_to_ns(qdf_ktime_add(
                                          qdf_ktime_get(),
                                          qdf_hrtimer_get_remaining(
                                              bpr_gen_timer))),
                                      qdf_hrtimer_callback_running(
                                          bpr_gen_timer));
                }
            } else
#endif
            {
                /*
                 * When MBSS IE feature is enabled, we send one probe response for a broadcast
                 * probe request, so we skip sending here. Response is sent from ieee80211_input_all().
                 * It is sent here in 2 cases:
                 * 1. Non-MBSS and unicast/broadcast probe req
                 * 2. MBSS and unicast probe req
                 */
                if (!is_mbssid_enabled ||
                    (!IEEE80211_IS_BROADCAST(wh->i_addr3) &&
                     ic->ic_mbss.prb_req_ssid_match_vap))
                {
                    if (ieee80211_vap_oce_check(vap)) {
                        if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan) && extractx.oce_sta) {
                            if (rs->rs_datarate < vap->iv_prb_rate)
                                extractx.datarate = rs->rs_datarate;
                            else
                                extractx.datarate = vap->iv_prb_rate;
                        }
                        extractx.retry = vap->iv_prb_retry;
                    }

                    /* in MBSS IE case, response is always sent from Tx BSS */
                    if (is_mbssid_enabled && is_non_tx_vap) {
                        tx_vap = ic->ic_mbss.transmit_vap;
                        if (!tx_vap) {
                             mbss_err(" Tx VAP is NULL, so not sending probe resp");
                             goto exit;
                        }
                        ni_bss_tx_vap = ieee80211_try_ref_bss_node(tx_vap, WLAN_MGMT_HANDLER_ID);
                        if (ni_bss_tx_vap) {
                             ieee80211_send_proberesp(ni_bss_tx_vap, wh->i_addr2, NULL, 0, &extractx);
                             ic->ic_mbss.resp_sent = 1;
                             ieee80211_free_node(ni_bss_tx_vap, WLAN_MGMT_HANDLER_ID);
                        }
                        else {
                             mbss_err(" Tx VAP(%d) BSS node is not valid, so not sending probe resp",
                                      tx_vap->iv_unit);
                             goto exit;
                        }
                    }
                    else {
                         ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);
                         ic->ic_mbss.resp_sent = 1;
                    }
                }
                else {
                    ret = 0;
                    goto exit;
                }
            }
        } /* if (ni) */
    }
    else {
        goto exit;
    }

    ret = 0;
exit:
#ifdef QCA_SUPPORT_CP_STATS
    if (ret != 0)
        vdev_cp_stats_prob_req_drops_inc(vap->vdev_obj, 1);
#endif

    if(found_vap == 1 || found_null_bssid == 1)
        ieee80211_free_node(ni, WLAN_MGMT_HANDLER_ID);

    return ret;
}

