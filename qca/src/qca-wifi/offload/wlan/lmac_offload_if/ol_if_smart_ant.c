/*
 * Copyright (c) 2013,2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2013 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/* This will be registered when smart antenna is not enabled. So that WMI doesnt print
 * unhandled message.
 */
#include <ieee80211_var.h>
#include <ol_if_athvar.h>
#include "qdf_mem.h"
#include "ol_tx_desc.h"
#include <ol_if_athpriv.h>
#include <htt.h>
#include "cdp_txrx_ctrl.h"
#include <init_deinit_lmac.h>
#if UNIFIED_SMARTANTENNA
#include <wlan_sa_api_utils_defs.h>
#include <target_if_sa_api.h>
#include "ol_if_smart_ant.h"
#include "wlan_osif_priv.h"

void
ol_ath_smart_ant_get_txfeedback (void *pdev_handle, enum WDI_EVENT event, void *data,
                                 uint16_t peer_id, enum htt_rx_status status)
{
    struct ath_smart_ant_pktlog_hdr pl_hdr;
    uint32_t *pl_tgt_hdr;
    int txstatus = 0;
    int i = 0;
    struct sa_tx_feedback tx_feedback;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_peer *peer;
    struct wlan_objmgr_pdev *pdev = (struct wlan_objmgr_pdev *)pdev_handle;
    uint32_t sa_mode;
    QDF_STATUS refstatus;

    if (!pdev) {
        qdf_err("Invalid pdev in %s", __func__);
        return;
    }
    scn = (struct ol_ath_softc_net80211 *)lmac_get_pdev_feature_ptr(pdev);
    if (!scn) {
        qdf_warn("scn is NULL for pdev:%pK", pdev);
        return;
    }

    refstatus = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_SA_API_ID);
    if (QDF_IS_STATUS_ERROR(refstatus)) {
        qdf_print("%s, %d unable to get reference", __func__, __LINE__);
        return;
    }

    /* intentionally avoiding locks in data path code */
    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
        return;
    }

    if (event != WDI_EVENT_TX_STATUS) {
        qdf_print("%s: Un Subscribed Event: %d ", __func__, event);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
        return;
    }

    sa_mode = target_if_sa_api_get_sa_mode(psoc, pdev);

    pl_tgt_hdr = (uint32_t *)data;
    pl_hdr.log_type =  (*(pl_tgt_hdr + ATH_SMART_ANT_PKTLOG_HDR_LOG_TYPE_OFFSET) &
                                        ATH_SMART_ANT_PKTLOG_HDR_LOG_TYPE_MASK) >>
                                        ATH_SMART_ANT_PKTLOG_HDR_LOG_TYPE_SHIFT;

    if ((pl_hdr.log_type == SMART_ANT_PKTLOG_TYPE_TX_CTRL)) {
        int frame_type;
        int peer_id;
        void *tx_ppdu_ctrl_desc;
        u_int32_t *tx_ctrl_ppdu, try_status = 0;
        uint8_t total_tries =0, sbw_indx_succ = 0, bw = 0;
        uint8_t peer_mac[QDF_NET_MAC_ADDR_MAX_LEN];

        tx_ppdu_ctrl_desc = (void *)data + sizeof(struct ath_smart_ant_pktlog_hdr);

        tx_ctrl_ppdu = (u_int32_t *)tx_ppdu_ctrl_desc;

        frame_type = (tx_ctrl_ppdu[TX_FRAME_OFFSET]
                          & TX_FRAME_TYPE_MASK) >> TX_FRAME_TYPE_SHIFT;

        if (frame_type == TX_FRAME_TYPE_DATA) { /* data frame */

            peer_id = tx_ctrl_ppdu[TX_PEER_ID_OFFSET];

            if (peer_id == HTT_INVALID_PEER) {
                wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
                return;
            }

            if (scn->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] == 0) {
                wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
                return;
            }

            cdp_get_peer_mac_from_peer_id(wlan_psoc_get_dp_handle(psoc), peer_id, peer_mac);

            peer = wlan_objmgr_get_peer(psoc, wlan_objmgr_pdev_get_pdev_id(pdev), peer_mac, WLAN_SA_API_ID);
            if (!peer) {
                wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
                return;
            }

            if (!wlan_vdev_get_bsspeer(peer->peer_objmgr.vdev)) {

                total_tries = (scn->tx_ppdu_end[TX_TOTAL_TRIES_OFFSET] & TX_TOTAL_TRIES_MASK) >> TX_TOTAL_TRIES_SHIFT;

                OS_MEMZERO(&tx_feedback, sizeof(tx_feedback));
                tx_feedback.nPackets = (scn->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] & 0xffff);
                tx_feedback.nBad = (scn->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] & 0x1fff0000) >> 16;

                /* Rate code and Antenna values */
                tx_feedback.tx_antenna[0] = (tx_ctrl_ppdu[TX_ANT_OFFSET_S0] & TX_ANT_MASK);
                tx_feedback.tx_antenna[1] = (tx_ctrl_ppdu[TX_ANT_OFFSET_S1] & TX_ANT_MASK);

                /* RateCode */
                tx_feedback.rate_mcs[0] = ((tx_ctrl_ppdu[TXCTRL_S0_RATE_BW20_OFFSET] & TXCTRL_RATE_MASK) >> 24) |
                                          ((tx_ctrl_ppdu[TXCTRL_S0_RATE_BW40_OFFSET] & TXCTRL_RATE_MASK) >> 16) |
                                          ((tx_ctrl_ppdu[TXCTRL_S0_RATE_BW80_OFFSET] & TXCTRL_RATE_MASK) >> 8) |
                                          (tx_ctrl_ppdu[TXCTRL_S0_RATE_BW160_OFFSET] & TXCTRL_RATE_MASK);

                tx_feedback.rate_mcs[1] = ((tx_ctrl_ppdu[TXCTRL_S1_RATE_BW20_OFFSET] & TXCTRL_RATE_MASK) >> 24) |
                                          ((tx_ctrl_ppdu[TXCTRL_S1_RATE_BW40_OFFSET] & TXCTRL_RATE_MASK) >> 16) |
                                          ((tx_ctrl_ppdu[TXCTRL_S1_RATE_BW80_OFFSET] & TXCTRL_RATE_MASK) >> 8) |
                                          (tx_ctrl_ppdu[TXCTRL_S1_RATE_BW160_OFFSET] & TXCTRL_RATE_MASK);


                if (sa_mode == SMART_ANT_MODE_SERIAL) {
                    /* Extract and fill */
                    /* index0 - s0_bw20, index1 - s0_bw40  index4 - s1_bw20 ... index7: s1_bw160 */
                    for (i = 0; i < MAX_RETRIES; i++) {
                        tx_feedback.nlong_retries[i] =  ((scn->tx_ppdu_end[LONG_RETRIES_OFFSET] >> (i*4)) & 0x0f);
                        tx_feedback.nshort_retries[i] = ((scn->tx_ppdu_end[SHORT_RETRIES_OFFSET] >> (i*4)) & 0x0f);

                        /* HW gives try counts and for SA module we need to provide failure counts
                         * So manipulate short failure count accordingly.
                         */
                        if (tx_feedback.nlong_retries[i]) {
                            if (tx_feedback.nshort_retries[i] == tx_feedback.nlong_retries[i]) {
                                tx_feedback.nshort_retries[i]--;
                            }
                        }
                    }
                }
                /* ACK RSSI */
                tx_feedback.rssi[0] = scn->tx_ppdu_end[ACK_RSSI0_OFFSET];
                tx_feedback.rssi[1] = scn->tx_ppdu_end[ACK_RSSI1_OFFSET];
                tx_feedback.rssi[2] = scn->tx_ppdu_end[ACK_RSSI2_OFFSET];
                tx_feedback.rssi[3] = scn->tx_ppdu_end[ACK_RSSI3_OFFSET];

                try_status = scn->tx_ppdu_end[total_tries-1];
                sbw_indx_succ = (try_status & TX_TRY_SERIES_MASK)?NUM_DYN_BW_MAX:0;
                sbw_indx_succ += ((try_status & TX_TRY_BW_MASK) >> TX_TRY_BW_SHIFT);
                if (sa_mode == SMART_ANT_MODE_SERIAL) {
                    if (tx_feedback.nPackets != tx_feedback.nBad) {

                        if (tx_feedback.nlong_retries[sbw_indx_succ]) {
                            tx_feedback.nlong_retries[sbw_indx_succ] -= 1;
                        }

                        if (tx_feedback.nshort_retries[sbw_indx_succ]) {
                            tx_feedback.nshort_retries[sbw_indx_succ] -= 1;
                        }
                    }
                }

                tx_feedback.rate_index = sbw_indx_succ;
                tx_feedback.is_trainpkt = ((scn->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] & SMART_ANT_FEEDBACK_TRAIN_MASK) ? 1: 0);
		for (bw = 0; bw < SA_BW_COUNT; bw++) {
			tx_feedback.ratemaxphy[bw] =
			((scn->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET_2] >> (bw * (SA_RC_LEN))) & (SA_RC_MASK));
		}
                tx_feedback.goodput =  (scn->tx_ppdu_end[(SMART_ANT_FEEDBACK_OFFSET_2+1)]);

                tx_feedback.num_comb_feedback = (scn->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET]  & 0x60000000) >> 29;
                *((uint32_t *)&tx_feedback.comb_fb[0]) = scn->tx_ppdu_end[LONG_RETRIES_OFFSET];
                *((uint32_t *)&tx_feedback.comb_fb[1]) = scn->tx_ppdu_end[SHORT_RETRIES_OFFSET];

                /* Data recevied from the associated node, Prepare TX feed back structure and send to SA module */
                txstatus = target_if_sa_api_update_tx_feedback(psoc, pdev, peer, &tx_feedback);
            }
            wlan_objmgr_peer_release_ref(peer, WLAN_SA_API_ID);
        }
    } else {
        /* First We will get status */
        if (pl_hdr.log_type == SMART_ANT_PKTLOG_TYPE_TX_STAT) {
            void *tx_ppdu_status_desc;
            u_int32_t *tx_status_ppdu;
            tx_ppdu_status_desc = (void *)data + sizeof(struct ath_smart_ant_pktlog_hdr);
            tx_status_ppdu = (u_int32_t *)tx_ppdu_status_desc;
            /* cache ppdu end (tx status desc) for smart antenna txfeedback */
            OS_MEMCPY(&scn->tx_ppdu_end, tx_status_ppdu, (sizeof(uint32_t)*MAX_TX_PPDU_SIZE));
        }
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_SA_API_ID);
    return;
}

int ol_ath_smart_ant_enable_txfeedback(struct wlan_objmgr_pdev *pdev, int enable)
{
    struct ol_ath_softc_net80211 *scn;
    struct smart_ant_enable_tx_feedback_params param;
    struct pdev_osif_priv *osif_priv = NULL;
    ol_txrx_soc_handle soc_txrx_handle;
    uint8_t pdev_id;
    struct wmi_unified *pdev_wmi_handle;

    /* intentionally avoiding locks in data path code */
    osif_priv = wlan_pdev_get_ospriv(pdev);
    if (NULL == osif_priv) {
        qdf_print("%s: osif_priv is NULL!", __func__);
        return A_ERROR;
    }

    scn = (ol_scn_t)osif_priv->legacy_osif_priv;
    if (NULL == scn) {
        qdf_print("%s: scn is NULL!", __func__);
        return A_ERROR;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.enable = enable;
    soc_txrx_handle = wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(pdev));
    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);

    if (enable == 1) {
        /* Call back for txfeedback */
        ((scn->sa_event_sub).callback) = ol_ath_smart_ant_get_txfeedback;
        ((scn->sa_event_sub).context) = scn->sc_pdev;
        if(cdp_wdi_event_sub(soc_txrx_handle,
                        pdev_id,
                        &(scn->sa_event_sub),
                        WDI_EVENT_TX_STATUS)) {
            return A_ERROR;
        }
    } else if (enable == 0) {
        if(cdp_wdi_event_unsub(soc_txrx_handle,
                    pdev_id,
                    &(scn->sa_event_sub),
                    WDI_EVENT_TX_STATUS)) {
            return A_ERROR;
        }
    }

    return wmi_unified_smart_ant_enable_tx_feedback_cmd_send(pdev_wmi_handle, &param);
}
qdf_export_symbol(ol_ath_smart_ant_enable_txfeedback);

#endif
