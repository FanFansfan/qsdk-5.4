/*
 * Copyright (c) 2011-2014, 2017-2018, 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */
/*
 * 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/* standard header files */
#include <qdf_nbuf.h>         /* qdf_nbuf_map */
#include <qdf_mem.h>       /* qdf_mem_cmp */

/* external header files */
#include <ol_cfg.h>           /* wlan_op_mode_ap, etc. */
#include <ol_htt_rx_api.h>    /* htt_rx_msdu_desc_retrieve */
/* internal header files */
#include <ol_txrx_types.h>    /* ol_txrx_dev_t, etc. */
#include <ol_rx_fwd.h>        /* our own defs */
#include <ol_rx.h>            /* ol_rx_deliver */
#include <ol_txrx_internal.h> /* TXRX_ASSERT1 */
#include <ieee80211.h>         /* ieee80211_frame */
#include <ieee80211_var.h>     /* IEEE80211_ADDR_COPY */
#include <dp_txrx.h>
#if QCA_PARTNER_DIRECTLINK_TX
#define QCA_PARTNER_DIRECTLINK_OL_RX_FWD 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_OL_RX_FWD
#endif /* QCA_PARTNER_DIRECTLINK_TX */
#if QCA_SUPPORT_PEER_ISOLATION
#include <ol_txrx_peer_find.h>
#include <ol_txrx.h>
#endif /* QCA_SUPPORT_PEER_ISOLATION */

extern void transcap_nwifi_to_8023(qdf_nbuf_t msdu);

static inline
void
ol_rx_fwd_to_tx(struct ol_txrx_vdev_t *vdev, qdf_nbuf_t msdu)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ether_header *eh = (struct ether_header *)msdu->data;
    struct ieee80211vap *vap = NULL;
    struct ieee80211_node *ni = NULL;

    vap = ol_ath_pdev_vap_get(((struct ol_ath_softc_net80211 *)pdev->scnctx)->sc_pdev,
                                                 vdev->vdev_id);
    if (pdev->host_80211_enable) {
        transcap_nwifi_to_8023(msdu);
    }

    qdf_nbuf_set_next(msdu, NULL); /* add NULL terminator */

#if UMAC_SUPPORT_WNM
    if (vap && wlan_wnm_tfs_filter(vap, msdu)) {
        htt_rx_msdu_desc_free(pdev->htt_pdev, msdu);
        htt_rx_desc_frame_free(pdev->htt_pdev, msdu);
        ol_ath_release_vap(vap);
        return;
    }
#endif

    /*
     * Dont allow intra vap forwarding frames if drivers internal flow
     * control queue (acnbufq) is almost full. keeping 2 * scn->vdev_count
     * queue entries explicitly reserved for frames coming from
     * hard_start_xmit will allow driver to pause kernel queue before
     * any frame is dropped into driver. These reserved entries will
     * also avoid race condition in reading acqcnt. Allowing kernel to
     * queue few extra frames is fair as kernel queue will remain paused
     * Untill available queue size reaches OL_TX_FLOW_CTRL_QUEUE_WAKEUP_THRESOLD
     * but intra vap forwarding will get chance to grab an empty slot in acnbufq.
     */

    if (pdev->acqcnt < (pdev->acqcnt_len - (2 * pdev->vdev_count))) {

       if (vap) {
           if((IEEE80211_IS_IPV4_MULTICAST((eh)->ether_dhost) ||
              IEEE80211_IS_IPV6_MULTICAST((eh)->ether_dhost)) &&
              ((vap)->iv_sta_assoc > 0 ) &&
              (!IEEE80211_IS_BROADCAST((eh)->ether_dhost)) &&
              (dp_get_me_mode((struct cdp_soc_t *)(pdev->soc), vdev->vdev_id))) {
                   ni = ieee80211_find_node(vap->iv_ic, (eh)->ether_shost, WLAN_MLME_SB_ID);
                   if (ni) {
                       ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                       /*
                        * if the convert function returns some value larger
                        * than 0, it means that one or more frames have been
                        * transmitted and it is safe to return from here.
                        */
                       OL_VDEV_TX_MCAST_ENHANCE((struct cdp_soc_t *)(pdev->soc),
                                                vdev,
                                                pdev->pdev_id,
                                                msdu, vap);
                       /* Else continue with normal path. This happens when
                        * mcast frame is recieved but enhance is not enabled
                        * OR if it a broadcast frame send it as-is
                        */
                   }
           }
       }

        /* For VLAN frames, remove extra 2 bytes */
        if (ntohs(eh->ether_type) == ETH_P_8021Q) {
            transcap_dot3_to_eth2(msdu);
        }
        OL_VDEV_TX((ol_txrx_vdev_handle) vdev, msdu, pdev->osdev);
        OL_TXRX_STATS_MSDU_INCR(vdev->pdev, rx.forwarded, msdu);
    } else {
        /* Drop this frame right now */
        vdev->stats.tx_i.dropped.desc_na.num++;
        qdf_nbuf_free(msdu);
    }
    if (vap) {
        ol_ath_release_vap(vap);
    }
}

void
ol_rx_fwd_check(
    struct ol_txrx_vdev_t *vdev,
    struct ol_txrx_peer_t *src_peer,
    unsigned tid,
    qdf_nbuf_t msdu_list)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    qdf_nbuf_t deliver_list_head = NULL;
    qdf_nbuf_t deliver_list_tail = NULL;
    qdf_nbuf_t msdu;

    if (OL_CFG_RAW_RX_LIKELINESS(vdev->rx_decap_type == htt_pkt_type_raw)) {
        /* Forwarding is not handled since keys would reside on Access
         * Controller.
         *
         * Full fledged Mixed VAP functionality can add requisite exceptions in
         * this function.
         */
        ol_rx_deliver(vdev, src_peer, tid, msdu_list);
        return;
    }

    msdu = msdu_list;
    while (msdu) {
        struct ol_txrx_vdev_t *tx_vdev;
        void *rx_desc;
        /*
         * Remember the next list elem, because our processing
         * may cause the MSDU to get linked into a different list.
         */
        msdu_list = qdf_nbuf_next(msdu);

        rx_desc = htt_rx_msdu_desc_retrieve(pdev->htt_pdev, msdu);

        if (htt_rx_msdu_forward(pdev->htt_pdev, rx_desc)) {
#if QCA_SUPPORT_PEER_ISOLATION
            struct ether_header *eh = (struct ether_header *)msdu->data;
            struct ol_txrx_peer_t *dst_peer = NULL;
#endif

            /*
             * Use the same vdev that received the frame to
             * transmit the frame.
             * This is exactly what we want for intra-BSS forwarding,
             * like STA-to-STA forwarding and multicast echo.
             * If this is a intra-BSS forwarding case (which is not
             * currently supported), then the tx vdev is different
             * from the rx vdev.
             * On the LL host the vdevs are not actually used for tx,
             * so it would still work to use the rx vdev rather than
             * the tx vdev.
             * For HL, the tx classification searches for the DA within
             * the given vdev, so we would want to get the DA peer ID
             * from the target, so we can locate the tx vdev.
             */
            tx_vdev = vdev;
#if QCA_SUPPORT_PEER_ISOLATION
            /* check if the device sending packets has the isolation flag set OR
             * if the destination device is in the mac isolation list, and in either case
             * send the traffic to the CPU/Host/Linux */
            if ((src_peer && src_peer->isolation) || (
#if ATH_SUPPORT_WRAP
                (dst_peer = ol_txrx_peer_find_hash_find(pdev, eh->ether_dhost, 0,
                                                   vdev->vdev_id))
#else
                (dst_peer = ol_txrx_peer_find_hash_find(pdev, eh->ether_dhost, 0))
#endif
                && dst_peer->isolation)) {
                htt_rx_msdu_discard_clear(pdev->htt_pdev, rx_desc);
            } else
#endif
            {
                /*
                 * This MSDU needs to be forwarded to the tx path.
                 * Check whether it also needs to be sent to the OS shim,
                 * in which case we need to make a copy (or clone?).
                 */
                if (htt_rx_msdu_discard(pdev->htt_pdev, rx_desc)) {
                    htt_rx_msdu_desc_free(pdev->htt_pdev, msdu);

                    ol_rx_fwd_to_tx(tx_vdev, msdu);

                    msdu = NULL; /* already handled this MSDU */
                } else {
                    qdf_nbuf_t copy;
                    copy = qdf_nbuf_copy(msdu);
                    if (copy) {
                        ol_rx_fwd_to_tx(tx_vdev, copy);
                    }
                }
            }
#if QCA_SUPPORT_PEER_ISOLATION
            if (dst_peer)
                ol_txrx_peer_unref_delete((ol_txrx_peer_handle) dst_peer);
#endif
        }
        if (msdu) {
            /* send this frame to the OS */
            OL_TXRX_LIST_APPEND(deliver_list_head, deliver_list_tail, msdu);
        }
        msdu = msdu_list;
    }
    if (deliver_list_head) {
        qdf_nbuf_set_next(deliver_list_tail, NULL); /* add NULL terminator */
        ol_rx_deliver(vdev, src_peer, tid, deliver_list_head);
    }
}
