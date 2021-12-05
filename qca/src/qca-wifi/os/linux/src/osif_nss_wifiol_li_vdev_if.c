/*
 * Copyright (c) 2015-2018,2020-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2015-2016 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,9,0))
#include <net/ipip.h>
#else
#include <net/ip_tunnels.h>
#endif

#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <asm/cacheflush.h>
#include "osif_private.h"
#include <nss_api_if.h>
#include <nss_cmn.h>
#include <qdf_nbuf.h>
#include "ol_if_athvar.h"


#include "osif_private.h"
#include "osif_nss_wifiol_vdev_if.h"
#include <ar_internal.h>
#include "dp_htt.h"
#include "dp_types.h"
#include "dp_internal.h"
#include "dp_rx.h"
#include "dp_peer.h"
#include "dp_txrx_wds.h"

#include "osif_nss_wifiol_if.h"
#include "../../wlan_cfg/wlan_cfg.h"
#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"

#include <if_meta_hdr.h>
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
#include <rawsim_api_defs.h>
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
#include "osif_wrap_private.h"
extern osif_dev * osif_wrap_wdev_vma_find(struct wrap_devt *wdt,unsigned char *mac);
#else
#include "dp_wrap.h"
extern osif_dev *wlan_get_osdev(struct wlan_objmgr_vdev *vdev);
extern struct ieee80211vap *wlan_get_vap(struct wlan_objmgr_vdev *vdev);
#endif
#endif

#if MESH_MODE_SUPPORT
u_int32_t osif_rx_status_dump(void* rs);
#endif

#define ETHERNET_HDR_LEN sizeof(struct ether_header)

extern struct osif_nss_vdev_cfg_pvt osif_nss_vdev_cfgp;

/*
 * This file is responsible for interacting with qca-nss-drv's
 * WIFI to manage WIFI VDEVs.
 *
 * This driver also exposes few APIs which can be used by
 * another module to perform operations on CAPWAP tunnels. However, we create
 * one netdevice for all the CAPWAP tunnels which is done at the module's
 * init time if NSS_wifimgr_ONE_NETDEV is set in the Makefile.
 *
 * If your requirement is to create one netdevice per-CAPWAP tunnel, then
 * netdevice needs to be created before CAPWAP tunnel create. Netdevice are
 * created using nss_wifimgr_netdev_create() API.
 *
 */
#define OSIF_NSS_DEBUG_LEVEL 1

#define OSIF_NSS_MAX_AST 4096

/*
 * NSS WiFi offload debug macros
 */
#if (OSIF_NSS_DEBUG_LEVEL < 1)
#define osif_nss_assert(fmt, args...)
#else
#define osif_nss_assert(c) if (!(c)) { BUG_ON(!(c)); }
#endif /* OSIF_NSS_DEBUG_LEVEL */

/*
 * Compile messages for dynamic enable/disable
 */
#if !defined(CONFIG_DYNAMIC_DEBUG)
#define osif_nss_warn(s, ...) qdf_nofl_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define osif_nss_info(s, ...) qdf_nofl_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define osif_nss_trace(s, ...) qdf_nofl_debug("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else /* CONFIG_DYNAMIC_DEBUG */
/*
 * Statically compile messages at different levels
 */
#if (OSIF_NSS_DEBUG_LEVEL < 2)
#define osif_nss_warn(s, ...)
#else
#define osif_nss_warn(s, ...) qdf_nofl_warn("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (OSIF_NSS_DEBUG_LEVEL < 3)
#define osif_nss_info(s, ...)
#else
#define osif_nss_info(s, ...)   pr_notice("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#if (OSIF_NSS_DEBUG_LEVEL < 4)
#define osif_nss_trace(s, ...)
#else
#define osif_nss_trace(s, ...)  qdf_nofl_info("%s[%d]:" s, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif
#endif /* CONFIG_DYNAMIC_DEBUG */

static inline struct dp_soc *
osif_nss_ol_li_dp_soc_from_scn(struct ol_ath_softc_net80211 *scn)
{
    return wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
}

static inline struct dp_soc *
osif_nss_ol_li_dp_soc_from_vap(struct ieee80211vap *vap)
{
    return wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(osif_nss_ol_get_objmgr_pdev_from_vap(vap)));
}

/*
 * TODO: Currently function dp_peer_find_hash_find is defined
 * as static inside dp_peer.c. We have to decide upon a way to expose
 * this function here.
 */
extern struct dp_peer *dp_peer_find_hash_find(struct dp_soc *soc,
        uint8_t *peer_mac_addr, int mac_addr_is_aligned, uint8_t vdev_id,
	enum dp_mod_id id);

#if DBDC_REPEATER_SUPPORT
int dbdc_rx_process (os_if_t *osif ,struct net_device **dev ,wlan_if_t vap, struct sk_buff *skb);
int dbdc_tx_process (wlan_if_t vap, osif_dev **osdev , struct sk_buff *skb);
#endif

/*
 * osif_nss_wifili_vdev_update_statsv2()
 * Update statsv2 per ppdu
 */
void osif_nss_wifili_vdev_update_statsv2(struct ol_ath_softc_net80211 *scn, struct sk_buff * nbuf, void *rx_mpdu_desc, uint8_t htt_rx_status)
{
    /* NA */
}

/*
 * osif_nss_wifili_vdev_txinfo_handler()
 * Handler for tx info packets exceptioned from WIFI
 */
void osif_nss_wifili_vdev_txinfo_handler(struct ol_ath_softc_net80211 *scn, struct sk_buff *skb, struct nss_wifi_vdev_per_packet_metadata *wifi_metadata, bool is_raw)
{
	/* NA */
}

/*
 * osif_nss_ol_li_vdev_get_per_pkt_vdev_id_check()
 * To get if per packet vdev id check is enabled or disabled
 */
uint32_t osif_nss_ol_li_vdev_get_per_pkt_vdev_id_check(struct ol_ath_softc_net80211 *scn)
{
    struct dp_soc *dpsoc = osif_nss_ol_li_dp_soc_from_scn(scn);
    return wlan_cfg_is_tx_per_pkt_vdev_id_check_enabled(dpsoc->wlan_cfg_ctx);
}

/**
 * osif_nss_ol_li_vdev_check_local_dev() - Check system local netdevice
 *                                          for particular mac address.
 * @mac_addr: MAC address.
 *
 * Return: TRUE if local netdevice present with specified mac address.
 *          Otherwise FALSE.
 */
bool osif_nss_ol_li_vdev_check_local_dev(struct qdf_mac_addr *wds_src_mac)
{
    struct net_device *dev = NULL;

    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
        if (!dev) {
            continue;
        }
        if (qdf_is_macaddr_equal((struct qdf_mac_addr *)dev->dev_addr, wds_src_mac)) {
            rcu_read_unlock();
            QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
                    "MAC:%pM matches local netdev:%s dev:%p",
                    wds_src_mac, dev->name, dev);
            return true;
        }
    }
    rcu_read_unlock();
    QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_TRACE,
            "MAC:%pM does not match any local netdev address",wds_src_mac);
    return false;
}

/*
 * osif_nss_wifili_vdev_tx_inspect_handler()
 *	Handler for tx inspect packets exceptioned from WIFI
 */
void osif_nss_wifili_vdev_tx_inspect_handler(struct cdp_soc_t *soc_hdl, uint8_t vdev_id, struct sk_buff *skb)
{
    struct dp_peer *peer;
    struct sk_buff *skb_copy;
    uint16_t peer_id = HTT_INVALID_PEER;
    struct dp_vdev *vdev;
    struct dp_soc *soc = (struct dp_soc *)soc_hdl;

    vdev = dp_vdev_get_ref_by_id(soc, vdev_id, DP_MOD_ID_NSS_OFFLOAD);
    if ((!vdev) || vdev->osif_proxy_arp(vdev->osif_vdev, skb)) {
        goto out;
    }

    peer = dp_vdev_bss_peer_ref_n_get(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);

    if(peer) {
        peer_id = peer->peer_id;
        if (peer_id == HTT_INVALID_PEER) {
            dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
            goto out;
        }

        skb_copy = qdf_nbuf_copy(skb);
        if (skb_copy) {
            qdf_nbuf_reset_ctxt(skb_copy);
            osif_nss_vdev_peer_tx_buf(vdev->osif_vdev, skb_copy, peer_id);
        }
        dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
    }

out:
    if(vdev)
        dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
    qdf_nbuf_free(skb);
}

/*
 * osif_nss_wifili_vdev_handle_monitor_mode()
 *	handle monitor mode, returns false if packet is consumed
 */
bool osif_nss_wifili_vdev_handle_monitor_mode(struct net_device *netdev, struct sk_buff *skb, uint8_t is_chain)
{
    /*
     * Not required for 8074 as of now.
     *  Decided as per internal discussions
     */
    return true;
}


/*
 * osif_nss_wifili_vdev_spl_receive_exttx_compl()
 *  Handler for data packets exceptioned from WIFI
 */
/*
 * Li currently does not have special data receive implemented
 * TODO: Implement this for 8074 later when needed
 */
void osif_nss_wifili_vdev_spl_receive_exttx_compl(struct net_device *dev, struct sk_buff *skb, struct nss_wifi_vdev_tx_compl_metadata *tx_compl_metadata)
{
    return;
}

#if MESH_MODE_SUPPORT
extern void os_if_tx_free_ext(struct sk_buff *skb);
#endif

/*
 * osif_nss_wifili_vdev_spl_receive_ext_mesh()
 *  Handler for EXT Mesh data packets exceptioned from WIFI
 */
void osif_nss_wifili_vdev_spl_receive_ext_mesh(struct net_device *dev, struct sk_buff *skb, struct nss_wifi_vdev_mesh_per_packet_metadata *mesh_metadata)
{
#if MESH_MODE_SUPPORT
    struct meta_hdr_s *mhdr = NULL;
    struct ol_ath_softc_net80211 *av_sc = osif_nss_ol_get_scn_from_netdev(dev);
    uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(osif_nss_ol_get_objmgr_pdev_from_scn(av_sc));
    struct dp_soc *soc = osif_nss_ol_li_dp_soc_from_scn(av_sc);
    struct dp_pdev *pdev = dp_get_pdev_from_soc_pdev_id_wifi3(soc, pdev_id);

    if (!pdev) {
        return;
    }

    if (qdf_nbuf_headroom(skb) < sizeof(struct meta_hdr_s)) {
        qdf_print("Unable to accomodate mesh mode meta header");
        qdf_nbuf_free(skb);
        return;
    }

    qdf_nbuf_push_head(skb, sizeof(struct meta_hdr_s));

    mhdr = (struct meta_hdr_s *)qdf_nbuf_data(skb);
    mhdr->rssi =  mesh_metadata->rssi;
    mhdr->retries = mesh_metadata->tx_retries;
    mhdr->band = pdev->operating_channel.band;
    mhdr->channel = pdev->operating_channel.num;

    os_if_tx_free_ext(skb);
#else
    qdf_nbuf_free(skb);
#endif
    return;
}

/*
 * osif_nss_ol_li_vdev_spl_receive_ext_wdsdata
 * 	WDS special data receive
 */
bool osif_nss_ol_li_vdev_spl_receive_ext_wdsdata(struct net_device *dev, struct sk_buff *nbuf, struct nss_wifi_vdev_wds_per_packet_metadata *wds_metadata)
{
    osif_dev  *osdev;
    struct ieee80211vap *vap = NULL;
    struct dp_pdev *pdev = NULL;
    struct dp_soc *soc = NULL;
    uint8_t wds_src_mac[QDF_MAC_ADDR_SIZE];
    uint8_t dest_mac[QDF_MAC_ADDR_SIZE];
    uint8_t sa_is_valid = 0, addr4_valid = 0;
    uint16_t sa_idx = 0, sa_sw_peer_id = 0;
    uint16_t peer_id;
    uint8_t pdev_id;
    struct dp_peer *ta_peer = NULL;
    enum wifi_vdev_ext_wds_info_type wds_type;
    uint8_t *tx_status;
    struct dp_ast_entry *ast_entry = NULL;
    struct ol_ath_softc_net80211 *av_sc;
    struct dp_vdev *vdev;
#if ATH_SUPPORT_WRAP
    osif_dev *psta_osdev = NULL;
    uint8_t mac_addr[QDF_MAC_ADDR_SIZE];
    uint8_t i = 0;
#if !WLAN_QWRAP_LEGACY
    struct wlan_objmgr_vdev *psta_vdev = NULL;
#endif
#endif
    bool status;
    /*
     * Need to move this code to wifi driver
     */
    if(dev == NULL) {
        qdf_print(KERN_CRIT "%s , netdev is NULL, freeing skb", __func__);
        return false;
    }

    osdev = ath_netdev_priv(dev);
    vap = osdev->os_if;
    av_sc = osif_nss_ol_get_scn_from_vap(vap);
    pdev_id = wlan_objmgr_pdev_get_pdev_id(osif_nss_ol_get_objmgr_pdev_from_scn(av_sc));
    soc = osif_nss_ol_li_dp_soc_from_scn(av_sc);
    pdev = dp_get_pdev_from_soc_pdev_id_wifi3(soc, pdev_id);
    vdev = dp_vdev_get_ref_by_id(soc, wlan_vdev_get_id(osdev->ctrl_vdev), DP_MOD_ID_NSS_OFFLOAD);

    if (!vdev || !pdev) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                        "vdev = %pK, pdev = %pK", vdev, pdev);
        status = false;
        goto out;
    }

    sa_is_valid = wds_metadata->is_sa_valid;
    peer_id = wds_metadata->peer_id;
    wds_type = wds_metadata->wds_type;
    addr4_valid = wds_metadata->addr4_valid;
    sa_idx = wds_metadata->sa_idx;
    sa_sw_peer_id = wds_metadata->sa_sw_peer_id;

    switch (wds_type) {
        case NSS_WIFI_VDEV_WDS_TYPE_RX:
            ta_peer = dp_peer_get_ref_by_id(pdev->soc, peer_id, DP_MOD_ID_NSS_OFFLOAD);
            if (!ta_peer) {
                QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_WARN,
                        "Unable to find peer %d", peer_id);
                break;
            }

            memcpy(wds_src_mac, (qdf_nbuf_data(nbuf) + QDF_MAC_ADDR_SIZE),
                    QDF_MAC_ADDR_SIZE);

            qdf_spin_lock_bh(&soc->ast_lock);

            if (soc->ast_override_support) {
                ast_entry = dp_peer_ast_hash_find_by_pdevid(soc, wds_src_mac, pdev->pdev_id);
            } else {
                ast_entry = dp_peer_ast_hash_find_soc(soc, wds_src_mac);
            }

            if (ast_entry) {
                /*
                 * If WDS update is coming back on same peer it indicates that it is not roamed
                 * This situation can happen if a MEC packet reached in Rx direction even before the
                 * ast entry installation in happend in HW
                 */
                if ((ast_entry->peer_id == ta_peer->peer_id) && (vdev->opmode == wlan_op_mode_sta)) {
                    qdf_spin_unlock_bh(&soc->ast_lock);
                    dp_peer_unref_delete(ta_peer, DP_MOD_ID_NSS_OFFLOAD);
                    break;
                }

                if (ast_entry->type == CDP_TXRX_AST_TYPE_SELF) {
                    qdf_spin_unlock_bh(&soc->ast_lock);
                    dp_peer_unref_delete(ta_peer, DP_MOD_ID_NSS_OFFLOAD);
                    break;
                }
            }

            /*
             * Avoid WDS learning if sa_idx is corrupted
             */
            if (sa_is_valid && sa_idx >= wlan_cfg_get_max_ast_idx(soc->wlan_cfg_ctx)) {
                qdf_spin_unlock_bh(&soc->ast_lock);
                qdf_err("Invalid sa_idx = %d\n", sa_idx);
                dp_peer_unref_delete(ta_peer, DP_MOD_ID_NSS_OFFLOAD);
                break;
            }

            qdf_spin_unlock_bh(&soc->ast_lock);

            /*
             * Avoid WDS learning if src mac address matches
             * any of local netdevice mac address.
             */
            if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
                if (osif_nss_ol_li_vdev_check_local_dev((struct qdf_mac_addr *)wds_src_mac)) {
                    dp_peer_unref_delete(ta_peer, DP_MOD_ID_NSS_OFFLOAD);
                    break;
                }
            }
            dp_rx_wds_add_or_update_ast(soc, ta_peer, nbuf, addr4_valid, sa_is_valid, 1,
                                         sa_idx, sa_sw_peer_id);
            dp_peer_unref_delete(ta_peer, DP_MOD_ID_NSS_OFFLOAD);
            break;

        case NSS_WIFI_VDEV_WDS_TYPE_MEC:
            /*
             * Need to free the buffer here
             */
            tx_status = (uint8_t *)qdf_nbuf_data(nbuf);
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
            if (vap->iv_mpsta) {
#else
            if (dp_wrap_vdev_is_mpsta(vap->vdev_obj)) {
#endif
                for (i = 0; i < QDF_MAC_ADDR_SIZE; i++) {
                    mac_addr[(QDF_MAC_ADDR_SIZE - 1) - i] = tx_status[(QDF_MAC_ADDR_SIZE - 2) + i];
                }
#if WLAN_QWRAP_LEGACY
                /* Mpsta vap here, find the correct tx vap from the wrap common based on src address */
                psta_osdev = osif_wrap_wdev_vma_find(&vap->iv_ic->ic_wrap_com->wc_devt, mac_addr);
#else
                psta_vdev = dp_wrap_vdev_vma_find(vap->iv_ic->ic_pdev_obj, mac_addr);
                if (!psta_vdev) {
                    break;
                }
                psta_osdev = wlan_get_osdev(psta_vdev);
                if (!psta_osdev) {
                    break;
                }
#endif
                soc = osif_nss_ol_li_dp_soc_from_vap(psta_osdev->os_if);
                if  (!vdev) {
                    break;
                }
            }
#endif
            dp_tx_mec_handler(vdev, tx_status);
            break;

        case NSS_WIFI_VDEV_WDS_TYPE_DA:

            /* Donot add AST type DA if DA was is not enabled.*/
            if (!soc->da_war_enabled)
                break;

            ta_peer = dp_peer_get_ref_by_id(pdev->soc, peer_id, DP_MOD_ID_NSS_OFFLOAD);
            if (!ta_peer) {
                qdf_err("Unable to find peer for NSS_WIFI_VDEV_WDS_TYPE_DA type,peer_id = %d\n", peer_id);
                break;
            }

            memcpy(dest_mac, qdf_nbuf_data(nbuf), QDF_MAC_ADDR_SIZE);

            /*
             * Add ast for destination address
             */
            dp_peer_add_ast(soc, ta_peer, dest_mac, CDP_TXRX_AST_TYPE_DA, IEEE80211_NODE_F_WDS_HM);
            dp_peer_unref_delete(ta_peer, DP_MOD_ID_NSS_OFFLOAD);
            break;

        case NSS_WIFI_VDEV_WDS_TYPE_NONE:
            qdf_print("WDS Source port learn path invalid type %d", peer_id);
            break;
    }

out:
    if(vdev)
        dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
    return false;
}

/*
 * osif_nss_ol_li_vdev_spl_receive_ppdu_metadata
 * 	PPDU meta data.
 */
bool osif_nss_ol_li_vdev_spl_receive_ppdu_metadata(struct net_device *dev, struct sk_buff *nbuf,
                                                   struct nss_wifi_vdev_ppdu_metadata *ppdu_mdata)
{
    struct net_device *netdev;
    osif_dev  *osdev;
    struct dp_pdev *pdev = NULL;
    struct dp_soc *soc = NULL;
    struct dp_peer *peer = NULL;
    struct hal_tx_completion_status ts;
    struct ol_ath_softc_net80211 *av_sc;
    uint8_t pdev_id;

    /*
     * Need to move this code to wifi driver
     */
    if(dev == NULL) {
        qdf_print(KERN_CRIT "%s , netdev is NULL, freeing skb", __func__);
        return false;
    }

    netdev = (struct net_device *)dev;
    osdev = ath_netdev_priv(netdev);

    av_sc = (OL_ATH_SOFTC_NET80211((osdev->os_if)->iv_ic));
    pdev_id = wlan_objmgr_pdev_get_pdev_id(av_sc->sc_ic.ic_pdev_obj);
    soc = wlan_psoc_get_dp_handle(av_sc->soc->psoc_obj);
    pdev = dp_get_pdev_from_soc_pdev_id_wifi3(soc, pdev_id);

    if (!pdev) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                 "[nss-wifili]: %s, pdev = %pK", __FUNCTION__, pdev);
        return false;
    }

    peer = (ppdu_mdata->peer_id == HTT_INVALID_PEER) ? NULL : dp_peer_get_ref_by_id(soc, ppdu_mdata->peer_id, DP_MOD_ID_NSS_OFFLOAD);

    ts.ppdu_id = ppdu_mdata->ppdu_id;
    ts.peer_id = ppdu_mdata->peer_id;
    ts.first_msdu = ppdu_mdata->first_msdu;
    ts.last_msdu = ppdu_mdata->last_msdu;

#ifdef FEATURE_PERPKT_INFO
    if (dp_get_completion_indication_for_stack(soc, pdev, peer, &ts, nbuf, 0) == QDF_STATUS_SUCCESS) {
        dp_send_completion_to_stack(soc, pdev, ppdu_mdata->peer_id, ppdu_mdata->ppdu_id, nbuf);
        if (peer) {
            dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
        }

        return true;
    }
#endif

    if (peer) {
        dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
    }
    return false;
}

/*
 * osif_nss_wifili_fill_mesh_stats
 *      Fill mesh stats.
 */
static
void osif_nss_wifili_fill_mesh_stats(struct ieee80211vap *vap, qdf_nbuf_t nbuf,
                                     struct nss_wifi_vdev_meshmode_rx_metadata *mesh_metadata)
{
#define MESH_RSSI_WAR 1
    struct mesh_recv_hdr_s *rx_info = NULL;
    uint16_t peer_id;
    uint8_t mac[QDF_MAC_ADDR_SIZE] = {0};
    struct dp_soc *soc = NULL;
    struct dp_vdev *vdev = NULL;
#if MESH_RSSI_WAR
    struct dp_peer *peer = NULL;
#endif

    soc = osif_nss_ol_li_dp_soc_from_vap(vap);
    vdev = dp_vdev_get_ref_by_id(soc, mesh_metadata->vdev_id, DP_MOD_ID_NSS_OFFLOAD);

    if (qdf_unlikely(!vdev)) {
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
                "vdev is NULL");
        return;
    }

    /* fill recv mesh stats */
    rx_info = qdf_mem_malloc(sizeof(struct mesh_recv_hdr_s));

    /* caller is responsible to free this memory */
    if (rx_info == NULL) {
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
                "Memory allocation failed for mesh rx stats");
        DP_STATS_INC(vdev->pdev, mesh_mem_alloc, 1);
        dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
        return;
    }

    qdf_mem_zero(rx_info, (sizeof(struct mesh_recv_hdr_s)));

    rx_info->rs_band = wlan_reg_freq_to_band(mesh_metadata->cntr_chan_freq);
    rx_info->rs_channel = mesh_metadata->rs_channel;
    rx_info->rs_flags = mesh_metadata->rs_flags;
    rx_info->rs_keyix = mesh_metadata->rs_keyix;
    rx_info->rs_ratephy1 = mesh_metadata->rs_ratephy_lo |
                           mesh_metadata->rs_ratephy_hi << 16;
    peer_id = mesh_metadata->peer_id;
    cdp_get_peer_mac_from_peer_id((struct cdp_soc_t *)soc, peer_id, mac);
#if MESH_RSSI_WAR
    peer = dp_peer_get_ref_by_id(soc, peer_id, DP_MOD_ID_NSS_OFFLOAD);

    if (!(peer)) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_WARN,
                  "[nss-wifili]: %s, peer = %pK", __FUNCTION__, peer);
            return ;
    }

    rx_info->rs_snr = peer->stats.rx.snr;
    dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
#else
    rx_info->rs_snr = mesh_metadata->rs_rssi;
#endif

    if ((rx_info->rs_flags & MESH_RX_DECRYPTED) && vdev->osif_get_key) {
         vdev->osif_get_key(vdev->osif_vdev, &rx_info->rs_decryptkey[0],
                               mac, rx_info->rs_keyix);
    }

    qdf_nbuf_set_rx_fctx_type(nbuf, (void *)rx_info, CB_FTYPE_MESH_RX_INFO);
    dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
}

/*
 * osif_nss_li_vdev_set_peer_nexthop()
 *      Handles set_peer_nexthop message
 */
int osif_nss_li_vdev_set_peer_nexthop(osif_dev *osif, uint8_t *addr, nss_if_num_t if_num)
{
    struct nss_ctx_instance *nss_ctx = NULL;
    int status = 0;
    nss_tx_status_t nss_status;

    if (!osif) {
        return status;
    }

    nss_ctx = osif->nss_wifiol_ctx;
    if (!nss_ctx) {
        return status;
    }

    nss_status = nss_wifi_vdev_set_peer_next_hop(nss_ctx, osif->nss_ifnum, addr, if_num);
    if (nss_status != NSS_TX_SUCCESS) {
        osif_nss_warn("Unable to send the peer next hop message to NSS\n");
        return status;
    }

    qdf_print("\nSetting next hop of peer %pM to %d interface number", addr, if_num);

    return 1;
}

/*
 * osif_nss_wifili_vdev_data_receive_meshmode_rxinfo()
 *       Handler for data packets exceptioned from WIFI
 */
#if MESH_MODE_SUPPORT
void osif_nss_wifili_vdev_data_receive_meshmode_rxinfo(struct net_device *dev, struct sk_buff *skb)
{
    osif_dev  *osdev;
    struct nss_wifi_vdev_meshmode_rx_metadata *mesh_metadata = NULL;
    qdf_nbuf_t msdu = (qdf_nbuf_t)skb;
    struct ieee80211vap *vap;

    /*
     * Need to move this code to wifi driver
     */
    if(dev == NULL) {
        qdf_err(KERN_CRIT "%s , netdev is NULL, freeing skb", __func__);
        qdf_nbuf_free(skb);
        return;
    }

    osdev = ath_netdev_priv(dev);
    vap = osdev->os_if;

    if (!vap->iv_mesh_vap_mode) {
        return;
    }

    mesh_metadata = (struct nss_wifi_vdev_meshmode_rx_metadata *)skb->data;
    skb_pull(skb, sizeof(struct nss_wifi_vdev_meshmode_rx_metadata));
    osif_nss_wifili_fill_mesh_stats(vap, msdu, mesh_metadata);
    if (vap->mdbg & MESH_DEBUG_DUMP_STATS)
        osif_rx_status_dump((void *)qdf_nbuf_get_rx_fctx(skb));

    qdf_mem_free((void *)qdf_nbuf_get_rx_fctx(skb));
    qdf_nbuf_set_rx_fctx_type(skb, 0, CB_FTYPE_INVALID);
}
#endif

uint8_t osif_nss_wifili_vdev_call_monitor_mode(struct net_device *netdev, osif_dev  *osdev, qdf_nbuf_t skb_list_head, uint8_t is_chain)
{

    /*
     * Handle Monitor Mode is not required for 8074
     */
    return 0;
}

void osif_nss_wifili_vdevcfg_set_offload_params(struct cdp_soc_t *soc_hdl, uint8_t vdev_id, struct nss_wifi_vdev_config_msg **p_wifivdevcfg)
{
    struct dp_soc *soc = cdp_soc_t_to_dp_soc(soc_hdl);
    struct nss_wifi_vdev_config_msg *wifivdevcfg = *p_wifivdevcfg;
    struct dp_vdev *vdev_handle = dp_vdev_get_ref_by_id(soc, vdev_id, DP_MOD_ID_NSS_OFFLOAD);

    if (!vdev_handle)
        return;

    wifivdevcfg->vdev_id = vdev_id;
    wifivdevcfg->opmode = vdev_handle->opmode;
    memcpy(wifivdevcfg->mac_addr,  &vdev_handle->mac_addr.raw[0], 6);
    dp_vdev_unref_delete(soc, vdev_handle, DP_MOD_ID_NSS_OFFLOAD);
    return;
}

void osif_nss_wifili_get_peerid( struct MC_LIST_UPDATE* list_entry, uint32_t *peer_id)
{
    struct dp_peer *peer = NULL;
    struct ieee80211_node   *ni;
    struct ol_ath_softc_net80211 *scn;

    if (!list_entry)
        return;

    ni = list_entry->ni;

    if (!ni)
        return;

    scn = OL_ATH_SOFTC_NET80211(ni->ni_ic);

    peer = dp_peer_find_hash_find(wlan_psoc_get_dp_handle(scn->soc->psoc_obj),
                                  ni->ni_macaddr, 0, wlan_vdev_get_id(ni->ni_vap->vdev_obj),
				  DP_MOD_ID_NSS_OFFLOAD);
    if (!peer)
        return;

    *peer_id = peer->peer_id;

    dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
    return;
}

uint8_t osif_nss_wifili_get_vdevid_fromvdev(void *vdev, uint8_t *vdev_id)
{
    struct dp_vdev *vdev_handle = (struct dp_vdev *)vdev;
    if (!vdev_handle)
        return 0;

    *vdev_id = vdev_handle->vdev_id;
    return 1;
}

bool osif_nss_wifili_check_valid_vdev_for_id(struct cdp_soc_t *soc_hdl, uint8_t vdev_id)
{
    struct dp_soc *soc = cdp_soc_t_to_dp_soc(soc_hdl);
    struct dp_vdev *vdev = dp_vdev_get_ref_by_id(soc, vdev_id, DP_MOD_ID_NSS_OFFLOAD);
    if (vdev) {
        dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
        return true;
    }
    return false;
}

uint8_t osif_nss_wifili_get_vdevid_fromosif(osif_dev *osifp, uint8_t *vdev_id)
{
    *vdev_id = wlan_vdev_get_id(osifp->ctrl_vdev);

    return 1;
}

/*
 * osif_nss_ol_peerid_find_hash_find()
 * 	Get the peer_id using the hash index.
 */
uint32_t osif_nss_wifili_peerid_find_hash_find(struct ieee80211vap *vap, uint8_t *peer_mac_addr, int mac_addr_is_aligned)
{

    uint32_t peer_id = 0;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT_LI
    struct dp_peer *peer = NULL;

    peer = dp_peer_find_hash_find(osif_nss_ol_li_dp_soc_from_vap(vap),
                                  peer_mac_addr, mac_addr_is_aligned, wlan_vdev_get_id(vap->vdev_obj),
				  DP_MOD_ID_NSS_OFFLOAD);

    if (!(peer)) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_WARN,
                 "[nss-wifili]: %s, peer = %pK", __FUNCTION__, peer);
        return HTT_INVALID_PEER;
    }
    peer_id = peer->local_id;
    dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
#endif

    return peer_id;
}

void
osif_nss_wifili_rsim_rx_decap(os_if_t osif, qdf_nbuf_t *pdeliver_list_head, qdf_nbuf_t *pdeliver_list_tail, uint8_t *peer_mac)
{
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    wlan_rawsim_api_rx_decap(osif, pdeliver_list_head, pdeliver_list_tail, peer_mac);
#endif
}

uint8_t osif_nss_wifili_get_peer_mac_by_id(osif_dev *osifp, uint32_t peer_id, uint8_t *peer_mac)
{
    struct dp_peer *peer = NULL;

    peer = dp_peer_get_ref_by_id(osif_nss_ol_li_dp_soc_from_vap(osifp->os_if), peer_id,
                               DP_MOD_ID_NSS_OFFLOAD);

    if (peer) {
        qdf_mem_copy(peer_mac, peer->mac_addr.raw, QDF_MAC_ADDR_SIZE);
        dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
        return 1;
    }

    return 0;
}

uint8_t osif_nss_wifili_find_pstosif_by_id(struct net_device *netdev, uint32_t peer_id, osif_dev **psta_osifp)
{
    struct dp_vdev *pstavdev = NULL;
    struct dp_peer *pstapeer;
    osif_dev  *osifp = ath_netdev_priv(netdev);

    pstapeer = dp_peer_get_ref_by_id(osif_nss_ol_li_dp_soc_from_vap(osifp->os_if), peer_id, DP_MOD_ID_NSS_OFFLOAD);
    if (!pstapeer) {
        qdf_print("no peer available free packet ");
        return 0;
    }
    pstavdev = pstapeer->vdev;
    dp_peer_unref_delete(pstapeer, DP_MOD_ID_NSS_OFFLOAD);
    if (!pstavdev) {
        qdf_print("no vdev available free packet ");
        return 0;
    }
    *psta_osifp = (osif_dev *)pstavdev->osif_vdev;
    return 1;
}

/*
 * osif_nss_wifili_vap_updchdhdr()
 *	API for updating header cache in NSS.
 */
/*
 * Note: This function has been created seperately for 8064
 * and 8074 as there is no element called "hdrcache" in dp_vdev
 * (vdev->hdrcache). And this function might not be required
 * for 8074, so this is a dummy function here.
 */
int32_t osif_nss_wifili_vap_updchdhdr(osif_dev *osifp)
{
    return 0;
}

/*
 * osif_nss_wifili_vdev_set_cfg
 */
uint32_t osif_nss_wifili_vdev_set_cfg(osif_dev *osifp, enum osif_nss_vdev_cmd osif_cmd)
{
    uint32_t val = 0;
    enum nss_wifi_vdev_cmd cmd = 0;
    struct dp_vdev *vdev = NULL;

    if (!osifp) {
        return 0;
    }

    if (!NSS_IF_IS_TYPE_DYNAMIC(osifp->nss_ifnum)) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                  " vap transmit called on invalid interface");
        return 0;
    }

    vdev = dp_vdev_get_ref_by_id(osif_nss_ol_li_dp_soc_from_vap(osifp->os_if),
                              wlan_vdev_get_id(osifp->ctrl_vdev),
                              DP_MOD_ID_NSS_OFFLOAD);

    if (!vdev) {
        qdf_print("DP vdev handler is NULL");
	return 0;
    }

    switch (osif_cmd) {
        case OSIF_NSS_VDEV_DROP_UNENC:
            cmd = NSS_WIFI_VDEV_DROP_UNENC_CMD;
            val = vdev->drop_unenc;
            break;

        case OSIF_NSS_WIFI_VDEV_NAWDS_MODE:
            cmd = NSS_WIFI_VDEV_NAWDS_MODE_CMD;
            val = vdev->nawds_enabled;
            break;

#ifdef WDS_VENDOR_EXTENSION
        case OSIF_NSS_WIFI_VDEV_WDS_EXT_ENABLE:
            cmd = NSS_WIFI_VDEV_CFG_WDS_EXT_ENABLE_CMD;
            val = WDS_EXT_ENABLE;
            break;
#endif

        case OSIF_NSS_VDEV_WDS_CFG:
            cmd = NSS_WIFI_VDEV_CFG_WDS_CMD;
            val = vdev->wds_enabled;
            break;

        case OSIF_NSS_VDEV_AP_BRIDGE_CFG:
            cmd = NSS_WIFI_VDEV_CFG_AP_BRIDGE_CMD;
            val = vdev->ap_bridge_enabled;
            break;

        case OSIF_NSS_VDEV_SECURITY_TYPE_CFG:
            cmd = NSS_WIFI_VDEV_SECURITY_TYPE_CMD;
            val = vdev->sec_type;
            break;

        case OSIF_NSS_WIFI_VDEV_ENABLE_HLOS_TID_OVERRIDE:
            cmd = NSS_WIFI_VDEV_CFG_HLOS_TID_OVERRIDE_CMD;
            val = !!(vdev->skip_sw_tid_classification & DP_TXRX_HLOS_TID_OVERRIDE_ENABLED);
            break;

#ifdef QCA_SUPPORT_WDS_EXTENDED
        case OSIF_NSS_WIFI_VDEV_WDS_BACKHAUL_CFG:
            cmd = NSS_WIFI_VDEV_CFG_WDS_BACKHAUL_CMD;
            val = vdev->wds_ext_enabled;
            break;
#endif /* QCA_SUPPORT_WDS_EXTENDED */

        default:
            break;
    }

    dp_vdev_unref_delete(osif_nss_ol_li_dp_soc_from_vap(osifp->os_if), vdev, DP_MOD_ID_NSS_OFFLOAD);
    return val;
}

/*
 * osif_nss_wifili_vdev_get_stats
 *
 * Note: dp_pdev structure stats structure is different from "ol_txrx_stats"
 * structure in ol_txrx_pdev_t.
 * Also one-to-one mapping for 8074 could not be found so this is a dummy
 * function for 8074
 */
uint8_t osif_nss_wifili_vdev_get_stats(osif_dev *osifp, struct nss_cmn_msg *wifivdevmsg)
{
    wlan_if_t vap;
    struct nss_wifi_vdev_stats_sync_msg *stats =
    (struct nss_wifi_vdev_stats_sync_msg *)&((struct nss_wifi_vdev_msg *)wifivdevmsg)->msg.vdev_stats;
    struct ieee80211_mac_stats *unimacstats ;
    struct nss_wifi_vdev_mcast_enhance_stats *nss_mestats = NULL;
    struct ol_ath_softc_net80211 *av_sc = NULL;
    struct dp_vdev *vdev = NULL;
    struct dp_pdev *pdev = NULL;
    struct cdp_tx_ingress_stats *txi_stats = NULL;
    struct cdp_tx_stats *tx_stats = NULL;
    struct cdp_rx_stats *rx_stats = NULL;
    uint8_t pdev_id;
    struct dp_soc *soc;

    if (!osifp) {
        return 0;
    }

    vap = osifp->os_if;
    if (!vap) {
        return 0;
    }

    av_sc = osif_nss_ol_get_scn_from_vap(vap);
    pdev_id = wlan_objmgr_pdev_get_pdev_id(osif_nss_ol_get_objmgr_pdev_from_scn(av_sc));
    soc = osif_nss_ol_li_dp_soc_from_scn(av_sc);
    pdev = dp_get_pdev_from_soc_pdev_id_wifi3(soc, pdev_id);
    vdev = dp_vdev_get_ref_by_id(soc, wlan_vdev_get_id(osifp->ctrl_vdev), DP_MOD_ID_NSS_OFFLOAD);

    if (!vdev || !pdev) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_ERROR,
                 "[nss-wifili]: %s, pdev = %pK, vdev = %pK", __FUNCTION__, pdev, vdev);
        if(vdev)
            dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
        return 0;
    }

    nss_mestats = &stats->wvmes;
    txi_stats = &vdev->stats.tx_i;
    tx_stats = &vdev->stats.tx;
    rx_stats = &vdev->stats.rx;

    txi_stats->mcast_en.mcast_pkt.num += nss_mestats->mcast_rcvd;
    txi_stats->mcast_en.mcast_pkt.bytes += nss_mestats->mcast_rcvd_bytes;
    txi_stats->mcast_en.ucast += nss_mestats->mcast_ucast_converted;
    txi_stats->mcast_en.fail_seg_alloc += nss_mestats->mcast_alloc_fail;
    txi_stats->mcast_en.dropped_send_fail += (nss_mestats->mcast_pbuf_enq_fail +
            nss_mestats->mcast_pbuf_copy_fail + nss_mestats->mcast_peer_flow_ctrl_send_fail);
    txi_stats->mcast_en.dropped_self_mac += (nss_mestats->mcast_loopback_err +
            nss_mestats->mcast_dst_address_err + nss_mestats->mcast_no_enhance_drop_cnt);

    txi_stats->igmp_mcast_en.igmp_rcvd += nss_mestats->igmp_rcvd;
    txi_stats->igmp_mcast_en.igmp_ucast_converted += nss_mestats->igmp_ucast_converted;

    txi_stats->rcvd.num += stats->tx_rcvd;
    txi_stats->rcvd.bytes += stats->tx_rcvd_bytes;
    txi_stats->processed.num += stats->tx_enqueue_cnt;
    txi_stats->processed.bytes += stats->tx_enqueue_bytes;
    txi_stats->dropped.ring_full += stats->tx_hw_ring_full;
    txi_stats->dropped.desc_na.num += stats->tx_desc_alloc_fail;
    txi_stats->dropped.dma_error += stats->tx_dma_map_fail;
    txi_stats->tso_stats.num_tso_pkts.num += stats->tx_tso_pkt;
    txi_stats->cce_classified += stats->cce_classified;
    txi_stats->cce_classified_raw += stats->cce_classified_raw;
    txi_stats->nawds_mcast.num += stats->nawds_tx_mcast_cnt;
    txi_stats->nawds_mcast.bytes += stats->nawds_tx_mcast_bytes;
    txi_stats->dropped.fail_per_pkt_vdev_id_check += stats->per_pkt_vdev_check_fail;

    if (qdf_unlikely(vdev->tx_encap_type == htt_cmn_pkt_type_raw)) {
        txi_stats->raw.raw_pkt.num += stats->tx_rcvd;
        txi_stats->raw.raw_pkt.bytes += stats->tx_rcvd_bytes;
    }

    if (osifp->is_delete_in_progress || (vap->iv_opmode == IEEE80211_M_MONITOR)) {
        dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
        return 0;
    }

    unimacstats = &vap->iv_unicast_stats;
    unimacstats->ims_tx_eapol_packets += stats->tx_eapol_cnt;

    if (!pdev->enhanced_stats_en) {
        /*
         * Update net device statistics
         */
        rx_stats->to_stack.num += (stats->rx_enqueue_cnt + stats->rx_except_enqueue_cnt);
        rx_stats->to_stack.bytes += stats->rx_enqueue_bytes;
        rx_stats->multicast.num += stats->rx_mcast_cnt;
        rx_stats->multicast.bytes += stats->rx_mcast_bytes;
        rx_stats->unicast.num = rx_stats->to_stack.num - rx_stats->multicast.num;
        rx_stats->unicast.bytes = rx_stats->to_stack.bytes - rx_stats->multicast.bytes;
        rx_stats->rx_discard += (stats->rx_enqueue_fail_cnt + stats->rx_except_enqueue_fail_cnt);
        rx_stats->err.decrypt_err += stats->rx_decrypt_err;
        rx_stats->err.mic_err += stats->rx_mic_err;

        tx_stats->comp_pkt.num += (stats->tx_enqueue_cnt + stats->tx_intra_bss_enqueue_cnt);
        tx_stats->comp_pkt.bytes += stats->tx_enqueue_bytes;
        tx_stats->mcast.num += stats->tx_intra_bss_mcast_send_cnt;
        tx_stats->tx_failed += (stats->tx_enqueue_fail_cnt + stats->tx_intra_bss_enqueue_fail_cnt +
                stats->tx_intra_bss_mcast_send_fail_cnt);
        txi_stats->dropped.dropped_pkt.num = txi_stats->dropped.desc_na.num + txi_stats->dropped.ring_full +
            txi_stats->dropped.dma_error + tx_stats->tx_failed;

    }

    dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
    return 1;
}

#if ATH_SUPPORT_WRAP
/*
 * osif_nss_wifili_vdev_get_mpsta_vdevid
 */
uint8_t osif_nss_wifili_vdev_get_mpsta_vdevid(ol_ath_soc_softc_t *soc, uint16_t peer_id, uint8_t vdev_id, uint8_t *mpsta_vdev_id)
{
    struct ieee80211vap *mpsta_vap = NULL;
    osif_dev  *mpsta_osdev = NULL;
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_vdev *vdev = NULL;
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;

    if (!psoc) {
        qdf_print("Get MPSTA: psoc is NULL");
        return 0;
    }

    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id, WLAN_MLME_SB_ID);
    if (!vdev) {
        qdf_print("Get MPSTA: vdev is NULL");
        return 0;
    }

    vap = wlan_vdev_get_vap(vdev);
    if (!vap) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
        qdf_print("Get MPSTA: vap is NULL");
        return 0;
    }

    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
    /*
     * Vap is psta and not mpsta
     */
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (!vap->iv_mpsta && vap->iv_psta) {
        mpsta_vap = vap->iv_ic->ic_mpsta_vap;
#else
    if (!dp_wrap_vdev_is_mpsta(vap->vdev_obj) && dp_wrap_vdev_is_psta(vap->vdev_obj)) {
        mpsta_vap = wlan_get_vap(dp_wrap_get_mpsta_vdev(vap->iv_ic->ic_pdev_obj));
#endif
#endif
        if (!mpsta_vap) {
            qdf_print("Get MPSTA: mpsta_vap is NULL");
            return 0;
        }
    } else {
        return 0;
    }

    mpsta_osdev = (osif_dev *)mpsta_vap->iv_ifp;
    if (!mpsta_osdev) {
        qdf_print("Get MPSTA: mpsta_osdev is NULL");
        return 0;
    }

    return osif_nss_wifili_get_vdevid_fromosif(mpsta_osdev, mpsta_vdev_id);
}

/*
 * osif_nss_ol_li_vdev_qwrap_mec_check
 */
uint8_t osif_nss_ol_li_vdev_qwrap_mec_check(osif_dev *mpsta_osifp, struct sk_buff *skb)
{
    struct dp_soc *soc = NULL;
    struct ether_header *eh = NULL;
    uint8_t src_mac[QDF_MAC_ADDR_SIZE];
    struct dp_vdev *vdev = NULL;
    osif_dev *psta_osdev = NULL;
    struct ieee80211vap *mpsta_vap = NULL;
#if !WLAN_QWRAP_LEGACY
    struct wlan_objmgr_vdev *psta_vdev = NULL;
#endif

    if (!mpsta_osifp) {
        return 0;
    }

    mpsta_vap = mpsta_osifp->os_if;
    if (!mpsta_vap) {
        return 0;
    }

    /*
     * If Qwrap Isolation Mode is enabled, the mec check is not
     * required.
     */
#if WLAN_QWRAP_LEGACY
    if (mpsta_vap->iv_ic->ic_wrap_com->wc_isolation) {
        return 0;
    }
#else
    if (dp_wrap_pdev_get_isolation(wlan_vdev_get_pdev(mpsta_vap->vdev_obj))) {
        return 0;
    }
#endif

    eh = (struct ether_header *)(skb->data);
    memcpy(src_mac, (uint8_t *)eh->ether_shost, QDF_MAC_ADDR_SIZE);

    /* Mpsta vap here, find the correct vap from the wrap common based on src address */
#if WLAN_QWRAP_LEGACY
    psta_osdev = osif_wrap_wdev_vma_find(&mpsta_vap->iv_ic->ic_wrap_com->wc_devt, src_mac);
#else
    psta_vdev = dp_wrap_vdev_vma_find(wlan_vdev_get_pdev(mpsta_vap->vdev_obj), src_mac);
    if (!psta_vdev) {
        return 0;
    }
    psta_osdev = wlan_get_osdev(psta_vdev);
#endif
    if (!psta_osdev) {
        return 0;
    }

    soc = osif_nss_ol_li_dp_soc_from_vap(psta_osdev->os_if);
    vdev = dp_vdev_get_ref_by_id(soc,
                        wlan_vdev_get_id(psta_osdev->ctrl_vdev), DP_MOD_ID_NSS_OFFLOAD);

    if (!vdev) {
        return 0;
    }

    if (!(memcmp(src_mac, vdev->mac_addr.raw, QDF_MAC_ADDR_SIZE))) {
        dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
        return 1;
    }

    dp_vdev_unref_delete(soc, vdev, DP_MOD_ID_NSS_OFFLOAD);
    return 0;
}

uint8_t osif_nss_ol_li_vdev_get_nss_qwrap_en(struct ieee80211vap *vap)
{
    return vap->iv_nss_qwrap_en;
}

#endif

/*
 * osif_nss_ol_li_vdev_data_receive_mec_check()
 *  In STA mode, Pass/Drop frame based on ast entry of type MEC
 */
bool osif_nss_ol_li_vdev_data_receive_mec_check(osif_dev *osdev, struct sk_buff *nbuf)
{
    struct dp_pdev *pdev = NULL;
    struct ol_ath_softc_net80211 *av_sc;
    struct dp_soc *soc = NULL;
    uint8_t src_mac_addr[QDF_MAC_ADDR_SIZE];
    bool status = false;
    uint8_t pdev_id;

    av_sc = osif_nss_ol_get_scn_from_vap(osdev->os_if);
    pdev_id = wlan_objmgr_pdev_get_pdev_id(osif_nss_ol_get_objmgr_pdev_from_scn(av_sc));
    soc = osif_nss_ol_li_dp_soc_from_scn(av_sc);
    pdev = dp_get_pdev_from_soc_pdev_id_wifi3(soc, pdev_id);

    if (!pdev) {
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
                  "pdev NULL for pdev_id = %d", pdev_id);
        return status;
    }

    memcpy(src_mac_addr, (qdf_nbuf_data(nbuf) + QDF_MAC_ADDR_SIZE),
            QDF_MAC_ADDR_SIZE);

    qdf_spin_lock_bh(&soc->mec_lock);

    if (dp_peer_mec_hash_find_by_pdevid(soc, pdev_id, src_mac_addr)) {
        status = true;
    }

    qdf_spin_unlock_bh(&soc->mec_lock);
    return status;
}

#ifdef QCA_SUPPORT_WDS_EXTENDED
/*
 * osif_nss_wifili_ext_vdev_rx()
 *	Function handler from parent VAP's handler. Return true if buffer is consumed
 */
bool osif_nss_wifili_ext_vdev_rx(osif_dev *osdev, struct sk_buff *nbuf, struct napi_struct *napi)
{
    uint8_t wds_src_mac[QDF_MAC_ADDR_SIZE];
    struct dp_ast_entry *ast_entry = NULL;
    struct dp_soc *soc = NULL;
    struct dp_pdev *pdev = NULL;
    struct dp_peer *peer = NULL;
    struct dp_vdev *vdev = NULL;
    struct ol_ath_softc_net80211 *av_sc;
    uint16_t peer_id;
    osif_peer_dev *osifp;
    struct net_device *netdev;
    uint8_t pdev_id;

    av_sc = osif_nss_ol_get_scn_from_vap(osdev->os_if);
    pdev_id = wlan_objmgr_pdev_get_pdev_id(osif_nss_ol_get_objmgr_pdev_from_scn(av_sc));
    soc = osif_nss_ol_li_dp_soc_from_scn(av_sc);
    pdev = dp_get_pdev_from_soc_pdev_id_wifi3(soc, pdev_id);

    if (!pdev) {
        QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_ERROR,
                  "pdev NULL for pdev_id = %d", pdev_id);
        return false;
    }

    memcpy(wds_src_mac, (qdf_nbuf_data(nbuf) + QDF_MAC_ADDR_SIZE),
            QDF_MAC_ADDR_SIZE);

    qdf_spin_lock_bh(&soc->ast_lock);
    ast_entry = dp_peer_ast_hash_find_soc(soc, wds_src_mac);
    if (qdf_unlikely(!ast_entry)) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
             "[nss-wifili]: could not find ast_entry with mac %pM", wds_src_mac);
	qdf_spin_unlock_bh(&soc->ast_lock);
        return false;
    }
    qdf_spin_unlock_bh(&soc->ast_lock);

    peer_id = ast_entry->peer_id;
    peer = dp_peer_get_ref_by_id(soc, peer_id, DP_MOD_ID_NSS_OFFLOAD);
    if (!peer) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
                "[nss-wifili]: peer is null");
        return false;
    }

    vdev = peer->vdev;
    if (qdf_likely(!vdev->wds_ext_enabled)) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
                "[nss-wifili]: wds ext not enabled vdev_id(%d)", vdev->vdev_id);
        dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
        return false;
    }

    if (!peer->wds_ext.init) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
                "[nss-wifili]:peer wds is not initialized on peer_id(%d)", peer_id);
        dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
        return false;
    }

     if (!peer->wds_ext.osif_peer) {
        QDF_TRACE(QDF_MODULE_ID_NSS, QDF_TRACE_LEVEL_INFO,
                "[nss-wifili]:peer wds osif vap is null");
        dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);
        goto free_nbuf;
    }

    osifp = (osif_peer_dev *)peer->wds_ext.osif_peer;
    dp_peer_unref_delete(peer, DP_MOD_ID_NSS_OFFLOAD);

    netdev = osifp->netdev;
    dev_hold(netdev);
    nbuf->dev = netdev;
    nbuf->protocol = eth_type_trans(nbuf, netdev);

    nbuf_debug_del_record(nbuf);
    napi_gro_receive(napi, nbuf);
    dev_put(netdev);

    return true;

free_nbuf:
    qdf_nbuf_free(nbuf);
    return true;
}
#endif /* QCA_SUPPORT_WDS_EXTENDED */

/*
 * osif_nss_li_vdev_prepare_wifi_mac_db()
 *  Prepare Wi-Fi MAC database before DBDC is enabled.
 */
bool osif_nss_li_vdev_prepare_wifi_mac_db(osif_dev *osifp)
{
    struct net_device *netdev = OSIF_TO_NETDEV(osifp);

    /*
     * Initialize nss wifi mac address table before enabling DBDC.
     */
    if (!osif_nss_wifi_mac_db_init(netdev)) {
	    qdf_warn("\nCould not initialize qca multi link for NSS");
	    return false;
    }

    return true;
}

/*
 * osif_nss_li_vdev_wifi_mac_db_pool_entries_send()
 *  Send Wi-Fi MAC database pool entries to NSS FW.
 */
bool osif_nss_li_vdev_wifi_mac_db_pool_entries_send(osif_dev *osifp)
{
    struct net_device *netdev = OSIF_TO_NETDEV(osifp);
    /*
     * Send nss wifi mac database pool of entries to nss fw before enabling DBDC.
     */
    osif_nss_wifi_mac_db_pool_entries_send(netdev);
    return true;
}

/*
 * osif_nss_li_vdev_wifi_mac_db_is_ready()
 *  Check if Wi-Fi MAC database is ready for DBDC enable
 */
bool osif_nss_li_vdev_wifi_mac_db_is_ready(osif_dev *osifp)
{
    return osif_nss_wifi_mac_db_is_ready();
}

/*
 * osif_nss_li_vdev_wifi_mac_db_reset_state()
 *  Reset the entries send state anc collect entries in pool.
 */
bool osif_nss_li_vdev_wifi_mac_db_reset_state(osif_dev *osifp)
{
    return osif_nss_wifi_mac_db_reset_state();
}
