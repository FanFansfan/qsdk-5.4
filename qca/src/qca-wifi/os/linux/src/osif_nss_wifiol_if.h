/*
 * Copyright (c) 2015-2016,2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2015-2016 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __OSIF_NSS_WIFIOL_IF_H
#define __OSIF_NSS_WIFIOL_IF_H
#include <nss_api_if.h>
#include <ol_if_athvar.h>

extern struct nss_wifi_soc_ops nss_wifili_soc_ops;

#define OSIF_NSS_WIFI_CFG_TIMEOUT_MS 1000
#define OSIF_NSS_WIFI_INIT_TIMEOUT_MS 5000
#define OSIF_NSS_WIFI_PDEV_INIT_TIMEOUT_MS 5000
#define OSIF_NSS_WIFI_SOC_START_TIMEOUT_MS 5000
#define OSIF_NSS_WIFI_SOC_STOP_TIMEOUT_MS 5000
#define OSIF_NSS_WIFI_SOC_RESTART_TIMEOUT_MS 5000
#define OSIF_NSS_WIFI_PEER_SECURITY_TIMEOUT_MS 5000


#define OSIF_NSS_OL_MAX_PEER_POOLS 8
#define OSIF_NSS_OL_MAX_RRA_POOLS 8
#define OSIF_NSS_OL_MAX_RETRY_CNT 16
enum osif_nss_wifi_cmd {
    OSIF_NSS_WIFI_FILTER_NEIGH_PEERS_CMD,
    OSIF_NSS_WIFI_MAX
};

struct ol_ath_nss_del_wds_entry {
        void *scn;
        uint8_t dest_mac[6];
        uint8_t peer_mac[6];
        qdf_work_t wds_del_work;
        uint8_t ast_type;
        uint8_t pdev_id;
};

struct nss_wifi_soc_ops {
    void (*nss_soc_wifi_peer_delete)(ol_ath_soc_softc_t *soc, uint16_t peer_id, uint8_t vdev_id);
    void (*nss_soc_wifi_peer_create)(ol_ath_soc_softc_t *soc, uint16_t peer_id,
            uint16_t hw_peer_id, uint8_t vdev_id, uint8_t *peer_mac_addr, uint32_t tx_ast_hash);
    int  (*nss_soc_wifi_init)(ol_ath_soc_softc_t *soc);
    void (*nss_soc_ce_post_recv_buffer)(ol_ath_soc_softc_t *soc);
    int (*nss_soc_ce_flush)(ol_ath_soc_softc_t *soc);
    void (*nss_soc_wifi_set_cfg)(ol_ath_soc_softc_t *soc, uint32_t wifili_cfg);
    int  (*nss_soc_wifi_detach)(ol_ath_soc_softc_t *soc, uint32_t delay);
    int  (*nss_soc_wifi_attach)(ol_ath_soc_softc_t *soc);
    int (*nss_soc_map_wds_peer)(ol_ath_soc_softc_t *soc, uint16_t peer_id, uint16_t hw_ast_idx, uint8_t vdev_id, uint8_t *peer_mac);
    int  (*nss_soc_wifi_stop)(ol_ath_soc_softc_t *soc);
    void (*nss_soc_nawds_enable)(ol_ath_soc_softc_t *soc, uint8_t *peer_mac, uint16_t vdev_id, uint16_t is_nawds);
    int (*nss_soc_wifi_set_default_nexthop)(ol_ath_soc_softc_t *soc);
    void (*nss_soc_desc_pool_free)(ol_ath_soc_softc_t *soc);
    void (*nss_soc_wifi_peer_ast_flowid_map)(ol_ath_soc_softc_t *soc, uint16_t peer_id,
            uint8_t vdev_id, uint8_t *peer_mac_addr);
    QDF_STATUS (*nss_soc_peer_update_auth_flag)(struct ol_ath_softc_net80211 *scn, uint8_t *peer_mac, uint8_t vdev_id, uint32_t auth_flag);

};

struct nss_wifi_radio_ops {
#ifdef WDS_VENDOR_EXTENSION
    int  (*ic_nss_ol_wds_extn_peer_cfg_send)(struct ol_ath_softc_net80211 *scn, uint8_t *peer_mac, uint8_t vdev_id);
#endif
    void (*ic_nss_ol_set_primary_radio)(struct ol_ath_softc_net80211 *scn , uint32_t enable);

    void (*ic_nss_ol_set_always_primary)(struct ieee80211com* ic, bool enable);

    void (*ic_nss_ol_set_force_client_mcast_traffic)(struct ieee80211com* ic, bool enable);

    void (*ic_nss_ol_set_perpkt_txstats)(struct ol_ath_softc_net80211 *scn);

    void (*ic_nss_ol_set_igmpmld_override_tos)(struct ol_ath_softc_net80211 *scn);

    int  (*ic_nss_ol_stats_cfg)(struct ol_ath_softc_net80211 *scn, uint32_t cfg);

    void (*ic_nss_ol_enable_ol_statsv2)(struct ol_ath_softc_net80211 *scn, uint32_t value);

    int  (*ic_nss_ol_pktlog_cfg)(struct ol_ath_softc_net80211 *scn, int enable);

    int  (*ic_nss_tx_queue_cfg)(struct ol_ath_softc_net80211 *scn, uint32_t range, uint32_t buf_size);

    int  (*ic_nss_tx_queue_min_threshold_cfg)(struct ol_ath_softc_net80211 *scn, uint32_t min_threshold);

    int  (*ic_nss_ol_wifi_tx_capture_set)(struct ol_ath_softc_net80211 *scn, uint8_t tx_capture_enable);

    int  (*ic_nss_ol_pdev_add_wds_peer)(struct ol_ath_softc_net80211 *scn, uint8_t vdev_id, uint8_t *peer_mac, uint16_t peer_id, uint8_t *dest_mac, uint8_t *next_node_mac, uint8_t ast_type);

    int  (*ic_nss_ol_pdev_del_wds_peer)(struct ol_ath_softc_net80211 *scn, uint8_t *peer_mac, uint8_t *dest_mac, uint8_t ast_type, uint8_t pdev_id);
    void (*ic_nss_ol_enable_dbdc_process)(struct ieee80211com* ic, uint32_t enable);
    void (*ic_nss_set_cmd)(struct ol_ath_softc_net80211 *scn, enum osif_nss_wifi_cmd osif_cmd);
    void (*ic_nss_ol_read_pkt_prehdr)(struct ol_ath_softc_net80211 *scn, struct sk_buff *nbuf);
    void (*ic_nss_ol_set_drop_secondary_mcast)(struct ieee80211com* ic, bool enable);
    int (*ic_nss_ol_set_peer_sec_type)(struct ol_ath_softc_net80211 *scn, uint8_t *peer_mac, uint8_t vdev_id,
                                           uint8_t pkt_type, uint8_t cipher_type, uint8_t mic_key[]);
    void (*ic_nss_ol_set_hmmc_dscp_override)(struct ol_ath_softc_net80211 *scn, uint8_t value);
    void (*ic_nss_ol_set_hmmc_dscp_tid)(struct ol_ath_softc_net80211 *scn, uint8_t tid);
    int (*ic_nss_ol_enable_v3_stats)(struct ol_ath_softc_net80211 *scn, uint32_t value);
    int  (*ic_nss_ol_pdev_update_wds_peer)(struct ol_ath_softc_net80211 *scn, uint8_t *peer_mac,
                                            uint8_t *dest_mac, uint8_t pdev_id);
    int (*ic_nss_ol_peer_set_vlan_id)(struct ol_ath_softc_net80211 *scn, uint8_t vdev_id,
                                      uint8_t *mac_addr, uint16_t vlan_id);
    void (*ic_nss_ol_set_dbdc_fast_lane)(struct ieee80211com* ic, bool enable);
    int (*ic_nss_ol_pdev_update_lmac_n_target_pdev_id)(struct ol_ath_softc_net80211 *scn, uint8_t *pdev_id, uint8_t *lmac_id, uint8_t *target_pdev_id);
    QDF_STATUS (*ic_nss_ol_set_peer_isolation)(struct ol_ath_softc_net80211 *scn, uint8_t *mac_addr,
            uint8_t vdev_id, uint8_t value);
    QDF_STATUS (*ic_nss_ol_nss_stats_clr)(struct ol_ath_softc_net80211 *scn, uint8_t vdev_id);
#ifdef QCA_SUPPORT_WDS_EXTENDED
    QDF_STATUS (*ic_osif_nss_wifili_peer_set_4addr_cfg)(struct ol_ath_softc_net80211 *scn, uint8_t *mac, uint8_t vdev_id, nss_if_num_t if_num);
#endif /* QCA_SUPPORT_WDS_EXTENDED */
    void (*ic_nss_ol_set_dbdc_no_backhaul_radio)(struct ieee80211com* ic, bool enable);
};


void osif_nss_wifi_soc_setup(ol_ath_soc_softc_t *soc);
void osif_nss_br_fdb_notifier_register(void);
void osif_nss_br_fdb_update_notifier_register(void);
bool osif_nss_wifi_mac_db_init(struct net_device *netdev);
bool osif_nss_wifi_mac_db_pool_entries_send(struct net_device *netdev);
bool osif_nss_wifi_mac_db_is_ready(void);
bool osif_nss_wifi_mac_db_reset_state(void);

static inline struct ol_ath_softc_net80211 *
osif_nss_ol_get_scn_from_vap(struct ieee80211vap *vap)
{
    return (OL_ATH_SOFTC_NET80211((vap->iv_ic)));
}

static inline struct ol_ath_softc_net80211 *
osif_nss_ol_get_scn_from_netdev(struct net_device *dev)
{
    return osif_nss_ol_get_scn_from_vap(((osif_dev *)ath_netdev_priv(dev))->os_if);
}

static inline struct wlan_objmgr_pdev *
osif_nss_ol_get_objmgr_pdev_from_scn(struct ol_ath_softc_net80211 *scn)
{
    return scn->sc_ic.ic_pdev_obj;
}

static inline struct wlan_objmgr_pdev *
osif_nss_ol_get_objmgr_pdev_from_vap(struct ieee80211vap *vap)
{
    return osif_nss_ol_get_objmgr_pdev_from_scn(osif_nss_ol_get_scn_from_vap(vap));
}

#endif
