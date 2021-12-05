/*
 * Copyright (c) 2019-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#ifndef __WLAN_MLME_VDEV_MGMT_OPS_H__
#define __WLAN_MLME_VDEV_MGMT_OPS_H__

#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_mlme.h>
#include <ieee80211_target.h>
#include <ieee80211_rateset.h>
#include <ieee80211_wds.h>
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif
#include <wlan_mlme_dp_dispatcher.h>
#include <wlan_vdev_mgr_tgt_if_rx_defs.h>
#include <wlan_cmn.h>

enum mlme_sta_clean_mode {
   MLME_REPEATER_PEER_CLEANUP = 0x1,
   MLME_INDIVIDUAL_PEER_CLEANUP = 0x2,
   MLME_MULTIPLE_PEER_CLEANUP = 0x3
};

QDF_STATUS
vdev_mlme_set_param(struct vdev_mlme_obj *vdev_mlme,
                    enum wlan_mlme_cfg_id param_id,
                    struct wlan_vdev_mgr_cfg mlme_cfg);

enum ieee80211_opmode ieee80211_new_opmode(struct ieee80211vap *vap, bool vap_active);

struct ieee80211vap
*mlme_ext_vap_create(struct ieee80211com *ic,
                     struct vdev_mlme_obj *vdev_mlme,
                     enum ieee80211_opmode opmode,
                     int                 scan_priority_base,
                     u_int32_t           flags,
                     const u_int8_t      bssid[QDF_MAC_ADDR_SIZE],
                     const u_int8_t      mataddr[QDF_MAC_ADDR_SIZE]);

QDF_STATUS mlme_ext_vap_delete(struct ieee80211vap *vap);

QDF_STATUS mlme_ext_vap_recover(struct ieee80211vap *vap);

QDF_STATUS mlme_ext_vap_recover_init(struct wlan_objmgr_vdev *vdev);

QDF_STATUS mlme_ext_vap_stop(struct wlan_objmgr_vdev *vdev);

QDF_STATUS mlme_ext_vap_up(struct ieee80211vap *, bool);

void mlme_ext_vap_beacon_stop(struct ieee80211vap *vap);

void mlme_ext_vap_defer_beacon_buf_free(struct ieee80211vap *vap);

QDF_STATUS mlme_ext_vap_down(struct wlan_objmgr_vdev *vdev);

int
mlme_ext_vap_start_response_event_handler(struct vdev_start_response *rsp,
                                          struct vdev_mlme_obj *vdev_mlme);

QDF_STATUS mlme_ext_vap_start(struct wlan_objmgr_vdev *vdev,
                              u_int8_t restart);

void mlme_ext_vap_flush_bss_peer_tids(struct ieee80211vap *vap);

QDF_STATUS mlme_ext_multi_vdev_restart(
                                    struct ieee80211com *ic,
                                    uint32_t *vdev_ids, uint32_t num_vdevs,
                                    struct vdev_mlme_mvr_param *mvr_param);

int mlme_ext_update_channel_param(struct mlme_channel_param *ch_param,
                                  struct ieee80211com *ic);

void mlme_ext_update_multi_vdev_restart_param(struct ieee80211com *ic,
                                              uint32_t *vdev_ids,
                                              uint32_t num_vdevs,
                                              bool reset,
                                              bool restart_success);
QDF_STATUS mlme_ext_vap_custom_aggr_size_send(
                                        struct vdev_mlme_obj *vdev_mlme,
                                        bool is_amsdu);

enum ieee80211_phymode
wlan_vdev_get_ieee_phymode(enum wlan_phymode wlan_phymode);

QDF_STATUS mlme_ext_peer_delete_all_response_event_handler(
                                        struct vdev_mlme_obj *vdev_mlme,
                                        struct peer_delete_all_response *rsp);

QDF_STATUS mlme_vdev_send_deauth(struct ieee80211vap *vap);

enum ieee80211_phymode ieee80211_coex_derive_phymode(
					struct ieee80211com *ic,
					struct wlan_channel *des_chan);

void ieee80211_update_peer_cw(struct ieee80211com *ic,
			      struct ieee80211vap *vap);

uint32_t wlan_vdev_get_bcn_tx_rate(struct vdev_mlme_obj *vdev_mlme,
                                   struct ieee80211_ath_channel *curchan);
#endif /* __WLAN_MLME_VDEV_MGMT_OPS_H__ */
