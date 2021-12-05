/*
 * Copyright (c) 2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#ifndef _WLAN_ATF_TGT_API_H_
#define _WLAN_ATF_TGT_API_H_

#include "../../core/atf_defs_i.h"

/**
 * tgt_atf_get_fmcap() - API to get firmware capability for ATF
 * @psoc : Reference to psoc global object
 *
 * This API is used to get firmware capability for ATF feature.
 *
 * Return : 1 if capable
 *          0 if not capable
 */
uint32_t tgt_atf_get_fmcap(struct wlan_objmgr_psoc *psoc);

/**
 * tgt_atf_get_mode() - API to get atf_mode
 * @psoc : Reference to psoc global object
 *
 * This API is used to get atf_mode.
 *
 * Return : configured atf_mode
 */
uint32_t tgt_atf_get_mode(struct wlan_objmgr_psoc *psoc);

/**
 * tgt_atf_get_msdu_desc() - API to get atf_msdu_desc value
 * @psoc : Reference to psoc global object
 *
 * This API is used to get configured atf_msdu_desc value.
 *
 * Return : configured atf_msdu_desc
 */
uint32_t tgt_atf_get_msdu_desc(struct wlan_objmgr_psoc *psoc);

/**
 * tgt_atf_get_max_vdevs() - API to get maximum number of vdevs
 * @psoc : Reference to psoc global object
 *
 * This API is used to get configured maximum number of allowed vdevs
 * for requested radio.
 *
 * Return : maximum number of vdevs
 */
uint32_t tgt_atf_get_max_vdevs(struct wlan_objmgr_psoc *psoc);

/**
 * tgt_atf_get_peers() - API to get number peer for ATF
 * @psoc : Reference to psoc global object
 *
 * This API is used to get number of peers configured for ATF.
 *
 * Return : number of peers
 */
uint32_t tgt_atf_get_peers(struct wlan_objmgr_psoc *psoc);

/**
 * tgt_atf_get_tput_based() - API to get throughput atf enabled or not
 * @pdev : Reference to pdev global object
 *
 * This API is used to get throughput atf enabled or not.
 *
 * Return : 1 if enabled
 *          0 if disabled
 */
uint32_t tgt_atf_get_tput_based(struct wlan_objmgr_pdev *pdev);

/**
 * tgt_atf_get_logging() - API to get logging is enabled/disabled
 * @pdev : Reference to pdev global object
 *
 * This API is used to get logging is enabled or not.
 *
 * Return : 1 if enabled
 *          0 if disabled
 */
uint32_t tgt_atf_get_logging(struct wlan_objmgr_pdev *pdev);

/**
 * tgt_atf_get_ssidgroup() - API to get ssid group enable state
 * @pdev : Reference to pdev global object
 *
 * This API is used to get configured ssid group enable state.
 *
 * Return : 1 if enable
 *          0 if disable
 */
uint32_t tgt_atf_get_ssidgroup(struct wlan_objmgr_pdev *pdev);

/**
 * tgt_atf_get_vdev_ac_blk_cnt() - API to get vdev ac block count
 * @vdev : Reference to vdev global object
 *
 * This API is used to get number of ACs blocked for perticular vdev.
 *
 * Return : tx blocked count
 */
uint32_t tgt_atf_get_vdev_ac_blk_cnt(struct wlan_objmgr_vdev *vdev);

/**
 * tgt_atf_get_peer_blk_txbitmap() - API to get peer's tx AC bitmap
 * @peer : Reference to peer global object
 *
 * This API is used to get bitmap indicating AC state per peer
 *
 * Return : 1 if blocked
 *          0 if not blocked
 */
uint8_t tgt_atf_get_peer_blk_txbitmap(struct wlan_objmgr_peer *peer);

/**
 * tgt_atf_get_vdev_blk_txtraffic() - API to get vdev's tx traffic block state
 * @vdev : Reference to vdev global object
 *
 * This API is used to get tx traffic block state for a vdev.
 *
 * Return : 1 if blocked
 *          0 if not blocked
 */
uint8_t tgt_atf_get_vdev_blk_txtraffic(struct wlan_objmgr_vdev *vdev);

/**
 * tgt_atf_get_sched() - API to get configured schedule policy
 * @pdev : Reference to pdev global object
 *
 * This API is used to get configured configured schedule policy.
 *
 * Return : Configured atf schedule policy
 */
uint32_t tgt_atf_get_sched(struct wlan_objmgr_pdev *pdev);

/**
 * tgt_atf_set_sched() - API to set requested schedule policy
 * @pdev  : Reference to pdev global object
 * @value : Requested schedule policy
 *
 * This API is used to set requested schedule policy.
 *
 * Return : None
 */
void tgt_atf_set_sched(struct wlan_objmgr_pdev *pdev, uint32_t value);

/**
 * tgt_atf_set_fmcap() - API to set firmware capability for ATF
 * @psoc  : Reference to psoc global object
 * @value : Value to enable/disable
 *
 * This API used to set firmware capable flag to 1/0.
 *
 * Return : None
 */
void tgt_atf_set_fmcap(struct wlan_objmgr_psoc *psoc, uint32_t value);

/**
 * tgt_atf_set_msdu_desc() - API to set msdu desc value
 * @psoc  : Reference to psoc global object
 * @value : Value to set msdu desc
 *
 * This API is used to set msdu desc value.
 *
 * Return : None
 */
void tgt_atf_set_msdu_desc(struct wlan_objmgr_psoc *psoc, uint32_t value);

/**
 * tgt_atf_set_max_vdevs() - API to set max vdevs
 * @psoc  : Reference to psoc global object
 * @value : Max vdevs value
 *
 * This API is used to set max vdevs.
 *
 * Return : None
 */
void tgt_atf_set_max_vdevs(struct wlan_objmgr_psoc *psoc, uint32_t value);

/**
 * tgt_atf_set_peers() - API to set number of peers
 * @psoc  : Reference to psoc global object
 * @value : Number of peers
 *
 * This API is used to set number of peers.
 *
 * Return : None
 */
void tgt_atf_set_peers(struct wlan_objmgr_psoc *psoc, uint32_t value);

/**
 * tgt_atf_get_peer_stats() - API to get peer atf stats from lmac
 * @peer  : Reference to peer global object
 * @stats : Reference to atf stats object (out)
 *
 * This API is used to get peer atf shats filled in 'stats' parameter.
 *
 * Return : None
 */
void tgt_atf_get_peer_stats(struct wlan_objmgr_peer *peer,
			    struct atf_stats *stats);

/**
 * tgt_atf_get_token_allocated() - API to get token allocated value
 * @peer  : Reference to peer global object
 *
 * This API is used to set token allocated for a peer.
 *
 * Return : Token allocated
 */
uint16_t tgt_atf_get_token_allocated(struct wlan_objmgr_peer *peer);

/**
 * tgt_atf_get_token_utilized() - API to get token utilized value
 * @peer  : Reference to peer global object
 *
 * This API is used to set token utilized for a peer.
 *
 * Return : Token utilised
 */
uint16_t tgt_atf_get_token_utilized(struct wlan_objmgr_peer *peer);

/**
 * tgt_atf_set_peer_stats() - API to update peer stats for ATF
 * @peer  : Reference to peer global object
 * @stats : ATF peer stats from LMAC
 *
 * This API used to update peer stats for ATF.
 *
 * Return : None
 */
void tgt_atf_set_peer_stats(struct wlan_objmgr_peer *peer,
			    struct atf_stats *stats);

/**
 * tgt_atf_set_vdev_blk_txtraffic() - API to block/unblock vdev tx traffic
 * @vdev  : Reference to vdev global object
 * @value : Value 1 for block and 0 for unblock
 *
 * This API is used to block/unblock vdev tx traffic.
 *
 * Return : None
 */
void tgt_atf_set_vdev_blk_txtraffic(struct wlan_objmgr_vdev *vdev,
				    uint8_t value);

/**
 * tgt_atf_peer_blk_txtraffic() - API to block/unblock peer tx traffic
 * @peer  : Reference to peer global object
 * @ac_id : AC id to block. 0xFF to block all AC's
 *
 * This API is used to block peer tx traffic.
 *
 * Return : none
 */
void tgt_atf_peer_blk_txtraffic(struct wlan_objmgr_peer *peer,
				    int8_t ac_id);

/**
 * tgt_atf_peer_unblk_txtraffic() - API to unblock peer tx traffic
 * @peer  : Reference to peer global object
 * @ac_id : AC id to unblock. 0xFF to unblock all AC's
 *
 * This API is used to unblock peer tx traffic.
 *
 * Return : none
 */
void tgt_atf_peer_unblk_txtraffic(struct wlan_objmgr_peer *peer,
				    int8_t ac_id);

/**
 * tgt_atf_set_token_allocated() - API to set token allocated value
 * @peer  : Reference to peer global object
 * @value : Value to set
 *
 * This API is used to set token allocated for a peer.
 *
 * Return : None
 */
void tgt_atf_set_token_allocated(struct wlan_objmgr_peer *peer, uint16_t value);

/**
 * tgt_atf_set_token_utilized() - API to set token utilized value
 * @peer  : Reference to peer global object
 * @value : Value to set
 *
 * This API is used to set token utilized for a peer.
 *
 * Return : None
 */
void tgt_atf_set_token_utilized(struct wlan_objmgr_peer *peer, uint16_t value);

/**
 * tgt_atf_is_stats_enabled() - API to check ATF stats enabled ot not
 * @pdev   : Reference to Pdev global object
 *
 * Return  : 1 if enabled and 0 if disabled
 */
uint8_t tgt_atf_is_stats_enabled(struct wlan_objmgr_pdev *pdev);

/**
 * tgt_atf_process_ppdu_stats() - API to process PPDU stats
 * @pdev   : Reference to Pdev global object
 * @msg    : QDF buffer containing PPDU stats
 *
 * Return  : None
 */
void tgt_atf_process_ppdu_stats(struct wlan_objmgr_pdev *pdev, qdf_nbuf_t msg);
#endif /* _WLAN_ATF_TGT_API_H_*/
