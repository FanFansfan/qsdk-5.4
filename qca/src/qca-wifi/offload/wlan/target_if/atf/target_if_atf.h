/*
 * Copyright (c) 2017, 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#ifndef _TARGET_IF_ATF_H_
#define _TARGET_IF_ATF_H_

#include <wlan_atf_utils_defs.h>
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_objmgr_vdev_obj.h>
#include <wlan_objmgr_peer_obj.h>

#define atf_log(level, args...) \
QDF_TRACE(QDF_MODULE_ID_ATF, level, ## args)

#define atf_logfl(level, format, args...) atf_log(level, FL(format), ## args)

#define atf_fatal(format, args...) \
	atf_logfl(QDF_TRACE_LEVEL_FATAL, format, ## args)
#define atf_err(format, args...) \
	atf_logfl(QDF_TRACE_LEVEL_ERROR, format, ## args)
#define atf_warn(format, args...) \
	atf_logfl(QDF_TRACE_LEVEL_WARN, format, ## args)
#define atf_info(format, args...) \
	atf_logfl(QDF_TRACE_LEVEL_INFO, format, ## args)
#define atf_debug(format, args...) \
	atf_logfl(QDF_TRACE_LEVEL_DEBUG, format, ## args)

void target_if_atf_tx_ops_register(struct wlan_lmac_if_tx_ops *tx_ops);

uint32_t target_if_atf_get_num_msdu_desc(struct wlan_objmgr_psoc *psoc);

uint8_t target_if_atf_is_tx_traffic_blocked(struct wlan_objmgr_vdev *vdev,
					    uint8_t *peer_mac,
					    struct sk_buff *skb);

static inline uint32_t target_if_atf_get_vdev_ac_blk_cnt(
		struct wlan_objmgr_psoc *psoc, struct wlan_objmgr_vdev *vdev)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_vdev_ac_blk_cnt(vdev);
}

static inline uint32_t target_if_atf_get_vdev_blk_txtraffic(
		struct wlan_objmgr_psoc *psoc, struct wlan_objmgr_vdev *vdev)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_vdev_blk_txtraffic(vdev);
}

static inline uint8_t target_if_atf_get_peer_blk_txbitmap(
		struct wlan_objmgr_psoc *psoc, struct wlan_objmgr_peer *peer)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_peer_blk_txbitmap(peer);
}

static inline void target_if_atf_set_sched(struct wlan_objmgr_psoc *psoc,
				struct wlan_objmgr_pdev *pdev, uint8_t value)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return;
	}

	rx_ops->atf_rx_ops.atf_set_sched(pdev, value);
}

static inline uint32_t target_if_atf_get_sched(struct wlan_objmgr_psoc *psoc,
						struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_sched(pdev);
}

static inline uint8_t target_if_atf_get_ssid_group(
		struct wlan_objmgr_psoc *psoc, struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_ssidgroup(pdev);
}

static inline uint8_t target_if_atf_get_mode(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_mode(psoc);
}

static inline uint32_t target_if_atf_get_msdu_desc(
						struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_msdu_desc(psoc);
}

static inline uint32_t target_if_atf_get_max_vdevs(
						struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_max_vdevs(psoc);
}

static inline uint32_t target_if_atf_get_peers(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_peers(psoc);
}

static inline uint8_t target_if_atf_get_fmcap(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_fmcap(psoc);
}

static inline void target_if_atf_set_fmcap(struct wlan_objmgr_psoc *psoc,
						uint8_t value)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return;
	}

	rx_ops->atf_rx_ops.atf_set_fmcap(psoc, value);
}

static inline uint16_t target_if_atf_get_token_allocated(
	struct wlan_objmgr_psoc *psoc, struct wlan_objmgr_peer *peer)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_token_allocated(peer);
}

static inline void target_if_atf_set_token_allocated(
	struct wlan_objmgr_psoc *psoc,
	struct wlan_objmgr_peer *peer, uint16_t value)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return;
	}

	rx_ops->atf_rx_ops.atf_set_token_allocated(peer, value);
}

static inline uint16_t target_if_atf_get_token_utilized(
	struct wlan_objmgr_psoc *psoc, struct wlan_objmgr_peer *peer)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_get_token_utilized(peer);
}

static inline void target_if_atf_set_token_utilized(
	struct wlan_objmgr_psoc *psoc,
	struct wlan_objmgr_peer *peer, uint16_t value)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return;
	}

	rx_ops->atf_rx_ops.atf_set_token_utilized(peer, value);
}

static inline uint8_t target_if_atf_stats_enabled(struct wlan_objmgr_psoc *psoc,
						  struct wlan_objmgr_pdev *pdev)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		return 0;
	}

	return rx_ops->atf_rx_ops.atf_is_stats_enabled(pdev);
}

static inline
void target_if_atf_process_ppdu_stats(struct wlan_objmgr_psoc *psoc,
		struct wlan_objmgr_pdev *pdev, qdf_nbuf_t msg)
{
	struct wlan_lmac_if_rx_ops *rx_ops;

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		atf_err("rx_ops is NULL");
		qdf_nbuf_free(msg);
		return;
	}

	rx_ops->atf_rx_ops.atf_process_ppdu_stats(pdev, msg);
}
#endif /* _TARGET_IF_ATF_H_ */
