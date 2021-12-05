/*
 * Copyright (c) 2017, 2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary . Qualcomm Innovation Center, Inc.
 *
 */

#ifndef __OL_IF_STATS_API_H__
#define __OL_IF_STATS_API_H__

/**
 * ol_ath_update_dp_peer_stats() - Updates peer stats for given peer id
 * @scn_handle: pointer to scn handle
 * @stats: pointer to stats
 * @peer_id: peer id
 *
 * Return: A_OK on success, A_ERROR on failure
 */
A_STATUS ol_ath_update_dp_peer_stats(void *scn_handle, void *stats,
				     uint16_t peer_id);

/**
 * ol_ath_update_dp_vdev_stats() - Updates vdev stats for given vdev id
 * @scn_handle: pointer to scn handle
 * @stats: pointer to stats
 * @vdev_id: vdev id
 *
 * Return: A_OK on success, A_ERROR on failure
 */
A_STATUS ol_ath_update_dp_vdev_stats(void *scn_handle, void *stats,
				     uint16_t vdev_id);

/**
 * ol_ath_update_dp_pdev_stats() - Updates pdev stats for given pdev id
 * @scn_handle: pointer to scn handle
 * @stats: pointer to stats
 * @pdev_id: pdev id
 *
 * Return: A_OK on success, A_ERROR on failure
 */
A_STATUS ol_ath_update_dp_pdev_stats(void *scn_handle, void *stats,
				     uint16_t pdev_id);

/**
 * ol_ath_sched_ppdu_stats() - Retrieves ppdu stats for rx and tx ppdu desc
 * schedules work to collect ppdu stats
 * @scn: pointer to ath soft context
 * @ic: ic pointer
 * @data: ppdu stats data pointer
 * @dir: tx or rx direction, 0 - Tx, 1 - Rx
 *
 * Return: none
 */
void ol_ath_sched_ppdu_stats(struct ol_ath_softc_net80211 *scn,
			     struct ieee80211com *ic, void *data, uint8_t dir);

/**
 * process_rx_ppdu_stats() - Retrieves rx ppdu stats
 * @context: rx ppdu stats context
 *
 * Return: none
 */
void process_rx_ppdu_stats(void *context);

/**
 * process_tx_ppdu_stats() - Retrieves tx ppdu stats
 * @context: tx ppdu stats context
 *
 * Return: none
 */
void process_tx_ppdu_stats(void *context);

/**
 * ol_ath_process_ppdu_stats() - process tx/rx ppdu stats based on wdi event
 * @pdev_hdl: pdev handle
 * @event: wdi event
 * @data: pointer to ppdu stats
 * @peer_id: peer id
 * @status: htt rx packet status
 *
 * Return: none
 */
void ol_ath_process_ppdu_stats(void *pdev_hdl, enum WDI_EVENT event, void *data,
			       uint16_t peer_id, enum htt_cmn_rx_status status);

#endif /* __OL_IF_STATS_API_H__ */
