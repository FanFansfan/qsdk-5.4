/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2011, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef OL_IF_PDEV_H
#define OL_IF_PDEV_H

#include <hif.h>
#include <qdf_trace.h>
#include <wmi_unified_api.h>
#include <wlan_lmac_if_def.h>
#include <wlan_lmac_if_api.h>
#include <cdp_txrx_ctrl.h>
#include <wlan_global_lmac_if_api.h>
#include <init_deinit_lmac.h>
#include <target_if.h>

#if UMAC_SUPPORT_CFG80211
#include <ieee80211_cfg80211.h>
#endif /* UMAC_SUPPORT_CFG80211 */

#define MAX_IE_SIZE 512
#define MAX_HT_IE_LEN 32
#define MAX_VHT_IE_LEN 32

/**
 * ol_ath_pdev_set_param() - Sends pdev parameters to firmware via wmi layer
 * @pdev: pointer to pdev object
 * @param_id: pdev param id
 * @param_value: parameter value
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_pdev_set_param(struct wlan_objmgr_pdev *pdev,
			  wmi_conv_pdev_params_id param_id,
			  uint32_t param_value);

/**
 * ol_ath_pdev_dfs_phyerr_offload_en() - Send dfs phyerr offload enable
 * command to Firmware
 * @pdev: pointer to pdev object
 *
 * In full-offload mode, after wifi is brought down and brought up,
 * the phyerror offload enable command (phyerr_offload_en_cmd) should
 * be resent since the firmware gets reloaded.
 * The command is to process the dfs pulses in the firmware and to
 * send the radar-found event to the host
 *
 * Return: None
 */
void ol_ath_pdev_dfs_phyerr_offload_en(struct wlan_objmgr_pdev *pdev);

/**
 * ol_ath_pdev_fips() - Send pdev fips config parameters to firmware
 * @pdev: pdev object
 * @key: Pointer to fips key
 * @key_len: length of key
 * @data: Pointer to data buf
 * @data_len: length of data buf
 * @mode: mode
 * @op: operation
 * @pdev_id: pdev_id for identifying the MAC
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_pdev_fips(struct wlan_objmgr_pdev *pdev, uint8_t *key,
		     uint32_t key_len, uint8_t *data, uint32_t data_len,
		     uint32_t mode, uint32_t op, uint32_t pdev_id);

int ol_ath_set_protocol_tagging(struct wlan_objmgr_pdev *pdev,
                                RX_PKT_TAG_OPCODE_TYPE opcode,
                                RX_PKT_TAG_RECV_PKT_TYPE pkt_type,
                                uint32_t metadata);

/**
 * ol_ath_set_ht_vht_ies() - Set ht vht ie information
 * @ni: Node information
 *
 * Return: none
 */
void ol_ath_set_ht_vht_ies(struct ieee80211_node *ni);

/**
 * ol_ath_set_rxfilter() - Set Rx Filter value
 * @pdev: pdev object
 * @filter: Rx filter value
 *
 * Return: none
 */
void ol_ath_set_rxfilter(struct wlan_objmgr_pdev *pdev, uint32_t filter);

/**
 * ol_ath_setTxPowerLimit() - Set Tx Power limit value
 * @pdev: pdev object
 * @limit: tx power limit
 * @tpcInDb: tx power in db
 * @is2GHz: if 2GHz band
 *
 * Return: none
 */
void ol_ath_setTxPowerLimit(struct wlan_objmgr_pdev *pdev, uint32_t limit,
			    uint16_t tpcInDb, uint32_t is2GHz);

/**
 * ol_ath_setmfpqos() - set hw mfp qos feature
 * @pdev: pdev object
 * @dot11w: the feature to set
 *
 * Return: none
 */
void ol_ath_setmfpQos(struct wlan_objmgr_pdev *pdev, uint32_t dot11w);

#if ATH_OL_FAST_CHANNEL_RESET_WAR
#define DISABLE_FAST_CHANNEL_RESET 1
/**
 * ol_ath_fast_chan_change() - Disables fast channel reset
 * @pdev: pdev object
 *
 * Return: none
 */
void ol_ath_fast_chan_change(struct wlan_objmgr_pdev *pdev);
#endif

/**
 * ol_ath_set_mgmt_retry_limit() - Set mgmt frame retry limit
 * @pdev: pdev object
 * @limit: retry limit value
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_set_mgmt_retry_limit(struct wlan_objmgr_pdev *pdev, uint8_t limit);

/**
 * ol_ath_set_default_pcp_tid_map() -Set pcp to tid mapping
 * @pdev: pdev object
 * @pcp: pcp value
 * @tid: tid value
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_set_default_pcp_tid_map(struct wlan_objmgr_pdev *pdev, uint32_t pcp,
				   uint32_t tid);

/**
 * ol_ath_set_default_tidmap_prty() -Set tid map priority
 * @pdev: pdev object
 * @val: tid map priority value
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_set_default_tidmap_prty(struct wlan_objmgr_pdev *pdev, uint32_t val);

/**
 * ol_scan_set_chan_list() -Set channel list
 * @pdev: pdev object
 * @arg: scan list parameters
 *
 * Return: QDF_STATUS_SUCCESS if success, other qdf status if failure
 */
QDF_STATUS ol_scan_set_chan_list(struct wlan_objmgr_pdev *pdev, void *arg);

/**
 * ol_ath_fill_umac_legacy_chanlist() -Set legacy channel list
 * @pdev: pdev object
 * @curr_chan_list: Channel list
 *
 * Return: QDF_STATUS_SUCCESS if success, other qdf status if failure
 */
QDF_STATUS ol_ath_fill_umac_legacy_chanlist(struct wlan_objmgr_pdev *pdev,
                                            struct regulatory_channel *curr_chan_list);

/**
 * ol_ath_set_duration_based_tx_mode_select() -Set Tx Mode Selection
 * @pdev: pdev object
 * @tx_mode_select_enable: Flag to set tx mode select
 * Return: void
 */
void ol_ath_set_duration_based_tx_mode_select(struct wlan_objmgr_pdev *pdev,
                                              uint32_t tx_mode_select_enable);

/**
 * ol_ath_enable_low_latency_mode() - Enable low latency mode
 * @pdev: pdev object
 * @enable_low_latency_mode: Flag to enable low latency mode
 * Return: QDF_STATUS_SUCCESS if success, other qdf status if failure
 */
QDF_STATUS ol_ath_enable_low_latency_mode(struct wlan_objmgr_pdev *pdev,
                                    uint32_t enable_low_latency_mode);
#endif /* OL_IF_PDEV_H */
