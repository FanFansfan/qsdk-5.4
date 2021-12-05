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

#include <ol_if_pdev.h>

int ol_ath_pdev_set_param(struct wlan_objmgr_pdev *pdev,
			  wmi_conv_pdev_params_id param_id,
                          uint32_t param_value)
{
	struct pdev_params pparam;
	int32_t pdev_idx;
	struct wmi_unified *pdev_wmi_handle;
	QDF_STATUS status;

	pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
	if (!pdev_wmi_handle)
		return -1;

	pdev_idx = lmac_get_pdev_idx(pdev);
	if (pdev_idx < 0)
		return -1;

	qdf_mem_set(&pparam, sizeof(pparam), 0);
	pparam.param_id = param_id;
	pparam.param_value = param_value;

	status = wmi_unified_pdev_param_send(pdev_wmi_handle,
					     &pparam, pdev_idx);

	return qdf_status_to_os_return(status);
}

void ol_ath_pdev_dfs_phyerr_offload_en(struct wlan_objmgr_pdev *pdev)
{
	struct wmi_unified *wmi_handle;
	struct wmi_unified *pdev_wmi_handle;
	struct wlan_objmgr_psoc *psoc;

	psoc = wlan_pdev_get_psoc(pdev);
	wmi_handle = lmac_get_wmi_hdl(psoc);
	if (!wmi_handle) {
		qdf_err("wmi_handle is null");
		return;
	}

	pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
	if (!pdev_wmi_handle) {
		qdf_err("pdev wmi handle is null");
		return;
	}

	if (wmi_service_enabled(wmi_handle, wmi_service_dfs_phyerr_offload))
		wmi_unified_dfs_phyerr_offload_en_cmd(pdev_wmi_handle,
						      WMI_HOST_PDEV_ID_SOC);
}

int ol_ath_pdev_fips(struct wlan_objmgr_pdev *pdev, uint8_t *key,
		     uint32_t key_len, uint8_t *data, uint32_t data_len,
		     uint32_t mode, uint32_t op, uint32_t pdev_id)
{
	struct fips_params param;
	struct wmi_unified *pdev_wmi_handle;
	QDF_STATUS status;

	pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
	if (!pdev_wmi_handle) {
		qdf_err("pdev wmi handle is null");
		return -EINVAL;
	}

	qdf_mem_set(&param, sizeof(param), 0);
	param.key_len = key_len;
	param.data_len = data_len;
	param.op = op;
	param.key = key;
	param.data = data;
	param.mode = mode;
	param.pdev_id = pdev_id;

	status = wmi_unified_pdev_fips_cmd_send(pdev_wmi_handle, &param);
	return qdf_status_to_os_return(status);
}

/**
 * ol_ath_pdev_set_ht_ie() - Set ht ie data
 * @pdev: pdev object
 * @ie_len: ie length
 * @ie_data: ie data
 *
 * Return: 0 if success, other value if failure
 */
static int ol_ath_pdev_set_ht_ie(struct wlan_objmgr_pdev *pdev,
				 uint32_t ie_len, uint8_t *ie_data)
{
	struct ht_ie_params param;
	struct wmi_unified *pdev_wmi_handle;
	QDF_STATUS status;

	pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
	if (!pdev_wmi_handle) {
		qdf_err("pdev wmi handle is null");
		return -EINVAL;
	}

	qdf_mem_set(&param, sizeof(param), 0);
	param.ie_len = ie_len;
	param.ie_data = ie_data;

	status = wmi_unified_set_ht_ie_cmd_send(pdev_wmi_handle, &param);
	return qdf_status_to_os_return(status);
}

/**
 * ol_ath_pdev_set_vht_ie() - Set vht ie data
 * @pdev:  pdev object
 * @ie_len: ie length
 * @ie_data: ie data
 *
 * Return: 0 if success, other value if failure
 */
static int ol_ath_pdev_set_vht_ie(struct wlan_objmgr_pdev *pdev,
				  uint32_t ie_len, uint8_t *ie_data)
{
	struct vht_ie_params param;
	struct wmi_unified *pdev_wmi_handle;
	QDF_STATUS status;

	pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
	if (!pdev_wmi_handle) {
		qdf_err("pdev wmi handle is null");
		return -EINVAL;
	}

	qdf_mem_set(&param, sizeof(param), 0);
	param.ie_len = ie_len;
	param.ie_data = ie_data;

	status = wmi_unified_set_vht_ie_cmd_send(pdev_wmi_handle, &param);
	return qdf_status_to_os_return(status);
}

void ol_ath_set_ht_vht_ies(struct ieee80211_node *ni)
{
	struct ieee80211com *ic = NULL;
	struct ieee80211vap *vap = NULL;
	struct ol_ath_softc_net80211 *scn = NULL;
	uint8_t *buf = NULL;
	uint8_t *buf_end = NULL;

	if (!ni) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY,
			       QDF_TRACE_LEVEL_ERROR,
			       "%s: Node is NULL\n", __func__);
		return;
	}

	ic = ni->ni_ic;
	vap = ni->ni_vap;
	if (!ic || !vap) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY,
			       QDF_TRACE_LEVEL_ERROR,
			       "%s: IC or VAP is NULL\n", __func__);
		return;
	}

	scn = OL_ATH_SOFTC_NET80211(ic);
	if (!scn) {
		QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY,
			       QDF_TRACE_LEVEL_ERROR,
			       "%s: SCN is NULL\n", __func__);
		return;
	}

	if (scn->set_ht_vht_ies)
		return;

	buf = qdf_mem_malloc(MAX_IE_SIZE);

	if (buf) {
		buf_end = ieee80211_add_htcap(buf, vap->iv_bss,
					      IEEE80211_FC0_SUBTYPE_PROBE_REQ);
		if ((buf_end - buf) <= MAX_HT_IE_LEN)
			ol_ath_pdev_set_ht_ie(scn->sc_pdev, buf_end - buf, buf);
		else
			qdf_err("HT IE len %d is more than expected",
				(int)(buf_end - buf));

		buf_end = ieee80211_add_vhtcap(buf, vap->iv_bss, ic,
					       IEEE80211_FC0_SUBTYPE_PROBE_REQ,
					       NULL, NULL);

		if ((buf_end - buf) <= MAX_VHT_IE_LEN)
			ol_ath_pdev_set_vht_ie(scn->sc_pdev, buf_end-buf, buf);
		else
			qdf_err("VHT IE len %d is more than expected",
				(int)(buf_end - buf));

		scn->set_ht_vht_ies = 1;
		qdf_mem_free(buf);
	}
}

void ol_ath_set_rxfilter(struct wlan_objmgr_pdev *pdev, uint32_t filter)
{
	if (ol_ath_pdev_set_param(pdev, wmi_pdev_param_rx_filter, filter))
		qdf_err("Error setting rxfilter 0x%08x", filter);
}

void ol_ath_setTxPowerLimit(struct wlan_objmgr_pdev *pdev, uint32_t limit,
			    uint16_t tpcInDb, uint32_t is2GHz)
{
	int ret = 0;
	uint16_t cur_tx_power;
	struct ol_ath_softc_net80211 *scn;
	struct ieee80211com *ic = wlan_pdev_mlme_get_ext_hdl(pdev);

	if (!ic) {
		qdf_err("ic is NULL!");
		return;
	}

	scn = OL_ATH_SOFTC_NET80211(ic);
	if (!scn) {
		qdf_err("scn is NULL!");
		return;
	}

	cur_tx_power = ieee80211com_get_txpowerlimit(ic);

	if (cur_tx_power == limit)
		return;

	/* Update max tx power only if the curr max tx power is diff */
	if (limit > scn->max_tx_power) {
		qdf_info("Tx power value is greater than supported ");
		qdf_info("max tx power %d, Limiting to default Max",
			  scn->max_tx_power);
		limit = scn->max_tx_power;
	}

	if (is2GHz)
		ret = ol_ath_pdev_set_param(pdev,
					    wmi_pdev_param_txpower_limit2g,
					    limit);
	else
		ret = ol_ath_pdev_set_param(pdev,
					    wmi_pdev_param_txpower_limit5g,
					    limit);
	if (ret)
		return;

	/* Update the ic_txpowlimit */
	if (is2GHz)
		scn->txpowlimit2G = limit;
	else
		scn->txpowlimit5G = limit;

	if ((is2GHz && IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) ||
	    (!is2GHz && !IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)))
		ieee80211com_set_txpowerlimit(ic, (uint16_t)limit);
}

void ol_ath_setmfpQos(struct wlan_objmgr_pdev *pdev, uint32_t dot11w)
{
	ol_ath_pdev_set_param(pdev, wmi_pdev_param_pmf_qos, dot11w);
}

#ifdef WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG
int ol_ath_set_protocol_tagging(struct wlan_objmgr_pdev *pdev,
                                RX_PKT_TAG_OPCODE_TYPE opcode,
		                RX_PKT_TAG_RECV_PKT_TYPE pkt_type,
		                uint32_t metadata)
{
	struct ol_ath_softc_net80211 *scn;
	struct ieee80211com *ic = wlan_pdev_mlme_get_ext_hdl(pdev);
	struct ieee80211_rx_pkt_protocol_tag tag_info;

	if (!ic) {
		qdf_err("ic is NULL!");
		return -EINVAL;
	}

	scn = OL_ATH_SOFTC_NET80211(ic);
	if (!scn) {
		qdf_err("scn is NULL!");
		return -EINVAL;
	}

	tag_info.op_code = opcode;
	tag_info.pkt_type = pkt_type;
	tag_info.pkt_type_metadata = metadata;
	ol_ath_ucfg_set_rx_pkt_protocol_tagging(scn, &tag_info);

	return 0;
}
#else
int ol_ath_set_protocol_tagging(struct wlan_objmgr_pdev *pdev,
                        RX_PKT_TAG_OPCODE_TYPE opcode,
                        RX_PKT_TAG_RECV_PKT_TYPE pkt_type,
                        uint32_t metadata)
{
    return 0;
}
#endif

#if ATH_OL_FAST_CHANNEL_RESET_WAR
/* WAR for EV#117307, MSDU_DONE is not set for data packet,
 * to fix this issue, fast channel change is disabled for x86 platform
 */
void ol_ath_fast_chan_change(struct wlan_objmgr_pdev *pdev)
{
	qdf_info("Disabling fast channel reset");

	if (ol_ath_pdev_set_param(pdev, wmi_pdev_param_fast_channel_reset,
				  DISABLE_FAST_CHANNEL_RESET))
		qdf_err("Failed to disable fast channel reset");
}
#endif

int ol_ath_set_mgmt_retry_limit(struct wlan_objmgr_pdev *pdev, uint8_t limit)
{
	int ret = 0;
	struct ol_ath_softc_net80211 *scn;
	struct ieee80211com *ic = wlan_pdev_mlme_get_ext_hdl(pdev);

	if (!ic) {
		qdf_err("ic is NULL!");
		return -EINVAL;
	}

	scn = OL_ATH_SOFTC_NET80211(ic);
	if (!scn) {
		qdf_err("scn is NULL!");
		return -EINVAL;
	}

	qdf_info("Set mgmt retry limit to %d", limit);

	ret = ol_ath_pdev_set_param(pdev, wmi_pdev_param_mgmt_retry_limit,
				    limit);
	if (ret) {
		qdf_err("Set mgmt retry limit failed!");
		return ret;
	}

	scn->scn_mgmt_retry_limit = limit;
	return 0;
}

int ol_ath_set_default_pcp_tid_map(struct wlan_objmgr_pdev *pdev, uint32_t pcp,
				   uint32_t tid)
{
	ol_txrx_soc_handle soc_txrx_handle;
	QDF_STATUS status;
	struct wlan_objmgr_psoc *psoc;

	psoc = wlan_pdev_get_psoc(pdev);
	soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
	if (!soc_txrx_handle) {
		qdf_err("dp handle is null");
		return -EINVAL;
	}

	status = cdp_set_pdev_pcp_tid_map(soc_txrx_handle,
					  wlan_objmgr_pdev_get_pdev_id(pdev),
					  pcp, tid);
	return qdf_status_to_os_return(status);
}

int ol_ath_set_default_tidmap_prty(struct wlan_objmgr_pdev *pdev, uint32_t val)
{
	ol_txrx_soc_handle soc_txrx_handle;
	cdp_config_param_type value = {0};
	QDF_STATUS status;
	struct wlan_objmgr_psoc *psoc;

	psoc = wlan_pdev_get_psoc(pdev);

	soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
	if (!soc_txrx_handle) {
		qdf_err("dp handle is null");
		return -EINVAL;
	}

	value.cdp_pdev_param_tidmap_prty = val;

	status = cdp_txrx_set_pdev_param(soc_txrx_handle,
					 wlan_objmgr_pdev_get_pdev_id(pdev),
					 CDP_TIDMAP_PRTY, value);
	return qdf_status_to_os_return(status);
}

QDF_STATUS ol_scan_set_chan_list(struct wlan_objmgr_pdev *pdev, void *arg)
{
    struct ieee80211com *ic = NULL;
    struct scan_chan_list_params *param = arg;
    struct wmi_unified *pdev_wmi_handle;

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("ic is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
    if (!pdev_wmi_handle) {
        qdf_err("pdev_wmi_handle is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    return wmi_unified_scan_chan_list_cmd_send(pdev_wmi_handle, param);
}

QDF_STATUS ol_ath_fill_umac_legacy_chanlist(struct wlan_objmgr_pdev *pdev,
                                    struct regulatory_channel *curr_chan_list)
{
    struct ieee80211com *ic;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_psoc *psoc;

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("ic is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return QDF_STATUS_E_FAILURE;
    }

    if (wmi_service_enabled(wmi_handle, wmi_service_regulatory_db)) {
        ieee80211_reg_get_current_chan_list(ic, curr_chan_list);

        qdf_event_set(&ic->ic_wait_for_init_cc_response);
    }

    return QDF_STATUS_SUCCESS;
}

/*
 * Enable duration based Tx mode selection per radio
 */
void ol_ath_set_duration_based_tx_mode_select(struct wlan_objmgr_pdev *pdev,
                                       uint32_t tx_mode_select_enable)
{
    struct wmi_unified *pdev_wmi_handle;
    struct ieee80211com *ic;
    struct wmi_pdev_enable_tx_mode_selection tx_mode_select_param;

    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!ic) {
        qdf_err("ic is NULL");
        return;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle)
        return;

    qdf_mem_set(&tx_mode_select_param, sizeof(tx_mode_select_param), 0);
    tx_mode_select_param.pdev_id = lmac_get_pdev_idx(pdev);
    tx_mode_select_param.enable_tx_mode_selection = tx_mode_select_enable;

    (void)wmi_unified_set_radio_tx_mode_select_cmd_send(pdev_wmi_handle,
                    &tx_mode_select_param);
}

/*
 * Enable low latency mode
 */
QDF_STATUS ol_ath_enable_low_latency_mode(struct wlan_objmgr_pdev *pdev,
                                       uint32_t enable_low_latency_mode)
{
    if (!pdev) {
        qdf_err("pdev is NULL");
        return -EINVAL;
    }

    return ol_ath_pdev_set_param(pdev, wmi_pdev_param_low_latency_mode,
                                  enable_low_latency_mode);
}
