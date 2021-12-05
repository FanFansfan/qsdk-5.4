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

#include <ol_if_twt.h>
#include <cdp_txrx_ctrl.h>

/**
 * ol_ath_twt_enable_complete_event_handler() - twt enable complete handler
 * @sc: soc handle
 * @data: event data
 * @datalen: length of data
 *
 * Event handler for WMI_TWT_ENABLE_COMPLETE_EVENTID sent to host
 * driver in response to a WMI_TWT_ENABLE_CMDID being sent to WLAN
 * firmware
 *
 * Return: 0 on success
 */
int ol_ath_twt_enable_complete_event_handler(ol_soc_t sc,
					     uint8_t *data,
					     uint32_t datalen)
{
	ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
	struct wmi_unified *wmi_handle;
	struct wmi_twt_enable_complete_event_param params;
	enum WMI_HOST_ENABLE_TWT_STATUS status = WMI_HOST_ENABLE_TWT_STATUS_OK;

	wmi_handle = lmac_get_wmi_unified_hdl(soc->psoc_obj);
	if (wmi_handle) {
		if (wmi_extract_twt_enable_comp_event(wmi_handle, data,
						      &params)) {
			qdf_err("twt disable comp evt err");
			return -EINVAL;;
		}
	} else {
		qdf_err("twt enable failed.");
		return -EINVAL;;
	}

	status = params.status;
	if (status != WMI_HOST_ENABLE_TWT_STATUS_OK) {
		qdf_err("twt enable err");
		return -EINVAL;
	}

	qdf_info("twt enabled");
	return 0;
}

/**
 * ol_ath_twt_disable_complete_event_handler() - twt enable complete handler
 * @sc: soc handle
 * @data: event data
 * @datalen: length of data
 *
 * Event handler for WMI_TWT_DISABLE_COMPLETE_EVENTID sent to host
 * driver in response to a WMI_TWT_DISABLE_CMDID being sent to WLAN
 * firmware
 *
 * Return: 0 on success
 */
int ol_ath_twt_disable_complete_event_handler(ol_soc_t sc,
					      uint8_t *data,
					      uint32_t datalen)
{
	ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
	struct wmi_unified *wmi_handle;
	struct wmi_twt_disable_complete_event params;

	wmi_handle = lmac_get_wmi_unified_hdl(soc->psoc_obj);
	if (wmi_handle) {
		if (wmi_extract_twt_disable_comp_event(wmi_handle, data,
						       &params)) {
			qdf_err("twt disable comp evt err");
			return -EINVAL;;
		}
		qdf_info("twt disabled");
	} else {
		qdf_err("twt disable failed");
		return -EINVAL;
	}

	return 0;
}

void init_twt_default_config(ol_ath_soc_softc_t *soc)
{
	struct wlan_objmgr_psoc *psoc = soc->psoc_obj;

	soc->twt_enable = cfg_get(psoc, CFG_OL_TWT_ENABLE);
	soc->twt.sta_cong_timer_ms =
			cfg_get(psoc, CFG_OL_TWT_STA_CONG_TIMER_MS);
	soc->twt.mbss_support =
			cfg_get(psoc, CFG_OL_TWT_MBSS_SUPPORT);
	soc->twt.default_slot_size =
			cfg_get(psoc, CFG_OL_TWT_DEFAULT_SLOT_SIZE);
	soc->twt.congestion_thresh_setup =
			cfg_get(psoc, CFG_OL_TWT_CONGESTION_THRESH_SETUP);
	soc->twt.congestion_thresh_teardown =
			cfg_get(psoc, CFG_OL_TWT_CONGESTION_THRESH_TEARDOWN);
	soc->twt.congestion_thresh_critical =
			cfg_get(psoc, CFG_OL_TWT_CONGESTION_THRESH_CRITICAL);
	soc->twt.interference_thresh_teardown =
			cfg_get(psoc, CFG_OL_TWT_INTERFERENCE_THRESH_TEARDOWN);
	soc->twt.interference_thresh_setup =
			cfg_get(psoc, CFG_OL_TWT_INTERFERENCE_THRESH_SETUP);
	soc->twt.min_no_sta_setup =
			cfg_get(psoc, CFG_OL_TWT_MIN_NUM_STA_SETUP);
	soc->twt.min_no_sta_teardown =
			cfg_get(psoc, CFG_OL_TWT_MIN_NUM_STA_TEARDOWN);
	soc->twt.no_of_bcast_mcast_slots =
			cfg_get(psoc, CFG_OL_TWT_NUM_BCMC_SLOTS);
	soc->twt.min_no_twt_slots =
			cfg_get(psoc, CFG_OL_TWT_MIN_NUM_SLOTS);
	soc->twt.max_no_sta_twt =
			cfg_get(psoc, CFG_OL_TWT_MAX_NUM_STA_TWT);
	soc->twt.mode_check_interval =
			cfg_get(psoc, CFG_OL_TWT_MODE_CHECK_INTERVAL);
	soc->twt.add_sta_slot_interval =
			cfg_get(psoc, CFG_OL_TWT_ADD_STA_SLOT_INTERVAL);
	soc->twt.remove_sta_slot_interval =
			cfg_get(psoc, CFG_OL_TWT_REMOVE_STA_SLOT_INTERVAL);
	soc->twt.b_twt_enable =
			wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_BCAST_TWT);
}

int ol_ath_twt_enable_command(struct ol_ath_softc_net80211 *scn)
{
	struct wmi_twt_enable_param twt_param = {0};
	ol_ath_soc_softc_t *soc = scn->soc;
	wmi_unified_t wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
	QDF_STATUS status;

	if (!wmi_handle)
		return -EINVAL;

	if (!soc->twt_enable) {
		qdf_info("TWT is disable in INI. Do not send enable cmd to FW");
		/* Clear ext caps in psoc to indicate no support for TWT */
		wlan_psoc_nif_fw_ext_cap_clear(soc->psoc_obj,
					       WLAN_SOC_CEXT_TWT_REQUESTER);
		wlan_psoc_nif_fw_ext_cap_clear(soc->psoc_obj,
					       WLAN_SOC_CEXT_TWT_RESPONDER);
		return 0;
	}
	twt_param.pdev_id = lmac_get_pdev_idx(scn->sc_pdev);
	twt_param.sta_cong_timer_ms = scn->soc->twt.sta_cong_timer_ms;
	twt_param.mbss_support = scn->soc->twt.mbss_support;
	twt_param.default_slot_size = scn->soc->twt.default_slot_size;
	twt_param.congestion_thresh_setup =
				scn->soc->twt.congestion_thresh_setup;
	twt_param.congestion_thresh_teardown =
				scn->soc->twt.congestion_thresh_teardown;
	twt_param.congestion_thresh_critical =
				scn->soc->twt.congestion_thresh_critical;
	twt_param.interference_thresh_teardown =
				scn->soc->twt.interference_thresh_teardown;
	twt_param.interference_thresh_setup =
				scn->soc->twt.interference_thresh_setup;
	twt_param.min_no_sta_setup =
				scn->soc->twt.min_no_sta_setup;
	twt_param.min_no_sta_teardown =
				scn->soc->twt.min_no_sta_teardown;
	twt_param.no_of_bcast_mcast_slots =
				scn->soc->twt.no_of_bcast_mcast_slots;
	twt_param.min_no_twt_slots =
				scn->soc->twt.min_no_twt_slots;
	twt_param.max_no_sta_twt =
				scn->soc->twt.max_no_sta_twt;
	twt_param.mode_check_interval =
				scn->soc->twt.mode_check_interval;
	twt_param.add_sta_slot_interval =
		scn->soc->twt.add_sta_slot_interval;
	twt_param.remove_sta_slot_interval =
		scn->soc->twt.remove_sta_slot_interval;
	twt_param.b_twt_enable = scn->soc->twt.b_twt_enable;

	status = wmi_unified_twt_enable_cmd(wmi_handle, &twt_param);
	return qdf_status_to_os_return(status);
}

/**
 * ol_ath_twt_req - sends the twt dialog command to fw
 * @vap: legacy vap handle
 * @req: pointer to ieee80211req_athdbg struct
 *
 * This function used to send twt dialog commands to fw.
 *
 * Return: 0 on success
 */
static int ol_ath_twt_req(wlan_if_t vap, struct ieee80211req_athdbg *req)
{
	struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vap->vdev_obj);
	wmi_unified_t wmi_handle = lmac_get_pdev_wmi_handle(pdev);
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

	if (!wmi_handle)
		return -EINVAL;

	switch (req->cmd) {
	case IEEE80211_DBGREQ_TWT_ADD_DIALOG:
	{
		struct wmi_twt_add_dialog_param param = {0};

		if (req->data.twt_add.twt_cmd >
		    WMI_HOST_TWT_COMMAND_REJECT_TWT) {
			qdf_err("TWT cmd %d is invalid",
				 req->data.twt_add.twt_cmd);
			return -EINVAL;
		}

		param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
		qdf_mem_copy(param.peer_macaddr, req->dstmac, 6);
		param.dialog_id = req->data.twt_add.dialog_id;
		param.wake_intvl_us = req->data.twt_add.wake_intvl_us;
		param.wake_intvl_mantis = req->data.twt_add.wake_intvl_mantis;
		param.wake_dura_us = req->data.twt_add.wake_dura_us;
		param.sp_offset_us = req->data.twt_add.sp_offset_us;
		param.twt_cmd = req->data.twt_add.twt_cmd;

		if (req->data.twt_add.flags & IEEE80211_TWT_FLAG_BCAST) {
			if (!wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_BCAST_TWT)) {
				qdf_err("BTWT feature is disabled");
				return -EINVAL;
			}

			param.flag_bcast = 1;
		}
		if (req->data.twt_add.flags & IEEE80211_TWT_FLAG_TRIGGER)
			param.flag_trigger = 1;
		if (req->data.twt_add.flags & IEEE80211_TWT_FLAG_FLOW_TYPE)
			param.flag_flow_type = 1;
		if (req->data.twt_add.flags & IEEE80211_TWT_FLAG_PROTECTION)
			param.flag_protection = 1;
#ifdef WLAN_SUPPORT_BCAST_TWT
		if(req->data.twt_add.flags & IEEE80211_TWT_FLAG_BTWT_ID0) {
			uint32_t flags = req->data.twt_add.flags;

			if (!wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_BCAST_TWT)) {
				qdf_err("BTWT feature is disabled");
				return -EINVAL;
			}

			param.flag_b_twt_id0 = 1;
			param.b_twt_persistence =
				IEEE80211_GET_BTWT_PERSISTENCE(flags);
			param.b_twt_recommendation =
				IEEE80211_GET_BTWT_RECOMMENDATION(flags);
		}
#endif
		status = wmi_unified_twt_add_dialog_cmd(wmi_handle, &param);
	}
	break;
	case IEEE80211_DBGREQ_TWT_DEL_DIALOG:
	{
		struct wmi_twt_del_dialog_param param = {0};

		param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
		qdf_mem_copy(param.peer_macaddr, req->dstmac, 6);
		param.dialog_id = req->data.twt_del_pause.dialog_id;
		status = wmi_unified_twt_del_dialog_cmd(wmi_handle, &param);

	}
	break;
	case IEEE80211_DBGREQ_TWT_PAUSE_DIALOG:
	{
		struct wmi_twt_pause_dialog_cmd_param param;

		param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
		qdf_mem_copy(param.peer_macaddr, req->dstmac, 6);
		param.dialog_id = req->data.twt_del_pause.dialog_id;

		status = wmi_unified_twt_pause_dialog_cmd(wmi_handle, &param);
	}
	break;
	case IEEE80211_DBGREQ_TWT_RESUME_DIALOG:
	{
		struct wmi_twt_resume_dialog_cmd_param param =	{0};

		param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
		qdf_mem_copy(param.peer_macaddr, req->dstmac, 6);
		param.dialog_id = req->data.twt_resume.dialog_id;
		param.sp_offset_us = req->data.twt_resume.sp_offset_us;
		param.next_twt_size = req->data.twt_resume.next_twt_size;

		status = wmi_unified_twt_resume_dialog_cmd(wmi_handle, &param);
	}
	break;
#ifdef WLAN_SUPPORT_BCAST_TWT
        case IEEE80211_DBGREQ_TWT_BTWT_INVITE_STA:
        {
		struct wmi_twt_btwt_invite_sta_cmd_param param = {0};

		if (!wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_BCAST_TWT)) {
			qdf_err("BTWT feature is disabled");
			return -EINVAL;
		}

		param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
		qdf_mem_copy(param.peer_macaddr, req->dstmac, 6);
		param.dialog_id = req->data.twt_btwt_sta_inv_remove.dialog_id;

		status = wmi_unified_twt_btwt_invite_sta_cmd(wmi_handle, &param);
        }
        break;
        case IEEE80211_DBGREQ_TWT_BTWT_REMOVE_STA:
        {
		struct wmi_twt_btwt_remove_sta_cmd_param param = {0};

		if (!wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_BCAST_TWT)) {
			qdf_err("BTWT feature is disabled");
			return -EINVAL;
		}

		param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
		qdf_mem_copy(param.peer_macaddr, req->dstmac, 6);
		param.dialog_id = req->data.twt_btwt_sta_inv_remove.dialog_id;

		status = wmi_unified_twt_btwt_remove_sta_cmd(wmi_handle, &param);
        }
        break;
#endif
	default:
		qdf_err("Unknown option %d", req->cmd);
		return -EINVAL;
	};

	if (status != QDF_STATUS_SUCCESS) {
		qdf_err("wmi dialog cmd returned failure");
		return qdf_status_to_os_return(status);
	}

	return 0;
}

void ol_ath_twt_attach(struct ieee80211com *ic)
{
	ic->ic_twt_req = ol_ath_twt_req;
}

/**
 * ol_ath_twt_session_stats_event_handler() - twt stats event handler
 * @sc: soc handle
 * @data: event data
 * @datalen: length of data
 *
 * Event handler for WMI_TWT_SESSION_STATS_EVENTID from FW
 *
 * Return: 0 on success
 */
int
ol_ath_twt_session_stats_event_handler(ol_soc_t sc, u_int8_t *data, u_int32_t datalen)
{
	ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
	struct wmi_unified *wmi_handle;
	struct wmi_twt_session_stats_event_param *params;
	struct wmi_host_twt_session_stats_info *h_twt;
	struct wlan_objmgr_psoc *psoc;
	QDF_STATUS status = QDF_STATUS_E_INVAL;
	uint8_t i;
	struct wlan_objmgr_peer *peer;
	uint32_t ev;
	cdp_config_param_type val = {0};
	ol_txrx_soc_handle soc_txrx_handle;
	struct wmi_host_twt_session_stats_info twt_se;

	psoc = soc->psoc_obj;
	soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

	params = qdf_mem_malloc(sizeof(struct wmi_twt_session_stats_event_param));
	if (!params) {
		return status;
	}
	wmi_handle = lmac_get_wmi_unified_hdl(soc->psoc_obj);
	if (wmi_handle) {
		status = wmi_extract_twt_session_stats_event(wmi_handle,
							     data, params);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_err("Could not extract twt session stats event");
			qdf_mem_free(params);
			return status;
		}
	} else {
		qdf_err("Could not get wmi_handle");
		qdf_mem_free(params);
		return status;
	}

	for (i = 0;i < params->num_sessions; i++) {
		status = wmi_extract_twt_session_stats_data(wmi_handle, data,
							    params, &twt_se, i);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_err("Could not extract twt session stats event");
			qdf_mem_free(params);
			return status;
		}

		h_twt = &twt_se;
		peer = wlan_objmgr_get_peer(psoc, params->pdev_id,
					    h_twt->peer_mac, WLAN_CP_STATS_ID);
		if (peer) {
			ev = h_twt->event_type;
			if (ev == HOST_TWT_SESSION_SETUP) {
				val.cdp_peer_param_in_twt = 1;
			} else if (ev == HOST_TWT_SESSION_TEARDOWN) {
				val.cdp_peer_param_in_twt = 0;
			}
			cdp_txrx_set_peer_param(soc_txrx_handle,
						h_twt->vdev_id,
						h_twt->peer_mac,
						CDP_CONFIG_IN_TWT, val);
#ifdef QCA_SUPPORT_CP_STATS
			peer_cp_stats_twt_event_type_update(peer,
							    h_twt->event_type);
			peer_cp_stats_twt_flow_id_update(peer,
							 h_twt->flow_id);
			peer_cp_stats_twt_bcast_update(peer,
						       h_twt->bcast);
			peer_cp_stats_twt_trig_update(peer,
						      h_twt->trig);
			peer_cp_stats_twt_announ_update(peer,
							h_twt->announ);
			peer_cp_stats_twt_dialog_id_update(peer,
							   h_twt->dialog_id);
			peer_cp_stats_twt_wake_dura_us_update(peer,
                                                              h_twt->wake_dura_us);
			peer_cp_stats_twt_wake_intvl_us_update(peer,
                                                               h_twt->wake_intvl_us);
			peer_cp_stats_twt_sp_offset_us_update(peer,
                                                              h_twt->sp_offset_us);
#endif
			wlan_objmgr_peer_release_ref(peer, WLAN_CP_STATS_ID);
		}
	}

	qdf_mem_free(params);
	return 0;
}

void ol_ath_soc_twt_attach(ol_ath_soc_softc_t *soc)
{
	struct wmi_unified *wmi_handle = NULL;

	wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);

	if(!wmi_handle)
		return;

	wmi_unified_register_event_handler(wmi_handle,
					   wmi_twt_enable_complete_event_id,
					   ol_ath_twt_enable_complete_event_handler,
					   WMI_RX_UMAC_CTX);

	wmi_unified_register_event_handler(wmi_handle,
					   wmi_twt_disable_complete_event_id,
					   ol_ath_twt_disable_complete_event_handler,
					   WMI_RX_UMAC_CTX);

	wmi_unified_register_event_handler(wmi_handle,
					   wmi_twt_session_stats_event_id,
					   ol_ath_twt_session_stats_event_handler,
					   WMI_RX_UMAC_CTX);
}
