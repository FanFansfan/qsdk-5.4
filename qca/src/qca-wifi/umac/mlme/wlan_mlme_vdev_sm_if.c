/*
 * Copyright (c) 2011-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <ieee80211_mlme_priv.h>
#include <ieee80211_ucfg.h>
#include <ieee80211_cfg80211.h>
#include <include/wlan_mlme_cmn.h>
#include <include/wlan_pdev_mlme.h>
#include <include/wlan_vdev_mlme.h>
#include <wlan_son_pub.h>
#include <ieee80211_mlme_dfs_dispatcher.h>
#if UNIFIED_SMARTANTENNA
#include <wlan_sa_api_utils_api.h>
#include <wlan_sa_api_utils_defs.h>
#endif
#include <wlan_mlme_dbg.h>
#include <wlan_utility.h>
#include "core/inc/vdev_mlme_sm_actions.h"
#include "vdev_mgr/core/src/vdev_mgr_ops.h"
#include <wlan_osif_priv.h>
#include <wlan_mlme_if.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <cfg_ucfg_api.h>
#include "vdev_mgr/core/src/vdev_mlme_sm.h"
#include <wlan_psoc_mlme.h>
#include <wlan_psoc_mlme_main.h>
#include <wlan_rnr.h>
#include <wlan_cm_api.h>
#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_ucfg_api.h>
#endif /* WLAN_SUPPORT_FILS */


QDF_STATUS mlme_register_ops(struct vdev_mlme_obj *vdev_mlme);
static os_timer_func(mlme_vdev_peer_del_timeout_handler);

enum mlme_sm_cmd_type {
    MLME_SM_CMD_PDEV_RADAR_DETECT,
};

struct mlme_sm_cmd_sched_data {
    struct wlan_objmgr_pdev *pdev;
    enum mlme_sm_cmd_type cmd_type;
    struct ieee80211_ath_channel *new_chan;
};

/*
 * mlme_sm_cmd_sched_cb(): cb function from scheduler context
 * @msg: scheduler msg data
 *
 * This cb will be called when a msg posted to the scheduler queue
 * has to be flushed
 *
 * Return: Success
 */
QDF_STATUS mlme_sm_cmd_flush_cb(struct scheduler_msg *msg)
{
	struct mlme_sm_cmd_sched_data *req = msg->bodyptr;

	switch (req->cmd_type) {
	case MLME_SM_CMD_PDEV_RADAR_DETECT:
		wlan_pdev_mlme_op_clear(req->pdev,
					WLAN_PDEV_OP_RADAR_DETECT_DEFER);
	break;
	}

	wlan_objmgr_pdev_release_ref(req->pdev, WLAN_SCHEDULER_ID);
	qdf_mem_free(req);
	return QDF_STATUS_SUCCESS;
}

/*
 * mlme_sm_cmd_sched_cb(): cb function from scheduler context
 * @msg: scheduler msg data
 *
 * This is the cb from the scheduler context where MBSSID scenario
 * related vdev cmds are processed
 *
 * Return: Success if vdev cmd is processed else error.
 */
QDF_STATUS mlme_sm_cmd_sched_cb(struct scheduler_msg *msg)
{
	struct mlme_sm_cmd_sched_data *req = msg->bodyptr;
	wlan_dev_t ic = wlan_pdev_get_mlme_ext_obj(req->pdev);

	if (!ic) {
		qdf_err("NULL ic");
		wlan_objmgr_pdev_release_ref(req->pdev, WLAN_SCHEDULER_ID);
		qdf_mem_free(req);
		return QDF_STATUS_SUCCESS;
	}

	switch (req->cmd_type) {
	case MLME_SM_CMD_PDEV_RADAR_DETECT:
		wlan_pdev_mlme_vdev_sm_notify_radar_ind(req->pdev,
							req->new_chan);
	break;
	default:
		qdf_err("Unknown cmd type");
	}

	wlan_objmgr_pdev_release_ref(req->pdev, WLAN_SCHEDULER_ID);
	qdf_mem_free(req);

	return QDF_STATUS_SUCCESS;
}

/*
 * mlme_sm_cmd_schedule_req(): Form a scheduler msg to be posted for
 * vdev operations in MBSSID scenario
 * @vdev: Object manager vdev
 * @cmd_type: Serialization command type
 *
 * Return: Success if the request is posted to the scheduler, else error
 */
QDF_STATUS mlme_sm_cmd_schedule_req(struct wlan_objmgr_pdev *pdev,
				    enum mlme_sm_cmd_type cmd_type,
				    struct ieee80211_ath_channel *chan)
{
	struct scheduler_msg msg = {0};
	struct mlme_sm_cmd_sched_data *req;
	QDF_STATUS ret = QDF_STATUS_E_FAILURE;

	if (!pdev)
		return QDF_STATUS_E_INVAL;

	req = qdf_mem_malloc(sizeof(*req));
	if (!req) {
		qdf_err("req is NULL");
		return ret;
	}

	ret = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_SCHEDULER_ID);
	if (QDF_IS_STATUS_ERROR(ret)) {
		qdf_err("unable to get reference");
		goto sched_error;
	}

	req->pdev = pdev;
	req->cmd_type = cmd_type;
	req->new_chan = chan;

	msg.bodyptr = req;
	msg.callback = mlme_sm_cmd_sched_cb;
	msg.flush_callback = mlme_sm_cmd_flush_cb;

	ret = scheduler_post_message(QDF_MODULE_ID_OS_IF,
				QDF_MODULE_ID_OS_IF, QDF_MODULE_ID_OS_IF, &msg);
	if (QDF_IS_STATUS_ERROR(ret)) {
		wlan_objmgr_pdev_release_ref(pdev, WLAN_SCHEDULER_ID);
		qdf_err("failed to post scheduler_msg");
		goto sched_error;
	}
	return ret;

sched_error:
	qdf_mem_free(req);
	return ret;
}

QDF_STATUS mlme_vdev_reset_proto_params_cb(
                        struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_channel *bss_chan;

	if (!vdev_mlme) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;

	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	bss_chan = wlan_vdev_mlme_get_bss_chan(vdev);
	if (bss_chan)
		ieee80211_update_vdev_chan(bss_chan, IEEE80211_CHAN_ANYC);
	else
		mlme_err("(vdev-id:%d) BSS chan is not allocated",
						    wlan_vdev_get_id(vdev));

	if (vdev_mlme->mgmt.generic.ssid_len) {
		qdf_mem_zero(vdev_mlme->mgmt.generic.ssid, WLAN_SSID_MAX_LEN+1);
		vdev_mlme->mgmt.generic.ssid_len = 0;
	}

	return QDF_STATUS_SUCCESS;
}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
static QDF_STATUS mlme_sta_cac_start(struct ieee80211com *ic,
                                        struct ieee80211vap *vap)
{
	int cac_timeout;
	if (mlme_is_stacac_needed(vap)) {
		qdf_info(
			"STACAC_start chan %d timeout %d sec, curr time:%d sec",
			ic->ic_curchan->ic_freq,
			ieee80211_dfs_get_cac_timeout(ic, ic->ic_curchan),
			(qdf_system_ticks_to_msecs(qdf_system_ticks()) / 1000));
		mlme_set_stacac_running(vap,1);
		/* start CAC timer */
		ieee80211_dfs_cac_start(vap);
		mlme_reset_mlme_req(vap);
		cac_timeout = ieee80211_dfs_get_cac_timeout(ic, ic->ic_curchan);
		wlan_cfg80211_dfs_cac_start(vap, cac_timeout);
		IEEE80211_DELIVER_EVENT_CAC_STARTED(vap,
					ic->ic_curchan->ic_freq, cac_timeout);
		return QDF_STATUS_SUCCESS;
	}
	return QDF_STATUS_E_FAILURE;
}
#endif

static int
ieee80211_vap_wme_param_update(struct ieee80211com *ic, wlan_if_t vaphandle)
{
    enum ieee80211_phymode mode;
    int i;
    struct ieee80211_wme_state *wme;

    wme = &vaphandle->iv_wmestate;
    mode = ieee80211_chan2mode(vaphandle->iv_bsschan);
    for(i = 0;i< WME_NUM_AC;i++){
        ic->phyParamForAC[i][mode].logcwmin = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmin;
        ic->phyParamForAC[i][mode].logcwmax = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_logcwmax;
        ic->phyParamForAC[i][mode].aifsn = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_aifsn;
        ic->phyParamForAC[i][mode].txopLimit = wme->wme_wmeChanParams.cap_wmeParams[i].wmep_txopLimit;
        ic->bssPhyParamForAC[i][mode].logcwmin = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_logcwmin;
        ic->bssPhyParamForAC[i][mode].logcwmax = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_logcwmax;
        ic->bssPhyParamForAC[i][mode].aifsn = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_aifsn;
        ic->bssPhyParamForAC[i][mode].txopLimit = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_txopLimit;
        ic->bssPhyParamForAC[i][mode].acm = wme->wme_wmeBssChanParams.cap_wmeParams[i].wmep_acm;
    }
    return 0;
}

static inline void ieee80211_update_chan_history(struct ieee80211com  *ic)
{
    ic->ic_chanhist[ic->ic_chanidx].chanid = (ic->ic_curchan)->ic_ieee;
    ic->ic_chanhist[ic->ic_chanidx].chanband = wlan_reg_freq_to_band(ic->ic_curchan->ic_freq);
    ic->ic_chanhist[ic->ic_chanidx].chanjiffies = OS_GET_TIMESTAMP();
    ic->ic_chanidx == (IEEE80211_CHAN_MAXHIST - 1) ? ic->ic_chanidx = 0 : ++(ic->ic_chanidx);
}

/**
 * ieee80211_coex_derive_phymode:
 * Check if the current selected channel is marked as intolerant due to
 * 20/40MHz coexistence in the 2.4GHz band and return the correct phymode.
 *
 * Parameters:
 * ic      : Pointer to ic structure
 * des_chan: Pointer to the wlan_channel structure for the vdev des chan
 *
 * Return:
 * Desired phymode: Success
 * AUTO           : Failure
 */
enum ieee80211_phymode ieee80211_coex_derive_phymode(struct ieee80211com *ic,
						     struct wlan_channel *des_chan)
{
	enum ieee80211_phymode phymode;

	if (!ic) {
		qdf_err("Invalid ic");
		return IEEE80211_MODE_AUTO;
	}

	if (!des_chan) {
		qdf_err("Invalid channel");
		return IEEE80211_MODE_AUTO;
	}

	phymode = wlan_vdev_get_ieee_phymode(des_chan->ch_phymode);

	/*
	 * If 20/40MHz coexistence is enabled, move the phymode down to
	 * 20MHz for HT40 and HE40 modes.
	 */
	if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE) && (IEEE80211_IS_FLAG_40INTOL(des_chan->ch_flags))) {
		switch(phymode) {
			case IEEE80211_MODE_11NG_HT40:
			case IEEE80211_MODE_11NG_HT40PLUS:
			case IEEE80211_MODE_11NG_HT40MINUS:
                            phymode = IEEE80211_MODE_11NG_HT20;
			break;

			case IEEE80211_MODE_11AXG_HE40:
			case IEEE80211_MODE_11AXG_HE40PLUS:
			case IEEE80211_MODE_11AXG_HE40MINUS:
                            phymode = IEEE80211_MODE_11AXG_HE20;
			break;

			default:
			break;
		}
	}

	return phymode;
}

/*
 * ieee80211_reset_dcsim:
 * Reset DCS interference management depending on if the VAP was
 * brought up with fixed channel configuration or ACS.
 * Don't enable DCS WLAN IM for fixed channel configuration in order to avoid
 * moving to a channel other than the preset one.
 *
 * Parameters:
 * @ic: Pointer to the ic structure
 */
static void ieee80211_reset_dcsim(struct ieee80211com *ic)
{
#if ATH_SUPPORT_VOW_DCS
	if (!ic->ic_eacs_done && !ieee80211_get_num_ap_vaps_up(ic)) {
		/* disable dcs when channel is not chosen by EACS */
		ic->ic_disable_dcsim(ic);
	} else {
		ic->ic_eacs_done = 0;
	}
#endif

	return;
}

void ieee80211_update_peer_cw(struct ieee80211com *ic,
			      struct ieee80211vap *vap)
{
	struct node_chan_width_switch_params pi = {0};

	/* Update new channel and width for associated STA's */
	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		pi.max_peers = wlan_vdev_get_peer_count(vap->vdev_obj);
		pi.chan_width_peer_list = qdf_mem_malloc(sizeof(struct node_chan_width_switch_info) *
							 pi.max_peers);

		if (!pi.chan_width_peer_list) {
			qdf_err("Error in allocating peer chwidth list");

		/* Sanity check is done within ieee80211_node_update_chan_and_phymode
		 * This is to ensure, in the case of failure to update target info
		 * downgrades will still be supported (as before) */
		}

		wlan_iterate_station_list(vap, ieee80211_node_update_chan_and_phymode, &pi);

		if (pi.chan_width_peer_list) {
			/* Peer information will be sent to the target only if
			 * the necessary space was allocated */
			if (pi.num_peers > 0) {
				ic->ic_node_chan_width_switch(&pi, vap);
			}

			qdf_mem_free(pi.chan_width_peer_list);
		}
	}
}

QDF_STATUS mlme_ext_restart_bmiss_sched_cb(struct scheduler_msg *msg)
{
	struct wlan_objmgr_vdev *vdev = msg->bodyptr;
	struct ieee80211vap *vap;

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
		return QDF_STATUS_E_FAILURE;
	}

	IEEE80211_DELIVER_EVENT_BEACON_MISS(vap);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_ext_restart_bmiss_flush_cb(struct scheduler_msg *msg)
{
	struct wlan_objmgr_vdev *vdev = msg->bodyptr;

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_start_continue_cb(struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;
	struct ieee80211com *ic;
	struct ieee80211_node *ni;
	struct ieee80211vap *vap;
	struct ieee80211_ath_channel *chan, *des_ic_chan;
	struct wlan_channel *des_chan;
	enum QDF_OPMODE opmode;
	uint8_t numvaps_up = 0;
	struct ieee80211_wme_state wme_zero = {0};
	uint8_t restart = 0;
	int8_t error;
	struct cdp_soc_t *soc_txrx_handle;
	enum ieee80211_phymode phymode;
	struct wlan_cm_vdev_reassoc_req req = {0};
	struct scheduler_msg msg = {0};

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (pdev == NULL) {
		mlme_err("(vdev-id:%d) PDEV is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
	if (!ic) {
		mlme_err("(vdev-id:%d) ic is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	soc_txrx_handle = wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(pdev));

	if (!soc_txrx_handle) {
		mlme_err("Failed to get DP handles");
		return QDF_STATUS_E_FAILURE;
	}

	if (event_data_len == 1)
		restart = *((uint8_t *)event_data);

	des_chan = wlan_vdev_mlme_get_des_chan(vdev);
	opmode = wlan_vdev_mlme_get_opmode(vdev);

	/*
	 * Derive the appropriate phymode after checking the 2.4GHz
	 * 20/40MHz intolerance flags for the desired channel.
	 */
	phymode = ieee80211_coex_derive_phymode(ic, des_chan);
	des_ic_chan = ieee80211_find_dot11_channel(ic, des_chan->ch_freq,
                              des_chan->ch_cfreq2,
                              wlan_vdev_get_ieee_phymode(des_chan->ch_phymode));
	chan =  ieee80211_find_dot11_channel(ic,des_chan->ch_freq,
					     des_chan->ch_cfreq2, phymode);
	numvaps_up = ieee80211_get_num_ap_vaps_up(ic);
	if (!chan) {
		if (!numvaps_up) {
			mlme_err("(vdev-id:%d) chan is NULL (ieee: %d)",
					wlan_vdev_get_id(vdev), des_chan->ch_ieee);
			return QDF_STATUS_E_FAILURE;
		} else {
			/*
			 * There are UP vaps, go ahead and use the ic's
			 * current operating channel.
			 */
			chan = ic->ic_curchan;
		}
	}

	switch (opmode) {

	case QDF_MONITOR_MODE:
		/* Handle same as HOSTAP */
	case QDF_SAP_MODE:
		ni = vap->iv_bss;
		/* Skip re-assigning ni_intval for LP IOT vap */
		if (!(vap->iv_create_flags & IEEE80211_LP_IOT_VAP))
			ni->ni_intval = ic->ic_intval;

		if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
		    vap->iv_special_vap_mode && !restart) {
		    if (cdp_set_monitor_mode(soc_txrx_handle,
					     wlan_vdev_get_id(vap->vdev_obj),
					     vap->iv_smart_monitor_vap)) {
			mlme_err("Unable to configure monitor ring buffers for special vap");
			return QDF_STATUS_E_FAILURE;
		    }
		    vap->iv_special_vap_is_monitor = 1;
		}

		/* Update RNR cache during channel switch */
		if (restart && vdev->vdev_mlme.bss_chan) {
			/* vdev->vdev_mlme.bss_chan is the previous channel for
			 * the vap and chan is the destination channel for CSA
			 */
			if (wlan_reg_freq_to_band(vdev->vdev_mlme.bss_chan->ch_freq) == REG_BAND_6G) {
				if (IEEE80211_IS_CHAN_6GHZ(chan)) {
					/* This is a case where we are only
					 * changing channel but band is still 6G
					 * So simple cache update is sufficient
					 */
					wlan_update_6ghz_rnr_cache(vap, 0);
				} else if (IEEE80211_IS_CHAN_5GHZ(chan)) {
					/* This is a case where we are changing
					 * band from 6G to 5G. So vap must be
					 * removed from cache.
					 */
					wlan_remove_vap_from_6ghz_rnr_cache(vap);
				}
			} else if (wlan_reg_freq_to_band(vdev->vdev_mlme.bss_chan->ch_freq) == REG_BAND_5G) {
				if (IEEE80211_IS_CHAN_6GHZ(chan)) {
					/* This is a case where we are switching
					 * from 5G band to 6G. So vap must be
					 * added to cache.
					 */
					wlan_update_6ghz_rnr_cache(vap, 1);
				}
			}
		}

#ifdef WLAN_SUPPORT_FILS
		/*
		 * At this point 'vdev_mlme.bss_chan' refers to the previous
		 * channel while 'chan' points to new channel. When moving from
		 * 6GHz to 5GHz, FILS offload will need to be disabled by
		 * updating the FW with zero period to disable FILS or broadcast
		 * probe responses.
		 */
		if (vdev->vdev_mlme.bss_chan &&
		    (wlan_reg_freq_to_band(vdev->vdev_mlme.bss_chan->ch_freq) == REG_BAND_6G) &&
		    IEEE80211_IS_CHAN_5GHZ(chan)) {
			wlan_vdev_mlme_feat_ext_cap_clear(vap->vdev_obj,
						WLAN_VDEV_FEXT_FILS_DISC_6G_SAP);
			ucfg_fils_config(vap->vdev_obj, 0);
		}
#endif /* WLAN_SUPPORT_FILS */


		/*
		 * if there is a vap already running.
		 * ignore the desired channel and use the
		 * operating channel of the other vap.
		 */
		if (numvaps_up == 0) {
			 /* 20/40 Mhz coexistence  handler */
			ic->ic_prevchan = ic->ic_curchan;
			ic->ic_curchan = chan;
			/* update max channel power to max regpower of current channel */
			ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);
			/* Update the channel for monitor mode path */
			cdp_set_curchan(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(pdev), chan->ic_freq);

			/* ieee80211 Layer - Default Configuration */
			vap->iv_bsschan = ic->ic_curchan;

			/* This function was being called before "vap->iv_bsschan = ic->ic_curchan" and now moved here.
			 * This fixes a bug where the wme parameters are set to FW before the current channel gets
			 * updated("vap->iv_bsschan"). The "ic_flags" in "iv_bsschan" is used to get the corresponding
			 * phy mode with respect to the channel (ieee80211_chan2mode), and this phy mode is used to set the
			 * wme parameters to FW. IR-088422.
			 */
			if (vap->iv_wme_reset) {
			   ieee80211_wme_initparams_locked(vap);
			   vap->iv_wme_reset = 0;
			} else {
			   ieee80211_wme_updateparams_locked(vap);
			}

			if (memcmp(&wme_zero, &vap->iv_wmestate, sizeof(wme_zero)) != 0) {
				ieee80211_vap_wme_param_update(ic, vap);
			}
			/* reset erp state */
			ieee80211_reset_erp(ic, ic->ic_curmode, vap->iv_opmode);

			/* reset DCS WLAN IM */
			ieee80211_reset_dcsim(ic);
		} else {
			/* Copy the wme params from ic to vap structure if vaps are up for the first time */
			if(qdf_mem_cmp(&wme_zero, &vap->iv_wmestate,
				 	sizeof(wme_zero)) == 0)
				qdf_mem_copy(&vap->iv_wmestate,
					     &ic->ic_wme, sizeof(ic->ic_wme));

			/* ieee80211 Layer - Default Configuration */
			vap->iv_bsschan = ic->ic_curchan;
			if (vap->iv_wme_reset) {
			   ieee80211_wme_initparams_locked(vap);
			   vap->iv_wme_reset = 0;
			} else {
			   ieee80211_wme_updateparams_locked(vap);
			}
		}

		if (ieee80211_get_num_ap_vaps_up(ic) == 0) {
			/*update channel history*/
			ieee80211_update_chan_history(ic);
		}

		if (vdev->vdev_mlme.bss_chan) {
		    QDF_TRACE(QDF_MODULE_ID_DFS, QDF_TRACE_LEVEL_INFO,
				       "vdev[%d] ieee chan:%d freq:%d",
				       wlan_vdev_get_id(vdev),
				       vap->iv_bsschan->ic_ieee,
				       vap->iv_bsschan->ic_freq);
			ieee80211_update_vdev_chan(vdev->vdev_mlme.bss_chan,
						   vap->iv_bsschan);
		}
		if (vap->iv_bss) {
		    vap->iv_bss->ni_chan = vap->iv_bsschan;
		}

		ic->ic_opmode = ieee80211_new_opmode(vap, true);

		vap->iv_enable_radar_table(ic, vap, 1, 1);

		if(IEEE80211_IS_CHAN_DFS(ic->ic_curchan))
		{
			/*
			 * When there is radar detect in Repeater, repeater sends RCSAs, CSAs and
			 * switches to new next channel, in ind rpt case repeater AP could start
			 * beaconing before Root comes up, next channel needs to be changed
			 */
			if(!ic->ic_tx_next_ch ||
			   ic->ic_curchan == ic->ic_tx_next_ch)
				ieee80211_update_dfs_next_channel(ic);
		}
		else {
			ic->ic_tx_next_ch = NULL;
		}
		// Tell the vap that the channel change has happened.
		/* For Band steering enabled:- it will be sent from ieee80211_state_event*/
		IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(vap, ic->ic_curchan);
		ieee80211com_clear_flags(ic, IEEE80211_F_DFS_CHANSWITCH_PENDING);
		vap->channel_switch_state = 0;

		if (restart) {
			uint8_t peer_ext_nss_update_count = 0;
			/* ni_phymode is updated based on iv_cur_mode if new channel
			* width is 160. Hence
			* update iv_cur_mode based on new target channel's
			* width.
			*/
			vap->iv_cur_mode = ieee80211_chan2mode(chan);
			ieee80211_update_peer_cw(ic, vap);
			wlan_iterate_station_list(vap,
				update_peer_nss, &peer_ext_nss_update_count);
			if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
				/* Restart dtim-count in case of mbssid vap */
				ieee80211_mbssid_update_mbssie_cache_entry(
						vap, MBSS_CACHE_ENTRY_IDX);
			}
		}

		if (opmode == QDF_SAP_MODE)
			error = ieee80211_mlme_create_infra_continue(vap);
		else
			error = wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
				WLAN_VDEV_SM_EV_START_SUCCESS, 0, NULL);
		if (!error)
			IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(
					vap, IEEE80211_STATUS_SUCCESS);
		break;
	case QDF_STA_MODE:
		ni = vap->iv_bss;

		/*
		 * The channel sent for vdev restart/start is different from the
		 * BSS channel. Proceeding further results in invalid channel
		 * set for the STA. Stop connection SM and return failure. */
		if (!ni || des_ic_chan != ni->ni_chan) {
			if (restart) {
				msg.bodyptr = vdev;
				msg.callback = mlme_ext_restart_bmiss_sched_cb;
				msg.flush_callback =
					mlme_ext_restart_bmiss_flush_cb;
				wlan_objmgr_vdev_try_get_ref(vdev,
						WLAN_SCHEDULER_ID);
				scheduler_post_message(QDF_MODULE_ID_MLME,
						QDF_MODULE_ID_MLME,
						QDF_MODULE_ID_MLME, &msg);
				return QDF_STATUS_SUCCESS;
			}

			ieee80211_mlme_join_infra_continue(vap, EINVAL);
			return QDF_STATUS_E_FAILURE;
		}

		ieee80211_update_vdev_chan(vdev->vdev_mlme.bss_chan, chan);

		if (!ieee80211_ic_rpt_max_phy_is_set(ic)||
		    !ieee80211_ic_enh_ind_rpt_is_set(ic)) {
			ic->ic_prevchan = ic->ic_curchan;
			ic->ic_curchan = chan;
		}

		vap->iv_bsschan = chan;

		if(restart && ni) {
		/* Updated chwidth & phymode is sent to FW as part of ol_ath_send_peer_assoc */
			ni->ni_chwidth = ic->ic_cwm_get_width(ic);
			ieee80211_update_ht_vht_he_phymode(ic, ni);

			/* Ensure that the mitigation logic for Tx/Rx Supported
			 * HE-MCS and NSS validation failures for 80+80/160 MHz
			 * applied in ieee80211_hecap_parse_mcs_nss() is
			 * preserved here. If the validation failure had
			 * occurred for HE80, HE capability would have been
			 * marked as unavailable in ni flags by
			 * ieee80211_hecap_parse_mcs_nss(), and the ni would
			 * not have an HE PHY mode, hence there is no need to
			 * consider HE80 below.
			*/
			switch(ni->ni_phymode) {
			case IEEE80211_MODE_11AXA_HE80_80:
				if (!ni->ni_he.he_basic_txrxmcsnss_req_met_80_80) {
					qdf_info("Valid Tx/Rx Supported HE-MCS and NSS info for 80+80 MHz not found - adjusting ni chwidth and phymode to 160 MHz");
					ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
					ni->ni_phymode =
						IEEE80211_MODE_11AXA_HE160;
				}
				/* Fall through */
			case IEEE80211_MODE_11AXA_HE160:
				if (!ni->ni_he.he_basic_txrxmcsnss_req_met_160) {
					qdf_info("Valid Tx/Rx Supported HE-MCS and NSS info for 160 MHz not found - adjusting ni chwidth and phymode to 80 MHz");
					ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
					ni->ni_phymode =
						IEEE80211_MODE_11AXA_HE80;
				}
			}
		}

		/* update max channel power to max regpower of current channel */
		ieee80211com_set_curchanmaxpwr(ic, chan->ic_maxregpower);
		/* Update the channel for monitor mode path */
		cdp_set_curchan(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(pdev), chan->ic_freq);

		/* ieee80211 Layer - Default Configuration */
		if (!ieee80211_ic_rpt_max_phy_is_set(ic)||
		    !ieee80211_ic_enh_ind_rpt_is_set(ic)) {
			vap->iv_bsschan = ic->ic_curchan;
                }

		/* XXX reset erp state */
		ieee80211_reset_erp(ic, ic->ic_curmode, vap->iv_opmode);
		ieee80211_wme_initparams(vap);

		vap->iv_enable_radar_table(ic, vap, 0, 0);
		if (wlan_cm_get_active_req_type(vap->vdev_obj) == CM_ROAM_ACTIVE)
			wlan_cm_get_active_reassoc_req(vap->vdev_obj, &req);

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
		if (mlme_sta_cac_start(ic, vap) == QDF_STATUS_SUCCESS) {
			wlan_mlme_inc_act_cmd_timeout(vdev,
					WLAN_SER_CMD_VDEV_CONNECT);
			wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
				WLAN_VDEV_SM_EV_DFS_CAC_WAIT, 0, NULL);
		}
		else
#endif
		{
			wlan_assoc_sm_start(wlan_mlme_get_assoc_sm_handle(vap->vdev_obj),
					    mlme_cm_get_active_scan_entry(vap),
					    req.prev_bssid.bytes);
			ieee80211_mlme_join_infra_continue(vap,EOK);
		}

		if (!vap->iv_quick_reconnect && restart) {
			wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
				WLAN_VDEV_SM_EV_START_SUCCESS, 0, NULL);
		}
		// Tell the vap that the channel change has happened.
		/* For Band steering enabled:- it will be sent from ieee80211_state_event*/
		IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(vap, ic->ic_curchan);
		ieee80211com_clear_flags(ic, IEEE80211_F_DFS_CHANSWITCH_PENDING);
		vap->channel_switch_state = 0;
		break;
	default:
		break;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_sta_conn_start_cb(struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct ieee80211vap *vap;
	struct ieee80211_mlme_priv *mlme_priv;
	struct wlan_objmgr_vdev *vdev;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv = vap->iv_mlme_priv;
	if (!mlme_priv) {
		mlme_err("(vdev-id:%d) mlme_priv  is NULL",
			 wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
	mlme_set_stacac_valid(vap,1);
#endif
	wlan_assoc_sm_start(wlan_mlme_get_assoc_sm_handle(vap->vdev_obj),
			    mlme_cm_get_active_scan_entry(vap), NULL);
	mlme_priv->im_request_type = MLME_REQ_JOIN_INFRA;
	ieee80211_mlme_join_infra_continue(vap,EOK);
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
	mlme_priv->im_is_stacac_running = 0;
#endif
	qdf_info("STACAC expired");

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_sta_disconn_start_cb(struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct ieee80211vap *vap;
	struct wlan_objmgr_vdev *vdev;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	if (vap->iv_opmode == IEEE80211_M_STA)
		wlan_assoc_sm_stop(wlan_mlme_get_assoc_sm_handle(vap->vdev_obj), 0);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_start_req_failed_cb(struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct ieee80211vap *vap;
	struct wlan_objmgr_vdev *vdev;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	if (vap->iv_opmode == IEEE80211_M_STA) {
		ieee80211_reset_bss(vap);
		ieee80211_mlme_join_infra_continue(vap, EINVAL);
	}
	else if (vap->iv_opmode == IEEE80211_M_HOSTAP)
		ieee80211_mlme_create_infra_continue_async(vap, EINVAL);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_notify_up_complete_cb(
                        struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_vdev *vdev;
	struct ieee80211vap *vap;
	ieee80211_vap_event evt;
	struct wlan_channel *iter_des_chan = NULL;
	struct ieee80211vap *tmpvap;
	struct ieee80211com *ic;
	uint8_t restart_progress = 0;
	uint8_t issue_evt = 0;
	enum wlan_vdev_sm_evt event;
	cm_ext_t *cm_ext_handle = NULL;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	evt.type = IEEE80211_VAP_UP;
	ieee80211_vap_deliver_event(vap, &evt);

	ic = vap->iv_ic;
	/* If any VDEV has moved to RESTART_PROGRESS substate, but this VDEV
	 * missed the event, then move to RESTART_PROGRESS sub state
	 */
	if ((wlan_pdev_mlme_op_get(ic->ic_pdev_obj,
				   WLAN_PDEV_OP_RESTART_INPROGRESS)) &&
	    (!wlan_pdev_mlme_op_get(ic->ic_pdev_obj,
				    WLAN_PDEV_OP_RADAR_DETECT_DEFER))) {
		TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
			if (wlan_vdev_is_restart_progress(tmpvap->vdev_obj) ==
						QDF_STATUS_SUCCESS) {
				iter_des_chan = wlan_vdev_mlme_get_des_chan(
							tmpvap->vdev_obj);
				restart_progress = 1;
				event = WLAN_VDEV_SM_EV_FW_VDEV_RESTART;
				mlme_err("vdev (%d)Issuing vdev SM_EV_FW_VDEV_RESTART",
					 wlan_vdev_get_id(vdev));
				issue_evt = 1;
				break;
			}
		}
	}

	/* If any VDEV has moved to CSA_RESTART sub state, but this non-sta VDEV
	 * missed event, then move to CSA_RESTART sub state
	 */
	if ((!restart_progress) &&
	    (wlan_vdev_mlme_get_opmode(vdev) != QDF_STA_MODE)) {
		TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
			if (wlan_vdev_mlme_is_csa_restart(tmpvap->vdev_obj) ==
						QDF_STATUS_SUCCESS) {
				iter_des_chan = wlan_vdev_mlme_get_des_chan(
							tmpvap->vdev_obj);
				event = WLAN_VDEV_SM_EV_CSA_RESTART;
				mlme_err("vdev (%d)Issuing vdev SM_EV_CSA_RESTART",
				 wlan_vdev_get_id(vdev));
				issue_evt = 1;
				break;
			}
		}
	}
	if (iter_des_chan)
		wlan_chan_copy(vdev->vdev_mlme.des_chan, iter_des_chan);

	if (issue_evt)
		wlan_vdev_mlme_sm_deliver_evt_sync(vdev, event, 0, NULL);

	if (vap->iv_opmode == IEEE80211_M_STA) {
		cm_ext_handle = wlan_cm_get_ext_hdl(vdev);
		if (!cm_ext_handle)
			return QDF_STATUS_E_FAILURE;

		cm_ext_handle->cm_conn_rsp.connect_status = QDF_STATUS_SUCCESS;
		wlan_mlme_dispatch_cm_resp(vap, CM_CONNECT_RESP);
		return QDF_STATUS_SUCCESS;
	}

	wlan_mlme_release_vdev_req(vdev_mlme->vdev,
				   WLAN_SER_CMD_VDEV_START_BSS, EOK);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_update_beacon_cb(struct vdev_mlme_obj *vdev_mlme,
                        enum beacon_update_op op,
			uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;
	struct ieee80211com *ic;
	struct ieee80211vap *vap;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;

	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (pdev == NULL) {
		mlme_err("(vdev-id:%d) PDEV is NULL",
				wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
	if (!ic) {
		mlme_err("(vdev-id:%d) ic is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	switch (op) {
	case BEACON_INIT:
		/* handled as part of vap->iv_up() */
		break;
	case BEACON_UPDATE:
		break;
	case BEACON_CSA:
		/* If there is at least one active AP VAP then it
		 * will finish the CSA and post the following event
		 * (WLAN_VDEV_SM_EV_CSA_COMPLETE) to the monitor/MESH VAP's
		 * state machine. */
		if ((vap->iv_opmode == IEEE80211_M_MONITOR)
		    || wlan_is_non_beaconing_ap_vap(vap)) {
			if (!ieee80211_get_num_beaconing_vaps(ic) ||
			    !ieee80211_num_apvap_running(ic)) {
				/* In case of only vaps in monitor or/and no-beacon
				 * mesh mode, no CSA is required,
				 * move to RESTART state. Also if monitor vdev has missed CSA_COMPLETE
				 * due to delay in processing EV_CSA_RESTART, then deliver EV_CSA_COMPLETE
				 * to move to RESTART state
				 */
				wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
					WLAN_VDEV_SM_EV_CSA_COMPLETE, 0, NULL);
			}
		}
		else {
			ic->ic_flags |= IEEE80211_F_CHANSWITCH;
			ic->ic_flags_ext2 |= IEEE80211_FEXT2_CSA_WAIT;
			wlan_vdev_beacon_update(vap);
		}
		break;
	case BEACON_FREE:
		ic->ic_beacon_free(vap);
		break;
	default:
		break;
	}

	return QDF_STATUS_SUCCESS;
}

static
void mlme_vdev_peer_timeout_rel_handler(struct ieee80211vap *vap)
{
	qdf_list_t *logical_del_peerlist;
	struct wlan_objmgr_peer *peer;
	qdf_list_node_t *peerlist;
	struct wlan_logically_del_peer *temp_peer = NULL;
	struct ieee80211_node *ni;

	if (!vap || !vap->iv_peer_rel_ref) {
		mlme_err("Null vap, vap: 0x%pK", vap);
		return;
	}

	logical_del_peerlist =
		wlan_objmgr_vdev_get_log_del_peer_list(vap->vdev_obj,
						       WLAN_MLME_SB_ID);
	if (!logical_del_peerlist)
		return;

	while (QDF_IS_STATUS_SUCCESS(qdf_list_remove_front(logical_del_peerlist,
				     &peerlist))) {
		temp_peer = qdf_container_of(peerlist,
					     struct wlan_logically_del_peer,
					     list);
		peer = temp_peer->peer;
		ni = wlan_peer_get_mlme_ext_obj(peer);

		mlme_err("peer mac: %s", ether_sprintf(peer->macaddr));

		if (vap->iv_peer_rel_ref(vap, ni, peer->macaddr))
			mlme_err("Failed to handle peer del failure");
		/*
		 * Release the ref taken during wlan_objmgr_vdev_get_log_del_peer_list
		 */
		wlan_objmgr_peer_release_ref(peer, WLAN_MLME_SB_ID);
		qdf_mem_free(temp_peer);
	}
	qdf_list_destroy(logical_del_peerlist);
	qdf_mem_free(logical_del_peerlist);
}

static os_timer_func(mlme_vdev_peer_del_timeout_handler)
{
	struct ieee80211vap *vap;

	OS_GET_TIMER_ARG(vap, struct ieee80211vap *);
	if (wlan_vdev_get_peer_count(vap->vdev_obj) <= 1)
		return;

	mlme_err("Print peer refs timed out for vdev:%u",
		 wlan_vdev_get_id(vap->vdev_obj));
#if VDEV_ASSERT_MANAGEMENT
	/*
	 * Release references held for pending peer delete response
	 */
	mlme_vdev_peer_timeout_rel_handler(vap);

	if (wlan_vdev_get_peer_count(vap->vdev_obj) > 1) {
		if (vap->iv_ic->ic_print_peer_refs)
			vap->iv_ic->ic_print_peer_refs(vap->vdev_obj, false);
	}
#else
	/*
	 * Print any leaked peer refs and do FW assert if there are any missing
	 * peer delete responses or mgmt completions for STA peers
	 */
	if (vap->iv_ic->ic_print_peer_refs)
		vap->iv_ic->ic_print_peer_refs(vap->vdev_obj, true);
#endif

	return;
}

static os_timer_func(mlme_vdev_peer_del_bss_tid_flush)
{
	struct ieee80211vap *vap;
	struct wlan_objmgr_vdev *vdev;
	struct ol_ath_softc_net80211 *scn;
	ol_ath_soc_softc_t *soc;

	OS_GET_TIMER_ARG(vap, struct ieee80211vap *);

	vdev = vap->vdev_obj;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return;
	}

	mlme_err("Peer del wait timed out for vdev:%u, flush bss peer tids",
		 wlan_vdev_get_id(vdev));


	if (wlan_vdev_mlme_get_state(vdev) != WLAN_VDEV_S_SUSPEND) {
		mlme_err("VDEV %u: is not in SUSPEND state, current state %d",
			 wlan_vdev_get_id(vdev),
			 wlan_vdev_mlme_get_state(vdev));
		return;
	}

	/* flush bss peer tids */
	mlme_ext_vap_flush_bss_peer_tids(vap);

	if (wlan_vdev_get_peer_count(vdev) <= 1)
		return;

	/* Applicable for only lithium platform */
	if (vap->iv_ic->ic_print_peer_refs) {
		scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
		soc = scn->soc;

		qdf_timer_mod(&vap->peer_del_wait_timer,
			      soc->peer_del_wait_time);
	}

	return;
}

static void mlme_vdev_cleanup_peers(struct ieee80211vap *vap)
{
	if (wlan_vdev_get_peer_count(vap->vdev_obj) == 1)
		return;

	/* Flush any pending mgmt frame in host queue for this vap */
	ieee80211_flush_vap_mgmt_queue(vap, false);
	/* cleanup all associated sta peers on this vap */
	wlan_iterate_station_list(vap, cleanup_sta_peer, NULL);
	/* cleanup all unassociated sta peers on this vap */
	wlan_iterate_unassoc_sta_list(vap, cleanup_sta_peer, NULL);
	/* flush bss peer tids */
	mlme_ext_vap_flush_bss_peer_tids(vap);

	return;
}

static os_timer_func(mlme_vdev_force_cleanup_peers)
{
	struct ieee80211vap *vap;

	OS_GET_TIMER_ARG(vap, struct ieee80211vap *);

	mlme_vdev_cleanup_peers(vap);
}

static void mlme_vdev_get_temp_peer_count(
					struct wlan_objmgr_vdev *vdev,
					void *object, void *arg)
{
	struct wlan_objmgr_peer *peer = (struct wlan_objmgr_peer *)object;
	uint16_t *temp_peers = arg;

	if (wlan_peer_get_peer_type(peer) == WLAN_PEER_STA_TEMP)
		(*temp_peers)++;
}

/* Get logically deleted per count */
static uint16_t
mlme_vdev_get_lstate_peer_count(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_logically_del_peer *temp_peer = NULL;
	qdf_list_t *logical_del_peerlist = NULL;
	qdf_list_node_t *peerlist = NULL;
	uint16_t lstate_peer_cnt = 0;
	struct wlan_objmgr_peer *peer;

	logical_del_peerlist =
		wlan_objmgr_vdev_get_log_del_peer_list(vdev,
						       WLAN_MLME_SB_ID);
	if (!logical_del_peerlist)
		return 0;

	while (QDF_IS_STATUS_SUCCESS(qdf_list_remove_front(logical_del_peerlist,
				     &peerlist))) {
		temp_peer = qdf_container_of(peerlist,
					     struct wlan_logically_del_peer,
					     list);
		peer = temp_peer->peer;
		lstate_peer_cnt++;
		wlan_objmgr_peer_release_ref(peer, WLAN_MLME_SB_ID);
		qdf_mem_free(temp_peer);
	}
	qdf_list_destroy(logical_del_peerlist);
	qdf_mem_free(logical_del_peerlist);
	return lstate_peer_cnt;
}

QDF_STATUS mlme_vdev_send_deauth(struct ieee80211vap *vap)
{
	bool send_bcast_deauth = false;
	bool send_ucast_deauth = false;
	struct vdev_mlme_obj *vdev_mlme;
	struct wlan_objmgr_psoc *psoc;
	uint8_t peer_del_req_send = MLME_INDIVIDUAL_PEER_CLEANUP;
	extern void sta_deauth (void *arg, struct ieee80211_node *ni);
	struct vdev_response_timer *vdev_rsp;
	struct psoc_mlme_obj *psoc_mlme;
	uint8_t vdev_id;
	uint16_t temp_peers = 0;
	uint16_t lstate_peers = 0;
	int16_t total_peers = 0;

	if (vap->iv_csa_deauth_mode == CSA_DEAUTH_MODE_UNICAST)
		send_ucast_deauth = true;
	else if (vap->iv_csa_deauth_mode == CSA_DEAUTH_MODE_BROADCAST)
		send_bcast_deauth = true;
	else {
		if (g_unicast_deauth_on_stop)
			send_ucast_deauth = true;
		else
			send_bcast_deauth = true;
	}

	if (send_ucast_deauth || wlan_vap_is_pmf_enabled(vap)) {
		mlme_nofl_info("Sending ucast %s to %s associated stas",
			       vap->iv_send_deauth ? "deauth" : "disassoc",
			       wlan_vap_is_pmf_enabled(vap) ? "PMF" : "ALL");

		if (vap->iv_send_deauth)
			wlan_iterate_station_list(vap, sta_deauth,
						  &peer_del_req_send);
		else
			wlan_iterate_station_list(vap, sta_disassoc,
						  &peer_del_req_send);

		wlan_iterate_unassoc_sta_list(vap, sta_deauth,
					      &peer_del_req_send);

	} else {
		/* send peer delete all only when fw capability is set */
		if (wlan_pdev_nif_feat_cap_get(
					wlan_vdev_get_pdev(vap->vdev_obj),
					WLAN_PDEV_F_DELETE_ALL_PEER))
			peer_del_req_send = MLME_MULTIPLE_PEER_CLEANUP;

		vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vap->vdev_obj);
		psoc = wlan_vdev_get_psoc(vap->vdev_obj);
		if (!psoc) {
			mlme_nofl_err("PSOC is NULL");
			return QDF_STATUS_E_FAILURE;
		}

		wlan_objmgr_iterate_peerobj_list(
					vap->vdev_obj,
					mlme_vdev_get_temp_peer_count,
					&temp_peers,
					WLAN_MLME_SB_ID);

		lstate_peers = mlme_vdev_get_lstate_peer_count(vap->vdev_obj);
		total_peers = wlan_vdev_get_peer_count(vap->vdev_obj) - temp_peers - lstate_peers;
		mlme_nofl_info("PSOC_%d VDEV_%d Sending bcast deauth and %s, clients: %d",
                               wlan_psoc_get_id(psoc),
			       wlan_vdev_get_id(vap->vdev_obj),
			       (peer_del_req_send == MLME_MULTIPLE_PEER_CLEANUP ?
			       "DELETE_ALL_PEER":"PEER_DELETE"),
			       total_peers);
		/* Send broadcast deauth frames twice */
		ieee80211_send_deauth(vap->iv_bss, IEEE80211_REASON_AUTH_LEAVE);
		ieee80211_send_deauth(vap->iv_bss, IEEE80211_REASON_AUTH_LEAVE);
		/* cleanup all associated sta peers on this vap */
		wlan_iterate_station_list(vap, cleanup_sta_peer,
					  &peer_del_req_send);
		/* cleanup all unassociated sta peers on this vap */
		wlan_iterate_unassoc_sta_list(vap, cleanup_sta_peer,
					      &peer_del_req_send);

		vdev_id = wlan_vdev_get_id(vap->vdev_obj);
		psoc_mlme = mlme_psoc_get_priv(psoc);
		if (!psoc_mlme) {
			mlme_err("VDEV_%d PSOC_%d PSOC_MLME is NULL", vdev_id,
					wlan_psoc_get_id(psoc));
			return QDF_STATUS_E_FAILURE;
		}

		vdev_rsp =  &psoc_mlme->psoc_vdev_rt[vdev_id];

		/* send peer delete all cmd */
		if (peer_del_req_send == MLME_MULTIPLE_PEER_CLEANUP &&
		    (total_peers > 1) &&
		    !qdf_atomic_test_bit(PEER_DELETE_ALL_RESPONSE_BIT,
					 &vdev_rsp->rsp_status)) {
			if (vdev_mgr_peer_delete_all_send(vdev_mlme)
							== QDF_STATUS_SUCCESS) {
#ifdef QCA_SUPPORT_CP_STATS
			    vdev_cp_stats_peer_delete_all_req_inc(
							vap->vdev_obj, 1);
#endif
			} else {
				mlme_vdev_peer_timeout_rel_handler(vap);
			}
		}
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_disconnect_peers_cb(
                        struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_vdev *vdev;
	struct ieee80211_mlme_priv *mlme_priv;
	struct ieee80211vap *vap;
	struct ol_ath_softc_net80211 *scn;
	ol_ath_soc_softc_t *soc;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}
	vdev = vdev_mlme->vdev;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL",
			wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	mlme_priv = vap->iv_mlme_priv;
	switch(vap->iv_opmode) {
	case IEEE80211_M_HOSTAP:
	case IEEE80211_M_BTAMP:
		/* Reset connection state, so that no new connections occur */
		mlme_priv->im_connection_up = 0;
		/* disassoc/deauth all stations */
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME|IEEE80211_MSG_AUTH,
			"%s: disassoc/deauth all stations. peer_cnt: %d\n",
			__func__, wlan_vdev_get_peer_count(vdev));

		/* flush mgmt frames for this vap to make down faster */
		ieee80211_flush_vap_mgmt_queue(vap, false);

		if (wlan_vdev_get_peer_count(vdev) == 1) {
			mlme_vdev_sm_notify_peers_disconnected(vap);
			return QDF_STATUS_SUCCESS;
		}
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME|IEEE80211_MSG_AUTH,
			"%s: sending %s deauth to all stations.\n",
			__func__, g_unicast_deauth_on_stop ? "UNICAST" : "BROADCAST");

		if (vap->force_cleanup_peers)
			mlme_vdev_cleanup_peers(vap);
		else
			mlme_vdev_send_deauth(vap);

		vap->force_cleanup_peers = 0;

		qdf_timer_mod(&vap->peer_cleanup_timer, 1000);

		scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
		soc = scn->soc;
		qdf_timer_mod(&vap->peer_del_bss_tid_flush,
			      soc->peer_del_wait_time);
		break;

	case IEEE80211_M_STA:
		/* There should be no mlme requests pending */
		ASSERT(vap->iv_mlme_priv->im_request_type == MLME_REQ_NONE);

		/* Reset state variables */
		mlme_priv->im_connection_up = 0;
		mlme_sta_swbmiss_timer_stop(vap);
		ucfg_son_set_root_dist(vap->vdev_obj,
						SON_INVALID_ROOT_AP_DISTANCE);

		 /* Station BSS peer is deleted after sending STOP request, here
		  * connection sm gives event to move to STOP state*/

		/* Send disconnect complete to VDEV SM, if the connection SM
		 * moved to init state, and the disconnect complete sent from
		 * connection SM is not handled, since we can move to RESTART
		 * before moving to SUSPEND and we need disconnect event to
		 * move from SUSPEND to STOP state
		 */
		if (wlan_assoc_sm_stop(wlan_mlme_get_assoc_sm_handle(vap->vdev_obj),
				       IEEE80211_ASSOC_SM_STOP_DISASSOC))
			wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
				WLAN_VDEV_SM_EV_DISCONNECT_COMPLETE, 0, NULL);
		break;

	case IEEE80211_M_MONITOR:
		wlan_vdev_mlme_sm_deliver_evt_sync(vdev,
			WLAN_VDEV_SM_EV_DISCONNECT_COMPLETE, 0, NULL);
		break;
	default:
		break;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_dfs_cac_timer_stop_cb(
		struct vdev_mlme_obj *vdev_mlme,
		uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_pdev *pdev;
	struct ieee80211vap *vap;
	struct ieee80211com *ic;
	uint8_t force = 0;

	vap = wlan_vdev_get_mlme_ext_obj(vdev_mlme->vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL",
			 wlan_vdev_get_id(vdev_mlme->vdev));
		return QDF_STATUS_E_FAILURE;
	}
	ic = vap->iv_ic;

	pdev = ic->ic_pdev_obj;
	if(pdev == NULL) {
		mlme_err("pdev is null");
		return QDF_STATUS_E_FAILURE;
	}

	if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
			QDF_STATUS_SUCCESS) {
		return QDF_STATUS_E_FAILURE;
	}
	if(!force && (!mlme_dfs_is_ap_cac_timer_running(pdev) ||
				ieee80211_dfs_vaps_in_dfs_wait(ic, vap))) {
		wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
		return QDF_STATUS_E_FAILURE;
	}
	mlme_dfs_cac_stop(pdev);
	wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);

	return QDF_STATUS_SUCCESS;
}

static void mlme_vdev_cleanup(struct ieee80211vap *vap)
{
    struct ieee80211vap *tmpvap;
    struct ieee80211com *ic = vap->iv_ic;

#if WLAN_SUPPORT_FILS
        /* Free FILS FD buffer on receiving stopped event */
     vap->iv_cleanup(vap);
#endif
     /* 6Ghz 20 tu probe response free */
     if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
         ic->ic_prb_rsp_free(vap);

     if (vap->iv_he_bsscolor_detcn_configd_vap) {
         /* if bsscolor collision detection
          * event was registered for this
          * vap then disable color detection
          * for this vap
          */
         QDF_TRACE(QDF_MODULE_ID_BSSCOLOR,
                   QDF_TRACE_LEVEL_INFO,
                   "Disabling bsscolor collision detection "
                   "for stopping vap. vdev-id: 0x%x",
                   wlan_vdev_get_id(vap->vdev_obj));
         vap->iv_config_bss_color_offload(vap, true);
         vap->iv_he_bsscolor_detcn_configd_vap = false;

          /* configure collision detection
           * for the next avaailable ap vap
           */
         TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
             if ((tmpvap->iv_opmode == IEEE80211_M_HOSTAP)
                     && tmpvap->iv_is_up) {
                 QDF_TRACE(QDF_MODULE_ID_BSSCOLOR,
                           QDF_TRACE_LEVEL_INFO,
                           "Configuring fw for AP mode bsscolor collision "
                           "detection for the next active vap. vdev-id: 0x%x",
                           wlan_vdev_get_id(tmpvap->vdev_obj));
                 tmpvap->iv_he_bsscolor_detcn_configd_vap = true;
                 tmpvap->iv_config_bss_color_offload(tmpvap, false);
                 break;
             }
         }
     } /* end check if (vap->iv_he_bsscolor_detcn_configd_vap) */
}

QDF_STATUS mlme_vdev_stop_continue_cb(struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct ieee80211vap *vap;
	struct ieee80211com *ic;
	struct wlan_objmgr_vdev *vdev;

	if (!vdev_mlme) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}
	vdev = vdev_mlme->vdev;
	if (!vdev) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL",
			wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	ic = vap->iv_ic;

        if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
            /* Remove this AP info in rnr_buf in soc and notify lower band AP
             * to advertize updated RNR cache
             */
            wlan_remove_vap_from_6ghz_rnr_cache(vap);
            wlan_tmpl_update_lower_band_vdevs(wlan_pdev_get_psoc(ic->ic_pdev_obj));
            wlan_rnr_6ghz_vdev_dec();
            if(!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap))
                wlan_global_6ghz_pdev_destroy();
        }

	/* If last lower band vdev goes down, notify 6Ghz Vdevs
	 * to update template based on 6Ghz only AP case scenario
	 */
        if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
            ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
            wlan_rnr_lower_band_vdev_dec();
            if (0 == wlan_lower_band_ap_cnt_get())
                wlan_tmpl_update_6ghz_frm();
        }

        if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                    WLAN_PDEV_F_MBSS_IE_ENABLE)) {
            if (ic->ic_mbss.ema_ext_enabled &&
                    (ic->ic_mbss.transmit_vap &&
                     (ic->ic_mbss.transmit_vap->iv_unit == vap->iv_unit))) {
                vap->iv_mbss.ie_overflow = false;
            }

            /* update the particular node's dtim_count
            * to value 255 to meet the fw requiremnt
            * that a new profile added should have
            * value 255 in the dtim_count field in the
            * template sent from host to fw. If the
            * profile already exists then the corresponding
            * value should be 0
            */
            ieee80211_mbssid_update_mbssie_cache_entry(vap, MBSS_CACHE_ENTRY_IDX);
        }

	if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
		if (ic->ic_mbss.transmit_vap) {
			/* Delete VAP profile from MBSS IE */
			ieee80211_mbssid_del_profile(vap);
		} else {
			mbss_warn("Transmitting VAP has been deleted!");
		}
	} else {
		mlme_vdev_update_beacon(vdev_mlme, BEACON_FREE,
						event_data_len, event_data);
	}

	son_send_vap_stop_event(vdev_mlme->vdev);

	mlme_vdev_cleanup(vap);

	/*
	 * In case of AP, peer bss will be reset only at the time of vdev delete,
	 * But in case of STA, BSS peer delete request will be sent to FW for
	 * every instance of vdev up/down.
	 */
	if ((vap->iv_opmode == IEEE80211_M_STA))
		wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_DELETE_IND);
	else
		ieee80211_node_reset(vap->iv_bss);


	if (((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
             (wlan_vdev_get_peer_count(vdev) == 1)) ||
	    ((vap->iv_opmode != IEEE80211_M_HOSTAP) &&   /* If !AP and !STA */
	     (vap->iv_opmode != IEEE80211_M_STA))) {
		wlan_vdev_mlme_sm_deliver_evt_sync(vap->vdev_obj,
					WLAN_VDEV_SM_EV_MLME_DOWN_REQ, 0, NULL);
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_notify_down_complete_cb(
				struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_vdev *vdev;
	struct ieee80211vap *vap;
	cm_ext_t *cm_ext_handle = NULL;

	vdev = vdev_mlme->vdev;
	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	if (vap->iv_opmode == IEEE80211_M_STA) {
		cm_ext_handle = wlan_cm_get_ext_hdl(vdev);
		if (!cm_ext_handle)
			return QDF_STATUS_E_FAILURE;

		if (wlan_cm_get_active_req_type(vdev) == CM_CONNECT_ACTIVE)
			wlan_mlme_dispatch_cm_resp(vap, CM_CONNECT_RESP);
		else if (wlan_cm_get_active_req_type(vdev) == CM_ROAM_ACTIVE &&
			 QDF_IS_STATUS_ERROR(cm_ext_handle->cm_conn_rsp.connect_status))
			wlan_mlme_dispatch_cm_resp(vap, CM_CONNECT_RESP);
		else
			wlan_mlme_dispatch_cm_resp(vap, CM_DISCONNECT_RESP);
		return QDF_STATUS_SUCCESS;
	}
	wlan_mlme_release_vdev_req(vdev_mlme->vdev,
				   WLAN_SER_CMD_VDEV_STOP_BSS, EOK);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_vdev_notify_down_complete(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_mlme_obj *vdev_mlme;

	vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
	if (!vdev_mlme)
		return QDF_STATUS_E_FAILURE;

	mlme_vdev_notify_down_complete_cb(vdev_mlme, 0, NULL);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_notify_start_state_exit_cb(struct vdev_mlme_obj *vdev_mlme)
{
	struct wlan_objmgr_pdev *pdev;
	struct ieee80211vap *vap;
	struct ieee80211com *ic;

	vap = wlan_vdev_get_mlme_ext_obj(vdev_mlme->vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL",
			 wlan_vdev_get_id(vdev_mlme->vdev));
		return QDF_STATUS_E_FAILURE;
	}
	ic = vap->iv_ic;

	pdev = ic->ic_pdev_obj;
	if(pdev == NULL) {
		mlme_err("pdev is null");
		return QDF_STATUS_E_FAILURE;
	}

	if (!wlan_pdev_mlme_op_get(pdev, WLAN_PDEV_OP_RADAR_DETECT_DEFER))
		return QDF_STATUS_SUCCESS;

	/* Invoke RADAR detect defer with last VDEV which moves out of Start
	 * state
	 */
	if (wlan_util_is_pdev_restart_progress(pdev, WLAN_MLME_SB_ID) ==
					QDF_STATUS_SUCCESS)
		return QDF_STATUS_SUCCESS;

	mlme_sm_cmd_schedule_req(pdev, MLME_SM_CMD_PDEV_RADAR_DETECT,
				 ic->ic_radar_defer_chan);

	return QDF_STATUS_SUCCESS;
}


QDF_STATUS mlme_vdev_is_newchan_no_cac_cb(struct vdev_mlme_obj *vdev_mlme)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_channel *des_chan;
	struct ieee80211_ath_channel *new_chan;
	struct ieee80211vap *vap;
	struct ieee80211com *ic;
	struct wlan_objmgr_pdev *pdev;
	bool is_cac_continuable;

	if (!vdev_mlme) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;
	if (!vdev) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		mlme_err("(vdev-id:%d) PDEV is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
	if (!ic) {
		mlme_err("(vdev-id:%d) ic is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	des_chan = wlan_vdev_mlme_get_des_chan(vdev);

	new_chan = ieee80211_find_dot11_channel(ic, des_chan->ch_freq,
			des_chan->ch_cfreq2,
			wlan_vdev_get_ieee_phymode(des_chan->ch_phymode));
	if (!new_chan) {
		mlme_err("(vdev-id:%d) des chan(%d) is NULL",
			  wlan_vdev_get_id(vdev), des_chan->ch_ieee);
		return QDF_STATUS_E_FAILURE;
	}

	if (mlme_dfs_is_cac_required(pdev,
				     new_chan,
				     ic->ic_curchan,
				     &is_cac_continuable)) {
		mlme_err("(vdev-id:%d) des chan(%d) needs CAC",
			  wlan_vdev_get_id(vdev), des_chan->ch_ieee);

		vap->force_cleanup_peers = 1;
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_dfs_cac_wait_notify_cb(struct vdev_mlme_obj *vdev_mlme)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;
	struct pdev_mlme_obj *pdev_mlme;

	if (!vdev_mlme) {
		wlan_mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_INVAL;
	}

	vdev = vdev_mlme->vdev;
	if (!vdev) {
		wlan_mlme_err("VDEV is NULL");
		return QDF_STATUS_E_INVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	pdev_mlme = wlan_pdev_mlme_get_cmpt_obj(pdev);
	if (!pdev_mlme) {
		wlan_mlme_err("Null input");
		return QDF_STATUS_E_INVAL;
	}
	/*
	 * For CSA due to any south bound request such as radar detect,
	 * fallback to multivdev restart as there is no CSA_RESTART
	 * command enqueued at serialization.
	 */
	if (!pdev_mlme->pdev_restart.vdev) {
		wlan_mlme_debug("SB triggered CSA restart");
		return QDF_STATUS_E_NOSUPPORT;
	}

	wlan_mlme_release_vdev_req(vdev,
				   WLAN_SER_CMD_PDEV_CSA_RESTART, EINVAL);

	return QDF_STATUS_SUCCESS;
}

/* Translation table for conversion from QDF mode to IEEE80211 opmode */
uint8_t qdf_opmode2ieee80211_opmode[QDF_MAX_NO_OF_MODE+1] = {
	IEEE80211_M_STA,         /* QDF_STA_MODE,        */
	IEEE80211_M_HOSTAP,      /* QDF_SAP_MODE,        */
	IEEE80211_M_P2P_CLIENT,  /* QDF_P2P_CLIENT_MODE, */
	IEEE80211_M_P2P_GO,      /* QDF_P2P_GO_MODE,     */
	IEEE80211_M_ANY,         /* QDF_FTM_MODE,        */
	IEEE80211_M_IBSS,        /* QDF_IBSS_MODE,       */
	IEEE80211_M_MONITOR,     /* QDF_MONITOR_MODE,    */
	IEEE80211_M_P2P_DEVICE,  /* QDF_P2P_DEVICE_MODE, */
	IEEE80211_M_ANY,         /* QDF_OCB_MODE,        */
	IEEE80211_M_ANY,         /* QDF_EPPING_MODE,     */
	IEEE80211_M_ANY,         /* QDF_QVIT_MODE,       */
	IEEE80211_M_ANY,         /* QDF_NDI_MODE,        */
	IEEE80211_M_WDS,         /* QDF_WDS_MODE,        */
	IEEE80211_M_BTAMP,       /* QDF_BTAMP_MODE,      */
	IEEE80211_M_AHDEMO,      /* QDF_AHDEMO_MODE      */
	IEEE80211_M_ANY,         /* QDF_MAX_NO_OF_MODE   */
};

struct ieee80211com *wlan_sc_get_ic(struct ol_ath_softc_net80211 *scn)
{
	return &scn->sc_ic;
}

QDF_STATUS mlme_pdev_ext_obj_create(struct pdev_mlme_obj *pdev_mlme)
{
	struct ieee80211com *ic;
	struct pdev_osif_priv *osif_priv;
	struct wlan_objmgr_pdev *pdev;

	if (!pdev_mlme) {
		mlme_err("PDEV MLME is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	pdev = pdev_mlme->pdev;
	if (!pdev) {
		mlme_err("PDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	/*
	* From scn, get ic pointer.
	* since ic is static member of scn, so to have minimal changes
	* using ic from scn instead of allocating
	*/
	osif_priv = wlan_pdev_get_ospriv(pdev);

	ic = wlan_sc_get_ic((struct ol_ath_softc_net80211 *)
				osif_priv->legacy_osif_priv);
	/* store back pointer in pdev */
	ic->ic_pdev_obj = pdev;
	pdev_mlme->ext_pdev_ptr = ic;
	pdev_mlme->mlme_register_ops = mlme_register_ops;

	mlme_restart_timer_init(pdev_mlme);


	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_pdev_ext_obj_destroy(struct pdev_mlme_obj *pdev_mlme)
{
	struct ieee80211com *ic;
	struct wlan_objmgr_pdev *pdev;

	if (!pdev_mlme) {
		mlme_err("PDEV MLME is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	pdev = pdev_mlme->pdev;
	if (!pdev) {
		mlme_err("PDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
	if(ic != NULL) {
		mlme_restart_timer_delete(pdev_mlme);
		ic->ic_pdev_obj = NULL;
	}
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_ext_obj_create(struct vdev_mlme_obj *vdev_mlme)
{
	enum ieee80211_opmode opmode;
	uint8_t *bssid;
	uint8_t *mataddr;
	uint32_t flags;
	struct wlan_objmgr_pdev *pdev;
	wlan_dev_t devhandle;
	wlan_if_t vap;
	struct wlan_objmgr_vdev *vdev;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;

	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}
	/* get MAC address from VDEV */
	bssid = wlan_vdev_mlme_get_macaddr(vdev);
	/* get opmode from VDEV */
	opmode = qdf_opmode2ieee80211_opmode[wlan_vdev_mlme_get_opmode(vdev)];
	if (opmode == IEEE80211_M_ANY) {
		mlme_err("qdf opmode %d is not supported",
			 wlan_vdev_mlme_get_opmode(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	mataddr = wlan_vdev_mlme_get_mataddr(vdev);
	flags = vdev->vdev_objmgr.c_flags;
	pdev = wlan_vdev_get_pdev(vdev);
	if(pdev == NULL) {
		mlme_err("PDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	devhandle = (wlan_dev_t )wlan_pdev_get_mlme_ext_obj(pdev);
	if(devhandle == NULL) {
		mlme_err("ic is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vap_create(devhandle, opmode, 0, flags, bssid, mataddr,
			      vdev_mlme);
	if(vap == NULL) {
		mlme_err(" VDEV MLME legacy obj creation failed");
		return QDF_STATUS_E_FAILURE;
	}
	vdev_mlme->ext_vdev_ptr = vap;

	return QDF_STATUS_SUCCESS;
}


QDF_STATUS mlme_vdev_ext_obj_post_create(struct vdev_mlme_obj *vdev_mlme)
{
	wlan_if_t vap;
	enum QDF_OPMODE opmode;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = vdev_mlme->ext_vdev_ptr;
	if(vap == NULL) {
		mlme_err("Legacy VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

#if ATH_PERF_PWR_OFFLOAD
	opmode = wlan_vdev_mlme_get_opmode(vap->vdev_obj);
        /* If lp_iot_mode vap then skip turning on BF */
        if ((opmode == QDF_SAP_MODE) &&
                (vap->iv_ic->ic_implicitbf) &&
                !(vap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
             wlan_set_param(vap, IEEE80211_SUPPORT_IMPLICITBF, 1);
        }
#endif
	ieee80211_vap_attach(vap);
	qdf_timer_init(NULL, &vap->peer_cleanup_timer,
		       mlme_vdev_force_cleanup_peers, (void *)(vap),
		       QDF_TIMER_TYPE_WAKE_APPS);

	qdf_timer_init(NULL, &vap->peer_del_wait_timer,
		       mlme_vdev_peer_del_timeout_handler, (void *)(vap),
		       QDF_TIMER_TYPE_WAKE_APPS);

	qdf_timer_init(NULL, &vap->peer_del_bss_tid_flush,
		       mlme_vdev_peer_del_bss_tid_flush, (void *)(vap),
		       QDF_TIMER_TYPE_WAKE_APPS);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_ext_obj_destroy(struct vdev_mlme_obj *vdev_mlme)
{
	wlan_if_t vap;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vap = vdev_mlme->ext_vdev_ptr;
	if (vap != NULL) {
		qdf_timer_stop(&vap->peer_cleanup_timer);
		qdf_timer_stop(&vap->peer_del_wait_timer);
		qdf_timer_stop(&vap->peer_del_bss_tid_flush);
		status = mlme_ext_vap_delete(vap);
		if (QDF_IS_STATUS_ERROR(status))
			mlme_err("VAP delete is not Successful!!");
		ieee80211_vap_free(vap);
		vdev_mlme->ext_vdev_ptr = NULL;
	}

	return status;
}

static QDF_STATUS mlme_vdev_up_send_cb(struct vdev_mlme_obj *vdev_mlme,
			uint16_t event_data_len, void *event_data)
{
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;
	struct ieee80211com *ic;
	struct ieee80211vap *vap;
	bool restart = false;

	if (vdev_mlme == NULL) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev = vdev_mlme->vdev;

	if (vdev == NULL) {
		mlme_err("VDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (pdev == NULL) {
		mlme_err("(vdev-id:%d) PDEV is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
	if (!ic) {
		mlme_err("(vdev-id:%d) ic is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return QDF_STATUS_E_FAILURE;
	}

	if (vap->restart_txn)
		restart = true;

	mlme_ext_vap_up(vap, restart);

        vap->force_cleanup_peers = 0;
	vap->restart_txn = 0;

        /* Send peer authorize command to FW after channel switch announcement */
        if(restart && vap->iv_opmode == IEEE80211_M_STA) {
               if(vap->iv_root_authorize(vap, 1)) {
                      qdf_err("Unable to authorize peer");
               }
               if (ic->ic_repeater_move.state == REPEATER_MOVE_START) {
                   IEEE80211_DELIVER_EVENT_BEACON_MISS(vap);
                   ic->ic_repeater_move.state = REPEATER_MOVE_IN_PROGRESS;
               }
        }

	/* Send the CAC Complete Event to the stavap if it is waiting
	* in state REPEATER_CAC
	*/
	{
		struct ieee80211vap *stavap = NULL;
		STA_VAP_DOWNUP_LOCK(ic);
		stavap = ic->ic_sta_vap;
		if(stavap) {
			if (mlme_get_active_req_type(stavap) == MLME_REQ_REPEATER_CAC)
				IEEE80211_DELIVER_EVENT_MLME_REPEATER_CAC_COMPLETE(stavap,0);
		}
		STA_VAP_DOWNUP_UNLOCK(ic);
	}
#if UNIFIED_SMARTANTENNA
	if ((vap->iv_opmode == IEEE80211_M_HOSTAP) && (ieee80211_get_num_active_vaps(ic) == 1)) {
		QDF_STATUS status;
		status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SA_API_ID);
		if (QDF_IS_STATUS_ERROR(status)) {
			mlme_err("unable to get vdev reference (smartantenna");
		} else {
			wlan_sa_api_stop(pdev, vdev, SMART_ANT_RECONFIGURE);
			wlan_sa_api_start(pdev, vdev, SMART_ANT_RECONFIGURE);
			wlan_objmgr_vdev_release_ref(vdev, WLAN_SA_API_ID);
		}
	}
#endif

	/* Set default mcast rate */
	ieee80211_set_mcast_rate(vap);
	return QDF_STATUS_SUCCESS;
}

static void wlan_vdev_set_restart_flag(struct wlan_objmgr_pdev *pdev,
				       void *object,
				       void *arg)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
	unsigned long *send_array = (unsigned long *)arg;
	struct ieee80211vap *vap;

	if (wlan_util_map_index_is_set(send_array, wlan_vdev_get_id(vdev)) ==
					false)
		return;

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return;
	}

	vap->restart_txn = 1;
}

QDF_STATUS mlme_ext_restart_fail_sched_cb(struct scheduler_msg *msg)
{
	struct wlan_objmgr_vdev *vdev = msg->bodyptr;

	wlan_vdev_mlme_sm_deliver_evt(vdev,
				      WLAN_VDEV_SM_EV_RESTART_REQ_FAIL,
				      0, NULL);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_ext_restart_fail_flush_cb(struct scheduler_msg *msg)
{
	struct wlan_objmgr_vdev *vdev = msg->bodyptr;

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_multivdev_restart_fw_send_cb(struct wlan_objmgr_pdev *pdev)
{
	struct ieee80211com *ic;
	struct wlan_channel *des_chan;
	struct ieee80211_ath_channel *curchan;
	struct wlan_objmgr_vdev *vdev, *tmp_vdev;
	uint32_t vdev_ids[WLAN_UMAC_PDEV_MAX_VDEVS];
	struct vdev_mlme_mvr_param mvr_param[WLAN_UMAC_PDEV_MAX_VDEVS];
	uint32_t num_vdevs = 0, i;
	struct pdev_mlme_obj *pdev_mlme;
	struct vdev_mlme_obj *vdev_mlme;
	uint32_t max_vdevs = 0;
	QDF_STATUS status;
	struct scheduler_msg msg = {0};

	if (pdev == NULL) {
		mlme_err("PDEV is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	pdev_mlme = wlan_pdev_mlme_get_cmpt_obj(pdev);
	if (!pdev_mlme) {
		mlme_err(" PDEV MLME is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
	if (!ic) {
		mlme_err("ic is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	max_vdevs = wlan_psoc_get_max_vdev_count(wlan_pdev_get_psoc(pdev));
	for (i = 0; i < max_vdevs; i++) {
		if (wlan_util_map_index_is_set(
			pdev_mlme->restart_send_vdev_bmap, i)
					== false)
			continue;

		tmp_vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, i,
							WLAN_MLME_NB_ID);
		if (!tmp_vdev) {
			mlme_err("objmgr vdev not found for id %d", i);
			return QDF_STATUS_E_FAILURE;
		}
		vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(tmp_vdev);
		if (!vdev_mlme) {
			wlan_objmgr_vdev_release_ref(tmp_vdev, WLAN_MLME_NB_ID);
			continue;
		}
		vdev_ids[num_vdevs] = i;
		mvr_param[num_vdevs].phymode = vdev_mlme->mgmt.generic.phy_mode;
		num_vdevs++;
		wlan_objmgr_vdev_release_ref(tmp_vdev, WLAN_MLME_NB_ID);
	}

	if (num_vdevs == 0)
		return QDF_STATUS_E_FAILURE;

	vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_ids[0],
						    WLAN_MLME_NB_ID);
	if (!vdev)
		return QDF_STATUS_E_FAILURE;

	des_chan = wlan_vdev_mlme_get_des_chan(vdev);

	curchan =  ieee80211_find_dot11_channel(ic, des_chan->ch_freq,
			des_chan->ch_cfreq2,
			wlan_vdev_get_ieee_phymode(des_chan->ch_phymode));

	mlme_err("(vdev-id:%d) des chan(%d)",
			  wlan_vdev_get_id(vdev), des_chan->ch_ieee);
	if (!curchan) {
		mlme_err("(vdev-id:%d) des chan(%d) is NULL",
			  wlan_vdev_get_id(vdev), des_chan->ch_ieee);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
		return QDF_STATUS_E_FAILURE;
	}

	ic->ic_prevchan = ic->ic_curchan;
	ic->ic_curchan = curchan;
	wlan_objmgr_pdev_iterate_obj_list(pdev,
			WLAN_VDEV_OP,
			wlan_vdev_set_restart_flag,
			pdev_mlme->restart_send_vdev_bmap, 0,
			WLAN_MLME_NB_ID);

	status = mlme_ext_multi_vdev_restart(ic, vdev_ids, num_vdevs, mvr_param);
	if (QDF_IS_STATUS_ERROR(status)) {
		for (i = 0; i < num_vdevs; i++) {
			tmp_vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev,
					vdev_ids[i], WLAN_SCHEDULER_ID);
			if (tmp_vdev == NULL)
				continue;
			mlme_info("Multivdev restart failure vdev:%u",
				  wlan_vdev_get_id(tmp_vdev));
			msg.bodyptr = tmp_vdev;
			msg.callback = mlme_ext_restart_fail_sched_cb;
			msg.flush_callback = mlme_ext_restart_fail_flush_cb;
			scheduler_post_message(QDF_MODULE_ID_MLME,
					QDF_MODULE_ID_MLME,
					QDF_MODULE_ID_MLME, &msg);
		}
	}

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_NB_ID);
	ieee80211_send_chanswitch_complete_event(ic);

	/* Restoring DCS value after channel change */
	if ((ic->ic_prevchan != ic->ic_curchan) && ic->ic_dcs_restore) {
		ic->ic_dcs_restore(ic);
	}

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_vdev_peer_del_all_response_cb(
				     struct vdev_mlme_obj *vdev_mlme,
                                     struct peer_delete_all_response *rsp)
{
   return mlme_ext_peer_delete_all_response_event_handler(vdev_mlme, rsp);
}

static QDF_STATUS mlme_vdev_ext_stop_response_cb(
				     struct vdev_mlme_obj *vdev_mlme,
                                     struct vdev_stop_response *rsp)
{
   struct ieee80211vap *vap = vdev_mlme->ext_vdev_ptr;

   wlan_vdev_mlme_sm_deliver_evt(vap->vdev_obj, WLAN_VDEV_SM_EV_STOP_RESP,
		   		 0, NULL);

   return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_vdev_ext_start_response_cb(
				     struct vdev_mlme_obj *vdev_mlme,
                                     struct vdev_start_response *rsp)
{
   return mlme_ext_vap_start_response_event_handler(rsp, vdev_mlme);
}


static QDF_STATUS mlme_multi_vdev_restart_resp_cb(
		struct wlan_objmgr_psoc *psoc,
		struct multi_vdev_restart_resp *resp)
{
	struct wlan_objmgr_pdev *pdev;
	struct wlan_objmgr_vdev *vdev;
	struct vdev_mlme_obj *vdev_mlme;
	struct vdev_start_response vdev_rsp;
	uint8_t max_vdevs, vdev_idx;

	pdev = wlan_objmgr_get_pdev_by_id(psoc, resp->pdev_id,
					  WLAN_MLME_SB_ID);
	if (!pdev) {
		mlme_err("PSOC_%d PDEV_%d is NULL", wlan_psoc_get_id(psoc),
			 resp->pdev_id);
		return QDF_STATUS_E_FAILURE;
	}

	max_vdevs = wlan_psoc_get_max_vdev_count(psoc);
	for (vdev_idx = 0; vdev_idx < max_vdevs; vdev_idx++) {
		if (!qdf_test_bit(vdev_idx, resp->vdev_id_bmap))
			continue;

		mlme_debug("PSOC_%d VDEV_%d Received restart resp",
			   wlan_psoc_get_id(psoc), vdev_idx);

		vdev = wlan_objmgr_get_vdev_by_id_from_pdev(pdev, vdev_idx,
							    WLAN_MLME_SB_ID);
		if (vdev == NULL) {
			mlme_err("PSOC_%d VDEV_%d VDEV is NULL",
				 wlan_psoc_get_id(psoc), vdev_idx);
			continue;
		}

		vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
		if (!vdev_mlme) {
			mlme_err("PSOC_%d VDEV_%d VDEV_MLME is NULL",
				 wlan_psoc_get_id(psoc), vdev_idx);
			wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
			continue;
		}

		vdev_rsp.vdev_id = vdev_idx;
		vdev_rsp.status = resp->status;
		vdev_rsp.resp_type = WLAN_MLME_HOST_VDEV_RESTART_RESP_EVENT;
		mlme_ext_vap_start_response_event_handler(&vdev_rsp, vdev_mlme);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
	}

	wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
	return QDF_STATUS_SUCCESS;
}

static struct vdev_mlme_ops mlme_ops = {
	.mlme_vdev_reset_proto_params = mlme_vdev_reset_proto_params_cb,
	.mlme_vdev_start_continue = mlme_vdev_start_continue_cb,
	.mlme_vdev_sta_conn_start = mlme_vdev_sta_conn_start_cb,
	.mlme_vdev_start_req_failed = mlme_vdev_start_req_failed_cb,
	.mlme_vdev_up_send = mlme_vdev_up_send_cb,
	.mlme_vdev_notify_up_complete = mlme_vdev_notify_up_complete_cb,
	.mlme_vdev_update_beacon = mlme_vdev_update_beacon_cb,
	.mlme_vdev_disconnect_peers = mlme_vdev_disconnect_peers_cb,
	.mlme_vdev_dfs_cac_timer_stop = mlme_vdev_dfs_cac_timer_stop_cb,
	.mlme_vdev_stop_continue = mlme_vdev_stop_continue_cb,
	.mlme_vdev_notify_down_complete = mlme_vdev_notify_down_complete_cb,
	.mlme_vdev_ext_stop_rsp = mlme_vdev_ext_stop_response_cb,
	.mlme_vdev_ext_start_rsp = mlme_vdev_ext_start_response_cb,
	.mlme_vdev_notify_start_state_exit =
					mlme_vdev_notify_start_state_exit_cb,
	.mlme_vdev_is_newchan_no_cac = mlme_vdev_is_newchan_no_cac_cb,
	.mlme_vdev_ext_peer_delete_all_rsp = mlme_vdev_peer_del_all_response_cb,
	.mlme_vdev_dfs_cac_wait_notify = mlme_vdev_dfs_cac_wait_notify_cb,
	.mlme_vdev_sta_disconn_start = mlme_vdev_sta_disconn_start_cb,
};

struct mlme_ext_ops glbl_ops_ext = {
	.mlme_pdev_ext_hdl_create = mlme_pdev_ext_obj_create,
	.mlme_pdev_ext_hdl_destroy = mlme_pdev_ext_obj_destroy,
	.mlme_vdev_ext_hdl_create = mlme_vdev_ext_obj_create,
	.mlme_vdev_ext_hdl_post_create = mlme_vdev_ext_obj_post_create,
	.mlme_vdev_ext_hdl_destroy = mlme_vdev_ext_obj_destroy,
	.mlme_vdev_start_fw_send = mlme_ext_vap_start,
	.mlme_vdev_stop_fw_send = mlme_ext_vap_stop,
	.mlme_vdev_down_fw_send = mlme_ext_vap_down,
	.mlme_multivdev_restart_fw_send =
				mlme_vdev_multivdev_restart_fw_send_cb,
	.mlme_multi_vdev_restart_resp =
				mlme_multi_vdev_restart_resp_cb,
	.mlme_vdev_enqueue_exp_cmd = NULL,
	.mlme_cm_ext_connect_start_ind_cb = wlan_mlme_cm_connect_start,
	.mlme_cm_ext_bss_select_ind_cb = wlan_mlme_cm_connect_active,
	.mlme_cm_ext_bss_peer_create_req_cb = wlan_mlme_cm_ext_bss_peer_create_req,
	.mlme_cm_ext_connect_req_cb = wlan_mlme_cm_join_start,
	.mlme_cm_ext_connect_complete_ind_cb = wlan_mlme_cm_connect_complete,
	.mlme_cm_ext_disconnect_start_ind_cb = wlan_mlme_cm_disconnect_start,
	.mlme_cm_ext_disconnect_req_cb = wlan_mlme_cm_disconnect_active,
	.mlme_cm_ext_bss_peer_delete_req_cb = wlan_mlme_cm_bss_peer_delete_req,
	.mlme_cm_ext_disconnect_complete_ind_cb = wlan_mlme_cm_disconnect_complete,
	.mlme_cm_ext_vdev_down_req_cb = wlan_mlme_cm_vdev_down,
	.mlme_cm_ext_roam_start_ind_cb = NULL,
	.mlme_cm_ext_reassoc_req_cb = wlan_mlme_cm_reassoc_join_start,
	.mlme_cm_ext_hdl_create_cb = wlan_mlme_cm_ext_hdl_create,
	.mlme_cm_ext_hdl_destroy_cb = wlan_mlme_cm_ext_hdl_destroy,
};

QDF_STATUS mlme_register_ops(struct vdev_mlme_obj *vdev_mlme)
{
	if (!vdev_mlme) {
		mlme_err("VDEV MLME obj is NULL");
		return QDF_STATUS_E_FAILURE;
	}

	vdev_mlme->ops = &mlme_ops;

	mlme_register_cmn_ops(vdev_mlme);

	return QDF_STATUS_SUCCESS;
}

struct mlme_ext_ops *mlme_get_global_ops(void)
{
	return &glbl_ops_ext;
}

QDF_STATUS mlme_vdev_sm_peers_discon_sched_cb(struct scheduler_msg *msg)
{
	struct wlan_objmgr_vdev *vdev = msg->bodyptr;
	struct ieee80211vap *vap;
	if (wlan_vdev_mlme_get_opmode(vdev) == QDF_STA_MODE) {
		vap = wlan_vdev_get_mlme_ext_obj(vdev);
		if (!vap) {
			wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
			return QDF_STATUS_E_FAILURE;
		}

		if (wlan_cm_get_active_req_type(vdev) == CM_DISCONNECT_ACTIVE) {
			wlan_mlme_dispatch_cm_resp(vap, CM_BSS_PEER_DELETE_SUCCESS_RESP);
		} else {
			wlan_vdev_mlme_sm_deliver_evt(vdev,
					WLAN_VDEV_SM_EV_MLME_DOWN_REQ, 0, NULL);
		}

	} else {
		if (wlan_vdev_get_peer_count(vdev) == 1) {
			wlan_vdev_mlme_sm_deliver_evt(
				vdev, WLAN_VDEV_SM_EV_DISCONNECT_COMPLETE, 0, NULL);
		}
	}

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);

	return QDF_STATUS_SUCCESS;
}

void mlme_vdev_sm_peers_discon_post_sched_msg(struct wlan_objmgr_vdev *vdev)
{
	struct scheduler_msg msg = {0};
	QDF_STATUS ret = QDF_STATUS_SUCCESS;

	/* Here both scheduler callback and msg flush callback are the same,
	 * since the event has to be dispatched to VDEV SM even if scheduler
	 * message is flushed. Else it would lead to VDEV SM stuck in same
	 * state.
	 */
	msg.bodyptr = vdev;
	msg.callback = mlme_vdev_sm_peers_discon_sched_cb;
	msg.flush_callback = mlme_vdev_sm_peers_discon_sched_cb;

	ret = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SCHEDULER_ID);
	if (QDF_IS_STATUS_ERROR(ret)) {
		wlan_mlme_err("Try get ref failed for vdev:%d",
			      wlan_vdev_get_id(vdev));
		QDF_BUG(0);
	}

	ret = scheduler_post_message(QDF_MODULE_ID_MLME,
			QDF_MODULE_ID_MLME,
			QDF_MODULE_ID_MLME, &msg);

	if (QDF_IS_STATUS_ERROR(ret)) {
		wlan_mlme_err("Failed to post scheduler msg");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
		QDF_BUG(0);
	}
}

void mlme_vdev_sm_notify_peers_disconnected(struct ieee80211vap *vap)
{
	struct wlan_objmgr_vdev *vdev = vap->vdev_obj;

	if (wlan_vdev_mlme_get_opmode(vdev) == QDF_STA_MODE) {
		mlme_vdev_sm_peers_discon_post_sched_msg(vdev);
	} else {
		if (wlan_vdev_get_peer_count(vdev) == 1) {
			qdf_timer_stop(&vap->peer_cleanup_timer);
			qdf_timer_stop(&vap->peer_del_wait_timer);
			qdf_timer_stop(&vap->peer_del_bss_tid_flush);
			mlme_vdev_sm_peers_discon_post_sched_msg(vdev);
		}
	}
}

void mlme_vdev_sm_notify_conn_sm_init_state(struct ieee80211vap *vap)
{
	struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
	enum wlan_vdev_state state;
	enum wlan_vdev_state substate;
	enum wlan_vdev_sm_evt event;

	if (vap->iv_opmode != IEEE80211_M_STA)
		return;

	state = wlan_vdev_mlme_get_state(vdev);
	substate = wlan_vdev_mlme_get_substate(vdev);

	if (state == WLAN_VDEV_S_INIT) {
		event = WLAN_VDEV_SM_EV_DOWN;
	}
        else {
		if (state == WLAN_VDEV_S_START) {
		    if (substate == WLAN_VDEV_SS_START_DISCONN_PROGRESS)
			event = WLAN_VDEV_SM_EV_CONNECTION_FAIL;
		    else if (substate == WLAN_VDEV_SS_START_RESTART_PROGRESS ||
		             substate == WLAN_VDEV_SS_START_START_PROGRESS)
		        event = WLAN_VDEV_SM_EV_DOWN;
                    else
			event = WLAN_VDEV_SM_EV_DISCONNECT_COMPLETE;
                }
		else {
			event = WLAN_VDEV_SM_EV_DISCONNECT_COMPLETE;
                }
	}

	wlan_vdev_mlme_sm_deliver_evt(vdev, event, 0, NULL);
}

static void mlme_vdev_sm_radar_notify(struct wlan_objmgr_pdev *pdev,
				      void *object, void *arg)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
	struct ieee80211_ath_channel *new_chan = arg;
	struct ieee80211vap *vap = wlan_vdev_get_mlme_ext_obj(vdev);
        struct ieee80211com *ic =  wlan_pdev_get_mlme_ext_obj(pdev);
        struct ieee80211vap *tmp_vap = NULL;

	if (!vap) {
		mlme_err("(vdev-id:%d) vap is NULL", wlan_vdev_get_id(vdev));
		return;
	}

	if (wlan_vdev_mlme_get_opmode(vdev) != QDF_STA_MODE) {
		if (vdev->vdev_mlme.des_chan)
			ieee80211_update_vdev_chan(vdev->vdev_mlme.des_chan,
						   new_chan);
		wlan_vdev_mlme_sm_deliver_evt(vdev,
					      WLAN_VDEV_SM_EV_RADAR_DETECTED,
					      0, NULL);
	} else {
		if (wlan_vdev_is_up(vdev) != QDF_STATUS_SUCCESS) {
			/*
		 	* For STA VDEV not in UP state, dispatch beacon miss event.
		 	* So that the assoc_sm is brought down and same is notified to
		 	* conn_sm and vdev_sm.
		 	*/
			IEEE80211_DELIVER_EVENT_BEACON_MISS(vap);
		}
		/* If RADAR is found on operating channel, SM triggers MVR.
		 * During MVR, SM waits till all VAP's are in down state.
		 * If this wait time expires, host assert gets triggered.
		 * with rpt_max_phy feature, it is possible that rpt ap vap's
		 * BW is more than that rpt STA. If RADAR is found on rpt ap
		 * vap's BW, SM triggers MVR but since rpt STA did not found
		 * radar in its BW, it will never be brought down which causes
		 * host assert during MVR.
		 * Bring down rpt STA here to address above scenario.
		 */
		if (ic && ieee80211_ic_rpt_max_phy_is_set(ic)) {
			TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
				if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) &&
				    (wlan_vdev_is_up(tmp_vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
					ieee80211_bringdown_sta_vap(ic);
					break;
				}
			}
		}
        }
}

void
wlan_pdev_mlme_vdev_sm_notify_radar_ind(struct wlan_objmgr_pdev *pdev,
					struct ieee80211_ath_channel *new_chan)
{
	struct ieee80211com *ic;

	if (!pdev)
		return;

	if (wlan_util_is_pdev_restart_progress(pdev, WLAN_MLME_SB_ID) ==
					QDF_STATUS_SUCCESS) {
		if (wlan_pdev_mlme_op_get(pdev,
					  WLAN_PDEV_OP_RESTART_INPROGRESS)) {
			mlme_info("Channel change is in progress, ignore radar detect event");
			return;
		}
		ic = wlan_pdev_get_mlme_ext_obj(pdev);
		if (!ic) {
			mlme_err("ic is NULL");
			return;
		}
		ic->ic_radar_defer_chan = new_chan;

		/* Defer RADAR detection as RESTART is in progress */
		wlan_pdev_mlme_op_set(pdev, WLAN_PDEV_OP_RADAR_DETECT_DEFER);
	} else {
		mlme_err("Starting MVR for Pdev %d",
			 wlan_objmgr_pdev_get_pdev_id(pdev));
		wlan_pdev_mlme_op_set(pdev, WLAN_PDEV_OP_MBSSID_RESTART);

		wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
					  mlme_vdev_sm_radar_notify,
					  new_chan, 0, WLAN_MLME_SB_ID);
		/* clear defer RADAR detection as RESTART is triggered */
		wlan_pdev_mlme_op_clear(pdev, WLAN_PDEV_OP_RADAR_DETECT_DEFER);
	}
}


static void mlme_vdev_sm_nol_chan_change(struct wlan_objmgr_pdev *pdev,
				      void *object, void *arg)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
	struct ieee80211_ath_channel *new_chan = arg;
	struct ieee80211vap *vap;

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return;
	}

	vap->vap_start_failure_action_taken = true;
	if (vdev->vdev_mlme.des_chan)
		ieee80211_update_vdev_chan(vdev->vdev_mlme.des_chan,
					   new_chan);

	/* If VDEV is in RESTART_PROGRESS substate, do not notify radar */
	if (wlan_vdev_is_restart_progress(vdev) == QDF_STATUS_SUCCESS)
		return;

	/* For STA, it should do beacon miss */
	if ((vap->iv_opmode == IEEE80211_M_STA) &&
	    (wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS)) {
		wlan_scan_update_channel_list(vap->iv_ic);
		IEEE80211_DELIVER_EVENT_BEACON_MISS(vap);
	} else {
		wlan_vdev_mlme_sm_deliver_evt(vdev,
					      WLAN_VDEV_SM_EV_RADAR_DETECTED,
					      0, NULL);
	}
}

void
wlan_pdev_mlme_vdev_sm_notify_chan_failure(struct wlan_objmgr_pdev *pdev,
					struct ieee80211_ath_channel *new_chan)
{
	if (!pdev)
		return;

	mlme_err("Starting MVR for Pdev %d",
		 wlan_objmgr_pdev_get_pdev_id(pdev));
	wlan_pdev_mlme_op_set(pdev, WLAN_PDEV_OP_MBSSID_RESTART);
	wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
					  mlme_vdev_sm_nol_chan_change,
					  new_chan, 0, WLAN_MLME_SB_ID);
}

static void mlme_vdev_sm_csa_restart_helper(struct ieee80211vap *vap,
					struct ieee80211_ath_channel *new_chan)
{
	struct wlan_objmgr_vdev *vdev = vap->vdev_obj;

	if (!vdev)
		return;

	ieee80211vap_set_flag(vap, IEEE80211_F_CHANSWITCH);
	vap->iv_chanchange_count = 0;
	if (vdev->vdev_mlme.des_chan)
		ieee80211_update_vdev_chan(vdev->vdev_mlme.des_chan,
					   new_chan);
	wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_CSA_RESTART,
				      0, NULL);
}

static void mlme_vdev_sm_csa_restart(struct wlan_objmgr_pdev *pdev,
				      void *object, void *arg)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
	struct ieee80211_ath_channel *new_chan = arg;
	struct ieee80211vap *vap;
	bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(pdev,
					WLAN_PDEV_F_MBSS_IE_ENABLE);

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return;
	}

	if (is_mbssid_enabled && (vap == vap->iv_ic->ic_mbss.transmit_vap)) {
		/* In MBSSID case, deliver CSA_RESTART event for tx-vap
		 * only after delivering the ones for non-tx vaps. This
		 * is required to ensure that all the non-tx vaps are in
		 * SUSPEND_CSA_RESTART substate when the only csa_status
		 * _complete_event is recieved for the tx-vap
		 */
		return;
	}

	if(vap->iv_opmode == IEEE80211_M_HOSTAP ||
	   vap->iv_opmode == IEEE80211_M_MONITOR) {
		mlme_vdev_sm_csa_restart_helper(vap, new_chan);
	}
}

void
wlan_pdev_mlme_vdev_sm_csa_restart(struct wlan_objmgr_pdev *pdev,
				   struct ieee80211_ath_channel *new_chan)
{
	bool is_mbssid_enabled = false;
	struct ieee80211com *ic;

	if (!pdev)
		return;

	ic = wlan_pdev_get_mlme_ext_obj(pdev);
	if (!ic)
		return;

	is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(pdev,
				WLAN_PDEV_F_MBSS_IE_ENABLE);

	mlme_err("Starting MVR for Pdev %d",
		 wlan_objmgr_pdev_get_pdev_id(pdev));
	wlan_pdev_mlme_op_set(pdev, WLAN_PDEV_OP_MBSSID_RESTART);
	wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
					  mlme_vdev_sm_csa_restart,
					  new_chan, 0, WLAN_MLME_SB_ID);

	/* In MBSSID case, deliver CSA_RESTART event for tx-vap
	* at the end after all non-tx vaps
	*/
	if (is_mbssid_enabled && ic->ic_mbss.transmit_vap) {
		mlme_vdev_sm_csa_restart_helper(ic->ic_mbss.transmit_vap,
						new_chan);
	}
}

static void mlme_vdev_sm_chan_change(struct wlan_objmgr_pdev *pdev,
				     void *object, void *arg)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
	struct ieee80211_ath_channel *new_chan = arg;
	struct ieee80211vap *vap;
	enum wlan_vdev_sm_evt event;

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		mlme_err("(vdev-id:%d) vap  is NULL", wlan_vdev_get_id(vdev));
		return;
	}

	if(vap->iv_opmode == IEEE80211_M_HOSTAP ||
	   vap->iv_opmode == IEEE80211_M_MONITOR) {
		if (vdev->vdev_mlme.des_chan)
			ieee80211_update_vdev_chan(vdev->vdev_mlme.des_chan,
						   new_chan);

		if (wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS)
			event = WLAN_VDEV_SM_EV_SUSPEND_RESTART;
		else
			event = WLAN_VDEV_SM_EV_RADAR_DETECTED;

		wlan_vdev_mlme_sm_deliver_evt(vdev, event, 0, NULL);
	} else if (vap->iv_opmode == IEEE80211_M_STA) {
		wlan_scan_update_channel_list(vap->iv_ic);
		IEEE80211_DELIVER_EVENT_BEACON_MISS(vap);
	}
}

static void wlan_vdev_sm_chan_config_valid(struct wlan_objmgr_pdev *pdev,
					   void *object, void *arg)
{
	struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
	bool *restart = (bool *)arg;

	if (wlan_vdev_chan_config_valid(vdev) == QDF_STATUS_SUCCESS)
		*restart = true;
}

void
wlan_pdev_mlme_vdev_sm_chan_change(struct wlan_objmgr_pdev *pdev,
				   struct ieee80211_ath_channel *new_chan)
{
	bool do_restart = false;

	if (!pdev)
		return;

	wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
					  wlan_vdev_sm_chan_config_valid,
					  &do_restart, 0, WLAN_MLME_SB_ID);

	if (do_restart) {
		mlme_err("Starting MVR for Pdev %d",
			 wlan_objmgr_pdev_get_pdev_id(pdev));
		wlan_pdev_mlme_op_set(pdev, WLAN_PDEV_OP_MBSSID_RESTART);
		wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
						  mlme_vdev_sm_chan_change,
						  new_chan, 0, WLAN_MLME_SB_ID);
	}
}

static void mlme_vdev_send_fw_vdev_restart(struct wlan_objmgr_vdev *vdev,
				  struct ieee80211_ath_channel *new_chan)
{
	if (vdev->vdev_mlme.des_chan)
		ieee80211_update_vdev_chan(vdev->vdev_mlme.des_chan, new_chan);

	wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_FW_VDEV_RESTART, 0,
				      NULL);
}

void wlan_pdev_mlme_vdev_sm_seamless_chan_change
				(struct wlan_objmgr_pdev *pdev,
				 struct wlan_objmgr_vdev *vdev,
				 struct ieee80211_ath_channel *new_chan)
{
	if (!vdev)
		return;

	if ((wlan_vdev_mlme_get_opmode(vdev) == QDF_STA_MODE) ||
	    !(wlan_pdev_mlme_op_get(pdev, WLAN_PDEV_OP_MBSSID_RESTART))) {
		mlme_err("Starting MVR Vdev %d Pdev %d",wlan_vdev_get_id(vdev),
			 wlan_objmgr_pdev_get_pdev_id(pdev));
		wlan_pdev_mlme_op_set(pdev, WLAN_PDEV_OP_MBSSID_RESTART);
	}

	mlme_vdev_send_fw_vdev_restart(vdev, new_chan);
}

void mlme_vdev_sm_deliver_csa_complete(struct wlan_objmgr_vdev *vdev)
{
    wlan_vdev_mlme_sm_deliver_evt(vdev, WLAN_VDEV_SM_EV_CSA_COMPLETE, 0, NULL);
}
