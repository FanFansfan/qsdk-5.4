/*
 * Copyright (c) 2011-2014, 2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <scheduler_api.h>
#include <wlan_dfs_ucfg_api.h>
#include <dfs.h>
#include <wlan_dfs_mlme_api.h>
#include <wlan_vdev_mlme_ser_if.h>
#include <wlan_mlme_if.h>
#include <wlan_vdev_mgr_utils_api.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <wlan_pdev_mlme.h>
#include <wlan_utility.h>
#include <ieee80211_acs_internal.h>
#include <wlan_cm_api.h>

#if UMAC_SUPPORT_CFG80211
#include <ieee80211_cfg80211.h>
#endif

QDF_STATUS mlme_vdev_add_cmd_to_pq(struct wlan_objmgr_vdev *vdev,
                                   enum wlan_serialization_cmd_type type,
                                   uint8_t high_prio);

#if SM_ENG_HIST_ENABLE
#include <wlan_sm_engine_dbg.h>

#define VDEV_MLME_LINE "-----------------------------------"\
		       "-----------------------------------"\
		       "-----------------------------------"

void wlan_mlme_print_vdev_sm_history(struct wlan_objmgr_psoc *psoc,
					    void *obj,
					    void *arg)
{
	struct vdev_mlme_obj *vdev_mlme = NULL;
	struct wlan_sm *vdev_sm = NULL;
	struct wlan_objmgr_vdev *vdev = NULL;
	uint8_t psoc_index;

	psoc_index = *((uint8_t *)arg);

	vdev = (struct wlan_objmgr_vdev *)obj;
	if (!vdev) {
		mlme_err("VDEV is null");
		goto error;
	}
	vdev_mlme = wlan_objmgr_vdev_get_comp_private_obj(
			vdev,
			WLAN_UMAC_COMP_MLME);
	if (!vdev_mlme) {
		mlme_err("VDEV MLME is null");
		goto error;
	}

	vdev_sm = vdev_mlme->sm_hdl;

	if (!vdev_sm) {
		mlme_err("VDEV SM is null");
		goto error;
	}

	mlme_nofl_err(VDEV_MLME_LINE);
	mlme_nofl_err("SM History: PSOC ID: %d VDEV ID: %d",
		      psoc_index,
		      wlan_vdev_get_id(vdev));
	mlme_nofl_err(VDEV_MLME_LINE);
	wlan_sm_print_history(vdev_sm);

error:
	return;
}

void wlan_mlme_psoc_iterate_handler(
		struct wlan_objmgr_psoc *psoc,
		void *arg, uint8_t index)
{
	uint8_t psoc_index = index;
	wlan_objmgr_iterate_obj_list(psoc, WLAN_VDEV_OP,
				     wlan_mlme_print_vdev_sm_history,
				     &psoc_index, false, WLAN_MLME_NB_ID);

	return;
}

#if SM_HIST_DEBUGFS_SUPPORT
#define VDEV_MLME_LINE_PROC "-----------------------------------"\
		       "-----------------------------------"\
		       "-----------------------------------\n"
struct sm_psoc {
	struct seq_file *m;
	uint8_t psoc_index;
};


void wlan_mlme_print_vdev_sm_fs_history(struct wlan_objmgr_psoc *psoc,
					    void *obj,
					    void *arg)
{
	struct vdev_mlme_obj *vdev_mlme = NULL;
	struct wlan_sm *vdev_sm = NULL;
	struct wlan_objmgr_vdev *vdev = NULL;
	uint8_t psoc_index;
	struct sm_psoc *psoc_dbg;

	psoc_dbg = ((struct sm_psoc *)arg);

	psoc_index = psoc_dbg->psoc_index;

	vdev = (struct wlan_objmgr_vdev *)obj;
	if (!vdev) {
		mlme_err("VDEV is null");
		goto error;
	}
	vdev_mlme = wlan_objmgr_vdev_get_comp_private_obj(
			vdev,
			WLAN_UMAC_COMP_MLME);
	if (!vdev_mlme) {
		mlme_err("VDEV MLME is null");
		goto error;
	}

	vdev_sm = vdev_mlme->sm_hdl;

	if (!vdev_sm) {
		mlme_err("VDEV SM is null");
		goto error;
	}

	seq_printf(psoc_dbg->m, VDEV_MLME_LINE_PROC);

	seq_printf(psoc_dbg->m, "SM History: PSOC ID: %d VDEV ID: %d\n",
		      psoc_index,
		      wlan_vdev_get_id(vdev));
	seq_printf(psoc_dbg->m, VDEV_MLME_LINE_PROC);
	wlan_sm_print_fs_history(vdev_sm, psoc_dbg->m);

error:
	return;
}

void wlan_mlme_psoc_fs_iterate_handler(
		struct wlan_objmgr_psoc *psoc,
		void *arg, uint8_t index)
{
	struct sm_psoc psoc_dbg;

	psoc_dbg.psoc_index = index;
	psoc_dbg.m = (struct seq_file *)arg;
	wlan_objmgr_iterate_obj_list(psoc, WLAN_VDEV_OP,
				     wlan_mlme_print_vdev_sm_fs_history,
				     &psoc_dbg, false, WLAN_MLME_NB_ID);

	return;
}

int
wlan_mlme_sm_debugfs_history(qdf_debugfs_file_t m, void *arg)
{
	wlan_objmgr_iterate_psoc_list(
			wlan_mlme_psoc_fs_iterate_handler,
			(void *)m,
			WLAN_MLME_NB_ID);

	return 0;
}
#endif

void wlan_mlme_print_all_sm_history(void)
{
	wlan_objmgr_iterate_psoc_list(
			wlan_mlme_psoc_iterate_handler,
			NULL,
			WLAN_MLME_NB_ID);
}
#endif

QDF_STATUS mlme_is_active_cmd_in_sched_ctx(void *umac_cmd)
{
    struct wlan_mlme_ser_data *data = (struct wlan_mlme_ser_data *)umac_cmd;

    if (!data) {
        wlan_mlme_err("Null data");
        return QDF_STATUS_E_INVAL;
    }

    if (data->activation_ctx == MLME_CTX_SCHED)
        return QDF_STATUS_SUCCESS;
    else
        return QDF_STATUS_E_FAILURE;
}

static QDF_STATUS
wlan_mlme_start_ap_vdev(struct wlan_serialization_command *cmd)
{
    wlan_dev_t comhandle;
    wlan_chan_t chan;
    int error;
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    wlan_if_t vap;
    osif_dev *osifp;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;
    int forcescan = data->flags;
    enum ieee80211_phymode des_mode;
    ieee80211_acs_t acs;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        wlan_mlme_err("vap is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    if (!vap->iv_ic) {
        wlan_mlme_err("IC is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    osifp = (osif_dev *)vap->iv_ifp;
    des_mode = wlan_get_desired_phymode(vap);

    if (vap->iv_ic->recovery_in_progress) {
        wlan_mlme_err("recovery_in_progress on vap %d", vap->iv_unit);
        return QDF_STATUS_E_FAILURE;
    }

    if ((wlan_vdev_mlme_get_opmode(vdev) == QDF_MONITOR_MODE) &&
        (!wlan_autoselect_in_progress(vap))) {
        wlan_mlme_start_monitor(vap);
        return QDF_STATUS_SUCCESS;
    }

    comhandle = wlan_vap_get_devhandle(vap);
    if(comhandle->ic_sta_vap && wlan_is_connected(comhandle->ic_sta_vap)) {
        chan = wlan_get_current_channel(vap, true);
    } else {
        chan = wlan_get_current_channel(vap, false);
    }

#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
    if(chan && chan != IEEE80211_CHAN_ANYC &&
            !ieee80211_ic_externalacs_enable_is_set(vap->iv_ic) &&
            vap->iv_ic->ic_primary_allowed_enable &&
            !(ieee80211_check_allowed_prim_freqlist(
                    vap->iv_ic,chan->ic_freq))) {
        wlan_mlme_err("channel %d freq %d is not a primary allowed channel",
                      chan->ic_ieee, chan->ic_freq);
        chan = NULL;
    }
#endif

    if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
        /* Prevent ACS for special vap, user is supposed to fix channel */
        if (vap->iv_special_vap_mode && !vap->iv_smart_monitor_vap) {
            wlan_mlme_err("ACS is not supported with special vap");
            return QDF_STATUS_E_FAILURE;
        }

        if (ieee80211_ic_externalacs_enable_is_set(vap->iv_ic)) {
            /*
             * If any VAP is active, the channel is already selected
             * so go ahead and init the VAP, the same channel will be used
             */
            if (ieee80211_vaps_active(vap->iv_ic)) {
                /* Set the curent channel to the VAP */
                wlan_chan_t sel_chan;
                sel_chan = wlan_get_current_channel(vap, true);
                error = wlan_set_channel(vap, sel_chan->ic_freq,
                        sel_chan->ic_vhtop_freq_seg2);
                wlan_mlme_info("wlan_set_channel error code: %d", error);
                if (error !=0) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACS,
                            "%s : failed to set channel with error code %d\n",
                            __func__, error);
                    return QDF_STATUS_E_FAILURE;
                }
            } else {
                /*
                 * No VAPs active. An external entity is responsible for
                 * auto channel selection at VAP init time
                 */
                wlan_mlme_info("No active vaps");
                return QDF_STATUS_E_FAILURE;
            }
        } else {
            /* start ACS module to get channel */
            vap->iv_needs_up_on_acs = 1;
            wlan_autoselect_register_event_handler(vap,
                    &osif_acs_event_handler, (void *)osifp);
            wlan_autoselect_find_infra_bss_channel(vap, NULL);
            wlan_mlme_debug("started wlan_autoselect_find_infra_bss_channel");
            return QDF_STATUS_SUCCESS;
        }
    }

    /*
     * 11AX: Recheck future 802.11ax drafts (>D1.0) on coex rules
     */
    if (ieee80211_is_phymode_g40(des_mode) &&
            (wlan_coext_enabled(vap) &&
	     !vap->iv_ic->ic_obss_done_freq &&
             (osif_get_num_running_vaps(comhandle) == 0))) {

        vap->iv_needs_up_on_acs = 1;
        wlan_autoselect_register_event_handler(vap,
                &osif_ht40_event_handler, (void *)osifp);
        wlan_attempt_ht40_bss(vap);
        wlan_mlme_debug("started wlan_attempt_ht40_bss");
        return QDF_STATUS_SUCCESS;
    }

    if (forcescan)
        vap->iv_rescan = 1;

    acs = vap->iv_ic->ic_acs;
    IEEE80211_VAP_LOCK(vap);
    if (wlan_autoselect_in_progress(vap) && !acs->acs_bkscantimer_en) {
        /* do not start AP if there is already a pending ACS */
        IEEE80211_VAP_UNLOCK(vap);
        wlan_mlme_debug("ACS Scan in progress for vdev:%d",
                      wlan_vdev_get_id(vap->vdev_obj));
        return QDF_STATUS_E_FAILURE;
    }
    IEEE80211_VAP_UNLOCK(vap);

    error = wlan_mlme_start_bss(vap, forcescan);
    if (error) {
        /* Radio resource is busy on scanning, try later */
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "%s :mlme busy mostly scanning \n", __func__);
        return QDF_STATUS_E_FAILURE;
    } else {
        wlan_mlme_connection_up(vap);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s :vap up \n", __func__);
        if (wlan_coext_enabled(vap))
            wlan_determine_cw(vap, chan);
    }

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
wlan_mlme_stop_ap_vdev(struct wlan_serialization_command *cmd)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    wlan_if_t vap;
    osif_dev *osifp;
    struct net_device *dev;
    struct ieee80211com *ic;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;
    enum QDF_OPMODE opmode = wlan_vdev_mlme_get_opmode(vdev);
    int flags = 0;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        wlan_mlme_err("vap is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    osifp = (osif_dev *)vap->iv_ifp;
    dev = osifp->netdev;
    ic = vap->iv_ic;

    if (opmode == QDF_MONITOR_MODE) {
        flags =  WLAN_MLME_STOP_BSS_F_NO_RESET |
                 WLAN_MLME_STOP_BSS_F_FORCE_STOP_RESET;
        wlan_mlme_stop_bss(vap, flags);
        return QDF_STATUS_SUCCESS;
    }
    /* Cancel CBS */
    wlan_bk_scan_stop_async(ic);
    osif_vap_acs_cancel(dev, 0);
    if (wlan_vdev_scan_in_progress(vap->vdev_obj)) {
        wlan_mlme_debug("Scan in progress.. Cancelling it. vap: 0x%pK", vap);
        wlan_ucfg_scan_cancel(vap, osifp->scan_requestor, 0,
                WLAN_SCAN_CANCEL_VDEV_ALL, false);
#if UMAC_SUPPORT_CFG80211
        if (ic->ic_cfg80211_config)
            wlan_cfg80211_cleanup_scan_queue(ic->ic_pdev_obj, dev);
#endif
        /* we know a scan was interrupted because we're stopping
         * the VAP. This may lead to an invalid channel pointer.
         * Thus, initialise it with the default channel information
         * from the ic to prevent a crash in
         * ieee80211_init_node_rates() during bss reset.
         */
        if (vap->iv_bsschan == IEEE80211_CHAN_ANYC) {
            wlan_mlme_err("Info: overwriting invalid BSS channel"
                    "info by defaults (%pK)", vap->iv_ic->ic_curchan);
            vap->iv_bsschan = vap->iv_ic->ic_curchan;
        }
    }

    flags = WLAN_MLME_STOP_BSS_F_NO_RESET;
    if (data)
        flags |= data->flags;
    wlan_mlme_stop_bss(vap, flags);
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_add_stop_start_to_pq_head(struct wlan_objmgr_vdev *vdev)
{
    wlan_mlme_debug("Adding STOP-START Sequence for vdev:%u",
                    wlan_vdev_get_id(vdev));
    mlme_vdev_add_cmd_to_pq(vdev, WLAN_SER_CMD_VDEV_START_BSS, true);
    mlme_vdev_add_cmd_to_pq(vdev, WLAN_SER_CMD_VDEV_STOP_BSS, true);

    return QDF_STATUS_SUCCESS;
}

void wlan_mlme_check_if_mvr_sup(struct wlan_objmgr_pdev *pdev,
                                void *object, void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
    bool *restart = (bool *)arg;
    enum wlan_vdev_state vdev_state;

    /*
     * Get number of VDEVs not in INIT or UP state
     */
    vdev_state = wlan_vdev_mlme_get_state(vdev);
    if (vdev_state != WLAN_VDEV_S_INIT &&
            vdev_state != WLAN_VDEV_S_UP) {
        *restart = false;
    }
}

void wlan_mlme_restart_bss_iter_cb(struct wlan_objmgr_pdev *pdev,
                                   void *object, void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
    bool *restart = (bool*)arg;

    if (wlan_vdev_mlme_get_state(vdev) == WLAN_VDEV_S_INIT)
        return;

    if (*restart) {
        wlan_mlme_restart_bss(vdev);
    } else {
        mlme_vdev_add_stop_start_to_pq_head(vdev);
    }
}

static QDF_STATUS
mlme_activate_vdev_start(struct wlan_serialization_command *cmd)
{
    enum QDF_OPMODE opmode;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_mlme_ser_data *data;

    if (!cmd || !cmd->vdev || !cmd->umac_cmd) {
        wlan_mlme_err("Null input cmd:%pK", cmd);
        return QDF_STATUS_E_INVAL;
    }

    vdev = cmd->vdev;
    data = cmd->umac_cmd;
    opmode = wlan_vdev_mlme_get_opmode(vdev);

    data->cmd_in_sched = 0;
    if (opmode == QDF_SAP_MODE || opmode == QDF_MONITOR_MODE)
        return wlan_mlme_start_ap_vdev(cmd);

    return QDF_STATUS_E_INVAL;
}

static QDF_STATUS
mlme_activate_vdev_stop(struct wlan_serialization_command *cmd)
{
    enum QDF_OPMODE opmode;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_mlme_ser_data *data;

    if (!cmd || !cmd->vdev || !cmd->umac_cmd) {
        wlan_mlme_err("Null input cmd:%pK", cmd);
        return QDF_STATUS_E_INVAL;
    }

    vdev = cmd->vdev;
    data = cmd->umac_cmd;
    opmode = wlan_vdev_mlme_get_opmode(vdev);

    data->cmd_in_sched = 0;
    if (opmode == QDF_SAP_MODE || opmode == QDF_MONITOR_MODE)
        return wlan_mlme_stop_ap_vdev(cmd);

    return QDF_STATUS_E_INVAL;
}

static QDF_STATUS
mlme_activate_pdev_restart(struct wlan_serialization_command *cmd)
{
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_mlme_ser_data *data;
    struct pdev_mlme_obj *pdev_mlme;
    bool do_restart = true;

    if (!cmd || !cmd->vdev || !cmd->umac_cmd) {
        wlan_mlme_err("Null input cmd:%pK", cmd);
        return QDF_STATUS_E_INVAL;
    }

    vdev = cmd->vdev;
    data = cmd->umac_cmd;
    data->cmd_in_sched = 0;

    pdev = wlan_vdev_get_pdev(vdev);
    pdev_mlme = wlan_pdev_mlme_get_cmpt_obj(pdev);
    if (!pdev_mlme) {
        wlan_mlme_err("Null input");
        return QDF_STATUS_E_INVAL;
    }

    qdf_mem_zero(&pdev_mlme->pdev_restart.restart_bmap,
                sizeof(pdev_mlme->pdev_restart.restart_bmap));

    pdev_mlme->pdev_restart.vdev = vdev;

    /*
     * Multivdev restart only if all the VDEVs are in UP state, else
     * individual stop-start is dispatched
     */
    wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
                                      wlan_mlme_check_if_mvr_sup,
                                      &do_restart, 0,
                                      WLAN_MLME_SER_IF_ID);

    if (do_restart) {
        wlan_mlme_err("Starting MVR Vdev %d Pdev %d",wlan_vdev_get_id(vdev),
                      wlan_objmgr_pdev_get_pdev_id(pdev));
        wlan_pdev_mlme_op_set(pdev, WLAN_PDEV_OP_MBSSID_RESTART);
    }

    wlan_mlme_debug("MVR Restart:%u", do_restart);
    wlan_objmgr_pdev_iterate_obj_list(pdev, WLAN_VDEV_OP,
                                      wlan_mlme_restart_bss_iter_cb,
                                      &do_restart, 0, WLAN_MLME_SER_IF_ID);

    /*
     * Remove the pdev restart request from serialization queue if
     * stop-start sequence is dispatched
     */
    if (!do_restart)
        wlan_mlme_release_vdev_req(vdev,
                                   WLAN_SER_CMD_PDEV_RESTART, EINVAL);

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
mlme_activate_vdev_restart(struct wlan_serialization_command *cmd)
{
    struct wlan_objmgr_vdev *vdev;
    struct wlan_mlme_ser_data *data;

    if (!cmd || !cmd->vdev || !cmd->umac_cmd) {
        wlan_mlme_err("Null input cmd:%pK", cmd);
        return QDF_STATUS_E_INVAL;
    }

    vdev = cmd->vdev;
    data = cmd->umac_cmd;

    data->cmd_in_sched = 0;

    if (wlan_vdev_mlme_get_state(vdev) == WLAN_VDEV_S_INIT)
        return QDF_STATUS_E_FAILURE;

    if (wlan_vdev_mlme_get_state(vdev) == WLAN_VDEV_S_UP) {
        return wlan_mlme_restart_bss(vdev);
    } else {
        /*
         * On restart cmd activation, if the VDEV SM is not in UP state, then
         * follow the default stop-start mechanism to restart the vdev.
         * and remove the existing restart cmd from active queue
         */
        mlme_vdev_add_stop_start_to_pq_head(vdev);
    }

    return QDF_STATUS_E_FAILURE;
}

static QDF_STATUS
mlme_activate_pdev_csa_restart(struct wlan_serialization_command *cmd)
{
    struct ieee80211com *ic;
    struct wlan_objmgr_vdev *vdev;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_mlme_ser_data *data;
    struct pdev_mlme_obj *pdev_mlme;

    if (!cmd || !cmd->vdev || !cmd->umac_cmd) {
        wlan_mlme_err("Null input cmd:%pK", cmd);
        return QDF_STATUS_E_INVAL;
    }

    vdev = cmd->vdev;
    data = cmd->umac_cmd;
    data->cmd_in_sched = 0;

    pdev = wlan_vdev_get_pdev(vdev);
    pdev_mlme = wlan_pdev_mlme_get_cmpt_obj(pdev);
    ic = wlan_pdev_get_mlme_ext_obj(pdev);
    if (!pdev_mlme || !ic) {
        wlan_mlme_err("Null input");
        return QDF_STATUS_E_INVAL;
    }

    pdev_mlme->pdev_restart.vdev = vdev;

    qdf_mem_zero(&pdev_mlme->pdev_restart.restart_bmap,
                sizeof(pdev_mlme->pdev_restart.restart_bmap));

    wlan_pdev_mlme_vdev_sm_csa_restart(pdev, ic->ic_chanchange_channel);

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_vdev_req_flush_cb(struct scheduler_msg *msg)
{
    struct wlan_serialization_command *cmd = msg->bodyptr;

    if (!cmd || !cmd->vdev) {
        wlan_mlme_err("Null input cmd:%pK", cmd);
        return QDF_STATUS_E_INVAL;
    }

    wlan_objmgr_vdev_release_ref(cmd->vdev, WLAN_SCHEDULER_ID);
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS mlme_vdev_req_sched_cb(struct scheduler_msg *msg)
{
    struct wlan_serialization_command *cmd = msg->bodyptr;
    struct wlan_objmgr_vdev *vdev;
    QDF_STATUS ret = QDF_STATUS_E_FAILURE;

    if (!cmd) {
        wlan_mlme_err("cmd is null");
        return QDF_STATUS_E_INVAL;
    }

    vdev = cmd->vdev;
    if (!vdev) {
        wlan_mlme_err("vdev is null");
        return QDF_STATUS_E_INVAL;
    }

    switch (cmd->cmd_type) {
    case WLAN_SER_CMD_VDEV_START_BSS:
        wlan_mlme_nofl_debug("START_SCHED V:%u", wlan_vdev_get_id(vdev));
        ret = mlme_activate_vdev_start(cmd);
        break;
    case WLAN_SER_CMD_VDEV_STOP_BSS:
        wlan_mlme_nofl_debug("STOP_SCHED V:%u", wlan_vdev_get_id(vdev));
        ret = mlme_activate_vdev_stop(cmd);
        break;
    case WLAN_SER_CMD_PDEV_RESTART:
        wlan_mlme_nofl_debug("PDEV_RESTART_SCH V:%u", wlan_vdev_get_id(vdev));
        ret = mlme_activate_pdev_restart(cmd);
        break;
    case WLAN_SER_CMD_VDEV_RESTART:
        wlan_mlme_nofl_debug("VDEV_RESTART_SCH V:%u", wlan_vdev_get_id(vdev));
        ret = mlme_activate_vdev_restart(cmd);
        break;
    case WLAN_SER_CMD_PDEV_CSA_RESTART:
        wlan_mlme_nofl_debug("VDEV_CSA_RESTART_SCH V:%u", wlan_vdev_get_id(vdev));
        ret = mlme_activate_pdev_csa_restart(cmd);
        break;
    default:
        break;
    }
    /*
     * Called from scheduler context hence release the command on error
     */
    if (QDF_IS_STATUS_ERROR(ret)) {
        wlan_mlme_nofl_debug("Activation failed for cmd:%d", cmd->cmd_type);
        wlan_mlme_release_vdev_req(vdev, cmd->cmd_type, EINVAL);
    }

    wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
    return ret;
}

static QDF_STATUS
mlme_activate_cmd_in_sched_ctx(struct wlan_serialization_command *cmd)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;
    struct scheduler_msg msg = {0};
    QDF_STATUS ret;

    msg.bodyptr = cmd;
    msg.callback = mlme_vdev_req_sched_cb;
    msg.flush_callback = mlme_vdev_req_flush_cb;

    ret = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SCHEDULER_ID);
    if (QDF_IS_STATUS_ERROR(ret))
        return ret;

    data->cmd_in_sched = 1;
    data->activation_ctx = MLME_CTX_SCHED;
    ret = scheduler_post_message(QDF_MODULE_ID_MLME,
            QDF_MODULE_ID_MLME, QDF_MODULE_ID_MLME, &msg);
    if (QDF_IS_STATUS_ERROR(ret)) {
        wlan_mlme_err("failed to post scheduler_msg");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
        return ret;
    }
    wlan_mlme_debug("Cmd act in sched vdev:%d cmd type:%d",
            wlan_vdev_get_id(vdev), cmd->cmd_type);

    return ret;
}

/*
 * mlme_proc_vdev_cmd_error_handler() - Default case cmd activation handler
 * @cmd: Serialization command
 * @reason: Cmd processing reason from serialization module
 *
 * Vdev cmd activation error handels the default cases such as
 * cancel, timeout and release
 *
 * Return: Success on handling the error.
 * */
QDF_STATUS
mlme_proc_vdev_cmd_error_handler(struct wlan_serialization_command *cmd,
                                 enum wlan_serialization_cb_reason reason)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    struct wlan_objmgr_psoc *psoc = wlan_vdev_get_psoc(vdev);
    uint8_t psoc_id = wlan_psoc_get_id(psoc);

    switch (reason) {
    case WLAN_SER_CB_CANCEL_CMD:
        break;
    case WLAN_SER_CB_RELEASE_MEM_CMD:
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);
        qdf_mem_free(cmd->umac_cmd);
        cmd->umac_cmd = NULL;
        break;
    case WLAN_SER_CB_ACTIVE_CMD_TIMEOUT:
        wlan_mlme_err("Timeout for vdev:%d cmdtype:%d",
                      wlan_vdev_get_id(vdev), cmd->cmd_type);
        wlan_mlme_print_vdev_sm_history(psoc, vdev, &psoc_id);
        break;
    default:
        QDF_ASSERT(0);
        return QDF_STATUS_E_INVAL;
        break;
    }
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS
mlme_ser_proc_vdev_start(struct wlan_serialization_command *cmd,
                         enum wlan_serialization_cb_reason reason)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;

    wlan_mlme_nofl_debug("START V:%u rs:%d act:%d",
                         wlan_vdev_get_id(vdev),
                         reason, cmd->activation_reason);

    switch (reason) {
    case WLAN_SER_CB_ACTIVATE_CMD:
        if (cmd->activation_reason == SER_PENDING_TO_ACTIVE) {
            return mlme_activate_cmd_in_sched_ctx(cmd);
        } else {
            data->activation_ctx = MLME_CTX_DIRECT;
            return mlme_activate_vdev_start(cmd);
        }
        break;
    default:
        return mlme_proc_vdev_cmd_error_handler(cmd, reason);
        break;
    }

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS
mlme_ser_proc_vdev_stop(struct wlan_serialization_command *cmd,
                        enum wlan_serialization_cb_reason reason)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;

    wlan_mlme_nofl_debug("STOP V:%u rs:%d act:%d",
                         wlan_vdev_get_id(vdev),
                         reason, cmd->activation_reason);

    switch (reason) {
    case WLAN_SER_CB_ACTIVATE_CMD:
        if (cmd->activation_reason == SER_PENDING_TO_ACTIVE) {
            return mlme_activate_cmd_in_sched_ctx(cmd);
        } else {
            data->activation_ctx = MLME_CTX_DIRECT;
            return mlme_activate_vdev_stop(cmd);
        }
        break;
    default:
        return mlme_proc_vdev_cmd_error_handler(cmd, reason);
        break;
    }

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS
mlme_ser_proc_pdev_restart(struct wlan_serialization_command *cmd,
                           enum wlan_serialization_cb_reason reason)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;

    wlan_mlme_nofl_debug("PDEV restart V:%u rs:%d act:%d",
                         wlan_vdev_get_id(vdev),
                         reason, cmd->activation_reason);

    switch (reason) {
    case WLAN_SER_CB_ACTIVATE_CMD:
        if (cmd->activation_reason == SER_PENDING_TO_ACTIVE) {
            return mlme_activate_cmd_in_sched_ctx(cmd);
        } else {
            data->activation_ctx = MLME_CTX_DIRECT;
            return mlme_activate_pdev_restart(cmd);
        }
        break;
    default:
        return mlme_proc_vdev_cmd_error_handler(cmd, reason);
        break;
    }

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS
mlme_ser_proc_vdev_restart(struct wlan_serialization_command *cmd,
                           enum wlan_serialization_cb_reason reason)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;

    wlan_mlme_nofl_debug("VDEV restart V:%u rs:%d act:%d",
                         wlan_vdev_get_id(vdev),
                         reason, cmd->activation_reason);

    switch (reason) {
    case WLAN_SER_CB_ACTIVATE_CMD:
        if (cmd->activation_reason == SER_PENDING_TO_ACTIVE) {
            return mlme_activate_cmd_in_sched_ctx(cmd);
        } else {
            data->activation_ctx = MLME_CTX_DIRECT;
            return mlme_activate_vdev_restart(cmd);
        }
        break;
    default:
        return mlme_proc_vdev_cmd_error_handler(cmd, reason);
        break;
    }

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS
mlme_ser_proc_pdev_csa_restart(struct wlan_serialization_command *cmd,
                         enum wlan_serialization_cb_reason reason)
{
    struct wlan_objmgr_vdev *vdev = cmd->vdev;
    struct wlan_mlme_ser_data *data = cmd->umac_cmd;

    wlan_mlme_nofl_debug("CSA_RESTART V:%u rs:%d act:%d",
                         wlan_vdev_get_id(vdev),
                         reason, cmd->activation_reason);

    switch (reason) {
    case WLAN_SER_CB_ACTIVATE_CMD:
        if (cmd->activation_reason == SER_PENDING_TO_ACTIVE) {
            return mlme_activate_cmd_in_sched_ctx(cmd);
        } else {
            data->activation_ctx = MLME_CTX_DIRECT;
            return mlme_activate_pdev_csa_restart(cmd);
        }
        break;
    default:
        return mlme_proc_vdev_cmd_error_handler(cmd, reason);
        break;
    }

    return QDF_STATUS_SUCCESS;
}

void wlan_mlme_vdev_cmd_ap_handler(struct wlan_objmgr_vdev *vdev,
                                   enum wlan_serialization_cmd_type cmd_type)
{
    wlan_if_t vap = wlan_vdev_get_mlme_ext_obj(vdev);

    if (!vap) {
        wlan_mlme_err("vap is NULL");
        return;
    }

    switch (cmd_type) {
    case WLAN_SER_CMD_VDEV_START_BSS:
    case WLAN_SER_CMD_VDEV_RESTART:
        wlan_mlme_debug("START complete notification");
        wlan_restore_vap_params(vap);
        break;
    default:
        break;
    }
}

void wlan_mlme_vdev_cmd_sta_handler(struct wlan_objmgr_vdev *vdev,
                                    enum wlan_serialization_cmd_type cmd_type)
{
    /*No-op for now*/
}

void wlan_mlme_vdev_cmd_handler(struct wlan_objmgr_vdev *vdev,
                                enum wlan_serialization_cmd_type cmd_type)
{
    enum QDF_OPMODE opmode = wlan_vdev_mlme_get_opmode(vdev);

    if (opmode == QDF_SAP_MODE)
        wlan_mlme_vdev_cmd_ap_handler(vdev, cmd_type);
    else
        wlan_mlme_vdev_cmd_sta_handler(vdev, cmd_type);
}

QDF_STATUS mlme_check_and_rel_pdev_restart(struct wlan_objmgr_vdev *vdev,
                                           struct pdev_mlme_obj *pdev_mlme)
{
    struct wlan_objmgr_vdev *restart_vdev;
    enum wlan_serialization_cmd_type active_cmd_type;
    /*
     * If pdev restart is in progress, then don't remove the active pdev
     * restart cmd until all the vdevs are up. Reset the bitmap of the
     * corresponding vdev when the vdev sm notifies it is in UP state.
     */
    wlan_util_change_map_index(pdev_mlme->pdev_restart.restart_bmap,
                               wlan_vdev_get_id(vdev), 0);
    if (wlan_util_map_is_any_index_set(pdev_mlme->pdev_restart.restart_bmap,
                sizeof(pdev_mlme->pdev_restart.restart_bmap))) {
        wlan_mlme_debug("Vdev:%u wait for others vdev to move to UP",
                        wlan_vdev_get_id(vdev));
        return QDF_STATUS_E_PENDING;
    }

    /*
     * Remove pdev restart from active queue since all the vdevs are UP
     */
    restart_vdev = pdev_mlme->pdev_restart.vdev;
    pdev_mlme->pdev_restart.vdev = NULL;

    active_cmd_type = wlan_serialization_get_vdev_active_cmd_type(restart_vdev);

    if (active_cmd_type == WLAN_SER_CMD_PDEV_CSA_RESTART)
        wlan_vdev_mlme_ser_remove_request(restart_vdev,
                                      wlan_vdev_get_id(restart_vdev),
                                      WLAN_SER_CMD_PDEV_CSA_RESTART);
    else
        wlan_vdev_mlme_ser_remove_request(restart_vdev,
                                      wlan_vdev_get_id(restart_vdev),
                                      WLAN_SER_CMD_PDEV_RESTART);

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_cancel_scan_on_acs_vap(wlan_if_t vap)
{
    struct scan_cancel_request *cancel_req = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_vdev *vdev = NULL;
    osif_dev *osifp;

    if (!vap || !vap->vdev_obj) {
        return QDF_STATUS_E_INVAL;
    }

    osifp = (osif_dev *)vap->iv_ifp;
    vdev = vap->vdev_obj;
    pdev = wlan_vdev_get_pdev(vdev);

    cancel_req = qdf_mem_malloc(sizeof(*cancel_req));
    if (!cancel_req)
        return QDF_STATUS_E_NOMEM;

    cancel_req->vdev = vdev;
    cancel_req->cancel_req.requester = osifp->scan_requestor;
    cancel_req->cancel_req.scan_id = 0;
    cancel_req->cancel_req.req_type = WLAN_SCAN_CANCEL_VDEV_ALL;
    cancel_req->cancel_req.vdev_id = wlan_vdev_get_id(vdev);
    cancel_req->cancel_req.pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);

    return ucfg_scan_cancel(cancel_req);
}

QDF_STATUS
wlan_mlme_release_vdev_req(struct wlan_objmgr_vdev *vdev,
                           enum wlan_serialization_cmd_type cmd_type,
                           int32_t notify_status)
{
    wlan_if_t vap;
    uint8_t vdev_id;
    uint8_t notify_osif;
    struct wlan_objmgr_psoc *psoc;
    enum wlan_serialization_cmd_type active_cmd_type;
    struct wlan_mlme_ser_data *data;
    struct wlan_objmgr_pdev *pdev;
    struct pdev_mlme_obj *pdev_mlme;
    ieee80211_acs_t acs;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    vdev_id = wlan_vdev_get_id(vdev);
    psoc = wlan_vdev_get_psoc(vdev);
    if (!vap || !psoc) {
        wlan_mlme_err("%s is null", vap ? "psoc" : "vap");
        return QDF_STATUS_E_INVAL;
    }

    active_cmd_type = wlan_serialization_get_vdev_active_cmd_type(vdev);
    /* If requested release command is STOP, remove command though active
     * command type is not STOP, otherwise release only if active command and
     * requested command types match
     */
    if ((cmd_type != active_cmd_type) &&
        (active_cmd_type == WLAN_SER_CMD_VDEV_STOP_BSS)) {
        wlan_mlme_nofl_debug("cmd mismatch, v:%u ct:%d rt:%d", vdev_id,
                             cmd_type, active_cmd_type);
        return QDF_STATUS_E_FAILURE;
    }

    pdev = wlan_vdev_get_pdev(vdev);
    pdev_mlme = wlan_pdev_mlme_get_cmpt_obj(pdev);
    if (!pdev_mlme) {
        wlan_mlme_err("Null input");
        return QDF_STATUS_E_INVAL;
    }

    if (pdev_mlme->pdev_restart.vdev)
        return mlme_check_and_rel_pdev_restart(vdev, pdev_mlme);

    /*
     * If the cmd is activated in scheduler context, then wait until cmd
     * completes its execution i.e do not free the cmd now.
     */
    data = wlan_serialization_get_active_cmd(psoc, vdev_id, active_cmd_type);
    if (data && data->cmd_in_sched) {
        wlan_mlme_nofl_err("IF_REL V:%u exec in sched type:%d",
                           vdev_id, active_cmd_type);
        return QDF_STATUS_E_PENDING;
    }

    /*
     * If vdev restart is complete, then up complete cb requests for
     * removal for start bss instead of vdev restart. If the active cmd type
     * is vdev restart then replace the cmd type with the active cmd type.
     */
    if (cmd_type == WLAN_SER_CMD_VDEV_START_BSS &&
            active_cmd_type == WLAN_SER_CMD_VDEV_RESTART)
        cmd_type = WLAN_SER_CMD_VDEV_RESTART;

    /*
     * If the requested cmd type and the active cmd type is same,
     * only then call mlme and osif callback.
     */
    if (cmd_type == active_cmd_type && notify_status == EOK) {
        data = wlan_serialization_get_active_cmd(psoc, vdev_id, cmd_type);
        if (data) {
            acs = vap->iv_ic->ic_acs;
            if (cmd_type == WLAN_SER_CMD_VDEV_STOP_BSS &&
                    acs->acs_vap == vap) {
                wlan_mlme_debug("vdev-%d down, call osif_start_acs_on_other_vaps",
                        wlan_vdev_get_id(vdev));
                /* check if other vaps need acs at this stage */
                wlan_cancel_scan_on_acs_vap(vap);
                wlan_iterate_vap_list(vap->iv_ic,
                        osif_start_acs_on_other_vaps, (void *) &vap);
            }

            notify_osif = data->notify_osif;
            if ((notify_osif == WLAN_MLME_NOTIFY_MLME ||
                 notify_osif == WLAN_MLME_NOTIFY_OSIF)) {
                /* MLME Post processing handler */
                wlan_mlme_vdev_cmd_handler(vdev, cmd_type);

                /* OSIF Post processing handler */
                if (notify_osif == WLAN_MLME_NOTIFY_OSIF)
                    osif_mlme_notify_handler(vap, cmd_type);
            }
        }
    }
    wlan_mlme_nofl_debug("IF_REL V:%u notif:%d ct:%d rt:%d", vdev_id,
                         notify_status, cmd_type, active_cmd_type);
    if (active_cmd_type < WLAN_SER_CMD_MAX)
        wlan_vdev_mlme_ser_remove_request(vdev, vdev_id, active_cmd_type);

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_cmd_abort_flush_cb(struct scheduler_msg *msg)
{
    struct wlan_objmgr_vdev *vdev = msg->bodyptr;
    wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
    return QDF_STATUS_SUCCESS;

}

static QDF_STATUS mlme_cmd_abort_start_sched_cb(struct scheduler_msg *msg)
{
    struct wlan_objmgr_vdev *vdev = msg->bodyptr;

    wlan_vdev_mlme_ser_remove_request(vdev, wlan_vdev_get_id(vdev),
                                      WLAN_SER_CMD_VDEV_START_BSS);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_cmd_abort_restart_sched_cb(struct scheduler_msg *msg)
{
    struct wlan_objmgr_vdev *vdev = msg->bodyptr;

    wlan_vdev_mlme_ser_remove_request(vdev, wlan_vdev_get_id(vdev),
                                      WLAN_SER_CMD_VDEV_RESTART);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_cmd_abort(struct wlan_objmgr_vdev *vdev)
{
    enum wlan_serialization_cmd_type active_cmd;
    struct scheduler_msg msg = {0};
    QDF_STATUS ret;

    active_cmd = wlan_serialization_get_vdev_active_cmd_type(vdev);

    /*
     * Serialization command abort is not applicable for
     * 1. VDEV STOP cmd
     * 2. PDEV Restart cmd
     * 3. PDEV CSA Restart cmd
     */
    if (active_cmd == WLAN_SER_CMD_VDEV_STOP_BSS ||
        active_cmd == WLAN_SER_CMD_PDEV_RESTART ||
        active_cmd == WLAN_SER_CMD_PDEV_CSA_RESTART) {
        wlan_mlme_err("Skip cmd abort for vdev:%d cmd:%d",
                      wlan_vdev_get_id(vdev), active_cmd);
        return QDF_STATUS_E_INVAL;
    }

    ret = wlan_ser_validate_umac_cmd(vdev,
                                     active_cmd,
                                     mlme_is_active_cmd_in_sched_ctx);

    if (ret == QDF_STATUS_SUCCESS) {
        if (active_cmd == WLAN_SER_CMD_VDEV_START_BSS) {
            msg.callback = mlme_cmd_abort_start_sched_cb;
        } else if (active_cmd == WLAN_SER_CMD_VDEV_RESTART) {
            msg.callback = mlme_cmd_abort_restart_sched_cb;
        } else {
            /*
             * When a new command is added to be part of abort sequence then add
             * a corresponding scheduler callback here
             */
            wlan_mlme_err("Unknown active_cmd_type %u", active_cmd);
            return QDF_STATUS_E_FAILURE;
        }

        ret = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SCHEDULER_ID);
        if (QDF_IS_STATUS_ERROR(ret))
            return ret;

        msg.bodyptr = vdev;
        msg.flush_callback = mlme_cmd_abort_flush_cb;
        ret = scheduler_post_message(QDF_MODULE_ID_MLME, QDF_MODULE_ID_MLME,
                                     QDF_MODULE_ID_MLME, &msg);
        if (QDF_IS_STATUS_ERROR(ret)) {
            wlan_objmgr_vdev_release_ref(vdev, WLAN_SCHEDULER_ID);
            wlan_mlme_err("failed to post scheduler_msg active cmd:%u",
                          active_cmd);
            return ret;
        }
    } else if (ret == QDF_STATUS_E_FAILURE) {
        wlan_vdev_mlme_ser_remove_request(vdev, wlan_vdev_get_id(vdev),
                                          active_cmd);
    } else {
        wlan_mlme_err("Active cmd not found type:%u", active_cmd);
        return ret;
    }

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_start_vdev(struct wlan_objmgr_vdev *vdev,
                                  uint32_t f_scan, uint8_t notify_osif)
{
    struct wlan_serialization_command cmd = {0};
    struct wlan_mlme_ser_data *data;
    QDF_STATUS status;
    enum wlan_serialization_status ret;
    uint8_t vdev_id = wlan_vdev_get_id(vdev);

    wlan_mlme_debug("vdev:%d notify:%d", vdev_id, notify_osif);
    data = qdf_mem_malloc(sizeof(*data));
    if (!data)
        return QDF_STATUS_E_NOMEM;

    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        qdf_mem_free(data);
        return QDF_STATUS_E_BUSY;
    }

    data->vdev = vdev;
    data->flags = f_scan;
    data->notify_osif = notify_osif;

    cmd.source = WLAN_UMAC_COMP_MLME;
    cmd.vdev = vdev;
    cmd.cmd_type = WLAN_SER_CMD_VDEV_START_BSS;
    cmd.cmd_cb = mlme_ser_proc_vdev_start;
    cmd.cmd_id = vdev_id;
    cmd.umac_cmd = data;
    cmd.cmd_timeout_duration = WLAN_MLME_SER_CMD_TIMEOUT_MS;

    ret = wlan_vdev_mlme_ser_start_bss(&cmd);
    if (ret != WLAN_SER_CMD_ACTIVE && ret != WLAN_SER_CMD_PENDING) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);
        qdf_mem_free(data);
        wlan_mlme_nofl_err("IF_START V:%u err:%d", vdev_id, ret);
        return QDF_STATUS_E_FAILURE;
    }

    wlan_mlme_nofl_debug("IF_START V:%u notif:%d ret:%d %s",
                         vdev_id, notify_osif, ret, ret ? "AQ" : "PQ");
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS mlme_stop_vdev(struct wlan_objmgr_vdev *vdev,
                                 uint32_t flags, uint8_t notify_osif)
{
    struct wlan_mlme_ser_data *data;
    QDF_STATUS status;
    enum wlan_serialization_status ret;
    struct wlan_serialization_command cmd = {0};
    wlan_if_t vap;
    osif_dev *osifp;
    uint8_t vdev_id = wlan_vdev_get_id(vdev);

    wlan_mlme_debug("vdev:%d notify:%d", vdev_id, notify_osif);
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        wlan_mlme_err("vap is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    osifp = (osif_dev *)vap->iv_ifp;

    data = qdf_mem_malloc(sizeof(*data));
    if (!data)
        return QDF_STATUS_E_NOMEM;

    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        qdf_mem_free(data);
        return QDF_STATUS_E_BUSY;
    }

    data->vdev = vdev;
    data->flags = flags;
    data->notify_osif = notify_osif;

    cmd.source = WLAN_UMAC_COMP_MLME;
    cmd.vdev = vdev;
    cmd.cmd_type = WLAN_SER_CMD_VDEV_STOP_BSS;
    cmd.cmd_cb = mlme_ser_proc_vdev_stop;
    cmd.cmd_id = vdev_id;
    cmd.umac_cmd = data;
    cmd.cmd_timeout_duration = WLAN_MLME_SER_CMD_TIMEOUT_MS;

    /* Mark to disable queue if vdev delete has triggered this stop cmd */
    if (osifp && osifp->is_delete_in_progress) {
        cmd.queue_disable = 1;
        wlan_mlme_nofl_info("IF_STOP: V:%u Serialization queue disable",
                            vdev_id);
    }

    ret = wlan_vdev_mlme_ser_stop_bss(&cmd);
    if (ret != WLAN_SER_CMD_ACTIVE && ret != WLAN_SER_CMD_PENDING &&
        ret != WLAN_SER_CMD_ALREADY_EXISTS) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);
        qdf_mem_free(data);
        wlan_mlme_nofl_debug("IF_STOP V:%u err_ret:%d", vdev_id, ret);
        return QDF_STATUS_E_FAILURE;
    }

    wlan_mlme_nofl_debug("IF_STOP V:%u notif:%d ret:%d %s",
                         vdev_id, notify_osif, ret, ret ? "AQ" : "PQ");
    if (ret == WLAN_SER_CMD_PENDING) {
        /*
         * To avoid the stop cmd waiting in pending queue, we are
         * triggering active cmd abort, where remove request for the cmd in the
         * active queue is sent.
         */
        wlan_mlme_nofl_debug("IF_STOP V:%u act cmd abort", vdev_id);
        mlme_cmd_abort(vdev);
    }
    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
mlme_pdev_or_vdev_restart(struct wlan_objmgr_vdev *vdev,
                          enum wlan_serialization_cmd_type type)
{
    struct wlan_serialization_command cmd = {0};
    struct wlan_mlme_ser_data *data;
    QDF_STATUS status;
    enum wlan_serialization_status ret;
    uint8_t vdev_id = wlan_vdev_get_id(vdev);

    wlan_mlme_debug("vdev:%d type:%d", vdev_id, type);
    data = qdf_mem_malloc(sizeof(*data));
    if (!data)
        return QDF_STATUS_E_NOMEM;

    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        qdf_mem_free(data);
        return QDF_STATUS_E_BUSY;
    }

    cmd.source = WLAN_UMAC_COMP_MLME;
    cmd.vdev = vdev;
    cmd.cmd_id = vdev_id;
    cmd.umac_cmd = data;
    cmd.cmd_type = type;
    cmd.cmd_timeout_duration = MLME_SER_RESTART_CMD_TIMEOUT_MS;

    if (type == WLAN_SER_CMD_VDEV_RESTART) {
        data->notify_osif = WLAN_MLME_NOTIFY_MLME;
        cmd.cmd_cb = mlme_ser_proc_vdev_restart;
        ret = wlan_vdev_mlme_ser_vdev_restart(&cmd);
    } else {
        cmd.cmd_cb = mlme_ser_proc_pdev_restart;
        cmd.is_blocking = true;
        ret = wlan_vdev_mlme_ser_pdev_restart(&cmd);
    }

    if (ret != WLAN_SER_CMD_ACTIVE && ret != WLAN_SER_CMD_PENDING) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);
        qdf_mem_free(data);
        wlan_mlme_nofl_err("IF_RESTART V:%u err:%d", vdev_id, ret);
        return QDF_STATUS_E_FAILURE;
    }

    wlan_mlme_nofl_debug("IF_RESTART V:%u ret:%d %s",
                         vdev_id, ret, ret ? "AQ" : "PQ");
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_start_vdev(struct wlan_objmgr_vdev *vdev,
                                uint32_t f_scan, uint8_t notify_osif)
{
	QDF_STATUS status;
	QDF_STATUS ret_val;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		wlan_mlme_info("unable to get reference");
		return QDF_STATUS_E_BUSY;
	}

	wlan_vdev_mlme_cmd_lock(vdev);
	ret_val = mlme_start_vdev(vdev, f_scan, notify_osif);
	wlan_vdev_mlme_cmd_unlock(vdev);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);

	return ret_val;
}

QDF_STATUS wlan_mlme_stop_vdev(struct wlan_objmgr_vdev *vdev,
                               uint32_t flags, uint8_t notify_osif)
{
	QDF_STATUS status;
	QDF_STATUS ret_val;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		wlan_mlme_info("unable to get reference");
		return QDF_STATUS_E_BUSY;
	}

	wlan_vdev_mlme_cmd_lock(vdev);
	ret_val = mlme_stop_vdev(vdev, flags, notify_osif);
	wlan_vdev_mlme_cmd_unlock(vdev);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);

	return ret_val;

}

QDF_STATUS wlan_mlme_stop_start_vdev(struct wlan_objmgr_vdev *vdev,
                                     uint32_t flags, uint8_t notify_osif)
{
	QDF_STATUS status;
	QDF_STATUS ret_val;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		wlan_mlme_info("unable to get reference");
		return QDF_STATUS_E_BUSY;
	}

	wlan_vdev_mlme_cmd_lock(vdev);
	ret_val = mlme_stop_vdev(vdev, flags, notify_osif);
	ret_val = mlme_start_vdev(vdev, flags, notify_osif);

	wlan_vdev_mlme_cmd_unlock(vdev);

	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);

	return ret_val;

}

void wlan_mlme_inc_act_cmd_timeout(struct wlan_objmgr_vdev *vdev,
                                   enum wlan_serialization_cmd_type cmd_type)
{
    struct wlan_serialization_command cmd = {0};
    uint32_t dfs_cac_timeout;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_channel *chan;
    cm_ext_t *cm_ext_handle = NULL;

    pdev = wlan_vdev_get_pdev(vdev);
    if (!pdev) {
        wlan_mlme_err("pdev is NULL");
        return;
    }

    if (wlan_vdev_mlme_get_opmode(vdev) == QDF_STA_MODE) {
        cm_ext_handle = wlan_cm_get_ext_hdl(vdev);
        if (!cm_ext_handle)
            return;
    }

    chan = wlan_vdev_mlme_get_des_chan(vdev);
    dfs_cac_timeout = dfs_mlme_get_cac_timeout_for_freq(pdev,
                                                        chan->ch_freq,
                                                        chan->ch_cfreq2,
                                                        chan->ch_flags);

    /* Seconds to milliseconds with added delta of ten seconds*/
    dfs_cac_timeout = (dfs_cac_timeout + 10) * 1000;

    wlan_mlme_debug("DFS timeout:%u", dfs_cac_timeout);
    cmd.vdev = vdev;
    if (cmd_type == WLAN_SER_CMD_VDEV_CONNECT) {
        if (!cm_ext_handle)
            return;
        cmd.cmd_id = cm_ext_handle->cm_conn_rsp.cm_id;
    } else {
        cmd.cmd_id = wlan_vdev_get_id(vdev);
    }

    cmd.cmd_timeout_duration = dfs_cac_timeout;
    cmd.cmd_type = cmd_type;
    cmd.source = WLAN_UMAC_COMP_MLME;
    mlme_ser_inc_act_cmd_timeout(&cmd);
}

void wlan_mlme_wait_for_cmd_completion(struct wlan_objmgr_vdev *vdev)
{
    qdf_event_t vdev_wait_for_active_cmds;
    uint32_t max_wait_iterations =
                   WLAN_SERIALZATION_CANCEL_WAIT_ITERATIONS;
    uint8_t vdev_id = wlan_vdev_get_id(vdev);

    memset(&vdev_wait_for_active_cmds, 0, sizeof(vdev_wait_for_active_cmds));

    qdf_event_create(&vdev_wait_for_active_cmds);
    qdf_event_reset(&vdev_wait_for_active_cmds);

    while(wlan_serialization_get_vdev_active_cmd_type(vdev)
                    != WLAN_SER_CMD_MAX && max_wait_iterations) {
        qdf_wait_single_event(&vdev_wait_for_active_cmds,
                              WLAN_SERIALZATION_CANCEL_WAIT_TIME);
        max_wait_iterations--;
    }

    if (!max_wait_iterations)
            wlan_mlme_err("Waiting for active cmds removal timed out. vdev id: %d\n",
                     vdev_id);

    qdf_event_destroy(&vdev_wait_for_active_cmds);
}

void wlan_mlme_wait_for_scan_cmd_completion(struct wlan_objmgr_vdev *vdev)
{
    qdf_event_t vdev_wait_for_active_cmds;
    uint32_t max_wait_iterations = SCM_CANCEL_SCAN_WAIT_ITERATION;
    uint8_t vdev_id = wlan_vdev_get_id(vdev);
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);

    /* Cancel the scan commands from Pending and Active queue */
    wlan_serialization_purge_all_scan_cmd_by_vdev_id(pdev, vdev_id);

    /* Wait for already activated scan commands to complete */
    memset(&vdev_wait_for_active_cmds, 0, sizeof(vdev_wait_for_active_cmds));

    qdf_event_create(&vdev_wait_for_active_cmds);
    qdf_event_reset(&vdev_wait_for_active_cmds);

    while(wlan_vdev_scan_in_progress(vdev) && max_wait_iterations) {
        qdf_wait_single_event(&vdev_wait_for_active_cmds,
                              SCM_CANCEL_SCAN_WAIT_TIME);
        max_wait_iterations--;
    }

    if (!max_wait_iterations)
        wlan_mlme_err("Failed to wait for scans to get complete: %d\n",
                vdev_id);

    qdf_event_destroy(&vdev_wait_for_active_cmds);
}

QDF_STATUS wlan_mlme_dev_restart(struct wlan_objmgr_vdev *vdev,
                                 enum wlan_serialization_cmd_type type)
{
    QDF_STATUS status;
    QDF_STATUS ret_val;

    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        wlan_mlme_info("unable to get reference");
        return QDF_STATUS_E_BUSY;
    }

    wlan_vdev_mlme_cmd_lock(vdev);
    ret_val = mlme_pdev_or_vdev_restart(vdev, type);
    wlan_vdev_mlme_cmd_unlock(vdev);

    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);

    return ret_val;
}

QDF_STATUS mlme_vdev_add_cmd_to_pq(struct wlan_objmgr_vdev *vdev,
                                   enum wlan_serialization_cmd_type type,
                                   uint8_t high_prio)
{
    struct wlan_serialization_command cmd = {0};
    struct wlan_mlme_ser_data *data;
    QDF_STATUS status;
    enum wlan_serialization_status ret;
    uint8_t vdev_id = wlan_vdev_get_id(vdev);

    wlan_mlme_info("vdev:%d cmd_type:%d", vdev_id, type);

    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
    if (QDF_IS_STATUS_ERROR(status))
        return QDF_STATUS_E_BUSY;

    data = qdf_mem_malloc(sizeof(*data));
    if (!data) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);
        return QDF_STATUS_E_NOMEM;
    }

    data->vdev = vdev;
    cmd.source = WLAN_UMAC_COMP_MLME;
    cmd.vdev = vdev;
    cmd.cmd_type = type;
    cmd.cmd_id = vdev_id;
    cmd.umac_cmd = data;
    cmd.is_high_priority = high_prio;
    cmd.cmd_timeout_duration = WLAN_MLME_SER_CMD_TIMEOUT_MS;

    if (type == WLAN_SER_CMD_VDEV_START_BSS)
        cmd.cmd_cb = mlme_ser_proc_vdev_start;
    else if (type == WLAN_SER_CMD_VDEV_STOP_BSS)
        cmd.cmd_cb = mlme_ser_proc_vdev_stop;
    else {
        wlan_mlme_err("V:%u Unknown cmd type:%d", vdev_id, type);
        goto add_cmd_fail;
    }

    ret = wlan_serialization_request(&cmd);
    if (ret != WLAN_SER_CMD_ACTIVE && ret != WLAN_SER_CMD_PENDING) {
        wlan_mlme_err("V:%u type:%d Enqueue failed ret:%d",
                      vdev_id, type, ret);
        goto add_cmd_fail;
    }

    wlan_mlme_nofl_debug("IF_ADD V:%u type:%d ret:%d", vdev_id, type, ret);
    return QDF_STATUS_SUCCESS;

add_cmd_fail:
    qdf_mem_free(data);
    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);

    return QDF_STATUS_E_FAILURE;
}

static QDF_STATUS mlme_pdev_csa_restart(struct wlan_objmgr_vdev *vdev,
                                 uint32_t flags, uint8_t notify_osif)
{
    struct wlan_mlme_ser_data *data;
    QDF_STATUS status;
    enum wlan_serialization_status ret;
    struct wlan_serialization_command cmd = {0};
    wlan_if_t vap;
    wlan_dev_t ic;
    wlan_if_t tmp_vap;
    osif_dev *osifp;
    uint8_t vdev_id = wlan_vdev_get_id(vdev);

    wlan_mlme_debug("vdev:%d notify:%d", vdev_id, notify_osif);
    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        wlan_mlme_err("vap is NULL");
        return QDF_STATUS_E_FAILURE;
    }
    osifp = (osif_dev *)vap->iv_ifp;
    ic = vap->iv_ic;
    data = qdf_mem_malloc(sizeof(*data));
    if (!data)
        return QDF_STATUS_E_NOMEM;

    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        qdf_mem_free(data);
        return QDF_STATUS_E_BUSY;
    }

    data->vdev = vdev;
    data->flags = flags;
    data->notify_osif = notify_osif;

    cmd.source = WLAN_UMAC_COMP_MLME;
    cmd.vdev = vdev;
    cmd.cmd_type = WLAN_SER_CMD_PDEV_CSA_RESTART;
    cmd.cmd_cb = mlme_ser_proc_pdev_csa_restart;
    cmd.cmd_id = vdev_id;
    cmd.umac_cmd = data;
    cmd.is_blocking = true;
    cmd.cmd_timeout_duration = MLME_SER_RESTART_CMD_TIMEOUT_MS;

    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
        if (tmp_vap->iv_opmode == IEEE80211_M_STA) {
            wlan_cm_disconnect(tmp_vap->vdev_obj, CM_OSIF_CFG_DISCONNECT,
                               REASON_DISASSOC_NETWORK_LEAVING, NULL);
        }
    }

    ret = wlan_vdev_mlme_ser_pdev_csa_restart(&cmd);
    if (ret != WLAN_SER_CMD_ACTIVE && ret != WLAN_SER_CMD_PENDING &&
        ret != WLAN_SER_CMD_ALREADY_EXISTS) {
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);
        qdf_mem_free(data);
        wlan_mlme_nofl_debug("IF_CSA_RESTART V:%u err_ret:%d", vdev_id, ret);
        return QDF_STATUS_E_FAILURE;
    }

    wlan_mlme_nofl_debug("IF_CSA_RESTART V:%u notif:%d ret:%d %s",
                         vdev_id, notify_osif, ret, ret ? "AQ" : "PQ");

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_mlme_pdev_csa_restart(struct wlan_objmgr_vdev *vdev,
        uint32_t flags, uint8_t notify_osif)
{
    QDF_STATUS status;
    QDF_STATUS ret_val;

    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_MLME_SER_IF_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        wlan_mlme_info("unable to get reference");
        return QDF_STATUS_E_BUSY;
    }

    wlan_vdev_mlme_cmd_lock(vdev);
    ret_val = mlme_pdev_csa_restart(vdev, flags, notify_osif);
    wlan_vdev_mlme_cmd_unlock(vdev);

    wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SER_IF_ID);

    return ret_val;
}

QDF_STATUS wlan_mlme_cm_start(struct wlan_objmgr_vdev *vdev,
                              enum wlan_cm_source source)
{
    struct wlan_cm_connect_req req = {0};
    QDF_STATUS ret;

    req.source = source;

    ret = wlan_vdev_mlme_get_ssid(vdev, req.ssid.ssid,
                                  &req.ssid.length);
    if (QDF_IS_STATUS_ERROR(ret)) {
        wlan_mlme_err("SSID not found");
        return ret;
    }

    ret = wlan_vdev_get_bss_peer_mac(vdev, &req.bssid);
    if (QDF_IS_STATUS_ERROR(ret)) {
        wlan_mlme_err("BSSID not found");
        return ret;
    }

    req.crypto.auth_type =
        wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_AUTH_MODE);

    req.crypto.ciphers_pairwise =
        wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_UCAST_CIPHER);

    req.crypto.group_cipher =
        wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_MCAST_CIPHER);

    req.crypto.akm_suites =
        wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_KEY_MGMT);

    req.crypto.rsn_caps =
        wlan_crypto_get_param(vdev, WLAN_CRYPTO_PARAM_RSN_CAP);

    return wlan_cm_start_connect(vdev, &req);
}

QDF_STATUS wlan_mlme_cm_stop(struct wlan_objmgr_vdev *vdev,
                             enum wlan_cm_source source,
                             enum wlan_reason_code reason, bool sync)
{
    if (sync)
        return wlan_cm_disconnect_sync(vdev, source, reason);
    else
        return wlan_cm_disconnect(vdev, source, reason, NULL);
}
