/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2011 Atheros Communications Inc.
 *
 */

#include <target_if_fd.h>
#include <target_if.h>
#include <hif.h>
#include <wmi_unified_api.h>
#include <wlan_lmac_if_def.h>
#include <init_deinit_lmac.h>
#include "wlan_utility.h"

extern uint8_t ol_ath_is_bcn_mode_burst(struct wlan_objmgr_pdev *pdev);

static QDF_STATUS
target_if_fd_vdev_config_fils(struct wlan_objmgr_vdev* vdev, uint32_t fd_period)
{
	struct config_fils_params param;
	struct wlan_objmgr_pdev *pdev;
	void *wmi_hdl;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (pdev == NULL) {
		fd_err("PDEV is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	if (fd_period && !ol_ath_is_bcn_mode_burst(pdev)) {
		fd_err("Beacon mode set to staggered. Cannot enable FD\n");
		return QDF_STATUS_E_INVAL;
	}

	if ((wlan_vdev_chan_config_valid(vdev) == QDF_STATUS_SUCCESS) &&
	    (wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS)) {
		fd_info("Configuring FD frame with period %d\n", fd_period);
		qdf_mem_set(&param, sizeof(param), 0);
		param.vdev_id = wlan_vdev_get_id(vdev);
		param.fd_period = fd_period;
		wmi_hdl = GET_WMI_HDL_FROM_PDEV(pdev);
		if (wmi_hdl == NULL) {
			fd_err("wmi handle is NULL!!\n");
			return QDF_STATUS_E_INVAL;
		}

		return wmi_unified_fils_vdev_config_send_cmd(wmi_hdl, &param);
	}

	return QDF_STATUS_SUCCESS;
}

static int
target_if_fd_swfda_handler(ol_scn_t sc, uint8_t *data, uint32_t datalen)
{
	ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *)sc;
	struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
	struct wlan_objmgr_vdev *vdev = NULL;
	uint32_t vdev_id;
	struct wmi_unified *wmi_handle;
	struct wlan_lmac_if_rx_ops *rx_ops;

	wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
	if (!wmi_handle) {
		fd_err("wmi_handle is null");
		return -EINVAL;
	}

	if (wmi_extract_swfda_vdev_id(wmi_handle, data, &vdev_id)) {
		fd_err("Unable to extact vdev id from swfda event\n");
		return -1;
	}
	if (psoc == NULL) {
		fd_err("PSOC is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	/* Get the VDEV corresponding to the id */
	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id,
				WLAN_FD_ID);
	if (vdev == NULL) {
		fd_err("VDEV not found!\n");
		return -1;
	}

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		fd_err("rx_ops is NULL \n");
		return -1;
	}

	if (rx_ops->fd_rx_ops.fd_swfda_handler(vdev) != QDF_STATUS_SUCCESS) {
		wlan_objmgr_vdev_release_ref(vdev, WLAN_FD_ID);
		return -1;
	}
	wlan_objmgr_vdev_release_ref(vdev, WLAN_FD_ID);

	return 0;
}

static void
target_if_fd_register_event_handler(struct wlan_objmgr_psoc *psoc)
{
	if (psoc == NULL) {
		fd_err("PSOC is NULL!!\n");
		return;
	}

	wmi_unified_register_event_handler(
			get_wmi_unified_hdl_from_psoc(psoc),
			wmi_host_swfda_event_id, target_if_fd_swfda_handler,
			WMI_RX_UMAC_CTX);
}

static QDF_STATUS
target_if_fd_offload_tmpl_send(struct wlan_objmgr_pdev *pdev,
		struct fils_discovery_tmpl_params *fd_tmpl_param)
{
	struct wmi_unified *wmi_hdl;

	if (pdev == NULL) {
		fd_err("PDEV is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	wmi_hdl = get_wmi_unified_hdl_from_pdev(pdev);
	if (wmi_hdl == NULL) {
		fd_err("WMI Handle is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	return wmi_unified_fd_tmpl_send_cmd(wmi_hdl, fd_tmpl_param);
}

static void
target_if_fd_unregister_event_handler(struct wlan_objmgr_psoc *psoc)
{
	if (psoc == NULL) {
		fd_err("PSOC is NULL!!\n");
		return;
	}

	wmi_unified_unregister_event_handler(
			get_wmi_unified_hdl_from_psoc(psoc),
			wmi_host_swfda_event_id);
}

void target_if_fd_register_tx_ops(struct wlan_lmac_if_tx_ops *tx_ops)
{
	struct wlan_lmac_if_fd_tx_ops *fd_tx_ops = &tx_ops->fd_tx_ops;

	fd_tx_ops->fd_vdev_config_fils = target_if_fd_vdev_config_fils;
	fd_tx_ops->fd_register_event_handler =
				target_if_fd_register_event_handler;
	fd_tx_ops->fd_unregister_event_handler =
				target_if_fd_unregister_event_handler;
	fd_tx_ops->fd_offload_tmpl_send = target_if_fd_offload_tmpl_send;
}

QDF_STATUS target_if_fd_offload(struct wlan_objmgr_vdev * vdev)
{
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_rx_ops *rx_ops;

	if (!vdev) {
		fd_err("VDEV not found!\n");
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		fd_err("PSOC is NULL!\n");
		return QDF_STATUS_E_INVAL;
	}

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		fd_err("rx_ops is NULL \n");
		return QDF_STATUS_E_INVAL;
	}
	/* Offload FD frame */
	rx_ops->fd_rx_ops.fd_offload(vdev, (uint32_t)wlan_vdev_get_id(vdev));

	return QDF_STATUS_SUCCESS;
}

void target_if_fd_alloc(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_rx_ops *rx_ops;

	if (!vdev) {
		fd_err("Invalid VDEV!\n");
		return;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (!psoc) {
		fd_err("Invalid PSOC\n");
		return;
	}
	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		fd_err("rx_ops is NULL \n");
		return;
	}

	rx_ops->fd_rx_ops.fd_alloc(vdev);
}

QDF_STATUS target_if_fd_tmpl_update(struct wlan_objmgr_vdev * vdev)
{
	struct wlan_objmgr_psoc *psoc;
	QDF_STATUS retval = 0;
	struct wlan_lmac_if_rx_ops *rx_ops;

	if (vdev == NULL) {
		fd_err("VDEV not found!\n");
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("PSOC is NULL!\n");
		return QDF_STATUS_E_INVAL;
	}

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		fd_err("rx_ops is NULL \n");
		return QDF_STATUS_E_INVAL;
	}
	if (!rx_ops->fd_rx_ops.fd_is_fils_enable(vdev))
		return QDF_STATUS_E_INVAL;

	/* Offload FD frame */
	retval = rx_ops->fd_rx_ops.fd_tmpl_update(vdev);

	return retval;
}

QDF_STATUS target_if_fd_reconfig(struct wlan_objmgr_vdev *vdev)
{
	uint32_t fd_period = 0;
	struct wlan_objmgr_psoc *psoc;
	struct ieee80211vap *vap;
	uint8_t is_modified = 0;
	struct wlan_lmac_if_rx_ops *rx_ops;

	if (vdev == NULL) {
		fd_err("VDEV not found!\n");
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("PSOC is NULL\n");
		return QDF_STATUS_E_INVAL;
	}
	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (vap == NULL) {
		fd_err("VAP is NULL\n");
		return QDF_STATUS_E_INVAL;
	}

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		fd_err("rx_ops is NULL \n");
		return QDF_STATUS_E_INVAL;
	}

	if (IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan) &&
	    !wlan_vdev_mlme_feat_ext_cap_get(vdev,
				WLAN_VDEV_FEXT_FILS_DISC_6G_SAP)) {
		fd_debug("FILS is not enabled on this 6GHz AP");
		return QDF_STATUS_E_INVAL;
	}
	/* Get valid FD Period */
	fd_period = rx_ops->fd_rx_ops.fd_get_valid_fd_period(vdev,
							     &is_modified);
	if (!IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan)) {
		/* Allocate FD buff */
		target_if_fd_alloc(vdev);
	}

	/* FD enable WMI for offload case(6GHz) is sent after vap up */
	return target_if_fd_vdev_config_fils(vdev, fd_period);
}

QDF_STATUS target_if_fd_send(struct wlan_objmgr_vdev *vdev, qdf_nbuf_t wbuf)
{
	struct fd_params param;
	uint16_t frame_ctrl;
	struct ieee80211_frame *wh;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_pdev *pdev;
	void *wmi_hdl;

	if (vdev == NULL) {
		fd_err("VDEV not found!\n");
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("PSOC is NULL\n");
		return QDF_STATUS_E_INVAL;
	}
	pdev = wlan_vdev_get_pdev(vdev);
	if (pdev == NULL) {
		fd_err("PDEV is NULL\n");
		return QDF_STATUS_E_INVAL;
	}

	qdf_mem_zero(&param, sizeof(param));
	param.wbuf = wbuf;
	param.vdev_id = wlan_vdev_get_id(vdev);

	/* Get the frame ctrl field */
	wh = (struct ieee80211_frame *)qdf_nbuf_data(wbuf);
	frame_ctrl = qdf_le16_to_cpu(*((uint16_t *)wh->i_fc));

	/* Map the FD buffer to DMA region */
	qdf_nbuf_map_single(wlan_psoc_get_qdf_dev(psoc), wbuf,
			QDF_DMA_TO_DEVICE);

	param.frame_ctrl = frame_ctrl;
	wmi_hdl = GET_WMI_HDL_FROM_PDEV(pdev);
	if (wmi_hdl == NULL) {
		fd_err("wmi handle is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	return wmi_unified_fils_discovery_send_cmd(wmi_hdl, &param);
}

void target_if_fd_stop(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_rx_ops *rx_ops;

	if (vdev == NULL) {
		fd_err("VDEV not found!\n");
		return;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("PSOC is NULL\n");
		return;
	}

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		fd_err("rx_ops is NULL \n");
		return;
	}

	rx_ops->fd_rx_ops.fd_stop(vdev);
}

void target_if_fd_free(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_rx_ops *rx_ops;

	if (vdev == NULL) {
		fd_err("VDEV not found!\n");
		return;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("PSOC is NULL\n");
		return;
	}

	rx_ops = wlan_psoc_get_lmac_if_rxops(psoc);
	if (!rx_ops) {
		fd_err("rx_ops is NULL \n");
		return;
	}

	rx_ops->fd_rx_ops.fd_free(vdev);
}
