/*
 * Copyright (c) 2018, 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#include "fd_priv_i.h"
#include "wlan_fd_utils_api.h"

static QDF_STATUS fd_enable_ol(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_tx_ops *tx_ops;
	if (psoc == NULL) {
		qdf_info("Invalid PSOC!");
		return QDF_STATUS_E_INVAL;
	}

	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops) {
		qdf_info("tx_ops is NULL");
		return QDF_STATUS_E_INVAL;
	}

	if (tx_ops->fd_tx_ops.fd_register_event_handler)
		tx_ops->fd_tx_ops.fd_register_event_handler(psoc);

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS fd_disable_ol(struct wlan_objmgr_psoc *psoc)
{
	struct wlan_lmac_if_tx_ops *tx_ops;
	if (psoc == NULL) {
		qdf_info("Invalid PSOC!");
		return QDF_STATUS_E_INVAL;
	}

	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops) {
		qdf_info("tx_ops is NULL");
		return QDF_STATUS_E_INVAL;
	}

	if (tx_ops->fd_tx_ops.fd_unregister_event_handler)
		tx_ops->fd_tx_ops.fd_unregister_event_handler(psoc);

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS fd_tmpl_send(struct wlan_objmgr_pdev *pdev,
		struct fils_discovery_tmpl_params *fd_tmpl_param)
{
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_tx_ops *tx_ops;
	QDF_STATUS retval = 0;

	if (pdev == NULL) {
		qdf_err("Invlaid PDEV!");
		return QDF_STATUS_E_INVAL;
	}

	psoc = wlan_pdev_get_psoc(pdev);
	if (psoc == NULL) {
		qdf_err("Invalid PSOC!");
		return QDF_STATUS_E_INVAL;
	}

	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops) {
		qdf_info("tx_ops is NULL");
		return QDF_STATUS_E_INVAL;
	}

	if (tx_ops->fd_tx_ops.fd_offload_tmpl_send)
		retval = tx_ops->fd_tx_ops.fd_offload_tmpl_send(pdev, fd_tmpl_param);

	return retval;
}

void fd_ctx_init(struct fd_context *fd_ctx)
{
	fd_ctx->is_fd_capable = true;

	fd_ctx->fd_enable = fd_enable_ol;
	fd_ctx->fd_disable = fd_disable_ol;
	fd_ctx->fd_tmpl_send = fd_tmpl_send;
}

void fd_ctx_deinit(struct fd_context *fd_ctx)
{
	fd_ctx->is_fd_capable = false;

	fd_ctx->fd_enable = NULL;
	fd_ctx->fd_disable = NULL;
	fd_ctx->fd_tmpl_send = NULL;
}

void fd_vdev_configure_fils(struct wlan_objmgr_vdev* vdev, uint32_t fd_period)
{
	struct fd_vdev *fv;
	struct wlan_objmgr_psoc *psoc;
	struct wlan_lmac_if_tx_ops *tx_ops;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("PSOC is NULL!!\n");
		return;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_err("FILS Discovery obj is NULL\n");
		return;
	}

	fd_period &= WLAN_FD_PERIOD_MASK;
	if (!wlan_fd_capable(psoc)) {
		fd_info("FILS Discovery not Supported!\n");
		fd_period = 0;
	}
	tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	if (!tx_ops) {
		qdf_info("tx_ops is NULL");
		return;
	}

	qdf_spin_lock_bh(&fv->fd_period_lock);
	wlan_fd_set_valid_fd_period(vdev, fd_period);

	if (tx_ops->fd_tx_ops.fd_vdev_config_fils)
		tx_ops->fd_tx_ops.fd_vdev_config_fils(vdev, fv->fd_period);
	qdf_spin_unlock_bh(&fv->fd_period_lock);
}

static void fd_free_buf_entry(struct wlan_objmgr_psoc *psoc,
			      struct fd_buf_entry *buf_entry)
{
	qdf_device_t qdf_dev;

	qdf_dev = wlan_psoc_get_qdf_dev(psoc);
	if (!qdf_dev) {
		fd_err("qdf_device is Null");
		return;
	}
	if (buf_entry) {
		if (buf_entry->fd_buf) {
			if (buf_entry->is_dma_mapped) {
				qdf_nbuf_unmap_single(qdf_dev,
						      buf_entry->fd_buf,
						      QDF_DMA_TO_DEVICE);
				buf_entry->is_dma_mapped = false;
			}
			qdf_nbuf_free(buf_entry->fd_buf);
		}
		qdf_mem_free(buf_entry);
	}
}

void fd_free_list(struct wlan_objmgr_psoc *psoc, qdf_list_t *fd_deferred_list)
{
	struct fd_buf_entry *buf_entry;
	qdf_list_node_t *node = NULL;

	if (!psoc || !fd_deferred_list)
		return;

	while (!qdf_list_empty(fd_deferred_list)) {
		if (QDF_STATUS_SUCCESS !=
			qdf_list_remove_front(fd_deferred_list, &node)) {
			fd_err("Failed removal of node from list!\n");
			break;
		}
		if (node) {
			buf_entry = qdf_container_of(node, struct fd_buf_entry,
						     fd_deferred_list_elem);
			fd_free_buf_entry(psoc, buf_entry);
		}
		buf_entry = NULL;
		node = NULL;
	}
}

