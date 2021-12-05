/*
 * Copyright (c) 2017-2018 Qualcomm Innovation Center, Inc.
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
/**
 * DOC: init_deinit_ops.h
 *
 * Public APIs to WIN ops
 */

#ifndef _INIT_DEINIT_OPS_H_
#define _INIT_DEINIT_OPS_H_

/**
 * init_deinit_register_featurs_ops()- To Register feature ops
 * @psoc: PSOC object
 *
 * API to register feature ops
 *
 *Return: SUCCESS on succesful registration of feature ops or FAILURE
 */
QDF_STATUS init_deinit_register_featurs_ops(struct wlan_objmgr_psoc *psoc);

/**
 * init_deinit_get_total_peers_for_pdev_id() - Get total number of peers from
 * cfg private context of psoc for given pdev id.
 * @psoc: PSOC object
 * @pdev_id : Pdev id
 *
 * This API can be called only before WMI_INIT_CMDID sent from host to FW.
 * After WMI_READY_EVENTID, call either wlan_pdev_get_max_peer_count()/
 * wlan_psoc_get_max_peer_count().
 *
 * Return: Sum of number of vdevs, montior vaps and peers for given pdev id.
 */
uint16_t init_deinit_get_total_peers_for_pdev_id(struct wlan_objmgr_psoc *psoc,
		uint16_t pdev_id);

/**
 * init_deinit_get_total_vdevs_for_pdev_id() - Get total number of vdevs from
 * cfg private context of psoc for given pdev id.
 * @psoc: PSOC object
 * @pdev_id : Pdev id
 *
 * This API can be called only before WMI_INIT_CMDID sent from host to FW.
 * After WMI_READY_EVENTID, call either wlan_pdev_get_max_vdev_count()/
 * wlan_psoc_get_max_vdev_count().
 *
 * Return: Sum of number of vdevs, montior vaps for given pdev id.
 */
uint8_t init_deinit_get_total_vdevs_for_pdev_id(struct wlan_objmgr_psoc *psoc,
		uint16_t pdev_id);

/**
 * init_deinit_get_qwrap_peers_for_pdev_id() - Get total number of qwrap peers
 * from cfg private context of psoc for given pdev id.
 * @psoc: PSOC object
 * @pdev_id : Pdev id
 *
 * This API can be called only before WMI_INIT_CMDID sent from host to FW.
 * After WMI_READY_EVENTID, call either wlan_pdev_get_max_vdev_count()/
 * wlan_psoc_get_max_vdev_count().
 *
 * Return: Number of qwrap peers for given pdev_id in max client mode
 */
uint8_t init_deinit_get_qwrap_peers_for_pdev_id(struct wlan_objmgr_psoc *psoc,
		uint16_t pdev_id);

/**
 * init_deinit_get_qwrap_vdevs_for_pdev_id() - Get total number of qwrap vdevs
 * from cfg private context of psoc for given pdev id.
 * @psoc: PSOC object
 * @pdev_id : Pdev id
 *
 * This API can be called only before WMI_INIT_CMDID sent from host to FW.
 * After WMI_READY_EVENTID, call either wlan_pdev_get_max_vdev_count()/
 * wlan_psoc_get_max_vdev_count().
 *
 * Return: Number of qwrap vdevs for given pdev_id in max client mode
 */
uint8_t init_deinit_get_qwrap_vdevs_for_pdev_id(struct wlan_objmgr_psoc *psoc,
		uint16_t pdev_id);
#endif /* _INIT_DEINIT_OPS_H_ */
