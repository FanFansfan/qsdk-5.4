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

#include <ol_if_athvar.h>
#include <init_deinit_lmac.h>

/**
 * ol_ath_bss_color_collision_det_config_event_handler() - bss color
 * collision detect event handler
 * @sc: soc context
 * @data: event data
 * @datalen: data len
 *
 * Return: return 0 on success, other value on failure
 */
static int
ol_ath_bss_color_collision_det_config_event_handler(ol_soc_t sc, uint8_t *data,
						    uint32_t datalen)
{
	ol_ath_soc_softc_t *soc           = (ol_ath_soc_softc_t *) sc;
	struct ieee80211vap *vap          = NULL;
	struct ieee80211com *ic           = NULL;
	struct wlan_objmgr_vdev *vdev;
	struct wmi_unified *wmi_handle;
	struct wmi_obss_color_collision_info info;
	uint32_t vdev_id;

	QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
		  "%s>>", __func__);

	wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);

	if (!wmi_handle) {
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "%s wmi handle is NULL", __func__);
		return -EINVAL;
	}

	if (wmi_unified_extract_obss_color_collision_info(wmi_handle,
	    data, &info) != QDF_STATUS_SUCCESS) {
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "%s<< Extracting bss color collision info failed",
			   __func__);
		return -1;
	}

	vdev_id = info.vdev_id;
	vdev = wlan_objmgr_get_vdev_by_id_from_psoc(soc->psoc_obj, vdev_id,
						    WLAN_MLME_SB_ID);

	if (!vdev) {
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "%s<< Unable to find vdev for %d vdev_id",
			  __func__, vdev_id);
		return -EINVAL;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "vap is NULL");
		wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);
		return QDF_STATUS_E_FAILURE;
	}

	ic = vap->iv_ic;

	switch(info.evt_type) {
	case OBSS_COLOR_COLLISION_DETECTION:
		/* Disable BSS Color collision fw offload */
		ol_ath_config_bss_color_offload(vap, true);

		/* if user has overridden bsscolor to force it
		 * then disable force bit on collision detection
		 * as the collision has happened on the forced
		 * color
		 */
		ic->ic_he_bsscolor_override = false;

		/* call BSS Color detection call back to bsscolor
		 * module
		 */
		ic->ic_bsscolor_hdl.
			ieee80211_bss_color_collision_detection_hdler_cb
			(ic, info.obss_color_bitmap_bit0to31,
			 info.obss_color_bitmap_bit32to63);
	break;
	default:
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "Unhandled BSS Color Event : 0x%x received",
			  info.evt_type);
	}


	wlan_objmgr_vdev_release_ref(vdev, WLAN_MLME_SB_ID);

	QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
		  "%s<<", __func__);
	return 0;
}

void ol_ath_config_bss_color_offload(wlan_if_t vap, bool disable)
{
	struct wlan_objmgr_pdev *pdev = NULL;
	struct wmi_unified *pdev_wmi_handle = NULL;
	struct ieee80211com *ic = vap->iv_ic;
	struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
	struct wmi_obss_color_collision_cfg_param collision_cfg_param;

	QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
		  "%s>> %s", __func__, disable ? "true" : "false");

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "%s<< pdev NULL", __func__);
		return;
	}

	pdev_wmi_handle = lmac_get_pdev_wmi_handle(pdev);
	if (!pdev_wmi_handle) {
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "%s<< wmi handle NULL", __func__);
		return;
	}

	qdf_mem_zero(&collision_cfg_param,
		     sizeof(struct wmi_obss_color_collision_cfg_param));

	/* populate bss_color_collision_cfg_cmd */
	collision_cfg_param.vdev_id        = wlan_vdev_get_id(vap->vdev_obj);
	collision_cfg_param.scan_period_ms =
				IEEE80211_BSS_COLOR_COLLISION_SCAN_PERIOD_MS;

	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
		if (disable) {
			collision_cfg_param.evt_type =
					OBSS_COLOR_COLLISION_DETECTION_DISABLE;
		} else {
			collision_cfg_param.evt_type =
					OBSS_COLOR_COLLISION_DETECTION;
		}

		collision_cfg_param.current_bss_color =
					ic->ic_bsscolor_hdl.selected_bsscolor;
		collision_cfg_param.detection_period_ms =
			IEEE80211_BSS_COLOR_COLLISION_DETECTION_AP_PERIOD_MS;
	} else {
		collision_cfg_param.evt_type = OBSS_COLOR_COLLISION_DETECTION;
		collision_cfg_param.detection_period_ms =
			IEEE80211_BSS_COLOR_COLLISION_DETECTION_STA_PERIOD_MS;

		/* send bss_color_change_enable_cmd with enable set to true */
		if (wmi_unified_send_bss_color_change_enable_cmd(
			pdev_wmi_handle, wlan_vdev_get_id(vap->vdev_obj), true))
			QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
				  "%s<< returned failure", __func__);
	}

	if (wmi_unified_send_obss_color_collision_cfg_cmd(pdev_wmi_handle,
	    &collision_cfg_param))
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "%s<< returned failure", __func__);

	QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
		  "%s<<", __func__);
}

void
ol_ath_mgmt_register_bss_color_collision_det_config_evt(struct ieee80211com *ic)
{
	struct wlan_objmgr_psoc *psoc;
	wmi_unified_t wmi_handle;

	QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
		  "%s>>", __func__);

	psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

	wmi_handle = lmac_get_wmi_unified_hdl(psoc);

	if (!wmi_handle) {
		QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
			  "%s<< wmi_handle is null", __func__);
		return;
	}

	wmi_unified_register_event_handler(wmi_handle,
			wmi_obss_color_collision_report_event_id,
			ol_ath_bss_color_collision_det_config_event_handler,
			WMI_RX_UMAC_CTX);

	QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
		  "%s<<", __func__);
}
