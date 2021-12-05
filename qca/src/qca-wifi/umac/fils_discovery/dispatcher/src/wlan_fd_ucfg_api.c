/*
 *
 * Copyright (c) 2018 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#include <wlan_fd_ucfg_api.h>
#include <wlan_fd_utils_api.h>
#include "../../core/fd_priv_i.h"

uint32_t ucfg_fd_get_enable_period(uint32_t value1, uint32_t value2)
{
	if (value1) {
		value1 = (1 << WLAN_FILS_ENABLE_BIT);
		value2 &= WLAN_FD_PERIOD_MASK;
	} else {
		value2 = 0;
	}

	return (value1 | value2);
}

void ucfg_fils_config(struct wlan_objmgr_vdev *vdev, uint32_t value)
{
	struct fd_vdev *fv;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_err("FILS Discovery obj is NULL\n");
		return;
	}

	if (value & (1 << WLAN_FILS_ENABLE_BIT)) {
		if(!(value & WLAN_FD_PERIOD_MASK)) {
			fd_err("Invalid FD period for enabling FD frame. \n"
				"Minimum valid valid value for FD is %d ms\n",
				WLAN_FD_INTERVAL_MIN);
			return;
		}
		fv->fils_enable = 1;
		fd_info("[Vdev-%d] FILS Enable\n", wlan_vdev_get_id(vdev));
	} else {
		if(!fv->fils_enable) {
			fd_err("FILS Discovery is already disabled\n");
			return;
		} else {
			fv->fils_enable = 0;
			fd_info("[Vdev-%d] FILS Disable\n",
				wlan_vdev_get_id(vdev));
		}
	}

	fd_vdev_configure_fils(vdev, value);
}

/* ucfg_fils_disable() is needed in addition to the ucfg_fils_config() API
 * to disable the FD setting without sending the disable WMI to FW.
 */
void ucfg_fils_disable(struct wlan_objmgr_vdev *vdev)
{
	struct fd_vdev *fv;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_err("FILS Discovery obj is NULL\n");
		return;
	}

	/* Reset the FILS period before disabling */
	fd_vdev_configure_fils(vdev, 0);
	fv->fils_enable = 0;
}
