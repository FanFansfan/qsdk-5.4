/*
 * Copyright (c) 2017, 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
*/

/*
 *This File provides framework direct attach architecture for SON.
*/
#ifndef __WLAN_SON_SUPPORT_TGT_API_H_
#define __WLAN_SON_SUPPORT_TGT_API_H_

#include <wlan_objmgr_cmn.h>
#include <qdf_status.h>

struct wlan_lmac_if_son_tx_ops {
	/* Function pointer to enable/disable band steering */
	QDF_STATUS (*son_send_null)(struct wlan_objmgr_pdev *pdev,
				    u_int8_t *macaddr,
				    struct wlan_objmgr_vdev *vdev);

	u_int32_t  (*get_peer_rate)(struct wlan_objmgr_peer *peer, u_int8_t type);

	QDF_STATUS (*peer_ext_stats_enable)(struct wlan_objmgr_pdev *pdev,
					    u_int8_t *peer_addr,
					    struct wlan_objmgr_vdev *vdev,
					    u_int32_t stats_count, u_int32_t enable);
};

struct wlan_lmac_if_son_rx_ops {
};

#endif
