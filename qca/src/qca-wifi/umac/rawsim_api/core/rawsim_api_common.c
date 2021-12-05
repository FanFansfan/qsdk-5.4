/*
 * Copyright (c) 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#include <qdf_types.h>
#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif
#include "rawsim_api_defs.h"

struct rawsim_ops *g_rs_ops = NULL;
qdf_export_symbol(g_rs_ops);

void wlan_rawsim_api_print_stats(struct rawmode_sim_ctxt *ctxt)
{
	if (g_rs_ops && g_rs_ops->print_rawmode_pkt_sim_stats)
		g_rs_ops->print_rawmode_pkt_sim_stats(ctxt);
	else
		qdf_err("rawmode simulation print stats api not registered");
}
qdf_export_symbol(wlan_rawsim_api_print_stats);

void wlan_rawsim_api_clear_stats(struct rawmode_sim_ctxt *ctxt)
{
	if (g_rs_ops && g_rs_ops->clear_rawmode_pkt_sim_stats)
		g_rs_ops->clear_rawmode_pkt_sim_stats(ctxt);
	else
		qdf_err("rawmode simulation clear stats api not registered");
}
qdf_export_symbol(wlan_rawsim_api_clear_stats);

ol_txrx_rsim_rx_decap_fp wlan_rawsim_api_get_rx_decap(void)
{
	return (ol_txrx_rsim_rx_decap_fp)wlan_rawsim_api_rx_decap;
}
qdf_export_symbol(wlan_rawsim_api_get_rx_decap);

int wlan_update_rawsim_config(struct ieee80211vap *vap)
{
	struct rawmode_sim_cfg cfg;
	ol_txrx_soc_handle soc_txrx_handle;
	struct rawmode_sim_ctxt *ctxt;
	uint8_t vdev_id;

	if (!vap) {
		qdf_rl_err("NULL vap");
		return 0;
	}

	soc_txrx_handle = wlan_psoc_get_dp_handle
				(wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj));
	if (!soc_txrx_handle)
		return 0;

	vdev_id = wlan_vdev_get_id(vap->vdev_obj);
	ctxt = dp_get_vdev_rawmode_sim_ctxt(soc_txrx_handle, vdev_id);

	if (!ctxt)
		return 0;

#if MESH_MODE_SUPPORT
	cfg.mesh_mode = vap->iv_mesh_vap_mode;
	cfg.mhdr = vap->mhdr;
	cfg.mdbg = vap->mdbg;
	cfg.mhdr_len = vap->mhdr_len;
	IEEE80211_ADDR_COPY(cfg.bssid_mesh, vap->bssid_mesh);
#endif
	cfg.vdev_id = vdev_id;
	cfg.opmode = wlan_vap_get_opmode(vap);
	cfg.rawmodesim_txaggr = vap->iv_rawmodesim_txaggr;
	cfg.rawmodesim_debug_level = vap->iv_rawmodesim_debug_level;
	cfg.privacyEnabled = IEEE80211_VAP_IS_PRIVACY_ENABLED(vap);
	cfg.tx_encap_type = vap->iv_tx_encap_type;
	cfg.rx_decap_type = vap->iv_rx_decap_type;
	cfg.rawmode_pkt_sim = vap->iv_rawmode_pkt_sim;

	if (g_rs_ops && g_rs_ops->update_rawsim_config)
		return g_rs_ops->update_rawsim_config(cfg, ctxt);

	return 0;
}
qdf_export_symbol(wlan_update_rawsim_config);

int wlan_update_rawsim_encap_frame_count(struct ieee80211vap *vap)
{
	ol_txrx_soc_handle soc_txrx_handle;
	struct rawmode_sim_ctxt *ctxt;
	uint8_t vdev_id;
	int frame_count;
	u_int8_t flag = 0;

	if (!vap) {
		qdf_rl_err("NULL vap");
		return 0;
	}

	soc_txrx_handle = wlan_psoc_get_dp_handle
		(wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj));
	if (!soc_txrx_handle)
		return 0;

	vdev_id = wlan_vdev_get_id(vap->vdev_obj);
	ctxt = dp_get_vdev_rawmode_sim_ctxt(soc_txrx_handle, vdev_id);
	if (!ctxt)
		return 0;

	frame_count = vap->iv_num_encap_frames;
	flag = vap->iv_fixed_frm_cnt_flag;

	if (g_rs_ops && g_rs_ops->update_rawsim_encap_frame_count)
		return g_rs_ops->update_rawsim_encap_frame_count
			(ctxt, frame_count, flag);
	return 0;
}
qdf_export_symbol(wlan_update_rawsim_encap_frame_count);

int wlan_update_rawsim_decap_frame_count(struct ieee80211vap *vap)
{
	ol_txrx_soc_handle soc_txrx_handle;
	struct rawmode_sim_ctxt *ctxt;
	uint8_t vdev_id;
	int frame_count;
	u_int8_t flag = 0;

	if (!vap) {
		qdf_rl_err("NULL vap");
		return 0;
	}

	soc_txrx_handle = wlan_psoc_get_dp_handle
		(wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj));
	if (!soc_txrx_handle)
		return 0;

	vdev_id = wlan_vdev_get_id(vap->vdev_obj);
	ctxt = dp_get_vdev_rawmode_sim_ctxt(soc_txrx_handle, vdev_id);
	if (!ctxt)
		return 0;

	frame_count = vap->iv_num_decap_frames;
	flag = vap->iv_fixed_frm_cnt_flag;

	if (g_rs_ops && g_rs_ops->update_rawsim_decap_frame_count)
		return g_rs_ops->update_rawsim_decap_frame_count
			(ctxt, frame_count, flag);

	return 0;
}
qdf_export_symbol(wlan_update_rawsim_decap_frame_count);

void wlan_delete_rawsim_ctxt(struct rawmode_sim_ctxt *ctxt)
{
	if (g_rs_ops && g_rs_ops->delete_rawsim_ctxt)
		g_rs_ops->delete_rawsim_ctxt(ctxt);
}

void wlan_create_attach_vdev_rawsim_ctxt(struct ieee80211vap *vap)
{
	uint8_t vdev_id;
	ol_txrx_soc_handle soc_txrx_handle;
	struct rawmode_sim_ctxt *ctxt = NULL;
	dp_vdev_txrx_handle_t *dp_hdl;

	if (!vap) {
		qdf_err("NULL vap");
		return;
	}

	soc_txrx_handle = wlan_psoc_get_dp_handle
				(wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj));
	if (!soc_txrx_handle) {
		qdf_err("Failed to get soc");
		return;
	}

	vdev_id = wlan_vdev_get_id(vap->vdev_obj);

	dp_hdl = cdp_vdev_get_dp_ext_txrx_handle(soc_txrx_handle, vdev_id);

	if (!dp_hdl) {
		qdf_err("NULL dp_hdl");
		return;
	}

	if (ctxt) {
		qdf_err("rawsim ctxt already attached for vdev[%u]", vdev_id);
		return;
	}

	if (g_rs_ops && g_rs_ops->create_rawsim_ctxt) {
		ctxt = g_rs_ops->create_rawsim_ctxt();
		if (!ctxt) {
			qdf_err("Fail to create simulation context");
			return;
		}
		dp_hdl->rsim_ctxt = ctxt;
	} else {
		qdf_err("simulation module not registerd");
		return;
	}
}

void register_rawsim_ops(struct rawsim_ops *rs_ops)
{
	g_rs_ops = rs_ops;
}

void deregister_rawsim_ops(void)
{
	g_rs_ops = NULL;
}
