/*
 * Copyright (c) 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc
 */

#ifndef __RAWSIM_API_DEFS__
#define __RAWSIM_API_DEFS__
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_objmgr_psoc_obj.h>
#include <qdf_list.h>
#include <qdf_timer.h>
#include <qdf_util.h>
#include <ieee80211_var.h>
#include <dp_txrx.h>
#include <cdp_txrx_raw.h>
#include <cdp_txrx_cmn_struct.h>
#include <osif_private.h>

extern struct rawsim_ops *g_rs_ops;

struct rawsim_ast_entry {
	uint8_t ast_found;
	uint8_t mac_addr[6];
};

#define RAWSIM_MIN_FRAGS_PER_TX_MPDU 2


struct rawmode_sim_cfg {
#if MESH_MODE_SUPPORT
	u_int8_t mesh_mode;
	u_int32_t mhdr;
	u_int32_t mdbg;
	u_int8_t mhdr_len;
	u_int8_t bssid_mesh[QDF_MAC_ADDR_SIZE];
#endif
	uint8_t vdev_id;
	uint8_t opmode;
	u_int8_t rawmodesim_txaggr:4,
		 rawmodesim_debug_level:2;
	bool privacyEnabled;
	u_int8_t tx_encap_type;
	u_int8_t rx_decap_type;
	u_int8_t rawmode_pkt_sim;
};

struct rawsim_ops {
	struct rawmode_sim_ctxt *
		(*create_rawsim_ctxt)(void);
	void (*rsim_rx_decap)(struct rawmode_sim_ctxt *ctxt,
			      qdf_nbuf_t *pdeliver_list_head,
			      qdf_nbuf_t *pdeliver_list_tail,
			      uint8_t *peer_mac,
			      uint32_t sec_type,
			      uint32_t auth_type);
	int (*rsim_tx_encap)(struct rawmode_sim_ctxt *ctxt,
			     qdf_nbuf_t *pnbuf,
			     u_int8_t *bssid,
			     struct rawsim_ast_entry ast_entry);
	void (*print_rawmode_pkt_sim_stats)(struct rawmode_sim_ctxt *ctxt);
	void (*clear_rawmode_pkt_sim_stats)(struct rawmode_sim_ctxt *ctxt);
	int (*update_rawsim_config)(struct rawmode_sim_cfg cfg,
				    struct rawmode_sim_ctxt *ctxt);
	int (*update_rawsim_encap_frame_count)(struct rawmode_sim_ctxt *ctxt,
					       int frame_count,
					       u_int8_t flag);
	int (*update_rawsim_decap_frame_count)(struct rawmode_sim_ctxt *ctxt,
					       int frame_count,
					       u_int8_t flag);
	void (*delete_rawsim_ctxt)(struct rawmode_sim_ctxt *ctxt);
};

static inline void wlan_rawsim_api_rx_decap(os_if_t osif,
					    qdf_nbuf_t *pdeliver_list_head,
					    qdf_nbuf_t *pdeliver_list_tail,
					    uint8_t *peer_mac)
{
	osif_dev  *osdev = (osif_dev *)osif;
	wlan_if_t vap = osdev->os_if;
	ol_txrx_soc_handle soc_txrx_handle;
	struct rawmode_sim_ctxt *ctxt;
	uint8_t vdev_id;
	int32_t sec_type = 0;
	int32_t auth_type = 0;

	if (vap == NULL) {
		qdf_rl_err("NULL vap");
		return;
	}

	vdev_id = wlan_vdev_get_id(vap->vdev_obj);
	soc_txrx_handle = wlan_psoc_get_dp_handle
			(wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj));

	if (!soc_txrx_handle) {
		qdf_rl_nofl_info("NULL soc");
		return;
	}

	sec_type = wlan_crypto_get_param(vap->vdev_obj,
					 WLAN_CRYPTO_PARAM_UCAST_CIPHER);
        if ( sec_type == -1 ) {
            qdf_rl_err("crypto_err while getting ucast_cipher params\n");
            return ;
        }

	auth_type = wlan_crypto_get_param(vap->vdev_obj,
					  WLAN_CRYPTO_PARAM_AUTH_MODE);

        if ( auth_type == -1 ) {
            qdf_rl_err("crypto_err while getting authmode params\n");
            return ;
        }

	if (g_rs_ops && g_rs_ops->rsim_rx_decap) {
		ctxt = dp_get_vdev_rawmode_sim_ctxt(soc_txrx_handle, vdev_id);
		g_rs_ops->rsim_rx_decap(ctxt,
					pdeliver_list_head,
					pdeliver_list_tail,
					peer_mac,
					sec_type,
					auth_type);
	} else {
		qdf_rl_err("g_rs_ops->rsim_rx_decap not registered");
	}
}

/* Files which includes this header file should also include if_meta_hdr.h */
#if MESH_MODE_SUPPORT
#define MESH_DBG_FLAGS_OFFSET 24
static inline void wlan_rawsim_update_mhdr(struct ieee80211vap* vap, int status)
{
	if (vap->iv_mesh_vap_mode && !status) {
		vap->mhdr &=
			~(METAHDR_FLAG_INFO_UPDATED << MESH_DBG_FLAGS_OFFSET);
	}
}
#else
static inline void wlan_rawsim_update_mhdr(struct ieee80211vap* vap, int status)
{

}
#endif

static inline int wlan_rawsim_api_tx_encap(struct ieee80211vap* vap,
					   qdf_nbuf_t *pnbuf)
{
	struct rawsim_ast_entry ast_entry;
	uint8_t vdev_id;
	u_int8_t bssid[QDF_MAC_ADDR_SIZE];
	ol_txrx_soc_handle soc_txrx_handle;
	struct rawmode_sim_ctxt *ctxt;
	int status = 0;

	if (!vap) {
		qdf_rl_err("NULL vap");
		return -1;
	}

	soc_txrx_handle = wlan_psoc_get_dp_handle
				(wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj));
	if (!soc_txrx_handle) {
		qdf_rl_nofl_info("NULL soc");
		return -1;
	}

	vdev_id = wlan_vdev_get_id(vap->vdev_obj);
	ast_entry.ast_found = 0;
	cdp_rawsim_get_astentry(soc_txrx_handle,
				vdev_id,
				pnbuf,
				(struct cdp_raw_ast *)&ast_entry);
	ctxt = dp_get_vdev_rawmode_sim_ctxt(soc_txrx_handle, vdev_id);
	wlan_vap_get_bssid(vap, bssid);

	if (g_rs_ops && g_rs_ops->rsim_tx_encap) {
		status = g_rs_ops->rsim_tx_encap(ctxt,
						 pnbuf,
						 bssid,
						 ast_entry);
		wlan_rawsim_update_mhdr(vap, status);
		return status;
	} else {
		qdf_rl_err("g_rs_ops->rsim_tx_encap not registered");
	}
	return -1;
}

extern ol_txrx_rsim_rx_decap_fp wlan_rawsim_api_get_rx_decap(void);

extern void wlan_rawsim_api_print_stats(struct rawmode_sim_ctxt *ctxt);

extern void wlan_rawsim_api_clear_stats(struct rawmode_sim_ctxt *ctxt);

extern int wlan_update_rawsim_encap_frame_count(struct ieee80211vap *vap);

extern int wlan_update_rawsim_decap_frame_count(struct ieee80211vap *vap);

extern int wlan_update_rawsim_config(struct ieee80211vap *vap);

extern void wlan_create_attach_vdev_rawsim_ctxt(struct ieee80211vap *vap);

extern void wlan_delete_rawsim_ctxt(struct rawmode_sim_ctxt *ctxt);

extern void register_rawsim_ops(struct rawsim_ops *rs_ops);

extern void deregister_rawsim_ops(void);
#endif /* __RAWSIM_API_DEFS__ */
