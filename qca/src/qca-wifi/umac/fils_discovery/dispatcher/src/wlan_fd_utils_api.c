/*
 * Copyright (c) 2011, 2017-2018 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include <ieee80211_var.h>
#include <ieee80211_rateset.h>
#include <qdf_nbuf.h>
#include <wlan_mlme_dispatcher.h>
#include <wlan_fd_utils_api.h>
#include <wlan_vdev_mgr_utils_api.h>
#include <wlan_mlme_if.h>
#include <ieee80211_objmgr_priv.h>
#include "../../core/fd_priv_i.h"
#include <wlan_rnr.h>
#include "ol_if_athvar.h"

#define WLAN_FD_MIN_HEAD_ROOM 64

static QDF_STATUS
wlan_fd_psoc_obj_create_handler(struct wlan_objmgr_psoc *psoc, void *arg)
{
	struct fd_context *fd_ctx;

	if (psoc == NULL) {
		fd_err("Invalid PSOC!\n");
		return QDF_STATUS_E_INVAL;
	}
	fd_ctx = qdf_mem_malloc(sizeof(*fd_ctx));
	if (fd_ctx == NULL) {
		fd_err("Memory allocation faild!!\n");
		return QDF_STATUS_E_NOMEM;
	}
	fd_ctx->psoc_obj = psoc;
	fd_ctx_init(fd_ctx);

	wlan_objmgr_psoc_component_obj_attach(psoc, WLAN_UMAC_COMP_FD,
			(void *)fd_ctx, QDF_STATUS_SUCCESS);

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
wlan_fd_psoc_obj_destroy_handler(struct wlan_objmgr_psoc *psoc, void *arg)
{
	struct fd_context *fd_ctx;

	if (psoc == NULL) {
		fd_err("Invalid PSOC!\n");
		return QDF_STATUS_E_INVAL;
	}

	fd_ctx = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_FD);
	if (fd_ctx) {
		wlan_objmgr_psoc_component_obj_detach(psoc, WLAN_UMAC_COMP_FD,
				(void *)fd_ctx);
		fd_ctx_deinit(fd_ctx);
		qdf_mem_free(fd_ctx);
	}

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
wlan_fd_vdev_obj_create_handler(struct wlan_objmgr_vdev *vdev, void *arg)
{
	struct fd_vdev *fv;
	struct wlan_objmgr_psoc *psoc;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("Invalid PSOC!\n");
		return QDF_STATUS_E_INVAL;
	}

	if (QDF_SAP_MODE == wlan_vdev_mlme_get_opmode(vdev)) {
		fv = qdf_mem_malloc(sizeof(*fv));
		if (fv == NULL) {
			fd_err("Memory allocation faild!!\n");
			return QDF_STATUS_E_NOMEM;
		}
		qdf_mem_zero(fv, sizeof(*fv));
		fv->vdev_obj = vdev;
		qdf_spinlock_create(&fv->fd_lock);
		qdf_spinlock_create(&fv->fd_period_lock);
		qdf_list_create(&fv->fd_deferred_list,
				WLAN_FD_DEFERRED_MAX_SIZE);
		wlan_objmgr_vdev_component_obj_attach(vdev, WLAN_UMAC_COMP_FD,
				(void *)fv, QDF_STATUS_SUCCESS);
	} else {
		return QDF_STATUS_COMP_DISABLED;
	}

	return QDF_STATUS_SUCCESS;
}

static QDF_STATUS
wlan_fd_vdev_obj_destroy_handler(struct wlan_objmgr_vdev *vdev, void *arg)
{
	struct fd_vdev *fv;
	struct wlan_objmgr_psoc *psoc;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}
	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("Invalid PSOC!\n");
		return QDF_STATUS_E_INVAL;
	}

	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv) {
		wlan_objmgr_vdev_component_obj_detach(vdev, WLAN_UMAC_COMP_FD,
					(void *)fv);
		qdf_spin_lock_bh(&fv->fd_lock);
		fd_free_list(psoc, &fv->fd_deferred_list);
		qdf_spin_unlock_bh(&fv->fd_lock);
		qdf_list_destroy(&fv->fd_deferred_list);
		qdf_spinlock_destroy(&fv->fd_lock);
		qdf_spinlock_destroy(&fv->fd_period_lock);
		qdf_mem_free(fv);
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_fd_init(void)
{
	if (wlan_objmgr_register_psoc_create_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_psoc_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		goto fail_psoc_create;
	}
	if (wlan_objmgr_register_psoc_destroy_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_psoc_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		goto fail_psoc_destroy;
	}
	if (wlan_objmgr_register_vdev_create_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_vdev_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		goto fail_vdev_create;
	}
	if (wlan_objmgr_register_vdev_destroy_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_vdev_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		goto fail_vdev_destroy;
	}

	return QDF_STATUS_SUCCESS;

fail_vdev_destroy:
	wlan_objmgr_unregister_vdev_create_handler(WLAN_UMAC_COMP_FD,
					wlan_fd_vdev_obj_create_handler, NULL);
fail_vdev_create:
	wlan_objmgr_unregister_psoc_destroy_handler(WLAN_UMAC_COMP_FD,
					wlan_fd_psoc_obj_destroy_handler, NULL);
fail_psoc_destroy:
	wlan_objmgr_unregister_psoc_create_handler(WLAN_UMAC_COMP_FD,
					wlan_fd_psoc_obj_create_handler, NULL);
fail_psoc_create:
	return QDF_STATUS_E_FAILURE;
}

QDF_STATUS wlan_fd_deinit(void)
{
	if (wlan_objmgr_unregister_psoc_create_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_psoc_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		return QDF_STATUS_E_FAILURE;
	}
	if (wlan_objmgr_unregister_psoc_destroy_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_psoc_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		return QDF_STATUS_E_FAILURE;
	}
	if (wlan_objmgr_unregister_vdev_create_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_vdev_obj_create_handler, NULL) != QDF_STATUS_SUCCESS) {
		return QDF_STATUS_E_FAILURE;
	}
	if (wlan_objmgr_unregister_vdev_destroy_handler(WLAN_UMAC_COMP_FD,
		wlan_fd_vdev_obj_destroy_handler, NULL) != QDF_STATUS_SUCCESS) {
		return QDF_STATUS_E_FAILURE;
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_fd_enable(struct wlan_objmgr_psoc *psoc)
{
	struct fd_context *fd_ctx;

	if (psoc == NULL) {
		fd_err("Invalid PSOC!\n");
		return QDF_STATUS_E_INVAL;
	}
	fd_ctx = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_FD);
	if (fd_ctx == NULL) {
		fd_err("Invalid FILS Discovery Context\n");
		return QDF_STATUS_E_INVAL;
	}

	if (fd_ctx->fd_enable)
		fd_ctx->fd_enable(psoc);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wlan_fd_disable(struct wlan_objmgr_psoc *psoc)
{
	struct fd_context *fd_ctx;

	if (psoc == NULL) {
		fd_err("Invalid PSOC!\n");
		return QDF_STATUS_E_INVAL;
	}
	fd_ctx = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_FD);
	if (fd_ctx == NULL) {
		fd_debug("Invalid FILS Discovery Context\n");
		return QDF_STATUS_E_INVAL;
	}

	if (fd_ctx->fd_disable)
		fd_ctx->fd_disable(psoc);

	return QDF_STATUS_SUCCESS;
}

uint8_t* wlan_fd_frame_init(struct wlan_objmgr_peer *peer, uint8_t *frm)
{
	uint16_t fd_cntl_subfield = 0;
	struct fd_action_header *fd_header;
	struct wlan_objmgr_vdev *vdev;
	struct wlan_objmgr_pdev *pdev;
	struct ieee80211vap *vap;
	struct ieee80211com *ic;
	struct ol_ath_softc_net80211 *scn;
	uint8_t fd_cap[WLAN_FD_CAP_LEN] = {0};
	uint8_t *length;
	uint8_t ssid_len = 0, ssid[WLAN_SSID_MAX_LEN+1] = {0};
	uint32_t ielen = 0, shortssid = 0;
	uint8_t prim_chan;
	uint8_t op_class;
	uint8_t ch_seg1;
	uint16_t chwidth;
	uint8_t nss;
	uint16_t behav_lim;
	bool global_lookup = false;
	uint32_t rate;
	bool rnr_filled = false;

	if (frm == NULL) {
		fd_err("frm is NULL!!\n");
		return frm;
	}

	vdev = wlan_peer_get_vdev(peer);
	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return frm;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (pdev == NULL) {
		fd_err("PDEV is NULL!!\n");
		return frm;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (vap == NULL) {
		fd_err("vap is NULL!!\n");
		return frm;
	}

	ic = vap->iv_ic;
	if (ic == NULL) {
		fd_err("ic is NULL!!\n");
		return frm;
	}
	scn = OL_ATH_SOFTC_NET80211(ic);
	nss = MIN(ieee80211_get_rxstreams(ic, vap),
			ieee80211_get_txstreams(ic, vap));

	if(vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
		chwidth = vap->iv_chwidth;
	} else {
		chwidth = ic->ic_cwm_get_width(ic);
	}

	fd_header = (struct fd_action_header *)frm;
	fd_header->action_header.ia_category = IEEE80211_ACTION_CAT_PUBLIC;
	fd_header->action_header.ia_action  = WLAN_ACTION_FILS_DISCOVERY;

	/**
	 * FILS DIscovery Frame Control Subfield - 2 byte
	 * Enable Short SSID
	 */
	fd_cntl_subfield = 3 & 0x1F;
	fd_cntl_subfield |= WLAN_FD_FRAMECNTL_SHORTSSID;

	if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
		fd_cntl_subfield |= WLAN_FD_FRAMECNTL_CAP;
	}

	if((!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
		ieee80211_is_phymode_11ac_vht80_80(vap->iv_cur_mode)) ||
		(ic->ic_non_ht_dup & IEEE80211_NON_HT_DUP_FILS_DISCOVERY_M)) {
		fd_cntl_subfield |= WLAN_FD_FRAMECNTL_PRIMARY_CH;
	}

	/* For 80+80 set Channel center freq segment 1 */
	if (ieee80211_is_phymode_11ac_vht80_80(vap->iv_cur_mode)) {
		fd_cntl_subfield |= WLAN_FD_FRAMECNTL_CH_CENTERFREQ;
	}
#if ATH_SUPPORT_MBO
	if (ieee80211_vap_oce_check(vap) && ieee80211_non_oce_ap_present (vap)) {
		fd_cntl_subfield |= WLAN_FD_FRAMECNTL_NON_OCE_PRESENT;
	}
	if (ieee80211_vap_oce_check(vap) && ieee80211_11b_ap_present (vap)) {
		fd_cntl_subfield |= WLAN_FD_FRAMECNTL_11B_PRESENT;
	}
#endif
	fd_cntl_subfield |= WLAN_FD_FRAMECNTL_LEN_PRES;
	fd_header->fd_frame_cntl = qdf_cpu_to_le16(fd_cntl_subfield);
	fd_debug("fd_cntl : %02x\n", fd_cntl_subfield);

	/* Timestamp - 8 byte */
	qdf_mem_zero(fd_header->timestamp, sizeof(fd_header->timestamp));

	/* Beacon Interval - 2 byte */
	fd_header->bcn_interval = qdf_cpu_to_le16(
				wlan_peer_get_beacon_interval(peer));
	fd_debug("bcn_intvl : %02x\n", fd_header->bcn_interval);
	frm = &fd_header->elem[0];

	wlan_vdev_mlme_get_ssid(vdev, ssid, &ssid_len);

	/* SSID/Short SSID - 1 - 32 byte */
	if (WLAN_FD_IS_SHORTSSID_PRESENT(fd_cntl_subfield)) {
		shortssid = ieee80211_construct_shortssid(ssid, ssid_len);
		*(uint32_t *)frm = qdf_cpu_to_le32(shortssid);
		frm += 4;
	} else {
		qdf_mem_copy(frm, ssid, ssid_len);
		frm += ssid_len;
	}
	/* Length - 1 byte */
	if (WLAN_FD_IS_LEN_PRESENT(fd_cntl_subfield)) {
		length = frm;
		frm++;
	}

	if(WLAN_FD_IS_CAP_PRESENT(fd_cntl_subfield)) {

		fd_cap[0] |= ((!WLAN_FD_CAP_ESS_ENABLE << WLAN_FD_CAP_ESS_S) |
			(!WLAN_FD_CAP_PRIVACY_ENABLE << WLAN_FD_CAP_PRIVACY_S));

		switch (chwidth) {
			case IEEE80211_CWM_WIDTH20:
				fd_cap[0] |= (IEEE80211_6GOP_CHWIDTH_20 <<
					    WLAN_FD_CAP_BSS_CHWIDTH_S);
			break;
			case IEEE80211_CWM_WIDTH40:
				fd_cap[0] |= (IEEE80211_6GOP_CHWIDTH_40 <<
					    WLAN_FD_CAP_BSS_CHWIDTH_S);
			break;
			case IEEE80211_CWM_WIDTH80:
				fd_cap[0] |= (IEEE80211_6GOP_CHWIDTH_80 <<
					    WLAN_FD_CAP_BSS_CHWIDTH_S);
			break;
			case IEEE80211_CWM_WIDTH160:
			case IEEE80211_CWM_WIDTH80_80:
				fd_cap[0] |= (IEEE80211_6GOP_CHWIDTH_160_80_80
					    << WLAN_FD_CAP_BSS_CHWIDTH_S);
			break;
		}

		switch (nss) {
			case 1:
			case 2:
			case 3:
			case 4:
				fd_cap[0] |= ((nss - 1) << WLAN_FD_CAP_NSS_S);
			break;
			default: /* NSS 5-8 */
				fd_cap[0] |= (WLAN_FD_CAP_NSS_GTE_5 <<
					    WLAN_FD_CAP_NSS_S);
			break;
		}

		if(wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
					WLAN_PDEV_F_MBSS_IE_ENABLE)) {
			fd_cap[1] |= (WLAN_FD_CAP_MBSSID_PRESENT <<
					WLAN_FD_CAP_MBSSID_S);
		}
		wlan_util_vdev_mlme_get_param(vap->vdev_mlme,
			WLAN_MLME_CFG_TX_MGMT_RATE, &rate);
		/* Set PHY index based on vap current mode.
		 */
		switch (vap->iv_cur_mode) {
			case IEEE80211_MODE_11AXA_HE20:
			case IEEE80211_MODE_11AXG_HE20:
			case IEEE80211_MODE_11AXA_HE40:
			case IEEE80211_MODE_11AXG_HE40:
			case IEEE80211_MODE_11AXA_HE40PLUS:
			case IEEE80211_MODE_11AXG_HE40PLUS:
			case IEEE80211_MODE_11AXA_HE40MINUS:
			case IEEE80211_MODE_11AXG_HE40MINUS:
			case IEEE80211_MODE_11AXA_HE80:
			case IEEE80211_MODE_11AXA_HE160:
			case IEEE80211_MODE_11AXA_HE80_80:
				fd_cap[1] |= (WLAN_FD_CAP_PHY_INDEX_HE <<
						WLAN_FD_CAP_PHY_INDEX_S);
				break;
			case IEEE80211_MODE_11AC_VHT20:
			case IEEE80211_MODE_11AC_VHT40:
			case IEEE80211_MODE_11AC_VHT40PLUS:
			case IEEE80211_MODE_11AC_VHT40MINUS:
			case IEEE80211_MODE_11AC_VHT80:
			case IEEE80211_MODE_11AC_VHT160:
			case IEEE80211_MODE_11AC_VHT80_80:
				fd_cap[1] |= (WLAN_FD_CAP_PHY_INDEX_VHT <<
						WLAN_FD_CAP_PHY_INDEX_S);
				break;
			case IEEE80211_MODE_11NA_HT20:
			case IEEE80211_MODE_11NG_HT20:
			case IEEE80211_MODE_11NA_HT40PLUS:
			case IEEE80211_MODE_11NA_HT40MINUS:
			case IEEE80211_MODE_11NG_HT40PLUS:
			case IEEE80211_MODE_11NG_HT40MINUS:
			case IEEE80211_MODE_11NG_HT40:
			case IEEE80211_MODE_11NA_HT40:
				fd_cap[1] |= (WLAN_FD_CAP_PHY_INDEX_HT <<
						WLAN_FD_CAP_PHY_INDEX_S);
				break;
			default:
				fd_cap[1] |= (WLAN_FD_CAP_PHY_INDEX_NON_HT_OFDM <<
						WLAN_FD_CAP_PHY_INDEX_S);
				break;
		}

		fd_cap[1] |= (WLAN_FD_CAP_MIN_RATE << WLAN_FD_CAP_MIN_RATE_S);
		qdf_mem_copy(frm, fd_cap, WLAN_FD_CAP_LEN);
		frm += WLAN_FD_CAP_LEN;
	}

	/**
	 * Operating Class
	 * Primary Channel
	 * AP configuration Sequence Number
	 * Access Network Options
	 * FD RSN Information
	 * Channel Center Freq Segment 1
	 * Mobility Domain
	 */

	/* Operating Class (0 or 1 byte) and Primary Channel (0 or 1 byte) */
	if (WLAN_FD_IS_FRAMECNTL_PRIMARY_CH(fd_cntl_subfield)) {
		wlan_get_bw_and_behav_limit(ic->ic_curchan,
			&chwidth, &behav_lim);
		wlan_reg_freq_width_to_chan_op_class_auto(pdev,
			ic->ic_curchan->ic_freq, chwidth,
			global_lookup, behav_lim,
			&op_class, &prim_chan);
		*frm = op_class;
		frm++;
		*frm = prim_chan;
		frm++;
	}
	/* Channel Center Freq Segment 1 */
	if (WLAN_FD_IS_FRAMECNTL_CH_CENTERFREQ(fd_cntl_subfield)) {
		/* spec has seg0 and seg1 naming while we use seg1 and seg2 */
		ch_seg1 = wlan_get_seg1(vdev);
		*frm = ch_seg1;
		frm++;
	}
	/* Update the length field */
	if (WLAN_FD_IS_LEN_PRESENT(fd_cntl_subfield)) {
		/*Indicates length from FD cap to Mobility Domain */
		*length = (uint8_t)(frm - length) - 1;
	}

        /* Reduced Neighbour Report element */
        if (vap->rnr_enable && vap->rnr_enable_fd) {
            frm = ieee80211_add_rnr_ie(frm, vap, vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);
        } else if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
                   ((WLAN_6GHZ_RNR_USR_MODE_IS_SET(ic->ic_6ghz_rnr_enable) &&
                     WLAN_6GHZ_RNR_ADV_FILS_20TU_IS_SET(ic->ic_6ghz_rnr_enable)) ||
                    (!WLAN_6GHZ_RNR_USR_MODE_IS_SET(ic->ic_6ghz_rnr_enable) && (
                     wlan_lower_band_ap_cnt_get()==0 || scn->soc->rnr_6ghz_adv_override)))) {
		/* add the IE if user set it or if it's 6G only AP */
		frm = ieee80211_add_oob_rnr_ie(frm, vap,
					       vap->iv_bss->ni_essid,
					       vap->iv_bss->ni_esslen,
					       IEEE80211_FC0_SUBTYPE_ACTION, &rnr_filled);
	}

	/**
	 * FILS Indication element
	 */
	if (wlan_vdev_get_elemid(vdev, IEEE80211_FRAME_TYPE_BEACON, frm,
		&ielen, WLAN_ELEMID_FILS_INDICATION) == QDF_STATUS_SUCCESS) {
		frm += ielen;
	}

	if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
		/* Add TPE IE */
		frm = ieee80211_add_vht_txpwr_envlp(frm, vap->iv_bss, ic,
						IEEE80211_FC0_SUBTYPE_ACTION, 0);
	}

	return frm;
}

QDF_STATUS wlan_fd_offload(struct wlan_objmgr_vdev *vdev, uint32_t vdev_id)
{
	struct fd_vdev *fv;
	struct ieee80211_frame *wh;
	struct fd_context *fd_ctx;
	struct fils_discovery_tmpl_params fd_tmpl_param = {0};
	struct wlan_objmgr_psoc *psoc;
	struct wlan_objmgr_pdev *pdev;
	QDF_STATUS retval = 0;
	struct ieee80211vap *vap;

	if (vdev == NULL) {
		fd_err("%s: VDEV is NULL!!\n", __func__);
		return QDF_STATUS_E_INVAL;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (pdev == NULL) {
		fd_err("%s: PDEV is NULL!!\n", __func__);
		return QDF_STATUS_E_INVAL;
	}

	psoc = wlan_vdev_get_psoc(vdev);
	if (psoc == NULL) {
		fd_err("%s: PSOC is NULL!!\n", __func__);
		return QDF_STATUS_E_INVAL;
	}

	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_err("%s: FILS DISC object is NULL!!"
			" Skip sending FD template for vdev %d", __func__, vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	fd_ctx = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_FD);
	if (fd_ctx == NULL) {
		fd_err("%s: FILS DISC context is NULL!!"
			" Skip sending FD template for vdev %d", __func__, vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (!vap) {
		fd_err("VAP is NULL!");
		return QDF_STATUS_E_INVAL;
	}

	qdf_spin_lock_bh(&fv->fd_period_lock);
	/* If VAP is not a non transmitting vap, then
	 * Set FILS enable flag and the default FD period when
	 * FILS Discovery frame is offloaded */
	if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap) && !(fv->fils_enable) &&
            !(vap->iv_he_6g_bcast_prob_rsp)) {
		fv->fils_enable = 1;
		wlan_fd_set_valid_fd_period(vdev, WLAN_FD_INTERVAL_MIN);
	}

	wh = (struct ieee80211_frame *)qdf_nbuf_data(fv->fd_wbuf);
	fd_tmpl_param.vdev_id = vdev_id;
	fd_tmpl_param.tmpl_len = qdf_nbuf_len(fv->fd_wbuf);
	fd_tmpl_param.tmpl_len_aligned = roundup(fd_tmpl_param.tmpl_len,
						sizeof(uint32_t));
	fd_tmpl_param.frm = (uint8_t *)wh;

	if (fd_ctx->fd_tmpl_send)
		retval = fd_ctx->fd_tmpl_send(pdev, &fd_tmpl_param);
	qdf_spin_unlock_bh(&fv->fd_period_lock);

	return retval;

}

qdf_nbuf_t wlan_fd_alloc(struct wlan_objmgr_vdev *vdev)
{
	uint8_t bcast[QDF_MAC_ADDR_SIZE] = {0xff,0xff,0xff,0xff,0xff,0xff};
	struct ieee80211_frame *wh;
	struct wlan_objmgr_peer *bss_peer;
	qdf_nbuf_t wbuf;
	uint8_t *frm;

	bss_peer = wlan_vdev_get_bsspeer(vdev);
	if (bss_peer == NULL) {
		fd_err("Invalid BSS Peer!!\n");
		return NULL;
	}
	wbuf = qdf_nbuf_alloc(NULL,
		qdf_roundup(MAX_TX_RX_PACKET_SIZE + WLAN_FD_MIN_HEAD_ROOM, 4),
			WLAN_FD_MIN_HEAD_ROOM, 4, true);
	if (wbuf == NULL) {
		fd_err("Failed to allocate qdf_nbuf!!\n");
		return NULL;
	}

	wh = (struct ieee80211_frame *)qdf_nbuf_data(wbuf);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
				IEEE80211_FC0_SUBTYPE_ACTION;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	*(uint16_t *)wh->i_dur = 0;
	WLAN_ADDR_COPY(wh->i_addr1, bcast);
	WLAN_ADDR_COPY(wh->i_addr2, wlan_vdev_mlme_get_macaddr(vdev));
	WLAN_ADDR_COPY(wh->i_addr3, wlan_peer_get_macaddr(bss_peer));
	*(uint16_t *)wh->i_seq = 0;

	frm = (uint8_t *)&wh[1];
	frm = wlan_fd_frame_init(bss_peer, frm);

	qdf_nbuf_set_pktlen(wbuf, (frm - (uint8_t *)qdf_nbuf_data(wbuf)));

	return wbuf;
}

void wlan_fd_vdev_defer_fd_buf_free(struct wlan_objmgr_vdev *vdev)
{
	struct fd_buf_entry* buf_entry;
	struct fd_vdev *fv;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_debug("Invalid FILS DISC object!\n");
		return;
	}
	if (!fv->fd_wbuf) {
		return;
	}
	buf_entry = qdf_mem_malloc(sizeof(*buf_entry));
	if (buf_entry == NULL) {
		fd_err("Memory allocation failed!\n");
		return;
	}

	qdf_spin_lock_bh(&fv->fd_lock);
	buf_entry->is_dma_mapped = fv->is_fd_dma_mapped;
	fv->is_fd_dma_mapped = false;
	buf_entry->fd_buf = fv->fd_wbuf;
	qdf_list_insert_back(&fv->fd_deferred_list,
				&buf_entry->fd_deferred_list_elem);
	fv->fd_wbuf = NULL;
	qdf_spin_unlock_bh(&fv->fd_lock);
}

void
wlan_fd_set_valid_fd_period(struct wlan_objmgr_vdev *vdev, uint32_t fd_period)
{
	uint16_t bcn_intval = 0;
	struct wlan_objmgr_peer *bss_peer;
	struct fd_vdev *fv;
	struct ieee80211vap *vap;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return;
	}
	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if(!vap) {
		fd_err("VAP is NULL!\n");
		return;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_debug("Invalid FILS DISC object!\n");
		return;
	}
	bss_peer = wlan_vdev_get_bsspeer(vdev);
	if (bss_peer == NULL) {
		fd_err("Invalid bss peer\n");
		return;
	}

	bcn_intval = wlan_peer_get_beacon_interval(bss_peer);
	if (!fd_period) {
		fd_period = 0;
		fv->fils_enable = 0;
		fd_info("FD is disabled\n");
	} else {
		if (fd_period && ((fd_period < WLAN_FD_INTERVAL_MIN) ||
		                            (fd_period >= bcn_intval))) {
		    fd_err("[Vded-%d] Invalid FD Interval : %d. Valid range is %d - %dms.\n"
			    "Disabling FD\n", wlan_vdev_get_id(vdev), fd_period,
			    WLAN_FD_INTERVAL_MIN, bcn_intval);
			fd_period = 0;
			fv->fils_enable = 0;
		} else if ((bcn_intval % fd_period) != 0) {
			if(IEEE80211_IS_CHAN_6GHZ(vap->iv_ic->ic_curchan)) {
				fd_info("FD Interval %d is not a factor of BI."
				    " Setting FD Interval to default %dTU",
				    fd_period, WLAN_FD_INTERVAL_MIN);
				fd_period = WLAN_FD_INTERVAL_MIN;
			} else {
				fd_err("Invalid FD Interval: %d. "
				       "FD Interval should be a factor of BI.\n"
				       "Disabling FD\n", fd_period);
				fd_period = 0;
				fv->fils_enable = 0;
			}
		}
	}

	fv->fd_period = fd_period;
}

uint32_t
wlan_fd_get_fd_period(struct wlan_objmgr_vdev *vdev)
{
	struct fd_vdev *fv;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return 0;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_debug("Invalid FILS DISC object!\n");
		return 0;
	}

	return fv->fd_period;
}

bool wlan_fd_capable(struct wlan_objmgr_psoc *psoc)
{
	struct fd_context *fd_ctx;

	if (psoc == NULL) {
		fd_err("Invalid PSOC!\n");
		return false;
	}
	fd_ctx = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_FD);
	if (fd_ctx == NULL) {
		fd_err("Invalid FD Context!\n");
		return false;
	}

	return fd_ctx->is_fd_capable;
}

QDF_STATUS wlan_fd_update(struct wlan_objmgr_vdev *vdev)
{
	uint8_t *frm = NULL;
	struct fd_vdev *fv;
	struct wlan_objmgr_peer *bss_peer;
	struct ieee80211vap *vap;
	struct ieee80211com *ic;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_debug("Invalid FILS DISC object!\n");
		return QDF_STATUS_E_INVAL;
	}
	bss_peer = wlan_vdev_get_bsspeer(fv->vdev_obj);
	if (bss_peer == NULL) {
		fd_err("Invalid BSS Peer!!\n");
		return QDF_STATUS_E_INVAL;
	}
	if (!fv->fd_wbuf) {
		fd_debug("Invalid FD buffer!!\n");
		return QDF_STATUS_E_INVAL;
	}

	vap = wlan_vdev_get_mlme_ext_obj(vdev);
	if (vap == NULL) {
		fd_err("vap is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	ic = vap->iv_ic;
	if (ic == NULL) {
		fd_err("ic is NULL!!\n");
		return QDF_STATUS_E_INVAL;
	}

	if (fv->fd_update) {
		frm = (uint8_t *)qdf_nbuf_data(fv->fd_wbuf) +
					sizeof(struct ieee80211_frame);
		frm = wlan_fd_frame_init(bss_peer, frm);
		qdf_nbuf_set_pktlen(fv->fd_wbuf,
			(frm - (uint8_t *)qdf_nbuf_data(fv->fd_wbuf)));
		fv->fd_update = 0;
		if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
			wlan_fd_offload(vdev, wlan_vdev_get_id(vdev));
		}
	}

	return QDF_STATUS_SUCCESS;
}

uint8_t wlan_fils_is_enable(struct wlan_objmgr_vdev *vdev)
{
	struct fd_vdev *fv;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return 0;
	}
	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_debug("Invalid FILS DISC object!\n");
		return 0;
	}

	return fv->fils_enable;
}

void wlan_fd_update_trigger(struct wlan_objmgr_vdev *vdev)
{
	struct fd_vdev *fv;

	if (vdev == NULL) {
		fd_err("VDEV is NULL!!\n");
		return;
	}

	fv = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_FD);
	if (fv == NULL) {
		fd_debug("Invalid FILS DISC object!\n");
		return;
	}

	fv->fd_update = 1;
}
