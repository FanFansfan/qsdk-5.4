/*
 * Copyright (c) 2017, 2019-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
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
#include <ieee80211_var.h>
#include "ieee80211_ioctl.h"
#include "ald_netlink.h"
#if QCA_SUPPORT_SON
#include "wlan_son_ald_priv.h"    /* Private to ALD module */
#include "wlan_son_internal.h"
#include "wlan_son_pub.h"
#include "ath_dev.h"
#include "ol_if_athvar.h"
#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif

#define IEEE80211_ALD_COMPUTE_UTILITY(value) ((value) * 100 / 256)
#define ALD_MSDU_SIZE 1300
#define DEFAULT_MSDU_SIZE 1000

struct son_iter_arg {
	uint32_t count;
	struct wlan_objmgr_peer *peers[MAX_NODES_NETWORK];
};

QDF_STATUS son_ald_vattach(struct wlan_objmgr_vdev *vdev, void *vdev_priv)
{
	struct ath_linkdiag *ald_priv = NULL;
	struct son_vdev_priv *vd_priv = (struct son_vdev_priv *)vdev_priv;

	ald_priv = qdf_mem_malloc(sizeof(struct ath_linkdiag));
	if (!ald_priv) {
		SON_LOGE("%s: ALD vdev priv alloc failed", __func__);
		return QDF_STATUS_E_NOMEM;
	}

	vd_priv->ald_pid = WLAN_DEFAULT_NETLINK_PID;
	vd_priv->iv_ald = ald_priv;
	qdf_mem_zero(ald_priv, sizeof(*ald_priv));
	spin_lock_init(&ald_priv->ald_lock);
	ald_priv->ald_phyerr = UINT_MAX;
	ald_priv->ald_maxcu = WLAN_MAX_MEDIUM_UTILIZATION;

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS son_ald_vdetach(struct wlan_objmgr_vdev *vdev)
{
	struct son_vdev_priv *vd_priv = NULL;

	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv) {
		SON_LOGE("%s: SON vdev priv is NULL", __func__);
		return QDF_STATUS_E_INVAL;
	}

	if (vd_priv->iv_ald) {
		spin_lock_destroy(&vd_priv->iv_ald->ald_lock);
		qdf_mem_free(vd_priv->iv_ald);
	}

	return QDF_STATUS_SUCCESS;
}

/**
 * @brief Calculate the PHY error rate (and update the link
 *        diagnostic stats)
 *
 * @param [in] ald  pointer to link diagnostic stats
 * @param [in] new_phyerr  current PHY error rate reported on
 *                         the radio
 */
void son_ald_update_phy_error_rate(struct ath_linkdiag *ald,
				   u_int32_t new_phyerr)
{
	u_int32_t old_phyerr;
	u_int32_t old_ostime, new_ostime, time_diff = 0;
	u_int32_t phyerr_rate = 0, phyerr_diff;

	old_phyerr = ald->ald_phyerr;
	old_ostime = ald->ald_ostime;
	new_ostime = CONVERT_SYSTEM_TIME_TO_SEC(OS_GET_TIMESTAMP());

	/*
	 * The PHY error counts (received from firmware) is a running count
	 * (ie monotonically increasing until wrap-around).  Get the difference
	 * since last time the PHY error has been read to calculate how many PHY
	 * errors have occurred in the last sampling interval.
	 */
	if (new_ostime > old_ostime) {
		time_diff = new_ostime - old_ostime;
	} else if (new_ostime < old_ostime) {
		time_diff = UINT_MAX - old_ostime + new_ostime;
	}

	if (old_phyerr == UINT_MAX) {
		/*
		 * This is probably the first time sample - ignore
		 */
		time_diff = 0;
	}

	if (time_diff) {
		if (new_phyerr >= old_phyerr) {
			phyerr_diff = new_phyerr - old_phyerr;
		} else {
			phyerr_diff = (UINT_MAX - old_phyerr) + new_phyerr;
		}
		phyerr_rate = phyerr_diff / time_diff;
	}

	ald->ald_phyerr = new_phyerr;
	ald->ald_ostime = new_ostime;
	ald->phyerr_rate = phyerr_rate;
}

static void son_peer_reset_ald_stats(struct wlan_objmgr_peer *peer)
{
	struct wlan_objmgr_psoc *psoc = NULL;
	struct wlan_objmgr_vdev *vdev = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	struct cdp_peer_stats *peer_stats = NULL;
	struct son_peer_priv *pe_priv = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint8_t i;

	if (!peer) {
		SON_LOGE("%s: peer is NULL", __func__);
		return;
	}
	pe_priv = wlan_son_get_peer_priv(peer);
	if (!pe_priv) {
		SON_LOGE("%s: SON peer priv is NULL", __func__);
		return;
	}

	/* Do not reset ald_avgmax4msaggr and ald_aggr.
	 * Past values are used when there is no traffic
	 */
	vdev = wlan_peer_get_vdev(peer);
	if (!vdev) {
		SON_LOGE("%s: vdev is NULL", __func__);
		return;
	}
	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		SON_LOGE("%s: pdev is NULL", __func__);
		return;
	}
	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc) {
		SON_LOGE("%s: psoc is NULL", __func__);
		return;
	}

	if (!(peer_stats = qdf_mem_malloc(sizeof(struct cdp_peer_stats))))
		return;

	status = cdp_host_get_peer_stats(wlan_psoc_get_dp_handle(psoc),
					 wlan_vdev_get_id(vdev),
					 peer->macaddr, peer_stats);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_mem_free(peer_stats);
		return;
	}

	pe_priv->tx_cnt = peer_stats->tx.fw_tx_cnt;
	pe_priv->tx_bytes = peer_stats->tx.fw_tx_bytes;
	pe_priv->tx_rates_used = peer_stats->tx.last_tx_rate_used;
	pe_priv->tx_ratecount = peer_stats->tx.fw_ratecount;
	pe_priv->ni_ald.ald_max4msframelen = peer_stats->tx.fw_max4msframelen;
	pe_priv->ni_ald.ald_txcount = peer_stats->tx.fw_txcount;
	pe_priv->ni_ald.ald_retries = peer_stats->tx.retries;
	for (i = 0; i < WME_AC_MAX; i++) {
		pe_priv->ni_ald.ald_ac_nobufs[i] = peer_stats->tx.ac_nobufs[i];
		pe_priv->ni_ald.ald_ac_excretries[i] = peer_stats->tx.excess_retries_per_ac[i];
	}
	pe_priv->ni_ald.ald_lastper = 0;
	pe_priv->ni_ald.ald_phyerr = 0;
	pe_priv->ni_ald.ald_msdusize = 0;
	pe_priv->ni_ald.ald_capacity = 0;
	OS_MEMZERO(&pe_priv->ni_ald.ald_ac_txpktcnt, sizeof(pe_priv->ni_ald.ald_ac_txpktcnt));
	qdf_mem_free(peer_stats);
}

static void
son_peer_wrap_ald_stats(struct son_peer_priv *pe_priv, struct cdp_peer_stats *peer_stats)
{
	if (pe_priv->tx_cnt > peer_stats->tx.fw_tx_cnt)
		pe_priv->tx_cnt = peer_stats->tx.fw_tx_cnt;

	if (pe_priv->tx_bytes > peer_stats->tx.fw_tx_bytes)
		pe_priv->tx_bytes = peer_stats->tx.fw_tx_bytes;
}

static int
son_peer_prepare_ald_stats(struct wlan_objmgr_peer *peer)
{
	struct wlan_objmgr_vdev *vdev = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	struct wlan_objmgr_psoc *psoc = NULL;
	struct son_peer_priv *pe_priv = NULL;
	struct cdp_peer_stats *peer_stats = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint8_t i;

	vdev = wlan_peer_get_vdev(peer);
	if (!vdev) {
		SON_LOGE("%s: vdev is NULL", __func__);
		return -ENOENT;
	}
	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		SON_LOGE("%s: pdev is NULL", __func__);
		return -ENOENT;
	}
	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc) {
		SON_LOGE("%s: psoc is NULL", __func__);
		return -ENOENT;
	}

	if (!(peer_stats = qdf_mem_malloc(sizeof(struct cdp_peer_stats))))
		return -ENOMEM;

	status = cdp_host_get_peer_stats(wlan_psoc_get_dp_handle(psoc),
					 wlan_vdev_get_id(vdev),
					 peer->macaddr, peer_stats);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_mem_free(peer_stats);
		return -ENOENT;
	}

	pe_priv = wlan_son_get_peer_priv(peer);
	/* check if tx_cnt is less than peer_stats->tx.fw_tx_cnt,
	 * to ensure peer_stats were not reset
	 */
	son_peer_wrap_ald_stats(pe_priv, peer_stats);

	if (pe_priv->tx_cnt != peer_stats->tx.fw_tx_cnt) {
		pe_priv->tx_cnt =
			peer_stats->tx.fw_tx_cnt - pe_priv->tx_cnt;
	}

	if (pe_priv->tx_bytes != peer_stats->tx.fw_tx_bytes) {
		pe_priv->tx_bytes =
			peer_stats->tx.fw_tx_bytes - pe_priv->tx_bytes;
	}

	if (pe_priv->tx_rates_used != peer_stats->tx.last_tx_rate_used) {
		pe_priv->tx_rates_used =
			peer_stats->tx.last_tx_rate_used - pe_priv->tx_rates_used;
	}

	if (pe_priv->tx_rate != peer_stats->tx.rnd_avg_tx_rate) {
		pe_priv->tx_rate =
			peer_stats->tx.rnd_avg_tx_rate;
	}

	if (pe_priv->tx_ratecount != peer_stats->tx.fw_ratecount) {
		pe_priv->tx_ratecount =
			peer_stats->tx.fw_ratecount - pe_priv->tx_ratecount;
	}

	if (pe_priv->ni_ald.ald_txcount != peer_stats->tx.fw_txcount) {
		pe_priv->ni_ald.ald_txcount =
			peer_stats->tx.fw_txcount - pe_priv->ni_ald.ald_txcount;
	}

	if (pe_priv->ni_ald.ald_max4msframelen != peer_stats->tx.fw_max4msframelen) {
		pe_priv->ni_ald.ald_max4msframelen =
			peer_stats->tx.fw_max4msframelen - pe_priv->ni_ald.ald_max4msframelen;
	}

	if (pe_priv->ni_ald.ald_retries != peer_stats->tx.retries) {
		pe_priv->ni_ald.ald_retries =
			peer_stats->tx.retries - pe_priv->ni_ald.ald_retries;
	}

	for (i = 0; i < WME_AC_MAX; i++) {
		if (pe_priv->ni_ald.ald_ac_nobufs[i] != peer_stats->tx.ac_nobufs[i]) {
			pe_priv->ni_ald.ald_ac_nobufs[i] =
				peer_stats->tx.ac_nobufs[i] - pe_priv->ni_ald.ald_ac_nobufs[i];
		}

		if (pe_priv->ni_ald.ald_ac_excretries[i] != peer_stats->tx.excess_retries_per_ac[i]) {
			pe_priv->ni_ald.ald_ac_excretries[i] =
				peer_stats->tx.excess_retries_per_ac[i] - pe_priv->ni_ald.ald_ac_excretries[i];
		}
	}

	pe_priv->ni_ald.ald_lastper = peer_stats->tx.last_per;
	qdf_mem_free(peer_stats);

	return 0;
}

static void son_peer_collect_stats(struct wlan_objmgr_peer *peer)
{
	u_int32_t msdu_size, max_msdu_size;
	struct wlan_objmgr_vdev *vdev = NULL;
	struct son_peer_priv *pe_priv = NULL;
	struct son_vdev_priv *vd_priv = NULL;

	vdev = wlan_peer_get_vdev(peer);
	if (!vdev) {
		SON_LOGE("%s: vdev is NULL", __func__);
		return;
	}
	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv) {
		SON_LOGE("%s: SON vdev priv is NULL", __func__);
		return;
	}
	pe_priv = wlan_son_get_peer_priv(peer);
	if (!pe_priv) {
		SON_LOGE("%s: SON peer priv is NULL", __func__);
		return;
	}

	if (son_peer_prepare_ald_stats(peer))
		return;

	pe_priv->ni_ald.ald_phyerr = vd_priv->iv_ald->phyerr_rate;

	pe_priv->ni_ald.ald_capacity = pe_priv->tx_cnt ?
				       (pe_priv->tx_rates_used / pe_priv->tx_cnt) : 0;

	if (!pe_priv->ni_ald.ald_capacity)
		pe_priv->ni_ald.ald_capacity = qdf_do_div(pe_priv->tx_rate, 1000);

	if (!pe_priv->tx_bytes || !pe_priv->ni_ald.ald_txcount)
		msdu_size = ALD_MSDU_SIZE;
	else
		msdu_size = (pe_priv->tx_bytes / pe_priv->ni_ald.ald_txcount);

	if (msdu_size < DEFAULT_MSDU_SIZE)
		pe_priv->ni_ald.ald_msdusize = ALD_MSDU_SIZE;
	else
		pe_priv->ni_ald.ald_msdusize = msdu_size;

	max_msdu_size = (msdu_size > ALD_MSDU_SIZE) ? msdu_size : ALD_MSDU_SIZE;
	if (pe_priv->tx_ratecount > 0) {
		pe_priv->ni_ald.ald_avgmax4msaggr =
			pe_priv->ni_ald.ald_max4msframelen / (pe_priv->tx_ratecount * max_msdu_size);
	}

	if (pe_priv->ni_ald.ald_avgmax4msaggr > 192)
		pe_priv->ni_ald.ald_avgmax4msaggr = 192;

	if (pe_priv->ni_ald.ald_avgmax4msaggr > 0)
		pe_priv->ni_ald.ald_aggr = pe_priv->ni_ald.ald_avgmax4msaggr / 2;
	else
		pe_priv->ni_ald.ald_aggr = 96; //Max aggr 192/2

	/* Avg Aggr should be atleast 1 */
	pe_priv->ni_ald.ald_aggr = pe_priv->ni_ald.ald_aggr > 1 ? pe_priv->ni_ald.ald_aggr : 1;

}

static void son_check_buffull_condition(struct wlan_objmgr_pdev *pdev)
{
	struct wlan_objmgr_psoc *psoc = NULL;

	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc) {
		SON_LOGE("%s: psoc is NULL", __func__);
		return;
	}

	if(son_ald_record_get_free_descs(psoc) <= son_ald_record_get_buff_lvl(psoc))
		son_ald_record_set_buff_full_warn(psoc, 0);
	else
		son_ald_record_set_buff_full_warn(psoc, 1);
}

static void
son_ald_collect_statistics_iter(struct wlan_objmgr_vdev *vdev,
				struct wlan_objmgr_peer *peer, uint32_t *index)
{
	struct son_vdev_priv *vd_priv = NULL;
	struct son_peer_priv *pe_priv = NULL;

	if (!vdev || !peer || !index)
		return;

	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv) {
		SON_LOGE("%s: SON vdev priv is NULL", __func__);
		return;
	}
	pe_priv = wlan_son_get_peer_priv(peer);
	if (!pe_priv) {
		SON_LOGE("%s: SON peer priv is NULL", __func__);
		return;
	}

	qdf_mem_copy(vd_priv->iv_ald->staticp->lkcapacity[*index].da,
		     peer->macaddr, QDF_MAC_ADDR_SIZE);

	son_peer_collect_stats(peer);
	vd_priv->iv_ald->staticp->lkcapacity[*index].capacity = pe_priv->ni_ald.ald_capacity;
	vd_priv->iv_ald->staticp->lkcapacity[*index].aggr = pe_priv->ni_ald.ald_aggr;
	vd_priv->iv_ald->staticp->lkcapacity[*index].aggrmax = pe_priv->ni_ald.ald_avgmax4msaggr;
	vd_priv->iv_ald->staticp->lkcapacity[*index].phyerr = pe_priv->ni_ald.ald_phyerr;
	vd_priv->iv_ald->staticp->lkcapacity[*index].lastper = pe_priv->ni_ald.ald_lastper;
	vd_priv->iv_ald->staticp->lkcapacity[*index].msdusize = pe_priv->ni_ald.ald_msdusize;
	vd_priv->iv_ald->staticp->lkcapacity[*index].retries = pe_priv->ni_ald.ald_retries;
	qdf_mem_copy(vd_priv->iv_ald->staticp->lkcapacity[*index].nobufs,
		     pe_priv->ni_ald.ald_ac_nobufs, sizeof(pe_priv->ni_ald.ald_ac_nobufs));
	qdf_mem_copy(vd_priv->iv_ald->staticp->lkcapacity[*index].excretries,
		     pe_priv->ni_ald.ald_ac_excretries, sizeof(pe_priv->ni_ald.ald_ac_excretries));
	qdf_mem_copy(vd_priv->iv_ald->staticp->lkcapacity[*index].txpktcnt,
		     pe_priv->ni_ald.ald_ac_txpktcnt, sizeof(pe_priv->ni_ald.ald_ac_txpktcnt));

	son_peer_reset_ald_stats(peer);

	(*index)++;
}

static void
son_ald_list_peer_iter(struct wlan_objmgr_vdev *vdev,
		       void *object, void *arg)
{
	struct wlan_objmgr_peer *peer = NULL;
	struct son_iter_arg *iter_arg = NULL;

	if (!vdev || !object || !arg)
		return;

	peer = (struct wlan_objmgr_peer *)object;
	iter_arg = (struct son_iter_arg *)arg;

	if (iter_arg->count >= MAX_NODES_NETWORK)
		return;

	if (vdev != peer->peer_objmgr.vdev)
		return;

	if (wlan_vdev_get_selfpeer(peer->peer_objmgr.vdev) == peer)
		return;

	/* Ref taken to store peer ptr in list. Released later once stats collected */
	if (wlan_objmgr_peer_try_get_ref(peer, WLAN_ALD_ID) ==
			QDF_STATUS_SUCCESS) {
		iter_arg->peers[iter_arg->count] = peer;
		++iter_arg->count;
	}
}

void son_ald_collect_statistics(struct wlan_objmgr_vdev *vdev)
{
	struct wlan_objmgr_pdev *pdev = NULL;
	struct son_vdev_priv *vd_priv = NULL;
#ifdef QCA_SUPPORT_CP_STATS
	struct pdev_ic_cp_stats *pdev_cps = NULL;
#endif
	struct son_iter_arg *iter_arg = NULL;
	uint32_t i, index;

	iter_arg = qdf_mem_malloc(sizeof(struct son_iter_arg));
	if (!iter_arg) {
		SON_LOGE("%s: alloc FAIL", __func__);
		return;
	}
	qdf_mem_zero(iter_arg, sizeof(*iter_arg));

	if (!vdev) {
		SON_LOGE("%s: vdev is NULL", __func__);
		goto fail;
	}

	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv) {
		SON_LOGE("%s: SON vdev priv is NULL", __func__);
		goto fail;
	}

	pdev = wlan_vdev_get_pdev(vdev);
	if (!pdev) {
		SON_LOGE("%s: pdev is NULL", __func__);
		goto fail;
	}

#ifdef QCA_SUPPORT_CP_STATS
	pdev_cps = wlan_get_pdev_cp_stats_ref(pdev);
	if (!pdev_cps) {
		SON_LOGE("%s: pdev_cps is NULL", __func__);
		goto fail;
	}
#endif

	son_check_buffull_condition(pdev);
#ifdef QCA_SUPPORT_CP_STATS
	son_ald_update_phy_error_rate(vd_priv->iv_ald,
				      pdev_cps->stats.cs_phy_err_count);
#endif

	vd_priv->iv_ald->staticp->utility = IEEE80211_ALD_STAT_UTILITY_UNCHANGED;
	vd_priv->iv_ald->staticp->load = vd_priv->iv_ald->ald_dev_load;
	vd_priv->iv_ald->staticp->txbuf = vd_priv->iv_ald->ald_txbuf_used;
	vd_priv->iv_ald->staticp->curThroughput = vd_priv->iv_ald->ald_curThroughput;

	wlan_objmgr_iterate_peerobj_list(vdev, son_ald_list_peer_iter,
					 (void *)iter_arg, WLAN_ALD_ID);

	index = 0;
	for (i = 0; i < iter_arg->count; ++i) {
		son_ald_collect_statistics_iter(vdev, iter_arg->peers[i], &index);
		/* Peer ref taken in son_ald_list_peer_iter is released here */
		wlan_objmgr_peer_release_ref(iter_arg->peers[i], WLAN_ALD_ID);
	}

	vd_priv->iv_ald->staticp->nientry = index;
	vd_priv->iv_ald->staticp->vapstatus =
		(wlan_vdev_allow_connect_n_tx(vdev) == QDF_STATUS_SUCCESS ? 1 : 0);

fail:
	qdf_mem_free(iter_arg);
}

int son_ald_get_statistics(struct wlan_objmgr_vdev *vdev, void *para)
{
	struct ald_stat_info *param = NULL;
	struct son_vdev_priv *vd_priv = NULL;
	int retval = 0;

	if (!vdev) {
		SON_LOGE("%s: vdev is NULL", __func__);
		return -EINVAL;
	}
	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv) {
		SON_LOGE("%s: SON vdev priv is NULL", __func__);
		return -EINVAL;
	}

	if (!para) {
		son_ald_collect_statistics(vdev);
		return retval;
	}

	param = (struct ald_stat_info *)para;
	vd_priv->iv_ald->staticp = param;
	switch (param->cmd) {
		case IEEE80211_ALD_MAXCU:
			retval = -1;
			break;
		default:
			break;
	}
	son_ald_collect_statistics(vdev);

	return retval;
}

void son_ald_record_tx(struct wlan_objmgr_vdev *vdev, wbuf_t wbuf, int datalen)
{
	struct son_vdev_priv *vd_priv = NULL;
	struct ieee80211_frame *wh = NULL;
	int type;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	if (!wbuf) {
		SON_LOGE("%s: wbuf is NULL", __func__);
		return;
	}

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return;
	}

	vd_priv = wlan_son_get_vdev_priv(vdev);
	if (!vd_priv) {
		SON_LOGE("%s: SON vdev priv is NULL", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return;
	}

	wh = (struct ieee80211_frame *)wbuf_header(wbuf);
	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

	if ((type == IEEE80211_FC0_TYPE_DATA) &&
	    (!IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
	    (!IEEE80211_IS_BROADCAST(wh->i_addr1))) {
		int32_t tmp;

		tmp = vd_priv->iv_ald->ald_unicast_tx_bytes;
		spin_lock(&vd_priv->iv_ald->ald_lock);
		vd_priv->iv_ald->ald_unicast_tx_bytes += datalen;
		if (tmp > vd_priv->iv_ald->ald_unicast_tx_bytes) {
			vd_priv->iv_ald->ald_unicast_tx_bytes = datalen;
			vd_priv->iv_ald->ald_unicast_tx_packets = 0;
		}
		vd_priv->iv_ald->ald_unicast_tx_packets++;
		spin_unlock(&vd_priv->iv_ald->ald_lock);
	}

	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
}

/* Enable ald statistics for a station with give MAC address */
int son_ald_sta_enable(struct wlan_objmgr_vdev *vdev, u_int8_t *macaddr, u_int32_t enable)
{
	int retval = 0;
	u_int32_t peer_ext_stats_enable;
	struct wlan_objmgr_peer *peer = NULL;
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_SON_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		SON_LOGE("%s: Unable to get reference", __func__);
		return -EINVAL;
	}

	if (!macaddr) {
		SON_LOGE("%s: macaddr is NULL", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -EINVAL;
	}

	peer = wlan_objmgr_vdev_find_peer_by_mac(vdev, macaddr, WLAN_ALD_ID);
	if (!peer) {
		SON_LOGE("%s: cannot find peer", __func__);
		wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);
		return -EINVAL;
	}

	enable = !!enable;
	peer_ext_stats_enable = (wlan_peer_is_flag_set(peer, IEEE80211_NODE_EXT_STATS)) ? 1 : 0;
	if ((peer_ext_stats_enable != enable) &&
	    ((retval = son_enable_disable_peer_ext_stats(peer, enable)) == 0)) {
		if (wlan_peer_is_flag_set(peer, IEEE80211_NODE_EXT_STATS))
			wlan_clear_node_peer_flag(peer, IEEE80211_NODE_EXT_STATS);
		else
			wlan_set_node_peer_flag(peer, IEEE80211_NODE_EXT_STATS);
	}

	wlan_objmgr_peer_release_ref(peer, WLAN_ALD_ID);
	wlan_objmgr_vdev_release_ref(vdev, WLAN_SON_ID);

	return retval;
}
#endif /* QCA_SUPPORT_SON */
