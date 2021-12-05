/*
 *
 * Copyright (c) 2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#include <wlan_atf_tgt_api.h>
#include "../../core/atf_cmn_api_i.h"
#include <cdp_txrx_cmn_struct.h>

uint32_t tgt_atf_get_fmcap(struct wlan_objmgr_psoc *psoc)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return 0;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return 0;
	}

	return ac->atf_fmcap;
}

uint32_t tgt_atf_get_mode(struct wlan_objmgr_psoc *psoc)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return 0;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return 0;
	}

	return ac->atf_mode;
}

uint32_t tgt_atf_get_msdu_desc(struct wlan_objmgr_psoc *psoc)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return 0;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return 0;
	}

	return ac->atf_msdu_desc;
}

uint32_t tgt_atf_get_max_vdevs(struct wlan_objmgr_psoc *psoc)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return 0;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return 0;
	}

	return ac->atf_max_vdevs;
}

uint32_t tgt_atf_get_peers(struct wlan_objmgr_psoc *psoc)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return 0;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return 0;
	}

	return ac->atf_peers;
}

uint32_t tgt_atf_get_tput_based(struct wlan_objmgr_pdev *pdev)
{
	struct pdev_atf *pa;

	if (NULL == pdev) {
		atf_err("PDEV is NULL!\n");
		return 0;
	}
	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("pdev_atf component object NULL!\n");
		return 0;
	}

	return pa->atf_tput_based;
}

uint32_t tgt_atf_get_logging(struct wlan_objmgr_pdev *pdev)
{
	struct pdev_atf *pa;

	if (NULL == pdev) {
		atf_err("PDEV is NULL!\n");
		return 0;
	}
	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("pdev_atf component object NULL!\n");
		return 0;
	}

	return pa->atf_logging;
}

uint32_t tgt_atf_get_ssidgroup(struct wlan_objmgr_pdev *pdev)
{
	struct pdev_atf *pa;

	if (NULL == pdev) {
		atf_err("PDEV is NULL!\n");
		return 0;
	}
	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("pdev_atf component object NULL!\n");
		return 0;
	}

	return pa->atf_ssidgroup;
}

uint32_t tgt_atf_get_vdev_ac_blk_cnt(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_atf *va;

	if (NULL == vdev) {
		atf_err("VDEV is NULL!\n");
		return 0;
	}
	va = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_ATF);
	if (NULL == va) {
		atf_err("vdev_atf component object NULL!\n");
		return 0;
	}

	return va->ac_blk_cnt;
}

uint8_t tgt_atf_get_vdev_blk_txtraffic(struct wlan_objmgr_vdev *vdev)
{
	struct vdev_atf *va;

	if (NULL == vdev) {
		atf_err("VDEV is NULL!\n");
		return 0;
	}
	va = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_ATF);
	if (NULL == va) {
		atf_err("vdev_atf component object NULL!\n");
		return 0;
	}

	return va->block_tx_traffic;
}

uint8_t tgt_atf_get_peer_blk_txbitmap(struct wlan_objmgr_peer *peer)
{
	struct peer_atf *pa;

	if (NULL == peer) {
		atf_err("PEER is NULL!\n");
		return 0;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return 0;
	}

	return pa->block_tx_bitmap;
}

uint32_t tgt_atf_get_sched(struct wlan_objmgr_pdev *pdev)
{
	struct pdev_atf *pa;

	if (NULL == pdev) {
		atf_err("PDEV is NULL!\n");
		return 0;
	}
	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("pdev_atf component object NULL!\n");
		return 0;
	}

	return pa->atf_sched;
}

void tgt_atf_get_peer_stats(struct wlan_objmgr_peer *peer,
			    struct atf_stats *stats)
{
	struct peer_atf *pa;

	if ((NULL == peer) || (NULL == stats)) {
		atf_err("Invalid inputs!\n");
		return;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return;
	}

	qdf_mem_copy(stats, &pa->atf_peer_stats, sizeof(pa->atf_peer_stats));
}

uint16_t tgt_atf_get_token_allocated(struct wlan_objmgr_peer *peer)
{
	struct peer_atf *pa;

	if (NULL == peer) {
		atf_err("PEER is NULL!\n");
		return -1;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return 0;
	}

	return pa->atf_token_allocated;
}

uint16_t tgt_atf_get_token_utilized(struct wlan_objmgr_peer *peer)
{
	struct peer_atf *pa;

	if (NULL == peer) {
		atf_err("PEER is NULL!\n");
		return -1;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return 0;
	}

	return pa->atf_token_utilized;
}

void tgt_atf_set_sched(struct wlan_objmgr_pdev *pdev, uint32_t value)
{
	struct pdev_atf *pa;

	if (NULL == pdev) {
		atf_err("PDEV is NULL!\n");
		return;
	}
	pa = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("pdev_atf component object NULL!\n");
		return;
	}

	pa->atf_sched = value;
}

void tgt_atf_set_fmcap(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return;
	}

	ac->atf_fmcap = !!value;
}

void tgt_atf_set_msdu_desc(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return;
	}

	ac->atf_msdu_desc = value;
}

void tgt_atf_set_max_vdevs(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return;
	}

	ac->atf_max_vdevs = value;
}

void tgt_atf_set_peers(struct wlan_objmgr_psoc *psoc, uint32_t value)
{
	struct atf_context *ac = NULL;

	if (NULL == psoc) {
		atf_err("PSOC is NULL!\n");
		return;
	}
	ac = wlan_objmgr_psoc_get_comp_private_obj(psoc, WLAN_UMAC_COMP_ATF);
	if (NULL == ac) {
		atf_err("atf context is NULL!\n");
		return;
	}

	ac->atf_peers = value;
}

void tgt_atf_set_peer_stats(struct wlan_objmgr_peer *peer,
			    struct atf_stats *stats)
{
	struct peer_atf *pa;

	if ((NULL == peer) || (NULL == stats)) {
		atf_err("Invalid inputs!\n");
		return;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return;
	}

	qdf_mem_copy(&pa->atf_peer_stats, stats, sizeof(pa->atf_peer_stats));
}

static void
atf_peer_block_unblock(struct wlan_objmgr_vdev *vdev, void *object, void *arg) {
	struct wlan_objmgr_peer *peer = (struct wlan_objmgr_peer *)object;
	int8_t *block = (int8_t*)arg;
	struct peer_atf *pa;
	struct vdev_atf *va;

	if (NULL == peer) {
		atf_err ("peer is NULL!\n");
		return;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return;
	}
	va = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_ATF);
	if (NULL == va) {
		atf_err("vdev_atf component object NULL!\n");
		return;
	}

	if (!*block) {
		pa->block_tx_bitmap = 0;
		va->block_tx_traffic = 0;
		va->ac_blk_cnt = 0;
		pa->ac_blk_cnt = 0;
		atf_debug("Peer:%s bitmap:0x%08x blktxtraffic:%d acblkct:%d \n",
			  ether_sprintf(peer->macaddr), pa->block_tx_bitmap,
			  va->block_tx_traffic, va->ac_blk_cnt);
	} else {
		pa->block_tx_bitmap = ATF_TX_BLOCK_AC_ALL;
		va->block_tx_traffic = !!block;
		va->ac_blk_cnt = wlan_vdev_get_peer_count(vdev) * WME_NUM_AC;
		pa->ac_blk_cnt += WME_NUM_AC;
		atf_debug("peer:%s bitmap:0x%08x blktxtraffic:%d acblkct:%d \n",
			  ether_sprintf(peer->macaddr), pa->block_tx_bitmap,
			  va->block_tx_traffic, va->ac_blk_cnt);
	}
}

void
tgt_atf_set_vdev_blk_txtraffic(struct wlan_objmgr_vdev *vdev, uint8_t block)
{
	struct vdev_atf *va;

	if (NULL == vdev) {
		atf_err("VDEV is NULL!\n");
		return;
	}
	va = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_ATF);
	if (NULL == va) {
		atf_err("vdev_atf component object NULL!\n");
		return;
	}

	wlan_objmgr_iterate_peerobj_list(vdev,
					 atf_peer_block_unblock,
					 &block,
					 WLAN_UMAC_COMP_ATF);

}

uint8_t atf_peer_num_ac_blocked(uint8_t ac_bitmap)
{
	uint8_t num_ac_blocked = 0;

	while (ac_bitmap) {
		ac_bitmap &= ac_bitmap - 1;
		num_ac_blocked++;
	}

	return num_ac_blocked;
}

void
tgt_atf_peer_blk_txtraffic(struct wlan_objmgr_peer *peer, int8_t ac_id)
{
	struct peer_atf *pa;
	struct wlan_objmgr_vdev *vdev;
	struct vdev_atf *va;
	int8_t ac_blocked = 0;

	if (NULL == peer) {
		atf_err("PEER is NULL!\n");
		return;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return;
	}
	vdev = wlan_peer_get_vdev(peer);
	if (NULL == vdev) {
		atf_err("vdev is NULL!\n");
		return;
	}
	va = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_ATF);
	if (NULL == va) {
		atf_err("vdev_atf component object NULL!\n");
		return;
	}

	if (ac_id == ATF_TX_BLOCK_AC_ALL) {
		ac_blocked = atf_peer_num_ac_blocked(pa->block_tx_bitmap);
		pa->block_tx_bitmap |= ATF_TX_BLOCK_AC_ALL;
		va->ac_blk_cnt += (WME_NUM_AC - ac_blocked);
		pa->ac_blk_cnt += (WME_NUM_AC - ac_blocked);
		atf_debug("peer:%s vapac blk_cnt:%d peerblock count:0x%08x \n",
			  ether_sprintf(peer->macaddr), va->ac_blk_cnt,
			  pa->block_tx_bitmap);
	} else {
		pa->block_tx_bitmap |= (1 << (ac_id-1));
		va->ac_blk_cnt++;
		pa->ac_blk_cnt++;
		atf_debug("peer:%s vapac blk_cnt: %d peerblock count:0x%08x \n",
			   ether_sprintf(peer->macaddr), va->ac_blk_cnt,
			   pa->block_tx_bitmap);

	}
}

void
tgt_atf_peer_unblk_txtraffic(struct wlan_objmgr_peer *peer, int8_t ac_id)
{
	struct peer_atf *pa;
	struct wlan_objmgr_vdev *vdev;
	struct vdev_atf *va;
	uint8_t ac_blocked = 0;

	if (NULL == peer) {
		atf_err("PEER is NULL!\n");
		return;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		atf_err("peer_atf component object NULL!\n");
		return;
	}
        vdev = wlan_peer_get_vdev(peer);
	if (NULL == vdev) {
		atf_err("vdev is NULL!\n");
		return;
	}
	va = wlan_objmgr_vdev_get_comp_private_obj(vdev, WLAN_UMAC_COMP_ATF);
	if (NULL == va) {
		atf_err("vdev_atf component object NULL!\n");
		return;
	}

	if (pa->block_tx_bitmap) {
		if (va->ac_blk_cnt && (ac_id == ATF_TX_BLOCK_AC_ALL)) {
			ac_blocked = atf_peer_num_ac_blocked(pa->block_tx_bitmap);
			pa->block_tx_bitmap &= ~(ATF_TX_BLOCK_AC_ALL);
			va->ac_blk_cnt -= ac_blocked;
			pa->ac_blk_cnt -= ac_blocked;
			atf_debug("peer:%s vapacblkcnt:%d peerblkcnt:0x%08x\n",
				  ether_sprintf(peer->macaddr), va->ac_blk_cnt,
				  pa->block_tx_bitmap);
		} else {
			pa->block_tx_bitmap &= ~(1 << (ac_id-1));
			if (va->ac_blk_cnt) {
				va->ac_blk_cnt--;
				pa->ac_blk_cnt--;
				atf_debug("peer%s vpacblkct%d prblkcnt0x%08x\n",
					  ether_sprintf(peer->macaddr),
					  va->ac_blk_cnt, pa->block_tx_bitmap);
			}
		}
	}
}

void tgt_atf_set_token_allocated(struct wlan_objmgr_peer *peer, uint16_t value)
{
	struct peer_atf *pa;

	if (NULL == peer) {
		return;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		return;
	}

	pa->atf_token_allocated = value;
}

void tgt_atf_set_token_utilized(struct wlan_objmgr_peer *peer, uint16_t value)
{
	struct peer_atf *pa;

	if (NULL == peer) {
		return;
	}
	pa = wlan_objmgr_peer_get_comp_private_obj(peer, WLAN_UMAC_COMP_ATF);
	if (NULL == pa) {
		return;
	}

	pa->atf_token_utilized = value;
}

uint8_t tgt_atf_is_stats_enabled(struct wlan_objmgr_pdev *pdev)
{
	struct pdev_atf *patf = NULL;

	if (!pdev) {
		return 0;
	}
	patf = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_ATF);
	if (!patf) {
		return 0;
	}

	return patf->atf_stats_enable;
}

void tgt_atf_process_ppdu_stats(struct wlan_objmgr_pdev *pdev, qdf_nbuf_t msg)
{
	struct wlan_objmgr_psoc *psoc = NULL;
	struct wlan_objmgr_vdev *vdev = NULL;
	struct wlan_objmgr_peer *peer = NULL;
	struct pdev_atf *patf = NULL;
	struct atf_config *cfg = NULL;
	struct cdp_tx_completion_ppdu *cdp_tx_ppdu = NULL;
	struct cdp_tx_completion_ppdu_user *ppdu_user = NULL;
	struct atf_actual_airtime *act_grp = NULL;
	uint8_t usr_iter = 0, ac_num = 0;
	uint8_t i = 0, index, inx;
	bool skipped = true;
	struct atf_ac_config *ac_cfg = NULL;

	if (!pdev || !msg) {
		goto err;
	}
	cdp_tx_ppdu = (struct cdp_tx_completion_ppdu *)qdf_nbuf_data(msg);
	if (!cdp_tx_ppdu) {
		goto err;
	}
	psoc = wlan_pdev_get_psoc(pdev);
	if (!psoc) {
		goto err;
	}
	patf = wlan_objmgr_pdev_get_comp_private_obj(pdev, WLAN_UMAC_COMP_ATF);
	if (!patf) {
		goto err;
	}
	if (qdf_atomic_read(&patf->atf_stats_pause)) {
		goto err;
	}
	cfg = &patf->atfcfg_set;
	for (usr_iter = 0; (usr_iter < cdp_tx_ppdu->num_users) &&
			    (usr_iter < CDP_MU_MAX_USER_INDEX); usr_iter++) {
		index = 0xFF;
		inx = 0xFF;
		act_grp = NULL;

		ppdu_user = &cdp_tx_ppdu->user[usr_iter];
		peer = wlan_objmgr_get_peer(psoc, wlan_objmgr_pdev_get_pdev_id(pdev),
					    ppdu_user->mac_addr, WLAN_ATF_ID);
		if (!peer)
			continue;
		vdev = wlan_peer_get_vdev(peer);
		if (qdf_unlikely(!vdev)) {
			wlan_objmgr_peer_release_ref(peer, WLAN_ATF_ID);
			continue;
		}
		if ((QDF_SAP_MODE == wlan_vdev_mlme_get_opmode(vdev)) &&
		    (peer == wlan_vdev_get_bsspeer(vdev))) {
			wlan_objmgr_peer_release_ref(peer, WLAN_ATF_ID);
			continue;
		}

		for (i = 0; (i < cfg->peer_num_cal) &&
			     (i < ATF_ACTIVED_MAX_CLIENTS); i++) {
			if (!qdf_mem_cmp(cfg->peer_id[i].sta_mac,
					 ppdu_user->mac_addr,
					 QDF_MAC_ADDR_SIZE)) {
				index = i;
				break;
			}
		}
		if (index == 0xFF) {
			wlan_objmgr_peer_release_ref(peer, WLAN_ATF_ID);
			continue;
		}

		skipped = false;

		if (patf->atf_ssidgroup) {
			if (!cfg->peer_id[i].index_group ||
			    cfg->peer_id[i].index_group == 0xFF)
				inx = 0;
			else
				inx = cfg->peer_id[i].index_group - 1;
			ac_cfg = &cfg->atfgroup[inx].atf_cfg_ac;
			act_grp = &cfg->atfgroup[inx].act_airtime;
			act_grp->actual_airtime += ppdu_user->phy_tx_time_us;
		} else {
			if ((cfg->peer_id[i].index_vdev == 0xFF) ||
			    (!cfg->peer_id[i].index_vdev)) {
				inx = atf_find_vdev_index(patf, vdev) - 1;
			} else {
				inx = cfg->peer_id[i].index_vdev - 1;
			}
			if (inx < ATF_CFG_NUM_VDEV) {
				ac_cfg = &cfg->vdev[inx].atf_cfg_ac;
				cfg->vdev[inx].actual_airtime +=
						ppdu_user->phy_tx_time_us;
				if (atf_config_is_group_exist(cfg,
					cfg->vdev[inx].essid, &index)) {
					if (index < ATF_ACTIVED_MAX_ATFGROUPS) {
						act_grp =
						&cfg->atfgroup[index].act_airtime;
					}
				}
			}
		}
		if (!cfg->peer_id[i].cfg_flag && act_grp &&
		    ac_cfg->ac_cfg_flag) {
			ac_num = TID_TO_WME_AC(ppdu_user->tid);
			act_grp->actual_ac_airtime[ac_num] +=
						ppdu_user->phy_tx_time_us;
		}
		cfg->peer_id[i].actual_airtime += ppdu_user->phy_tx_time_us;
		wlan_objmgr_peer_release_ref(peer, WLAN_ATF_ID);
	}
	if (!skipped) {
		patf->actual_total_airtime +=
					cdp_tx_ppdu->phy_ppdu_tx_time_us;
	}

err:
	/* free cloned nbuf */
	qdf_nbuf_free(msg);
}
