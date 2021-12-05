/*
 * Copyright (c) 2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
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

/*
 * Radio interface configuration routines for perf_pwr_offload
 */
#include <osdep.h>
#include "ol_if_athvar.h"
#include "ol_if_txrx_handles.h"
#include "ol_if_athpriv.h"
#include "dbglog_host.h"
#include "fw_dbglog_api.h"
#include "ol_ath_ucfg.h"
#include <target_if.h>
#include <wlan_rnr.h>
#ifdef QCA_CBT_INSTRUMENTATION
#include "qdf_func_tracker.h"
#endif
#define IF_ID_OFFLOAD (1)
#if ATH_PERF_PWR_OFFLOAD
#if WLAN_SPECTRAL_ENABLE
#include <target_if_spectral.h>
#endif
#include "osif_private.h"

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#include "osif_nss_wifiol_vdev_if.h"
#endif
#include <ieee80211_ioctl_acfg.h>
#include <ieee80211_api.h>
#include <ieee80211_var.h>
#if QCA_AIRTIME_FAIRNESS
#include <target_if_atf.h>
#endif /* QCA_AIRTIME_FAIRNESS */
#include "cdp_txrx_ctrl.h"
#include "cdp_txrx_cmn_struct.h"
#include <wlan_lmac_if_api.h>
#include <init_deinit_lmac.h>
#include "target_type.h"
#include <wlan_utility.h>
#include <ol_regdomain_common.h>
#include <wlan_reg_ucfg_api.h>
#include <ieee80211_mlme_dfs_dispatcher.h>
#include <ol_if_pdev.h>
#include <ieee80211_api.h>
#if DBDC_REPEATER_SUPPORT
#include "qca_multi_link.h"
#endif
/*The value of the threshold is compared against the OBSS RSSI in dB.
* It is a 8-bit value whose
* range is -128 to 127 (after two's complement operation).
* For example, if the parameter value is 0xF5, the target will
* allow spatial reuse if the RSSI detected from other BSS
* is below -10 dB.
*/
#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif
#include <wlan_vdev_mgr_ucfg_api.h>

#if QCA_SUPPORT_AGILE_DFS
#include <wlan_dfs_ucfg_api.h>
#endif

#ifdef WLAN_DFS_PRECAC_AUTO_CHAN_SUPPORT
#include "../../../cmn_dev/umac/dfs/core/src/dfs_zero_cac.h"
#endif

#include "qdf_platform.h"
#if WLAN_CFR_ENABLE
#include <wlan_cfr_ucfg_api.h>
#endif

#include "cfg_ucfg_api.h"
#include "pld_common.h"
#include "dp_txrx.h"

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
extern struct ieee80211vap *wlan_get_vap(struct wlan_objmgr_vdev *vdev);
#endif
#endif

#include <wlan_son_pub.h>
#include <ol_if_dcs.h>

#if ATH_SUPPORT_HYFI_ENHANCEMENTS && ATH_SUPPORT_DSCP_OVERRIDE
/* Do we need to move these to some appropriate header */
void ol_ath_set_hmmc_tid(struct ieee80211com *ic , u_int32_t tid);
void ol_ath_set_hmmc_dscp_override(struct ieee80211com *ic , u_int32_t val);
void ol_ath_set_hmmc_tid(struct ieee80211com *ic , u_int32_t tid);


u_int32_t ol_ath_get_hmmc_tid(struct ieee80211com *ic);
u_int32_t ol_ath_get_hmmc_dscp_override(struct ieee80211com *ic);
#endif
void ol_ath_reset_vap_stat(struct ieee80211com *ic);
uint32_t promisc_is_active (struct ieee80211com *ic);

extern ol_ath_soc_softc_t *ol_global_soc[GLOBAL_SOC_SIZE];
extern int ol_num_global_soc;
extern int ol_ath_target_start(ol_ath_soc_softc_t *soc);

static u_int32_t ol_ath_net80211_get_total_per(struct ieee80211com *ic)
{
    u_int32_t total_per = ic->ic_get_tx_hw_retries(ic);

    if ( total_per == 0) {
    return 0;
    }

    return (total_per);
}

bool ol_ath_validate_chainmask(struct ol_ath_softc_net80211 *scn,
        uint32_t chainmask, int direction, int phymode)
{
    struct wlan_objmgr_psoc *psoc = scn->soc->psoc_obj;
    struct wlan_psoc_host_service_ext_param *ext_param;
    struct target_psoc_info *tgt_hdl;
    struct target_pdev_info *tgt_pdev;
    uint8_t phy_idx;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap = NULL;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap_arr = NULL;
    struct wlan_psoc_host_chainmask_table *table = NULL;
    struct wlan_psoc_host_chainmask_capabilities *capability = NULL;
#if QCA_SUPPORT_AGILE_DFS
    struct wlan_objmgr_pdev *pdev = scn->sc_pdev;
    bool is_agile_precac_enabled;
#endif
    int j = 0;
    bool is_2g_band_supported = false;
    bool is_5g_band_supported = false;
    uint32_t table_id = 0;
    enum ieee80211_cwm_width ch_width;

    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
    	qdf_info("%s: psoc target_psoc_info is null", __func__);
    	return false;
    }

    ext_param = &(tgt_hdl->info.service_ext_param);

    tgt_pdev = (struct target_pdev_info *)wlan_pdev_get_tgt_if_handle(scn->sc_pdev);
    phy_idx = target_pdev_get_phy_idx(tgt_pdev);
    mac_phy_cap_arr = target_psoc_get_mac_phy_cap(tgt_hdl);
    if (mac_phy_cap_arr) {
        uint8_t i, num_radios;

        num_radios = target_psoc_get_num_radios_for_mode(tgt_hdl,
                                  tgt_hdl->info.preferred_hw_mode);
        for(i = 0; i < num_radios; i++) {
            if(phy_idx == mac_phy_cap_arr[i].phy_id) {

                /* Get mac_phy caps for the phy_id. */
                mac_phy_cap = &mac_phy_cap_arr[i];
                /* get table ID for a given pdev */
                table_id = mac_phy_cap->chainmask_table_id;
                break;
            }
       }
    } else {
        qdf_err("%s: mac phy cap arr is NULL", __func__);
    }

    /* table */
    table =  &(ext_param->chainmask_table[table_id]);

    /* Return if table is null, usually should be false */
    if (!table->cap_list){
        qdf_info("%s: Returning due to null table", __func__);
        return false;
    }

    for (j = 0; j < table->num_valid_chainmasks; j++) {
        if (table->cap_list[j].chainmask != chainmask) {
            continue;
        } else {
            capability = &(table->cap_list[j]);

            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "chainmask num %d: 0x%08x \n",j, capability->chainmask);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_chan_width_20: %u \n", capability->supports_chan_width_20);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_chan_width_40: %u \n", capability->supports_chan_width_40);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_chan_width_80: %u \n", capability->supports_chan_width_80);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_chan_width_160: %u \n", capability->supports_chan_width_160);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_chan_width_80P80: %u \n", capability->supports_chan_width_80P80);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t chain_mask_2G: %u \n", capability->chain_mask_2G);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t chain_mask_5G: %u \n", capability->chain_mask_5G);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t chain_mask_tx: %u \n", capability->chain_mask_tx);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t chain_mask_rx: %u \n", capability->chain_mask_rx);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_aDFS: %u \n",  capability->supports_aDFS);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_aSpectral: %u \n",  capability->supports_aSpectral);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_aDFS_160: %u \n",  capability->supports_aDFS_160);
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "\t supports_aSpectral_160: %u \n",  capability->supports_aSpectral_160);
            break;
        }
    }

    if (capability == NULL) {
        QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "Chain Mask is not available for radio \n");
        return false;
    }

    /*
     * 1. check given chain mask supports tx/rx.
     * 2. check given chain mask supports 2G/5G.
     * 3. check given chain mask supports current phymode
     *      20, 40, 80, 160, 80P80.
     * 4. Check given chain mask supprts aDFS.
     * Once given chain mask validation is done, Calculate NSS and update nss for radio.
     */

    if (direction == VALIDATE_TX_CHAINMASK) {
        if (!capability->chain_mask_tx) {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "%s: chain mask does not support TX \n", __func__);
            return false;
        }
    }

    if (direction == VALIDATE_RX_CHAINMASK) {
        if (!capability->chain_mask_rx) {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "%s: chain mask does not support RX \n", __func__);
            return false;
        }
    }

    if (mac_phy_cap) {
        if ((mac_phy_cap->supported_bands & WMI_HOST_WLAN_2G_CAPABILITY) &&
                capability->chain_mask_2G) {
            is_2g_band_supported = true;
        }
        if ((mac_phy_cap->supported_bands & WMI_HOST_WLAN_5G_CAPABILITY) &&
                capability->chain_mask_5G) {
            is_5g_band_supported = true;
        }
    }

    if (ieee80211_is_phymode_auto(phymode)) {
        if (!is_2g_band_supported && !is_5g_band_supported)
            return false;
        else
            return true;
    }

    /* check BAND for a given chain mask */
    if (ieee80211_is_phymode_2g(phymode)) {
        if (!capability->chain_mask_2G) {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "%s: Invalid chain mask for mode: %d 2.4G band not supported\n", __func__, phymode);
            return false;
        }
    }

    if (ieee80211_is_phymode_5g_or_6g(phymode)) {
        if (!capability->chain_mask_5G) {
            QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                    "%s: Invalid chain mask for mode: %d 5G band not supported\n", __func__, phymode);
            return false;
        }
    }

    /* check channel width for a given chain mask */
    ch_width = get_chwidth_phymode(phymode);
    switch(ch_width)
    {
        case IEEE80211_CWM_WIDTH20:
            if (!capability->supports_chan_width_20) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                        "%s: Invalid chain mask for mode: %d chwidth20 not supported\n", __func__, phymode);
                return false;
            }
            break;
        case IEEE80211_CWM_WIDTH40:
            if (!capability->supports_chan_width_40) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                        "%s: Invalid chain mask for mode: %d chwidth40 not supported\n", __func__, phymode);
                return false;
            }
            break;
        case IEEE80211_CWM_WIDTH80:
            if (!capability->supports_chan_width_80) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                        "%s: Invalid chain mask for mode: %d chwidth80 not supported\n", __func__, phymode);
                return false;
            }
            break;
        case IEEE80211_CWM_WIDTH160:
            if (!capability->supports_chan_width_160) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                        "%s: Invalid chain mask for mode: %d chwidth160 not supported\n", __func__, phymode);
                return false;
            }
            break;
        case IEEE80211_CWM_WIDTH80_80:
            if (!capability->supports_chan_width_80P80) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO_LOW,
                        "%s: Invalid chain mask for mode: %d chwidth80+80 not supported\n", __func__, phymode);
                return false;
            }

        default:
            break;

    }

#if QCA_SUPPORT_AGILE_DFS
        ucfg_dfs_get_agile_precac_enable(pdev, &is_agile_precac_enabled);
        if (is_agile_precac_enabled) {
            if (!capability->supports_aDFS) {
                QDF_TRACE(QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                          "%s:FW does not support aDFS, disabling in host. chainmask = 0x%08x\n",
			  __func__, capability->chainmask);
                ucfg_dfs_set_precac_enable(pdev, 0);
            }
        }
#endif

    return true;
}

void
ol_ath_dump_chainmaks_tables(struct ol_ath_softc_net80211 *scn)
{
    struct wlan_objmgr_psoc *psoc = scn->soc->psoc_obj;
    struct wlan_psoc_host_service_ext_param *ext_param;
    struct target_psoc_info *tgt_hdl;
    uint8_t pdev_idx;
    struct wlan_psoc_host_chainmask_table *table = NULL;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap_arr = NULL;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap = NULL;
    int j = 0, table_id = 0;

    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if(!tgt_hdl) {
    	qdf_info("%s: psoc target_psoc_info is null", __func__);
    	return;
    }

    mac_phy_cap_arr = target_psoc_get_mac_phy_cap(tgt_hdl);
    ext_param       = target_psoc_get_service_ext_param(tgt_hdl);
    pdev_idx        = lmac_get_pdev_idx(scn->sc_pdev);

    if(mac_phy_cap_arr) {
        mac_phy_cap = &mac_phy_cap_arr[pdev_idx];
        /* get table ID for a given pdev */
        table_id    = mac_phy_cap->chainmask_table_id;
    } else {
        qdf_err("%s: mac_phy_cap_arr is NULL!", __func__);
    }

    if (ext_param) {
        table =  &(ext_param->chainmask_table[table_id]);
        if (table) {
            qdf_info("------------- table ID: %d --------------- ",
                    table->table_id);
            qdf_info("num valid chainmasks: %d ", table->num_valid_chainmasks);
            for (j = 0; j < table->num_valid_chainmasks; j++) {
                qdf_info("chainmask num %d: 0x%08x ",
                        j, table->cap_list[j].chainmask);
                qdf_info("\t supports_chan_width_20: %u ",
                        table->cap_list[j].supports_chan_width_20);
                qdf_info("\t supports_chan_width_40: %u ",
                        table->cap_list[j].supports_chan_width_40);
                qdf_info("\t supports_chan_width_80: %u ",
                        table->cap_list[j].supports_chan_width_80);
                qdf_info("\t supports_chan_width_160: %u ",
                        table->cap_list[j].supports_chan_width_160);
                qdf_info("\t supports_chan_width_80P80: %u ",
                        table->cap_list[j].supports_chan_width_80P80);
                qdf_info("\t chain_mask_2G: %u ",
                        table->cap_list[j].chain_mask_2G);
                qdf_info("\t chain_mask_5G: %u ",
                        table->cap_list[j].chain_mask_5G);
                qdf_info("\t chain_mask_tx: %u ",
                        table->cap_list[j].chain_mask_tx);
                qdf_info("\t chain_mask_rx: %u ",
                        table->cap_list[j].chain_mask_rx);
                qdf_info("\t supports_aDFS: %u ",
                        table->cap_list[j].supports_aDFS);
                qdf_info("\t supports_aSpectral: %u ",
                        table->cap_list[j].supports_aSpectral);
                qdf_info("\t supports_aDFS_160: %u ",
                        table->cap_list[j].supports_aDFS_160);
                qdf_info("\t supports_aSpectral_160: %u ",
                        table->cap_list[j].supports_aSpectral_160);
            } /* end for */
        } /* end if (table) */
    } /* end if (ext_param) */
}

int config_txchainmask(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct wlan_vdev_mgr_cfg mlme_cfg;
    int retval = 0;
    uint32_t iv_nss;

    retval = ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_tx_chain_mask,
                                   scn->user_config_txval);
    if (retval == EOK) {
        u_int8_t  nss;
        struct ieee80211vap *tmpvap = NULL;
        /* Update the ic_chainmask */
        ieee80211com_set_tx_chainmask(ic, (u_int8_t)(scn->user_config_txval));
        /* Update num chains for preferred streams */
        ieee80211com_set_num_tx_chain(ic,
                              num_chain_from_chain_mask(ic->ic_tx_chainmask));
        /* Get nss from configured tx chainmask */
        nss = ieee80211_getstreams(ic, ic->ic_tx_chainmask);

        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            u_int8_t retv;
            /* On changing chain mask, per VAP's vht_mcs map should be computed
             * with newly configured chain mask. Mark iv_set_vht_mcsmap as
             * false so that ieee80211_setup_vht() gets latest chainmask from
             * ic till iv_vhtcap_max_mcs is computed freshly
             * from latest chainmask in ieee80211_set_vhtrates().
             */
            tmpvap->iv_set_vht_mcsmap = false;
            /* Update the iv_nss before restart the vap by sending WMI CMD to FW
               to configure the NSS */
            if (ic->ic_vap_set_param) {
                retv = wlan_set_param(tmpvap,IEEE80211_FIXED_NSS,nss);
                if (retv == EOK) {
                    mlme_cfg.value = nss;
                    ucfg_wlan_vdev_mgr_set_param(tmpvap->vdev_obj, WLAN_MLME_CFG_NSS,
                                                 mlme_cfg);
                } else {
                    ucfg_wlan_vdev_mgr_get_param(tmpvap->vdev_obj, WLAN_MLME_CFG_NSS,
                                                 &iv_nss);
                    qdf_info("vap %d :%pK Failed to configure NSS from %d to %d ",
                              tmpvap->iv_unit, tmpvap, iv_nss, nss);
                }
            }
            mlme_cfg.value = ic->ic_num_tx_chain;
            ucfg_wlan_vdev_mgr_set_param(tmpvap->vdev_obj, WLAN_MLME_CFG_TX_STREAMS,
                                         mlme_cfg);
        }
    }
    return 0;
}

int config_rxchainmask(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *tmpvap = NULL;
    struct wlan_vdev_mgr_cfg mlme_cfg;
    int retval = 0;

    retval = ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_rx_chain_mask,
                                   scn->user_config_rxval);
    if (retval == EOK) {
        ol_ath_update_fw_adfs_support(ic, scn->user_config_rxval);
        /* Update the ic_chainmask */
        ieee80211com_set_rx_chainmask(ic, scn->user_config_rxval);
        /* Update the ic_num_rx_chain */
        ieee80211com_set_num_rx_chain(ic,
                              num_chain_from_chain_mask(ic->ic_rx_chainmask));

        /* On changing chain mask, per VAP's vht_mcs map should be computed
         * with newly configured chain mask. Mark iv_set_vht_mcsmap as
         * false so that ieee80211_setup_vht() gets latest chainmask from
         * ic till iv_vhtcap_max_mcs is computed freshly
         * from latest chainmask in ieee80211_set_vhtrates().
         */

        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            tmpvap->iv_set_vht_mcsmap = false;
            mlme_cfg.value = ic->ic_num_rx_chain;
            ucfg_wlan_vdev_mgr_set_param(tmpvap->vdev_obj, WLAN_MLME_CFG_RX_STREAMS,
                                         mlme_cfg);
        }
    }
    return 0;
}

void ol_ath_pdev_config_update(struct ieee80211com *ic)
{
    uint8_t restart_reason = ic->ic_restart_reason;

    if (!restart_reason)
        return;

    if (restart_reason & PDEV_CFG_TXCHAINMASK) {
        qdf_info("Updating TX chainmask");
        config_txchainmask(ic, NULL);
    }

    if (restart_reason & PDEV_CFG_RXCHAINMASK) {
        qdf_info("Updating RX chainmask");
        config_rxchainmask(ic, NULL);
    }

    ic->ic_restart_reason = 0;
}

void wmi_dis_dump (void *psoc,enum qdf_hang_reason reason,
                   const char *func, const uint32_t line)
{
    qdf_err("WMI disconnect assert called wait for target to assert !!!!\n");
}

enum _dp_param_t ol_ath_param_to_dp_param(enum _ol_ath_param_t param)
{
    switch(param) {
        case OL_ATH_PARAM_MSDU_TTL:
            return DP_PARAM_MSDU_TTL;
        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE0:
            return DP_PARAM_TOTAL_Q_SIZE_RANGE0;
        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE1:
            return DP_PARAM_TOTAL_Q_SIZE_RANGE1;
        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE2:
            return DP_PARAM_TOTAL_Q_SIZE_RANGE2;
        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE3:
            return DP_PARAM_TOTAL_Q_SIZE_RANGE3;
        case OL_ATH_PARAM_VIDEO_DELAY_STATS_FC:
            return DP_PARAM_VIDEO_DELAY_STATS_FC;
        case OL_ATH_PARAM_QFLUSHINTERVAL:
            return DP_PARAM_QFLUSHINTERVAL;
        case OL_ATH_PARAM_TOTAL_Q_SIZE:
            return DP_PARAM_TOTAL_Q_SIZE;
        case OL_ATH_PARAM_MIN_THRESHOLD:
            return DP_PARAM_MIN_THRESHOLD;
        case OL_ATH_PARAM_MAX_Q_LIMIT:
            return DP_PARAM_MAX_Q_LIMIT;
        case OL_ATH_PARAM_MIN_Q_LIMIT:
            return DP_PARAM_MIN_Q_LIMIT;
        case OL_ATH_PARAM_CONG_CTRL_TIMER_INTV:
            return DP_PARAM_CONG_CTRL_TIMER_INTV;
        case OL_ATH_PARAM_STATS_TIMER_INTV:
            return DP_PARAM_STATS_TIMER_INTV;
        case OL_ATH_PARAM_ROTTING_TIMER_INTV:
            return DP_PARAM_ROTTING_TIMER_INTV;
        case OL_ATH_PARAM_LATENCY_PROFILE:
            return DP_PARAM_LATENCY_PROFILE;
        case OL_ATH_PARAM_HOSTQ_DUMP:
            return DP_PARAM_HOSTQ_DUMP;
        case OL_ATH_PARAM_TIDQ_MAP:
            return DP_PARAM_TIDQ_MAP;
        case OL_ATH_PARAM_VIDEO_STATS_FC:
            return DP_PARAM_VIDEO_STATS_FC;
        case OL_ATH_PARAM_STATS_FC:
            return DP_PARAM_STATS_FC;
        default:
            return DP_PARAM_MAX;
    }
}

/* PPDU max time limit for JAPAN country code is 4 ms */
#define PPDU_MAX_4MS_TIME_LIMIT_US_JPN 4000

/* PPDU max time limit is 5.4 ms (applicable to all the country codes other
 * than JAPAN country code).
 */
#define PPDU_MAX_TIME_LIMIT_US 5400

static uint16_t get_max_ppdu_duration(struct ieee80211com *ic)
{
    uint8_t ctry_iso[REG_ALPHA2_LEN + 1];

    ieee80211_getCurrentCountryISO(ic, ctry_iso);

    if (qdf_mem_cmp(ctry_iso, "JP", REG_ALPHA2_LEN) == 0)
        return PPDU_MAX_4MS_TIME_LIMIT_US_JPN;

    return PPDU_MAX_TIME_LIMIT_US;
}


void ol_ath_set_fw_recovery(struct ol_ath_softc_net80211 *scn, int value)
{
	int target_type = 0, soc_idx;
	ol_ath_soc_softc_t *temp_soc = NULL;
	void *dev;

	if (value < RECOVERY_DISABLE || value > RECOVERY_ENABLE_SSR_ONLY) {
		qdf_info("Please enter: 0 = Disable,  1 = Enable (auto recover), 2 = Enable (wait for user) 3 = Enable SSR only");
		return;
	}

	target_type  = lmac_get_tgt_type(scn->soc->psoc_obj);

	switch (target_type) {
	case TARGET_TYPE_QCA5018:
	case TARGET_TYPE_QCN6122:
		if (value == RECOVERY_ENABLE_AUTO) {
			/* Unlink UserPD assert from RootPD assert */
			ol_ath_pdev_set_param(scn->sc_pdev,
					      wmi_pdev_param_mpd_userpd_ssr,
					      1);
		} else if (value == RECOVERY_DISABLE) {
			/* Link UserPD assert to cause a RootPD assert */
			ol_ath_pdev_set_param(scn->sc_pdev,
					      wmi_pdev_param_mpd_userpd_ssr,
					      0);
		}
		/* fallthrough */
	default:
		for (soc_idx = 0; soc_idx < ol_num_global_soc; soc_idx++) {
			temp_soc = ol_global_soc[soc_idx];
			if (temp_soc) {
				temp_soc->recovery_enable =  value;
				dev = temp_soc->sc_osdev->device;
				pld_set_recovery_enabled(dev, !(value == RECOVERY_DISABLE));
			}
		}
		break;
	}
}

#define MAX_ANTENNA_GAIN 30
int
ol_ath_set_config_param(struct ol_ath_softc_net80211 *scn,
        enum _ol_ath_param_t param, void *buff, bool *restart_vaps)
{
    int retval = 0;
    u_int32_t value = *(u_int32_t *)buff, param_id;
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *tmp_vap = NULL;
    struct target_psoc_info *tgt_psoc_info = NULL;
#if QCA_SUPPORT_SON
    int thresh = 0;
#endif
#if DBDC_REPEATER_SUPPORT
    struct ieee80211com *tmp_ic = NULL;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ol_ath_softc_net80211 *tmp_scn = NULL;
#endif
    int i = 0;
    struct ieee80211com *fast_lane_ic;
    struct wiphy *primary_wiphy = NULL;
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    u_int32_t nss_soc_cfg;
#endif
#if ATH_SUPPORT_WRAP && QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_dev *osd = NULL;
    struct ieee80211vap *mpsta_vap = NULL;
#endif
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
#if QCA_AIRTIME_FAIRNESS
    int atf_sched = 0;
#endif

#if ATH_SUPPORT_DFS
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
#if ATH_SUPPORT_STA_DFS
    struct wlan_lmac_if_tx_ops *tx_ops;
    struct wlan_lmac_if_dfs_tx_ops *dfs_tx_ops;
    bool prev_stadfs_en = false, cur_stadfs_en = false;
#endif
#endif
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;

    struct ieee80211_vap_opmode_count vap_opmode_count;
    target_resource_config *tgt_cfg;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap;
    uint8_t pdev_idx, pdev_id;
    ol_ath_soc_softc_t *soc = scn->soc;
    struct wmi_unified *wmi_handle;
    struct wmi_unified *pdev_wmi_handle;
    cdp_config_param_type val = {0};
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                WLAN_PDEV_F_MBSS_IE_ENABLE);

    wmi_handle = lmac_get_wmi_hdl(scn->soc->psoc_obj);
    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_info("%s : pdev is NULL", __func__);
        return -1;
    }

    psoc = wlan_pdev_get_psoc(pdev);

    if (psoc == NULL) {
        qdf_info("%s : psoc is NULL", __func__);
        return -1;
    }

    pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    tgt_cfg = lmac_get_tgt_res_cfg(psoc);
    if (!tgt_cfg) {
        qdf_info("%s: psoc target res cfg is null", __func__);
        return -1;
    }
#if ATH_SUPPORT_DFS
    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
#if ATH_SUPPORT_STA_DFS
    tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
    if (!tx_ops) {
        qdf_err("tx_ops is NULL");
        return -1;
    }
    dfs_tx_ops = &tx_ops->dfs_tx_ops;
#endif
#endif

    tgt_psoc_info = wlan_psoc_get_tgt_if_handle(psoc);
    reg_cap = ucfg_reg_get_hal_reg_cap(psoc);
    pdev_idx = lmac_get_pdev_idx(pdev);
    qdf_assert_always(restart_vaps != NULL);

    if (qdf_atomic_test_bit(SOC_RESET_IN_PROGRESS_BIT,
                            &scn->soc->reset_in_progress)) {
        qdf_info("Reset in progress, return");
        return -1;
    }

    if (scn->soc->down_complete) {
        qdf_info("Starting the target before sending the command");
        if (ol_ath_target_start(scn->soc)) {
               qdf_info("failed to start the target");
               return -1;
        }
    }

    switch(param)
    {
        case OL_ATH_PARAM_TXCHAINMASK:
        {
            u_int8_t cur_mask = ieee80211com_get_tx_chainmask(ic);
            enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
            OS_MEMZERO(&vap_opmode_count, sizeof(struct ieee80211_vap_opmode_count));
            ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);

            if (!value) {
                /* value is 0 - set the chainmask to be the default
                 * supported tx_chain_mask value
                 */
                if (cur_mask == tgt_cfg->tx_chain_mask){
                    break;
                }
                scn->user_config_txval = tgt_cfg->tx_chain_mask;
                /*
                 * If any sta vap is found to be part of this pdev, or if there
                 * are no vaps on radio, then use the default stop_start path
                 * i.e osif_restart_for_config to update the config.
                 * Else use the optimized multi-vdev restart path
                 */
                if (vap_opmode_count.sta_count || !vap_opmode_count.total_vaps) {
                    osif_restart_for_config(ic, config_txchainmask, NULL);
                } else {
                    ic->ic_restart_reason |= PDEV_CFG_TXCHAINMASK;
                    osif_pdev_restart_vaps(ic);
                }
            } else if (cur_mask != value) {
                /* Update chainmask only if the current chainmask is different */

                if (ol_target_lithium(scn->soc->psoc_obj)) {

                    if (TAILQ_EMPTY(&ic->ic_vaps)) {
                        /* No vaps present, make phymode as AUTO */
                        phymode = IEEE80211_MODE_AUTO;
                    } else {
                        /*
                         * Currently phymode is per radio and it is same for all VAPS.
                         * So first vap mode alone fine for validaitons.
                         * Note: In future if we support different phymode per VAP then
                         * we need to check for all VAPS here or have per VAP chainmasks.
                         */
                        tmp_vap = TAILQ_FIRST(&ic->ic_vaps);
                        phymode = tmp_vap->iv_des_mode;
                    }

                    if (!ol_ath_validate_chainmask(scn, value, VALIDATE_TX_CHAINMASK, phymode)) {
                        qdf_info("Invalid TX chain mask: %d for phymode: %d", value, phymode);
                        return -1;
                    }
                } else if (value > tgt_cfg->tx_chain_mask) {
                    qdf_info("ERROR - value is greater than supported chainmask 0x%x \n",
                            tgt_cfg->tx_chain_mask);
                    return -1;
                }
                scn->user_config_txval = value;
                if (vap_opmode_count.sta_count || !vap_opmode_count.total_vaps) {
                    osif_restart_for_config(ic, config_txchainmask, NULL);
                } else {
                    ic->ic_restart_reason |= PDEV_CFG_TXCHAINMASK;
                    osif_pdev_restart_vaps(ic);
                }
            }
        }
        break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS && ATH_SUPPORT_DSCP_OVERRIDE
		case OL_ATH_PARAM_HMMC_DSCP_TID_MAP:
			ol_ath_set_hmmc_tid(ic,value);
		break;

		case OL_ATH_PARAM_HMMC_DSCP_OVERRIDE:
			ol_ath_set_hmmc_dscp_override(ic,value);
        break;
#endif
        case OL_ATH_PARAM_RXCHAINMASK:
        {
            u_int8_t cur_mask = ieee80211com_get_rx_chainmask(ic);
            enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
#if WLAN_SPECTRAL_ENABLE
            u_int8_t spectral_rx_chainmask;
#endif
            OS_MEMZERO(&vap_opmode_count, sizeof(struct ieee80211_vap_opmode_count));
            ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
            if (!value) {
                /* value is 0 - set the chainmask to be the default
                 * supported rx_chain_mask value
                 */
                if (cur_mask == tgt_cfg->rx_chain_mask){
                    break;
                }
                scn->user_config_rxval = tgt_cfg->rx_chain_mask;
                /*
                 * If any sta vap is found to be part of this pdev, or if there
                 * are no vaps on radio, then use the default stop_start path
                 * i.e osif_restart_for_config to update the config.
                 * Else use the optimized multi-vdev restart path
                 */
                if (vap_opmode_count.sta_count || !vap_opmode_count.total_vaps) {
                    osif_restart_for_config(ic, config_rxchainmask, NULL);
                } else {
                    ic->ic_restart_reason |= PDEV_CFG_RXCHAINMASK;
                    osif_pdev_restart_vaps(ic);
                }
            } else if (cur_mask != value) {
                /* Update chainmask only if the current chainmask is different */

                if (ol_target_lithium(scn->soc->psoc_obj)) {
                    if (TAILQ_EMPTY(&ic->ic_vaps)) {
                        /* No vaps present, make phymode as AUTO */
                        phymode = IEEE80211_MODE_AUTO;
                    } else {
                        /*
                         * Currently phymode is per radio and it is same for all VAPS.
                         * So first vap mode alone fine for validaitons.
                         * Note: In future if we support different phymode per VAP then
                         * we need to check for all VAPS here or have per VAP chainmasks.
                         */
                        tmp_vap = TAILQ_FIRST(&ic->ic_vaps);
                        phymode = tmp_vap->iv_des_mode;
                    }

                    if (!ol_ath_validate_chainmask(scn, value, VALIDATE_RX_CHAINMASK, phymode)) {
                        qdf_info("Invalid RX chain mask: %d for phymode %d", value, phymode);
                        return -1;
                    }
                } else if (value > tgt_cfg->rx_chain_mask) {
                    qdf_info("ERROR - value is greater than supported chainmask 0x%x \n",
                            tgt_cfg->rx_chain_mask);
                    return -1;
                }
                scn->user_config_rxval = value;
                if (vap_opmode_count.sta_count || !vap_opmode_count.total_vaps) {
                    osif_restart_for_config(ic, config_rxchainmask, NULL);
                } else {
                    ic->ic_restart_reason |= PDEV_CFG_RXCHAINMASK;
                    osif_pdev_restart_vaps(ic);
                }
            }
#if WLAN_SPECTRAL_ENABLE
            qdf_info("Resetting spectral chainmask to Rx chainmask\n");
            spectral_rx_chainmask = ieee80211com_get_rx_chainmask(ic);
            target_if_spectral_set_rxchainmask(ic->ic_pdev_obj, spectral_rx_chainmask);
#endif
        }
        break;
#if QCA_AIRTIME_FAIRNESS
        case  OL_ATH_PARAM_ATF_STRICT_SCHED:
        {
            if ((value != 0) && (value != 1)) {
                qdf_err("ATF Strict Sched value only accept 1 (Enable) or 0 (Disable)!!");
                return -1;
            }
            atf_sched = target_if_atf_get_sched(psoc, pdev);
            if ((value == 1) && (!(atf_sched & ATF_GROUP_SCHED_POLICY))
               && (target_if_atf_get_ssid_group(psoc, pdev))) {
                qdf_err("Fair queue across groups is enabled so strict queue "
                        "within groups is not allowed. Invalid combination");
                return -EINVAL;
            }
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_atf_strict_sch,
                                           value);
            if (retval == EOK) {
                if (value)
                    target_if_atf_set_sched(psoc, pdev,
                                            atf_sched | ATF_SCHED_STRICT);
                else
                    target_if_atf_set_sched(psoc, pdev,
                                            atf_sched & ~ATF_SCHED_STRICT);
            }
        }
        break;
        case  OL_ATH_PARAM_ATF_GROUP_POLICY:
        {
            if ((value != 0) && (value != 1)) {
                qdf_err("ATF Group policy value only accept 1 (strict) or 0 (fair)!!");
                return -1;
            }
            atf_sched = target_if_atf_get_sched(psoc, pdev);
            if ((value == 0) && (atf_sched & ATF_SCHED_STRICT)) {
                qdf_err("Strict queue within groups is enabled so fair queue "
                        "across groups is not allowed.Invalid combination");
                return -EINVAL;
            }
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_atf_ssid_group_policy,
                                           value);
            if (retval == EOK) {
                if (value)
                    target_if_atf_set_sched(psoc, pdev,
                                            atf_sched | ATF_GROUP_SCHED_POLICY);
                else
                    target_if_atf_set_sched(psoc, pdev,
                                            atf_sched & ~ATF_GROUP_SCHED_POLICY);
            }
        }
        break;
        case  OL_ATH_PARAM_ATF_OBSS_SCHED:
        {
#if 0 /* remove after FW support */
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                 wmi_pdev_param_atf_obss_noise_sch, !!value);
#endif
            if (retval == EOK) {
                atf_sched = target_if_atf_get_sched(psoc, pdev);
                if (value)
                    target_if_atf_set_sched(psoc, pdev, atf_sched | ATF_SCHED_OBSS);
                else
                    target_if_atf_set_sched(psoc, pdev, atf_sched & ~ATF_SCHED_OBSS);
            }
        }
        break;
#endif
        case OL_ATH_PARAM_TXPOWER_LIMIT2G:
        {
            if (!value) {
                value = scn->max_tx_power;
            }
            ic->ic_set_txPowerLimit(ic->ic_pdev_obj, value, value, 1);
        }
        break;

        case OL_ATH_PARAM_TXPOWER_LIMIT5G:
        {
            if (!value) {
                value = scn->max_tx_power;
            }
            ic->ic_set_txPowerLimit(ic->ic_pdev_obj, value, value, 0);
        }
        break;
        case OL_ATH_PARAM_RTS_CTS_RATE:
        if(value > 4) {
            qdf_info("Invalid value for setctsrate Disabling it in Firmware \n");
            value = WMI_HOST_FIXED_RATE_NONE;
        }
        scn->ol_rts_cts_rate = value;
        return ol_ath_pdev_set_param(scn->sc_pdev,
                                     wmi_pdev_param_rts_fixed_rate,value);
        break;

        case OL_ATH_PARAM_DEAUTH_COUNT:
#if WDI_EVENT_ENABLE
        if(value) {
            scn->scn_user_peer_invalid_cnt = value;
            scn->scn_peer_invalid_cnt = 0;
        }
#endif
        break;

        case OL_ATH_PARAM_TXPOWER_SCALE:
        {
            if ((WMI_HOST_TP_SCALE_MAX <= value) &&
                (value <= WMI_HOST_TP_SCALE_MIN)) {
                scn->txpower_scale = value;
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_txpower_scale,
                                             value);
            } else {
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_PS_STATE_CHANGE:
        {
            ol_ath_pdev_set_param(scn->sc_pdev,
                                  wmi_pdev_peer_sta_ps_statechg_enable, value);
            scn->ps_report = value;
        }
        break;
        case OL_ATH_PARAM_NON_AGG_SW_RETRY_TH:
        {
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_non_agg_sw_retry_th,
                                         value);
        }
        break;
        case OL_ATH_PARAM_AGG_SW_RETRY_TH:
        {
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_agg_sw_retry_th, value);
        }
        break;
        case OL_ATH_PARAM_STA_KICKOUT_TH:
        {
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_sta_kickout_th, value);
        }
        break;
        case OL_ATH_PARAM_DYN_GROUPING:
        {
            value = !!value;
            if ((ic->ic_dynamic_grouping_support)) {
                if (scn->dyngroup == (u_int8_t)value) {
                   break;
                }
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_mu_group_policy,
                                               value);
                if (retval == EOK)
                    scn->dyngroup = (u_int8_t)value;
            } else {
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_DBGLOG_RATELIM:
        {
                void *dbglog_handle;
                struct target_psoc_info *tgt_psoc_info;

                tgt_psoc_info = wlan_psoc_get_tgt_if_handle(scn->soc->psoc_obj);
                if (tgt_psoc_info == NULL) {
                        qdf_info("%s: target_psoc_info is null ", __func__);
                        return -EINVAL;
                }

                if (!(dbglog_handle = target_psoc_get_dbglog_hdl(tgt_psoc_info))) {
                        qdf_info("%s: dbglog_handle is null ", __func__);
                        return -EINVAL;
                }

                fwdbg_ratelimit_set(dbglog_handle, value);
        }
        break;
        case OL_ATH_PARAM_BCN_BURST:
        {
            /* value is set to either 1 (bursted) or 0 (staggered).
             * if value passed is non-zero, convert it to 1 with
             * double negation
             */
            value = !!value;
            if (ieee80211_vap_is_any_running(ic)) {
                qdf_err("VAP(s) in running state "
                        "Cannot change between burst/staggered beacon modes");
                retval = -EINVAL;
                break;
            }
            if (scn->bcn_mode != (u_int8_t)value) {
                if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                              WLAN_PDEV_F_MBSS_IE_ENABLE)) {
                    if (value != 1) {
                        qdf_err("Disabling bursted mode not allowed "
                                "when MBSS feature is enabled");
                        retval = -EINVAL;
                        break;
                    }
                }
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_beacon_tx_mode,
                                               value);
                if (retval == EOK) {
                    scn->bcn_mode = (u_int8_t)value;
                    *restart_vaps = TRUE;
                }
            }
            break;
        }
        break;
        case OL_ATH_PARAM_DPD_ENABLE:
        {
            value = !!value;
            if ((ic->ic_dpd_support)) {
                if (scn->dpdenable == CLI_DPD_CMD_INPROGRES) {
                    qdf_err("Previous command is in progress");
                    break;
                }
                if (scn->dpdenable == (u_int8_t)value) {
                    qdf_err("dpd_enable already in same state");
                    break;
                }
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_dpd_enable,
                                               value);
                if (retval == EOK) {
                    if (value)
                        scn->dpdenable = CLI_DPD_CMD_INPROGRES;
                    else
                        scn->dpdenable = (u_int8_t)value;
                }
            } else {
                qdf_err("dpd_support feature not enabled !!");
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_ARPDHCP_AC_OVERRIDE:
        {
            if ((WME_AC_BE <= value) && (value <= WME_AC_VO)) {
                scn->arp_override = value;
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_arp_ac_override,
                                               value);
            } else {
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_IGMPMLD_OVERRIDE:
            if ((0 == value) || (value == 1)) {
                scn->igmpmld_override = value;
                val.cdp_pdev_param_igmpmld_override = value;
                cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id,
                                        CDP_CONFIG_IGMPMLD_OVERRIDE, val);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                if (ic->nss_radio_ops)
                    ic->nss_radio_ops->ic_nss_ol_set_igmpmld_override_tos(scn);
#endif
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_igmpmld_override,
                                               value);
            } else {
                retval = -EINVAL;
            }
        break;
        case OL_ATH_PARAM_IGMPMLD_TID:
        if ((0 <= value) && (value <= 7)) {
            scn->igmpmld_tid = value;
            val.cdp_pdev_param_igmpmld_tid = value;
            cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id, CDP_CONFIG_IGMPMLD_TID, val);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                if (ic->nss_radio_ops)
                    ic->nss_radio_ops->ic_nss_ol_set_igmpmld_override_tos(scn);
#endif
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_igmpmld_tid,
                                               value);
            } else {
                retval = -EINVAL;
            }
        break;
        case OL_ATH_PARAM_ANI_ENABLE:
        {
            if (value <= 1) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_ani_enable,
                                               value);
            } else {
                retval = -EINVAL;
            }

            if (retval == EOK) {
                if (!value)
                    scn->is_ani_enable = false;
                else
                    scn->is_ani_enable = true;
            }
        }
        break;
        case OL_ATH_PARAM_ANI_POLL_PERIOD:
        {
            if (value > 0) {
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_ani_poll_period,
                                             value);
            } else {
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_ANI_LISTEN_PERIOD:
        {
            if (value > 0) {
                return ol_ath_pdev_set_param(scn->sc_pdev,
                        wmi_pdev_param_ani_listen_period, value);
            } else {
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_ANI_OFDM_LEVEL:
        {
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_ani_ofdm_level, value);
        }
        break;
        case OL_ATH_PARAM_ANI_CCK_LEVEL:
        {
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_ani_cck_level, value);
        }
        break;
        case OL_ATH_PARAM_BURST_DUR:
        {
            if (!wmi_service_enabled(wmi_handle, wmi_service_burst)) {
                qdf_err("Target does not support burst_dur");
                return -EINVAL;
            }

            /* In case of Lithium based targets, value = 0 is allowed for
             * burst_dur, whereas for default case, minimum value is 1 and
             * should return error if value  = 0.
             */
            if ((value >= ic->ic_burst_min) && (value <= 8192)) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_burst_dur, value);
                if (retval == EOK)
                    scn->burst_dur = (u_int16_t)value;
            } else {
                retval = -EINVAL;
            }
        }
        break;

        case OL_ATH_PARAM_BURST_ENABLE:
        {
            if (!wmi_service_enabled(wmi_handle, wmi_service_burst)) {
                qdf_err("Target does not support burst command");
                return -EINVAL;
            }

            if ((value == 0) || (value == 1))
                retval = ol_ath_pdev_set_burst(scn, value);
            else
                retval = -EINVAL;
        }
        break;

#define CCA_THRESHOLD_LIMIT_UPPER  -11
#define CCA_THRESHOLD_LIMIT_LOWER  -94
        case OL_ATH_PARAM_CCA_THRESHOLD:
        {
            if ((int32_t)value > CCA_THRESHOLD_LIMIT_UPPER)
                value = CCA_THRESHOLD_LIMIT_UPPER;
            else if ((int32_t)value < CCA_THRESHOLD_LIMIT_LOWER)
                value = CCA_THRESHOLD_LIMIT_LOWER;

            if (value) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_cca_threshold,
                                               value);
                if (retval == EOK)
                    scn->cca_threshold = (int32_t)value;
            } else {
                retval = -EINVAL;
            }
        }
        break;

        case OL_ATH_PARAM_DCS_WIDEBAND_POLICY:
            {
                if ((value < 0) ||
                    (value >= DCS_WIDEBAND_POLICY_INVALID)) {
                    qdf_err("Invalid wideband policy setting");
                    retval = -EINVAL;
                } else if ((value == DCS_WIDEBAND_POLICY_INTERBAND) &&
                           !ic->ic_wideband_csa_support) {
                    qdf_err("Interband DCS wideband policy not supported");
                    retval = -EINVAL;
                } else {
                    qdf_info("Setting DCS wideband policy to %d", value);
                    scn->scn_dcs.dcs_wideband_policy = value;
                }
            }
        break;

        case OL_ATH_PARAM_DCS:
            {
                value &= CAP_DCS_MASK;
                if ((value & CAP_DCS_WLANIM) && (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))) {
                    qdf_info("Disabling DCS-WLANIM for 11G mode\n");
                    value &= (~CAP_DCS_WLANIM);
                }

                /*
                 * Don't enable AWGN detection if not supported by FW
                 */
                if (value & CAP_DCS_AWGNIM) {
                    ol_ath_ctrl_dcsawgn(ic, &value, true);
                }

                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) {
                    retval = EOK;
                    break;
                }
                /* if already enabled and run state is not running, more
                 * likely that channel change is in progress, do not let
                 * user modify the current status
                 */
                if ((OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable))  &&
                    !(OL_IS_DCS_RUNNING(scn->scn_dcs.dcs_enable)) &&
                    ic->cw_inter_found) {
                    retval = EINVAL;
                    break;
                }

                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_dcs, value);

                /*
                 * we do not expect this to fail, if failed, eventually
                 * target and host may not be at agreement. Otherway is
                 * to keep it in same old state.
                 */
                if (EOK == retval) {
                    scn->scn_dcs.dcs_enable = value;
                    qdf_info("DCS: dcs enable value %d return value %d",
                             value, retval);
                } else {
                    qdf_err("DCS: target command fail, setting return value %d",
                            retval);
                }
                (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) ? (OL_ATH_DCS_SET_RUNSTATE(scn->scn_dcs.dcs_enable)) :
                                        (OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable));
            }
            break;
        case OL_ATH_PARAM_DCS_RANDOM_CHAN_EN:
                ol_ath_set_dcs_param(ic, OL_ATH_DCS_PARAM_RANDOM_CHAN_EN, value);
                break;
        case OL_ATH_PARAM_DCS_CSA_TBTT:
		ol_ath_set_dcs_param(ic, OL_ATH_DCS_PARAM_CSA_TBTT, value);
                break;
        case OL_ATH_PARAM_DCS_SIM:
            switch (value) {
            case CAP_DCS_CWIM: /* cw interferecne*/
                if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & CAP_DCS_CWIM) {
                    ol_ath_dcs_generic_interference_handler(scn, NULL, value);
                }
                break;
            case CAP_DCS_WLANIM: /* wlan interference stats*/
                if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & CAP_DCS_WLANIM) {
                    ol_ath_dcs_generic_interference_handler(scn, NULL, value);
                }
                break;
            case CAP_DCS_AWGNIM: /* AWGN interference */
                if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & CAP_DCS_AWGNIM) {
                    ol_ath_dcs_generic_interference_handler(scn, NULL, value);
                }
                break;
            default:
                break;
            }
            break;
        case OL_ATH_PARAM_DCS_COCH_THR:
            scn->scn_dcs.coch_intr_thresh = value;
            break;
        case OL_ATH_PARAM_DCS_TXERR_THR:
            scn->scn_dcs.tx_err_thresh = value;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_THR:
            scn->scn_dcs.phy_err_threshold = value;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_PENALTY:
            scn->scn_dcs.phy_err_penalty = value;         /* phy error penalty*/
            break;
        case OL_ATH_PARAM_DCS_RADAR_ERR_THR:
            scn->scn_dcs.radar_err_threshold = value;
            break;
        case OL_ATH_PARAM_DCS_USERMAX_CU_THR:
            scn->scn_dcs.user_max_cu = value;             /* tx_cu + rx_cu */
            break;
        case OL_ATH_PARAM_DCS_INTR_DETECT_THR:
            scn->scn_dcs.intr_detection_threshold = value;
            break;
        case OL_ATH_PARAM_DCS_SAMPLE_WINDOW:
            scn->scn_dcs.intr_detection_window = value;
            break;
        case OL_ATH_PARAM_DCS_RE_ENABLE_TIMER:
            if (value < DCS_ENABLE_TIME_MIN || value > DCS_ENABLE_TIME_MAX) {
                qdf_info("DCS re enable timer should be in between"
                              "%d and %d\n", DCS_ENABLE_TIME_MIN, DCS_ENABLE_TIME_MAX);
                return -EINVAL;
            }
            scn->scn_dcs.dcs_re_enable_time = value;
            break;
        case OL_ATH_PARAM_DCS_DEBUG:
            if (value < 0 || value > 2) {
                qdf_info("0-disable, 1-critical 2-all, %d-not valid option\n", value);
                return -EINVAL;
            }
            scn->scn_dcs.dcs_debug = value;
            break;

        case OL_ATH_PARAM_DYN_TX_CHAINMASK:
            /****************************************
             *Value definition:
             * bit 0        dynamic TXCHAIN
             * bit 1        single TXCHAIN
             * bit 2        single TXCHAIN for ctrl frames
             * For bit 0-1, if value =
             * 0x1  ==>   Dyntxchain enabled,  single_txchain disabled
             * 0x2  ==>   Dyntxchain disabled, single_txchain enabled
             * 0x3  ==>   Both enabled
             * 0x0  ==>   Both disabled
             *
             * bit 3-7      reserved
             * bit 8-11     single txchain mask, only valid if bit 1 set
             *
             * For bit 8-11, the single txchain mask for this radio,
             * only valid if single_txchain enabled, by setting bit 1.
             * Single txchain mask need to be updated when txchainmask,
             * is changed, e.g. 4x4(0xf) ==> 3x3(0x7)
             ****************************************/
#define DYN_TXCHAIN         0x1
#define SINGLE_TXCHAIN      0x2
#define SINGLE_TXCHAIN_CTL  0x4
            if( (value & SINGLE_TXCHAIN) ||
                     (value & SINGLE_TXCHAIN_CTL) ){
                value &= 0xf07;
            } else{
                value &= 0x1;
            }

            if (scn->dtcs != value) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_dyntxchain,
                                               value);
                if (retval == EOK)
                    scn->dtcs = value;
            }
        break;
#if QCA_SUPPORT_SON
		case OL_ATH_PARAM_BUFF_THRESH:
			thresh = value;
			son_ald_record_set_buff_lvl(soc->psoc_obj, thresh);
			break;
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
		case OL_ATH_PARAM_DROP_STA_QUERY:
			ic->ic_dropstaquery = !!value;
			break;
		case OL_ATH_PARAM_BLK_REPORT_FLOOD:
			ic->ic_blkreportflood = !!value;
			break;
#endif

        case OL_ATH_PARAM_VOW_EXT_STATS:
            {
                scn->vow_extstats = value;
            }
            break;

        case OL_ATH_PARAM_LTR_ENABLE:
            param_id = wmi_pdev_param_ltr_enable;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_BE:
            param_id = wmi_pdev_param_ltr_ac_latency_be;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_BK:
            param_id = wmi_pdev_param_ltr_ac_latency_bk;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_VI:
            param_id = wmi_pdev_param_ltr_ac_latency_vi;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_VO:
            param_id = wmi_pdev_param_ltr_ac_latency_vo;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_TIMEOUT:
            param_id = wmi_pdev_param_ltr_ac_latency_timeout;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_TX_ACTIVITY_TIMEOUT:
            param_id = wmi_pdev_param_ltr_tx_activity_timeout;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_SLEEP_OVERRIDE:
            param_id = wmi_pdev_param_ltr_sleep_override;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_RX_OVERRIDE:
            param_id = wmi_pdev_param_ltr_rx_override;
            goto low_power_config;
        case OL_ATH_PARAM_L1SS_ENABLE:
            param_id = wmi_pdev_param_l1ss_enable;
            goto low_power_config;
        case OL_ATH_PARAM_DSLEEP_ENABLE:
            param_id = wmi_pdev_param_dsleep_enable;
            goto low_power_config;
low_power_config:
            retval = ol_ath_pdev_set_param(scn->sc_pdev, param_id, value);
        case OL_ATH_PARAM_ACS_CTRLFLAG:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_CTRLFLAG , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_ENABLE_BK_SCANTIMEREN:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_ENABLE_BK_SCANTIMER , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_CBS:
            if (ic->ic_cbs) {
                ieee80211_cbs_set_param(ic->ic_cbs, IEEE80211_CBS_ENABLE , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_CBS_DWELL_SPLIT_TIME:
            if (ic->ic_cbs) {
                ieee80211_cbs_set_param(ic->ic_cbs, IEEE80211_CBS_DWELL_SPLIT_TIME , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_CBS_DWELL_REST_TIME:
            if (ic->ic_cbs) {
                ieee80211_cbs_set_param(ic->ic_cbs, IEEE80211_CBS_DWELL_REST_TIME , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_CBS_REST_TIME:
            if (ic->ic_cbs) {
                ieee80211_cbs_set_param(ic->ic_cbs, IEEE80211_CBS_REST_TIME , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_CBS_WAIT_TIME:
            if (ic->ic_cbs) {
                ieee80211_cbs_set_param(ic->ic_cbs, IEEE80211_CBS_WAIT_TIME , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_CBS_CSA:
            if (ic->ic_cbs) {
                ieee80211_cbs_set_param(ic->ic_cbs, IEEE80211_CBS_CSA_ENABLE , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_SCANTIME:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_SCANTIME , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_SNRVAR:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_SNRVAR , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_CHAN_EFFICIENCY_VAR:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_CHAN_EFFICIENCY_VAR , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_CHLOADVAR:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_CHLOADVAR , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_SRLOADVAR:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_SRLOADVAR , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_LIMITEDOBSS:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_LIMITEDOBSS , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_DEBUGTRACE:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_DEBUGTRACE , *(int *)buff);
            }
             break;
#if ATH_CHANNEL_BLOCKING
        case OL_ATH_PARAM_ACS_BLOCK_MODE:
            if (ic->ic_acs) {
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_BLOCK_MODE , *(int *)buff);
            }
            break;
#endif
        case OL_ATH_PARAM_RESET_OL_STATS:
            ol_ath_reset_vap_stat(ic);
            break;
#if ATH_RX_LOOPLIMIT_TIMER
        case OL_ATH_PARAM_LOOPLIMIT_NUM:
            if (*(int *)buff > 0)
                scn->rx_looplimit_timeout = *(int *)buff;
            break;
#endif
#define ANTENNA_GAIN_2G_MASK    0x0
#define ANTENNA_GAIN_5G_MASK    0x8000
        case OL_ATH_PARAM_ANTENNA_GAIN_2G:
            if (value >= 0 && value <= 30) {
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_antenna_gain,
                                             value | ANTENNA_GAIN_2G_MASK);
            } else {
                retval = -EINVAL;
            }
            break;
        case OL_ATH_PARAM_ANTENNA_GAIN_5G:
            if (value >= 0 && value <= 30) {
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_antenna_gain,
                                             value | ANTENNA_GAIN_5G_MASK);
            } else {
                retval = -EINVAL;
            }
            break;
        case OL_ATH_PARAM_RX_FILTER:
            if (ic->ic_set_rxfilter)
                ic->ic_set_rxfilter(ic->ic_pdev_obj, value);
            else
                retval = -EINVAL;
            break;
       case OL_ATH_PARAM_SET_FW_HANG_ID:
            ol_ath_set_fw_hang(pdev_wmi_handle, value);
            break;
       case OL_ATH_PARAM_FW_RECOVERY_ID:
	    ol_ath_set_fw_recovery(scn, value);
	    break;
#ifdef CE_TASKLET_DEBUG_ENABLE
       case OL_ATH_PARAM_ENABLE_CE_LATENCY_STATS:
                ol_ath_enable_ce_latency_stats(scn->soc, !!value);
            break;
#endif
       case OL_ATH_PARAM_FW_DUMP_NO_HOST_CRASH:
            if (value == 1){
                /* Do not crash host when target assert happened */
                /* By default, host will crash when target assert happened */
                scn->soc->sc_dump_opts |= FW_DUMP_NO_HOST_CRASH;
            }else{
                scn->soc->sc_dump_opts &= ~FW_DUMP_NO_HOST_CRASH;
            }
            break;
       case OL_ATH_PARAM_DISABLE_DFS:
            {
                if (!value)
                    scn->sc_is_blockdfs_set = false;
                else
                    scn->sc_is_blockdfs_set = true;
            }
            break;
        case OL_ATH_PARAM_QBOOST:
            {
		        if (!ic->ic_qboost_support)
                    return -EINVAL;
                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == scn->scn_qboost_enable) {
                    retval = EOK;
                    break;
                }

                    scn->scn_qboost_enable = value;
                    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                        qboost_config(tmp_vap, tmp_vap->iv_bss, scn->scn_qboost_enable);
                    }

                    qdf_info("QBOOST: %s qboost value %d\n", __func__, value);
            }
            break;
        case OL_ATH_PARAM_SIFS_FRMTYPE:
            {
		        if (!ic->ic_sifs_frame_support)
                    return -EINVAL;
                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == scn->scn_sifs_frmtype) {
                    retval = EOK;
                    break;
                }

                    scn->scn_sifs_frmtype = value;

                    qdf_info("SIFS RESP FRMTYPE: %s SIFS  value %d\n", __func__, value);
            }
            break;
        case OL_ATH_PARAM_SIFS_UAPSD:
            {
		        if (!ic->ic_sifs_frame_support)
                    return -EINVAL;
                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == scn->scn_sifs_uapsd) {
                    retval = EOK;
                    break;
                }

                    scn->scn_sifs_uapsd = value;

                    qdf_info("SIFS RESP UAPSD: %s SIFS  value %d\n", __func__, value);
            }
            break;
        case OL_ATH_PARAM_BLOCK_INTERBSS:
        {
            if (!ic->ic_block_interbss_support)
                return -EINVAL;

            if (value == scn->scn_block_interbss) {
                retval = EOK;
                break;
            }
            /* send the WMI command to enable and if that is success update the state */
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_block_interbss,
                                           value);
            /*
             * we do not expect this to fail, if failed, eventually
             * target and host may not be in agreement. Otherway is
             * to keep it in same old state.
             */
            if (EOK == retval) {
                scn->scn_block_interbss = value;
                qdf_info("set block_interbss: val %d status %d", value, retval);
            } else {
                qdf_err("set block_interbss: wmi failed. retval = %d", retval);
            }
        }
        break;
        case OL_ATH_PARAM_FW_DISABLE_RESET:
        {
            if (!ic->ic_disable_reset_support)
                return -EINVAL;
            /* value is set to either 1 (enable) or 0 (disable).
             * if value passed is non-zero, convert it to 1 with
             * double negation
             */
            value = !!value;
            if (scn->fw_disable_reset != (u_int8_t)value) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                             wmi_pdev_param_set_disable_reset_cmdid, value);
                if (retval == EOK)
                    scn->fw_disable_reset = (u_int8_t)value;
            }
        }
        break;
        case OL_ATH_PARAM_MSDU_TTL:
        {
#if PEER_FLOW_CONTROL
            enum _dp_param_t dp_param;
#endif
            if (!ic->ic_msdu_ttl_support)
                return -EINVAL;
            /* value is set to 0 (disable) else set msdu_ttl in ms.
             */
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_set_msdu_ttl_cmdid,
                                           value);
            if (retval == EOK)
                qdf_info("set MSDU_TTL: value %d wmi_status %d", value, retval);
            else
                qdf_err("set MSDU_TTL wmi_failed: wmi_status %d", retval);
#if PEER_FLOW_CONTROL
            /* update host msdu ttl */
            dp_param = ol_ath_param_to_dp_param(param);
            cdp_pflow_update_pdev_params(soc_txrx_handle, pdev_id,
                                         dp_param, value, NULL);
#endif
        }
        break;
        case OL_ATH_PARAM_PPDU_DURATION:
        {
            uint16_t ppdu_max_duration = get_max_ppdu_duration(ic);

            if (!ic->ic_ppdu_duration_support)
                return -EINVAL;
            /* Set global PPDU duration in usecs.
             */

            /* In case Lithium based targets, value = 0 is allowed
             * for ppdu_duration, whereas for default case minimum value is 100,
             * should return error if value  = 0.
             */
            if ((value < ic->ic_ppdu_min) || (value > ppdu_max_duration)) {
                qdf_err("Input value should be within %d to %d",
                        ic->ic_ppdu_min, ppdu_max_duration);
                return -EINVAL;
            }

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                 wmi_pdev_param_set_ppdu_duration_cmdid, value);
            if (retval == EOK)
                qdf_info("set PPDU_DURATION: val %d status %d", value, retval);
            else
                qdf_err("set PPDU_DURATION: wmi_failed status %d", retval);
        }
        break;

        case OL_ATH_PARAM_SET_TXBF_SND_PERIOD:
        {
            /* Set global TXBF sounding duration in usecs.
             */
            if (value < 10 || value > 10000)
                return -EINVAL;
            scn->txbf_sound_period = value;
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                 wmi_pdev_param_txbf_sound_period_cmdid, value);
            if (retval == EOK)
                qdf_info("set TXBF_SND_PERIOD: val %d stat %d", value, retval);
            else
                qdf_err("set TXBF_SND_PERIOD: wmi_failed: status %d", retval);
        }
        break;

        case OL_ATH_PARAM_ALLOW_PROMISC:
        {
            if (!ic->ic_promisc_support)
                return -EINVAL;
            /* Set or clear promisc mode.
             */
            if (promisc_is_active(&scn->sc_ic)) {
                qdf_info("Device have an active monitor vap");
                retval = -EINVAL;
            } else if (value == scn->scn_promisc) {
                retval = EOK;
            } else {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                 wmi_pdev_param_set_promisc_mode_cmdid, value);
                if (retval == EOK) {
                    scn->scn_promisc = value;
                    qdf_info("set PROMISC_MODE: val %d stat %d", value, retval);
                } else {
                    qdf_err("set PROMISC_MODE: wmi_failed: status %d", retval);
                }
            }
        }
        break;

        case OL_ATH_PARAM_BURST_MODE:
        {
            if (!ic->ic_burst_mode_support)
                return -EINVAL;
            /* Set global Burst mode data-cts:0 data-ping-pong:1 data-cts-ping-pong:2.
             */
            if (value < 0 || value >= 3) {
                qdf_err("Usage: burst_mode <0:data-cts 1:data-data 2:data-(data/cts)");
                return -EINVAL;
            }

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                 wmi_pdev_param_set_burst_mode_cmdid, value);
            if (retval == EOK)
                qdf_info("set BURST_MODE: val %d wmi_status %d", value, retval);
            else
                qdf_err("set BURST_MODE: wmi_failed: wmi_status %d", retval);
        }
        break;

#if ATH_SUPPORT_WRAP
        case OL_ATH_PARAM_MCAST_BCAST_ECHO:
        {
            /* Set global Burst mode data-cts:0 data-ping-pong:1 data-cts-ping-pong:2.
             */
            if (value < 0 || value > 1) {
                qdf_err("Usage: Mcast Bcast Echo mode usage 0:disable 1:enable");
                return -EINVAL;
            }

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_set_mcast_bcast_echo,
                                           value);
            if (retval == EOK) {
                qdf_info("set Mcast Bcast Echo val %d stat %d", value, retval);
                scn->mcast_bcast_echo = (u_int8_t)value;
            } else {
                qdf_err("set Mcast Bcast Echo mode failed, status %d", retval);
            }
        }
        break;

        case OL_ATH_PARAM_ISOLATION:
            if(value < 0 || value > 1) {
                qdf_err("Usage: wrap_isolation mode usage  <0:disable 1:enable \n");
                return -EINVAL;
            }
#if WLAN_QWRAP_LEGACY
            ic->ic_wrap_com->wc_isolation = value;
#else
            dp_wrap_pdev_set_isolation(ic->ic_pdev_obj, value);
#endif
            qdf_info("Set: Qwrap isolation mode value %d", value);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#if WLAN_QWRAP_LEGACY
            mpsta_vap = ic->ic_mpsta_vap;
#else
            mpsta_vap = wlan_get_vap(dp_wrap_get_mpsta_vdev(ic->ic_pdev_obj));
#endif
            if((value == 1) && mpsta_vap && ic->nss_vops && ic->nss_vops->ic_osif_nss_vdev_qwrap_isolation_enable) {
                osd = (osif_dev *)mpsta_vap->iv_ifp;
                ic->nss_vops->ic_osif_nss_vdev_qwrap_isolation_enable(osd);
                qdf_info("Set: NSS qwrap isolation mode value %d", value);
            }
#endif
	break;
#endif
         case OL_ATH_PARAM_OBSS_SNR_THRESHOLD:
        {
            if (value >= OBSS_SNR_MIN && value <= OBSS_SNR_MAX) {
                ic->obss_snr_threshold = value;
            } else {
                retval = -EINVAL;
            }
        }
        break;
         case OL_ATH_PARAM_OBSS_RX_SNR_THRESHOLD:
        {
            if (value >= OBSS_SNR_MIN && value <= OBSS_SNR_MAX) {
                ic->obss_rx_snr_threshold = value;
            } else {
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_ACS_TX_POWER_OPTION:
        {
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_TX_POWER_OPTION, *(int *)buff);
            }
        }
        break;

        case OL_ATH_PARAM_ACS_2G_ALLCHAN:
        {
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_2G_ALL_CHAN, *(int *)buff);
            }
        }
        break;
        case OL_ATH_PARAM_ACS_CHAN_GRADE_ALGO:
        {
            if (!ol_target_lithium(scn->soc->psoc_obj)) {
                qdf_info("Feature not supported for this target!");
                retval = -EINVAL;
            } else {
                if (ic->ic_acs){
                    ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_CHAN_GRADE_ALGO, *(int *)buff);
                }
            }
        }
        break;
        case OL_ATH_PARAM_ACS_NEAR_RANGE_WEIGHTAGE:
        {
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_OBSS_NEAR_RANGE_WEIGHTAGE, *(int *)buff);
            }
        }
        break;
        case OL_ATH_PARAM_ACS_MID_RANGE_WEIGHTAGE:
        {
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_OBSS_MID_RANGE_WEIGHTAGE, *(int *)buff);
            }
        }
        break;
        case OL_ATH_PARAM_ACS_FAR_RANGE_WEIGHTAGE:
        {
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_OBSS_FAR_RANGE_WEIGHTAGE, *(int *)buff);
            }
        }
        break;
	case OL_ATH_PARAM_ACS_PRECAC_SUPPORT:
        {
            ic->ic_acs_precac_completed_chan_only = *(int *)buff;
        }
        break;
        case OL_ATH_PARAM_ANT_POLARIZATION:
        {
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_ant_plzn, value);
        }
        break;

         case OL_ATH_PARAM_ENABLE_AMSDU:
        {

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_enable_per_tid_amsdu,
                                           value);
            if (retval == EOK) {
                qdf_info("enable AMSDU: value %d wmi_status %d", value, retval);
                scn->scn_amsdu_mask = value;
            } else {
                qdf_err("enable AMSDU: wmi_failed: wmi_status %d", retval);
            }
        }
        break;

        case OL_ATH_PARAM_MAX_CLIENTS_PER_RADIO:
        {
            uint16_t max_clients = 0;

            max_clients = ol_ath_get_num_clients(pdev);

            if (value <= max_clients) {
                ic->ic_num_clients = value;
            } else {
                qdf_info("Range 1-%d clients", max_clients);
                retval = -EINVAL;
                break;
            }
        }
        TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
            if ((tmp_vap->iv_opmode == IEEE80211_M_HOSTAP) &&
                (wlan_vdev_is_up(tmp_vap->vdev_obj) == QDF_STATUS_SUCCESS)) {
                wlan_iterate_station_list(tmp_vap, sta_disassoc, NULL);
            }
        }
        break;

        case OL_ATH_PARAM_ENABLE_AMPDU:
        {
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_enable_per_tid_ampdu,
                                           value);
            if (retval == EOK) {
                qdf_info("enable AMPDU: value %d wmi_status %d", value, retval);
                scn->scn_ampdu_mask = value;
            } else {
                qdf_err("enable AMPDU: wmi_failed: wmi_status %d", retval);
            }
        }
        break;

#if WLAN_CFR_ENABLE
        case OL_ATH_PARAM_PERIODIC_CFR_CAPTURE:
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID) !=
                    QDF_STATUS_SUCCESS) {
                return -1;
            }
            if (value > 1) {
                qdf_info("Use 1/0 to enable/disable the timer\n");
                wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);
                return -EINVAL;
            }

            retval = ucfg_cfr_set_timer(pdev, value);

            wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);
        break;
#endif

       case OL_ATH_PARAM_PRINT_RATE_LIMIT:

        if (value <= 0) {
            retval = -EINVAL;
        } else {
            scn->soc->dbg.print_rate_limit = value;
            qdf_info("Changing rate limit to: %d \n", scn->soc->dbg.print_rate_limit);
        }
        break;

        case OL_ATH_PARAM_PDEV_RESET:
        {
            if ((value > 0) && (value < 6)) {
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_pdev_reset, value);
            } else {
                qdf_info(" Invalid vaue : Use any one of the below values \n"
                    "    TX_FLUSH = 1 \n"
                    "    WARM_RESET = 2 \n"
                    "    COLD_RESET = 3 \n"
                    "    WARM_RESET_RESTORE_CAL = 4 \n"
                    "    COLD_RESET_RESTORE_CAL = 5 \n");
                retval = -EINVAL;
            }
        }
        break;

        case OL_ATH_PARAM_CONSIDER_OBSS_NON_ERP_LONG_SLOT:
        {
            ic->ic_consider_obss_long_slot = !!value;
        }

        break;

        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE0:
        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE1:
        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE2:
        case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE3:
        {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (scn->sc_ic.nss_radio_ops) {
                scn->sc_ic.nss_radio_ops->ic_nss_tx_queue_cfg(scn,
                        (param - OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE0), value);
            }
#endif
        }
        break;

#if PEER_FLOW_CONTROL
         case OL_ATH_PARAM_VIDEO_DELAY_STATS_FC:
         case OL_ATH_PARAM_QFLUSHINTERVAL:
         case OL_ATH_PARAM_TOTAL_Q_SIZE:
         case OL_ATH_PARAM_MIN_THRESHOLD:
         case OL_ATH_PARAM_MAX_Q_LIMIT:
         case OL_ATH_PARAM_MIN_Q_LIMIT:
         case OL_ATH_PARAM_CONG_CTRL_TIMER_INTV:
         case OL_ATH_PARAM_STATS_TIMER_INTV:
         case OL_ATH_PARAM_ROTTING_TIMER_INTV:
         case OL_ATH_PARAM_LATENCY_PROFILE:
         case OL_ATH_PARAM_HOSTQ_DUMP:
         case OL_ATH_PARAM_TIDQ_MAP:
        {
            enum _dp_param_t dp_param = ol_ath_param_to_dp_param(param);
            cdp_pflow_update_pdev_params(soc_txrx_handle, pdev_id,
                                         dp_param, value, NULL);
        }
        break;
#endif
        case OL_ATH_PARAM_DBG_ARP_SRC_ADDR:
        {
            scn->sc_arp_dbg_srcaddr = value;
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_arp_srcaddr,
                                           scn->sc_arp_dbg_srcaddr);
            if (retval != EOK)
                qdf_err("Failed to set ARP DEBUG SRC addr in firmware");
        }
        break;

        case OL_ATH_PARAM_DBG_ARP_DST_ADDR:
        {
            scn->sc_arp_dbg_dstaddr = value;
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_arp_dstaddr,
                                           scn->sc_arp_dbg_dstaddr);
            if (retval != EOK)
                qdf_err("Failed to set ARP DEBUG DEST addr in firmware");
        }
        break;

        case OL_ATH_PARAM_ARP_DBG_CONF:
        {
#define ARP_RESET 0xff000000
            if (value & ARP_RESET) {
                /* Reset stats */
                scn->sc_tx_arp_req_count = 0;
                scn->sc_rx_arp_req_count = 0;
            } else {
                scn->sc_arp_dbg_conf = value;
                val.cdp_pdev_param_arp_dbg_conf = value;
                cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id, CDP_CONFIG_ARP_DBG_CONF, val);
            }
#undef ARP_RESET
        }
        break;
            /* Disable AMSDU for Station vap */
        case OL_ATH_PARAM_DISABLE_STA_VAP_AMSDU:
        {
            ic->ic_sta_vap_amsdu_disable = value;
        }
        break;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        case OL_ATH_PARAM_STADFS_ENABLE:
            if(!value) {
                ieee80211com_clear_cap_ext(ic,IEEE80211_CEXT_STADFS);
            } else {
                ieee80211com_set_cap_ext(ic,IEEE80211_CEXT_STADFS);
            }

            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                    QDF_STATUS_SUCCESS) {
                return -1;
            }

            OS_MEMZERO(&vap_opmode_count,
                       sizeof(struct ieee80211_vap_opmode_count));

            if (!dfs_rx_ops || !dfs_tx_ops) {
                qdf_err("dfs tx ops or rx ops is null");
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                return -1;
            }

            if (dfs_rx_ops->dfs_is_stadfs_enabled)
                prev_stadfs_en = dfs_rx_ops->dfs_is_stadfs_enabled(pdev);

            if (dfs_rx_ops->dfs_enable_stadfs)
                dfs_rx_ops->dfs_enable_stadfs(pdev, !!value);

            if (dfs_rx_ops->dfs_is_stadfs_enabled)
                cur_stadfs_en = dfs_rx_ops->dfs_is_stadfs_enabled(pdev);

            /** Even though the user tries to enable STA DFS, it will not
              * be enabled if the country is non ETSI; so value is not
              * always same as cur_stadfs_en.
              */
            if (prev_stadfs_en == cur_stadfs_en) {
                qdf_err("No change in STA DFS Enable value");
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                break;
            }

            ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);

            /* For fulloffload, radar detection for STA DFS is controlled in the
             * FW. Enabling and disabling the STA DFS is done through vdev_start
             * WMI command and done only for STA only mode. Therefore, restart
             * the VAPs. */
            if (dfs_tx_ops->dfs_is_tgt_offload(psoc)
                && vap_opmode_count.total_vaps
                && (vap_opmode_count.sta_count == vap_opmode_count.total_vaps))
                osif_restart_for_config(ic, NULL, NULL);

            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            break;
#endif
        case OL_ATH_PARAM_CHANSWITCH_OPTIONS:
            ic->ic_chanswitch_flags = (*(int *)buff);
            /* When TxCSA is set to 1, Repeater CAC(IEEE80211_CSH_OPT_CAC_APUP_BYSTA)
             * will be forced to 1. Because, the TXCSA is done by changing channel in
             * the beacon update function(ieee80211_beacon_update) and AP VAPs change
             * the channel, if the new channel is DFS then AP VAPs do CAC and STA VAP
             * has to synchronize with the AP VAPS' CAC.
             */
            if (IEEE80211_IS_CSH_CSA_APUP_BYSTA_ENABLED(ic)) {
                IEEE80211_CSH_CAC_APUP_BYSTA_ENABLE(ic);
                qdf_info("%s: When TXCSA is set to 1, Repeater CAC is forced to 1", __func__);
            }
            break;
#if ATH_SUPPORT_DFS
        case OL_ATH_PARAM_BW_REDUCE:
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_bw_reduction) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_set_bw_reduction(pdev, (bool)value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
            break;
#endif
        case OL_ATH_PARAM_NO_BACKHAUL_RADIO:
            if(value != 1) {
                qdf_info("Value should be given as 1 to set no backhaul radio");
                retval = -EINVAL;
                break;
            }

            if(ic->ic_nobackhaul_radio == value) {
                qdf_info("primary radio is set already for this radio");
                break;
            }
            ic->ic_nobackhaul_radio = value;

#if DBDC_REPEATER_SUPPORT
            if (ic->ic_wiphy) {
                qca_multi_link_add_no_backhaul_radio(ic->ic_wiphy);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (ic->nss_radio_ops)
                ic->nss_radio_ops->ic_nss_ol_set_dbdc_no_backhaul_radio(ic, value);
#endif
            }
#endif

            break;
        case OL_ATH_PARAM_HE_MBSSID_CTRL_FRAME_CONFIG:
            if(!is_mbssid_enabled) {
                qdf_err("MBSSID Ctrl frame setting is disllowed when MBSSID feature is disabled");
                retval = -EINVAL;
                break;
            }

            if(value > IEEE80211_MBSSID_CTRL_FRAME_MAX_VAL) {
                qdf_err("Invalid input: 0x%x\n"
                        "MBSSID Control frame config bit interpretation:\n"
                        "B0: Basic Trigger setting\n"
                        "B1: BSR Trigger setting\n"
                        "B2: MU RTS setting\n"
                        "B3-B31: Reserved\n", value);
                retval = -EINVAL;
                break;
            }

            if (ol_ath_pdev_set_param(scn->sc_pdev,
                                      wmi_pdev_param_enable_mbssid_ctrl_frame,
                                      value) != EOK) {
                qdf_err("HE MBSSID Basic Trigger setting WMI failed");
                retval = -EINVAL;
            } else {
                ic->ic_he_mbssid_ctrl_frame_config = value;
                qdf_info("MBSSID Control frame config: 0x%x\n"
                        "Basic Trigger setting: %s\n"
                        "BSR Trigger setting: %s\n"
                        "MU RTS setting: %s",
                        value,
                        (value & IEEE80211_MBSSID_BASIC_TRIG_MASK) ? "ENABLED" : "DISABLED",
                        (value & IEEE80211_MBSSID_BSR_TRIG_MASK) ? "ENABLED" : "DISABLED",
                        (value & IEEE80211_MBSSID_MU_RTS_MASK) ? "ENABLED" : "DISABLED");
            }
            break;
#ifdef QCA_CBT_INSTRUMENTATION
        case OL_ATH_PARAM_FUNC_CALL_MAP:
            if (value == 1) {
                char *cc_buf = qdf_mem_malloc(QDF_FUNCTION_CALL_MAP_BUF_LEN);
                qdf_err("\n\nFunction call map dump start");
                qdf_get_func_call_map(cc_buf);
                qdf_trace_hex_dump(QDF_MODULE_ID_ANY,
                    QDF_TRACE_LEVEL_ERROR, cc_buf, QDF_FUNCTION_CALL_MAP_BUF_LEN);
                qdf_err("Function call map dump end\n\n");
                qdf_mem_free(cc_buf);
            } else if (value == 0) {
                qdf_clear_func_call_map();
                qdf_err("Function call map clear\n\n");
            } else {
                qdf_info("Usage: iwpriv wifiX get_call_map 0/1");
                return -EINVAL;
            }
            break;
#endif
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_PRIMARY_RADIO:
            if(value != 1) {
                qdf_info("Value should be given as 1 to set primary radio");
                retval = -EINVAL;
                break;
            }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (ic->nss_radio_ops) {
                ic->nss_radio_ops->ic_nss_ol_set_primary_radio(scn, ic->ic_primary_radio);
            }
#endif

            if (ic->ic_wiphy) {
                if (value) {
                    qca_multi_link_set_primary_radio(ic->ic_wiphy);
                } else {
                    primary_wiphy = qca_multi_link_get_primary_radio();
                    if (primary_wiphy == ic->ic_wiphy)
                        qca_multi_link_set_primary_radio(NULL);
                }
            }

            val.cdp_pdev_param_primary_radio = value;
            cdp_txrx_set_pdev_param(soc_txrx_handle,
                                    pdev_id,
                                    CDP_CONFIG_PRIMARY_RADIO, val);
            /*
             * For Lithium, because of HW AST issue, primary/secondary radio
             * configuration is needed for AP mode also
             */
            if(!ic->ic_sta_vap && !ol_target_lithium(scn->soc->psoc_obj)) {
                break;
            }

            for (i=0; i < MAX_RADIO_CNT; i++) {
                GLOBAL_IC_LOCK_BH(ic->ic_global_list);
                tmp_ic = ic->ic_global_list->global_ic[i];
                GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
                if (tmp_ic) {
                    spin_lock(&tmp_ic->ic_lock);
                    if (ic == tmp_ic) {
                        /* Setting current radio as primary radio*/
                        qdf_info("Setting primary radio for %s", ether_sprintf(ic->ic_myaddr));
                        tmp_ic->ic_primary_radio = 1;
                    } else {
                        tmp_ic->ic_primary_radio = 0;
                    }
                    dp_lag_pdev_set_primary_radio(tmp_ic->ic_pdev_obj,
                            tmp_ic->ic_primary_radio);
                    spin_unlock(&tmp_ic->ic_lock);
                }
            }
            if (ic->fast_lane) {
                if (ic->fast_lane_ic && !ic->fast_lane_ic->ic_primary_radio) {
                    /*
                     * In Fast lane if any of the fast radios is primary, the other
                     * is also set to primary.
                     */
                    ic->fast_lane_ic->ic_primary_radio = 1;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                    tmp_scn = OL_ATH_SOFTC_NET80211(ic->fast_lane_ic);
                    if (ic->fast_lane_ic->nss_radio_ops) {
                        ic->fast_lane_ic->nss_radio_ops->ic_nss_ol_set_primary_radio(tmp_scn, ic->fast_lane_ic->ic_primary_radio);
                    }
#endif
                }
            }
            wlan_update_radio_priorities(ic);
#if ATH_SUPPORT_WRAP
            osif_set_primary_radio_event(ic);
#endif
            break;
        case OL_ATH_PARAM_DBDC_ENABLE:
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            ic->ic_global_list->dbdc_process_enable = (value) ?1:0;
	    if (value) {
                qca_multi_link_set_dbdc_enable(true);
            } else {
                qca_multi_link_set_dbdc_enable(false);
            }

            if ((value == 0) || ic->ic_global_list->num_stavaps_up > 1) {

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                if (ic->nss_radio_ops) {
                    ic->nss_radio_ops->ic_nss_ol_enable_dbdc_process(ic,
                            (uint32_t)ic->ic_global_list->dbdc_process_enable);
                }
#endif

            }

            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            for (i = 0; i < MAX_RADIO_CNT; i++) {
                tmp_ic = ic->ic_global_list->global_ic[i];
                if (tmp_ic) {
                    tmp_scn = OL_ATH_SOFTC_NET80211(tmp_ic);
                    if (tmp_scn) {
                        spin_lock(&tmp_ic->ic_lock);
                        if (value) {
                            if (tmp_ic->ic_global_list->num_stavaps_up > 1) {
                                if (tmp_ic->nss_radio_ops)
                                    tmp_ic->nss_radio_ops->ic_nss_ol_enable_dbdc_process(tmp_ic, value);
                            }
                        } else {
                            if (tmp_ic->nss_radio_ops)
                                tmp_ic->nss_radio_ops->ic_nss_ol_enable_dbdc_process(tmp_ic, 0);
                        }
                        spin_unlock(&tmp_ic->ic_lock);
                    }
                }
            }
#endif
            break;
        case OL_ATH_PARAM_CLIENT_MCAST:
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            if(value) {
                ic->ic_global_list->force_client_mcast_traffic = 1;
                qca_multi_link_set_force_client_mcast(true);
                qdf_info("Enabling MCAST client traffic to go on corresponding STA VAP\n");
            } else {
                ic->ic_global_list->force_client_mcast_traffic = 0;
                qca_multi_link_set_force_client_mcast(false);
                qdf_info("Disabling MCAST client traffic to go on corresponding STA VAP\n");
            }

            dp_lag_soc_set_force_client_mcast_traffic(ic->ic_pdev_obj,
                    ic->ic_global_list->force_client_mcast_traffic);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            for (i = 0; i < MAX_RADIO_CNT; i++) {
                tmp_ic = ic->ic_global_list->global_ic[i];
                if (tmp_ic) {
                    tmp_scn = OL_ATH_SOFTC_NET80211(tmp_ic);
                    if (tmp_ic->nss_radio_ops) {
                        tmp_ic->nss_radio_ops->ic_nss_ol_set_force_client_mcast_traffic(tmp_ic, ic->ic_global_list->force_client_mcast_traffic);
                    }
                }
            }
#endif
            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            break;
#endif
        case OL_ATH_PARAM_TXPOWER_DBSCALE:
        {
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_txpower_decr_db,
                                           value);
        }
        break;
        case OL_ATH_PARAM_CTL_POWER_SCALE:
        {
            if ((WMI_HOST_TP_SCALE_MAX <= value) &&
                (value <= WMI_HOST_TP_SCALE_MIN)) {
                scn->powerscale = value;
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_cust_txpower_scale,
                                             value);
            } else {
                retval = -EINVAL;
            }
        }
        break;

#ifdef QCA_EMIWAR_80P80_CONFIG_SUPPORT
        case OL_ATH_PARAM_EMIWAR_80P80:
            {
                uint16_t cc;
                uint32_t target_type = lmac_get_tgt_type(scn->soc->psoc_obj);

                if (IS_EMIWAR_80P80_APPLICABLE(target_type)) {
                    if ((value >= EMIWAR_80P80_DISABLE) && (value < EMIWAR_80P80_MAX)) {
                        (scn->sc_ic).ic_emiwar_80p80 = value;
                        qdf_info("Re-applying current country code.\n");
                        cc = ieee80211_getCurrentCountry(ic);
                        retval = wlan_set_countrycode(&scn->sc_ic, NULL,
                                cc, CLIST_NEW_COUNTRY);
                        /*Using set country code for re-usability and non-duplication of INIT code */
                    }
                    else {
                        qdf_info(" Please enter 0:Disable, 1:BandEdge (FC1:5775, and FC2:5210), 2:All FC1>FC2\n");
                        retval = -EINVAL;
                    }
                }
                else {
                    qdf_info("emiwar80p80 not applicable for this chipset \n");

                }
            }
            break;
#endif /*QCA_EMIWAR_80P80_CONFIG_SUPPORT*/
        case OL_ATH_PARAM_BATCHMODE:
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_rx_batchmode, !!value);
            break;
        case OL_ATH_PARAM_PACK_AGGR_DELAY:
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_packet_aggr_delay,
                                         !!value);
            break;
#if UMAC_SUPPORT_ACFG
        case OL_ATH_PARAM_DIAG_ENABLE:
            if (value == 0 || value == 1) {
                if (value && !ic->ic_diag_enable) {
                    acfg_diag_pvt_t *diag = (acfg_diag_pvt_t *)ic->ic_diag_handle;
                    if (diag) {
                        ic->ic_diag_enable = value;
                        OS_SET_TIMER(&diag->diag_timer, 0);
                    }
                }else if (!value) {
                    ic->ic_diag_enable = value;
                }
            } else {
                qdf_info("Please enter 0 or 1.\n");
                retval = -EINVAL;
            }
            break;
#endif /* UMAC_SUPPORT_ACFG */

        case OL_ATH_PARAM_CHAN_STATS_TH:
            ic->ic_chan_stats_th = (value % 100);
            break;

        case OL_ATH_PARAM_PASSIVE_SCAN_ENABLE:
            ic->ic_strict_pscan_enable = !!value;
            break;

        case OL_ATH_MIN_SNR_ENABLE:
            {
                if (value == 0 || value == 1) {
                    if (value)
                        ic->ic_min_snr_enable = true;
                    else
                        ic->ic_min_snr_enable = false;
               } else {
                   qdf_info("Please enter 0 or 1.\n");
                   retval = -EINVAL;
               }
            }
            break;
        case OL_ATH_MIN_SNR:
            {
                int val = *(int *)buff;
                if (val <= 0) {
                    qdf_info("snr should be a positive value.\n");
                    retval = -EINVAL;
                } else if (ic->ic_min_snr_enable)
                    ic->ic_min_snr = val;
                else
                    qdf_info("Cannot set, feature not enabled.\n");
            }
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_DELAY_STAVAP_UP:
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            if(value) {
                ic->ic_global_list->delay_stavap_connection = value;
                qdf_info("Enabling DELAY_STAVAP_UP:%d",value);
            } else {
                ic->ic_global_list->delay_stavap_connection = 0;
                qdf_info("Disabling DELAY_STAVAP_UP");
            }
            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            break;
#endif
        case OL_ATH_BTCOEX_ENABLE:
        {
            int val = !!(*((int *) buff));

            if(wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj,
                                          WLAN_SOC_F_BTCOEX_SUPPORT)) {
                if (ol_ath_pdev_set_param(scn->sc_pdev,
                                          wmi_pdev_param_enable_btcoex,
                                          val) == EOK) {
                    scn->soc->btcoex_enable = val;

                    if (scn->soc->btcoex_enable) {
                        if (scn->soc->btcoex_wl_priority == 0) {
                            scn->soc->btcoex_wl_priority =
                                        WMI_HOST_PDEV_VI_PRIORITY_BIT |
                                        WMI_HOST_PDEV_BEACON_PRIORITY_BIT |
                                        WMI_HOST_PDEV_MGMT_PRIORITY_BIT;

                            if (ol_ath_btcoex_wlan_priority(scn->soc,
                                        scn->soc->btcoex_wl_priority) != EOK) {
                                qdf_err("Assign btcoex_wlan_priority:%d failed",
                                        scn->soc->btcoex_wl_priority);
                                return -ENOMEM;
                            } else {
                                qdf_err("Set btcoex_wlan_priority:%d",
                                        scn->soc->btcoex_wl_priority);
                            }
                        }
                        if (scn->soc->btcoex_duty_cycle &&
                            (scn->soc->btcoex_period <= 0)) {
                            if (ol_ath_btcoex_duty_cycle(scn->soc,
                                                         DEFAULT_PERIOD,
                                                         DEFAULT_WLAN_DURATION)
                                                         != EOK) {
                                qdf_err("Assignign btcoex_period:%d "
                                        "btcoex_duration duration:%d failed",
                                        DEFAULT_PERIOD,DEFAULT_WLAN_DURATION);
                                return -ENOMEM;
                            } else {
                                scn->soc->btcoex_period = DEFAULT_PERIOD;
                                scn->soc->btcoex_duration = DEFAULT_WLAN_DURATION;
                                qdf_info("Set default val btcoex_period:%d "
                                         "btcoex_duration:%d ",
                                         scn->soc->btcoex_period,
                                         scn->soc->btcoex_duration);
                            }
                        }
                    }
                } else {
                    qdf_err("Failed to send enable btcoex cmd:%d ", val);
                    return -ENOMEM;
                }
            } else {
                retval = -EPERM;
            }
        }
        break;
        case OL_ATH_BTCOEX_WL_PRIORITY:
            {
                int val = *((int *) buff);

                if(wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj,
					WLAN_SOC_F_BTCOEX_SUPPORT)) {
                    if (ol_ath_btcoex_wlan_priority(scn->soc,val) == EOK) {
                        scn->soc->btcoex_wl_priority = val;
                    } else {
                        return -ENOMEM;
                    }
                } else {
                    retval = -EPERM;
                }
            }
            break;
        case OL_ATH_PARAM_CAL_VER_CHECK:
            {
                if(wlan_psoc_nif_fw_ext_cap_get(scn->soc->psoc_obj,
                                              WLAN_SOC_CEXT_SW_CAL)) {
                    if(value == 0 || value == 1) {
                        ic->ic_cal_ver_check = value;
                        /* Setting to 0x0 as expected by FW */
                        retval = wmi_send_pdev_caldata_version_check_cmd(pdev_wmi_handle, 0);
                    } else {
                        qdf_info("Enter value 0 or 1. ");
                        retval = -EINVAL;
                    }
                } else {
                    qdf_info(" wmi service to check cal version not supported ");
                }
            }
            break;
        case OL_ATH_PARAM_TID_OVERRIDE_QUEUE_MAPPING:
             val.cdp_pdev_param_tidq_override = value;
             cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id, CDP_TIDQ_OVERRIDE, val);
            break;
        case OL_ATH_PARAM_NO_VLAN:
            ic->ic_no_vlan = !!value;
            break;
        case OL_ATH_PARAM_ATF_LOGGING:
            ic->ic_atf_logging = !!value;
            break;

        case OL_ATH_PARAM_STRICT_DOTH:
            ic->ic_strict_doth  = !!value;
            break;
        case OL_ATH_PARAM_CHANNEL_SWITCH_COUNT:
            ic->ic_chan_switch_cnt = value;
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_SAME_SSID_DISABLE:
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            ic->ic_global_list->same_ssid_disable = (value) ?1:0;
            qdf_info("Same ssid global disable:%d",ic->ic_global_list->same_ssid_disable);
            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            break;
        case OL_ATH_PARAM_DISCONNECTION_TIMEOUT:
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            ic->ic_global_list->disconnect_timeout = value;
            qdf_info("Disconnect_timeout value: %d",value);
            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            break;
        case OL_ATH_PARAM_RECONFIGURATION_TIMEOUT:
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            ic->ic_global_list->reconfiguration_timeout = value;
            qdf_info("Reconfiguration_timeout value:%d",value);
            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            break;
        case OL_ATH_PARAM_ALWAYS_PRIMARY:
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            ic->ic_global_list->always_primary = (value) ?1:0;
            if (value) {
                qca_multi_link_set_always_primary(true);
            } else {
                qca_multi_link_set_always_primary(false);
            }
            dp_lag_soc_set_always_primary(ic->ic_pdev_obj,
                    ic->ic_global_list->always_primary);
            qdf_info("Setting always primary flag as %d ",value);
            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            for (i=0; i < MAX_RADIO_CNT - 1; i++) {
                GLOBAL_IC_LOCK_BH(ic->ic_global_list);
                tmp_ic = ic->ic_global_list->global_ic[i];
                if (tmp_ic) {
                    tmp_scn = OL_ATH_SOFTC_NET80211(tmp_ic);
                    if (tmp_ic->nss_radio_ops)
                        tmp_ic->nss_radio_ops->ic_nss_ol_set_always_primary(tmp_ic, ic->ic_global_list->always_primary);
                }
                GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            }
#endif
            break;
        case OL_ATH_PARAM_FAST_LANE:
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            /*
             * DBDC Fast-Lane is supported in NSS WiFi Offload mode for 807x V1, V2
             * and 601x platforms and not supported in legacy platforms.
             */
            if (scn->nss_radio.nss_rctx) {
                if ((lmac_get_tgt_type(scn->soc->psoc_obj) != TARGET_TYPE_QCA8074) &&
                    (lmac_get_tgt_type(scn->soc->psoc_obj) != TARGET_TYPE_QCA8074V2) &&
                    (lmac_get_tgt_type(scn->soc->psoc_obj) != TARGET_TYPE_QCN9000) &&
                    (lmac_get_tgt_type(scn->soc->psoc_obj) != TARGET_TYPE_QCN6122) &&
                    (lmac_get_tgt_type(scn->soc->psoc_obj) != TARGET_TYPE_QCA5018) &&
                    (lmac_get_tgt_type(scn->soc->psoc_obj) != TARGET_TYPE_QCA6018)) {
                        qdf_info( "fast lane not supported on nss offload ");
                        break;
                    }
            }
#endif

            if (value && (ic->ic_global_list->num_fast_lane_ic > 1)) {
                /* fast lane support allowed only on 2 radios*/
                qdf_info("fast lane support allowed only on 2 radios ");
                retval = -EPERM;
                break;
            }
            if ((ic->fast_lane == 0) && value) {
                GLOBAL_IC_LOCK_BH(ic->ic_global_list);
                ic->ic_global_list->num_fast_lane_ic++;
                GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            }
            if ((ic->fast_lane == 1) && !value) {
                GLOBAL_IC_LOCK_BH(ic->ic_global_list);
                ic->ic_global_list->num_fast_lane_ic--;
                GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
            }
            spin_lock(&ic->ic_lock);
            ic->fast_lane = value ?1:0;
            dp_lag_pdev_set_fast_lane(ic->ic_pdev_obj, ic->fast_lane);

            if (ic->fast_lane) {
                qca_multi_link_add_fastlane_radio(ic->ic_wiphy);
            } else {
                qca_multi_link_remove_fastlane_radio(ic->ic_wiphy);
            }
            spin_unlock(&ic->ic_lock);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            GLOBAL_IC_LOCK_BH(ic->ic_global_list);
            if (ic->nss_radio_ops)
                ic->nss_radio_ops->ic_nss_ol_set_dbdc_fast_lane(ic, value);
            GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
#endif
            qdf_info("Setting fast lane flag as %d for radio:%s",value,ether_sprintf(ic->ic_my_hwaddr));
            if (ic->fast_lane) {
                for (i=0; i < MAX_RADIO_CNT; i++) {
                    GLOBAL_IC_LOCK_BH(ic->ic_global_list);
                    tmp_ic = ic->ic_global_list->global_ic[i];
                    GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
                    if (tmp_ic && (tmp_ic != ic) && tmp_ic->fast_lane) {
                        spin_lock(&tmp_ic->ic_lock);
                        tmp_ic->fast_lane_ic = ic;
                        spin_unlock(&tmp_ic->ic_lock);
                        spin_lock(&ic->ic_lock);
                        ic->fast_lane_ic = tmp_ic;
                        qdf_info("fast lane ic mac:%s",ether_sprintf(ic->fast_lane_ic->ic_my_hwaddr));
                        spin_unlock(&ic->ic_lock);
                        /*
                         * In Fast lane if any of the fast radios is primary, the other
                         * is also set to primary.
                         */
                        if ((tmp_ic->ic_primary_radio) || (ic->ic_primary_radio)) {
                            ic->ic_primary_radio = 1;
                            tmp_ic->ic_primary_radio = 1;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                            tmp_scn = OL_ATH_SOFTC_NET80211(ic);
                            if (ic->nss_radio_ops) {
                                ic->nss_radio_ops->ic_nss_ol_set_primary_radio(tmp_scn, ic->ic_primary_radio);
                            }
                            tmp_scn = OL_ATH_SOFTC_NET80211(tmp_ic);
                            if (tmp_ic->nss_radio_ops) {
                                tmp_ic->nss_radio_ops->ic_nss_ol_set_primary_radio(tmp_scn, tmp_ic->ic_primary_radio);
                            }
#endif
                        }
                    }
                }
            } else {
                fast_lane_ic = ic->fast_lane_ic;
                if (fast_lane_ic) {
                    spin_lock(&fast_lane_ic->ic_lock);
                    fast_lane_ic->fast_lane_ic = NULL;
                    spin_unlock(&fast_lane_ic->ic_lock);
                }
                spin_lock(&ic->ic_lock);
                ic->fast_lane_ic = NULL;
                spin_unlock(&ic->ic_lock);
            }
            qdf_info("num fast lane ic count %d",ic->ic_global_list->num_fast_lane_ic);
            break;
        case OL_ATH_PARAM_PREFERRED_UPLINK:
            if(!ic->ic_sta_vap) {
                qdf_info("Radio not configured on repeater mode");
                retval = -EINVAL;
                break;
            }
            if(value != 1) {
                qdf_info("Value should be given as 1 to set as preferred uplink");
                retval = -EINVAL;
                break;
            }
            for (i=0; i < MAX_RADIO_CNT; i++) {
                GLOBAL_IC_LOCK_BH(ic->ic_global_list);
                tmp_ic = ic->ic_global_list->global_ic[i];
                GLOBAL_IC_UNLOCK_BH(ic->ic_global_list);
                if (tmp_ic) {
                    spin_lock(&tmp_ic->ic_lock);
                    if (ic == tmp_ic) {
                        /* Setting current radio as preferred uplink*/
                        tmp_ic->ic_preferredUplink = 1;
                    } else {
                        tmp_ic->ic_preferredUplink = 0;
                    }
                    spin_unlock(&tmp_ic->ic_lock);
                }
            }
            break;
#endif
        case OL_ATH_PARAM_SECONDARY_OFFSET_IE:
            ic->ic_sec_offsetie = !!value;
            break;
        case OL_ATH_PARAM_WIDE_BAND_SUB_ELEMENT:
            ic->ic_wb_subelem = !!value;
            break;
#if ATH_SUPPORT_DFS && ATH_SUPPORT_ZERO_CAC_DFS
        case OL_ATH_PARAM_PRECAC_ENABLE:
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_precac_enable) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_set_precac_enable(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
            break;
        case OL_ATH_PARAM_PRECAC_TIMEOUT:
            /* Call a function to update the PRECAC Timeout */
            if (dfs_rx_ops && dfs_rx_ops->dfs_override_precac_timeout) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_override_precac_timeout(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
            break;
#ifdef WLAN_DFS_PRECAC_AUTO_CHAN_SUPPORT
        case OL_ATH_PARAM_PRECAC_INTER_CHANNEL:
            /* Call a function to update the PRECAC intermediate channel */
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_precac_intermediate_chan) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                retval = dfs_rx_ops->dfs_set_precac_intermediate_chan(pdev,
								      value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
            break;
#endif

#endif
	case OL_ATH_PARAM_PDEV_TO_REO_DEST:
	    if ((value < cdp_host_reo_dest_ring_1) || (value > cdp_host_reo_dest_ring_4)) {
		qdf_info("reo ring destination value should be between 1 to 4");
		retval = -EINVAL;
		break;
	    }
	    if (cdp_set_pdev_reo_dest(soc_txrx_handle,
				  pdev_id,
				  value) != QDF_STATUS_SUCCESS) {
                retval = -EINVAL;
            }
	    break;
        case OL_ATH_PARAM_DUMP_OBJECTS:
            wlan_objmgr_print_ref_cnts(ic);
            break;

        case OL_ATH_PARAM_MGMT_SNR_THRESHOLD:
            if (value < SNR_MIN || value > SNR_MAX) {
                qdf_info("invalid value: %d, RSSI is between 1-127 ", value);
                return -EINVAL;
            }
            ic->mgmt_rx_snr = value;
            break;

        case OL_ATH_PARAM_EXT_NSS_CAPABLE:
            if (!ic->ic_fw_ext_nss_capable) {
                qdf_info("FW is not Ext NSS Signaling capable");
                return -EINVAL;
            }
            if ((value != 0) && (value != 1)) {
                qdf_info("Valid values 1:Enable 0:Disable");
                return -EINVAL;
            }
            if (value != ic->ic_ext_nss_capable) {
                ic->ic_ext_nss_capable = value;
                if(!ic->ic_ext_nss_capable){
                    TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                               tmp_vap->iv_ext_nss_support = 0;
                    }
                }
                osif_pdev_restart_vaps(ic);
            }
            break;
#if QCN_ESP_IE
        case OL_ATH_PARAM_ESP_PERIODICITY:
            if (value < 0 || value > 5000) {
                qdf_err("Invalid value! Periodicity value should be between 0 and 5000");
                retval = -EINVAL;
            } else {
                /* ESP indication period doesn't need service check to become compatible with legacy firmware. */
                if (ol_ath_pdev_set_param(scn->sc_pdev,
                                          wmi_pdev_param_esp_indication_period,
                                          value) != EOK) {
                    QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                    "%s: ERROR - Param setting failed. Periodicity value 0x%x.\n", __func__, value);
                } else {
                    ic->ic_esp_periodicity = value;
                    ic->ic_esp_flag = 1; /* This is required for updating the beacon packet */
                }
            }
            break;
        case OL_ATH_PARAM_ESP_AIRTIME:
            if (value < 0 || value > 255) {
                qdf_err("Invalid value! Airtime value should be between 0 and 255");
                retval = -EINVAL;
            } else {
                if (wmi_service_enabled(wmi_handle, wmi_service_esp_support)) {
                    if (ol_ath_pdev_set_param(scn->sc_pdev,
                                              wmi_pdev_param_esp_airtime_fraction,
                                              value) != EOK) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                        "%s: ERROR - Param setting failed. Airtime value 0x%x.\n", __func__, value);
                        return -1;
                    }
                }
                ic->ic_esp_air_time_fraction = value;
                ic->ic_esp_flag = 1; /* This is required for updating the beacon packet */
            }
            break;
        case OL_ATH_PARAM_ESP_PPDU_DURATION:
            if (value < 0 || value > 255) {
                qdf_err("Invalid value! PPDU duration target should be between 0 and 255");
                retval = -EINVAL;
            } else {
                if (wmi_service_enabled(wmi_handle, wmi_service_esp_support)) {
                    if (ol_ath_pdev_set_param(scn->sc_pdev,
                                              wmi_pdev_param_esp_ppdu_duration,
                                              value) != EOK) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                        "%s: ERROR - Param setting failed. PPDU duration value 0x%x.\n", __func__, value);
                        return -1;
                    }
                }
                ic->ic_esp_ppdu_duration = value;
                ic->ic_esp_flag = 1; /* This is required for updating the beacon packet */
            }
            break;
        case OL_ATH_PARAM_ESP_BA_WINDOW:
            if (value <= 0 || value > 7) {
                qdf_err("Invalid value! BA window size should be between 1 and 7");
                retval = -EINVAL;
            } else {
                if (wmi_service_enabled(wmi_handle, wmi_service_esp_support)) {
                    if (ol_ath_pdev_set_param(scn->sc_pdev,
                                              wmi_pdev_param_esp_ba_window,
                                              value) != EOK) {
                        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                        "%s: ERROR - Param setting failed. BA window size value 0x%x.\n", __func__, value);
                        return -1;
                    }
                }
                ic->ic_esp_ba_window = value;
                ic->ic_esp_flag = 1; /* This is required for updating the beacon packet */
            }
            break;
#endif /* QCN_ESP_IE */

        case OL_ATH_PARAM_MGMT_PDEV_STATS_TIMER:
            if(value) {
                scn->pdev_stats_timer = value;
            } else {
                scn->is_scn_stats_timer_init = 0;
            }
            break ;

        case OL_ATH_PARAM_ICM_ACTIVE:
            ic->ic_extacs_obj.icm_active = value;
            break;

        case OL_ATH_PARAM_CHAN_INFO:
            qdf_mem_zero(ic->ic_extacs_obj.chan_info, sizeof(struct scan_chan_info)
                         * NUM_MAX_CHANNELS);
            break;

        case OL_ATH_PARAM_TXACKTIMEOUT:
        {
            if (wmi_service_enabled(wmi_handle,wmi_service_ack_timeout)) {
                if (value >= DEFAULT_TX_ACK_TIMEOUT &&
                    value <= MAX_TX_ACK_TIMEOUT) {
                    if (ol_ath_pdev_set_param(scn->sc_pdev,
                                              wmi_pdev_param_tx_ack_timeout,
                                              value) == EOK)
                        scn->tx_ack_timeout = value;
                    else
                        retval = -1;
                }
                else {
                    qdf_err("TX ACK Time-out value should be between 0x40 and 0xFF");
                    retval = -1;
                }
            }
            else {
                qdf_err("TX ACK Timeout Service is not supported");
                retval = -1;
            }
        }
        break;
        case OL_ATH_PARAM_ACS_RANK:
            if (ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_RANK , *(int *)buff);
            }
            break;

#ifdef OL_ATH_SMART_LOGGING
        case OL_ATH_PARAM_SMARTLOG_ENABLE:
            if (scn->soc->ol_if_ops->enable_smart_log)
                scn->soc->ol_if_ops->enable_smart_log(scn, value);
            break;

        case OL_ATH_PARAM_SMARTLOG_FATAL_EVENT:
            if (scn->soc->ol_if_ops->send_fatal_cmd)
                scn->soc->ol_if_ops->send_fatal_cmd(scn, value, 0);
            break;

        case OL_ATH_PARAM_SMARTLOG_SKB_SZ:
            ic->smart_log_skb_sz = value;
            break;

        case OL_ATH_PARAM_SMARTLOG_P1PINGFAIL:
            if ((value != 0) && (value != 1)) {
                qdf_info("Invalid value. Value for P1 ping failure smart "
                         "logging start/stop can be 1 (start) or 0 (stop). "
                         "Smart logging feature should be enabled in order to "
                         "start P1 ping failure smart logging.");
                retval = -EINVAL;
            } else if (value == 1) {
                if (!ic->smart_logging_p1pingfail_started) {
                    if (!ic->smart_logging) {
                        qdf_info("Smart logging feature not enabled. Cannot "
                                 "start P1 ping failure smart logging.");
                        retval = -EINVAL;
                    } else {
                        if (scn->soc->ol_if_ops->send_fatal_cmd) {
                            if ((scn->soc->ol_if_ops->send_fatal_cmd(scn,
                                    WMI_HOST_FATAL_CONDITION_CONNECTION_ISSUE,
                                    WMI_HOST_FATAL_SUBTYPE_P1_PING_FAILURE_START_DEBUG))
                                != QDF_STATUS_SUCCESS) {
                                qdf_err("Error: Could not successfully send "
                                        "command to start P1 ping failure "
                                        "logging. Smart logging or rest of "
                                        "system may no longer function as "
                                        "expected. Investigate!");
                                qdf_err("Preserving P1 ping failure status as "
                                        "stopped within host. This may or may "
                                        "not be consistent with FW state due "
                                        "to command send failure.");
                                retval = -EIO;
                            } else {
                                ic->smart_logging_p1pingfail_started = true;
                            }
                        } else {
                            qdf_info("No functionality available for sending "
                                     "fatal condition related command.");
                            retval = -EINVAL;
                        }
                    }
                } else {
                    qdf_info("P1 ping failure smart logging already started. "
                             "Ignoring.");
                }
            } else {
                 if (ic->smart_logging_p1pingfail_started) {
                    if (scn->soc->ol_if_ops->send_fatal_cmd) {
                        if ((scn->soc->ol_if_ops->send_fatal_cmd(scn,
                                WMI_HOST_FATAL_CONDITION_CONNECTION_ISSUE,
                                WMI_HOST_FATAL_SUBTYPE_P1_PING_FAILURE_STOP_DEBUG))
                             != QDF_STATUS_SUCCESS) {
                            qdf_err("Error: Could not successfully send "
                                    "command to stop P1 ping failure logging. "
                                    "Smart logging or rest of system may no "
                                    "longer function as expected. "
                                    "Investigate!");
                            qdf_err("Marking P1 ping failure as stopped "
                                    "within host. This may not be consistent "
                                    "with FW state due to command send "
                                    "failure.");
                            retval = -EIO;
                        }

                        ic->smart_logging_p1pingfail_started = false;
                    } else {
                        /*
                         * We should not have been able to start P1 ping failure
                         * logging if scn->soc->ol_if_ops->send_fatal_cmd were
                         * unavailable. This indicates a likely corruption. So
                         * we assert here.
                         */
                        qdf_err("No function registered for sending fatal "
                                "condition related command though P1 ping "
                                "failure logging is already enabled. "
                                "Asserting. Investigate!");
                        qdf_assert_always(0);
                    }
                } else {
                    qdf_info("P1 ping failure smart logging already stopped. "
                             "Ignoring.");
                }
            }
            break;
#endif /* OL_ATH_SMART_LOGGING */

        case OL_ATH_PARAM_TXCHAINSOFT:
            if (scn->soft_chain != value) {
                if (value > tgt_cfg->tx_chain_mask) {
                    qdf_info("ERROR - value 0x%x is greater than supported chainmask 0x%x",
                              value, tgt_cfg->tx_chain_mask);
                    retval = -EINVAL;
                } else {
                    if (ol_ath_pdev_set_param(scn->sc_pdev,
                                              wmi_pdev_param_soft_tx_chain_mask,
                                              value) != EOK)
                        qdf_err("couldnt set soft chainmask value 0x%x", value);
                    else
                        scn->soft_chain = value;
                }
            }
            break;

        case OL_ATH_PARAM_WIDE_BAND_SCAN:
            if (ic->ic_widebw_scan == !!value) {
                qdf_info("same wide band scan config %d", value);
            } else {
                ic->ic_widebw_scan = !!value;
                wlan_scan_update_wide_band_scan_config(ic);
                /* update scan channel list */
                wlan_scan_update_channel_list(ic);
            }
            break;
#if ATH_PARAMETER_API
         case OL_ATH_PARAM_PAPI_ENABLE:
             if (value == 0 || value == 1) {
                 ic->ic_papi_enable = value;
             } else {
                 QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO,
                                "Value should be either 0 or 1\n");
                 return (-1);
             }
             break;
#endif
        case OL_ATH_PARAM_NF_THRESH:
            if (!ic->ic_acs) {
                qdf_info("Failed to set ACS NF Threshold");
                return -1;
            }

            retval = ieee80211_acs_set_param(ic->ic_acs,
                                             IEEE80211_ACS_NF_THRESH,
                                             *(int *)buff);
            break;

        case OL_ATH_PARAM_DUMP_TARGET:
            if(ol_target_lithium(scn->soc->psoc_obj)) {
                qdf_info("Feature not supported for this target!");
                retval = -EINVAL;
            } else {
		if (soc->ol_if_ops->dump_target)
			soc->ol_if_ops->dump_target(scn->soc);
            }
        break;

        case OL_ATH_PARAM_CCK_TX_ENABLE:
        if ((lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_QCA8074) ||
                (lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_QCA8074V2) ||
                (lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_QCN9000) ||
                (lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_QCN6122) ||
                (lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_QCA5018) ||
                (lmac_get_tgt_type(scn->soc->psoc_obj) == TARGET_TYPE_QCA6018)) {

                if (!reg_cap) {
                    qdf_err("reg_cap NULL, unable to process further, Investigate");
                    retval = -1;
                } else {
                    if (reg_cap[pdev_idx].wireless_modes & WIRELESS_MODES_2G) {
                        if (ic->cck_tx_enable != value) {
                            if (ol_ath_pdev_set_param(scn->sc_pdev,
                                    wmi_pdev_param_cck_tx_enable, !!value))
                                qdf_err("Couldn't set CCK Tx enable val 0x%x",
                                        !!value);
                            else
                                ic->cck_tx_enable = value;
                        }
                    } else
                        qdf_info("CCK Tx is not supported for this band");
                }
            } else
                qdf_info("Setting the value of cck_tx_enable is not allowed for this chipset");
        break;

        case OL_ATH_PARAM_HE_UL_RU_ALLOCATION:

            if(!ic->ic_he_target) {
                qdf_err("Equal RU allocation setting not supported for this target\n");
                return -EINVAL;
            }

            if(value > 1) {
                qdf_err("Value should be either 0 or 1\n");
                return -EINVAL;
            }

            if(ic->ic_he_ru_allocation != value) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                        wmi_pdev_param_equal_ru_allocation_enable, value);
                if (retval == EOK) {
                    ic->ic_he_ru_allocation = value;
                }
                else {
                    qdf_err("WMI send for he_ru_alloc failed");
                    return retval;
                }
            }
            else {
                qdf_info("RU allocation enable already set with val %d", value);
            }
        break;
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
        case OL_ATH_PARAM_DFS_HOST_WAIT_TIMEOUT:
        /* Call a function to update the Host wait status Timeout */
        if (dfs_rx_ops && dfs_rx_ops->dfs_override_status_timeout) {
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                    QDF_STATUS_SUCCESS) {
                return -1;
            }
            dfs_rx_ops->dfs_override_status_timeout(pdev, value);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
        }
        break;
#endif /* HOST_DFS_SPOOF_TEST */
        case OL_ATH_PARAM_TWICE_ANTENNA_GAIN:
        if ((value >= 0) && (value <= (MAX_ANTENNA_GAIN * 2))) {
            if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_antenna_gain_half_db,
                                             value | ANTENNA_GAIN_2G_MASK);
            } else {
                return ol_ath_pdev_set_param(scn->sc_pdev,
                                             wmi_pdev_param_antenna_gain_half_db,
                                             value | ANTENNA_GAIN_5G_MASK);
            }
        } else {
            retval = -EINVAL;
        }
        break;
        case OL_ATH_PARAM_ENABLE_PEER_RETRY_STATS:
            scn->retry_stats = value;
            return ol_ath_pdev_set_param(scn->sc_pdev,
                                         wmi_pdev_param_enable_peer_retry_stats,
                                         !!value);
        break;
        case OL_ATH_PARAM_HE_UL_TRIG_INT:
            if(value > IEEE80211_HE_TRIG_INT_MAX) {
                qdf_err("Trigger interval value should be less than %dms",
                        IEEE80211_HE_TRIG_INT_MAX);
                retval = -EINVAL;
            }

            if (ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_ul_trig_int,
                                      value))
                qdf_err("Trigger interval value %d could not be set", value);
            else
                ic->ic_he_ul_trig_int = value;
        break;
        case OL_ATH_PARAM_DFS_NOL_SUBCHANNEL_MARKING:
#if ATH_SUPPORT_DFS
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_nol_subchannel_marking) {
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                            QDF_STATUS_SUCCESS) {
                return -1;
            }
                    retval = dfs_rx_ops->dfs_set_nol_subchannel_marking(pdev,
                                        value);
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                }
                break;
#else
        retval = -EINVAL;
        break;
#endif
        case OL_ATH_PARAM_HE_SR:
            if(value > 1) {
                qdf_err("%s: Spatial Reuse value should be either 0 or 1\n",
                        __func__);
                retval = -EINVAL;
            }

            ic->ic_he_sr_enable = value;
            osif_restart_for_config(ic, NULL, NULL);
            break;

        case OL_ATH_PARAM_HE_UL_PPDU_DURATION:
            if (!ic->ic_he_target) {
                qdf_err("UL PPDU Duration setting not supported for this target");
                return -EINVAL;
            }

            if (value > IEEE80211_UL_PPDU_DURATION_MAX) {
                qdf_err("UL PPDU Duration should be less than %d",
                        IEEE80211_UL_PPDU_DURATION_MAX);
                return -EINVAL;
            }

            if (ic->ic_he_ul_ppdu_dur != value) {
                retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                               wmi_pdev_param_ul_ppdu_duration,
                                               value);
                if (retval == EOK) {
                    ic->ic_he_ul_ppdu_dur = value;
                }
                else {
                    qdf_err("WMI send for ul_ppdu_dur failed");
                    return -EINVAL;
                }
            }
            else {
                qdf_info("UL PPDU duration already set with value %d", value);
            }
        break;
        case OL_ATH_PARAM_FLUSH_PEER_RATE_STATS:
             if (cdp_flush_rate_stats_request(soc_txrx_handle, pdev_id) != QDF_STATUS_SUCCESS)
                 return -EINVAL;
            break;
        case OL_ATH_PARAM_MGMT_TTL:
            if (!ic->ic_he_target) {
                qdf_err("MGMT TTL setting not supported for this target");
                return -EINVAL;
            }

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_set_mgmt_ttl, value);
            if (retval == EOK) {
               ic->ic_mgmt_ttl = value;
            }
            else {
                 qdf_err("WMI send for set mgmt ttl failed");
                 return -EINVAL;
            }
            break;
        case OL_ATH_PARAM_PROBE_RESP_TTL:
            if (!ic->ic_he_target) {
                qdf_err("PROBE RESP TTL setting not supported for this target");
                return -EINVAL;
            }

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_set_prb_rsp_ttl,
                                           value);
            if (retval == EOK) {
               ic->ic_probe_resp_ttl = value;
            }
            else {
                 qdf_err("WMI send for set probe respttl failed");
                 return -EINVAL;
            }
            break;
        case OL_ATH_PARAM_MU_PPDU_DURATION:
            if (!ic->ic_he_target) {
                qdf_err("MU PPDU DUR setting not supported for this target");
                return -EINVAL;
            }

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_set_mu_ppdu_duration,
                                           value);
            if (retval == EOK) {
                ic->ic_mu_ppdu_dur = value;
            } else {
                qdf_err("WMI send for set mu_ppdu_dur failed");
                return -EINVAL;
            }
            break;
        case OL_ATH_PARAM_TBTT_CTRL:
            if (!ic->ic_he_target) {
                qdf_err("TBTT CTRL setting not supported for this target");
                return -EINVAL;
            }

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                           wmi_pdev_param_set_tbtt_ctrl,
                                           value);
            if (retval == EOK) {
                ic->ic_tbtt_ctrl = value;
            } else {
                qdf_err("WMI send for set tbtt_ctrl failed");
                return -EINVAL;
            }
            break;

#ifdef WLAN_RX_PKT_CAPTURE_ENH
        case OL_ATH_PARAM_RX_MON_LITE:
            val.cdp_pdev_param_en_tx_cap = value;
            if (QDF_STATUS_SUCCESS != cdp_txrx_set_pdev_param(soc_txrx_handle,
                   pdev_id, CDP_CONFIG_ENH_RX_CAPTURE, val))
                return -EINVAL;

            if (ic->ic_rx_mon_lite == RX_ENH_CAPTURE_DISABLED &&
                value != RX_ENH_CAPTURE_DISABLED) {
                scn->soc->scn_rx_lite_monitor_mpdu_subscriber.callback
                    = process_rx_mpdu;
                scn->soc->scn_rx_lite_monitor_mpdu_subscriber.context  = scn;
                cdp_wdi_event_sub(soc_txrx_handle, pdev_id,
                    &scn->soc->scn_rx_lite_monitor_mpdu_subscriber, WDI_EVENT_RX_MPDU);
            } else if (ic->ic_rx_mon_lite != RX_ENH_CAPTURE_DISABLED &&
                       value == RX_ENH_CAPTURE_DISABLED) {
                scn->soc->scn_rx_lite_monitor_mpdu_subscriber.context  = scn;
                cdp_wdi_event_unsub(soc_txrx_handle, pdev_id,
                    &scn->soc->scn_rx_lite_monitor_mpdu_subscriber, WDI_EVENT_RX_MPDU);
            }
            ic->ic_rx_mon_lite = value;
        break;
#endif
        case OL_ATH_PARAM_WIFI_DOWN_IND:
            /* In MBSSIE case, deletion of transmitting VAP is not allowed explicitly using
             * 'iw <vap> del' command. But it is allowed as part of 'wifi down'. This param
             * is used during 'wifi down' to notify the driver.
             */
            if ((value < 0) || (value > 1)) {
                qdf_err("Valid value is 0 or 1 ");
                return -EINVAL;
            }

            ic->ic_wifi_down_ind = value;
            break;
        case OL_ATH_PARAM_TX_CAPTURE:
            if (scn->soc->rdkstats_enabled) {
                qdf_info("TX monitor mode not supported when RDK stats are enabled");
                break;
            }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            nss_soc_cfg = cfg_get(soc->psoc_obj, CFG_NSS_WIFI_OL);

            if (nss_soc_cfg)
            {
                qdf_info("TX monitor mode not supported when NSS offload is enabled");
                break;
            }
#endif /* QCA_NSS_WIFI_OFFLOAD_SUPPORT */
            if (value >= CDP_TX_ENH_CAPTURE_MAX) {
               qdf_err("value %d is not allowed for this config - disable/"
                       "enable for all peers/enable per peer supported ", value);
               return -EINVAL;
            }
            if (ic->ic_tx_pkt_capture && value)
            {
               qdf_err("value %u is not allowed"
                       "Disable before enabling tx_capture for all/per peer ",
               value);
               return -EINVAL;
            }

            val.cdp_pdev_param_en_tx_cap = value;
            if (cdp_txrx_set_pdev_param(soc_txrx_handle, pdev_id,
                                        CDP_CONFIG_ENH_TX_CAPTURE, val) ==
                                        QDF_STATUS_SUCCESS) {
                ic->ic_tx_pkt_capture = value;
                ol_ath_set_debug_sniffer(scn, SNIFFER_TX_MONITOR_MODE);
            } else {
                qdf_err(" busy in handling previous request !!!");
                return -EINVAL;
            }

            break;

        case OL_ATH_PARAM_WMI_DIS_DUMP:
        {
            if (!value) {
                scn->scn_wmi_dis_dump = !!value;
            } else {
                if (value == 1) {
                    scn->scn_wmi_dis_dump = !!value;
                    scn->scn_wmi_hang_wait_time = WAIT_TIME;
                    scn->scn_wmi_hang_after_time = FW_HANG_TIME;
                } else if ((value >> 16) < (value & 0xFF)) {
                    scn->scn_wmi_dis_dump = !!value;
                    scn->scn_wmi_hang_wait_time = (value >> 16);
                    scn->scn_wmi_hang_after_time = (value & 0xFF);
                } else {
                    qdf_err("Wait time is greater than hang time\n");
                    return -EINVAL;
                }
                qdf_info("WMI dump collection value is %d, wait time %d secs, Hang after %d secs\n",
                    scn->scn_wmi_dis_dump, scn->scn_wmi_hang_wait_time, scn->scn_wmi_hang_after_time);
                //Register recovery callback
                if (scn->scn_wmi_dis_dump) {
                    qdf_register_self_recovery_callback(wmi_dis_dump);
                }
            }
        }
        break;

        case OL_ATH_EXT_ACS_REQUEST_IN_PROGRESS:
            ic->ext_acs_request_in_progress = !!value;
            break;

        case OL_ATH_PARAM_HW_MODE:
        {
            /* Currently, value = 1 (DBS) and value = 4 (DBS_SBS)
             * supported
             */
            if (!(value == WMI_HOST_HW_MODE_DBS ||
                        value == WMI_HOST_HW_MODE_DBS_SBS)) {
                qdf_err("HW mode %d not supported", value);
                return -EINVAL;
            }

            return ol_ath_handle_hw_mode_switch(scn, value);
        }
        break;
        case OL_ATH_PARAM_HW_MODE_SWITCH_OMN_TIMER:
        {
            return ol_ath_set_hw_mode_omn_timer(scn, value);
        }
        case OL_ATH_PARAM_HW_MODE_SWITCH_OMN_ENABLE:
        {
            return ol_ath_set_hw_mode_omn_enable(scn, value);
        }
        case OL_ATH_PARAM_HW_MODE_SWITCH_PRIMARY_IF:
        {
            return ol_ath_set_hw_mode_primary_if(scn, (unsigned)value);
        }

        case OL_ATH_PARAM_CHAN_COEX:
        {
            if (TAILQ_EMPTY(&ic->ic_vaps)) {
                reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
                if (!(reg_rx_ops && reg_rx_ops->reg_disable_chan_coex)) {
                    qdf_err("%s : reg_rx_ops is NULL", __func__);
                    return -EINVAL;
                }

                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
                    QDF_STATUS_SUCCESS) {
                    return -EINVAL;
                }

                reg_rx_ops->reg_disable_chan_coex(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
            } else {
                qdf_err("Chan coex cmd cant be executed after vap creation\n");
            }
        }
        break;
        case OL_ATH_PARAM_OOB_ENABLE:
        {
            if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)){
              qdf_err("Out of band advertisement of 6Ghz in 2G/5g radio only");
              return -EINVAL;
            }
            if(value > 1){
              qdf_err("Value is 0 or 1");
              return -EINVAL;
            }
            if (value == 1) {
                WLAN_6GHZ_ADV_USER_SET(ic->ic_6ghz_rnr_enable, WLAN_RNR_IN_BCN);
                WLAN_6GHZ_ADV_USER_SET(ic->ic_6ghz_rnr_enable, WLAN_RNR_IN_PRB);
                WLAN_6GHZ_RNR_USR_MODE_SET(ic->ic_6ghz_rnr_enable);
            } else { /* value == 0 */
                WLAN_6GHZ_ADV_USER_CLEAR(ic->ic_6ghz_rnr_enable, WLAN_RNR_IN_BCN);
                WLAN_6GHZ_ADV_USER_CLEAR(ic->ic_6ghz_rnr_enable, WLAN_RNR_IN_PRB);
                WLAN_6GHZ_RNR_USR_MODE_SET(ic->ic_6ghz_rnr_enable);
            }
            osif_pdev_restart_vaps(ic);
        }
        break;

        case OL_ATH_PARAM_RNR_UNSOLICITED_PROBE_RESP_ACTIVE:
        {
            if(!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)){
              qdf_err(" RNR Unsolicited Probe Resp Active can be enabled  on 6GHz pdev only");
              return -EINVAL;
            }
            if(value > 1){
              qdf_err(" RNR Unsolicited Probe Resp should be either 0 or 1");
              return -EINVAL;
            }

            if (value && ic->ic_mbss.transmit_vap) {
                if (!ic->ic_mbss.transmit_vap->iv_he_6g_bcast_prob_rsp) {
                    qdf_err(" RNR: 20TU prb is not active for this AP");
                    return -EINVAL;
                }
            }
            if(ic->ic_6ghz_rnr_unsolicited_prb_resp_active != value) {
                ic->ic_6ghz_rnr_unsolicited_prb_resp_active = value;
                return ieee80211_set_rnr_bss_param(ic, RNR_BSS_PARAM_UNSOLICITED_PROBE_RESPONSE_ACTIVE, value);
            } else {
                qdf_info(" RNR Unsolicited Probe Resp is already set to %d ", value);
            }
       }
        break;

        case OL_ATH_PARAM_RNR_MEMBER_OF_ESS_24G_5G_CO_LOCATED:
        {
            if(!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)){
              qdf_err(" RNR Member of ESS of 2.4/5G Cco-located can be enabled on 6GHz pdev only");
              return -EINVAL;
            }
            if(value > 1){
              qdf_err(" RNR Member of ESS 2.4/5G co-located should be either 0 or 1");
              return -EINVAL;
            }
            if (value && wlan_lower_band_ap_cnt_get() == 0) {
                qdf_err(" RNR: 6Ghz Only AP. No co-located 2.4ghz/5ghz");
                return -EINVAL;
            }
            if(ic->ic_6ghz_rnr_ess_24g_5g_co_located != value) {
                ic->ic_6ghz_rnr_ess_24g_5g_co_located = value;
                    return ieee80211_set_rnr_bss_param(ic, RNR_BSS_PARAM_MEMBER_ESS_24G_5G_CO_LOCATED_AP, value);
            } else {
                    qdf_info(" RNR Member of ESS 2.4G/5G co-located is already set to %d ", value);
            }
        }
        break;

        case OL_ATH_PARAM_OPCLASS_TBL:
            return ol_ath_set_opclass_tbl(ic, value);
#ifdef QCA_SUPPORT_ADFS_RCAC
        case OL_ATH_PARAM_ROLLING_CAC_ENABLE:
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_rcac_enable) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                retval = dfs_rx_ops->dfs_set_rcac_enable(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
            break;
        case OL_ATH_PARAM_CONFIGURE_RCAC_FREQ:
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_rcac_freq) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_set_rcac_freq(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
            break;
#endif
#if ATH_SUPPORT_DFS
        case OL_ATH_SCAN_OVER_CAC:
            ic->ic_scan_over_cac = !!value;
        break;
#endif
        case OL_ATH_PARAM_NXT_RDR_FREQ:
            if (mlme_dfs_is_freq_in_nol(ic->ic_pdev_obj, value)) {
                qdf_err("user configured channel should not be in NOL list\n");
                return -EINVAL;
            }
            ic->ic_radar_next_usr_freq = value;
            qdf_info("ic_radar_next_usr_freq  %d",ic->ic_radar_next_usr_freq);
        break;
        case OL_ATH_PARAM_NON_INHERIT_ENABLE:
            if (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE)) {
                qdf_err("MBSS IE mode not enabled!");
                return -EINVAL;
            }

            if(value > 1) {
               qdf_err("Value is 0 or 1");
               return -EINVAL;
            }

            ic->ic_mbss.non_inherit_enable = value;

            if (ic->ic_mbss.transmit_vap &&
                    osif_restart_vaps(ic)) {
                return -EINVAL;
            }
        break;
        case OL_ATH_PARAM_RPT_MAX_PHY:
            /* rpt_max_phy feature uses bw_reduce and mark_subchan features */
            value = !!value;
            if (value && !ieee80211_ic_rpt_max_phy_is_set(ic)) {
#if ATH_SUPPORT_DFS
                if (dfs_rx_ops && dfs_rx_ops->dfs_set_bw_reduction) {
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                        return -1;
                    }
                    dfs_rx_ops->dfs_set_bw_reduction(pdev, true);
                    dfs_rx_ops->dfs_set_nol_subchannel_marking(pdev, 1);
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                }
#endif
                ieee80211_ic_rpt_max_phy_set(ic);
                osif_pdev_restart_vaps(ic);
           } else if (!value && ieee80211_ic_rpt_max_phy_is_set(ic)) {
#if ATH_SUPPORT_DFS
                if (dfs_rx_ops && dfs_rx_ops->dfs_set_bw_reduction) {
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                        return -1;
                    }
                    dfs_rx_ops->dfs_set_bw_reduction(pdev, false);
                    dfs_rx_ops->dfs_set_nol_subchannel_marking(pdev, 0);
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                }
#endif
                ieee80211_ic_rpt_max_phy_clear(ic);
                osif_pdev_restart_vaps(ic);
           } else {
                qdf_err("rpt_max_phy is already %s!",
                        ieee80211_ic_rpt_max_phy_is_set(ic) ?
                        "enabled" : "disabled");
           }
        break;
#ifdef QCA_SUPPORT_DFS_CHAN_POSTNOL
	case OL_ATH_DFS_CHAN_POSTNOL_FREQ:
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_postnol_freq) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_set_postnol_freq(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
	break;
	case OL_ATH_DFS_CHAN_POSTNOL_MODE:
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_postnol_mode) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_set_postnol_mode(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
	break;
	case OL_ATH_DFS_CHAN_POSTNOL_CFREQ2:
            if (dfs_rx_ops && dfs_rx_ops->dfs_set_postnol_cfreq2) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_set_postnol_cfreq2(pdev, value);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
	break;
#endif
        case OL_ATH_PARAM_ENABLE_ADDITIONAL_TRIPLETS:
        {
           uint8_t ctry_iso[REG_ALPHA2_LEN + 1];
           QDF_STATUS status;

           if (!value && !ic->ic_enable_additional_triplets) {
               qdf_err("Do not set 0");
               return -EINVAL;
           }

           status = ieee80211_set_6G_opclass_triplets(ic, value);
           if (status != QDF_STATUS_SUCCESS) {
               qdf_err("%d is an invalid input", value);
               return -EINVAL;
           }

           ieee80211_getCurrentCountryISO(ic, ctry_iso);
           ieee80211_build_countryie_all(ic, ctry_iso);
           osif_pdev_restart_vaps(ic);
           break;
        }
        case OL_ATH_PARAM_RNR_SELECTIVE_ADD:
            if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                qdf_err("RNR_SELECTIVE_ADD only for 6G radio");
                return -EINVAL;
            }
            if (value == 1) {
                ic->ic_flags_ext2 |= IEEE80211_FEXT2_RNR_SELECTIVE_ADD;
            } else if (value == 0){
                ic->ic_flags_ext2 &= ~IEEE80211_FEXT2_RNR_SELECTIVE_ADD;
            } else {
                qdf_err("Invalid value %d",value);
                return -EINVAL;
            }
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if (tmp_vap && !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(tmp_vap) &&
                    tmp_vap->iv_opmode == IEEE80211_M_HOSTAP &&
                    ieee80211_is_vap_state_running(tmp_vap)) {
                        tmp_vap->iv_oob_update = 1;
                        wlan_vdev_beacon_update(tmp_vap);
                        tmp_vap->iv_oob_update = 0;
                        if (tmp_vap->iv_he_6g_bcast_prob_rsp) {
                            struct ol_ath_vap_net80211 *avn;
                            struct ieee80211_node *ni;
                            ni = tmp_vap->iv_bss;
                            avn = OL_ATH_VAP_NET80211(tmp_vap);
                            avn->av_pr_rsp_wbuf = ieee80211_prb_rsp_alloc_init(ni,
                                                  &avn->av_prb_rsp_offsets);
                            if (avn->av_pr_rsp_wbuf) {
                               if (QDF_STATUS_SUCCESS !=
                                   ic->ic_prb_rsp_tmpl_send(tmp_vap->vdev_obj))
                                   qdf_err("20TU prb rsp send failed");
                            }
                        }
                }
            }
        break;
        case OL_ATH_PARAM_PUNCTURED_BAND:
        {
            uint32_t mode = ieee80211_get_current_phymode(ic);

            if (!ieee80211_is_phymode_11axa_he80(mode)) {
                qdf_err("Band puncturing only supported for IEEE80211_MODE_11AXA_HE80."
                        "\nNot supported for current phymode");
                return -EINVAL;
            }

            if (!target_psoc_get_preamble_puncture_cap(tgt_psoc_info)) {
                qdf_err("Target does not support Preamble Puncturing Tx");
                return -EINVAL;
            }

            if (ol_ath_punctured_band_setting_check(ic, value) < 0) {
                qdf_err("Invalid input");
                return -EINVAL;
            }

            if (ol_ath_pdev_set_param(scn->sc_pdev,
                                      wmi_pdev_param_pream_punct_bw,
                                      value)) {
                qdf_err("Error sending WMI for Punctured Band");
                return -EINVAL;
            } else {
                ic->ic_punctured_band = value;
            }
        }
        break;
        case OL_ATH_PARAM_MBSS_AUTOMODE:
           if (value)
               ieee80211_ic_mbss_automode_set(ic);
           else
               ieee80211_ic_mbss_automode_clear(ic);
        break;
        case OL_ATH_PARAM_ENABLE_EMA:
        {
            retval = ieee80211_mbss_mode_switch_sanity(ic, value);
            if (retval) {
                qdf_err("Sanity check for MBSS mode switch failed");
            } else {
                qdf_info("Setting %s mode", value ? "EMA" : "Co-hosted");
                retval = ieee80211_mbss_handle_mode_switch(ic, value ?
                                                           MBSS_MODE_MBSSID_EMA :
                                                           MBSS_MODE_COHOSTED);
            }
        }
        break;
        case OL_ATH_PARAM_ENABLE_TX_MODE_SELECT:
           scn = OL_ATH_SOFTC_NET80211(ic);
           if (!scn)
               return -EINVAL;

           pdev = scn->sc_pdev;
           if (!pdev)
               return -EINVAL;
           ol_ath_set_duration_based_tx_mode_select(pdev, value);
        break;
#if !(defined REMOVE_PKT_LOG) && (defined PKTLOG_DUMP_UPLOAD_SSR)
        case OL_ATH_PARAM_PKTLOG_DUMP_UPLOAD_SSR:
            if (value == 0 || value == 1) {
                scn->upload_pktlog = value;
            } else {
                qdf_info("Please enter: 0 = Disable,  1 = Enable");
                retval = -EINVAL;
            }
        break;
#endif
        case OL_ATH_PARAM_USER_RNR_FRM_CTRL:
            if (value > IEEE80211_BCN_PROBERSP_RNR_EN) {
                qdf_err(" User frame selection cannot be more than 0x3(bcn and probersp)");
                return -EINVAL;
            }
            if (ic->ic_user_rnr_frm_ctrl != value) {
                ieee80211_user_rnr_frm_update(ic, value, false);
                ic->ic_user_rnr_frm_ctrl = value;
            }
        break;
        case OL_ATH_PARAM_ENABLE_LOW_LATENCY_MODE:
           scn = OL_ATH_SOFTC_NET80211(ic);
           if (!scn)
               return -EINVAL;

           pdev = scn->sc_pdev;
           if (!pdev)
               return -EINVAL;
           if (ol_ath_enable_low_latency_mode(pdev, value) != QDF_STATUS_SUCCESS)
               return -EINVAL;
        break;

        default:
            return (-1);
    }

    osif_radio_activity_update(scn);

#if QCN_ESP_IE
    if (ic->ic_esp_flag)
        wlan_pdev_beacon_update(ic);
#endif /* QCN_ESP_IE */

    return retval;
}

int
ol_ath_get_config_param(struct ol_ath_softc_net80211 *scn, enum _ol_ath_param_t param, void *buff)
{
    int retval = 0;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS || PEER_FLOW_CONTROL
    u_int32_t value = *(u_int32_t *)buff;
#endif
    struct ieee80211com *ic = &scn->sc_ic;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    ol_txrx_soc_handle soc_txrx_handle;
    bool bw_reduce = false;
#if QCA_AIRTIME_FAIRNESS
    int atf_sched = 0;
#endif
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
#if ATH_SUPPORT_ZERO_CAC_DFS
    bool is_legacy_precac_enabled = false;
#if QCA_SUPPORT_AGILE_DFS
    bool is_adfs_enabled = false;
#endif
#endif
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap;
    uint8_t pdev_idx;
    struct wmi_unified *wmi_handle;
#ifdef DIRECT_BUF_RX_ENABLE
    struct wlan_lmac_if_tx_ops *tx_ops;
    struct wlan_lmac_if_direct_buf_rx_tx_ops *dbr_tx_ops = NULL;
#endif
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;
    uint8_t pdev_id;
    cdp_config_param_type val = {0};

    wmi_handle = lmac_get_wmi_hdl(scn->soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_info("%s : pdev is null ", __func__);
        return -1;
    }

    pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
    psoc = wlan_pdev_get_psoc(pdev);

    if (psoc == NULL) {
        qdf_info("%s : psoc is null", __func__);
        return -1;
    }

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
#if ATH_SUPPORT_DFS
    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
#endif
    reg_cap = ucfg_reg_get_hal_reg_cap(psoc);
    pdev_idx = lmac_get_pdev_idx(pdev);

    switch(param)
    {
        case OL_ATH_PARAM_GET_IF_ID:
            *(int *)buff = IF_ID_OFFLOAD;
            break;

        case OL_ATH_PARAM_TXCHAINMASK:
            *(int *)buff = ieee80211com_get_tx_chainmask(ic);
            break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS && ATH_SUPPORT_DSCP_OVERRIDE
        case OL_ATH_PARAM_HMMC_DSCP_TID_MAP:
            *(int *)buff = ol_ath_get_hmmc_tid(ic);
            break;

        case OL_ATH_PARAM_HMMC_DSCP_OVERRIDE:
            *(int *)buff = ol_ath_get_hmmc_dscp_override(ic);
            break;
#endif
        case OL_ATH_PARAM_RXCHAINMASK:
            *(int *)buff = ieee80211com_get_rx_chainmask(ic);
            break;
        case OL_ATH_PARAM_DYN_GROUPING:
            *(int *)buff = scn->dyngroup;
            break;
        case OL_ATH_PARAM_BCN_BURST:
            *(int *)buff = scn->bcn_mode;
            break;
        case OL_ATH_PARAM_DPD_ENABLE:
            *(int *)buff = scn->dpdenable;
            {
                switch (scn->dpdenable) {
                    case CLI_DPD_CMD_INPROGRES:
                        qdf_info("DPD cal in progess");
                        break;
                    case CLI_DPD_STATUS_FAIL:
                        qdf_info("DPD cal failed Or DPD disabled BDF loaded");
                        break;
                    case CLI_DPD_STATUS_DISABLED:
                        qdf_info("DPD cal disabled");
                        break;
                    case CLI_DPD_STATUS_PASS:
                        qdf_info("DPD cal Passed !!");
                        break;
                    case CLI_DPD_NA_STATE:
                        qdf_info("INVALID!! DPD not triggered via CLI command");
                        break;
                    default:
                        qdf_info("unknown state");
                }
            }
            break;
        case OL_ATH_PARAM_ARPDHCP_AC_OVERRIDE:
            *(int *)buff = scn->arp_override;
            break;
        case OL_ATH_PARAM_IGMPMLD_OVERRIDE:
            *(int *)buff = scn->igmpmld_override;
            break;
        case OL_ATH_PARAM_IGMPMLD_TID:
            *(int *)buff = scn->igmpmld_tid;
            break;

        case OL_ATH_PARAM_TXPOWER_LIMIT2G:
            *(int *)buff = scn->txpowlimit2G;
            break;

        case OL_ATH_PARAM_TXPOWER_LIMIT5G:
            *(int *)buff = scn->txpowlimit5G;
            break;

        case OL_ATH_PARAM_TXPOWER_SCALE:
            *(int *)buff = scn->txpower_scale;
            break;
        case OL_ATH_PARAM_RTS_CTS_RATE:
            *(int *)buff =  scn->ol_rts_cts_rate;
            break;
        case OL_ATH_PARAM_DEAUTH_COUNT:
#if WDI_EVENT_ENABLE
            *(int *)buff =  scn->scn_user_peer_invalid_cnt;;
#endif
            break;
        case OL_ATH_PARAM_DYN_TX_CHAINMASK:
            *(int *)buff = scn->dtcs;
            break;
        case OL_ATH_PARAM_VOW_EXT_STATS:
            *(int *)buff = scn->vow_extstats;
            break;
        case OL_ATH_PARAM_DCS_WIDEBAND_POLICY:
            *(int *)buff = scn->scn_dcs.dcs_wideband_policy;
            break;
        case OL_ATH_PARAM_DCS:
            /* do not need to talk to target */
            *(int *)buff = OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable);
            break;
        case OL_ATH_PARAM_DCS_RANDOM_CHAN_EN:
            *(int *)buff = scn->scn_dcs.dcs_random_chan_en;
            break;
        case OL_ATH_PARAM_DCS_CSA_TBTT:
            *(int *)buff = scn->scn_dcs.dcs_csa_tbtt;
            break;
        case OL_ATH_PARAM_DCS_COCH_THR:
            *(int *)buff = scn->scn_dcs.coch_intr_thresh ;
            break;
        case OL_ATH_PARAM_DCS_TXERR_THR:
            *(int *)buff = scn->scn_dcs.tx_err_thresh;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_THR:
            *(int *)buff = scn->scn_dcs.phy_err_threshold ;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_PENALTY:
            *(int *)buff = scn->scn_dcs.phy_err_penalty ;
            break;
        case OL_ATH_PARAM_DCS_RADAR_ERR_THR:
            *(int *)buff = scn->scn_dcs.radar_err_threshold ;
            break;
        case OL_ATH_PARAM_DCS_USERMAX_CU_THR:
            *(int *)buff = scn->scn_dcs.user_max_cu ;
            break;
        case OL_ATH_PARAM_DCS_INTR_DETECT_THR:
            *(int *)buff = scn->scn_dcs.intr_detection_threshold ;
            break;
        case OL_ATH_PARAM_DCS_SAMPLE_WINDOW:
            *(int *)buff = scn->scn_dcs.intr_detection_window ;
            break;
        case OL_ATH_PARAM_DCS_RE_ENABLE_TIMER:
            *(int *)buff = scn->scn_dcs.dcs_re_enable_time;
            break;
        case OL_ATH_PARAM_DCS_DEBUG:
            *(int *)buff = scn->scn_dcs.dcs_debug ;
            break;
#if QCA_SUPPORT_SON
        case OL_ATH_PARAM_BUFF_THRESH:
            *(int *)buff = son_ald_record_get_pool_size(scn->soc->psoc_obj) -
                               son_ald_record_get_buff_lvl(scn->soc->psoc_obj);
            break;
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        case OL_ATH_PARAM_BLK_REPORT_FLOOD:
            *(int *)buff = ic->ic_blkreportflood;
            break;
        case OL_ATH_PARAM_DROP_STA_QUERY:
            *(int *)buff = ic->ic_dropstaquery;
            break;
#endif
        case OL_ATH_PARAM_BURST_ENABLE:
            if (!wmi_service_enabled(wmi_handle, wmi_service_burst)) {
                qdf_err("Target does not support burst command");
                return -EINVAL;
            }

            *(int *)buff = scn->burst_enable;
            break;
        case OL_ATH_PARAM_CCA_THRESHOLD:
            *(int *)buff = scn->cca_threshold;
            break;
        case OL_ATH_PARAM_BURST_DUR:
            if (!wmi_service_enabled(wmi_handle, wmi_service_burst)) {
                qdf_err("Target does not support burst_dur");
                return -EINVAL;
            }

            *(int *)buff = scn->burst_dur;
            break;
        case OL_ATH_PARAM_ANI_ENABLE:
            *(int *)buff =  (scn->is_ani_enable == true);
            break;
        case OL_ATH_PARAM_ACS_CTRLFLAG:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_CTRLFLAG );
            }
            break;
        case OL_ATH_PARAM_ACS_ENABLE_BK_SCANTIMEREN:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_ENABLE_BK_SCANTIMER );
            }
            break;
        case OL_ATH_PARAM_ACS_SCANTIME:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_SCANTIME );
            }
            break;
        case OL_ATH_PARAM_ACS_SNRVAR:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_SNRVAR );
            }
            break;
        case OL_ATH_PARAM_ACS_CHAN_EFFICIENCY_VAR:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_CHAN_EFFICIENCY_VAR);
            }
            break;
        case OL_ATH_PARAM_ACS_CHLOADVAR:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_CHLOADVAR );
            }
            break;
        case OL_ATH_PARAM_ACS_SRLOADVAR:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_SRLOADVAR );
            }
            break;
        case OL_ATH_PARAM_ACS_LIMITEDOBSS:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_LIMITEDOBSS);
            }
            break;
        case OL_ATH_PARAM_ACS_DEBUGTRACE:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_DEBUGTRACE);
            }
            break;
#if ATH_CHANNEL_BLOCKING
        case OL_ATH_PARAM_ACS_BLOCK_MODE:
            if (ic->ic_acs) {
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_BLOCK_MODE);
            }
            break;
#endif
        case OL_ATH_PARAM_RESET_OL_STATS:
            ol_ath_reset_vap_stat(ic);
            break;
        case OL_ATH_PARAM_TOTAL_PER:
            *(int *)buff =
                ol_ath_net80211_get_total_per(ic);
            break;
#if ATH_RX_LOOPLIMIT_TIMER
        case OL_ATH_PARAM_LOOPLIMIT_NUM:
            *(int *)buff = scn->rx_looplimit_timeout;
            break;
#endif
        case OL_ATH_PARAM_RADIO_TYPE:
            *(int *)buff = 1;
            break;

        case OL_ATH_PARAM_FW_RECOVERY_ID:
            *(int *)buff = scn->soc->recovery_enable;
            break;
        case OL_ATH_PARAM_FW_DUMP_NO_HOST_CRASH:
            *(int *)buff = (scn->soc->sc_dump_opts & FW_DUMP_NO_HOST_CRASH ? 1: 0);
            break;
        case OL_ATH_PARAM_DISABLE_DFS:
            *(int *)buff =	(scn->sc_is_blockdfs_set == true);
            break;
        case OL_ATH_PARAM_PS_STATE_CHANGE:
            {
                *(int *) buff =  scn->ps_report ;
            }
            break;
        case OL_ATH_PARAM_BLOCK_INTERBSS:
            *(int*)buff = scn->scn_block_interbss;
            break;
        case OL_ATH_PARAM_SET_TXBF_SND_PERIOD:
            qdf_info("\n scn->txbf_sound_period hex %x %d\n", scn->txbf_sound_period, scn->txbf_sound_period);
            *(int*)buff = scn->txbf_sound_period;
            break;
#if ATH_SUPPORT_WRAP
        case OL_ATH_PARAM_MCAST_BCAST_ECHO:
            *(int*)buff = scn->mcast_bcast_echo;
            break;
        case OL_ATH_PARAM_ISOLATION:
#if WLAN_QWRAP_LEGACY
            *(int *)buff = ic->ic_wrap_com->wc_isolation;
#else
            *(int *)buff = dp_wrap_pdev_get_isolation(ic->ic_pdev_obj);
#endif
            break;
#endif
        case OL_ATH_PARAM_OBSS_SNR_THRESHOLD:
            {
                *(int*)buff = ic->obss_snr_threshold;
            }
            break;
        case OL_ATH_PARAM_OBSS_RX_SNR_THRESHOLD:
            {
                *(int*)buff = ic->obss_rx_snr_threshold;
            }
            break;
        case OL_ATH_PARAM_ALLOW_PROMISC:
            {
                *(int*)buff = (scn->scn_promisc || promisc_is_active(&scn->sc_ic)) ? 1 : 0;
            }
            break;
        case OL_ATH_PARAM_ACS_TX_POWER_OPTION:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_TX_POWER_OPTION);
            }
            break;
         case OL_ATH_PARAM_ACS_2G_ALLCHAN:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_2G_ALL_CHAN);
            }
            break;
         case OL_ATH_PARAM_ACS_CHAN_GRADE_ALGO:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_CHAN_GRADE_ALGO);
            }
            break;
         case OL_ATH_PARAM_ACS_NEAR_RANGE_WEIGHTAGE:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_OBSS_NEAR_RANGE_WEIGHTAGE);
            }
            break;
         case OL_ATH_PARAM_ACS_MID_RANGE_WEIGHTAGE:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_OBSS_MID_RANGE_WEIGHTAGE);
            }
            break;
         case OL_ATH_PARAM_ACS_FAR_RANGE_WEIGHTAGE:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_OBSS_FAR_RANGE_WEIGHTAGE);
            }
            break;

        case OL_ATH_PARAM_MAX_CLIENTS_PER_RADIO:
             *(int*)buff = ic->ic_num_clients;
        break;

        case OL_ATH_PARAM_ENABLE_AMSDU:
             *(int*)buff = scn->scn_amsdu_mask;
        break;

#if WLAN_CFR_ENABLE
        case OL_ATH_PARAM_PERIODIC_CFR_CAPTURE:
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID) !=
                    QDF_STATUS_SUCCESS) {
                return -1;
            }

            *(int *)buff = ucfg_cfr_get_timer(pdev);

            wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);
        break;
        case OL_ATH_PARAM_CFR_CAPTURE_STATUS:
        {
            enum cfr_capt_status status;
            ucfg_cfr_get_capture_status(pdev, &status);
            *(int *)buff = status;
            break;
        }
#endif

        case OL_ATH_PARAM_ENABLE_AMPDU:
             *(int*)buff = scn->scn_ampdu_mask;
        break;

       case OL_ATH_PARAM_PRINT_RATE_LIMIT:
             *(int*)buff = scn->soc->dbg.print_rate_limit;
       break;
        case OL_ATH_PARAM_CONSIDER_OBSS_NON_ERP_LONG_SLOT:
            *(int*)buff = ic->ic_consider_obss_long_slot;
        break;

#if PEER_FLOW_CONTROL
        case OL_ATH_PARAM_VIDEO_STATS_FC:
        case OL_ATH_PARAM_STATS_FC:
        case OL_ATH_PARAM_QFLUSHINTERVAL:
        case OL_ATH_PARAM_TOTAL_Q_SIZE:
        case OL_ATH_PARAM_MIN_THRESHOLD:
        case OL_ATH_PARAM_MAX_Q_LIMIT:
        case OL_ATH_PARAM_MIN_Q_LIMIT:
        case OL_ATH_PARAM_CONG_CTRL_TIMER_INTV:
        case OL_ATH_PARAM_STATS_TIMER_INTV:
        case OL_ATH_PARAM_ROTTING_TIMER_INTV:
        case OL_ATH_PARAM_LATENCY_PROFILE:
            {
                enum _dp_param_t dp_param = ol_ath_param_to_dp_param(param);
                cdp_pflow_update_pdev_params(soc_txrx_handle, pdev_id,
                                             dp_param, value, buff);
            }
            break;
#endif

        case OL_ATH_PARAM_DBG_ARP_SRC_ADDR:
        {
             /* arp dbg stats */
             qdf_info("---- ARP DBG STATS ---- \n");
             qdf_info("\n TX_ARP_REQ \t TX_ARP_RESP \t RX_ARP_REQ \t RX_ARP_RESP\n");
             qdf_info("\n %d \t\t %d \t %d \t %d \n", scn->sc_tx_arp_req_count, scn->sc_tx_arp_resp_count, scn->sc_rx_arp_req_count, scn->sc_rx_arp_resp_count);
        }
        break;

        case OL_ATH_PARAM_ARP_DBG_CONF:

             *(int*)buff = scn->sc_arp_dbg_conf;
        break;

        case OL_ATH_PARAM_DISABLE_STA_VAP_AMSDU:
            *(int*)buff = ic->ic_sta_vap_amsdu_disable;
        break;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        case OL_ATH_PARAM_STADFS_ENABLE:
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                QDF_STATUS_SUCCESS) {
            return -1;
        }

        if (dfs_rx_ops && dfs_rx_ops->dfs_is_stadfs_enabled)
            *(int *)buff = dfs_rx_ops->dfs_is_stadfs_enabled(pdev);

        wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
        break;
#endif
        case OL_ATH_PARAM_CHANSWITCH_OPTIONS:
            (*(int *)buff) = ic->ic_chanswitch_flags;
            qdf_info(
                    "IEEE80211_CSH_OPT_NONDFS_RANDOM    0x00000001\n"
                    "IEEE80211_CSH_OPT_IGNORE_CSA_DFS   0x00000002\n"
                    "IEEE80211_CSH_OPT_CAC_APUP_BYSTA   0x00000004\n"
                    "IEEE80211_CSH_OPT_CSA_APUP_BYSTA   0x00000008\n"
                    "IEEE80211_CSH_OPT_RCSA_TO_UPLINK   0x00000010\n"
                    "IEEE80211_CSH_OPT_PROCESS_RCSA     0x00000020\n"
                    "IEEE80211_CSH_OPT_APRIORI_NEXT_CHANNEL 0x00000040\n"
                    "IEEE80211_CSH_OPT_AVOID_DUAL_CAC   0x00000080\n"
                    );
        break;
        case OL_ATH_PARAM_BW_REDUCE:
            if (dfs_rx_ops && dfs_rx_ops->dfs_is_bw_reduction_needed) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }

                dfs_rx_ops->dfs_is_bw_reduction_needed(pdev, &bw_reduce);
                *(int *) buff = bw_reduce;
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
            break;
        case OL_ATH_PARAM_NO_BACKHAUL_RADIO:
            *(int *) buff =  ic->ic_nobackhaul_radio;
            break;
        case OL_ATH_PARAM_HE_MBSSID_CTRL_FRAME_CONFIG:
            *(int *) buff = ic->ic_he_mbssid_ctrl_frame_config;
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_PRIMARY_RADIO:
            *(int *) buff =  ic->ic_primary_radio;
            break;
        case OL_ATH_PARAM_DBDC_ENABLE:
            *(int *) buff =  ic->ic_global_list->dbdc_process_enable;
            break;
        case OL_ATH_PARAM_CLIENT_MCAST:
            *(int *)buff = ic->ic_global_list->force_client_mcast_traffic;
            break;
#endif
        case OL_ATH_PARAM_CTL_POWER_SCALE:
            *(int *)buff = scn->powerscale;
            break;
#if QCA_AIRTIME_FAIRNESS
    case  OL_ATH_PARAM_ATF_STRICT_SCHED:
        atf_sched = target_if_atf_get_sched(psoc, pdev);
        *(int *)buff =!!(atf_sched & ATF_SCHED_STRICT);
        break;
    case  OL_ATH_PARAM_ATF_GROUP_POLICY:
        atf_sched = target_if_atf_get_sched(psoc, pdev);
        *(int *)buff =  !!(atf_sched & ATF_GROUP_SCHED_POLICY);
        break;
    case  OL_ATH_PARAM_ATF_OBSS_SCHED:
        atf_sched = target_if_atf_get_sched(psoc, pdev);
        *(int *)buff =!!(atf_sched & ATF_SCHED_OBSS);
        break;
#endif
        case OL_ATH_PARAM_PHY_OFDM_ERR:
#ifdef QCA_SUPPORT_CP_STATS
            *(int *)buff = pdev_cp_stats_rx_phy_err_get(pdev);
#endif
            break;
        case OL_ATH_PARAM_PHY_CCK_ERR:
#ifdef QCA_SUPPORT_CP_STATS
            *(int *)buff = pdev_cp_stats_rx_phy_err_get(pdev);
#endif
            break;
        case OL_ATH_PARAM_FCS_ERR:
#ifdef QCA_SUPPORT_CP_STATS
            *(int *)buff = pdev_cp_stats_fcsbad_get(pdev);
#endif
            break;
        case OL_ATH_PARAM_CHAN_UTIL:
#ifdef QCA_SUPPORT_CP_STATS
            *(int *)buff = 100 - ucfg_pdev_chan_stats_free_medium_get(pdev);
#endif
            break;
        case OL_ATH_PARAM_EMIWAR_80P80:
            *(int *)buff = ic->ic_emiwar_80p80;
            break;
#if UMAC_SUPPORT_ACFG
        case OL_ATH_PARAM_DIAG_ENABLE:
            *(int *)buff = ic->ic_diag_enable;
        break;
#endif

        case OL_ATH_PARAM_CHAN_STATS_TH:
            *(int *)buff = ic->ic_chan_stats_th;
            break;

        case OL_ATH_PARAM_PASSIVE_SCAN_ENABLE:
            *(int *)buff = ic->ic_strict_pscan_enable;
            break;

        case OL_ATH_MIN_SNR_ENABLE:
            *(int *)buff = ic->ic_min_snr_enable;
            break;
        case OL_ATH_MIN_SNR:
            *(int *)buff = ic->ic_min_snr;
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_DELAY_STAVAP_UP:
            *(int *)buff = ic->ic_global_list->delay_stavap_connection;
            break;
#endif
        case OL_ATH_BTCOEX_ENABLE:
            *((int *) buff) = scn->soc->btcoex_enable;
            break;
        case OL_ATH_BTCOEX_WL_PRIORITY:
            *((int *) buff) = scn->soc->btcoex_wl_priority;
            break;
        case OL_ATH_GET_BTCOEX_DUTY_CYCLE:
            qdf_info("period: %d wlan_duration: %d ",
		      scn->soc->btcoex_period,scn->soc->btcoex_duration);
            *(int *)buff = scn->soc->btcoex_period;
            break;
        case OL_ATH_PARAM_CAL_VER_CHECK:
            *(int *)buff = ic->ic_cal_ver_check;
           break;
        case OL_ATH_PARAM_TID_OVERRIDE_QUEUE_MAPPING:
            cdp_txrx_get_pdev_param(soc_txrx_handle, pdev_id, CDP_TIDQ_OVERRIDE, &val);
            *(int *)buff = val.cdp_pdev_param_tidq_override;
            break;
        case OL_ATH_PARAM_NO_VLAN:
            *(int *)buff = ic->ic_no_vlan;
            break;
        case OL_ATH_PARAM_ATF_LOGGING:
            *(int *)buff = ic->ic_atf_logging;
            break;
        case OL_ATH_PARAM_STRICT_DOTH:
            *(int *)buff = ic->ic_strict_doth;
            break;
        case OL_ATH_PARAM_CHANNEL_SWITCH_COUNT:
            *(int *)buff = ic->ic_chan_switch_cnt;
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_DISCONNECTION_TIMEOUT:
            *(int *)buff = ic->ic_global_list->disconnect_timeout;
            break;
        case OL_ATH_PARAM_RECONFIGURATION_TIMEOUT:
            *(int *)buff = ic->ic_global_list->reconfiguration_timeout;
            break;
        case OL_ATH_PARAM_ALWAYS_PRIMARY:
            *(int *)buff = ic->ic_global_list->always_primary;
            break;
        case OL_ATH_PARAM_FAST_LANE:
            *(int *)buff = ic->fast_lane;
            break;
        case OL_ATH_PARAM_PREFERRED_UPLINK:
            *(int *) buff =  ic->ic_preferredUplink;
            break;
#endif
        case OL_ATH_PARAM_SECONDARY_OFFSET_IE:
            *(int *)buff = ic->ic_sec_offsetie;
            break;
        case OL_ATH_PARAM_WIDE_BAND_SUB_ELEMENT:
            *(int *)buff = ic->ic_wb_subelem;
            break;
#if ATH_SUPPORT_ZERO_CAC_DFS
        case OL_ATH_PARAM_PRECAC_ENABLE:
            if (!dfs_rx_ops)
                break;
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS)
                return -1;
            if (dfs_rx_ops->dfs_get_legacy_precac_enable)
                dfs_rx_ops->dfs_get_legacy_precac_enable(pdev,
                        &is_legacy_precac_enabled);
#if QCA_SUPPORT_AGILE_DFS
            if (dfs_rx_ops->dfs_get_agile_precac_enable)
                dfs_rx_ops->dfs_get_agile_precac_enable(pdev,
                                                        &is_adfs_enabled);
            *(int *)buff = is_legacy_precac_enabled || is_adfs_enabled;
#else
            *(int *)buff = is_legacy_precac_enabled;
#endif
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            break;
        case OL_ATH_PARAM_PRECAC_TIMEOUT:
            {
                int tmp = 0;

                /* Call a function to get the precac timeout value */
                if (dfs_rx_ops && dfs_rx_ops->dfs_get_override_precac_timeout) {
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                            QDF_STATUS_SUCCESS) {
                        return -1;
                    }
                    dfs_rx_ops->dfs_get_override_precac_timeout(pdev, &tmp);
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                }
                *(int *)buff = tmp;
            }
            break;
#ifdef WLAN_DFS_PRECAC_AUTO_CHAN_SUPPORT
        case OL_ATH_PARAM_PRECAC_INTER_CHANNEL:
            if (dfs_rx_ops && dfs_rx_ops->dfs_get_precac_intermediate_chan) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                dfs_rx_ops->dfs_get_precac_intermediate_chan(pdev,
							     (int *)buff);
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
           break;
        case OL_ATH_PARAM_PRECAC_CHAN_STATE:
            if (dfs_rx_ops && dfs_rx_ops->dfs_get_precac_chan_state_for_freq) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                retval = dfs_rx_ops->dfs_get_precac_chan_state_for_freq(pdev,
                                                        *((int *)buff + 1));
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                if (retval == PRECAC_ERR)
                    retval = -EINVAL;
                else {
                    *((int *)buff) = retval;
                    retval = EOK;
                }
            }
            break;
#endif
#endif
        case OL_ATH_PARAM_PDEV_TO_REO_DEST:
            *(int *)buff = cdp_get_pdev_reo_dest(soc_txrx_handle,
                                                 wlan_objmgr_pdev_get_pdev_id(pdev));
            break;

        case OL_ATH_PARAM_DUMP_CHAINMASK_TABLES:
            ol_ath_dump_chainmaks_tables(scn);
            break;

        case OL_ATH_PARAM_MGMT_SNR_THRESHOLD:
            *(int *)buff = ic->mgmt_rx_snr;
            break;

        case OL_ATH_PARAM_EXT_NSS_CAPABLE:
             *(int *)buff = ic->ic_ext_nss_capable;
             break;

#if QCN_ESP_IE
        case OL_ATH_PARAM_ESP_PERIODICITY:
            *(int *)buff = ic->ic_esp_periodicity;
            break;
        case OL_ATH_PARAM_ESP_AIRTIME:
            *(int *)buff = ic->ic_esp_air_time_fraction;
            break;
        case OL_ATH_PARAM_ESP_PPDU_DURATION:
            *(int *)buff = ic->ic_esp_ppdu_duration;
            break;
        case OL_ATH_PARAM_ESP_BA_WINDOW:
            *(int *)buff = ic->ic_esp_ba_window;
            break;
#endif /* QCN_ESP_IE */

        case OL_ATH_PARAM_MGMT_PDEV_STATS_TIMER:
            *(int *)buff = scn->pdev_stats_timer;

        case OL_ATH_PARAM_ICM_ACTIVE:
            *(int *)buff = ic->ic_extacs_obj.icm_active;
            break;

#if ATH_SUPPORT_ICM
        case OL_ATH_PARAM_NOMINAL_NOISEFLOOR:
            *(int *)buff = ol_get_nominal_nf(ic);
            break;
#endif

        case OL_ATH_PARAM_TXACKTIMEOUT:
            if (wmi_service_enabled(wmi_handle,wmi_service_ack_timeout))
            {
                *(int *)buff = scn->tx_ack_timeout;
            }
            else
            {
                qdf_info("TX ACK Timeout Service is not supported");
                retval = -1;
            }
            break;

        case OL_ATH_PARAM_ACS_RANK:
            if (ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_RANK);
            }
            break;

	case OL_ATH_PARAM_ACS_PRECAC_SUPPORT:
            *(int *)buff = ic->ic_acs_precac_completed_chan_only;
        break;
#ifdef OL_ATH_SMART_LOGGING
        case OL_ATH_PARAM_SMARTLOG_ENABLE:
            *(int *)buff = ic->smart_logging;
            break;

        case OL_ATH_PARAM_SMARTLOG_SKB_SZ:
            *(int *)buff = ic->smart_log_skb_sz;
            break;

        case OL_ATH_PARAM_SMARTLOG_P1PINGFAIL:
            *(int *)buff = ic->smart_logging_p1pingfail_started;
            break;
#endif /* OL_ATH_SMART_LOGGING */

        case OL_ATH_PARAM_CBS:
            if (ic->ic_cbs) {
                *(int *)buff = ieee80211_cbs_get_param(ic->ic_cbs, IEEE80211_CBS_ENABLE);
            }
            break;

        case OL_ATH_PARAM_CBS_DWELL_SPLIT_TIME:
            if (ic->ic_cbs) {
                *(int *)buff = ieee80211_cbs_get_param(ic->ic_cbs, IEEE80211_CBS_DWELL_SPLIT_TIME);
            }
            break;

        case OL_ATH_PARAM_CBS_DWELL_REST_TIME:
            if (ic->ic_cbs) {
                *(int *)buff = ieee80211_cbs_get_param(ic->ic_cbs, IEEE80211_CBS_DWELL_REST_TIME);
            }
            break;

        case OL_ATH_PARAM_CBS_WAIT_TIME:
            if (ic->ic_cbs) {
                *(int *)buff = ieee80211_cbs_get_param(ic->ic_cbs, IEEE80211_CBS_WAIT_TIME);
            }
            break;

        case OL_ATH_PARAM_CBS_REST_TIME:
            if (ic->ic_cbs) {
                *(int *)buff = ieee80211_cbs_get_param(ic->ic_cbs, IEEE80211_CBS_REST_TIME);
            }
            break;

        case OL_ATH_PARAM_CBS_CSA:
            if (ic->ic_cbs) {
                *(int *)buff = ieee80211_cbs_get_param(ic->ic_cbs, IEEE80211_CBS_CSA_ENABLE);
            }
            break;


        case OL_ATH_PARAM_TXCHAINSOFT:
            *(int *)buff = scn->soft_chain;
            break;

        case OL_ATH_PARAM_WIDE_BAND_SCAN:
            *(int *)buff = ic->ic_widebw_scan;
            break;

        case OL_ATH_PARAM_CCK_TX_ENABLE:
            if (reg_cap == NULL)
            {
                qdf_info("reg_cap is NULL, unable to process further. Investigate.");
                retval = -1;
            } else {
                if (reg_cap[pdev_idx].wireless_modes & WIRELESS_MODES_2G)
                {
                    *(int *)buff = ic->cck_tx_enable;
                }
                else
                {
                    qdf_info("CCK Tx is not supported for this band");
                    retval = -1;
                }
            }
            break;

#if ATH_PARAMETER_API
        case OL_ATH_PARAM_PAPI_ENABLE:
            *(int *)buff = ic->ic_papi_enable;
            break;
#endif
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
        case OL_ATH_PARAM_DFS_HOST_WAIT_TIMEOUT:
            {
                int tmp;

                /* Call a function to get the precac timeout value */
                if (dfs_rx_ops && dfs_rx_ops->dfs_get_override_status_timeout) {
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                            QDF_STATUS_SUCCESS) {
                        return -1;
                    }
                    dfs_rx_ops->dfs_get_override_status_timeout(pdev, &tmp);
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                    *(int *)buff = tmp;
                } else {
                    qdf_info(" Host Wait Timeout is not supported");
                    retval = -1;
                }
            }
            break;
#endif /* HOST_DFS_SPOOF_TEST */
        case OL_ATH_PARAM_NF_THRESH:
            if (ic->ic_acs)
                *(int *)buff =  ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_NF_THRESH);
            else {
                qdf_info("Failed to get ACS NF Threshold");
                retval = -1;
            }
            break;
#ifdef DIRECT_BUF_RX_ENABLE
	case OL_ATH_PARAM_DBR_RING_STATUS:
	    tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
	    if (!tx_ops) {
		qdf_err("tx_ops is null");
		return -1;
	    }
	    dbr_tx_ops = &tx_ops->dbr_tx_ops;
            if (dbr_tx_ops->direct_buf_rx_print_ring_stat) {
                dbr_tx_ops->direct_buf_rx_print_ring_stat(pdev);
            }
            break;
#endif
        case OL_ATH_PARAM_ACTIVITY_FACTOR:
            {
                *(int *)buff =
                    (((scn->mib_cycle_cnts.rx_clear_count - scn->mib_cycle_cnts.rx_frame_count -
                       scn->mib_cycle_cnts.tx_frame_count) / scn->mib_cycle_cnts.cycle_count) * 100);
            }
            break;
        case OL_ATH_PARAM_ENABLE_PEER_RETRY_STATS:
            *(int *)buff = scn->retry_stats;
        break;
	case OL_ATH_PARAM_DFS_NOL_SUBCHANNEL_MARKING:
#if ATH_SUPPORT_DFS
	    {
		bool tmpval;
		if (dfs_rx_ops && dfs_rx_ops->dfs_get_nol_subchannel_marking) {
			if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
					QDF_STATUS_SUCCESS) {
				return -1;
			}
		retval = dfs_rx_ops->dfs_get_nol_subchannel_marking(pdev, &tmpval);
		wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
		if (retval == QDF_STATUS_SUCCESS)
			*(int *)buff = tmpval;
		}
	    }
	break;
#else
	retval = -EINVAL;
	break;
#endif
#ifdef QCA_SUPPORT_CP_STATS
        case OL_ATH_PARAM_CHAN_AP_RX_UTIL:
            *(int *)buff = pdev_chan_stats_ap_rx_util_get(pdev);
            break;
        case OL_ATH_PARAM_CHAN_FREE:
            *(int *)buff = pdev_chan_stats_free_medium_get(pdev);
            break;
        case OL_ATH_PARAM_CHAN_AP_TX_UTIL:
            *(int *)buff = pdev_chan_stats_ap_tx_util_get(pdev);
            break;
        case OL_ATH_PARAM_CHAN_OBSS_RX_UTIL:
            *(int *)buff = pdev_chan_stats_obss_rx_util_get(pdev);
            break;
        case OL_ATH_PARAM_CHAN_NON_WIFI:
            *(int *)buff = pdev_chan_stats_non_wifi_util_get(pdev);
            break;
        case OL_ATH_PARAM_HE_UL_TRIG_INT:
            *(int *)buff = ic->ic_he_ul_trig_int;
            break;
#endif
        case OL_ATH_PARAM_BAND_INFO:
            *(int *)buff = ol_ath_fill_umac_radio_band_info(pdev);
            break;
        case OL_ATH_PARAM_HE_SR:
            *(int *)buff = ic->ic_he_sr_enable;
            break;
        case OL_ATH_PARAM_HE_UL_PPDU_DURATION:
            *(int *)buff = ic->ic_he_ul_ppdu_dur;
            break;
        case OL_ATH_PARAM_HE_UL_RU_ALLOCATION:
            *(int *)buff = ic->ic_he_ru_allocation;
#ifdef WLAN_RX_PKT_CAPTURE_ENH
        case OL_ATH_PARAM_RX_MON_LITE:
            *(int *)buff = ic->ic_rx_mon_lite;
            break;
#endif
        case OL_ATH_PARAM_TX_CAPTURE:
            *(int *)buff = ic->ic_tx_pkt_capture;
            break;
        case OL_ATH_PARAM_MGMT_TTL:
            *(int *)buff = ic->ic_mgmt_ttl;
            break;
        case OL_ATH_PARAM_PROBE_RESP_TTL:
            *(int *)buff = ic->ic_probe_resp_ttl;
            break;
        case OL_ATH_PARAM_MU_PPDU_DURATION:
            *(int *)buff = ic->ic_mu_ppdu_dur;
            break;
        case OL_ATH_PARAM_TBTT_CTRL:
            *(int *)buff = ic->ic_tbtt_ctrl;
            break;
        case OL_ATH_PARAM_RCHWIDTH:
            /*
             * Return the baseline radio level channel width applicable for the
             * current channel configured in ic.
             */
            *(int *)buff = ic->ic_cwm_get_width(ic);
            break;
        case OL_ATH_PARAM_HW_MODE:
            *(int *)buff = scn->soc->hw_mode_ctx.current_mode;
            break;
        case OL_ATH_PARAM_HW_MODE_SWITCH_OMN_TIMER:
            *(int *)buff = ic->ic_omn_cxt.omn_timeout;
        case OL_ATH_PARAM_HW_MODE_SWITCH_OMN_ENABLE:
            *(int *)buff = ic->ic_omn_cxt.omn_enable;

        case OL_ATH_PARAM_MBSS_EN:
            *(int *)buff = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                                    WLAN_PDEV_F_MBSS_IE_ENABLE);
            break;
        case OL_ATH_PARAM_CHAN_COEX:
            {
                uint8_t chan_coex_bitmap;

                reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
                if (!(reg_rx_ops && reg_rx_ops->reg_get_unii_5g_bitmap)) {
                    qdf_err("%s : reg_rx_ops is NULL", __func__);
                    return -EINVAL;
                }

                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
                    QDF_STATUS_SUCCESS) {
                    return -EINVAL;
                }
                if ((reg_rx_ops->reg_get_unii_5g_bitmap(pdev,
                                                        &chan_coex_bitmap)
                     == QDF_STATUS_SUCCESS))
                    *(int *)buff = chan_coex_bitmap;
                else
                    retval = -EINVAL;
                wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);

                break;
            }
        case OL_ATH_PARAM_OOB_ENABLE:
            {
              if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)){
                qdf_err("Out of band advertisement of 6Ghz AP in 2G/5G radio only");
                return -EINVAL;
              }
              *(int *)buff = ic->ic_6ghz_rnr_enable;
            }
            break;
        case OL_ATH_PARAM_RNR_UNSOLICITED_PROBE_RESP_ACTIVE:
            {
              if(!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)){
                qdf_err("Getting RNR Unsolicited Probe Response is only available on 6GHz");
                return -EINVAL;
              }
              *(int *)buff = ic->ic_6ghz_rnr_unsolicited_prb_resp_active;
            }
            break;
        case OL_ATH_PARAM_RNR_MEMBER_OF_ESS_24G_5G_CO_LOCATED:
            {
              if(!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)){
                qdf_err("Getting RNR Member of ESS 2.5/5G Co-located is only available on 6GHz");
                return -EINVAL;
              }
              *(int *)buff = ic->ic_6ghz_rnr_ess_24g_5g_co_located;
            }
            break;
        case OL_ATH_PARAM_USER_RNR_FRM_CTRL:
            *(int *)buff = ic->ic_user_rnr_frm_ctrl;
            break;
        case OL_ATH_PARAM_GET_PSOC_NUM_VDEVS:
            *(int *)buff = wlan_psoc_get_max_vdev_count(psoc);
            break;
        case OL_ATH_PARAM_GET_PSOC_NUM_PEERS:
            *(int *)buff = wlan_psoc_get_max_peer_count(psoc);
            break;
        case OL_ATH_PARAM_GET_PDEV_NUM_VDEVS:
            *(int *)buff = wlan_pdev_get_max_vdev_count(pdev);
            break;
        case OL_ATH_PARAM_GET_PDEV_NUM_PEERS:
            *(int *)buff = ol_ath_get_num_clients(pdev);
            break;
        case OL_ATH_PARAM_GET_PDEV_NUM_MONITOR_VDEVS:
            *(int *)buff = wlan_pdev_get_max_monitor_vdev_count(pdev);
            break;
        case OL_ATH_PARAM_OPCLASS_TBL:
            {
                uint8_t opclass_tbl;
                if (ol_ath_get_opclass_tbl(ic, &opclass_tbl))
                {
                    qdf_err("Could not get current operating class table");
                    return -EINVAL;
                }
                *(int *)buff = opclass_tbl;
            }
            break;
#ifdef QCA_SUPPORT_ADFS_RCAC
        case OL_ATH_PARAM_ROLLING_CAC_ENABLE:
            {
                bool rcac_en = 0;
                if (dfs_rx_ops && dfs_rx_ops->dfs_get_rcac_enable) {
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                        return -1;
                    }
                    if(dfs_rx_ops->dfs_get_rcac_enable(pdev, &rcac_en)
                       == QDF_STATUS_SUCCESS)
                        *(int *)buff = rcac_en;
                    else
                        retval = -EINVAL;
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                }
            }
            break;
        case OL_ATH_PARAM_CONFIGURE_RCAC_FREQ:
            {
                uint16_t rcac_freq = 0;
                if (dfs_rx_ops && dfs_rx_ops->dfs_get_rcac_freq) {
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                        return -1;
                    }
                    if(dfs_rx_ops->dfs_get_rcac_freq(pdev, &rcac_freq)
                       == QDF_STATUS_SUCCESS)
                        *(int *)buff = rcac_freq;
                    else
                        retval = -EINVAL;
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                }
            }
            break;
#endif
#if ATH_SUPPORT_DFS
        case OL_ATH_SCAN_OVER_CAC:
            *(int *)buff = ic->ic_scan_over_cac;
            break;
#endif
        case OL_ATH_PARAM_NXT_RDR_FREQ:
            *(int *)buff = ic->ic_radar_next_usr_freq;
            break;
        case OL_ATH_PARAM_NON_INHERIT_ENABLE:
            *(int *)buff = ic->ic_mbss.non_inherit_enable;
            break;
        case OL_ATH_PARAM_RPT_MAX_PHY:
            *(int *)buff = ieee80211_ic_rpt_max_phy_is_set(ic);
            break;
#ifdef QCA_SUPPORT_DFS_CHAN_POSTNOL
	case OL_ATH_DFS_CHAN_POSTNOL_FREQ:
	{
            uint16_t postnol_freq = 0;

            if (dfs_rx_ops && dfs_rx_ops->dfs_get_postnol_freq) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                if(dfs_rx_ops->dfs_get_postnol_freq(pdev, &postnol_freq) ==
                   QDF_STATUS_SUCCESS)
                    *(int *)buff = postnol_freq;
                else
                    retval = -EINVAL;
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
	}
	break;
	case OL_ATH_DFS_CHAN_POSTNOL_MODE:
        {
            uint8_t postnol_mode = 0;

            if (dfs_rx_ops && dfs_rx_ops->dfs_get_postnol_mode) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                if(dfs_rx_ops->dfs_get_postnol_mode(pdev, &postnol_mode) ==
                   QDF_STATUS_SUCCESS)
                    *(int *)buff = postnol_mode;
                else
                    retval = -EINVAL;
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
        }
	break;
	case OL_ATH_DFS_CHAN_POSTNOL_CFREQ2:
        {
            uint16_t postnol_cfreq2 = 0;

            if (dfs_rx_ops && dfs_rx_ops->dfs_get_postnol_cfreq2) {
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                        QDF_STATUS_SUCCESS) {
                    return -1;
                }
                if(dfs_rx_ops->dfs_get_postnol_cfreq2(pdev, &postnol_cfreq2) ==
                   QDF_STATUS_SUCCESS)
                    *(int *)buff = postnol_cfreq2;
                else
                    retval = -EINVAL;
                wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
            }
        }
	break;
#endif
        case OL_ATH_PARAM_ENABLE_ADDITIONAL_TRIPLETS:
            *(int *)buff = ic->ic_enable_additional_triplets;
        break;
        case OL_ATH_PARAM_PUNCTURED_BAND:
            *(int *)buff = ic->ic_punctured_band;
        break;
        case OL_ATH_PARAM_OFDMA_MAX_USERS:
            *(int *)buff = ol_ath_get_ofdma_max_users(scn->soc);
            break;
        case OL_ATH_PARAM_MUMIMO_MAX_USERS:
            *(int *)buff = ol_ath_get_mumimo_max_users(scn->soc);
            break;
        case OL_ATH_PARAM_RNR_SELECTIVE_ADD:
            *(int *) buff = ic->ic_flags_ext2 & IEEE80211_FEXT2_RNR_SELECTIVE_ADD;
        break;
        case OL_ATH_PARAM_RNR_STATS:
            if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                qdf_err("command for 6Ghz radio only!!!");
                return -EINVAL;
            }
            ieee80211_display_rnr_stats(ic);
        break;
        case OL_ATH_PARAM_MBSS_AUTOMODE:
            *(int *)buff = ieee80211_ic_mbss_automode_is_set(ic);
        break;
        case OL_ATH_PARAM_NSS_WIFI_OFFLOAD_STATUS:
        {
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            int nss_wifi_ol = (ic->nss_radio_ops) ? 1 : 0;
            qdf_info("NSS WiFi offload status: %s", (nss_wifi_ol) ? "Enabled" : "Disabled");
            *(int *)buff = nss_wifi_ol;
#else
            qdf_info("NSS WiFi offload not supported");
            retval = -EOPNOTSUPP;
#endif
        }
        break;
#if !(defined REMOVE_PKT_LOG) && (defined PKTLOG_DUMP_UPLOAD_SSR)
        case OL_ATH_PARAM_PKTLOG_DUMP_UPLOAD_SSR:
            *(int *)buff = scn->upload_pktlog;
        break;
#endif
        case OL_ATH_PARAM_DISPLAY_PHY_ID:
        {
            struct wlan_lmac_if_reg_tx_ops *reg_tx_ops;
            uint8_t phy_id;

            reg_tx_ops = wlan_reg_get_tx_ops(psoc);
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
                QDF_STATUS_SUCCESS) {
                return -EINVAL;
            }
            if (reg_tx_ops->get_phy_id_from_pdev_id) {
                reg_tx_ops->get_phy_id_from_pdev_id(psoc, pdev_id, &phy_id);
                *(int *)buff = phy_id;
            } else {
                retval = -EINVAL;
            }

            wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
        }
        break;
        case OL_ATH_PARAM_CURCHAN_REG_TXPOWER:
        {
           *(int *)buff = ic->ic_curchan->ic_maxregpower;
        }
        break;
        default:
            return (-1);
    }
    return retval;
}

int
ol_hal_set_config_param(struct ol_ath_softc_net80211 *scn, enum _ol_hal_param_t param, void *buff)
{
    return -1;
}

int
ol_hal_get_config_param(struct ol_ath_softc_net80211 *scn, enum _ol_hal_param_t param, void *address)
{
    return -1;
}

int ol_net80211_set_mu_whtlist(wlan_if_t vap, uint8_t *macaddr,
                               uint16_t tidmask)
{
    int retval = 0;
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vap->vdev_obj);

    retval = ol_ath_node_set_param(pdev, macaddr,
                                   WMI_HOST_PEER_SET_MU_WHITELIST,
                                   tidmask, wlan_vdev_get_id(vap->vdev_obj));
    if (retval)
        qdf_err("Unable to set peer MU white list");
    return retval;
}

#endif /* ATH_PERF_PWR_OFFLOAD */
