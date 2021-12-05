/*
 * Copyright (c) 2015,2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
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

/*
 * LMAC offload interface functions for UMAC - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include <ol_if_athpriv.h>
#include "ol_ath.h"
#include "ol_cfg.h"
#include "ieee80211_bssload.h"
#include <ieee80211_cfg80211.h>

#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include "qdf_lock.h"  /* qdf_spinlock_* */
#include "qdf_types.h" /* qdf_vprint */
#include "dbglog_host.h"
#include "a_debug.h"
#include <wdi_event_api.h>
#include <net.h>
#include <pktlog_ac_api.h>
#include <pktlog_ac_fmt.h>
#include <pktlog_ac_i.h>
#include <ol_if_stats.h>
#include <ol_if_stats_api.h>
#include "osif_private.h"
#if QCA_AIRTIME_FAIRNESS
#include <target_if_atf.h>
#endif
#include "cepci.h"
#include "ath_pci.h"
#include "cdp_txrx_ctrl.h"

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif
#include <wlan_son_pub.h>
#if WLAN_SPECTRAL_ENABLE
#include <target_if_spectral.h>
#endif
#include <init_deinit_lmac.h>

#include "cdp_txrx_stats_struct.h"

#include "target_type.h"

#if ATH_ACS_DEBUG_SUPPORT
#include "acs_debug.h"
#endif

#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif

#if QCA_PARTNER_DIRECTLINK_RX
#define QCA_PARTNER_DIRECTLINK_OL_IF_STATS 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_OL_IF_STATS
#endif /* QCA_PARTNER_DIRECTLINK_RX */

#include <cfg_ucfg_api.h>
#include <dp_rate_stats.h>
#include <wlan_utility.h>

#if UNIFIED_SMARTANTENNA
#include "target_if_sa_api.h"
#endif

#if WLAN_CFR_ENABLE
#include <wlan_cfr_utils_api.h>
#endif

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
#endif
#endif

#if ATH_PERF_PWR_OFFLOAD


char *intr_display_strings[] = {
    "ISR profile data",
    "DSR profile data",
    "SWTASK profile data",
    "DSR LATENCY data",
    "SWTASK LATENCY data",
    0,
};

/*
 * Function num_elements get the number of elements in array intr_display_strings
 */
static
int num_elements(char *intr_display_strings[])
{
    int i;
    for(i=0; intr_display_strings[i]==0;i++);
    return i;
}

#define MAX_STRING_IDX num_elements(intr_display_strings)

int ol_ath_wlan_profile_data_event_handler(ol_soc_t sc, uint8_t *data,
                                           uint32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    u_int32_t i;
    int32_t base;
    int32_t stridx = -1;
    wmi_host_wlan_profile_ctx_t profile_ctx;
    wmi_host_wlan_profile_t profile_data;
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_profile_ctx(wmi_handle, data, &profile_ctx)) {
	qdf_print("Extracting profile ctx failed");
	return -1;
    }

    /* A small state machine implemented here to enable the
     * WMI_WLAN_PROFILE_DATA_EVENTID message to be used iteratively
     * to report > 32 profile points. The target sends a series of
     * events; on the first one in the series, the tot field will
     * be non-zero; subsequent events in the series have tot == 0
     * and are assumed to be a continuation of the first.
     * On the initial record, print the header.
     */
    if (profile_ctx.tot != 0) {
    qdf_nofl_info("\n\t PROFILE DATA\n");
    qdf_nofl_info("Profile duration : %d\n", profile_ctx.tot);
    qdf_nofl_info("Tx Msdu Count    : %d\n", profile_ctx.tx_msdu_cnt);
    qdf_nofl_info("Tx Mpdu Count    : %d\n", profile_ctx.tx_mpdu_cnt);
    qdf_nofl_info("Tx Ppdu Count    : %d\n", profile_ctx.tx_ppdu_cnt);
    qdf_nofl_info("Rx Msdu Count    : %d\n", profile_ctx.rx_msdu_cnt);
    qdf_nofl_info("Rx Mpdu Count    : %d\n", profile_ctx.rx_mpdu_cnt);

    qdf_nofl_info("Profile ID   Count   Total      Min      Max   hist_intvl  hist[0]   hist[1]   hist[2]\n");
        base = 0;
    } else {
        base = -1;
    }

    for(i=0; i<profile_ctx.bin_count; i++) {
        uint32_t id;
	if (wmi_extract_profile_data(wmi_handle, data, i, &profile_data)) {
	    qdf_print("Extracting profile data failed");
	    return -1;
	}
	id = profile_data.id;
        if (profile_ctx.tot == 0) {
            if (base == -1) {
                stridx = 0;
                base = 0;
                qdf_nofl_info("\n%s\n", intr_display_strings[stridx]);
            } else if (((id - base) > 32) && (stridx < MAX_STRING_IDX)) {
                stridx++;
                base += 32;
                qdf_nofl_info("\n%s\n", intr_display_strings[stridx]);
            }
        }

        qdf_nofl_info("%8d   %8d %8d %8d %8d     %8d %8d %8d %8d\n", profile_data.id - base,
            profile_data.cnt, profile_data.tot,
            profile_data.min, profile_data.max,
            profile_data.hist_intvl, profile_data.hist[0],
            profile_data.hist[1], profile_data.hist[2]);

    }

    qdf_nofl_info("\n");
    return 0;
}

int
convert_wmi_host_chan_info_to_periodic_chan_stats(
        wmi_host_chan_info_event *chan_info_ev,
        struct ieee80211_mib_cycle_cnts *new_stats)
{
    new_stats->cycle_count = chan_info_ev->cycle_count;
    new_stats->rx_clear_count = chan_info_ev->rx_clear_count;
    new_stats->rx_frame_count = chan_info_ev->rx_frame_count;
    new_stats->my_bss_rx_cycle_count = chan_info_ev->my_bss_rx_cycle_count;
    new_stats->tx_frame_count = chan_info_ev->tx_frame_cnt;
    new_stats->rx_clear_ext_count = chan_info_ev->rx_clear_ext20_count;
    new_stats->rx_clear_ext40_count = chan_info_ev->rx_clear_ext40_count;
    new_stats->rx_clear_ext80_count = chan_info_ev->rx_clear_ext80_count;

    return EOK;
}

static inline uint32_t ol_get_wraparound_offset(struct wlan_objmgr_psoc *psoc)
{
    /* In Beeliner family chipsets, cycle counters like tx_frame_count,
     * rx_frame_count and rx_clear_count saturates and starts from 0x7FFFFFFF
     * when they reach max value of 0xFFFFFFFF.
     * Whereas in Lithium, cycle counters wraps from 0xFFFFFFFF to 0x0 where
     * offset to be subrated is 0x0.
     */
    if (ol_target_lithium(psoc))
        return 0;
    else
        return (IEEE80211_MAX_32BIT_UNSIGNED_VALUE >> 1); /* 0x7FFFFFFF */
}

QDF_STATUS ol_find_chan_stats_delta(struct ieee80211com *ic,
                                    periodic_chan_stats_t *pstats,
                                    periodic_chan_stats_t *nstats,
                                    periodic_chan_stats_t *delta)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    uint32_t offset;

    /* Peregrine hardware design is such that when cycle counter reaches
     * 0xffffffff, cycle counters along with other counters are right shifted by
     * one bit in same cycle. As we don't know the max value of different
     * HW counters before wrapping, there is no way to calculate correct
     * channel utilization for Peregrine family.
     *
     * For Beeliner, Cascade, Besra etc, all HW counters reach their max value
     * of 0xffffffff on their own and then wrap to 0x7fffffff. Here we know
     * the max value of different counters (0xffffffff) before wrap around so
     * channel utilization can be calculated correctly.
     */

    /* Drop Peregrine wrap around cases */
    if (!(lmac_is_target_ar900b(psoc) || ol_target_lithium(psoc)) &&
        (pstats->cycle_count > nstats->cycle_count)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL,
                             IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                             "%s: ignoring due to counter wrap around:"
                             "p_cycle: %u, n_cycle: %u, p_rx_clear: %u,"
                             "n_rx_clear: %u, p_mybss_rx: %u, n_mybss_rx: %u\n",
                             __func__, pstats->cycle_count, nstats->cycle_count,
                             pstats->rx_clear_count, nstats->rx_clear_count,
                             pstats->my_bss_rx_cycle_count,
                             nstats->my_bss_rx_cycle_count);
        return QDF_STATUS_E_INVAL;
    }

    /* We are here it means either it's beeliner/Lithium family or non wrap
     * aroud case. Calculate different delta counts based on previous mib
     * counters and new mib counters.
     */
    offset = ol_get_wraparound_offset(psoc);

    if (pstats->cycle_count > nstats->cycle_count) {
        delta->cycle_count = (IEEE80211_MAX_32BIT_UNSIGNED_VALUE -
                              pstats->cycle_count) +
                             (nstats->cycle_count - offset);
    } else {
        delta->cycle_count = nstats->cycle_count - pstats->cycle_count;
    }

    if (pstats->rx_clear_count > nstats->rx_clear_count) {
        delta->rx_clear_count = (IEEE80211_MAX_32BIT_UNSIGNED_VALUE -
                                 pstats->rx_clear_count) +
                                (nstats->rx_clear_count - offset);
    } else {
        delta->rx_clear_count = nstats->rx_clear_count - pstats->rx_clear_count;
    }

    if (pstats->tx_frame_count > nstats->tx_frame_count) {
        delta->tx_frame_count = (IEEE80211_MAX_32BIT_UNSIGNED_VALUE -
                                 pstats->tx_frame_count) +
                                (nstats->tx_frame_count - offset);
    } else {
        delta->tx_frame_count = nstats->tx_frame_count - pstats->tx_frame_count;
    }

    if (pstats->my_bss_rx_cycle_count > nstats->my_bss_rx_cycle_count) {
        delta->my_bss_rx_cycle_count = IEEE80211_MAX_32BIT_UNSIGNED_VALUE -
                                       pstats->my_bss_rx_cycle_count +
                                       nstats->my_bss_rx_cycle_count;
    } else {
        delta->my_bss_rx_cycle_count = nstats->my_bss_rx_cycle_count -
                                       pstats->my_bss_rx_cycle_count;
    }

    if (pstats->rx_frame_count > nstats->rx_frame_count) {
        delta->rx_frame_count = (IEEE80211_MAX_32BIT_UNSIGNED_VALUE -
                                 pstats->rx_frame_count) +
                                (nstats->rx_frame_count - offset);
    } else {
        delta->rx_frame_count = nstats->rx_frame_count - pstats->rx_frame_count;
    }

    if (pstats->rx_clear_ext_count > nstats->rx_clear_ext_count) {
        delta->rx_clear_ext_count = (IEEE80211_MAX_32BIT_UNSIGNED_VALUE -
                                     pstats->rx_clear_ext_count) +
                                    (nstats->rx_clear_ext_count - offset);
    } else {
        delta->rx_clear_ext_count = nstats->rx_clear_ext_count -
                                    pstats->rx_clear_ext_count;
    }

    /* Suggested workarounds for corner cases by HW team */
    if (delta->rx_clear_count < (delta->tx_frame_count +
                                 delta->rx_frame_count)) {
        delta->rx_clear_count = (delta->tx_frame_count +
                                 delta->rx_frame_count);
    }

    if (delta->my_bss_rx_cycle_count > delta->rx_frame_count) {
        delta->my_bss_rx_cycle_count = delta->rx_frame_count;
    }

    return QDF_STATUS_SUCCESS;
}

int ol_scan_chan_stats_update(struct ieee80211com *ic,
                              wmi_host_chan_info_event *chan_info_ev)
{
    int i = 0;
    uint8_t flag = (uint8_t)chan_info_ev->cmd_flags;
    struct scan_chan_entry_stats *entry_stats = NULL;
    struct ieee80211_mib_cycle_cnts new_stats = {0};
    struct ieee80211_mib_cycle_cnts delta = {0};
    struct channel_stats *chan_stats = &(ic->ic_channel_stats.scan_chan_stats[0]);

    convert_wmi_host_chan_info_to_periodic_chan_stats(chan_info_ev, &new_stats);
    entry_stats = &(ic->ic_channel_stats.entry_stats);

    qdf_spin_lock_bh(&ic->ic_channel_stats.lock);
    if (flag == WMI_CHAN_INFO_FLAG_START_RESP) {
       entry_stats->freq = chan_info_ev->freq;
       entry_stats->stats = new_stats;
    } else if (flag == WMI_CHAN_INFO_FLAG_END_RESP) {
        if ((!entry_stats->stats.cycle_count) ||
                (entry_stats->freq != chan_info_ev->freq)) {
            qdf_mem_zero(entry_stats, sizeof(*entry_stats));
            qdf_spin_unlock_bh(&ic->ic_channel_stats.lock);
            return -EINVAL;
        }
    } else if (flag == WMI_CHAN_INFO_FLAG_END_DIFF) {
        entry_stats->freq = chan_info_ev->freq;
    }

    if ((flag == WMI_CHAN_INFO_FLAG_END_DIFF) || (flag == WMI_CHAN_INFO_FLAG_END_RESP)) {
        if (ol_find_chan_stats_delta(ic, &entry_stats->stats,
                                     &new_stats, &delta)) {
            qdf_mem_zero(entry_stats, sizeof(*entry_stats));
            qdf_spin_unlock_bh(&ic->ic_channel_stats.lock);
            return -EINVAL;
        }
        for (i = 0; i < NUM_CHANNELS; i++) {
            if ((chan_stats[i].freq == entry_stats->freq) ||
                (chan_stats[i].freq == 0)) {
                chan_stats[i].freq = entry_stats->freq;
                chan_stats[i].cycle_cnt += delta.cycle_count;
                chan_stats[i].clear_cnt += delta.rx_clear_count;
                chan_stats[i].tx_frm_cnt += delta.tx_frame_count;
                chan_stats[i].rx_frm_cnt += delta.rx_frame_count;
                chan_stats[i].bss_rx_cnt += delta.my_bss_rx_cycle_count;
                break;
            }
        }
        qdf_mem_zero(entry_stats, sizeof(*entry_stats));
    }

    qdf_spin_unlock_bh(&ic->ic_channel_stats.lock);
    return EOK;
}

/*
 * WMI event handler for Channel info WMI event
 */
static int
ol_ath_chan_info_event_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    u_int8_t flags;
    uint16_t ieee_chan_freq;
    int16_t chan_nf;
    struct ieee80211_chan_stats chan_stats;
    wmi_host_chan_info_event chan_info_ev = {0};
#if ATH_SUPPORT_ICM
    struct external_acs_obj *extacs_handle;
    struct scan_chan_info schan_info;
#endif
    struct wmi_unified *wmi_handle;
    struct wmi_unified *pdev_wmi_handle;
    struct wlan_objmgr_pdev *pdev;
    cdp_config_param_type value = {0};

    wmi_host_chan_info_event *event = (wmi_host_chan_info_event *)&chan_info_ev;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_chan_info_event(wmi_handle, data, &chan_info_ev) !=
                                     QDF_STATUS_SUCCESS) {
           qdf_print("Failed to extract chan_info event");
           return -1;
    }
    /* pdev_id is derived from vdev_id. pdev_id will be invalid if vdev is not
     * active or logically deleted or vdev_id is invalid.
     */
    if (chan_info_ev.pdev_id == WLAN_INVALID_PDEV_ID || chan_info_ev.pdev_id >= 3) {
           qdf_print("%s:pdev id derived from vdev_id %d is invalid.",
                                               __func__, chan_info_ev.vdev_id);
           return -1;
    }

    if (event->freq == 0) {
        if (event->cmd_flags == WMI_CHAN_INFO_FLAG_START_RESP) {
               qdf_print("%s: invalid frequency %d ", __func__, event->freq);
               return -1;
        } else {
               return 0;
        }
    }
    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(chan_info_ev.pdev_id), WLAN_MLME_SB_ID);
    if (pdev == NULL) {
         qdf_print("%s: pdev object (id: %d) is NULL ", __func__,
                                               PDEV_UNIT(chan_info_ev.pdev_id));
         return -1;
    }

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (scn == NULL) {
         qdf_print("%s: scn (id: %d) is NULL ", __func__,
                                               PDEV_UNIT(chan_info_ev.pdev_id));
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }
    ic = &scn->sc_ic;
    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    if (pdev_wmi_handle == NULL) {
         qdf_print("%s: pdev WMI handle (id: %d) is NULL ", __func__, chan_info_ev.pdev_id);
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_ACS,
                   "  Chan Info event status_code:%d pdev_idx:%d vdev_id:%d\n"
                   "  freq:%d, flags:0x%x, noise_floor:%d, rx_clr_dur:%d, rx_cycle_dur:%d\n"
                   "  rx_frame_cnt:%d tx_frame_cnt:%d my_bss_rx_cycle_dur:%d rx_11b_mode_data_dur: %d\n"
                   "  tx power(range:%d tp:%d) mac_clk_mhz:%d\n", event->err_code, event->pdev_id, event->vdev_id,
                   event->freq, event->cmd_flags, event->noise_floor,event->rx_clear_count, event->cycle_count,
                   event->rx_frame_count, event->tx_frame_cnt, event->my_bss_rx_cycle_count, event->rx_11b_mode_data_duration,
                   event->chan_tx_pwr_range, event->chan_tx_pwr_tp, event->mac_clk_mhz);

    if (event->err_code == 0) {
       ieee_chan_freq = event->freq;

       if (wmi_service_enabled(pdev_wmi_handle, wmi_service_chan_load_info)) {
           flags = WMI_CHAN_INFO_FLAG_END_DIFF;
       } else {
           flags = (u_int8_t)event->cmd_flags;
       }

       event->cmd_flags = flags;
       chan_nf = (int16_t)event->noise_floor;
       chan_stats.chan_clr_cnt = event->rx_clear_count;
       chan_stats.cycle_cnt = event->cycle_count;
       chan_stats.chan_tx_power_range = event->chan_tx_pwr_range;
       chan_stats.chan_tx_power_tput = event->chan_tx_pwr_tp;
       chan_stats.duration_11b_data  = event->rx_11b_mode_data_duration;
       qdf_mem_copy(chan_stats.perchain_nf, event->per_chain_noise_floor,
               sizeof(chan_stats.perchain_nf));
#if ATH_ACS_DEBUG_SUPPORT
       if (ic->ic_acs_debug_support) {
           acs_debug_add_chan_event_acs(&chan_stats, &chan_nf, ieee_chan_freq, ic->ic_acs);
           acs_debug_add_bcn(soc, ic, ieee_chan_freq);
       }
#endif
       ol_scan_chan_stats_update(ic, event);
       ieee80211_acs_stats_update(ic->ic_acs, flags, ieee_chan_freq, chan_nf, &chan_stats);
       if (flags == WMI_CHAN_INFO_FLAG_BEFORE_END_RESP ||
                flags == WMI_CHAN_INFO_FLAG_END_DIFF) {
           ol_txrx_soc_handle soc_txrx_handle;
           soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);

           scn->chan_nf = chan_nf;
           value.cdp_pdev_param_chn_noise_flr = scn->chan_nf;
           cdp_txrx_set_pdev_param(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(pdev),
                                   CDP_CHAN_NOISE_FLOOR, value);
       }

#if ATH_SUPPORT_ICM
       if (ic->ic_extacs_obj.icm_active) {
           extacs_handle = &ic->ic_extacs_obj;
#if ATH_ACS_DEBUG_SUPPORT
           /* To update the scan channel information for ICM Debug */
           if (ic->ic_acs_debug_support) {
               acs_debug_add_chan_event_icm(&chan_stats, &chan_nf,
                                           ieee_chan_freq, flags, &schan_info);
           } else
#endif
           {
               schan_info.freq           = event->freq;
               schan_info.cmd_flag       = flags;
               schan_info.noise_floor    = event->noise_floor;
               schan_info.cycle_count    = event->cycle_count;
               schan_info.rx_clear_count = event->rx_clear_count;
               schan_info.tx_frame_count = event->tx_frame_cnt;
               schan_info.clock_freq     = event->mac_clk_mhz;
               schan_info.tx_power_tput  = event->chan_tx_pwr_tp;
               schan_info.tx_power_range = event->chan_tx_pwr_range;
           }
           ieee80211_extacs_record_schan_info(extacs_handle, &schan_info, wlan_reg_freq_to_chan(ic->ic_pdev_obj, ieee_chan_freq));
       }
#endif
    } else {
          /** FIXME Handle it, whenever channel freq mismatch occurs in target */
       qdf_print("Err code is non zero, Failed to read stats from target ");
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    return 0;
}

static void ol_ath_net80211_set_noise_detection_param(struct ieee80211com *ic, int cmd,int val)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int8_t flush_stats = 0;
#define IEEE80211_ENABLE_NOISE_DETECTION 1
#define IEEE80211_NOISE_THRESHOLD 2
    switch(cmd)
    {
        case IEEE80211_ENABLE_NOISE_DETECTION:
            if (val) {
                scn->sc_enable_noise_detection = val;
                /* Disabling DCS as soon as we enable noise detection algo */
                ic->ic_disable_dcscw(ic);

                flush_stats = 1;
                ol_ath_pdev_set_param(scn->sc_pdev,
                                      wmi_pdev_param_noise_detection, val);
            }
          break;
        case IEEE80211_NOISE_THRESHOLD:
            if (val) {
                scn->sc_noise_floor_th = val;
                ol_ath_pdev_set_param(scn->sc_pdev,
                                      wmi_pdev_param_noise_threshold, val);
                flush_stats = 1;
            }
          break;

        default:
              qdf_nofl_info("UNKNOWN param %s %d \n",__func__,__LINE__);
          break;
    }
    if(flush_stats) {
        scn->sc_noise_floor_report_iter = 0;
        scn->sc_noise_floor_total_iter = 0;
    }
#undef IEEE80211_ENABLE_NOISE_DETECTION
#undef IEEE80211_NOISE_THRESHOLD
    return;
}


static void ol_ath_net80211_get_noise_detection_param(struct ieee80211com *ic, int cmd,int *val)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#define IEEE80211_ENABLE_NOISE_DETECTION 1
#define IEEE80211_NOISE_THRESHOLD 2
#define IEEE80211_GET_COUNTER_VALUE 3
    switch(cmd)
    {
        case IEEE80211_ENABLE_NOISE_DETECTION:
          *val = scn->sc_enable_noise_detection;
          break;
        case IEEE80211_NOISE_THRESHOLD:
          *val =(int) scn->sc_noise_floor_th;
          break;
        case IEEE80211_GET_COUNTER_VALUE:
          if( scn->sc_noise_floor_total_iter) {
              *val =  (scn->sc_noise_floor_report_iter *100)/scn->sc_noise_floor_total_iter;
          } else
              *val = 0;
          break;
        default:
              qdf_nofl_info("UNKNOWN param %s %d \n",__func__,__LINE__);
          break;
    }
#undef IEEE80211_ENABLE_NOISE_DETECTION
#undef IEEE80211_NOISE_THRESHOLD
    return;

}

static int
ol_ath_channel_hopping_event_handler(ol_scn_t sc, u_int8_t *data,
                                    u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct ol_ath_softc_net80211 *scn;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_pdev *pdev;

    wmi_host_pdev_channel_hopping_event channel_hopping_event;
    wmi_host_pdev_channel_hopping_event *event =
            (wmi_host_pdev_channel_hopping_event *) &channel_hopping_event;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if(wmi_extract_channel_hopping_event(wmi_handle, data, event) !=
                 QDF_STATUS_SUCCESS) {
          qdf_print("Failed to extract channel hopping event");
          return -1;
    }
    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(event->pdev_id), WLAN_MLME_SB_ID);
    if (pdev == NULL) {
         qdf_print("%s: pdev object (id: %d) is NULL ", __func__, PDEV_UNIT(event->pdev_id));
         return -1;
    }

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (scn == NULL) {
         qdf_print("%s: scn (id: %d) is NULL ", __func__, PDEV_UNIT(event->pdev_id));
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }

    scn->sc_noise_floor_report_iter = event->noise_floor_report_iter;
    scn->sc_noise_floor_total_iter = event->noise_floor_total_iter;
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);

    return 0;
}
/*
 * Registers WMI event handler for Channel info event
 */
void
ol_ath_chan_info_attach(struct ieee80211com *ic)
{
    /*used as part of channel hopping algo to trigger noise detection in counter window */
    ic->ic_set_noise_detection_param     = ol_ath_net80211_set_noise_detection_param;
    ic->ic_get_noise_detection_param     = ol_ath_net80211_get_noise_detection_param;

    return;
}

void
ol_ath_soc_chan_info_attach(ol_ath_soc_softc_t *soc)
{
    wmi_unified_t wmi_handle;

    wmi_handle = lmac_get_wmi_unified_hdl(soc->psoc_obj);
    /* Register WMI event handlers */
    wmi_unified_register_event_handler(wmi_handle,
                    wmi_chan_info_event_id,
                   ol_ath_chan_info_event_handler, WMI_RX_UMAC_CTX);

    wmi_unified_register_event_handler(wmi_handle,
                   wmi_pdev_channel_hopping_event_id,
                   ol_ath_channel_hopping_event_handler, WMI_RX_UMAC_CTX);

    return;
}

/*
 * Unregisters WMI event handler for Channel info event
 */
void ol_ath_soc_chan_info_detach(ol_ath_soc_softc_t *soc)
{
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    /* Unregister ACS event handler */
    wmi_unified_unregister_event_handler((void *)wmi_handle,
                                          wmi_chan_info_event_id);

    wmi_unified_unregister_event_handler((void *)wmi_handle,
                                          wmi_pdev_channel_hopping_event_id);

    return;
}

/*
 * Prepares and Sends the WMI cmd to retrieve channel info from Target
 */
static void
ol_ath_get_chan_info(struct ieee80211com *ic, u_int8_t flags)
{
    /* In offload architecture this is stub function
       because target chan information is indicated as events timely
       (No need to poll for the chan info
     */
}

/**
* @brief    sets chan_stats to zero to mark invalid stats
*
* @param ic pointer to struct ieee80211com
*
* @return   0
*/
inline int
ol_ath_invalidate_channel_stats(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    qdf_mem_zero(&(scn->scn_dcs.chan_stats), sizeof(scn->scn_dcs.chan_stats));
    return 0;
}

/**
* @brief            Calculate obss and self bss utilization
*                   and invoke API's to send it to user space
*
* @param ic         pointer to ieee80211com
* @param pstats     previous saved stats
* @param nstats     new stats
* @param delta      stats delta
*/
void ol_chan_stats_event (struct ieee80211com *ic,
                          periodic_chan_stats_t *pstats,
                          periodic_chan_stats_t *nstats)
{
    uint8_t total_cu = 0;
    uint8_t ap_tx_cu = 0;
    uint8_t ap_rx_cu = 0;
    uint8_t self_util = 0;
    uint8_t obss_util = 0;
    uint8_t rx_obss_cu = 0;
    uint8_t non_wifi_cu = 0;
    uint8_t num_of_ss = 0;
    struct ol_ath_softc_net80211 *scn = NULL;
    periodic_chan_stats_t delta = {0};
    union iwreq_data wrqu;
    char buf[128];
#ifdef QCA_SUPPORT_CP_STATS
    struct pdev_ic_cp_stats *pdev_cps = NULL;
    struct pdev_dcs_chan_stats *pdev_chan_stats = NULL;
#endif

    if (!pstats || !nstats) {
        return;
    }

    /* If previous stats is 0, we don't have previous counter
     * values and we can't find utilization for last period.
     */
     if (pstats->cycle_count == 0) {
         return;
     }

    scn = OL_ATH_SOFTC_NET80211(ic);

    if (ol_find_chan_stats_delta(ic, pstats, nstats, &delta)) {
        qdf_err("Unable to derive chan stats delta");
        return;
    }

    /* Sanitize cycle_count value to make sure divide by zero error
     * is not encountered. Also if cycle count delta is zero, the stats
     * recorded are not proper. So return here.
     */
    if(delta.cycle_count == 0) {
        return;
    }

    /* Calculate self bss and obss channel utilization
     * based on previous mib counters and new mib counters
     */
    /* Calculate total wifi + non wifi channel utilization percentage */
    total_cu = ((delta.rx_clear_count) / (delta.cycle_count / 100));;
    /* Calculate total AP wlan Tx channel utilization percentage */
    ap_tx_cu = ((delta.tx_frame_count) / (delta.cycle_count / 100));
    /* Calculate total AP wlan Rx channel utilization percentage */
    ap_rx_cu = ((delta.my_bss_rx_cycle_count) / (delta.cycle_count / 100));
    /* Calculate total Rx channel utilization percentage */
    rx_obss_cu = ((delta.rx_frame_count - delta.my_bss_rx_cycle_count) /
                  (delta.cycle_count / 100));

    /* Calculate Non-wifi channel utilization percentage */
    non_wifi_cu = ((delta.rx_clear_count -
                    (delta.tx_frame_count + delta.rx_frame_count)) /
                   (delta.cycle_count / 100));

    /* Self bss channel utilization is sum of AP Tx and AP Rx utilization */
    self_util = ap_tx_cu + ap_rx_cu;

    /* Other bss channel utilization is:
     * Total utilization - seld bss  utilization
     */
    obss_util = total_cu - self_util;

    num_of_ss = ieee80211com_get_spatialstreams(ic);
#ifdef QCA_SUPPORT_CP_STATS
    pdev_cps = wlan_get_pdev_cp_stats_ref(ic->ic_pdev_obj);
    if (pdev_cps) {
        pdev_chan_stats = &pdev_cps->stats.chan_stats;
        if (num_of_ss == 0 || delta.tx_frame_count == 0) {
            pdev_chan_stats->dcs_ss_under_util = 0;
        } else {
            pdev_chan_stats->dcs_ss_under_util =
                     ((((num_of_ss * delta.rx_clear_count) -
                         delta.tx_frame_count) /
                      (num_of_ss * delta.tx_frame_count)) * 255);
        }

        pdev_chan_stats->dcs_self_bss_util = self_util;
        pdev_chan_stats->dcs_obss_util = obss_util;
        pdev_chan_stats->dcs_obss_rx_util = rx_obss_cu;
        pdev_chan_stats->dcs_ap_rx_util = ap_rx_cu;
        pdev_chan_stats->dcs_ap_tx_util = ap_tx_cu;
        pdev_chan_stats->dcs_free_medium = (100 - total_cu);
        pdev_chan_stats->dcs_non_wifi_util = non_wifi_cu;
        pdev_chan_stats->dcs_sec_20_util = nstats->rx_clear_ext_count;
        pdev_chan_stats->dcs_sec_40_util = nstats->rx_clear_ext40_count;
        pdev_chan_stats->dcs_sec_80_util = nstats->rx_clear_ext80_count;
    }
#endif

    qdf_spin_lock_bh(&ic->ic_channel_stats.lock);
    ic->ic_channel_stats.home_chan_stats.freq =
        (ic->ic_curchan ? ic->ic_curchan->ic_freq : 0);
    ic->ic_channel_stats.home_chan_stats.cycle_cnt += delta.cycle_count;
    ic->ic_channel_stats.home_chan_stats.clear_cnt += delta.rx_clear_count;
    ic->ic_channel_stats.home_chan_stats.tx_frm_cnt += delta.tx_frame_count;
    ic->ic_channel_stats.home_chan_stats.rx_frm_cnt += delta.rx_frame_count;
    ic->ic_channel_stats.home_chan_stats.bss_rx_cnt += delta.my_bss_rx_cycle_count;
    ic->ic_channel_stats.home_chan_stats.ext_busy_cnt += delta.rx_clear_ext_count;
    qdf_spin_unlock_bh(&ic->ic_channel_stats.lock);

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL,
            IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
            "p_cycle: %u, n_cycle: %u, p_rx_clear: %u, n_rx_clear: %u, "
            "p_tx: %u, n_tx: %u, p_mybss_rx: %u, p_rx: %u, n_rx: %u, "
            "n_mybss_rx: %u, obss: %u, self: %u\n, ap_rx_cu=%u, ap_tx_cu=%u, "
            "total_cu=%u, non_wifi_cu=%u rxclr_delta=%d, tx_frame_delta=%d, "
            "rx_frame_delta=%d cycle_count_delta=%d\n",
            pstats->cycle_count, nstats->cycle_count, pstats->rx_clear_count,
            nstats->rx_clear_count, pstats->tx_frame_count,
            nstats->tx_frame_count, pstats->my_bss_rx_cycle_count,
            nstats->my_bss_rx_cycle_count, pstats->rx_frame_count,
            nstats->rx_frame_count, rx_obss_cu, self_util, ap_rx_cu, ap_tx_cu,
            total_cu, non_wifi_cu, delta.rx_clear_count, delta.tx_frame_count,
            delta.rx_frame_count, delta.cycle_count);

#if UMAC_SUPPORT_ACFG
    /* send acfg event with channel stats now */
    acfg_chan_stats_event(ic, self_util, obss_util);
#endif
    /* Send iwevent with the channel Utilization info */
    snprintf(buf, sizeof(buf), "Channel Utilization:"
             "AP Rx:%d Unused:%d AP Tx:%d OBSS Rx:%d",
              ap_rx_cu, (100 - total_cu), ap_tx_cu, rx_obss_cu);
    qdf_mem_zero(&wrqu, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    WIRELESS_SEND_EVENT(ic->ic_osdev->netdev, IWEVCUSTOM, &wrqu, buf);
}

static void ol_ath_vap_iter_update_chanutil(void *arg, wlan_if_t vap)
{
    if (vap->iv_bcn_offload_enable || vap->iv_special_vap_mode || (vap->iv_opmode == IEEE80211_M_MONITOR)) {
#if UMAC_SUPPORT_QBSSLOAD
        if (ieee80211_vap_qbssload_is_set(vap) || ieee80211_vap_oce_is_set(vap)) {
            if (!ieee80211_is_bcca_ongoing_for_any_vap(vap->iv_ic)) {
                wlan_vdev_beacon_update(vap);
            }
        } else {
            ieee80211_beacon_chanutil_update(vap);
        }
#elif UMAC_SUPPORT_CHANUTIL_MEASUREMENT
        if (vap->iv_chanutil_enab) {
            if (ieee80211_vap_qbssload_is_set(vap)) {
                if (!ieee80211_is_bcca_ongoing_for_any_vap(vap->iv_ic)) {
                    wlan_vdev_beacon_update(vap);
                }
            } else {
                ieee80211_beacon_chanutil_update(vap);
            }
        }
#endif
    }
}

static void ol_ath_vap_iter_update_txpow(void *arg, wlan_if_t vap)
{
    struct ieee80211_node *ni;
    u_int16_t oldTxpow;
    u_int16_t txpowlevel = *((u_int32_t *) arg);
    QDF_STATUS status;

    /*
     * If VAP delete is in progress, then ignore txpow update
     */
    if (vap && !ieee80211_vap_deleted_is_set(vap)) {
        ni = ieee80211vap_get_bssnode(vap);
        if (ni == NULL) {
           return;
        }
        ASSERT(ni);
        status = wlan_objmgr_try_ref_node(ni, WLAN_CP_STATS_ID);
        if (QDF_IS_STATUS_ERROR(status)) {
            return;
        }
        oldTxpow = ieee80211_node_get_txpower(ni);
        ieee80211node_set_txpower(ni, txpowlevel);
        wlan_objmgr_free_node(ni, WLAN_CP_STATS_ID);

        if (txpowlevel != oldTxpow) {
            wlan_vdev_beacon_update(vap);
            son_send_txpower_change_event(vap->vdev_obj, txpowlevel);
        }
    }
}

void ol_ath_sched_ppdu_stats(struct ol_ath_softc_net80211 *scn, struct ieee80211com *ic, void *data, uint8_t dir)
{
    qdf_nbuf_t nbuf = (qdf_nbuf_t) data;
    struct ieee80211_node *ni;
    struct ieee80211vap *vap = NULL;

    struct cdp_tx_completion_ppdu *cdp_tx_ppdu;
    struct cdp_rx_indication_ppdu *cdp_rx_ppdu;
#if  ATH_DATA_TX_INFO_EN
    qdf_nbuf_t dropnbuf = NULL;
    struct ol_ath_txrx_ppdu_info_ctx *ppdu_stats_ctx;
#endif
    struct cdp_tx_completion_ppdu *ppdu_desc;
    struct cdp_tx_completion_ppdu_user *ppdu_user_desc;
    int i;

    if (dir == 0) {
#if  ATH_DATA_TX_INFO_EN
        ppdu_stats_ctx = scn->tx_ppdu_stats_ctx;
#endif
        cdp_tx_ppdu = (struct cdp_tx_completion_ppdu *) qdf_nbuf_data(nbuf);
        /* for MU case we recieve user information from BA */
        if (cdp_tx_ppdu->frame_type == CDP_PPDU_FTYPE_CTRL)
            goto exit;
        ppdu_desc = cdp_tx_ppdu;
        for (i = 0; i < ppdu_desc->num_users; i++) {
            ppdu_user_desc = &ppdu_desc->user[i];

        }
    } else {
#if  ATH_DATA_TX_INFO_EN
        ppdu_stats_ctx = scn->rx_ppdu_stats_ctx;
#endif
        cdp_rx_ppdu = (struct cdp_rx_indication_ppdu *)nbuf->data;

        if (cdp_rx_ppdu->peer_id == CDP_INVALID_PEER)
            goto exit;

        vap = ol_ath_vap_get(scn, cdp_rx_ppdu->vdev_id);
        if(vap == NULL) {
          if ((!scn->soc->hw_mode_ctx.is_switch_in_progress) &&
              (!(scn->soc->hw_mode_ctx.dynamic_hw_mode ==
                 WMI_HOST_DYNAMIC_HW_MODE_FAST))) {
                qdf_warn("%s:%d VAP instance is NULL",__func__,__LINE__);
            }
            goto exit;
        }

        if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_bss_is_set(vap->wnm)) {
            ni = ieee80211_find_node(ic, cdp_rx_ppdu->mac_addr, WLAN_MLME_SB_ID);
            if (ni)
            {
                uint8_t fc1 = (cdp_rx_ppdu->frame_ctrl & 0xFF00) >> 8;
                int secured = 0;

                if(fc1 & IEEE80211_FC1_WEP)
                    secured = 1;

                ieee80211_wnm_bssmax_updaterx(ni, secured);
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            }
        }

        ol_ath_release_vap(vap);
    }

#if  ATH_DATA_TX_INFO_EN
    if (!scn->enable_perpkt_txstats)
#endif
        goto exit;

#if  ATH_DATA_TX_INFO_EN
    qdf_spin_lock(&ppdu_stats_ctx->lock);
#endif

    /* if the queue is full, drop the entries */
#if  ATH_DATA_TX_INFO_EN
    if (qdf_nbuf_queue_len(&ppdu_stats_ctx->nbufq) >
                    OL_ATH_PPDU_STATS_BACKLOG_MAX) {
            dropnbuf = qdf_nbuf_queue_remove(&ppdu_stats_ctx->nbufq);
            qdf_assert_always(dropnbuf);
            qdf_nbuf_free(dropnbuf);
    }

    qdf_nbuf_queue_add(&ppdu_stats_ctx->nbufq, nbuf);

    qdf_spin_unlock(&ppdu_stats_ctx->lock);

    qdf_sched_work(scn->soc->qdf_dev, &ppdu_stats_ctx->work);
#endif
    return;
exit:
    qdf_nbuf_free(nbuf);
    return;
}
/**
  * qdf_nbuf_t() - Clone nbuf and returns pointer
  *
  * return : nbuf pointer in success & NULL in failure
  */
static inline qdf_nbuf_t clone_nbuf(qdf_nbuf_t nbuf)
{
    qdf_nbuf_t msg_copy;
    msg_copy = qdf_nbuf_clone(nbuf);
    if (!msg_copy) {
        qdf_warn("Failed to clone nbuf");
        return NULL;
    }
    return msg_copy;
}

#if UNIFIED_SMARTANTENNA
/*
 * sa_process_tx_feedback() - Wrapper function for sa_tx_processing.
 * @pdev_obj : wlan_objmgr_pdev
 * @nbuf     : qdf_nbuf_t
 *
 * Process for all user in desc and then free nbuf.
 */
static inline void sa_process_tx_feedback(struct wlan_objmgr_pdev *pdev_obj,
                                          qdf_nbuf_t nbuf)
{
    uint8_t usr_iter;
    struct cdp_tx_completion_ppdu *cdp_tx_ppdu =
        (struct cdp_tx_completion_ppdu *)qdf_nbuf_data(nbuf);

    for (usr_iter = 0; usr_iter < cdp_tx_ppdu->num_users; usr_iter++)
        target_if_sa_api_process_tx_feedback(pdev_obj, &cdp_tx_ppdu->user[usr_iter]);

    /* free cloned nbuf */
    qdf_nbuf_free(nbuf);
}

/*
 * sa_process_rx_feedback() - Wrapper function for sa_rx_processing.
 * @pdev_obj : wlan_objmgr_pdev
 * @nbuf     : qdf_nbuf_t
 */
static inline void sa_process_rx_feedback(struct wlan_objmgr_pdev *pdev_obj,
                                          qdf_nbuf_t nbuf)
{
    struct cdp_rx_indication_ppdu *cdp_rx_ppdu =
        (struct cdp_rx_indication_ppdu *)qdf_nbuf_data(nbuf);

    target_if_sa_api_process_rx_feedback(pdev_obj, cdp_rx_ppdu);

    /* free cloned nbuf */
    qdf_nbuf_free(nbuf);
}
#endif

/*
 * ol_ath_process_rate_stats() - Process wlan_peer_update_rate_stats
 * @pdev    : pdev object
 * @event   : WDI_EVENT
 * @peer_id : peer id
 * @status  : htt_cmn_rx_status
 * @nbuf    : qdf_nbuf_t
 *
 * Return: none
 */
static inline void
ol_ath_process_rate_stats(struct wlan_objmgr_pdev *pdev,
                          enum WDI_EVENT event, uint16_t peer_id,
                          enum htt_cmn_rx_status status, qdf_nbuf_t nbuf)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);
    ol_txrx_soc_handle soc_txrx_handle;
    void *rate_stats_ctx;

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    rate_stats_ctx = cdp_soc_get_rate_stats_ctx(soc_txrx_handle);
    wlan_peer_update_rate_stats(rate_stats_ctx, event,
                                (void *)nbuf, peer_id, status);
}


void ol_ath_process_ppdu_stats(void *pdev_hdl, enum WDI_EVENT event,
                               void *data, uint16_t peer_id,
                               enum htt_cmn_rx_status status)
{
    struct wlan_objmgr_pdev *pdev_obj = (struct wlan_objmgr_pdev *)pdev_hdl;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    qdf_nbuf_t nbuf = (qdf_nbuf_t) data;
    qdf_nbuf_t msg_copy;
#if defined(UNIFIED_SMARTANTENNA) || defined(QCA_AIRTIME_FAIRNESS)
    struct wlan_objmgr_psoc *psoc;
#endif
#if defined(WLAN_CFR_ENABLE) && defined(WLAN_ENH_CFR_ENABLE)
    ol_txrx_soc_handle soc_txrx_handle;
    uint8_t pdev_id;
#endif

    if (qdf_unlikely((!pdev_obj || !data))) {
        qdf_err("Invalid pdev %p or data %p for event %d", pdev_obj, data, event);
        qdf_nbuf_free(nbuf);
        return;
    }
    ic = wlan_pdev_get_mlme_ext_obj(pdev_obj);
    if (!ic) {
        qdf_err("Invalid ic %p", ic);
        qdf_nbuf_free(nbuf);
        return;
    }

#if defined(UNIFIED_SMARTANTENNA) || defined(QCA_AIRTIME_FAIRNESS)
    wlan_pdev_obj_lock(pdev_obj);
    psoc = wlan_pdev_get_psoc(pdev_obj);
    wlan_pdev_obj_unlock(pdev_obj);
    if (!psoc) {
        qdf_err("Invalid Psoc %p", psoc);
        qdf_nbuf_free(nbuf);
        return;
    }
#endif
    scn = OL_ATH_SOFTC_NET80211(ic);

    switch(event) {
        case WDI_EVENT_TX_PPDU_DESC:
            if ((msg_copy = clone_nbuf(nbuf)))
                ol_ath_sched_ppdu_stats(scn, ic, (void *)msg_copy, 0);

            if (scn->soc->rdkstats_enabled) {
                if ((msg_copy = clone_nbuf(nbuf)))
                    ol_ath_process_rate_stats(pdev_obj, event, peer_id, status,
                                              msg_copy);
            }
            /* process tx ppdu desc if sniffer is enabled */
            if (scn->sc_ic.ic_debug_sniffer) {
                if ((msg_copy = clone_nbuf(nbuf)))
                    ol_ath_process_tx_metadata(ic, (void *)msg_copy);
            }
#if UNIFIED_SMARTANTENNA
            /* smart antenna tx handler */
            if (target_if_sa_api_is_tx_feedback_enabled(psoc, pdev_obj)) {
                if ((msg_copy = clone_nbuf(nbuf)))
                    sa_process_tx_feedback(pdev_obj, msg_copy);
            }
#endif
#if QCA_AIRTIME_FAIRNESS
            if (target_if_atf_stats_enabled(psoc, pdev_obj)) {
                if ((msg_copy = clone_nbuf(nbuf))) {
                    target_if_atf_process_ppdu_stats(psoc, pdev_obj, msg_copy);
                }
            }
#endif
            qdf_nbuf_free(nbuf);
            break;
        case WDI_EVENT_RX_PPDU_DESC:
            if ((msg_copy = clone_nbuf(nbuf)))
                ol_ath_sched_ppdu_stats(scn, ic, (void *)msg_copy, 1);

            if (scn->soc->rdkstats_enabled) {
                if ((msg_copy = clone_nbuf(nbuf)))
                    ol_ath_process_rate_stats(pdev_obj, event, peer_id, status,
                                              msg_copy);
            }
            /* process m_copy if sniffer is enabled */
            if (ol_ath_is_mcopy_enabled(&scn->sc_ic)) {
                if ((msg_copy = clone_nbuf(nbuf)))
                    ol_ath_process_rx_metadata(ic, (void *)msg_copy);
            }
#if UNIFIED_SMARTANTENNA
            /* smart antenna rx handler */
            if (target_if_sa_api_is_rx_feedback_enabled(psoc, pdev_obj)) {
                if ((msg_copy = clone_nbuf(nbuf)))
                    sa_process_rx_feedback(pdev_obj, msg_copy);
            }
#endif

#if defined(WLAN_CFR_ENABLE) && defined(WLAN_ENH_CFR_ENABLE)
            soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
            pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev_obj);

            if (cdp_get_cfr_rcc(soc_txrx_handle, pdev_id)) {
                    if ((msg_copy = clone_nbuf(nbuf)))
                            wlan_cfr_rx_tlv_process(pdev_obj, (void *)msg_copy);
            }
#endif

            qdf_nbuf_free(nbuf);
            break;
        case WDI_EVENT_TX_MSDU_DESC:
            qdf_warn("%s Not supported event %d", __func__, event);
            break;
        default:
            qdf_warn("%s Not supported event %d", __func__, event);
            break;
    }
}
static int
ol_update_peer_stats(struct ieee80211_node *ni,wmi_host_peer_stats *peer_stats)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = NULL;
    struct ieee80211vap *vap = NULL;
    uint32_t last_tx_rate_mcs = 0;
    int32_t sgi;
    struct ieee80211_mac_stats *mac_stats = NULL;
#if !ALL_POSSIBLE_RATES_SUPPORTED
    int nss, ch_width;
    struct ieee80211_bwnss_map nssmap = {0};
    u_int8_t tx_chainmask;
    uint32_t iv_nss;
#endif

    if(ni) {
        vap = ni->ni_vap;
        ic = vap->iv_ic;
        scn = OL_ATH_SOFTC_NET80211(ic);

        mac_stats =  ( ni == vap->iv_bss ) ? &vap->iv_multicast_stats : &vap->iv_unicast_stats;
        ni->ni_snr = peer_stats->peer_rssi;

        if (ic->ic_min_snr_enable) {
            if (ni != ni->ni_bss_node && vap->iv_opmode == IEEE80211_M_HOSTAP) {
                /* compare the user provided rssi with peer rssi received */
                if (ni->ni_associd && ni->ni_snr && (ic->ic_min_snr > ni->ni_snr)) {
                    /* send de-auth to ni_macaddr */
                    qdf_nofl_info( "Client %s(snr = %u) de-authed due to insufficient SNR\n",
                                   ether_sprintf(ni->ni_macaddr), ni->ni_snr);
                    ieee80211_try_mark_node_for_delayed_cleanup(ni);
                    wlan_mlme_deauth_request(vap, ni->ni_macaddr, IEEE80211_REASON_UNSPECIFIED);
                    return -1;
                }
            }
        }
        if(ni->ni_snr < ni->ni_snr_min)
            ni->ni_snr_min = ni->ni_snr;
        else if (ni->ni_snr > ni->ni_snr_max)
            ni->ni_snr_max = ni->ni_snr;

        if(!ieee80211_is_phymode_11ax(vap->iv_cur_mode))
           sgi = vap->iv_data_sgi;
        else
           sgi = vap->iv_he_data_sgi;

#if ALL_POSSIBLE_RATES_SUPPORTED
	if(scn->soc->ol_if_ops->kbps_to_mcs) {
		mac_stats->ims_last_tx_rate_mcs =
			scn->soc->ol_if_ops->kbps_to_mcs(mac_stats->ims_last_tx_rate,
				       			vap->iv_data_sgi,
							phymode_to_htflag(vap->iv_cur_mode));
        	last_tx_rate_mcs = scn->soc->ol_if_ops->kbps_to_mcs(
					peer_stats->peer_tx_rate, sgi , phymode_to_htflag(vap->iv_cur_mode));
	}
#else
        wlan_util_vdev_mlme_get_param(vap->vdev_mlme,
                WLAN_MLME_CFG_NSS, &iv_nss);
        nss = (iv_nss >
                ieee80211_getstreams(ic, ic->ic_tx_chainmask)) ?
                ieee80211_getstreams(ic, ic->ic_tx_chainmask)  :
                iv_nss;

        ch_width = wlan_get_param(vap, IEEE80211_CHWIDTH);

        if (ch_width == IEEE80211_CWM_WIDTH160 || ch_width == IEEE80211_CWM_WIDTH80_80) {
            tx_chainmask = ieee80211com_get_tx_chainmask(ic);
            ieee80211_get_bw_nss_mapping(vap, &nssmap, tx_chainmask);
            nss = nssmap.bw_nss_160;
        }
	if(scn->soc->ol_if_ops->kbps_to_mcs) {
	        mac_stats->ims_last_tx_rate_mcs =
			scn->soc->ol_if_ops->kbps_to_mcs(mac_stats->ims_last_tx_rate,
                                                         vap->iv_data_sgi,
                                                         phymode_to_htflag(vap->iv_cur_mode),
                                                         nss,
                                                         ch_width);

        	last_tx_rate_mcs = scn->soc->ol_if_ops->kbps_to_mcs(
					peer_stats->peer_tx_rate, sgi , 0, 0);
	}
#endif
            cdp_update_peer_stats(wlan_psoc_get_dp_handle(scn->soc->psoc_obj), wlan_vdev_get_id(vap->vdev_obj), ni->ni_macaddr,
                                                              peer_stats, last_tx_rate_mcs,
                                                              WMI_HOST_REQUEST_PEER_STAT);
    }

    return 0;
}
/*
 * WMI event handler for periodic target stats event
 */
static int
ol_ath_update_stats_event_handler(ol_scn_t sc, u_int8_t *data,
                                    u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com *ic;
    struct ieee80211_node *ni;
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
#if QCA_AIRTIME_FAIRNESS
    struct wlan_objmgr_peer *peer = NULL;
#endif
    A_UINT8 i;
    u_int8_t c_macaddr[QDF_MAC_ADDR_SIZE];
    wmi_host_stats_event stats_param = {0};
    struct wmi_unified *wmi_handle;
#ifdef QCA_SUPPORT_CP_STATS
    struct pdev_ic_cp_stats *pdev_cps = NULL;
#endif
    struct wlan_objmgr_pdev *pdev;
    cdp_config_param_type value = {0};
    bool is_mbssid_enable;
    bool is_ema_enable;

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    OS_MEMZERO(&stats_param, sizeof(wmi_host_stats_event));
    if (wmi_extract_stats_param(wmi_handle, data, &stats_param) !=
              QDF_STATUS_SUCCESS) {
         QDF_TRACE(QDF_MODULE_ID_CP_STATS, QDF_TRACE_LEVEL_INFO,
                 "Failed to extract stats");
         return -1;
    }

#ifdef QCA_SUPPORT_CP_STATS
    cp_stats_debug("pdev_id[%d] stats_id[0x%x]",
                   stats_param.pdev_id, stats_param.stats_id);

    cp_stats_debug("num_pdev_stats[%u] num_pdev_ext_stats[%u] num_vdev_stats[%u] num_peer_stats[%u]",
                   stats_param.num_pdev_stats, stats_param.num_pdev_ext_stats,
                   stats_param.num_vdev_stats, stats_param.num_peer_stats);
    cp_stats_debug("num_peer_extd_stats[%u] num_bcnflt_stats[%u] num_chan_stats[%u] num_bcn_stats[%u]",
                   stats_param.num_peer_extd_stats,
                   stats_param.num_bcnflt_stats,
                   stats_param.num_chan_stats, stats_param.num_bcn_stats);
    cp_stats_debug("num_rssi_stats[%u] num_peer_adv_stats[%u] num_mib_stats[%u] num_mib_extd_stats[%u]",
                   stats_param.num_rssi_stats, stats_param.num_peer_adv_stats,
                   stats_param.num_mib_stats, stats_param.num_mib_extd_stats);
    cp_stats_debug("num_peer_stats_info_ext[%u] num_vdev_extd_stats[%u] last_event[%u]",
                   stats_param.num_peer_stats_info_ext,
                   stats_param.num_vdev_extd_stats,
                   stats_param.last_event);
#endif

    pdev = wlan_objmgr_get_pdev_by_id(psoc, PDEV_UNIT(stats_param.pdev_id), WLAN_MLME_SB_ID);
    if (pdev == NULL) {
         qdf_print("%s: pdev object (id: %d) is NULL ", __func__, PDEV_UNIT(stats_param.pdev_id));
         return -1;
    }

    is_mbssid_enable = wlan_pdev_nif_feat_cap_get(pdev,
                                                  WLAN_PDEV_F_MBSS_IE_ENABLE);
    is_ema_enable =
           wlan_pdev_nif_feat_ext_cap_get(pdev, WLAN_PDEV_FEXT_EMA_AP_ENABLE);

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (scn == NULL) {
         qdf_print("%s: scn (id: %d) is NULL ",
                              __func__, PDEV_UNIT(stats_param.pdev_id));
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }
    ic = &scn->sc_ic;
#ifdef QCA_SUPPORT_CP_STATS
    pdev_cps = wlan_get_pdev_cp_stats_ref(ic->ic_pdev_obj);
    if (!pdev_cps) {
         qdf_print("Failed to get pdev cp stats reference");
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }
#endif
    if (stats_param.num_pdev_stats > 0) {
        wmi_host_pdev_stats st_pdev_stats;
        wmi_host_pdev_stats *pdev_stats = &st_pdev_stats;

        for (i = 0; i < stats_param.num_pdev_stats; i++) {
            ol_txrx_soc_handle soc_txrx_handle;
            soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
            qdf_mem_set(pdev_stats, sizeof(wmi_host_pdev_stats), 0);

            wmi_extract_pdev_stats(wmi_handle, data, i, pdev_stats);
            if (ic->ic_is_target_lithium(psoc))
                scn->cur_hw_nf = pdev_stats->chan_nf;
            else
                scn->chan_nf = scn->cur_hw_nf = pdev_stats->chan_nf;

            value.cdp_pdev_param_chn_noise_flr = scn->chan_nf;
            cdp_txrx_set_pdev_param(soc_txrx_handle,
                                    wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
                                    CDP_CHAN_NOISE_FLOOR,
                                    value);
            scn->mib_cycle_cnts.tx_frame_count = pdev_stats->tx_frame_count;
            scn->mib_cycle_cnts.rx_frame_count = pdev_stats->rx_frame_count;
            scn->mib_cycle_cnts.rx_clear_count = pdev_stats->rx_clear_count;
            scn->mib_cycle_cnts.rx_clear_ext_count = pdev_stats->rx_clear_count;
            scn->mib_cycle_cnts.rx_clear_ext40_count = pdev_stats->rx_clear_count;
            scn->mib_cycle_cnts.rx_clear_ext80_count = pdev_stats->rx_clear_count;
            scn->mib_cycle_cnts.cycle_count = pdev_stats->cycle_count;
            scn->chan_stats.chan_clr_cnt = pdev_stats->rx_clear_count;
            scn->chan_stats.cycle_cnt = pdev_stats->cycle_count;
            scn->chan_stats.phy_err_cnt = pdev_stats->phy_err_count;
            scn->chan_tx_pwr = pdev_stats->chan_tx_pwr;
            wlan_iterate_vap_list(ic, ol_ath_vap_iter_update_txpow,(void *) &scn->chan_tx_pwr);
            wlan_iterate_vap_list(ic, ol_ath_vap_iter_update_chanutil, NULL);
#ifdef QCA_SUPPORT_CP_STATS
            pdev_cps->stats.cs_rx_ack_err = pdev_stats->ackRcvBad;
            pdev_cps->stats.cs_rx_rts_err = pdev_stats->rtsBad;
            pdev_cps->stats.cs_rx_rts_success = pdev_stats->rtsGood;
            pdev_cps->stats.cs_no_beacons = pdev_stats->noBeacons;
            pdev_cps->stats.cs_mib_int_count = pdev_stats->mib_int_count;
            pdev_cps->stats.cs_chan_nf = pdev_stats->chan_nf;
            pdev_cps->stats.cs_tx_frame_count = pdev_stats->tx_frame_count;
            pdev_cps->stats.cs_rx_frame_count = pdev_stats->rx_frame_count;
            pdev_cps->stats.cs_rx_clear_count = pdev_stats->rx_clear_count;
            pdev_cps->stats.cs_cycle_count = pdev_stats->cycle_count;
            pdev_cps->stats.cs_phy_err_count = pdev_stats->phy_err_count;
            pdev_cps->stats.cs_chan_tx_pwr = scn->chan_tx_pwr;
            pdev_cps->stats.cs_fcsbad = pdev_stats->fcsBad;
#endif
            /* Peer stats */
#ifdef QCA_SUPPORT_CP_STATS
            pdev_cps->stats.cs_rx_phy_err = scn->ath_stats.rx.phy_errs;
#endif
            cdp_update_pdev_host_stats(wlan_psoc_get_dp_handle(psoc),
                                       wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj),
                                       &pdev_stats->pdev_stats,
                                       WMI_HOST_REQUEST_PDEV_STAT);

        }
    }

    if (stats_param.num_pdev_ext_stats > 0) {
            wmi_host_pdev_ext_stats st_pdev_ext_stats;
            wmi_host_pdev_ext_stats *pdev_ext_stats = &st_pdev_ext_stats;
            i = 0;

            wmi_extract_pdev_ext_stats(wmi_handle, data, i, pdev_ext_stats);

#ifdef QCA_SUPPORT_CP_STATS
            pdev_cps->stats.cs_rx_rssi_comb = (pdev_ext_stats->rx_rssi_comb & RX_RSSI_COMB_MASK);
            /* rssi of separate chains */
            RSSI_CHAIN_STATS(pdev_ext_stats->rx_rssi_chain0, pdev_cps->stats.cs_rx_rssi_chain0);
            RSSI_CHAIN_STATS(pdev_ext_stats->rx_rssi_chain1, pdev_cps->stats.cs_rx_rssi_chain1);
            RSSI_CHAIN_STATS(pdev_ext_stats->rx_rssi_chain2, pdev_cps->stats.cs_rx_rssi_chain2);
            RSSI_CHAIN_STATS(pdev_ext_stats->rx_rssi_chain3, pdev_cps->stats.cs_rx_rssi_chain3);
            pdev_cps->stats.cs_tx_rssi= pdev_ext_stats->ack_rssi;
#endif

#define HOST_PDEV_EXTD_STATS 0x100
            cdp_update_pdev_host_stats(wlan_psoc_get_dp_handle(psoc),
                                       wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj),
                                       pdev_ext_stats,
                                       HOST_PDEV_EXTD_STATS);
    }

    if (stats_param.num_vdev_stats > 0) {
          for (i = 0; i < stats_param.num_vdev_stats; i++) {
            wmi_host_vdev_stats vdev_stats;

            wmi_extract_vdev_stats(wmi_handle, data, i, &vdev_stats);
            cdp_update_host_vdev_stats(wlan_psoc_get_dp_handle(psoc),
                                       &vdev_stats,
                                       sizeof(wmi_host_vdev_stats),
                                       WMI_HOST_REQUEST_VDEV_STAT);
        }
    }

    if (stats_param.num_peer_stats > 0) {
        ic = &scn->sc_ic;
        for (i = 0; i < stats_param.num_peer_stats; i++) {
            wmi_host_peer_stats st_peer_stats;
            wmi_host_peer_stats *peer_stats = &st_peer_stats;

            wmi_extract_peer_stats(wmi_handle, data, i, peer_stats);

            WMI_HOST_MAC_ADDR_TO_CHAR_ARRAY(&peer_stats->peer_macaddr, c_macaddr);
            ni = ieee80211_find_node(ic, c_macaddr, WLAN_MLME_SB_ID);
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
            if(ni && ni->ni_vap && wlan_is_psta(ni->ni_vap)) {
#else
            if(ni && ni->ni_vap && dp_wrap_vdev_is_psta(ni->ni_vap->vdev_obj)) {
#endif
                struct ieee80211vap *tmpvap = NULL;
                struct ieee80211_node *tmp_bss_ni = NULL;

                if(!peer_stats->peer_rssi) {
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                    //temp += sizeof(wmi_peer_stats);
                    continue;
                }

                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
#if WLAN_QWRAP_LEGACY
                    if((ni->ni_vap != tmpvap) && wlan_is_psta(tmpvap)) {
#else
                    if((ni->ni_vap != tmpvap) && dp_wrap_vdev_is_psta(tmpvap->vdev_obj)) {
#endif
                        tmp_bss_ni = ieee80211_try_ref_bss_node(tmpvap, WLAN_MLME_SB_ID);

                        if(tmp_bss_ni) {
                            ol_update_peer_stats(tmp_bss_ni,peer_stats);
                            ieee80211_free_node(tmp_bss_ni, WLAN_MLME_SB_ID);
                            tmp_bss_ni = NULL;
                        }
                    }
                }
            }
#endif

            if (ni) {
                if(ol_update_peer_stats(ni,peer_stats)) {
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                    //temp += sizeof(wmi_peer_stats);
                    continue;
                }

                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            }
        }
    }
    /*Go to the end of buffer after bcnfilter*/
//    temp += (ev->num_bcnflt_stats * sizeof(wmi_bcnfilter_stats_t));
    if (stats_param.stats_id & WMI_HOST_REQUEST_PEER_EXTD_STAT) {
        if(stats_param.num_peer_stats  > 0) {
            ic = &scn->sc_ic;
            for (i = 0; i < stats_param.num_peer_stats; i++) {
                uint32_t last_tx_rate_mcs = 0;
                wmi_host_peer_extd_stats st_peer_extd_stats;
                wmi_host_peer_extd_stats *peer_extd_stats = &st_peer_extd_stats;

                wmi_extract_peer_extd_stats(wmi_handle, data, i, peer_extd_stats);

                WMI_HOST_MAC_ADDR_TO_CHAR_ARRAY(&peer_extd_stats->peer_macaddr, c_macaddr);

                ni = ieee80211_find_node(ic, c_macaddr, WLAN_MLME_SB_ID);
                if (ni) {
                    cdp_update_peer_stats(wlan_psoc_get_dp_handle(scn->soc->psoc_obj),
                                            wlan_vdev_get_id(ni->ni_vap->vdev_obj), ni->ni_macaddr,
                                            peer_extd_stats, last_tx_rate_mcs, WMI_HOST_REQUEST_PEER_EXTD_STAT);
#if QCA_AIRTIME_FAIRNESS
                    if (target_if_atf_get_mode(psoc)) {
                        peer = wlan_objmgr_get_peer(psoc, stats_param.pdev_id, c_macaddr, WLAN_ATF_ID);
                        if (peer) {
                            target_if_atf_set_token_allocated(psoc, peer,
                                        (A_UINT16)peer_extd_stats->atf_tokens_allocated);
                            target_if_atf_set_token_utilized(psoc, peer,
                                        (A_UINT16)peer_extd_stats->atf_tokens_utilized);
                            wlan_objmgr_peer_release_ref(peer, WLAN_ATF_ID);
                        }
                    }
#endif
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                }
//                temp += sizeof(wmi_peer_extd_stats);
            }
        }
    }

    if (stats_param.stats_id & WMI_HOST_REQUEST_VDEV_EXTD_STAT) {
        for (i = 0; i < stats_param.num_vdev_stats; i++) {
            wmi_host_vdev_extd_stats vdev_extd_stats;

            wmi_extract_vdev_extd_stats(wmi_handle, data, i, &vdev_extd_stats);
            cdp_update_host_vdev_stats(wlan_psoc_get_dp_handle(psoc),
                                       &vdev_extd_stats,
                                       sizeof(wmi_host_vdev_extd_stats),
                                       WMI_HOST_REQUEST_VDEV_EXTD_STAT);
        }
    }

    if (stats_param.stats_id & WMI_HOST_REQUEST_BCN_STAT) {
        for (i = 0; i < stats_param.num_bcn_stats; i++) {
            struct ieee80211vap *vap;
            wmi_host_bcn_stats vdev_bcn_stats;

            wmi_extract_bcn_stats(wmi_handle, data, i, &vdev_bcn_stats);
            vap = ol_ath_vap_get(scn, vdev_bcn_stats.vdev_id);

            if (!is_mbssid_enable) {
                if (!vap)
                    continue;
#ifdef QCA_SUPPORT_CP_STATS
                    vdev_cp_stats_tx_bcn_outage_update(vap->vdev_obj,
                                              vdev_bcn_stats.tx_bcn_outage_cnt);
                    vdev_cp_stats_tx_bcn_success_update(vap->vdev_obj,
                                              vdev_bcn_stats.tx_bcn_succ_cnt);
#endif
            } else {
                struct ieee80211vap *temp_vap;
                bool is_non_tx_vap;

                if (!vap)
                    continue;

                is_non_tx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
                if (is_non_tx_vap) {
                    QDF_TRACE(QDF_MODULE_ID_CP_STATS, QDF_TRACE_LEVEL_INFO,
                              "VAP from fw is not a tx vap. vdevid given = %d",
                              vdev_bcn_stats.vdev_id);
                    ol_ath_release_vap(vap);
                    continue;
                }

                TAILQ_FOREACH(temp_vap, &ic->ic_vaps, iv_next) {
                    if (ieee80211_mbss_is_beaconing_ap(temp_vap)) {
#ifdef QCA_SUPPORT_CP_STATS
                        vdev_cp_stats_tx_bcn_outage_update(temp_vap->vdev_obj,
                                              vdev_bcn_stats.tx_bcn_outage_cnt);
                        vdev_cp_stats_tx_bcn_success_update(temp_vap->vdev_obj,
                                              vdev_bcn_stats.tx_bcn_succ_cnt);
#endif
                    }
                }
            }
            qdf_atomic_inc(&(vap->vap_bcn_event));
            vap->vap_bcn_stats_time = OS_GET_TICKS();
            ol_ath_release_vap(vap);
        }
    }


    if (stats_param.stats_id & WMI_HOST_REQUEST_VDEV_PRB_FILS_STAT) {
        struct ieee80211vap *vap;
        struct ieee80211vap *temp_vap;
        struct wmi_host_vdev_prb_fils_stats vdev_prb_fils_stats = {0};

        ic = &scn->sc_ic;
        for (i = 0; i < stats_param.num_vdev_extd_stats; i++) {
            wmi_extract_vdev_prb_fils_stats(wmi_handle, data, i,
                                       &vdev_prb_fils_stats);

            vap = ol_ath_vap_get(scn, vdev_prb_fils_stats.vdev_id);

            qdf_debug("scn: %p, i: %d, num_stats: %d, vap: %p, vdev_id: %d FD_S:%d FD_F:%d UN_PRB_S:%d UN_PRB_F:%d\n",
                      scn, i, stats_param.num_vdev_extd_stats, vap,
                      vdev_prb_fils_stats.vdev_id,
                      vdev_prb_fils_stats.fd_succ_cnt,
                      vdev_prb_fils_stats.fd_fail_cnt,
                      vdev_prb_fils_stats.unsolicited_prb_succ_cnt,
                      vdev_prb_fils_stats.unsolicited_prb_fail_cnt);

            if (vap && vap->iv_opmode != IEEE80211_M_HOSTAP) {
                ol_ath_release_vap(vap);
                continue;
            }

            if (vap) {
#ifdef QCA_SUPPORT_CP_STATS
                vdev_cp_stats_tx_offload_prb_resp_succ_cnt_update(
                            vap->vdev_obj,
                            vdev_prb_fils_stats.unsolicited_prb_succ_cnt);
                vdev_cp_stats_tx_offload_prb_resp_fail_cnt_update(
                            vap->vdev_obj,
                            vdev_prb_fils_stats.unsolicited_prb_fail_cnt);
                if (is_mbssid_enable && (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
                    && !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
                    TAILQ_FOREACH(temp_vap, &ic->ic_vaps, iv_next) {
                        vdev_cp_stats_fils_frames_sent_update(temp_vap->vdev_obj,
                                               vdev_prb_fils_stats.fd_succ_cnt);
                        vdev_cp_stats_fils_frames_sent_fail_update(temp_vap->vdev_obj,
                                               vdev_prb_fils_stats.fd_fail_cnt);
		    }
                }
#endif
                qdf_atomic_inc(&(vap->vap_prb_fils_event));
                ol_ath_release_vap(vap);
            }

        }
    }

    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
/*
    Extension stats extract API needs to be added - TBD
    if(ev->stats_id & WMI_REQUEST_PDEV_EXT2_STAT) {
       wmi_pdev_ext2_stats *pdev_ext2_stats =  (wmi_pdev_ext2_stats *)temp;
       scn->chan_nf_sec80 = pdev_ext2_stats->chan_nf_sec80;
       temp += sizeof(wmi_pdev_ext2_stats);
    }
*/
#if ATH_SUPPORT_NAC_RSSI
    if (stats_param.stats_id & WMI_HOST_REQUEST_NAC_RSSI) {
        struct ieee80211vap *vap = 0;
        char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        struct wmi_host_vdev_nac_rssi_event nac_rssi_stats;
        struct wmi_unified *pdev_wmi_handle;

        pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);

        if (!pdev_wmi_handle) {
            qdf_debug("Pdev WMI handle is NULL");
            goto esc_nac_rssi;
        }

        wmi_extract_vdev_nac_rssi_stats(pdev_wmi_handle, data,  &nac_rssi_stats);
        vap = ol_ath_vap_get(scn, nac_rssi_stats.vdev_id);
        if (vap) {
            if ((IEEE80211_ADDR_EQ(vap->iv_nac_rssi.bssid_mac, nullmac)) ||
                (IEEE80211_ADDR_EQ(vap->iv_nac_rssi.client_mac, nullmac))) {
                qdf_print("Extract NAC_RSSI Wrong VAP%d", nac_rssi_stats.vdev_id);
                ol_ath_release_vap(vap);
                return 0;
            }
            if (nac_rssi_stats.avg_rssi != 0) {
                vap->iv_nac_rssi.client_rssi = nac_rssi_stats.avg_rssi;
                vap->iv_nac_rssi.client_rssi_valid = (nac_rssi_stats.rssi_seq_num == 0) ? 0 : 1;
            }
            ol_ath_release_vap(vap);
        }
    }
esc_nac_rssi:
#endif
    if (stats_param.stats_id & WMI_HOST_REQUEST_PEER_RETRY_STAT) {
       if(stats_param.num_peer_stats  > 0) {
            ic = &scn->sc_ic;
            for (i = 0; i < stats_param.num_peer_stats; i++) {
                uint32_t last_tx_rate_mcs = 0;
                struct wmi_host_peer_retry_stats st_peer_retry_stats;
                struct wmi_host_peer_retry_stats *peer_retry_stats = &st_peer_retry_stats;
                wmi_extract_peer_retry_stats(wmi_handle, data, i, peer_retry_stats);
                WMI_HOST_MAC_ADDR_TO_CHAR_ARRAY(&peer_retry_stats->peer_macaddr, c_macaddr);
                ni = ieee80211_find_node(ic, c_macaddr, WLAN_MLME_SB_ID);
                if (ni) {
                    cdp_update_peer_stats(wlan_psoc_get_dp_handle(scn->soc->psoc_obj),
                                          wlan_vdev_get_id(ni->ni_vap->vdev_obj), ni->ni_macaddr,
                                          peer_retry_stats,
                                          last_tx_rate_mcs,
                                          WMI_HOST_REQUEST_PEER_RETRY_STAT);
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                }
            }
        }
    }
    return 0;
}

static void
ol_ath_net80211_get_cur_chan_stats(struct ieee80211com *ic, struct ieee80211_chan_stats *chan_stats)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    chan_stats->chan_clr_cnt = scn->chan_stats.chan_clr_cnt;
    chan_stats->cycle_cnt = scn->chan_stats.cycle_cnt;
    chan_stats->phy_err_cnt = scn->chan_stats.phy_err_cnt;
}

static int
ol_ath_bss_chan_info_event_handler(ol_scn_t sc, u_int8_t *data, u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    wmi_host_pdev_bss_chan_info_event bss_chan_info;
    wmi_host_pdev_bss_chan_info_event *chan_stats = &bss_chan_info;
    struct ol_ath_softc_net80211 *scn;
    uint32_t target_type;

    struct hw_params {
        char name[10];
        uint64_t channel_counters_freq;
    };

    static const struct hw_params hw_params_list[] = {
        {
            .name = "ar9888",
            .channel_counters_freq = 88000,
        },
        {
            .name = "ipq4019",
            .channel_counters_freq = 125000,
        },
        {
            .name = "qca9984",
            .channel_counters_freq = 150000,
        },
        {
            .name = "qca9888",
            .channel_counters_freq = 150000,
        },
        {
            .name = "ar900b",
            .channel_counters_freq = 150000,
        },
    };

    const struct hw_params *target;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_pdev *pdev;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_bss_chan_info_event(wmi_handle, data, &bss_chan_info) !=
                   QDF_STATUS_SUCCESS) {
        qdf_print("Failed to extract bss chan info");
    }
    target_type = lmac_get_tgt_type(soc->psoc_obj);

    if(target_type == TARGET_TYPE_AR9888)
            target = &hw_params_list[0];
    else if(target_type == TARGET_TYPE_IPQ4019)
            target = &hw_params_list[1];
    else if(target_type == TARGET_TYPE_QCA9984)
            target = &hw_params_list[2];
    else if(target_type == TARGET_TYPE_QCA9888)
            target = &hw_params_list[3];
    else {
            qdf_print("Error: not enabled for target type");
            return 0;
        }

    pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj, PDEV_UNIT(bss_chan_info.pdev_id), WLAN_MLME_SB_ID);
    if (pdev == NULL) {
         qdf_print("%s: pdev object (id: %d) is NULL ", __func__, PDEV_UNIT(bss_chan_info.pdev_id));
         return -1;
    }

    scn = lmac_get_pdev_feature_ptr(pdev);
    if (scn == NULL) {
         qdf_print("%s: scn (id: %d) is NULL ", __func__, PDEV_UNIT(bss_chan_info.pdev_id));
         wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
         return -1;
    }

    if(chan_stats && !scn->tx_rx_time_info_flag) {
        qdf_print("BSS Chan info stats :");
        qdf_print("Frequency               : %d",chan_stats->freq);
        qdf_print("noise_floor             : %d",chan_stats->noise_floor);
        qdf_print("rx_clear_count_low      : %u",chan_stats->rx_clear_count_low);
        qdf_print("rx_clear_count_high     : %u",chan_stats->rx_clear_count_high);
        qdf_print("cycle_count_low         : %u",chan_stats->cycle_count_low);
        qdf_print("cycle_count_high        : %u",chan_stats->cycle_count_high);
        qdf_print("tx_cycle_count_low      : %u",chan_stats->tx_cycle_count_low);
        qdf_print("tx_cycle_count_high     : %u",chan_stats->tx_cycle_count_high);
        qdf_print("rx_cycle_count_low      : %u",chan_stats->rx_cycle_count_low);
        qdf_print("rx_cycle_count_high     : %u",chan_stats->rx_cycle_count_high);
        qdf_print("rx_bss_cycle_count_low  : %u",chan_stats->rx_bss_cycle_count_low);
        qdf_print("rx_bss_cycle_count_high : %u",chan_stats->rx_bss_cycle_count_high);
    }
    else if(chan_stats && scn->tx_rx_time_info_flag) {
        uint64_t tx_cycle_count = (uint64_t) chan_stats->tx_cycle_count_high << 32 |
            chan_stats->tx_cycle_count_low;
        uint64_t rx_cycle_count = (uint64_t) chan_stats->rx_cycle_count_high << 32 |
            chan_stats->rx_cycle_count_low;
        uint64_t rx_bss_cycle_count = (uint64_t) chan_stats->rx_bss_cycle_count_high << 32 |
            chan_stats->rx_bss_cycle_count_low;
        uint64_t rx_outside_bss_cycle_count = rx_cycle_count - rx_bss_cycle_count;
        uint64_t cycle_count = (uint64_t) chan_stats->cycle_count_high << 32 |
            chan_stats->cycle_count_low;
        uint64_t tx_duration = div_u64(tx_cycle_count, target->channel_counters_freq);
        uint64_t rx_duration = div_u64(rx_cycle_count, target->channel_counters_freq);
        uint64_t rx_in_bss_duration = div_u64(rx_bss_cycle_count,
            target->channel_counters_freq);
        uint64_t rx_outside_bss_dur = div_u64(rx_outside_bss_cycle_count,
            target->channel_counters_freq);
        uint64_t total_duration = div_u64(cycle_count, target->channel_counters_freq);

        qdf_print("tx rx info stats :");

        qdf_print("tx cycle count                : %llu", tx_cycle_count);
        qdf_print("rx cycle count                : %llu", rx_cycle_count);
        qdf_print("rx inside bss cycle count     : %llu", rx_bss_cycle_count);
        qdf_print("rx outside bss cycle count    : %llu\n", rx_outside_bss_cycle_count);

        qdf_print("tx duration(msec)             : %llu", tx_duration);
        qdf_print("rx duration(msec)             : %llu", rx_duration);
        qdf_print("rx inside bss duration(msec)  : %llu", rx_in_bss_duration);
        qdf_print("rx outside bss duration(msec) : %llu", rx_outside_bss_dur);
        qdf_print("total duration(msec)          : %llu\n", total_duration);

        qdf_print("tx duration(%%)               : %llu", div_u64(tx_duration*100,
            total_duration));
        qdf_print("rx duration(%%)               : %llu", div_u64(rx_duration*100,
            total_duration));
        qdf_print("rx inside bss duration(%%)    : %llu",
            div_u64(rx_in_bss_duration*100, total_duration));
        qdf_print("rx outside bss duration(%%)   : %llu",
            div_u64(rx_outside_bss_dur*100, total_duration));
        scn->tx_rx_time_info_flag = 0;
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
    return 0;
}

extern void ieee80211_update_ack_rssi(struct ieee80211_node *ni, int rssi);

/*
 * stats_id is a bitmap of wmi_stats_id- pdev/vdev/peer
 */

static int
ol_ath_rssi_cb(ol_scn_t sc,
                u_int8_t *data,
                u_int32_t datalen)
{
    ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *) sc;
    struct wlan_objmgr_peer *peer_obj = NULL;
    wmi_host_inst_stats_resp inst_rssi_resp;
    wmi_host_inst_stats_resp *ev = &inst_rssi_resp;
    u_int8_t c_macaddr[QDF_MAC_ADDR_SIZE];
    struct wmi_unified *wmi_handle;
    struct ieee80211_node *ni = NULL;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (wmi_extract_inst_rssi_stats_event(wmi_handle, data,
                    &inst_rssi_resp) != QDF_STATUS_SUCCESS) {
         qdf_print("Unable to extract inst rssi event");
         return -1;
    }

    WMI_HOST_MAC_ADDR_TO_CHAR_ARRAY(&ev->peer_macaddr, c_macaddr);
    peer_obj = wlan_objmgr_get_peer_by_mac(soc->psoc_obj,
                                    c_macaddr,
                                    WLAN_MLME_SB_ID);

    if (peer_obj == NULL) {
        qdf_print("%s: Unable to find peer object", __func__);
        return -1;
    }

#if QCA_SUPPORT_SON
#define WMI_INST_STATS_VALID_RSSI_MAX 127
    /* 0x80 will be reported as invalid RSSI by hardware,
       so we want to make sure the RSSI reported to band steering
       is valid, i.e. in the range of (0, 127]. */
    if (ev->iRSSI > WMI_HOST_INST_STATS_INVALID_RSSI &&
        ev->iRSSI <= WMI_INST_STATS_VALID_RSSI_MAX) {
            son_record_inst_peer_rssi(peer_obj, ev->iRSSI);
    } else {
            son_record_inst_peer_rssi_err(peer_obj);
    }
#undef WMI_INST_STATS_VALID_RSSI_MAX
#endif

    ni = wlan_peer_get_mlme_ext_obj(peer_obj);
    if (!ni) {
        qdf_info("Unable to find ni");
        wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
        return -1;
    }

    ieee80211_update_ack_rssi(ni, ev->iRSSI);
    wlan_objmgr_peer_release_ref(peer_obj, WLAN_MLME_SB_ID);
    return 0;
}

static int32_t ol_ath_send_rssi(struct ieee80211com *ic,
                                uint8_t *macaddr, struct ieee80211vap *vap)
{
    struct stats_request_params param = {0};
    wmi_unified_t pdev_wmi_handle;
    QDF_STATUS qdf_status;

    pdev_wmi_handle = lmac_get_pdev_wmi_unified_handle(ic->ic_pdev_obj);
    param.vdev_id = wlan_vdev_get_id(vap->vdev_obj);
    param.stats_id = WMI_HOST_REQUEST_INST_STAT;

    if (pdev_wmi_handle) {
        qdf_status = wmi_unified_stats_request_send(pdev_wmi_handle, macaddr,
                                                    &param);
        return qdf_status_to_os_return(qdf_status);
    } else {
        qdf_err("WMI handle is NULL");
        return -EINVAL;
    }
}

static int32_t
ol_ath_bss_chan_info_request_stats(struct ieee80211com *ic, int param)
{
    struct bss_chan_info_request_params chan_info_param;
    struct wmi_unified *pdev_wmi_handle;
    QDF_STATUS qdf_status;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle) {
        qdf_debug("Pdev WMI handle is NULL");
        return -EINVAL;
    }

    qdf_mem_set(&chan_info_param, sizeof(chan_info_param), 0);
    chan_info_param.param = param;

    qdf_status = wmi_unified_bss_chan_info_request_cmd_send(pdev_wmi_handle,
                                                            &chan_info_param);
    return qdf_status_to_os_return(qdf_status);
}

void
reset_node_stat(void *arg, wlan_node_t node)
{
    struct ieee80211_node *ni = node;
    struct wlan_objmgr_psoc *psoc;

    psoc = wlan_pdev_get_psoc(ni->ni_ic->ic_pdev_obj);

    cdp_host_reset_peer_stats(wlan_psoc_get_dp_handle(psoc),
                              wlan_objmgr_pdev_get_pdev_id(ni->ni_ic->ic_pdev_obj),
                              ni->ni_macaddr);
    return;
}

void
reset_vap_stat(void *arg , struct ieee80211vap *vap)
{
    wlan_iterate_station_list(vap, reset_node_stat, NULL);
#ifdef QCA_SUPPORT_CP_STATS
    vdev_cp_stats_reset(vap->vdev_obj);
#endif
    return;
}

void
ol_ath_reset_vap_stat(struct ieee80211com *ic)
{
     wlan_iterate_vap_list(ic, reset_vap_stat, NULL);
}

static int ol_ath_enable_ap_stats(struct ieee80211com *ic, u_int8_t stats_cmd)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct hif_opaque_softc *h_sc;
    uint32_t types = 0;
    uint32_t param_value = 0;
    ol_txrx_soc_handle soc_txrx_handle;
    struct wmi_unified *pdev_wmi_handle;
#if defined(CONFIG_AR900B_SUPPORT) || defined(CONFIG_AR9888_SUPPORT)
    uint32_t pdev_idx = lmac_get_pdev_idx(ic->ic_pdev_obj);
#endif
#ifdef QCA_SUPPORT_CP_STATS
    uint32_t assert_count;
#endif
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);
    h_sc = lmac_get_ol_hif_hdl(psoc);
    if (!h_sc) {
        qdf_info("Invalid h_sc");
        return A_ERROR;
    }

    if (stats_cmd == 1) {
        /* Call back for stats */
#ifdef QCA_SUPPORT_CP_STATS
        if (pdev_cp_stats_ap_stats_tx_cal_enable_get(ic->ic_pdev_obj)) {
            return A_OK;
        }
#endif

        ol_ath_subscribe_ppdu_desc_info(scn, PPDU_DESC_ENHANCED_STATS);
        if (lmac_is_target_ar900b(psoc)) {
            param_value = cdp_fw_supported_enh_stats_version(
                soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj));
            if (ol_ath_pdev_set_param(ic->ic_pdev_obj,
                                      wmi_pdev_param_en_stats, param_value))
                return A_ERROR;
        } else if (!ol_target_lithium(psoc)) {
                types |= (WMI_HOST_PKTLOG_EVENT_TX | WMI_HOST_PKTLOG_EVENT_RCU);

#if defined(CONFIG_AR900B_SUPPORT) || defined(CONFIG_AR9888_SUPPORT)
            if (types) {
                if (!pdev_wmi_handle) {
                    qdf_debug("Pdev WMI Handle is NULL");
                    return A_ERROR;
                }
                /*enabling the pktlog for stats*/
                if(wmi_unified_packet_log_enable_send(pdev_wmi_handle, types,
                                        pdev_idx)) {
                    return A_ERROR;
                }
            }
#endif
        }
#ifdef QCA_SUPPORT_CP_STATS
        pdev_cp_stats_ap_stats_tx_cal_enable_update(ic->ic_pdev_obj, 1);
#endif
        cdp_enable_enhanced_stats(soc_txrx_handle,  wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj));

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_radio_ops) {
            ic->nss_radio_ops->ic_nss_ol_stats_cfg(scn, stats_cmd);
        }
#endif

        return A_OK;
    } else if (stats_cmd == 0) {
#ifdef QCA_SUPPORT_CP_STATS
        if (!pdev_cp_stats_ap_stats_tx_cal_enable_get(ic->ic_pdev_obj)) {
            return A_OK;
        }
#endif
        /* store the assert count and restore after memzero */
#ifdef QCA_SUPPORT_CP_STATS
        assert_count = pdev_cp_stats_tgt_asserts_get(ic->ic_pdev_obj);
        pdev_cp_stats_reset(ic->ic_pdev_obj);
        pdev_cp_stats_tgt_asserts_update(ic->ic_pdev_obj, assert_count);
        pdev_cp_stats_ap_stats_tx_cal_enable_update(ic->ic_pdev_obj, 0);
#endif
        cdp_disable_enhanced_stats(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj));

        if (lmac_is_target_ar900b(psoc)) {
            if (ol_ath_pdev_set_param(ic->ic_pdev_obj,
                                      wmi_pdev_param_en_stats, 0) != EOK)
                return A_ERROR;
        }

        ol_ath_unsubscribe_ppdu_desc_info(scn, PPDU_DESC_ENHANCED_STATS);

#if defined(CONFIG_AR900B_SUPPORT) || defined(CONFIG_AR9888_SUPPORT)
        if (!(lmac_is_target_ar900b(psoc) || ol_target_lithium(psoc))) {
            if (!pdev_wmi_handle) {
                qdf_debug("Pdev WMI Handle is NULL");
                return A_ERROR;
            }
            if(wmi_unified_packet_log_disable_send(pdev_wmi_handle,
                        pdev_idx)) {
                return A_ERROR;
            }
        }
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_radio_ops) {
            ic->nss_radio_ops->ic_nss_ol_stats_cfg(scn, stats_cmd);
        }
#endif

        return A_OK;
    } else {
        return A_ERROR;
    }
}

#define IEEE80211_DEFAULT_CHAN_STATS_PERIOD     (1000)

void ol_ath_stats_soc_attach(ol_ath_soc_softc_t *soc)
{
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);
    /* register target stats event handler */
    wmi_unified_register_event_handler((void *)wmi_handle, wmi_update_stats_event_id,
            ol_ath_update_stats_event_handler, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler((void *)wmi_handle,
            wmi_inst_rssi_stats_event_id,
            ol_ath_rssi_cb, WMI_RX_UMAC_CTX);
    wmi_unified_register_event_handler((void *)wmi_handle, wmi_pdev_bss_chan_info_event_id,
            ol_ath_bss_chan_info_event_handler, WMI_RX_UMAC_CTX);
}

void process_rx_ppdu_stats(void *context)
{
    int i;
#if  ATH_DATA_TX_INFO_EN
    struct ol_ath_txrx_ppdu_info_ctx *ppdu_stats_ctx =
        (struct ol_ath_txrx_ppdu_info_ctx *) context;
    struct ol_ath_softc_net80211 *scn = ppdu_stats_ctx->scn;
#endif
    struct cdp_rx_indication_ppdu *cdp_rx_ppdu;
    qdf_nbuf_t nbuf;
    qdf_nbuf_queue_t tempq;

    char *ppdu_type[] = {"SU", "MU_MIMO", "MU_OFDMA", "MU_MIMO_OFDMA",
        "UL_TRIG", "BURST_BCN", "UL_BSR_RESP",
        "UL_BSR_TRIG", "UL_RESP"};
    qdf_nbuf_queue_init(&tempq);

#if  ATH_DATA_TX_INFO_EN
    qdf_spin_lock_bh(&ppdu_stats_ctx->lock);
    while ((nbuf = qdf_nbuf_queue_remove(&ppdu_stats_ctx->nbufq)) != NULL) {
	    qdf_nbuf_queue_add(&tempq, nbuf);
    }
    qdf_spin_unlock_bh(&ppdu_stats_ctx->lock);
#endif

    while ((nbuf = qdf_nbuf_queue_remove(&tempq)) != NULL) {
        cdp_rx_ppdu = (struct cdp_rx_indication_ppdu *)nbuf->data;

#if  ATH_DATA_TX_INFO_EN
        qdf_info("****** Rx ppdu stats for %s ******", scn->netdev->name);
#endif
        qdf_info("ppdu_id              :%d ", cdp_rx_ppdu->ppdu_id);
        qdf_info("channel              :%u ", cdp_rx_ppdu->channel);
        qdf_info("timestamp            :%llu ", cdp_rx_ppdu->timestamp);
        qdf_info("duration             :%u ", cdp_rx_ppdu->duration);
        qdf_info("lsig_a               :%u ", cdp_rx_ppdu->lsig_a);
        qdf_info("bw                   :%d ", cdp_rx_ppdu->u.bw);
        qdf_info("mcs                  :%d ", cdp_rx_ppdu->u.mcs);
        qdf_info("nss                  :%d ", cdp_rx_ppdu->u.nss);
        qdf_info("num_mpdu             :%d ", cdp_rx_ppdu->num_mpdu);
        qdf_info("num_msdu             :%d ", cdp_rx_ppdu->num_msdu);
        qdf_info("rssi :               :%d ", cdp_rx_ppdu->rssi);
        qdf_info("ppdu_length          :%d ", cdp_rx_ppdu->length);
        qdf_info("rate_info            :0x%x ", cdp_rx_ppdu->u.rate_info);
        qdf_info("ltf_size             :%u ", cdp_rx_ppdu->u.ltf_size);
        qdf_info("stbc                 :%u ", cdp_rx_ppdu->u.stbc);
        qdf_info("he_re                :%u ", cdp_rx_ppdu->u.he_re);
        qdf_info("gi                   :%u ", cdp_rx_ppdu->u.gi);
        qdf_info("dcm                  :%u ", cdp_rx_ppdu->u.dcm);
        qdf_info("ldpc                 :%u ", cdp_rx_ppdu->u.ldpc);
        qdf_info("ppdu_type            :%u ", cdp_rx_ppdu->u.ppdu_type);

        if (cdp_rx_ppdu->u.ppdu_type < (sizeof(ppdu_type)/sizeof(ppdu_type[0]))) {
            qdf_info("ppdu_type_str        :%s ", ppdu_type[cdp_rx_ppdu->u.ppdu_type]);
        }

        for (i = 0; i < cdp_rx_ppdu->num_users; i++) {
            struct cdp_rx_stats_ppdu_user *rx_stats_peruser;
            rx_stats_peruser = &(cdp_rx_ppdu->user[i]);

            qdf_info("USER : %d ", i);
            qdf_info("    mac_addr            :%pM ",
                        rx_stats_peruser->mac_addr);
            qdf_info("    tid                 :%d ", rx_stats_peruser->tid);
            qdf_info("    first_data_seq_ctrl :0x%x ",
                        rx_stats_peruser->first_data_seq_ctrl);
            qdf_info("    sequence number     :%d ",
                        (rx_stats_peruser->first_data_seq_ctrl >> 4) & 0xFFFF);
            qdf_info("    frame_control       :%d ",
                        rx_stats_peruser->frame_control);
            qdf_info("    preamble            :%d ",
                        rx_stats_peruser->preamble_type);
            qdf_info("    is_ampdu            :%d ",
                        rx_stats_peruser->is_ampdu);
	    qdf_info("    mpdu success        :%d ",
                        rx_stats_peruser->mpdu_cnt_fcs_ok);
	    qdf_info("    mpdu failed         :%d ",
                        rx_stats_peruser->mpdu_cnt_fcs_err);
	    qdf_info("    mpdu ok byte count  :%d ",
                        rx_stats_peruser->mpdu_ok_byte_count);
	    qdf_info("    mpdu err byte count  :%d ",
                        rx_stats_peruser->mpdu_err_byte_count);
            qdf_info("    retries             :%d ",
                        rx_stats_peruser->retries);
            if (rx_stats_peruser->mu_ul_info_valid) {
                qdf_info("    RU index            :%d ",
                        rx_stats_peruser->ofdma_ru_start_index);
                qdf_info("    RU width            :%d ",
                        rx_stats_peruser->ofdma_ru_width);
                qdf_info("    NSS                 :%d ",
                        rx_stats_peruser->nss);
                qdf_info("    MCS                 :%d ",
                        rx_stats_peruser->mcs);
            }
        }


        qdf_nbuf_free(nbuf);

    }

}

void process_tx_ppdu_stats(void *context)
{
    int i;
    qdf_nbuf_t nbuf;
#if  ATH_DATA_TX_INFO_EN
    struct ol_ath_txrx_ppdu_info_ctx *ppdu_stats_ctx =
        (struct ol_ath_txrx_ppdu_info_ctx *) context;
    struct ol_ath_softc_net80211 *scn = ppdu_stats_ctx->scn;
#endif
    struct cdp_tx_completion_ppdu *ppdu_desc;
    struct cdp_tx_completion_ppdu_user *ppdu_user_desc;
    qdf_nbuf_queue_t tempq;

    char *ppdu_type[] = {"SU", "MU_MIMO", "MU_OFDMA", "MU_MIMO_OFDMA",
        "UL_TRIG", "BURST_BCN", "UL_BSR_RESP", "UL_BSR_TRIG",
        "UL_RESP"};

    qdf_nbuf_queue_init(&tempq);

#if  ATH_DATA_TX_INFO_EN
    qdf_spin_lock_bh(&ppdu_stats_ctx->lock);
    while ((nbuf = qdf_nbuf_queue_remove(&ppdu_stats_ctx->nbufq)) != NULL) {
	    qdf_nbuf_queue_add(&tempq, nbuf);
    }
    qdf_spin_unlock_bh(&ppdu_stats_ctx->lock);
#endif

    while ((nbuf = qdf_nbuf_queue_remove(&tempq)) != NULL) {
        ppdu_desc = (struct cdp_tx_completion_ppdu *) qdf_nbuf_data(nbuf);

#if  ATH_DATA_TX_INFO_EN
        qdf_info("****** Tx ppdu stats for %s ******", scn->netdev->name);
#endif
        qdf_info("PPDU Id      : %u", ppdu_desc->ppdu_id);
        qdf_info("MPDU count   : %d", ppdu_desc->num_mpdu);
        qdf_info("MSDU count   : %d", ppdu_desc->num_msdu);
        qdf_info("Channel      : %u", ppdu_desc->channel);
        qdf_info("Start TSF    : %llu End TSF     : %llu",
                ppdu_desc->ppdu_start_timestamp, ppdu_desc->ppdu_end_timestamp);
        qdf_info("Duration     : %u", ppdu_desc->tx_duration);
        qdf_info("Ack TSF      : %llu", ppdu_desc->ack_timestamp);
        qdf_info("Ack RSSI     : %u", ppdu_desc->ack_rssi);
        qdf_info("Frame_type   : %u", ppdu_desc->frame_type);
        qdf_info("Num users    : %u", ppdu_desc->num_users);

        for (i = 0; i < ppdu_desc->num_users; i++) {

            ppdu_user_desc = &ppdu_desc->user[i];

            if ((ppdu_user_desc->mac_addr[0] == 0) &&
                    (ppdu_user_desc->mac_addr[1] == 0) &&
                    (ppdu_user_desc->mac_addr[2] == 0) &&
                    (ppdu_user_desc->mac_addr[3] == 0) &&
                    (ppdu_user_desc->mac_addr[4] == 0) &&
                    (ppdu_user_desc->mac_addr[5] == 0)) {
                continue;
            }

            /**
             * TID > 8 is set only for multicast data and management/ctrl packets
             * Stats print are required only for multicast data packets
             */
            if ((ppdu_user_desc->tid) > 8 && !ppdu_user_desc->is_mcast &&
                ppdu_user_desc->tid != 16)
                    continue;

            qdf_info(" User     : %d", i);
            qdf_info("    mac_addr        : %pM ", ppdu_user_desc->mac_addr);
            qdf_info("    peer_id         : %d ", ppdu_user_desc->peer_id);
            qdf_info("    tid             : %d ", ppdu_user_desc->tid);
            qdf_info("    is_ampdu        : %d ", ppdu_user_desc->is_ampdu);
            qdf_info("    mpdu_tried_mcast: %d ", ppdu_user_desc->mpdu_tried_mcast);
            qdf_info("    mpdu_tried_ucast: %d ", ppdu_user_desc->mpdu_tried_ucast);
            qdf_info("    mpdu_success    : %d ", ppdu_user_desc->mpdu_success);
            qdf_info("    mpdu_failed     : %d ", ppdu_user_desc->mpdu_failed);
            qdf_info("    long_retries    : %d ", ppdu_user_desc->long_retries);
            qdf_info("    short_retries   : %d ", ppdu_user_desc->short_retries);
            qdf_info("    success_msdus   : %d ", ppdu_user_desc->success_msdus);
            qdf_info("    retry_msdus     : %d ", ppdu_user_desc->retry_msdus);
            qdf_info("    failed_msdus    : %d ", ppdu_user_desc->failed_msdus);
            qdf_info("    success_bytes   : %u ", ppdu_user_desc->success_bytes);
            qdf_info("    retry_bytes     : %d ", ppdu_user_desc->retry_bytes);
            qdf_info("    bw              : %d ", ppdu_user_desc->bw);
            qdf_info("    nss             : %d ", (ppdu_user_desc->nss + 1));
            qdf_info("    mcs             : %d ", ppdu_user_desc->mcs);
            qdf_info("    preamble        : %d ", ppdu_user_desc->preamble);
            qdf_info("    gi              : %d ", ppdu_user_desc->gi);
            qdf_info("    dcm             : %d ", ppdu_user_desc->dcm);
            qdf_info("    ldpc            : %d ", ppdu_user_desc->ldpc);
            qdf_info("    ppdu_type       : %d ", ppdu_user_desc->ppdu_type);

            if (ppdu_user_desc->ppdu_type < (sizeof(ppdu_type)/sizeof(ppdu_type[0])))
                qdf_info("    ppdu_type_str   : %s ", ppdu_type[ppdu_user_desc->ppdu_type]);

            qdf_info("    ltf_size        : %d ", ppdu_user_desc->ltf_size);
            qdf_info("    stbc            : %d ", ppdu_user_desc->stbc);
            qdf_info("    he_re           : %d ", ppdu_user_desc->he_re);
            qdf_info("    txbf            : %d ", ppdu_user_desc->txbf);
        }

        qdf_nbuf_free(nbuf);
    }

}

#if  ATH_DATA_TX_INFO_EN
    void
ol_ath_stats_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_txrx_ppdu_info_ctx *ppdu_stats_ctx;
	struct wmi_unified *wmi_handle;

	wmi_handle = lmac_get_wmi_hdl(scn->soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return;
    }

    scn->periodic_chan_stats = wmi_service_enabled(wmi_handle,
                                     wmi_service_periodic_chan_stat_support);
    qdf_info("periodic_chan_stats: %d",
              scn->periodic_chan_stats);

    ic->ic_get_cur_chan_stats = ol_ath_net80211_get_cur_chan_stats;
    ic->ic_ath_request_stats = NULL;
    ic->ic_hal_get_chan_info = ol_ath_get_chan_info;
    ic->ic_ath_send_rssi = ol_ath_send_rssi;
    ic->ic_ath_bss_chan_info_stats = ol_ath_bss_chan_info_request_stats;
    /* Enable and disable stats*/
    ic->ic_ath_enable_ap_stats = ol_ath_enable_ap_stats;

    if (!ol_target_lithium(scn->soc->psoc_obj)) {
        /* enable the pdev stats event */
        ol_ath_pdev_set_param(scn->sc_pdev,
                              wmi_pdev_param_pdev_stats_update_period,
                              PDEV_DEFAULT_STATS_UPDATE_PERIOD);

        /* enable the vdev stats event */
        ol_ath_pdev_set_param(scn->sc_pdev,
                              wmi_pdev_param_vdev_stats_update_period,
                              VDEV_DEFAULT_STATS_UPDATE_PERIOD);
        /* enable the peer stats event */
        ol_ath_pdev_set_param(scn->sc_pdev,
                              wmi_pdev_param_peer_stats_update_period,
                              PEER_DEFAULT_STATS_UPDATE_PERIOD);
    }

    /* enable periodic chan stats event */
    ol_ath_periodic_chan_stats_config(scn, true, IEEE80211_DEFAULT_CHAN_STATS_PERIOD);

    scn->tx_ppdu_stats_ctx = NULL;
    scn->rx_ppdu_stats_ctx = NULL;

    if (scn->soc->ol_if_ops->ol_stats_attach)
	    scn->soc->ol_if_ops->ol_stats_attach(ic);

        ppdu_stats_ctx = qdf_mem_malloc(sizeof(struct ol_ath_txrx_ppdu_info_ctx));

        if (!ppdu_stats_ctx) {
            qdf_print("%s ppdu stats initialization failed ",
                    __func__);
            return;
        }

        ppdu_stats_ctx->scn = scn;
        scn->tx_ppdu_stats_ctx = ppdu_stats_ctx;

        ppdu_stats_ctx = qdf_mem_malloc(sizeof(struct ol_ath_txrx_ppdu_info_ctx));

        if (!ppdu_stats_ctx) {
            qdf_print("%s ppdu stats initialization failed ",
                    __func__);
            qdf_mem_free(scn->tx_ppdu_stats_ctx);
            return;
        }

        ppdu_stats_ctx->scn = scn;
        scn->rx_ppdu_stats_ctx = ppdu_stats_ctx;

        qdf_create_work(0, &scn->tx_ppdu_stats_ctx->work, process_tx_ppdu_stats, scn->tx_ppdu_stats_ctx);
        qdf_nbuf_queue_init(&scn->tx_ppdu_stats_ctx->nbufq);
        qdf_spinlock_create(&scn->tx_ppdu_stats_ctx->lock);

        qdf_create_work(0, &scn->rx_ppdu_stats_ctx->work, process_rx_ppdu_stats, scn->rx_ppdu_stats_ctx);
        qdf_nbuf_queue_init(&scn->rx_ppdu_stats_ctx->nbufq);
        qdf_spinlock_create(&scn->rx_ppdu_stats_ctx->lock);
#ifdef QCA_SUPPORT_RDK_STATS
    if (scn->soc->rdkstats_enabled) {
        void *rate_stats_ctx;
        ol_txrx_soc_handle soc_txrx_handle;
        uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

        soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
        rate_stats_ctx = cdp_soc_get_rate_stats_ctx(soc_txrx_handle);

        ol_ath_subscribe_ppdu_desc_info(scn, PPDU_DESC_RDK_STATS);

        scn->sojourn_stats_subscriber.callback = wlan_peer_update_rate_stats;
        scn->sojourn_stats_subscriber.context = rate_stats_ctx;
        cdp_wdi_event_sub(soc_txrx_handle, pdev_id,
            &scn->sojourn_stats_subscriber, WDI_EVENT_TX_SOJOURN_STAT);

        scn->peer_create_subscriber.callback = wlan_peer_create_event_handler;
        scn->peer_create_subscriber.context = rate_stats_ctx;
        cdp_wdi_event_sub(soc_txrx_handle, pdev_id,
            &scn->peer_create_subscriber, WDI_EVENT_PEER_CREATE);

        scn->peer_destroy_subscriber.callback = wlan_peer_destroy_event_handler;
        scn->peer_destroy_subscriber.context = rate_stats_ctx;
        cdp_wdi_event_sub(soc_txrx_handle, pdev_id,
            &scn->peer_destroy_subscriber, WDI_EVENT_PEER_DESTROY);

        scn->peer_flush_rate_stats_sub.callback = wlan_cfg80211_flush_rate_stats;
        scn->peer_flush_rate_stats_sub.context = ic->ic_pdev_obj;
        cdp_wdi_event_sub(soc_txrx_handle, pdev_id,
            &scn->peer_flush_rate_stats_sub, WDI_EVENT_PEER_FLUSH_RATE_STATS);

        scn->flush_rate_stats_req_sub.callback = wlan_peer_rate_stats_flush_req;
        scn->flush_rate_stats_req_sub.context = rate_stats_ctx;
        cdp_wdi_event_sub(soc_txrx_handle, pdev_id,
            &scn->flush_rate_stats_req_sub, WDI_EVENT_FLUSH_RATE_STATS_REQ);
    }
#endif
}

void ol_ath_stats_soc_detach(ol_ath_soc_softc_t *soc)
{
    wmi_unified_t wmi_handle;

    wmi_handle = lmac_get_wmi_unified_hdl(soc->psoc_obj);
    /* unregister target stats event handler */
    wmi_unified_unregister_event_handler(wmi_handle, wmi_update_stats_event_id);
    wmi_unified_unregister_event_handler(wmi_handle, wmi_inst_rssi_stats_event_id);
    wmi_unified_unregister_event_handler(wmi_handle, wmi_pdev_bss_chan_info_event_id);

}

void
ol_ath_stats_detach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#if defined(QCA_SUPPORT_RDK_STATS) || (defined(WLAN_CFR_ENABLE) && defined(WLAN_ENH_CFR_ENABLE))
    ol_txrx_soc_handle soc_txrx_handle;

    soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
#endif

    ic->ic_get_cur_chan_stats = NULL;
    ic->ic_ath_request_stats = NULL;
    ic->ic_hal_get_chan_info = NULL;
    ic->ic_ath_send_rssi = NULL;
    ic->ic_ath_enable_ap_stats = NULL;
    /* disable target stats event */
    ol_ath_pdev_set_param(scn->sc_pdev,
                          wmi_pdev_param_pdev_stats_update_period, 0);
    ol_ath_pdev_set_param(scn->sc_pdev,
                          wmi_pdev_param_vdev_stats_update_period, 0);
    ol_ath_pdev_set_param(scn->sc_pdev,
                          wmi_pdev_param_peer_stats_update_period, 0);
    /* disable periodic chan stats event */
    ol_ath_periodic_chan_stats_config(scn, false, IEEE80211_DEFAULT_CHAN_STATS_PERIOD);

    if (scn->tx_ppdu_stats_ctx) {
        qdf_flush_work(&scn->tx_ppdu_stats_ctx->work);
        qdf_disable_work(&scn->tx_ppdu_stats_ctx->work);
        qdf_spinlock_destroy(&scn->tx_ppdu_stats_ctx->lock);
        qdf_mem_free(scn->tx_ppdu_stats_ctx);
    }

    if (scn->rx_ppdu_stats_ctx) {
        qdf_flush_work(&scn->rx_ppdu_stats_ctx->work);
        qdf_disable_work(&scn->rx_ppdu_stats_ctx->work);
        qdf_spinlock_destroy(&scn->rx_ppdu_stats_ctx->lock);
        qdf_mem_free(scn->rx_ppdu_stats_ctx);
    }
#ifdef QCA_SUPPORT_RDK_STATS
    if (scn->soc->rdkstats_enabled) {
        uint8_t pdev_id = wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev);
        ol_txrx_soc_handle soc_txrx_handle;

        soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
        if (soc_txrx_handle) {
            ol_ath_unsubscribe_ppdu_desc_info(scn, PPDU_DESC_RDK_STATS);
            cdp_wdi_event_unsub(soc_txrx_handle, pdev_id,
                &scn->sojourn_stats_subscriber, WDI_EVENT_TX_SOJOURN_STAT);
            cdp_wdi_event_unsub(soc_txrx_handle, pdev_id,
                &scn->peer_create_subscriber, WDI_EVENT_PEER_CREATE);
            cdp_wdi_event_unsub(soc_txrx_handle, pdev_id,
                &scn->peer_destroy_subscriber, WDI_EVENT_PEER_DESTROY);
            cdp_wdi_event_unsub(soc_txrx_handle, pdev_id,
                &scn->peer_flush_rate_stats_sub, WDI_EVENT_PEER_FLUSH_RATE_STATS);
            cdp_wdi_event_unsub(soc_txrx_handle, pdev_id,
                &scn->flush_rate_stats_req_sub, WDI_EVENT_FLUSH_RATE_STATS_REQ);
        }
    }
#endif

#if defined(WLAN_CFR_ENABLE) && defined(WLAN_ENH_CFR_ENABLE)
    if (cdp_get_cfr_rcc(soc_txrx_handle,
                        wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj))) {
            ol_ath_unsubscribe_ppdu_desc_info(scn, PPDU_DESC_CFR_RCC);
            cdp_set_cfr_rcc(soc_txrx_handle,
                            wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj),
                            false);
    }
#endif
}
#endif

void ol_ath_soc_rate_stats_attach(ol_ath_soc_softc_t *soc)
{
#ifdef QCA_SUPPORT_RDK_STATS
    struct wlan_soc_rate_stats_ctx *rate_stats_ctx = NULL;
    ol_txrx_soc_handle soc_txrx_handle;
    cdp_config_param_type val = {0};
    enum rdk_stats_version stats_ver;
    uint8_t is_lithium = ol_target_lithium(soc->psoc_obj);

    stats_ver = cfg_get(soc->psoc_obj, CFG_OL_PEER_RATE_STATS);

    if (!is_lithium && stats_ver > RDK_RATE_STATS) {
        qdf_err("stats version 2 and 3 not supported for non-lithium platforms");
        return;
    }

    if (stats_ver != RDK_STATS_DISABLED) {
        soc_txrx_handle = wlan_psoc_get_dp_handle(soc->psoc_obj);

        rate_stats_ctx = qdf_mem_malloc(sizeof(*rate_stats_ctx));
        if (!rate_stats_ctx) {
            qdf_err("failed to allocate rate stats context");
            cdp_txrx_set_psoc_param(soc_txrx_handle, CDP_ENABLE_RATE_STATS, val);
             return;
        }

        soc->rdkstats_enabled = 1;
        rate_stats_ctx->is_lithium = is_lithium;

        val.cdp_psoc_param_en_rate_stats = 1;
        cdp_txrx_set_psoc_param(soc_txrx_handle, CDP_ENABLE_RATE_STATS, val);
        rate_stats_ctx->soc = soc_txrx_handle;
        rate_stats_ctx->stats_ver = stats_ver;
        STATS_CTX_LOCK_CREATE(&rate_stats_ctx->tx_ctx_lock);
        STATS_CTX_LOCK_CREATE(&rate_stats_ctx->rx_ctx_lock);
        cdp_soc_set_rate_stats_ctx(soc_txrx_handle, rate_stats_ctx);
        qdf_info("enable rdk stats %d soc: %p ", soc->rdkstats_enabled, soc);
    }
#endif
}

void ol_ath_soc_rate_stats_detach(ol_ath_soc_softc_t *soc)
{
#ifdef QCA_SUPPORT_RDK_STATS
    void *rate_stats_hdl;
    struct wlan_soc_rate_stats_ctx *rate_stats_ctx = NULL;
    ol_txrx_soc_handle soc_txrx_handle;
    cdp_config_param_type val = {0};

    if (cfg_get(soc->psoc_obj, CFG_OL_PEER_RATE_STATS)) {
        soc->rdkstats_enabled = 0;
        soc_txrx_handle = wlan_psoc_get_dp_handle(soc->psoc_obj);
        cdp_txrx_set_psoc_param(soc_txrx_handle, CDP_ENABLE_RATE_STATS, val);
        rate_stats_hdl = cdp_soc_get_rate_stats_ctx(soc_txrx_handle);
        if (rate_stats_hdl) {
            rate_stats_ctx = (struct wlan_soc_rate_stats_ctx *)rate_stats_hdl;
            STATS_CTX_LOCK_DESTROY(&rate_stats_ctx->tx_ctx_lock);
            STATS_CTX_LOCK_DESTROY(&rate_stats_ctx->rx_ctx_lock);
            qdf_mem_free(rate_stats_hdl);
        }
        cdp_soc_set_rate_stats_ctx(soc_txrx_handle, NULL);
        qdf_warn("disable rdk stats");
    }
#endif
}

int
ol_get_tx_free_desc(struct ol_ath_softc_net80211 *scn)
{
    uint64_t total;
    cdp_config_param_type val = {0};
    ol_txrx_soc_handle psoc = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);

    total = ol_cfg_target_tx_credit((ol_soc_handle)scn->soc->psoc_obj);
    cdp_txrx_get_pdev_param(psoc, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev), CDP_TX_PENDING, &val);

    return (total - val.cdp_pdev_param_tx_pending);
}

extern int wlan_update_pdev_cp_stats(struct ieee80211com *ic,
                              struct ol_ath_radiostats *scn_stats_user);

void ol_get_radio_stats(struct ol_ath_softc_net80211 *scn,
        struct ol_ath_radiostats *stats)
{
#ifdef QCA_SUPPORT_CP_STATS
    struct ieee80211com *ic = NULL;
#endif

    if (!stats) {
        qdf_print("stats buffer is null");
        return;
    }
#ifdef QCA_SUPPORT_CP_STATS
    ic = &scn->sc_ic;
    if (wlan_update_pdev_cp_stats(ic, stats) != 0) {
        qdf_print("Invalid input to ol_get_radio_stats");
        return;
    }
    stats->tx_buf_count = ol_get_tx_free_desc(scn);
    stats->chan_nf = scn->chan_nf;
    stats->chan_nf_sec80 = scn->chan_nf_sec80;
#endif
}

#endif /* ATH_PERF_PWR_OFFLOAD */
