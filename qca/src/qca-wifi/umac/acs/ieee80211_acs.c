/*
 * Copyright (c) 2011,2016-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011, 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 */

#include <osdep.h>

#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_acs.h>
#include <ieee80211_acs_internal.h>
#include <ol_if_athvar.h>
#include <ieee80211.h>
#include <wlan_son_pub.h>
#include <wlan_lmac_if_api.h>
#include "wlan_utility.h"
#include <ieee80211_cbs.h>
#include <wlan_reg_services_api.h>
#include <wlan_reg_channel_api.h>
#include <ieee80211_mlme_dfs_dispatcher.h>
#include <wlan_reg_ucfg_api.h>

#if ATH_ACS_DEBUG_SUPPORT
#include "acs_debug.h"
#endif

#if WIFI_MEM_MANAGER_SUPPORT
#include "mem_manager.h"
#endif

uint32_t acs_dbg_mask = 0; /* Mask for acs_info() */

static void ieee80211_free_ht40intol_scan_resource(ieee80211_acs_t acs);
static void ieee80211_acs_free_scan_resource(ieee80211_acs_t acs);
static void ieee80211_acs_scan_report_internal(struct ieee80211com *ic);

static QDF_STATUS ieee80211_get_chan_neighbor_list(void *arg, wlan_scan_entry_t se);

static uint8_t ieee80211_acs_get_ieee_chan_from_ch_idx(uint16_t acs_ch_idx);

static uint16_t ieee80211_acs_get_center_freq_idx(uint8_t ch_num,
                                                  uint16_t freq);
static uint16_t ieee80211_acs_get_ieee_freq_from_ch_idx(ieee80211_acs_t acs,
                                                        uint16_t acs_ch_idx);

static QDF_STATUS ieee80211_acs_derive_adj_chans(ieee80211_acs_t acs,
                                          struct ieee80211_ath_channel *channel,
                                          int16_t *first_adj_chan,
                                          int16_t *last_adj_chan);

static int ieee80211_acs_derive_sec_chans_with_mode(ieee80211_acs_t acs,
                                                enum ieee80211_phymode mode,
                                                uint16_t pri_chan_freq,
                                                uint16_t center_chan_80,
                                                uint16_t center_chan_160,
                                                struct acs_sec_chans *sec_chans);

static int ieee80211_check_and_execute_pending_acsreport(wlan_if_t vap);

static OS_TIMER_FUNC(ieee80211_ch_long_timer);
static OS_TIMER_FUNC(ieee80211_ch_nohop_timer);
static OS_TIMER_FUNC(ieee80211_ch_cntwin_timer);

static inline uint8_t ieee80211_acs_in_progress(ieee80211_acs_t acs);

/*
 * ieee80211_acs_in_progress:
 * Check if ACS is still in progress.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 *     0: ACS is not in progress.
 * Non-0: ACS is in progress.
 */
static inline uint8_t ieee80211_acs_in_progress(ieee80211_acs_t acs)
{
    return atomic_read(&(acs->acs_in_progress));
}

/*
 * ieee80211_acs_channel_is_set:
 * Check if a channel is already set.
 *
 * @vap: Pointer to the VAP structure.
 *
 * Return:
 * 0: Channel is not set.
 * 1: Channel is set.
 */
static int ieee80211_acs_channel_is_set(struct ieee80211vap *vap)
{
    struct ieee80211_ath_channel    *chan = NULL;

    chan =  vap->iv_des_chan[vap->iv_des_mode];

    if ((chan == NULL) || (chan == IEEE80211_CHAN_ANYC)) {
        return (0);
    } else {
        return (1);
    }
}

/*
 * ieee80211_acs_get_chan_idx:
 * Get the internal ACS channel index for a given frequency.
 *
 * @acs : Pointer to the ACS structure.
 * @freq: Value of the given frequency.
 *
 * Return:
 *     0: Invalid channel index.
 * Non-0: Valid channel index.
 */
uint16_t ieee80211_acs_get_chan_idx(ieee80211_acs_t acs, uint16_t freq)
{
    uint16_t acs_ch_idx = 0;

    acs_ch_idx = wlan_reg_freq_to_chan(acs->acs_ic->ic_pdev_obj, freq);

    switch (wlan_reg_freq_to_band(freq)) {
        case REG_BAND_2G:
            acs_ch_idx += ACS_2G_START_CH_IDX;
            break;
        case REG_BAND_5G:
            acs_ch_idx += ACS_5G_START_CH_IDX;
            break;
        case REG_BAND_6G:
            acs_ch_idx += ACS_6G_START_CH_IDX;
            break;
        default:
            acs_err("Invalid freq (%4uMHz)", freq);
    }

    if (acs_ch_idx >= IEEE80211_ACS_CHAN_MAX) {
        acs_err("Invalid acs_ch_idx (%4d)", acs_ch_idx);
        acs_ch_idx = 0;
    }

    return acs_ch_idx;
}

/*
 * ieee80211_acs_get_center_freq_idx:
 * Get the internal ACS channel index for a given channel number and band
 * (defined by frequency).
 *
 * @ch_num: Value of the given channel number.
 * @freq  : Value of the given frequency (used to derive the given band).
 *
 * Return:
 *     0: Invalid channel index.
 * Non-0: Valid channel index.
 */
static uint16_t ieee80211_acs_get_center_freq_idx(uint8_t ch_num,
                                                  uint16_t freq)
{
    uint16_t chan_idx = ch_num;

    switch (wlan_reg_freq_to_band(freq)) {
        case REG_BAND_2G:
            chan_idx += ACS_2G_START_CH_IDX;
            break;
        case REG_BAND_5G:
            chan_idx += ACS_5G_START_CH_IDX;
            break;
        case REG_BAND_6G:
            chan_idx += ACS_6G_START_CH_IDX;
            break;
        default:
            acs_err("Invalid freq (%d)", freq);
    }

    return chan_idx;
}

/*
 * ieee80211_acs_get_ieee_chan_from_ch_idx:
 * Get the IEE channel for a given internal ACS channel index.
 *
 * @acs_ch_idx: Value of the given channel index.
 *
 * Return:
 *     0: Invalid IEEE channel number.
 * Non-0: Valid IEEE channel index.
 */
static uint8_t ieee80211_acs_get_ieee_chan_from_ch_idx(uint16_t acs_ch_idx)
{
    if (acs_ch_idx >= ACS_6G_START_CH_IDX) {
        return acs_ch_idx - ACS_6G_START_CH_IDX;
    } else if (acs_ch_idx >= ACS_5G_START_CH_IDX) {
        return acs_ch_idx - ACS_5G_START_CH_IDX;
    } else if (acs_ch_idx >= ACS_2G_START_CH_IDX) {
        return acs_ch_idx - ACS_2G_START_CH_IDX;
    } else {
        acs_err("Invalid acs_ch_idx (%3d)", acs_ch_idx);
        return (uint8_t)acs_ch_idx;
    }
}

/*
 * ieee80211_acs_get_ieee_freq_from_ch_idx:
 * Get the IEEE center channel frequency for a given internal ACS channel index.
 *
 * @acs       : Pointer to the ACS structure.
 * @acs_ch_idx: Value of the given channel index.
 *
 * Return:
 *     0: Invalid IEEE channel frequency.
 * Non-0: Valid IEEE channel frequency.
 */
static uint16_t ieee80211_acs_get_ieee_freq_from_ch_idx(ieee80211_acs_t acs,
                                                        uint16_t acs_ch_idx)
{
    if (acs_ch_idx > ACS_6G_START_CH_IDX) {
        return wlan_reg_chan_band_to_freq(acs->acs_ic->ic_pdev_obj, acs_ch_idx - ACS_6G_START_CH_IDX, BIT(REG_BAND_6G));
    } else {
        return wlan_reg_chan_band_to_freq(acs->acs_ic->ic_pdev_obj, acs_ch_idx, (BIT(REG_BAND_2G) | BIT(REG_BAND_5G)));
    }
}

/*
 * ieee80211_acs_check_precac_status:
 * Check if a given channel has completed its Channel Availability Check (or
 * CAC).
 *
 * The API assumes the following:
 * (1) The channel is a DFS channel.
 * (2) The preCAC completion channel list is non-empty.
 *
 * @acs    : Pointer to acs
 * @channel: Pointer to a given channel
 *
 * Return:
 * 0: PreCAC is complete; Accept
 * 1: PreCAC is incomplete; Reject
 */
static int ieee80211_acs_check_precac_status(ieee80211_acs_t acs,
                                      struct ieee80211_ath_channel *channel)
{
    enum precac_status_for_chan status;

    status = mlme_dfs_precac_status_for_channel(acs->acs_ic->ic_pdev_obj,
                                                channel);

    /*
     * If status is set to preCAC required, then return back with a rejection
     * code
     */
    if (status == DFS_PRECAC_REQUIRED_CHAN) {
        return 1;
    }

    /*
     * For all other status codes, COMPLETED and INVALID, don't reject the
     * channel.
     */
    return 0;
}

/*
 * ieee80211_acs_check_interference:
 * Check for channel interference.
 *
 * @chan: Pointer to the given channel.
 * @vap : Pointer to the VAP structure.
 *
 * Return:
 * -1: Could not check interference.
 *  0: No interference detected for a given channel.
 *  1: Interference detected for a given channel.
 */
static int ieee80211_acs_check_interference(struct ieee80211_ath_channel *chan,
                                            struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t dfs_reg = 0;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;

    pdev = ic->ic_pdev_obj;
    if(!pdev) {
        acs_err("Null pdev");
        return -1;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        acs_err("Null psoc");
        return -1;
    }

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
    if (!reg_rx_ops) {
        acs_err("Null reg_rx_ops");
        return -1;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
            QDF_STATUS_SUCCESS) {
        return -1;
    }
    reg_rx_ops->get_dfs_region(pdev, &dfs_reg);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);

    /*
     * (1) skip static turbo channel as it will require STA to be in
     * static turbo to work.
     * (2) skip channel which's marked with radar detection
     * (3) WAR: we allow user to config not to use any DFS channel
     * (4) skip excluded 11D channels. See bug 31246
     */
    if ( IEEE80211_IS_CHAN_STURBO(chan) ||
            IEEE80211_IS_CHAN_RADAR(ic, chan) ||
            IEEE80211_IS_CHAN_11D_EXCLUDED(chan) ||
            ( ic->ic_no_weather_radar_chan &&
                (ieee80211_check_weather_radar_channel(chan)) &&
                (DFS_ETSI_DOMAIN == dfs_reg)
            )) {
        return (1);
    } else {
        return (0);
    }
}

/*
 * ieee80211_acs_get_adj_ch_stats:
 * Get adjacent channel statistics for a given channel.
 *
 * @acs    : Pointer to the ACS structure.
 * @channel: Pointer to the given channel.
 */
static void ieee80211_acs_get_adj_ch_stats(ieee80211_acs_t acs,
                            struct ieee80211_ath_channel *channel,
                            struct ieee80211_acs_adj_chan_stats *adj_chan_stats)
{
    uint16_t acs_ch_idx = 0;
    int k;
    int16_t first_adj_chan, last_adj_chan;
    struct acs_sec_chans sec_chans = {0};
    uint32_t obss_weighted = 0;
    uint16_t center_chan = 0, center_chan_160 = 0;
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;
    int status;

    if ((channel == NULL) || (acs == NULL)) {
        acs_err("Null channel (%p) or acs (%p)", channel, acs);
        return;
    }

    mode = ieee80211_chan2mode(channel);
    if (mode == IEEE80211_MODE_AUTO) {
        acs_err("Invalid phymode in channel (%4uMHz)", channel->ic_freq);
    }

    acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
    adj_chan_stats->if_valid_stats = 1;
    adj_chan_stats->adj_chan_load = 0;
    adj_chan_stats->adj_chan_rssi = 0;
    adj_chan_stats->adj_chan_idx = 0;

    center_chan = ieee80211_acs_get_center_freq_idx(channel->ic_vhtop_ch_num_seg1,
                                                    channel->ic_freq);
    if (!center_chan &&
        ((mode == IEEE80211_MODE_11AC_VHT160)   ||
         (mode == IEEE80211_MODE_11AXA_HE160)   ||
         (mode == IEEE80211_MODE_11AC_VHT80_80) ||
         (mode == IEEE80211_MODE_11AXA_HE80_80))) {
        acs_err("Could not derive center_chan");
        return;
    }

    center_chan_160 = ieee80211_acs_get_center_freq_idx(channel->ic_vhtop_ch_num_seg2,
                                                        channel->ic_freq);
    if (!center_chan_160 &&
        ((mode == IEEE80211_MODE_11AC_VHT160) ||
         (mode == IEEE80211_MODE_11AXA_HE160))) {
        acs_err("Could not derive center_chan");
        return;
    }

    status = ieee80211_acs_derive_sec_chans_with_mode(acs,
                                                      mode,
                                                      channel->ic_freq,
                                                      center_chan,
                                                      center_chan_160,
                                                      &sec_chans);
    if (status) {
        acs_err("Could not derive secondary channels");
        return;
    }

    if(sec_chans.sec_chan_20 && (sec_chans.sec_chan_20 != acs_ch_idx)) {
        if( (acs->acs_noisefloor[sec_chans.sec_chan_20] != NF_INVALID)
                && (acs->acs_noisefloor[sec_chans.sec_chan_20] >=
                    acs->acs_noisefloor_threshold) ) {
            adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC_NF_FLAG;
        }
    }

    /* Block secondary 40MHz only for 80+80MHz and 160MHz */
    if (((mode == IEEE80211_MODE_11AC_VHT160)   ||
         (mode == IEEE80211_MODE_11AXA_HE160)   ||
         (mode == IEEE80211_MODE_11AC_VHT80_80) ||
         (mode == IEEE80211_MODE_11AXA_HE80_80)) &&
        sec_chans.sec_chan_40_1 && sec_chans.sec_chan_40_2) {
       if( (acs->acs_noisefloor[sec_chans.sec_chan_40_1] != NF_INVALID)
                && (acs->acs_noisefloor[sec_chans.sec_chan_40_1] >=
                    acs->acs_noisefloor_threshold )) {
           adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC1_NF_FLAG;
       }

       if( (acs->acs_noisefloor[sec_chans.sec_chan_40_2] != NF_INVALID)
               && (acs->acs_noisefloor[sec_chans.sec_chan_40_2] >=
                   acs->acs_noisefloor_threshold )) {
           adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC2_NF_FLAG;
       }
    }

    /* Block secondary 80MHz only for 160MHz */
    if (((mode == IEEE80211_MODE_11AC_VHT160)   ||
         (mode == IEEE80211_MODE_11AXA_HE160)) &&
        sec_chans.sec_chan_80_1 && sec_chans.sec_chan_80_2 &&
        sec_chans.sec_chan_80_3 && sec_chans.sec_chan_80_4) {
        if((acs->acs_noisefloor[sec_chans.sec_chan_80_1] != NF_INVALID)
                 && (acs->acs_noisefloor[sec_chans.sec_chan_80_1] >=
                     acs->acs_noisefloor_threshold)) {
            adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC3_NF_FLAG;
        }

        if( (acs->acs_noisefloor[sec_chans.sec_chan_80_2] !=NF_INVALID)
                && (acs->acs_noisefloor[sec_chans.sec_chan_80_2] >=
                    acs->acs_noisefloor_threshold )) {
            adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC4_NF_FLAG;
        }

        if( (acs->acs_noisefloor[sec_chans.sec_chan_80_3] !=NF_INVALID)
                && (acs->acs_noisefloor[sec_chans.sec_chan_80_3] >=
                    acs->acs_noisefloor_threshold )) {
            adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC5_NF_FLAG;
        }

        if( (acs->acs_noisefloor[sec_chans.sec_chan_80_4] !=NF_INVALID)
                && (acs->acs_noisefloor[sec_chans.sec_chan_80_4] >=
                    acs->acs_noisefloor_threshold)) {
            adj_chan_stats->adj_chan_flag |= ADJ_CHAN_SEC6_NF_FLAG;
        }
    }

    /*Update EACS plus parameter */
    adj_chan_stats->adj_chan_loadsum = 0;
    adj_chan_stats->adj_chan_rssisum = 0;
    adj_chan_stats->adj_chan_obsssum = 0;
    adj_chan_stats->adj_chan_srsum = 0;

    status = ieee80211_acs_derive_adj_chans(acs,
                                            channel,
                                            &first_adj_chan,
                                            &last_adj_chan);
    if (status) {
        acs_err("Could not derive adjacent channels");
        return;
    }


    for (k = first_adj_chan ; (k <= last_adj_chan); k += 2) {
        int effchfactor;

        if ((k == acs_ch_idx) || (k <= 0)) continue;
        obss_weighted = 0;

        effchfactor =  k - acs_ch_idx;

        if(effchfactor < 0)
            effchfactor = 0 - effchfactor;

        effchfactor = effchfactor >> 1;
        if(effchfactor == 0)  effchfactor =1;

        if((acs->acs_noisefloor[k] != NF_INVALID) && (acs->acs_noisefloor[k] >= acs->acs_noisefloor_threshold )){
            acs_info(ADJCHAN, "Adjacent channel NF (%4d) exceeded threshold (%4d), "
                     "add 100 each to RSSI and load",
                     acs->acs_noisefloor[k], acs->acs_noisefloor_threshold);
            adj_chan_stats->adj_chan_loadsum += 100 / effchfactor;
            adj_chan_stats->adj_chan_rssisum += 100 / effchfactor ;
        }
        else{
            adj_chan_stats->adj_chan_loadsum += (acs->acs_chan_load[k] / effchfactor) ;
            adj_chan_stats->adj_chan_rssisum += (acs->acs_chan_snr[k] / effchfactor) ;
        }
        obss_weighted = (acs->acs_chan_nbss_near[k] * acs->acs_obss_near_range_weightage)
                            + (acs->acs_chan_nbss_mid[k] * acs->acs_obss_mid_range_weightage)
                            + (acs->acs_chan_nbss_far[k] * acs->acs_obss_far_range_weightage);
        adj_chan_stats->adj_chan_obsssum += (obss_weighted / effchfactor);
        adj_chan_stats->adj_chan_srsum   += (ACS_DEFAULT_SR_LOAD / effchfactor) * acs->acs_srp_supported[k];

        acs_info(ADJCHAN, "Per-adjacent-channel stats - "
                 "pri_chan (%3d), "
                 "adj_chan (%3d), "
                 "effchfactor (%3d), "
                 "acs_chan_load (%3d), "
                 "acs_chan_rssi (%4d), "
                 "acs_obss_weighted (%4d), "
                 "acs_sr_load (%4d)",
                 acs_ch_idx,
                 k,
                 effchfactor,
                 adj_chan_stats->adj_chan_loadsum,
                 adj_chan_stats->adj_chan_rssisum,
                 adj_chan_stats->adj_chan_obsssum,
                 adj_chan_stats->adj_chan_srsum);
    }

    acs_info(ADJCHAN, "Cumulative adjacent channel stats - "
             "pri_chan (%3d), "
             "sec_chan (%3d), "
             "first_adj_chan (%3d), "
             "last_adj_chan (%3d), "
             "sec_chan_40_1 (%3d), "
             "sec_chan_40_2 (%3d), "
             "sec_chan_80_1 (%3d), "
             "sec_chan_80_2 (%3d), "
             "sec_chan_80_3 (%3d), "
             "sec_chan_80_4 (%3d), "
             "adj_chan_if_valid_stats (%1d), "
             "adj_chan_rssisum (%4d), "
             "adj_chan_loadsum (%4d), "
             "adj_chan_obsssum (%4d), "
             "adj_chan_srsum (%4d), "
             "adj_chan_flags (%#010x)",
             acs_ch_idx,
             sec_chans.sec_chan_20,
             first_adj_chan,
             last_adj_chan,
             sec_chans.sec_chan_40_1,
             sec_chans.sec_chan_40_2,
             sec_chans.sec_chan_80_1,
             sec_chans.sec_chan_80_2,
             sec_chans.sec_chan_80_3,
             sec_chans.sec_chan_80_4,
             adj_chan_stats->if_valid_stats,
             adj_chan_stats->adj_chan_rssisum,
             adj_chan_stats->adj_chan_loadsum,
             adj_chan_stats->adj_chan_obsssum,
             adj_chan_stats->adj_chan_srsum,
             adj_chan_stats->adj_chan_flag);
}

/*
 * eacs_plus_filter:
 * Accept and reject channel based on the primary and secondary input
 * parameters.
 *
 * @acs      : Pointer to the ACS structure.
 * @pristr   : Pointer to the string describing the primary parameter.
 * @priparam : Pointer to the primary parameter array.
 * @secstr   : Pointer to the string describing the secondary parameter.
 * @secparam : Pointer to the secondary parameter array.
 * @primin   : Value of the min/max for the primary parameter.
 * @privar   : Value of the accepted variance for the primary parameter.
 * @rejflag  : Value of the rejection flag to use for primary parameter.
 * @minval   : Pointer to variable to store min/max value from secondary
 *             parameter.
 * @rejhigher: Value of policy for rejecting higher/lower variance channels for
 *             primary parameter.
 * @findmin  : Value of policy for finding minimum or maximum channels for the
 *             secondary parameter.
 *
 * Return:
 * Channel with minimum secondary parameter.
 */
static int eacs_plus_filter(ieee80211_acs_t acs,
                            const char *pristr,
                            int *primparam,
                            const char *secstr,
                            int *secparam,
                            int primin,
                            int privar,
                            unsigned int rejflag,
                            int *minval,
                            int rejhigher,
                            int findmin)
{
    int minix, i, cur_chan, priparamval, secparamval;
    struct ieee80211_ath_channel *channel;

    acs_info(BASE, "Filter input params - "
             "primary_str (%9s), "
             "primary_min (%3d), "
             "primary_var (%3d), "
             "rejflag (%#010x), "
             "secondary_str (%9s), "
             "rejhigher (%#03x), "
             "findmin (%#03x)",
             pristr,
             primin,
             privar,
             rejflag,
             secstr,
             rejhigher,
             findmin);
    minix = -1;

    if (findmin) {
        *minval = 0xfff;
    } else {
        *minval = 0;
    }


    for(i = 0; i < acs->acs_nchans ; i++)
    {
        channel =  acs->acs_chans[i];
        cur_chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);

         /* WAR to handle channel 5,6,7 for HT40 mode (2 entries of channel are present) */
        if(((cur_chan >= 5) && (cur_chan <= 7)) &&
           (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel) || IEEE80211_IS_CHAN_11AXG_HE40MINUS(channel))) {
            cur_chan = 15 + (cur_chan - 5);
        }

        if(acs->acs_channelrejflag[cur_chan] && (strcmp(pristr, "NBSS"))) {
           acs_info(FILTER, "Skipped chan (%3d) with primary filter (%9s) - "
                    "already rejected (%#010x)",
                    cur_chan, pristr,
                    acs->acs_channelrejflag[cur_chan]);
           continue;
        }

        if((acs->acs_channelrejflag[cur_chan] & ACS_REJFLAG_NON2G) && !(strcmp(pristr, "NBSS"))) {
           acs_info(FILTER, "Skipped chan (%3d) with primary filter (%9s) - "
                    "already rejected (%#010x)",
                    cur_chan, pristr,
                    acs->acs_channelrejflag[cur_chan]);
           continue;
        }

        priparamval = primparam[cur_chan];
        secparamval = secparam [cur_chan];

        if (strcmp(pristr, "NBSS")) {
            if(rejhigher){

               if(  ( priparamval - primin )  > privar  ){
                   acs->acs_channelrejflag[cur_chan] |= rejflag;
                   acs_info(FILTER, "Reject  chan (%3d) with primary filter (%9s) - "
                            "current (%4d), "
                            "minimum (%4d), "
                            "delta (%4d), "
                            "allowed (%4d)",
                            cur_chan, pristr,
                            priparamval,
                            primin,
                            (priparamval - primin),
                            privar);
               }
            }else{
               if(  (primin - priparamval) >  privar  ){
                   acs->acs_channelrejflag[cur_chan] |= rejflag;
                   acs_info(FILTER, "Reject  chan (%3d) with primary filter (%9s) - "
                            "current (%4d), "
                            "minimum (%4d), "
                            "delta (%4d), "
                            "allowed (%4d)",
                            cur_chan, pristr,
                            priparamval,
                            primin,
                            (priparamval- primin)*100/(primin+1),
                            privar);
               }
            }
        }
        if(!(acs->acs_channelrejflag[cur_chan] & rejflag))
            acs_info(FILTER, "Accept  chan (%3d) with primary filter (%9s) - "
                     "current (%4d), "
                     "minimum (%4d), "
                     "delta (%4d), "
                     "allowed (%4d)",
                     cur_chan, pristr,
                     priparamval,
                     primin,
                     (priparamval- primin),
                     privar);
        if((!acs->acs_channelrejflag[cur_chan] && (strcmp(pristr, "NBSS"))) ||
                        !(strcmp(pristr, "NBSS"))) {
            if(findmin ){
                if(  secparamval  <  *minval ){
                    minix = i;
                    *minval = secparamval;
                    acs_info(FILTER, "Selected chan (%3d) as minimum (%4d) "
                             "with secondary param (%9s)",
                             minix, *minval, secstr);
                }
            }
            else{
                if(  secparamval  >  *minval ){
                    minix = i;
                    *minval = secparamval;
                    acs_info(FILTER, "Selected chan (%3d) as maximum (%4d) "
                             "with secondary param (%9s)",
                             minix, *minval, secstr);
                }
            }

        }
    }
    return minix;
}

/*
 * acs_find_secondary_80mhz_chan:
 * Find the best secondary 80MHz channel.
 *
 * @acs    : Pointer to the ACS structure.
 * @prichan: Value of the IEEE channel of the given primary channel.
 *
 * Return:
 * -1: Could not find secondary 80MHz channel.
 *  0: Channel index to the best secondary 80MHz channel.
 */
static int acs_find_secondary_80mhz_chan(ieee80211_acs_t acs, u_int8_t prichan)
{
    u_int8_t flag = 0;
    u_int16_t i;
    uint16_t chan;
    struct ieee80211_ath_channel *channel;

    do {
       for (i = 0; i < acs->acs_nchans; i++) {
           channel = acs->acs_chans[i];
           chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
           /* skip Primary 80 mhz channel */
           if((acs->acs_channelrejflag[chan] & ACS_REJFLAG_PRIMARY_80_80) ||
              (acs->acs_channelrejflag[chan] & ACS_REJFLAG_NO_SEC_80_80) ||
              (acs->acs_channelrejflag[chan] & ACS_REJFLAG_SEC80_DIFF_BAND)) {
               continue;
           }
            /* Skip channels, if high NF is seen in its primary and secondary channels */
           if(!flag && (acs->acs_channelrejflag[chan] & ACS_REJFLAG_HIGHNOISE)) {
               continue;
           }
           if(!flag && acs->acs_adjchan_flag[chan]) {
               continue;
           }
           return i;
       }
       flag++;
    } while(flag < 2); /* loop for two iterations only */
    /* It should not reach here */
    return -1;
}

/*
 * acs_emiwar80p80_skip_secondary_80mhz_chan:
 * EMIWAR to skip the secondary channel based on the EMIVAR value.
 *
 * @acs            : Pointer to the ACS structure.
 * @primary_channel: Pointer to the given primary channel.
 */
static void acs_emiwar80p80_skip_secondary_80mhz_chan(ieee80211_acs_t acs,
                                  struct ieee80211_ath_channel *primary_channel)
{

    struct ieee80211com *ic = NULL;

    if((NULL == acs) || (NULL == primary_channel) || (NULL == acs->acs_ic))
        return;

    ic = acs->acs_ic;

    if(ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) {
        /* WAR to skip all secondary 80 whose channel center freq ie less than primary channel center freq*/
        u_int8_t sec_channelrej_list[] = {36,40,44,48 /*1st 80MHz Band*/
                                          ,52,56,60,64 /*2nd 80MHz Band*/
                                          ,100,104,108,112/*3rd 80MHz Band*/
                                          ,116,120,124,128/*4th 80MHz Band*/
                                          ,132,136,140,144/*5th 80MHz Band*/};
        u_int8_t channelrej_num = 0;
        u_int8_t chan_i;

        switch(ieee80211_acs_get_center_freq_idx(primary_channel->ic_vhtop_ch_num_seg1, primary_channel->ic_freq)) {
            case 58:
                channelrej_num = 4; /*Ignore the 1st 80MHz Band*/
                break;
            case 106:
                channelrej_num = 8; /*Ignore the 1st,2nd 80MHz Band*/
                break;
            case 122:
                channelrej_num = 12; /*Ignore the 1st,2nd and 3rd 80MHz Band*/
                break;
            case 138:
                channelrej_num = 16; /*Ignore the 1st,2nd,3rd and 4th 80MHz Band*/
                break;
            case 155:
                channelrej_num = 20; /*Ignore the 1st,2nd,3rd,4th and 5th 80MHz Band*/
                break;
            default:
                channelrej_num = 0;
                break;
        }

        for(chan_i=0;chan_i < channelrej_num;chan_i++)
            acs->acs_channelrejflag[sec_channelrej_list[chan_i]] |= ACS_REJFLAG_NO_SEC_80_80;

    }else if((ic->ic_emiwar_80p80 == EMIWAR_80P80_BANDEDGE) && (ieee80211_acs_get_center_freq_idx(primary_channel->ic_vhtop_ch_num_seg1, primary_channel->ic_freq) == 155)) {
        /* WAR to skip 42 as secondary 80, if 155 as primary 80 center freq */
        acs->acs_channelrejflag[36] |= ACS_REJFLAG_NO_SEC_80_80;
        acs->acs_channelrejflag[40] |= ACS_REJFLAG_NO_SEC_80_80;
        acs->acs_channelrejflag[44] |= ACS_REJFLAG_NO_SEC_80_80;
        acs->acs_channelrejflag[48] |= ACS_REJFLAG_NO_SEC_80_80;
    }
}

/*
 * ieee80211_acs_select_min_nbss:
 * Find the channel with the minimum BSS count.
 *
 * @ic: Pointer to the IC structure.
 *
 * Return:
 * Pointer to the best channel.
 */
static struct ieee80211_ath_channel *
ieee80211_acs_select_min_nbss(struct ieee80211com *ic)
{
#define ADJ_CHANS 8
#define NUM_CHANNELS_2G     11
#define CHANNEL_2G_FIRST    1
#define CHANNEL_2G_LAST     14
#define CHANNEL_5G_FIRST  36

    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_ath_channel *channel = NULL, *best_channel = NULL;
    struct ieee80211_ath_channel *channel_sec80 = NULL, *min_bss_channel = NULL;
    u_int8_t i, min_bss_count = 0xFF;
    uint16_t acs_ch_idx = 0;
    uint16_t channel_num = 0;
    int bestix = -1, bestix_sec80 = -1;
    uint16_t pri20 = 0;
    struct acs_sec_chans sec_chans = {0};
    u_int8_t chan_i, first_adj_chan, last_adj_chan;
    int base_cnt = 0, matc_cnt = 0;

    channel = ieee80211_find_dot11_channel(ic, 0, 0, acs->acs_vap->iv_des_mode);
    if (channel == NULL) {
        return NULL;
    }
    channel_num = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);;

    if ((channel_num >= CHANNEL_2G_FIRST) && (channel_num <= CHANNEL_2G_LAST)) {
        /* mode is 2.4 G */
        for(i = 0; i < acs->acs_nchans; i++)
        {
            channel = acs->acs_chans[i];
            acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);

            if (((acs_ch_idx >= 5) &&  (acs_ch_idx <= 7)) &&
                (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel) || IEEE80211_IS_CHAN_11AXG_HE40MINUS(channel))) {
                 acs_ch_idx = 15 + (acs_ch_idx - 5);
            }


            if(acs->acs_2g_allchan == 0) {
                if((acs_ch_idx != 1) && (acs_ch_idx != 6) && (acs_ch_idx != 11)) {
                  acs_info(BASE, "acs_2g_allchan is disabled, "
                           "channel (%3d) is not 1, 6 or 11. Skipping",
                           acs_ch_idx);
                  continue;
                }
            }
#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
            if(ic->ic_primary_allowed_enable &&
                        !ieee80211_check_allowed_prim_freqlist(ic, channel->ic_freq))
            {
                    acs_info(BASE, "Channel (%3d) is not a primary allowed channel",
                             acs_ch_idx);
                    continue;
            }
#endif
            if (min_bss_count > acs->acs_chan_nbss[acs_ch_idx])
            {
                min_bss_count = acs->acs_chan_nbss[acs_ch_idx];
                min_bss_channel = channel;
                acs_info(BASE, "Update min BSS chan (%3d) and BSS counter (%3d)",
                         ieee80211_chan2freq(acs->acs_ic, min_bss_channel),
                         min_bss_count);
            }
            base_cnt++;
            if (acs->acs_channelrejflag[acs_ch_idx] & ACS_REJFLAG_ADJINTERFERE)
                matc_cnt++;

            acs_info(BASE, "Per-channel information - "
                     "acs_ch_idx (%3d), "
                     "BSS counter (%3d), "
                     "chan_loadsum (%4d), "
                     "base_cnt (%3d), "
                     "match_cnt (%3d)",
                     acs_ch_idx,
                     acs->acs_chan_nbss[acs_ch_idx],
                     acs->acs_chan_loadsum[acs_ch_idx],
                     base_cnt,
                     matc_cnt);
        }

        if (base_cnt == matc_cnt)
        {
            int loadmin = 0xFFFF, minloadix = 0;
            minloadix = eacs_plus_filter(acs,"NBSS", acs->acs_chan_nbss,
                                        "CHLOAD", acs->acs_chan_loadsum,
                                        min_bss_count, 0, ACS_REJFLAG_BLACKLIST,
                                        &loadmin, ACS_REJECT_HIGH, ACS_FIND_MIN);
            if ((minloadix < IEEE80211_ACS_ENH_CHAN_MAX) && (minloadix >= 0))
                 best_channel = acs->acs_chans[minloadix];

            acs_info(BASE, "Selected best chan (%4uMHz) and min load (%4d)",
                     ieee80211_chan2freq(acs->acs_ic, best_channel), loadmin);
        }
        else {
            best_channel = min_bss_channel;
            acs_info(BASE, "Selected best chan (%4uMHz) and BSS counter (%2d)",
                     ieee80211_chan2freq(acs->acs_ic, best_channel), min_bss_count);
        }

    } else if(channel_num >= CHANNEL_5G_FIRST) {
        /* mode is 5 G */
        for (i = 0; i < acs->acs_nchans; i++) {
            channel = acs->acs_chans[i];
            if (ieee80211_acs_check_interference(channel, acs->acs_vap) &&
                (ieee80211_find_dot11_channel(acs->acs_ic,
                          ieee80211_chan2freq(acs->acs_ic, channel), channel->ic_vhtop_freq_seg2,
                             acs->acs_vap->iv_des_mode) != NULL)) {
                    continue;
            }
            acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
            if(acs->acs_channelrejflag[acs_ch_idx] & ACS_REJFLAG_NO_PRIMARY_80_80)
                    continue;

            if (min_bss_count > acs->acs_chan_nbss[acs_ch_idx])
            {
                min_bss_count = acs->acs_chan_nbss[acs_ch_idx];
                best_channel = acs->acs_chans[i];
                bestix = i;
            }
        }
        if ((best_channel) && ieee80211_is_phymode_8080(acs->acs_vap->iv_des_mode)) {
           uint16_t acs_center_idx = ieee80211_acs_get_center_freq_idx(channel->ic_vhtop_ch_num_seg1, channel->ic_freq);
           channel = acs->acs_chans[bestix];
           pri20 = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);

           /* Only secondary 20MHz and secondary 40MHz are required */
           ieee80211_acs_derive_sec_chans_with_mode(acs,
                                                    acs->acs_vap->iv_des_mode,
                                                    channel->ic_freq,
                                                    acs_center_idx,
                                                    0, /* mode is not VHT/HE160 */
                                                    &sec_chans);

           acs->acs_channelrejflag[pri20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_chans.sec_chan_20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_chans.sec_chan_40_1] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_chans.sec_chan_40_2] |= ACS_REJFLAG_PRIMARY_80_80;

           /* EMIWAR 80P80 to skip secondary 80 */
           if(ic->ic_emiwar_80p80) {
               acs_emiwar80p80_skip_secondary_80mhz_chan(acs,channel);
               /*
               * WAR clear the Primary Reject channle flag
               * So channel can be chose best secondary 80 mhz channel
               */

               for (i = 0; i < acs->acs_nchans; i++) {
                   acs_ch_idx = ieee80211_acs_get_chan_idx(acs, acs->acs_chans[i]->ic_freq);
                   acs->acs_channelrejflag[acs_ch_idx] &= ~ACS_REJFLAG_NO_PRIMARY_80_80;
               }
           }
           /* mark channels as unusable for secondary 80 */
           first_adj_chan = (acs_center_idx - 6) - 2*ADJ_CHANS;
           last_adj_chan =  (acs_center_idx + 6) + 2*ADJ_CHANS;
           for(chan_i=first_adj_chan;chan_i <= last_adj_chan; chan_i += 4) {
              if ((chan_i >= (acs_center_idx - 6)) && (chan_i <= (acs_center_idx + 6))) {
                 continue;
              }
              acs->acs_channelrejflag[chan_i] |= ACS_REJFLAG_NO_SEC_80_80;
           }
           bestix_sec80 = acs_find_secondary_80mhz_chan(acs, bestix);
           if(bestix_sec80 == -1) {
              acs_info(BASE, "Issue in random channel selection for sec 80MHz");
           }
           else {
              channel_sec80 = acs->acs_chans[bestix_sec80];
              best_channel->ic_vhtop_ch_num_seg2 = channel_sec80->ic_vhtop_ch_num_seg1;
           }
        }
        acs_info(BASE, "Selected best channel (%4uMHz) with sec 80MHz (%4uMHz) "
                 "and min_bss_count (%2d)",
                 ieee80211_chan2freq(acs->acs_ic, best_channel),
                 ieee80211_chan2freq(acs->acs_ic, channel_sec80),
                 min_bss_count);
    }
#undef NUM_CHANNELS_2G
#undef CHANNEL_2G_FIRST
#undef CHANNEL_2G_LAST
#undef CHANNEL_5G_FIRST
#undef ADJ_CHANS
    return best_channel;
}

/*
 * acs_find_best_channel_ix:
 * Find the best ACS channel based on RSSI filtering.
 *
 * @acs       : Pointer to the ACS structure.
 * @snrvarcor : Value of the given SNR accepted variance.
 * @snrmin    : Value of the minimum SNR in the channel list.
 *
 * Return:
 * Channel number of the best channel.
 */
static int acs_find_best_channel_ix(ieee80211_acs_t acs,
                                    int snrvarcor,
                                    int snrmin)
{
    int snrmix,minload,minloadix,maxregpower,maxregpowerindex;
    int minsrix, minsrload;
    /*Find Best Channel load channel out of Best RSSI Channel with variation of 20%*/
    acs_info(BASE, "Running RSSI filter");
    minsrload = 0xFFFF;
    minsrix = eacs_plus_filter(acs,"RSSI",acs->acs_chan_snrtotal, "SR",
                             acs->acs_srp_load, snrmin,
                             acs->acs_snrvar + snrvarcor, ACS_REJFLAG_SNR,
                             &minsrload, ACS_REJECT_HIGH, ACS_FIND_MIN);

    if ((minsrix > 0) && (minsrix < IEEE80211_ACS_ENH_CHAN_MAX))
        acs_info(BASE, "Selected channel (%4uMHz) with minimum SR (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[minsrix]),
                 minsrload);

    acs_info(BASE, "Running SR filter");
    minload = 0xFFFF;
    minloadix  = eacs_plus_filter(acs,"SR",acs->acs_srp_load, "CHLOAD",
                             acs->acs_chan_loadsum, minsrload,
                             acs->acs_srvar, ACS_REJFLAG_SPATIAL_REUSE,
                             &minload, ACS_REJECT_HIGH, ACS_FIND_MIN);

    if ((minloadix > 0) && (minloadix < IEEE80211_ACS_ENH_CHAN_MAX))
        acs_info(BASE, "Selected channel (%4uMHz) with minimum chan load (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[minloadix]),
                 minload);

    acs_info(BASE, "Running channel load filter");
    maxregpower =0;
    maxregpowerindex  = eacs_plus_filter(acs,"CH LOAD",acs->acs_chan_loadsum,
                                          "REGPOWER", acs->acs_chan_regpower,
                                          minload, acs->acs_chloadvar,
                                          ACS_REJFLAG_CHANLOAD, &maxregpower,
                                          ACS_REJECT_HIGH, ACS_FIND_MAX);

    if ((maxregpowerindex > 0) && (maxregpowerindex < IEEE80211_ACS_ENH_CHAN_MAX))
        acs_info(BASE, "Selected channel (%4uMHz) with max reg power (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[maxregpowerindex]),
                 maxregpower);

    acs_info(BASE, "Running regulatory filter");

    snrmin = 1;
    snrmix  = eacs_plus_filter(acs,"REG POWER",acs->acs_chan_regpower,
                                  "RSSI TOTOAL", acs->acs_chan_snrtotal,
                                  maxregpower, 0 ,  ACS_REJFLAG_REGPOWER, &snrmin,
                                  ACS_REJECT_LOW, ACS_FIND_MIN);

    if ((snrmix > 0) && (snrmix < IEEE80211_ACS_ENH_CHAN_MAX)) {
        acs_info(BASE, "Selected channel (%4uMHz) with minimum RSSI (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[snrmix]),
                 snrmin);
    }
    return snrmix;
}

/*
 * acs_find_best_channel_ix_chan_efficiency:
 * Find the best channel based on the channel efficiency filtering.
 *
 * @acs      : Pointer to the ACS structure.
 * @effvarcor: Value of the accepted variance for channel efficiency.
 * @effmax   : Value of the minimum channel efficiency in the channel list.
 *
 * Return:
 * Channel number of the best channel.
 */
static int acs_find_best_channel_ix_chan_efficiency(ieee80211_acs_t acs,
                                                    int effvarcor,
                                                    int effmax)
{
    int effmix,minload,minloadix,maxregpower,maxregpowerindex;
    int minsrix, minsrload;
    /*Find Best Channel load channel out of Best RSSI Channel with variation of 20%*/
    acs_info(BASE, "Running channel efficiency filter");
    minsrload = 1;
    minsrix = eacs_plus_filter(acs,"EFF",acs->chan_efficiency, "SR",
                             acs->acs_srp_load, effmax,
                             acs->acs_effvar + effvarcor, ACS_REJFLAG_EFF,
                             &minsrload, ACS_REJECT_LOW, ACS_FIND_MIN );

    if ((minsrix > 0) && (minsrix < IEEE80211_ACS_ENH_CHAN_MAX))
        acs_info(BASE, "Selected channel (%4uMHz) with minimum SR (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[minsrix]),
                 minsrload);

    acs_info(BASE, "Running SR filter");
    minload = 0xFFFF;
    minloadix  = eacs_plus_filter(acs,"SR",acs->acs_srp_load, "CHLOAD",
                             acs->acs_chan_loadsum, minsrload,
                             acs->acs_srvar, ACS_REJFLAG_SPATIAL_REUSE,
                             &minload, ACS_REJECT_HIGH, ACS_FIND_MIN);

    if ((minloadix > 0) && (minloadix < IEEE80211_ACS_ENH_CHAN_MAX))
        acs_info(BASE, "Selected channel (%4uMHz) with minimum chan load (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[minloadix]),
                 minload);

    acs_info(BASE, "Running channel load filter");
    maxregpower =0;
    maxregpowerindex  = eacs_plus_filter(acs,"CH LOAD",acs->acs_chan_loadsum,
                                          "REGPOWER", acs->acs_chan_regpower,
                                          minload, acs->acs_chloadvar,
                                          ACS_REJFLAG_CHANLOAD, &maxregpower,
                                          ACS_REJECT_HIGH, ACS_FIND_MAX);

    if ((maxregpowerindex > 0) && (maxregpowerindex < IEEE80211_ACS_ENH_CHAN_MAX))
        acs_info(BASE, "Selected channel (%4uMHz) with max reg power (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[maxregpowerindex]),
                 maxregpower);

    acs_info(BASE, "Running regulatory filter");

    effmax = 0;
    effmix = eacs_plus_filter(acs,"REG POWER",acs->acs_chan_regpower,
                                          "CHEFF", acs->chan_efficiency,
                                          maxregpower, 0 ,
                                          ACS_REJFLAG_REGPOWER, &effmax,
                                          ACS_REJECT_LOW, ACS_FIND_MAX);
    if ((effmix > 0) && (effmix < IEEE80211_ACS_ENH_CHAN_MAX)) {
        acs_info(BASE, "Selected channel (%4uMHz) with minimum channel efficiency (%4d)",
                 ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[effmix]),
                 effmax);
    }

    return effmix;
}

/*
 * ieee80211_acs_find_best_11na_centerchan:
 * Find the best channel for the 5GHz/6GHz band.
 *
 * NOTE:
 * In 5 GHz, if the channel is unoccupied the max rssi should be zero;
 * just take it. Otherwise track the channel with the lowest
 * rssi and use that when all channels appear occupied.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 * Pointer to the best channel for the 5GHz/6GHz band.
 */
static struct ieee80211_ath_channel *
ieee80211_acs_find_best_11na_centerchan(ieee80211_acs_t acs)
{
#define ADJ_CHANS 8
    struct ieee80211_ath_channel *channel, *channel_sec80;
    struct ieee80211_ath_channel *tmpchannel;
    int i;
    int cur_chan;
    struct ieee80211_acs_adj_chan_stats *adj_chan_stats;
    int minnf,nfmix,rssimin,rssimix,bestix, bestix_sec80;
    int tmprssimix = 0;
    int rssivarcor=0,prinfclean = 0, secnfclean = 0;
    int effmax,effmix;
    int effvarcor=0;
    int reg_tx_power;
    bool is_dfs_precac_list_empty = false;
    uint16_t pri20;
    struct acs_sec_chans sec_chans = {0};
    uint16_t center_freq;
    uint16_t chan_i, first_adj_chan, last_adj_chan;
    struct ieee80211com *ic = acs->acs_ic;
    uint32_t dfs_reg = 0;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;
#if ATH_SUPPORT_VOW_DCS
    u_int32_t nowms =  (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    u_int8_t intr_chan_cnt = 0;
    uint16_t acs_ch_idx = 0;

#define DCS_PENALTY    30     /* channel utilization in % */
    for (i = 0; i < acs->acs_nchans; i++) {
        channel = acs->acs_chans[i];
        if (ieee80211_acs_check_interference(channel, acs->acs_vap)) {
            continue;
        }
        acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);

        if ( acs->acs_intr_status[acs_ch_idx] ){
            if ((nowms >= acs->acs_intr_ts[acs_ch_idx]) &&
                    ((nowms - acs->acs_intr_ts[acs_ch_idx]) <= DCS_AGING_TIME)){
                acs->acs_chan_load[acs_ch_idx] += DCS_PENALTY;
                intr_chan_cnt = acs->acs_intr_status[acs_ch_idx];
            }
            else{
                acs->acs_intr_status[acs_ch_idx] = 0;
            }
        }
    }

#undef DCS_PENALTY
#endif

    acs_info(BASE, "Finding best 5/6GHz channel");

    acs->acs_minrssi_11na = 0xffffffff; /* Some large value */

    /* Scan through the channel list to find the best channel */
    minnf = 0xFFFF; /*Find max NF*/
    nfmix = -1;

    rssimin = 0xFFFF;
    rssimix= -1;

    effmax = 0;
    effmix = -1;

    if(ieee80211_is_phymode_8080(acs->acs_vap->iv_des_mode) && \
          (acs->acs_ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2)) {
          /*
          * When EMIWAR is EMIWAR_80P80_FC1GTFC2
          * there will be no 80_80 channel combination for 149,153,157,161,
          * as we forcefully added the 80MHz channel to acs_chan list
          * mark those channle as NO Primary Select so acs will consider as primary channel
          * but can consider these channel as secondary channel.
          */
          for (i = 0; i < acs->acs_nchans; i++) {
              if (!ieee80211_is_phymode_8080(ieee80211_chan2mode(acs->acs_chans[i]))){
                  cur_chan = ieee80211_acs_get_chan_idx(acs, acs->acs_chans[i]->ic_freq);
                  acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_NO_PRIMARY_80_80;
              }
          }
    }

    pdev = ic->ic_pdev_obj;
    if(!pdev) {
        acs_err("Null pdev");
        return NULL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        acs_err("Null psoc");
        return NULL;
    }

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
    if (!reg_rx_ops) {
        acs_err("Null reg_rx_ops");
        return NULL;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
            QDF_STATUS_SUCCESS) {
        acs_err("Could not get reference to pdev");
        return NULL;
    }

    reg_rx_ops->get_dfs_region(pdev, &dfs_reg);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);

    /* Check if the preCAC completed channel list is empty */
    if (acs->acs_ic->ic_acs_precac_completed_chan_only &&
        (mlme_dfs_precac_status_for_channel(acs->acs_ic->ic_pdev_obj,
                                 acs->acs_chans[0]) == DFS_NO_PRECAC_COMPLETED_CHANS)) {
        acs_info(BASE, "Precac done list is empty. Ignoring precac rejections");
        is_dfs_precac_list_empty = true;
    }

    adj_chan_stats = (struct ieee80211_acs_adj_chan_stats *) OS_MALLOC(acs->acs_osdev,
            IEEE80211_CHAN_MAX * sizeof(struct ieee80211_acs_adj_chan_stats), 0);

    if (adj_chan_stats) {
        OS_MEMZERO(adj_chan_stats, sizeof(struct ieee80211_acs_adj_chan_stats) * IEEE80211_CHAN_MAX);
    } else {
        acs_err("Failed to allocate memory for adj_chan_stats");
        return NULL;
    }

    for (i = 0; i < acs->acs_nchans; i++) {
        channel = acs->acs_chans[i];
        cur_chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
        acs_info(BASE, "Checking chan (%d)", cur_chan);

        /* The BLACKLIST flag need to be preserved for each channel till all
         * the channels are looped, since it is used rejecting the already
         * Ranked channels in the ACS ranking feature */
        if ((acs->acs_ranking) && (acs->acs_channelrejflag[cur_chan] & ACS_REJFLAG_BLACKLIST))
        {
            acs->acs_channelrejflag[cur_chan] &= ACS_REJFLAG_NO_PRIMARY_80_80;
            acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_BLACKLIST;
        }
        else {
        /*Clear all the reject flag except ACS_REJFLAG_NO_PRIMARY_80_80*/
            acs->acs_channelrejflag[cur_chan] &= ACS_REJFLAG_NO_PRIMARY_80_80;
        }

        /* Check if it is 5GHz channel  */
        if (!IEEE80211_IS_CHAN_5GHZ_6GHZ(channel)){
            acs->acs_channelrejflag[cur_chan] |= ACS_FLAG_NON5G;
            continue;
        }
        /* Best Channel for VHT BSS shouldn't be the secondary channel of other BSS
         * Do not consider this channel for best channel selection
         */
        if((acs->acs_vap->iv_des_mode == IEEE80211_MODE_AUTO) ||
                (acs->acs_vap->iv_des_mode >= IEEE80211_MODE_11AC_VHT20)) {
            if (acs->acs_sec_chan[cur_chan] == true) {
                acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_SECCHAN;
                acs_info(BASE, "Rejecting (%#010x) channel (%3d) as secondary channel due to AUTO/VHT phymode",
                         acs->acs_channelrejflag[cur_chan], cur_chan);
            }
        }
        if(acs->acs_ic->ic_no_weather_radar_chan) {
            if(ieee80211_check_weather_radar_channel(channel)
                    && (dfs_reg == DFS_ETSI_DOMAIN)) {
                acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_WEATHER_RADAR ;
                acs_info(BASE, "Rejecting (%#010x) channel (%3d) due to presence of weather/radar",
                         acs->acs_channelrejflag[cur_chan], cur_chan);
                continue;
            }
        }
        /* Check of DFS and other modes where we do not want to use the
         * channel
         */
        if (ieee80211_acs_check_interference(channel, acs->acs_vap)) {
            acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_DFS ;
            acs_info(BASE, "Rejecting (%#010x) channel (%3d) due to presence of DFS interference",
                     acs->acs_channelrejflag[cur_chan], cur_chan);
            continue;
        }

        /*
         * Check if the current channel, if DFS, has completed its preCAC.
         * The API will check the entire bandwidth of the desired channel.
         * The channel is to be rejected even if the secondary channels are
         * preCAC incomplete.
         */
        if (acs->acs_ic->ic_acs_precac_completed_chan_only &&
            !is_dfs_precac_list_empty &&
            IEEE80211_IS_CHAN_DFSFLAG(channel) &&
            ieee80211_acs_check_precac_status(acs, channel)) {
            acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_PRECAC_INCOMPLETE;
            acs_info(BASE, "Rejecting (%#010x) channel (%3d) since pre-CAC is not cleared",
                     acs->acs_channelrejflag[cur_chan], cur_chan);
            continue;
        }

        /* Check if the noise floor value is very high. If so, it indicates
         * presence of CW interference (Video Bridge etc). This channel
         * should not be used
         */

        if ((minnf > acs->acs_noisefloor[cur_chan]) &&
             ((acs->acs_channelrejflag[cur_chan] & ACS_REJFLAG_SECCHAN) == 0) &&
             ((acs->acs_channelrejflag[cur_chan] & ACS_REJFLAG_NO_PRIMARY_80_80) == 0))
        {
            minnf = acs->acs_noisefloor[cur_chan];
            nfmix = i;
        }

        acs->acs_chan_nbss_weighted[cur_chan] = 100 + (acs->acs_chan_nbss_near[cur_chan] * acs->acs_obss_near_range_weightage)
                                                + (acs->acs_chan_nbss_mid[cur_chan] * acs->acs_obss_mid_range_weightage)
                                                + (acs->acs_chan_nbss_far[cur_chan] * acs->acs_obss_far_range_weightage);

        if ((acs->acs_noisefloor[cur_chan] != NF_INVALID) && (acs->acs_noisefloor[cur_chan] >= ic->ic_acs->acs_noisefloor_threshold) ) {
            acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_HIGHNOISE;
            acs->acs_chan_loadsum[cur_chan] = 100;
            if(acs->acs_chan_snr[cur_chan] < 100) {
               acs->acs_chan_snr[cur_chan] = 100;
            }
            acs->acs_chan_nbss_weighted[cur_chan] = 10000;
            acs_info(BASE, "Rejecting (%#010x) channel (%3d) due to high NF",
                     acs->acs_channelrejflag[cur_chan], cur_chan);
        } else {
            prinfclean++;
            acs->acs_chan_loadsum[cur_chan] = acs->acs_chan_load[cur_chan];
        }

        acs->acs_chan_snrtotal[cur_chan] = acs->acs_chan_snr[cur_chan];
        acs->acs_srp_load[cur_chan] = acs->acs_srp_supported[cur_chan] * ACS_DEFAULT_SR_LOAD;

        if (!adj_chan_stats[i].if_valid_stats) {
            ieee80211_acs_get_adj_ch_stats(acs, channel, &adj_chan_stats[i]);
            acs->acs_adjchan_load[cur_chan]    =  adj_chan_stats[i].adj_chan_load;
            acs->acs_chan_loadsum[cur_chan]   +=  adj_chan_stats[i].adj_chan_loadsum;
            acs->acs_chan_snrtotal[cur_chan] +=  adj_chan_stats[i].adj_chan_rssisum;
            acs->acs_chan_nbss_weighted[cur_chan] +=  adj_chan_stats[i].adj_chan_obsssum;
            acs->acs_adjchan_flag[cur_chan]       =  adj_chan_stats[i].adj_chan_flag;
            acs->acs_srp_load[cur_chan] +=  adj_chan_stats[i].adj_chan_srsum;

            if(! acs->acs_adjchan_flag[cur_chan])
                secnfclean++;
        }

        if (!acs->acs_channelrejflag[cur_chan]) {
            if (rssimin > acs->acs_chan_snrtotal[cur_chan]) {
                rssimin = acs->acs_chan_snrtotal[cur_chan];
                rssimix = i;
            }
        }

        /*
         * ETSI UNII-II Ext band has different limits for STA and AP.
         * The software reg domain table contains the STA limits(23dBm).
         * For AP we adjust the max power(30dBm) dynamically
         */
        if (UNII_II_EXT_BAND(ieee80211_chan2freq(acs->acs_ic, channel))
                && (dfs_reg == DFS_ETSI_DOMAIN)){
            reg_tx_power = MIN( 30, channel->ic_maxregpower+7 );
        }
        else {
            reg_tx_power  = channel->ic_maxregpower;
        }

        if(acs->acs_chan_regpower[cur_chan]) {
            acs->acs_chan_regpower[cur_chan] = MIN( acs->acs_chan_regpower[cur_chan], reg_tx_power);
        }
        else {
            acs->acs_chan_regpower[cur_chan] = reg_tx_power;
        }
        acs_info(REGPOWER, "Received tx power (%4d) for chan (%3d) and self tx power (%d)",
                 acs->acs_chan_regpower[cur_chan], cur_chan, reg_tx_power);

	/* channel efficieny is (100 /(OBSS/100)) * (channel grade/100). To collect one decimal point extra
	multipling with 10 */
        acs->chan_efficiency[cur_chan] = (1000 * acs->hw_chan_grade[cur_chan])/acs->acs_chan_nbss_weighted[cur_chan];

        if(!acs->acs_channelrejflag[cur_chan]){
            if(effmax < acs->chan_efficiency[cur_chan]){
                effmax = acs->chan_efficiency[cur_chan];
                effmix = i;
            }
        }

        /* check neighboring channel load
         * pending - first check the operating mode from beacon( 20MHz/40 MHz) and
         * based on that find the interfering channel
         */
        acs_info(BASE, "Collected channel stats - "
                 "cur_chan (%3d), "
                 "acs_chan_rssi (%4d), "
                 "acs_chan_rssitotal (%4d), "
                 "acs_noisefloor (%4d), "
                 "acs_chan_regpower (%4d), "
                 "acs_chan_load (%4d), "
                 "acs_adjchan_load (%4d), "
                 "acs_chan_loadsum (%4d), "
                 "acs_chan_nbss_weighted (%4d), "
                 "acs_chan_efficiency (%4d)",
                 cur_chan,
                 acs->acs_chan_snr[cur_chan],
                 acs->acs_chan_snrtotal[cur_chan],
                 acs->acs_noisefloor[cur_chan],
                 acs->acs_chan_regpower[cur_chan],
                 acs->acs_chan_load[cur_chan],
                 acs->acs_adjchan_load[cur_chan],
                 acs->acs_chan_loadsum[cur_chan],
                 acs->acs_chan_nbss_weighted[cur_chan],
                 acs->chan_efficiency[cur_chan]);
    }

    if(prinfclean == 0){
        acs_info(BASE, "Extremely exceptional case - "
                 "all channels flooded with high NF, "
                 "selecting min NF channel (%4d)",
                 nfmix);
        bestix = nfmix;
        goto selectchan;
    }

    if(secnfclean > 0){
        rssimix =-1;
        rssimin = 0xFFFF;

        /*apply adj channel nf free filter to main rej flag i recalculate rssimin*/
        for (i = 0; i < acs->acs_nchans; i++) {

            channel = acs->acs_chans[i];
            cur_chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
            acs->acs_channelrejflag[cur_chan] |= acs->acs_adjchan_flag[cur_chan];
            if(!acs->acs_channelrejflag[cur_chan]){
                if(rssimin > acs->acs_chan_snrtotal[cur_chan]){
                    rssimin = acs->acs_chan_snrtotal[cur_chan];
                    tmprssimix = i;
                }
            }
        }
        /*
        * Don't update the rssimix if all the secondary channels are rejected
        * and Clear the rejection flag
        */
        if(tmprssimix == -1) {
            for (i = 0; i < acs->acs_nchans; i++) {
               channel = acs->acs_chans[i];
               cur_chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
               acs->acs_channelrejflag[cur_chan] &= ~acs->acs_adjchan_flag[cur_chan];
            }
        } else {
            rssimix = tmprssimix;
        }

    } else {
        /*Non of the secondary are clean */
        /*Ignor the RSSI use only channle load */
        rssivarcor=1000;
        effvarcor = 60;
        acs_info(BASE, "Rare scenario - All the channel has NF at the secondary channel - "
                 "Increase rssivarcor to 1000 and effvarcor to 60");
    }

    if (rssimix > 0) {
        acs_info(BASE, "Minimum RSSI channel (%3d)",  ieee80211_acs_get_chan_idx(acs, acs->acs_chans[rssimix]->ic_freq));
    }
    if (effmix > 0) {
        acs_info(BASE, "Maximum efficiency channel (%3d)", ieee80211_acs_get_chan_idx(acs, acs->acs_chans[effmix]->ic_freq));
    }

    if (!acs->acs_chan_grade_algo) {
        acs_info(BASE, "Finding best channel through RSSI metric");
        bestix = rssimix;
        bestix = acs_find_best_channel_ix(acs, rssivarcor, rssimin);
    } else {
        acs_info(BASE, "Finding best channel through channel grade metric");
        bestix = effmix;
        bestix = acs_find_best_channel_ix_chan_efficiency(acs, effvarcor, effmax);
    }

selectchan :

    acs->acs_11nabestchan = bestix;
    if ((bestix >= 0) && (bestix < IEEE80211_ACS_ENH_CHAN_MAX)) {
        channel = acs->acs_chans[bestix];
        if (!channel) {
            /* It is unlikely acs_chans will be NULL. */
            acs_err("Invalid channel with bestix (%d)", bestix);
            OS_FREE(adj_chan_stats);
            return NULL;
        }

        acs->acs_status = ACS_SUCCESS;
#if ATH_SUPPORT_VOW_DCS
        ic->ic_eacs_done = 1;
#endif

        acs_info(BASE, "Selected 80MHz index (%3d) with frequency (%4uMHz) and IEEE chan (%3d)",
                 bestix, channel->ic_freq, channel->ic_ieee);
        if ((acs->acs_vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) ||
            (acs->acs_vap->iv_des_mode == IEEE80211_MODE_11AXA_HE80_80)) {
            /* dervice primary and secondary channels from the channel */
           pri20 = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
            /* Derive secondary channels */
           center_freq = ieee80211_acs_get_center_freq_idx(channel->ic_vhtop_ch_num_seg1, channel->ic_freq);

           /* Only secondary 20MHz and secondary 40MHz required */
           ieee80211_acs_derive_sec_chans_with_mode(acs,
                                                    acs->acs_vap->iv_des_mode,
                                                    channel->ic_freq,
                                                    center_freq,
                                                    0, /* Mode is not VHT/HE160 */
                                                    &sec_chans);

            /* Mark Primary 80Mhz channels for not selecting as secondary 80Mhz */
           acs->acs_channelrejflag[pri20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_chans.sec_chan_20] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_chans.sec_chan_40_1] |= ACS_REJFLAG_PRIMARY_80_80;
           acs->acs_channelrejflag[sec_chans.sec_chan_40_2] |= ACS_REJFLAG_PRIMARY_80_80;

           /* EMIWAR 80P80 to skip secondary 80 */
           if(ic->ic_emiwar_80p80)
               acs_emiwar80p80_skip_secondary_80mhz_chan(acs,channel);
           /* mark channels as unusable for secondary 80 */
           first_adj_chan = (center_freq - 6) - 2*ADJ_CHANS;
           last_adj_chan =  (center_freq + 6) + 2*ADJ_CHANS;
           for(chan_i=first_adj_chan;chan_i <= last_adj_chan; chan_i += 4) {
              if ((chan_i >= (center_freq -6)) && (chan_i <= (center_freq +6))) {
                 continue;
              }
              acs->acs_channelrejflag[chan_i] |= ACS_REJFLAG_NO_SEC_80_80;
           }

           tmprssimix = -1;
           for (i = 0; i < acs->acs_nchans; i++) {
               tmpchannel = acs->acs_chans[i];
               cur_chan = ieee80211_acs_get_chan_idx(acs, tmpchannel->ic_freq);
               rssimin = 0xFFFF;
               /*
               *  reset RSSI, CHANLOAD, REGPOWER, NO_PRIMARY_80_80 flags,
               *  to allow it chose best secondary 80 mhz channel
               */
               acs->acs_channelrejflag[cur_chan] = acs->acs_channelrejflag[cur_chan] &
                                                   (~(ACS_REJFLAG_SNR | ACS_REJFLAG_CHANLOAD
                                                        | ACS_REJFLAG_REGPOWER | ACS_REJFLAG_SECCHAN
                                                        | ACS_REJFLAG_NO_PRIMARY_80_80
                                                        | ACS_REJFLAG_SEC80_DIFF_BAND));

               if (ieee80211_get_band_flag(channel->ic_freq) != ieee80211_get_band_flag(tmpchannel->ic_freq)) {
                   acs->acs_channelrejflag[cur_chan] |= ACS_REJFLAG_SEC80_DIFF_BAND;
               }

               if(!acs->acs_channelrejflag[cur_chan]){
                   if(rssimin > acs->acs_chan_snrtotal[cur_chan]){
                       rssimin = acs->acs_chan_snrtotal[cur_chan];
                       tmprssimix = i;
                   }
               }
           }
           if(tmprssimix != -1) {
              bestix_sec80 = tmprssimix;
           }
            /* how to handle DFS channels XXX*/
           bestix_sec80 = acs_find_best_channel_ix(acs, rssivarcor, rssimin);

           acs_info(BASE, "Selected best secondary 80MHz index (%3d)", bestix_sec80);
            /* Could not find the secondary 80mhz channel, pick random channel as
               secondary 80mhz channel */
           if (!((bestix_sec80 >= 0) && (bestix_sec80 < IEEE80211_ACS_ENH_CHAN_MAX))) {
              bestix_sec80 = acs_find_secondary_80mhz_chan(acs, bestix);
              acs_info(BASE, "Random channel is selected for secondary 80MHz (%3d)", bestix_sec80);
           }
           if(bestix_sec80 == -1) {
              acs_info(BASE, "Issue in random secondary 80MHz channel selection");
           }
           else {
              channel_sec80 = acs->acs_chans[bestix_sec80];
              acs_info(BASE, "Selected secondary 80MHz index (%3d) with freq (%4uMHz) and IEEE chan (%3d)",
                       bestix_sec80, channel_sec80->ic_freq, channel_sec80->ic_ieee);
              channel = ieee80211_find_dot11_channel(acs->acs_ic, channel->ic_freq, channel_sec80->ic_vhtop_freq_seg1, acs->acs_vap->iv_des_mode);
              if (channel == NULL) {
                  qdf_err("null freq");
              }
           }
        }
    } else {
        /* If no channel is derived, then pick the random channel(least BSS) for operation */
        acs_err("ACS failed to derive a channel. So selecting channel with least BSS");
        channel = ieee80211_acs_select_min_nbss(acs->acs_ic);
        acs->acs_status = ACS_FAILED_NBSS;
        if (channel == NULL) {
            if (ieee80211_is_phymode_8080(acs->acs_vap->iv_des_mode)) {
                acs->acs_ic->ic_curchan->ic_vhtop_freq_seg2 = 5775;
            }
            channel = ieee80211_find_dot11_channel(acs->acs_ic, 0, 0, acs->acs_vap->iv_des_mode);
            acs->acs_status = ACS_FAILED_RNDM;
            if (channel) {
                acs_info(BASE, "Selected channel (%3d)", ieee80211_acs_get_chan_idx(acs, channel->ic_freq));
            }
        }
        if(channel) {
            acs_info(BASE, "Selected random channel (%3d) with freq (%4uMHz)",
                     channel->ic_ieee,channel->ic_freq);
        }
        /* In case of ACS ranking this is called multiple times and creates
		 * lot of logs on console */
        if (!acs->acs_ranking) {
            ieee80211_acs_scan_report_internal(acs->acs_ic);
        }
    }
    OS_FREE(adj_chan_stats);

    /*
     * The channel information is maintained in ACS as an array of objects of
     * the ieee80211_ath_channel type and not as an array of pointers to ic
     * channels list. Since right now, IC channels are maintained and all
     * the major pointers like ic_curchan, ic_prevchan etc., still point to the
     * ic channels global array, to continue comparison of the channel found
     * here and other global pointers directly (pointer comparison),
     * find the pointer with the same channel parameters in the ic channels
     * and return that pointer.
     * Please note that once ic channels is no longer in use, this conversion
     * will be removed.
     */
    if (channel)
        channel = ieee80211_find_dot11_channel(acs->acs_ic, channel->ic_freq,
                                               channel->ic_vhtop_freq_seg2,
                                               ieee80211_chan2mode(channel));
    return channel;
#undef ADJ_CHANS
}

struct centerchan {
    u_int8_t count;                                      /* number of chans to average the rssi */
    u_int8_t chanlist[IEEE80211_OVERLAPPING_INDEX_MAX];  /* the possible beacon channels around center chan */
};

/*
 * ieee80211_acs_find_channel_totalrssi:
 * Calculate the RSSI-related parameters for a given channel and its overlapping
 * channels in the 2.4GHz band.
 *
 * @acs      : Pointer to the ACS structure.
 * @chanlist : Pointer to overlapping channel list.
 * @chancount: Value of the number of channels in the overlapping channel list.
 * @centChan : Value of the given center channel.
 *
 * Return:
 * RSSI of the given center channel.
 */
static int32_t ieee80211_acs_find_channel_totalrssi(ieee80211_acs_t acs,
                                                    const uint8_t *chanlist,
                                                    uint8_t chancount,
                                                    uint8_t centChan)
{
    u_int8_t chan;
    int i;
    u_int32_t totalrssi = 0; /* total rssi for all channels so far */
    uint32_t total_srload = 0;
    uint16_t total_nbss_weighted = 100; /* Set to include the self-BSS */
    int effchfactor;

    if (chancount <= 0) {
        /* return a large enough number for not to choose this channel */
        return 0xffffffff;
    }

    for (i = 0; i < chancount; i++) {
        chan = chanlist[i];

        effchfactor = chan - centChan;

        if(effchfactor < 0)
            effchfactor = 0 - effchfactor;

        effchfactor += 1;

        totalrssi += acs->acs_chan_snr[chan]/effchfactor;
        total_srload += acs->acs_srp_supported[chan] * (ACS_DEFAULT_SR_LOAD/effchfactor);
        total_nbss_weighted += ((acs->acs_chan_nbss_near[chan] * acs->acs_obss_near_range_weightage)
                               + (acs->acs_chan_nbss_mid[chan]  * acs->acs_obss_mid_range_weightage)
                               + (acs->acs_chan_nbss_far[chan]  * acs->acs_obss_far_range_weightage))/effchfactor;

        /* Check if centChan has adjacent channel wifi interference*/
        if ((chan != centChan) && (acs->acs_chan_snr[chan] > 0))
            acs->acs_channelrejflag[centChan] |= ACS_REJFLAG_ADJINTERFERE;

        acs_info(RSSI, "Per-channel RSSI stats - "
                 "center_chan (%3d), "
                 "chan (%3d), "
                 "effchfactor (%3d), "
                 "eff_rssi (%4d), "
                 "eff_srload (%4d), "
                 "num_SRP_bss (%4d), "
                 "weighted NBSS (%4d)",
                 centChan,
                 chan,
                 effchfactor,
                 acs->acs_chan_snr[chan],
                 (acs->acs_srp_supported[chan] * (ACS_DEFAULT_SR_LOAD/effchfactor)),
                 acs->acs_srp_supported[chan],
                 total_nbss_weighted);
    }

    acs->acs_chan_snrtotal[centChan] = totalrssi;
    acs->acs_srp_load[centChan] = total_srload;
    acs->acs_chan_nbss_weighted[centChan] = total_nbss_weighted;

    acs_info(BASE, "Compiled RSSI stats for center channel (%3d) - "
             "rssitotal (%4d), "
             "srp_load (%4d), "
             "nbss_weighted (%4d)",
             centChan,
             acs->acs_chan_snrtotal[centChan],
             acs->acs_srp_load[centChan],
             acs->acs_chan_nbss_weighted[centChan]);
    return totalrssi;
}

static int ieee80211_acs_check_overlapping_channel_nf(ieee80211_acs_t acs, const u_int8_t *chanlist, u_int8_t chancount, u_int8_t centChan)
{
    u_int8_t chan = 0;
    int i;

    if (chancount <= 0) {
        return -1;
    }

    for (i = 0; i < chancount; i++) {
        chan = chanlist[i];

        if (((acs->acs_noisefloor[chan] != NF_INVALID) &&
               (acs->acs_noisefloor[chan] > ACS_11NG_NOISE_FLOOR_REJ)) ||
                                           (acs->acs_noisefloor[chan] == 0)) {
            acs_info(NF, "Skipping channel (%3d) due to high NF (%4d)",
                     chan, acs->acs_noisefloor[chan]);
            /* Reject centChan if CW found in overlapping channel */
            acs->acs_channelrejflag[centChan] |= ACS_REJFLAG_HIGHNOISE;
            acs->acs_chan_loadsum[centChan] += 100;
            acs->acs_chan_nbss_weighted[centChan] += 100;
            return -1;
        }
    }
    return 0;
}

/*
 * ieee80211_get_11ng_overlapping_chans:
 * Find the overlapping channels for a given channel in the 2.4GHz band.
 *
 * @centerchans: Pointer to the memory block to store channels in.
 * @acs        : Pointer to the ACS structure.
 */
static void ieee80211_get_11ng_overlapping_chans(struct centerchan *centerchans,
                                                 ieee80211_acs_t acs)
{
    u_int8_t i, j, max_chans;
    u_int32_t first_chfreq, acs_nchfreq, min_freq, low_freq, high_freq;

    if(!IEEE80211_IS_CHAN_2GHZ(acs->acs_chans[0]))
    {
        /* We should never end up here */
        acs_info(BASE, "Not a 2.4GHz channel (%3d)",
                 ieee80211_acs_get_chan_idx(acs, acs->acs_chans[0]->ic_freq));
        return;
    }
    first_chfreq = 2412;
    acs_nchfreq = acs->acs_chans[acs->acs_nchans - 1]->ic_freq;
    min_freq = acs->acs_chans[0]->ic_freq;

    max_chans = ieee80211_acs_get_chan_idx(acs,acs_nchfreq);
    /* When the scan is happening on dual-band, the first channels added to acs_chans will be of 2GH */
    for(i = (ieee80211_acs_get_chan_idx(acs, min_freq) - 1);min_freq <= acs_nchfreq && i < max_chans && i < IEEE80211_MAX_2G_SUPPORTED_CHAN; min_freq += 5, i++)
    {
       low_freq = (min_freq - 10) < first_chfreq ? first_chfreq : (min_freq - 10);
       high_freq = (min_freq + 10) > acs_nchfreq ? acs_nchfreq : (min_freq + 10);
       for(j = 0; low_freq <= high_freq && j < IEEE80211_OVERLAPPING_INDEX_MAX; j++)
       {
          centerchans[i].chanlist[j] = ieee80211_acs_get_chan_idx(acs, low_freq);
          centerchans[i].count++;
          low_freq += 5;
       }
    }
}

/*
 * ieee80211_acs_find_best_11ng_centerchan:
 * Find the best channel for the 2.4GHz band.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 * Pointer to the best channel.
 */
static struct ieee80211_ath_channel *
ieee80211_acs_find_best_11ng_centerchan(ieee80211_acs_t acs)
{
    struct ieee80211_ath_channel *channel;
    int i;
    u_int8_t chan;
#if 0
    u_int8_t band;
#endif
    unsigned int   totalrssi = 0;
    int            bestix,nfmin,nfmix,rssimin,rssimix;
    int            extchan,ht40minus_chan ;
    int rssivarcor=0;
    int effmax, effmix;
    int effvarcor=0;
    uint32_t obss_weighted = 0;

#if ATH_SUPPORT_VOW_DCS || WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
    struct ieee80211com *ic = acs->acs_ic;
#endif

    struct centerchan centerchans[IEEE80211_MAX_2G_SUPPORTED_CHAN];

    acs_info(BASE, "Finding best 2.4GHz channel");
    /*
     * The following center chan data structures are used to calculare the
     * the Total RSSI of beacon seen in the center chan and overlapping channel
     * The channle with minimum Rssi gets piccked up as best channel
     * The channel with 20% Rssi variance with minimum will go for next phase of
     * filteration for channel load.
     */
    OS_MEMSET(centerchans, 0x0, sizeof(centerchans));
    ieee80211_get_11ng_overlapping_chans(centerchans, acs);

    acs->acs_minrssisum_11ng = 0xffffffff;

    bestix  = -1;
    nfmin   = 0xFFFF;
    nfmix   = -1;
    rssimin = 0xFFFF;
    rssimix = -1;
    effmax  =  0;
    effmix  = -1;

    for (i = 0; i < acs->acs_nchans; i++) {
        channel = acs->acs_chans[i];
        chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
        acs_info(BASE, "Checking channel (%3d)", chan);

        /* The BLACKLIST flag need to be preserved for each channel till all
         * the channels are looped, since it is used rejecting the already
         * Ranked channels in the ACS ranking feature */
        if ((acs->acs_ranking) && (acs->acs_channelrejflag[chan] & ACS_REJFLAG_BLACKLIST)) {
            acs->acs_channelrejflag[chan] = 0;
            acs->acs_channelrejflag[chan] |= ACS_REJFLAG_BLACKLIST;
        }
        else {
            acs->acs_channelrejflag[chan]=0;
        }

        if(chan > 14)
        {
            acs->acs_channelrejflag[chan] |= ACS_REJFLAG_NON2G;
            continue;
        }
        if(acs->acs_2g_allchan == 0) {
            if ((chan != 1) && (chan != 6) && (chan != 11)) {
                /* Don't bother with other center channels except for 1, 6 & 11 */
                acs->acs_channelrejflag[chan] |= ACS_REJFLAG_NON2G;
            }
        }

        if(acs->acs_chan_regpower[chan]) {
            acs->acs_chan_regpower[chan] = MIN( acs->acs_chan_regpower[chan], channel->ic_maxregpower);
        }
        else {
            acs->acs_chan_regpower[chan] = channel->ic_maxregpower;
        }

        acs_info(REGPOWER, "Received Tx power (%4d) for chan (%3d) and reg_tx_power (%4d)",
                 acs->acs_chan_regpower[chan], chan, channel->ic_maxregpower);

        if (acs->acs_ch_hopping.ch_max_hop_cnt < ACS_CH_HOPPING_MAX_HOP_COUNT &&
                ieee80211com_has_cap_ext(acs->acs_ic,IEEE80211_ACS_CHANNEL_HOPPING)) {
            if(IEEE80211_CH_HOPPING_IS_CHAN_BLOCKED(channel)) {
                acs->acs_channelrejflag[chan] |= ACS_REJFLAG_NON2G;
                acs_info(BASE, "Rejecting channel (%3d) due to channel hopping", chan);
                continue;
            }
        }
        /* find the Total rssi for this 40Mhz band */
        if (chan > 0) {
              totalrssi = ieee80211_acs_find_channel_totalrssi(acs, centerchans[chan-1].chanlist, centerchans[chan-1].count, chan);
              ieee80211_acs_check_overlapping_channel_nf(acs, centerchans[chan-1].chanlist, centerchans[chan-1].count, chan);
        }

        /*OBSS check */
        switch (channel->ic_flags & IEEE80211_CHAN_BW_MASK)
        {
            case IEEE80211_CHAN_HT40PLUS:
            case IEEE80211_CHAN_HE40PLUS:
                extchan = chan + 4;
                acs_info(BASE, "HT40+/HE40+ with extchan (%3d)", extchan);
                break;
            case IEEE80211_CHAN_HT40MINUS:
            case IEEE80211_CHAN_HE40MINUS:
                extchan = chan - 4;
                acs_info(BASE, "HT40-/HE40- with extchan (%3d)", extchan);
                break;
            default: /* neither HT40+ nor HT40-, finish this call */
                extchan =0;
                break;
        }
         /* WAR to handle channel 6 for HT40 mode (2 entries of channel 6 are present) */
        if(((chan >= 5)&& (chan <= 7)) &&
            (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel) || IEEE80211_IS_CHAN_11AXG_HE40MINUS(channel))) {

            ht40minus_chan = 15 + (chan-5);
            acs->acs_chan_loadsum[ht40minus_chan] = acs->acs_chan_load[chan];
            acs->acs_chan_regpower[ht40minus_chan] = acs->acs_chan_regpower[chan];
            acs->acs_chan_snrtotal[ht40minus_chan] = acs->acs_chan_snrtotal[chan];
            acs->acs_channelrejflag[ht40minus_chan] = acs->acs_channelrejflag[chan];
            acs->acs_noisefloor[ht40minus_chan] = acs->acs_noisefloor[chan];
            acs->acs_srp_load[ht40minus_chan] = acs->acs_srp_load[chan];
            acs->acs_chan_nbss[ht40minus_chan] = acs->acs_chan_nbss[chan];
            acs->hw_chan_grade[ht40minus_chan] = acs->hw_chan_grade[chan];
            acs->acs_chan_nbss_weighted[ht40minus_chan] = acs->acs_chan_nbss_weighted[chan];
            chan = ht40minus_chan;
        }
        else {
            acs->acs_chan_loadsum[chan] = acs->acs_chan_load[chan];
        }
        if(acs->acs_2g_allchan == 0) {
           if ((chan != 1) && (chan != 6) && (chan != 11) && (chan != 16)) {
                /* Don't bother with other center channels except for 1, 6 & 11 */
                /* channel 16 means channel 6 HT40- */
                acs->acs_channelrejflag[chan] |= ACS_REJFLAG_NON2G;
                continue;
            }
        }
        if((extchan > 0) && (extchan < IEEE80211_ACS_CHAN_MAX)) {
            acs->acs_srp_load[chan] += acs->acs_srp_load[extchan]/2;

            obss_weighted = (acs->acs_chan_nbss_near[extchan] * acs->acs_obss_near_range_weightage) +
                            (acs->acs_chan_nbss_mid[extchan]  * acs->acs_obss_mid_range_weightage) +
                            (acs->acs_chan_nbss_far[extchan]  * acs->acs_obss_far_range_weightage);

            acs->acs_chan_nbss_weighted[chan] += obss_weighted/2;

            if ((acs->acs_noisefloor[extchan] !=NF_INVALID) && (acs->acs_noisefloor[extchan] < ACS_11NG_NOISE_FLOOR_REJ)) {
                acs->acs_chan_loadsum[chan] += acs->acs_chan_load[extchan]/2;
            } else {
                acs->acs_chan_loadsum[chan] += 50;
            }
        }

        if((extchan > 0) && (extchan < IEEE80211_ACS_CHAN_MAX)) {
            acs_info(BASE, "Extended channel information - "
                     "extchan (%3d), "
                     "acs_extchan_load (%4d), "
                     "acs_extchan_srp_load (%4d), "
                     "acs_extchan_nbss_weighted (%4d)",
                     extchan,
                     acs->acs_chan_load[extchan],
                     acs->acs_srp_load[extchan],
                     acs->acs_chan_nbss_weighted[extchan]);
        }

        acs_info(BASE, "Primary channel information - "
                 "chan (%3d), "
                 "acs_chan_load (%4d), "
                 "acs_chan_srp_load (%4d), "
                 "acs_chan_nbss_weighted (%4d), "
                 "beacon_rssi (%4d), "
                 "noisefloor (%4d)",
                 chan,
                 acs->acs_chan_load[chan],
                 acs->acs_srp_load[chan],
                 acs->acs_chan_nbss_weighted[chan],
                 totalrssi,
                 acs->acs_noisefloor[chan]);

        if( nfmin > acs->acs_noisefloor[chan]){
            nfmin = acs->acs_noisefloor[chan];
            nfmix = i;
        }

        /* Omit chan with highnoise or adjacent interference */
        if ((rssimin > totalrssi) && !(acs->acs_channelrejflag[chan] & ACS_REJFLAG_HIGHNOISE)
               && !(acs->acs_channelrejflag[chan] & ACS_REJFLAG_ADJINTERFERE)) {
            rssimin = totalrssi;
            rssimix = i;
        }

        /* Channel Efficiency:
         * (100 / (OBSS / 100)) * (Channel_Grade / 100)
         * To collect one decimal place extra, we are multiplying by 10
         */
        acs->chan_efficiency[chan] = (1000 * acs->hw_chan_grade[chan])/acs->acs_chan_nbss_weighted[chan];
        if (acs->acs_chan_grade_algo) {
            acs_info(BASE, "Calculated channel efficiency (%4d) for chan (%3d)",
                     acs->chan_efficiency[chan], chan);
        }

        if (!acs->acs_channelrejflag[chan]) {
            if (effmax < acs->chan_efficiency[chan]) {
                effmax = acs->chan_efficiency[chan];
                effmix = i;
            }
        }
    }

    if(rssimin == -1){
        acs_info(BASE, "Unlikely scenario where all channels are having high NF");
        bestix =nfmix;
        goto selectchan;

    }

    if (!acs->acs_chan_grade_algo) {
        acs_info(BASE, "Finding best channel through RSSI metric");
        bestix = rssimix;
        bestix = acs_find_best_channel_ix(acs, rssivarcor, rssimin);
    } else {
        acs_info(BASE, "Finding best channel through channel grade metric");
        bestix = effmix;
        bestix = acs_find_best_channel_ix_chan_efficiency(acs, effvarcor, effmax);
    }

selectchan:


    acs->acs_11ngbestchan = bestix;
    if ((bestix >= 0) && (bestix < IEEE80211_ACS_ENH_CHAN_MAX)) {
        channel = acs->acs_chans[bestix];

        acs->acs_status = ACS_SUCCESS;
#if ATH_SUPPORT_VOW_DCS
        ic->ic_eacs_done = 1;
#endif
        acs_info(BASE, "Best channel selected (%4uMHz) with RSSI (%4d) and NF (%4d)",
                ieee80211_chan2freq(acs->acs_ic, channel),rssimin,
                acs->acs_noisefloor[ieee80211_acs_get_chan_idx(acs, channel->ic_freq)]);
    } else {
         /* If no channel is derived, then pick the random channel(least BSS) for operation */
        channel = ieee80211_acs_select_min_nbss(acs->acs_ic);
        acs->acs_status = ACS_FAILED_NBSS;
        if (channel == NULL) {
#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
                if(ic->ic_primary_allowed_enable) {
                        channel = ieee80211_find_dot11_channel(acs->acs_ic,
                                acs->acs_ic->ic_primary_chanlist->freq[0],
                                0,
                                acs->acs_vap->iv_des_mode);
                } else
#endif
            channel = ieee80211_find_dot11_channel(acs->acs_ic, 0, 0, acs->acs_vap->iv_des_mode);
            acs->acs_status = ACS_FAILED_RNDM;
            acs_info(BASE, "Selected channel (%4uMHz)", ieee80211_chan2freq(acs->acs_ic, channel));
        }
        acs_err("ACS failed to derive the channel. Selecting random channel");

        /* In case of ACS ranking this is called multiple times and creates lot of logs on console */
        if (!acs->acs_ranking) {
            ieee80211_acs_scan_report_internal(acs->acs_ic);
        }
    }

    if (!channel) {
        acs_err("ACS failed to derive the channel !!");
        return NULL;
    }

    /*
     * The channel information is maintained in ACS as an array of objects of
     * the ieee80211_ath_channel type and not as an array of pointers to ic
     * channels list. Since right now, IC channels are maintained and all
     * the major pointers like ic_curchan, ic_prevchan etc., still point to the
     * ic channels global array, to continue comparison of the channel found
     * here and other global pointers directly (pointer comparison),
     * find the pointer with the same channel parameters in the ic channels
     * and return that pointer.
     * Please note that once ic channels is no longer in use, this conversion
     * will be removed.
     */
    channel = ieee80211_find_dot11_channel(acs->acs_ic, channel->ic_freq,
                                           channel->ic_vhtop_freq_seg2,
                                           ieee80211_chan2mode(channel));
    return channel ;
}

/*
 * ieee80211_acs_find_best_auto_centerchan:
 * Find the best channel for all channel bands.
 *
 * @acs: Pointer to the ACS channel structure.
 *
 * Return:
 * Pointer to the best channel.
 */
static inline struct ieee80211_ath_channel *
ieee80211_acs_find_best_auto_centerchan(ieee80211_acs_t acs)
{
    struct ieee80211_ath_channel *channel_11na, *channel_11ng;

    uint32_t idx_chan_11na = 0;
    uint32_t idx_chan_11ng = 0;
    uint32_t ch_load_11na = 0;
    uint32_t ch_load_11ng = 0;

    acs_info(BASE, "entry");
    channel_11na = ieee80211_acs_find_best_11na_centerchan(acs);
    channel_11ng = ieee80211_acs_find_best_11ng_centerchan(acs);

    if (channel_11ng) {
        idx_chan_11ng = ieee80211_acs_get_chan_idx(acs, channel_11ng->ic_freq);
    }
    if (channel_11na) {
        idx_chan_11na = ieee80211_acs_get_chan_idx(acs, channel_11na->ic_freq);
    }

    acs_info(BASE, "Best channel summary - "
             "5/6GHz chan_idx (%3d) with RSSI (%4d), "
             "2.4GHz chan_idx (%3d) with RSSI (%4d)",
             idx_chan_11na, acs->acs_minrssi_11na,
             idx_chan_11ng, acs->acs_minrssisum_11ng);

    ch_load_11na = acs->acs_chan_load[idx_chan_11na];
    ch_load_11ng = acs->acs_chan_load[idx_chan_11ng];

    /* Do channel load comparison only if radio supports both 11ng and 11na */
    if ((idx_chan_11ng != 0) && (idx_chan_11na != 0)) {
    /* Check which of them have the minimum channel load. If both have the same,
     * choose the 5GHz channel
     */
        if (ch_load_11ng <= ch_load_11na) {
            return channel_11ng;
        } else {
            if ((ch_load_11na - ch_load_11ng) <= acs->acs_chloadvar) {
                /* prefer 2G channel over 5G when channel loads are similar */
                return channel_11ng;
            } else {
                return channel_11na;
            }
        }
    } else if (idx_chan_11na != 0) {
            return channel_11na;
    } else if (idx_chan_11ng != 0) {
            return channel_11ng;
    } else {
            return IEEE80211_CHAN_ANYC;
    }
}

/*
 * ieee80211_acs_find_best_centerchan:
 * Find the best channel based on the desired phymode of the VAP.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 * Pointer to the best channel.
 */
static inline struct ieee80211_ath_channel *
ieee80211_acs_find_best_centerchan(ieee80211_acs_t acs)
{
    struct ieee80211_ath_channel *channel;

    acs_info(BASE, "Finding the best channel based on VAP desired mode");
    switch (acs->acs_vap->iv_des_mode)
    {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AXA_HE80_80:

            channel = ieee80211_acs_find_best_11na_centerchan(acs);
            break;

        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_G:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11AXG_HE20:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40:

            channel = ieee80211_acs_find_best_11ng_centerchan(acs);
            break;

        default:
            if (acs->acs_scan_2ghz_only) {
                channel = ieee80211_acs_find_best_11ng_centerchan(acs);
            }
            else if (acs->acs_scan_5ghz_only) {
                channel = ieee80211_acs_find_best_11na_centerchan(acs);
            }
            else {
                channel = ieee80211_acs_find_best_auto_centerchan(acs);
            }
            break;
    }
    return channel;
}

/*
 * ieee80211_mark_40intol:
 * Find all channels with active APs and mark the channel as intolerant due
 * to 2.4GHz 20MHz/40MHz coexistence.
 *
 * @arg: Opaque handle to the OBSS information for a given channel.
 * @se : Pointer to the scan entry of the given beacon in the channel.
 *
 * Return:
 *     0: Successful OBSS check.
 * Non-0: Failed OBSS check.
 */
static QDF_STATUS
ieee80211_mark_40intol(void *arg, wlan_scan_entry_t se)
{
    struct ieee80211_ath_channel *scan_chan = wlan_util_scan_entry_channel(se);

    struct acs_obsscheck *ochk = (struct acs_obsscheck *) arg ;

    int sechan;
    ieee80211_acs_t acs = NULL;
    struct ieee80211com *ic = NULL;
    struct ieee80211_ath_channel *channel = NULL;
    u_int8_t obss_snr = 0;
    uint8_t ssid [IEEE80211_MAX_SSID + 1] = {0, };
    uint8_t extchan_ix;

    if (!ochk) {
        acs_err("NULL ochk");
        return QDF_STATUS_E_INVAL;
    }

    if (!ochk->acs) {
        acs_err("NULL ochk->acs");
        return QDF_STATUS_E_INVAL;
    }

    if (!ochk->acs->acs_ic) {
        acs_err("NULL ochk->acs->acs_ic");
        return QDF_STATUS_E_INVAL;
    }

    acs = ochk->acs;
    ic = acs->acs_ic;
    channel = ochk->channel;

    sechan = ieee80211_acs_get_chan_idx(acs, scan_chan->ic_freq);
    qdf_mem_copy(ssid, util_scan_entry_ssid(se)->ssid, util_scan_entry_ssid(se)->length);
    ssid[util_scan_entry_ssid(se)->length] = '\0';

    acs_info(OBSS, "Scan entry information - "
             "SSID (%s), "
             "RSSI (%4d), "
             "SNR (%4d), "
             "Channel (%3d)",
             ssid,
             util_scan_entry_rssi(se),
             util_scan_entry_snr(se),
             sechan);

    /* If we see any beacon with some RSSI mark that channel as intolaraent */
    obss_snr = util_scan_entry_snr(se);

    if(obss_snr <= ic->obss_snr_threshold ) {
        acs_info(OBSS, "Skipping scan entry since it's less than threshold value - "
                 "RSSI (%4d), "
                 "Threshold (%4d)",
                 obss_snr,
                 ic->obss_snr_threshold);
        return EOK;
    }

    if (ochk->onlyextcheck){
        for (extchan_ix = ochk->extchan_low; extchan_ix <= ochk->extchan_high; extchan_ix++) {
            if (extchan_ix == sechan){
                acs_info(OBSS, "Marking overlap detection for chan (%3d) - "
                         "Scan entry found on ext chan (%3d)",
                         ieee80211_acs_get_chan_idx(acs, channel->ic_freq),
                         extchan_ix);

                channel->ic_flags |= IEEE80211_CHAN_40INTOL;
                break;
            }
        }
    }else{
        /* In case of primary channel we should not consider for OBSS */
        if (sechan == ieee80211_acs_get_chan_idx(acs, channel->ic_freq)) {
            acs_info(OBSS, "Skipping scan entry since scan entry on pri_chan (%4uMHz) ",
                     ieee80211_chan2freq(acs->acs_ic, channel));
            return EOK;
        }

        if ((sechan >= ochk->olminlimit) && (sechan <= ochk->olmaxlimit)){
            acs_info(OBSS, "Marking overlap detection for chan (%4uMHz) - "
                     "Scan entry chan (%3d) within overlap range (%3d to %3d)",
                     ieee80211_chan2freq(acs->acs_ic, channel),
                     sechan, ochk->olminlimit, ochk->olmaxlimit);

            channel->ic_flags |= IEEE80211_CHAN_40INTOL;
        }
    }
    return EOK;
}

/*
 * ieee80211_find_40intol_overlap:
 * Check 20/40MHz coexistence intolerance for the 2.4GHz band.
 *
 * @acs    : Pointer to the ACS structure.
 * @channel: Pointer to the given channel.
 */
static void ieee80211_find_40intol_overlap(ieee80211_acs_t acs,
                                          struct ieee80211_ath_channel *channel)
{
#define HT40_NUM_CHANS 5
    uint16_t ieee_chan = 0;
    int mean_chan, extchan_low, extchan_high, extchan_ix, min_oper_chan,
        max_oper_chan, temp_ix, temp_freq;
    uint8_t min24_chan, max24_chan;
    struct ieee80211_ath_channel *temp_channel = NULL;

    struct acs_obsscheck obsschk;
    struct wlan_objmgr_pdev *pdev = acs->acs_ic->ic_pdev_obj;

    acs_info(BASE, "entry");
    min24_chan = wlan_reg_freq_to_chan(pdev, WLAN_REG_MIN_24GHZ_CHAN_FREQ);
    max24_chan = wlan_reg_freq_to_chan(pdev, WLAN_REG_MAX_24GHZ_CHAN_FREQ);

    if (!channel || (channel == IEEE80211_CHAN_ANYC) || (ieee_chan == (uint16_t)IEEE80211_CHAN_ANY))
        return;

    ieee_chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
    switch (channel->ic_flags & IEEE80211_CHAN_BW_MASK)
    {
        case IEEE80211_CHAN_HT40PLUS:
        case IEEE80211_CHAN_HE40PLUS:
            mean_chan    = ieee_chan + 2;
            extchan_low  = ieee_chan + 3;
            extchan_high = MIN(max24_chan,(extchan_low + 4));
            acs_info(BASE, "HT40+/HE40+ - "
                     "ext_low (%3d), "
                     "ext_high (%3d)",
                     extchan_low, extchan_high);
            break;
        case IEEE80211_CHAN_HT40MINUS:
        case IEEE80211_CHAN_HE40MINUS:
            mean_chan    = ieee_chan - 2;
            extchan_high = ieee_chan - 3;
            extchan_low  = MAX(min24_chan, extchan_high - 4);
            acs_info(BASE, "HT40-/HE40- - "
                     "ext_low (%3d), "
                     "ext_high (%3d)",
                     extchan_low,
                     extchan_high);
            break;
        default: /* neither HT40+ nor HT40-, finish this call */
            acs_info(BASE, "Invalid phymode mask in channel flags");
            return;
    }


    /* We should mark the intended channel as 40 MHz intolerant
       if the intended frequency overlaps the iterated channel partially */

    /* According to 802.11n 2009, affected channel = [mean_chan-5, mean_chan+5] */
    obsschk.acs = acs;
    obsschk.channel = channel;
    obsschk.onlyextcheck = acs->acs_limitedbsschk;
    obsschk.extchan_low = extchan_low;
    obsschk.extchan_high = extchan_high;

    /* Find the minimum and maximum channels as per current operational
     * regulatory domain.
     */
    min_oper_chan = max_oper_chan = -1;

    for (temp_ix = min24_chan;
            temp_ix <= max24_chan; temp_ix++)
    {
        temp_freq = wlan_reg_chan_band_to_freq(acs->acs_ic->ic_pdev_obj,
                temp_ix, BIT(REG_BAND_2G));

        if (!temp_freq) {
            continue;
        }

        temp_channel = NULL;
        temp_channel = wlan_find_full_channel(acs->acs_ic, temp_freq);
        if (temp_channel) {
            /* temp_ix is valid for the current operational regulatory domain */
            if (-1 == min_oper_chan) {
                min_oper_chan = temp_ix;
            }

            if (temp_ix > max_oper_chan) {
                max_oper_chan = temp_ix;
            }
        }
    }

    acs_info(BASE, "Channel range per current regulatory operation - "
             "min channel number (%3d), "
             "max channel number (%3d)",
             min_oper_chan, max_oper_chan);

    qdf_assert_always(min_oper_chan >= min24_chan &&
            min_oper_chan <= max24_chan);
    qdf_assert_always(max_oper_chan >= min24_chan &&
            min_oper_chan <= max24_chan);
    qdf_assert_always(max_oper_chan >= min_oper_chan);

    obsschk.olminlimit = MAX(mean_chan - HT40_NUM_CHANS, min_oper_chan);
    obsschk.olmaxlimit  = MIN(max_oper_chan, mean_chan + HT40_NUM_CHANS);

    ucfg_scan_db_iterate(wlan_vap_get_pdev(acs->acs_vap),
            ieee80211_mark_40intol, (void *)&obsschk);

    for (extchan_ix = extchan_low; (extchan_ix > 0) && (extchan_ix <= extchan_high); extchan_ix++) {
        if ((acs->acs_noisefloor[extchan_ix] != NF_INVALID) && (acs->acs_noisefloor[extchan_ix] > ACS_11NG_NOISE_FLOOR_REJ)) {
            acs_info(OBSS, "Rejecting ext chan (%3d) - "
                     "extchan NF (%4d) is greater than threshold (%4d)",
                     extchan_ix,
                     acs->acs_noisefloor[extchan_ix], ACS_11NG_NOISE_FLOOR_REJ);

            channel->ic_flags |= IEEE80211_CHAN_40INTOL;
        }
    }

    acs_info(OBSS, "Selected channel (%3d) with overlap (%#018llx)",
             ieee_chan, (channel->ic_flags & IEEE80211_CHAN_40INTOL));
    acs->acs_ic->ic_obss_done_freq = channel->ic_freq;

#undef CEILING
#undef FLOOR
#undef HT40_NUM_CHANS
}

/*
 * ieee80211_get_chan_neighbor_list:
 * Get a list of neighbor channels from the incoming beacon.
 *
 * @arg: Opaque pointer to the neighbour list.
 * @se : Pointer to the scan entry of a given beacon.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
static QDF_STATUS
ieee80211_get_chan_neighbor_list(void *arg, wlan_scan_entry_t se)
{
    ieee80211_chan_neighbor_list *chan_neighbor_list = (ieee80211_chan_neighbor_list *) arg ;
    struct ieee80211_ath_channel *channel_se = NULL;
    uint16_t chan_freq;
    int nbss;
    u_int8_t ssid_len;
    u_int8_t *ssid = NULL;
    u_int8_t *bssid = NULL;
    u_int8_t snr = 0;
    u_int32_t phymode = 0;
    ieee80211_acs_t acs = NULL;
    struct ieee80211com *ic = NULL;
    struct ieee80211_ie_qbssload *qbssload_ie = NULL;

    /* sanity check */
    if ((chan_neighbor_list == NULL) || (chan_neighbor_list->acs == NULL) ||
        (chan_neighbor_list->acs->acs_ic == NULL) ||
        (chan_neighbor_list->nbss >= IEEE80211_MAX_NEIGHBOURS)) {
        acs_err("Null chan_neighbor_list (%p) or acs (%p) or ic (%p) or "
                 "NBSS (%d) is greater than max neighbors (%d)",
                 chan_neighbor_list,
                 chan_neighbor_list ? chan_neighbor_list->acs : 0,
                 chan_neighbor_list ? (chan_neighbor_list->acs ?
                                       chan_neighbor_list->acs->acs_ic : 0) : 0,
                 chan_neighbor_list ? chan_neighbor_list->nbss : 0,
                 IEEE80211_MAX_NEIGHBOURS);
        return EINVAL;
    }

    ssid = (char *)util_scan_entry_ssid(se)->ssid;
    ssid_len = util_scan_entry_ssid(se)->length;
    bssid = (char *)util_scan_entry_bssid(se);
    snr = util_scan_entry_snr(se);
    phymode = util_scan_entry_phymode(se);
    qbssload_ie = (struct ieee80211_ie_qbssload *)util_scan_entry_qbssload(se);

    /*if both ssid and bssid is null it is invalid entry*/
    if ((ssid == NULL) && (bssid == NULL)) {
        acs_err("Null SSID (%p) or BSSID (%p)",
                 ssid, bssid);
        return EINVAL;
    }

    acs = chan_neighbor_list->acs;
    ic = acs->acs_ic;
    nbss = chan_neighbor_list->nbss;
    channel_se = wlan_util_scan_entry_channel(se);
    chan_freq = ieee80211_chan2freq(acs->acs_ic, channel_se);

    /* Only copy the SSID if it in current channel scan entry */
    if ((chan_freq == chan_neighbor_list->freq)) {

        if (qbssload_ie != NULL) {
            chan_neighbor_list->neighbor_list[nbss].qbssload_ie_valid = true;
            chan_neighbor_list->neighbor_list[nbss].station_count = qbssload_ie->station_count;
            chan_neighbor_list->neighbor_list[nbss].channel_utilization =
            qbssload_ie->channel_utilization;
        }

        /* Hidden AP the SSID might be null */
        if (ssid != NULL) {
            memcpy(chan_neighbor_list->neighbor_list[nbss].ssid, ssid, ssid_len);
            if (ssid_len < IEEE80211_NWID_LEN) {
                chan_neighbor_list->neighbor_list[nbss].ssid[ssid_len] = '\0';
            }
            else {
                chan_neighbor_list->neighbor_list[nbss].ssid[IEEE80211_NWID_LEN] = '\0';
            }
        }
        memcpy(chan_neighbor_list->neighbor_list[nbss].bssid, bssid, QDF_MAC_ADDR_SIZE);
        chan_neighbor_list->neighbor_list[nbss].rssi = snr;
        chan_neighbor_list->neighbor_list[nbss].phymode = phymode;
        chan_neighbor_list->nbss++;
    }

    return EOK;

}

/*
 * ieee80211_acs_derive_sec_chans:
 * Derive secondary channels for a given phymode, primary channel.
 *
 * @acs            : Pointer to the ACS structure.
 * @pri_chan_freq  : Value of the given primary channel (in MHz).
 * @center_chan_80 : Value of the center channel of the primary 80MHz.
 * @center_chan_160: Value of the center channel of the secondary 80MHz.
 * @sec_chans      : Pointer to store secondary channels.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
static int ieee80211_acs_derive_sec_chans_with_mode(ieee80211_acs_t acs,
                                                enum ieee80211_phymode mode,
                                                uint16_t pri_chan_freq,
                                                uint16_t center_chan_80,
                                                uint16_t center_chan_160,
                                                struct acs_sec_chans *sec_chans)
{
    uint16_t pri_chan;
    int32_t  pri_center_chan_diff;
    int8_t  sec_level;

    if (!sec_chans) {
        acs_err("Invalid secondary channel structure - "
                 "pri_chan_freq (%4uMHz), "
                 "mode (%d)",
                 pri_chan_freq, mode);
        return -EINVAL;
    }

    pri_chan = ieee80211_acs_get_chan_idx(acs, pri_chan_freq);
    if (!pri_chan) {
        acs_err("Could not derive secondary channel - "
                 "pri_chan_freq (%4uMHz), "
                 "mode (%d)",
                 pri_chan_freq, mode);
        return -EINVAL;
    }

    switch(mode) {
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
            sec_chans->sec_chan_20 = pri_chan - 4;
        break;

        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40PLUS:
            sec_chans->sec_chan_20 = pri_chan + 4;
        break;

        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AC_VHT80_80:
        case IEEE80211_MODE_11AXA_HE80_80:
            /* Get the center frequency of the full 80MHz band */
            if (!center_chan_80) {
                acs_err("Invalid center chan for 80MHz for mode (%d) - "
                         "pri_chan_freq (%3d)",
                         mode, pri_chan_freq);
                return -EINVAL;
            }

            /*
             * For VHT mode, The center frequency is given in VHT OP IE
             * For example: 42 is center freq and 36 is primary channel
             * then secondary 20 channel would be 40
             */
            pri_center_chan_diff = pri_chan - center_chan_80;

            /* Secondary 20 channel would be less(2 or 6) or more (2 or 6)
             * than center frequency based on primary channel
             */
            if(pri_center_chan_diff > 0) {
                sec_level = LOWER_FREQ_SLOT;
                sec_chans->sec_chan_40_1 = center_chan_80 + SEC_40_LOWER;
            } else {
                sec_level = UPPER_FREQ_SLOT;
                sec_chans->sec_chan_40_1 = center_chan_80 - SEC_40_UPPER;
            }

            sec_chans->sec_chan_40_2 = sec_chans->sec_chan_40_1 + 4;

            if((sec_level * pri_center_chan_diff) < -2)
                sec_chans->sec_chan_20 = center_chan_80 - (sec_level* SEC20_OFF_2);
            else
                sec_chans->sec_chan_20 = center_chan_80 - (sec_level* SEC20_OFF_6);

            /* NOTE: Even for 80+80MHz, secondary 80MHz is not derived */
        break;

        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AXA_HE160:
            /* Get the center frequency of the full 160MHz band */
            if (!center_chan_80) {
                acs_err("Invalid center chan 80MHz for mode (%d) - "
                         "pri_chan_freq (%3d)",
                         mode, pri_chan_freq);
                return -EINVAL;
            }

            /*
             * For VHT mode, The center frequency is given in VHT OP IE
             * For example: 42 is center freq and 36 is primary channel
             * then secondary 20 channel would be 40
             */
            pri_center_chan_diff = pri_chan - center_chan_80;

            /* Secondary 20 channel would be less(2 or 6) or more (2 or 6)
             * than center frequency based on primary channel
             */
            if(pri_center_chan_diff > 0) {
                sec_level = LOWER_FREQ_SLOT;
                sec_chans->sec_chan_40_1 = center_chan_80  + SEC_40_LOWER;
            } else {
                sec_level = UPPER_FREQ_SLOT;
                sec_chans->sec_chan_40_1 = center_chan_80  - SEC_40_UPPER;
            }

            sec_chans->sec_chan_40_2 = sec_chans->sec_chan_40_1 + 4;

            if((sec_level * pri_center_chan_diff) < -2)
                sec_chans->sec_chan_20 = center_chan_80 - (sec_level* SEC20_OFF_2);
            else
                sec_chans->sec_chan_20 = center_chan_80 - (sec_level* SEC20_OFF_6);

            if (!center_chan_160) {
                acs_info(CHLST, "Invalid center chan for 160MHz for mode (%d) - "
                         "pri_chan_freq (%3d)",
                         mode, pri_chan_freq);
                return -EINVAL;
            }

            pri_center_chan_diff = pri_chan - center_chan_160;

            if(pri_center_chan_diff > 0) {
                sec_chans->sec_chan_80_1 = center_chan_160 - SEC_80_4;
                sec_chans->sec_chan_80_2 = center_chan_160 - SEC_80_3;
                sec_chans->sec_chan_80_3 = center_chan_160 - SEC_80_2;
                sec_chans->sec_chan_80_4 = center_chan_160 - SEC_80_1;
            } else {
                sec_chans->sec_chan_80_1 = center_chan_160 + SEC_80_1;
                sec_chans->sec_chan_80_2 = center_chan_160 + SEC_80_2;
                sec_chans->sec_chan_80_3 = center_chan_160 + SEC_80_3;
                sec_chans->sec_chan_80_4 = center_chan_160 + SEC_80_4;
            }
        break;

        default:
            /*
             * No secondary channels for 20MHz modes.
             * Cannot derive secondary channels for 40MHz if offset is not
             * given, even for 5GHz modes.
             */
        break;
    }

    return EOK;
}

/*
 * ieee80211_acs_derive_sec_chan:
 * Derive secondary channels based on the phymode of the scan entry.
 *
 * @se           : Scan entry of a given beacon.
 * @acs_ch_idx   : Value of the channel index to a given channel.
 * @sec_chan_20  : Pointer to the secondary 20MHz channel.
 * @sec_chan_40_1: Pointer to the first 20MHz segment of the secondary 40MHz
 *                 channel.
 * @sec_chan_40_2: Pointer to the second 20MHz segment of the secondary 40MHz
 *                 channel.
 * @ic           : Pointer to the IC structure.
 *
 * Return:
 *  0: Success
 * -1: Failure
 */
static int ieee80211_acs_derive_sec_chan(wlan_scan_entry_t se,
        uint16_t acs_ch_idx, uint16_t *sec_chan_20,
        uint16_t *sec_chan_40_1, uint16_t *sec_chan_40_2, struct ieee80211com *ic)
{
    /*
     * center_freq refers to the center frequency of the primary 80MHz
     * in the case of VHT80, VHT80+80 and VHT160MHz
     */
    uint16_t center_freq = 0;
    u_int8_t phymode_se;
    struct ieee80211_ie_vhtop *vhtop = NULL;
    struct ieee80211_ie_vhtcap *vhtcap = NULL;
    struct ieee80211_ie_heop *heop = NULL;
    struct heop_6g_param *heop_6g = NULL;
    struct acs_sec_chans sec_chans = {0};

    phymode_se = util_scan_entry_phymode(se);
    vhtop = (struct ieee80211_ie_vhtop *)util_scan_entry_vhtop(se);

    heop = (struct ieee80211_ie_heop *) util_scan_entry_heop(se);
    if (heop && wlan_reg_is_6ghz_chan_freq(se->channel.chan_freq)) {
        heop_6g = ieee80211_get_he_6g_opinfo(heop);
    }

    switch (phymode_se)
    {
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AXA_HE80:
            if (heop_6g) {
                center_freq = heop_6g->chan_cent_freq_seg0;
            } else {
                center_freq = vhtop->vht_op_ch_freq_seg1;
            }
            break;
        case IEEE80211_MODE_11AC_VHT80_80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AXA_HE80_80:
        case IEEE80211_MODE_11AXA_HE160:
            vhtcap = (struct ieee80211_ie_vhtcap *)util_scan_entry_vhtcap(se);
            if (heop_6g) {
                center_freq = heop_6g->chan_cent_freq_seg0;
            } else if(!vhtop->vht_op_ch_freq_seg2) {
                if (peer_ext_nss_capable(vhtcap) && ic->ic_ext_nss_capable) {
                    /* seg1 contains primary 80 center frequency in the case of
                     * ext_nss enabled revised signalling. This applies to both 160 MHz
                     * and 80+80 MHz
                     */
                    center_freq = vhtop->vht_op_ch_freq_seg1;
                } else {
                    /* seg1 contains the 160 center frequency in the case of
                     * legacy signalling before revised signalling was introduced.
                     * This applies only to 160 MHz and not to 80+80 MHz.
                     */
                    if ((vhtop->vht_op_ch_freq_seg1 - ieee80211_acs_get_ieee_chan_from_ch_idx(acs_ch_idx)) < 0)
                        center_freq = vhtop->vht_op_ch_freq_seg1 + 8;
                    else
                        center_freq = vhtop->vht_op_ch_freq_seg1 - 8;
                }
	    } else {
                /* For 160 MHz: seg1 contains primary 80 center frequency in
                 * the case of revised signalling with ext_nss disabled, or in the case
                 * of revised signaling with ext_nss enabled in which CCFS1 is used.
                 * For 80+80 MHz: seg1 contains primary 80 center frequency in
                 * the case of legacy signaling before revised signalling was
                 * introduced, or revised signalling with ext_nss disabled, or revised
                 * signaling with ext_nss enabled in which CCFS1 is used.
                 */
                center_freq = vhtop->vht_op_ch_freq_seg1;
            }

            break;
    }

    center_freq = ieee80211_acs_get_center_freq_idx(center_freq, se->channel.chan_freq);
    /*
     * Sending 0 as center_chan_160 because sec_chan_80 info is not required.
     * Set secondary 40MHz only for 80+80MHz.
     */
    ieee80211_acs_derive_sec_chans_with_mode(ic->ic_acs,
                phymode_se,
                ieee80211_acs_get_ieee_freq_from_ch_idx(ic->ic_acs, acs_ch_idx),
                center_freq,
                0,
                &sec_chans);

    *sec_chan_20   = sec_chans.sec_chan_20;
    *sec_chan_40_1 = sec_chans.sec_chan_40_1;
    *sec_chan_40_2 = sec_chans.sec_chan_40_2;

    return EOK;
}

/*
 * ieee80211_acs_get_channel_maxrssi_n_secondary_ch:
 * Record the max/min RSSI and channel efficiency related parameters for a
 * given scan entry of a beacon/probe.
 *
 * @arg: Opaque pointer to the ACS structure.
 * @se : Pointer to the given scan entry.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
static QDF_STATUS
ieee80211_acs_get_channel_maxrssi_n_secondary_ch(void *arg, wlan_scan_entry_t se)
{
    ieee80211_acs_t acs = (ieee80211_acs_t) arg;
    struct ieee80211_ath_channel *channel_se = wlan_util_scan_entry_channel(se);
    enum ieee80211_phymode phymode_se = util_scan_entry_phymode(se);
    u_int8_t snr_se = util_scan_entry_snr(se);
    uint16_t acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel_se->ic_freq);
    uint16_t sec_chan_20 = 0;
    uint16_t sec_chan_40_1 = 0;
    uint16_t sec_chan_40_2 = 0;
    u_int8_t len;
    uint8_t ssid [IEEE80211_MAX_SSID + 1] = {0, };
    struct ieee80211_ie_srp_extie *srp_ie;
    struct ieee80211_ie_hecap *hecap_ie;
    uint32_t srps = 0;
    uint32_t srp_nobsspd = 1;
    uint8_t *hecap_phy_ie;

    len = util_scan_entry_ssid(se)->length;
    qdf_mem_copy(ssid, util_scan_entry_ssid(se)->ssid, len);
    ssid[len] = '\0';

    if (snr_se > acs->acs_chan_maxsnr[acs_ch_idx]) {
        acs->acs_chan_maxsnr[acs_ch_idx] = snr_se;
    }
    acs->acs_chan_snr[acs_ch_idx] += snr_se;
    /* This support is for stats */
    if ((acs->acs_chan_minsnr[acs_ch_idx] == 0) ||
            (snr_se < acs->acs_chan_minsnr[acs_ch_idx])) {
        acs->acs_chan_minsnr[acs_ch_idx] = snr_se;
    }

    acs->acs_chan_nbss[acs_ch_idx] += 1;
    if (snr_se > ACS_SNR_NEAR_RANGE_MIN) {
       acs->acs_chan_nbss_near[acs_ch_idx] += 1;
    } else if (snr_se > ACS_SNR_MID_RANGE_MIN) {
       acs->acs_chan_nbss_mid[acs_ch_idx] += 1;
    } else {
       acs->acs_chan_nbss_far[acs_ch_idx] += 1;
    }

    if (!ieee80211_acs_derive_sec_chan(se, acs_ch_idx, &sec_chan_20, &sec_chan_40_1, &sec_chan_40_2, acs->acs_ic)) {
        acs->acs_sec_chan[sec_chan_20] = true;
        /* Secondary 40 would be enabled for 80+80 Mhz channel or
         * 160 Mhz channel
         */
        if (((phymode_se == IEEE80211_MODE_11AC_VHT160) ||
             (phymode_se == IEEE80211_MODE_11AXA_HE160) ||
             (phymode_se == IEEE80211_MODE_11AC_VHT80_80) ||
             (phymode_se == IEEE80211_MODE_11AXA_HE80_80)) &&
            (sec_chan_40_1 != 0) && (sec_chan_40_2 != 0)) {
            acs->acs_sec_chan[sec_chan_40_1] = true;
            acs->acs_sec_chan[sec_chan_40_2] = true;
        }
    }

    hecap_ie = (struct ieee80211_ie_hecap *)util_scan_entry_hecap(se);
    srp_ie = (struct ieee80211_ie_srp_extie *)util_scan_entry_spatial_reuse_parameter(se);

    if (hecap_ie) {
        hecap_phy_ie = &hecap_ie->hecap_phyinfo[0];
        srps = HECAP_PHY_SRPSPRESENT_GET_FROM_IE(&hecap_phy_ie);
    }

#ifdef OBSS_PD
    if (srp_ie) {
        srp_nobsspd = srp_ie->sr_control & IEEE80211_SRP_SRCTRL_OBSS_PD_DISALLOWED_MASK;
    }
#endif

    if (srps) {
        acs->acs_srp_info[acs_ch_idx].srp_allowed += 1;
    }

    if (!srp_nobsspd) {
            acs->acs_srp_info[acs_ch_idx].srp_obsspd_allowed += 1;
    }

    if (!srp_nobsspd || srps) {
           acs->acs_srp_supported[acs_ch_idx]++;
    }

    acs_info(OBSS, "OBSS information - "
             "Channel (%3d),"
             "Phymode (%2d), "
             "Sec_Chan_20 (%3d), "
             "Sec_Chan_40_1 (%3d), "
             "Sec_Chan_40_2 (%3d), "
             "NBSS (%4d), "
             "RSSI (%4d), "
             "SNR (%4d), "
             "Total RSSI (%4d), "
             "Noise (%4d), "
             "SRP (%1d), "
             "SRP_NoBSSPD (%1d), "
             "Total_SRP_BSS (%4d), "
             "SSID (%s)",
             acs_ch_idx,
             util_scan_entry_phymode(se),
             sec_chan_20,
             sec_chan_40_1,
             sec_chan_40_2,
             acs->acs_chan_nbss[acs_ch_idx], util_scan_entry_rssi(se),
             snr_se, acs->acs_chan_snr[acs_ch_idx],
             acs->acs_noisefloor[acs_ch_idx],
             srps,
             srp_nobsspd,
             acs->acs_srp_supported[acs_ch_idx],
             ssid);

    return EOK;
}

/*
 * ieee80211_acs_check_band_to_scan:
 * Mark the bands to scan based on a given number of 2GHz channels.
 *
 * @acs        : Pointer to the ACS structure.
 * @nchans_2ghz: No. of 2Ghz channels.
 */
static INLINE void ieee80211_acs_check_band_to_scan(ieee80211_acs_t acs, u_int16_t nchans_2ghz)
{
    if ((nchans_2ghz) && (acs->acs_nchans == nchans_2ghz)) {
        acs_info(BASE, "No 5GHz channel available, skip 5GHz scan");
        acs->acs_scan_5ghz_only = 0;
        acs->acs_scan_2ghz_only = 1;
    }
    else if (!(nchans_2ghz) && (acs->acs_nchans)) {
        acs_info(BASE, "No 2.4GHz channel available, skip 2GHz scan");
        acs->acs_scan_2ghz_only = 0;
        acs->acs_scan_5ghz_only = 1;
    }
}


/*
 * acs_is_channel_blocked:
 * Check if the given channel is present in the ACS block channel list.
 *
 * @acs : Pointer to the ACS structure.
 * @freq: Value of the frequency of the given channel.
 *
 * Return:
 * 1   : Channel is blocked.
 * 0   : Channel is not blocked.
 * Else: Could not check if channel is blocked.
 */
static inline int acs_is_channel_blocked(ieee80211_acs_t acs, uint16_t freq)
{
    acs_bchan_list_t * bchan = NULL ;
    u_int16_t i = 0;

    if(acs == NULL)
        return EPERM;

    bchan = &(acs->acs_bchan_list);
    for (i = 0;i < bchan->uchan_cnt;i++) {
        if (bchan->uchan[i] == freq) {
            /* Non zero values means ignore this channel */
            return true;
        }
    }
    return false;
}

/*
 * ieee80211_acs_get_phymode_channels:
 * Populate the ACS channel list based on a given phymode.
 *
 * @acs : Pointer to the ACS structure.
 * @mode: Value of the given phymode.
 */
static void ieee80211_acs_get_phymode_channels(ieee80211_acs_t acs, enum ieee80211_phymode mode)
{
    int i, extchan, skipchanextinvalid;
    struct ieee80211_ath_channel_list chan_info;
    struct regulatory_channel *cur_chan_list;

    cur_chan_list = qdf_mem_malloc(NUM_CHANNELS * sizeof(*cur_chan_list));
    if (!cur_chan_list)
        return;

    if (wlan_reg_get_current_chan_list(acs->acs_ic->ic_pdev_obj, cur_chan_list)
        != QDF_STATUS_SUCCESS) {
        qdf_err("Failed to get cur_chan list");
        qdf_mem_free(cur_chan_list);
        return;
    }

    for (i = 0; i < NUM_CHANNELS; i++) {
        struct ieee80211_ath_channel *channel;
        uint16_t acs_ch_idx;
        uint16_t chan_freq;
#if ATH_CHANNEL_BLOCKING
        uint16_t ext_chan_freq;
#endif

        if (cur_chan_list[i].state == CHANNEL_STATE_DISABLE)
            continue;

        channel = ieee80211_find_dot11_channel(acs->acs_ic,
                                               cur_chan_list[i].center_freq,
                                               0,
                                               mode);

        if (!channel)
            continue;

        acs_info(BASE, "Getting channels with phymode (%2d)", mode);
        acs_info(CHLST, "ic_freq (%4uMHz), ic_ieee (%3d), ic_flags (%#018llx)",
                 channel->ic_freq, channel->ic_ieee, channel->ic_flags);

        acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
        chan_freq = ieee80211_chan2freq(acs->acs_ic, channel);

        /*
         * When EMIWAR is EMIWAR_80P80_FC1GTFC2 for some channel 80_80MHZ channel combination is not allowed
         * this code will allowed the 80MHz combination to add in to acs_channel list
         * so that these can be used as secondary channel
         */
        if((acs->acs_ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) &&
           (ieee80211_is_phymode_80(mode) && ieee80211_is_phymode_8080(acs->acs_vap->iv_des_mode)) &&
           (acs->acs_chan_maps[acs_ch_idx] != 0xff)) {
            acs_info(CHLST, "Duplicate channel freq (%4uMHz)", channel->ic_freq);
            continue;
        }
        /* VHT80_80, channel list has duplicate entries, since ACS picks both primary and secondary 80 mhz channels
           single entry in ACS would be sufficient */
        if(acs->acs_nchans &&
           (ieee80211_chan2freq(acs->acs_ic, acs->acs_chans[acs->acs_nchans-1]) == chan_freq))
        {
            acs_info(CHLST, "Duplicate channel freq (%4uMHz)", channel->ic_freq);
            continue;
        }
#if ATH_SUPPORT_IBSS_ACS
        /*
         * ACS : filter out DFS channels for IBSS mode
         */
        if((wlan_vap_get_opmode(acs->acs_vap) == IEEE80211_M_IBSS) && IEEE80211_IS_CHAN_DISALLOW_ADHOC(channel)) {
            acs_info(CHLST, "Skip DFS-check channel (%4uMHz)", channel->ic_freq);
            continue;
        }
#endif
        if ((wlan_vap_get_opmode(acs->acs_vap) == IEEE80211_M_HOSTAP) && IEEE80211_IS_CHAN_DISALLOW_HOSTAP(channel)) {
            acs_info(CHLST, "Skip STA-only channel (%4uMHz)", channel->ic_freq);
            continue;
        }

#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
        if(acs->acs_ic->ic_primary_allowed_enable &&
           !(ieee80211_check_allowed_prim_freqlist(
                                                   acs->acs_ic, channel->ic_freq))) {
            acs_info(CHLST, "Channel (%4uMHz) is not a primary allowed channel",
                     chan_freq);
            continue;
        }
#endif
        /*channel is blocked as per user setting */
        if(acs_is_channel_blocked(acs, chan_freq)) {
            acs_info(CHLST, "Channel (%4uMHz) is blocked in phymode (%2d)",
                     chan_freq, mode);
            continue;
        }

        /* channel is present in nol list */
        if (IEEE80211_IS_CHAN_RADAR(acs->acs_ic, channel)){
            acs_info(CHLST, "Channel (%4uMHz) is in NOL in phymode (%2d)",
                     chan_freq, mode);
            continue;
        }

        ieee80211_get_extchaninfo(acs->acs_ic, channel, &chan_info);

        skipchanextinvalid = 0;

        for (extchan = 0; extchan < chan_info.cl_nchans ; extchan++) {
            if (chan_info.cl_channels[extchan] == NULL) {
                if(ieee80211_is_extchan_144(acs->acs_ic, channel, extchan)) {
                    continue;
                }
                acs_info(CHLST, "Rejecting channel (%4uMHz) due to NULL extchan (%3d) - ",
                         chan_freq, extchan);
                skipchanextinvalid = 1;
                break;
            } else if (IEEE80211_IS_CHAN_RADAR(acs->acs_ic, chan_info.cl_channels[extchan])) {
                acs_info(CHLST, "Rejecting channel (%4uMHz) due to extchan (%3d) in NOL - ",
                         chan_freq, extchan);
                skipchanextinvalid = 1;
                break;
            }
        }

#if ATH_CHANNEL_BLOCKING
        if (acs->acs_block_mode & ACS_BLOCK_EXTENSION) {
            /* extension channel (in NAHT40/ACVHT40/ACVHT80 mode) is blocked as per user setting */
            for (extchan = 0; (skipchanextinvalid == 0) && (extchan < chan_info.cl_nchans); extchan++) {
                ext_chan_freq = ieee80211_chan2freq(acs->acs_ic, chan_info.cl_channels[extchan]);
                if (acs_is_channel_blocked(acs, ext_chan_freq)) {
                    acs_info(CHLST, "Rejecting channel (%4uMHz) since "
                             "extchan is blocked (%4uMHz) for phymode (%2d)",
                             chan_freq, ext_chan_freq, mode);
                    skipchanextinvalid = 1; /* break */
                }
            }

            /* in 2.4GHz band checking channels overlapping with primary,
             * or if required with secondary too (NGHT40 mode) */
            if (!skipchanextinvalid && IEEE80211_IS_CHAN_2GHZ(channel)) {
                struct ieee80211_ath_channel *ext_chan;
                int start = channel->ic_freq - 15, end = channel->ic_freq + 15, f;
                if (IEEE80211_IS_CHAN_11NG_HT40PLUS(channel) ||
                    IEEE80211_IS_CHAN_11AXG_HE40PLUS(channel))
                    end = channel->ic_freq + 35;
                if (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel) ||
                    IEEE80211_IS_CHAN_11AXG_HE40MINUS(channel))
                    start = channel->ic_freq - 35;
                for (f = start; f <= end; f += 5) {
                    ext_chan = acs->acs_ic->ic_find_channel(acs->acs_ic, f, 0, IEEE80211_CHAN_B);
                    if (ext_chan) {
                        ext_chan_freq = ieee80211_chan2freq(acs->acs_ic, ext_chan);
                        if (acs_is_channel_blocked(acs, ext_chan_freq)) {
                            acs_info(CHLST, "Rejecting channel (%4uMHz) "
                                     "since ext/overlapping chan (%4uMHz) is "
                                     "blocked for phymode (%2d)",
                                     chan_freq, ext_chan_freq, mode);
                            skipchanextinvalid = 1;
                            break;
                        }
                    }
                }
            }
        }
#endif

        if ( skipchanextinvalid ) {
            continue;
        }

        acs_info(CHLST, "Adding channel (%4uMHz) with flag (%#018llx) to list",
                 channel->ic_freq, channel->ic_flags);

        if (chan_freq != (uint16_t) IEEE80211_FREQ_ANY) {
            acs->acs_chan_maps[acs_ch_idx] = acs->acs_nchans;
        }

        if (acs->acs_nchans < IEEE80211_ACS_ENH_CHAN_MAX) {
            acs->acs_chan_objs[acs->acs_nchans] = *channel;
            acs->acs_chans[acs->acs_nchans] = &acs->acs_chan_objs[acs->acs_nchans];
            acs->acs_nchans++;
        } else {
            acs_info(CHLST, "Number of ACS channels (%4d) are more than "
                     "maximum channels (%4d)",
                     acs->acs_nchans, IEEE80211_ACS_ENH_CHAN_MAX);
            break;
        }
    }

    qdf_mem_free(cur_chan_list);
}

/*
 * ieee80211_acs_construct_chan_list
 * Construct the available channel list for a given mode.
 *
 * @acs : Pointer to the ACS structure.
 * @mode: Value of the given phymode.
 */
static void ieee80211_acs_construct_chan_list(ieee80211_acs_t acs, int mode)
{
    u_int16_t nchans_2ghz = 0;

    acs_info(BASE, "Constructing channel list for phymode (%2d)", mode);
    /* reset channel mapping array */
    OS_MEMSET(&acs->acs_chan_maps, 0xff, sizeof(acs->acs_chan_maps));
    acs->acs_nchans = 0;

    switch (mode) {
        case IEEE80211_MODE_AUTO:
            /*
             * Try to add channels corresponding to different 2.4GHz modes
             * in decreasing order, starting from highgest possible mode.
             * The higher mode channels, that the device doesn't support, won't be added.
             * So, this will select highest mode, the device supports.
             */

            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXG_HE40PLUS);
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXG_HE40MINUS);

            /*
             * acs->acs_nchans will be incremented by ieee80211_acs_get_phymode_channels.
             * check if the previous call could add the channels.
             * If it has already added, no need to add the lower mode channels.
             * otherwise we will try to add lower mode channels.
             */
            if (!acs->acs_nchans) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT40PLUS);
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT40MINUS);
            }

            if (!acs->acs_nchans) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT20);
            }

            if (!acs->acs_nchans) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11G);
            }

            if (!acs->acs_nchans) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11B);
            }

            nchans_2ghz = acs->acs_nchans;
            /*
             * Try to add channels corresponding to different 5GHz modes
             * in decreasing order, starting from highgest possible mode.
             * The higher mode channels, that the device doesn't support, won't be added.
             * So, this will select highest mode, the device supports.
             */

            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE160);

           /*
             * acs->acs_nchans will be incremented by ieee80211_acs_get_phymode_channels.
             * check if the previous call could add the channels.
             * If it has already added, no need to add the lower mode channels.
             * otherwise we will try to add lower mode channels.
             * We will try to add the 5GHz channels, even though we have already added 2.4GHz channels,
             * since this could be a dual-band radio.
             */

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE80);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE40PLUS);
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE40MINUS);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE20);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT160);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT80);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT40PLUS);
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT40MINUS);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT20);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT40PLUS);
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT40MINUS);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT20);
            }

            if (!(acs->acs_nchans > nchans_2ghz)) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11A);
            }

            ieee80211_acs_check_band_to_scan(acs, nchans_2ghz);
            break;

        case IEEE80211_MODE_NONE:
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXG_HE20);
            nchans_2ghz = acs->acs_nchans;
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE20);

            if (acs->acs_nchans == 0) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT20);
                nchans_2ghz = acs->acs_nchans;
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT20);
            }

            /* If no HT channel available */
            if (acs->acs_nchans == 0) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11G);
                nchans_2ghz = acs->acs_nchans;
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11A);
            }

            /* If still no channel available */
            if (acs->acs_nchans == 0) {
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11B);
                nchans_2ghz = acs->acs_nchans;
            }
            ieee80211_acs_check_band_to_scan(acs, nchans_2ghz);
            break;

        case IEEE80211_MODE_11AXG_HE40:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXG_HE40PLUS);
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXG_HE40MINUS);
            acs->acs_scan_2ghz_only = 1;
            acs_info(BASE, "Getting channels with phymode HE40+ and HE40-");
            break;

        case IEEE80211_MODE_11NG_HT40:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT40PLUS);
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT40MINUS);
            acs->acs_scan_2ghz_only = 1;
            acs_info(BASE, "Getting channels with phymode HT40+ and HT40-");
            break;

        case IEEE80211_MODE_11NA_HT40:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT40PLUS);
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NA_HT40MINUS);
            acs_info(BASE, "Getting channels with phymode HT40+ and HT40-");
            break;
        case IEEE80211_MODE_11AXA_HE40:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE40PLUS);
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE40MINUS);
            acs_info(BASE, "Getting channels with phymode HE40+ and HE40-");
            break;

        case IEEE80211_MODE_11AC_VHT40:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT40PLUS);
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT40MINUS);
            acs_info(BASE, "Getting channels with phymode VHT40+ and VHT40-");
            break;
        case IEEE80211_MODE_11AXA_HE80:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE80);
            acs_info(BASE, "Getting channels with phymode HE80");
            break;
        case IEEE80211_MODE_11AC_VHT80:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT80);
            acs_info(BASE, "Getting channels with phymode VHT80");
            break;
        case IEEE80211_MODE_11AXA_HE80_80:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE80_80);
            acs_info(BASE, "Getting channels with phymode HE80_80");
            if(acs->acs_ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) {
                /*
                 * When EMIWAR is EMIWAR_80P80_FC1GTFC2
                 * there will be no 80_80 channel combination for 149,153,157,161,
                 * because of which these channel will not be added to acs_chan list
                 * in which case acs will not even consider as these channel as secondary channel.
                 * So in this case add 149,153,157,161 80MHz channels to acs channel list
                 * and force acs not to select these channel as primary
                 * but can consider these channel as secondary channel.
                 */
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE80);
                acs_info(BASE, "EMIWAR_80P80_FC1GTFC2 is enabled"
                         "Getting channels with phymode HE80");
            }
            break;
        case IEEE80211_MODE_11AC_VHT80_80:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT80_80);
            acs_info(BASE, "Getting channels with phymode VHT80_80");
            if(acs->acs_ic->ic_emiwar_80p80 == EMIWAR_80P80_FC1GTFC2) {
                /*
                 * When EMIWAR is EMIWAR_80P80_FC1GTFC2
                 * there will be no 80_80 channel combination for 149,153,157,161,
                 * because of which these channel will not be added to acs_chan list
                 * in which case acs will not even consider as these channel as secondary channel.
                 * So in this case add 149,153,157,161 80MHz channels to acs channel list
                 * and force acs not to select these channel as primary
                 * but can consider these channel as secondary channel.
                 */
                ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT80);
                acs_info(BASE, "EMIWAR_80P80_FC1GTFC2 is enabled"
                         "Getting channels with phymode VHT80");
            }
            break;
        case IEEE80211_MODE_11AXA_HE160:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AXA_HE160);
            acs_info(BASE, "Getting channels with phymode HE160");
            break;
        case IEEE80211_MODE_11AC_VHT160:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11AC_VHT160);
            acs_info(BASE, "Getting channels with phymode VHT160");
            break;
        default:
            /* if PHY mode is not AUTO, get channel list by PHY mode directly */
            ieee80211_acs_get_phymode_channels(acs, mode);
            break;
    }
}

/*
 * acs_bk_scan_timer:
 * Function to run every ACS background scan interval.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 * N/A
 */
static OS_TIMER_FUNC(acs_bk_scan_timer)
{
    ieee80211_acs_t acs;

    OS_GET_TIMER_ARG(acs, ieee80211_acs_t );
    acs_info(BASE, "Scan timer handler");

    qdf_sched_work(0 , &acs->acs_bk_scan_work);

}

/*
 * acs_bk_scan_work_handler:
 * Handle background scan events.
 *
 * @data: Opaque handle to the ACS structure.
 */
void acs_bk_scan_work_handler(void *data)
{
    ieee80211_acs_t acs;

    acs = (ieee80211_acs_t)data;
    acs_info(BASE, "Background scan work handler");

    if(acs->acs_scantimer_handler)
        acs->acs_scantimer_handler(acs->acs_scantimer_arg);

    OS_SET_TIMER(&acs->acs_bk_scantimer, acs->acs_bk_scantime*1000);
}

/*
 * ieee80211_acs_init:
 * Initialize ACS data.
 *
 * @acs      : Pointer to the ACS structure.
 * @devhandle: Pointer to the ic structure.
 * @osdev    : Pointer to the OS device structure.
 *
 * Return:
 * 0: Success
 */
int ieee80211_acs_init(ieee80211_acs_t *acs, wlan_dev_t devhandle, osdev_t osdev)
{
    int i;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ieee80211com *ic = devhandle;
#if ATH_ACS_DEBUG_SUPPORT
    struct acs_debug_bcn_event_container *bcn   = NULL;
    struct acs_debug_chan_event_container *chan = NULL;
#endif

    if(ic == NULL) {
        acs_err("Null ic");
        return EINVAL;
    }

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        acs_err("Null pdev");
        return EINVAL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (psoc == NULL) {
        acs_err("Null psoc");
        return EINVAL;
    }

#if ATH_ACS_DEBUG_SUPPORT
    /* Retaining previous debug framework data */
    bcn  = (struct acs_debug_bcn_event_container *)((*acs)->acs_debug_bcn_events);
    chan = (struct acs_debug_chan_event_container *)((*acs)->acs_debug_chan_events);
#endif

    OS_MEMZERO(*acs, sizeof(struct ieee80211_acs));

#if ATH_ACS_DEBUG_SUPPORT
    (*acs)->acs_debug_bcn_events = bcn;
    (*acs)->acs_debug_chan_events = chan;
#endif

    /* Save handles to required objects.*/
    (*acs)->acs_ic     = devhandle;
    (*acs)->acs_osdev  = osdev;

    (*acs)->acs_noisefloor_threshold = ACS_NOISE_FLOOR_THRESH_MIN;
    (*acs)->acs_obss_near_range_weightage = ACS_OBSS_NEAR_RANGE_WEIGHTAGE_DEFAULT;
    (*acs)->acs_obss_mid_range_weightage = ACS_OBSS_MID_RANGE_WEIGHTAGE_DEFAULT;
    (*acs)->acs_obss_far_range_weightage = ACS_OBSS_FAR_RANGE_WEIGHTAGE_DEFAULT;

    qdf_spinlock_create(&((*acs)->acs_lock));
    qdf_spinlock_create(&((*acs)->acs_ev_lock));
    (*acs)->acs_snrvar   = ACS_ALLOWED_SNRVARAINCE ;
    (*acs)->acs_effvar   = ACS_ALLOWED_CHEFFVARAINCE ;
    (*acs)->acs_chloadvar = ACS_ALLOWED_CHANLOADVARAINCE;
    (*acs)->acs_srvar = ACS_ALLOWED_SRVARAINCE;
    (*acs)->acs_bk_scantime  = ATH_ACS_DEFAULT_SCANTIME;
    (*acs)->acs_bkscantimer_en = 0;
    (*acs)->acs_ic->ic_acs_ctrlflags = 0;
    (*acs)->acs_limitedbsschk = 0;
    /* By default report to user space is disabled  */
    (*acs)->acs_scan_req_param.acs_scan_report_active = false;
    (*acs)->acs_scan_req_param.acs_scan_report_pending = false;
    acs_dbg_mask = 0;
    (*acs)->acs_ch_hopping.param.nohop_dur = CHANNEL_HOPPING_NOHOP_TIMER ; /* one minute*/
    /* 15 minutes */
    (*acs)->acs_ch_hopping.param.long_dur =  CHANNEL_HOPPING_LONG_DURATION_TIMER;
    (*acs)->acs_ch_hopping.param.cnt_dur = CHANNEL_HOPPING_CNTWIN_TIMER ; /* 5 sec */
    /* switch channel if out of total time 75 % idetects noise */
    (*acs)->acs_ch_hopping.param.cnt_thresh = 75;
    /* INIT value will increment at each channel selection*/
    (*acs)->acs_ch_hopping.ch_max_hop_cnt = 0;
    /*video bridge Detection threshold */
    (*acs)->acs_ch_hopping.param.noise_thresh = CHANNEL_HOPPING_VIDEO_BRIDGE_THRESHOLD;
    (*acs)->acs_ch_hopping.ch_nohop_timer_active = false ; /*HOPPING TIMER ACTIVE  */
    /*Default channel change will happen through usual ways not by channel hopping */
    (*acs)->acs_ch_hopping.ch_hop_triggered = false;
    /* Init these values will help us in reporting user
       the values being used in case he wants to enquire
       even before setting these values */
    (*acs)->acs_scan_req_param.mindwell = MIN_DWELL_TIME         ;
    (*acs)->acs_scan_req_param.maxdwell = MAX_DWELL_TIME ;
    atomic_set(&(*acs)->acs_in_progress,false);
    (*acs)->acs_run_status = ACS_RUN_IDLE;
    (*acs)->acs_tx_power_type = ACS_TX_POWER_OPTION_TPUT;
    (*acs)->acs_2g_allchan = 0;
    (*acs)->acs_status = ACS_DEFAULT;

    qdf_create_work(0, &(*acs)->acs_bk_scan_work, acs_bk_scan_work_handler, (void *)(*acs));
    OS_INIT_TIMER(osdev, & (*acs)->acs_bk_scantimer, acs_bk_scan_timer, (void * )(*acs), QDF_TIMER_TYPE_WAKE_APPS);

    OS_INIT_TIMER((*acs)->acs_ic->ic_osdev,
            &((*acs)->acs_ch_hopping.ch_long_timer), ieee80211_ch_long_timer, (void *) ((*acs)->acs_ic), QDF_TIMER_TYPE_WAKE_APPS);

    OS_INIT_TIMER((*acs)->acs_ic->ic_osdev,
            &((*acs)->acs_ch_hopping.ch_nohop_timer), ieee80211_ch_nohop_timer,
            (void *) (*acs)->acs_ic, QDF_TIMER_TYPE_WAKE_APPS);

    OS_INIT_TIMER((*acs)->acs_ic->ic_osdev,
            &((*acs)->acs_ch_hopping.ch_cntwin_timer), ieee80211_ch_cntwin_timer,
            (void *) (*acs)->acs_ic, QDF_TIMER_TYPE_WAKE_APPS);

    for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
        (*acs)->hw_chan_grade[i] = 100;
    }
    if (ic->ic_is_target_lithium && (ic->ic_is_target_lithium(psoc))) {
        (*acs)->acs_chan_grade_algo = 1;
        acs_info(BASE, "Running channel grade/efficiency based selection");
    } else {
        (*acs)->acs_chan_grade_algo = 0;
        acs_info(BASE, "Running RSSI based selection");
    }

    return 0;
}

/*
 * ieee80211_acs_attach:
 * Attach the ACS data during interface attach.
 *
 * @acs      : Pointer to the ACS structure.
 * @devhandle: Pointer to the IC structure.
 * @osdev    : Pointer to the OS device structure.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
int ieee80211_acs_attach(ieee80211_acs_t *acs,
        wlan_dev_t          devhandle,
        osdev_t             osdev)
{
#if WIFI_MEM_MANAGER_SUPPORT
    struct ol_ath_softc_net80211 *scn;
    int soc_idx;
    uint8_t pdev_idx;
#endif

    if (*acs)
        return -EINPROGRESS; /* already attached ? */

#if WIFI_MEM_MANAGER_SUPPORT
    scn = OL_ATH_SOFTC_NET80211(devhandle);
    soc_idx = scn->soc->soc_idx;

    if (scn->sc_pdev) {
        pdev_idx = wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev);
    } else {
        acs_err("Null pdev");
        return -EINVAL;
    }

    *acs = (ieee80211_acs_t ) (wifi_kmem_allocation(soc_idx, pdev_idx, KM_ACS, sizeof(struct ieee80211_acs), 0));
#else
    *acs = (ieee80211_acs_t) OS_MALLOC(osdev, sizeof(struct ieee80211_acs), 0);
#endif

    if (*acs) {
#if ATH_ACS_DEBUG_SUPPORT
        (*acs)->acs_debug_bcn_events = NULL;
        (*acs)->acs_debug_chan_events = NULL;
#endif

        ieee80211_acs_init(&(*acs), devhandle, osdev);
        return EOK;
    }
    return -ENOMEM;
}

/*
 * ieee80211_acs_set_param:
 * API to set various ACS parameters.
 *
 * @acs: Pointer to the ACS structure.
 * @param: Given parameter to set.
 * @val: Given input value.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
int ieee80211_acs_set_param(ieee80211_acs_t acs, int param , int val)
{

    switch(param){
        case  IEEE80211_ACS_ENABLE_BK_SCANTIMER:
            acs->acs_bkscantimer_en = val ;
            if(val == 1){
                OS_SET_TIMER(&acs->acs_bk_scantimer, acs->acs_bk_scantime *1000);
            }else{
                OS_CANCEL_TIMER(&acs->acs_bk_scantimer);
            }
            break;
        case  IEEE80211_ACS_SCANTIME:
            acs->acs_bk_scantime = val;
            break;
        case  IEEE80211_ACS_SNRVAR:
            acs->acs_snrvar = val ;
            break;
        case  IEEE80211_ACS_CHAN_EFFICIENCY_VAR:
            acs->acs_effvar = val ;
            break;
        case  IEEE80211_ACS_CHLOADVAR:
            acs->acs_chloadvar = val;
            break;
        case  IEEE80211_ACS_SRLOADVAR:
            acs->acs_srvar = val;
            break;
        case  IEEE80211_ACS_LIMITEDOBSS:
            acs->acs_limitedbsschk = val;
            break;
        case IEEE80211_ACS_CTRLFLAG:
            acs->acs_ic->ic_acs_ctrlflags =val;
            break;
        case IEEE80211_ACS_DEBUGTRACE:
            acs_dbg_mask = val;
            break;
#if ATH_CHANNEL_BLOCKING
        case IEEE80211_ACS_BLOCK_MODE:
            acs->acs_block_mode = val & 0x3;
            break;
#endif

        case IEEE80211_ACS_TX_POWER_OPTION:
            if((val == ACS_TX_POWER_OPTION_TPUT) || (val == ACS_TX_POWER_OPTION_RANGE)) {
               acs->acs_tx_power_type = val;
            }
            else {
               acs_err("Invalid Tx power type (%d) - "
                        "%d: Throughput, %d: Range",
                         val,
                         ACS_TX_POWER_OPTION_TPUT,
                         ACS_TX_POWER_OPTION_RANGE);
            }
            break;

        case IEEE80211_ACS_2G_ALL_CHAN:
           acs->acs_2g_allchan = val;
           break;

        case IEEE80211_ACS_RANK:
            acs->acs_ranking = !!val;
            break;

        case IEEE80211_ACS_NF_THRESH:
            if ((val <= ACS_NOISE_FLOOR_THRESH_MAX)
                && (val >= ACS_NOISE_FLOOR_THRESH_MIN)) {
                acs->acs_noisefloor_threshold = val;
            }
	    else {
                acs_err("Invalid value (%d) - "
                         "Valid range (%d to %d)",
                         val,
                         ACS_NOISE_FLOOR_THRESH_MIN,
                         ACS_NOISE_FLOOR_THRESH_MAX);
                return -EINVAL;
            }
            break;

        case IEEE80211_ACS_CHAN_GRADE_ALGO:
            acs->acs_chan_grade_algo = !!val;
            break;
        case IEEE80211_ACS_OBSS_NEAR_RANGE_WEIGHTAGE:
            if ((val < 0) || (val > 100)) {
                acs_err("Invalid value (%d) - "
                         "Valid range (0 to 100)", val);
                return -EINVAL;
            }
            acs->acs_obss_near_range_weightage = val;
            break;
        case IEEE80211_ACS_OBSS_MID_RANGE_WEIGHTAGE:
            if ((val < 0) || (val > 100)) {
                acs_err("Invalid value (%d) - "
                         "Valid range (0 to 100)", val);
                return -EINVAL;
            }
            acs->acs_obss_mid_range_weightage = val;
            break;
        case IEEE80211_ACS_OBSS_FAR_RANGE_WEIGHTAGE:
            if ((val < 0) || (val > 100)) {
                acs_err("Invalid value (%d) - "
                         "Valid range (0 to 100)", val);
                return -EINVAL;
            }
            acs->acs_obss_far_range_weightage = val;
            break;
        default :
            acs_err("Invalid param (%d)", param);
            return -1;

    }

    return 0;

}

/*
 * ieee80211_acs_get_param:
 * API to get various ACS parameters.
 *
 * @acs  : Pointer to the ACS structure.
 * @param: Given parameter for get command.
 *
 * Return:
 *   -1: Invalid value returned (or) Error.
 * Else: Value of the requested parameter
 */
int ieee80211_acs_get_param(ieee80211_acs_t acs, int param )
{
    int val =0;
    switch(param){
        case IEEE80211_ACS_ENABLE_BK_SCANTIMER:
            val = acs->acs_bkscantimer_en ;
            break;
        case IEEE80211_ACS_SCANTIME:
            val = acs->acs_bk_scantime ;
            break;
        case IEEE80211_ACS_SNRVAR:
            val = acs->acs_snrvar ;
            break;
        case IEEE80211_ACS_CHAN_EFFICIENCY_VAR:
            val = acs->acs_effvar ;
            break;
        case  IEEE80211_ACS_CHLOADVAR:
            val = acs->acs_chloadvar ;
            break;
        case  IEEE80211_ACS_SRLOADVAR:
            val = acs->acs_srvar ;
            break;
        case IEEE80211_ACS_LIMITEDOBSS:
            val = acs->acs_limitedbsschk ;
            break;
        case IEEE80211_ACS_CTRLFLAG:
            val = acs->acs_ic->ic_acs_ctrlflags ;
            break;
        case IEEE80211_ACS_DEBUGTRACE:
            val = acs_dbg_mask;
            break;
#if ATH_CHANNEL_BLOCKING
        case IEEE80211_ACS_BLOCK_MODE:
            val = acs->acs_block_mode;
            break;
#endif
        case IEEE80211_ACS_TX_POWER_OPTION:
            val = acs->acs_tx_power_type ;
            break;
        case IEEE80211_ACS_2G_ALL_CHAN:
           val = acs->acs_2g_allchan;
           break;

        case IEEE80211_ACS_RANK:
           val = acs->acs_ranking;
           break;

        case IEEE80211_ACS_NF_THRESH:
            val = acs->acs_noisefloor_threshold;
            break;

        case IEEE80211_ACS_CHAN_GRADE_ALGO:
            val = acs->acs_chan_grade_algo;
            break;

        case IEEE80211_ACS_OBSS_NEAR_RANGE_WEIGHTAGE:
            val = acs->acs_obss_near_range_weightage;
            break;

        case IEEE80211_ACS_OBSS_MID_RANGE_WEIGHTAGE:
            val = acs->acs_obss_mid_range_weightage;
            break;

        case IEEE80211_ACS_OBSS_FAR_RANGE_WEIGHTAGE:
            val = acs->acs_obss_far_range_weightage;
            break;

        default :
            val = -1;
            acs_err("Invalid param (%d)", param);
            return -1;

    }
    return val ;
}

/*
 * ieee80211_acs_deinit:
 * Deinitialize ACS data.
 *
 * @acs: Pointer to the ACS structure.
 */
void ieee80211_acs_deinit(ieee80211_acs_t *acs)
{
    struct acs_ch_hopping_t *ch = NULL;

    ch = &((*acs)->acs_ch_hopping);
    /*
     * Free synchronization objects
     */
    OS_FREE_TIMER(&(*acs)->acs_bk_scantimer);
    qdf_flush_work(&(*acs)->acs_bk_scan_work);
    qdf_disable_work(&(*acs)->acs_bk_scan_work);

    OS_FREE_TIMER(&ch->ch_cntwin_timer);
    OS_FREE_TIMER(&ch->ch_nohop_timer);
    OS_FREE_TIMER(&ch->ch_long_timer);
    qdf_spinlock_destroy(&((*acs)->acs_lock));
    qdf_spinlock_destroy(&((*acs)->acs_ev_lock));
}

/*
 * ieee80211_acs_deinit:
 * Detach ACS from interface
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 *     0: Success
 * Non-0: Failed
 */
int ieee80211_acs_detach(ieee80211_acs_t *acs)
{
#if WIFI_MEM_MANAGER_SUPPORT
    wlan_dev_t devhandle;
    struct ol_ath_softc_net80211 *scn;
    uint8_t pdev_idx;
#endif

    if (*acs == NULL)
        return EINPROGRESS; /* already detached ? */

#if WIFI_MEM_MANAGER_SUPPORT
    devhandle = (*acs)->acs_ic;
    scn = OL_ATH_SOFTC_NET80211(devhandle);

    if (scn->sc_pdev) {
        pdev_idx = wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev);
    } else {
        acs_err("Null pdev");
        return -EINVAL;
    }
#endif

    ieee80211_acs_deinit(&(*acs));

#if ATH_ACS_DEBUG_SUPPORT
    /* Cleanup the ACS debug framework */
    acs_debug_cleanup(*acs);
#endif

#if WIFI_MEM_MANAGER_SUPPORT
    wifi_kmem_free(scn->soc->soc_idx, pdev_idx, KM_ACS, (void *)(*acs));
#else
    OS_FREE(*acs);
#endif

    *acs = NULL;

    return EOK;
}

/*
 * ieee80211_acs_post_event:
 * Post ACS events to all event handlers.
 *
 * @acs    : Pointer to the ACS structure.
 * @channel: Pointer to a selected channel.
 */
static void
ieee80211_acs_post_event(ieee80211_acs_t acs,
                         struct ieee80211_ath_channel *channel)
{
    int                                 i,num_handlers;
    ieee80211_acs_event_handler         acs_event_handlers[IEEE80211_MAX_ACS_EVENT_HANDLERS];
    void                                *acs_event_handler_arg[IEEE80211_MAX_ACS_EVENT_HANDLERS];

    acs_info(BASE, "Entry");
    /*
     * make a local copy of event handlers list to avoid
     * the call back modifying the list while we are traversing it.
     */
    qdf_spin_lock_bh(&acs->acs_lock);
    num_handlers=acs->acs_num_handlers;
    for (i=0; i < num_handlers; ++i) {
        acs_event_handlers[i] = acs->acs_event_handlers[i];
        acs_event_handler_arg[i] = acs->acs_event_handler_arg[i];
    }
    qdf_spin_unlock_bh(&acs->acs_lock);
    for (i = 0; i < num_handlers; ++i) {
        (acs_event_handlers[i]) (acs_event_handler_arg[i], channel);
    }
}

/*
 * ieee80211_ht40intol_evhandler:
 * Scan event handler for 20MHz/40MHz coexistence check specifically.
 *
 * @vdev : Pointer to the VDEV structure.
 * @event: Type of scan event received from scan manager.
 * @arg  : Opaque handle to the ACS structure.
 */
static void ieee80211_ht40intol_evhandler(struct wlan_objmgr_vdev *vdev,
        struct scan_event *event, void *arg)
{
    struct ieee80211vap *originator = wlan_vdev_get_mlme_ext_obj(vdev);
    ieee80211_acs_t acs = NULL;
    struct ieee80211vap *vap = NULL;
    int i = 0;
    uint64_t lock_held_duration = 0;
    uint16_t acs_ch_idx = 0;

    if (originator == NULL) {
        acs_err("Null originator (vap)");
        return;
    }

    if (arg == NULL) {
        acs_err("Null arg (acs)");
        return;
    }
    acs = (ieee80211_acs_t) arg;
    vap = acs->acs_vap;

    acs_ch_idx = ieee80211_acs_get_chan_idx(acs, event->chan_freq);
    /*
     * we don't need lock in evhandler since
     * 1. scan module would guarantee that event handlers won't get called simultaneously
     * 2. acs_in_progress prevent furher access to ACS module
     */
#if 0
#if DEBUG_EACS
    qdf_nofl_info( "%s scan_id %08X event %d reason %d ", __func__, event->scan_id, event->type, event->reason);
#endif
#endif

#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event SCAN_EVENT_TYPE_DEQUEUED.
     */
    ASSERT(0);

#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

    /* Ignore events reported by scans requested by other modules */
    if (acs->acs_scan_id != event->scan_id) {
        return;
    }

    if ( event->type == SCAN_EVENT_TYPE_FOREIGN_CHANNEL_GET_NF ) {
        struct ieee80211com *ic = originator->iv_ic;
        /* Get the noise floor value */
        acs->acs_noisefloor[acs_ch_idx] =
            ic->ic_get_cur_chan_nf(ic);
        acs_info(SCAN, "Updating channel (%3d) noisefloor (%4d)",
                 acs_ch_idx,
                 acs->acs_noisefloor[acs_ch_idx]);
    }

    if ((event->type != SCAN_EVENT_TYPE_COMPLETED) &&
            (event->type != SCAN_EVENT_TYPE_DEQUEUED)) {
        return;
    }
    vap->iv_ic->ic_ht40intol_scan_running = 0;
    qdf_spin_lock(&acs->acs_ev_lock);
    /* If ACS is not in progress, then return, since ACS cancel was called before this*/
    if (!ieee80211_acs_in_progress(acs)) {
        qdf_spin_unlock(&acs->acs_ev_lock);
        return;
    }
    lock_held_duration = qdf_ktime_to_ms(qdf_ktime_get());

    if (event->reason != SCAN_REASON_COMPLETED) {
        acs_err("Scan not totally complete. Investigate");
        goto scan_done;
    }
    ieee80211_find_40intol_overlap(acs, vap->iv_des_chan[vap->iv_des_mode]);

    for(i=0; i<IEEE80211_CHAN_MAX ;i++) {
        acs->acs_chan_snrtotal[i]= 0;
        acs->acs_chan_snr[i] = 0;
    }

    ucfg_scan_db_iterate(wlan_vap_get_pdev(acs->acs_vap),
            ieee80211_acs_get_channel_maxrssi_n_secondary_ch, acs);

scan_done:
    ieee80211_free_ht40intol_scan_resource(acs);
    ieee80211_acs_post_event(acs, vap->iv_des_chan[vap->iv_des_mode]);

    /*Comparing to true and setting it false return value is
        true in case comparison is successfull */

    if(!OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),true,false))
     {
         acs_err("Wrong locking in ACS, investigate");
         atomic_set(&(acs->acs_in_progress),false);
     }

    ieee80211_check_and_execute_pending_acsreport(vap);

    lock_held_duration = qdf_ktime_to_ms(qdf_ktime_get()) - lock_held_duration;
    qdf_spin_unlock(&acs->acs_ev_lock);
    acs_info(EXT, "Lock held duration (%llums)", lock_held_duration);
    return;
}

/*
 * ieee80211_acs_update_sec_chan_rssi:
 * Update the secondary channel RSSI information based on the current scan
 * entries in the scan database.
 *
 * @acs: Pointer to the ACS structure.
 */
static void ieee80211_acs_update_sec_chan_rssi(ieee80211_acs_t acs)
{
    int i;

    for (i = 0; i < IEEE80211_CHAN_MAX ;i++) {
        acs->acs_chan_snrtotal[i]= 0;
        acs->acs_chan_snr[i] = 0;
    }

    acs->acs_ic->ic_get_chan_grade_info(acs->acs_ic, acs->hw_chan_grade);

    ucfg_scan_db_iterate(wlan_vap_get_pdev(acs->acs_vap),
            ieee80211_acs_get_channel_maxrssi_n_secondary_ch, acs);
    return;
}

/*
 * ieee80211_acs_rank_channels:
 * Rank the channels after ACS scan.
 *
 * @chans_to_rank: Number of channels to rank from the top.
 *
 * Return:
 * Top ranked channel.
 */
static struct ieee80211_ath_channel *ieee80211_acs_rank_channels(ieee80211_acs_t acs, uint8_t chans_to_rank)
{
    int i;
    struct ieee80211_ath_channel *channel = NULL;
    struct ieee80211_ath_channel *top_channel = NULL;
    uint16_t acs_ch_idx = 0;
    u_int32_t random_chan = 0;
    u_int32_t ht40minus_chan = 0;

    /* For ACS channel ranking, get best channel repeatedly after blacklisting
     * the gotten channel and rank them in order */

        OS_MEMSET(acs->acs_rank, 0x0, sizeof(acs_rank_t)*IEEE80211_ACS_CHAN_MAX);
        /* Allot Rank for the returned best channel and mark it as blacklisted
         * channel so that it wont be considered for selection of best channel
         * in the next iteration.
         * A random channel is returned when all the channels are unusable
         * in which case its noted*/
        for (i = 0; i < chans_to_rank; i++) {
            channel = ieee80211_acs_find_best_centerchan(acs);
            if (channel == NULL) {
                acs_err("Null channel");
                return NULL;
            }

            switch (acs->acs_vap->iv_des_mode) {
                case IEEE80211_MODE_11NG_HT40PLUS:
			    case IEEE80211_MODE_11NG_HT40MINUS:
			    case IEEE80211_MODE_11NG_HT40:
			    case IEEE80211_MODE_11AXG_HE40PLUS:
			    case IEEE80211_MODE_11AXG_HE40MINUS:
			    case IEEE80211_MODE_11AXG_HE40:
			        ieee80211_find_40intol_overlap(acs, channel);
                default:
                    break;
            }

            acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
            if (!acs_ch_idx) {
                acs_err("Invalid acs_ch_idx");
                continue;
            }

            if (acs->acs_status != ACS_SUCCESS) {
                /*
                 * If ACS has not succeeded for this iteration, that is,
                 * through random channel selection or min-NBSS selection, then
                 * ranking is also random. Therefore, completing the iteration
                 * is redundant.
                 *
                 * In such a case, exit the ACS ranking iteration and make a
                 * note of the last ranked channel.
                 */
                random_chan = acs_ch_idx;

                /* Update the ranking only if not already set */
                if (!acs->acs_rank[acs_ch_idx].rank) {
                    acs->acs_channelrejflag[acs_ch_idx] |= ACS_REJFLAG_BLACKLIST;
                    acs->acs_rank[acs_ch_idx].rank = (i+1);
                }

                acs_err("Random channel detected. Exiting with rank of (%d)",
                        acs->acs_rank[acs_ch_idx].rank);

                /* If a top_channel has not been set, use the random channel */
                if (!top_channel)
                    top_channel = channel;
                break;
            }
            else {
                if (acs_ch_idx != 0) {
                    acs->acs_channelrejflag[acs_ch_idx] |= ACS_REJFLAG_BLACKLIST;
                    acs->acs_rank[acs_ch_idx].rank = (i+1);
                        if (!i)
                           top_channel = channel;

                }
            }
        }

        /* Mark a Reason code in the channel rank description for the all other
         * channels which have been Rejected for use */
        for (i = 0; i < acs->acs_nchans; i++) {
            channel = acs->acs_chans[i];
            acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);

            /* WAR to handle channel 5,6,7 for HT40 mode
             * (2 entries of channel are present) one for HT40PLUS and
             * another for HT40MINUS, the HT40MINUS channel flags are
             * stored in ht40minus_chan index of the acs flags array */
            if (((acs_ch_idx >= 5)&& (acs_ch_idx <= 7)) &&
                (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel) || IEEE80211_IS_CHAN_11AXG_HE40MINUS(channel))) {

                ht40minus_chan = 15 + (acs_ch_idx - 5);

                snprintf(acs->acs_rank[acs_ch_idx].desc, ACS_RANK_DESC_LEN,
                        "(%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s)",
                        !acs->acs_rank[acs_ch_idx].rank ? "SKP ": "",
                        (acs_ch_idx == random_chan) ? "Random ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SECCHAN))? "SC ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_WEATHER_RADAR))? "WR ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_DFS))? "DF ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_HIGHNOISE))? "HN ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SNR))? "RS ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_CHANLOAD))? "CL ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_REGPOWER))? "RP ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NON2G))? "N2G ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_PRIMARY_80_80))? "P80X ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_SEC_80_80))? "NS80X ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_PRIMARY_80_80))? "NP80X ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_FLAG_NON5G))? "N5G ":"",
                        ((acs->acs_channelrejflag[ht40minus_chan] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SPATIAL_REUSE))? "SPRE ":"");

                        acs->acs_channelrejflag[ht40minus_chan] &= ~ACS_REJFLAG_BLACKLIST;
            }
            else
            {
                snprintf(acs->acs_rank[acs_ch_idx].desc, ACS_RANK_DESC_LEN,
                        "(%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s)",
                        !acs->acs_rank[acs_ch_idx].rank ? "SKP ": "",
                        (acs_ch_idx == random_chan) ? "Random ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SECCHAN))? "SC ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_WEATHER_RADAR))? "WR ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_DFS))? "DF ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_HIGHNOISE))? "HN ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SNR))? "RS ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_CHANLOAD))? "CL ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_REGPOWER))? "RP ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NON2G))? "N2G ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_PRIMARY_80_80))? "P80X ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_SEC_80_80))? "NS80X ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_NO_PRIMARY_80_80))? "NP80X ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_FLAG_NON5G))? "N5G ":"",
                        ((acs->acs_channelrejflag[acs_ch_idx] &
                                (~ACS_REJFLAG_BLACKLIST)) &
                                (ACS_REJFLAG_SPATIAL_REUSE))? "SPRE ":"");

                        acs->acs_channelrejflag[acs_ch_idx] &= ~ACS_REJFLAG_BLACKLIST;
            }
        }
    return top_channel;
}

/*
 * acs_noise_detection_param:
 * Set/get noise detection parameter.
 *
 * @ic   : Pointer to the IC structure.
 * @cmd  : Set/get value
 * @param: Type of the parameter.
 * @val  : Value of the given parameter.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
static int acs_noise_detection_param(struct ieee80211com *ic ,int cmd ,int param,int *val)
{
    int err = EOK;

    if (!ieee80211com_has_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING))
        return EINVAL;

    if (cmd) {
        if (ic->ic_set_noise_detection_param) {
            if (param == IEEE80211_ENABLE_NOISE_DETECTION ||
                    param == IEEE80211_NOISE_THRESHOLD) /*Rest param are not supported */
                ic->ic_set_noise_detection_param(ic,param,*val);
            else {
                err = EINVAL;
            }
        }
        else { /* SET Noise detection in ath layer not enabled */
            err = EINVAL;
        }
    } else { /* GET part */
        if (ic->ic_get_noise_detection_param) {
            if (IEEE80211_GET_COUNTER_VALUE == param)
                ic->ic_get_noise_detection_param(ic,param,val);
            else  { /* in get path we dont need to get it from ath layer*/
                err = EINVAL;
            }
        } else
                err = EINVAL;
    }
    return err;
}

/*
 * ieee80211_acs_retrieve_chan_info:
 * Retrieve channel info for a given type of scan event and given freq.
 *
 * @ic  : Pointer to the IC structure.
 * @type: Type of scan event requested.
 * @freq: Value of the given frequency.
 */
void ieee80211_acs_retrieve_chan_info(struct ieee80211com *ic, enum scan_event_type type, uint32_t freq)
{
    u_int32_t now = 0;
    u_int8_t flags;
    ieee80211_acs_t acs = ic->ic_acs;
    uint16_t acs_ch_idx = ieee80211_acs_get_chan_idx(acs, freq);

    if (type == SCAN_EVENT_TYPE_FOREIGN_CHANNEL_GET_NF) {
        now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
        flags = ACS_CHAN_STATS_NF;
        /* Get the noise floor value */
        acs->acs_noisefloor[acs_ch_idx] = ic->ic_get_cur_chan_nf(ic);

        acs_info(SCAN, "Requesting channel stats and NF from target - "
                 "current_timestamp (%u.%03us)",
                 now / 1000, now % 1000);
        if (ic->ic_hal_get_chan_info)
            ic->ic_hal_get_chan_info(ic, flags);
    }
    if ( type == SCAN_EVENT_TYPE_FOREIGN_CHANNEL ) {
        /* get initial chan stats for the current channel */
        flags = ACS_CHAN_STATS;
        if (ic->ic_hal_get_chan_info)
            ic->ic_hal_get_chan_info(ic, flags);
    }
    return;
}

/*
 * ieee80211_acs_scan_evhandler:
 * Scan handler used for general ACS scanning.
 *
 * @vdev : Pointer to the VDEV structure.
 * @event: Type of the scan event received from scan manager.
 * @arg  : Opaque handle to the ACS structure.
 */
static void ieee80211_acs_scan_evhandler(struct wlan_objmgr_vdev *vdev,
        struct scan_event *event, void *arg)
{
    struct ieee80211vap *originator = wlan_vdev_get_mlme_ext_obj(vdev);
    struct ieee80211_ath_channel *channel = IEEE80211_CHAN_ANYC;
    struct ieee80211com *ic;
    ieee80211_acs_t acs;
    struct acs_ch_hopping_t *ch = NULL;
    int val = 0,retval = 0;
    struct ieee80211vap *vap, *tvap;
    uint64_t lock_held_duration = 0;

    if (originator == NULL) {
        acs_err("Null originator (vap)");
        return;
    }

    if (arg == NULL) {
        acs_err("Null arg (acs)");
        return;
    }

    ic = originator->iv_ic;
    acs = (ieee80211_acs_t) arg;
    ch = &(acs->acs_ch_hopping);
    /*
     * we don't need lock in evhandler since
     * 1. scan module would guarantee that event handlers won't get called simultaneously
     * 2. acs_in_progress prevent furher access to ACS module
     */
    acs_info(BASE, "Received scan event - "
             "scan_id (%#010x), "
             "chan_freq (%4uMHz), "
             "event (%2u), "
             "reason (%2u)",
             event->scan_id, event->chan_freq, event->type, event->reason);

    /* Ignore events reported by scans requested by other modules */
    if (acs->acs_scan_id != event->scan_id) {
        return;
    }
#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event IEEE80211_SCAN_DEQUEUED.
     */
    ASSERT(0);

#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

    /*
     * Retrieve the Noise floor information and channel load
     * in case of channel change and restart the noise floor
     * computation for the next channel
     */
    ieee80211_acs_retrieve_chan_info(ic, event->type, event->chan_freq);

    if (event->type != SCAN_EVENT_TYPE_COMPLETED) {
        return;
    }

#if ATH_ACS_DEBUG_SUPPORT
    /*
     * Resets the beacon flag for the ACS debug framework (if enabled)
     */
    if (ic->ic_acs_debug_support) {
        acs_debug_reset_flags(ic->ic_acs);
    }
#endif


    qdf_spin_lock(&acs->acs_ev_lock);
    /* If ACS is not in progress, then return, since ACS cancel was callled before this*/
    if (!ieee80211_acs_in_progress(acs)) {
        qdf_spin_unlock(&acs->acs_ev_lock);
        return;
    }

    lock_held_duration = qdf_ktime_to_ms(qdf_ktime_get());

    if (event->reason != SCAN_REASON_COMPLETED) {
        acs_info(SCAN, "Scan not totally complete. Should not occur! Investigate.");
        /* If scan is cancelled, ACS should invoke the scan again*/
        channel = IEEE80211_CHAN_ANYC;
        goto scan_done;
    }

    ieee80211_acs_update_sec_chan_rssi(acs);
    if (acs->acs_ranking) {
        channel = ieee80211_acs_rank_channels(acs, acs->acs_nchans);
    } else {
        /* To prevent channel selection when acs report is active */
        if (!acs->acs_scan_req_param.acs_scan_report_active) {
            channel = ieee80211_acs_find_best_centerchan(acs);
            switch (acs->acs_vap->iv_des_mode) {
            case IEEE80211_MODE_11NG_HT40PLUS:
            case IEEE80211_MODE_11NG_HT40MINUS:
            case IEEE80211_MODE_11NG_HT40:
            case IEEE80211_MODE_11AXG_HE40PLUS:
            case IEEE80211_MODE_11AXG_HE40MINUS:
            case IEEE80211_MODE_11AXG_HE40:
                ieee80211_find_40intol_overlap(acs, channel);
                break;
            default:
                break;
            }
        }
    }

scan_done:
    /* Generate ACS Complete Event for MAPv2 device */
    son_update_mlme_event(acs->acs_vap->vdev_obj, NULL, SON_EVENT_ALD_ACS_COMPLETE, NULL);

    ieee80211_acs_free_scan_resource(acs);
    /*ACS scan report is going on no need to take any decision for
      channel hopping timers */
    if (!acs->acs_scan_req_param.acs_scan_report_active) {
        if (ieee80211com_has_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING)) {

            if (!acs->acs_ch_hopping.ch_max_hop_cnt) {
                retval = acs_noise_detection_param(ic,true,IEEE80211_NOISE_THRESHOLD,
                        &ch->param.noise_thresh);
                if (retval == EOK ) {
                    OS_SET_TIMER(&ch->ch_long_timer, SEC_TO_MSEC(ch->param.long_dur));
                } else {
                    goto out;
                }
            }
            if (acs->acs_ch_hopping.ch_max_hop_cnt < ACS_CH_HOPPING_MAX_HOP_COUNT) {
                /* API to intimate sc that no hop is going on so should
                 * not calculate the noise floor */
                retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);
                if (retval == EOK) {
                    OS_SET_TIMER(&ch->ch_nohop_timer, SEC_TO_MSEC(ch->param.nohop_dur)); /*In sec*/
                    acs->acs_ch_hopping.ch_nohop_timer_active = true;
                }
                else {
                    goto out;
                }
            }
        }
    }
out:
    /* To prevent channel selection when channel load report is active */
    if(!acs->acs_scan_req_param.acs_scan_report_active) {
        ieee80211_acs_post_event(acs, channel);
    }
#if QCA_SUPPORT_SON
    else {
        u_int32_t i = 0;
        for (i = 0; i < acs->acs_uchan_list.uchan_cnt; i++) {
            uint16_t acs_ch_idx = ieee80211_acs_get_chan_idx(acs, acs->acs_uchan_list.uchan[i]);
            u_int8_t channel = ieee80211_acs_get_ieee_chan_from_ch_idx(acs_ch_idx);

            /* Inform the band steering module of the channel utilization. It will
             * ignore it if it is not for the right channel or it was not
             * currently requesting it.
             */

            /* SoN required channel number not channel index. There is no issue in 5G and 2G
             * since it has unique channels. For 2G and 5G channel index starts with 0
             * where as 6G starts with 188.
             * Ex. if 6G channel is 33 then channel index(acs_ch_idx) is 33+188 = 221
             * if 5G channel is 149 then channel index(acs_ch_idx) is 149+0 = 149
             */
            son_record_utilization(acs->acs_vap->vdev_obj, channel,
                                   acs->acs_chan_load[acs_ch_idx]);
        }
    }
#endif

    if (!OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),true,false))
    {
        acs_info(SCAN, "Wrong locking in ACS --investigate");
        atomic_set(&(acs->acs_in_progress),false);
    }

    acs->acs_scan_req_param.acs_scan_report_active = false;
    ieee80211_check_and_execute_pending_acsreport(acs->acs_vap);

    /*as per requirement we need to send event both for DCS as well as channel hop*/
    if (ch->ch_hop_triggered || ic->cw_inter_found) {
        if (channel && (channel != IEEE80211_CHAN_ANYC)) {
            acs_info(SCAN, "Changed channel due to channel hopping (%3d)",
                     ieee80211_acs_get_chan_idx(acs, channel->ic_freq));
            IEEE80211_DELIVER_EVENT_CH_HOP_CHANNEL_CHANGE(acs->acs_vap,ieee80211_acs_get_chan_idx(acs, channel->ic_freq));
        }
    }
    ch->ch_hop_triggered = false;

    TAILQ_FOREACH_SAFE(vap, &ic->ic_vaps, iv_next, tvap) {
        if (vap->ap_chan_rpt_enable && ieee80211_bg_scan_enabled(vap))
            ieee80211_update_ap_chan_rpt(vap);

        if (vap->rnr_enable && ieee80211_bg_scan_enabled(vap))
            ieee80211_update_rnr(vap);
    }

    acs->acs_run_status = ACS_RUN_COMPLETED;

    lock_held_duration = qdf_ktime_to_ms(qdf_ktime_get()) - lock_held_duration;
    qdf_spin_unlock(&acs->acs_ev_lock);
    acs_info(EXT, "lock held duration (%llums)", lock_held_duration);
    return;
}

/*
 * ieee80211_acs_free_scan_resource:
 * Free and unregister the general scan resources.
 *
 * @acs: Pointer to the ACS structure.
 */
static void ieee80211_acs_free_scan_resource(ieee80211_acs_t acs)
{
    struct wlan_objmgr_psoc *psoc = NULL;

    psoc = wlan_vap_get_psoc(acs->acs_vap);
    /* Free requester ID and callback () */
    ucfg_scan_unregister_requester(psoc, acs->acs_scan_requestor);
}

/*
 * ieee80211_free_ht40intol_scan_resource:
 * Free and unregister 20/40MHz coexistence (40MHz intolerance) scan
 * resources for the 2.4GHz band.
 *
 * @acs: Pointer to the ACS structure.
 */
static void ieee80211_free_ht40intol_scan_resource(ieee80211_acs_t acs)
{
    struct wlan_objmgr_psoc *psoc = NULL;

    psoc = wlan_vap_get_psoc(acs->acs_vap);
    /* Free requester ID and callback () */
    ucfg_scan_unregister_requester(psoc, acs->acs_scan_requestor);
}

/*
 * ieee80211_acs_iter_vap_channel:
 * Set the channel for each VAP when called from an iteration function.
 *
 * @arg: Opaque handle to the iteration VAP.
 * @vap: Pointer to the active VAP structure.
 * @is_last_vap: Flag to verify the last VAP in the iteration.
 */
static inline void ieee80211_acs_iter_vap_channel(void *arg,
                                                  struct ieee80211vap *vap,
                                                  bool is_last_vap)
{
    struct ieee80211vap *current_vap = (struct ieee80211vap *) arg;
    struct ieee80211_ath_channel *channel;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) {
        return;
    }
    if (ieee80211_acs_channel_is_set(current_vap)) {
        return;
    }
    if (vap == current_vap) {
        return;
    }

    if (ieee80211_acs_channel_is_set(vap)) {
        channel =  vap->iv_des_chan[vap->iv_des_mode];
        current_vap->iv_ic->ic_acs->acs_channel = channel;
    }

}

/*
 * ieee80211_acs_flush_olddata:
 * Reset all the ACS data.
 *
 * @acs: Pointer to the ACS structure.
 */
static void ieee80211_acs_flush_olddata(ieee80211_acs_t acs)
{
    int i;

    acs_info(BASE, "Flushing old data");
    acs->acs_minrssi_11na = 0xffffffff ;
    acs->acs_minrssisum_11ng = 0xffffffff;
    OS_MEMSET(acs->acs_chan_nbss, 0x0, sizeof(acs->acs_chan_nbss));
    OS_MEMSET(acs->acs_chan_snrtotal, 0x0, sizeof(acs->acs_chan_snrtotal));
    OS_MEMSET(acs->acs_chan_snr,      0x0, sizeof(acs->acs_chan_snr));
    OS_MEMSET(acs->acs_chan_maxsnr,    0x0, sizeof(acs->acs_chan_maxsnr));
    OS_MEMSET(acs->acs_chan_minsnr,   0x0, sizeof(acs->acs_chan_minsnr));
    OS_MEMSET(acs->acs_chan_load,      0x0, sizeof(acs->acs_chan_load));
    OS_MEMSET(acs->acs_cycle_count,    0x0, sizeof(acs->acs_cycle_count));
    OS_MEMSET(acs->acs_adjchan_load,   0x0, sizeof(acs->acs_adjchan_load));
    OS_MEMSET(acs->acs_chan_loadsum,   0x0, sizeof(acs->acs_chan_loadsum));
    OS_MEMSET(acs->acs_chan_regpower,  0x0, sizeof(acs->acs_chan_regpower));
    OS_MEMSET(acs->acs_channelrejflag, 0x0, sizeof(acs->acs_channelrejflag));
    OS_MEMSET(acs->acs_adjchan_flag,   0x0, sizeof(acs->acs_adjchan_flag));
    OS_MEMSET(acs->acs_adjchan_load,   0x0, sizeof(acs->acs_adjchan_load));
    OS_MEMSET(acs->acs_srp_supported,  0x0, sizeof(acs->acs_srp_supported));
    OS_MEMSET(acs->acs_srp_load,       0x0, sizeof(acs->acs_srp_load));
    OS_MEMSET(acs->acs_chan_nbss_weighted, 0x0, sizeof(acs->acs_chan_nbss_weighted));
    OS_MEMSET(acs->chan_efficiency, 0x0, sizeof(acs->chan_efficiency));
    OS_MEMSET(acs->acs_chan_nbss_near, 0x0, sizeof(acs->acs_chan_nbss_near));
    OS_MEMSET(acs->acs_chan_nbss_mid, 0x0, sizeof(acs->acs_chan_nbss_mid));
    OS_MEMSET(acs->acs_chan_nbss_far, 0x0, sizeof(acs->acs_chan_nbss_far));
    OS_MEMSET(acs->acs_chan_nbss_weighted, 0x0, sizeof(acs->acs_chan_nbss_weighted));

    for(i = 0 ; i < IEEE80211_CHAN_MAX ; i++) {
         acs->acs_noisefloor[i] = NF_INVALID;
         acs->acs_sec_chan[i] = false;
    }




}

/*
 * ieee80211_ht40_reset_intol_flag: Reset INTOL flag of all the channels
 *
 * @ic: Pointer to the struct ieee80211com structure
 *
 * Return: none
 */
static void ieee80211_ht40_reset_intol_flag(struct ieee80211com *ic)
{
    struct ieee80211_ath_channel *channel;
    int i;

    qdf_assert_always(ic);

    ieee80211_enumerate_channels(channel, ic, i) {
        if (!channel)
            continue;

        if (IEEE80211_IS_CHAN_BW_40INTOL(channel)) {
            channel->ic_flags &= ~(IEEE80211_CHAN_40INTOLMARK | IEEE80211_CHAN_40INTOL);
        }
    }
}

/*
 * ieee80211_find_ht40intol_bss:
 * Run 20/40MHz coexistence check for the 2.4GHz band.
 *
 * @vap: Pointer to the VAP structure.
 *
 * Return:
 * Non-0: Failure.
 * Passed from wlan_ucfg_scan_start().
 */
static int ieee80211_find_ht40intol_bss(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = NULL;
    ieee80211_acs_t acs = NULL;
    struct ieee80211_ath_channel *chan;
    struct scan_start_request *scan_params = NULL;
    uint32_t *chan_list = NULL;
    uint32_t chan_count = 0;
    int ret = EOK;
    u_int8_t i;
    struct wlan_objmgr_vdev *vdev = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    if ((vap == NULL) || (vap->iv_ic == NULL) || (vap->iv_ic->ic_acs == NULL)) {
        acs_err("Null vap (%p) or ic (%p) or acs (%p)",
                 vap,
                 vap ? vap->iv_ic : 0,
                 vap ? (vap->iv_ic ? vap->iv_ic->ic_acs : 0) : 0);
        return EINVAL;
    }

    vdev = vap->vdev_obj;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
        acs_err("Unable to get vdev reference");
        return EBUSY;
    }

    ic = vap->iv_ic;
    acs = ic->ic_acs;

    acs_info(OBSS, "entry");
    qdf_spin_lock_bh(&acs->acs_lock);

    if(OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),false,true)) {
        /* Just wait for acs done */
        qdf_spin_unlock_bh(&acs->acs_lock);
        wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
        return EINPROGRESS;
    }

    acs->acs_run_status = ACS_RUN_IDLE;
    qdf_spin_unlock_bh(&acs->acs_lock);

   /* acs_in_progress prevents others from reaching here so unlocking is OK */

    acs->acs_vap = vap;

    /* reset channel mapping array */
    OS_MEMSET(&acs->acs_chan_maps, 0xff, sizeof(acs->acs_chan_maps));
    acs->acs_nchans = 0;
    /* Get 11NG HT20 channels */
    ieee80211_acs_get_phymode_channels(acs, IEEE80211_MODE_11NG_HT20);

    if (acs->acs_nchans == 0) {
        acs_err("Cannot construct the available channel list.");
        goto err;
    }

    ieee80211_ht40_reset_intol_flag(ic);
    /* register scan event handler */
    psoc = wlan_vap_get_psoc(vap);
    acs->acs_scan_requestor = ucfg_scan_register_requester(psoc, (uint8_t*)"acs",
            ieee80211_ht40intol_evhandler, (void *)acs);
    if (!acs->acs_scan_requestor) {
        acs_err("Unable to allocate requestor - "
                 "status (%2d), "
                 "handler (%p), "
                 "acs (%p)",
                 status, ieee80211_ht40intol_evhandler, acs);
        goto err;
    }

    chan_list = (u_int32_t *) qdf_mem_malloc(sizeof(u_int32_t)*acs->acs_nchans);
    if (!chan_list) {
        acs_err("unable to allocate chan list");
        goto err;
    }

    scan_params = (struct scan_start_request*) qdf_mem_malloc(sizeof(*scan_params));
    if (!scan_params) {
        acs_err("unable to allocate scan request");
        goto err;
    }
    status = wlan_update_scan_params(vap,scan_params,IEEE80211_M_HOSTAP,
            false,true,false,true,0,NULL,0);
    if (status) {
        qdf_mem_free(scan_params);
        acs_err("scan param init failed - status (%2d)", status);
        goto err;
    }

    scan_params->scan_req.scan_flags = 0;
    scan_params->scan_req.scan_f_passive = true;
    scan_params->scan_req.dwell_time_passive = MAX_DWELL_TIME;
    scan_params->scan_req.dwell_time_active = MAX_DWELL_TIME;
    scan_params->scan_req.dwell_time_active_6g = MAX_DWELL_TIME;
    scan_params->scan_req.dwell_time_passive_6g = MAX_DWELL_TIME;

    scan_params->scan_req.scan_f_2ghz = true;

    /* scan needs to be done on 2GHz  channels */
    for (i = 0; i < acs->acs_nchans; i++) {
        chan = acs->acs_chans[i];
        if (IEEE80211_IS_CHAN_2GHZ(chan)) {
            chan_list[chan_count++] = chan->ic_freq;
        }
    }
    status = ucfg_scan_init_chanlist_params(scan_params,
            chan_count, chan_list, NULL);
    if (status) {
        qdf_mem_free(scan_params);
        goto err;
    }

    /* If scan is invoked from ACS, Channel event notification should be
     * enabled  This is must for offload architecture
     */
    scan_params->scan_req.scan_f_chan_stat_evnt = true;

    pdev = wlan_vdev_get_pdev(vdev);
    /*Flush scan table before starting scan */
    ucfg_scan_flush_results(pdev, NULL);

    ieee80211_acs_flush_olddata(acs);

    /* Try to issue a scan */
    if ((status = wlan_ucfg_scan_start(vap,
                scan_params,
                acs->acs_scan_requestor,
                SCAN_PRIORITY_HIGH,
                &(acs->acs_scan_id), 0, NULL)) != QDF_STATUS_SUCCESS) {
        acs_err("Failed to start scan - status (%2d)", status);
        goto err;
    }


    vap->iv_ic->ic_ht40intol_scan_running = 1;
    goto end;

err:
    ieee80211_free_ht40intol_scan_resource(acs);

    if(!OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),true,false))
     {
         acs_err("Wrong locking in ACS -- investigate");
         atomic_set(&(acs->acs_in_progress),false);
      }

    ieee80211_acs_post_event(acs, vap->iv_des_chan[vap->iv_des_mode]);
end:
    if (chan_list) {
        qdf_mem_free(chan_list);
    }
    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
    return ret;
}

/*
 * ieee80211_acs_derive_adj_chans:
 * Derive adjacent (for 5/6GHz) and overlapping channels (for 2.4GHz) for a
 * given channel.
 *
 * @acs           : Pointer to the ACS structure.
 * @channel       : Pointer to the given channel.
 * @first_adj_chan: Pointer to the location to store the first_adj_chan
 * @last_adj_chan : Pointer to the location to store the last_adj_chan
 *
 * Return:
 * QDF_STATUS_SUCESS: Success
 * Else             : Failure
 */
static QDF_STATUS ieee80211_acs_derive_adj_chans(ieee80211_acs_t acs,
                                          struct ieee80211_ath_channel *channel,
                                          int16_t *first_adj_chan,
                                          int16_t *last_adj_chan)
{
#define ADJ_CHANS 8 /* Implies 8/2 channels */
#define OVERLAP_CHANS 2 /* Implies 2 channels */
    uint16_t pri_chan = 0, center_chan = 0, center_chan_160 = 0;
    struct acs_sec_chans sec_chans = {0};
    int status;
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;

    if (!channel) {
        return QDF_STATUS_E_INVAL;
    }

    pri_chan = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
    if (!pri_chan) {
        return QDF_STATUS_E_INVAL;
    }

    mode = ieee80211_chan2mode(channel);
    if (mode == IEEE80211_MODE_AUTO) {
        return QDF_STATUS_E_INVAL;
    }

    center_chan = ieee80211_acs_get_center_freq_idx(channel->ic_vhtop_ch_num_seg1,
                                                    channel->ic_freq);
    if (!center_chan &&
        ((mode == IEEE80211_MODE_11AC_VHT160)   ||
         (mode == IEEE80211_MODE_11AXA_HE160)   ||
         (mode == IEEE80211_MODE_11AC_VHT80_80) ||
         (mode == IEEE80211_MODE_11AXA_HE80_80))) {
        acs_err("Could not derive center_chan");
        return QDF_STATUS_E_INVAL;
    }

    center_chan_160 = ieee80211_acs_get_center_freq_idx(channel->ic_vhtop_ch_num_seg2,
                                                        channel->ic_freq);
    if (!center_chan_160 &&
        ((mode == IEEE80211_MODE_11AC_VHT160) ||
         (mode == IEEE80211_MODE_11AXA_HE160))) {
        acs_err("Could not derive center_chan");
        return QDF_STATUS_E_INVAL;
    }

    status = ieee80211_acs_derive_sec_chans_with_mode(acs,
                                                      mode,
                                                      channel->ic_freq,
                                                      center_chan,
                                                      center_chan_160,
                                                      &sec_chans);
    if (status) {
        acs_err("Could not derive secondary channels");
        return QDF_STATUS_E_INVAL;
    }

    switch (ieee80211_chan2mode(channel))
    {
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40PLUS:
            /* Only secondary 20MHz is required */
            if (IEEE80211_IS_CHAN_2GHZ(channel)) {
                *first_adj_chan = pri_chan - OVERLAP_CHANS;
                *last_adj_chan  = sec_chans.sec_chan_20;
            } else {
                *first_adj_chan = pri_chan - ADJ_CHANS;
                *last_adj_chan  = sec_chans.sec_chan_20 + ADJ_CHANS;
            }
            break;

        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
            if (IEEE80211_IS_CHAN_2GHZ(channel)) {
                *first_adj_chan = sec_chans.sec_chan_20;
                *last_adj_chan  = pri_chan + OVERLAP_CHANS;
            } else {
                *first_adj_chan = sec_chans.sec_chan_20 - ADJ_CHANS;
                *last_adj_chan  = pri_chan + ADJ_CHANS;
            }
            break;

        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AC_VHT80_80:
        case IEEE80211_MODE_11AXA_HE80_80:
           /* Adjacent channels are 4 channels before the band and 4 channels are
               after the band */
            *first_adj_chan = (center_chan - 6) - 2*ADJ_CHANS;
            *last_adj_chan =  (center_chan + 6) + 2*ADJ_CHANS;
            break;
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AXA_HE160:
           /* Adjacent channels are 4 channels before the band and 4 channels are
               after the band */
            *first_adj_chan = (center_chan_160 - 14) - 2*ADJ_CHANS;
            *last_adj_chan =  (center_chan_160 + 14) + 2*ADJ_CHANS;
            break;

        default: /* neither HT40+ nor HT40-, finish this call */
            if (IEEE80211_IS_CHAN_2GHZ(channel)) {
                *first_adj_chan = pri_chan - OVERLAP_CHANS;
                *last_adj_chan  = pri_chan + OVERLAP_CHANS;
            } else {
                *first_adj_chan = pri_chan - ADJ_CHANS;
                *last_adj_chan  = pri_chan + ADJ_CHANS;
            }
            break;

    }

    return 0;
#undef OVERLAP_CHANS
#undef ADJ_CHANS
}

/*
 * ieee80211_acs_construct_scan_chan_list:
 * Contruct the channel list and populate the scan params for ACS scanning.
 *
 * @acs             : Pointer to the ACS structure.
 * @mode            : Value of the given phymode.
 * @chan_list       : Pointer to the given channel list.
 * @chan_count      : Value of the number of chans in the given chan_list.
 * @require_adj_chan: Value of policy of adding adjacent channels to given list.
 * @scan_params     : Pointer to the scan_params for the pending scan_request.
 *
 * Return:
 * QDF_STATUS_SUCCESS: Success
 * Else              : Failure
 */
static QDF_STATUS ieee80211_acs_construct_scan_chan_list(ieee80211_acs_t acs,
                                         enum ieee80211_phymode mode,
                                         const uint32_t *chan_list,
                                         uint32_t chan_count,
                                         bool require_adj_chans,
                                         struct scan_start_request *scan_params)
{
    struct ieee80211com       *ic;
    struct regulatory_channel *full_channel_list;
    wlan_chan_t               channel_1 = NULL, channel_2 = NULL;
    enum ieee80211_phymode    mode_1 = IEEE80211_MODE_AUTO,
                              mode_2 = IEEE80211_MODE_AUTO;
    int16_t                   last_adj_chan = 0,
                              first_adj_chan = IEEE80211_ACS_CHAN_MAX,
                              last_adj_chan_temp = 0,
                              first_adj_chan_temp = IEEE80211_ACS_CHAN_MAX;
    bool                      add_all_supported_chans = false;
    uint16_t                  acs_ch_idx, scan_channel_count = 0,
                              bitfield_size = 0;
    uint32_t                  *scan_channel_list = NULL;
    int16_t                   chan_ix, chan_ix_2;
    acs_chan_bitfield_t       channel_bitfield = NULL;
    uint16_t                  limit_band = 0;
    enum reg_wifi_band        chan_band = 0;
    QDF_STATUS                status;

    if (!acs) {
        acs_err("NULL acs");
        return QDF_STATUS_E_INVAL;
    }

    if (!scan_params) {
        acs_err("NULL scan_params");
        return QDF_STATUS_E_INVAL;
    }

    ic = acs->acs_ic;
    if (!ic) {
        acs_err("NULL ic");
        return QDF_STATUS_E_INVAL;
    }

    qdf_mem_zero(acs->acs_ch_idx, IEEE80211_ACS_CHAN_MAX);
    acs->acs_nchans_scan = 0;

    if (chan_list && chan_count) {
        /* Creating a bitfield for describing adjacent channels */
        bitfield_size = howmany(IEEE80211_ACS_CHAN_MAX,
                                sizeof(acs_chan_bitfield_t *) * BITS_PER_BYTE);
        channel_bitfield = qdf_mem_malloc(bitfield_size *
                                          sizeof(acs_chan_bitfield_t *));
        if (!channel_bitfield) {
            acs_err("Could not allocate memory for channel_bitfield");
            status = QDF_STATUS_E_NOMEM;
            goto exit;
        } else {
            qdf_mem_zero(channel_bitfield, bitfield_size*sizeof(acs_chan_bitfield_t *));
        }
    }

    if (chan_list && chan_count && channel_bitfield) {
        /*
         * If a valid channel list and channel count is present, then
         * use only the channels mentioned along with adjacent channels
         * to ensure accurate channel selection.
         */
        for(chan_ix = 0; chan_ix < chan_count; chan_ix++) {
            if (!require_adj_chans) {
                acs_ch_idx = ieee80211_acs_get_chan_idx(acs,
                                                        chan_list[chan_ix]);
                if (!acs_ch_idx) {
                    acs_info(CHLST, "Could not find ACS channel index for given "
                             "frequency (%4uMHz)",
                             chan_list[chan_ix]);
                    continue;
                }

                ACS_CHAN_BITFIELD_SET(channel_bitfield, acs_ch_idx);
                scan_channel_count++;
            } else {
                if ((mode == IEEE80211_MODE_AUTO) ||
                    (mode == IEEE80211_MODE_NONE)) {
                    /*
                     * If the mode is set to AUTO or NONE, secondary and
                     * adjacent channel derivation is not possible, therefore,
                     * consider all channels.
                     */
                    acs_err("Cannot find adjacent channels. Adding all chans - "
                            "mode (%2d)",
                            mode);
                    add_all_supported_chans = true;
                    scan_channel_count = NUM_CHANNELS;
                    break;
                }

                /*
                 * Some 11NG and 11AXG 40MHz channels support for + and -
                 * secondary offsets (eg. channel 6). As a result, the adjacent
                 * channel used for scanning needs to consider both (if
                 * applicable).
                 */
                mode_1 = IEEE80211_MODE_AUTO;
                mode_2 = IEEE80211_MODE_AUTO;
                if (mode == IEEE80211_MODE_11NG_HT40) {
                    mode_1 = IEEE80211_MODE_11NG_HT40PLUS;
                    mode_2 = IEEE80211_MODE_11NG_HT40MINUS;
                } else if (mode == IEEE80211_MODE_11AXG_HE40) {
                    mode_1 = IEEE80211_MODE_11AXG_HE40PLUS;
                    mode_2 = IEEE80211_MODE_11AXG_HE40MINUS;
                } else {
                    mode_1 = mode;
                }

                if (mode_1)
                    channel_1 = ieee80211_find_dot11_channel(acs->acs_ic,
                                                          chan_list[chan_ix], 0,
                                                          mode_1);

                if (mode_2)
                    channel_2 = ieee80211_find_dot11_channel(acs->acs_ic,
                                                          chan_list[chan_ix], 0,
                                                          mode_2);

                if (!channel_1 && !channel_2) {
                    acs_info(CHLST, "Could not add channel due "
                             "invalid channel for given mode - "
                             "primary_channel (%4uMHz)",
                             chan_list[chan_ix]);
                    continue;
                }

                if (channel_1) {
                    status = ieee80211_acs_derive_adj_chans(acs,
                                                      channel_1,
                                                      &first_adj_chan,
                                                      &last_adj_chan);
                    if (status) {
                        acs_info(CHLST, "Could not derive adjacent "
                                 "channel list - "
                                 "primary_channel (%4uMHz)",
                                 chan_list[chan_ix]);
                        continue;
                    }
                }

                if (channel_2) {
                    status = ieee80211_acs_derive_adj_chans(acs,
                                                      channel_2,
                                                      &first_adj_chan_temp,
                                                      &last_adj_chan_temp);
                    if (status) {
                        acs_info(CHLST, "Could not derive adjacent "
                                 "channel list - "
                                 "primary_channel (%4uMHz)",
                                 chan_list[chan_ix]);
                        continue;
                    }

                    /*
                     * channel_2 will be valid for channels where both + and -
                     * secondary offsets are valid for 40MHz. For example,
                     * 2.4GHz channel 6 supports both 40+ and 40-.
                     * In such a case, if channel_1 is also valid, then extend
                     * adjacent channels to include both + and - for scanning.
                     */
                    first_adj_chan = (channel_1) ?
                                     MIN(first_adj_chan, first_adj_chan_temp) :
                                     first_adj_chan_temp;
                    last_adj_chan  = (channel_1) ?
                                     MAX(last_adj_chan, last_adj_chan_temp) :
                                     last_adj_chan_temp;
                }

                /* Check if the adjacent channels are valid */
                if (last_adj_chan <= first_adj_chan) {
                    acs_info(CHLST, "Derived adjacent channels are invalid - "
                             "first_adj_chan (%3d), "
                             "last_adj_chan (%3d)",
                             first_adj_chan, last_adj_chan);
                    continue;
                }

                for (chan_ix_2 = first_adj_chan; chan_ix_2 <= last_adj_chan; chan_ix_2++) {
                    if ((chan_ix_2 >= 0) &&
                        (chan_ix_2 < IEEE80211_ACS_CHAN_MAX) &&
                        ieee80211_acs_get_ieee_freq_from_ch_idx(acs, chan_ix_2) &&
                        ieee80211_find_dot11_channel(ic,
                                         ieee80211_acs_get_ieee_freq_from_ch_idx(acs, chan_ix_2),
                                         0, IEEE80211_MODE_AUTO) &&
                        !ACS_IS_CHAN_BITFIELD_SET(channel_bitfield, chan_ix_2)){
                        ACS_CHAN_BITFIELD_SET(channel_bitfield, chan_ix_2);
                        scan_channel_count++;
                    }
                }
            }
        }

        acs_info(CHLST, "Populating (%3d) channels from given channel "
                 "list and mode (%2d)",
                 scan_channel_count, mode);
    } else {
        /*
         * If the channel list is NULL or if the channel count is zero,
         * then add all supported channels from regulatory depending on the
         * band described by the phymode.
         */
        acs_info(CHLST, "Populating all supported channels by phymode (%2d)",
                 mode);
        add_all_supported_chans = true;
        scan_channel_count = NUM_CHANNELS;

        if (ieee80211_is_phymode_2g(mode)) {
            limit_band |= BIT(REG_BAND_2G);
        }

        if (ieee80211_is_phymode_5g_or_6g(mode)) {
            limit_band |= (BIT(REG_BAND_5G) | BIT(REG_BAND_6G));
        }
    }

    if (!scan_channel_count) {
        /* No channels found for scanning */
        acs_err("No channels found for scanning");
        status = QDF_STATUS_E_INVAL;
        goto exit;
    }

    scan_channel_list = qdf_mem_malloc(sizeof(uint32_t) * scan_channel_count);
    if (!scan_channel_list) {
        acs_err("Could not allocate memory for scan_channel_list");
        status = QDF_STATUS_E_NOMEM;
        goto exit;
    }

    chan_ix_2 = 0;

    full_channel_list = qdf_mem_malloc(NUM_CHANNELS *
                                   sizeof(struct regulatory_channel));
    if (!full_channel_list) {
        acs_err("Could not allocate memory for full_channel_list");
        return QDF_STATUS_E_NOMEM;
    }

    status = ucfg_reg_get_current_chan_list(ic->ic_pdev_obj, full_channel_list);
    if (status) {
        acs_err("Could not get current channel list");
        qdf_mem_free(full_channel_list);
        return QDF_STATUS_E_INVAL;
    }

    for (chan_ix = 0; chan_ix < NUM_CHANNELS; chan_ix++) {
        if ((full_channel_list[chan_ix].chan_flags & REGULATORY_CHAN_DISABLED) &&
            (full_channel_list[chan_ix].state == CHANNEL_STATE_DISABLE)) {
            continue;
        }

        acs_ch_idx = ieee80211_acs_get_chan_idx(acs,
                                        full_channel_list[chan_ix].center_freq);
        if (!acs_ch_idx) {
            /* Frequency not part of ACS supported channels */
            continue;
        }

        if (!add_all_supported_chans && channel_bitfield &&
            !ACS_IS_CHAN_BITFIELD_SET(channel_bitfield, acs_ch_idx)) {
            /* The channel is not part of the requested scanning list */
            continue;
        }

        chan_band = wlan_reg_freq_to_band(full_channel_list[chan_ix].center_freq);
        if (add_all_supported_chans && limit_band &&
            !(BIT(chan_band) & limit_band)) {
            /* Channel is not from the supported band */
            continue;
        }

        if (chan_band == REG_BAND_2G) {
            scan_params->scan_req.scan_f_2ghz = true;
        } else if ((chan_band == REG_BAND_5G) || (chan_band == REG_BAND_6G)) {
            scan_params->scan_req.scan_f_5ghz = true;
        }

        acs->acs_ch_idx[chan_ix_2]     = acs_ch_idx;
        scan_channel_list[chan_ix_2++] = full_channel_list[chan_ix].center_freq;

        if (chan_ix_2 == scan_channel_count) {
            break;
        }
    }

    qdf_mem_free(full_channel_list);

    if ((!scan_params->scan_req.scan_f_2ghz &&
         !scan_params->scan_req.scan_f_5ghz) ||
        !chan_ix_2) {
        acs_err("None of the channels are supported");
        status = QDF_STATUS_E_INVAL;
        goto exit;
    }

    if (scan_params->scan_req.scan_f_2ghz &&
        !scan_params->scan_req.scan_f_5ghz) {
        acs->acs_scan_2ghz_only = true;
        acs->acs_scan_5ghz_only = false;
    } else if (!scan_params->scan_req.scan_f_2ghz &&
               scan_params->scan_req.scan_f_5ghz) {
        acs->acs_scan_5ghz_only = true;
        acs->acs_scan_2ghz_only = false;
    } else {
        acs->acs_scan_2ghz_only = false;
        acs->acs_scan_5ghz_only = false;
    }

    /* acs_ch_idx[ix] will be used for ACS report */
    acs->acs_nchans_scan = chan_ix_2;
    status = ucfg_scan_init_chanlist_params(scan_params, chan_ix_2,
                                            scan_channel_list, NULL);

    acs_info(CHLST, "Selecting (%3d) channels for scanning",
             acs->acs_nchans_scan);

exit:
    if (scan_channel_list) {
        qdf_mem_free(scan_channel_list);
    }

    if (channel_bitfield) {
        qdf_mem_free(channel_bitfield);
    }

    return status;
}

/*
 * ieee80211_autoselect_infra_bss_channel:
 * Run the ACS channel scanning and selection algorithm called from external
 * entities (through a wrapper API).
 *
 * @vap           : Pointer to the VAP structure.
 * @is_scan_report: Policy of scanning only or scanning+selection.
 * @cfg_acs_params: Pointer to the ACS parameters to be used for selection.
 *
 * Return:
 * Non-0: Failure
 * Passed from wlan_ucfg_scan_start().
 */
static int ieee80211_autoselect_infra_bss_channel(struct ieee80211vap *vap,
                                    bool is_scan_report,
                                    cfg80211_hostapd_acs_params *cfg_acs_params)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_ath_channel *channel;
    struct scan_start_request *scan_params = NULL;
    u_int32_t num_vaps;
    int ret = EOK;
    u_int8_t chan_list_allocated = false;
    struct acs_ch_hopping_t *ch = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    uint32_t *chan_list = NULL;
    QDF_STATUS status = QDF_STATUS_SUCCESS;
    struct wlan_objmgr_vdev *vdev = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    u_int8_t skip_scan = 0;
#if ATH_SUPPORT_VOW_DCS
    uint16_t acs_ch_idx = 0;
#endif

    acs_info(BASE, "Invoking ACS module for best channel selection - "
             "vap (%p)", vap);
    vdev = vap->vdev_obj;
    status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
    if (QDF_IS_STATUS_ERROR(status)) {
         acs_err("unable to get reference");
        return EBUSY;
    }

    qdf_spin_lock_bh(&acs->acs_lock);

    if(OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),false,true)) {
        /* Just wait for acs done */
        qdf_spin_unlock_bh(&acs->acs_lock);
        wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
        acs_err("ACS is in progress");
        return EINPROGRESS;
    }
    acs->acs_run_status = ACS_RUN_IDLE;
    /* check if any VAP already set channel */
    acs->acs_channel = NULL;
    ch = &(acs->acs_ch_hopping);
    ieee80211_iterate_vap_list_internal(ic, ieee80211_acs_iter_vap_channel,vap,num_vaps);

    qdf_spin_unlock_bh(&acs->acs_lock);

    acs->acs_scan_req_param.acs_scan_report_active = is_scan_report;

    /* acs_in_progress prevents others from reaching here so unlocking is OK */
    /* Report active means we dont want to select channel so its okay to go beyond */
    /* if channel change triggered by channel hopping then go ahead */
    if (acs->acs_channel && (!ic->cw_inter_found)
            &&  (!acs->acs_scan_req_param.acs_scan_report_active)
            &&  (!ch->ch_hop_triggered)) {
        /* wlan scanner not yet started so acs_in_progress = true is OK */
        ieee80211_acs_post_event(acs, acs->acs_channel);
        atomic_set(&acs->acs_in_progress,false);
        wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
        acs_err("Channel already set!");
        return EOK;
    }

    acs->acs_vap = vap;

    if(cfg_acs_params != NULL){
        vap->iv_des_mode = cfg_acs_params->hw_mode;
    }

    /*  when report is active we dont want to depend on des mode as des mode will
        give channel list only for paricular mode in acsreport so choosing IEEE80211_MODE_NONE instead.
        IEEE80211_MODE_NONE mode makes sure maximum channels are added for the scanning.
    */

    if (acs->acs_scan_req_param.acs_scan_report_active) {
        ieee80211_acs_construct_chan_list(acs, IEEE80211_MODE_NONE);
    } else if ((cfg_acs_params != NULL) && (cfg_acs_params->freq_list != NULL)) {
        u_int8_t i;
        enum ieee80211_phymode  phy_mode_plus;
        enum ieee80211_phymode  phy_mode_minus;

        acs->acs_nchans = 0;
        if (ieee80211_is_phymode_11ng_ht40(cfg_acs_params->hw_mode) ||
                ieee80211_is_phymode_11axg_he40(cfg_acs_params->hw_mode)) {
             for(i = 0; i < cfg_acs_params->ch_list_len; i++){
                 if (!acs_is_channel_blocked(acs, cfg_acs_params->freq_list[i])) {

                     if (ieee80211_is_phymode_11ng_ht40(cfg_acs_params->hw_mode)) {
                         phy_mode_plus = IEEE80211_MODE_11NG_HT40PLUS;
                         phy_mode_minus = IEEE80211_MODE_11NG_HT40MINUS;
                     } else if (ieee80211_is_phymode_11axg_he40(cfg_acs_params->hw_mode)) {
                         phy_mode_plus = IEEE80211_MODE_11AXG_HE40PLUS;
                         phy_mode_minus = IEEE80211_MODE_11AXG_HE40MINUS;
                     }

                     channel = ieee80211_find_dot11_channel(ic, cfg_acs_params->freq_list[i],
                                        0, phy_mode_plus);
                     if((channel) && (channel != IEEE80211_CHAN_ANYC) && ((acs->acs_nchans) < IEEE80211_ACS_ENH_CHAN_MAX)) {
                        acs->acs_chan_objs[acs->acs_nchans] = *channel;
                        acs->acs_chans[acs->acs_nchans] = &acs->acs_chan_objs[acs->acs_nchans];
                        acs->acs_nchans++;
                     }

                     channel = ieee80211_find_dot11_channel(ic, cfg_acs_params->freq_list[i],
                                        0, phy_mode_minus);
                     if((channel) && (channel != IEEE80211_CHAN_ANYC) && ((acs->acs_nchans) < IEEE80211_ACS_ENH_CHAN_MAX)) {
                        acs->acs_chan_objs[acs->acs_nchans] = *channel;
                        acs->acs_chans[acs->acs_nchans] = &acs->acs_chan_objs[acs->acs_nchans];
                        acs->acs_nchans++;
                     }
                 }
             }
        } else {
             for(i = 0; i < cfg_acs_params->ch_list_len; i++){
                 if (!acs_is_channel_blocked(acs, cfg_acs_params->freq_list[i])) {
                     channel = ieee80211_find_dot11_channel(ic, cfg_acs_params->freq_list[i],
                                         0, cfg_acs_params->hw_mode);
                     if((channel) && (channel != IEEE80211_CHAN_ANYC) && ((acs->acs_nchans) < IEEE80211_ACS_ENH_CHAN_MAX)) {
                        acs->acs_chan_objs[acs->acs_nchans] = *channel;
                        acs->acs_chans[acs->acs_nchans] = &acs->acs_chan_objs[acs->acs_nchans];
                        acs->acs_nchans++;
                     }
                 }
             }
        }
    } else {
        ieee80211_acs_construct_chan_list(acs,acs->acs_vap->iv_des_mode);
    }

    if (acs->acs_nchans == 0) {
        acs_err("Cannot construct the available channel list.");
        ret = -EINVAL;
        goto err;
    }
#if ATH_SUPPORT_VOW_DCS
    /* update dcs information */
    if(ic->cw_inter_found && ic->ic_curchan){
        acs_ch_idx = ieee80211_acs_get_chan_idx(acs, ic->ic_curchan->ic_freq);
        acs->acs_intr_status[acs_ch_idx] += 1;
        acs->acs_intr_ts[acs_ch_idx] =
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    }
#endif

    /* register scan event handler */
    psoc = wlan_vap_get_psoc(vap);
    acs->acs_scan_requestor = ucfg_scan_register_requester(psoc, (uint8_t*)"acs",
        ieee80211_acs_scan_evhandler, (void *)acs);

    if (!acs->acs_scan_requestor) {
        acs_err("Could not allocate scan requestor - "
                 "status (%2d), "
                 "handler (%p), "
                 "acs (%p)",
                 status, acs, ieee80211_acs_scan_evhandler);
        ret = -ENOMEM;
        goto err;
    }

    scan_params = (struct scan_start_request *) qdf_mem_malloc(sizeof(*scan_params));
    if (!scan_params) {
        ret = -ENOMEM;
        acs_err("unable to allocate scan request");
        goto err;
    }

    /* Fill scan parameter */
    status = wlan_update_scan_params(vap,scan_params,IEEE80211_M_HOSTAP,
            false,true,false,true,0,NULL,0);
    if (status) {
        qdf_mem_free(scan_params);
        ret = -EINVAL;
        acs_err("init ssid failed with status (%2d)", status);
        goto err;
    }

    scan_params->scan_req.scan_flags = 0;
    scan_params->scan_req.scan_f_passive = true;
    scan_params->scan_req.dwell_time_passive = MAX_DWELL_TIME;
    scan_params->scan_req.dwell_time_active = MAX_DWELL_TIME;
    scan_params->scan_req.dwell_time_active_6g = MAX_DWELL_TIME;
    scan_params->scan_req.dwell_time_passive_6g = MAX_DWELL_TIME;

    /* giving priority to user configured param when report is active  */
    if(acs->acs_scan_req_param.acs_scan_report_active) {

        if(acs->acs_scan_req_param.maxdwell) {
            scan_params->scan_req.dwell_time_active = acs->acs_scan_req_param.maxdwell;
            scan_params->scan_req.dwell_time_passive = acs->acs_scan_req_param.maxdwell;
        }
        if(acs->acs_scan_req_param.rest_time) {
            /* rest time only valid for background scan */
            scan_params->scan_req.min_rest_time = acs->acs_scan_req_param.rest_time;
            scan_params->scan_req.max_rest_time = acs->acs_scan_req_param.rest_time;
        }
        if(acs->acs_scan_req_param.scan_mode) {
            /* Enabeling promise mode to get 11b stats */
            scan_params->scan_req.scan_f_promisc_mode = true;
        }
        if(acs->acs_scan_req_param.idle_time) {
            scan_params->scan_req.idle_time = acs->acs_scan_req_param.idle_time;
        }
        if(acs->acs_scan_req_param.max_scan_time) {
            scan_params->scan_req.max_scan_time  = acs->acs_scan_req_param.max_scan_time;
        }
    }

    /* If scan is invoked from ACS, Channel event notification should be
     * enabled  This is must for offload architecture
     */
    scan_params->scan_req.scan_f_chan_stat_evnt = true;

    if (acs->acs_scan_req_param.acs_scan_report_active) {
        acs_info(BASE, "User channel count (%3d)", acs->acs_uchan_list.uchan_cnt);
        /*
         * If user channel list is empty, all supported channels will be added
         */
        status = ieee80211_acs_construct_scan_chan_list(acs,
                        IEEE80211_MODE_NONE,
                        acs->acs_uchan_list.uchan_cnt ? acs->acs_uchan_list.uchan
                                                        : NULL,
                        acs->acs_uchan_list.uchan_cnt ? acs->acs_uchan_list.uchan_cnt
                                                        : 0,
                        false,
                        scan_params);
    } else {
        if (cfg_acs_params && cfg_acs_params->freq_list) {
            status = ieee80211_acs_construct_scan_chan_list(acs,
                                                  cfg_acs_params->hw_mode,
                                                  cfg_acs_params->freq_list,
                                                  cfg_acs_params->ch_list_len,
                                                  true,
                                                  scan_params);
        } else {
            status = ieee80211_acs_construct_scan_chan_list(acs,
                                                  IEEE80211_MODE_NONE,
                                                  NULL, 0, false,
                                                  scan_params);
        }
    }

    if (status) {
        qdf_mem_free(scan_params);
        ret = -EINVAL;
        acs_err("init chan list failed - status (%2d)", status);
        goto err2;
    }

    pdev = wlan_vdev_get_pdev(vdev);
    /*Flush scan table before starting scan */
    ucfg_scan_flush_results(pdev, NULL);

    ieee80211_acs_flush_olddata(acs);
    if (skip_scan || (ret = wlan_ucfg_scan_start(vap,
                    scan_params,
                    acs->acs_scan_requestor,
                    SCAN_PRIORITY_HIGH,
                    &(acs->acs_scan_id), 0, NULL)) != QDF_STATUS_SUCCESS) {

        acs_err("Failed to issue scan - status (%2d)", ret);
        ret = -EINVAL;
        goto err2;
    }
    acs->acs_startscantime = OS_GET_TIMESTAMP();
    goto end;

err2:
    acs_info(BASE, "err2 - Clearing ACS scan resources");
    /* Since the scan didn't happen, clear the acs_scan_report_active flag */
    acs->acs_scan_req_param.acs_scan_report_active = false;
    ieee80211_acs_free_scan_resource(acs);
err:
    acs_info(BASE, "err - Select first available channel and start");
    /* select the first available channel to start */
    if(!acs->acs_scan_req_param.acs_scan_report_active) {
        channel = ieee80211_find_dot11_channel(ic, 0, 0, vap->iv_des_mode);
        ieee80211_acs_post_event(acs, channel);
        acs_info(BASE, "Use the first available channel (%4uMHz) to start",
                 ieee80211_chan2freq(ic, channel));
    }

    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
    atomic_set(&acs->acs_in_progress,false);
    ch->ch_hop_triggered = false;
    if(chan_list_allocated == true)
        OS_FREE(chan_list);
    return ret;
end:
    wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
    if(chan_list_allocated == true)
        OS_FREE(chan_list);
    return ret;
}

/*
 * ieee80211_acs_startscantime:
 * Get the scan start time value from ACS structure.
 *
 * @ic: Pointer to the IC structure.
 *
 * Return:
 * Value of the acs_startscantime.
 */
int ieee80211_acs_startscantime(struct ieee80211com *ic)
{
    ieee80211_acs_t acs = ic->ic_acs;
    return(acs->acs_startscantime);
}

/*
 * ieee80211_acs_state:
 * Get the ACS state (in-progress or not).
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 *     0: ACS is completed/not-running.
 * Non-0: ACS is in-progress (or) scan never initiated.
 */
int ieee80211_acs_state(struct ieee80211_acs *acs)
{
    if(acs->acs_startscantime == 0){
        /*
         * Scan never initiated
         */
        return EINVAL;
    }
   if(ieee80211_acs_in_progress(acs)) {
       /*
        * Scan is in progress
        */
       return EINPROGRESS;
   }
   else{
        /*
         * Scan has been completed
         */
        return EOK;

    }
    return -1;
}

/*
 * ieee80211_acs_register_scantimer_handler:
 * API to register a scan timer event handler.
 *
 * @arg      : Opaque handle to IC structure
 * @evhandler: Pointer to the event handler to register.
 * @arg2     : Opaque handle to the event handler arguments.
 *
 * Return:
 * 0: Success
 */
static int ieee80211_acs_register_scantimer_handler(void *arg,
        ieee80211_acs_scantimer_handler evhandler,
        void                         *arg2)
{

    struct ieee80211com *ic = (struct ieee80211com *)arg;
    ieee80211_acs_t          acs = ic->ic_acs;

    acs_info(BASE, "Registering scantimer handler");
    qdf_spin_lock_bh(&acs->acs_lock);
    acs->acs_scantimer_handler= evhandler;
    acs->acs_scantimer_arg = arg2;
    qdf_spin_unlock_bh(&acs->acs_lock);

    return EOK;
}

/*
 * ieee80211_acs_register_event_handler:
 * Register the ACS event handler internally.
 *
 * @acs      : Pointer to the ACS structure.
 * @evhandler: Event handler to register.
 * @arg      : Opaque handle to the event handler arguments.
 *
 * Return:
 *     0: Success.
 * Non-0: Failure.
 */
static int ieee80211_acs_register_event_handler(ieee80211_acs_t          acs,
        ieee80211_acs_event_handler evhandler,
        void                         *arg)
{
    int    i;

    for (i = 0; i < IEEE80211_MAX_ACS_EVENT_HANDLERS; ++i) {
        if ((acs->acs_event_handlers[i] == evhandler) &&
                (acs->acs_event_handler_arg[i] == arg)) {
            return EEXIST; /* already exists */
        }
    }

    if (acs->acs_num_handlers >= IEEE80211_MAX_ACS_EVENT_HANDLERS) {
        return ENOSPC;
    }

    qdf_spin_lock_bh(&acs->acs_lock);
    acs->acs_event_handlers[acs->acs_num_handlers] = evhandler;
    acs->acs_event_handler_arg[acs->acs_num_handlers++] = arg;
    qdf_spin_unlock_bh(&acs->acs_lock);

    return EOK;
}

/*
 * ieee80211_acs_unregister_event_handler:
 * Unregister the ACS event handler internally.
 *
 * @acs      : Pointer to the ACS structure.
 * @evhandler: Event handler to unregister.
 * @arg      : Opaque handle to the event handler arguments.
 *
 * Return:
 *     0: Success.
 * Non-0: Failure.
 */
static int ieee80211_acs_unregister_event_handler(ieee80211_acs_t acs,
                                          ieee80211_acs_event_handler evhandler,
                                          void *arg)
{
    int    i;

    qdf_spin_lock_bh(&acs->acs_lock);
    for (i = 0; i < IEEE80211_MAX_ACS_EVENT_HANDLERS; ++i) {
        if ((acs->acs_event_handlers[i] == evhandler) &&
                (acs->acs_event_handler_arg[i] == arg)) {
            /* replace event handler being deleted with the last one in the list */
            acs->acs_event_handlers[i]    = acs->acs_event_handlers[acs->acs_num_handlers - 1];
            acs->acs_event_handler_arg[i] = acs->acs_event_handler_arg[acs->acs_num_handlers - 1];

            /* clear last event handler in the list */
            acs->acs_event_handlers[acs->acs_num_handlers - 1]    = NULL;
            acs->acs_event_handler_arg[acs->acs_num_handlers - 1] = NULL;
            acs->acs_num_handlers--;

            qdf_spin_unlock_bh(&acs->acs_lock);

            return EOK;
        }
    }
    qdf_spin_unlock_bh(&acs->acs_lock);

    return ENXIO;

}

/*
 * ieee80211_acs_cancel:
 * Cancel the scan internally.
 *
 * @vap: Pointer to the VAP handle.
 *
 * Return:
 * Non-0: Failure.
 *     0: Success.
 */
static int ieee80211_acs_cancel(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    ieee80211_acs_t acs;

    /* If vap is NULL return here */
    if(vap == NULL) {
       return 0;
    }

    vap->iv_ic->ic_ht40intol_scan_running = 0;
    ic = vap->iv_ic;
    acs = ic->ic_acs;

    /* If ACS is not initiated from this vap, so
       don't unregister scan handlers */
    if(vap != acs->acs_vap) {
       return 0;
    }
    qdf_spin_lock(&acs->acs_ev_lock);
    /* If ACS is not in progress, then return, since the ACS handling must have completed before
     acquiring the lock*/
    if (!ieee80211_acs_in_progress(acs)) {
        qdf_spin_unlock(&acs->acs_ev_lock);
        return 0;
    }

       /* Unregister scan event handler */
    ieee80211_acs_free_scan_resource(acs);
    ieee80211_free_ht40intol_scan_resource(acs);
     /* Post ACS event with NULL channel to report cancel scan */
    ieee80211_acs_post_event(acs, IEEE80211_CHAN_ANYC);
     /*Reset ACS in progress flag */
    atomic_set(&acs->acs_in_progress,false);
    acs->acs_ch_hopping.ch_hop_triggered = false;
    qdf_spin_unlock(&acs->acs_ev_lock);
    return 1;
}


/*
 * wlan_autoselect_register_scantimer_handler:
 * API to register a scan timer handler.
 *
 * @arg      : Opaque pointer to the ic structure.
 * @evhandler: Pointer to the event handler to register.
 * @arg2     : Opaque pointer to the event handler arguments.
 *
 * Return:
 * Passed from wlan_autoselect_register_scantimer_handler()
 */
int wlan_autoselect_register_scantimer_handler(void * arg ,
        ieee80211_acs_scantimer_handler  evhandler,
        void                          *arg2)
{
    return ieee80211_acs_register_scantimer_handler(arg ,
            evhandler,
            arg2);
}

/*
 * wlan_autoselect_register_event_handler:
 * API to register an ACS event handler.
 *
 * @vaphandle: Pointer to the vap handle.
 * @evhandler: Pointer to the event handler to register.
 * @arg      : Opaque pointer to the event handler arguments.
 *
 * Return:
 * Passed from ieee80211_acs_register_event_handler().
 */
int wlan_autoselect_register_event_handler(wlan_if_t vaphandle,
                                          ieee80211_acs_event_handler evhandler,
                                          void *arg)
{
    return ieee80211_acs_register_event_handler(vaphandle->iv_ic->ic_acs,
                                                evhandler,
                                                arg);
}

/*
 * wlan_autoselect_unregister_event_handler:
 * API to unregister an ACS event handler.
 *
 * @vaphandle: Pointer to the vap handle.
 * @evhandler: Pointer to the registered event handler.
 * @arg      : Opaque pointer to the event handler arguments.
 *
 * Return:
 * Passed from ieee80211_acs_unregister_event_handler.
 */
int wlan_autoselect_unregister_event_handler(wlan_if_t vaphandle,
                                          ieee80211_acs_event_handler evhandler,
                                          void *arg)
{
    return ieee80211_acs_unregister_event_handler(vaphandle->iv_ic->ic_acs,
                                                  evhandler,
                                                  arg);
}

/*
 * wlan_autoselect_in_progress:
 * Wrapper function to check if ACS is in progress from external callers.
 *
 * @vaphandle: Pointer to the VAP structure.
 *
 * Return:
 * 0: Success
 * Passed from ieee80211_acs_in_progress()
 */
int wlan_autoselect_in_progress(wlan_if_t vaphandle)
{
    if (!vaphandle->iv_ic->ic_acs) return 0;
    return ieee80211_acs_in_progress(vaphandle->iv_ic->ic_acs);
}

/*
 * wlan_autoselect_find_infra_bss_channel:
 * Wrapper function to run ACS from external callers.
 *
 * @vaphandle     : Pointer to the VAP structure.
 * @cfg_acs_params: Pointer to the input ACS parameters.
 *
 * Return:
 * Passed from ieee80211_autoselect_infra_bss_channel()
 */
int wlan_autoselect_find_infra_bss_channel(wlan_if_t vaphandle,
                                                 cfg80211_hostapd_acs_params *cfg_acs_params)
{
    return ieee80211_autoselect_infra_bss_channel(vaphandle, false /* is_scan_report */, cfg_acs_params);
}

/*
 * wlan_attempt_ht40_bss:
 * Check for OBSS for 20/40MHz coexience adherence in the 2.4GHz band.
 *
 * @vap: Pointer to the VAP structure.
 *
 * Return:
 * Passed from ieee80211_find_ht40intol_bss()
 */
int wlan_attempt_ht40_bss(wlan_if_t vaphandle)
{
    return ieee80211_find_ht40intol_bss(vaphandle);
}

/*
 * wlan_autoselect_cancel_selection:
 * Cancel ACS channel selection.
 *
 * @vaphandle: Pointer to the VAP structure.
 *
 * Return:
 * Passed from ieee80211_acs_cancel()
 */
int wlan_autoselect_cancel_selection(wlan_if_t vaphandle)
{
   return ieee80211_acs_cancel(vaphandle);
}

/*
 * wlan_acs_find_best_channel:
 * Find the best channel as called from an external API.
 *
 * @vap     : Pointer to the VAP structure.
 * @bestfreq: Pointer to the variable for storing the best channel.
 * @num     : Number of best channels to select.
 *
 * Return:
 *     0: Success
 * Non-0: Failed
 */
int wlan_acs_find_best_channel(struct ieee80211vap *vap, int *bestfreq, int num)
{

    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_ath_channel *best_11na = NULL;
    struct ieee80211_ath_channel *best_11ng = NULL;
    struct ieee80211_ath_channel *best_overall = NULL;
    int retv = 0,i=0;

    ieee80211_acs_t acs = ic->ic_acs;
    ieee80211_acs_t temp_acs;

    acs_info(BASE, "Finding best overall channel (ext call)");

    temp_acs = (ieee80211_acs_t) OS_MALLOC(acs->acs_osdev, sizeof(struct ieee80211_acs), 0);

    if (temp_acs) {
        OS_MEMZERO(temp_acs, sizeof(struct ieee80211_acs));
    }
    else {
        acs_err("Failed to allocate memory for temp_acs");
        return ENOMEM;
    }

    temp_acs->acs_ic = ic;
    temp_acs->acs_vap = vap;
    temp_acs->acs_osdev = acs->acs_osdev;
    temp_acs->acs_num_handlers = 0;
    atomic_set(&(temp_acs->acs_in_progress),true);
    temp_acs->acs_scan_2ghz_only = 0;
    temp_acs->acs_scan_5ghz_only = 0;
    temp_acs->acs_channel = NULL;
    temp_acs->acs_nchans = 0;



    ieee80211_acs_construct_chan_list(temp_acs,IEEE80211_MODE_AUTO);
    if (temp_acs->acs_nchans == 0) {
        acs_err("Failed to allocate memory for channel construction list");
        retv = -1;
        goto err;
    }

    for(i=0; i<IEEE80211_CHAN_MAX ;i++) {
        acs->acs_chan_snrtotal[i]= 0;
        acs->acs_chan_snr[i] = 0;
    }

    acs->acs_ic->ic_get_chan_grade_info(acs->acs_ic, acs->hw_chan_grade);

    ucfg_scan_db_iterate(wlan_vap_get_pdev(temp_acs->acs_vap),
            ieee80211_acs_get_channel_maxrssi_n_secondary_ch, temp_acs);

    best_11na = ieee80211_acs_find_best_11na_centerchan(temp_acs);
    best_11ng = ieee80211_acs_find_best_11ng_centerchan(temp_acs);

    if (temp_acs->acs_minrssi_11na > temp_acs->acs_minrssisum_11ng) {
        best_overall = best_11ng;
    } else {
        best_overall = best_11na;
    }

    if( best_11na==NULL || best_11ng==NULL || best_overall==NULL) {
        acs_err("Null best_11na chan (%p) or best_11ng chan (%p) or "
                 "best_overall (%p)", best_11na, best_11ng, best_overall);
        retv = -1;
        goto err;
    }

    bestfreq[0] = (int) best_11na->ic_freq;
    bestfreq[1] = (int) best_11ng->ic_freq;
    bestfreq[2] = (int) best_overall->ic_freq;

err:
    OS_FREE(temp_acs);
    return retv;

}

/*
 * ieee80211_acs_stats_update:
 * Update NF, channel load and other stats on receiving WMI stats event from
 * FW.
 *
 * @acs           : Pointer to the ACS structure.
 * @flags         : Type of stats received.
 * @ieee_chan_freq: Frequency for which the stats is received.
 * @noisefloor    : NF value of the given channel.
 * @chan_stats    : Received channel stats for the given channel.
 */
#define MIN_CLEAR_CNT_DIFF 1000
void ieee80211_acs_stats_update(ieee80211_acs_t acs,
        u_int8_t flags,
        uint16_t ieee_chan_freq,
        int16_t noisefloor,
        struct ieee80211_chan_stats *chan_stats)
{
    u_int32_t temp = 0,cycles_cnt = 0;
    u_int32_t now = (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    bool is_wrap_around = false;
    uint16_t acs_ch_idx = 0;

    acs_info(SCAN, "Received stats - "
             "current timestamp (%u.%03us)",
             now / 1000, now % 1000);
    if (acs == NULL) {
        acs_err("Null acs");
        return;
    }

    acs_ch_idx = ieee80211_acs_get_chan_idx(acs, ieee_chan_freq);
    if (acs_ch_idx == 0) {
        acs_err("Invalid channel freq (%4uMHz)", ieee_chan_freq);
        return;
    }

    if (!ieee80211_acs_in_progress(acs)) {
        if(acs->acs_run_status == ACS_RUN_COMPLETED)
            return;

        acs_info(SCAN, "ACS is not in progress. Returning");
        acs->acs_run_status = ACS_RUN_INCOMPLETE;
        return;
    }

    if (flags == ACS_CHAN_STATS_NF) {
        /* Ensure we received ACS_CHAN_STATS event before for same channel */
        if ((acs->acs_last_evt.event != ACS_CHAN_STATS) ||
                (acs->acs_last_evt.chan_freq != ieee_chan_freq)) {
            acs_err("Received Stats_NF without Stats_Diff - "
                     "prev chan (%4uMHz), "
                     "event (%#03x)",
                     ieee_chan_freq, flags);
            return;
        }
    }
    ic = acs->acs_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    if (flags == ACS_CHAN_STATS_DIFF) {

        acs->acs_cycle_count[acs_ch_idx] = chan_stats->cycle_cnt;
        acs->acs_chan_load[acs_ch_idx] = chan_stats->chan_clr_cnt;
        acs->acs_80211_b_duration[acs_ch_idx] = chan_stats->duration_11b_data;

        acs_info(CHLOAD, "Cycle count statistics - "
                 "channel (%3d), "
                 "cycle_cnt (%4u), "
                 "clear_cnt (%4u), "
                 "chan_load (%4u)",
                 acs_ch_idx, chan_stats->cycle_cnt, chan_stats->chan_clr_cnt,
                 acs->acs_chan_load[acs_ch_idx]);

    } else if (flags == ACS_CHAN_STATS_NF) {
        acs->acs_last_evt.event = ACS_CHAN_STATS_NF;
        acs->acs_last_evt.chan_freq = ieee_chan_freq;

        /* if initial counters are not recorded, return */
        if (acs->acs_cycle_count[acs_ch_idx] == 0)  {
            acs_info(BASE, "Channel load (and other stats) cannot be updated - "
                     "invalid initial counters");
            return;
        }

        /* For Beeliner family of chipsets, hardware counters cycle_cnt and chan_clr_cnt wrap
         * around independently. After reaching max value of 0xffffffff they become 0x7fffffff.
         *
         * For Peregrine and Direct attach chipsets, once cycle_cnt reaches 0xffffffff, both
         * cycle_cnt and chan_clr_cnt are right shifted by one bit. Because of this right
         * shifting we can't calculate correct channel utilization when wrap around happens.
         */

        if (acs->acs_cycle_count[acs_ch_idx] > chan_stats->cycle_cnt) {
            is_wrap_around = true;
            acs->acs_cycle_count[acs_ch_idx] = (MAX_32BIT_UNSIGNED_VALUE - acs->acs_cycle_count[acs_ch_idx])
                + (chan_stats->cycle_cnt - (MAX_32BIT_UNSIGNED_VALUE >> 1));
        } else {
            acs->acs_cycle_count[acs_ch_idx] = chan_stats->cycle_cnt - acs->acs_cycle_count[acs_ch_idx] ;
        }

        if (ic->ic_is_target_ar900b(ic)) {
            /* Beeliner family */
            if (acs->acs_chan_load[acs_ch_idx] > chan_stats->chan_clr_cnt) {
                is_wrap_around = true;
                acs->acs_chan_load[acs_ch_idx] = (MAX_32BIT_UNSIGNED_VALUE - acs->acs_chan_load[acs_ch_idx])
                    + (chan_stats->chan_clr_cnt - (MAX_32BIT_UNSIGNED_VALUE >> 1));
            } else {
                acs->acs_chan_load[acs_ch_idx] = chan_stats->chan_clr_cnt - acs->acs_chan_load[acs_ch_idx] ;
            }
        } else {
            /* Peregrine and Diretc attach family */
            if (acs->acs_cycle_count[acs_ch_idx] > chan_stats->cycle_cnt) {
                is_wrap_around = true;
                acs->acs_chan_load[acs_ch_idx] = chan_stats->chan_clr_cnt - (acs->acs_chan_load[acs_ch_idx] >> 1);
            } else {
                acs->acs_chan_load[acs_ch_idx] = chan_stats->chan_clr_cnt - acs->acs_chan_load[acs_ch_idx] ;
            }
        }

        if (acs->acs_80211_b_duration[acs_ch_idx] > chan_stats->duration_11b_data) {
             acs->acs_80211_b_duration[acs_ch_idx] = (MAX_32BIT_UNSIGNED_VALUE - acs->acs_80211_b_duration[acs_ch_idx])
                                                      + chan_stats->duration_11b_data;
        } else {
             acs->acs_80211_b_duration[acs_ch_idx] = chan_stats->duration_11b_data - acs->acs_80211_b_duration[acs_ch_idx] ;
        }

        acs_info(CHLOAD, "Cycle count stats - "
                 "channel (%3d), "
                 "cycle cnt (%4u), "
                 "clear cnt (%4u), "
                 "diff (%4u)",
                 acs_ch_idx,chan_stats->chan_clr_cnt,chan_stats->cycle_cnt,
                 acs->acs_chan_load[acs_ch_idx]);
    } else if (flags == ACS_CHAN_STATS) {
        acs_info(CHLOAD, "Cycle count stats - "
                 "channel (%3d), "
                 "chan_clr_cnt (%4u), "
                 "cycle_cnt (%4u)",
                 acs_ch_idx, chan_stats->chan_clr_cnt,chan_stats->cycle_cnt);
        acs->acs_last_evt.event = ACS_CHAN_STATS;
        acs->acs_last_evt.chan_freq = ieee_chan_freq;

        acs->acs_chan_load[acs_ch_idx] = chan_stats->chan_clr_cnt;
        acs->acs_cycle_count[acs_ch_idx] = chan_stats->cycle_cnt;
        acs->acs_80211_b_duration[acs_ch_idx] = chan_stats->duration_11b_data;
    }

    if ((flags == ACS_CHAN_STATS_DIFF) || (flags == ACS_CHAN_STATS_NF)) {
        if (ieee_chan_freq != (uint16_t)IEEE80211_FREQ_ANY) {
            int chain = 0;

            acs->acs_noisefloor[acs_ch_idx] = noisefloor;

            for (chain = 0; chain < HOST_MAX_CHAINS ; chain++) {
                acs->acs_perchain_nf[acs_ch_idx][chain] = (int16_t)chan_stats->perchain_nf[chain];
            }
            acs_info(NF, "Noise floor (%4d) received for channel (%3d)",
                     noisefloor, acs_ch_idx);
        }

        if((chan_stats->chan_tx_power_range > 0) || (chan_stats->chan_tx_power_tput > 0)) {
            if(acs->acs_tx_power_type == ACS_TX_POWER_OPTION_TPUT) {
               acs->acs_chan_regpower[acs_ch_idx] = chan_stats->chan_tx_power_tput;
            } else if(acs->acs_tx_power_type == ACS_TX_POWER_OPTION_RANGE)  {
               acs->acs_chan_regpower[acs_ch_idx] = chan_stats->chan_tx_power_range;
            }

            acs_info(REGPOWER, "Received Tx power stats update - "
                     "tx_power_type (%1d), "
                     "channel (%3d), "
                     "regpower val (%3d)",
                     acs->acs_tx_power_type,
                     acs_ch_idx,
                     acs->acs_chan_regpower[acs_ch_idx]);
        }

        /* make sure when new clr_cnt is more than old clr cnt, ch utilization is non-zero */
        if ((acs->acs_chan_load[acs_ch_idx] > MIN_CLEAR_CNT_DIFF) &&
             (acs->acs_cycle_count[acs_ch_idx] != 0)){
            temp = (u_int32_t)(acs->acs_chan_load[acs_ch_idx]);
            cycles_cnt = (u_int32_t) acs->acs_cycle_count[acs_ch_idx]/100;/*divide it instead multiply temp */
            if (!cycles_cnt) {
                cycles_cnt = 1;
            }
            temp = (u_int32_t)(temp/cycles_cnt);
            /* Some results greater than 100% have been seen. The reason for
             * this is unknown, so for now just floor the results to 100.
             */
            acs->acs_chan_load[acs_ch_idx] = MIN(MAX( 1,temp), 100);
            acs_info(CHLOAD, "Channel load (%3u) derived for channel (%3d)",
                     acs->acs_chan_load[acs_ch_idx], acs_ch_idx);
        } else {
            acs_info(CHLOAD, "Channel load (%3u) diff is less than minimum (or) "
                     "cycle count is zero for channel (%3d)",
                     acs->acs_chan_load[acs_ch_idx], acs_ch_idx);
            acs->acs_chan_load[acs_ch_idx] = 0;
        }
        if (is_wrap_around) {
            if ((acs->acs_chan_load[acs_ch_idx] >= 100) &&
                (acs->acs_last_evt.last_util.ieee_chan == acs_ch_idx)) {
                acs_info(CHLOAD, "Wrap around detected for chan (%3d) - "
                         "calculated util (%3u), "
                         "restored util (%3u)",
                         acs_ch_idx, acs->acs_chan_load[acs_ch_idx], acs->acs_last_evt.last_util.ch_util);
                acs->acs_chan_load[acs_ch_idx] = acs->acs_last_evt.last_util.ch_util;
            }
        } else {
            acs->acs_last_evt.last_util.ch_util = acs->acs_chan_load[acs_ch_idx];
            acs->acs_last_evt.last_util.ieee_chan = acs_ch_idx;
        }
    }
}

/*
 * wlan_acs_get_user_chanlist:
 * Get the channels in the user channel list.
 *
 * @vaphandle: Pointer to the VAP structure.
 * @chanlist : Pointer to the channel list to save the user channel list.
 *
 * Return:
 * Number of channels populated.
 */
int wlan_acs_get_user_chanlist(wlan_if_t vaphandle, qdf_freq_t *chanlist)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int32_t i=0;

    for(i=0;i<acs->acs_uchan_list.uchan_cnt;i++)
    {
        chanlist[i] = acs->acs_uchan_list.uchan[i];
    }
    return i;
}

/*
 * wlan_acs_set_user_chanlist:
 * Set the custom user-configured channel list for ACS scanning and channel
 * selection.
 *
 * @vap      : Pointer to the VAP structure.
 * @append   : Policy to append or flush.
 * @chan_list: Pointer to the given channel list.
 *
 * Return:
 * 0: Success
 */
int wlan_acs_set_user_chanlist(struct ieee80211vap *vap, bool append, qdf_freq_t *chan_list)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int32_t i = 0;
    int *ptr = NULL, dup = false;

    if(append) {
        /*append list*/
        ptr = (int *)(&(acs->acs_uchan_list.uchan[acs->acs_uchan_list.uchan_cnt]));
    }
    else {
        /*Flush list and start copying */
        OS_MEMZERO(acs->acs_uchan_list.uchan,IEEE80211_ACS_CHAN_MAX);
        ptr =(int *)(&(acs->acs_uchan_list.uchan[0]));
        acs->acs_uchan_list.uchan_cnt = 0;
    }

    while(*chan_list) {
        if(append) /*duplicate detection */
        {
            for(i = 0;i < acs->acs_uchan_list.uchan_cnt; i++) {
                if(*chan_list == acs->acs_uchan_list.uchan[i]) {
                    dup = true;
                    chan_list++;
                    break;
                } else {
                    dup = false;
                }
            }
        }
        if(!dup) {
            *ptr++ = *chan_list++;
            acs->acs_uchan_list.uchan_cnt++;
        }
    }
    return 0;
}

/*
 * ieee80211_acs_channel_hopping_change_channel:
 * Channel change for channel hopping.
 *
 * @vap: Pointer to the VAP structure.
 */
static void ieee80211_acs_channel_hopping_change_channel(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    ieee80211_acs_t acs;
    struct acs_ch_hopping_t *ch;

    ASSERT(vap);
    ic = vap->iv_ic;
    acs = ic->ic_acs;

    if(acs == NULL)
        return;

    ch = &(acs->acs_ch_hopping);

    if (ch->ch_hop_triggered)
        return ;  /* channel change is already active  */

    spin_lock(&ic->ic_lock);
    ch->ch_hop_triggered = true; /* To bail out acs in multivap scenarios */
    spin_unlock(&ic->ic_lock);

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            if (!wlan_set_channel(vap, IEEE80211_CHAN_ANY, 0)) {
                /* ACS is done on per radio, so calling it once is
                 * good enough
                 */
                goto done;
            }
        }
    }
done:
    return;
}

/*
 * ieee80211_ch_cntwin_timer:
 * Timer to keep track of noise detection.
 *
 * @ic: Pointer to the IC structure.
 */
static OS_TIMER_FUNC(ieee80211_ch_cntwin_timer)
{
    struct ieee80211com *ic = NULL;
    ieee80211_acs_t acs = NULL;
    struct acs_ch_hopping_t *ch = NULL;
    struct ieee80211_ath_channel *channel = NULL;
    struct ieee80211vap *vap = NULL;
    int32_t flag = 0,retval = 0, val = 0;
    qdf_freq_t cur_freq = 0;
    struct regulatory_channel *cur_chan_list;
    enum channel_enum chan_ix;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    ASSERT(ic);

    acs = ic->ic_acs;

    if(acs == NULL)
        return;

    ch = &(acs->acs_ch_hopping);

    vap = acs->acs_vap;

    if(vap == NULL)
        return;

    if(ieee80211_vap_deleted_is_clear(vap)) {
        /*Stopping noise detection To collect stats */
        val = false;
        retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);

        if(retval == EOK) {
            retval = acs_noise_detection_param(ic,false,IEEE80211_GET_COUNTER_VALUE,&val);
            if(val > acs->acs_ch_hopping.param.cnt_thresh)
            {
                if (ieee80211_acs_channel_is_set(vap)) {
                    channel =  vap->iv_des_chan[vap->iv_des_mode];
                    if(channel) {
                        cur_chan_list = qdf_mem_malloc(NUM_CHANNELS * sizeof(*cur_chan_list));
                        if (!cur_chan_list)
                            return;

                        if (wlan_reg_get_current_chan_list(ic->ic_pdev_obj,
                                                           cur_chan_list) !=
                            QDF_STATUS_SUCCESS) {
                            qdf_err("Failed to get cur_chan list");
                            qdf_mem_free(cur_chan_list);
                            return;
                        }

                        cur_freq = ieee80211_chan2freq(ic,channel);
                        for (chan_ix = 0; chan_ix < NUM_CHANNELS; chan_ix++) {
                            if (cur_freq == cur_chan_list[chan_ix].center_freq) {
                                acs_info(BASE, "Iterated channel (%4uMHz)",
                                         cur_chan_list[chan_ix].center_freq);
                                wlan_reg_set_chan_blocked(ic->ic_pdev_obj,
                                                          cur_chan_list[chan_ix].center_freq);
                                flag = true;
                            }
                        }

                       qdf_mem_free(cur_chan_list);
                    }
                }
            }
        } /*retval == EOK*/
        else
            return;


        if(flag) {
            acs->acs_ch_hopping.ch_max_hop_cnt++;
            ieee80211_acs_channel_hopping_change_channel(vap);
            return; /*Donot fire timer */
        }

        if(acs->acs_ch_hopping.ch_max_hop_cnt < ACS_CH_HOPPING_MAX_HOP_COUNT ) { /*Three hops are enough */
            /*Resting time over should enable noise detection now */
            val = true;
            retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);
            if(EOK == retval ) {
                /*Restarting noise detection again */
                OS_SET_TIMER(&ch->ch_cntwin_timer, SEC_TO_MSEC(ch->param.cnt_dur)); /*in sec */
            }
        }
    }/*vap deleted is clear */
    else {
        return; /*Do not fire timer return */
    }
}

/*
 * ieee80211_ch_long_timer:
 * Long duration timer for keeping track of history.
 *
 * @ic: Pointer to the IC structure.
 */
static OS_TIMER_FUNC(ieee80211_ch_long_timer)
{
    struct ieee80211com *ic = NULL;
    ieee80211_acs_t acs = NULL;
    struct acs_ch_hopping_t *ch = NULL;
    int i=0,retval = 0;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    ASSERT(ic);

    acs = ic->ic_acs;

    if(acs == NULL) /*vap delete may be in process */
        return;

    ch = &(acs->acs_ch_hopping);
    wlan_reg_clear_allchan_blocked(ic->ic_pdev_obj);

    if(acs->acs_ch_hopping.ch_max_hop_cnt >= ACS_CH_HOPPING_MAX_HOP_COUNT) {

        /*Restarting noise detection again */
        i = true;
        retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&i);
        if(retval == EOK)
            OS_SET_TIMER(&ch->ch_cntwin_timer, SEC_TO_MSEC(ch->param.cnt_dur)); /*in sec */
    }

    acs->acs_ch_hopping.ch_max_hop_cnt = 0;
    acs_info(BASE, "Long duration timer expiry, set itself");
    if(retval == EOK )
        OS_SET_TIMER(&ch->ch_long_timer, SEC_TO_MSEC(ch->param.long_dur)); /*in sec */
}

/*
 * ieee80211_ch_nohop_timer:
 * No channel chopping timer.
 * As long as the timer is active, channel cannot be changed.
 *
 * @ic: Pointer to the IC structure.
 */
static OS_TIMER_FUNC(ieee80211_ch_nohop_timer)
{
    struct ieee80211com *ic = NULL;
    int val = true,retval = 0;
    ieee80211_acs_t acs = NULL;
    struct acs_ch_hopping_t *ch = NULL;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    ASSERT(ic);

    acs = ic->ic_acs;
    ch = &(acs->acs_ch_hopping);
    acs_info(BASE, "No-hop timer expired, set cntwin_timer");
    acs->acs_ch_hopping.ch_nohop_timer_active = false;
    retval = acs_noise_detection_param(ic,true,IEEE80211_ENABLE_NOISE_DETECTION,&val);

    if(retval == EOK)
        OS_SET_TIMER(&ch->ch_cntwin_timer, SEC_TO_MSEC(ch->param.cnt_dur)); /*in sec */
    /* Any thing for else ?*/
    return;
}

/*
 * ieee80211_acs_ch_long_dur:
 * Set the long duration timer from user land.
 *
 * @acs: Pointer to the ACS structure.
 * @val: Value of the given long duration time
 *
 * Return:
 *     0: Success.
 * Non-0: Failure.
 */
int ieee80211_acs_ch_long_dur(ieee80211_acs_t acs,int val)
{
    struct acs_ch_hopping_t *ch = &(acs->acs_ch_hopping);
    /* Long duration  in minutes */
    if(val)
    {
        if(val < ch->param.nohop_dur)
            return EINVAL;

        /* start timer */
        ch->param.long_dur = val;
        OS_SET_TIMER(&ch->ch_long_timer, SEC_TO_MSEC(ch->param.long_dur)); /*in sec */
    } else {
        /* stop timer */
        OS_CANCEL_TIMER(&ch->ch_long_timer);
    }
    return EOK;
}

/*
 * ieee80211_acs_ch_nohop_dur:
 * Set the no hopping timer from user land.
 *
 * @acs: Pointer to the ACS structure.
 * @val: Value of the given no hop duration.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
int ieee80211_acs_ch_nohop_dur(ieee80211_acs_t acs,int val)
{
    struct acs_ch_hopping_t *ch = &(acs->acs_ch_hopping);

    /*channel hopping in seconds */
    if(val)
    {
        /* Do not restart timer,its for
           next evalutaion of no hopping */
        ch->param.nohop_dur = val;
    } else {
        /* stop timer */
        OS_CANCEL_TIMER(&ch->ch_nohop_timer);
    }
    return EOK;
}

/*
 * wlan_acs_param_ch_hopping:
 * Get/set channel hopping information from OS specific files.
 *
 * @vap  : Pointer to the VAP structure.
 * @param: Value of the given parameter (get/set).
 * @cmd  : Value of the given command.
 * @val  : Value of a given input value for a command.
 *
 * Return:
 *     0: Success.
 * Non-0: Failure.
 */
int wlan_acs_param_ch_hopping(wlan_if_t vap, int param, int cmd,int *val)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    int error = EOK,retval = EOK;
#define NOISE_FLOOR_MAX -60
#define NOISE_FLOOR_MIN -128
#define MAX_COUNTER_THRESH  100
    switch (param)
    {
        case true: /*SET */
            switch(cmd)
            {
                case IEEE80211_ACS_ENABLE_CH_HOP:
                    if(*val) {
                        ieee80211com_set_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING);
                        /*See if we want to init timer used in attached function */
                    }else {
                        ieee80211com_clear_cap_ext (ic,IEEE80211_ACS_CHANNEL_HOPPING);
                    }
                    break;
                case IEEE80211_ACS_CH_HOP_LONG_DUR:
                    ieee80211_acs_ch_long_dur(acs,*val);
                    break;
                case IEEE80211_ACS_CH_HOP_NO_HOP_DUR:
                    ieee80211_acs_ch_nohop_dur(acs,*val);
                    break;
                case IEEE80211_ACS_CH_HOP_CNT_WIN_DUR:
                    if(*val) {
                        acs->acs_ch_hopping.param.cnt_dur = *val;
                        if( acs->acs_ch_hopping.ch_nohop_timer_active == false) {
                            /*Timer not working*/
                            OS_CANCEL_TIMER(&acs->acs_ch_hopping.ch_cntwin_timer);
                            OS_SET_TIMER(&(acs->acs_ch_hopping.ch_cntwin_timer),
                                    SEC_TO_MSEC(acs->acs_ch_hopping.param.cnt_dur));
                        } else {
                            error = -EINVAL;
                        }

                    }
                    break;
                case IEEE80211_ACS_CH_HOP_NOISE_TH:
                    if((*val > NOISE_FLOOR_MIN) && (*val < NOISE_FLOOR_MAX)) {
                        acs->acs_ch_hopping.param.noise_thresh = *val;
                        retval = acs_noise_detection_param(ic,true,IEEE80211_NOISE_THRESHOLD,
                                &acs->acs_ch_hopping.param.noise_thresh);
                        if((acs->acs_ch_hopping.ch_nohop_timer_active == false)
                                && EOK == retval) {
                            /*Timer not working*/
                            OS_CANCEL_TIMER(&acs->acs_ch_hopping.ch_cntwin_timer);
                            OS_SET_TIMER(&(acs->acs_ch_hopping.ch_cntwin_timer),
                                    SEC_TO_MSEC(acs->acs_ch_hopping.param.cnt_dur));
                        }
                    } else {
                        error = -EINVAL;
                    }
                    break;
                case IEEE80211_ACS_CH_HOP_CNT_TH:
                    if(*val && *val <= MAX_COUNTER_THRESH) /*value is in percentage */
                        acs->acs_ch_hopping.param.cnt_thresh = *val;
                    else {
                        error = -EINVAL;
                    }
                    break;
                default:
                    acs_err("Invalid cmd (%d)", cmd);
                    error = -EINVAL;
                    break;
            }
            break;
        case false: /*GET */
            switch(cmd)
            {
                case IEEE80211_ACS_ENABLE_CH_HOP:
                    *val = ieee80211com_has_cap_ext(ic,IEEE80211_ACS_CHANNEL_HOPPING);
                    break;
                case IEEE80211_ACS_CH_HOP_LONG_DUR:
                    *val = acs->acs_ch_hopping.param.long_dur;
                    break;
                case IEEE80211_ACS_CH_HOP_NO_HOP_DUR:
                    *val = acs->acs_ch_hopping.param.nohop_dur;
                    break;
                case IEEE80211_ACS_CH_HOP_CNT_WIN_DUR:
                    *val = acs->acs_ch_hopping.param.cnt_dur;
                    break;
                case IEEE80211_ACS_CH_HOP_NOISE_TH:
                    *val = acs->acs_ch_hopping.param.noise_thresh;
                    break;

                case IEEE80211_ACS_CH_HOP_CNT_TH:
                    *val = acs->acs_ch_hopping.param.cnt_thresh;
                    break;

                default:
                    acs_err("Invalid cmd (%d)", cmd);
                    error = -EINVAL;
                    break;
            }
            break;
        default:
                acs_err("Invalid param (%d)", param);
                error = -EINVAL;
                break;
    }
#undef NOISE_FLOOR_MAX
#undef NOISE_FLOOR_MIN
#undef MAX_COUNTER_THRESH
    return error;
}

/*
 * ieee80211_check_and_execute_pending_acsreport:
 * Check if there are any pending ACS scans called while ACS was in progress
 * and execute them.
 *
 * @vap: Pointer to the VAP structure.
 *
 * Return:
 * Passed from ieee80211_autoselect_infra_bss_channel()
 */
int ieee80211_check_and_execute_pending_acsreport(wlan_if_t vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int32_t status = EOK;

    if(true == acs->acs_scan_req_param.acs_scan_report_pending) {
        status = ieee80211_autoselect_infra_bss_channel(vap, true /* is_scan_report */, NULL);
        if(status!= EOK) {
            acs_err("ACS is active. Cannot execute ACS report");
        }
    }
    acs->acs_scan_req_param.acs_scan_report_pending = false;
    return status;
}

/**
 * @brief to start acs scan report
 *
 * @param vap
 * @param set
 * @param cmd
 * @param val
 *
 * @return EOK in case of success
 */
int wlan_acs_start_scan_report(wlan_if_t vap, int set, int cmd, void *val)
{
/* XXX tunables */
/* values used in scan state machines  HW_DEFAULT_REPEAT_PROBE_REQUEST_INTVAL*/
#define IEEE80211_MIN_DWELL 50
#define IEEE80211_MAX_DWELL 10000 /* values used in scan state machines in msec */
#define CHANNEL_LOAD_REQUESTED 2
    struct ieee80211com *ic = vap->iv_ic;
    unsigned int status = EOK;
    ieee80211_acs_t acs = ic->ic_acs;
    acs_info(EXT, "Invoking ACS module for ACS report");
    if(set) {
        switch(cmd)
        {
            case IEEE80211_START_ACS_REPORT:
                if(*((u_int32_t *)val))
                {
                    status = ieee80211_autoselect_infra_bss_channel(vap, true /* is_scan_report */, NULL);

                    if(status!= EOK) {
                        /* Bypassing failure for direct attach hardware as for direct
                           attach we are taking channel load directly from hardware
                           for failure cases */
                        if( *((u_int32_t *)val) != CHANNEL_LOAD_REQUESTED) {
                            acs->acs_scan_req_param.acs_scan_report_pending = true;
                            acs_err("ACS is active - ACS report will be "
                                     "processed after ACS is done");
                        }
                    }
                    return status;
                }
                else
                    return -EINVAL;
                break;
            case IEEE80211_MIN_DWELL_ACS_REPORT:
                if( *((u_int32_t *)val) > IEEE80211_MIN_DWELL)
                {
                    acs->acs_scan_req_param.mindwell =  *((u_int32_t *)val);
                    return EOK;
                } else {
                    acs_err("Min dwell time (%d) must be greater than (%d)ms",
                             *((u_int32_t *)val), IEEE80211_MIN_DWELL);
                    return -EINVAL;
                }
                break;
            case IEEE80211_MAX_DWELL_ACS_REPORT:
                if( *((u_int32_t *)val) < IEEE80211_MAX_DWELL)
                {
                    if(acs->acs_scan_req_param.mindwell) {
                        if( *((u_int32_t *)val) < acs->acs_scan_req_param.mindwell) {
                            acs_err("Max dwell time (%d) less than min dwell time (%d)",
                                     *((u_int32_t *)val), acs->acs_scan_req_param.mindwell);
                            return -EINVAL;
                        }
                    }
                    acs->acs_scan_req_param.maxdwell =  *((u_int32_t *)val);
                    return EOK;
                } else {
                    acs_err("Max dwell time (%d) greater than (%d)",
                             *((u_int32_t *)val), IEEE80211_MAX_DWELL);
                    return -EINVAL;
                }
                break;
             case IEEE80211_MAX_SCAN_TIME_ACS_REPORT:
                if ( *((u_int32_t *)val) >= 0) {
                    acs->acs_scan_req_param.max_scan_time =  *((u_int32_t *)val);
                    return EOK;
                } else {
                    return -EINVAL;
                }
                break;
#if QCA_LTEU_SUPPORT
             case IEEE80211_SCAN_IDLE_TIME:
                if (*((u_int32_t *)val) >= 0) {
                    acs->acs_scan_req_param.idle_time = *((u_int32_t *)val);
                    return EOK;
                } else {
                    return -EINVAL;
                }
#endif
                break;
            case IEEE80211_SCAN_REST_TIME:
                if ( *((u_int32_t *)val) >= 0) {
                    acs->acs_scan_req_param.rest_time =  *((u_int32_t *)val);
                    return EOK;
                } else {
                    return -EINVAL;
                }
                break;
            case IEEE80211_SCAN_MODE:
                if ((*((u_int8_t *)val) == IEEE80211_SCAN_PASSIVE)
                        || (*((u_int8_t *)val) == IEEE80211_SCAN_ACTIVE)) {
                    acs->acs_scan_req_param.scan_mode = *((u_int8_t *)val);
                    return EOK;
                } else {
                    return -EINVAL;
                }
                break;
            default :
                acs_err("Invalid parameter (%d)", cmd);
                return -EINVAL;
        }
    } else /*get part */
    {
        switch(cmd) {
            case IEEE80211_START_ACS_REPORT:
                *((u_int32_t *)val) = (u_int32_t) acs->acs_scan_req_param.acs_scan_report_active;;
                break;
            case IEEE80211_MIN_DWELL_ACS_REPORT:
                *((u_int32_t *)val) = (u_int32_t) acs->acs_scan_req_param.mindwell;
                break;
            case IEEE80211_MAX_DWELL_ACS_REPORT:
                *((u_int32_t *)val) = (u_int32_t) acs->acs_scan_req_param.maxdwell;
                break;
            case IEEE80211_MAX_SCAN_TIME_ACS_REPORT:
                *((u_int32_t *)val) = (u_int32_t) acs->acs_scan_req_param.max_scan_time;
                break;
#if QCA_LTEU_SUPPORT
            case IEEE80211_SCAN_IDLE_TIME:
                *((u_int32_t *)val) = (u_int32_t)acs->acs_scan_req_param.idle_time;
                break;
#endif
            default :
                acs_err("Invalid parameter (%d)", cmd);
                return -EINVAL;
        }
        return EOK;
    }
#undef IEEE80211_MIN_DWELL
#undef IEEE80211_MAX_DWELL
#undef CHANNEL_LOAD_REQUESTED
}

/**
 * ieee80211_acs_scan_report:
 * Generates EACS report on request
 *
 * @ic      : Pointer to the ACS structure.
 * @acs_r   : Entry of debug stats.
 * @internal: to know whether report is requested by EACS or other module
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
static int ieee80211_acs_scan_report(struct ieee80211com *ic,
                                     struct ieee80211vap *vap,
                                     struct ieee80211_acs_dbg *acs_report,
                                     uint8_t internal)
{
    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_ath_channel *channel = NULL;
    u_int8_t i, ieee_chan, temp_chan;
    uint16_t acs_ch_idx = 0;
    u_int16_t nchans;
    ieee80211_chan_neighbor_list *acs_neighbor_list = NULL;
    int status = 0;
    struct ieee80211_acs_dbg *acs_r = NULL;
    uint8_t  acs_entry_id = 0;
    ACS_LIST_TYPE acs_type = 0;
    ieee80211_neighbor_info *neighbour_list;
    ieee80211_neighbor_info *neighbour_list_user;
    uint32_t neighbour_size;
    uint8_t nbss_allocated;
    int error;

    error = __xcopy_from_user(&acs_entry_id, &acs_report->entry_id, sizeof(acs_report->entry_id));
    if (error) {
        acs_err("Copy from user failed");
        return -EFAULT;
    }

    error = __xcopy_from_user(&acs_type, &acs_report->acs_type, sizeof(acs_report->acs_type));
    if (error) {
        acs_err("Copy from user failed");
        return -EFAULT;
    }

    acs_r = (struct ieee80211_acs_dbg *) qdf_mem_malloc(sizeof(*acs_r));
    if (!acs_r) {
        acs_err("Failed to allocate memory");
        return -ENOMEM;
    }

    if(ieee80211_acs_in_progress(acs) && !internal) {
        acs_err("ACS scan is in progress. Request for a report later");
        acs_r->nchans = 0;
        goto end;
    }

    if(acs->acs_run_status == ACS_RUN_INCOMPLETE) {
        acs_err("ACS run status is incomplete");
        acs_r->nchans = 0;
        goto end;
    }

    /* For ACS Ranking, we need only the channels which have been analysed when
     * selecting the best channel
     *
     * acs_nchans_scan is the channel count for the number of channel that
     * are scanned, while acs_nchans is the number of channels that are
     * eligible for ACS.
     *
     * The scanned channels is always less than or equal to the eligible
     * channels. Therefore, always use acs_nchans_scan unless it is 0.
     */
    nchans = (acs->acs_nchans_scan)?(acs->acs_nchans_scan):(acs->acs_nchans);

    i = acs_entry_id;
    if(i >= nchans) {
        acs_r->nchans = 0;
        status = -EINVAL;
        goto end;
    }

    acs_r->nchans = nchans;
    acs_r->acs_status = acs->acs_status;
    /* If scan channel list is not generated by ACS,
       acs_chans[i] have all channels */
    if(acs->acs_nchans_scan == 0) {
        channel = acs->acs_chans[i];
        ieee_chan = ieee80211_chan2ieee(acs->acs_ic, channel);
        acs_ch_idx = ieee80211_acs_get_chan_idx(acs, channel->ic_freq);
        acs_r->chan_freq = ieee80211_chan2freq(acs->acs_ic, channel);
        acs_r->chan_band = reg_wifi_band_to_wlan_band_id(
                wlan_reg_freq_to_band(channel->ic_freq));
    } else {
        acs_ch_idx = acs->acs_ch_idx[i];
        ieee_chan = ieee80211_acs_get_ieee_chan_from_ch_idx(acs_ch_idx);
        acs_r->chan_freq = ieee80211_acs_get_ieee_freq_from_ch_idx(acs, acs_ch_idx);
        acs_r->chan_band = reg_wifi_band_to_wlan_band_id(wlan_reg_freq_to_band(acs_r->chan_freq));
    }

    if (acs_type == ACS_CHAN_STATS) {
        acs_r->ieee_chan = ieee_chan;
        acs_r->chan_nbss = acs->acs_chan_nbss[acs_ch_idx];
        acs_r->chan_maxrssi = acs->acs_chan_maxsnr[acs_ch_idx];
        acs_r->chan_minrssi = acs->acs_chan_minsnr[acs_ch_idx];
        acs_r->noisefloor = acs->acs_noisefloor[acs_ch_idx];
        acs_r->channel_loading = 0;   /*Spectral dependency from ACS is removed*/
        acs_r->chan_load = acs->acs_chan_load[acs_ch_idx];
        acs_r->sec_chan = acs->acs_sec_chan[acs_ch_idx];
        acs_r->chan_80211_b_duration = acs->acs_80211_b_duration[acs_ch_idx];
        acs_r->chan_nbss_srp = acs->acs_srp_supported[acs_ch_idx];
        acs_r->chan_srp_load = acs->acs_srp_load[acs_ch_idx];
	if (acs->acs_chan_nbss_weighted[acs_ch_idx]) {
            acs_r->chan_availability = 10000/acs->acs_chan_nbss_weighted[acs_ch_idx];
	} else {
            acs_r->chan_availability = 100;
	}
        acs_r->chan_efficiency = acs->chan_efficiency[acs_ch_idx];
        acs_r->chan_nbss_near = acs->acs_chan_nbss_near[acs_ch_idx];
        acs_r->chan_nbss_mid = acs->acs_chan_nbss_mid[acs_ch_idx];
        acs_r->chan_nbss_far = acs->acs_chan_nbss_far[acs_ch_idx];
        acs_r->chan_nbss_eff = acs->acs_chan_nbss_weighted[acs_ch_idx];
        acs_r->chan_grade = acs->hw_chan_grade[acs_ch_idx];
        acs_r->chan_radar_noise = wlan_reg_is_nol_for_freq(acs->acs_ic->ic_pdev_obj,
                                            ieee80211_acs_get_ieee_freq_from_ch_idx(acs, acs_ch_idx));
        acs_r->chan_width = IEEE80211_CWM_WIDTH20; /* All scans take place in 20MHz slices */
        wlan_reg_freq_width_to_chan_op_class(ic->ic_pdev_obj,
                                          acs_r->chan_freq,
                                          BW_20_MHZ,
                                          true, BIT(BEHAV_NONE),
                                          &acs_r->op_class,
                                          &temp_chan);
        acs_r->chan_in_pool = (acs_r->chan_radar_noise) ? 0 : 1;

        /* For ACS channel Ranking, copy the rank and description */
        if (acs->acs_ranking) {
            acs_r->acs_rank.rank = acs->acs_rank[acs_ch_idx].rank;
            memcpy(acs_r->acs_rank.desc, acs->acs_rank[acs_ch_idx].desc, ACS_RANK_DESC_LEN);
        }

        if (copy_to_user(acs_report, acs_r, sizeof(*acs_r))) {
            acs_err("Copy to user failed");
        }
    }

    if (acs_type == ACS_CHAN_NF_STATS) {
        int chain = 0;

        acs_r->ieee_chan = ieee_chan;
        for (chain = 0; chain < HOST_MAX_CHAINS; chain++)
            acs_r->perchain_nf[chain] = acs->acs_perchain_nf[acs_ch_idx][chain];

        if (copy_to_user(acs_report, acs_r, sizeof(*acs_r))) {
            acs_err("Copy to user failed");
        }
    }

    if (acs_type == ACS_NEIGHBOUR_GET_LIST_COUNT || acs_type == ACS_NEIGHBOUR_GET_LIST) {

        acs_neighbor_list = (ieee80211_chan_neighbor_list *) qdf_mem_malloc(sizeof(ieee80211_chan_neighbor_list));
        if (!acs_neighbor_list) {
            acs_err("Failed to allocate memory for acs_neighbor_list");
            status = -ENOMEM;
            goto end;
        }

        OS_MEMZERO(acs_neighbor_list, sizeof(ieee80211_chan_neighbor_list));

        neighbour_list = (ieee80211_neighbor_info *) qdf_mem_malloc(sizeof(ieee80211_neighbor_info) * IEEE80211_MAX_NEIGHBOURS);
        if (!neighbour_list) {
            OS_FREE(acs_neighbor_list);
            acs_err("Failed to allocate memory for neighbor list");
            status = -ENOMEM;
            goto end;
        }

        OS_MEMZERO(neighbour_list, sizeof(ieee80211_neighbor_info) * IEEE80211_MAX_NEIGHBOURS);
        neighbour_size = sizeof(ieee80211_neighbor_info) * IEEE80211_MAX_NEIGHBOURS;

        acs_neighbor_list->acs = acs;
        acs_neighbor_list->freq = acs_r->chan_freq;
        acs_neighbor_list->neighbor_list = neighbour_list;
        acs_neighbor_list->neighbor_size = neighbour_size;

        ucfg_scan_db_iterate(wlan_vap_get_pdev(vap),
                ieee80211_get_chan_neighbor_list, (void *)acs_neighbor_list);

        if (copy_to_user(&acs_report->chan_nbss, &acs_neighbor_list->nbss, sizeof(acs_neighbor_list->nbss))) {
            acs_err("Copy to user failed");
            status = -EFAULT;
            goto clean_list;
        }

        if (copy_to_user(&acs_report->ieee_chan, &ieee_chan , sizeof(acs_report->ieee_chan))) {
            acs_err("Copy to user failed");
            status = -EFAULT;
            goto clean_list;
        }

        if (copy_to_user(&acs_report->chan_freq, &acs_neighbor_list->freq , sizeof(acs_neighbor_list->freq))) {
            acs_err("Copy to user failed");
            status = -EFAULT;
            goto clean_list;
        }

        if (acs_type == ACS_NEIGHBOUR_GET_LIST) {
            error = __xcopy_from_user(&nbss_allocated, &acs_report->chan_nbss, sizeof(acs_report->chan_nbss));
            if (error) {
                acs_err("Copy from user failed");
                status = -EFAULT;
                goto clean_list;
            }

            error = __xcopy_from_user(&neighbour_list_user, &acs_report->neighbor_list, sizeof(ieee80211_neighbor_info *));
            if (error) {
                acs_err("Copy from user failed");
                status = -EFAULT;
                goto clean_list;
            }

            if (copy_to_user(neighbour_list_user, acs_neighbor_list->neighbor_list, sizeof(ieee80211_neighbor_info) * nbss_allocated)) {
                acs_err("Copy to user failed");
                status = -EFAULT;
                goto clean_list;
            }
        }

clean_list:
        OS_FREE(acs_neighbor_list);
        OS_FREE(neighbour_list);
    }

end:
    qdf_mem_free(acs_r);
    return status;
}

/*
 * ieee80211_acs_scan_report_internal:
 * Displays ACS statistics.
 *
 * @ic: Pointer to the ic structure.
 */
static void ieee80211_acs_scan_report_internal(struct ieee80211com *ic)
{
    struct ieee80211_acs_dbg *acs_dbg;
    ieee80211_acs_t acs = ic->ic_acs;
    u_int8_t i;

    acs_dbg = (struct ieee80211_acs_dbg *) OS_MALLOC(acs->acs_osdev,
                        sizeof(struct ieee80211_acs_dbg), 0);

    if (acs_dbg) {
        OS_MEMZERO(acs_dbg, sizeof(struct ieee80211_acs_dbg));
    }
    else {
        acs_err("Failed to allocate memory for acs_dbg");
        return;
    }

    /* output the current configuration */
    i = 0;
    do {
        acs_dbg->entry_id = i;
        acs_dbg->acs_type = ACS_CHAN_STATS;

        ieee80211_acs_scan_report(ic, acs->acs_vap, acs_dbg, 1);
        if((acs_dbg->nchans) && (i == 0)) {
            acs_nofl_info(EXT, "******** ACS report ******** ");
            acs_nofl_info(EXT, " Channel | BSS  | minrssi | maxrssi | NF | Ch load | spect load | sec_chan | SR bss | SR load | Ch Avil | Chan eff | NearBSS | Med BSS | Far BSS | Eff BSS | chan grade");
            acs_nofl_info(EXT, "----------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        } else if(acs_dbg->nchans == 0) {
            acs_err("Failed to print ACS scan report");
            break;
        }
        /*To make sure we are not getting more than 100 %*/
        if(acs_dbg->chan_load  > 100)
            acs_dbg->chan_load = 100;

        acs_nofl_info(EXT, " %4d(%3d) %4d     %4d      %4d   %4d    %4d        %4d       %4d     %4d      %4d      %4u      %4u      %4u      %4u      %4u      %4u      %4u   ",
                acs_dbg->chan_freq,
                acs_dbg->ieee_chan,
                acs_dbg->chan_nbss,
                acs_dbg->chan_minrssi,
                acs_dbg->chan_maxrssi,
                acs_dbg->noisefloor,
                acs_dbg->chan_load,
                acs_dbg->channel_loading,
                acs_dbg->sec_chan,
                acs_dbg->chan_nbss_srp,
                acs_dbg->chan_srp_load,
                acs_dbg->chan_availability,
                acs_dbg->chan_efficiency,
                acs_dbg->chan_nbss_near,
                acs_dbg->chan_nbss_mid,
                acs_dbg->chan_nbss_far,
                acs_dbg->chan_nbss_eff,
                acs_dbg->chan_grade
                );

       i++;
    } while(i < acs_dbg->nchans);
    OS_FREE(acs_dbg);

}

/*
 * wlan_acs_scan_report:
 * Invoke EACS report handler, it acts as inteface for other modules
 *
 * @vaphandle: Pointer to the VAP structure.
 * @acs_rp   : Pointer to the ACS debug report structure.
 *
 * Return:
 * Passed through from ieee80211_acs_scan_report
 */
int wlan_acs_scan_report(wlan_if_t vaphandle,void *acs_rp)
{
    struct ieee80211_acs_dbg *acs_r = (struct ieee80211_acs_dbg *)acs_rp;
    return ieee80211_acs_scan_report(vaphandle->iv_ic, vaphandle, acs_r, 0);
}

/*
 * wlan_acs_block_channel_list:
 * Populate the ACS blocked channel list with a given channel list.
 *
 * @freq : List of frequencies to block.
 * @nfreq: Number of frequencies in the given channel list.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
int wlan_acs_block_channel_list(wlan_if_t vap,u_int16_t *freq,u_int8_t nfreq)
{
#define FLUSH_LIST 0
    int i = 0;
    acs_bchan_list_t *bchan = NULL;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;

    if(NULL == freq)
        return -ENOSPC;

    bchan = &(acs->acs_bchan_list);

    if(FLUSH_LIST == freq[0])
    {
        OS_MEMZERO(&(bchan->uchan[0]),bchan->uchan_cnt);
        bchan->uchan_cnt = 0;

        /* Re-populating the CFG blocked channels (if any) since these channels
         * are not intended to be flushed unless directly removed from CFG  */
        if (ic->ic_pri20_cfg_blockchanlist.n_freq) {
            wlan_acs_block_channel_list(vap,
                                        ic->ic_pri20_cfg_blockchanlist.freq,
                                        ic->ic_pri20_cfg_blockchanlist.n_freq);
        }

        return 0;
    }
    else {
        while(i < nfreq) {
            if (acs_is_channel_blocked(acs, freq[i])) {
                /* Channel is already present in the list */
                acs_info(EXT, "Freq (%4uMHz) is already in the list",
                         freq[i]);
                i++;
                continue;
            }

            bchan->uchan[bchan->uchan_cnt] = freq[i];
            bchan->uchan_cnt++;
            i++;
        }
    }

    bchan->uchan_cnt %= IEEE80211_CHAN_MAX;
    return 0;
#undef FLUSH_LIST
}

/*
 * wlan_acs_channel_allowed:
 * Check if a given channel is allowed (keeping in mind the phymode).
 *
 * @vap : Pointer to the VAP structure.
 * @c   : Pointer to the given channel.
 * @mode: Value of the given phymode.
 *
 * Return:
 * NULL    : Invalid channel (or) Channel is blocked.
 * Non-NULL: Channel is allowed.
 */
#if ATH_CHANNEL_BLOCKING
struct ieee80211_ath_channel *
wlan_acs_channel_allowed(wlan_if_t vap, struct ieee80211_ath_channel *c, enum ieee80211_phymode mode)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_acs_t acs = ic->ic_acs;
    struct ieee80211_ath_channel *channel;
    int i, j, n_modes, extchan, blocked;
    enum ieee80211_phymode modes[IEEE80211_MODE_MAX];
    struct regulatory_channel *cur_chan_list;

    if (!(acs->acs_block_mode & ACS_BLOCK_MANUAL))
        return c;

    /* real phymode */
    if (ieee80211_is_phymode_auto(mode)) {
        modes[0] = IEEE80211_MODE_11AXA_HE160;
        modes[1] = IEEE80211_MODE_11AXA_HE80;
        modes[2] = IEEE80211_MODE_11AXA_HE40PLUS;
        modes[3] = IEEE80211_MODE_11AXA_HE40MINUS;
        modes[4] = IEEE80211_MODE_11AXA_HE20;
        modes[5] = IEEE80211_MODE_11AC_VHT160;
        modes[6] = IEEE80211_MODE_11AC_VHT80;
        modes[7] = IEEE80211_MODE_11AC_VHT40PLUS;
        modes[8] = IEEE80211_MODE_11AC_VHT40MINUS;
        modes[9] = IEEE80211_MODE_11AC_VHT20;
        modes[10] = IEEE80211_MODE_11AXG_HE40PLUS;
        modes[11] = IEEE80211_MODE_11AXG_HE40MINUS;
        modes[13] = IEEE80211_MODE_11NG_HT40PLUS;
        modes[14] = IEEE80211_MODE_11NG_HT40MINUS;
        modes[15] = IEEE80211_MODE_11NA_HT40PLUS;
        modes[16] = IEEE80211_MODE_11NA_HT40MINUS;
        modes[12] = IEEE80211_MODE_11AXG_HE20;
        modes[17] = IEEE80211_MODE_11NG_HT20;
        modes[18] = IEEE80211_MODE_11NA_HT20;
        modes[19] = IEEE80211_MODE_11G;
        modes[20] = IEEE80211_MODE_11A;
        modes[21] = IEEE80211_MODE_11B;
        n_modes = 22;

    } else if (ieee80211_is_phymode_11ng_ht40(mode)) {
        modes[0] = IEEE80211_MODE_11NG_HT40PLUS;
        modes[1] = IEEE80211_MODE_11NG_HT40MINUS;
        n_modes = 2;
    } else if (ieee80211_is_phymode_11na_ht40(mode)) {
        modes[0] = IEEE80211_MODE_11NA_HT40PLUS;
        modes[1] = IEEE80211_MODE_11NA_HT40MINUS;
        n_modes = 2;
    } else if (ieee80211_is_phymode_11ac_vht40(mode)) {
        modes[0] = IEEE80211_MODE_11AC_VHT40PLUS;
        modes[1] = IEEE80211_MODE_11AC_VHT40MINUS;
        n_modes = 2;
    } else if (ieee80211_is_phymode_11axg_he40(mode)) {
        modes[0] = IEEE80211_MODE_11AXG_HE40PLUS;
        modes[1] = IEEE80211_MODE_11AXG_HE40MINUS;
        n_modes = 2;
    } else if (ieee80211_is_phymode_11axa_he40(mode)) {
        modes[0] = IEEE80211_MODE_11AXA_HE40PLUS;
        modes[1] = IEEE80211_MODE_11AXA_HE40MINUS;
        n_modes = 2;
    } else {
        modes[0] = mode;
        n_modes = 1;
    }

    cur_chan_list = qdf_mem_malloc(NUM_CHANNELS * sizeof(*cur_chan_list));
    if (!cur_chan_list)
        return NULL;

    if (wlan_reg_get_current_chan_list(ic->ic_pdev_obj, cur_chan_list) != QDF_STATUS_SUCCESS) {
        qdf_err("Failed to get cur_chan list");
        qdf_mem_free(cur_chan_list);
        return NULL;
    }

    for (j = 0; j < n_modes; j++) {
        blocked = 0;
        for (i = 0; i < NUM_CHANNELS; i++) {
            uint16_t chan_freq = cur_chan_list[i].center_freq;
            uint16_t ext_chan_freq;
            int n_subchans = 0;
            qdf_freq_t subchannels[IEE80211_MAX_20M_SUB_CH];

            if (cur_chan_list[i].chan_flags & REGULATORY_CHAN_DISABLED)
                continue;

            if (!ieee80211_is_phymode_supported_by_channel(ic, chan_freq,
                                                           modes[j])) {
                acs_info(BLOCK, "Channel(%4uMHz) does not support phymode(%2d)",
                         chan_freq, modes[j]);
                continue; /* next channel */
            }

            if (chan_freq != ieee80211_chan2freq(ic, c)) {
                acs_info(BLOCK, "Channel (%4uMHz) with mode (%2d) is not equal to "
                         "channel (%2d). Skipping",
                         chan_freq, modes[j], ieee80211_chan2freq(ic, c));
                continue; /* next channel */
            }

            /* channel is blocked as per user setting */
            if (acs_is_channel_blocked(acs, chan_freq)) {
                acs_info(BLOCK, "Channel (%4uMHz) is blocked for phymode (%2d)",
                         chan_freq, modes[j]);
                blocked = 1;
                break; /* next phymode */
            }

            n_subchans = ieee80211_get_subchannels(ic, chan_freq, modes[j],
                                                   subchannels);

            for (extchan = 0; extchan < n_subchans; extchan++) {
                /* extension channel (in NAHT40/ACVHT40/ACVHT80 mode) is blocked as per user setting */
                if (acs->acs_block_mode & ACS_BLOCK_EXTENSION) {
                    ext_chan_freq = subchannels[extchan];
                    if (acs_is_channel_blocked(acs, ext_chan_freq)) {
                        acs_info(BLOCK, "Channel (%4uMHz) cannot be used - "
                                 "ext channel (%3d) is blocked for phymode (%2d)",
                                 chan_freq, ext_chan_freq, modes[j]);
                        blocked = 1;
                        break;
                    }
                }
            }

            if (blocked)
                break; /* next phymode */

            /*
             * Find the channel of ieee80211_ath_channel type for the current
             * channel mode combination.
             */
            channel = ieee80211_find_dot11_channel(ic, chan_freq, 0 , modes[j]);
            if (!channel)
                continue;

            /* in 2.4GHz band checking channels overlapping with primary,
             * or if required with secondary too (NGHT40 mode) */
            if ((acs->acs_block_mode & ACS_BLOCK_EXTENSION) &&  IEEE80211_IS_CHAN_2GHZ(channel)) {
                struct ieee80211_ath_channel *ext_chan;
                int start = chan_freq - 15, end = chan_freq + 15, f;
                if (IEEE80211_IS_CHAN_11NG_HT40PLUS(channel) ||
                    IEEE80211_IS_CHAN_11AXG_HE40PLUS(channel))
                    end = chan_freq + 35;
                if (IEEE80211_IS_CHAN_11NG_HT40MINUS(channel) ||
                    IEEE80211_IS_CHAN_11AXG_HE40MINUS(channel))
                    start = chan_freq - 35;
                for (f = start; f <= end; f += 5) {
                    ext_chan = ic->ic_find_channel(ic, f, 0, IEEE80211_CHAN_B);
                    if (ext_chan) {
                        ext_chan_freq = ieee80211_chan2freq(ic, ext_chan);
                        if (acs_is_channel_blocked(acs, ext_chan_freq)) {
                            acs_info(BLOCK, "Channel (%4uMHz) cannot be used - "
                                     "ext/overlapping channel (%4uMHz) is blocked "
                                     "for phymode (%2d)",
                                     chan_freq, ext_chan_freq, modes[j]);
                            blocked = 1;
                            break;
                        }
                    }
                }
            }

            if (blocked)
                break; /* next phymode */

            /* channel is allowed in this phymode */
            if (c != channel) {
                acs_info(BLOCK, "Replacing channel (%3uMHz) with phymode (%2d) "
                         "with channel (%3uMHz) with phymode (%2d)",
                         ieee80211_chan2freq(ic, c), ieee80211_chan2mode(c),
                         ieee80211_chan2freq(ic, channel), ieee80211_chan2mode(channel));
            }
            qdf_mem_free(cur_chan_list);
            return channel;
        }
    }

    qdf_mem_free(cur_chan_list);
    return NULL;
}
#endif

/*
 * ieee80211_acs_api_prepare:
 * Prepare ACS for use by external callers (eg. CBS)
 *
 * @vap      : Pointer to the VAP structure.
 * @acs      : Pointer to the ACS structure.
 * @mode     : Value of the given phymode.
 * @chan_list: Pointer to the channel list to populate.
 * @nchans   : Value of the number of channels in chan_list.
 *
 * Return:
 *     0: Success.
 * Non-0: Failure.
 */
int ieee80211_acs_api_prepare(struct ieee80211vap *vap, ieee80211_acs_t acs, enum ieee80211_phymode mode,
                              uint32_t *chan_list, uint32_t *nchans)
{
    struct ieee80211com *ic = acs->acs_ic;
    qdf_freq_t *chans;
    u_int8_t i;
#if ATH_SUPPORT_VOW_DCS
    uint16_t acs_ch_idx = 0;
#endif
    uint32_t bandmask = BIT(REG_BAND_2G) | BIT(REG_BAND_5G) | BIT(REG_BAND_6G);

    *nchans = 0;

    qdf_spin_lock_bh(&acs->acs_lock);
    if (OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),false,true)) {
        qdf_spin_unlock_bh(&acs->acs_lock);
        /* Just wait for acs done */
        return -EINPROGRESS;
    }
    qdf_spin_unlock_bh(&acs->acs_lock);

    acs->acs_vap = vap;
    ieee80211_acs_construct_chan_list(acs, mode);
    if (acs->acs_nchans == 0) {
        acs_err("Cannot construct available channel list");
        return -EINVAL;
    }

#if ATH_SUPPORT_VOW_DCS
    /* update dcs information */
    if (ic->cw_inter_found && ic->ic_curchan) {
        acs_ch_idx = ieee80211_acs_get_chan_idx(acs, ic->ic_curchan->ic_freq);
        acs->acs_intr_status[acs_ch_idx] += 1;
        acs->acs_intr_ts[acs_ch_idx] =
            (u_int32_t) CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());
    }
#endif

    if (acs->acs_uchan_list.uchan_cnt) {
        *nchans = acs->acs_uchan_list.uchan_cnt;

        for (i = 0; i < *nchans; i++) {
            chan_list[i] = acs->acs_uchan_list.uchan[i];
        }
    }
    else {
        chans = qdf_mem_malloc(sizeof(qdf_freq_t) * IEEE80211_CHAN_MAX);
        if (chans == NULL)
            return -ENOMEM;

        *nchans = wlan_get_channel_list(ic, bandmask, chans,
                                        IEEE80211_CHAN_MAX);

        if (*nchans == 0) {
            acs_err("No channels present in list. Returning");
            qdf_mem_free(chans);
            return -EINVAL;
        }

        for (i = 0; i < *nchans; i++) {
            if (!chans[i]) {
                acs_err("NULL chans[%3u]. Returning", i);
                qdf_mem_free(chans);
                return -EINVAL;
            }

            chan_list[i] = chans[i];
            acs->acs_ch_idx[i] = ieee80211_acs_get_chan_idx(acs, chans[i]);
        }

        acs->acs_nchans_scan = *nchans;
        qdf_mem_free(chans);
    }
    return EOK;
}

/*
 * ieee80211_acs_api_rank:
 * Rank the channels based on the current ACS parameters.
 *
 * @acs: Pointer to the ACS structure.
 * @top: Value of given number of channels to rank (from the top).
 *
 * Return:
 *     0: Success.
 * Non-0: Failure.
 */
int ieee80211_acs_api_rank(ieee80211_acs_t acs, u_int8_t top)
{
    ieee80211_acs_update_sec_chan_rssi(acs);
    ieee80211_acs_rank_channels(acs, top);
    return EOK;
}

/*
 * ieee80211_acs_api_complete:
 * Mark ACS as complete atomically.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
int ieee80211_acs_api_complete(ieee80211_acs_t acs)
{
    if (!OS_ATOMIC_CMPXCHG(&(acs->acs_in_progress),true,false))
    {
        acs_info(SCAN, "Wrong locking in ACS, investigate");
        atomic_set(&(acs->acs_in_progress),false);
    }
    acs->acs_run_status = ACS_RUN_COMPLETED;
    return EOK;
}

/*
 * ieee80211_acs_api_flush:
 * Flush all the ACS data.
 *
 * @vap: Pointer to the VAP structure.
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
int ieee80211_acs_api_flush(struct ieee80211vap *vap)
{
    ieee80211_acs_t acs = vap->iv_ic->ic_acs;
    struct wlan_objmgr_vdev *vdev = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    vdev = vap->vdev_obj;
    pdev = wlan_vdev_get_pdev(vdev);

    /*Flush scan table before starting scan */
    ucfg_scan_flush_results(pdev, NULL);
    ieee80211_acs_flush_olddata(acs);
    acs->acs_startscantime = OS_GET_TIMESTAMP();

    return EOK;
}

/*
 * ieee80211_acs_api_update:
 * Update the ACS structures with channel stats from the latest scan event for
 * a given channel.
 *
 * @ic  : Pointer to the ic structure.
 * @type: Type of scan event stats to update.
 * @freq: Frequency of the given channel (MHz).
 *
 * Return:
 *     0: Success
 * Non-0: Failure
 */
int ieee80211_acs_api_update(struct ieee80211com *ic, enum scan_event_type type, uint32_t freq)
{
    ieee80211_acs_retrieve_chan_info(ic, type, freq);

    return EOK;
}

/*
 * ieee80211_acs_api_get_ranked_chan:
 * Get the channel frequency for a given ranking in the channel list.
 *
 * @acs : Pointer to the ACS structure.
 * @rank: Value of the given rank.
 *
 * Return:
 *     0: Invalid channel frequency.
 * Non-0: Valid channel frequency for a given rank.
 */
uint16_t ieee80211_acs_api_get_ranked_chan(ieee80211_acs_t acs, int rank)
{
    int i;
    uint16_t chan_freq;

    for (i = 0; i < IEEE80211_ACS_CHAN_MAX; i++) {
        if (acs->acs_rank[i].rank == rank)
            break;
    }
    if (i == IEEE80211_ACS_CHAN_MAX) {
        return 0;
    }

    chan_freq = ieee80211_acs_get_ieee_freq_from_ch_idx(acs, i);
    acs_info(EXT, "Found channel (%4uMHz) with rank (%3d)",
             chan_freq, rank);

    return chan_freq;
}

/*
 * ieee80211_acs_api_resttime:
 * Get the rest time for the ACS scan request.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 * Value of the rest time (ms).
 */
int ieee80211_acs_api_resttime(struct ieee80211_acs *acs)
{
    return acs->acs_scan_req_param.rest_time;
}

/*
 * ieee80211_acs_api_dwelltime:
 * Get the minimum dwell time for the ACS scan request.
 *
 * @acs: Pointer to the ACS structure.
 *
 * Return:
 * Value of the minimum dwell time (ms).
 */
int ieee80211_acs_api_dwelltime(struct ieee80211_acs *acs)
{
    return acs->acs_scan_req_param.mindwell;
}
