/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
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

#include <ol_if_athvar.h>
#include <init_deinit_lmac.h>
#include <cdp_txrx_ctrl.h>
#include <ieee80211_ucfg.h>
#include <ieee80211_channel.h>
#include <wlan_reg_channel_api.h>

#if UMAC_SUPPORT_CFG80211
#include <ieee80211_cfg80211.h>
#endif /* UMAC_SUPPORT_CFG80211 */

void ol_ath_reset_dcs_params(struct ol_ath_softc_net80211 *scn)
{
	if (!scn) {
		qdf_err("scn null");
		return;
	}

	scn->scn_dcs.dcs_enable          = 0;
	scn->scn_dcs.coch_intr_thresh    = DCS_COCH_INTR_THRESHOLD ;
	scn->scn_dcs.tx_err_thresh       = DCS_TXERR_THRESHOLD;
	scn->scn_dcs.phy_err_threshold   = DCS_PHYERR_THRESHOLD ;
	scn->scn_dcs.user_max_cu         = DCS_USER_MAX_CU;
	scn->scn_dcs.dcs_debug           = DCS_DEBUG_DISABLE;
	scn->scn_dcs.dcs_re_enable_time  = DCS_ENABLE_TIME;
	scn->scn_dcs.dcs_trigger_ts[0]   = 0;
	scn->scn_dcs.dcs_trigger_ts[1]   = 0;
	scn->scn_dcs.dcs_trigger_ts[2]   = 0;
	scn->scn_dcs.dcs_trigger_count   = 0;
	scn->scn_dcs.is_enable_timer_set = 0;
	qdf_timer_stop(&(scn->scn_dcs.dcs_enable_timer));

	/* Enable AWGN interference management by default */
	ol_ath_ctrl_dcsawgn(&scn->sc_ic, &scn->scn_dcs.dcs_enable, true);
}

#if ATH_SUPPORT_VOW_DCS
/**
 * dcs_enable_wlan_im() - enable dcs wlan im functionality
 * @ic: ic handle
 *
 * Return: none
 */
static void dcs_enable_wlan_im(struct ieee80211com *ic)
{
	/* Enable DCS WLAN_IM functionality */
	ic->ic_enable_dcsim(ic);
}

/**
 * dcs_disable_wlan_im() - disable dcs wlan im functionality
 * @ic: ic handle
 *
 * Return: none
 */
static void dcs_disable_wlan_im(struct ieee80211com *ic)
{
	/* Disable DCS WLAN_IM functionality */
	ic->ic_disable_dcsim(ic);
}
#else
static void dcs_enable_wlan_im(struct ieee80211com *ic)
{
}

static void dcs_disable_wlan_im(struct ieee80211com *ic)
{
}
#endif /* ATH_SUPPORT_VOW_DCS */

void dcs_enable_timer_fn(void *arg)
{
	struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)arg;
	struct ieee80211com *ic = NULL;

	if (!scn) {
		qdf_err("scn null");
		return;
	}

	ic = &scn->sc_ic;
	if (!ic) {
		qdf_err("ic null");
		return;
	}

	qdf_info("In DCS timer");
	scn->scn_dcs.is_enable_timer_set = 0;
	scn->scn_dcs.dcs_trigger_count = 0;
	/* Enable DCS WLAN_IM functionality */
	dcs_enable_wlan_im(ic);
	/* Deleting DCS enable timer and resetting timer flag to 0
	 * once DCS WLAN_IM is enabled
	 */
	qdf_timer_stop(&scn->scn_dcs.dcs_enable_timer);
}

void ol_ath_dcs_attach(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

	if (!scn) {
		return;
	}

	/* Enable AWGN interference detection by default */
	scn->scn_dcs.dcs_enable                   = 0;
	OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable);
	scn->scn_dcs.phy_err_penalty              = DCS_PHYERR_PENALTY;
	scn->scn_dcs.phy_err_threshold            = DCS_PHYERR_THRESHOLD ;
	scn->scn_dcs.radar_err_threshold          = DCS_RADARERR_THRESHOLD;
	scn->scn_dcs.coch_intr_thresh             = DCS_COCH_INTR_THRESHOLD;
	scn->scn_dcs.tx_err_thresh                = DCS_TXERR_THRESHOLD;
	scn->scn_dcs.user_max_cu                  = DCS_USER_MAX_CU;
	scn->scn_dcs.intr_detection_threshold     = DCS_INTR_DETECTION_THR;
	scn->scn_dcs.intr_detection_window        = DCS_SAMPLE_SIZE;
	scn->scn_dcs.scn_dcs_im_stats.im_intr_cnt = 0;
	scn->scn_dcs.scn_dcs_im_stats.im_samp_cnt = 0;
	scn->scn_dcs.dcs_debug                    = DCS_DEBUG_DISABLE;
	scn->scn_dcs.dcs_re_enable_time           = DCS_ENABLE_TIME;
	scn->scn_dcs.dcs_trigger_ts[0]            = 0;
	scn->scn_dcs.dcs_trigger_ts[1]            = 0;
	scn->scn_dcs.dcs_trigger_ts[2]            = 0;
	scn->scn_dcs.dcs_trigger_count            = 0;
	scn->scn_dcs.is_enable_timer_set          = 0;
	scn->scn_dcs.dcs_wideband_policy          = DCS_WIDEBAND_POLICY_INTRABAND;
	scn->scn_dcs.dcs_random_chan_en           = true;
	scn->scn_dcs.dcs_csa_tbtt                 = DCS_CSA_TBTT_DEFAULT;

	qdf_timer_init(ic->ic_osdev, &(scn->scn_dcs.dcs_enable_timer),
		       dcs_enable_timer_fn,
		       (void *)(scn), QDF_TIMER_TYPE_WAKE_APPS);

	/* Enable AWGN interference management by default */
	ol_ath_ctrl_dcsawgn(&scn->sc_ic, &scn->scn_dcs.dcs_enable, true);
	return;
}

void ol_ath_dcs_dettach(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

	if (!scn)
		return;

	qdf_timer_free(&(scn->scn_dcs.dcs_enable_timer));

	return;
}

extern void target_if_spectral_send_intf_found_msg(struct wlan_objmgr_pdev *dev,
						   uint16_t cw_int,
						   uint32_t dcs_enabled);

#if UMAC_SUPPORT_CFG80211
/**
 * ol_ath_req_ext_dcs_trigger_cfg80211 - Request sending of DCS trigger to
 * external handler using cfg80211
 * @scn: Pointer to net80211 softc object
 * @interference_type: Interference type
 *
 * Return: 0 on success, negative error number on failure
 */
static
int ol_ath_req_ext_dcs_trigger_cfg80211(struct ol_ath_softc_net80211 *scn,
					uint32_t interference_type)
{
	struct ieee80211com *ic = NULL;
	struct ieee80211vap *vap = NULL;

	if (!scn) {
		qdf_err("scn is NULL");
		return -EINVAL;
	}

	ic = &scn->sc_ic;

	if (!OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) {
		qdf_err("DCS is not enabled. Ext DCS trigger not applicable");
		return -EINVAL;
	}

	qdf_info("Requesting DCS trigger to external handler using cfg80211");
	qdf_info("DCS flag = %hhu", OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable));

	/* We trigger external DCS on the first active HostAP VAP. Even if we
	 * encounter an error in trying to trigger external DCS on any of the
	 * VAPs that fulfill these criteria, we try our best to execute the
	 * trigger by trying all the VAPs until we are successful.
	 */
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
			if ((wlan_vdev_mlme_is_active(vap->vdev_obj) ==
			    QDF_STATUS_SUCCESS) &&
			    !wlan_cfg80211_do_dcs_trigger(vap,
			    interference_type)) {
				return 0;
			}
		}
	}

	return -EINVAL;
}
#endif /* UMAC_SUPPORT_CFG80211 */

#if WLAN_SPECTRAL_ENABLE
/**
 * ol_ath_req_ext_dcs_trigger_custom - Request sending of DCS trigger to
 * external handler using custom mechanism
 * @scn: Pointer to net80211 softc object
 * @interference_type: Interference type
 *
 * Request sending of DCS trigger to external handler using custom Spectral
 * based interference notification mechanism. This is for legacy support
 * purposes. This may be deprecated in the future
 *
 * Return: 0 on success, negative error number on failure
 */
static int ol_ath_req_ext_dcs_trigger_custom(struct ol_ath_softc_net80211 *scn,
					     uint32_t interference_type)
{
	struct ieee80211com *ic = NULL;
	uint32_t dcs_enabled;

	if (!scn) {
		qdf_err("scn is NULL");
		return -EINVAL;
	}

	ic = &scn->sc_ic;

	if (!OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) {
		qdf_err("DCS is not enabled. Ext DCS trigger not applicable");
		return -EINVAL;
	}

	qdf_info("Requesting DCS trig to ext handler using custom mechanism");
	qdf_info("DCS flag = %hhu", OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable));

	spin_lock(&ic->ic_lock);

	dcs_enabled = OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable);

	if (interference_type == CAP_DCS_CWIM) {
		target_if_spectral_send_intf_found_msg(ic->ic_pdev_obj, 1,
						       dcs_enabled);
	} else if (interference_type == CAP_DCS_WLANIM) {
		target_if_spectral_send_intf_found_msg(ic->ic_pdev_obj, 0,
						       dcs_enabled);
	} else if (interference_type == CAP_DCS_AWGNIM) {
		target_if_spectral_send_intf_found_msg(ic->ic_pdev_obj, 1,
						       dcs_enabled);
        }

	spin_unlock(&ic->ic_lock);

	return 0;
}
#else /* WLAN_SPECTRAL_ENABLE */
static int ol_ath_req_ext_dcs_trigger_custom(struct ol_ath_softc_net80211 *scn,
					     uint32_t interference_type)
{
	return -ENOSYS;
}
#endif /* WLAN_SPECTRAL_ENABLE */

#if UMAC_SUPPORT_CFG80211
int ol_ath_req_ext_dcs_trigger(struct ol_ath_softc_net80211 *scn,
			       uint32_t interference_type)
{
	if (!scn) {
		qdf_err("scn is NULL");
		return -EINVAL;
	}

	if (scn->sc_ic.ic_cfg80211_config)
		return ol_ath_req_ext_dcs_trigger_cfg80211(scn,
							   interference_type);
	else
		return ol_ath_req_ext_dcs_trigger_custom(scn,
							 interference_type);
}
#else
int ol_ath_req_ext_dcs_trigger(struct ol_ath_softc_net80211 *scn,
			       uint32_t interference_type)
{
	if (!scn) {
		qdf_err("scn is NULL");
		return -EINVAL;
	}

	return ol_ath_req_ext_dcs_trigger_custom(scn, interference_type);
}
#endif /* UMAC_SUPPORT_CFG80211 */

void wlan_dcs_im_copy_stats(wmi_host_dcs_im_tgt_stats_t *prev_stats,
			    wmi_host_dcs_im_tgt_stats_t *curr_stats)
{
	/* right now no other actions are required beyond memcopy,
	 * if required the rest of the code would follow
	 */
	qdf_mem_copy(prev_stats, curr_stats,
		     sizeof(wmi_host_dcs_im_tgt_stats_t));
}

void wlan_dcs_im_print_stats(wmi_host_dcs_im_tgt_stats_t *prev_stats,
			     wmi_host_dcs_im_tgt_stats_t *curr_stats)
{
	/* debug, dump all received stats first */
	qdf_info("tgt_curr/tsf,%u", curr_stats->reg_tsf32);
	qdf_info(",tgt_curr/last_ack_rssi,%u", curr_stats->last_ack_rssi);
	qdf_info(",tgt_curr/tx_waste_time,%u", curr_stats->tx_waste_time);
	qdf_info(",tgt_curr/dcs_rx_time,%u", curr_stats->rx_time);
	qdf_info(",tgt_curr/listen_time,%u", curr_stats->mib_stats.listen_time);
	qdf_info(",tgt_curr/tx_frame_cnt,%u",
		 curr_stats->mib_stats.reg_tx_frame_cnt);
	qdf_info(",tgt_curr/rx_frame_cnt,%u",
		 curr_stats->mib_stats.reg_rx_frame_cnt);
	qdf_info(",tgt_curr/rxclr_cnt,%u", curr_stats->mib_stats.reg_rxclr_cnt);
	qdf_info(",tgt_curr/reg_cycle_cnt,%u",
		 curr_stats->mib_stats.reg_cycle_cnt);
	qdf_info(",tgt_curr/rxclr_ext_cnt,%u",
		 curr_stats->mib_stats.reg_rxclr_ext_cnt);
	qdf_info(",tgt_curr/ofdm_phyerr_cnt,%u",
		 curr_stats->mib_stats.reg_ofdm_phyerr_cnt);
	qdf_info(",tgt_curr/cck_phyerr_cnt,%u",
		 curr_stats->mib_stats.reg_cck_phyerr_cnt);

	qdf_info("tgt_prev/tsf,%u", prev_stats->reg_tsf32);
	qdf_info(",tgt_prev/last_ack_rssi,%u", prev_stats->last_ack_rssi);
	qdf_info(",tgt_prev/tx_waste_time,%u", prev_stats->tx_waste_time);
	qdf_info(",tgt_prev/rx_time,%u", prev_stats->rx_time);
	qdf_info(",tgt_prev/listen_time,%u", prev_stats->mib_stats.listen_time);
	qdf_info(",tgt_prev/tx_frame_cnt,%u",
		 prev_stats->mib_stats.reg_tx_frame_cnt);
	qdf_info(",tgt_prev/rx_frame_cnt,%u",
		 prev_stats->mib_stats.reg_rx_frame_cnt);
	qdf_info(",tgt_prev/rxclr_cnt,%u", prev_stats->mib_stats.reg_rxclr_cnt);
	qdf_info(",tgt_prev/reg_cycle_cnt,%u",
		 prev_stats->mib_stats.reg_cycle_cnt);
	qdf_info(",tgt_prev/rxclr_ext_cnt,%u",
		 prev_stats->mib_stats.reg_rxclr_ext_cnt);
	qdf_info(",tgt_prev/ofdm_phyerr_cnt,%u",
		 prev_stats->mib_stats.reg_ofdm_phyerr_cnt);
	qdf_info(",tgt_prev/cck_phyerr_cnt,%u",
		 prev_stats->mib_stats.reg_cck_phyerr_cnt);
}

/*
 * ieee80211_are_chans_intraband - Compare if two input frequencies are present
 * in the same band.
 * @freq1 - Channel Frequency.
 * @freq2 - Channel Frequency.
 * @band - Regulatory Band.
 */
static bool ieee80211_are_chans_intraband(qdf_freq_t freq1,
                                          qdf_freq_t freq2,
					  enum reg_wifi_band band)
{
    bool is_same_band;

    switch (band) {
        case REG_BAND_6G:
            is_same_band = wlan_reg_is_6ghz_chan_freq(freq1) &&
                                wlan_reg_is_6ghz_chan_freq(freq2);
            break;
        case REG_BAND_5G:
            is_same_band = wlan_reg_is_5ghz_ch_freq(freq1) &&
                                wlan_reg_is_5ghz_ch_freq(freq2);
            break;
        case REG_BAND_2G:
            is_same_band = wlan_reg_is_24ghz_ch_freq(freq1) &&
                                wlan_reg_is_24ghz_ch_freq(freq2);
            break;
        default:
            is_same_band = false;
            break;

    }

    return  is_same_band;
}

int wlan_dcs_send_acs_request(struct ieee80211vap *vap)
{
    struct ol_ath_softc_net80211 *scn;
    struct ieee80211com *ic = NULL;
    cfg80211_hostapd_acs_params cfg_acs_params = {0};
    uint32_t *freq_list = NULL;
    enum reg_wifi_band current_band;
    struct regulatory_channel *cur_chan_list;
    enum channel_enum chan_ix;
    bool is_wideband_csa_allowed;

    if (!vap) {
        qdf_err("VAP NULL");
        return -EINVAL;
    }

    ic  = vap->iv_ic;
    if (!ic) {
        qdf_err("ic NULL");
        return -EINVAL;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn) {
        qdf_err("scn NULL");
        return -EINVAL;
    }

    cfg_acs_params.ch_list_len = 0;
    freq_list = qdf_mem_malloc(sizeof(uint32_t) * ACS_MAX_CHANNEL_COUNT);
    if (!freq_list) {
        qdf_err("Could not allocate memory for the frequency list");
        return -EINVAL;
    }

    current_band = wlan_reg_freq_to_band(ic->ic_curchan->ic_freq);

    if (check_inter_band_switch_compatibility(ic) == QDF_STATUS_SUCCESS) {
        is_wideband_csa_allowed = true;
    } else {
        is_wideband_csa_allowed = false;
    }

    cur_chan_list = qdf_mem_malloc(NUM_CHANNELS * sizeof(*cur_chan_list));
    if (!cur_chan_list)
        return -EINVAL;

   if (wlan_reg_get_current_chan_list(ic->ic_pdev_obj, cur_chan_list) != QDF_STATUS_SUCCESS) {
       qdf_err("Failed to get cur_chan list");
       qdf_mem_free(cur_chan_list);
       return -EINVAL;
    }

    for (chan_ix = 0; chan_ix < NUM_CHANNELS; chan_ix++) {
        qdf_freq_t chan_freq = cur_chan_list[chan_ix].center_freq;

        if (!ieee80211_is_phymode_supported_by_channel(ic, chan_freq,
                                                       vap->iv_des_mode))
                continue;

        if (is_wideband_csa_allowed) {
            switch(scn->scn_dcs.dcs_wideband_policy) {
                case DCS_WIDEBAND_POLICY_INTERBAND:
                    /*
                     * If interband is selected, consider all supported
                     * channels.
                     */
                    OL_ATH_DCS_FREQ_TO_LIST(freq_list,
                                            &cfg_acs_params.ch_list_len,
                                            chan_freq);
                    break;

                case DCS_WIDEBAND_POLICY_INTRABAND:
                default:
                    /*
                     * Add only channels within current operating
                     * band if policy is set to intraband or if invalid
                     * policy is set.
                     */
         if (ieee80211_are_chans_intraband(chan_freq, ic->ic_curchan->ic_freq,
                                           REG_BAND_5G) ||
             ieee80211_are_chans_intraband(chan_freq, ic->ic_curchan->ic_freq,
                                           REG_BAND_6G)) {
                        OL_ATH_DCS_FREQ_TO_LIST(freq_list,
                                                &cfg_acs_params.ch_list_len,
                                                chan_freq);
                    }
                    break;
            }
        } else if (ieee80211_are_chans_intraband(chan_freq,
                                                 ic->ic_curchan->ic_freq,
                                                 REG_BAND_2G) ||
                   ieee80211_are_chans_intraband(chan_freq,
                                                 ic->ic_curchan->ic_freq,
                                                 REG_BAND_5G) ||
                   ieee80211_are_chans_intraband(chan_freq,
                                                 ic->ic_curchan->ic_freq,
                                                 REG_BAND_6G))  {
            /*
             * If wideband CSA is disabled, or if channel is not 11AXA, or if
             * channel is not 5/6GHz, then stay within current band.
             */
                OL_ATH_DCS_FREQ_TO_LIST(freq_list,
                                        &cfg_acs_params.ch_list_len,
                                        chan_freq);
        }

        if (cfg_acs_params.ch_list_len == (ACS_MAX_CHANNEL_COUNT - 1)) {
            /* Channel list full */
            break;
        }

    }

    qdf_mem_free(cur_chan_list);

    if (!cfg_acs_params.ch_list_len) {
        qdf_err("Could not find any channels");

        if (freq_list) {
           qdf_mem_free(freq_list);
        }

        return -EINVAL;
    }

    cfg_acs_params.hw_mode = vap->iv_des_mode;

    switch(get_chwidth_phymode(cfg_acs_params.hw_mode)) {
        case IEEE80211_CWM_WIDTH20:
            cfg_acs_params.ch_width = NL80211_CHAN_WIDTH_20;
            break;

        case IEEE80211_CWM_WIDTH40:
            cfg_acs_params.ch_width = NL80211_CHAN_WIDTH_40;
            break;

        case IEEE80211_CWM_WIDTH80:
            cfg_acs_params.ch_width = NL80211_CHAN_WIDTH_80;
            break;

        case IEEE80211_CWM_WIDTH160:
            cfg_acs_params.ch_width = NL80211_CHAN_WIDTH_160;
            break;

        case IEEE80211_CWM_WIDTH80_80:
            cfg_acs_params.ch_width = NL80211_CHAN_WIDTH_80P80;
            break;

        default:
            cfg_acs_params.ch_width = NL80211_CHAN_WIDTH_20_NOHT;
            break;
    }

    cfg_acs_params.freq_list = (const uint32_t *)freq_list;

    wlan_autoselect_register_event_handler(vap, &ieee80211_dcs_acs_event_handler,
                                   (void *)wlan_vap_get_registered_handle(vap));
    wlan_autoselect_find_infra_bss_channel(vap, &cfg_acs_params);

    if (freq_list) {
        qdf_mem_free(freq_list);
    }

    return 0;
}

/*
 * ol_ath_dcs_change_channel:
 * Wrapper API to change the channel as per the flag sent by the argument.
 *
 * @ic             : Pointer to the VAP structure
 * @new_channel    : Pointer to the new channel structure
 * @chanswitch_type: Flag for the type of channel switch
 *
 * Return:
 * QDF_STATUS_SUCCESS: Success
 * QDF_STATUS_E_*    : Error
 */
static QDF_STATUS ol_ath_dcs_change_channel(struct ieee80211vap *vap,
                                      struct ieee80211_ath_channel *new_channel,
                                      enum dcs_chanswitch_type chanswitch_type)
{
    struct ol_ath_softc_net80211 *scn;
    uint32_t ch_width = 0;

    if (!vap) {
        return QDF_STATUS_E_INVAL;
    }

    scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    if (!scn) {
        return QDF_STATUS_E_INVAL;
    }

    if (!new_channel) {
        return QDF_STATUS_E_INVAL;
    }

    switch (get_chwidth_phymode(ieee80211_chan2mode(new_channel))) {
        case IEEE80211_CWM_WIDTH20   : ch_width = CHWIDTH_20;  break;
        case IEEE80211_CWM_WIDTH40   : ch_width = CHWIDTH_40;  break;
        case IEEE80211_CWM_WIDTH80   : ch_width = CHWIDTH_80;  break;
        case IEEE80211_CWM_WIDTH160  :
        case IEEE80211_CWM_WIDTH80_80: ch_width = CHWIDTH_160; break;
        default                      : return QDF_STATUS_E_INVAL;
    }

    switch (chanswitch_type) {
        case DCS_CHANSWITCH_CSA:
            return ieee80211_ucfg_set_chanswitch(vap, new_channel->ic_freq,
                                                 scn->scn_dcs.dcs_csa_tbtt,
                                                 ch_width);
        break;

        case DCS_CHANSWITCH_HARD:
            return ieee80211_ucfg_set_freq(vap, new_channel->ic_freq);
        break;
    }

    return QDF_STATUS_E_INVAL;
}

/*
 * ol_ath_dcs_select_random_channel:
 * Find a random channel to start operation without having to initiate
 * scanning and channel selection through ACS/ICM/CBS.
 *
 * @ic          : Pointer to the ic structure.
 * @consider_dfs: Flag to consider DFS channels in random channel selection.
 *
 * Return:
 * QDF_STATUS_SUCCESS: Success
 * QDF_STATUS_E_*    : Error
 */
static struct ieee80211_ath_channel *
ol_ath_dcs_select_random_channel(struct ieee80211vap *vap,
                                 bool   consider_dfs)
{
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    uint32_t freq_count;
    uint32_t *freq_list;
    struct regulatory_channel *cur_chan_list;
    struct ieee80211_ath_channel *random_chan = NULL;
    enum channel_enum chan_ix;
    uint32_t random_chan_idx = 0;
    qdf_freq_t random_chan_freq = 0;
    bool is_wideband_enabled;
    qdf_freq_t chan_freq;
    enum ieee80211_phymode desired_mode;
    enum ieee80211_cwm_width current_width;

    if (!vap) {
        return NULL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        return NULL;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn) {
        return NULL;
    }

    freq_count = 0;
    freq_list = qdf_mem_malloc(sizeof(uint32_t) * NUM_CHANNELS);
    if (!freq_list) {
        qdf_err("Could not allocate memory for the frequency list");
        return NULL;
    }

    cur_chan_list = qdf_mem_malloc(NUM_CHANNELS * sizeof(*cur_chan_list));
    if (!cur_chan_list) {
        goto free_freq_list;
    }

   if (wlan_reg_get_current_chan_list(ic->ic_pdev_obj,
                                      cur_chan_list) != QDF_STATUS_SUCCESS) {
       goto free_cur_chan_list;
    }

    is_wideband_enabled = false;
    if ((check_inter_band_switch_compatibility(ic) == QDF_STATUS_SUCCESS) &&
        (scn->scn_dcs.dcs_wideband_policy == DCS_WIDEBAND_POLICY_INTERBAND)) {
        is_wideband_enabled = true;
    }

    current_width = get_chwidth_phymode(ieee80211_chan2mode(ic->ic_curchan));

    /* Use the VAP's desired mode unless desired mode is 80+80MHz. */
    desired_mode = vap->iv_des_mode;
    if (IEEE80211_IS_CHAN_11AXA_HE80_80(ic->ic_curchan)) {
        desired_mode = IEEE80211_MODE_11AXA_HE80;
    } else if (IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan)) {
        desired_mode = IEEE80211_MODE_11AC_VHT80;
    }

    /* Populate the channel list used for random channel selection */
    for (chan_ix = 0; chan_ix < NUM_CHANNELS; chan_ix++) {
        if (!consider_dfs &&
            (cur_chan_list[chan_ix].chan_flags & REGULATORY_CHAN_DISABLED) &&
            (cur_chan_list[chan_ix].state == CHANNEL_STATE_DISABLE)) {
            continue;
        }

        chan_freq = cur_chan_list[chan_ix].center_freq;

        if (!ieee80211_is_phymode_supported_by_channel(ic, chan_freq,
                                                       desired_mode)) {
            continue;
        }

        /*
         * Skip channels part of the current bandwidth, since all of
         * them contain interference.
         */
        if (OL_ATH_DCS_IS_FREQ_IN_WIDTH(ic->ic_curchan->ic_freq,
                                        ic->ic_curchan->ic_vhtop_freq_seg1,
                                        ic->ic_curchan->ic_vhtop_freq_seg2,
                                        current_width, chan_freq)) {
            continue;
        }

        if (!is_wideband_enabled &&
            ((wlan_reg_is_6ghz_chan_freq(chan_freq) &&
              IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) ||
             (wlan_reg_is_5ghz_ch_freq(chan_freq) &&
              IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)))) {
            continue;
        }

        OL_ATH_DCS_FREQ_TO_LIST(freq_list, &freq_count, chan_freq);
    }

    /*
     * Use a service API to retrieve a random uint32_t variable and limit
     * it to a range of 0 to (freq_count - 1).
     */
    OS_GET_RANDOM_BYTES(&random_chan_idx, sizeof(random_chan_idx));
    random_chan_idx = (random_chan_idx + OS_GET_TICKS()) % freq_count;
    random_chan_freq = freq_list[random_chan_idx];
    random_chan = ieee80211_find_dot11_channel(ic,
                                               random_chan_freq, 0,
                                               desired_mode);
    if (!random_chan) {
        goto free_cur_chan_list;
    }

free_cur_chan_list:
    if (cur_chan_list) {
        qdf_mem_free(cur_chan_list);
    }

free_freq_list:
    if (freq_list) {
        qdf_mem_free(freq_list);
    }

    return random_chan;
}

/*
 * ol_ath_dcs_check_and_reduce_bandwidth:
 * Check if channel change can be avoided by a bandwidth reduction and find
 * a new channel with the new bandwidth.
 *
 * @vap      : Pointer to the VAP structure
 * @awgn_info: Pointer to the AWGN information
 *
 * Return:
 * New channel
 */
static struct ieee80211_ath_channel *
ol_ath_dcs_check_and_reduce_bandwidth(struct ieee80211vap *vap,
                                      struct wmi_host_dcs_awgn_info *awgn_info)
{
    struct ieee80211com *ic;
    enum ieee80211_cwm_width current_chan_width = IEEE80211_CWM_WIDTHINVALID;
    enum ieee80211_phymode target_mode = IEEE80211_MODE_AUTO;

    if (!vap) {
        qdf_err("vap NULL");
        return NULL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("ic NULL");
        return NULL;
    }

    if (!ic->ic_curchan || !IEEE80211_IS_CHAN_5GHZ_6GHZ(ic->ic_curchan)) {
        qdf_err("Current channel is invalid");
        return NULL;
    }

    if (!awgn_info) {
        qdf_err("Invalid AWGN information received");
        return NULL;
    }

    if (!awgn_info->chan_bw_intf_bitmap) {
        qdf_err("Bitmap is empty - cannot perform bandwidth reduction");
        return NULL;
    }

    if (OL_ATH_DCS_GET_BITMAP_IDX(awgn_info, PRI20)) {
        /* If pri20 contains interference, then do full channel change */
        qdf_err("Primary 20MHz channel interference detected - cannot "
                "perform bandwidth reduction");
        return NULL;
    }

    current_chan_width = get_chwidth_phymode(ieee80211_chan2mode(ic->ic_curchan));

    if ((current_chan_width > IEEE80211_CWM_WIDTH80) &&
        !OL_ATH_DCS_GET_BITMAP_IDX(awgn_info, SEC40) &&
        !OL_ATH_DCS_GET_BITMAP_IDX(awgn_info, SEC20)) {
        /* If the current channel width is greater than 80MHz, check if 80MHz
         * bandwidth reduction is possible */
        if (IEEE80211_IS_CHAN_11AXA(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11AXA_HE80;
        } else if (IEEE80211_IS_CHAN_11AC(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11AC_VHT80;
        }
    } else if ((current_chan_width > IEEE80211_CWM_WIDTH40) &&
               !OL_ATH_DCS_GET_BITMAP_IDX(awgn_info, SEC20)) {
        /* For bandwidth reduction to 40MHz, ignore PLUS/MINUS since 5/6GHz
         * is assumed and all channels are bonded */
        if (IEEE80211_IS_CHAN_11AXA(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11AXA_HE40;
        } else if (IEEE80211_IS_CHAN_11AC(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11AC_VHT40;
        } else if (IEEE80211_IS_CHAN_11NA(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11NA_HT40;
        }
    } else {
        if (IEEE80211_IS_CHAN_11AXA(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11AXA_HE20;
        } else if (IEEE80211_IS_CHAN_11AC(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11AC_VHT20;
        } else if (IEEE80211_IS_CHAN_11NA(ic->ic_curchan)) {
            target_mode = IEEE80211_MODE_11NA_HT20;
        } else {
            target_mode = IEEE80211_MODE_11A;
        }
    }

    return ieee80211_find_dot11_channel(ic, ic->ic_curchan->ic_freq,
                                        0, target_mode);
}

/*
 * ol_ath_dcs_validate_awgn_info:
 * Validate AWGN information received from WMI
 *
 * @ic       : Pointer to the ic structure
 * @awgn_info: Pointer to the AWGN information
 *
 * Return:
 * QDF_STATUS_SUCCESS: Success
 * QDF_STATUS_E_*    : Error
 */
static inline QDF_STATUS ol_ath_dcs_validate_awgn_info(struct ieee80211com *ic,
                                       struct wmi_host_dcs_awgn_info *awgn_info)
{
    /* If the channel in the DCS event doesn't match the current channel,
     * drop the event.
     */
    if (ic->ic_curchan->ic_freq != awgn_info->center_freq) {
        return QDF_STATUS_E_INVAL;
    }

    switch(awgn_info->channel_width) {
        case WMI_HOST_CHAN_WIDTH_20:
            if (awgn_info->chan_bw_intf_bitmap > OL_ATH_DCS_SEG_PRI20) {
                return QDF_STATUS_E_INVAL;
            }
        break;

        case WMI_HOST_CHAN_WIDTH_40:
            if (awgn_info->chan_bw_intf_bitmap > OL_ATH_DCS_SEG_SEC20) {
                return QDF_STATUS_E_INVAL;
            }
        break;

        case WMI_HOST_CHAN_WIDTH_80:
            if (awgn_info->chan_bw_intf_bitmap > OL_ATH_DCS_SEG_SEC40) {
                return QDF_STATUS_E_INVAL;
            }
        break;

        case WMI_HOST_CHAN_WIDTH_160:
        case WMI_HOST_CHAN_WIDTH_80P80:
            if (awgn_info->chan_bw_intf_bitmap > OL_ATH_DCS_SEG_SEC80) {
                return QDF_STATUS_E_INVAL;
            }
        break;

        default:
            return QDF_STATUS_E_INVAL;
        break;
    }

    return QDF_STATUS_SUCCESS;
}

void ol_ath_dcs_generic_interference_handler(struct ol_ath_softc_net80211 *scn,
					     void *intf_info,
					     enum cap_dcs_type interference_type)
{
	struct ieee80211vap *vap = NULL, *tmpvap = NULL;
	struct ieee80211com *ic = NULL;
	wlan_host_dcs_params_t *dcs = NULL;
	uint32_t nowms = 0;
	bool disable_dcs = false;
	int ix = 0;
        struct wmi_host_dcs_awgn_info *awgn_info = NULL;
	struct ieee80211_ath_channel *new_channel = NULL;
#if UMAC_SUPPORT_CBS
	int cbs_csa = 0;
#endif

	if (!scn) {
		qdf_err("scn null");
		return;
	}

	ic = &scn->sc_ic;
	dcs = &scn->scn_dcs;

	if (!dcs || !ic) {
		qdf_err("dcs %pK ic %pK", dcs, ic);
		return;
	}

	if (interference_type == CAP_DCS_AWGNIM) {
            awgn_info = (struct wmi_host_dcs_awgn_info *)intf_info;
        }

#if UMAC_SUPPORT_CBS
	cbs_csa = ieee80211_cbs_get_param(ic->ic_cbs, IEEE80211_CBS_ENABLE);
#endif
	/* Check if CW Interference is already been found and being handled */
	if (ic->cw_inter_found)
		return;

	qdf_info("DCS: inteference_handler - start");

	spin_lock(&ic->ic_lock);

	/*
	 * mark this channel as cw_interference is found
	 * Set the CW interference flag so that ACS does not bail out this flag
	 * would be reset in ieee80211_beacon.c:ieee80211_beacon_update()
	 */
	ic->cw_inter_found = 1;

	/* Before triggering the channel change, turn off the dcs until the
	 * channel change completes, to avoid repeated reports.
	 */
	if (ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_dcs, 0))
		qdf_err("set pdev param for dcs failed");

	qdf_info("DCS ch change triggered, Disabling until ch change complete");

	OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable);
	spin_unlock(&ic->ic_lock);

        /*
         * For AWGN detection, skip bcast deauth and instead select a
         * random channel within the same context as the trigger event
         */
        if (interference_type == CAP_DCS_AWGNIM) {
            /* Get the lowest desired mode greater than 0 among all VAPs
             * Channel switch operations will be uniformly applied to all VAPs based
             * the lowest desired mode and the corresponding VAP */
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                if (!vap) {
                    vap = tmpvap;
                }

                if ((tmpvap != vap) &&
                    (tmpvap->iv_des_mode < vap->iv_des_mode)) {
                    vap  = tmpvap;
                }
            }

            /* If the AWGN information is invalid, then move directly to
             * channel change through random channel selection or ACS/ICM/CBS.
             */
            if (awgn_info) {
                if (ol_ath_dcs_validate_awgn_info(ic, awgn_info)) {
                    qdf_err("Invalid AWGN TLV - Skipping event");
                    ol_ath_dcs_restore(ic);
                    return;
                }

                new_channel = ol_ath_dcs_check_and_reduce_bandwidth(vap,
                                                                    awgn_info);
                if (new_channel) {
                    if (!ol_ath_dcs_change_channel(vap,
                                              new_channel,
                                              DCS_CHANSWITCH_CSA)) {
                        goto done;
                    }

                    ol_ath_dcs_restore(ic);
                    return;
                }
            }

            if (scn->scn_dcs.dcs_random_chan_en) {
                new_channel = ol_ath_dcs_select_random_channel(vap,
                                                               true);
                if (new_channel) {
                    if (!ol_ath_dcs_change_channel(vap,
                                              new_channel,
                                              DCS_CHANSWITCH_CSA)) {
                        goto done;
                    }

                    ol_ath_dcs_restore(ic);
                    return;
                }
            }
        }

#if UMAC_SUPPORT_CBS
        if (!cbs_csa) {
#endif
		TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
			if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
				qdf_info("De-authenticating all the nodes ");
				qdf_info("before channel change");
				wlan_deauth_all_stas(vap);
			}
		}
#if UMAC_SUPPORT_CBS
	}
#endif

	if (ic->ic_extacs_obj.icm_active) {
		qdf_info("ICM is active, requesting external DCS trigger");

		if (ol_ath_req_ext_dcs_trigger(scn, interference_type)) {
			qdf_err("DCS: External trigger failed");
		}
	} else {
		/* Loop through and figure the first VAP on this radio */
		/* FIXME
		 * There could be some issue in mbssid mode. It does look like
		 * if wlan_set_channel fails on first vap, it tries on the
		 * second vap again. Given that all vaps on same radio, we may
		 * need to do this. Need a test case for this.
		 * Leaving the code as it is.
		 */
#if UMAC_SUPPORT_CBS
		if (!cbs_csa ||
		    (ieee80211_cbs_api_change_home_channel(ic->ic_cbs,
                                   scn->scn_dcs.dcs_wideband_policy) != EOK)) {
#endif
			TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
				if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
				    (wlan_vdev_mlme_is_active(vap->vdev_obj) ==
				    QDF_STATUS_SUCCESS)) {
					vap->channel_switch_state = 1;
				}
			}

			TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
				if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
					if ((wlan_vdev_mlme_is_active(
					    vap->vdev_obj)
					    == QDF_STATUS_SUCCESS) &&
                                            !wlan_dcs_send_acs_request(vap)) {
					     /* ACS is done on per radio, so
					      * calling it once is good
					      * enough
					      */
					     goto done;
					 }
				}
			}
#if UMAC_SUPPORT_CBS
		} else
			goto done;
#endif
		spin_lock(&ic->ic_lock);
		/*
		 * reset cw_interference found flag since ACS is not triggered,
		 * so it can change the channel on next CW intf detection
		 */
		ic->cw_inter_found = 0;

		spin_unlock(&ic->ic_lock);
	}

	if (!ic->ic_extacs_obj.icm_active) {
	    qdf_err("DCS: ACS Trigger failed");
	}

	/* Should not come here (if ICM is not active), something is not right,
	 * hope something better happens next time the flag is set
	 */

done:
	if (interference_type == CAP_DCS_WLANIM) {
		nowms = (uint32_t)
			 CONVERT_SYSTEM_TIME_TO_MS(OS_GET_TIMESTAMP());

		if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_CRITICAL))
			qdf_info("DCS: dcs trigger count %d current ts %d",
				 dcs->dcs_trigger_count, nowms);

		if (dcs->dcs_trigger_count >= (DCS_MAX_TRIGGERS - 1)) {
			if ((nowms - dcs->dcs_trigger_ts[0]) < DCS_AGING_TIME) {
				disable_dcs = true;
			} else {
				for (ix = 0; ix < (dcs->dcs_trigger_count - 1);
				     ix++) {
					dcs->dcs_trigger_ts[ix] =
						dcs->dcs_trigger_ts[ix + 1];
				}
				dcs->dcs_trigger_count--;
			}
			/* To avoid frequent channel change,if channel change is
			 * triggered three times in last 5 mins, disable dcs.
			 */
			if (unlikely
			    (scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE)) {
				qdf_info("DCS: disable %d dcs trig count %d",
					 disable_dcs, dcs->dcs_trigger_count);
				for (ix = 0; ix < dcs->dcs_trigger_count;
				     ix++) {
					qdf_info("trigger num %d, ts %d\n",
						 ix, dcs->dcs_trigger_ts[ix]);
				}
			}
		}

		if (disable_dcs) {
			dcs_disable_wlan_im(ic);
			if (!dcs->is_enable_timer_set) {
				qdf_info("DCS:reenable timer started time %d",
					 dcs->dcs_re_enable_time);
				qdf_timer_mod(&dcs->dcs_enable_timer,
					      dcs->dcs_re_enable_time * 1000);
				dcs->is_enable_timer_set = true;
				dcs->dcs_trigger_count = 0;
			}
		} else if (dcs->dcs_trigger_count < DCS_MAX_TRIGGERS) {
			dcs->dcs_trigger_ts[dcs->dcs_trigger_count] = nowms;
			dcs->dcs_trigger_count++;
		}
	}
	qdf_info("DCS: interference_handling completed");
}

/*
 * ol_ath_dcs_interference_handler() - dcs interference handler
 * @sc: soc object
 * @data: data pointer
 * @datalen: len of data
 *
 * Return: none
 */
static int
ol_ath_dcs_interference_handler(ol_soc_t sc, uint8_t *data, uint32_t datalen)
{
	ol_ath_soc_softc_t *soc = (ol_ath_soc_softc_t *)sc;
	struct ieee80211com *ic;
	struct ol_ath_softc_net80211 *scn;
	periodic_chan_stats_t new_stats;
	periodic_chan_stats_t *prev_stats = NULL;
	wmi_host_dcs_im_tgt_stats_t wlan_stat = {0};
	struct wmi_host_dcs_awgn_info awgn_info = {0};
	struct wmi_host_dcs_interference_param dcs_param = {0};
	struct wmi_unified *wmi_hdl;
	struct wlan_objmgr_pdev *pdev;
	cdp_config_param_type value = {0};

	wmi_hdl = lmac_get_wmi_hdl(soc->psoc_obj);
	if (!wmi_hdl) {
		qdf_err("wmi_handle is null");
		return -EINVAL;
	}

	/* Extract interference type */
	if (wmi_extract_dcs_interference_type(wmi_hdl, data, &dcs_param) !=
					      QDF_STATUS_SUCCESS) {
		qdf_info("Unable to extract dcs interference type");
		return -1;
	}

	/* Get pdev from pdev_id */
	pdev = wlan_objmgr_get_pdev_by_id(soc->psoc_obj,
					  PDEV_UNIT(dcs_param.pdev_id),
					  WLAN_MLME_SB_ID);
	if (!pdev) {
		qdf_err("pdev object (id: %d) is NULL",
			 PDEV_UNIT(dcs_param.pdev_id));
		return -1;
	}

	scn = lmac_get_pdev_feature_ptr(pdev);
	if (!scn) {
		qdf_err("scn (id: %d) is NULL",
			 PDEV_UNIT(dcs_param.pdev_id));
		wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
		return -1;
	}

	ic = &scn->sc_ic;

	/*
	 * If none of the VAPs are ready, then ignore the DCS event since
	 * a channel is not active.
	 * NOTE: Receiving a DCS event when VAPs are not ready is incorrect
	 * behavior and needs to be investigated.
	 */
	if (!ieee80211_vaps_ready(ic, IEEE80211_M_HOSTAP)) {
		wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
		return -1;
	}

	/* This event is extended to provide periodic channel stats to user
	 * space irrespective of DCS eneble or disable.
	 * update periodic stats before handling DCS.
	 */
	if (dcs_param.interference_type == CAP_DCS_WLANIM) {
		ol_txrx_soc_handle soc_txrx_handle;
		soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
		if (!soc_txrx_handle) {
			wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
			return -1;
		}

		/* periodic channel stats */
		if (wmi_extract_dcs_im_tgt_stats(wmi_hdl, data, &wlan_stat) !=
						 QDF_STATUS_SUCCESS) {
			qdf_info("Unable to extract WLAN IM stats");
			wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
			return -1;
		}

		new_stats.tx_frame_count = wlan_stat.mib_stats.reg_tx_frame_cnt;
		new_stats.rx_frame_count = wlan_stat.mib_stats.reg_rx_frame_cnt;
		new_stats.rx_clear_count = wlan_stat.mib_stats.reg_rxclr_cnt;
		new_stats.cycle_count = wlan_stat.mib_stats.reg_cycle_cnt;
		new_stats.my_bss_rx_cycle_count =
					wlan_stat.my_bss_rx_cycle_count;
		new_stats.rx_clear_ext_count =
					wlan_stat.mib_stats.reg_rxclr_ext_cnt;
		new_stats.rx_clear_ext40_count = wlan_stat.reg_rxclr_ext40_cnt;
		new_stats.rx_clear_ext80_count = wlan_stat.reg_rxclr_ext80_cnt;

		/* update noise floor information */
		scn->chan_nf = wlan_stat.chan_nf;
		value.cdp_pdev_param_chn_noise_flr = scn->chan_nf;
		cdp_txrx_set_pdev_param(soc_txrx_handle,
				wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
				CDP_CHAN_NOISE_FLOOR, value);

		prev_stats = &scn->scn_dcs.chan_stats;

		/* process channel stats first*/
		if (!wlan_pdev_scan_in_progress(ic->ic_pdev_obj)) {
			/*
			 * During scan our hardware and software counters keep
			 * incrementing although they are tracking the stats of
			 * foreign channel. Don't send periodic home channel
			 * stats while scan is in progress.
			 */
			ol_chan_stats_event(ic, prev_stats, &new_stats);
			/* Update the counter vauses with latest one */
			scn->scn_dcs.chan_stats = new_stats;
		} else {
			ol_ath_invalidate_channel_stats(ic);
		}
	} else if (dcs_param.interference_type == CAP_DCS_AWGNIM) {
		if (wmi_extract_dcs_awgn_info(wmi_hdl, data, &awgn_info)) {
			qdf_info("Unable to extract AWGN stats");
			wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
			return -EINVAL;
		}
	}

	/*
	 * Do not handle any thing if host is in disabled state
	 * This shall not happen, provide extra safty for against any delays
	 * causing any kind of races.
	 */
	if (!(OL_IS_DCS_RUNNING(scn->scn_dcs.dcs_enable))) {
		wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
		return 0;
	}

	switch (dcs_param.interference_type) {
	case CAP_DCS_CWIM: /* cw interferecne*/
		if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) &
		    CAP_DCS_CWIM) {
			ol_ath_dcs_generic_interference_handler(scn,
						NULL,
						dcs_param.interference_type);
		}
	break;

	case CAP_DCS_WLANIM: /* wlan interference stats*/
		if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) &
		    CAP_DCS_WLANIM) {
			ol_ath_wlan_interference_handler(scn, &wlan_stat,
						dcs_param.interference_type);
		}
	break;
        case CAP_DCS_AWGNIM: /* AWGN interference */
                if (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) &
                    CAP_DCS_AWGNIM) {
                        ol_ath_dcs_generic_interference_handler(scn,
						&awgn_info,
                                                dcs_param.interference_type);
                }
        break;
	default:
		if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_CRITICAL)) {
			qdf_info("DCS:unidentified interference type reported");
		}
	break;
	}
	wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_SB_ID);
	return 0;
}

void ol_ath_disable_dcsim(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

	/* clear the run state, only when cwim is not set */
	if (!(OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & CAP_DCS_CWIM) &&
            !(OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & CAP_DCS_AWGNIM)) {
		OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable);
	}

	OL_ATH_DCS_DISABLE(scn->scn_dcs.dcs_enable, CAP_DCS_WLANIM);

	/* send target to disable and then disable in host */
	if (ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_dcs,
				  scn->scn_dcs.dcs_enable))
		qdf_err("set pdev param disable dcsim failed");
}

void ol_ath_enable_dcsim(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

	/* Enable wlanim for DCS */
	OL_ATH_DCS_ENABLE(scn->scn_dcs.dcs_enable, CAP_DCS_WLANIM);

	QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY,
		       QDF_TRACE_LEVEL_INFO,
		       "DCS: state %x", scn->scn_dcs.dcs_enable);

	/* send target to enable and then enable in host */
	if (ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_dcs,
				  scn->scn_dcs.dcs_enable & 0x0f))
		qdf_err("set pdev param enable dcsim failed");

	(OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) ?
		(OL_ATH_DCS_SET_RUNSTATE(scn->scn_dcs.dcs_enable)) :
		(OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable));
}

void ol_ath_ctrl_dcsawgn(struct ieee80211com *ic, uint32_t *flag, bool enable)
{
	struct ol_ath_softc_net80211 *scn = NULL;
	struct wmi_unified *wmi_hdl = NULL;

	if (!ic) {
		return;
	}

	scn = OL_ATH_SOFTC_NET80211(ic);
	if (!scn) {
		return;
	}

	wmi_hdl = lmac_get_wmi_hdl(scn->soc->psoc_obj);
	if (!wmi_hdl) {
		return;
	}

	if (!flag) {
		return;
	}

	*flag &= (~CAP_DCS_AWGNIM);
	if (enable &&
            wmi_service_enabled(wmi_hdl, wmi_service_dcs_awgn_int_support)) {
                *flag |= CAP_DCS_AWGNIM;
	}

	return;
}

void ol_ath_disable_dcscw(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
	uint8_t dcs_enable = scn->scn_dcs.dcs_enable;

	qdf_info("DCS: state %x", scn->scn_dcs.dcs_enable);

	if (!(OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable) & CAP_DCS_CWIM)) {
		return;
	}

	OL_ATH_DCS_DISABLE(scn->scn_dcs.dcs_enable, CAP_DCS_CWIM);
	/* send target to disable and then disable in host */
	if (ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_dcs,
				  scn->scn_dcs.dcs_enable) != EOK) {
		OL_ATH_DCS_ENABLE(scn->scn_dcs.dcs_enable, dcs_enable);
		qdf_err("Error in disabling CWIM");
	}
}

void ol_ath_dcs_restore(struct ieee80211com *ic)
{
	struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
	spin_lock(&ic->ic_lock);
	if (ic->cw_inter_found)
		ic->cw_inter_found = 0;

	if (unlikely(scn->scn_dcs.dcs_debug >= DCS_DEBUG_VERBOSE))
		qdf_info("DCS: state %x", scn->scn_dcs.dcs_enable);

	/* once the channel change is complete, turn on the dcs,
	 * use the same state as what the current enabled state of the dcs. Also
	 * set the run state accordingly.
	 */
	if (ol_ath_pdev_set_param(scn->sc_pdev, wmi_pdev_param_dcs,
				  scn->scn_dcs.dcs_enable & 0x0f))
		qdf_err("set pdev param enable dcs failed");

	(OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) ?
		(OL_ATH_DCS_SET_RUNSTATE(scn->scn_dcs.dcs_enable)) :
		(OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable));
	spin_unlock(&ic->ic_lock);
}

void ol_ath_soc_dcs_attach(ol_ath_soc_softc_t *soc)
{
	struct wmi_unified *wmi_handle;

	wmi_handle = lmac_get_wmi_hdl(soc->psoc_obj);

	wmi_unified_register_event_handler((wmi_unified_t)wmi_handle,
					   wmi_dcs_interference_event_id,
					   ol_ath_dcs_interference_handler,
					   WMI_RX_UMAC_CTX);
}

void ol_ath_set_dcs_param(struct ieee80211com *ic,
			  enum ol_ath_dcs_params param,
			  uint32_t value)
{
	struct ol_ath_softc_net80211 *scn;

	if (!ic) {
		qdf_err("Invalid ic");
		return;
	}

	scn = OL_ATH_SOFTC_NET80211(ic);
	if (!scn) {
		qdf_err("Invalid scn");
		return;
	}

	switch(param) {
		case OL_ATH_DCS_PARAM_RANDOM_CHAN_EN:
			scn->scn_dcs.dcs_random_chan_en = !!value;
			qdf_info("DCS random channel selection %s",
				 scn->scn_dcs.dcs_random_chan_en ? "enabled" :
								   "disabled");
		break;

		case OL_ATH_DCS_PARAM_CSA_TBTT:
			scn->scn_dcs.dcs_csa_tbtt = value ? value :
							   DCS_CSA_TBTT_DEFAULT;
			qdf_info("DCS CSA TBTT set as %d",
				 scn->scn_dcs.dcs_csa_tbtt);
		break;

		default:
			qdf_info("Invalid param: %d", param);
		break;
	}

	return;
}
