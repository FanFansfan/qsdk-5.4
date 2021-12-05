/*
 * Copyright (c) 2017,2019 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#ifndef _IEEE80211_MLME_DFS_DISPATCHER_H_
#define _IEEE80211_MLME_DFS_DISPATCHER_H_

#include <ieee80211_var.h>

/* Do we need to use the RootAP's beacon interval as RCSA interval ??? */
#define RCSA_INTVAL         (100)     /* 100 millisecond */
#define WAIT_FOR_CSA_TIME   (2000)    /* 2sec (roundtrip(1sec) + grace period(1sec)) */
#define RCSA_INIT_COUNT     (5)       /* Send 5 RCSA */
#define WAIT_FOR_RCSA_COMPLETION   ((RCSA_INIT_COUNT + 1) * RCSA_INTVAL)    /* 600ms = 500ms(5 RCSAs) + 100 ms grace period after last RCSA */

/**
 * Software use: channel interference used for as AR as well as RADAR
 * interference detection.
 */
#define CHANNEL_INTERFERENCE    0x01

/**
 * mlme_dfs_control()- Used to process ioctls related to DFS.
 * @pdev: Pointer to DFS pdev object.
 * @id: Command type.
 * @indata: Input buffer.
 * @insize: size of the input buffer.
 * @outdata: A buffer for the results.
 * @outsize: Size of the output buffer.
 * @error: return value.
 */
void mlme_dfs_control(struct wlan_objmgr_pdev *pdev,
		u_int id,
		void *indata,
		uint32_t insize,
		void *outdata,
		uint32_t *outsize,
		int *error);

/**
 * mlme_dfs_reset()- Reset dfs members.
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_reset(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_is_freq_in_nol() - check if given channel in nol list
 * @pdev: Pointer to DFS pdev object
 * @freq: channel frequency
 *
 * check if given channel in nol list.
 *
 * Return: true if channel in nol, false else
 */
bool mlme_dfs_is_freq_in_nol(struct wlan_objmgr_pdev *pdev, uint32_t freq);

/**
 * mlme_dfs_cac_valid_reset_for_freq() - Cancels the dfs_cac_valid_timer timer.
 * @pdev: Pointer to DFS pdev object.
 * @prevchan_ieee: Prevchan frequency.
 * @prevchan_flags: Prevchan flags.
 */
void mlme_dfs_cac_valid_reset_for_freq(struct wlan_objmgr_pdev *pdev,
				       uint16_t prevchan_freq,
				       uint32_t prevchan_flags);

/**
 * mlme_dfs_reset_precaclists() - Clears and initializes precac_list.
 * @pdev: Pointer to DFS pdev object.
 */
#ifdef ATH_SUPPORT_ZERO_CAC_DFS
void mlme_dfs_reset_precaclists(struct wlan_objmgr_pdev *pdev);
#else
static inline
void mlme_dfs_reset_precaclists(struct wlan_objmgr_pdev *pdev)
{
}
#endif
/**
 * mlme_dfs_cac_stop() - Clear the AP CAC timer.
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_cac_stop(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_start_cac_timer() - Starts the CAC timer.
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_start_cac_timer(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_is_skip_cac() - Check if AP can skip the CAC
 * @pdev: Pointer to DFS pdev object.
 *
 * If the new channel is same as or subset of cac started channel, then AP
 * can skip the CAC.
 *
 * Return: true if CAC can be skipped, else false.
 */
bool mlme_dfs_is_skip_cac(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_set_update_nol_flag() - Sets update_nol flag.
 * @pdev: Pointer to DFS pdev object.
 * @val: update_nol flag.
 */
void mlme_dfs_set_update_nol_flag(struct wlan_objmgr_pdev *pdev,
		bool val);

/**
 * mlme_dfs_nol_addchan() - Add channel to NOL.
 * @pdev: Pointer to DFS pdev object.
 * @chan: channel t o add NOL.
 * @dfs_nol_timeout: NOL timeout.
 */
void mlme_dfs_nol_addchan(struct wlan_objmgr_pdev *pdev,
		struct ieee80211_ath_channel *chan,
		uint32_t dfs_nol_timeout);

/**
 * mlme_dfs_get_nol_timeout() - Get NOL timeout.
 * @pdev: Pointer to DFS pdev object.
 * @dfs_nol_timeout: Pointer to dfs_nol_timeout.
 */
void mlme_dfs_get_nol_timeout(struct wlan_objmgr_pdev *pdev,
		int *dfs_nol_timeout);

/**
 * mlme_dfs_nol_update() - NOL update
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_nol_update(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_get_usenol() - Returns use_nol flag.
 * @pdev: Pointer to DFS pdev object.
 */
uint16_t mlme_dfs_get_usenol(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_set_update_nol_flag() - Sets update_nol flag.
 * @pdev: Pointer to DFS pdev object.
 */
bool mlme_dfs_get_update_nol_flag(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_random_channel() - Function to choose the random channel from the
 *                        current channel list.
 * @pdev: Pointer to DFS pdev object.
 * @ch_params: Current channel params.
 * @flags: Select NON-DFS chan or both NON-DFS and DFS.
 *
 * Return: Random channel number.
 */
int mlme_dfs_random_channel(struct wlan_objmgr_pdev *pdev,
		struct ch_params *ch_params,
		uint16_t flags);

/**
 * mlme_dfs_bw_reduced_channel() - Function to reduce bandwidth of current
 *                            primary beaconing channel, if current primary
 *                            channel is not affected by Radar.
 * @pdev: Pointer to DFS pdev object.
 * @ch_params: Current channel params.
 *
 * Return: Primary channel for the radio.
 */
int mlme_dfs_bw_reduced_channel(struct wlan_objmgr_pdev *pdev,
		struct ch_params *ch_params);

#ifdef QCA_SUPPORT_ADFS_RCAC
/* mlme_dfs_get_rcac_channel() - API to find if a completed rolling CAC channel
 *                           exists and return it.
 * @pdev: Pointer to DFS pdev object.
 * @ch_params: Current channel params.
 *
 * Return: Next primary channel frequency for the radio of type qdf_freq_t.
 */
qdf_freq_t mlme_dfs_get_rcac_channel(struct wlan_objmgr_pdev *pdev,
		struct ch_params *ch_params);
/**
 * mlme_dfs_is_agile_rcaccac_enabled() - Returns the value of
 *                                       agile rcac flag.
 * @pdev: Pointer to DFS pdev object.
 *
 * Return: Value of dfs_is_agile_rcac_enabled()
 */
bool mlme_dfs_is_agile_rcac_enabled(struct wlan_objmgr_pdev *pdev);
#else
static inline
qdf_freq_t mlme_dfs_get_rcac_channel(struct wlan_objmgr_pdev *pdev,
		struct ch_params *ch_params)
{
	return 0;
}
static inline
bool mlme_dfs_is_agile_rcac_enabled(struct wlan_objmgr_pdev *pdev)
{
	return false;
}
#endif

/**
 * mlme_dfs_radar_disable() - Disables the radar.
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_radar_disable(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_get_rn_use_nol() - Get usenol.
 * @pdev: Pointer to DFS pdev object.
 */
int mlme_dfs_get_rn_use_nol(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_second_segment_radar_disable() - Disables the second segment radar.
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_second_segment_radar_disable(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_is_ap_cac_timer_running() - Returns the dfs cac timer.
 * @pdev: Pointer to DFS pdev object.
 * @is_ap_cac_timer_running: Pointer to save dfs_cac_timer_running value.
 */
int mlme_dfs_is_ap_cac_timer_running(struct wlan_objmgr_pdev *pdev);

#ifdef WLAN_DFS_PRECAC_AUTO_CHAN_SUPPORT
/**
 * mlme_dfs_is_legacy_precac_enabled() - Returns the value of preCAC flag
 * in partial offload chipsets.
 * @pdev: Pointer to DFS pdev object.
 *
 * Return: True if legacy preCAC is enabled, else false.
 */
bool mlme_dfs_is_legacy_precac_enabled(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_is_agile_precac_enabled() - Returns the value of
 *                                      agile precac flag.
 * @pdev: Pointer to DFS pdev object.
 *
 * Return: Value of dfs_get_agile_precac_enable
 */
bool mlme_dfs_is_agile_precac_enabled(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_decide_precac_preferred_chan_for_freq() - Decides whether configured
 *                                           DFS channel should be used or
 *                                            intermediate channel should
 *                                            be used based on preCAC state.
 * @pdev: Pointer to DFS pdev object.
 * @ch_ieee: Configured DFS channel.
 * @mode: Configured PHY mode.
 * Return: True if intermediate channel needs to configure. False otherwise.
 */

bool
mlme_dfs_decide_precac_preferred_chan_for_freq(struct wlan_objmgr_pdev *pdev,
					       uint16_t *ch_freq,
					       enum wlan_phymode mode);
#endif

/**
 * mlme_dfs_override_cac_timeout() -  Override the default CAC timeout.
 * @pdev: Pointer to DFS pdev object.
 * @cac_timeout: CAC timeout value.
 */
int mlme_dfs_override_cac_timeout(struct wlan_objmgr_pdev *pdev,
		int cac_timeout);

/**
 * mlme_dfs_get_override_cac_timeout() -  Get override CAC timeout value.
 * @pdev: Pointer to DFS pdev object.
 * @cac_timeout: Pointer to save the CAC timeout value.
 */
int mlme_dfs_get_override_cac_timeout(struct wlan_objmgr_pdev *pdev,
		int *cac_timeout);

/**
 * mlme_dfs_getnol() - Wrapper function for dfs_get_nol()
 * @pdev: Pointer to DFS pdev object.
 * @dfs_nolinfo: Pointer to dfsreq_nolinfo structure.
 */
void mlme_dfs_getnol(struct wlan_objmgr_pdev *pdev,
		void *dfs_nolinfo);

/**
 * mlme_dfs_stacac_stop() - Clear the STA CAC timer.
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_stacac_stop(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_set_cac_timer_running() - Sets the cac timer running.
 * @pdev: Pointer to DFS pdev object.
 * @val: Set this value to dfs_cac_timer_running variable.
 */
void mlme_dfs_set_cac_timer_running(struct wlan_objmgr_pdev *pdev,
		int val);

/**
 * mlme_dfs_get_nol_chfreq_and_chwidth() - Sets the cac timer running.
 * @pdev: Pointer to DFS pdev object.
 * @nollist: Pointer to NOL channel entry.
 * @nol_chfreq: Pointer to save channel frequency.
 * @nol_chwidth: Pointer to save channel width.
 * @index: Index into nol list.
 */
void mlme_dfs_get_nol_chfreq_and_chwidth(struct wlan_objmgr_pdev *pdev,
		void *nollist,
		uint32_t *nol_chfreq,
		uint32_t *nol_chwidth,
		int index);

/**
 * mlme_dfs_stop() - Clear dfs timers.
 * @pdev: Pointer to DFS pdev object.
 */
void mlme_dfs_stop(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_update_cur_chan_flags() - Update DFS current channel flags.
 * @pdev: Pointer to DFS pdev object.
 * @flags: New channel flags
 * @flagext: Extended flags
 */
void mlme_dfs_update_cur_chan_flags(struct wlan_objmgr_pdev *pdev,
		uint64_t flags,
		uint16_t flagext);

#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
/**
 * mlme_dfs_is_spoof_check_failed() - Gets the value of is_spoof_check_failed.
 * @pdev: Pointer to DFS pdev object.
 */
bool mlme_dfs_is_spoof_check_failed(struct wlan_objmgr_pdev *pdev);

/**
 * mlme_dfs_is_spoof_done() - Checks if spoof is done or not. For chips that
 * do not support spoof it is always true.
 * @pdev: Pointer to DFS pdev object.
 */
bool mlme_dfs_is_spoof_done(struct wlan_objmgr_pdev *pdev);

void ieee80211_dfs_non_dfs_chan_config(void *arg);
#else
static inline
bool mlme_dfs_is_spoof_done(struct wlan_objmgr_pdev *pdev)
{
	return true;
}
#endif /* HOST_DFS_SPOOF_TEST */

/**
 * mlme_dfs_is_cac_required() - Check if CAC is required on the current
 * channel.
 * @pdev: Pointer to DFS pdev object.
 * @cur_chan: Pointer to the current channel of the pdev.
 * @prev_chan: Pointer to the previous channel of the pdev.
 * @continue_current_cac: If AP can start CAC then this variable indicates
 * whether to continue with the current CAC or restart the CAC. This variable
 * is valid only if this function returns true.
 *
 * Return: True if AP requires CAC or can continue current CAC, else false.
 */
bool mlme_dfs_is_cac_required(struct wlan_objmgr_pdev *pdev,
			      struct ieee80211_ath_channel *cur_chan,
			      struct ieee80211_ath_channel *prev_chan,
			      bool *continue_current_cac);

/**
 * mlme_dfs_is_cac_required_on_dfs_curchan() - Check if CAC is required on the
 * DFS current channel.
 * @pdev: Pointer to DFS pdev object.
 * @continue_current_cac: If AP can start CAC then this variable indicates
 * whether to continue with the current CAC or restart the CAC. This variable
 * is valid only if this function returns true.
 *
 * Return: True if AP requires CAC or can continue current CAC, else false.
 */
bool mlme_dfs_is_cac_required_on_dfs_curchan(struct wlan_objmgr_pdev *pdev,
					     bool *continue_current_cac);
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
/**
 * mlme_dfs_freq_to_chan() - Convert a given freq to chan number.
 * @freq: Freq to convert
 */
uint8_t mlme_dfs_freq_to_chan(uint16_t freq);

/**
 * mlme_dfs_reg_update_nol_ch_for_freq() - Update NOL channels in regdb component.
 * @pdev: Pointer to DFS pdev object.
 * @ch_list:Pointer to NOL freq channel.
 * @num_ch : No of NOL channel.
 * @nol_ch: Flag to NOL.
 */

void mlme_dfs_reg_update_nol_ch_for_freq(struct wlan_objmgr_pdev *pdev,
					 uint16_t *freq,
					 uint8_t num_ch,
					 bool nol_ch);
#endif

/**
 * mlme_dfs_fetch_nol_ie_info() - Fills the arguments with information
 * needed for sending NOL IE.
 * @pdev: Pointer to DFS pdev object.
 * @nol_ie_bandwidth: Minimum DFS subchannel Bandwidth.
 * @nol_ie_startfreq: Radar affected channel list start channel's
 * centre frequency.
 * @nol_ie_bitmap: Bitmap of radar affected subchannels.
 */
QDF_STATUS mlme_dfs_fetch_nol_ie_info(struct wlan_objmgr_pdev *pdev,
				      uint8_t *nol_ie_bandwidth,
				      uint16_t *nol_ie_startfreq,
				      uint8_t *nol_ie_bitmap);

/**
 * mlme_dfs_set_rcsa_flags() - Set the flags that are required to send
 * RCSA and NOL IE.
 * @pdev: Pointer to DFS pdev object.
 * @is_rcsa_ie_sent: Boolean to check if RCSA should be sent or not.
 * @is_nol_ie_sent: Boolean to check if NOL IE should be sent or not.
 */
QDF_STATUS mlme_dfs_set_rcsa_flags(struct wlan_objmgr_pdev *pdev,
				   bool is_rcsa_ie_sent,
				   bool is_nol_ie_sent);

/**
 * mlme_dfs_get_rcsa_flags() - Get the flags that are required to send
 * RCSA and NOL IE.
 * @pdev: Pointer to DFS pdev object.
 * @is_rcsa_ie_sent: Boolean to check if RCSA should be sent or not.
 * @is_nol_ie_sent: Boolean to check if NOL IE should be sent or not.
 */
QDF_STATUS mlme_dfs_get_rcsa_flags(struct wlan_objmgr_pdev *pdev,
				   bool *is_rcsa_ie_sent,
				   bool *is_nol_ie_sent);

/**
 * mlme_dfs_process_nol_ie_bitmap() - Update NOL with external radar
 * information.
 * pdev: Pointer to DFS pdev object.
 * nol_ie_bandwidth: Minimum DFS subchannel Bandwidth.
 * nol_ie_startfreq: Radar affected subhannel list start channel's
 * centre frequency.
 * nol_ie_bitmap: Bitmap of radar affected subchannels.
 *
 * Return: True if NOL IE has been processed and added to NOL, else false.
 */
bool mlme_dfs_process_nol_ie_bitmap(struct wlan_objmgr_pdev *pdev,
				    uint8_t nol_ie_bandwidth,
				    uint16_t nol_ie_startfreq,
				    uint8_t nol_ie_bitmap);


#ifdef ATH_SUPPORT_ZERO_CAC_DFS
/**
 * mlme_dfs_precac_status_for_channel() - API to find the preCAC status
 * of the given channel.
 * @pdev: Pointer to DFS pdev object.
 * @deschan: Pointer to desired channel of ieee80211_ath_channel structure.
 */
enum precac_status_for_chan
mlme_dfs_precac_status_for_channel(struct wlan_objmgr_pdev *pdev,
				   struct ieee80211_ath_channel *des_channel);
#else
static inline enum precac_status_for_chan
mlme_dfs_precac_status_for_channel(struct wlan_objmgr_pdev *pdev,
				   struct ieee80211_ath_channel *des_channel)
{
	return DFS_INVALID_PRECAC_STATUS;
}
#endif

#endif
