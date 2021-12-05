/*
 * Copyright (c) 2017-2018 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#ifndef _IEEE80211_REGDMN_DISPATCHER_H_
#define _IEEE80211_REGDMN_DISPATCHER_H_

/**
 * ieee80211_regdmn_program_cc() - Program user country code or regdomain
 * @pdev: The physical dev to program country code or regdomain
 * @rd: User country code or regdomain
 *
 * Return: QDF_STATUS
 */
int ieee80211_regdmn_program_cc(struct wlan_objmgr_pdev *pdev,
		struct cc_regdmn_s *rd);

/**
 * ieee80211_regdmn_get_chip_mode() - Get supported chip mode
 * @pdev: pdev pointer
 * @chip_mode: chip mode
 *
 * Return: QDF STATUS
 */
QDF_STATUS ieee80211_regdmn_get_chip_mode(struct wlan_objmgr_pdev *pdev,
		uint32_t *chip_mode);

/**
 * ieee80211_regdmn_get_phybitmap() - Get phybitmap from regulatory pdev_priv_obj
 * @pdev: pdev pointer
 * @phybitmap: pointer to phybitmap
 *
 * Return: QDF STATUS
 */
QDF_STATUS ieee80211_regdmn_get_phybitmap(struct wlan_objmgr_pdev *pdev,
                                          uint16_t *phybitmap);

/**
 * ieee80211_regdmn_get_freq_range() - Get 2GHz and 5GHz frequency range
 * @pdev: pdev pointer
 * @low_2g: low 2GHz frequency range
 * @high_2g: high 2GHz frequency range
 * @low_5g: low 5GHz frequency range
 * @high_5g: high 5GHz frequency range
 *
 * Return: QDF status
 */
QDF_STATUS ieee80211_regdmn_get_freq_range(struct wlan_objmgr_pdev *pdev,
		qdf_freq_t *low_2g,
		qdf_freq_t *high_2g,
		qdf_freq_t *low_5g,
		qdf_freq_t *high_5g);

/**
 * ieee80211_regdmn_get_current_chan_list () - get current channel list
 * @pdev: pdev ptr
 * @chan_list: channel list
 *
 * Return: QDF_STATUS
 */
QDF_STATUS ieee80211_regdmn_get_current_chan_list(struct wlan_objmgr_pdev *pdev,
		struct regulatory_channel *chan_list);

/**
 * ieee80211_regdmn_get_current_cc() - get current country code or regdomain
 * @pdev: The physical dev to program country code or regdomain
 * @rd: Pointer to country code or regdomain
 *
 * Return: QDF_STATUS
 */
QDF_STATUS ieee80211_regdmn_get_current_cc(struct wlan_objmgr_pdev *pdev,
		struct cc_regdmn_s *rd);

/**
 * ieee80211_regdmn_get_5g_bonded_channel_state_for_freq() - Get 5G bonded
 * channel state
 * @pdev: The physical dev to program country code or regdomain.
 * @freq: channel center frequency.
 * @bw: channel band width.
 *
 * Return: channel state
 */
enum channel_state ieee80211_regdmn_get_5g_bonded_channel_state_for_freq(
                struct wlan_objmgr_pdev *pdev, qdf_freq_t freq,
                enum phy_ch_width bw);

/**
 * ieee80211_regdmn_get_2g_bonded_channel_state_for_freq() - Get 2G bonded
 * channel state
 * @pdev: The physical dev to program country code or regdomain.
 * @freq: channel center frequency.
 * @sec_ch_freq: Secondary channel frequency.
 * @bw: channel band width.
 *
 * Return: channel state
 */
enum channel_state ieee80211_regdmn_get_2g_bonded_channel_state_for_freq(
                struct wlan_objmgr_pdev *pdev, qdf_freq_t freq,
                qdf_freq_t sec_ch_freq, enum phy_ch_width bw);

/**
 * ieee80211_regdmn_set_channel_params_for_freq () - Sets channel parameteres for given bandwidth
 * @pdev: The physical dev to program country code or regdomain.
 * @freq: channel center frequency.
 * @sec_ch_2g_freq: Secondary channel frequency.
 * @ch_params: pointer to the channel parameters.
 *
 * Return: None
 */
void ieee80211_regdmn_set_channel_params_for_freq(
                struct wlan_objmgr_pdev *pdev,
                qdf_freq_t freq,
                qdf_freq_t sec_ch_2g_freq,
                struct ch_params *ch_params);

/*
 * ieee80211_regdmn_get_channel_params () - Gets channel parameters for a given bandwidth
 * The function "ieee80211_regdmn_set_channel_params_for_freq" does the same,
 * with the following difference: the "ieee80211_regdmn_set_channel_params_for_freq"
 * does not include the NOL channels for its search and "ieee80211_regdmn_get_channel_params"
 * includes all enabled channels and NOL channels for its search.
 * @pdev: The physical dev to program country code or regdomain.
 * @freq: channel center frequency.
 * @sec_ch_2g_freq: Secondary channel frequency.
 * @ch_params: pointer to the channel parameters.
 *
 * Return: None
 */
void ieee80211_regdmn_get_channel_params(
                struct wlan_objmgr_pdev *pdev,
                qdf_freq_t freq,
                qdf_freq_t sec_ch_2g_freq,
                struct ch_params *ch_params);

/**
 * ieee80211_regdmn_get_dfs_region() - Get the DFS region.
 * @pdev: The physical dev to program country code or regdomain
 * @dfs_region: pointer to dfs_reg.
 *
 * Return: QDF_STATUS
 */
int ieee80211_regdmn_get_dfs_region(struct wlan_objmgr_pdev *pdev,
		enum dfs_reg *dfs_region);
#endif
