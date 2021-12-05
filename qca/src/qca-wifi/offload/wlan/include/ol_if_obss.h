/*
 * Copyright (c) 2011-2014,2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * copyright (c) 2011 Atheros Communications Inc.
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
#ifndef OL_IF_OBSS_H
#define OL_IF_OBSS_H

#include <ol_if_athvar.h>
#include <ieee80211_var.h>
#include <init_deinit_lmac.h>
#include <ol_if_pdev.h>
#include <target_if.h>
#include "target_type.h"

#if OBSS_PD

/**
 * ol_ath_send_derived_obsee_spatial_reuse_param() - sends obss spatial
 * reuse parameters to fw
 * @vap: pointer to ieee80211vap
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_send_derived_obsee_spatial_reuse_param(struct ieee80211vap *vap);

/**
 * ol_ath_is_spatial_reuse_enabled() - checks if spatial reuse is enabled
 * @ic: pointer to ieee80211com
 *
 * Return: True is enabled, else return false
 */
bool ol_ath_is_spatial_reuse_enabled(struct ieee80211com *ic);

/**
 * ol_ath_vap_set_self_psr_tx_enable() - Sets self psr TX value
 * @vap: pointer to ieee80211vap
 * @enable: Value to be set
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_vap_set_self_psr_tx_enable(struct ieee80211vap *vap,
                                      uint8_t enable);
/**
 * ol_ath_vap_set_self_sr_config() - sets self SR config
 * @vap: pointer to ieee80211vap
 * @param: parameter to determine config command
 * @data: data to be set
 * @data_len: length of the data
 * @value: value for setting SR config
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_vap_set_self_sr_config(
    struct ieee80211vap *vap, uint32_t param,
    void *data, uint32_t data_len, uint32_t value);

/**
 * ol_ath_vap_get_self_sr_config() - gets self SR config
 * @vap: pointer to ieee80211vap
 * @param: parameter to determine config command
 * @value: the set value of the configuration
 * @length: length of the value[]
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_vap_get_self_sr_config(
    struct ieee80211vap *vap, uint8_t param, char value[], size_t length);

/**
 * ol_ath_vap_set_he_sr_config() - sets HE SR configuration
 * @vap: pointer to ieee80211vap
 * @param: parameter to determine config command
 * @value: value for setting SR config
 * @data1: min offset to be set
 * @data2: max offset to be set
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_vap_set_he_sr_config(struct ieee80211vap *vap, uint8_t param,
                                uint8_t value, uint8_t data1, uint8_t data2);

/**
 * ol_ath_vap_get_he_sr_config() - gets HE SR configuration
 * @vap: pointer to ieee80211vap
 * @param: parameter to determine config command
 * @value: pointer for getting SR config
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_vap_get_he_sr_config(struct ieee80211vap *vap,
                                uint8_t param, uint32_t *value);

/**
 * ol_ath_vap_set_he_srg_bitmap() - sets HE SRG bitmap
 * @vap: pointer to ieee80211vap
 * @value: pointer for setting SRG bitmap
 * @param: parameter to determine the command
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_vap_set_he_srg_bitmap(struct ieee80211vap *vap,
                                 uint32_t *val, uint32_t param);

/**
 * ol_ath_vap_get_he_srg_bitmap() - gets HE SRG bitmap
 * @vap: pointer to ieee80211vap
 * @value: pointer for getting SRG bitmap
 * @param: parameter to determine the command
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_vap_get_he_srg_bitmap(struct ieee80211vap *vap,
                                 uint32_t *val, uint32_t param);

/**
 * ol_ath_send_obss_spatial_reuse_param() - sends obss SR parameters
 * @vdev: vdev object
 *
 * Return: QDF_STATUS_SUCCESS on success, other status on failure
 */
QDF_STATUS ol_ath_send_obss_spatial_reuse_param(struct wlan_objmgr_vdev *vdev);

/**
 * ol_ath_sr_validate_vap_config() - Ensure that Spatial Reuse is disabled if both
 * AP and STA VAPs exist on same pdev
 * @ic: pointer to ieee80211com
 * @scn: pointer to ol_ath_softc_net80211
 * @type: SR type
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_sr_validate_vap_config(struct ieee80211com *ic,
                                  struct ol_ath_softc_net80211 *scn, enum srtype type);

/**
 * ol_ath_set_obss_pd_enable_bit() - sets obss PD bit
 * @ic: pointer to ieee80211com
 * @enable: value to be set
 * @scn: pointer to ol_ath_softc_net80211
 * @type: SR type
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_set_obss_pd_enable_bit(struct ieee80211com *ic, uint32_t enable,
                                  struct ol_ath_softc_net80211 *scn, enum srtype type);

/**
 * ol_ath_set_obss_pd_threshold() - sets obss PD threshold value
 * @ic: pointer to ieee80211com
 * @threshold: value to be set
 * @scn: pointer to ol_ath_softc_net80211
 * @type: SR type
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_set_obss_pd_threshold(struct ieee80211com *ic, int32_t threshold,
                                 struct ol_ath_softc_net80211 *scn, enum srtype type);

/**
 * ol_ath_set_self_srg_bss_color_bitmap() - send wmi command for setting bss color bitmap
 * @ic: pointer to ieee80211com
 * @bitmap_0: lower 32 bits in BSS color bitmap
 * @bitmap_1: upper 32 bits in BSS color bitmap
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_set_self_srg_bss_color_bitmap(struct ieee80211com *ic,
                                         uint32_t bitmap_0, uint32_t bitmap_1);

/**
 * ol_ath_set_self_srg_partial_bssid_bitmap() - send wmi command for setting partial bssid bitmap
 * @ic: pointer to ieee80211com
 * @bitmap_0: lower 32 bits in BSS color bitmap
 * @bitmap_1: upper 32 bits in BSS color bitmap
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_set_self_srg_partial_bssid_bitmap(struct ieee80211com *ic,
                                             uint32_t bitmap_0, uint32_t bitmap_1);

/**
 * ol_ath_set_sr_per_ac() - Sends wmi cmd for Spatial Reuse per AC
 * @ic: ic pointer
 * @value: value for setting SR AC's
 * @type: Spatial Reuse type
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_set_sr_per_ac(struct ieee80211com *ic, uint32_t value,
                         enum srtype type);

/**
 * ol_ath_set_self_hesiga_sr15_enable() - send wmi command to set HESIGA SR15 value
 * @ic: pointer to ieee80211com
 * @enable: value to be set
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_set_self_hesiga_sr15_enable(struct ieee80211com *ic, uint8_t enable);

/**
 * ol_ath_set_self_psr_tx_enable() - send wmi command to set PSR TX value
 * @ic: pointer to ieee80211com
 * @enable: value to be set
 *
 * Return: 0 on success, other value on failure
 */
int ol_ath_set_self_psr_tx_enable(struct ieee80211com *ic, uint8_t enable);

/**
 * ol_ath_set_self_safety_margin_psr() - Configure safety margin value (in dB)
 * to be used to calculate SR field for PSR based Spatial Reuse.
 * @ic: Pointer to ieee80211com object
 * @margin: safety margin to be configured
 *
 * Safety margin will be used in calculating the acceptable interference level
 * for PSR based Spatial Reuse operation.
 * Accepted value as per the Specification are 0 to 5 dB (inclusive).
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_set_self_safety_margin_psr(struct ieee80211com *ic, uint8_t margin);

/**
 * ol_ath_pdev_sr_init() - Initialize SR at pdev level
 * @ic: Pointer to ol_ath_softc_net80211 corresponding to this pdev
 *
 * Initialize the Host data structures and send WMIs to the target using INI
 * values set by the user or default values
 *
 * Return: none
 */
void ol_ath_pdev_sr_init(struct ol_ath_softc_net80211 *scn);
#endif /* OBSS_PD */
#endif /* OL_IF_OBSS_H */
