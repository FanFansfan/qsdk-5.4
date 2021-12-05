/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * Copyright (c) 2008-2010, Atheros Communications Inc.
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

#ifndef __ACFG_API_MODIFIED_H
#define __ACFG_API_MODIFIED_H

#include <qcatools_lib.h>
#include <qdf_types.h>
#include <acfg_api_types.h>
#ifndef BUILD_X86
#include <ieee80211_external_config.h>
#else
#include <bsd/string.h>
#endif

uint32_t
acfg_get_err_status(void);


int compare_string(char *str1, char *str2);

uint32_t
acfg_wpa_supplicant_get(acfg_wlan_profile_vap_params_t *vap_params);

extern uint32_t
acfg_wlan_iface_present(char *ifname);

uint32_t
acfg_hostapd_get(acfg_wlan_profile_vap_params_t *vap_params);

int get_uint32(char *str, uint32_t *val);

uint32_t
acfg_wlan_vap_profile_get (acfg_wlan_profile_vap_params_t *vap_params);

uint32_t
acfg_hostapd_getconfig(uint8_t *vap_name, char *reply_buf);
uint32_t
acfg_wlan_profile_get (acfg_wlan_profile_t *profile);
uint32_t
acfg_assoc_sta_info(uint8_t *vap_name, acfg_sta_info_req_t *sinfo);
/**
 * @brief Get the phymode
 *
 * @param vap_name
 * @param mode
 *
 * @return
 */
uint32_t
acfg_get_phymode(uint8_t *vap_name, uint32_t *mode);
/**
 * @brief get Vap vendor param
 *
 * @param vap_name
 * @param param
 * @param data
 * @param type
 * @return
 */
uint32_t
acfg_get_vap_vendor_param(uint8_t *vap_name, \
        acfg_vendor_param_vap_t param, uint8_t *data,
        uint32_t *type);
/**
 * @brief Get the Channel (IEEE) number
 *
 * @param wifi_name (Radio)
 * @param chan_num
 * @param chan_band
 */
uint32_t
acfg_get_channel(uint8_t *wifi_name, uint8_t *chan_num, uint8_t *chan_band);

uint32_t
acfg_get_tx_antenna(uint8_t *radio_name,  uint32_t *mask);
uint32_t
acfg_get_rx_antenna(uint8_t *radio_name,  uint32_t *mask);
uint32_t
acfg_send_raw_multi(uint8_t  *vap_name, uint8_t *pkt_buf, uint32_t len, uint8_t type, uint16_t chan, uint8_t chan_band, uint8_t nss, uint8_t preamble, uint8_t mcs, uint8_t retry, uint8_t power, uint16_t scan_dur);

uint32_t
acfg_send_raw_cancel(uint8_t  *vap_name);

uint32_t
acfg_offchan_rx(uint8_t  *vap_name, uint16_t chan, uint16_t scan_dur, char *params[]);

#if QCA_SUPPORT_GPR
uint32_t
acfg_start_gpr(uint8_t  *vap_name, uint8_t *pkt_buf, uint32_t len, uint32_t period, uint8_t nss, uint8_t preamble, uint8_t mcs);

uint32_t
acfg_send_gpr_cmd(uint8_t  *vap_name, uint32_t command);
#endif
uint32_t
acfg_set_muedca_ecwmin(uint8_t *vap, uint32_t ac, uint32_t value);
uint32_t
acfg_get_muedca_ecwmin(uint8_t *vap, uint32_t ac, uint32_t *value);
uint32_t
acfg_set_muedca_ecwmax(uint8_t *vap, uint32_t ac, uint32_t value);
uint32_t
acfg_get_muedca_ecwmax(uint8_t *vap, uint32_t ac, uint32_t *value);
uint32_t
acfg_set_muedca_aifsn(uint8_t *vap, uint32_t ac, uint32_t value);
uint32_t
acfg_get_muedca_aifsn(uint8_t *vap, uint32_t ac, uint32_t *value);
uint32_t
acfg_set_muedca_acm(uint8_t *vap, uint32_t ac, uint32_t value);
uint32_t
acfg_get_muedca_acm(uint8_t *vap, uint32_t ac, uint32_t *value);
uint32_t
acfg_set_muedca_timer(uint8_t *vap, uint32_t ac, uint32_t value);
uint32_t
acfg_get_muedca_timer(uint8_t *vap, uint32_t ac, uint32_t *value);


uint32_t
acfg_mon_listmac(uint8_t *vap_name);

uint32_t
acfg_mon_enable_filter(uint8_t *vap_name, u_int32_t val);

uint32_t
acfg_mon_addmac(uint8_t *vap_name, uint8_t *addr);

uint32_t
acfg_mon_delmac(uint8_t *vap_name, uint8_t *addr);

uint32_t
acfg_alloc_profile(acfg_wlan_profile_t **new_profile, acfg_wlan_profile_t **curr_profile);

uint32_t
acfg_populate_profile(acfg_wlan_profile_t *curr_profile, char *radioname);

void
acfg_get_wep_str(char *str, uint8_t *key, uint8_t key_len, uint16_t str_max_len);

#endif
