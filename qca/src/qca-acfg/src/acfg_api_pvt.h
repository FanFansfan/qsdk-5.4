/*
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

#ifndef __ACFG_API_PVT_H
#define __ACFG_API_PVT_H

#include <stdint.h>
#include <qdf_types.h>
#include <acfg_api_types.h>
#include <acfg_api.h>

#define ACFG_CONF_FILE "/etc/acfg_common.conf"
#define ACFG_APP_CTRL_IFACE "/tmp/acfg-app"

#define ACFG_MAX_RADIO 4

#define IEEE80211_IOCTL_ATF_ADDSSID     0xFF01
#define IEEE80211_IOCTL_ATF_DELSSID     0xFF02
#define IEEE80211_IOCTL_ATF_ADDSTA      0xFF03
#define IEEE80211_IOCTL_ATF_DELSTA      0xFF04
#define IEEE80211_IOCTL_ATF_SHOWATFTBL  0xFF05
#define IEEE80211_IOCTL_ATF_SHOWAIRTIME 0xFF06
#define IEEE80211_IOCTL_ATF_FLUSHTABLE  0xFF07                 /* Used to Flush the ATF table entries */

#define IEEE80211_IOCTL_ATF_ADDGROUP    0xFF08
#define IEEE80211_IOCTL_ATF_CONFIGGROUP 0xFF09
#define IEEE80211_IOCTL_ATF_DELGROUP    0xFF0a
#define IEEE80211_IOCTL_ATF_SHOWGROUP   0xFF0b

#define IEEE80211_IOCTL_ATF_ADDSTA_TPUT     0xFF0C
#define IEEE80211_IOCTL_ATF_DELSTA_TPUT     0xFF0D
#define IEEE80211_IOCTL_ATF_SHOW_TPUT       0xFF0E

#define IEEE80211_IOCTL_ATF_GROUPSCHED      0XFF0F
#define IEEE80211_IOCTL_ATF_ADDAC           0xFF10
#define IEEE80211_IOCTL_ATF_DELAC           0xFF11
#define IEEE80211_IOCTL_ATF_SHOWSUBGROUP    0xFF12

typedef struct {
    uint8_t new_vap_idx[ACFG_MAX_VAPS];
    uint8_t cur_vap_idx[ACFG_MAX_VAPS];
    uint8_t num_vaps;
} acfg_wlan_profile_vap_list_t;

typedef struct vap_list {
    char iface[ACFG_MAX_VAPS * ACFG_MAX_RADIO][ACFG_MAX_IFNAME];
    int num_iface;
} acfg_vap_list_t;


/**
 * @brief Send Request Data in a OS specific way
 *
 * @param hdl
 * @param req (Request Structure)
 *
 * @return
 */
uint32_t
acfg_os_send_req(uint8_t  *ifname, acfg_os_req_t  *req);

uint32_t
acfg_os_check_str(uint8_t *src, uint32_t maxlen);

uint32_t
acfg_os_strcpy(char  *dst, const char *src, uint32_t  maxlen);

uint32_t
acfg_os_strlcat(char  *dst, const char *src, uint32_t  maxlen);

uint32_t
acfg_os_snprintf(char *str, uint32_t size, const char *fmt, ...);

uint32_t
acfg_os_cmp_str(uint8_t *str1, uint8_t *str2, uint32_t maxlen) ;

uint32_t
acfg_log(uint8_t *msg);

uint8_t
acfg_mhz2ieee(uint32_t);

uint32_t
acfg_hostapd_modify_bss(acfg_wlan_profile_vap_params_t *vap_params,
        acfg_wlan_profile_vap_params_t *cur_vap_params,
        int8_t *sec);

uint32_t
acfg_hostapd_delete_bss(acfg_wlan_profile_vap_params_t *vap_params);

uint32_t
acfg_hostapd_add_bss(acfg_wlan_profile_vap_params_t *vap_params, int8_t *sec);

uint32_t
acfg_get_iface_list(acfg_vap_list_t *list, int *count);

uint32_t acfg_get_vap_iface_names(acfg_vap_list_t *list, int *count);

int
acfg_get_ctrl_iface_path(char *filename, char *hapd_ctrl_iface_dir,
        char *wpa_supp_ctrl_iface_dir);
int acfg_ctrl_req(uint8_t *ifname, char *cmd, size_t cmd_len, char *replybuf,
        uint32_t *reply_len, acfg_opmode_t opmode);
void
acfg_update_wps_config_file(uint8_t *ifname, char *prefix, char *data, int len);

void
acfg_update_wps_dev_config_file(acfg_wlan_profile_vap_params_t *vap_params, int force_update);

void acfg_set_wps_default_config(acfg_wlan_profile_vap_params_t *vap_params);

void acfg_set_hs_iw_vap_param(acfg_wlan_profile_vap_params_t *vap_params);

uint32_t
acfg_wlan_iface_up(uint8_t  *ifname, acfg_wlan_profile_vap_params_t *vap_params);

uint32_t
acfg_wlan_iface_down(uint8_t *ifname, acfg_wlan_profile_vap_params_t *vap_params);

void
acfg_rem_wps_config_file(uint8_t *ifname);

void
acfg_rem_dpp_config_file(uint8_t *ifname);

uint32_t
acfg_dpp_bootstrap_gen(char *ifname, char *params);

uint32_t
acfg_dpp_bootstrap_remove(char *ifname, char *params);

uint32_t
acfg_dpp_bootstrap_info(char *ifname, char *params);

uint32_t
acfg_dpp_configurator_add(char *ifname, char *params);

uint32_t
acfg_dpp_configurator_get_key(char *ifname, char *params);

uint32_t
acfg_dpp_configurator_sign(char *ifname, char *params);

uint32_t
acfg_dpp_configurator_remove(char *ifname, char *params);

uint32_t
acfg_dpp_bootstrap_get_uri(char *ifname, char *params);

uint32_t
acfg_dpp_qr_code(char *ifname, char *params);

uint32_t
acfg_dpp_bootstrap_set(char *ifname, char *params);

uint32_t
acfg_dpp_configurator_params(char *ifname, char *params);

uint32_t
acfg_dpp_auth_init(char *ifname, char *params);

uint32_t
acfg_dpp_listen(char *ifname, char *params);

uint32_t
acfg_dpp_stop_listen(char *ifname);

uint32_t
acfg_dpp_chirp(char *ifname, char *params);

uint32_t
acfg_dpp_stop_chirp(char *ifname);

uint32_t
acfg_dpp_controller_start(char *ifname, char *params);

uint32_t
acfg_dpp_controller_stop(char *ifname);

uint32_t
acfg_dpp_pkex_add(char *ifname, char *params);

uint32_t
acfg_dpp_pkex_remove(char *ifname, char *params);

uint32_t
acfg_dpp_mud_url_set(char *ifname, char *params);

uint32_t
acfg_dpp_pfs_set(char *ifname, char *params);

uint32_t
acfg_dpp_controller_set(char *ifname, char *params);

void acfg_reset_errstr(void);

void _acfg_log_errstr(const char *fmt, ...);
void _acfg_print(const char *fmt, ...);

//Prints all the debug messages
#define ACFG_DEBUG 0
//Prints only the error messages
#define ACFG_DEBUG_ERROR 0

#if ACFG_DEBUG
#undef ACFG_DEBUG_ERROR
#define ACFG_DEBUG_ERROR 1
#define acfg_print(fmt, ...) _acfg_print(fmt, ##__VA_ARGS__)
#else
#define acfg_print(fmt, ...)
#endif

#if ACFG_DEBUG_ERROR
#define acfg_log_errstr(fmt, ...) _acfg_print(fmt, ##__VA_ARGS__)
#else
#define acfg_log_errstr(fmt, ...) _acfg_log_errstr(fmt, ##__VA_ARGS__)
#endif

#define ACFG_RATE_BASIC            (0x80)
#define ACFG_RATE_VAL              (0x7f)

#define MAX_PAYLOAD 8192
#define MAX_CMD_LEN 128
#endif
