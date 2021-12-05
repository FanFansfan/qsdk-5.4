/*
 * Copyright (c) 2016-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef IEEE80211_UCFG_H_
#define IEEE80211_UCFG_H_

int ieee80211_ucfg_set_essid(wlan_if_t vap, ieee80211_ssid *data, bool is_vap_restart_required);
int ieee80211_ucfg_set_beacon_interval(wlan_if_t vap, struct ieee80211com *ic,
        int value, bool is_vap_restart_required);
int ieee80211_ucfg_get_essid(wlan_if_t vap, ieee80211_ssid *data, int *nssid);
int ieee80211_ucfg_get_freq(wlan_if_t vap);
QDF_STATUS ieee80211_get_csa_chwidth_from_cwm(
        enum ieee80211_cwm_width cwm_width, u_int16_t *pcsa_ch_width);

int ieee80211_ucfg_set_freq(wlan_if_t vap, uint16_t freq);
int ieee80211_ucfg_set_freq_internal(wlan_if_t vap, uint16_t freq);
bool ieee80211_is_dot11_channel_mode_valid(struct ieee80211com *ic,
                                             int freq,
                                             int mode,
                                             int cfreq2);
int ieee80211_ucfg_set_chanswitch(wlan_if_t vaphandle, uint16_t chan_freq, u_int8_t tbtt, u_int16_t ch_width);
wlan_chan_t ieee80211_ucfg_get_current_channel(wlan_if_t vaphandle, bool hwChan);
wlan_chan_t ieee80211_ucfg_get_bss_channel(wlan_if_t vaphandle);
int ieee80211_ucfg_delete_vap(wlan_if_t vap);
int ieee80211_ucfg_set_rts(wlan_if_t vap, u_int32_t val);
int ieee80211_ucfg_set_frag(wlan_if_t vap, u_int32_t val);
int ieee80211_ucfg_set_txpow(wlan_if_t vaphandle, int txpow);
int ieee80211_ucfg_get_txpow(wlan_if_t vaphandle, int *txpow, int *fixed);
int ieee80211_ucfg_get_txpow_fraction(wlan_if_t vaphandle, int *txpow, int *fixed);
int ieee80211_ucfg_set_ap(wlan_if_t vap, u_int8_t (*des_bssid)[QDF_MAC_ADDR_SIZE]);
int ieee80211_ucfg_get_ap(wlan_if_t vap, u_int8_t *addr);
int ieee80211_ucfg_setparam(wlan_if_t vap, int param, int value, char *extra);
int ieee80211_ucfg_getparam(wlan_if_t vap, int param, int *value);
u_int32_t ieee80211_ucfg_get_maxphyrate(wlan_if_t vaphandle);
int ieee80211_ucfg_set_phymode(wlan_if_t vap, char *modestr, int len, bool reset_vap);
int ieee80211_ucfg_set_wirelessmode(wlan_if_t vap, int mode);
int ieee80211_ucfg_set_encode(wlan_if_t vap, u_int16_t length, u_int16_t flags, void *keybuf);
int ieee80211_ucfg_set_rate(wlan_if_t vap, int value);
int ieee80211_ucfg_get_phymode(wlan_if_t vap, char *modestr, u_int16_t *length, int type);
int ieee80211_ucfg_splitmac_add_client(wlan_if_t vap, u_int8_t *stamac, u_int16_t associd,
        u_int8_t qos, struct ieee80211_rateset lrates,
        struct ieee80211_rateset htrates, u_int16_t vhtrates);
int ieee80211_ucfg_splitmac_del_client(wlan_if_t vap, u_int8_t *stamac);
int ieee80211_ucfg_splitmac_authorize_client(wlan_if_t vap, u_int8_t *stamac, u_int32_t authorize);
int ieee80211_ucfg_splitmac_set_key(wlan_if_t vap, u_int8_t *macaddr, u_int8_t cipher,
        u_int16_t keyix, u_int32_t keylen, u_int8_t *keydata);
int ieee80211_ucfg_splitmac_del_key(wlan_if_t vap, u_int8_t *macaddr, u_int16_t keyix);
int ieee80211_ucfg_getstainfo(wlan_if_t vap, struct ieee80211req_sta_info *si, uint32_t *len);
int ieee80211_ucfg_getstaspace(wlan_if_t vap);

int ieee80211_convert_mode(const char *mode);
void ieee80211_convert_phymode_to_string(enum ieee80211_phymode  phymode,
                                           char *modestr, u_int16_t *length);

#if ATH_SUPPORT_IQUE
int ieee80211_ucfg_rcparams_setrtparams(wlan_if_t vap, uint8_t rt_index, uint8_t per, uint8_t probe_intvl);
int ieee80211_ucfg_rcparams_setratemask(wlan_if_t vap, uint8_t preamble,
        uint32_t mask_lower32, uint32_t mask_higher32, uint32_t mask_lower32_2);
#endif
int ieee80211_ucfg_rtt_params(struct ieee80211com *ic, wlan_if_t vap,
                              struct ieee80211_wlanconfig *config);
int ieee80211_ucfg_nawds(wlan_if_t vap, struct ieee80211_wlanconfig *config);
int ieee80211_ucfg_me_list(wlan_if_t vap, struct ieee80211_wlanconfig *config);
int ieee80211_ucfg_ald(wlan_if_t vap, struct ieee80211_wlanconfig *config);
int ieee80211_ucfg_hmwds(wlan_if_t vap, struct ieee80211_wlanconfig *config, int buffer_len);
int ieee80211_ucfg_wnm(wlan_if_t vap, struct ieee80211_wlanconfig *config);
int ieee80211_ucfg_vendorie(wlan_if_t vap, struct ieee80211_wlanconfig_vendorie *vie);
int ieee80211_ucfg_addie(wlan_if_t vap, struct ieee80211_wlanconfig_ie *ie_buffer);
int ieee80211_ucfg_nac(wlan_if_t vap, struct ieee80211_wlanconfig *config);
int ieee80211_ucfg_nac_rssi(wlan_if_t vap, struct ieee80211_wlanconfig *config);
int ieee80211_ucfg_isolation(wlan_if_t vap, struct ieee80211_wlanconfig *config);
int ieee80211_ucgf_scanlist(wlan_if_t vap);
size_t scan_space(wlan_scan_entry_t se, u_int16_t *ielen);
QDF_STATUS get_scan_space(void *arg, wlan_scan_entry_t se);
QDF_STATUS get_scan_space_rep_move(void *arg, wlan_scan_entry_t se);
QDF_STATUS get_scan_result(void *arg, wlan_scan_entry_t se);
int ieee80211_ucfg_get_best_otherband_uplink_bssid(wlan_if_t vap, char *bssid);
int ieee80211_ucfg_get_otherband_uplink_bssid(wlan_if_t vap, char *bssid);
int ieee80211_ucfg_set_otherband_bssid(wlan_if_t vap, int *val);
int ieee80211_ucfg_scanlist(wlan_if_t vap);
void ieee80211_ucfg_setmaxrate_per_client(void *arg, wlan_node_t node);
void get_sta_space(void *arg, wlan_node_t node);
uint8_t get_phymode_from_chwidth(struct ieee80211com *ic, struct ieee80211_node *ni);
void get_sta_info(void *arg, wlan_node_t node);
int ieee80211_ucfg_setwmmparams(void *osif, int wmmparam, int ac, int bss, int value);
int ieee80211_ucfg_getwmmparams(void *osif, int wmmparam, int ac, int bss);
int ieee80211_ucfg_set_peer_nexthop(void *osif, uint8_t *mac, int32_t if_num);
int ieee80211_ucfg_set_vlan_type( void *osif, uint8_t default_vlan, uint8_t port_vlan);
int ieee80211_ucfg_set_hlos_tid_override(void *osif, uint8_t val, bool is_mscs);
int ieee80211_ucfg_get_hlos_tid_override(void *osif);
int ieee80211_ucfg_set_muedcaparams(void *osif, uint8_t muedcaparam,
        uint8_t ac, uint8_t value);
int ieee80211_ucfg_set_peer_tid_latency_enable(void *osif, uint8_t val);
int ieee80211_ucfg_get_peer_tid_latency_enable(void *osif);
int ieee80211_ucfg_set_vap_mesh_tid(void *osif, uint8_t val);
int ieee80211_ucfg_get_vap_mesh_tid(void *osif, uint8_t *tid, uint8_t *dl_ul_enable);;
struct ieee80211vap *ieee80211_ucfg_get_txvap(struct ieee80211com *ic);
#if QCA_SUPPORT_GPR
int ieee80211_ucfg_send_gprparams(wlan_if_t vap, uint8_t value);
#endif
int ieee80211_ucfg_get_muedcaparams(void *osif, uint8_t muedcaparam, uint8_t ac);
int ieee80211_ucfg_setmlme(struct ieee80211com *ic, void *osif, struct ieee80211req_mlme *mlme);
int ieee80211_ucfg_cfr_params(struct ieee80211com *ic, wlan_if_t vap, struct ieee80211_wlanconfig *config);
extern unsigned int g_unicast_deauth_on_stop;
extern unsigned int g_csa_max_rx_wait_time;
int ieee80211_ucfg_get_quality(wlan_if_t vap, void *iq);
int ieee80211_get_chan_nf(struct ieee80211com *ic, int16_t *nf_val);
int ieee80211_ucfg_send_probereq(wlan_if_t vap, int val);
QDF_STATUS check_inter_band_switch_compatibility(struct ieee80211com *ic);
int ieee80211_ucfg_set_txvap(wlan_if_t vap);
int ieee80211_ucfg_reset_txvap(wlan_if_t vap, uint8_t force);
int ieee80211_ucfg_bringdown_txvap(wlan_if_t vap);
void ieee80211_ucfg_copy_txvap_param(struct ieee80211vap *vap,
                                     struct ieee80211vap *last_txvap);
int ieee80211_ucfg_reset_mesh_nawds_txvap(wlan_if_t vap);

/*
 * IEEE80211_SKIP_WIDEBAND_SWITCH:
 * Wideband channel sanity is not checked for the following:
 * (1) If there are no beaconing AP VAPs present
 *     i.e., the channel change request came from a non-AP VAP and therefore
 *     there is no need for a mode switch or security compliancy check.
 * (2) If the desired mode or channel is not set
 *     i.e., bring-up channel should not be restricted.
 *     Security compliancy will be checked during start_ap() and MBSS
 *     mode compliancy is not required since mode switch will not
 *     be performed to honor the bring-up MBSS mode.
 * (3) If the target frequency is zero
 *     i.e., ACS invokation from userspace need not have a wideband check
 *     since the channel is still not determined
 * (4) If the transition is not a wideband channel switch
 *     Don't restrict intraband channel changes.
 */

#define IEEE80211_SKIP_WIDEBAND_SWITCH(__vap, __target_chan)           \
    (!ieee80211_get_num_beacon_ap_vaps((__vap)->iv_ic) ||              \
     !(__vap)->iv_des_mode ||                                          \
     !((__vap)->vdev_obj->vdev_mlme.des_chan)->ch_freq ||              \
     !(__target_chan) ||                                               \
     !IEEE80211_ARE_CHANS_INTERWIDEBAND((__vap)->iv_ic->ic_curchan,    \
                                        (__target_chan)))              \

#endif //IEEE80211_UCFG_H_
