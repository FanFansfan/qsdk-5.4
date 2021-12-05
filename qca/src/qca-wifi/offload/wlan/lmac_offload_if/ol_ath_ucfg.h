/*
 * Copyright (c) 2016-2017,2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary . Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef OL_ATH_UCFG_H_
#define OL_ATH_UCFG_H_
/*
 ** "split" of config param values, since they are all combined
 ** into the same table.  This value is a "shift" value for ATH parameters
 */
#include <cfg80211_ven_cmd.h>

#define OL_ATH_PARAM_SHIFT     0x1000
#define OL_SPECIAL_PARAM_SHIFT 0x2000
#define OL_MGMT_RETRY_LIMIT_MIN (1)
#define OL_MGMT_RETRY_LIMIT_MAX (15)
#define ATH_XIOCTL_UNIFIED_UTF_CMD  0x1000
#define ATH_XIOCTL_UNIFIED_UTF_RSP  0x1001
#define ATH_FTM_UTF_CMD 0x1002
#define MAX_UTF_LENGTH 2048

#define HE_SR_NON_SRG_OBSS_PD_MAX_THRESH_OFFSET_VAL 20
#define HE_SR_SRG_OBSS_PD_MAX_ALLOWED_OFFSET_VAL    20
enum {
    HE_SR_PSR_ENABLE                        = 1,
    HE_SR_NON_SRG_OBSSPD_ENABLE             = 2,
    HE_SR_SR15_ENABLE                       = 3,
    HE_SR_SRG_OBSSPD_ENABLE                 = 4,
    HE_SR_ENABLE_PER_AC                     = 5,
};

enum {
    HE_SRP_IE_SRG_BSS_COLOR_BITMAP                 = 1,
    HE_SRP_IE_SRG_PARTIAL_BSSID_BITMAP             = 2,
};

enum {
    SR_SELF_OBSS_PD_TX_ENABLE                  = 0,
    SR_SELF_OBSS_PD_THRESHOLD_DB               = 1,
    SR_SELF_SRG_BSS_COLOR_BITMAP               = 2,
    SR_SELF_SRG_PARTIAL_BSSID_BITMAP           = 3,
    SR_SELF_ENABLE_PER_AC                      = 5,
    SR_SELF_HESIGA_SR15_ENABLE                 = 6,
    SR_SELF_SRG_OBSS_COLOR_ENABLE_BITMAP       = 7,
    SR_SELF_SRG_OBSS_BSSID_ENABLE_BITMAP       = 8,
    SR_SELF_NON_SRG_OBSS_COLOR_ENABLE_BITMAP   = 9,
    SR_SELF_NON_SRG_OBSS_BSSID_ENABLE_BITMAP   = 10,
    SR_SELF_PSR_TX_ENABLE                      = 11,
    SR_SELF_SAFETY_MARGIN_PSR                  = 12,
    SR_SELF_OBSS_PD_THRESHOLD_DBM              = 13,
};

enum {
    SET_HE_BSSCOLOR     = 1,
    ENABLE_MESH_MODE    = 2,
};

/* Forward declaration of structs to avoid warnings */
struct ol_ath_softc_net80211;
struct ieee80211_clone_params;
struct ol_ath_softc_net80211;
struct ieee80211_profile;
struct packet_power_info_params;
struct ieee80211_rateset;
struct ieee80211_pkt_capture_enh;
enum ieee80211_phymode;
struct ieee80211com;
struct ieee80211_rx_pkt_protocol_tag;
struct ieee80211_rx_flow_tag;

int ol_ath_ucfg_setparam(void *vscn, int param, int value);
int ol_ath_ucfg_getparam(void *vscn, int param, int *val);
int ol_ath_ucfg_set_country(void *vscn, char *cntry);
int ol_ath_ucfg_get_country(void *vscn, char *str);
int ol_ath_ucfg_set_mac_address(void *vscn, char *addr);
int ol_ath_ucfg_set_smart_antenna_param(void *vscn, char *val);
int ol_ath_ucfg_get_smart_antenna_param(void *vscn, char *val);
void ol_ath_ucfg_txrx_peer_stats(void *vscn, char *addr);
void ol_ath_set_ba_timeout(void *vscn, uint8_t ac, uint32_t value);
void ol_ath_get_ba_timeout(void *vscn, uint8_t ac, uint32_t *value);
int ol_ath_ucfg_create_vap(struct ol_ath_softc_net80211 *scn, struct ieee80211_clone_params *cp, char *dev_name);
/*Function to handle UTF commands from QCMBR and FTM daemon */
int ol_ath_ucfg_utf_unified_cmd(void *data, int cmd, char *userdata, unsigned int length);
int ol_ath_ucfg_get_ath_stats(void *vscn, void *vasc);
int ol_ath_ucfg_get_vap_info(struct ol_ath_softc_net80211 *scn, struct ieee80211_profile *profile);
int ol_ath_ucfg_get_nf_dbr_dbm_info(struct ol_ath_softc_net80211 *scn);
int ol_ath_ucfg_get_packet_power_info(struct ol_ath_softc_net80211 *scn, struct packet_power_info_params *param);
int ol_ath_ucfg_phyerr(void *vscn, void *vad);
int ol_ath_ucfg_ctl_set(struct ol_ath_softc_net80211 *scn, ath_ctl_table_t *ptr);
int ol_ath_ucfg_set_op_support_rates(struct ol_ath_softc_net80211 *scn, struct ieee80211_rateset *target_rs);
int ol_ath_ucfg_btcoex_duty_cycle(void *vscn, u_int32_t period, u_int32_t duration);
int ol_ath_ucfg_set_muedca_mode(void *vscn, uint8_t mode);
int ol_ath_ucfg_get_muedca_mode(void *vscn, int *value);
int ol_ath_ucfg_set_non_ht_dup(void *vscn, uint8_t frame, bool enable);
int ol_ath_ucfg_get_non_ht_dup(void *vscn, uint8_t frame, uint8_t *value);
int ol_ath_ucfg_set_col_6ghz_rnr(void *vscn, uint8_t mode, uint8_t frm_val);
int ol_ath_ucfg_get_col_6ghz_rnr(void *vscn, uint8_t *value);
#if DBG_LVL_MAC_FILTERING
int ol_ath_ucfg_set_dbglvlmac(struct ieee80211vap *vap, uint8_t *mac_addr, uint8_t mac_addr_len, uint8_t value);
int ol_ath_ucfg_get_dbglvlmac(struct ieee80211vap *vap, uint8_t value);
#endif
int ol_ath_ucfg_get_radio_supported_rates(struct ol_ath_softc_net80211 *scn,
    enum ieee80211_phymode mode,
    struct ieee80211_rateset *target_rs);

int ol_ath_ucfg_set_aggr_burst(void *scn, uint32_t ac, uint32_t duration);
int ol_ath_ucfg_set_atf_sched_dur(void *vscn, uint32_t ac, uint32_t duration);
int ol_ath_extended_commands(struct net_device *dev, void *vextended_cmd);
int ol_ath_iw_get_aggr_burst(struct net_device *dev, void *vinfo, void *w, char *extra);
void ol_ath_get_dp_fw_peer_stats(void *vscn, char *extra, uint8_t caps);
void ol_ath_get_dp_htt_stats (void *vscn, void *data, uint32_t data_len);
void ol_ath_get_cp_wmi_stats (void *vscn, void *buf_ptr, uint32_t buf_len);
int ol_ath_get_target_pdev_id(void *vscn, uint32_t *val);
#if ATH_SUPPORT_ICM
int ol_get_nominal_nf(struct ieee80211com *ic);
#endif /* ATH_SUPPORT_ICM */
int ol_ath_ucfg_set_he_mesh_config(void *vscn, void *args);
int ol_ath_ucfg_get_he_mesh_config(void *vscn, int *value, uint8_t subcmd);
#if OBSS_PD
int ol_ath_ucfg_set_he_sr_config(void *vscn, uint8_t param, uint8_t value,
    uint8_t data1, uint8_t data2);
int ol_ath_ucfg_get_he_sr_config(void *vscn, uint8_t param, uint32_t *value);
int ol_ath_ucfg_set_he_srg_bitmap(void *vscn, uint32_t *val, uint32_t param);
int ol_ath_ucfg_get_he_srg_bitmap(void *vscm, uint32_t *val, uint32_t param);
int ol_ath_ucfg_set_sr_self_config(void *vscn, uint32_t param,
	void *data, uint32_t data_len, uint32_t value);
int ol_ath_ucfg_get_sr_self_config(void *vscm, uint8_t param, char value[], size_t length);
#endif /* OBSS PD */
int ol_ath_ucfg_set_pcp_tid_map(void *vscn, uint32_t pcp, uint32_t tid);
int ol_ath_ucfg_get_pcp_tid_map(void *vscn, uint32_t pcp, uint32_t *value);
int ol_ath_ucfg_set_tidmap_prty(void *vscn, uint32_t val);
int ol_ath_ucfg_get_tidmap_prty(void *vscn, uint32_t *val);
int ol_ath_ucfg_set_nav_override_config(void *vscn, uint8_t value, uint32_t threshold);
int ol_ath_ucfg_get_nav_override_config(void *vscn, int *value);

#ifdef WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG
int ol_ath_ucfg_set_rx_pkt_protocol_tagging(void *vscn,
            struct ieee80211_rx_pkt_protocol_tag *rx_pkt_protocol_tag_info);
#ifdef WLAN_SUPPORT_RX_TAG_STATISTICS
int ol_ath_ucfg_dump_rx_pkt_protocol_tag_stats(void *vscn, uint32_t protocol_type);
#endif /* WLAN_SUPPORT_RX_TAG_STATISTICS */
#endif /* WLAN_SUPPORT_RX_PROTOCOL_TYPE_TAG */
#ifdef WLAN_SUPPORT_RX_FLOW_TAG
int ol_ath_ucfg_rx_flow_tag_op(void *vscn, struct ieee80211_rx_flow_tag *rx_flow_tag_info);
#endif /* WLAN_SUPPORT_RX_FLOW_TAG */
#if defined(WLAN_TX_PKT_CAPTURE_ENH) || defined(WLAN_RX_PKT_CAPTURE_ENH)
int ol_ath_ucfg_set_peer_pkt_capture(void *vscn,
                          struct ieee80211_pkt_capture_enh *peer_info);
#endif /* WLAN_TX_PKT_CAPTURE_ENH || WLAN_RX_PKT_CAPTURE_ENH */

#endif /* OL_ATH_UCFG_H_ */

