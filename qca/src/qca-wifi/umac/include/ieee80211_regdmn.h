/*
 * Copyright (c) 2011,2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 */

#ifndef _NET80211_IEEE80211_REGDMN_H
#define _NET80211_IEEE80211_REGDMN_H

#include <ieee80211_var.h>

int ieee80211_set_country_code(struct ieee80211com *ic, char* isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd);
void ieee80211_update_spectrumrequirement(struct ieee80211vap *vap, bool *thread_started);
void ieee80211_set_regclassids(struct ieee80211com *ic, const u_int8_t *regclassids, u_int nregclass);

#define FULL_BW 20
#define HALF_BW 10
#define QRTR_BW  5

#define OPCLASS_TBL_MAX 9

#define BW_WITHIN(min, bw, max) ((min) <= (bw) && (bw) <= (max))
/* Get N bits from the index position */
#define REG_GET_BITS(_val,_index,_num_bits) (((_val) >> (_index)) & \
    ((1 << (_num_bits)) - 1))
/* Set a value to a variable, N bits from the index position */
#define REG_SET_BITS(_var,_index,_num_bits,_val)                    \
    do {                                                            \
    (_var) &= ~(((1 << (_num_bits)) - 1) << (_index));              \
    (_var) |= (((_val) & ((1 << (_num_bits)) - 1)) << (_index));    \
    } while (0)

#define HW_OP_CLASS  apcap->hwcap.opclasses[(*total_n_sup_opclass)]
#define AP_CAP       reg_ap_cap[idx]
#define MAP_OP_CHAN  map_op_chan[(*total_n_sup_opclass)]

/* Offset between two HT20 channels is 20MHz */
#define CHAN_HT40_OFFSET 20

#define MAX_CHANNELS_PER_OPERATING_CLASS  24

#define WIRELESS_11AX_MODES ( HOST_REGDMN_MODE_11AXG_HE20 \
                             | HOST_REGDMN_MODE_11AXG_HE40PLUS \
                             | HOST_REGDMN_MODE_11AXG_HE40MINUS \
                             | HOST_REGDMN_MODE_11AXA_HE20 \
                             | HOST_REGDMN_MODE_11AXA_HE40PLUS \
                             | HOST_REGDMN_MODE_11AXA_HE40MINUS \
                             | HOST_REGDMN_MODE_11AXA_HE80 \
                             | HOST_REGDMN_MODE_11AXA_HE160 \
                             | HOST_REGDMN_MODE_11AXA_HE80_80)

#define WIRELESS_11AC_MODES (HOST_REGDMN_MODE_11AC_VHT20 \
                             | HOST_REGDMN_MODE_11AC_VHT40PLUS \
                             | HOST_REGDMN_MODE_11AC_VHT40MINUS \
                             | HOST_REGDMN_MODE_11AC_VHT80 \
                             | HOST_REGDMN_MODE_11AC_VHT160 \
                             | HOST_REGDMN_MODE_11AC_VHT80_80)

#define WIRELESS_11N_MODES   (HOST_REGDMN_MODE_11NG_HT20 \
                              | HOST_REGDMN_MODE_11NA_HT20 \
                              | HOST_REGDMN_MODE_11NG_HT40PLUS \
                              | HOST_REGDMN_MODE_11NG_HT40MINUS \
                              | HOST_REGDMN_MODE_11NA_HT40PLUS \
                              | HOST_REGDMN_MODE_11NA_HT40MINUS)

#define WIRELESS_11G_MODES   (HOST_REGDMN_MODE_PUREG \
                              | HOST_REGDMN_MODE_11G \
                              | HOST_REGDMN_MODE_108G)

#define WIRELESS_11B_MODE   (HOST_REGDMN_MODE_11B)

#define WIRELESS_11A_MODE   (HOST_REGDMN_MODE_11A \
                             | HOST_REGDMN_MODE_TURBO \
                             | HOST_REGDMN_MODE_108A \
                             | HOST_REGDMN_MODE_11A_HALF_RATE \
                             | HOST_REGDMN_MODE_11A_QUARTER_RATE)

#define WIRELESS_6G_MODES (HOST_REGDMN_MODE_11AXA_HE20 \
                           | HOST_REGDMN_MODE_11AXA_HE40PLUS \
                           | HOST_REGDMN_MODE_11AXA_HE40MINUS \
                           | HOST_REGDMN_MODE_11AXA_HE80 \
                           | HOST_REGDMN_MODE_11AXA_HE160 \
                           | HOST_REGDMN_MODE_11AXA_HE80_80)

#define WIRELESS_5G_MODES (HOST_REGDMN_MODE_11AXA_HE20 \
                           | HOST_REGDMN_MODE_11AXA_HE40PLUS \
                           | HOST_REGDMN_MODE_11AXA_HE40MINUS \
                           | HOST_REGDMN_MODE_11AXA_HE80 \
                           | HOST_REGDMN_MODE_11AXA_HE160 \
                           | HOST_REGDMN_MODE_11AXA_HE80_80 \
                           | HOST_REGDMN_MODE_11AC_VHT20 \
                           | HOST_REGDMN_MODE_11AC_VHT40PLUS \
                           | HOST_REGDMN_MODE_11AC_VHT40MINUS \
                           | HOST_REGDMN_MODE_11AC_VHT80 \
                           | HOST_REGDMN_MODE_11AC_VHT160 \
                           | HOST_REGDMN_MODE_11AC_VHT80_80 \
                           | HOST_REGDMN_MODE_11NA_HT20 \
                           | HOST_REGDMN_MODE_11NA_HT40PLUS \
                           | HOST_REGDMN_MODE_11NA_HT40MINUS \
                           | HOST_REGDMN_MODE_11A \
                           | HOST_REGDMN_MODE_TURBO \
                           | HOST_REGDMN_MODE_108A \
                           | HOST_REGDMN_MODE_11A_HALF_RATE \
                           | HOST_REGDMN_MODE_11A_QUARTER_RATE)

#define WIRELESS_49G_MODES (HOST_REGDMN_MODE_11A \
                            | HOST_REGDMN_MODE_11A_HALF_RATE \
                            | HOST_REGDMN_MODE_11A_QUARTER_RATE)

#define WIRELESS_2G_MODES (HOST_REGDMN_MODE_11AXG_HE20 \
                           | HOST_REGDMN_MODE_11AXG_HE40PLUS \
                           | HOST_REGDMN_MODE_11AXG_HE40MINUS \
                           | HOST_REGDMN_MODE_11NG_HT20 \
                           | HOST_REGDMN_MODE_11NG_HT40PLUS \
                           | HOST_REGDMN_MODE_11NG_HT40MINUS \
                           | HOST_REGDMN_MODE_PUREG \
                           | HOST_REGDMN_MODE_11G \
                           | HOST_REGDMN_MODE_108G \
                           | HOST_REGDMN_MODE_11B)

typedef enum {
	IEEE80211_MIN_2G_CHANNEL = 1,
	IEEE80211_MAX_2G_CHANNEL = 14,
	IEEE80211_MIN_5G_CHANNEL = 36,
	IEEE80211_MAX_5G_CHANNEL = 169,
} IEEE80211_MIN_MAX_CHANNELS;

/* Supported STA Bands*/
typedef enum {
	IEEE80211_2G_BAND,
	IEEE80211_5G_BAND,
	IEEE80211_6G_BAND,
	IEEE80211_INVALID_BAND,
} IEEE80211_STA_BAND;

typedef struct regdmn_op_class_map {
    uint8_t op_class;
    enum ieee80211_cwm_width ch_width;
    uint8_t sec20_offset;
    uint8_t ch_set[MAX_CHANNELS_PER_OPERATING_CLASS];
} regdmn_op_class_map_t;

int regdmn_get_current_chan_txpower(struct wlan_objmgr_pdev *pdev);

void regdmn_get_curr_chan_and_opclass(struct wlan_objmgr_vdev *vdev,
                                      uint8_t *chan_num,
                                      uint8_t *opclass);

void regdmn_get_supp_opclass_list(struct wlan_objmgr_pdev *pdev,
                                  uint8_t *opclass_list,
                                  uint8_t *num_supp_op_class,
                                  bool global_tbl_lookup);

void regdmn_update_ic_channels(
        struct wlan_objmgr_pdev *pdev,
        struct ieee80211com *ic,
        uint32_t mode_select,
        struct regulatory_channel *curr_chan_list,
        struct ieee80211_ath_channel *chans,
        u_int maxchans,
        u_int *nchans,
        qdf_freq_t low_2g,
        qdf_freq_t high_2g,
        qdf_freq_t low_5g,
        qdf_freq_t high_5g);
/* Get sta band capabilities from supporting opclass */
uint8_t regdmn_get_band_cap_from_op_class(uint8_t no_of_opclass,
                                          const  uint8_t *opclass);

uint16_t regdmn_get_min_6ghz_chan_freq(void);

uint16_t regdmn_get_max_6ghz_chan_freq(void);

uint16_t regdmn_get_min_5ghz_chan_freq(void);

uint16_t regdmn_get_max_5ghz_chan_freq(void);

void regdmn_get_channel_list_from_op_class(
        uint8_t reg_class,
        struct ieee80211_node *ni);
uint8_t regdmn_get_opclass (uint8_t *country_iso, struct ieee80211_ath_channel *channel);

uint8_t regdmn_get_map_opclass(struct wlan_objmgr_pdev *pdev,
                               mapapcap_t *apcap,
                               struct map_op_chan_t *map_op_chan,
                               struct map_op_class_t *map_op_class,
                               bool global_tbl_lookup,
                               bool dfs_required);

/** ieee80211_send_tpc_power_cmd() - Send EIRP-PSD/EIRP power-levels
 *  to the FW through the WMI_SET_TPC_POWER_CMDID.
 *  @vap - Pointer to vap.
 */
void ieee80211_send_tpc_power_cmd(struct ieee80211vap *vap);

/** ieee80211_fill_reg_tpc_obj() - Fill the reg_tpc_obj object that is sent to
 *  the FW through the WMI_SET_TPC_POWER_CMDID.
 *  @vap - Pointer to vap.
 */
void ieee80211_fill_reg_tpc_obj(struct ieee80211vap *vap);

QDF_STATUS ieee80211_set_6G_opclass_triplets(struct ieee80211com *ic,
                                             uint16_t value);

/**
 * ieee80211_get_channel_list() - Fill channel list with primary channel
 * parameters and all supported flags.
 * @ic: Pointer to ieee80211_com.
 * @chan_list: Channel list to be filled.
 * @chan_info: Channel info
 * @nchans: Numbers of channels filled.
 * @flag_160: flag indicating the API to fill the center frequencies of 160MHz.
 *
 */
void ieee80211_get_channel_list(
        struct ieee80211com *ic,
        struct ieee80211_ath_channel *chan_list,
        struct ieee80211_channel_info *chan_info,
        int *nchans,
        bool flag_160);

/**
 * ieee80211_get_default_psd_power - Fetch default PSD power values from the
 * regulatory component.
 * @vap - Pointer to vap.
 * @client -  6G client type.
 * @psd_pwr - Pointer to psd power.
 */
void ieee80211_get_default_psd_power(struct ieee80211vap *vap,
                                     enum reg_6g_client_type client_type,
                                     uint8_t *psd_pwr);
#endif /* _NET80211_IEEE80211_REGDMN_H */
