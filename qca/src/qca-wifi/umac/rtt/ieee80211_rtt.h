/*
* Copyright (c) 2016, 2018 Qualcomm Innovation Center, Inc.
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/

/*
 * 2016 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _IEEE80211_RTT_H_
#define _IEEE80211_RTT_H_

/* Used for Where are you: LCI measurement request */
struct wru_lci_request {
    u_int8_t sta_mac[QDF_MAC_ADDR_SIZE];
    u_int8_t dialogtoken;
    u_int16_t num_repetitions;
    u_int8_t id;
    u_int8_t len;
    u_int8_t meas_token;
    u_int8_t meas_req_mode;
    u_int8_t meas_type;
    u_int8_t loc_subject;
}__attribute__((packed));


#define MAX_NEIGHBOR_NUM 15
#define MAX_NEIGHBOR_LEN 50
struct ftmrr_request {
    u_int8_t sta_mac[QDF_MAC_ADDR_SIZE];
    u_int8_t dialogtoken;
    u_int16_t num_repetitions;
    u_int8_t id;
    u_int8_t len;
    u_int8_t meas_token;
    u_int8_t meas_req_mode;
    u_int8_t meas_type;
    u_int16_t rand_inter;
    u_int8_t min_ap_count;
    u_int8_t elem[MAX_NEIGHBOR_NUM*MAX_NEIGHBOR_LEN];
}__attribute__((packed));

/* Neighbor Report ID */
#define RM_NEIGHBOR_RPT_ELEM_ID 52
/* Wide Bandwidth channel ID*/
#define RM_WIDE_BW_CHANNEL_ELEM_ID 6
/* Measurement Request ID */
#define RM_MEAS_REQ_ELEM_ID 38
/* Fine Timing Measurement Range Request Frame */
#define LOWI_WLAN_FTM_RANGE_REQ_TYPE 16

/**
 * neighbor_report_element_arr - Neighbor report elements
 * @sub_element_id: Neighbor Report ID
 * @sub_element_len: sizeof(struct neighbor_report_element_arr) -
 *                   sizeof(sub_element_id) - sizeof(sub_element_len);
 * @bssid: STA mac address
 * @bssid_info: BSSID info
 * @opclass: Operating class
 * @channel_num: Channel number
 * @phytype: Phytype
 * @wbc_element_id: Wide Bandwidth channel ID
 * @wbc_len: sizeof(wbc_ch_width) + sizeof(wbc_center_ch0) +
 *           sizeof(wbc_center_ch0);
 * @wbc_ch_width: Channel bandwidth
 * @wbc_center_ch0: Center channel number of segment0
 * @wbc_center_ch1:Center channel number of segment1
 */
struct neighbor_report_element_arr {
    uint8_t sub_element_id;
    uint8_t sub_element_len;
    uint8_t bssid[IEEE80211_ADDR_LEN];
    uint32_t bssid_info;
    uint8_t opclass;
    uint8_t channel_num;
    uint8_t phytype;
    uint8_t wbc_element_id;
    uint8_t wbc_len;
    uint8_t wbc_ch_width;
    uint8_t wbc_center_ch0;
    uint8_t wbc_center_ch1;
}__attribute__((packed));

/**
 * ieee80211_ftmrr - FTMRR structure to send FTMRR action frame
 * @sta_mac: Station mac address
 * @dialogtoken: WLAN frame parameter included in the action frame
 * @num_repetitions: Number of repetitions.
 * @element_id: Measurement Request ID.
 * @len: Sum of size of below parameters - meas_token, meas_req_mode, meas_type,
 *       rand_inter, min_ap_count * sizeof(struct neighbor_report_element_arr)
 * @meas_token: WLAN frame parameter included in the action frame
 * @meas_req_mode: Measurement request mode.
 * @meas_type: Fine Timing Measurement Range Request Frame
 * @rand_inter: Upper bound of the random delay to be used prior to making the
 *              measurement.
 * @min_ap_count: Minimum number of fine timing measurement ranges.
 * @elem: Pointer to neighbor_report_element_arr structure.
 */
struct ieee80211_ftmrr {
    uint8_t sta_mac[IEEE80211_ADDR_LEN];
    uint8_t dialogtoken;
    uint16_t num_repetitions;
    uint8_t element_id;
    uint8_t len;
    uint8_t meas_token;
    uint8_t meas_req_mode;
    uint8_t meas_type;
    uint16_t rand_inter;
    uint8_t min_ap_count;
    struct neighbor_report_element_arr elem[MAX_NEIGHBOR_NUM];
}__attribute__((packed));

int ieee80211_send_ftmrr_frame(struct wlan_objmgr_pdev *pdev,
                               struct ieee80211_wlanconfig_ftmrr *ftmrr_config);
#endif
