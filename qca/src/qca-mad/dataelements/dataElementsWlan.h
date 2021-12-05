/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#define _GNU_SOURCE

#include <asm/types.h>

struct ucred {
    __u32   pid;
    __u32   uid;
    __u32   gid;
};

#include <linux/nl80211.h>
#include <linux/version.h>
#include <qcatools_lib.h>
#include <cfg80211_nlwrapper_pvt.h>

#ifndef _CFG80211_DE_
#define _CFG80211_DE_

#define MAX_VAP_PER_BAND 16
#define WLANIF_MAX_RADIOS 4

extern int finish_handler(struct nl_msg *msg, void *arg);
extern int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
extern int valid_handler(struct nl_msg *msg, void *arg);
extern int ack_handler(struct nl_msg *msg, void *arg);

#define MAX_CMD_LEN 128
static const unsigned NL80211_ATTR_MAX_INTERNAL = 256;

struct dataElementWlanVapInfo {
    int valid;
    struct ether_addr macaddr;
    char ifname[IFNAMSIZ + 1];
};

struct dataElementWlanRadioInfo {
    DE_BOOL valid;
    DE_BOOL radioBasicCapabilitiesValid : 1;
    struct ether_addr radioAddr;
    char ifname[IFNAMSIZ + 1];
    int numOfVap;
    struct dataElementWlanVapInfo vaps[MAX_VAP_PER_BAND];
    ieee1905APRadioBasicCapabilities_t radioBasicCapabilities;
};

struct wdev_info {
    enum nl80211_iftype nlmode;
    char name[IFNAMSIZ];
};

typedef enum EspAccessCategory_e {
    deEspAC_BK,
    deEspAC_BE,
    deEspAC_VO,
    deEspAC_VI,
    deEspAC_Max,  // always last
} EspAccessCategory_e;

/**
 * @brief Enumerations for bandwidth (MHz) supported by STA
 */
typedef enum de_chwidth_e {
    de_chwidth_20,
    de_chwidth_40,
    de_chwidth_80,
    de_chwidth_160,

    de_chwidth_invalid
} de_chwidth_e;

/**
 * @brief Enumerations for IEEE802.11 PHY mode
 */
typedef enum de_phymode_e {
    de_phymode_basic,
    de_phymode_ht,
    de_phymode_vht,
    de_phymode_he,

    de_phymode_invalid
} de_phymode_e;

/*
 * @brief phymode required for neighbour bandwidth
 *        Should be the replica for what driver defined
 */
enum wlan_phymode {
    WLAN_PHYMODE_AUTO               = 0,
    WLAN_PHYMODE_11A                = 1,
    WLAN_PHYMODE_11B                = 2,
    WLAN_PHYMODE_11G                = 3,
    WLAN_PHYMODE_11G_ONLY           = 4,
    WLAN_PHYMODE_11NA_HT20          = 5,
    WLAN_PHYMODE_11NG_HT20          = 6,
    WLAN_PHYMODE_11NA_HT40          = 7,
    WLAN_PHYMODE_11NG_HT40PLUS      = 8,
    WLAN_PHYMODE_11NG_HT40MINUS     = 9,
    WLAN_PHYMODE_11NG_HT40          = 10,
    WLAN_PHYMODE_11AC_VHT20         = 11,
    WLAN_PHYMODE_11AC_VHT20_2G      = 12,
    WLAN_PHYMODE_11AC_VHT40         = 13,
    WLAN_PHYMODE_11AC_VHT40PLUS_2G  = 14,
    WLAN_PHYMODE_11AC_VHT40MINUS_2G = 15,
    WLAN_PHYMODE_11AC_VHT40_2G      = 16,
    WLAN_PHYMODE_11AC_VHT80         = 17,
    WLAN_PHYMODE_11AC_VHT80_2G      = 18,
    WLAN_PHYMODE_11AC_VHT160        = 19,
    WLAN_PHYMODE_11AC_VHT80_80      = 20,
    WLAN_PHYMODE_11AXA_HE20         = 21,
    WLAN_PHYMODE_11AXG_HE20         = 22,
    WLAN_PHYMODE_11AXA_HE40         = 23,
    WLAN_PHYMODE_11AXG_HE40PLUS     = 24,
    WLAN_PHYMODE_11AXG_HE40MINUS    = 25,
    WLAN_PHYMODE_11AXG_HE40         = 26,
    WLAN_PHYMODE_11AXA_HE80         = 27,
    WLAN_PHYMODE_11AXG_HE80         = 28,
    WLAN_PHYMODE_11AXA_HE160        = 29,
    WLAN_PHYMODE_11AXA_HE80_80      = 30,
    WLAN_PHYMODE_MAX
};

/**
 * @brief PHY capabilities supported by a VAP or client
 */
typedef struct de_phyCapInfo_t {
    /// Flag indicating if this PHY capability entry is valid or not
    DE_BOOL valid : 1;

    /// The maximum bandwidth supported by this STA
    de_chwidth_e maxChWidth : 3;

    /// The spatial streams supported by this STA
    u_int8_t numStreams : 4;

    /// The PHY mode supported by this STA
    de_phymode_e phyMode : 8;

    /// The maximum MCS supported by this STA
    u_int8_t maxMCS;

    /// The maximum TX power supporetd by this STA
    u_int8_t maxTxPower;
} de_phyCapInfo_t;

typedef struct
{
    /// Whether the ESP Info for this AC is included
    DE_BOOL includeESPInfo : 1;

    /// Access Category
    u_int8_t ac : 2;

    /// Data format
    u_int8_t dataFormat : 2;

    /// BA window size
    u_int8_t baWindowSize;

    /// Estimated air time fraction (as a percentage from 0 - 100)
    u_int8_t estAirTimeFraction;

    /// Data PPDU duration target (in microseconds)
    u_int16_t dataPPDUDurTarget;
} dEEspInfo_t;


struct ol_ath_dbg_rx_rssi {
    uint8_t     rx_rssi_pri20;
    uint8_t     rx_rssi_sec20;
    uint8_t     rx_rssi_sec40;
    uint8_t     rx_rssi_sec80;
};

struct ol_ath_radiostats {
    uint64_t    tx_beacon;
    uint32_t    tx_buf_count;
    int32_t     tx_mgmt;
    int32_t     rx_mgmt;
    uint32_t    rx_num_mgmt;
    uint32_t    rx_num_ctl;
    uint32_t    tx_rssi;
    uint32_t    rx_rssi_comb;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain0;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain1;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain2;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain3;
    uint32_t    rx_overrun;
    uint32_t    rx_phyerr;
    uint32_t    ackrcvbad;
    uint32_t    rtsbad;
    uint32_t    rtsgood;
    uint32_t    fcsbad;
    uint32_t    nobeacons;
    uint32_t    mib_int_count;
    uint32_t    rx_looplimit_start;
    uint32_t    rx_looplimit_end;
    uint8_t     ap_stats_tx_cal_enable;
    uint8_t     self_bss_util;
    uint8_t     obss_util;
    uint8_t     ap_rx_util;
    uint8_t     free_medium;
    uint8_t     ap_tx_util;
    uint8_t     obss_rx_util;
    uint8_t     non_wifi_util;
    uint32_t    tgt_asserts;
    int16_t     chan_nf;
    int16_t     chan_nf_sec80;
    uint64_t    wmi_tx_mgmt;
    uint64_t    wmi_tx_mgmt_completions;
    uint32_t    wmi_tx_mgmt_completion_err;
    uint32_t    rx_mgmt_rssi_drop;
    uint32_t    tx_frame_count;
    uint32_t    rx_frame_count;
    uint32_t    rx_clear_count;
    uint32_t    cycle_count;
    uint32_t    phy_err_count;
    uint32_t    chan_tx_pwr;
    uint32_t    be_nobuf;
    uint32_t    tx_packets;
    uint32_t    rx_packets;
    uint32_t    tx_num_data;
    uint32_t    rx_num_data;
    uint32_t    tx_mcs[10];
    uint32_t    rx_mcs[10];
    uint64_t    rx_bytes;
    uint64_t    tx_bytes;
    uint32_t    tx_compaggr;
    uint32_t    rx_aggr;
    uint32_t    tx_bawadv;
    uint32_t    tx_compunaggr;
    uint32_t    rx_badcrypt;
    uint32_t    rx_badmic;
    uint32_t    rx_crcerr;
    uint32_t    rx_last_msdu_unset_cnt;
    uint32_t    rx_data_bytes;
    uint32_t    tx_retries;
};
// Single AP mode Init function
DE_STATUS dataElementWlanInit(void);

//Single AP mode deInit Function
void dataElementsWlanFini(void);

//Get Radio information
DE_STATUS dEGetWlanRadioData(dataElementsRadio_t *radioData, int radioIndex);

//Get Network data
DE_STATUS dEGetWlanNetworkData(dataElementsNetwork_t *networkData);

//Get Device data
DE_STATUS dEGetWlanDeviceData(dataElementsDevice_t *deviceData);

//Get Currrent Opclass data
DE_STATUS dEGetWlanCurOpClassData(dataElementsRadio_t *radioData,dataElementsCurrentOpClassProfile_t *cOp);

//Get Radio Capability data
DE_STATUS dEGetWlanRadioCapsData(dataElementsRadio_t *radioData, dataElementsCapabilities_t *capData);

//Get Radio Capable Opclass data
DE_STATUS dEGetWlanRadioCapableOpClassData(dataElementsCapableOpClassProfile_t *capOpClassData);

//Get Radio BSS data
DE_STATUS dEGetWlanBssData(u_int8_t radioIndex, dataElementsRadio_t *radioData, dataElementsBSS_t *bssData);

//Request scan
void dESendScanRequest();

//Get Scan List data
DE_STATUS dEGetWlanScanListData(dataElementsScanResult_t *scanData );

//Get Sta List data
DE_STATUS dEGetWlanStaData( u_int32_t bssCount, u_int32_t no_of_sta, dataElementsSTAList_t *staData );

#endif
