/*
 * Copyright (c) 2017-2019 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */


#ifndef __WLANIF_CMN_H__
#define __WLANIF_CMN_H__

struct wlanif_config {
    void *ctx;
    uint32_t IsCfg80211;
    int pvt_cmd_sock_id;
    int pvt_event_sock_id;
};

#if !SONLIB_SUPPORT_ENABLED
/// The number of bytes in a MAC address
#define IEEE80211_ADDR_LEN 6

/// The max SSID length in bytes
#define IEEE80211_NWID_LEN  32

#ifndef ACS_RANK_DESC_DBG_LEN
/// The max length in bytes for the ACS channel ranking description
#define ACS_RANK_DESC_DBG_LEN 80
#endif  // ACS_RANK_DESC_DBG_LEN

#ifndef HOST_MAX_CHAINS
#define HOST_MAX_CHAINS 8
#endif

// This struct has to be a duplicate definition of ieee80211_neighbor_info
typedef struct ieee80211_neighbor_info_t {
    u_int32_t   phymode; /* ap channel width*/
    int32_t     rssi; /* ap singal strength */
    u_int8_t    bssid[IEEE80211_ADDR_LEN]; /* BSSID information */
    u_int8_t    ssid_len; /* length of the ssid */
    u_int8_t    ssid[IEEE80211_NWID_LEN + 1]; /* SSID details */
    u_int8_t    qbssload_ie_valid; /* Flag to indicate if qbss load ie is present */
    u_int8_t    station_count; /* number of station associated */
    u_int8_t    channel_utilization; /* channel busy time in 0-255 scale */
} ieee80211_neighbor_info_t;

// This struct has to be a duplicate definition of ACS_LIST_TYPE
typedef enum {
    acsChanStats,
    acsNeighGetListCount,
    acsNeighGetList,
} acs_list_type_e;

// This struct has to be a duplicate definition of wlan_band_id
enum wlan_band_id_e {
    wlanBand_UnSpecified = 0,
    wlanBand_2GHZ = 1,
    wlanBand_5GHZ = 2,
    wlanBand_6GHZ = 3,
    /* Add new band definitions here */
    wlanBand_MAX,
};

// This struct has to be a duplicate definition of ieee80211_acs_dbg
typedef struct ieee80211_acs_report_t {
    u_int8_t  nchans;
    u_int8_t  entry_id;
    u_int16_t chan_freq;
    enum wlan_band_id_e chan_band;
    u_int8_t  ieee_chan;
    u_int8_t  chan_nbss;
    int32_t   chan_maxrssi;
    int32_t   chan_minrssi;
    int16_t   noisefloor;
    int16_t   perchain_nf[HOST_MAX_CHAINS];
    int16_t   channel_loading;
    u_int32_t chan_load;
    u_int8_t  sec_chan;
    int32_t   chan_nbss_srp;
    int32_t   chan_srp_load;
    u_int8_t  chan_in_pool;
    u_int8_t  chan_radar_noise;
    int32_t neighbor_size;
    ieee80211_neighbor_info_t *neighbor_list;
    u_int32_t chan_80211_b_duration;
    /* ACS Channel Ranking structure
     *    rank: Channel Rank
     *    desc: Reason in case of no rank
     */
    struct acs_rank {
        u_int32_t rank;
        char desc[ACS_RANK_DESC_DBG_LEN];
    } acs_rank;
    u_int8_t acs_status;
    acs_list_type_e acs_type;
    uint32_t chan_availability;
    uint32_t chan_efficiency;
    uint32_t chan_nbss_near;
    uint32_t chan_nbss_mid;
    uint32_t chan_nbss_far;
    uint32_t chan_nbss_eff;
    uint32_t chan_grade;
    u_int8_t op_class;
    u_int8_t chan_width;
} ieee80211_acs_report_t;

#define IEEE80211_RRM_CHAN_MAX 255
#define IEEE80211_MAX_REQ_IE 255

#define IEEE80211_BCNREQUEST_VALIDSSID_REQUESTED 0x01
#define IEEE80211_BCNREQUEST_NULLSSID_REQUESTED 0x02

#define IEEE80211_RRM_NUM_CHANREQ_MAX 16
#define IEEE80211_RRM_NUM_CHANREP_MAX 2

typedef struct wlanifBSteerEventsPriv_t *wlanifBSteerEventsHandle_t;

#endif /*SONLIB_SUPPORT_ENABLED*/

/* Netlink socket ports for different applications to bind to
 * These ports are reserved for these specific applications and
 * should take care not to reuse it.
 */
#define LBD_NL80211_CMD_SOCK      899
#define LBD_NL80211_EVENT_SOCK    900
#define WSPLCD_NL80211_CMD_SOCK   901
#define WSPLCD_NL80211_EVENT_SOCK 902
#define HYD_NL80211_CMD_SOCK      903
#define HYD_NL80211_EVENT_SOCK    904
#define IFACEMGR_NL80211_CMD_SOCK      950
#define IFACEMGR_NL80211_EVENT_SOCK    951
#define LIBSTORAGE_NL80211_CMD_SOCK    952
#define LIBSTORAGE_NL80211_EVENT_SOCK  953


int wlanif_cfg80211_init(struct wlanif_config *cfg80211_conf);
void wlanif_cfg80211_deinit(struct wlanif_config *cfg80211_conf);
int getName_cfg80211(void *,const char *ifname, char *name );
int isAP_cfg80211(void *, const char * ifname, uint32_t *result);
int getBSSID_cfg80211(void *, const char *ifname, struct ether_addr *BSSID );
int getESSID_cfg80211(void *ctx, const char * ifname, void *buf, uint32_t *len );
int getFreq_cfg80211(void *, const char * ifname, int32_t * freq);
int getChannelWidth_cfg80211(void *, const char *ifname, int * chwidth);
int getChannelExtOffset_cfg80211(void *, const char *ifname, int * choffset);
int getChannelBandwidth_cfg80211(void *, const char *ifname, int * bandwidth);
int getAcsState_cfg80211(void *, const char *ifname, int * acsstate);
int getCacState_cfg80211(void *, const char *ifname, int * cacstate);
int getParentIfindex_cfg80211(void *, const char *ifname, int * cacstate);
int getSmartMonitor_cfg80211(void *, const char *ifname, int * smartmonitor);
int getGenericInfoAtf_cfg80211(void *, const char *ifname, int cmd, void * chanInfo, int chanInfoSize);
int getGenericInfoAld_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getGenericInfoHmwds_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getGenericNac_cfg80211(void *, const char *ifname, void * config, int configSize);
int getCfreq2_cfg80211(void *, const char * ifname, int32_t * cfreq2);
int getChUtil_cfg80211(void *ctx, const char * ifname, int32_t * chUtil);
int getChannelInfo_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getChannelInfo160_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getStationInfo_cfg80211(void *, const char *ifname, void *buf, int* len);
int getDbgreq_cfg80211(void * , const char *ifname, void *data , uint32_t data_len);
int getExtended_cfg80211(void * , const char *ifname, void *data , uint32_t data_len);
int addDelKickMAC_cfg80211(void *, const char *ifname, int operation, void *data, uint32_t len);
int setFilter_cfg80211(void *, const char *ifname, void *data, uint32_t len);
int getWirelessMode_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len);
int sendMgmt_cfg80211(void *, const char *ifname, void *data, uint32_t len);
int setParamMaccmd_cfg80211(void *, const char *ifname, void *data, uint32_t len);
int setMapVapBeacon_cfg80211(void *ctx, const char *ifname, void *data, uint32_t len);
int setParam_cfg80211(void *, const char *ifname,int cmd, void *data, uint32_t len);
int getStaStats_cfg80211(void *, const char *ifname, void *data, uint32_t len);
int getRange_cfg80211(void *ctx, const char *ifname, int *we_version);
int getStaCount_cfg80211(void *ctx, const char *ifname, int32_t *result);
int setIntfMode_cfg80211(void *ctx, const char *ifname, const char *mode, u_int8_t len);
int setParamVapInd_cfg80211(void *ctx, const char *ifname, void *data, uint32_t len);
int setFreq_cfg80211(void *ctx, const char *ifname, int freq, int band);

int getCountryCode_cfg80211(void *ctx, const char *ifname, size_t size, char *countryCode);
int setCACTimeout_cfg80211(void *ctx, const char * ifname, int cac_timeout);
int setCFreq2_cfg80211(void *ctx, const char * ifname, int chan_num);
int getACSReport_cfg80211(void *ctx, const char *ifName, u_int8_t* numChans,
                          ieee80211_acs_report_t *chanData, u_int8_t* numNeighbors,
                          ieee80211_neighbor_info_t *neighborData, u_int8_t neighborChans[]);
int setAcsChanList_cfg80211(void *ctx, const char *ifName, u_int8_t numChans, u_int8_t *channels);
int getMapBssRole_cfg80211(void *ctx, const char *ifName, u_int8_t *mapBssRole);
int getFallbackFreq_cfg80211(void *ctx, const char * ifname, int * fallbackFreq);
int setFallbackFreq_cfg80211(void *ctx, const char * ifname, int fallbackFreq);
int setNOLChannel_cfg80211(void *ctx, const char * radioName);
int getNOLChannel_cfg80211(void *ctx, const char * radioName, void* nolinfo);
int setRRMFilter_cfg80211(void *ctx, const char* ifname, u_int8_t rrm_filter);
int setWNMFilter_cfg80211(void *ctx, const char* ifname, u_int8_t wnm_filter);

/**
 * @brief Get the BandInfo from the Wi-Fi driver for the given radio interface.
 *
 * @param     [in] context: opaque pointer.
 * @param     [in] ifname: radio interface name
 * @param     [out] band_info: BandInfo for given radio interface name.
 *                  band_info details are
 *                       1 indicates the RADIO_IN_HIGH_BAND
 *                       2 indicates the RADIO_IN_FULL_BAND
 *                       3 indicates the RADIO_IN_LOW_BAND
 *                       4 indicates the RADIO_IS_NON_5G ie 2G BAND
 * @return    Success:0, Failure: -1
 */
int getBandInfo_cfg80211(void *ctx, const char * ifname, uint8_t * band_info);

/**
 * @brief Get the uplink rate from the Wi-Fi driver for the given VAP interface.
 *
 * @param     [in] context: opaque pointer.
 * @param     [in] ifname: vap interface name
 * @param     [out] ul_rate: uplink rate for given vap interface name.
 * @return    Success:0, Failure: -1
 */
int getUplinkRate_cfg80211(void *ctx, const char * ifname, uint16_t * ul_rate);

/**
 * @brief Set the uplink rate to the Wi-Fi driver for the given VAP interface.
 *
 * @param     [in] context: opaque pointer.
 * @param     [in] ifname: vap interface name
 * @param     [in] ul_rate: set uplink rate
 * @return    Success:0, Failure: -1
 */
int setUplinkRate_cfg80211(void * ctx, const char *ifname, uint16_t ul_rate);

/**
 * @brief Set the backhaul type whenever there is a change
 * in the backhaul connection between WiFi and Ethernet vice versa.
 *
 * @param     [in] context: opaque pointer.
 * @param     [in] ifname: vap interface name
 * @param     [in] bh_type: backhaul type.
 *                 backhaul type : WiFiBh is 1 and EthBh is 2
 * @return    Success:0, Failure: -1
 */
int setSonBhType_cfg80211(void * ctx, const char *ifname, uint8_t bh_type);

/**
 * @brief Function to get phystats of radio
 *
 * @param [in] ctx   opaque pointer to private vendor struct
 * @param [in] ifname   interface name
 * @param [in] data pointer to ol_stats structure
 * @param [in] len length of the data
 *
 * @return Success: 0, Failure: -1
 */
int getPhyStats_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len);
struct iw_priv_args *getPrivArgs_cfg80211(void *ctxt, const char *ifname, size_t *len);

/**
 * @brief: get_nl80211_event_msg: Function to parse the cfg event data
 * @msg: Pointer to netlink event message
 * @outbuf: out put, pointer on whcih parsed data is stored
 * @return Success: 0
 */
int get_nl80211_event_msg(u_int8_t *msg, void * ctx, void *outbuf);
int get_cfg80211_event_sock(void * ctx);

/*enum to handle MAC operations*/
enum wlanif_ioops_t
{
    IO_OPERATION_ADDMAC=0,
    IO_OPERATION_DELMAC,
    IO_OPERATION_KICKMAC,
    IO_OPERATION_LOCAL_DISASSOC,
    IO_OPERATION_ADDMAC_VALIDITY_TIMER,
};


/**
 * @brief Get whether the Radio is tuned for low, high, full band or 2g.
 * the equivalent enum declared in ol_if_athvar.h and one-to-one mapping.
*/
typedef enum wlanifBandInfo_e {
    bandInfo_Unknown, /* unable to retrieve band info due to some error */
    bandInfo_High, /* supports channel starts from 100 to 165 */
    bandInfo_Full, /* supports channel starts from 36 to 165 */
    bandInfo_Low, /* supports channel starts from 36 to 64 */
    bandInfo_Non5G, /* supports 2g channel 1 to 14 */
    bandInfo_6G
} wlanifBandInfo_e;

/**
 * SON WiFi backhaul type is defined 1 and
 * Eth backhaul type is defined 2, PLC is defined as 3 respectively.
 */
typedef enum backhaulType_e {
    backhaulType_Unknown = 0,
    backhaulType_Wifi = 1,
    backhaulType_Ether = 2,
    bacckhaulType_Plc = 3,
} backhaulType_e;

extern struct wlanif_config * wlanif_config_init(int pvt_cmd_sock_id,
                                                 int pvt_event_sock_id);
extern void wlanif_config_deinit(struct wlanif_config *);

#endif /* #define __WLANIF_CMN_H__ */
