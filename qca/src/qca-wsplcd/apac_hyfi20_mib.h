/* @File: apac_hyfi20_mib.h
 * @Notes:
 *
 * Copyright (c) 2011-2012, 2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary.
 * All rights reserved.
 *
 */

#ifndef _APAC_HYFI20_MIB_H
#define _APAC_HYFI20_MIB_H

/*
   APCLONE TYPE for WPS:
   0x0000-0x00ff: reserved for other non-WLAN parameters
   0x0100-0x01ff: RADIO
   0x0200-0x02ff: BSS
   0x0300-        : reserved
   low byte of RADIO and BSS  used as index
   */
#define APCLONE_TYPE_MASK                   0xff00
#define APCLONE_TYPE_RADIO                  0x0100
#define APCLONE_TYPE_BSS                    0x0200
#define RADIO_TYPE_CHANNEL                  0x0001
#define RADIO_TYPE_RADIOENABLED             0x0002
#define RADIO_TYPE_POWERLEVEL               0x0003
#define RADIO_TYPE_RXCHAINMASK              0x0004
#define RADIO_TYPE_TXCHAINMASK              0x0005
#define RADIO_TYPE_TBRLIMIT                 0x0006
#define RADIO_TYPE_AMPDUENABLED             0x0007
#define RADIO_TYPE_AMPDULIMIT               0x0008
#define RADIO_TYPE_AMPDUFRAMES              0x0009
#define RADIO_TYPE_MACADDRESS               0x000A
#define BSS_TYPE_ENABLE                     0x0001
#define BSS_TYPE_RADIOINDEX                 0x0002
#define BSS_TYPE_SSID                       0x0003
#define BSS_TYPE_BEACONTYPE                 0x0004
#define BSS_TYPE_STANDARD                   0x0005
#define BSS_TYPE_WEPKEYINDEX                0x0006
#define BSS_TYPE_KEYPASSPHRASE              0x0007
#define BSS_TYPE_BASIC_ENCRYPTIONMODE       0x0008
#define BSS_TYPE_BASIC_AUTHMODE             0x0009
#define BSS_TYPE_WPA_ENCRYPTIONMODE         0x000A
#define BSS_TYPE_WPA_AUTHMODE               0x000B
#define BSS_TYPE_11I_ENCRYPTIONMODE         0x000C
#define BSS_TYPE_11I_AUTHMODE               0x000D
#define BSS_TYPE_WAPI_AUTHMODE              0x000E
#define BSS_TYPE_WAPI_PSKTYPE               0x000F
#define BSS_TYPE_WAPI_PREAUTH               0x0010
#define BSS_TYPE_WAPI_PSK                   0x0011
#define BSS_TYPE_WAPI_CERTCONTENT           0x0012
#define BSS_TYPE_WAPI_CERTINDEX             0x0013
#define BSS_TYPE_WAPI_CERTSTATUS            0x0014
#define BSS_TYPE_WAPI_CERTMODE              0x0015
#define BSS_TYPE_WAPI_ASUADDRESS            0x0016
#define BSS_TYPE_WAPI_ASUPORT               0x0017
#define BSS_TYPE_WAPI_UCASTREKEYTIME        0x0018
#define BSS_TYPE_WAPI_UCASTREKEYPACKET      0x001A
#define BSS_TYPE_WAPI_MCASTREKEYTIME        0x001B
#define BSS_TYPE_WAPI_MCASTREKEYPACKET      0x001C
#define BSS_TYPE_BASIC_DATA_TXRATES         0x001D
#define BSS_TYPE_RTS                        0x001E
#define BSS_TYPE_FRAGMENTATION              0x001F
#define BSS_TYPE_AUTH_SERVICE_MODE          0x0020
#define BSS_TYPE_EAP_REAUTH_PERIOD          0x0021
#define BSS_TYPE_WEP_REKEY_PERIOD           0x0022
#define BSS_TYPE_AUTH_SERVER_ADDR           0x0023
#define BSS_TYPE_AUTH_SERVER_PORT           0x0024
#define BSS_TYPE_AUTH_SERVER_SECRET         0x0025
#define BSS_TYPE_RSN_PREAUTH                0x0026
#define BSS_TYPE_SSID_HIDE                  0x0027
#define BSS_TYPE_APMODULE_ENABLE            0x0028
#define BSS_TYPE_WPS_PIN                    0x0029
#define BSS_TYPE_WPS_CONFIGURED             0x002A
#define BSS_TYPE_SHORT_GI                   0x002B
#define BSS_TYPE_CWM_ENABLE                 0x002C
#define BSS_TYPE_WMM                        0x002D
#define BSS_TYPE_HT40COEXIST                0x002E
#define BSS_TYPE_HBRENABLE                  0x002F
#define BSS_TYPE_HBRPERLOW                  0x0030
#define BSS_TYPE_HBRPERHIGH                 0x0031
#define BSS_TYPE_MEMODE                     0x0032
#define BSS_TYPE_MELENGTH                   0x0033
#define BSS_TYPE_METIMER                    0x0034
#define BSS_TYPE_METIMEOUT                  0x0035
#define BSS_TYPE_MEDROPMCAST                0x0036
#define BSS_TYPE_WEPKEY_1                   0x0037
#define BSS_TYPE_WEPKEY_2                   0x0038
#define BSS_TYPE_WEPKEY_3                   0x0039
#define BSS_TYPE_WEPKEY_4                   0x003A
#define BSS_TYPE_DEV_OPMODE                 0x003B
#define BSS_TYPE_GROUP_REKEY_PERIOD         0x003C
#define BSS_TYPE_PRESHARED_KEY              0x003D
#define BSS_TYPE_PSK_KEYPASSPHRASE          0x003E
#define BSS_TYPE_DEVICE_OPMODE              0x003F
#define HY_TYPE_WLAN2                       0x0040
#define HY_TYPE_WLAN5                       0x0041
#define BSS_TYPE_IFNAME                     0x0042
#define BSS_TYPE_CHANNEL                    0x0043
#define BSS_TYPE_BSSID                      0x0044
#define BSS_TYPE_WSPLCD_UNMANAGED           0x0045
#define BSS_TYPE_NETWORK                    0x0046

/* WPA3 - SAE */
#define BSS_TYPE_WPA3_SAE                   0x0046
#define BSS_TYPE_WPA3_SAE_PASSWORD          0x0047
#define BSS_TYPE_WPA3_SAE_ANTI_CLOG_THRES   0x0048
#define BSS_TYPE_WPA3_SAE_SYNC              0x0049
#define BSS_TYPE_WPA3_SAE_GROUPS            0x004A
#define BSS_TYPE_WPA3_SAE_REQUIRE_MFP       0x004B

/* WPA3 - OWE */
#define BSS_TYPE_WPA3_OWE                   0x004C
#define BSS_TYPE_WPA3_OWE_GROUPS            0x004D
#define BSS_TYPE_WPA3_OWE_TRANS_IF          0x004E
#define BSS_TYPE_WPA3_OWE_TRANS_SSID        0x004F
#define BSS_TYPE_WPA3_OWE_TRANS_BSSID       0x0050

/* WPA3 - SUITE_B */
#define BSS_TYPE_WPA3_SUITE_B               0x0051
#define BSS_TYPE_NASID                      0x0052

/* MFP */
#define BSS_TYPE_IEEE80211W                 0x0053

#define BSS_TYPE_BACKHAUL_AP                0x0054
#define BSS_TYPE_DISABLE_STEER              0x0055

/* WPA3 - 6G specific parameter*/
#define BSS_TYPE_SAE_PWE                    0x0056
#define BSS_TYPE_SAE_EN_6G_SEC_COMP         0x0057


/*Enum currently handled as string, but may be optimized as interger int the future*/
#define WPS_VALTYPE_ENUM WPS_VALTYPE_PTR

/*Minimum length of a TLV, equals the size of type and length*/
#define WPS_TLV_MIN_LEN 4

typedef struct apac_mib_session_t{
    const char * mib_path;
    struct wps_data* mib_data;;
    const struct apac_mib_param_set * mib_sets;
}apac_mib_session;


struct apac_mib_param_set {
    char    *name;
    u16     type;
    u16     value_type;
};

/**
 * Mapping from "iwpriv athx get_mode" output to the format required
 * by "Standard" TLV in QCA extension
 */
static const struct {
    char *phy_mode;
    char *apac_std;
} phy_to_std_mappings[] = {
    { "11NGHT20",      "ng20" },
    { "11NGHT40MINUS", "ng40minus" },
    { "11NGHT40PLUS", "ng40plus" },
    { "11NGHT40", "ng40" },
    { "11NAHT20", "na20" },
    { "11NAHT40MINUS", "na40minus" },
    { "11NAHT40PLUS", "na40plus" },
    { "11NAHT40", "na40" },
    { "11ACVHT20", "acvht20" },
    { "11ACVHT40MINUS", "acvht40minus" },
    { "11ACVHT40PLUS", "acvht40plus" },
    { "11ACVHT40", "acvht40" },
    { "11ACVHT80", "acvht80" },
    { "11ACVHT160", "acvht160" },
    { "11ACVHT80_80", "acvht80_80" },
    { "11AHE20", "axahe20" },
    { "11AHE40MINUS", "axahe40minus" },
    { "11AHE40PLUS", "axahe40plus" },
    { "11AHE40", "axahe40" },
    { "11AHE80", "axahe80" },
    { "11AHE160", "axahe160" },
    /* Not all radio supports 160 & driver picks legacy instead of 80
     Till driver gets fixed to pick best instead of legay will pass only HT80*/
    { "11AHE80_80", "axahe80_80" },
    { "11GHE20", "axghe20" },
    { "11GHE40MINUS", "axghe40minus" },
    { "11GHE40PLUS", "axghe40plus" },
    { NULL, NULL }
};


#if HYFI10_COMPATIBLE
extern const struct apac_mib_param_set clone_param_sets[];
extern const struct apac_mib_param_set radio_param_sets[];
#endif
extern const struct apac_mib_param_set bss_param_sets[];
struct wps_credential;

int apac_mib_get_tlv(const struct apac_mib_param_set *mibset, const char *value,  struct wps_tlv **tlv);
int apac_mib_parse_value(const struct apac_mib_param_set *mibset, const char *buf, size_t length, char *value, size_t size);
int apac_mib_get_object(char * path, struct wps_data *data, const struct apac_mib_param_set * mibsets);
#if HYFI10_COMPATIBLE
int apac_mib_set_object(char * path, struct wps_data *data, const struct apac_mib_param_set * mibsets);
int apac_mib_del_object(const char * const mibpath);
int apac_mib_add_object(const char * const mibpath);
int apac_mib_update_credential(struct wps_credential* cred);
#endif

int apac_parse_wps_data(const u8 *buf, size_t len,
        struct wps_data *data, const struct apac_mib_param_set *parse_table);

/* retrieved data is in wps_data format instead of (u8 *) */
int apac_get_mib_data_in_wpsdata(char * path, const struct apac_mib_param_set * mibsets,
        struct wps_data *data, size_t *length);

//apclone stuff
#if HYFI10_COMPATIBLE
int apac_get_mib_data(char * path, const struct apac_mib_param_set * mibsets, u8 **buf, size_t *length);
int apac_set_clone_data(const u8 *buf, size_t len);
int apac_get_clone_data(char **buf, size_t* len);
#endif

//1905.1 AP configuration
int apac_mib_get_wifi_configuration(apacHyfi20AP_t* apinfo, int vap_index);
int apac_mib_set_wifi_configuration(apacHyfi20Data_t* pApacData, apacHyfi20AP_t* apinfo,
        int vap_type, int vap_index,
        const char* ssid_suffix, apacBool_e changeBand,
        apacBool_e manageVAPInd, apacBool_e deepCloneNoBSSID);
int apac_get_qca_ext_from_tlv(apacHyfi20AP_t* apinfo);

/**
 * @brief Apply all saved Wi-Fi configuration
 *
 * The old handle will also be freed and a new handle will be returned.
 *
 * @param [in] mibHandle  the handle contains all saved configuration params
 * @param [in] createNew  whether to create a new handle after applying current one
 *
 * @return a new storage handle if requested or NULL on failure or not requested
 */
void * apac_mib_apply_wifi_configuration(void *mibHandle, apacBool_e createNew);

#if MAP_ENABLED
/**
 * @brief Set the configuration params received from controller
 *
 * @param [in] mibHandle  the handle contains all saved configuration params
 * @param [in] pData  data structure containing device information
 * @param [in] radioIdx  the index which identifies the radio
 * @param [in] freq  represents the frequency band
 * @param [in] vapIndexList  contains the list of all the existing AP VAPs that
 *                           are managed by wsplcd
 * @param [in] unmanagedVapList  contains the list of all the existing AP
 *                               VAPs that are unmanaged by wsplcd
 * @param [in] bStaIdxList  contains the list of all STA VAPs
 *
 * @return -1 if failure, 0 if success
 */
int apac_mib_set_map_data(void *mibHandle, apacHyfi20Data_t *pData, u8 radioIdx,
                          apacHyfi20WifiFreq_e freq, const u8 *vapIndexList,
                          const u8 *unmanagedVapList, const u8 *bStaIdxList);
#endif
/**
 * @brief Get a storage handle to store Wi-Fi configuration params
 *
 * @return the storage handle or NULL on failure
 */
void * apac_mib_get_wifi_config_handle(void);


#if SON_ENABLED
//QCA Extension
int apac_mib_get_qca_ext(apacHyfi20AP_t* apinfo, int vap_index, int channel, u8 use_bh_standard);
int apac_mib_get_qca_ext_wpa3(apacHyfi20AP_t* apinfo, int vap_index);
int apac_mib_get_qca_ext_channel(apacHyfi20AP_t* apinfo, int vap_index);
#endif
#if MAP_ENABLED
int apac_mib_get_map_qca_ext_wpa3(apacHyfi20AP_t* apinfo, int vap_index);
int apac_mib_get_map_qca_ext(apacHyfi20AP_t* apinfo, int vap_index);
int apac_map_parse_sae_vendor_ext(apacMapAP_t* map, u8* vendor_ext, size_t len);
int apac_map_parse_qca_vendor_ext(apacMapAP_t* map, u8* vendor_ext, size_t len);
#endif
int apac_mib_set_vap_status(int vap_index, int status);
int apac_mib_set_vapind(apacHyfi20Data_t *pData, int enable);

//API for get the MIB index of VAP
int apac_mib_get_vapindex(const char *ifname);
int apac_mib_get_wlan_standard_by_vapindex(int vap_index, char *standard);
int apac_mib_get_radio_by_vapindex(int vap_index);
int apac_mib_get_wsplcdUnmanaged_by_vapindex(int vap_index);
int apac_mib_get_wlan_network_by_vapindex(int vap_index, char *network);
int apac_mib_get_bsstype_by_vapindex(int vap_index, uint32_t *bss_type);

//1905.1 UCPK
int apac_mib_set_ucpk(apacHyfi20Data_t *pData, const char *wpapsk, const char *plcnmk);

void apac_mib_restart_wireless(void);

#if MAP_ENABLED
/**
 * @brief Receive BackHaul Steering data
 *
 * @param [in] buf  buffer containing backhaul steering data
 *
 * @return -1 if failure, 0 if success
 */
int apac_mib_backhaul_sta_callback(apacHyfi20Data_t *pData, char *backhaulData);

/**
 * @brief Receive Traffic Separation Data from HYD
 *
 * @param [in] buf  buffer containing Traffic Separation data
 *
 * @return -1 if failure, 0 if success
 */
int apac_mib_traffic_separation_cb(apacHyfi20Data_t *pData, char *trafficData);

/**
 * @brief Receive Channel and Mode Data from HYD
 *
 * @param [in] buf  buffer containing Channel Mode data
 *
 * @return -1 if failure, 0 if success
 */
int apac_mib_channel_mode_update_cb(apacHyfi20Data_t *pData, char *channelModeData);
#endif

#endif
