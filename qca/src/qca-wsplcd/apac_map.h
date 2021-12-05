/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * @@-COPYRIGHT-END-@@
 */

#include "wsplcd.h"
#if HYFI10_COMPATIBLE
#include "apclone.h"
#endif
#include "eloop.h"

#include "apac_hyfi20_wps.h"
#include "apac_hyfi20_mib.h"
#include "apac_priv.h"

/* BackHaul Steering Parameters */
#define BACKHAUL_STA_MAC "BackhaulStaMac"
#define TARGET_BSSID "TargetBSSID"

/* Traffic Separation Parameters */
#define CONFIG_NETWORK_TS_ENABLED "TSEnabled"
#define MAP2_SERVICE_MAX_VLAN_SUPPORTED 4
#define CONFIG_NETWORK_PRIMARY_VLAN "PrimaryLAN"
#define CONFIG_NETWORK_SECONDARY_VLAN "SecondaryLAN"
#define CONFIG_NETWORK_PRIMARY_VLAN_ID "PrimaryVLANID"
#define CONFIG_NETWORK_SECONDARY_VLAN_ID "SecondaryVLANID"
#define CONFIG_NETWORK_BSTA_IFACE "bSTAIface"
#define CONFIG_NETWORK_BHBSS_IFACE "bhBSSIface"
#define CONFIG_NETWORK_BHBSS_IFACE_R1_ONLY "R1BhBSSIface"
#define CONFIG_NETWORK_UPSTREAM_DEVICE_VERSION "UpstreamDeviceVersion"

#define CONFIG_CHANNEL "Chan"
#define CONFIG_MODE "Mode"

#define MAP_SERVICE_AGENT_MAX_BRIDGE_IFNAME_LENGTH 128
#define MAP_SERVICE_MAX_RADIOS 3

enum map_wps_attribute {
    ATTR_AUTH_TYPE = 0x1003,
    ATTR_CRED = 0x100e,
    ATTR_NETWORK_INDEX = 0x1026,
    ATTR_SSID = 0x1045,
    ATTR_ENCR_TYPE = 0x100f,
    ATTR_NETWORK_KEY_INDEX = 0x1028,
    ATTR_NETWORK_KEY = 0x1027,
    ATTR_MAC_ADDR = 0x1020
};

struct credbuf {
    u8 len;
    u8 buf[200];
};

apacHyfi20MapVersion_e apacHyfiMapIsEnabled(apacMapData_t *map);
apacBool_e apacHyfiMapPfComplianceEnabled(apacMapData_t *map);
apacBool_e apacHyfiMapIsTrafficSeparationEnabled(apacMapData_t *map);
apacBool_e apacHyfiMapConfigServiceEnabled(apacMapData_t *map);
int apac_map_get_mib_vap_index(apacMapData_t *map, int idx);
int apacMapGetRadioIdxByOpclass(apacMapData_t *map, int numOpClassRanges, int minOpClass, int maxOpClass);
ieee1905TLV_t *ieee1905MapAddRadioIdTLV(ieee1905TLV_t *TLV,
        u_int32_t *Len,
        struct apac_wps_session *sess);

ieee1905TLV_t *ieee1905MapAddTrafficSeparationPolicyTLV(ieee1905TLV_t *TLV, u_int32_t *Len,
                                                        struct apac_wps_session *sess);

/**
 * @brief Initialize the Multi-AP SIG component.
 *
 * @param [inout] map  the structure tracking all Multi-AP configuration
 *                     attributes and runtime state
 * @param [in] profileType  the type of profile specifications to expect
 *                          in the file
 * @param [in] filename  the file to read the profile specifications from
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
apacBool_e apacHyfiMapInit(apacMapData_t *map);

/**
 * @brief Terminate the Multi-AP SIG component.
 *
 * Clean up all memory and reset the internal state to its uninitialized
 * state.
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
apacBool_e apacHyfiMapDInit(apacMapData_t *map);

/**
 * @brief  Print the current configuration to the debug log stream/file.
 *
 * @param [in] map  the structure tracking all Multi-AP configuration
 *                  attributes and runtime state
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
void apacHyfiMapConfigDump(const apacMapData_t *map);

int apacGetPIFMapCap( apacHyfi20Data_t *pData);

ieee1905TLV_t *ieee1905MapAddBasicRadioTLV(ieee1905TLV_t *TLV,
        u_int32_t *Len,
        u8 band,
        apacHyfi20Data_t *pData);

ieee1905TLV_t *ieee1905Map2AddApCapTLV(ieee1905TLV_t *TLV, u_int32_t *Len, u8 band,
                                       apacHyfi20Data_t *pData);

ieee1905TLV_t *ieee1905Map2AddApRadioAdvancedCapTLV(ieee1905TLV_t *TLV, u_int32_t *Len, u8 band,
                                                    apacHyfi20Data_t *pData);

u8 apac_map_get_eprofile(struct apac_wps_session* sess, u8 *list, u8 *requested_m2);

u8 apac_map_get_configured_maxbss(struct apac_wps_session *sess);

u8 apac_map_parse_vendor_ext(struct apac_wps_session *sess,
        u8 *vendor_ext,
        u8 vendor_ext_len,
        u8 *mapBssType);

/**
 * @brief Populate the information necessary to instantiate a BSS based on
 *        the encryption profile specified by its index.
 *
 * @param [in] map  the overall structure for Multi-AP state
 * @param [in] index  the index of the encryption profile
 * @param [out] ap  the structure into which to copy the data
 *
 * @return APAC_TRUE on success; otherwise APAC_FALSE
 */
apacBool_e apac_map_copy_apinfo(apacMapData_t *map, u8 index, apacHyfi20AP_t *ap);

#define MAP_SERVICE_MAX_SSID_LEN 32
#define MAP_SERVICE_MAX_INTERFACES 15
/**
 * @brief Representation of Traffic Seperation policy
 */
typedef struct mapServiceTrafficSepPolicy_t {
    /// Number of SSIDs
    u_int8_t numOfSSIDs;

    struct {
        /// Length of SSID name
        u_int8_t ssidLen;

        /// SSID name
        char ssid[MAP_SERVICE_MAX_SSID_LEN];

        /// 0x0000 – 0x0002: Reserved
        /// 0x0003 – 0x0FFE
        /// 0xFFF – 0xFFFF: Reserved
        u_int16_t vlanID;
    } interfaceConf[MAP_SERVICE_MAX_INTERFACES];
} mapServiceTrafficSepPolicy_t;

u8 ieee1905MapParseTrafficSepTLV(struct apac_wps_session *sess,
                                 mapServiceTrafficSepPolicy_t *trafficSepPolicy);
