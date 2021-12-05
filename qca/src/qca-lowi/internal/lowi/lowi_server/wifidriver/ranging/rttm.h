/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        WIPS module - RTT Measurements

GENERAL DESCRIPTION
  This file contains the declaration and some global constants for RTT
  measurements.

Copyright (c) 2013-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/
#ifndef _RTTM_H_
#define _RTTM_H_

#include <linux/types.h>
#include "wlan_location_defs.h"
#include "innavService.h"

#define ETH_ALEN_PLUS_2 ETH_ALEN + 2 // 2 extra bytes added for alignment

/* RTT message subtype definitions */
typedef enum {
    RTT_MSG_SUBTYPE_INVALID                  = 0x00,
    RTT_MSG_SUBTYPE_CAPABILITY_REQ           = 0x01,
    RTT_MSG_SUBTYPE_CAPABILITY_RSP           = 0x02,
    RTT_MSG_SUBTYPE_MEASUREMENT_REQ          = 0x03,
    RTT_MSG_SUBTYPE_MEASUREMENT_RSP          = 0x04,
    RTT_MSG_SUBTYPE_ERROR_REPORT_RSP         = 0x05,
    RTT_MSG_SUBTYPE_CONFIGURE_LCR            = 0x06,
    RTT_MSG_SUBTYPE_CONFIGURE_LCI            = 0x07,
    RTT_MSG_SUBTYPE_CLEANUP_REQ              = 0x08,
    RTT_MSG_SUBTYPE_CLEANUP_RSP              = 0x09,
    RTT_MSG_SUBTYPE_GET_CHANNEL_INFO_REQ     = 0x10, //REQ for channel info
    RTT_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP     = 0x11, // RESPONSE for channel info
    RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_REQ   = 0x12, // REQ for  enable or disable responder mode
    RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_RSP   = 0x13, // RESPONSE for enable mode
    RTT_MSG_SUBTYPE_CANCEL_MEASUREMENT_REQ   = 0x14, // Request to cancel measurement request
    RTT_MSG_SUBTYPE_CANCEL_MEASUREMENT_RSP   = 0x15, // Response for cancel measurement request
    RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_REQ = 0x16, // REQ to enable or disable responder measurement
    RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_RSP = 0x17, // RESPONSE to responder measurement enable/disable request
    RTT_MSG_SUBTYPE_RESPONDER_MEASUREMENT_RSP = 0x18, // responder measurement report
} WMIRTT_OEM_MSG_SUBTYPE;

/* ROME CLD related Info */

/* Netlink socket Message Type definition  - At some point Replace this with a header file inclusion */
#define ANI_NL_MSG_BASE     0x10    /* Some arbitrary base */

typedef enum eAniNlModuleTypes {
   ANI_NL_MSG_PUMAC = ANI_NL_MSG_BASE + 0x01,// PTT Socket App
   ANI_NL_MSG_PTT   = ANI_NL_MSG_BASE + 0x07,// Quarky GUI
   WLAN_NL_MSG_BTC,
   WLAN_NL_MSG_OEM,
   ANI_NL_MSG_MAX
} tAniNlModTypes, tWlanNlModTypes;

/* ANI Message IDs */
#define ANI_DRIVER_MSG_START         0x0001
#define ANI_MSG_APP_REG_REQ         (ANI_DRIVER_MSG_START + 0)
#define ANI_MSG_APP_REG_RSP         (ANI_DRIVER_MSG_START + 1)
#define ANI_MSG_OEM_DATA_REQ        (ANI_DRIVER_MSG_START + 2)
#define ANI_MSG_OEM_DATA_RSP        (ANI_DRIVER_MSG_START + 3)
#define ANI_MSG_CHANNEL_INFO_REQ    (ANI_DRIVER_MSG_START + 4)
#define ANI_MSG_CHANNEL_INFO_RSP    (ANI_DRIVER_MSG_START + 5)
#define ANI_MSG_OEM_ERROR           (ANI_DRIVER_MSG_START + 6)
#define ANI_MSG_PEER_STATUS_IND     (ANI_DRIVER_MSG_START + 7)
#define ANI_MSG_UNKNOWN             100

/* ANI Message Header */
typedef PACK (struct)
{
   unsigned short type;
   unsigned short length;
} tAniHdr, tAniMsgHdr;

#define APP_REG_SIGNATURE "QUALCOMM-OEM-APP"
#define APP_REG_SIGNATURE_LENGTH (sizeof(APP_REG_SIGNATURE) - 1)

/** The following are the interface Ids that will be mapped to their vdev Ids */
typedef enum device_mode
{
   WLAN_HDD_INFRA_STATION,      /* Wlan Station Interface */
   WLAN_HDD_SOFTAP,             /* Soft AP Interface */
   WLAN_HDD_P2P_CLIENT,         /* P2P Client Interface */
   WLAN_HDD_P2P_GO,             /* P2P Group Owner Interface */
   WLAN_HDD_MONITOR,
   WLAN_HDD_FTM,
   WLAN_HDD_IBSS,
   WLAN_HDD_P2P_DEVICE,
   WLAN_HDD_MAX_DEV_MODE        /* Maximum supported Interfaces */
} device_mode_t;

typedef PACK (struct)
{
  tANI_U8 iFaceId;
  tANI_U8 vDevId;
} VDevMap;

typedef PACK (struct)
{
  tANI_U8 numInterface;
  VDevMap vDevMap[WLAN_HDD_MAX_DEV_MODE];
} VDevInfo;
/************* Error Message Definitions **********************/
typedef enum
{
  /* Error null context */
  OEM_ERR_NULL_CONTEXT = 1,

  /* OEM App is not registered */
  OEM_ERR_APP_NOT_REGISTERED,

  /* Inavalid signature */
  OEM_ERR_INVALID_SIGNATURE,

  /* Invalid message type */
  OEM_ERR_NULL_MESSAGE_HEADER,

  /* Invalid message type */
  OEM_ERR_INVALID_MESSAGE_TYPE,

  /* Invalid length in message body */
  OEM_ERR_INVALID_MESSAGE_LENGTH
} eOemErrorCode;

typedef PACK (struct)
{
  tANI_U8 errorCode;
} OemErrorMsg;

/************* Channel info Message definitions  **************/
typedef PACK (struct)
{
 tANI_U8 numChan;
 tANI_U8* chanIds;
} AniChanInfoReqMsg;

typedef PACK (struct)
{
  /** primary 20 MHz channel frequency in mhz */
  tANI_U32 mhz;
  /** Center frequency 1 in MHz*/
  tANI_U32 band_center_freq1;
  /** Center frequency 2 in MHz . valid only for 11acvht 80plus80 mode*/
  tANI_U32 band_center_freq2;
  /** channel info described below */
  tANI_U32 info;
  /** contains min power, max power, reg power and reg class id.  */
  tANI_U32 reg_info_1;
  /** contains antennamax */
  tANI_U32 reg_info_2;
} wmi_channel;

typedef PACK (struct)
{
  /* channel id */
  tANI_U32 chan_id;
  tANI_U32 reserved0;
  wmi_channel channel_info;

} Ani_channel_info;

/******** OEM message subtype information *************/

typedef tANI_U32 OemMsgSubType;

#define TARGET_OEM_CAPABILITY_REQ       0x01
#define TARGET_OEM_CAPABILITY_RSP       0x02
#define TARGET_OEM_MEASUREMENT_REQ      0x03
#define TARGET_OEM_MEASUREMENT_RSP      0x04
#define TARGET_OEM_ERROR_REPORT_RSP     0x05
#define TARGET_OEM_NAN_MEAS_REQ         0x06
#define TARGET_OEM_NAN_MEAS_RSP         0x07
#define TARGET_OEM_NAN_PEER_INFO        0x08
#define TARGET_OEM_CONFIGURE_LCR        0x09
#define TARGET_OEM_CONFIGURE_LCI        0x0A
#define TARGET_OEM_LCI_REQ              0x80
#define TARGET_OEM_FTMR_REQ             0x81

/* WMI message information starts here */
#define MAX_WMI_MESSAGE_SIZE 1400 // in bytes

/* MAX Civic Info string length */
#define MAX_CIVIC_INFO_LEN 255

// Size of elements in bytes
// LCI Elements
#define LCI_LCI_ELE_MAX_LEN 18
#define LCI_Z_ELE_MAX_LEN 5
#define LCI_USAGE_RULES_MAX_LEN 5
#define LCI_CO_LOC_BSSIDS_MAX_LEN 257
#define LCI_FTM_LCI_TOT_MAX_LEN (LCI_LCI_ELE_MAX_LEN + LCI_Z_ELE_MAX_LEN + LCI_USAGE_RULES_MAX_LEN + LCI_CO_LOC_BSSIDS_MAX_LEN)
// Location Civic Element
// Civic Loca Type (1) + Sub Ele ID (1) + Len (1) + Loc Civic (255 - Max)
#define LOC_CIVIC_ELE_MAX_LEN 258

/* MAX Length of co-located bssid info.
   Currently we give max length is 32 * SIZEOF(MAC_ADDRS) + 3 + 1(padding) */
#define MAX_COLOCATED_INFO_LEN 196

/******** Access Macros ***************/
#define WMI_F_MS(_v, _f)                             \
  ( ((_v) & (_f)) >> (_f##_S) )

#define WMI_F_RMW(_var, _v, _f)                      \
  do {                                               \
  (_var) &= ~(_f);                                   \
  (_var) |= ( ((_v) << (_f##_S)) & (_f));            \
  } while (0)



/*-----------Rome RTT Request Header IE --------------*/
// Used for Where are you: LCI measurement request
typedef PACK(struct)
{
    tANI_U32  req_id;             //unique request ID for this req
    tANI_U8   sta_mac[BSSID_SIZE];// Target MAC address
    tANI_U8   dialogtoken;        // Dialogue token
    tANI_U16  num_repetitions;    // Number of repetations
    tANI_U8   element_id;         // Element id for measurement request as per defined in nl80211
    tANI_U8   length;             // Total length of elements which appear after this
    tANI_U8   meas_token;         // Unique nonzero number for Measurement Request elements
    tANI_U8   meas_req_mode;      // Measurement Request Mode field
    tANI_U8   meas_type;          // LCI Measurement Request Types as per defined in nl80211
    tANI_U8   loc_subject;        // Location Subject field of LCI request
}
meas_req_lci_request;

// Used for FTMRR
#define MAX_NEIGHBOR_NUM 15
typedef PACK(struct) {
  tANI_U8 sub_element_id;
  tANI_U8 sub_element_len;
  tANI_U8 bssid[BSSID_SIZE];
  tANI_U32 bssid_info;
  tANI_U8 operating_class;
  tANI_U8 channel_num;
  tANI_U8 phy_type;
  tANI_U8 wbc_element_id;
  tANI_U8 wbc_len;
  tANI_U8 wbc_ch_width;
  tANI_U8 wbc_center_ch0;
  tANI_U8 wbc_center_ch1;
}
neighbor_report_element_arr;

typedef PACK(struct) {
    tANI_U32  req_id;             //unique request ID for this req
    tANI_U8 sta_mac[BSSID_SIZE];
    tANI_U8 dialogtoken;
    tANI_U16 num_repetitions;
    tANI_U8 element_id;
    tANI_U8 len;
    tANI_U8 meas_token;
    tANI_U8 meas_req_mode;
    tANI_U8 meas_type;
    tANI_U16 rand_inter;         // upper bound of the random delay to be used prior to making the measurement
    tANI_U8 min_ap_count;        // minimum number of fine timing measurement ranges
    neighbor_report_element_arr elem[MAX_NEIGHBOR_NUM];
}
neighbor_report_arr;

typedef enum
{
    MOTION_NOT_EXPECTED = 0, // Not expected to change location
    MOTION_EXPECTED = 1,     // Expected to change location
    MOTION_UNKNOWN  = 2,     // Movement pattern unknown
}
wmi_rtt_z_subelem_motion_pattern;

typedef PACK (struct)
{
    tANI_U32 req_id; //unique request ID for this RTT measure req
    /******************************************************************************
     *bits 15:0       Request ID
     *bit  16:        sps enable  0- unenable  1--enable
     *bits 31:17      reserved
     ******************************************************************************/
    tANI_U64 latitude;             // LS 34 bits - latitude in degrees * 2^25 , 2's complement
    tANI_U64 longitude;            // LS 34 bits - latitude in degrees * 2^25 , 2's complement
    tANI_U32 lci_cfg_param_info;   // Uncertainities & motion pattern cfg
    /******************************************************************************
     *bits 7:0       Latitude_uncertainity as defined in Section 2.3.2 of IETF RFC 6225
     *bits 15:8      Longitude_uncertainity as defined in Section 2.3.2 of IETF RFC 6225
     *bits 18:16     Datum
     *bits 19:19     RegLocAgreement
     *bits 20:20     RegLocDSE
     *bits 21:21     Dependent State
     *bits 23:22     Version
     *bits 27:24     motion_pattern for use with z subelement cfg as per
                     wmi_rtt_z_subelem_motion_pattern
     *bits 28:28     co-located BSSIDs info is present
     *bits 30:29     Reserved
     *bits 31:31     Clear LCI - Force LCI to "Unknown"
      ******************************************************************************/
    tANI_U32 altitude;             // LS 30bits - Altitude in units of 1/256 m
    tANI_U32 altitude_info;
    /******************************************************************************
     *bits 7:0       Altitude_uncertainity as defined in Section 2.4.5 of IETF RFC 6225
     *bits 15:8      Altitude type
     *bits 31:16     Reserved
      ******************************************************************************/
     //Following elements for configuring the Z subelement
    tANI_U32  floor;               // in units 1/16th of floor # if known.
                                   // value is 80000000 if unknown.
    tANI_U32  floor_param_info;    // height_above_floor & uncertainity
    /******************************************************************************
     *bits 15:0      Height above floor in units of 1/64 m
     *bits 23:16     Height uncertainity as defined in 802.11REVmc D4.0 Z subelem format
                     value 0 means unknown, values 1-18 are valid and 19 and above are reserved
     *bits 31:24     reserved
      ******************************************************************************/
    tANI_U32  usage_rules;
    /******************************************************************************
     *bit  0         usage_rules: retransmittion allowed: 0-No 1-Yes
     *bit  1         usage_rules: retention expires relative present: 0-No 1-Yes
     *bit  2         usage_rules: STA Location policy for Additional neighbor info: 0-No 1-Yes
     *bits 7:3       usage_rules: reserved
     *bits 23:8      usage_rules: retention expires relative, if present, as per IETF RFC 4119
     *bits 31:24     reserved
      ******************************************************************************/
    tANI_U32 co_located_bssid_len;
    /******************************************************************************
     *bit  15:0      Length of co-located bssid info
     *bit  31:16     reserved
     ******************************************************************************/
    tANI_U8  colocated_bssids_info[MAX_COLOCATED_INFO_LEN];
} wmi_rtt_lci_cfg_head;

typedef PACK (struct)
{
    tANI_U32 req_id; //unique request ID for this RTT measure req
    /******************************************************************************
     *bit 15:0       Request ID
     *bit 16:        sps enable  0- unenable  1--enable
     *bit 31:17      reserved
     ******************************************************************************/
    tANI_U32 loc_civic_params; // country code and length
    /******************************************************************************
     *bit 7:0        len in bytes. civic_info to be used in reference to this.
     *bit 31:8       reserved
     ******************************************************************************/
    tANI_U32 civic_info[64];      // Civic info including country_code to be copied in FTM frame.
                                  // 256 bytes max. Based on len, FW will copy byte-wise into
                                  // local buffers and transfer OTA. This is packed as a 4 bytes
                                  // aligned buffer at this interface for transfer to FW though.
} wmi_rtt_lcr_cfg_head;


#define WMI_RTT_LCI_LAT_UNC_S 0
#define WMI_RTT_LCI_LAT_UNC (0xff << WMI_RTT_LCI_LAT_UNC_S)
#define WMI_RTT_LCI_LAT_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_LAT_UNC)
#define WMI_RTT_LCI_LAT_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_LAT_UNC)

#define WMI_RTT_LCI_LON_UNC_S 8
#define WMI_RTT_LCI_LON_UNC (0xff << WMI_RTT_LCI_LON_UNC_S)
#define WMI_RTT_LCI_LON_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_LON_UNC)
#define WMI_RTT_LCI_LON_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_LON_UNC)

#define WMI_RTT_LCI_ALT_UNC_S 16
#define WMI_RTT_LCI_ALT_UNC (0xff << WMI_RTT_LCI_ALT_UNC_S)
#define WMI_RTT_LCI_ALT_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_ALT_UNC)
#define WMI_RTT_LCI_ALT_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_ALT_UNC)

#define WMI_RTT_LCI_Z_MOTION_PAT_S 24
#define WMI_RTT_LCI_Z_MOTION_PAT (0xff << WMI_RTT_LCI_Z_MOTION_PAT_S)
#define WMI_RTT_LCI_Z_MOTION_PAT_GET(x) WMI_F_MS(x,WMI_RTT_LCI_Z_MOTION_PAT)
#define WMI_RTT_LCI_Z_MOTION_PAT_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_Z_MOTION_PAT)

#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_S 0
#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR (0xffff << WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_S)
#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_GET(x) WMI_F_MS(x,WMI_RTT_LCI_Z_HEIGHT_ABV_FLR)
#define WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_Z_HEIGHT_ABV_FLR)

#define WMI_RTT_LCI_Z_HEIGHT_UNC_S 16
#define WMI_RTT_LCI_Z_HEIGHT_UNC (0xff << WMI_RTT_LCI_Z_HEIGHT_UNC_S)
#define WMI_RTT_LCI_Z_HEIGHT_UNC_GET(x) WMI_F_MS(x,WMI_RTT_LCI_Z_HEIGHT_UNC)
#define WMI_RTT_LCI_Z_HEIGHT_UNC_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_Z_HEIGHT_UNC)

#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_S 0
#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED (0x1 << WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_S)
#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED)
#define WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_RETRANS_ALLOWED)

#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_S 1
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP (0x1 << WMI_RTT_LCI_USG_RUL_RETENTION_EXP_S)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_RETENTION_EXP)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_RETENTION_EXP)

#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_S 2
#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY (0x1 << WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_S)
#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY)
#define WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_STA_LOC_POLICY)

#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_S 8
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE (0xff << WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_S)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_GET(x) WMI_F_MS(x,WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE)
#define WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LCI_USG_RUL_RETENTION_EXP_RELATIVE)

#define WMI_RTT_LOC_CIVIC_LENGTH_S 0
#define WMI_RTT_LOC_CIVIC_LENGTH (0xff << WMI_RTT_LOC_CIVIC_LENGTH_S)
#define WMI_RTT_LOC_CIVIC_LENGTH_GET(x) WMI_F_MS(x,WMI_RTT_LOC_CIVIC_LENGTH)
#define WMI_RTT_LOC_CIVIC_LENGTH_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_LOC_CIVIC_LENGTH)

typedef PACK (struct)
{
  /******************************************************************************
   * Uniquie Request ID for this RTT Meas Req
   *bit 15:0       Request ID
   *bit 16:        sps enable  0- unenable  1--enable
   *bit 31:17      reserved
   ******************************************************************************/
  tANI_U32 requestID;

  /******************************************************************************
   * Total Number of STA in this RTT Meas Request
   *bit 7:0        # of measurement peers
   *bit 23:8       if  sps, time delay for SPS (ms)
   *bit 31:24      reserved
   ******************************************************************************/
  tANI_U32 numSTA;

  wmi_channel channelInfo;
} RomeRttReqHeaderIE;

#define WMI_RTT_REQ_ID_S 0
#define WMI_RTT_REQ_ID (0xffff << WMI_RTT_REQ_ID_S)
#define WMI_RTT_REQ_ID_GET(x) WMI_F_MS(x,WMI_RTT_REQ_ID)
#define WMI_RTT_REQ_ID_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REQ_ID)

#ifndef USE_NEW_MEAS_REQ_TLV_DEFS
//SPS here is synchronized power save
#define WMI_RTT_SPS_S 16
#define WMI_RTT_SPS (0x1 << WMI_RTT_SPS_S)
#define WMI_RTT_SPS_GET(x) WMI_F_MS(x,WMI_RTT_SPS)
#define WMI_RTT_SPS_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_SPS)

#define WMI_RTT_NUM_STA_S 0
#define WMI_RTT_NUM_STA (0xff << WMI_RTT_NUM_STA_S)
#define WMI_RTT_NUM_STA_GET(x) WMI_F_MS(x,WMI_RTT_NUM_STA)
#define WMI_RTT_NUM_STA_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_NUM_STA)

#define WMI_RTT_SPS_DELAY_S 8
#define WMI_RTT_SPS_DELAY (0xffff << WMI_RTT_SPS_DELAY_S)
#define WMI_RTT_SPS_DELAY_GET(x) WMI_F_MS(x,WMI_RTT_SPS_DELAY)
#define WMI_RTT_SPS_DELAY_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_SPS_DELAY)
#endif

/*-----------Rome RTT Request Command IE --------------*/

#define FRAME_TYPE_NULL     0   /* RTT Type 2 */
#define FRAME_TYPE_QOS_NULL 1   /* RTT Type 2 */
#define FRAME_TYPE_TMR      2   /* RTT Type 3 */

#define TX_CHAIN_1          0x1
#define TX_CHAIN_2          0x2
#define TX_CHAIN_3          0x4

#define RX_CHAIN_1          0x1
#define RX_CHAIN_2          0x2
#define RX_CHAIN_3          0x4

#define NON_QTI_PEER        0
#define QTI_PEER            1

#define ROME_BW_20MHZ            0
#define ROME_BW_40MHZ            1
#define ROME_BW_80MHZ            2
#define ROME_BW_160MHZ           3

#define ROME_PREAMBLE_LEGACY     0
#define ROME_PREAMBLE_CCK        1
#define ROME_PREAMBLE_HT         2
#define ROME_PREAMBLE_VHT        3

#define REPORT_CFR_NOFAC_1FRAME        0
#define REPORT_NOCFR_FAC_1FRAME        1
#define REPORT_AGGREGATE_MULTIFRAME    2

typedef PACK (struct)
{
  /*********************************************************************************
   *Bits 1:0:   Reserved
   *Bits 4:2:   802.11 Frame Type to measure RTT
   *            000: NULL, 001: Qos NULL, 010: TMR-TM
   *Bits 8:5:   Tx chain mask used for transmission 0000 - 1111
   *Bits 12:9:  Receive chainmask to use for reception 0000 - 1111
   *Bits 13:13  peer is qca chip or not
   *Bits 15:14: BW 0- 20MHz 1- 40MHz 2- 80MHz 3 - 160 MHz
   *Bits 17:16: Preamble 0- Legacy 1- CCK 2- HT 3- VHT
   *Bits 21:18: Retry times
   *Bits 29:22  MCS
   *Bits 31:30  Reserved
   *********************************************************************************/
  tANI_U32 controlFlag;

  /*******************************************************************************
   *Bit 0-7 vdev_id vdev used for RTT
   *Bit 15-8 num_meas #of measurements of each peer
   *Bit 23:16 timeout for this rtt mesurement (ms)
   *Bit 31-24 report_type
   *******************************************************************************/
  tANI_U32 measurementInfo;

  tANI_U8 destMac[ETH_ALEN + 2];     /* 2 extra bytes added for alignment */
  tANI_U8 spoofBSSID[ETH_ALEN + 2];  /* 2 extra bytes added for alignment */

  /**********************************************************************************
   * FTMR Related fields
   * Bit 0: ASAP = 0/1 - This field indicates whether to start FTM session
   *                     immediately or not. ASAP = 1 means immediate FTM session
   * Bit 1: LCI Req = True/False   - Request Location Configuration Information report
   * Bit 2: Location Civic Req = True/False
   * Bit 3: TSF Delta Valid 1:True 0:False
   * Bits 4-7: Reserved
   * Bits 8-11: Number of Bursts Exponent - This field indicates the number of
   *            bursts of FTM bursts to perform. The numbe rof bursts is indidcated
   *            as Num of Bursts = 2^ Burst exponent. This format is used to be
   *            consistent with the format in the 802.11mc spec.
   * Bits 12-15: Burst Duration - Duration of each FTM burst, defined by the
   *             following table:
   *                                   Value               Burst Duration
   *                                    0-1                   Reserved
   *                                     2                      250us
   *                                     3                      500us
   *                                     4                        1ms
   *                                     5                        2ms
   *                                     6                        4ms
   *                                     7                        8ms
   *                                     8                       16ms
   *                                     9                       32ms
   *                                     10                      64ms
   *                                     11                     128ms
   *                                   12-14                  Reserved
   *                                     15                 No Preference
   *
   * Bits 16-31: Burst Period (time between Bursts) Units: 100ms (0 - no preference)
   *********************************************************************************/
  #define FTM_TSF_BIT 3
  #define FTM_SET_TSF_VALID(x) (x = (x | (1 << FTM_TSF_BIT)))
  #define FTM_CLEAR_TSF_VALID(x) (x & ~(1 << FTM_TSF_BIT))
  #define FTM_GET_TSF_VALID_BIT(x) ((x & (1 << FTM_TSF_BIT)) >> FTM_TSF_BIT)
  tANI_U32 ftmParams;

  /* Bits 31:0:   Signed TSF Delta between local device and target device */
  tANI_U32 tsfDelta;

} RomeRTTReqCommandIE;

#define WMI_RTT_VDEV_ID_S 0
#define WMI_RTT_VDEV_ID (0xff << WMI_RTT_VDEV_ID_S)
#define WMI_RTT_VDEV_ID_GET(x) WMI_F_MS(x,WMI_RTT_VDEV_ID)
#define WMI_RTT_VDEV_ID_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_VDEV_ID)

#ifndef USE_NEW_MEAS_REQ_TLV_DEFS
/*RTT Req Command Macros */
#define WMI_RTT_FRAME_TYPE_S 2
#define WMI_RTT_FRAME_TYPE (7 << WMI_RTT_FRAME_TYPE_S)
#define WMI_RTT_FRAME_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_FRAME_TYPE)
#define WMI_RTT_FRAME_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_FRAME_TYPE)

#define WMI_RTT_TX_CHAIN_S 5
#define WMI_RTT_TX_CHAIN (0xf << WMI_RTT_TX_CHAIN_S)
#define WMI_RTT_TX_CHAIN_GET(x) WMI_F_MS(x,WMI_RTT_TX_CHAIN)
#define WMI_RTT_TX_CHAIN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_TX_CHAIN)

#define WMI_RTT_RX_CHAIN_S 9
#define WMI_RTT_RX_CHAIN (0xf << WMI_RTT_RX_CHAIN_S)
#define WMI_RTT_RX_CHAIN_GET(x) WMI_F_MS(x,WMI_RTT_RX_CHAIN)
#define WMI_RTT_RX_CHAIN_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RX_CHAIN)

#define WMI_RTT_QCA_PEER_S 13
#define WMI_RTT_QCA_PEER (0x1 << WMI_RTT_QCA_PEER_S)
#define WMI_RTT_QCA_PEER_GET(x) WMI_F_MS(x,WMI_RTT_QCA_PEER)
#define WMI_RTT_QCA_PEER_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_QCA_PEER)

#define WMI_RTT_BW_S 14
#define WMI_RTT_BW (0x3 <<WMI_RTT_BW_S)
#define WMI_RTT_BW_GET(x) WMI_F_MS(x,WMI_RTT_BW)
#define WMI_RTT_BW_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_BW)

#define WMI_RTT_PREAMBLE_S 16
#define WMI_RTT_PREAMBLE (0x3 <<WMI_RTT_PREAMBLE_S)
#define WMI_RTT_PREAMBLE_GET(x) WMI_F_MS(x,WMI_RTT_PREAMBLE)
#define WMI_RTT_PREAMBLE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_PREAMBLE)

#define WMI_RTT_RETRIES_S 18
#define WMI_RTT_RETRIES (0xf << WMI_RTT_RETRIES_S)
#define WMI_RTT_RETRIES_GET(x) WMI_F_MS(x,WMI_RTT_RETRIES)
#define WMI_RTT_RETRIES_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_RETRIES)

#define WMI_RTT_MCS_S 22
#define WMI_RTT_MCS (0xff << WMI_RTT_MCS_S)
#define WMI_RTT_MCS_GET(x) WMI_F_MS(x,WMI_RTT_MCS)
#define WMI_RTT_MCS_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_MCS)

#define WMI_RTT_MEAS_NUM_S 8
#define WMI_RTT_MEAS_NUM (0xff << WMI_RTT_MEAS_NUM_S)
#define WMI_RTT_MEAS_NUM_GET(x) WMI_F_MS(x,WMI_RTT_MEAS_NUM)
#define WMI_RTT_MEAS_NUM_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_MEAS_NUM)

#define WMI_RTT_TIMEOUT_S 16
#define WMI_RTT_TIMEOUT (0xff << WMI_RTT_TIMEOUT_S)
#define WMI_RTT_TIMEOUT_GET(x) WMI_F_MS(x,WMI_RTT_TIMEOUT)
#define WMI_RTT_TIMEOUT_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_TIMEOUT)

#define WMI_RTT_REPORT_TYPE_S 24
#define WMI_RTT_REPORT_TYPE (0x3 <<WMI_RTT_REPORT_TYPE_S)
#define WMI_RTT_REPORT_TYPE_GET(x) WMI_F_MS(x,WMI_RTT_REPORT_TYPE)
#define WMI_RTT_REPORT_TYPE_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REPORT_TYPE)
#endif

/*-----------Rome RTT Measurement Report Header IE --------------*/

#define RTT_FAILED  0
#define RTT_SUCCESS 1

typedef PACK (struct)
{
  /*Request ID and Command info
   *bit 0:15 req_id from measurement request command
   *bit 16: Success 1 / Fail 0
   *bit 17: Measurement Finished 1 / Measurement not Finished 0 (report type 2 ignore)
   *bit 20:18 RTT measurement Type 000 - NULL 001-QoS_NULL 002 -TMR
   *bit 23:21 report type (0,1,2)
   *bit 25:24 V3 report status (v2 ignore) (report type 2 ignore)
   *    00-Good 01 - Bad CFR 10 -- bad token
   *bit 26:   V3 accomplishment (v2 ignore) (report type 2 ignore)
   *    0 - sending side is not finishing
   *    1 - sending side finish
   *bit 27: V3 start of a TM sequence (v2 ignore) (report type 2 ignore)
   *    0 - not a start frame  1 -- start frame
   *bit 31:28: #of AP inside this report (only for report type 2, 0,1 ignore)
   */
  tANI_U32 req_id;

  tANI_U8 dest_mac[ETH_ALEN + 2];  /* 2 extra bytes added for alignment */
  //In report type 1 and 2, MAC of the AP
  //in report type 2, bit 31:0 is the channel info
} RomeRTTReportHeaderIE;

/* RTT report macros */
#define WMI_RTT_REPORT_REQ_ID_S 0
#define WMI_RTT_REPORT_REQ_ID (0xffff << WMI_RTT_REPORT_REQ_ID_S)
#define WMI_RTT_REPORT_REQ_ID_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_REQ_ID)
#define WMI_RTT_REPORT_REQ_ID_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_REQ_ID)

#define WMI_RTT_REPORT_CHAN_INFO_S 0
#define WMI_RTT_REPORT_CHAN_INFO (0xffffffff << WMI_RTT_REPORT_CHAN_INFO_S)
#define WMI_RTT_REPORT_CHAN_INFO_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_CHAN_INFO)
#define WMI_RTT_REPORT_CHAN_INFO_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_CHAN_INFO)

#define WMI_RTT_REPORT_STATUS_S 16
#define WMI_RTT_REPORT_STATUS (0x1 << WMI_RTT_REPORT_STATUS_S)
#define WMI_RTT_REPORT_STATUS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_STATUS)
#define WMI_RTT_REPORT_STATUS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_STATUS)

#ifndef USE_NEW_MEAS_RSP_TLV_DEFS

#define WMI_RTT_REPORT_MEAS_TYPE_S 18
#define WMI_RTT_REPORT_MEAS_TYPE (0x7 << WMI_RTT_REPORT_MEAS_TYPE_S)
#define WMI_RTT_REPORT_MEAS_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_MEAS_TYPE)
#define WMI_RTT_REPORT_MEAS_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_MEAS_TYPE)

#define WMI_RTT_REPORT_REPORT_TYPE_S 21
#define WMI_RTT_REPORT_REPORT_TYPE (0x7 << WMI_RTT_REPORT_REPORT_TYPE_S)
#define WMI_RTT_REPORT_REPORT_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_REPORT_TYPE)
#define WMI_RTT_REPORT_REPORT_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_REPORT_TYPE)

#define WMI_RTT_REPORT_V3_STATUS_S 24
#define WMI_RTT_REPORT_V3_STATUS (0x3 << WMI_RTT_REPORT_V3_STATUS_S)
#define WMI_RTT_REPORT_V3_STATUS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_STATUS)
#define WMI_RTT_REPORT_V3_STATUS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_STATUS)

#define WMI_RTT_REPORT_V3_FINISH_S 26
#define WMI_RTT_REPORT_V3_FINISH (0x1 << WMI_RTT_REPORT_V3_FINISH_S)
#define WMI_RTT_REPORT_V3_FINISH_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_FINISH)
#define WMI_RTT_REPORT_V3_FINISH_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_FINISH)

#define WMI_RTT_REPORT_V3_TM_START_S 27
#define WMI_RTT_REPORT_V3_TM_START (0x1 << WMI_RTT_REPORT_V3_TM_START_S)
#define WMI_RTT_REPORT_V3_TM_START_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_V3_TM_START)
#define WMI_RTT_REPORT_V3_TM_START_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_V3_TM_START)

#define WMI_RTT_REPORT_NUM_AP_S 28     //used for only Report Type 2
#define WMI_RTT_REPORT_NUM_AP (0xf << WMI_RTT_REPORT_NUM_AP_S)
#define WMI_RTT_REPORT_NUM_AP_GET(x) WMI_F_MS(x,WMI_RTT_REPORT_NUM_AP)
#define WMI_RTT_REPORT_NUM_AP_SET(x,z) WMI_F_RMW(x,z,WMI_RTT_REPORT_NUM_AP)
#endif

typedef enum {
    RTT_COMMAND_HEADER_ERROR          = 0,  //rtt cmd header parsing error  --terminate
    RTT_COMMAND_ERROR                 = 1,  //rtt body parsing error -- skip current STA REQ
    RTT_MODULE_BUSY                   = 2,  //rtt no resource        -- terminate
    RTT_TOO_MANY_STA                  = 3,  //exceed support limit, service only up to limit
    RTT_NO_RESOURCE                   = 4,  //any allocate failure
    RTT_VDEV_ERROR                    = 5,  //can not find vdev with vdev ID -- skip current STA REQ
    RTT_TRANSIMISSION_ERROR           = 6,  //Tx failure   -- continiue and measure number--
    RTT_TM_TIMER_EXPIRE               = 7,  //wait for first TM timer expire. Target did not send
                                            //an FTM1 or not all FTM frms came during the burst
                                            //duration -- terminate current STA measurement
    RTT_FRAME_TYPE_NOSUPPORT          = 8,  //RTT measurement not supported w/this frm type
    RTT_TIMER_EXPIRE                  = 9,  //if channel allocation timeout occurs before
                                            //whole RTT measurement timer expire  --
                                            //terminate current STA measurement
    RTT_CHAN_SWITCH_ERROR             = 10, //channel swicth failed
    RTT_TMR_TRANS_ERROR               = 11, //TMR trans error, this dest peer will be skipped
    RTT_NO_REPORT_BAD_CFR_TOKEN       = 12, //V3 only. If both CFR and Token mismatch, do not report
    RTT_NO_REPORT_FIRST_TM_BAD_CFR    = 13, //For First TM, if CFR is bad, then do not report
    RTT_REPORT_TYPE2_MIX              = 14, //do not allow report type 2 mix with type 0, 1, 3
    RTT_REPORT_TYPE3_MIX              = 15, //do not allow report type 3 mix with type 0, 1, 2
    RTT_LCI_CFG_OK                    = 16, //LCI Configuration OK. - Responder only
    RTT_LCR_CFG_OK                    = 17, //LCR configuration OK. - Responder only
    RTT_CFG_ERROR                     = 18, //Bad configuration LCI (or) LCR request - Rspder only
    RTT_STATUS_SUCCESS                = 19,
    RTT_UNKNOWN_REPORT_TYPE           = 20,
    RTT_TOO_MANY_CHAN_CONFIG          = 21, //channel configuration exceeds the max supported limit;
                                            //request won't be serviced
    RTT_DUPLICATE_REQ_ID              = 22, //request won't be serviced
    RTT_TOO_MANY_MULTIBURST_SESSIONS  = 23, //Too many multiburst sessions
    RTT_MULTIBUST_INVALID_REPORT_TYPE = 24, //Invalid rprt type (valid rprt type is 3 only)
    RTT_CFG_RESPONDER_MODE_FAIL       = 25, // Failed to enable responder mode
    RTT_CFG_RESPONDER_MODE_SUCCESS    = 26, // enabled responder mode successfully
#ifndef LOWI_ON_ACCESS_POINT
    RTT_DFS_CHANNEL_QUIET             = 27, // DFS channel is quiet, no beacons seen
    RTT_VOIP_IN_PROGRESS              = 28, // VOIP in progress during measurements
    RTT_LCI_REQ_OK                    = 29, // Where are you/LCI request OK
    RTT_FTMRR_OK                      = 30, // FTMRR OK
    RTT_CANCEL_MEASUREMENT_REQ_FAILED = 31, // Failed to cancel ranging request
    RTT_PDEV_ERROR                    = 32, // Invalid pdev ID
    RTT_NAN_REQUEST_FAILURE           = 33, // NAN ranging request failure
    RTT_NAN_NEGOTIATION_FAILURE       = 34, // NAN Ranging negotiation failure
    RTT_NAN_DATA_PATH_ACTIVE          = 35, // Active NDP
    WMI_RTT_REJECT_MAX                = 255
#else
    RTT_LCI_REQ_OK                    = 27, // Where are you/LCI request OK
    RTT_FTMRR_OK                      = 28, // FTMRR OK
    /* Following two needs to be confirmed */
    RTT_DFS_CHANNEL_QUIET             = 29, // DFS channel is quiet, no beacons seen
    RTT_VOIP_IN_PROGRESS              = 30, // VOIP in progress during measurements
    RTT_CANCEL_MEASUREMENT_REQ_FAILED = 31, // Failed to cancel ranging request
    RTT_PDEV_ERROR                    = 32, // Invalid pdev ID
    RTT_NAN_REQUEST_FAILURE           = 33, // NAN ranging request failure
    RTT_NAN_NEGOTIATION_FAILURE       = 34, // NAN Ranging negotiation failure
    RTT_NAN_DATA_PATH_ACTIVE          = 35, // Active NDP
    WMI_RTT_REJECT_MAX                = 255
#endif
} WMI_RTT_STATUS_INDICATOR;

typedef PACK (struct)
{
  tANI_U32 rttErrorInfo;
} RomeRTTErrorResponseIE;

/*-----------Rome RTT Measurement Response IE for Response type 0 & 1 --------------*/

#define WMI_RTT_REPORT_RX_CHAIN_S 0
#define WMI_RTT_REPORT_RX_CHAIN (0xf << WMI_RTT_REPORT_RX_CHAIN_S)
#define WMI_RTT_REPORT_RX_CHAIN_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_RX_CHAIN)
#define WMI_RTT_REPORT_RX_CHAIN_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_RX_CHAIN)

#define WMI_RTT_REPORT_RX_BW_S 4
#define WMI_RTT_REPORT_RX_BW (0x3 << WMI_RTT_REPORT_RX_BW_S)
#define WMI_RTT_REPORT_RX_BW_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_RX_BW)
#define WMI_RTT_REPORT_RX_BW_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_RX_BW)

/*-----------Rome RTT Measurement Response IE for Response type 2 --------------*/
typedef PACK (struct)
{

  tANI_U8  dest_mac[ETH_ALEN + 2];  /* 2 extra bytes added for alignment */

  /* Control Field
   *bit 0:7 #of measurement reports for this AP
   *bit 10:8 RTT measurement type
   *bit 31:11 reserved
   */
  tANI_U32 control;

  /** bits 15:0: num_frames_attempted
   *  bits 31:16: actual_burst_duration
   */
  tANI_U32 result_info1;

  /** bits 7:0:  negotiated_num_frames_per_burst
   *  bits 15:8: retry_after_duration
   *  bits 23:16 actual_burst_exp
   *  bits 31:24 num_ie_in_hdr
   *  If event contains an IE, num_ie_in_hdr will be nonzero and
   *  based on num_ie_in_hdr, wmi_rtt_ie (s) will follow here.
   *  Each IE has a length field according to which
   *  wmi_rtt_per_frame_ie_v2 or wmi_rtt_per_frame_ie_v2 will
   *  follow // the wmi_rtt_ie (s)
   */
  tANI_U32 result_info2;
} RomeRttPerPeerReportHdr;

#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_S 0
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS (0xff << WMI_RTT_REPORT_TYPE2_NUM_MEAS_S)
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_NUM_MEAS)
#define WMI_RTT_REPORT_TYPE2_NUM_MEAS_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_NUM_MEAS)

#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_S 8
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE (0x7 << WMI_RTT_REPORT_TYPE2_MEAS_TYPE_S)
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_MEAS_TYPE)
#define WMI_RTT_REPORT_TYPE2_MEAS_TYPE_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_MEAS_TYPE)

#define WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED_S 0
#define WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED (0xffff << WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED_S)
#define WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED)
#define WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED)

#define WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR_S 16
#define WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR (0xffff << WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR_S)
#define WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR)
#define WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR)

#define WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST_S 0
#define WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST (0xff << WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST_S)
#define WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST)
#define WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST)

#define WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR_S 8
#define WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR (0xff << WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR_S)
#define WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR)
#define WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR)

#define WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP_S 16
#define WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP (0xff << WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP_S)
#define WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP)
#define WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP)

#define WMI_RTT_REPORT_TYPE2_NUM_IES_S 24
#define WMI_RTT_REPORT_TYPE2_NUM_IES (0xff << WMI_RTT_REPORT_TYPE2_NUM_IES_S)
#define WMI_RTT_REPORT_TYPE2_NUM_IES_GET(x) WMI_F_MS(x, WMI_RTT_REPORT_TYPE2_NUM_IES)
#define WMI_RTT_REPORT_TYPE2_NUM_IES_SET(x,z) WMI_F_RMW(x,z, WMI_RTT_REPORT_TYPE2_NUM_IES)

/* TLVs for WMI_RTT_IES */

#define MAX_RTT_IE_LEN 600
typedef PACK(struct)
{
  // IE Element ID
  tANI_U8 ieID;
  // IE Length
  tANI_U8 ieLen;
  // this will be the IE data - and the data will be of ieLen (above)
  tANI_U8 bytes[MAX_RTT_IE_LEN];
} wmi_rtt_ie;

#define RTT_MEAS_TYPE_UNKNOWN 255
#define RTT_LCI_ELE_ID        8
#define RTT_LOC_CIVIC_ELE_ID  11

/** The following are access macros for the wmi_rtt_ie fields */
#define WMI_RTT_WMI_RTT_IE_LEN (2*sizeof(tANI_U8))
#define WMI_RTT_WMI_RTT_IE_ELE_ID_S  0
#define WMI_RTT_WMI_RTT_IE_ELE_ID    (0xff << WMI_RTT_WMI_RTT_IE_ELE_ID_S)
#define WMI_RTT_WMI_RTT_IE_ELE_ID_GET(x)  WMI_F_MS(x, WMI_RTT_WMI_RTT_IE_ELE_ID)
#define WMI_RTT_RSP_WMI_RTT_IE_LEN_S 8
#define WMI_RTT_RSP_WMI_RTT_IE_LEN   (0xff << WMI_RTT_RSP_WMI_RTT_IE_LEN_S)
#define WMI_RTT_RSP_WMI_RTT_IE_LEN_GET(x) WMI_F_MS(x, WMI_RTT_RSP_WMI_RTT_IE_LEN)

typedef PACK (struct)
{
  tANI_U32 time32;     //upper 32 bits of time stamp
  tANI_U32 time0;      //lower 32 bits of time stamp
} tANI_TIME64;

typedef PACK (struct)
{
  tANI_U32 rx_bw;
  tANI_U32 rssi;
  tANI_TIME64 tod;
  tANI_TIME64 toa;

  tANI_U32 tx_rate_info_1;
  /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
   *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
   *  bits 7:    reserved
   *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
   *                           ieee std in the units of 0.5mbps
   *                         - HT/VHT it would be mcs index
   *  31:16: reserved  */

  tANI_U32 tx_rate_info_2;
  /** bits 31:0: TX bit rate in 100kbps */

  tANI_U32 rx_rate_info_1;
  /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
   *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
   *  bits 7:    reserved
   *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
   *                           ieee std in the units of 0.5mbps
   *                         - HT/VHT it would be mcs index
   *  31:16: reserved  */

  tANI_U32 rx_rate_info_2;
  /** bits 31:0: TX bit rate in 100kbps */
} RomeRttPerFrame_IE_RTTV2;

typedef PACK (struct)
{
  tANI_U32 rx_bw;
  tANI_U32 rssi;
  tANI_TIME64 t1;
  tANI_TIME64 t2;
  tANI_U32 t3_del;
  tANI_U32 t4_del;

  tANI_U32 tx_rate_info_1;
  /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
   *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
   *  bits 7:    reserved
   *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
   *                           ieee std in the units of 0.5mbps
   *                         - HT/VHT it would be mcs index
   *  31:16: reserved  */

  tANI_U32 tx_rate_info_2;
  /** bits 31:0: TX bit rate in 100kbps */

  tANI_U32 rx_rate_info_1;
  /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
   *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
   *  bits 7:    reserved
   *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
   *                           ieee std in the units of 0.5mbps
   *                         - HT/VHT it would be mcs index
   *  31:16: reserved  */

  tANI_U32 rx_rate_info_2;
  /** bits 31:0: TX bit rate in 100kbps */
} RomeRttPerFrame_IE_RTTV3;

/** The following are access macros for the the varies
 *  bitfields within the "rx_bw_ field in the RTT report
 *  message */
#define WMI_RTT_RSP_PREAMBLE_TYPE_S  0
#define WMI_RTT_RSP_PREAMBLE_TYPE    (0x7 << WMI_RTT_RSP_PREAMBLE_TYPE_S)
#define WMI_RTT_RSP_PREAMBLE_GET(x)  WMI_F_MS(x, WMI_RTT_RSP_PREAMBLE_TYPE)
#define WMI_RTT_RSP_BW_TYPE_S        3
#define WMI_RTT_RSP_BW_TYPE          (0x7 << WMI_RTT_RSP_BW_TYPE_S)
#define WMI_RTT_RSP_BW_GET(x)        WMI_F_MS(x, WMI_RTT_RSP_BW_TYPE)
#define WMI_RTT_RSP_MCS_TYPE_S       6
#define WMI_RTT_RSP_MCS_TYPE         (0x1F << WMI_RTT_RSP_MCS_TYPE_S)
#define WMI_RTT_RSP_MCS_GET(x)       WMI_F_MS(x, WMI_RTT_RSP_MCS_TYPE)
#define WMI_RTT_RSP_BIT_RATE_TYPE_S  11
#define WMI_RTT_RSP_BIT_RATE_TYPE    (0x1FFFFF << WMI_RTT_RSP_BIT_RATE_TYPE_S)
#define WMI_RTT_RSP_BIT_RATE_GET(x)  WMI_F_MS(x, WMI_RTT_RSP_BIT_RATE_TYPE)

#define WMI_RTT_RSP_X_PREAMBLE_S      0
#define WMI_RTT_RSP_X_PREAMBLE        (0x7 << WMI_RTT_RSP_X_PREAMBLE_S)
#define WMI_RTT_RSP_X_PREAMBLE_GET(x) WMI_F_MS(x, WMI_RTT_RSP_X_PREAMBLE)

#define WMI_RTT_RSP_X_BW_USED_S       3
#define WMI_RTT_RSP_X_BW_USED         (0xf << WMI_RTT_RSP_X_BW_USED_S)
#define WMI_RTT_RSP_X_BW_USED_GET(x)  WMI_F_MS(x, WMI_RTT_RSP_X_BW_USED)

#define WMI_RTT_RSP_X_MCS_S      8
#define WMI_RTT_RSP_X_MCS        (0xff << WMI_RTT_RSP_X_MCS_S)
#define WMI_RTT_RSP_X_MCS_GET(x) WMI_F_MS(x, WMI_RTT_RSP_X_MCS)

/* This struct represents the p2p peer status information passed by
 * the driver to LOWI in the p2p info event: ANI_MSG_PEER_STATUS_IND.
 * This information will primarily be used to do RTT ranging between
 * p2p devices when a connection exists.
 */
typedef PACK (struct)
{
  /* peer mac address */
  tANI_U8 peer_mac_addr[6];
  /* peer status: 1: CONNECTED, 2: DISCONNECTED */
  tANI_U8 peer_conn_status;
  /* vdev_id for the peer mac */
  tANI_U8 vdev_id;
  /* peer capability: 0: RTT/RTT2, 1: RTT3. Default is 0 */
  tANI_U32 peer_rtt_cap;
  tANI_U32 reserved0;
  /* channel info on which peer is connected */
  Ani_channel_info peer_chan_info;
} ani_peer_status_info;

/** This struct is used to extract the parameters from the wmi_rtt_oem_measrsp_head TLV */
typedef struct
{
  uint8 rprtType;
  uint8 rttMeasType;
  uint8 rprtStatusV3;
  uint8 sendDoneV3;
  uint8 tmStart;
  uint8 numAPs;
  uint8 destMac[ETH_ALEN_PLUS_2];
  uint32 channel; // primary 20MHz frequency
} rttMeasRspHead;

/** This struct is used to extract the parameters from the
 *  wmi_rtt_oem_per_peer_event_hdr TLV */
typedef struct
{
  uint8  peerMac[ETH_ALEN_PLUS_2];
  uint8  numMeasThisAP;
  uint8  rttMeasType;
  bool   isQtiPeer;
  uint32 numFrmAttempted;
  uint32 actualBurstDur;
  uint8  actualNumFrmPerBur;
  uint8  retryAfterDur;
  uint8  actualBurstExp;
  uint8  numIEs;
  uint32 burstIdx;
  uint32 measStartTSF;
} rttPerPeerInfo;

/** This struct is used to extract the parameters from the
 *  wmi_rtt_oem_per_frame_info TLV */
typedef struct
{
  tANI_TIME64 t1; //tod; resolution picoseconds
  tANI_TIME64 t2; // resolution picoseconds; valid for v3 only
  uint32 rssi;
  uint32 t3_del; // toa -tod; resolution picoseconds
  uint32 t4_del; // resolution picoseconds; valid for v3 only
// A_UINT32 tx_rate_info_1;
  /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
   *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
   *  bits 7:    reserved
   *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
   *                           ieee std in the units of 0.5mbps
   *                         - HT/VHT it would be mcs index
   *  bits 19:16: useTxChainNo
   *  31:20: reserved  */
  uint32 txPreamble :3;
  uint32 txBw :4;
  uint32 txReserved1 :1;
  uint32 txRateMcsIdx :8;
  uint32 useTxChainNo :4;
  uint32 txReserved2 :12;

// A_UINT32 tx_rate_info_2;
  /** bits 31:0: TX bit rate in 100kbps */
  uint32 txBitRate;

//  A_UINT32 rx_rate_info_1;
  /** bits 2:0:  preamble    - 0: OFDM, 1:CCK, 2:HT 3:VHT
   *  bits 6:3:  bw          - 0:20MHz, 1:40Mhz, 2:80Mhz, 3:160Mhz
   *  bits 7:    reserved
   *  bits 15:8: rateMcsIdx  - OFDM/CCK rate code would be as per
   *                           ieee std in the units of 0.5mbps
   *                         - HT/VHT it would be mcs index
   *  bits 19:16: chain mask
   *  bits 23:20  useRxChainNo
   *  31:24: reserved */
  uint32 rxPreamble :3;
  uint32 rxBw :4;
  uint32 rxReserved1 :1;
  uint32 rxRateMcsIdx :8;
  uint32 chainMask :4;
  uint32 useRxChainNo :4;
  uint32 rxReserved2 :8;

//  A_UINT32 rx_rate_info_2;
  /** bits 31:0: TX bit rate in 100kbps */
  uint32 rxBitRate;

//  A_UINT32 maxTodToaError;
  uint16 maxTodError;
  uint16 maxToaError;
  /*******************************************************************************
   *Bits 15:0:   Max TOD Error
   *Bits 31:16: Max TOA Error
   *******************************************************************************/
} rttPerFrameInfo;

/** This struct fragmentation information for a given FW msg */
typedef struct
{
  uint8  isFragment;  // non-zero if more fragments follow
  uint8  fragmentIdx; // associate with token id
  uint32 fragmentLen; // fragment length that follows: # bytes after this rsp head TLV
  uint8  tokenId;
} rttFragmentInfo;

/** This struct is used to extract the parameters from the wmi_rtt_oem_rsp_head TLV */
typedef struct
{
  uint32 reqId;
  uint8  status;
  uint8  subType;
  bool   isLastMeas;
  rttFragmentInfo fragInfo;
} rttRspInfo;

/**
 *enum WMIRTT_FIELD_ID - identifies which field is being specified
 *@WMIRTT_FIELD_ID_oem_data_sub_type: oem data req sub type
 *@WMIRTT_FIELD_ID_channel_mhz: channel mhz info
 *@WMIRTT_FIELD_ID_pdev: pdev info
 **/
enum WMIRTT_FIELD_ID {
  WMIRTT_FIELD_ID_oem_data_sub_type,
  WMIRTT_FIELD_ID_channel_mhz,
  WMIRTT_FIELD_ID_pdev,
};

/**
 ** struct sAniMetaData - wifi positioning field element
 ** @id: RTT field id
 ** @offset: data offset in field info buffer
 ** @length: length of related data in field info buffer
 **/
struct tAniMetaData {
  uint32_t id;
  uint32_t offset;
  uint32_t length;
};

/* Length of interface name */
#define MAX_INTERFACE_LEN 16
/*
 * struct tAniInterface - Identifies the wifi interface
 * @length: Interface length
 * @name: Interface name
 */
struct tAniInterface {
  uint8 length;
  char name[MAX_INTERFACE_LEN];
};
#endif
