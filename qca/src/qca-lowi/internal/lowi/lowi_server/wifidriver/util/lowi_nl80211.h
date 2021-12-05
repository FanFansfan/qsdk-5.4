/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

                LOWI NL80211 Library Header File
GENERAL DESCRIPTION
  This file contains the functions for Parsing and generating IEEE 802.11
  frames.

Copyright (c) 2015-2016, 2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

History:

Date         User      Change
==============================================================================
08/24/2015   subashm   Created
=============================================================================*/

#ifndef LOWI_NL80211_H
#define LOWI_NL80211_H

#include "innavService.h"
#include <base_util/vector.h>

namespace qc_loc_fw
{

/* Global Defines */

#define VENDOR_SPEC_ELEM_LEN 255
#define BSSID_INFO_LEN 4

/* Neighbor Report Element Lengths */
#define NR_TSF_SUB_ELEM_LEN 4
#define NR_ELEM_MIN_LEN 13
#define NR_ELEM_HDR_LEN 2
/* Neighbor Report SubElement lengths */
#define NR_SUB_ELEM_HDR_LEN 2
#define NR_SUB_ELEM_WBC_LEN 3

/* Neighbor Report BSSID info Subfields */
#define NR_BSSID_ACCESS_READ(start, mask, x) ((x & (mask << start)) >> start)
#define NR_BSSID_ACCESS_WRITE(start, mask, x, val) ((x & ~(mask << start)) | (val << start))

#define NR_BSSID_INFO_HT_START 11
#define NR_BSSID_INFO_HT_MASK 0x1
#define NR_BSSID_INFO_HT_LEN 1
#define NR_GET_BSSID_INFO_HT(x) NR_BSSID_ACCESS_READ(NR_BSSID_INFO_HT_START, NR_BSSID_INFO_HT_MASK, x)

#define NR_BSSID_INFO_VHT_START 12
#define NR_BSSID_INFO_VHT_MASK 0x1
#define NR_BSSID_INFO_VHT_LEN 1
#define NR_GET_BSSID_INFO_VHT(x) NR_BSSID_ACCESS_READ(NR_BSSID_INFO_VHT_START, NR_BSSID_INFO_VHT_MASK, x)

#define NR_BSSID_INFO_FTM_START 13
#define NR_BSSID_INFO_FTM_MASK 0x1
#define NR_BSSID_INFO_FTM_LEN 1
#define NR_GET_BSSID_INFO_FTM(x) NR_BSSID_ACCESS_READ(NR_BSSID_INFO_FTM_START, NR_BSSID_INFO_FTM_MASK, x)


/* Measurement request element length */
#define MEAS_REQ_ELEM_HDR_LEN 2

/* Subelement header length */
#define SUBELEM_HEADER_LEN 2

/* Element IDs */

#define RM_MEAS_REQ_ELEM_ID 38     /* Measurement Request ID */
#define RM_MEAS_RPT_ELEM_ID 39     /* Measurement Report ID */
#define RM_NEIGHBOR_RPT_ELEM_ID 52 /* Neighbor Report ID */
#define RM_WIDE_BW_CHANNEL_ELEM_ID 6 /* Wide Bandwidth channel ID*/

/* Neighbor Report Sub Element IDs */
#define NR_TSF_INFO_ELEM_ID                 1
#define NR_CONDENSED_CTRY_STR_ELEM_ID       2
#define NR_BSS_TRANSITION_CAND_PREF_ELEM_ID 3
#define NR_BSS_TERMINATION_DUR_ELEM_ID      4
#define NR_BEARING_ELEM_ID                  5
#define NR_WBC_ELEM_ID                      6
#define NR_MEAS_REPORT_ELEM_ID              39
#define NR_HT_CAP_ELEM_ID                   45
#define NR_HT_OPERATION_ELEM_ID             61
#define NR_SEC_CHAN_OFFSET_ELEM_ID          62
#define NR_MEAS_PILOT_TRANS_ELEM_ID         66
#define NR_RM_ENABLED_CAP_ELEM_ID           70
#define NR_MULTI_BSSID_ELEM_ID              71
#define NR_VHT_CAP_ELEM_ID                  191
#define NR_VHT_OPERATION_ELEM_ID            192
#define NR_VENDOR_SPEC_ELEM_ID              221

/* Defines Neighbor Report WBC element sub fields */
#define NR_WBC_BW_20 0
#define NR_WBC_BW_40 1
#define NR_WBC_BW_80 2
#define NR_WBC_BW_160 3
#define NR_WBC_BW_80_80 4

/* Action Categories */
#define LOWI_WLAN_ACTION_RADIO_MEAS 5 /* Radio Measurement Action Category */

/* Radio Measurement Action Values*/
#define LOWI_RM_ACTION_REQ 0 /* Radio Measurement Request */
#define LOWI_RM_ACTION_RPT 1 /* Radio Measurement Report */
#define LOWI_NR_ACTION_REQ 4 /* Neighbor Report Request */

/* Measurement Request Types*/
#define LOWI_WLAN_LCI_REQ_TYPE       8  /* LCI Request Frame */
#define LOWI_WLAN_LOC_CIVIC_REQ_TYPE 11 /* Location Civic Request Frame */
#define LOWI_WLAN_FTM_RANGE_REQ_TYPE 16 /* Fine Timing Measurement Range Request Frame */

/* Defines for Field values */
#define LOWI_LOC_SUBJECT_LOCAL  0 /* Location Subject - Local (Where am I?)        */
#define LOWI_LOC_SUBJECT_REMOTE 1 /* Location Subject - Remote (Where are you?)    */
#define LOWI_LOC_SUBJECT_THIRD  2 /* Location Subject - Third party (Where is it?) */
#define LOWI_LOC_SUBJECT_UNDEF  3 /* Location Subject - Undefined */

#define LOWI_MAX_SIZE_LCI_FIELD 16 // bytes

/** LCI Report Subelement IDs currently in use */
#define LOWI_LCI_SUBELEM_ID         0
#define LOWI_Z_SUBELEM_ID           4
#define LOWI_USAGE_RULES_SUBELEM_ID 6

/** Usage Rules subelement minimum length */
#define LOWI_USAGE_RULES_SUBELEM_MIN_LEN 1
#define LOWI_USAGE_RULES_SUBELEM_MAX_LEN 3

/** Z subelement min/max length */
#define LOWI_Z_SUBELEM_MIN_LEN 2
#define LOWI_Z_SUBELEM_MAX_LEN 5

/** LCI subelement min/max length */
#define LOWI_LCI_SUBELEM_MIN_LEN 0
#define LOWI_LCI_SUBELEM_MAX_LEN 16

/** Indicates unknown floor number in Z subelement */
#define LOWI_UNKNOWN_FLOOR -8192

/**************************************************/
/* Frame Structures *******************************/
/**************************************************/
/* Neightbor Report Request Element */
typedef PACK(struct) _NeighborRequestElem
{
  uint8 catagory;
  uint8 radioMeasAction;
  uint8 dialogTok;
  // Optional SSID element goes here - defined seperately
  // Optional LCI Meas Req Element - defined seperately
  // Optional Loc Civic Req Element - defined seperately
} NeighborRequestElem;

/* Measurement Request Element */
typedef PACK(struct) _MeasReqElem
{
  uint8 elementId;
  uint8 len;
  uint8 measTok;
  uint8 measReqMode;
  uint8 measType;
  // Measurement Request - defined seperately
} MeasReqElem;

/* Fine Timing Measurement Range Request element */
typedef PACK (struct) _FtmrReqHead
{
  tANI_U16 randomInterval;
  tANI_U8 minApCount;
} FtmrReqHead;

typedef PACK (struct) _NeighborRprtElem
{
  tANI_U8 bssid[BSSID_SIZE];
  tANI_U32 bssidInfo;
  tANI_U8 operatingClass;
  tANI_U8 channelNumber;
  tANI_U8 channelWidth;
  tANI_U8 centerFreq0_Channel;
  tANI_U8 centerFreq1_Channel;
  tANI_U8 phyType;
} NeighborRprtElem;

typedef PACK (struct) _NR_TsfInfoElem
{
  tANI_U16 tsfOffset;
  tANI_U16 beaconInterval;
} NR_TsfInfoElem;

typedef PACK (struct) _NR_CountryStrElem
{
  tANI_U16 countryString;
} NR_CountryStrElem;

typedef PACK (struct) _MaxAgeElem
{
  tANI_U16 maxAge;
} MaxAgeElem;

typedef PACK (struct) _VendorSpecElem
{
  tANI_U8 vendorSpecContent[VENDOR_SPEC_ELEM_LEN];
} VendorSpecElem;

/** FTM Range Request from Measurement Request Frame */
class FineTimingMeasRangeReq
{
public:
  uint8 dialogTok;
  MeasReqElem measReqElem;
  FtmrReqHead ftmrrReqHead;
  vector <NeighborRprtElem> neighborRprtElem;

  FineTimingMeasRangeReq()
  {
    memset(&measReqElem, 0, sizeof(measReqElem));
    memset(&ftmrrReqHead, 0, sizeof(ftmrrReqHead));
    neighborRprtElem.flush();
  }
  ~FineTimingMeasRangeReq()
  {
    neighborRprtElem.flush();
  }
};

// Measurement Request field corresponding to an LCI request
typedef PACK(struct) _LciElemCom
{
  uint8 locSubject;
} LciElemCom;

// STA Floor Info field
typedef PACK(struct)
{
  uint8 expectedToMove; // 0: sta is NOT expected to change its location
                        // 1: sta is expected to change its location
                        // 2: sta movement pattern unknown
                        // 3: reserved
  int16 floorNum;
} LOWISTAFloorInfo;

// Z subelement used to report the floor and location
// of the STA with respect to the floor level
typedef PACK(struct)
{
  LOWISTAFloorInfo staFloorInfo;
  uint32           staHeightAboveFloor;
  uint8            staHeightAboveFloorUncert;
} LOWIZSubelementInfo;

// Usage Rules/Policy subelement parameters
typedef PACK(struct)
{
  uint8 retranmissionAllowed : 1;
  uint8 retentionExpires     : 1;
  uint8 staLocPolicy         : 1;
  uint8 reserved             : 5;
} LOWIUsageRulesParams;

// LCI information
// Definitions per rfc6225
typedef PACK(struct)
{
  uint8 latitudeUnc;      // latitude uncertainty
  uint64 latitude;        // latitude (degrees)
  uint8 longitudeUnc;     // longitude uncertainty
  uint64 longitude;       // longitude (degrees)
  uint8 altitudeType;     // (0)unknown, (1)meters, (2)floors
  uint8 altitudeUnc;      // altitude uncertainty
  uint32 altitude;        // altitude
  uint8 datum        : 3; // determines how coordinates are organized and related to the
                          // real world. (1)WGS84, (2)NAD83 + NAVD88, (3)NAD83 + MLLW
  uint8 regLocAgree  : 1; // (1) STA is operating within a national policy area or an
                          // international agreement area near a national border, else (0)
  uint8 regLocDSE    : 1; // (1)DSE operation enabled (0)DSE operation disabled
  uint8 dependentSTA : 1; // (1)STA is operating with the enablement of the enabling
                          // STA whose LCI is being reported
  uint8 version      : 2; // version specification per rfc6225
  bool  lciInfoIsKnown;   // whether this structure is filled with "valid" information
} LOWILCIInfo;

// LCI Field (part of LCI subelement)
typedef PACK(struct)
{
  uint8 latUnc       : 6; // B0-B5   (6 bits)
  uint8 lat1         : 2; // B6-B39  (34 bits)
  uint8 lat2         : 8;
  uint8 lat3         : 8;
  uint8 lat4         : 8;
  uint8 lat5         : 8;
  uint8 lonUnc       : 6; // B40-B45 (6 bits)
  uint8 lon1         : 2; // B46-B79 (34 bits)
  uint8 lon2         : 8;
  uint8 lon3         : 8;
  uint8 lon4         : 8;
  uint8 lon5         : 8;
  uint8 altType      : 4; // B80-B83 (4 bits)
  uint8 altUnc1      : 4; // B84-B89 (6 bits)
  uint8 altUnc2      : 2;
  uint8 alt1         : 6; // B90-B119 (30 bits)
  uint8 alt2         : 8;
  uint8 alt3         : 8;
  uint8 alt4         : 8;
  uint8 datum        : 3; // B120-122 (3 bits)
  uint8 regLocAgree  : 1; // B123     (1 bit)
  uint8 regLocDSE    : 1; // B124     (1 bit)
  uint8 dependentSTA : 1; // B125     (1 bit)
  uint8 version      : 2; // B126-127 (2 bits)
} LOWILCIField;

/** LCI information needed for LCI Report response */
class LOWILCIRprtInfo
{
public:
  LOWILCIInfo          lciParams;
  LOWIZSubelementInfo  zSubElem;
  LOWIUsageRulesParams usageRules;

  /** Constructor */
  LOWILCIRprtInfo()
  {
    memset(&lciParams, 0, sizeof(lciParams));
    memset(&zSubElem, 0, sizeof(zSubElem));
    memset(&usageRules, 0, sizeof(usageRules));
  };
  /** Destructor */
  ~LOWILCIRprtInfo()
  {
  };
};

/** Information related to successful range measurement with a single AP  */
typedef PACK(struct) _FtmrrRangeEntry
{
  /** Contains the least significant 4 octets of the TSF (synchronized with the
   *  associated AP) at the time (± 32 us) at which the initial Fine Timing
   *  Measurement frame was transmitted where the timestamps of both the frame
   *  and response frame were successfully measured.
   */
  uint32 measStartTime;
  /** BSSID of AP whose range is being reported */
  uint8 bssid[BSSID_SIZE];
  /** Estimated range between the requested STA and the AP using the fine timing
   *  measurement procedure, in units of 1/4096 m. A value of (2^24)-1 indicates
   *  a range of ((2^24)–1)/4096 m or higher.
   */
  uint32 range : 24;
  /**
   *  The Max Range Error Exponent field contains an upper bound for the
   *  error in the value specified in the Range field. A value of zero
   *  indicates an unknown error. A nonzero value indicates a maximum range
   *  error of 2^(max range error exponent - 13) m. The Max Range Error
   *  Exponent field has a maximum value of 25. Values in the range 26–255
   *  are reserved. A value of 25 indicates a maximum range error of 4096 m
   *  or higher. For example, a value of 14 in the Max Range Error Exponent
   *  field indicates that the value in the Range field has a maximum error
   *  of ±2 m.
   */
  uint32 maxErrRange : 8;
  /** Reserved field   */
  uint8  reserved;
} FtmrrRangeEntry;

/** Information related to failure range measurement with a single AP */
typedef PACK(struct) _FtmrrErrEntry
{
  /** Contains the least significant 4 octets of the TSF (synchronized with the
   *  associated AP) at the time (± 32 us) at which the Fine Timing Measurement
   *  failure was first detected.
   */
  uint32 measStartTime;
  /** BSSID of AP whose range is being reported */
  uint8 bssid[BSSID_SIZE];
  /** Error report code */
  uint8 errCode;
} FtmrrErrEntry;

typedef PACK(struct) _LocCivElemCom
{
  uint8 locSubject;
  uint8 civicType;
  uint8 locServiceIntUnits;
  uint16 locServiceInterval;
} LocCivElemCom;
} // namespace qc_loc_fw

#endif // LOWI_NL80211_H
