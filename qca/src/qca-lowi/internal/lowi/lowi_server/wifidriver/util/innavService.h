/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

                Innav Service Header File
GENERAL DESCRIPTION
  This file contains the functions for testing IWSS

Copyright (c) 2010-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
All Rights Reserved.
Qualcomm Atheros Confidential and Proprietary.

History:

Date         User      Change
==============================================================================
11/20/2010   ns        Created
=============================================================================*/

#ifndef INNAV_SERVICE_H
#define INNAV_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "lowi_defines.h"

#define MAX_BSSIDS_ALLOWED_FOR_MEASUREMENTS 16
#define BSSID_SIZE 6

/* Common type definitions */
typedef uint8_t      tANI_U8;
typedef int8_t       tANI_S8;
typedef uint16_t     tANI_U16;
typedef int16_t      tANI_S16;
typedef uint32_t     tANI_U32;
typedef int32_t      tANI_S32;
typedef uint64_t     tANI_U64;
typedef int64_t      tANI_S64;
typedef tANI_U8   tSirMacAddr[6];

/*********************************************************
 IOCTL INTERFACE DEFINITIONS
 *********************************************************/
//Number to be added to reported RSSI for converting RSSI to dBm
#define LOWI_RSSI_ADJ_FACTOR -100
#define LOWI_RSSI_05DBM_UNITS(rssi) ((((int16) rssi) + LOWI_RSSI_ADJ_FACTOR) * 2)
/*
 * RSSI CHAIN INFO field, We focus only on primary channel
 *
 * rssi_pri_chain0                 :  8, //[7:0]
 * rssi_sec20_chain0               :  8, //[15:8]
 * rssi_sec40_chain0               :  8, //[23:16]
 * rssi_sec80_chain0               :  8; //[31:24]
 */
#define LOWI_PRI_CHAN_RSSI_MSB_BIT_POS 7

static inline int16_t lowi_get_primary_channel_rssi (uint32_t rssi_info)
{
  int8_t rssi = rssi_info & 0x000000FF;
  /* Convert RSSI to 0.5 dBm units */
  return LOWI_RSSI_05DBM_UNITS(rssi);
}

#define WLAN_PRIV_SET_INNAV_MEASUREMENTS 0x8BF1
#define WLAN_PRIV_GET_INNAV_MEASUREMENTS 0x8BF3

/* The Maximum number of valid channels supported by Wi-Fi driver */
#define WNI_CFG_VALID_CHANNEL_LIST_LEN   256

#define LOWI_MAX_WLAN_FRAME_SIZE 2048
#define LOWI_WLAN_MAX_FRAMES 10

/* Frame header */

typedef PACK (struct) _Wlan80211FrameHeader
{
  tANI_U16 frameControl;
  tANI_U16 durationId;
  tANI_U8  addr1[BSSID_SIZE];
  tANI_U8  addr2[BSSID_SIZE];
  tANI_U8  addr3[BSSID_SIZE];
  tANI_U16 seqCtrl;
} Wlan80211FrameHeader;

typedef PACK(struct)
{
  tANI_U8 sourceMac[BSSID_SIZE + 2];
  tANI_U32 frameLen;
  tANI_U32 freq;
  tANI_U8 frameBody[LOWI_MAX_WLAN_FRAME_SIZE];
} WlanFrame;

typedef PACK (struct)
{
  tANI_U8 numFrames;
  WlanFrame wlanFrames[LOWI_WLAN_MAX_FRAMES];
} WlanFrameStore;

/*-------------------------------------------------------------------------
  WLAN_HAL_START_INNAV_MEAS_REQ
--------------------------------------------------------------------------*/
typedef enum
{
  eRTS_CTS_BASED = 1,
  eFRAME_BASED,
} tInNavMeasurementMode;

typedef PACK (struct)
{
  tSirMacAddr   bssid;
  tANI_U16      channel;
} tBSSIDChannelInfo;

typedef PACK (struct)
{
  /* Number of BSSIDs */
  tANI_U8                  numBSSIDs;
  /* Number of Measurements required */
  tANI_U8                  numInNavMeasurements;
  /*.Type of measurements (RTS-CTS or FRAME-BASED) */
  tANI_U16                 measurementMode;
  tANI_U16                 rtsctsTag; //reserved; /* rts/cts measurement tag */

  /* bssid channel info for doing the measurements */
  tBSSIDChannelInfo        bssidChannelInfo[MAX_BSSIDS_ALLOWED_FOR_MEASUREMENTS];

} tInNavMeasReqParams;

/*-------------------------------------------------------------------------
  WLAN_HAL_START_INNAV_MEAS_RSP
--------------------------------------------------------------------------*/
typedef PACK (struct) // 16 bytes
{
  tANI_U32     rssi;
  tANI_U16     rtt;
  tANI_U16     snr;
  tANI_U32     measurementTime;
  tANI_U32     measurementTimeHi;
} tRttRssiTimeData;

typedef PACK (struct) // 24 bytes
{
  tSirMacAddr         bssid;
  tANI_U8             numSuccessfulMeasurements;
  tANI_U8             channel;
  tRttRssiTimeData    rttRssiTimeData[1];
} tRttRssiResults;

typedef PACK (struct) // 36 bytes
{
  tANI_U16         numBSSIDs;
  tANI_U16         rspLen;
  tANI_U32         status;
  tANI_U32         rtsctsTag;
  tRttRssiResults  rttRssiResults[1];
} tInNavMeasRspParams, *tpInNavRspParams;

#ifdef __cplusplus
}
#endif
#endif
