/*
 * Copyright (c) 2014,2017-2018 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2014 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#ifndef _SPECTRAL_DATA_H_
#define _SPECTRAL_DATA_H_

#include "spec_msg_proto.h"

#ifndef MAX_SPECTRAL_MSG_ELEMS
#define MAX_SPECTRAL_MSG_ELEMS 10
#endif

#define SPECTRAL_SIGNATURE  0xdeadbeef

#ifndef NETLINK_ATHEROS
#define NETLINK_ATHEROS              (NETLINK_GENERIC + 1)
#endif


#ifdef WIN32
#pragma pack(push, spectral_data, 1)
#define __ATTRIB_PACK
#else
#ifndef __ATTRIB_PACK
#define __ATTRIB_PACK __attribute__ ((packed))
#endif
#endif

typedef struct spectral_data {
    int16_t     spectral_data_len;
    int16_t     spectral_rssi;
    int16_t     spectral_bwinfo;    
    int32_t     spectral_tstamp;    
    int16_t     spectral_max_index; 
    int16_t     spectral_max_mag;   
} __ATTRIB_PACK SPECTRAL_DATA;

struct spectral_scan_data {
    u_int16_t chanMag[128];
    u_int8_t  chanExp;
    int16_t   primRssi;
    int16_t   extRssi;
    u_int16_t dataLen;
    u_int32_t timeStamp;
    int16_t   filtRssi;
    u_int32_t numRssiAboveThres;
    int16_t   noiseFloor;
    u_int32_t center_freq;
};

typedef struct spectral_msg {
    int16_t      num_elems;
    SPECTRAL_DATA data_elems[MAX_SPECTRAL_MSG_ELEMS];
} SPECTRAL_MSG;

/* This should match the defination in drivers/wlan_modules/include/ath_dev.h */
#define ATH_CAP_DCS_CWIM     0x1
#define ATH_CAP_DCS_WLANIM   0x2

#ifdef WIN32
#pragma pack(pop, spectral_data)
#endif
#ifdef __ATTRIB_PACK
#undef __ATTRIB_PACK
#endif

#endif
