/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef deServiceCtrl__h
#define deServiceCtrl__h

#include "dataElements.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* HT capability flags */
#define IEEE80211_HTCAP_C_CHWIDTH40 0x0002
#define IEEE80211_HTCAP_C_SHORTGI20 0x0020
#define IEEE80211_HTCAP_C_SHORTGI40 0x0040

/* VHT capability flags */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80 0x00000000     /* Does not support 160 or 80+80 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 0x00000004    /* Supports 160 */
#define IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 0x00000008 /* Support both 160 or 80+80 */
#define IEEE80211_VHTCAP_SHORTGI_80 0x00000020            /* B5 Short GI for 80MHz */
#define IEEE80211_VHTCAP_SHORTGI_160 0x00000040           /* B6 Short GI for 160 and 80+80 MHz */
#define IEEE80211_VHTCAP_SU_BFORMER 0x00000800            /* B11 SU Beam former capable */
#define IEEE80211_VHTCAP_MU_BFORMER 0x00080000            /* B19 MU Beam Former */

enum ScanStates
{
    SCAN_DATA_START = 1,
    SCAN_DATA_IN_PROGRESS = 2,
    SCAN_DATA_STOP = 3,
};

// ====================================================================
// Lifecycle functions
// ====================================================================
/* Init functions and deInit functions */
DE_STATUS dataElementHydInit(void);

DE_STATUS dataElementHydFini(void);

/* Functions requesting data from hyd */
DE_STATUS dERequestHydRadioData(int radioIndex);

DE_STATUS dERequestHydNetworkData();

DE_STATUS dERequestHydDeviceData();

DE_STATUS dERequestHydCurOpClassData();

DE_STATUS dEGetRadioCapsData();

DE_STATUS dERequestHydRadioCapableOpClassData();

DE_STATUS dERequestHydScanListData();

DE_STATUS dERequestHydBssData(u_int8_t radioIndex);

DE_STATUS dERequestHydStaData();

DE_STATUS dERequestHydUnAssocStaData();

DE_STATUS dERequestHydBackHaulStaData();

DE_STATUS dERequestNbEventsEnableData();

DE_STATUS dERequestEventsEnable();

/* function parses the payload from hyd */
int meshDEParseFrame(char *frame);

#if defined(__cplusplus)
}
#endif

#endif /* deServiceCtrl__h */
