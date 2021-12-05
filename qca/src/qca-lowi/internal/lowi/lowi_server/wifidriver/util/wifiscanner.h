/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

                       WiFi Scanner API

GENERAL DESCRIPTION
   This file contains the definition of WiFi Scanner API.

Copyright (c) 2010, 2012-2013, 2015-2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
All Rights Reserved.
Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#ifndef __WIFI_SCANNNER_API_H
#define __WIFI_SCANNNER_API_H

/*--------------------------------------------------------------------------
 * Include Files
 * -----------------------------------------------------------------------*/
#include <stdint.h>
#include "innavService.h"

extern WlanFrameStore wlanFrameStore;

#ifdef __cplusplus
extern "C" {
#endif

namespace qc_loc_fw
{

class LOWIRequest;
class LOWIMeasurementResult;

class LOWIWifiScanner
{
public:

/*=============================================================================================
 * Function description:
 *   Function with processes RIVA passive scan request with fresh WIFI passive scan measurement.
 *
 * Parameters:
 *   cached   Cache results are needed or fresh
 *   max_age_sec if a cached result is within this maximum age, just return that.
 *   max_meas_age_sec
 *   timeout  Timeout for the request
 *   pRetVal  Return value from the function
 *   pFreq    Pointer to an Array of frequencies to be scanned
 *   num_of_freq  Number of items in the Array of frequencies
 *   frameArrived Indicates that an 80211 frame has arrived and requires processing
  *   LOWIRequest* Pointer to the LOWIRequest
 *
 * Return value:
 *    Non-NULL : pointer to parsed scan result.
 *    NULL : failure
 =============================================================================================*/
static LOWIMeasurementResult* lowi_proc_req_passive_scan_with_live_meas (const int cached,
                                                                         const uint32 max_age_sec,
                                                                         const uint32 max_meas_age_sec,
                                                                         int timeout,
                                                                         int* pRetVal,
                                                                         int* pFreq,
                                                                         int num_of_freq,
                                                                         int* frameArrived,
                                                                         LOWIRequest* request);
};
} //namespace

#ifdef __cplusplus
}
#endif

/*=============================================================================================
 * Function description:
 * Send Action Frame To Access Point.
 *
 * Parameters:
 *    frameBody: Frame body to be transmitted
 *    frameLen: Length of Frame body to be transmitted
 *    freq: Frequency on which to transmit the frame
 *    sourceMac: the access point receiving the FTM Range report
 *    selfMac:   The Local STA's MAC address
 *
 * Return value:
 *    Error Code: 0 - Success, all other values indicate failure
 =============================================================================================*/
extern int lowi_send_action_frame(uint8* frameBody,
                           uint32 frameLen,
                           uint32 freq,
                           uint8 sourceMac[BSSID_SIZE],
                           uint8 selfMac[BSSID_SIZE]);

#endif /* __WIFI_SCANNNER_API_H */

