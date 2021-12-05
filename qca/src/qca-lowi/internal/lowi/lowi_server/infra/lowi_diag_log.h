/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

                  QUIPC Diag logging Interface Header File

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  the logging the structures through DIAG.

Copyright (c) 2013, 2016-2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

#ifndef _LOWI_DIAG_LOG_H_
#define _LOWI_DIAG_LOG_H_

#include <inc/lowi_request.h>
#include <inc/lowi_response.h>
#include "lowi_request_extn.h"
#include "lowi_response_extn.h"
#include "lowi_scan_measurement_extn.h"
#include <lowi_measurement_result.h>

#ifdef __cplusplus
extern "C"
{
#endif

//#include "poslog.h"

namespace qc_loc_fw
{
/**
 * NOTE:
 * This enum represents the LOWI struct types that can be logged.
 *
 * DO NOT ALTER THE ORDER OF THE FIELDS. ENUM SEQUENCE MUST BE
 * MAINTAINED IN ORDER TO ENSURE CORRECT LOGGING. WHEN ADDING NEW
 * FIELDS, ADD THEM AT THE END JUST BEFORE LOWI_STRUCT_LAST.
 */
typedef enum
{
  /* User & LOWI Controller */
  LOWI_DISCOVERY_SCAN_REQUEST,
  LOWI_RANGING_SCAN_REQUEST,
  LOWI_DISCOVERY_SCAN_RESPONSE,
  LOWI_RANGING_SCAN_RESPONSE,
  /* LOWI Controller & LOWI WiFi Driver */
  LOWI_WLAN_DISCOVERY_SCAN_MEAS,
  LOWI_WLAN_RANGING_SCAN_MEAS,
  LOWI_WLAN_DISCOVERY_SCAN_REQ,
  LOWI_WLAN_RANGING_SCAN_REQ,
  /* LOWI WiFi Driver & Rome Driver*/
  LOWI_ROME_RANGING_REQ,
  LOWI_ROME_RANGING_RESP,
  /* requests handled by scheduler */
  LOWI_PERIODIC_RANGING_SCAN_REQUEST,
  LOWI_CANCEL_RANGING_SCAN_REQUEST,
  /* batching response from LP */
  LOWI_BGSCAN_BATCHING_MEAS_FROM_LP,
  /* User & LOWI Controller */
  LOWI_BGSCAN_CACHED_RESULTS_REQ,
  LOWI_BGSCAN_CACHED_RESULTS_RESP,
  /* must always be the last field in this enum */
  LOWI_STRUCT_LAST
}e_lowi_diag_struct_type;

/**
 * Logs to the diag interface
 */
class LOWIDiagLog
{
public:
  /**
   * Initializes the Diag module to start the
   * logging.
   * Note: This function must be called as of now
   * because of a bug in Diag implementation that needs
   * some time between the init and actual logging to start.
   */
  static bool Init ()
  {
    return false;
  }

  /**
   * Clean up the Diag module.
   */
  static void Cleanup ()
  {
  }

  /**
   * Logs the LOWIRequest to diag interface
   * @param LOWIRequest Request to be logged
   * @return bool true for success, false otherwise
   */
  static bool Log (LOWIRequest* request)
  {
    return false;
  }

  /**
   * Logs the LOWIResponse to diag interface
   * @param LOWIResponse Response to be logged
   * @param Char* Originator
   * @return bool true for success, false otherwise
   */
  static bool Log (LOWIResponse* response, const char* const originator)
  {
    return false;
  }

 /**
   * Logs the LOWIMeasurementResult for discovery scan to diag interface
   * @param LOWIMeasurementResult measurements from driver to be
   *         logged
   * @return bool true for success, false otherwise
   */
  static bool Log (const LOWIMeasurementResult* lowiMeasResult)
  {
    return false;
  }


  /**
   * Logs the LOWIMeasurementResult to diag interface
   * @param rtsCtsTag RTS CTS Request tag
   * @param LOWIMeasurementResult measurements from driver to be
   *                              logged
   * @return bool true for success, false otherwise
   */
  static bool Log (const uint32 rtsCtsTag, const LOWIMeasurementResult* lowiMeasResult)
  {
    return false;
  }

  /**
   * Logs the discovery scan request sent to wifi driver
   * @param cached If the request is for cached results or not
   * @param max_scan_age_sec Maximum age limit if the scan results are cached
   * @param max_meas_age_sec Maximum age limit if the scan results are fresh
   * @param timeout Timeout for the request
   * @param pFreq Array of frequencies that needs to be scanned
   * @param num_of_freq Number of frequencies to be scanned
   * @return bool true for success, false otherwise
   */
  static bool Log (const int cached,
                    const uint32 max_scan_age_sec,
                    const uint32 max_meas_age_sec,
                    int timeout,
                    int* pFreq,
                    int num_of_freq)
  {
    return false;
  }

  /**
   * Logs the ranging scan request sent to wifi driver
   * @param rtsCtsTag RTS CTS Request tag
   * @param numBSSID Number of BSSIDs in the request
   * @param BSSIDs Array of BSSIDs. Number of items indicated by numBSSID
   * @param spoofMac Array of spoof MacIds.
   *                 Number of items indicated by numBSSID
   * @param channels Array of channels that needs to be scanned.
   *                 Number of items indicated by numBSSID
   * @param num_of_meas Number of meas needed per AP
   * @param timeout Request timeout
   * @return bool true for success, false otherwise
   */
  static bool Log (uint32 rtsCtsTag,
                    const int numBSSIDS,
                    const char BSSIDs[][6],
                    char spoofMac[][6],
                    const int *channels,
                    int num_of_meas,
                    int timeout)
  {
    return false;
  }

  /**
   * Logs the ranging scan request sent to Rome wifi driver
   * @param rtsCtsTag RTS CTS Request tag
   * @param v The vector containing the LOWI nodes sent for
   *          ranging.
   * @param num_of_meas Number of meas needed per AP
   * @param timeout Request timeout
   * @return bool true for success, false otherwise
   */
  static bool Log (uint32 rtsCtsTag,
                   vector <LOWINodeInfo> &v,
                   int num_of_meas,
                   int timeout)
  {
    return false;
  }

  /**
   * Logs the ranging scan Request/Response to/from Rome wifi
   * driver
   * @param dataLength: Length of NL Message
   * @param nlMessage:  NL Message
   * @param type:       Diag Log type Request or Response
   * @return bool true for success, false otherwise
   */
  static bool Log (uint16 dataLength,
                   uint8* nlMessage,
                   e_lowi_diag_struct_type type)
  {
    return false;
  }

  /**
   * Checks if the logging in enabled
   * @return bool true if logging enabled false otherwise
   */
  static bool isLoggingEnabled ()
  {
    return false;
  }

  /**
   * Logs the BGscan batching results to diag interface
   * @param LOWIMeasurementResult measurements from LP to be logged
   * @return bool true for success, false otherwise
   */
  static bool LogLPBatchingResults (const LOWIMeasurementResult *lowiMeasResult)
  {
    return false;
  }
};
} // namespace
#ifdef __cplusplus
}
#endif

#endif /* LOWI_DIAG_LOG_H */
