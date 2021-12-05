/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Wrapper

GENERAL DESCRIPTION
  This file contains the Wrapper around LOWI Client

Copyright (c) 2015-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_WRAPPER_H__
#define __LOWI_WRAPPER_H__

#include "lowi_request.h"
#include "lowi_scan_measurement.h"
#include "lowi_response.h"
#include "lowi_test_internal.h"


#ifdef __cplusplus
extern "C" {
#endif

using namespace qc_loc_fw;

typedef int (*ptr2CallbackFunc)(LOWIResponse *rsp);

/*=============================================================================================
 * Function description:
 *   This function initializes LOWI client.
 *   Please note that this function shall be called only once before destroy is called
 *
 * Parameters:
 *    ptr2CallbackFunc: Pointer to function to be called for LOWI Responses
 *
 * Return value:
 *    error code: 0: success
 *                non-zero: error
 =============================================================================================*/
int lowi_wrapper_init (ptr2CallbackFunc rsp_callback);

/*=============================================================================================
 * Function description:
 *   This function destroys LOWI client.
 *   Please note that this function shall be called once when the procC daemon starts
 *
 * Parameters:
 *    none
 *
 * Return value:
 *    error code: 0: success
 *                non-zero: error
 =============================================================================================*/
extern int lowi_wrapper_destroy ();

/*=============================================================================================
 * lowi_queue_rtt_req
 *
 * Description:
 *   This function requests for Ranging scan for the given APs
 *
 * Parameters:
 *   rttRequest - Scan parameters: AP MAC ID and channel number.
 *
 * WARNING: LOWIWrapper WILL free the memory pointed by rttRequest
 *   regardless whether the function
 *   succeeds or not. That means the caller should only allocate prior to calling this function
 *   but never FREE it.
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_rtt_req( LOWIPeriodicRangingScanRequest * rttRequest );

/*=============================================================================================
 * lowi_queue_discovery_scan_req_band
 *
 * Description:
 *   This function requests for discovery scan on a specified band.
 *
 * Parameters:
 *  Band: A band at which the passive scan is requested.
 *  timeout: A request time out after which the request is dropped.
 *  scan_type: Active or Passive
 *  meas_filter_type: Filter the measurements based on the age filter
 *  fullBeaconResponse: Full beacon response - true / otherwise - false
 *  vector <LOWIMacAddress>&: Bssids for unicast scan
 *  vector <LOWISsid>&: SSIDs for directed probe request
 *  uint32: Fallback tolerance in seconds
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
int lowi_queue_discovery_scan_req_band (LOWIDiscoveryScanRequest::eBand band,
    int64 request_timeout, LOWIDiscoveryScanRequest::eScanType scan_type,
    uint32 meas_filter_age, bool fullBeaconResponse,
    vector <LOWIMacAddress>& bssids, vector <LOWISsid>& ssids, uint32 fb_tol);

/*=============================================================================================
 * lowi_queue_discovery_scan_req_ch
 *
 * Description:
 *   This function requests for discovery scan on a specific channels.
 *
 * Parameters:
 *  vec: vector of channels to be scanned
 *  request_timeout: A request time out after which the request is dropped.
 *  scan_type: Active or Passive
 *  meas_filter_type: Filter the measurements based on the age filter
 *  fullBeaconResponse: Full beacon response - true / otherwise - false
 *  vector <LOWIMacAddress>&: Bssids for unicast scan
 *  vector <LOWISsid>&: SSIDs for directed probe request
 *  uint32: Fallback tolerance in seconds
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
int lowi_queue_discovery_scan_req_ch (vector <LOWIChannelInfo>& vec,
    int64 request_timeout, LOWIDiscoveryScanRequest::eScanType scan_type,
    uint32 meas_filter_age, bool fullBeaconResponse,
    vector <LOWIMacAddress>& bssids, vector <LOWISsid>& ssids, uint32 fb_tol);

/*=============================================================================================
 * lowi_queue_capabilities_req
 *
 * Description:
 *   This function requests for driver capabilities from lowi
 *
 * Parameters: None
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_capabilities_req(std::string interface);

/*=============================================================================================
 * lowi_queue_async_discovery_scan_result_req
 *
 * Description:
 *   This function requests for async discovery scan results
 *
 * Parameters: uint32 : Timeout in seconds after which the request can be dropped
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_async_discovery_scan_result_req( uint32 timeout );

extern int lowi_queue_get_batching_results (boolean flush, uint32 max_results);
extern int lowi_queue_batching_subscription_req (boolean subscribe, uint32 threshold);
extern int lowi_queue_capabilities_subs_req ();
extern int lowi_queue_anqp_request(const LOWIMacAddress& mac_addr);

extern int lowi_queue_nr_request();

/**
 * Function to send LOWIWlanStatusQueryRequest to LOWI
 * @ return 0 for SUCCESS, -1 otherwise
 */
extern int lowi_queue_wsq_request ();

/*=============================================================================================
 * lowi_queue_set_lci
 *
 * Description:
 *   This function sets LCI information
 *
 * Parameters: lciInfo : LCI information
 *             interface: Interface name
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_set_lci(qc_loc_fw::LOWILciInformation *lciInfo, std::string interface);

/*=============================================================================================
 * lowi_queue_set_lcr
 *
 * Description:
 *   This function sets LCR information
 *
 * Parameters: lciInfo : LCR information
 *             interface: Interface name
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_set_lcr(qc_loc_fw::LOWILcrInformation *lcrInfo, std::string interface);

/*=============================================================================================
 * lowi_queue_where_are_you
 *
 * Description:
 *   This function requests Where are you for the given AP
 *
 * Parameters:
 *   bssid - Target STA MAC
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_where_are_you(qc_loc_fw::LOWIMacAddress bssid);

/*=============================================================================================
 * lowi_queue_ftmrr
 *
 * Description:
 *   This function requests FTM mesurements to given AP
 *
 * Parameters:
 *   bssid - Target STA MAC
 *   randInterval - rand interval
 *   nodes - FTMRR nodes
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_ftmrr(qc_loc_fw::LOWIMacAddress bssid,
                            uint16 randInterval, qc_loc_fw::vector<qc_loc_fw::LOWIFTMRRNodeInfo>& nodes);

/*=============================================================================================
 * lowi_queue_log_config
 *
 * Description:
 *   This function requests the log config for different modules.
 *
 * Parameters:
 *   LOWIConfigRequest* - Pointer to lowiconfigrequest.
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_config_req(LOWIConfigRequest* request);
/*=============================================================================================
 * lowi_queue_start_responder_meas_req
 *
 * Description:
 *   This function requests the responder measurement configuration.
 *
 * Parameters:
 *   uint32  - report type
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_start_responder_meas_req(uint8 reportType);
/*=============================================================================================
 * lowi_queue_start_responder_meas_req
 *
 * Description:
 *   This function requests the responder measurement configuration.
 *
 * Return value:
 *   0 - success
 *   non-zero: error
 =============================================================================================*/
extern int lowi_queue_stop_responder_meas_req();
#ifdef __cplusplus
}
#endif

#endif /* __LOWI_WRAPPER_H__ */
