/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Wrapper

GENERAL DESCRIPTION
  This file contains the Wrapper around LOWI Client

Copyright (c) 2015-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "lowi_wrapper.h"
#include <inc/lowi_client.h>
#include "lowi_request_extn.h"

using namespace qc_loc_fw;



LOWIClient* client           = NULL;
LOWIClientListener* listener = NULL;
uint32 req_id;
boolean lowi_wrapper_initialized = FALSE;

ptr2CallbackFunc    ptr2LowiRspCallback = NULL;

/**
 * LOWIClientListener class implementation
 */
class LOWIClientListenerImpl : public LOWIClientListener
{
private:
  static const char * const TAG;
public:

  void printResponse (vector <LOWIScanMeasurement*> & scanMeasurements)
  {
    for (unsigned int ii = 0; ii < scanMeasurements.getNumOfElements(); ++ii)
    {
      LOWIScanMeasurement* scan = scanMeasurements[ii];
      vector<LOWIMeasurementInfo*> measurements = scan->measurementsInfo;
      log_debug (TAG, LOWI_MACADDR_FMT" Frequency = %d",
                 LOWI_MACADDR(scan->bssid), scan->frequency);
      log_debug (TAG, "Is Secure = %d, Node type = %d, # Meas = %d, associated = %d,"
          "max Tx rate = %d, target TSF %llu, Encryption = %d, phyMode =%d",
          scan->isSecure, scan->type,
          measurements.getNumOfElements(), scan->associatedToAp,
          scan->maxTxRate, scan->targetTSF, scan->encryptionType,
          scan->phyMode);

      for (unsigned int jj = 0; jj < measurements.getNumOfElements(); ++jj)
      {
        LOWIMeasurementInfo * meas = measurements[jj];
        log_debug (TAG, "#%d, RSSI = %d, RTT = %d, TIMESTAMP = %llu",
                   jj, meas->rssi, meas->rtt, meas->rssi_timestamp);
      }
    }
  }

  void responseReceived (LOWIResponse* response)
  {
    if (NULL == response)
    {
      log_debug(TAG, "response received was NULL");
      return;
    }

    log_debug(TAG, "responseReceived Request Id = %d",
              response->getRequestId());
    if (ptr2LowiRspCallback != NULL)
    {
      ptr2LowiRspCallback(response);
    }
  }

  virtual ~LOWIClientListenerImpl ()
  {
    log_verbose (TAG, "~LOWIClientListenerImpl");
  }
}; // class LOWIClientListenerImpl

const char * const LOWIClientListenerImpl::TAG = "LOWIWrapper";
////////////////////////////
// Exposed functions
////////////////////////////

int lowi_queue_rtt_req(
    LOWIPeriodicRangingScanRequest * rttRequest)
{
  int ret_val = -1;

  do
  {
    // This is illegal operation if lowi wrapper has not been initialized
    if (!lowi_wrapper_initialized)
    {
      log_error ("LOWIWrapper", "%s: LOWIWrapper uninitialized", __FUNCTION__);
      break;
    }

    if (NULL == rttRequest)
    {
      log_error ("LOWIWrapper", "%s, Input parameter NULL", __FUNCTION__);
      break;
    }

    if (LOWIClient::STATUS_OK != client->sendRequest(rttRequest))
    {
      ret_val = -2;
      break;
    }
    ret_val = 0;
  }
  while (0);
  delete rttRequest;
  return ret_val;
}

int lowi_queue_discovery_scan_req_band (LOWIDiscoveryScanRequest::eBand band,
    int64 request_timeout, LOWIDiscoveryScanRequest::eScanType scan_type,
    uint32 meas_filter_age, bool fullBeaconResponse,
    vector <LOWIMacAddress>& bssids, vector <LOWISsid>& ssids, uint32 fb_tol)
{
  int retVal = 0;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error ("LOWIWrapper", "illegal discovery_scan_req_band"
        " - uninitialized");
    retVal = -1;
    return retVal;
  }

  LOWIDiscoveryScanRequest* dis = NULL;
  if (0 == fb_tol)
  {
    dis = LOWIDiscoveryScanRequest::createFreshScanRequest(++req_id,
            band, scan_type, meas_filter_age, request_timeout,
            LOWIDiscoveryScanRequest::FORCED_FRESH, fullBeaconResponse);
  }
  else
  {
    dis = LOWIDiscoveryScanRequest::createCacheFallbackRequest(++req_id, band, scan_type,
            meas_filter_age, fb_tol, request_timeout, false, false);
  }
  if (NULL == dis)
  {
    retVal = -2;
  }
  else
  {
    if (0 != bssids.getNumOfElements())
    {
      dis->setScanMacAddress (bssids);
    }
    if (0 != ssids.getNumOfElements())
    {
      dis->setScanSsids(ssids);
    }
    if (LOWIClient::STATUS_OK != client->sendRequest(dis))
    {
      retVal = -1;
    }
  }
  delete dis;
  return retVal;
}

int lowi_queue_discovery_scan_req_ch (vector <LOWIChannelInfo>& vec,
                                      int64 request_timeout,
                                      LOWIDiscoveryScanRequest::eScanType scan_type,
                                      uint32 meas_filter_age,
                                      bool fullBeaconResponse,
                                      vector <LOWIMacAddress>& bssids,
                                      vector <LOWISsid>& ssids,
                                      uint32 fb_tol)
{
  int retVal = 0;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error ("LOWIWrapper", "%s: uninitialized", __FUNCTION__);
    retVal = -1;
    return retVal;
  }

  if (0 == vec.getNumOfElements())
  {
    log_error ("LOWIWrapper", "%s: Empty channel list", __FUNCTION__);
    return -3;
  }

  LOWIDiscoveryScanRequest* p_disc_req = NULL;
  if (0 == fb_tol)
  {
    p_disc_req = LOWIDiscoveryScanRequest::createFreshScanRequest(++req_id,
                   vec, scan_type, meas_filter_age, request_timeout,
                   LOWIDiscoveryScanRequest::FORCED_FRESH, fullBeaconResponse);
  }
  else
  {
    p_disc_req = LOWIDiscoveryScanRequest::createCacheFallbackRequest(++req_id, vec,
      scan_type, meas_filter_age, fb_tol, request_timeout, false, false);
  }
  if (NULL == p_disc_req)
  {
    retVal = -2;
  }
  else
  {
    if (0 != bssids.getNumOfElements())
    {
      p_disc_req->setScanMacAddress (bssids);
    }
    if (0 != ssids.getNumOfElements())
    {
      p_disc_req->setScanSsids(ssids);
    }

    if (LOWIClient::STATUS_OK != client->sendRequest(p_disc_req))
    {
      retVal = -1;
    }
  }
  delete p_disc_req;
  return retVal;

}


int lowi_queue_capabilities_req (std::string interface)
{
  int retVal = 0;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error ("LOWIWrapper", "illegal capabilities_req"
        " - uninitialized");
    retVal = -1;
    return retVal;
  }

  LOWICapabilityRequest* cap = new LOWICapabilityRequest(++req_id);

  if (NULL == cap)
  {
    retVal = -2;
  }
  else
  {
    cap->Interface = interface;
    if (LOWIClient::STATUS_OK != client->sendRequest(cap))
    {
      retVal = -1;
    }
  }
  delete cap;
  return retVal;
}

int lowi_queue_async_discovery_scan_result_req (uint32 timeout)
{
  int retVal = 0;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error ("LOWIWrapper", "illegal async_discovery_scan_result_req"
        " - uninitialized");
    retVal = -1;
    return retVal;
  }

  LOWIAsyncDiscoveryScanResultRequest* async =
      new LOWIAsyncDiscoveryScanResultRequest (++req_id, timeout);

  if (LOWIClient::STATUS_OK != client->sendRequest(async))
  {
    retVal = -1;
  }

  delete async;
  return retVal;
}

int lowi_queue_wsq_request()
{
  int retVal = -1;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error ("LOWIWrapper", "illegal lowi_queue_wsq_request"
               " - uninitialized");
    return retVal;
  }

  LOWIWLANStateQueryRequest* req = new LOWIWLANStateQueryRequest(++req_id);

  if (LOWIClient::STATUS_OK != client->sendRequest(req))
  {
    log_debug ("LOWIWrapper", "Failed to send LOWIWLANStateQueryRequest to LOWI");
  }
  else
  {
    retVal = 0;
  }

  delete req;

  return retVal;
}

int lowi_queue_set_lci(LOWILciInformation *lciInfo, std::string interface)
{
  int retVal = -1;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "illegal lowi_queue_set_lci"
              " - uninitialized");
    return retVal;
  }

  if (NULL == lciInfo)
  {
    log_error("LOWIWrapper", "lowi_queue_set_lci: null input");
    return retVal;
  }

  uint32 usageRules = 0x01; //set to 1 by default.

  LOWISetLCILocationInformation *lciReq = new LOWISetLCILocationInformation(++req_id, *lciInfo, usageRules);
  if (NULL == lciReq)
  {
    log_error("LOWIWrapper", "lowi_queue_set_lci"
              " - out of memory");
    return retVal;
  }
  lciReq->set_interface(interface);

  if (LOWIClient::STATUS_OK != client->sendRequest(lciReq))
  {
    log_debug("LOWIWrapper", "Failed to set LCI information");
  }
  else
  {
    retVal = 0;
  }

  delete lciReq;

  return retVal;
}

int lowi_queue_set_lcr(LOWILcrInformation *lcrInfo, std::string interface)
{
  int retVal = -1;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "illegal lowi_queue_set_lcr"
              " - uninitialized");
    return retVal;
  }

  if (NULL == lcrInfo)
  {
    log_error("LOWIWrapper", "lowi_queue_set_lcr: null input");
    return retVal;
  }

  LOWISetLCRLocationInformation *lcrReq = new LOWISetLCRLocationInformation(++req_id, *lcrInfo);
  if (NULL == lcrReq)
  {
    log_error("LOWIWrapper", "lowi_queue_set_lcr"
              " - out of memory");
    return retVal;
  }
  lcrReq->set_interface(interface);


  if (LOWIClient::STATUS_OK != client->sendRequest(lcrReq))
  {
    log_debug("LOWIWrapper", "Failed to set LCR information");
  }
  else
  {
    retVal = 0;
  }

  delete lcrReq;

  return retVal;
}

int lowi_queue_where_are_you(LOWIMacAddress bssid)
{
  int retVal = 0;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "illegal where are you request"
              " - uninitialized");
    retVal = -1;
    return retVal;
  }

  LOWISendLCIRequest *wru = new LOWISendLCIRequest(++req_id, bssid);
  if (NULL == wru)
  {
    retVal = -2;
  }
  else
  {
    if (LOWIClient::STATUS_OK != client->sendRequest(wru))
    {
      retVal = -1;
    }
  }
  delete wru;
  return retVal;
}

int lowi_queue_ftmrr(qc_loc_fw::LOWIMacAddress bssid,
                     uint16 randInterval, vector<qc_loc_fw::LOWIFTMRRNodeInfo>& nodes)
{
  int retVal = 0;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "illegal FTMRR"
              " - uninitialized");
    retVal = -1;
    return retVal;
  }

  LOWIFTMRangingRequest *ftmrr = new LOWIFTMRangingRequest(++req_id, bssid,
                                                         randInterval, nodes);
  if (NULL == ftmrr)
  {
    retVal = -2;
  }
  else
  {
    if (LOWIClient::STATUS_OK != client->sendRequest(ftmrr))
    {
      retVal = -1;
    }
  }
  delete ftmrr;
  return retVal;
}

int lowi_queue_config_req(LOWIConfigRequest* request)
{
  int retVal = 0;
  if (request == NULL)
  {
    retVal = -1;
    return retVal;
  }
  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "illegal Config request"
              " - uninitialized");
    retVal = -1;
    return retVal;
  }

  if (LOWIClient::STATUS_OK != client->sendRequest(request))
  {
    retVal = -1;
  }
  return retVal;
}
int lowi_queue_start_responder_meas_req(uint8 report_type)
{
  int retVal = 0;
#if 0
  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "illegal Config request"
              " - uninitialized");
    retVal = -1;
    return retVal;
  }

  LOWIStartResponderMeasRequest *request = new LOWIStartResponderMeasRequest(++req_id, report_type);
  if (NULL == request)
  {
    log_error("LOWIWrapper", "lowi_queue_start_responder_meas_req"
              " - out of memory");
    return retVal;
  }

  if (LOWIClient::STATUS_OK != client->sendRequest(request))
  {
    retVal = -1;
  }
#endif
  return retVal;
}
int lowi_queue_stop_responder_meas_req()
{
  int retVal = 0;
#if 0
  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "illegal Config request"
              " - uninitialized");
    retVal = -1;
    return retVal;
  }

  LOWIStopResponderMeasRequest *request = new LOWIStopResponderMeasRequest(++req_id);
  if (NULL == request)
  {
    log_error("LOWIWrapper", "lowi_queue_stop_responder_meas_req"
              " - out of memory");
    return retVal;
  }

  if (LOWIClient::STATUS_OK != client->sendRequest(request))
  {
    retVal = -1;
  }
#endif
  return retVal;
}
int lowi_queue_nr_request()
{
  int retVal = -1;

  // This is illegal operation if lowi wrapper has not been initialized
  if (!lowi_wrapper_initialized)
  {
    log_error ("LOWIWrapper", "illegal lowi_queue_get_batching_results"
               " - uninitialized");
    return retVal;
  }

  LOWINeighborReportRequest* nrReq = new LOWINeighborReportRequest(++req_id);

  if (LOWIClient::STATUS_OK != client->sendRequest(nrReq))
  {
    log_debug ("LOWIWrapper", "Failed to send Neighbor Report Request to LOWI");
  }
  else
  {
    retVal = 0;
  }

  delete nrReq;

  return retVal;
}


int lowi_wrapper_init(ptr2CallbackFunc rsp_callback)
{
  int retVal = 0;
  listener = NULL;
  client = NULL;

  // Set the log level to Warning
  log_set_local_level_for_tag ("LOWIWrapper", EL_INFO);

  if (lowi_wrapper_initialized)
  {
    log_error("LOWIWrapper", "init - LOWI wrapper already initialized!");
    return retVal;
  }

  listener = new LOWIClientListenerImpl();
  if (NULL == listener)
  {
    log_error ("LOWIWrapper", "Could not create the LOWIClientListener");
    retVal = -1;
    return retVal;
  }

  client = LOWIClient::createInstance(listener, true, LOWIClient::LL_INFO);
  req_id = 0;

  if (NULL == client)
  {
    log_error ("LOWIWrapper", "Could not create the LOWIClient");
    retVal = -1;
    return retVal;
  }

  lowi_wrapper_initialized = TRUE;
  ptr2LowiRspCallback = rsp_callback;

  return retVal;
}

int lowi_wrapper_destroy()
{
  int retVal = 0;

  if (NULL != client)
  {
    delete client;
    client = NULL;
  }

  if (NULL != listener)
  {
    delete listener;
    listener = NULL;
  }

  lowi_wrapper_initialized = FALSE;
  ptr2LowiRspCallback = NULL;

  return retVal;
}

