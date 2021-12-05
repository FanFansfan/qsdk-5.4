/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Controller

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Controller

Copyright (c) 2012-2013, 2016-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <lowi_server/lowi_controller.h>
#include <base_util/vector.h>
#include <common/lowi_utils.h>
#include <lowi_server/lowi_wifidriver_interface.h>
#include <lowi_server/lowi_discovery_scan_result_receiver.h>
#include <lowi_server/lowi_ranging_scan_result_receiver.h>
#include <lowi_server/lowi_scan_request_sender.h>
#include <lowi_server/lowi_version.h>
#include <lowi_server/wifidriver/util/lowi_wifidriver_utils.h>
#include "lowi_time.h"
#include <lowi_server/lowi_scheduler.h>
#include "lowi_utils_extn.h"
#include "lowi_diag_log.h"
#include "lowi_background_scan_mgr.h"
#include "lowi_lp_scan_result_receiver.h"
#include "lowi_strings.h"

using namespace qc_loc_fw;

#ifdef LOWI_ON_LE
//remove the cache on LE
#define DEFAULT_CACHE_SIZE 0
#else
#define DEFAULT_CACHE_SIZE 100
#endif
#define DEFAULT_MAX_QUEUE_SIZE 255
#define DEFAULT_THRESHOLD 500
#define DEFAULT_USE_LOWI_LP false
#define DEFAULT_USE_LP_RANGING false

extern int net_admin_capable;
// Global log level for lowi
int lowi_debug_level;
const char * const LOWIController::TAG = "LOWIController" ;

template <class T>
bool createReceiver(T* &scanReceiver, LOWIScanResultReceiverListener* pScanListener, LOWIWifiDriverInterface* pWifiDriver)
{
  bool result = false;
  if (NULL == scanReceiver)
  {
    scanReceiver = new (std::nothrow) T(pScanListener, pWifiDriver);
    if (NULL == scanReceiver)
    {
      log_error ("LOWIController", "Could not create scanReceiver");
    }
    else if (false == scanReceiver->init ())
    {
      log_error ("LOWIController", "Could not init scanReceiver");
      delete scanReceiver;
      scanReceiver = NULL;
    }
    else
    {
      log_debug ("LOWIController", "created scanReceiver successfully");
      result = true;
    }
  }
  return result;
}

LOWIController::LOWIController(const char * const socket_name,
    const char * const config_name) :
    MqClientControllerBase(TAG, SERVER_NAME, socket_name, config_name),
    mEventReceiver (NULL), mCacheManager (NULL), mEventDispatcher (NULL),
    mCurrentRequest (NULL), mDiscoveryScanResultReceiver (NULL),
    mRangingScanResultReceiver(NULL), mBgScanResultReceiver(NULL),
    mScanRequestSender(NULL), mNetlinkSocketReceiver(NULL), mWifiDriver (NULL),
    mWigigDriver(NULL), mPassiveListeningTimerData (NULL), mTimerCallback (NULL),
    mScheduler(NULL), mBackgroundScanMgr(NULL), mLPScanResultReceiver (NULL),
    mInternalCapabilityRequest (NULL)
{
  mEventReceiver           = new (std::nothrow) LOWIEventReceiver ();
  mEventDispatcher         = new (std::nothrow) LOWIEventDispatcher (this);
  mFreshScanThreshold      = DEFAULT_THRESHOLD;
  mMaxQueueSize            = DEFAULT_MAX_QUEUE_SIZE;
  mWifiStateEnabled        = false;
  mWigigStateEnabled       = false;
  mReadDriverCacheDone     = false;
  mNlWifiStatus            = INTF_UNKNOWN;
  mLOWILPPresent           = false;
  mUseLowiLp               = DEFAULT_USE_LOWI_LP;
  mWigigDriverRttSupported = true;
  mLogLevel                = qc_loc_fw::EL_INFO;
  mCacheSize               = DEFAULT_CACHE_SIZE;
  mUseLowiLpRanging        = DEFAULT_USE_LP_RANGING;
}

LOWIController::~LOWIController()
{
  _shutdown();
  if (NULL != mEventReceiver)
  {
    mEventReceiver->removeListener(this);
    delete mEventReceiver;
  }
  if (NULL != mCacheManager)
  {
    delete mCacheManager;
  }
  if (NULL != mEventDispatcher)
  {
    delete mEventDispatcher;
  }
  if (NULL != mDiscoveryScanResultReceiver)
  {
    delete mDiscoveryScanResultReceiver;
  }
  if (NULL != mRangingScanResultReceiver)
  {
    delete mRangingScanResultReceiver;
  }
  if (NULL != mBgScanResultReceiver)
  {
    delete mBgScanResultReceiver;
  }
  if (NULL != mScanRequestSender)
  {
    delete mScanRequestSender;
  }
  if (NULL != mWifiDriver)
  {
    delete mWifiDriver;
  }
  if (NULL != mPassiveListeningTimerData)
  {
    removeLocalTimer (mTimerCallback, mPassiveListeningTimerData);
    delete mPassiveListeningTimerData;
  }
  if (NULL != mTimerCallback)
  {
    delete mTimerCallback;
  }
  if (NULL != mLPScanResultReceiver)
  {
    delete mLPScanResultReceiver;
  }
  if (NULL != mNetlinkSocketReceiver)
  {
    delete mNetlinkSocketReceiver;
  }

  // terminate the ranging scan request scheduler
  terminateScheduler();
  if (NULL != mBackgroundScanMgr)
  {
    delete mBackgroundScanMgr;
    mBackgroundScanMgr = NULL;
  }
  if (NULL != mInternalCapabilityRequest)
  {
    delete mInternalCapabilityRequest;
    mInternalCapabilityRequest = NULL;
  }

  // Cleanup internal lists.
  emptyList(mAsyncScanRequestList);
  emptyList(mPendingRequestQueue);

  lowi_time_close();
  LOWIDiagLog::Cleanup();
}

#define LOC_PROCESS_MAX_NUM_GROUPS 50
#define AID_NET_ADMIN 0xfffff

void LOWIController::emptyList(List<LOWIRequest *>& list)
{
  for (List<LOWIRequest *>::Iterator it = list.begin();
      it != list.end(); ++it)
  {
    LOWIRequest * req = *it;
    delete req;
  }
  list.flush();
}
int LOWIController::_init()
{
  log_verbose(TAG, "init");
  int result = 0;
  gid_t gid_list[LOC_PROCESS_MAX_NUM_GROUPS];
  int ngroups = 0;

  // if lowi.conf is found, load the config items from there.
  // else use the defaults.
  loadConfigItems();

  qc_loc_fw::log_set_global_level(LOWIUtils::to_logLevel(mLogLevel));

  mCacheManager = new (std::nothrow) LOWICacheManager (mCacheSize);
  if (NULL == mCacheManager)
  {
    log_error (TAG, "Cache not created! Operating without it");
  }


  // Set-up event listener from EventReceiver
  if (NULL != mEventReceiver)
  {
    mEventReceiver->addListener(this);
  }

  mTimerCallback = new (std::nothrow) TimerCallback ();
  if (NULL == mTimerCallback)
  {
    log_error (TAG, "Unable to create Timer callback");
    result = -1;
  }

  //Read current group subscriptions
   memset(gid_list, 0, sizeof(gid_list));
   ngroups = getgroups(LOC_PROCESS_MAX_NUM_GROUPS, gid_list);
   if(ngroups == -1) {
      log_error(TAG, "Could not find groups for lowi\n");
   }
   else {
      log_verbose(TAG,"GIDs count : %d ", ngroups);
      for(int i = 0; i < ngroups; i++) {

          log_verbose(TAG," %d ", gid_list[i]);

          if(gid_list[i] == AID_NET_ADMIN)
             net_admin_capable = 1;
      }
  }

  lowi_time_init ();

  // Create the periodic ranging scan request scheduler
  if( false == createScheduler() )
  {
    log_error (TAG, "%s:create scheduler failed", __FUNCTION__);
    result = -1;
  }

  // Create the netlink socket receiver
  if( false == createNetLinkSocketReceiver() )
  {
    result = -1;
  }

  // Do any other initializations
  result = initialize ();

  // Internal Capability request
  mInternalCapabilityRequest = new (std::nothrow) LOWICapabilityRequest (0);

  //check wifi state from system properties at bootup
  bool wifiState = isWifiEnabled ();
  log_verbose (TAG, "wifiState from system properties %d",wifiState);

  return result;
}

eRequestStatus LOWIController::requestMeasurements (LOWIRequest* req)
{
  eRequestStatus retVal = INTERNAL_ERROR;

  log_verbose(TAG, "%s: Request type(%s)", __FUNCTION__,
              (req ? LOWIUtils::to_string(req->getRequestType()) : "NULL"));

  // If the request is for LOWI-LP, we do not have to perform checks to
  // check for WifiDriver or Wifi enable / disable
  if( (NULL != req) &&
      ((LOWIRequest::BATCHING_START == req->getRequestType()) ||
       (LOWIRequest::BATCHING_STOP == req->getRequestType()) ||
       (LOWIRequest::BATCHING_CACHED_RESULTS == req->getRequestType()) ||
       (LOWIRequest::CAPABILITY == req->getRequestType()) ) )
  {
    // If LOWI LP is found, all above requests should go through it.
    if( mLOWILPPresent == true )
    {
      // Send the request
      if( NULL != mLPScanResultReceiver &&
          true == mLPScanResultReceiver->execute(req) )
      {
        retVal = SUCCESS;
      }
    }
    // Return from here because these requests can only be passed to LOWI-LP
    return retVal;
  }

  if( false == isWifiEnabled () )
  {
    log_warning (TAG, "%s: Wifi is not enabled.", __FUNCTION__);
    // Wifi is not enabled, no need to issue the request
    // For a passive listening request return true to indicate that the
    // request is successfully sent to the driver to avoid issuing the
    // request over and over again.
    retVal = (NULL == req) ? SUCCESS : NO_WIFI;
    return retVal;
  }

  if( NULL == mWifiDriver )
  {
    // Can not continue without the driver to service the request
    if (NULL != req)
    {
    log_debug (TAG, "%s: No wifi driver, request " LOWI_REQINFO_FMT " not serviced",
               __FUNCTION__, LOWI_REQINFO(req));
    }
    return NOT_SUPPORTED;
  }

  // Check the request types
  if( (NULL == req) || (LOWIRequest::NEIGHBOR_REPORT == req->getRequestType()) )
  {
    // Passive listening request. Send it to mDiscoveryScanResultReceiver
    if( NULL != mDiscoveryScanResultReceiver &&
        true == mDiscoveryScanResultReceiver->execute (req) )
    {
      retVal = SUCCESS;
    }
  }
  else if( LOWIRequest::LOWI_INTERNAL_MESSAGE == req->getRequestType() )
  {
    LOWIInternalMessage *r = (LOWIInternalMessage *)req;
    if ((LOWIInternalMessage::LOWI_IMSG_FTM_RANGE_RPRT       == r->getInternalMessageType()) ||
        (LOWIInternalMessage::LOWI_IMSG_WIFI_INTF_STATUS_MSG == r->getInternalMessageType()) ||
        (LOWIInternalMessage::LOWI_IMSG_LCI_RPRT             == r->getInternalMessageType()))
    {
      log_debug (TAG, "%s: Internal Message %d sent to driver",
                 __FUNCTION__, r->getInternalMessageType());
      // Internal message. Send it to mDiscoveryScanResultReceiver
      if( NULL != mDiscoveryScanResultReceiver &&
          true == mDiscoveryScanResultReceiver->execute (req) )
      {
        retVal = SUCCESS;
      }
    }
  }
  else if( LOWIRequest::DISCOVERY_SCAN == req->getRequestType() )
  {
    // if discovery scan request not served in LOWI LP,
    // Send the discovery request to mDiscoveryScanResultReceiver
    if( NULL != mDiscoveryScanResultReceiver &&
        true == mDiscoveryScanResultReceiver->execute (req) )
    {
      log_verbose (TAG, "%s: Discovery request " LOWI_REQINFO_FMT " sent",
                   __FUNCTION__, LOWI_REQINFO(req));
      retVal = SUCCESS;
    }
  }
  else if( LOWIRequest::RANGING_SCAN == req->getRequestType() )
  {
    // check if RANGING SCAN can be handled by LOWI-LP
    LOWIRangingScanRequest* request = (LOWIRangingScanRequest*) req;
    int32 ret = handleLowiLpRangingRequest(request);
    if (0 == ret)
    {
      retVal = SUCCESS;
    }
    else if (-1 == ret)
    {
      // Request not accepted over LOWI-LP interface. Use the host
      if( (NULL != mRangingScanResultReceiver) &&
          (true == mRangingScanResultReceiver->execute (req)) )
      {
        retVal = SUCCESS;
      }
    }
    else
    {
      // Request allowed over LP interface but failed may be due to QMI issue
      // Error will be reported to client
      log_debug (TAG, "%s: LP Ranging request " LOWI_REQINFO_FMT " failed",
                 __FUNCTION__, LOWI_REQINFO(req));
    }
  }
  else if( LOWIRequest::SET_LCI_INFORMATION == req->getRequestType() ||
           LOWIRequest::SET_LCR_INFORMATION == req->getRequestType() ||
           LOWIRequest::LOWI_RTT_RM_CHANNEL_REQUEST == req->getRequestType() ||
           LOWIRequest::LOWI_ENABLE_RESPONDER_REQUEST == req->getRequestType() ||
           LOWIRequest::LOWI_DISABLE_RESPONDER_REQUEST == req->getRequestType() ||
           LOWIRequest::LOWI_START_RESPONDER_MEAS_REQUEST == req->getRequestType() ||
           LOWIRequest::LOWI_STOP_RESPONDER_MEAS_REQUEST == req->getRequestType() ||
           LOWIRequest::SEND_LCI_REQUEST == req->getRequestType() ||
           LOWIRequest::FTM_RANGE_REQ == req->getRequestType())
  {
    // Assume the request to be ranging related if we are here; send the request.
    if( NULL != mRangingScanResultReceiver &&
        true == mRangingScanResultReceiver->execute (req) )
    {
      retVal = SUCCESS;
    }
  }
  else if (true == requestBackgroundScan (req) )
  {
    retVal = SUCCESS;
  }
  return retVal;
}

void LOWIController::processRequest (LOWIRequest* request)
{
  log_verbose (TAG, "%s:" LOWI_REQINFO_FMT, __FUNCTION__, LOWI_REQINFO(request));
  // Msg contained a Request

  // Analyze the request and process immediately if possible
  if (0 == processRequestImmediately(request))
  {
    log_debug (TAG, "%s: Request " LOWI_REQINFO_FMT " processed immediately",
               __FUNCTION__, LOWI_REQINFO(request));
    delete request;
  }
  else
  {
    // Request could not be processed immediately.
    // Check if current request is for async scan results
    // and put in appropriate request queue.
    int32 ret= addRequestToAsyncScanRequestList(request);
    if (0 == ret)
    {
      // check for asynchronous requests that need to be sent and skip
      log_debug (TAG, "%s: Request " LOWI_REQINFO_FMT " added to async scan list",
                 __FUNCTION__, LOWI_REQINFO(request));
      return;
    }
    if (-1 == ret)
    {
      log_debug (TAG, "%s: Async scan request " LOWI_REQINFO_FMT " not added",
                 __FUNCTION__, LOWI_REQINFO(request));
      delete request;
      return;
    }

    // not an Async request - continue

    // Check if current request is for batching subscription
    ret= handleBatchingSubscriptionRequest(request);
    if (0 == ret)
    {
      log_debug (TAG, "%s: Batching Request " LOWI_REQINFO_FMT " handled",
                 __FUNCTION__, LOWI_REQINFO(request));
      return;
    }
    if (-1 == ret)
    {
      log_debug (TAG, "%s: Batching request " LOWI_REQINFO_FMT " not handled.",
                 __FUNCTION__, LOWI_REQINFO(request));
      delete request;
      return;
    }

    // not a batching subscription request - continue

    // Check if current request is for capability subscription
    ret= handleCapabilitySubscriptionRequest(request);
    if (0 == ret)
    {
      log_debug (TAG, "%s: Capability Request " LOWI_REQINFO_FMT " added",
                 __FUNCTION__, LOWI_REQINFO(request));
      return;
    }
    if (-1 == ret)
    {
      log_debug (TAG, "%s: Capability request " LOWI_REQINFO_FMT " not added.",
                 __FUNCTION__, LOWI_REQINFO(request));
      delete request;
      return;
    }

    // not a capability subscription request - continue


    /* if it is a discovery scan request, check if could be
     * send to LOWI-LP, if LOWI-LP is present, it doesn't need
     * to be part of pending queue.(LOWI-LP will maintain its own queue)
     * if LOWI-LP is NOT present, treat it as a normal request
     * which will be served in discoveryscanreciever and will be
     * part of pending queue if there is a ongoing request */
    ret= handleLowiLpRequest(request);
    if (0 == ret)
    {
      log_debug (TAG, "%s: Request " LOWI_REQINFO_FMT " sent to LOWI-LP",
                 __FUNCTION__, LOWI_REQINFO(request));
      return;
    }
    if (-1 == ret)
    {
      log_debug (TAG, "%s: Sending Request failed" LOWI_REQINFO_FMT " to LOWI-LP, delete it",
                 __FUNCTION__, LOWI_REQINFO(request));
      delete request;
      return;
    }

    // Check if there is any current request executing
    if ( NULL == mCurrentRequest )
    {
      // No current request
      // Make the request a current request and issue the request
      issueRequest (request);
    }
    else
    {
      // Check if the Pending Q is full and respond
      if (mPendingRequestQueue.getSize() >= (uint32)mMaxQueueSize)
      {
        log_debug (TAG, "%s: Queue size (%d) full!"
                   "Respond busy - request " LOWI_REQINFO_FMT,
                   __FUNCTION__, mPendingRequestQueue.getSize(),
                   LOWI_REQINFO(request));
        // Respond to the request as LOWI is busy.
        sendErrorResponse (*request, LOWIResponse::SCAN_STATUS_BUSY);

        delete request;
      }
      else
      {
        // Already a Request is executing
        // Queue the request, just received
        mPendingRequestQueue.push (request);
        log_debug (TAG, "%s: Request " LOWI_REQINFO_FMT " Queued - queue size = %d "
                   " current request " LOWI_REQINFO_FMT, __FUNCTION__,
                   LOWI_REQINFO(request), mPendingRequestQueue.getSize(),
                   LOWI_REQINFO(mCurrentRequest));
      }
    }
  }
}

bool LOWIController::handleRequestFailure (eRequestStatus req_status,
                                           LOWIRequest* request)
{
  bool retVal = true;
  log_info(TAG, "%s: Request " LOWI_REQINFO_FMT " not sent to wifi driver,"
           " status = %s", __FUNCTION__, LOWI_REQINFO(request),
           LOWIStrings::to_string(req_status));

  LOWIResponse::eScanStatus scan_status =
      LOWIResponse::SCAN_STATUS_INTERNAL_ERROR;
  if (NO_WIFI == req_status)
  {
    scan_status = LOWIResponse::SCAN_STATUS_NO_WIFI;
  }
  else if (NOT_SUPPORTED == req_status)
  {
    scan_status = LOWIResponse::SCAN_STATUS_NOT_SUPPORTED;
  }

  if( (NULL != mScheduler) && mScheduler->isSchedulerRequest(request) )
  {
    // if the scheduler generated the request, then it needs to generate the
    // appropriate error response to the clients.
    mScheduler->manageErrRsp(request, scan_status);
  }
  else if( (NULL != mBackgroundScanMgr) &&
       LOWIUtils::isBackgroundScan(request) )
  {
    // the BSM needs to manage the error so clients get the correct response
    mBackgroundScanMgr->manageErrRsp(request, scan_status);
    return true;
  }
  else
  {
    // handle error response to request not generated by scheduler
    sendErrorResponse (*request, scan_status);
  }
  return retVal;
}

void LOWIController::processMeasurementResults(LOWIMeasurementResult* meas_result)
{

  processMeasurementResultsLP (meas_result);

  bool response_generated = false;
  // Cache the measurements, if there is no current request
  // This means meas results for the Passive listening / Batching

  // Discovery scan results need to update the cache if results are valid
  if ((meas_result->driverError == LOWI_DRIVER_ERROR_NONE) &&
      (!meas_result->request ||
       (meas_result->request->getRequestType() == LOWIRequest::DISCOVERY_SCAN)))
  {
    // Update the Result from cache, if they were received from LP
    mCacheManager->updateResultRecdFrmLP (*meas_result);
    mCacheManager->putInCache(meas_result->scanMeasurements,
        meas_result->isResultFromLOWILP());
  }
  if ((NULL == mCurrentRequest) ||
      (meas_result->request != mCurrentRequest))
  {
    if (mCurrentRequest)
    {
      log_info (TAG, "%s: Results for Req %p.Current Req " LOWI_REQINFO_FMT,
                __FUNCTION__, meas_result->request, LOWI_REQINFO(mCurrentRequest));
    }
    else
    {
      log_debug (TAG, "%s: No current Request. Cache measurements", __FUNCTION__);
    }
    // Send the response to the Async scan requests
    sendAsyncScanResponse (NULL, meas_result);

    // Send response to batching
    sendBatchingStatusResponse (meas_result);

    // Send Capabilities subscription response
    sendCapabilitiesSubscriptionResponse (meas_result);

    // Send LOWI-LP discovery scan results
    response_generated = sendLOWILpDiscoveryScanResponse(meas_result);
    // Get rid of the allocated memory ourselves if
    // no response is being generated
    if(false == response_generated)
    {
      for (unsigned int ii = 0;
           ii < meas_result->scanMeasurements.getNumOfElements();
           ++ii)
      {
        delete meas_result->scanMeasurements[ii];
      }
    }
  }
  else
  {
    // Measurements correspond to current request
    if( LOWIRequest::LOWI_INTERNAL_MESSAGE != mCurrentRequest->getRequestType() )
    {
      // Send the response to the Async scan requests
      sendAsyncScanResponse (mCurrentRequest, meas_result);
      response_generated = sendResponse (*mCurrentRequest, meas_result);
      log_info (TAG, "%s: response sent for current request " LOWI_REQINFO_FMT,
                __FUNCTION__, LOWI_REQINFO(mCurrentRequest));
    }
    // Delete the current request
    delete mCurrentRequest;
    mCurrentRequest = NULL;
  }

  processPendingRequests();

  issuePendingRequest ();

  // Delete the measurement results
  delete meas_result;
}

void LOWIController::issuePendingRequest ()
{
  // Issue a new request if there is no current request,
  if (NULL == mCurrentRequest)
  {
    while (0 != mPendingRequestQueue.getSize())
    {
      // Loop through all the pending request with the intention to just issue
      // one request. If the request is unsuccessful, issue an error response
      // to the corresponding client and then pick up the next request.
      LOWIRequest* req = NULL;
      int result = mPendingRequestQueue.pop(&req);
      if ((0 == result) && (req != NULL))
      {
        log_debug (TAG, "%s: Pending request " LOWI_REQINFO_FMT " retrieved, Queue size = %d", __FUNCTION__,
                   LOWI_REQINFO(req), mPendingRequestQueue.getSize());
        // Send the request to wifi driver.
        bool retVal = issueRequest (req);
        if (true == retVal)
        {
          break;
        }
      }
    }
  }
  else
  {
    log_debug (TAG, "%s: Current request " LOWI_REQINFO_FMT " pending for measurements",
               __FUNCTION__, LOWI_REQINFO(mCurrentRequest));
  }
}

bool LOWIController::issueRequest (LOWIRequest* req)
{
  bool retVal = false;
  eRequestStatus req_status = requestMeasurements (req);
  log_debug (TAG, "%s: " LOWI_REQINFO_FMT " sent to driver request - %s",
             __FUNCTION__, LOWI_REQINFO(req),
             LOWIStrings::to_string(req_status));
  if (SUCCESS == req_status)
  {
    mCurrentRequest = req;
    retVal = true;
  }
  else
  {
    handleRequestFailure (req_status, req);
    delete req;
  }
  return retVal;
}

void LOWIController::_process(InPostcard * const in_msg)
{
// This is useful to stop the process to be able to check memory leaks etc
//#define TEST 1
#ifdef TEST
    uint32 request_id = 0;
#endif
  if(NULL == in_msg) return;

  int result = 1;
  do
  {
    // Parse the post card to get a Local Msg
    LOWILocalMsg* msg = mEventReceiver->handleEvent (in_msg);
    if (NULL == msg)
    {
      result = 0; // No processing is required.
      break;
    }

    // If msg contains a request, log it in diags
    if (true == msg->containsRequest())
    {
      log_debug(TAG, "%s: Request " LOWI_REQINFO_FMT " received, type(%s)",
                __FUNCTION__, LOWI_REQINFO(msg->getLOWIRequest()),
                LOWIUtils::to_string(msg->getLOWIRequest()->getRequestType()));
      LOWIDiagLog::Log(msg->getLOWIRequest());
    }

    // check results to avoid race condition
    LOWIMeasurementResult *meas_result = msg->getMeasurementResult();
    if (meas_result)
    {
      // if results is from LOWI-LP and contains information regarding LP service
      // don't delete the measurement result. This will avoid the race condition where
      // LOWI-LP indication comes before the wireless interface status indication
      if ((true == meas_result->isResultFromLOWILP()) &&
          ((meas_result->driverError == LOWI_LP_SERVICE_FOUND)
           || (meas_result->driverError == LOWI_LP_SERVICE_ERROR)))
      {
        log_verbose(TAG, "Meas result from LOWI-LP "
                    "dont delete it even if Wireless is off");
      }
      //If wifi and wigig are off, discard measurement results
      else if (false == isWirelessIntfEnabled(msg))
      {
        LOWIMeasurementResult::deleteInstance(msg->getMeasurementResult());
        delete msg;
        msg = NULL;
        result = 0;
        break;
      }
    }

    // The BackgroundScanMgr module handles all the requests that are related to bgscan and
    // hotlist such as the following: bgscan start, bgscan stop, hotlist set, hotlist clear,
    // significant change list set, significant change list clear, get bgscan cached results
    // and MAC OUI set.
    // The BackgroundScanMgr also handles the following responses:
    // --
    // --
    if( (NULL != mBackgroundScanMgr) && mBackgroundScanMgr->bsmManageMsg(msg) )
    {
      log_debug (TAG, "BSM is managing the msg");
      // delete and set ptr to NULL so that subsequent logic does not handle
      delete msg;
      msg = NULL;
    }

    // The scheduler intercepts the message to manage the following:
    // -- periodic ranging scan requests
    // -- ranging scan requests with NAN wifi nodes in them
    // -- cancel requests
    // The scheduler also manages the responses for these requests.
    // Any other type of request/response will fall through and be processed as usual
    if( (NULL != mScheduler) && mScheduler->manageMsg(msg) )
    {
      log_debug (TAG, "Scheduler is managing the msg");
      // delete and set ptr to NULL so that subsequent logic does not handle
      delete msg;
      msg = NULL;
    }

    LOWIRequest* request = NULL;

    if (NULL != msg)
    {
      if (true == msg->containsRequest())
      {
        // Contains a Request
        request = msg->getLOWIRequest();
        if (NULL != request)
        {
          processRequest (request);
        }
        else
        {
          log_error (TAG, "Request pointer NULL");
        }
      }
      else
      {
        // Message contains Measurement Result
        meas_result = msg->getMeasurementResult ();
        if (NULL != meas_result)
        {
          log_debug (TAG, "Measurements received");
#ifdef TEST
          if (NULL != meas_result->request)
            request_id = meas_result->request->getRequestId();
#endif
          processMeasurementResults (meas_result);
        }
        else
        {
          log_error (TAG, "Measurements result pointer NULL");
        }
      }
      delete msg;
    }

    result = 0;
  } while (0);

  delete in_msg;
  if(0 != result)
  {
    log_error(TAG, "_process failed %d", result);
  }
#ifdef TEST
  if (9999 == request_id)
  {
    kill ();
  }
#endif
}

void LOWIController::_shutdown()
{
  if(CS_DESTROYED != m_state)
  {
    log_debug(TAG, "shutdown");

    // flush and kill all modules

    m_state = CS_DESTROYED;
  }
  else
  {
    log_debug(TAG, "shutdown: already in DESTROYED state, skip");
  }
}

void LOWIController::scanResultsReceived (LOWIMeasurementResult* result)
{
  log_verbose (TAG, "%s", __FUNCTION__);

  if (NULL == result)
  {
    log_error (TAG, "%s: Measurements NULL!", __FUNCTION__);
    return;
  }

  // Pass the pointer to the measurements through the Postcard
  // Measurements should be deleted by the LOWIController once used.
  InPostcard* card = LOWIMeasurementResultBase::createPostcard(result);
  if (NULL == card)
  {
    log_error (TAG, "%s: create Scan Meas card - failed", __FUNCTION__);
  }
  else
  {
    // Insert the card to the local msg queue so that the
    // Controller thread can get the InPostcard from the Blocking Queue
    MqMsgWrapper * wrapper = MqMsgWrapper::createInstance(card);
    if (0 != this->m_local_msg_queue->push (wrapper))
    {
      log_error (TAG, "%s: push results to queue - failed"
          " Delete it", __FUNCTION__);
      delete result;
      delete card;
    }
  }
}

void LOWIController::internalMessageReceived (LOWIInternalMessage* req)
{
  log_verbose (TAG, "%s", __FUNCTION__);

  if (NULL == req)
  {
    log_error (TAG, "%s: internal message NULL!", __FUNCTION__);
    return;
  }

  // Pass the pointer to the internal message through the Postcard
  InPostcard* card = LOWIInternalMessage::createPostcard(req);
  if (NULL == card)
  {
    log_error (TAG, "%s: create internal message card - failed", __FUNCTION__);
  }
  else
  {
    // Insert the card to the local msg queue so that the
    // Controller thread can get the InPostcard from the Blocking Queue
    MqMsgWrapper * wrapper = MqMsgWrapper::createInstance(card);
    if (0 != this->m_local_msg_queue->push (wrapper))
    {
      log_error (TAG, "%s: push to internal message to queue -- failed"
          " Delete it", __FUNCTION__);
      delete req;
      delete card;
    }
  }
}

void LOWIController::intfStateReceived(LOWIDriverInterface &result)
{
  log_debug (TAG, "%s: ifname(%s) state(%d)", __FUNCTION__, result.ifname, result.state);
  OutPostcard* outcard = NULL;
  InPostcard* incard = NULL;
  outcard = OutPostcard::createInstance();
  if (outcard == NULL ||
      outcard->init () != 0 ||
      outcard->addString("INFO", "INTF-STATUS-UPDATE")   ||
      outcard->addString("IFNAME", result.ifname)        ||
      outcard->addInt32("IS_INTF_ON", result.state) != 0 ||
      outcard->finalize() != 0)
  {
    log_warning (TAG, "%s: create postcard failed", __FUNCTION__);
  }
  else
  {
    incard = InPostcard::createInstance (outcard);
    MqMsgWrapper * wrapper = MqMsgWrapper::createInstance(incard);
    if (0 != this->m_local_msg_queue->push (wrapper))
    {
      log_error (TAG, "%s: push card on queue - failed", __FUNCTION__);
      // Insert the card to the local msg queue so that the
      // Controller thread can get the InPostcard from the Blocking Queue
      delete incard;
    }
  }
  delete outcard;
} // intfStateReceived

bool LOWIController::sendResponse (LOWIRequest& req,
                                   LOWIMeasurementResult* result)
{
  bool retVal = false;
  LOWIResponse* resp = (LOWIUtils::isBackgroundScan(&req)) ?
                       generateBgScanResponse(req, result):
                       generateResponse (req, result);

  if( NULL == resp )
  {
    log_error (TAG, "Unable to generate Response to the request!");
  }
  else
  {
    mEventDispatcher->sendResponse (resp, req.getRequestOriginator());
    delete resp;
    retVal = true;
  }
  return retVal;
}

bool LOWIController::sendErrorResponse (LOWIRequest& req,
    LOWIResponse::eScanStatus status)
{
  bool retVal = false;
  log_verbose (TAG, "%s:Send %d Response to the Request!", __FUNCTION__, status);
  LOWIMeasurementResult result;
  result.measurementTimestamp = 0;
  result.scanStatus = status;
  result.scanType = LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;

  LOWIResponse* resp = generateResponse (req, &result);
  if (NULL != resp)
  {
    mEventDispatcher->sendResponse (resp,
        req.getRequestOriginator());
    retVal = true;
  }
  else
  {
    log_error (TAG, "Unable to send the error response");
  }
  delete resp;
  return retVal;
}

LOWIResponse* LOWIController::generateResponse (LOWIRequest& req,
                                                LOWIMeasurementResult* meas_result)
{
  LOWIResponse* response = NULL;
  LOWIRequest* request = &req;
  LOWIResponse::eScanStatus scanStatus = LOWIResponse::SCAN_STATUS_UNKNOWN;

  switch (req.getRequestType())
  {
  case LOWIRequest::DISCOVERY_SCAN:
  {
    if (NULL == meas_result)
    {
      log_error (TAG, "Measurement Result null");
      break;
    }

    LOWIDiscoveryScanResponse* resp = new (std::nothrow)
                LOWIDiscoveryScanResponse (req.getRequestId());
    if (NULL == resp)
    {
      log_error (TAG, "%s, Memory allocation failure!");
      break;
    }

    resp->scanTypeResponse = meas_result->scanType;
    resp->scanStatus = meas_result->scanStatus;
    resp->timestamp = meas_result->measurementTimestamp;
    // The vector might be empty for no measurements
    resp->scanMeasurements = meas_result->scanMeasurements;
    scanStatus = resp->scanStatus;
    if (mCacheManager &&
        mCacheManager->getStaMacInCache(resp->self_mac) == false)
    {
      log_error(TAG, "%s - Failed to request Local STA MAC",
               __FUNCTION__);
    }
    else
    {
      log_verbose(TAG, "%s - Local STA MAC: " LOWI_MACADDR_FMT ,
                 __FUNCTION__, LOWI_MACADDR(resp->self_mac));
    }
    response = resp;
  }
  break;
  case LOWIRequest::RANGING_SCAN:
  case LOWIRequest::PERIODIC_RANGING_SCAN:
  {

    if (NULL == meas_result)
    {
      log_error (TAG, "Measurement Result null");
      break;
    }

    LOWIRangingScanResponse* resp = new (std::nothrow)
                LOWIRangingScanResponse (req.getRequestId());
    if (NULL == resp)
    {
      log_error (TAG, "%s, Memory allocation failure!");
      break;
    }

    resp->scanStatus = meas_result->scanStatus;
    scanStatus = resp->scanStatus;
    // The measurements as such could be null because of
    // no AP's being in range so NULL vector pointer is fine
    resp->scanMeasurements = meas_result->scanMeasurements;

    response = resp;
  }
  break;
  case LOWIRequest::CAPABILITY:
  {

    // Start with default capabilities which are nothing supported.
    LOWICapabilities cap;
    bool status = false;
    if (NULL != mWifiDriver)
    {
      status = mWifiDriver->sendCapabilitiesReq(request->get_interface());
      if (!status) {
          log_error (TAG, "%s, failed to send the capability request", __FUNCTION__);
          break;
      }
      cap = mWifiDriver->getCapabilities();
    }
    else
    {
      log_info (TAG, "%s, Get Wifi capabilitiles from controller", __FUNCTION__);
      cap = mWifiCaps;
    }

    // if there is a functioning wigig driver, add on the wigig caps to the response
    if (NULL != mWigigDriver)
    {
      LOWICapabilities wigigCaps = mWigigDriver->getCapabilities();
      cap.supportedCapsWigig     = wigigCaps.supportedCapsWigig;
    }
    else
    {
      log_info (TAG, "%s, Get Wigig capabilitiles from controller", __FUNCTION__);
      cap.supportedCapsWigig     = mWigigCaps.supportedCapsWigig;
    }
      status = true;

    LOWICapabilityResponse* resp = new (std::nothrow)
                LOWICapabilityResponse (req.getRequestId(), cap, status);
    if (NULL == resp)
    {
      log_error (TAG, "%s, Memory allocation failure!", __FUNCTION__);
      break;
    }
    resp->getCapabilities().PrintCapabilities();

    response = resp;
  }
  break;
  case LOWIRequest::RESET_CACHE:
  {
    LOWICacheResetResponse* resp = new (std::nothrow)
                LOWICacheResetResponse (req.getRequestId(),
                    mCacheManager->resetCache());
    if (NULL == resp)
    {
      log_error (TAG, "%s, Memory allocation failure!", __FUNCTION__);
      break;
    }

    response = resp;

  }
  break;
  case LOWIRequest::LOWI_WLAN_STATE_QUERY_REQUEST:
  {
    LOWIResponse::eScanStatus status = LOWIResponse::SCAN_STATUS_SUCCESS;
    if (NULL != meas_result)
    {
      status = meas_result->scanStatus;
    }
    LOWIWlanStateQueryResponse* resp =
        new (std::nothrow) LOWIWlanStateQueryResponse (req.getRequestId(), status);
    if (NULL == resp)
    {
      log_error (TAG, "%s, Memory allocation failure!", __FUNCTION__);
      break;
    }
    LOWIScanMeasurement scan;
    bool ret = mCacheManager->getAssociatedAP(scan);
    if (true == ret)
    {
      resp->connected = ret;
      resp->connectedNodeBssid = scan.bssid;
      resp->connectedNodeFreq = scan.frequency;
      resp->connectedNodeSsid = scan.ssid;
      resp->connectedNodeRssi = scan.measurementsInfo[0]->rssi;
    }

    response = resp;

  }
  break;

  case LOWIRequest::ASYNC_DISCOVERY_SCAN_RESULTS:
  {
    if (NULL == meas_result)
    {
      log_error (TAG, "Measurement Result null");
      break;
    }

    LOWIAsyncDiscoveryScanResultResponse* resp = new (std::nothrow)
      LOWIAsyncDiscoveryScanResultResponse (req.getRequestId());
    if (NULL == resp)
    {
      log_error (TAG, "%s, Memory allocation failure!", __FUNCTION__);
      break;
    }

    resp->scanTypeResponse = meas_result->scanType;
    resp->scanStatus = meas_result->scanStatus;
    scanStatus = resp->scanStatus;
    resp->timestamp = meas_result->measurementTimestamp;
    // Do a deep copy here instead of a simple vector assignment
    // Reason for doing this expensive operation is
    // The Response when deleted has to completely delete all the
    // scan measurements from the vector as we expect the clients
    // to only delete the response. So if we just copy the vector
    // the delete response with in the lowi_server will delete the
    // all the scan measurements leaving no measurements to be notified
    // to remaining requests
    unsigned int size = meas_result->scanMeasurements.getNumOfElements();
    // The vector might be empty for no measurements
    if (0 == size)
    {
      resp->scanMeasurements = meas_result->scanMeasurements;
    }
    else
    {
      for (unsigned int ii = 0; ii < size; ++ii)
      {
        LOWIScanMeasurement* meas = new (std::nothrow)
          LOWIScanMeasurement(*meas_result->scanMeasurements[ii]);
        if (NULL != meas)
        {
          resp->scanMeasurements.push_back(meas);
        }
        else
        {
          log_error(TAG, "%s: Copy LOWIScanMeasurement Failed", __FUNCTION__);
        }
      }
    }

    response = resp;
  }
  break;
  case LOWIRequest::LOWI_CONFIG_REQUEST:
  {
      LOWIStatusResponse* resp =
          new (std::nothrow) LOWIStatusResponse (req.getRequestId());
      LOWI_BREAK_ON_COND((NULL == resp), debug, "@generateResponse: LOWI_CONFIG_REQUEST unable to create response")
      resp->scanStatus = meas_result->scanStatus;
      response = resp;
  }
  break;
  case LOWIRequest::LOCATION_ANQP:
  {
    LOWIStatusResponse* resp =
      new (std::nothrow) LOWIStatusResponse (req.getRequestId());
    LOWI_BREAK_ON_COND((NULL == resp), debug, "@generateResponse: LOCATION_ANQP unable to create response")
    resp->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
    response = resp;
  }
  break;
  default:
    break;
  }
  if (response != NULL)
  {
    log_debug (TAG, "%s: Type (%s) ScanStatus (%d) request " LOWI_REQINFO_FMT,
               __FUNCTION__, LOWIUtils::to_string(request->getRequestType()),
               scanStatus, LOWI_REQINFO(request));
  }
  else
  {
    log_debug (TAG, "%s: No response, Type (%s) ScanStatus (%d) request " LOWI_REQINFO_FMT,
               __FUNCTION__, LOWIUtils::to_string(request->getRequestType()),
               scanStatus, LOWI_REQINFO(request));
  }
  return response;
}

int32 LOWIController::processRequestImmediately (LOWIRequest* request)
{
  int32 retVal = -1;
  bool responseSent = false;
  // Check if the Request is Reset Cache or Capability check request
  // and respond to them immediately

  if (LOWIRequest::CAPABILITY == request->getRequestType ())
  {
    responseSent = sendResponse (*request, NULL);
    retVal = 0;
  }
  else if (LOWIRequest::RESET_CACHE == request->getRequestType ())
  {
    responseSent = sendResponse (*request, NULL);
    retVal = 0;
  }
  else if (LOWIRequest::LOWI_WLAN_STATE_QUERY_REQUEST == request->getRequestType ())
  {
    responseSent = sendResponse (*request, NULL);
    retVal = 0;
  }
  else if (LOWIRequest::DISCOVERY_SCAN == request->getRequestType())
  {
    LOWIDiscoveryScanRequest* req = (LOWIDiscoveryScanRequest*) request;

    int32 err = 0;
    int64 fb_ts = 0;
    int64 cache_ts = 0;
    LOWIMeasurementResult result;
    // Check if it is a cache only request
    if (LOWIDiscoveryScanRequest::CACHE_ONLY == req->getRequestMode())
    {
      // process immediately if there is no current request pending
      // else, check the buffer bit and only process right now if the
      // buffer bit is not set.
      if (false == req->getBufferCacheRequest() || NULL == mCurrentRequest)
      {
        // Cache only request should be served immediately if the buffer
        // bit is not set
        cache_ts =
          LOWIUtils::currentTimeMs()- (req->getMeasAgeFilterSec()*1000);
        fb_ts = 0;
        err = getMeasurementResultsFromCache (cache_ts, fb_ts, req, result);
        // Send the response to the cache only request
        // Not bothered regarding the err code here.
        responseSent = sendResponse (*request, &result);
        retVal = 0;
      }
    }
    else if (LOWIDiscoveryScanRequest::CACHE_FALLBACK
        == req->getRequestMode())
    {
      cache_ts =
        LOWIUtils::currentTimeMs()- (req->getMeasAgeFilterSec()*1000);
      fb_ts =
        LOWIUtils::currentTimeMs()- (req->getFallbackToleranceSec()*1000);
      err = getMeasurementResultsFromCache (cache_ts, fb_ts, req, result);
      if (err == 0)
      {
        // Measurements for all the freq / band are found after the fallback
        // timestamp. We can respond with the results from cache
        responseSent = sendResponse (*request, &result);
        retVal = 0;
      }
    }
    else if (LOWIDiscoveryScanRequest::NORMAL == req->getRequestMode())
    {
      // In NORMAL Request mode, we should check if all the freq / bands
      // are scanned last, between current time and fresh threshold.
      // In that case, we can service the NORMAL request from Cache itself
      // considering that the measurements in the cache are recent enough.

      // To do this, we query the measurements from the cache with the
      // cache ts = current ts - fresh threshold
      // If all the requested channels were scanned after the cache timestamp,
      // we will get the results as well as err 0, otherwise we will get what
      // ever channels are scanned after cached ts and -1 in error code
      fb_ts = 0;
      cache_ts = LOWIUtils::currentTimeMs() - mFreshScanThreshold;
      if (cache_ts > 0)
      {
        err = getMeasurementResultsFromCache (cache_ts, fb_ts, req, result);
        if (0 == err)
        {
          responseSent = sendResponse (*request, &result);
          retVal = 0;
        }
      }
      else
      {
        log_warning (TAG, "%s: Invalid cache ts"
            " request " LOWI_REQINFO_FMT " - try later", __FUNCTION__, LOWI_REQINFO(req));
      }
    }
  }
  else if (LOWIRequest::LOCATION_ANQP == request->getRequestType())
  {
    processLocANQPRequest(request);
    responseSent = sendResponse (*request, NULL);
    retVal = 0;
  }
  else if (LOWIRequest::LOWI_CONFIG_REQUEST == request->getRequestType())
  {
    LOWIResponse::eScanStatus scan_status =
      LOWIResponse::SCAN_STATUS_INTERNAL_ERROR;
    LOWIConfigRequest* req = (LOWIConfigRequest*) request;
    if (true == ProcessConfigRequest(req))
    {
      retVal = 0;
      scan_status = LOWIResponse::SCAN_STATUS_SUCCESS;
    }
    responseSent = sendErrorResponse (*request, scan_status);
  }
  if (responseSent == true)
  {
    log_debug (TAG, "%s: Response sent for request(%s) " LOWI_REQINFO_FMT,
               __FUNCTION__,
               LOWIUtils::to_string(request->getRequestType()), LOWI_REQINFO(request));

  }
  return retVal;
}

int32 LOWIController::getMeasurementResultsFromCache(int64 cache_ts,
    int64 fb_ts, LOWIDiscoveryScanRequest* req, LOWIMeasurementResult & result)
{
  int32 err = 0;
  int64 latest_cached_timestamp = 0;
  log_verbose (TAG, "%s", __FUNCTION__);
  if (0 == req->getChannels().getNumOfElements())
  {
    // Request is for bands
    err = mCacheManager->getFromCache(cache_ts, fb_ts,
        req->getBand(),result.scanMeasurements,
        latest_cached_timestamp);
  }
  else
  {
    // Request is for channels
    err = mCacheManager->getFromCache(cache_ts, fb_ts,
        req->getChannels(),result.scanMeasurements,
        latest_cached_timestamp);
  }
  if (0 == err)
  {
    log_verbose (TAG, "%s: Got results", __FUNCTION__);
    result.scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
    // TODO: Check if type should be active / passive in this case
    result.scanType =
        LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
    result.measurementTimestamp = latest_cached_timestamp;
  }
  else
  {
    result.scanStatus = LOWIResponse::SCAN_STATUS_INTERNAL_ERROR;
    // TODO: Check if type should be active / passive in this case
    result.scanType =
        LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
    result.measurementTimestamp = latest_cached_timestamp;
  }
  return err;
}

void LOWIController::notifyWlanInterfaceStatusChange()
{
  static uint32 cntr = 0;
  LOWIWifiIntfStateMessage *r =
  new (std::nothrow) LOWIWifiIntfStateMessage((++cntr), mNlWifiStatus, TAG);
  if ( NULL != r )
  {
    // Send the Interface State message to the Discovery Scan receiver.
    log_debug(TAG, "%s: Send Interface state request " LOWI_REQINFO_FMT,
              __FUNCTION__, LOWI_REQINFO(r));
    processRequest(r);
  }
}

void LOWIController::updateIntfState (LOWIDriverInterface &intf)
{
  if (0 == strncmp(LOWIWifiDriverUtils::get_wigig_interface_name(),
                   intf.ifname,
                   LOWI_MAX_INTF_NAME_LEN))
  {
    log_debug (TAG, "%s: WIGIG enabled %d mNlWigigStatus %d mWigigStateEnabled %d",
              __FUNCTION__, intf.state, mNlWigigStatus, mWigigStateEnabled);
    mNlWigigStatus = intf.state;
    isWigigEnabled();
  }
  else if (0 == strcmp(LOWIWifiDriverUtils::get_interface_name(), intf.ifname))
  {
    log_debug (TAG, "%s: WIFI enabled %d mNlWifiStatus %d mWifiStateEnabled %d",
              __FUNCTION__, intf.state, mNlWifiStatus, mWifiStateEnabled);
    eWifiIntfState prevState = mNlWifiStatus;
    mNlWifiStatus = intf.state;
    isWifiEnabled ();
    if ((mNlWifiStatus == INTF_RUNNING) && (prevState != INTF_RUNNING))
    {
      notifyWlanInterfaceStatusChange();
    }
  }
} // updateIntfState

void LOWIController::timerCallback (eTimerId id)
{
  log_verbose (TAG, "%s", __FUNCTION__);
  if(RANGING_REQUEST_SCHEDULER_TIMER == id)
  {
    if(NULL != mScheduler)
    {
      log_debug(TAG, "%s: ranging request scheduler timer", __FUNCTION__);
      mScheduler->timerCallback();
    }
    else
    {
      log_warning(TAG, "%s: mScheduler NULL", __FUNCTION__);
    }
  }
}

bool LOWIController::isWifiEnabled ()
{
  boolean prevWiFiState           = mWifiStateEnabled;
  eWifiIntfState prevNlWifiStatus = mNlWifiStatus;

  log_debug(TAG, "%s: mNlWifiStatus %d mWifiStateEnabled %d", __FUNCTION__,
             mNlWifiStatus, mWifiStateEnabled);
  // If states match, no need to process
  if (((INTF_DOWN == mNlWifiStatus) && !mWifiStateEnabled) ||
      ((INTF_DOWN < mNlWifiStatus) && mWifiStateEnabled))
  {
    return mWifiStateEnabled;
  }

  if (INTF_UNKNOWN == mNlWifiStatus)
  {
    mNlWifiStatus =
    LOWIWifiDriverInterface::getInterfaceState(LOWIWifiDriverUtils::get_interface_name());
  }
  mWifiStateEnabled = ((mNlWifiStatus == INTF_UP) ||
                       (mNlWifiStatus == INTF_RUNNING));
  if (false == prevWiFiState && true == mWifiStateEnabled)
  {
    // Wifi enabled now
    log_info (TAG, "%s: Wifi is now enabled", __FUNCTION__);
    // Terminate the previous Scan result receiver
    terminateScanResultReceiver ();

    // Create the wifi driver
    if (true == createWifiDriver ())
    {
      // Read the cached data from the wifi driver.
      readCachedMeasurementsFromDriver ();

      //! Store the Driver LOWI capabilities in the controller
      getWifiCapabilities();

      // Create new Scan result receivers
      createScanResultReceiver ();

      if ((INTF_RUNNING == mNlWifiStatus) &&
          (INTF_UNKNOWN == prevNlWifiStatus))
      {
        notifyWlanInterfaceStatusChange();
      }
    }
    else
    {
      log_verbose (TAG, "%s: createWifiDriver failed", __FUNCTION__);
    }
  }
  else if (true == prevWiFiState && false == mWifiStateEnabled)
  {
    log_info (TAG, "%s: Wifi is now disabled", __FUNCTION__);

    // Terminate the scan result receivers
    terminateScanResultReceiver ();

    // Terminate Wifi driver
    terminateWifiDriver ();
    // Wifi is not enabled anymore.
    mNlWifiStatus = INTF_DOWN;
    // There might be a current request that was issued.
    // We should notify an error to the client and cancel all
    // pending requests from the queue as well.
    if (NULL != mCurrentRequest)
    {
      log_verbose (TAG, "%s: Wifi disabled, Send error for current request", __FUNCTION__);
      sendErrorResponse (*mCurrentRequest, LOWIResponse::SCAN_STATUS_NO_WIFI);
      delete mCurrentRequest;
      mCurrentRequest = NULL;
      // this will ensure that all pending requests will be removed
      // and the respective clients notified.
      issuePendingRequest ();
    }
    mScheduler->removePeers(WIFI_PEERS);
  }
  return mWifiStateEnabled;
} // isWifiEnabled

bool LOWIController::isWigigEnabled()
{
  boolean prevWiGigState           = mWigigStateEnabled;

  if (!mWigigDriverRttSupported)
  {
    log_verbose (TAG, "%s: RTT is NOT supported", __FUNCTION__);
    terminateWigigRangingScanResultReceiver();
    terminateWigigDriver();
    mWigigStateEnabled = false;
    return mWigigStateEnabled;
  }

  log_debug (TAG, "%s: mNlWigigStatus %d mWigigStateEnabled %d",
             __FUNCTION__, mNlWigigStatus, mWigigStateEnabled);
  // If states match, no need to process
  if (((INTF_DOWN == mNlWigigStatus) && !mWigigStateEnabled) ||
      ((INTF_DOWN < mNlWigigStatus) && mWigigStateEnabled))
  {
    return mWigigStateEnabled;
  }

  if (INTF_UNKNOWN == mNlWigigStatus)
  {
    mNlWigigStatus =
    LOWIWifiDriverInterface::getInterfaceState(LOWIWifiDriverUtils::get_wigig_interface_name());
  }
  mWigigStateEnabled = ((mNlWigigStatus == INTF_UP) ||
                       (mNlWigigStatus == INTF_RUNNING));
  if (false == prevWiGigState && true == mWigigStateEnabled)
  {
    // In this case the wigig driver was disabled, but upon checking the latest wigig
    // interface status (mNlWigigStatus), we find that the interface is either up or
    // running, which in turn, means the wigig driver is now enabled.
    // To ensure proper initialization, create the wigig driver again.
    log_debug (TAG, "%s: Wigig is now enabled", __FUNCTION__);

    // Terminate the previous scan result receiver
    terminateWigigRangingScanResultReceiver();

    if (true == createWigigDriver())
    {
      //! Store the Driver LOWI capabilities in the controller
      getWigigCapabilities();

      createWigigRangingScanResultReceiver();
    }
    else
    {
      log_verbose(TAG, "%s: createWigigDriver failed", __FUNCTION__);
    }
  }
  else if (true == prevWiGigState && false == mWigigStateEnabled)
  {
    // In this case the wigig driver was enbled, but upon checking the latest wigig
    // interface status (mNlWigigStatus), we find that the interface is down, which
    // in turn, means the wigig driver is not available.
    // Remove the driver along with the scan result receiver that calls it.
    log_debug (TAG, "%s: Wigig is now disabled", __FUNCTION__);

    terminateWigigRangingScanResultReceiver ();
    terminateWigigDriver ();
    mNlWigigStatus = INTF_DOWN; // Wigig driver is not enabled anymore.

    // Cancel any current, pending, or potential future
    // requests and notify the clients.
    mScheduler->cancelCurrentRequest();
    mScheduler->removePeers(WIGIG_PEERS);
  }
  return mWigigStateEnabled;
} // isWigigEnabled

void LOWIController::readCachedMeasurementsFromDriver ()
{
  if (NULL == mWifiDriver)
  {
    log_debug (TAG, "%s: Failed as no driver available", __FUNCTION__);
    return;
  }
  // Just read it once only if not read already
  if (false == mReadDriverCacheDone)
  {
    LOWIMeasurementResult* res = mWifiDriver->getCacheMeasurements();
    if (NULL == res)
    {
      log_debug (TAG, "%s: No cached measurements", __FUNCTION__);
    }
    else
    {
      mReadDriverCacheDone = true;
      // Cache the results
      log_debug (TAG, "%s: Cache measurements", __FUNCTION__);
      mCacheManager->putInCache(res->scanMeasurements, res->isResultFromLOWILP());

      // Get rid of the allocated memory
      for (unsigned int ii = 0; ii < res->scanMeasurements.getNumOfElements();
            ++ii)
      {
        delete res->scanMeasurements[ii];
      }
      delete res;
    }
  }
}

// Dont Add a pointer in LOWI Capability class,
// as we are not performing deep copy in to the contoller
void LOWIController::getWigigCapabilities()
{
  log_debug (TAG, "%s", __FUNCTION__);
  LOWICapabilities wigigCaps = mWigigDriver->getCapabilities();
  mWigigCaps.supportedCapsWigig = wigigCaps.supportedCapsWigig;
}

// Dont Add a pointer in LOWI Capability class,
// as we are not performing deep copy in to the contoller
void LOWIController:: getWifiCapabilities()
{
   log_debug (TAG, "%s", __FUNCTION__);
   mWifiCaps = mWifiDriver->getCapabilities();
}

void LOWIController::terminateWifiDriver ()
{
  log_debug (TAG, "%s", __FUNCTION__);
  delete mWifiDriver;
  mWifiDriver = NULL;
}

void LOWIController::terminateWigigDriver ()
{
  log_debug (TAG, "%s", __FUNCTION__);
  delete mWigigDriver;
  mWigigDriver = NULL;
}

bool LOWIController::terminateScanResultReceiver ()
{
  bool result = true;
  log_debug (TAG, "%s", __FUNCTION__);

  if (NULL != mDiscoveryScanResultReceiver)
  {
    delete mDiscoveryScanResultReceiver;
    mDiscoveryScanResultReceiver = NULL;
  }

  if (NULL != mRangingScanResultReceiver)
  {
    delete mRangingScanResultReceiver;
    mRangingScanResultReceiver = NULL;
  }

  if (NULL != mBgScanResultReceiver)
  {
    delete mBgScanResultReceiver;
    mBgScanResultReceiver = NULL;
  }

  // HACK - HACK
  if (NULL != mScanRequestSender)
  {
    delete mScanRequestSender;
    mScanRequestSender = NULL;
  }

  return result;
} // terminateScanResultReceiver

void LOWIController::terminateWigigRangingScanResultReceiver ()
{
  log_debug(TAG, "%s", __FUNCTION__);
  delete mWigigRangingScanResultReceiver;
  mWigigRangingScanResultReceiver = NULL;
}

void LOWIController::terminateScheduler()
{
  log_debug(TAG, "%s", __FUNCTION__);
  delete mScheduler;
  mScheduler = NULL;
}

bool LOWIController::createWifiDriver ()
{
  bool result = true;

  // Create the wifi driver
  if (NULL == mWifiDriver)
  {
    mWifiDriver = LOWIWifiDriverInterface::createInstance(m_config, this, this, mCacheManager);
    if (NULL == mWifiDriver)
    {
      log_error (TAG, "%s: create wifi driver - Failed", __FUNCTION__);
      result = false;
    }
    else
    {
      log_debug (TAG, "%s: wifi driver created.", __FUNCTION__);
    }
  }

  return result;
} // createWifiDriver

bool LOWIController::createWigigDriver ()
{
  bool result = false;

  int useWigigDriver = 1; // Enable wigig ranging by default
  m_config->getInt32Default("LOWI_USE_WIGIG_DRIVER", useWigigDriver, useWigigDriver);

  // Create the wigig driver
  if ((NULL == mWigigDriver) && useWigigDriver)
  {
    mWigigDriver = LOWIWifiDriverInterface::createWiGigInstance(m_config, this, this, mCacheManager);
    if (NULL == mWigigDriver)
    {
      log_error (TAG, "%s: create wigig driver - failed", __FUNCTION__);
    }
    else
    {
      log_debug (TAG, "%s: wigig driver created", __FUNCTION__);
      result = true;
    }
  }
  else
  {
    log_debug(TAG, "%s: Wigig feature off in conf file (%d)",
              __FUNCTION__, useWigigDriver);
  }

  return result;
} // createWigigDriver

bool LOWIController::createScanResultReceiver ()
{
  bool result = false;

  log_debug (TAG, "%s: Capabilities: discovery(%d), ranging(%d), bgscan(%d), scanbitmask(0x%x)",
             __FUNCTION__,
             mWifiDriver->getCapabilities().discoveryScanSupported,
             mWifiDriver->getCapabilities().rangingScanSupported,
             mWifiDriver->getCapabilities().bgscanSupported,
             mWifiDriver->getCapabilities().supportedCapablities);

  do
  {
    if((mWifiDriver->getCapabilities().supportedCapablities & LOWI_DISCOVERY_SCAN_SUPPORTED) &&
        (mDiscoveryScanResultReceiver == NULL))
    {
      LOWIDiscoveryScanResultReceiver *receiver = NULL;
      result = createReceiver(receiver, this, mWifiDriver);
      mDiscoveryScanResultReceiver = receiver;
      if (!result)
      {
        break;
      }
    }
    if((mWifiDriver->getCapabilities().supportedCapablities & LOWI_RANGING_SCAN_SUPPORTED) &&
        (mRangingScanResultReceiver == NULL))
    {
      LOWIRangingScanResultReceiver *receiver = NULL;
      result = createReceiver(receiver, this, mWifiDriver);
      mRangingScanResultReceiver = receiver;
      if (!result)
      {
        break;
      }
    }
    result = true;
  }
  while (0);
  return result;
} // createScanResultReceiver

int32 LOWIController::addRequestToAsyncScanRequestList (LOWIRequest* req)
{
  int32 retVal = -2;

  // Check if the Request is Async scan request
  if (LOWIRequest::ASYNC_DISCOVERY_SCAN_RESULTS ==
      req->getRequestType ())
  {
    // Let's use the same max size as for the pending queue
    if (mAsyncScanRequestList.getSize() >= (uint32)mMaxQueueSize)
    {
      log_info (TAG, "%s: List full! Respond busy - req " LOWI_REQINFO_FMT,
                __FUNCTION__, LOWI_REQINFO(req));
      // Respond to the request as LOWI is busy.
      sendErrorResponse (*req, LOWIResponse::SCAN_STATUS_BUSY);
      retVal = -1;
    }
    else
    {
      // Check all the Async scan Requests for validity
      // Also check if the current request exists in the list
      for (List<LOWIRequest *>::Iterator it = mAsyncScanRequestList.begin();
          it != mAsyncScanRequestList.end();)
      {
        int64 timeout = 0;
        LOWIAsyncDiscoveryScanResultRequest* request =
          (LOWIAsyncDiscoveryScanResultRequest*) *it;
        timeout = request->getTimeoutTimestamp();

        log_verbose (TAG, "%s:Timeout = %llu for request " LOWI_REQINFO_FMT " currenttime %llu",
                   __FUNCTION__, timeout, LOWI_REQINFO(request), LOWIUtils::currentTimeMs());

        if (timeout < LOWIUtils::currentTimeMs())
        {
          log_info (TAG, "%s: Request " LOWI_REQINFO_FMT " timeout! Dropping it!",
                    __FUNCTION__, LOWI_REQINFO(request));
          sendErrorResponse (*request, LOWIResponse::SCAN_STATUS_INVALID_REQ);
          it = mAsyncScanRequestList.erase(it);
          delete request;
        }
        else
        {
          // Valid request
          // Check if the request is from the same client
          // as the current request. If it does, remove it from the list, and
          // later, replace it with the new one.
          if (0 == strcmp (req->getRequestOriginator(),
              request->getRequestOriginator()) )
          {
            log_info (TAG, "%s: Delete request " LOWI_REQINFO_FMT "Same originator",
                      __FUNCTION__, LOWI_REQINFO(request));
            it = mAsyncScanRequestList.erase(it);
            delete request;
          }
          else
          {
            // Increment the Iterator
            ++it;
          }
        }
      }
      int64 timeout = 0;
      LOWIAsyncDiscoveryScanResultRequest* new_req =
        (LOWIAsyncDiscoveryScanResultRequest*) req;
      timeout = new_req->getRequestExpiryTime()*1000 +
        LOWIUtils::currentTimeMs();
      new_req->setTimeoutTimestamp(timeout);
      log_debug (TAG, "%s: Add request " LOWI_REQINFO_FMT " timeout(ms) = %lld",
                   __FUNCTION__, LOWI_REQINFO(new_req), timeout);
      mAsyncScanRequestList.add(new_req);
      retVal = 0;
    }
  }
  return retVal;
}

bool LOWIController::sendAsyncScanResponse (LOWIRequest* req,
    LOWIMeasurementResult* meas_result)
{
  bool retVal = false;
  if (0 == mAsyncScanRequestList.getSize())
  {
    log_verbose (TAG, "%s: No request in list", __FUNCTION__);
    return retVal;
  }

  if (NULL != meas_result->request &&
    meas_result->request->getRequestType() != LOWIRequest::DISCOVERY_SCAN)
  {
    log_verbose (TAG, "%s: Not discovery scan or passive listening"
        " result. No response needed", __FUNCTION__);
    return retVal;
  }

  // Iterate over the list and generate responses for all the requests
  // As long as
  // 1. They are still valid
  // 2. The request in the list does not match the incoming request param
  // Also drop the the invalid requests from the list
  for (List<LOWIRequest *>::Iterator it = mAsyncScanRequestList.begin();
      it != mAsyncScanRequestList.end();)
  {
    int64 timeout = 0;
    LOWIAsyncDiscoveryScanResultRequest* asyncReq =
      (LOWIAsyncDiscoveryScanResultRequest*) *it;
    timeout = asyncReq->getTimeoutTimestamp();

    log_verbose (TAG, "%s: Request " LOWI_REQINFO_FMT " Timeout = %lld currentime = %lld",
               __FUNCTION__, LOWI_REQINFO(asyncReq), timeout, LOWIUtils::currentTimeMs());

    if (timeout < LOWIUtils::currentTimeMs())
    {
      log_info (TAG, "%s: Request " LOWI_REQINFO_FMT " timeout! Dropping silently!",
                __FUNCTION__, LOWI_REQINFO(asyncReq));
      it = mAsyncScanRequestList.erase(it);
      delete asyncReq;
    }
    else
    {

       if(NULL == asyncReq->getRequestOriginator())
       {
         it = mAsyncScanRequestList.erase(it);
         delete asyncReq;
         log_error (TAG, "%s: Async request Originator is NULL", __FUNCTION__);
         continue;
       }
       else
       {
         // Valid request
         // Check if the request is from the same client
         // as the current request

         LOWIRequest* discReq = (req ? req : meas_result->request);

         if ((NULL != discReq) && (NULL != discReq->getRequestOriginator()) &&
              (0 == strcmp (discReq->getRequestOriginator(),
                            asyncReq->getRequestOriginator())))
         {
           log_verbose (TAG, "%s: Request " LOWI_REQINFO_FMT " from same client."
                     " No response needed", __FUNCTION__,
                     LOWI_REQINFO(asyncReq));
         }
         else
         {
           log_debug (TAG, "%s: Request " LOWI_REQINFO_FMT " is from a different client.",
                        __FUNCTION__, LOWI_REQINFO(asyncReq));

           // Generate response
           LOWIResponse* resp = generateResponse (*asyncReq, meas_result);
           if (NULL == resp)
           {
             log_error (TAG, "%s:Generate Response - failed", __FUNCTION__);
           }
           else
           {
             mEventDispatcher->sendResponse (resp, asyncReq->getRequestOriginator());
             delete resp;
             retVal = true;
           }
         }
       }
      // Increment the Iterator
      ++it;
    }
  }
  return retVal;
}

bool LOWIController::createScheduler()
{
  bool result = true;

  if (NULL == mScheduler)
  {
    mScheduler = new (std::nothrow)LOWIScheduler(this);
    if (NULL == mScheduler)
    {
      log_error (TAG, "%s:create ranging request scheduler - failed", __FUNCTION__);
      result = false;
    }
  }

  return result;
}

bool LOWIController::createNetLinkSocketReceiver()
{
  bool result = false;

  log_verbose (TAG, "%s", __FUNCTION__);
  // create the netlink socket receiver to receive
  // netlink socket packets.
  if (NULL == mNetlinkSocketReceiver)
  {
    mNetlinkSocketReceiver =
          new (std::nothrow) LOWINetlinkSocketReceiver(this);
    if (NULL == mNetlinkSocketReceiver)
    {
      log_warning (TAG, "%s:Failed", __FUNCTION__);
      result = false;
    }
    else
    {
      if (false == mNetlinkSocketReceiver->init())
      {
        log_warning (TAG, "%s - init failed", __FUNCTION__);
        result = false;
      }
      else
      {
        log_verbose (TAG, "%s - init success", __FUNCTION__);
        result = true;
      }
    }
  }
  return result;
}

LOWIRequest* LOWIController::getCurrReqPtr()
{
  return mCurrentRequest;
}

void LOWIController::setCurrReqPtr(LOWIRequest* r)
{
  mCurrentRequest = r;
}

void LOWIController::processPendingRequests()
{
  // Check all the pending Requests for validity and respond
  // to Requests that can be responded through the data in cache
  for( List<LOWIRequest *>::Iterator it = mPendingRequestQueue.begin();
     it != mPendingRequestQueue.end(); )
  {
    LOWIRequest* const req = *it;
    int64 timeout = 0;
    // Only requests that can be in the pending request queue can be either
    // discovery scan or ranging scan
    if( LOWIRequest::DISCOVERY_SCAN == req->getRequestType () )
    {
      LOWIDiscoveryScanRequest* r = (LOWIDiscoveryScanRequest*) req;
      timeout = r->getTimeoutTimestamp();
    }
    else if( LOWIRequest::RANGING_SCAN == req->getRequestType () )
    {
      LOWIRangingScanRequest* r = (LOWIRangingScanRequest*) req;
      timeout = r->getTimeoutTimestamp();
    }
    log_verbose (TAG, "%s: Request " LOWI_REQINFO_FMT " Timeout = %llu currenttime = %llu",
               __FUNCTION__, LOWI_REQINFO(req), timeout, LOWIUtils::currentTimeMs());

    if( 0 != timeout && timeout < LOWIUtils::currentTimeMs() )
    {
      log_info (TAG, "%s: Request " LOWI_REQINFO_FMT " timeout! Dropping",
                __FUNCTION__, LOWI_REQINFO(req));
      it = mPendingRequestQueue.erase(it);
      delete req;
    }
    else
    {
      // Valid request
      log_debug (TAG, "%s: Request " LOWI_REQINFO_FMT " is valid. Check if can be"
                 " serviced", __FUNCTION__, LOWI_REQINFO(req));
      // Check if the request can be serviced from the cache
      if( 0 == processRequestImmediately(req) )
      {
        log_debug (TAG, "%s: Request " LOWI_REQINFO_FMT " processed from cache!",
                   __FUNCTION__, LOWI_REQINFO(req));

        // Remove the request from the queue and delete it.
        it = mPendingRequestQueue.erase(it);
        delete req;
      }
      else
      {
        // Increment the Iterator
        ++it;
      }
    }
  }
}


TimerCallback* LOWIController::getTimerCallback()
{
  return mTimerCallback;
}

void
TimerCallback::timerCallback(const qc_loc_fw::TimerDataInterface * const data)
{
  // Timer callback
  log_verbose ("TimerCallback", "%s", __FUNCTION__);
  const TimerData * const myData = (const TimerData * const ) data;
  if (NULL != myData)
  {
    log_debug("TimerCallback", "timer id: %d", myData->mTimerId);
    if (NULL != myData->mController)
    {
      // Send the callback to the controller
      myData->mController->timerCallback (myData->mTimerId);
    }
  }
}

bool LOWIController::isWirelessIntfEnabled(LOWILocalMsg *msg)
{
  bool retVal = false;

  do
  {
    if ((NULL == msg) || (NULL == msg->getMeasurementResult()))
    {
      break;
    }

    LOWIMeasurementResult *meas_result = msg->getMeasurementResult();

    log_verbose(TAG, "%s: isWigigResult(%u) mWigigStateEnabled(%u) mWifiStateEnabled(%u)",
                __FUNCTION__, meas_result->isWigigResult, mWigigStateEnabled, mWifiStateEnabled);

    // determine if these are wigig or wifi measurements. if measurements came in
    // while the corresponding driver was "off", we delete the measurements.
    if (true == meas_result->isWigigResult && !mWigigStateEnabled)
    {
      log_debug(TAG, "%s: Results received when wigig off", __FUNCTION__);
      break;
    }
    else if (false == meas_result->isWigigResult && !mWifiStateEnabled)
    {
      log_debug(TAG, "%s: Results received when wifi off", __FUNCTION__);
      break;
    }

    retVal = true;
  } while (0);

  return retVal;
} // isWirelessIntfEnabled

void LOWIController::loadConfigItems()
{
  if (m_config->loaded())
  {

    // Read and set the log level from the config file
    m_config->getInt32Default ("LOWI_LOG_LEVEL", mLogLevel, mLogLevel);

    // Read the cache size and create the cache manager
    m_config->getInt32Default ("LOWI_MAX_NUM_CACHE_RECORDS", mCacheSize, mCacheSize);

    // Read other config values
    m_config->getInt32Default ("LOWI_MAX_OUTSTANDING_REQUEST", mMaxQueueSize,
                               mMaxQueueSize);
    m_config->getInt32Default ("LOWI_FRESH_SCAN_THRESHOLD", mFreshScanThreshold,
                               mFreshScanThreshold);

    log_info (TAG, "%s: Log level = %d, Cache Records = %d,"
               " max queue size = %d, fresh scan threshold = %d",
               __FUNCTION__, mLogLevel, mCacheSize, mMaxQueueSize,
               mFreshScanThreshold);
  }
}

bool LOWIController::ProcessConfigRequest(LOWIConfigRequest* req)
{
  bool retVal = false;
  if (NULL == req)
  {
    log_warning (TAG, "%s: LOWIConfig Request NULL", __FUNCTION__);
    return retVal;
  }
  switch (req->getConfigRequestMode())
  {
  case LOWIConfigRequest::LOG_CONFIG:
  {
    vector <LOWILogInfo>& logVector = req->getLogInfo();
    for (unsigned int ii = 0; ii < logVector.getNumOfElements(); ++ii)
    {
      if (NULL == logVector[ii].tag)
      {
        log_debug (TAG, "%s: Tag is NULL,skip it", __FUNCTION__);
        continue;
      }
      qc_loc_fw::ERROR_LEVEL level = LOWIUtils::to_logLevel(logVector[ii].log_level);
      if (0 != log_set_local_level_for_tag (logVector[ii].tag, level))
      {
        log_debug (TAG, "%s: failed to set log level(%u) for tag %s", __FUNCTION__,
                   level, logVector[ii].tag);
      }
    }
    if (true == req->getGlobalLogFlag())
    {
      qc_loc_fw::ERROR_LEVEL level = LOWIUtils::to_logLevel(req->getGlobalLogLevel());
      log_set_global_level(level);
    }
    retVal = true;
    break;
  }
  case LOWIConfigRequest::LOWI_EXIT:
  {
    log_info(TAG, "%s: Request to kill lowi-server", __FUNCTION__);
    if (isDebugBuild())
    {
      kill();
      retVal = true;
    }
    break;
  }
  default:
  {
    log_debug(TAG, "%s: Unexpected config request %d", __FUNCTION__,
              req->getConfigRequestMode());
    break;
  }
  }
  return retVal;
}
