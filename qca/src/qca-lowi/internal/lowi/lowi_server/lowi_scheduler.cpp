/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Ranging Request Scheduler

GENERAL DESCRIPTION
  This file contains the implementation for the LOWI ranging request scheduler.
  The scheduler optimizes requests based on periodicity, retries, node type, etc.

Copyright (c) 2014-2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <base_util/log.h>
#include <base_util/config_file.h>
#include "common/lowi_utils.h"
#include "inc/lowi_response.h"
#include "inc/lowi_request.h"
#include "lowi_controller.h"
#include "lowi_scheduler.h"
#include "lowi_internal_message.h"
#include "lowi_strings.h"

using namespace qc_loc_fw;

// strings used for debugging purposes
const char* SCAN_STATUS[12] =
{
  "SCAN_STATUS_UNKNOWN",
  "SCAN_STATUS_SUCCESS",
  "SCAN_STATUS_BUSY",
  "SCAN_STATUS_DRIVER_ERROR",
  "SCAN_STATUS_DRIVER_TIMEOUT",
  "SCAN_STATUS_INTERNAL_ERROR",
  "SCAN_STATUS_INVALID_REQ",
  "SCAN_STATUS_NOT_SUPPORTED",
  "SCAN_STATUS_NO_WIFI",
  "SCAN_STATUS_TOO_MANY_REQUESTS",
  "SCAN_STATUS_OUT_OF_MEMORY",
  "SCAN_STATUS_NO_WIGIG"
};

// msg strings used for printing/debugging PREAMBLE from LOWI
const char* PREAMBLE_STR_[4] = {
  "PREAMBLE_LEGACY",
  "PREAMBLE_CCK",
  "PREAMBLE_HT",
  "PREAMBLE_VHT"
};

// msg strings used for printing/debugging RTT type from LOWI
const char* RTT_STR_[4] = {
  "RTT1",
  "RTT2",
  "RTT3",
  "BEST"
};

// msg strings used for printing/debugging wifi node type from LOWI
const char* NODE_STR_[5] = {
  "UNKNOWN",
  "AP",
  "P2P",
  "NAN",
  "STA"
};


// msg strings used for printing/debugging BW type from LOWI
const char* BW_STR_[BW_160MHZ + 1] =
{
  "BW_20",
  "BW_40",
  "BW_80",
  "BW_160"
};

/** strings used for debugging purposes */
static const char* WIFI_NODE_STATE[WIFI_NODE_DONE + 1] =
{
  "WIFI_NODE_MEAS_IN_PROGRESS",
  "WIFI_NODE_READY_FOR_REQ",
  "WIFI_NODE_READY_FOR_RSP",
  "WIFI_NODE_WAITING_FOR_TIMER",
  "WIFI_NODE_DONE"
};

// any nodes in the database whose time2ReqMsec time is within this timer interval will
// be included in the next ranging request
#define INCLUSION_TIME_INTERVAL_MS 200

// definitions used for processing wifi nodes in a scan response
#define LOWER_PERIODIC_CNTR 1
#define LOWER_RETRY_CNTR    1
#define NO_ACTION           0
#define RESET_RETRY_CNTR    0xff

// initial minimum time used in the search for the actual minimum time
#define INITIAL_MIN_TIME 0xDEADBEEF

// initial minimum period used to search for the actual minimum period among the wifi nodes
// in the data base
#define INITIAL_MIN_PERIOD 0xFFFFFFFF

// maximum time in msec that an wifi node would have to wait before going on a request if
// it arrives while a timer is ongoing
#define ACCEPTABLE_WAIT_TIME_MSEC 200

// Enter/Exit debug macros
#define SCHED_ENTER() log_verbose(TAG, "ENTER: %s", __func__);
#define SCHED_EXIT()  log_verbose(TAG, "EXIT: %s", __func__);

const char * const LOWIScheduler::TAG = "LOWIScheduler";
const char * const LOWIScheduler::LOWI_SCHED_ORIGINATOR_TAG = "LOWIRequestOriginator";

LOWIClientInfo::LOWIClientInfo(LOWIRequest *req)
{
  clientReq = req;
  result    = NULL;
  iReq      = NULL;
  log_verbose("LOWIClientInfo", "LOWIClientInfo() ctor: reqid(%u), reqOriginator(%s)",
              clientReq->getRequestId(), clientReq->getRequestOriginator());
}

void LOWIClientInfo::saveIReq(LOWIInternalMessage *iR)
{
  iReq      = iR;
  log_verbose("LOWIClientInfo", "LOWIClientInfo() ctor: reqid(%u), reqOriginator(%s)",
              clientReq->getRequestId(), clientReq->getRequestOriginator());
}

WiFiNodeInfo::WiFiNodeInfo(LOWIPeriodicNodeInfo *n, LOWIRequest *req)
{
  // store the original request the wifi node came in
  origReq      = req;
  // store the specific node information
  nodeInfo     = *n;

  schReqId     = 0;
  rssi         = 0;
  lastRssi     = 0;
  lastBw       = n->bandwidth;
  periodicCntr = ((int32) n->num_measurements < 0) ? 0 : (int32)n->num_measurements;

  // init the retryCntr
  // set to 0 always as retries have moved to FW
  retryCntr = 0;

  // init the state of the wifi node
  nodeState = WIFI_NODE_READY_FOR_REQ;

  // set the time2ReqMsec time based on periodicity
  time2ReqMsec = nodeInfo.periodic ? nodeInfo.meas_period : 0;

  measResult = NULL;
  meas = NULL;
}

LOWIScheduler::LOWIScheduler(LOWIController *lowiController)
{
  log_verbose(TAG, "%s", __FUNCTION__);
  mController           = lowiController;
  mNumPeriodicNodesInDB = 0;
  mSchedulerTimerData   = NULL;
  mCurrTimeoutMsec          = 0;
  mTimerRunning         = false;
  mWigigCurrentRequest  = NULL;
}

LOWIScheduler::~LOWIScheduler()
{
  log_verbose(TAG, "%s", __FUNCTION__);
  delete mSchedulerTimerData;
  mSchedulerTimerData = NULL;
}

bool LOWIScheduler::manageMsg(LOWILocalMsg *msg)
{

  bool retVal = false;

  if( (NULL == msg) )
  {
    log_debug(TAG, "%s: msg NULL", __FUNCTION__);
    return retVal;
  }

  LOWIRequest           *req         = NULL;
  LOWIMeasurementResult *meas_result = NULL;

  // process the message
  if( true == msg->containsRequest() )
  {
    req = msg->getLOWIRequest();

    if(false == isReqOk(req)) return retVal;

    // check if it's a ranging or stop ranging request, otherwise do nothing
    if( (req->getRequestType() == LOWIRequest::PERIODIC_RANGING_SCAN) ||
        (req->getRequestType() == LOWIRequest::RANGING_SCAN)          ||
        (req->getRequestType() == LOWIRequest::CANCEL_RANGING_SCAN) )
    {
      int32 status = manageRequest(req); // manage the request

      if( (-1 == status) || (0 == status) )
      {
        retVal = true; // indicates that the scheduler is managing the request
      }
    }
    else if(req->getRequestType() == LOWIRequest::LOWI_INTERNAL_MESSAGE)
    {
      LOWIInternalMessage *iReq = (LOWIInternalMessage*)req;
      // handle the FTMRR request
      if (LOWIInternalMessage::LOWI_IMSG_FTM_RANGE_REQ == iReq->getInternalMessageType())
      {
        retVal = HandleFTMRangeReq(iReq);
      }
      // handle the LCI request
      else if (LOWIInternalMessage::LOWI_IMSG_LCI_REQ == iReq->getInternalMessageType())
      {
        LOWILCIReqMessage *r = (LOWILCIReqMessage*)iReq;
        retVal = HandleLCIReq(r);
      }
      // handle wigig driver no caps support message
      else if (LOWIInternalMessage::LOWI_IMSG_WIGIG_NO_LOC_CAPS == iReq->getInternalMessageType())
      {
        // The wigig driver does not support location capabilities. Shut down all lowi
        // wigig driver, result receiver, etc, so as to not have idle resources.
        mController->mWigigDriverRttSupported = false;
        mController->terminateWigigRangingScanResultReceiver();
        mController->terminateWigigDriver();
      }
    }
    else
    {
      log_debug(TAG, "%s: Request: %s -- not handled", __FUNCTION__,
                LOWIUtils::to_string(req->getRequestType()));
      retVal = false;
    }
  }
  else
  { // gotta response from the driver
    meas_result = msg->getMeasurementResult();

    if( (NULL !=  meas_result) && (NULL != meas_result->request) && (NULL != mController) )
    {
      // Check if lowi-scheduler originated the request and if the current request matches
      // the request returned in the results. Can either be results coming from the wifi
      // driver or the wigig driver. In either case, process the measurement results.
      if( isSchedulerRequest(meas_result->request)                &&
          ((meas_result->request == mController->getCurrReqPtr()) ||
           (meas_result->request == mWigigCurrentRequest)) )
      {
        log_debug(TAG, "%s: Results for %s -- handled: scanStatus(%s)",
                  __FUNCTION__,
                  LOWIUtils::to_string(meas_result->request->getRequestType()),
                  SCAN_STATUS[meas_result->scanStatus]);

        // check the status of the response and handle accordingly
        switch(meas_result->scanStatus)
        {
          case LOWIResponse::SCAN_STATUS_SUCCESS:
            if (meas_result->request->getRequestType() == LOWIRequest::RANGING_SCAN)
            {
              if (mController->getCacheManager() != NULL) /* making sure we have a valid Cache */
              {
                (mController->getCacheManager())->putInCache(meas_result->scanMeasurements,
                                                       meas_result->isResultFromLOWILP(),
                                                       true);
              }
            }
            manageRangRsp(meas_result);
            break;
          default:
            manageErrRsp(meas_result);
        }

        // for wifi results, reset the request tracking
        // pointer and take care of pending requests
        if(meas_result->request == mController->getCurrReqPtr())
        {
          if( NULL != mController->getCurrReqPtr() )
          {
            log_debug(TAG, "%s: delete current wifi request", __FUNCTION__);
            delete(mController->getCurrReqPtr());
            mController->setCurrReqPtr(NULL);
          }
          // if there are pending requests, this is the time to process them
          mController->processPendingRequests();

          log_verbose(TAG, "%s: issueRequest... wifi", __FUNCTION__);
          mController->issuePendingRequest();
        }

        // for wigig results, reset the request tracking
        // pointer and take care of pending requests
        if(meas_result->request == mWigigCurrentRequest)
        {
          if( NULL != mWigigCurrentRequest )
          {
            log_debug(TAG, "%s: delete current wigig request", __FUNCTION__);
            delete(mWigigCurrentRequest);
            mWigigCurrentRequest = NULL;
          }
          // if there are pending requests, this is the time to process them
          processPendingRequests();

          log_verbose(TAG, "%s: issueRequest wigig...", __FUNCTION__);
          issueRequest();
        }

        delete meas_result;
        retVal = true;
      }
      else
      {
        log_verbose(TAG, "%s: Results -- not handled", __FUNCTION__);
        retVal = false;
      }
    }
    else
    {
      log_debug(TAG, "%s: NULL results or NULL request in results", __FUNCTION__);
      retVal = false;
    }
  }
  return retVal;
}

int32 LOWIScheduler::manageRequest(LOWIRequest *req)
{
  SCHED_ENTER()
  //**********************************************
  // process a periodic ranging scan or AoA request:
  // 1. add wifi nodes to the wifi node data base
  // 2. check for periodic nodes
  // 3. check for NAN nodes and set up NAN request
  // 4. set up a request for all other nodes
  //**********************************************
  if( req->getRequestType() == LOWIRequest::PERIODIC_RANGING_SCAN )
  {
    log_debug(TAG, "%s: Received: PERIODIC_RANGING_SCAN", __FUNCTION__);

    // add to requests that are being managed by the scheduler
    LOWIClientInfo *info = new (std::nothrow)LOWIClientInfo(req);
    if( NULL == info )
    {
      return -1;
    }
    mClients.add(info);

    log_verbose(TAG, "%s: #clients(%u)", __FUNCTION__, mClients.getSize());
    // put wifi nodes from request into data base from where they will be managed
    addPeriodicNodesToDB(req);

    // Check data base for periodic nodes
    log_debug(TAG, "%s: NumPeriodicNodesInDB(%u) DBsize(%u) mTimerRunning(%d)",
              __FUNCTION__, mNumPeriodicNodesInDB, mNodeDataBase.getSize(), mTimerRunning);
    printDataBase();
    // This case occurs when a request that has periodic nodes arrives and a timer is not
    // already running. That means, either timer has never run or it ran but all the
    // periodic nodes were serviced so the timer was killed
    if( mNumPeriodicNodesInDB && (false == mTimerRunning) )
    {
      // calculate the min period among the periodic nodes
      computeTimerPeriod();

      if( 0 != startTimer() )
      {
        log_error(TAG, "%s: set up scheduler timer - failed", __FUNCTION__);
        return -1;
      }
    }
    else if( mNumPeriodicNodesInDB && (true == mTimerRunning) )
    {
      log_verbose(TAG, "%s: adjust scheduler timer", __FUNCTION__);
      // get the time left to expire on the timer and the
      // time that has elapsed since the timer started
      uint32 timeLeft = (uint32)(mTimerStarted + mCurrTimeoutMsec - LOWIUtils::currentTimeMs());
      uint32 timeElaped = (uint32)(LOWIUtils::currentTimeMs() - mTimerStarted);

      // The wifi node can wait until the timer expires if the time left on the timer is
      // less than some acceptable wait time. This would prevent the timer from being
      // preempted when it is "about" to expire.
      if( timeLeft > ACCEPTABLE_WAIT_TIME_MSEC )
      {
        // get the minimum period from those periodic wifi nodes that came in the request
        uint32 newMinTimerPeriod = mCurrTimeoutMsec;
        findNewMinPeriod(newMinTimerPeriod);

        // There is still a possibility that the timer doesn't need to be adjusted if the
        // minimum period found is greater than the time left on the timer. If this is not
        // the case, adjust the timer period
        if( timeLeft > newMinTimerPeriod )
        {
          if( 0 != adjustTimerPeriod(timeElaped, newMinTimerPeriod) )
          {
            log_error(TAG, "%s: adjust timer period - failed", __FUNCTION__);
            return -1;
          }
        }
      }
    }

    // set up the ranging request(s) with nodes that are ready
    setupRequest();

    //*************************************************************************************
    // Handle NAN nodes
    //*************************************************************************************
    // check data base for NAN types
    if( foundNanNodesInDB() )
    {
      setupNanRequest();
    }
    return 0;
  }

  //**************************************************************************************
  // Handle CANCEL_RANGING_SCAN requests
  //**************************************************************************************
  if( req->getRequestType() == LOWIRequest::CANCEL_RANGING_SCAN )
  {
    log_debug(TAG, "%s: Received: CANCEL_RANGING_SCAN", __FUNCTION__);
    processCancelReq(req);
    return 0;
  }

  //**************************************************************************************
  // Handle RANGING_SCAN request that include NAN nodes
  //**************************************************************************************
  // If this is a ranging scan, we need to see if there are NAN nodes in it. If yes,
  // separate them out and send them to the driver. If no, the request can be processed
  // without adding the wifi nodes to the data base.
  if( req->getRequestType() == LOWIRequest::RANGING_SCAN )
  {
    log_debug(TAG, "%s: Received: RANGING_SCAN", __FUNCTION__);

    // check if NAN nodes are included
    if( false == foundNanNodesInReq() )
    {
      // if this is a regular ranging request without NAN nodes, there is
      // no need to add nodes to the data base, just process as before.
      log_debug (TAG, "%s: No NAN nodes in RANGING_SCAN request", __FUNCTION__);
      return 1;
    }
    else
    {
      log_debug (TAG, "%s: Process NAN nodes in RANGING_SCAN request", __FUNCTION__);
    }

    // add to requests that are being managed by the scheduler
    LOWIClientInfo *info = new (std::nothrow)LOWIClientInfo(req);
    if( NULL == info )
    {
      return -1;
    }
    mClients.add(info);

    // there are NAN nodes in this ranging request. Will need to put them in the data
    // base and keep track of them so we can return the appropriate response to the
    // client
    processNanNodes();
  }
  return 0;
} // manageRequest

void LOWIScheduler::addPeriodicNodesToDB(LOWIRequest* req)
{
  SCHED_ENTER()

  LOWIPeriodicRangingScanRequest *perReq = (LOWIPeriodicRangingScanRequest*)req;
  vector<LOWIPeriodicNodeInfo> vec       = perReq->getNodes();

  for(unsigned int ii = 0; ii < vec.getNumOfElements(); ii++)
  {
    LOWIPeriodicNodeInfo *n = (LOWIPeriodicNodeInfo*)&vec[ii];

    WiFiNodeInfo *node = new (std::nothrow)WiFiNodeInfo(n, req);

    if( NULL == node )
    {
      log_error(TAG, "%s: memory allocation failure", __FUNCTION__);
      continue;
    }
    // add node to wifi node data base
    mNodeDataBase.add(node);

    // keep track of the number of periodic nodes being managed
    if( node->nodeInfo.periodic ) mNumPeriodicNodesInDB++;
  }
}

uint32 LOWIScheduler::foundPeriodicNodes()
{
  SCHED_ENTER()

  uint32 cntr = 0;

  for(List<WiFiNodeInfo*>::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it)
  {
    WiFiNodeInfo* info = *it;

    if(info->nodeInfo.periodic)
    {
      ++cntr;
    }
  }
  return cntr;
}

uint32 LOWIScheduler::foundNanNodesInDB()
{
  // todo
  return 0;
}


bool LOWIScheduler::foundNanNodesInReq()
{
  // todo
  return false;
}

void LOWIScheduler::setupNanRequest()
{
  // todo
}

void LOWIScheduler::setupRequest()
{
  vector<LOWINodeInfo> v_rpt; // contains wifi peers
  vector<LOWINodeInfo> v_wigig; // contains wigig peers

  // collect those nodes in the database whose state is WIFI_NODE_READY_FOR_REQ
  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it )
  {
    WiFiNodeInfo *info = *it;

    // pick those wifi nodes that are ready to be requested,
    // separate wifi peers from wigig peers so they go to their respective drivers
    LOWINodeInfo node = (LOWINodeInfo)info->nodeInfo;

    if ( WIFI_NODE_READY_FOR_REQ == info->nodeState &&
         LOWIUtils::isWigigPeer(info->nodeInfo.frequency) )
    {
      v_wigig.push_back(node);
    }
    else if ( WIFI_NODE_READY_FOR_REQ == info->nodeState )
    {
      v_rpt.push_back(node);
    }
  }

  // construct and send the request if we have peers to process
  if(v_rpt.getNumOfElements() > 0 || v_wigig.getNumOfElements() > 0)
  {
    log_debug (TAG, "%s: #nodes in: wifi req(%d), wigig req(%d)",
               __FUNCTION__, v_rpt.getNumOfElements(), v_wigig.getNumOfElements());

    // construct the request for the wifi peers
    if( v_rpt.getNumOfElements() > 0 )
    {
      // generate a scheduler request id for this request
      uint32 reqId = createSchedulerReqId();

      LOWIRangingScanRequest *r = new LOWIRangingScanRequest(reqId, v_rpt, 0);
      if( NULL != r )
      {
        r->setRequestOriginator(LOWI_SCHED_ORIGINATOR_TAG);
        r->setTimeoutTimestamp(0);
        r->setReportType(RTT_REPORT_AGGREGATE);

        // pass the request to the lowi-controller who will either send it right away or
        // put it in the pending queue
        mController->processRequest(r);
        updateNodeInfoInDB(r);
      }
      else
      {
        log_error(TAG, "%s: memory alloc error - wifi ranging request", __FUNCTION__);
      }
    }

    // construct the request for the wigig peers
    if( v_wigig.getNumOfElements() > 0 )
    {
      // generate a scheduler request id for this request
      uint32 reqId = createSchedulerReqId();

      LOWIRangingScanRequest *r = new LOWIRangingScanRequest(reqId, v_wigig, 0);
      if( NULL != r )
      {
        r->setRequestOriginator(LOWI_SCHED_ORIGINATOR_TAG);
        r->setTimeoutTimestamp(0);
        r->setReportType(RTT_REPORT_AGGREGATE);

        // send it right away or put it in the pending queue
        if(0 == processWigigRangRequest(*r))
        {
          updateNodeInfoInDB(r);
        }
        else
        {
          log_debug (TAG, "%s: Process wigig ranging request - failed", __FUNCTION__);
          delete r;
          r = NULL;
        }
      }
      else
      {
        log_error(TAG, "%s: memory alloc error - wigig ranging request", __FUNCTION__);
      }
    }
    log_debug (TAG, "%s: database updated", __FUNCTION__);
    printDataBase();
  }
}

void LOWIScheduler::adjustTimeLeft(uint32 adjustment)
{
  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it )
  {
    WiFiNodeInfo *info = *it;

    if( info->nodeInfo.periodic && (info->nodeState == WIFI_NODE_WAITING_FOR_TIMER) )
    {
      info->time2ReqMsec -= adjustment;
    }
  }
}

void LOWIScheduler::findNewMinPeriod(uint32 &newMinTimerPeriod)
{
  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it )
  {
    WiFiNodeInfo *info = *it;

    if( info->nodeInfo.periodic                    &&    //periodic node
        (info->nodeState == WIFI_NODE_READY_FOR_REQ) &&    // just came in request
        (info->nodeInfo.meas_period < newMinTimerPeriod) ) // it's minimum?
    {
      newMinTimerPeriod = info->nodeInfo.meas_period;
    }
  }
}

int32 LOWIScheduler::adjustTimerPeriod(uint32 timeElaped, uint32 newMinTimerPeriod)
{
  SCHED_ENTER()
  int32 retVal = 0;

  //stop the timer
  mController->removeLocalTimer(mController->getTimerCallback(),
                                mSchedulerTimerData);
  mTimerRunning = false;

  //adjust the periodic nodes in the data base
  adjustTimeLeft(timeElaped);

  //set new timer period
  mCurrTimeoutMsec = newMinTimerPeriod;

  //restart the timer with the new period
  if( 0 != startTimer() )
  {
    log_error(TAG, "%s: Set up scheduler timer - failed", __FUNCTION__);
    retVal = -1;
  }
  return retVal;
}

void LOWIScheduler::computeTimerPeriod( )
{
  SCHED_ENTER()

  // calling this function w/o periodic nodes in the data base is not allowed
  if( 0 == mNumPeriodicNodesInDB ) return;

  uint32 minTime = INITIAL_MIN_TIME;
  uint32 minPeriod = INITIAL_MIN_PERIOD;

  // iterate over the database of nodes, recalculate the time2ReqMsec values
  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it )
  {
    WiFiNodeInfo *info = *it;

    // recalculate the time2ReqMsec values
    if( info->nodeInfo.periodic && (0 != info->periodicCntr) )
    {
      info->time2ReqMsec -= (int32)mCurrTimeoutMsec;
      log_verbose(TAG, "%s: bssid(" LOWI_MACADDR_FMT") stepdown time2ReqMsec(%d)",
                  __FUNCTION__, LOWI_MACADDR(info->nodeInfo.bssid), info->time2ReqMsec);
      if( info->time2ReqMsec <= 0 )
      {
        info->time2ReqMsec = 0;
      }
    }

    // As we iterate over the periodic wifi nodes in the data base, keep track of the
    // minimum time2ReqMsec time, but exclude time2ReqMsec == 0. The minimum time2ReqMsec
    // time will become the next timer period.
    if( 0 != info->time2ReqMsec )
    {
      if( INITIAL_MIN_TIME == minTime )
      {
        minTime = info->time2ReqMsec;
      }
      else
      {
        if( info->time2ReqMsec < (int32)minTime )
        {
          minTime = info->time2ReqMsec;
        }
      }
    }

    // We need to cover the case where we end up with one or more periodic nodes but the
    // time2ReqMsec times are zero; hence, there is not suitable minTime. In that case,
    // keep track of the min period for each node and use that as the next timer period.
    if( info->nodeInfo.meas_period < minPeriod )
    {
      minPeriod = info->nodeInfo.meas_period;
    }
    if( INITIAL_MIN_TIME == minTime )
    {
      minTime = minPeriod;
    }
  }

  // new timeout for scheduler timer
  mCurrTimeoutMsec = minTime;
  log_debug(TAG, "%s: minTime(%d) set mCurrTimeoutMsec same(%d)", __FUNCTION__,
            minTime, mCurrTimeoutMsec);
}

void LOWIScheduler::setNodesToReady()
{
  SCHED_ENTER()
  int cnt = 0;
  // calling this function w/o periodic nodes in the data base is not allowed
  if( 0 == mNumPeriodicNodesInDB ) return;

  // iterate over the database of nodes, look at periodic nodes
  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it )
  {
    WiFiNodeInfo *info = *it;

    // check for periodic nodes that have not been fully serviced
    if( info->nodeInfo.periodic &&
       (0 != info->periodicCntr)  &&
       (info->nodeState = WIFI_NODE_WAITING_FOR_TIMER) )
    {
      // any nodes with time2ReqMsec time < the inclusion period are readied for request
      if( info->time2ReqMsec <= (int32)INCLUSION_TIME_INTERVAL_MS )
      {
        info->nodeState = WIFI_NODE_READY_FOR_REQ;
        log_debug(TAG, "%s: bssid(" LOWI_MACADDR_FMT
                  ") time2ReqMsec(%d) state(%s) setback to orig period(%d)", __FUNCTION__,
                  LOWI_MACADDR(info->nodeInfo.bssid),
                  info->time2ReqMsec,
                  WIFI_NODE_STATE[info->nodeState],
                  info->nodeInfo.meas_period);

        // next time2ReqMsec time for this node is its original period
        info->time2ReqMsec = info->nodeInfo.meas_period;
        ++cnt;
      }
      else
      {
        log_debug(TAG, "%s: bssid(" LOWI_MACADDR_FMT") time2ReqMsec(%d) state(%s)",
                  __FUNCTION__, LOWI_MACADDR(info->nodeInfo.bssid),
                  info->time2ReqMsec, WIFI_NODE_STATE[info->nodeState]);
      }
    }
  }
  log_debug(TAG, "%s: num nodes ready to go(%d)", __FUNCTION__, cnt);
}

int32 LOWIScheduler::startTimer()
{
  SCHED_ENTER()
  int32 result = -1;
  mTimerRunning = false;

  if( NULL == mSchedulerTimerData )
  {
    mSchedulerTimerData =
    new (std::nothrow) TimerData(RANGING_REQUEST_SCHEDULER_TIMER, mController);
  }

  if( NULL != mSchedulerTimerData )
  {
    TimeDiff timeout;
    timeout.reset(true);
    int res = timeout.add_msec(mCurrTimeoutMsec);

    if( !res && (NULL != mController->getTimerCallback()) )
    {
      log_verbose(TAG, "%s: timer running(%11.0f msec)", __FUNCTION__, timeout.get_total_msec());
      mController->setLocalTimer(timeout,
                                 mController->getTimerCallback(),
                                 mSchedulerTimerData);
      mTimerRunning = true;
      mTimerStarted = LOWIUtils::currentTimeMs();
      result = 0;
    }
    else
    {
      log_error(TAG, "%s: set timer(%d) - failed", __FUNCTION__, res);
    }
  }
  else
  {
    log_error(TAG, "%s: create scheduler timer data - failed", __FUNCTION__);
  }

  return result;
}

void LOWIScheduler::timerCallback()
{
  SCHED_ENTER()

  if( mNumPeriodicNodesInDB )
  {
    // calculate the new timer period and restart the timer
    log_verbose (TAG, "%s: renewing the timer", __FUNCTION__);
    computeTimerPeriod();
    setNodesToReady();

    if( 0 != startTimer() )
    {
      log_error(TAG, "%s: set up timer in scheduler - failed", __FUNCTION__);
      return;
    }

    // set up the ranging request(s) with nodes that are ready
    setupRequest();
  }
  else
  {
    log_verbose(TAG, "%s: no more periodic nodes to process", __FUNCTION__);
    if( NULL != mSchedulerTimerData )
    {
      log_debug (TAG, "%s: removing local timer -- (%u)",
                 __FUNCTION__, mNumPeriodicNodesInDB);
      mController->removeLocalTimer(mController->getTimerCallback(),
                                    mSchedulerTimerData);
      mTimerRunning = false;
      mCurrTimeoutMsec = 0;
    }
  }
}

bool LOWIScheduler::isSchedulerRequest(const LOWIRequest *req)
{
  // Can not handle a request if originator is NULL
  if (NULL == req->getRequestOriginator())
  {
    return false;
  }

  uint32 val = strcmp(LOWI_SCHED_ORIGINATOR_TAG,
                      req->getRequestOriginator());
  if( 0 == val )
  {
    return true;
  }
  else
  {
    return false;
  }
}

uint32 LOWIScheduler::createSchedulerReqId()
{
  static uint32 cntr = 0;
  uint32 pid = getpid();

  // take the pid, shift it to the upper 16 bits, and or it with the cntr.
  uint32 reqId = ((pid & 0x0000ffff) << 16) | (++cntr & 0x0000ffff);
  log_verbose(TAG, "%s:create id: pid: %u, cntr: %u", __FUNCTION__, pid, cntr);
  printSchReqId(reqId);
  return reqId;
}

void LOWIScheduler::printSchReqId(uint32 reqId)
{
  uint32 pid = (reqId & 0xffff0000) >> 16;
  uint32 cntr = (reqId & 0x0000ffff);
  char buff[32] = {0};
  snprintf(buff, sizeof(buff), "%u-%u", pid, cntr);
  log_debug(TAG, "schReqId: %s", buff);
}

void LOWIScheduler::updateNodeInfoInDB(LOWIRequest *req)
{
  SCHED_ENTER()
  if(NULL == req)
  {
    return;
  }

  LOWIRangingScanRequest *r = (LOWIRangingScanRequest *)req;
  vector<LOWINodeInfo> v = r->getNodes();

  // find every vector from the request in the wifi node database and update its
  // scheduler request id and the node state
  for(uint32 ii = 0; ii < v.getNumOfElements(); ii++)
  {
    for(List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it)
    {
      WiFiNodeInfo *node = *it;

      if( (WIFI_NODE_READY_FOR_REQ == node->nodeState) &&
          (0 == node->nodeInfo.bssid.compareTo(v[ii].bssid)) )
      {
        node->schReqId = req->getRequestId();
        node->nodeState = WIFI_NODE_MEAS_IN_PROGRESS;
      }
    }
  }
}

void LOWIScheduler::manageRangRsp(LOWIMeasurementResult *measResult)
{
  SCHED_ENTER()
  bool retriesApply;
  bool isPeriodic;
  bool noMeasurements = false;

  log_verbose(TAG, "%s: # wifi nodes in results(%u)", __FUNCTION__,
              measResult->scanMeasurements.getNumOfElements());
  // iterate over the wifi nodes in this set of results
  for(uint32 ii = 0; ii < measResult->scanMeasurements.getNumOfElements(); ii++)
  {
     // get the wifi node to process
     LOWIScanMeasurement *node = measResult->scanMeasurements[ii];

     // ensure wifi node is on DB, if it is do the following:
     // -- retrieve some info
     // -- save measurement result info
     if( !isWiFiNodeInDB(node->bssid, node->rttType, retriesApply, isPeriodic, measResult) ) continue;

     // check if we got any measurements for this wifi node
     // this is what tells us the status of the node response, if got no measurements,
     // the node is elegible to be retried if retries apply to it.
     noMeasurements = (node->measurementsInfo.getNumOfElements() == 0) ? true : false;

     //////////////////////////////////////////////////////////////////////////////////////
     // the following table shows what needs to be checked on each wifi node and
     // the action that needs to be taken.
     //////////////////////////////////////////////////////////////////////////////////////
     // RETRIES | PERIODIC | STATUS | ACTION
     // no      |  yes     |  good  | lower periodic cntr, ready_for_resp
     // no      |  yes     |  bad   | lower periodic cntr, ready_for_resp
     // no      |  no      |  good  | ready_for_resp
     // no      |  no      |  bad   | ready_for_resp
     // yes     |  yes     |  bad   | lower retry cntr , ready_for_req (will change to rsp if retries ran out)
     // yes     |  no      |  bad   | lower retry cntr , ready_for_req (will change to rsp if retries ran out)
     // yes     |  yes     |  good  | lower periodic cntr, reset retry cntr, ready_for_resp
     // yes     |  no      |  good  |                      reset retry cntr, ready_for_resp
     //////////////////////////////////////////////////////////////////////////////////////

     // disable retries logic in scheduler as it has moved down to FW
     // disable periodicity in scheduler as it is not required for m-release
     retriesApply = false;
     isPeriodic   = false;

     if(!retriesApply)
     {
        log_verbose(TAG, "%s: noRetries", __FUNCTION__);
        if(isPeriodic)
        {
          log_verbose(TAG, "%s: periodic node", __FUNCTION__);
          // lower periodic cntr and set new wifi node state
          processNode(node, NO_ACTION, LOWER_PERIODIC_CNTR,
                      WIFI_NODE_READY_FOR_RSP, measResult->scanStatus);
          continue;
        }
        // set new wifi node state
        processNode(node, NO_ACTION, NO_ACTION,
                    WIFI_NODE_READY_FOR_RSP, measResult->scanStatus);
     }
     else
     {
        log_verbose(TAG, "%s: RetriesApply", __FUNCTION__);
        if(noMeasurements)
        {
          log_verbose(TAG, "%s: noMeasurements", __FUNCTION__);
          // lower retry cntr, lower periodic cntr and set new wifi node state
          processNode(node, LOWER_RETRY_CNTR, NO_ACTION,
                      WIFI_NODE_READY_FOR_REQ, measResult->scanStatus);
        }
        else
        { // got measurements
          log_verbose(TAG, "%s: got measurements", __FUNCTION__);
          if(isPeriodic)
          {
            log_verbose(TAG, "%s: periodic node", __FUNCTION__);
            // lower periodic cntr and set new wifi node state
            processNode(node, RESET_RETRY_CNTR, LOWER_PERIODIC_CNTR,
                        WIFI_NODE_READY_FOR_RSP, measResult->scanStatus);
            continue;
          }
          // reset retry cntr and set wifi node state
          processNode(node, RESET_RETRY_CNTR, NO_ACTION,
                      WIFI_NODE_READY_FOR_RSP, measResult->scanStatus);
        }
     }
  }

  // Check if there are nodes ready for response
  if( nodesForRsp() )
  {
    processRangRsp();
  }

  // clean up database, requests, timer, etc.
  cleanUp();

  // if there are retries, this will pick them up.
  log_verbose(TAG, "%s: setupRequest() to pick up retries", __FUNCTION__);
  setupRequest();
}

void LOWIScheduler::manageErrRsp(LOWIMeasurementResult *measResult)
{
  SCHED_ENTER()
  bool retriesApply;
  bool isPeriodic;

  uint32 numNodes = measResult->scanMeasurements.getNumOfElements();

  log_verbose(TAG, "%s: # wifi nodes in results: %u", numNodes, __FUNCTION__);

  // This is the case where the FSM rejected the request.
  // Check the nodes in the request and retry those for which retries apply.
  // Those nodes for which retries do not apply are sent back to the client in a response.
  // Periodic nodes, not yet fully serviced, remain on the database.
  if( !numNodes )
  {
    log_verbose(TAG, "%s: bad rsp and no nodes", __FUNCTION__);
    // get nodes from request
    LOWIRangingScanRequest *r = NULL;
    r = (measResult->request == mController->getCurrReqPtr())  ?
        (LOWIRangingScanRequest *)mController->getCurrReqPtr() : // wifi request
        (LOWIRangingScanRequest *)mWigigCurrentRequest;          // wigig request

    vector<LOWINodeInfo> vec = r->getNodes();

    for( uint32 ii = 0; ii < vec.getNumOfElements(); ii++ )
    {
      LOWINodeInfo n = vec[ii];

      log_debug(TAG, "%s: node from request: " LOWI_MACADDR_FMT, __FUNCTION__,
                LOWI_MACADDR(n.bssid));

      if( !isWiFiNodeInDB(n.bssid, n.rttType, retriesApply, isPeriodic, measResult) ) continue;

      // STATUS | RETRIES | PERIODIC | ACTION
      //  bad   | no      |  yes     | lower periodic cntr, ready_for_resp
      //  bad   | no      |  no      | ready_for_resp
      //  bad   | yes     |  dontcare| lower retry cntr , ready_for_req (will change to rsp if retries ran out)
      //  bad   | yes     |  dontcare| lower retry cntr , ready_for_req (will change to rsp if retries ran out)

      // disable retries logic in scheduler as it has moved down to FW
      // disable periodicity in scheduler as it is not required for m-release
      retriesApply = false;
      isPeriodic   = false;

      if( !retriesApply )
      {
        log_verbose(TAG, "%s: noRetries", __FUNCTION__);
        if( isPeriodic )
        {
          log_verbose(TAG, "%s: periodic node", __FUNCTION__);
          // lower periodic cntr and set new wifi node state
          processNode(n.bssid, NO_ACTION, LOWER_PERIODIC_CNTR,
                      WIFI_NODE_READY_FOR_RSP, measResult->scanStatus);
          continue;
        }
        // set new wifi node state
        processNode(n.bssid, NO_ACTION, NO_ACTION,
                    WIFI_NODE_READY_FOR_RSP, measResult->scanStatus);
      }
      else
      {
        log_verbose(TAG, "%s: RetriesApply", __FUNCTION__);
        // lower retry cntr, lower periodic cntr and set new wifi node state
        processNode(n.bssid, LOWER_RETRY_CNTR, NO_ACTION,
                    WIFI_NODE_READY_FOR_REQ, measResult->scanStatus);
      }
    }

    // Check if there are nodes ready for response
    if( nodesForRsp() )
    {
      processRangRsp();
    }

    // clean up database, requests, timer, etc.
    cleanUp();

    // if there are retries, this will pick them up.
    log_verbose(TAG, "%s: setupRequest() to pick up retries", __FUNCTION__);
    setupRequest();
  }
  else
  {
    log_error(TAG, "%s: Bad rsp with nodes, this should not happen???", __FUNCTION__);
  }
}

void LOWIScheduler::manageErrRsp(LOWIRequest *req, LOWIResponse::eScanStatus scan_status)
{
  SCHED_ENTER()
  bool retriesApply;
  bool isPeriodic;
  vector<uint32> v; // keep track of the reqId for those nodes that are ready for response
  vector<LOWINodeInfo> vec;

  // update the node status prior to processing the error
  updateNodeInfoInDB(req);

  LOWIRangingScanRequest *r = (LOWIRangingScanRequest *)(req);
  vec = r->getNodes();
  log_verbose(TAG, "%s: request not sent to wifi driver. #nodes(%u)", __FUNCTION__,
              vec.getNumOfElements());

  // This is the case where the FSM rejected the request.
  // Check the nodes in the request and retry those for which retries apply.
  // Those nodes for which retries do not apply are sent back to the client in a response.
  // Periodic nodes, not yet fully serviced, remain on the database.
  if( vec.getNumOfElements() )
  {
    for( uint32 ii = 0; ii < vec.getNumOfElements(); ii++ )
    {
      LOWINodeInfo n = vec[ii];

      log_debug(TAG, "%s: node from request: " LOWI_MACADDR_FMT,
                __FUNCTION__, LOWI_MACADDR(n.bssid));

      if( !isWiFiNodeInDB(n.bssid, n.rttType, retriesApply, isPeriodic, req) ) continue;

      // STATUS | RETRIES | PERIODIC | ACTION
      //  bad   | no      |  yes     | lower periodic cntr, ready_for_resp
      //  bad   | no      |  no      | ready_for_resp
      //  bad   | yes     |  dontcare| lower retry cntr , ready_for_req (will change to rsp if retries ran out)
      //  bad   | yes     |  dontcare| lower retry cntr , ready_for_req (will change to rsp if retries ran out)
      if( !retriesApply )
      {
        log_verbose(TAG, "%s: noRetries", __FUNCTION__);
        if( isPeriodic )
        {
          log_verbose(TAG, "%s: periodic node", __FUNCTION__);
          // lower periodic cntr and set new wifi node state
          processNode(n.bssid, NO_ACTION, LOWER_PERIODIC_CNTR, WIFI_NODE_READY_FOR_RSP, scan_status);
          continue;
        }
        // set new wifi node state
        processNode(n.bssid, NO_ACTION, NO_ACTION, WIFI_NODE_READY_FOR_RSP, scan_status);
      }
      else
      {
        log_verbose(TAG, "%s: RetriesApply", __FUNCTION__);
        // lower retry cntr, lower periodic cntr and set new wifi node state
        processNode(n.bssid, LOWER_RETRY_CNTR, NO_ACTION, WIFI_NODE_READY_FOR_REQ, scan_status);
      }
    }

    // Check if there are nodes ready for response
    if( nodesForRsp() )
    {
      processRangRsp();
    }

    // clean up database, requests, timer, etc.
    cleanUp();

    // if there are retries, this will pick them up.
    log_verbose(TAG, "%s: setupRequest() to pick up retries", __FUNCTION__);
    setupRequest();
  }
  else
  {
    log_error(TAG, "%s: Req failed but no nodes, this should not happen???", __FUNCTION__);
  }
}

// find the node as many times as it is in the database...
void LOWIScheduler::processNode(LOWIScanMeasurement *inNode,
                                int32 retry_step,
                                int32 periodic_step,
                                eWiFiNodeState nextState,
                                LOWIResponse::eScanStatus scan_status)
{
  log_verbose(TAG, "%s: retry_step(%u) periodic_step(%u)", __FUNCTION__, retry_step, periodic_step);

  for(List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it)
  {
    WiFiNodeInfo *info = *it;

    // if bssid matches and request id matches, we got a winner.
    // there is a chance that the same node could be on the data base more than once. If
    // that is the case, the state will distinguish them. If they happen to have the same
    // state also, then a response will be sent out for both and the tracking metrics
    // adjusted for both.
    if( (NULL != info->measResult)                           &&
        (0 == info->nodeInfo.bssid.compareTo(inNode->bssid)) &&
        (WIFI_NODE_MEAS_IN_PROGRESS == info->nodeState)      &&
        info->schReqId == info->measResult->request->getRequestId() )
    {
      log_debug(TAG, "%s: " LOWI_MACADDR_FMT,
                __FUNCTION__, LOWI_MACADDR(info->nodeInfo.bssid));

      // handle node state
      info->nodeState = nextState;

      // handle the retry cntr
      if( LOWIResponse::SCAN_STATUS_NO_WIFI == scan_status )
      {
        log_verbose(TAG, "%s: SCAN_STATUS_NO_WIFI no more retries...", __FUNCTION__);
        // we're done retrying this wifi node, respond to client
        info->nodeState = WIFI_NODE_READY_FOR_RSP;
        // reset the retry counter, do not retry
        info->retryCntr = 0;
      }
      else if(retry_step > (int)MAX_RETRIES_PER_MEAS)
      {
        log_verbose(TAG, "%s: reset retries to MAX_RETRIES_PER_MEAS", __FUNCTION__);
        // results were good, reset retry cntr to the top
        info->retryCntr = MAX_RETRIES_PER_MEAS;
      }
      else
      {
        // adjust the retry cntr
        info->retryCntr -= retry_step;
        log_verbose(TAG, "%s: retries left = %d", __FUNCTION__, info->retryCntr);

        // retries exhausted
        if( 0 == info->retryCntr )
        {
          log_verbose(TAG, "%s: no more retries...WIFI_NODE_READY_FOR_RSP", __FUNCTION__);
          // we're done retrying this wifi node, respond to client
          info->nodeState = WIFI_NODE_READY_FOR_RSP;
          if( !info->nodeInfo.periodic )
          {
          // reset the retry counter
            info->retryCntr = info->nodeInfo.num_retries_per_meas;
          }
        }
      }

      // handle the periodic cntr
      if( info->nodeInfo.periodic )
      {
        info->periodicCntr -= periodic_step; // adjust the periodic cntr

        // for those periodic nodes which have retries and for which the retry
        // counter has gone done to zero, their periodic cntr needs to be adjusted
        if( (info->retryCntr == 0) && (info->nodeInfo.num_retries_per_meas > 0) )
        {
          info->periodicCntr -= 1;
          // reset the retry counter
          info->retryCntr = info->nodeInfo.num_retries_per_meas;
        }

        log_verbose(TAG, "%s: periodicCntr left = %d", __FUNCTION__, info->periodicCntr);
      }

      // if the state is WIFI_NODE_READY_FOR_RSP, we gather the request id of the clients
      // so we can put together all the WIFI_NODE_READY_FOR_RSP nodes that go to the same client
      if( WIFI_NODE_READY_FOR_RSP == info->nodeState )
      {
        // if periodic, add measurement number
        if( info->nodeInfo.periodic )
        {
          inNode->measurementNum = info->nodeInfo.num_measurements - info->periodicCntr;
        }

        // store the measurement information for this node for use when it's time
        // to put together a response to the client
        info->meas = inNode;
        addToClientList(info, scan_status);
      }
    } // if
  } // for loop
}

void LOWIScheduler::processNode(LOWIMacAddress bssid,
                                int32 retry_step,
                                int32 periodic_step,
                                eWiFiNodeState nextState,
                                LOWIResponse::eScanStatus scan_status)
{

  for(List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it)
  {
    WiFiNodeInfo *info = *it;

    // There is a chance that the same node could be on the data base more than once. If
    // that is the case, the state will distinguish them. If they happen to have the same
    // state also, then a response will be sent out for both and the tracking metrics
    // adjusted for both.
    if( ( 0 == info->nodeInfo.bssid.compareTo(bssid)) &&
        (WIFI_NODE_MEAS_IN_PROGRESS == info->nodeState))
    {
      log_debug(TAG, "%s: " LOWI_MACADDR_FMT,
                __FUNCTION__, LOWI_MACADDR(info->nodeInfo.bssid));

      // handle node state
      info->nodeState = nextState;

      // handle the retry cntr
      if( LOWIResponse::SCAN_STATUS_NO_WIFI == scan_status )
      {
        log_verbose(TAG, "%s: SCAN_STATUS_NO_WIFI no more retries", __FUNCTION__);
        // we're done retrying this wifi node, respond to client
        info->nodeState = WIFI_NODE_READY_FOR_RSP;
        // reset the retry counter, do not retry
        info->retryCntr = 0;
      }
      else if(retry_step > (int)MAX_RETRIES_PER_MEAS)
      {
        log_verbose(TAG, "%s: reset retries to MAX_RETRIES_PER_MEAS", __FUNCTION__);
        // results were good, reset retry cntr to the top
        info->retryCntr = MAX_RETRIES_PER_MEAS;
      }
      else
      {
        // adjust the retry cntr
        info->retryCntr -= retry_step;
        log_verbose(TAG, "%s: retries left = %d", __FUNCTION__, info->retryCntr);

        if(0 == info->retryCntr)
        {
          log_verbose(TAG, "%s: no more retries...WIFI_NODE_READY_FOR_RSP", __FUNCTION__);
          // we're done retrying this wifi node, respond to client
          info->nodeState = WIFI_NODE_READY_FOR_RSP;
        }
      }

      // handle the periodic cntr
      if( info->nodeInfo.periodic )
      {
        info->periodicCntr -= periodic_step; // adjust the periodic cntr
        // for those periodic nodes which have retries and for which the retry
        // counter has gone done to zero, their periodic cntr needs to be adjusted
        if( (info->retryCntr == 0) && (info->nodeInfo.num_retries_per_meas > 0) )
        {
          info->periodicCntr -= 1;
          // reset the retry counter
          info->retryCntr = MAX_RETRIES_PER_MEAS;
        }
        log_verbose(TAG, "%s: periodicCntr left = %d", __FUNCTION__, info->periodicCntr);
      }

      // if the state is WIFI_NODE_READY_FOR_RSP, and since we're handling an error rsp,
      // we update the meas field for this node in its context structure
      if( WIFI_NODE_READY_FOR_RSP == info->nodeState )
      {
        // Since we're managing an error condition, there are no real rtt measurements for
        // this node. Therefore; fill up the measurement info with the request info but
        // without rtt or rssi measurements in the results. This, along with the scan
        // status will tell the client that this particular wifi node was unsuccessful.
        // In addition, this passes other relevant information about the node to the
        // client, and ensures that LOWI will process the response properly. (i.e. LOWI
        // doesn't process "bad" responses with wifi nodes in them, until now)
        LOWIScanMeasurement *r = new (std::nothrow)LOWIScanMeasurement();
        if( NULL != r )
        {
          r->bssid.setMac(info->nodeInfo.bssid);
          r->frequency = info->nodeInfo.frequency;
          r->isSecure  = false;
          r->type      = info->nodeInfo.nodeType;
          r->rttType   = info->nodeInfo.rttType;
          r->msapInfo  = NULL;
          r->cellPowerLimitdBm = 0;
          info->meas = r; // add it to the database

      // if periodic, add measurement number
          if( info->nodeInfo.periodic )
          {
            r->measurementNum = info->nodeInfo.num_measurements - info->periodicCntr;
          }
        }
        else
        {
            log_error(TAG, "%s: memory allocation failure", __FUNCTION__);
        }

        // store the measurement information for this node for use when it's time
        // to put together a response to the client
        log_verbose(TAG, "%s: adding node to client list", __FUNCTION__, info->periodicCntr);
        addToClientList(info, scan_status);
      }
    } // if
  } // for loop
}

bool LOWIScheduler::isWiFiNodeInDB(LOWIMacAddress bssid,
                                   eRttType rttType,
                                   bool &retries,
                                   bool &periodic,
                                   LOWIMeasurementResult *measResult)
{
  SCHED_ENTER()
  for(List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it)
  {
    WiFiNodeInfo *info = *it;

    if( (0 == info->nodeInfo.bssid.compareTo(bssid)) &&
        (measResult->request->getRequestId() == info->schReqId) &&
        WIFI_NODE_MEAS_IN_PROGRESS == info->nodeState &&
        (rttType == info->nodeInfo.rttType))
    {
      log_verbose (TAG, "%s(1): Found a match: bssid(" LOWI_MACADDR_FMT ") reqId(%u) rttType(%u)",
                   __FUNCTION__, LOWI_MACADDR(bssid), info->schReqId, info->nodeInfo.rttType);
      retries = (info->nodeInfo.num_retries_per_meas > 0);
      periodic = info->nodeInfo.periodic;
      // save the meas_result that this node came in
      info->measResult = measResult;
      return true;
    }
  }
  log_verbose (TAG, "%s(1): Not found: bssid(" LOWI_MACADDR_FMT ") reqId(%u)",
               __FUNCTION__, LOWI_MACADDR(bssid),
               measResult->request->getRequestId());
  return false;
}

bool LOWIScheduler::isWiFiNodeInDB(LOWIMacAddress bssid,
                                   eRttType rttType,
                                   bool &retries,
                                   bool &periodic,
                                   LOWIRequest *req)
{
  SCHED_ENTER()
  for(List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); ++it)
  {
    WiFiNodeInfo *info = *it;
    if( (0 == info->nodeInfo.bssid.compareTo(bssid)) &&
        (req->getRequestId() == info->schReqId) &&
        WIFI_NODE_MEAS_IN_PROGRESS == info->nodeState &&
        rttType == info->nodeInfo.rttType)
    {
      log_verbose (TAG, "%s(2): Found a match: bssid(" LOWI_MACADDR_FMT ") reqId(%u) rttType(%u)",
                   __FUNCTION__, LOWI_MACADDR(bssid), info->schReqId, info->nodeInfo.rttType);
      retries = (info->nodeInfo.num_retries_per_meas > 0);
      periodic = info->nodeInfo.periodic;
      // save the meas_result that this node came in
      info->measResult = NULL;
      return true;
    }
  }
  log_verbose (TAG, "%s(2): Not found: bssid(" LOWI_MACADDR_FMT ") reqId(%u)",
               __FUNCTION__, LOWI_MACADDR(bssid), req->getRequestId());
  return false;
}

void LOWIScheduler::processRangRsp()
{
  SCHED_ENTER()

  // Iterate over the list of client requests and send responses to those clients that
  // have nodes ready for response
  for( List<LOWIClientInfo*>::Iterator it = mClients.begin(); it != mClients.end(); ++it )
  {
    LOWIClientInfo *client = *it;

    if( (client->scanMeasVec.getNumOfElements() > 0) &&
        (NULL != client->clientReq)                  &&
        (NULL != client->result) )
    {
      // check for internal messages
      if (NULL != client->iReq)
      {
        log_verbose(TAG, "%s: internal message detected", __FUNCTION__);
        processInternalMsg(client);
      }
      else
      {
        LOWIMeasurementResult *result = new(std::nothrow) LOWIMeasurementResult;
        if ( NULL != result )
        {
          result->measurementTimestamp = client->result->measurementTimestamp;
          result->scanStatus           = client->result->scanStatus;
          result->scanType             = client->result->scanType;
          result->request              = client->clientReq;
          result->scanMeasurements     = client->scanMeasVec;

          log_debug(TAG, "%s: Create response: status(%s) numBssids(%u) reqId(%u) "
                           "originator(%s) reqType(%u)", __FUNCTION__,
                      SCAN_STATUS[result->scanStatus],
                      result->scanMeasurements.getNumOfElements(),
                      result->request->getRequestId(),
                      result->request->getRequestOriginator(),
                      result->request->getRequestType());

          // send the response to the client
          LOWIRequest *origReq = client->clientReq;
          mController->sendResponse(*origReq, result);
          log_verbose(TAG, "%s: Response sent", __FUNCTION__);
          // clean up any result information
          client->scanMeasVec.flush();
          client->result = NULL;
          delete result;
        }
      }
    }
  }
}

void LOWIScheduler::addToClientList(WiFiNodeInfo *pNode,
                                    LOWIResponse::eScanStatus scan_status)
{
  SCHED_ENTER()
  for( List<LOWIClientInfo*>::Iterator it = mClients.begin(); it != mClients.end(); ++it)
  {
    LOWIClientInfo *client = *it;

    // when the request id and the originator id match, then we have found the
    // correct client to which the measurement should go.
    if((pNode->origReq->getRequestId() == client->clientReq->getRequestId()) &&
       (0 == strcmp(pNode->origReq->getRequestOriginator(),
                    client->clientReq->getRequestOriginator())))
    {
      // store the scan measurement for this node which will go to this client in the rsp
      client->scanMeasVec.push_back(pNode->meas);
      // store measurement information to be used in the rsp to the client
      client->result = pNode->measResult;

      // This case arises when a request fails to be sent to the wifi driver and the
      // client needs to be notified. Since the measurement result can't be null, we
      // create a fake one here.
      if( NULL == client->result )
      {
        client->result = new (std::nothrow) LOWIMeasurementResult;
        if( NULL != client->result )
        {
          client->result->measurementTimestamp = LOWIUtils::currentTimeMs();
          client->result->scanStatus           = scan_status;
          client->result->scanType             = LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
          client->result->request              = client->clientReq;
        }
        else
        {
          log_error(TAG, "%s: memory allocation failure", __FUNCTION__);
        }
      }
    }
  }
}

void LOWIScheduler::dataBaseCleanup()
{
  SCHED_ENTER()

  if(mNodeDataBase.getSize() == 0)
  {
    log_debug(TAG, "%s:Empty.nothing to clean up", __FUNCTION__);
    return;
  }

  log_debug(TAG, "%s:Status before cleanup", __FUNCTION__);
  printDataBase();

  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); )
  {
    WiFiNodeInfo *info = *it;

    LOWIPeriodicRangingScanRequest* r = (LOWIPeriodicRangingScanRequest*)info->origReq;
    int64 timeout = r->getTimeoutTimestamp();

    // remove nodes that have "expired" per their own timeout timestamp
    if( 0 != timeout && (timeout < LOWIUtils::currentTimeMs()) )
    {
      delete info;
      it = mNodeDataBase.erase(it);
      continue;
    }
    else
    {
      // for periodic nodes, check to see if the periodic counter has been exhausted
      if( info->nodeInfo.periodic )
      {
        if( 0 == info->periodicCntr )
        {
          log_debug(TAG, "Periodic node fully serviced: " LOWI_MACADDR_FMT,
                   LOWI_MACADDR(info->nodeInfo.bssid));

          delete info;
          it = mNodeDataBase.erase(it); // remove the wifi node from database
          mNumPeriodicNodesInDB--;     // adjust the periodic node count
        }
        else
        {
          // periodic node still valid, reset state if it's not on a retry mode;
          // A node that is  going to be retried, would have state
          // WIFI_NODE_READY_FOR_REQ when it gets here.  That node would not wait
          // for teh timer but would be requested right away
          if( info->nodeState != WIFI_NODE_READY_FOR_REQ )
          {
          info->nodeState = WIFI_NODE_WAITING_FOR_TIMER;
          }
          ++it;
        }
      }
      else
      { // This is a one-shot node
        // At this point, a one-shot node that is WIFI_NODE_READY_FOR_RSP means that the
        // response already went out to the client. The wifi node can be removed.
        // If the node is to be retried, the state would be WIFI_NODE_READY_FOR_REQ
        // instead.
        if( WIFI_NODE_READY_FOR_RSP == info->nodeState )
        {
          log_debug(TAG, "One-shot node fully serviced: " LOWI_MACADDR_FMT,
                   LOWI_MACADDR(info->nodeInfo.bssid));

          delete info;
          it = mNodeDataBase.erase(it);
        }
        else
        {
          ++it;
        }
      }
    }
  }

  log_debug(TAG, "%s:Status after cleanup", __FUNCTION__);
  printDataBase();
}

void LOWIScheduler::deleteClientInfo()
{
  SCHED_ENTER()
  bool reqStillUsed = false;

  // iterate over the client information list
  for( List<LOWIClientInfo*>::Iterator it = mClients.begin(); it != mClients.end(); )
  {
    LOWIClientInfo *clInfo = *it;
    reqStillUsed = false;

    // for each client request, iterate over the node database checking if any node
    // still is using the request
    for( List<WiFiNodeInfo* >::Iterator iter = mNodeDataBase.begin(); iter != mNodeDataBase.end(); )
    {
      WiFiNodeInfo *node = *iter;
      if( clInfo->clientReq->getRequestId() == node->origReq->getRequestId() )
      {
        reqStillUsed = true;
        break;
      }
      else
      {
        ++iter;
      }
    }

    // no WiFiNode in the data base matched this request which means that all nodes
    // that came in this request have been serviced, hence, free the memory
    if( false == reqStillUsed )
    {
      delete clInfo->iReq;

      if ( NULL != clInfo->clientReq)
      {
        log_debug(TAG, "%s: deleting reqId(%u) originator(%s), reqType(%s)",__FUNCTION__,
                 clInfo->clientReq->getRequestId(),
                 clInfo->clientReq->getRequestOriginator(),
                 LOWIUtils::to_string(clInfo->clientReq->getRequestType()));
        delete clInfo->clientReq;
      }

      delete clInfo;  // remove the client information (request, etc).
      it = mClients.erase(it); // remove it from the client info list
    }
    else
    {
        ++it;
    }
  } //for
}

void LOWIScheduler::processCancelReq(LOWIRequest *req)
{
  SCHED_ENTER()

  if( mNodeDataBase.getSize() == 0 )
  {
    log_debug(TAG, "%s: Database empty.Nothing to cancel", __FUNCTION__);
    return;
  }

  LOWICancelRangingScanRequest *r = (LOWICancelRangingScanRequest*)req;
  vector<LOWIMacAddress> v        = r->getBssids();

  // check if this wifinode to cancel is in the data base
  for( uint32 ii = 0; ii < v.getNumOfElements(); ii++ )
  {
    bool found = false;

  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); )
  {
    WiFiNodeInfo *info = *it;

    // compare request originators
    uint32 val = strcmp(r->getRequestOriginator(),
                        info->origReq->getRequestOriginator());

      if( info->nodeInfo.periodic && (0 == info->nodeInfo.bssid.compareTo(v[ii])) && !val )
      {
        // cancelling a periodic node
        log_debug(TAG, "%s: Periodic node cancelled: " LOWI_MACADDR_FMT, __FUNCTION__,
                  LOWI_MACADDR(info->nodeInfo.bssid));
        mNumPeriodicNodesInDB--; // adjust the periodic node count
        delete info;
        it = mNodeDataBase.erase(it);
        found = true;
        break;
      }
      else if( 0 == info->nodeInfo.bssid.compareTo(v[ii]) && !val )
      {
        // cancelling a one-shot node
        log_debug(TAG, "%s: One-shot node cancelled: " LOWI_MACADDR_FMT, __FUNCTION__,
                  LOWI_MACADDR(info->nodeInfo.bssid));
        delete info;
        it = mNodeDataBase.erase(it);
        found = true;
        break;
      }
      else
      {
        ++it; // next node in data base
      }
    }

    if( false == found )
    {
      log_verbose(TAG, "%s: Node not found: " LOWI_MACADDR_FMT, __FUNCTION__,
                  LOWI_MACADDR(v[ii]));
    }
  }
} // processCancelReq

void LOWIScheduler::cancelCurrentRequest()
{
  if (NULL != mWigigCurrentRequest)
  {
    log_debug (TAG, "%s: Wigig disabled, Send error for current request", __FUNCTION__);
    mController->sendErrorResponse(*mWigigCurrentRequest, LOWIResponse::SCAN_STATUS_NO_WIGIG);
    delete mWigigCurrentRequest;
    mWigigCurrentRequest = NULL;
    // cancel any pending requests
    issueRequest();
  }
}

void LOWIScheduler::printDataBase()
{
  char header[256];
  char line[256];

  log_debug(TAG,"****************************** WiFiNode Database *****************************************************************************************");
  log_debug(TAG,"Num of remaining nodes: %u", mNodeDataBase.getSize());
  snprintf(header, sizeof(header), "%-17s %-4s %-5s %-5s %-6s %-4s %-4s %-12s %-7s %-7s %-7s %-7s %-10s %-10s %-27s\n", "BSSID", "Freq", "nodeT", "rttT", "BW", "pkts", "cont", "period", "numMeas", "perCntr", "retries", "retCntr", "ReqId", "schId", "nodeState");
  log_debug(TAG,"%s", header);
  for( List<WiFiNodeInfo* >::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end(); )
  {
    WiFiNodeInfo *node = *it;
    snprintf(line, sizeof(line), LOWI_MACADDR_FMT " %-4u %-5s %-5s %-6s %-4u %-4u %-12u %-7u %-7d %-7u %-7d %-10u %-10u %-27s\n",
              LOWI_MACADDR(node->nodeInfo.bssid),
              node->nodeInfo.frequency,
              NODE_STR_[node->nodeInfo.nodeType],
              RTT_STR_[node->nodeInfo.rttType],
              BW_STR_[node->lastBw],
              node->nodeInfo.num_pkts_per_meas,
              node->nodeInfo.periodic,
              node->nodeInfo.meas_period,
              node->nodeInfo.num_measurements,
              node->periodicCntr,
              node->nodeInfo.num_retries_per_meas,
              node->retryCntr,
              node->origReq->getRequestId(),
              node->schReqId,
              WIFI_NODE_STATE[node->nodeState]);
    log_debug(TAG,"%s", line);

    ++it;
  }
  log_debug(TAG,"******************************************************************************************************************************************");
} // printDataBase

bool LOWIScheduler::isReqOk(LOWIRequest* req)
{
  if(NULL == req)
  {
    log_debug(TAG, "%s: Request NULL", __FUNCTION__);
    return false;
  }
  else if(req->getRequestType() > LOWIRequest::LOWI_INTERNAL_MESSAGE)
  {
    log_debug(TAG, "%s: Unknown request type(%u)", __FUNCTION__, req->getRequestType());
    return false;
  }
  else
  {
    return true;
  }
}

void LOWIScheduler::cleanUp()
{
  SCHED_ENTER()
  // Now that responses have been sent, remove the nodes that
  // have been fully serviced or have expired
  dataBaseCleanup();
  log_debug (TAG, "%s: NumPeriodicNodesInDB left: %u", __FUNCTION__, mNumPeriodicNodesInDB);

  // "kill" the timer if there aren't any more periodic nodes to service
  if( (0 == mNumPeriodicNodesInDB) && mTimerRunning )
  {
    if( NULL != mSchedulerTimerData )
    {
      log_debug (TAG, "%s: remove local timer", __FUNCTION__);
      mController->removeLocalTimer(mController->getTimerCallback(),
                                    mSchedulerTimerData);
      mTimerRunning = false;
      mCurrTimeoutMsec = 0;
    }
  }

  // remove any client requests that are no longer valid
  deleteClientInfo();
}

bool LOWIScheduler::nodesForRsp()
{
  SCHED_ENTER()
  for( List<LOWIClientInfo*>::Iterator it = mClients.begin(); it != mClients.end(); ++it)
  {
    LOWIClientInfo *client = *it;
    if( client->scanMeasVec.getNumOfElements() > 0 )
    {
      log_debug(TAG, "%s: # nodes for this client(%u)", __FUNCTION__,
                  client->scanMeasVec.getNumOfElements());
      return true;
    }
  }
  log_verbose(TAG, "%s: no nodes for rsp", __FUNCTION__);
  return false;
}

void LOWIScheduler::saveIReq(LOWIRequest *req, LOWIInternalMessage *iReq)
{
  // Iterate over the list of client requests and find the matching request
  for( List<LOWIClientInfo*>::Iterator it = mClients.begin(); it != mClients.end(); ++it )
  {
    LOWIClientInfo *client = *it;

    // requests are equal if they have the same request id
    if ( client->clientReq->getRequestId() == req->getRequestId() )
    {
      // this request is an internal message
      client->saveIReq(iReq);
    }
  }
}

uint32 LOWIScheduler::calculateRangeForFTMRR(vector <LOWIMeasurementInfo *> &measInfo)
{
  uint32 range  = 0;
  int32 rttSum  = 0;
  int32 rttMean = 0;

  if ( measInfo.getNumOfElements() > 0 )
  {
    for (uint32 ii = 0; ii < measInfo.getNumOfElements(); ++ii)
    {
      rttSum += measInfo[ii]->rtt_ps;
    }

    rttMean = rttSum/measInfo.getNumOfElements();

    range = uint32((float)rttMean * RTT_DIST_CONST_PS / FTMRR_RANGE_UNITS);
  }
  return range;
}

void LOWIScheduler::processInternalMsg(LOWIClientInfo *client)
{
  if ( NULL == client )
  {
    return;
  }

  // find what type of internal message it is and process it.
  if ( LOWIInternalMessage::LOWI_IMSG_FTM_RANGE_REQ == client->iReq->getInternalMessageType() )
  {
    log_verbose(TAG, "%s: FTMRR message detected", __FUNCTION__);
    vector<LOWIRangeEntry> vSuccess;
    vector<LOWIErrEntry> vErr;

    // process the node info
    // go through all the APs in the client list
    for (uint32 ii = 0; ii < client->scanMeasVec.getNumOfElements(); ii++)
    {
      if ( client->scanMeasVec[ii]->targetStatus ==
           LOWIScanMeasurement::LOWI_TARGET_STATUS_SUCCESS )
      {
        LOWIRangeEntry entry;
        entry.measStartTime = (uint32)client->scanMeasVec[ii]->rttMeasTimeStamp;
        entry.bssid = client->scanMeasVec[ii]->bssid;
        entry.range = calculateRangeForFTMRR(client->scanMeasVec[ii]->measurementsInfo);
        entry.maxErrRange = 0x0;
        entry.reserved    = 0x0;
        log_verbose(TAG, "%s: bssid(" LOWI_MACADDR_FMT ") range(%u) measStartTime(%u) maxErrRange(%u)",
                    __FUNCTION__,
                    LOWI_MACADDR(entry.bssid), entry.range, entry.measStartTime, entry.maxErrRange);
        vSuccess.push_back(entry);
      }
      else
      {
        LOWIErrEntry entry;
        switch ( client->scanMeasVec[ii]->targetStatus )
        {
          case LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_TARGET_BUSY_TRY_LATER:
            {
              entry.errCode = REQ_FAILED_AT_AP;
            }
            break;
          case LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_TARGET_NOT_CAPABLE:
            {
              entry.errCode = REQ_INCAPABLE_AP;
            }
            break;
          default:
            {
              entry.errCode = TX_FAIL;
            }
            break;
        }
        entry.measStartTime = (uint32)client->scanMeasVec[ii]->rttMeasTimeStamp;
        entry.bssid   = client->scanMeasVec[ii]->bssid;
        entry.errCode = qc_loc_fw::TX_FAIL;
        log_verbose(TAG, "%s: bssid(" LOWI_MACADDR_FMT ") errCode(%d) measStartTime(%u)",
                    __FUNCTION__,
                    LOWI_MACADDR(entry.bssid), entry.errCode, entry.measStartTime);
        vErr.push_back(entry);
      }
    }
    // create the request that will send the FTMRR report to the driver
    LOWIFTMRangeReqMessage *re = (LOWIFTMRangeReqMessage *)client->iReq;
    RadioMeasReqParams params = re->getRadioMeasReqParams();
    LOWIFTMRangeRprtMessage *r =
    new (std::nothrow) LOWIFTMRangeRprtMessage(createSchedulerReqId(),
                                               params,
                                               vSuccess,
                                               vErr, TAG);
    if ( NULL != r )
    {
      r->setRequestOriginator("Scheduler");
      // pass the request to the lowi-controller who will either send it right away or
      // put it in the pending queue
      mController->processRequest(r);
    }
  }
} // processInternalMsg

void LOWIScheduler::getRangingInfoFromRequest(vector<LOWIPeriodicNodeInfo> &v,
                                              vector<LOWIPeriodicNodeInfo> &vNodes)
{
  for (uint32 ii=0; ii < v.getNumOfElements(); ++ii)
  {
    LOWIScanMeasurement scanMeas;
    LOWIPeriodicNodeInfo n;
    n.frequency         = v[ii].frequency;
    n.band_center_freq1 = v[ii].band_center_freq1;
    n.band_center_freq2 = v[ii].band_center_freq2;
    n.bandwidth         = v[ii].bandwidth;
    n.bssid             = v[ii].bssid;
    n.periodic          = 0;
    n.preamble          = v[ii].preamble;
    n.rttType           = v[ii].rttType;
    n.num_pkts_per_meas = 5;
    FTM_SET_ASAP(n.ftmRangingParameters); // set ASAP to 1 by default
    vNodes.push_back(n);
    log_debug(TAG, "%s: " LOWI_MACADDR_FMT " freq(%u) bcf1(%u) bcf2(%u)",
              __FUNCTION__, LOWI_MACADDR(n.bssid),
              n.frequency, n.band_center_freq1, n.band_center_freq2);
  }
}

bool LOWIScheduler::HandleFTMRangeReq(LOWIInternalMessage *iReq)
{
  bool retVal = false;

  if (NULL != iReq)
  {
    // convert the request into a regular LOWIRequest so
    // that it gets processed with existing functions
    LOWIFTMRangeReqMessage *ftmrrMsg = (LOWIFTMRangeReqMessage *)iReq;

    // request id provided by the scheduler
    uint32 reqId = createSchedulerReqId();

    // Configure the node vector based on request.
    vector<LOWIPeriodicNodeInfo> vNodes;
    getRangingInfoFromRequest(ftmrrMsg->getNodes(), vNodes);

    // create the periodic scan request
    LOWIPeriodicRangingScanRequest *r =
        new(std::nothrow) LOWIPeriodicRangingScanRequest(reqId, vNodes, 0);
    if ( NULL != r )
    {
      r->setRequestOriginator(LOWI_SCHED_ORIGINATOR_TAG);
      r->setTimeoutTimestamp(0);
      r->setReportType(RTT_REPORT_AGGREGATE);

      // manage the request
      int32 status = manageRequest(r);

      if ( 0 == status )
      {
        // the scheduler is managing the request
        retVal = true;
        // , the results will be placed in the client's list
        // results struct. From there they can easily be processed
        // by looking at the iReq flag of the client in the client list.

        // Find the client in the client list and save the internal message along with
        // the request created by the scheduler to carry out the FTMs. This way when
        // the response comes back, the APs that need to go on an FTMRR Report can be
        // identified.
        saveIReq(r, iReq);
      }
      else if ( -1 == status )
      {
        // scheduler was managing the request, but something went wrong.
        // set this flag so the upper layer will discard the local message.
        retVal = true;
      }
    }
  }

  return retVal;
} // HandleFTMRangeReq

void LOWIScheduler::loadSydneyOperaHouseLCI(LOWILCIRprtInfo& lciInfo)
{

   // for now, provide fixed coordinates for the LCI Field
    double latitude  = -33.8570095; // degrees
    double longitude = 151.2152005; // degrees
    double altitude  = 11.2;        // meters

    lciInfo.lciParams.latitude       = encodeLatLon(latitude);
    lciInfo.lciParams.longitude      = encodeLatLon(longitude);
    lciInfo.lciParams.altitude       = encodeAltitude(altitude);
    lciInfo.lciParams.latitudeUnc    = 18;
    lciInfo.lciParams.longitudeUnc   = 18;
    lciInfo.lciParams.altitudeType   = 1;
    lciInfo.lciParams.altitudeUnc    = 15;
    lciInfo.lciParams.datum          = 1;
    lciInfo.lciParams.regLocAgree    = 0;
    lciInfo.lciParams.regLocDSE      = 0;
    lciInfo.lciParams.dependentSTA   = 0;
    lciInfo.lciParams.version        = 1;
    lciInfo.lciParams.lciInfoIsKnown = true;
    log_verbose(TAG, "%s: latitudeIn(%11.7f degrees) latitude encoded(0x%l02x) "
                     "longitudeIn(%11.7f degrees) longitude encoded(0x%l02x) "
                     "altitudeIn(%11.2f degrees) altitude encoded(0x%02x)",
                __FUNCTION__, latitude, lciInfo.lciParams.latitude, longitude,
                lciInfo.lciParams.longitude, altitude, lciInfo.lciParams.altitude);

    // Z subelement info
    lciInfo.zSubElem.staFloorInfo.expectedToMove = 0;
    lciInfo.zSubElem.staFloorInfo.floorNum       = LOWI_UNKNOWN_FLOOR;
    lciInfo.zSubElem.staHeightAboveFloor         = 0;
    lciInfo.zSubElem.staHeightAboveFloorUncert   = 0;

    // Usage rules/policy params
    lciInfo.usageRules.retranmissionAllowed = 0;
    lciInfo.usageRules.retentionExpires     = 0;
    lciInfo.usageRules.staLocPolicy         = 0;
}

void LOWIScheduler::loadUnknownLCI(LOWILCIRprtInfo& lciInfo)
{
  memset(&lciInfo, 0, sizeof(LOWILCIRprtInfo));
  lciInfo.lciParams.lciInfoIsKnown = false;
}

bool LOWIScheduler::HandleLCIReq(LOWILCIReqMessage *r)
{
  SCHED_ENTER()
  bool retVal = false;
  do
  {
    if ( r == NULL )
    {
      log_error(TAG, "%s: NULL request", __FUNCTION__);
      break;
    }

    // gather all the LCI information needed for the report
    LOWILCIRprtInfo lciInfo;

    /** Load Unknown LCI - For now until we get clarification on
     *  privacy rules LOWI will send out an unknown LCI for Where
     *  are you requests from connected Access Points.
    */
    loadUnknownLCI(lciInfo);

    // create the request that will send the LCI report to the driver
    RadioMeasReqParams params = r->getRadioMeasReqParams();
    LOWILCIRprtMessage *req =
      new (std::nothrow) LOWILCIRprtMessage(createSchedulerReqId(), params, lciInfo, TAG);
    if ( NULL != req )
    {
      // pass the request to the lowi-controller who will either
      // send it right away or put it in the pending queue
      mController->processRequest(req);
    }

    retVal = true;
  } while (0);

  return retVal;
} // HandleLCIReq

void LOWIScheduler::processNanNodes()
{
  // todo
}

LOWIResponse::eScanStatus LOWIScheduler::requestMeasurements(LOWIRequest *req)
{
  LOWIResponse::eScanStatus retVal = LOWIResponse::SCAN_STATUS_INTERNAL_ERROR;

  log_verbose(TAG, "%s -- request type(%s)", __FUNCTION__,
              (req ? LOWIUtils::to_string(req->getRequestType()) : "NULL"));

  do
  {
    if( false == mController->isWigigEnabled() )
    {
      log_warning(TAG, "%s -- wigig not enabled.", __FUNCTION__);
      // wigig is not enabled, no need to issue the request
      retVal = (NULL == req) ? LOWIResponse::SCAN_STATUS_SUCCESS :
                               LOWIResponse::SCAN_STATUS_NO_WIGIG;
      break;
    }

    if( NULL == mController->mWigigDriver )
    {
      // Can not continue without the driver to service the request
      log_debug(TAG, "%s -- Wigig driver not available", __FUNCTION__);
      retVal = LOWIResponse::SCAN_STATUS_NOT_SUPPORTED;
      break;
    }

    // Send request to ranging scan result receiver which will send it to the
    // lowi driver which in turn will send it to the FSM ...
    if( NULL != req                                          &&
        NULL != mController->mWigigRangingScanResultReceiver &&
        true == mController->mWigigRangingScanResultReceiver->execute(req) )
    {
      retVal = LOWIResponse::SCAN_STATUS_SUCCESS;
    }
  } while(0);
  return retVal;
} // requestMeasurements

int LOWIScheduler::processWigigRangRequest(LOWIRequest &req)
{
  int retVal = -1;

  LOWIRequest *request = &req;

  // Check if there is any current request executing
  if ( NULL == mWigigCurrentRequest )
  {
    log_debug(TAG, "%s, No request currently executing", __FUNCTION__);
    // No current request
    // Make the request a current request and issue the request
    LOWIResponse::eScanStatus req_status = requestMeasurements(request);
    if ( LOWIResponse::SCAN_STATUS_SUCCESS == req_status )
    {
      mWigigCurrentRequest = request;
      log_info(TAG, "%s: Request " LOWI_REQINFO_FMT " sent to wigig driver",
                __FUNCTION__, LOWI_REQINFO(mWigigCurrentRequest));
      retVal = 0;
    }
    else
    {
      log_warning(TAG, "%s: request " LOWI_REQINFO_FMT " sent to wigig driver - failed, status(%s)",
                  __FUNCTION__, LOWI_REQINFO(request), LOWI_TO_STRING(req_status, SCAN_STATUS));

      // generate the appropriate error response to the clients
      manageErrRsp(request, req_status);
    }
  }
  else
  {
    // Check if the pending Q is full and respond
    if ( mWigigRequestQueue.getSize() >= (uint32)mController->mMaxQueueSize )
    {
      log_debug(TAG, "%s: Wigig pending Q full! Respond busy!", __FUNCTION__);
      // Respond to the request as LOWI is busy.
      mController->sendErrorResponse(*request, LOWIResponse::SCAN_STATUS_BUSY);
    }
    else
    {
      log_debug(TAG, "%s: Queue Request" LOWI_REQINFO_FMT, __FUNCTION__, LOWI_REQINFO(request));
      // Already a Request is executing
      // Queue the request, just received
      mWigigRequestQueue.push(request);
      retVal = 0;
    }
  }
  return retVal;
} // processWigigRangRequest

void LOWIScheduler::processPendingRequests()
{
  // Check all the pending requests for validity and respond
  // to requests that can be responded through the data in cache
  for( List<LOWIRequest *>::Iterator it = mWigigRequestQueue.begin();
     it != mWigigRequestQueue.end(); )
  {
    LOWIRequest* const req = *it;
    LOWIRangingScanRequest* r = (LOWIRangingScanRequest*) req;
    int64 timeout = r->getTimeoutTimestamp();
    log_debug (TAG, "Request Timeout(%" PRId64")", timeout);

    if( 0 != timeout && timeout < LOWIUtils::currentTimeMs() )
    {
      log_info (TAG, "%s:Request " LOWI_REQINFO_FMT " timeout! Dropping it",
                __FUNCTION__, LOWI_REQINFO(r));
      it = mWigigRequestQueue.erase(it);
      delete req;
    }
    else
    {
      log_debug (TAG, "%s:Request " LOWI_REQINFO_FMT " is still valid", __FUNCTION__, LOWI_REQINFO(r));
      ++it;
    }
  }
} // processPendingRequests

void LOWIScheduler::issueRequest()
{
  // if a request is currently being serviced, don't do anything
  if (NULL != mWigigCurrentRequest)
  {
    log_info (TAG, "%s: Current request " LOWI_REQINFO_FMT " still pending",
              __FUNCTION__, LOWI_REQINFO(mWigigCurrentRequest));
    return;
  }

  // No pending requests, issue a new request
  if( 0 != mWigigRequestQueue.getSize() )
  {
    // Loop through all the pending request with the intention to just issue
    // one request. If the request is unsuccessful, issue an error response
    // and then pick up the next request.
    for( List<LOWIRequest *>::Iterator it = mWigigRequestQueue.begin();
         it != mWigigRequestQueue.end();)
    {
      mWigigCurrentRequest = *it;
      it = mWigigRequestQueue.erase(it);

      log_debug(TAG, "%s: Pending request retrieved" LOWI_REQINFO_FMT,
                __FUNCTION__, LOWI_REQINFO(mWigigCurrentRequest));
      // Send the request to wigig driver.
      LOWIResponse::eScanStatus req_status = requestMeasurements(mWigigCurrentRequest);
      if( LOWIResponse::SCAN_STATUS_SUCCESS == req_status )
      {
        log_debug(TAG, "%s: Request " LOWI_REQINFO_FMT "sent to wigig driver",
                  __FUNCTION__, LOWI_REQINFO(mWigigCurrentRequest));
        break;
      }
      else
      {
        log_warning(TAG, "%s: Request " LOWI_REQINFO_FMT " sent to wigig driver - failed, status(%s)",
                    __FUNCTION__, LOWI_REQINFO(mWigigCurrentRequest), LOWI_TO_STRING(req_status, SCAN_STATUS));

        // handle error response to request not generated by scheduler
        mController->sendErrorResponse(*mWigigCurrentRequest, req_status);
        delete mWigigCurrentRequest;
        mWigigCurrentRequest = NULL;
      }
    } // for
  }
} // issueRequest

void LOWIScheduler::removePeers(LOWIController::ePeerTypes remove)
{
  // Notify all clients that have peers in their requests for which
  // the driver is not available. Those requests that contain only
  // those peers in them will be removed from the lists maintained by
  // the scheduler.
  for( List<LOWIClientInfo *>::Iterator it = mClients.begin(); it != mClients.end();)
  {
    LOWIClientInfo *client = *it;
    if( NULL == client->clientReq )
      continue;
    LOWIRangingScanRequest *r = (LOWIRangingScanRequest *)client->clientReq;
    bool foundWifiPeers  = false;
    bool foundWigigPeers = false;

    // check the peers in the request and determine if it has wigig peers
    for( uint32 ii = 0; r->getNodes().getNumOfElements(); ii++ )
    {
      // if there are any wifi nodes, skip this request. don't want
      // to clean up any requests that may be mixed wifi/wigig as
      // the wifi peers may still be able to be serviced.
      if( !LOWIUtils::isWigigPeer(r->getNodes()[ii].frequency) )
      {
        foundWifiPeers = true;
      }

      if( LOWIUtils::isWigigPeer(r->getNodes()[ii].frequency) )
      {
        foundWigigPeers = true;
      }
    } // for

    if( (!foundWigigPeers && foundWifiPeers && remove == LOWIController::WIFI_PEERS) ||
        (!foundWifiPeers && foundWigigPeers && remove == LOWIController::WIGIG_PEERS) )
    {
      // this request has only wigig peers. notify the client and
      // delete the request
      log_debug(TAG, "%s: Wigig disabled, notify client ... "
                "deleting reqId(%u) originator(%s), reqType(%s)",
                __FUNCTION__,
                client->clientReq->getRequestId(),
                client->clientReq->getRequestOriginator(),
                LOWIUtils::to_string(client->clientReq->getRequestType()));
      mController->sendErrorResponse(*(client->clientReq), LOWIResponse::SCAN_STATUS_NO_WIGIG);
      delete client->clientReq;
      delete client->result;
      delete client->iReq;
      delete client;  // remove the client information (request, etc).
      it = mClients.erase(it); // remove it from the client info list
    }
    else
    {
      ++it;
    }
  } // for

  // Now that the wigig-only requests have been removed, we proceed to iterate
  // over the list of peers in the peer data base and remove all the wigig peers
  for( List<WiFiNodeInfo *>::Iterator it = mNodeDataBase.begin(); it != mNodeDataBase.end();)
  {
    WiFiNodeInfo *info = *it;

    if( (!LOWIUtils::isWigigPeer(info->nodeInfo.frequency) && remove == LOWIController::WIFI_PEERS) ||
        (LOWIUtils::isWigigPeer(info->nodeInfo.frequency)  && remove == LOWIController::WIGIG_PEERS) )
    {
      delete info->meas;
      delete info->measResult;
      delete info;
      it = mNodeDataBase.erase(it);
    }
    else
    {
      ++it;
    }
  }
} // removePeers


