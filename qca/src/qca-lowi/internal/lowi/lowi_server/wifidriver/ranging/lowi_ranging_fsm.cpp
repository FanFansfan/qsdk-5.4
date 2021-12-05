/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI ROME Finite State Machine Header file

GENERAL DESCRIPTION
  This file contains the functions and global data definitions used by the
  LOWI Rome Finite State Machine

Copyright (c) 2014-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/

#include <base_util/log.h>
#include <common/lowi_utils.h>
#include "lowi_ranging_fsm.h"
#include "lowi_ranging_pronto_fsm.h"
#include "lowi_ranging_helium_fsm.h"
#include "lowi_ranging_sparrow_fsm.h"
#include "lowi_wifidriver_utils.h"
#include "lowi_p2p_ranging.h"
#include "rttm.h"
#include "lowi_time.h"
#include "lowi_internal_const.h"
#include <lowi_strings.h>

#include <base_util/time_routines.h>


#define LOWI_FSM_EXIT_IF_NULL_POINTER(p,s) if (NULL == p) \
  {                                                       \
    log_warning(TAG, "%s: %s", __FUNCTION__, s);          \
    return -1;                                            \
  }


// Enter/Exit debug macros
#undef ALLOW_ENTER_EXIT_DBG_RANGING_FSM

#ifdef ALLOW_ENTER_EXIT_DBG_RANGING_FSM
#define FSM_ENTER() log_verbose(TAG, "ENTER: %s", __FUNCTION__);
#define FSM_EXIT() log_verbose(TAG, "EXIT: %s", __FUNCTION__);
#else
#define FSM_ENTER()
#define FSM_EXIT()
#endif

using namespace qc_loc_fw;

const char * const LOWIRangingFSM::TAG = "LOWIRangingFSM";
bool RangingCapRespRecevied = false;

eLOWIPhyMode validPhyModeTable[LOWIDiscoveryScanRequest::BAND_ALL][RTT_PREAMBLE_MAX][BW_MAX] =
{
  /* 2G BAND */
  {
                               /*    BW_20MHZ                 BW_40MHZ                      BW_80MHZ                     BW_160MHZ      */
    /* RTT_PREAMBLE_LEGACY */  {LOWI_PHY_MODE_11G          , LOWI_PHY_MODE_UNKNOWN      , LOWI_PHY_MODE_UNKNOWN,       LOWI_PHY_MODE_UNKNOWN},
    /* RTT_PREAMBLE_HT     */  {LOWI_PHY_MODE_11NG_HT20    , LOWI_PHY_MODE_11NG_HT40    , LOWI_PHY_MODE_UNKNOWN,       LOWI_PHY_MODE_UNKNOWN},
    /* RTT_PREAMBLE_VHT    */  {LOWI_PHY_MODE_11AC_VHT20_2G, LOWI_PHY_MODE_11AC_VHT40_2G, LOWI_PHY_MODE_11AC_VHT80_2G, LOWI_PHY_MODE_UNKNOWN}
  },
  /* 5G BAND */
  {
                               /*    BW_20MHZ                  BW_40MHZ                  BW_80MHZ                  BW_160MHZ      */
    /* RTT_PREAMBLE_LEGACY */  {LOWI_PHY_MODE_11A,        LOWI_PHY_MODE_UNKNOWN,    LOWI_PHY_MODE_UNKNOWN,    LOWI_PHY_MODE_UNKNOWN},
    /* RTT_PREAMBLE_HT     */  {LOWI_PHY_MODE_11NA_HT20,  LOWI_PHY_MODE_11NA_HT40,  LOWI_PHY_MODE_UNKNOWN,    LOWI_PHY_MODE_UNKNOWN},
    /* RTT_PREAMBLE_VHT    */  {LOWI_PHY_MODE_11AC_VHT20, LOWI_PHY_MODE_11AC_VHT40, LOWI_PHY_MODE_11AC_VHT80, LOWI_PHY_MODE_11AC_VHT160}
  }
};
RangingFSM_Event RomeCLDToRomeFSMEventMap[ROME_MSG_MAX] =
{
  /** ROME CLD Messages */
  /* ROME_REG_RSP_MSG */             EVENT_REGISTRATION_SUCCESS,
  /* ROME_CHANNEL_INFO_MSG */        EVENT_CHANNEL_INFO,
  /* ROME_P2P_PEER_EVENT_MSG */      EVENT_P2P_STATUS_UPDATE,
  /* ROME_CLD_ERROR_MSG */           EVENT_CLD_ERROR_MESSAGE,
  /* ROME_WIPHY_INFO_MSG */          EVENT_WIPHY_INFO,

  /** ROME FW Messages */
  /* ROME_RANGING_CAP_MSG */         EVENT_RANGING_CAP_INFO,
  /* ROME_RANGING_MEAS_MSG */        EVENT_RANGING_MEAS_RECV,
  /* ROME_RANGING_ERROR_MSG */       EVENT_RANGING_ERROR,
  /* ROME_RTT_CHANNEL_INFO_MSG */    EVENT_RTT_AVAILABLE_CHANNEL_INFO,
  /* ROME_RESPONDER_INFO_MSG */      EVENT_RESPONDER_CHANNEL_INFO,
  /* ROME_CFG_RESPONDER_MEAS_RSP_MSG*/ EVENT_CFG_RESPONDER_MEAS_RSP,
  /* ROME_RESPONDER_MEAS_INFO_MSG*/    EVENT_RESPONDER_MEAS_INFO,
  /* ROME_FTM_SESSION_DONE_MSG */    EVENT_FTM_SESSION_DONE,

  /** NL/Kernel Messages */
  /* ROME_NL_ERROR_MSG */            EVENT_INVALID_NL_MESSAGE
};

// initialize static variables
LOWIRangingFSM *LOWIRangingFSM::mWigigInstance = NULL;
LOWIRangingFSM *LOWIRangingFSM::mWifiInstance  = NULL;

_RomeRangingRequest::_RomeRangingRequest()
{
  validRangingScan = FALSE;
  curChIndex       = 0;
  totChs           = 0;
  curAp            = 0;
  totAp            = 0;
}

LOWIRangingFSM::LOWIRangingFSM(LOWIScanResultReceiverListener *scanResultListener,
                               LOWICacheManager *cacheManager,
                               LOWIRanging *lowiRanging)
{
  mListener = scanResultListener;
  mCacheManager = cacheManager;
  mRangingFsmContext.curEvent = EVENT_START_THREAD;
  mRangingFsmContext.curState = STATE_IDLE_START;
  mRangingFsmContext.timeEnd = ROME_FSM_TIMEOUT_FOREVER;
  mRangingFsmContext.terminate_thread = FALSE;
  mRangingFsmContext.notTryingToRegister = TRUE;
  mRangingFsmContext.internalFsmEventPending = FALSE;
  mNewReq = NULL;
  mRangingPipeEvents = MAX_PIPE_EVENTS;
  mLowiMeasResult = NULL;
  mLOWIRanging    = lowiRanging;
  mRtsCtsTag = 1;
  //initialize the responder expiry time to invalid,if responder is not enabled
  //make it valid only when enableresponder API request comes
  mRTTResponderExpiryTimeStamp = 0;

  mRTTResponderMeasStarted = false;

  memset(&mRangingReqRspInfo, 0, sizeof(RangingReqRspInfo));
  memset(mChannelInfoArray, 0, sizeof(mChannelInfoArray));
  /* Ready for new request */
  mRangingReqRspInfo.lastResponseRecv = TRUE;
  mRangingReqRspInfo.nonAsapTargetPresent = FALSE;
  mRomeRttCapabilities.rangingTypeMask = 0;
  SetupFsm();
};

LOWIRangingFSM::~LOWIRangingFSM()
{
  mWigigInstance = NULL;
  mWifiInstance  = NULL;
}

void LOWIRangingFSM::SetupFsm()
{
  FSM_ENTER()
  /** Initialize all action functions to "DoNothing". */

  for (unsigned int state = STATE_IDLE_START; state < STATE_MAX; state++)
  {
    for (unsigned int fsmEvent = EVENT_START_THREAD; fsmEvent < EVENT_MAX; fsmEvent++)
    {
      stateTable[state][fsmEvent] = DoNothing;
    }
  }

  /***************** State Functions for State: STATE_IDLE_START *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */    /** Trigger Event */                     /** Action Function */
  stateTable[STATE_IDLE_START]   [EVENT_START_THREAD]                         = SendRegRequest;
  stateTable[STATE_IDLE_START]   [EVENT_RANGING_REQ]                          = HandleRangingReqWhenNotReg;
  /** -- Events from NL Socket -- */
  stateTable[STATE_IDLE_START]   [EVENT_REGISTRATION_SUCCESS]                 = HandleRegSuccess;
  /** -- Events from Timer -- */
  stateTable[STATE_IDLE_START]   [EVENT_TIMEOUT]                              = HandleRegFailureOrLost;

  /***************** State Functions for State: STATE_WAITING_FOR_WIPHY_INFO *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */              /** Trigger Event */                /** Action Function */
  stateTable[STATE_WAITING_FOR_WIPHY_INFO]   [EVENT_RANGING_REQ]                   = HandleRangingReqWhenNotReg;
  /** -- Events from NL Socket -- */
  stateTable[STATE_WAITING_FOR_WIPHY_INFO]   [EVENT_CHANNEL_INFO]                  = HandleChannelInfo;
  /** -- Internal FSM Events  --  */
  stateTable[STATE_WAITING_FOR_WIPHY_INFO]   [EVENT_REGISTRATION_FAILURE_OR_LOST]  = HandleRegFailureOrLost;
  /** -- Events from Timer -- */
  stateTable[STATE_WAITING_FOR_WIPHY_INFO]   [EVENT_TIMEOUT]                       = HandleRegFailureOrLost;

  /***************** State Functions for State: STATE_WAITING_FOR_RANGING_CAP *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */             /** Trigger Event */                /** Action Function */
  stateTable[STATE_WAITING_FOR_RANGING_CAP]   [EVENT_RANGING_REQ]                   = HandleRangingReqWhenNotReg;
  /** -- Events from NL Socket -- */
  stateTable[STATE_WAITING_FOR_RANGING_CAP]   [EVENT_RANGING_CAP_INFO]              = HandleRangingCap;
  /** -- Internal FSM Events  --  */
  stateTable[STATE_WAITING_FOR_RANGING_CAP]   [EVENT_REGISTRATION_FAILURE_OR_LOST]  = HandleRegFailureOrLost;
  /** -- Events from Timer -- */
  stateTable[STATE_WAITING_FOR_RANGING_CAP]   [EVENT_TIMEOUT]                       = HandleRegFailureOrLost;

  /***************** State Functions for State: STATE_READY_AND_IDLE *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */    /** Trigger Event */                /** Action Function */
  stateTable[STATE_READY_AND_IDLE]   [EVENT_RANGING_REQ]                   = HandleRangingReq;
  stateTable[STATE_READY_AND_IDLE]   [EVENT_CONFIGURATION_REQ]             = HandleConfigReq;
  stateTable[STATE_READY_AND_IDLE]   [EVENT_INVALID_REQ]                   = IgnoreRangingReq;
  /** -- Events from NL Socket -- */
  stateTable[STATE_READY_AND_IDLE]   [EVENT_P2P_STATUS_UPDATE]             = HandleP2PInfo;
  /** -- Internal FSM Events  --  */
  stateTable[STATE_READY_AND_IDLE]   [EVENT_REGISTRATION_FAILURE_OR_LOST]  = HandleRegFailureOrLost;

  /***************** State Functions for State: STATE_PROCESSING_RANGING_REQ *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */           /** Trigger Event */                 /** Action Function */
  stateTable[STATE_PROCESSING_RANGING_REQ]   [EVENT_RANGING_REQ]                   = IgnoreRangingReq;
  /** -- Events from NL Socket -- */
  stateTable[STATE_PROCESSING_RANGING_REQ]   [EVENT_RANGING_ERROR]                 = HandleRangingErrorMsg;
  stateTable[STATE_PROCESSING_RANGING_REQ]   [EVENT_RANGING_MEAS_RECV]             = HandleRangingMeas;
  stateTable[STATE_PROCESSING_RANGING_REQ]   [EVENT_P2P_STATUS_UPDATE]             = HandleP2PInfo;
  stateTable[STATE_PROCESSING_RANGING_REQ]   [EVENT_CLD_ERROR_MESSAGE]             = HandleCldErrorMsg;
  /** -- Internal FSM Events  --  */
  stateTable[STATE_PROCESSING_RANGING_REQ]   [EVENT_REGISTRATION_FAILURE_OR_LOST]  = HandleRegFailureOrLost;
  /** -- Events from Timer -- */
             /** Current State */           /** Trigger Event */                 /** Action Function */
  stateTable[STATE_PROCESSING_RANGING_REQ]   [EVENT_TIMEOUT]                       = HandleNlTimeout;

  /***************** State Functions for State: STATE_PROCESSING_CONFIG_REQ *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */           /** Trigger Event */                 /** Action Function */
  stateTable[STATE_PROCESSING_CONFIG_REQ]   [EVENT_RANGING_REQ]                   = IgnoreRangingReq;
  /** -- Events from NL Socket -- */
  stateTable[STATE_PROCESSING_CONFIG_REQ]   [EVENT_RANGING_ERROR]                 = HandleConfigRspOrErrorMsg;
  stateTable[STATE_PROCESSING_CONFIG_REQ]   [EVENT_P2P_STATUS_UPDATE]             = HandleP2PInfo;
  stateTable[STATE_PROCESSING_CONFIG_REQ]   [EVENT_CLD_ERROR_MESSAGE]             = HandleCldErrorMsg;
  /** -- Internal FSM Events  --  */
  stateTable[STATE_PROCESSING_CONFIG_REQ]   [EVENT_REGISTRATION_FAILURE_OR_LOST]  = HandleRegFailureOrLost;
  /** -- Events from Timer -- */
             /** Current State */           /** Trigger Event */                 /** Action Function */
  stateTable[STATE_PROCESSING_CONFIG_REQ]   [EVENT_TIMEOUT]                       = HandleNlTimeout;
  FSM_EXIT()
}

int LOWIRangingFSM::HandleRegFailureOrLost(LOWIRangingFSM* pFsmObj)
{
  int retVal = 0;

  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  if (pFsmObj->ProcessingRangingRequest())
  {
    /* Stop Processing Request and return Result to User */
    pFsmObj->SendCurrentResultToUser(LOWIResponse::SCAN_STATUS_DRIVER_ERROR);
  }
  if (pFsmObj->NewRequestPending())
  {
    /* Respond to User with Failure */
    IgnoreRangingReq(pFsmObj);
  }

  /* Reset to STATE_IDLE_START and wait indefinitely */
  log_warning(TAG, "%s:Failed with Host Driver", __FUNCTION__);
  pFsmObj->mRangingFsmContext.curState = STATE_IDLE_START;
  pFsmObj->mRangingFsmContext.timeEnd = ROME_FSM_TIMEOUT_FOREVER;
  pFsmObj->mRangingFsmContext.notTryingToRegister = TRUE;

  return retVal;
}

int LOWIRangingFSM::HandleCldErrorMsg(LOWIRangingFSM* pFsmObj)
{
  int retVal = 0;
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  tAniMsgHdr * pMsgHdr = (tAniMsgHdr *)pFsmObj->mRangingFsmData;
  if ((ANI_MSG_OEM_ERROR != pMsgHdr->type) ||
      (0 == pMsgHdr->length))
  {
    log_warning(TAG, "%s: Invalid ANI Msg Type %u, len = %d", __FUNCTION__,
                pMsgHdr->type, pMsgHdr->length);
    return -1;
  }
  eOemErrorCode errCode = *((eOemErrorCode *)(pFsmObj->mRangingFsmData +
                                              sizeof(tAniMsgHdr)));
  log_debug(TAG, "%s: CLD Error Msg Type %u, len = %d, code %d", __FUNCTION__,
            pMsgHdr->type, pMsgHdr->length, errCode);
  switch (errCode)
  {
    case OEM_ERR_APP_NOT_REGISTERED:   /* OEM App is not registered */
      /* Reset to STATE_IDLE_START */
      pFsmObj->mRangingFsmContext.curState = STATE_IDLE_START;
      pFsmObj->mRangingFsmContext.timeEnd = ROME_FSM_TIMEOUT_FOREVER;
      pFsmObj->mRangingFsmContext.notTryingToRegister = TRUE;

      //Copy the appropriate request to New Req
      if (pFsmObj->mCurReq)
      {
        if(pFsmObj->eRequestType == LOWIRequest::RANGING_SCAN)
        {
          // Clean up the state for Previous Ranging Request.
          pFsmObj->mRangingReqRspInfo.lastResponseRecv = TRUE;
          pFsmObj->mRangingReqRspInfo.expectedRspFromFw = 0;
        }
        pFsmObj->mNewReq = pFsmObj->mCurReq;
        pFsmObj->mCurReq = NULL;
      }
      // Clean up the stored measurement result.
      // Make sure the measurement result vector is empty
      if (pFsmObj->mLowiMeasResult)
      {
        for (vector <LOWIScanMeasurement*>::Iterator it = pFsmObj->mLowiMeasResult->scanMeasurements.begin();
             it != pFsmObj->mLowiMeasResult->scanMeasurements.end(); it++)
        {
          delete (*it);
        }
        pFsmObj->mLowiMeasResult->scanMeasurements.flush();
        delete pFsmObj->mLowiMeasResult;
        pFsmObj->mLowiMeasResult = NULL;
      }
      //start Registration
      SendRegRequest(pFsmObj);
      break;

    case OEM_ERR_NULL_CONTEXT:          /* Error null context */
    case OEM_ERR_INVALID_SIGNATURE:     /* Invalid signature */
    case OEM_ERR_NULL_MESSAGE_HEADER:   /* Invalid message type */
    case OEM_ERR_INVALID_MESSAGE_TYPE:  /* Invalid message type */
    case OEM_ERR_INVALID_MESSAGE_LENGTH:/* Invalid length in message body */
    default:
      log_warning(TAG, "%s:Unexpected error code %d", __FUNCTION__, errCode);
      break;
  }

  return retVal;
}

int LOWIRangingFSM::DoNothing(LOWIRangingFSM* pFsmObj)
{
  int retVal = 0;
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  log_debug(TAG, "%s: FSM Recieved Event: %s while in State: %s", __FUNCTION__,
              LOWIStrings::to_string(pFsmObj->mRangingFsmContext.curEvent),
              LOWIStrings::to_string(pFsmObj->mRangingFsmContext.curState));
  return retVal;
}

void LOWIRangingFSM::setFsmInternalEvent()
{
  mRangingFsmContext.internalFsmEventPending = true;
}

void LOWIRangingFSM::clearFsmInternalEvent()
{
  mRangingFsmContext.internalFsmEventPending = false;
}

int LOWIRangingFSM::HandleRangingReqWhenNotReg(LOWIRangingFSM* pFsmObj)
{
  log_verbose(TAG, "%s: Received Ranging Request when Not registered", __FUNCTION__);
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  if (pFsmObj->mRangingFsmContext.notTryingToRegister)
  {
    if(SendRegRequest(pFsmObj) != 0)
    {
      log_debug(TAG, "%s: Failed to Start Registration Process", __FUNCTION__);
      return -1;
    }
  }
  return 0;
}
int LOWIRangingFSM::IgnoreRangingReq(LOWIRangingFSM* pFsmObj)
{
  int retVal = 0;
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  log_debug(TAG, "%s: Ignore newly arrived ranging request", __FUNCTION__);
  LOWIMeasurementResult* result = new (std::nothrow) LOWIMeasurementResult;
  if (result == NULL)
  {
    log_debug(TAG, "%s:Ranging Measurment Results memory allocation faliure", __FUNCTION__);
    return -1;
  }
  if (pFsmObj->mRangingFsmContext.curEvent == EVENT_INVALID_REQ)
  {
    retVal = pFsmObj->InitializeMeasResult(result, LOWIResponse::SCAN_STATUS_INVALID_REQ);
  }
  else
  {
    retVal = pFsmObj->InitializeMeasResult(result);
  }
  if (retVal != 0)
  {
    log_info(TAG, "%s: initialize LOWI Meas Results failed", __FUNCTION__);
  }
  else
  {
    pFsmObj->mRangingFsmContext.curEvent = EVENT_RANGING_RESPONSE_TO_USER;
    /* Send Result to User */
    pFsmObj->SendResultToClient(result);
  }
  return retVal;
}

int LOWIRangingFSM::SendRegRequest(LOWIRangingFSM* pFsmObj)
{
  int retVal = 0;
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj->mLOWIRanging, "Invalid LOWIRanging object")

  retVal = pFsmObj->mLOWIRanging->RomeSendRegReq();
  if (retVal != 0)
  {
    /* Failed to send Registration request */
    log_warning(TAG, "%s: Failed - Send Registration request to Host Driver", __FUNCTION__);
    pFsmObj->mRangingFsmContext.curEvent = EVENT_REGISTRATION_FAILURE_OR_LOST;
    HandleRegFailureOrLost(pFsmObj);
  }
  else
  {
    pFsmObj->mRangingFsmContext.notTryingToRegister = FALSE;
    pFsmObj->mRangingFsmContext.timeEnd = get_time_rtc_ms() + (SELECT_TIMEOUT_NORMAL * 1000);
  }
  return retVal;
}

int LOWIRangingFSM::HandleRegSuccess(LOWIRangingFSM* pFsmObj)
{
  IwOemDataCap iwOemDataCap;
  int retVal = -1;
  LOWIMacAddress localStaMac;
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj->mLOWIRanging, "Invalid LOWIRanging object")

  do
  {
    if ( pFsmObj->mLOWIRanging->RomeExtractRegRsp(pFsmObj->mRangingFsmData) != 0)
    {
      log_warning(TAG, "%s:Failed - Register with Wi-Fi Host Driver", __FUNCTION__);
      HandleRegFailureOrLost(pFsmObj);
      break;
    }
    if (LOWIWifiDriverUtils::getWiFiIdentityandCapability(&(iwOemDataCap), localStaMac) < 0)
    {
      log_warning(TAG, "%s:Failed - Get Wifi Capabilities", __FUNCTION__);
      HandleRegFailureOrLost(pFsmObj);
      break;
    }
    if(pFsmObj->mLOWIRanging->RomeSendChannelInfoReq(iwOemDataCap) != 0)
    {
      log_warning(TAG, "%s:Failed - get Channel Information", __FUNCTION__);
      HandleRegFailureOrLost(pFsmObj);
      break;
    }
    pFsmObj->mRangingFsmContext.timeEnd = get_time_rtc_ms() + (SELECT_TIMEOUT_NORMAL * 1000);
    pFsmObj->mRangingFsmContext.curState = STATE_WAITING_FOR_WIPHY_INFO;
    retVal = 0;
  } while(0);

  return retVal;
}

int LOWIRangingFSM::HandleChannelInfo(LOWIRangingFSM* pFsmObj)
{
  std::string interface = "wifi0";
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj->mLOWIRanging, "Invalid LOWIRanging object")

  memset(pFsmObj->mChannelInfoArray, 0, sizeof(pFsmObj->mChannelInfoArray));
  if(pFsmObj->mLOWIRanging->RomeExtractChannelInfo(pFsmObj->mRangingFsmData,
                                                   pFsmObj->mChannelInfoArray) != 0)
  {
    log_warning(TAG, "%s: Failed - get Channel Information", __FUNCTION__);
    HandleRegFailureOrLost(pFsmObj);
    return -1;
  }
  RangingCapRespRecevied = false;
  if(pFsmObj->mLOWIRanging->RomeSendRangingCapReq(interface) != 0)
  {
    log_warning(TAG, "%s:Failed - get Ranging Capabilities from FW", __FUNCTION__);
    HandleRegFailureOrLost(pFsmObj);
    return -1;
  }
  pFsmObj->mRangingFsmContext.timeEnd = get_time_rtc_ms() + (SELECT_TIMEOUT_NORMAL * 1000);
  pFsmObj->mRangingFsmContext.curState = STATE_WAITING_FOR_RANGING_CAP;
  return 0;
}

int LOWIRangingFSM::HandleRangingCap(LOWIRangingFSM* pFsmObj)
{
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj->mLOWIRanging, "Invalid LOWIRanging object")

  if(pFsmObj->mLOWIRanging->RomeExtractRangingCap(pFsmObj->mRangingFsmData, &(pFsmObj->mRomeRttCapabilities)) != 0)
  {
    log_warning(TAG, "%s:Failed - get Ranging Capabilities from FW", __FUNCTION__);
    HandleRegFailureOrLost(pFsmObj);
    RangingCapRespRecevied = true;
    return -1;
  }
  pFsmObj->mRangingFsmContext.curState = STATE_READY_AND_IDLE;
  RangingCapRespRecevied = true;

  if (pFsmObj->NewRequestPending()) /* Check if there is a pending new request, if so process it immediately */
  {
    pFsmObj->setFsmInternalEvent();
    pFsmObj->LowiReqToEvent(pFsmObj->mNewReq);
  }
  else /* Other wise sit and wait for new request */
  {
    pFsmObj->mRangingFsmContext.timeEnd = ROME_FSM_TIMEOUT_FOREVER;
  }
  return 0;
}

int LOWIRangingFSM::InitializeMeasResult(LOWIMeasurementResult* lowiMeasResult, LOWIResponse::eScanStatus status)
{
  log_verbose(TAG, "%s", __FUNCTION__);
  if (lowiMeasResult == NULL)
  {
    log_warning(TAG, "%s:NULL Meas Results Pointer!!!", __FUNCTION__);
    return -1;
  }

  lowiMeasResult->scanType = LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
  lowiMeasResult->scanStatus = status;
  lowiMeasResult->request = (LOWIRangingScanRequest*)mCurReq;

  return 0;
}

int LOWIRangingFSM::HandleConfigReq(LOWIRangingFSM* pFsmObj)
{
  int retVal = 0;
  log_verbose(TAG, "%s", __FUNCTION__);
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj->mLOWIRanging, "Invalid LOWIRanging object")

  log_verbose(TAG, "%s: Send %s request", __FUNCTION__, LOWIUtils::to_string(pFsmObj->eRequestType));
  pFsmObj->mRtsCtsTag++;
  if (pFsmObj->mCurReq && (pFsmObj->eRequestType == LOWIRequest::SET_LCI_INFORMATION))
  {
    retVal = pFsmObj->mLOWIRanging->RomeSendLCIConfiguration(pFsmObj->mRtsCtsTag,
                                                             (LOWISetLCILocationInformation*)pFsmObj->mCurReq);
  }
  else if (pFsmObj->mCurReq && (pFsmObj->eRequestType == LOWIRequest::SET_LCR_INFORMATION))
  {
    retVal = pFsmObj->mLOWIRanging->RomeSendLCRConfiguration(pFsmObj->mRtsCtsTag,
                                                             (LOWISetLCRLocationInformation*)pFsmObj->mCurReq);
  }
  else if (pFsmObj->mCurReq && (pFsmObj->eRequestType == LOWIRequest::SEND_LCI_REQUEST))
  {
    retVal = pFsmObj->mLOWIRanging->RomeSendLCIRequest(pFsmObj->mRtsCtsTag,
                                                       (LOWISendLCIRequest*)pFsmObj->mCurReq);
  }
  else if (pFsmObj->mCurReq && (pFsmObj->eRequestType == LOWIRequest::FTM_RANGE_REQ))
  {
    retVal = pFsmObj->mLOWIRanging->RomeSendFTMRR(pFsmObj->mRtsCtsTag,
                                                  (LOWIFTMRangingRequest*)pFsmObj->mCurReq);
  }
  else
  {
    retVal = -1;
  }

  if (retVal != -1) // Successfully sent Request to FW
  {
    pFsmObj->mRangingFsmContext.curState = STATE_PROCESSING_CONFIG_REQ;

    log_verbose(TAG, "%s: Setting timeout %u secs in the future",
                __FUNCTION__,
                SELECT_TIMEOUT_NORMAL);
    pFsmObj->mRangingFsmContext.timeEnd = get_time_rtc_ms() + (SELECT_TIMEOUT_NORMAL * 1000);
  }

  return retVal;
}

int LOWIRangingFSM::HandleRangingReq(LOWIRangingFSM* pFsmObj)
{
  FSM_ENTER()
  int retVal = -1;
  do
  {
    LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
    uint64 rangingRequestTimestamp = lowi_get_time_from_boot();
    // if RTT responder is still enabled ignore the incoming ranging request
    if((pFsmObj->mRTTResponderExpiryTimeStamp > 0) &&
       (rangingRequestTimestamp <= pFsmObj->mRTTResponderExpiryTimeStamp))
    {
      log_debug(TAG, "%s: Responder mode is enabled", __FUNCTION__);
      IgnoreRangingReq(pFsmObj);
      break;
    }

    if(pFsmObj->PrepareRangingRequest() != 0)
    {
      log_debug(TAG, "%s: Failed - Prepare Ranging Request", __FUNCTION__);
      IgnoreRangingReq(pFsmObj);
      break;
    }
    if (pFsmObj->ValidateRangingRequest() != 0)
    {
      log_debug(TAG, "%s: Ranging Request Not Valid, Aborting request", __FUNCTION__);
      pFsmObj->RejectNewRangingReq();
      break;
    }
    retVal = pFsmObj->SendRangingReq();
    if(retVal < 0)
    {
      log_debug(TAG, "%s: Failed - Send Ranging Request to FW", __FUNCTION__);
      IgnoreRangingReq(pFsmObj);
      break;
    }
    else if (retVal > 0)
    {
      retVal = pFsmObj->SendReqToFwOrRespToUser();
      break;
    }
    pFsmObj->mRangingFsmContext.curState = STATE_PROCESSING_RANGING_REQ;

    uint64 timeOut = (pFsmObj->mRangingReqRspInfo.nonAsapTargetPresent ?
                      SELECT_TIMEOUT_NON_ASAP_TARGET :
                      SELECT_TIMEOUT_NORMAL);
    log_verbose(TAG, "%s: Setting timeout %u secs in the future", __FUNCTION__, timeOut);
    pFsmObj->mRangingFsmContext.timeEnd = get_time_rtc_ms() + (timeOut * 1000);
  }
  while (0);
  FSM_EXIT()
  return 0;
}

int LOWIRangingFSM::HandleRangingMeas(LOWIRangingFSM* pFsmObj)
{
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  if(pFsmObj->ProcessRangingMeas() != 0)
  {
    log_info(TAG, "%s: Failed - Process Ranging Measurements", __FUNCTION__);
    pFsmObj->ProcessRttRejected();
  }

  pFsmObj->SendReqToFwOrRespToUser();

  return 0;
}

int LOWIRangingFSM::RejectNewRangingReq()
{
  int retVal = 0;
  log_debug(TAG, "%s: Reject newly arrived ranging request", __FUNCTION__);
  LOWIMeasurementResult* result = new (std::nothrow) LOWIMeasurementResult;
  if (result == NULL)
  {
    log_debug(TAG, "%s - memory allocation faliure - Ranging Measurment Results", __FUNCTION__);
    return -1;
  }
  retVal = InitializeMeasResult(result, LOWIResponse::SCAN_STATUS_INVALID_REQ);
  if (retVal != 0)
  {
    log_info(TAG, "%s: initialize LOWI Meas Results failed", __FUNCTION__);
  }
  else
  {
    mRangingFsmContext.curEvent = EVENT_RANGING_RESPONSE_TO_USER;
    /* Set New request to NULL */
    SetLOWIRequest(NULL);
    /* Send Result to User */
    SendResultToClient(result);
  }
  return retVal;
}

int LOWIRangingFSM::SendCurrentResultToUser(LOWIResponse::eScanStatus status)
{
  /* Done with the Ranging Request - Respond to User */
  mRangingFsmContext.timeEnd = ROME_FSM_TIMEOUT_FOREVER;
  mRangingFsmContext.curEvent = EVENT_RANGING_RESPONSE_TO_USER;
  mRangingFsmContext.curState = STATE_READY_AND_IDLE;
  /* Send Result to User */
  if (mLowiMeasResult)
  {
    mLowiMeasResult->scanStatus = status;
    SendResultToClient(mLowiMeasResult);
  }
  else
  {
    IgnoreRangingReq(this);
  }

  return 0;
}

int LOWIRangingFSM::SendReqToFwOrRespToUser()
{
  /* check to see if all expected Responses from FW have arrived */
  mRangingReqRspInfo.lastResponseRecv = (mRangingReqRspInfo.totalRspFromFw == mRangingReqRspInfo.expectedRspFromFw)? TRUE : FALSE;

  /* All Expected responses have arrived from FW */
  if (mRangingReqRspInfo.lastResponseRecv)
  {
    /* Send another Ranging Request to FW if the Ranging request is still valid */
    if (mRomeRangingReq.validRangingScan)
    {
      if(SendRangingReq() != 0)
      {
        log_warning(TAG, "%s:Send Ranging Request - failed, Aborting current LOWI request", __FUNCTION__);
        /* Done with the Ranging Request - Respond to User */
        (mLowiMeasResult)->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
        mRangingFsmContext.timeEnd = ROME_FSM_TIMEOUT_FOREVER;
        mRangingFsmContext.curEvent = EVENT_RANGING_RESPONSE_TO_USER;
        mRangingFsmContext.curState = STATE_READY_AND_IDLE;
        /* Send Result to User */
        SendResultToClient(mLowiMeasResult);
        return -1;
      }
      uint64 timeOut = (mRangingReqRspInfo.nonAsapTargetPresent ?
                        SELECT_TIMEOUT_NON_ASAP_TARGET :
                        SELECT_TIMEOUT_NORMAL);
      log_verbose(TAG, "%s: Setting timeout %u secs in the future",
                  __FUNCTION__,
                  timeOut);
      mRangingFsmContext.timeEnd = get_time_rtc_ms() + (timeOut * 1000);
    }
    else /* Other wise send the result to User */
    {
      /* Done with the Ranging Request - Respond to User */
      mRangingFsmContext.timeEnd = ROME_FSM_TIMEOUT_FOREVER;
      mRangingFsmContext.curEvent = EVENT_RANGING_RESPONSE_TO_USER;
      mRangingFsmContext.curState = STATE_READY_AND_IDLE;
      /* Send Result to User */
      if (NULL != mLowiMeasResult)
      {
        log_info(TAG, "%s: All ranging meas completed.Send response to client", __FUNCTION__);
        (mLowiMeasResult)->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
        SendResultToClient(mLowiMeasResult);
      }
    }
  }
  else /* Still expecting responses from FW */
  {
    // Do Nothing
  }

  return 0;
}

int LOWIRangingFSM::HandleConfigRspOrErrorMsg(LOWIRangingFSM* pFsmObj)
{
  log_verbose(TAG, "%s", __FUNCTION__);
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  int retVal = HandleRangingErrorMsg(pFsmObj);

  if (pFsmObj->mRangingReqRspInfo.rangingConfigStatus == CONFIG_SUCCESS ||
      pFsmObj->mRangingReqRspInfo.rangingConfigStatus == CONFIG_FAIL)
  {
    log_verbose(TAG, "%s Response for Configuration request", __FUNCTION__);
    pFsmObj->mLowiMeasResult = new (std::nothrow) LOWIMeasurementResult;
    if (pFsmObj->mLowiMeasResult == NULL)
    {
      log_debug(TAG, "%s:Memory allocation faliure - Ranging Measurment Results", __FUNCTION__);
      return -1;
    }
    pFsmObj->mLowiMeasResult->scanType = LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
    if (pFsmObj->mRangingReqRspInfo.rangingConfigStatus == CONFIG_SUCCESS)
    {
      log_verbose(TAG, "%s: Response for Config request: SUCCESS", __FUNCTION__);
      pFsmObj->mLowiMeasResult->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
    }
    else
    {
      log_verbose(TAG, "%s: Response for Config request: FAILURE", __FUNCTION__);
      pFsmObj->mLowiMeasResult->scanStatus = LOWIResponse::SCAN_STATUS_DRIVER_ERROR;
    }
    pFsmObj->mLowiMeasResult->request = pFsmObj->mCurReq;

    pFsmObj->SendResultToClient(pFsmObj->mLowiMeasResult);

    pFsmObj->mCurReq = NULL;

    pFsmObj->mRangingFsmContext.timeEnd  = ROME_FSM_TIMEOUT_FOREVER;
    pFsmObj->mRangingFsmContext.curEvent = EVENT_CONFIG_RESPONSE_TO_USER;
    pFsmObj->mRangingFsmContext.curState = STATE_READY_AND_IDLE;
  }
  return retVal;
}

int LOWIRangingFSM::HandleRangingErrorMsg(LOWIRangingFSM* pFsmObj)
{
  int retVal = 0;
  tANI_U32 errorCode;
  tANI_U8 bssid[BSSID_LEN + 2];

  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj->mLOWIRanging, "Invalid LOWIRanging object")

  if (pFsmObj->mLOWIRanging->RomeExtractRangingError(pFsmObj->mRangingFsmData, &errorCode, bssid) != 0)
  {
    log_info(TAG, "%s: Extract Err Code faliure from Ranging Err Msg", __FUNCTION__);
    return -1;
  }

  if (errorCode > WMI_RTT_REJECT_MAX)
  {
    log_debug(TAG, "%s:Received invalid errCode from FW: %s",__FUNCTION__,
              LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)errorCode));
    return -1;
  }
  log_debug(TAG, "%s:Received Error(%s)",__FUNCTION__,
            LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)errorCode));
  switch (errorCode)
  {
    case RTT_COMMAND_HEADER_ERROR:       //rtt cmd header parsing error --terminate
    case RTT_MODULE_BUSY:                //rtt no resource -- terminate
    case RTT_NO_RESOURCE:                //Any Resource allocate failure
    case RTT_CHAN_SWITCH_ERROR:          //channel swicth failed
    case RTT_REPORT_TYPE2_MIX:           //do not allow report type2 mix with type 0, 1
    case RTT_COMMAND_ERROR:              //rtt body parsing error -- skip current STA REQ
    case RTT_VOIP_IN_PROGRESS:           // voip call in progress, reject the request
    {
      // Entire request Rejected
      pFsmObj->ProcessRttRejected();
      break;
    }
    case RTT_TOO_MANY_STA:               //STA exceed the support limit -- only serve the first n STA
    {
      // Do Nothing
      if (pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_WITH_CFR ||
          pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_NO_CFR)
      {
        /* For Report Type 0/1 Reduce the expected number of measurements
           to MAX supported */
        pFsmObj->mRangingReqRspInfo.expectedRspFromFw = (MAX_BSSIDS_TO_SCAN * pFsmObj->mRangingReqRspInfo.measPerTarget);
      }
      break;
    }
    case RTT_VDEV_ERROR:                 //can not find vdev with vdev ID -- skip current STA REQ
    case RTT_FRAME_TYPE_NOSUPPORT:       //We do not support RTT measurement with this type of frame
    case RTT_TMR_TRANS_ERROR:            //TMR trans error, this dest peer will be skipped
    case RTT_TM_TIMER_EXPIRE:            //wait for first TM timer expire -- terminate current STA measurement
    case WMI_RTT_REJECT_MAX:             // Temporarily this will be used to indicate FTMR rejected by peer
    case RTT_DFS_CHANNEL_QUIET:          // Ranging request send with DFS channel for a BSSID. BSSID will be skipped.
    case RTT_NAN_REQUEST_FAILURE:        // NAN ranging request failure
    case RTT_NAN_NEGOTIATION_FAILURE:    // NAN Ranging negotiation failure
    case RTT_NAN_DATA_PATH_ACTIVE:       // concurrency not supported (NDP+RTT)
    {
      // For Report Type 0/1 - No measurement reports for the specifed BSSID
      // For report Type 2   - No measurements for specified BSSID in Aggregated Report
      log_debug(TAG, "%s: Due to error(%s), skip bssid(" LOWI_MACADDR_FMT ") ",__FUNCTION__,
               LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)errorCode), LOWI_MACADDR(bssid));

      if (pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_WITH_CFR ||
          pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_NO_CFR)
      {
        /* For Report Type 0/1 Reduce the expected number of measurements
           by subtracting number of measurements/Target */
        pFsmObj->mRangingReqRspInfo.expectedRspFromFw -= pFsmObj->mRangingReqRspInfo.measPerTarget;
      }
      break;
    }
    case RTT_TRANSIMISSION_ERROR:        //Tx failure -- continiue and measure number-- Applicable only for RTT V2
    case RTT_NO_REPORT_BAD_CFR_TOKEN:    //V3 only. If both CFR and Token mismatch, do not report
    case RTT_NO_REPORT_FIRST_TM_BAD_CFR: //For First TM, if CFR is bad, then do not report
    {
      // For Report Type 0/1 - No measurement report for current Frame for specifed BSSID
      // For report Type 2   - No measurement for 1 frame in aggregated report for specifed BSSID
      if (pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_WITH_CFR ||
          pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_NO_CFR)
      {
        /* For Report Type 0/1 Reduce the expected number of measurements by 1 */
        pFsmObj->mRangingReqRspInfo.expectedRspFromFw--;
      }
      break;
    }
    case RTT_TIMER_EXPIRE:               //Whole RTT measurement timer expire -- terminate current STA measurement
    {
      // For Report Type 0/1 - No MORE measurement reports for the specifed BSSID
      // For report Type 2   - Less than requested measurements for specified BSSID in Aggregated Report
      if (pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_WITH_CFR ||
          pFsmObj->mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_NO_CFR)
      {
        /* For Report Type 0/1 Reduce the expected number of measurements
           by subtracting number of measurements remaining for the current BSSID */
        pFsmObj->mRangingReqRspInfo.expectedRspFromFw -= (pFsmObj->mRangingReqRspInfo.measPerTarget - (pFsmObj->mRangingReqRspInfo.totalRspFromFw % pFsmObj->mRangingReqRspInfo.measPerTarget));
      }
      break;
    }
    case RTT_LCI_CFG_OK:                 //LCI Configuration OK
    case RTT_LCR_CFG_OK:                 //LCR Configuration OK
    case RTT_CFG_ERROR:                  //Bad LCI or LCR Configuration Request
    case RTT_LCI_REQ_OK:                 //Where are you request OK
    case RTT_FTMRR_OK:                   //FTMRR OK
    {
      if (pFsmObj->mRangingFsmContext.curState == STATE_PROCESSING_CONFIG_REQ)
      {
        pFsmObj->mRangingReqRspInfo.rangingConfigStatus =
          (errorCode == RTT_CFG_ERROR) ? CONFIG_FAIL : CONFIG_SUCCESS;
      }
      else
      {
        // Do Nothing
        log_info(TAG,"%s Received unexpected error code(%s)", __FUNCTION__,
                 LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)errorCode));
      }
      break;
    }
    default:
    {
      log_debug(TAG, "%s: invalid error(%d) -- %s arrived!, not expected",
                __FUNCTION__, errorCode, LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)errorCode));
      break;
    }
  }

  if (errorCode != RTT_LCI_CFG_OK &&
      errorCode != RTT_LCR_CFG_OK &&
      errorCode != RTT_CFG_ERROR  &&
      errorCode != RTT_LCI_REQ_OK &&
      errorCode != RTT_FTMRR_OK )
  {
    /* Add Skipped Target to List */
    pFsmObj->mLOWIRanging->RomeAddSkippedTargetToList(errorCode, bssid);
    retVal = pFsmObj->SendReqToFwOrRespToUser();
  }

  return retVal;
}

int LOWIRangingFSM::HandleP2PInfo(LOWIRangingFSM* pFsmObj)
{
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj->mLOWIRanging, "Invalid LOWIRanging object")

  if(pFsmObj->mLOWIRanging->RomeExtractP2PInfo(pFsmObj->mRangingFsmData) != 0)
  {
    log_debug(TAG, "%s:Extract P2P info faliure", __FUNCTION__);
    return -1;
  }
  return 0;
}

int LOWIRangingFSM::HandleNlTimeout(LOWIRangingFSM* pFsmObj)
{
  LOWI_FSM_EXIT_IF_NULL_POINTER(pFsmObj, "Invalid FSM object")

  log_verbose(TAG, "%s", __FUNCTION__);
  if(pFsmObj->mCurReq)
  {
    if((pFsmObj->eRequestType == LOWIRequest::RANGING_SCAN) ||
       (pFsmObj->eRequestType == LOWIRequest::PERIODIC_RANGING_SCAN))
     {
  pFsmObj->ProcessRttRejected();
  if(pFsmObj->SendReqToFwOrRespToUser() != 0)
  {
    log_debug(TAG, "%s: Failed to Respond to User!!", __FUNCTION__);
    return -1;
       }
     }
     else
     {
       if( pFsmObj->mLowiMeasResult == NULL)
       {
         pFsmObj->mLowiMeasResult = new (std::nothrow) LOWIMeasurementResult;
         if (pFsmObj->mLowiMeasResult == NULL)
         {
           log_debug(TAG, "%s Warning: failed to allocate memory", __FUNCTION__);
           return -1;
         }
       }
       pFsmObj->mRTTResponderExpiryTimeStamp = 0;
       pFsmObj->mLowiMeasResult->request = pFsmObj->mCurReq;
       pFsmObj->mLowiMeasResult->scanStatus   = LOWIResponse::SCAN_STATUS_DRIVER_TIMEOUT;
       pFsmObj->mRangingFsmContext.timeEnd    = ROME_FSM_TIMEOUT_FOREVER;
       pFsmObj->mRangingFsmContext.curEvent   = EVENT_CONFIG_RESPONSE_TO_USER;
       pFsmObj->mRangingFsmContext.curState   = STATE_READY_AND_IDLE;
       pFsmObj->SendResultToClient(pFsmObj->mLowiMeasResult);
     }
  }
  return 0;
}

void LOWIRangingFSM::ProcessRttRejected()
{
  /* We will get no more Responses from FW */
  mRangingReqRspInfo.totalRspFromFw = 0;
  mRangingReqRspInfo.expectedRspFromFw = 0;
  AddDummyMeas();
}

int LOWIRangingFSM::SetLOWIRequest(LOWIRequest* pReq)
{
  mNewReq = pReq;
  return 0;
}

bool LOWIRangingFSM::NewRequestPending()
{
  if (mNewReq != NULL)
  {
    return true;
  }
  else
  {
    return false;
  }
}

bool LOWIRangingFSM::ProcessingRangingRequest()
{
  return mRomeRangingReq.validRangingScan;
}

int LOWIRangingFSM::SendResultToClient(LOWIMeasurementResult* result)
{
  int retVal = 0;
  /* Send Result through listener */
  if (mListener != NULL)
  {
    log_verbose(TAG, "%s: Total Number of APs in result: %u", __FUNCTION__,
                result->scanMeasurements.getNumOfElements());

    mListener->scanResultsReceived(result);
  }
  else
  {
    log_debug(TAG, "%s: Invalid Listener, send back Result failed", __FUNCTION__);
    delete result;
    retVal = -1;
  }

  /* Reset the request pointer */
  mCurReq = NULL;

  return retVal;
}

bool LOWIRangingFSM::IsReady()
{
  if (mRangingFsmContext.curState == STATE_READY_AND_IDLE)
    return TRUE;
  else
    return FALSE;
}

#define CAPABILITY_RESP_TIMEOUT_COUNT 2
bool LOWIRangingFSM::SendRangingCap(std::string interface)
{
    int count = 0;

    RangingCapRespRecevied = false;
    mRangingFsmContext.timeEnd = get_time_rtc_ms() + (SELECT_TIMEOUT_NORMAL * 1000);
    mRangingFsmContext.curState = STATE_WAITING_FOR_RANGING_CAP;

    if(mLOWIRanging->RomeSendRangingCapReq(interface) != 0)
    {
        log_warning(TAG, "%s:Failed - to send Ranging Capabilities request to FW", __FUNCTION__);
        return false;
    }

    do {
        sleep (1);
        count++;
    } while (!RangingCapRespRecevied && (CAPABILITY_RESP_TIMEOUT_COUNT < 3));

    if (!RangingCapRespRecevied) {
        log_warning(TAG, "%s:Failed - get Ranging Capabilities from FW", __FUNCTION__);
        return false;
    }

    return true;
}

LOWI_RangingCapabilities LOWIRangingFSM::GetRangingCap()
{
  FSM_ENTER()
  LOWI_RangingCapabilities lowiRangingCap;
  memset(&lowiRangingCap, 0, sizeof(LOWI_RangingCapabilities));

  lowiRangingCap.oneSidedSupported = true;
  lowiRangingCap.dualSidedSupported11mc = true;
  lowiRangingCap.bwSupport = RTT_CAP_BW_80;
  lowiRangingCap.preambleSupport = (CAP_PREAMBLE_LEGACY |
                                    CAP_PREAMBLE_HT     |
                                    CAP_PREAMBLE_VHT);
  if (mRangingFsmContext.curState == STATE_READY_AND_IDLE)
  {
    lowiRangingCap.oneSidedSupported = (CAP_SINGLE_SIDED_RTT_SUPPORTED(mRomeRttCapabilities.rangingTypeMask)) ? TRUE : FALSE;
    lowiRangingCap.dualSidedSupported11mc = (CAP_11MC_DOUBLE_SIDED_RTT_SUPPORTED(mRomeRttCapabilities.rangingTypeMask)) ? TRUE : FALSE;
    lowiRangingCap.bwSupport = mRomeRttCapabilities.maxBwAllowed;
    lowiRangingCap.preambleSupport = mRomeRttCapabilities.preambleSupportedMask;
    if (mRomeRttCapabilities.fwMultiBurstSupport)
    {
      lowiRangingCap.supportedCaps |= LOWI_FW_MULTI_BURST_SUPPORTED;
    }
    else
    {
      lowiRangingCap.supportedCaps &= ~LOWI_FW_MULTI_BURST_SUPPORTED;
    }
  }
  FSM_EXIT()
  return lowiRangingCap;
}

unsigned int LOWIRangingFSM::ExpectedMeasSizeForTarget(unsigned int numMeas, uint32 ftmRangingParams)
{
  unsigned int maxLen = 0;
  bool lci = false, lcr = false;

  lci = FTM_GET_LCI_REQ(ftmRangingParams);
  lcr = FTM_GET_LOC_CIVIC_REQ(ftmRangingParams);

  // The size of Subtype Field +
  // RTT Message Header +
  // Per Target Header
  maxLen += sizeof(OemMsgSubType) +
            sizeof(RomeRTTReportHeaderIE) +
            sizeof(RomeRttPerPeerReportHdr);
  // Measurement Size
  maxLen += numMeas * (sizeof(RomeRttPerFrame_IE_RTTV3));
  // Size for LCI information
  maxLen += lci ? LCI_FTM_LCI_TOT_MAX_LEN : 0;
  // Size for LCR information
  maxLen += lcr ? LOC_CIVIC_ELE_MAX_LEN : 0;

  return maxLen;
}

void LOWIRangingFSM::AddDummyMeas()
{
  // Find the index of the channel and the first BSSID in the previous request
  unsigned int chIdx = mRomeRangingReq.curChIndex;
  unsigned int apIdx = mRomeRangingReq.curAp;

  if (!mRomeRangingReq.validRangingScan || (apIdx == 0))
  {
    // If on 1st AP that means previous channel was used.
    // Go to last AP on this channel.
    chIdx--;
    apIdx = mRomeRangingReq.arrayVecRangingNodes[chIdx].getNumOfElements()-1;
  }
  else
  {
    apIdx--;
  }
  vector <LOWIRangingNode>& vNodes = mRomeRangingReq.arrayVecRangingNodes[chIdx];
  for (unsigned int bssIdx = 0; (bssIdx < mRangingReqRspInfo.bssidCount) &&
                                (bssIdx <= apIdx); bssIdx++)
  {
    AddTargetToResult(vNodes[apIdx-bssIdx].targetNode,
                      LOWIScanMeasurement::LOWI_TARGET_STATUS_FAILURE);
  }
}

bool LOWIRangingFSM::validChannelBWCombo(eRangingBandwidth bw, uint32 primary_freq,
                                         uint32 center_freq1, uint32 center_freq2)
{
  bool retVal = false;

  /* Ensure that the Channel spacing requested is allowed for requested BW */
  switch (bw)
  {
    case BW_20MHZ:
    {
      /* For 20MHZ BW, only allow Center Frequency of 0 or same as Primary */
      if (IS_VALID_20MHZ_CHAN_SPACING(primary_freq, center_freq1))
      {
        /* Valid channel spacing */
        retVal = true;
      }
      break;
    }
    case BW_40MHZ:
    {
      /* For 40MHZ BW, only allow Center Frequency of Primary +/- 10 MHz */
      if (IS_VALID_40MHZ_CHAN_SPACING(primary_freq, center_freq1))
      {
        /* Valid channel spacing */
        retVal = true;
      }
      break;
    }
    case BW_80MHZ:
    {
      /* For 80MHZ BW, allow Center Frequency of Primary +/- 10 MHz OR Primary +/- 30 MHz */
      if (IS_VALID_80MHZ_CHAN_SPACING(primary_freq, center_freq1))
      {
        /* Valid channel spacing */
        retVal = true;
      }
      break;
    }
    case BW_160MHZ:
    {
      // 160MHz BW can operation can be in either one single 160MHz Band or 80 + 80
      if (IS_VALID_160MHZ_CHAN_SPACING(primary_freq, center_freq1, center_freq2) ||
          IS_VALID_80P80MHZ_CHAN_SPACING(primary_freq, center_freq1, center_freq2))
      {
        /* Valid channel spacing */
        retVal = true;
      }
      break;
    }
    default:
    {
      /* Invalid Bandwidth - Do Nothing */
      log_debug (TAG, "%s, Invalid bandwidth requested", __FUNCTION__);
      break;
    }
  }
  return retVal;
}

bool LOWIRangingFSM::validChannelBWPreambleCombo(LOWIRangingNode targetNode)
{

  bool retVal = false;
  wmi_channel chanInfo = targetNode.chanInfo.wmiChannelInfo;
  LOWINodeInfo node = targetNode.targetNode;

  do
  {
    /* Check to ensure the primary and center frequency provided by user are valid */
    if (LOWIUtils::freqToChannel(chanInfo.mhz) == 0)
    {
      log_debug (TAG, "%s, Invalid primary channel", __FUNCTION__);
      break;
    }

    /* Ensure Preamble requested by user is within the supported range */
    if (node.preamble < RTT_PREAMBLE_LEGACY ||
        node.preamble > RTT_PREAMBLE_VHT)
    {
      log_debug (TAG, "%s, Invalid Preamble requested", __FUNCTION__);
      break;
    }

    if (!validChannelBWCombo(node.bandwidth, chanInfo.mhz, chanInfo.band_center_freq1,
                             chanInfo.band_center_freq2))
    {
      break;
    }
    /* Ensure that the requested Bandwidth, Channel and preamble are an allowed combination */
    /* Using the valid Phy mode table to check the combination */
    uint32 band = LOWIUtils::freqToBand(chanInfo.mhz);
    if ((band == LOWIDiscoveryScanRequest::BAND_ALL) ||
        (validPhyModeTable[band][node.preamble][node.bandwidth] == LOWI_PHY_MODE_UNKNOWN))
    {
      break;
    }
    log_debug (TAG, "%s, Valid BW(%s), Channel(%u:%u) and preamble(%s) for AP:" LOWI_MACADDR_FMT,
               __FUNCTION__, LOWIUtils::to_string(node.bandwidth),
               chanInfo.mhz, chanInfo.band_center_freq1,
               LOWIUtils::to_string(node.preamble), LOWI_MACADDR(node.bssid));
    retVal = true;
  } while(0);

  if (retVal == false)
  {
    log_debug (TAG, "%s, Invalid BW(%s), Channel and preamble(%s), Aborting! AP:" LOWI_MACADDR_FMT
              " frequency: %u, center_freq1: %u",
              __FUNCTION__, LOWIUtils::to_string(node.bandwidth),
              LOWIUtils::to_string(node.preamble),
              LOWI_MACADDR(node.bssid),
              chanInfo.mhz, chanInfo.band_center_freq1);
  }

  return retVal;
}

bool LOWIRangingFSM::validRangingNode(LOWIRangingNode &rangingNode)
{
  FSM_ENTER()
  bool retVal = false;
  LOWINodeInfo &node = rangingNode.targetNode;

  do
  {
    if ((node.rttType < RTT1_RANGING) ||
        (node.rttType > RTT3_RANGING))
    {
      log_debug (TAG, "%s, Invalid Ranging type requested: %s",
                 __FUNCTION__,
                 LOWIStrings::to_string(node.rttType));
      break;
    }

    if (node.num_pkts_per_meas > MAX_RTT_MEAS_PER_DEST)
    {
      log_debug (TAG, "%s, Invalid number fo FTM frames requested: %u",
                 __FUNCTION__,
                 node.num_pkts_per_meas);
      break;
    }

    if (!validChannelBWPreambleCombo(rangingNode))
    {
     log_debug (TAG, "%s, Invalid Combination of Channel/BW/Preamble",
                __FUNCTION__);
     break;

    }
    if (node.frequency == BAND_2G_FREQ_LAST)
    {
      if (node.rttType == RTT3_RANGING)
      {
        log_debug (TAG, "%s, Reject 2 sided RTT for channel 14",
                   __FUNCTION__);
        break;
      }
      else if (!((node.rttType < RTT3_RANGING) &&
                 (node.bandwidth == BW_20MHZ) &&
                 (node.preamble == RTT_PREAMBLE_LEGACY)))
      {
        log_debug (TAG, "%s, reject one sided ranging request for channel 14"
                   "with BW %d and preamble %d",
                   __FUNCTION__, node.bandwidth, node.preamble);
        break;
      }
    }
    retVal = true;
  } while(0);

  FSM_EXIT()
  return retVal;
}

int LOWIRangingFSM::ValidateRangingRequest()
{
  FSM_ENTER()
  if ((mCurReq == NULL) ||
      (eRequestType != LOWIRequest::RANGING_SCAN))
  {
    log_debug(TAG, "%s: No New request to handle, Aborting call", __FUNCTION__);
    return -1;
  }
  vector <LOWIRangingNode>& v = mRomeRangingReq.vecRangingNodes;
  unsigned int numNonAsapTargets = 0;

  if (0 == v.getNumOfElements())
  {
    log_warning (TAG, "%s:No AP's in range request", __FUNCTION__);
    return -1;
  }
  else
  {
    for(unsigned int n = 0; n < v.getNumOfElements(); n++)
    {
      LOWINodeInfo& node = v[n].targetNode;
      /* Check if it is an ASAP 0 request */
      if (FTM_GET_ASAP(node.ftmRangingParameters) == 0 &&
          node.rttType == RTT3_RANGING)
      {
        numNonAsapTargets++;
      }

      if (0 != ValidatePeriodicity(node))
      {
        return -1;
      }
    }

    /* Only 1 ASAP 0 target allowed per request*/
    if (numNonAsapTargets > 1)
    {
      log_debug (TAG, "%s, Aborting, numNonAsapTargets: %u, Max supported = 1",
                 __FUNCTION__, numNonAsapTargets);
      return -1;
    }
  }

  FSM_EXIT()
  return 0;
}

int LOWIRangingFSM::ValidatePeriodicity(LOWINodeInfo const & /* info */)
{
  return 0;
}

bool LOWIRangingFSM::setPhyMode(LOWIRangingNode &rangingNode)
{
  bool retVal = false;
  eLOWIPhyMode phyMode = LOWI_PHY_MODE_11G;
  uint32 band = LOWIUtils::freqToBand(rangingNode.chanInfo.wmiChannelInfo.mhz);

  if ((LOWIUtils::freqToChannel(rangingNode.chanInfo.wmiChannelInfo.mhz) == 0) ||
      (rangingNode.targetNode.bandwidth <  BW_20MHZ) ||
      (rangingNode.targetNode.bandwidth >= BW_MAX) ||
      (rangingNode.targetNode.preamble  <  RTT_PREAMBLE_LEGACY) ||
      (rangingNode.targetNode.preamble  >= RTT_PREAMBLE_MAX) ||
      (band == LOWIDiscoveryScanRequest::BAND_ALL))
  {
    log_debug(TAG, "%s, Not a valid preamble/BW/Channel: channel: %u, preamble: %u, Bw: %u",
              __FUNCTION__,
              rangingNode.chanInfo.wmiChannelInfo.mhz,
              rangingNode.targetNode.preamble,
              rangingNode.targetNode.bandwidth);
  }
  else
  {
    wmi_channel chanInfo = rangingNode.chanInfo.wmiChannelInfo;
    eLOWIPhyMode lowiPhyMode = validPhyModeTable[band][rangingNode.targetNode.preamble][rangingNode.targetNode.bandwidth];
    phyMode = lowiPhyMode;
    // Handle Special 80 + 80 -> 160MHz case
    if ((phyMode == LOWI_PHY_MODE_11AC_VHT160) &&
        IS_VALID_80P80MHZ_CHAN_SPACING(chanInfo.mhz, chanInfo.band_center_freq1, chanInfo.band_center_freq2))
    {
      // change to 80 + 80 if band_center_frequency2 is non zero,
      // because this implies 160 MHz BW is achieved using 80 + 80
      phyMode = LOWI_PHY_MODE_11AC_VHT80_80;
    }
    /* Default to LOWI_PHY_MODE_11G if invalid preamble, BW & band combination */
    phyMode = (phyMode == LOWI_PHY_MODE_UNKNOWN) ? LOWI_PHY_MODE_11G : phyMode;
    log_debug(TAG, "%s: validPhyModeTable[] PhyMode - %s, phyMode set - %s", __FUNCTION__,
              LOWIUtils::to_string(lowiPhyMode), LOWIUtils::to_string(phyMode));
    retVal = true;
  }

  rangingNode.chanInfo.wmiChannelInfo.info &= PHY_MODE_MASK;
  rangingNode.chanInfo.wmiChannelInfo.info |= phyMode;
  return retVal;
}

int LOWIRangingFSM::AddTargetToResult(LOWINodeInfo node, LOWIScanMeasurement::eTargetStatus errorCode)
{
  log_debug(TAG, "%s: Add " LOWI_MACADDR_FMT " errorCode %d",
            __FUNCTION__, LOWI_MACADDR(node.bssid), errorCode);
  vector <LOWIScanMeasurement*> *scanMeasurements = &mLowiMeasResult->scanMeasurements;
  LOWIScanMeasurement* rangingMeasurement = new (std::nothrow) LOWIScanMeasurement;
  if (rangingMeasurement == NULL)
  {
    log_warning(TAG, "%s: rangingMeasurement - allocation faliure", __FUNCTION__);
    return -1;
  }
  rangingMeasurement->bssid.setMac(node.bssid);
  rangingMeasurement->frequency = node.frequency;
  rangingMeasurement->isSecure = false;
  rangingMeasurement->msapInfo = NULL;
  rangingMeasurement->cellPowerLimitdBm = 0;

  rangingMeasurement->type = ACCESS_POINT;
  rangingMeasurement->rttType = node.rttType;
  rangingMeasurement->num_frames_attempted = 0;
  rangingMeasurement->actual_burst_duration = 0;
  rangingMeasurement->negotiated_num_frames_per_burst = 0;
  rangingMeasurement->retry_after_duration = 0;
  rangingMeasurement->negotiated_burst_exp = 0;

  rangingMeasurement->targetStatus = errorCode;

  scanMeasurements->push_back(rangingMeasurement);

  return 0;

}

void LOWIRangingFSM::loadInfoFromCache(LOWIRangingNode &rangingNode,
                                                   LOWIScanMeasurement &scanMeasurement)
{
  rangingNode.chanInfo.wmiChannelInfo.mhz = scanMeasurement.frequency;
  rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 = 0;
  rangingNode.chanInfo.wmiChannelInfo.band_center_freq2 = 0;
  // Load Band Center Frequency based on requested BW from cache
  if(rangingNode.targetNode.bandwidth < BW_MAX)
  {
    rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 =
      scanMeasurement.band_center_freq1[rangingNode.targetNode.bandwidth];
  }

  // If requested BW doesn't have a valid band center frequency, set it to primary freq by default
  if(rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 == 0)
  {
    rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 = scanMeasurement.frequency;
  }
  if (rangingNode.targetNode.bandwidth == BW_160MHZ)
  {
    rangingNode.chanInfo.wmiChannelInfo.band_center_freq2 = scanMeasurement.band_center_freq2;
  }
  rangingNode.chanInfo.wmiChannelInfo.info = scanMeasurement.info;
}

int LOWIRangingFSM::PrepareRangingRequest()
{
  log_verbose(TAG, "%s", __FUNCTION__);
  if (mCurReq != NULL && (eRequestType == LOWIRequest::RANGING_SCAN))
  {
    if (0 != CheckRangingSupport())
    {
      return -1;
    }

    LOWIRangingScanRequest *rangingrequest = (LOWIRangingScanRequest *)mCurReq;
    vector<LOWINodeInfo> v = rangingrequest->getNodes();
    if (0 == v.getNumOfElements())
    {
      log_warning(TAG, "%s: No AP's in range request", __FUNCTION__);
      return -1;
    }

    mLowiMeasResult = new(std::nothrow) LOWIMeasurementResult;
    if (mLowiMeasResult == NULL)
    {
      log_debug(TAG, "%s:Ranging Measurment Results - allocation faliure", __FUNCTION__);
      return -1;
    }
    if (InitializeMeasResult(mLowiMeasResult) != 0)
    {
      log_info(TAG, "%s:initialize LOWI Meas Results - failed", __FUNCTION__);
      return -1;
    }
    log_verbose(TAG, "Ranging scan requested with : %u APs", v.getNumOfElements());

    mRomeRangingReq.vecRangingNodes.flush();
    for (unsigned int oof = 0; oof < v.getNumOfElements(); oof++)
    {
      LOWIScanMeasurement scanMeasurement;
      LOWIRangingNode rangingNode;
      wmi_channel &chanInfo = rangingNode.chanInfo.wmiChannelInfo;
      rangingNode.targetNode = v[oof];
      rangingNode.targetNode.interface = v[oof].interface;

      /* Skip target if it is not supported */
      if (false == targetParamsSupported(v[oof]))
      {
        AddTargetToResult(v[oof],
                          LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_TARGET_NOT_CAPABLE);
        continue;
      }

      uint32 chan = LOWIUtils::freqToChannel(v[oof].frequency);
      if (chan == 0 || chan > MAX_CHANNEL_ID)
      {
        return -1;
      }

      do
      {
        if (v[oof].paramControl == LOWI_USE_PARAMS_FROM_CACHE)
        {
          if (mCacheManager &&
              mCacheManager->getFromCache(v[oof].bssid, scanMeasurement) == true)
          {
            loadInfoFromCache(rangingNode, scanMeasurement);
            log_verbose(TAG, "%s: AP - " LOWI_MACADDR_FMT " Found in Cache",
                        __FUNCTION__, LOWI_MACADDR(v[oof].bssid));
            break;
          }
          else
          {
            log_verbose(TAG, "%s: AP - " LOWI_MACADDR_FMT " NOT Found in Cache",
                        __FUNCTION__, LOWI_MACADDR(v[oof].bssid));
            if ((LOWIUtils::freqToBand(v[oof].frequency) == LOWIDiscoveryScanRequest::FIVE_GHZ) &&
                (rangingNode.targetNode.bandwidth < BW_160MHZ))
            {
              chanInfo.mhz = v[oof].frequency;
              chanInfo.band_center_freq1 = LOWIUtils::getCenterFreq1(v[oof].frequency);
              chanInfo.band_center_freq2 = 0;
              chanInfo.info &= PHY_MODE_MASK;
              //! channel 165 supports only VHT20
              if (chanInfo.band_center_freq1 == 5825)
                chanInfo.info |= LOWI_PHY_MODE_11AC_VHT20;
              else
              chanInfo.info |= LOWI_PHY_MODE_11AC_VHT80;
              break;
            }
          }
        }
        chanInfo.mhz = v[oof].frequency;
        chanInfo.band_center_freq1 = v[oof].band_center_freq1;
        chanInfo.band_center_freq2 = v[oof].band_center_freq2;
        chanInfo.info = mChannelInfoArray[chan - 1].wmiChannelInfo.info;
        // set the phy mode for the case when no cache was used. When cache is used,
        // the phy mode is set inside loadInfoFromCache().
        setPhyMode(rangingNode);
      } while(0);

      chanInfo.reg_info_1 = mChannelInfoArray[chan - 1].wmiChannelInfo.reg_info_1;
      chanInfo.reg_info_2 = mChannelInfoArray[chan - 1].wmiChannelInfo.reg_info_2;

      eLOWIPhyMode pM = (eLOWIPhyMode)(chanInfo.info & ~PHY_MODE_MASK);
      log_verbose(TAG, "%s: AP: " LOWI_MACADDR_FMT " frequency: %u, phy mode: %s "
                  " %s Overwrite chanInfo from cache",
                  __FUNCTION__,
                  LOWI_MACADDR(v[oof].bssid),
                  v[oof].frequency,
                  LOWIUtils::to_string(pM),
                  (v[oof].paramControl == LOWI_USE_PARAMS_FROM_CACHE ? " " : "DONOT"));

      if (validRangingNode(rangingNode))
      {
        mRomeRangingReq.vecRangingNodes.push_back(rangingNode);
      }
      else
      {
        log_verbose(TAG, "%s: Invalid Ranging Target, skipping target: " LOWI_MACADDR_FMT,
                    __FUNCTION__,
                    LOWI_MACADDR(rangingNode.targetNode.bssid));
        AddTargetToResult(v[oof],
                          LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_TARGET_NOT_CAPABLE);
      }
    }

    /** Group APs by Channel Structure */
    for (unsigned int i = 0; i < MAX_DIFFERENT_CHANNELS_ALLOWED; i++)
    {
      mRomeRangingReq.arrayVecRangingNodes[i].flush();
    }
    mRomeRangingReq.totChs = groupByChannel(mRomeRangingReq.vecRangingNodes,
                                            &mRomeRangingReq.arrayVecRangingNodes[0],
                                            MAX_DIFFERENT_CHANNELS_ALLOWED);
    mRomeRangingReq.curChIndex = 0;
    mRomeRangingReq.totAp = mRomeRangingReq.arrayVecRangingNodes[mRomeRangingReq.curChIndex].getNumOfElements();
    mRomeRangingReq.curAp = 0;
    mRomeRangingReq.validRangingScan = TRUE;
    for (unsigned int foo = 0; foo < mRomeRangingReq.totChs; ++foo)
    {
      unsigned int apCount = mRomeRangingReq.vecChGroup[foo].getNumOfElements();
      for (unsigned int bar = 0; bar < apCount; bar++)
      {
        log_verbose(TAG, "BSSID: " LOWI_MACADDR_FMT "frequency: %u, Center Frequency 1: %u",
                    LOWI_MACADDR(mRomeRangingReq.arrayVecRangingNodes[foo][bar].targetNode.bssid),
                    mRomeRangingReq.arrayVecRangingNodes[foo][bar].chanInfo.wmiChannelInfo.mhz,
                    mRomeRangingReq.arrayVecRangingNodes[foo][bar].chanInfo.wmiChannelInfo.band_center_freq1);
      }
    }
  }
  else
  {
    log_debug(TAG, "%s:No New request", __FUNCTION__);
    return -1;
  }

  return 0;
}

unsigned int LOWIRangingFSM::groupByChannel(vector <LOWIRangingNode>& origVec,
                                         vector <LOWIRangingNode> *vec,
                                         unsigned int maxChannels)
{
  unsigned int chCount = 0;

  log_verbose (TAG, "%s:Num Aps: %u", __FUNCTION__, origVec.getNumOfElements());
  for(unsigned int i = 0; i < origVec.getNumOfElements(); ++i)
  {
    ChannelInfo chanInfo = origVec[i].chanInfo;
    log_verbose (TAG, "%s:Current AP's Frequency: %u, BSSID: " LOWI_MACADDR_FMT, __FUNCTION__,
                 chanInfo.wmiChannelInfo.mhz, LOWI_MACADDR(origVec[i].targetNode.bssid));

    if(chanInfo.wmiChannelInfo.mhz == 0)
    {
      /** Note:  This should never happen, but simply,
        *  continuing to gracefully handle this case
        */
        log_debug(TAG, "AP with Channel Frequency of 0 was sent for Ranging!");
        continue;
    }

    boolean found = false;
    /* Search already gathered channels (last discovered channel first) */
    if (chCount != 0)
    {
      for(int j = (chCount - 1); j >= 0; j--)
      {
        LOWIRangingNode& topNode = vec[j][0];

        if (memcmp(&(topNode.chanInfo), &chanInfo, sizeof(chanInfo)) == 0)
        {
          /* Match Found vector already exists so add to vector */
          log_verbose (TAG, "%s:Adding to existing vector [%u]",  __FUNCTION__, j);
          vec[j].push_back(origVec[i]);
          found = true;
          break;
        }
      }
    }
    if(found == false) /* No matching freq was found, create a new vector for this frequency */
    {
      chCount++;
      if(chCount < maxChannels)
      {
        vec[chCount - 1].push_back(origVec[i]);
        log_verbose (TAG, "%s:Creating new vector for new channel", __FUNCTION__);
      }
      else
      {
        log_debug (TAG, "%s:Reached MAX number of different Channels per RTT request!", __FUNCTION__);
        return chCount;
      }
    }
  }

  log_verbose(TAG, "%s - Tot Channels %u", __FUNCTION__, chCount);
  return chCount;
}

bool LOWIRangingFSM::targetParamsSupported(LOWINodeInfo &node)
{
  LOWI_RangingCapabilities lowiRangingCap;
  lowiRangingCap = GetRangingCap();
  bool supported = false;

  do
  {
    /* Check if the reqeusted Ranging Type is supported by HW */
    if ((false == lowiRangingCap.dualSidedSupported11mc) && (RTT3_RANGING == node.rttType))
    {

      log_debug (TAG, "%s: Dual sided RTT NOT supported "
                "Skipping AP - " LOWI_MACADDR_FMT, __FUNCTION__,
                LOWI_MACADDR(node.bssid));
      break;
    }
    /* Check if the requested Preamble  is supported by HW */
    if (!(lowiRangingCap.preambleSupport & (1 << node.preamble)))
    {
      log_debug (TAG, "%s: Preamble %s NOT supported (%x)"
                "Skipping this AP - " LOWI_MACADDR_FMT, __FUNCTION__,
                LOWIUtils::to_string(node.preamble),
                lowiRangingCap.preambleSupport,
                LOWI_MACADDR(node.bssid));
      break;
    }
    /* Check if the requested BW is supported by HW */
    if (node.bandwidth > lowiRangingCap.bwSupport)
    {
      log_debug (TAG, "%s: BW %s NOT supported (%s)"
                "Skipping this AP - " LOWI_MACADDR_FMT, __FUNCTION__,
                LOWIUtils::to_string(LOWIUtils::to_eRangingBandwidth(node.bandwidth)),
                LOWIUtils::to_string(LOWIUtils::to_eRangingBandwidth(lowiRangingCap.bwSupport)),
                LOWI_MACADDR(node.bssid));
      break;
    }
    /* Todo: Add check for Multiburst */

    /* If all above tests pass then set supported to true */
    supported = true;
  } while(0);

  return supported;
}

int LOWIRangingFSM::SendRangingReq()
{
  int retVal = 0;

  DestInfo   bssidsToScan[MAX_BSSIDS_TO_SCAN];
  vector <LOWIRangingNode>::Iterator it = mRomeRangingReq.arrayVecRangingNodes[mRomeRangingReq.curChIndex].begin();
  ChannelInfo chanInfo = (*it).chanInfo;
  unsigned int bssidIdx = 0;
  std::string interface = "wifi0";


  if (!mRangingReqRspInfo.lastResponseRecv)
  {
    /* Don't send another Request because FW is still handling previous request */
    log_debug(TAG, "%s:FW Still handling previous request", __FUNCTION__);
    return 0;
  }

  log_debug(TAG, "%s: curChIndex: %u, totChs: %u, curAp: %u, totAp: %u",
            __FUNCTION__, mRomeRangingReq.curChIndex,
            mRomeRangingReq.totChs,
            mRomeRangingReq.curAp,
            mRomeRangingReq.totAp);

  if ((mRomeRangingReq.curChIndex == 0) && (mRomeRangingReq.curAp == 0))
  {
    log_info(TAG, "%s: Starting RTT with %u APs over %u channels",__FUNCTION__,
             mRomeRangingReq.totAp, mRomeRangingReq.totChs);
  }
  mRangingReqRspInfo.nonAsapTargetPresent = FALSE;

  if (mRomeRangingReq.curChIndex < mRomeRangingReq.totChs &&
      mRomeRangingReq.curAp < mRomeRangingReq.totAp)
  {
    vector <LOWIRangingNode>& vNodes = mRomeRangingReq.arrayVecRangingNodes[mRomeRangingReq.curChIndex];
    unsigned int spaceLeftInRsp = MAX_WMI_MESSAGE_SIZE;
    while (mRomeRangingReq.curAp < mRomeRangingReq.totAp)
    {
      LOWIRangingNode & rangingNode = vNodes[mRomeRangingReq.curAp];
      unsigned int spaceNeeded = ExpectedMeasSizeForTarget(MIN(rangingNode.targetNode.num_pkts_per_meas, MAX_RTT_MEAS_PER_DEST),
                                                           rangingNode.targetNode.ftmRangingParameters);
      if ((spaceNeeded < spaceLeftInRsp) && (bssidIdx < MAX_BSSIDS_TO_SCAN))
      {
        spaceLeftInRsp -= spaceNeeded;
        log_verbose(TAG, "%s: Adding AP at index %d - spaceUsed: %u spaceLeftInRsp: %u",
                     __FUNCTION__, bssidIdx, spaceNeeded, spaceLeftInRsp);
      }
      else
      {
        log_verbose(TAG, "%s: Done with this request, AP Cnt %d, spaceUsed: %u, spaceLeftInRsp: %u",
                    __FUNCTION__, bssidIdx, spaceNeeded, spaceLeftInRsp);
        break;
      }
      interface = rangingNode.targetNode.interface;
      switch (rangingNode.targetNode.rttType)
      {
        case RTT3_RANGING:
        {
          bssidsToScan[bssidIdx].rttFrameType  = RTT_MEAS_FRAME_TMR;
          break;
        }
        case RTT1_RANGING:
        case RTT2_RANGING:
        case BEST_EFFORT_RANGING: /* For now Best effor will default to RTT V2 */
        default: /* This should never happen, but just in case RTTV2 is the default */
        {
          bssidsToScan[bssidIdx].rttFrameType  = RTT_MEAS_FRAME_QOSNULL;
          break;
        }
      }
      for (int ii = 0; ii < BSSID_LEN; ++ii)
      {
        bssidsToScan[bssidIdx].mac[ii]  = rangingNode.targetNode.bssid[ii];
      }
      bssidsToScan[bssidIdx].bandwidth = rangingNode.targetNode.bandwidth;
      bssidsToScan[bssidIdx].preamble  = rangingNode.targetNode.preamble;
      bssidsToScan[bssidIdx].numFrames = MIN(rangingNode.targetNode.num_pkts_per_meas, MAX_RTT_MEAS_PER_DEST);
      bssidsToScan[bssidIdx].numFrameRetries = rangingNode.targetNode.num_retries_per_meas;
      bssidsToScan[bssidIdx].vDevType = rangingNode.targetNode.nodeType;

      /* FTM Parameters*/
      bssidsToScan[bssidIdx].ftmParams = rangingNode.targetNode.ftmRangingParameters;
      bssidsToScan[bssidIdx].tsfDelta  = rangingNode.tsfDelta;
      bssidsToScan[bssidIdx].tsfValid  = rangingNode.tsfValid;
      bssidsToScan[bssidIdx].isQtiPeer = rangingNode.isQtiPeer;

      mRomeRangingReq.reportType = rangingNode.targetNode.reportType;
      /** Check if target is an ASAP 0 target */
      if ((rangingNode.targetNode.rttType == RTT3_RANGING) &&
          (FTM_GET_ASAP(rangingNode.targetNode.ftmRangingParameters) == 0))
      {
        mRangingReqRspInfo.nonAsapTargetPresent = TRUE;
      }

      mRomeRangingReq.curAp++;
      bssidIdx++;
    }

    log_verbose(TAG, "%s: Sending %u APs to FW for Ranging, ASAP %d",
                __FUNCTION__, bssidIdx, mRangingReqRspInfo.nonAsapTargetPresent);

    mRangingReqRspInfo.bssidCount = bssidIdx;
    mRangingReqRspInfo.measPerTarget = MAX_RTT_MEAS_PER_DEST;
    mRangingReqRspInfo.lastResponseRecv = FALSE;
    mRangingReqRspInfo.totalRspFromFw = 0;

    ++mRtsCtsTag; //Increment the tag before sending request to FW.
    // send the request for this set of targets
    retVal = SendRttRequest(chanInfo, bssidIdx, bssidsToScan, bssidsToScan, mRomeRangingReq.reportType, interface);

    /* If we still have APs left in the current channel */
    if (mRomeRangingReq.curAp < mRomeRangingReq.totAp)
    {
      log_verbose(TAG,"Staying on current Channel Channel");
    }
    else /* Move to APs on the next channel if we are done with all APs in this channel*/
    {
      mRomeRangingReq.curChIndex++;
      /* if we have Channels left, change AP count and iterator to the list of APs in the new Channel */
      if (mRomeRangingReq.curChIndex < mRomeRangingReq.totChs)
      {
        log_verbose(TAG,"Moving to Next Channel");
        mRomeRangingReq.curAp = 0;
        mRomeRangingReq.totAp = mRomeRangingReq.arrayVecRangingNodes[mRomeRangingReq.curChIndex].getNumOfElements();
      }
      else /* We are done with all channels, mark this request as invalid */
      {
        log_verbose(TAG,"Done with All channels and APs");
        mRomeRangingReq.validRangingScan = FALSE;
      }
    }
  }
  else
  {
    mRomeRangingReq.validRangingScan = FALSE;
    log_verbose(TAG," %s: not valid range scan", __FUNCTION__);
  }

  return retVal;
}

int LOWIRangingFSM::SendRttRequest(ChannelInfo chanInfo, unsigned int bssidIdx,
                                   DestInfo *bssidsToScan, DestInfo *spoofBssids, unsigned int reportType,
                                   std::string interface)
{
  int retVal = -1;

    retVal = mLOWIRanging->RomeSendRttReq(mRtsCtsTag,
                                          chanInfo,
                                          bssidIdx,
                                          bssidsToScan,
                                          spoofBssids,
                                          reportType,
                                          interface  );

  mRangingReqRspInfo.reportType = reportType;

  if(reportType == RTT_AGGREGATE_REPORT_NON_CFR)
  {
     mRangingReqRspInfo.expectedRspFromFw = RESP_REPORT_TYPE2;
  }
  else
  {
     mRangingReqRspInfo.expectedRspFromFw = (bssidIdx * MAX_RTT_MEAS_PER_DEST);
  }

  return retVal;
}

int LOWIRangingFSM::ProcessRangingMeas()
{
  log_verbose(TAG, "%s", __FUNCTION__);

  /* Increment the total number of Measurement responses received from FW */
  mRangingReqRspInfo.totalRspFromFw++;


  if (mLOWIRanging->RomeParseRangingMeas((char*)mRangingFsmData, &mLowiMeasResult->scanMeasurements) != 0)
  {
    log_info (TAG, "%s, Process Ranging Meas - Failed", __FUNCTION__);
    return -1;
  }

  return 0;
}
/*=============================================================================================
 * Function description:
 *   Waits on the Private Netlink Socket and the LOWI controller pipe.
 *   If Messages/Data arrive, collects and processes them accordingly.
 *   If LOWI controller requests a shutdown then exits and picks up the new pequest to process
 *
 * Return value:
 *    error code
 *
 =============================================================================================*/
int LOWIRangingFSM::ListenForEvents()
{
  FSM_ENTER()
  int retVal = -1;

  int timeout_val = SELECT_TIMEOUT_NEVER;

  if (mRangingFsmContext.timeEnd)
  {
    uint64 timeNow = get_time_rtc_ms();
    timeout_val = (mRangingFsmContext.timeEnd - timeNow) / 1000;
    log_verbose(TAG, "%s:Time left to wait: %u sec.\n", __FUNCTION__, timeout_val);
  }

  if (NULL != mLOWIRanging)
  {
    retVal = mLOWIRanging->RomeWaitOnActivityOnSocketOrPipe(timeout_val);
  }

  if(retVal > 0) /* Some Valid Message Arrived on Socket */
  {
    RomeNlMsgType msgType;
    log_verbose(TAG, "%s: Valid message received on Socket \n", __FUNCTION__);
    mLOWIRanging->RomeNLRecvMessage(&msgType, mRangingFsmData, sizeof(mRangingFsmData));
    mRangingFsmContext.curEvent = RomeCLDToRomeFSMEventMap[msgType];
  }
  else if(retVal == ERR_SELECT_TIMEOUT)      /* Timeout Occured */
  {
    log_debug(TAG, "%s: Timeout for netlink socket msg \n", __FUNCTION__);
    mRangingFsmContext.curEvent = EVENT_TIMEOUT;
  }
  else if(retVal == ERR_SELECT_TERMINATED)   /* Shutdown Through Pipe */
  {
    if (mRangingPipeEvents == TERMINATE_THREAD)
    {
      mRangingFsmContext.curEvent = EVENT_TERMINATE_REQ;
    }
    else if (mRangingPipeEvents == NEW_REQUEST_ARRIVED)
    {
      LowiReqToEvent(mNewReq);
    }
    log_verbose(TAG, "%s: Got Event over PIPE from controller: %s", __FUNCTION__,
                LOWIStrings::to_string(mRangingFsmContext.curEvent));
  }
  else                                       /* Some Error Occured */
  {
    log_warning(TAG, "%s: %s %d", __FUNCTION__,
                retVal == ERR_NOT_READY ? "Driver not ready" :
                "Error when waiting for event", retVal);
    mRangingFsmContext.curEvent = EVENT_NOT_READY;
  }

  FSM_EXIT()
  return retVal;
}

int LOWIRangingFSM::LowiReqToEvent(const LOWIRequest * const pReq)
{
  int ret_val = -1;
  if (NULL == pReq)
  {
    mRangingFsmContext.curEvent = EVENT_INVALID_REQ;
  }
  else if (mRangingFsmContext.curState >= STATE_READY_AND_IDLE)
  {
    eRequestType = pReq->getRequestType();
    mCurReq = mNewReq;
    switch(pReq->getRequestType())
    {
      case LOWIRequest::RANGING_SCAN:
        {
          mRangingFsmContext.curEvent = EVENT_RANGING_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::SET_LCI_INFORMATION:
        {
          mRangingFsmContext.curEvent = EVENT_CONFIGURATION_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::LOWI_RTT_RM_CHANNEL_REQUEST:
        {
          mRangingFsmContext.curEvent = EVENT_RTT_AVAILABLE_CHANNEL_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::LOWI_ENABLE_RESPONDER_REQUEST:
        {
          mRangingFsmContext.curEvent = EVENT_ENABLE_RESPONDER_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::LOWI_DISABLE_RESPONDER_REQUEST:
        {
          mRangingFsmContext.curEvent = EVENT_DISABLE_RESPONDER_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::LOWI_START_RESPONDER_MEAS_REQUEST:
        {
          mRangingFsmContext.curEvent = EVENT_START_RESPONDER_MEAS_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::LOWI_STOP_RESPONDER_MEAS_REQUEST:
        {
          mRangingFsmContext.curEvent = EVENT_STOP_RESPONDER_MEAS_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::SET_LCR_INFORMATION:
        {
          mRangingFsmContext.curEvent = EVENT_CONFIGURATION_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::SEND_LCI_REQUEST:
        {
          mRangingFsmContext.curEvent = EVENT_CONFIGURATION_REQ;
          ret_val = 0;
        }
        break;
      case LOWIRequest::FTM_RANGE_REQ:
        {
          mRangingFsmContext.curEvent = EVENT_CONFIGURATION_REQ;
          ret_val = 0;
        }
        break;
      default:
        {
          mRangingFsmContext.curEvent = EVENT_INVALID_REQ;
        }
        break;
    }
    SetLOWIRequest(NULL);
  }
  else
  {
    mRangingFsmContext.curEvent = EVENT_RANGING_REQ;
  }
  return ret_val;
}

int LOWIRangingFSM::FSM()
{
  int retVal = -1;
  do
  {
    log_debug(TAG, "%s: Received Event %s, Current state: %s", __FUNCTION__,
             LOWIStrings::to_string(mRangingFsmContext.curEvent),
             LOWIStrings::to_string(mRangingFsmContext.curState));

    if (mRangingFsmContext.curState < STATE_MAX &&
        mRangingFsmContext.curEvent < EVENT_MAX)
    {
      retVal = stateTable[mRangingFsmContext.curState][mRangingFsmContext.curEvent](this);
      log_debug(TAG, "%s: New FSM state: %s", __FUNCTION__,
               LOWIStrings::to_string(mRangingFsmContext.curState));
    }
    else
    {
      log_warning(TAG, "%s:Received a bad State: %u or Event: %u", __FUNCTION__,
                  mRangingFsmContext.curState, mRangingFsmContext.curEvent);
    }

    /* Check to see if there any any pending internal Events */
    if (mRangingFsmContext.internalFsmEventPending)
    {
      /* clear the flag and allow the event to be procesed by FSM */
      clearFsmInternalEvent();
    }
    else
    {
      /** After FSM has processed current event, wait listening for
       *  new events from Timer, NL socket & LOWI Controller */
      ListenForEvents();
    }
    /** If a terminate request arrived then stop FSM and return
     *  to caller */
    if (mRangingFsmContext.curEvent == EVENT_TERMINATE_REQ)
    {
      log_debug(TAG, "%s: Received Terminate Thread request from Controller",
                __FUNCTION__);
      break;
    }

  } while(1);
  return retVal;
}

int LOWIRangingFSM::SetNewPipeEvent(RangingPipeEvents newEvent)
{
  mRangingPipeEvents = newEvent;
  return mLOWIRanging->RomeUnblockRangingThread();
}

LOWIRangingFSM* LOWIRangingFSM::createInstance(LOWIScanResultReceiverListener *scanResultListener,
                                               LOWICacheManager *cacheManager,
                                               LOWIRanging *lowiRanging,
                                               LOWIRangingFSM::eLowiRangingInterface lowiRangingInterface)
{
  LOWIRangingFSM *fsmInstance = NULL;
  switch (lowiRangingInterface)
  {
    case LOWIRangingFSM::LOWI_ROME_RANGING_INTERFACE:
      if (NULL == mWifiInstance)
      {
        mWifiInstance = new LOWIRangingFSM(scanResultListener, cacheManager, lowiRanging);
      }
      fsmInstance = mWifiInstance;
      break;

      case LOWIRangingFSM::LOWI_PRONTO_RANGING_INTERFACE:
#if !defined(LOWI_ON_ACCESS_POINT) && !defined(LOWI_ON_LE)
      if (NULL == mWifiInstance)
      {
        mWifiInstance = new LOWIRangingProntoFSM(scanResultListener, cacheManager, lowiRanging);
      }
      fsmInstance = mWifiInstance;
#endif
      break;

    case LOWIRangingFSM::LOWI_HELIUM_RANGING_INTERFACE:
      if (NULL == mWifiInstance)
      {
        mWifiInstance = new LOWIRangingHeliumFSM(scanResultListener, cacheManager, lowiRanging);
      }
      fsmInstance = mWifiInstance;
      break;

    case LOWIRangingFSM::LOWI_SPARROW_RANGING_INTERFACE:
#if !defined(LOWI_ON_ACCESS_POINT) && !defined(LOWI_ON_LE)
      if (NULL == mWigigInstance)
      {
        mWigigInstance = new LOWIRangingSparrowFSM(scanResultListener, cacheManager, lowiRanging);
      }
      fsmInstance = mWigigInstance;
#endif
      break;

    default:
      log_debug(TAG, "%s: LOWI Ranging Interface Unknown", __FUNCTION__);
      break;
  }

  if (NULL == fsmInstance)
  {
    log_warning(TAG, "Failed to create FSM of type: %d", lowiRangingInterface);
  }
  return fsmInstance;
} // createInstance

int LOWIRangingFSM::ProcessResponderChannelMeas()
{
  return 0;
}

int LOWIRangingFSM::CheckRangingSupport()
{
  if (mRomeRttCapabilities.rangingTypeMask == 0)
  {
    // No support for Ranging
    log_debug(TAG, "Ranging Not supported: %d",
              mRomeRttCapabilities.rangingTypeMask);
    return -1;
  }
  return 0;
}

