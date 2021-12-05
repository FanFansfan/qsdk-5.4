/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWIRangingHeliumFSM class implementation

GENERAL DESCRIPTION
  This file contains the implementation for the LOWIRangingHeliumFSM class

  Copyright (c) 2016-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc
=============================================================================*/
#include <base_util/log.h>
#include <common/lowi_utils.h>
#include "lowi_helium_ranging.h"
#include "lowi_ranging_helium_fsm.h"
#include "innavService.h"
#include "lowi_time.h"
#include <lowi_strings.h>

#include <base_util/time_routines.h>

// Enter/Exit debug macros
#undef ALLOW_ENTER_EXIT_DBG_RANGING_HELIUM_FSM

#ifdef ALLOW_ENTER_EXIT_DBG_RANGING_HELIUM_FSM
#define HFSM_ENTER() log_verbose(TAG, "ENTER: %s", __FUNCTION__);
#define HFSM_EXIT()  log_verbose(TAG, "EXIT: %s", __FUNCTION__);
#else
#define HFSM_ENTER()
#define HFSM_EXIT()
#endif

#define LOWI_RTT_RESPONDER_MAX_DURATION_SECS 3600

using namespace qc_loc_fw;
extern eRangingBandwidth validBWTable[LOWI_PHY_MODE_MAX+1][LOWIDiscoveryScanRequest::BAND_ALL];

const char * const LOWIRangingHeliumFSM::TAG = "LOWIRangingHeliumFSM";

LOWIReqInfo::LOWIReqInfo(LOWIMacAddress macaddr, LOWIRequest *request)
{
  req = request;
  macAddr = macaddr;
}

LOWIReqInfo::~LOWIReqInfo()
{
}

LOWIRangingHeliumFSM::LOWIRangingHeliumFSM(LOWIScanResultReceiverListener *scanResultListener,
                                           LOWICacheManager *cacheManager,
                                           LOWIRanging *lowiRanging)
:LOWIRangingFSM(scanResultListener, cacheManager, lowiRanging)
{
  log_verbose(TAG, "%s: ctor", __FUNCTION__);
  mPeriodicReq = false;
  mLastMeas = false;
  SetupFsm();
}

LOWIRangingHeliumFSM::~LOWIRangingHeliumFSM()
{
  log_verbose(TAG, "%s: dtor", __FUNCTION__);
}

void LOWIRangingHeliumFSM::SetupFsm()
{
  log_verbose(TAG, "%s: setupfsm", __FUNCTION__);
  /***************** State Functions for State: STATE_IDLE_START *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */    /** Trigger Event */                                  /** Action Function */
  stateTable[STATE_IDLE_START]   [EVENT_ENABLE_RESPONDER_REQ]                             = SendEnableResponderReq;
  stateTable[STATE_IDLE_START]   [EVENT_DISABLE_RESPONDER_REQ]                            = SendDisableResponderReq;
  stateTable[STATE_IDLE_START]   [EVENT_START_RESPONDER_MEAS_REQ]                         = SendResponderMeasStartReq;
  stateTable[STATE_IDLE_START]   [EVENT_RTT_AVAILABLE_CHANNEL_REQ]                        = SendRTTAvailableChannelReq;

  /** -- Events from LOWI Controller -- */
             /** Current State */                 /** Trigger Event */                      /** Action Function */
  stateTable[STATE_WAITING_FOR_RTT_CHANNEL_INFO]   [EVENT_RTT_AVAILABLE_CHANNEL_INFO]     = HandleRTTAvailableChannelRsp;
  stateTable[STATE_WAITING_FOR_RTT_CHANNEL_INFO]   [EVENT_RESPONDER_CHANNEL_INFO]         = HandleResponderChannelRsp;
  stateTable[STATE_WAITING_FOR_RTT_CHANNEL_INFO]   [EVENT_TIMEOUT]                        = HandleNlTimeout;
  stateTable[STATE_WAITING_FOR_RTT_CHANNEL_INFO]   [EVENT_CLD_ERROR_MESSAGE]              = HandleCldErrorMsg;
  stateTable[STATE_WAITING_FOR_RTT_CHANNEL_INFO]   [EVENT_RANGING_ERROR]                  = HandleRangingErrorMsg;
  stateTable[STATE_WAITING_FOR_RTT_CHANNEL_INFO]   [EVENT_REGISTRATION_FAILURE_OR_LOST]   = HandleRegFailureOrLost;
  stateTable[STATE_PROCESSING_RESPONDER_CONFIG_REQ] [EVENT_CFG_RESPONDER_MEAS_RSP]         = HandleConfigResponderMeasRsp;
  stateTable[STATE_PROCESSING_RESPONDER_MEAS_INFO]  [EVENT_RESPONDER_MEAS_INFO]            = HandleRangingMeas; /* Use appropriate func*/
  stateTable[STATE_PROCESSING_RESPONDER_MEAS_INFO]  [EVENT_STOP_RESPONDER_MEAS_REQ]        = SendResponderMeasStopReq;

  /***************** State Functions for State: STATE_READY_AND_IDLE *************/
  /** -- Events from LOWI Controller -- */
             /** Current State */    /** Trigger Event */                                  /** Action Function */
  stateTable[STATE_READY_AND_IDLE]   [EVENT_ENABLE_RESPONDER_REQ]                         = SendEnableResponderReq;
  stateTable[STATE_READY_AND_IDLE]   [EVENT_DISABLE_RESPONDER_REQ]                        = SendDisableResponderReq;
  stateTable[STATE_READY_AND_IDLE]   [EVENT_START_RESPONDER_MEAS_REQ]                     = SendResponderMeasStartReq;
  stateTable[STATE_READY_AND_IDLE]   [EVENT_STOP_RESPONDER_MEAS_REQ]                      = SendResponderMeasStopReq;
  stateTable[STATE_READY_AND_IDLE]   [EVENT_RTT_AVAILABLE_CHANNEL_REQ]                    = SendRTTAvailableChannelReq;
}

int LOWIRangingHeliumFSM::SendRttRequest(ChannelInfo chanInfo, unsigned int bssidIdx,
                                         DestInfo *bssidsToScan, DestInfo *spoofBssids, unsigned int reportType,
                                         std::string interface)
{
  HFSM_ENTER()
  int retVal = -1;

  if ((reportType == RTT_REPORT_PER_FRAME_WITH_CFR) ||
      (reportType == RTT_REPORT_PER_FRAME_WITH_CFR_CIR))
  {
    retVal = mLOWIRanging->RomeSendRttReq(mRtsCtsTag,
                                          chanInfo,
                                          bssidIdx,
                                          bssidsToScan,
                                          spoofBssids,
                                          reportType,
                                          interface);

    mRangingReqRspInfo.reportType = reportType;
    mRangingReqRspInfo.expectedRspFromFw = (bssidIdx * MAX_RTT_MEAS_PER_DEST);
  }
  else if (!mPeriodicReq)
  {
    retVal = mLOWIRanging->RomeSendRttReq(mRtsCtsTag,
                                          chanInfo,
                                          bssidIdx,
                                          bssidsToScan,
                                          spoofBssids,
                                          RTT_AGGREGATE_REPORT_NON_CFR,
                                          interface);

    mRangingReqRspInfo.reportType = RTT_AGGREGATE_REPORT_NON_CFR;
    mRangingReqRspInfo.expectedRspFromFw = RESP_REPORT_TYPE2;
  }
  else if (mPeriodicReq)
  {
    retVal = mLOWIRanging->RomeSendRttReq(mRtsCtsTag,
                                          chanInfo,
                                          bssidIdx,
                                          bssidsToScan,
                                          spoofBssids,
                                          RTT_REPORT_PER_BURST_NON_CFR,
                                          interface);
    log_verbose(TAG,"setting rprtType to RTT_REPORT_PER_BURST_NON_CFR");
    mRangingReqRspInfo.reportType = RTT_REPORT_PER_BURST_NON_CFR;
    mRangingReqRspInfo.expectedRspFromFw = RESP_REPORT_TYPE2; // still expect just one response for now
  }

  HFSM_EXIT()

  return retVal;
}

int LOWIRangingHeliumFSM::ValidatePeriodicity(LOWINodeInfo const &info)
{
  HFSM_ENTER()

  int retVal = -1;

  do
  {
    if (isTargetPeriodic(info))
    {
      // check periodic parameters
      if (validPeriodicParams(info))
      {
        if(mCurReq == NULL && (eRequestType != LOWIRequest::RANGING_SCAN))
        {
          log_warning(TAG, "%s: not a valid request", __FUNCTION__);
          break;
        }
        // store target info so it can be managed as responses come in
        LOWIReqInfo *reqInfo = new(std::nothrow) LOWIReqInfo(info.bssid, mCurReq);
        if (reqInfo == NULL)
        {
          log_warning(TAG, "%s: reqinfo mem alloc failure", __FUNCTION__);
          break;
        }
        mPendingReq.add(reqInfo);
        mPeriodicReq = true;
        log_verbose(TAG, "%s: Adding periodic nodes to pendingReq", __FUNCTION__);
        retVal = 0;
      }
      else
      {
        log_debug(TAG, "%s: Invalid periodic params", __FUNCTION__);
      }
    }
    retVal = 0;
  } while (0);

  HFSM_EXIT()
  return retVal;
}

int LOWIRangingHeliumFSM::SendReqToFwOrRespToUser()
{
  HFSM_ENTER()

  if (mRangingFsmContext.curEvent == EVENT_RANGING_MEAS_RECV)
  {
    // check if last measurement finished
    mRangingReqRspInfo.lastResponseRecv = mLastMeas;
  }
  else
  {
    /* check to see if all expected Responses from FW have arrived */
    mRangingReqRspInfo.lastResponseRecv = (mRangingReqRspInfo.totalRspFromFw == mRangingReqRspInfo.expectedRspFromFw);
  }

  /* All Expected responses have arrived from FW */
  if (mRangingReqRspInfo.lastResponseRecv)
  {
    /* Send another Ranging Request to FW if the Ranging request is still valid */
    if (mRomeRangingReq.validRangingScan)
    {
      if(SendRangingReq() != 0)
      {
        log_warning(TAG, "%s: Send Ranging Request Failed, Aborting current request", __FUNCTION__);
        /* Done with the Ranging Request - Respond to User */
        (mLowiMeasResult)->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
        mRangingFsmContext.timeEnd    = ROME_FSM_TIMEOUT_FOREVER;
        mRangingFsmContext.curEvent   = EVENT_RANGING_RESPONSE_TO_USER;
        mRangingFsmContext.curState   = STATE_READY_AND_IDLE;
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
      log_info(TAG, "%s: All ranging measurments completed.Send response to client", __FUNCTION__);
      (mLowiMeasResult)->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
      mRangingFsmContext.timeEnd  = ROME_FSM_TIMEOUT_FOREVER;
      mRangingFsmContext.curEvent = EVENT_RANGING_RESPONSE_TO_USER;
      mRangingFsmContext.curState = STATE_READY_AND_IDLE;
      /* Send Result to User */
      SendResultToClient(mLowiMeasResult);
    }
  }
  else /* Still expecting responses from FW */
  {
    log_verbose(TAG, "%s: Expecting more responses from FW...", __FUNCTION__);
  }

  if (mLastMeas)
  {
    mLastMeas = false;
  }
  HFSM_EXIT()
  return 0;
}

int LOWIRangingHeliumFSM::ProcessRangingMeas()
{
  HFSM_ENTER()
  // FIXME Expect mLastMeas from firmware , based on the mLast we will
  // send the respose to Scheduler for cfrmode
  if((mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_WITH_CFR) ||
     (mRangingReqRspInfo.reportType == RTT_REPORT_PER_FRAME_WITH_CFR_CIR))
  {
    mRangingReqRspInfo.totalRspFromFw++;
  }

  if (mLOWIRanging->RomeParseRangingMeas((char *)mRangingFsmData,
                                         &mLowiMeasResult->scanMeasurements,
                                         mLastMeas, mRangingReqRspInfo.reportType) != 0)
  {
    log_info (TAG, "%s: Parse Ranging Meas from FW! - Failed", __FUNCTION__);
    mLastMeas = true; // Do not expect more measurements in error scenario
    return -1;
  }

  if (mLastMeas)
  {
    log_verbose(TAG, "%s: Received last fragment from FW ", __FUNCTION__);
    /* Increment the total number of Measurement responses received from FW */
    mRangingReqRspInfo.totalRspFromFw++;
  }

  HFSM_EXIT()
  return 0;
}
bool LOWIRangingHeliumFSM::isTargetPeriodic(LOWINodeInfo const &node)
{
  HFSM_ENTER()
  uint32 numBursts = FTM_GET_BURSTS_EXP(node.ftmRangingParameters);
  bool retVal = (numBursts == MIN_NUM_BURST_EXP) ? false : true;

  HFSM_EXIT()
  return retVal;
}

bool LOWIRangingHeliumFSM::validPeriodicParams(LOWINodeInfo const &node)
{
  bool retVal = false;

  do
  {
    // num burst exponent check
    uint32 numBurstExp = FTM_GET_BURSTS_EXP(node.ftmRangingParameters);
    if (numBurstExp > MAX_NUM_BURST_EXP)
    {
      log_debug(TAG, "%s: num burst exponent out of range(%u), allowed max(%u)",
                __FUNCTION__, numBurstExp, MAX_NUM_BURST_EXP);
      break;
    }

    // burst_period check
    uint32 burstPeriod = FTM_GET_BURST_PERIOD(node.ftmRangingParameters);
    if (burstPeriod > MAX_BURST_PERIOD)
    {
      log_debug(TAG, "%s: burst period out of range(%u), allowed max(%u)",
                __FUNCTION__, burstPeriod, MAX_BURST_PERIOD);
      break;
    }

    // num_frames_per_burst check
    if ((node.num_pkts_per_meas < MIN_FRAMES_PER_BURST) ||
        (node.num_pkts_per_meas > MAX_FRAMES_PER_BURST))
    {
      log_debug(TAG, "%s: num frames per burst out of range(%u), allowed max(%u)",
                __FUNCTION__, node.num_pkts_per_meas, MAX_FRAMES_PER_BURST);
      break;
    }

    // burst_duration check
    uint32 burstDur = FTM_GET_BURST_DUR(node.ftmRangingParameters);

    // check for no preference option with single-sided RTT
    if (node.rttType == RTT2_RANGING && burstDur == BURST_DURATION_NO_PREFERENCE)
    {
      log_debug(TAG, "%s: 1-sided RTT, got illegal burst_duration: no preference", __FUNCTION__);
      break;
    }
    // boundary and acceptable values check
    if ((burstDur < MIN_BURST_DURATION || burstDur > MAX_BURST_DURATION) &&
              burstDur != BURST_DURATION_NO_PREFERENCE)
    {
      log_debug(TAG, "%s: burst duration out of range or invalid(%u), allowed max(%u)",
                __FUNCTION__, burstDur, MAX_BURST_DURATION);
      break;
    }

    retVal = true; // all periodic parameters are within acceptable boundaries
  } while (0);

  return retVal;
}

unsigned int LOWIRangingHeliumFSM::ExpectedMeasSizeForTarget(unsigned int /* numMeas */,
                                                             uint32 /* ftmRangingParams */)
{
  // Since Helium uses fragmentation, we don't care about expected size.
  // The limit is solely due to number of APs.
  return 0;
}
int LOWIRangingHeliumFSM::HandleRTTAvailableChannelRsp(LOWIRangingFSM* pFsmObj)
{
  HFSM_ENTER()
  log_verbose(TAG, "%s", __FUNCTION__);
  if (NULL == pFsmObj)
  {
    log_warning(TAG, "%s: Invalid FSM Object", __FUNCTION__);
    return -1;
  }
  pFsmObj->mLowiMeasResult = new (std::nothrow) LOWIMeasurementResult;
  if (pFsmObj->mLowiMeasResult == NULL)
  {
        log_debug(TAG, "%s channel info Results - alloc failure", __FUNCTION__);
        return -1;
  }
  if(pFsmObj->mCurReq && (pFsmObj->eRequestType == LOWIRequest::LOWI_RTT_RM_CHANNEL_REQUEST))
  {
    pFsmObj->mLowiMeasResult->request = pFsmObj->mCurReq;
    if(pFsmObj->ProcessResponderChannelMeas() != 0)
    {
      log_info(TAG, "%s Process STA channel Measurements - Failed", __FUNCTION__);
    }
  }
  else
  {
    log_debug(TAG, "%s wrong request", __FUNCTION__);
    return -1;
  }
  HFSM_EXIT()
  return 0;
}

void LOWIRangingHeliumFSM::loadInfoFromCache(LOWIRangingNode &rangingNode,
                                             LOWIScanMeasurement &scanMeasurement)
{
  // set up default frequencies
  rangingNode.chanInfo.wmiChannelInfo.mhz = scanMeasurement.frequency;
  rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 = scanMeasurement.frequency;
  rangingNode.chanInfo.wmiChannelInfo.band_center_freq2 = 0;
  bool apSupport = false;

  // retrieve phy mode supported by AP
  eLOWIPhyMode pM = (eLOWIPhyMode)(scanMeasurement.info & ~PHY_MODE_MASK);

  // check whether the target AP supports the packet BW in the request. This flag
  // will be checked when the ranging node is validated later on.
  apSupport = bwSupportedByAP(rangingNode.targetNode, pM);

  // get the frequency band and proceed accordingly
  uint32 band = LOWIUtils::freqToBand(scanMeasurement.frequency);

  if (LOWIDiscoveryScanRequest::FIVE_GHZ == band)
  {
    // By default, use VHT80 phy mode and set center_freq1 accordingly. The exception
    // will be if the target AP does not support the packet BW requested. In that case,
    // center_freq1 == primary center frequency and the request will be rejected when
    // the node request is validated later on.
    if (apSupport)
    {
      rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 =
        LOWIUtils::getCenterFreq1(rangingNode.chanInfo.wmiChannelInfo.mhz);
    }
    // set the phy mode
    rangingNode.chanInfo.wmiChannelInfo.info &= PHY_MODE_MASK;
    // channel 165 supports only VHT20
    if (rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 == 5825)
      rangingNode.chanInfo.wmiChannelInfo.info |= LOWI_PHY_MODE_11AC_VHT20;
    else
    rangingNode.chanInfo.wmiChannelInfo.info |= LOWI_PHY_MODE_11AC_VHT80;
  }
  else if (LOWIDiscoveryScanRequest::TWO_POINT_FOUR_GHZ == band)
  {
    if (rangingNode.targetNode.bandwidth < BW_MAX)
    {
      // By default, use the pkt BW to determine the center_freq1
      rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 =
        scanMeasurement.band_center_freq1[rangingNode.targetNode.bandwidth];
    }
    // set the phy mode
    rangingNode.chanInfo.wmiChannelInfo.info = scanMeasurement.info;
  }

  // Exception case:
  // If highest phy mode supported by the target AP is 160, use that only
  // if the requested RTT packet bw is also 160MHz.
  if ((rangingNode.targetNode.bandwidth == BW_160MHZ) &&
      ((LOWI_PHY_MODE_11AC_VHT160   == pM) ||
       (LOWI_PHY_MODE_11AC_VHT80_80 == pM)))
  {
    // set the frequencies
    rangingNode.chanInfo.wmiChannelInfo.band_center_freq1 =
      scanMeasurement.band_center_freq1[BW_160MHZ];
    rangingNode.chanInfo.wmiChannelInfo.band_center_freq2 =
      scanMeasurement.band_center_freq2;
    // set the phy mode
    rangingNode.chanInfo.wmiChannelInfo.info = scanMeasurement.info;
  }

  /* Load Peer information from Cache */
  rangingNode.isQtiPeer = (scanMeasurement.peerOEM == LOWIScanMeasurement::LOWI_PEER_OEM_QTI);
} // loadInfoFromCache

bool LOWIRangingHeliumFSM::validChannelPhyModeCombo(eLOWIPhyMode phyMode, uint32 primary_freq,
                                                    uint32 center_freq1, uint32 center_freq2)
{
  bool retVal = false;

  // Ensure that the channel spacing requested matches the correct phy mode
  switch (phyMode)
  {
    case LOWI_PHY_MODE_11A:
    case LOWI_PHY_MODE_11NA_HT20:
    case LOWI_PHY_MODE_11AC_VHT20:
    case LOWI_PHY_MODE_11G:
    case LOWI_PHY_MODE_11NG_HT20:
    case LOWI_PHY_MODE_11AC_VHT20_2G:
    {
      // For 20MHz phy modes, only allow center frequency of 0 or same as primary
      retVal = IS_VALID_20MHZ_CHAN_SPACING(primary_freq, center_freq1);
      break;
    }
    case LOWI_PHY_MODE_11NA_HT40:
    case LOWI_PHY_MODE_11AC_VHT40:
    case LOWI_PHY_MODE_11NG_HT40:
    case LOWI_PHY_MODE_11AC_VHT40_2G:
    {
      // For 40MHz phy modes, only allow center frequency of primary +/- 10 MHz
      retVal = IS_VALID_40MHZ_CHAN_SPACING(primary_freq, center_freq1);
      break;
    }
    case LOWI_PHY_MODE_11AC_VHT80:
    case LOWI_PHY_MODE_11AC_VHT80_2G:
    {
      // For 80MHz phy modes, only allow center frequency +/- 10 MHz OR Primary +/- 30 MHz
      retVal = IS_VALID_80MHZ_CHAN_SPACING(primary_freq, center_freq1);
      break;
    }
    case LOWI_PHY_MODE_11AC_VHT160:
    {
      // For 160MHz phy mode operation should be one single 160MHz Band
      retVal = IS_VALID_160MHZ_CHAN_SPACING(primary_freq, center_freq1, center_freq2);
      break;
    }
    case LOWI_PHY_MODE_11AC_VHT80_80:
    {
      // For 160MHz (80 + 80) phy mode operation should be 80 + 80
      retVal = IS_VALID_80P80MHZ_CHAN_SPACING(primary_freq, center_freq1, center_freq2);
      break;
    }
    default:
    {
      /* Invalid phy mode - Do Nothing */
      log_debug (TAG, "%s, Invalid phy mode (%s)", __FUNCTION__);
      break;
    }
  }
  return retVal;
} // validChannelPhyModeCombo

bool LOWIRangingHeliumFSM::validChannelBWPreambleCombo(LOWIRangingNode targetNode)
{
  bool retVal = false;
  wmi_channel &chanInfo = targetNode.chanInfo.wmiChannelInfo;
  eLOWIPhyMode pM = (eLOWIPhyMode)(chanInfo.info & ~PHY_MODE_MASK);
  LOWINodeInfo &node = targetNode.targetNode;

  do
  {
    /* Ensure Preamble requested by user is within the supported range */
    if (node.preamble < RTT_PREAMBLE_LEGACY ||
        node.preamble > RTT_PREAMBLE_VHT)
    {
      log_debug (TAG, "%s: Invalid preamble(%s), aborting! AP:" LOWI_MACADDR_FMT,
                 __FUNCTION__, LOWIUtils::to_string(node.preamble), LOWI_MACADDR(node.bssid));
      break;
    }

    // The check between 5G and 2G channels is different because we're not assigning the
    // phy mode in the same way.
    uint32 band = LOWIUtils::freqToBand(chanInfo.mhz);
    if (LOWIDiscoveryScanRequest::FIVE_GHZ == band)
    {
      if (!validChannelPhyModeCombo(pM, chanInfo.mhz, chanInfo.band_center_freq1,
                                    chanInfo.band_center_freq2))
      {
        log_debug(TAG, "%s: Invalid channel(%u:%u:%u) or phyMode(%s)...aborting! AP:"
                  LOWI_MACADDR_FMT, __FUNCTION__, chanInfo.mhz, chanInfo.band_center_freq1,
                  chanInfo.band_center_freq2, LOWIUtils::to_string(pM), LOWI_MACADDR(node.bssid));
        break;
      }
    }
    else
    {
      if (!validChannelPhyModeCombo(pM, chanInfo.mhz, chanInfo.band_center_freq1,
                               chanInfo.band_center_freq2))
      {
        log_debug(TAG, "%s: Invalid channel(%u:%u:%u) spacing or phyMode(%s)...aborting! AP:"
                  LOWI_MACADDR_FMT, __FUNCTION__, chanInfo.mhz, chanInfo.band_center_freq1,
                  chanInfo.band_center_freq2, LOWIUtils::to_string(pM),
                  LOWI_MACADDR(node.bssid));
        break;
      }
    }
      // Ensure that the requested BW, channel and preamble are an allowed combination
      // using the valid phy mode table
      if ((band == LOWIDiscoveryScanRequest::BAND_ALL) ||
          (validPhyModeTable[band][node.preamble][node.bandwidth] == LOWI_PHY_MODE_UNKNOWN))
      {
        log_debug(TAG, "%s: Invalid channel(%u:%u:%u) bw(%s) preamble(%s) combo...aborting! AP:"
                  LOWI_MACADDR_FMT, __FUNCTION__, chanInfo.mhz, chanInfo.band_center_freq1,
                chanInfo.band_center_freq2,
                  LOWIUtils::to_string(node.bandwidth), LOWIUtils::to_string(node.preamble),
                  LOWI_MACADDR(node.bssid));
        break;
      }

    log_debug (TAG, "%s: Valid combo: BW(%s) channel(%u:%u) phy mode(%s) & preamble(%s) "
                    "for AP:" LOWI_MACADDR_FMT,
               __FUNCTION__, LOWIUtils::to_string(node.bandwidth), chanInfo.mhz,
               chanInfo.band_center_freq1, LOWIUtils::to_string(pM),
               LOWIUtils::to_string(node.preamble), LOWI_MACADDR(node.bssid));
    retVal = true;
  } while(0);

  return retVal;
} // validChannelBWPreambleCombo

bool LOWIRangingHeliumFSM::setPhyMode(LOWIRangingNode &rangingNode)
{
  bool retVal = false;
  if ( LOWIRangingFSM::setPhyMode(rangingNode) &&
      (LOWI_PHY_MODE_UNKNOWN != rangingNode.targetNode.phyMode))
  {
    log_debug(TAG, "%s: overwrite with user provided phy mode(%s)",
              __FUNCTION__, LOWIUtils::to_string(rangingNode.targetNode.phyMode));
    rangingNode.chanInfo.wmiChannelInfo.info &= PHY_MODE_MASK;
    rangingNode.chanInfo.wmiChannelInfo.info |= rangingNode.targetNode.phyMode;
    retVal = true;
  }
  return retVal;
} // setPhyMode

bool LOWIRangingHeliumFSM::bwSupportedByAP(LOWINodeInfo &requested,
                                           eLOWIPhyMode targetApPhyMode)
{
  bool retVal = false;

  // Check AP's phy mode supports the preamble/bw combination
  do
  {
    // allowed phy mode check in case of special one-sided RTT/phy mode combination
    if ((RTT2_RANGING == requested.rttType) && (LOWI_PHY_MODE_11GONLY == targetApPhyMode))
    {
      retVal = true;
      break;
    }

    // allowed phy modes check
    LOWI_BREAK_ON_COND(((targetApPhyMode == LOWI_PHY_MODE_11B) ||
                        (targetApPhyMode == LOWI_PHY_MODE_11GONLY)), debug,
                       "phy mode does not support RTT")
    // preamble check
    LOWI_BREAK_ON_COND((LOWIUtils::phymodeToPreamble(targetApPhyMode) < requested.preamble),
                       debug, "AP does not support requested preamble")
    // packet bandwidth check
    LOWI_BREAK_ON_COND((LOWIUtils::phymodeToBw(targetApPhyMode) < requested.bandwidth),
                       debug, "AP does not support requested packet bandwidth")
    retVal = true;
  } while (0);

  return retVal;
} // bwSupportedByAP
