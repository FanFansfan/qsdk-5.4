/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI ROME Wifi Driver

GENERAL DESCRIPTION
  This file contains the implementation of Rome Wifi Driver

Copyright (c) 2012-2013, 2015-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <lowi_server/lowi_rome_wifidriver.h>
#include "wipsiw.h"
#include "wifiscanner.h"
#include "lowi_measurement_result.h"
#include "lowi_wifidriver_utils.h"
#include "lowi_diag_log.h"
#include "lowi_wifi_hal.h"
#include <lowi_server/lowi_internal_message.h>
#include "lowi_ranging.h"
#include "lowi_helium_ranging.h"
#include "lowi_sparrow_ranging.h"
#include "lowi_internal_const.h"

using namespace qc_loc_fw;

#define RETURN_IF_BAD_FRAME_LEN(x) if (x < MIN_FRAME_LEN)       \
  {                                                             \
    log_debug(TAG, "%s: Bad frame length: currentFrameLen(%u)", \
              __FUNCTION__, x);                                 \
    return NULL;                                                \
  }

#define RETURN_IF_NULL(x,s) if (NULL == x)    \
  {                                           \
    log_debug(TAG, "%s: %s", __FUNCTION__, s); \
    return NULL;                              \
  }

// Enter/Exit debug macros
#define ROMEDRV_ENTER() log_verbose(TAG, "ENTER: %s", __func__);
#define ROMEDRV_EXIT()  log_verbose(TAG, "EXIT: %s", __func__);

// MAximum RTT measurements per target for CFR capture measurements
#define MAX_RTT_MEAS_PER_DEST_CFR_CAP 1
#define DEFAULT_LOWI_RTS_CTS_NUM_MEAS 5
#define DEFAULT_LOWI_RSSI_THRESHOLD_FOR_RTT -140
#define MAX_CACHED_SCAN_AGE_SEC 30

// Minimum length of the measurement request element
#define MIN_LENGTH_MEAS_REQ_ELEM 3

// Minimum length of the FTMR field
#define MIN_LENGTH_FTMR_FIELD 3

// Minimum frame length in bytes
#define MIN_FRAME_LEN 2

// Measurement Response frame length
#define LOWI_MEAS_RSP_FRAME_LEN 2048


/* WLAN frame parameters */
static uint8 gDialogTok = 1;
static uint8 gMeasTok = 1;

const char * const LOWIROMEWifiDriver::TAG = "LOWIROMEWifiDriver";


static vector <LOWINodeInfo> vecChGroup[MAX_DIFFERENT_CHANNELS_ALLOWED];

LOWIROMEWifiDriver::LOWIROMEWifiDriver (ConfigFile* config,
                                        LOWIScanResultReceiverListener* scanResultListener,
                                        LOWIInternalMessageReceiverListener* internalMessageListener,
                                        LOWICacheManager* cacheManager)
: LOWIROMEWifiDriver (config, scanResultListener, internalMessageListener, cacheManager,
                      LOWIRangingFSM::LOWI_HELIUM_RANGING_INTERFACE)
{
  log_verbose (TAG, "LOWIROMEWifiDriver ()");
  //read the lowi.conf whether LOWI_USE_LOWI_LP flag is set or not
  int lpscanEnabled = 0;
  mConfig->getInt32Default ("LOWI_USE_LOWI_LP", lpscanEnabled, 1);
  log_debug (TAG, "lpscanEnabled = %d",lpscanEnabled);
  if(lpscanEnabled)
  {
    mCapabilities.supportedCapablities |= LOWI_LP_SCAN_SUPPORTED;
  }
  int bgscanEnabled = 0;
  mConfig->getInt32Default ("LOWI_WIFIHAL_ENABLE_BGSCAN_SUPPORT", bgscanEnabled, bgscanEnabled);
  mCapabilities.bgscanSupported = bgscanEnabled ? true : false;
  if(bgscanEnabled)
  {
    mCapabilities.supportedCapablities |= LOWI_BG_SCAN_SUPPORTED;
  }
  mCapabilities.mcVersion = MC_DRAFT_VERSION_40;
}


LOWIROMEWifiDriver::LOWIROMEWifiDriver (ConfigFile* config,
                                        LOWIScanResultReceiverListener* scanResultListener,
                                        LOWIInternalMessageReceiverListener* internalMessageListener,
                                        LOWICacheManager* cacheManager,
                                        LOWIRangingFSM::eLowiRangingInterface lowiRangingInterface)
: LOWIWifiDriverInterface (config)
{
  log_verbose (TAG, "LOWIROMEWifiDriver - interface %d", lowiRangingInterface);

  mReq = NULL;
  mInternalMsgId = 0;

  mCacheManager = cacheManager;

#ifdef LOWI_ON_ACCESS_POINT
  mCapabilities.activeScanSupported = false;
  mCapabilities.discoveryScanSupported = false;
  mCapabilities.supportedCapablities = LOWI_RANGING_SCAN_SUPPORTED;
#else
  mCapabilities.activeScanSupported = true;
  mCapabilities.discoveryScanSupported = true;
  mCapabilities.supportedCapablities = LOWI_DISCOVERY_SCAN_SUPPORTED | LOWI_RANGING_SCAN_SUPPORTED;
#endif
  mInternalMessageListener = internalMessageListener;
  mConnectedToDriver = FALSE;
  mLowiRangingFsm = NULL;
  mLowiRanging    = NULL;

  // instantiate the ranging object for the appropriate interface
  if (lowiRangingInterface == LOWIRangingFSM::LOWI_ROME_RANGING_INTERFACE ||
      lowiRangingInterface == LOWIRangingFSM::LOWI_PRONTO_RANGING_INTERFACE)
  {
    mLowiRanging = new LOWIRanging();
  }
  else if (lowiRangingInterface == LOWIRangingFSM::LOWI_HELIUM_RANGING_INTERFACE)
  {
    mLowiRanging = new LOWIHeliumRanging();
  }
  else if (lowiRangingInterface == LOWIRangingFSM::LOWI_SPARROW_RANGING_INTERFACE)
  {
    mLowiRanging = LOWISparrowRanging::createInstance(internalMessageListener);
  }
  if (mLowiRanging == NULL)
  {
    log_error(TAG, "LOWI Failed to allocate memory for the Ranging Object");
  }
  else
  {
    if (lowiRangingInterface != LOWIRangingFSM::LOWI_SPARROW_RANGING_INTERFACE)
    {
      // initialize the socket used for sending the RTT requests
      mLowiRanging->RomeWipsOpen();
    }
    // instantiate the FSM
    mLowiRangingFsm = LOWIRangingFSM::createInstance(scanResultListener,cacheManager,
                                                     mLowiRanging, lowiRangingInterface);
    if (mLowiRangingFsm == NULL)
    {
      log_warning(TAG, "LOWI Failed to allocate memory for the FSM Object");
      delete mLowiRanging;
      mLowiRanging = NULL;
    }
  }
}

LOWIROMEWifiDriver::~LOWIROMEWifiDriver ()
{
  log_verbose (TAG, "~LOWIROMEWifiDriver ()");
  mConnectedToDriver = FALSE;
  if(mLowiRanging != NULL)
  {
    mLowiRanging->RomeWipsClose();
    delete mLowiRanging;
  }
  if(mLowiRangingFsm != NULL)
  {
    delete mLowiRangingFsm;
  }
}

void LOWIROMEWifiDriver::setNewRequest(const LOWIRequest* r, eListenMode mode)
{
  AutoLock autolock(mMutex);
  if (mode == this->RANGING_SCAN)
  {
    if (mLowiRangingFsm)
    {
      /* Pass in new Request from LOWI Controller to FSM */
      log_verbose(TAG, "%s - Passing in new Request to FSM", __FUNCTION__);
      mLowiRangingFsm->SetLOWIRequest((LOWIRangingScanRequest*)r);
    }
    else
    {
      log_debug(TAG, "Failed to pass in new Ranging request because FSM object is NULL");
    }
  }
}

int LOWIROMEWifiDriver::processPipeEvent(eListenMode mode, RangingPipeEvents newEvent)
{
  log_verbose(TAG, "Processing Pipe Event, mode: %s , Event: %u",
              LOWI_TO_STRING(mode, LOWIWifiDriverInterface::modeStr), newEvent);
  AutoLock autolock(mMutex);
  if (mode == this->DISCOVERY_SCAN)
  {
    return Wips_nl_shutdown_communication();
  }
  else if (mode == this->BACKGROUND_SCAN)
  {
      return lowi_nl_unblock();
  }
  else
  {
    if(mLowiRangingFsm)
    {
      return mLowiRangingFsm->SetNewPipeEvent(newEvent);
    }
    else
    {
      log_debug(TAG, "Failed to Process Pipe Event because FSM object is NULL");
      return -1;
    }
  }
}

int LOWIROMEWifiDriver::unBlock (eListenMode mode)
{
  return processPipeEvent(mode, NEW_REQUEST_ARRIVED);
}

int LOWIROMEWifiDriver::terminate (eListenMode mode)
{
  if (mode == REQUEST_SCAN)
  {
    // Unblock the thread
    // Thread could be blocked waiting for status response from the host driver
      return lowiUnblockThread();
  }
  return processPipeEvent(mode, TERMINATE_THREAD);
}

int LOWIROMEWifiDriver::initFileDescriptor (eListenMode mode)
{
  log_verbose (TAG, "initFileDescriptor Mode = %d", mode);

  switch (mode)
  {
    case RANGING_SCAN:
    {
      AutoLock autolock(mMutex);
      return mLowiRanging->RomeInitRangingPipe();
    }
    case DISCOVERY_SCAN:
    case BACKGROUND_SCAN:
    case REQUEST_SCAN:
    default:
      return LOWIWifiDriverInterface::initFileDescriptor(mode);
  }
}

int LOWIROMEWifiDriver::closeFileDescriptor (eListenMode mode)
{
  log_verbose (TAG, "closeFileDescriptor Mode = %d", mode);

  switch (mode)
  {
    case RANGING_SCAN:
    {
      AutoLock autolock(mMutex);
      return mLowiRanging->RomeCloseRangingPipe();
    }
    case DISCOVERY_SCAN:
    case BACKGROUND_SCAN:
    case REQUEST_SCAN:
    default:
      return LOWIWifiDriverInterface::closeFileDescriptor(mode);
  }
}

bool LOWIROMEWifiDriver::sendCapabilitiesReq (std::string interface)
{
  if (mLowiRangingFsm)
      return mLowiRangingFsm->SendRangingCap(interface);
  else
      return false;
}

LOWICapabilities LOWIROMEWifiDriver::getCapabilities ()
{
  if (mLowiRangingFsm)
  {
    LOWI_RangingCapabilities lowiRangingCap;
    mCapabilities.rangingScanSupported = false;
    lowiRangingCap = mLowiRangingFsm->GetRangingCap();
    mCapabilities.oneSidedRangingSupported = lowiRangingCap.oneSidedSupported;
    mCapabilities.dualSidedRangingSupported11mc = lowiRangingCap.dualSidedSupported11mc;
    mCapabilities.dualSidedRangingSupported11v = lowiRangingCap.dualSidedSupported11v;
    mCapabilities.bwSupport = lowiRangingCap.bwSupport;
    mCapabilities.preambleSupport = lowiRangingCap.preambleSupport;
    if (mCapabilities.oneSidedRangingSupported ||
        mCapabilities.dualSidedRangingSupported11mc ||
        mCapabilities.dualSidedRangingSupported11v)
    {
      mCapabilities.rangingScanSupported = true;
    }
    // check for BGSCAN support
    if(lowiIsBgscanSupportedByDriver())
    {
      log_debug (TAG, "@getCapabilities(): Driver supports BGSCAN");
    }
  }
  return mCapabilities;
}

uint8* LOWIROMEWifiDriver::parseNeighborReport(uint8 &elemLen,
                                               uint8 *frameBody,
                                               FineTimingMeasRangeReq &rangeReq)
{
  log_verbose(TAG, "%s", __FUNCTION__);
  if (elemLen    < NR_ELEM_MIN_LEN ||
      frameBody == NULL)
  {
    log_debug(TAG, "%s - Abort - Elem Len(%u) < Min Len(%u). ",
              __FUNCTION__, elemLen, NR_ELEM_MIN_LEN);
    return NULL;
  }

  NeighborRprtElem neighborRprtElem;
  uint8 elemId = *frameBody++;
  uint8 len    = *frameBody++;

  log_debug(TAG, "%s - parentElemLen %u, elemId: %u, len: %u", __FUNCTION__, elemLen, elemId, len);

  /** Account for the length of this element. This is done so that
   *  the caller can keep track of how much data is yet to be
   *  parsed */
  if (elemLen >= (len + NR_ELEM_HDR_LEN))
  {
    elemLen -= (len + NR_ELEM_HDR_LEN);
    if (elemId == RM_NEIGHBOR_RPT_ELEM_ID)
    {
      log_verbose(TAG, "%s - Going to parse NR Element", __FUNCTION__);
    }
    else
    {
      log_debug(TAG, "%s - %u is not a NR Element - Not Parsing", __FUNCTION__, elemId);
      frameBody += len;
      return frameBody;
    }
  }
  else
  {
    log_debug(TAG, "%s - Bad Element Length: %u - Not Going to Parse Element", __FUNCTION__, elemLen);
    elemLen = 0;
    return NULL;
  }

  memcpy(neighborRprtElem.bssid, frameBody, BSSID_SIZE);
  frameBody   += BSSID_SIZE;
  memcpy(&neighborRprtElem.bssidInfo, frameBody, BSSID_INFO_LEN);
  frameBody   += BSSID_INFO_LEN;
  neighborRprtElem.operatingClass = *frameBody++;
  neighborRprtElem.channelNumber  = *frameBody++;
  neighborRprtElem.phyType        = *frameBody++;

  log_debug(TAG, "%s - NR Elem - elemId(%u) len(%u) BSSID(" LOWI_MACADDR_FMT
              ") Bssid-Info(0x%x) operatingClass(%u) channelNumber(%u) phyType(%u)",
              __FUNCTION__,
              elemId,
              len,
              LOWI_MACADDR(neighborRprtElem.bssid),
              neighborRprtElem.bssidInfo,
              neighborRprtElem.operatingClass,
              neighborRprtElem.channelNumber,
              neighborRprtElem.phyType);

  /** The basic Neighbor report Element is NR_ELEM_MIN_LEN(13)
   *  bytes long. These bytes have been parsed above. All
   *  additional bytes will ignored for the moment.
   */
  if (len > NR_ELEM_MIN_LEN)
  {
    uint8 extraBytes = len - NR_ELEM_MIN_LEN;
    uint8* optSubElements = frameBody;
    /* Move Frame Body to next Element */
    frameBody += extraBytes;

    bool discardBytes = false;
    while (extraBytes)
    {
      if (extraBytes >  NR_SUB_ELEM_HDR_LEN)
      {
        /* Parse additional subelements but pick up only the WBC element */
        uint8 subElemId  = *optSubElements++;
        uint8 subElemLen = *optSubElements++;
        extraBytes -= NR_SUB_ELEM_HDR_LEN;
        if (subElemLen <= extraBytes)
        {
          if (subElemId == NR_WBC_ELEM_ID &&
              subElemLen == NR_SUB_ELEM_WBC_LEN)
          {
            extraBytes -= NR_SUB_ELEM_WBC_LEN;
            neighborRprtElem.channelWidth = *optSubElements++;
            neighborRprtElem.centerFreq0_Channel = *optSubElements++;
            neighborRprtElem.centerFreq1_Channel = *optSubElements++;
            log_debug(TAG, "%s: Successfully parsed WBC element: channelWidth: %u, "
                           "centerFreq0_Channel: %u, centerFreq1_Channel: %u",
                      __FUNCTION__,
                      neighborRprtElem.channelWidth,
                      neighborRprtElem.centerFreq0_Channel,
                      neighborRprtElem.centerFreq1_Channel);
          }
          else /* NOT a WBC element Move onto next element */
          {
            optSubElements += subElemLen;
            extraBytes -= subElemLen;
          }
        }
        else /* invalid Sub element Length - discard extra bytes */
        {
          discardBytes = true;
        }
      }
      else /* Invalid Sub Element - discard extra bytes */
      {
        discardBytes = true;
      }

      if (discardBytes)
      {
        discardBytes = false;
        log_debug(TAG, "%s - Discard %u extra bytes in NR Element, because they are corrupt",
                  __FUNCTION__,
                  extraBytes);
        optSubElements += extraBytes;
        extraBytes = 0;
      }
    }
  }

  rangeReq.neighborRprtElem.push_back(neighborRprtElem);

  return frameBody;
}

void LOWIROMEWifiDriver::bssidInfoToPreambleAndBw(uint32 bssidInfo,
                                                  uint8 channelWidth,
                                                  eRangingPreamble &preamble,
                                                  eRangingBandwidth &bandwidth)
{
  /* set to defaults - LEGACY Preamble and 20MHZ BW */
  preamble = (NR_GET_BSSID_INFO_VHT(bssidInfo) ? RTT_PREAMBLE_VHT :
              (NR_GET_BSSID_INFO_HT(bssidInfo) ? RTT_PREAMBLE_HT  :
               RTT_PREAMBLE_LEGACY));

  switch (channelWidth)
  {
    case NR_WBC_BW_40:
    {
      bandwidth = BW_40MHZ;
      break;
    }
    case NR_WBC_BW_80:
    {
      bandwidth = BW_80MHZ;
      break;
    }
    case NR_WBC_BW_20:
    case NR_WBC_BW_160:    // Not supported yet.
    case NR_WBC_BW_80_80:  // Not supported yet
    default:               // Default to 20 MHz
    {
      bandwidth = BW_20MHZ;
      break;
    }
  }
}

uint8* LOWIROMEWifiDriver::parseMeasReqElem(uint32 &currentFrameLen,
                                            uint8 *frameBody,
                                            uint8 dialogTok,
                                            uint8 sourceMac[BSSID_SIZE],
                                            uint8 staMac[BSSID_SIZE],
                                            uint32 freq)
{
  log_verbose(TAG, "%s", __FUNCTION__);
  RETURN_IF_BAD_FRAME_LEN(currentFrameLen)
  RETURN_IF_NULL(frameBody, "Bad input: NULL frameBody")

  // start parsing the Measurement Request Element
  //         | Element | Length | Meas  | Meas    | Meas | Meas     |
  //         | ID      |        | Token | ReqMode | Type | Request  |
  // #bytes: | 1       | 1      | 1     | 1       | 1    | variable |

  uint8 elemId     = *frameBody++;
  uint8 elemLen    = *frameBody++;
  currentFrameLen -= MEAS_REQ_ELEM_HDR_LEN; // subtract elemId and elemLen
  uint8 *measReqElemBody = frameBody;

  if (elemLen > currentFrameLen || elemLen < MIN_LENGTH_MEAS_REQ_ELEM)
  {
    log_debug(TAG, "%s: Abort - Bad Elem Len: elemLen(%u) frameLen(%u)",
              __FUNCTION__, elemLen, currentFrameLen);
    return NULL;
  }

  /* Move Frame Body pointer to the next element */
  frameBody += elemLen;
  currentFrameLen -= elemLen;

  if (elemId != RM_MEAS_REQ_ELEM_ID)
  {
    log_debug(TAG, "%s - Skipping element that is not a Measurement Request Element: E-ID: %u",
             __FUNCTION__, elemId);
    return frameBody;
  }

  MeasReqElem measReqElement;
  measReqElement.measTok     = *measReqElemBody++;
  measReqElement.measReqMode = *measReqElemBody++;
  measReqElement.measType    = *measReqElemBody++;

  log_verbose(TAG, "%s: Measurement Request Hdr - ElemId(%u) ElemLen(%u) MeasToken(%u) "
                   "MeasReqMode(%u) MeasType(%u)", __FUNCTION__, elemId, elemLen,
              measReqElement.measTok, measReqElement.measReqMode, measReqElement.measType);

  // update the elemLen now that we're passed the fields that are always there
  elemLen -= MIN_LENGTH_MEAS_REQ_ELEM;
  if (0 == elemLen)
  { /* reached end of Measurement Request Element */
    log_debug(TAG, "%s - Reached end of element prematurely! - aborting", __FUNCTION__);
    return frameBody;
  }

  // process the appropriate request
  int8 retVal = -1;
  switch (measReqElement.measType)
  {
    case LOWI_WLAN_FTM_RANGE_REQ_TYPE:
      retVal = processFtmRangeReq(dialogTok, elemLen, measReqElement,
                                  measReqElemBody, sourceMac, staMac, freq);
      break;
    case LOWI_WLAN_LCI_REQ_TYPE:
      retVal = processLciReq(dialogTok, measReqElement, measReqElemBody,
                             sourceMac, staMac, freq);
      break;
    default:
      log_debug(TAG, "%s: Unknown element! - aborting", __FUNCTION__);
      break;
  }

  return (retVal < 0) ? NULL : frameBody;
}

void LOWIROMEWifiDriver::processWlanFrame()
{
  char tempBuff[5000];
  log_verbose(TAG, "%s", __FUNCTION__);
  for (int i = 0; i < wlanFrameStore.numFrames; ++i)
  {
    uint8 sourceMac[BSSID_SIZE];
    uint8 staMac[BSSID_SIZE];
    uint32 freq = wlanFrameStore.wlanFrames[i].freq;
    uint8 frameLen = wlanFrameStore.wlanFrames[i].frameLen;
    uint8 *frame = wlanFrameStore.wlanFrames[i].frameBody;
    Wlan80211FrameHeader *wlanFrameHeader = (Wlan80211FrameHeader*) frame;
    uint8 *frameBody = frame + sizeof(Wlan80211FrameHeader);

    int l = 0;
    for (unsigned int i = 0; i < frameLen; i++)
    {
      l+=snprintf(tempBuff+l, 10, "0x%02x ", frameBody[i]);
    }

    uint8 actCatagory = *frameBody++;
    uint8 frameBodyLen = frameLen - sizeof(Wlan80211FrameHeader) - 1;

    log_verbose(TAG, "%s - Frame Header - frameControl:0x%x durationId: 0x%x addr1:" LOWI_MACADDR_FMT " addr2:" LOWI_MACADDR_FMT " addr3:" LOWI_MACADDR_FMT " SeqControl: 0x%x",
                __FUNCTION__,
                wlanFrameHeader->frameControl,
                wlanFrameHeader->durationId,
                LOWI_MACADDR(wlanFrameHeader->addr1),
                LOWI_MACADDR(wlanFrameHeader->addr2),
                LOWI_MACADDR(wlanFrameHeader->addr3),
                wlanFrameHeader->seqCtrl);

    memcpy(sourceMac, wlanFrameHeader->addr2, BSSID_SIZE);
    memcpy(staMac, wlanFrameHeader->addr1, BSSID_SIZE);

    log_verbose(TAG, "%s - Received Action Frame: Source Addr: " LOWI_MACADDR_FMT " Category: %u Data Len: %u",
                __FUNCTION__,
                LOWI_MACADDR(wlanFrameHeader->addr2),
                actCatagory,
                frameBodyLen);

    log_verbose(TAG, "%s - Frame: %s", __FUNCTION__, tempBuff);

    uint8 rmAction  = *frameBody++;
    uint8 dialogTok = *frameBody++;
    uint16 numRep   = ((frameBody[0] << 8) | (frameBody[1]));
    frameBody += 2;
    uint32 currentFrameLen = frameBodyLen - 4;


    if (actCatagory != LOWI_WLAN_ACTION_RADIO_MEAS ||
        rmAction    != LOWI_RM_ACTION_REQ)
    {
      log_debug(TAG, "%s: Skipping Non Radio Measurement Req Frame" , __FUNCTION__);
      continue;
    }
    else
    {
      log_debug(TAG, "%s: Radio Measurement Req Frame received: Action-Cat(%u) "
                     "Action Type(%u) dialogTok(%u) numRep(%u)",
                __FUNCTION__, actCatagory, rmAction, dialogTok, numRep);
    }

    while(currentFrameLen)
    {
      frameBody = parseMeasReqElem(currentFrameLen, frameBody, dialogTok, sourceMac, staMac, freq);
      if (frameBody == NULL)
      {
        break;
      }
    }
  }
}

void LOWIROMEWifiDriver::sendNeighborRprtReq()
{
  uint8 frameBody[2048];
  char frameChar[2048];
  int l = 0;
  uint32 i = 0, frameBodyLen = 0;
  uint8 destMac[BSSID_SIZE];
  uint8 staMac[BSSID_SIZE];
  uint32 freq;
  LOWIScanMeasurement associatedApMeas;
  LOWIMacAddress localStaMac;

  if (mCacheManager && mCacheManager->getAssociatedAP(associatedApMeas) == false)
  {
    log_debug(TAG, "%s - Not associated to any AP so cannot request Neighbor Report - Aborting",
              __FUNCTION__);
    return;
  }
  else
  {
    log_debug(TAG, "%s - Associated to AP: " LOWI_MACADDR_FMT " requesting Neighbor Report",
                __FUNCTION__, LOWI_MACADDR(associatedApMeas.bssid));
  }

  freq = associatedApMeas.frequency;

  for (i = 0; i < BSSID_SIZE; i++)
  {
    destMac[i] = associatedApMeas.bssid[i];
  }
  log_debug(TAG, "%s - The Destination MAC address for the NR request is: " LOWI_MACADDR_FMT,
            __FUNCTION__, LOWI_MACADDR(destMac));

  if (mCacheManager &&
      mCacheManager->getStaMacInCache(localStaMac) == false)
  {
    log_debug(TAG, "%s - Failed to request Local STA MAC so cannot request Neighbor Report - Aborting",
              __FUNCTION__);
    return;
  }
  else
  {
    log_debug(TAG, "%s - Local STA MAC from cache: " LOWI_MACADDR_FMT,
                __FUNCTION__, LOWI_MACADDR(localStaMac));
    for (i = 0; i < BSSID_SIZE; i++)
    {
      staMac[i] = localStaMac[i];
    }
    log_error(TAG, "%s - The Local STA MAC address for the NR request is: " LOWI_MACADDR_FMT,
              __FUNCTION__, LOWI_MACADDR(staMac));
  }

  NeighborRequestElem nrReqElem;
  MeasReqElem measReqElemlci;
  MeasReqElem measReqElemlcr;
  LciElemCom lciElemCom;
  LocCivElemCom locCivElemCom;

  nrReqElem.catagory = LOWI_WLAN_ACTION_RADIO_MEAS;
  nrReqElem.radioMeasAction = LOWI_NR_ACTION_REQ;
  nrReqElem.dialogTok = gDialogTok++;
  if (gDialogTok == 0)
  {
    /* Dialog Token shall always be a non zero number so increment again*/
    gDialogTok++;
  }

  measReqElemlci.elementId = RM_MEAS_REQ_ELEM_ID;
  measReqElemlci.len = 3 + sizeof(lciElemCom);
  measReqElemlci.measTok = gMeasTok++;
  if (gMeasTok == 0)
  {
    /* Measurement Token shall always be a non zero number so increment again*/
    gMeasTok++;
  }
  measReqElemlci.measReqMode = 0; /* Reserved */
  measReqElemlci.measType = LOWI_WLAN_LCI_REQ_TYPE;

  measReqElemlcr.elementId = RM_MEAS_REQ_ELEM_ID;
  measReqElemlcr.len = 3 + sizeof(locCivElemCom);
  measReqElemlcr.measTok = gMeasTok++;
  if (gMeasTok == 0)
  {
    /* Measurement Token shall always be a non zero number so increment again*/
    gMeasTok++;
  }
  measReqElemlcr.measReqMode = 0; /* Reserved */
  measReqElemlcr.measType = LOWI_WLAN_LOC_CIVIC_REQ_TYPE;

  lciElemCom.locSubject = LOWI_LOC_SUBJECT_REMOTE;

  locCivElemCom.locSubject = LOWI_LOC_SUBJECT_REMOTE;
  locCivElemCom.civicType = 0; /*IETF RFC format*/
  locCivElemCom.locServiceIntUnits = 0; /* Seconds units */
  locCivElemCom.locServiceInterval = 0; /* 0 Seconds */

  memset(frameBody, 0, sizeof(frameBody));

  /* Construct the Neighbor Request Frame header */
  memcpy(frameBody, &nrReqElem, sizeof(nrReqElem));
  frameBodyLen += sizeof(nrReqElem);

  /* Construct the Measurement Elements */
  /* Construct LCI Measurement Element */
  memcpy((frameBody + frameBodyLen), &measReqElemlci, sizeof(measReqElemlci));
  frameBodyLen += sizeof(measReqElemlci);
  /* LCI Element */
  memcpy((frameBody + frameBodyLen), &lciElemCom, sizeof(lciElemCom));
  frameBodyLen += sizeof(lciElemCom);
  /* Construct Location Civic Measurement Element */
  memcpy((frameBody + frameBodyLen), &measReqElemlcr, sizeof(measReqElemlcr));
  frameBodyLen += sizeof(measReqElemlcr);
  /* Location Civic Element */
  memcpy((frameBody + frameBodyLen), &locCivElemCom, sizeof(locCivElemCom));
  frameBodyLen += sizeof(locCivElemCom);

  for (i = 0; i < frameBodyLen; i++)
  {
    l+=snprintf(frameChar+l, 10, "0x%02x ", frameBody[i]);
  }

  log_debug(TAG, "%s - FrameBody: %s", __FUNCTION__, frameChar);

  lowi_send_action_frame(frameBody, frameBodyLen, freq, destMac, staMac);
}

uint8 * LOWIROMEWifiDriver::initMeasRspFrame(LOWIInternalMessage *req, uint8 *frameBody,
                                             uint32 &frameBodyLen, uint32 &measRptLen)
{
  uint8 *retVal = NULL;
  LOWIInternalMessage *iReq = NULL;
  do
  {
    // check that it is a request we can handle
    if (LOWIRequest::LOWI_INTERNAL_MESSAGE != req->getRequestType())
    {
      log_debug(TAG, "%s - Wrong input request(%s)", __FUNCTION__,
                LOWIUtils::to_string(req->getRequestType()));
      break;
    }

    // check for the only internal requests supported
    iReq = (LOWIInternalMessage *)req;

    if (LOWIInternalMessage::LOWI_IMSG_FTM_RANGE_RPRT != iReq->getInternalMessageType() &&
        LOWIInternalMessage::LOWI_IMSG_LCI_RPRT       != iReq->getInternalMessageType())
    {
      log_debug(TAG, "%s - Wrong internal msg(%u)", __FUNCTION__, iReq->getInternalMessageType());
      break;
    }

    // request is good, get tokens
    uint32 diagToken = 0;
    uint32 measToken = 0;
    uint8 measType   = 0;
    if (LOWIInternalMessage::LOWI_IMSG_FTM_RANGE_RPRT == iReq->getInternalMessageType())
    {
      LOWIFTMRangeRprtMessage *r = (LOWIFTMRangeRprtMessage *)iReq;
      diagToken = r->getRadioMeasReqParams().mDiagToken;
      measToken = r->getRadioMeasReqParams().mMeasToken;
      measType  = (uint8)LOWI_WLAN_FTM_RANGE_REQ_TYPE;
    }
    else if (LOWIInternalMessage::LOWI_IMSG_LCI_RPRT == iReq->getInternalMessageType())
    {
      LOWILCIRprtMessage *r = (LOWILCIRprtMessage *)iReq;
      diagToken = r->getRadioMeasReqParams().mDiagToken;
      measToken = r->getRadioMeasReqParams().mMeasToken;
      measType  = (uint8)LOWI_WLAN_LCI_REQ_TYPE;
    }

    /* Construct the Radio Measurement Frame header */
    /* Add Catagory to the frame */
    frameBody[frameBodyLen++] = LOWI_WLAN_ACTION_RADIO_MEAS;
    /* Radio Measurement Action Type*/
    frameBody[frameBodyLen++] = LOWI_RM_ACTION_RPT;
    /* Dialog Token */
    frameBody[frameBodyLen++] = (uint8)diagToken;

    /* Construct the Measurement Report Elements */
    /* Add Element ID*/
    frameBody[frameBodyLen++] = RM_MEAS_RPT_ELEM_ID;
    /* Get ptr to the length of the Report Element, it shall be filled in later */
    uint8 *measRptLenField = &frameBody[frameBodyLen++];
    /* Add Measurement Token */
    frameBody[frameBodyLen++] = (uint8)measToken;
    /* Add Measurement Report Mode - all zeros */
    frameBody[frameBodyLen++] = 0;
    /* Add Measurement Type */
    frameBody[frameBodyLen++] = measType;

    // update the report length...so far, 3 bytes have been added to the report
    measRptLen += 3;
    retVal = measRptLenField;
  } while (0);

  return retVal;
} // initMeasRspFrame

void LOWIROMEWifiDriver::SendFTMRRep(LOWIFTMRangeRprtMessage* req)
{
  ROMEDRV_ENTER()

  if (req == NULL)
  {
    log_info(TAG, "%s - Received an null pointer for the request - Aborting", __FUNCTION__);
    return;
  }

  uint32 freq;
  LOWIMacAddress mac = req->getRadioMeasReqParams().mRequesterBssid;
  if ((NULL == mCacheManager) || (false == mCacheManager->getFreqFromCache(mac, freq)))
  {
    return;
  }

  uint8 frameBody[LOWI_MEAS_RSP_FRAME_LEN];
  memset(frameBody, 0, sizeof(frameBody));
  // keep track of where contents are placed in the array
  uint32 frameBodyLen = 0;
  // Keep track of the length of the Measurement Report Element
  uint32 measRptLen = 0;

  // Initialize the Radio Measurement Report Frame
  LOWIInternalMessage *request = (LOWIInternalMessage*)req;
  uint8 *measRptLenField = initMeasRspFrame(request, frameBody, frameBodyLen, measRptLen);
  if (NULL == measRptLenField)
  {
    log_info(TAG, "%s: initMeasRspFrame failed - Aborting", __FUNCTION__);
    return;
  }

  vector <LOWIRangeEntry> &rangeEntries = req->getSuccessNodes();
  vector <LOWIErrEntry>   &errEntries   = req->getErrNodes();

  uint8 rangeEntryCount = rangeEntries.getNumOfElements();
  uint8 errEntryCount   = errEntries.getNumOfElements();


  /* Construct the Fine Timing Range Report Body */
  /* Add Range Entry Count */
  frameBody[frameBodyLen++] = rangeEntryCount;
  /* Add Range Entries */
  if (rangeEntryCount)
  {
    FtmrrRangeEntry* rangeEntElems = (FtmrrRangeEntry*) &frameBody[frameBodyLen];
    for (uint32 i = 0; i < rangeEntryCount; i++)
    {
      FtmrrRangeEntry rangeEntry;

      memset(&rangeEntry, 0, sizeof(rangeEntry));
      /* Measurement Start Time */
      rangeEntry.measStartTime = rangeEntries[i].measStartTime;
      /* BSSID */
      for (int j = 0; j < BSSID_SIZE; j++)
      {
        rangeEntry.bssid[j] = rangeEntries[i].bssid[j];
      }
      /* Range */
      rangeEntry.range = rangeEntries[i].range;
      /* Max Range Error */
      rangeEntry.maxErrRange = rangeEntries[i].maxErrRange;

      log_verbose(TAG, "%s: Range Entry[%d] BSSID: " LOWI_MACADDR_FMT
                  " Starttime:%u range:%u maxErr:%u", __FUNCTION__, i,
                  LOWI_MACADDR(rangeEntries[i].bssid), rangeEntries[i].measStartTime,
                  rangeEntries[i].range, rangeEntries[i].maxErrRange);
      memcpy(rangeEntElems, &rangeEntry, sizeof(FtmrrRangeEntry));
      rangeEntElems++;
      frameBodyLen += sizeof(FtmrrRangeEntry);
    }
  }
  /* Add Range Error Count */
  frameBody[frameBodyLen++] = errEntryCount;
  /* Add Error Entries */
  if (errEntryCount)
  {
    FtmrrErrEntry* errEntElems = (FtmrrErrEntry*) &frameBody[frameBodyLen];
    for (uint32 i = 0; i < errEntryCount; i++)
    {
      FtmrrErrEntry errEntry;
      /* Measurement Start Time */
      log_verbose(TAG, "%s - errEntries[%d].measStartTime: %u",
                  __FUNCTION__, i, errEntries[i].measStartTime);
      errEntry.measStartTime = errEntries[i].measStartTime;
      /* BSSID */
      log_verbose(TAG, "%s -  Error Entry[%d] - BSSID: " LOWI_MACADDR_FMT,
                  __FUNCTION__, i, LOWI_MACADDR(errEntries[i].bssid));
      for (int j = 0; j < BSSID_SIZE; j++)
      {
        errEntry.bssid[j] = errEntries[i].bssid[j];
      }
      /* Error Code */
      log_verbose(TAG, "%s - errEntries[%d].errCode: %u",
                  __FUNCTION__, i, errEntries[i].errCode);
      errEntry.errCode = errEntries[i].errCode;

      memcpy(errEntElems, &errEntry, sizeof(FtmrrErrEntry));
      errEntElems++;
      frameBodyLen += sizeof(FtmrrErrEntry);
    }
  }
  /* Keep track of the length of the Measurement Report Element */
  measRptLen += 1 + (sizeof(FtmrrRangeEntry) * rangeEntryCount) + 1 + (sizeof(FtmrrErrEntry) * errEntryCount);
  /* Update Measurement Report Length Field */
  *measRptLenField = measRptLen;

  uint8 sourceMac[BSSID_SIZE];
  for (uint32 i = 0; i < BSSID_SIZE; i++)
  {
    sourceMac[i] = mac[i];
  }

  uint8 staMac[BSSID_SIZE];
  LOWIMacAddress selfMac = req->getRadioMeasReqParams().mSelfBssid;
  for (uint32 i = 0; i < BSSID_SIZE; i++)
  {
    staMac[i] = selfMac[i];
  }
  log_debug(TAG, "%s: Dest MAC addr(" LOWI_MACADDR_FMT ") Self MAC addr(" LOWI_MACADDR_FMT ")",
            __FUNCTION__, LOWI_MACADDR(mac), LOWI_MACADDR(selfMac));

  printFrame(frameBody, frameBodyLen);

  lowi_send_action_frame(frameBody, frameBodyLen, freq, sourceMac, staMac);
} // SendFTMRRep

void LOWIROMEWifiDriver::SendLCIReport(LOWILCIRprtMessage* req)
{
  ROMEDRV_ENTER()
  if (NULL == req)
  {
    log_info(TAG, "%s: NULL pointer in request - Abort", __FUNCTION__);
    return;
  }

  uint32 freq;
  LOWIMacAddress mac = req->getRadioMeasReqParams().mRequesterBssid;
  if ((NULL == mCacheManager) || (false == mCacheManager->getFreqFromCache(mac, freq)))
  {
    return;
  }

  // this array will be populated with the measurement report
  uint8 frameBody[LOWI_MEAS_RSP_FRAME_LEN];
  memset(frameBody, 0, sizeof(frameBody));
  // keep track of where contents are placed in the array
  uint32 frameBodyLen = 0;
  // Keep track of the length of the Measurement Report Element
  uint32 measRptLen = 0;

  // Initialize the Radio Measurement Report Frame
  LOWIInternalMessage *request = (LOWIInternalMessage*)req;
  uint8 *measRptLenField = initMeasRspFrame(request, frameBody, frameBodyLen, measRptLen);
  if (NULL == measRptLenField)
  {
    log_info(TAG, "%s: initMeasRspFrame failed - Abort", __FUNCTION__);
    return;
  }

  ///////////////////////////////////////////////////////////////
  // Construct the LCI Report Body.
  // It consists of 3 subelements: LCI, Z and Usage Rules/Policy
  ///////////////////////////////////////////////////////////////

  // append the LCI subelement to the frame body
  appendLciSubElem(req, frameBody, frameBodyLen, measRptLen);

  LOWILCIInfo lciInfo = req->getLCIRprtInfo().lciParams;

  // Only add subsequent Sub elements if LCI is known
  if (lciInfo.lciInfoIsKnown)
  {

    // append the Z subelement to the frame body
    appendZSubElem(req, frameBody, frameBodyLen, measRptLen);

    // append the Usage Rules subelement to the frame body
    appendUsageRulesSubElem(req, frameBody, frameBodyLen, measRptLen);

  }

  /* Update Measurement Report Length Field */
  *measRptLenField = measRptLen;

  uint8 sourceMac[BSSID_SIZE];
  for( unsigned int ii = 0; ii < BSSID_SIZE; ii++ )
  {
    sourceMac[ii] = mac[ii];
  }

  uint8 staMac[BSSID_SIZE];
  LOWIMacAddress selfMac = req->getRadioMeasReqParams().mSelfBssid;
  for( unsigned int ii = 0; ii < BSSID_SIZE; ii++ )
  {
    staMac[ii] = selfMac[ii];
  }
  log_debug(TAG, "%s: Dest MAC addr(" LOWI_MACADDR_FMT ") Self MAC addr(" LOWI_MACADDR_FMT ")",
            __FUNCTION__, LOWI_MACADDR(mac), LOWI_MACADDR(selfMac));

  printFrame(frameBody, frameBodyLen);

  lowi_send_action_frame(frameBody, frameBodyLen, freq, sourceMac, staMac);
} // SendLCIReport

LOWIMeasurementResult* LOWIROMEWifiDriver::getMeasurements
(LOWIRequest* r, eListenMode mode)
{
  ROMEDRV_ENTER()
  LOWIMeasurementResult* result = NULL;

  int retVal = -1001;

  if (LOWIWifiDriverInterface::DISCOVERY_SCAN == mode)
  {
    // Check the type of request and issue the request to the wifi driver accordingly
    if (NULL == r)
    {
      return LOWIWifiDriverInterface::getMeasurements (r, mode);
    }
    else if(LOWIRequest::DISCOVERY_SCAN == r->getRequestType())
    {
      return LOWIWifiDriverInterface::getMeasurements (r, mode);
    } // else if(DISCOVERY_SCAN == r->getRequestType())
    else if (LOWIRequest::LOWI_INTERNAL_MESSAGE == r->getRequestType())
    {
      LOWIInternalMessage *intreq = (LOWIInternalMessage*)r;
      if (LOWIInternalMessage::LOWI_IMSG_FTM_RANGE_RPRT == intreq->getInternalMessageType())
      {
        log_verbose(TAG, "%s - Sending out Fine Timing Measurement Range Report", __FUNCTION__);
        LOWIFTMRangeRprtMessage* req = (LOWIFTMRangeRprtMessage*) r;
        SendFTMRRep(req);
      }
      else if (LOWIInternalMessage::LOWI_IMSG_LCI_RPRT == intreq->getInternalMessageType())
      {
        log_verbose(TAG, "%s - Sending out LCI Report", __FUNCTION__);
        LOWILCIRprtMessage* req = (LOWILCIRprtMessage*) r;
        SendLCIReport(req);
      }
      else
      {
        return LOWIWifiDriverInterface::getMeasurements (r, mode);
      }
    }
    else if (LOWIRequest::NEIGHBOR_REPORT == r->getRequestType())
    {
      log_verbose(TAG, "%s - Sending out Neighbor Report Request", __FUNCTION__);
      sendNeighborRprtReq();
    }

  }

  // REQUEST_SCAN thread handles scan requests of certain types
  if(LOWIWifiDriverInterface::REQUEST_SCAN == mode)
  {
    // Background scan requests
    if( LOWIUtils::isBackgroundScan(r) )
    {
      result = performRequest(r, getBGscanConfigFlags());
      return result;
    }
  }

  /** Ranging FSM */
  if (LOWIWifiDriverInterface::RANGING_SCAN == mode)
  {
    /** This is a blocking Call to the FSM. The FSM will return
     *  when there is a terminate Thread request */
    if(mLowiRangingFsm->FSM() != 0)
    {
      log_debug(TAG, "FSM returned an non zero value indicating something bad happened");
    }
    /* Reset the Request and Result Vector Pointer in the FSM */
    mLowiRangingFsm->SetLOWIRequest(NULL);
  }
  /*************/

  if (LOWIWifiDriverInterface::RANGING_SCAN != mode)
  {

    log_verbose (TAG, "getMeasurements () - Request type: %u analyzing the results - %d", (r) ? r->getRequestType() : 2000, retVal);
    result = NULL;
    if (r != NULL &&
        ((LOWIRequest::NEIGHBOR_REPORT == r->getRequestType()) ||
        (LOWIRequest::LOWI_INTERNAL_MESSAGE == r->getRequestType())))
    {
      log_verbose(TAG,"%s - Finished processing Neighbor Report Request returning to Passive Listennig mode", __FUNCTION__);
      result = new (std::nothrow) LOWIMeasurementResult;
      if (NULL == result)
      {
        log_error (TAG, "Unable to create the measurement result");
      }
      else
      {
        result->request = r;
        result->scanStatus = LOWIResponse::SCAN_STATUS_SUCCESS;
      }
    }
  }

  return result;
}

int8 LOWIROMEWifiDriver::processFtmRangeReq(uint8 dialogTok, uint8 &elemLen,
                                            MeasReqElem &measReqElement,
                                            uint8 *measReqElemBody,
                                            uint8 sourceMac[BSSID_SIZE],
                                            uint8 staMac[BSSID_SIZE], uint32 freq)
{
  int8 retVal = -1;
  FineTimingMeasRangeReq rangeReq;
  rangeReq.dialogTok               = dialogTok;
  rangeReq.measReqElem.measTok     = measReqElement.measTok;
  rangeReq.measReqElem.measReqMode = measReqElement.measReqMode;
  rangeReq.measReqElem.measType    = measReqElement.measType;

  // Start Parsing Fine Timing Measurement Range Request field
  //         | randomization | Minimum AP | FTM Range   |
  //         | interval      | count      | Subelements |
  // #bytes: |     2         |    1       |  variable   |
  FtmrReqHead fmtrReqHead;
  fmtrReqHead.randomInterval = ((measReqElemBody[0] << 8) | (measReqElemBody[1]));
  measReqElemBody += MEAS_REQ_ELEM_HDR_LEN;
  fmtrReqHead.minApCount = *measReqElemBody++;

  rangeReq.ftmrrReqHead = fmtrReqHead;
  log_verbose(TAG, "%s - FTMRR Header - randomInterval(%u) minApCount(%u)",
              __FUNCTION__, fmtrReqHead.randomInterval, fmtrReqHead.minApCount);

  // after moving passed the FTMR field header,
  // see if we have any FTM Range subelements
  elemLen -= MIN_LENGTH_FTMR_FIELD;
  if (0 == elemLen)
  {
    // Bad element - expected to find neighbor report elements
    log_debug(TAG, " %s - Received FTM Range request with no elements, aborting!",
              __FUNCTION__);
    return retVal;
  }

  // parse the frame and put the NR elements in a vector
  while (elemLen)
  {
    measReqElemBody = parseNeighborReport(elemLen, measReqElemBody, rangeReq);
    if (measReqElemBody == NULL)
    {
      break; // no more elements to parse
    }
  }

  // parse the NR elements
  if (rangeReq.neighborRprtElem.getNumOfElements())
  {
    vector<LOWIPeriodicNodeInfo> nodes;
    log_verbose(TAG, "%s - Number of ranging APs(%u)",
                __FUNCTION__, rangeReq.neighborRprtElem.getNumOfElements());
    for (unsigned int i = 0; i < rangeReq.neighborRprtElem.getNumOfElements(); i++)
    {
      LOWIPeriodicNodeInfo node;
      NeighborRprtElem nbrElem = rangeReq.neighborRprtElem[i];
      node.bssid = LOWIMacAddress(nbrElem.bssid);

      retrieveFreqInfo(node, nbrElem);

      bssidInfoToPreambleAndBw(nbrElem.bssidInfo, nbrElem.channelWidth,
                               node.preamble, node.bandwidth);

      node.rttType = RTT3_RANGING;

      nodes.push_back(node);
    }

    // Create LOWI Request and send out to LOWI controller.
    // Use dummy message Id for now since no response is expected for this msg. The FTMR
    // report request is another request from the controller to send out FTMR Report
    mInternalMsgId++;

    log_verbose(TAG, "%s: Sending Internal FTMRR to LOWI controller with %u Aps and msgID(%u)",
                __FUNCTION__, rangeReq.neighborRprtElem.getNumOfElements(), mInternalMsgId);
    LOWIMacAddress mac     = LOWIMacAddress(sourceMac);
    LOWIMacAddress selfMac = LOWIMacAddress(staMac);
    RadioMeasReqParams params;
    params.mRequesterBssid = mac;
    params.mSelfBssid      = selfMac;
    params.mFrequency      = freq;
    params.mDiagToken      = rangeReq.dialogTok;
    params.mMeasToken      = rangeReq.measReqElem.measTok;

    LOWIFTMRangeReqMessage *lowiFtmrMessage =
        new (std::nothrow) LOWIFTMRangeReqMessage(mInternalMsgId, nodes, params, TAG);
    if (NULL != lowiFtmrMessage)
    {
      mInternalMessageListener->internalMessageReceived(lowiFtmrMessage);
    }
    else
    {
      log_debug(TAG, "%s: Mem alloc failure", __FUNCTION__);
      return retVal;
    }
  }
  else
  {
    log_verbose(TAG, "%s: No APs in FTMRR - No Ranging to be done",
                __FUNCTION__);
  }

  retVal = 0;
  return retVal;
} // processFtmRangeReq


void LOWIROMEWifiDriver::retrieveFreqInfo(LOWIPeriodicNodeInfo &node,
                                          NeighborRprtElem &nbrElem)
{
  node.frequency         = LOWIUtils::channelBandToFreq(nbrElem.channelNumber);
  node.band_center_freq1 = LOWIUtils::channelBandToFreq(nbrElem.centerFreq0_Channel);
  node.band_center_freq2 = 0;
} // retrieveFreqInfo

int8 LOWIROMEWifiDriver::processLciReq(uint8 dialogTok,
                                       MeasReqElem &measReqElement,
                                       uint8 *measReqElemBody,
                                       uint8 sourceMac[BSSID_SIZE],
                                       uint8 staMac[BSSID_SIZE],
                                       uint32 freq)
{
  int8 retVal = -1;
  // start parsing the LCI Measurement Request field
  //         | Location | Optional    |
  //         | Subject  | Subelements |
  // #bytes: | 1        | variable    |

  uint8 locSubject = *measReqElemBody;

  // check if out of range or not supported
  if ((locSubject >= LOWI_LOC_SUBJECT_UNDEF) || (LOWI_LOC_SUBJECT_REMOTE != locSubject))
  {
    log_debug(TAG, "%s: location subject out of range or not supported(%u)",
              __FUNCTION__, locSubject);
    return retVal;
  }

  // Create LOWI Request and send out to LOWI controller.
  RadioMeasReqParams params;
  params.mRequesterBssid = LOWIMacAddress(sourceMac);
  params.mSelfBssid      = LOWIMacAddress(staMac);
  params.mFrequency      = freq;
  params.mDiagToken      = dialogTok;
  params.mMeasToken      = measReqElement.measTok;

  LOWILCIReqMessage *lciMsg =
      new(std::nothrow) LOWILCIReqMessage(mInternalMsgId++, locSubject, params, TAG);
  if (NULL != lciMsg)
  {
    mInternalMessageListener->internalMessageReceived(lciMsg);
  }
  else
  {
    log_debug(TAG, "%s: Mem alloc failure", __FUNCTION__);
    return retVal;
  }

  retVal = 0;
  return retVal;
} // processLciReq

void LOWIROMEWifiDriver::appendLciSubElem(LOWILCIRprtMessage* req, uint8 *frameBody,
                                          uint32 &frameBodyLen, uint32 &measRptLen)
{
  LOWILCIInfo lciInfo;

  // Add the LCI Subelement ID
  frameBody[frameBodyLen++] = LOWI_LCI_SUBELEM_ID;
  // Keep track of where to store the subelement length
  uint8 * pMeasSubElemLen   = &frameBody[frameBodyLen++];
  // default lci subelement length
  uint8 elemLen = LOWI_LCI_SUBELEM_MIN_LEN;

  // pack the LCI Field if available
  lciInfo = req->getLCIRprtInfo().lciParams;
  if (true == lciInfo.lciInfoIsKnown)
  {
    elemLen = LOWI_LCI_SUBELEM_MAX_LEN;
    LOWILCIField lciField;
    memset(&lciField, 0, sizeof(lciField));
    packLciField(lciField, lciInfo);
    memcpy(&frameBody[frameBodyLen], &lciField, sizeof(lciField));
    frameBodyLen += elemLen;
  }

  *pMeasSubElemLen = elemLen;

  // Update the Measurement Report length
  measRptLen += (SUBELEM_HEADER_LEN + elemLen);
} // appendLciSubElem

void LOWIROMEWifiDriver::appendZSubElem(LOWILCIRprtMessage* req, uint8 *frameBody,
                                        uint32 &frameBodyLen, uint32 &measRptLen)
{
  uint8 elemLen = LOWI_Z_SUBELEM_MIN_LEN;
  // Z Subelement:
  //         | Subelem | Length | STA Floor   | STA Height  | STA Height         |
  //         | ID      |        | Information | Above Floor | Above Floor Uncert |
  // #bytes: |   1     |   1    |    2        |     3       |      1             |

  // Add the LCI Subelement ID
  frameBody[frameBodyLen++] = LOWI_Z_SUBELEM_ID;

  LOWIZSubelementInfo zSubElem = req->getLCIRprtInfo().zSubElem;
  if (LOWI_UNKNOWN_FLOOR == zSubElem.staFloorInfo.floorNum)
  {
    // Add the subelement length
    frameBody[frameBodyLen++] = LOWI_Z_SUBELEM_MIN_LEN;
    elemLen = LOWI_Z_SUBELEM_MIN_LEN;
    // Add the STA Floor Information
    uint16 floorInfo = (zSubElem.staFloorInfo.floorNum << 2) |
                       (zSubElem.staFloorInfo.expectedToMove & 0x3);
    frameBody[frameBodyLen++] = (uint8) (floorInfo & 0xff);
    frameBody[frameBodyLen++] = (uint8)((floorInfo >> 8) & 0xff);
  }
  else
  {
    // Add the subelement length
    frameBody[frameBodyLen++] = LOWI_Z_SUBELEM_MAX_LEN;
    elemLen = LOWI_Z_SUBELEM_MAX_LEN;

    // Add the STA Floor Information
    uint16 floorInfo = (zSubElem.staFloorInfo.floorNum << 2) |
                       (zSubElem.staFloorInfo.expectedToMove & 0x3);
    frameBody[frameBodyLen++] = (uint8) (floorInfo & 0xff);
    frameBody[frameBodyLen++] = (uint8)((floorInfo >> 8) & 0xff);

    // Add the STA Height Above Floor
    frameBody[frameBodyLen++] = (uint8) (zSubElem.staHeightAboveFloor & 0xff);
    frameBody[frameBodyLen++] = (uint8)((zSubElem.staHeightAboveFloor >> 8) & 0xff);
    frameBody[frameBodyLen++] = (uint8)((zSubElem.staHeightAboveFloor >> 16) & 0xff);

    // Add the STA Height Above Floor Uncertainty
    frameBody[frameBodyLen++] = (uint8)zSubElem.staHeightAboveFloorUncert;
  }

  // Update the Measurement Report length
  measRptLen += (SUBELEM_HEADER_LEN + elemLen);
} // appendZSubElem

void LOWIROMEWifiDriver::appendUsageRulesSubElem(LOWILCIRprtMessage* req, uint8 *frameBody,
                                                 uint32 &frameBodyLen, uint32 &measRptLen)
{
  // Add the LCI Subelement ID
  frameBody[frameBodyLen++] = LOWI_USAGE_RULES_SUBELEM_ID;

  // Add the Usage Rules/Policy paramaters
  LOWIUsageRulesParams usageRules = req->getLCIRprtInfo().usageRules;
  uint8 rules = 0;
  rules |= (usageRules.staLocPolicy         & 0x1) << 3;
  rules |= (usageRules.retentionExpires     & 0x1) << 2;
  rules |= (usageRules.retranmissionAllowed & 0x1);
  frameBody[frameBodyLen++] = LOWI_USAGE_RULES_SUBELEM_MIN_LEN;
  frameBody[frameBodyLen++] = rules;

  // Update the Measurement Report length
  measRptLen += (SUBELEM_HEADER_LEN + LOWI_USAGE_RULES_SUBELEM_MIN_LEN);
}  // appendUsageRulesSubElem

void LOWIROMEWifiDriver::packLciField(LOWILCIField &lciField, LOWILCIInfo &lciInfo)
{
  // pack the latitude parameters
  lciField.latUnc       = lciInfo.latitudeUnc        & 0x3F;
  lciField.lat1         = lciInfo.latitude           & 0x03;
  lciField.lat2         = (lciInfo.latitude >> 2)    & 0xFF;
  lciField.lat3         = (lciInfo.latitude >> 10)   & 0xFF;
  lciField.lat4         = (lciInfo.latitude >> 18)   & 0xFF;
  lciField.lat5         = (lciInfo.latitude >> 26)   & 0xFF;
  // pack the longitude parameters
  lciField.latUnc       = lciInfo.latitudeUnc        & 0x3F;
  lciField.lon1         = lciInfo.longitude          & 0x03;
  lciField.lon2         = (lciInfo.longitude >> 2)   & 0xFF;
  lciField.lon3         = (lciInfo.longitude >> 10)  & 0xFF;
  lciField.lon4         = (lciInfo.longitude >> 18)  & 0xFF;
  lciField.lon5         = (lciInfo.longitude >> 26)  & 0xFF;
  // pack the altitude parameters
  lciField.altType      = lciInfo.altitudeType       & 0x0F;
  lciField.altUnc1      = lciInfo.altitudeUnc        & 0x0F;
  lciField.altUnc2      = (lciInfo.altitudeUnc >> 4) & 0x03;
  lciField.alt1         = lciInfo.altitude           & 0x3F;
  lciField.alt2         = (lciInfo.altitude >> 6)    & 0xFF;
  lciField.alt3         = (lciInfo.altitude >> 14)   & 0xFF;
  lciField.alt4         = (lciInfo.altitude >> 22)   & 0xFF;
  lciField.datum        = lciInfo.datum;
  lciField.regLocAgree  = lciInfo.regLocAgree;
  lciField.regLocDSE    = lciInfo.regLocDSE;
  lciField.dependentSTA = lciInfo.dependentSTA;
  lciField.version      = lciInfo.version;

  log_verbose(TAG, "%s: latUnc(0x%x) lat1(0x%x)  lat2(0x%x) lat3(0x%x) lat4(0x%x) lat5(0x%x)",
              __FUNCTION__, lciField.latUnc, lciField.lat1, lciField.lat2,
              lciField.lat3, lciField.lat4, lciField.lat5) ;
}

void LOWIROMEWifiDriver::printFrame(uint8 *frameBody, uint32 frameBodyLen)
{
  if (NULL != frameBody)
  {
    int kk = 0;
    int retVal = 0;
    char frameChar[LOWI_MEAS_RSP_FRAME_LEN];
    memset(frameChar, 0, LOWI_MEAS_RSP_FRAME_LEN);
    for (uint32 ii = 0; ii < frameBodyLen && kk < LOWI_MEAS_RSP_FRAME_LEN; ii++)
    {
      retVal = snprintf(frameChar+kk, LOWI_MEAS_RSP_FRAME_LEN-kk, "%02x ", frameBody[ii]);
      if (retVal < 0)
      {
        break;
      }
      kk += retVal;
    }

    if (retVal < 0)
    {
      log_debug(TAG, "%s: Failed to print frameBody", __FUNCTION__);
    }
    else
    {
      log_debug(TAG, "%s: FrameBody(%s)", __FUNCTION__, frameChar);
    }
  }
}
