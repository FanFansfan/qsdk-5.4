/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI TLV class implementation

GENERAL DESCRIPTION
  This file contains the implementation for the LOWI TLV class

  Copyright (c) 2016, 2018-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc
=============================================================================*/
#include <base_util/log.h>
#include "lowi_tlv.h"

using namespace qc_loc_fw;

const char * const LOWITlv::TAG = "LOWITlv";


/* msg strings used for printing/debugging LOWITlv type */
const char* LOWI_TLV_TYPE[10] =
{
  "LOWITLV_BASE",
  "LOWITLV_RSP_HEAD",
  "LOWITLV_CAP_RSP_HEAD",
  "LOWITLV_CAP_RSP_EVENT",
  "LOWITLV_MEASRSP_HEAD",
  "LOWITLV_PER_PEER_EVENT_HDR",
  "LOWITLV_PER_FRAME_INFO",
  "LOWITLV_CHANNELRESP_HEAD",
  "LOWITLV_RESPONDERRESP_HEAD",
  "LOWITLV_CHANNELINFO_HEAD"
};

// Bitmask used by capabilities for 11 MC
#define LOWI_CLEAR_11MC_BIT 0xfe

///////////////////////////////////////////////////////////////
// LOWTlv Class Implementation (base class for all other TLVs)
///////////////////////////////////////////////////////////////
LOWITlv::LOWITlv()
{
  mTlv = NULL;
  mTag = WMIRTT_TLV_TAG_UNKNOWN;
  mLen = 0;
}

LOWITlv::LOWITlv(uint8 *pTlv, uint32 len):LOWITlv()
{
  mTlv = new uint8[len];
  if (NULL != mTlv)
  {
    // fill in the TLV contents
    memcpy(mTlv, pTlv, len);
    // get the tag
    uint32 *tlvHeader = (uint32 *)mTlv;
    mTag = (WMIRTT_TLV_TAG_ID)WMIRTT_TLV_GET_TLVTAG(*tlvHeader);
    // Use the length passed by the client. In general, this should be the length
    // of the specific TLV structure we are subclassing.
    mLen = len;
  }
  else
  {
    log_debug(TAG, "%s: mem alloc failure while constructing TLV\n", __FUNCTION__);
  }
}

LOWITlv::LOWITlv(const LOWITlv &rhs):LOWITlv()
{
  log_verbose(TAG, "%s (copy ctor)\n", __FUNCTION__);
  mTlv = new uint8[rhs.mLen];
  if (NULL != mTlv)
  {
    mLen = rhs.mLen;
    memcpy(mTlv, rhs.mTlv, mLen);
    mTag = rhs.mTag;
  }
  else
  {
    log_debug(TAG, "%s: mem alloc failure while constructing TLV\n", __FUNCTION__);
  }
}

LOWITlv& LOWITlv::operator=(const LOWITlv &rhs)
{
  if (this != &rhs)
  {
    mLen = rhs.mLen;
    uint8 *temp = new uint8[mLen];
    if (NULL != temp)
    {
      delete[] mTlv;
      mTlv = temp;
      memcpy(mTlv, rhs.mTlv, mLen);
      mTag = rhs.mTag;
    }
  }
  return *this;
}

LOWITlv::~LOWITlv()
{
  if (NULL != mTlv)
  {
      delete[] mTlv;
      mTlv = NULL;
  }
}

////////////////////////////////////////////
// LOWITlvRspHead Class Implementation
////////////////////////////////////////////
LOWITlvRspHead::LOWITlvRspHead(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), mRttMsgSubType(RTT_MSG_SUBTYPE_INVALID),
  mReqId(0), mFragField(0)
{
  wmi_rtt_oem_rsp_head *pTlv = (wmi_rtt_oem_rsp_head *)mTlv;
  if (pTlv != NULL)
  {
    mRttMsgSubType = pTlv->sub_type;
    mReqId         = pTlv->req_id;
    mFragField     = pTlv->fragment_info;
  }
}

LOWITlvRspHead::~LOWITlvRspHead()
{
}

void LOWITlvRspHead::getFragmentInfo(rttFragmentInfo & fragInfo) const
{
  fragInfo.isFragment  = WMI_RTT_RSP_MORE_FRAG_GET(mFragField);
  fragInfo.fragmentIdx = WMI_RTT_RSP_FRAG_IDX_GET(mFragField);
  fragInfo.fragmentLen = WMI_RTT_RSP_FRAG_LEN_GET(mFragField);
  fragInfo.tokenId     = WMI_RTT_RSP_TOKEN_ID_GET(mFragField);
}

////////////////////////////////////////////
// LOWICapRspHeadTlv Class Implementation
////////////////////////////////////////////
LOWICapRspHeadTlv::LOWICapRspHeadTlv(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), version(0), revision(0)
{
  wmi_rtt_oem_cap_rsp_head *pTlv = (wmi_rtt_oem_cap_rsp_head *)mTlv;
  if (pTlv != NULL)
  {
    version  = pTlv->version;
    revision = pTlv->revision;
    memcpy(serviceBitMask, pTlv->service_bitmask, RTT_SERVICE_BITMASK_SZ);
  }
  else
  {
    memset(serviceBitMask, 0, sizeof(serviceBitMask));
  }
}

LOWICapRspHeadTlv::~LOWICapRspHeadTlv()
{
}

////////////////////////////////////////////
// LOWIOemChannelRspHeadTlv Class Implementation
////////////////////////////////////////////
LOWIOemChannelRspHeadTlv::LOWIOemChannelRspHeadTlv(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), version(0), revision(0)
{
  wmi_rtt_oem_get_channel_info_rsp_head *pTlv = (wmi_rtt_oem_get_channel_info_rsp_head *)mTlv;
  if (pTlv != NULL)
  {
    version  = pTlv->version;
    revision = pTlv->revision;
  }
}


////////////////////////////////////////////
// LOWIResponderRspHeadTlv Class Implementation
////////////////////////////////////////////
LOWIResponderRspHeadTlv::LOWIResponderRspHeadTlv(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), version(0), revision(0)
{
  wmi_rtt_oem_set_responder_mode_rsp_head *pTlv = (wmi_rtt_oem_set_responder_mode_rsp_head *)mTlv;
  if (pTlv != NULL)
  {
    version  = pTlv->version;
    revision = pTlv->revision;
  }
}

LOWIResponderRspHeadTlv::~LOWIResponderRspHeadTlv()
{
}

////////////////////////////////////////////
// LOWIChannelRspHeadTlv Class Implementation
////////////////////////////////////////////
LOWIChannelRspHeadTlv::LOWIChannelRspHeadTlv(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), mMhz(0), mCenterFreq1(0), mCenterFreq2(0), mInfo(0),
  mRegInfo1(0), mRegInfo2(0)
{
  wmi_rtt_oem_channel_info *pTlv = (wmi_rtt_oem_channel_info *)mTlv;
  if (pTlv != NULL)
  {
    mMhz  = pTlv->mhz;
    mCenterFreq1 = pTlv->band_center_freq1;
    mCenterFreq2 = pTlv->band_center_freq2;
    mInfo = pTlv->info;
    mRegInfo1 = pTlv->reg_info_1;
    mRegInfo2 = pTlv->reg_info_2;
  }
}

////////////////////////////////////////////
// LOWICapRspEventTlv Class Implementation
////////////////////////////////////////////
LOWICapRspEventTlv::LOWICapRspEventTlv(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), mSupport(0), mCap(0), mCap2(0)
{
  wmi_rtt_oem_cap_rsp_event *pTlv = (wmi_rtt_oem_cap_rsp_event *)mTlv;
  if (pTlv != NULL)
  {
    mSupport = pTlv->support;
    mCap     = pTlv->cap;
    mCap2    = pTlv->cap_2;
  }
}

LOWICapRspEventTlv::~LOWICapRspEventTlv()
{
}

void LOWICapRspEventTlv::getRttCaps(RomeRttCapabilities & caps) const
{
  // LOWI expects bit 2 to enabled if 11mc is supported,
  // but FW only enables bit 1 if 11mc is supported

  // Save bit 0 and shift rest of bits by 1.
  // This will move the mc support bit to bit 2.
  caps.rangingTypeMask = WMI_RTT_CAP_VER_GET(mSupport) & 0x01;
  uint8 tmp = WMI_RTT_CAP_VER_GET(mSupport) & LOWI_CLEAR_11MC_BIT;
  tmp = tmp << 1;
  caps.rangingTypeMask         |= tmp;
  caps.supportedFramesMask     = WMI_RTT_CAP_FRAME_GET(mSupport);
  caps.maxDestPerReq           = WMI_RTT_CAP_MAX_DES_NUM_GET(mSupport);
  caps.maxMeasPerDest          = WMI_RTT_CAP_MAX_MEAS_NUM_GET(mSupport);
  caps.maxChannelsAllowed      = WMI_RTT_CAP_MAX_CHAN_NUM_GET(mCap);
  caps.maxBwAllowed            = WMI_RTT_CAP_MAX_BW_GET(mCap);
  caps.preambleSupportedMask   = WMI_RTT_CAP_PREAMBLE_GET(mCap);
  caps.reportTypeSupportedMask = WMI_RTT_CAP_REPORT_TYPE_GET(mCap);
  caps.maxRfChains             = WMI_RTT_CAP_MAX_CHAIN_MASK_GET(mCap2);
  caps.facTypeMask             = WMI_RTT_CAP_FAC_GET(mCap2);
  caps.numPhys                 = WMI_RTT_CAP_RADIO_NUM_GET(mCap2);
  caps.fwMultiBurstSupport     = WMI_RTT_CAP_MULTIBURST_SUPPORT_GET(mCap2);
}

////////////////////////////////////////////
// LOWIMeasRspHeadTlv Class Implementation
////////////////////////////////////////////
LOWIMeasRspHeadTlv::LOWIMeasRspHeadTlv(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), mInfo(0), mChannel(0)
{
  wmi_rtt_oem_measrsp_head *pTlv = (wmi_rtt_oem_measrsp_head *)mTlv;
  if (pTlv != NULL)
  {
    mInfo = pTlv->info;
    memcpy(mDestMac, pTlv->dest_mac, ETH_ALEN_PLUS_2);
    mChannel = pTlv->channel_info;
  }
  else
  {
    memset(mDestMac, 0, sizeof(wmi_mac_addr));
  }
}

LOWIMeasRspHeadTlv::~LOWIMeasRspHeadTlv()
{
}

void LOWIMeasRspHeadTlv::getMeasRspHead(rttMeasRspHead &rspHeadInfo) const
{
  rspHeadInfo.rprtType     = WMI_RTT_REPORT_REPORT_TYPE_GET(mInfo);
  rspHeadInfo.rttMeasType  = WMI_RTT_REPORT_MEAS_TYPE_GET(mInfo);
  rspHeadInfo.rprtStatusV3 = WMI_RTT_REPORT_V3_STATUS_GET(mInfo); // tula, or is it V3_FINISH???
  rspHeadInfo.sendDoneV3   = WMI_RTT_REPORT_V3_FINISH_GET(mInfo);
  rspHeadInfo.tmStart      = WMI_RTT_REPORT_V3_TM_START_GET(mInfo);
  rspHeadInfo.numAPs       = WMI_RTT_REPORT_NUM_AP_GET(mInfo);
  memcpy(rspHeadInfo.destMac, mDestMac, ETH_ALEN_PLUS_2);
  rspHeadInfo.channel      = mChannel;
}

void LOWIArrayUINT8Tlv::getArrayUint8Buff(uint8 *buff, uint32 len)
{
  memcpy(buff, mTlv, len);
}
///////////////////////////////////////////////
// LOWIPerPeerEventHdrTlv Class Implementation
///////////////////////////////////////////////

LOWIPerPeerEventHdrTlv::LOWIPerPeerEventHdrTlv(uint8 *tlv, uint32 len, uint32 lenFromFW)
: LOWITlv(tlv, MIN(len, lenFromFW)), mControl(0), mResultInfo1(0), mResultInfo2(0),
  mResultInfo3(0), mMeasStartTSF(LOWI_INVALID_MEAS_START_TSF)
{
  wmi_rtt_oem_per_peer_event_hdr *pTlv = (wmi_rtt_oem_per_peer_event_hdr *)mTlv;
  if (pTlv != NULL)
  {
    memcpy(mPeerMac, pTlv->dest_mac, ETH_ALEN_PLUS_2);
    mControl      = pTlv->control;
    mResultInfo1  = pTlv->result_info1;
    mResultInfo2  = pTlv->result_info2;
    mResultInfo3  = pTlv->result_info3;
  }
  else
  {
    memset(mPeerMac, 0, sizeof(wmi_mac_addr));
  }

  // If the length of the TLV sent by FW is smaller that the length of the TLV known
  // to LOWI, then some fields in lowi will be invalid. This would be the case, for
  // example, when LOWI is working with older FW. In order to determine which fields
  // in LOWI are invalid, the offset of the potentially invalid fields is checked against
  // the length of the TLV sent by FW.
  uint32 measStartTsfOffset =
    (uint32)offsetof(wmi_rtt_oem_per_peer_event_hdr, meas_start_tsf);
  if (measStartTsfOffset >= lenFromFW)
  {
    log_debug(TAG, "%s: meas_start_tsf field invalid in TLV "
                   "wmi_rtt_oem_per_peer_event_hdr (measStartTsfOffset: %u)(lenFromFW: %u)",
              __FUNCTION__, measStartTsfOffset, lenFromFW);
    mMeasStartTSF = LOWI_INVALID_MEAS_START_TSF;
  }
  else if (pTlv != NULL)
  {
    mMeasStartTSF = pTlv->meas_start_tsf;
  }
}

LOWIPerPeerEventHdrTlv::~LOWIPerPeerEventHdrTlv()
{
}

void LOWIPerPeerEventHdrTlv::getPerPeerInfo(rttPerPeerInfo & perPeerInfo) const
{
  memcpy(perPeerInfo.peerMac, mPeerMac, ETH_ALEN_PLUS_2);
  perPeerInfo.numMeasThisAP      = getNumMeasRprts();
  perPeerInfo.rttMeasType        = getRttMeasType();
  perPeerInfo.isQtiPeer          = isQtiPeerType();
  perPeerInfo.numFrmAttempted    = getMeasFramesAttempted();
  perPeerInfo.actualBurstDur     = getActualBurstDur();
  perPeerInfo.actualNumFrmPerBur = getActualNumFramesPerBurst();
  perPeerInfo.retryAfterDur      = getRetryAfterDur();
  perPeerInfo.actualBurstExp     = getActualBurstExp();
  perPeerInfo.numIEs             = getNumIEsInHdr();
  perPeerInfo.burstIdx           = getBurstIdx();
  perPeerInfo.measStartTSF       = getTSF();
}

////////////////////////////////////////////
// LOWIPerFrameInfoTlv Class Implementation
////////////////////////////////////////////
LOWIPerFrameInfoTlv::LOWIPerFrameInfoTlv(uint8 *tlv, uint32 len)
: LOWITlv(tlv, len), mRssi(0), mT1{}, mT2{}, mT3Del(0), mT4Del(0),
  mTxRateInfo1(0), mTxRateInfo2(0), mRxRateInfo1(0), mRxRateInfo2(0),
  mMaxTodToaErr(0)
{
  wmi_rtt_oem_per_frame_info *pTlv = (wmi_rtt_oem_per_frame_info *)mTlv;
  if (pTlv != NULL)
  {
    mRssi = pTlv->rssi;
    mT1 = pTlv->t1;
    mT2 = pTlv->t2;
    mT3Del = pTlv->t3_del;
    mT4Del = pTlv->t4_del;
    mTxRateInfo1 = pTlv->tx_rate_info_1;
    mTxRateInfo2 = pTlv->tx_rate_info_2;
    mRxRateInfo1 = pTlv->rx_rate_info_1;
    mRxRateInfo2 = pTlv->rx_rate_info_2;
    mMaxTodToaErr = pTlv->max_tod_toa_error;
  }
}

LOWIPerFrameInfoTlv::~LOWIPerFrameInfoTlv()
{
}

void LOWIPerFrameInfoTlv::parsePerFrameInfo(rttPerFrameInfo & perFrmInfo) const
{
  perFrmInfo.rssi         = mRssi;
  perFrmInfo.t1           = mT1;
  perFrmInfo.t2           = mT2;
  perFrmInfo.t3_del       = mT3Del;
  perFrmInfo.t4_del       = mT4Del;
  perFrmInfo.txPreamble   = WMI_RTT_RSP_X_PREAMBLE_GET(mTxRateInfo1);
  perFrmInfo.txBw         = WMI_RTT_RSP_X_BW_USED_GET(mTxRateInfo1);
  perFrmInfo.txRateMcsIdx = WMI_RTT_RSP_X_MCS_GET(mTxRateInfo1);
  perFrmInfo.txBitRate    = mTxRateInfo2;
  perFrmInfo.rxPreamble   = WMI_RTT_RSP_X_PREAMBLE_GET(mRxRateInfo1);
  perFrmInfo.rxBw         = WMI_RTT_RSP_X_BW_USED_GET(mRxRateInfo1);
  perFrmInfo.rxRateMcsIdx = WMI_RTT_RSP_X_MCS_GET(mRxRateInfo1);
  perFrmInfo.chainMask    = WMI_RTT_CHAIN_MASK_GET(mRxRateInfo1);
  perFrmInfo.useTxChainNo = WMI_RTT_USED_TX_CHAIN_NUM_MASK_GET(mTxRateInfo1);
  perFrmInfo.useRxChainNo = WMI_RTT_USED_RX_CHAIN_NUM_MASK_GET(mRxRateInfo1);
  perFrmInfo.rxBitRate    = mRxRateInfo2;
  perFrmInfo.maxTodError  = WMI_RTT_TOD_ERR_GET(mMaxTodToaErr);
  perFrmInfo.maxToaError  = WMI_RTT_TOA_ERR_GET(mMaxTodToaErr);
  //Add Sanity check for TX BW
  if (perFrmInfo.txBw >= BW_MAX)
  {
    log_error(TAG, "Received invalid Tx BW from fw %d, capping to default", perFrmInfo.txBw);
    perFrmInfo.txBw = BW_20MHZ;
  }

  //Add Sanity check for RX BW
  if (perFrmInfo.rxBw >= BW_MAX)
  {
    log_error(TAG, "Received Invalid Rx BW from fw %d, capping to default", perFrmInfo.rxBw);
    perFrmInfo.rxBw = BW_20MHZ;
  }
}

/////////////////////////////////////
// LOWIFragInfo Class Implementation
/////////////////////////////////////
const char * const LOWIFragInfo::TAG = "LOWIFragInfo";

LOWIFragInfo::LOWIFragInfo(uint32 tknId)
{
  log_verbose(TAG, "%s (ctor)\n", __FUNCTION__);
  mTknId    = tknId;
  mFragBuff = NULL;
}

LOWIFragInfo::~LOWIFragInfo()
{
  log_verbose(TAG, "%s (dtor)\n", __FUNCTION__);
  delete mFragBuff;
}

uint32 LOWIFragInfo::addFrag(uint8 *frag, uint32 len)
{
  uint32 retVal = -1;
  do
  {
    if (NULL == mFragBuff)
    {
      // create buffer and add the data
      mFragBuff = LOWIDynBuffer::createInstance(frag, len, 0);
      if (NULL == mFragBuff)
      {
        log_warning(TAG, "%s: mem alloc failure", __FUNCTION__);
        break;
      }
      retVal = 0;
    }
    else
    {
      // add to existing buffer
      retVal = mFragBuff->addData(frag, len);
    }
  } while (0);
  return retVal;
}

