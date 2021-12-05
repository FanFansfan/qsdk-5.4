/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI TLV Handler class implementation

GENERAL DESCRIPTION
  This file contains the implementation of functions that handle TLVs

Copyright (c) 2016-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/

#include <base_util/log.h>
#include "lowi_wifi_tlv_handler.h"
#include <lowi_strings.h>

using namespace qc_loc_fw;

// Break if variable is null and use a string to log the reason
#define LOWI_BREAK_IF_NULL(r,s) if (NULL == (r))      \
        {                                             \
          log_debug (TAG, "%s: %s", __FUNCTION__, s); \
          break;                                      \
        }

#define LOWI_TLV_BREAK_IF_BAD_TAG(t,x,s) if((t) != (x))              \
        {                                                            \
          log_debug (TAG,"%s: Invalid TLV: %s", __FUNCTION__, s);    \
          break;                                                     \
        }                                                            \
        else                                                         \
        {                                                            \
          log_verbose (TAG,"%s: Received TLV: %s", __FUNCTION__, s); \
        }

#undef HDLR_ENTER_EXIT_DBG

#ifdef HDLR_ENTER_EXIT_DBG
#define HDLR_ENTER() log_verbose(TAG, "ENTER: %s", __FUNCTION__);
#define HDLR_EXIT()  log_verbose(TAG, "EXIT: %s", __FUNCTION__);
#define LOOP_END_DBG() log_verbose(TAG, "%s: Loop end TLV\n", __FUNCTION__);
#define LOOP_START_DBG() log_verbose(TAG, "%s: Loop start TLV\n", __FUNCTION__);
#else
#define HDLR_ENTER()
#define HDLR_EXIT()
#define LOOP_END_DBG()
#define LOOP_START_DBG()
#endif

#define LEGACY_6MBPS_MCS   3
#define VHT_HT_6_5MBPS_MCS 0

const char * const LOWIWifiTlvHandler::TAG = "LOWIWifiTlvHandler";

LOWIWifiTlvHandler::LOWIWifiTlvHandler()
{
  mPeerIdx  = 0;
  mPeerLs   = 0;
  mMeasLs   = 0;
  mMsgArrSz = 0;
}

LOWIWifiTlvHandler::~LOWIWifiTlvHandler()
{

}

int LOWIWifiTlvHandler::processTLVs(uint8* msg,
                                    vector<LOWITlv *> &tlvs,
                                    uint8 subtype, uint32 reportType)
{
  HDLR_ENTER()
  int retVal = -1;

  do
  {
    // check the expected order of the TLVs
    switch (subtype)
    {
      case RTT_MSG_SUBTYPE_CAPABILITY_RSP:
        mMsgArrSz = sizeof(capsMsgArr)/sizeof(measMsgInfo);
        retVal = processCommonTlvs(msg, capsMsgArr, tlvs);
        break;
      case RTT_MSG_SUBTYPE_ERROR_REPORT_RSP:
        mMsgArrSz = sizeof(errMsgArr)/sizeof(measMsgInfo);
        retVal = processCommonTlvs(msg, errMsgArr, tlvs);
        break;
      case RTT_MSG_SUBTYPE_MEASUREMENT_RSP:
        if((reportType == RTT_REPORT_PER_FRAME_WITH_CFR) ||
           (reportType == RTT_REPORT_PER_FRAME_WITH_CFR_CIR))
        {
          mMsgArrSz = sizeof(cfrmeasMsgArr)/sizeof(measMsgInfo);
          retVal = processCommonTlvs(msg, cfrmeasMsgArr, tlvs);
        }
        else
        {
        mMsgArrSz = sizeof(measMsgArr)/sizeof(measMsgInfo);
        retVal = processCommonTlvs(msg, measMsgArr, tlvs);
        }
        break;
      case RTT_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP:
        mMsgArrSz = sizeof(channelMsgArr)/sizeof(measMsgInfo);
        retVal = processCommonTlvs(msg, channelMsgArr, tlvs);
        break;
      case RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_RSP:
        mMsgArrSz = sizeof(ResponderchannelMsgArr)/sizeof(measMsgInfo);
        retVal = processCommonTlvs(msg, ResponderchannelMsgArr, tlvs);
        break;
      default:
        log_verbose(TAG,"%s: Received subtype(%u)", __FUNCTION__,
                    LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)subtype));
        break;
    }
  } while (0);

  HDLR_EXIT()
  return retVal;
}

int LOWIWifiTlvHandler::verifyTlvRspHead(wmi_rtt_oem_rsp_head *pHead, WMIRTT_OEM_MSG_SUBTYPE *subtype)
{
  HDLR_ENTER()
  int retVal = -1;
  do
  {
    LOWI_BREAK_IF_NULL(pHead, "Bad argument...NULL ptr")

    // check the tag
    if ((WMIRTT_TLV_TAG_ID)WMIRTT_TLV_GET_TLVTAG(pHead->tlv_header) !=
        WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head)
    {
        log_verbose(TAG,"%s: Invalid TLV at the head of the FW msg(%u)", __FUNCTION__,
                    (WMIRTT_TLV_TAG_ID)WMIRTT_TLV_GET_TLVTAG(pHead->tlv_header));
        break;
    }

    *subtype = (WMIRTT_OEM_MSG_SUBTYPE)WMI_RTT_SUB_TYPE_GET(pHead->sub_type);

    // need to always subtract 1 when printing subtype
    log_verbose(TAG,"%s: Received subtype(%s)",
                __FUNCTION__, LOWIStrings::to_string(*subtype) );
    retVal = 0;
  } while (0);

  HDLR_EXIT()
  return retVal;
}
// Note to self: report type 3 needs to go in when it's multi burst. i.e. burst exponent is > 0. Need to guard for illegal combinations.
void LOWIWifiTlvHandler::cleanupTlvs(vector<LOWITlv *> &tlvs)
{
  HDLR_ENTER()
  for(uint32 ii = 0; ii < tlvs.getNumOfElements(); ++ii)
  {
     delete tlvs[ii];
  }
  tlvs.flush();
  HDLR_EXIT()
}

int LOWIWifiTlvHandler::processCommonTlvs(uint8 *msg,
                                          measMsgInfo const *msgArr,
                                          vector<LOWITlv *> &tlvs)
{
  int retVal  = -1;
  uint8 *pMsg = msg;
  uint32 tag;
  uint32 lenFromFW;

  log_verbose(TAG,"%s: mMsgArrSz(%u)", __FUNCTION__, mMsgArrSz);

  // this index keeps track of which element in msgArr[] is being processed
  uint8 idx = 0;

  // common processing starts
  do
  {
    // get the TLV header and check the tag
    uint32 *pTlvHdr = (uint32 *)pMsg;
    tag = WMIRTT_TLV_GET_TLVTAG(*pTlvHdr);

    // check the expected tag
    int val = checkTlvTag(tag, msgArr, idx);
    if (val < 0)
    {
      log_debug(TAG, "%s: bad TLV, stop processing tagIn(%u) "
                     "pTlvHdr: 0x%x, 0x%x, 0x%x, 0x%x idx(%u) TotalTlvs(%u)\n",
                __FUNCTION__, tag, pTlvHdr[0], pTlvHdr[1], pTlvHdr[2], pTlvHdr[3], idx, mMsgArrSz);
      break;
    }
    else if (val > 0)
    {
      // change the index to go to the appropriate entry in the array
      idx = val;
      continue; // unexpected but good TLV
    }

    lenFromFW = WMIRTT_TLV_GET_TLVLEN(*pTlvHdr);

    // generate a LOWITlv and store it in the vector
    // except for loop_start and loop_end TLVs
    if ( (WMIRTT_TLV_TAG_STRUC_loop_start != msgArr[idx].tag) &&
         (WMIRTT_TLV_TAG_STRUC_loop_end   != msgArr[idx].tag) )
    {
      if (0 != generateLowiTlv(tag, pMsg, msgArr, idx, tlvs, lenFromFW))
      {
        log_debug(TAG, "%s: could not generate LOWITlv idx = %u\n", __FUNCTION__, idx);
        break;
      }
    }
    // advance the ptr to the next tlv
    pMsg += WMIRTT_TLV_GET_TLVLEN(*pTlvHdr);
    idx++;
  } while (idx < mMsgArrSz);

  // Check how far the index has been advanced. For success, the
  // index should have gone through all the elements in msgArr.
  if (idx == mMsgArrSz)
  {
    log_verbose(TAG, "%s: processed all %u TLVs successfully\n", __FUNCTION__, mMsgArrSz);
    printBssidInfo();
    retVal = 0;
  }

  if (0 != retVal)
  {
    // something happened: either TLV is bad or mem alloc failure
    // clean up the vector as there is nothing to parse
    cleanupTlvs(tlvs);
  }

  return retVal;
} // processCommonTlvs

uint32 LOWIWifiTlvHandler::setLoopStartTlv(char *msg)
{
  uint32 *tlvHdr = (uint32 *)msg;

  WMIRTT_TLV_SET_HDR(&(*tlvHdr),
                     WMIRTT_TLV_TAG_STRUC_loop_start,
                     RTT_TLV_HDR_SIZE);
  LOOP_START_DBG()
  return RTT_TLV_HDR_SIZE;
}

uint32 LOWIWifiTlvHandler::setLoopEndTlv(char *msg)
{
  uint32 *tlvHdr = (uint32 *)msg;

  WMIRTT_TLV_SET_HDR(&(*tlvHdr),
                     WMIRTT_TLV_TAG_STRUC_loop_end,
                     RTT_TLV_HDR_SIZE);
  LOOP_END_DBG()
  return RTT_TLV_HDR_SIZE;
}


uint32 LOWIWifiTlvHandler::setReqHeadTlv(char *msg, A_UINT32 reqId, A_UINT32 pdev_id)
{
  wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)msg;

  WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                     WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                     sizeof(wmi_rtt_oem_req_head));
  reqHead->sub_type = RTT_MSG_SUBTYPE_MEASUREMENT_REQ;
  reqHead->req_id   = reqId;
  reqHead->pdev_id  = pdev_id;
  log_verbose(TAG, "%s: subtype(0x%x) requestID(0x%x) pdev_id(%d)\n",
                __FUNCTION__, reqHead->sub_type, reqHead->req_id, reqHead->pdev_id);
  return sizeof(wmi_rtt_oem_req_head);
}

uint32 LOWIWifiTlvHandler::setMeasReqHeadTlv(char *msg, A_UINT32 channelCnt)
{
  wmi_rtt_oem_measreq_head *measReqHead = (wmi_rtt_oem_measreq_head *)msg;
  WMIRTT_TLV_SET_HDR(&measReqHead->tlv_header,
                     WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_head,
                     sizeof(wmi_rtt_oem_measreq_head));
  WMI_RTT_NUM_CHAN_SET(measReqHead->channel_cnt, channelCnt);
  return sizeof(wmi_rtt_oem_measreq_head);
}

uint32 LOWIWifiTlvHandler::setChannelInfoTlv(char *msg, wmi_channel &channelInfo)
{
  wmi_rtt_oem_channel_info *chanInfo = (wmi_rtt_oem_channel_info *)msg;
  WMIRTT_TLV_SET_HDR(&chanInfo->tlv_header,
                     WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info,
                     sizeof(wmi_rtt_oem_channel_info));

  if (channelInfo.band_center_freq1 == 0)
  {
    log_verbose(TAG, "%s: band_center_freq1 = primary Frequency(%u)\n",
                __FUNCTION__, channelInfo.mhz);
    channelInfo.band_center_freq1 = channelInfo.mhz;
  }
  memcpy(&(chanInfo->mhz), &channelInfo, sizeof(channelInfo));
  return sizeof(wmi_rtt_oem_channel_info);
}

uint32 LOWIWifiTlvHandler::setPerChannelInfoTlv(char *msg, A_UINT32 numSTA)
{
  wmi_rtt_oem_measreq_per_channel_info *perChannelInfo =
    (wmi_rtt_oem_measreq_per_channel_info *)msg;

  WMIRTT_TLV_SET_HDR(&perChannelInfo->tlv_header,
                     WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_per_channel_info,
                     sizeof(wmi_rtt_oem_measreq_per_channel_info));

  WMI_RTT_NUM_STA_SET(perChannelInfo->sta_num, numSTA);

  return sizeof(wmi_rtt_oem_measreq_per_channel_info);
}

uint32 LOWIWifiTlvHandler::setPeerInfoTlv(char *msg,
                                          DestInfo *bssidsToScan,
                                          uint32 numBSSIDs,
                                          unsigned int reportType,
                                          DestInfo *spoofBssids,
                                          uint32 timeoutPerTarget)
{
  wmi_rtt_oem_measreq_peer_info *peerInfo;

  // set the local pointer to where the first TLV will be added
  char* pMsg = msg;

  for(uint32 ii = 0; ii < numBSSIDs; ii++)
  {
    peerInfo = (wmi_rtt_oem_measreq_peer_info *)pMsg;

    WMIRTT_TLV_SET_HDR(&peerInfo->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measreq_peer_info,
                       sizeof(wmi_rtt_oem_measreq_peer_info));

    setControlFlagBits(*peerInfo, bssidsToScan[ii], ii);

    tANI_U8 vDevType = mapLOWINodeTypeToFW(bssidsToScan[ii].vDevType);
    setMeasInfoBits(peerInfo, bssidsToScan[ii], ii, vDevType, reportType, timeoutPerTarget);

    setMeasParams1Bits(peerInfo, bssidsToScan[ii], ii);

    // set the destination and spoof mac addresses
    memcpy(peerInfo->dest_mac, &bssidsToScan[ii].mac[0], ETH_ALEN);
    memcpy(peerInfo->spoof_bssid, &spoofBssids[ii].mac[0], ETH_ALEN);
    log_verbose(TAG, "%s: dest_mac: " QUIPC_MACADDR_FMT " spoof_bssid: " QUIPC_MACADDR_FMT " "
                     "vDevType(%u) vDevType2FW(%u)", __FUNCTION__,
                QUIPC_MACADDR(peerInfo->dest_mac), QUIPC_MACADDR(peerInfo->spoof_bssid),
                bssidsToScan[ii].vDevType, vDevType);

    // advance the pointer to the start of the next wmi_rtt_oem_measreq_peer_info TLV
    pMsg += sizeof(wmi_rtt_oem_measreq_peer_info);
  }

  // return the total size of all wmi_rtt_oem_measreq_peer_info TLVs added so the
  // client pointer will be advanced to the next channel_info TLV
  return numBSSIDs * sizeof(wmi_rtt_oem_measreq_peer_info);
}

uint8 LOWIWifiTlvHandler::getPreamble(uint8 preamble) const
{
  switch (preamble)
  {
    case RTT_PREAMBLE_LEGACY: return ROME_PREAMBLE_LEGACY;
    case RTT_PREAMBLE_HT:     return ROME_PREAMBLE_HT;
    case RTT_PREAMBLE_VHT:    return ROME_PREAMBLE_VHT;
    default:                  return ROME_PREAMBLE_LEGACY;
  }
}

void LOWIWifiTlvHandler::setControlFlagBits(wmi_rtt_oem_measreq_peer_info &peerInfo,
                                           DestInfo bssidsToScan, uint32 ii)
{
  WMI_RTT_FRAME_TYPE_SET(peerInfo.control_flag, bssidsToScan.rttFrameType);
  uint32 txChainMask = TX_CHAIN_1;
  // For 160 MHz, we use 2 TX chains
  if (bssidsToScan.bandwidth == BW_160MHZ)
  {
    txChainMask = (TX_CHAIN_1 | TX_CHAIN_2);
  }
  WMI_RTT_TX_CHAIN_SET(peerInfo.control_flag, txChainMask);
  WMI_RTT_RX_CHAIN_SET(peerInfo.control_flag, RX_CHAIN_1);
  WMI_RTT_QCA_PEER_SET(peerInfo.control_flag, (bssidsToScan.isQtiPeer ? QTI_PEER : NON_QTI_PEER));
  // set qca peer if FTM parameters tells to force set
  if(FTM_GET_QCA_PEER(bssidsToScan.ftmParams))
  {
    WMI_RTT_QCA_PEER_SET (peerInfo.control_flag, QTI_PEER);
  }
  WMI_RTT_BW_SET(peerInfo.control_flag, bssidsToScan.bandwidth);
  WMI_RTT_PREAMBLE_SET(peerInfo.control_flag, getPreamble(bssidsToScan.preamble));

  // Pick the data rate
  if (WMI_RTT_PREAMBLE_GET(peerInfo.control_flag) == ROME_PREAMBLE_LEGACY)
  {
    // for Legacy Frame types, we will always use a data rate of 6MBps.
    // This is indicated to FW by setting the MCS field to LEGACY_6MBPS_MCS
    WMI_RTT_MCS_SET(peerInfo.control_flag, LEGACY_6MBPS_MCS);
  }
  else
  {
    // for HT and VHT Frame types always use a data rate of 6.5MBps.
    // This is indicated to FW by setting the MCS field to VHT_HT_6_5MBPS_MCS
    WMI_RTT_MCS_SET(peerInfo.control_flag, VHT_HT_6_5MBPS_MCS);
  }

  //  Set the number of HW retries for RTT frames:
  //  For RTT2 it is the QosNull Frame retries
  //  For RTT3 it is the FTMR Frame retries.
  WMI_RTT_RETRIES_SET (peerInfo.control_flag, bssidsToScan.numFrameRetries);

  // sets whether to use legacy acks in FTM transations
  WMI_RTT_FORCE_LEGACY_ACK_SET (peerInfo.control_flag, FTM_GET_LEG_ACK_ONLY(bssidsToScan.ftmParams));

  log_verbose(TAG, "%s: control_flag[%u](0x%x) bw(%s) pktType(%s) pream(%s) "
                   "retries(%u) qtiPeer(%u) forceqtiPeer(%u) useLegAcks(%u) \n", __FUNCTION__,
              ii, peerInfo.control_flag,
              LOWIUtils::to_string(LOWIUtils::to_eRangingBandwidth(bssidsToScan.bandwidth)),
              LOWIStrings::rtt_pkt_type_to_string(bssidsToScan.rttFrameType),
              LOWIStrings::rtt_preamble_type_to_string(getPreamble(bssidsToScan.preamble)),
              bssidsToScan.numFrameRetries,
              bssidsToScan.isQtiPeer,
              FTM_GET_QCA_PEER(bssidsToScan.ftmParams),
              FTM_GET_LEG_ACK_ONLY(bssidsToScan.ftmParams));
}

void LOWIWifiTlvHandler::setMeasInfoBits(wmi_rtt_oem_measreq_peer_info *peerInfo,
                                        DestInfo bssidsToScan,
                                        uint32 ii,
                                        tANI_U8 vDevType,
                                        unsigned int reportType,
                                        uint32 timeoutPerTarget)
{
  WMI_RTT_VDEV_TYPE_SET(peerInfo->measure_info, vDevType);
  WMI_RTT_MEAS_NUM_SET(peerInfo->measure_info, bssidsToScan.numFrames);
  WMI_RTT_TIMEOUT_SET(peerInfo->measure_info, timeoutPerTarget);
  WMI_RTT_REPORT_TYPE_SET(peerInfo->measure_info, reportType);
  log_verbose(TAG, "%s: measurementInfo[%u](0x%x) numFrames[%u](%u)\n",
               __FUNCTION__,
               ii, peerInfo->measure_info,
               ii, WMI_RTT_MEAS_NUM_GET(peerInfo->measure_info));
}

void LOWIWifiTlvHandler::setMeasParams1Bits(wmi_rtt_oem_measreq_peer_info *peerInfo,
                                           DestInfo bssidsToScan, uint32 ii)
{
    WMI_RTT_ASAP_MODE_SET(peerInfo->measure_params_1, FTM_GET_ASAP(bssidsToScan.ftmParams));
    WMI_RTT_LCI_REQ_SET(peerInfo->measure_params_1, FTM_GET_LCI_REQ(bssidsToScan.ftmParams));
    WMI_RTT_LOC_CIV_REQ_SET(peerInfo->measure_params_1, FTM_GET_LOC_CIVIC_REQ(bssidsToScan.ftmParams));
    WMI_RTT_PTSF_TIMER_SET(peerInfo->measure_params_1, FTM_GET_PTSF_TIMER_NO_PREF(bssidsToScan.ftmParams));
    WMI_RTT_NUM_BURST_EXP_SET(peerInfo->measure_params_1, FTM_GET_BURSTS_EXP(bssidsToScan.ftmParams));
    WMI_RTT_BURST_DUR_SET(peerInfo->measure_params_1, FTM_GET_BURST_DUR(bssidsToScan.ftmParams));
    WMI_RTT_BURST_PERIOD_SET(peerInfo->measure_params_1, FTM_GET_BURST_PERIOD(bssidsToScan.ftmParams));
    log_verbose(TAG, "%s: ftmParams[%u](0x%x) ASAP(0x%x) LCI Req(0x%x) Civic(0x%x) "
                "PTSFTimer(0x%x) BurstExp(%u) BurstDur(%u) BurstPeriod(%u)",
                 __FUNCTION__,
                 ii,
                 peerInfo->measure_params_1,
                 WMI_RTT_ASAP_MODE_GET(peerInfo->measure_params_1),
                 WMI_RTT_LCI_REQ_GET(peerInfo->measure_params_1),
                 WMI_RTT_LOC_CIV_REQ_GET(peerInfo->measure_params_1),
                 WMI_RTT_PTSF_TIMER_GET(peerInfo->measure_params_1),
                 WMI_RTT_NUM_BURST_EXP_GET(peerInfo->measure_params_1),
                 WMI_RTT_BURST_DUR_GET(peerInfo->measure_params_1),
                 WMI_RTT_BURST_PERIOD_GET(peerInfo->measure_params_1));
}

int LOWIWifiTlvHandler::generateLowiTlv(uint32 tag, uint8 *pMsg, measMsgInfo const *arr,
                                        uint32 idx, vector<LOWITlv *> &tlvs, uint32 lenFromFW)
{
  int retVal = -1;
  LOWITlv *pTlv = NULL;

  switch (tag)
  {
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head:
      pTlv = new(std::nothrow) LOWITlvRspHead(pMsg, arr[idx].tlvSize);
      break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head:
      pTlv = new(std::nothrow) LOWIMeasRspHeadTlv(pMsg, arr[idx].tlvSize);
      break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_peer_event_hdr:
      pTlv = new(std::nothrow) LOWIPerPeerEventHdrTlv(pMsg, arr[idx].tlvSize, lenFromFW);
      break;
    case WMIRTT_TLV_TAG_ARRAY_UINT8:
      pTlv = new(std::nothrow) LOWITlv(pMsg, lenFromFW);
      break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info:
      pTlv = new(std::nothrow) LOWIPerFrameInfoTlv(pMsg, arr[idx].tlvSize);
      break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_event:
      pTlv = new(std::nothrow) LOWICapRspEventTlv(pMsg, arr[idx].tlvSize);
      break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_head:
      pTlv = new(std::nothrow) LOWICapRspHeadTlv(pMsg, arr[idx].tlvSize);
      break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_get_channel_info_rsp_head:
        pTlv = new(std::nothrow) LOWIOemChannelRspHeadTlv(pMsg, arr[idx].tlvSize);
        break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_rsp_head:
        pTlv = new(std::nothrow) LOWIResponderRspHeadTlv(pMsg, arr[idx].tlvSize);
        break;
    case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info:
        pTlv = new(std::nothrow) LOWIChannelRspHeadTlv(pMsg, arr[idx].tlvSize);
        break;
    default:
      log_debug(TAG, "%s: Unknown TLV tag", __FUNCTION__);
      break;
  }

  do
  {
    LOWI_BREAK_IF_NULL(pTlv, "Memory allocation failure")
    tlvs.push_back(pTlv);
    retVal = 0;
  } while (0);

  return retVal;
} // generateLowiTlv

int LOWIWifiTlvHandler::checkTlvTag(uint32 tag,
                                    measMsgInfo const *msgArr,
                                    uint8 &idx)
{
  int retVal = -1;

  do
  {
    if (msgArr[idx].tag == tag) // tag matches
    {
      log_debug(TAG, "%s: Processing idx(%u) received TLV: %s", __FUNCTION__, idx, msgArr[idx].tlvStr);

      // these calls are used to figure out the number of
      // peers and number of measurements for each peer
      processIfLoopStartTag(msgArr[idx].tag);
      processIfLoopEndTag(msgArr[idx].tag);
      processIfPeerEvtHdrTag(msgArr[idx].tag);
      processIfPerFrmInfoTag(msgArr[idx].tag);
      retVal = 0;
    }
    else
    {
      // do we expect other tags?
      if (NULL == msgArr[idx].otherTags)
      {
        // there are no other expected tags after this TLV,
        log_debug(TAG, "%s: Processing idx(%u) No tags expected -- break(%s)",
                  __FUNCTION__, idx, msgArr[idx].tlvStr);
        break;
      }

      for (uint32 jj = 0; jj < msgArr[idx].numOtherTags; ++jj)
      {
        if (msgArr[idx].otherTags[jj].tag == tag)
        {
          // found a tag, return the new array index
          retVal = msgArr[idx].otherTags[jj].idx;
          log_debug(TAG, "%s: Processing idx(%u) received unexpected but valid TLV(%s), going to idx(%u)",
                    __FUNCTION__, idx, msgArr[idx].tlvStr, msgArr[idx].otherTags[jj].idx);
          break;
        }
      }
    }
  } while (0);

  return retVal;
}  // checkTlvTag

void LOWIWifiTlvHandler::processIfLoopStartTag(uint32 tag)
{
  if (WMIRTT_TLV_TAG_STRUC_loop_start == tag)
  {
    if (mPeerLs == 0)
    {
      mPeerLs = 1; // peer list begins
    }
    else
    {
      mMeasLs = 1; // peer measurement begins
    }
  }
  log_verbose(TAG, "%s: mMeasLs(%u) mPeerLs(%u)", __FUNCTION__, mMeasLs, mPeerLs);
}

void LOWIWifiTlvHandler::processIfLoopEndTag(uint32 tag)
{
  if (WMIRTT_TLV_TAG_STRUC_loop_end == tag)
  {
    if (mMeasLs != 0)
    {
      mMeasLs = 0; // peer measurement done
      log_verbose(TAG, "%s: mMeasLs(%u)...peer measurement done", __FUNCTION__, mMeasLs);
    }
    else
    {
      mPeerLs = 0; // peer list ends
      log_debug(TAG, "%s: mPeerLs(%u)...peer list ends", __FUNCTION__, mPeerLs);
    }
  }
}

void LOWIWifiTlvHandler::processIfPeerEvtHdrTag(uint32 tag)
{
  if (WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_peer_event_hdr == tag)
  { // add peer to peer vector
    uint8 numMeas = 0; // no measurements yet
    mPeerSet.push_back(numMeas);
    mPeerIdx = mPeerSet.getNumOfElements()-1;
    log_verbose(TAG, "%s: mPeerIdx : %u", __FUNCTION__, mPeerIdx);
  }
  else
  {
    log_debug(TAG, "%s: Invalid Tag(%u), not added to vector mPeerIdx(%u)", __FUNCTION__, tag, mPeerIdx);
  }
}

void LOWIWifiTlvHandler::processIfPerFrmInfoTag(uint32 tag)
{
  if (WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info == tag)
  {
    if(mPeerSet.getNumOfElements() > 0) {
      // increment the measurement count for the current peer
      log_verbose(TAG, "%s: mPeerIdx : %u", __FUNCTION__, mPeerIdx);
    mPeerSet[mPeerIdx]++;
    }
  }
  else
  {
    log_debug(TAG, "%s: Invalid Tag(%u) measurement not added for peer(%u)",
              __FUNCTION__, tag, mPeerIdx);

  }
}

int LOWIWifiTlvHandler::processRspHeadTlv(uint8 *pMsg, rttRspInfo &rspInfo, uint8 &subType)
{
  HDLR_ENTER()
  int retVal = -1;

  do
  {
    LOWI_BREAK_IF_NULL(pMsg, "Bad argument...NULL ptr")

    // check for the correct TLV tag
    wmi_rtt_oem_rsp_head *pHead = (wmi_rtt_oem_rsp_head *)pMsg;
    if (WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head != WMIRTT_TLV_GET_TLVTAG(pHead->tlv_header))
    {
      log_debug(TAG, "%s: wrong tag(%u), expected wmi_oem_rtt_rsp_head tag \n",
                __FUNCTION__ , WMIRTT_TLV_GET_TLVTAG(pHead->tlv_header));
      break;
    }

    // create a temporary object to extract the TLV data
    LOWITlvRspHead *pTlv =
      new (std::nothrow) LOWITlvRspHead(pMsg, sizeof(wmi_rtt_oem_rsp_head));
    LOWI_BREAK_IF_NULL(pTlv, "Memory allocation failure")

    // extract the TLV data
    subType = pTlv->getSubType();
    pTlv->getFragmentInfo(rspInfo.fragInfo);

    rspInfo.isLastMeas = pTlv->getRttMeasDone();

    log_debug(TAG,"%s: reqId(%u) measDone(%u) rttStatus(%s) subtype(%s) isFrag(%u) "
                  "fragIdx(%u) fragLen(%u) tknId(%u)\n",
              __FUNCTION__, pTlv->getReqId(), pTlv->getRttMeasDone(),
              LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)pTlv->getRttStatus()),
              LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)subType),
              rspInfo.fragInfo.isFragment, rspInfo.fragInfo.fragmentIdx,
              rspInfo.fragInfo.fragmentLen, rspInfo.fragInfo.tokenId);

    delete pTlv;
    retVal = 0;
  }
  while (0);

  HDLR_EXIT()
  return retVal;
} // processRspHeadTlv

uint8 LOWIWifiTlvHandler::getNumPeers() const
{
  return mPeerSet.getNumOfElements();
}

void LOWIWifiTlvHandler::clearPeerSetInfo()
{
  mPeerLs = 0;
  mMeasLs = 0;
  mPeerIdx = 0;
  mPeerSet.flush();
}

uint8 LOWIWifiTlvHandler::getNumMeas(uint32 idx) const
{
  return mPeerSet[idx];
}

void LOWIWifiTlvHandler::printBssidInfo()
{

  if (mPeerSet.getNumOfElements() > 0)
  {
    for (uint32 ii = 0; ii < mPeerSet.getNumOfElements(); ++ii)
    {
      log_debug(TAG,"%s: Peer %u of %u,  numMeas = %u\n",
                __FUNCTION__, ii, mPeerSet.getNumOfElements(), mPeerSet[ii]);
    }
  }
  else
  {
    log_debug(TAG,"%s: No peer info from processing TLVs\n", __FUNCTION__);
  }
}
uint8 LOWIWifiTlvHandler::mapLOWINodeTypeToFW(uint8 nodeType)
{
  switch(nodeType)
  {
    case ACCESS_POINT:
    case STA_DEVICE:
      return RTT_WMI_VDEV_TYPE_STA;
    case PEER_DEVICE:
      return RTT_WMI_VDEV_TYPE_P2P_CLI;
    case NAN_DEVICE:
      return RTT_WMI_VDEV_TYPE_NAN;
    default:
      return RTT_WMI_VDEV_TYPE_STA;
  }
}
