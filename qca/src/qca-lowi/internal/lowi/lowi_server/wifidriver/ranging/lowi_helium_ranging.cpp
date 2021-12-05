/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

   NL80211 Interface for ranging scan

   GENERAL DESCRIPTION
   This component performs ranging scan with NL80211 Interface.

Copyright (c) 2016-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/

#define LOG_NDEBUG 0
#include <lowi_server/lowi_log.h>
#include <common/lowi_utils.h>
#include "lowi_diag_log.h"
#include "lowi_wifi_tlv_handler.h"
#include "lowi_helium_ranging.h"
#include "lowi_ranging_fsm.h"
#include "lowi_p2p_ranging.h"
#include <lowi_strings.h>
#include "lowi_nl80211.h"
#include "lowi_wifidriver_interface.h"
#include <stddef.h>

using namespace qc_loc_fw;

// This needs to be further evaluated and logged under different log levels.
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "LOWI-HELIUM-RTT"

// Enter/Exit debug macros
#undef ALLOW_ENTER_EXIT_DBG_HELIUM_RANGING
#ifdef ALLOW_ENTER_EXIT_DBG_HELIUM_RANGING
#define LRH_ENTER() LOWI_LOG_ERROR("ENTER: %s", __FUNCTION__);
#define LRH_EXIT()  LOWI_LOG_ERROR("EXIT: %s", __FUNCTION__);
#else
#define LRH_ENTER()
#define LRH_EXIT()
#endif

// AR6K - RTT offset to bring it down to RIVA level
/* 11577000 = (5100 * 22.7) * 1000, this offset was copied over from AR6K (units ps)*/
#define RTT2_OFFSET_ROME_PS (115770000)

#define BREAK_IF_BAD_TAG(tag, nextTlv, errVal) if (tlvs[nextTlv]->getTag() != tag)     \
                          {                                                            \
                            LOWI_LOG_VERB("%s: wrong tag...expecting %u, got (%u)\n",  \
                                          __FUNCTION__, tag, tlvs[nextTlv]->getTag()); \
                            errInloop = errVal;                                        \
                            break;                                                     \
                          }

LOWIHeliumRanging::LOWIHeliumRanging()
: LOWIRanging()
{
  mTlvHandler = new LOWIWifiTlvHandler();
  if (NULL == mTlvHandler)
  {
    LOWI_LOG_DBG("%s: Mem alloc failure for tlv handler", __FUNCTION__);
  }
}

LOWIHeliumRanging::~LOWIHeliumRanging()
{
  if (NULL != mTlvHandler)
  {
    delete mTlvHandler;
    mTlvHandler = NULL;
  }
}

/**********************************************************************************
 *  Message Senders - These functions send construct and send messages to CLD/FW
 **********************************************************************************/
int LOWIHeliumRanging::RomeSendRangingCapReq(std::string interface)
{
  LRH_ENTER()
  int retVal = -1;

  do
  {
    // ani message header length
    uint32 const aniHdrLen = sizeof(tAniMsgHdr);
    uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

    // ani message length = length of all TLVs
    uint32 aniMsgLen = sizeof(wmi_rtt_oem_req_head) + sizeof(wmi_rtt_oem_cap_req_head);

    uint32 aniInterfaceLen = sizeof(tAniInterface);

    // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
    // and fill out the header
    char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
    if (aniMessage == NULL)
    {
      LOWI_LOG_ERROR("%s: Failed to allocate memory for ANI message", __FUNCTION__);
      break;
    }

    // Fill out the ANI message body with the TLVs. Message body starts after the header.
    char *aniMsgBody = (char *)(aniMessage + (char)aniHdrLen);

    // Adding the wmi_rtt_oem_req_head TLV
    wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)aniMsgBody;
    WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                       sizeof(wmi_rtt_oem_req_head));
    reqHead->sub_type = RTT_MSG_SUBTYPE_CAPABILITY_REQ;
    reqHead->req_id   = ++req_id;
    /* Always sent on first radio */
    reqHead->pdev_id = 1;

    // Adding the wmi_rtt_oem_cap_req_head TLV
    wmi_rtt_oem_cap_req_head *capReqHead =
        (wmi_rtt_oem_cap_req_head *)(aniMsgBody + sizeof(wmi_rtt_oem_req_head));
    WMIRTT_TLV_SET_HDR(&capReqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_req_head,
                       sizeof(wmi_rtt_oem_cap_req_head));
    capReqHead->version  = RTT_VER_SET_VERSION(RTT_VERSION_MAJOR, RTT_VERSION_MINOR);
    capReqHead->revision = RTT_REVISION;

    LOWI_LOG_VERB("%s: subtype(%s) requestID(%d) aniMsgLen(%u) aniHdrLen(%u)\n", __FUNCTION__,
                  LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)reqHead->sub_type),
                  reqHead->req_id, aniMsgLen, aniHdrLen);

    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);

    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        break;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + (char)aniHdrLen + (char) aniMsgLen + (char)aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

    /* Send ANI Message over Netlink Socket */
    if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
    {
      LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
      free(aniMessage);
      break;
    }

    free(aniMessage);
    retVal = 0;
  } while (0);

  LRH_EXIT()
  return retVal;
}

int LOWIHeliumRanging::RomeSendRttReq(uint16 reqId,
                                      ChannelInfo  chanInfo,
                                      unsigned int numBSSIDs,
                                      DestInfo bssidsToScan[MAX_BSSIDS_TO_SCAN],
                                      DestInfo spoofBssids[MAX_BSSIDS_TO_SCAN],
                                      unsigned int reportType,
                                      std::string interface)
{
  LRH_ENTER()

  /* flush the list of failed Targets */
  failedTargets.flush();
  wmi_channel channelInfo = chanInfo.wmiChannelInfo;
  int retVal = -1;
  int pdev_id;

  /** Retrieve Channel information from Channel Info Array for the specific channel ID */
  /* Check to see if the Target is a P2P Peer.
   * IF target is a P2P Peer, load the channel info from p2p event storage table
   * currently p2p is not supported
   * p2pBssidDetected((tANI_U32)numBSSIDs, bssidsToScan, &channelInfo, &vDevType);
   *  */

  LOWI_LOG_VERB("%s: Channel info for chNum(%u): mhz#= %u band_center_freq1= %u band_center_freq2= %u, info= 0x%x, reg_info_1= 0x%x, reg_info_2= 0x%x\n",
                __FUNCTION__,
                LOWIUtils::freqToChannel(channelInfo.mhz),
                channelInfo.mhz,
                channelInfo.band_center_freq1,
                channelInfo.band_center_freq2,
                channelInfo.info,
                channelInfo.reg_info_1,
                channelInfo.reg_info_2);

  // ani message header length
  uint32 aniHdrLen = sizeof(tAniMsgHdr);

  uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

  uint32 aniInterfaceLen = sizeof(tAniInterface) + sizeof(uint32_t);

  // ani message length = length of all TLVs
  uint32 aniMsgLen = sizeof(wmi_rtt_oem_req_head) +
                     sizeof(wmi_rtt_oem_measreq_head) +
                     sizeof(wmi_rtt_oem_channel_info) +
                     RTT_TLV_HDR_SIZE + // loop start
                     sizeof(wmi_rtt_oem_measreq_per_channel_info) +
                     RTT_TLV_HDR_SIZE + // loop start
                     numBSSIDs * sizeof(wmi_rtt_oem_measreq_peer_info) +
                     RTT_TLV_HDR_SIZE + // loop end
                     RTT_TLV_HDR_SIZE;  // loop end

  // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
  // and fill out the header
  char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
  if (aniMessage == NULL)
  {
    LOWI_LOG_ERROR("%s: Failed to allocate memory for ANI message", __FUNCTION__);
    return retVal;
  }


  std::size_t pos = interface.find(INTERFACE_PREFIX);
  if  (std::string::npos == pos)
  {
     pdev_id = 1;
  } else
  {
     char cstr[INTERFACE_IDX_LEN + 1];
     uint jj = 0;
     for (uint ii = pos + strlen(INTERFACE_PREFIX); ii < interface.length() && jj < INTERFACE_IDX_LEN; ii++, jj++)
     {
         cstr[jj] = interface[ii];
     }
     cstr[jj] = 0;
     pdev_id = std::atoi(cstr) + 1;
  }

  // Fill out the ANI message body with TLVs. The first TLV in the message body
  // starts after the header. Every time a TLV is added, the pointer: nextTlv,is
  // advanced by the size of the TLV just added. This will leave nextTlv pointing
  // to where the next TLV will be added.
  char *aniMsgBody = (char *)(aniMessage + (char)aniHdrLen);
  char *nextTlv    = aniMsgBody;

  // Add the wmi_rtt_oem_req_head TLV and advance the pointer
  nextTlv += mTlvHandler->setReqHeadTlv(nextTlv, reqId, pdev_id);

  // Add the wmi_rtt_oem_measreq_head TLV and advance the pointer
  // Note: only one channel allowed for now
  nextTlv += mTlvHandler->setMeasReqHeadTlv(nextTlv, 1);

  // Add the loop start TLV header here
  nextTlv += mTlvHandler->setLoopStartTlv(nextTlv);

  // Add the wmi_rtt_oem_channel_info TLV and advance the pointer
  nextTlv += mTlvHandler->setChannelInfoTlv(nextTlv, channelInfo);

  // Add wmi_rtt_oem_measreq_per_channel_info and advance the pointer
  // todo, add loop here so multi-channel requests can be done
  nextTlv += mTlvHandler->setPerChannelInfoTlv(nextTlv, numBSSIDs);

  // Add the loop start TLV header here
  nextTlv += mTlvHandler->setLoopStartTlv(nextTlv);

  // Add wmi_rtt_oem_measreq_peer_info TLVs and advance the pointer
  nextTlv += mTlvHandler->setPeerInfoTlv(nextTlv, bssidsToScan, numBSSIDs,
                                         reportType, spoofBssids,
                                         RTT_TIMEOUT_PER_TARGET);

  // Add the loop end TLV header here
  nextTlv += mTlvHandler->setLoopEndTlv(nextTlv);

  // Add the loop end TLV header here
  nextTlv += mTlvHandler->setLoopEndTlv(nextTlv);

  // This info is the same for all STAs, print once here
  tANI_U32 phyMode  = channelInfo.info & ~(PHY_MODE_MASK);
  LOWI_LOG_DBG("%s: PHY Mode(%s) timeoutPerTarget(%u) reportType(%s)\n", __FUNCTION__,
               LOWIUtils::to_string(LOWIUtils::to_eLOWIPhyMode(phyMode)), RTT_TIMEOUT_PER_TARGET,
               LOWIUtils::to_string(LOWIUtils::to_eRttReportType((uint8)reportType)));

  LOWI_LOG_VERB("%s: Sending Ranging Req of len %u over NL at TS: %" PRId64
                " ms, reqId(%u), reportType requested(%u)\n", __FUNCTION__,
                aniMsgLen, LOWIUtils::currentTimeMs(), reqId, reportType);

    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        return retVal;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + (char)aniHdrLen + (char) aniMsgLen + (char)aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return retVal;
  }

  free(aniMessage);
  retVal = 0;
  LRH_EXIT()
  return retVal;
}

int LOWIHeliumRanging::RomeSendLCIConfiguration(tANI_U16 reqId, LOWISetLCILocationInformation* request)
{
  int retVal = -1;

  LOWI_LOG_VERB("%s: \n", __FUNCTION__);

  if (request == NULL)
  {
    return retVal;
  }

  LOWILciInformation lciInfo = request->getLciParams();
  tANI_U32        usageRules = request->getUsageRules();

  LOWI_LOG_VERB("%s: LCIParams: latitude(%" PRId64 ") latitude_unc(%d) longitude(%" PRId64 ")"
                " longitude_unc(%d) altitude(%d) altitude_unc(%d) motion_pattern(%d) floor(%d)"
                " usageRules(%u) height_above_floor(%d) height_unc(%d)\n",
                __FUNCTION__, lciInfo.latitude, lciInfo.latitude_unc, lciInfo.longitude,
                lciInfo.longitude_unc, lciInfo.altitude, lciInfo.altitude_unc,
                lciInfo.motion_pattern, lciInfo.floor, usageRules,
                lciInfo.height_above_floor, lciInfo.height_unc);


  // ani message header length
  uint32 const aniHdrLen = sizeof(tAniMsgHdr);
  uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

  uint32 aniMsgLen = sizeof(wmi_rtt_oem_req_head) + sizeof(wmi_rtt_oem_lci_cfg_head);

  uint32 aniInterfaceLen = sizeof(tAniInterface);

  // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
  // and fill out the header
  char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
  if(aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    return retVal;
  }

  /* Fill in the ANI Message Body */
  char* aniMsgBody = (char*) (aniMessage + (char)aniHdrLen);

  uint32 pdev_id;
  std::string interface = request->get_interface();
  std::size_t pos = interface.find(INTERFACE_PREFIX);
  if  (std::string::npos == pos)
  {
     pdev_id = 1;
  } else
  {
     char cstr[INTERFACE_IDX_LEN + 1];
     uint jj = 0;
     for (uint ii = pos + strlen(INTERFACE_PREFIX); ii < interface.length() && jj < INTERFACE_IDX_LEN; ii++, jj++)
     {
         cstr[jj] = interface[ii];
     }
     cstr[jj] = 0;
     pdev_id = std::atoi(cstr) + 1;
  }
  // Adding the wmi_rtt_oem_req_head TLV
    wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)aniMsgBody;
    WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                       sizeof(wmi_rtt_oem_req_head));
    reqHead->sub_type = RTT_MSG_SUBTYPE_CONFIGURE_LCI;
    reqHead->pdev_id = pdev_id;
    WMI_RTT_REQ_ID_SET ((reqHead->req_id), reqId);

    // Adding the wmi_rtt_oem_lci_cfg_head TLV
    wmi_rtt_oem_lci_cfg_head *lciConfig =
        (wmi_rtt_oem_lci_cfg_head *)(aniMsgBody + sizeof(wmi_rtt_oem_req_head));
    WMIRTT_TLV_SET_HDR(&lciConfig->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_lci_cfg_head,
                       sizeof(wmi_rtt_oem_lci_cfg_head));

  lciConfig->latitude  = (tANI_U64)lciInfo.latitude;
  lciConfig->longitude = (tANI_U64)lciInfo.longitude;
  lciConfig->altitude  = (tANI_U64)lciInfo.altitude;
  WMI_RTT_LCI_LAT_UNC_SET(lciConfig->lci_cfg_param_info, lciInfo.latitude_unc);
  WMI_RTT_LCI_LON_UNC_SET(lciConfig->lci_cfg_param_info, lciInfo.longitude_unc);
  WMI_RTT_LCI_ALT_UNC_SET(lciConfig->lci_cfg_param_info, lciInfo.altitude_unc);
  WMI_RTT_LCI_Z_MOTION_PAT_SET(lciConfig->lci_cfg_param_info, lciInfo.motion_pattern);
  lciConfig->floor     = (tANI_U32)lciInfo.floor;
  WMI_RTT_LCI_Z_HEIGHT_ABV_FLR_SET(lciConfig->floor_param_info, (tANI_U32)lciInfo.height_above_floor);
  WMI_RTT_LCI_Z_HEIGHT_UNC_SET(lciConfig->floor_param_info, (tANI_U32)lciInfo.height_unc);
  lciConfig->usage_rules = usageRules;

  LOWI_LOG_VERB("%s: Sending LCI Configuration Req message over NL at TS: %" PRId64 " ms"
                "subtype(%s) requestID(%d) aniMsgLen(%u) aniHdrLen(%u)\n", __FUNCTION__,
                LOWIUtils::currentTimeMs(),
                LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)reqHead->sub_type),
                reqHead->req_id, aniMsgLen, aniHdrLen);

    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        return retVal;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + (char)aniHdrLen + (char) aniMsgLen + (char)aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return retVal;
  }

  free(aniMessage);
  retVal = 0;

  return retVal;
}

int LOWIHeliumRanging::RomeSendLCRConfiguration(tANI_U16 reqId, LOWISetLCRLocationInformation* request)
{
  int retVal = -1;

  LOWI_LOG_VERB("%s: \n", __FUNCTION__);

  if (request == NULL)
  {
    return retVal;
  }

  LOWILcrInformation lcrInfo = request->getLcrParams();

  // ani message header length
  uint32 const aniHdrLen = sizeof(tAniMsgHdr);
  uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

  unsigned int aniMsgLen = sizeof(wmi_rtt_oem_req_head) + sizeof(wmi_rtt_oem_lcr_cfg_head);

  uint32 aniInterfaceLen = sizeof(tAniInterface) + sizeof(uint32_t);

  // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
  // and fill out the header
  char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
  if(aniMessage == NULL)
  {
    /* Failed to Allocate Memory */
    return retVal;
  }

  /* Fill in the ANI Message Body */
  char* aniMsgBody = (char*) (aniMessage + aniHdrLen);

  uint32 pdev_id;
  std::string interface = request->get_interface();
  std::size_t pos = interface.find(INTERFACE_PREFIX);
  if  (std::string::npos == pos)
  {
     pdev_id = 1;
  } else
  {
     char cstr[INTERFACE_IDX_LEN + 1];
     uint jj = 0;
     for (uint ii = pos + strlen(INTERFACE_PREFIX); ii < interface.length() && jj < INTERFACE_IDX_LEN; ii++, jj++)
     {
         cstr[jj] = interface[ii];
     }
     cstr[jj] = 0;
     pdev_id = std::atoi(cstr) + 1;
  }
  // Adding the wmi_rtt_oem_req_head TLV
    wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)aniMsgBody;
    WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                       sizeof(wmi_rtt_oem_req_head));
    reqHead->sub_type = RTT_MSG_SUBTYPE_CONFIGURE_LCR;
    reqHead->pdev_id = pdev_id;
    WMI_RTT_REQ_ID_SET ((reqHead->req_id), reqId);

    // Adding the wmi_rtt_oem_lcr_cfg_head TLV
    wmi_rtt_oem_lcr_cfg_head *lcrConfig =
        (wmi_rtt_oem_lcr_cfg_head *)(aniMsgBody + sizeof(wmi_rtt_oem_req_head));
    WMIRTT_TLV_SET_HDR(&lcrConfig->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_lcr_cfg_head,
                       sizeof(wmi_rtt_oem_lcr_cfg_head));

  /* The following subtraction and addition of the value 2 to length is being done because
   * Country code which is 2 bytes comes separately from the actual Civic Info String
   */
  tANI_U8 len = (lcrInfo.length > (MAX_CIVIC_INFO_LEN - 2)) ? (MAX_CIVIC_INFO_LEN - 2) : lcrInfo.length;

  WMI_RTT_LOC_CIVIC_LENGTH_SET(lcrConfig->loc_civic_params, (len + 2));

  tANI_U8* civicInfo = (tANI_U8*) lcrConfig->civic_info;

  LOWI_LOG_VERB("%s - subtype(0x%x) requestID(0x%x) LCRParam: country[0](%c) country[1](%c)",
                __FUNCTION__,  LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)reqHead->sub_type),
                reqHead->req_id,
                lcrInfo.country_code[0], lcrInfo.country_code[1]);

  civicInfo[0] = lcrInfo.country_code[0];
  civicInfo[1] = lcrInfo.country_code[1];
  memcpy(&civicInfo[2], lcrInfo.civic_info, (tANI_U8)lcrInfo.length);


  char civic_info_string[MAX_CIVIC_INFO_LEN];
  if((snprintf(civic_info_string, len, "%c", lcrInfo.civic_info[3])) >= 0)
  {
    LOWI_LOG_VERB("%s - LCRParam: len: %u: civic_info: %s",
                  __FUNCTION__,
                  len,
                  civic_info_string);
  }

  LOWI_LOG_VERB("%s: Sending LCR Configuration Req message over NL at TS: %" PRId64 " ms\n",
                __FUNCTION__, LOWIUtils::currentTimeMs());

    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        return retVal;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *)(aniMsgBody + aniMsgLen + aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

  /* ANI Message over Netlink Socket */
  if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
  {
    LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
    free(aniMessage);
    return retVal;
  }

  free(aniMessage);
  retVal = 0;

  return retVal;
}

/***** END - Message Senders *******/

/******* Message Handlers **************/

bool LOWIHeliumRanging::isAniMsgValid(uint8 aniMsgType)
{
  switch (aniMsgType)
  {
    case ANI_MSG_APP_REG_RSP:      return true;
    case ANI_MSG_CHANNEL_INFO_RSP: return true;
    case ANI_MSG_OEM_ERROR:        return true;
    case ANI_MSG_PEER_STATUS_IND:  return true;
    case ANI_MSG_OEM_DATA_RSP:     return true;
    default:                       return false;
  }
}

bool LOWIHeliumRanging::isRttMsgSubTypeValid(uint8 subType)
{
  if (subType == RTT_MSG_SUBTYPE_CAPABILITY_RSP  ||
      subType == RTT_MSG_SUBTYPE_MEASUREMENT_RSP ||
      subType == RTT_MSG_SUBTYPE_ERROR_REPORT_RSP)
  {
    return true;
  }
  return false;
}

RomeNlMsgType LOWIHeliumRanging::mapAniToRomeMsg(uint8 aniMsgType)
{
  switch (aniMsgType)
  {
    case ANI_MSG_APP_REG_RSP:      return ROME_REG_RSP_MSG;
    case ANI_MSG_CHANNEL_INFO_RSP: return ROME_CHANNEL_INFO_MSG;
    case ANI_MSG_OEM_ERROR:        return ROME_CLD_ERROR_MSG;
    case ANI_MSG_PEER_STATUS_IND:  return ROME_P2P_PEER_EVENT_MSG;
    default:                       return ROME_NL_ERROR_MSG;
  }
}

int LOWIHeliumRanging::RomeNLRecvMessage(RomeNlMsgType* msgType, void* data, tANI_U32 maxDataLen)
{
  LRH_ENTER()
  int retVal = 0;
  WMIRTT_OEM_MSG_SUBTYPE oemMsgSubType = RTT_MSG_SUBTYPE_INVALID;
  tAniMsgHdr* aniMsgHdr = NULL;
  bool validMsgType = TRUE;
  char* localp = (char*)data;

  if (msgType == NULL || localp == NULL)
  {
    LOWI_LOG_ERROR("%s, Received invalid pointer for msgType or data", __FUNCTION__);
    return -1;
  }

  tANI_U32 maxCopyLen = (maxDataLen > MAX_NLMSG_LEN) ? MAX_NLMSG_LEN : maxDataLen;
  memset(rxBuff, 0, MAX_NLMSG_LEN);
  memset(localp, 0, maxDataLen);
  *msgType = ROME_NL_ERROR_MSG;

  if(recv_nl_msg(nl_sock_fd, rxBuff, MAX_NLMSG_LEN) > 0)
  {
    aniMsgHdr = (tAniMsgHdr *)rxBuff;

    LOWI_LOG_VERB("RomeNLRecvMessage: aniMsgHdr(0x%x)(%s) aniMsgLen(%u)", aniMsgHdr->type,
                  LOWIStrings::cld_ani_msg_type_to_string(aniMsgHdr->type), aniMsgHdr->length);

    if(ANI_MSG_OEM_DATA_RSP == aniMsgHdr->type)
    {
      // call the tlv handler to check the head of the tlv msg
      wmi_rtt_oem_rsp_head *pHead = (wmi_rtt_oem_rsp_head *)(rxBuff + sizeof(tAniMsgHdr));
      retVal = mTlvHandler->verifyTlvRspHead(pHead, &oemMsgSubType);
      if (retVal < 0)
      {
        return -1;
      }

      LOWI_LOG_DBG("RomeNLRecvMessage:  received message of subtype: %s",
                     LOWIStrings::to_string(oemMsgSubType));

      switch (oemMsgSubType)
      {
        case RTT_MSG_SUBTYPE_CAPABILITY_RSP:
          {
            *msgType = ROME_RANGING_CAP_MSG;
            break;
          }
        case RTT_MSG_SUBTYPE_MEASUREMENT_RSP:
          {
            LOWI_LOG_VERB("%s: Received Ranging Response message over NL at TS: %" PRId64 " ms\n",
                          __FUNCTION__, LOWIUtils::currentTimeMs());

            *msgType = ROME_RANGING_MEAS_MSG;
            break;
          }
        case RTT_MSG_SUBTYPE_ERROR_REPORT_RSP:
          {
            *msgType = ROME_RANGING_ERROR_MSG;
            break;
          }
        case RTT_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP:
          {
            *msgType = ROME_RTT_CHANNEL_INFO_MSG;
            break;
          }
        case RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_RSP:
          {
            *msgType = ROME_RESPONDER_INFO_MSG;
            break;
          }
        case RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_RSP:
          {
            *msgType = ROME_CFG_RESPONDER_MEAS_RSP_MSG;
            break;
          }
        case RTT_MSG_SUBTYPE_RESPONDER_MEASUREMENT_RSP:
          {
            *msgType = ROME_RESPONDER_MEAS_INFO_MSG;
            break;
          }
        default:
          {
            LOWI_LOG_ERROR("%s: Received a OEM Data message with bad subtype: %s",
                           __FUNCTION__, LOWIStrings::to_string(oemMsgSubType));
            validMsgType = FALSE;
            retVal = -1;
            break;
          }
      }
    }
    else
    {
      *msgType = mapAniToRomeMsg(aniMsgHdr->type);
      validMsgType = (*msgType == ROME_NL_ERROR_MSG) ? FALSE : TRUE;
    }
  }
  else
  {
    if (errno < 0)
    {
      LOWI_LOG_ERROR("%s: NL Recv Failed, with errno(%d): %s", __FUNCTION__, errno, strerror(errno));
    }
    retVal = -1;
  }

  if (validMsgType)
  {
    memcpy(localp, rxBuff, maxCopyLen);
  }

  if (aniMsgHdr)
  {
    if (oemMsgSubType != RTT_MSG_SUBTYPE_INVALID)
    {
      LOWI_LOG_DBG("%s: The Received ANI Msg Type: %s, OEM Type: %s, RomeMsgType: %s",
                    __FUNCTION__, LOWIStrings::cld_ani_msg_type_to_string(aniMsgHdr->type),
                    LOWIStrings::to_string(oemMsgSubType),
                    LOWIStrings::to_string(*msgType));
    }
    else
    {
      LOWI_LOG_DBG("%s: The Received ANI Msg Type: %u, Type: %u",
                    __FUNCTION__, aniMsgHdr->type, *msgType);
    }
  }
  return retVal;
}

int LOWIHeliumRanging::RomeExtractRangingCap(void *data, RomeRttCapabilities *pRttCapabilities)
{
  LRH_ENTER()
  int retVal = -1;

  do
  {
    if (data == NULL || pRttCapabilities == NULL)
    {
      LOWI_LOG_ERROR("%s: Invalid ptr for msg body or capabilties struct", __FUNCTION__);
      break;
    }

    //Get ptr to FW msg. FW msg starts after the ANI message header
    uint8 *fwMsg = ((uint8 *)(data)) + sizeof(tAniMsgHdr);

    rttRspInfo rspInfo;
    uint8 subtype;
    vector<LOWITlv *> tlvs; // vector to hold the TLVs

    // Get information from the wmi_rtt_oem_rsp_head TLV
    if (0 != mTlvHandler->processRspHeadTlv(fwMsg, rspInfo, subtype))
    {
      break;
    }

    // Report type is dummy for subtype RTT_MSG_SUBTYPE_CAPABILITY_RSP
    // so the last parameter for processTLVs is 0
    if (0 != mTlvHandler->processTLVs(fwMsg, tlvs, subtype, 0))
    {
      break;
    }

    RomeRttCapabilities localCap;

    parseRttCapabilitiesMsg(tlvs, localCap);

    memcpy(pRttCapabilities, &localCap, sizeof(RomeRttCapabilities));

    /* Extract number of RX chains being used and store in Ranging Driver*/
    tANI_U8 rxChainBitMask = pRttCapabilities->maxRfChains;

    /* This for loop counts the bits that are set in the chain mask */
    for (rxChainsUsed = 0; rxChainBitMask; rxChainsUsed++)
    {
      rxChainBitMask &= rxChainBitMask - 1;
    }

    mTlvHandler->cleanupTlvs(tlvs);  // Free the memory used by the TLVs

    retVal = 0;
  } while (0);

  LRH_EXIT()
  return retVal;
}

int LOWIHeliumRanging::RomeExtractRangingError(void* data, tANI_U32* errorCode, tANI_U8* bssid)
{
  LRH_ENTER()
  int retVal = -1;
  do
  {
    if ( (data == NULL) || (errorCode == NULL) || (bssid == NULL) )
    {
      LOWI_LOG_ERROR("%s, Received invalid pointer - data: %p, errorCode: %p, bssid: %p",
                     __FUNCTION__, data, errorCode, bssid);
      break;
    }

    //Get ptr to FW msg. FW msg starts after the ANI message header
    uint8 *fwMsg = ((uint8 *)(data)) + sizeof(tAniMsgHdr);

    rttRspInfo rspInfo;
    uint8 subtype;
    vector<LOWITlv *> tlvs; // vector to hold the TLVs

    // Get information from the wmi_rtt_oem_rsp_head TLV
    if (0 != mTlvHandler->processRspHeadTlv(fwMsg, rspInfo, subtype))
    {
      break;
    }

    // Report type is dummy for subtype RTT_MSG_SUBTYPE_ERROR_REPORT_RSP
    // so the last parameter for processTLVs is 0
    if (0 != mTlvHandler->processTLVs(fwMsg, tlvs, subtype, 0))
    {
      break;
    }

    // parse the vector of TLVs
    rttMeasRspHead measRspInfo;
    if (0 != parseErrRprt(tlvs, measRspInfo, *errorCode))
    {
      break;
    }

    // copy params requested by the caller
    memcpy(bssid, measRspInfo.destMac, ETH_ALEN_PLUS_2);
    LOWI_LOG_VERB("%s: bssid(" LOWI_MACADDR_FMT ") errorCode(%s)", __FUNCTION__,
                  LOWI_MACADDR(bssid), LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)*errorCode));

    mTlvHandler->cleanupTlvs(tlvs);  // Free the memory used by the TLVs

    retVal = 0;
  } while(0);

  LRH_EXIT()
  return retVal;
} // RomeExtractRangingError

int LOWIHeliumRanging::RomeParseRangingMeas(char* measResp, vector <LOWIScanMeasurement*> *scanMeasurements, bool &lastMeas, unsigned int reportType)
{
  LRH_ENTER()
  int retVal = -1;
  vector<LOWITlv *> tlvs; // vector to hold the TLVs
  do
  {
    if (NULL == scanMeasurements)
    {
      break;
    }

    //Get ptr to FW msg. FW msg starts after the ANI message header
    uint8 *fwMsg = ((uint8 *)(measResp)) + sizeof(tAniMsgHdr);

    rttRspInfo rspInfo; // retrieves info for upper layers
    rspInfo.isLastMeas = false;
    uint8 subtype;

    // Get information from the wmi_rtt_oem_rsp_head TLV
    if (0 != mTlvHandler->processRspHeadTlv(fwMsg, rspInfo, subtype))
    {
      LOWI_LOG_DBG("%s: failed to process the wmi_rtt_oem_rsp_head TLV", __FUNCTION__);
      break;
    }

    if (rspInfo.fragInfo.isFragment)
    {
      LOWI_LOG_DBG("%s: Received TLV fragment idx(%u) len(%u)", __FUNCTION__,
                   rspInfo.fragInfo.fragmentIdx, rspInfo.fragInfo.fragmentLen);
      // store msg in list for later processing when all
      // fragments for a given token id have been received
      if (0 != storeFragment(rspInfo, fwMsg))
      {
        LOWI_LOG_DBG("%s: fragment could not be stored", __FUNCTION__);
        break;
      }
    }
    else if ((0 == rspInfo.fragInfo.isFragment) && (0 != rspInfo.fragInfo.fragmentIdx))
    { // last fragment in a given set
      // store it and proceed to process the entire measurement rsp.
      LOWI_LOG_DBG("%s: Received last TLV fragment(%u) len(%u)", __FUNCTION__,
                   rspInfo.fragInfo.fragmentIdx, rspInfo.fragInfo.fragmentLen);

      if (0 != storeFragment(rspInfo, fwMsg))
      {
        LOWI_LOG_DBG("%s: last fragment could not be stored", __FUNCTION__);
        break;
      }

      // Now that all the fragments have been received,
      // proceed to process and parse the entire message
      if (0 != parseFragmentedMsg(rspInfo.fragInfo.tokenId, scanMeasurements, subtype, reportType))
      {
        LOWI_LOG_DBG("%s: failed to parse multi-fragment TLVs", __FUNCTION__);
        break;
      }
    }
    else if ((0 == rspInfo.fragInfo.isFragment) && (0 == rspInfo.fragInfo.fragmentIdx))
    { // not a fragment at all, process it
      if (0 != mTlvHandler->processTLVs(fwMsg, tlvs, subtype, reportType))
      {
        LOWI_LOG_DBG("%s: received bad TLVs", __FUNCTION__);
        break;
      }

      LOWI_LOG_VERB("%s: Got %u TLVs to parse", __FUNCTION__, tlvs.getNumOfElements());
      if (0 != parseMeasRspMsg(tlvs, scanMeasurements))
      {
        LOWI_LOG_DBG("%s: failed to parse TLVs", __FUNCTION__);
        break;
      }
    }

    //Last meas if no more fragments to follow and lastmeas is set
    lastMeas = (!rspInfo.fragInfo.isFragment && rspInfo.isLastMeas);
    failedTargets.flush();

    retVal = 0;
  } while (0);

  mTlvHandler->cleanupTlvs(tlvs);  // Free the memory used by the TLVs
  mTlvHandler->clearPeerSetInfo(); // Reset the peer set info

  LRH_EXIT()
  return retVal;
} // ParseRangingMeas

void LOWIHeliumRanging::parseRttCapabilitiesMsg(vector<LOWITlv *> &tlvs, RomeRttCapabilities &caps)
{
  uint32 serviceBitMask[RTT_SERVICE_BITMASK_SZ]={0};
  LRH_ENTER()

  LOWI_LOG_VERB("%s: vector has %u TLVs\n", __FUNCTION__, tlvs.getNumOfElements());
  for(uint32 ii = 0; ii < tlvs.getNumOfElements(); ++ii)
  {
     switch (tlvs[ii]->getTag())
     {
       case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head:
         {
           LOWI_LOG_DBG("%s: Skipping wmi_rtt_oem_rsp_head\n", __FUNCTION__);
         }
         break;
       case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_head:
         {
           LOWICapRspHeadTlv *pTlv = (LOWICapRspHeadTlv *)tlvs[ii];
           uint32 major = pTlv->getVersionMajor();
           uint32 minor = pTlv->getVersionMinor();
           memcpy(serviceBitMask, pTlv->getServiceBitMask(), RTT_SERVICE_BITMASK_SZ);
           LOWI_LOG_DBG("%s: parsing wmi_rtt_oem_cap_rsp_head TLV"
                        "version(0x%x) major(0x%x) minor(0x%x) serviceBitMask[0](0x%x) "
                        "serviceBitMask[1](0x%x) serviceBitMask[2](0x%x) serviceBitMask[3](0x%x)\n",
                        __FUNCTION__, pTlv->getRttRevision(), major, minor, serviceBitMask[0],
                        serviceBitMask[1], serviceBitMask[2], serviceBitMask[3]);
         }
         break;
       case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_event:
         {
           LOWICapRspEventTlv *pTlv = (LOWICapRspEventTlv *)tlvs[ii];
           pTlv->getRttCaps(caps);
           LOWI_LOG_DBG("%s: parsing wmi_rtt_oem_cap_rsp_event TLV"
                        "rangingTypeMask(%u) supportedFramesMask(%u) maxDestPerReq(%u) "
                        "maxMeasPerDest(%u) maxChannelsAllowed(%u) maxBwAllowed(%u) "
                        "preambleSupportedMask(%u) reportTypeSupportedMask(%u) maxRfChains(%u) "
                        "facTypeMask(%u) numPhys(%u) fwMultiBurstSupport(%u)\n",
                        __FUNCTION__, caps.rangingTypeMask, caps.supportedFramesMask, caps.maxDestPerReq,
                        caps.maxMeasPerDest, caps.maxChannelsAllowed, caps.maxBwAllowed,
                        caps.preambleSupportedMask, caps.reportTypeSupportedMask, caps.maxRfChains,
                        caps.facTypeMask, caps.numPhys, caps.fwMultiBurstSupport);
         }
         break;
       default:
         LOWI_LOG_DBG("%s: unknown tag\n", __FUNCTION__);
         break;
     }
  }

  LRH_EXIT()
} // parseRttCapabilitiesMsg

int LOWIHeliumRanging::parseErrRprt(vector<LOWITlv *> &tlvs, rttMeasRspHead &errRprtInfo, uint32 &errCode)
{
  int retVal = -1;
  for(uint32 ii = 0; ii < tlvs.getNumOfElements(); ++ii)
  {
     switch (tlvs[ii]->getTag())
     {
       case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head:
        {
          LOWITlvRspHead *pTlv = (LOWITlvRspHead *)tlvs[ii];
          LOWI_LOG_VERB("%s: reqId(%u) rttStatus(%s)\n", __FUNCTION__, pTlv->getReqId(),
                        LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)pTlv->getRttStatus()));
          errCode = pTlv->getRttStatus();
        }
         break;
       case WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head:
         {
           LOWI_LOG_VERB("%s: parsing wmi_rtt_oem_measrsp_head TLV\n", __FUNCTION__);
           LOWIMeasRspHeadTlv *pTlv = (LOWIMeasRspHeadTlv *)tlvs[ii];
           pTlv->getMeasRspHead(errRprtInfo);
           printMeasRspHeadInfo(pTlv, errRprtInfo);
           retVal = 0;
         }
         break;
       default:
         LOWI_LOG_DBG("%s: unknown tag\n", __FUNCTION__);
         break;
     }
  }
  return retVal;
} // parseErrRprt
int LOWIHeliumRanging::processPerFrameInfo(uint8 rttMeasType, int numMeasThisAP, vector<LOWITlv *> &tlvs,
                                                     uint32 &nextTlv, LOWIMeasurementInfo *measurementInfo)
{
  int64 rtt64 = 0;

  LOWI_LOG_VERB("%s: parsing wmi_rtt_oem_per_frame_info\n", __FUNCTION__);
  LOWIPerFrameInfoTlv *pTlv4 = (LOWIPerFrameInfoTlv *)tlvs[nextTlv];
  rttPerFrameInfo perFrmInfo;
  pTlv4->parsePerFrameInfo(perFrmInfo);
  printPerFrameInfo(perFrmInfo, pTlv4);

  // V2 measurements
  if (rttMeasType == FRAME_TYPE_NULL ||
      rttMeasType == FRAME_TYPE_QOS_NULL)
  {
    /* Get RSSI and convert it to 0.5 dBm units */
    measurementInfo->rssi = lowi_get_primary_channel_rssi(perFrmInfo.rssi);

    rtt64 = perFrmInfo.t4_del; // resolution picoseconds

    // Subtracting an offset value for Rome HW. For Helium HW
    // there is no offset. It is taken care of in the FW.
    if (LOWIWifiDriverInterface::mCurrTargetHW == TARGET_TYPE_HELIUM ||
        LOWIWifiDriverInterface::mCurrTargetHW == TARGET_TYPE_HASTING)
    {
      measurementInfo->rtt_ps = (tANI_U32)(rtt64);
    }
    else
    {
      measurementInfo->rtt_ps = (tANI_U32)(rtt64 - RTT2_OFFSET_ROME_PS);
    }
    measurementInfo->rtt = measurementInfo->rtt_ps/1000;

    LOWI_LOG_DBG("%s: RTT V2 Performed - Raw RSSI(0x%x), toa - tod = 0x%" PRIx64 "(pre-offset),"
                 " RTT(%u psecs), RSSI(%d) \n", __FUNCTION__, measurementInfo->rssi,
                 rtt64, measurementInfo->rtt_ps, measurementInfo->rssi);

    // Get Tx/Rx measurements
    getTxRxMeasurements(measurementInfo, perFrmInfo);
  }
  else if (rttMeasType == FRAME_TYPE_TMR) // V3 measurements
  {
    LOWI_LOG_VERB("%s: RTT V3 Performed\n", __FUNCTION__);

    if ((numMeasThisAP == 1) && (!perFrmInfo.t3_del && !perFrmInfo.t4_del))
    {
      /* This implies that there are no valid successful measurements */
      nextTlv++; // move to the next tlv
      return -1; /* Skip this measurement */
    }

    /* Get RSSI and convert it to 0.5 dBm units */
    measurementInfo->rssi = lowi_get_primary_channel_rssi(perFrmInfo.rssi);

    // According to FW team t3_del & t4_del are defined as follows:
    //  t3_del = T3 - T2
    //  t4_Del = T4 - T1
    // In RTTV3 protocol:   RTT =  (T4 - T1) - (T3 - T2)
    // which translates to: RTT =    t4_del  -  t3_del
    // T1 and T2 are not needed for calculating RTT
    // Since t4_del and t3_del are uint32, cast to int32 and then
    // to int64 to keep sign.
    measurementInfo->rtt_ps = (int32)(perFrmInfo.t4_del - perFrmInfo.t3_del);

    /* store in nsecs */
    measurementInfo->rtt = measurementInfo->rtt_ps/1000;
    LOWI_LOG_DBG("%s: RTT: %d (ps), RSSI: %d \n", __FUNCTION__,
                  measurementInfo->rtt_ps,
                  measurementInfo->rssi);
    // Get Tx/Rx measurements
    getTxRxMeasurements(measurementInfo, perFrmInfo);
  }

  /* Set the timestamp for this measurement */
  measurementInfo->rssi_timestamp = measurementInfo->rtt_timestamp = LOWIUtils::currentTimeMs();

  return 0;

}


int LOWIHeliumRanging::parseMeasRspMsg(vector<LOWITlv *> &tlvs,
                                        vector<LOWIScanMeasurement *> *scanMeasurements)
{
  LRH_ENTER()
  int retVal = -1;
  uint32 nextTlv = 0; // tlv counter: every time we increment this counter
                      // we're moving to the next LOWITlv to be parsed
  bool errInloop = false;

  // Since the TLVs are already correct and in the
  // correct order, go through and parse each one.
  do
  {
    // parse the wmi_rtt_oem_rsp_head
    BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head, nextTlv, false)

    LOWITlvRspHead *pTlv0 = (LOWITlvRspHead *)tlvs[nextTlv];
    uint32 reqId = pTlv0->getReqId();
    uint8  rttStatus = pTlv0->getRttStatus();
    LOWI_LOG_VERB("%s: parsing wmi_rtt_oem_rsp_head TLV - reqId(%u) rttStatus(%s)\n",
                  __FUNCTION__, reqId, LOWIStrings::to_string((WMI_RTT_STATUS_INDICATOR)rttStatus));

    nextTlv++;

    // parse wmi_rtt_oem_measrsp_head TLV
    BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head, nextTlv, false)

    LOWIMeasRspHeadTlv *pTlv = (LOWIMeasRspHeadTlv *)tlvs[nextTlv];
    rttMeasRspHead measRspHead;
    pTlv->getMeasRspHead(measRspHead);

    // Overwrite the number of peers with the number obtained
    // when the loop processing was done in processTLVs.
    measRspHead.numAPs = mTlvHandler->getNumPeers();
    if (RTT_REPORT_PER_FRAME_WITH_CFR == measRspHead.rprtType ||
        RTT_REPORT_PER_FRAME_WITH_CFR_CIR == measRspHead.rprtType)
    {
       measRspHead.numAPs = 1;
    }
    LOWI_LOG_VERB("%s: parsing wmi_rtt_oem_measrsp_head TLV - numPeers from processing(%u)\n",
                  __FUNCTION__, measRspHead.numAPs);

    // ignore rtt meas type for rprt type 2 & 3
    printMeasRspHeadInfo(pTlv, measRspHead);

    nextTlv++;

    // variable used to store the per-peer information
    rttPerPeerInfo perPeerInfo;

    // loop based on num of AP in info field of wmi_rtt_oem_measrsp_head.
    // (For report type 3, num of APs would always be 1)
    LOWIRangingScanMeasurement *rangingMeasurement = NULL;
    for (uint32 ii = 0; ii < measRspHead.numAPs; ++ii)
    {
      rangingMeasurement = new(std::nothrow) LOWIRangingScanMeasurement;
      bool invalidTimeStamp = false;
      if (rangingMeasurement == NULL)
      {
        LOWI_LOG_WARN("%s: Failed to allocate memory for rangingMeasurement", __FUNCTION__);
        errInloop = true;
        break;
      }

      if (RTT_REPORT_PER_FRAME_WITH_CFR == measRspHead.rprtType ||
          RTT_REPORT_PER_FRAME_WITH_CFR_CIR == measRspHead.rprtType)
      {
        transferMeasureRspInfo(rangingMeasurement, measRspHead);

        // parse wmi_rtt_oem_per_frame_info TLV
        BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info, nextTlv, true)

        // create a container for passing the measurements back
        LOWIMeasurementInfo *measurementInfo = new(std::nothrow) LOWIMeasurementInfo;
        if (measurementInfo == NULL)
        {
          LOWI_LOG_WARN("%s: Allocation failure for measurementInfo", __FUNCTION__);
          errInloop = true;
          break;
        }

        retVal = processPerFrameInfo(measRspHead.rttMeasType, 1, tlvs, nextTlv, measurementInfo);
        if(retVal)
        {
          delete measurementInfo;
          measurementInfo = NULL;
          invalidTimeStamp = true;
          break;
        }

        nextTlv++;
        // parse WMIRTT_TLV_TAG_ARRAY_UINT8 TLV
        BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_ARRAY_UINT8, nextTlv, true)
        //! FIXME :Process Byte array TLV including rssi for each chain

        nextTlv++;
        // Process CFR and CIR Data
        // parse WMIRTT_TLV_TAG_ARRAY_UINT8 TLV
        BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_ARRAY_UINT8, nextTlv, true)

        measurementInfo->cfrcirInfo = new(std::nothrow) LOWICFRCIRInfo;
        if (measurementInfo->cfrcirInfo == NULL)
        {
          LOWI_LOG_WARN("%s: Allocation failure for cfr cir Info", __FUNCTION__);
          errInloop = true;
          break;
        }
        LOWIArrayUINT8Tlv *pTlv6 = (LOWIArrayUINT8Tlv *)tlvs[nextTlv];

        measurementInfo->cfrcirInfo->len = pTlv6->getLength();
        measurementInfo->cfrcirInfo->data = new uint8[measurementInfo->cfrcirInfo->len];
        if(measurementInfo->cfrcirInfo->data)
        {
          pTlv6->getArrayUint8Buff(measurementInfo->cfrcirInfo->data, measurementInfo->cfrcirInfo->len);
        }
        else
        {
          measurementInfo->cfrcirInfo->len = 0;
          errInloop = true;
          break;
        }
        rangingMeasurement->measurementsInfo.push_back(measurementInfo);
        nextTlv++;
        // parse WMIRTT_TLV_TAG_ARRAY_UINT8 TLV
        BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_ARRAY_UINT8, nextTlv, true)
        //! FIXME :Process Byte array TLV including rx location


        if (errInloop) break; // something happened while parsing measurement info

        // assign error code to the current AP measurement
        assignErrCode(measRspHead.destMac, rangingMeasurement, invalidTimeStamp);
      }
      else if (RTT_REPORT_PER_FRAME_NO_CFR == measRspHead.rprtType)
      {
        //To do
      }
      else if (RTT_AGGREGATE_REPORT_NON_CFR == measRspHead.rprtType ||
               RTT_REPORT_PER_BURST_NON_CFR == measRspHead.rprtType)
      {
        BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_peer_event_hdr, nextTlv, true)

        // parse wmi_rtt_oem_per_peer_event_hdr TLV
        LOWIPerPeerEventHdrTlv *pTlv1 = (LOWIPerPeerEventHdrTlv *)tlvs[nextTlv];
        pTlv1->getPerPeerInfo(perPeerInfo);
        // Overwrite the number of measurements for the current peer with
        // the number obtained when the loop processing was done in processTLVs.
        perPeerInfo.numMeasThisAP = mTlvHandler->getNumMeas(ii);
        LOWI_LOG_VERB("%s: parsing wmi_rtt_oem_per_peer_event_hdr TLV -- numMeas for peer(%u)"
                      " from processing(%u)\n", __FUNCTION__, ii, perPeerInfo.numMeasThisAP);
        printPerPeerInfo(perPeerInfo, pTlv1);

        transferPeerInfo(rangingMeasurement, perPeerInfo, measRspHead.channel);

        nextTlv++;

        // parse any byte array TLVs that include IEs
        BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_ARRAY_UINT8, nextTlv, true)
        LOWI_LOG_VERB("%s: parsing WMIRTT_TLV_TAG_ARRAY_UINT8 TLV (IEs)\n", __FUNCTION__);

        // parse the IEs if there are any
        if (perPeerInfo.numIEs > 0)
        {
          LOWI_LOG_INFO("%s: Received %u IEs...parsing wmi_rtt_oem_ie TLV",
                         __FUNCTION__, perPeerInfo.numIEs);

          // get the LOWITlv that contains the IE's
          LOWITlv *pLowiTlv = (LOWITlv *) tlvs[nextTlv];
          uint8 *pTlvIe = pLowiTlv->getTlv();

          // move passed the TLV header to find the wmi_rtt_oem_ie of the first IE.
          pTlvIe += RTT_TLV_HDR_SIZE;

          // parse wmi_rtt_oem_ie TLVs
          for (uint32 jj = 0; jj < perPeerInfo.numIEs; ++jj)
          {
            // get ID and length of the element
            uint32 ieInfo = (*(uint32 *)pTlvIe);
            uint8 elemId = WMI_RTT_WMI_RTT_IE_ELE_ID_GET(ieInfo);
            uint16 elemLen = WMI_RTT_RSP_WMI_RTT_IE_LEN_GET(ieInfo);
            uint8 measType = RTT_MEAS_TYPE_UNKNOWN;
            if (elemId == RM_MEAS_RPT_ELEM_ID &&
                elemLen >= sizeof(MeasReqElem) - RTT_TLV_HDR_SIZE)
            {
              MeasReqElem *pMeasReqElem = (MeasReqElem *)pTlvIe;
              measType = pMeasReqElem->measType;
            }
            LOWI_LOG_INFO("%s: Received IE(%u) len(%u) measType(%u)",
                          __FUNCTION__,
                          elemId,
                          elemLen,
                          measType);

            // Only handle two elements for now. Anything else, skip.
            if ( (measType == RTT_LCI_ELE_ID) || (measType == RTT_LOC_CIVIC_ELE_ID) )
            {
              // store the IE
              storeIE(pTlvIe, rangingMeasurement);
            }
            // move to next IE + sizeof IE length + sizeof IE Type
            pTlvIe += elemLen + 2;
          }
        }
        else
        {
          LOWI_LOG_VERB("%s: No IEs were received", __FUNCTION__);
        }

        nextTlv++;

        // time to parse the actual measurements
        for (uint32 kk = 0; kk < perPeerInfo.numMeasThisAP; ++kk)
        {

          // parse wmi_rtt_oem_per_frame_info TLV
          BREAK_IF_BAD_TAG(WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info, nextTlv, true)

          LOWIMeasurementInfo *measurementInfo = new(std::nothrow) LOWIMeasurementInfo;
          if (measurementInfo == NULL)
          {
            LOWI_LOG_WARN("%s: Allocation failure for measurementInfo", __FUNCTION__);
            errInloop = true;
            break;
          }

          retVal = processPerFrameInfo(perPeerInfo.rttMeasType,perPeerInfo.numMeasThisAP, tlvs, nextTlv, measurementInfo);

          if(retVal)
            {
              delete measurementInfo;
              measurementInfo = NULL;
              invalidTimeStamp = true;
              break;
            }

          rangingMeasurement->measurementsInfo.push_back(measurementInfo);
          nextTlv++; // moving to the next set of measurements (or next peer if last measurement)
        } // for (uint32 kk = 0; kk < numMeasThisAP; ++kk)
      if (errInloop) break; // something happened while parsing measurement info

      // assign error code to the current AP measurement
      assignErrCode(perPeerInfo.peerMac, rangingMeasurement, invalidTimeStamp);
      }

      // add AP to LOWIScanMeasurement
      scanMeasurements->push_back(rangingMeasurement);
      invalidTimeStamp = false;
      memset(&perPeerInfo, 0, sizeof(rttPerPeerInfo));
      rangingMeasurement = NULL;
    } // for (uint32 ii = 0; ii < numAPs; ++ii)
    if (rangingMeasurement)
    {
      delete rangingMeasurement;
    }
    if (errInloop) break; // something happened while parsing measurement info

    retVal = 0;
  } while (0);

  // clear the mPeerSet prior to parsing the measurement msg
  mTlvHandler->clearPeerSetInfo();

  LRH_EXIT()
  return retVal;
} // parseMeasRspMsg


int LOWIHeliumRanging::parseFragmentedMsg(uint32 tokenId,
                                          vector<LOWIScanMeasurement *> *scanMeasurements,
                                          uint8 &subtype, uint32 reportType)
{
  LRH_ENTER()
  int retVal = -1;
  vector<LOWITlv *> tlvs; // vector to hold the TLVs
  LOWIFragInfo *fragInfo = NULL;

  do
  {
    // Find the token id for the fragments that need to be parsed
    for(List<LOWIFragInfo *>::Iterator it = mFragInfoList.begin(); it != mFragInfoList.end(); ++it)
    {
      if((*it)->getTknId() == tokenId)
      { // found token id that has a buffer ready to be processed
        // process the entire message
        fragInfo = *it;

        // done with this token id, remove from the list
        mFragInfoList.erase(it);

        uint8 *frag = fragInfo->getFrag();
        if(NULL == frag)
        {
          LOWI_LOG_DBG("%s: frag is NULL", __FUNCTION__);
          break;
        }

        // log through diag interface. this logs the ranging results that lowi received
        // from the driver before lowi parses the tlvs. All other messages are logged in
        // recv_nl_msg()
        LOWIDiagLog::Log(fragInfo->getFragLen(), frag, LOWI_ROME_RANGING_RESP);

        if (-1 == mTlvHandler->processTLVs(frag, tlvs, subtype, reportType))
        {
          LOWI_LOG_DBG("%s: TLV processing failed", __FUNCTION__);
          break;
        }

        // parse the fragments
        if (0 != parseMeasRspMsg(tlvs, scanMeasurements))
        {
          LOWI_LOG_DBG("%s: Failed to parse fragmented msg", __FUNCTION__);
          break;
        }
        retVal = 0;
        break;
      }
    } // for...
  } while(0);
  mTlvHandler->cleanupTlvs(tlvs);  // Free the memory used by the TLVs
  delete fragInfo;

  LRH_EXIT()
  return retVal;
} // parseFragmentedMsg

void LOWIHeliumRanging::printPerFrameInfo(rttPerFrameInfo const &perFrmInfo,
                                          LOWITlv *pTlv)
{
  if (pTlv == NULL)
  {
    return;
  }

  if (LOWITlv::LOWITLV_PER_FRAME_INFO != pTlv->getTlvType())
  {
    LOWI_LOG_DBG("%s: Wrong Lowi Tlv type(%s)", __FUNCTION__,
                 LOWI_TO_STRING(pTlv->getTlvType(), LOWI_TLV_TYPE));
    return;
  }

  LOWIPerFrameInfoTlv *pTlv4 = (LOWIPerFrameInfoTlv *)pTlv;

  LOWI_LOG_DBG("%s: tx_rate_info1(0x%x) tx_rate_info2(0x%x) rx_rate_info1(0x%x) "
               "rx_rate_info2(0x%x) max_tod_toa_error(0x%x)\n", __FUNCTION__,
               pTlv4->getTxRateInfo1(), pTlv4->getTxRateInfo2(), pTlv4->getRxRateInfo1(),
               pTlv4->getRxRateInfo2(), pTlv4->getMaxTodToaErr());
  LOWI_LOG_DBG("%s: rssi(%u) T1.time32(0x%x) T1.time0(0x%x) T2.time32(0x%x) T2.time0(0x%x) "
               "T3_del(0x%x) T4_del(0x%x) txPreamble(0x%x) txBw(0x%x) txRateMcsIdx(0x%x) "
               "txBitRate(0x%x) rxPreamble(0x%x) rxBw(0x%x) rxRateMcsIdx(0x%x) rxBitRate(0x%x) "
               "chainMask(0x%x) maxTodError(0x%x) maxToaError(0x%x) useTxChainNo (0x%x) useRxChainNo (0x%x)",
               __FUNCTION__,
               perFrmInfo.rssi, perFrmInfo.t1.time32, perFrmInfo.t1.time0, perFrmInfo.t2.time32,
               perFrmInfo.t2.time0, perFrmInfo.t3_del, perFrmInfo.t4_del, perFrmInfo.txPreamble,
               perFrmInfo.txBw, perFrmInfo.txRateMcsIdx, perFrmInfo.txBitRate, perFrmInfo.rxPreamble,
               perFrmInfo.rxBw, perFrmInfo.rxRateMcsIdx, perFrmInfo.rxBitRate,
               perFrmInfo.chainMask, perFrmInfo.maxTodError, perFrmInfo.maxToaError,
               perFrmInfo.useTxChainNo, perFrmInfo.useRxChainNo);
} // printPerFrameInfo

void LOWIHeliumRanging::getTxRxMeasurements(LOWIMeasurementInfo *measurementInfo,
                                            rttPerFrameInfo const &perFrmInfo)
{
  if (NULL == measurementInfo)
  {
    return;
  }
  // get Tx parameters
  measurementInfo->tx_preamble = perFrmInfo.txPreamble;
  measurementInfo->tx_nss      = TX_CHAIN_1;
  measurementInfo->tx_bw       = perFrmInfo.txBw;
  measurementInfo->tx_mcsIdx   = perFrmInfo.txRateMcsIdx;
  measurementInfo->tx_bitrate  = perFrmInfo.txBitRate;
  measurementInfo->tx_chain_no = this->getChainNum(perFrmInfo.useTxChainNo);
  // get Rx parameters
  measurementInfo->rx_preamble = perFrmInfo.rxPreamble;
  measurementInfo->rx_nss      = rxChainsUsed;
  measurementInfo->rx_bw       = perFrmInfo.rxBw;
  measurementInfo->rx_mcsIdx   = perFrmInfo.rxRateMcsIdx;
  measurementInfo->rx_bitrate  = perFrmInfo.rxBitRate;
  measurementInfo->rx_chain_no = this->getChainNum(perFrmInfo.useRxChainNo);

  //Add Sanity check for TX BW
  if (measurementInfo->tx_bw >= BW_MAX)
  {
    LOWI_LOG_ERROR("%s Invalid measurementInfo Tx BW %d, capping to default", __func__, measurementInfo->tx_bw);
    measurementInfo->tx_bw = BW_20MHZ;
  }

  //Add Sanity check for RX BW
  if (measurementInfo->rx_bw >= BW_MAX)
  {
    LOWI_LOG_ERROR("%s Invalid measurementInfo Rx BW %d, capping to default", __func__, measurementInfo->rx_bw);
    measurementInfo->rx_bw = BW_20MHZ;
  }
} // getTxRxMeasurements

void LOWIHeliumRanging::assignErrCode(tANI_U8  bssid[ETH_ALEN_PLUS_2],
                                      LOWIRangingScanMeasurement *rangingMeasurement,
                                      bool invalidTimeStamp)
{
  if (NULL == rangingMeasurement)
  {
    LOWI_LOG_VERB("%s: NULL rangingMeasurement argument\n", __FUNCTION__);
    return;
  }

  WMI_RTT_STATUS_INDICATOR errorCode;
  if (failedTargetCheck(bssid, errorCode))
  {
    /* Target failed so it was skipped by FW */
    if (errorCode == RTT_TRANSIMISSION_ERROR ||
        errorCode == RTT_TMR_TRANS_ERROR)
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_NO_RSP;
    }
    else if (errorCode == RTT_NAN_REQUEST_FAILURE)
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_FAILURE;
      goto exit;
    }
    else if (errorCode == RTT_NAN_NEGOTIATION_FAILURE)
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_NAN_RANGING_PROTOCOL_FAILURE;
      goto exit;
    }
    else if (errorCode == RTT_NAN_DATA_PATH_ACTIVE)
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_NAN_RANGING_CONCURRENCY_NOT_SUPPORTED;
      goto exit;
    }
    else if (errorCode == WMI_RTT_REJECT_MAX)
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_REJECTED;
    }
  }
  else if (rangingMeasurement->retry_after_duration)
  {
    rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_TARGET_BUSY_TRY_LATER;
  }

  /* Target has no valid measurements because all the Time stamps were invalid */
  if (invalidTimeStamp &&
      rangingMeasurement->measurementsInfo.getNumOfElements() == 0)
  {
    if (errorCode == RTT_TM_TIMER_EXPIRE)
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_FTM_TIMEOUT;
    }
    else
    {
      rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_RTT_FAIL_INVALID_TS;
    }
  }

exit:
  LOWI_LOG_VERB("%s: Target Status set to: %u\n", __FUNCTION__, rangingMeasurement->targetStatus);
} // assignErrCode


void LOWIHeliumRanging::printMeasRspHeadInfo(LOWITlv *pMeasTlv, rttMeasRspHead const &errRprtInfo)
{
  do
  {
    if (NULL == pMeasTlv)
    {
      LOWI_LOG_DBG("%s: Meas TLV NULL ", __FUNCTION__);
      break;
    }

    if (LOWITlv::LOWITLV_MEASRSP_HEAD != pMeasTlv->getTlvType())
    {
      LOWI_LOG_DBG("%s: Wrong Lowi Tlv type(%s)", __FUNCTION__,
                   LOWI_TO_STRING(pMeasTlv->getTlvType(), LOWI_TLV_TYPE));
      break;
    }

    LOWIMeasRspHeadTlv *pTlv = (LOWIMeasRspHeadTlv *)pMeasTlv;

    LOWI_LOG_DBG("%s: info(0x%x) channel_info(0x%x) rprtType(%u) rttMeasType(%u) rprtStatusV3(%u) "
                 "tmStart(%u) numAPs(%u) destMac(" LOWI_MACADDR_FMT ") channelInfo(%u)\n",
                 __FUNCTION__, pTlv->getInfoField(), pTlv->getChannel(), errRprtInfo.rprtType,
                 errRprtInfo.rttMeasType, errRprtInfo.rprtStatusV3, errRprtInfo.tmStart,
                 errRprtInfo.numAPs, LOWI_MACADDR(errRprtInfo.destMac), errRprtInfo.channel);
  } while (0);
} // printMeasRspHeadInfo

void LOWIHeliumRanging::printPerPeerInfo(rttPerPeerInfo const &perPeerInfo,
                                         LOWITlv *pPeerTlv)
{
  do
  {
    if (NULL == pPeerTlv)
    {
      LOWI_LOG_DBG("%s: NULL pPeerTlv pointer", __FUNCTION__);
      break;
    }

    if (LOWITlv::LOWITLV_PER_PEER_EVENT_HDR != pPeerTlv->getTlvType())
    {
      LOWI_LOG_DBG("%s: Wrong Lowi Tlv type(%s)", __FUNCTION__,
                   LOWI_TO_STRING(pPeerTlv->getTlvType(), LOWI_TLV_TYPE));
      break;
    }

    LOWIPerPeerEventHdrTlv * pTlv = (LOWIPerPeerEventHdrTlv *)pPeerTlv;
    LOWI_LOG_DBG("%s: peerMac(" LOWI_MACADDR_FMT ") burstIdx(%u) numIEs(%u) numMeasThisAP(%u)"
                 "rttMeasType(%u) isQtiPeer(%u) numFrmAttempted(%u) actualBurstDur(%u) actualNumFrmPerBur(%u) "
                 "actualBurstExp(%u) retryAfterDur(%u) measStartTSF(%u) control(0x%x) result_info_1(0x%x)"
                 "result_info_2(0x%x) result_info_3(0x%x) measStartTSF_field(0x%x)\n",
                 __FUNCTION__, LOWI_MACADDR(perPeerInfo.peerMac), perPeerInfo.burstIdx,
                 perPeerInfo.numIEs, perPeerInfo.numMeasThisAP, perPeerInfo.rttMeasType,
                 perPeerInfo.isQtiPeer, perPeerInfo.numFrmAttempted, perPeerInfo.actualBurstDur,
                 perPeerInfo.actualNumFrmPerBur, perPeerInfo.actualBurstExp,
                 perPeerInfo.retryAfterDur, perPeerInfo.measStartTSF,pTlv->getControl(),
                 pTlv->getResultInfo1(), pTlv->getResultInfo2(), pTlv->getResultInfo3(),
                 pTlv->getTsfField());
  } while (0);
} // printPerPeerInfo

void LOWIHeliumRanging::transferMeasureRspInfo(LOWIRangingScanMeasurement *rangingMeasurement,
                                         rttMeasRspHead &measRspHead)
{
  if (NULL == rangingMeasurement)
  {
    return;
  }

  rangingMeasurement->bssid.setMac(measRspHead.destMac); // insert mac address
  rangingMeasurement->frequency = measRspHead.channel;
  rangingMeasurement->isSecure = false;
  rangingMeasurement->msapInfo = NULL;
  rangingMeasurement->cellPowerLimitdBm = 0;
  /* by default the measurement is a success */
  rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_SUCCESS;

  // check P2P cache to decide on type of peer
  rangingMeasurement->type = p2pIsStored(measRspHead.destMac, NULL) ?
                             PEER_DEVICE : ACCESS_POINT;

  // derive the rtt type from the frame used for the measurements
  rangingMeasurement->rttType = (measRspHead.rttMeasType == RTT_MEAS_FRAME_TMR) ?
      qc_loc_fw::RTT3_RANGING : qc_loc_fw::RTT2_RANGING;

  rangingMeasurement->peerOEM                         = (0 /* Check for appropriate bit*/) ?
                                                        LOWIScanMeasurement::LOWI_PEER_OEM_QTI :
                                                        LOWIScanMeasurement::LOWI_PEER_OEM_UNKNOWN;
  rangingMeasurement->num_frames_attempted            = 0;
  rangingMeasurement->actual_burst_duration           = 0;
  rangingMeasurement->negotiated_num_frames_per_burst = 0;
  rangingMeasurement->retry_after_duration            = 0;
  rangingMeasurement->negotiated_burst_exp            = 0;
  rangingMeasurement->lciInfo                         = NULL;
  rangingMeasurement->lcrInfo                         = NULL;
  rangingMeasurement->rttMeasTimeStamp                = 0;
} // transferMeasureRspInfo

void LOWIHeliumRanging::transferPeerInfo(LOWIRangingScanMeasurement *rangingMeasurement,
                                         rttPerPeerInfo &perPeerInfo, uint32 channel)
{
  if (NULL == rangingMeasurement)
  {
    return;
  }

  rangingMeasurement->bssid.setMac(perPeerInfo.peerMac); // insert mac address
  rangingMeasurement->frequency = channel;
  rangingMeasurement->isSecure = false;
  rangingMeasurement->msapInfo = NULL;
  rangingMeasurement->cellPowerLimitdBm = 0;
  /* by default the measurement is a success */
  rangingMeasurement->targetStatus = LOWIScanMeasurement::LOWI_TARGET_STATUS_SUCCESS;

  // check P2P cache to decide on type of peer
  rangingMeasurement->type = p2pIsStored(perPeerInfo.peerMac, NULL) ?
                             PEER_DEVICE : ACCESS_POINT;

  // derive the rtt type from the frame used for the measurements
  rangingMeasurement->rttType = (perPeerInfo.rttMeasType == RTT_MEAS_FRAME_TMR) ?
      qc_loc_fw::RTT3_RANGING : qc_loc_fw::RTT2_RANGING;

  rangingMeasurement->peerOEM                         = (perPeerInfo.isQtiPeer) ?
                                                        LOWIScanMeasurement::LOWI_PEER_OEM_QTI :
                                                        LOWIScanMeasurement::LOWI_PEER_OEM_UNKNOWN;
  rangingMeasurement->num_frames_attempted            = perPeerInfo.numFrmAttempted;
  rangingMeasurement->actual_burst_duration           = perPeerInfo.actualBurstDur;
  rangingMeasurement->negotiated_num_frames_per_burst = perPeerInfo.actualNumFrmPerBur;
  rangingMeasurement->retry_after_duration            = perPeerInfo.retryAfterDur;
  rangingMeasurement->negotiated_burst_exp            = perPeerInfo.actualBurstExp;
  rangingMeasurement->lciInfo                         = NULL;
  rangingMeasurement->lcrInfo                         = NULL;
  rangingMeasurement->rttMeasTimeStamp                = (uint64)perPeerInfo.measStartTSF;
} // transferPeerInfo

int LOWIHeliumRanging::storeFragment(rttRspInfo const &rspInfo, uint8* pMsg)
{
  int retVal = -1;

  do
  {
    if (NULL == pMsg)
    {
      LOWI_LOG_DBG("%s: Null msg pointer", __FUNCTION__);
      break;
    }

    // Find if there are other fragments already stored for this token id
    bool foundIt = false;
    wmi_rtt_oem_rsp_head* rttOemRspHead = (wmi_rtt_oem_rsp_head*) pMsg;
    uint16 oemRspHeadLen = WMIRTT_TLV_GET_TLVLEN(rttOemRspHead->tlv_header);
    for(List<LOWIFragInfo *>::Iterator it = mFragInfoList.begin(); it != mFragInfoList.end(); ++it)
    {
      LOWIFragInfo *info = *it;

      if(info->getTknId() == rspInfo.fragInfo.tokenId)
      {
        // Found token id to which this fragment belongs to. Save fragment.
        // Move passed the wmi_rtt_oem_rsp_head and store the rest of the msg
        uint8 *pTmp = pMsg + oemRspHeadLen;

        LOWI_LOG_DBG("%s: old fragment group, tokenid(%u), adding %u chars @position %u\n",
                     __FUNCTION__, rspInfo.fragInfo.tokenId, rspInfo.fragInfo.fragmentLen, info->getNextIdx());
        retVal = info->addFrag(pTmp, rspInfo.fragInfo.fragmentLen);
        foundIt = true;
        break;
      }
    } // for loop

    if (true == foundIt)
    {
      break;
    }

    // This is a NEW fragment. Alloc memory for it.
    LOWIFragInfo *item = new (std::nothrow) LOWIFragInfo(rspInfo.fragInfo.tokenId);
    if (NULL == item)
    {
      LOWI_LOG_DBG("%s: Memory allocation failure", __FUNCTION__);
      break;
    }

    // Since it is the first fragment of a series, store the entire fragment.
    // Subsequent fragments for this token id will skip the wmi_rtt_oem_rsp_head.
    uint32 totalSize = rspInfo.fragInfo.fragmentLen + oemRspHeadLen;
    LOWI_LOG_DBG("%s: new fragment group, tokenid(%u), adding %u chars @position %u\n",
                 __FUNCTION__, rspInfo.fragInfo.tokenId, totalSize, item->getNextIdx());
    item->addFrag(pMsg, totalSize);

    // store in list of fragments
    mFragInfoList.add(item);

    retVal = 0;
  } while (0);

  return retVal;

} // storeFragment

int LOWIHeliumRanging::hasFragsForTokenId(uint32 tokenId)
{
    int retVal = -1;

    for(List<LOWIFragInfo *>::Iterator it = mFragInfoList.begin(); it != mFragInfoList.end(); ++it)
    {
      LOWIFragInfo *info = *it;

      if(info->getTknId() == tokenId)
      { // found token id to which this fragment belongs to
          retVal = 0;
          break;
      }
    }
    return retVal;
} // hasFragsForTokenId

int LOWIHeliumRanging::storeIE(uint8 *pIEData, LOWIRangingScanMeasurement *rangingMeasurement)
{
  int retVal = -1;

  do
  {
    LOWILocationIE *locIe = new LOWILocationIE();
    if (NULL == locIe)
    {
      LOWI_LOG_DBG("%s: Memory allocation failure", __FUNCTION__);
      break;
    }

    MeasReqElem *pMeasReqElem = (MeasReqElem *)pIEData;
    pIEData += WMI_RTT_WMI_RTT_IE_LEN;
    locIe->id  = pMeasReqElem->elementId;
    locIe->len = pMeasReqElem->len;
    locIe->locData = new uint8[locIe->len];
    if (NULL == locIe->locData)
    {
      LOWI_LOG_DBG("%s: Memory allocation failure", __FUNCTION__);
      delete locIe;
      break;
    }

    memcpy(locIe->locData, pIEData, locIe->len);

    switch (pMeasReqElem->measType)
    {
      case RTT_LCI_ELE_ID:
        {
          if(rangingMeasurement->lciInfo == NULL && locIe != NULL)
          {
            LOWI_LOG_VERB("%s: Received LCI Report IE %u - len: %u", __FUNCTION__,
                          locIe->id, locIe->len);
            rangingMeasurement->lciInfo = locIe;
            retVal = 0;
          }
          else
          {
            LOWI_LOG_WARN("%s: Already have LCI IE discarding this one", __FUNCTION__);
            delete locIe;
          }
          break;
        }
      case RTT_LOC_CIVIC_ELE_ID:
        {
          if (rangingMeasurement->lcrInfo == NULL && locIe != NULL)
          {
            LOWI_LOG_VERB("%s: Received LCR Report IE %u - len: %u", __FUNCTION__,
                          locIe->id, locIe->len);
            rangingMeasurement->lcrInfo = locIe;
            retVal = 0;
          }
          else
          {
            LOWI_LOG_WARN("%s: Already have LCR IE discarding this one", __FUNCTION__);
            delete locIe;
          }
          break;
        }
      default:
        {
          LOWI_LOG_WARN("%s: Received Report IE it doesn't recognize: %u", __FUNCTION__,
                        pMeasReqElem->measType);
          delete locIe;
          break;
        }
    }
  } while (0);

  return retVal;
} // storeIE

char * LOWIHeliumRanging::allocAniMsgHdr(uint32 aniMsgLen, uint32 aniHdrLen,
                                         uint32 aniMetaLen, uint32 aniInterfaceLen)
{
  char *aniMsg = NULL;
  aniMsg = (char *)calloc(aniHdrLen + aniMsgLen + aniMetaLen + aniInterfaceLen, 1);
  if (aniMsg != NULL)
  {
    tAniMsgHdr *pHdr = (tAniMsgHdr *)aniMsg;
    pHdr->type       = ANI_MSG_OEM_DATA_REQ;
    pHdr->length     = aniMsgLen;
  }
  return aniMsg;
}

int LOWIHeliumRanging::SendEnableResponderReq(int8 width, uint32 duration_seconds, int32 primary_freq,
                                              int32 center_freq1, int32 center_freq2,
                                              uint32 reg_info_1, uint32 reg_info_2, uint32 phyMode)
{
  int retVal = -1;
  std::string interface = "wifi0";

  do
  {
    uint32 band = LOWIUtils::freqToBand(primary_freq);
    if(width >= BW_MAX || band >= LOWIDiscoveryScanRequest::BAND_ALL)
    {
      LOWI_LOG_DBG("%s: Out of bound: width:%d band:%d\n", __FUNCTION__, width, band);
      break;
    }
    // ani message header length
    uint32 aniHdrLen = sizeof(tAniMsgHdr);
    uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

    // ani message length = length of all TLVs
    uint32 aniMsgLen = sizeof(wmi_rtt_oem_req_head) + sizeof(wmi_rtt_oem_set_responder_mode_req_head);

    uint32 aniInterfaceLen = sizeof(tAniInterface);

    // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
    // and fill out the header
    char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
    if (aniMessage == NULL)
    {
      LOWI_LOG_ERROR("%s: Allocation failure for ANI message", __FUNCTION__);
      break;
    }

    // Fill out the ANI message body with the TLVs. Message body starts after the header.
    char *aniMsgBody = (char *)(aniMessage + (char)aniHdrLen);

    // Adding the wmi_rtt_oem_req_head TLV
    wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)aniMsgBody;
    WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                       sizeof(wmi_rtt_oem_req_head));
    reqHead->sub_type = RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_REQ;
    reqHead->req_id   = ++req_id;
    reqHead->pdev_id = 1;

    // Adding the wmi_rtt_oem_set_responder_mode_req_head TLV
    wmi_rtt_oem_set_responder_mode_req_head *setResponderReqHead =
      (wmi_rtt_oem_set_responder_mode_req_head *)(aniMsgBody + sizeof(wmi_rtt_oem_req_head));
    WMIRTT_TLV_SET_HDR(&setResponderReqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_req_head,
                       sizeof(wmi_rtt_oem_set_responder_mode_req_head));
    setResponderReqHead->version = RTT_VER_SET_VERSION(RTT_VERSION_MAJOR, RTT_VERSION_MINOR);
    setResponderReqHead->revision  = RTT_REVISION;
    setResponderReqHead->mode  = RTT_RESP_MODE_ENABLE;
    setResponderReqHead->duration = duration_seconds;
    WMIRTT_TLV_SET_HDR(&setResponderReqHead->channel_info.tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info,
                       sizeof(wmi_rtt_oem_channel_info));
    setResponderReqHead->channel_info.mhz = primary_freq;
    setResponderReqHead->channel_info.band_center_freq1 = center_freq1;
    setResponderReqHead->channel_info.band_center_freq2 = center_freq2;

    setResponderReqHead->channel_info.info = phyMode;
    setResponderReqHead->channel_info.reg_info_1 = reg_info_1;
    setResponderReqHead->channel_info.reg_info_2 = reg_info_2;

    LOWI_LOG_VERB("%s: subtype(%s) requestID(%d) aniMsgLen(%u) aniHdrLen(%u)"
                  " frequency(%u-%u,%u) phyMode(%u)", __FUNCTION__,
                  LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)reqHead->sub_type),
                  reqHead->req_id, aniMsgLen, aniHdrLen,
                  setResponderReqHead->channel_info.mhz,
                  setResponderReqHead->channel_info.band_center_freq1,
                  setResponderReqHead->channel_info.band_center_freq2,
                  setResponderReqHead->channel_info.info);

    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        break;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + (char)aniHdrLen + (char) aniMsgLen + (char)aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

    /* Send ANI Message over Netlink Socket */
    if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
    {
      LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
      free(aniMessage);
      break;
    }

    free(aniMessage);
    retVal = 0;
  } while (0);
  return retVal;
}

int LOWIHeliumRanging::SendDisableResponderReq()
{
  int retVal = -1;
  std::string interface = "wifi0";

  do
  {
    // ani message header length
    uint32 aniHdrLen = sizeof(tAniMsgHdr);
    uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

    // ani message length = length of all TLVs
    uint32 aniMsgLen = sizeof(wmi_rtt_oem_req_head) + sizeof(wmi_rtt_oem_set_responder_mode_req_head);

    uint32 aniInterfaceLen = sizeof(tAniInterface);

    // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
    // and fill out the header
    char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
    if (aniMessage == NULL)
    {
      LOWI_LOG_ERROR("%s: Allocation failure for ANI message", __FUNCTION__);
      break;
    }

    // Fill out the ANI message body with the TLVs. Message body starts after the header.
    char *aniMsgBody = (char *)(aniMessage + (char)aniHdrLen);

    // Adding the wmi_rtt_oem_req_head TLV
    wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)aniMsgBody;
    WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                       sizeof(wmi_rtt_oem_req_head));
    reqHead->sub_type = RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_REQ;
    reqHead->req_id   = ++req_id;
    reqHead->pdev_id = 1;

    // Adding the wmi_rtt_oem_cap_req_head TLV
    wmi_rtt_oem_set_responder_mode_req_head *setResponderReqHead =
      (wmi_rtt_oem_set_responder_mode_req_head *)(aniMsgBody + sizeof(wmi_rtt_oem_req_head));
    WMIRTT_TLV_SET_HDR(&setResponderReqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_req_head,
                       sizeof(wmi_rtt_oem_set_responder_mode_req_head));
    setResponderReqHead->version = RTT_VER_SET_VERSION(RTT_VERSION_MAJOR, RTT_VERSION_MINOR);
    setResponderReqHead->revision  = RTT_REVISION;
    setResponderReqHead->mode  = RTT_RESP_MODE_DISABLE;
    WMIRTT_TLV_SET_HDR(&setResponderReqHead->channel_info.tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info,
                       sizeof(wmi_rtt_oem_channel_info));
    setResponderReqHead->channel_info.mhz = 0;
    setResponderReqHead->channel_info.band_center_freq1 = 0;
    setResponderReqHead->channel_info.band_center_freq2 = 0;
    setResponderReqHead->channel_info.info = 0;
    setResponderReqHead->channel_info.reg_info_1 = 0;
    setResponderReqHead->channel_info.reg_info_2 = 0;
    LOWI_LOG_VERB("%s: subtype(%s) requestID(%d) aniMsgLen(%u) aniHdrLen(%u)\n", __FUNCTION__,
                  LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)reqHead->sub_type),
                  reqHead->req_id, aniMsgLen, aniHdrLen);


    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        break;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + (char)aniHdrLen + (char) aniMsgLen + (char)aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

    /* Send ANI Message over Netlink Socket */
    if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
    {
      LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
      free(aniMessage);
      break;
    }

    free(aniMessage);
    retVal = 0;
  } while (0);
  return retVal;
}

int LOWIHeliumRanging::SendResponderMeasurementConfigReq(uint8 report_type, uint8 req_type)
{
  int retVal = -1;
  std::string interface = "wifi0";

  do
  {
    // ani message header length
    uint32 aniHdrLen = sizeof(tAniMsgHdr);
    uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

    // ani message length = length of all TLVs
    uint32 aniMsgLen = sizeof(wmi_rtt_oem_req_head) + sizeof(wmi_rtt_oem_cfg_resp_meas_req_head);

    uint32 aniInterfaceLen = sizeof(tAniInterface);

    // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
    // and fill out the header
    char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
    if (aniMessage == NULL)
    {
      LOWI_LOG_ERROR("%s: Allocation failure for ANI message", __FUNCTION__);
      break;
    }

    // Fill out the ANI message body with the TLVs. Message body starts after the header.
    char *aniMsgBody = (char *)(aniMessage + (char)aniHdrLen);

    // Adding the wmi_rtt_oem_req_head TLV
    wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)aniMsgBody;
    WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                       sizeof(wmi_rtt_oem_req_head));
    reqHead->sub_type = RTT_MSG_SUBTYPE_CFG_RESPONDER_MEASUREMENT_REQ;
    reqHead->req_id   = ++req_id;

    // Adding the wmi_rtt_oem_cap_req_head TLV
    wmi_rtt_oem_cfg_resp_meas_req_head *setResponderMeasReqHead =
      (wmi_rtt_oem_cfg_resp_meas_req_head *)(aniMsgBody + sizeof(wmi_rtt_oem_req_head));
    WMIRTT_TLV_SET_HDR(&setResponderMeasReqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cfg_resp_meas_req_head,
                       sizeof(wmi_rtt_oem_cfg_resp_meas_req_head));
    WMI_RTT_CFG_RESP_MEAS_REQ_REPORT_TYPE_SET(setResponderMeasReqHead->config, report_type);

    if(req_type)
    {
      setResponderMeasReqHead->config  |= WMI_RTT_CFG_RESP_MEAS_REQ_ENABLE;
    }
    else
    {
      setResponderMeasReqHead->config  &= ~WMI_RTT_CFG_RESP_MEAS_REQ_ENABLE;
    }

    LOWI_LOG_VERB("%s: subtype(%s) responder_meas_req(%s) requestID(%d) aniMsgLen(%u) aniHdrLen(%u)\n", __FUNCTION__,
                  LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)reqHead->sub_type),
                  (req_type ? "START" : "STOP"),
                  reqHead->req_id, aniMsgLen, aniHdrLen);


    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        break;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + (char)aniHdrLen + (char) aniMsgLen + (char)aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

    /* Send ANI Message over Netlink Socket */
    if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
    {
      LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
      free(aniMessage);
      break;
    }

    free(aniMessage);
    retVal = 0;
  } while (0);
  return retVal;
}

int LOWIHeliumRanging::SendResponderMeasurementStartReq(uint8 report_type)
{
   return SendResponderMeasurementConfigReq(report_type, 1);
}

int LOWIHeliumRanging::SendResponderMeasurementStopReq()
{
   return SendResponderMeasurementConfigReq(0, 0);
}
int LOWIHeliumRanging::SendRTTAvailableChannelReq()
{
  int retVal = -1;
  std::string interface = "wifi0";

  do
  {
    // ani message header length
    uint32 aniHdrLen = sizeof(tAniMsgHdr);
    uint32 aniMetaLen = sizeof(tAniMetaData) + sizeof(uint32_t);

    // ani message length = length of all TLVs
    uint32 aniMsgLen = sizeof(wmi_rtt_oem_req_head) + sizeof(wmi_rtt_oem_get_channel_info_req_head);

    uint32 aniInterfaceLen = sizeof(tAniInterface);

    // alloc memory for the entire ani message: AniMsgHdr + aniMsgBody
    // and fill out the header
    char *aniMessage = allocAniMsgHdr(aniMsgLen, aniHdrLen, aniMetaLen, aniInterfaceLen);
    if (aniMessage == NULL)
    {
      LOWI_LOG_ERROR("%s: Allocation failure for ANI message", __FUNCTION__);
      break;
    }

    // Fill out the ANI message body with the TLVs. Message body starts after the header.
    char *aniMsgBody = (char *)(aniMessage + (char)aniHdrLen);

    // Adding the wmi_rtt_oem_req_head TLV
    wmi_rtt_oem_req_head *reqHead = (wmi_rtt_oem_req_head *)aniMsgBody;
    WMIRTT_TLV_SET_HDR(&reqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_req_head,
                       sizeof(wmi_rtt_oem_req_head));
    reqHead->sub_type = RTT_MSG_SUBTYPE_GET_CHANNEL_INFO_REQ;
    reqHead->req_id   = ++req_id;
    reqHead->pdev_id = 1;

    // Adding the wmi_rtt_oem_cap_req_head TLV
    wmi_rtt_oem_get_channel_info_req_head *channelReqHead =
      (wmi_rtt_oem_get_channel_info_req_head *)(aniMsgBody + sizeof(wmi_rtt_oem_req_head));
    WMIRTT_TLV_SET_HDR(&channelReqHead->tlv_header,
                       WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_get_channel_info_req_head,
                       sizeof(wmi_rtt_oem_get_channel_info_req_head));
    channelReqHead->version = RTT_VER_SET_VERSION(RTT_VERSION_MAJOR, RTT_VERSION_MINOR);
    channelReqHead->revision  = RTT_REVISION;

    LOWI_LOG_VERB("%s: subtype(%s) requestID(%d) aniMsgLen(%u) aniHdrLen(%u)\n", __FUNCTION__,
                  LOWIStrings::to_string((WMIRTT_OEM_MSG_SUBTYPE)reqHead->sub_type),
                  reqHead->req_id, aniMsgLen, aniHdrLen);



    /* Fill Meta data */
    uint32_t *count = (uint32_t*)(aniMsgBody + aniMsgLen);
    *count = 1;
    struct tAniMetaData *sMetaData = (struct tAniMetaData *) (count + 1);
    sMetaData->id = WMIRTT_FIELD_ID_pdev;
    sMetaData->offset = offsetof(wmi_rtt_oem_req_head, pdev_id);
    sMetaData->length = sizeof(uint32_t);

    if (interface.length() > MAX_INTERFACE_LEN) {
        LOWI_LOG_ERROR("%s: interface.length(%d) exceeds MAX_INTERFACE_LEN(%d)", __FUNCTION__, interface.length(), MAX_INTERFACE_LEN);
        free(aniMessage);
        break;
    }

    struct tAniInterface *aniInterface = (struct tAniInterface *) (aniMessage + (char)aniHdrLen + (char) aniMsgLen + (char)aniMetaLen);
    aniInterface->length = interface.length();
    strlcpy((char *)aniInterface->name, interface.c_str(), sizeof(aniInterface->name));

    /* Send ANI Message over Netlink Socket */
    if (send_nl_msg(nl_sock_fd, aniMessage, aniHdrLen, aniMsgLen, aniMetaLen, aniInterfaceLen) < 0)
    {
      LOWI_LOG_ERROR("%s: NL Send Failed", __FUNCTION__);
      free(aniMessage);
      break;
    }

    free(aniMessage);
    retVal = 0;
  } while (0);

  return retVal;
}
/************ END - Message Handlers ****************/

