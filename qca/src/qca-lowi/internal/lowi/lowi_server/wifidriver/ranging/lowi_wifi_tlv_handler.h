#ifndef __LOWI_WIFI_TLV_HANDLER_H__
#define __LOWI_WIFI_TLV_HANDLER_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI TLV Handler class header file

GENERAL DESCRIPTION
  This file contains the interface for the class LOWI TLV Handler.

Copyright (c) 2016, 2018-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/
// the order of these includes matters: DO NOT CHANGE ORDER
#include "rtt_oem_interface.h"
#include "lowi_tlv.h"
#include <lowi_ranging.h>

/** this struct pairs a tag with an index into an array where the common TLV
 *  processing should continue */
typedef struct
{
  uint8 tag;
  uint8 idx;
} tagIdxInfo;

/** struct contains the basic parameters needed to do the common
 *  processing of a TLV msg */
typedef struct
{
  uint8  tag;            // TLV tag
  uint32 tlvSize;        // size of TLV in bytes
  uint8  subtype;        // RTT msg subtype (i.e. WMIRTT_OEM_MSG_SUBTYPE)
  uint8  numOtherTags;   // number of other tags that could potentially be at this index
                         // when the TLV is verified
  const char *tlvStr;    // TLV name
  tagIdxInfo *otherTags; // if numOtherTags != 0, this is the array that contains
                         // the (tag, index) information for the other tags. If
                         // numOtherTags == 0, this will be null.
} measMsgInfo;

namespace qc_loc_fw
{

/**
 * LOWIWifiTlvHandler class
 * This class handles most of the TLV manipulations such putting together TLV
 * requests and processing TLVs when they arrive in a FW msg
 */
class LOWIWifiTlvHandler
{
private:
  static const char* const TAG;
  /** index into the vector mPeerSet where the number of rtt measurements
   *  will be stored during common processing of the rtt response msg */
  uint32 mPeerIdx;

  /** this vector stores the numver of rtt measurements for each peer in the
   *  rtt response msg as the TLVs are being processed */
  vector<uint8> mPeerSet;

  /** this var is used to keep track of the peer loop start TLVs encountered
   *  during common processing */
  uint8 mPeerLs;

  /** this var is used to keep track of the measurement loop start TLVs
   *  encountered during common processing */
  uint8 mMeasLs;

  /** size of the array to be used in the TLV common processing routine */
  uint32 mMsgArrSz;

  /** array used when processing msg subtype RTT_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP*/
  #define CHANNEL_MSG_ARR_SZ 3
  measMsgInfo const channelMsgArr[CHANNEL_MSG_ARR_SZ] =
    { // idx 0
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head,
      sizeof(wmi_rtt_oem_rsp_head),
      (uint8)RTT_MSG_SUBTYPE_GET_CHANNEL_INFO_RSP,
      0, "wmi_rtt_oem_rsp_head", NULL},

      // idx 1
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_get_channel_info_rsp_head,
      sizeof(wmi_rtt_oem_get_channel_info_req_head), 0,
      0, "wmi_rtt_oem_get_channel_info_rsp_head", NULL},

      // idx 2
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info,
      sizeof(wmi_rtt_oem_channel_info), 0,
      0, "wmi_rtt_oem_channel_info", NULL}
    };

  /** array used when processing msg subtype RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_RSP*/
  #define RESPONDER_CHANNEL_MSG_ARR_SZ 3
  measMsgInfo const ResponderchannelMsgArr[RESPONDER_CHANNEL_MSG_ARR_SZ] =
    { // idx 0
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head,
      sizeof(wmi_rtt_oem_rsp_head),
      (uint8)RTT_MSG_SUBTYPE_CFG_RESPONDER_MODE_RSP,
      0, "wmi_rtt_oem_rsp_head", NULL},

      // idx 1
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_set_responder_mode_rsp_head,
      sizeof(wmi_rtt_oem_set_responder_mode_rsp_head), 0,
      0, "wmi_rtt_oem_set_responder_mode_rsp_head", NULL},

      // idx 2
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info,
      sizeof(wmi_rtt_oem_channel_info), 0,
      0, "wmi_rtt_oem_channel_info", NULL}
    };
  /** array used when processing msg subtype RTT_MSG_SUBTYPE_CAPABILITY_RSP */
  #define CAPS_MSG_ARR_SZ 3
  measMsgInfo const capsMsgArr[CAPS_MSG_ARR_SZ] =
    { // idx 0
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head,
      sizeof(wmi_rtt_oem_rsp_head),
      (uint8)RTT_MSG_SUBTYPE_CAPABILITY_RSP,
      0, "wmi_rtt_oem_rsp_head", NULL},

      // idx 1
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_head,
      sizeof(wmi_rtt_oem_cap_rsp_head), 0,
      0, "wmi_rtt_oem_cap_rsp_head", NULL},

      // idx 2
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_cap_rsp_event,
      sizeof(wmi_rtt_oem_cap_rsp_event), 0,
      0, "wmi_rtt_oem_cap_rsp_event", NULL}
    };
  /** array used when processing msg subtype RTT_MSG_SUBTYPE_ERROR_REPORT_RSP */
  #define ERR_MSG_ARR_SZ 2
  measMsgInfo const errMsgArr[ERR_MSG_ARR_SZ] =
    { // idx 0
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head,
      sizeof(wmi_rtt_oem_rsp_head),
      (uint8)RTT_MSG_SUBTYPE_ERROR_REPORT_RSP,
      0, "wmi_rtt_oem_rsp_head", NULL},

      // idx 1
      {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head,
      sizeof(wmi_rtt_oem_measrsp_head), 0,
      0, "wmi_rtt_oem_measrsp_head", NULL}
    };

  /** array used when processing msg subtype RTT_MSG_SUBTYPE_MEASUREMENT_RSP */
#define CFR_MEAS_MSG_ARR_SZ 8
  measMsgInfo const cfrmeasMsgArr[CFR_MEAS_MSG_ARR_SZ] =
  { // idx 0
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head,
    sizeof(wmi_rtt_oem_rsp_head),
    (uint8)RTT_MSG_SUBTYPE_MEASUREMENT_RSP,
    0, "wmi_rtt_oem_rsp_head", NULL},

    // idx 1
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head,
    sizeof(wmi_rtt_oem_measrsp_head), 0,
    0, "wmi_rtt_oem_measrsp_head", NULL},

    // idx 2
    {WMIRTT_TLV_TAG_STRUC_loop_start,
    RTT_TLV_HDR_SIZE,0,
    0, "loop_start", NULL},

    // idx 3
    {WMIRTT_TLV_TAG_STRUC_loop_end,
    RTT_TLV_HDR_SIZE, 0,
    0, "loop_end", NULL},

    // idx 4
    {WMIRTT_TLV_TAG_STRUC_loop_start,
    RTT_TLV_HDR_SIZE,0,
    0, "loop_start", NULL},

    // idx 5
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info,
    sizeof(wmi_rtt_oem_per_frame_info), 0,
    0, "wmi_rtt_oem_per_frame_info", NULL},

    // idx 6
    {WMIRTT_TLV_TAG_ARRAY_UINT8,
    RTT_TLV_HDR_SIZE, 0,
    2, "WMIRTT_TLV_TAG_ARRAY_UINT8", otherTagsARRAYUINT8InfoTlv},

    // idx 7
    {WMIRTT_TLV_TAG_STRUC_loop_end,
    RTT_TLV_HDR_SIZE, 0,
    2, "loop_end", otherTagsARRAYUINT8InfoTlv},

  };

  /** array used when processing msg subtype RTT_MSG_SUBTYPE_MEASUREMENT_RSP */
  #define MEAS_MSG_ARR_SZ 9
  measMsgInfo const measMsgArr[MEAS_MSG_ARR_SZ] =
  { // idx 0
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_rsp_head,
    sizeof(wmi_rtt_oem_rsp_head),
    (uint8)RTT_MSG_SUBTYPE_MEASUREMENT_RSP,
    0, "wmi_rtt_oem_rsp_head", NULL},

    // idx 1
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_measrsp_head,
    sizeof(wmi_rtt_oem_measrsp_head), 0,
    0, "wmi_rtt_oem_measrsp_head", NULL},

    // idx 2
    {WMIRTT_TLV_TAG_STRUC_loop_start,
    RTT_TLV_HDR_SIZE,0,
    0, "loop_start", NULL},

    // idx 3
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_peer_event_hdr,
    sizeof(wmi_rtt_oem_per_peer_event_hdr), 0,
    2, "wmi_rtt_oem_per_peer_event_hdr", otherTagsPerPeerEvtHdrTlv},

    // idx 4
    {WMIRTT_TLV_TAG_ARRAY_UINT8,
    RTT_TLV_HDR_SIZE, 0,
    0, "WMIRTT_TLV_TAG_ARRAY_UINT8", NULL},

    // idx 5
    {WMIRTT_TLV_TAG_STRUC_loop_start,
    RTT_TLV_HDR_SIZE, 0,
    0, "loop_start", NULL},

    // idx 6
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info,
    sizeof(wmi_rtt_oem_per_frame_info), 0,
    2, "wmi_rtt_oem_per_frame_info", otherTagsPerFrameInfoTlv},

    // idx 7
    {WMIRTT_TLV_TAG_STRUC_loop_end,
    RTT_TLV_HDR_SIZE, 0,
    1, "loop_end", otherTagsMeasLoopEndTlv},

    // idx 8
    {WMIRTT_TLV_TAG_STRUC_loop_end,
    RTT_TLV_HDR_SIZE, 0,
    1, "loop_end", otherTagsPeerLoopEndTlv}
  };

  // todo: consider moving to common processing code
  /** Array contains other expected tags for wmi_rtt_oem_per_frame_info TLV
   *  and the corresponding entries in the measMsgArr array */
  tagIdxInfo otherTagsPerFrameInfoTlv[2] =
  {
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info, 6},
    {WMIRTT_TLV_TAG_STRUC_loop_end, 7}
  };

  tagIdxInfo otherTagsARRAYUINT8InfoTlv[1] =
  {
    {WMIRTT_TLV_TAG_ARRAY_UINT8, 6}
  };
  /**
   * Array contains other expected tags for wmi_rtt_oem_per_peer_event_hdr TLV
   * and the corresponding entries in the measMsgArr array */
  tagIdxInfo otherTagsPerPeerEvtHdrTlv[2] =
  {
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info, 6},
    {WMIRTT_TLV_TAG_STRUC_loop_end, 8}
  };

  /**
   * Array contains other expected tags for "measurement" loop end TLV and the
   * corresponding entries in the measMsgArr array */
  tagIdxInfo otherTagsMeasLoopEndTlv[1] =
  {
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info, 6}
  };
  tagIdxInfo otherTagsCFRMeasLoopEndTlv[1] =
  {
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_frame_info, 5}
  };

  /**
   * Array contains other expected tags for "peer" loop end and the
   * corresponding entries in the measMsgArr array */
  tagIdxInfo otherTagsPeerLoopEndTlv[1] =
  {
    {WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_per_peer_event_hdr, 3},
  };

  /**
   * Retrieves the rome preamble given the RTT preamble type
   * @param preamble: rtt preamble
   * @return uint8: rome preamble
   */
  uint8 getPreamble(uint8 preamble) const;

  /**
   * Populates the control flag bits in the TLV
   * wmi_rtt_oem_measreq_peer_info. Used when filling out the
   * wmi_rtt_oem_measreq_peer_info TLV in an rtt measurements request.
   *
   * @param peerInfo: TLV struct to populate
   * @param bssidsToScan: peers to range with
   * @param ii: index to current TLV struct to populate
   */
  void setControlFlagBits(wmi_rtt_oem_measreq_peer_info &peerInfo,
                          DestInfo bssidsToScan, uint32 ii);

  /**
   * Populates the measure_info field in the TLV wmi_rtt_oem_measreq_peer_info.
   * Used when filling out the wmi_rtt_oem_measreq_peer_info TLV in an rtt
   * measurements request.
   *
   * @param peerInfo: TLV struct to be filled out
   * @param bssidsToScan: peer to scan
   * @param ii: index of the current TLV struct to populate
   * @param locVDevId: vDev type
   * @param reportType: report type for the response
   * @param timeoutPerTarget: time out to be waited by FW for each target
   */
  void setMeasInfoBits(wmi_rtt_oem_measreq_peer_info *peerInfo,
                       DestInfo bssidsToScan,
                       uint32 ii,
                       tANI_U8 locVDevType,
                       unsigned int reportType,
                       uint32 timeoutPerTarget);

  /**
   * Populates the measure_params_1 field in the TLV
   * wmi_rtt_oem_measreq_peer_info. Used when filling out the
   * wmi_rtt_oem_measreq_peer_info TLV in an rtt measurements request.
   *
   * @param peerInfo: TLV struct to be filled out
   * @param bssidsToScan: peer to scan
   * @param ii: index of the current TLV struct to populate
   */
  void setMeasParams1Bits(wmi_rtt_oem_measreq_peer_info *peerInfo,
                          DestInfo bssidsToScan, uint32 ii);

  /**
   * Uses the tag passed in to determine which LOWITlv needs to be created and
   * stores it in the vector passed in.  These TLVs will be used later during
   * parsing.
   *
   * @param tag: TLV tag
   * @param pMsg: pointer to where the TLV begins
   * @param arr: array containing the information about the TLV type being
   *           processed
   * @param idx: index into arr
   * @param tlvs: vector where the LOWITlv will be stored
   * @param lenFromFW: actual length of TLV sent by FW
   *
   * @return int: 0 if success, else failure
   */
  int generateLowiTlv(uint32 tag,
                      uint8 *pMsg,
                      measMsgInfo const *arr,
                      uint32 idx,
                      vector<LOWITlv *> &tlvs,
                      uint32 lenFromFW);
  /**
   * Verifies that the TLV tag passed in matches the expected tag(s) from the
   * common processing array arr.
   *
   * @param tag: TLV tag to verify
   * @param arr: common processing array
   * @param idx: index into the common processing array
   *
   *@return int: 0 if tag was verified. Else, failure, tag is invalid.
   */
  int  checkTlvTag(uint32 tag, measMsgInfo const *arr, uint8 &idx);

  /**
   * When a loop start TLV tag is encountered during common processing,
   * this function changes mPeerLs or mMeasLs variables to keep track of
   * whether a peer list is starting or a new rtt measurement is
   * starting.
   *
   * @param tag: TLV tag
   */
  void processIfLoopStartTag(uint32 tag);

  /**
   * When a loop end TLV tag is encountered during common processing,
   * this function changes mPeerLs or mMeasLs variables to keep track of
   * whether a peer list is ending or a new rtt measurement is ending.
   *
   * @param tag: TLV tag
   */
  void processIfLoopEndTag(uint32 tag);

  /**
   * When a wmi_rtt_oem_per_peer_event_hdr TLV tag is encountered during common
   * processing, this function starts the rtt measurement count for a peer and
   * increments the peer counter where the next peer can be stored.
   *
   * @param tag: TLV tag
   */
  void processIfPeerEvtHdrTag(uint32 tag);

  /**
   * When a wmi_rtt_oem_per_frame_info TLV tag is encountered during common
   * processing, this function increments the rtt measurement count for the
   * peer at the current mPeerIdx in the mPeerSet vector.
   *
   * @param tag: TLV tag
   */
  void processIfPerFrmInfoTag(uint32 tag);

  /** Prints information about the number of peers found in the rtt
   *  message response during common processing. Mainly: number of peers,
   *  index if a peer, and the number of rtt measurements per peer */
  void printBssidInfo();

  /**
   * Maps RTT target node type to FW wmi_rtt_vdev_type
   *
   * @param uint8 nodetype: RTT target nodetype
   * @return uint8 : mapped nodetype to FW wmi_rtt_vdev_type
   */
  uint8 mapLOWINodeTypeToFW(uint8 nodeType);

public:

  /** Constructor */
  LOWIWifiTlvHandler();

  /** Destructor */
  virtual ~LOWIWifiTlvHandler();

  /**
   * Returns the number of peers found during common processing of the rtt
   * message response TLVs
   *
   * @return uint8: number of peers
   */
  uint8 getNumPeers() const;

  /**
   * Clears the vector holding information about the number of peers and rtt
   * measurements found during common processing of the rtt message response
   * TLVs
   */
  void clearPeerSetInfo();

  /**
   * Returns the number of RTT measurements for a given peer in mPeerSet using
   * the index into the vector.
   *
   * @param idx: index of the peer which measurements the caller is inquiring
   *
   * @return uint8: number of rtt measurements for a given peer
   */
  uint8 getNumMeas(uint32 idx) const;

  /**
   * Verify that the wmi_rtt_oem_rsp_head TLV has the correct tag
   *
   * @param pHead: pointer to TLV wmi_rtt_oem_rsp_head
   * @param subtype: message subtype
   *
   * @return int: 0 if success, else failure
   */
  int verifyTlvRspHead(wmi_rtt_oem_rsp_head *pHead, WMIRTT_OEM_MSG_SUBTYPE *subtype);

  /**
   * Parses wmi_rtt_oem_rsp_head TLV
   *
   * @param msg: pointer to the TLV
   * @param rspInfo: struct where info will be passed to the caller
   * @param subType: OEM MSG subtype
   *
   * @return int: 0 if success, else failure
   */
  int processRspHeadTlv(uint8 *msg, rttRspInfo &rspInfo, uint8 &subType);

  /**
   * Process the TLVs in the message received from FW. Based on the subtype, it
   * chooses the correct function to do the common processing.
   *
   * @param msg: message from FW
   * @param tlvs:vector where TLVs will be placed
   * @param subtype: message subtype
   *
   * @return int: 0 if success, else failure
   */
  int  processTLVs(uint8* msg,
                   vector<LOWITlv *> &tlvs,
                   uint8 subtype, uint32 reportType);

  /**
   * Common processing function for the TLVs of subtype:
   *   RTT_MSG_SUBTYPE_CAPABILITY_RSP
   *   RTT_MSG_SUBTYPE_ERROR_REPORT_RSP
   *   RTT_MSG_SUBTYPE_MEASUREMENT_RSP
   *
   * This function uses the array "msgArr" to do the processing. This array
   * will be specific to the msg subtype to be processed. It checks for
   * correct tags, proper order and fragmentation information. If all good,
   * it stores the TLVs for parsing.
   *
   * @param msg: message from FW
   * @param msgArr: array used for common processing
   * @param tlvs: vector where TLVs will be placed
   *
   * @return int: 0 if success, else failure
   */
  int processCommonTlvs(uint8 *msg, measMsgInfo const *msgArr, vector<LOWITlv *> &tlvs);

  /**
   * Removes all TLVs from the list and frees memory
   * @param tlvs:  vector of TLVs to clean up
   */
  void cleanupTlvs(vector<LOWITlv *> &tlvs);

  /**
   * This function is used when creating an rtt measurements request. It fills
   * out the TLV struct for the wmi_rtt_oem_req_head TLV at the point given by
   * the argument msg. The function then returns the size of the TLV structure
   * wmi_rtt_oem_req_head which will be used to find the placement point of the
   * next TLV in the request message.
   *
   * @param msg: point into the caller's buffer where the TLV will be placed
   * @param reqId: request id filled into the TLV
   *
   * @return uint32: sizeof(wmi_rtt_oem_req_head)
   */
  uint32 setReqHeadTlv(char *msg, A_UINT32 reqId, A_UINT32 pdev_id);

  /**
   * This function is used when creating an rtt measurements request. It fills
   * out the TLV struct for the wmi_rtt_oem_measreq_head TLV at the point given
   * by the argument msg. The function then returns the size of the TLV
   * structure wmi_rtt_oem_measreq_head which will be used to find the placement
   * point of the next TLV in the request message.
   *
   * @param msg: point into the caller's buffer where the TLV will be placed
   * @param channelCnt: number of channels in the request
   *
   * @return uint32: sizeof(wmi_rtt_oem_measreq_head)
   */
  uint32 setMeasReqHeadTlv(char *msg, A_UINT32 channelCnt);

  /**
   * This function is used when creating an rtt measurements request. It fills
   * out the TLV struct for the wmi_rtt_oem_channel_info TLV at the point given
   * by the argument msg. The function then returns the size of the TLV
   * structure wmi_rtt_oem_channel_info which will be used to find the placement
   * point of the next TLV in the request message.
   *
   * @param msg: point into the caller's buffer where the TLV will be placed
   * @param pChanInfo: channel information to be filled into the TLV
   *
   * @return uint32: sizeof(wmi_rtt_oem_channel_info)
   */
  uint32 setChannelInfoTlv(char *msg, wmi_channel &pChanInfo);

  /**
   *
   *
   * @param msg: point into the caller's buffer where the TLV will be placed
   * @param numSTA
   *
   * @return uint32: sizeof(wmi_rtt_oem_measreq_per_channel_info)
   */
  uint32 setPerChannelInfoTlv(char *msg, A_UINT32 numSTA);

  /**
   * This function is used when creating an rtt measurements request. It fills
   * out the TLV struct for the wmi_rtt_oem_measreq_peer_info TLV at the point
   * given by the argument msg. The function then returns the size of the TLV
   * structure wmi_rtt_oem_measreq_peer_info which will be used to find the
   * placement point of the next TLV in the request message.
   *
   * @param msg: point into the caller's buffer where the TLV will be placed
   * @param bssidsToScan:  peer information used to fill out the TLV
   * @param numBSSIDs: number of peers on this channel
   * @param rprtType: report type for the response
   * @param spoofBssids: spoof peer information used to fill out the TLV
   * @param timeoutPerTarget: max time to spend getting the rtt measurements
   *                        for a peer on this channel.
   *
   * @return uint32: sizeof(wmi_rtt_oem_measreq_peer_info)
   */
  uint32 setPeerInfoTlv(char *msg, DestInfo *bssidsToScan, uint32 numBSSIDs,
                        unsigned int rprtType, DestInfo *spoofBssids, uint32 timeoutPerTarget);

  /**
   * This function is used when creating an rtt measurements request. It fills
   * out the TLV header for the loop_start TLV at the point given by the
   * argument msg. The function then returns the size of the TLV header which
   * will be used to find the placement point of the next TLV in the request
   * message.
   *
   * @param msg: point into the caller's buffer where the TLV will be placed
   *
   * @return uint32: RTT_TLV_HDR_SIZE
   */
  uint32 setLoopStartTlv(char *msg);

  /**
   * This function is used when creating an rtt measurements request. It fills
   * out the TLV header for the loop_end TLV at the point given by the argument
   * msg. The function then returns the size of the TLV header which will be
   * used to find the placement point of the next TLV in the request message.
   *
   * @param msg: point into the caller's buffer where the TLV will be placed
   *
   * @return uint32: RTT_TLV_HDR_SIZE
   */
  uint32 setLoopEndTlv(char *msg);
};

}
#endif // __LOWI_WIFI_TLV_HANDLER_H__

