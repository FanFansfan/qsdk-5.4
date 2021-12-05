#ifndef __LOWI_HELIUM_RANGING_H__
#define __LOWI_HELIUM_RANGING_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Ranging for Helium driver

GENERAL DESCRIPTION
  This file contains the class LOWIHeliumRanging which was derived from
  LOWIRanging.

  Copyright (c) 2016,2018-2019  Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc

=============================================================================*/
#include <base_util/list.h>
#include <common/lowi_utils.h>
#include <inc/lowi_scan_measurement.h>
#include "lowi_ranging.h"
#include "lowi_p2p_ranging.h"

namespace qc_loc_fw
{

class LOWIWifiTlvHandler;
class LOWITlv;
class LOWIFragInfo;

/** Subclass of LOWIRanging specific for the Helium Driver. It handles all
 *  the parsing of the message coming from FW */
class LOWIHeliumRanging : public LOWIRanging
{
private:
  /** Object used to process the TLVs  */
  LOWIWifiTlvHandler *mTlvHandler;

  /** Reservoir of fragments. Fragments are stored in
   *  this list until they are ready to be processed
   *  as a single message. Each fragment that belongs
   *  to the same message, has the same token id.
   *  Hence, all fragments with the same token id are
   *  stored in the same list element.
   */
  List<LOWIFragInfo *> mFragInfoList;

  /**
   * Stores a fw message fragment for later processsing
   *
   * @param rspInfo: fragment information
   * @param pMsg: ptr to fragment
   * @return int: 0 if success, else failure
   */
  int storeFragment(rttRspInfo const &rspInfo, uint8* pMsg);

  /**
   * Determines if fragments for the given tokenId have already been stored
   *
   * @param tokenId: token id from FW identifying a set of messages
   * @return int: 0 if fragments have already been stored for this token id,
   *         non-zero otherwise.
   *
   */
  int hasFragsForTokenId(uint32 tokenId);

  /**
   * Stores an information element (IE)
   *
   * @param uint8*: IE's data
   * @param LOWIRangingScanMeasurement*: scan measurement
   *                          container where IE will be stored
   *                          and passed to caller
   * @return int: 0 if success, else failure
   */
  int storeIE(uint8 *pIEData, LOWIRangingScanMeasurement *rangingMeasurement);

  /**
   * Alloc memory for the entire ani message and fill out the ani message header
   * @param aniMsg: msg length
   * @param aniHdrLen: ANI header length
   * @param aniMetaLen: ANI meta data length
   * @param aniInterfaceLen: Interface length
   * @return char *: ptr to ANI Msg
   */
  char * allocAniMsgHdr(uint32 aniMsgLen, uint32 aniHdrLen, uint32 aniMetaLen, uint32 aniInterfaceLen);

public:
  /**
   * Create Ranging Capabilities request and send to FW. The message going to the host (ani
   * message) is composed of a message header and a message body. The TLVs going to the FW
   * form the ani message body:
   * msg Hdr: |aniMsgType  |AniMsgLen    |
   * TLV    : |wmi_rtt_oem_req_head      |
   * TLV    : |wmi_rtt_oem_cap_req_head  |
   * TLV    : |wmi_rtt_oem_cap_rsp_event |
   *
   * @param: none
   * @return int: 0 if success, else failure
   */
  virtual int RomeSendRangingCapReq(std::string interface);

  /**
   * Sends RTT measurments request to driver
   *
   * @param reqId: request identification
   * @param chanInfo: channel id of target devices
   * @param numBSSIDs: number of target devices in this request
   * @param bssidsToScan: DestInfo Array of target devices and RTT Type
   * @param spoofBssids: DestInfo Array of Spoof peers and RTT Type
   * @param reportType: report type to be used by FW for the response
   * @return int: 0 if success, else failure
   */
  virtual int RomeSendRttReq(uint16 reqId,
                     ChannelInfo  chanInfo,
                     unsigned int numBSSIDs,
                     DestInfo bssidsToScan[MAX_BSSIDS_TO_SCAN],
                     DestInfo spoofBssids[MAX_BSSIDS_TO_SCAN],
                     unsigned int reportType,
                     std::string interface);

  /**
   * This function constructs the LCI configuration message and sends it to FW.
   *
   * @param reqId: request identification for this request
   * @param request: the LCI configuration request and parameters
   * @return int: 0 if success, else failure
   */
  virtual int RomeSendLCIConfiguration(tANI_U16 reqId, LOWISetLCILocationInformation *request);

  /**
   * This function constructs the LCI configuration message and sends it to FW.
   *
   * @param reqId: request identification for this request
   * @param request: the LCI configuration request and parameters
   * @return int: 0 if success, else failure
   */
  virtual int RomeSendLCRConfiguration(tANI_U16 reqId, LOWISetLCRLocationInformation *request);

  /**
   * This function receives the FW message, extracts the OEM subtype so that the
   * FSM can process it.
   *
   * @param msgType: OEM subtype of message received
   * @param data: message body
   * @param maxDataLen: length of message (bytes)
   * @return int: 0 if success, else failure
   */
  virtual int RomeNLRecvMessage(RomeNlMsgType *msgType, void *data, tANI_U32 maxDataLen);

  /**
   * Extract information from ranging capability message
   *
   * @param data: message body
   * @param pRomeRttCapabilities: structure in which capabilities will be passed
   *                            to the caller
   * @return int: 0 if success, else failure
   */
  virtual int RomeExtractRangingCap(void *data, RomeRttCapabilities *pRomeRttCapabilities);

  /**
   * Extract error code from ranging error message
   *
   * @param data: message body
   * @param errorCode: variable where error code will be passed to the caller
   * @param bssid: variable where bssid will be passed to the caller
   * @return int: 0 if success, else failure
   */
  virtual int RomeExtractRangingError(void *data, tANI_U32 *errorCode, tANI_U8 *bssid);

  /**
   * Parses the ranging measurements message from FW
   *
   * @param measResp: pointer to message
   * @param scanMeasurements: where parsed measurements will be stored
   * @param lastMeas: indicates whether this is the last measurement. Used as an
   *                indicator for the FSM to change states. (at least for now)
   * @return int: 0 if success, else failure
   */
  virtual int RomeParseRangingMeas(char *measResp,
                           vector<LOWIScanMeasurement *> *scanMeasurements,
                           bool &lastMeas, unsigned int reportType);
  /**
   * Parses the responder channel info measurement from FW
   *
   * @param measResp: pointer to message
   * @param channelresponse: where parsed measurements will be stored
   * @return int: 0 if success, else failure
   */
  virtual int ParseResponderChannelMeas(char* measResp, LOWIRMChannelResponse* channelresponse);

  /**
   * Parses and process the TLV format of channel info received from FW.
   *
   * @param tlvs: pointer to tlv message
   * @param channelresponse: where parsed measurements will be stored
   * @return int: 0 if success, else failure
   */
  int ParseResponderChannelInfoMsg(vector<LOWITlv *> &tlvs, LOWIRMChannelResponse &channelresponse);
  /**
   * Validates ANI type coming in message from HD
   *
   * @param aniMsgType: ANI type to check
   * @return bool: true if ANI is valid
   */
  bool isAniMsgValid(uint8 aniMsgType);

  /**
   * Validates OEM subtype coming in message from FW
   *
   * @param subType: subtype to check
   * @return bool: true if OEM subtype is valid
   */
  bool isRttMsgSubTypeValid(uint8 subType);

  /**
   * Maps ANI type to Rome NL msg type
   *
   * @param aniMsgType: ANI type to be matched
   * @return RomeNlMsgType: Rome NL msg type
   */
  RomeNlMsgType mapAniToRomeMsg(uint8 aniMsgType);

  /**
   * Parses the rtt capabilities message coming from FW
   *
   * @param tlvs: LOWITlvs to be parsed
   * @param caps: struct where capabilities will be passed to the caller
   */
  void parseRttCapabilitiesMsg(vector<LOWITlv *> &tlvs, RomeRttCapabilities &caps);

  /**
   * Parses the rtt error message coming from FW
   *
   * @param tlvs: LOWITlvs to be parsed
   * @param errRprtInfo: struct where error info will be passed to the caller
   * @param errCode: error code extracted from the message
   * @return int: 0 if success, else failure
   */
  int parseErrRprt(vector<LOWITlv *> &tlvs, rttMeasRspHead &errRprtInfo, uint32 &errCode);
  /**
   * Process the rtt measurements response coming from FW
   * @param rttMeasType: Measurement frame type
   * @param numMeasThisAP: No of measurements this peer has
   * @param tlvs: LOWITlvs to be parsed
   * @param nextTlv: next tlv num
   * @param measurementInfo: Measurement info buffer pointer
   *
   * @return int: 0 if success, else failure
   */

  int processPerFrameInfo(uint8 rttMeasType, int numMeasThisAP, vector<LOWITlv *> &tlvs,
                          uint32 &nextTlv, LOWIMeasurementInfo *measurementInfo);

  /**
   * Parses the rtt measurements response coming from FW
   *
   * @param tlvs: LOWITlvs to be parsed
   * @param scanMeasurements: where measurements will be stored for the caller
   *
   * @return int: 0 if success, else failure
   */
  int parseMeasRspMsg(vector<LOWITlv *> &tlvs,
                      vector <LOWIScanMeasurement*> *scanMeasurements);

  /**
   * Prints the information in the wmi_rtt_oem_per_peer_event_hdr TLV
   *
   * @param perPeerInfo: extracted peer information to be printed
   * @param pTlv: TLV fields to be printed
   */
  void printPerPeerInfo(rttPerPeerInfo const &perPeerInfo, LOWITlv *pTlv);

  /**
   * Prints the information in the wmi_rtt_oem_per_frame_info TLV
   *
   * @param perFrmInfo: extracted frame information to be printed
   * @param pTlv: TLV fields to be printed
   */
  void printPerFrameInfo(rttPerFrameInfo const &perFrmInfo, LOWITlv *pTlv);

  /**
   * Transfers TxRx measurements from extracted container into container for the
   * caller
   *
   * @param measurementInfo: caller container where measurements will be placed
   * @param perFrmInfo: extracted measurements
   */
  void getTxRxMeasurements(LOWIMeasurementInfo *measurementInfo, rttPerFrameInfo const &perFrmInfo);

  /**
   * Assigns the correct code error for the caller based on what was received
   * from FW
   *
   * @param bssid: destination bssid
   * @param rangingMeasurement: caller container
   * @param invalidTimeStamp: whether timestamp is valid
   */
  void assignErrCode(tANI_U8  bssid[ETH_ALEN_PLUS_2],
                     LOWIRangingScanMeasurement *rangingMeasurement,
                     bool invalidTimeStamp);

  /**
   * Print rtt measurement information received from FW in
   * wmi_rtt_oem_measrsp_head TLV
   *
   * @param pTlv: TLV fields to be printed
   * @param headInfo: extracted information to be printed
   */
  void printMeasRspHeadInfo(LOWITlv *pTlv, rttMeasRspHead const &headInfo);

  /**
   * Transfers Measure response information extracted from FW msg into caller's container
   *
   * @param rangingMeasurement: caller's container
   * @param rttMeasRspHead: measure resp information extracted from message
   */

  void  transferMeasureRspInfo(LOWIRangingScanMeasurement *rangingMeasurement,
                               rttMeasRspHead &measRspHead);
  /**
   * Transfers peer information extracted from FW msg into caller's container
   *
   * @param rangingMeasurement: caller's container
   * @param perPeerInfo: peer information extracted from message
   * @param channel: peer channel extracted from message
   */
  void transferPeerInfo(LOWIRangingScanMeasurement *rangingMeasurement,
                        rttPerPeerInfo &perPeerInfo, uint32 channel);

  /**
   * This function parses a message from FW that was received in multiple
   * fragments after all the fragments have been received.
   *
   * @param tokenId: token id of message to be parsed
   * @param scanMeasurements: caller container where measurements will be placed
   * @param subtype: OEM message subtype
   * @return int: 0 if success, else failure
   */
  int parseFragmentedMsg(uint32 tokenId, vector<LOWIScanMeasurement *> *scanMeasurements,
                         uint8 &subtype, uint32 reportType);
  /**
   * This function will send the rtt available channel request to FW.
   *
   * @param none
   * @return int: 0 if success, else failure
   */
  virtual int SendRTTAvailableChannelReq();
  /**
   * This function will send the enable responder request to FW.
   *
   * @param int8   : channel width
   *        uint32 : duration in seconds for which responder should be enabled
   *        int32  : primary freq
   *        int32  : center freq 0
   *        int32  : center freq 1
   *        uint32 : reg info 1
   *        uint32 : reg info 2
   *        uint32 : Phy mode
   * @return int: 0 if success, else failure
   */
  virtual int SendEnableResponderReq(int8, uint32, int32, int32, int32, uint32, uint32, uint32);
  /**
   * This function will send the disable responder request to FW.
   *
   * @param none
   * @return int: 0 if success, else failure
   */
  /** defines for the chain number and its mask */
  #define CHAIN_0_MASK (0x0001)
  #define CHAIN_1_MASK (0x0002)
  enum CHAIN_NUM {
     CHAIN_NUM_INVALID = -1,
     CHAIN_NUM_0 = 0,
     CHAIN_NUM_1 = 1,
  };

  /* Get TX/RX chain number from chain sent by fwr */
  int8 getChainNum(uint32 chain_num_mask) const
  {
     if (chain_num_mask & CHAIN_0_MASK)
        return CHAIN_NUM_0;
     else if (chain_num_mask & CHAIN_1_MASK)
        return CHAIN_NUM_1;
     else
        return CHAIN_NUM_INVALID;
  }
  virtual int SendDisableResponderReq();
  virtual int SendResponderMeasurementConfigReq(uint8 ,uint8);
  virtual int SendResponderMeasurementStartReq(uint8);
  virtual int SendResponderMeasurementStopReq();
  /** Constructor */
  LOWIHeliumRanging();

  /** Destructor */
  virtual ~LOWIHeliumRanging();
};
} // namespace qc_loc_fw
#endif // __LOWI_HELIUM_RANGING_H__

