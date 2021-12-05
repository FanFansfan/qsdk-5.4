/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI TLV class header file

GENERAL DESCRIPTION
  This file contains the interface for a LOWI TLV

  Copyright (c) 2016, 2018-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_TLV_H__
#define __LOWI_TLV_H__

#include <inc/lowi_const.h>
#include "rtt_oem_interface.h"
#include "wlan_capabilities.h"
#include "lowi_dynamic_buffer.h"

/* msg strings used for printing/debugging LOWITlv type */
extern const char *LOWI_TLV_TYPE[10];

namespace qc_loc_fw
{

// invalid value for meas_start_tsf field found in
// tlv "wmi_rtt_oem_per_peer_event_hdr"
uint32 const LOWI_INVALID_MEAS_START_TSF = 1;

/** LOWITlv
 *  Class representing a TLV
 */
class LOWITlv
{
private:
  /** Constructor */
  LOWITlv();
protected:
  /** Holds the TLV tag */
  uint32 mTag;
  /** Holds the TLV length */
  uint32 mLen;
  /** Holds the entire TLV */
  uint8 *mTlv;

public:
  /** Log Tag */
  static char const *const TAG;

  /** LOWI TLV types */
  enum eTlvType
  {
    /** Base class LOWITlv type */
    LOWITLV_BASE = 0,
    /** Represents the wmi_rtt_oem_rsp_head TLV */
    LOWITLV_RSP_HEAD,
    /**  Represents the wmi_rtt_oem_cap_rsp_head TLV */
    LOWITLV_CAP_RSP_HEAD,
    /** Represents the wmi_rtt_oem_cap_rsp_event TLV */
    LOWITLV_CAP_RSP_EVENT,
    /** Represents the wmi_rtt_oem_measrsp_head TLV  */
    LOWITLV_MEASRSP_HEAD,
    /** Represents the wmi_rtt_oem_per_peer_event_hdr TLV */
    LOWITLV_PER_PEER_EVENT_HDR,
    /** Represents the wmi_rtt_oem_per_frame_info TLV */
    LOWITLV_PER_FRAME_INFO,
    /** Represents the wmi_rtt_oem_get_channel_info_rsp_head TLV */
    LOWITLV_CHANNELRESP_HEAD,
    /** Represents the wmi_rtt_oem_set_responder_mode_rsp_head TLV */
    LOWITLV_RESPONDERRESP_HEAD,
    /** Represents the WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info TLV */
    LOWITLV_CHANNELINFO_HEAD,
   /** Represents the WMIRTT_TLV_TAG_ARRAY_UINT8 */
    LOWITLV_ARRAY_UINT8
  };

  /** Constructor */
  LOWITlv(uint8* pTlv, uint32 len);
  /** Copy Constructor */
  LOWITlv(const LOWITlv &rhs);
  /** Assignment operator */
  LOWITlv& operator=(const LOWITlv &rhs);
  /** Destructor */
  virtual ~LOWITlv();
  /** return the TLV tag */
  uint32 getTag() const
  {
      return mTag;
  }
  /** return the TLV length */
  uint32 getLength() const
  {
      return mLen;
  }
  /** returns a ptr to the entire TLV */
  uint8* getTlv() const
  {
      return mTlv;
  }

  /**
   * Returns the LOWI TLV type
   * @return eTlvType type of LOWI TLV
   */
  virtual eTlvType getTlvType () const
  {
    return LOWITLV_BASE;
  }
};

/** LOWITlvRspHead
 *  Class representing the wmi_rtt_oem_rsp_head TLV
 */
class LOWITlvRspHead : public LOWITlv
{
private:
  /** rtt message subtype field */
  uint8  mRttMsgSubType;
  /** rtt request id field */
  uint32 mReqId;
  /** fragmentation information field */
  uint32 mFragField;

public:
  /** Constructor */
  LOWITlvRspHead(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWITlvRspHead();
  /** returns the fragment information as a struct */
  void getFragmentInfo(rttFragmentInfo & fragInfo) const;
  /** return the WMIRTT_OEM_MSG_SUBTYPE */
  uint8 getSubType() const
  {
    return WMI_RTT_SUB_TYPE_GET(mRttMsgSubType);
  }
  /** return the request id */
  uint32 getReqId() const
  {
    return WMI_RTT_REQ_ID_GET(mReqId);
  }
  /** return the RTT status indicator */
  uint8 getRttStatus() const
  {
    return WMI_RTT_RSP_STATUS_GET(mReqId);
  }
  /** return RTT request fully serviced bit */
  uint8 getRttMeasDone() const
  {
    return WMI_RTT_RSP_DONE_GET(mReqId);
  }
  /** return the fragment_info field */
  uint32 getFragmentField() const
  {
    return (mFragField);
  }
  /** return whether is TLV is a partial measurement */
  bool isFragment()
  {
    return (WMI_RTT_RSP_MORE_FRAG_GET(mFragField) == 0 ? false : true);
  }

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_RSP_HEAD;
  }
};

/** LOWICapRspHeadTlv
 *  Class representing the wmi_rtt_oem_cap_rsp_head TLV
 */
class LOWICapRspHeadTlv : public LOWITlv
{
private:
  /** RTT version field */
  uint32 version;
  /** RTT revision   */
  uint32 revision;
  /** service bit mask indicates features supported by FW */
  uint32 serviceBitMask[RTT_SERVICE_BITMASK_SZ];

public:
  /** Constructor */
  LOWICapRspHeadTlv(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWICapRspHeadTlv();

  /** return the version field */
  uint32 getVersion() const
  {
    return version;
  }
  /** return the RTT major version */
  uint32 getVersionMajor() const
  {
    return RTT_VER_GET_MAJOR(version);
  }
  /** return the RTT minor version */
  uint32 getVersionMinor() const
  {
    return RTT_VER_GET_MINOR(version);
  }
  /** return the RTT revision */
  uint32 getRttRevision() const
  {
    return revision;
  }
  /** return the service bit mask */
  uint32* getServiceBitMask()
  {
    return serviceBitMask;
  }

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_CAP_RSP_HEAD;
  }
};

/** LOWIOemChannelRspHeadTlv
 *  Class representing the wmi_rtt_oem_get_channel_info_rsp_head TLV
 */
class LOWIOemChannelRspHeadTlv : public LOWITlv
{
private:
  /** RTT version field */
  uint32 version;
  /** RTT revision   */
  uint32 revision;

public:
  /** Constructor */
  LOWIOemChannelRspHeadTlv(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWIOemChannelRspHeadTlv()
  {
  }
  /** return the version field */
  uint32 getVersion() const
  {
    return version;
  }
  /** return the RTT major version */
  uint32 getVersionMajor() const
  {
    return RTT_VER_GET_MAJOR(version);
  }
  /** return the RTT minor version */
  uint32 getVersionMinor() const
  {
    return RTT_VER_GET_MINOR(version);
  }
  /** return the RTT revision */
  uint32 getRttRevision() const
  {
    return revision;
  }

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_CHANNELRESP_HEAD;
  }
};
/** LOWIResponderRspHeadTlv
 *  Class representing the wmi_rtt_oem_set_responder_mode_rsp_head TLV
 */
class LOWIResponderRspHeadTlv : public LOWITlv
{
private:
  /** RTT version field */
  uint32 version;
  /** RTT revision   */
  uint32 revision;

public:
  /** Constructor */
  LOWIResponderRspHeadTlv(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWIResponderRspHeadTlv();

  /** return the version field */
  uint32 getVersion() const
  {
    return version;
  }
  /** return the RTT major version */
  uint32 getVersionMajor() const
  {
    return RTT_VER_GET_MAJOR(version);
  }
  /** return the RTT minor version */
  uint32 getVersionMinor() const
  {
    return RTT_VER_GET_MINOR(version);
  }
  /** return the RTT revision */
  uint32 getRttRevision() const
  {
    return revision;
  }

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_RESPONDERRESP_HEAD;
  }
};
/** LOWIchannelRspHeadTlv
 *  Class representing the WMIRTT_TLV_TAG_STRUC_wmi_rtt_oem_channel_info TLV
 */
class LOWIChannelRspHeadTlv : public LOWITlv
{
  private:
    /** primary channel frequency */
    uint32 mMhz;
    /** center frequency 1   */
    uint32 mCenterFreq1;
    /** center frequency 2   */
    uint32 mCenterFreq2;
    /** channel info   */
    uint32 mInfo;
    /** contains min power, max power, reg power and reg class id.   */
    uint32 mRegInfo1;
    /** contains antennamax */
    uint32 mRegInfo2;

  public:
    /** Constructor */
    LOWIChannelRspHeadTlv(uint8* pTlv, uint32 len);
    /** Destructor */
    ~LOWIChannelRspHeadTlv()
    {
    }
    /** return the Mhz field */
    uint32 getMhz() const
    {
      return mMhz;
    }
    /** return the Center freq 1 */
    uint32 getCenterFreq1() const
    {
      return mCenterFreq1;
    }
    /** return the Center freq 2 */
    uint32 getCenterFreq2() const
    {
      return mCenterFreq2;
    }
    /** return the channel Info */
    uint32 getInfo() const
    {
      return mInfo;
    }
    /** return the reg Info 1 */
    uint32 getRegInfo1() const
    {
      return mRegInfo1;
    }
    /** return the reg Info 2 */
    uint32 getRegInfo2() const
    {
      return mRegInfo1;
    }

    LOWITlv::eTlvType getTlvType() const
    {
      return LOWITLV_CHANNELINFO_HEAD;
    }
};
/** LOWICapRspEventTlv
 *  Class representing the wmi_rtt_oem_cap_rsp_event TLV
 */
class LOWICapRspEventTlv : public LOWITlv
{
private:
  /** support TLV field */
  A_UINT32 mSupport;
  /** cap TLV field */
  A_UINT32 mCap;
  /** cap_2 TLV field */
  A_UINT32 mCap2;

public:
  /** Constructor */
  LOWICapRspEventTlv(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWICapRspEventTlv();
  /** return RTT capabilities in one convenient form */
  void getRttCaps(RomeRttCapabilities & caps) const;
  /** return support field */
  uint32 getSupport() const
  {
    return mSupport;
  }
  /** return cap field */
  uint32 getCap() const
  {
    return mCap;
  }
  /** return cap_2 field */
  uint32 getCap2() const
  {
    return mCap2;
  }

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_CAP_RSP_EVENT;
  }
};

/** LOWIMeasRspHeadTlv
 *  Class representing the wmi_rtt_oem_measrsp_head TLV
 */
class LOWIMeasRspHeadTlv : public LOWITlv
{
private:
  /** Information field
   *  bit 8:0: Report type (0,1,2,3)
   *  bit 9: Measurement Finished 1 / Measurement not Finished 0 (valid for report type 0, 1, 3) (for entire request)
   *  bit 14:10 RTT measurement Type 000 - NULL 001-QoS_NULL 002 -TMR (valid for report type 0, 1)(report type 2,3
   *    ignore)
   *  bit 17:15 V3 report status (v2 ignore) (report type 2,3 ignore) 00-Good 01 - Bad CFR 10 -- bad token
   *  bit 18:   V3 accomplishment (v2 ignore) (report type 2,3 ignore)
   *    0 - sending side is not finishing
   *    1 - sending side finish
   *  bit 19: V3 start of a TM sequence (v2 ignore) (report type 2,3 ignore)
   *    0 - not a start frame  1 -- start frame
   *  bit 23:20: #of AP inside this report (valid for report type 2,3; 0,1 ignore) bit 31:24: reserved
   */
  uint32 mInfo;
  /** Peer mac address. Valid for report type 0 and 1. Valid also for
   *  error_report subtype irrespective of report_type */
  wmi_mac_addr mDestMac;
  /** Frequency of the peer. Valid for report type 2 and 3. Not valid for
   *  error_report subtype */
  uint32 mChannel;

public:
  /** Constructor */
  LOWIMeasRspHeadTlv(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWIMeasRspHeadTlv();
  /** return the mInfo field */
  uint32 getInfoField() const
  {
    return mInfo;
  }
  /** return the peer mac address */
  uint8 * getDestMac()
  {
    return mDestMac;
  }
  /** return the channel frequency */
  uint32 getChannel() const
  {
    return mChannel;
  }
  /** parses the wmi_rtt_oem_measrsp_head TLV */
  void getMeasRspHead(rttMeasRspHead &rspHeadInfo) const;
  /** return the report type */
  uint8 getRprtType() const
  {
    return WMI_RTT_REPORT_REPORT_TYPE_GET(mInfo);
  }
  /** return the number of peers in the response */
  uint8 getNumAPs() const
  {
    return WMI_RTT_REPORT_NUM_AP_GET(mInfo);
  }
  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_MEASRSP_HEAD;
  }
};

/** LOWIPerPeerEventHdrTlv
 *  Class representing the wmi_rtt_oem_per_peer_event_hdr TLV
 */
class LOWIPerPeerEventHdrTlv : public LOWITlv
{
private:
  /** mac address for the peer */
  wmi_mac_addr mPeerMac;
  /** control field in the TLV */
  uint32 mControl;
  /** result_info1 field in the TLV */
  uint32 mResultInfo1;
  /** result_info2 field in the TLV */
  uint32 mResultInfo2;
  /** result_info3 field in the TLV */
  uint32 mResultInfo3;
  /** TSF measurement timestamp */
  uint32 mMeasStartTSF;

public:
  /** Constructor */
  LOWIPerPeerEventHdrTlv(uint8* pTlv, uint32 len, uint32 lenFromFW);
  /** Destructor */
  ~LOWIPerPeerEventHdrTlv();

  /** get per peer information */
  void getPerPeerInfo(rttPerPeerInfo & peerInfo) const;

  /** return the peer mac address */
  uint8 * getPeerMac()
  {
    return mPeerMac;
  }
  /** return the number of measurements for this AP */
  uint8 getNumMeasRprts() const
  {
    return WMI_RTT_REPORT_TYPE2_NUM_MEAS_GET(mControl);
  }
  /** return the RTT measurement type */
  uint8 getRttMeasType() const
  {
    return WMI_RTT_REPORT_TYPE2_MEAS_TYPE_GET(mControl);
  }
  /** return true if peer is a Qualcomm peer */
  bool isQtiPeerType() const
  {
    return ((WMI_RTT_REPORT_TYPE2_QTI_PEER_GET(mControl)) ? true : false);
  }
  /** return the number of frames attempted */
  uint32 getMeasFramesAttempted() const
  {
    return WMI_RTT_REPORT_TYPE2_NUM_FRAMES_ATTEMPTED_GET(mResultInfo1);
  }
  /** return the actual burst duration used during the measurements */
  uint32 getActualBurstDur() const
  {
    return WMI_RTT_REPORT_TYPE2_ACT_BURST_DUR_GET(mResultInfo1);
  }
  /** return the actual number fo frames per burst */
  uint8 getActualNumFramesPerBurst() const
  {
    return WMI_RTT_REPORT_TYPE2_NEGOT_NUM_FRAMES_PER_BURST_GET(mResultInfo2);
  }
  /** return the retry after duration field */
  uint8 getRetryAfterDur() const
  {
    return WMI_RTT_REPORT_TYPE2_RETRY_AFTER_DUR_GET(mResultInfo2);
  }
  /** return the actual burst exponent used for the measurements */
  uint8 getActualBurstExp() const
  {
    return WMI_RTT_REPORT_TYPE2_ACT_BURST_EXP_GET(mResultInfo2);
  }
  /** return the number of IEs included in the header */
  uint8 getNumIEsInHdr() const
  {
    return WMI_RTT_REPORT_TYPE2_NUM_IES_GET(mResultInfo2);
  }
  /** return the current burst index */
  uint8 getBurstIdx() const // valid for report type 3 only
  {
    return WMI_RTT_REPORT_BUR_IDX_GET(mResultInfo3);
  }
  /** return the TSF */
  uint32 getTSF() const
  {
    uint32 tsf = (mMeasStartTSF == LOWI_INVALID_MEAS_START_TSF) ?
                                   LOWI_INVALID_MEAS_START_TSF  :
                                   WMI_RTT_REPORT_TSF_GET(mMeasStartTSF);
    return tsf;
  }
  /** return the control field from the TLV */
  uint32 getControl() const
  {
    return mControl;
  }
  /** return the result_info_1 field from the TLV */
  uint32 getResultInfo1() const
  {
    return mResultInfo1;
  }
  /** return the result_info_2 field from the TLV */
  uint32 getResultInfo2() const
  {
    return mResultInfo2;
  }
  /** return the result_info_3 field from the TLV */
  uint32 getResultInfo3() const
  {
    return mResultInfo3;
  }
  /** return the tsf field from the TLV */
  uint32 getTsfField() const
  {
    return mMeasStartTSF;
  }

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_PER_PEER_EVENT_HDR;
  }
};

/** LOWIPerFrameInfoTlv
 *  Class representing the wmi_rtt_oem_per_frame_info TLV
 */
class LOWIPerFrameInfoTlv : public LOWITlv
{
private:
  /** raw rssi measurement */
  uint32 mRssi;
  /** TOD: resolution picoseconds */
  A_TIME64 mT1;
  /** timestamp, resolution picoseconds; valid for v3 only */
  A_TIME64 mT2;
  /** timestamp diff: t3-t2 for V3, resolution picoseconds; valid for v3 only */
  uint32 mT3Del;
  /** timestamp diff: toa - tod for V2; t4-t1 for V3; resolution picoseconds */
  uint32 mT4Del;
  /** tx_rate_info_1 field in the TLV */
  uint32 mTxRateInfo1;
  /** tx_rate_info_2 field in the TLV */
  uint32 mTxRateInfo2;
  /** rx_rate_info_1 field in the TLV */
  uint32 mRxRateInfo1;
  /** rx_rate_info_2 field in the TLV */
  uint32 mRxRateInfo2;
  /** max timing error */
  uint32 mMaxTodToaErr;

public:
  /** Constructor */
  LOWIPerFrameInfoTlv(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWIPerFrameInfoTlv();
  /** parses the per-frame-info and returns it as a struct */
  void parsePerFrameInfo(rttPerFrameInfo & perPeerInfo) const;

  /** return tx_rate_info1 field */
  uint32 getTxRateInfo1() const
  {
    return mTxRateInfo1;
  }
  /** return tx_rate_info2 field */
  uint32 getTxRateInfo2() const
  {
    return mTxRateInfo2;
  }
  /** return rx_rate_info1 field */
  uint32 getRxRateInfo1() const
  {
    return mRxRateInfo1;
  }
  /** return rx_rate_info2 field */
  uint32 getRxRateInfo2() const
  {
    return mRxRateInfo2;
  }
  /** return max_tod_toa_err field */
  uint32 getMaxTodToaErr() const
  {
    return mMaxTodToaErr;
  }
  /** return raw RSSI */
  uint32 getRssi() const
  {
    return LOWI_RSSI_05DBM_UNITS(mRssi);
  }
  /** return t1 timestamp */
  A_TIME64 getT1() const
  {
    return mT1;
  }
  /** return t2 timestamp */
  A_TIME64 getT2() const
  {
    return mT2;
  }
  /** return t3 timestamp */
  uint32 getT3Del() const
  {
    return mT3Del;
  }
  /** return t4 timestamp */
  uint32 getT4Del() const
  {
    return mT4Del;
  }
  /** returns the maximum TOD error */
  uint32 getMaxTODErr() const
  {
    return WMI_RTT_TOD_ERR_GET(mMaxTodToaErr);
  }
  /** returns the maximum TOA error */
  uint32 getMaxTOAErr() const
  {
    return WMI_RTT_TOA_ERR_GET(mMaxTodToaErr);
  }

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_PER_FRAME_INFO;
  }
  //! Note : update eRangingBandwidth enums in all defined include files
  //! FYI - Present in lowi_tlv.h and lowi_request.h
  enum eRangingBandwidth
  {
    BW_20MHZ = 0,
    BW_40MHZ,
    BW_80MHZ,
    BW_160MHZ,
    BW_MAX
};
};

/** LOWI Byte Array Tlv
 *  Class representing the Array uint8 TLV
 */
class LOWIArrayUINT8Tlv : public LOWITlv
{
public:
  /** Constructor */
  LOWIArrayUINT8Tlv(uint8* pTlv, uint32 len);
  /** Destructor */
  ~LOWIArrayUINT8Tlv();
  /** parses uint8 Array buffer TLV */
  void getArrayUint8Buff(uint8     * buff, uint32 len);

  LOWITlv::eTlvType getTlvType() const
  {
    return LOWITLV_ARRAY_UINT8;
  }
};

/** This class holds the fragmentation information for a given token id */
class LOWIFragInfo
{
private:
  static const char *const TAG;
  /** token id sent by FW in a fragment */
  uint32 mTknId;
  /** dynamic array that holds the fragments before processing */
  LOWIDynBuffer *mFragBuff;

public:
  /** Constructor */
  LOWIFragInfo(uint32 tknId);
  /** Destructor */
  ~LOWIFragInfo();
  /** returns the token id */
  uint32 getTknId() const
  {
    return mTknId;
  }
  /** returns the next idx */
  uint32 getNextIdx() const
  {
    return (NULL == mFragBuff) ? 0 : mFragBuff->getNumElems();;
  }

  /**
   * store a fragment in fragBuff
   * @param frag: pointer to fragment to be stored
   * @param len: length in bytes of the fragment
   * @return uint32: 0 if successful, else -1
   */
  uint32 addFrag(uint8 *frag, uint32 len);

  /** return a pointer to the fragBuff */
  uint8* getFrag()
  {
    return (NULL != mFragBuff ? mFragBuff->getData() : NULL);
  }

  /** return the # of bytes stored in the fragBuff */
  uint16 getFragLen()
  {
    return (NULL != mFragBuff ? mFragBuff->getNumElems() : 0);
  }
};

} // namespace qc_loc_fw
#endif // __LOWI_TLV_H__
