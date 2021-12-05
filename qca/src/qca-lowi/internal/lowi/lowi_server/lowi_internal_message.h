#ifndef __LOWI_INTERNAL_MESSAGE_H__
#define __LOWI_INTERNAL_MESSAGE_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
LOWI Internal Message Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWIInternalMessage

Copyright (c) 2015-2016, 2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <base_util/postcard.h>
#include <inc/lowi_const.h>
#include <inc/lowi_mac_address.h>
#include <inc/lowi_request.h>
#include "lowi_nl80211.h"

namespace qc_loc_fw
{
class LOWIUtils;
/**
 * Base class for all internal messages LOWI can handle. Internal messages are
 * messages coming from modules such as the wifi driver, etc; not from
 * external clients. External clients use LOWIRequest.
 */
class LOWIInternalMessage : public LOWIRequest
{
private:

public:
/** Internal message types */
enum eLowiInternalMessage
{
  LOWI_IMSG_FTM_RANGE_REQ        = 0,
  LOWI_IMSG_FTM_RANGE_RPRT       = 1,
  LOWI_IMSG_WIFI_INTF_STATUS_MSG = 2,
  LOWI_IMSG_LCI_REQ              = 3,
  LOWI_IMSG_LCI_RPRT             = 4,
  LOWI_IMSG_WIGIG_NO_LOC_CAPS    = 5
};

/** Log Tag */
  static const char * const TAG;

  /**
   * Constructor
   * @param uint32 Request Id generated by the client
   * @param orig Originator of the this internal message.
   */
  LOWIInternalMessage (uint32 msgId, const char* const orig);

  /** Destructor*/
  virtual ~LOWIInternalMessage ();
  /**
   * Creates an InPostcard and inserts the measurement pointer
   * as a blob to it.
   * @param LOWIMeasurementResult* Scan Measurements
   * @return InPostcard
   */

  static InPostcard * createPostcard (LOWIInternalMessage *req);

  /**
   * Parses the InPostcard and retrieves the internal message pointer
   * stored as a blob in it
   * @param InPostcard *card
   * @return LOWIInternalMessage pointer
   */
  static LOWIInternalMessage * parseInternalMessage (InPostcard* card);

  /**
   * Returns the request type
   * @return eRequestType type of request
   */
  virtual eRequestType getRequestType () const;

  /**
   * Returns the LOWI internal message type
   * @return eLowiInternalMessage type of request
   */
   virtual eLowiInternalMessage getInternalMessageType () const = 0;
};


/** Radio Measurement Request parameters passed through from driver
  * for the purpose of putting together the Radio Measurement Report
  */
class RadioMeasReqParams
{
public:
  /** BSSID of the AP requesting the Radio Measurement Request */
  LOWIMacAddress mRequesterBssid;

  /** BSSID of the wifi node servicing the Radio Measurement Request */
  LOWIMacAddress mSelfBssid;

  /** Channel frequency at which wifi node is associated with AP */
  uint32 mFrequency;

  /** Dialog token that came in the Radio Measurement request and that needs to
   *  be returned in the measurement report response */
  uint32 mDiagToken;

  /** Measurement token for the measurement element within the Radio
   *  Measurement request. It needs to be returned in the measurement
   *  report response */
  uint32 mMeasToken;

  /** Constructor */
  RadioMeasReqParams()
  {
    mFrequency = 0;
    mDiagToken = 0;
    mMeasToken = 0;
  };

  /** Destructor */
  ~RadioMeasReqParams() {};
};

/**
 * FTMRangeReq Message
 */
class LOWIFTMRangeReqMessage: public LOWIInternalMessage
{
private:

  /**
   * Parameters passed from driver into LOWI for the purpose of constructing
   * an FTM Range Report
   */
  RadioMeasReqParams mRangeReqParams;

  /**
   * Dynamic array containing a list of wifi nodes and the
   * relevant information for thoses wifi nodes to be scanned.
   *
   * NOTE:
   * There may be a limit to the number of wifi nodes that can
   * be scanned in a single request. The user of this interface
   * may want to inquire what that is at the time of use.
   */
  vector <LOWIPeriodicNodeInfo> mNodeInfo;

public:
  /**
   * Constructor
   * @param uint32 Request id. This will be echoed back in the corresponding
   *               response.
   */
  /**
   * Constructor
   *
   * @param msgId. This will be echoed back in the corresponding response (if
   *             any). Also, used for easier debugging.
   * @param v: wifi nodes to be FTM'ed with //BAA??? fix.
   * @param bssid: mac address of the AP requesting the FTM events
   * @param selfBssid: mac address of the node sending the message
   * @param frequency: frequency at which wifi node is associated with AP
   * @param mDToken: dialog token for the request
   * @param mMToken: measurement token for the FTM element in the request
   * @param orig Originator of the this internal message.
   */
  LOWIFTMRangeReqMessage (uint32 msgId,
                          vector<LOWIPeriodicNodeInfo> &v,
                          RadioMeasReqParams &, const char* const orig);

  /** Destructor*/
  virtual ~LOWIFTMRangeReqMessage ();

  /**
   * Returns FTM Range Request parameters
   * @return const RadioMeasReqParams&: passthrough parameters
   */
  const RadioMeasReqParams & getRadioMeasReqParams() const;

  /**
   * Returns the Dynamic array containing the LOWINodeInfo
   * @return Dynamic array containing the LOWINodeInfo
   */
  vector <LOWIPeriodicNodeInfo> & getNodes ();

  /**
   * Returns the LOWI internal message type
   * @return eLowiInternalMessage type of request
   */
   virtual eLowiInternalMessage getInternalMessageType () const;
};

/** Information related to successful range measurement with a single AP  */
struct LOWIRangeEntry
{
  /** Contains the least significant 4 octets of the TSF (synchronized with the
   *  associated AP) at the time (� 32 ?s) at which the initial Fine Timing
   *  Measurement frame was transmitted where the timestamps of both the frame
   *  and response frame were successfully measured.
   */
  uint32 measStartTime;
  /** BSSID of AP whose range is being reported */
  LOWIMacAddress bssid;
  /** Estimated range between the requested STA and the AP using the fine timing
   *  measurement procedure, in units of 1/64 m. A value of 216�1 indicates a
   *  range of (216�1)/64 m or higher.
   */
  uint16 range;
  /**
   *  The Max Range Error field contains an upper bound for the error in the
   *  value specified in the Range field, in units of 1/64 m. A value of
   *  zero indicates an unknown error. A value of 216�1 indicates error of
   *  (216-1)/64 m or higher. For instance, a value of 128 in the Max Range
   *  Error field indicates that the value in the Range field has a maximum
   *  error of � 2 m.
   */
  uint16 maxErrRange;
  /** Reserved field   */
  uint8  reserved;

  /** Constructor */
  LOWIRangeEntry();
};

/** Error report codes related to failure range measurement */
enum LOWIMeasRptrErrCodes
{
  /** AP reported "Request incapable" */
  REQ_INCAPABLE_AP = 2,
  /** AP reported "Request failed. Do not send new request for a specified
   *  period */
  REQ_FAILED_AT_AP = 3,
  /** Unable to successfully transmit to AP */
  TX_FAIL  = 8,
};

/** Information related to failure range measurement with a single AP */
struct LOWIErrEntry
{
  /** Contains the least significant 4 octets of the TSF (synchronized with the
   *  associated AP) at the time (� 32 us) at which the Fine Timing Measurement
   *  failure was first detected.
   */
  uint32 measStartTime;
  /** BSSID of AP whose range is being reported */
  LOWIMacAddress bssid;
  /** Error report code */
  enum LOWIMeasRptrErrCodes errCode;

  /** Constructor */
  LOWIErrEntry();
};

/**
 * FTMRR Report Message
 */
class LOWIFTMRangeRprtMessage: public LOWIInternalMessage
{
private:

  /**
   * Parameters passed from driver into LOWI for the purpose of constructing
   * an FTM Range Report
   */
  RadioMeasReqParams mRangeReqParams;

  /** successful FTMs */
  vector<LOWIRangeEntry> measInfoSuccess;

  /** unsuccessful FTMs */
  vector<LOWIErrEntry>   measInfoErr;

public:
  /**
   * Constructor
   * @param msgId: scheduler generated request identifier
   * @param bssid: mac address of the AP requesting the FTM events
   * @param params: FTM Range Request pass-through parameters
   * @param vR: vector of successful entries
   * @param vE  vector of error entries
   * @param orig Originator of the this internal message.
   */
  LOWIFTMRangeRprtMessage(uint32 msgId,
                          RadioMeasReqParams & params,
                          vector<LOWIRangeEntry> &vR,
                          vector<LOWIErrEntry> &vE, const char* const orig);

  /** Destructor*/
  virtual ~LOWIFTMRangeRprtMessage();

  /**
   * Returns FTM Range Request parameters
   * @return const RadioMeasReqParams&: passthrough parameters
   */
  const RadioMeasReqParams & getRadioMeasReqParams() const;

  /**
   * Returns a reference to the vector containing the measurement success APs
   * @return vector<LOWIRangeEntry>&
   */
  vector <LOWIRangeEntry> & getSuccessNodes ();

  /**
   * Returns a reference to the vector containing the measurement error APs
   * @return vector<LOWIErrEntry>&
   */
  vector <LOWIErrEntry> & getErrNodes ();

  /**
   * Returns the LOWI internal message type
   * @return eLowiInternalMessage type of request
   */
   virtual eLowiInternalMessage getInternalMessageType () const;
};

/**
 * Wifi Interface state update message
 */
class LOWIWifiIntfStateMessage: public LOWIInternalMessage
{
private:

  /** Wi-Fi interface state */
  eWifiIntfState  mWifiState;

public:
  /**
   * Constructor
   * @param msgId: scheduler generated request identifier
   * @param state: Wifi Interface state
   * @param orig Originator of the this internal message.
   */
  LOWIWifiIntfStateMessage(uint32 msgId,
                          eWifiIntfState wifiState, const char* const orig) ;

  /** Destructor*/
  virtual ~LOWIWifiIntfStateMessage();

  /**
   * Returns the Wifi State information in the message
   * @return eWifiIntfState
   */
  eWifiIntfState getIntfState () const;

  virtual eLowiInternalMessage getInternalMessageType () const;
};

/**
 * LCI request message
 */
class LOWILCIReqMessage: public LOWIInternalMessage
{
private:
  /**
   * Radio Measurement request parameters passed from driver into LOWI for
   * the purpose of constructing an LCI Report */
  RadioMeasReqParams mRadioMeasReqParams;
  /** Location Subject */
  uint8 mLocSub;

public:
  /**
   * Constructor
   * @param msgId: scheduler generated request identifier
   * @param locSub: location subject
   * @param params: Radio Measurement parameters from the request needed for
   *                sending out the LCI report.
   * @param orig Originator of the this internal message.
   */

  LOWILCIReqMessage(uint32 msgId, uint8 locSub, RadioMeasReqParams &params,
                    const char* const orig)
    : LOWIInternalMessage (msgId, orig)
  {
    log_verbose (TAG, "LOWILCIReqMessage(%u)", locSub);
    mLocSub = locSub;
    mRadioMeasReqParams = params;
  }
  /** Destructor*/
  virtual ~LOWILCIReqMessage()
  {
    log_verbose (TAG, "~LOWILCIReqMessage");
  }

  /**
   * Returns Radio Measurement request parameters
   * @return const RadioMeasReqParams&: passthrough parameters
   */
  const RadioMeasReqParams & getRadioMeasReqParams() const
  {
    return mRadioMeasReqParams;
  }

  /**
   * Returns the location subject in the message
   * @return uint8: location subject
   */
  uint8 getLocationSub() const
  {
    return mLocSub;
  }

  /**
   * Returns the LOWI internal message type
   * @return LOWIInternalMessage::eLowiInternalMessage: internal msg type
   */
  virtual LOWIInternalMessage::eLowiInternalMessage getInternalMessageType () const
  {
    return LOWI_IMSG_LCI_REQ;
  }
};

/**
 * LCI Report Message
 */
class LOWILCIRprtMessage : public LOWIInternalMessage
{
private:
  /** Parameters passed from driver into LOWI for the purpose of constructing an
   *  LCI Report */
  RadioMeasReqParams mRadioMeasParams;

  /** LCI information required for the LCI rprt response */
  LOWILCIRprtInfo mLciRprtInfo;

public:
  /** Constructor
   *  @param msgId: scheduler generated request identifier
   *  @param params: LCI Request pass-through parameters
   *  @param lciRprtInfo: location info needed to construct the LCI report
   *  @param orig Originator of the this internal message.
   */
  LOWILCIRprtMessage(uint32 msgId,
                     RadioMeasReqParams &params,
                     LOWILCIRprtInfo    &lciRprtInfo, const char* const orig)
  : LOWIInternalMessage (msgId, orig)
  {
    log_verbose (TAG, "LOWILCIRprtMessage");
    mRadioMeasParams = params;
    mLciRprtInfo     = lciRprtInfo;
  }

  /** Destructor */
  virtual ~LOWILCIRprtMessage()
  {
    log_verbose (TAG, "~LOWILCIRprtMessage");
  }

  /**
   * Returns Radio Measurement Request parameters
   * @return const RadioMeasReqParams&: passthrough parameters
   */
  const RadioMeasReqParams & getRadioMeasReqParams() const
  {
    return mRadioMeasParams;
  }

  /**
  * Returns LCI report information
  * @return const LOWILCIRprtInfo& : LCI information used in the report response
  */
  const LOWILCIRprtInfo & getLCIRprtInfo() const
  {
    return mLciRprtInfo;
  }

  /**
   * Returns the LOWI internal message type
   * @return eLowiInternalMessage type of request
   */
   virtual LOWIInternalMessage::eLowiInternalMessage getInternalMessageType () const
   {
     return LOWI_IMSG_LCI_RPRT;
   }
};


/**
 * Wigig driver supports no location capabilities message
 */
class LOWIWigigNoLocCapsMessage : public LOWIInternalMessage
{
public:
  /** Constructor */
  LOWIWigigNoLocCapsMessage(uint32 msgId, const char* const orig) : LOWIInternalMessage(msgId, orig) {}
  /** Destructor*/
  virtual ~LOWIWigigNoLocCapsMessage() { }

  virtual LOWIInternalMessage::eLowiInternalMessage getInternalMessageType() const
  {
    return LOWI_IMSG_WIGIG_NO_LOC_CAPS;
  }
};

}// namespace qc_loc_fw

#endif //#ifndef __LOWI_INTERNAL_MESSAGE_H__