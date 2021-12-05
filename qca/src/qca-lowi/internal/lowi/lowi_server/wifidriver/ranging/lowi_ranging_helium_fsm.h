/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWIRangingHeliumFSM class header file

GENERAL DESCRIPTION
  This file contains the interface for the LOWIRangingHeliumFSM class

  Copyright (c) 2016-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_RANGING_HELIUM_FSM_H__
#define __LOWI_RANGING_HELIUM_FSM_H__

#include "lowi_ranging_fsm.h"


namespace qc_loc_fw
{
/** This struct contains the mac address of targets that came in periodic
  * ranging requests. It stores the mac address and the original LOWIRequest
  */
struct LOWIReqInfo
{
  LOWIRequest *req;
  LOWIMacAddress macAddr;
public:
  /** Constructor */
  LOWIReqInfo(LOWIMacAddress macaddr, LOWIRequest *req);
  /** Destructor */
  ~LOWIReqInfo();
};

/** This class handles the specific FSM tasks needed by the Helium driver */
class LOWIRangingHeliumFSM : public LOWIRangingFSM
{
private:
  static const char* const TAG;
  /**
   * List of structures containing client request info. The
   * FSM keeps a list of client requests so that as responses
   * to periodic requests come back; the FSM can decide when
   * every bssid in a given request is fully serviced
   * before the request is removed.
   */
    List<LOWIReqInfo *> mPendingReq;

    /** Indicates whether request is periodic */
    bool mPeriodicReq;

protected:
    /** indicates when last measurement occurs */
    bool mLastMeas;

public:
  /** Constructor */
  LOWIRangingHeliumFSM(LOWIScanResultReceiverListener* scanResultListener,
                       LOWICacheManager* cacheManager,
                       LOWIRanging *rangingObj);

  /** Destructor */
  virtual ~LOWIRangingHeliumFSM();

  /**
   * This function is called when the cache is NOT used. It sets the phy mode in
   * the channel structure. If a valid phy mode is provided by the user, it uses
   * that; othewise the phy mode is chosen from validPhyModeTable[] based on the
   * channel, BW and preamble information.
   *
   * @param LOWIRangingNode&: The ranging node
   *
   * @return bool: true: phy mode overwritten with the one provided by user,
   *         else false
   */
  virtual bool setPhyMode(LOWIRangingNode &rangingNode);

  /**
   * Determines if the combination of Channel, BW & Preamble is valid. The
   * check is done to prevent FW from getting an invalid combination of
   * parameters that could potentially cause a crash.
   *
   * @param LOWIRangingNode: The node to validate
   *
   * @return bool: false - NOT Valid & true - Valid
   */
  virtual bool validChannelBWPreambleCombo(LOWIRangingNode node);

  /**
   * Selects the frequency and phymode based on the target AP's cached
   * information. How the information from cache is used, was agreed upon with
   * FW group's input.This function will also load whether or not the target is
   * a QTI target.
   *
   * @param LOWIRangingNode&: The ranging node
   * @param LOWIScanMeasurement&: Scan measurement from cache for target node
   */
  virtual void loadInfoFromCache(LOWIRangingNode &rangingNode,
                                 LOWIScanMeasurement &scanMeasurement);

  /**
   * Checks whether the target AP supports the packet bandwidth/preamble
   * combination in the RTT request.
   *
   * @param LOWINodeInfo &: requested RTT parameters
   * @param eLOWIPhyMode: maximum phy mode supported by the target AP
   *
   * @return bool: true if target AP supports the packet bw/preamble
   *         combination, else false
   */
  bool bwSupportedByAP(LOWINodeInfo &requested,
                       eLOWIPhyMode targetApPhyMode);

  /**
   * Determine if the frequency spacing is valid for the given phy mode. The
   * check is done to prevent FW from getting an invalid combination of
   * parameters that could potentially cause a crash.
   *
   * @param eLOWIPhyMode: phy mode
   * @param uint32: primary channel frequency
   * @param uint32: center frequency of primary band
   * @param uint32: center frequency of secondary band
   *
   * @return bool: false - NOT Valid & true - Valid
   */
  bool validChannelPhyModeCombo(eLOWIPhyMode phyMode, uint32 primary_freq,
                                uint32 center_freq1, uint32 center_freq2);
  /**
   * Validates the periodicity of the parameters in the request.
   * @param info: LOWI node info with target parameters
   * @return int: 0 if success, else failure
   */
  virtual int ValidatePeriodicity(LOWINodeInfo const &info);

  /**
   * This function decides whether to send another ranging request to FW or if
   * all the Targets from the LOWI request have been serviced, it responds to
   * the user with the results.
   * @return int: 0 if success, else failure
   */
  virtual int SendReqToFwOrRespToUser();
  /**
   * This function is called when new ranging measurements arrive from FW. It is
   * where they are parsed and put into the measurement result object for the
   * caller.
   * @return int: 0 if success, else failure
   */
  virtual int ProcessRangingMeas();
  /**
   * This function is called when new responder channel info arrives from FW.
   * It is where they are parsed and put into the measurement result object
   * for the caller.
   * @return int: 0 if success, else failure
   */
  virtual int ProcessResponderChannelMeas();
  /**
   * This function determines if the rtt request for the specific target is
   * periodic.
   *
   * @param node: target's request information
   * @return bool: true if target's request is periodic
   */
  virtual bool isTargetPeriodic(LOWINodeInfo const &node);

  /**
   * This function validates the request parameters once it has been determined
   * that the request is periodic
   *
   * @param node: target's request information
   * @return bool: true if periodic parameters are valid
   */
  virtual bool validPeriodicParams(LOWINodeInfo const &node);

  /**
   * Wrapper used for sending the RTT request
   *
   * @param chanInfo     : Channel Id of Target devices
   * @param bssidIdx     : unsigned int Number of BSSIDs in this request
   * @param bssidsToScan : DestInfo Array of BSSIDs and RTT Type
   * @param spoofBssids  : DestInfo Array of Spoof BSSIDs and RTT Type
   *
   * @return int: 0 if success, else failure
   */
  virtual int SendRttRequest(ChannelInfo chanInfo, unsigned int bssidIdx,
                             DestInfo *bssidsToScan, DestInfo *spoofBssids,  unsigned int reportType,
                             std::string interface);

  /**
   *   Calculates the number of bytes that will be needed by FW to provide the Measurements,
   *   LCI & LCR information for a target. This will be used to make sure that LOWI to ensure
   *   that it limits the number of targets per request so that the MAX WMI message size is not
   *   exceeded.
   *
   *   @param numMeas: Num Measurements for this target.
   *   @param ftmRangingParams: Fine timing measurement ranging
   *                          parameters
   *
   *   @return unsigned int: The bytes needed for this target.
   */
  virtual unsigned int ExpectedMeasSizeForTarget(unsigned int numMeas, uint32 ftmRangingParams);
  /**
   * Function description:
   *   This function is called to setup the FSM's state function table
   *
   * @Param None
   *
   * @return None
   *
   */
  virtual void SetupFsm();
  /**
   * Function description:
   *   This function is called when LOWI get available channel info
   *   response from the FW.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int HandleRTTAvailableChannelRsp(LOWIRangingFSM* pFsmObj);
  /**
   * Function description:
   *   This function is called when LOWI get the responder channel
   *   response of set responder request.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int HandleResponderChannelRsp(LOWIRangingFSM* pFsmObj);
  /**
   * Function description:
   *   This function is called by the client to send the RTT available
   *   channel req and wait for the channel response.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int SendRTTAvailableChannelReq(LOWIRangingFSM* pFsmObj);
  /**
   * Function description:
   *   This function is called by the client to send the enable
   *   responder request to FW and wait for channel info as response.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int SendEnableResponderReq(LOWIRangingFSM* pFsmObj);
  /**
   * Function description:
   *   This function is called by the client to disable the responder.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int SendDisableResponderReq(LOWIRangingFSM* pFsmObj);
  /**
   * Function description:
   *   This function is called when LOWI get the responder channel
   *   response of set responder request.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int HandleConfigResponderMeasRsp(LOWIRangingFSM* pFsmObj);
   /**
   * Function description:
   *   This function is called by the client to send the enable
   *   responder request to FW and wait for channel info as response.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int SendResponderMeasStartReq(LOWIRangingFSM* pFsmObj);
  /**
   * Function description:
   *   This function is called by the client to disable the responder.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   */
  static int SendResponderMeasStopReq(LOWIRangingFSM* pFsmObj);
  /**
   * Function description:
   *   This function will return the channel index from the channelinfoArray
   *   for the highest available PHY mode.
   *
   * @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    channel index or -1 in case of Failure
   *
   */
  static int32 getBestResponderChannel(LOWIRangingFSM* pFsmObj);
};

} // namespace

#endif // __LOWI_RANGING_HELIUM_FSM_H__
