#ifndef __LOWI_RANGING_FSM_H__
#define __LOWI_RANGING_FSM_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Ranging Finite State Machine Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Ranging Finite State Machine

Copyright (c) 2014-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/

#include <inc/lowi_defines.h>
#include <inc/lowi_request.h>
#include <base_util/vector.h>
#include "lowi_measurement_result.h"
#include <lowi_server/lowi_scan_result_listener.h>
#include <lowi_server/lowi_cache_manager.h>
#include "wlan_capabilities.h"
#include "lowi_ranging.h"
#include "lowi_ranging_defines.h"

#define MAX_DIFFERENT_CHANNELS_ALLOWED 65

// Maximum Scan result length
#define MAX_SCAN_RES_LEN 65534

// Responses from FW for Report Type 2
#define RESP_REPORT_TYPE2 1

// Number of retries the FSM will perform for failure cases
#define ROME_FSM_RETRY_COUNT 3

// Timeout value which will make the FSM block forever
#define ROME_FSM_TIMEOUT_FOREVER 0

extern qc_loc_fw::eLOWIPhyMode validPhyModeTable[qc_loc_fw::LOWIDiscoveryScanRequest::BAND_ALL][qc_loc_fw::RTT_PREAMBLE_MAX][qc_loc_fw::BW_MAX];

namespace qc_loc_fw
{

typedef enum
{
  NEW_REQUEST_ARRIVED,
  TERMINATE_THREAD,
  MAX_PIPE_EVENTS
} RangingPipeEvents;

/** LOWI FSM events */
typedef enum
{
  /* Events from LOWI Controller */
  EVENT_START_THREAD = 0,
  EVENT_RANGING_REQ,
  EVENT_CONFIGURATION_REQ,
  EVENT_INVALID_REQ,
  EVENT_TERMINATE_REQ,
  /* Events from NL Socket */
  EVENT_REGISTRATION_SUCCESS,
  EVENT_RANGING_CAP_INFO,
  EVENT_CHANNEL_INFO,
  EVENT_RANGING_MEAS_RECV,
  EVENT_RANGING_ERROR,
  EVENT_P2P_STATUS_UPDATE,
  EVENT_CLD_ERROR_MESSAGE,
  EVENT_WIPHY_INFO,
  EVENT_INVALID_NL_MESSAGE,
  EVENT_FTM_SESSION_DONE,       // sent by wigig driver when FSM session is complete
  /* Internal FSM Events*/
  EVENT_REGISTRATION_FAILURE_OR_LOST,
  EVENT_RANGING_RESPONSE_TO_USER,
  EVENT_CONFIG_RESPONSE_TO_USER,
  EVENT_NOT_READY,
  /* Events from Timer */
  EVENT_TIMEOUT,
  EVENT_RTT_AVAILABLE_CHANNEL_INFO,
  EVENT_RTT_AVAILABLE_CHANNEL_REQ,
  EVENT_ENABLE_RESPONDER_REQ,
  EVENT_DISABLE_RESPONDER_REQ,
  EVENT_RESPONDER_CHANNEL_INFO,
  EVENT_START_RESPONDER_MEAS_REQ,
  EVENT_STOP_RESPONDER_MEAS_REQ,
  EVENT_CFG_RESPONDER_MEAS_RSP,
  EVENT_RESPONDER_MEAS_INFO,
  EVENT_MAX
} RangingFSM_Event;

/** LOWI FSM states */
typedef enum
{
  STATE_IDLE_START = 0,
  STATE_WAITING_FOR_WIPHY_INFO,
  STATE_WAITING_FOR_RANGING_CAP,
  STATE_READY_AND_IDLE,
  STATE_PROCESSING_RANGING_REQ,
  STATE_PROCESSING_CONFIG_REQ,
  STATE_WAITING_FOR_RTT_CHANNEL_INFO,
  STATE_PROCESSING_RESPONDER_CONFIG_REQ,
  STATE_PROCESSING_RESPONDER_MEAS_INFO,
  STATE_MAX
} RangingFSM_State;

/** The following struct holds the current
 *  State of the FSM */
typedef struct
{
  /* The current Event being processed by the FSM */
  RangingFSM_Event curEvent;
  /* The current State of the FSM */
  RangingFSM_State curState;
  /* The NL Socket timeout */
  uint64 timeEnd;
  /* This flag is used by the FSM to indicate to the
     LOWI Wi-Fi Driver that a new valid result is waiting */
  bool valid_result;
  /* This flag is used by the FSM to indicate to the
     LOWI Wi-Fi Driver that a terminate request arrived */
  bool terminate_thread;
  /* This flag is used to indicate if the FSM is in the process
     of trying to register with the Wi-Fi Driver*/
  bool notTryingToRegister;
  /* Flag to indicate that there is a pending
   * Internal FSM event to be processed.
   */
  bool internalFsmEventPending;
} RangingFSM_ContextInfo;

/** This structure is used to store ranging and AoA capabilities from wifi or
 *  wigig drivers. Those fields that are not applicable to a particular
 *  driver will not be populated. */
typedef struct
{
  /** true if single-sided ranging is supported */
  bool oneSidedSupported;

  /** true if dual-sided ranging per 11v std is supported */
  bool dualSidedSupported11v;

  /** true if dual-sided ranging per 11mc std is supported */
  bool dualSidedSupported11mc;

  /** Highest bandwidth support for rtt requests */
  uint8 bwSupport;

  /** Bit mask representing preambles supported for rtt requests */
  uint8 preambleSupport;

  /** Maximum burst exponent */
  uint8 maxBurstExp;

  /** Maximum number of measurements per burst */
  uint8 maxMeasPerBurst;

  /** Masks for other supported capabilites */
  #define LOWI_FW_MULTI_BURST_SUPPORTED             0x00000001
  #define LOWI_IS_ASAP_CAPABLE                      0x00000002
  #define LOWI_FTM_RESPONDER_SUPPORTED              0x00000004
  #define LOWI_FTM_INITIATOR_SUPPORTED              0x00000008
  #define LOWI_AOA_MEAS_STANDALONE_SUPPORTED        0x00000010
  #define LOWI_AOA_MEAS_FTM_SESSION_SUPPORTED       0x00000020
  #define LOWI_AOA_MEAS_TOP_CIR_PH_SUPPORTED        0x00000040
  #define LOWI_AOA_MEAS_TOP_CIR_PH_AMP_SUPPORTED    0x00000080
  uint32 supportedCaps;
} LOWI_RangingCapabilities;

typedef enum
{
  NO_RSP_YET = 0,
  CONFIG_SUCCESS,
  CONFIG_FAIL
} RangingConfigStatus;
/** The following struct conatains information on request
 *  that FW is currently processing, it is used by the FSM to
 *  decide whether to send the next request to FW or wait for
 *  more responses from FW */
typedef struct
{
  /** The report Type requested from FW */
  unsigned int reportType;
  /** The total number of BSSIDs in teh last request send to FW */
  unsigned int bssidCount;
  /** The total number of measurements requested per BSSID */
  unsigned int measPerTarget;
  /** Expected number response messages from FW for this
   *  request */
  unsigned int expectedRspFromFw;
  /** Total number of responses so far received from FW for
   *  this request */
  unsigned int totalRspFromFw;
  /** Flag to indicate to the FSM that the last expected
   *  response has arrived from FW */
  bool         lastResponseRecv;
  /** Does the current Req contain an ASAP 0 target */
  bool nonAsapTargetPresent;
  /** Configuration Success/Failed */
  RangingConfigStatus rangingConfigStatus;
} RangingReqRspInfo;

struct LOWIRangingNode
{
  ChannelInfo chanInfo;
  LOWINodeInfo targetNode;
  uint32 tsfDelta;
  bool tsfValid;
  bool isQtiPeer;
  LOWIRangingNode()
  {
    memset(&chanInfo, 0, sizeof(chanInfo));
    tsfDelta = 0;
    tsfValid = FALSE;
    isQtiPeer = false;
  }
};

/** The following  structure is used to store the information
 *  from the latest LOWI request plus additional information
 *  request related for the FSM */
typedef struct _RomeRangingRequest
{
  /** vector containing the LOWI Nodes and their associated
   *  Channel structures */
  vector <LOWIRangingNode> vecRangingNodes;
  /** 2D vector containing the LOWI Nodes grouped according to
   *  their Channel structures */
  vector <LOWIRangingNode> arrayVecRangingNodes[MAX_DIFFERENT_CHANNELS_ALLOWED];
  /** vector LOWI Node Arrays, each member of the array
   *  contains a list of BSSIDs for a particulat channel */
  vector <LOWINodeInfo> vecChGroup[MAX_DIFFERENT_CHANNELS_ALLOWED];
  /** The list of channels corresponding to each member in the
   *  above array */
  unsigned int chList[MAX_DIFFERENT_CHANNELS_ALLOWED];
  /** Flag to indicate that this ranging request is still valid
   *  and has not been fully processed by the FSM */
  bool validRangingScan;
  /** The current Channel index indicating the member in the
   *  vecChGroup array that is being serviced by the FSM */
  unsigned int curChIndex;
  /** total number of channels the current request contains */
  unsigned int totChs;
  /** This is an index variable pointing to the current AP in
   *  vecChGroup */
  unsigned int curAp;
  /** Total APs in the current vecChGroup Member */
  unsigned int totAp;

  unsigned int reportType;
  /** Constructor
    */
  _RomeRangingRequest();
} RomeRangingRequest;

/* Maximum buffer length of the ranging data received from host or FW */
#define MAX_RANGING_DALA_LEN 4096

class LOWIRangingFSM
{
private:
  static LOWIRangingFSM *mWigigInstance;
  static LOWIRangingFSM *mWifiInstance;
protected:
  static const char* const TAG;
  RomeRangingRequest                       mRomeRangingReq;
  RangingReqRspInfo                        mRangingReqRspInfo;
  RomeRttCapabilities                      mRomeRttCapabilities;
  uint32                                   mRtsCtsTag;
  /* The following variable is used to indicate the type of event
     that arrived from LOWI controller */
  RangingPipeEvents                        mRangingPipeEvents;

  /* The listener through which FSM will report Ranging results */
  LOWIScanResultReceiverListener*          mListener;

  /** The Cache Manager object through which the FSM can access
   *  the BSSID cache.
   */
  LOWICacheManager*                        mCacheManager;
  /** The following array stores the channel info for all
    *  supported channels for the 20MHz Bandwidth */
  ChannelInfo                              mChannelInfoArray[MAX_CHANNEL_ID];
  //below field used for channel hint being passed to FW as part of
  //enable responder command.
  /*=============================================================================================
   * Function description:
   *   This function determines if the combination of Channel & BW is valid.
   *   This check is done to prevent FW from getting an invalid combo that can potentially
   *   cause a crash.
   *
   * Parameters:
   *   eRangingBandwidth: Channel bandwidth
   *   uint32: Primary Channel frequency
   *   uint32: Center frequency of primary band
   *   uint32: Center frequency of secondary band
   *
   * Return value:
   *    bool: false - NOT Valid & true - Valid
   *
   =============================================================================================*/
  static bool validChannelBWCombo(eRangingBandwidth bw, uint32 primary_freq,
                                  uint32 center_freq1, uint32 center_freq2);

  /*=============================================================================================
   * Function description:
   *   This function determines if the combination of Channel, BW & Preamble is valid.
   *   This check is done to prevent FW from getting an invalid combo that can potentially
   *   cause a crash.
   *
   * Parameters:
   *   LOWIRangingNode: The node to validate.
   *
   * Return value:
   *    bool: false - NOT Valid & true - Valid
   *
   =============================================================================================*/
  virtual bool validChannelBWPreambleCombo(LOWIRangingNode node);

  /*=============================================================================================
   * Function description:
   *   This function ensures that the ranging node has parameters that
   *   are within acceptable limits.
   *
   * Parameters:
   *   LOWIRangingNode&: The node to validate.
   *
   * Return value:
   *    bool: true - valid & false - NOT Valid
   *
   =============================================================================================*/
  virtual bool validRangingNode(LOWIRangingNode &rangingNode);

  /*=============================================================================================
   * Function description:
   *   This function sets the Phy Mode in the channel structure for the provided node based
   *   on the provided channel, BW and Preamble information.
   *
   * Parameters:
   *   LOWIRangingNode: The ranging node
   *
   * Return value:
   *    bool: true - phy mode set from validPhyModeTable[], else false
   *
   =============================================================================================*/
  virtual bool setPhyMode(LOWIRangingNode &rangingNode);

  /*=============================================================================================
   * Function description:
   *   This function determines the band center frequency for the requested bandwidth
   *   from the Cache, it will also load whether or not the target is a QTI target.
   *
   * Parameters:
   *   LOWIRangingNode: The ranging node
   *   LOWIScanMeasurement: Scan measurement for BSSID of node from the cache
   *
   * Return value:
   *    None
   *
   =============================================================================================*/
  virtual void loadInfoFromCache(LOWIRangingNode &rangingNode,
                                             LOWIScanMeasurement &scanMeasurement);

  /*=============================================================================================
   * Function description:
   *   This function takes the LOWI ranging Request and performs the following operations:
   *   1) Sets up the FSM to start performing Ranging Scans
   *   2) Groups APs/Channel
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int PrepareRangingRequest();

  /*=============================================================================================
   * Function description:
   *   This function adds the current node in the Scan Results with the associated error code:
   *
   * Parameters:
   *   node: The target that needs to be added to the scan result
   *   errorCode: the error code for this target
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int AddTargetToResult(LOWINodeInfo node, LOWIScanMeasurement::eTargetStatus errorCode);

  /*=============================================================================================
   * Function description:
   *   This function validates the incoming LOWI ranging Request from LOWI controller.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  virtual int ValidateRangingRequest();

  /*=============================================================================================
   * Function description:
   *   This function validates the periodicity of a given LOWINodeInfo. This function is
   *   not used in the base class, but it's used in some of the subclasses.
   *
   * Parameters:
   *   info: LOWINodeInfo for which periodicity will be validated
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   =============================================================================================*/
  virtual int ValidatePeriodicity(LOWINodeInfo const &info);

  /*=============================================================================================
   * Function description:
   *   This is a helper function that takesa a vector of APs and generates an array of vectors
   *   with each vector containg Aps on the same channel.
   *
   * Parameters:
   *   origVec: Original vector with all the APs
   *   vec    : Array of vectors with APs in each vector grouped by channel
   *   maxChanels: Max different channels in the original Vector.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  virtual unsigned int groupByChannel(vector <LOWIRangingNode>& origVec,
                                      vector <LOWIRangingNode>* vec,
                                      unsigned int maxChannels);

  /*=============================================================================================
   * Function description:
   *   This function decides whether to send another ranging request to FW or if all the Targets
   *   from the LOWI request have been serviced, it responds to the user with the results.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  virtual int SendReqToFwOrRespToUser();

  /*=============================================================================================
   * Function description:
   *   This function determines if the parameters requested for the ranging node are supported
   *   by the underlying hardware.
   *
   * Parameters:
   *   LOWINodeInfo&: The target and the ranging parameters associated with it.
   *
   * Return value:
   *    bool: True if parameters are supported, false otherwise.
   *
   =============================================================================================*/
  virtual bool targetParamsSupported(LOWINodeInfo &node);

  /*=============================================================================================
   * Function description:
   *   This function takes the Vectors of APs grouped by channel and sends the Ranging request
   *   to the driver layer within LOWI.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  virtual int SendRangingReq();

  /*=============================================================================================
   * Function description:
   *   This function is called when New Ranging Measurements arrive from wifi FW. This is where
   *   they are parsed and put into the measurement result object for LOWI.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  virtual int ProcessRangingMeas();

  /*=============================================================================================
   * Function description:
   *   This is the state action function called when the State is "Not Registered" and
   *   a start thread event arrives.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object on which the state function should
   *                             work on / make changes.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int SendRegRequest(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when A registeration response arrives from the WLAN Host
   *   driver.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleRegSuccess(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when the channel info response arrives from the WLAN Host
   *   driver.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleChannelInfo(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when the ranging capability response arrives
   *   from the WLAN Host driver.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleRangingCap(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called a PIPE event ocurs, this usually happens when LOWI
   *   controller has an event waiting for the FSM.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandlePipeEvent(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when a Ranging request arrives from LOWI controller
   *   driver.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleRangingReq(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when a configuration request arrives from LOWI controller
   *   driver. Currently two cases are handled:
   *                            1. LCI configuration
   *                            2. LCR configuration
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleConfigReq(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when new Ranging measurements arrive from the WLAN FW.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleRangingMeas(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function is called when a Ranging Error message arrives
   *   from the WLAN FW.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleRangingErrorMsg(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function is called when a Ranging Error message arrives
   *   from the WLAN FW and the FSM has just sent an LCI/LCR configuration request
   *   to FW.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleConfigRspOrErrorMsg(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when a P2P Peer info message arrives from the WLAN Host
   *   driver.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleP2PInfo(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when an error message arrives from
   *   the WLAN Host driver.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleCldErrorMsg(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when a registration failure message arrives from
   *   the WLAN Host driver.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleRegFailureOrLost(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
  * Function description:
  *   This state action function called when a ranging request arrives and the FSM is state
  *   STATE_IDLE_START.
  *
  * Parameters:
  *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
  *                             work on / make changes to.
  *
  * Return value:
  *    error code: 0 - Success & -1 - Failure
  *
  =============================================================================================*/
  static int HandleRangingReqWhenNotReg(LOWIRangingFSM* pFsmObj);

   /*=============================================================================================
   * Function description:
   *   This state action function called when a ranging request arrives and the FSM is not in
   *   state to handle or accept new requests.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int IgnoreRangingReq(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function is called a timeout occures while waiting on the NL Socket
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int HandleNlTimeout(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This state action function called when an event that has no effect on the current state
   *   arrives.
   *
   * Parameters:
   *   @param [in] LOWIRangingFSM*: Pointer to the FSM object which the state function should
   *                             work on / make changes to.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  static int DoNothing(LOWIRangingFSM* pFsmObj);

  /*=============================================================================================
   * Function description:
   *   This function sets the an FSM flag to indicate that there is an internal FSM event
   *   pending.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *   None
   *
   =============================================================================================*/
  void setFsmInternalEvent();

  /*=============================================================================================
   * Function description:
   *   This function clears the FSM flag that indicates that there is an internal FSM event
   *   pending.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *   None
   *
   =============================================================================================*/
  void clearFsmInternalEvent();

  /*=============================================================================================
   * Function description:
   *   This function is called to setup the FSM's state function table
   *
   * Parameters:
   *   None
   *
   * Return value:
   *   None
   *
   =============================================================================================*/
  virtual void SetupFsm();

  /*=============================================================================================
   * Function description:
   *   Calculates the number of bytes that will be needed by FW to provide the Measurements,
   *   LCI & LCR information for a target. This will be used to make sure that LOWI to ensure
   *   that it limits the number of targets per request so that the MAX WMI message size is not
   *   exceeded.
   *
   * Parameters:
   *   numMeas: Num Measurements for this target.
   *   ftmRangingParams: Fine timing measurement ranging parameters.
   *
   * Return value:
   *   The bytes needed for this target.
   *
   =============================================================================================*/
  virtual unsigned int ExpectedMeasSizeForTarget(unsigned int numMeas, uint32 ftmRangingParams);

  /*=============================================================================================
   * Function description:
   *   Wrapper used for sending the RTT request
   *
   * Parameters:
   *   chanInfo     : Channel Id of Target devices
   *   bssidIdx     : unsigned int Number of BSSIDs in this request
   *   bssidsToScan : DestInfo Array of BSSIDs and RTT Type
   *   spoofBssids  : DestInfo Array of Spoof BSSIDs and RTT Type
   *
   * Return value:
   *   error code: 0 - Success & -1 - Failure
   =============================================================================================*/
  virtual int SendRttRequest(ChannelInfo chanInfo, unsigned int bssidIdx,
                             DestInfo *bssidsToScan, DestInfo *spoofBssids, unsigned int reportType,
                             std::string interface);

  /*=============================================================================================
   * Function description:
   *   Add Dummy Measurements for previous RTT Measurement Request
   *   This should be called when the FW does not send a response
   *
   * Parameters:
   *   None
   *
   * Return value:
   *   None
   *
   =============================================================================================*/
  void AddDummyMeas();

  /*=============================================================================================
   * Function description:
   *   Process rejection of RTT request by WLAN Host or FW.
   *   This calls AddDummyMeas to add dummy measurements for
   *   BSSIDs in the RTT request.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *   None
   *
   =============================================================================================*/
   void ProcessRttRejected();

  typedef int (*stateFunction) (LOWIRangingFSM*);

  stateFunction stateTable[STATE_MAX][EVENT_MAX];

public:
  /* The following variable is used to store the pointer to the
     LOWI result object where results for the current request will be
     stored */
  LOWIMeasurementResult*                   mLowiMeasResult;
  LOWIRequest*                             mNewReq;
  RangingFSM_ContextInfo                   mRangingFsmContext;
  LOWIRanging*                             mLOWIRanging;
  LOWIRequest*                             mCurReq;
  LOWIRequest::eRequestType                eRequestType;
  tANI_U8                                  mRangingFsmData[MAX_RANGING_DALA_LEN];
  /* time from the boot plus the responder enabled duration will be
   * added into the below variable, this is used to ignore any ranging
   * request if it comes during this time */
  uint64                                   mRTTResponderExpiryTimeStamp;
  bool                                     mRTTResponderMeasStarted;
  enum eLowiRangingInterface
  {
    LOWI_ROME_RANGING_INTERFACE,
    LOWI_PRONTO_RANGING_INTERFACE,
    LOWI_HELIUM_RANGING_INTERFACE,
    LOWI_SPARROW_RANGING_INTERFACE
  };
  /**
   * This function is called when new responder channel info arrives from FW.
   * It is where they are parsed and put into the measurement result object
   * for the caller.
   * @return int: 0 if success, else failure
   */
  virtual int ProcessResponderChannelMeas();
  /**
   * Passes on the Request sent from LOWI Controller to LOWI
   * Ranging FSM module
   *
   * @param  LOWIRequest* mReq - The Ranging Request
   * @return 0 - success, -1 failure
   */
  int SetLOWIRequest(LOWIRequest* pReq);

  /**
   * Passes on the Request sent from LOWI Controller to LOWI
   * Ranging FSM module
   *
   * @param  uint32 channel for the ChannelInfo is needed
   * @return const ChannelInfo& Reference to Channel info struct
   */
  const ChannelInfo& GetChannelInfo(uint32 channel) const
  {
    if (channel >= MAX_CHANNEL_ID)
    {
      log_warning(TAG, "%s: Index too large (%u)", __FUNCTION__, channel);
    }
    // Prevent out of bounds access
    return mChannelInfoArray[channel >= MAX_CHANNEL_ID ? 0 : channel];
  }

  /*=============================================================================================
   * Function description:
   *   This function checks to see if there is a new Ranging request pending.
   *
   * Parameters:
   *   None
   *
   * Return value: true or false
   *
   =============================================================================================*/
  bool NewRequestPending();

  /*=============================================================================================
   * Function description:
   *   This function checks to see if FSM is currently processing a request.
   *
   * Parameters:
   *   None
   *
   * Return value: true or false
   *
   =============================================================================================*/
  bool ProcessingRangingRequest();

  /*=============================================================================================
   * Function description:
   *   This function rejects the new request sent by the caller.
   *
   * Parameters:
   *   NONE
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int RejectNewRangingReq();

  /*=============================================================================================
   * Function description:
   *   This function sends the current Ranging result to user with the status provided by
   *   the caller.
   *
   * Parameters:
   *   eScanStatus: The Status of the Ranging scan Results.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int SendCurrentResultToUser(LOWIResponse::eScanStatus status);

  /*=============================================================================================
   * Function description:
   *   This Main FSM function called by the any object that has an instance of the FSM class.
   *   This function when called inturn calls the appropriate action function from the FSM
   *   action function table based in the current FSM state and the current Event.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int FSM();

  /*=============================================================================================
   * Function description:
   *   This function is called by the LOWI wifi Driver object to indicate to the FSM
   *   that a new PIPE event has arrived from LOWI controller.
   *
   * Parameters:
   *   Pipe Event
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int SetNewPipeEvent(RangingPipeEvents newEvent);

  /*=============================================================================================
   * Function description:
   *   This function is called to send results to the user via the Listenener Object.
   *
   * Parameters:
   *   LOWIMeasurementResult*: Measurement results.
   *
   * Return value:
   *    error code: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int SendResultToClient(LOWIMeasurementResult* result);

  /*=============================================================================================
   * Function description:
   *   This function is called by the LOWI wifi Driver object to check if the FSM is ready
   *   for accepting ranging requests.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *   FSM state: 0 - Not ready & 1 - Ready & Idle
   *
   =============================================================================================*/
  bool IsReady();

  /*=============================================================================================
   * Function description:
   *   This function is called by the LOWI wifi Driver object to get the Ranging
   *   capabilities from the FSM.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    LOWI_RangingCapabilities -- the ranging capabilites for the driver
   *
   =============================================================================================*/
  virtual LOWI_RangingCapabilities GetRangingCap();
  virtual bool SendRangingCap(std::string interface);

  /*=============================================================================================
   * Function description:
   *   Waits on the Private Netlink Socket and the LOWI controller pipe for timeout if timeout >0
   *   If Messages/Data arrive, collects and processes them accordingly.
   *   If LOWI controller requests a shutdown then exits and picks up the new pequest to process
   *   If Timeout occurs exits without processing any data.
   *
   * Parameters:
   *   None
   *
   * Return value:
   *    error code
   *
   =============================================================================================*/
  virtual int ListenForEvents();

  /*=============================================================================================
   * Function description:
   *   Check the ranging type mask to determine if ranging is supported
   *
   * Parameters:
   *   None
   *
   * Return value:
   *   0 if ranging is supported, non-zero otherwise.
   =============================================================================================*/
  virtual int CheckRangingSupport();

  /*=============================================================================================
   * Function description:
   *   Map LOWI Request to internal event.
   *
   * Parameters:
   *   LOWIRequest* mReq - The Request
   *
   * Return value:
   *   0 if request is valid., -1 otherwise.
   *
   =============================================================================================*/
  int LowiReqToEvent(const LOWIRequest * const pReq);

  /**
   * This function Initializes the Measurement result object when a new ranging
   * request arrives
   *
   * @param LOWIMeasurementResult*:
   * @param LOWIResponse::eScanStatus:
   *
   * @return int: error code: 0 - Success & -1 - Failure
   */
  int InitializeMeasResult(LOWIMeasurementResult* lowiMeasResult,
                           LOWIResponse::eScanStatus status = LOWIResponse::SCAN_STATUS_DRIVER_ERROR);

  /*=============================================================================================
   * Function description:
   *   Create an FSM Instance
   *
   * Parameters:
   *   LOWIScanResultReceiverListener* scanResultListener - Listener for Scan results
   *   LOWICacheManager* cacheManager  - Pointer to Cache Manager
   *   LOWIRanging* lowiRanging  - Pointer to Lowi Ranging
   *   LOWIRanging::eLowiRangingInterface - Type of Ranging interface to create
   *
   * Return value:
   *   pointer to LOWIRangingFSM object.
   *
   =============================================================================================*/
   static LOWIRangingFSM* createInstance(LOWIScanResultReceiverListener* scanResultListener,
                                        LOWICacheManager* cacheManager,
                                        LOWIRanging* lowiRanging,
                                        LOWIRangingFSM::eLowiRangingInterface);

   LOWIRangingFSM(LOWIScanResultReceiverListener* scanResultListener,
              LOWICacheManager* cacheManager,
              LOWIRanging *lowiRanging);

  virtual ~LOWIRangingFSM();
};

} // namepsace

#endif //#ifndef __LOWI_RANGING_FSM_H__
