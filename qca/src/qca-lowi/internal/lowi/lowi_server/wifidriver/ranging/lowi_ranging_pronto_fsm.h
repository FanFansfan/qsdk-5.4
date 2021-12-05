#ifndef __LOWI_RANGING_PRONTO_FSM_H__
#define __LOWI_RANGING_PRONTO_FSM_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Ranging Finite State Machine Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Ranging Finite State Machine

Copyright (c) 2014-2015,2017-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/

#include "lowi_ranging.h"
#include "lowi_ranging_fsm.h"
#include "wipsFuncs.h"


namespace qc_loc_fw
{
class LOWIRangingProntoFSM: public LOWIRangingFSM
{
  static const char* const TAG;
public:
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
   *   This is a helper function that takesa a vector of APs and generates an array of vectors
   *   with each vector containg Aps on the same channel.it also sorts out the RTT1 APs from the
   *   RTT3 APs in channel index 0.
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
  LOWIRangingProntoFSM(LOWIScanResultReceiverListener* scanResultListener,
              LOWICacheManager* cacheManager, LOWIRanging* lowiRanging);
  virtual ~LOWIRangingProntoFSM();
private:
  /*=============================================================================================
   * Function description:
   *   This function that takes a vector of APs which are RTT1 capable and
   *   generates the RTT1 request and sends it to the firmware.
   *
   * Parameters:
   *   vector <LOWINodeInfo> &: Vector containing the LOWINodeInfo for the APs which are RTT1 capable
   *
   * Return value:
   *    int: 0 - Success & -1 - Failure
   *
   =============================================================================================*/
  int Process1SidedRTTRequest(vector <LOWINodeInfo>& v);
  /*=============================================================================================
   * Function description:
   *   This function takes a vector of APs which are sent as RTT1 request
   *   and find the missing/failed APs in the vector for which measurements were
   *   not successful and add dummy measurments for those APs.
   *
   * Parameters:
   *   vector <LOWINodeInfo> &: Vector containing the LOWINodeInfo for the APs which are RTT1 capable
   *
   =============================================================================================*/
  void AddDummyMeas(vector <LOWINodeInfo> &v);
  /*=============================================================================================
   * Function description:
   *   This function is responsible for parsing the Single Sided Ranging measurements
   *   recieved from the FW and fill the LOWIMeasurementInfo.
   *
   * Parameters:
   *   tInNavMeasRspParams : scan results.
   *   eRttType            : RTT type (RTT1 or RTT2) requested.
   *
   * Return value:
   *    true if parsing is successful, false otherwise.
   *
   =============================================================================================*/
  bool Parse1SidedRangingMeas(const tInNavMeasRspParams *pAppMeasurementRsp, eRttType rttType);
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
};

} // namepsace

#endif //#ifndef __LOWI_RANGING_PRONTO_FSM_H__
