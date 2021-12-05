/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWIRangingHeliumFSM class implementation

GENERAL DESCRIPTION
  This file contains the implementation for the LOWIRangingHeliumFSM class

Copyright (c) 2016,2018-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <base_util/log.h>
#include <common/lowi_utils.h>
#include "lowi_helium_ranging.h"
#include "lowi_ranging_helium_fsm.h"
#include "innavService.h"
#include "lowi_time.h"

#include <base_util/time_routines.h>

// Enter/Exit debug macros
#undef ALLOW_ENTER_EXIT_DBG_RANGING_HELIUM_FSM

#ifdef ALLOW_ENTER_EXIT_DBG_RANGING_HELIUM_FSM
#define HFSM_ENTER() log_verbose(TAG, "ENTER: %s", __FUNCTION__);
#define HFSM_EXIT()  log_verbose(TAG, "EXIT: %s", __FUNCTION__);
#else
#define HFSM_ENTER()
#define HFSM_EXIT()
#endif

#define LOWI_RTT_RESPONDER_MAX_DURATION_SECS 3600

extern qc_loc_fw::eRangingBandwidth validBWTable[LOWI_PHY_MODE_MAX][qc_loc_fw::LOWIDiscoveryScanRequest::BAND_ALL];
using namespace qc_loc_fw;

int LOWIRangingHeliumFSM::ProcessResponderChannelMeas()
{
  return -1;
}

int LOWIRangingHeliumFSM::HandleResponderChannelRsp(LOWIRangingFSM* pFsmObj)
{
  return -1;
}
int LOWIRangingHeliumFSM::SendRTTAvailableChannelReq(LOWIRangingFSM* /*pFsmObj*/)
{
  return -1;
}
int LOWIRangingHeliumFSM::SendEnableResponderReq(LOWIRangingFSM* /*pFsmObj */)
{
  return -1;
}
int LOWIRangingHeliumFSM::SendDisableResponderReq(LOWIRangingFSM* /*pFsmObj*/)
{
  return -1;
}
int LOWIRangingHeliumFSM::HandleConfigResponderMeasRsp(LOWIRangingFSM* /*pFsmObj*/)
{
  return -1;
}
int LOWIRangingHeliumFSM::SendResponderMeasStartReq(LOWIRangingFSM* /*pFsmObj */)
{
  return -1;
}
int LOWIRangingHeliumFSM::SendResponderMeasStopReq(LOWIRangingFSM* /*pFsmObj*/)
{
  return -1;
}

int32 LOWIRangingHeliumFSM::getBestResponderChannel(LOWIRangingFSM* /*pFsmObj*/)
{
  return -1;
}
