/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
        LOWIRangingSparrowFSM Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWIRangingSparrowFSM class

  Copyright (c) 2017-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_RANGING_SPARROW_FSM_H__
#define __LOWI_RANGING_SPARROW_FSM_H__

#include "lowi_ranging_fsm.h"
#include "lowi_ranging_helium_fsm.h"

namespace qc_loc_fw
{
/** This class handles the specific FSM tasks needed by the Sparrow driver */
class LOWIRangingSparrowFSM : public LOWIRangingHeliumFSM
{
private:
  static const char* const TAG;

public:
  /** Constructor */
  LOWIRangingSparrowFSM(LOWIScanResultReceiverListener *scanResultListener,
                        LOWICacheManager *cacheManager,
                        LOWIRanging *lowiRanging):LOWIRangingHeliumFSM(scanResultListener, cacheManager, lowiRanging)
  {
  }

  /** Destructor */
  virtual ~LOWIRangingSparrowFSM()
  {
  }
};

} // namespace

#endif // __LOWI_RANGING_SPARROW_FSM_H__
