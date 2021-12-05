#ifndef WIPS_FUNC_H
#define WIPS_FUNC_H

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        WIPS module - Wifi Scanner Interface for Positioning System

GENERAL DESCRIPTION
  This file contains the declaration and some global constants for WIPS
  module.

  Copyright (c) 2012-2013, 2016-2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.
=============================================================================*/
#include <stdint.h>
#include "innavService.h"
#include "lowi_request.h"

namespace qc_loc_fw
{
bool parse1SidedRangingMeas(const tInNavMeasRspParams *pAppMeasurementRsp,
                            eRttType rttType, LOWIMeasurementResult& result);
int process1SidedRTTRequest(vector <LOWINodeInfo> &v, LOWIMeasurementResult& result,
                            uint32& rttTag, int timeout);
void addBssidMeasFail(vector <LOWINodeInfo> &v, LOWIMeasurementResult& result);
}

#endif // WIPS_FUNC_H

