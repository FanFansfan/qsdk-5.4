#ifndef __LOWI_WIFI_HAL_H
#define __LOWI_WIFI_HAL_H
/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
GENERAL DESCRIPTION
   This file contains interface used by the wifi driver to handle background
   scan requests.

   Copyright (c) 2015-2016,2018 Qualcomm Technologies, Inc.
   All Rights Reserved.
   Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <inc/lowi_request.h>
#include <inc/lowi_response.h>
#include "lowi_measurement_result.h"

using namespace qc_loc_fw;

int lowiWifiHalInit();

void lowiWifiHalCleanup();
LOWIMeasurementResult * performRequest(qc_loc_fw::LOWIRequest*, uint32);
LOWIMeasurementResult * waitForAsyncResults();
int lowi_nl_unblock();
int lowi_nl_init_pipe(void);
int lowi_nl_close_pipe(void);
int lowi_nl_wait_on_socket(int timeout);
int lowiUnblockThread();
bool lowiIsBgscanSupportedByDriver();

#endif /* __LOWI_WIFI_HAL_H */

