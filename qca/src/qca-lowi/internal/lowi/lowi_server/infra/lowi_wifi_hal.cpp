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
#include "lowi_wifi_hal.h"

using namespace qc_loc_fw;

int lowiWifiHalInit()
{
  return -1;
}

void lowiWifiHalCleanup()
{
}
LOWIMeasurementResult * performRequest(qc_loc_fw::LOWIRequest*, uint32)
{
  return NULL;
}
LOWIMeasurementResult * waitForAsyncResults()
{
  return NULL;
}
int lowi_nl_unblock()
{
  return 0;
}
int lowi_nl_init_pipe(void)
{
  return 0;
}
int lowi_nl_close_pipe(void)
{
  return 0;
}
int lowi_nl_wait_on_socket(int /*timeout*/)
{
  return 0;
}
int lowiUnblockThread()
{
  return 0;
}
bool lowiIsBgscanSupportedByDriver()
{
  return false;
}

