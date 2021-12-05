/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        Wifi Driver Utilities

GENERAL DESCRIPTION
  This file contains the implementation of utilities for Wifi Driver

Copyright (c) 2012-2013, 2015-2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

#include <string.h>
#include "lowi_wifidriver_utils.h"

using namespace qc_loc_fw;


bool LOWIWifiDriverUtils::sendDriverCmd (char* /*buf*/)
{
  return true;
}

void LOWIWifiDriverUtils::cleanupWifiCapability ()
{
}

LOWIWifiDriverUtils::eGetWiFiCapabilityError
LOWIWifiDriverUtils::getWiFiIdentityandCapability(IwOemDataCap* /*pIwOemDataCap*/, LOWIMacAddress& /*localStaMac*/)
{
  eGetWiFiCapabilityError retVal = CAP_FAILURE;
  return retVal;
}
