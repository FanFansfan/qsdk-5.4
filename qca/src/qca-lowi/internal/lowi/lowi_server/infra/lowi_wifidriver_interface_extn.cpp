/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Wifi Driver Interface Extension

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Wifi Driver Interface
  Extension

Copyright (c) 2012-2014, 2016-2019 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2014 Qualcomm Atheros, Inc.
All Rights Reserved.
Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <lowi_server/lowi_wifidriver_interface.h>
#ifdef LOWI_ON_LE
#include "lowi_external_wifidriver.h"
#else
#include "lowi_rome_wifidriver.h"
#endif
#ifndef LOWI_ON_ACCESS_POINT
#include "lowi_external_wifidriver.h"
#endif
#include "wipsiw.h"
#include "lowi_internal_const.h"


using namespace qc_loc_fw;


LOWIWifiDriverInterface* LOWIWifiDriverInterface::createInstance
(ConfigFile* config,
 LOWIScanResultReceiverListener* scanResultListener,
 LOWIInternalMessageReceiverListener* internalMessageListener,
 LOWICacheManager* cacheManager)

{
  log_verbose (TAG, "%s:Creating Rome Wifi Driver", __FUNCTION__);
#ifdef LOWI_ON_LE
  LOWIWifiDriverInterface* ptr = new (std::nothrow) LOWIExternalWifiDriver (config);
#else
  LOWIWifiDriverInterface* ptr = new (std::nothrow) LOWIROMEWifiDriver(config, scanResultListener,
                                                    internalMessageListener, cacheManager);
#endif
  if (NULL == ptr)
  {
    log_error (TAG, "Unable to create the rome target Driver!");
  }
  else
  {
    LOWICapabilities configCap;

    // initialize to do-not-care for now
    configCap.activeScanSupported = true;
    configCap.discoveryScanSupported = true;
    configCap.rangingScanSupported = true;
    ptr->configCapabilities(configCap);
  }

  return ptr;
}

LOWIWifiDriverInterface* LOWIWifiDriverInterface::createWiGigInstance (
    ConfigFile *config,
    LOWIScanResultReceiverListener *scanResultListener,
    LOWIInternalMessageReceiverListener *internalMessageListener,
    LOWICacheManager *cacheManager)
{
  log_verbose (TAG, "%s", __FUNCTION__);
  LOWIWifiDriverInterface* pDriver = NULL;

  return pDriver;
} // createWiGigInstance

LOWIMeasurementResult* LOWIWifiDriverInterface::block
(LOWIRequest* request, eListenMode mode)
{
  LOWIMeasurementResult* result = NULL;

  if(LOWIWifiDriverInterface::BACKGROUND_SCAN == mode)
  {
      log_debug(TAG, "%s, Not supported", __FUNCTION__);
  }
  else
  {
    result = getMeasurements (request, mode);
  }
  return result;
}

