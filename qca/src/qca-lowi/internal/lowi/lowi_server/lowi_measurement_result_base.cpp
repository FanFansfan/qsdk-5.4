/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Measurement Result Base

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Measurement Result Base

Copyright (c) 2012, 2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <base_util/log.h>
#include <base_util/postcard.h>
#include <inc/lowi_const.h>
#include <inc/lowi_scan_measurement.h>
#include <lowi_server/lowi_measurement_result_base.h>
#include <inc/lowi_response.h>
#include "lowi_measurement_result.h"

using namespace qc_loc_fw;

const char * const LOWIMeasurementResultBase::TAG = "LOWIMeasurementResultBase";

InPostcard* LOWIMeasurementResultBase::createPostcard
(LOWIMeasurementResult* measurements)
{
  InPostcard* card = NULL;
  do
  {
    if (NULL == measurements) break;

    OutPostcard* out = OutPostcard::createInstance ();
    if (NULL == out) break;

    out->init ();

    const void* blob = (const void*) &measurements;
    size_t length = sizeof (measurements);
    out->addBlob ("SCAN_MEASUREMENTS", blob, length);
    out->finalize ();

    // Create InPostcard from the OutPostcard
    card = InPostcard::createInstance (out);
    delete out;

  } while (0);
  return card;
}

LOWIMeasurementResult* LOWIMeasurementResultBase::parseScanMeasurement
(InPostcard* card)
{
  LOWIMeasurementResult * result = NULL;

  do
  {
    if (NULL == card) break;

    const void* blob = NULL;
    size_t length = 0;
    card->getBlob ("SCAN_MEASUREMENTS", &blob, &length);
    result =  *(LOWIMeasurementResult **) blob;

  } while (0);
  return result;
}

LOWIMeasurementResultBase::LOWIMeasurementResultBase (bool result_from_lowi_lp)
{
  driverError = LOWI_DRIVER_ERROR_NONE;
  scanType = LOWIDiscoveryScanResponse::WLAN_SCAN_TYPE_UNKNOWN;
  scanStatus = LOWIResponse::SCAN_STATUS_UNKNOWN;
  measurementTimestamp = 0;
  request = NULL;
  resultFromLOWILP = result_from_lowi_lp;
  isWigigResult = false;
}
