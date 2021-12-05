/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Local Msg

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Local Msg

  Copyright (c) 2012, 2018 Qualcomm Technologies, Inc.

  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <lowi_server/lowi_controller.h>

using namespace qc_loc_fw;

const char * const LOWILocalMsg::TAG = "LOWILocalMsg";

LOWILocalMsg::LOWILocalMsg (LOWIMeasurementResult * meas)
: mRequest (NULL), mMeasurementResults (meas)
{
  log_verbose (TAG, "LOWILocalMsg with meas");
  mContainsRequest = false;
  if (NULL == meas)
  {
    log_error (TAG, "Invalid LocalMsg!");
  }
}

LOWILocalMsg::LOWILocalMsg (LOWIRequest* req)
: mRequest (req), mMeasurementResults (NULL)
{
  log_verbose (TAG, "LOWILocalMsg with Request");
  mContainsRequest = false;
  if (NULL == req)
  {
    log_error (TAG, "Invalid LocalMsg!");
  }
  else
  {
    mContainsRequest = true;
  }
}

LOWILocalMsg::~LOWILocalMsg ()
{
}

LOWIRequest* LOWILocalMsg::getLOWIRequest ()
{
  return mRequest;
}

LOWIMeasurementResult * LOWILocalMsg::getMeasurementResult ()
{
  return mMeasurementResults;
}

bool LOWILocalMsg::containsRequest ()
{
  return mContainsRequest;
}

