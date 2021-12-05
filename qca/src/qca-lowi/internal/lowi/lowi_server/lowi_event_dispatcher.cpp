/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Event Dispatcher

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Event Dispatcher

  Copyright (c) 2012-2013, 2018 Qualcomm Technologies, Inc.

  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <string.h>
#include <base_util/log.h>
#include <lowi_server/lowi_event_dispatcher.h>
#include <lowi_server/lowi_controller.h>
#include <common/lowi_utils.h>
#include "lowi_diag_log.h"

using namespace qc_loc_fw;

const char * const LOWIEventDispatcher::TAG = "LOWIEventDispatcher";

LOWIEventDispatcher::LOWIEventDispatcher (LOWIController* const controller)
: mController (controller)
{
  log_verbose (TAG, "LOWIEventDispatcher");
  if (NULL == controller)
  {
    log_error (TAG, "LOWIEventDispatcher in invalid state!"
        " Invalid arguments");
  }
}

LOWIEventDispatcher::~LOWIEventDispatcher ()
{
  log_verbose(TAG, "~LOWIEventDispatcher");
}

void LOWIEventDispatcher::sendResponse (LOWIResponse* response,
    const char* const request_originator)
{
  log_debug(TAG, "sendResponse - originator = %s", request_originator);
  // Log the response through binary logging as well.
  LOWIDiagLog::Log (response, request_originator);

  OutPostcard* card = NULL;
  card = LOWIUtils::responseToOutPostcard (response, request_originator);
  if (NULL == card)
  {
    log_error (TAG, "Unable to create the Postcard");
    return;
  }

  mController->sendIpcMessage(card->getEncodedBuffer());
  delete card;
}
