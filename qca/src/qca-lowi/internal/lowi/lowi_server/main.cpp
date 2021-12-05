/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Starting module

GENERAL DESCRIPTION
  This file contains the implementation of LOWI Starting module

  Copyright (c) 2012-2013, 2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <base_util/log.h>

#include <base_util/postcard.h>
#include <mq_client/mq_client.h>

using namespace qc_loc_fw;

#include <lowi_server/lowi_controller.h>
#include <lowi_server/lowi_version.h>
#include "lowi_controller_extn.h"
#ifdef LOWI_ON_ACCESS_POINT
#include <mq_server/mq_server.h>
#endif

int main(int /*argc */, char** /* argv[] */)
{
  qc_loc_fw::log_set_global_tag(LOWI_VERSION);
  qc_loc_fw::log_set_global_level(qc_loc_fw::EL_INFO);
#ifdef LOWI_ON_ACCESS_POINT
  int log_level = qc_loc_fw::EL_LOG_OFF;
  mq_server_launch(LOWIUtils::to_logLevel(log_level));
#endif
  LOWIController* controller = new (std::nothrow)
             LOWIControllerExtn (MQ_SERVER_SOCKET_NAME, CONFIG_NAME);

  if ( (NULL != controller) && (0 == controller->init ()) )
  {
    controller->launch();
    controller->join ();
  }
  else
  {
    log_error ("main", "Unable to initialize the LOWIController");
  }
  delete controller;
  controller = 0;
  return 0;
}
