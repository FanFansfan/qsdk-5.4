/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Background Scan Manager

GENERAL DESCRIPTION
  This file contains the class definition for the LOWIBackgroundScanMgr class
  used to handle background scan requests

Copyright (c) 2015-2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/

#ifndef __LOWI_BACKGROUND_SCAN_MGR_H__
#define __LOWI_BACKGROUND_SCAN_MGR_H__

#include "lowi_diag_log.h"

namespace qc_loc_fw
{

// Provides just the stub implementation
class LOWIBackgroundScanMgr
{
public:
  /**
   * Constructor takes a lowi-controller object so that the
   * background scan manager can call lowi-controller functions
   *
   * @param pController : lowi controller object
   */
  LOWIBackgroundScanMgr(LOWIController* /*pController*/)
  {}

  /** Destructor */
  ~LOWIBackgroundScanMgr()
  {}

  /**
   * This function is called by the lowi controller. It's the entry point into
   * the BSM. It takes the input message into the lowi
   * controller and passes it to the BSM to process the ranging requests and
   * responses
   *
   * @param msg : message to be handled
   *
   * @return bool : true: BSM managed the msg, false: BSM did not
   *         managed the msg
   */
  bool bsmManageMsg(LOWILocalMsg* /*msg*/)
  { return false;}

  /**
   * Handles a request that was not successfully sent to the wifi driver from
   * LOWI-controller.
   *
   * @param req: LOWI request that could not be sent
   * @param scan_status: scan status passed in the response to the client
   */
  void manageErrRsp(LOWIRequest* /*req*/, LOWIResponse::eScanStatus /*scan_status*/)
  {}
};
} // namespace qc_loc_fw

#endif // __LOWI_BACKGROUND_SCAN_MGR_H__
