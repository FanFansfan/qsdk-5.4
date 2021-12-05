#ifndef __LOWI_SCAN_RESULT_LISTENER_H__
#define __LOWI_SCAN_RESULT_LISTENER_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Scan Result Listener Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Scan Result Listener

  Copyright (c) 2014, 2016, 2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc

=============================================================================*/
#include <lowi_server/lowi_event_receiver.h>

namespace qc_loc_fw
{

class LOWIScanResultReceiverListener {
public:
  /** Destructor */
  virtual ~LOWIScanResultReceiverListener ()
  {

  }

  /**
   * Notifies to the listener that the scan measurement results
   * are received
   * @param LOWIMeasurementResult* Scan measurements results
   */
  virtual void scanResultsReceived(LOWIMeasurementResult* result) = 0;
  /**
   * Notifies to the listener about the wireless interface state changes
   * @param LOWIDriverInterface &: driver interface info
   */
  virtual void intfStateReceived(LOWIDriverInterface &result) = 0;
};

} // namespace
#endif //#ifndef __LOWI_SCAN_RESULT_RECEIVER_H__
