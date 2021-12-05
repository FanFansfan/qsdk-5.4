#ifndef __LOWI_WIGIG_RANGING_SCAN_RESULT_RECEIVER_H__
#define __LOWI_WIGIG_RANGING_SCAN_RESULT_RECEIVER_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Wigig Ranging Scan Result Receiver Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Wigig Ranging Scan Result Receiver

  Copyright (c) 2017-2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <base_util/sync.h>
#include <inc/lowi_request.h>
#include <inc/lowi_response.h>
#include <lowi_measurement_result.h>
#include <lowi_scan_result_receiver.h>

namespace qc_loc_fw
{

/**
 * This class provides the mechanism to get the ranging scan measurements
 * from the wigig Driver. It is run in a separate thread. It's
 * responsibility is twofold:
 * 1. to receive the results from the wigig driver and provide the
 * results to it's listener.
 * 2. to receive ranging requests and pass them to the FSM for
 * processing.
 * The thread normally will block on a select call waiting for a ranging
 * scan requests or results. Upon receiving a new ranging request, the
 * thread unblocks and issues the request to WLAN drive.
 */
class LOWIWigigRangingScanResultReceiver : public LOWIScanResultReceiver
{
private:
  static const char * const TAG;

protected:

public:

  /**
   * Constructor
   *
   * @param listener : listener to be notified with measurement results.
   * @param interface : driver interface to be used by
   *                  LOWIWigigRangingScanResultReceiver for listening to the
   *                  scan measurements.
   */
  LOWIWigigRangingScanResultReceiver(LOWIScanResultReceiverListener *listener,
                                     LOWIWifiDriverInterface *interface);

  /** Destructor */
  virtual ~LOWIWigigRangingScanResultReceiver();
};

} // namespace
#endif //#ifndef __LOWI_WIGIG_RANGING_SCAN_RESULT_RECEIVER_H__
