#ifndef __LOWI_LP_SCAN_RESULT_RECEIVER_H__
#define __LOWI_LP_SCAN_RESULT_RECEIVER_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Low Power Scan Result Receiver Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI LP Scan Result Receiver


Copyright (c) 2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/

#include <base_util/sync.h>
#include <inc/lowi_request.h>
#include <inc/lowi_response.h>
#include "lowi_measurement_result.h"
#include <lowi_server/lowi_scan_result_receiver.h>

namespace qc_loc_fw
{

  struct LowiLpRequest
  {
    uint16 requestId;
    LOWIRequest* request;
    public:
    /**
     * Constructor
     *
     * @param uint16: unique request id for each request
     * @param LOWIRequest*: lowi request.
     */
    LowiLpRequest(uint16 /*requestid*/, LOWIRequest* /*req*/)
    {}
  };
/**
 * This class provides the mechanism to get the scan measurements
 * from LOWI LP.
 * It's responsibility is to receive the results and provide the results
 * to it's listener. It's responsibility is to convert the data between
 * LOWI structures to LOWIQMIClient structures and pass the request and
 * responses. Also provides the mechanism to notify the listener when the
 * communication is lost with the QMI service and tries to reestablish the
 * connection.
 */
class LOWILPScanResultReceiver : public LOWIScanResultReceiver
{
private:
  List<LowiLpRequest*>              mLowiLpRequestList;

  friend class LOWIController;

public:

  /**
   * Executes LOWIRequest.
   * @param LOWIRequest*               LOWIRequest for which the
   *                                   scan is to be performed
   * @return bool true is success, false otherwise
   */
  virtual bool execute (LOWIRequest* /*request*/)
  { return false;}

  /**
   * Constructor
   * @param LOWIScanResultReceiverListener* listener to be notified
   *                                   with measurement results.
   * @param LOWIWifiDriverInterface* WifiDriverInterface to be used by
   *                                   LOWIScanResultReceiver for listening
   *                                   to the scan measurements.
   *                                   This param is not used in because the
   *                                   listening is done with LOWI LP.
   */
  LOWILPScanResultReceiver(LOWIScanResultReceiverListener* listener,
                           LOWIWifiDriverInterface* interface = NULL)
  : LOWIScanResultReceiver (listener, interface)
  {}

  /** Destructor*/
  virtual ~LOWILPScanResultReceiver()
  {}

};
} // namespace
#endif //#ifndef __LOWI_LP_SCAN_RESULT_RECEIVER_H__
