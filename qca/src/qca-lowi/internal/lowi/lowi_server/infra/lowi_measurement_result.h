#ifndef __LOWI_MEASUREMENT_RESULT_H__
#define __LOWI_MEASUREMENT_RESULT_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Measurement Result Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Measurement Result

Copyright (c) 2012, 2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc

(c) 2012 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/

#include <base_util/postcard.h>
#include <inc/lowi_const.h>
#include <inc/lowi_scan_measurement.h>
#include <inc/lowi_response.h>
#include "lowi_scan_measurement_extn.h"
#include "lowi_response_extn.h"
#include "lowi_measurement_result_base.h"

namespace qc_loc_fw
{
/**
 * This class defines the measurement taken for every scan request.
 * This contains the measurements corresponding the discovery, ranging
 * and background scan requests. However, the fields are valid /
 * invalid based on type of scan as documented below.
 */
class LOWIMeasurementResult : public LOWIMeasurementResultBase
{
private:

public:

  virtual ~LOWIMeasurementResult ()
  {
  }

  /**
   * Constructor
   * @param bool Indicates, if the result is generated from LOWI-LP
   */
  LOWIMeasurementResult (bool result_from_lowi_lp = false)
  : LOWIMeasurementResultBase (result_from_lowi_lp)
  {
  }

  /**
   * Deletes an instance of type LOWIMeasurementResult.
   *
   * @param LOWIMeasurementResult *: instance to be deleted
   */
  static void deleteInstance(LOWIMeasurementResult *meas_result)
  {
    do
    {
      if (NULL == meas_result)
      {
        break;
      }

      for (uint32 ii = 0; ii < meas_result->scanMeasurements.getNumOfElements(); ++ii)
      {
        delete meas_result->scanMeasurements[ii];
      }
    } while (0);

    delete meas_result;
  } // deleteInstance

};

} // namespace qc_loc_fw

#endif //#ifndef __LOWI_MEASUREMENT_RESULT_H__
