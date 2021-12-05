/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
        LOWI SPARROW ranging functionality header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  Sparrow driver LOWI Ranging Object and supporting classes

  Copyright (c) 2017-2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_SPARROW_RANGING_H__
#define __LOWI_SPARROW_RANGING_H__

#include <lowi_server/lowi_internal_message_listener.h>
#include "lowi_ranging.h"

namespace qc_loc_fw
{

/** Subclass of LOWIRanging specific for the sparrow wigig driver. It
 *  handles all the rtt and AoA requests and the parsing of the
 *  messages coming from the wigig driver */
class LOWISparrowRanging : public LOWIRanging
{

public:

  /**
   * Creates and initializes the LOWIRanging object
   * @param LOWIInternalMessageReceiverListener: internal msg listener
   * @return LOWIRanging *: ptr to LOWIRanging object if success, else NULL
   */
  static LOWIRanging * createInstance(LOWIInternalMessageReceiverListener *internalMessageListener)
  {
    return NULL;
  }

  /** Constructor */
  LOWISparrowRanging()
  {
  }

  /** Destructor */
  virtual ~LOWISparrowRanging()
  {
  }
};


} // namespace qc_loc_fw
#endif // __LOWI_SPARROW_RANGING_H__
