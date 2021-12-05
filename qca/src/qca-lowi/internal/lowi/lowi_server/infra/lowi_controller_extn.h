#ifndef __LOWI_CONTROLLER_EXTN_H__
#define __LOWI_CONTROLLER_EXTN_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Controller Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Controller

Copyright (c) 2012-2013, 2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.

=============================================================================*/


#include <lowi_server/lowi_controller.h>
namespace qc_loc_fw
{

/**
 * This class extends the main controller of LOWI
 */
class LOWIControllerExtn : public LOWIController
{
private:
public:
  /**
   * Constructor
   * @param char*:  Name of the server socket to connect to
   * @param char*:  Name with path of the config file
   */
  LOWIControllerExtn(const char * const socket_name,
      const char * const config_name)
  : LOWIController (socket_name, config_name)
  {
  }
  /** Destructor*/
  virtual ~LOWIControllerExtn()
  {
  }


};

} // namespace
#endif //#ifndef __LOWI_CONTROLLER_EXTN_H__
