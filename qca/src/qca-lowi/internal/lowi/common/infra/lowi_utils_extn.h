#ifndef __LOWI_UTILS_EXTN_H__
#define __LOWI_UTILS_EXTN_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Utils Interface Extension Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Utils Extension

  Copyright (c) 2012-2013, 2015-2016,2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.

  (c) 2012-2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.
=============================================================================*/

#include <base_util/postcard.h>
#include <inc/lowi_const.h>
#include <inc/lowi_request.h>
#include <inc/lowi_response.h>


namespace qc_loc_fw
{

/**
 * Utility Extension Class
 */
class LOWIUtilsExtn
{
private:

public:
  /**
   * Log TAG
   */
  static const char * const TAG;

  /**
   * This API is an extension to the requestToOutPostCard API in LOWIUtils
   * Populates an OutPostCard from the Request created by the client.
   *
   * Note: Memory should be deallocated by the client
   *
   * @param LOWIRequest* Request to be converted to an OutPostCard
   * @param OutPostcard& Reference to the OutPostcard to be updated with information
   *        from the LOWIRequest
   * @return bool true if request is handled false otherwise
   */
  static bool requestToOutPostcard (LOWIRequest* const /*request*/,
                                    OutPostcard& /*card*/)
  {
    return true;
  }

  /**
   * This API is an extension to the inPostcardToResponse API in LOWIUtils
   * Parses an InPostCard and generates the Response needed by the client.
   *
   * Note: Memory should be deallocated by the client
   *
   * @param InPostcard& Reference to InPostcard to be parsed
   * @param LOWIResponse** Pointer to pointer to the newly created Response.
   *                      Client should free the memory for this
   *                      NULL if unable to handle the InPostcard
   * @return bool true if InPostcard was parsed and a response is generated,
   *              false otherwise
   */
  static bool inPostcardToResponse (InPostcard& /*postcard*/, LOWIResponse** /*response*/)
  {
    return true;
  }

  /**
   * This API is an extension to the inPostcardToRequest API in LOWIUtils
   * Creates a Request from a InPostcard
   * Used by the LOWI server to parse the InPostcard and create a Request
   * @param InPostcard& Reference to the Postcard to be parsed
   * @param LOWIRequest** Pointer to pointer to LOWIRequest if the card is parsed and request
   *                     is handled. NULL otherwise. Client needs to delete the
   *                     allocated memory
   * @return bool true if success, false otherwise
   */
  static bool inPostcardToRequest (InPostcard& /*card*/, LOWIRequest** /*request*/)
  {
    return true;
  }

  /**
   * This API is an extension to the responseToOutPostcard API in LOWIUtils
   * Parses a response to create the OutPostcard
   * Used by the LOWI server to create a OutPostcard to be sent to the Hub.
   *
   * NOTE: Client is responsible to free the memory allocated for OutPostcard
   *
   * @param LOWIResponse* Response for which the Postcard is to be created
   * @return OutPostcard* Creates the post card from LOWIResponse
   */
  static OutPostcard* responseToOutPostcard(LOWIResponse* /*resp*/)
  {
    return NULL;
  }
};

} // namespace qc_loc_fw

#endif //#ifndef __LOWI_UTILS_EXTN_H__
