#ifndef __LOWI_RESPONSE_EXTN_H__
#define __LOWI_RESPONSE_EXTN_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Response Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWIResponse

Copyright (c) 2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
namespace qc_loc_fw
{

/**
 * Response containing channel info supported by the wifi driver
 */
////////////////////////////////////////
// LOWIRMChannelResponse
//  LOWI RTT Response Mode(RM) Channel Response
////////////////////////////////////////
class LOWIRMChannelResponse : public LOWIResponse
{
public:
  /**
   * Returns the response type
   * @return eResponseType: type of response
   */
  eResponseType getResponseType()
  {
    return LOWI_RTT_RM_CHANNEL_RESPONSE;
  }
};
} // namespace qc_loc_fw

#endif //#ifndef __LOWI_RESPONSE_EXTN_H__
