/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

   NL80211 Interface for Helium ranging extension

   GENERAL DESCRIPTION
   This component performs ranging scan with NL80211 Interface.

Copyright (c) 2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/

#define LOG_NDEBUG 0
#include <lowi_server/lowi_log.h>
#include <common/lowi_utils.h>
#include "lowi_diag_log.h"
#include "lowi_wifi_tlv_handler.h"
#include "lowi_helium_ranging.h"
#include "lowi_ranging_fsm.h"
#include "lowi_p2p_ranging.h"

using namespace qc_loc_fw;

int LOWIHeliumRanging::ParseResponderChannelMeas(char* /*measResp*/, LOWIRMChannelResponse* /*channelresponse*/)
{
  return -1;
} // ParseResponderChannelMeas

int LOWIHeliumRanging::ParseResponderChannelInfoMsg(vector<LOWITlv *>& /*tlvs*/, LOWIRMChannelResponse& /*channelresponse*/)
{
  return -1;
} //parseResponderChannelInfoMsg
