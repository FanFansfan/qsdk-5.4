#ifndef __LOWI_STRINGS_H__
#define __LOWI_STRINGS_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Strings Header file

GENERAL DESCRIPTION
  This file contains the Class and Function Prototypes for
  Strings used in LOWI Logs

Copyright (c) 2016-2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/

#include <lowi_ranging.h>
#include <lowi_ranging_fsm.h>
#include <lowi_p2p_ranging.h>
#include <lowi_controller.h>

namespace qc_loc_fw
{

// The below macro is the format to log LOWI Request info
#define LOWI_REQINFO_FMT "%s_%u"
// The below macro is to log the LOWI request info with originator and request id.
// with the above given format (LOWI_REQINFO_FMT) macro
// This macro with take the input(r) as LOWIRequest pointer.
// The LOWIRequest pointer should not be NULL when using this macro
#define LOWI_REQINFO(r) \
  ((r)->getRequestOriginator() == NULL ? "" : (r)->getRequestOriginator()), (r)->getRequestId()

#define QUIPC_MACADDR_FMT LOWI_MACADDR_FMT
#define QUIPC_MACADDR     LOWI_MACADDR
/**
 * Strings Utility Class
 */
class LOWIStrings
{
public:

    /* The following functions convert enumerations to Strings */
    static char const* rtt_pkt_type_to_string(uint8 a);
    static char const* rtt_preamble_type_to_string(uint8 a);
    static char const* cld_ani_msg_type_to_string(uint8 a);
    static char const* to_string(WMIRTT_OEM_MSG_SUBTYPE a);
    static char const* to_string(RomeNlMsgType a);
    static char const* to_string(WMI_RTT_STATUS_INDICATOR a);
    static char const* to_string(peer_status_t a);
    static char const* to_string(p2p_peer_cap_t a);
    static char const* to_string(RangingFSM_Event a);
    static char const* to_string(RangingFSM_State a);
    static char const* to_string(eRttType a);
    static char const* to_string(eNodeType a);
    static char const* to_string(eRequestStatus a);
};

} // namespace qc_loc_fw

#endif //#ifndef __LOWI_STRINGS_H__
