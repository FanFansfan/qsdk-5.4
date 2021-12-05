#ifndef __LOWI_RANGING_DEFINES_H
#define __LOWI_RANGING_DEFINES_H
/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
GENERAL DESCRIPTION
   This file contains includes and definitions used by the Ranging functionality.

   Copyright (c) 2016,2018-2019 Qualcomm Technologies, Inc.
   All Rights Reserved.
   Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include "lowi_nl80211.h"

using namespace qc_loc_fw;

// Maximum RTT measurements per target for Aggregate report type
#define MAX_RTT_MEAS_PER_DEST 25

/* Netlink socket protocol to communicate qca wifi */
#define NETLINK_LOWI NETLINK_USERSOCK

#define RTT2_OFFSET (0)

#endif /* __LOWI_RANGING_DEFINES_H */

