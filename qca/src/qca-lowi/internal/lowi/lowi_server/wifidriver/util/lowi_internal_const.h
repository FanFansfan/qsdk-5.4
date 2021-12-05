#ifndef __LOWI_INTERNAL_CONST_H__
#define __LOWI_INTERNAL_CONST_H__

/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Internal Const Interface Header file

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  LOWI Internal Const

  Copyright (c) 2016, 2018-2019 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc
=============================================================================*/
#ifdef __cplusplus
extern "C" {
#endif

namespace qc_loc_fw
{

#define WIPS_MAX_BSSIDS_TO_SCAN MAX_BSSIDS_ALLOWED_FOR_MEASUREMENTS
#define ERR_SELECT_TERMINATED -301
#define ERR_SELECT_TIMEOUT    -10
#define ERR_NOT_READY         -11
//! Note 123 is the random num, which would not be less then
//! number of fds the select is waiting on
#define SELECT_UBLOCKED_ON_MONSOCKET   123

/* Maximum number of BSSIDs to be output from passive scan from libwifiscanner module */
#define NUM_MAX_BSSIDS 75

/* This value is to indicate that cell power limit is not found within the beacon */
#define WPOS_CPL_UNAVAILABLE 0x7F

} // namespace qc_loc_fw
#endif //#ifndef __LOWI_INTERNAL_CONST_H__

#ifdef __cplusplus
}
#endif
