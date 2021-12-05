#ifndef __LOWI_UTILS_DEFINES_H
#define __LOWI_UTILS_DEFINES_H
/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*
GENERAL DESCRIPTION
   This file contains includes and definitions used by the Utils functionality.

   Copyright (c) 2016-2018 Qualcomm Technologies, Inc.
   All Rights Reserved.
   Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/

#include <stdint.h>
#include <net/if.h>

#define ifr_name    ifr_ifrn.ifrn_name    /* interface name     */

// This is some random value
#define PROPERTY_VALUE_MAX 92

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 256
#endif

#endif /* __LOWI_UTILS_DEFINES_H */

