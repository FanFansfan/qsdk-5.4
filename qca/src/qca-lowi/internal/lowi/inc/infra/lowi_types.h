/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

                       LOWI Types Used

GENERAL DESCRIPTION
  This file contains the definition of common types that are used by various
  LOWI modules.

Copyright (c) 2010,2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

=============================================================================*/
#ifndef __LOWI_TYPES_H
#define __LOWI_TYPES_H

/* ------------------------------------------------------------------------
** Constants
** ------------------------------------------------------------------------ */

#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

#define TRUE   1   /* Boolean true value. */
#define FALSE  0   /* Boolean false value. */

#ifndef __ANDROID__
#define ALOGE printf
#define ALOGW printf
#define ALOGI printf
#define ALOGD printf
#define ALOGV printf
#endif

/*--------------------------------------------------------------------------
 * Type Declarations
 * -----------------------------------------------------------------------*/

typedef  uint8_t            boolean;     /* Boolean value type. */
typedef  uint32_t           uint32;      /* Unsigned 32 bit value */
typedef  uint16_t           uint16;      /* Unsigned 16 bit value */
typedef  uint8_t            uint8;       /* Unsigned 8  bit value */
typedef  int32_t            int32;       /* Signed 32 bit value */
typedef  int16_t            int16;       /* Signed 16 bit value */
typedef  int8_t             int8;        /* Signed 8  bit value */
typedef  int64_t            int64;       /* Signed 64 bit value */
typedef  uint64_t           uint64;      /* Unsigned 64 bit value */

/*********************** BEGIN PACK() Definition ***************************/
#ifndef PACK
#if defined __GNUC__
  #define PACK(x)       x __attribute__((__packed__))
#elif defined __arm
  #define PACK(x)       __packed x
#else
  #error No PACK() macro defined for this compiler
#endif
#endif // ifndef PACK
/********************** END PACK() Definition *****************************/
#endif /* __LOWI_TYPES_H */
