/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

                  LOWI Debug Message Interface Header File

GENERAL DESCRIPTION
  This file contains the structure definitions and function prototypes for
  the debugging message interface for LOWI software.

Copyright (c) 2013, 2016,2018 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.

(c) 2013 Qualcomm Atheros, Inc.
  All Rights Reserved.
  Qualcomm Atheros Confidential and Proprietary.
=============================================================================*/
#ifndef _LOWI_LOG_H_
#define _LOWI_LOG_H_

/*=============================================================================================
                                  Debug message module
             This portion of the header file will need to be updated for each OS
 =============================================================================================*/
#ifndef LOG_NDEBUG
#define LOG_NDEBUG 0
#endif

#include <base_util/log.h>


extern int lowi_debug_level;

#define LOWI_LOG_ERROR(...) { log_error(LOG_TAG, __VA_ARGS__); }

#define LOWI_LOG_WARN(...) { log_warning(LOG_TAG, __VA_ARGS__); }

#define LOWI_LOG_INFO(...) { log_info(LOG_TAG, __VA_ARGS__); }

#define LOWI_LOG_DBG(...) { log_debug(LOG_TAG, __VA_ARGS__); }

#define LOWI_LOG_VERB(...) { log_verbose(LOG_TAG, __VA_ARGS__); }

#endif /* _LOWI_LOG_H_ */
