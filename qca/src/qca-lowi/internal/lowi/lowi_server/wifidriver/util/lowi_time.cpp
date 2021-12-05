/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Time module

GENERAL DESCRIPTION
  This file contains the declaration and some global constants for Time
  module.

  Copyright (c) 2013, 2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc

=============================================================================*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <base_util/time_routines.h>

#include "lowi_time.h"
#include <lowi_server/lowi_log.h>
#include <base_util/time_routines.h>
#undef LOG_TAG
#define LOG_TAG "LOWI-Scan"

using namespace qc_loc_fw;

pthread_mutex_t mutex;

int lowi_time_init()
{
  return pthread_mutex_init(&mutex, NULL);
}

int lowi_time_close()
{
  return pthread_mutex_destroy(&mutex);
}

uint64 lowi_get_time_from_boot()
{
  uint64 cur_time_ms = 0;
  cur_time_ms = get_time_boot_ms();
  pthread_mutex_lock(&mutex);
  static uint64 prev_time_ms = 0;

  if ( (prev_time_ms == 0) || (cur_time_ms > prev_time_ms) )
  {
    // Prev time uninitialized or time moving forward
    prev_time_ms = cur_time_ms;
  }
  else if (cur_time_ms < prev_time_ms)
  {
    // Time moved backwards
    LOWI_LOG_WARN("Time moved backwards, last = %" PRId64 ", now = %" PRId64 "\n",
        prev_time_ms, cur_time_ms);
    cur_time_ms = prev_time_ms;
  }
  pthread_mutex_unlock(&mutex);
  return cur_time_ms;
}
