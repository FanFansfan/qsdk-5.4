/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI TEST DEFINES

GENERAL DESCRIPTION
  This file contains the definitions for LOWI TEST

Copyright (c) 2016-2019, 2021 Qualcomm Technologies, Inc.
All Rights Reserved.
Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#ifndef __LOWI_TEST_DEFINES_H__
#define __LOWI_TEST_DEFINES_H__

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>



/* Max Number of measurements for RTS/CTS or in AP list */
#define MAX_BSSIDS_ALLOWED_FOR_RANGING_SCAN 50
/* Data file and Summary file location */
#ifndef LOWI_ON_LE
#ifndef ROOT_DIR
#define LOWI_OUT_FILE_NAME "/usr/share/location/lowi/lowi_ap_res.csv"
#define LOWI_SUMMARY_FILE_NAME "/usr/share/location/lowi/lowi_ap_summary.csv"
#define DEFAULT_AP_LIST_FILE "/usr/share/location/lowi/ap_list.xml"
#define LOWI_OUT_CFR_FILE_NAME "/usr/share/location/lowi/lowi_ap_cfr.csv"
#define LOWI_KPI_LOG_FILE "/usr/share/location/lowi_kpi_logs.txt"
#else
#define LOWI_OUT_FILE_NAME     ROOT_DIR "lowi/lowi_ap_res.csv"
#define LOWI_SUMMARY_FILE_NAME ROOT_DIR "lowi/lowi_ap_summary.csv"
#define DEFAULT_AP_LIST_FILE   ROOT_DIR "lowi/ap_list.xml"
#define LOWI_OUT_CFR_FILE_NAME ROOT_DIR "lowi/lowi_ap_cfr.csv"
#define LOWI_KPI_LOG_FILE "lowi/lowi_kpi_logs.txt"
#endif
#else
#define LOWI_OUT_FILE_NAME "/data/vendor/location/lowi_ap_res.csv"
#define LOWI_SUMMARY_FILE_NAME "/data/vendor/location/lowi_ap_summary.csv"
#define DEFAULT_AP_LIST_FILE "/data/vendor/location/ap_list.xml"
#define LOWI_OUT_CFR_FILE_NAME "/data/vendor/location/lowi_ap_cfr.csv"
#define LOWI_KPI_LOG_FILE "/data/vendor/location/lowi_kpi_logs.txt"
#endif
// Not using Wake lock
#define LOWI_TEST_REQ_WAKE_LOCK
#define LOWI_TEST_REL_WAKE_LOCK

#endif /* __LOWI_TEST_DEFINES_H__ */
