/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

        LOWI Test Extension

GENERAL DESCRIPTION
  This file contains the Implementation for LOWI test Extension

Copyright (c) 2016-2018 Qualcomm Technologies, Inc.
  All Rights Reserved.
  Confidential and Proprietary - Qualcomm Technologies, Inc.
=============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <inc/lowi_client.h>
#include <lowi_wrapper.h>
#include "lowi_request_extn.h"
#include "lowi_response_extn.h"
#include "lowi_test_defines.h"
#include "lowi_test_internal.h"

#include "lowi_utils.h"


using namespace qc_loc_fw;

extern t_lowi_test lowi_test;
extern t_lowi_test_cmd* lowi_cmd;

int lowi_test_extn_response_callback(LOWIResponse *response)
{
  return -1;
}


// Table of function pointers
lowi_test_func lowi_test_function [LOWI_MAX_SCAN] =
{
    lowi_test_do_passive_scan,          // LOWI_DISCOVERY_SCAN
    lowi_test_do_rtt_scan,              // LOWI_RTS_CTS_SCAN
    lowi_test_do_combo_scan,            // LOWI_BOTH_SCAN
    lowi_test_do_async_discovery_scan,  // LOWI_ASYNC_DISCOVERY_SCAN
    NULL,                               // LOWI_BATCHING
    NULL,                               // LOWI_ANQP_REQ
    lowi_test_do_neighbor_report_request, // LOWI_NR_REQ
    NULL,     // LOWI_UART_TEST_REQ
    lowi_test_do_wlan_state_query_request, // LOWI_WSQ_REQ
    lowi_test_set_lci,                  // LOWI_SET_LCI
    lowi_test_set_lcr,                  // LOWI_SET_LCR
    lowi_test_where_are_you,            // LOWI_WRU_REQ
    lowi_test_ftmrr,                    // LOWI_FTMR_REQ
    lowi_test_config_req,               // LOWI_CONFIG_REQ
};
