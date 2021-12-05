/* @File:   common-lib.h
 * @Notes:  This Header file has inclusion of other standard library header files,
 *          useful macro definition, enum declaration used by the memory debug library
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#ifndef QCA_SON_MEM_DBG_COMMON_H
#define QCA_SON_MEM_DBG_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

/* SON_CLI include files */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#define MAC_ADDRESS_SIZE 6
#define SON_FUNC_NAME_LENGTH 48
#define MAX_VMDATA 10
#define OUTPUT_FILE_NAME_LEN 48
#define PROC_CMD_LINE_FILE_LEN 48
#define PROC_CMD_LINE_DATA_LEN 128
#define INFO_TMP_DIR "/tmp/sonmeminfo"
#define DBG_TMP_DIR "/tmp/sonmemdbg"
#define GRAPH_TMP_DIR "/tmp/sonmemgraph"

#define SON_MEM_DEBUG_FREE              // Enable this macro to keep track of last N freed memory information (N - configurable through /etc/config/<app> file)

enum mem_debug_mode
{
    ENABLE_FEATURE = 0,
    DEBUG_ALLOC_LIST = 1,
    DEBUG_FREE_LIST = 2,
    DEBUG_FILTER_LIST = 3
};

#define CHECK_BIT_ENABLED(data, bit_pos) \
    (data & (1 << bit_pos) )

enum log_mode
{
    REPORT_MEMINFO = 0,
    REPORT_GRAPH = 1,
    REPORT_DBG_OUTPUT = 2
};

#define print_mem_info \
    if (CHECK_BIT_ENABLED(g_enableloggingtofile, REPORT_MEMINFO) ) fprintf

#define dbg_print \
    if (CHECK_BIT_ENABLED(g_enableloggingtofile, REPORT_DBG_OUTPUT) ) fprintf

#define graph_print \
    if (CHECK_BIT_ENABLED(g_enableloggingtofile, REPORT_GRAPH) ) fprintf

#define debug_printf \
    if (CHECK_BIT_ENABLED(g_enableloggingtofile, REPORT_DBG_OUTPUT)) printf

/* SON_CLI Declarations (meminfo.h copied) */

#define SOCK_DATA_MAX_LINE 1024
#define APP_CONFIG_LEN 20
#define CAT_CMD_LEN 4
#define OUTPUT_FILE_NAME_LEN 48
#define MAX_MEMINFO_REQ_RETRANSMIT 5
#define RETRANSMIT_WAITTIME 200*1000    // 200 ms
#define INVALID_PORT_NUM 0

/* SON CLI variable */
typedef struct memdbg_data {
        char output_file[OUTPUT_FILE_NAME_LEN];
}memdbg_data_t;

/* Port numbers used for communication with memory debug library */
#define SON_CLI_PORT 8810
#define SON_CLI_WSPLCD_LAN_PORT 8811
#define SON_CLI_WSPLCD_GUEST_PORT 8812
#define SON_CLI_HYD_LAN_PORT 8813
#define SON_CLI_HYD_GUEST_PORT 8814
#define SON_CLI_LBD_PORT 8815

/* SON-CLI Declarations (meminfo.h copied) */

#define MEMDBG_ADD_FPRINTF_TRACE \
    fprintf(dbg_op, "%s %d\n", __func__, __LINE__); fflush(dbg_op);
#define MEMDBG_ADD_FPRINTF_TRACE_INT(x) \
    fprintf(dbg_op, "%s %d %d\n", __func__, __LINE__, x); fflush(dbg_op);
#define MEMDBG_ADD_FPRINTF_TRACE_STR(x) \
    fprintf(dbg_op, "%s %d %s\n", __func__, __LINE__, x); fflush(dbg_op);
#define MEMDBG_ADD_FPRINTF_TRACE_PTR(x) \
    fprintf(dbg_op, "%s %d %p\n", __func__, __LINE__, x); fflush(dbg_op);

#define MEMDBG_ADD_FPRINTF_TRACE_GRAPH \
    fprintf(graph_op, "%s %d\n", __func__, __LINE__); fflush(dbg_op);


#define MEMDBG_ADD_PRINTF_TRACE \
    printf( "%s %d\n", __func__, __LINE__);
#define MEMDBG_ADD_PRINTF_TRACE_INT(x) \
    printf( "%s %d %d\n", __func__, __LINE__, x);
#define MEMDBG_ADD_PRINTF_TRACE_PTR(x) \
    printf( "%s %d %p\n", __func__, __LINE__, x);
#define MEMDBG_ADD_PRINTF_TRACE_STR(x) \
    printf("%s %d %s\n", __func__, __LINE__, x);


#endif /* QCA_SON_MEM_DBG_COMMON_H */
