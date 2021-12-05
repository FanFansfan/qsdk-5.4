/* @File:   meminfo.h
 *
 * @Notes:
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#ifndef MEMINFO_H
#define MEMINFO_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#define SOCK_DATA_MAX_LINE 1024
#define APP_CONFIG_LEN 16
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


#define debug_print \
    if (enable_debug) printf

struct user_input_data;


/* Function Prototypes */
void send_meminfo_request_to_memlib(struct user_input_data *input);
void receive_meminfo_from_memlib();
void retrieve_mem_info(struct user_input_data *input);

#endif
