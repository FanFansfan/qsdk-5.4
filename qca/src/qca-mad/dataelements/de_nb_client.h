/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */


/* C and system library includes */
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>

#define DATA_LEN_MAX 1024
#define PORT 8091
#define SERV_PORT 8090

/**
 * @brief Frame the request in HTTP format
 *
 * @param [in] query  the query provided by the client
 * @param [inout] request  the HTTP request generated from the query
 *
 */
void frame_request(char *query, char *request);


/**
 * @brief Creates the north bound client socket
 *
 * @param [in] query  the query provided by the client
 *
 * return 0 on success. Otherwise return 1.
 */
int create_client_socket(char *query);
