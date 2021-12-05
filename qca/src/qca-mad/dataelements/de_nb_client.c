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

#include "de_nb_client.h"


/**
 * @brief Frame the request in HTTP format
 *
 * @param [in] query  the query provided by the client
 * @param [inout] request  the HTTP request generated from the query
 *
 */
void frame_request(char *query, char *request)
{
    strlcpy(request, "GET /", DATA_LEN_MAX);
    strlcat(request, query, DATA_LEN_MAX);
    strlcat(request, " HTTP/1.1", DATA_LEN_MAX);
}

/**
 * @brief Creates the north bound client socket
 *
 * @param [in] query  the query provided by the client
 *
 * return 0 on success. Otherwise return 1.
 */
int create_client_socket(char *query)
{
    int Socket;
    struct sockaddr_in serv_addr, address;

    char *buffer = NULL;
    char request[DATA_LEN_MAX] = {0};
    int status = 0, ret = 0;
    int serv_len = 0;

    if ((Socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        fprintf(stdout, "\n Socket creation error \n");
        status = 1;
        goto ret;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(PORT);
    serv_len = sizeof(serv_addr);

    if(bind(Socket, (const struct sockaddr *)&serv_addr,
            sizeof(serv_addr)) < 0 )
    {
        fprintf(stdout,"bind failed\n");
        status = 1;
        goto ret;
    }


    frame_request(query, request);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(SERV_PORT);

    sendto(Socket, (const char *)request, strlen(request), MSG_CONFIRM, (const struct sockaddr *) &address, sizeof(address));

    buffer = malloc(DATA_LEN_MAX);
    if (buffer == NULL) {
        fprintf(stdout, "\n Memory allocation falied \n");
        status = 1;
        goto ret;
    } else {
        memset(buffer, 0, DATA_LEN_MAX);
    }

    ret = recvfrom(Socket, buffer, DATA_LEN_MAX, MSG_WAITALL/*0*/, (struct sockaddr *) &serv_addr, (socklen_t *)&serv_len);
    if (ret != -1) {
        fprintf(stdout, "%s", buffer);
    } else {
        perror("recvfrom failed");
    }

    free(buffer);
    close(Socket);

ret:
    return status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
//// North Bound Client Socket  -- Entry point
//////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    char query[100] = {0};

    strlcpy(query, argv[1], sizeof(query));

    return create_client_socket(query);
}
