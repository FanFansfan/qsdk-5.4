/* @File:   meminfo.c
 *
 * @Notes:   *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

/* Client side implementation of UDP client-server model */
#include "meminfo.h"
#include "son_cli.h"

// Set this variable to Enable Debug Prints
int enable_debug = 0, meminfo_req_retransmit = 0, received_meminfo = 0;
struct memdbg_data m_data;

extern int soncli_pthread_create( pthread_t *thread, void * (*thread_cb)(void *data), void *arg );
/*
 * Send meminfo request to memory debug library until reply is received
 * for MAX_MEMINFO_REQ_RETRANSMIT times
 * and for every RETRANSMIT_WAITTIME interval
 */
void send_meminfo_request_to_memlib(struct user_input_data *input)
{
    int sockfd, ret = 0;
    struct sockaddr_in servaddr;
    int meminforeq = 1;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family    = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(input->memdbg_cli_port);

    meminfo_req_retransmit = 1;
    while (received_meminfo != 1) {
        debug_print("soncli:%s...%d [retransmit : %d]\n",__func__, __LINE__, meminfo_req_retransmit);
        ret = sendto(sockfd, (const char *)&meminforeq, sizeof(meminforeq),
            MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
        debug_print("soncli:%s...%d\n",__func__, __LINE__);

        if (ret < 0) {
            printf("%s: sendto failed!!!\n", __func__);
        } else {
            debug_print("soncli:%s: Sent to server !!!:%d\n", __func__, ret);
        }
        if (meminfo_req_retransmit >= MAX_MEMINFO_REQ_RETRANSMIT) {
            exit(0);
        }
        meminfo_req_retransmit++;
        usleep(RETRANSMIT_WAITTIME);    // 200 ms
    }
    close(sockfd);
}

/*
 * Receive acknowledgement from mem debug library for data ready
 */
void receive_meminfo_from_memlib()
{
    int sockfd = 0, ret = 0;
    struct sockaddr_in servaddr;
    socklen_t len = 0;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family    = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(SON_CLI_PORT);

    // Bind the socket with the server address
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,
            sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    debug_print("soncli:%s...%d\n",__func__, __LINE__);
    ret = recvfrom(sockfd, m_data.output_file, OUTPUT_FILE_NAME_LEN,
        MSG_WAITALL, (struct sockaddr*) &servaddr, &len );
    if (ret != -1) {
        received_meminfo = 1;
        m_data.output_file[ret]='\0';
        debug_print("soncli:Received [%s] from Server\n", m_data.output_file);
    } else {
        perror("recvfrom failed");
    }
    close(sockfd);
}

/*
 * Retrieve memory usage information - Send request and receive response
 */
void retrieve_mem_info(user_input_data_t *input)
{
    int ret = 0;
    char cmd[OUTPUT_FILE_NAME_LEN+CAT_CMD_LEN];
    pthread_t soncli_th;

    // Create thread to Receive acknowledgement from mem debug library for data ready
    ret = soncli_pthread_create(&soncli_th, (void*)receive_meminfo_from_memlib, NULL);
    if (ret != 0) {
        printf("%s: Error: soncli_pthread_create failed [%d]!!!\n", __func__, ret);
    }
    else {
        debug_print("thread created !!!\n");
    }

    if (input->memdbg_cli_port != 0 && input->memdbg_repeat_count > 0) {
        do {
            received_meminfo = 0;

            // Send meminfo request to SON application (retransmit until reply)
            send_meminfo_request_to_memlib(input);

            // prepare displaying file content
            debug_print("%s:%d: logfilename:%s \n", __func__, __LINE__, m_data.output_file );
            snprintf(cmd, OUTPUT_FILE_NAME_LEN+CAT_CMD_LEN, "cat %s", m_data.output_file);
            debug_print("%s: command execution: [%s]\n", __func__, cmd);

            // Print file content
            system(cmd);

            input->memdbg_repeat_count--;
            sleep ( input->memdbg_report_interval );
        }while (input->memdbg_repeat_count);
    }
}

