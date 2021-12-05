/*
* Copyright (c) 2017-2018 Qualcomm Innovation Center, Inc.
*
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/
#ifndef _WIFISTATS_H_
#define _WIFISTATS_H_

#include <netinet/in.h>
#include <arpa/inet.h>
#include <qcatools_lib.h>

/* struct wifistats_module - wifistats module plugin functions
 * @next: Next module in the list (internal)
 * @help: Help print
 * @input_validate: Validate input arguments
 * @input_buff_alloc: Allocate buffer for driver input
 * @input_parse: Parse the command line input into the input buffer
 * @input_cookie_generate: Generate cookie to be placed in input
 * @ouput_handler: Print the Output buffer contents after parsing
 * @output_cookie_get: Get the cookie from the output buffer
 * @output_print_tlv: Print a single TLV within the output buffer
 * @output_get_buf_start: Gets the start of the output buffer after skipping
 *                        the protocol header
 * @output_tlv_length: Returns the TLV length for the TLV buffer given
 * @timeout: Maximum time by which all buffers should arrive from the driver
 * @output_fp: File pointer where output should be printed.  NULL implies stdout
 * @tlv_hdr_len: Length of the TLV header for the specific protocol
 */
struct wifistats_module {
    struct wifistats_module *next;
    char *name;
    void (*help) (int argc, char *argv[]);
    int (*input_validate) (int argc, char *argv[]);
    void * (*input_buff_alloc) (int *size);
    int (*input_parse) (void *, int argc, char *argv[], int *parsed_len, int pdev_id);
    void (*input_buff_free) (void *);
    int (*input_cookie_generate) (void);
    int (*output_handler) (void *, int len);
    int (*output_cookie_get) (void *, int len);
    void (*output_print_tlv)(void *tlv_ptr);
    void *(*output_get_buf_start)(void *buff, int32_t *len, int *listen_done);
    int (*output_tlv_length)(void *tlv);
    int timeout; /* timeout value in milli seconds */
    FILE *output_fp;
    int tlv_hdr_len;
};

int wifistats_module_register (struct wifistats_module *module, int size);
int wifistats_module_unregister (struct wifistats_module *module, int size);
int  extract_mac_addr(uint8_t *addr, const char *text);

enum LISTEN_STATUS {
    LISTEN_CONTINUE = 0,
    LISTEN_DONE,
};

typedef enum {
        HTT_FW_STATS        = 0,
        WMI_FW_STATS        = 1,
        MAX_FW_STATS_ID,
} wifistats_fw_moduleid;

enum ath_param {
     OL_ATH_PARAM_GET_TARGET_PDEV_ID = 447,
};

#define IEEE80211_ADDR_LEN 6

#define A_ASSERT(expr)  \
    if (!(expr)) {   \
        errx(1, "Debug Assert Caught, File %s, Line: %d, Test:%s \n",__FILE__, __LINE__,#expr); \
    }
#endif /*_WIFISTATS_H_*/
