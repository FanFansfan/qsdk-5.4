/*
 * Copyright (c) 2018-2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */


/*
 * Common headerfiles across multiple applications are sourced from here.
 */
#ifndef _QCATOOLS_LIB_H_
#define _QCATOOLS_LIB_H_
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <qdf_types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#if UMAC_SUPPORT_CFG80211
#include <netlink/attr.h>
#include <nl80211_copy.h>
#include <cfg80211_nlwrapper_api.h>
#include <qca_vendor.h>
#endif
#include <sys/queue.h>

/* These are defined outside UMAC_SUPPORT_CFG80211 as
 * some data structures are used by functions common
 * to both cfg and wext
 */
#include <cfg80211_external.h>
#include <signal.h>
#include <if_athioctl.h>

/*
 * Common declarations are also sourced from here
 */

#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN  1234
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN 4321
#endif

#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#if BUILD_X86
struct cfg80211_data {
    void *data; /* data pointer */
    unsigned int length; /* data length */
    unsigned int flags; /* flags for data */
    unsigned int parse_data; /* 1 - data parsed by caller 0- data parsed by wrapper */
    /* callback that needs to be called when data recevied from driver */
    void (*callback) (struct cfg80211_data *);
};
#endif

/*
 * default socket id
 */
#define DEFAULT_NL80211_CMD_SOCK_ID 777
#define DEFAULT_NL80211_EVENT_SOCK_ID 778

#define FILE_NAME_LENGTH 64
#define MAX_WIPHY 3
#define MAC_STRING_LENGTH 17


/*
 * Case-sensitive full length string comparison
 */
#define streq(a,b) ((strlen(a) == strlen(b)) && (strncasecmp(a,b,strlen(b)) == 0))

typedef enum config_mode_type {
    CONFIG_IOCTL    = 0, /* driver config mode is WEXT */
    CONFIG_CFG80211 = 1, /* driver config mode is cfg80211 */
    CONFIG_INVALID  = 2, /* invalid driver config mode */
} config_mode_type;

struct socket_context {
    u_int8_t cfg80211; /* cfg80211 enable flag */
#if UMAC_SUPPORT_CFG80211
    wifi_cfg80211_context cfg80211_ctxt; /* cfg80211 context */
#endif
    int sock_fd; /* wext socket file descriptor */
};

/*
 * struct queue_entry - Queue Entry
 * @value: abstact object in the queue
 * @tailq: TAILQ Entry
 */
struct queue_entry {
    void *value;
    TAILQ_ENTRY(queue_entry) tailq;
};
TAILQ_HEAD(queue_head, queue_entry);

/*
 * struct queue - Queue
 * @mutex: Mutex for locking queue operation
 * @head: Head of the queue
 * @cnt: Number of objects in the queue
 */
struct queue {
    pthread_mutex_t mutex;
    struct queue_head head;
    int cnt;
};

int q_init(struct queue *q);
void q_insert(struct queue *q, void *value);
int q_remove(struct queue *q, void **value);
void *collector_start(void);
int collector_insert(void *ctx, void *data, void (*callback)(void *));
void collector_end(void *ctx);

int ether_mac2string(char *mac_string, const uint8_t mac[QDF_MAC_ADDR_SIZE]);
int ether_string2mac( uint8_t mac[QDF_MAC_ADDR_SIZE], const char *mac_addr);
long long int power (int index, int exponent);
void print_hex_buffer(void *buf, int len);
int start_event_thread (struct socket_context *sock_ctx);
int init_socket_context (struct socket_context *sock_ctx, int cmd_sock_id, int event_sock_id);
void destroy_socket_context (struct socket_context *sock_ctx);
enum config_mode_type get_config_mode_type();
int send_command (struct socket_context *sock_ctx, const char *ifname, void *buf, size_t buflen,
    void (*callback) (struct cfg80211_data *arg), int cmd, int ioctl_cmd);
int is_new_channel_display_format(void);

/*
 * wifistats_get_with_text_args: wifistats get API
 * @col: collector context
 * @argc: number of arguments
 * @argv: argument string array
 * @callback: callback function to be called after wifistats is collected
 * return 0 on success otherwise negative value on failure
 */
int wifistats_get_with_text_args(void *col, int argc, char *argv[],
                                 void (*callback)(void *));

/*
 * wifistats_get_with_text_args_token: wifistats get API
 * @col: collector context
 * @argc: number of arguments
 * @argv: argument string array
 * @callback: callback function to be called after wifistats is collected
 * @token: opaque token to be given back to upper layer when callback is
 *         invoked
 * return 0 on success otherwise negative value on failure
 */
int wifistats_get_with_text_args_token(void *col,
                                 int argc,
                                 char *argv[],
                                 void (*callback)(void *data, void *token),
                                 void *token);

/*
 * wifistats_get_next_tlv: wifistats API to get next TLV in the output
 * @ctx: wifistats buffers context
 * return TLV buffer pointer on success, NULL if no more TLVs
 *        after returning NULL, the iterator resets back to the first TLV
 *        so that a subsequent call to wifistats_get_next_tlv will return 
 *        the first TLV again
 */
void *wifistats_get_next_tlv(void *ctx);

/*
 * wifistats_free: Free the wifistats buffers that were collected as part of
 *                 wifistats_get API
 * @ctx: wifistats buffer context
 * return void
 */
void wifistats_free(void *ctx);

/*
 * wifistats_print: Prints one single wifistats TLV
 * @fp: file where the TLV will be printed
 * @block: Pointer to the TLV block (including TLV header)
 * return void
 */
void wifistats_print(FILE *fp, void *block);

#endif
