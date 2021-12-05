/*
 * Copyright (c) 2019 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

#include <qcatools_lib.h>         /* library for common headerfiles */
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <time.h>
#include <sys/queue.h>
#include <pthread.h>
#include <netlink/attr.h>
#include <ieee80211_external.h>
#include <qld_api.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>

static const unsigned NL80211_ATTR_MAX_INTERNAL = 256;

/*
 * qld_print_table(): QLD table print
 */
void qld_print_table_user(void);

/**
 * struct qld_dump - Memory dump of registered structures
 * @total_list_count:Total qld list count
 * @qld_userdump:    buffer for continuous qld_userentries
 */
struct qld_dump {
    uint32_t total_list_count;
    struct qld_userentry qld_userdump[0];
};

static struct qld_dump *q_dump = NULL;

enum qca_wlan_genric_data {
    QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_PARAM_DATA,
    QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH,
    QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS,

    /* keep last */
    QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_LAST,
    QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_MAX =
        QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_LAST - 1
};

#define WIFI_NL80211_CMD_SOCK_ID    DEFAULT_NL80211_CMD_SOCK_ID
#define WIFI_NL80211_EVENT_SOCK_ID  DEFAULT_NL80211_EVENT_SOCK_ID

struct queue event_q;
static uint8_t event_filter_array[IEEE80211_DBGREQ_MAX] = {0};
static const char *if_name_filter;

/**
 * set_event_filter() - set filter
 * @cmd: command passed
 */
static void inline set_event_filter(uint8_t cmd)
{
    event_filter_array[cmd] = 1;
}

/**
 * clear_event_filter() - clear filter
 * @cmd: command passed
 */
static void inline clear_event_filter(uint8_t cmd)
{
    event_filter_array[cmd] = 0;
}

/**
 * set_if_name_filter() - set name filter
 * @ifname: interface name
 */
static void inline set_if_name_filter(const char *ifname)
{
    if_name_filter = ifname;
}

/**
 * set_if_name_filter_set() - check if name filter set
 * @ifname: interface name
 *
 * Return: 1 - OK 0 - failure
 */
static int if_name_filter_set(char *ifname)
{
    if (if_name_filter == NULL) {
        return 0;
    } else if (strncmp(if_name_filter, ifname, MAX_IFNAME_LEN) == 0) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * Global context to decide whether
 * ioctl calls should be used or cfg80211
 * calls should be used.
 * Default is ioctl.
 */
struct socket_context sock_ctx;

static void qld_usage(void)
{
    fprintf(stderr, "qldtool for memory dump of important structures\n"
                    "usage: qldtool -B -i [-h]\n"
                    "options:\n"
                    "    -B run daemon in the background\n"
                    "    -i radio name wifiX\n"
                    "    -h help\n");
    exit(-1);
}

/*
 * cfg80211_event_getwifi: Command for cfg80211 event to establish wifi
 * @ifname: interface name
 * @cmdid: enum value as command id
 * @buffer: pointer to buffer received
 * @len: total buffer length
 */
void cfg80211_event_getwifi(char *ifname, int cmdid, void *buffer,
        uint32_t len)
{
    struct qld_event *q_event = NULL;
    struct qld_event *q_buffer = NULL;
    uint32_t event_size;

    if (buffer == NULL) {
        printf("ERROR!! DBGREQ received with NULL buffer\n");
        return;
    }

    q_event = buffer;
    event_size = q_event->current_event_size;
    printf("QLD:: Process event size of %d %d\n", event_size, __LINE__);
    printf("QLD:: CMD ID is %d\n", cmdid);
    if (cmdid != QCA_NL80211_VENDOR_SUBCMD_DBGREQ) {
        /*
         * Wifitool is only interested in vendor events of type
         * QCA_NL80211_VENDOR_SUBCMD_DBGREQ
         */
        return;
    }

    if (!if_name_filter_set(ifname)) {
        printf("QLD: Interface didn't match ,allow from any interface\n");
    }

    if (!event_filter_array[q_event->cmd]) {
        /*
         * Ignore events which no body is interested in
         */
         return;
    }

    q_buffer = malloc(event_size);

    if (q_buffer == NULL) {
        fprintf(stderr, "%s:%d Could not allocate memory\n", __func__, __LINE__);
        return;
    }

    memcpy(q_buffer, q_event, event_size);
    q_insert(&event_q, q_buffer);
}

/*
 * nl80211_vendor_event_qca_parse_get_wifi: nl80211 vendor event to get wifi configuration
 * @ifname: interface name
 * @data: pointer to data
 * @len: length of the data
 */
static void nl80211_vendor_event_qca_parse_get_wifi(char *ifname,
        uint8_t *data, size_t len)
{
    struct nlattr *tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX + 1];
    struct nlattr *tb;
    void *buffer = NULL;
    uint32_t buffer_len = 0;
    uint32_t subcmd;

    if (nla_parse(tb_array, QCA_WLAN_VENDOR_ATTR_CONFIG_MAX,
                (struct nlattr *) data, len, NULL)) {
        printf("INVALID EVENT\n");
        return;
    }
    tb = tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND];
    if (!tb) {
        printf("ERROR!!!GENERIC CMD not found within get-wifi subcmd\n");
        return;
    }
    subcmd = nla_get_u32(tb);

    tb = tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA];
    if (tb) {
        buffer = nla_data(tb);
        buffer_len = nla_len(tb);
        cfg80211_event_getwifi(ifname, subcmd, buffer, buffer_len);
    }
}

/*
 * cfg80211_event_callback: cfg80211 event callback to get wifi configuration
 * @ifname: interface name
 * @subcmd: enum value for sub command
 * @data: pointer to the data
 * @len: length of the data
 */
void cfg80211_event_callback(char *ifname,
        uint32_t subcmd, uint8_t *data, size_t len)
{
    switch(subcmd) {
        case QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION:
            printf("QLD:NL CALLBACK received\n");
            nl80211_vendor_event_qca_parse_get_wifi(ifname, data, len);
            break;
    }
}

/*
 * receive_qld_table: receive qld table from driver
 * @event: a pointer to a structure of type struct qld_event
 * @total_event_size: Complete size of event table
 * @pid: process id
 * @dst: destination to copy.
 * @current_size: buffer size received in current event
 */
void receive_qld_table(struct qld_event *event,
        uint32_t total_event_size,
        struct qld_userentry **dst, uint32_t current_size)
{
    struct ol_qld_entry *q_entry;
    struct ol_qld_entry *start;
    struct qld_userentry *q_user;
    uint32_t current_entries;
    uint32_t index = 0;

    current_entries = current_size/sizeof(struct ol_qld_entry);
    printf("QLD:Number of entries are %d\n", current_entries);
    start = &event->qld_buffer[0];
    while(index < current_entries){
        /* Position to current entry to copy */
        q_entry = &start[index];
        q_user =  *dst;
        printf("QLD: Current entry is %" PRIx64 "  %d  %s\n",
               q_entry->addr, q_entry->size, q_entry->name);
        /* copy memory to user space table*/
        memcpy(&q_user->entry, q_entry, sizeof(struct ol_qld_entry));
        *dst = *dst + 1;
        index++;
    }

    return;
}

/*
 * qld_print_table_user(): print userspace table
 */
void qld_print_table_user(void)
{
    struct qld_userentry *q_entry;
    struct qld_userentry *start = NULL;
    uint32_t total_list_count;
    uint8_t index = 0;

    total_list_count = q_dump->total_list_count;
    start = &q_dump->qld_userdump[0];
    while(index < total_list_count){
        /* Position to current entry to copy */
        q_entry = &start[index];
        printf("QLD: Current user entry is %" PRIx64 " %" PRIx64 " %d %s\n",\
                q_entry->u_addr, q_entry->entry.addr,\
                q_entry->entry.size, q_entry->entry.name);
        index++;
    }
    printf("QLD: Table size is %d ALL entries printed \n", total_list_count);
}

/*
 * get_qld_entry(): callback function for nl request
 * @buffer: cfg buffer
 */
static void get_qld_entry(struct cfg80211_data *buffer)
{
    printf("QLD: ONE structure copied successfully\n");
}

/*
 * get_qld_entry_last(): last callback function for nl request
 * @buffer: cfg buffer
 */
static void get_qld_entry_last(struct cfg80211_data *buffer)
{
    struct rlimit rl;
    pid_t pid;

    printf("QLD: LAST structure copied successfully\n");
    printf("QLD: qld_dump head pointer is %p\n",q_dump);

    pid = fork();
    switch (pid) {
    case 0: /* Child */
        /* First get the present core limit */
        getrlimit(RLIMIT_CORE, &rl);
        printf("QLD: Init core file size limit is: %lld\n", (long long int)rl.rlim_cur);
        /* Change the time to unlimited */
        rl.rlim_cur = RLIM_INFINITY;
        /* Now call setrlimit() set new value */
        setrlimit(RLIMIT_CORE, &rl);
        /* Again get the limit and check */
        getrlimit(RLIMIT_CORE, &rl);
        printf("QLD:New core file size limit is: %lld\n", (long long int)rl.rlim_cur);
        printf("QLD: Trigger a seg fault in child and analyse\n");
        raise(SIGSEGV);
        return;

    case -1:
        printf("fork failed (errno "
                "%d %s)\n", errno, strerror(errno));
        goto err;

    default: /* Parent */
        return;
    }

err:
    exit(EXIT_FAILURE);

}

/*
 * qld_get_dump: get the strucuture dump from lower layer
 * @sock_ctx: socket context
 * @ifname: interface name
 */
void qld_get_dump(struct socket_context *sock_ctx, const char *ifname) {

    struct cfg80211_data buffer;
    struct qld_userentry *q_user = NULL;
    uint32_t total_list_count;
    uint32_t total_size;
    uint32_t index;
    struct qld_userentry *start = NULL;
#ifndef __LP64__
    uint32_t  u_32_addr;
#endif
    total_list_count = q_dump->total_list_count;
    /* Allocate comple user dump memory */
    printf("QLD: Table main handler is %p\n",q_dump);
    start = &q_dump->qld_userdump[0];

    /* Get entries from kernel */
    for (index = 0;index < total_list_count;index++) {
        printf("QLD: Fetching index %d from kernel\n",index);
        q_user = &start[index];
        total_size = q_user->entry.size;
        printf("QLD: Fetching index %d size is %d from kernel\n", index, total_size);
        printf("QLD: Allocation of %d bytes now requesting kernel to copy\n", q_user->entry.size);
        q_user->u_addr = (uintptr_t) malloc(q_user->entry.size);
        if (!q_user->u_addr) {
            fprintf(stderr, "Unable to allocate memory for station list\n");
            return;
        }
        /* Call appropriate types based on arch type */
#ifdef __LP64__
        memset((void*)q_user->u_addr,0,q_user->entry.size);
#else
        u_32_addr = q_user->u_addr;
        memset((void*)u_32_addr,0,q_user->entry.size);
#endif
        printf("QLD: Malloc done for size %d user address is %" PRIx64 "\n",
               q_user->entry.size, q_user->u_addr);
        buffer.data = (int8_t*)q_user;
        buffer.length = sizeof(struct qld_userentry);
        if(index == total_list_count-1) {
            buffer.callback = &get_qld_entry_last;
            buffer.flags = QLD_DATA_END_FLAG;
        } else {
            buffer.flags = QLD_DATA_START_FLAG;
            buffer.callback = &get_qld_entry;
        }
        buffer.parse_data = 0;
        if(!&sock_ctx->cfg80211_ctxt) {
            printf("QLD: cfg context in NULL\n");
        }

        wifi_cfg80211_send_generic_command(&(sock_ctx->cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_GET_QLD_ENTRY, ifname,
                (char *)&buffer,sizeof(struct qld_userentry));
    }
}

/*
 * qld_receive_event: QLD event handler
 * @sock_ctx: socket context
 * @ifname: interface name
 */
void qld_receive_event(struct socket_context *sock_ctx, const char *ifname)
{

    struct qld_event *q_event = NULL;
    uint32_t total_list_count = 0;
    uint32_t table_size = 0;
    uint32_t curr_size = 0;
    struct qld_userentry *cur_entry = NULL;
    uint8_t cur_flag = 0;
    int status = 0;

    set_event_filter(IEEE80211_DBGREQ_GET_QLD_DUMP_TABLE);
    set_if_name_filter(ifname);

    while(1) {
        printf("QLD:WAITING FOR EVENT FROM DRIVER\n");
        while (1) {
            if (q_remove(&event_q, (void **)&q_event)) {
                usleep(1000000);
                continue;
            }
            cur_flag = q_event->flags;
            if(cur_flag & QLD_START_EVENT) {
                printf("QLD: going to read NL DATA list start count is %d\n", q_event->total_list_count);
                total_list_count = q_event->total_list_count;
                /* Table size including header*/
                table_size = total_list_count * sizeof(struct qld_userentry)+ sizeof(struct qld_dump);
                q_dump = (struct qld_dump*)malloc (table_size);
                if (q_dump == NULL) {
                    fprintf(stderr, "%s:%d Could not allocate memory\n", __func__, __LINE__);
                    free(q_event);
                    exit(-1);
                }
                memset(q_dump,0,table_size);
                q_dump->total_list_count = total_list_count;
                cur_entry = &q_dump->qld_userdump[0];
            }
            printf("QLD: current event size is %d\n", q_event->current_event_size);
            /*Header adjustment*/
            curr_size =  q_event->current_event_size - sizeof(struct qld_event);
            printf("QLD: size need for table is  %d\n", table_size);
            /* Receive table from driver */
            receive_qld_table(q_event, table_size, &cur_entry, curr_size);
            printf("QLD: Freeing this queue entry\n");
            free(q_event);
            if(cur_flag & QLD_END_EVENT){
                printf("QLD: END of table data now break\n");
                break;
            }
        }
        /*Dump memory into userspace*/
        qld_get_dump(sock_ctx,ifname);
        /* Print the table */
        qld_print_table_user();
        printf("QLD: Waiting for child to finish\n");
        wait(&status);
        printf("QLD: Wait finished status %d\n", status);
        /*Cleanup*/
        free(q_dump);
        q_dump = NULL;
    }
}

/*
 * main: QLD main function
 * @argc: total number of command line arguments
 * @argv: values of command line arguments
 */
int main(int argc, char *argv[])
{
    char ifname[IFNAMSIZ];
    int daemonize = 0;
    int c;

    if (argc < 4) {
        qld_usage();
    }

    /* Only for cfg mode*/
    sock_ctx.cfg80211 = get_config_mode_type();
    if(!sock_ctx.cfg80211) {
        fprintf(stderr, "Error wext mode not supported run driver in cfg mode.\n");
        return -EINVAL;
    }

    memset(ifname, '\0', IFNAMSIZ);
    while ((c = getopt (argc, argv, "Bi:h")) != -1) {
        switch (c){
          case 'B':
            daemonize = 1;
            break;
          case 'i':
            if (strlcpy(ifname, optarg, IFNAMSIZ) >= IFNAMSIZ) {
                printf("Source too long !");
                return -EINVAL;
            }
            break;
          case 'h':
            qld_usage();
            break;
          default:
            qld_usage();
        }
    }
    if (daemonize && (strlen(ifname) != 0)) {
        /* Run as daemon without disconnecting console logs*/
        if (daemon(0,1)) {
            perror("daemon");
            exit(1);
        }
        /* Register event handler callback */
        sock_ctx.cfg80211_ctxt.event_callback = cfg80211_event_callback;
        init_socket_context(&sock_ctx, WIFI_NL80211_CMD_SOCK_ID, WIFI_NL80211_EVENT_SOCK_ID);
        q_init(&event_q);
        if (start_event_thread(&sock_ctx)) {
            printf("QLD:ERROR!!! Unable to setup nl80211 event thread\n");
            return 0;
        }
        qld_receive_event(&sock_ctx,(const char *)&ifname);
        destroy_socket_context(&sock_ctx);
    }
    return 0;
}
