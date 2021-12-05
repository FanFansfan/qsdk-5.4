/*
 * Copyright (c) 2018 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

/*
 * Including common library headerfile
 */
#include <qcatools_lib.h>
#include <sys/queue.h>
#include <pthread.h>
#include <semaphore.h>

/*
 * ether_mac2string: converts array containing mac address into a printable string format.
 * @mac: input mac address array
 * @mac_string: output mac string
 * returns -1 if passed mac array is NULL or copy fails else returns 0
 */
int ether_mac2string(char *mac_string, const uint8_t mac[QDF_MAC_ADDR_SIZE])
{
    int i;
    if (mac) {
        i = snprintf(mac_string, MAC_STRING_LENGTH+1, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        return -1;
    }
    return i;
}

/*
 * ether_string2mac: converts mac address string into integer array format.
 * @mac_addr: mac string to be converted
 * @mac converted mac array
 * returns 0 on succesful conversion and -1 otherwise
 */
int ether_string2mac( uint8_t mac[QDF_MAC_ADDR_SIZE], const char *mac_addr)
{
    int i, j = 2;
    char mac_string[MAC_STRING_LENGTH+1];

    if (strlcpy(mac_string, mac_addr, sizeof(mac_string)) >= sizeof(mac_string)) {
        printf("Invalid MAC address");
        return -1;
    }

    for (i = 2; i < MAC_STRING_LENGTH; i += 3) {
        mac_string[j++] = mac_string[i + 1];
        mac_string[j++] = mac_string[i + 2];
    }

    for(i = 0; i < 12; i++) {
        /* check 0~9, A~F */
        mac_string[i] = ((mac_string[i] - 48) < 10) ? (mac_string[i] - 48) : (mac_string[i] - 55);
        /* check a~f */
        if (mac_string[i] >= 42)
            mac_string[i] -= 32;
        if (mac_string[i] > 0xf)
            return -1;
    }

    for(i = 0; i < 6; i++) {
        mac[i] = (mac_string[(i<<1)] << 4) + mac_string[(i<<1)+1];
    }

    return 0;
}

/*
 * power: computes power using exponentiation by squaring method.
 * @index: index of which power has to be computed
 * @exponent: exponet to which power has to be raised
 * returns the resultant value of index raised to exponent
 */
long long int power (int index, int exponent)
{
    long long int temp;
    if (exponent == 0) return 1;
    if (exponent == 1) return index;

    temp = power(index, exponent / 2);

    if (exponent % 2 == 0) {
        return temp * temp;
    } else {
        if (exponent > 0){
            return index * temp * temp;
        } else {
            return (temp * temp) / index;
        }
    }
    return temp;
}

/*
 * print_hex_buffer: prints a buffer in hex format - used for dumping test events.
 * @buf: buffer to be printed
 * @len: length of buffer to be printed
 */
void print_hex_buffer(void *buf, int len)
{
    int cnt;
    for (cnt = 0; cnt < len; cnt++) {
        if (cnt % 8 == 0) {
            printf("\n");
        }
        printf("%02x ",((uint8_t *)buf) [cnt]);
    }
    fflush(stdout);
}

#if UMAC_SUPPORT_CFG80211
int start_event_thread (struct socket_context *sock_ctx)
{
    if (!sock_ctx->cfg80211) {
        return 0;
    }
    return wifi_nl80211_start_event_thread(&(sock_ctx->cfg80211_ctxt));
}
#endif

/*
 * is_new_channel_display_format: Function to check new channel
 * output format required in applications or not.
 *  Return: non zero value if new output format required
 *          zero for older output format
 */
int is_new_channel_display_format(void)
{
    char cmd[]="grep channel_print_format /lib/wifi/tools_config | grep -m1 -v ^[#] | awk -F'=' '{print $2}'" ;
    FILE* command_pipe = NULL;
    int value = 0;

    command_pipe = popen(cmd, "r");
    if (command_pipe == NULL) {
        return 0;
    }

    fscanf(command_pipe, "%d", &value);
    pclose(command_pipe);

    return value;
}

/*
 * get_config_mode_type: function that detects current config type
 *     and returns enum value corresponding to driver mode.
 *     returns CONFIG_CFG80211 if driver is in cfg mode,
 *     or CONFIG_IOCTL if driver is in wext mode.
 */
enum config_mode_type get_config_mode_type()
{
    int fd = -1;
    char filename[FILE_NAME_LENGTH];
    int radio;
    config_mode_type ret = CONFIG_IOCTL;

    for (radio = 0; radio < MAX_WIPHY; radio++) {
        snprintf(filename, sizeof(filename),"/sys/class/net/wifi%d/phy80211/",radio);
        fd = open(filename, O_RDONLY);
        if (fd > 0) {
            ret = CONFIG_CFG80211;
            close(fd);
            break;
        }
    }

    return ret;
}

/*
 * send_command; function to send the cfg command or ioctl command.
 * @sock_ctx: socket context
 * @ifname :interface name
 * @buf: buffer
 * @buflen : buffer length
 * @callback: callback that needs to be called when data recevied from driver
 * @cmd : command type
 * @ioctl_cmd: ioctl command type
 * returns 0 if success; otherwise negative value on failure
 */
int send_command (struct socket_context *sock_ctx, const char *ifname, void *buf,
        size_t buflen, void (*callback) (struct cfg80211_data *arg), int cmd, int ioctl_cmd)
{
#if UMAC_SUPPORT_WEXT
    struct iwreq iwr;
    int sock_fd, err;
#endif
#if UMAC_SUPPORT_CFG80211
    int msg;
    struct cfg80211_data buffer;
#endif
    if (sock_ctx->cfg80211) {
#if UMAC_SUPPORT_CFG80211
        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = callback;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_generic_command(&(sock_ctx->cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                cmd, ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            printf("Could not send NL command\n");
            return -1;
        }
        return buffer.length;
#endif
    } else {
#if UMAC_SUPPORT_WEXT
        sock_fd = sock_ctx->sock_fd;
        (void) memset(&iwr, 0, sizeof(iwr));

        if (strlcpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name)) >= sizeof(iwr.ifr_name)) {
            fprintf(stderr, "ifname too long: %s\n", ifname);
            return -1;
        }

        iwr.u.data.pointer = buf;
        iwr.u.data.length = buflen;
        err = ioctl(sock_fd, ioctl_cmd, &iwr);
        if (err < 0) {
            errx(1, "unable to send command");
            return -1;
        }

        return iwr.u.data.length;
#endif
    }

    return 0;
}

/*
 * init_socket_context: initialize the context
 * @sock_ctx: socket context
 * @cmd_sock_id, @event_sock_id: If application can run as background
 *                               process/daemon then use unique port numbers
 *                               otherwise default socket id for simple applications.
 * return 0 on success otherwise negative value on failure
 */
int init_socket_context (struct socket_context *sock_ctx,
        int cmd_sock_id, int event_sock_id)
{
    int err = 0;
#if UMAC_SUPPORT_CFG80211
    if (sock_ctx->cfg80211) {
        sock_ctx->cfg80211_ctxt.pvt_cmd_sock_id = cmd_sock_id;
        sock_ctx->cfg80211_ctxt.pvt_event_sock_id = event_sock_id;

        err = wifi_init_nl80211(&(sock_ctx->cfg80211_ctxt));
        if (err) {
            errx(1, "unable to create NL socket");
            return -EIO;
        }
    } else
#endif
    {
#if UMAC_SUPPORT_WEXT
        sock_ctx->cfg80211 = 0 /*false*/;
        sock_ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_ctx->sock_fd < 0) {
            errx(1, "socket creation failed");
            return -EIO;
        }
#endif
    }
    return 0;
}

/**
 * destroy_socket_context: destroys the context
 * @sock_ctx: socket context
 * returns 0 if success; otherwise negative values on failures
 */
void destroy_socket_context (struct socket_context *sock_ctx)
{
#if UMAC_SUPPORT_CFG80211
    if (sock_ctx->cfg80211) {
        wifi_destroy_nl80211(&(sock_ctx->cfg80211_ctxt));
    } else
#endif
    {
#if UMAC_SUPPORT_WEXT
        close(sock_ctx->sock_fd);
#endif
    }
    return;
}

/*
 * q_init; function to initialize queue
 * @q: queue object
 * returns 0 if success; otherwise negative value on failure
 */
int q_init(struct queue *q)
{
    TAILQ_INIT(&q->head);
    return pthread_mutex_init(&q->mutex, NULL);
}

/*
 * q_insert; function to insert into queue
 * @q: queue object
 * @value: abstract object to be inserted
 * returns 0 if success; otherwise negative value on failure
 */
void q_insert(struct queue *q, void *value)
{
    struct queue_entry *entry;
    entry = malloc(sizeof(*entry));
    if (entry == NULL) {
        fprintf(stderr, "%s:%d Could not allocate memory\n", __func__, __LINE__);
        return;
    }
    entry->value = value;
    pthread_mutex_lock(&q->mutex);
    TAILQ_INSERT_TAIL(&q->head, entry, tailq);
    q->cnt++;
    pthread_mutex_unlock(&q->mutex);
}

/*
 * q_remove: function to remove from queue
 * @q: queue object
 * @value: abstract object to be removed
 * returns 0 if the queue is not empty, negative if queue is empty
 */
int q_remove(struct queue *q, void **value)
{
    struct queue_entry *entry;
    pthread_mutex_lock(&q->mutex);
    if (TAILQ_EMPTY(&q->head)) {
        pthread_mutex_unlock(&q->mutex);
        return -EINVAL;
    }
    entry = TAILQ_FIRST(&q->head);
    *value = entry->value;
    TAILQ_REMOVE(&q->head, entry, tailq);
    q->cnt--;
    pthread_mutex_unlock(&q->mutex);
    free(entry);
    return 0;
}

/*
 * q_count: function to get the number of objects in queue
 * @q: queue object
 * returns the number of objects in queue
 */
int q_count(struct queue *q)
{
    return q->cnt;
}

/*
 * struct collector_ctx - Collector context (internal)
 * @event_q: queue associated with the Collector thread
 * @tid: Thread ID for the collector thread
 * @semaphore: Semaphore associated with the collector thread queue
 * @thread_running: Control variable to stop the thread
 */
struct collector_ctx
{
    struct queue event_q;
    pthread_t tid;
    sem_t semaphore;
    volatile int thread_running;
};

/*
 * struct collector_job - Collector job (callback-data pair) which is inserted
 *                        into the Collector queue
 * @callback: callback function to be called
 * @data: data to be passed to the callback function
 */
struct collector_job
{
    void *data;
    void (*callback)(void *);
};

/*
 * collector_thread: Thread function which simply fetches collector_job
 *                   from the queue and the callback function called with the
 *                   data
 * @arg: Collector object
 * returns NULL
 */
static void *collector_thread(void *arg)
{
    struct collector_ctx *ctx = arg;
    struct collector_job *job;

    if (!arg) {
        printf("ERROR! %s:%d\n", __func__, __LINE__);
        return NULL;
    }

    while(ctx->thread_running)
    {
        if (sem_wait(&ctx->semaphore)) {
            continue;
        }

        if (q_remove(&ctx->event_q, (void **)&job)) {
            continue;
        }

        job->callback(job->data);
        free(job);
    }
    /*
     * Remove all the backlog while collector_end is waiting for the thread
     * to join. This way we can avoid potential memory leaks
     */
    while (q_remove(&ctx->event_q, (void **)&job) == 0) {

        job->callback(job->data);
        free(job);
    }
    return NULL;
}

/*
 * collector_start: Start Collector thread after initializing collector context
 * returns the collector context that is newly created
 */
void *collector_start(void)
{
    struct collector_ctx *ctx = calloc(sizeof(*ctx), 1);
    if (ctx == NULL) {
        return NULL;
    }

    if (sem_init(&ctx->semaphore, 0, 0)) {
        goto error_free_ctx;
    }

    if (q_init(&ctx->event_q)) {
        goto error_sem_destroy;
    }

    ctx->thread_running = 1;
    if (pthread_create(&ctx->tid, NULL, collector_thread, ctx)) {
        goto error_sem_destroy;
    }
    return ((void *)ctx);

error_sem_destroy:
    sem_destroy(&ctx->semaphore);
error_free_ctx:
    free(ctx);
    return NULL;
}

/*
 * collector_end: End Collector thread and destroy the collector context
 * @ctx_arg: Collector context
 * returns void
 */
void collector_end(void *ctx_arg)
{
    struct collector_ctx *ctx = (struct collector_ctx *)ctx_arg;

    ctx->thread_running = 0;
    /*
     * Wake up the thread in case it is in sem_wait sleep
     */
    sem_post(&ctx->semaphore);
    pthread_join(ctx->tid, NULL);
    sem_destroy(&ctx->semaphore);
    free(ctx);
}

/*
 * collector_insert: Insert a callback function and argument data to the
 *                   collector
 * @ctx_arg: Collector context
 * @data: data to be passed to the callback function
 * @callback: callback function to be called by the collector thread
 * returns 0 if inserted properly, -EINVAL in case of error
 */
int collector_insert(void *ctx_arg, void *data,void (*callback)(void *))
{
    struct collector_ctx *ctx;
    struct collector_job *job = calloc(sizeof(*job), 1);

    if (!job) {
        printf("ERROR!! %s:%d FAILED TO ALLOCATE\n", __func__, __LINE__);
        return -EINVAL;
    }

    ctx = (struct collector_ctx *)ctx_arg;
    job->data = data;
    job->callback = callback;

    if (ctx->thread_running != 1) {
        printf("ERROR!! %s:%d Thread not running\n", __func__, __LINE__);
        free(job);
        return -EINVAL;
    }
    q_insert(&ctx->event_q, job);
    sem_post(&ctx->semaphore);
    return 0;
}

