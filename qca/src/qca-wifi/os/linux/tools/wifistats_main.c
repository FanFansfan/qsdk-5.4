/*
* Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
*
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/
#include <wifistats.h>
#include <netlink/attr.h>
#include "qcatools_lib.h"

#define MAX_BUFFERS 10
#define MAX_WIFISTATS_ARG_STRLEN 50
#define MAX_WIFISTATS_ARGS 10

/* Struct wifistats_buffers - Internal structure to maintain stats buffers
 * @output_buf: Buffers received from the driver are maintained in this array
 * @buf_cnt: How many buffers in the output_buf array
 * @iterator: used by wifistats_get_next to keep track of the buffer pointer
 */
struct wifistats_buffers
{
    struct {
        char *buf; /* The start of the buffer */
        /*
         * Length below does not include the first-part of the
         * split-TLV (whose second part is in the next buffer
         */
        int len;
    } output_buf[MAX_BUFFERS];
    int buf_cnt;

    /* struct iterator: iterator structure used for iterating over the
     *                  stats buffers as part of wifistats_get_next
     * @buf_index: which index in output_buf is the iterator currently at
     * @buf_offset: Within the buffer (indicated by buf_index),
     *              what is the offset at which the iterator is at
     * @complete: Whether iteration is complete
     */
    struct {
        int buf_index;
        int buf_offset;
        int complete;
    } iterator;
};

/*
 * Struct wifistats_api_ctx: State variables to be shared between
 *                           main thread and cfg80211 event callback
 * @interface: Interface on which the stats are being received
 * @cookie: Cookie number to validate the stats buffer being received
 * @responses_done: This is marked once all the responses are received from
 *                  the driver
 * @split_tlv_ptr: In case the TLV does not fit in the current buffer
 *                 this pointer marks the start of the TLV which is not complete
 * @split_tlv_len: How much length is remaining in the incomplete TLV buffer
 *                 above
 * @tlv_len_remain: How much length of the TLV is to be obtained from the next
 *                  buffer in order to complete the above split-TLV buffer
 * @error: If there is any error during processing of the stats buffer, mark
 *         error here
 * @stats_buffers: The stats buffers structure where the stats buffers
 *                 received from driver are collected
 */
struct {
    char interface[IFNAMSIZ];
    int32_t cookie;
    int32_t responses_done;

    /*
     * Book-keeping variables to manage TLV split across multiple
     * buffers. These are only relevant during stats collection
     */
    void *split_tlv_ptr;
    int split_tlv_len;
    int tlv_len_remain;
    int error;
    struct wifistats_buffers *stats_buffers;
} wifistats_api_ctx;

struct wifistats_module *modulelist = NULL;
struct wifistats_module *current_module = NULL;

static inline char *string_from_moduleid(int id)
{
        static const char *strings[MAX_FW_STATS_ID] = {"htt_fw_stats",
                                                    "wmi_fw_stats"};

        if (id >= MAX_FW_STATS_ID)
            return NULL;

        return (char *)strings[id];
}

#ifdef WIFISTATS_API_INTERFACE

/*
 * wifistats_free: Free the wifistats buffers that were collected as part of
 *                 wifistats_get API
 * @ctx: wifistats buffer context
 * return void
 */
void wifistats_free(void *ctx)
{
    int cnt;
    struct wifistats_buffers *output_ctx = ctx;

    if (ctx == NULL) {
        printf("ERROR!! %s:%d\n", __func__, __LINE__);
        return;
    }

    for (cnt=0; cnt < output_ctx->buf_cnt; cnt++) {
        if (output_ctx->output_buf[cnt].buf)
            free(output_ctx->output_buf[cnt].buf);
        else
            printf("ERROR!! %s:%d unexpected NULL Pointer at %d\n",
                   __func__, __LINE__, cnt);
    }
    free(ctx);
}

static int copy_remainder_of_tlv(void *data, int32_t msg_remain_len)
{
    void *new_buf;
    int new_buf_len;
    struct wifistats_buffers *stats_buffers = wifistats_api_ctx.stats_buffers;

    if (!wifistats_api_ctx.split_tlv_ptr)
        return 0;

    /*
     * This is a continuation of TLV from the previous buffer
     */
    if (msg_remain_len <  wifistats_api_ctx.tlv_len_remain) {
        printf("ERROR!! %s:%d The remainder of the TLV does not "
                "fit in the next buffer. This case cannot be handled\n",
                __func__, __LINE__);
        return -EINVAL;
    }

    new_buf_len = wifistats_api_ctx.tlv_len_remain +
        wifistats_api_ctx.split_tlv_len;
    new_buf = calloc(new_buf_len, 1);
    if (new_buf == NULL) {
        printf("ERROR!! %s:%d FAILED TO GET MEM\n", __func__, __LINE__);
        return -EINVAL;
    }

    /*
     * Copy the beginning of TLV from previous buffer
     */
    memcpy(new_buf, wifistats_api_ctx.split_tlv_ptr,
            wifistats_api_ctx.split_tlv_len);

    /*
     * Copy the remaining from this buffer
     */
    memcpy(new_buf + wifistats_api_ctx.split_tlv_len, data,
            wifistats_api_ctx.tlv_len_remain);

    /*
     * Reset the split_tlv book-keeping
     */
    wifistats_api_ctx.split_tlv_ptr = NULL;

    /*
     * This new buffer is the intermediate buffer
     * to accomodate the split TLV
     */
    stats_buffers->output_buf[stats_buffers->buf_cnt].buf = new_buf;
    stats_buffers->output_buf[stats_buffers->buf_cnt].len = new_buf_len;
    stats_buffers->buf_cnt++;

    /*
     * For creating the next buffer,
     * Continue from the next TLV
     */
    data += wifistats_api_ctx.tlv_len_remain;
    msg_remain_len -= wifistats_api_ctx.tlv_len_remain;
    return 0;
}


static int parse_buffer(
        void *data,
        int32_t msg_remain_len)
{
    void *new_buf;
    struct wifistats_buffers *stats_buffers = wifistats_api_ctx.stats_buffers;
    int ret;

    if (wifistats_api_ctx.error) {
        /*
         * Error has occured already
         * No pointing in parsing HTT Stats response
         */
        return -EINVAL;
    }

    if ((ret = copy_remainder_of_tlv(data, msg_remain_len)))
        return ret;

    new_buf = calloc(msg_remain_len, 1);
    if (new_buf == NULL) {
        printf("ERROR!! %s:%d FAILED TO ALLOCATE MEMORY\n", __func__, __LINE__);
        return -EINVAL;
    }
    stats_buffers->output_buf[stats_buffers->buf_cnt].buf = new_buf;
    memcpy(new_buf, data, msg_remain_len);
    /*
     * Don't set the length beforehand
     * Increment the length TLV-by-TLV
     */

    while (msg_remain_len) {
        uint32_t tlv_remain_len;
        uint32_t tlv_hdr_len = current_module->tlv_hdr_len;

        if (msg_remain_len < tlv_hdr_len) {
            printf("ERROR!! %s:%d TLV header not complete\n", __func__,
                                                              __LINE__);
            return -EINVAL;
        }

        tlv_remain_len = current_module->output_tlv_length(data);
        if (msg_remain_len < tlv_remain_len) {
            wifistats_api_ctx.tlv_len_remain = (tlv_remain_len - msg_remain_len);
            wifistats_api_ctx.split_tlv_ptr = data;
            wifistats_api_ctx.split_tlv_len = msg_remain_len;
            break;
        }

        stats_buffers->output_buf[stats_buffers->buf_cnt].len += tlv_remain_len;
        msg_remain_len -= tlv_remain_len;
        data += tlv_remain_len;
    }
    stats_buffers->buf_cnt++;
    return 0;
}
#else
#define wifistats_free(a)
#define parse_buffer(a, b) (0)
#endif

static void wifistats_event_callback(char *ifname, uint32_t cmdid, uint8_t *data,
                                    size_t len)
{
    int response_cookie = 0;

    struct nlattr *tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX + 1];
    struct nlattr *tb;
    void *buffer = NULL;
    int32_t buffer_len;
    int32_t responses_done = 0;

    if (cmdid != QCA_NL80211_VENDOR_SUBCMD_WIFI_FW_STATS) {
       /* ignore anyother events*/
       return;
    }

    if (strncmp(wifistats_api_ctx.interface, ifname, sizeof(wifistats_api_ctx.interface)) != 0) {
       /* ignore events for other interfaces*/
       return;
    }

    if (nla_parse(tb_array, QCA_WLAN_VENDOR_ATTR_CONFIG_MAX,
                (struct nlattr *) data, len, NULL)) {
        printf("INVALID EVENT\n");
        return;
    }

    tb = tb_array[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA];
    if (tb) {
        buffer = (void *)nla_data(tb);
        buffer_len = (int32_t) nla_len(tb);
    } else {
        printf("ERROR!! %s:%d tb is NULL\n", __func__, __LINE__);
        return;
    }

    if (buffer == NULL) {
        printf("ERROR!! wifistats received with NULL data\n");
        return;
    }

    response_cookie  = current_module->output_cookie_get(buffer, buffer_len); /*Cookie LSB*/
    if (response_cookie != wifistats_api_ctx.cookie) {
        /* ignore events if there is cookie mismatch*/
        return;
    }

    if (wifistats_api_ctx.stats_buffers) {
        buffer = current_module->output_get_buf_start(buffer, &buffer_len, &responses_done);
        wifistats_api_ctx.error = parse_buffer(buffer, buffer_len);
    } else {
        responses_done = current_module->output_handler(buffer, buffer_len);
    }
    wifistats_api_ctx.responses_done = responses_done;
}

/**
 * wifi_send_command; function to send the cfg command or ioctl command.
 * @ifname :interface name
 * @buf: buffer
 * @buflen : buffer length
 * @cmd : command type
 * @ioctl_cmd: ioctl command type
 * return : 0 for success
 */
static int wifi_send_command (wifi_cfg80211_context *cfg80211_ctxt, const char *ifname, void *buf, size_t buflen, int cmd)
{
    int msg;
    struct cfg80211_data buffer;

        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = NULL;
        msg = wifi_cfg80211_send_generic_command(cfg80211_ctxt,
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                cmd, ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            fprintf(stderr, "Couldn't send NL command\n");
            return msg;
        }
        return buffer.flags;
}

static int wifi_get_target_pdevid (char *ifname)
{
    int err = 0;
    wifi_cfg80211_context cfg80211_ctxt;
    struct cfg80211_data buffer;
    int pdev_id;
    int msg;

    /* Reset the cfg80211 context to 0 if the application does not pass
     * custom private event and command sockets. In this case, the default
     * port is used for netlink communication.
     */
    memset(&cfg80211_ctxt, 0, sizeof(wifi_cfg80211_context));

    err = wifi_init_nl80211(&cfg80211_ctxt);
    if (err) {
        fprintf(stderr, "unable to create NL socket\n");
        return -EIO;
    }

    buffer.data = &pdev_id;
    buffer.length = sizeof(uint32_t);
    buffer.callback = NULL;
    buffer.parse_data = 0;
    msg = wifi_cfg80211_send_getparam_command(&cfg80211_ctxt,
            QCA_NL80211_VENDOR_SUBCMD_GET_TARGET_PDEVID, 0,
            ifname, (char *)&buffer, sizeof(uint32_t));
        /* we need to pass subcommand as well */
        if (msg < 0) {
            fprintf(stderr, "Couldn't send NL command\n");
            wifi_destroy_nl80211(&cfg80211_ctxt);
            return -EIO;
        }
    wifi_destroy_nl80211(&cfg80211_ctxt);
    return pdev_id;
}

static int chartohex(char c)
{
    int val = -1;
    if (c >= '0' && c <= '9')
        val = c - '0';
    else if (c >= 'a' && c <= 'f')
        val = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        val = c - 'A' + 10;

    return val;
}


int  extract_mac_addr(uint8_t *addr, const char *text)
{
    uint8_t i=0;
    int nibble;
    const char *temp = text;
    while (temp && i < QDF_MAC_ADDR_SIZE) {
        nibble = chartohex(*temp++);
        if (nibble == -1)
            return -1;
        addr[i] = nibble << 4;
        nibble = chartohex(*temp++);
        if (nibble == -1)
            return -1;
        addr[i++] += nibble;
        if (*temp == ':')
            temp++;
    }
    return 0;
}

void wifistats_usage (int argc, char *argv[]) {
    struct wifistats_module * temp = modulelist;

    printf("========= GENERIC USAGE =================\n");

    while (temp != NULL) {
        printf("\t%s %s <ifname> <private args> \n", argv[0], temp->name);
        temp = temp->next;
    }
    printf("=========================================\n");
}

struct wifistats_module *wifistats_module_get (char *modulename) {
    struct wifistats_module * temp = modulelist;

    while (temp != NULL) {
        if (strcmp(modulename, temp->name) == 0) {
            return temp;
        }
        temp = temp->next;
    }

    return NULL;
}

int wifistats_module_unregister (struct wifistats_module *module, int size)
{
    struct wifistats_module *prev = NULL, *temp = modulelist;

    if ((temp != NULL) && (strcmp(module->name, temp->name) == 0)) {
        modulelist = temp->next;
        return 0;
    }

    while ((temp != NULL) && (strcmp(module->name, temp->name) == 0)) {
        prev = temp;
        temp = temp->next;
    }

    if (temp == NULL)
         return -1;

    if (prev)
        prev->next = temp->next;

    return 0;
}

int wifistats_module_register (struct wifistats_module *module, int size)
{
    if(size != sizeof(struct wifistats_module)) {
        fprintf(stderr, "###### ERROR structure size mismatch######\n");
        exit(-1);
    }
    module->next = modulelist;
    modulelist = module;
    return 0;
}

#ifdef WIFISTATS_API_INTERFACE
/*
 * struct wifistats_job - internal structure to pass along to the
 *                        collector context
 * @argc: Number of arguments
 * @argv_buffer: Array to pack in all the arguments
 * @argv: Mark the beginning of each string argument in the above 2-d array
 * @callback: callback function to be called at the end
 * @token: opaque object to be given back to the upper layer when callback is
 *         invoked
 * @callback_token: callback function to be called at the end (with token)
 */
struct wifistats_job
{
    int argc;
    char argv_buffer[MAX_WIFISTATS_ARGS][MAX_WIFISTATS_ARG_STRLEN];
    char *argv[MAX_WIFISTATS_ARGS];
    void (*callback)(void *ctx);
    void *token;
    void (*callback_token)(void *ctx, void *token);
};

/*
 * wifistats_get_next_tlv: wifistats API to get next TLV in the output
 * @ctx: wifistats buffers context
 * return TLV buffer pointer on success, NULL if no more TLVs
 *        after returning NULL, the iterator resets back to the first TLV
 *        so that a subsequent call to wifistats_get_next_tlv will return
 *        the first TLV again
 */
void *wifistats_get_next_tlv(void *ctx)
{
    struct wifistats_buffers *output_ctx = ctx;
    void *next_tlv_ptr;
    int buf_index;
    int buf_offset;

    if (ctx == NULL) {
        printf("ERROR!! %s:%d NULL pointer\n", __func__, __LINE__);
        return NULL;
    }

    if (output_ctx->iterator.complete) {
        /*
         * This is an implicit reset of the iterator
         * once the end is reached
         */
        memset(&output_ctx->iterator, 0, sizeof(output_ctx->iterator));
        return NULL;
    }

    buf_index = output_ctx->iterator.buf_index;
    buf_offset = output_ctx->iterator.buf_offset;
    next_tlv_ptr = output_ctx->output_buf[buf_index].buf + buf_offset;
    buf_offset += current_module->output_tlv_length(next_tlv_ptr);
    if (buf_offset >= output_ctx->output_buf[buf_index].len) {
        output_ctx->iterator.buf_index++;
        if (output_ctx->iterator.buf_index >= output_ctx->buf_cnt)
            output_ctx->iterator.complete = 1;

        output_ctx->iterator.buf_offset = 0;
    } else {
        output_ctx->iterator.buf_offset = buf_offset;
    }
    return next_tlv_ptr;
}

/*
 * wifistats_print: Prints one single wifistats TLV
 * @fp: file where the TLV will be printed
 * @block: Pointer to the TLV block (including TLV header)
 * return void
 */
void wifistats_print(FILE *fp, void *block)
{
    current_module->output_fp = fp;
    current_module->output_print_tlv(block);
}

static int wifistats_api_init()
{
    memset(&wifistats_api_ctx, 0, sizeof(wifistats_api_ctx));
    wifistats_api_ctx.stats_buffers =
        calloc(sizeof(*wifistats_api_ctx.stats_buffers), 1);
    if (wifistats_api_ctx.stats_buffers == NULL) {
        printf("ERROR!! %s:%d failure to allocate memory\n", __func__,
                __LINE__);
        return -EIO;
    }
    return 0;
}
#else
#define wifistats_api_init() (0)
#endif

static int
wifistats_main(int argc, char *argv[],
               void (*callback)(void *ctx),
               void (*callback_token)(void *ctx, void *token),
               void *token)
{
    int err = 0;
    int pdev_id = 0;
    wifi_cfg80211_context cfg80211_ctxt;
    char *ifname;
    int num_msecs = 0;
    void *req_buff = NULL;
    int req_buff_sz = 0;
    int parsed_len = 0;
    int status = 0;
    wifistats_fw_moduleid module_id = HTT_FW_STATS;
    char *module_name = NULL;

    if (streq(argv[argc-1], "--wmi")) {
        module_id = WMI_FW_STATS;
    }


    if (callback || callback_token)
        if ((status = wifistats_api_init()))
            goto cleanup;

    if(argc < 3) {
        fprintf(stderr, "Invalid commands args\n");
        wifistats_usage(argc, argv);
        status = -EIO;
        goto cleanup;
    }

    module_name = string_from_moduleid(module_id);
    if (!module_name) {
        status = -EIO;
        goto cleanup;
    }

    current_module = wifistats_module_get (module_name);
    if (current_module == NULL) {
        fprintf (stderr, "%s is not registered for wifistats\n", string_from_moduleid(module_id));
        status = -EIO;
        goto cleanup;
    }

    ifname = argv[1];
    if (module_id == WMI_FW_STATS) {
        pdev_id = wifi_get_target_pdevid(ifname);
    }

    /* Reset the cfg80211 context to 0 if the application does not pass
     * custom private event and command sockets. In this case, the default
     * port is used for netlink communication.
     */
    memset(&cfg80211_ctxt, 0, sizeof(wifi_cfg80211_context));

    req_buff = current_module->input_buff_alloc(&req_buff_sz);
    if (req_buff == NULL) {
        fprintf (stderr, "%s unable to alloc memory for IO\n", current_module->name);
        status = -EIO;
        goto cleanup;
    }

    if (current_module->input_parse(req_buff, argc, argv, &parsed_len, pdev_id)) {
        fprintf(stderr, "Invalid commands args \n");
        current_module->help(argc, argv);
        status = -EIO;
        goto cleanup;
    }

    memcpy(wifistats_api_ctx.interface, ifname, sizeof(wifistats_api_ctx.interface));
    wifistats_api_ctx.cookie = current_module->input_cookie_generate();
    cfg80211_ctxt.event_callback = wifistats_event_callback;

    err = wifi_init_nl80211(&cfg80211_ctxt);
    if (err) {
        fprintf(stderr, "unable to create NL socket\n");
        status = -EIO;
        goto cleanup;
    }

    switch (module_id) {
        case HTT_FW_STATS:
            wifi_send_command(&cfg80211_ctxt, ifname, req_buff, req_buff_sz, QCA_NL80211_VENDOR_SUBCMD_HTTSTATS);
            break;
        case WMI_FW_STATS:
            wifi_send_command(&cfg80211_ctxt, ifname, req_buff, parsed_len, QCA_NL80211_VENDOR_SUBCMD_WMISTATS);
            break;
        default:
            break;
    }
    /* Starting event thread to listen for responses*/
    if (wifi_nl80211_start_event_thread(&cfg80211_ctxt)) {
        fprintf(stderr, "Unable to setup nl80211 event thread\n");
        status = -EIO;
        goto cleanup_cfg80211;
    }

    while ((wifistats_api_ctx.responses_done != LISTEN_DONE) && (num_msecs < current_module->timeout)) {
        /*sleep for 1 ms*/
        usleep (1000);
        num_msecs++;
    }

    if (num_msecs >= current_module->timeout) {
        status = -EBUSY;
        goto cleanup_cfg80211;
    }

    if (callback || callback_token) {
        if (wifistats_api_ctx.error) {
            status = -EIO;
            goto cleanup_cfg80211;
        }
        else if (callback_token)
            callback_token(wifistats_api_ctx.stats_buffers, token);
        else
            callback(wifistats_api_ctx.stats_buffers);
    }
    status = 0;

cleanup_cfg80211:
    wifi_destroy_nl80211(&cfg80211_ctxt);

cleanup:
    if (wifistats_api_ctx.stats_buffers && (status != 0))
        /*
         * Free the buffers if status is failure since the user-application
         * cannot use these buffers if status is failure
         * if status is success, we cannot free here. We have to make
         * user-application free the stats-buffers after it is done using these
         */
        wifistats_free(wifistats_api_ctx.stats_buffers);

    if (req_buff) {
        if (current_module) {
            current_module->input_buff_free(req_buff);
        }
    }

    if ((callback || callback_token) && (status != 0)) {
        if (callback_token)
            callback_token(NULL, token);
        else
            callback(NULL);
    }
    return status;
}

#ifdef WIFISTATS_API_INTERFACE
static void wifistats_api_service(struct wifistats_job *job)
{
    if (job == NULL) {
        printf("ERROR! %s:%d got NULL pointer\n", __func__, __LINE__);
        return;
    }
    wifistats_main(job->argc, job->argv, job->callback,
                   job->callback_token, job->token);
    free(job);
}

/*
 * wifistats_get_with_text_args: wifistats get API
 * @col: collector context
 * @argc: number of arguments
 * @argv: argument string array
 * @callback: callback function to be called after wifistats is collected
 * return 0 on success otherwise negative value on failure
 */
int wifistats_get_with_text_args(void *col, int argc, char *argv[],
                                  void (*callback)(void *))
{
    int cnt;
    struct wifistats_job *job = calloc(sizeof(*job), 1);

    if (!job) {
        printf("ERROR!! %s:%d FAILED TO ALLOCATE\n", __func__, __LINE__);
        return -ENOMEM;
    }

    job->argc = argc;
    for (cnt=0; cnt < argc; cnt++) {
        strlcpy(job->argv_buffer[cnt], argv[cnt], MAX_WIFISTATS_ARG_STRLEN);
        job->argv[cnt] = job->argv_buffer[cnt];
    }
    job->callback = callback;
    return collector_insert(col, job, (void (*)(void *))wifistats_api_service);
}

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
                                 void *token)
{
    int cnt;
    struct wifistats_job *job = calloc(sizeof(*job), 1);

    if (!job) {
        printf("ERROR!! %s:%d FAILED TO ALLOCATE\n", __func__, __LINE__);
        return -ENOMEM;
    }

    job->argc = argc;
    for (cnt=0; cnt < argc; cnt++) {
        strlcpy(job->argv_buffer[cnt], argv[cnt], MAX_WIFISTATS_ARG_STRLEN);
        job->argv[cnt] = job->argv_buffer[cnt];
    }
    job->callback_token = callback;
    job->token = token;
    return collector_insert(col, job, (void (*)(void *))wifistats_api_service);
}

#else
int main(int argc, char *argv[])
{
    return wifistats_main(argc, argv, NULL, NULL, NULL);
}
#endif

