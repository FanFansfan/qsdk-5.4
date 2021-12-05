/*
 * Copyright (c) 2020  Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 */

#include "wifistats.h"
#include <a_types.h>    /* A_UINT32 */
#include "wmi.h"
#include "wmi_unified.h"
#include "wmi_tlv_helper.h"
#include "wmi_tlv_defs.h"

#define WMI_MAX_STRING_LEN 1000
#define WMI_CMDS_SIZE_MAX 2048

#ifdef __KERNEL__
#define WMI_STATS_PRINT DP_TRACE_STATS
#else
#define WMI_STATS_PRINT(level, fmt, ...) \
    do { \
        printf(fmt,##__VA_ARGS__); \
        printf("\n"); \
    } while (0)

void __attribute__ ((constructor)) wmistats_init(void);
void __attribute__ ((destructor)) wmistats_fini(void);

#endif /* ifdef __KERNEL__ */

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#else
#error confilicting defs of min
#endif


/*
 * Provide a forward declaration of wmistats.
 * (The definition is at the bottom of this file.)
 */
static struct wifistats_module wmistats;

/*
 * wmi_print_ctrl_path_pdev_tx_stats_tlv: display wmi_print_ctrl_path_pdev_tx_stats
 * @tag_buf: buffer containing the tlv wmi_ctrl_path_pdev_stats_struct_tlv
 *
 * return:void
 */
static inline void wmi_print_ctrl_path_pdev_tx_stats_tlv(void *tag_buf)
{
    wmi_ctrl_path_pdev_stats_struct *wmi_stats_buf =
        (wmi_ctrl_path_pdev_stats_struct *)tag_buf;
    A_UINT8  i;
    A_UINT16 index_tx                               = 0;
    A_UINT16 index_rx                               = 0;
    A_CHAR   fw_tx_mgmt_subtype[WMI_MAX_STRING_LEN] = {0};
    A_CHAR   fw_rx_mgmt_subtype[WMI_MAX_STRING_LEN] = {0};


    WMI_STATS_PRINT(FATAL, "WMI_CTRL_PATH_PDEV_TX_STATS_TLV:");

    WMI_STATS_PRINT(FATAL, "pdev_id = %u",
            wmi_stats_buf->pdev_id);

    for (i = 0; i < WMI_MGMT_FRAME_SUBTYPE_MAX; i++) {
        index_tx += snprintf(&fw_tx_mgmt_subtype[index_tx],
                WMI_MAX_STRING_LEN - index_tx,
                " %u:%u,", i,
                wmi_stats_buf->tx_mgmt_subtype[i]);
        index_rx += snprintf(&fw_rx_mgmt_subtype[index_rx],
                 WMI_MAX_STRING_LEN - index_rx,
                 " %u:%u,", i,
                 wmi_stats_buf->rx_mgmt_subtype[i]);
    }

    WMI_STATS_PRINT(FATAL, "fw_tx_mgmt_subtype = %s \n", fw_tx_mgmt_subtype);

    WMI_STATS_PRINT(FATAL, "fw_rx_mgmt_subtype = %s \n", fw_rx_mgmt_subtype);

    WMI_STATS_PRINT(FATAL, "scan_fail_dfs_violation_time_ms = %u",
            wmi_stats_buf->scan_fail_dfs_violation_time_ms);

    WMI_STATS_PRINT(FATAL, "nol_check_fail_time_stamp_ms = %u",
            wmi_stats_buf->nol_check_fail_time_stamp_ms);

    WMI_STATS_PRINT(FATAL, "nol_check_fail_last_chan_freq = %u",
            wmi_stats_buf->nol_check_fail_last_chan_freq);

    WMI_STATS_PRINT(FATAL, "nol_check_fail_time_stamp_ms = %u",
            wmi_stats_buf->nol_check_fail_time_stamp_ms);

    WMI_STATS_PRINT(FATAL, "total_peer_create_cnt = %u",
            wmi_stats_buf->total_peer_create_cnt);

    WMI_STATS_PRINT(FATAL, "total_peer_delete_cnt = %u",
            wmi_stats_buf->total_peer_delete_cnt);

    WMI_STATS_PRINT(FATAL, "total_peer_delete_resp_cnt = %u",
            wmi_stats_buf->total_peer_delete_resp_cnt);

    WMI_STATS_PRINT(FATAL, "vdev_pause_fail_rt_to_sched_algo_fifo_full_cnt = %u",
            wmi_stats_buf->vdev_pause_fail_rt_to_sched_algo_fifo_full_cnt);
}

/*
 * wmi_print_ctrl_path_mem_stats_tlv: display wmi_print_ctrl_path_mem_stats
 * @tag_buf: buffer containing the tlv wmi_ctrl_path_mem_stats_struct_tlv
 *
 * return:void
 */
static inline void wmi_print_ctrl_path_mem_stats_tlv(void *tag_buf)
{
    wmi_ctrl_path_mem_stats_struct *wmi_stats_buf =
        (wmi_ctrl_path_mem_stats_struct *) tag_buf;
    if (0 != wmi_stats_buf->total_bytes) {
        if (0 == wmi_stats_buf->arena_id) {
            WMI_STATS_PRINT(FATAL,
                "|------------------------------------------------------------"
                "---------------------------------------------------|");
            WMI_STATS_PRINT(FATAL,
                "| %.20s  \t\t| %.16s \t\t|                  %.16s  \t| %.16s "
                "\t\t|","Arena","Total Size","Consumption","Headroom");
            WMI_STATS_PRINT(FATAL,
                "|        \t\t|       \t\t|       \t\t|     \t\t|       \t\t|");
            WMI_STATS_PRINT(FATAL,
                "|        \t\t|       \t\t| %.16s \t\t| %.16s \t|       \t\t|",
                "Absolute", "Percent(%)");
            WMI_STATS_PRINT(FATAL,
                "|------------------------------------------------------------"
                "---------------------------------------------------|");
        }
        WMI_STATS_PRINT(FATAL,
            "| %.20s  \t\t| %-16u \t| %-16u \t| %05.2f%%  \t| %-16u \t|",
            ((A_UINT8 *) wmi_ctrl_path_fw_arena_id_to_name(
                wmi_stats_buf->arena_id) + sizeof("WMI_CTRL_PATH_STATS_ARENA")),
            wmi_stats_buf->total_bytes,
            wmi_stats_buf->allocated_bytes,
            ((wmi_stats_buf->allocated_bytes * 100.0) /
                wmi_stats_buf->total_bytes),
            (wmi_stats_buf->total_bytes - wmi_stats_buf->allocated_bytes));
        WMI_STATS_PRINT(FATAL,
            "|----------------------------------------------------------------"
            "-----------------------------------------------|");
    }
}

/*
 * wmi_print_ctrl_path_calibration_stats_tlv: display wmi_print_ctrl_path_calibration_stats
 * @tag_buf: buffer containing the tlv wmi_ctrl_path_calibration_stats_struct_tlv
 *
 * return:void
 */
static inline void wmi_print_ctrl_path_calibration_stats_tlv(void *tag_buf)
{
    wmi_ctrl_path_calibration_stats_struct *wmi_stats_buf =
        (wmi_ctrl_path_calibration_stats_struct *) tag_buf;
    static A_UINT32 prev_cal_profile = WMI_CTRL_PATH_STATS_CAL_PROFILE_INVALID;

    if (WMI_CTRL_PATH_CALIBRATION_STATS_CAL_PROFILE_GET(wmi_stats_buf->cal_info) == WMI_CTRL_PATH_STATS_CAL_PROFILE_INVALID) {
        if (!WMI_CTRL_PATH_CALIBRATION_STATS_IS_PERIODIC_CAL_GET(wmi_stats_buf->cal_info)) {
            WMI_STATS_PRINT(FATAL, "WMI_CTRL_PATH_CALIBRATION_STATS_TLV:");
            WMI_STATS_PRINT(FATAL, "pdev_id = %u", wmi_stats_buf->pdev_id);
            WMI_STATS_PRINT(FATAL,
                "|==========================================================="
                "============================================================"
                "=======|");
            WMI_STATS_PRINT(FATAL,
                "| %-25s| %-25s| %-17s| %-16s| %-16s| %-16s|",
                "cal_profile", "cal_type", "cal_triggered_cnt", "cal_fail_cnt",
                "cal_fcs_cnt", "cal_fcs_fail_cnt");
        } else {
            WMI_STATS_PRINT(FATAL,
                "|==========================================================="
                "============================================================"
                "=======|");
        }
        return;
    }

    if (prev_cal_profile != WMI_CTRL_PATH_CALIBRATION_STATS_CAL_PROFILE_GET(wmi_stats_buf->cal_info)) {
        WMI_STATS_PRINT(FATAL,
            "|==============================================================="
            "===============================================================|");
        prev_cal_profile = WMI_CTRL_PATH_CALIBRATION_STATS_CAL_PROFILE_GET(wmi_stats_buf->cal_info);
    }

    if (!WMI_CTRL_PATH_CALIBRATION_STATS_IS_PERIODIC_CAL_GET(wmi_stats_buf->cal_info)) {
        WMI_STATS_PRINT(FATAL,
            "| %-25s| %-25s| %-17u| %-16u| %-16u| %-16u|",
            ((A_UINT8 *) wmi_ctrl_path_cal_profile_id_to_name(
                WMI_CTRL_PATH_CALIBRATION_STATS_CAL_PROFILE_GET(wmi_stats_buf->cal_info)) +
                sizeof("WMI_CTRL_PATH_STATS_CAL_PROFILE")),
            ((A_UINT8 *) wmi_ctrl_path_cal_type_id_to_name(
                WMI_CTRL_PATH_CALIBRATION_STATS_CAL_TYPE_GET(wmi_stats_buf->cal_info)) +
                sizeof("WMI_CTRL_PATH_STATS_CAL_TYPE")),
            wmi_stats_buf->cal_triggered_cnt,
            wmi_stats_buf->cal_fail_cnt,
            wmi_stats_buf->cal_fcs_cnt,
            wmi_stats_buf->cal_fcs_fail_cnt);
    } else {
        WMI_STATS_PRINT(FATAL,
            "| %-25s| %-25s| %-17u| %-16u| %-16u| %-16u|",
            "PERIODIC_CAL",
            ((A_UINT8 *) wmi_ctrl_path_periodic_cal_type_id_to_name(
                WMI_CTRL_PATH_CALIBRATION_STATS_CAL_TYPE_GET(wmi_stats_buf->cal_info)) +
                sizeof("WMI_CTRL_PATH_STATS_PERIODIC_CAL_TYPE")),
            wmi_stats_buf->cal_triggered_cnt,
            wmi_stats_buf->cal_fail_cnt,
            wmi_stats_buf->cal_fcs_cnt,
            wmi_stats_buf->cal_fcs_fail_cnt);
    }

    WMI_STATS_PRINT(FATAL,
        "|```````````````````````````````````````````````````````````````````"
        "```````````````````````````````````````````````````````````|");
}

/*
 * wmi_stats_print_tag: function to select the tag type and
 * print the corresponding tag structure
 * @tag_type: tag type that is to be printed
 * @tag_buf: pointer to the tag structure
 *
 * return: void
 */
void wmi_stats_print_tag(
        A_UINT32 tag_type,
        void *tag_buf)
{
    switch (tag_type) {
    case WMITLV_TAG_STRUC_wmi_ctrl_path_pdev_stats_struct:
        wmi_print_ctrl_path_pdev_tx_stats_tlv(tag_buf);
        break;

    case WMITLV_TAG_STRUC_wmi_ctrl_path_mem_stats_struct:
        wmi_print_ctrl_path_mem_stats_tlv(tag_buf);
        break;

    case WMITLV_TAG_STRUC_wmi_ctrl_path_calibration_stats_struct:
        wmi_print_ctrl_path_calibration_stats_tlv(tag_buf);
        break;

    /* Add cases for newly added stats here */

    default:
        break;
    }
}

#ifndef __KERNEL__

static void wmi_stats_usage(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= USAGE =================\n");
    printf("%s %s\n", argv[0], argv[1]);
    printf("\t - necessary args \n");
    printf("\t\t<radio_name>\t- ex: wifiX\n");
    printf("\t\t<cmd_id>\t- 1\n");
    printf("\t - optional args\n");
    printf("Example:\n");
    printf("\twifistats wifiX <cmd_id> <optional arg> --wmi\n");
    printf("=========================================\n");
}

static void wmi_stats_usage_pdevstats(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= CONTROL PATH PDEV STATS USAGE =================\n");
    printf("wifistats \n");
    printf("\t - necessary args \n");
    printf("\t\t<radio_name>\t: wifiX\n");
    printf("\t\t<cmid_id>\t: %d\n", WMI_REQUEST_CTRL_PATH_PDEV_TX_STAT);
    printf("\t - optional args\n");
    printf("\t\t<argument>\t: --action\n");
    printf("\t\t--action\t: followed by ACTION to perform \n");
    printf("\t\t--wmi\n");
    printf("Example:\n");
    printf("1. To Display Control Path Stats\n");
    printf("\t %s %s %d --wmi \n", argv[0], argv[1], WMI_REQUEST_CTRL_PATH_PDEV_TX_STAT);
    printf("2. To Reset Control Path PATH Stats\n");
    printf("\t %s %s %d --action 2 --wmi \n", argv[0], argv[1],
            WMI_REQUEST_CTRL_PATH_PDEV_TX_STAT);
    printf("=========================================\n");
}

static void wmi_stats_usage_memstats(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= CONTROL PATH DYNAMIC MEMORY STATS USAGE =================\n");
    printf("wifistats \n");
    printf("\t - necessary args \n");
    printf("\t\t<radio_name>\t: wifiX\n");
    printf("\t\t<cmid_id>\t: %d\n", WMI_REQUEST_CTRL_PATH_MEM_STAT);
    printf("\t - optional args\n");
    printf("\t\t<argument>\t: --action\n");
    printf("\t\t--action\t: followed by ACTION to perform \n");
    printf("\t\t--wmi\n");
    printf("Example:\n");
    printf("1. To Display dynamic memory control path stats\n");
    printf("\t %s %s %d --wmi \n", argv[0], argv[1], WMI_REQUEST_CTRL_PATH_MEM_STAT);
    printf("2. To Reset dynamic memory control path stats\n");
    printf("\t %s %s %d --action 2 --wmi \n", argv[0], argv[1],
            WMI_REQUEST_CTRL_PATH_MEM_STAT);
    printf("=========================================\n");
}

static void wmi_stats_usage_calibrationstats(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= CONTROL PATH CALIBRATION STATS USAGE =================\n");
    printf("wifistats \n");
    printf("\t - necessary args \n");
    printf("\t\t<radio_name>\t: wifiX\n");
    printf("\t\t<cmid_id>\t: %d\n", WMI_REQUEST_CTRL_PATH_CALIBRATION_STAT);
    printf("\t - optional args\n");
    printf("\t\t<argument>\t: --action\n");
    printf("\t\t--action\t: followed by ACTION to perform \n");
    printf("\t\t--wmi\n");
    printf("Example:\n");
    printf("1. To Display Calibration control path stats\n");
    printf("\t %s %s %d --wmi \n", argv[0], argv[1], WMI_REQUEST_CTRL_PATH_CALIBRATION_STAT);
    printf("2. To Reset Calibration control path stats\n");
    printf("\t %s %s %d --action 2 --wmi \n", argv[0], argv[1],
            WMI_REQUEST_CTRL_PATH_CALIBRATION_STAT);
    printf("=========================================\n");
}

void wmi_stats_help(
        A_INT32 argc,
        A_CHAR *argv[])
{
    A_INT32 stats_id = atoi(argv[2]);

    if (stats_id == WMI_REQUEST_CTRL_PATH_PDEV_TX_STAT) {
        wmi_stats_usage_pdevstats(argc, argv);
    } else if (stats_id == WMI_REQUEST_CTRL_PATH_MEM_STAT) {
        wmi_stats_usage_memstats(argc, argv);
    } else if (stats_id == WMI_REQUEST_CTRL_PATH_CALIBRATION_STAT) {
        wmi_stats_usage_calibrationstats(argc, argv);
    } else {
        wmi_stats_usage(argc, argv);
    }
}

/*
 * wmi_stats_buff_alloc: Allocate maximum size buffer
 *
 * return: buff
 */
static void *wmi_stats_buff_alloc(A_INT32 *buff_len)
{
    void *buff = malloc(WMI_CMDS_SIZE_MAX);

    if (!buff) {
        return NULL;
    }
    memset(buff, 0x0, WMI_CMDS_SIZE_MAX);
    *buff_len = WMI_CMDS_SIZE_MAX;

    return buff;
}

/*
 * wmi_stats_buff_free:
 * @buff - Bufferto be freed
 * return:none
 */
static void wmi_stats_buff_free(void *buff)
{
    free(buff);
}

/*
 * wmi_stats_cookie_generate:
 * Generate cookie
 * return: wmistats_cookie
 */
static A_INT32 wmi_stats_cookie_generate(void)
{
    static A_INT32 wmistats_cookie = 0;

    if (!wmistats_cookie) {
        wmistats_cookie = getpid();
    }

    return wmistats_cookie;
}

/*
 * wmi_stats_input_parse: api to be used to parse all input entered by user in CLI
 * @buff - Buffer to be used to fill wmi command
 * @argc - Total number of arguments entered by user
 * @argv[] -- character array of arguments entered by used in CLI interface
 * buff_len -- Pointer to filled, to indicate how much buffer length is filled
 * pdev_id -- Interface id converted to pdev id by host
 * return:
 */
static A_INT32 wmi_stats_input_parse(
        void *buff,
        A_INT32 argc,
        A_CHAR *argv[],
        A_INT32 *buff_len,
        A_INT32 pdev_id)
{

    wmi_request_ctrl_path_stats_cmd_fixed_param *cmd_fixed_param = (wmi_request_ctrl_path_stats_cmd_fixed_param *)buff;
    /*pointer to pdev_id_array*/
    A_UINT32 *pdev_id_array = (A_UINT32 *)(buff + sizeof(wmi_request_ctrl_path_stats_cmd_fixed_param) + WMI_TLV_HDR_SIZE);
    A_UINT32 num_pdev_ids = 0;
    A_UINT32 num_vdev_ids = 0;
    A_UINT32 num_mac_addr_list = 0;
    A_UINT32 i;
    A_UINT8 *buf_ptr=NULL;
    A_UINT32 stats_id = atoi(argv[2]);
    cmd_fixed_param->stats_id_mask = (1 << atoi(argv[2]));

    /*generate cookie information*/
    cmd_fixed_param->request_id = wmi_stats_cookie_generate();

    if (argc < 4) {
        fprintf(stderr, "Invalid commands args\n");
        return -EIO;
    }


    switch (stats_id) {
    case WMI_REQUEST_CTRL_PATH_PDEV_TX_STAT:
    case WMI_REQUEST_CTRL_PATH_CALIBRATION_STAT:
        /*Use pdev_id passed by host,host will convert interface id to proper pdev id*/
        pdev_id_array[num_pdev_ids] = pdev_id;
        num_pdev_ids++;
        break;

    case WMI_REQUEST_CTRL_PATH_MEM_STAT:
        /* No inputs to parse for MEM stats */
        break;

    /* Add case for newly wmi ctrl path added stats here */

    default:
        printf("Specify correct stats id \n");
        return -EIO;
        break;
    }

    /* By default stats is requested & action field is not passed, process get stats */
    if (argc == 4) {
        if (strcmp(argv[3], "--wmi") == 0) {
            cmd_fixed_param->action = WMI_REQUEST_CTRL_PATH_STAT_GET;
            goto parse_done;
        } else {
            printf("Specify correct arguments \n");
            return -EIO;
        }
    }

    for (i = 3; i < argc; i += 2) {
        if (strcmp(argv[i], "--action") == 0) {
            cmd_fixed_param->action = strtoul(argv[i + 1], NULL, 0);
        } else if (strcmp(argv[i], "--wmi") == 0) {
            goto parse_done;;
        } else {
           printf("Unsupported option entered\n");
           return -EIO;
        }
    }

    if (cmd_fixed_param->action == WMI_REQUEST_CTRL_PATH_STAT_RESET) {
        wmistats.timeout = 0;
    }

parse_done:

    /*Set TLV header*/
    WMITLV_SET_HDR(&cmd_fixed_param->tlv_header, WMITLV_TAG_STRUC_wmi_request_ctrl_path_stats_cmd_fixed_param,WMITLV_GET_STRUCT_TLVLEN(wmi_request_ctrl_path_stats_cmd_fixed_param));

    /* Setting tlv header for pdev id arrays*/
    buf_ptr = buff + sizeof(wmi_request_ctrl_path_stats_cmd_fixed_param);
    WMITLV_SET_HDR(buf_ptr,  WMITLV_TAG_ARRAY_UINT32, sizeof(A_UINT32) * num_pdev_ids);

    /* Setting tlv header for vdev id arrays*/
     buf_ptr = buf_ptr + WMI_TLV_HDR_SIZE +(sizeof(A_UINT32) * num_pdev_ids);
    WMITLV_SET_HDR(buf_ptr, WMITLV_TAG_ARRAY_UINT32, sizeof(A_UINT32)*num_vdev_ids);

    /* Setting tlv header for mac addr arrays*/
    buf_ptr = buf_ptr + WMI_TLV_HDR_SIZE +(sizeof(A_UINT32) * num_vdev_ids);
    WMITLV_SET_HDR(buf_ptr,WMITLV_TAG_ARRAY_FIXED_STRUC, sizeof( wmi_mac_addr)*num_mac_addr_list);


    /* Calculate total buffer length */
    *buff_len = (sizeof(wmi_request_ctrl_path_stats_cmd_fixed_param) + WMI_TLV_HDR_SIZE+ (sizeof(A_UINT32)*(num_pdev_ids))
                + WMI_TLV_HDR_SIZE+sizeof(A_UINT32)*(num_vdev_ids)+WMI_TLV_HDR_SIZE+sizeof(wmi_mac_addr)*(num_mac_addr_list));

    return 0;
}

/*
 * wmi_stats_handler: api to be used to parse wmi event and print all the TLV filed in buffer
 * @buff - Buffer containing wmi event
 * len  -- length of event buffer
 * return:
 */
static A_INT32 wmi_stats_handler(
        void *buff,
        A_INT32 len)
{
    A_INT32  status    = LISTEN_CONTINUE;
    A_UINT8* buf_ptr = (A_UINT8*)buff;

    A_UINT32 curr_tlv_tag = WMITLV_GET_TLVTAG(WMITLV_GET_HDR(buf_ptr));
    A_UINT32 curr_tlv_len = WMITLV_GET_TLVLEN(WMITLV_GET_HDR(buf_ptr));

    if (curr_tlv_tag ==  WMITLV_TAG_STRUC_wmi_ctrl_path_stats_event_fixed_param) {
        wmi_ctrl_path_stats_event_fixed_param *ev_fix_param = (wmi_ctrl_path_stats_event_fixed_param *)buff;
        if (!(ev_fix_param->more)) {
          status = LISTEN_DONE;
        }
       /*buffer should point to next TLV in event*/
        buf_ptr += (curr_tlv_len + WMI_TLV_HDR_SIZE) ;
        len -= (curr_tlv_len + WMI_TLV_HDR_SIZE);
    } else {
        printf("wmi_stats_handler Passed wrong buffer \n");
        return status;
    }

    curr_tlv_tag = WMITLV_GET_TLVTAG(WMITLV_GET_HDR(buf_ptr));
    curr_tlv_len = WMITLV_GET_TLVLEN(WMITLV_GET_HDR(buf_ptr));

    while ((len >= curr_tlv_len) && (curr_tlv_tag >= WMITLV_TAG_FIRST_ARRAY_ENUM)) {
        if ((curr_tlv_tag == WMITLV_TAG_ARRAY_UINT32) ||
            (curr_tlv_tag == WMITLV_TAG_ARRAY_BYTE) ||
            (curr_tlv_tag == WMITLV_TAG_ARRAY_STRUC))
        {
            /*buf pointer indicates to header of TLV*/
            buf_ptr += WMI_TLV_HDR_SIZE ;
            len -= WMI_TLV_HDR_SIZE ;
        }
        curr_tlv_tag = WMITLV_GET_TLVTAG(WMITLV_GET_HDR(buf_ptr));
        curr_tlv_len = WMITLV_GET_TLVLEN(WMITLV_GET_HDR(buf_ptr));
        if (curr_tlv_len) {
            wmi_stats_print_tag(curr_tlv_tag,(void *) buf_ptr);
        }
        buf_ptr += curr_tlv_len + WMI_TLV_HDR_SIZE;
        len -= (curr_tlv_len + WMI_TLV_HDR_SIZE) ;
    }

    return status;
}

/*
 * wmi_stats_cookie_get:
 * extract cookie information from event
 * return: wmistats_cookie
 */
static A_INT32 wmi_stats_cookie_get(
        void *buff,
        A_INT32 len)
{
    A_INT32  cookie    = 0;

    wmi_ctrl_path_stats_event_fixed_param *cp_stats_fixed = (wmi_ctrl_path_stats_event_fixed_param*) buff;

    cookie = cp_stats_fixed->request_id; /* Cookie */

    return cookie;
}

static struct wifistats_module wmistats = {
    .name                  = "wmi_fw_stats",
    .help                  = wmi_stats_help,
    .input_buff_alloc      = wmi_stats_buff_alloc,
    .input_parse           = wmi_stats_input_parse,
    .input_buff_free       = wmi_stats_buff_free,
    .input_cookie_generate = wmi_stats_cookie_generate,
    .output_handler        = wmi_stats_handler,
    .output_cookie_get     = wmi_stats_cookie_get,
    .timeout               = 2000,
};

void wmistats_init(void)
{
    wifistats_module_register(&wmistats, sizeof(wmistats));
}

void wmistats_fini(void)
{
    wifistats_module_unregister(&wmistats, sizeof(wmistats));
}

#endif /* ifndef __KERNEL__ */
