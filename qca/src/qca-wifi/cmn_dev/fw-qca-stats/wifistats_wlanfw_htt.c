/*
 * Copyright (c) 2018-2020 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef __KERNEL__
#include "qdf_types.h"
#include "dp_types.h"
#include "dp_internal.h"
#else
#include "wifistats.h"
#endif
#include <stddef.h> /* offsetof */
#include "htt.h"
#include "htt_stats.h"

#define HTT_TLV_HDR_LEN HTT_T2H_EXT_STATS_CONF_TLV_HDR_SIZE
#define HTT_MAX_STRING_LEN 1000

/*
 * This HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER is a compile time check
 * creates a array with negative size if the check fails. This
 * failure check occurs during compile time
 *
 */
#define HTT_MAX_PRINT_CHAR_PER_ELEM 15

#ifdef __KERNEL__
#define HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(num_elements, print_buffer_length)
#define malloc(size) qdf_mem_malloc(size)
#define free(ptr) qdf_mem_free(ptr)
#define FATAL 1
static qdf_debugfs_file_t file = NULL;
#define HTT_STATS_PRINT(level, fmt, ...)  qdf_debugfs_printf(file, fmt"\n", ##__VA_ARGS__)

static inline A_UINT32 *htt_stats_msg_get(void *data)
{
    struct htt_dbgfs_cfg *dbgfs_cfg = (struct htt_dbgfs_cfg *)data;
    file = dbgfs_cfg->m;
    return dbgfs_cfg->msg_word;
}
#define HTT_STATS_ERR DP_TRACE
#else
#define HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(num_elements, print_buffer_length) \
    typedef __attribute__ ((__unused__)) char string_buf[(2 * (print_buffer_length >= (num_elements * HTT_MAX_PRINT_CHAR_PER_ELEM))) - 1];

#define HTT_STATS_PRINT(level, fmt, ...) \
    do { \
        if (httstats.output_fp) { \
            fprintf(httstats.output_fp, fmt,##__VA_ARGS__); \
            fprintf(httstats.output_fp, "\n"); \
        } else { \
            printf(fmt,##__VA_ARGS__); \
            printf("\n"); \
        } \
    } while (0)

#define HTT_STATS_ERR HTT_STATS_PRINT
/*
 * Provide a forward declaration of httstats.
 * (The definition is at the bottom of this file.)
 */
static struct wifistats_module httstats;
#define htt_stats_msg_get(data) data
void __attribute__ ((constructor)) httstats_init(void);
void __attribute__ ((destructor)) httstats_fini(void);
#endif /* ifdef __KERNEL__ */

struct httstats_cmd_request {
    A_UINT32 config_param0;

    A_UINT32 config_param1;
    A_UINT32 config_param2;
    A_UINT32 config_param3;
    A_INT32  pid;
    A_INT8   stats_id;
};

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

/*
 * htt_print_stats_string_tlv: display htt_stats_string_tlv
 * @tag_buf: buffer containing the tlv htt_stats_string_tlv
 *
 * return:void
 */
static void htt_print_stats_string_tlv(A_UINT32 *tag_buf)
{
    htt_stats_string_tlv *htt_stats_buf =
        (htt_stats_string_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                    = 0;
    A_CHAR   data[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                  = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_STATS_STRING_TLV:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&data[index],
                HTT_MAX_STRING_LEN - index,
                "%.*s", 4, (A_CHAR *)&(htt_stats_buf->data[i]));
    }

    HTT_STATS_PRINT(FATAL, "data = %s\n", data);
}

static void htt_stringify_array(
        A_CHAR *str,
        A_UINT32 str_size,
        A_UINT32 *array,
        A_UINT32 num_array_elements,
        A_UINT32 index_offset,
        A_UINT8 skip_zero_vals )
{
    A_UINT8  i;
    A_UINT16 index = 0;
    A_UINT8  null_output = 1;

    if ( str && str_size ) {
        str[0] = '\0';
    } else {
        return;
    }

    for (i = 0; i < num_array_elements; i++) {
        if ( !skip_zero_vals || array[i] ) {
            null_output = 0;
            index += snprintf(str+index,
                    str_size - index,
                    " %u:%u,", i+index_offset,
                    array[i]);
        }
    }

    if ( null_output && skip_zero_vals ) {
            index += snprintf(str+index,
                    str_size - index,
                    " NONE");
    }
}

A_CHAR g_mgmt_fc_subtype[HTT_STATS_SUBTYPE_MAX][12]={
    "ASSOC_REQ",    /* 0 */
    "ASSOC_RES",    /* 1 */
    "REASSOC_REQ",  /* 2 */
    "REASSOC_RES",  /* 3 */
    "PRB_REQ",      /* 4 */
    "PRB_RES",      /* 5 */
    "RESV",         /* 6 */
    "RESV",         /* 7 */
    "BCN",          /* 8 */
    "ATIM",         /* 9 */
    "DISASSOC",     /* 10 */
    "AUTH",         /* 11 */
    "DAUTH",        /* 12 */
    "ACTN",         /* 13 */
    "RESV",         /* 14 */
    "RESV",         /* 15 */
};

/*
 * htt_print_peer_ctrl_path_txrx_stats_tlv: display htt_peer_ctrl_path_txrx_stats_tlv
 * @tag_buf: buffer containing the tlv htt_peer_ctrl_path_txrx_stats_tlv
 *
 * return: void
 */
static void htt_print_peer_ctrl_path_txrx_stats_tlv(A_UINT32 *tag_buf)
{
    htt_peer_ctrl_path_txrx_stats_tlv *htt_stats_buf =
        (htt_peer_ctrl_path_txrx_stats_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index;
    A_CHAR   *peer_tx_mgmt_subtype = NULL;
    A_CHAR   *peer_rx_mgmt_subtype = NULL;

    peer_tx_mgmt_subtype = (A_CHAR *)malloc(HTT_MAX_STRING_LEN * sizeof(A_CHAR));
    if (!peer_tx_mgmt_subtype) {
       HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
       return;
    }

    peer_rx_mgmt_subtype = (A_CHAR *)malloc(HTT_MAX_STRING_LEN * sizeof(A_CHAR));
    if (!peer_rx_mgmt_subtype) {
       HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
       free(peer_tx_mgmt_subtype);
       return;
    }

    HTT_STATS_PRINT(FATAL, "HTT_STATS_PEER_CTRL_PATH_TXRX_STATS_TAG:");
    HTT_STATS_PRINT(FATAL, "peer_mac_addr = %02x:%02x:%02x:%02x:%02x:%02x",
            (htt_stats_buf->peer_mac_addr.mac_addr31to0  & 0x000000FF),
            (htt_stats_buf->peer_mac_addr.mac_addr31to0  & 0x0000FF00) >> 8,
            (htt_stats_buf->peer_mac_addr.mac_addr31to0  & 0x00FF0000) >> 16,
            (htt_stats_buf->peer_mac_addr.mac_addr31to0  & 0xFF000000) >> 24,
            (htt_stats_buf->peer_mac_addr.mac_addr47to32 & 0x000000FF),
            (htt_stats_buf->peer_mac_addr.mac_addr47to32 & 0x0000FF00) >> 8);

    index = 0;
    for (i = 0; i < HTT_STATS_SUBTYPE_MAX; i++) {
        if (strncmp(g_mgmt_fc_subtype[i],"RESV",4) == 0) {
            continue;
        }
        index += snprintf(&peer_tx_mgmt_subtype[index],
                HTT_MAX_STRING_LEN - index,
                " %s[%u]:%u,", g_mgmt_fc_subtype[i], i,
                htt_stats_buf->peer_tx_mgmt_subtype[i]);
    }
    HTT_STATS_PRINT(FATAL, "peer_tx_mgmt_fc_subtype = %s ", peer_tx_mgmt_subtype);

    index = 0;
    for (i = 0; i < HTT_STATS_SUBTYPE_MAX; i++) {
        if (strncmp(g_mgmt_fc_subtype[i],"RESV",4) == 0) {
            continue;
        }
        index += snprintf(&peer_rx_mgmt_subtype[index],
                HTT_MAX_STRING_LEN - index,
                " %s[%u]:%u,", g_mgmt_fc_subtype[i], i,
                htt_stats_buf->peer_rx_mgmt_subtype[i]);
    }
    HTT_STATS_PRINT(FATAL, "peer_rx_mgmt_fc_subtype = %s \n", peer_rx_mgmt_subtype);

    free(peer_tx_mgmt_subtype);
    free(peer_rx_mgmt_subtype);
}

/*
 * htt_print_tx_pdev_stats_cmn_tlv: display htt_tx_pdev_stats_cmn_tlv
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_cmn_tlv
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_cmn_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_cmn_tlv *htt_stats_buf =
        (htt_tx_pdev_stats_cmn_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_CMN_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    HTT_STATS_PRINT(FATAL, "comp_delivered = %u",
            htt_stats_buf->comp_delivered);
    HTT_STATS_PRINT(FATAL, "self_triggers = %u",
            htt_stats_buf->self_triggers);
    /*HTT_STATS_PRINT(FATAL, "word(reserved) = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "hw_queued = %u",
            htt_stats_buf->hw_queued);
    HTT_STATS_PRINT(FATAL, "hw_reaped = %u",
            htt_stats_buf->hw_reaped);
    HTT_STATS_PRINT(FATAL, "underrun = %u",
            htt_stats_buf->underrun);
    HTT_STATS_PRINT(FATAL, "hw_paused = %u",
            htt_stats_buf->hw_paused);
    HTT_STATS_PRINT(FATAL, "hw_flush = %u",
            htt_stats_buf->hw_flush);
    HTT_STATS_PRINT(FATAL, "hw_filt = %u",
            htt_stats_buf->hw_filt);
    HTT_STATS_PRINT(FATAL, "tx_abort = %u",
            htt_stats_buf->tx_abort);
    HTT_STATS_PRINT(FATAL, "ppdu_ok = %u",
            htt_stats_buf->ppdu_ok);
    HTT_STATS_PRINT(FATAL, "mpdu_requeued = %u",
            htt_stats_buf->mpdu_requed);
    HTT_STATS_PRINT(FATAL, "tx_xretry = %u",
            htt_stats_buf->tx_xretry);
    HTT_STATS_PRINT(FATAL, "data_rc = %u",
            htt_stats_buf->data_rc);
    HTT_STATS_PRINT(FATAL, "mpdu_dropped_xretry = %u",
            htt_stats_buf->mpdu_dropped_xretry);
    HTT_STATS_PRINT(FATAL, "illegal_rate_phy_err = %u",
            htt_stats_buf->illgl_rate_phy_err);
    HTT_STATS_PRINT(FATAL, "cont_xretry = %u",
            htt_stats_buf->cont_xretry);
    HTT_STATS_PRINT(FATAL, "tx_timeout = %u",
            htt_stats_buf->tx_timeout);
    HTT_STATS_PRINT(FATAL, "tx_time_dur_data = %u",
            htt_stats_buf->tx_time_dur_data);
    HTT_STATS_PRINT(FATAL, "pdev_resets = %u",
            htt_stats_buf->pdev_resets);
    HTT_STATS_PRINT(FATAL, "phy_underrun = %u",
            htt_stats_buf->phy_underrun);
    HTT_STATS_PRINT(FATAL, "txop_ovf = %u",
            htt_stats_buf->txop_ovf);
    HTT_STATS_PRINT(FATAL, "seq_posted = %u",
            htt_stats_buf->seq_posted);
    HTT_STATS_PRINT(FATAL, "seq_failed_queueing = %u",
            htt_stats_buf->seq_failed_queueing);
    HTT_STATS_PRINT(FATAL, "seq_completed = %u",
            htt_stats_buf->seq_completed);
    HTT_STATS_PRINT(FATAL, "seq_restarted = %u",
            htt_stats_buf->seq_restarted);
    HTT_STATS_PRINT(FATAL, "seq_txop_repost_stop = %u",
            htt_stats_buf->seq_txop_repost_stop);
    HTT_STATS_PRINT(FATAL, "next_seq_cancel = %u",
            htt_stats_buf->next_seq_cancel);
    HTT_STATS_PRINT(FATAL, "dl_mu_mimo_seq_posted = %u",
            htt_stats_buf->mu_seq_posted);
    HTT_STATS_PRINT(FATAL, "dl_mu_ofdma_seq_posted = %u",
            htt_stats_buf->mu_ofdma_seq_posted);
    HTT_STATS_PRINT(FATAL, "ul_mu_mimo_seq_posted = %u",
            htt_stats_buf->ul_mumimo_seq_posted);
    HTT_STATS_PRINT(FATAL, "ul_mu_ofdma_seq_posted = %u",
            htt_stats_buf->ul_ofdma_seq_posted);
    HTT_STATS_PRINT(FATAL, "mu_mimo_peer_blacklist_count = %u",
            htt_stats_buf->num_mu_peer_blacklisted);
    HTT_STATS_PRINT(FATAL, "seq_qdepth_repost_stop = %u",
            htt_stats_buf->seq_qdepth_repost_stop);
    HTT_STATS_PRINT(FATAL, "seq_min_msdu_repost_stop = %u",
            htt_stats_buf->seq_min_msdu_repost_stop);
    HTT_STATS_PRINT(FATAL, "mu_seq_min_msdu_repost_stop = %u",
            htt_stats_buf->mu_seq_min_msdu_repost_stop);
    HTT_STATS_PRINT(FATAL, "seq_switch_hw_paused = %u",
            htt_stats_buf->seq_switch_hw_paused);
    HTT_STATS_PRINT(FATAL, "next_seq_posted_dsr = %u",
            htt_stats_buf->next_seq_posted_dsr);
    HTT_STATS_PRINT(FATAL, "seq_posted_isr = %u",
            htt_stats_buf->seq_posted_isr);
    HTT_STATS_PRINT(FATAL, "seq_ctrl_cached = %u",
            htt_stats_buf->seq_ctrl_cached);
    HTT_STATS_PRINT(FATAL, "mpdu_count_tqm = %u",
            htt_stats_buf->mpdu_count_tqm);
    HTT_STATS_PRINT(FATAL, "msdu_count_tqm = %u",
            htt_stats_buf->msdu_count_tqm);
    HTT_STATS_PRINT(FATAL, "mpdu_removed_tqm = %u",
            htt_stats_buf->mpdu_removed_tqm);
    HTT_STATS_PRINT(FATAL, "msdu_removed_tqm = %u",
            htt_stats_buf->msdu_removed_tqm);
    HTT_STATS_PRINT(FATAL, "remove_mpdus_max_retries = %u",
            htt_stats_buf->remove_mpdus_max_retries);
    HTT_STATS_PRINT(FATAL, "mpdus_sw_flush = %u",
            htt_stats_buf->mpdus_sw_flush);
    HTT_STATS_PRINT(FATAL, "mpdus_hw_filter = %u",
            htt_stats_buf->mpdus_hw_filter);
    HTT_STATS_PRINT(FATAL, "mpdus_truncated = %u",
            htt_stats_buf->mpdus_truncated);
    HTT_STATS_PRINT(FATAL, "mpdus_ack_failed = %u",
            htt_stats_buf->mpdus_ack_failed);
    HTT_STATS_PRINT(FATAL, "mpdus_expired = %u",
            htt_stats_buf->mpdus_expired);
    HTT_STATS_PRINT(FATAL, "mpdus_seq_hw_retry = %u",
            htt_stats_buf->mpdus_seq_hw_retry);
    HTT_STATS_PRINT(FATAL, "ack_tlv_proc = %u",
            htt_stats_buf->ack_tlv_proc);
    HTT_STATS_PRINT(FATAL, "coex_abort_mpdu_cnt_valid = %u",
            htt_stats_buf->coex_abort_mpdu_cnt_valid);
    HTT_STATS_PRINT(FATAL, "coex_abort_mpdu_cnt = %u",
            htt_stats_buf->coex_abort_mpdu_cnt);
    HTT_STATS_PRINT(FATAL, "num_total_ppdus_tried_ota = %u",
            htt_stats_buf->num_total_ppdus_tried_ota);
    HTT_STATS_PRINT(FATAL, "num_data_ppdus_tried_ota = %u",
            htt_stats_buf->num_data_ppdus_tried_ota);
    HTT_STATS_PRINT(FATAL, "local_ctrl_mgmt_enqued = %u",
            htt_stats_buf->local_ctrl_mgmt_enqued);
    HTT_STATS_PRINT(FATAL, "local_ctrl_mgmt_freed = %u",
            htt_stats_buf->local_ctrl_mgmt_freed);
    HTT_STATS_PRINT(FATAL, "local_data_enqued = %u",
            htt_stats_buf->local_data_enqued);
    HTT_STATS_PRINT(FATAL, "local_data_freed = %u",
            htt_stats_buf->local_data_freed);
    HTT_STATS_PRINT(FATAL, "mpdu_tried = %u",
            htt_stats_buf->mpdu_tried);
    HTT_STATS_PRINT(FATAL, "isr_wait_seq_posted = %u",
            htt_stats_buf->isr_wait_seq_posted);
    HTT_STATS_PRINT(FATAL, "tx_active_dur_us_low = %u",
            htt_stats_buf->tx_active_dur_us_low);
    HTT_STATS_PRINT(FATAL, "tx_active_dur_us_high = %u",
            htt_stats_buf->tx_active_dur_us_high);
    HTT_STATS_PRINT(FATAL, "fes_offsets_err_cnt = %u\n",
            htt_stats_buf->fes_offsets_err_cnt);
}

/*
 * htt_print_tx_pdev_stats_urrn_tlv_v: display htt_tx_pdev_stats_urrn_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_urrn_tlv_v
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_urrn_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_urrn_tlv_v *htt_stats_buf =
        (htt_tx_pdev_stats_urrn_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                          = 0;
    A_CHAR   urrn_stats[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                        = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_URRN_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&urrn_stats[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->urrn_stats[i]);
    }

    HTT_STATS_PRINT(FATAL, "urrn_stats = %s\n", urrn_stats);
}

/*
 * htt_print_tx_pdev_stats_flush_tlv_v: display htt_tx_pdev_stats_flush_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_flush_tlv_v
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_flush_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_flush_tlv_v *htt_stats_buf =
        (htt_tx_pdev_stats_flush_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                          = 0;
    A_CHAR   flush_errs[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                        = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_FLUSH_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&flush_errs[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->flush_errs[i]);
    }

    HTT_STATS_PRINT(FATAL, "flush_errs = %s\n", flush_errs);
}

/*
 * htt_print_pdev_ctrl_path_tx_stats_tlv: display htt_pdev_ctrl_path_tx_stats_tlv_v
 * @tag_buf: buffer containing the tlv htt_pdev_ctrl_path_tx_stats_tlv_v
 *
 * return:void
 */
static void htt_print_pdev_ctrl_path_tx_stats_tlv(A_UINT32 *tag_buf)
{
    htt_pdev_ctrl_path_tx_stats_tlv_v *htt_stats_buf =
        (htt_pdev_ctrl_path_tx_stats_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                    = 0;
    A_CHAR   fw_tx_mgmt_subtype[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_STATS_PDEV_CTRL_PATH_TX_STATS_TAG:");
    for (i = 0; i < HTT_STATS_SUBTYPE_MAX; i++) {
        index += snprintf(&fw_tx_mgmt_subtype[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->fw_tx_mgmt_subtype[i]);
    }

    HTT_STATS_PRINT(FATAL, "fw_tx_mgmt_subtype = %s \n", fw_tx_mgmt_subtype);
}

/*
 * htt_print_tx_pdev_stats_sifs_tlv_v: display htt_tx_pdev_stats_sifs_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_sifs_tlv_v
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_sifs_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_sifs_tlv_v *htt_stats_buf =
        (htt_tx_pdev_stats_sifs_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                           = 0;
    A_CHAR   sifs_status[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                         = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_SIFS_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&sifs_status[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->sifs_status[i]);
    }

    HTT_STATS_PRINT(FATAL, "sifs_status = %s\n", sifs_status);
}

/*
 * htt_print_tx_pdev_stats_phy_err_tlv_v: display htt_tx_pdev_stats_phy_err_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_phy_err_tlv_v
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_phy_err_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_phy_err_tlv_v *htt_stats_buf =
        (htt_tx_pdev_stats_phy_err_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                        = 0;
    A_CHAR   phy_errs[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                      = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_PHY_ERR_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&phy_errs[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->phy_errs[i]);
    }

    HTT_STATS_PRINT(FATAL, "phy_errs = %s\n", phy_errs);
}

/*
 * htt_print_tx_pdev_stats_sifs_hist_tlv_v: display htt_tx_pdev_stats_sifs_hist_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_sifs_hist_tlv_v
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_sifs_hist_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_sifs_hist_tlv_v *htt_stats_buf =
        (htt_tx_pdev_stats_sifs_hist_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                = 0;
    A_CHAR   sifs_hist_status[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                              = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_SIFS_HIST_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&sifs_hist_status[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->sifs_hist_status[i]);
    }

    HTT_STATS_PRINT(FATAL, "sifs_hist_status = %s\n", sifs_hist_status);
}

/*
 * htt_print_tx_pdev_stats_tx_ppdu_stats_tlv_v: display htt_tx_pdev_stats_tx_ppdu_stats_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_tx_ppdu_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_tx_ppdu_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_tx_ppdu_stats_tlv_v *htt_stats_buf =
        (htt_tx_pdev_stats_tx_ppdu_stats_tlv_v *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_TX_PPDU_STATS_TLV_V:");

    HTT_STATS_PRINT(FATAL, "num_data_ppdus_legacy_su = %u",
            htt_stats_buf->num_data_ppdus_legacy_su);

    HTT_STATS_PRINT(FATAL, "num_data_ppdus_ac_su = %u",
            htt_stats_buf->num_data_ppdus_ac_su);

    HTT_STATS_PRINT(FATAL, "num_data_ppdus_ax_su = %u",
            htt_stats_buf->num_data_ppdus_ax_su);

    HTT_STATS_PRINT(FATAL, "num_data_ppdus_ac_su_txbf = %u",
            htt_stats_buf->num_data_ppdus_ac_su_txbf);

    HTT_STATS_PRINT(FATAL, "num_data_ppdus_ax_su_txbf = %u\n",
            htt_stats_buf->num_data_ppdus_ax_su_txbf);
}

/*
 * htt_print_tx_pdev_stats_tried_mpdu_cnt_hist_tlv_v: display htt_tx_pdev_stats_tried_mpdu_cnt_hist_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_tried_mpdu_cnt_hist_tlv_v
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_tried_mpdu_cnt_hist_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_tried_mpdu_cnt_hist_tlv_v *htt_stats_buf =
        (htt_tx_pdev_stats_tried_mpdu_cnt_hist_tlv_v *)tag_buf;

    A_UINT8  i;
    A_UINT16 index                                   = 0;
    A_CHAR   tried_mpdu_cnt_hist[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 num_elements                            =
        ((HTT_STATS_TLV_LENGTH_GET(*tag_buf) - sizeof(htt_stats_buf->hist_bin_size)) >> 2);
    A_UINT32 required_buffer_size = HTT_MAX_PRINT_CHAR_PER_ELEM * num_elements;

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_TRIED_MPDU_CNT_HIST_TLV_V:");
    HTT_STATS_PRINT(FATAL, "TRIED_MPDU_CNT_HIST_BIN_SIZE : %u", htt_stats_buf->hist_bin_size);

    if (required_buffer_size < HTT_MAX_STRING_LEN) {
        for (i = 0; i < num_elements; i++) {
            index += snprintf(&tried_mpdu_cnt_hist[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i, htt_stats_buf->tried_mpdu_cnt_hist[i]);
        }

        HTT_STATS_PRINT(FATAL, "tried_mpdu_cnt_hist = %s\n", tried_mpdu_cnt_hist);
    } else {
        HTT_STATS_PRINT(FATAL, "INSUFFICIENT PRINT BUFFER\n");
    }
}

/*
 * htt_print_hw_stats_intr_misc_tlv: display htt_hw_stats_intr_misc_tlv
 * @tag_buf: buffer containing the tlv htt_hw_stats_intr_misc_tlv
 *
 * return:void
 */
static void htt_print_hw_stats_intr_misc_tlv(A_UINT32 *tag_buf)
{
    htt_hw_stats_intr_misc_tlv *htt_stats_buf =
        (htt_hw_stats_intr_misc_tlv *)tag_buf;
    A_CHAR   hw_intr_name[HTT_STATS_MAX_HW_INTR_NAME_LEN + 1] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_HW_STATS_INTR_MISC_TLV:");
    memcpy(hw_intr_name, &(htt_stats_buf->hw_intr_name[0]), HTT_STATS_MAX_HW_INTR_NAME_LEN);
    HTT_STATS_PRINT(FATAL, "hw_intr_name = %s ", hw_intr_name);
    HTT_STATS_PRINT(FATAL, "mask = %u",
            htt_stats_buf->mask);
    HTT_STATS_PRINT(FATAL, "count = %u\n",
            htt_stats_buf->count);
}

/*
 * htt_print_hw_stats_wd_timeout_tlv: display htt_hw_stats_wd_timeout_tlv
 * @tag_buf: buffer containing the tlv htt_hw_stats_wd_timeout_tlv
 *
 * return:void
 */
static void htt_print_hw_stats_wd_timeout_tlv(A_UINT32 *tag_buf)
{
    htt_hw_stats_wd_timeout_tlv *htt_stats_buf =
        (htt_hw_stats_wd_timeout_tlv *)tag_buf;
    A_CHAR   hw_module_name[HTT_STATS_MAX_HW_MODULE_NAME_LEN + 1] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_HW_STATS_WD_TIMEOUT_TLV:");
    memcpy(hw_module_name, &(htt_stats_buf->hw_module_name[0]), HTT_STATS_MAX_HW_MODULE_NAME_LEN);
    HTT_STATS_PRINT(FATAL, "hw_module_name = %s ", hw_module_name);
    HTT_STATS_PRINT(FATAL, "count = %u",
            htt_stats_buf->count);
}

/*
 * htt_print_hw_stats_pdev_errs_tlv: display htt_hw_stats_pdev_errs_tlv
 * @tag_buf: buffer containing the tlv htt_hw_stats_pdev_errs_tlv
 *
 * return:void
 */
static void htt_print_hw_stats_pdev_errs_tlv(A_UINT32 *tag_buf)
{
    htt_hw_stats_pdev_errs_tlv *htt_stats_buf =
        (htt_hw_stats_pdev_errs_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_HW_STATS_PDEV_ERRS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "tx_abort = %u",
            htt_stats_buf->tx_abort);
    HTT_STATS_PRINT(FATAL, "tx_abort_fail_count = %u",
            htt_stats_buf->tx_abort_fail_count);
    HTT_STATS_PRINT(FATAL, "rx_abort = %u",
            htt_stats_buf->rx_abort);
    HTT_STATS_PRINT(FATAL, "rx_abort_fail_count = %u",
            htt_stats_buf->rx_abort_fail_count);
    HTT_STATS_PRINT(FATAL, "rx_flush_cnt = %u",
            htt_stats_buf->rx_flush_cnt);
    HTT_STATS_PRINT(FATAL, "warm_reset = %u",
            htt_stats_buf->warm_reset);
    HTT_STATS_PRINT(FATAL, "cold_reset = %u",
            htt_stats_buf->cold_reset);
    HTT_STATS_PRINT(FATAL, "mac_cold_reset_restore_cal = %u",
            htt_stats_buf->mac_cold_reset_restore_cal);
    HTT_STATS_PRINT(FATAL, "mac_cold_reset = %u",
            htt_stats_buf->mac_cold_reset);
    HTT_STATS_PRINT(FATAL, "mac_warm_reset = %u",
            htt_stats_buf->mac_warm_reset);
    HTT_STATS_PRINT(FATAL, "mac_only_reset = %u",
            htt_stats_buf->mac_only_reset);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset = %u",
            htt_stats_buf->phy_warm_reset);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_ucode_trig = %u",
            htt_stats_buf->phy_warm_reset_ucode_trig);
    HTT_STATS_PRINT(FATAL, "mac_warm_reset_restore_cal = %u",
            htt_stats_buf->mac_warm_reset_restore_cal);
    HTT_STATS_PRINT(FATAL, "mac_sfm_reset = %u",
            htt_stats_buf->mac_sfm_reset);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_m3_ssr = %u",
            htt_stats_buf->phy_warm_reset_m3_ssr);
    HTT_STATS_PRINT(FATAL, "fw_rx_rings_reset = %u",
            htt_stats_buf->fw_rx_rings_reset);
    HTT_STATS_PRINT(FATAL, "tx_flush = %u",
            htt_stats_buf->tx_flush);
    HTT_STATS_PRINT(FATAL, "tx_glb_reset = %u",
            htt_stats_buf->tx_glb_reset);
    HTT_STATS_PRINT(FATAL, "tx_txq_reset = %u",
            htt_stats_buf->tx_txq_reset);
    HTT_STATS_PRINT(FATAL, "rx_timeout_reset = %u\n",
            htt_stats_buf->rx_timeout_reset);

    HTT_STATS_PRINT(FATAL, "PDEV_PHY_WARM_RESET_REASONS:");

    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_phy_m3 = %u",
            htt_stats_buf->phy_warm_reset_reason_phy_m3);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_tx_hw_stuck = %u",
            htt_stats_buf->phy_warm_reset_reason_tx_hw_stuck);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_num_cca_rx_frame_stuck = %u",
            htt_stats_buf->phy_warm_reset_reason_num_cca_rx_frame_stuck);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_wal_rx_recovery_rst_rx_busy = %u",
            htt_stats_buf->phy_warm_reset_reason_wal_rx_recovery_rst_rx_busy);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_wal_rx_recovery_rst_mac_hang = %u",
            htt_stats_buf->phy_warm_reset_reason_wal_rx_recovery_rst_mac_hang);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_mac_reset_converted_phy_reset = %u",
            htt_stats_buf->phy_warm_reset_reason_mac_reset_converted_phy_reset);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_tx_lifetime_expiry_cca_stuck = %u",
            htt_stats_buf->phy_warm_reset_reason_tx_lifetime_expiry_cca_stuck);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_tx_consecutive_flush9_war = %u",
            htt_stats_buf->phy_warm_reset_reason_tx_consecutive_flush9_war);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_tx_hwsch_reset_war = %u",
            htt_stats_buf->phy_warm_reset_reason_tx_hwsch_reset_war);
    HTT_STATS_PRINT(FATAL, "phy_warm_reset_reason_hwsch_wdog_or_cca_wdog_war = %u\n",
            htt_stats_buf->phy_warm_reset_reason_hwsch_wdog_or_cca_wdog_war);


    HTT_STATS_PRINT(FATAL, "WAL_RX_RECOVERY_STATS:");

    HTT_STATS_PRINT(FATAL, "wal_rx_recovery_rst_mac_hang_count = %u",
            htt_stats_buf->wal_rx_recovery_rst_mac_hang_count);
    HTT_STATS_PRINT(FATAL, "wal_rx_recovery_rst_known_sig_count = %u",
            htt_stats_buf->wal_rx_recovery_rst_known_sig_count);
    HTT_STATS_PRINT(FATAL, "wal_rx_recovery_rst_no_rx_count = %u",
            htt_stats_buf->wal_rx_recovery_rst_no_rx_count);
    HTT_STATS_PRINT(FATAL, "wal_rx_recovery_rst_no_rx_consecutive_count = %u",
            htt_stats_buf->wal_rx_recovery_rst_no_rx_consecutive_count);
    HTT_STATS_PRINT(FATAL, "wal_rx_recovery_rst_rx_busy_count = %u",
            htt_stats_buf->wal_rx_recovery_rst_rx_busy_count);
    HTT_STATS_PRINT(FATAL, "wal_rx_recovery_rst_phy_mac_hang_count = %u\n",
            htt_stats_buf->wal_rx_recovery_rst_phy_mac_hang_count);
}

/*
 * htt_print_msdu_flow_stats_tlv: display htt_msdu_flow_stats_tlv
 * @tag_buf: buffer containing the tlv htt_msdu_flow_stats_tlv
 *
 * return:void
 */
static void htt_print_msdu_flow_stats_tlv(A_UINT32 *tag_buf)
{
    htt_msdu_flow_stats_tlv *htt_stats_buf =
        (htt_msdu_flow_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_MSDU_FLOW_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "last_update_timestamp = %u",
            htt_stats_buf->last_update_timestamp);
    HTT_STATS_PRINT(FATAL, "last_add_timestamp = %u",
            htt_stats_buf->last_add_timestamp);
    HTT_STATS_PRINT(FATAL, "last_remove_timestamp = %u",
            htt_stats_buf->last_remove_timestamp);
    HTT_STATS_PRINT(FATAL, "total_processed_msdu_count = %u",
            htt_stats_buf->total_processed_msdu_count);
    HTT_STATS_PRINT(FATAL, "cur_msdu_count_in_flowq = %u",
            htt_stats_buf->cur_msdu_count_in_flowq);
    HTT_STATS_PRINT(FATAL, "sw_peer_id = %u",
            htt_stats_buf->sw_peer_id);
    HTT_STATS_PRINT(FATAL, "tx_flow_no = %u",
            htt_stats_buf->tx_flow_no__tid_num__drop_rule & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "tid_num = %u",
            (htt_stats_buf->tx_flow_no__tid_num__drop_rule & 0xF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "drop_rule = %u",
            (htt_stats_buf->tx_flow_no__tid_num__drop_rule & 0x100000) >> 20);
    HTT_STATS_PRINT(FATAL, "last_cycle_enqueue_count = %u",
            htt_stats_buf->last_cycle_enqueue_count);
    HTT_STATS_PRINT(FATAL, "last_cycle_dequeue_count = %u",
            htt_stats_buf->last_cycle_dequeue_count);
    HTT_STATS_PRINT(FATAL, "last_cycle_drop_count = %u",
            htt_stats_buf->last_cycle_drop_count);
    HTT_STATS_PRINT(FATAL, "current_drop_th = %u\n",
            htt_stats_buf->current_drop_th);
}

/*
 * htt_print_tx_tid_stats_tlv: display htt_tx_tid_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_tid_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_tid_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_tid_stats_tlv *htt_stats_buf =
        (htt_tx_tid_stats_tlv *)tag_buf;
    A_CHAR   tid_name[MAX_HTT_TID_NAME + 1] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TX_TID_STATS_TLV:");
    memcpy(tid_name, &(htt_stats_buf->tid_name[0]), MAX_HTT_TID_NAME);
    HTT_STATS_PRINT(FATAL, "tid_name = %s ", tid_name);
    HTT_STATS_PRINT(FATAL, "sw_peer_id = %u",
            htt_stats_buf->sw_peer_id__tid_num & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "tid_num = %u",
            (htt_stats_buf->sw_peer_id__tid_num & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "num_sched_pending = %u",
            htt_stats_buf->num_sched_pending__num_ppdu_in_hwq & 0xFF);
    HTT_STATS_PRINT(FATAL, "num_ppdu_in_hwq = %u",
            (htt_stats_buf->num_sched_pending__num_ppdu_in_hwq & 0xFF00) >> 8);
    HTT_STATS_PRINT(FATAL, "tid_flags = 0x%x",
            htt_stats_buf->tid_flags);
    HTT_STATS_PRINT(FATAL, "hw_queued = %u",
            htt_stats_buf->hw_queued);
    HTT_STATS_PRINT(FATAL, "hw_reaped = %u",
            htt_stats_buf->hw_reaped);
    HTT_STATS_PRINT(FATAL, "mpdus_hw_filter = %u",
            htt_stats_buf->mpdus_hw_filter);
    HTT_STATS_PRINT(FATAL, "qdepth_bytes = %u",
            htt_stats_buf->qdepth_bytes);
    HTT_STATS_PRINT(FATAL, "qdepth_num_msdu = %u",
            htt_stats_buf->qdepth_num_msdu);
    HTT_STATS_PRINT(FATAL, "qdepth_num_mpdu = %u",
            htt_stats_buf->qdepth_num_mpdu);
    HTT_STATS_PRINT(FATAL, "last_scheduled_tsmp = %u",
            htt_stats_buf->last_scheduled_tsmp);
    HTT_STATS_PRINT(FATAL, "pause_module_id = %u",
            htt_stats_buf->pause_module_id);
    HTT_STATS_PRINT(FATAL, "block_module_id = %u\n",
            htt_stats_buf->block_module_id);
    /*HTT_STATS_PRINT(FATAL, "tid_tx_airtime = %u\n",
            htt_stats_buf->tid_tx_airtime);*/
}

/*
 * htt_print_tx_tid_stats_v1_tlv: display htt_tx_tid_stats_v1_tlv
 * @tag_buf: buffer containing the tlv htt_tx_tid_stats_v1_tlv
 *
 * return:void
 */
static void htt_print_tx_tid_stats_v1_tlv(A_UINT32 *tag_buf)
{
    htt_tx_tid_stats_v1_tlv *htt_stats_buf =
        (htt_tx_tid_stats_v1_tlv *)tag_buf;
    A_CHAR   tid_name[MAX_HTT_TID_NAME + 1] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TX_TID_STATS_V1_TLV:");
    memcpy(tid_name, &(htt_stats_buf->tid_name[0]), MAX_HTT_TID_NAME);
    HTT_STATS_PRINT(FATAL, "tid_name = %s ", tid_name);
    HTT_STATS_PRINT(FATAL, "sw_peer_id = %u",
            htt_stats_buf->sw_peer_id__tid_num & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "tid_num = %u",
            (htt_stats_buf->sw_peer_id__tid_num & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "num_sched_pending = %u",
            htt_stats_buf->num_sched_pending__num_ppdu_in_hwq & 0xFF);
    HTT_STATS_PRINT(FATAL, "num_ppdu_in_hwq = %u",
            (htt_stats_buf->num_sched_pending__num_ppdu_in_hwq & 0xFF00) >> 8);
    HTT_STATS_PRINT(FATAL, "tid_flags = 0x%x",
            htt_stats_buf->tid_flags);
    HTT_STATS_PRINT(FATAL, "max_qdepth_bytes = %u",
            htt_stats_buf->max_qdepth_bytes);
    HTT_STATS_PRINT(FATAL, "max_qdepth_n_msdus = %u",
            htt_stats_buf->max_qdepth_n_msdus);
    HTT_STATS_PRINT(FATAL, "rsvd = %u",
            htt_stats_buf->rsvd);
    HTT_STATS_PRINT(FATAL, "qdepth_bytes = %u",
            htt_stats_buf->qdepth_bytes);
    HTT_STATS_PRINT(FATAL, "qdepth_num_msdu = %u",
            htt_stats_buf->qdepth_num_msdu);
    HTT_STATS_PRINT(FATAL, "qdepth_num_mpdu = %u",
            htt_stats_buf->qdepth_num_mpdu);
    HTT_STATS_PRINT(FATAL, "last_scheduled_tsmp = %u",
            htt_stats_buf->last_scheduled_tsmp);
    HTT_STATS_PRINT(FATAL, "pause_module_id = %u",
            htt_stats_buf->pause_module_id);
    HTT_STATS_PRINT(FATAL, "block_module_id = %u",
            htt_stats_buf->block_module_id);
    /*HTT_STATS_PRINT(FATAL, "tid_tx_airtime = %u\n",
            htt_stats_buf->tid_tx_airtime);*/
    HTT_STATS_PRINT(FATAL, "allow_n_flags = 0x%x",
            htt_stats_buf->allow_n_flags);
    HTT_STATS_PRINT(FATAL, "sendn_frms_allowed = %u\n",
            htt_stats_buf->sendn_frms_allowed);
}

/*
 * htt_print_rx_tid_stats_tlv: display htt_rx_tid_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_tid_stats_tlv
 *
 * return:void
 */
static void htt_print_rx_tid_stats_tlv(A_UINT32 *tag_buf)
{
    htt_rx_tid_stats_tlv *htt_stats_buf =
        (htt_rx_tid_stats_tlv *)tag_buf;
    A_CHAR   tid_name[MAX_HTT_TID_NAME + 1] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_RX_TID_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "sw_peer_id = %u",
            htt_stats_buf->sw_peer_id__tid_num & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "tid_num = %u",
            (htt_stats_buf->sw_peer_id__tid_num & 0xFFFF0000) >> 16);
    memcpy(tid_name, &(htt_stats_buf->tid_name[0]), MAX_HTT_TID_NAME);
    HTT_STATS_PRINT(FATAL, "tid_name = %s ", tid_name);
    HTT_STATS_PRINT(FATAL, "dup_in_reorder = %u",
            htt_stats_buf->dup_in_reorder);
    HTT_STATS_PRINT(FATAL, "dup_past_outside_window = %u",
            htt_stats_buf->dup_past_outside_window);
    HTT_STATS_PRINT(FATAL, "dup_past_within_window = %u",
            htt_stats_buf->dup_past_within_window);
    HTT_STATS_PRINT(FATAL, "rxdesc_err_decrypt = %u\n",
            htt_stats_buf->rxdesc_err_decrypt);
}

/*
 * htt_print_counter_tlv: display htt_counter_tlv
 * @tag_buf: buffer containing the tlv htt_counter_tlv
 *
 * return:void
 */
static void htt_print_counter_tlv(A_UINT32 *tag_buf)
{
    htt_counter_tlv *htt_stats_buf =
        (htt_counter_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                            = 0;
    A_CHAR   counter_name[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_COUNTER_TLV:");

    for (i = 0; i < HTT_MAX_COUNTER_NAME; i++) {
        index += snprintf(&counter_name[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->counter_name[i]);
    }

    HTT_STATS_PRINT(FATAL, "counter_name = %s ", counter_name);
    HTT_STATS_PRINT(FATAL, "count = %u\n",
            htt_stats_buf->count);
}

/*
 * htt_print_peer_stats_cmn_tlv: display htt_peer_stats_cmn_tlv
 * @tag_buf: buffer containing the tlv htt_peer_stats_cmn_tlv
 *
 * return:void
 */
static void htt_print_peer_stats_cmn_tlv(A_UINT32 *tag_buf)
{
    htt_peer_stats_cmn_tlv *htt_stats_buf =
        (htt_peer_stats_cmn_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_PEER_STATS_CMN_TLV:");
    HTT_STATS_PRINT(FATAL, "ppdu_cnt = %u",
            htt_stats_buf->ppdu_cnt);
    HTT_STATS_PRINT(FATAL, "mpdu_cnt = %u",
            htt_stats_buf->mpdu_cnt);
    HTT_STATS_PRINT(FATAL, "msdu_cnt = %u",
            htt_stats_buf->msdu_cnt);
    HTT_STATS_PRINT(FATAL, "pause_bitmap = %u",
            htt_stats_buf->pause_bitmap);
    HTT_STATS_PRINT(FATAL, "block_bitmap = %u",
            htt_stats_buf->block_bitmap);
    HTT_STATS_PRINT(FATAL, "last_rssi = %d",
            htt_stats_buf->rssi);
    HTT_STATS_PRINT(FATAL, "enqueued_count = %llu",
            htt_stats_buf->peer_enqueued_count_low | ((unsigned long long)htt_stats_buf->peer_enqueued_count_high << 32));
    HTT_STATS_PRINT(FATAL, "dequeued_count = %llu",
            htt_stats_buf->peer_dequeued_count_low | ((unsigned long long)htt_stats_buf->peer_dequeued_count_high << 32));
    HTT_STATS_PRINT(FATAL, "dropped_count = %llu",
            htt_stats_buf->peer_dropped_count_low | ((unsigned long long)htt_stats_buf->peer_dropped_count_high << 32));
    HTT_STATS_PRINT(FATAL, "transmitted_ppdu_bytes = %llu",
            htt_stats_buf->ppdu_transmitted_bytes_low | ((unsigned long long)htt_stats_buf->ppdu_transmitted_bytes_high << 32));
    HTT_STATS_PRINT(FATAL, "remove_mpdus_max_retries = %u",
            htt_stats_buf->remove_mpdus_max_retries);
    /*HTT_STATS_PRINT(FATAL, "current_timestamp = %u",
            htt_stats_buf->current_timestamp);*/
    HTT_STATS_PRINT(FATAL, "ttl_removed_count = %u",
            htt_stats_buf->peer_ttl_removed_count);
    HTT_STATS_PRINT(FATAL, "inactive_time = %u\n",
            htt_stats_buf->inactive_time);
}

/*
 * htt_print_peer_details_tlv: display htt_peer_details_tlv
 * @tag_buf: buffer containing the tlv htt_peer_details_tlv
 *
 * return:void
 */
static void htt_print_peer_details_tlv(A_UINT32 *tag_buf)
{
    htt_peer_details_tlv *htt_stats_buf =
        (htt_peer_details_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_PEER_DETAILS_TLV:");
    HTT_STATS_PRINT(FATAL, "peer_type = %u",
            htt_stats_buf->peer_type);
    HTT_STATS_PRINT(FATAL, "sw_peer_id = %u",
            htt_stats_buf->sw_peer_id);
    HTT_STATS_PRINT(FATAL, "vdev_id = %u",
            htt_stats_buf->vdev_pdev_ast_idx & 0xFF);
    HTT_STATS_PRINT(FATAL, "pdev_id = %u",
            (htt_stats_buf->vdev_pdev_ast_idx & 0xFF00) >> 8);
    HTT_STATS_PRINT(FATAL, "ast_idx = %u",
            (htt_stats_buf->vdev_pdev_ast_idx & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "mac_addr = %02x:%02x:%02x:%02x:%02x:%02x",
            htt_stats_buf->mac_addr.mac_addr31to0 & 0xFF,
            (htt_stats_buf->mac_addr.mac_addr31to0 & 0xFF00) >> 8,
            (htt_stats_buf->mac_addr.mac_addr31to0 & 0xFF0000) >> 16,
            (htt_stats_buf->mac_addr.mac_addr31to0 & 0xFF000000) >> 24,
            (htt_stats_buf->mac_addr.mac_addr47to32 & 0xFF),
            (htt_stats_buf->mac_addr.mac_addr47to32 & 0xFF00) >> 8);
    HTT_STATS_PRINT(FATAL, "peer_flags = 0x%x",
            htt_stats_buf->peer_flags);
    HTT_STATS_PRINT(FATAL, "qpeer_flags = 0x%x\n",
            htt_stats_buf->qpeer_flags);
}

/*
 * htt_print_tx_peer_rate_txbf_stats_tlv: display htt_tx_peer_rate_txbf_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_peer_rate_txbf_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_peer_rate_txbf_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_txbf_rate_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_txbf_rate_stats_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN]               = {0};
    A_UINT32 tag_len                                   = (HTT_STATS_TLV_LENGTH_GET(*tag_buf));
    A_UINT32 legacy_stats_end_pos;

    legacy_stats_end_pos =
        offsetof(htt_tx_pdev_txbf_rate_stats_tlv,tx_legacy_ofdm_rate) -
        sizeof(htt_tlv_hdr_t) +
        sizeof(htt_stats_buf->tx_legacy_ofdm_rate);

    HTT_STATS_PRINT(FATAL, "HTT_STATS_PDEV_TX_RATE_TXBF_STATS:");

    if (legacy_stats_end_pos <= tag_len) {
        HTT_STATS_PRINT(FATAL,
            "Legacy OFDM Rates: 6 Mbps: %u, 9 Mbps: %u, 12 Mbps: %u, 18 Mbps: %u\n"
            "                   24 Mbps: %u, 36 Mbps: %u, 48 Mbps: %u, 54 Mbps: %u",
            htt_stats_buf->tx_legacy_ofdm_rate[0],
            htt_stats_buf->tx_legacy_ofdm_rate[1],
            htt_stats_buf->tx_legacy_ofdm_rate[2],
            htt_stats_buf->tx_legacy_ofdm_rate[3],
            htt_stats_buf->tx_legacy_ofdm_rate[4],
            htt_stats_buf->tx_legacy_ofdm_rate[5],
            htt_stats_buf->tx_legacy_ofdm_rate[6],
            htt_stats_buf->tx_legacy_ofdm_rate[7]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_TXBF_RATE_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_ol_mcs[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_ol_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_TXBF_RATE_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_ibf_mcs[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_ibf_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_TXBF_RATE_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_txbf_mcs[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_txbf_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_ol_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_ol_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_ibf_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_ibf_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_txbf_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_txbf_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_TXBF_RATE_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_ol_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_ol_bw = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_TXBF_RATE_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_ibf_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_ibf_bw = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_TXBF_RATE_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_txbf_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_txbf_bw = %s ", str_buf);
}

/*
 * htt_print_tx_peer_rate_stats_tlv: display htt_tx_peer_rate_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_peer_rate_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_peer_rate_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_peer_rate_stats_tlv *htt_stats_buf =
        (htt_tx_peer_rate_stats_tlv *)tag_buf;
    A_UINT8  i, j;
    A_UINT16 index                                     = 0;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN]               = {0};
    A_CHAR   *tx_gi[HTT_TX_PEER_STATS_NUM_GI_COUNTERS] = {0};

    for (i = 0; i < HTT_TX_PEER_STATS_NUM_GI_COUNTERS; i++) {
        tx_gi[i] = (A_CHAR *)malloc(HTT_MAX_STRING_LEN);
        if (!tx_gi[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(tx_gi[j]);
           }
           return;
        }
    }

    HTT_STATS_PRINT(FATAL, "HTT_TX_PEER_RATE_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "tx_ldpc = %u",
            htt_stats_buf->tx_ldpc);
    HTT_STATS_PRINT(FATAL, "rts_cnt = %u",
            htt_stats_buf->rts_cnt);
    HTT_STATS_PRINT(FATAL, "ack_rssi = %u",
            htt_stats_buf->ack_rssi);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_mcs[i]);
    }
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PEER_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->tx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_su_mcs[i]);
    }
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PEER_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->tx_su_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_su_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_mu_mcs[i]);
    }
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PEER_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->tx_mu_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_mu_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->tx_nss[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_bw[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_bw = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_stbc[i]);
    }
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PEER_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->tx_stbc_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_stbc = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PEER_STATS_NUM_PREAMBLE_TYPES; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_pream[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_pream = %s ", str_buf);

    for (j = 0; j < HTT_TX_PEER_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        for (i = 0; i < HTT_TX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->tx_gi[j][i]);
        }
        for (i = 0; i < HTT_TX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i + HTT_TX_PEER_STATS_NUM_MCS_COUNTERS,
                    htt_stats_buf->tx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "tx_gi[%u] = %s ", j, tx_gi[j]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PEER_STATS_NUM_DCM_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_dcm[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_dcm = %s\n", str_buf);

    for (i = 0; i < HTT_TX_PEER_STATS_NUM_GI_COUNTERS; i++) {
        free(tx_gi[i]);
    }
}

/*
 * htt_print_rx_peer_rate_stats_tlv: display htt_rx_peer_rate_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_peer_rate_stats_tlv
 *
 * return:void
 */
static void htt_print_rx_peer_rate_stats_tlv(A_UINT32 *tag_buf)
{
    htt_rx_peer_rate_stats_tlv *htt_stats_buf =
        (htt_rx_peer_rate_stats_tlv *)tag_buf;
    A_UINT8  i, j;
    A_UINT16 index;
    A_CHAR   *rssi_chain[HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS];
    A_CHAR   *rx_gi[HTT_RX_PEER_STATS_NUM_GI_COUNTERS];
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    for (i = 0; i < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; i++) {
        rssi_chain[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rssi_chain[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rssi_chain[j]);
           }
           return;
        }
    }

    for (i = 0; i < HTT_RX_PEER_STATS_NUM_GI_COUNTERS; i++) {
        rx_gi[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rx_gi[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rx_gi[j]);
           }
           for (j = 0; j < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; j++) {
                free(rssi_chain[j]);
           }
           return;
        }
    }

    HTT_STATS_PRINT(FATAL, "HTT_RX_PEER_RATE_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "nsts = %u",
            htt_stats_buf->nsts);
    HTT_STATS_PRINT(FATAL, "rx_ldpc = %u",
            htt_stats_buf->rx_ldpc);
    HTT_STATS_PRINT(FATAL, "rts_cnt = %u",
            htt_stats_buf->rts_cnt);
    HTT_STATS_PRINT(FATAL, "rssi_mgmt = %u",
            htt_stats_buf->rssi_mgmt);
    HTT_STATS_PRINT(FATAL, "rssi_data = %u",
            htt_stats_buf->rssi_data);
    HTT_STATS_PRINT(FATAL, "rssi_comb = %d",
            htt_stats_buf->rssi_comb);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_mcs[i]);
    }
    for (i = 0; i < HTT_RX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_RX_PEER_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->rx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->rx_nss[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PEER_STATS_NUM_DCM_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_dcm[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_dcm = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_stbc[i]);
    }
    for (i = 0; i < HTT_RX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_RX_PEER_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->rx_stbc_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_stbc = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PEER_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_bw[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_bw = %s ", str_buf);

    for (j = 0; j < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; j++) {
        memset(rssi_chain[j], 0x0, HTT_MAX_STRING_LEN);
        index = 0;

        for (i = 0; i < HTT_RX_PEER_STATS_NUM_BW_COUNTERS; i++) {
            index += snprintf(&rssi_chain[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->rssi_chain[j][i]);
        }

        HTT_STATS_PRINT(FATAL, "rssi_chain[%u] = %s ", j, rssi_chain[j]);
    }

    for (j = 0; j < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; j++) {
        memset(rssi_chain[j], 0x0, HTT_MAX_STRING_LEN);
        index = 0;

        for (i = 0; i < HTT_RX_PEER_STATS_NUM_BW_EXT_COUNTERS; i++) {
            index += snprintf(&rssi_chain[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->rssi_chain_ext[j][i]);
        }

        HTT_STATS_PRINT(FATAL, "rssi_chain_ext[%u] = %s ", j, rssi_chain[j]);
    }

    for (j = 0; j < HTT_RX_PEER_STATS_NUM_GI_COUNTERS; j++) {
        memset(rx_gi[j], 0x0, HTT_MAX_STRING_LEN);
        index = 0;

        for (i = 0; i < HTT_RX_PEER_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&rx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->rx_gi[j][i]);
        }
        for (i = 0; i < HTT_RX_PEER_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
            index += snprintf(&rx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i + HTT_RX_PEER_STATS_NUM_MCS_COUNTERS,
                    htt_stats_buf->rx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "rx_gi[%u] = %s ", j, rx_gi[j]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PEER_STATS_NUM_PREAMBLE_TYPES; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_pream[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_pream = %s", str_buf);

    for (i = 0; i < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; i++) {
        free(rssi_chain[i]);
    }

    for (i = 0; i < HTT_RX_PEER_STATS_NUM_GI_COUNTERS; i++) {
        free(rx_gi[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulofdma_non_data_ppdu = %u",
            htt_stats_buf->rx_ulofdma_non_data_ppdu);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_data_ppdu = %u",
            htt_stats_buf->rx_ulofdma_data_ppdu);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_mpdu_ok = %u",
            htt_stats_buf->rx_ulofdma_mpdu_ok);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_mpdu_fail = %u",
            htt_stats_buf->rx_ulofdma_mpdu_fail);

    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_non_data_ppdu = %u",
            htt_stats_buf->rx_ulmumimo_non_data_ppdu);
    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_data_ppdu = %u",
            htt_stats_buf->rx_ulmumimo_data_ppdu);
    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_mpdu_ok = %u",
            htt_stats_buf->rx_ulmumimo_mpdu_ok);
    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_mpdu_fail = %u",
            htt_stats_buf->rx_ulmumimo_mpdu_fail);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%d,", i, htt_stats_buf->rx_ul_fd_rssi[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ul_fd_rssi = %s", str_buf);

    HTT_STATS_PRINT(FATAL, "per_chain_rssi_pkt_type = %#x",
            htt_stats_buf->per_chain_rssi_pkt_type);

    for (j = 0; j < HTT_RX_PEER_STATS_NUM_SPATIAL_STREAMS; j++) {
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        index = 0;

        for (i = 0; i < HTT_RX_PEER_STATS_NUM_BW_COUNTERS; i++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i, htt_stats_buf->rx_per_chain_rssi_in_dbm[j][i]);
        }

        HTT_STATS_PRINT(FATAL,
                "rx_per_chain_rssi_in_dbm[%u] = %s ", j, str_buf);
    }

    HTT_STATS_PRINT(FATAL, "\n");
}

/*
 * htt_print_tx_hwq_mu_mimo_sch_stats_tlv: display htt_tx_hwq_mu_mimo_sch_stats
 * @tag_buf: buffer containing the tlv htt_tx_hwq_mu_mimo_sch_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_hwq_mu_mimo_sch_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_hwq_mu_mimo_sch_stats_tlv *htt_stats_buf =
        (htt_tx_hwq_mu_mimo_sch_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_MU_MIMO_SCH_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mu_mimo_sch_posted = %u",
            htt_stats_buf->mu_mimo_sch_posted);
    HTT_STATS_PRINT(FATAL, "mu_mimo_sch_failed = %u",
            htt_stats_buf->mu_mimo_sch_failed);
    HTT_STATS_PRINT(FATAL, "mu_mimo_ppdu_posted = %u\n",
            htt_stats_buf->mu_mimo_ppdu_posted);
}

/*
 * htt_print_tx_hwq_mu_mimo_mpdu_stats_tlv: display htt_tx_hwq_mu_mimo_mpdu_stats
 * @tag_buf: buffer containing the tlv htt_tx_hwq_mu_mimo_mpdu_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_hwq_mu_mimo_mpdu_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_hwq_mu_mimo_mpdu_stats_tlv *htt_stats_buf =
        (htt_tx_hwq_mu_mimo_mpdu_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_MU_MIMO_MPDU_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mu_mimo_mpdus_queued_usr = %u",
            htt_stats_buf->mu_mimo_mpdus_queued_usr);
    HTT_STATS_PRINT(FATAL, "mu_mimo_mpdus_tried_usr = %u",
            htt_stats_buf->mu_mimo_mpdus_tried_usr);
    HTT_STATS_PRINT(FATAL, "mu_mimo_mpdus_failed_usr = %u",
            htt_stats_buf->mu_mimo_mpdus_failed_usr);
    HTT_STATS_PRINT(FATAL, "mu_mimo_mpdus_requeued_usr = %u",
            htt_stats_buf->mu_mimo_mpdus_requeued_usr);
    HTT_STATS_PRINT(FATAL, "mu_mimo_err_no_ba_usr = %u",
            htt_stats_buf->mu_mimo_err_no_ba_usr);
    HTT_STATS_PRINT(FATAL, "mu_mimo_mpdu_underrun_usr = %u",
            htt_stats_buf->mu_mimo_mpdu_underrun_usr);
    HTT_STATS_PRINT(FATAL, "mu_mimo_ampdu_underrun_usr = %u\n",
            htt_stats_buf->mu_mimo_ampdu_underrun_usr);
}

/*
 * htt_print_tx_hwq_mu_mimo_cmn_stats_tlv: display htt_tx_hwq_mu_mimo_cmn_stats
 * @tag_buf: buffer containing the tlv htt_tx_hwq_mu_mimo_cmn_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_hwq_mu_mimo_cmn_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_hwq_mu_mimo_cmn_stats_tlv *htt_stats_buf =
        (htt_tx_hwq_mu_mimo_cmn_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_MU_MIMO_CMN_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__hwq_id__word & 0xFF);
    HTT_STATS_PRINT(FATAL, "hwq_id = %u\n",
            (htt_stats_buf->mac_id__hwq_id__word & 0xFF00) >> 8);
    /*HTT_STATS_PRINT(FATAL, "word = %u\n",
            (htt_stats_buf->mac_id__hwq_id__word & 0xFFFF0000) >> 16);*/
}

/*
 * htt_print_tx_hwq_stats_cmn_tlv: display htt_tx_hwq_stats_cmn_tlv
 * @tag_buf: buffer containing the tlv htt_tx_hwq_stats_cmn_tlv
 *
 * return:void
 */
static void htt_print_tx_hwq_stats_cmn_tlv(A_UINT32 *tag_buf)
{
    htt_tx_hwq_stats_cmn_tlv *htt_stats_buf =
        (htt_tx_hwq_stats_cmn_tlv *)tag_buf;

    // TODO: HKDBG
    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_STATS_CMN_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__hwq_id__word & 0xFF);
    HTT_STATS_PRINT(FATAL, "hwq_id = %u",
            (htt_stats_buf->mac_id__hwq_id__word & 0xFF00) >> 8);
    /*HTT_STATS_PRINT(FATAL, "word = %u\n",
            (htt_stats_buf->mac_id__hwq_id__word & 0xFFFF0000) >> 16);*/
    HTT_STATS_PRINT(FATAL, "xretry = %u",
            htt_stats_buf->xretry);
    HTT_STATS_PRINT(FATAL, "underrun_cnt = %u",
            htt_stats_buf->underrun_cnt);
    HTT_STATS_PRINT(FATAL, "flush_cnt = %u",
            htt_stats_buf->flush_cnt);
    HTT_STATS_PRINT(FATAL, "filt_cnt = %u",
            htt_stats_buf->filt_cnt);
    HTT_STATS_PRINT(FATAL, "null_mpdu_bmap = %u",
            htt_stats_buf->null_mpdu_bmap);
    HTT_STATS_PRINT(FATAL, "user_ack_failure = %u",
            htt_stats_buf->user_ack_failure);
    HTT_STATS_PRINT(FATAL, "ack_tlv_proc = %u",
            htt_stats_buf->ack_tlv_proc);
    HTT_STATS_PRINT(FATAL, "sched_id_proc = %u",
            htt_stats_buf->sched_id_proc);
    HTT_STATS_PRINT(FATAL, "null_mpdu_tx_count = %u",
            htt_stats_buf->null_mpdu_tx_count);
    HTT_STATS_PRINT(FATAL, "mpdu_bmap_not_recvd = %u",
            htt_stats_buf->mpdu_bmap_not_recvd);
    HTT_STATS_PRINT(FATAL, "num_bar = %u",
            htt_stats_buf->num_bar);
    HTT_STATS_PRINT(FATAL, "rts = %u",
            htt_stats_buf->rts);
    HTT_STATS_PRINT(FATAL, "cts2self = %u",
            htt_stats_buf->cts2self);
    HTT_STATS_PRINT(FATAL, "qos_null = %u",
            htt_stats_buf->qos_null);
    HTT_STATS_PRINT(FATAL, "mpdu_tried_cnt = %u",
            htt_stats_buf->mpdu_tried_cnt);
    HTT_STATS_PRINT(FATAL, "mpdu_queued_cnt = %u",
            htt_stats_buf->mpdu_queued_cnt);
    HTT_STATS_PRINT(FATAL, "mpdu_ack_fail_cnt = %u",
            htt_stats_buf->mpdu_ack_fail_cnt);
    HTT_STATS_PRINT(FATAL, "mpdu_filt_cnt = %u",
            htt_stats_buf->mpdu_filt_cnt);
    HTT_STATS_PRINT(FATAL, "false_mpdu_ack_count = %u",
            htt_stats_buf->false_mpdu_ack_count);
    HTT_STATS_PRINT(FATAL, "txq_timeout = %u\n",
            htt_stats_buf->txq_timeout);
}

/*
 * htt_print_tx_hwq_difs_latency_stats_tlv_v: display
 *                    htt_tx_hwq_difs_latency_stats_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_hwq_difs_latency_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_hwq_difs_latency_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_hwq_difs_latency_stats_tlv_v *htt_stats_buf =
        (htt_tx_hwq_difs_latency_stats_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                 = 0;
    A_CHAR   difs_latency_hist[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                               = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_DIFS_LATENCY_STATS_TLV_V:");
    HTT_STATS_PRINT(FATAL, "hist_intvl = %u",
            htt_stats_buf->hist_intvl);

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&difs_latency_hist[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->difs_latency_hist[i]);
    }

    HTT_STATS_PRINT(FATAL, "difs_latency_hist = %s\n", difs_latency_hist);
}

/*
 * htt_print_tx_hwq_cmd_result_stats_tlv_v: display htt_tx_hwq_cmd_result_stats
 * @tag_buf: buffer containing the tlv htt_tx_hwq_cmd_result_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_hwq_cmd_result_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_hwq_cmd_result_stats_tlv_v *htt_stats_buf =
        (htt_tx_hwq_cmd_result_stats_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                          = 0;
    A_CHAR   cmd_result[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                        = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_CMD_RESULT_STATS_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&cmd_result[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->cmd_result[i]);
    }

    HTT_STATS_PRINT(FATAL, "cmd_result = %s \n", cmd_result);
}

/*
 * htt_print_tx_hwq_cmd_stall_stats_tlv_v: display htt_tx_hwq_cmd_stall_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_hwq_cmd_stall_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_hwq_cmd_stall_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_hwq_cmd_stall_stats_tlv_v *htt_stats_buf =
        (htt_tx_hwq_cmd_stall_stats_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                = 0;
    A_CHAR   cmd_stall_status[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                              = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_CMD_STALL_STATS_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&cmd_stall_status[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->cmd_stall_status[i]);
    }

    HTT_STATS_PRINT(FATAL, "cmd_stall_status = %s\n", cmd_stall_status);
}

/*
 * htt_print_tx_hwq_fes_result_stats_tlv_v: display htt_tx_hwq_fes_result_stats
 * @tag_buf: buffer containing the tlv htt_tx_hwq_fes_result_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_hwq_fes_result_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_hwq_fes_result_stats_tlv_v *htt_stats_buf =
        (htt_tx_hwq_fes_result_stats_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                          = 0;
    A_CHAR   fes_result[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                        = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_FES_RESULT_STATS_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&fes_result[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->fes_result[i]);
    }

    HTT_STATS_PRINT(FATAL, "fes_result = %s \n", fes_result);
}

/*
 * htt_print_tx_hwq_tried_mpdu_cnt_hist_tlv_v: display htt_tx_hwq_tried_mpdu_cnt_hist
 * @tag_buf: buffer containing the tlv htt_tx_hwq_tried_mpdu_cnt_hist_tlv_v
 *
 * return:void
 */
static void htt_print_tx_hwq_tried_mpdu_cnt_hist_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_hwq_tried_mpdu_cnt_hist_tlv_v *htt_stats_buf =
        (htt_tx_hwq_tried_mpdu_cnt_hist_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                   = 0;
    A_CHAR   tried_mpdu_cnt_hist[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 num_elements                            =
        ((HTT_STATS_TLV_LENGTH_GET(*tag_buf) - sizeof(htt_stats_buf->hist_bin_size)) >> 2);
    A_UINT32 required_buffer_size = HTT_MAX_PRINT_CHAR_PER_ELEM * num_elements;

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_TRIED_MPDU_CNT_HIST_TLV_V:");
    HTT_STATS_PRINT(FATAL, "TRIED_MPDU_CNT_HIST_BIN_SIZE : %u", htt_stats_buf->hist_bin_size);

    if (required_buffer_size < HTT_MAX_STRING_LEN) {
        for (i = 0; i < num_elements; i++) {
            index += snprintf(&tried_mpdu_cnt_hist[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i, htt_stats_buf->tried_mpdu_cnt_hist[i]);
        }

        HTT_STATS_PRINT(FATAL, "tried_mpdu_cnt_hist = %s \n", tried_mpdu_cnt_hist);
    } else {
        HTT_STATS_PRINT(FATAL, "INSUFFICIENT PRINT BUFFER ");
    }
}

/*
 * htt_print_tx_hwq_txop_used_cnt_hist_tlv_v: display htt_tx_hwq_txop_used_cnt_hist
 * @tag_buf: buffer containing the tlv htt_tx_hwq_txop_used_cnt_hist_tlv_v
 *
 * return:void
 */
static void htt_print_tx_hwq_txop_used_cnt_hist_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_hwq_txop_used_cnt_hist_tlv_v *htt_stats_buf =
        (htt_tx_hwq_txop_used_cnt_hist_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                  = 0;
    A_CHAR   txop_used_cnt_hist[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 num_elements                           = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);
    A_UINT32 required_buffer_size                   = HTT_MAX_PRINT_CHAR_PER_ELEM * num_elements;

    HTT_STATS_PRINT(FATAL, "HTT_TX_HWQ_TXOP_USED_CNT_HIST_TLV_V:");

    if (required_buffer_size < HTT_MAX_STRING_LEN) {
        for (i = 0; i < num_elements; i++) {
            index += snprintf(&txop_used_cnt_hist[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i, htt_stats_buf->txop_used_cnt_hist[i]);
        }

        HTT_STATS_PRINT(FATAL, "txop_used_cnt_hist = %s \n", txop_used_cnt_hist);
    } else {
        HTT_STATS_PRINT(FATAL, "INSUFFICIENT PRINT BUFFER ");
    }
}

/*
 * htt_tx_sounding_stats_tlv: display htt_tx_sounding_stats
 * @tag_buf: buffer containing the tlv htt_tx_sounding_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_sounding_stats_tlv(A_UINT32 *tag_buf)
{
    A_INT32 i, j = 0;
    htt_tx_sounding_stats_tlv *htt_stats_buf =
        (htt_tx_sounding_stats_tlv *)tag_buf;

    if (htt_stats_buf->tx_sounding_mode == HTT_TX_AC_SOUNDING_MODE) {
        HTT_STATS_PRINT(FATAL, "\nHTT_TX_AC_SOUNDING_STATS_TLV: \n");
        HTT_STATS_PRINT(FATAL, "ac_cbf_20 = IBF : %u, SU_SIFS : %u, SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u ",
                htt_stats_buf->cbf_20[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);
        HTT_STATS_PRINT(FATAL, "ac_cbf_40 = IBF : %u, SU_SIFS : %u, "
                               "SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u",
                htt_stats_buf->cbf_40[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);
        HTT_STATS_PRINT(FATAL, "ac_cbf_80 = IBF : %u, SU_SIFS : %u, "
                               "SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u",
                htt_stats_buf->cbf_80[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);
        HTT_STATS_PRINT(FATAL, "ac_cbf_160 = IBF : %u, SU_SIFS : %u, "
                               "SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u",
                htt_stats_buf->cbf_160[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);

        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS; i++) {
            HTT_STATS_PRINT(FATAL, "Sounding User %u = 20MHz: %u, 40MHz : %u, 80MHz: %u, 160MHz: %u ", i,
                    htt_stats_buf->sounding[j+0], htt_stats_buf->sounding[j+1],
                    htt_stats_buf->sounding[j+2], htt_stats_buf->sounding[j+3]);
            j += 4;
        }
    } else if (htt_stats_buf->tx_sounding_mode == HTT_TX_AX_SOUNDING_MODE) {
        HTT_STATS_PRINT(FATAL, "\nHTT_TX_AX_SOUNDING_STATS_TLV:\n");
        HTT_STATS_PRINT(FATAL, "ax_cbf_20 = IBF : %u, SU_SIFS : %u, "
                               "SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u ",
                htt_stats_buf->cbf_20[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_20[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);
        HTT_STATS_PRINT(FATAL, "ax_cbf_40 = IBF : %u, SU_SIFS : %u, "
                               "SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u",
                htt_stats_buf->cbf_40[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_40[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);
        HTT_STATS_PRINT(FATAL, "ax_cbf_80 = IBF : %u, SU_SIFS : %u, "
                               "SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u",
                htt_stats_buf->cbf_80[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_80[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);
        HTT_STATS_PRINT(FATAL, "ax_cbf_160 = IBF : %u, SU_SIFS : %u, "
                               "SU_RBO : %u, MU_SIFS : %u, MU_RBO : %u",
                htt_stats_buf->cbf_160[HTT_IMPLICIT_TXBF_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_SU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_SU_RBO_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_MU_SIFS_STEER_STATS],
                htt_stats_buf->cbf_160[HTT_EXPLICIT_TXBF_MU_RBO_STEER_STATS]);

        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
            HTT_STATS_PRINT(FATAL, "Sounding User %u = 20MHz: %u, 40MHz : %u, 80MHz: %u, 160MHz: %u ", i,
                    htt_stats_buf->sounding[j+0], htt_stats_buf->sounding[j+1],
                    htt_stats_buf->sounding[j+2], htt_stats_buf->sounding[j+3]);
            j += 4;
        }
    }
}

/*
 * htt_print_tx_selfgen_cmn_stats_tlv: display htt_tx_selfgen_cmn_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_selfgen_cmn_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_selfgen_cmn_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_selfgen_cmn_stats_tlv *htt_stats_buf =
        (htt_tx_selfgen_cmn_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_SELFGEN_CMN_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "su_bar = %u",
            htt_stats_buf->su_bar);
    HTT_STATS_PRINT(FATAL, "rts = %u",
            htt_stats_buf->rts);
    HTT_STATS_PRINT(FATAL, "cts2self = %u",
            htt_stats_buf->cts2self);
    HTT_STATS_PRINT(FATAL, "qos_null = %u",
            htt_stats_buf->qos_null);
    HTT_STATS_PRINT(FATAL, "delayed_bar_1 = %u",
            htt_stats_buf->delayed_bar_1);
    HTT_STATS_PRINT(FATAL, "delayed_bar_2 = %u",
            htt_stats_buf->delayed_bar_2);
    HTT_STATS_PRINT(FATAL, "delayed_bar_3 = %u",
            htt_stats_buf->delayed_bar_3);
    HTT_STATS_PRINT(FATAL, "delayed_bar_4 = %u",
            htt_stats_buf->delayed_bar_4);
    HTT_STATS_PRINT(FATAL, "delayed_bar_5 = %u",
            htt_stats_buf->delayed_bar_5);
    HTT_STATS_PRINT(FATAL, "delayed_bar_6 = %u",
            htt_stats_buf->delayed_bar_6);
    HTT_STATS_PRINT(FATAL, "delayed_bar_7 = %u",
            htt_stats_buf->delayed_bar_7);
    HTT_STATS_PRINT(FATAL, "bar_with_tqm_head_seq_num = %u",
            htt_stats_buf->bar_with_tqm_head_seq_num);
    HTT_STATS_PRINT(FATAL, "bar_with_tid_seq_num = %u\n",
            htt_stats_buf->bar_with_tid_seq_num);
}

/*
 * htt_print_tx_selfgen_ac_stats_tlv: display htt_tx_selfgen_ac_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_selfgen_ac_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_selfgen_ac_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_selfgen_ac_stats_tlv *htt_stats_buf =
        (htt_tx_selfgen_ac_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_SELFGEN_AC_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "ac_su_ndpa_queued = %u",
            htt_stats_buf->ac_su_ndpa_queued);
    HTT_STATS_PRINT(FATAL, "ac_su_ndpa_tried = %u",
                htt_stats_buf->ac_su_ndpa);
    HTT_STATS_PRINT(FATAL, "ac_su_ndp_queued = %u",
            htt_stats_buf->ac_su_ndp_queued);
    HTT_STATS_PRINT(FATAL, "ac_su_ndp_tried = %u",
                htt_stats_buf->ac_su_ndp);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndpa_queued = %u",
            htt_stats_buf->ac_mu_mimo_ndpa_queued);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndpa_tried = %u",
                htt_stats_buf->ac_mu_mimo_ndpa);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndp_queued = %u",
            htt_stats_buf->ac_mu_mimo_ndp_queued);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndp_tried = %u",
                htt_stats_buf->ac_mu_mimo_ndp);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brpoll1_queued = %u",
            htt_stats_buf->ac_mu_mimo_brpoll_1_queued);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brpoll1_tried = %u",
                htt_stats_buf->ac_mu_mimo_brpoll_1);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brpoll2_queued = %u",
            htt_stats_buf->ac_mu_mimo_brpoll_2_queued);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brpoll2_tried = %u",
                htt_stats_buf->ac_mu_mimo_brpoll_2);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brpoll3_queued = %u",
            htt_stats_buf->ac_mu_mimo_brpoll_3_queued);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brpoll3_tried = %u\n",
                htt_stats_buf->ac_mu_mimo_brpoll_3);
}

/*
 * htt_print_txbf_ofdma_ndpa_stats_tlv: display htt_txbf_ofdma_ndpa_stats_tlv
 * @tag_buf: buffer containing the tlv htt_txbf_ofdma_ndpa_stats_tlv
 *
 * return:void
 */
static void htt_print_txbf_ofdma_ndpa_stats_tlv(A_UINT32 *tag_buf)
{
    htt_txbf_ofdma_ndpa_stats_tlv *htt_stats_buf =
        (htt_txbf_ofdma_ndpa_stats_tlv *)tag_buf;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TXBF_OFDMA_NDPA_STATS_TLV:");

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndpa_queued, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndpa_queued = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndpa_tried, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndpa_tried = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndpa_flushed, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndpa_flushed = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndpa_err, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndpa_err = %s\n", str_buf);
}

/*
 * htt_print_txbf_ofdma_ndp_stats_tlv: display htt_txbf_ofdma_ndp_stats_tlv
 * @tag_buf: buffer containing the tlv htt_txbf_ofdma_ndp_stats_tlv
 *
 * return:void
 */
static void htt_print_txbf_ofdma_ndp_stats_tlv(A_UINT32 *tag_buf)
{
    htt_txbf_ofdma_ndp_stats_tlv *htt_stats_buf =
        (htt_txbf_ofdma_ndp_stats_tlv *)tag_buf;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TXBF_OFDMA_NDP_STATS_TLV:");

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndp_queued, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndp_queued = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndp_tried, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndp_tried = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndp_flushed, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndp_flushed = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_ndp_err, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_ndp_err = %s\n", str_buf);
}

/*
 * htt_print_txbf_ofdma_brp_stats_tlv: display htt_txbf_ofdma_brp_stats_tlv
 * @tag_buf: buffer containing the tlv htt_txbf_ofdma_brp_stats_tlv
 *
 * return:void
 */
static void htt_print_txbf_ofdma_brp_stats_tlv(A_UINT32 *tag_buf)
{
    htt_txbf_ofdma_brp_stats_tlv *htt_stats_buf =
        (htt_txbf_ofdma_brp_stats_tlv *)tag_buf;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TXBF_OFDMA_BRP_STATS_TLV:");

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_brpoll_queued, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_brpoll_queued = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_brpoll_tried, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_brpoll_tried = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_brpoll_flushed, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_brpoll_flushed = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_brp_err, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_brp_err = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_brp_err_num_cbf_rcvd, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS + 1, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_brp_err_num_cbf_rcvd = %s\n", str_buf);
}

/*
 * htt_print_txbf_ofdma_steer_stats_tlv: display htt_txbf_ofdma_steer_stats_tlv
 * @tag_buf: buffer containing the tlv htt_txbf_ofdma_brp_stats_tlv
 *
 * return:void
 */
static void htt_print_txbf_ofdma_steer_stats_tlv(A_UINT32 *tag_buf)
{
    htt_txbf_ofdma_steer_stats_tlv *htt_stats_buf =
        (htt_txbf_ofdma_steer_stats_tlv *)tag_buf;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TXBF_OFDMA_STEER_STATS_TLV:");

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_num_ppdu_steer, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_num_ppdu_steer = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_num_ppdu_ol, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_num_ppdu_ol = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_num_usrs_prefetch, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_num_usrs_prefetch = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_num_usrs_sound, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_num_usrs_sound = %s", str_buf);

    htt_stringify_array(str_buf, HTT_MAX_STRING_LEN, htt_stats_buf->ax_ofdma_num_usrs_force_sound, HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS, 1, 1);
    HTT_STATS_PRINT(FATAL, "ax_ofdma_num_usrs_force_sound = %s\n", str_buf);
}

/*
 * htt_print_tx_selfgen_ax_stats_tlv: display htt_tx_selfgen_ax_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_selfgen_ax_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_selfgen_ax_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_selfgen_ax_stats_tlv *htt_stats_buf =
        (htt_tx_selfgen_ax_stats_tlv *)tag_buf;
    A_UINT8 i;
    A_UINT16 index                       = 0;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TX_SELFGEN_AX_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "ax_su_ndpa_queued = %u",
            htt_stats_buf->ax_su_ndpa_queued);
    HTT_STATS_PRINT(FATAL, "ax_su_ndpa_tried = %u",
            htt_stats_buf->ax_su_ndpa);
    HTT_STATS_PRINT(FATAL, "ax_su_ndp_queued = %u",
            htt_stats_buf->ax_su_ndp_queued);
    HTT_STATS_PRINT(FATAL, "ax_su_ndp_tried = %u",
            htt_stats_buf->ax_su_ndp);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndpa_queued = %u",
            htt_stats_buf->ax_mu_mimo_ndpa_queued);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndpa_tried = %u",
            htt_stats_buf->ax_mu_mimo_ndpa);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndp_queued = %u",
            htt_stats_buf->ax_mu_mimo_ndp_queued);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndp_tried = %u",
            htt_stats_buf->ax_mu_mimo_ndp);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS - 1; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_brpoll_queued[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_brpollX_queued = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS - 1; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_brpoll[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_brpollX_tried = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_ul_mumimo_trigger[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_ul_mumimo_trigger = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "ax_basic_trigger = %u",
            htt_stats_buf->ax_basic_trigger);
    HTT_STATS_PRINT(FATAL, "ax_ulmumimo_total_trigger = %u",
            htt_stats_buf->ax_ulmumimo_trigger);
    HTT_STATS_PRINT(FATAL, "ax_bsr_trigger = %u",
            htt_stats_buf->ax_bsr_trigger);
    HTT_STATS_PRINT(FATAL, "ax_mu_bar_trigger = %u",
            htt_stats_buf->ax_mu_bar_trigger);
    HTT_STATS_PRINT(FATAL, "ax_mu_rts_trigger = %u\n",
            htt_stats_buf->ax_mu_rts_trigger);
}

/*
 * htt_print_tx_selfgen_ac_err_stats_tlv: display htt_tx_selfgen_ac_err_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_selfgen_ac_err_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_selfgen_ac_err_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_selfgen_ac_err_stats_tlv *htt_stats_buf =
        (htt_tx_selfgen_ac_err_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_SELFGEN_AC_ERR_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "ac_su_ndp_err = %u",
            htt_stats_buf->ac_su_ndp_err);
    HTT_STATS_PRINT(FATAL, "ac_su_ndp_flushed = %u",
            htt_stats_buf->ac_su_ndp_flushed);
    HTT_STATS_PRINT(FATAL, "ac_su_ndpa_err = %u",
            htt_stats_buf->ac_su_ndpa_err);
    HTT_STATS_PRINT(FATAL, "ac_su_ndpa_flushed = %u",
            htt_stats_buf->ac_su_ndpa_flushed);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndpa_err = %u",
            htt_stats_buf->ac_mu_mimo_ndpa_err);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndpa_flushed = %u",
            htt_stats_buf->ac_mu_mimo_ndpa_flushed);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndp_err = %u",
            htt_stats_buf->ac_mu_mimo_ndp_err);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndp_flushed = %u",
            htt_stats_buf->ac_mu_mimo_ndp_flushed);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp1_err = %u",
            htt_stats_buf->ac_mu_mimo_brp1_err);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp2_err = %u",
            htt_stats_buf->ac_mu_mimo_brp2_err);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp3_err = %u\n",
            htt_stats_buf->ac_mu_mimo_brp3_err);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp1_flushed = %u",
            htt_stats_buf->ac_mu_mimo_brpoll1_flushed);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp2_flushed = %u",
            htt_stats_buf->ac_mu_mimo_brpoll2_flushed);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp3_flushed = %u\n",
            htt_stats_buf->ac_mu_mimo_brpoll3_flushed);
}

/*
 * htt_print_tx_selfgen_ax_err_stats_tlv: display htt_tx_selfgen_ax_err_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_selfgen_ax_err_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_selfgen_ax_err_stats_tlv(A_UINT32 *tag_buf)
{
    A_UINT16 index = 0;
    A_UINT8  i = 0;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    htt_tx_selfgen_ax_err_stats_tlv *htt_stats_buf =
        (htt_tx_selfgen_ax_err_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_SELFGEN_AX_ERR_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "ax_su_ndp_err = %u",
            htt_stats_buf->ax_su_ndp_err);
    HTT_STATS_PRINT(FATAL, "ax_su_ndp_flushed = %u",
            htt_stats_buf->ax_su_ndp_flushed);
    HTT_STATS_PRINT(FATAL, "ax_su_ndpa_err = %u",
            htt_stats_buf->ax_su_ndpa_err);
    HTT_STATS_PRINT(FATAL, "ax_su_ndpa_flushed = %u",
            htt_stats_buf->ax_su_ndpa_flushed);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndpa_err = %u",
            htt_stats_buf->ax_mu_mimo_ndpa_err);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndpa_flushed = %u",
            htt_stats_buf->ax_mu_mimo_ndpa_flushed);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndp_err = %u",
            htt_stats_buf->ax_mu_mimo_ndp_err);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndp_flushed = %u",
            htt_stats_buf->ax_mu_mimo_ndp_flushed);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS - 1; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_brp_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_brpX_err = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS - 1; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_brpoll_flushed[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_brpollX_flushed = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
        index += snprintf(&str_buf[index],
            HTT_MAX_STRING_LEN - index, " %u:%u,",
            i, htt_stats_buf->ax_mu_mimo_brp_err_num_cbf_received[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_num_cbf_rcvd_on_brp_err = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
        index += snprintf(&str_buf[index],
            HTT_MAX_STRING_LEN - index, " %u:%u,",
            i+1, htt_stats_buf->ax_ul_mumimo_trigger_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_ul_mumimo_trigger_err = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "ax_basic_trigger_err = %u",
            htt_stats_buf->ax_basic_trigger_err);
    HTT_STATS_PRINT(FATAL, "ax_ulmumimo_total_trigger_err = %u",
            htt_stats_buf->ax_ulmumimo_trigger_err);
    HTT_STATS_PRINT(FATAL, "ax_bsr_trigger_err = %u",
            htt_stats_buf->ax_bsr_trigger_err);
    HTT_STATS_PRINT(FATAL, "ax_mu_bar_trigger_err = %u",
            htt_stats_buf->ax_mu_bar_trigger_err);
    HTT_STATS_PRINT(FATAL, "ax_mu_rts_trigger_err = %u\n",
            htt_stats_buf->ax_mu_rts_trigger_err);
}

/*
 * htt_print_tx_selfgen_ac_sched_status_stats_tlv: display htt_tx_selfgen_ac_sched_status_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_selfgen_ac_sched_status_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_selfgen_ac_sched_status_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_selfgen_ac_sched_status_stats_tlv *htt_stats_buf = (htt_tx_selfgen_ac_sched_status_stats_tlv*) tag_buf;
    A_UINT8 i;
    A_UINT16 index                       = 0;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TX_SELFGEN_AC_SCHED_STATUS_STATS_TLV:");

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_su_ndpa_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_su_ndpa_sch_status = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_su_ndp_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_su_ndp_sch_status = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_mu_mimo_ndpa_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndpa_sch_status = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_mu_mimo_ndp_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndp_sch_status = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_mu_mimo_brp_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp_sch_status = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_su_ndp_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_su_ndp_sch_flag_err = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_mu_mimo_ndp_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ndp_sch_flag_err = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_mu_mimo_brp_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_brp_sch_flag_err = %s \n ", str_buf);
}

/*
 htt_print_tx_selfgen_ax_sched_status_stats_tlv : display htt_tx_selfgen_ax_sched_status_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_selfgen_ax_sched_status_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_selfgen_ax_sched_status_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_selfgen_ax_sched_status_stats_tlv *htt_stats_buf = (htt_tx_selfgen_ax_sched_status_stats_tlv*) tag_buf;
    A_UINT8 i;
    A_UINT16 index                       = 0;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_TX_SELFGEN_AX_SCHED_STATUS_STATS_TLV:");

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_su_ndpa_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_su_ndpa_sch_status = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_su_ndp_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_su_ndp_sch_status = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_ndpa_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndpa_sch_status = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_ndp_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndp_sch_status = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_brp_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_brp_sch_status = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_bar_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_bar_sch_status = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_TX_ERR_STATUS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_basic_trig_sch_status[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_basic_trig_sch_status = %s ", str_buf);


    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_su_ndp_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_su_ndp_sch_flag_err = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_ndp_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ndp_sch_flag_err = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_brp_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_brp_sch_flag_err = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_bar_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_bar_sch_flag_err = %s ", str_buf);
    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_SELFGEN_NUM_SCH_TSFLAG_ERROR_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_basic_trig_sch_flag_err[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_basic_trig_sch_flag_err = %s \n ", str_buf);
}

static void htt_print_tx_pdev_dl_mu_mimo_sch_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_dl_mu_mimo_sch_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_dl_mu_mimo_sch_stats_tlv *)tag_buf;
    A_UINT8 i;

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_MU_MIMO_SCH_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mu_mimo_sch_posted = %u",
            htt_stats_buf->mu_mimo_sch_posted);
    HTT_STATS_PRINT(FATAL, "mu_mimo_sch_failed = %u",
            htt_stats_buf->mu_mimo_sch_failed);
    HTT_STATS_PRINT(FATAL, "mu_mimo_ppdu_posted = %u\n",
            htt_stats_buf->mu_mimo_ppdu_posted);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ac_mu_mimo_sch_posted_per_group_index %u = %u,",
                i, htt_stats_buf->ac_mu_mimo_sch_posted_per_grp_sz[i]);
    }

    HTT_STATS_PRINT(FATAL, "\n");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_mu_mimo_sch_posted_per_group_index %u = %u,",
                i, htt_stats_buf->ax_mu_mimo_sch_posted_per_grp_sz[i]);
    }
    HTT_STATS_PRINT(FATAL, "\n");

/*
    A_UINT32 ac_mu_mimo_sch_nusers[HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS];
    A_UINT32 ax_mu_mimo_sch_nusers[HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS];
 */
    HTT_STATS_PRINT(FATAL, "11ac DL MU_MIMO SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ac_mu_mimo_sch_nusers_%u = %u", i,
                htt_stats_buf->ac_mu_mimo_sch_nusers[i]);
    }

    HTT_STATS_PRINT(FATAL, "\n11ax DL MU_MIMO SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_mu_mimo_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_mu_mimo_sch_nusers[i]);
    }
    HTT_STATS_PRINT(FATAL, "\n");
}

static void htt_print_tx_pdev_ul_mu_mimo_sch_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_ul_mu_mimo_sch_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_ul_mu_mimo_sch_stats_tlv *)tag_buf;
    A_UINT8 i;

    HTT_STATS_PRINT(FATAL, "\n11ax UL MU_MIMO SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_UL_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_ul_mu_mimo_basic_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_mu_mimo_basic_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_mu_mimo_brp_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_mu_mimo_brp_sch_nusers[i]);
    }
}

static void htt_print_tx_pdev_ul_mu_ofdma_sch_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_ul_mu_ofdma_sch_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_ul_mu_ofdma_sch_stats_tlv *)tag_buf;
    A_UINT8 i;

    HTT_STATS_PRINT(FATAL, "\n11ax UL MU_OFDMA SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_ul_mu_ofdma_basic_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_mu_ofdma_basic_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_mu_ofdma_bsr_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_mu_ofdma_bsr_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_mu_ofdma_bar_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_mu_ofdma_bar_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_mu_ofdma_brp_sch_nusers_%u = %u\n", i,
                htt_stats_buf-> ax_ul_mu_ofdma_brp_sch_nusers[i]);
    }
}

static void htt_print_tx_pdev_dl_mu_ofdma_sch_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_dl_mu_ofdma_sch_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_dl_mu_ofdma_sch_stats_tlv *)tag_buf;
    A_UINT8 i;

    HTT_STATS_PRINT(FATAL, "\n11ax DL MU_OFDMA SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_mu_ofdma_sch_nusers[i]);
    }
}

/*
 * htt_print_tx_pdev_mu_mimo_sch_stats_tlv: display htt_tx_pdev_mu_mimo_sch_stats
 * @tag_buf: buffer containing the tlv htt_tx_pdev_mu_mimo_sch_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_pdev_mu_mimo_sch_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_mu_mimo_sch_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_mu_mimo_sch_stats_tlv *)tag_buf;
    A_UINT8 i;

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_MU_MIMO_SCH_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mu_mimo_sch_posted = %u",
            htt_stats_buf->mu_mimo_sch_posted);
    HTT_STATS_PRINT(FATAL, "mu_mimo_sch_failed = %u",
            htt_stats_buf->mu_mimo_sch_failed);
    HTT_STATS_PRINT(FATAL, "mu_mimo_ppdu_posted = %u\n",
            htt_stats_buf->mu_mimo_ppdu_posted);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ac_mu_mimo_sch_posted_per_group_index %u = %u,",
                i, htt_stats_buf->ac_mu_mimo_sch_posted_per_grp_sz[i]);
    }
    HTT_STATS_PRINT(FATAL, "\n");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_mu_mimo_sch_posted_per_group_index %u = %u,",
                i, htt_stats_buf->ax_mu_mimo_sch_posted_per_grp_sz[i]);
    }
    HTT_STATS_PRINT(FATAL, "\n");

/*  A_UINT32 ac_mu_mimo_sch_nusers[HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS];
    A_UINT32 ax_mu_mimo_sch_nusers[HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS];
    A_UINT32 ax_ofdma_sch_nusers[HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS];
 */
    HTT_STATS_PRINT(FATAL, "11ac MU_MIMO SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ac_mu_mimo_sch_nusers_%u = %u", i,
                htt_stats_buf->ac_mu_mimo_sch_nusers[i]);
    }

    HTT_STATS_PRINT(FATAL, "\n11ax MU_MIMO SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_mu_mimo_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_mu_mimo_sch_nusers[i]);
    }

    HTT_STATS_PRINT(FATAL, "\n11ax OFDMA SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_ofdma_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ofdma_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_ofdma_basic_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_ofdma_basic_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_ofdma_bsr_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_ofdma_bsr_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_ofdma_bar_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_ofdma_bar_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_ofdma_brp_sch_nusers_%u = %u\n", i,
                htt_stats_buf-> ax_ul_ofdma_brp_sch_nusers[i]);
    }

    HTT_STATS_PRINT(FATAL, "\n11ax UL MUMIMO SCH STATS:");

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_UL_MUMIMO_USER_STATS; i++) {
        HTT_STATS_PRINT(FATAL, "ax_ul_mumimo_basic_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_mumimo_basic_sch_nusers[i]);
        HTT_STATS_PRINT(FATAL, "ax_ul_mumimo_brp_sch_nusers_%u = %u", i,
                htt_stats_buf->ax_ul_mumimo_brp_sch_nusers[i]);
    }
}

/*
 * htt_print_tx_pdev_mu_mimo_mpdu_stats_tlv: display
 *                htt_tx_pdev_mpdu_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_pdev_mpdu_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_pdev_mu_mimo_mpdu_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_mpdu_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_mpdu_stats_tlv *)tag_buf;

    if (htt_stats_buf->tx_sched_mode == HTT_STATS_TX_SCHED_MODE_MU_MIMO_AC) {
        if (!htt_stats_buf->user_index) {
            HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_MU_MIMO_AC_MPDU_STATS:\n");
        }

        if (htt_stats_buf->user_index < HTT_TX_PDEV_STATS_NUM_AC_MUMIMO_USER_STATS) {
            HTT_STATS_PRINT(FATAL, "ac_mu_mimo_mpdus_queued_usr_%u = %u",     htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_queued_usr);
            HTT_STATS_PRINT(FATAL, "ac_mu_mimo_mpdus_tried_usr_%u = %u",      htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_tried_usr);
            HTT_STATS_PRINT(FATAL, "ac_mu_mimo_mpdus_failed_usr_%u = %u",     htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_failed_usr);
            HTT_STATS_PRINT(FATAL, "ac_mu_mimo_mpdus_requeued_usr_%u = %u",   htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_requeued_usr);
            HTT_STATS_PRINT(FATAL, "ac_mu_mimo_err_no_ba_usr_%u = %u",        htt_stats_buf->user_index,
                    htt_stats_buf->err_no_ba_usr);
            HTT_STATS_PRINT(FATAL, "ac_mu_mimo_mpdu_underrun_usr_%u = %u",    htt_stats_buf->user_index,
                    htt_stats_buf->mpdu_underrun_usr);
            HTT_STATS_PRINT(FATAL, "ac_mu_mimo_ampdu_underrun_usr_%u = %u\n", htt_stats_buf->user_index,
                    htt_stats_buf->ampdu_underrun_usr);
        }
    }

    if (htt_stats_buf->tx_sched_mode == HTT_STATS_TX_SCHED_MODE_MU_MIMO_AX) {
        if (!htt_stats_buf->user_index) {
            HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_MU_MIMO_AX_MPDU_STATS:\n");
        }

        if (htt_stats_buf->user_index < HTT_TX_PDEV_STATS_NUM_AX_MUMIMO_USER_STATS) {
            HTT_STATS_PRINT(FATAL, "ax_mu_mimo_mpdus_queued_usr_%u = %u",     htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_queued_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_mimo_mpdus_tried_usr_%u = %u",      htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_tried_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_mimo_mpdus_failed_usr_%u = %u",     htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_failed_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_mimo_mpdus_requeued_usr_%u = %u",   htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_requeued_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_mimo_err_no_ba_usr_%u = %u",        htt_stats_buf->user_index,
                    htt_stats_buf->err_no_ba_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_mimo_mpdu_underrun_usr_%u = %u",    htt_stats_buf->user_index,
                    htt_stats_buf->mpdu_underrun_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_mimo_ampdu_underrun_usr_%u = %u\n", htt_stats_buf->user_index,
                    htt_stats_buf->ampdu_underrun_usr);
        }
    }

    if (htt_stats_buf->tx_sched_mode == HTT_STATS_TX_SCHED_MODE_MU_OFDMA_AX) {
        if (!htt_stats_buf->user_index) {
            HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_AX_MU_OFDMA_MPDU_STATS:\n");
        }

        if (htt_stats_buf->user_index < HTT_TX_PDEV_STATS_NUM_OFDMA_USER_STATS) {
            HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_mpdus_queued_usr_%u = %u",     htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_queued_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_mpdus_tried_usr_%u = %u",      htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_tried_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_mpdus_failed_usr_%u = %u",     htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_failed_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_mpdus_requeued_usr_%u = %u",   htt_stats_buf->user_index,
                    htt_stats_buf->mpdus_requeued_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_err_no_ba_usr_%u = %u",        htt_stats_buf->user_index,
                    htt_stats_buf->err_no_ba_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_mpdu_underrun_usr_%u = %u",    htt_stats_buf->user_index,
                    htt_stats_buf->mpdu_underrun_usr);
            HTT_STATS_PRINT(FATAL, "ax_mu_ofdma_ampdu_underrun_usr_%u = %u\n", htt_stats_buf->user_index,
                    htt_stats_buf->ampdu_underrun_usr);
        }
    }
}

/*
 * htt_print_sched_txq_cmd_posted_tlv_v: display htt_sched_txq_cmd_posted_tlv_v
 * @tag_buf: buffer containing the tlv htt_sched_txq_cmd_posted_tlv_v
 *
 * return:void
 */
static void htt_print_sched_txq_cmd_posted_tlv_v(A_UINT32 *tag_buf)
{
    htt_sched_txq_cmd_posted_tlv_v *htt_stats_buf =
        (htt_sched_txq_cmd_posted_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                = 0;
    A_CHAR   sched_cmd_posted[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                              = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_SCHED_TXQ_CMD_POSTED_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&sched_cmd_posted[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->sched_cmd_posted[i]);
    }

    HTT_STATS_PRINT(FATAL, "sched_cmd_posted = %s\n", sched_cmd_posted);
}

/*
 * htt_print_sched_txq_cmd_reaped_tlv_v: display htt_sched_txq_cmd_reaped_tlv_v
 * @tag_buf: buffer containing the tlv htt_sched_txq_cmd_reaped_tlv_v
 *
 * return:void
 */
static void htt_print_sched_txq_cmd_reaped_tlv_v(A_UINT32 *tag_buf)
{
    htt_sched_txq_cmd_reaped_tlv_v *htt_stats_buf =
        (htt_sched_txq_cmd_reaped_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                = 0;
    A_CHAR   sched_cmd_reaped[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                              = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_SCHED_TXQ_CMD_REAPED_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&sched_cmd_reaped[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->sched_cmd_reaped[i]);
    }

    HTT_STATS_PRINT(FATAL, "sched_cmd_reaped = %s\n", sched_cmd_reaped);
}

/*
 * htt_print_sched_txq_sched_order_su_tlv_v: display htt_sched_txq_sched_order_su_tlv_v
 * @tag_buf: buffer containing the tlv htt_sched_txq_sched_order_su_tlv_v
 *
 * return:void
 */
static void htt_print_sched_txq_sched_order_su_tlv_v(A_UINT32 *tag_buf)
{
    htt_sched_txq_sched_order_su_tlv_v *htt_stats_buf =
        (htt_sched_txq_sched_order_su_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                              = 0;
    A_CHAR   sched_order_su[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 sched_order_su_num_entries         = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2); /* each entry is A_UINT32, i.e. 4 bytes */

    HTT_STATS_PRINT(FATAL, "HTT_SCHED_TXQ_SCHED_ORDER_SU_TLV_V:");

    for (i = 0; i < sched_order_su_num_entries; i++) {
        index += snprintf(&sched_order_su[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->sched_order_su[i]);

        /*
         * Only process the next array element if there's enough space within
         * the print buffer to hold the entire array element printout.
         */
        if (index >= (HTT_MAX_STRING_LEN - HTT_MAX_PRINT_CHAR_PER_ELEM)) {
            break;
        }
    }

    HTT_STATS_PRINT(FATAL, "sched_order_su = %s\n", sched_order_su);
}

/*
 * htt_print_sched_txq_sched_ineligibility_tlv_v: display htt_sched_txq_sched_ineligibility_tlv_v
 * @tag_buf: buffer containing the tlv htt_sched_txq_sched_ineligibility_tlv_v
 *
 * return:void
 */
static void htt_print_sched_txq_sched_ineligibility_tlv_v(A_UINT32 *tag_buf)
{
    htt_sched_txq_sched_ineligibility_tlv_v *htt_stats_buf =
        (htt_sched_txq_sched_ineligibility_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                   = 0;
    A_CHAR   sched_ineligibility[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 sched_ineligibility_num_entries         = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2); /* each entry is A_UINT32, i.e. 4 bytes */

    HTT_STATS_PRINT(FATAL, "HTT_SCHED_TXQ_SCHED_INELIGIBILITY_V:");

    for (i = 0; i < sched_ineligibility_num_entries && index < HTT_MAX_STRING_LEN; i++) {
        index += snprintf(&sched_ineligibility[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->sched_ineligibility[i]);

        /*
         * Only process the next array element if there's enough space within
         * the print buffer to hold the entire array element printout.
         */
        if (index >= (HTT_MAX_STRING_LEN - HTT_MAX_PRINT_CHAR_PER_ELEM)) {
            break;
        }
    }

    HTT_STATS_PRINT(FATAL, "sched_ineligibility = %s\n", sched_ineligibility);
}

/*
 * htt_print_sched_txq_supercycle_trigger_tlv_v: display htt_sched_txq_supercycle_triggers_tlv_v
 * @tag_buf: buffer containing the tlv htt_sched_txq_supercycle_triggers_tlv_v
 *
 * return:void
 */
static void htt_print_sched_txq_supercycle_trigger_tlv_v(A_UINT32 *tag_buf)
{
    htt_sched_txq_supercycle_triggers_tlv_v *htt_stats_buf =
        (htt_sched_txq_supercycle_triggers_tlv_v *)tag_buf;
    A_UINT32  i;
    A_UINT16 index                                   = 0;
    A_CHAR   supercycle_triggers[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 supercycle_triggers_num_entries         = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2); /* each entry is A_UINT32, i.e. 4 bytes */

    HTT_STATS_PRINT(FATAL, "HTT_SCHED_TXQ_SUPERCYCLE_TRIGGER_V:");

    for (i = 0; i < supercycle_triggers_num_entries && index < HTT_MAX_STRING_LEN; i++) {
        index += snprintf(&supercycle_triggers[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->supercycle_triggers[i]);

        /*
         * Only process the next array element if there's enough space within
         * the print buffer to hold the entire array element printout.
         */
        if (index >= (HTT_MAX_STRING_LEN - HTT_MAX_PRINT_CHAR_PER_ELEM)) {
            break;
        }
    }

    HTT_STATS_PRINT(FATAL, "supercycle_triggers = %s\n", supercycle_triggers);
}

/*
 * htt_print_tx_pdev_stats_sched_per_txq_tlv: display
 *                htt_tx_pdev_stats_sched_per_txq_tlv
 * @tag_buf: buffer containing the tlv htt_tx_pdev_stats_sched_per_txq_tlv
 *
 * return:void
 */
static void htt_print_tx_pdev_stats_sched_per_txq_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_stats_sched_per_txq_tlv *htt_stats_buf =
        (htt_tx_pdev_stats_sched_per_txq_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_STATS_SCHED_PER_TXQ_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__txq_id__word & 0xFF);
    HTT_STATS_PRINT(FATAL, "txq_id = %u",
            (htt_stats_buf->mac_id__txq_id__word & 0xFF00) >> 8);
    /*HTT_STATS_PRINT(FATAL, "word = %u\n",
            (htt_stats_buf->mac_id__txq_id__word & 0xFFFF0000) >> 16);*/
    HTT_STATS_PRINT(FATAL, "sched_policy = %u",
            htt_stats_buf->sched_policy);
    HTT_STATS_PRINT(FATAL, "last_sched_cmd_posted_timestamp = %u",
            htt_stats_buf->last_sched_cmd_posted_timestamp);
    HTT_STATS_PRINT(FATAL, "last_sched_cmd_compl_timestamp = %u",
            htt_stats_buf->last_sched_cmd_compl_timestamp);
    HTT_STATS_PRINT(FATAL, "sched_2_tac_lwm_count = %u",
            htt_stats_buf->sched_2_tac_lwm_count);
    HTT_STATS_PRINT(FATAL, "sched_2_tac_ring_full = %u",
            htt_stats_buf->sched_2_tac_ring_full);
    HTT_STATS_PRINT(FATAL, "sched_cmd_post_failure = %u",
            htt_stats_buf->sched_cmd_post_failure);
    HTT_STATS_PRINT(FATAL, "num_active_tids = %u",
            htt_stats_buf->num_active_tids);
    HTT_STATS_PRINT(FATAL, "num_ps_schedules = %u",
            htt_stats_buf->num_ps_schedules);
    HTT_STATS_PRINT(FATAL, "sched_cmds_pending = %u",
            htt_stats_buf->sched_cmds_pending);
    HTT_STATS_PRINT(FATAL, "num_tid_register = %u",
            htt_stats_buf->num_tid_register);
    HTT_STATS_PRINT(FATAL, "num_tid_unregister = %u",
            htt_stats_buf->num_tid_unregister);
    HTT_STATS_PRINT(FATAL, "num_qstats_queried = %u",
            htt_stats_buf->num_qstats_queried);
    HTT_STATS_PRINT(FATAL, "qstats_update_pending = %u",
            htt_stats_buf->qstats_update_pending);
    HTT_STATS_PRINT(FATAL, "last_qstats_query_timestamp = %u",
            htt_stats_buf->last_qstats_query_timestamp);
    HTT_STATS_PRINT(FATAL, "num_tqm_cmdq_full = %u",
            htt_stats_buf->num_tqm_cmdq_full);
    HTT_STATS_PRINT(FATAL, "num_de_sched_algo_trigger = %u",
            htt_stats_buf->num_de_sched_algo_trigger);
    HTT_STATS_PRINT(FATAL, "num_rt_sched_algo_trigger = %u",
            htt_stats_buf->num_rt_sched_algo_trigger);
    HTT_STATS_PRINT(FATAL, "num_tqm_sched_algo_trigger = %u",
            htt_stats_buf->num_tqm_sched_algo_trigger);
    HTT_STATS_PRINT(FATAL, "notify_sched = %u",
            htt_stats_buf->notify_sched);
    HTT_STATS_PRINT(FATAL, "dur_based_sendn_term = %u",
            htt_stats_buf->dur_based_sendn_term);
    HTT_STATS_PRINT(FATAL, "su_notify2_sched = %u",
            htt_stats_buf->su_notify2_sched);
    HTT_STATS_PRINT(FATAL, "su_optimal_queued_msdus_sched = %u",
            htt_stats_buf->su_optimal_queued_msdus_sched);
    HTT_STATS_PRINT(FATAL, "su_delay_timeout_sched = %u",
            htt_stats_buf->su_delay_timeout_sched);
    HTT_STATS_PRINT(FATAL, "su_min_txtime_sched_delay = %u",
            htt_stats_buf->su_min_txtime_sched_delay);
    HTT_STATS_PRINT(FATAL, "su_no_delay = %u",
            htt_stats_buf->su_no_delay);
    HTT_STATS_PRINT(FATAL, "num_supercycles = %u",
            htt_stats_buf->num_supercycles);
    HTT_STATS_PRINT(FATAL, "num_subcycles_with_sort = %u",
            htt_stats_buf->num_subcycles_with_sort);
    HTT_STATS_PRINT(FATAL, "num_subcycles_no_sort = %u\n",
            htt_stats_buf->num_subcycles_no_sort);
}

/*
 * htt_print_stats_tx_sched_cmn_tlv: display htt_stats_tx_sched_cmn_tlv
 * @tag_buf: buffer containing the tlv htt_stats_tx_sched_cmn_tlv
 *
 * return:void
 */
static void htt_print_stats_tx_sched_cmn_tlv(A_UINT32 *tag_buf)
{
    htt_stats_tx_sched_cmn_tlv *htt_stats_buf =
        (htt_stats_tx_sched_cmn_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_STATS_TX_SCHED_CMN_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "current_timestamp = %u\n",
            htt_stats_buf->current_timestamp);
}

/*
 * htt_print_tx_tqm_gen_mpdu_stats_tlv_v: display htt_tx_tqm_gen_mpdu_stats_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_tqm_gen_mpdu_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_tqm_gen_mpdu_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_tqm_gen_mpdu_stats_tlv_v *htt_stats_buf =
        (htt_tx_tqm_gen_mpdu_stats_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                   = 0;
    A_CHAR   gen_mpdu_end_reason[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                                 = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_TQM_GEN_MPDU_STATS_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&gen_mpdu_end_reason[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->gen_mpdu_end_reason[i]);
    }

    HTT_STATS_PRINT(FATAL, "gen_mpdu_end_reason = %s\n", gen_mpdu_end_reason);
}

/*
 * htt_print_tx_tqm_list_mpdu_stats_tlv_v: display htt_tx_tqm_list_mpdu_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_tqm_list_mpdu_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_tqm_list_mpdu_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_tqm_list_mpdu_stats_tlv_v *htt_stats_buf =
        (htt_tx_tqm_list_mpdu_stats_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                    = 0;
    A_CHAR   list_mpdu_end_reason[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                                  = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_TQM_LIST_MPDU_STATS_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&list_mpdu_end_reason[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->list_mpdu_end_reason[i]);
    }

    HTT_STATS_PRINT(FATAL, "list_mpdu_end_reason = %s\n",
            list_mpdu_end_reason);
}

/*
 * htt_print_tx_tqm_list_mpdu_cnt_tlv_v: display htt_tx_tqm_list_mpdu_cnt_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_tqm_list_mpdu_cnt_tlv_v
 *
 * return:void
 */
static void htt_print_tx_tqm_list_mpdu_cnt_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_tqm_list_mpdu_cnt_tlv_v *htt_stats_buf =
        (htt_tx_tqm_list_mpdu_cnt_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                  = 0;
    A_CHAR   list_mpdu_cnt_hist[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                                = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_TX_TQM_LIST_MPDU_CNT_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&list_mpdu_cnt_hist[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->list_mpdu_cnt_hist[i]);
    }

    HTT_STATS_PRINT(FATAL, "list_mpdu_cnt_hist = %s\n", list_mpdu_cnt_hist);
}

/*
 * htt_print_tx_tqm_pdev_stats_tlv_v: display htt_tx_tqm_pdev_stats_tlv_v
 * @tag_buf: buffer containing the tlv htt_tx_tqm_pdev_stats_tlv_v
 *
 * return:void
 */
static void htt_print_tx_tqm_pdev_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_tx_tqm_pdev_stats_tlv_v *htt_stats_buf =
        (htt_tx_tqm_pdev_stats_tlv_v *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_TQM_PDEV_STATS_TLV_V:");
    HTT_STATS_PRINT(FATAL, "msdu_count = %u",
            htt_stats_buf->msdu_count);
    HTT_STATS_PRINT(FATAL, "mpdu_count = %u",
            htt_stats_buf->mpdu_count);
    HTT_STATS_PRINT(FATAL, "remove_msdu = %u",
            htt_stats_buf->remove_msdu);
    HTT_STATS_PRINT(FATAL, "remove_mpdu = %u",
            htt_stats_buf->remove_mpdu);
    HTT_STATS_PRINT(FATAL, "remove_msdu_ttl = %u",
            htt_stats_buf->remove_msdu_ttl);
    HTT_STATS_PRINT(FATAL, "send_bar = %u",
            htt_stats_buf->send_bar);
    HTT_STATS_PRINT(FATAL, "bar_sync = %u",
            htt_stats_buf->bar_sync);
    HTT_STATS_PRINT(FATAL, "notify_mpdu = %u",
            htt_stats_buf->notify_mpdu);
    HTT_STATS_PRINT(FATAL, "sync_cmd = %u",
            htt_stats_buf->sync_cmd);
    HTT_STATS_PRINT(FATAL, "write_cmd = %u",
            htt_stats_buf->write_cmd);
    HTT_STATS_PRINT(FATAL, "hwsch_trigger = %u",
            htt_stats_buf->hwsch_trigger);
    HTT_STATS_PRINT(FATAL, "ack_tlv_proc = %u",
            htt_stats_buf->ack_tlv_proc);
    HTT_STATS_PRINT(FATAL, "gen_mpdu_cmd = %u",
            htt_stats_buf->gen_mpdu_cmd);
    HTT_STATS_PRINT(FATAL, "gen_list_cmd = %u",
            htt_stats_buf->gen_list_cmd);
    HTT_STATS_PRINT(FATAL, "remove_mpdu_cmd = %u",
            htt_stats_buf->remove_mpdu_cmd);
    HTT_STATS_PRINT(FATAL, "remove_mpdu_tried_cmd = %u",
            htt_stats_buf->remove_mpdu_tried_cmd);
    HTT_STATS_PRINT(FATAL, "mpdu_queue_stats_cmd = %u",
            htt_stats_buf->mpdu_queue_stats_cmd);
    HTT_STATS_PRINT(FATAL, "mpdu_head_info_cmd = %u",
            htt_stats_buf->mpdu_head_info_cmd);
    HTT_STATS_PRINT(FATAL, "msdu_flow_stats_cmd = %u",
            htt_stats_buf->msdu_flow_stats_cmd);
    HTT_STATS_PRINT(FATAL, "remove_msdu_cmd = %u",
            htt_stats_buf->remove_msdu_cmd);
    HTT_STATS_PRINT(FATAL, "remove_msdu_ttl_cmd = %u",
            htt_stats_buf->remove_msdu_ttl_cmd);
    HTT_STATS_PRINT(FATAL, "flush_cache_cmd = %u",
            htt_stats_buf->flush_cache_cmd);
    HTT_STATS_PRINT(FATAL, "update_mpduq_cmd = %u",
            htt_stats_buf->update_mpduq_cmd);
    HTT_STATS_PRINT(FATAL, "enqueue = %u",
            htt_stats_buf->enqueue);
    HTT_STATS_PRINT(FATAL, "enqueue_notify = %u",
            htt_stats_buf->enqueue_notify);
    HTT_STATS_PRINT(FATAL, "notify_mpdu_at_head = %u",
            htt_stats_buf->notify_mpdu_at_head);
    HTT_STATS_PRINT(FATAL, "notify_mpdu_state_valid = %u",
            htt_stats_buf->notify_mpdu_state_valid);
    HTT_STATS_PRINT(FATAL, "sched_udp_notify1 = %u",
            htt_stats_buf->sched_udp_notify1);
    HTT_STATS_PRINT(FATAL, "sched_udp_notify2 = %u",
            htt_stats_buf->sched_udp_notify2);
    HTT_STATS_PRINT(FATAL, "sched_nonudp_notify1 = %u",
            htt_stats_buf->sched_nonudp_notify1);
    HTT_STATS_PRINT(FATAL, "sched_nonudp_notify2 = %u\n",
            htt_stats_buf->sched_nonudp_notify2);
}

/*
 * htt_print_tx_tqm_cmn_stats_tlv: display htt_tx_tqm_cmn_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_tqm_cmn_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_tqm_cmn_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_tqm_cmn_stats_tlv *htt_stats_buf =
        (htt_tx_tqm_cmn_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_TQM_CMN_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "max_cmdq_id = %u",
            htt_stats_buf->max_cmdq_id);
    HTT_STATS_PRINT(FATAL, "list_mpdu_cnt_hist_intvl = %u",
            htt_stats_buf->list_mpdu_cnt_hist_intvl);
    HTT_STATS_PRINT(FATAL, "add_msdu = %u",
            htt_stats_buf->add_msdu);
    HTT_STATS_PRINT(FATAL, "q_empty = %u",
            htt_stats_buf->q_empty);
    HTT_STATS_PRINT(FATAL, "q_not_empty = %u",
            htt_stats_buf->q_not_empty);
    HTT_STATS_PRINT(FATAL, "drop_notification = %u",
            htt_stats_buf->drop_notification);
    HTT_STATS_PRINT(FATAL, "desc_threshold = %u",
            htt_stats_buf->desc_threshold);
    HTT_STATS_PRINT(FATAL, "hwsch_tqm_invalid_status = %u",
            htt_stats_buf->hwsch_tqm_invalid_status);
    HTT_STATS_PRINT(FATAL, "missed_tqm_gen_mpdus = %u",
            htt_stats_buf->missed_tqm_gen_mpdus);

    if (htt_stats_buf->tlv_hdr.length >
            (offsetof(htt_tx_tqm_cmn_stats_tlv, tqm_active_tids) -
                 offsetof(htt_tx_tqm_cmn_stats_tlv, mac_id__word))) {
        HTT_STATS_PRINT(FATAL, "active_tqm_tids = %u",
                    htt_stats_buf->tqm_active_tids);
        HTT_STATS_PRINT(FATAL, "inactive_tqm_tids = %u",
                    htt_stats_buf->tqm_inactive_tids);
        HTT_STATS_PRINT(FATAL, "tqm_active_msduq_flows = %u",
                    htt_stats_buf->tqm_active_msduq_flows);
    }

    HTT_STATS_PRINT(FATAL, "\n");
}

/*
 * htt_print_unavailable_error_stats_tlv: display htt_stats_error_tlv_v
 * @tag_buf: buffer containing the tlv htt_stats_error_tlv_v
 *
 * return:void
 */
static void htt_print_unavailable_error_stats_tlv(A_UINT32 *tag_buf)
{
   htt_stats_error_tlv_v *error_stats_tlv = (htt_stats_error_tlv_v *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_ERROR_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "No stats to print for current request: %d",
            error_stats_tlv->htt_stats_type);
}

/*
 * htt_print_unsupported_error_stats_tlv: display htt_tx_tqm_error_stats_tlv
 * @tag_buf: buffer containing the tlv htt_stats_error_tlv_v
 *
 * return:void
 */
static void htt_print_unsupported_error_stats_tlv(A_UINT32 *tag_buf)
{
    htt_stats_error_tlv_v *error_stats_tlv = (htt_stats_error_tlv_v *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_ERROR_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "Unsupported HTT stats type: %d",
            error_stats_tlv->htt_stats_type);
}

/*
 * htt_print_tx_tqm_error_stats_tlv: display htt_tx_tqm_error_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_tqm_error_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_tqm_error_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_tqm_error_stats_tlv *htt_stats_buf =
        (htt_tx_tqm_error_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_TQM_ERROR_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "q_empty_failure = %u",
            htt_stats_buf->q_empty_failure);
    HTT_STATS_PRINT(FATAL, "q_not_empty_failure = %u",
            htt_stats_buf->q_not_empty_failure);
    HTT_STATS_PRINT(FATAL, "add_msdu_failure = %u\n",
            htt_stats_buf->add_msdu_failure);
}

/*
 * htt_print_tx_tqm_cmdq_status_tlv: display htt_tx_tqm_cmdq_status_tlv
 * @tag_buf: buffer containing the tlv htt_tx_tqm_cmdq_status_tlv
 *
 * return:void
 */
static void htt_print_tx_tqm_cmdq_status_tlv(A_UINT32 *tag_buf)
{
    htt_tx_tqm_cmdq_status_tlv *htt_stats_buf =
        (htt_tx_tqm_cmdq_status_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_TQM_CMDQ_STATUS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__cmdq_id__word & 0xFF);
    HTT_STATS_PRINT(FATAL, "cmdq_id = %u\n",
            (htt_stats_buf->mac_id__cmdq_id__word & 0xFF00) >> 8);
    /*HTT_STATS_PRINT(FATAL, "word = %u\n",
            (htt_stats_buf->mac_id__cmdq_id__word & 0xFFFF0000) >> 16);*/
    HTT_STATS_PRINT(FATAL, "sync_cmd = %u",
            htt_stats_buf->sync_cmd);
    HTT_STATS_PRINT(FATAL, "write_cmd = %u",
            htt_stats_buf->write_cmd);
    HTT_STATS_PRINT(FATAL, "gen_mpdu_cmd = %u",
            htt_stats_buf->gen_mpdu_cmd);
    HTT_STATS_PRINT(FATAL, "mpdu_queue_stats_cmd = %u",
            htt_stats_buf->mpdu_queue_stats_cmd);
    HTT_STATS_PRINT(FATAL, "mpdu_head_info_cmd = %u",
            htt_stats_buf->mpdu_head_info_cmd);
    HTT_STATS_PRINT(FATAL, "msdu_flow_stats_cmd = %u",
            htt_stats_buf->msdu_flow_stats_cmd);
    HTT_STATS_PRINT(FATAL, "remove_mpdu_cmd = %u",
            htt_stats_buf->remove_mpdu_cmd);
    HTT_STATS_PRINT(FATAL, "remove_msdu_cmd = %u",
            htt_stats_buf->remove_msdu_cmd);
    HTT_STATS_PRINT(FATAL, "flush_cache_cmd = %u",
            htt_stats_buf->flush_cache_cmd);
    HTT_STATS_PRINT(FATAL, "update_mpduq_cmd = %u",
            htt_stats_buf->update_mpduq_cmd);
    HTT_STATS_PRINT(FATAL, "update_msduq_cmd = %u\n",
            htt_stats_buf->update_msduq_cmd);
}

/*
 * htt_print_tx_de_eapol_packets_stats_tlv: display htt_tx_de_eapol_packets_stats
 * @tag_buf: buffer containing the tlv htt_tx_de_eapol_packets_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_eapol_packets_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_eapol_packets_stats_tlv *htt_stats_buf =
        (htt_tx_de_eapol_packets_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_EAPOL_PACKETS_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "m1_packets = %u",
            htt_stats_buf->m1_packets);
    HTT_STATS_PRINT(FATAL, "m2_packets = %u",
            htt_stats_buf->m2_packets);
    HTT_STATS_PRINT(FATAL, "m3_packets = %u",
            htt_stats_buf->m3_packets);
    HTT_STATS_PRINT(FATAL, "m4_packets = %u",
            htt_stats_buf->m4_packets);
    HTT_STATS_PRINT(FATAL, "g1_packets = %u",
            htt_stats_buf->g1_packets);
    HTT_STATS_PRINT(FATAL, "g2_packets = %u",
            htt_stats_buf->g2_packets);
    HTT_STATS_PRINT(FATAL, "rc4_packets = %u",
            htt_stats_buf->rc4_packets);
    HTT_STATS_PRINT(FATAL, "eap_packets = %u",
            htt_stats_buf->eap_packets);
    HTT_STATS_PRINT(FATAL, "eapol_start_packets = %u",
            htt_stats_buf->eapol_start_packets);
    HTT_STATS_PRINT(FATAL, "eapol_logoff_packets = %u",
            htt_stats_buf->eapol_logoff_packets);
    HTT_STATS_PRINT(FATAL, "eapol_encap_asf_packets = %u\n",
            htt_stats_buf->eapol_encap_asf_packets);
}

/*
 * htt_print_tx_de_classify_failed_stats_tlv: display
 *                htt_tx_de_classify_failed_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_de_classify_failed_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_classify_failed_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_classify_failed_stats_tlv *htt_stats_buf =
        (htt_tx_de_classify_failed_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_CLASSIFY_FAILED_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "ap_bss_peer_not_found = %u",
            htt_stats_buf->ap_bss_peer_not_found);
    HTT_STATS_PRINT(FATAL, "ap_bcast_mcast_no_peer = %u",
            htt_stats_buf->ap_bcast_mcast_no_peer);
    HTT_STATS_PRINT(FATAL, "sta_delete_in_progress = %u",
            htt_stats_buf->sta_delete_in_progress);
    HTT_STATS_PRINT(FATAL, "ibss_no_bss_peer = %u",
            htt_stats_buf->ibss_no_bss_peer);
    HTT_STATS_PRINT(FATAL, "invaild_vdev_type = %u",
            htt_stats_buf->invaild_vdev_type);
    HTT_STATS_PRINT(FATAL, "invalid_ast_peer_entry = %u",
            htt_stats_buf->invalid_ast_peer_entry);
    HTT_STATS_PRINT(FATAL, "peer_entry_invalid = %u",
            htt_stats_buf->peer_entry_invalid);
    HTT_STATS_PRINT(FATAL, "ethertype_not_ip = %u",
            htt_stats_buf->ethertype_not_ip);
    HTT_STATS_PRINT(FATAL, "eapol_lookup_failed = %u",
            htt_stats_buf->eapol_lookup_failed);
    HTT_STATS_PRINT(FATAL, "qpeer_not_allow_data = %u",
            htt_stats_buf->qpeer_not_allow_data);
    HTT_STATS_PRINT(FATAL, "fse_tid_override = %u",
            htt_stats_buf->fse_tid_override);
    HTT_STATS_PRINT(FATAL, "ipv6_jumbogram_zero_length = %u",
            htt_stats_buf->ipv6_jumbogram_zero_length);
    HTT_STATS_PRINT(FATAL, "qos_to_non_qos_in_prog = %u",
            htt_stats_buf->qos_to_non_qos_in_prog);
    HTT_STATS_PRINT(FATAL, "ap_bcast_mcast_eapol = %u",
            htt_stats_buf->ap_bcast_mcast_eapol);
    HTT_STATS_PRINT(FATAL, "unicast_on_ap_bss_peer = %u",
            htt_stats_buf->unicast_on_ap_bss_peer);
    HTT_STATS_PRINT(FATAL, "ap_vdev_invalid = %u",
            htt_stats_buf->ap_vdev_invalid);
    HTT_STATS_PRINT(FATAL, "incomplete_llc = %u",
            htt_stats_buf->incomplete_llc);
    HTT_STATS_PRINT(FATAL, "eapol_duplicate_m3 = %u",
            htt_stats_buf->eapol_duplicate_m3);
    HTT_STATS_PRINT(FATAL, "eapol_duplicate_m4 = %u\n",
            htt_stats_buf->eapol_duplicate_m4);
}

/*
 * htt_print_tx_de_classify_stats_tlv: display htt_tx_de_classify_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_de_classify_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_classify_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_classify_stats_tlv *htt_stats_buf =
        (htt_tx_de_classify_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_CLASSIFY_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "arp_packets = %u",
            htt_stats_buf->arp_packets);
    HTT_STATS_PRINT(FATAL, "igmp_packets = %u",
            htt_stats_buf->igmp_packets);
    HTT_STATS_PRINT(FATAL, "dhcp_packets = %u",
            htt_stats_buf->dhcp_packets);
    HTT_STATS_PRINT(FATAL, "host_inspected = %u",
            htt_stats_buf->host_inspected);
    HTT_STATS_PRINT(FATAL, "htt_included = %u",
            htt_stats_buf->htt_included);
    HTT_STATS_PRINT(FATAL, "htt_valid_mcs = %u",
            htt_stats_buf->htt_valid_mcs);
    HTT_STATS_PRINT(FATAL, "htt_valid_nss = %u",
            htt_stats_buf->htt_valid_nss);
    HTT_STATS_PRINT(FATAL, "htt_valid_preamble_type = %u",
            htt_stats_buf->htt_valid_preamble_type);
    HTT_STATS_PRINT(FATAL, "htt_valid_chainmask = %u",
            htt_stats_buf->htt_valid_chainmask);
    HTT_STATS_PRINT(FATAL, "htt_valid_guard_interval = %u",
            htt_stats_buf->htt_valid_guard_interval);
    HTT_STATS_PRINT(FATAL, "htt_valid_retries = %u",
            htt_stats_buf->htt_valid_retries);
    HTT_STATS_PRINT(FATAL, "htt_valid_bw_info = %u",
            htt_stats_buf->htt_valid_bw_info);
    HTT_STATS_PRINT(FATAL, "htt_valid_power = %u",
            htt_stats_buf->htt_valid_power);
    HTT_STATS_PRINT(FATAL, "htt_valid_key_flags = 0x%x",
            htt_stats_buf->htt_valid_key_flags);
    HTT_STATS_PRINT(FATAL, "htt_valid_no_encryption = %u",
            htt_stats_buf->htt_valid_no_encryption);
    HTT_STATS_PRINT(FATAL, "fse_entry_count = %u",
            htt_stats_buf->fse_entry_count);
    HTT_STATS_PRINT(FATAL, "fse_priority_be = %u",
            htt_stats_buf->fse_priority_be);
    HTT_STATS_PRINT(FATAL, "fse_priority_high = %u",
            htt_stats_buf->fse_priority_high);
    HTT_STATS_PRINT(FATAL, "fse_priority_low = %u",
            htt_stats_buf->fse_priority_low);
    HTT_STATS_PRINT(FATAL, "fse_traffic_ptrn_be = %u",
            htt_stats_buf->fse_traffic_ptrn_be);
    HTT_STATS_PRINT(FATAL, "fse_traffic_ptrn_over_sub = %u",
            htt_stats_buf->fse_traffic_ptrn_over_sub);
    HTT_STATS_PRINT(FATAL, "fse_traffic_ptrn_bursty = %u",
            htt_stats_buf->fse_traffic_ptrn_bursty);
    HTT_STATS_PRINT(FATAL, "fse_traffic_ptrn_interactive = %u",
            htt_stats_buf->fse_traffic_ptrn_interactive);
    HTT_STATS_PRINT(FATAL, "fse_traffic_ptrn_periodic = %u",
            htt_stats_buf->fse_traffic_ptrn_periodic);
    HTT_STATS_PRINT(FATAL, "fse_hwqueue_alloc = %u",
            htt_stats_buf->fse_hwqueue_alloc);
    HTT_STATS_PRINT(FATAL, "fse_hwqueue_created = %u",
            htt_stats_buf->fse_hwqueue_created);
    HTT_STATS_PRINT(FATAL, "fse_hwqueue_send_to_host = %u",
            htt_stats_buf->fse_hwqueue_send_to_host);
    HTT_STATS_PRINT(FATAL, "mcast_entry = %u",
            htt_stats_buf->mcast_entry);
    HTT_STATS_PRINT(FATAL, "bcast_entry = %u",
            htt_stats_buf->bcast_entry);
    HTT_STATS_PRINT(FATAL, "htt_update_peer_cache = %u",
            htt_stats_buf->htt_update_peer_cache);
    HTT_STATS_PRINT(FATAL, "htt_learning_frame = %u",
            htt_stats_buf->htt_learning_frame);
    HTT_STATS_PRINT(FATAL, "fse_invalid_peer = %u",
            htt_stats_buf->fse_invalid_peer);
    HTT_STATS_PRINT(FATAL, "mec_notify = %u\n",
            htt_stats_buf->mec_notify);
}

/*
 * htt_print_tx_de_classify_status_stats_tlv: display
 *                htt_tx_de_classify_status_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_de_classify_status_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_classify_status_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_classify_status_stats_tlv *htt_stats_buf =
        (htt_tx_de_classify_status_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_CLASSIFY_STATUS_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "eok = %u",
            htt_stats_buf->eok);
    HTT_STATS_PRINT(FATAL, "classify_done = %u",
            htt_stats_buf->classify_done);
    HTT_STATS_PRINT(FATAL, "lookup_failed = %u",
            htt_stats_buf->lookup_failed);
    HTT_STATS_PRINT(FATAL, "send_host_dhcp = %u",
            htt_stats_buf->send_host_dhcp);
    HTT_STATS_PRINT(FATAL, "send_host_mcast = %u",
            htt_stats_buf->send_host_mcast);
    HTT_STATS_PRINT(FATAL, "send_host_unknown_dest = %u",
            htt_stats_buf->send_host_unknown_dest);
    HTT_STATS_PRINT(FATAL, "send_host = %u",
            htt_stats_buf->send_host);
    HTT_STATS_PRINT(FATAL, "status_invalid = %u\n",
            htt_stats_buf->status_invalid);
}

/*
 * htt_print_tx_de_enqueue_packets_stats_tlv: display
 *                htt_tx_de_enqueue_packets_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_de_enqueue_packets_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_enqueue_packets_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_enqueue_packets_stats_tlv *htt_stats_buf =
        (htt_tx_de_enqueue_packets_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_ENQUEUE_PACKETS_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "enqueued_pkts = %u",
            htt_stats_buf->enqueued_pkts);
    HTT_STATS_PRINT(FATAL, "to_tqm = %u",
            htt_stats_buf->to_tqm);
    HTT_STATS_PRINT(FATAL, "to_tqm_bypass = %u\n",
            htt_stats_buf->to_tqm_bypass);
}

/*
 * htt_print_tx_de_enqueue_discard_stats_tlv: display
 *                    htt_tx_de_enqueue_discard_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_de_enqueue_discard_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_enqueue_discard_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_enqueue_discard_stats_tlv *htt_stats_buf =
        (htt_tx_de_enqueue_discard_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_ENQUEUE_DISCARD_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "discarded_pkts = %u",
            htt_stats_buf->discarded_pkts);
    HTT_STATS_PRINT(FATAL, "local_frames = %u",
            htt_stats_buf->local_frames);
    HTT_STATS_PRINT(FATAL, "is_ext_msdu = %u\n",
            htt_stats_buf->is_ext_msdu);
}

/*
 * htt_print_tx_de_compl_stats_tlv: display htt_tx_de_compl_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_de_compl_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_compl_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_compl_stats_tlv *htt_stats_buf =
        (htt_tx_de_compl_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_COMPL_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "tcl_dummy_frame = %u",
            htt_stats_buf->tcl_dummy_frame);
    HTT_STATS_PRINT(FATAL, "tqm_dummy_frame = %u",
            htt_stats_buf->tqm_dummy_frame);
    HTT_STATS_PRINT(FATAL, "tqm_notify_frame = %u",
            htt_stats_buf->tqm_notify_frame);
    HTT_STATS_PRINT(FATAL, "fw2wbm_enq = %u",
            htt_stats_buf->fw2wbm_enq);
    HTT_STATS_PRINT(FATAL, "tqm_bypass_frame = %u\n",
            htt_stats_buf->tqm_bypass_frame);
}

/*
 * htt_print_tx_de_fw2wbm_ring_full_hist_tlv: display htt_tx_de_fw2wbm_ring_full_hist_tlv
 * @tag_buf: buffer containing the tlv  htt_tx_de_fw2wbm_ring_full_hist_tlv
 *
 * return:void
 */
static void htt_print_tx_de_fw2wbm_ring_full_hist_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_fw2wbm_ring_full_hist_tlv *htt_stats_buf =
        (htt_tx_de_fw2wbm_ring_full_hist_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                     = 0;
    A_CHAR   fw2wbm_ring_full_hist[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 num_elements                              = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);
    A_UINT32 required_buffer_size                      = HTT_MAX_PRINT_CHAR_PER_ELEM * num_elements;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_FW2WBM_RING_FULL_HIST_TLV");

    if (required_buffer_size < HTT_MAX_STRING_LEN) {
        for (i = 0; i < num_elements; i++) {
            index += snprintf(&fw2wbm_ring_full_hist[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->fw2wbm_ring_full_hist[i]);
        }

        HTT_STATS_PRINT(FATAL, "fw2wbm_ring_full_hist = %s\n", fw2wbm_ring_full_hist);
    } else {
        HTT_STATS_PRINT(FATAL, "INSUFFICIENT PRINT BUFFER ");
    }
}

/*
 * htt_print_tx_de_cmn_stats_tlv: display htt_tx_de_cmn_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_de_cmn_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_de_cmn_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_de_cmn_stats_tlv *htt_stats_buf =
        (htt_tx_de_cmn_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_TX_DE_CMN_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "tcl2fw_entry_count = %u",
            htt_stats_buf->tcl2fw_entry_count);
    HTT_STATS_PRINT(FATAL, "not_to_fw = %u",
            htt_stats_buf->not_to_fw);
    HTT_STATS_PRINT(FATAL, "invalid_pdev_vdev_peer = %u",
            htt_stats_buf->invalid_pdev_vdev_peer);
    HTT_STATS_PRINT(FATAL, "tcl_res_invalid_addrx = %u",
            htt_stats_buf->tcl_res_invalid_addrx);
    HTT_STATS_PRINT(FATAL, "wbm2fw_entry_count = %u",
            htt_stats_buf->wbm2fw_entry_count);
    HTT_STATS_PRINT(FATAL, "invalid_pdev = %u",
            htt_stats_buf->invalid_pdev);
    HTT_STATS_PRINT(FATAL, "tcl_res_addrx_timeout = %u",
            htt_stats_buf->tcl_res_addrx_timeout);
    HTT_STATS_PRINT(FATAL, "invalid_vdev = %u",
            htt_stats_buf->invalid_vdev);
    HTT_STATS_PRINT(FATAL, "invalid_tcl_exp_frame_desc = %u\n",
            htt_stats_buf->invalid_tcl_exp_frame_desc);
}

/*
 * htt_print_ring_if_stats_tlv: display htt_ring_if_stats_tlv
 * @tag_buf: buffer containing the tlv htt_ring_if_stats_tlv
 *
 * return:void
 */
static void htt_print_ring_if_stats_tlv(A_UINT32 *tag_buf)
{
    htt_ring_if_stats_tlv *htt_stats_buf =
        (htt_ring_if_stats_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                 = 0;
    A_CHAR   *low_wm_hit_count = NULL;
    A_CHAR   *high_wm_hit_count = NULL;

    low_wm_hit_count = (A_CHAR *)malloc(HTT_MAX_STRING_LEN * sizeof(A_CHAR));
    if (!low_wm_hit_count) {
        HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
        return;
    }

    high_wm_hit_count = (A_CHAR *)malloc(HTT_MAX_STRING_LEN * sizeof(A_CHAR));
    if (!high_wm_hit_count) {
        HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
        free(low_wm_hit_count);
        return;
    }

    HTT_STATS_PRINT(FATAL, "HTT_RING_IF_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "base_addr = %u",
            htt_stats_buf->base_addr);
    HTT_STATS_PRINT(FATAL, "elem_size = %u",
            htt_stats_buf->elem_size);
    HTT_STATS_PRINT(FATAL, "num_elems = %u",
            htt_stats_buf->num_elems__prefetch_tail_idx & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "prefetch_tail_idx = %u",
            (htt_stats_buf->num_elems__prefetch_tail_idx & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "head_idx = %u",
            htt_stats_buf->head_idx__tail_idx & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "tail_idx = %u",
            (htt_stats_buf->head_idx__tail_idx & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "shadow_head_idx = %u",
            htt_stats_buf->shadow_head_idx__shadow_tail_idx & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "shadow_tail_idx = %u",
            (htt_stats_buf->shadow_head_idx__shadow_tail_idx & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "num_tail_incr = %u",
            htt_stats_buf->num_tail_incr);
    HTT_STATS_PRINT(FATAL, "lwm_thresh = %u",
            htt_stats_buf->lwm_thresh__hwm_thresh & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "hwm_thresh = %u",
            (htt_stats_buf->lwm_thresh__hwm_thresh & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "overrun_hit_count = %u",
            htt_stats_buf->overrun_hit_count);
    HTT_STATS_PRINT(FATAL, "underrun_hit_count = %u",
            htt_stats_buf->underrun_hit_count);
    HTT_STATS_PRINT(FATAL, "prod_blockwait_count = %u",
            htt_stats_buf->prod_blockwait_count);
    HTT_STATS_PRINT(FATAL, "cons_blockwait_count = %u",
            htt_stats_buf->cons_blockwait_count);

    for (i = 0; i < HTT_STATS_LOW_WM_BINS; i++) {
        index += snprintf(&low_wm_hit_count[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->low_wm_hit_count[i]);
    }

    HTT_STATS_PRINT(FATAL, "low_wm_hit_count = %s ", low_wm_hit_count);

    index = 0;

    for (i = 0; i < HTT_STATS_HIGH_WM_BINS; i++) {
        index += snprintf(&high_wm_hit_count[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->high_wm_hit_count[i]);
    }

    HTT_STATS_PRINT(FATAL, "high_wm_hit_count = %s\n", high_wm_hit_count);

    free(low_wm_hit_count);
    free(high_wm_hit_count);
}

/*
 * htt_print_ring_if_cmn_tlv: display htt_ring_if_cmn_tlv
 * @tag_buf: buffer containing the tlv htt_ring_if_cmn_tlv
 *
 * return:void
 */
static void htt_print_ring_if_cmn_tlv(A_UINT32 *tag_buf)
{
    htt_ring_if_cmn_tlv *htt_stats_buf =
        (htt_ring_if_cmn_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_RING_IF_CMN_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "num_records = %u\n",
            htt_stats_buf->num_records);
}

/*
 * htt_print_sfm_client_user_tlv_v: display htt_sfm_client_user_tlv_v
 * @tag_buf: buffer containing the tlv htt_sfm_client_user_tlv_v
 *
 * return:void
 */
static void htt_print_sfm_client_user_tlv_v(A_UINT32 *tag_buf)
{
    htt_sfm_client_user_tlv_v *htt_stats_buf =
        (htt_sfm_client_user_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                     = 0;
    A_CHAR   dwords_used_by_user_n[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                                   = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_SFM_CLIENT_USER_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&dwords_used_by_user_n[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->dwords_used_by_user_n[i]);
    }

    HTT_STATS_PRINT(FATAL, "dwords_used_by_user_n = %s\n",
            dwords_used_by_user_n);
}

/*
 * htt_print_sfm_client_tlv: display htt_sfm_client_tlv
 * @tag_buf: buffer containing the tlv htt_sfm_client_tlv
 *
 * return:void
 */
static void htt_print_sfm_client_tlv(A_UINT32 *tag_buf)
{
    htt_sfm_client_tlv *htt_stats_buf =
        (htt_sfm_client_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_SFM_CLIENT_TLV:");
    HTT_STATS_PRINT(FATAL, "client_id = %u",
            htt_stats_buf->client_id);
    HTT_STATS_PRINT(FATAL, "buf_min = %u",
            htt_stats_buf->buf_min);
    HTT_STATS_PRINT(FATAL, "buf_max = %u",
            htt_stats_buf->buf_max);
    HTT_STATS_PRINT(FATAL, "buf_busy = %u",
            htt_stats_buf->buf_busy);
    HTT_STATS_PRINT(FATAL, "buf_alloc = %u",
            htt_stats_buf->buf_alloc);
    HTT_STATS_PRINT(FATAL, "buf_avail = %u",
            htt_stats_buf->buf_avail);
    HTT_STATS_PRINT(FATAL, "num_users = %u\n",
            htt_stats_buf->num_users);
}

/*
 * htt_print_sfm_cmn_tlv: display htt_sfm_cmn_tlv
 * @tag_buf: buffer containing the tlv htt_sfm_cmn_tlv
 *
 * return:void
 */
static void htt_print_sfm_cmn_tlv(A_UINT32 *tag_buf)
{
    htt_sfm_cmn_tlv *htt_stats_buf =
        (htt_sfm_cmn_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_SFM_CMN_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "buf_total = %u",
            htt_stats_buf->buf_total);
    HTT_STATS_PRINT(FATAL, "mem_empty = %u",
            htt_stats_buf->mem_empty);
    HTT_STATS_PRINT(FATAL, "deallocate_bufs = %u",
            htt_stats_buf->deallocate_bufs);
    HTT_STATS_PRINT(FATAL, "num_records = %u\n",
            htt_stats_buf->num_records);
}

/*
 * htt_print_sring_stats_tlv: display htt_sring_stats_tlv
 * @tag_buf: buffer containing the tlv htt_sring_stats_tlv
 *
 * return:void
 */
static void htt_print_sring_stats_tlv(A_UINT32 *tag_buf)
{
    htt_sring_stats_tlv *htt_stats_buf =
        (htt_sring_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_SRING_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__ring_id__arena__ep & 0xFF);
    HTT_STATS_PRINT(FATAL, "ring_id = %u",
            (htt_stats_buf->mac_id__ring_id__arena__ep & 0xFF00) >> 8);
    HTT_STATS_PRINT(FATAL, "arena = %u",
            (htt_stats_buf->mac_id__ring_id__arena__ep & 0xFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "ep = %u",
            (htt_stats_buf->mac_id__ring_id__arena__ep & 0x1000000) >> 24);
    HTT_STATS_PRINT(FATAL, "base_addr_lsb = 0x%x",
            htt_stats_buf->base_addr_lsb);
    HTT_STATS_PRINT(FATAL, "base_addr_msb = 0x%x",
            htt_stats_buf->base_addr_msb);
    HTT_STATS_PRINT(FATAL, "ring_size = %u",
            htt_stats_buf->ring_size);
    HTT_STATS_PRINT(FATAL, "elem_size = %u",
            htt_stats_buf->elem_size);
    HTT_STATS_PRINT(FATAL, "num_avail_words = %u",
            htt_stats_buf->num_avail_words__num_valid_words & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "num_valid_words = %u",
            (htt_stats_buf->num_avail_words__num_valid_words & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "head_ptr = %u",
            htt_stats_buf->head_ptr__tail_ptr & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "tail_ptr = %u",
            (htt_stats_buf->head_ptr__tail_ptr & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "consumer_empty = %u",
            htt_stats_buf->consumer_empty__producer_full & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "producer_full = %u",
            (htt_stats_buf->consumer_empty__producer_full & 0xFFFF0000) >> 16);
    HTT_STATS_PRINT(FATAL, "prefetch_count = %u",
            htt_stats_buf->prefetch_count__internal_tail_ptr & 0xFFFF);
    HTT_STATS_PRINT(FATAL, "internal_tail_ptr = %u\n",
            (htt_stats_buf->prefetch_count__internal_tail_ptr & 0xFFFF0000) >> 16);
}

/*
 * htt_print_sring_cmn_tlv: display htt_sring_cmn_tlv
 * @tag_buf: buffer containing the tlv htt_sring_cmn_tlv
 *
 * return:void
 */
static void htt_print_sring_cmn_tlv(A_UINT32 *tag_buf)
{
    htt_sring_cmn_tlv *htt_stats_buf =
        (htt_sring_cmn_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_SRING_CMN_TLV:");
    HTT_STATS_PRINT(FATAL, "num_records = %u\n",
            htt_stats_buf->num_records);
}

/*
 * htt_print_tx_pdev_rate_stats_tlv: display htt_tx_pdev_rate_stats_tlv
 * @tag_buf: buffer containing the tlv htt_tx_pdev_rate_stats_tlv
 *
 * return:void
 */
static void htt_print_tx_pdev_rate_stats_tlv(A_UINT32 *tag_buf)
{
    htt_tx_pdev_rate_stats_tlv *htt_stats_buf =
        (htt_tx_pdev_rate_stats_tlv *)tag_buf;
    A_UINT8  i, j;
    A_UINT16 index                       = 0;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};
    A_CHAR   *tx_gi[HTT_TX_PEER_STATS_NUM_GI_COUNTERS];

    for (i = 0; i < HTT_TX_PEER_STATS_NUM_GI_COUNTERS; i++) {
        tx_gi[i] = (A_CHAR *)malloc(HTT_MAX_STRING_LEN);
        if (!tx_gi[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(tx_gi[j]);
           }
           return;
        }
    }

    HTT_STATS_PRINT(FATAL, "HTT_TX_PDEV_RATE_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "tx_ldpc = %u",
            htt_stats_buf->tx_ldpc);
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_tx_ldpc = %u",
            htt_stats_buf->ac_mu_mimo_tx_ldpc);
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_tx_ldpc = %u",
            htt_stats_buf->ax_mu_mimo_tx_ldpc);
    HTT_STATS_PRINT(FATAL, "ofdma_tx_ldpc = %u",
            htt_stats_buf->ofdma_tx_ldpc);
    HTT_STATS_PRINT(FATAL, "rts_cnt = %u",
            htt_stats_buf->rts_cnt);
    HTT_STATS_PRINT(FATAL, "rts_success = %u",
            htt_stats_buf->rts_success);
    HTT_STATS_PRINT(FATAL, "ack_rssi = %u",
            htt_stats_buf->ack_rssi);
    HTT_STATS_PRINT(FATAL, "tx_11ax_su_ext = %u",
            htt_stats_buf->tx_11ax_su_ext);

    HTT_STATS_PRINT(FATAL, "Legacy CCK Rates: 1 Mbps: %u, 2 Mbps: %u, 5.5 Mbps: %u, 11 Mbps: %u",
            htt_stats_buf->tx_legacy_cck_rate[0], htt_stats_buf->tx_legacy_cck_rate[1],
            htt_stats_buf->tx_legacy_cck_rate[2], htt_stats_buf->tx_legacy_cck_rate[3]);

    HTT_STATS_PRINT(FATAL, "Legacy OFDM Rates: 6 Mbps: %u, 9 Mbps: %u, 12 Mbps: %u, 18 Mbps: %u\n"
                           "                   24 Mbps: %u, 36 Mbps: %u, 48 Mbps: %u, 54 Mbps: %u",
            htt_stats_buf->tx_legacy_ofdm_rate[0], htt_stats_buf->tx_legacy_ofdm_rate[1],
            htt_stats_buf->tx_legacy_ofdm_rate[2], htt_stats_buf->tx_legacy_ofdm_rate[3],
            htt_stats_buf->tx_legacy_ofdm_rate[4], htt_stats_buf->tx_legacy_ofdm_rate[5],
            htt_stats_buf->tx_legacy_ofdm_rate[6], htt_stats_buf->tx_legacy_ofdm_rate[7]);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_mcs[i]);
    }
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->tx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ac_mu_mimo_tx_mcs[i]);
    }
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->ax_mu_mimo_tx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_tx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ax_mu_mimo_tx_mcs[i]);
    }
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->ax_mu_mimo_tx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_tx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ofdma_tx_mcs[i]);
    }
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->ofdma_tx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "ofdma_tx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->tx_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ac_mu_mimo_tx_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_tx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ax_mu_mimo_tx_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_tx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ofdma_tx_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "ofdma_tx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_bw = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ac_mu_mimo_tx_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "ac_mu_mimo_tx_bw = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ax_mu_mimo_tx_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "ax_mu_mimo_tx_bw = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ofdma_tx_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "ofdma_tx_bw = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_stbc[i]);
    }
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                htt_stats_buf->tx_stbc_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "tx_stbc = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_PREAMBLE_TYPES; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_pream[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_pream = %s ",                 str_buf);

    HTT_STATS_PRINT(FATAL, "HE LTF: 1x: %u, 2x: %u, 4x: %u", htt_stats_buf->tx_he_ltf[1],
            htt_stats_buf->tx_he_ltf[2], htt_stats_buf->tx_he_ltf[3]);

    /* SU GI Stats */
    for (j = 0; j < HTT_TX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->tx_gi[j][i]);
        }
        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                    htt_stats_buf->tx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "tx_gi[%u] = %s ", j, tx_gi[j]);
    }

    /* AC MU-MIMO GI Stats */
    for (j = 0; j < HTT_TX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;

        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->ac_mu_mimo_tx_gi[j][i]);
        }

        HTT_STATS_PRINT(FATAL, "ac_mu_mimo_tx_gi[%u] = %s ", j, tx_gi[j]);
    }

    /* AX MU-MIMO GI Stats */
    for (j = 0; j < HTT_TX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->ax_mu_mimo_tx_gi[j][i]);
        }
        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                    htt_stats_buf->ax_mu_mimo_tx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "ax_mu_mimo_tx_gi[%u] = %s ", j, tx_gi[j]);
    }

    /* DL OFDMA GI Stats */
    for (j = 0; j < HTT_TX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->ofdma_tx_gi[j][i]);
        }
        for (i = 0; i < HTT_TX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
            index += snprintf(&tx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i + HTT_TX_PDEV_STATS_NUM_MCS_COUNTERS,
                    htt_stats_buf->ofdma_tx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "ofdma_tx_gi[%u] = %s ", j, tx_gi[j]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_DCM_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->tx_dcm[i]);
    }

    HTT_STATS_PRINT(FATAL, "tx_dcm = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_11AX_TRIGGER_TYPES; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->trigger_type_11ax[i]);
    }

    HTT_STATS_PRINT(FATAL, "11ax_trigger_type = %s\n", str_buf);

    for (i = 0; i < HTT_TX_PEER_STATS_NUM_GI_COUNTERS; i++) {
        free(tx_gi[i]);
    }
}

/*
 * htt_print_rx_pdev_ul_mumimo_trig_stats_tlv: display htt_rx_pdev_ul_mumimo_trig_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_pdev_ul_mumimo_trig_stats_tlv
 *
 * return:void
 */
static void htt_print_ul_mumimo_trig_stats(A_UINT32 *tag_buf)
{
    htt_rx_pdev_ul_mumimo_trig_stats_tlv *htt_ul_mumimo_trig_stats_buf =
        (htt_rx_pdev_ul_mumimo_trig_stats_tlv *)tag_buf;

    A_CHAR str_buf[HTT_MAX_STRING_LEN];
    A_CHAR *rx_gi[HTT_RX_PDEV_STATS_NUM_GI_COUNTERS];
    A_UINT8 i, j;
    A_UINT16 index;

    for (i=0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        rx_gi[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rx_gi[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rx_gi[j]);
           }
           return;
        }
    }

    HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_UL_MUMIMO_TRIG_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
        htt_ul_mumimo_trig_stats_buf->mac_id__word & 0xFF);

    HTT_STATS_PRINT(FATAL, "rx_11ax_ul_mumimo = %u",
            htt_ul_mumimo_trig_stats_buf->rx_11ax_ul_mumimo);

    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(
            HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS +
                HTT_RX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS,
            HTT_MAX_STRING_LEN);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_mcs[i]);
    }
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS,
                htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_mumimo_rx_mcs = %s ", str_buf);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        memset(rx_gi[j], 0x0, HTT_MAX_STRING_LEN);
        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&rx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i, htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_gi[j][i]);
        }
        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_EXTRA_MCS_COUNTERS; i++) {
            index += snprintf(&rx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i + HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS,
                    htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "ul_mumimo_rx_gi[%u] = %s ", j, rx_gi[j]);
    }

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        free(rx_gi[i]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_ULMUMIMO_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_nss[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_mumimo_rx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_bw[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_mumimo_rx_bw = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "ul_mumimo_rx_stbc = %u",
            htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_stbc);
    HTT_STATS_PRINT(FATAL, "ul_mumimo_rx_ldpc = %u",
            htt_ul_mumimo_trig_stats_buf->ul_mumimo_rx_ldpc);

    for (i = 0; i < HTT_RX_PDEV_STATS_ULMUMIMO_NUM_SPATIAL_STREAMS; i++) {
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        index = 0;
        for (j = 0; j < HTT_RX_PDEV_STATS_TOTAL_BW_COUNTERS; j++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", j, htt_ul_mumimo_trig_stats_buf->rx_ul_mumimo_chain_rssi_in_dbm[i][j]);
        }
        HTT_STATS_PRINT(FATAL,
                "rx_ul_mumimo_rssi_in_dbm: chain[%u] = %s ", i, str_buf);
    }

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_UL_MUMIMO_USER_STATS; i++) {
        index = 0;
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        for (j = 0; j <HTT_RX_PDEV_STATS_NUM_BW_COUNTERS; j++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%d,", j, htt_ul_mumimo_trig_stats_buf->rx_ul_mumimo_target_rssi[i][j]);
        }
        HTT_STATS_PRINT(FATAL, "rx_ul_mumimo_target_rssi: user[%u] = %s ", i, str_buf);
    }

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_UL_MUMIMO_USER_STATS; i++) {
        index = 0;
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        for (j = 0; j < HTT_RX_PDEV_STATS_ULMUMIMO_NUM_SPATIAL_STREAMS; j++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%d,", j, htt_ul_mumimo_trig_stats_buf->rx_ul_mumimo_fd_rssi[i][j]);
        }
        HTT_STATS_PRINT(FATAL, "rx_ul_mumimo_fd_rssi: user[%u] = %s ", i, str_buf);
    }

    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_UL_MUMIMO_USER_STATS; i++) {
        index = 0;
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        for (j = 0; j < HTT_RX_PDEV_STATS_ULMUMIMO_NUM_SPATIAL_STREAMS; j++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%d,", j, htt_ul_mumimo_trig_stats_buf->rx_ulmumimo_pilot_evm_dB_mean[i][j]);
        }
        HTT_STATS_PRINT(FATAL, "rx_ulmumimo_pilot_evm_dB_mean: user [%u] = %s ", i, str_buf);
    }
    HTT_STATS_PRINT(FATAL, "\n");
}

/*
 * htt_print_ul_mimo_user_stats : display htt_rx_pdev_ul_mimo_user_stats_tlv
 * @tag_buf:buffer containing the tlv htt_rx_pdev_ul_mimo_user_stats_tlv
 * return:void
 */
static void htt_print_ul_mimo_user_stats(A_UINT32 *tag_buf)
{
    htt_rx_pdev_ul_mimo_user_stats_tlv *htt_ul_user_stats_buf =
        (htt_rx_pdev_ul_mimo_user_stats_tlv *)tag_buf;

    if (htt_ul_user_stats_buf->user_index < HTT_RX_PDEV_MAX_ULMUMIMO_NUM_USER) {
        if (htt_ul_user_stats_buf->user_index == 0) {
            HTT_STATS_PRINT(FATAL, "HTT_STATS_RX_PDEV_UL_MIMO_USER_STATS_TLV");
        }

        HTT_STATS_PRINT(FATAL, "rx_ulmumimo_non_data_ppdu_%u = %u ",
                htt_ul_user_stats_buf->user_index,
                htt_ul_user_stats_buf->rx_ulmumimo_non_data_ppdu);
        HTT_STATS_PRINT(FATAL, "rx_ulmumimo_data_ppdu_%u = %u ",
                htt_ul_user_stats_buf->user_index,
                htt_ul_user_stats_buf->rx_ulmumimo_data_ppdu);
        HTT_STATS_PRINT(FATAL, "rx_ulmumimo_mpdu_ok_%u = %u ",
                htt_ul_user_stats_buf->user_index,
                htt_ul_user_stats_buf->rx_ulmumimo_mpdu_ok);
        HTT_STATS_PRINT(FATAL, "rx_ulmumimo_mpdu_fail_%u = %u",
                htt_ul_user_stats_buf->user_index,
                htt_ul_user_stats_buf->rx_ulmumimo_mpdu_fail);
    }
}

/*
 * htt_print_ul_ofdma_user_stats : display htt_rx_pdev_ul_ofdma_user_stats_tlv
 * @tag_buf:buffer containing the tlv htt_rx_pdev_ul_ofdma_user_stats_tlv
 * return:void
 */
static void htt_print_ul_ofdma_user_stats(A_UINT32 *tag_buf)
{
    htt_rx_pdev_ul_ofdma_user_stats_tlv *htt_ul_user_stats_buf =
        (htt_rx_pdev_ul_ofdma_user_stats_tlv *)tag_buf;

    if (htt_ul_user_stats_buf->user_index == 0) {
        HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_UL_OFDMA_USER_STAS_TLV");
    }

    HTT_STATS_PRINT(FATAL, "rx_ulofdma_non_data_ppdu_%u = %u ",
            htt_ul_user_stats_buf->user_index,
            htt_ul_user_stats_buf->rx_ulofdma_non_data_ppdu);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_data_ppdu_%u = %u ",
            htt_ul_user_stats_buf->user_index,
            htt_ul_user_stats_buf->rx_ulofdma_data_ppdu);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_mpdu_ok_%u = %u ",
            htt_ul_user_stats_buf->user_index,
            htt_ul_user_stats_buf->rx_ulofdma_mpdu_ok);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_mpdu_fail_%u = %u",
            htt_ul_user_stats_buf->user_index,
            htt_ul_user_stats_buf->rx_ulofdma_mpdu_fail);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_non_data_nusers_%u = %u",
            htt_ul_user_stats_buf->user_index,
            htt_ul_user_stats_buf->rx_ulofdma_non_data_nusers);
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_data_nusers_%u = %u",
            htt_ul_user_stats_buf->user_index,
            htt_ul_user_stats_buf->rx_ulofdma_data_nusers);
}

/*
 * htt_print_rx_pdev_ul_ofdma_stats_tlv: display htt_rx_pdev_ul_ofdma_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_pdev_ul_ofdma_stats_tlv
 *
 * return:void
 */
static void htt_print_ul_ofdma_trigger_stats(A_UINT32 *tag_buf)
{

    htt_rx_pdev_ul_trigger_stats_tlv *htt_trigger_stats_buf =
        (htt_rx_pdev_ul_trigger_stats_tlv *)tag_buf;

    A_CHAR   str_buf[HTT_MAX_STRING_LEN];
    A_CHAR   *rx_gi[HTT_RX_PDEV_STATS_NUM_GI_COUNTERS];
    A_UINT8  i, j;
    A_UINT16 index;

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        rx_gi[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rx_gi[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rx_gi[j]);
           }
           return;
        }
    }

    HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_UL_TRIGGER_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            HTT_STATS_CMN_MAC_ID_GET(htt_trigger_stats_buf->mac_id__word));
    HTT_STATS_PRINT(FATAL, "rx_11ax_ul_ofdma =%u",
        htt_trigger_stats_buf->rx_11ax_ul_ofdma);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->ul_ofdma_rx_mcs[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_mcs = %s ", str_buf);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        memset(rx_gi[j], 0x0, HTT_MAX_STRING_LEN);
        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&rx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_trigger_stats_buf->ul_ofdma_rx_gi[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_gi[%u] = %s ", j, rx_gi[j]);
    }

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        free(rx_gi[i]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_trigger_stats_buf->ul_ofdma_rx_nss[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->ul_ofdma_rx_bw[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_bw = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_stbc = %u",
            htt_trigger_stats_buf->ul_ofdma_rx_stbc);
    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_ldpc = %u",
            htt_trigger_stats_buf->ul_ofdma_rx_ldpc);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_RU_SIZE_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->rx_ulofdma_data_ru_size_ppdu[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_non_data_ru_size_ppdu = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_RU_SIZE_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->rx_ulofdma_non_data_ru_size_ppdu[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_data_ru_size_ppdu = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_UL_MAX_UPLINK_RSSI_TRACK; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->uplink_sta_aid[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_rssi_track_sta_aid = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_UL_MAX_UPLINK_RSSI_TRACK; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->uplink_sta_target_rssi[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_sta_target_rssi = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_UL_MAX_UPLINK_RSSI_TRACK; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->uplink_sta_fd_rssi[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_sta_fd_rssi = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_UL_MAX_UPLINK_RSSI_TRACK; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_trigger_stats_buf->uplink_sta_power_headroom[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_sta_power_headroom = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "\n");
}

/*
 * htt_print_rx_pdev_rate_stats_tlv: display htt_rx_pdev_rate_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_pdev_rate_stats_tlv
 *
 * return:void
 */
static void htt_print_rx_pdev_rate_stats_tlv(A_UINT32 *tag_buf)
{
    htt_rx_pdev_rate_stats_tlv *htt_stats_buf =
        (htt_rx_pdev_rate_stats_tlv *)tag_buf;
    A_UINT8  i, j;
    A_UINT16 index = 0;
    A_CHAR   *rssi_chain[HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS];
    A_CHAR   *rx_gi[HTT_RX_PDEV_STATS_NUM_GI_COUNTERS];
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};
    A_CHAR   *rx_pilot_evm_dB[HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS];

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        rssi_chain[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rssi_chain[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rssi_chain[j]);
           }
           return;
        }
    }

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        rx_gi[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rx_gi[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rx_gi[j]);
           }
           for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
                free(rssi_chain[j]);
           }
           return;
        }
    }

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        rx_pilot_evm_dB[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rx_pilot_evm_dB[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rx_pilot_evm_dB[j]);
           }
           for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
                free(rssi_chain[j]);
           }
           for (j = 0; j < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
                free(rx_gi[j]);
           }
           return;
        }
    }

    HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_RATE_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "nsts = %u",
            htt_stats_buf->nsts);
    HTT_STATS_PRINT(FATAL, "rx_ldpc = %u",
            htt_stats_buf->rx_ldpc);
    HTT_STATS_PRINT(FATAL, "rts_cnt = %u",
            htt_stats_buf->rts_cnt);
    HTT_STATS_PRINT(FATAL, "rssi_mgmt = %u",
            htt_stats_buf->rssi_mgmt);
    HTT_STATS_PRINT(FATAL, "rssi_data = %u",
            htt_stats_buf->rssi_data);
    HTT_STATS_PRINT(FATAL, "rssi_comb = %u",
            htt_stats_buf->rssi_comb);
    HTT_STATS_PRINT(FATAL, "rssi_in_dbm = %d",
            htt_stats_buf->rssi_in_dbm);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_mcs[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->rx_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_DCM_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_dcm[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_dcm = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_stbc[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_stbc = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_bw = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "rx_evm_nss_count = %u",
            htt_stats_buf->nss_count);

    HTT_STATS_PRINT(FATAL, "rx_evm_pilot_count = %u",
            htt_stats_buf->pilot_count);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
        index = 0;

        for (i = 0; i < HTT_RX_PDEV_STATS_RXEVM_MAX_PILOTS_PER_NSS; i++) {
            index += snprintf(&rx_pilot_evm_dB[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%d,", i, htt_stats_buf->rx_pilot_evm_dB[j][i]);
        }

        HTT_STATS_PRINT(FATAL, "pilot_evm_dB[%u] = %s ", j, rx_pilot_evm_dB[j]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%d,", i, htt_stats_buf->rx_pilot_evm_dB_mean[i]);
    }

    HTT_STATS_PRINT(FATAL, "pilot_evm_dB_mean = %s ", str_buf);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
        index = 0;

        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
            index += snprintf(&rssi_chain[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->rssi_chain[j][i]);
        }

        HTT_STATS_PRINT(FATAL, "rssi_chain[%u] = %s ", j, rssi_chain[j]);
    }

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&rx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->rx_gi[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "rx_gi[%u] = %s ", j, rx_gi[j]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_PREAMBLE_TYPES; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_pream[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_pream = %s", str_buf);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        free(rssi_chain[i]);
    }

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        free(rx_pilot_evm_dB[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_11ax_su_ext = %u",
            htt_stats_buf->rx_11ax_su_ext);
    HTT_STATS_PRINT(FATAL, "rx_11ac_mumimo = %u",
            htt_stats_buf->rx_11ac_mumimo);
    HTT_STATS_PRINT(FATAL, "rx_11ax_mumimo = %u",
            htt_stats_buf->rx_11ax_mumimo);
    HTT_STATS_PRINT(FATAL, "rx_11ax_ofdma = %u",
            htt_stats_buf->rx_11ax_ofdma);
    HTT_STATS_PRINT(FATAL, "txbf = %u",
            htt_stats_buf->txbf);
    HTT_STATS_PRINT(FATAL, "rx_su_ndpa = %u",
            htt_stats_buf->rx_su_ndpa);

    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(
            HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS, HTT_MAX_STRING_LEN);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_11ax_su_txbf_mcs[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_11ax_su_txbf_mcs = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "rx_mu_ndpa = %u",
            htt_stats_buf->rx_mu_ndpa);

    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(
            HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS, HTT_MAX_STRING_LEN);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_11ax_mu_txbf_mcs[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_11ax_mu_txbf_mcs = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "rx_br_poll = %u",
            htt_stats_buf->rx_br_poll);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(HTT_RX_PDEV_STATS_NUM_LEGACY_CCK_STATS,
            HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_LEGACY_CCK_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_legacy_cck_rate[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_legacy_cck_rate = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(HTT_RX_PDEV_STATS_NUM_LEGACY_OFDM_STATS,
            HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_LEGACY_OFDM_STATS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_legacy_ofdm_rate[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_legacy_ofdm_rate = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "rx_active_dur_us_low = %u",
            htt_stats_buf->rx_active_dur_us_low);
    HTT_STATS_PRINT(FATAL, "rx_active_dur_us_high = %u",
            htt_stats_buf->rx_active_dur_us_high);

    HTT_STATS_PRINT(FATAL, "rx_11ax_ul_ofdma = %u",
            htt_stats_buf->rx_11ax_ul_ofdma);

    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(
            HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS, HTT_MAX_STRING_LEN);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ul_ofdma_rx_mcs[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_mcs = %s ", str_buf);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&rx_gi[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i, htt_stats_buf->ul_ofdma_rx_gi[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_gi[%u] = %s ", j, rx_gi[j]);
    }

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        free(rx_gi[i]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i + 1, htt_stats_buf->ul_ofdma_rx_nss[i]);
    }

    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_nss = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ul_ofdma_rx_bw[i]);
    }

    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_bw = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_stbc = %u",
            htt_stats_buf->ul_ofdma_rx_stbc);
    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_ldpc = %u",
            htt_stats_buf->ul_ofdma_rx_ldpc);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_OFDMA_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulofdma_non_data_ppdu[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulofdma_non_data_ppdu = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_OFDMA_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulofdma_data_ppdu[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulofdma_data_ppdu = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_OFDMA_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulofdma_mpdu_ok[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulofdma_mpdu_ok = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_OFDMA_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulofdma_mpdu_fail[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulofdma_mpdu_fail = %s", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_ULMUMIMO_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulmumimo_non_data_ppdu[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_non_data_ppdu = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_ULMUMIMO_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulmumimo_data_ppdu[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_data_ppdu = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_ULMUMIMO_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulmumimo_mpdu_ok[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_mpdu_ok = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_MAX_ULMUMIMO_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulmumimo_mpdu_fail[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_ulmumimo_mpdu_fail = %s", str_buf);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
        index = 0;
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

        for (i = 0; i < HTT_RX_PDEV_MAX_OFDMA_NUM_USER; i++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%d,", i, htt_stats_buf->rx_ul_fd_rssi[j][i]);
        }

        HTT_STATS_PRINT(FATAL, "rx_ul_fd_rssi: nss[%u] = %s", j, str_buf);
    }

    HTT_STATS_PRINT(FATAL, "per_chain_rssi_pkt_type = %#x",
            htt_stats_buf->per_chain_rssi_pkt_type);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        index = 0;

        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_COUNTERS; i++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%d,", i,
                    (signed char) htt_stats_buf->rx_per_chain_rssi_in_dbm[j][i]);
        }

        HTT_STATS_PRINT(FATAL,
                "rx_per_chain_rssi_in_dbm[%u] = %s ", j, str_buf);
    }

    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(
            HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS, HTT_MAX_STRING_LEN);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_11ax_dl_ofdma_mcs[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_11ax_dl_ofdma_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    HTT_CHECK_FOR_SPACE_ON_PRINT_BUFFER(HTT_RX_PDEV_STATS_NUM_RU_SIZE_COUNTERS,
            HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_RU_SIZE_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_11ax_dl_ofdma_ru[i]);
    }

    HTT_STATS_PRINT(FATAL, "rx_11ax_dl_ofdma_ru = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_MAX_OFDMA_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulofdma_non_data_nusers[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_non_data_nusers = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_MAX_OFDMA_NUM_USER; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_ulofdma_data_nusers[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_ulofdma_data_nusers = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "\n");
}

/*
 * htt_print_rx_pdev_rate_ext_stats_tlv: display htt_rx_pdev_rate_ext_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_pdev_rate_ext_stats_tlv
 *
 * return:void
 */
static void htt_print_rx_pdev_rate_ext_stats_tlv(A_UINT32 *tag_buf)
{
    htt_rx_pdev_rate_ext_stats_tlv *htt_stats_buf =
        (htt_rx_pdev_rate_ext_stats_tlv *)tag_buf;
    A_UINT8  i, j;
    A_UINT16 index = 0;
    A_CHAR   str_buf[HTT_MAX_STRING_LEN] = {0};
    A_CHAR   *rx_gi_ext[HTT_RX_PDEV_STATS_NUM_GI_COUNTERS];

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        rx_gi_ext[i] = malloc(HTT_MAX_STRING_LEN);
        if (!rx_gi_ext[i]) {
           HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
           for (j = 0; j < i; j++) {
               free(rx_gi_ext[j]);
           }
           return;
        }
    }

    HTT_STATS_PRINT(FATAL, "rssi_mcast_in_dbm = %d",
    htt_stats_buf->rssi_mcast_in_dbm);

    HTT_STATS_PRINT(FATAL, "rssi_mgmt_in_dbm = %d",
    htt_stats_buf->rssi_mgmt_in_dbm);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        index = 0;

        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_EXT_COUNTERS; i++) {
            index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rssi_chain_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "rssi_chain_ext[%u] = %s ", j, str_buf);
    }
    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_SPATIAL_STREAMS; j++) {
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
        index = 0;

        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_BW_EXT_COUNTERS; i++) {
            index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rx_per_chain_rssi_ext_in_dbm[j][i]);
        }
        HTT_STATS_PRINT(FATAL,
            "rx_per_chain_rssi_ext_in_dbm[%u] = %s ", j, str_buf);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_mcs_ext = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rx_stbc_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_stbc_ext = %s ", str_buf);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        memset(rx_gi_ext[j], 0x0, HTT_MAX_STRING_LEN);
        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
            index += snprintf(&rx_gi_ext[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->rx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "rx_gi_ext[%u] = %s ", j, rx_gi_ext[j]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->ul_ofdma_rx_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_mcs_ext = %s ", str_buf);

    for (j = 0; j < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        memset(rx_gi_ext[j], 0x0, HTT_MAX_STRING_LEN);
        for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
            index += snprintf(&rx_gi_ext[j][index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->ul_ofdma_rx_gi_ext[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "ul_ofdma_rx_gi_ext[%u] = %s ", j, rx_gi_ext[j]);
    }

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rx_11ax_su_txbf_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_11ax_su_txbf_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rx_11ax_mu_txbf_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_11ax_mu_txbf_mcs_ext = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_MCS_COUNTERS_EXT; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rx_11ax_dl_ofdma_mcs_ext[i]);
    }
    HTT_STATS_PRINT(FATAL, "rx_11ax_dl_ofdma_mcs_ext = %s ", str_buf);


    HTT_STATS_PRINT(FATAL, "\n");

    for (i = 0; i < HTT_RX_PDEV_STATS_NUM_GI_COUNTERS; i++) {
        free(rx_gi_ext[i]);
    }
}

/*
 * htt_print_rx_soc_fw_stats_tlv: display htt_rx_soc_fw_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_soc_fw_stats_tlv
 *
 * return:void
 */
static void htt_print_rx_soc_fw_stats_tlv(A_UINT32 *tag_buf)
{
    htt_rx_soc_fw_stats_tlv *htt_stats_buf =
        (htt_rx_soc_fw_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_RX_SOC_FW_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "fw_reo_ring_data_msdu = %u",
            htt_stats_buf->fw_reo_ring_data_msdu);
    HTT_STATS_PRINT(FATAL, "fw_to_host_data_msdu_bcmc = %u",
            htt_stats_buf->fw_to_host_data_msdu_bcmc);
    HTT_STATS_PRINT(FATAL, "fw_to_host_data_msdu_uc = %u",
            htt_stats_buf->fw_to_host_data_msdu_uc);
    HTT_STATS_PRINT(FATAL, "ofld_remote_data_buf_recycle_cnt = %u",
            htt_stats_buf->ofld_remote_data_buf_recycle_cnt);
    HTT_STATS_PRINT(FATAL, "ofld_remote_free_buf_indication_cnt = %u",
            htt_stats_buf->ofld_remote_free_buf_indication_cnt);
    HTT_STATS_PRINT(FATAL, "ofld_buf_to_host_data_msdu_uc = %u",
            htt_stats_buf->ofld_buf_to_host_data_msdu_uc);
    HTT_STATS_PRINT(FATAL, "reo_fw_ring_to_host_data_msdu_uc = %u",
            htt_stats_buf->reo_fw_ring_to_host_data_msdu_uc);
    HTT_STATS_PRINT(FATAL, "wbm_sw_ring_reap = %u",
            htt_stats_buf->wbm_sw_ring_reap);
    HTT_STATS_PRINT(FATAL, "wbm_forward_to_host_cnt = %u",
            htt_stats_buf->wbm_forward_to_host_cnt);
    HTT_STATS_PRINT(FATAL, "wbm_target_recycle_cnt = %u",
            htt_stats_buf->wbm_target_recycle_cnt);
    HTT_STATS_PRINT(FATAL, "target_refill_ring_recycle_cnt = %u",
            htt_stats_buf->target_refill_ring_recycle_cnt);
}

/*
 * htt_print_rx_soc_fw_refill_ring_empty_tlv_v: display
 *                    htt_rx_soc_fw_refill_ring_empty_tlv_v
 * @tag_buf: buffer containing the tlv htt_rx_soc_fw_refill_ring_empty_tlv_v
 *
 * return:void
 */
static void htt_print_rx_soc_fw_refill_ring_empty_tlv_v(A_UINT32 *tag_buf)
{
    htt_rx_soc_fw_refill_ring_empty_tlv_v *htt_stats_buf =
        (htt_rx_soc_fw_refill_ring_empty_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                     = 0;
    A_CHAR   refill_ring_empty_cnt[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                                   = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_RX_SOC_FW_REFILL_RING_EMPTY_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&refill_ring_empty_cnt[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->refill_ring_empty_cnt[i]);
    }

    HTT_STATS_PRINT(FATAL, "refill_ring_empty_cnt = %s\n",
            refill_ring_empty_cnt);
}

/*
 * htt_rx_soc_fw_refill_ring_num_rxdma_err_tlv_v: display
 *                    htt_rx_soc_fw_refill_ring_num_rxdma_err_tlv_v
 * @tag_buf: buffer containing the tlv htt_rx_soc_fw_refill_ring_num_rxdma_err_tlv_v
 *
 * return:void
 */
static void htt_print_rx_soc_fw_refill_ring_num_rxdma_err_tlv_v(A_UINT32 *tag_buf)
{
    htt_rx_soc_fw_refill_ring_num_rxdma_err_tlv_v *htt_stats_buf =
        (htt_rx_soc_fw_refill_ring_num_rxdma_err_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                             = 0;
    A_CHAR   rxdma_err_cnt[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                           = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_RX_SOC_FW_REFILL_RING_NUM_RXDMA_ERR_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&rxdma_err_cnt[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->rxdma_err[i]);
    }

    HTT_STATS_PRINT(FATAL, "rxdma_err = %s\n",
            rxdma_err_cnt);
}

/*
 * htt_rx_soc_fw_refill_ring_num_reo_err_tlv_v: display
 *                    htt_rx_soc_fw_refill_ring_num_reo_err_tlv_v
 * @tag_buf: buffer containing the tlv htt_rx_soc_fw_refill_ring_num_reo_err_tlv_v
 *
 * return:void
 */
static void htt_print_rx_soc_fw_refill_ring_num_reo_err_tlv_v(A_UINT32 *tag_buf)
{
    htt_rx_soc_fw_refill_ring_num_reo_err_tlv_v *htt_stats_buf =
        (htt_rx_soc_fw_refill_ring_num_reo_err_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                           = 0;
    A_CHAR   reo_err_cnt[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                         = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_RX_SOC_FW_REFILL_RING_NUM_REO_ERR_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&reo_err_cnt[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->reo_err[i]);
    }

    HTT_STATS_PRINT(FATAL, "reo_err = %s\n",
            reo_err_cnt);
}

/*
 * htt_rx_reo_debug_stats_tlv_v: display
 *                    htt_rx_reo_debug_stats_tlv_v
 * @tag_buf: buffer containing the tlv htt_rx_reo_debug_stats_tlv_v
 *
 * return:void
 */
static void htt_print_rx_reo_debug_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_rx_reo_resource_stats_tlv_v *htt_stats_buf =
        (htt_rx_reo_resource_stats_tlv_v *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_RX_REO_RESOURCE_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "sample_id = %u",
            htt_stats_buf->sample_id);
    HTT_STATS_PRINT(FATAL, "total_max = %u",
            htt_stats_buf->total_max);
    HTT_STATS_PRINT(FATAL, "total_avg = %u",
            htt_stats_buf->total_avg);
    HTT_STATS_PRINT(FATAL, "total_sample = %u",
            htt_stats_buf->total_sample);
    HTT_STATS_PRINT(FATAL, "non_zeros_avg = %u",
            htt_stats_buf->non_zeros_avg);
    HTT_STATS_PRINT(FATAL, "non_zeros_sample = %u",
            htt_stats_buf->non_zeros_sample);
    HTT_STATS_PRINT(FATAL, "last_non_zeros_max = %u",
            htt_stats_buf->last_non_zeros_max);
    HTT_STATS_PRINT(FATAL, "last_non_zeros_min %u",
            htt_stats_buf->last_non_zeros_min);
    HTT_STATS_PRINT(FATAL, "last_non_zeros_avg %u",
            htt_stats_buf->last_non_zeros_avg);
    HTT_STATS_PRINT(FATAL, "last_non_zeros_sample %u\n",
            htt_stats_buf->last_non_zeros_sample);
}

/*
 * htt_print_rx_soc_fw_refill_ring_num_refill_tlv_v: display
 *                htt_rx_soc_fw_refill_ring_num_refill_tlv_v
 * @tag_buf: buffer containing the tlv htt_rx_soc_fw_refill_ring_num_refill_tlv
 *
 * return:void
 */
static void htt_print_rx_soc_fw_refill_ring_num_refill_tlv_v(A_UINT32 *tag_buf)
{
    htt_rx_soc_fw_refill_ring_num_refill_tlv_v *htt_stats_buf =
        (htt_rx_soc_fw_refill_ring_num_refill_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                      = 0;
    A_CHAR   refill_ring_num_refill[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                                    = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_RX_SOC_FW_REFILL_RING_NUM_REFILL_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&refill_ring_num_refill[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->refill_ring_num_refill[i]);
    }

    HTT_STATS_PRINT(FATAL, "refill_ring_num_refill = %s\n",
            refill_ring_num_refill);
}

/*
 * htt_print_rx_pdev_fw_stats_tlv: display htt_rx_pdev_fw_stats_tlv
 * @tag_buf: buffer containing the tlv htt_rx_pdev_fw_stats_tlv
 *
 * return:void
 */
static void htt_print_rx_pdev_fw_stats_tlv(A_UINT32 *tag_buf)
{
    htt_rx_pdev_fw_stats_tlv *htt_stats_buf =
        (htt_rx_pdev_fw_stats_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                    = 0;
    A_CHAR   *fw_ring_mgmt_subtype = NULL;
    A_CHAR   *fw_ring_ctrl_subtype = NULL;

    fw_ring_ctrl_subtype = (A_CHAR *)malloc(HTT_MAX_STRING_LEN * sizeof(A_CHAR));
    if (!fw_ring_ctrl_subtype) {
        HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
        return;
    }

    fw_ring_mgmt_subtype = (A_CHAR *)malloc(HTT_MAX_STRING_LEN * sizeof(A_CHAR));
    if (!fw_ring_mgmt_subtype) {
       HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
       free(fw_ring_ctrl_subtype);
       return;
    }

    HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_FW_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "ppdu_recvd = %u",
            htt_stats_buf->ppdu_recvd);
    HTT_STATS_PRINT(FATAL, "mpdu_cnt_fcs_ok = %u",
            htt_stats_buf->mpdu_cnt_fcs_ok);
    HTT_STATS_PRINT(FATAL, "mpdu_cnt_fcs_err = %u",
            htt_stats_buf->mpdu_cnt_fcs_err);
    HTT_STATS_PRINT(FATAL, "tcp_msdu_cnt = %u",
            htt_stats_buf->tcp_msdu_cnt);
    HTT_STATS_PRINT(FATAL, "tcp_ack_msdu_cnt = %u",
            htt_stats_buf->tcp_ack_msdu_cnt);
    HTT_STATS_PRINT(FATAL, "udp_msdu_cnt = %u",
            htt_stats_buf->udp_msdu_cnt);
    HTT_STATS_PRINT(FATAL, "other_msdu_cnt = %u",
            htt_stats_buf->other_msdu_cnt);
    HTT_STATS_PRINT(FATAL, "fw_ring_mpdu_ind = %u",
            htt_stats_buf->fw_ring_mpdu_ind);

    for (i = 0; i < HTT_STATS_SUBTYPE_MAX; i++) {
        index += snprintf(&fw_ring_mgmt_subtype[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->fw_ring_mgmt_subtype[i]);
    }

    HTT_STATS_PRINT(FATAL, "fw_ring_mgmt_subtype = %s ", fw_ring_mgmt_subtype);

    index = 0;

    for (i = 0; i < HTT_STATS_SUBTYPE_MAX; i++) {
        index += snprintf(&fw_ring_ctrl_subtype[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->fw_ring_ctrl_subtype[i]);
    }

    HTT_STATS_PRINT(FATAL, "fw_ring_ctrl_subtype = %s ", fw_ring_ctrl_subtype);
    HTT_STATS_PRINT(FATAL, "fw_ring_mcast_data_msdu = %u",
            htt_stats_buf->fw_ring_mcast_data_msdu);
    HTT_STATS_PRINT(FATAL, "fw_ring_bcast_data_msdu = %u",
            htt_stats_buf->fw_ring_bcast_data_msdu);
    HTT_STATS_PRINT(FATAL, "fw_ring_ucast_data_msdu = %u",
            htt_stats_buf->fw_ring_ucast_data_msdu);
    HTT_STATS_PRINT(FATAL, "fw_ring_null_data_msdu = %u",
            htt_stats_buf->fw_ring_null_data_msdu);
    HTT_STATS_PRINT(FATAL, "fw_ring_mpdu_drop = %u",
            htt_stats_buf->fw_ring_mpdu_drop);
    HTT_STATS_PRINT(FATAL, "ofld_local_data_ind_cnt = %u",
            htt_stats_buf->ofld_local_data_ind_cnt);
    HTT_STATS_PRINT(FATAL, "ofld_local_data_buf_recycle_cnt = %u",
            htt_stats_buf->ofld_local_data_buf_recycle_cnt);
    HTT_STATS_PRINT(FATAL, "drx_local_data_ind_cnt = %u",
            htt_stats_buf->drx_local_data_ind_cnt);
    HTT_STATS_PRINT(FATAL, "drx_local_data_buf_recycle_cnt = %u",
            htt_stats_buf->drx_local_data_buf_recycle_cnt);
    HTT_STATS_PRINT(FATAL, "local_nondata_ind_cnt = %u",
            htt_stats_buf->local_nondata_ind_cnt);
    HTT_STATS_PRINT(FATAL, "local_nondata_buf_recycle_cnt = %u",
            htt_stats_buf->local_nondata_buf_recycle_cnt);
    HTT_STATS_PRINT(FATAL, "fw_status_buf_ring_refill_cnt = %u",
            htt_stats_buf->fw_status_buf_ring_refill_cnt);
    HTT_STATS_PRINT(FATAL, "fw_status_buf_ring_empty_cnt = %u",
            htt_stats_buf->fw_status_buf_ring_empty_cnt);
    HTT_STATS_PRINT(FATAL, "fw_pkt_buf_ring_refill_cnt = %u",
            htt_stats_buf->fw_pkt_buf_ring_refill_cnt);
    HTT_STATS_PRINT(FATAL, "fw_pkt_buf_ring_empty_cnt = %u",
            htt_stats_buf->fw_pkt_buf_ring_empty_cnt);
    HTT_STATS_PRINT(FATAL, "fw_link_buf_ring_refill_cnt = %u",
            htt_stats_buf->fw_link_buf_ring_refill_cnt);
    HTT_STATS_PRINT(FATAL, "fw_link_buf_ring_empty_cnt = %u",
            htt_stats_buf->fw_link_buf_ring_empty_cnt);
    HTT_STATS_PRINT(FATAL, "host_pkt_buf_ring_refill_cnt = %u",
            htt_stats_buf->host_pkt_buf_ring_refill_cnt);
    HTT_STATS_PRINT(FATAL, "host_pkt_buf_ring_empty_cnt = %u",
            htt_stats_buf->host_pkt_buf_ring_empty_cnt);
    HTT_STATS_PRINT(FATAL, "mon_pkt_buf_ring_refill_cnt = %u",
            htt_stats_buf->mon_pkt_buf_ring_refill_cnt);
    HTT_STATS_PRINT(FATAL, "mon_pkt_buf_ring_empty_cnt = %u",
            htt_stats_buf->mon_pkt_buf_ring_empty_cnt);
    HTT_STATS_PRINT(FATAL, "mon_status_buf_ring_refill_cnt = %u",
            htt_stats_buf->mon_status_buf_ring_refill_cnt);
    HTT_STATS_PRINT(FATAL, "mon_status_buf_ring_empty_cnt = %u",
            htt_stats_buf->mon_status_buf_ring_empty_cnt);
    HTT_STATS_PRINT(FATAL, "mon_desc_buf_ring_refill_cnt = %u",
            htt_stats_buf->mon_desc_buf_ring_refill_cnt);
    HTT_STATS_PRINT(FATAL, "mon_desc_buf_ring_empty_cnt = %u",
            htt_stats_buf->mon_desc_buf_ring_empty_cnt);
    HTT_STATS_PRINT(FATAL, "mon_dest_ring_update_cnt = %u",
            htt_stats_buf->mon_dest_ring_update_cnt);
    HTT_STATS_PRINT(FATAL, "mon_dest_ring_full_cnt = %u",
            htt_stats_buf->mon_dest_ring_full_cnt);
    HTT_STATS_PRINT(FATAL, "rx_suspend_cnt = %u",
            htt_stats_buf->rx_suspend_cnt);
    HTT_STATS_PRINT(FATAL, "rx_suspend_fail_cnt = %u",
            htt_stats_buf->rx_suspend_fail_cnt);
    HTT_STATS_PRINT(FATAL, "rx_resume_cnt = %u",
            htt_stats_buf->rx_resume_cnt);
    HTT_STATS_PRINT(FATAL, "rx_resume_fail_cnt = %u",
            htt_stats_buf->rx_resume_fail_cnt);
    HTT_STATS_PRINT(FATAL, "rx_ring_switch_cnt = %u",
            htt_stats_buf->rx_ring_switch_cnt);
    HTT_STATS_PRINT(FATAL, "rx_ring_restore_cnt = %u",
            htt_stats_buf->rx_ring_restore_cnt);
    HTT_STATS_PRINT(FATAL, "rx_flush_cnt = %u",
            htt_stats_buf->rx_flush_cnt);
    HTT_STATS_PRINT(FATAL, "rx_recovery_reset_cnt = %u\n",
            htt_stats_buf->rx_recovery_reset_cnt);

    free(fw_ring_mgmt_subtype);
    free(fw_ring_ctrl_subtype);
}

/*
 * htt_print_rx_pdev_fw_ring_mpdu_err_tlv_v: display
 *                htt_rx_pdev_fw_ring_mpdu_err_tlv_v
 * @tag_buf: buffer containing the tlv htt_rx_pdev_fw_ring_mpdu_err_tlv_v
 *
 * return:void
 */
static void htt_print_rx_pdev_fw_ring_mpdu_err_tlv_v(A_UINT32 *tag_buf)
{
    htt_rx_pdev_fw_ring_mpdu_err_tlv_v *htt_stats_buf =
        (htt_rx_pdev_fw_ring_mpdu_err_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                                = 0;
    A_CHAR   fw_ring_mpdu_err[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_FW_RING_MPDU_ERR_TLV_V:");

    for (i = 0; i < HTT_RX_STATS_RXDMA_MAX_ERR; i++) {
        index += snprintf(&fw_ring_mpdu_err[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i,
                htt_stats_buf->fw_ring_mpdu_err[i]);
    }

    HTT_STATS_PRINT(FATAL, "fw_ring_mpdu_err = %s\n", fw_ring_mpdu_err);
}

/*
 * htt_print_rx_pdev_fw_mpdu_drop_tlv_v: display htt_rx_pdev_fw_mpdu_drop_tlv_v
 * @tag_buf: buffer containing the tlv htt_rx_pdev_fw_mpdu_drop_tlv_v
 *
 * return:void
 */
static void htt_print_rx_pdev_fw_mpdu_drop_tlv_v(A_UINT32 *tag_buf)
{
    htt_rx_pdev_fw_mpdu_drop_tlv_v *htt_stats_buf =
        (htt_rx_pdev_fw_mpdu_drop_tlv_v *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                            = 0;
    A_CHAR   fw_mpdu_drop[HTT_MAX_STRING_LEN] = {0};
    A_UINT32 tag_len                          = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_FW_MPDU_DROP_TLV_V:");

    for (i = 0; i < tag_len; i++) {
        index += snprintf(&fw_mpdu_drop[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->fw_mpdu_drop[i]);
    }

    HTT_STATS_PRINT(FATAL, "fw_mpdu_drop = %s\n", fw_mpdu_drop);
}

/*
 * htt_print_rx_pdev_fw_stats_phy_err_tlv: display htt_rx_pdev_fw_stats_phy_err_tlv
 * @tag_buf: buffer containing the tlv htt_rx_pdev_fw_stats_phy_err_tlv
 *
 * return:void
 */
static void htt_print_rx_pdev_fw_stats_phy_err_tlv(A_UINT32 *tag_buf)
{
    htt_rx_pdev_fw_stats_phy_err_tlv *htt_stats_buf =
        (htt_rx_pdev_fw_stats_phy_err_tlv *)tag_buf;
    A_UINT8  i;
    A_UINT16 index                        = 0;
    A_CHAR   phy_errs[HTT_MAX_STRING_LEN] = {0};

    HTT_STATS_PRINT(FATAL, "HTT_RX_PDEV_FW_STATS_PHY_ERR_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id__word = %u",
            htt_stats_buf->mac_id__word);
    HTT_STATS_PRINT(FATAL, "tota_phy_err_nct = %u",
            htt_stats_buf->total_phy_err_cnt);

    for (i = 0; i < HTT_STATS_PHY_ERR_MAX; i++) {
        index += snprintf(&phy_errs[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->phy_err[i]);
    }

    HTT_STATS_PRINT(FATAL, "phy_errs = %s\n", phy_errs);
}

/*
 * htt_print_pdev_cca_stats_hist_tlv: display htt_pdev_cca_stats_hist_v1_tlv
 * @tag_buf: buffer containing the tlv htt_pdev_cca_stats_hist_v1_tlv
 *
 * return:void
 */
static void htt_print_pdev_cca_stats_hist_tlv(A_UINT32 *tag_buf)
{
    htt_pdev_cca_stats_hist_v1_tlv *htt_stats_buf =
        (htt_pdev_cca_stats_hist_v1_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "\nHTT_PDEV_CCA_STATS_HIST_TLV:");
    HTT_STATS_PRINT(FATAL, "chan_num = %u",
            htt_stats_buf->chan_num);
    HTT_STATS_PRINT(FATAL, "num_records = %u",
            htt_stats_buf->num_records);
    HTT_STATS_PRINT(FATAL, "valid_cca_counters_bitmap = 0x%x",
            htt_stats_buf->valid_cca_counters_bitmap);
    HTT_STATS_PRINT(FATAL, "collection_interval = %u\n",
            htt_stats_buf->collection_interval);

    HTT_STATS_PRINT(FATAL, "HTT_PDEV_STATS_CCA_COUNTERS_TLV:(in usec)");
    HTT_STATS_PRINT(FATAL,
            "|  tx_frame|   rx_frame|   rx_clear| my_rx_frame|        cnt| med_rx_idle| med_tx_idle_global|   cca_obss|");
}

/*
 * htt_print_pdev_stats_cca_counters_tlv: display htt_pdev_stats_cca_counters_tlv
 * @tag_buf: buffer containing the tlv htt_pdev_stats_cca_counters_tlv
 *
 * return:void
 */
static void htt_print_pdev_stats_cca_counters_tlv(A_UINT32 *tag_buf)
{
    htt_pdev_stats_cca_counters_tlv *htt_stats_buf =
        (htt_pdev_stats_cca_counters_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "|%10u| %10u| %10u| %11u| %10u| %11u| %18u| %10u|",
            htt_stats_buf->tx_frame_usec, htt_stats_buf->rx_frame_usec, htt_stats_buf->rx_clear_usec,
            htt_stats_buf->my_rx_frame_usec, htt_stats_buf->usec_cnt, htt_stats_buf->med_rx_idle_usec,
            htt_stats_buf->med_tx_idle_global_usec, htt_stats_buf->cca_obss_usec);
}

/*
 * htt_print_hw_stats_whal_tx_tlv: display htt_hw_stats_whal_tx_tlv
 * @tag_buf: buffer containing the tlv htt_hw_stats_pdev_errs_tlv
 *
 * return:void
 */
static void htt_print_hw_stats_whal_tx_tlv(A_UINT32 *tag_buf)
{
    htt_hw_stats_whal_tx_tlv *htt_stats_buf =
        (htt_hw_stats_whal_tx_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_HW_STATS_WHAL_TX_TLV:");
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);
    /*HTT_STATS_PRINT(FATAL, "word = %u",
            ((htt_stats_buf->mac_id__word & 0xFFFFFF00) >> 8 ));*/
    HTT_STATS_PRINT(FATAL, "last_unpause_ppdu_id = %u",
            htt_stats_buf->last_unpause_ppdu_id);
    HTT_STATS_PRINT(FATAL, "hwsch_unpause_wait_tqm_write = %u",
            htt_stats_buf->hwsch_unpause_wait_tqm_write);
    HTT_STATS_PRINT(FATAL, "hwsch_dummy_tlv_skipped = %u",
            htt_stats_buf->hwsch_dummy_tlv_skipped);
    HTT_STATS_PRINT(FATAL, "hwsch_misaligned_offset_received = %u",
            htt_stats_buf->hwsch_misaligned_offset_received);
    HTT_STATS_PRINT(FATAL, "hwsch_reset_count = %u",
            htt_stats_buf->hwsch_reset_count);
    HTT_STATS_PRINT(FATAL, "hwsch_dev_reset_war = %u",
            htt_stats_buf->hwsch_dev_reset_war);
    HTT_STATS_PRINT(FATAL, "hwsch_delayed_pause = %u",
            htt_stats_buf->hwsch_delayed_pause);
    HTT_STATS_PRINT(FATAL, "hwsch_long_delayed_pause = %u",
            htt_stats_buf->hwsch_long_delayed_pause);
    HTT_STATS_PRINT(FATAL, "sch_rx_ppdu_no_response = %u",
            htt_stats_buf->sch_rx_ppdu_no_response);
    HTT_STATS_PRINT(FATAL, "sch_selfgen_response = %u",
            htt_stats_buf->sch_selfgen_response);
    HTT_STATS_PRINT(FATAL, "sch_rx_sifs_resp_trigger= %u\n",
            htt_stats_buf->sch_rx_sifs_resp_trigger);
}

/*
 * htt_print_pdev_stats_twt_sessions_tlv: display htt_pdev_stats_twt_sessions_tlv
 * @tag_buf: buffer containing the tlv htt_pdev_stats_twt_sessions_tlv
 *
 * return:void
 */
static void htt_print_pdev_stats_twt_sessions_tlv(A_UINT32 *tag_buf)
{
    htt_pdev_stats_twt_sessions_tlv *htt_stats_buf =
        (htt_pdev_stats_twt_sessions_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_PDEV_STATS_TWT_SESSIONS_TLV:");
    HTT_STATS_PRINT(FATAL, "pdev_id = %u",
            htt_stats_buf->pdev_id);
    HTT_STATS_PRINT(FATAL, "num_sessions = %u\n",
            htt_stats_buf->num_sessions);
}

/*
 * htt_print_pdev_stats_twt_session_tlv: display htt_pdev_stats_twt_session_tlv
 * @tag_buf: buffer containing the tlv htt_pdev_stats_twt_session_tlv
 *
 * return:void
 */
static void htt_print_pdev_stats_twt_session_tlv(A_UINT32 *tag_buf)
{
    htt_pdev_stats_twt_session_tlv *htt_stats_buf =
        (htt_pdev_stats_twt_session_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_PDEV_STATS_TWT_SESSION_TLV:");
    HTT_STATS_PRINT(FATAL, "vdev_id = %u",
            htt_stats_buf->vdev_id);
    HTT_STATS_PRINT(FATAL, "peer_mac = %02x:%02x:%02x:%02x:%02x:%02x",
            htt_stats_buf->peer_mac.mac_addr31to0 & 0xFF,
            (htt_stats_buf->peer_mac.mac_addr31to0 & 0xFF00) >> 8,
            (htt_stats_buf->peer_mac.mac_addr31to0 & 0xFF0000) >> 16,
            (htt_stats_buf->peer_mac.mac_addr31to0 & 0xFF000000) >> 24,
            (htt_stats_buf->peer_mac.mac_addr47to32 & 0xFF),
            (htt_stats_buf->peer_mac.mac_addr47to32 & 0xFF00) >> 8);
    HTT_STATS_PRINT(FATAL, "flow_id_flags = %u",
            htt_stats_buf->flow_id_flags);
    HTT_STATS_PRINT(FATAL, "dialog_id = %u",
            htt_stats_buf->dialog_id);
    HTT_STATS_PRINT(FATAL, "wake_dura_us = %u",
            htt_stats_buf->wake_dura_us);
    HTT_STATS_PRINT(FATAL, "wake_intvl_us = %u",
            htt_stats_buf->wake_intvl_us);
    HTT_STATS_PRINT(FATAL, "sp_offset_us = %u\n",
            htt_stats_buf->sp_offset_us);
}

/*
 * htt_print_hw_war_tlv_v: display htt_hw_war_stats_tlv_v
 * @tag_buf: buffer containing the tlv htt_hw_war_stats_tlv
 *
 * return:void
 */
static void htt_print_hw_war_tlv_v(A_UINT32 *tag_buf)
{
    htt_hw_war_stats_tlv *htt_stats_buf =
        (htt_hw_war_stats_tlv *)tag_buf;

    A_UINT8  i;
    A_UINT32 tag_words = (HTT_STATS_TLV_LENGTH_GET(*tag_buf) >> 2);

    HTT_STATS_PRINT(FATAL, "HTT_HW_WAR_STATS_TLV:");

    tag_words--; /* first word beyond TLV header is for mac_id */
    HTT_STATS_PRINT(FATAL, "mac_id = %u",
            htt_stats_buf->mac_id__word & 0xFF);

    for (i = 0; i < tag_words; i++) {
        HTT_STATS_PRINT(FATAL, "hw_war %u = %u\n",
                i, htt_stats_buf->hw_wars[i]);
    }
}

/*
 * htt_pdev_obss_pd_stats_tlv: display htt_pdev_obss_pd_stats
 * @tag_buf: buffer containing the tlv htt_pdev_obss_pd_stats_tlv
 *
 * return:void
 */
static void htt_print_pdev_obss_pd_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_pdev_obss_pd_stats_tlv *htt_stats_buf =
        (htt_pdev_obss_pd_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_PDEV_OBSS_PD_STATS_TLV:");
    /*
     * Successful/Failure OBSS Transmission stats are commented out as they
     * are not supported in the current chipsets.
     * Based on MAC team suggestion, the stats will be supported in future.
     */
    #if 0
    HTT_STATS_PRINT(FATAL, "OBSS Tx success PPDU = %u",
            htt_stats_buf->num_obss_tx_ppdu_success);
    HTT_STATS_PRINT(FATAL, "OBSS Tx failures PPDU = %u\n",
            htt_stats_buf->num_obss_tx_ppdu_failure);
    #endif
    HTT_STATS_PRINT(FATAL, "num_spatial_reuse_tx = %u",
            htt_stats_buf->num_sr_tx_transmissions);
    HTT_STATS_PRINT(FATAL, "num_spatial_reuse_opportunities = %u",
            htt_stats_buf->num_spatial_reuse_opportunities);

    HTT_STATS_PRINT(FATAL, "num_non_srg_opportunities = %u",
            htt_stats_buf->num_non_srg_opportunities);
    HTT_STATS_PRINT(FATAL, "num_non_srg_ppdu_tried = %u",
            htt_stats_buf->num_non_srg_ppdu_tried);
    HTT_STATS_PRINT(FATAL, "num_non_srg_ppdu_success = %u",
            htt_stats_buf->num_non_srg_ppdu_success);

    HTT_STATS_PRINT(FATAL, "num_srg_opportunities = %u",
            htt_stats_buf->num_srg_opportunities);
    HTT_STATS_PRINT(FATAL, "num_srg_ppdu_tried = %u",
            htt_stats_buf->num_srg_ppdu_tried);
    HTT_STATS_PRINT(FATAL, "num_srg_ppdu_success = %u",
            htt_stats_buf->num_srg_ppdu_success);

    HTT_STATS_PRINT(FATAL, "num_psr_opportunities = %u",
            htt_stats_buf->num_psr_opportunities);
    HTT_STATS_PRINT(FATAL, "num_psr_ppdu_tried = %u",
            htt_stats_buf->num_psr_ppdu_tried);
    HTT_STATS_PRINT(FATAL, "num_psr_ppdu_success = %u\n",
            htt_stats_buf->num_psr_ppdu_success);
}

static void htt_print_soc_latency_prof_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_latency_prof_stats_tlv *htt_stats_buf =
        (htt_latency_prof_stats_tlv *) tag_buf;
    A_CHAR latency_prof_stat_name[HTT_STATS_MAX_PROF_STATS_NAME_LEN + 1] = {0};
    int page_fault_avg = 0;

    if (htt_stats_buf->print_header == 1) {
        HTT_STATS_PRINT(FATAL, "HTT_STATS_LATENCY_PROF_TLV:");
        HTT_STATS_PRINT(FATAL,
            "|%-32s|%8s|%8s|%8s|%8s|%8s|%8s|%15s|%26s|%8s|%8s|%8s|%10s|%14s|%5s|",
            "prof_name", "cnt","min", "max","last","tot",
            "avg",  "hist_intvl", "hist", "pf_max",
            "pf_avg", "pf_tot" ,"ignoredCnt", "intHist", "intMax");
    }
    if (htt_stats_buf->cnt) {
        page_fault_avg = htt_stats_buf->page_fault_total/htt_stats_buf->cnt;
    }

    memcpy(
        latency_prof_stat_name,
        &(htt_stats_buf->latency_prof_name[0]),
        HTT_STATS_MAX_PROF_STATS_NAME_LEN);
    HTT_STATS_PRINT(FATAL,
        "|%-32s|%8u|%8u|%8u|%8u|%8u|%8u|%15u|%8u:%8u:%8u|%8u|%8u|%8u|%10u|%4u:%4u:%4u|%5u|",
        latency_prof_stat_name, htt_stats_buf->cnt, htt_stats_buf->min,
        htt_stats_buf->max, htt_stats_buf->last, htt_stats_buf->tot,
        htt_stats_buf->avg, htt_stats_buf->hist_intvl,
        htt_stats_buf->hist[0], htt_stats_buf->hist[1], htt_stats_buf->hist[2],
        htt_stats_buf->page_fault_max, page_fault_avg, htt_stats_buf->page_fault_total,
        htt_stats_buf->ignored_latency_count, htt_stats_buf->interrupts_hist[0],
        htt_stats_buf->interrupts_hist[1], htt_stats_buf->interrupts_hist[2],
        htt_stats_buf->interrupts_max);
}

static void htt_print_soc_latency_prof_ctx_tlv(A_UINT32 *tag_buf)
{
    htt_latency_prof_ctx_tlv *htt_stats_buf =
        (htt_latency_prof_ctx_tlv *) tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_STATS_LATENCY_CTX_TLV:");
    HTT_STATS_PRINT(FATAL, "duration= %u", htt_stats_buf->duration);
    HTT_STATS_PRINT(FATAL, "tx_msdu_cnt = %u", htt_stats_buf->tx_msdu_cnt);
    HTT_STATS_PRINT(FATAL, "tx_mpdu_cnt = %u", htt_stats_buf->tx_mpdu_cnt);
    HTT_STATS_PRINT(FATAL, "rx_msdu_cnt = %u", htt_stats_buf->rx_msdu_cnt);
    HTT_STATS_PRINT(FATAL, "rx_mpdu_cnt = %u", htt_stats_buf->rx_mpdu_cnt);
}

static void htt_print_latency_prof_cnt(A_UINT32 *tag_buf)
{
    htt_latency_prof_cnt_tlv *htt_stats_buf =
        (htt_latency_prof_cnt_tlv *)tag_buf;
    HTT_STATS_PRINT(FATAL,
        "prof_enable_cnt = %u", htt_stats_buf->prof_enable_cnt);
}

/*
 * htt_ring_backpressure_stats_tlv : display htt_ring_backpressure_stats
 * @tag_buf: buffer containing the tlv htt_ring_backpressure_stats_tlv
 *
 * return:void
 */
static void
htt_print_pdev_ring_backpressure_stats_tlv_v(A_UINT32 *tag_buf)
{
    htt_ring_backpressure_stats_tlv *htt_stats_buf =
        (htt_ring_backpressure_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "pdev_id = %u\n",
            htt_stats_buf->pdev_id);
    HTT_STATS_PRINT(FATAL, "Head index = %u\n",
            htt_stats_buf->current_head_idx);
    HTT_STATS_PRINT(FATAL, "Tail index = %u\n",
            htt_stats_buf->current_tail_idx);
    HTT_STATS_PRINT(FATAL, "Num Backpressure Msgs Sent = %u\n",
            htt_stats_buf->num_htt_msgs_sent);
    HTT_STATS_PRINT(FATAL, "Current Backpressure Time in Milliseconds = %u\n",
            htt_stats_buf->backpressure_time_ms);
    HTT_STATS_PRINT(FATAL, "Ring Backpressure Histogram \n");
    HTT_STATS_PRINT(FATAL,
            "100ms to 200ms = %u, 200ms to 300ms = %u, 300ms to 400ms = %u\n",
            htt_stats_buf->backpressure_hist[0],
            htt_stats_buf->backpressure_hist[1],
            htt_stats_buf->backpressure_hist[2]);
    HTT_STATS_PRINT(FATAL,
            "400ms to 500 ms = %u, Above 500ms = %u\n",
            htt_stats_buf->backpressure_hist[3],
            htt_stats_buf->backpressure_hist[4]);
}

static void htt_print_rx_fse_stats_tlv(A_UINT32 *tag_buf)
{
    htt_rx_fse_stats_tlv *htt_stats_buf =
        (htt_rx_fse_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_STATS_RX_FSE_STATS_TLV: \n");

    HTT_STATS_PRINT(FATAL, "=== Software RX FSE STATS ===\n");
    HTT_STATS_PRINT(FATAL,
            "Enable count  = %u", htt_stats_buf->fse_enable_cnt);
    HTT_STATS_PRINT(FATAL,
            "Disable count = %u\n", htt_stats_buf->fse_disable_cnt);

    HTT_STATS_PRINT(FATAL,
            "Cache Invalidate Entry Count   = %u\n",
            htt_stats_buf->fse_cache_invalidate_entry_cnt);
    HTT_STATS_PRINT(FATAL,
            "Full Cache Invalidate Count    = %u\n",
            htt_stats_buf->fse_full_cache_invalidate_cnt);

    HTT_STATS_PRINT(FATAL, "=== Hardware RX FSE STATS ===\n");
    HTT_STATS_PRINT(FATAL, "Cache hits Count = %u\n",
            htt_stats_buf->fse_num_cache_hits_cnt);
    HTT_STATS_PRINT(FATAL, "Cache No. of searches = %u\n",
            htt_stats_buf->fse_num_searches_cnt);
    HTT_STATS_PRINT(FATAL, "Cache occupancy Peak Count: \n");
    HTT_STATS_PRINT(FATAL,
             " [0] = %u [1-16] = %u [17-32] = %u "
             "[33-48] = %u [49-64] = %u [65-80] = %u "
             "[81-96] = %u [97-112] = %u [113-127] = %u "
             "[128] = %u\n",
             htt_stats_buf->fse_cache_occupancy_peak_cnt[0],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[1],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[2],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[3],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[4],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[5],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[6],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[7],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[8],
             htt_stats_buf->fse_cache_occupancy_peak_cnt[9]);
    HTT_STATS_PRINT(FATAL, "Cache occupancy Current Count: \n");
    HTT_STATS_PRINT(FATAL,
             " [0] = %u [1-16] = %u [17-32] = %u "
             "[33-48] = %u [49-64] = %u [65-80] = %u "
             "[81-96] = %u [97-112] = %u [113-127] = %u "
             "[128] = %u\n",
             htt_stats_buf->fse_cache_occupancy_curr_cnt[0],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[1],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[2],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[3],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[4],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[5],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[6],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[7],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[8],
             htt_stats_buf->fse_cache_occupancy_curr_cnt[9]);
    HTT_STATS_PRINT(FATAL, "Cache search Square Count: \n");
    HTT_STATS_PRINT(FATAL,
             " [0] = %u [1-50] = %u [51-100] = %u "
             "[101-200] = %u [201-255] = %u [256] = %u \n",
             htt_stats_buf->fse_search_stat_square_cnt[0],
             htt_stats_buf->fse_search_stat_square_cnt[1],
             htt_stats_buf->fse_search_stat_square_cnt[2],
             htt_stats_buf->fse_search_stat_square_cnt[3],
             htt_stats_buf->fse_search_stat_square_cnt[4],
             htt_stats_buf->fse_search_stat_square_cnt[5]);

    HTT_STATS_PRINT(FATAL, "Cache search Peak Pending Count:  \n");
    HTT_STATS_PRINT(FATAL,
             " [0] = %u [1-2] = %u [3-4] = %u "
             "[Greater/Equal to 5] = %u \n",
             htt_stats_buf->fse_search_stat_peak_cnt[0],
             htt_stats_buf->fse_search_stat_peak_cnt[1],
             htt_stats_buf->fse_search_stat_peak_cnt[2],
             htt_stats_buf->fse_search_stat_peak_cnt[3]);
    HTT_STATS_PRINT(FATAL, "Cache search Number of Pending Count: \n");
    HTT_STATS_PRINT(FATAL,
             "[0] = %u [1-2] = %u [3-4] = %u "
             "[Greater/Equal to 5] = %u \n",
             htt_stats_buf->fse_search_stat_search_pending_cnt[0],
             htt_stats_buf->fse_search_stat_search_pending_cnt[1],
             htt_stats_buf->fse_search_stat_search_pending_cnt[2],
             htt_stats_buf->fse_search_stat_search_pending_cnt[3]);
}

/*
 * htt_print_peer_sched_stats: display htt_peer_sched_stats_tlv
 * @tag_buf: buffer containing the tlv htt_peer_sched_stats_tlv
 *
 * return:void
 */
static void htt_print_peer_sched_stats(A_UINT32 *tag_buf)
{
    htt_peer_sched_stats_tlv *htt_stats_buf =
        (htt_peer_sched_stats_tlv *)tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_PEER_SCHED_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "peer_id = %u",
            htt_stats_buf->peer_id);
    HTT_STATS_PRINT(FATAL, "num_sched_dl = %u",
            htt_stats_buf->num_sched_dl);
    HTT_STATS_PRINT(FATAL, "num_sched_ul = %u",
            htt_stats_buf->num_sched_ul);
#ifdef __KERNEL__
    HTT_STATS_PRINT(FATAL, "peer_tx_active_dur_ms = %llu",
                    qdf_do_div((htt_stats_buf->peer_tx_active_dur_us_low |
                    ((unsigned long long)htt_stats_buf->peer_tx_active_dur_us_high << 32)),
                    1000));
    HTT_STATS_PRINT(FATAL, "peer_rx_active_dur_ms = %llu",
                    qdf_do_div((htt_stats_buf->peer_rx_active_dur_us_low |
                    ((unsigned long long)htt_stats_buf->peer_rx_active_dur_us_high << 32)),
                    1000));
#else
    HTT_STATS_PRINT(FATAL, "peer_tx_active_dur_ms = %llu",
                    ((htt_stats_buf->peer_tx_active_dur_us_low |
                    ((unsigned long long)htt_stats_buf->peer_tx_active_dur_us_high << 32)) /
                    1000));
    HTT_STATS_PRINT(FATAL, "peer_rx_active_dur_ms = %llu",
                    ((htt_stats_buf->peer_rx_active_dur_us_low |
                    ((unsigned long long)htt_stats_buf->peer_rx_active_dur_us_high << 32)) /
                    1000));
#endif
    HTT_STATS_PRINT(FATAL, "peer_curr_rate_kbps = %u\n",
            htt_stats_buf->peer_curr_rate_kbps);
}

/*
 * htt_print_sta_ul_ofdma_stats: display htt_sta_ul_ofdma_stats_tlv values
 * @tag_buf: buffer containing the tlv htt_sta_ul_ofdma_stats_tlv
 *
 * return:void
 */

static void htt_print_sta_ul_ofdma_stats_tlv(A_UINT32 *tag_buf)
{
    A_UINT32 i, j;
    A_UINT16 index;
    char str_buf[HTT_MAX_STRING_LEN] = {0};

    htt_sta_ul_ofdma_stats_tlv *htt_stats_buf =
              (htt_sta_ul_ofdma_stats_tlv *) tag_buf;

    HTT_STATS_PRINT(FATAL, "==============STA UL OFDMA STATS================\n");

    HTT_STATS_PRINT(FATAL, "pdev ID = %d ", htt_stats_buf->pdev_id);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

    for (i = 0; i < HTT_STA_UL_OFDMA_NUM_TRIG_TYPE; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->rx_trigger_type[i]);
    }
    HTT_STATS_PRINT(FATAL, "STA HW Trigger Type = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    snprintf(str_buf, HTT_MAX_STRING_LEN - index,
              " BASIC:%u, BRPOLL:%u, MUBAR:%u, MURTS:%u BSRP:%u Others:%u",
              htt_stats_buf->ax_trigger_type[0],
              htt_stats_buf->ax_trigger_type[1],
              htt_stats_buf->ax_trigger_type[2],
              htt_stats_buf->ax_trigger_type[3],
              htt_stats_buf->ax_trigger_type[4],
              htt_stats_buf->ax_trigger_type[5]);
    HTT_STATS_PRINT(FATAL, "11ax Trigger Type = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    snprintf(str_buf, HTT_MAX_STRING_LEN - index,
              " HIPRI:%u, LOWPRI:%u, BSR:%u",
              htt_stats_buf->num_data_ppdu_responded_per_hwq[0],
              htt_stats_buf->num_data_ppdu_responded_per_hwq[1],
              htt_stats_buf->num_data_ppdu_responded_per_hwq[2]);
    HTT_STATS_PRINT(FATAL, "Data PPDU Resp per HWQ = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    snprintf(str_buf, HTT_MAX_STRING_LEN - index,
              " HIPRI:%u, LOWPRI:%u, BSR:%u",
              htt_stats_buf->num_null_delimiters_responded_per_hwq[0],
              htt_stats_buf->num_null_delimiters_responded_per_hwq[1],
              htt_stats_buf->num_null_delimiters_responded_per_hwq[2]);
    HTT_STATS_PRINT(FATAL, "Null Delim Resp per HWQ = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    snprintf(str_buf, HTT_MAX_STRING_LEN - index,
              " Data:%u, NullDelim:%u",
              htt_stats_buf->num_total_trig_responses[0],
              htt_stats_buf->num_total_trig_responses[1]);
    HTT_STATS_PRINT(FATAL, "Trigger Resp Status = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "Last Trigger RX Time Interval = %u \n", htt_stats_buf->last_trig_rx_time_delta_ms);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_STA_UL_OFDMA_NUM_MCS_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ul_ofdma_tx_mcs[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_tx_mcs = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_TX_PDEV_STATS_NUM_SPATIAL_STREAMS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ul_ofdma_tx_nss[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_tx_nss = %s ", str_buf);

    for (j = 0; j < HTT_TX_PDEV_STATS_NUM_GI_COUNTERS; j++) {
        index = 0;
        memset(str_buf, 0x0, HTT_MAX_STRING_LEN);

        for (i = 0; i < HTT_STA_UL_OFDMA_NUM_MCS_COUNTERS; i++) {
            index += snprintf(&str_buf[index],
                    HTT_MAX_STRING_LEN - index,
                    " %u:%u,", i,
                    htt_stats_buf->ul_ofdma_tx_gi[j][i]);
        }
        HTT_STATS_PRINT(FATAL, "ul_ofdma_tx_gi[%u] = %s ", j, str_buf);
    }

    HTT_STATS_PRINT(FATAL, "ul_ofdma_tx_ldpc = %u ", htt_stats_buf->ul_ofdma_tx_ldpc);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_STA_UL_OFDMA_NUM_BW_COUNTERS; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->ul_ofdma_tx_bw[i]);
    }
    HTT_STATS_PRINT(FATAL, "ul_ofdma_tx_bw = %s \n", str_buf);

    HTT_STATS_PRINT(FATAL, "Trig Based Tx PPDU = %u ", htt_stats_buf->trig_based_ppdu_tx);
    HTT_STATS_PRINT(FATAL, "RBO Based Tx PPDU = %u ", htt_stats_buf->rbo_based_ppdu_tx);
    HTT_STATS_PRINT(FATAL, "MU to SU EDCA Switch Count = %u ", htt_stats_buf->mu_edca_to_su_edca_switch_count);
    HTT_STATS_PRINT(FATAL, "MU EDCA Params Apply Count = %u \n", htt_stats_buf->num_mu_edca_param_apply_count);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_NUM_AC_WMM; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->current_edca_hwq_mode[i]);
    }
    HTT_STATS_PRINT(FATAL, "current_edca_hwq_mode[AC] = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_NUM_AC_WMM; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->current_cw_min[i]);
    }
    HTT_STATS_PRINT(FATAL, "current_cw_min = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_NUM_AC_WMM; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->current_cw_max[i]);
    }
    HTT_STATS_PRINT(FATAL, "current_cw_max = %s ", str_buf);

    index = 0;
    memset(str_buf, 0x0, HTT_MAX_STRING_LEN);
    for (i = 0; i < HTT_NUM_AC_WMM; i++) {
        index += snprintf(&str_buf[index],
                HTT_MAX_STRING_LEN - index,
                " %u:%u,", i, htt_stats_buf->current_aifs[i]);
    }
    HTT_STATS_PRINT(FATAL, "current_aifs = %s ", str_buf);

    HTT_STATS_PRINT(FATAL, "=========================================== \n");
}

/*
 * htt_print_vdev_rtt_resp_stats_tlv: display htt_vdev_rtt_resp_stats_tlv values
 * @tag_buf: buffer containing the tlv htt_vdev_rtt_resp_stats_tlv
 *
 * return:void
 */
static void htt_print_vdev_rtt_resp_stats_tlv(A_UINT32 *tag_buf)
{

    htt_vdev_rtt_resp_stats_tlv *htt_vdev_rtt_resp_stats_buf =
              (htt_vdev_rtt_resp_stats_tlv *) tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_VDEV_RTT_RESP_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "tx_ftm_suc = %u",
            htt_vdev_rtt_resp_stats_buf->tx_ftm_suc);
    HTT_STATS_PRINT(FATAL, "tx_ftm_suc_retry = %u",
            htt_vdev_rtt_resp_stats_buf->tx_ftm_suc_retry);
    HTT_STATS_PRINT(FATAL, "tx_ftm_fail = %u",
            htt_vdev_rtt_resp_stats_buf->tx_ftm_fail);
    HTT_STATS_PRINT(FATAL, "rx_ftmr_cnt = %u",
            htt_vdev_rtt_resp_stats_buf->rx_ftmr_cnt);
    HTT_STATS_PRINT(FATAL, "rx_ftmr_dup_cnt = %u",
            htt_vdev_rtt_resp_stats_buf->rx_ftmr_dup_cnt);
    HTT_STATS_PRINT(FATAL, "rx_iftmr_cnt = %u",
            htt_vdev_rtt_resp_stats_buf->rx_iftmr_cnt);
    HTT_STATS_PRINT(FATAL, "rx_iftmr_dup_cnt = %u",
            htt_vdev_rtt_resp_stats_buf->rx_iftmr_dup_cnt);

    HTT_STATS_PRINT(FATAL, "=========================================== \n");
}

static void htt_print_dlpager_stats(A_UINT32 *tag_buf)
{
    A_UINT32 idx;
    htt_dlpager_stats_t *htt_stats_buf =
        (htt_dlpager_stats_t *) tag_buf;
    htt_dl_pager_stats_tlv *dl_pager_stats = (htt_dl_pager_stats_tlv *) &htt_stats_buf->dl_pager_stats;
    HTT_STATS_PRINT(FATAL, "HTT_DLPAGER_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "=========================================== \n");
    HTT_STATS_PRINT(FATAL, "ASYNC locked pages = %u", HTT_DLPAGER_ASYNC_LOCK_PAGE_COUNT_GET(dl_pager_stats->msg_dword_1));
    HTT_STATS_PRINT(FATAL, "SYNC locked pages = %u", HTT_DLPAGER_SYNC_LOCK_PAGE_COUNT_GET(dl_pager_stats->msg_dword_1));
    HTT_STATS_PRINT(FATAL, "Total locked pages = %u", HTT_DLPAGER_TOTAL_LOCKED_PAGES_GET(dl_pager_stats->msg_dword_2));
    HTT_STATS_PRINT(FATAL, "Total free pages = %u", HTT_DLPAGER_TOTAL_FREE_PAGES_GET(dl_pager_stats->msg_dword_2));
    HTT_STATS_PRINT(FATAL, "=========================================== \n");
    HTT_STATS_PRINT(FATAL, "LOCKED PAGES HISTORY");
    HTT_STATS_PRINT(FATAL, "=========================================== \n");
    HTT_STATS_PRINT(FATAL, "last_locked_page_idx = %u", (HTT_DLPAGER_LAST_LOCKED_PAGE_IDX_GET(dl_pager_stats->msg_dword_3)) ? \
                            (HTT_DLPAGER_LAST_LOCKED_PAGE_IDX_GET(dl_pager_stats->msg_dword_3) - 1) : (HTT_DLPAGER_STATS_MAX_HIST-1));
    for (idx = 0; idx < HTT_DLPAGER_STATS_MAX_HIST; idx++) {
        HTT_STATS_PRINT(FATAL, "Index - %u : Page Number - %u : Num of pages - %u : Timestamp - %llu us",
                idx,
                dl_pager_stats->last_pages_info[HTT_STATS_PAGE_LOCKED][idx].page_num,
                dl_pager_stats->last_pages_info[HTT_STATS_PAGE_LOCKED][idx].num_of_pages,
                ((dl_pager_stats->last_pages_info[HTT_STATS_PAGE_LOCKED][idx].timestamp_lsbs) |
                 (((unsigned long long) dl_pager_stats->last_pages_info[HTT_STATS_PAGE_LOCKED][idx].timestamp_msbs) << 32)));
    }

    HTT_STATS_PRINT(FATAL, "=========================================== \n");
    HTT_STATS_PRINT(FATAL, "UNLOCKED PAGES HISTORY");
    HTT_STATS_PRINT(FATAL, "=========================================== \n");
    HTT_STATS_PRINT(FATAL, "last_unlocked_page_idx = %u", (HTT_DLPAGER_LAST_UNLOCKED_PAGE_IDX_GET(dl_pager_stats->msg_dword_3)) ? \
            (HTT_DLPAGER_LAST_UNLOCKED_PAGE_IDX_GET(dl_pager_stats->msg_dword_3) - 1) : (HTT_DLPAGER_STATS_MAX_HIST-1));
    for (idx = 0; idx < HTT_DLPAGER_STATS_MAX_HIST; idx++) {
        HTT_STATS_PRINT(FATAL, "Index - %u : Page Number - %u : Num of pages - %u : Timestamp - %llu us",
                idx,
                dl_pager_stats->last_pages_info[HTT_STATS_PAGE_UNLOCKED][idx].page_num,
                dl_pager_stats->last_pages_info[HTT_STATS_PAGE_UNLOCKED][idx].num_of_pages,
                ((dl_pager_stats->last_pages_info[HTT_STATS_PAGE_UNLOCKED][idx].timestamp_lsbs) |
                 (((unsigned long long) dl_pager_stats->last_pages_info[HTT_STATS_PAGE_UNLOCKED][idx].timestamp_msbs) << 32)));
    }
    HTT_STATS_PRINT(FATAL, "=========================================== \n");
}

/*
 * htt_print_pktlog_and_htt_ring_stats_tlv: display htt_pktlog_and_htt_ring_stats_tlv values
 * @tag_buf: buffer containing the tlv htt_pktlog_and_htt_ring_stats_tlv
 *
 * return:void
 */
static void htt_print_pktlog_and_htt_ring_stats_tlv(A_UINT32 *tag_buf)
{
    htt_pktlog_and_htt_ring_stats_tlv *htt_stats_pktlog_and_htt_ring_stats_buf =
              (htt_pktlog_and_htt_ring_stats_tlv *) tag_buf;

    HTT_STATS_PRINT(FATAL, "HTT_PKTLOG_AND_HTT_RING_STATS_TLV:");
    HTT_STATS_PRINT(FATAL, "pktlog_lite_drop_cnt = %u",
            htt_stats_pktlog_and_htt_ring_stats_buf->pktlog_lite_drop_cnt);
    HTT_STATS_PRINT(FATAL, "pktlog_tqm_drop_cnt = %u",
            htt_stats_pktlog_and_htt_ring_stats_buf->pktlog_tqm_drop_cnt);
    HTT_STATS_PRINT(FATAL, "pktlog_ppdu_stats_drop_cnt = %u",
            htt_stats_pktlog_and_htt_ring_stats_buf->pktlog_ppdu_stats_drop_cnt);
    HTT_STATS_PRINT(FATAL, "pktlog_ppdu_ctrl_drop_cnt = %u",
            htt_stats_pktlog_and_htt_ring_stats_buf->pktlog_ppdu_ctrl_drop_cnt);
    HTT_STATS_PRINT(FATAL, "pktlog_sw_events_drop_cnt = %u",
            htt_stats_pktlog_and_htt_ring_stats_buf->pktlog_sw_events_drop_cnt);

    HTT_STATS_PRINT(FATAL, "=========================================== \n");
}

/*
 * htt_print_phy_counters_tlv: display htt_print_phy_counters_tlv values
 * @tag_buf: buffer containing the tlv htt_print_phy_counters_tlv
 *
 * return:void
 */
static void htt_print_phy_counters_tlv(A_UINT32 *tag_buf)
{
    htt_phy_counters_tlv *htt_stats_phy_counters_buf =
              (htt_phy_counters_tlv *) tag_buf;
    A_UINT8 i;

    HTT_STATS_PRINT(FATAL, "HTT_PHY_COUNTERS_TLV:");
    HTT_STATS_PRINT(FATAL, "rx_ofdma_timing_err_cnt = %u",
            htt_stats_phy_counters_buf->rx_ofdma_timing_err_cnt);
    HTT_STATS_PRINT(FATAL, "mactx_abort_cnt = %u",
            htt_stats_phy_counters_buf->mactx_abort_cnt);
    HTT_STATS_PRINT(FATAL, "macrx_abort_cnt = %u",
            htt_stats_phy_counters_buf->macrx_abort_cnt);
    HTT_STATS_PRINT(FATAL, "phytx_abort_cnt = %u",
            htt_stats_phy_counters_buf->phytx_abort_cnt);
    HTT_STATS_PRINT(FATAL, "phyrx_abort_cnt = %u",
            htt_stats_phy_counters_buf->phyrx_abort_cnt);
    HTT_STATS_PRINT(FATAL, "phyrx_defer_abort_cnt = %u",
            htt_stats_phy_counters_buf->phyrx_defer_abort_cnt);
    HTT_STATS_PRINT(FATAL, "rx_gain_adj_lstf_event_cnt = %u",
            htt_stats_phy_counters_buf->rx_gain_adj_lstf_event_cnt);
    HTT_STATS_PRINT(FATAL, "rx_gain_adj_non_legacy_cnt = %u",
            htt_stats_phy_counters_buf->rx_gain_adj_non_legacy_cnt);
    for (i = 0; i < HTT_MAX_RX_PKT_CNT; i++)
    {
        HTT_STATS_PRINT(FATAL, "rx_pkt_cnt[%d] =%u",
            i, htt_stats_phy_counters_buf->rx_pkt_cnt[i]);
    }
    for (i = 0; i < HTT_MAX_RX_PKT_CRC_PASS_CNT; i++)
    {
        HTT_STATS_PRINT(FATAL, "rx_pkt_crc_pass_cnt[%d] =%u",
            i, htt_stats_phy_counters_buf->rx_pkt_crc_pass_cnt[i]);
    }
    for (i = 0; i < HTT_MAX_PER_BLK_ERR_CNT; i++)
    {
        HTT_STATS_PRINT(FATAL, "per_blk_err_cnt[%d] =%u",
            i, htt_stats_phy_counters_buf->per_blk_err_cnt[i]);
    }
    for (i = 0; i < HTT_MAX_RX_OTA_ERR_CNT; i++)
    {
        HTT_STATS_PRINT(FATAL, "rx_ota_err_cnt[%d] =%u",
            i, htt_stats_phy_counters_buf->rx_ota_err_cnt[i]);
    }

    HTT_STATS_PRINT(FATAL, "=========================================== \n");
}

/*
 * htt_print_phy_stats_tlv: display htt_print_phy_stats_tlv values
 * @tag_buf: buffer containing the tlv htt_print_phy_stats_tlv
 *
 * return:void
 */
static void htt_print_phy_stats_tlv(A_UINT32 *tag_buf)
{
    htt_phy_stats_tlv *htt_stats_phy_stats_buf =
              (htt_phy_stats_tlv *) tag_buf;
    A_UINT8 i;

    HTT_STATS_PRINT(FATAL, "HTT_PHY_STATS_TLV:");
    for (i = 0; i < HTT_STATS_MAX_CHAINS; i++)
    {
        HTT_STATS_PRINT(FATAL, "nf_chain%d = %d",
            i, htt_stats_phy_stats_buf->nf_chain[i]);
    }

    HTT_STATS_PRINT(FATAL, "false_radar_cnt = %u / %u (mins)",
            htt_stats_phy_stats_buf->false_radar_cnt,
            htt_stats_phy_stats_buf->fw_run_time);
    HTT_STATS_PRINT(FATAL, "radar_cs_cnt = %u",
            htt_stats_phy_stats_buf->radar_cs_cnt);
    HTT_STATS_PRINT(FATAL, "ani_level = %d",
            htt_stats_phy_stats_buf->ani_level);

    HTT_STATS_PRINT(FATAL, "=========================================== \n");
}

/*
 * htt_htt_stats_print_tag: function to select the tag type and
 * print the corresponding tag structure
 * @tag_type: tag type that is to be printed
 * @tag_buf: pointer to the tag structure
 *
 * return: void
 */
void htt_htt_stats_print_tag(
        A_UINT8 tag_type,
        A_UINT32 *tag_buf)
{
    // htt_htt_stats_debug_dump(tag_buf);
    switch (tag_type) {
    case HTT_STATS_TX_PDEV_CMN_TAG:
        htt_print_tx_pdev_stats_cmn_tlv(tag_buf);
        break;
    case HTT_STATS_TX_PDEV_UNDERRUN_TAG:
        htt_print_tx_pdev_stats_urrn_tlv_v(tag_buf);
        break;
    case HTT_STATS_TX_PDEV_SIFS_TAG:
        htt_print_tx_pdev_stats_sifs_tlv_v(tag_buf);
        break;
    case HTT_STATS_TX_PDEV_FLUSH_TAG:
        htt_print_tx_pdev_stats_flush_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_PHY_ERR_TAG:
        htt_print_tx_pdev_stats_phy_err_tlv_v(tag_buf);
        break;
    case HTT_STATS_TX_PDEV_SIFS_HIST_TAG:
        htt_print_tx_pdev_stats_sifs_hist_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_TX_PPDU_STATS_TAG:
        htt_print_tx_pdev_stats_tx_ppdu_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_TRIED_MPDU_CNT_HIST_TAG:
        htt_print_tx_pdev_stats_tried_mpdu_cnt_hist_tlv_v(tag_buf);
        break;

    case HTT_STATS_STRING_TAG:
        htt_print_stats_string_tlv(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_CMN_TAG:
        htt_print_tx_hwq_stats_cmn_tlv(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_DIFS_LATENCY_TAG:
        htt_print_tx_hwq_difs_latency_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_CMD_RESULT_TAG:
        htt_print_tx_hwq_cmd_result_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_CMD_STALL_TAG:
        htt_print_tx_hwq_cmd_stall_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_FES_STATUS_TAG:
        htt_print_tx_hwq_fes_result_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_TRIED_MPDU_CNT_HIST_TAG:
        htt_print_tx_hwq_tried_mpdu_cnt_hist_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_TXOP_USED_CNT_HIST_TAG:
        htt_print_tx_hwq_txop_used_cnt_hist_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_TQM_GEN_MPDU_TAG:
        htt_print_tx_tqm_gen_mpdu_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_TQM_LIST_MPDU_TAG:
        htt_print_tx_tqm_list_mpdu_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_TQM_LIST_MPDU_CNT_TAG:
        htt_print_tx_tqm_list_mpdu_cnt_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_TQM_CMN_TAG:
        htt_print_tx_tqm_cmn_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_TQM_PDEV_TAG:
        htt_print_tx_tqm_pdev_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_TX_TQM_CMDQ_STATUS_TAG:
        htt_print_tx_tqm_cmdq_status_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_EAPOL_PACKETS_TAG:
        htt_print_tx_de_eapol_packets_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_CLASSIFY_FAILED_TAG:
        htt_print_tx_de_classify_failed_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_CLASSIFY_STATS_TAG:
        htt_print_tx_de_classify_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_CLASSIFY_STATUS_TAG:
        htt_print_tx_de_classify_status_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_ENQUEUE_PACKETS_TAG:
        htt_print_tx_de_enqueue_packets_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_ENQUEUE_DISCARD_TAG:
        htt_print_tx_de_enqueue_discard_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_FW2WBM_RING_FULL_HIST_TAG:
        htt_print_tx_de_fw2wbm_ring_full_hist_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_CMN_TAG:
        htt_print_tx_de_cmn_stats_tlv(tag_buf);
        break;

    case HTT_STATS_RING_IF_TAG:
        htt_print_ring_if_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_MU_MIMO_STATS_TAG:
        htt_print_tx_pdev_mu_mimo_sch_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_DL_MU_OFDMA_STATS_TAG:
        htt_print_tx_pdev_dl_mu_ofdma_sch_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_UL_MU_OFDMA_STATS_TAG:
        htt_print_tx_pdev_ul_mu_ofdma_sch_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_DL_MU_MIMO_STATS_TAG:
        htt_print_tx_pdev_dl_mu_mimo_sch_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_UL_MU_MIMO_STATS_TAG:
        htt_print_tx_pdev_ul_mu_mimo_sch_stats_tlv(tag_buf);
        break;

    case HTT_STATS_SFM_CMN_TAG:
        htt_print_sfm_cmn_tlv(tag_buf);
        break;

    case HTT_STATS_SRING_STATS_TAG:
        htt_print_sring_stats_tlv(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_FW_STATS_TAG:
        htt_print_rx_pdev_fw_stats_tlv(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_FW_RING_MPDU_ERR_TAG:
        htt_print_rx_pdev_fw_ring_mpdu_err_tlv_v(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_FW_MPDU_DROP_TAG:
        htt_print_rx_pdev_fw_mpdu_drop_tlv_v(tag_buf);
        break;

    case HTT_STATS_RX_SOC_FW_STATS_TAG:
        htt_print_rx_soc_fw_stats_tlv(tag_buf);
        break;

    case HTT_STATS_RX_SOC_FW_REFILL_RING_EMPTY_TAG:
        htt_print_rx_soc_fw_refill_ring_empty_tlv_v(tag_buf);
        break;

    case HTT_STATS_RX_SOC_FW_REFILL_RING_NUM_REFILL_TAG:
        htt_print_rx_soc_fw_refill_ring_num_refill_tlv_v(
                tag_buf);
        break;
    case HTT_STATS_RX_REFILL_RXDMA_ERR_TAG:
        htt_print_rx_soc_fw_refill_ring_num_rxdma_err_tlv_v(
                tag_buf);
        break;

    case HTT_STATS_RX_REFILL_REO_ERR_TAG:
        htt_print_rx_soc_fw_refill_ring_num_reo_err_tlv_v(
                tag_buf);
        break;

    case HTT_STATS_RX_REO_RESOURCE_STATS_TAG:
        htt_print_rx_reo_debug_stats_tlv_v(
                tag_buf);
        break;
    case HTT_STATS_RX_PDEV_FW_STATS_PHY_ERR_TAG:
        htt_print_rx_pdev_fw_stats_phy_err_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_RATE_STATS_TAG:
        htt_print_tx_pdev_rate_stats_tlv(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_RATE_STATS_TAG:
        htt_print_rx_pdev_rate_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_SCHEDULER_TXQ_STATS_TAG:
        htt_print_tx_pdev_stats_sched_per_txq_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SCHED_CMN_TAG:
        htt_print_stats_tx_sched_cmn_tlv(tag_buf);
        break;

    case HTT_STATS_TX_PDEV_MPDU_STATS_TAG:
        htt_print_tx_pdev_mu_mimo_mpdu_stats_tlv(tag_buf);
        break;

    case HTT_STATS_SCHED_TXQ_CMD_POSTED_TAG:
        htt_print_sched_txq_cmd_posted_tlv_v(tag_buf);
        break;

    case HTT_STATS_RING_IF_CMN_TAG:
        htt_print_ring_if_cmn_tlv(tag_buf);
        break;

    case HTT_STATS_SFM_CLIENT_USER_TAG:
        htt_print_sfm_client_user_tlv_v(tag_buf);
        break;

    case HTT_STATS_SFM_CLIENT_TAG:
        htt_print_sfm_client_tlv(tag_buf);
        break;

    case HTT_STATS_TX_TQM_ERROR_STATS_TAG:
        htt_print_tx_tqm_error_stats_tlv(tag_buf);
        break;

    case HTT_STATS_SCHED_TXQ_CMD_REAPED_TAG:
        htt_print_sched_txq_cmd_reaped_tlv_v(tag_buf);
        break;

    case HTT_STATS_SRING_CMN_TAG:
        htt_print_sring_cmn_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SOUNDING_STATS_TAG:
        htt_print_tx_sounding_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SELFGEN_AC_ERR_STATS_TAG:
        htt_print_tx_selfgen_ac_err_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SELFGEN_CMN_STATS_TAG:
        htt_print_tx_selfgen_cmn_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SELFGEN_AC_STATS_TAG:
        htt_print_tx_selfgen_ac_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SELFGEN_AX_STATS_TAG:
        htt_print_tx_selfgen_ax_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SELFGEN_AX_ERR_STATS_TAG:
        htt_print_tx_selfgen_ax_err_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_MUMIMO_SCH_STATS_TAG:
        htt_print_tx_hwq_mu_mimo_sch_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_MUMIMO_MPDU_STATS_TAG:
        htt_print_tx_hwq_mu_mimo_mpdu_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_HWQ_MUMIMO_CMN_STATS_TAG:
        htt_print_tx_hwq_mu_mimo_cmn_stats_tlv(tag_buf);
        break;

    case HTT_STATS_HW_INTR_MISC_TAG:
        htt_print_hw_stats_intr_misc_tlv(tag_buf);
        break;

    case HTT_STATS_HW_WD_TIMEOUT_TAG:
        htt_print_hw_stats_wd_timeout_tlv(tag_buf);
        break;

    case HTT_STATS_HW_PDEV_ERRS_TAG:
        htt_print_hw_stats_pdev_errs_tlv(tag_buf);
        break;

    case HTT_STATS_COUNTER_NAME_TAG:
        htt_print_counter_tlv(tag_buf);
        break;

    case HTT_STATS_TX_TID_DETAILS_TAG:
        htt_print_tx_tid_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_TID_DETAILS_V1_TAG:
        htt_print_tx_tid_stats_v1_tlv(tag_buf);
        break;

    case HTT_STATS_RX_TID_DETAILS_TAG:
        htt_print_rx_tid_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PEER_STATS_CMN_TAG:
        htt_print_peer_stats_cmn_tlv(tag_buf);
        break;

    case HTT_STATS_PEER_DETAILS_TAG:
        htt_print_peer_details_tlv(tag_buf);
        break;

    case HTT_STATS_PEER_MSDU_FLOWQ_TAG:
        htt_print_msdu_flow_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PEER_TX_RATE_STATS_TAG:
        htt_print_tx_peer_rate_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PEER_RX_RATE_STATS_TAG:
        htt_print_rx_peer_rate_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_DE_COMPL_STATS_TAG:
        htt_print_tx_de_compl_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PDEV_CCA_1SEC_HIST_TAG:
    case HTT_STATS_PDEV_CCA_100MSEC_HIST_TAG:
    case HTT_STATS_PDEV_CCA_STAT_CUMULATIVE_TAG:
        htt_print_pdev_cca_stats_hist_tlv(tag_buf);
        break;

    case HTT_STATS_PDEV_CCA_COUNTERS_TAG:
        htt_print_pdev_stats_cca_counters_tlv(tag_buf);
        break;

    case HTT_STATS_WHAL_TX_TAG:
        htt_print_hw_stats_whal_tx_tlv(tag_buf);
        break;

    case HTT_STATS_PDEV_TWT_SESSIONS_TAG:
        htt_print_pdev_stats_twt_sessions_tlv(tag_buf);
        break;

    case HTT_STATS_PDEV_TWT_SESSION_TAG:
        htt_print_pdev_stats_twt_session_tlv(tag_buf);
        break;

    case HTT_STATS_SCHED_TXQ_SCHED_ORDER_SU_TAG:
        htt_print_sched_txq_sched_order_su_tlv_v(tag_buf);
        break;

    case HTT_STATS_SCHED_TXQ_SCHED_INELIGIBILITY_TAG:
        htt_print_sched_txq_sched_ineligibility_tlv_v(tag_buf);
        break;

    case HTT_STATS_PDEV_OBSS_PD_TAG:
        htt_print_pdev_obss_pd_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_HW_WAR_TAG:
        htt_print_hw_war_tlv_v(tag_buf);
        break;

    case HTT_STATS_RING_BACKPRESSURE_STATS_TAG:
        htt_print_pdev_ring_backpressure_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_LATENCY_PROF_STATS_TAG:
        htt_print_soc_latency_prof_stats_tlv_v(tag_buf);
        break;

    case HTT_STATS_LATENCY_CTX_TAG:
        htt_print_soc_latency_prof_ctx_tlv(tag_buf);
        break;

    case HTT_STATS_LATENCY_CNT_TAG:
        htt_print_latency_prof_cnt(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_UL_TRIG_STATS_TAG:
        htt_print_ul_ofdma_trigger_stats(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_UL_OFDMA_USER_STATS_TAG:
        htt_print_ul_ofdma_user_stats(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_UL_MIMO_USER_STATS_TAG:
        htt_print_ul_mimo_user_stats(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_UL_MUMIMO_TRIG_STATS_TAG:
        htt_print_ul_mumimo_trig_stats(tag_buf);
        break;

    case HTT_STATS_RX_FSE_STATS_TAG:
        htt_print_rx_fse_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PEER_SCHED_STATS_TAG:
        htt_print_peer_sched_stats(tag_buf);
        break;

    case HTT_STATS_SCHED_TXQ_SUPERCYCLE_TRIGGER_TAG:
        htt_print_sched_txq_supercycle_trigger_tlv_v(tag_buf);
        break;

    case HTT_STATS_PDEV_CTRL_PATH_TX_STATS_TAG:
        htt_print_pdev_ctrl_path_tx_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PEER_CTRL_PATH_TXRX_STATS_TAG:
        htt_print_peer_ctrl_path_txrx_stats_tlv(tag_buf);
        break;

    case HTT_STATS_RX_PDEV_RATE_EXT_STATS_TAG:
        htt_print_rx_pdev_rate_ext_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PDEV_TX_RATE_TXBF_STATS_TAG:
        htt_print_tx_peer_rate_txbf_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TXBF_OFDMA_NDPA_STATS_TAG:
        htt_print_txbf_ofdma_ndpa_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TXBF_OFDMA_NDP_STATS_TAG:
        htt_print_txbf_ofdma_ndp_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TXBF_OFDMA_BRP_STATS_TAG:
        htt_print_txbf_ofdma_brp_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TXBF_OFDMA_STEER_STATS_TAG:
        htt_print_txbf_ofdma_steer_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SELFGEN_AC_SCHED_STATUS_STATS_TAG:
        htt_print_tx_selfgen_ac_sched_status_stats_tlv(tag_buf);
        break;

    case HTT_STATS_TX_SELFGEN_AX_SCHED_STATUS_STATS_TAG:
        htt_print_tx_selfgen_ax_sched_status_stats_tlv(tag_buf);
        break;

    case HTT_STATS_UNAVAILABLE_ERROR_STATS_TAG:
        htt_print_unavailable_error_stats_tlv(tag_buf);
        break;

    case HTT_STATS_UNSUPPORTED_ERROR_STATS_TAG:
        htt_print_unsupported_error_stats_tlv(tag_buf);
        break;

    case HTT_STATS_VDEV_RTT_RESP_STATS_TAG:
        htt_print_vdev_rtt_resp_stats_tlv(tag_buf);
        break;

    case HTT_STATS_PKTLOG_AND_HTT_RING_STATS_TAG:
        htt_print_pktlog_and_htt_ring_stats_tlv(tag_buf);
        break;

    case HTT_STATS_DLPAGER_STATS_TAG:
        htt_print_dlpager_stats(tag_buf);
        break;

    case HTT_STATS_PHY_COUNTERS_TAG:
         htt_print_phy_counters_tlv(tag_buf);
         break;

    case HTT_STATS_PHY_STATS_TAG:
         htt_print_phy_stats_tlv(tag_buf);
         break;

    case HTT_STATS_STA_UL_OFDMA_STATS_TAG:
         htt_print_sta_ul_ofdma_stats_tlv(tag_buf);
         break;

    default:
        break;
    }
}

void htt_stats_msg_receive(
        void *data,
        A_INT32 len)
{
    static A_UINT8       *tlv_buf_head     = NULL;
    static A_UINT8       *tlv_buf_tail     = NULL;
    A_UINT32             msg_remain_len    = len;
    static A_UINT32      tlv_remain_len    = 0;
    A_UINT32             tlv_len           = 0;
    A_UINT32             *tlv_start;
    A_UINT32             *msg_word;
    static htt_tlv_tag_t tlv_type          = 0xff;

    msg_word = htt_stats_msg_get(data);

    while (msg_remain_len) {
        /*
         * if message is not a continuation of previous message
         * read the tlv type and tlv length
         */
        if (!tlv_buf_head) {
            tlv_type = HTT_STATS_TLV_TAG_GET(
                    *msg_word);
            tlv_len = HTT_STATS_TLV_LENGTH_GET(
                    *msg_word);
            tlv_remain_len = tlv_len;
        }

        if (tlv_remain_len == 0) {
            msg_remain_len = 0;

            if (tlv_buf_head) {
                free(tlv_buf_head);
                tlv_buf_head = NULL;
                tlv_buf_tail = NULL;
            }
            return;
        }
        if (!tlv_buf_head) {
            tlv_remain_len += HTT_TLV_HDR_LEN;
        }

        if ((tlv_remain_len <= msg_remain_len)) {
            /* Case 3 */
            if (tlv_buf_head) {
                memcpy(tlv_buf_tail,
                        (A_UINT8 *)msg_word,
                        tlv_remain_len);
                tlv_start = (A_UINT32 *)tlv_buf_head;
            } else {
                /* Case 1 */
                tlv_start = msg_word;
            }
            htt_htt_stats_print_tag(tlv_type, tlv_start);

            msg_remain_len -= tlv_remain_len;

            msg_word = (A_UINT32 *)
                       (((A_UINT8 *)msg_word) +
                        tlv_remain_len);

            tlv_remain_len = 0;

            if (tlv_buf_head) {
                free(tlv_buf_head);
                tlv_buf_head = NULL;
                tlv_buf_tail = NULL;
            }
        } else { /* tlv_remain_len > msg_remain_len */
            /* Case 2 & 3 */
            if (!tlv_buf_head) {
                tlv_buf_head = malloc(
                        tlv_remain_len);

                if (!tlv_buf_head) {
                    HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
                    return;
                }
                tlv_buf_tail = tlv_buf_head;
            }
            memcpy(tlv_buf_tail, (A_UINT8 *)msg_word,
                    msg_remain_len);
            tlv_remain_len -= msg_remain_len;
            tlv_buf_tail   += msg_remain_len;
            msg_remain_len  = 0;
        }
    }
}

#ifndef __KERNEL__

static void htt_stats_usage(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= USAGE =================\n");
    printf("%s %s\n", argv[0], argv[1]);
    printf("\t - necessary args \n");
    printf("\t\t<radio_name>\t- ex: wifiX\n");
    printf("\t\t<cmd_id>\t- 1 - 19\n");
    printf("\t - optional args\n");
    printf("\t\t <config_param0>\t default 0 if not mentioned\n");
    printf("\t\t <config_param1>\t default 0 if not mentioned\n");
    printf("\t\t <config_param2>\t default 0 if not mentioned\n");
    printf("\t\t <config_param3>\t default 0 if not mentioned\n");
    printf("Example:\n");
    printf("\twifistats wifiX <cmd_id> <optional config_params>\n");
    printf("=========================================\n");
}

static void htt_stats_usage_peerstats(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= PEER STATS USAGE =================\n");
    printf("%s \n",                   argv[0]);
    printf("\t - necessary args \n");
    printf("\t\t<radio_name>\t- ex: wifiX\n");
    printf("\t\t <cmid_id> is %d \n", HTT_DBG_EXT_STATS_PEER_INFO);
    printf("\t\t One of either two below: --peerid or--mac\n");
    printf("\t\t\t --mac   \t followed by MAC in aa:bb:cc:dd:ee:ff format\n");
    printf("\t\t\t\t -OR- \n");
    printf("\t\t \t--peerid\t followed by sw_peer_id\n");
    printf("\t - optional args\n");
    printf("\t\t --mode\t followed by peer_stats_req_mode\n");
    printf("\t\t --mask\t followed by req_type_bitmask\n");
    printf("Example:\n");
    printf("\t %s %s wifiX %d --mac aa:bb:cc:dd:ee:ff <optional args>\n", argv[0], argv[1],
            HTT_DBG_EXT_STATS_PEER_INFO);
    printf("\t\t-OR- \n");
    printf("\t %s %s wifiX %d --peerid N <optional args>\n",              argv[0], argv[1],
            HTT_DBG_EXT_STATS_PEER_INFO);
    printf("=========================================\n");
}

static void htt_stats_usage_reset(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= RESET STATS USAGE =================\n");
    printf("%s \n",                                   argv[0]);
    printf("\t - necessary args \n");
    printf("\t\t <radio_name>\t- ex: wifiX\n");
    printf("\t\t <cmid_id> is %d \n",                 HTT_DBG_EXT_STATS_RESET);
    printf("\t\t <config_param0>\t stat number to reset\n");
    printf("Example:\n");
    printf("\t %s %s wifiX %d <stat_num_to_reset>\n", argv[0], argv[1], HTT_DBG_EXT_STATS_RESET);
    printf("=========================================\n");
}

static void htt_stats_usage_vdevstats(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= VDEV STATS USAGE =================\n");
    printf("wifistats \n");
    printf("\t - necessary args \n");
    printf("\t\t <radio_name>\t\t- ex: wifiX\n");
    printf("\t\t <cmid_id>\t\t  <%d|%d|%d>\n", HTT_DBG_EXT_STATS_TX_SELFGEN_INFO,
            HTT_DBG_EXT_STATS_PDEV_TX_MU, HTT_DBG_EXT_STATS_TX_SOUNDING_INFO);
    printf("\t\t --vdevid <vdev_id>\t- ex: --vdevid <0-255>\n");
    printf("Example:\n");
    printf("\twifistats wifiX %d --vdevid 5\n", HTT_DBG_EXT_STATS_TX_SELFGEN_INFO);
    printf("\twifistats wifiX %d --vdevid 7\n", HTT_DBG_EXT_STATS_PDEV_TX_MU);
    printf("\twifistats wifiX %d --vdevid 3\n", HTT_DBG_EXT_STATS_TX_SOUNDING_INFO);
    printf("=========================================\n");
}

static void htt_stats_usage_peer_ctrl_path_txrx_stats(
        A_INT32 argc,
        A_CHAR *argv[])
{
    printf("========= CONTROL PATH PEER TX RX STATS USAGE =================\n");
    printf("%s \n", argv[0]);
    printf("\t - necessary args \n");
    printf("\t\t<radio_name>\t: wifiX\n");
    printf("\t\t<cmid_id>\t: %d\n", HTT_DBG_EXT_PEER_CTRL_PATH_TXRX_STATS);
    printf("\t - optional args\n");
    printf("\t\t<argument>\t: --mac\n");
    printf("\t\t--mac\t: followed by MAC in aa:bb:cc:dd:ee:ff format\n");
    printf("Example:\n");
    printf("1. To Display Control Path Stats\n");
    printf("\t %s %s %d\n", argv[0], argv[1], HTT_DBG_EXT_PEER_CTRL_PATH_TXRX_STATS);
    printf("2. To Configure Peer and Display Control Path Stats\n");
    printf("\t %s %s %d --mac aa:bb:cc:dd:ee:ff\n", argv[0], argv[1],
            HTT_DBG_EXT_PEER_CTRL_PATH_TXRX_STATS);
    printf("3. To Reset Control Path Stats\n");
    printf("\t %s %s 0 %d\n", argv[0], argv[1], HTT_DBG_EXT_PEER_CTRL_PATH_TXRX_STATS);
    printf("=========================================\n");
}

void htt_stats_help(
        A_INT32 argc,
        A_CHAR *argv[])
{
    A_INT32 stats_id = atoi(argv[2]);

    if (stats_id == HTT_DBG_EXT_STATS_PEER_INFO) {
        htt_stats_usage_peerstats(argc, argv);
    } else if (stats_id == HTT_DBG_EXT_STATS_RESET) {
        htt_stats_usage_reset(argc, argv);
    } else if ((stats_id == HTT_DBG_EXT_STATS_TX_SOUNDING_INFO) ||
               (stats_id == HTT_DBG_EXT_STATS_PDEV_TX_MU) ||
               (stats_id == HTT_DBG_EXT_STATS_TX_SELFGEN_INFO))
    {
        htt_stats_usage_vdevstats(argc, argv);
    } else if (stats_id == HTT_DBG_EXT_PEER_CTRL_PATH_TXRX_STATS ) {
        htt_stats_usage_peer_ctrl_path_txrx_stats(argc, argv);
    } else {
        htt_stats_usage(argc, argv);
    }
}

static void *htt_stats_buff_alloc(A_INT32 *buff_len)
{
    void *buff = malloc(sizeof(struct httstats_cmd_request));

    if (!buff) {
        HTT_STATS_ERR(FATAL, "%s: %d: Failed to allocate memory", __func__, __LINE__);
        return NULL;
    }
    memset(buff, 0x0, sizeof(struct httstats_cmd_request));
    *buff_len = sizeof(struct httstats_cmd_request);

    return buff;
}

static void htt_stats_buff_free(void *buff)
{
    free(buff);
}

A_INT32 htt_vdev_stats_req_prepare(
        struct httstats_cmd_request *stats_req,
        A_INT32 argc,
        A_CHAR *argv[])
{
    A_INT8 vdev_id;

    /* To handle mu pdev stats numbers 12,17,22 */
    if (argc == 3) {
        if (stats_req->stats_id == HTT_DBG_EXT_STATS_PDEV_TX_MU)
            stats_req->config_param1 = HTT_UPLOAD_MU_STATS;
        return 0;
    }

    if ((stats_req->stats_id == HTT_DBG_EXT_STATS_PDEV_TX_MU) && (argc == 4) && (strcmp(argv[3], "--vdevid") != 0)) {
        stats_req->config_param1 = strtoul(argv[3], NULL, 0);
        return 0;
    } else {
        stats_req->config_param1 = HTT_UPLOAD_MU_STATS;
    }

    if ((argc == 5) && (strcmp(argv[3], "--vdevid") == 0)) {
        vdev_id = strtoul(argv[4], NULL, 0);

        if (vdev_id <= 255) {
            stats_req->config_param0 = HTT_DBG_EXT_STATS_SET_VDEV_MASK(vdev_id);
        } else {
            printf("Specify valid arguement value pair. Ex: --vdevid <vdev-id>\n");
            return -EIO;
        }
    } else {
        return -EIO;
    }
    return 0;
}

static A_INT32 htt_configure_debug_peer_stats_req_prepare(
        struct httstats_cmd_request *stats_req,
        A_INT32 argc,
        A_CHAR *argv[])
{
    A_CHAR mac_str[18] = {0};
    A_UINT8 mac_addr[IEEE80211_ADDR_LEN];
    A_UINT8 i = 0, id_or_mac_specified = 0;
    for (i = 3; i < argc; i += 2) {
        if (strcmp(argv[i], "--mac") == 0) {
            if (id_or_mac_specified) { /*Already specifed mac/peerid*/
                fprintf(stderr, "Specify only --mac\n");
                return -EIO;
            }
            strlcpy(mac_str, argv[i + 1], 18);

            if (extract_mac_addr(mac_addr, mac_str) != 0) {
                fprintf(stderr, "Invalid PEER MAC\n");
                return -EIO;
            }
            HTT_DBG_EXT_PEER_CTRL_PATH_TXRX_STATS_IS_MAC_ADDR_SET(stats_req->config_param0, 1);
            stats_req->config_param1 |= (mac_addr[0]         & 0x000000ff);
            stats_req->config_param1 |= ((mac_addr[1] << 8)  & 0x0000ff00);
            stats_req->config_param1 |= ((mac_addr[2] << 16) & 0x00ff0000);
            stats_req->config_param1 |= ((mac_addr[3] << 24) & 0xff000000);
            stats_req->config_param2 |= (mac_addr[4]         & 0x000000ff);
            stats_req->config_param2 |= ((mac_addr[5] << 8)  & 0x0000ff00);
            id_or_mac_specified++;
        }
    }
    return 0;
}

static A_INT32 htt_peer_stats_req_prepare(
        struct httstats_cmd_request *stats_req,
        A_INT32 argc,
        A_CHAR *argv[])
{
    A_CHAR mac_str[18] = {0};
    A_UINT8 mac_addr[IEEE80211_ADDR_LEN];
    A_UINT8 i = 0, id_or_mac_specified = 0;

    /*default values for optional params*/
    stats_req->config_param1 = 0xFFFFFFFF; /*all stats*/
    // HTT_DBG_EXT_STATS_PEER_REQ_MODE_SET(stats_req->config_param0, HTT_PEER_STATS_REQ_MODE_FLUSH_TQM);
    stats_req->config_param0 |= HTT_PEER_STATS_REQ_MODE_FLUSH_TQM << 1;

    for (i = 3; i < argc; i += 2) {
        if (strcmp(argv[i], "--mode") == 0) {
            stats_req->config_param0 &= ~HTT_DBG_EXT_STATS_PEER_REQ_MODE_M; /*clear default value entered earlier*/
            // HTT_DBG_EXT_STATS_PEER_REQ_MODE_SET(stats_req->config_param0, (strtoul(argv[i+1], NULL, 0) & 0x7FFF));
            stats_req->config_param0 |= (strtoul(argv[i + 1], NULL, 0) & 0x7FFF) << 1;
        } else if (strcmp(argv[i], "--mask") == 0) {
            stats_req->config_param1 = strtoul(argv[i + 1], NULL, 0);
        } else if (strcmp(argv[i], "--mac") == 0) {
            if (id_or_mac_specified) { /*Already specifed mac/peerid*/
                printf("Specify only one:either --peerid or --mac\n");
                return -EIO;
            }
            strlcpy(mac_str, argv[i + 1], 18);

            if (extract_mac_addr(mac_addr, mac_str) != 0) {
                printf("Invalid MAC PEER MAC\n");
                return -EIO;
            }
            HTT_DBG_EXT_STATS_PEER_INFO_IS_MAC_ADDR_SET(stats_req->config_param0, 1);
            stats_req->config_param2 |= (mac_addr[0] & 0x000000ff);
            stats_req->config_param2 |= ((mac_addr[1] << 8) & 0x0000ff00);
            stats_req->config_param2 |= ((mac_addr[2] << 16) & 0x00ff0000);
            stats_req->config_param2 |= ((mac_addr[3] << 24) & 0xff000000);
            stats_req->config_param3 |= (mac_addr[4] & 0x000000ff);
            stats_req->config_param3 |= ((mac_addr[5] << 8) & 0x0000ff00);
            id_or_mac_specified++;
        } else if (strcmp(argv[i], "--peerid") == 0) {
            if (id_or_mac_specified) { /*Already specifed mac/peerid*/
                printf("Specify only one:either --peerid or --mac\n");
                return -EIO;
            }
            HTT_DBG_EXT_STATS_PEER_INFO_IS_MAC_ADDR_SET(stats_req->config_param0, 0);
            HTT_DBG_EXT_STATS_PEER_INFO_SW_PEER_ID_SET(stats_req->config_param0,
                    (strtoul(argv[i + 1], NULL, 0) & 0xFFFF));
            id_or_mac_specified++;
        } else {
            printf("Unsupported option entered\n");
            return -EIO;
        }
    }

    if (id_or_mac_specified != 1) { /*Not specifed peerid or mac*/
        printf("Must Specify one:either --peerid or --mac\n");
        return -EIO;
    }
    return 0;
}

static A_INT32 htt_stats_cookie_generate(void)
{
    static A_INT32 httstats_cookie = 0;

    if (!httstats_cookie) {
        httstats_cookie = getpid();
    }
    return httstats_cookie;
}

static A_INT32 htt_stats_input_parse(
        void *buff,
        A_INT32 argc,
        A_CHAR *argv[],
        A_INT32 *buff_len,
        A_INT32 pdev_id)
{
    struct httstats_cmd_request *stats_req = (struct httstats_cmd_request *)buff;

    stats_req->stats_id = atoi(argv[2]);
    stats_req->pid      = htt_stats_cookie_generate();

    if (stats_req->stats_id == HTT_DBG_EXT_STATS_PEER_INFO) {
        if ((argc < 4) || (argc > 9) || (argc % 2 == 0)) {
            fprintf(stderr, "Invalid commands args\n");
            return -EIO;
        }

        if (htt_peer_stats_req_prepare(stats_req, argc, argv) != 0) {
            fprintf(stderr, "Invalid commands args\n");
            return -EIO;
        }
    } else if ((stats_req->stats_id == HTT_DBG_EXT_STATS_TX_SOUNDING_INFO) ||
               (stats_req->stats_id == HTT_DBG_EXT_STATS_PDEV_TX_MU) ||
               (stats_req->stats_id == HTT_DBG_EXT_STATS_TX_SELFGEN_INFO))
    {
        if (htt_vdev_stats_req_prepare(stats_req, argc, argv) != 0) {
            return -EIO;
        }
    } else if (stats_req->stats_id == HTT_DBG_EXT_PEER_CTRL_PATH_TXRX_STATS) {
        if (argc != 3 && argc != 5) {
            fprintf(stderr, "Invalid commands args\n");
            return -EIO;
        }
        if (argc == 5) {
            if (htt_configure_debug_peer_stats_req_prepare(stats_req, argc, argv) != 0) {
                fprintf(stderr, "Invalid commands args\n");
                return -EIO;
            }
        }
    } else {
        if (argc >= 4) {
            stats_req->config_param0 = strtoul(argv[3], NULL, 0);
        } else {
            if (stats_req->stats_id == HTT_DBG_EXT_STATS_RESET) {
                return -EIO;
            }
        }

        if (argc >= 5) {
            stats_req->config_param1 = strtoul(argv[4], NULL, 0);
        } else {
            if (stats_req->stats_id == HTT_DBG_EXT_STATS_RESET) {
                stats_req->config_param1 = 0x1; /*default query 1 stat*/
            }
        }

        if (argc >= 6) {
            stats_req->config_param2 = strtoul(argv[5], NULL, 0);
        }

        if (argc >= 7) {
            stats_req->config_param3 = strtoul(argv[6], NULL, 0);
        }
    }

    if (stats_req->stats_id == HTT_DBG_EXT_STATS_RESET) {
        httstats.timeout = 0;
    }
    *buff_len = sizeof(struct httstats_cmd_request);
    return 0;
}

static void htt_stats_print_tlv(void *tlv_ptr)
{
    htt_tlv_tag_t tlv_type;
    A_UINT32      *msg_word = (A_UINT32 *) tlv_ptr;
    tlv_type = HTT_STATS_TLV_TAG_GET(*msg_word);

    htt_htt_stats_print_tag(tlv_type, tlv_ptr);
}

static void *htt_stats_get_buf_start(void *buff, A_INT32 *len, int *listen_done)
{
    A_UINT32 *msg_word = NULL;

    msg_word = (A_UINT32 *)buff;
    msg_word = msg_word + 3;

    *listen_done = 0;
    if (HTT_T2H_EXT_STATS_CONF_TLV_DONE_GET(*msg_word)) {
        *listen_done = 1;
    }
    msg_word++;
    *len -= (((void *)msg_word) - buff);
    return msg_word;
}

static A_INT32 htt_stats_handler(
        void *buff,
        A_INT32 len)
{
    A_UINT32 *msg_word = NULL;
    A_UINT8  done      = 0;
    A_INT32  status    = LISTEN_CONTINUE;

    msg_word = (A_UINT32 *)buff;
    msg_word = msg_word + 3;

    done = HTT_T2H_EXT_STATS_CONF_TLV_DONE_GET(*msg_word);

    if (done) {
        status = LISTEN_DONE;
    }
    msg_word++;

    /* Updated length to reduce the HTT header len as
     * htt_stats_msg_receive() do not expect HTT header*/
    htt_stats_msg_receive((void *)msg_word, (len - 16));

    return status;
}

static A_INT32 htt_stats_cookie_get(
        void *buff,
        A_INT32 len)
{
    A_UINT32 *msg_word = NULL;
    A_INT32  cookie    = 0;

    msg_word = (A_UINT32 *)buff;
    cookie   = (A_INT32)(*(msg_word + 1)); /*Cookie LSB*/

    return cookie;
}

int htt_stats_tlv_length(void *data)
{
    return (HTT_TLV_HDR_LEN +
                   HTT_STATS_TLV_LENGTH_GET(*((A_UINT32 *) data)));
}

static struct wifistats_module httstats = {
    .name                  = "htt_fw_stats",
    .help                  = htt_stats_help,
    .input_buff_alloc      = htt_stats_buff_alloc,
    .input_parse           = htt_stats_input_parse,
    .input_buff_free       = htt_stats_buff_free,
    .input_cookie_generate = htt_stats_cookie_generate,
    .output_tlv_length     = htt_stats_tlv_length,
    .output_get_buf_start  = htt_stats_get_buf_start,
    .output_print_tlv      = htt_stats_print_tlv,
    .output_handler        = htt_stats_handler,
    .output_cookie_get     = htt_stats_cookie_get,
    .timeout               = 2000,
    .output_fp             = NULL,
    .tlv_hdr_len           = HTT_TLV_HDR_LEN,
};

void httstats_init(void)
{
    wifistats_module_register(&httstats, sizeof(httstats));
}

void httstats_fini(void)
{
    wifistats_module_unregister(&httstats, sizeof(httstats));
}

#endif /* ifndef __KERNEL__ */
