/*
 * Copyright (c) 2015,2017,2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <qdf_mem.h>   /* qdf_mem_malloc,free, etc. */
#include <qdf_types.h> /* qdf_print */
#include <qdf_nbuf.h>
#include <ieee80211_defines.h>
#include <ol_vowext_dbg_defs.h>
#include <ol_ratetable.h>
#include <ol_cfg_raw.h>

/* AR900B RX descriptor */
#include <AR900B/hw/interface/rx_location_info.h>
#include <AR900B/hw/interface/rx_pkt_end.h>
#include <AR900B/hw/interface/rx_phy_ppdu_end.h>
#include <AR900B/hw/interface/rx_timing_offset.h>
#include <AR900B/hw/interface/rx_location_info.h>
#include <AR900B/hw/tlv/rx_attention.h>
#include <AR900B/hw/tlv/rx_frag_info.h>
#include <AR900B/hw/tlv/rx_msdu_start.h>
#include <AR900B/hw/tlv/rx_msdu_end.h>
#include <AR900B/hw/tlv/rx_mpdu_start.h>
#include <AR900B/hw/tlv/rx_mpdu_end.h>
#include <AR900B/hw/tlv/rx_ppdu_start.h>
#include <AR900B/hw/tlv/rx_ppdu_end.h>

/* defines HW descriptor format */
#include "../include/rx_desc_internal.h"
#include "../include/ar_internal.h"

#define RX_DESC_ANTENNA_OFFSET 25
#define GET_L3_HEADER_PADDING(rx_desc) (((*(((u_int32_t *) &rx_desc->msdu_end)+ 8)) &\
                                            RX_MSDU_END_8_L3_HEADER_PADDING_MASK) >>\
                                            RX_MSDU_END_8_L3_HEADER_PADDING_LSB)

#define rx_desc_parse_ppdu_start_status(rx_desc, rx_status) \
    _ar900b_rx_desc_parse_ppdu_start_status(rx_desc, rx_status)

#if RX_CHECKSUM_OFFLOAD
#define rx_desc_set_checksum_result(rx_desc, msdu) \
    _ar900b_rx_desc_set_checksum_result(rx_desc, msdu)
#else
#define rx_desc_set_checksum_result(rx_desc, msdu)
#endif

static inline int
_ar900b_rx_desc_is_first_mpdu(void *_rxd)
{
    struct rx_desc_base *rxd;
    uint32_t *ptr;
    rxd = _rxd;
    ptr = (void *)&rxd->attention;
    return ptr[0] & RX_ATTENTION_0_FIRST_MPDU_MASK;
}

static inline int
_ar900b_rx_desc_is_last_mpdu(void *_rxd)
{
    struct rx_desc_base *rxd;
    uint32_t *ptr;
    rxd = _rxd;
    ptr = (void *)&rxd->attention;
    return ptr[0] & RX_ATTENTION_0_LAST_MPDU_MASK;
}

static int
_ar900b_rx_desc_is_retry(void *_rxd)
{
    struct rx_desc_base *rxd;
    uint32_t *ptr;
    rxd = _rxd;
    ptr = (void *)&rxd->mpdu_start;
    return ptr[0] & RX_MPDU_START_0_RETRY_MASK;
}

static void *
_ar900b_rx_desc_get_rssi(void *_rxd, int *co, int *cm, int *cs)
{
    struct rx_desc_base *rxd;
    rxd = _rxd;
    *co = RX_PPDU_START_4_RSSI_COMB_OFFSET / sizeof(uint32_t);
    *cm = RX_PPDU_START_4_RSSI_COMB_MASK;
    *cs = RX_PPDU_START_4_RSSI_COMB_LSB;
    return (void *)&rxd->ppdu_start;
}

static u_int32_t _ar900b_rx_desc_check_desc_phy_data_type(qdf_nbuf_t head_msdu, uint8_t *rx_phy_data_filter)
{
    struct rx_desc_base *rx_desc;
    qdf_nbuf_t next_msdu = head_msdu;
    int        msdu_chained = 0;
    uint32_t   flag_phy_data = 0;
    uint32_t   *phyerr_mask;

    *rx_phy_data_filter = 0;

    while(next_msdu)
    {
          rx_desc = ar_rx_desc(next_msdu);
          msdu_chained = (((*(u_int32_t *) &rx_desc->frag_info) &
                                          RX_FRAG_INFO_0_RING2_MORE_COUNT_MASK) >>
                                          RX_FRAG_INFO_0_RING2_MORE_COUNT_LSB);

        if (((*(u_int32_t *) &rx_desc->attention) & (RX_ATTENTION_0_LAST_MPDU_MASK)) &&
            ((*(u_int32_t *) &rx_desc->attention) & (RX_ATTENTION_0_PHY_DATA_TYPE_MASK)))
        {
            flag_phy_data = 1;
            phyerr_mask = (uint32_t *)&rx_desc->ppdu_end.rx_phy_ppdu_end;

            if(phyerr_mask[0] & (RX_PHY_PPDU_END_0_ERROR_FALSE_RADAR_EXT_MASK | RX_PHY_PPDU_END_0_ERROR_RADAR_MASK)) {
                *rx_phy_data_filter  |= RX_PHY_DATA_RADAR;
            }

            break;
        }else
            next_msdu = qdf_nbuf_next(next_msdu);

        while(msdu_chained-- && next_msdu)
        {
            if (qdf_unlikely(!next_msdu))
            {
                break;
            }
            next_msdu = qdf_nbuf_next(next_msdu);
        }
    }

    if(flag_phy_data)
        return 0;
    else
        return 1;
}

static u_int32_t _ar900b_rx_desc_get_l3_header_padding(qdf_nbuf_t head_msdu)
{
	struct rx_desc_base *rx_desc = ar_rx_desc(head_msdu);
	return GET_L3_HEADER_PADDING(rx_desc);
}

static u_int32_t _ar900b_msdu_desc_phy_data_type(void *rx_desc)
{
   struct rx_desc_base *desc =
        (struct rx_desc_base *) rx_desc;
    int phy_data_type =
            (((*((u_int32_t *) &desc->attention)) &
             RX_ATTENTION_0_PHY_DATA_TYPE_MASK) >> RX_ATTENTION_0_PHY_DATA_TYPE_LSB);
    return phy_data_type;
}

#if RX_CHECKSUM_OFFLOAD
static void _ar900b_rx_desc_set_checksum_result(void *rx_desc,
        qdf_nbuf_t msdu);
#endif
static void _ar900b_rx_desc_parse_ppdu_start_status(void *rx_desc,
        struct ieee80211_rx_status *rs);

/* Unified function definitions */
#include "../include/rx_desc_unified.h"

/* definitions for size and offset functions */
AR_RX_DESC_FIELD_FUNCS(ar900b, attention)
AR_RX_DESC_FIELD_FUNCS(ar900b, frag_info)
AR_RX_DESC_FIELD_FUNCS(ar900b, mpdu_start)
AR_RX_DESC_FIELD_FUNCS(ar900b, msdu_start)
AR_RX_DESC_FIELD_FUNCS(ar900b, msdu_end)
AR_RX_DESC_FIELD_FUNCS(ar900b, mpdu_end)
AR_RX_DESC_FIELD_FUNCS(ar900b, ppdu_start)
AR_RX_DESC_FIELD_FUNCS(ar900b, ppdu_end)

FN_RX_DESC_OFFSETOF_FW_DESC(ar900b)
FN_RX_DESC_OFFSETOF_HDR_STATUS(ar900b)
FN_RX_DESC_SIZE(ar900b)
FN_RX_DESC_FW_DESC_SIZE(ar900b)
FN_RX_DESC_INIT(ar900b)
FN_RX_DESC_MPDU_WIFI_HDR_RETRIEVE(ar900b)
FN_RX_DESC_MPDU_DESC_SEQ_NUM(ar900b)
FN_RX_DESC_MPDU_DESC_PN(ar900b)
FN_RX_DESC_MPDU_DESC_FRDS(ar900b)
FN_RX_DESC_MPDU_DESC_TODS(ar900b)
FN_RX_DESC_MPDU_IS_ENCRYPTED(ar900b)
FN_RX_DESC_GET_ATTN_WORD(ar900b)
FN_RX_DESC_GET_PPDU_START(ar900b)
FN_RX_DESC_ATTN_MSDU_DONE(ar900b)
FN_RX_DESC_MSDU_LENGTH(ar900b)
FN_RX_DESC_MSDU_DESC_COMPLETES_MPDU(ar900b)
FN_RX_DESC_MSDU_HAS_WLAN_MCAST_FLAG(ar900b)
FN_RX_DESC_MSDU_IS_WLAN_MCAST(ar900b)
FN_RX_DESC_MPDU_WLAN_PREAMBLE(ar900b)
FN_RX_DESC_MSDU_IS_FRAG(ar900b)
FN_RX_DESC_MSDU_FIRST_MSDU_FLAG(ar900b)
FN_RX_DESC_MSDU_KEY_ID_OCTET(ar900b)
#if RX_CHECKSUM_OFFLOAD
FN_RX_DESC_SET_CHECKSUM_RESULT(ar900b)
#endif
FN_RX_DESC_DUMP(ar900b)
FN_RX_DESC_CHECK_DESC_MGMT_TYPE(ar900b)
FN_RX_DESC_CHECK_DESC_CTRL_TYPE(ar900b)
FN_RX_DESC_MSDU_DESC_MSDU_CHAINED(ar900b)
FN_RX_DESC_MSDU_DESC_TSF_TIMESTAMP(ar900b)
FN_RX_DESC_AMSDU_POP(ar900b)
FN_RX_DESC_PARSE_PPDU_START_STATUS(ar900b)
FN_RX_DESC_RESTITCH_MPDU_FROM_MSDUS(ar900b)
FN_RX_DESC_GET_VOWEXT_STATS(ar900b)
#if ATH_DATA_RX_INFO_EN || MESH_MODE_SUPPORT
FN_RX_DESC_UPDATE_PKT_INFO(ar900b)
FN_RX_DESC_UPDATE_MSDU_INFO(ar900b)
#endif

static uint32_t
_ar900b_rx_desc_is_fcs_err(void *_rxd)
{
    struct rx_desc_base *rxd;
    uint32_t *ptr;
    rxd = _rxd;
    ptr = (void *)&rxd->attention;
    return ptr[0] & RX_ATTENTION_0_FCS_ERR_MASK;
}

static void*
_ar900b_rx_desc_get_ppdu_end(void *_rxd)
{
    struct rx_desc_base *rxd;
    rxd = _rxd;
    return (void *)&rxd->ppdu_end;
}

struct ar_rx_desc_ops ar900b_rx_desc_ops = {
    .sizeof_rx_desc = _ar900b_rx_desc_size,
    .offsetof_attention = _ar900b_rx_desc_offsetof_attention,
    .offsetof_frag_info = _ar900b_rx_desc_offsetof_frag_info,
    .offsetof_mpdu_start = _ar900b_rx_desc_offsetof_mpdu_start,
    .offsetof_msdu_start = _ar900b_rx_desc_offsetof_msdu_start,
    .offsetof_msdu_end = _ar900b_rx_desc_offsetof_msdu_end,
    .offsetof_mpdu_end = _ar900b_rx_desc_offsetof_mpdu_end,
    .offsetof_ppdu_start = _ar900b_rx_desc_offsetof_ppdu_start,
    .offsetof_ppdu_end = _ar900b_rx_desc_offsetof_ppdu_end,
    .offsetof_fw_desc = _ar900b_rx_desc_offsetof_fw_desc,
    .offsetof_hdr_status = _ar900b_rx_desc_offsetof_hdr_status,
    .sizeof_attention = _ar900b_rx_desc_sizeof_attention,
    .sizeof_frag_info = _ar900b_rx_desc_sizeof_frag_info,
    .sizeof_mpdu_start = _ar900b_rx_desc_sizeof_mpdu_start,
    .sizeof_msdu_start = _ar900b_rx_desc_sizeof_msdu_start,
    .sizeof_msdu_end = _ar900b_rx_desc_sizeof_msdu_end,
    .sizeof_mpdu_end = _ar900b_rx_desc_sizeof_mpdu_end,
    .sizeof_ppdu_start = _ar900b_rx_desc_sizeof_ppdu_start,
    .sizeof_ppdu_end = _ar900b_rx_desc_sizeof_ppdu_end,
    .init_desc = _ar900b_rx_desc_init,
    .wifi_hdr_retrieve = _ar900b_rx_desc_mpdu_wifi_hdr_retrieve,
    .mpdu_desc_seq_num = _ar900b_rx_desc_mpdu_desc_seq_num,
    .mpdu_desc_pn = _ar900b_rx_desc_mpdu_desc_pn,
    .mpdu_desc_frds = _ar900b_rx_desc_mpdu_desc_frds,
    .mpdu_desc_tods = _ar900b_rx_desc_mpdu_desc_tods,
    .mpdu_is_encrypted = _ar900b_rx_desc_mpdu_is_encrypted,
    .get_attn_word = _ar900b_rx_desc_get_attn_word,
    .get_ppdu_start = _ar900b_rx_desc_get_ppdu_start,
    .attn_msdu_done = _ar900b_rx_desc_attn_msdu_done,
    .msdu_desc_msdu_length = _ar900b_rx_desc_msdu_length,
    .msdu_desc_completes_mpdu = _ar900b_rx_desc_msdu_desc_completes_mpdu,
    .msdu_has_wlan_mcast_flag = _ar900b_rx_desc_msdu_has_wlan_mcast_flag,
    .msdu_is_wlan_mcast = _ar900b_rx_desc_msdu_is_wlan_mcast,
    .ppdu_wlan_preamble = _ar900b_rx_desc_ppdu_wlan_preamble,
    .msdu_is_frag = _ar900b_rx_desc_msdu_is_frag,
    .msdu_first_msdu_flag = _ar900b_rx_desc_msdu_first_msdu_flag,
    .msdu_key_id_octet = _ar900b_rx_desc_msdu_key_id_octet,
    .dump_desc = _ar900b_rx_desc_dump,
    .check_desc_mgmt_type = _ar900b_rx_desc_check_desc_mgmt_type,
    .check_desc_ctrl_type = _ar900b_rx_desc_check_desc_ctrl_type,
#ifndef REMOVE_PKT_LOG
    .check_desc_phy_data_type = _ar900b_rx_desc_check_desc_phy_data_type,
#endif
    .get_l3_header_padding = _ar900b_rx_desc_get_l3_header_padding,
    .amsdu_pop = _ar900b_rx_desc_amsdu_pop,
    .restitch_mpdu_from_msdus = _ar900b_rx_desc_restitch_mpdu_from_msdus,
    .get_vowext_stats = _ar900b_rx_desc_get_vowext_stats,
    .msdu_desc_phy_data_type = _ar900b_msdu_desc_phy_data_type,
    .msdu_desc_msdu_chained = _ar900b_msdu_desc_msdu_chained,
    .msdu_desc_tsf_timestamp = _ar900b_msdu_desc_tsf_timestamp,
    .fw_rx_desc_size = _ar900b_fw_rx_desc_size,
#if ATH_DATA_RX_INFO_EN || MESH_MODE_SUPPORT
    .update_pkt_info = _ar900b_rx_desc_update_pkt_info,
    .update_msdu_info = _ar900b_rx_desc_update_msdu_info,
#endif
    .is_first_mpdu = _ar900b_rx_desc_is_first_mpdu,
    .is_last_mpdu = _ar900b_rx_desc_is_last_mpdu,
    .is_retry = _ar900b_rx_desc_is_retry,
    .get_rssi = _ar900b_rx_desc_get_rssi,
    .is_fcs_err = _ar900b_rx_desc_is_fcs_err,
    .get_ppdu_end = _ar900b_rx_desc_get_ppdu_end,
};

struct ar_rx_desc_ops* ar900b_rx_attach(struct ar_s *ar)
{
    /* Attach the function pointers table */
    ar->ar_rx_ops = &ar900b_rx_desc_ops;
    return ar->ar_rx_ops;
}

