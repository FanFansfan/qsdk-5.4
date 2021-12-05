/*
 * Copyright (c) 2011, 2021 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 *
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Description:  Header file for the apstats application.
 *
 *
 * Version    :  0.1
 * Created    :  Thursday, June 30, 2011
 * Revision   :  none
 * Compiler   :  gcc
 *
 */
#ifndef APSTATS_H
#define APSTATS_H

#include <net/ethernet.h>
#include <qcatools_lib.h>
#include <cdp_txrx_stats_struct.h>
#include <athrs_ctrl.h>
#if ATH_PERF_PWR_OFFLOAD
#include <athtypes_linux.h>
#include <ol_ath_ucfg.h>
#include <ol_txrx_stats.h>
#include <cdp_txrx_extd_struct.h>
#endif

#include <ieee80211_external.h>

enum {
    HAL_PHYERR_UNDERRUN             = 0,    /* Transmit underrun */
    HAL_PHYERR_TIMING               = 1,    /* Timing error */
    HAL_PHYERR_PARITY               = 2,    /* Illegal parity */
    HAL_PHYERR_RATE                 = 3,    /* Illegal rate */
    HAL_PHYERR_LENGTH               = 4,    /* Illegal length */
    HAL_PHYERR_RADAR                = 5,    /* Radar detect */
    HAL_PHYERR_SERVICE              = 6,    /* Illegal service */
    HAL_PHYERR_TOR                  = 7,    /* Transmit override receive */
    /* NB: these are specific to the 5212 */
    HAL_PHYERR_OFDM_TIMING          = 17,    /* */
    HAL_PHYERR_OFDM_SIGNAL_PARITY   = 18,    /* */
    HAL_PHYERR_OFDM_RATE_ILLEGAL    = 19,    /* */
    HAL_PHYERR_OFDM_LENGTH_ILLEGAL  = 20,    /* */
    HAL_PHYERR_OFDM_POWER_DROP      = 21,    /* */
    HAL_PHYERR_OFDM_SERVICE         = 22,    /* */
    HAL_PHYERR_OFDM_RESTART         = 23,    /* */
    HAL_PHYERR_FALSE_RADAR_EXT      = 24,    /* Radar detect */

    HAL_PHYERR_CCK_TIMING           = 25,    /* */
    HAL_PHYERR_CCK_HEADER_CRC       = 26,    /* */
    HAL_PHYERR_CCK_RATE_ILLEGAL     = 27,    /* */
    HAL_PHYERR_CCK_SERVICE          = 30,    /* */
    HAL_PHYERR_CCK_RESTART          = 31,    /* */
    HAL_PHYERR_CCK_LENGTH_ILLEGAL   = 32,   /* */
    HAL_PHYERR_CCK_POWER_DROP       = 33,   /* */

    HAL_PHYERR_HT_CRC_ERROR         = 34,   /* */
    HAL_PHYERR_HT_LENGTH_ILLEGAL    = 35,   /* */
    HAL_PHYERR_HT_RATE_ILLEGAL      = 36,   /* */
    HAL_PHYERR_SPECTRAL             = 38,   /* Spectral scan packet -- Only Kiwi and later */
};

/**
 * Application configuration - populated based on command line arguments.
 */
typedef struct
{
    apstats_level_t     level;
    bool is_recursion;
    char                ifname[IFNAMSIZ];
    struct ether_addr   stamacaddr;
    void (*callback)(apstats_obj_t *);
    void *token;
    /*
     * Token can be passed by the caller which is passed back via the callback
     * This can be useful in the caller to match the callback function with
     * the API invocation
     */
    void (*callback_token)(apstats_obj_t *obj, void *token);
} apstats_config_t;

/**
 * Node (STA) level stats.
 */
typedef struct _nodelevel_stats_t
{
    /* Statistics. */

    apstats_obj_t obj;
    u_int64_t tx_data_packets;       /**< No. of data frames sent to STA. */
    u_int64_t tx_data_bytes;         /**< No. of data bytes sent to STA. */
#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    u_int64_t tx_data_packets_success;
    u_int64_t tx_data_bytes_success;
#endif
    u_int64_t tx_data_wme[WME_NUM_AC]; /** No. of data frames transmitted
					    per AC */

    u_int64_t rx_data_wme[WME_NUM_AC]; /** No. of data frames received
					    per AC */

    u_int64_t rx_data_packets;       /**< No. of data frames received from STA. */
    u_int64_t rx_data_bytes;         /**< No. of data bytes received from STA. */

#if ATH_SUPPORT_EXT_STAT
    u_int64_t tx_bytes_rate;         /* transmitted bytes for last one second */
    u_int64_t tx_data_rate;          /* transmitted packets for last one second */
    u_int64_t rx_bytes_rate;         /* received bytes for last one second */
    u_int64_t rx_data_rate;          /* received packets for last one second */
#endif

#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    u_int64_t rx_ucast_data_packets;
    u_int64_t rx_ucast_data_bytes;
    u_int64_t rx_mcast_data_packets;
    u_int64_t rx_mcast_data_bytes;
#endif

    u_int64_t tx_ucast_data_packets; /**< No. of unicast data frames sent to
                                          STA. */
    u_int32_t ru_tx[RU_INDEX_MAX];
    u_int32_t mcs_tx[DOT11_MAX][IEEE80211_MAX_MCS];
    u_int32_t ru_rx[RU_INDEX_MAX];
    u_int32_t mcs_rx[DOT11_MAX][MAX_MCS];

#if UMAC_SUPPORT_STA_STATS_ENHANCEMENT
    u_int64_t tx_ucast_data_bytes;
    u_int64_t tx_mcast_data_packets;
    u_int64_t tx_mcast_data_bytes;
    u_int64_t tx_bcast_data_packets;
    u_int64_t tx_bcast_data_bytes;
#endif
    u_int64_t last_per;		     /**< last Packet Error Rate */
    u_int32_t tx_rate;               /**< Average link rate used for
                                          transmissions to STA. */
    u_int32_t rx_rate;               /**< Average link rate used by STA to transmit
                                          to us. */

    u_int64_t host_discard;

    u_int64_t rx_micerr;             /**< No. of MIC errors in frames received
                                          from STA. */
    u_int64_t rx_decrypterr;         /**< No. of decryption errors in frames
                                          received from STA. */
    u_int64_t rx_err;                /**< No. of receive errors for this STA. */

    u_int64_t tx_discard;            /**< No. of frames destined to STA whose
                                          transmission failed (Note: Not number
                                          of failed attempts). */
    u_int64_t packets_queued;
    u_int64_t tx_failed;             /** failed tx counter */
    u_int64_t last_tx_rate;
    u_int64_t last_rx_rate;
    u_int64_t last_rx_mgmt_rate;     /** last received rate for mgmt frame */

    u_int64_t num_rx_mpdus;          /**< Number of mpdus received */
    u_int64_t num_rx_ppdus;          /**< Number of ppdus received */
    u_int64_t num_rx_retries;        /**< Number of rx retries */

    u_int8_t  rx_rssi;               /**< Rx RSSI of last frame received from
                                          this STA. */

    u_int8_t  rx_mgmt_rssi;          /**< Rx RSSI of last mgmt frame received from
                                          this STA. */
#if ATH_SUPPORT_EXT_STAT
    u_int8_t  chwidth;               /* communication band width with this STA */
    u_int32_t htcap;                 /* htcap of this STA */
    u_int32_t vhtcap;                /* vhtcap of this STA */
#endif

    u_int64_t tx_mgmt;               /**< No. of mgmt frames transmitted to STA */
    u_int64_t rx_mgmt;               /**< No. of mgmt frames received from STA */


#if ATH_PERF_PWR_OFFLOAD
    u_int32_t ack_rssi[MAX_CHAINS]; /**< Rx RSSI of ack frames received from
                                          this STA. */
#endif

    u_int32_t ppdu_tx_rate;         /* Avg per ppdu tx rate to the STA */
    u_int32_t ppdu_rx_rate;         /* Avg per ppdu rx rate from the STA */
    u_int8_t ol_enable;

    struct ieee80211req_sta_info si;

    /* Miscellaneous info required for application logic. */

    struct ether_addr macaddr;       /**< MAC address of STA. */

    uint64_t excretries[WME_NUM_AC];  /**< excessive retries */
 /* No of packets not trans successfully due to no of retrans attempts exceeding 802.11 retry limit */
    uint32_t failed_retry_count;
    /* No of packets that were successfully transmitted after one or more retransmissions */
    uint32_t retry_count;
    /* No of packets that were successfully transmitted after more than one retransmission */
    uint32_t multiple_retry_count;

#ifdef VDEV_PEER_PROTOCOL_COUNT
    uint16_t icmp_tx_ingress;
    uint16_t icmp_tx_egress;
    uint16_t icmp_rx_ingress;
    uint16_t icmp_rx_egress;

    uint16_t arp_tx_ingress;
    uint16_t arp_tx_egress;
    uint16_t arp_rx_ingress;
    uint16_t arp_rx_egress;

    uint16_t eap_tx_ingress;
    uint16_t eap_tx_egress;
    uint16_t eap_rx_ingress;
    uint16_t eap_rx_egress;
#endif
    /* TWT stats */
#if WLAN_SUPPORT_TWT
    u_int64_t tx_data_packets_success_twt;
    u_int64_t rx_data_packets_twt;   /** num of data frames received from STA in TWT session. */
    uint32_t twt_event_type; /* TWT session type */
    uint32_t twt_flow_id:16, /* TWT flow id */
             twt_bcast:1,    /* Broadcast TWT */
             twt_trig:1,     /* TWT trigger */
             twt_announ:1;   /* TWT announcement */
    uint32_t twt_dialog_id;  /* TWT diag ID */
    uint32_t twt_wake_dura_us; /* Wake time duration in us */
    uint32_t twt_wake_intvl_us; /* Interval between wake perions in us */
    uint32_t twt_sp_offset_us;  /* Time until first TWT SP occurs */
#endif
} nodelevel_stats_t;

/**
 * AP level stats.
 */
typedef struct
{
    /* WLAN statistics. */

    apstats_obj_t obj;
    u_int64_t tx_data_packets;      /**< No. of data frames transmitted. */
    u_int64_t tx_data_bytes;        /**< No. of data bytes transmitted. */
    u_int64_t rx_data_packets;      /**< No. of data frames received. */
    u_int64_t rx_data_bytes;        /**< No. of data bytes received. */

    u_int64_t tx_ucast_data_packets; /**< No. of unicast data frames
                                          transmitted. */
    u_int64_t tx_mbcast_data_packets;/**< No. of multicast/broadcast data frames
                                          transmitted. */

    u_int8_t  txrx_rate_available;  /**< Whether Average Tx/Rx rate information
                                         is available for the AP (depends on
                                         whether the information is available
                                         for at least one of the radios). */
    u_int32_t tx_rate;              /**< Average link rate of transmissions. */
    u_int32_t rx_rate;              /**< Average link rate at which frames
                                         were received. */

    u_int8_t  res_util_enab;        /**< Whether Resource Utilization measurement
                                         is available (depends on whether Channel
                                         Utilization is enabled for all
                                         radios). */
    u_int16_t res_util;             /**< Resource Utilization (0-255). This is
                                         the average of Channel Utilization
                                         figures across radios. */

    u_int64_t rx_phyerr;            /**< No. of PHY errors in frames received. */
    u_int64_t rx_crcerr;            /**< No. of CRC errors in frames received. */
    u_int64_t rx_micerr;            /**< No. of MIC errors in frames received. */
    u_int64_t rx_decrypterr;        /**< No. of decryption errors in frames
                                         received. */
    u_int64_t rx_err;               /**< No. of receive errors. */

    u_int64_t tx_discard;           /**< No. of frames whose transmission
                                         failed. (Note: Not number of failed
                                         attempts). */
    u_int64_t tx_err;               /**< No. of tx errors */

    u_int8_t  thrput_enab;          /**< Whether in-driver throughput measurement
                                         is available (depends on whether in-driver
                                         throughput measurement is enabled for at
                                         least one of the radios). */
    u_int32_t thrput;               /**< Throughput in kbps. This is the sum of
                                         of throughput values across radios. */

    u_int8_t total_per;             /**< PER measured from start of operation.
                                         This is the average of total PER values
                                         across radios. */
    u_int8_t prdic_per_enab;        /**< Whether periodic PER measurement is
                                         available (depends on whether periodic
                                         PER measurement is enabled for
                                         all radios). */
    u_int8_t prdic_per;             /**< Average of periodic PER values across
                                         all radios. */

    /* Miscellaneous info required for application logic. */
}  aplevel_stats_t;


/*
 * apstats_get: Collect the whole tree of statistics below what ever the level
 *              and interface specified
 *
 * @col: collector context
 * @config: apstats config (config includes the callback to be called)
 * return 0 on success otherwise negative value on failure
 */
int apstats_get(void *col, apstats_config_t *config);

/*
 * apstats_print: Print the apstats
 *
 * @fp: File where output will be printed
 * @obj: object that needs to be printed
 * @is_recursion: Whether object nodes below the object needs to be printed
 *
 * return void
 */
void apstats_print(FILE *fp, apstats_obj_t *obj,
                   bool is_recursion);

/*
 * apstats_get_next: Get the next object in the object tree
 *
 * @obj: Current object
 * return pointer to the next object, NULL if no more objects
 */

apstats_obj_t *apstats_get_next(apstats_obj_t *obj);

/*
 * apstats_destroy: Destroy the apstats objects, once they are used
 *
 * @obj: obj pointer that was given as part of apstats_get callback
 * return void
 */
void apstats_destroy(apstats_obj_t *obj);
#endif /* APSTATS_H */

