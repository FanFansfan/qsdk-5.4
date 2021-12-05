/*
 * Copyright (c) 2014,2017, 2020 Qualcomm Innovation Center, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __RAWMODE_SIM_H__
#define __RAWMODE_SIM_H__

#include <qdf_nbuf.h>           /* qdf_nbuf_t */
#include <ieee80211.h>
#include <qdf_atomic.h>

#if !RAWSIM_DISABLE_RC_LOG
#define rawsim_err(params...) \
    QDF_TRACE_ERROR_RL_NO_FL(QDF_MODULE_ID_QDF, ## params)
#else
#define rawsim_err(params...) \
    QDF_TRACE_ERROR_NO_FL(QDF_MODULE_ID_ANY, ## params)
#endif /* RAWSIM_DISABLE_RC_LOG */

#define rawsim_info(params...) \
    QDF_TRACE_INFO_NO_FL(QDF_MODULE_ID_ANY, ## params)

#ifndef __ubicom32__
#define IEEE80211_ADDR_EQ(a1,a2)        (OS_MEMCMP(a1, a2, IEEE80211_ADDR_LEN) == 0)
#define IEEE80211_ADDR_COPY(dst,src)    OS_MEMCPY(dst, src, IEEE80211_ADDR_LEN)
#else
#define IEEE80211_ADDR_EQ(a1,a2)        (OS_MACCMP(a1, a2) == 0)
#define IEEE80211_ADDR_COPY(dst,src)    OS_MACCPY(dst, src)
#endif

/* Raw Mode simulation - conversion between Raw 802.11 format and other
 * formats.
 */

/* Max MSDU length supported in the simulation */
#define MAX_RAWSIM_80211_MSDU_LEN                  (1508)

/* Number of MSDUs to place in A-MSDU */
#define NUM_RAWSIM_80211_MSDUS_IN_AMSDU            (2)

#define L_GET_LLC_ETHTYPE(ptr) \
    (((struct llc*)((ptr)))->llc_un.type_snap.ether_type)

#define L_LLC_ETHTYPE_OFFSET \
    ((u_int8_t*)&(((struct llc*)(0))->llc_un.type_snap.ether_type) - \
     (u_int8_t*)0)

#define L_ETH_ETHTYPE_SIZE \
    (sizeof(((struct ether_header*)(0))->ether_type))

#define GET_UNCONSUMED_CNT(is_frag, psctx, nonfragcnt)  \
    ((is_frag)? (psctx)->unconsumed_cnt_total:(nonfragcnt))

#define RAWSIM_PRINT_TXRXLEN_ERR_CONDITION            (0)

/* Fragment stream processing */

/*
 * We keep a limit on the peek offset and number of bytes, for simplicity
 * so that we don't have to cross more than one nbuf boundary.
 */
#define RAW_RX_FRAGSTREAM_PEEK_OFFSET_MAX   \
                                (sizeof(struct ieee80211_qosframe_addr4) + \
                                 sizeof(struct ether_header) + \
                                 sizeof(struct llc))

#define RAW_RX_FRAGSTREAM_PEEK_NBYTES_MAX   (16)

/*
 * Context for processing read and peek operations on an nbuf fragment stream
 * corresponding to an MPDU.
 */
typedef struct _raw_rx_fragstream_ctx
{
    /* Whether this context is valid. */
    u_int8_t is_valid;

    /* Head nbuf for fragment stream */
    qdf_nbuf_t list_head;

    /* Total 802.11 header size. To be determined by user of context. */
    u_int16_t headersize;

    /* Total 802.11 trailer size. To be determined by user of context. */
    u_int16_t trailersize;

    /* Current nbuf being used */
    qdf_nbuf_t currnbuf;

    /*
     * Position in current nbuf from where next read consumption/peek should
     * start
     */
    u_int8_t *currnbuf_ptr;

    /* Next nbuf to be used */
    qdf_nbuf_t nextnbuf;

    /* Count of unconsumed bytes in nbuf currently being processed */
    u_int32_t unconsumed_cnt_curr;

    /* Count of unconsumed bytes in all fragment nbufs put together */
    u_int32_t unconsumed_cnt_total;
} raw_rx_fragstream_ctx;

#define ENTIRE_PKT_DUMP      0x2
#define HEADERS_ONLY_DUMP    0x1
#define FIXED_NUM_ENCAP_DUMP 0x1
#define FIXED_NUM_DECAP_DUMP 0x2

#define RAWSIM_PKT_HEXDUMP(_buf, _len)                                  \
        qdf_trace_hex_ascii_dump(QDF_MODULE_ID_ANY,                     \
                                 QDF_TRACE_LEVEL_INFO, _buf, _len);     \

#define RAWSIM_TXRX_LIST_APPEND(head, tail, elem)            \
do {                                                         \
    if (!(head)) {                                           \
        (head) = (elem);                                     \
    } else {                                                 \
        qdf_nbuf_set_next((tail), (elem));                   \
    }                                                        \
    (tail) = (elem);                                         \
} while (0)

/* Delete a sub linked list starting at subhead and ending at subtail, from in
 * within a main linked list starting at head and ending at tail, with prev
 * pointing to the nbuf prior to subhead.  For efficiency, it is the
 * responsibility of the caller to ensure that the arguments are valid. tail's
 * next must be set to NULL. If subhead is equal to head, then prev must be
 * NULL.
 */
#define RAWSIM_TXRX_SUBLIST_DELETE(_head, _tail, _prev, _subhead, _subtail)  \
do {                                                                         \
    qdf_nbuf_t next = NULL;                                                  \
    qdf_nbuf_t nbuf = (_subhead);                                            \
                                                                             \
    if ((_head) == (_subhead)) {                                             \
        (_head) = qdf_nbuf_next((_subtail));                                 \
    }                                                                        \
                                                                             \
    if (!(_head)) {                                                          \
        (_tail) = NULL;                                                      \
    } else if ((_tail) == (_subtail)) {                                      \
        (_tail) = (_prev);                                                   \
        if ((_tail)) {                                                       \
            qdf_nbuf_set_next((_tail), NULL);                                \
        }                                                                    \
    } else if ((_prev)) {                                                    \
        qdf_nbuf_set_next((_prev), qdf_nbuf_next((_subtail)));               \
    }                                                                        \
                                                                             \
    while(nbuf != (_subtail))                                                \
    {                                                                        \
        next = qdf_nbuf_next(nbuf);                                          \
        qdf_nbuf_free(nbuf);                                                 \
        nbuf = next;                                                         \
    }                                                                        \
                                                                             \
    qdf_nbuf_free((_subtail));                                               \
} while (0)

/* Delete nbuf from in within a linked list starting at head and ending at tail,
 * with prev pointing to the element prior to nbuf.  For efficiency, it is the
 * responsibility of the caller to ensure that the arguments are valid. tail's
 * next must be set to NULL. If nbuf is equal to head, then prev must be NULL.
 */
#define RAWSIM_TXRX_NODE_DELETE(_head, _tail, _prev, _nbuf)                  \
do {                                                                         \
    if ((_head) == (_nbuf)) {                                                \
        (_head) = qdf_nbuf_next((_nbuf));                                    \
    }                                                                        \
                                                                             \
    if (!(_head)) {                                                          \
        (_tail) = NULL;                                                      \
    } else if ((_tail) == (_nbuf)) {                                         \
        (_tail) = (_prev);                                                   \
        if ((_tail)) {                                                       \
            qdf_nbuf_set_next((_tail), NULL);                                \
        }                                                                    \
    } else if ((_prev)) {                                                    \
        qdf_nbuf_set_next((_prev), qdf_nbuf_next((_nbuf)));                  \
    }                                                                        \
                                                                             \
    qdf_nbuf_free((_nbuf));                                                  \
} while (0)

/* Packet format configuration for a given interface or radio.
 * This must correspond to ordering in the enumeration htt_pkt_type.
 */
enum sim_pkt_type {
    pkt_type_raw = 0,
    pkt_type_native_wifi = 1,
    pkt_type_ethernet = 2,
};

enum {
    raw_sec_mcast = 0,
    raw_sec_ucast
};

enum raw_sec_type {
    raw_sec_type_none,
    raw_sec_type_wep128,
    raw_sec_type_wep104,
    raw_sec_type_wep40,
    raw_sec_type_tkip,
    raw_sec_type_tkip_nomic,
    raw_sec_type_aes_ccmp,
    raw_sec_type_wapi,
    raw_sec_type_aes_ccmp_256,
    raw_sec_type_aes_gcmp,
    raw_sec_type_aes_gcmp_256,

    /* keep this last! */
    raw_num_sec_types
};

struct rawsim_ast_entry {
    uint8_t ast_found;
    uint8_t mac_addr[6];
};


/* Statistics for the Raw Mode simulation module. These do not cover events
 * occurring outside the modules (such as higher layer failures to process a
 * successfully decapped MPDU, etc.)*/

struct rawmode_pkt_sim_rxstats {
    /* Rx Side simulation module statistics */

    /* Decap successes */

    /* Number of non-AMSDU bearing MPDUs decapped */
    u_int64_t num_rx_mpdu_noamsdu;

    /* Number of A-MSDU bearing MPDUs (fitting within single nbuf)
       decapped */
    u_int64_t num_rx_smallmpdu_withamsdu;

    /* Number of A-MSDU bearing MPDUs (requiring multiple nbufs) decapped */
    u_int64_t num_rx_largempdu_withamsdu;


    /* Decap errors */

    /* Number of MSDUs (contained in A-MSDU) with invalid length field */
    u_int64_t num_rx_inval_len_msdu;

    /* Number of A-MSDU bearing MPDUs which are shorter than expected from
       parsing A-MSDU fields */
    u_int64_t num_rx_tooshort_mpdu;

    /* Number of A-MSDU bearing MPDUs received which are longer than
       expected from parsing A-MSDU fields */
    u_int64_t num_rx_toolong_mpdu;

    /* Number of non-AMSDU bearing MPDUs (requiring multiple nbufs) seen
       (unhandled) */
    u_int64_t num_rx_chainedmpdu_noamsdu;

    /* Add anything else of interest */
};

struct rawmode_pkt_sim_txstats {
    /* Tx Side simulation module statistics */

    /* Number of non-AMSDU bearing MPDUs encapped */
    u_int64_t num_tx_mpdu_noamsdu;

    /* Number of A-MSDU bearing MPDUs encapped */
    u_int64_t num_tx_mpdu_withamsdu;

    /* Add anything else of interest */
};

struct rawmode_sim_cfg {
#if MESH_MODE_SUPPORT
    u_int8_t mesh_mode;
    u_int32_t mhdr;
    u_int32_t mdbg;
    u_int8_t mhdr_len;
    u_int8_t bssid_mesh[QDF_MAC_ADDR_SIZE];
#endif
    uint8_t vdev_id;
    uint8_t opmode;
    u_int8_t rawmodesim_txaggr:4,
             rawmodesim_debug_level:2;
    bool privacyEnabled;
    u_int8_t tx_encap_type;
    u_int8_t rx_decap_type;
    u_int8_t rawmode_pkt_sim;
};

struct rawmode_sim_ctxt {
#if MESH_MODE_SUPPORT
    u_int8_t mesh_mode;
    u_int32_t mhdr;
    u_int32_t mdbg;
    u_int8_t mhdr_len;
    u_int8_t bssid_mesh[QDF_MAC_ADDR_SIZE];
#endif
    uint8_t vdev_id;
    uint8_t opmode;
    u_int8_t rawmodesim_txaggr:4,
             rawmodesim_debug_level:2,
             fixed_frm_cnt_flag:2;
    qdf_atomic_t num_encap_frames;
    qdf_atomic_t num_decap_frames;
    bool privacyEnabled;
    u_int8_t tx_encap_type;
    u_int8_t rx_decap_type;
    u_int8_t rawmode_pkt_sim;
    struct rawmode_pkt_sim_rxstats rxstats;
    struct rawmode_pkt_sim_txstats txstats;
    qdf_spinlock_t tx_encap_lock;
    qdf_nbuf_t rawsim_nbuf_tx_list_head;
    qdf_nbuf_t rawsim_nbuf_tx_list_tail;
    u_int8_t rawsim_tx_frag_count;
};

typedef struct rawmode_sim_ctxt* rawsim_ctxt;
struct rawsim_ops {
    rawsim_ctxt (*create_rawsim_ctxt)(void);
    void (*rx_decap)(rawsim_ctxt ctxt,
                     qdf_nbuf_t *pdeliver_list_head,
                     qdf_nbuf_t *pdeliver_list_tail,
                     uint8_t *peer_mac,
                     uint32_t sec_type,
                     uint32_t auth_type);
    int (*tx_encap)(rawsim_ctxt ctxt,
                    qdf_nbuf_t *pnbuf,
                    u_int8_t *bssid,
                    struct rawsim_ast_entry ast_entry);
    void (*print_stats)(rawsim_ctxt ctxt);
    void (*clear_stats)(rawsim_ctxt ctxt);
    int (*update_config)(struct rawmode_sim_cfg cfg, rawsim_ctxt ctxt);
    int (*update_encap_frame_count)(rawsim_ctxt ctxt,
                                    int frame_count,
                                    u_int8_t flag);
    int (*update_decap_frame_count)(rawsim_ctxt ctxt,
                                    int frame_count,
                                    u_int8_t flag);
    void (*delete_rawsim_ctxt)(rawsim_ctxt ctxt);
};

/*
 * Cipher types
 */
typedef enum wlan_crypto_cipher_type {
    WLAN_CRYPTO_CIPHER_WEP             = 0,
    WLAN_CRYPTO_CIPHER_TKIP            = 1,
    WLAN_CRYPTO_CIPHER_AES_OCB         = 2,
    WLAN_CRYPTO_CIPHER_AES_CCM         = 3,
    WLAN_CRYPTO_CIPHER_WAPI_SMS4       = 4,
    WLAN_CRYPTO_CIPHER_CKIP            = 5,
    WLAN_CRYPTO_CIPHER_AES_CMAC        = 6,
    WLAN_CRYPTO_CIPHER_AES_CCM_256     = 7,
    WLAN_CRYPTO_CIPHER_AES_CMAC_256    = 8,
    WLAN_CRYPTO_CIPHER_AES_GCM         = 9,
    WLAN_CRYPTO_CIPHER_AES_GCM_256     = 10,
    WLAN_CRYPTO_CIPHER_AES_GMAC        = 11,
    WLAN_CRYPTO_CIPHER_AES_GMAC_256    = 12,
    WLAN_CRYPTO_CIPHER_WAPI_GCM4       = 13,
    WLAN_CRYPTO_CIPHER_FILS_AEAD       = 14,
    WLAN_CRYPTO_CIPHER_WEP_40          = 15,
    WLAN_CRYPTO_CIPHER_WEP_104         = 16,
    WLAN_CRYPTO_CIPHER_NONE            = 17,
    WLAN_CRYPTO_CIPHER_MAX             = (WLAN_CRYPTO_CIPHER_NONE + 1),
    WLAN_CRYPTO_CIPHER_INVALID,
} wlan_crypto_cipher_type;

/* Auth types */
typedef enum wlan_crypto_auth_mode {
    WLAN_CRYPTO_AUTH_NONE     = 0,
    WLAN_CRYPTO_AUTH_OPEN     = 1,
    WLAN_CRYPTO_AUTH_SHARED   = 2,
    WLAN_CRYPTO_AUTH_8021X    = 3,
    WLAN_CRYPTO_AUTH_AUTO     = 4,
    WLAN_CRYPTO_AUTH_WPA      = 5,
    WLAN_CRYPTO_AUTH_RSNA     = 6,
    WLAN_CRYPTO_AUTH_CCKM     = 7,
    WLAN_CRYPTO_AUTH_WAPI     = 8,
    WLAN_CRYPTO_AUTH_SAE      = 9,
    WLAN_CRYPTO_AUTH_FILS_SK  = 10,
    /** Keep WLAN_CRYPTO_AUTH_MAX at the end. */
    WLAN_CRYPTO_AUTH_MAX      = WLAN_CRYPTO_AUTH_FILS_SK,
} wlan_crypto_auth_mode;

#if MESH_MODE_SUPPORT
#define NUM_MESH_CONFIG_RATES 1 /* should not be greater than 4 */

#if NUM_MESH_CONFIG_RATES >  4
#error "Num mesh config rates should not be greater than 4!!!"
#endif

struct metahdr_rate_info {
    uint8_t mcs;
    uint8_t nss;
    uint8_t preamble_type;
    uint8_t max_tries;
};

struct meta_hdr_s {
    uint8_t magic;
    uint8_t flags;
    uint8_t channel; /* Operating channel */
    uint8_t keyix;

    uint8_t rssi;
    uint8_t silence;
    uint8_t power;
    uint8_t retries;

    struct metahdr_rate_info rate_info[NUM_MESH_CONFIG_RATES];

    uint8_t band; /* Operating band */

    uint8_t unused[3];
};

#define METAHDR_FLAG_TX                 (1<<0) /* packet transmission */
#define METAHDR_FLAG_TX_FAIL            (1<<1) /* transmission failed */
#define METAHDR_FLAG_TX_USED_ALT_RATE   (1<<2) /* used alternate bitrate */
#define METAHDR_FLAG_INFO_UPDATED       (1<<3)
#define METAHDR_FLAG_AUTO_RATE          (1<<5)
#define METAHDR_FLAG_NOENCRYPT          (1<<6)
#define METAHDR_FLAG_NOQOS              (1<<7)
#endif
#endif /* _RAWMODE_SIM__H_ */
