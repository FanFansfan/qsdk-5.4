/*
 * Copyright (c) 2013,2015,2017,2019-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2013, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _IEEE80211_ACS_INTERNAL_H
#define _IEEE80211_ACS_INTERNAL_H



#define NF_WEIGHT_FACTOR (2)
#define CHANLOAD_WEIGHT_FACTOR (4)
#define CHANLOAD_INCREASE_AVERAGE_RSSI (40)
#define ACS_NOISE_FLOOR_THRESH_MIN -85 /* noise floor threshold to detect presence of video bridge */
#define ACS_NOISE_FLOOR_THRESH_MAX -65 /* noise floor threshold to detect presence of video bridge */
#define ACS_DEFAULT_SR_LOAD 4

/* Parameters to derive secondary channels */
#define UPPER_FREQ_SLOT 1
#define LOWER_FREQ_SLOT -1
#define SEC_40_LOWER -6
#define SEC_40_UPPER -2
#define SEC20_OFF_2 2
#define SEC20_OFF_6 6
#define SEC_80_1 2
#define SEC_80_2 6
#define SEC_80_3 10
#define SEC_80_4 14
#define PRI_80_CENTER 8
/* Use a RSSI threshold of 10dB(?) above the noise floor*/
#define SPECTRAL_EACS_RSSI_THRESH  30 

#define ACS_11NG_NOISE_FLOOR_REJ (-80)
#define ACS_11NA_NOISE_FLOOR_REJ (-80)
#define IEEE80211_MAX_ACS_EVENT_HANDLERS WLAN_UMAC_PDEV_MAX_VDEVS
#define LIMITED_OBSS_CHECK 1
#define DEBUG_EACS 1
#define MIN_DWELL_TIME        200  /* scan param to be used during acs scan 200 ms */
#define MAX_DWELL_TIME        300  /* scan param to be used during acs scan 300 ms */

#define ACS_TX_POWER_OPTION_TPUT 1
#define ACS_TX_POWER_OPTION_RANGE 2


#define NF_INVALID -254

#define SEC_TO_MSEC(_t ) (_t * 1000) /* Macro to convert SEC to MSEC */
/* To restrict number of hoppings in 2.4 Gh used by channel hopping algorithm */
#define ACS_CH_HOPPING_MAX_HOP_COUNT  3 

/*cmd value to enhance read ablity between ic and ath layer */
#define IEEE80211_ENABLE_NOISE_DETECTION  1 /*from ic to enable/disable noise detection */ 
#define IEEE80211_NOISE_THRESHOLD         2 /* ic->ath noise threshold val set /get*/ 
#define IEEE80211_GET_COUNTER_VALUE       3 /* counter threshold value from ic->ath */  
#define CHANNEL_HOPPING_LONG_DURATION_TIMER 15*60 /* 15 min */
#define CHANNEL_HOPPING_NOHOP_TIMER 1*60 /* 1 min */
#define CHANNEL_HOPPING_CNTWIN_TIMER 5 /* 5 sec  */
#define CHANNEL_HOPPING_VIDEO_BRIDGE_THRESHOLD -90

#define MAX_32BIT_UNSIGNED_VALUE 0xFFFFFFFFU

#if DEBUG_EACS
extern uint32_t acs_dbg_mask;

/*
 * acs_info_dbglvl:
 * Debug levels for the ACS debug trace.
 *
 * NOTE: BASE is guaranteed to stay within watchdog timer limitations but
 * other prints need to enabled with caution.
 */
enum acs_dbglvl {
    ACS_DBG_EXT      = 0x0000, /* Always enabled for all external APIs */
    ACS_DBG_BASE     = 0x0001, /* Base prints */
    ACS_DBG_RSSI     = 0x0002, /* RSSI stats */
    ACS_DBG_ADJCHAN  = 0x0004, /* Adjacent channel stats collection */
    ACS_DBG_NF       = 0x0008, /* Noise floor stats */
    ACS_DBG_CHLOAD   = 0x0010, /* Channel load stats */
    ACS_DBG_REGPOWER = 0x0020, /* Regulatory tx power stats */
    ACS_DBG_OBSS     = 0x0040, /* OBSS/Coex checking */
    ACS_DBG_SCAN     = 0x0080, /* Scan handling */
    ACS_DBG_BLOCK    = 0x0100, /* Blocking logic */
    ACS_DBG_FILTER   = 0x0200, /* EACS-plus filtering logic */
    ACS_DBG_CHLST    = 0x0400, /* Channel list population */
    ACS_DBG_MAX      = 0xFFFF, /* All prints */
};

#define acs_err(args...)    qdf_err(args)
#define acs_info(log_level, args...)                                \
    do {                                                            \
        if ((ACS_DBG_ ## log_level == ACS_DBG_EXT) ||     \
            (acs_dbg_mask & (ACS_DBG_ ## log_level))) {   \
            qdf_info("[" #log_level "] " args);                     \
        }                                                           \
    } while(0)

#define acs_nofl_err(args...)    qdf_nofl_err(args)
#define acs_nofl_info(log_level, args...)                           \
    do {                                                            \
        if ((ACS_DBG_ ## log_level == ACS_DBG_EXT) ||     \
            (acs_dbg_mask & (ACS_DBG_ ## log_level))) {   \
            qdf_nofl_info(args);                                    \
        }                                                           \
    } while(0)
#else
#define acs_err(args...)
#define acs_info(log_level, args...)
#define acs_nofl_err(args...)
#define acs_nofl_info(log_level, args...)
#endif

/* Added to avoid Static overrun Coverity issues */
#define IEEE80211_ACS_CHAN_MAX IEEE80211_CHAN_MAX+1

/* Number of 20Mhz channels including HT40+ HT40- channel combinations. */
#define IEEE80211_ACS_ENH_CHAN_MAX 2*NUM_CHANNELS

struct acs_user_chan_list {
    u_int32_t uchan[IEEE80211_ACS_CHAN_MAX];    /* max user channels */
    u_int32_t uchan_cnt;
};

typedef struct acs_bchan_list_r {
    u_int32_t uchan[IEEE80211_CHAN_MAX];    /* max user channels */
    u_int32_t uchan_cnt;
} acs_bchan_list_t;

struct acs_scan_req_param_t {
    u_int8_t acs_scan_report_active;
    u_int8_t acs_scan_report_pending;
    u_int32_t mindwell;
    u_int32_t maxdwell;
    u_int8_t scan_mode;
    u_int32_t rest_time;
    u_int32_t idle_time;
    u_int32_t max_scan_time;
};
struct acs_ch_hopping_param_t {
    u_int32_t long_dur;
    u_int32_t nohop_dur;
    u_int32_t cnt_dur;
    u_int32_t cnt_thresh;
    int32_t noise_thresh;
};

struct acs_ch_hopping_t {
    struct acs_ch_hopping_param_t param;
    os_timer_t ch_long_timer;  /* Long timer */
    os_timer_t ch_nohop_timer; /* No hop timer */
    os_timer_t ch_cntwin_timer; /*counter window timer*/
    u_int32_t  ch_max_hop_cnt; /*we should not hop for more than this counter */
    bool       ch_nohop_timer_active;
    bool       ch_hop_triggered; /*To mark channel hopping is trying to change channel */
};

struct acs_srp_info_s {
    uint8_t srp_allowed:1,
            srp_obsspd_allowed:1;

    uint8_t srp_nonsrg_obss_pd_max_offset;
    uint8_t srp_srg_obss_pd_min_offset;
    uint8_t srp_srg_obss_pd_max_offset;
};

/* NOTE: This macro corresponds to macro ACS_RANK_DESC_DBG_LEN, Please change
 * it aswell if changing this.
 */
#define ACS_RANK_DESC_LEN 80

/* ACS Channel Ranking structure
 * rank: Channel Rank
 * desc: Reason in case of no rank
 */
typedef struct acs_rank {
    u_int32_t rank;
    char desc[ACS_RANK_DESC_LEN];
}acs_rank_t;

/**
 * struct acs_last_chutil - keeps track of last recorded channel utilization
 * @ieee_chan: channel number
 * @ch_util: last recorded chan util for ieee_chan
 */
struct acs_last_chutil {
    uint16_t ieee_chan;
    uint16_t ch_util;
};

/**
 * struct acs_last_event - keeps track of last acs activity/event
 * @ieee_chan: last events channel number 
 * @event: last event type
 * @last_util: last recorded channel utilization info
 */
struct acs_last_event {
    uint16_t chan_freq;
    uint16_t event;
    struct acs_last_chutil last_util;
};

struct ieee80211_acs {
    /* Driver-wide data structures */
    wlan_dev_t                          acs_ic;
    wlan_if_t                           acs_vap;
    osdev_t                             acs_osdev;

    qdf_spinlock_t                      acs_lock;                /* acs lock */
    qdf_spinlock_t                      acs_ev_lock;             /* serialize between scan event handling and iwpriv commands */

    /* List of clients to be notified about scan events */
    u_int16_t                           acs_num_handlers;
    ieee80211_acs_event_handler         acs_event_handlers[IEEE80211_MAX_ACS_EVENT_HANDLERS];
    void                                *acs_event_handler_arg[IEEE80211_MAX_ACS_EVENT_HANDLERS];

    wlan_scan_requester            	    acs_scan_requestor;    /* requestor id assigned by scan module */
    wlan_scan_id	                    acs_scan_id;           /* scan id assigned by scan scheduler */
    u_int8_t                            acs_scan_2ghz_only:1; /* flag for scan 2.4 GHz channels only */
    u_int8_t                            acs_scan_5ghz_only:1; /* flag for scan 5 GHz channels only */
    atomic_t                            acs_in_progress; /* flag for ACS in progress */
    u_int8_t                            acs_run_status;
    struct ieee80211_ath_channel            *acs_channel;

    u_int16_t                           acs_nchans;         /* # of all available chans */
    struct ieee80211_ath_channel        *acs_chans[IEEE80211_ACS_ENH_CHAN_MAX];
    struct ieee80211_ath_channel        acs_chan_objs[IEEE80211_ACS_ENH_CHAN_MAX]; /* Channel object array. */
    u_int8_t                            acs_chan_maps[IEEE80211_ACS_CHAN_MAX];       /* channel mapping array */

    int32_t                             acs_chan_snr[IEEE80211_ACS_CHAN_MAX];         /* Total snr of these channels */
    int32_t                             acs_chan_snrtotal[IEEE80211_ACS_CHAN_MAX];    /* Calculated rssi of these channels */
    int32_t                             hw_chan_grade[IEEE80211_ACS_CHAN_MAX];         /* Channel grade given by target */
    int32_t                             chan_efficiency[IEEE80211_ACS_CHAN_MAX];       /* Effective efficieny of the channel */
    int32_t                             acs_chan_loadsum[IEEE80211_ACS_CHAN_MAX];      /* Sum of channle load  */
    int32_t                             acs_adjchan_load[IEEE80211_ACS_CHAN_MAX];      /* Sum of channle load  */
    int32_t                             acs_chan_regpower[IEEE80211_ACS_CHAN_MAX];      /* Sum of channle load  */
    int32_t                             acs_80211_b_duration[IEEE80211_ACS_CHAN_MAX];   /* 11b duration in channel */


    int32_t                             acs_adjchan_flag[IEEE80211_ACS_CHAN_MAX];      /* Adj channel rej flag*/
    int32_t                             acs_channelrejflag[IEEE80211_ACS_CHAN_MAX];    /* Channel Rejection flag */


    int32_t                             acs_snrvar;
    int32_t                             acs_effvar;
    int32_t                             acs_chloadvar;
    int32_t                             acs_srvar;
    int32_t                             acs_limitedbsschk;
    int32_t                             acs_bkscantimer_en;
    int32_t                             acs_bk_scantime;


    int32_t                             acs_11nabestchan;
    int32_t                             acs_11ngbestchan;
    int32_t                             acs_minrssisum_11ng;

    ieee80211_acs_scantimer_handler     acs_scantimer_handler;
    void                               *acs_scantimer_arg;
    os_timer_t                          acs_bk_scantimer;
    qdf_work_t                          acs_bk_scan_work;

    int32_t                             acs_chan_maxsnr[IEEE80211_ACS_CHAN_MAX];    /* max snr of these channels */
    int32_t                             acs_chan_minsnr[IEEE80211_ACS_CHAN_MAX];    /* Min snr of the channel [debugging] */
    int32_t                             acs_noisefloor[IEEE80211_ACS_CHAN_MAX];      /* Noise floor value read current channel */
    int32_t                             acs_perchain_nf[IEEE80211_ACS_CHAN_MAX][HOST_MAX_CHAINS]; /* Per chain Noise floor value (in dBm) read current channel */
    int16_t                             acs_channel_loading[IEEE80211_ACS_CHAN_MAX];      /* Noise floor value read current channel */
    u_int32_t                           acs_chan_load[IEEE80211_ACS_CHAN_MAX];
    u_int32_t                           acs_cycle_count[IEEE80211_ACS_CHAN_MAX];
#if ATH_SUPPORT_VOW_DCS
    u_int32_t                           acs_intr_ts[IEEE80211_ACS_CHAN_MAX];
    u_int8_t                            acs_intr_status[IEEE80211_ACS_CHAN_MAX];
#endif
    int32_t                             acs_minrssi_11na;    /* min rssi in 5 GHz band selected channel */
    int32_t                             acs_avgrssi_11ng;    /* average rssi in 2.4 GHz band selected channel */
    bool                                acs_sec_chan[IEEE80211_ACS_CHAN_MAX];       /*secondary channel flag */
    u_int32_t                           acs_chan_nbss[IEEE80211_ACS_CHAN_MAX];      /* No. of OBSS of the channel */
    u_int8_t                            acs_chan_nbss_near[IEEE80211_ACS_CHAN_MAX];      /* No. of Near range OBSS of the channel */
    u_int8_t                            acs_chan_nbss_mid[IEEE80211_ACS_CHAN_MAX];      /* No. of Mid range OBSS of the channel */
    u_int8_t                            acs_chan_nbss_far[IEEE80211_ACS_CHAN_MAX];      /* No. of far range OBSS of the channel */
    u_int16_t                           acs_chan_nbss_weighted[IEEE80211_ACS_CHAN_MAX];
    u_int16_t                           acs_nchans_scan;         /* # of all available chans */
    uint16_t                            acs_ch_idx[IEEE80211_ACS_CHAN_MAX];       /* scanned channel mapping array */
    struct acs_srp_info_s               acs_srp_info[IEEE80211_ACS_CHAN_MAX]; /* srp info */
    int32_t                             acs_srp_supported[IEEE80211_ACS_CHAN_MAX]; /* no. of BSS supporting spatil reuse */
    int32_t                             acs_srp_load[IEEE80211_ACS_CHAN_MAX]; /* Load sue to spatil reuse APs */
    struct acs_scan_req_param_t         acs_scan_req_param;
    struct acs_user_chan_list           acs_uchan_list; 	      /* struct user chan */
    struct acs_ch_hopping_t             acs_ch_hopping;		      /* To hold channel hopping related parammeter */	
    acs_bchan_list_t                    acs_bchan_list;         /* channel blocked by user */
#if ATH_CHANNEL_BLOCKING
#define ACS_BLOCK_MANUAL           0x1
#define ACS_BLOCK_EXTENSION        0x2
    u_int32_t                           acs_block_mode;         /* whether to block a channel if extension channel is blocked or
                                                                 * whether to block a channel if set manually (instead of acs) */
#endif
    u_int32_t                           acs_startscantime;      /* to note the time when the scan has started */
    u_int8_t                            acs_tx_power_type;
    u_int8_t                            acs_2g_allchan;
    acs_rank_t                          acs_rank[IEEE80211_ACS_CHAN_MAX]; /* ACS Rank and channel reject code for max channels */
    bool                                acs_ranking;            /* Enable/Disable ACS channel Ranking */
#if ATH_ACS_DEBUG_SUPPORT
    void *                              acs_debug_bcn_events;    /* Pointer to beacon events for the ACS debug framework */
    void *                              acs_debug_chan_events;   /* Pointer to channel events for the ACS debug framework */
#endif
    int32_t                             acs_noisefloor_threshold;
    u_int8_t                            acs_status;              /* ACS success/failed status */
    struct acs_last_event               acs_last_evt;            /* Last acs event */
    bool                                acs_chan_grade_algo;    /* ACS channel grade based selection */
    uint8_t                             acs_obss_near_range_weightage;
    uint8_t                             acs_obss_mid_range_weightage;
    uint8_t                             acs_obss_far_range_weightage;
};

struct ieee80211_acs_adj_chan_stats {
    u_int32_t                           adj_chan_load;
    u_int32_t                           adj_chan_rssi;
    u_int8_t                            if_valid_stats;    
    u_int8_t                            adj_chan_idx;
    u_int32_t                           adj_chan_flag;
    u_int32_t                           adj_chan_loadsum;
    u_int32_t                           adj_chan_rssisum;
    u_int32_t                           adj_chan_obsssum;
    u_int32_t                           adj_chan_srsum;
};

struct acs_obsscheck{
	ieee80211_acs_t acs ;
	struct ieee80211_ath_channel *channel;
	int onlyextcheck;
	int extchan_low;
	int extchan_high;
	int olminlimit;
	int olmaxlimit;
};

#define UNII_II_EXT_BAND(freq)  (freq >= 5500) && (freq <= 5700)

#define ADJ_CHAN_SEC_NF_FLAG       0x1
#define ADJ_CHAN_SEC1_NF_FLAG      0x2
#define ADJ_CHAN_SEC2_NF_FLAG      0x4
#define ADJ_CHAN_SEC3_NF_FLAG      0x8
#define ADJ_CHAN_SEC4_NF_FLAG      0x10
#define ADJ_CHAN_SEC5_NF_FLAG      0x11
#define ADJ_CHAN_SEC6_NF_FLAG      0x12

#define ACS_FLAG_NON5G                      0x1
#define ACS_REJFLAG_SECCHAN                 0x2
#define ACS_REJFLAG_WEATHER_RADAR           0x4
#define ACS_REJFLAG_DFS                     0x8
#define ACS_REJFLAG_HIGHNOISE              0x10
#define ACS_REJFLAG_SNR                    0x20
#define ACS_REJFLAG_CHANLOAD               0x40
#define ACS_REJFLAG_REGPOWER               0x80
#define ACS_REJFLAG_NON2G                 0x100
#define ACS_REJFLAG_PRIMARY_80_80         0x200
#define ACS_REJFLAG_NO_SEC_80_80          0x400
#define ACS_REJFLAG_NO_PRIMARY_80_80      0x800
#define ACS_REJFLAG_SPATIAL_REUSE        0x1000
#define ACS_REJFLAG_BLACKLIST            0x2000
#define ACS_REJFLAG_EFF                  0x4000
#define ACS_REJFLAG_ADJINTERFERE         0x8000
#define ACS_REJFLAG_SEC80_DIFF_BAND     0x10000
#define ACS_REJFLAG_PRECAC_INCOMPLETE   0x20000

#define ACS_REJECT_HIGH 1
#define ACS_REJECT_LOW 0
#define ACS_FIND_MIN 1
#define ACS_FIND_MAX 0

#define ACS_ALLOWED_SNRVARAINCE   10
#define ACS_ALLOWED_CHEFFVARAINCE   100
#define ACS_ALLOWED_CHANLOADVARAINCE 10
#define ACS_ALLOWED_SRVARAINCE 3
#define ATH_ACS_DEFAULT_SCANTIME   120

#define ACS_SNR_NEAR_RANGE_MIN 60
#define ACS_SNR_MID_RANGE_MIN 30
#define ACS_SNR_FAR_RANGE_MIN 0

#define ACS_OBSS_NEAR_RANGE_WEIGHTAGE_DEFAULT 50
#define ACS_OBSS_MID_RANGE_WEIGHTAGE_DEFAULT 50
#define ACS_OBSS_FAR_RANGE_WEIGHTAGE_DEFAULT 25

#define ACS_LEGACY_START_CH_IDX 0
#define ACS_2G_START_CH_IDX   ACS_LEGACY_START_CH_IDX
#define ACS_5G_START_CH_IDX   ACS_LEGACY_START_CH_IDX
#define ACS_6G_START_CH_IDX 188 /* This is assuming in continuation of 5G channels */

struct acs_sec_chans {
    uint16_t sec_chan_20;
    uint16_t sec_chan_40_1;
    uint16_t sec_chan_40_2;
    uint16_t sec_chan_80_1;
    uint16_t sec_chan_80_2;
    uint16_t sec_chan_80_3;
    uint16_t sec_chan_80_4;
};

#define ACS_GET_CHAN_BAND_FLAG(__chan)           \
    ((__chan)->ic_flags & (IEEE80211_CHAN_BAND_MASK))

typedef long unsigned * acs_chan_bitfield_t;
#define ACS_CHAN_BITFIELD_SET(__field, __index) ({                       \
    qdf_atomic_set_bit((__index) % (sizeof(long unsigned) * BITS_PER_BYTE),   \
            &(__field)[(__index) / (sizeof(long unsigned) * BITS_PER_BYTE)]); \
    })

#define ACS_CHAN_BITFIELD_CLR(__field, __index) ({                         \
    qdf_atomic_clear_bit((__index) % (sizeof(long unsigned) * BITS_PER_BYTE),   \
              &(__field)[(__index) / (sizeof(long unsigned) * BITS_PER_BYTE)]); \
    })

#define ACS_IS_CHAN_BITFIELD_SET(__field, __index) ({                           \
    qdf_atomic_test_bit((__index) % (sizeof(long unsigned) * BITS_PER_BYTE),    \
              &(__field)[(__index) / (sizeof(long unsigned) * BITS_PER_BYTE)]); \
    })
#endif /* _IEEE80211_ACS_INTERNAL_H */
