/*
 * Copyright (c) 2012, 2018-2021 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2012 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 * =====================================================================================
 *
 *       Filename:  ath_classifier.h
 *
 *    Description:  Classifier
 *
 *        Version:  1.0
 *        Created:  12/26/2011 11:16:42 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (),
 *        Company:  Qualcomm Atheros
 *
 * =====================================================================================
 */

#ifndef _ATH_CLASSIFIER_H_
#define _ATH_CLASSIFIER_H_

#include "spectral_types.h"
#include "spectral_data.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <assert.h>
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#include "spectral_ioctl.h"

#ifndef _BYTE_ORDER
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _BYTE_ORDER _LITTLE_ENDIAN
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#define _BYTE_ORDER _BIG_ENDIAN
#endif
#endif  /* _BYTE_ORDER */
#include "ieee80211_external.h"

#define SPECTRAL_CLASSIFIER_ASSERT(expr)       assert((expr))

/*
 * TODO : MAX_FFT_BINS Should be changed to accomdate 802.11ac
 *        chips like Peregrine, ROme
 */

#define SPECTRAL_DBG_LOG_SAMP   (50000)
#define NUM_MISC_ITEMS          (11)
#define SPECTRAL_LOG_VERSION_ID1 314157  /* Increment for new revision */
#define SPECTRAL_LOG_VERSION_ID2 314158  /* Increment for new revision */
#define SPECTRAL_LOG_VERSION_ID3 314159  /* Increment for new revision */
#define SPECTRAL_LOG_VERSION_ID4 314160  /* Increment for new revision */

#ifndef TRUE
#define TRUE    (1)
#endif

#ifndef FALSE
#define FALSE   !(TRUE)
#endif

/* Number for spectral params printed in the outfile */
#define NUM_SPECTRAL_PARAMS_ADVANCED (20)
#define NUM_SPECTRAL_PARAMS_NON_ADVANCED (5)

#define IS_CHAN_WIDTH_160_OR_80P80(ch_width)    ((ch_width) == IEEE80211_CWM_WIDTH160 || \
                                                 (ch_width) == IEEE80211_CWM_WIDTH80_80)

#define IS_CHAN_WIDTH_160(ch_width)    ((ch_width) == IEEE80211_CWM_WIDTH160)
#define IS_CHAN_WIDTH_80P80(ch_width)  ((ch_width) == IEEE80211_CWM_WIDTH80_80)
#define IS_CHAN_WIDTH_INVALID(ch_width)  ((ch_width) == IEEE80211_CWM_WIDTHINVALID)

#define GET_WIFI_STATE_UPDATE_MODE(ch_width, use_sec80)  (IS_CHAN_WIDTH_160(ch_width) ? \
                                                          UPDATE_PRI80_AND_SEC80 : use_sec80 ? \
                                                          UPDATE_SEC80 : UPDATE_PRI80)

#define WIFI_SSCAN_BW_SHIFT  24
#define WIFI_SEG_BW_SHIFT    16
#define WIFI_SEG_ID_SHIFT     8

#define CLASSIFIER_DEBUG 0
#if CLASSIFIER_DEBUG
#define cinfo(fmt, args...) do {\
    printf("classifier: %s (%4d) : " fmt "\n", __func__, __LINE__, ## args); \
    } while (0)
#else
#define cinfo(fmt, args...)
#endif

typedef u_int32_t DETECT_MODE;

#define LOG_NONE        (0)
#define LOG_MWO         (1)
#define LOG_CW          (2)
#define LOG_WIFI        (3)
#define LOG_FHSS        (4)
#define LOG_ALL         (5)

#define SPECT_CLASS_DETECT_NONE          0
#define SPECT_CLASS_DETECT_MWO           0x1
#define SPECT_CLASS_DETECT_CW            0x2
#define SPECT_CLASS_DETECT_WiFi          0x4
#define SPECT_CLASS_DETECT_CORDLESS_24   0x8
#define SPECT_CLASS_DETECT_CORDLESS_5    0x10
#define SPECT_CLASS_DETECT_BT            0x20
#define SPECT_CLASS_DETECT_FHSS          0x40
#define SPECT_CLASS_DETECT_ALL           0xff

#define NUM_FHSS_BINS (10)
#define NUM_SEGMENTS    2
#define CLASSIFIER_HASHSIZE 32
#define MAC_ADDR_LEN        6
#define CLASSIFIER_HASH(addr)   \
    ((((const u_int8_t *)(addr))[MAC_ADDR_LEN - 1] ^ \
      ((const u_int8_t *)(addr))[MAC_ADDR_LEN - 2] ^ \
      ((const u_int8_t *)(addr))[MAC_ADDR_LEN - 3] ^ \
      ((const u_int8_t *)(addr))[MAC_ADDR_LEN - 4]) % CLASSIFIER_HASHSIZE)

#define SPECT_DETECTION_FREQ_DESC_STR_NORMAL_MODE       "primary"
#define SPECT_DETECTION_FREQ_DESC_STR_AGILE_MODE        "Agile span centre"

#define SPECT_DETECTION_FREQ_REGION_STR_MAXTOTALSIZE    (32)
#define SPECT_DETECTION_FREQ_REGION_STR_NORMAL_MODE     "segment"
#define SPECT_DETECTION_FREQ_REGION_STR_AGILE_MODE      "Agile span"

typedef struct _fhss_detect_param_ {
    u_int32_t start_ts;
    u_int32_t last_ts;
    u_int32_t delta;
    u_int16_t freq_bin;
    int16_t rssi;
    u_int16_t num_samp;
    u_int16_t in_use;
} spectral_fhss_param;

typedef struct _mwo_detect_param_ {
    u_int32_t start_ts;
    u_int32_t last_ts;
    u_int32_t delta;
    u_int32_t off_time;
    int16_t rssi;
    u_int16_t num_samp;
    u_int16_t in_use;
} spectral_mwo_param;
#define NUM_MWO_BINS (10)

typedef enum _spectral_scan_band {
    SCAN_NONE   = 0,
    SCAN_24GHZ  = 1,
    SCAN_5GHZ   = 2,
    SCAN_ALL    = 3,
} SPECTRAL_SCAN_BAND;

/* Thresholds that are different between legacy (11n)
   and 11ac chipsets */
typedef struct _classifier_thresholds {
    /* CW interference detection parameters */
    u_int32_t cw_int_det_thresh;
    
    /* Wi-Fi detection parameters */
    int wifi_det_min_diff;
    
    /* FHSS detection parameters */
    u_int32_t fhss_sum_scale_down_factor;

    /* MWO power variation threshold */
    u_int32_t mwo_pwr_variation_threshold;
} CLASSIFIER_THRESHOLDS;

typedef struct _CLASSIFIER_CW_PARAMS {
    u_int16_t burst_found;              /* Indicates that a CW burst is found */
    u_int32_t start_time;               /* Start time of the CW burst */
    u_int32_t last_found_time;          /* Start time of the previous CW burst found */
    int16_t rssi;                       /* Spectral RSSI value at the time of CW burst */
    u_int16_t num_detected;             /* Number of likely CW interference cases found */
    u_int32_t detect_ts;                /* Detect timestamp */
    u_int16_t num_detect;               /* Number of CW bursts detected */
    u_int16_t found_cw;                 /* Flag to indicate if CW is present already on the segment */
} CLASSIFIER_CW_PARAMS;

typedef struct _CLASSIFIER_FHSS_PARAMS {
    u_int32_t detect_ts;                            /* Detect timestamp */
    u_int32_t num_detect;                           /* Number of FHSS detects */
    u_int32_t dwell_time;
    u_int16_t cur_bin;                              /* Bin number of the current burst */
    u_int16_t found_fhss;                           /* Flag to indicate if FHSS is present
                                                       already on the segment */
    spectral_fhss_param fhss_param[NUM_FHSS_BINS];  /* Contains the set of FHSS params for each bin */
} CLASSIFIER_FHSS_PARAMS;

typedef struct _CLASSIFIER_DATA_STRUCT {

    int is_valid;                           /* indicates if the contents are valid */
    u_int8_t macaddr[MAC_ADDR_LEN];         /* associated MAC address */

    DETECT_MODE spectral_detect_mode;
    SPECTRAL_SCAN_BAND band;

    u_int16_t sm_init_done;
    u_int16_t cur_freq;
    u_int16_t cur_agile_freq1;
    u_int16_t cur_agile_freq2;

    /* MWO detect */
    u_int32_t mwo_burst_idx;
    u_int32_t mwo_burst_found;
    u_int32_t mwo_burst_start_time;
    u_int32_t mwo_in_burst_time;
    u_int32_t mwo_thresh;
    int32_t mwo_rssi;

    spectral_mwo_param mwo_param[NUM_MWO_BINS];
    u_int16_t mwo_cur_bin;

    /* Differentiated thresholds to be used,
       populated as per whether legacy (11n)
       or advanced (11ac) Spectral capability
       is available */
    CLASSIFIER_THRESHOLDS thresholds;

    CLASSIFIER_CW_PARAMS cw[NUM_SEGMENTS];

    /* WiFi detection */
    u_int32_t spectral_num_wifi_detected;
    u_int32_t spectral_wifi_ts;
    int32_t wifi_rssi;

    /* FHSS detection */
    CLASSIFIER_FHSS_PARAMS fhss[NUM_SEGMENTS];

    /* Overall detection */
    DETECT_MODE current_interference;

    u_int32_t mwo_detect_ts;
    u_int16_t mwo_num_detect;

    u_int32_t wifi_detect_ts;
    u_int16_t wifi_num_detect;

    u_int32_t dsss_detect_ts;
    u_int32_t dsss_num_detect;

    /* Total count of the detected interference */
    u_int32_t cw_cnt;
    u_int32_t wifi_cnt;
    u_int32_t fhss_cnt;
    u_int32_t mwo_cnt;

    /* Debug stuff only */
    bool spectral_log_first_time;
    size_t spectral_num_samp_log;
    bool commit_done;
    u_int8_t *spectral_bin_bufSave;
    u_int8_t *spectral_bin_bufSave_sec80;
    u_int8_t *spectral_bin_bufSave_5mhz;
    int32_t *spectral_data_misc;
    int32_t *spectral_data_misc_sec80;
    size_t spectral_log_num_bin;
    size_t spectral_log_num_bin_sec80;
    size_t spectral_log_num_bin_5mhz;
    size_t last_samp;
    u_int16_t log_mode;
    struct spectral_caps caps;
    struct spectral_config spectral_params;

    /* Placeholder to log state for each sample */
    u_int32_t pri80_detection_state;
    u_int32_t sec80_detection_state;
    /** is_commit added to indicate that interference is found in
     * either pri80 or sec80 and used as indication to commit data
     * to outfile after detection completes for sec80 in CW and FHSS
     * for ch_width 160 or 80p80.
     */
    bool is_commit;
    u_int32_t *spectral_state_log;
    u_int32_t *spectral_state_log_sec80;
} CLASSIFER_DATA_STRUCT;

typedef enum spect_samp_state_update_mode {
    UPDATE_PRI80 = 0,
    UPDATE_SEC80 = 1,
    UPDATE_PRI80_AND_SEC80 = 2,
} SAMP_STATE_UPDATE_MODE;

/* MWO STATES */
typedef enum spect_mwo_class_states {
    MWO_DETECT_INIT = 0,

    /* sample having timestamp equal to or older than
     * previous timestamp
     */
    MWO_TS_GOES_BACK_IN_TIME = 1,

    /* sample having primary channel frequency outside usual
     * range of interest
     */
    MWO_INVALID_FREQ = 2,

    MWO_FIRST_BURST_DETECTED = 3,

    /* instances when state machine is reset since max burst
     * time is exceeded
     */
    MWO_MAX_BURST_TIME_EXCEEDED = 4,

    /* instances when state machine is reset since burst looks too short */
    MWO_BURST_TOO_SHORT = 5,

    /* instances when state machine is reset since inter-burst
     * duration is exceeded
     */
    MWO_INTER_BURST_DURATION_TOO_HIGH = 6,

    MWO_NEW_BURST_DETECTED = 7,

    MWO_SUFFICIENT_BURSTS_FOR_DETECTION = 8,

    /* sample discarded since power variation between start
     * and end of operating span is below threshold
     */
    MWO_PULSE_PWR_VARIATION_W_DYN_THRESH_NOT_CROSSED = 9,

    /* instances when state machine is reset due to burst inactivity
     * though basic RSSI check passed but check of power variation
     * crossing dynamic threshold failed for current sample
     */
    MWO_BURST_INACTIVITY_TIMEOUT_EXCEEDED_W_DYN_THRESH_NOT_CROSSED = 10,

    /* sample discarded due to insufficient RSSI */
    MWO_RSSI_INSUFFICIENT = 11,

    /* instances when state machine is reset due to burst inactivity
     * coupled with failure of current sample to pass basic RSSI check
     */
    MWO_BURST_INACTIVITY_TIMEOUT_EXCEEDED_W_LOW_RSSI = 12,

    MWO_FIRST_DETECT_FOUND = 13,

    MWO_SUBSEQUENT_DETECT_FOUND = 14,

    MWO_INTERFERENCE_FOUND = 15,

    /* instances where we reset the counter of potential
     * MWO detects for final confirmation of stable detection
     * to 1, since new potential MWO detect is too late compared to
     * previous potential detect
     */
    MWO_STABLE_DETECT_THRESH_EXCEEDED = 16,

    MWO_DETECT_INACTIVITY_TIMEOUT_CROSSED = 17,
} SPECTRAL_MWO_SAMPLE_STATE;

#define WIFI_NUM_SEG_BWS 4

#define WIFI_MISC_STATE_MASK 0xFFFFFF00

/* Enum to indicate WiFi segment bandwidth */
typedef enum wifi_segment_bandwidth {
    WIFI_SEGMENT_BANDWIDTH_20MHZ = 20,
    WIFI_SEGMENT_BANDWIDTH_40MHZ = 40,
    WIFI_SEGMENT_BANDWIDTH_80MHZ = 80,
    WIFI_SEGMENT_BANDWIDTH_160MHZ = 160,
} WIFI_SEG_BANDWIDTH;

/* WIFI STATES */
/* Miscellaneous states defined to be appended to wifi_state
 * returned by athssd_get_wifi_detection_state. Refer to the
 * documentation of athssd_get_wifi_detection_state.
 */
typedef enum spect_wifi_class_states {
    /* Add new states here */

    WIFI_DETECT_INIT = 248,

    /* Channel width is invalid */
    WIFI_CW_INVALID = 249,

    /* First detection */
    WIFI_FIRST_DETECT = 250,

    /* Sufficient detection within 500ms of the first */
    WIFI_SUFFICIENT_DETECTS_WITHIN_DETECTION_WINDOW = 251,

    /* Sufficient detection candidate took greater than 500ms of the first */
    WIFI_TOO_MUCH_TIME_FOR_SUFFICIENT_DETECTS = 252,

    /* Positive detected after wifi detect reset time, i.e, 5000ms */
    WIFI_POSITIVE_DETECT_AFTER_WIFI_DET_RESET_TIME = 253,

    WIFI_ONE_MORE_DETETCED = 254,

    WIFI_NOT_DETECTED = 255,
} SPECTRAL_WIFI_SAMPLE_STATE;

/* CW STATES */
typedef enum spect_cw_class_states {
    CW_DETECT_INIT = 0,

    /* Found a likely CW interference case */
    CW_FOUND_LIKELY_BURST = 1,

    /* Found first burst */
    CW_FOUND_FIRST_BURST = 2,

    /* Found subsequent burst */
    CW_FOUND_SUBSEQUENT_BURST = 3,

    /* Found enough detections for a burst to be counted */
    CW_FOUND_MIN_COUNT_BURST = 4,

    /* Burst missing for too long with CW RSSI exceeded */
    CW_BURST_MISSING_FOR_TOO_LONG_W_CW_RSSI_THRESH_EXCEEDED = 5,

    /* Burst missing for too long  without CW RSSI exceeded*/
    CW_BURST_MISSING_FOR_TOO_LONG_WO_CW_RSSI_EXCEEDED = 6,

    /* History of BURSTS */
    CW_FOUND_FIRST_DETECT = 7,

    CW_FOUND_SUBSEQUENT_DETECT = 8,

    /* Found sufficient burst detects in a window for classification */
    CW_FOUND_SUFFICIENT_DETECTS_IN_WINDOW = 9,

    /* Detect found after long time */
    CW_FOUND_DETECT_AFTER_LONG_TIME = 10,

    /* Found insufficient bursts in a window */
    CW_FOUND_INSUFFICIENT_DETECTS_IN_WINDOW = 11,
} SPECTRAL_CW_SAMPLE_STATE;

/* FHSS states */
typedef enum spect_fhss_class_states {
    FHSS_DETECT_INIT = 0,

    /* samples having timestamp equal to or older than
     * previous timestamp
     */
    FHSS_TS_GOES_BACK_IN_TIME = 1,

    /* sample discarded due to insufficient RSSI */
    FHSS_RSSI_INSUFFICIENT = 2,

    /* sample with lower sum too high */
    FHSS_LWR_SUM_TOO_HIGH = 3,

    /* sample with upper sum too high */
    FHSS_UPR_SUM_TOO_HIGH = 4,

    /* Num samples with center sum too low*/
    FHSS_CENTER_SUM_TOO_LOW = 5,

    FHSS_POSSIBLE_BURST = 6,

    /* instance when state machine is reset due to a single
     * burst being too long
     */
    FHSS_REJECTION_ABOVE_SINGLE_BURST_TIME = 7,

    /* potential bursts which do satisfy min dwell time requirement */
    FHSS_MIN_DWELL_TIME_SATISFIED = 8,

    /* potential bursts which do not satisfy min dwell time requirement */
    FHSS_MIN_DWELL_TIME_NOT_SATISFIED = 9,

    FHSS_FIR_DELTA_NOT_CROSSING_MIN_DWELL = 10,

    /* instances where we find sufficient potential bursts but we
     * do not satisfy requirement of similar dwell time within +/-25%
     * of dwell time of second burst in group
     */
    FHSS_INSUFFICIENT_BINS_W_SAME_DWELL = 11,

    /* instances when state machine is reset since milestone of
     * finding minimum num of bursts is crossed
     */
    FHSS_REINIT_AFTER_ALL_BINS_PROCESSED = 12,

    /* instances when we do not satisfy requirement of min num of
     * potential bursts before a state machine reset happens due
     * to inactivity
     */
    FHSS_NUM_REQD_VIABLE_PEAKS_NOT_REACHED = 13,

    /* instances when state machine is reset due to burst inactivity
     * though basic RSSI check passed but other checks failed for current sample
     */
    FHSS_UNDETECTED_FOR_TOO_LONG_W_SUFFICIENT_RSSI = 14,

    /* instances when state machine is reset due to burst inactivity
     * coupled with failure of current sample to pass basic RSSI check
     */
    FHSS_UNDETECTED_FOR_TOO_LONG_W_LOW_RSSI = 15,

    FHSS_FIRST_DETECT_FOUND = 16,

    FHSS_SUBSEQUENT_DETECT_FOUND = 17,

    /* Num instances where we do not get a second detection for
     * confirmation within a time window
     */
    FHSS_NOT_SUFFICIENT_DETECTS_WITHIN_CONFIRMATION_WINDOW = 18,
} SPECTRAL_FHSS_SAMPLE_STATE;


#define IS_MWO_DETECTED(p)          ((p->current_interference & SPECT_CLASS_DETECT_MWO)?1:0)
#define IS_CW_DETECTED(p)           ((p->current_interference & SPECT_CLASS_DETECT_CW)?1:0)
#define IS_WiFi_DETECTED(p)         ((p->current_interference & SPECT_CLASS_DETECT_WiFi)?1:0)
#define IS_CORDLESS_24_DETECTED(p)  ((p->current_interference & SPECT_CLASS_DETECT_CORDLESS_24)?1:0)
#define IS_CORDLESS_5_DETECTED(p)   ((p->current_interference & SPECT_CLASS_DETECT_CORDLESS_5)?1:0)
#define IS_BT_DETECTED(p)           ((p->current_interference & SPECT_CLASS_DETECT_BT)?1:0)
#define IS_FHSS_DETECTED(p)         ((p->current_interference & SPECT_CLASS_DETECT_FHSS)?1:0)

#define SET_INTERFERENCE(p, type)   (p->current_interference |=  type)
#define CLR_INTERFERENCE(p, type)   (p->current_interference &= ~(type))

/* Function declarations */
extern void classifier_process_spectral_msg(struct spectral_samp_msg *msg,
        CLASSIFER_DATA_STRUCT *pclas, u_int16_t log_type,
        bool enable_gen3_linear_scaling);
extern void print_detected_interference(CLASSIFER_DATA_STRUCT* pclas);
extern void print_spect_int_stats(void);
extern const char* ether_sprintf(const u_int8_t *mac);
extern void init_classifier_data(const u_int8_t* macaddr, void *spectral_caps,
        size_t spectral_caps_len);
extern CLASSIFER_DATA_STRUCT* get_classifier_data(const u_int8_t* macaddr);
extern int check_wifi_signal(CLASSIFER_DATA_STRUCT* pclas, u_int32_t num_bins, u_int8_t* pfft_bins);
extern void init_classifier_lookup_tables(void);

#ifdef WLAN_FEATURE_ATHSSD_DEBUG
/*
 * Function     : athssd_update_sample_state
 * Description  : Updates the current state of detection for given interference sample
 * Input params : Pointer to classifier data struct, detection state of the sample
 * Return       : None
 *
 */
static void inline athssd_update_sample_state(CLASSIFER_DATA_STRUCT* pclas, u_int32_t state,
SAMP_STATE_UPDATE_MODE mode)
{
    switch(mode) {
    case UPDATE_PRI80:
        pclas->pri80_detection_state = state;
        break;
    case UPDATE_SEC80:
        pclas->sec80_detection_state = state;
        break;
    case UPDATE_PRI80_AND_SEC80:
        pclas->pri80_detection_state = state;
        pclas->sec80_detection_state = state;
        break;
    default:
        printf("Error: athssd sample state update mode not supported\n");
        break;
    }
}
/*
 * Function     : athssd_is_sample_state_logging_supported
 * Description  : Returns whether state logginjg is supported
 * Input params : None
 * Return       : true: Supported
 *                false: Not supported
 *
 */
static bool inline athssd_is_sample_state_logging_supported()
{
    return true;
}
#else
static void inline athssd_update_sample_state(CLASSIFER_DATA_STRUCT* pclas,
    u_int32_t state, SAMP_STATE_UPDATE_MODE mode)
{
    /* Do nothing */
}
static bool inline athssd_is_sample_state_logging_supported()
{
    return false;
}
#endif

/* --- Default spectral classifier parameters */

/* MWO parameters */
/* Minimum and maximum frequency to check for MWO interference */
#define MWO_MIN_FREQ                    (2437)
#define MWO_MAX_FREQ                    (2482)
/* Minimum RSSI for MWO detection */
#define MWO_MIN_DETECT_RSSI             (5)
/* Threshold for pulse power variation (both ascending and descending) */
#define MWO_POW_VARIATION_THRESH        (3000)
/* Expected time difference between two bursts, in microseconds */
#define MWO_INTER_BURST_DURATION        (8000)
/* Max expected time difference between two bursts, in microseconds */
#define MWO_MAX_INTER_BURST_DURATION    (16000)
/* Max burst time, in microseconds */
#define MWO_MAX_BURST_TIME              (15 * 1000)
/* Number of bursts required to be detected to declare preliminary
   detection success */
#define MWO_NUM_BURST                   (6)
/* Burst inactivity timeout in microseconds. Bursts should occur within this timeout. */
#define MWO_BURST_INACTIVITY_TIMEOUT    (30 * 1000)
/* Threshold in microseconds in within which successive preliminary 
   detects should occur, for hysteresis stability */
#define MWO_STABLE_DETECT_THRESH        (500 * 1000)
/* Detection inactivity timeout in microseconds. If occurrence of preliminary detects
   exceeds this timeout, an MWO is considered no longer present. */
#define MWO_DETECT_INACTIVITY_TIMEOUT   (5000 * 1000)


/* CW interference detection parameters */
#define CW_RSSI_THRESH              (10)
#define CW_INT_BIN_SUM_SIZE         (3) /* Should always be 3. Some design changes needed for other number */
#define CW_INT_DET_THRESH           (200)
#define CW_INT_FOUND_TIME_THRESH    (15*1000)
#define CW_INT_FOUND_MIN_CNT        (50)
#define CW_INT_MISSING_THRESH       (1000)
#define CW_INT_CONFIRM_WIN          (100*1000)
#define CW_INT_CONFIRM_MISSING_WIN  (2000*1000)
#define CW_SUM_SCALE_DOWN_FACTOR    (2)
#define CW_PEAK_TO_ADJ_THRESH       (3)

/* WiFI detection parameters */
#define WIFI_DET_MIN_RSSI           (10)
#define WIFI_DET_MIN_DIFF           (200)
#define WIFI_BIN_WIDTH              (4)
#define WIFI_DET_CONFIRM_WIN        (500*1000)
#define WIFI_DET_RESET_TIME         (5000*1000)
#define WIFI_MIN_NUM_DETECTS        (2)

/* FHSS detection parameters */
#define FHSS_DET_THRESH             (10)
#define FHSS_INT_BIN_SUM_SIZE       (3)  /* NOTE: Should always be 3, else will require design change */
#define FHSS_CENTER_THRESH          (100)
#define FHSS_MIN_DWELL_TIME         (500)
#define FHSS_SINGLE_BURST_TIME      (15*1000)
#define FHSS_LACK_OF_BURST_TIME     (3*150*1000)
#define FHSS_DETECTION_CONFIRM_WIN  (5*1000*1000)
#define FHSS_DETECTION_RESET_WIN    (10*1000*1000)
#define FHSS_SUM_SCALE_DOWN_FACTOR  (2)


/* Differentiated values for 11ac chipsets having advanced spectral
   capability */

/* CW interference detection parameters */
#define ADVNCD_CW_INT_DET_THRESH           (60)

/* WiFI detection parameters */
#define ADVNCD_WIFI_DET_MIN_DIFF           (20)

/* FHSS detection parameters */
#define ADVNCD_FHSS_SUM_SCALE_DOWN_FACTOR  (0)

/* MWO Power variation threshold */
#define ADVNCD_MWO_POW_VARTIATION_THRESH    2000

/* Number MWO Bin Cluster count */
#define MWO_BIN_CLUSTER_COUNT                     (10)

/* Macros to access thresholds */

#define ACCESS_THRESHOLD(pclas)                   (pclas->thresholds)

#define GET_MIN_MWO_FREQ(pclas)                   (MWO_MIN_FREQ)
#define GET_MAX_MWO_FREQ(pclas)                   (MWO_MAX_FREQ)
#define GET_MIN_RSS_TO_DETECT(pclas)              (MIN_RSS_TO_DETECT)
#define GET_MWO_INT_BIN_SUM_SIZE(pclas)           (MWO_INT_BIN_SUM_SIZE)
#define GET_MWO_INT_DET_THRESH(pclas)             (MWO_INT_DET_THRESH)
#define GET_MWO_MAX_GAP_WITHIN_BURST(pclas)       (MWO_MAX_GAP_WITHIN_BURST)
#define GET_MWO_MAX_BURST_TIME(pclas)             (MWO_MAX_BURST_TIME)
#define GET_MWO_MIN_DUTY_CYCLE(pclas)             (MWO_MIN_DUTY_CYCLE)
#define GET_MWO_MAX_DUTY_CYCLE(pclas)             (MWO_MAX_DUTY_CYCLE)
#define GET_MWO_SECOND_DET_THRESH(pclas)          (MWO_SECOND_DET_THRESH)
#define GET_MWO_DETECT_CONFIRM_COUNT(pclas)       (MWO_DETECT_CONFIRM_COUNT)
#define GET_MWO_CONFIRM_MISSING_TIME(pclas)       (MWO_CONFIRM_MISSING_TIME)
#define GET_MWO_MIN_RSSI_THRESHOLD(pclas)         (MWO_MIN_DETECT_RSSI)
#define GET_MWO_POW_VARIATION_THRESHOLD(pclas)    (ACCESS_THRESHOLD((pclas)).mwo_pwr_variation_threshold)


#define GET_CW_RSSI_THRESH(pclas)                 (CW_RSSI_THRESH)
#define GET_CW_INT_BIN_SUM_SIZE(pclas)            (CW_INT_BIN_SUM_SIZE)
#define GET_CW_INT_DET_THRESH(pclas)              (ACCESS_THRESHOLD((pclas)).cw_int_det_thresh)
#define GET_CW_INT_FOUND_TIME_THRESH(pclas)       (CW_INT_FOUND_TIME_THRESH)
#define GET_CW_INT_FOUND_MIN_CNT(pclas)           (CW_INT_FOUND_MIN_CNT)
#define GET_CW_INT_MISSING_THRESH(pclas)          (CW_INT_MISSING_THRESH)
#define GET_CW_INT_CONFIRM_WIN(pclas)             (CW_INT_CONFIRM_WIN)
#define GET_CW_INT_CONFIRM_MISSING_WIN(pclas)     (CW_INT_CONFIRM_MISSING_WIN)
#define GET_CW_SUM_SCALE_DOWN_FACTOR(pclas)       (CW_SUM_SCALE_DOWN_FACTOR)
#define GET_CW_PEAK_TO_ADJ_THRESH(pclas)          (CW_PEAK_TO_ADJ_THRESH)

#define GET_WIFI_DET_MIN_RSSI(pclas)              (WIFI_DET_MIN_RSSI)
#define GET_WIFI_DET_MIN_DIFF(pclas)              (ACCESS_THRESHOLD((pclas)).wifi_det_min_diff)
#define GET_WIFI_BIN_WIDTH(pclas)                 (WIFI_BIN_WIDTH)
#define GET_WIFI_DET_CONFIRM_WIN(pclas)           (WIFI_DET_CONFIRM_WIN)
#define GET_WIFI_DET_RESET_TIME(pclas)            (WIFI_DET_RESET_TIME)

#define GET_FHSS_DET_THRESH(pclas)                (FHSS_DET_THRESH)
#define GET_FHSS_INT_BIN_SUM_SIZE(pclas)          (FHSS_INT_BIN_SUM_SIZE)
#define GET_FHSS_CENTER_THRESH(pclas)             (FHSS_CENTER_THRESH)
#define GET_FHSS_MIN_DWELL_TIME(pclas)            (FHSS_MIN_DWELL_TIME)
#define GET_FHSS_SINGLE_BURST_TIME(pclas)         (FHSS_SINGLE_BURST_TIME)
#define GET_FHSS_LACK_OF_BURST_TIME(pclas)        (FHSS_LACK_OF_BURST_TIME)
#define GET_FHSS_DETECTION_CONFIRM_WIN(pclas)     (FHSS_DETECTION_CONFIRM_WIN)
#define GET_FHSS_DETECTION_RESET_WIN(pclas)       (FHSS_DETECTION_RESET_WIN)
#define GET_FHSS_SUM_SCALE_DOWN_FACTOR(pclas)     (ACCESS_THRESHOLD((pclas)).fhss_sum_scale_down_factor)

#define SAMP_NUM_OF_BINS(pmsg)                    (pmsg->samp_data.bin_pwr_count)
#define SAMP_GET_SPECTRAL_TIMESTAMP(pmsg)         (pmsg->samp_data.spectral_tstamp)
#define SAMP_GET_SPECTRAL_RSSI(pmsg)              (pmsg->samp_data.spectral_rssi)
#define IS_MWO_BURST_FOUND(pclas)                 (pclas->mwo_burst_found)
#define GET_PCLAS_MWO_TRHESHOLD(pclas)            (pclas->mwo_thresh)
#define GET_PCLAS_MWO_IN_BURST_TIME(pclas)        (pclas->mwo_in_burst_time)
#define GET_PCLAS_MWO_BURST_START_TIME(pclas)     (pclas->mwo_burst_start_time)
#define GET_PCLAS_MWO_DETECT_TIMESTAMP(pclas)     (pclas->mwo_detect_ts)

#endif  /* _ATH_CLASSIFIER_H_ */

