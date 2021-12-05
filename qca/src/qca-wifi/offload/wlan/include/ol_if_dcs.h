/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2011, Atheros Communications Inc.
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
 */

#ifndef OL_IF_DCS_H
#define OL_IF_DCS_H

#include <ieee80211_channel.h>

#define DCS_PHYERR_PENALTY      (500)
#define DCS_PHYERR_THRESHOLD    (300)
#define DCS_RADARERR_THRESHOLD  (1000)
#define DCS_COCH_INTR_THRESHOLD (30) /* 30 % excessive channel utilization */
#define DCS_TXERR_THRESHOLD     (30)
#define DCS_USER_MAX_CU         (50) /* tx ch utilization due to AP tx and rx */
#define DCS_TX_MAX_CU           (30)
#define DCS_INTR_DETECTION_THR  (6)
#define DCS_SAMPLE_SIZE         (10)
/* Duration after which DCS should be enabled back after
 * disabling it due to 3 triggers in 5 minutes */
#define DCS_ENABLE_TIME         (30 * 60)
#define DCS_ENABLE_TIME_MIN     (5 * 60)
#define DCS_ENABLE_TIME_MAX     (60 * 60)
#define DCS_MAX_TRIGGERS        (3)
#define DCS_AGING_TIME          (300000) /* 5 mins */

#define OL_ATH_DCS_ENABLE(__arg1, val)  ((__arg1) |= (val))
#define OL_ATH_DCS_DISABLE(__arg1, val) ((__arg1) &= ~(val))
#define OL_ATH_DCS_SET_RUNSTATE(__arg1) ((__arg1) |= 0x10)
#define OL_ATH_DCS_CLR_RUNSTATE(__arg1) ((__arg1) &= ~0x10)
#define OL_IS_DCS_ENABLED(__arg1) ((__arg1) & 0x0f)
#define OL_IS_DCS_RUNNING(__arg1) ((__arg1) & 0x10)

#define OL_ATH_DCS_FREQ_TO_LIST(__list, __num, freq) ((__list)[(*__num)++] = freq)

/**
 * struct _wlan_dcs_im_host_stats - dcs wlan interference mitigation stats
 * The below stats are sent from target to host every one second
 * @prev_dcs_im_stats: The previous statistics at last known time
 * @im_intr_count: number of times the interfernce is seen continuously
 * @sample_count: int_intr_count of sample_count, the interference is seen
 */
typedef struct _wlan_dcs_im_host_stats {
	wmi_host_dcs_im_tgt_stats_t prev_dcs_im_stats;
	uint8_t im_intr_cnt; /* Interefernce detection counter */
	uint8_t im_samp_cnt; /* sample counter */
} wlan_dcs_im_host_stats_t;

typedef enum {
	DCS_DEBUG_DISABLE  = 0,
	DCS_DEBUG_CRITICAL = 1,
	DCS_DEBUG_VERBOSE  = 2,
} wlan_dcs_debug_t;

/*
 * DCS interference types:
 * Types of DCS interference events received from FW
 */
enum cap_dcs_type {
	CAP_DCS_NONE   = 0,      /* 0x0 */
	CAP_DCS_CWIM   = BIT(0), /* 0x1 */
	CAP_DCS_WLANIM = BIT(1), /* 0x2 */
	CAP_DCS_AWGNIM = BIT(2), /* 0x4 */
	/* Add new interference management type here */
	CAP_DCS_ALLIM  = 0xF,
	CAP_DCS_MASK   = (CAP_DCS_CWIM | CAP_DCS_WLANIM | CAP_DCS_AWGNIM),
};

typedef struct ieee80211_mib_cycle_cnts periodic_chan_stats_t;

/**
 * struct _wlan_host_dcs_params - define dcs configuration parameters
 * @dcs_debug: dcs debug trace level value 0-disable, 1-critical, 2-all
 * @phy_err_penalty: phy error penalty
 * @phy_err_threshold: phy error threshold
 * @radar_err_threshold: radar error threshold
 * @coch_intr_thresh: co-channel interference threshold
 * @user_max_cu: tx channel utilization due to AP's tx and rx, tx_cu + rx_cu
 * @intr_detection_threshold: interference detection threshold
 * @intr_detection_window: interference sampling window
 * @tx_err_thresh: transmission failure rate threshold
 * @scn_dcs_im_stats: dcs wlan interference mitigation stats
 * @chan_stats: periodic channel stats
 * @dcs_enable_timer: dcs enable timer
 * @dcs_trigger_ts: dcs trigger timestamp
 * @is_enable_timer_set: check if timer is enabled/re-enabled
 * @dcs_re_enable_time: dcs re-enable time value for dcs timer
 * @dcs_trigger_count: dcs trigger count
 * @dcs_enable: dcs enabled or not, along with running state
 * @dcs_wideband_policy: dcs wideband policy for interband and intraband
 *                       channel selection
 * @dcs_random_chan_en: Enable/disable CSA channel change
 * @dcs_csa_tbtt: CSA TBTT count
 */
typedef struct _wlan_host_dcs_params {
	wlan_dcs_debug_t dcs_debug;
	uint32_t phy_err_penalty;
	uint32_t phy_err_threshold;
	uint32_t radar_err_threshold;
	uint32_t coch_intr_thresh ;
	uint32_t user_max_cu;
	uint32_t intr_detection_threshold;
	uint32_t intr_detection_window;
	uint32_t tx_err_thresh;
	wlan_dcs_im_host_stats_t scn_dcs_im_stats;
	periodic_chan_stats_t  chan_stats;
	qdf_timer_t dcs_enable_timer;
	uint32_t dcs_trigger_ts[DCS_MAX_TRIGGERS];
	bool is_enable_timer_set;
	uint16_t dcs_re_enable_time;
	uint8_t dcs_trigger_count;
	uint32_t dcs_enable;
	wlan_dcs_wideband_policy_t dcs_wideband_policy;
	bool dcs_random_chan_en;
	uint32_t dcs_csa_tbtt;
} wlan_host_dcs_params_t;

/**
 * ol_ath_dcs_generic_interference_handler() - wlan cw and awgn interference
 * handler
 * @scn: Pointer to net80211 softc object
 * @intf_info: Pointer to the interference information
 * @interference_type: Interference type
 *
 * Functionality of this should be the same as
 * ath_net80211_cw_interference_handler() in lmac layer of the direct
 * attach drivers. Keep this same across both.
 *
 * When the cw interference is sent from the target, kick start the scan
 * with auto channel. This is disruptive channel change. Non-discruptive
 * channel change is the responsibility of scan module.
 *
 * Return: none
 */
void ol_ath_dcs_generic_interference_handler(struct ol_ath_softc_net80211 *scn,
					     void *intf_info,
					     enum cap_dcs_type interference_type);

/**
 * ol_ath_wlan_interference_handler() - wlan interference handler
 * @scn: Pointer to net80211 softc object
 * @curr_stats: dcs curr stats
 * @interference_type: Interference type
 *
 * Return: none
 */
void ol_ath_wlan_interference_handler(struct ol_ath_softc_net80211 * scn,
				      wmi_host_dcs_im_tgt_stats_t *curr_stats,
				      uint32_t interference_type);

/**
 * ol_ath_reset_dcs_params() - Reset dcs parameters
 * @scn: Pointer to scn structure
 *
 * Return: none
 */
void ol_ath_reset_dcs_params(struct ol_ath_softc_net80211 *scn);

/**
 * ol_ath_disable_dcsim() - Disable DCS IM
 * @ic: ic handle
 *
 * Disable the dcs im when the intereference is detected too many times,
 * for thresholds check umac
 *
 * Return: none
 */
void ol_ath_disable_dcsim(struct ieee80211com *ic);

/**
 * ol_ath_enable_dcsim() - Enable DCS IM
 * @ic: ic handle
 *
 * Return: none
 */
void ol_ath_enable_dcsim(struct ieee80211com *ic);

/**
 * ol_ath_ctrl_dcs_awgnim() - Enable/disable DCS AWGN interference management
 * @ic    : ic handle
 * @flag  : Pointer to the flag to enable/disable AWGN
 * @enable: Flag to enable/disable AWGN interference
 *
 * Enable/Disable the DCS AWGN interference management.
 *
 * Return: None
 */
void ol_ath_ctrl_dcsawgn(struct ieee80211com *ic, uint32_t *flag, bool enable);

/**
 * ol_ath_disable_dcscw() - Disable DCS CW
 * @ic: ic handle
 *
 * Disable the dcs cw when the intereference is detected too many times
 * For thresholds check umac
 *
 * Return: none
 */
void ol_ath_disable_dcscw(struct ieee80211com *ic);

/**
 * ol_ath_dcs_restore() - Restore DCS state
 * @ic: ic handle
 *
 * Turn on the dcs, use the same state as what the current
 * enabled state of dcs and reset the cw interference flag
 * Also set the run state accordingly
 *
 * Return: none
 */
void ol_ath_dcs_restore(struct ieee80211com *ic);

/**
 * ol_ath_dcs_attach() - Register the DCS functionality
 * @ic: ic handle
 *
 * Return: none
 */
void ol_ath_dcs_attach(struct ieee80211com *ic);

/**
 * ol_ath_dcs_attach() - Deregister dcs functionality
 * @ic: ic handle
 *
 * Return: none
 */
void ol_ath_dcs_dettach(struct ieee80211com *ic);

/**
 * ol_ath_soc_dcs_attach() - Register DCS with target
 * @soc: soc soft context object
 *
 * Return: none
 */
void ol_ath_soc_dcs_attach(ol_ath_soc_softc_t *soc);

/**
 * ol_ath_req_ext_dcs_trigger - Request sending DCS trigger to extenal handler
 * @scn: Pointer to net80211 softc object
 * @interference_type: Interference type
 *
 * Return: 0 on success, negative error number on failure
 */
int ol_ath_req_ext_dcs_trigger(struct ol_ath_softc_net80211 *scn,
			       uint32_t interference_type);

/**
 * wlan_dcs_im_print_stats() - Print dcs im stats
 * @prev_stats: dcs prev stats
 * @curr_stats: dcs curr stats
 *
 * Return: none
 */
void wlan_dcs_im_print_stats(wmi_host_dcs_im_tgt_stats_t *prev_stats,
			     wmi_host_dcs_im_tgt_stats_t *curr_stats);

/*
 * wlan_dcs_im_copy_stats() - Copy dcs im stats
 * @prev_stats: dcs prev stats
 * @curr_stats: dcs curr stats
 *
 * Return: none
 */
void wlan_dcs_im_copy_stats(wmi_host_dcs_im_tgt_stats_t *prev_stats,
			    wmi_host_dcs_im_tgt_stats_t *curr_stats);

/*
 * wlan_dcs_send_acs_request() - Send ACS request after DCS trigger
 * @vap: Pointer to the VAP structure
 *
 * Return:
 *       0: Success
 * -EINVAL: Failure
 */
int wlan_dcs_send_acs_request(struct ieee80211vap *vap);

/**
 * ol_ath_dcs_params:
 * Set/unset the DCS parameter.
 */
enum ol_ath_dcs_params {
	OL_ATH_DCS_PARAM_RANDOM_CHAN_EN,
	OL_ATH_DCS_PARAM_CSA_TBTT,
	OL_ATH_DCS_PARAM_MAX,
};

/**
 * ol_ath_set_dcs_param:
 * Set miscellaneous DCS parameters.
 * @ic   : ic handle
 * @param: DCS parameter
 * @value: value to set
 *
 * Return:
 * None
 */
void ol_ath_set_dcs_param(struct ieee80211com *ic,
			  enum ol_ath_dcs_params param,
			  uint32_t value);

/**
 * dcs_chanswitch_type:
 * Types of channel switching invoked by DCS.
 */
enum dcs_chanswitch_type {
	DCS_CHANSWITCH_CSA,  /* CSA channel switching */
	DCS_CHANSWITCH_HARD, /* Hard channel switch involving VDEV down/up */
};

/**
 * ol_ath_dcs_chan_seg:
 * Different segments in the channel band.
 */
enum ol_ath_dcs_chan_seg {
	OL_ATH_DCS_SEG_PRI20             =  0x1,
	OL_ATH_DCS_SEG_SEC20             =  0x2,
	OL_ATH_DCS_SEG_SEC40_LOWER       =  0x4,
	OL_ATH_DCS_SEG_SEC40_UPPER       =  0x8,
	OL_ATH_DCS_SEG_SEC40             =  0xC,
	OL_ATH_DCS_SEG_SEC80_LOWER       = 0x10,
	OL_ATH_DCS_SEG_SEC80_LOWER_UPPER = 0x20,
	OL_ATH_DCS_SEG_SEC80_UPPER_LOWER = 0x40,
	OL_ATH_DCS_SEG_SEC80_UPPER       = 0x80,
	OL_ATH_DCS_SEG_SEC80             = 0xF0,
};

#define OL_ATH_DCS_CENTERCHAN_OFFSET 10
#define OL_ATH_DCS_CHAN_FREQ_OFFSET   5
#define OL_ATH_DCS_GET_BITMAP_IDX(__awgn_info, __seg)                           \
	(((__awgn_info)->chan_bw_intf_bitmap) & OL_ATH_DCS_SEG_ ## __seg)
#define OL_ATH_DCS_IS_FREQ_IN_WIDTH(__cfreq, __cfreq0, __cfreq1,                \
				    __width, __freq)                            \
	((((__width) == IEEE80211_CWM_WIDTH20) &&                               \
	  ((__cfreq) == (__freq))) ||                                           \
	 (((__width) == IEEE80211_CWM_WIDTH40) &&                               \
	  (((__freq) >= ((__cfreq0) - (2 * OL_ATH_DCS_CHAN_FREQ_OFFSET))) &&    \
	   ((__freq) <= ((__cfreq0) + (2 * OL_ATH_DCS_CHAN_FREQ_OFFSET))))) ||  \
	 (((__width) == IEEE80211_CWM_WIDTH80) &&                               \
	  (((__freq) >= ((__cfreq0) - (6 * OL_ATH_DCS_CHAN_FREQ_OFFSET))) &&    \
           ((__freq) <= ((__cfreq0) + (6 * OL_ATH_DCS_CHAN_FREQ_OFFSET))))) ||  \
         (((__width) == IEEE80211_CWM_WIDTH160) &&                              \
          (((__freq) >= ((__cfreq1) - (14 * OL_ATH_DCS_CHAN_FREQ_OFFSET))) &&   \
           ((__freq) <= ((__cfreq1) + (14 * OL_ATH_DCS_CHAN_FREQ_OFFSET))))) || \
	 (((__width) == IEEE80211_CWM_WIDTH80_80) &&                            \
	  ((((__freq) >= ((__cfreq0) - (6 * OL_ATH_DCS_CHAN_FREQ_OFFSET))) &&   \
	   ((__freq) <= ((__cfreq0) + (6 * OL_ATH_DCS_CHAN_FREQ_OFFSET)))) ||   \
	   (((__freq) >= ((__cfreq1) - (6 * OL_ATH_DCS_CHAN_FREQ_OFFSET))) &&   \
	   ((__freq) <= ((__cfreq1) + (6 * OL_ATH_DCS_CHAN_FREQ_OFFSET)))))))

/* Default CSA TBTT count for CSA channel selection is 2 beacons */
#define DCS_CSA_TBTT_DEFAULT 2
#endif /* OL_IF_DCS_H */
