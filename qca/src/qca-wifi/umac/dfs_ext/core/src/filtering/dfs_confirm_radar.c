/*
 * Copyright (c) 2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

/**
 * DOC: dfs_confirm_radar.c
 * This file provides routines needed for initializing proprietary
 * external radar filters and to confirm radar detection.
 */

#include <dfs.h>
#include <dfs_process_radar_found_ind.h>
#include <dfs_confirm_radar.h>
#include <dfs_internal.h>

/**
 * struct dfs_pulse dfs_mkkn_radars - MKKN radar table for Offload chipsets.
 */
static struct dfs_pulse dfs_mkkn_radars[] = {
	/** Since the table is empty  no new radar type shall be detected.
	 * New filters shall be added to this tables after proper testing
	 * and verification.
	 */
	/* constant PRF based */
	/* Type 1 */
	/* 0.8-5us, 200  300 PRF, 10 pulses */
	{10, 5,   200,  400, 0,  4,  5,  0,  8, 15, 0,   0, 2, 5, 0, 91},
	{10, 5,   400,  600, 0,  4,  5,  0,  8, 15, 0,   0, 2, 5, 0, 92},
	{10, 5,   600,  800, 0,  4,  5,  0,  8, 15, 0,   0, 2, 5, 0, 93},
	{10, 5,   800, 1000, 0,  4,  5,  0,  8, 15, 0,   0, 2, 5, 0, 94},
	/* {10, 5,   200, 1000, 0,  6,  5,  0,  8, 15, 0,   0, 2, 5, 33}, */

	/* Type 2 */
	/* 0.8-15us, 200-1600 PRF, 15 pulses */
	{15, 15,  200, 1600, 0,  4, 8,  0, 18, 24, 0,   0, 0, 5, 0, 95},

};

struct dfs_pulse* dfs_get_ext_filter(enum DFS_DOMAIN domain, uint8_t *num_radars)
{
	switch (domain) {
		case DFS_MKKN_DOMAIN:
			*num_radars = QDF_ARRAY_SIZE(dfs_mkkn_radars);
			return dfs_mkkn_radars;
		case DFS_UNINIT_DOMAIN:
		case DFS_FCC_DOMAIN:
		case DFS_ETSI_DOMAIN:
		case DFS_MKK4_DOMAIN:
		case DFS_CN_DOMAIN:
		case DFS_KR_DOMAIN:
		case DFS_UNDEF_DOMAIN:
		default:
			*num_radars = 0;
			return NULL;
	}
}

/**
 * dfs_get_durmargin() - Find duration margin
 * @rf: Pointer to dfs_filter structure.
 * @durmargin: Duration margin
 */
static inline void dfs_get_durmargin(struct dfs_filter *rf,
		uint32_t *durmargin)
{
#define DUR_THRESH 10
#define LOW_MARGIN 4
#define HIGH_MARGIN 6

	if (rf->rf_maxdur < DUR_THRESH)
		*durmargin = LOW_MARGIN;
	else
		*durmargin = HIGH_MARGIN;

#undef DUR_THRESH
#undef LOW_MARGIN
#undef HIGH_MARGIN
}

/**
 * dfs_is_real_radar() - This function checks for fractional PRI and jitter in
 * sidx index to determine if the radar is real or not.
 * @dfs: Pointer to dfs structure.
 * @rf: Pointer to dfs_filter structure.
 * @ext_chan_flag: Radar detection flags on an extension channel.
 */
bool dfs_is_real_radar(struct wlan_dfs *dfs,
		struct dfs_filter *rf,
		int ext_chan_flag)
{
	int i = 0;
	int index;
	struct dfs_delayline *dl = &rf->rf_dl;
	struct dfs_delayelem *de;
	uint64_t target_ts = 0;
	struct dfs_pulseline *pl;
	int start_index = 0, current_index, next_index;
	unsigned char scores[FRAC_PRI_SCORE_ARRAY_SIZE];
	uint32_t pri_margin;
	uint64_t this_diff_ts;
	uint32_t search_bin;

	unsigned char max_score = 0;
	int max_score_index = 0;

	uint32_t min_searchdur = 0xFFFFFFFF;
	uint32_t max_searchdur = 0x0;
	uint32_t durmargin = 0;
	uint32_t this_dur;
	uint32_t this_deltadur;

	pl = dfs->pulses;

	OS_MEMZERO(scores, sizeof(scores));
	scores[0] = rf->rf_threshold;

	pri_margin = dfs_get_pri_margin(dfs, ext_chan_flag,
			(rf->rf_patterntype == 1));
	dfs_get_durmargin(rf, &durmargin);


	/*
	 * Look for the entry that matches dl_seq_num_second.
	 * we need the time stamp and diff_ts from there.
	 */

	for (i = 0; i < dl->dl_numelems; i++) {
		index = (dl->dl_firstelem + i) & DFS_MAX_DL_MASK;
		de = &dl->dl_elems[index];
		if (dl->dl_seq_num_second == de->de_seq_num)
			target_ts = de->de_ts - de->de_time;

		if (de->de_dur < min_searchdur)
			min_searchdur = de->de_dur;

		if (de->de_dur > max_searchdur)
			max_searchdur = de->de_dur;
	}

	if (dfs->dfs_debug_mask & WLAN_DEBUG_DFS2) {
		dfs_print_delayline(dfs, &rf->rf_dl);

		/* print pulse line */
		dfs_debug(dfs, WLAN_DEBUG_DFS2,
				"%s: Pulse Line\n", __func__);
		for (i = 0; i < pl->pl_numelems; i++) {
			index =  (pl->pl_firstelem + i) &
				DFS_MAX_PULSE_BUFFER_MASK;
			dfs_debug(dfs, WLAN_DEBUG_DFS2,
					"Elem %u: ts=%llu dur=%u, seq_num=%d, delta_peak=%d, psidx_diff=%d\n",
					i, pl->pl_elems[index].p_time,
					pl->pl_elems[index].p_dur,
					pl->pl_elems[index].p_seq_num,
					pl->pl_elems[index].p_delta_peak,
					pl->pl_elems[index].p_psidx_diff);
		}
	}

	/*
	 * Walk through the pulse line and find pulse with target_ts.
	 * Then continue until we find entry with seq_number dl_seq_num_stop.
	 */

	for (i = 0; i < pl->pl_numelems; i++) {
		index =  (pl->pl_firstelem + i) & DFS_MAX_PULSE_BUFFER_MASK;
		if (pl->pl_elems[index].p_time == target_ts) {
			dl->dl_seq_num_start = pl->pl_elems[index].p_seq_num;
			start_index = index; /* save for future use */
		}
	}

	dfs_debug(dfs, WLAN_DEBUG_DFS2,
			"%s: target_ts=%llu, dl_seq_num_start=%d, dl_seq_num_second=%d, dl_seq_num_stop=%d\n",
			__func__, target_ts, dl->dl_seq_num_start,
			dl->dl_seq_num_second, dl->dl_seq_num_stop);

	current_index = start_index;
	while (pl->pl_elems[current_index].p_seq_num < dl->dl_seq_num_stop) {
		next_index = (current_index + 1) & DFS_MAX_PULSE_BUFFER_MASK;
		this_diff_ts = pl->pl_elems[next_index].p_time -
			pl->pl_elems[current_index].p_time;

		this_dur =  pl->pl_elems[next_index].p_dur;
		this_deltadur = DFS_MIN(DFS_DIFF(this_dur, min_searchdur),
				DFS_DIFF(this_dur, max_searchdur));

		/* Now update the score for this diff_ts */
		for (i = 1; i < FRAC_PRI_SCORE_ARRAY_SIZE; i++) {
			search_bin = dl->dl_search_pri / (i + 1);

			/*
			 * We do not give score to PRI that is lower then the
			 * limit.
			 */
			if (search_bin < DFS_INVALID_PRI_LIMIT)
				break;

			/*
			 * Increment the score if this_diff_ts belongs to this
			 * search_bin +/- margin.
			 */
			if ((this_diff_ts >= (search_bin - pri_margin)) &&
					(this_diff_ts <= (search_bin + pri_margin)) &&
					(this_deltadur < durmargin)) {
				/*increment score */
				scores[i]++;
			}
		}
		current_index = next_index;
	}

	for (i = 0; i < FRAC_PRI_SCORE_ARRAY_SIZE; i++)
		if (scores[i] > max_score) {
			max_score = scores[i];
			max_score_index = i;
		}

	if (max_score_index != 0) {
		dfs_debug(dfs, WLAN_DEBUG_DFS_ALWAYS,
				"Rejecting Radar since Fractional PRI detected: searchpri=%d, threshold=%d, fractional PRI=%d, Fractional PRI score=%d",
				dl->dl_search_pri, scores[0],
				dl->dl_search_pri/(max_score_index + 1),
				max_score);
		return 0;
	}


	/* Check for frequency spread */
	if (dl->dl_min_sidx > pl->pl_elems[start_index].p_sidx)
		dl->dl_min_sidx = pl->pl_elems[start_index].p_sidx;

	if (dl->dl_max_sidx < pl->pl_elems[start_index].p_sidx)
		dl->dl_max_sidx = pl->pl_elems[start_index].p_sidx;

	if ((dl->dl_max_sidx - dl->dl_min_sidx) > rf->rf_sidx_spread) {
		dfs_debug(dfs, WLAN_DEBUG_DFS_ALWAYS,
				"Rejecting Radar since frequency spread is too large : min_sidx=%d, max_sidx=%d, rf_sidx_spread=%d",
				dl->dl_min_sidx, dl->dl_max_sidx,
				rf->rf_sidx_spread);
		return 0;
	}

	if ((rf->rf_check_delta_peak) &&
			((dl->dl_delta_peak_match_count +
			  dl->dl_psidx_diff_match_count - 1) <
			 rf->rf_threshold)) {
		dfs_debug(dfs, WLAN_DEBUG_DFS_ALWAYS,
				"Rejecting Radar since delta peak values are invalid : dl_delta_peak_match_count=%d, dl_psidx_diff_match_count=%d, rf_threshold=%d",
				dl->dl_delta_peak_match_count,
				dl->dl_psidx_diff_match_count,
				rf->rf_threshold);
		return 0;
	}
	dfs_debug(dfs, WLAN_DEBUG_DFS_FALSE_DET, "%s : dl->dl_min_sidx: %d , dl->dl_max_sidx :%d",
			__func__, dl->dl_min_sidx, dl->dl_max_sidx);

	dfs->dfs_freq_offset = DFS_SIDX_TO_FREQ_OFFSET((dl->dl_min_sidx +
				dl->dl_max_sidx) / 2);
	return 1;
}
