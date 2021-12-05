/*
 * =====================================================================================
 *
 *       Filename:  ath_classifier.c
 *
 *    Description:  Classifier
 *
 *        Version:  1.0
 *        Created:  12/26/2011 11:16:31 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Anil Hebbar (Algorithm)
 *         Author:  S.Karthikeyan
 *        Company:  Qualcomm Atheros
 *
 *        Copyright (c) 2012-2021 Qualcomm Technologies, Inc.
 *
 *        All Rights Reserved.
 *        Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 *        2012-2016 Qualcomm Atheros, Inc.
 *
 *        All Rights Reserved.
 *        Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 */

#include "stdio.h"
#include "stdlib.h"
#include <linux/types.h>
#include <string.h>
#include <math.h>
#include "ath_classifier.h"

CLASSIFER_DATA_STRUCT class_data[CLASSIFIER_HASHSIZE];
float powf_precompute_table[256];

/* Buffers to log the FFT bin values */
static u_int8_t bin_log_buf[MAX_NUM_BINS_PRI80 * SPECTRAL_DBG_LOG_SAMP];
static int32_t mis_log_buf[NUM_MISC_ITEMS * SPECTRAL_DBG_LOG_SAMP];

/* Added to support secondary 80Mhz segment */
static u_int8_t bin_log_buf_sec80[MAX_NUM_BINS_SEC80 * SPECTRAL_DBG_LOG_SAMP];
static int32_t mis_log_buf_sec80[NUM_MISC_ITEMS * SPECTRAL_DBG_LOG_SAMP];

/* Added to support extra 5 MHz segment */
static u_int8_t bin_log_buf_5mhz[MAX_NUM_BINS_5MHZ * SPECTRAL_DBG_LOG_SAMP];

/* Added to support logging of sample detection state */
/* Primary 80 */
static u_int32_t state_mc_log[SPECTRAL_DBG_LOG_SAMP];
/* Secondary 80 */
static u_int32_t state_mc_log_sec80[SPECTRAL_DBG_LOG_SAMP];

static void init_powf_table(void);

/*
 * Function     : init_classifier_lookup_tables
 * Description  : Initialize all look up tables, should be called first
 * Input params : Void
 *
 */
void init_classifier_lookup_tables(void)
{
    init_powf_table();
}

/*
 * Function     : init_classifier_data
 * Description  : Initializes the classifier data structure for given MAC address
 * Input params : MAC address, pointer to Spectral capabilities information,
 *                length of Spectral capabilities information
 */
void init_classifier_data(const u_int8_t* macaddr, void *spectral_caps,
        size_t spectral_caps_len)
{
    int index = 0;
    CLASSIFER_DATA_STRUCT *pclas = NULL;

    SPECTRAL_CLASSIFIER_ASSERT(macaddr != NULL);
    SPECTRAL_CLASSIFIER_ASSERT(spectral_caps != NULL);
    SPECTRAL_CLASSIFIER_ASSERT(spectral_caps_len == sizeof(pclas->caps));

    index = CLASSIFIER_HASH(macaddr);
    pclas = &class_data[index];

    memcpy(&(pclas->caps), spectral_caps, sizeof(pclas->caps));

    if (pclas->caps.advncd_spectral_cap == true) {
        pclas->thresholds.cw_int_det_thresh = ADVNCD_CW_INT_DET_THRESH;
        pclas->thresholds.wifi_det_min_diff = (int)ADVNCD_WIFI_DET_MIN_DIFF;
        pclas->thresholds.fhss_sum_scale_down_factor = ADVNCD_FHSS_SUM_SCALE_DOWN_FACTOR;
        pclas->thresholds.mwo_pwr_variation_threshold = ADVNCD_MWO_POW_VARTIATION_THRESH;
    } else {
        pclas->thresholds.cw_int_det_thresh = CW_INT_DET_THRESH;
        pclas->thresholds.wifi_det_min_diff = (int)WIFI_DET_MIN_DIFF;
        pclas->thresholds.fhss_sum_scale_down_factor = FHSS_SUM_SCALE_DOWN_FACTOR;
        pclas->thresholds.mwo_pwr_variation_threshold = MWO_POW_VARIATION_THRESH;
    }

    pclas->commit_done = false;
    pclas->spectral_log_first_time = true;
}

/*
 * Function     : get_classifier_data
 * Description  : Returns the classifier data structure for given MAC address
 * Input params : MAC address
 * Return       : Pointer to Classifier data structure
 *
 */
CLASSIFER_DATA_STRUCT* get_classifier_data(const u_int8_t* macaddr)
{
    int index = CLASSIFIER_HASH(macaddr);
    return &class_data[index];
}

/*
 * Function     : spectral_scan_log_data
 * Description  : Log the spectral data
 * Input params : Pointer to classifier data structure, mode, commit
 * Return       : Void
 */
static void
spectral_scan_log_data(struct spectral_samp_msg* msg, CLASSIFER_DATA_STRUCT *pclas, DETECT_MODE mode, u_int32_t commit)
{
    u_int8_t *buf_ptr;

    /* Check if the mode matches */
    if (pclas->log_mode != mode) {
        return;
    }

    /* Check if enough data has already been logged */
    if (pclas->commit_done) {
        return;
    }

    if (msg->signature != SPECTRAL_SIGNATURE) {
        fprintf(stderr, "Unexpected Spectral signature %u\n", msg->signature);
        return;
    }

    /* Check if the initialization needs to be done */
    if (pclas->spectral_log_first_time) {
        pclas->spectral_log_first_time = false;
        pclas->spectral_log_num_bin = msg->samp_data.bin_pwr_count;
        pclas->spectral_log_num_bin_sec80 = msg->samp_data.bin_pwr_count_sec80;
        pclas->spectral_log_num_bin_5mhz = msg->samp_data.bin_pwr_count_5mhz;
        pclas->spectral_bin_bufSave = bin_log_buf;
        pclas->spectral_bin_bufSave_sec80 = bin_log_buf_sec80;
        pclas->spectral_bin_bufSave_5mhz = bin_log_buf_5mhz;
        pclas->spectral_data_misc = mis_log_buf;
        pclas->spectral_data_misc_sec80 = mis_log_buf_sec80;
        pclas->spectral_num_samp_log = 0;
        pclas->last_samp = 0;
        pclas->spectral_state_log = state_mc_log;
        pclas->spectral_state_log_sec80 = state_mc_log_sec80;
    }

    if (!commit) {
        /* Get the offset to the place where the data needs to be saved */
        buf_ptr = pclas->spectral_bin_bufSave +
                  pclas->spectral_log_num_bin * pclas->last_samp;

        /* Copy the bins */
        memcpy(buf_ptr, msg->samp_data.bin_pwr, pclas->spectral_log_num_bin);

        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS] =
                                                    msg->samp_data.spectral_tstamp;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 1] =
                                                    msg->samp_data.spectral_rssi;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 2] =
                                                    msg->samp_data.noise_floor;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 3] =
                                                    msg->samp_data.spectral_agc_total_gain;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 4] =
                                                    msg->samp_data.spectral_gainchange;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 5] =
                                                    msg->samp_data.spectral_pri80ind;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 6] =
                                                    msg->samp_data.raw_timestamp;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 7] =
                                                    msg->samp_data.timestamp_war_offset;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 8] =
                                                    msg->samp_data.last_raw_timestamp;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 9] =
                                                    msg->samp_data.reset_delay;
        pclas->spectral_data_misc[pclas->last_samp * NUM_MISC_ITEMS + 10] =
                                                    msg->samp_data.target_reset_count;
        pclas->spectral_state_log[pclas->last_samp] = pclas->pri80_detection_state;

        /* Logging secondary 80MHz data if channel width is 160/80p80 MHz */
        if (IS_CHAN_WIDTH_160_OR_80P80(msg->samp_data.ch_width)) {
            u_int8_t *buf_ptr_sec80;

            buf_ptr_sec80 = pclas->spectral_bin_bufSave_sec80 +
                            pclas->spectral_log_num_bin_sec80 * pclas->last_samp;

            memcpy(buf_ptr_sec80, msg->samp_data.bin_pwr_sec80, pclas->spectral_log_num_bin_sec80);

            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS] =
                                                        msg->samp_data.spectral_tstamp;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 1] =
                                                        msg->samp_data.spectral_rssi_sec80;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 2] =
                                                        msg->samp_data.noise_floor_sec80;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 3] =
                                                        msg->samp_data.spectral_agc_total_gain_sec80;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 4] =
                                                        msg->samp_data.spectral_gainchange_sec80;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 5] =
                                                        msg->samp_data.spectral_pri80ind_sec80;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 6] =
                                                        msg->samp_data.raw_timestamp_sec80;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 7] =
                                                        msg->samp_data.timestamp_war_offset;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 8] =
                                                        msg->samp_data.last_raw_timestamp;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 9] =
                                                        msg->samp_data.reset_delay;
            pclas->spectral_data_misc_sec80[pclas->last_samp * NUM_MISC_ITEMS + 10] =
                                                        msg->samp_data.target_reset_count;
            pclas->spectral_state_log_sec80[pclas->last_samp] = pclas->sec80_detection_state;

        }

        /* Logging additional 5 MHz FFT bins */
        if (pclas->spectral_log_num_bin_5mhz > 0) {
            u_int8_t *buf_ptr_5mhz;

            buf_ptr_5mhz = pclas->spectral_bin_bufSave_5mhz +
                           pclas->spectral_log_num_bin_5mhz * pclas->last_samp;
            memcpy(buf_ptr_5mhz, msg->samp_data.bin_pwr_5mhz, pclas->spectral_log_num_bin_5mhz);
        }
        pclas->spectral_num_samp_log++;

        if (pclas->spectral_num_samp_log >= SPECTRAL_DBG_LOG_SAMP ) {
            pclas->spectral_num_samp_log = SPECTRAL_DBG_LOG_SAMP;
            /* In case of log all samples, there is no trigger, commit */
            if (pclas->log_mode == SPECT_CLASS_DETECT_ALL) {
                commit = 1;
            }
        }

        pclas->last_samp++;

        if (pclas->last_samp == SPECTRAL_DBG_LOG_SAMP) {
            pclas->last_samp = 0;
        }
    }

    /* Check if enough samples have been captured. If so, log the data */
    if (commit) {
        /* Commit data to file */
        FILE* spectral_log_fp = fopen("classifier.log", "wt");
        u_int32_t version;

        /* Check and update LOG VERSION.
         * Classifier state information is to be written
         * while logging individual interference samples
         * such as MWO/CW/FHSS/WIFI.
         */
        if (athssd_is_sample_state_logging_supported() &&
            pclas->log_mode != SPECT_CLASS_DETECT_ALL &&
            pclas->log_mode != SPECT_CLASS_DETECT_NONE) {
            version = SPECTRAL_LOG_VERSION_ID4;
        } else {
            version = SPECTRAL_LOG_VERSION_ID3;
        }

        if (!spectral_log_fp) {
            printf("Spectral Classifier: Could not open file %s to write\n", "classifier.log");
            return;
        }

        printf("Spectral Classifier: Number of samples captured %zu\n", pclas->spectral_num_samp_log);

        printf("Spectral Classifier: Writing samples to file. Please wait for a \n"
               "                     few minutes. Classification functionality \n"
               "                     might be limited in the meantime...\n");
        {
            /* Print the data into a ascii file */
            size_t cnt = 0;
            bool is_165mhz_opearation = (msg->samp_data.bin_pwr_count_5mhz > 0);
            uint64_t num_bytes_written = 0;
            int wcnt;
            char delimiter = ' ';
            int advncd_spectral = 0;
            size_t sampIdx = pclas->last_samp;

            if (pclas->spectral_num_samp_log < SPECTRAL_DBG_LOG_SAMP) {
                /* In this case, no wrap around, so the first sample is the start of the
                * buffer
                */
                sampIdx = 0;
            }

            wcnt = fprintf(spectral_log_fp, "***** THIS IS A MACHINE GENERATED FILE, DO NOT EDIT *****\n\n");

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "version:%c%u\n", delimiter, version);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "mode:%c%u\n", delimiter, msg->samp_data.spectral_mode);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "primary_frequency:%c%u\n", delimiter, msg->freq);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "cfreq1:%c%u\n", delimiter, msg->vhtop_ch_freq_seg1);

            if (wcnt < 0) {
                perror("Error while writing to outFile");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "cfreq2:%c%u\n", delimiter, msg->vhtop_ch_freq_seg2);

            if (wcnt < 0) {
                perror("Error while writing to outFile");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "agile_frequency1:%c%u\n", delimiter,
                    msg->agile_freq1);

            if (wcnt < 0) {
                perror("Error while writing to outFile");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "agile_frequency2:%c%u\n", delimiter,
                    msg->agile_freq2);

            if (wcnt < 0) {
                perror("Error while writing to outFile");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "channel_width:%c%u\n", delimiter, msg->samp_data.ch_width);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "agile_channel_width:%c%u\n", delimiter, msg->samp_data.agile_ch_width);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "mac_address:%c%s\n", delimiter,
                           ether_sprintf(pclas->macaddr));

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "gen3_linear_scaling:%c%u\n", delimiter, 1);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "165mhz_operation:%c%u\n", delimiter,
                           is_165mhz_opearation);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "lb_edge_extrabins:%c%u\n", delimiter, msg->samp_data.lb_edge_extrabins);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "rb_edge_extrabins:%c%u\n", delimiter, msg->samp_data.rb_edge_extrabins);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "\nspectral_caps\n\n");

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "phy_diag_cap:%c%u\n", delimiter, pclas->caps.phydiag_cap);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "radar_cap:%c%u\n", delimiter, pclas->caps.radar_cap);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "spectral_cap:%c%u\n", delimiter, pclas->caps.spectral_cap);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "advanced_spectral_cap:%c%u\n", delimiter,
                pclas->caps.advncd_spectral_cap);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "hw_gen:%c%u\n", delimiter, pclas->caps.hw_gen);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "is_scaling_params_populated:%c%u\n", delimiter,
                           pclas->caps.is_scaling_params_populated);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "formula_id:%c%u\n", delimiter,
                           pclas->caps.formula_id);

            if (wcnt < 0) {
                perror("Error while writing to outFile");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "low_level_offset:%c%d\n", delimiter,
                           pclas->caps.low_level_offset);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "high_level_offset:%c%d\n", delimiter,
                           pclas->caps.high_level_offset);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "rssi_thr:%c%d\n", delimiter,
                           pclas->caps.rssi_thr);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "default_agc_max_gain:%c%u\n", delimiter,
                           pclas->caps.default_agc_max_gain);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "agile_spectral_cap:%c%u\n", delimiter,
                           pclas->caps.agile_spectral_cap);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "agile_spectral_cap_160:%c%u\n", delimiter,
                           pclas->caps.agile_spectral_cap_160);
            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }
            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "agile_spectral_cap_80p80:%c%u\n", delimiter,
                           pclas->caps.agile_spectral_cap_80p80);
            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }
            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "num_detectors_20mhz:%c%u\n", delimiter,
                           pclas->caps.num_detectors_20mhz);
            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }
            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "num_detectors_40mhz:%c%u\n", delimiter,
                           pclas->caps.num_detectors_40mhz);
            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }
            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "num_detectors_80mhz:%c%u\n", delimiter,
                           pclas->caps.num_detectors_80mhz);
            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }
            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "num_detectors_160mhz:%c%u\n", delimiter,
                           pclas->caps.num_detectors_160mhz);
            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }
            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "num_detectors_80p80mhz:%c%u\n", delimiter,
                           pclas->caps.num_detectors_80p80mhz);
            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }
            num_bytes_written += wcnt;

            advncd_spectral = pclas->caps.advncd_spectral_cap;
            wcnt = fprintf(spectral_log_fp, "\nspectral_params\n\n");

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            if (advncd_spectral)
                wcnt = fprintf(spectral_log_fp, "num_spectral_params:%c%u\n", delimiter,
                               NUM_SPECTRAL_PARAMS_ADVANCED);
            else
                wcnt = fprintf(spectral_log_fp, "num_spectral_params:%c%u\n", delimiter,
                               NUM_SPECTRAL_PARAMS_NON_ADVANCED);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            if (!advncd_spectral) {
                wcnt = fprintf(spectral_log_fp, "fft_period:%c%u\n", delimiter,
                               pclas->spectral_params.ss_fft_period);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;
            }

            wcnt = fprintf(spectral_log_fp, "scan_period:%c%u\n", delimiter,
                           pclas->spectral_params.ss_period);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "scan_count:%c%u\n", delimiter, pclas->spectral_params.ss_count);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            if (!advncd_spectral) {
                wcnt = fprintf(spectral_log_fp, "short_report:%c%u\n", delimiter,
                               pclas->spectral_params.ss_short_report);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;
            }

            wcnt = fprintf(spectral_log_fp, "priority:%c%u\n", delimiter,
                           pclas->spectral_params.ss_spectral_pri);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            if (advncd_spectral) {
                wcnt = fprintf(spectral_log_fp, "fft_size:%c%u\n", delimiter,
                               pclas->spectral_params.ss_fft_size);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "gc_ena:%c%u\n", delimiter,
                               pclas->spectral_params.ss_gc_ena);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "restart_ena:%c%u\n", delimiter,
                               pclas->spectral_params.ss_restart_ena);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "noise_floor_ref:%c%d\n", delimiter,
                               (int8_t)pclas->spectral_params.ss_noise_floor_ref);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "init_delay:%c%u\n", delimiter,
                               pclas->spectral_params.ss_init_delay);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "nb_tone_thr:%c%u\n", delimiter,
                               pclas->spectral_params.ss_nb_tone_thr);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "str_bin_thr:%c%u\n", delimiter,
                               pclas->spectral_params.ss_str_bin_thr);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "wb_rpt_mode:%c%u\n", delimiter,
                               pclas->spectral_params.ss_wb_rpt_mode);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "rssi_rpt_mode:%c%u\n", delimiter,
                               pclas->spectral_params.ss_rssi_rpt_mode);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "rssi_thr:%c%d\n", delimiter,
                               (int8_t)pclas->spectral_params.ss_rssi_thr);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "pwr_format:%c%u\n", delimiter,
                               pclas->spectral_params.ss_pwr_format);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "rpt_mode:%c%u\n", delimiter,
                               pclas->spectral_params.ss_rpt_mode);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "bin_scale:%c%u\n", delimiter,
                               pclas->spectral_params.ss_bin_scale);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "dBm_adj:%c%u\n", delimiter, pclas->spectral_params.ss_dbm_adj);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "chn_mask:%c%u\n", delimiter,
                               pclas->spectral_params.ss_chn_mask);

                if (wcnt < 0) {
                    perror("Error while writing to file");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "frequency1:%c%u\n", delimiter,
                               pclas->spectral_params.ss_frequency.cfreq1);

                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }

                num_bytes_written += wcnt;

                wcnt = fprintf(spectral_log_fp, "frequency2:%c%u\n", delimiter,
                               pclas->spectral_params.ss_frequency.cfreq2);

                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }

                num_bytes_written += wcnt;
            }

            wcnt = fprintf(spectral_log_fp, "\n");

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            wcnt = fprintf(spectral_log_fp, "S.No %c Num-FFT-Bins(N) %c bin1 %c bin2 %c ... %c"
                           "binN %c Timestamp %c RSSI %c NF %c AGC-Gain %c Gain-Change %c Pri80-Indication %c"
                           "raw_timestamp %c timestamp_war_offset %c last_raw_timestamp %c reset_delay %c reset_count %c detection state\n",
                           delimiter, delimiter, delimiter, delimiter,
                           delimiter, delimiter, delimiter, delimiter,
                           delimiter, delimiter, delimiter, delimiter,
                           delimiter, delimiter, delimiter, delimiter, delimiter);

            if (wcnt < 0) {
                perror("Error while writing to file");
                goto fail;
            }

            num_bytes_written += wcnt;

            for (cnt = 0; cnt < pclas->spectral_num_samp_log; cnt++) {
                size_t valCnt = 0;
                int is_pwr_format_enabled = 0;
                u_int8_t *buf_ptr;
                u_int8_t *buf_ptr_sec80;
                u_int8_t *buf_ptr_5mhz;

                buf_ptr = pclas->spectral_bin_bufSave + pclas->spectral_log_num_bin * sampIdx;
                buf_ptr_sec80 = pclas->spectral_bin_bufSave_sec80 +
                                pclas->spectral_log_num_bin_sec80 * sampIdx;
                buf_ptr_5mhz = pclas->spectral_bin_bufSave_5mhz +
                           pclas->spectral_log_num_bin_5mhz * sampIdx;

                /* Write sample number */
                wcnt = fprintf(spectral_log_fp, "%zu %c ", cnt, delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write bin count */
                wcnt = fprintf(spectral_log_fp, "%zu %c ", pclas->spectral_log_num_bin, delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                for (valCnt = 0; valCnt < pclas->spectral_log_num_bin; valCnt++) {
                    if (is_pwr_format_enabled)
                        /* Write bin values, dbm format */
                        wcnt = fprintf(spectral_log_fp, "%d %c ",
                                         (int8_t)(buf_ptr[valCnt]), delimiter);
                    else
                        /* Write bin values, linear format */
                        wcnt = fprintf(spectral_log_fp, "%u %c ",
                                         (u_int8_t)(buf_ptr[valCnt]), delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;
                }

                /* Write timestamp */
                wcnt = fprintf(spectral_log_fp, "%u %c ", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS],
                               delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write RSSI */
                wcnt = fprintf(spectral_log_fp, "%d %c ", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 1],
                               delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write noise floor */
                wcnt = fprintf(spectral_log_fp, "%d %c ", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 2],
                               delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write AGC total gain */
                wcnt = fprintf(spectral_log_fp, "%d %c ", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 3],
                               delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write gain change bit */
                wcnt = fprintf(spectral_log_fp, "%d %c ", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 4],
                               delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write pri80 indication bit */
                wcnt = fprintf(spectral_log_fp, "%u %c ", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 5],
                               delimiter);
                if (wcnt < 0) {
                    perror("Error while writing to outFile");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write raw_timestamp */
                wcnt = fprintf(spectral_log_fp, "%u %c", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 6],
                               delimiter);
                if (wcnt < 0) {
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write timestamp_war_offset */
                wcnt = fprintf(spectral_log_fp, "%u %c", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 7],
                               delimiter);
                if (wcnt < 0) {
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write last_raw_timestamp */
                wcnt = fprintf(spectral_log_fp, "%u %c", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 8],
                               delimiter);
                if (wcnt < 0) {
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write reset_delay */
                wcnt = fprintf(spectral_log_fp, "%u %c", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 9],
                               delimiter);
                if (wcnt < 0) {
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto fail;
                }
                num_bytes_written += wcnt;

                /* Write target_rest_count */
                wcnt = fprintf(spectral_log_fp, "%u %c", pclas->spectral_data_misc[sampIdx * NUM_MISC_ITEMS + 10],
                               delimiter);
                if (wcnt < 0) {
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto fail;
                }
                num_bytes_written += wcnt;

                if (version == SPECTRAL_LOG_VERSION_ID4) {
                    /* Write detection_state */
                    wcnt = fprintf(spectral_log_fp, "0x%08X %c\n", pclas->spectral_state_log[sampIdx],
                                   delimiter);
                } else {
                    wcnt = fprintf(spectral_log_fp, "\n");
                }
                if (wcnt < 0) {
                    fprintf(stderr, "Error while writing to outFile\n");
                    goto fail;
                }
                num_bytes_written += wcnt;

                buf_ptr += pclas->spectral_log_num_bin;

                if (IS_CHAN_WIDTH_160_OR_80P80(msg->samp_data.ch_width)) {
                    /* Write sample number */
                    wcnt = fprintf(spectral_log_fp, "%zu %c ", cnt, delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write bin count */
                    wcnt = fprintf(spectral_log_fp, "%zu %c ", pclas->spectral_log_num_bin_sec80,
                                   delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    for (valCnt = 0; valCnt < pclas->spectral_log_num_bin_sec80; valCnt++)
                    {
                        if (is_pwr_format_enabled) {
                            /* Write bin values, dbm format */
                            wcnt =fprintf(spectral_log_fp, "%d %c ", (int8_t)(buf_ptr_sec80[valCnt]),
                                          delimiter);
                            if (wcnt < 0) {
                                perror("Error while writing to outFile");
                                goto fail;
                            }
                            num_bytes_written += wcnt;

                        } else {
                            /* Write bin values, linear format */
                            wcnt = fprintf(spectral_log_fp, "%u %c ", (u_int8_t)(buf_ptr_sec80[valCnt]),
                                           delimiter);
                            if (wcnt < 0) {
                                perror("Error while writing to outFile");
                                goto fail;
                            }
                            num_bytes_written += wcnt;
                        }
                    }

                    /* Write timestamp */
                    wcnt = fprintf(spectral_log_fp, "%u %c ",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS],
                                   delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write RSSI */
                    wcnt = fprintf(spectral_log_fp, "%d %c ",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 1],
                                   delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write noise floor */
                    wcnt = fprintf(spectral_log_fp, "%d %c ",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 2],
                                   delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write AGC total gain */
                    wcnt = fprintf(spectral_log_fp, "%d %c ",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 3],
                                   delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write gain change bit */
                    wcnt = fprintf(spectral_log_fp, "%d %c ",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 4],
                                   delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write pri80 indication bit */
                    wcnt = fprintf(spectral_log_fp, "%u %c ",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 5],
                                   delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write raw_timestamp_sec80 */
                    wcnt = fprintf(spectral_log_fp, "%u %c",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 6],
                                   delimiter);
                    if (wcnt < 0) {
                        fprintf(stderr, "Error while writing to outFile\n");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write timestamp_war_offset */
                    wcnt = fprintf(spectral_log_fp, "%u %c",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 7],
                                   delimiter);
                    if (wcnt < 0) {
                        fprintf(stderr, "Error while writing to outFile\n");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write last_raw_timestamp */
                    wcnt = fprintf(spectral_log_fp, "%u %c",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 8],
                                   delimiter);
                    if (wcnt < 0) {
                        fprintf(stderr, "Error while writing to outFile\n");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write reset_delay */
                    wcnt = fprintf(spectral_log_fp, "%u %c",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 9],
                                   delimiter);
                    if (wcnt < 0) {
                        fprintf(stderr, "Error while writing to outFile\n");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write target_reset_count */
                    wcnt = fprintf(spectral_log_fp, "%u %c",
                                   pclas->spectral_data_misc_sec80[sampIdx * NUM_MISC_ITEMS + 10],
                                   delimiter);
                    if (wcnt < 0) {
                        fprintf(stderr, "Error while writing to outFile\n");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    if (version == SPECTRAL_LOG_VERSION_ID4) {
                        /* Write detection_state */
                        wcnt = fprintf(spectral_log_fp, "0x%08X %c\n", pclas->spectral_state_log_sec80[sampIdx],
                                       delimiter);
                    } else {
                        wcnt = fprintf(spectral_log_fp, "\n");
                    }
                    if (wcnt < 0) {
                        fprintf(stderr, "Error while writing to outFile\n");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    buf_ptr_sec80 += pclas->spectral_log_num_bin_sec80;
                }

                if (pclas->spectral_log_num_bin_5mhz > 0) {
                    /* Write sample number */
                    wcnt = fprintf(spectral_log_fp, "%zu %c ", cnt, delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    /* Write bin count */
                    wcnt = fprintf(spectral_log_fp, "%zu %c ", pclas->spectral_log_num_bin_5mhz, delimiter);
                    if (wcnt < 0) {
                        perror("Error while writing to outFile");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    for (valCnt = 0; valCnt < pclas->spectral_log_num_bin_5mhz; valCnt++)
                    {
                        if (is_pwr_format_enabled) {
                            /* Write bin values, dbm format */
                            wcnt =fprintf(spectral_log_fp, "%d %c ",
                                            (int8_t)(buf_ptr_5mhz[valCnt]),
                                            delimiter);
                            if (wcnt < 0) {
                                perror("Error while writing to outFile");
                                goto fail;
                            }
                            num_bytes_written += wcnt;

                        }
                        else {
                            /* Write bin values, linear format */
                            wcnt = fprintf(spectral_log_fp, "%u %c ",
                                             (u_int8_t)(buf_ptr_5mhz[valCnt]),
                                             delimiter);
                            if (wcnt < 0) {
                                perror("Error while writing to outFile");
                                goto fail;
                            }
                            num_bytes_written += wcnt;
                        }
                    }
                    /* Write new line */
                    wcnt = fprintf(spectral_log_fp, "\n");
                    if (wcnt < 0) {
                        fprintf(stderr, "Error while writing to outFile\n");
                        goto fail;
                    }
                    num_bytes_written += wcnt;

                    buf_ptr_5mhz += pclas->spectral_log_num_bin_5mhz;
                }

                sampIdx++;
                if (sampIdx == SPECTRAL_DBG_LOG_SAMP) {
                    sampIdx = 0;
                }
            }
        }
        printf("Spectral Classifier: Completed writing samples to file.\n");
fail:
        /* Cleanup */
        fclose(spectral_log_fp);
        system("sync");
        pclas->commit_done = true;
    }
}

/*
 * Function     : init_powf_table
 * Description  : Initialize precomputed table for powf function
 * Input params : Void
 * Return       : Void
 */
static void init_powf_table(void)
{
    int16_t i;

    for (i = -128; i <= 127; i++) {
        powf_precompute_table[((u_int8_t)i)] = powf((float)10.0, (float)(i / 20.0));
    }

    return;
}

/*
 * Function     : get_detection_freq
 * Description  : Helper function to get detection frequency corresponding to
 *                the Spectral mode
 * Input params : Pointer to SAMP message
 * Return       : Non-zero detection frequency on success, zero on failure
 */
static u_int16_t get_detection_freq(struct spectral_samp_msg *msg)
{
    SPECTRAL_CLASSIFIER_ASSERT(NULL != msg);

    switch(msg->samp_data.spectral_mode)
    {
        case SPECTRAL_SCAN_MODE_NORMAL:
            return msg->freq;
        case SPECTRAL_SCAN_MODE_AGILE:
            return msg->agile_freq1;
        default:
            return 0;
    }
}

/*
 * Function     : get_detection_freq_descriptor_str
 * Description  : Helper function to get detection frequency descriptor string
 *                corresponding to the Spectral mode
 * Input params : Pointer to SAMP message
 * Return       : Frequency descriptor string on success, NULL on failure
 */
static const char* get_detection_freq_descriptor_str(
        struct spectral_samp_msg *msg)
{
    SPECTRAL_CLASSIFIER_ASSERT(NULL != msg);

    switch(msg->samp_data.spectral_mode)
    {
        case SPECTRAL_SCAN_MODE_NORMAL:
            return SPECT_DETECTION_FREQ_DESC_STR_NORMAL_MODE;
        case SPECTRAL_SCAN_MODE_AGILE:
            return SPECT_DETECTION_FREQ_DESC_STR_AGILE_MODE;
        default:
            return NULL;
    }
}

/*
 * Function     : populate_detection_region_descriptor_str
 * Description  : Helper function to populate detection region descriptor string
 *                corresponding to the Spectral mode
 * Input params : Pointer to SAMP message, segment number (will be used only for
 *                normal mode, ignored for Agile mode), pointer to character
 *                array which should be populated, max size of character array
 *                to be populated (if the string to be written including the
 *                terminating '\0' cannot completely fit into the array, the
 *                function returns error. It is recommended that callers use a
 *                size of SPECT_DETECTION_FREQ_REGION_STR_MAXTOTALSIZE).
 * Return       : 0 on success, -1 on failure.
 */
static int populate_detection_region_descriptor_str(
        struct spectral_samp_msg *msg, int segnum,
        char *region_descriptor_str, size_t region_descriptor_str_size)
{
    int ret = 0;

    SPECTRAL_CLASSIFIER_ASSERT(NULL != msg);
    SPECTRAL_CLASSIFIER_ASSERT(NULL != region_descriptor_str);
    SPECTRAL_CLASSIFIER_ASSERT(0 != region_descriptor_str_size);

    switch(msg->samp_data.spectral_mode)
    {
        case SPECTRAL_SCAN_MODE_NORMAL:
            ret = snprintf(region_descriptor_str, region_descriptor_str_size,
                    "%s %d", SPECT_DETECTION_FREQ_REGION_STR_NORMAL_MODE,
                    segnum);

            if ((ret < 0) || (ret >= region_descriptor_str_size)) {
                return -1;
            } else {
                return 0;
            }

            break;
        case SPECTRAL_SCAN_MODE_AGILE:
            ret = snprintf(region_descriptor_str, region_descriptor_str_size,
                    "%s", SPECT_DETECTION_FREQ_REGION_STR_AGILE_MODE);

            if ((ret < 0) || (ret >= region_descriptor_str_size)) {
                return -1;
            } else {
                return 0;
            }

            break;
        default:
            return -1;
            break;
    }
}

/*
 * Function     : spectral_scan_classifer_sm_init
 * Description  : Initialize the Spectral Classifier State Machine. Init is done on type/mode
 * Input params : Pointer to classifier data, mode to initialize
 * Return       : Void
 */
void spectral_scan_classifer_sm_init(CLASSIFER_DATA_STRUCT *pclas, DETECT_MODE mode, uint8_t seg_index)
{
    /* Initialize the microwave oven interference */
    if (mode & SPECT_CLASS_DETECT_MWO) {

        pclas->mwo_burst_idx        = 0;
        pclas->mwo_burst_found      = 0;
        pclas->mwo_in_burst_time    = 0;
        pclas->mwo_thresh           = MWO_POW_VARIATION_THRESH;
        pclas->mwo_rssi             = 0;
        pclas->mwo_cur_bin          = 0;
        memset(&pclas->mwo_param, 0, sizeof(spectral_mwo_param)*NUM_MWO_BINS);

    }

    /* Initialize the CW interference */
    if (mode & SPECT_CLASS_DETECT_CW) {

      if(!seg_index) {
        pclas->cw[0].burst_found        = 0;
        pclas->cw[0].start_time         = 0;
        pclas->cw[0].last_found_time    = 0;
        pclas->cw[0].rssi               = 0;
        pclas->cw[0].num_detected       = 0;
      }
      else {
        pclas->cw[1].burst_found        = 0;
        pclas->cw[1].start_time         = 0;
        pclas->cw[1].last_found_time    = 0;
        pclas->cw[1].rssi               = 0;
        pclas->cw[1].num_detected       = 0;
      }
    }

    /* Initialize the WiFi interference */
    if (mode & SPECT_CLASS_DETECT_WiFi) {
        pclas->spectral_num_wifi_detected = 0;
        pclas->wifi_rssi = 0;
    }

    /* Initialize the FHSS interference */
    if (mode & SPECT_CLASS_DETECT_FHSS) {
      if(!seg_index) {
        pclas->fhss[0].cur_bin = 0;
        memset(&pclas->fhss[0].fhss_param, 0, sizeof(spectral_fhss_param) * NUM_FHSS_BINS);
      }
      else {
        pclas->fhss[1].cur_bin = 0;
        memset(&pclas->fhss[1].fhss_param, 0, sizeof(spectral_fhss_param) * NUM_FHSS_BINS);
      }
    }

    /* Initialize generic data */
    if (mode == SPECT_CLASS_DETECT_ALL) {
        /* Some generic init */
        pclas->spectral_detect_mode         = SPECT_CLASS_DETECT_ALL;
        pclas->spectral_num_wifi_detected   = 0;
        pclas->current_interference         = 0;
        pclas->mwo_detect_ts                = 0;
        pclas->mwo_num_detect               = 0;
        pclas->cw[0].detect_ts              = 0;
        pclas->cw[0].num_detect             = 0;
        pclas->cw[1].detect_ts              = 0;
        pclas->cw[1].num_detect             = 0;
        pclas->wifi_detect_ts               = 0;
        pclas->wifi_num_detect              = 0;
        pclas->dsss_detect_ts               = 0;
        pclas->dsss_num_detect              = 0;
        pclas->cur_freq                     = 0;
        pclas->cur_agile_freq1              = 0;
        pclas->cur_agile_freq2              = 0;
        pclas->cw_cnt                       = 0;
        pclas->wifi_cnt                     = 0;
        pclas->mwo_cnt                      = 0;
        pclas->fhss_cnt                     = 0;
    }

    pclas->sm_init_done = TRUE;
}

/*
 * Function     : detect_mwo
 * Description  : Detect Microwave oven
 * Input params : Pointers to SAMP msg and Classifier data
 * Return       : Found/Not Found
 *
 */
int detect_mwo(struct spectral_samp_msg* msg, CLASSIFER_DATA_STRUCT *pclas)
{
    int mwo_burst_found     = 0;
    int mwo_device_found    = 0;
    u_int16_t detect_freq   = 0;
    const char* detect_freq_desc_str = NULL;

    /* Check if this is a valid Microwave Oven frequency */
    if (msg->freq < MWO_MIN_FREQ || msg->freq > MWO_MAX_FREQ) {
        return 0;
    }

    /* Currently, we do not support Agile Spectral in 2.4 GHz */
    if ((SPECTRAL_SCAN_MODE_AGILE == msg->samp_data.spectral_mode)) {
        return 0;
    }

    pclas->pri80_detection_state = MWO_DETECT_INIT;
    pclas->sec80_detection_state = MWO_DETECT_INIT;

    pclas->is_commit = false;

    if (msg->samp_data.spectral_rssi > GET_MWO_MIN_RSSI_THRESHOLD(pclas)) {

        /* There is something in the air */
        float rssiLin                   = powf_precompute_table[(u_int8_t)msg->samp_data.spectral_rssi];
        u_int32_t bin_cnt               = 0;
        u_int32_t bin_pwr[MAX_NUM_BINS] = {0};
        u_int32_t low_bnd_pwr           = 0;
        u_int32_t up_bnd_pwr            = 0;
        u_int32_t bin_group_diff_abs    = 0;
        /* Time delta since last recorded in-burst instance */
        u_int32_t time_since_in_burst   = 0;

        /* Calculate power levels for each bins */
        for (bin_cnt = 0; bin_cnt < SAMP_NUM_OF_BINS(msg); bin_cnt++ ) {
            bin_pwr[bin_cnt] = (u_int32_t)(((float)msg->samp_data.bin_pwr[bin_cnt] * rssiLin) + 0.5);
        }

        for (bin_cnt = 0; bin_cnt < MWO_BIN_CLUSTER_COUNT; bin_cnt++) {
            low_bnd_pwr += bin_pwr[bin_cnt];
            up_bnd_pwr += bin_pwr[msg->samp_data.bin_pwr_count - bin_cnt - 1];
        }

        bin_group_diff_abs = abs((int)(up_bnd_pwr - low_bnd_pwr));

        if (bin_group_diff_abs > GET_MWO_POW_VARIATION_THRESHOLD(pclas)) {
            pclas->mwo_thresh = (GET_PCLAS_MWO_TRHESHOLD(pclas) - (GET_PCLAS_MWO_TRHESHOLD(pclas) >> 2)) +
                (bin_group_diff_abs >> 2);
        }

        //printf("%d,  %d,  %d, %d\n", low_bnd_pwr, up_bnd_pwr, bin_group_diff_abs, pclas->mwo_thresh);

        if (bin_group_diff_abs > (int)((GET_PCLAS_MWO_TRHESHOLD(pclas) * 7 ) >> 3) ) {
            /* Tune the threshold so that the threshold is not too low or too high */

            if (!IS_MWO_BURST_FOUND(pclas)) {

                /* First burst */
                athssd_update_sample_state(pclas, MWO_FIRST_BURST_DETECTED, UPDATE_PRI80_AND_SEC80);
                pclas->mwo_burst_start_time     = SAMP_GET_SPECTRAL_TIMESTAMP(msg);
                pclas->mwo_in_burst_time        = SAMP_GET_SPECTRAL_TIMESTAMP(msg);
                pclas->mwo_burst_found          = 1;
            } else {
                time_since_in_burst = SAMP_GET_SPECTRAL_TIMESTAMP(msg) -
                    GET_PCLAS_MWO_IN_BURST_TIME(pclas);

                if (time_since_in_burst < MWO_INTER_BURST_DURATION) {
                    pclas->mwo_in_burst_time = SAMP_GET_SPECTRAL_TIMESTAMP(msg);

                    if ((SAMP_GET_SPECTRAL_TIMESTAMP(msg) - GET_PCLAS_MWO_BURST_START_TIME(pclas)) > MWO_MAX_BURST_TIME) {
                        /* This is not an MWO burst because it is on for too long */
                        athssd_update_sample_state(pclas, MWO_MAX_BURST_TIME_EXCEEDED, UPDATE_PRI80_AND_SEC80);
                        spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_MWO, 0);
                    }
                } else {
                    if (GET_PCLAS_MWO_IN_BURST_TIME(pclas) ==
                                GET_PCLAS_MWO_BURST_START_TIME(pclas)) {
                        /* The burst is too short. Might be FHSS or some
                         * spurious signal.
                         */
#if CLASSIFIER_DEBUG
                        cinfo("Burst is too short. Might be spurious.\n");
#endif /* CLASSIFIER_DEBUG */
                        athssd_update_sample_state(pclas, MWO_BURST_TOO_SHORT, UPDATE_PRI80_AND_SEC80);
                        spectral_scan_classifer_sm_init(pclas,
                                SPECT_CLASS_DETECT_MWO, 0);
                    } else if (time_since_in_burst >
                            MWO_MAX_INTER_BURST_DURATION) {
                        /* The next burst occurred after too long a gap. Might be
                         * a spurious signal.
                         */
 #if CLASSIFIER_DEBUG
                        cinfo("Inter-burst duration is too high (%u us). Might "
                              "be spurious.\n",
                              time_since_in_burst);
#endif /* CLASSIFIER_DEBUG */
                        athssd_update_sample_state(pclas, MWO_INTER_BURST_DURATION_TOO_HIGH, UPDATE_PRI80_AND_SEC80);
                        spectral_scan_classifer_sm_init(pclas,
                                SPECT_CLASS_DETECT_MWO, 0);
                    } else {
                        athssd_update_sample_state(pclas, MWO_NEW_BURST_DETECTED, UPDATE_PRI80_AND_SEC80);
                        /* Previous burst is over, this could be a new burst */
                        pclas->mwo_burst_idx++;
                        pclas->mwo_rssi += SAMP_GET_SPECTRAL_RSSI(msg);

                        if (pclas->mwo_burst_idx == MWO_NUM_BURST) {
                            athssd_update_sample_state(pclas, MWO_SUFFICIENT_BURSTS_FOR_DETECTION, UPDATE_PRI80_AND_SEC80);
                            /* Got enough bursts to be sure */
                            pclas->mwo_rssi /= MWO_NUM_BURST;
                            mwo_burst_found = 1;
                            spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_MWO, 0);

                        } else {

                            /* Start recording the new burst */
                            pclas->mwo_burst_start_time = SAMP_GET_SPECTRAL_TIMESTAMP(msg);
                            pclas->mwo_in_burst_time    = SAMP_GET_SPECTRAL_TIMESTAMP(msg);
                        }
                    }
                }
            }

        } else {
            athssd_update_sample_state(pclas, MWO_PULSE_PWR_VARIATION_W_DYN_THRESH_NOT_CROSSED, UPDATE_PRI80_AND_SEC80);
            if ((pclas->mwo_burst_found) && (bin_group_diff_abs < (int)(((GET_PCLAS_MWO_TRHESHOLD(pclas) * 7) >> 3) >> 2))) {
                /* We had found a burst. Check if the time is too long ago and clear it */
                if ((SAMP_GET_SPECTRAL_TIMESTAMP(msg) - GET_PCLAS_MWO_BURST_START_TIME(pclas)) > MWO_BURST_INACTIVITY_TIMEOUT) {
                    athssd_update_sample_state(pclas, MWO_BURST_INACTIVITY_TIMEOUT_EXCEEDED_W_DYN_THRESH_NOT_CROSSED, UPDATE_PRI80_AND_SEC80);
                    /* too long without a burst, clear microwave detection */
                    spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_MWO, 0);
                }
            }
        }
    } else {
        athssd_update_sample_state(pclas, MWO_RSSI_INSUFFICIENT, UPDATE_PRI80_AND_SEC80);
        /* No interference detected, check if we were looking for something */
        if (IS_MWO_BURST_FOUND(pclas)) {
            /* We had found a burst. Check if the time is too far back in time, and clear it */
            if ((SAMP_GET_SPECTRAL_TIMESTAMP(msg) - GET_PCLAS_MWO_BURST_START_TIME(pclas)) > MWO_BURST_INACTIVITY_TIMEOUT) {
                athssd_update_sample_state(pclas, MWO_BURST_INACTIVITY_TIMEOUT_EXCEEDED_W_LOW_RSSI, UPDATE_PRI80_AND_SEC80);
                /* Too long without a burst, clear microwave detction */
                spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_MWO, 0);
            }
        }
    }

    if (mwo_burst_found) {

        /* Something has been detected. Introduce hysteresis for stability of detection */
        if (!(pclas->current_interference & SPECT_CLASS_DETECT_MWO)) {
            if (!pclas->mwo_num_detect) {
                athssd_update_sample_state(pclas, MWO_FIRST_DETECT_FOUND, UPDATE_PRI80_AND_SEC80);
                pclas->mwo_num_detect = 1;
                pclas->mwo_detect_ts = msg->samp_data.spectral_tstamp;
            } else {
                athssd_update_sample_state(pclas, MWO_SUBSEQUENT_DETECT_FOUND, UPDATE_PRI80_AND_SEC80);
                pclas->mwo_num_detect++;
                if ((int)(SAMP_GET_SPECTRAL_TIMESTAMP(msg) - GET_PCLAS_MWO_DETECT_TIMESTAMP(pclas)) < (MWO_STABLE_DETECT_THRESH)) {
                    pclas->current_interference |= SPECT_CLASS_DETECT_MWO;
                    pclas->mwo_detect_ts = SAMP_GET_SPECTRAL_TIMESTAMP(msg);

                    detect_freq = get_detection_freq(msg);
                    SPECTRAL_CLASSIFIER_ASSERT(0 != detect_freq);

                    detect_freq_desc_str =
                        get_detection_freq_descriptor_str(msg);
                    SPECTRAL_CLASSIFIER_ASSERT(
                            NULL != detect_freq_desc_str);

                    athssd_update_sample_state(pclas, MWO_INTERFERENCE_FOUND, UPDATE_PRI80_AND_SEC80);
                    printf("Spectral Classifier: Found MWO Interference in %s frequency %u\n",
                           detect_freq_desc_str,
                           detect_freq);
                    mwo_device_found = 0;
                    pclas->mwo_cnt++;
                    /* Interference is detected, set commit flag now, to be used in logging
                     * at the end of the API
                     */
                    pclas->is_commit = true;
                } else {
                    athssd_update_sample_state(pclas, MWO_STABLE_DETECT_THRESH_EXCEEDED, UPDATE_PRI80_AND_SEC80);
                    /* Took too much time, reset the counter -- Should not be here */
                    pclas->mwo_num_detect = 1;
                    pclas->mwo_detect_ts = SAMP_GET_SPECTRAL_TIMESTAMP(msg);
                }
            }
        } else {
            /* Update the time */
            pclas->mwo_num_detect = 1;
            pclas->mwo_detect_ts = SAMP_GET_SPECTRAL_TIMESTAMP(msg);
        }
    } else if (pclas->current_interference & SPECT_CLASS_DETECT_MWO) {
        /* Check if it has been found before and not found for some time */
        if ((int)(msg->samp_data.spectral_tstamp - pclas->mwo_detect_ts) > (MWO_DETECT_INACTIVITY_TIMEOUT)) {
            athssd_update_sample_state(pclas, MWO_DETECT_INACTIVITY_TIMEOUT_CROSSED, UPDATE_PRI80_AND_SEC80);
            pclas->current_interference &=  ~(SPECT_CLASS_DETECT_MWO);
            pclas->mwo_num_detect = 0;
            printf("Spectral Classifier: No MWO Interference\n");
        }
    }

    /* Check whether to log or commit or both */
    spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_MWO, 0);
    if (pclas->is_commit) {
        spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_MWO, 1);
        pclas->is_commit = false;
    }

    return mwo_device_found;
}

/*
 * Function     : detect_cw
 * Description  : Detect the CW interfernce.
 * Input params : Pointers to SAMP msg and classifier data
 * Return       : Found/Not Found
 *
 */
int detect_cw(struct spectral_samp_msg* msg, CLASSIFER_DATA_STRUCT *pclas, uint8_t use_sec80)
{
    int ret_val = 0;
    int index = (use_sec80)?1:0;    /* Index to determine if classifier operates on segment 0 or segment 1 */
    CLASSIFIER_CW_PARAMS *pseg = &pclas->cw[index];
    int16_t   spectral_rssi = 0;
    u_int16_t   bin_pwr_count = 0;
    u_int8_t *bin_pwr = NULL;
    char region_descriptor_str[SPECT_DETECTION_FREQ_REGION_STR_MAXTOTALSIZE] =
                                                            {0};
    int rdesc_ret = 0;

    if (!(pclas->spectral_detect_mode & SPECT_CLASS_DETECT_CW))  {
        return ret_val;
    }

    if (!use_sec80) {
        spectral_rssi = msg->samp_data.spectral_rssi;
        bin_pwr_count = msg->samp_data.bin_pwr_count;
        bin_pwr = (u_int8_t *)msg->samp_data.bin_pwr;
        pclas->pri80_detection_state = CW_DETECT_INIT;
        pclas->is_commit = false;
    } else {
        spectral_rssi = msg->samp_data.spectral_rssi_sec80;
        bin_pwr_count = msg->samp_data.bin_pwr_count_sec80;
        bin_pwr = (u_int8_t *)msg->samp_data.bin_pwr_sec80;
        pclas->sec80_detection_state = CW_DETECT_INIT;
    }

    /* Check if there is high noise floor */
    if (spectral_rssi > GET_CW_RSSI_THRESH(pclas)) {
        u_int16_t bin_cnt   = 0;
        u_int16_t peak_bin  = 0;
        u_int16_t peak_val  = 0;
        u_int16_t chk_upr   = 0;
        u_int16_t chk_lwr   = 0;
        u_int16_t cw_centre_upr_bin   = 0;
        u_int16_t cw_centre_lwr_bin   = 0;
        u_int32_t upr_sum   = 0;
        u_int32_t lwr_sum   = 0;
        u_int32_t center_sum = 0;
        u_int16_t peak_bin_to_upr_bin_offset = 0;
        u_int16_t peak_bin_to_lwr_bin_offset = 0;
        u_int16_t dc_bin_start = (bin_pwr_count >> 1) - 1;
        u_int16_t dc_bin_end = dc_bin_start + 1;

        for (bin_cnt = 0; bin_cnt < bin_pwr_count; bin_cnt++ ) {
            if (peak_val < bin_pwr[bin_cnt]) {
                peak_bin = bin_cnt;
                peak_val = bin_pwr[bin_cnt];
            }
        }

        /* set the upper and lower bin markers */
        /* Note, this logic works only for GET_CW_INT_BIN_SUM_SIZE(pclas) = 3 */
        if ((peak_bin != (bin_pwr_count - 1) &&
             bin_pwr[peak_bin + 1] > bin_pwr[peak_bin] / GET_CW_PEAK_TO_ADJ_THRESH(pclas)) &&
            (peak_bin != 0 && bin_pwr[peak_bin - 1] > bin_pwr[peak_bin] / GET_CW_PEAK_TO_ADJ_THRESH(pclas))) {
            if (bin_pwr[peak_bin + 1] > bin_pwr[peak_bin - 1]) {
                peak_bin_to_lwr_bin_offset = 1;
                peak_bin_to_upr_bin_offset = 2;
            } else {
                peak_bin_to_lwr_bin_offset = 2;
                peak_bin_to_upr_bin_offset = 1;
            }
        } else if (peak_bin != (bin_pwr_count - 1) &&
                   bin_pwr[peak_bin + 1] > bin_pwr[peak_bin] / GET_CW_PEAK_TO_ADJ_THRESH(pclas)) {
            peak_bin_to_lwr_bin_offset = 1;
            peak_bin_to_upr_bin_offset = 2;
        } else if (peak_bin != 0 && bin_pwr[peak_bin - 1] > bin_pwr[peak_bin] / GET_CW_PEAK_TO_ADJ_THRESH(pclas)) {
            peak_bin_to_lwr_bin_offset = 2;
            peak_bin_to_upr_bin_offset = 1;
        } else {
            peak_bin_to_lwr_bin_offset = 1;
            peak_bin_to_upr_bin_offset = 1;
        }

        if ((int)peak_bin - (int)peak_bin_to_lwr_bin_offset < 0) {
            cw_centre_lwr_bin = 0;
            cw_centre_upr_bin = cw_centre_lwr_bin + peak_bin_to_lwr_bin_offset + peak_bin_to_upr_bin_offset;
        } else if (peak_bin + peak_bin_to_upr_bin_offset > (bin_pwr_count - 1)) {
            cw_centre_upr_bin = bin_pwr_count - 1;
            cw_centre_lwr_bin = cw_centre_upr_bin - (peak_bin_to_lwr_bin_offset + peak_bin_to_upr_bin_offset);
        } else {
            cw_centre_lwr_bin = peak_bin - peak_bin_to_lwr_bin_offset;
            cw_centre_upr_bin = peak_bin + peak_bin_to_upr_bin_offset;
        }

        SPECTRAL_CLASSIFIER_ASSERT(cw_centre_lwr_bin >= 0 && cw_centre_lwr_bin <= (bin_pwr_count - 1));
        SPECTRAL_CLASSIFIER_ASSERT(cw_centre_upr_bin >= 0 && cw_centre_upr_bin <= (bin_pwr_count - 1));

        /* Skip lwr_sum/upr_sum if upper/lower bins are falling in the
         * bins corresponding to the DC */
        if (cw_centre_upr_bin + GET_CW_INT_BIN_SUM_SIZE(pclas) <= (bin_pwr_count - 1) &&
            (cw_centre_upr_bin + 3 < dc_bin_start || dc_bin_end < cw_centre_upr_bin + 1)) {
            chk_upr = 1;
        }

        if ((int)cw_centre_lwr_bin - GET_CW_INT_BIN_SUM_SIZE(pclas) >= 0 &&
            (cw_centre_lwr_bin - 1 < dc_bin_start || dc_bin_end < cw_centre_lwr_bin - 3)) {
            chk_lwr = 1;
        }

        /* center_sum = sum of bins in the range [cw_centre_lwr_bin, cw_centre_upr_bin] */
        for (bin_cnt = cw_centre_lwr_bin; bin_cnt <= cw_centre_upr_bin; bin_cnt++)
            center_sum += bin_pwr[bin_cnt];

        if (chk_upr) {
            SPECTRAL_CLASSIFIER_ASSERT(cw_centre_upr_bin + 3 <= (bin_pwr_count - 1));
            upr_sum = bin_pwr[cw_centre_upr_bin + 1] +
                      bin_pwr[cw_centre_upr_bin + 2] +
                      bin_pwr[cw_centre_upr_bin + 3];
        }

        if (chk_lwr) {
            SPECTRAL_CLASSIFIER_ASSERT((int)cw_centre_lwr_bin - 3 >= 0);
            lwr_sum = bin_pwr[cw_centre_lwr_bin - 1] +
                      bin_pwr[cw_centre_lwr_bin - 2] +
                      bin_pwr[cw_centre_lwr_bin - 3];
        }

        /*
         * Check if this is greater than threhold
         * XXX : Note, this logic works only for GET_CW_INT_BIN_SUM_SIZE(pclas) = 3
         */
        if ( (lwr_sum < (center_sum >> GET_CW_SUM_SCALE_DOWN_FACTOR(pclas))) &&
             (upr_sum < (center_sum >> GET_CW_SUM_SCALE_DOWN_FACTOR(pclas))) &&
             (center_sum > GET_CW_INT_DET_THRESH(pclas))) {
                  athssd_update_sample_state(pclas, CW_FOUND_LIKELY_BURST, use_sec80);
                  /* Found a likely CW interference case */
                  pseg->num_detected++;
                  pseg->rssi += spectral_rssi;

                  if (!pseg->burst_found) {
                      athssd_update_sample_state(pclas, CW_FOUND_FIRST_BURST, use_sec80);
                      pseg->burst_found       = 1;
                      pseg->start_time        = msg->samp_data.spectral_tstamp;
                      pseg->last_found_time   = msg->samp_data.spectral_tstamp;

                  } else {
                      athssd_update_sample_state(pclas, CW_FOUND_SUBSEQUENT_BURST, use_sec80);
                      pseg->last_found_time = msg->samp_data.spectral_tstamp;

                      if (((int)(pseg->last_found_time - pseg->start_time) > GET_CW_INT_FOUND_TIME_THRESH(pclas)) &&
                             (pseg->num_detected > GET_CW_INT_FOUND_MIN_CNT(pclas))) {
                          athssd_update_sample_state(pclas, CW_FOUND_MIN_COUNT_BURST, use_sec80);
                          pseg->rssi /= pseg->num_detected;
                          spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_CW, index);
                          ret_val = 1;

                      }
                  }

             } else {

                 if (pseg->burst_found) {

                     if ((int)(msg->samp_data.spectral_tstamp - pseg->last_found_time) > GET_CW_INT_MISSING_THRESH(pclas) ) {
                         /* Burst missing for too long */
                         athssd_update_sample_state(pclas, CW_BURST_MISSING_FOR_TOO_LONG_W_CW_RSSI_THRESH_EXCEEDED, use_sec80);
                         spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_CW, index);
                     }
                 }
             }

    } else {

        if (pseg->burst_found) {

            /* Check how long the burst has been missing */
            if ((int)(msg->samp_data.spectral_tstamp - pseg->last_found_time) > GET_CW_INT_MISSING_THRESH(pclas) ) {
                /* Burst missing for too long */
                athssd_update_sample_state(pclas, CW_BURST_MISSING_FOR_TOO_LONG_WO_CW_RSSI_EXCEEDED, use_sec80);
                spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_CW, index);
            }
        }
    }

    if (ret_val) {

        /* add hystrysis to the detection in order to provide stablity */
        ret_val = 0;

        if ((!(pclas->current_interference & SPECT_CLASS_DETECT_CW)) || (!pseg->found_cw)) {

            if (!pseg->num_detect) {
                athssd_update_sample_state(pclas, CW_FOUND_FIRST_DETECT, use_sec80);
                pseg->num_detect = 1;
                pseg->detect_ts = msg->samp_data.spectral_tstamp;

            } else {
                athssd_update_sample_state(pclas, CW_FOUND_SUBSEQUENT_DETECT, use_sec80);
                pseg->num_detect++;

                if (pseg->num_detect >=3) {
                    if ((int)(msg->samp_data.spectral_tstamp - pseg->detect_ts) < GET_CW_INT_CONFIRM_WIN(pclas)) {
                        athssd_update_sample_state(pclas, CW_FOUND_SUFFICIENT_DETECTS_IN_WINDOW, use_sec80);
                        /* found 2 detect within given window */
                        if(!pclas->cw[!index].found_cw) {
                            pclas->current_interference |= SPECT_CLASS_DETECT_CW;
                        }
                        pseg->detect_ts = msg->samp_data.spectral_tstamp;
                        pclas->cw_cnt++;

                        rdesc_ret =
                            populate_detection_region_descriptor_str(msg, index,
                                    region_descriptor_str,
                                    sizeof(region_descriptor_str));

                        SPECTRAL_CLASSIFIER_ASSERT(0 == rdesc_ret);

                        printf("Spectral Classifier: Found CW interference on %s\n",
                            region_descriptor_str);

                        /* Interference is detected, set commit flag now, to be used in logging
                         * at the end of the API
                         */
                        pclas->is_commit = true;

                        ret_val = 1;
                        pseg->found_cw = 1;
                    } else {
                        pseg->num_detect = 0;
                        pseg->detect_ts = msg->samp_data.spectral_tstamp;
                    }
                }
            }
        } else {
            athssd_update_sample_state(pclas, CW_FOUND_DETECT_AFTER_LONG_TIME, use_sec80);
            /* Found after a long time */
            pseg->num_detect = 1;
            pseg->detect_ts = msg->samp_data.spectral_tstamp;
        }

    } else if ((pclas->current_interference & SPECT_CLASS_DETECT_CW) && (pseg->found_cw)) {

        /* Check if it has been found before and not found of some time */
        if ((int)(msg->samp_data.spectral_tstamp - pseg->detect_ts) > GET_CW_INT_CONFIRM_MISSING_WIN(pclas)) {
            athssd_update_sample_state(pclas, CW_FOUND_INSUFFICIENT_DETECTS_IN_WINDOW, use_sec80);
            if(!pclas->cw[!index].found_cw) {
                pclas->current_interference &=  ~(SPECT_CLASS_DETECT_CW);
            }
            pseg->num_detect = 0;

            rdesc_ret =  populate_detection_region_descriptor_str(msg, index,
                                region_descriptor_str,
                                sizeof(region_descriptor_str));

            SPECTRAL_CLASSIFIER_ASSERT(0 == rdesc_ret);

            printf("Spectral Classifier: No CW interference on %s\n",
                    region_descriptor_str);
            pseg->found_cw = 0;
        }
    }

    /* Check whether to log or commit or both */
    /* We shouldn't log/commit in 80p80/160 primary 80 MHz case as we have
     * to wait for secondary 80 MHz detection to complete.
     */
    if (!(IS_CHAN_WIDTH_160_OR_80P80(msg->samp_data.ch_width) && !use_sec80)) {
        spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_CW, 0);
        if (pclas->is_commit) {
            spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_CW, 1);
            pclas->is_commit = false;
        }
    }

    return ret_val;
}


/*
 * Function     : get_sscan_bw
 * Description  : Get spectral scan bw from enum value of ch_width
 * Input params : ch_width
 * Return       : spectral scan bw
 *
 */
static u_int16_t get_sscan_bw(enum ieee80211_cwm_width ch_width)
{
    u_int16_t sscan_bw = 0;

    switch (ch_width)
        {
        case IEEE80211_CWM_WIDTH20:
            sscan_bw = 20;
            break;

        case IEEE80211_CWM_WIDTH40:
            sscan_bw = 40;
            break;

        case IEEE80211_CWM_WIDTH80:
        case IEEE80211_CWM_WIDTH80_80:
            sscan_bw = 80;
            break;

        case IEEE80211_CWM_WIDTH160:
            sscan_bw = 160;
            break;

        default:
            fprintf(stderr,"Invalid Channel width");
            return 0;
            break;
        }

    return sscan_bw;
}

/*
 * Function     : athssd_get_wifi_detection_state
 * Description  : Get the wifi sample state for given sscan bw, seg bw and seg id.
                  The API returns a 32 bit unsigned integer interpreted as below:
                  |........|........|........|........|
                  |   AA   |   BB   |   CC   |   DD   |
                  AA: sscan bw (stored as a factor WIFI_SEGMENT_BANDWIDTH_20MHZ
                      to ensure 1 byte limit)
                  BB: segment bw (stored as a factor WIFI_SEGMENT_BANDWIDTH_20MHZ
                      to ensure 1 byte limit)
                  CC: segment id
                  DD: miscellaneous state defined in SPECTRAL_WIFI_SAMPLE_STATE,
                      to be populated by the caller.
 * Input params : sscan_bw, seg bw, seg id
 * Return       : wifi sample state
 *
 */
static u_int32_t
athssd_get_wifi_detection_state(u_int32_t sscan_bw, u_int32_t seg_bw,
                                u_int8_t seg_id)
{
    return ((sscan_bw / WIFI_SEGMENT_BANDWIDTH_20MHZ) << WIFI_SSCAN_BW_SHIFT |
            (seg_bw / WIFI_SEGMENT_BANDWIDTH_20MHZ) << WIFI_SEG_BW_SHIFT |
            seg_id << WIFI_SEG_ID_SHIFT);
}

/*
 * Function     : detect_wifi
 * Description  : Detect WiFi interference
 * Input params : Pointers to SAMP msg and classifier data, flag for sec80,
                  pointer to temp bin pwr array, bin pwr array len
 * Return       : Found/Not Found
 *
 * INFO         : WiFi interference is Wide Band signal. Low on the edge and should
 *                high enough RSSI
 *
 *
 * FFT Size initialization done before starting spectral scan
 * ----------------------------------------------------------
 * 20MHz    - FFT Size is set to 7, FFT bin count is 64 for 11ac, 56 for legacy
 * 40MHz    - FFT Size is set ti 8, FFT bin count is 128
 * 80MHz    - FFT Size is set ti 9, FFT bin count is 256
 */

int detect_wifi(struct spectral_samp_msg* msg, CLASSIFER_DATA_STRUCT* pclas,
                       u_int8_t use_sec80, u_int8_t *temp_bin_pwr, u_int32_t temp_bin_pwr_len)
{

    int found           = 0;
    int ch_width        = 0;
    u_int8_t *pfft_bins = NULL;
    u_int32_t num_bins_segment = 0;
    int seg_bw_id = 0;
    u_int16_t detect_freq = 0;
    const char* detect_freq_desc_str = NULL;
    u_int16_t sscan_bw;
    u_int8_t num_segs;
    u_int32_t start_idx;
    unsigned int seg_bw, segment_id;
    SAMP_STATE_UPDATE_MODE wifi_state_mode;
    u_int32_t wifi_state = WIFI_DETECT_INIT;
    WIFI_SEG_BANDWIDTH wifi_seg_bws[WIFI_NUM_SEG_BWS] = {WIFI_SEGMENT_BANDWIDTH_20MHZ,
                                                         WIFI_SEGMENT_BANDWIDTH_40MHZ,
                                                         WIFI_SEGMENT_BANDWIDTH_80MHZ,
                                                         WIFI_SEGMENT_BANDWIDTH_160MHZ};

    if (!(pclas->spectral_detect_mode & SPECT_CLASS_DETECT_WiFi)) {
        return 0;
    }

    wifi_state_mode = GET_WIFI_STATE_UPDATE_MODE(ch_width, use_sec80);
    /* get operating channel width */
    ch_width = msg->samp_data.ch_width;
    if (IS_CHAN_WIDTH_INVALID(ch_width)) {
        /* ch_width is invalid, update sample state, stop further processing
         * and log the sample
         */
        athssd_update_sample_state(pclas, WIFI_CW_INVALID, wifi_state_mode);
        goto log;
    }

    athssd_update_sample_state(pclas, WIFI_DETECT_INIT, wifi_state_mode);

    if (!use_sec80)
        pclas->is_commit = false;

    sscan_bw = get_sscan_bw(ch_width);
    SPECTRAL_CLASSIFIER_ASSERT(sscan_bw);

    /* Check if there is a high signal */
    if (msg->samp_data.spectral_rssi > GET_WIFI_DET_MIN_RSSI(pclas)) {
        pfft_bins = temp_bin_pwr;
        for (seg_bw_id = (WIFI_NUM_SEG_BWS - 1); seg_bw_id >= 0; seg_bw_id--) {
            seg_bw = wifi_seg_bws[seg_bw_id];
            if (seg_bw > sscan_bw)
                continue;
            num_segs = sscan_bw / seg_bw;
            num_bins_segment = temp_bin_pwr_len / num_segs;
            for (segment_id = 0; segment_id < num_segs; segment_id++) {
                start_idx = num_bins_segment * segment_id;
                SPECTRAL_CLASSIFIER_ASSERT(start_idx < temp_bin_pwr_len);

                found = check_wifi_signal(pclas, num_bins_segment, pfft_bins + start_idx);
                if (found) {
                    wifi_state = athssd_get_wifi_detection_state(sscan_bw, seg_bw, segment_id + 1);
                    athssd_update_sample_state(pclas, wifi_state, wifi_state_mode);
                    break;
                }
            }
            if (found) {
#if CLASSIFIER_DEBUG
                if (IS_CHAN_WIDTH_80P80(msg->samp_data.ch_width)) {
                    if (use_sec80) {
                        cinfo("Detected WiFi (Channel Width 80p80 (Secondary %u MHz) : %u MHz Segment %u)\n",
                               sscan_bw, seg_bw, segment_id + 1);
                    }
                    else {
                        cinfo("Detected WiFi (Channel Width 80p80 (Primary %u MHz) : %u MHz Segment %u)\n",
                               sscan_bw, seg_bw, segment_id + 1);
                    }
                }
                else {
                    cinfo("Detected WiFi (Channel Width %u MHz : %u MHz Segment %u)\n",
                           sscan_bw, seg_bw, segment_id + 1);
                }
#endif
                break;
            }
        }
        /* If WiFi detected log the data */
        if (found) {
            pclas->spectral_num_wifi_detected++;
            pclas->wifi_rssi += msg->samp_data.spectral_rssi;

        }
    }

    if (found == TRUE) {
        found = FALSE;

        /* Check if there are at least 2 detects in a 500ms interval */
        if (!(pclas->current_interference & SPECT_CLASS_DETECT_WiFi)) {

            if (!pclas->wifi_num_detect) {

                /* First detect */
                athssd_update_sample_state(pclas, ((wifi_state & WIFI_MISC_STATE_MASK) |
                                           WIFI_FIRST_DETECT),
                                           wifi_state_mode);
                pclas->wifi_num_detect = 1;
                pclas->wifi_detect_ts = msg->samp_data.spectral_tstamp;

            } else {

                pclas->wifi_num_detect++;

                /* 500ms has not elapsed */
                if ((int)(msg->samp_data.spectral_tstamp - pclas->wifi_detect_ts) < GET_WIFI_DET_CONFIRM_WIN(pclas)) {

                    if (pclas->wifi_num_detect >= WIFI_MIN_NUM_DETECTS) {

                        /* And there are 2 detects, set the WiFi interference flag to 1 */
                        athssd_update_sample_state(pclas, ((wifi_state & WIFI_MISC_STATE_MASK) |
                                                   WIFI_SUFFICIENT_DETECTS_WITHIN_DETECTION_WINDOW),
                                                   wifi_state_mode);
                        pclas->current_interference |= SPECT_CLASS_DETECT_WiFi;
                        pclas->wifi_detect_ts       = msg->samp_data.spectral_tstamp;
                        pclas->wifi_rssi /= pclas->spectral_num_wifi_detected;

                        detect_freq = get_detection_freq(msg);
                        SPECTRAL_CLASSIFIER_ASSERT(0 != detect_freq);

                        detect_freq_desc_str =
                            get_detection_freq_descriptor_str(msg);
                        SPECTRAL_CLASSIFIER_ASSERT(
                                NULL != detect_freq_desc_str);

                        printf("Spectral Classifier: Found Wi-Fi interference in %s freq %u with RSSI %d\n",
                                detect_freq_desc_str, detect_freq,
                                pclas->wifi_rssi);

                        found = 1;
                        pclas->wifi_cnt++;
                        /* Interference is detected, set commit flag now, to be used in logging
                         * at the end of the API
                         */
                        pclas->is_commit = true;

                    }
                } else {
                    /* Took too much time, reset the counter */
                    athssd_update_sample_state(pclas, ((wifi_state & WIFI_MISC_STATE_MASK) |
                                               WIFI_TOO_MUCH_TIME_FOR_SUFFICIENT_DETECTS),
                                               wifi_state_mode);
                    pclas->wifi_num_detect = 1;
                    pclas->wifi_detect_ts = msg->samp_data.spectral_tstamp;
                }
            }
        } else {
            /* Check if a positive detect happend after a long time */
            if ((int)(msg->samp_data.spectral_tstamp - pclas->wifi_detect_ts) > GET_WIFI_DET_RESET_TIME(pclas)) {
                athssd_update_sample_state(pclas, ((wifi_state & WIFI_MISC_STATE_MASK) |
                                           WIFI_POSITIVE_DETECT_AFTER_WIFI_DET_RESET_TIME),
                                           wifi_state_mode);
                /* Too much time, reset and check again */
                pclas->current_interference &=  ~(SPECT_CLASS_DETECT_WiFi);
                pclas->wifi_num_detect = 0;
                printf("Spectral Classifier: No WiFi interference\n");
            } else {
                athssd_update_sample_state(pclas, ((wifi_state & WIFI_MISC_STATE_MASK) |
                                           WIFI_ONE_MORE_DETETCED),
                                           wifi_state_mode);
                /* One more detected, reset the time */
                pclas->wifi_num_detect = 1;
                pclas->wifi_detect_ts = msg->samp_data.spectral_tstamp;
            }
        }
    } else if (pclas->current_interference & SPECT_CLASS_DETECT_WiFi) {
        /* Check if it has been found before and not found of some time */
        if ((int)(msg->samp_data.spectral_tstamp - pclas->wifi_detect_ts) > GET_WIFI_DET_RESET_TIME(pclas)) {
            pclas->current_interference &=  ~(SPECT_CLASS_DETECT_WiFi);
            pclas->wifi_num_detect = 0;
            athssd_update_sample_state(pclas, ((wifi_state & WIFI_MISC_STATE_MASK) |
                                       WIFI_NOT_DETECTED),
                                       wifi_state_mode);
            printf("Spectral Classifier: No WiFi interference\n");
        }
    }

log:
    /* Check whether to log or commit or both */
    /* We shouldn't log/commit in 80p80 primary 80 MHz case as we have
     * to wait for secondary 80 MHz detection to complete.
     */
    if (!(IS_CHAN_WIDTH_80P80(msg->samp_data.ch_width) && !use_sec80)) {
        spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_WiFi, 0);
        if (pclas->is_commit) {
            spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_WiFi, 1);
            pclas->is_commit = false;
        }
    }

    return found;
}

/*
 * Function     : check_wifi_signal
 * Description  : checks for WiFi signal pattern in the given FFT bins
 * Input params : Pointers to classifier data, number of fft bins, pointer to fft bins
 * Return       : Found/Not Found
 *
 * INFO         : WiFi interference is Wide Band signal. Low on the edge and should
 *                high enough RSSI
 *
 */
int check_wifi_signal(CLASSIFER_DATA_STRUCT* pclas, u_int32_t num_bins, u_int8_t* pfft_bins)
{
    u_int16_t peak_val = 0;
    u_int16_t num_bins_above_threshold = 0;
    int i = 0;
    int found = FALSE;
    int peak_val_threshold = 0;

    /* find the peak value in the given bins */
    for (i = 0; i < num_bins; i++) {
        if (peak_val < pfft_bins[i]) {
            peak_val = pfft_bins[i];
        }
    }

    /* check how many bins are above peak bins are above threshold */
    /* Peak val threhold is set to 25% of peak value */
    peak_val_threshold = peak_val >> 2;

    for (i = 0; i < num_bins; i++) {
        if (pfft_bins[i] >= peak_val_threshold) {
            num_bins_above_threshold++;
        }
    }

    /* if at least half of the bins are greater than or equal to the peak value - 6dB */
    if (num_bins_above_threshold >= (num_bins >> 1)) {

        u_int32_t start_sum     = 0;
        u_int32_t mid_sum       = 0;
        u_int32_t end_sum       = 0;
        u_int32_t mid_bin_index = 0;

        mid_bin_index = (num_bins >> 1) - (GET_WIFI_BIN_WIDTH(pclas) >> 1) - 1;

        for (i = 0; i < (GET_WIFI_BIN_WIDTH(pclas)); i++) {
            start_sum   += pfft_bins[i];
            end_sum     += pfft_bins[num_bins - i -1];
            mid_sum     += pfft_bins[mid_bin_index + i - 1];
        }

        if (((int)(mid_sum - end_sum) > GET_WIFI_DET_MIN_DIFF(pclas)) &&
            ((int)(mid_sum - start_sum) > GET_WIFI_DET_MIN_DIFF(pclas))) {
            /* Most likely WiFi Signal */
            found = TRUE;
        }
    }

    return found;
}

/*
 * Function     : detect_fhss
 * Description  : Detect FHSS Interference
 * Input params : Pointer to SAMP msg and classifier data
 * Return       : Found/Not Found
 *
 * INFO         : FHSS in narrow band signal. Frequency hopping signals dwell for fixed amount
 *                of time (10ms) in single channel.
 *
 */
int detect_fhss(struct spectral_samp_msg* msg, CLASSIFER_DATA_STRUCT *pclas, uint8_t use_sec80)
{
    int ret_val = 0;
    int index = (use_sec80)?1:0;    /* Index to determine if classifier operates on segment 0 or segment 1 */
    CLASSIFIER_FHSS_PARAMS *pseg = &pclas->fhss[index];
    spectral_fhss_param *cur_fhss = &pseg->fhss_param[pseg->cur_bin];
    int16_t     spectral_rssi; /* This change to signed int16 is to fix the negative rssi issue */
    u_int16_t   bin_pwr_count;
    u_int8_t *bin_pwr = NULL;
    char region_descriptor_str[SPECT_DETECTION_FREQ_REGION_STR_MAXTOTALSIZE] =
                                                            {0};
    int rdesc_ret = 0;

    if (!(pclas->spectral_detect_mode & SPECT_CLASS_DETECT_FHSS)) {
        return ret_val;
    }

    if (!use_sec80) {
        spectral_rssi = msg->samp_data.spectral_rssi;
        bin_pwr_count = msg->samp_data.bin_pwr_count;
        bin_pwr = (u_int8_t *)msg->samp_data.bin_pwr;
        pclas->pri80_detection_state = FHSS_DETECT_INIT;
        pclas->is_commit = false;
    } else {
        spectral_rssi = msg->samp_data.spectral_rssi_sec80;
        bin_pwr_count = msg->samp_data.bin_pwr_count_sec80;
        bin_pwr = (u_int8_t *)msg->samp_data.bin_pwr_sec80;
        pclas->sec80_detection_state = FHSS_DETECT_INIT;
    }

    if (spectral_rssi <= GET_FHSS_DET_THRESH(pclas)) {
        athssd_update_sample_state(pclas, FHSS_RSSI_INSUFFICIENT, use_sec80);
    }

    if ((spectral_rssi > GET_FHSS_DET_THRESH(pclas)) && (!(pclas->current_interference & SPECT_CLASS_DETECT_MWO))) {

        /* something in the air */
        u_int16_t bin_cnt       = 0;
        u_int16_t peak_bin      = 0;
        u_int16_t peak_val      = 0;
        u_int16_t chk_upr       = 0;
        u_int16_t chk_lwr       = 0;
        u_int16_t upr_bin       = 0;
        u_int16_t lwr_bin       = 0;
        u_int32_t upr_sum       = 0;
        u_int32_t lwr_sum       = 0;
        u_int32_t center_sum    = 0;
        u_int16_t peak_upper    = 0;
        u_int16_t peak_lower    = 0;

        /* Do a peak search and figure out the max data */
        for (bin_cnt = 0; bin_cnt < bin_pwr_count; bin_cnt++ ) {
            if (peak_val < bin_pwr[bin_cnt]) {
                peak_bin = bin_cnt;
                peak_val = bin_pwr[bin_cnt];
            }
        }

        /* Check how many bins we can compare with */
        if (peak_bin + (GET_FHSS_INT_BIN_SUM_SIZE(pclas) + (GET_FHSS_INT_BIN_SUM_SIZE(pclas) >> 1)) <= msg->samp_data.bin_pwr_count) {
            chk_upr = 1;
        }

        if ((int)peak_bin - (GET_FHSS_INT_BIN_SUM_SIZE(pclas) + (GET_FHSS_INT_BIN_SUM_SIZE(pclas) >> 1)) <= 0) {
            chk_lwr = 1;
        }


        /* XXX : Note, this logic works only for GET_FHSS_INT_BIN_SUM_SIZE(pclas) = 3 */
        /* set the upper and lower bin markers */
        if (peak_bin == bin_pwr_count) {

            upr_bin     = peak_bin;
            lwr_bin     = peak_bin - 2;
            peak_upper  = peak_bin;
            peak_lower  = peak_bin - 2;

        } else if (peak_bin == 0) {

            upr_bin     = peak_bin + 2;
            lwr_bin     = peak_bin;
            peak_upper  = peak_bin + 2;
            peak_lower  = peak_bin;

        } else {

            upr_bin     = peak_bin + 1;
            lwr_bin     = peak_bin - 1;
            peak_upper  = peak_bin + 2;
            peak_lower  = peak_bin - 2;

        }

        center_sum = bin_pwr[lwr_bin] +
                bin_pwr[lwr_bin + 1] +
                bin_pwr[lwr_bin + 2];

        if (chk_upr) {
                upr_sum = bin_pwr[upr_bin + 1] +
                        bin_pwr[upr_bin + 2] +
                        bin_pwr[upr_bin + 3];
        }

        if (chk_lwr) {
                lwr_sum = bin_pwr[lwr_bin - 1] +
                        bin_pwr[lwr_bin - 2] +
                        bin_pwr[lwr_bin - 3];
        }

        if (!(lwr_sum < (center_sum >> GET_FHSS_SUM_SCALE_DOWN_FACTOR(pclas))))
            athssd_update_sample_state(pclas, FHSS_LWR_SUM_TOO_HIGH, use_sec80);
        if (!(upr_sum < (center_sum >> GET_FHSS_SUM_SCALE_DOWN_FACTOR(pclas))))
            athssd_update_sample_state(pclas, FHSS_UPR_SUM_TOO_HIGH, use_sec80);
        if (!(center_sum > GET_FHSS_CENTER_THRESH(pclas)))
            athssd_update_sample_state(pclas, FHSS_CENTER_SUM_TOO_LOW, use_sec80);

        /* Check if this is greater than threshold
         * XXX : Note, this logic works only for GET_FHSS_INT_BIN_SUM_SIZE(pclas) = 3
         */
        if ( (lwr_sum < (center_sum >> GET_FHSS_SUM_SCALE_DOWN_FACTOR(pclas))) &&
             (upr_sum < (center_sum >> GET_FHSS_SUM_SCALE_DOWN_FACTOR(pclas))) &&
             (center_sum > GET_FHSS_CENTER_THRESH(pclas)) ) {

            cur_fhss = &pseg->fhss_param[pseg->cur_bin];
            /* Possible FHSS burst */
            athssd_update_sample_state(pclas, FHSS_POSSIBLE_BURST, use_sec80);

            /* Check if this condition has lasted long enough */
            if (!cur_fhss->in_use) {

                /* This is being used for the first time */

                cur_fhss->in_use    = 1;
                cur_fhss->start_ts  = msg->samp_data.spectral_tstamp;
                cur_fhss->freq_bin  = peak_bin;
                cur_fhss->last_ts   = msg->samp_data.spectral_tstamp;
                cur_fhss->rssi      += spectral_rssi;
                cur_fhss->num_samp++;

            } else {

                /* This has been in use, check if this could be a new burst */
                if ( (cur_fhss->freq_bin < peak_upper) &&
                     (cur_fhss->freq_bin > peak_lower)) {

                    /* This is a current burst, check if this has been on for too long */
                    if ((int)(msg->samp_data.spectral_tstamp - cur_fhss->start_ts) > GET_FHSS_SINGLE_BURST_TIME(pclas)) {
                        /* This burst has been there for more then 15sec, it cannot be a FHSS burst */

                        athssd_update_sample_state(pclas, FHSS_REJECTION_ABOVE_SINGLE_BURST_TIME, use_sec80);
                        spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_FHSS, index);
                    } else {
                        /* Store the last time stamp */

                        cur_fhss->last_ts   =  msg->samp_data.spectral_tstamp;
                        cur_fhss->rssi      += spectral_rssi;
                        cur_fhss->num_samp++;
                    }

                } else {

                    /* Try putting it in the next bin */
                    cur_fhss->delta = (int)(cur_fhss->last_ts - cur_fhss->start_ts);

                    /* If the delta is too short, just reuse the bin, it is a fake signal */
                    if (cur_fhss->delta > GET_FHSS_MIN_DWELL_TIME(pclas)) {

                        pseg->cur_bin++;
                        athssd_update_sample_state(pclas, FHSS_MIN_DWELL_TIME_SATISFIED, use_sec80);

                        if (pseg->cur_bin == NUM_FHSS_BINS) {
                            /* All bins are full, search to see if there is a possible FHSS */
                            u_int32_t avg_delta         = 0;
                            u_int32_t fir_delta         = pseg->fhss_param[1].delta;
                            u_int32_t fir_min           = fir_delta - (fir_delta >> 2);
                            u_int32_t fir_max           = fir_delta + (fir_delta >> 2);
                            u_int16_t num_fhss_burst    = 0;
                            u_int32_t tot_burst         = 0;
                            int32_t tot_rssi          = 0;

                            /* Check if the dwell time is about the minimum
                            * TODO: Not needed because already weeded out
                            */
                            if (fir_delta > GET_FHSS_MIN_DWELL_TIME(pclas)) {
                                /* loop through the dwell time and see if the if the dwell time is about the same */
                                for (bin_cnt = 0; bin_cnt < NUM_FHSS_BINS; bin_cnt++) {
                                    if ((pseg->fhss_param[bin_cnt].delta > fir_min) &&
                                        (pseg->fhss_param[bin_cnt].delta < fir_max)) {
                                        /* dwell time is about the same */
                                        avg_delta   += pseg->fhss_param[bin_cnt].delta;
                                        tot_rssi    += pseg->fhss_param[bin_cnt].rssi;
                                        tot_burst   += pseg->fhss_param[bin_cnt].num_samp;
                                        num_fhss_burst++;
                                    }
                                }

                                if (num_fhss_burst > (NUM_FHSS_BINS >> 1)) {
                                    /* At least 1/2 the bins have about the same dwell time and hence declare
                                    * FHSS burst detection
                                    */
                                    avg_delta /= num_fhss_burst;
                                    tot_rssi /= tot_burst;
                                    //printf("Avg RSSI = %d total Burst %d Avg delta = %d\n",
                                    //    tot_rssi, tot_burst, avg_delta);

                                    ret_val = 1;
                                    /* Log the data */
                                } else {
                                    athssd_update_sample_state(pclas, FHSS_INSUFFICIENT_BINS_W_SAME_DWELL, use_sec80);
                                }
                            }else {
                                athssd_update_sample_state(pclas, FHSS_FIR_DELTA_NOT_CROSSING_MIN_DWELL, use_sec80);
                            }

                            spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_FHSS, index);
                            athssd_update_sample_state(pclas, FHSS_REINIT_AFTER_ALL_BINS_PROCESSED, use_sec80);
                        }else {
                            athssd_update_sample_state(pclas, FHSS_NUM_REQD_VIABLE_PEAKS_NOT_REACHED, use_sec80);
                        }

                        /* Put the data back in the same bin */
                        if (pseg->cur_bin <= NUM_FHSS_BINS) {
                            cur_fhss = &pseg->fhss_param[pseg->cur_bin];
                            cur_fhss->in_use    = 1;
                            cur_fhss->start_ts  = msg->samp_data.spectral_tstamp;
                            cur_fhss->freq_bin  = peak_bin;
                            cur_fhss->last_ts   = msg->samp_data.spectral_tstamp;
                        } else {
                            printf("Spectral Classifier: Array out of bound error \n");
                        }

                    } else {
                        athssd_update_sample_state(pclas, FHSS_MIN_DWELL_TIME_NOT_SATISFIED, use_sec80);

                        /* add a new bin with different frequency */
                        cur_fhss = &pseg->fhss_param[pseg->cur_bin];
                        cur_fhss->in_use    = 1;
                        cur_fhss->start_ts  = msg->samp_data.spectral_tstamp;
                        cur_fhss->freq_bin  = peak_bin;
                        cur_fhss->last_ts   = msg->samp_data.spectral_tstamp;
                    }
                }
            }

        } else {

            /* Not a narrow band burst, check if it has been absent for too long */
            /* This is a current burst, check if this has been on for too long */
            if ((int)(msg->samp_data.spectral_tstamp - cur_fhss->start_ts) > GET_FHSS_LACK_OF_BURST_TIME(pclas)) {
                /* This burst has been there for more then 15sec, it cannot be a FHSS burst */
                athssd_update_sample_state(pclas, FHSS_UNDETECTED_FOR_TOO_LONG_W_SUFFICIENT_RSSI, use_sec80);
                spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_FHSS, index);
            }
        }

    } else {

        /* No burst for a long time */
        /* This is a current burst, check if this has been on for too long */
        if ((int)(msg->samp_data.spectral_tstamp - cur_fhss->start_ts) > GET_FHSS_LACK_OF_BURST_TIME(pclas)) {
            /* This burst has been there for more then 15sec, it cannot be a FHSS burst */
            athssd_update_sample_state(pclas, FHSS_UNDETECTED_FOR_TOO_LONG_W_LOW_RSSI, use_sec80);
            spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_FHSS, index);
        }
    }

    if (ret_val) {

        ret_val = 0;

        /* Check if at least 2 detects happen in given amount of time */
        if (!(pclas->current_interference & SPECT_CLASS_DETECT_FHSS) || (!pseg->found_fhss)) {

            if (!pseg->num_detect) {
                athssd_update_sample_state(pclas, FHSS_FIRST_DETECT_FOUND, use_sec80);
                pseg->num_detect = 1;
                pseg->detect_ts  = msg->samp_data.spectral_tstamp;
            } else {

                pseg->num_detect++;
                athssd_update_sample_state(pclas, FHSS_SUBSEQUENT_DETECT_FOUND, use_sec80);

                if ((int)(msg->samp_data.spectral_tstamp - pseg->detect_ts) < GET_FHSS_DETECTION_CONFIRM_WIN(pclas)) {

                    if(!pclas->fhss[!index].found_fhss) {
                        pclas->current_interference |= SPECT_CLASS_DETECT_FHSS;
                    }
                    pseg->detect_ts = msg->samp_data.spectral_tstamp;

                    rdesc_ret =
                            populate_detection_region_descriptor_str(msg, index,
                                    region_descriptor_str,
                                    sizeof(region_descriptor_str));

                    SPECTRAL_CLASSIFIER_ASSERT(0 == rdesc_ret);

                    printf("Spectral Classifier: Found FHSS interference on %s\n",
                            region_descriptor_str);
                    pclas->fhss_cnt++;
                    pseg->found_fhss = 1;

                    /* Interference is detected, set commit flag now, to be used in logging
                     * at the end of the API
                     */
                    pclas->is_commit = true;

                } else {

                    pseg->num_detect = 0;
                    pseg->detect_ts = msg->samp_data.spectral_tstamp;
                    athssd_update_sample_state(pclas, FHSS_NOT_SUFFICIENT_DETECTS_WITHIN_CONFIRMATION_WINDOW, use_sec80);
                }
            }
        } else {

            /* Update the time */
            pseg->num_detect = 1;
            pseg->detect_ts = msg->samp_data.spectral_tstamp;

        }

    } else if ((pclas->current_interference & SPECT_CLASS_DETECT_FHSS) && (pseg->found_fhss)) {

        /* Check if it has been found before and not found of some time */
        if ((int)(msg->samp_data.spectral_tstamp - pseg->detect_ts) > GET_FHSS_DETECTION_RESET_WIN(pclas)) {
            if(!pclas->fhss[!index].found_fhss) {
                pclas->current_interference &=  ~(SPECT_CLASS_DETECT_FHSS);
            }
            pseg->num_detect      = 0;

            rdesc_ret =  populate_detection_region_descriptor_str(msg, index,
                                region_descriptor_str,
                                sizeof(region_descriptor_str));

            SPECTRAL_CLASSIFIER_ASSERT(0 == rdesc_ret);

            printf("Spectral Classifier: No FHSS interference on %s\n",
                    region_descriptor_str);
            pseg->found_fhss = 0;
        }
    }

    /* Check whether to log or commit or both */
    /* We shouldn't log/commit in 80p80/160 primary 80 MHz case as we have
     * to wait for secondary 80 MHz detection to complete.
     */
    if (!(IS_CHAN_WIDTH_160_OR_80P80(msg->samp_data.ch_width) && !use_sec80)) {
        spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_FHSS, 0);
        if (pclas->is_commit) {
            spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_FHSS, 1);
            pclas->is_commit = false;
        }
    }

    return ret_val;
}

/*
 * Function     : ether_sprintf
 * Description  : format MAC address for printing
 * Input params : pointer to mac address
 * Return       : formatted string
 *
 */

const char* ether_sprintf(const u_int8_t *mac)
{
    static char etherbuf[18];
    snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return etherbuf;
}


/*
 * Function     : print_spect_int_stats
 * Description  : Print spectral interference stats
 * Input params : Void
 * Return       : Void
 *
 */
extern void print_spect_int_stats()
{
    int i = 0;
    CLASSIFER_DATA_STRUCT *pclas;

    for (i = 0; i < CLASSIFIER_HASHSIZE; i++) {
        pclas = &class_data[i];

        if (pclas->is_valid) {
            printf("\nInterface = %s\n", ether_sprintf((const u_int8_t*)pclas->macaddr));
            printf("-----------------------------------------------\n");
            printf(" Number of MWO detection  %d\n"
                   " Number of WiFi detection %d\n"
                   " Number of FHSS detection %d\n"
                   " Number of CW detection   %d\n",
                    pclas->mwo_cnt,
                    pclas->wifi_cnt,
                    pclas->fhss_cnt,
                    pclas->cw_cnt);
        } /* end if */

    } /* end for */
}

/*
 * Function     : set_log_type
 * Description  : Set the type of info to log for debugging purpose
 * Input params : Pointer to classifier data structure, type of logging
 * Return       : Void
 *
 */
void set_log_type(CLASSIFER_DATA_STRUCT *pclas, u_int16_t log_type)
{
    switch (log_type) {
       case LOG_MWO:
           pclas->log_mode = SPECT_CLASS_DETECT_MWO;
           break;
       case LOG_CW:
           pclas->log_mode = SPECT_CLASS_DETECT_CW;
           break;
       case LOG_WIFI:
           pclas->log_mode = SPECT_CLASS_DETECT_WiFi;
           break;
       case LOG_FHSS:
           pclas->log_mode = SPECT_CLASS_DETECT_FHSS;
           break;
       case LOG_ALL:
           pclas->log_mode = SPECT_CLASS_DETECT_ALL;
           break;
       default:
           pclas->log_mode = SPECT_CLASS_DETECT_NONE;
           break;
    }
}

/*
 * Function     : get_bin_pwr_data
 * Description  : Get the pointer to bin pwr data adjusted based on bandwidth
 * Input params : Pointer to SAMP msg, bin pwr len to be populated for caller,
 *                flag to indicate secondary 80
 * Return       : Pointer to bin pwr data
 *
 */
static u_int8_t * get_bin_pwr_data(struct spectral_samp_msg* msg,
                                   u_int32_t *temp_bin_pwr_len, u_int8_t use_sec80)
{
    u_int8_t *temp_bin_pwr;
    u_int8_t lb_edge_bins = msg->samp_data.lb_edge_extrabins;
    u_int8_t rb_edge_bins = msg->samp_data.rb_edge_extrabins;
    u_int16_t num_bins_pri80;
    u_int16_t num_bins_sec80;
    u_int16_t bin_pwr_cnt_pri80 = msg->samp_data.bin_pwr_count;
    u_int16_t bin_pwr_cnt_sec80 = msg->samp_data.bin_pwr_count_sec80;

    if (IS_CHAN_WIDTH_160(msg->samp_data.ch_width)) {
        num_bins_pri80 = bin_pwr_cnt_pri80 - (lb_edge_bins + rb_edge_bins);
        num_bins_sec80 = bin_pwr_cnt_sec80 - (lb_edge_bins + rb_edge_bins);
        *temp_bin_pwr_len = num_bins_pri80 + num_bins_sec80;
        temp_bin_pwr = (u_int8_t *)malloc(*temp_bin_pwr_len);
        if (temp_bin_pwr == NULL) {
            printf("%s: Memory allocation failed!\n", __func__);
            return NULL;
        }

        memcpy(temp_bin_pwr, (u_int8_t*)&msg->samp_data.bin_pwr[lb_edge_bins], num_bins_pri80);
        memcpy(temp_bin_pwr + num_bins_pri80,
        (u_int8_t*)&msg->samp_data.bin_pwr_sec80[lb_edge_bins], num_bins_sec80);
    } else if (IS_CHAN_WIDTH_80P80(msg->samp_data.ch_width)) {
        if (!use_sec80) {
            temp_bin_pwr = (u_int8_t*)&msg->samp_data.bin_pwr[lb_edge_bins];
            *temp_bin_pwr_len = bin_pwr_cnt_pri80 - (lb_edge_bins + rb_edge_bins);
        } else {
            temp_bin_pwr = (u_int8_t*)&msg->samp_data.bin_pwr_sec80[lb_edge_bins];;
            *temp_bin_pwr_len = bin_pwr_cnt_sec80 - (lb_edge_bins + rb_edge_bins);
        }
    } else {
        temp_bin_pwr = (u_int8_t*)&msg->samp_data.bin_pwr[lb_edge_bins];
        *temp_bin_pwr_len = bin_pwr_cnt_pri80 - (lb_edge_bins + rb_edge_bins);
    }

    return temp_bin_pwr;
}

/*
 * Function     : classifier_process_spectral_msg
 * Description  : Process the incoming SAMP message
 * Input params : Pointers to SAMP msg, classifier struct, log type, and whether
 *                to enable linear scaling for Gen3 chipsets
 * Return       : Void
 *
 */
void classifier_process_spectral_msg(struct spectral_samp_msg* msg,
        CLASSIFER_DATA_STRUCT *pclas, u_int16_t log_type,
        bool enable_gen3_linear_scaling)
{
    u_int16_t bin_cnt = 0;
    u_int32_t temp_scaled_binmag = 0;

    /* validate */
    if (msg->signature != SPECTRAL_SIGNATURE) {
        return;
    }

    if (SPECTRAL_CAP_HW_GEN_3 == pclas->caps.hw_gen) {
        /*
         * For gen3 chipsets, the sample should be discarded if gain change is
         * indicated.
         */
        if (msg->samp_data.spectral_gainchange)
            return;
        /*
         * For gen3 chipsets, the sample should be discarded if hardware
         * indicates that the sample was received on the primary 80 MHz segment
         * instead of Agile frequency/secondary 80 MHz.
         */
        if ((SPECTRAL_SCAN_MODE_AGILE == msg->samp_data.spectral_mode) &&
                (msg->samp_data.spectral_pri80ind))
            return;

        if ((SPECTRAL_SCAN_MODE_NORMAL == msg->samp_data.spectral_mode) &&
            (IS_CHAN_WIDTH_160_OR_80P80(msg->samp_data.ch_width)) &&
            (msg->samp_data.spectral_pri80ind_sec80))
            return;
    }

    /* Mark as valid */
    pclas->is_valid = TRUE;

    /* Store the interface mac address */
    memcpy(pclas->macaddr, msg->macaddr, MAC_ADDR_LEN);

    if (enable_gen3_linear_scaling &&
            (pclas->caps.hw_gen == SPECTRAL_CAP_HW_GEN_3)) {
        /*
         * Scale the gen3 bins to values approximately similar to those of
         * gen2.
         */

        for (bin_cnt = 0; bin_cnt < msg->samp_data.bin_pwr_count; bin_cnt++)
        {
            /*
             * Note: Currently, we pass the same gen2 and gen3 bin_scale
             * values to the scaling formula, since for our algorithms we need
             * to scale for similar settings between gen2 and gen3. However, the
             * formula currently ignores the bin_scale values if they are the
             * same.
             * So we pass a bin_scale value of 1 for both gen2 and gen3 (which
             * is the recommended value for our algorithms anyway).
             *
             * A change can be added later to dynamically determine bin scale
             * values to be used.
             */

            /*
             * TODO: Get default max gain value, low level offset, RSSI
             * threshold, and high level offset from Spectral capabilities
             * structure once these are added there.
             */
            temp_scaled_binmag =
                spectral_scale_linear_to_gen2(msg->samp_data.bin_pwr[bin_cnt],
                        SPECTRAL_QCA9984_MAX_GAIN,
                        SPECTRAL_IPQ8074_DEFAULT_MAX_GAIN_HARDCODE,
                        SPECTRAL_SCALING_LOW_LEVEL_OFFSET,
                        msg->samp_data.spectral_rssi,
                        SPECTRAL_SCALING_RSSI_THRESH,
                        msg->samp_data.spectral_agc_total_gain,
                        SPECTRAL_SCALING_HIGH_LEVEL_OFFSET,
                        1,
                        1);

            msg->samp_data.bin_pwr[bin_cnt] =
                (temp_scaled_binmag > 255) ? 255: temp_scaled_binmag;
        }

        if (IS_CHAN_WIDTH_160_OR_80P80(msg->samp_data.ch_width)) {
            for (bin_cnt = 0;
                 bin_cnt < msg->samp_data.bin_pwr_count_sec80;
                 bin_cnt++)
            {
                /* See note for pri80 above regarding bin_scale values. */

                /*
                 * TODO: Get default max gain value, low level offset, RSSI
                 * threshold, and high level offset from Spectral capabilities
                 * structure once these are added there.
                 */
                temp_scaled_binmag =
                    spectral_scale_linear_to_gen2(\
                          msg->samp_data.bin_pwr_sec80[bin_cnt],
                          SPECTRAL_QCA9984_MAX_GAIN,
                          SPECTRAL_IPQ8074_DEFAULT_MAX_GAIN_HARDCODE,
                          SPECTRAL_SCALING_LOW_LEVEL_OFFSET,
                          msg->samp_data.spectral_rssi_sec80,
                          SPECTRAL_SCALING_RSSI_THRESH,
                          msg->samp_data.spectral_agc_total_gain_sec80,
                          SPECTRAL_SCALING_HIGH_LEVEL_OFFSET,
                          1,
                          1);

                msg->samp_data.bin_pwr_sec80[bin_cnt] =
                   (temp_scaled_binmag > 255) ? 255: temp_scaled_binmag;
            }
        }
    }

    if (!pclas->sm_init_done) {
        /* Initialize the classifier state machine */
        spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_ALL, 0);
        /* Set the log type */
        set_log_type(pclas, log_type);
    }

    /* Initialize the classifier state machine, if the frequency has changed */
    if (SPECTRAL_SCAN_MODE_NORMAL == msg->samp_data.spectral_mode) {
        if (pclas->cur_freq != msg->freq) {
            spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_ALL, 0);
            pclas->cur_freq = msg->freq;
        }
    } else if (SPECTRAL_SCAN_MODE_AGILE == msg->samp_data.spectral_mode) {
         if (pclas->cur_agile_freq1 != msg->agile_freq1 ||
             pclas->cur_agile_freq2 != msg->agile_freq2) {
            spectral_scan_classifer_sm_init(pclas, SPECT_CLASS_DETECT_ALL, 0);
            pclas->cur_agile_freq1 = msg->agile_freq1;
            pclas->cur_agile_freq2 = msg->agile_freq2;
        }
    }

    /* Log the Spectral data for debugging */
    spectral_scan_log_data(msg, pclas, SPECT_CLASS_DETECT_ALL, 0);

    /* Detect interference sources */
    detect_mwo(msg, pclas);

    /* Wi-Fi interference detection */
    u_int8_t *temp_bin_pwr;
    u_int32_t temp_bin_pwr_len;

    if (!IS_CHAN_WIDTH_80P80(msg->samp_data.ch_width)) {
        temp_bin_pwr = get_bin_pwr_data(msg, &temp_bin_pwr_len, 0);
        if (temp_bin_pwr != NULL)
            detect_wifi(msg, pclas, 0, temp_bin_pwr, temp_bin_pwr_len);
        if (IS_CHAN_WIDTH_160(msg->samp_data.ch_width)) {
            if (temp_bin_pwr)
                free(temp_bin_pwr);
        }
    } else {
        temp_bin_pwr = get_bin_pwr_data(msg, &temp_bin_pwr_len, 0);
        if (temp_bin_pwr != NULL)
            detect_wifi(msg, pclas, 0, temp_bin_pwr, temp_bin_pwr_len);

        temp_bin_pwr = get_bin_pwr_data(msg, &temp_bin_pwr_len, 1);
        if (temp_bin_pwr != NULL)
            detect_wifi(msg, pclas, 1, temp_bin_pwr, temp_bin_pwr_len);
    }
    /* Wi-Fi interference detection ends */

    if (IS_CHAN_WIDTH_160_OR_80P80(msg->samp_data.ch_width)) {
        /* Do not change the order of calls here */
        detect_cw(msg, pclas, 0);
        detect_cw(msg, pclas, 1);
        /*Do not change the order of calls here */
        detect_fhss(msg, pclas, 0);
        detect_fhss(msg, pclas, 1);
    } else {
        detect_cw(msg, pclas, 0);
        detect_fhss(msg, pclas, 0);
    }
}

/*
 * Function     : print_detected_interference
 * Description  : Print the type of interference detected
 * Input params : Pointer to classifier struct
 * Return       : Void
 *
 */
void print_detected_interference(CLASSIFER_DATA_STRUCT* pclas)
{

    if (IS_MWO_DETECTED(pclas)) {
        printf("MWO Detected\n");
    }

    if (IS_CW_DETECTED(pclas)) {
        printf("CW Detected\n");
    }

    if (IS_WiFi_DETECTED(pclas)) {
        printf("WiFi Detected\n");
    }

    if (IS_CORDLESS_24_DETECTED(pclas)) {
        printf("CP (2.4GHZ) Detected\n");
    }

    if (IS_CORDLESS_5_DETECTED(pclas)) {
        printf("CP (5GHz) Detected\n");
    }

    if (IS_BT_DETECTED(pclas)) {
        printf("BT Detected\n");
    }

    if (IS_FHSS_DETECTED(pclas)) {
        printf("FHSS Detected\n");
    }

}


