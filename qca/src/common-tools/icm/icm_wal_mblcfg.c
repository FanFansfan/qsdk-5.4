/*
 * Copyright (c) 2016-2018,2021 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2016 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 *
 *       Filename:  icm_wal_mblcfg.c
 *
 *    Description:  ICM WAL IOCTL related changes
 *
 *        Version:  1.0
 *        Created:  04/19/2012 01:18:58 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (),
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <icm.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#define _LINUX_TYPES_H

#include "icm.h"
#include "icm_wal.h"
#include "icm_api.h"
#include "icm_internal.h"
#include "driver_nl80211.h"

#ifndef ATH_DEFAULT
#define ATH_DEFAULT "wifi0"
#endif


/*
 * Function     : icm_wal_mblcfg_do_80211_scan
 * Description  : do an 802.11 scan and print scan results
 * Input params : pointer to icm
 * Return       : 0 on success, -1 on general errors, -2 on scan cancellation 
 */

int icm_wal_mblcfg_do_80211_scan(ICM_INFO_T * picm)
{
    int ret = 0, i;
    struct nl80211_scan_config scan_params;

    /* The below locking doesn't matter for standalone mode */
    pthread_mutex_lock(&picm->scanner_thread_mutex);
    if (picm->is_80211scan_cancel_requested == TRUE) {
        pthread_mutex_unlock(&picm->scanner_thread_mutex);
        fprintf(stderr, "%-8.16s  Scan cancelled\n\n", picm->dev_ifname);
        picm->substate = ICM_STATE_INVALID;
        return -2;
    }

    pthread_mutex_unlock(&picm->scanner_thread_mutex);

    scan_params.chan_info_flag = 0;
    scan_params.scan_ies = NULL;
    scan_params.scan_ies_len = 0;

    /* get freqs from channel list from capability info/structure */
    scan_params.freqs = zalloc(sizeof(int) * picm->chlist.count + 1);
    if (scan_params.freqs == NULL) {
        icm_printf("ICM: Failed to allocate memory\n");
        return -1;
    }

    for (i = 0; i < picm->chlist.count; i++) {
        scan_params.freqs[i] = picm->chlist.ch[i].freq;
    }
    scan_params.freqs[i] = 0; /* freqs array is expected to be zero terminated */

    ret = driver_nl80211_vendor_scan(picm, &scan_params);
    if (ret) {
        err("icm: failed to start vendor scan");
        return ret;
    }
    // Set state after sending vendor_scan
    picm->substate = ICM_STATE_CHANNEL_SCAN;

    return 0;
}

/*
 * Function     : icm_wal_mblcfg_set_width_and_channel
 * Description  : set width and channel as per best channel
 *                selection done previously.
 *                It is the caller's responsibility to ensure
 *                that the best channel selection has already been
 *                carried out, or if this has not been done, then
 *                a default channel has been set instead.
 *                It is the best channel selection code's
 *                responsibility to ensure that the width and channel
 *                are correct.
 * Input params : pointer to icm info, device name
 * Return       : SUCCESS/FAILURE
 */
int icm_wal_mblcfg_set_width_and_channel(ICM_INFO_T *picm, char *dev_ifname)
{
    char cmd[CMD_BUF_SIZE] = {'\0'};
    ICM_CONFIG_T* pconf = NULL;
    int ret;
    struct nl80211_channel_config chan_config;
    struct nl80211_chan_args *chan_list = NULL;
    ICM_CH_BW_T channel_width;
    ICM_BAND_T band = ICM_BAND_INVALID;
    int channel = 0;
    int ch_index = 0;
    int sec_channel = 0;
    int cfreq1_channel = 0;
    int cfreq2_channel = 0;

    char modestr[24] = {'\0'};
    ICM_DEV_INFO_T* pdev = get_pdev();
    int i = 0;
    int status = FAILURE;

    pconf = &pdev->conf;
    channel_width = picm->channel_width;

    if ((picm->ch_selection_mode == ICM_CH_SELECTION_MODE_MANUAL) ||
            (picm->best_channel < 0)) {
        int num_candidate_bands = ICM_GET_NUM_CANDIDATE_BANDS(picm);
        if (num_candidate_bands < 0) {
            err("Error when trying to retrieve the number of candidate bands\n");
            goto fail;
        }

        if (0 == num_candidate_bands) {
            err("No candidate bands present\n");
            goto fail;
        }

        if (num_candidate_bands > 1) {
            /* We do not process multi-band scenarios */
            err("Multi-band scenarios not handled\n");
            goto fail;
        }
    }

    if (picm->ch_selection_mode == ICM_CH_SELECTION_MODE_MANUAL) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "In manual channel selection mode; using default channel\n");

        band = ICM_GET_SINGLE_CANDIDATE_BAND(picm);
        if (ICM_BAND_INVALID == band) {
            err("Error when trying to retrieve single candidate band for manual channel selection mode\n");
            goto fail;
        }

        channel = picm->def_channel;
    } else if (picm->best_channel < 0) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Best channel not set/invalid. Considering "
                "default channel instead.\n");

        if (picm->def_channel == 0) {
            err("Both best channel and default channel are not set/invalid");
            goto fail;
        }

        band = ICM_GET_SINGLE_CANDIDATE_BAND(picm);
        if (ICM_BAND_INVALID == band) {
            err("Error when trying to retrieve single candidate band\n");
            goto fail;
        }

        channel = picm->def_channel;
    } else {
        band = picm->best_band;
        channel = picm->best_channel;

        /* We are operating in auto mode, so we need to use the resolved
           channel width. Without doing so, we won't properly set the
           mode in the case we have to resort to 20 MHz fallback
           or we selected plus/minus from the generic 40 MHz mode. */
        channel_width = picm->selected_channel_width;
    }

    if (channel == 0)
        goto send;

    /* get channel index in picm->chlist.ch.. channel should be non-zero. */
    for (ch_index = 0; ch_index < picm->chlist.count; ch_index++) {
        if ((picm->chlist.ch[ch_index].band == band) &&
                (picm->chlist.ch[ch_index].channel == channel))
            break;
    }

    if (ch_index == picm->chlist.count) {
        /* This is highly unlikely */
        err("Selected channel %d in band %s is not present in supported channel list",
                channel, icm_band_to_string(band));
        channel = 0;
        goto send;
    }

    if (channel_width >= ICM_CH_BW_INVALID) {
        err("Invalid channel width enumeration %u", channel_width);
        channel = 0;
        goto send;
    }

    if (channel_width > ICM_CH_BW_40) {
        /* figure out cfreq1_channel value from ic_vhtop_ch_freq_seg1 of supported channel list. */
        cfreq1_channel = picm->chlist.ch[ch_index].ic_vhtop_ch_freq_seg1;
    }

    if (channel_width == ICM_CH_BW_80_PLUS_80) {
        /* Add default channel processing for cfreq2 */
        cfreq2_channel = picm->best_cfreq2_channel;
    }

    /* Derive secondary channel */
    if (channel_width == ICM_CH_BW_40MINUS) {
        sec_channel = channel - 4; // Secondary for 40- is (primary - 20 Mhz)
    } else if (channel_width == ICM_CH_BW_40PLUS) {
        sec_channel = channel + 4; // Secondary for 40+ is (primary + 20 Mhz)
    } else if (channel_width == ICM_CH_BW_80 || channel_width == ICM_CH_BW_160) {
        /* This will be treated as offset in 80 or 160 case and is mandatory
         * As per hostapd logic, this field should exist.
         * Note: this is not being used in calculation of seg0/seg1. */

        if (ICM_IEEE80211REQ_IS_CHAN_HE40PLUS(&picm->chlist.ch[ch_index]) ||
            ICM_IEEE80211_IS_CHAN_VHT40PLUS(&picm->chlist.ch[ch_index])) {
            sec_channel = channel + 4;
        } else if (ICM_IEEE80211REQ_IS_CHAN_VHT40MINUS(&picm->chlist.ch[ch_index]) ||
                   ICM_IEEE80211REQ_IS_CHAN_HE40MINUS(&picm->chlist.ch[ch_index])) {
            sec_channel = channel - 4;
        }
    }

    /* Set mode */
    if (icm_compose_phymode_str(picm->phy_spec,
                channel_width,
                modestr,
                sizeof(modestr)) == NULL) {
        channel = 0;
        goto send;
    }

send:
    chan_config.ifname = dev_ifname;
    chan_config.reselect_reason = picm->reselect_reason;
    chan_config.num_channel = 1; /* TODO send entire list [Future task] */

    chan_list = zalloc(sizeof(*chan_list) * chan_config.num_channel);
    if (chan_list == NULL) {
        icm_printf("ICM: Failed to allocate memory\n");
        goto fail;
    }

    for (i = 0; i < chan_config.num_channel; i++) {
        u_int32_t primary_freq = 0, secondary_freq = 0, cfreq1_freq = 0,
                  cfreq2_freq = 0;

        if ((channel != 0) || (sec_channel != 0) || (cfreq1_channel != 0) ||
                (cfreq2_channel != 0)) {
            if ((band < 0) || (band >= ICM_BAND_MAX)) {
                err("Invalid band value %d. Unable to convert channel index to frequency, set channel failed.\n",
                        band);
                goto fail;
            }
        }

        if (channel != 0) {
            primary_freq = icm_convert_ieee2mhz(channel, band);

            if (0 == primary_freq) {
                err("Unable to convert primary channel index %d in band %s to frequency, set channel failed.\n",
                        channel, icm_band_to_string(band));
                goto fail;
            }
        }

        if (sec_channel != 0) {
            secondary_freq = icm_convert_ieee2mhz(sec_channel, band);

            if (0 == secondary_freq) {
                err("Unable to convert secondary channel index %d in band %s to frequency, set channel failed.\n",
                        sec_channel, icm_band_to_string(band));
                goto fail;
            }
        }

        if (cfreq1_channel != 0) {
            cfreq1_freq = icm_convert_ieee2mhz(cfreq1_channel, band);

            if (0 == cfreq1_freq) {
                err("Unable to convert cfreq1 channel index %d in band %s to frequency, set channel failed.\n",
                        cfreq1_channel, icm_band_to_string(band));
                goto fail;
            }
        }

        if (cfreq2_channel != 0) {
            cfreq2_freq = icm_convert_ieee2mhz(cfreq2_channel, band);

            if (0 == cfreq2_freq) {
                err("Unable to convert cfreq2 channel index %d in band %s to frequency, set channel failed.\n",
                        cfreq2_channel, icm_band_to_string(band));
                goto fail;
            }
        }

        chan_list[i].primary_freq = primary_freq; /* use sort_chan_list instead */
        chan_list[i].secondary_freq = secondary_freq;
#ifdef ICM_RTR_DRIVER
        chan_list[i].channel_width = convert_to_RTR_driver_chan_width(channel_width);
#else
        chan_list[i].channel_width = convert_RTR_to_mbl_chan_width(channel_width);
#endif /* ICM_RTR_DRIVER */
        chan_list[i].seg0_center_freq = cfreq1_freq;
        chan_list[i].seg1_center_freq = cfreq2_freq;
    }
    chan_config.channel_list = chan_list; 

    if (channel == 0)
        icm_printf("ICM: No Usable channel found. Setting 0 to indicate channel selection failed/completed");

#ifdef ICM_RTR_DRIVER
    if (ICM_IEEE80211_IS_CHAN_2GHZ(&(picm->chlist.ch[ch_index])) &&
            (pconf->spectral_enab && picm->spectral_capable)) {
        /* For 2G with Spectral change channel and mode
         * using iwconfig/cfg80211tool */
        snprintf(cmd, sizeof(cmd), "%s %s %s %s", "cfg80211tool",
                 dev_ifname, "mode",  modestr);
        ret = system(cmd);

        if (ret == -1) {
            perror("icm : system");
            goto fail;
        }

        if (WEXITSTATUS(ret) != 0) {
            err("Error in setting mode; command was: %s", cmd);
            goto fail;
        }

        /* Set channel */
        snprintf(cmd, sizeof(cmd), "%s %s %s %1d", "iwconfig",
                 dev_ifname, "channel", channel);
        ret = system(cmd);

        if (ret == -1) {
            perror("icm : system");
            goto fail;
        }

        if (WEXITSTATUS(ret) != 0) {
            err("Error in setting channel; command was: %s", cmd);
            goto fail;
        }
    } else {
        /* For 5G/ 2G without spectral set the channel using vendor event */
        if (icm_wal_set_channel(picm, &chan_config)) {
            err("Error in setting channel; ");
            goto fail;
        }
    }
#else
    if (icm_wal_set_channel(picm, &chan_config)) {
        err("Error in setting channel; ");
        goto fail;
    }
#endif

    if (channel == 0) {
        icm_printf("set_channel success with channel %d", channel);
        goto fail;
    }

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Successfully set channel %d mode %s\n",
            channel,
            modestr);

    if (channel_width == ICM_CH_BW_80_PLUS_80) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_MAIN,  "Successfully set secondary 80 MHz channel index %d mode %s\n",
                cfreq2_channel,
                modestr);
    }

    status = SUCCESS;

fail:
    if (chan_list != NULL)
        free(chan_list);

    return status;
}


/*
 * Function     : icm_wal_mblcfg_cancel_80211_scan
 * Description  : Cancel all 802.11 scans for the given icm
 * Input params : pointer to icm
 * Return       : success/failure
 */
int icm_wal_mblcfg_cancel_80211_scan(ICM_INFO_T * picm)
{
    //Print if error is returned
    return driver_nl80211_abort_scan(picm);
}

/*
 * Function     : icm_wal_mblcfg_set_channel
 * Description  : Set channel to driver
 * Input params : pointer to icm
 * Return       : success/failure
 */
int icm_wal_mblcfg_set_channel(ICM_INFO_T * picm, struct nl80211_channel_config *chan_config)
{
    return driver_nl80211_set_channel(picm, chan_config);
}

/*
 * Function     : icm_wal_mblcfg_set_channel
 * Description  : Set channel to driver
 * Input params : pointer to icm
 * Return       : success/failure
 */
int icm_wal_mblcfg_get_currdomain(ICM_INFO_T * picm)
{
    char country[4];

    if (driver_nl80211_get_country(picm, country) < 0) {
        icm_printf("Error in getting country code");
        return -1;
    }

    return 0;
}

/*
 * Function     : icm_wal_mblcfg_get_reg_domain
 * Description  : Get reg domain
 * Input params : pointer to icm
 * Return       : success/failure
 */
int icm_wal_mblcfg_get_reg_domain(ICM_INFO_T * picm)
{
    enum nl80211_dfs_regions dfs_domain;

    if (driver_nl80211_get_reg_domain(picm, &dfs_domain) < 0) {
        icm_printf("Error in getting country code");
        return FAILURE;
    }

    picm->dfs_domain = dfs_domain;
    return SUCCESS;
}

/*
 * Function     : icm_wal_cfg_init_channel_params
 * Description  : init channel related params
 *                Initialize base usability for all channels
 * Input params : pointer to icm
 * Return       : void
 *
 */
void icm_wal_cfg_init_channel_params(ICM_INFO_T* picm)
{
    int band = 0, channel = 0, i = 0;
    ICM_CHANNEL_LIST_T *pchlist = NULL;

    ICM_ASSERT(picm != NULL);

    for (band = 0; band < ICM_BAND_MAX; band++) {
        ICM_CLEAR_AS_CANDIDATE_BAND(picm, band);

        pchlist = ICM_GET_BAND_CHANNEL_LIST_PTR(picm, band);
        ICM_ASSERT(pchlist != NULL);

        pchlist->count = 0;
        pchlist->channel_index = 0;
        memset(&pchlist->ch, 0, sizeof(pchlist->ch));

        for (i = 0; i < ARRAY_LEN(pchlist->ch); i++) {
            pchlist->ch[i].band = band;
        }
    }

    for (band = 0; band < ICM_BAND_MAX; band++) {
        for (channel = 0; channel < MAX_NUM_CHANNEL; channel++) {
            ICM_CLEAR_CHANNEL_EXCLUDE(picm, band, channel);

            ICM_SET_CHANNEL_BLUSABILITY(picm, band, channel, MAX_USABILITY);
        }
    }
}

#ifdef ICM_RTR_DRIVER
/*
 * Function     : icm_wal_mblcfg_get_channel_status
 * Description  : Get channel-specific status information
 * Input params : pointer to icm
 * Return       : 0 on success, -1 on general errors
 */
int icm_wal_mblcfg_get_channel_status(ICM_INFO_T * picm)
{
    ICM_CONFIG_T* pconf = NULL;
    ICM_DEV_INFO_T* pdev = get_pdev();
    int ret    = 0;
    int status = 0;
    uint32_t i = 0, j = 0;
    struct nl80211_channel_status channel_status;

    pconf = &pdev->conf;

    memset(&channel_status, 0, sizeof(channel_status));

    status = driver_get_wifi_offchancac_status(picm,
                                               picm->radio_ifname,
                                               &channel_status);
    if (status) {
        err("icm: Failed to get channel status info\n");
        ret = -1;
        goto end;
    }

    /* Initializing OCAC status for all channels to CLEAR by default */
    for (i = 0; i < ICM_BAND_MAX; i++) {
        for (j = 0; j < MAX_NUM_CHANNEL; j++) {
            ICM_SET_CHANNEL_OCAC_STATUS(picm, i, j, OCAC_STATUS_CLEAR);
        }
    }

    if (!channel_status.num_ocaclinst) {
        icm_printf("OCAC list is empty. Disabling rejection\n");
        pconf->icm_rejection_rule[ICM_SELDBG_REJCODE_PRI_OCAC][ICM_REJECT_POLICY_SKIP] = true;
        pconf->icm_rejection_rule[ICM_SELDBG_REJCODE_BOND_OCAC][ICM_REJECT_POLICY_SKIP] = true;
        goto end;
    }

    for (i = 0; i < channel_status.num_ocaclinst; i++) {
        ICM_BAND_T band = ICM_BAND_INVALID;
        int pri_chan_idx = -1;

        band = icm_get_band_from_freq(channel_status.ocacl[i].primary_freq);
        if  (ICM_BAND_INVALID == band) {
            icm_printf("Unable to map frequency %u to recognized band. "
                       "Skipping OCAC instance.\n",
                       channel_status.ocacl[i].primary_freq);
            continue;
        }

        pri_chan_idx = icm_convert_mhz2channel(channel_status.ocacl[i].primary_freq);
        ICM_SET_CHANNEL_OCAC_STATUS(picm, band, pri_chan_idx,
                                    channel_status.ocacl[i].ocac_status);
    }

end:
    if (channel_status.ocacl != NULL) {
        free(channel_status.ocacl);
        channel_status.ocacl = NULL;
    }

    return ret;
}
#endif /* ICM_RTR_DRIVER */

/*
 * Function     : icm_wal_get_chan_rropinfo
 * Description  : Get Representative RF Operating Parameter (RROP) information
 * Input params : pointer to icm
 * Return       : 0 on success, -1 on general errors
 */
int icm_wal_mblcfg_get_chan_rropinfo(ICM_INFO_T * picm)
{
    int ret = 0;
    int status = 0;
    uint32_t i = 0;
    struct nl80211_rropinfo rropinfo;

    memset(&rropinfo, 0, sizeof(rropinfo));

    status = driver_nl80211_vendor_get_chan_rropinfo(picm, &rropinfo);
    if (status) {
        err("icm: Failed to get RROP info");
        ret = -1;
        goto end;
    }

    if ((rropinfo.num_rtplinst == 0) || (rropinfo.rtpl == NULL))
    {
        err("icm: Failed to get RTPL");
        ret = -1;
        goto end;
    }

    for (i = 0; i < rropinfo.num_rtplinst; i++) {
        ICM_BAND_T band = ICM_BAND_INVALID;
        int pri_chan_idx = -1;

        band = icm_get_band_from_freq(rropinfo.rtpl[i].primary_freq);
        if  (ICM_BAND_INVALID == band) {
            icm_printf("Unable to map frequency %u to recognized band. Skipping RTPL instance.\n",
                    rropinfo.rtpl[i].primary_freq);
            continue;
        }

        pri_chan_idx = icm_convert_mhz2channel(rropinfo.rtpl[i].primary_freq);

        ICM_SET_CHANNEL_TX_POWER_TPUT(picm, band, pri_chan_idx,
                rropinfo.rtpl[i].txpower_throughput);
        ICM_SET_CHANNEL_TX_POWER_RANGE(picm, band, pri_chan_idx,
                rropinfo.rtpl[i].txpower_range);
    }

end:
    if (rropinfo.rtpl != NULL)
    {
        free(rropinfo.rtpl);
        rropinfo.rtpl = NULL;
    }
    return ret;
}
