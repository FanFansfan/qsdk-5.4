/*
 * Copyright (c) 2012,2017,2019-2021 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * 2012 Qualcomm Atheros, Inc..
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * =====================================================================================
 *
 *       Filename:  icm_utils.c
 *
 *    Description:  Utility Functions for ICM
 *
 *        Version:  1.0
 *        Created:  05/17/2012 11:19:42 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (),
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <stdarg.h>
#include <icm.h>
#include <sys/time.h>
#include <errno.h>
#ifdef WLAN_SPECTRAL_ENABLE
#include "ath_classifier.h"
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#include "spectral_ioctl.h"
#endif /* WLAN_SPECTRAL_ENABLE */

#ifdef ICM_RTR_DRIVER
/*
 * Function     : convert_to_RTR_driver_chan_width
 * Description  : Convert ICM channel width to RTR driver channel width
 * Input params : channel width
 * Return       : RTR driver channel width
 *
 */
enum ieee80211_cwm_width convert_to_RTR_driver_chan_width(ICM_CH_BW_T ch_width)
{
    switch (ch_width){
        case ICM_CH_BW_20:
            return IEEE80211_CWM_WIDTH20;
        case ICM_CH_BW_40MINUS:
        case ICM_CH_BW_40PLUS:
        case ICM_CH_BW_40:
            return IEEE80211_CWM_WIDTH40;
        case ICM_CH_BW_80:
            return IEEE80211_CWM_WIDTH80;
        case ICM_CH_BW_160:
            return IEEE80211_CWM_WIDTH160;
        case ICM_CH_BW_80_PLUS_80:
            return IEEE80211_CWM_WIDTH80_80;
        default:
            return IEEE80211_CWM_WIDTHINVALID;
    }
}
#endif /* ICM_RTR_DRIVER */

/*
 * Function     : display_scan_db
 * Description  : Displays the contents of Scan results
 * Input params : pointer to icm
 * Return       : void
 *
 */
void icm_display_scan_db(ICM_INFO_T* picm)
{
    int i = 0;
    ICM_DEV_INFO_T* pdev = get_pdev();
    /*
     * XXX : 5GHz frequencies are not correctly decoded
     */

    for (i = 0; i < MAX_SCAN_ENTRIES; i++) {
        if (picm->slist.elem[i].valid) {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "Entry No    : %d\n", i);
            ICM_DPRINTF(pdev,
                    ICM_PRCTRL_FLAG_NO_PREFIX,
                    ICM_DEBUG_LEVEL_DEFAULT,
                    ICM_MODULE_ID_UTIL,
                    LINESTR);

            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tBSSID     : %s\n", icm_ether_sprintf(picm->slist.elem[i].bssid));
            /* XXX - SSIDs need not necessarily be NULL terminated, as per standard. Handle this */
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tSSID      : %s\n", picm->slist.elem[i].ssid);
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tChannel   : %d  %s\n", picm->slist.elem[i].channel,((picm->slist.elem[i].channel == (-2))?"Invalid":"Valid"));
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\tFrequency : %g\n", picm->slist.elem[i].freq);


            if (picm->slist.elem[i].htinfo.is_valid) {
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "HT Operation Info\n");

                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tExtension Channel Offset : %d\n",
                        picm->slist.elem[i].htinfo.ext_channel_offset);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tTx Channel Width         : %d\n",
                        picm->slist.elem[i].htinfo.tx_channel_width);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tOBSS NoHT Present        : %d\n",
                        picm->slist.elem[i].htinfo.obss_nonht_present);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tTx Burst Limit           : %d\n",
                        picm->slist.elem[i].htinfo.tx_burst_limit);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tNon GF Present           : %d\n",
                        picm->slist.elem[i].htinfo.non_gf_present);
            }


            if (picm->slist.elem[i].vhtop.is_valid) {

                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "VHT Operation Info\n");
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tChannel Width   : %d\n",
                        picm->slist.elem[i].vhtop.channel_width);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tChannel CF Seg1 : %d\n",
                        picm->slist.elem[i].vhtop.channel_cf_seg1);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tChannel CF Seg2 : %d\n",
                        picm->slist.elem[i].vhtop.channel_cf_seg2);

            }

            if (picm->slist.elem[i].heop.is_valid &&
                    picm->slist.elem[i].heop.heop_vhtopinfo.is_valid) {
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT,
                        ICM_MODULE_ID_UTIL, "HE VHT Operation Info\n");
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT,
                        ICM_MODULE_ID_UTIL, "\tChannel Width   : %d\n",
                        picm->slist.elem[i].heop.heop_vhtopinfo.channel_width);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT,
                        ICM_MODULE_ID_UTIL, "\tChannel CF Seg1 : %d\n",
                        picm->slist.elem[i].heop.heop_vhtopinfo.channel_cf_seg1);
                ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT,
                        ICM_MODULE_ID_UTIL, "\tChannel CF Seg2 : %d\n",
                        picm->slist.elem[i].heop.heop_vhtopinfo.channel_cf_seg2);
            }

            ICM_DPRINTF(pdev,
                    ICM_PRCTRL_FLAG_NO_PREFIX,
                    ICM_DEBUG_LEVEL_DEFAULT,
                    ICM_MODULE_ID_UTIL,
                    LINESTR);

            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL,  "\n");
        }
    }

}

/*
 * Function     : icm_ether_sprintf
 * Description  : print the mac address in user friendly string
 * Input params : pointer to address
 * Return       : const pointer to string
 *
 */
const char* icm_ether_sprintf(const uint8_t mac[6])
{
    static char buf[32];

    /* the format is done as per ntoh conversion */
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

/*
 * Function     : icm_convert_mhz2channel
 * Description  : converts MHz to IEEE channel
 * Input params : freq in MHz
 * Return       : channel number
 *
 */
int icm_convert_mhz2channel(u_int32_t freq)
{

    if (freq == BAND_2_4GHZ_FREQ_MAX)
        return 14;

    if (freq < BAND_2_4GHZ_FREQ_MAX)
        return (freq - BAND_2_4GHZ_FREQ_BASE) / 5;

    /* Only 6 GHz non-orphan channelization handled currently. Policy for orphan
     * channelization and any sort of generalized handling around this to be
     * decided separately after receiving more regulatory and productization
     * clarity.
     */
    if (freq > BAND_6GHZ_FREQ_BASE_NON_ORPHAN)
        return (freq - BAND_6GHZ_FREQ_BASE_NON_ORPHAN) / 5;

    if (freq < BAND_5GHZ_FREQ_BASE) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
            return ((freq * 10) + 
                    (((freq % 5) == 2) ? 5 : 0) -
                        (10 * BAND_PUBLIC_SAFETY_BASE))/5;
        } else if (freq > IEEE80211J_JP_FREQ_MIN) {
            return (freq - IEEE80211J_JP_FREQ_BASE) / 5;
        } else {
            return 15 + ((freq - WLAN_CHAN_15_FREQ) / 20);
        }
    }

    return (freq - BAND_5GHZ_FREQ_BASE) / 5;
}

/*
 * Function     : icm_convert_ieee2mhz
 * Description  : Convert IEEE channel to frequency in MHz. The conversion is
 *                currently provided only for bands supported in ICM.
 * Input params : IEEE channel, band
 * Return       : Frequency in MHz, 0 on error
 */
u_int32_t icm_convert_ieee2mhz(int chan, ICM_BAND_T band)
{
    if (band == ICM_BAND_2_4G) {
        if (chan == 14)
            return BAND_2_4GHZ_FREQ_MAX;
        if (chan < 14)          /* 0-13 */
            return BAND_2_4GHZ_FREQ_BASE + chan * 5;
    }

    if (band == ICM_BAND_5G) {
        return BAND_5GHZ_FREQ_BASE + (chan * 5);
    }

    /* Only 6 GHz non-orphan channelization handled currently. Policy for orphan
     * channelization and any sort of generalized handling around this to be
     * decided separately after receiving more regulatory and productization
     * clarity.
     */
    if (band == ICM_BAND_6G) {
        return BAND_6GHZ_FREQ_BASE_NON_ORPHAN + (chan * 5);
    }

    /*
     * Add handling of public safety band and channels 15-26 (2512 MHz onwards)
     * as and when required in the future.
     */

    return 0;
}

/*
 * Function     : icm_get_band_from_freq
 * Description  : Get band from frequency in MHz. This is currently provided
 *                only for bands supported in ICM.
 * Input params : Frequency in MHz
 * Return       : Valid ICM band on success, ICM_BAND_INVALID on failure
 */
ICM_BAND_T icm_get_band_from_freq(u_int32_t freq)
{
    if ((freq >= BAND_2_4GHZ_FREQ_MIN) && (freq <= BAND_2_4GHZ_FREQ_MAX))
        return ICM_BAND_2_4G;

    if ((freq >= BAND_5GHZ_FREQ_MIN) && (freq <= BAND_5GHZ_FREQ_MAX))
        return ICM_BAND_5G;

    /* Only 6 GHz non-orphan channelization handled currently. Policy for orphan
     * channelization and any sort of generalized handling around this to be
     * decided separately after receiving more regulatory and productization
     * clarity.
     */
    if ((freq >= BAND_6GHZ_FREQ_MIN_NON_ORPHAN) && (freq <= BAND_6GHZ_FREQ_MAX))
        return ICM_BAND_6G;

    return ICM_BAND_INVALID;
}

/*
 * Function     : icm_get_num_candidate_bands
 * Description  : Get the number of candidate bands being considered for channel
 *                selection.
 * Input params : Pointer to ICM info
 * Return       : Number of candidate bands on success, -1 on failure
 */
int icm_get_num_candidate_bands(ICM_INFO_T* picm)
{
    int band = 0;
    int count = 0;

    ICM_ASSERT(picm != NULL);

    for (band = 0; band < ICM_BAND_MAX; band++) {
        if (ICM_IS_CANDIDATE_BAND(picm, band)) {
            count++;
        }
    }

    return count;
}

/*
 * Function     : icm_get_single_candidate_band
 * Description  : Get the single candidate band being considered for channel
 *                selection.
 * Input params : Pointer to ICM info
 * Return       : Single candidate band on success, ICM_BAND_INVALID on failure
 *                (presence of no candidate band or multiple candidate bands is
 *                considered as one of the failures)
 */
ICM_BAND_T icm_get_single_candidate_band(ICM_INFO_T* picm)
{
    ICM_BAND_T band = 0;
    int count = 0;

    ICM_ASSERT(picm != NULL);

    count = ICM_GET_NUM_CANDIDATE_BANDS(picm);

    if (count != 1) {
        return ICM_BAND_INVALID;
    }

    for (band = 0; band < ICM_BAND_MAX; band++) {
        if (ICM_IS_CANDIDATE_BAND(picm, band)) {
            return band;
        }
    }

    return ICM_BAND_INVALID;
}

/*
 * Function     : icm_set_single_candidate_band
 * Description  : Set a single candidate band to be considered for channel
 *                selection, and remove candidature of all other bands.
 * Input params : Pointer to ICM info, band
 * Return       : 0 on success, -1 on failure
 */
int icm_set_single_candidate_band(ICM_INFO_T* picm, ICM_BAND_T candidate_band)
{
    ICM_BAND_T band = 0;

    ICM_ASSERT(picm != NULL);

    if ((candidate_band < 0)|| (candidate_band >= ICM_BAND_MAX)) {
        return -1;
    }

    ICM_SET_AS_CANDIDATE_BAND(picm, candidate_band);

    for (band = 0; band < ICM_BAND_MAX; band++) {
        if (band != candidate_band) {
            ICM_CLEAR_AS_CANDIDATE_BAND(picm, band);
        }
    }

    return 0;
}

#ifdef ICM_RTR_DRIVER
void icm_display_channel_flags(ICM_CHANNEL_T* pch)
{
    ICM_DEV_INFO_T* pdev = get_pdev();
    if (ICM_IEEE80211_IS_CHAN_FHSS(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tFHSS\n");
    }

    if (ICM_IEEE80211_IS_CHAN_11NA(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11na\n");
    } else if (ICM_IEEE80211_IS_CHAN_A(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11a\n");
    } else if (ICM_IEEE80211_IS_CHAN_11NG(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11ng\n");
    } else if (ICM_IEEE80211_IS_CHAN_G(pch) ||
            ICM_IEEE80211_IS_CHAN_PUREG(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11g\n");
    } else if (ICM_IEEE80211_IS_CHAN_B(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t11b\n");
    }
    if (ICM_IEEE80211_IS_CHAN_TURBO(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tTurbo\n");
    }
    if(ICM_IEEE80211_IS_CHAN_11N_CTL_CAPABLE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tControl capable\n");
    }
    if(ICM_IEEE80211_IS_CHAN_11N_CTL_U_CAPABLE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tControl capable upper\n");
    }
    if(ICM_IEEE80211_IS_CHAN_11N_CTL_L_CAPABLE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tControl capable lower\n");
    }

    if (ICM_IEEE80211_IS_CHAN_DFS(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tDFS\n");
    }

    if (ICM_IEEE80211_IS_CHAN_HALF(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tHalf\n");
    }

    if (ICM_IEEE80211_IS_CHAN_PASSIVE(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tPassive\n");
    }

    if (ICM_IEEE80211_IS_CHAN_QUARTER(pch)) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\tQuarter\n");
    }
}
#endif /* ICM_RTR_DRIVER */

/*
 * Function     : icm_display_channels
 * Description  : prints supported channels
 * Input params : pointer to ICM
 * Return       : void
 *
 */
void icm_display_channels(ICM_INFO_T* picm)
{
    icm_print_chaninfo(picm, ICM_BAND_2_4G);
    icm_print_chaninfo(picm, ICM_BAND_5G);
    icm_print_chaninfo(picm, ICM_BAND_6G);
    return ;
}

void icm_print_chaninfo(ICM_INFO_T* picm, ICM_BAND_T band)
{
    int i = 0;
    int wnw_found = 0;
    ICM_CHANNEL_LIST_T *pchlist = NULL;
    ICM_DEV_INFO_T* pdev = get_pdev();

    ICM_ASSERT(picm != NULL);

    if (band == ICM_BAND_2_4G) {
        pchlist = ICM_GET_2_4GHZ_CHANNEL_LIST_PTR(picm);
        ICM_ASSERT(pchlist != NULL);

        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\nSupported 2.4 GHz Channels\n");
        ICM_DPRINTF(pdev,
                ICM_PRCTRL_FLAG_NO_PREFIX,
                ICM_DEBUG_LEVEL_DEFAULT,
                ICM_MODULE_ID_UTIL,
                LINESTR);
    } else if (band == ICM_BAND_5G) {
        pchlist = ICM_GET_5GHZ_CHANNEL_LIST_PTR(picm);
        ICM_ASSERT(pchlist != NULL);

        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\nSupported 5 GHz Channels\n");
        ICM_DPRINTF(pdev,
                ICM_PRCTRL_FLAG_NO_PREFIX,
                ICM_DEBUG_LEVEL_DEFAULT,
                ICM_MODULE_ID_UTIL,
                LINESTR);
    } else if (band == ICM_BAND_6G) {
        pchlist = ICM_GET_6GHZ_CHANNEL_LIST_PTR(picm);
        ICM_ASSERT(pchlist != NULL);

        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT,
                ICM_MODULE_ID_UTIL, "\nSupported 6 GHz Channels\n");
        ICM_DPRINTF(pdev,
                ICM_PRCTRL_FLAG_NO_PREFIX,
                ICM_DEBUG_LEVEL_DEFAULT,
                ICM_MODULE_ID_UTIL,
                LINESTR);
    } else {
        pchlist = &picm->chlist;
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\nSupported Channels\n");
        ICM_DPRINTF(pdev,
                ICM_PRCTRL_FLAG_NO_PREFIX,
                ICM_DEBUG_LEVEL_DEFAULT,
                ICM_MODULE_ID_UTIL,
                LINESTR);
    }

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL, "total number of channels = %d\n", pchlist->count);
    for (i = 0; i < pchlist->count; i++) {
        wnw_found = icm_get_wireless_nw_in_channel(picm, pchlist->ch[i].channel);
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\nchannel : %d : Freq = %d MHz\n", pchlist->ch[i].channel, (int)pchlist->ch[i].freq);
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- Is extension channel 20 MHz : %s\n",
                (pchlist->ch[i].used_as_secondary_20)?"Yes":"No" );
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- Is secondary 40 MHz of 160/80+80 MHz BSS : %s\n",
                (pchlist->ch[i].used_as_160_80p80_secondary_40)?"Yes":"No" );
        if (wnw_found) {
            ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- Number of WNW %d\n", wnw_found);
        }
#ifdef ICM_RTR_DRIVER   
        icm_display_interference(pchlist->ch[i].flags);
        icm_display_channel_flags(&pchlist->ch[i]);
#endif /* ICM_RTR_DRIVER */
    }

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\n");

}


#ifdef ICM_RTR_DRIVER   
/*
 * Function     : icm_display_channels
 * Description  : prints supported channels
 * Input params : pointer to ICM
 * Return       : void
 *
 */
void icm_display_interference(int flags)
{
    ICM_DEV_INFO_T* pdev = get_pdev();
    if (flags & SPECT_CLASS_DETECT_MWO) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- MWO Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_CW) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- CW Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_WiFi) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- WiFi Interfernce detected\n");

    }

    if (flags & SPECT_CLASS_DETECT_CORDLESS_24) {

        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- CORDLESS 2.4GHz Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_CORDLESS_5) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- CORDLESS 5GHz Interfernce detected\n");
    }

    if (flags & SPECT_CLASS_DETECT_BT) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- BT Interfernce detected\n");

    }

    if (flags & SPECT_CLASS_DETECT_FHSS) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT, ICM_MODULE_ID_UTIL, "\t- FHSS Interfernce detected\n");
    }


}
#endif /* ICM_RTR_DRIVER */

int icm_display_chan_properties(ICM_INFO_T* picm, ICM_BAND_T band)
{
    int i;
    ICM_DEV_INFO_T* pdev = get_pdev();

    for (i = 0; i < MAX_NUM_CHANNEL; i++) {
        ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_DEFAULT,
                ICM_MODULE_ID_UTIL,
                "band=%d, chan idx=%d cycle count=%d free time=%d per=%d nf=%d\n",
                band,
                i,
                ICM_GET_CHANNEL_CYCLE_COUNT(picm, band, i),
                ICM_GET_CHANNEL_FREE_TIME(picm, band, i),
                ICM_GET_CHANNEL_PER(picm, band, i),
                ICM_GET_CHANNEL_NOISEFLOOR(picm, band, i));
    }

    return 0;
}

int icm_trim_spectral_scan_ch_list(ICM_INFO_T* picm)
{
    ICM_DEV_INFO_T* pdev = get_pdev();
    ICM_CHANNEL_LIST_T *pchlist = NULL;

    ICM_ASSERT(picm != NULL);

    pchlist = ICM_GET_2_4GHZ_CHANNEL_LIST_PTR(picm);
    ICM_ASSERT(pchlist != NULL);

    ICM_DPRINTF(pdev, ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR,
            ICM_MODULE_ID_UTIL, "Trimming 2.4 GHz Channels for Spectral Scan");
    pchlist->count = 3;
    pchlist->ch[0].channel = 1;
    pchlist->ch[1].channel = 6;
    pchlist->ch[2].channel = 11;
    return 0;
}


size_t os_strlcpy(char *dest, const char *src, size_t siz)
{
    const char *s = src;
    size_t left = siz;

    if (left) {
        /* Copy string up to the maximum size of the dest buffer */
        while (--left != 0) {
            if ((*dest++ = *s++) == '\0')
                break;
        }
    }

    if (left == 0) {
        /* Not enough room for the string; force NUL-termination */
        if (siz != 0)
            *dest = '\0';
        while (*s++)
            ; /* determine total src string length */
    }

    return s - src - 1;

}


void icm_print_dev_info(ICM_DEV_INFO_T* pdev)
{
#ifdef ICM_RTR_DRIVER
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "server (built at %s %s)\n", __DATE__, __TIME__);
#endif /* ICM_RTR_DRIVER */
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "daemon                  : %s\n",
            (pdev->conf.daemon)?"enabled":"disabled");
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "server mode             : %s\n",
            (pdev->conf.server_mode)?"enabled":"disabled");
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "debug level             : %d\n", pdev->conf.dbg_level);
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "debug module bitmap     : 0x%x\n", pdev->conf.dbg_module_bitmap);
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "socket                  : %s\n",
            (CONFIGURED_SOCK_TYPE(pdev) == SOCK_TYPE_UDP)? "udp":"tcp");
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "rep Tx power policy     : %d\n", pdev->conf.rep_txpower_policy);
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "11ax U-NII-3 preference : %s\n",
            (pdev->conf.enable_11ax_unii3_pref) ? "enabled":"disabled");
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "Chan grade info usage   : %s\n",
            (pdev->conf.enable_chan_grade_usage) ? "enabled":"disabled");
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "Channel rejection mask  : 0x%llx\n", pdev->conf.rej_policy_bitmask);
    ICM_DPRINTF(pdev,
            ICM_PRCTRL_FLAG_NONE, ICM_DEBUG_LEVEL_MAJOR, ICM_MODULE_ID_UTIL,
            "Wireless Presence Factor: rssi [min: %d max: %d weightage: %0.2lf],"
            " bss [weightage: %0.2lf]\n", pdev->conf.min_rssi, pdev->conf.max_rssi,
            pdev->conf.rssi_weightage, pdev->conf.bss_count_weightage);
}

int icm_get_iface_addr(ICM_DEV_INFO_T* pdev, char* ifname, u_int8_t *ifaddr)
{
    ICM_IOCSOCK_T *iocinfo = ICM_GET_ADDR_OF_IOCSOCK_INFO(pdev);
    struct ifreq ifr;

    ifr.ifr_addr.sa_family = AF_INET;
    os_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(iocinfo->sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("icm : ioctl");
        return FAILURE;
    }

    memcpy(ifaddr, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);

    return SUCCESS;
}

int icm_phy_spec_to_str(ICM_PHY_SPEC_T physpec, char *str, int strbufflen)
{
    int status = FAILURE;

    if (str == NULL || strbufflen < ICM_PHY_SPEC_STR_SIZE) {
        return status;
    }

    switch(physpec)
    {
        case ICM_PHY_SPEC_11A:
            os_strlcpy(str, "11A", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11B:
            os_strlcpy(str, "11B", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11G:
            os_strlcpy(str, "11G", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_FH:
            os_strlcpy(str, "FH", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_TURBO_A:
            os_strlcpy(str, "TURBO A", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_TURBO_G:
            os_strlcpy(str, "TURBO G", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11NA:
            os_strlcpy(str, "11NA", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11NG:
            os_strlcpy(str, "11NG", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11AC:
            os_strlcpy(str, "11AC", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11AXA:
            os_strlcpy(str, "11AXA", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_11AXG:
            os_strlcpy(str, "11AXG", strbufflen);
            status = SUCCESS;
            break;

        case ICM_PHY_SPEC_ANY:
            os_strlcpy(str, "ANY", strbufflen);
            status = SUCCESS;
            break;

        default:
            os_strlcpy(str, "none", strbufflen);
            status = FAILURE;
            /* Failure */
            break;
    }
    return status;
}

int icm_ch_bw_to_str(ICM_CH_BW_T bw, char *str, int strbufflen)
{
    int status = FAILURE;

    if (str == NULL || strbufflen < ICM_MAX_CH_BW_STR_SIZE) {
        return status;
    }

    switch(bw)
    {
        case ICM_CH_BW_20:
            os_strlcpy(str, "20", strbufflen);
            status = SUCCESS;
            break;

        case ICM_CH_BW_40MINUS:
            os_strlcpy(str, "40MINUS", strbufflen);
            status = SUCCESS;
            break;

        case ICM_CH_BW_40PLUS:
            os_strlcpy(str, "40PLUS", strbufflen);
            status = SUCCESS;
            break;

        case ICM_CH_BW_40:
            os_strlcpy(str, "40", strbufflen);
            status = SUCCESS;
            break;

        case ICM_CH_BW_80:
            os_strlcpy(str, "80", strbufflen);
            status = SUCCESS;
            break;

        case ICM_CH_BW_160:
            os_strlcpy(str, "160", strbufflen);
            status = SUCCESS;
            break;

        case ICM_CH_BW_80_PLUS_80:
            os_strlcpy(str, "80+80", strbufflen);
            status = SUCCESS;
            break;

        default:
            os_strlcpy(str, "none", strbufflen);
            status = FAILURE;
            /* Failure */
            break;
    }
    return status;
}

/* XXX: Though the integer parameters we require as at present are all >=0,
   we should change the radio and vap get int function signatures
   below to factor in the fact that signed integers are being returned
   and error values shouldn't collide with valid param values. */

/*
 * Function     : get_radio_priv_int_param
 * Description  : Get a radio-private integer parameter
 * Input params : pointer to pdev info, radio interface name, required parameter,
 *                pointer to return value buffer
 * Return       : On success: 0
 *                On error  : -1
 */
int get_radio_priv_int_param(ICM_DEV_INFO_T* pdev, const char *ifname, int param,
                             int32_t *val)
{
    return icm_wal_get_radio_priv_int_param(pdev, ifname, param, val);
}

/*
 * Function     : set_radio_priv_int_param
 * Description  : set a radio-private integer parameter
 * Input params : pointer to pdev info, radio interface name, required parameter,
 *                value
 * Return       : On success: 0
 *                On error  : -1
 */
int set_radio_priv_int_param(ICM_DEV_INFO_T* pdev, const char *ifname, int param, int32_t val)
{
    return icm_wal_set_radio_priv_int_param(pdev, ifname, param, val);
}
/*
 * Function     : get_vap_priv_int_param
 * Description  : Return private parameter of the given VAP from driver.
 * Input params : const char pointer pointing to interface name and required parameter
 * Return       : Success: value of the private param
 *                Failure: -1
 *
 */
int get_vap_priv_int_param(ICM_DEV_INFO_T* pdev,
        const char *ifname,
        int param)
{
    return icm_wal_get_vap_priv_int_param(pdev, ifname, param);
}

/*
 * Function     : set_vap_priv_int_param
 * Description  : Set a device-private integer parameter
 * Input params : pointer to pdev info, device interface name, parameter,
 *                value.
 * Return       : On success: 0
 *                On error  : -1
 */
int set_vap_priv_int_param(ICM_DEV_INFO_T* pdev,
        const char *ifname,
        int param,
        int32_t val)
{
    return icm_wal_set_vap_priv_int_param(pdev, ifname, param, val);
}

#ifdef ICM_RTR_DRIVER
/*
 * Function     : is_11ac_offload
 * Description  : Return whether the radio referred to in picm
 *                is an 11ac offload radio.
 * Input params : Pointer to icm data structure
 * Return       : On success: 1 (Offload) or 0 (Direct Attach)
 *                On error  : -1
 */
int is_11ac_offload(ICM_INFO_T* picm)
{
    int32_t ret;

    get_radio_priv_int_param(get_pdev(),
            picm->radio_ifname,
            OL_ATH_PARAM_GET_IF_ID,
            &ret);

    return ret;
}

/*
 * Function     : is_emiwar80p80_enab
 * Description  : Return whether 80+80 EMI WAR is enabled
 * Input params : Pointer to icm data structure
 * Return       : On success: 1 (Enabled) or 0 (Not enabled)
 *                On error  : -1
 */
int is_emiwar80p80_enab(ICM_INFO_T* picm)
{
    int32_t ret;

    get_radio_priv_int_param(get_pdev(),
            picm->radio_ifname,
            OL_ATH_PARAM_EMIWAR_80P80,
            &ret);

    return ret;
}
#endif /* ICM_RTR_DRIVER */

/*
 * Function     : icm_compose_phymode_str
 * Description  : Compose complete PHY mode string from PHY Spec
 *                and channel width.
 * Input params : ICM enumeration for PHY Spec,
 *                ICM enumeration for Width,
 *                Address of char buffer into which string giving
 *                PHY mode should be passed, length of char buffer.
 * Return       : On success: String giving PHY mode. Uses address
 *                passed.
 *                On error  : NULL
 */
char* icm_compose_phymode_str(ICM_PHY_SPEC_T physpec,
        ICM_CH_BW_T width,
        char *phymode,
        int phymodelen)
{
    int cont = 0;  /* Whether to proceed to next step */

    if (phymode == NULL)
    {
        err("%s: NULL char buffer passed", __func__);
        return NULL;
    }

    if (phymodelen < ICM_MAX_PHYMODE_STR_SIZE) {
        err("%s: Insufficient char buffer length %d", __func__, phymodelen);
        return NULL;
    }

    memset(phymode, 0, phymodelen);

    /* Note:
       - We do not currently support "11AST"
       - 160 and 80+80 support not added since corresponding
       PHY mode strings not defined at this time. */

    switch(physpec)
    {
        case ICM_PHY_SPEC_11A:
            os_strlcpy(phymode, "11A", phymodelen);
            break;

        case ICM_PHY_SPEC_11B:
            os_strlcpy(phymode, "11B", phymodelen);
            break;

        case ICM_PHY_SPEC_11G:
            os_strlcpy(phymode, "11G", phymodelen);
            break;

        case ICM_PHY_SPEC_FH:
            os_strlcpy(phymode, "FH", phymodelen);
            break;

        case ICM_PHY_SPEC_TURBO_A:
            os_strlcpy(phymode, "TA", phymodelen);
            break;

        case ICM_PHY_SPEC_TURBO_G:
            os_strlcpy(phymode, "TG", phymodelen);
            break;

        case ICM_PHY_SPEC_11NA:
            cont = os_strlcpy(phymode, "11NAHT", phymodelen);
            break;

        case ICM_PHY_SPEC_11NG:
            cont = os_strlcpy(phymode, "11NGHT", phymodelen);
            break;

        case ICM_PHY_SPEC_11AC:
            cont = os_strlcpy(phymode, "11ACVHT", phymodelen);
            break;

        case ICM_PHY_SPEC_11AXA:
            cont = os_strlcpy(phymode, "11AHE", phymodelen);
            break;

        case ICM_PHY_SPEC_11AXG:
            cont = os_strlcpy(phymode, "11GHE", phymodelen);
            break;

        case ICM_PHY_SPEC_ANY:
            cont = os_strlcpy(phymode, "ANY", phymodelen);
            break;

        case ICM_PHY_SPEC_INVALID:
            err("%s: Invalid PHY spec enumeration %d", __func__, physpec);
            return NULL;
    }

    if (!cont) {
        return phymode;
    }

    switch (width)
    {
        case ICM_CH_BW_20:
            os_strlcpy(phymode + cont, "20", phymodelen - cont);
            break;

        case ICM_CH_BW_40MINUS:
            os_strlcpy(phymode + cont, "40MINUS", phymodelen - cont);
            break;

        case ICM_CH_BW_40PLUS:
            os_strlcpy(phymode + cont, "40PLUS", phymodelen - cont);
            break;

        case ICM_CH_BW_40:
            os_strlcpy(phymode + cont, "40", phymodelen - cont);
            break;

        case ICM_CH_BW_80:
            if ((physpec != ICM_PHY_SPEC_11AC) &&
                    (physpec != ICM_PHY_SPEC_11AXA)) {
                err("%s: Invalid PHY spec enumeration %d with width 80 MHz",
                        __func__,
                        physpec);
                return NULL;
            }
            os_strlcpy(phymode + cont, "80", phymodelen - cont);
            break;

        case ICM_CH_BW_160:
            if ((physpec != ICM_PHY_SPEC_11AC) &&
                    (physpec != ICM_PHY_SPEC_11AXA)) {
                err("%s: Invalid PHY spec enumeration %d with width 160 MHz",
                        __func__,
                        physpec);
                return NULL;
            }
            os_strlcpy(phymode + cont, "160", phymodelen - cont);
            break;

        case ICM_CH_BW_80_PLUS_80:
            if ((physpec != ICM_PHY_SPEC_11AC) &&
                    (physpec != ICM_PHY_SPEC_11AXA)) {
                err("%s: Invalid PHY spec enumeration %d with width 80+80 MHz",
                        __func__,
                        physpec);
                return NULL;
            }

            os_strlcpy(phymode + cont, "80_80", phymodelen - cont);
            break;

        case ICM_CH_BW_INVALID:
            err("%s: Invalid width enumeration %d", __func__, width);
            return NULL;
    }

    return phymode;
}

/*
 * Function     : icm_is_modulebitmap_valid
 * Description  : Determine if string giving module bitmap
 *                is valid. It is the caller's responsibility
 *                to ensure that the string is NULL terminated.
 * Input params : String giving module bitmap.
 * Return       : true if valid, false if invalid
 */
bool icm_is_modulebitmap_valid(const char* bitmapstr)
{
    long val = 0;

    val = strtol(bitmapstr, NULL, 0);

    if (errno != 0) {
        return false;
    }

    if (val < 0 || val > ICM_MODULE_ID_ALL) {
        return false;
    }

    return true;
}

/*
 * Function     : icm_is_debuglevel_valid
 * Description  : Determine if string giving debug level
 *                is valid. It is the caller's responsibility
 *                to ensure that the string is NULL terminated.
 * Input params : String giving debug level.
 * Return       : true if valid, false if invalid
 */
bool icm_is_debuglevel_valid(const char* dgblevelstr)
{
    long val = 0;

    val = strtol(dgblevelstr, NULL, 0);

    if (errno != 0) {
        return false;
    }

    if (val <= 0 || val >= ICM_DEBUG_LEVEL_INVALID) {
        return false;
    }

    return true;
}
/*
 * Function     : icm_is_walflag_valid
 * Description  : Determine if string giving walflag
 *                is valid. It is the caller's responsibility
 *                to ensure that the string is NULL terminated.
 * Input params : String giving walflag.
 * Return       : true if valid, false if invalid
 */
bool icm_is_walflag_valid(const char* walflagstr)
{
    long val = 0;

    val = strtol(walflagstr, NULL, 0);

    if (errno != 0) {
        return false;
    }

    if (val <= 0 || val >= ICM_WAL_INVALID) {
        return false;
    }

    return true;
}

/*
 * Function     : icm_is_numericalbool_valid
 * Description  : Determine if string is either 0 (for false) or 1 (for true).
 *                It is the caller's responsibility to ensure that the string is
 *                NULL terminated.
 * Input params : String giving numerical bool value
 * Return       : true if valid, false if invalid
 */
bool icm_is_numericalbool_valid(const char* numericalboolstr)
{
    long val = 0;

    val = strtol(numericalboolstr, NULL, 0);

    if (errno != 0) {
        return false;
    }

    if ((val != 0) && (val != 1)) {
        return false;
    }

    return true;
}

/*
 * Function     : icm_is_rep_txpower_policy_valid
 * Description  : Determine if string giving representative Tx power policy is
 *                valid. It is the caller's responsibility to ensure that the
 *                string is NULL terminated.
 * Input params : String giving representative Tx power policy.
 * Return       : true if valid, false if invalid
 */
bool icm_is_rep_txpower_policy_valid(const char* reptxpowerpolicystr)
{
    long val = 0;

    val = strtol(reptxpowerpolicystr, NULL, 0);

    if (errno != 0) {
        return false;
    }

    if ((val < 0) || val > (ICM_REP_TXPOWER_POLICY_MAX)) {
        return false;
    }

    return true;
}

#ifdef WLAN_SPECTRAL_ENABLE
/*
 * Function     : icm_get_channel_width
 * Description  : Get current channel width from driver
 * Input params : pointer to icm info structure
 * Return       : Channel width on success
 *                IEEE80211_CWM_WIDTHINVALID on failure
 */
enum ieee80211_cwm_width icm_get_channel_width(ICM_INFO_T* picm)
{
    return icm_wal_get_channel_width(picm);
}
#endif /* WLAN_SPECTRAL_ENABLE */

/*
 * Function     : icm_get_channel_index
 * Description  : Find index of a given channel, in channel list
 * Input params : -pointer to channel list
 *                -IEEE channel number for which the index is required. It is
 *                the responsibility of the calling function (or function stack)
 *                to ensure this is valid.
 * Return       : Index of channel in list on success, or -1 on failure.
 */
int icm_get_channel_index(ICM_CHANNEL_LIST_T *pchlist, u_int32_t channel)
{
    int chn_idx = 0;

    for(chn_idx = 0; (chn_idx < pchlist->count) && (chn_idx < MAX_NUM_CHANNEL); chn_idx++) {
        if (pchlist->ch[chn_idx].channel == channel) {
            return chn_idx;
        }
    }

    return -1;
}

/*
 * Function     : icm_get_pcl_adjusted_usability
 * Description  : Adjust usability based on PCL weights. If PCL doesn't contain
 *                channel then set usabilty to zero.
 * Input params : -pointer to global ICM structure.
 *                -channel number.
 *                -current usability value.
 * Return       : adjusted usability value.
 */
u16 icm_get_pcl_adjusted_usability(ICM_INFO_T* picm, int channel, u16 usability)
{
    u16 adjusted_usability = usability;
    int i;
    /* scale weight from 0 to (MAX_USABILITY/2), hence pcl has 50% weightage
     * and rest is decided based on environment factors (icm selection logic) */
    int scaling_factor = MAX_USABILITY / (2 * ICM_MAX_PCL_WEIGHT);

    if (picm && picm->pcl) {
        for (i = 0; i < picm->pcl->len; i++) {
            if (picm->pcl->list[i] == channel) {
                adjusted_usability = usability -
                                      (u16)((ICM_MAX_PCL_WEIGHT - picm->pcl->weight[i])
                                             * scaling_factor);
                break;
            }
        }
        /* If PCL list is set and doesn't contain current channel, set usability
         * assuming 0 pcl weight for this channel. i.e. 1/2 (usability) */
        if ((picm->pcl->len > 0) && (i == picm->pcl->len)) {
            adjusted_usability = usability -
                                  (u16)(ICM_MAX_PCL_WEIGHT * scaling_factor);
        }
    }
    return adjusted_usability;
}

/*
 * Function     : icm_is_chan_unii3
 * Description  : Check whether the channel is in the U-NII-3 band
 * Input params : Channel number, band
 * Return       : true if the channel is in the U-NII-3 band, false otherwise.
 */
bool icm_is_chan_unii3(int channel, ICM_BAND_T band)
{
    if (band != ICM_BAND_5G) {
        return false;
    }

    if ((channel == 149) || (channel == 153) || (channel == 157) ||
            (channel == 161) || (channel == 165)) {
        return true;
    } else {
        return false;
    }
}

#ifdef WLAN_SPECTRAL_ENABLE
/*
 * Function    : get_free_mem
 * Description : Get amount of free physical memory, in bytes.
 * Input       : Pointer into which the value for free physical memory in bytes
 *               should be populated - value is valid only on success.
 * Output      : 0 on success, -1 on failure
 */
int icm_get_free_mem(size_t *free_mem_bytes)
{
    FILE* fp = NULL;
    char line[256];
    size_t free_mem_kibibytes = 0;
    bool entry_found = false;

    ICM_ASSERT(free_mem_bytes != NULL);

    fp = fopen("/proc/meminfo", "r");

    if (NULL == fp) {
        perror("fopen");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemFree: %zu kB", &free_mem_kibibytes) == 1) {
            entry_found = true;
            break;
        }
    }

    fclose(fp);

    if (entry_found) {
        *free_mem_bytes = free_mem_kibibytes * 1024;
        return 0;
    } else {
        return -1;
    }
}
#endif /* WLAN_SPECTRAL_ENABLE */

#ifndef ICM_RTR_DRIVER
#include <android/log.h>
#endif

void icm_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
#ifndef ICM_RTR_DRIVER
     __android_log_vprint(ANDROID_LOG_INFO, "icm", fmt, ap);
#else
    vprintf(fmt, ap);
#endif
    va_end(ap);
}

/**
 * icm_android_log_helper: aprintf should add data to a buffer unless it finds
 *     line termination (\n) in input data. once \n is found, just flush data
 *      via icm_printf().
 */
void icm_android_log_helper(const char *fmt, ...)
{
#define MAX_PRINT_BUF 512
    static char buf[MAX_PRINT_BUF];
    static int buflen = 0;
    char t_buf[MAX_PRINT_BUF];
    int t_buflen;

    va_list ap;
    va_start(ap, fmt);
    t_buflen = vsnprintf(t_buf, MAX_PRINT_BUF, fmt, ap);
    va_end(ap);

    if ((t_buflen <= 0)  || (t_buflen >= MAX_PRINT_BUF))
    {
        fprintf(stderr,"vsnprintf failed, its return value is = %d",t_buflen);
        return;
    }

    // If size exceeds, flush the previous buffer first.
    if (buflen + t_buflen >= MAX_PRINT_BUF) {
        icm_printf(buf);
        buflen = 0;
    }

    // Apend to previous buffer.
    if (buflen) {
        buflen += os_strlcpy(buf + buflen, t_buf, MAX_PRINT_BUF - buflen);
    } else {
        buflen = os_strlcpy(buf, t_buf, MAX_PRINT_BUF);
    }

    // line terminator encountered, flush the buffer and reset buflen to 0
    if (NULL != strchr(buf, '\n')) {
        icm_printf(buf);
        buflen = 0;
    }
#undef MAX_PRINT_BUF
}

double icm_get_wpf(int rssi) {
    double weight = 0;
    ICM_DEV_INFO_T* pdev = get_pdev();
    ICM_CONFIG_T* pconf = &pdev->conf;

#ifdef ICM_RTR_DRIVER
    weight = pconf->rssi_weightage + pconf->bss_count_weightage;
#else
    double rssi_weight = 0;
    if (rssi < pconf->min_rssi) {
        weight = 0;
    } else if (rssi > pconf->max_rssi) {
        weight = (pconf->bss_count_weightage + pconf->rssi_weightage);
    } else {
        rssi_weight = pconf->rssi_weightage * \
          ((double)(rssi - pconf->min_rssi) / (double)(pconf->max_rssi - pconf->min_rssi));

        weight = pconf->bss_count_weightage + rssi_weight;
    }
#endif /* ICM_RTR_DRIVER */

    return weight;
}
