/*
 * Copyright (c) 2011,2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 *  Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 */

/*
 * Regulatory domain and DFS implementation
 */

#include <osdep.h>
#include <ieee80211_regdmn.h>
#include <ieee80211_channel.h>
#if UMAC_SUPPORT_CFG80211
#include <ieee80211_cfg80211.h>
#endif
#include <wlan_mlme_dispatcher.h>
#include <ieee80211_mlme_dfs_dispatcher.h>
#include <wlan_reg_ucfg_api.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <reg_services_public_struct.h>
#include <wlan_reg_services_api.h>
#include <ieee80211_mlme_priv.h>
#include <wlan_lmac_if_api.h>
#include "ieee80211_regdmn_dispatcher.h"
#include <wlan_reg_services_api.h>
#include <wlan_reg_channel_api.h>
#include <ol_if_athvar.h>

static int outdoor = FALSE;        /* enable outdoor use */
static int indoor  = FALSE;        /* enable indoor use  */

/* Difference between two channel numbers. Ex: 40 - 36 = 4 */
#define CHAN_DIFF    4
/* Size of triplets in the Country IE */
#define TRIPLET_SIZE 3

static int
ieee80211_set_countrycode(struct ieee80211com *ic, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd);
static void regdmn_populate_channel_list_from_map(regdmn_op_class_map_t *map,
                          u_int8_t reg_class, struct ieee80211_node *ni);
static void wlan_notify_country_changed(void *arg, wlan_if_t vap)
{
    char *country = (char*)arg;
    IEEE80211_DELIVER_EVENT_COUNTRY_CHANGE(vap, country);
}

int ieee80211_reg_program_opclass_tbl(struct ieee80211com *ic, uint8_t opclass)
{
    if (opclass > OPCLASS_TBL_MAX) {
        qdf_err("invalid opclass table index");
        return -EINVAL;
    }

    ic->ic_opclass_tbl_idx = opclass;
    return 0;
}
qdf_export_symbol(ieee80211_reg_program_opclass_tbl);

int ieee80211_reg_get_opclass_tbl(struct ieee80211com *ic, uint8_t *opclass)
{
    *opclass = ic->ic_opclass_tbl_idx;
    return 0;
}
qdf_export_symbol(ieee80211_reg_get_opclass_tbl);

int ieee80211_reg_program_cc(struct ieee80211com *ic,
        char *isoName, u_int16_t cc)
{
    struct cc_regdmn_s rd;

    qdf_mem_zero(&rd, sizeof(rd));

    rd.flags = INVALID_CC;
    if(isoName && isoName[0] && isoName[1]) {
        /* Map the ISO name ' ', 'I', 'O' */
        if (isoName[2] == 'O') {
            outdoor = true;
            indoor  = false;
            ic->ic_opclass_tbl_idx = 0;
        }
        else if (isoName[2] == 'I') {
            indoor  = true;
            outdoor = false;
            ic->ic_opclass_tbl_idx = 0;
        }
        else if ((isoName[2] == ' ') || (isoName[2] == 0)) {
            outdoor = false;
            indoor  = false;
            ic->ic_opclass_tbl_idx = 0;
        }
        else if ((isoName[2] >= '1') && (isoName[2] <= '9')) {
            outdoor = false;
            indoor  = false;
            ic->ic_opclass_tbl_idx = isoName[2] - '0';
            /* Convert ascii value to numeric one */
            isoName[2] = isoName[2] - '0';
        }
        rd.cc.alpha[0] = isoName[0];
        rd.cc.alpha[1] = isoName[1];
        rd.cc.alpha[2] = isoName[2];
        rd.flags = ALPHA_IS_SET;
    } else if (cc) {
        rd.cc.country_code = cc;
        rd.flags = CC_IS_SET;
    }

    return ieee80211_regdmn_program_cc(ic->ic_pdev_obj, &rd);
}
qdf_export_symbol(ieee80211_reg_program_cc);

/**
 * ieee80211_is_non_dfs_chans_available() - Compute the number of non-DFS.
 * channels available in the current regdomain.
 * @ic: Pointer to radio object.
 *
 * Return: Number of non-DFS channels.
 */
static int ieee80211_is_non_dfs_chans_available(struct ieee80211com *ic)
{
    int i, num_non_dfs_chans = 0;

    for (i = 0; i < ic->ic_nchans; i++) {
        if (!IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(&ic->ic_channels[i])) {
            num_non_dfs_chans++;
        }
    }
    return num_non_dfs_chans;
}

/*
 * Remove wireless mode flags from mode_select based on input phybitmap.
 * @mode_select: Pointer to mode_select.
 * @phybitmap: Phy bitmap retrieved from regulatory pdev_priv_obj.
 *
 */
static void
ieee80211_regdmn_remove_phybitmap_from_modeselect(uint32_t *mode_select,
                                                  uint16_t phybitmap)
{
    if (phybitmap & REGULATORY_PHYMODE_NO11AX) {
        *mode_select &= ~(WIRELESS_11AX_MODES);
    }

    if (phybitmap & REGULATORY_PHYMODE_NO11AC) {
        *mode_select &= ~(WIRELESS_11AC_MODES);
    }

    if (phybitmap & REGULATORY_CHAN_NO11N) {
        *mode_select &= ~(WIRELESS_11N_MODES);
    }

    if (phybitmap & REGULATORY_PHYMODE_NO11G) {
        *mode_select &= ~(WIRELESS_11G_MODES);
    }

    if (phybitmap & REGULATORY_PHYMODE_NO11B) {
        *mode_select &= ~(WIRELESS_11B_MODE);
    }

    if (phybitmap & REGULATORY_PHYMODE_NO11A) {
        *mode_select &= ~(WIRELESS_11A_MODE);
    }
}

int ieee80211_reg_get_current_chan_list(
        struct ieee80211com *ic,
        struct regulatory_channel *curr_chan_list)
{
    uint32_t num_chan;
    int i;
    int8_t max_tx_power = 0, min_tx_power = 0;
    uint32_t user_mode = 0, chip_mode, mode_select;
    uint16_t phybitmap;
    qdf_freq_t low_2g, high_2g, low_5g, high_5g;
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    uint8_t num_non_dfs_chans;
#endif
    if(ic->ic_get_modeSelect) {
        user_mode = ic->ic_get_modeSelect(ic);
    }

    ieee80211_regdmn_get_chip_mode(ic->ic_pdev_obj, &chip_mode);
    ieee80211_regdmn_get_freq_range(ic->ic_pdev_obj, &low_2g, &high_2g, &low_5g, &high_5g);

    mode_select = (user_mode & chip_mode);
    ieee80211_regdmn_get_phybitmap(ic->ic_pdev_obj, &phybitmap);
    ieee80211_regdmn_remove_phybitmap_from_modeselect(&mode_select, phybitmap);

    qdf_mem_zero(ic->ic_channels, sizeof(ic->ic_channels));

    regdmn_update_ic_channels(ic->ic_pdev_obj, ic,
            mode_select,
            curr_chan_list,
            ic->ic_channels,
            IEEE80211_CHAN_MAX,
            &num_chan,
            low_2g,
            high_2g,
            low_5g,
            high_5g);

#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    /* In case of scan failure event from FW due to dfs violation,
     * rebuilding channel list to have only non-DFS channel. If a regdomain
     * has only DFS channel, then bring down the vaps.
     */
    if (ic->ic_is_dfs_scan_violation) {
        num_non_dfs_chans = ieee80211_is_non_dfs_chans_available(ic);

        if (num_non_dfs_chans == 0) {
            ic->no_chans_available = 1;
            ieee80211_bringdown_vaps(ic);
            return -1;
        }
    }
#endif

    if (ic->ic_nchans == 0) {
        return -1;
    }

    if(ic->ic_get_min_and_max_power)
        ic->ic_get_min_and_max_power(ic, &max_tx_power, &min_tx_power);

    for (i = 0; i < ic->ic_nchans; i++) {
        ic->ic_channels[i].ic_maxpower = max_tx_power;
        ic->ic_channels[i].ic_minpower = min_tx_power;
    }

    if(ic->ic_fill_hal_chans_from_reg_db)
            ic->ic_fill_hal_chans_from_reg_db(ic);

    return 0;
}
qdf_export_symbol(ieee80211_reg_get_current_chan_list);

int ieee80211_reg_create_ieee_chan_list(
        struct ieee80211com *ic)
{
    struct regulatory_channel *curr_chan_list;
    int err;

    curr_chan_list = qdf_mem_malloc(NUM_CHANNELS*sizeof(struct regulatory_channel));
    if(curr_chan_list == NULL) {
        qdf_print("%s: fail to alloc", __func__);
        return -1;
    }

    ieee80211_regdmn_get_current_chan_list(ic->ic_pdev_obj, curr_chan_list);
    err = ieee80211_reg_get_current_chan_list(ic, curr_chan_list);
    qdf_mem_free(curr_chan_list);

    return err;
}
qdf_export_symbol(ieee80211_reg_create_ieee_chan_list);

/**
  * ieee80211_get_max5gbw() - Get maximum 5G bandwidth supported by
  * the country/regdomain
  * @ic: Pointer to ieee80211com structure
  *
  * Return : maximum 5G bandwidth supported or 0
  */

static uint16_t ieee80211_get_max5gbw(struct ieee80211com *ic)
{
    uint16_t cc, regdomain;
    uint16_t max_bw_5g = 0;

    cc = ieee80211_getCurrentCountry(ic);
    if (cc) {
       wlan_reg_get_max_5g_bw_from_country_code(cc, &max_bw_5g);
    } else {
       regdomain = ieee80211_get_regdomain(ic);
    if (regdomain) {
       wlan_reg_get_max_5g_bw_from_regdomain(regdomain,&max_bw_5g);
       }
    }

    return max_bw_5g;
}

uint16_t ieee80211_getCurrentCountry(struct ieee80211com *ic)
{
    struct cc_regdmn_s rd;

    qdf_mem_set(&rd, sizeof(struct cc_regdmn_s), 0);
    rd.flags = CC_IS_SET;
    ieee80211_regdmn_get_current_cc(ic->ic_pdev_obj, &rd);

    return rd.cc.country_code;
}
qdf_export_symbol(ieee80211_getCurrentCountry);

uint16_t ieee80211_getCurrentCountryISO(struct ieee80211com *ic, char *str)
{
    struct cc_regdmn_s rd;

    rd.flags = ALPHA_IS_SET;
    ieee80211_regdmn_get_current_cc(ic->ic_pdev_obj, &rd);
    qdf_mem_copy(str, rd.cc.alpha, sizeof(rd.cc.alpha));

    if (str[0] && str[1]) {
        if (outdoor)
            str[2] = 'O';
        else if (indoor)
            str[2] = 'I';
        else if (ic->ic_opclass_tbl_idx)
            str[2] = ic->ic_opclass_tbl_idx;
        else
            str[2] = ' ';
    }

    return 0;
}
qdf_export_symbol(ieee80211_getCurrentCountryISO);

uint32_t ieee80211_get_regdomain(struct ieee80211com *ic)
{
    struct cc_regdmn_s rd;
    uint32_t regdomain = 0;
    qdf_freq_t low_5g, high_5g;

    qdf_mem_set(&rd, sizeof(struct cc_regdmn_s), 0);
    rd.flags = REGDMN_IS_SET;
    ieee80211_regdmn_get_current_cc(ic->ic_pdev_obj, &rd);
    ieee80211_regdmn_get_freq_range(ic->ic_pdev_obj, NULL, NULL, &low_5g, &high_5g);

    REG_SET_BITS(regdomain, 0, 16, rd.cc.regdmn.reg_2g_5g_pair_id);
    if (wlan_reg_is_range_overlap_6g(low_5g, high_5g))
        REG_SET_BITS(regdomain, 16, 16, rd.cc.regdmn.sixg_superdmn_id);

    return regdomain;
}

qdf_export_symbol(ieee80211_get_regdomain);

/*
 * Set country code
 */
int
ieee80211_set_ctry_code(struct ieee80211com *ic, char *isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    int  error = 0;
    uint8_t ctry_iso[REG_ALPHA2_LEN + 1];

    ieee80211_getCurrentCountryISO(ic, ctry_iso);
    if (!cc) {
        if (isoName == NULL) {

        } else if((ctry_iso[0] == isoName[0]) &&
                (ctry_iso[1] == isoName[1]) &&
                (ctry_iso[2] == isoName[2])) {
            return 0;
        }
    }

    IEEE80211_DISABLE_11D(ic);

    error = ic->ic_set_country(ic, isoName, cc, cmd);

    return error;
}

int ieee80211_set_ctry_code_continue(struct ieee80211com *ic,
                             bool no_chanchange)
{
    uint8_t ctry_iso[REG_ALPHA2_LEN + 1];
    int err;
    struct wlan_objmgr_pdev *pdev;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_print("%s : pdev is null", __func__);
        return -1;
    }

    /* update the country information for 11D */
    ieee80211_getCurrentCountryISO(ic, ctry_iso);

    /* update channel list */
    err = ieee80211_update_channellist(ic, 1, no_chanchange);
    if (err)
        return err;

    ieee80211_build_countryie_all(ic, ctry_iso);

    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
        IEEE80211_ENABLE_11D(ic);
    }

    if (ic->ic_flags_ext2 & IEEE80211_FEXT2_RESET_PRECACLIST) {
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                QDF_STATUS_SUCCESS) {
            return -1;
        }

        mlme_dfs_reset_precaclists(pdev);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    }
    /* notify all vaps that the country changed */
    wlan_iterate_vap_list(ic, wlan_notify_country_changed, (void *)&ctry_iso);

    return 0;
}

int ieee80211_setctry_tryretaining_curchan(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
    uint16_t freq;
    uint64_t flags;
    uint16_t cfreq2;
    uint32_t mode;
    int32_t err = 0;
    struct ieee80211_ath_channel *new_chan;
    wlan_if_t tmpvap;

    freq = ieee80211_chan2freq(ic, chan);
    flags = chan->ic_flags;
    cfreq2 = chan->ic_vhtop_freq_seg2;
    mode = ieee80211_chan2mode(chan);

    /* Reset precac channel list when user changes the country code */
    ic->ic_flags_ext2 |= IEEE80211_FEXT2_RESET_PRECACLIST;
    err = ieee80211_set_ctry_code(ic, ic->ic_set_ctry_params->isoName, ic->ic_set_ctry_params->cc, ic->ic_set_ctry_params->cmd);
    if (err)
        return err;

    err = ieee80211_set_ctry_code_continue(ic, ic->ic_set_ctry_params->no_chanchange_during_cc);
    if (err)
        return err;

    if (!ic->ic_set_ctry_params->no_chanchange_during_cc){
        qdf_print("[%d] Skipping current channel retention during set_country operation", __LINE__);
        return EOK;
    }

    new_chan = ieee80211_find_channel(ic, freq, cfreq2, flags);
    if (new_chan == NULL) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL,
                IEEE80211_MSG_MLME,
                "Current channel not supported in new country. Configuring to a random channel\n");
        new_chan = ieee80211_find_dot11_channel(ic, 0, 0, mode);
        if (new_chan == NULL) {
            new_chan = ieee80211_find_dot11_channel(ic, 0, 0, 0);
            if(new_chan) {
                mode = ieee80211_chan2mode(new_chan);
                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    tmpvap->iv_des_mode = mode;
                    tmpvap->iv_des_hw_mode = mode;
                }
            }
        }
    }
    ieee80211_set_channel_for_cc_change(ic, new_chan);
    ic->ic_flags_ext2 &= ~IEEE80211_FEXT2_RESET_PRECACLIST;
    return 0;
}

int ieee80211_set_channel_for_cc_change(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
    wlan_if_t tmpvap;
    u_int8_t des_cfreq2;

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if(tmpvap) {
            if (chan) {
                if (ieee80211_chan2mode(chan) != tmpvap->iv_des_mode)
                     des_cfreq2 = tmpvap->iv_des_cfreq2;
                else
                     des_cfreq2 = chan->ic_vhtop_freq_seg2;
                wlan_set_channel(tmpvap, chan->ic_freq, des_cfreq2);
            } else {
                IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL,
                            IEEE80211_MSG_MLME,
                            "No valid channel to be selected in current country\n");
                return -EINVAL;
            }
        }
    }
         return 0;
 }

int
ieee80211_set_country_code(struct ieee80211com *ic, char *isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    struct ieee80211_ath_channel *chan;
    int ret;

    ic->ic_set_ctry_params = (struct ieee80211_set_country_params*)
        qdf_mem_malloc(sizeof(struct ieee80211_set_country_params));

    if (!ic->ic_set_ctry_params)
        return -ENOMEM;

    /* Store the set country parameters */
    ic->ic_set_ctry_params->cc = cc;
    if(isoName)
        qdf_mem_copy(ic->ic_set_ctry_params->isoName, isoName, REG_ALPHA2_LEN+1);
    ic->ic_set_ctry_params->cmd = cmd;
    chan = ieee80211_get_current_channel(ic);

    if (ieee80211_get_num_active_vaps(ic) != 0)
        ic->ic_set_ctry_params->no_chanchange_during_cc = true;

    /* Bring the vaps down, set the country and then bring the vaps up.*/
    ret = osif_restart_for_config(ic, ieee80211_setctry_tryretaining_curchan, chan);

    qdf_mem_free(ic->ic_set_ctry_params);
    return ret;
}

void ieee80211_set_country_code_assoc_sm(void *data)
{
    struct ieee80211com *ic = (struct ieee80211com *)data;
    struct assoc_sm_set_country *set_country = ic->set_country;
    struct ieee80211_node *ni = set_country->ni;
    struct ieee80211_mlme_priv    *mlme_priv = set_country->vap->iv_mlme_priv;

    if (ieee80211_set_ctry_code(ic, (char*)ni->ni_cc,
                set_country->cc, set_country->cmd) == 0) {
        if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT)
            ieee80211_ic_doth_set(ic);
    }

    OS_CANCEL_TIMER(&mlme_priv->im_timeout_timer);
    IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_SET_COUNTRY(set_country->vap, 0);
}

void
ieee80211_update_spectrumrequirement(struct ieee80211vap *vap,
        bool *thread_started)
{
    /*
     * 1. If not multiple-domain capable, check to update the country IE.
     * 2. If multiple-domain capable,
     *    a. If the country has been set by using desired country,
     *       then it is done, the ie has been updated.
     *       For IBSS or AP mode, if we are DFS owner, then need to enable Radar detect.
     *    b. If the country is not set, if no AP or peer country info,
     *       just assuming legancy mode.
     *       If we have AP or peer country info, using default to see if AP accept for now.
     */
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = vap->iv_bss;
    uint8_t ctry_iso[REG_ALPHA2_LEN + 1];

    if (!ieee80211_ic_2g_csa_is_set(vap->iv_ic))
        ieee80211_ic_doth_clear(ic);
    ieee80211_getCurrentCountryISO(ic, ctry_iso);

    if (ic->ic_country.isMultidomain == 0) {
        if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
            if (!IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
                ieee80211_build_countryie_all(ic, ctry_iso);
            }
            ieee80211_ic_doth_set(ic);
        }

        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_SET_COUNTRY(vap,0);
        return;
    }

    if (IEEE80211_HAS_DESIRED_COUNTRY(ic)) {
        /* If the country has been set, enabled the flag */
        if( (ctry_iso[0] == ni->ni_cc[0]) &&
            (ctry_iso[1] == ni->ni_cc[1]) &&
            (ctry_iso[2] == ni->ni_cc[2])) {
            if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
                ieee80211_ic_doth_set(ic);
            }

            IEEE80211_ENABLE_11D(ic);
            IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_SET_COUNTRY(vap,0);
            return;
        }
    }

    if ((ni->ni_cc[0] == 0)   ||
        (ni->ni_cc[1] == 0)   ||
        (ni->ni_cc[0] == ' ') ||
        (ni->ni_cc[1] == ' ')) {
        if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
            ieee80211_ic_doth_set(ic);
        }

        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_SET_COUNTRY(vap,0);
        return;
    }

    // Update the cc only for platforms that request this : Currently, only Windows.
    if (ieee80211_ic_disallowAutoCCchange_is_set(ic)) {
        if ((ni->ni_cc[0] == ctry_iso[0] &&
             ni->ni_cc[1] == ctry_iso[1] &&
             ni->ni_cc[2] == ctry_iso[2]))
        {
            ieee80211_build_countryie_all(ic, ctry_iso);
            if (ni->ni_capinfo & IEEE80211_CAPINFO_SPECTRUM_MGMT) {
                ieee80211_ic_doth_set(ic);
            }
        }

        IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_SET_COUNTRY(vap,0);
    }
    else {
        // If ignore11dBeacon, using the original reg. domain setting.
        if (!IEEE80211_IS_11D_BEACON_IGNORED(ic)) {
            ic->set_country->cc = 0;
            ic->set_country->cmd = CLIST_UPDATE;
            ic->set_country->ni = ni;
            ic->set_country->vap = vap;
            qdf_sched_work(NULL, &ic->assoc_sm_set_country_code);
            *thread_started = true;
        } else {
            /* Post an event to move to next state. */
            IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_SET_COUNTRY(vap,0);
        }
    }
}

void
ieee80211_set_regclassids(struct ieee80211com *ic, const u_int8_t *regclassids, u_int nregclass)
{
    int i;

    if (nregclass >= IEEE80211_REGCLASSIDS_MAX)
        nregclass = IEEE80211_REGCLASSIDS_MAX;

    ic->ic_nregclass = nregclass;

    for (i = 0; i < nregclass; i++)
        ic->ic_regclassids[i] = regclassids[i];
}

#ifdef BEACON_CHANLIST_COMPRESSION
bool
ieee80211_chanlist_compression_possible(struct regulatory_channel *curchan,
                                        u_int8_t prevchan,
                                        struct country_ie_triplet *pTriplet)
{
    bool cmp_possible = false;
    uint8_t chan_ieee_separation;

    if (wlan_reg_is_24ghz_ch_freq(curchan->center_freq)) {
        chan_ieee_separation = 1;
        if ((curchan->chan_num == prevchan + chan_ieee_separation) &&
            (pTriplet->maxtxpwr == curchan->tx_power))
            cmp_possible = true;
    } else if (wlan_reg_is_5ghz_ch_freq(curchan->center_freq) ||
               wlan_reg_is_6ghz_chan_freq(curchan->center_freq)) {
        if (WLAN_REG_IS_49GHZ_FREQ(curchan->center_freq)) {
            chan_ieee_separation = 1;
            if ((curchan->chan_num == prevchan + chan_ieee_separation) &&
                (pTriplet->maxtxpwr == curchan->tx_power))
                cmp_possible = true;
        } else {
            chan_ieee_separation = 4;
            if ((curchan->chan_num == prevchan + chan_ieee_separation) &&
                (pTriplet->maxtxpwr == curchan->tx_power))
                cmp_possible = true;
        }
    }
    return cmp_possible;
}
#endif

#ifdef CONFIG_BAND_6GHZ
/**
 * ieee80211_set_6G_opclass_triplets() - Set ic_enable_additional_triplets with the input max_bw.
 * @ic: Pointer to ic.
 * @max_bw: Maximum bandwidth.
 *
 * Return: QDF_STATUS
 */
QDF_STATUS ieee80211_set_6G_opclass_triplets(struct ieee80211com *ic,
                                             uint16_t max_bw)
{
   if ((max_bw != BW_20_MHZ) && (max_bw != BW_40_MHZ) &&
       (max_bw != BW_80_MHZ) && (max_bw != BW_160_MHZ))
       return QDF_STATUS_E_FAILURE;

   ic->ic_enable_additional_triplets = max_bw;

   return QDF_STATUS_SUCCESS;
}

/**
 * ieee80211_add_additional_triplets() - Increment num_opclass based on the
 * value present in ic_enable_additional_triplets, to enable additional
 * operating triplets in the country IE.
 * @ic: Pointer to ic.
 * @num_opclass: Pointer to num_opclass.
 *
 * Return: void
 */
static void ieee80211_add_additional_triplets(struct ieee80211com *ic,
                                              uint8_t *num_opclass)
{
   switch(ic->ic_enable_additional_triplets) {
          case 0:
          case BW_20_MHZ:
                         break;
          case BW_40_MHZ:
                         /* Since opclass 132 appears twice in the array "sixg_opclss_arr",
                          * (First time for IEEE80211_MODE_11AXA_HE40PLUS  and second time
                          * for IEEE80211_MODE_11AXA_HE40MINUS) if the device supports both
			  * 40+ and 40-, the opclass will appear twice in the country IE.
			  * To avoid that, increment *num_opclass by 2, to add 132 only once.
                          */
                         *num_opclass += 2;
                         break;
          case BW_80_MHZ:
                         *num_opclass += 3;
                         break;
          case BW_160_MHZ:
                          *num_opclass += 4;
                          break;
          default:
                  qdf_debug("%d is an invalid input bandwidth",
                            ic->ic_enable_additional_triplets);
                  break;
   }
}

/* For a given chan_width, provide the next higher chan_width */
static const enum phy_ch_width next_higher_bw[] = {
    [CH_WIDTH_20MHZ] = CH_WIDTH_40MHZ,
    [CH_WIDTH_40MHZ] = CH_WIDTH_80MHZ,
    [CH_WIDTH_80MHZ] = CH_WIDTH_160MHZ,
    [CH_WIDTH_160MHZ] = CH_WIDTH_80P80MHZ,
    [CH_WIDTH_80P80MHZ] = CH_WIDTH_INVALID
};

/** ieee82011_get_num_pwr_levels() - Find the number of subchannels in a channel
 *  based on the input channel frequency and channel width.
 *  @pdev - Pointer to pdev.
 *  @freq - Channel frequency in MHz.
 *  @ch_width - Channel width.
 */
static uint8_t ieee82011_get_num_pwr_levels(struct wlan_objmgr_pdev *pdev,
                                            qdf_freq_t freq,
                                            enum ieee80211_cwm_width ch_width)
{
    uint8_t num_pwr_levels;

    if (wlan_reg_is_6g_psd_power(pdev)) {
        switch (ch_width) {
                case IEEE80211_CWM_WIDTH20:
                     num_pwr_levels = 1;
                     break;
                case IEEE80211_CWM_WIDTH40:
                     num_pwr_levels = 2;
                      break;
                case IEEE80211_CWM_WIDTH80:
                     num_pwr_levels = 4;
                     break;
                case IEEE80211_CWM_WIDTH160:
                case IEEE80211_CWM_WIDTH80_80:
                     num_pwr_levels = 8;
                     break;
                default:
                     return 1;
         }
     } else {
        switch (ch_width) {
                case IEEE80211_CWM_WIDTH20:
                     num_pwr_levels = 1;
                     break;
                case IEEE80211_CWM_WIDTH40:
                     num_pwr_levels = 2;
                     break;
                case IEEE80211_CWM_WIDTH80:
                     num_pwr_levels = 3;
                           break;
                case IEEE80211_CWM_WIDTH160:
                case IEEE80211_CWM_WIDTH80_80:
                     num_pwr_levels = 4;
                     break;
                default:
                     return 1;
       }
     }

     return num_pwr_levels;
}

void ieee80211_send_tpc_power_cmd(struct ieee80211vap *vap)
{
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_reg_tx_ops *tx_ops;

    psoc = wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj);
    tx_ops = wlan_reg_get_tx_ops(psoc);

    if (!tx_ops || !tx_ops->set_tpc_power) {
        qdf_err("No regulatory tx_ops");
        return;
    }

    ieee80211_fill_reg_tpc_obj(vap);
    tx_ops->set_tpc_power(psoc, vap->vdev_obj->vdev_objmgr.vdev_id,
                          &vap->vdev_mlme->reg_tpc_obj);
}

/* ieee80211_get_tpc_reg_power() - Fill the members reg_tpc_obj object that is
 * sent to the FW through the WMI_SET_TPC_POWER_CMDID.
 * @vap - Pointer to vap.
 * @reg_tpc_objp - Pointer to reg_tpc_obj.
 * @ap_power_type_6g - 6G AP power type.
 * @cur_freq - Current operating frequency.
 * @start_freq - Center frequency of the first sub-channelin the current
 * operating channel.
 */
static void ieee80211_get_tpc_reg_power(struct ieee80211vap *vap,
                                        struct reg_tpc_power_info *reg_tpc_objp,
                                        enum reg_6g_ap_type ap_power_type_6g,
                                        qdf_freq_t cur_freq,
                                        qdf_freq_t start_freq)
{
   uint8_t count;
   int8_t tpe_tx_pwr;
   enum QDF_OPMODE opmode;
   int8_t max_tx_power[MAX_PSD_VALS];
   struct ch_params ch_params;
   uint8_t num_pwr_levels;
   bool is_psd_power;
   uint16_t reg_tx_pwr = 0, reg_eirp_pwr = 0;
   qdf_freq_t center_freq;
   struct wlan_objmgr_pdev *pdev = vap->iv_ic->ic_pdev_obj;

   num_pwr_levels = reg_tpc_objp->num_pwr_levels;
   opmode = wlan_vdev_mlme_get_opmode(vap->vdev_obj);
   ch_params.ch_width = CH_WIDTH_20MHZ;

   for (count = 0; count < num_pwr_levels; count++) {
        if (opmode == QDF_STA_MODE) {
            struct ieee80211_node *ni = vap->iv_bss;

            if (ni == NULL) {
                qdf_err("ni is NULL");
                return;
            }

            wlan_reg_get_client_power_for_connecting_ap(pdev, ap_power_type_6g,
                                                        start_freq + BW_20_MHZ *
                                                        count, &is_psd_power,
                                                        &reg_tx_pwr, &reg_eirp_pwr);
            /** If the opmode is STA, then take the minimum of the power
             *  received in the TPE, and the regulatory max power.
             */
            tpe_tx_pwr = (is_psd_power ? ni->ni_eirppsd_limit[count] :
                     ni->ni_eirp_limit[count]);
            max_tx_power[count] = QDF_MIN(reg_tx_pwr, tpe_tx_pwr);
        } else {
            wlan_reg_get_6g_chan_ap_power(pdev, start_freq + BW_20_MHZ *
                                          count, &is_psd_power, &reg_tx_pwr,
                                          &reg_eirp_pwr);
            max_tx_power[count] = reg_tx_pwr;
        }

        if (is_psd_power) {
            center_freq = cur_freq + (BW_20_MHZ * count);
        } else {
            wlan_reg_set_channel_params_for_freq(pdev, cur_freq, 0, &ch_params);
            center_freq = ch_params.mhz_freq_seg0;
            if (next_higher_bw[ch_params.ch_width] == CH_WIDTH_INVALID)
                break;

            ch_params.ch_width = next_higher_bw[ch_params.ch_width];
        }

        reg_tpc_objp->chan_power_info[count].chan_cfreq = center_freq;
        reg_tpc_objp->chan_power_info[count].tx_power = max_tx_power[count];
   }

   reg_tpc_objp->eirp_power = reg_eirp_pwr;
}

void ieee80211_fill_reg_tpc_obj(struct ieee80211vap *vap)
{
   enum reg_6g_ap_type ap_power_type_6g;
   struct wlan_objmgr_pdev *pdev = vap->iv_ic->ic_pdev_obj;
   const struct bonded_channel_freq *bonded_chan_ptr = NULL;
   qdf_freq_t start_freq, freq;
   struct vdev_mlme_obj *vdev_mlme;
   struct reg_tpc_power_info *reg_tpc_objp;
   uint8_t chwidth;

   vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vap->vdev_obj);
   if (!vdev_mlme)
       return;

   reg_tpc_objp = &vdev_mlme->reg_tpc_obj;
   freq = vap->iv_bsschan->ic_freq;
   chwidth = wlan_vdev_get_chwidth(vap->vdev_obj);
   ucfg_reg_get_cur_6g_ap_pwr_type(pdev, &ap_power_type_6g);
   reg_tpc_objp->power_type_6g = ap_power_type_6g;
   reg_tpc_objp->is_psd_power = wlan_reg_is_6g_psd_power(pdev);
   reg_tpc_objp->num_pwr_levels =
                  ieee82011_get_num_pwr_levels(pdev, freq, chwidth);

   wlan_reg_get_5g_bonded_channel_and_state_for_freq(pdev, freq, chwidth,
                                                     &bonded_chan_ptr);
   start_freq = bonded_chan_ptr ? bonded_chan_ptr->start_freq : freq;
   ieee80211_get_tpc_reg_power(vap, reg_tpc_objp,
                               ap_power_type_6g, freq, start_freq);
}

/**
 * ieee80211_fill_20mhz_6gsubband_triplets() - Fill 6G subband triplets for 20mhz opclass.
 * @vap: Pointer to vap.
 * @pTriplet: Pointer to *pTriplet.
 *
 * Return: void
 */
static void
ieee80211_fill_20mhz_6gsubband_triplets(struct ieee80211vap *vap,
                                        struct country_ie_triplet **pTriplet)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct country_ie_triplet *sixg_pTriplet;
    struct regulatory_channel *chan_list_6g;
    uint8_t j;
    bool isnewband = true;
    uint8_t curchan, prevchan, num_6g_channels;

    chan_list_6g = qdf_mem_malloc(NUM_6GHZ_CHANNELS *
                                  sizeof(struct regulatory_channel));
    if (!chan_list_6g)
        return;

    num_6g_channels = wlan_reg_get_band_channel_list(ic->ic_pdev_obj,
                                                     BIT(REG_BAND_6G),
                                                     chan_list_6g);

    if (num_6g_channels > NUM_6GHZ_CHANNELS)
        num_6g_channels = NUM_6GHZ_CHANNELS;

    for (j = 0; j < num_6g_channels; j++) {
         curchan = chan_list_6g[j].chan_num;
         if (isnewband) {
             isnewband = false;
             sixg_pTriplet = (*pTriplet)++;
	 } else if (curchan == (prevchan + CHAN_DIFF)) {
             sixg_pTriplet->nchan++;
             prevchan = curchan;
             continue;
         } else {
             sixg_pTriplet = (*pTriplet)++;
         }

         prevchan = curchan;
         sixg_pTriplet->schan = curchan;
         sixg_pTriplet->nchan = 1;
         /* "The Maximum Transmit Power Level field is reserved if it
          * is within an Operating/Subband Sequence field with the
          * Operating class for which the Channel starting frequency
          * (GHz) column in Table E-4 is greater than or
          * equal to 5.925 and less than or equal to 7.125"
          */
         sixg_pTriplet->maxtxpwr = 0;
         vap->iv_country_ie_data.country_len += TRIPLET_SIZE;
    }

    qdf_mem_free(chan_list_6g);

}

/**
 * ieee80211_fill_country_ie_for_6g() - Fill Country IE for the 6G channels.
 * @vap: Pointer to vap.
 * @pTriplet: Pointer to *pTriplet.
 *
 * Return: Void
 */
static void
ieee80211_fill_country_ie_for_6g(struct ieee80211vap *vap,
                                 struct country_ie_triplet **pTriplet)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct country_ie_triplet *sixg_pTriplet;
    uint8_t i;
    const u_int8_t sixg_opclss_arr[][2] = {{131, IEEE80211_MODE_11AXA_HE20},
                                           {132, IEEE80211_MODE_11AXA_HE40PLUS},
                                           {132, IEEE80211_MODE_11AXA_HE40MINUS},
                                           {133, IEEE80211_MODE_11AXA_HE80},
                                           {134, IEEE80211_MODE_11AXA_HE160} };
    /* By default (if not enabled) only 20Mhz opclass will be present */
    uint8_t num_opclass = 1;

   /* Rule-1 :- No regular Subband Triplet
    * When the Country element is included in a frame transmitted in the
    * 6 GHz band, the Triplet field is composed of zero subband Triplet
    * fields, and only has one or more Operating/subband Sequences.
    *
    * Rule-2: Fill Operating/Subband Sequences for 6g
    * Fill Operating/Subband Sequences for every BW 20/40/80/80+80/160
    * Fill for 20 Operating Triplet+Subband Triplet sequences
    * OP_EXT_ID can be anything greater than 200 and lesser than or equal to 23
    */
#define OP_EXT_ID    201

    ieee80211_add_additional_triplets(ic, &num_opclass);

    /* Fill for 20/40/80/160 */
    for (i = 0; i < num_opclass; i++) {
         if (IEEE80211_SUPPORT_PHY_MODE(ic, sixg_opclss_arr[i][1])) {
             sixg_pTriplet = (*pTriplet)++;
             sixg_pTriplet->regextid = OP_EXT_ID;
             sixg_pTriplet->regclass = sixg_opclss_arr[i][0];
             sixg_pTriplet->coverageclass = 0;
             vap->iv_country_ie_data.country_len += TRIPLET_SIZE;
             /* Since opclass 132 appear twice in the array "sixg_opclss_arr"
              * (First time for IEEE80211_MODE_11AXA_HE40PLUS  and second time
              * for IEEE80211_MODE_11AXA_HE40MINUS) appear twice in the array,
              * if the device supports both 40+ and 40-, the opclass will
              * appear twice in the country IE. To avoid that do not add 132
              * if it is already added.
              */
             if (ieee80211_is_phymode_11axa_he40plus(sixg_opclss_arr[i][1])) {
                 /* if  132 already added do not add it again */
                 i = i + 1;
             }

             /* Subband Triplet sequences is mandatory only for 20 MHz */
             if (i == 0)
                 ieee80211_fill_20mhz_6gsubband_triplets(vap, pTriplet);

         }
    }

}
#endif

static bool ieee80211_regdmn_check_weather_radar_channel(qdf_freq_t freq)
{
    return ((freq >= 5600) && (freq <= 5640));
}

/*
 * Build the country information element.
 */
void
ieee80211_build_countryie(struct ieee80211vap *vap, uint8_t *country_iso)
{
    struct country_ie_triplet *pTriplet;
    struct country_ie_triplet *first_pTriplet;
    struct regulatory_channel *cur_chan_list;
    int i, isnewband;
    u_int64_t chanflags = 0;
    u_int8_t prevchan;
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t dfs_reg = 0;
    qdf_freq_t low_2g, high_2g, low_5g, high_5g;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_print("%s : pdev is null", __func__);
        return;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (psoc == NULL) {
        qdf_print("%s : psoc is null", __func__);
        return;
    }

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
    if (reg_rx_ops == NULL) {
        qdf_err("%s : rx_ops is null", __func__);
        return;
    }
    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
            QDF_STATUS_SUCCESS) {
        return;
    }
    reg_rx_ops->get_dfs_region(pdev, &dfs_reg);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);

    if (!country_iso[0] || !country_iso[1] || !country_iso[2]) {
        /* Default, no country is set */
        vap->iv_country_ie_data.country_len = 0;
        IEEE80211_DISABLE_COUNTRYIE(ic);
        return;
    }

    IEEE80211_ENABLE_COUNTRYIE(ic);

    /*
     * Construct the country IE:
     * 1. The country string come first.
     * 2. Then construct the channel triplets from lowest channel to highest channel.
     * 3. If we support the regulatory domain class (802.11J)
     *    then add the class triplets before the channel triplets of each band.
     */
    OS_MEMZERO(&vap->iv_country_ie_data, sizeof(vap->iv_country_ie_data));
    vap->iv_country_ie_data.country_id = IEEE80211_ELEMID_COUNTRY;
    vap->iv_country_ie_data.country_len = 3;

    vap->iv_country_ie_data.country_str[0] = country_iso[0];
    vap->iv_country_ie_data.country_str[1] = country_iso[1];
    vap->iv_country_ie_data.country_str[2] = country_iso[2];

    if (wlan_reg_is_6ghz_chan_freq(ic->ic_curchan->ic_freq)) {
        ic->ic_opclass_tbl_idx = OPCLS_TAB_IDX_GLOBAL;
        vap->iv_country_ie_data.country_str[2] = ic->ic_opclass_tbl_idx;
    }

    pTriplet = (struct country_ie_triplet*)&vap->iv_country_ie_data.country_triplet;
    first_pTriplet = pTriplet;
    ieee80211_regdmn_get_freq_range(ic->ic_pdev_obj, &low_2g, &high_2g,
                                    &low_5g, &high_5g);
    if (wlan_reg_is_range_overlap_2g(low_2g, high_2g))
        chanflags |= IEEE80211_CHAN_2GHZ;
#ifdef CONFIG_BAND_6GHZ
    if (wlan_reg_is_range_overlap_6g(low_5g, high_5g))
        chanflags |= IEEE80211_CHAN_6GHZ;
#endif
    if (wlan_reg_is_range_overlap_5g(low_5g, high_5g))
        chanflags |= IEEE80211_CHAN_5GHZ;

    vap->iv_country_ie_chanflags = chanflags;

    prevchan = 0;
    isnewband = 1;
    cur_chan_list = qdf_mem_malloc(NUM_CHANNELS * sizeof(*cur_chan_list));
    if (!cur_chan_list) {
        /* Default, no country is set */
        vap->iv_country_ie_data.country_len = 0;
        IEEE80211_DISABLE_COUNTRYIE(ic);
        return;
   }

   if (wlan_reg_get_current_chan_list(ic->ic_pdev_obj, cur_chan_list) !=
       QDF_STATUS_SUCCESS) {
       qdf_err("Failed to get cur_chan list");
       vap->iv_country_ie_data.country_len = 0;
       IEEE80211_DISABLE_COUNTRYIE(ic);
       qdf_mem_free(cur_chan_list);
       return;
   }

   for (i = 0; i < NUM_CHANNELS; i++) {
        if (wlan_reg_is_chan_disabled(&cur_chan_list[i]))
                continue;
       /* We assume the following sequence in the channel list:
        * |All 2.4Ghz channels| |All 5Ghz channels| |All 6Ghz channels|
        */
#ifdef CONFIG_BAND_6GHZ
        if (wlan_reg_is_6ghz_chan_freq(cur_chan_list[i].center_freq))
            break;
#endif
        if (ic->ic_no_weather_radar_chan &&
            (ieee80211_regdmn_check_weather_radar_channel(cur_chan_list[i].center_freq))
                && (DFS_ETSI_DOMAIN  == dfs_reg))
        {
            /* skipping advertising weather radar channels */
            continue;
        }

        if (isnewband) {
            isnewband = 0;
#ifdef BEACON_CHANLIST_COMPRESSION
        } else if (ieee80211_chanlist_compression_possible(&cur_chan_list[i],
                                                           prevchan,
                                                           pTriplet))
        {
            pTriplet->nchan++;
            prevchan = cur_chan_list[i].chan_num;
            continue;
#else
        } else if ((pTriplet->maxtxpwr == cur_chan_list[i].tx_power) &&
                   (cur_chan_list[i].chan_num == prevchan + 1)) {
            pTriplet->nchan++;
            prevchan = cur_chan_list[i].chan_num;
            continue;
#endif
        } else {
            pTriplet++;
        }

        prevchan = cur_chan_list[i].chan_num;
        pTriplet->schan = cur_chan_list[i].chan_num;
        pTriplet->nchan = 1; /* init as 1 channel */
        pTriplet->maxtxpwr = cur_chan_list[i].tx_power;
        vap->iv_country_ie_data.country_len += TRIPLET_SIZE;
    }
#ifdef CONFIG_BAND_6GHZ
    if (IEEE80211_IS_FLAG_6GHZ(chanflags)) {
        if (first_pTriplet != pTriplet)
            pTriplet++;

        ieee80211_fill_country_ie_for_6g(vap, &pTriplet);
    }
#endif
    /* pad */
    if (vap->iv_country_ie_data.country_len & 1) {
        vap->iv_country_ie_data.country_triplet[vap->iv_country_ie_data.country_len] = 0;
        vap->iv_country_ie_data.country_len++;
    }

    qdf_mem_free(cur_chan_list);
}

static void
ieee80211_build_countryie_vap(uint8_t *ctry_iso, struct ieee80211vap *vap, bool is_last_vap)
{
    if (IEEE80211_IS_COUNTRYIE_ENABLED(vap->iv_ic) &&
        ieee80211_vap_country_ie_is_set(vap)) {
        ieee80211_build_countryie(vap, ctry_iso);
    }
}

/*
* update the country ie in all vaps.
*/
void
ieee80211_build_countryie_all(struct ieee80211com *ic, uint8_t *ctry_iso)
{
    u_int8_t num_vaps;
    ieee80211_iterate_vap_list_internal(ic,ieee80211_build_countryie_vap,(void *)ctry_iso,num_vaps);
}
qdf_export_symbol(ieee80211_build_countryie_all);

static int
ieee80211_set_countrycode(struct ieee80211com *ic, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    struct ol_ath_softc_net80211 *scn;

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (ieee80211_set_country_code(ic, isoName, cc, cmd)) {
        IEEE80211_CLEAR_DESIRED_COUNTRY(ic);
        return -EINVAL;
    }

    if (!cc) {
        if ((isoName == NULL) || (isoName[0] == '\0') || (isoName[1] == '\0')) {
            IEEE80211_CLEAR_DESIRED_COUNTRY(ic);
        } else {
            IEEE80211_SET_DESIRED_COUNTRY(ic);
        }
    } else {
        IEEE80211_SET_DESIRED_COUNTRY(ic);
    }
#if UMAC_SUPPORT_CFG80211
    wlan_cfg80211_update_channel_list(ic);
#endif

    if (wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj, WLAN_SOC_F_STRICT_CHANNEL)) {
        wlan_if_t tmpvap;
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            if(tmpvap) {
                struct net_device *tmpdev;
                tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                if (!IS_UP(tmpdev)) {
                    IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(tmpvap, tmpvap->iv_des_chan[tmpvap->iv_des_mode]);
                }
            }
        }
    }

    return 0;
}

int
ieee80211_regdmn_reset(struct ieee80211com *ic)
{
    char cc[3];

    /* Reset to default country if any. */
    cc[0] = cc[1] = cc[2] = 0;
    ieee80211_set_countrycode(ic, cc, 0, CLIST_UPDATE);
    ic->ic_multiDomainEnabled = 0;

    return 0;
}


int
wlan_set_countrycode(wlan_dev_t devhandle, char isoName[3], u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    return ieee80211_set_countrycode(devhandle, isoName, cc, cmd);
}

u_int16_t
wlan_get_regdomain(wlan_dev_t devhandle)
{
    return devhandle->ic_country.regDmnEnum;
}

int
wlan_set_regdomain(wlan_dev_t devhandle, uint32_t regdmn)
{
    struct ieee80211com *ic = devhandle;
    struct cc_regdmn_s rd;

    rd.cc.regdmn.reg_2g_5g_pair_id = REG_GET_BITS(regdmn, 0, 16);
    rd.cc.regdmn.sixg_superdmn_id = REG_GET_BITS(regdmn, 16, 16);
    rd.flags = REGDMN_IS_SET;

    return ieee80211_regdmn_program_cc(ic->ic_pdev_obj, &rd);
}

u_int8_t
wlan_get_ctl_by_country(wlan_dev_t devhandle, u_int8_t *country, bool is2G)
{
    struct ieee80211com *ic = devhandle;
    return ic->ic_get_ctl_by_country(ic, country, is2G);
}

/* Global operating classes */
regdmn_op_class_map_t global_operating_class[] = {
    {81,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {82,  IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {14}},
    {83,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {1, 2, 3, 4, 5, 6, 7, 8, 9}},
    {84,  IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {5, 6, 7, 8, 9, 10, 11, 12, 13}},
    {115, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48}},
    {116, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {36, 44}},
    {117, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {40, 48}},
    {118, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {52, 56, 60, 64}},
    {119, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {52, 60}},
    {120, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {56, 64}},
    {121, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}},
    {122, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {100, 108, 116, 124, 132, 140}},
    {123, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {104, 112, 120, 128, 136, 144}},
    {125, IEEE80211_CWM_WIDTH20, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {149, 153, 157, 161, 165, 169}},
    {126, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCA,
          {149, 157}},
    {127, IEEE80211_CWM_WIDTH40, IEEE80211_SEC_CHAN_OFFSET_SCB,
          {153, 161}},
    {128, IEEE80211_CWM_WIDTH80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
           132, 136, 140, 144, 149, 153, 157, 161}},
    {129, IEEE80211_CWM_WIDTH160, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}},
    {130, IEEE80211_CWM_WIDTH80_80, IEEE80211_SEC_CHAN_OFFSET_SCN,
          {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
           132, 136, 140, 144, 149, 153, 157, 161}},
    {0, 0, 0, {0}},
};

/**
 * regdmn_get_supp_opclass_list - Get the maximum txpower of the current operating channel.
 * @pdev - Pointer to pdev.
 *
 * Return - return the 2's complement of maximum tx power of the current operating channel.
 */
int regdmn_get_current_chan_txpower(struct wlan_objmgr_pdev *pdev)
{
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev);

   if (ic == NULL) {
       qdf_err("ic is NULL");
       return -EINVAL;
   }

    return ~(wlan_channel_maxpower(ic->ic_curchan)) + 1;
}

/**
 * regdmn_get_supp_opclass_list - Get the current operating channel number and operating class.
 * @vdev - Pointer to vdev.
 * @chan_num - Pointer to channel number.
 * @opclass - Pointer to opclass.
 *
 * Return - void
 */
void regdmn_get_curr_chan_and_opclass(struct wlan_objmgr_vdev *vdev,
                                      uint8_t *chan_num,
                                      uint8_t *opclass)
{
   wlan_if_t vap;

   vap = (wlan_if_t)wlan_vdev_get_mlme_ext_obj(vdev);
   if (vap == NULL) {
       qdf_err("VAP is NULL");
       return;
   }

   if (opclass)
       *opclass = wlan_get_opclass(vdev);

   if (chan_num)
       *chan_num = vap->iv_ic->ic_curchan->ic_ieee;
}

/**
 * regdmn_get_supp_opclass_list - Get supported opclass list and number of supported opclasses.
 * @pdev - Pointer to pdev.
 * @opclass_list - Pointer to opclass list.
 * @num_supp_op_class - Pointer to number of supported opclass.
 * @global_tbl_lookup - Global table lookup.
 *
 * Return - void
 */
void regdmn_get_supp_opclass_list(struct wlan_objmgr_pdev *pdev,
                                  uint8_t *opclass_list,
                                  uint8_t *num_supp_op_class,
                                  bool global_tbl_lookup)
{
   struct regdmn_ap_cap_opclass_t *reg_ap_cap =  NULL;
   QDF_STATUS status;
   uint8_t index = 0, idx = 0;

   reg_ap_cap = qdf_mem_malloc(REG_MAX_SUPP_OPER_CLASSES * sizeof(*reg_ap_cap));

   if (!reg_ap_cap) {
       qdf_err("reg_ap_cap is NULL");
       return;
   }

   status = wlan_reg_get_opclass_details(pdev, reg_ap_cap,
                                         &index, REG_MAX_SUPP_OPER_CLASSES,
                                         global_tbl_lookup);

  if (status != QDF_STATUS_SUCCESS) {
      qdf_err("Failed to get opclass details");
      qdf_mem_free(reg_ap_cap);
      return;
  }

  while (reg_ap_cap[idx].op_class && (idx < index)) {
         if(opclass_list)
            opclass_list[idx] = reg_ap_cap[idx].op_class;

         idx++;
  }

  *num_supp_op_class  = idx;
  qdf_mem_free(reg_ap_cap);
}

static bool
ieee80211_chansort(const void *chan1, const void *chan2)
{
    const struct ieee80211_ath_channel *tmp_chan1 = chan1;
    const struct ieee80211_ath_channel *tmp_chan2 = chan2;

    return (tmp_chan1->ic_freq == tmp_chan2->ic_freq) ?
        (ieee80211_get_mode(tmp_chan1) > ieee80211_get_mode(tmp_chan2)):
        tmp_chan1->ic_freq > tmp_chan2->ic_freq;
}

/*
 * Insertion sort.
 */
#define ieee80211_swap(_chan1, _chan2, _size) {     \
    u_int8_t *tmp_chan2 = _chan2;                   \
    int i = _size;                                  \
    do {                                            \
        u_int8_t tmp = *_chan1;                     \
        *_chan1++ = *tmp_chan2;                     \
        *tmp_chan2++ = tmp;                         \
    } while (--i);                                  \
    _chan1 -= _size;                                \
}

static void ieee80211_channel_sort(void *chans, uint32_t next, uint32_t size)
{
    uint8_t *tmp_chan = chans;
    uint8_t *ptr1, *ptr2;

    for (ptr1 = tmp_chan + size; --next >= 1; ptr1 += size)
        for (ptr2 = ptr1; ptr2 > tmp_chan; ptr2 -= size) {
            uint8_t *index = ptr2 - size;
            if (!ieee80211_chansort(index, ptr2))
                break;
            ieee80211_swap(index, ptr2, size);
        }
}

enum {
    CHANNEL_40_NO,
    CHANNEL_40_PLUS,
    CHANNEL_40_MINUS,
};

struct reg_cmode {
    uint32_t mode;
    uint64_t flags;
    uint32_t bw;
    uint32_t chan_ext;
};

static const struct reg_cmode modes[] = {
    { HOST_REGDMN_MODE_TURBO,               IEEE80211_CHAN_ST,
        CH_WIDTH_20MHZ, CHANNEL_40_NO }, /* TURBO means 11a Static Turbo */
#ifndef ATH_NO_5G_SUPPORT
    { HOST_REGDMN_MODE_11A,                 IEEE80211_CHAN_A,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },
#endif

    { HOST_REGDMN_MODE_11B,                 IEEE80211_CHAN_B,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11G,                 IEEE80211_CHAN_PUREG,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },

    { HOST_REGDMN_MODE_11NG_HT20,           IEEE80211_CHAN_HT20,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11NG_HT40PLUS,       IEEE80211_CHAN_HT40PLUS,
        CH_WIDTH_40MHZ, CHANNEL_40_PLUS },
    { HOST_REGDMN_MODE_11NG_HT40MINUS,      IEEE80211_CHAN_HT40MINUS,
        CH_WIDTH_40MHZ, CHANNEL_40_MINUS },

#ifndef ATH_NO_5G_SUPPORT
    { HOST_REGDMN_MODE_11NA_HT20,           IEEE80211_CHAN_HT20,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11NA_HT40PLUS,       IEEE80211_CHAN_HT40PLUS,
        CH_WIDTH_40MHZ, CHANNEL_40_PLUS },
    { HOST_REGDMN_MODE_11NA_HT40MINUS,      IEEE80211_CHAN_HT40MINUS,
        CH_WIDTH_40MHZ, CHANNEL_40_MINUS },

    { HOST_REGDMN_MODE_11AC_VHT20,          IEEE80211_CHAN_VHT20,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AC_VHT40PLUS,      IEEE80211_CHAN_VHT40PLUS,
        CH_WIDTH_40MHZ, CHANNEL_40_PLUS },
    { HOST_REGDMN_MODE_11AC_VHT40MINUS,     IEEE80211_CHAN_VHT40MINUS,
        CH_WIDTH_40MHZ, CHANNEL_40_MINUS },
    { HOST_REGDMN_MODE_11AC_VHT80,          IEEE80211_CHAN_VHT80,
        CH_WIDTH_80MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AC_VHT160,         IEEE80211_CHAN_VHT160,
        CH_WIDTH_160MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AC_VHT80_80,       IEEE80211_CHAN_VHT80_80,
        CH_WIDTH_80P80MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AXG_HE20,          IEEE80211_CHAN_HE20,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AXA_HE20,          IEEE80211_CHAN_HE20,
        CH_WIDTH_20MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AXG_HE40PLUS,      IEEE80211_CHAN_HE40PLUS,
        CH_WIDTH_40MHZ, CHANNEL_40_PLUS },
    { HOST_REGDMN_MODE_11AXG_HE40MINUS,     IEEE80211_CHAN_HE40MINUS,
        CH_WIDTH_40MHZ, CHANNEL_40_MINUS },
    { HOST_REGDMN_MODE_11AXA_HE40PLUS,      IEEE80211_CHAN_HE40PLUS,
        CH_WIDTH_40MHZ, CHANNEL_40_PLUS },
    { HOST_REGDMN_MODE_11AXA_HE40MINUS,     IEEE80211_CHAN_HE40MINUS,
        CH_WIDTH_40MHZ, CHANNEL_40_MINUS },
    { HOST_REGDMN_MODE_11AXA_HE80,          IEEE80211_CHAN_HE80,
        CH_WIDTH_80MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AXA_HE160,         IEEE80211_CHAN_HE160,
        CH_WIDTH_160MHZ, CHANNEL_40_NO },
    { HOST_REGDMN_MODE_11AXA_HE80_80,       IEEE80211_CHAN_HE80_80,
        CH_WIDTH_80P80MHZ, CHANNEL_40_NO },
#endif
};

static bool
regdmn_duplicate_channel(struct ieee80211_ath_channel *chan,
        struct ieee80211_ath_channel *list, int size)
{
    uint16_t i;

    for (i=0; i<size; i++) {
        if (chan->ic_freq == list[i].ic_freq &&
                chan->ic_flags == list[i].ic_flags &&
                chan->ic_flagext == list[i].ic_flagext &&
                chan->ic_vhtop_freq_seg1 == list[i].ic_vhtop_freq_seg1 &&
                chan->ic_vhtop_freq_seg2 == list[i].ic_vhtop_freq_seg2)
            return true;
    }

    return false;
}

u_int
regdmn_mhz2ieee(u_int freq, u_int flags)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)

    if (freq == 2484)
        return 14;
    if (freq < 2484)
        return (freq - 2407) / 5;
    if (freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
            return ((freq * 10) +
                    (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
        } else if (freq > 4900) {
            return (freq - 4000) / 5;
        } else {
            return 15 + ((freq - 2512) / 20);
        }
    }
    return (freq - 5000) / 5;
}

static void
populate_ic_channel(struct ieee80211_ath_channel *icv,
        const struct reg_cmode *cm,
        struct regulatory_channel *reg_chan,
        struct ch_params *ch_params,
        struct ieee80211_ath_channel *chans,
        int *next, enum channel_state state1,
        enum channel_state state2,
        uint64_t flags)
{

#define CHANNEL_HALF_BW        10
#define CHANNEL_QUARTER_BW    5

    if (cm->flags == IEEE80211_CHAN_HT40PLUS ||
            cm->flags == IEEE80211_CHAN_HT40PLUS ||
            cm->flags == IEEE80211_CHAN_VHT40PLUS ||
            cm->flags == IEEE80211_CHAN_HE40PLUS ||
            cm->flags == IEEE80211_CHAN_HE40PLUS) {
        if (ch_params->sec_ch_offset == HIGH_PRIMARY_CH) {
            return;
        }
    }

    if (cm->flags == IEEE80211_CHAN_HT40MINUS ||
            cm->flags == IEEE80211_CHAN_HT40MINUS ||
            cm->flags == IEEE80211_CHAN_VHT40MINUS ||
            cm->flags == IEEE80211_CHAN_HE40MINUS ||
            cm->flags == IEEE80211_CHAN_HE40MINUS) {
        if (ch_params->sec_ch_offset == LOW_PRIMARY_CH) {
            return ;
        }
    }

    /* 11AC modes do not support 2.4Ghz channels. Do not add them */
    if (wlan_reg_is_24ghz_ch_freq(reg_chan->center_freq)) {
        if((cm->flags == IEEE80211_CHAN_VHT20) ||
           (cm->flags == IEEE80211_CHAN_VHT40MINUS) ||
           (cm->flags == IEEE80211_CHAN_VHT40PLUS) ||
           (cm->flags == IEEE80211_CHAN_VHT80) ||
           (cm->flags == IEEE80211_CHAN_VHT80_80) ||
           (cm->flags == IEEE80211_CHAN_VHT160)) {
           return;
        }
    }

#ifdef CONFIG_BAND_6GHZ
        if(wlan_reg_is_6ghz_chan_freq(reg_chan->center_freq)) {
           /* Do not build 6Ghz for non-11AX  phy modes */
          if(!((cm->flags == IEEE80211_CHAN_HE20) ||
             (cm->flags   == IEEE80211_CHAN_HE40MINUS) ||
             (cm->flags   == IEEE80211_CHAN_HE40PLUS) ||
             (cm->flags   == IEEE80211_CHAN_HE80) ||
             (cm->flags   == IEEE80211_CHAN_HE80_80) ||
             (cm->flags   == IEEE80211_CHAN_HE160))){
             return;
          }
        }
#endif

    OS_MEMZERO(icv, sizeof(icv));

    /* Set only 11b flag if REGULATORY_CHAN_NO_OFDM flag
     * is set in the reg-rules.
     */

    icv->ic_flags = cm->flags | flags;

    if (wlan_reg_is_5ghz_ch_freq(reg_chan->center_freq))
        icv->ic_flags = cm->flags | IEEE80211_CHAN_5GHZ;
    else if (wlan_reg_is_24ghz_ch_freq(reg_chan->center_freq))
        icv->ic_flags = cm->flags | IEEE80211_CHAN_2GHZ;
    else if (wlan_reg_is_6ghz_chan_freq(reg_chan->center_freq))
        icv->ic_flags = cm->flags | IEEE80211_CHAN_6GHZ;

    if (reg_chan->chan_flags & REGULATORY_CHAN_NO_OFDM)
        icv->ic_flags = IEEE80211_CHAN_B;

    icv->ic_freq = reg_chan->center_freq;
    icv->ic_maxregpower = reg_chan->tx_power;
    icv->ic_antennamax = reg_chan->ant_gain;
    icv->ic_flagext = 0;

    if (state1 == CHANNEL_STATE_DFS) {
        icv->ic_flags |= IEEE80211_CHAN_PASSIVE;
        if (WLAN_REG_IS_5GHZ_CH_FREQ(reg_chan->center_freq)) {
            icv->ic_flags &= ~IEEE80211_CHAN_DFS_RADAR;
            icv->ic_flagext |= IEEE80211_CHAN_DFS;
            icv->ic_flagext &= ~IEEE80211_CHAN_DFS_RADAR_FOUND;
        }
    }

    if (state2 == CHANNEL_STATE_DFS)
        icv->ic_flagext |= IEEE80211_CHAN_DFS_CFREQ2;
    else
        icv->ic_flagext &= ~IEEE80211_CHAN_DFS_CFREQ2;

    /* Check for ad-hoc allowableness */
    /* To be done: DISALLOW_ADHOC_11A_TURB should allow ad-hoc */
    if (icv->ic_flagext & IEEE80211_CHAN_DFS ||
            icv->ic_flagext & IEEE80211_CHAN_DFS_CFREQ2) {
        icv->ic_flagext |= IEEE80211_CHAN_DISALLOW_ADHOC;
    }

    if (WLAN_REG_IS_6GHZ_PSC_CHAN_FREQ(reg_chan->center_freq)) {
        icv->ic_flagext |= IEEE80211_CHAN_PSC;
    }

    icv->ic_ieee = reg_chan->chan_num;
    icv->ic_vhtop_ch_num_seg1 = ch_params->center_freq_seg0;
    icv->ic_vhtop_ch_num_seg2 = ch_params->center_freq_seg1;
    icv->ic_vhtop_freq_seg1 = ch_params->mhz_freq_seg0;
    icv->ic_vhtop_freq_seg2 = ch_params->mhz_freq_seg1;

    if (regdmn_duplicate_channel(icv, chans, *next+1)) {
        return;
    }

    OS_MEMCPY(&chans[(*next)++], icv, sizeof(struct ieee80211_ath_channel));

#undef CHANNEL_HALF_BW
#undef CHANNEL_QUARTER_BW
}

enum channel_state regdmn_reg_get_bonded_channel_state_for_freq(
        struct wlan_objmgr_pdev *pdev,
        qdf_freq_t freq,
        qdf_freq_t sec_ch_freq_2g,
        enum phy_ch_width bw)
{
        if (WLAN_REG_IS_5GHZ_CH_FREQ(freq))
            return ieee80211_regdmn_get_5g_bonded_channel_state_for_freq(pdev,
                                                                         freq,
                                                                         bw);
        else if  (WLAN_REG_IS_24GHZ_CH_FREQ(freq))
                  return ieee80211_regdmn_get_2g_bonded_channel_state_for_freq(pdev, freq, sec_ch_freq_2g, bw);

    return CHANNEL_STATE_INVALID;
}

#define FREQ_OFFSET_10MHZ 10
#define FREQ_OFFSET_80MHZ 80
#define CHAN_80MHZ_NUM QDF_ARRAY_SIZE(mhz80_5g_chan_list)
#define CHAN_80MHZ_NUM_5G QDF_ARRAY_SIZE(mhz80_5g_freq_list)

#ifdef CONFIG_BAND_6GHZ
#define CHAN_80MHZ_NUM_6G QDF_ARRAY_SIZE(mhz80_6g_freq_list)
#else
#define CHAN_80MHZ_NUM_6G 0
#endif

const uint16_t mhz80_5g_chan_list[] = {
    42,
    58,
    106,
    122,
    138,
    155
};

const uint16_t mhz80_5g_freq_list[] = {
    5210, /* 42 */
    5290, /* 58 */
    5530, /* 106 */
    5610, /* 122 */
    5690, /* 138 */
    5775, /* 155 */
};
#ifdef CONFIG_BAND_6GHZ
const uint16_t mhz80_6g_chan_list[] = {
    7 ,
    23,
    39,
    55,
    71,
    87,
    103,
    119,
    135,
    151,
    167,
    183,
    199,
    215,
};

const uint16_t mhz80_6g_freq_list[] = {
    5985, /* 7 */
    6065, /* 23 */
    6145, /* 39 */
    6225, /* 55 */
    6305, /* 71 */
    6385, /* 87 */
    6465, /* 103 */
    6545, /* 119 */
    6625, /* 135 */
    6705, /* 151 */
    6785, /* 167 */
    6865, /* 183 */
    6945, /* 199 */
    7025, /* 215 */
};
#endif

void regdmn_update_ic_channels(
        struct wlan_objmgr_pdev *pdev,
        struct ieee80211com *ic,
        uint32_t mode_select,
        struct regulatory_channel *curr_chan_list,
        struct ieee80211_ath_channel *chans,
        u_int maxchans,
        u_int *nchans,
        qdf_freq_t low_2g,
        qdf_freq_t high_2g,
        qdf_freq_t low_5g,
        qdf_freq_t high_5g)
{
    struct regulatory_channel *reg_chan;
    uint32_t num_chan;
    const struct reg_cmode *cm;
    struct ch_params ch_params;
    qdf_freq_t sec_ch_2g_freq = 0;
    struct ieee80211_ath_channel icv;
    uint32_t next = 0;
    enum channel_state chan_state1, chan_state2;
    uint32_t loop, i;
    uint64_t flags;
    const uint16_t *mhz80_freq_list, *mhz80_chan_list;
    struct wlan_objmgr_psoc *psoc;
    uint16_t max_bw_5g = 0;

    max_bw_5g = ieee80211_get_max5gbw(ic);
    psoc = wlan_pdev_get_psoc(pdev);
    if (psoc == NULL) {
        qdf_err("%s : psoc is null", __func__);
        return;
    }

    /*
     * Clear ic_49ghz_enabled as new channels are initialised.
     * This shall be set as soon as a 4.9 GHz channel in ic_chans[]
     * is initialised.
     */
    ic->ic_49ghz_enabled = false;

    for (cm = modes; cm < &modes[QDF_ARRAY_SIZE(modes)]; cm++) {
        if ((cm->mode & mode_select) == 0) {
            continue;
        }

        reg_chan = curr_chan_list;
        num_chan = NUM_CHANNELS;

        while(num_chan--)
        {
            if(reg_chan->state == CHANNEL_STATE_DISABLE) {
                reg_chan++;
                continue;
            }

            if (IEEE80211_IS_FLAG_5GHZ(cm->flags)) {
                if ((reg_chan->center_freq < low_5g) ||
                        (reg_chan->center_freq > high_5g)) {
                    reg_chan++;
                    continue;
                }
            } else if (IEEE80211_IS_FLAG_2GHZ(cm->flags)) {
                if ((reg_chan->center_freq < low_2g) ||
                        (reg_chan->center_freq > high_2g)) {
                    reg_chan++;
                    continue;
                }
            }
            if(WLAN_REG_IS_49GHZ_FREQ(reg_chan->center_freq))
            {

                if(cm->mode == HOST_REGDMN_MODE_11A) {
                    ch_params.center_freq_seg0 = reg_chan->chan_num;
                    ch_params.center_freq_seg1 = 0;
                    ch_params.mhz_freq_seg0 = reg_chan->center_freq;
                    ch_params.mhz_freq_seg1 = 0;
                    chan_state1 = reg_chan->state;
                    chan_state2 = CHANNEL_STATE_DISABLE;

                    if(BW_WITHIN(reg_chan->min_bw, FULL_BW, reg_chan->max_bw)) {
                        flags = 0;
                        populate_ic_channel(&icv, cm, reg_chan, &ch_params, chans,
                                &next, chan_state1, chan_state2, flags);
                    }

                    if(BW_WITHIN(reg_chan->min_bw, HALF_BW, reg_chan->max_bw)) {
                        flags = IEEE80211_CHAN_HALF;
                        populate_ic_channel(&icv, cm, reg_chan, &ch_params, chans,
                                &next, chan_state1, chan_state2, flags);
                    }

                    if(BW_WITHIN(reg_chan->min_bw, QRTR_BW, reg_chan->max_bw)) {
                        flags = IEEE80211_CHAN_QUARTER;
                        populate_ic_channel(&icv, cm, reg_chan, &ch_params, chans,
                                &next, chan_state1, chan_state2, flags);
                    }

                    ic->ic_49ghz_enabled = true;
                }

                reg_chan++;
                continue;
            }

            switch(cm->chan_ext) {
            case CHANNEL_40_NO:
                sec_ch_2g_freq = 0;
                break;
            case CHANNEL_40_PLUS:
                sec_ch_2g_freq = reg_chan->center_freq + CHAN_HT40_OFFSET;
                break;
            case CHANNEL_40_MINUS:
                sec_ch_2g_freq = reg_chan->center_freq - CHAN_HT40_OFFSET;
                break;
            }

            if (cm->bw == CH_WIDTH_80P80MHZ && max_bw_5g < BW_160_MHZ)
                continue ;

            if (cm->bw == CH_WIDTH_80P80MHZ) {
#ifdef CONFIG_BAND_6GHZ
                if (wlan_reg_is_6ghz_chan_freq(reg_chan->center_freq)) {
                    loop = CHAN_80MHZ_NUM_6G;
                    mhz80_freq_list = mhz80_6g_freq_list;
                    mhz80_chan_list = mhz80_6g_chan_list;
                } else {
                    loop = CHAN_80MHZ_NUM_5G;
                    mhz80_freq_list = mhz80_5g_freq_list;
                    mhz80_chan_list = mhz80_5g_chan_list;
                }
#else
                loop = CHAN_80MHZ_NUM_5G;
                mhz80_chan_list = mhz80_5g_chan_list;
                mhz80_freq_list = mhz80_5g_freq_list;
#endif
            }
            else
                loop = 1;

            i = 0;
            while (loop--) {
                if (cm->bw == CH_WIDTH_80P80MHZ) {
                    ch_params.center_freq_seg1 = mhz80_chan_list[i];
                    ch_params.mhz_freq_seg1 = mhz80_freq_list[i];
                    i++;
                } else {
                    ch_params.center_freq_seg1 = 0;
                    ch_params.mhz_freq_seg1 = 0;
                }

                ch_params.ch_width = cm->bw;
                ieee80211_regdmn_set_channel_params_for_freq(pdev, reg_chan->center_freq,
                        sec_ch_2g_freq, &ch_params);

                if (cm->bw == ch_params.ch_width) {

                    if (ch_params.ch_width == CH_WIDTH_80P80MHZ) {
                        chan_state1 = regdmn_reg_get_bonded_channel_state_for_freq(pdev,
                                reg_chan->center_freq, sec_ch_2g_freq, CH_WIDTH_80MHZ);
                        chan_state2 = regdmn_reg_get_bonded_channel_state_for_freq(pdev,
                                ch_params.mhz_freq_seg1 - FREQ_OFFSET_10MHZ, sec_ch_2g_freq, CH_WIDTH_80MHZ);
                        if ((abs(ch_params.mhz_freq_seg0 - ch_params.mhz_freq_seg1)) <= FREQ_OFFSET_80MHZ) {
                            continue;
                        }

                        /* In restricted 80P80 MHz enabled, only one 80+80 MHz
                         * channel is supported with cfreq=5690 and cfreq=5775.
                         * Therefore, do not populate other 80+80 MHz channels
                         * in ic channel list.
                         */
                        if (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_RESTRICTED_80P80_SUPPORT) &&
                            !(CHAN_WITHIN_RESTRICTED_80P80(ch_params.mhz_freq_seg0,
                                ch_params.mhz_freq_seg1)))
                            continue;
                    }
                    else if (ch_params.ch_width == CH_WIDTH_160MHZ) {
                        chan_state1 = regdmn_reg_get_bonded_channel_state_for_freq(pdev,
                                reg_chan->center_freq, sec_ch_2g_freq, CH_WIDTH_80MHZ);
                        chan_state2 = regdmn_reg_get_bonded_channel_state_for_freq(pdev,
                                ((2 * ch_params.mhz_freq_seg1) -
                                 ch_params.mhz_freq_seg0 + FREQ_OFFSET_10MHZ),
                                sec_ch_2g_freq, CH_WIDTH_80MHZ);
                    } else {
                        chan_state1 = regdmn_reg_get_bonded_channel_state_for_freq(pdev,
                                reg_chan->center_freq, sec_ch_2g_freq, ch_params.ch_width);

                        chan_state2 = CHANNEL_STATE_DISABLE;
                    }

                    flags = 0;
                    populate_ic_channel(&icv, cm, reg_chan, &ch_params, chans,
                        &next, chan_state1, chan_state2, flags);
                }
            }
            reg_chan++;
        }
    }
    if (next > 0) {
        ieee80211_channel_sort(chans, next, sizeof(struct ieee80211_ath_channel));
    }
    *nchans = next;
    ieee80211_set_nchannels(ic, next);

#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
    /* If the spoof dfs check has failed, AP should come up only in NON-DFS
     * channels. "Setregdomain and setcountry" cmd will rebuild the ic channel list
     * (could include DFS and non-DFS chans). The following code will ensure
     * that ic channel list still consists of non-DFS channels if spoof check
     * failed.
     */
    ic->dfs_spoof_test_regdmn = 1;
    if (ic->ic_rebuilt_chanlist)
        ic->ic_rebuilt_chanlist = 0;

    ieee80211_dfs_non_dfs_chan_config(ic);

#endif /* HOST_DFS_SPOOF_TEST */
}

uint8_t
regdmn_get_band_cap_from_op_class(uint8_t num_of_opclass,
                                  const uint8_t *opclass)
{
    uint8_t  supported_band;
    uint8_t country_iso[REG_ALPHA2_LEN + 1] = {};

    country_iso[2] = OP_CLASS_GLOBAL;
    supported_band = wlan_reg_get_band_cap_from_op_class(country_iso,
                                                         num_of_opclass,
                                                         opclass);

    if (!supported_band) {
        qdf_err("None of the Operating class is found");
        return supported_band;
    }

    if (supported_band & BIT(REG_BAND_2G))
        supported_band |= BIT(IEEE80211_2G_BAND);
    else if (supported_band & BIT(REG_BAND_5G))
             supported_band |= BIT(IEEE80211_5G_BAND);
    else if (supported_band & BIT(REG_BAND_6G))
             supported_band |= BIT(IEEE80211_6G_BAND);
    else
             qdf_err("Unknown band %X", supported_band);

    return supported_band;
}

/**
 * regdmn_get_min_6ghz_chan_freq - Retrieve the minimum 6G channel frequency
 *
 * Return - Return the 6G minimum channel frequency if found, else zero.
 */
uint16_t regdmn_get_min_6ghz_chan_freq(void)
{
    return wlan_reg_min_6ghz_chan_freq();
}
qdf_export_symbol(regdmn_get_min_6ghz_chan_freq);

/**
 * regdmn_get_max_6ghz_chan_freq - Retrieve the maximum 6G channel frequency
 *
 * Return - Return the 6G maximum channel frequency if found, else zero.
 */
uint16_t regdmn_get_max_6ghz_chan_freq(void)
{
    return wlan_reg_max_6ghz_chan_freq();
}
qdf_export_symbol(regdmn_get_max_6ghz_chan_freq);

/**
 * regdmn_get_min_5ghz_chan_freq - Retrieve the minimum 5G channel frequency
 *
 * Return - Return the 5G minimum channel frequency if found, else zero.
 */
uint16_t regdmn_get_min_5ghz_chan_freq(void)
{
    return wlan_reg_min_5ghz_chan_freq();
}
qdf_export_symbol(regdmn_get_min_5ghz_chan_freq);

/**
 * regdmn_get_max_5ghz_chan_freq - Retrieve the maximum 5G channel frequency
 *
 * Return - Return the 5G maximum channel frequency if found, else zero.
 */
uint16_t regdmn_get_max_5ghz_chan_freq(void)
{
    return wlan_reg_max_5ghz_chan_freq();
}
qdf_export_symbol(regdmn_get_max_5ghz_chan_freq);

void regdmn_populate_channel_list_from_map(regdmn_op_class_map_t *map,
                                  u_int8_t reg_class, struct ieee80211_node *ni) {
    uint8_t chanidx = 0;

    if(!map)
        return;

    while (map->op_class) {
        if (map->op_class == reg_class) {
            for (chanidx = 0; chanidx < MAX_CHANNELS_PER_OPERATING_CLASS &&
                                map->ch_set[chanidx] != 0; chanidx++) {
                IEEE80211_MBO_CHAN_BITMAP_SET(ni->ni_supp_op_cl.channels_supported, map->ch_set[chanidx]);
            }
            ni->ni_supp_op_cl.num_chan_supported += chanidx;
            break;
        }
        map++;
    }
    return;
}

void
regdmn_get_channel_list_from_op_class(uint8_t reg_class,
                                      struct ieee80211_node *ni)
{
    struct ieee80211com *ic = ni->ni_ic;
    uint8_t c_idx = 0;
    uint8_t idx = 0, n_opclasses = 0, max_supp_op_class = REG_MAX_SUPP_OPER_CLASSES;
    struct regdmn_ap_cap_opclass_t *reg_ap_cap =  NULL;
    bool global_tbl_lookup = true;
    QDF_STATUS status;

    reg_ap_cap = qdf_mem_malloc(max_supp_op_class * sizeof(*reg_ap_cap));
    if(reg_ap_cap == NULL) {
        qdf_err("Malloc failed for reg_ap_cap");
        return;
    }

    /* Get the regdmn map corresponding to country code */
    status = wlan_reg_get_opclass_details(ic->ic_pdev_obj, reg_ap_cap,
                                          &n_opclasses, max_supp_op_class,
                                          global_tbl_lookup);

    if (status != QDF_STATUS_SUCCESS) {
        qdf_err("Failed to get opclass details");
        qdf_mem_free(reg_ap_cap);
        return;
    }

    /* Update the supported channel list for the peer based on intersection
     * between AP's and STA's Supported Operating Class list.
     */
    while (AP_CAP.op_class && (idx < n_opclasses)) {
        if (AP_CAP.op_class == reg_class) {
            while(c_idx < AP_CAP.num_supported_chan) {
                IEEE80211_MBO_CHAN_BITMAP_SET(
                    ni->ni_supp_op_cl.channels_supported,
                    AP_CAP.sup_chan_list[c_idx]);
                c_idx++;
            }

            c_idx = 0;
            while(c_idx < AP_CAP.num_non_supported_chan) {
                IEEE80211_MBO_CHAN_BITMAP_SET(
                    ni->ni_supp_op_cl.channels_supported,
                    AP_CAP.non_sup_chan_list[c_idx]);
                c_idx++;
            }
        }
        idx++;
    }

    /* Check for global operating class and mark those channels also as true to
     * pass MBO related testcase.
     */
    regdmn_populate_channel_list_from_map(global_operating_class, reg_class, ni);
    qdf_mem_free(reg_ap_cap);

    return;
}

uint8_t regdmn_get_opclass(uint8_t *country_iso,
                           struct ieee80211_ath_channel *channel)
{

    uint16_t chan_width, behav_limit;
    uint8_t opclass = 0;

    wlan_get_bw_and_behav_limit(channel, &chan_width, &behav_limit);
    opclass = wlan_reg_get_opclass_from_freq_width(country_iso,
                                                   channel->ic_freq,
                                                   chan_width,
                                                   behav_limit);

     if (!opclass)
         qdf_err("Operating class is 0");

     return opclass;
}

#define CHAN_TO_FREQ_SCALE 5

static uint16_t
regdmn_chan_to_freq(struct regdmn_ap_cap_opclass_t *reg_ap_cap, uint8_t chan_num, uint8_t idx)
{
    return reg_ap_cap[idx].start_freq + (chan_num * CHAN_TO_FREQ_SCALE);
}

static void regdmn_fill_apcap(mapapcap_t *apcap,
                              struct regdmn_ap_cap_opclass_t *reg_ap_cap,
                              uint8_t idx,
                              uint8_t *total_n_sup_opclass)
{
    HW_OP_CLASS.opclass = AP_CAP.op_class;
    HW_OP_CLASS.max_tx_pwr_dbm = AP_CAP.max_tx_pwr_dbm;
    HW_OP_CLASS.num_non_oper_chan = AP_CAP.num_non_supported_chan;
    qdf_mem_copy(HW_OP_CLASS.non_oper_chan_num,
                 AP_CAP.non_sup_chan_list,
                 AP_CAP.num_non_supported_chan);
    apcap->map_ap_radio_basic_capabilities_valid = 1;
    (*total_n_sup_opclass)++;
}

static void regdmn_fill_map_op_chan(struct wlan_objmgr_pdev *pdev,
                                    struct map_op_chan_t *map_op_chan,
                                    struct regdmn_ap_cap_opclass_t *reg_ap_cap,
                                    uint8_t idx,
                                    uint8_t *total_n_sup_opclass,
                                    bool dfs_required)
{
    if (dfs_required) {
        uint8_t chan_idx = 0, i = 0;

        MAP_OP_CHAN.opclass = AP_CAP.op_class;
        switch(AP_CAP.ch_width) {
               case BW_20_MHZ:
                              MAP_OP_CHAN.ch_width = IEEE80211_CWM_WIDTH20;
                              break;
               case BW_25_MHZ:
                              MAP_OP_CHAN.ch_width = IEEE80211_CWM_WIDTH20;
                              break;
               case BW_40_MHZ:
                              MAP_OP_CHAN.ch_width = IEEE80211_CWM_WIDTH40;
                              break;
               case BW_80_MHZ:
                              if (AP_CAP.behav_limit == BIT(BEHAV_BW80_PLUS))
                                  MAP_OP_CHAN.ch_width = IEEE80211_CWM_WIDTH80_80;
                              else
                                  MAP_OP_CHAN.ch_width = IEEE80211_CWM_WIDTH80;

                              break;
              case BW_160_MHZ:
                              MAP_OP_CHAN.ch_width = IEEE80211_CWM_WIDTH160;
                              break;
              default:
                      MAP_OP_CHAN.ch_width = IEEE80211_CWM_WIDTHINVALID;
                      break;
       }

       while (AP_CAP.sup_chan_list[chan_idx]) {
              qdf_freq_t search_freq =
              regdmn_chan_to_freq(reg_ap_cap,
                                  AP_CAP.
                                  sup_chan_list[chan_idx],
                                  idx);

              if (wlan_reg_is_dfs_for_freq(pdev, search_freq))
                  MAP_OP_CHAN.oper_chan_num[i++] = AP_CAP.sup_chan_list[chan_idx++];
              else
                  chan_idx++;
       }

       MAP_OP_CHAN.num_oper_chan = i;

       if (i)
           (*total_n_sup_opclass)++;

    } else if (AP_CAP.op_class == map_op_chan->opclass) {
               map_op_chan->ch_width = AP_CAP.ch_width;
               switch(AP_CAP.ch_width) {
                      case BW_20_MHZ:
                                     map_op_chan->ch_width =
                                                          IEEE80211_CWM_WIDTH20;
                                     break;
                      case BW_25_MHZ:
                                     map_op_chan->ch_width =
                                                          IEEE80211_CWM_WIDTH20;
                                     break;
                      case BW_40_MHZ:
                                     map_op_chan->ch_width =
                                                         IEEE80211_CWM_WIDTH40;
                                     break;
                      case BW_80_MHZ:
                                     if (AP_CAP.behav_limit == BIT(BEHAV_BW80_PLUS))
                                         map_op_chan->ch_width =
                                                       IEEE80211_CWM_WIDTH80_80;
                                     else
                                         map_op_chan->ch_width =
                                                          IEEE80211_CWM_WIDTH80;
                                     break;
                      case BW_160_MHZ:
                                      map_op_chan->ch_width =
                                                         IEEE80211_CWM_WIDTH160;
                                      break;
                      default:
                              map_op_chan->ch_width = IEEE80211_CWM_WIDTHINVALID;
                              break;
                }

                map_op_chan->num_oper_chan = AP_CAP.num_supported_chan;
                qdf_mem_copy(map_op_chan->oper_chan_num,
                             AP_CAP.sup_chan_list,
                             AP_CAP.num_supported_chan);
    }
}

static void regdmn_fill_map_op_class_t(struct map_op_class_t *map_op_class,
                                       struct regdmn_ap_cap_opclass_t *reg_ap_cap,
                                       uint8_t idx)
{
    uint8_t chan_idx = 0, i = 0;

    if (map_op_class->opclass != AP_CAP.op_class)
        return;

    switch(AP_CAP.ch_width) {
           case BW_20_MHZ:
                   map_op_class->ch_width = IEEE80211_CWM_WIDTH20;
                   break;
           case BW_25_MHZ:
                   map_op_class->ch_width = IEEE80211_CWM_WIDTH20;
                   break;
           case BW_40_MHZ:
                   map_op_class->ch_width = IEEE80211_CWM_WIDTH40;
                   break;
           case BW_80_MHZ:
                   if (AP_CAP.behav_limit == BIT(BEHAV_BW80_PLUS))
                       map_op_class->ch_width = IEEE80211_CWM_WIDTH80_80;
                   else
                       map_op_class->ch_width = IEEE80211_CWM_WIDTH80;
                   break;
           case BW_160_MHZ:
                   map_op_class->ch_width = IEEE80211_CWM_WIDTH160;
                   break;
           default:
                   map_op_class->ch_width = IEEE80211_CWM_WIDTHINVALID;
                   break;
    }

    switch(AP_CAP.behav_limit) {
           case BIT(BEHAV_NONE):
                                map_op_class->sc_loc =
                                                 IEEE80211_SEC_CHAN_OFFSET_SCN;
                                break;
            case BIT(BEHAV_BW40_LOW_PRIMARY):
                                map_op_class->sc_loc =
                                                  IEEE80211_SEC_CHAN_OFFSET_SCA;
                                break;
            case BIT(BEHAV_BW40_HIGH_PRIMARY):
                                map_op_class->sc_loc =
                                                  IEEE80211_SEC_CHAN_OFFSET_SCB;
                                break;
            case BIT(BEHAV_BW80_PLUS):
                                map_op_class->sc_loc =
                                                  IEEE80211_SEC_CHAN_OFFSET_SCN;
                                break;
            default:
                    map_op_class->sc_loc = IEEE80211_SEC_CHAN_OFFSET_SCN;
            break;
    }

    map_op_class->num_chan = AP_CAP.num_supported_chan + AP_CAP.num_non_supported_chan;

    while(chan_idx < AP_CAP.num_supported_chan)
          map_op_class->channels[i++] = AP_CAP.sup_chan_list[chan_idx++];
    chan_idx = 0;

    while(chan_idx < AP_CAP.num_non_supported_chan)
          map_op_class->channels[i++] = AP_CAP.non_sup_chan_list[chan_idx++];

}

/**
 * @brief Populate AP capabilities with opclass and operable channels for MultiAP
 *
 * @param pdev Pointer to pdev
 * @param apcap Pointer to structure to populate AP capabilities
 * @param map_op_chan Pointer to structure to populate operable channel
 * @param map_op_class Pointer to structure to populate operating class
 * @param global_tbl_lookup Whether to lookup global op class tbl
 *
 * @return Total number of operating opclass, else return 0 in case of failure
 */
uint8_t regdmn_get_map_opclass(struct wlan_objmgr_pdev *pdev,
                               mapapcap_t *apcap,
                               struct map_op_chan_t *map_op_chan,
                               struct map_op_class_t *map_op_class,
                               bool global_tbl_lookup,
                               bool dfs_required)
{
    uint8_t total_n_sup_opclass = 0;
    uint8_t idx = 0, n_opclasses = 0, max_supp_op_class = REG_MAX_SUPP_OPER_CLASSES;
    struct regdmn_ap_cap_opclass_t *reg_ap_cap =  NULL;
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev);
    QDF_STATUS status;

    if (!ic) {
        qdf_err("ic is NULL");
        return 0;
    }

    reg_ap_cap = qdf_mem_malloc(max_supp_op_class * sizeof(*reg_ap_cap));

    if (!reg_ap_cap) {
        qdf_err("Failed to allocate reg_ap_cap");
        return 0;
    }

    status = wlan_reg_get_opclass_details(pdev, reg_ap_cap, &n_opclasses,
                                          max_supp_op_class,
                                          global_tbl_lookup);

    if (status != QDF_STATUS_SUCCESS) {
        qdf_err("Failed to get opclass details");
        return 0;
    }
    /* Only one of 'apcap' and 'map_op_chan' is expected to be not-NULL at a time*/
    if (apcap && map_op_chan) {
        qdf_err("Both apcap and map_op_chan should not be allocated at the same time");
        return 0;
    }

    while (AP_CAP.op_class && (idx < n_opclasses)) {
           /* check radio capability and skip unsupported channel width */
           if (((AP_CAP.ch_width == BW_160_MHZ) &&
               !(ic->ic_modecaps & (1 << IEEE80211_MODE_11AC_VHT160))) ||
               ((AP_CAP.behav_limit == BIT(BEHAV_BW80_PLUS)) &&
                !(ic->ic_modecaps & (1 << IEEE80211_MODE_11AC_VHT80_80)))) {
               idx++;
               continue;
           }

           if (apcap != NULL) {
               regdmn_fill_apcap(apcap, reg_ap_cap, idx, &total_n_sup_opclass);
           } else if (map_op_chan != NULL) {
               regdmn_fill_map_op_chan(pdev, map_op_chan, reg_ap_cap, idx,
                                       &total_n_sup_opclass, dfs_required);
           }

           if (map_op_class != NULL) {
               regdmn_fill_map_op_class_t(map_op_class, reg_ap_cap, idx);
           }
           idx++;
    }

    qdf_mem_free(reg_ap_cap);
    return total_n_sup_opclass;
}

/**
 * regdmn_convert_chanflags_to_chanwidth() - Convert chan flag to channel width
 * @chan: Pointer to current channel.
 *
 * Return: Channel width.
 */
static inline uint32_t regdmn_convert_chanflags_to_chanwidth(
        struct ieee80211_ath_channel *chan)
{
    uint32_t chanwidth = CH_WIDTH_INVALID;

    if (IEEE80211_IS_CHAN_ST(chan) ||
            IEEE80211_IS_CHAN_A(chan) ||
            IEEE80211_IS_CHAN_B(chan) ||
            IEEE80211_IS_CHAN_PUREG(chan) ||
            IEEE80211_IS_CHAN_20MHZ(chan))
        chanwidth = CH_WIDTH_20MHZ;
    else if (IEEE80211_IS_CHAN_40MHZ(chan))
        chanwidth = CH_WIDTH_40MHZ;
    else if (IEEE80211_IS_CHAN_80MHZ(chan))
        chanwidth = CH_WIDTH_80MHZ;
    else if (IEEE80211_IS_CHAN_160MHZ(chan))
        chanwidth = CH_WIDTH_160MHZ;
    else if (IEEE80211_IS_CHAN_80_80MHZ(chan))
        chanwidth = CH_WIDTH_80P80MHZ;

    return chanwidth;
}

/**
 * regdmn_get_sec_ch_offset() - Get second channel offset.
 * @chan: Pointer to current channel.
 *
 * Return: Second channel offset.
 */
static inline uint8_t regdmn_get_sec_ch_offset(
        struct ieee80211_ath_channel *chan)
{
    uint8_t sec_ch_offset = 0;

    if (IEEE80211_IS_CHAN_40PLUS(chan))
        sec_ch_offset = chan->ic_ieee + CHAN_DIFF;
    else if (IEEE80211_IS_CHAN_40MINUS(chan))
        sec_ch_offset = chan->ic_ieee - CHAN_DIFF;

    return sec_ch_offset;
}

void ieee80211_regdmn_get_des_chan_params(struct ieee80211vap *vap,
        struct ch_params *ch_params)
{
    struct ieee80211_ath_channel *chan;
    chan = vap->iv_des_chan[vap->iv_des_hw_mode];
    if ((chan != IEEE80211_CHAN_ANYC) && chan) {
        ch_params->ch_width = ieee80211_get_chan_width_from_phymode(vap->iv_des_hw_mode);
        ch_params->center_freq_seg0 = chan->ic_vhtop_ch_num_seg1;
        ch_params->center_freq_seg1 = chan->ic_vhtop_ch_num_seg2;
        ch_params->mhz_freq_seg0 = chan->ic_vhtop_freq_seg1;
        ch_params->mhz_freq_seg1 = chan->ic_vhtop_freq_seg2;
        ch_params->sec_ch_offset = regdmn_get_sec_ch_offset(chan);
    } else {
        ieee80211_regdmn_get_chan_params(vap->iv_ic, ch_params);
    }
}

void ieee80211_regdmn_get_chan_params(struct ieee80211com *ic,
        struct ch_params *ch_params)
{
    ch_params->ch_width = regdmn_convert_chanflags_to_chanwidth(ic->ic_curchan);
    ch_params->center_freq_seg0 = ic->ic_curchan->ic_vhtop_ch_num_seg1;
    ch_params->center_freq_seg1 = ic->ic_curchan->ic_vhtop_ch_num_seg2;
    ch_params->mhz_freq_seg0 = ic->ic_curchan->ic_vhtop_freq_seg1;
    ch_params->mhz_freq_seg1 = ic->ic_curchan->ic_vhtop_freq_seg2;
    ch_params->sec_ch_offset = regdmn_get_sec_ch_offset(ic->ic_curchan);
}

/**
 * ieee80211_convert_width_to_11ngflags() - Convert channel width to 11NG flags.
 * @ic: Pointer to ieee80211com structure.
 * @ch_params: Pointer to channel params structure.
 *
 * Return: Return 11NG flags.
 */
static inline enum ieee80211_phymode
ieee80211_convert_width_to_11ngflags(
        struct ieee80211com *ic,
        struct ch_params *ch_params)
{
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;

    switch (ch_params->ch_width) {
        case CH_WIDTH_20MHZ:
            mode = IEEE80211_MODE_11NG_HT20;
            break;
        case CH_WIDTH_40MHZ:
            if (ch_params->sec_ch_offset == HIGH_PRIMARY_CH)
                mode = IEEE80211_MODE_11NG_HT40MINUS;
            else if (ch_params->sec_ch_offset == LOW_PRIMARY_CH)
                mode = IEEE80211_MODE_11NG_HT40PLUS;
            break;
        default:
            mode = IEEE80211_MODE_AUTO;
            break;
    }

    return mode;
}

/**
 * ieee80211_convert_width_to_11naflags() - Convert channel width to 11NA flags.
 * @ic: Pointer to ieee80211com structure.
 * @ch_params: Pointer to channel params structure.
 *
 * Return: Return 11NA flags.
 */
static inline enum ieee80211_phymode
ieee80211_convert_width_to_11naflags(
        struct ieee80211com *ic,
        struct ch_params *ch_params)
{
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;

    switch (ch_params->ch_width) {
        case CH_WIDTH_20MHZ:
            mode = IEEE80211_MODE_11NA_HT20;
            break;
        case CH_WIDTH_40MHZ:
            if (ch_params->sec_ch_offset == HIGH_PRIMARY_CH)
                mode = IEEE80211_MODE_11NA_HT40MINUS;
            else if (ch_params->sec_ch_offset == LOW_PRIMARY_CH)
                mode = IEEE80211_MODE_11NA_HT40PLUS;
            break;
        default:
            mode = IEEE80211_MODE_AUTO;
            break;
    }

    return mode;
}

/**
 * ieee80211_convert_width_to_11acflags() - Convert channel width to 11AC flags.
 * @ic: Pointer to ieee80211com structure.
 * @ch_params: Pointer to channel params structure.
 *
 * Return: Return 11AC flags.
 */
static inline enum ieee80211_phymode
ieee80211_convert_width_to_11acflags(
        struct ieee80211com *ic,
        struct ch_params *ch_params)
{
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;

    switch (ch_params->ch_width) {
        case CH_WIDTH_20MHZ:
            mode = IEEE80211_MODE_11AC_VHT20;
            break;
        case CH_WIDTH_40MHZ:
            if (ch_params->sec_ch_offset == HIGH_PRIMARY_CH)
                mode = IEEE80211_MODE_11AC_VHT40MINUS;
            else if (ch_params->sec_ch_offset == LOW_PRIMARY_CH)
                mode = IEEE80211_MODE_11AC_VHT40PLUS;
            break;
        case CH_WIDTH_80MHZ:
            mode = IEEE80211_MODE_11AC_VHT80;
            break;
        case CH_WIDTH_160MHZ:
            mode = IEEE80211_MODE_11AC_VHT160;
            break;
        case CH_WIDTH_80P80MHZ:
            mode = IEEE80211_MODE_11AC_VHT80_80;
            break;
        default:
            mode = IEEE80211_MODE_AUTO;
            break;
    }

    return mode;
}

/**
 * ieee80211_convert_width_to_11axgflags() - Convert chan width to 11AXG flags.
 * @ic: Pointer to ieee80211com structure.
 * @ch_params: Pointer to channel params structure.
 *
 * Return: Return 11AXG flags.
 */
static inline enum ieee80211_phymode
ieee80211_convert_width_to_11axgflags(
        struct ieee80211com *ic,
        struct ch_params *ch_params)
{
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;

    switch (ch_params->ch_width) {
        case CH_WIDTH_20MHZ:
            mode = IEEE80211_MODE_11AXG_HE20;
            break;
        case CH_WIDTH_40MHZ:
            if (ch_params->sec_ch_offset == HIGH_PRIMARY_CH)
                mode = IEEE80211_MODE_11AXG_HE40MINUS;
            else if (ch_params->sec_ch_offset == LOW_PRIMARY_CH)
                mode = IEEE80211_MODE_11AXG_HE40PLUS;
            break;
        default:
            mode = IEEE80211_MODE_AUTO;
            break;
    }

    return mode;
}

/**
 * ieee80211_convert_width_to_11axaflags() - Convert chan width to 11AXA flags.
 * @ic: Pointer to ieee80211com structure.
 * @ch_params: Pointer to channel params structure.
 *
 * Return: Return 11AXA flags.
 */
static inline enum ieee80211_phymode
ieee80211_convert_width_to_11axaflags(
        struct ieee80211com *ic,
        struct ch_params *ch_params)
{
    enum ieee80211_phymode mode = IEEE80211_MODE_AUTO;

    switch (ch_params->ch_width) {
        case CH_WIDTH_20MHZ:
            mode = IEEE80211_MODE_11AXA_HE20;
            break;
        case CH_WIDTH_40MHZ:
            if (ch_params->sec_ch_offset == HIGH_PRIMARY_CH)
                mode = IEEE80211_MODE_11AXA_HE40MINUS;
            else if (ch_params->sec_ch_offset == LOW_PRIMARY_CH)
                mode = IEEE80211_MODE_11AXA_HE40PLUS;
            break;
        case CH_WIDTH_80MHZ:
            mode = IEEE80211_MODE_11AXA_HE80;
            break;
        case CH_WIDTH_160MHZ:
            mode = IEEE80211_MODE_11AXA_HE160;
            break;
        case CH_WIDTH_80P80MHZ:
            mode = IEEE80211_MODE_11AXA_HE80_80;
            break;
        default:
            mode = IEEE80211_MODE_AUTO;
            break;
    }

    return mode;
}

enum ieee80211_phymode
ieee80211_get_target_channel_mode(
        struct ieee80211com *ic,
        struct ch_params *ch_params)
{
    enum ieee80211_phymode mode;

    if (IEEE80211_IS_CHAN_11NG(ic->ic_curchan))
        mode = ieee80211_convert_width_to_11ngflags(ic, ch_params);
    else if (IEEE80211_IS_CHAN_11NA(ic->ic_curchan))
        mode = ieee80211_convert_width_to_11naflags(ic, ch_params);
    else if (IEEE80211_IS_CHAN_11AC(ic->ic_curchan))
        mode = ieee80211_convert_width_to_11acflags(ic, ch_params);
    else if (IEEE80211_IS_CHAN_11AXG(ic->ic_curchan))
        mode = ieee80211_convert_width_to_11axgflags(ic, ch_params);
    else if (IEEE80211_IS_CHAN_11AXA(ic->ic_curchan))
        mode = ieee80211_convert_width_to_11axaflags(ic, ch_params);
    else
        mode = IEEE80211_MODE_AUTO;

    return mode;
}

#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
int ieee80211_dfs_rebuild_chan_list_with_non_dfs_channels(struct ieee80211com *ic)
{
    struct ieee80211_ath_channel *tmp_chans = NULL;
    int i,j, num_non_dfs_chans = 0;

    if (ic->ic_rebuilt_chanlist == 1) {
        qdf_print("%s: Channel list already rebuilt, avoiding another iteration",__func__);
        return 0;
    }
    /* Iterate through the ic_nchans and find num of non-DFS chans.*/
    num_non_dfs_chans = ieee80211_is_non_dfs_chans_available(ic);

    if (num_non_dfs_chans == 0) {
        qdf_print("Current country: 0x%x does not support any"
                "non-DFS channels",ic->ic_country.countryCode);
        return 1;
    }
    /* Ensure that we save the current channel's flags (HT/VHT mode) before
     * we do a memzero of ic channel list. This is to replenish to the same
     * mode after re-starting vaps with non-DFS channels.
     */
    ic->ic_curchan_flags = (ic->ic_curchan->ic_flags) & IEEE80211_CHAN_ALL;
    ic->ic_tmp_ch_width = regdmn_convert_chanflags_to_chanwidth(ic->ic_curchan);
    ic->ic_tmp_center_freq_seg0 = ic->ic_curchan->ic_vhtop_ch_num_seg1;
    ic->ic_tmp_center_freq_seg1 = ic->ic_curchan->ic_vhtop_ch_num_seg2;
    ic->ic_tmp_sec_ch_offset = regdmn_get_sec_ch_offset(ic->ic_curchan);

    ucfg_reg_enable_dfs_channels(ic->ic_pdev_obj, false);
    /* Allocating memory for tmp_chans from heap. This is due to stack overflow
     * if statically allocated as IEEE80211_CHAN_MAX = 1023 & each chan
     *structure occupies 16 Bytes (16 * 1023 = 16,638 Bytes).
     */
    tmp_chans = (struct ieee80211_ath_channel *) OS_MALLOC(ic->ic_osdev,
            num_non_dfs_chans * sizeof(struct ieee80211_ath_channel),
            GFP_KERNEL);

    if (tmp_chans == NULL) {
        qdf_print("%s.. Could not allocate memory for tmp chan list ",__func__);
        return (-ENOMEM);
    }

    OS_MEMZERO(tmp_chans, sizeof(num_non_dfs_chans *
                sizeof(struct ieee80211_ath_channel)));

    for (i = j = 0; i < ic->ic_nchans; i++) {
        if (!(IEEE80211_IS_CHAN_DFS(&ic->ic_channels[i])||
                    ((IEEE80211_IS_CHAN_11AC_VHT160(&ic->ic_channels[i]) ||
                      IEEE80211_IS_CHAN_11AC_VHT80_80(&ic->ic_channels[i])) &&
                     IEEE80211_IS_CHAN_DFS_CFREQ2(&ic->ic_channels[i])))) {
            OS_MEMCPY(&tmp_chans[j++], &(ic->ic_channels[i]),
                    sizeof(struct ieee80211_ath_channel));
        }
    }
    /*Copy the tmp_chans of only non-DFS channels to ic_channels list.*/
    OS_MEMZERO(&ic->ic_channels, sizeof(ic->ic_channels));
    OS_MEMCPY(ic->ic_channels, tmp_chans,
            sizeof(struct ieee80211_ath_channel) * num_non_dfs_chans);
    ic->ic_curchan = &ic->ic_channels[0];
    ic->ic_nchans = num_non_dfs_chans;
    ic->ic_rebuilt_chanlist = 1;
    ic->ic_tempchan = 1;
    OS_FREE(tmp_chans);
    return 0;
}
qdf_export_symbol(ieee80211_dfs_rebuild_chan_list_with_non_dfs_channels);
#endif /* HOST_DFS_SPOOF_TEST */

static int bw_val[CH_WIDTH_MAX+1] = {
    20,  /* CH_WIDTH_20MHZ */
    40,  /* CH_WIDTH_40MHZ */
    80,  /* CH_WIDTH_80MHZ */
    160, /* CH_WIDTH_160MHZ */
    80,  /* CH_WIDTH_80P80MHZ */
    5,   /* CH_WIDTH_5MHZ */
    10,  /* CH_WIDTH_10MHZ */
    0,   /* CH_WIDTH_INVALID */
    0,   /* CH_WIDTH_MAX */
};

/**
 * ieee80211_is_80p80mhz_supported() - Find if 80p80mhz mode is supported
 * by the frequency and the radio.
 * @ic: Pointer to ieee80211com.
 * @primary_freq: Primary frequency to check for 80p80 supported.
 * @sec_cfreq: Output secondary center frequency.
 * @sec_cieee: Output secondary center IEEE channel.
 *
 * Return true if there exists another 80MHz non contiguous channel for the
 * given frequency, else false.
 */
static bool ieee80211_is_80p80mhz_supported(struct ieee80211com *ic,
                                            qdf_freq_t primary_freq,
                                            qdf_freq_t *sec_cfreq,
                                            uint8_t *sec_cieee)
{
    struct ch_params tmp_ch_params = {0};
    int loop, index = 0;
    bool found_80p80mhz = false;
    struct wlan_objmgr_psoc *psoc;
    const uint16_t *mhz80_freq_list, *mhz80_chan_list;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc) {
        qdf_err("%s : psoc is null", __func__);
        return found_80p80mhz;
    }
#ifdef CONFIG_BAND_6GHZ
    if (WLAN_REG_IS_6GHZ_CHAN_FREQ(primary_freq)) {
        loop = CHAN_80MHZ_NUM_6G;
        mhz80_freq_list = mhz80_6g_freq_list;
        mhz80_chan_list = mhz80_6g_chan_list;
    } else
#endif
    {
        loop = CHAN_80MHZ_NUM_5G;
        mhz80_freq_list = mhz80_5g_freq_list;
        mhz80_chan_list = mhz80_5g_chan_list;
    }

    while (loop--) {
        tmp_ch_params.center_freq_seg1 = mhz80_chan_list[index];
        tmp_ch_params.mhz_freq_seg1 = mhz80_freq_list[index];
        tmp_ch_params.ch_width = CH_WIDTH_80P80MHZ;
        index++;

        ieee80211_regdmn_get_channel_params(ic->ic_pdev_obj,
                                            primary_freq,
                                            0,
                                            &tmp_ch_params);

        if (tmp_ch_params.ch_width != CH_WIDTH_80P80MHZ)
            continue;

        /*
         * If restricted 80p80 is enabled, check if the 80P80 channels
         * are within the 165MHz band, else do not select the 80P80 channel.
         */
        if (wlan_psoc_nif_fw_ext_cap_get(psoc,
                                         WLAN_SOC_RESTRICTED_80P80_SUPPORT) &&
            !(CHAN_WITHIN_RESTRICTED_80P80(tmp_ch_params.mhz_freq_seg0,
                                           tmp_ch_params.mhz_freq_seg1)))
            continue;

        found_80p80mhz = true;
        *sec_cieee = tmp_ch_params.center_freq_seg1;
        *sec_cfreq = tmp_ch_params.mhz_freq_seg1;
        break;
    }

    return found_80p80mhz;
}

/**
 * ieee80211_is_ht40_ext_supported() - Find if the HT40 ext mode (Plus/Minus)
 * is supported by the channel.
 *
 * @ic: Pointer to ieee80211com.
 * @chan_ext: Channel extension flag (PLUS/MINUS).
 * @primary_freq: Primary_frequency to check.
 *
 * Return true if the given ext flag is supported, else false.
 */
static bool ieee80211_is_ht40_ext_supported(struct ieee80211com *ic,
                                            uint32_t chan_ext,
                                            qdf_freq_t primary_freq)
{
    qdf_freq_t sec_ch_2g_freq = 0;
    struct ch_params tmp_ch_params = {0};

    tmp_ch_params.ch_width = CH_WIDTH_40MHZ;
    if (WLAN_REG_IS_24GHZ_CH_FREQ(primary_freq)) {
        switch (chan_ext) {
            case CHANNEL_40_PLUS:
                sec_ch_2g_freq = primary_freq + CHAN_HT40_OFFSET;
                break;
            case CHANNEL_40_MINUS:
                sec_ch_2g_freq = primary_freq - CHAN_HT40_OFFSET;
                break;
            default:
                return false;
        }
    }

    ieee80211_regdmn_get_channel_params(ic->ic_pdev_obj,
                                        primary_freq,
                                        sec_ch_2g_freq,
                                        &tmp_ch_params);

    if (tmp_ch_params.ch_width != CH_WIDTH_40MHZ)
        return false;

    if ((primary_freq < tmp_ch_params.mhz_freq_seg0) &&
        (chan_ext != CHANNEL_40_PLUS))
        return false;

    if ((primary_freq > tmp_ch_params.mhz_freq_seg0) &&
        (chan_ext != CHANNEL_40_MINUS))
        return false;

    return true;
}

void  wlan_reg_get_channel_flags(struct ieee80211com *ic,
                                 qdf_freq_t primary_freq,
                                 uint32_t *flags_ext,
                                 uint64_t *flags)
{
    uint64_t t_flags = 0;
    uint16_t t_flags_ext = 0;

    wlan_reg_get_chan_flags(ic->ic_pdev_obj, primary_freq, 0,
                                &t_flags_ext, &t_flags);

    if (t_flags & WLAN_CHAN_PASSIVE)
        *flags |= IEEE80211_CHAN_PASSIVE;

    if (t_flags_ext & WLAN_CHAN_DFS)
        *flags_ext |= IEEE80211_CHAN_DFS;

    if (t_flags_ext & WLAN_CHAN_PSC)
        *flags_ext |= IEEE80211_CHAN_PSC;

    if (t_flags_ext & WLAN_CHAN_DISALLOW_ADHOC)
        *flags_ext |= IEEE80211_CHAN_DISALLOW_ADHOC;

    if (t_flags_ext & WLAN_CHAN_DFS_CFREQ2)
        *flags_ext |= IEEE80211_CHAN_DFS_CFREQ2;
}

/**
 * ieee80211_set_modeflag_for_chan() - Get all supported flags
 * for the channel.
 * @ic: Pointer to ieee80211com.
 * @mode_supported: All modes supported by the device.
 * @chan_params: Channel params to be filled after getting supported modes.
 * @regchan: Regulatory channel information for the channel.
 * @flag_160: To fill 160/80MHz channel information.
 *
 * Return: flags indicating all supported modes for the channel.
 */
static uint64_t
ieee80211_set_modeflag_for_chan(struct ieee80211com *ic,
                                uint32_t mode_supported,
                                struct ch_params *chan_params,
                                struct regulatory_channel *regchan,
                                bool flag_160,
                                struct ieee80211_channel_info *chan_info)
{
    const struct reg_cmode *cm;
    uint64_t flags = 0;
    qdf_freq_t primary_freq = regchan->center_freq;

    chan_params->ch_width = CH_WIDTH_INVALID;

    /* If regulatory says no OFDM, ignore all the flags filled. */
    if (regchan->chan_flags & REGULATORY_CHAN_NO_OFDM) {
        if (chan_info)
            chan_info->flags |= (uint64_t)wlan_get_channel_flags(IEEE80211_CHAN_B);
        return IEEE80211_CHAN_B;
    }

    for (cm = modes; cm < &modes[QDF_ARRAY_SIZE(modes)]; cm++) {
        /* Check if curr mode is supported by the device and regulatory. */
        if (!(cm->mode & mode_supported)) {
            continue;
        }

        /* Check if current mode is valid for the frequency to be filled. */
        if (WLAN_REG_IS_6GHZ_CHAN_FREQ(primary_freq) &&
            (!(cm->mode & WIRELESS_6G_MODES)))
            continue;

        if (WLAN_REG_IS_5GHZ_CH_FREQ(primary_freq) &&
            (!(cm->mode & WIRELESS_5G_MODES)))
            continue;

        if (WLAN_REG_IS_24GHZ_CH_FREQ(primary_freq) &&
            (!(cm->mode & WIRELESS_2G_MODES)))
            continue;

        if (WLAN_REG_IS_49GHZ_FREQ(primary_freq) &&
            (!(cm->mode & WIRELESS_49G_MODES)))
            continue;

        /* Check if the current bandwidth is supported by the frequency. */
        if (!BW_WITHIN(regchan->min_bw, bw_val[cm->bw], regchan->max_bw))
            continue;

        /* Find if any other valid 80MHz exists if bandwidth is 80p80MHZ. */
        if (cm->bw == CH_WIDTH_80P80MHZ) {
            if (!ieee80211_is_80p80mhz_supported(ic,
                                                 primary_freq,
                                                 &chan_params->mhz_freq_seg1,
                                                 &chan_params->center_freq_seg1))
                continue;
        }

        /* See if the channel supports HT40PLUS or HT40MINUS. */
        if (cm->chan_ext != CHANNEL_40_NO) {
            if (!ieee80211_is_ht40_ext_supported(ic,
                                                 cm->chan_ext,
                                                 primary_freq))
                continue;
        }

        flags |= cm->flags;
        if (chan_info)
            chan_info->flags |= (uint64_t)wlan_get_channel_flags(cm->flags);

        /* Fill 160MHz channel information only if the flag is set. */
        if (flag_160 && cm->bw == CH_WIDTH_160MHZ)
            chan_params->ch_width = CH_WIDTH_160MHZ;

        /* Fill the channel information for the bw (maximum of 80/80p80). */
        if (!flag_160) {
            if (cm->bw == CH_WIDTH_80P80MHZ)
                chan_params->ch_width = CH_WIDTH_80P80MHZ;
            else if (cm->bw == CH_WIDTH_80MHZ &&
                     chan_params->ch_width != CH_WIDTH_80P80MHZ)
                chan_params->ch_width = CH_WIDTH_80MHZ;
        }
    }

    return flags;
}

/**
 * ieee80211_fill_athchan() - Fill the ath channel structure based on the
 * regulatory channel information.
 * @regchan: Regulatory channel information.
 * @chan_list: Ath channel structure to be filled.
 * @min_tx_power: Minimum tx power for the channel.
 * @max_tx_power: Maximum tx power for the channel.
 * @flags: Flags indicating supported modes by the channel.
 */
static void
ieee80211_fill_athchan(struct regulatory_channel *regchan,
                       struct ieee80211_ath_channel *chan_list,
                       int8_t min_tx_power,
                       int8_t max_tx_power,
                       uint64_t flags)
{
    chan_list->ic_ieee = regchan->chan_num;
    chan_list->ic_freq = regchan->center_freq;
    chan_list->ic_maxregpower = regchan->tx_power;
    chan_list->ic_antennamax = regchan->ant_gain;
    chan_list->ic_minpower = min_tx_power;
    chan_list->ic_maxpower = max_tx_power;
    chan_list->ic_flags = flags;
}

/**
 * ieee80211_set_seg_centers() - Fill the ath channel structure with segment
 * center IEEEs and frequencies.
 * @ic: Pointer to ieee80211com.
 * @chan_params: Channel params that will have the channel mode to be filled.
 * @chan_list: Ath channel structure to be filled.
 * @primary_freq: Primary frequency of the channel.
 */
static void
ieee80211_set_seg_centers(struct ieee80211com *ic,
                          struct ch_params *chan_params,
                          struct ieee80211_ath_channel *chan_list,
                          qdf_freq_t primary_freq)
{
    ieee80211_regdmn_get_channel_params(ic->ic_pdev_obj,
                                        primary_freq,
                                        0,
                                        chan_params);
    chan_list->ic_vhtop_ch_num_seg1 = chan_params->center_freq_seg0;
    chan_list->ic_vhtop_ch_num_seg2 = chan_params->center_freq_seg1;
    chan_list->ic_vhtop_freq_seg1 = chan_params->mhz_freq_seg0;
    chan_list->ic_vhtop_freq_seg2 = chan_params->mhz_freq_seg1;
}

static void ieee80211_fill_channel_info_list(
        struct ieee80211_channel_info *chan_info,
        uint8_t chan_num,
        qdf_freq_t primary_freq,
        uint8_t ch_num_seg1, uint8_t ch_num_seg2)
{
    chan_info->ieee = chan_num;
    chan_info->freq = primary_freq;
    chan_info->vhtop_ch_num_seg1 = ch_num_seg1;
    chan_info->vhtop_ch_num_seg2 = ch_num_seg2;
}

#define MAX_TX_POW (63) /* dBm units */
#define MIN_TX_POW (-64) /* dBm units */
void ieee80211_get_channel_list(
        struct ieee80211com *ic,
        struct ieee80211_ath_channel *chan_list,
        struct ieee80211_channel_info *chan_info,
        int *nchans,
        bool flag_160)
{
    uint32_t user_mode = 0, chip_mode, modes_supported;
    uint16_t phybitmap;
    struct regulatory_channel *cur_chan_list;
    int8_t max_tx_power = MAX_TX_POW, min_tx_power = MIN_TX_POW;
    int i;

    if (ic->ic_get_modeSelect) {
        user_mode = ic->ic_get_modeSelect(ic);
    }

    ieee80211_regdmn_get_chip_mode(ic->ic_pdev_obj, &chip_mode);

    modes_supported = (user_mode & chip_mode);

    /* Get the phymodes that are not supported by regulatory. */
    ieee80211_regdmn_get_phybitmap(ic->ic_pdev_obj, &phybitmap);
    ieee80211_regdmn_remove_phybitmap_from_modeselect(&modes_supported,
                                                      phybitmap);

    cur_chan_list = qdf_mem_malloc(NUM_CHANNELS * sizeof(*cur_chan_list));
    if (!cur_chan_list)
        return;

    if (wlan_reg_get_current_chan_list(
            ic->ic_pdev_obj, cur_chan_list) != QDF_STATUS_SUCCESS) {
        qdf_err("Failed to get cur_chan list");
        goto exit;
    }

    if (ic->ic_get_min_and_max_power)
        ic->ic_get_min_and_max_power(ic, &max_tx_power, &min_tx_power);

    for (i = 0; i < NUM_CHANNELS; i++)
    {
        struct ch_params chan_params = {0};
        uint64_t flags = 0;
        uint64_t mode_flags, band_flags;
        uint32_t flag_ext = 0;
        uint64_t half_and_quarter_rate_flags = 0;
        qdf_freq_t primary_freq = cur_chan_list[i].center_freq;

        /*
         * See if the channel is enabled or disabled due to radar temporarily.
         * If it's disabled by default (not by radar), ignore the channel.
         */
        if (wlan_reg_is_chan_disabled(&cur_chan_list[i]))
            continue;

        /* Fill the band flag for the channel. */
        if (WLAN_REG_IS_6GHZ_CHAN_FREQ(primary_freq)) {
            if (!(modes_supported & WIRELESS_6G_MODES))
                continue;
            band_flags = IEEE80211_CHAN_6GHZ;
        } else if (WLAN_REG_IS_24GHZ_CH_FREQ(primary_freq)) {
            if (!(modes_supported & WIRELESS_2G_MODES))
                continue;
            band_flags = IEEE80211_CHAN_2GHZ;
        } else if (WLAN_REG_IS_5GHZ_CH_FREQ(primary_freq)) {
            if (!(modes_supported & WIRELESS_5G_MODES))
                continue;
            band_flags = IEEE80211_CHAN_5GHZ;
        } else if (WLAN_REG_IS_49GHZ_FREQ(primary_freq)) {
            if (!(modes_supported & WIRELESS_49G_MODES))
                continue;
            band_flags = IEEE80211_CHAN_5GHZ;

            /* If 4.9G Half and Quarter rates are supported by the channel,
               update them as separate entries to the list */
            if (BW_WITHIN(cur_chan_list[i].min_bw, HALF_BW,
                          cur_chan_list[i].max_bw)) {
                flags = IEEE80211_CHAN_HALF | IEEE80211_CHAN_A;
                ieee80211_fill_athchan(&cur_chan_list[i], &chan_list[*nchans],
                                       min_tx_power, max_tx_power, flags);

                if (chan_info) {
                    ieee80211_fill_channel_info_list(&chan_info[*nchans],
                            cur_chan_list[i].chan_num, primary_freq, 0, 0);
                    chan_info[*nchans].flags |= (uint64_t)wlan_get_channel_flags(IEEE80211_CHAN_HALF);
                    chan_info[*nchans].flags |= (uint64_t)wlan_get_channel_flags(IEEE80211_CHAN_A);
                    half_and_quarter_rate_flags = chan_info[*nchans].flags;
                }

                if (++(*nchans) >= IEEE80211_CHAN_MAX)
                    break;
            }
            if (BW_WITHIN(cur_chan_list[i].min_bw, QRTR_BW,
                          cur_chan_list[i].max_bw)) {
                flags = IEEE80211_CHAN_QUARTER | IEEE80211_CHAN_A;
                ieee80211_fill_athchan(&cur_chan_list[i], &chan_list[*nchans],
                                       min_tx_power, max_tx_power, flags);

                if (chan_info) {
                    ieee80211_fill_channel_info_list(&chan_info[*nchans],
                            cur_chan_list[i].chan_num, primary_freq, 0, 0);
                    chan_info[*nchans].flags |= (uint64_t)wlan_get_channel_flags(IEEE80211_CHAN_QUARTER);
                    chan_info[*nchans].flags |= (uint64_t)wlan_get_channel_flags(IEEE80211_CHAN_A);
                    half_and_quarter_rate_flags = chan_info[*nchans].flags;
                }

                if (++(*nchans) >= IEEE80211_CHAN_MAX)
                    break;
            }
        } else {
            continue;
        }

        mode_flags = ieee80211_set_modeflag_for_chan(
                ic, modes_supported, &chan_params, &cur_chan_list[i], flag_160,
                (chan_info) ? &chan_info[*nchans] : NULL);

        wlan_reg_get_channel_flags(ic, primary_freq, &flag_ext, &flags);

        if (chan_info) {
            chan_info[*nchans].flags |= (uint64_t)wlan_get_channel_flags(band_flags);
            chan_info[*nchans].flags |= (uint64_t)wlan_get_channel_flags(flags);
            chan_info[*nchans].flags_ext |= wlan_get_channel_flags_ext(flag_ext);
            chan_info[*nchans].flags |= half_and_quarter_rate_flags;
        }

        flags |= mode_flags | band_flags;

        ieee80211_fill_athchan(&cur_chan_list[i], &chan_list[*nchans],
                               min_tx_power, max_tx_power, flags);

        if (chan_params.ch_width != CH_WIDTH_INVALID)
            ieee80211_set_seg_centers(ic, &chan_params, &chan_list[*nchans],
                                      primary_freq);

        if (chan_info) {
            ieee80211_fill_channel_info_list(&chan_info[*nchans],
                    cur_chan_list[i].chan_num, primary_freq, chan_params.center_freq_seg0,
                    chan_params.center_freq_seg1);
        }

        chan_list[*nchans].ic_flagext = flag_ext;

        if (++(*nchans) >= IEEE80211_CHAN_MAX)
            break;
    }

exit:
    qdf_mem_free(cur_chan_list);
    return;
}

static void
ieee80211_get_subchan(struct ieee80211_ath_channel *chan, qdf_freq_t *sub_chan_freqs, uint8_t *nchans)
{
	qdf_freq_t center_freq;
	uint16_t ch_width = ieee80211_get_chan_width(chan);
	switch (ch_width) {
		case 20:
			center_freq = chan->ic_vhtop_freq_seg1;
			sub_chan_freqs[0] = center_freq;
			*nchans = 1;
			break;
		case 40:
			center_freq = chan->ic_vhtop_freq_seg1;
			sub_chan_freqs[0] = center_freq - 10;
			sub_chan_freqs[1] = center_freq + 10;
			*nchans = 2;
			break;
		case 80:
			center_freq = chan->ic_vhtop_freq_seg1;
			sub_chan_freqs[0] = center_freq - 30;
			sub_chan_freqs[1] = center_freq - 10;
			sub_chan_freqs[2] = center_freq + 10;
			sub_chan_freqs[3] = center_freq + 30;
			*nchans = 4;
			break;
		case 160:
			if (IEEE80211_IS_CHAN_11AXA_HE160(chan) || IEEE80211_IS_CHAN_11AC_VHT160(chan)) {
				center_freq = chan->ic_vhtop_freq_seg2;
				sub_chan_freqs[0] = center_freq - 70;
				sub_chan_freqs[1] = center_freq - 50;
				sub_chan_freqs[2] = center_freq - 30;
				sub_chan_freqs[3] = center_freq - 10;
				sub_chan_freqs[4] = center_freq + 10;
				sub_chan_freqs[5] = center_freq + 30;
				sub_chan_freqs[6] = center_freq + 50;
				sub_chan_freqs[7] = center_freq + 70;
				*nchans = 8;
			} else {
				center_freq = chan->ic_vhtop_freq_seg1;
				sub_chan_freqs[0] = center_freq - 30;
				sub_chan_freqs[1] = center_freq - 10;
				sub_chan_freqs[2] = center_freq + 10;
				sub_chan_freqs[3] = center_freq + 30;
				center_freq = chan->ic_vhtop_freq_seg2;
				sub_chan_freqs[4] = center_freq - 30;
				sub_chan_freqs[5] = center_freq - 10;
				sub_chan_freqs[6] = center_freq + 10;
				sub_chan_freqs[7] = center_freq + 30;
				*nchans = 8;
			}
			break;
	}
}

bool ieee80211_is_chan_radar(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
	qdf_freq_t sub_chan_freqs[8];
	uint8_t nchans;
	uint8_t i;

	if (!chan || !IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(chan))
		return false;
	ieee80211_get_subchan(chan, sub_chan_freqs, &nchans);
	for (i = 0; i < nchans; i++) {
		if(wlan_reg_is_nol_for_freq(ic->ic_pdev_obj, sub_chan_freqs[i]))
			return true;
	}
	return false;
}

bool ieee80211_is_chan_nol_history(struct ieee80211com *ic, struct ieee80211_ath_channel *chan)
{
	qdf_freq_t sub_chan_freqs[8];
	uint8_t nchans;
	uint8_t i;

	if (!chan || !IEEE80211_IS_PRIMARY_OR_SECONDARY_CHAN_DFS(chan))
		return false;
	ieee80211_get_subchan(chan, sub_chan_freqs, &nchans);
	for (i = 0; i < nchans; i++) {
		if(wlan_reg_is_nol_hist_for_freq(ic->ic_pdev_obj, sub_chan_freqs[i]))
			return true;
	}
	return false;
}

void ieee80211_get_default_psd_power(struct ieee80211vap *vap,
                                     enum reg_6g_client_type client_type,
                                     uint8_t *psd_pwr)
{
   struct ieee80211com *ic = vap->iv_ic;
   u_int8_t phy_chwidth, chwidth;
   enum reg_6g_ap_type ap_device_type;

   if(vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
      phy_chwidth = vap->iv_chwidth;
   } else {
      phy_chwidth = ic->ic_cwm_get_width(ic);
   }

   /* Update with actual BW setting value.
    * For instance:
    * chwidth = 20 in case AP BW is 20MHz
    */
   chwidth = wlan_reg_get_bw_value(phy_chwidth);
   ucfg_reg_get_cur_6g_ap_pwr_type(ic->ic_pdev_obj, &ap_device_type);
   wlan_reg_get_max_txpower_for_6g_tpe(ic->ic_pdev_obj,
                                       ic->ic_curchan->ic_freq,
                                       chwidth, ap_device_type,
                                       client_type, true,
                                       psd_pwr);
}
