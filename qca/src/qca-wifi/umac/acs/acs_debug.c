/*
 * Copyright (c) 2018, 2020-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Description:
 * The ACS debug framework enabled the testing and validation of the ACS
 * algorithm by the use of custom beacon and channel events which are injected
 * from the userspace to the driver
 */

#include <ieee80211_defines.h>
#include <wlan_scan_tgt_api.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <wlan_utility.h>

#include "acs_debug.h"

/*
 * process_phymode:
 * Takes the phymode value and accordingly adds flags to manage IE additions
 * as well as populating the said IEs. This is done in accordance to the
 * wlan_phymode enums
 *
 * Parameters:
 * ic_acs     : Pointer to the ACS structure
 * bcn        : The pointer to the beacon database
 * bcn_phymode: The phymode value to manipulate IEs
 * chan_num   : Primary channel number
 * secch_1    : Value of the VHTop secondary channel (segment 1)
 * secch_2    : Value of the VHTop secondary channel (segment 2)
 *
 * Return:
 * -1: Error
 *  0: Success
 */
static int process_phymode(ieee80211_acs_t ic_acs,
                           struct acs_debug_bcn_event *bcn, uint32_t wlan_phymode,
                           uint8_t chan_num, uint8_t band, uint8_t secch_1,
                           uint8_t secch_2)
{
    int8_t ret = ACSDBG_SUCCESS;
    int8_t offset_ret = 0;
    struct ieee80211_ath_channel *chan = NULL;
    struct heop_6g_param *heop_6g = NULL;
    enum ieee80211_phymode phymode = wlan_vdev_get_ieee_phymode(wlan_phymode);
    uint16_t freq = wlan_reg_chan_band_to_freq(ic_acs->acs_ic->ic_pdev_obj, chan_num,
                                               wlan_band_id_to_reg_wifi_band(band));

    switch (phymode) {
        /* Legacy Phymodes */
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
            bcn->is_dot11abg |= IS_DOT_11A;
            break;
        case IEEE80211_MODE_11B:
            bcn->is_dot11abg |= IS_DOT_11B;
            break;
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_FH:
        case IEEE80211_MODE_TURBO_G:
            bcn->is_dot11abg |= IS_DOT_11G;
            break;

        /* HT Phymodes  */
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
            /*
             * There is no need to populate HTcap specifically
             * For 11NA_HT20 and 11NG_HT20, just the presence of
             * the htcap IE is enough which will be added
             * since the is_dot11abg flag is not set
             */
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_20;
            break;
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            bcn->htcap.hc_ie.hc_cap |= WLAN_HTCAP_C_CHWIDTH40;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE)
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            else if (offset_ret == EXT_CHAN_OFFSET_BELOW)
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;
            break;
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
            bcn->htcap.hc_ie.hc_cap |= WLAN_HTCAP_C_CHWIDTH40;
            bcn->htinfo.hi_ie.hi_extchoff = WLAN_HTINFO_EXTOFFSET_ABOVE;
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;
            break;
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
            bcn->htcap.hc_ie.hc_cap        |= WLAN_HTCAP_C_CHWIDTH40;
            bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040 ;
            break;

        /* VHT Phymodes */
        case IEEE80211_MODE_11AC_VHT20:
            bcn->is_dot11acplus = 1;
            bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_2040;
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_20;
            break;
        case IEEE80211_MODE_11AC_VHT40:
            bcn->is_dot11acplus = 1;
            bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_2040;
            bcn->htcap.hc_ie.hc_cap  |= WLAN_HTCAP_C_CHWIDTH40;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            } else if (offset_ret == EXT_CHAN_OFFSET_BELOW) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            }
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;
            break;
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
            bcn->is_dot11acplus = 1;
            bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_2040;
            bcn->htcap.hc_ie.hc_cap |= WLAN_HTCAP_C_CHWIDTH40;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            } else if (offset_ret == EXT_CHAN_OFFSET_BELOW) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            }
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;
            break;
        case IEEE80211_MODE_11AC_VHT80:
            bcn->is_dot11acplus = 1;
            bcn->htcap.hc_ie.hc_cap |= WLAN_HTCAP_C_CHWIDTH40;
            bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_80;
            bcn->vhtop.vht_op_ch_freq_seg1 = secch_1;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            } else if (offset_ret == EXT_CHAN_OFFSET_BELOW) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            }
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;
            break;
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            bcn->is_dot11acplus = 1;
            bcn->htcap.hc_ie.hc_cap |= WLAN_HTCAP_C_CHWIDTH40;
            if (ieee80211_is_phymode_11ac_vht160(phymode))
                bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_160;
            else
                bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_80_80;
            bcn->vhtop.vht_op_ch_freq_seg1 = secch_1;
            bcn->vhtop.vht_op_ch_freq_seg2 = secch_2;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            } else if (offset_ret == EXT_CHAN_OFFSET_BELOW) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            }
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;
            break;

        /* HE Phymodes */
        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXG_HE20:
            bcn->is_dot11acplus = 1;
            bcn->is_dot11axplus = 1;
	    bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_2040;
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_20;

            if (band == WLAN_BAND_6GHZ) {
                /*
                 * For 6GHz, we will need to remove the HT and VHT information
                 * from the beacons.
                 */
                bcn->is_dot11acplus = 0;
                bcn->is_6ghz = 1;

                heop_6g = ieee80211_get_he_6g_opinfo(&(bcn->heop));
                if (!heop_6g) {
                    qdf_err("Could not retrieve HE 6GHz opinfo");
                    ret = ACSDBG_ERROR;
                    break;
                }

                heop_6g->channel_width = WLAN_HE_6GHZ_CHWIDTH_20;
            }
            break;
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXG_HE40:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
            bcn->is_dot11acplus = 1;
            bcn->is_dot11axplus = 1;
            bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_2040;
            bcn->htcap.hc_ie.hc_cap  |= WLAN_HTCAP_C_CHWIDTH40;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            } else if (offset_ret == EXT_CHAN_OFFSET_BELOW) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            }
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;

            if (band == WLAN_BAND_6GHZ) {
                /*
                 * For 6GHz, we will need to remove the HT and VHT information
                 * from the beacons.
                 */
                bcn->is_dot11acplus = 0;
                bcn->is_6ghz = 1;

                heop_6g = ieee80211_get_he_6g_opinfo(&(bcn->heop));
                if (!heop_6g) {
                    qdf_err("Could not retrieve HE 6GHz opinfo");
                    ret = ACSDBG_ERROR;
                    break;
                }

                heop_6g->channel_width = WLAN_HE_6GHZ_CHWIDTH_40;
            }
            break;
        case IEEE80211_MODE_11AXA_HE80:
            bcn->is_dot11acplus = 1;
            bcn->is_dot11axplus = 1;

            bcn->htcap.hc_ie.hc_cap |= WLAN_HTCAP_C_CHWIDTH40;
            bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_80;
            bcn->vhtop.vht_op_ch_freq_seg1 = secch_1;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            } else if (offset_ret == EXT_CHAN_OFFSET_BELOW) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            }
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;

            if (band == WLAN_BAND_6GHZ) {
                /*
                 * For 6GHz, we will need to remove the HT and VHT information
                 * from the beacons.
                 */
                bcn->is_dot11acplus = 0;
                bcn->is_6ghz = 1;

                heop_6g = ieee80211_get_he_6g_opinfo(&(bcn->heop));
                if (!heop_6g) {
                    qdf_err("Could not retrieve HE 6GHz opinfo");
                    ret = ACSDBG_ERROR;
                    break;
                }

                heop_6g->chan_cent_freq_seg0 = secch_1;
                heop_6g->channel_width = WLAN_HE_6GHZ_CHWIDTH_80;
            }
            break;
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AXA_HE80_80:
            bcn->is_dot11acplus = 1;
            bcn->is_dot11axplus = 1;

            bcn->htcap.hc_ie.hc_cap |= WLAN_HTCAP_C_CHWIDTH40;
            if (ieee80211_is_phymode_11axa_he160(phymode))
                bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_160;
            else
                bcn->vhtop.vht_op_chwidth = WLAN_VHTOP_CHWIDTH_80_80;
            bcn->vhtop.vht_op_ch_freq_seg1 = secch_1;
            bcn->vhtop.vht_op_ch_freq_seg2 = secch_2;
            chan = ieee80211_find_dot11_channel(ic_acs->acs_ic, freq, 0, phymode);
            offset_ret = ieee80211_secondary20_channel_offset(chan);
            if (offset_ret == EXT_CHAN_OFFSET_ABOVE) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_ABOVE;
            } else if (offset_ret == EXT_CHAN_OFFSET_BELOW) {
                bcn->htinfo.hi_ie.hi_extchoff   = WLAN_HTINFO_EXTOFFSET_BELOW;
            }
            bcn->htinfo.hi_ie.hi_txchwidth = IEEE80211_HTINFO_TXWIDTH_2040;

            if (band == WLAN_BAND_6GHZ) {
                /*
                 * For 6GHz, we will need to remove the HT and VHT information
                 * from the beacons.
                 */
                bcn->is_dot11acplus = 0;
                bcn->is_6ghz = 1;

                heop_6g = ieee80211_get_he_6g_opinfo(&(bcn->heop));
                if (!heop_6g) {
                    qdf_err("Could not retrieve HE 6GHz opinfo");
                    ret = ACSDBG_ERROR;
                    break;
                }

                heop_6g->chan_cent_freq_seg0 = secch_1;
                heop_6g->chan_cent_freq_seg1 = secch_2;
                heop_6g->channel_width = WLAN_HE_6GHZ_CHWIDTH_160_80_80;
           }
           break;

        /* Invalid Phymode */
        default:
            ret = ACSDBG_ERROR;
            break;
    }

    return ret;
}

/*
 * acs_debug_create_bcndb:
 * Takes the beacon information sent from the userspace and creates a database
 * of al lthe beacons which is kept ready to be injected into the ACS algorithm
 *
 * Parameters:
 * ic_acs : Pointer to the ACS structure
 * bcn_raw: Pointer to the raw beacon information sent from the userspace
 *
 * Return:
 * -1: Error
 *  0: Success
 */
int acs_debug_create_bcndb(ieee80211_acs_t ic_acs,
                           struct acs_debug_raw_bcn_event_container *bcn_raw)
{
    uint8_t ix, index;
    int8_t  ret = 0;
    struct acs_debug_bcn_event_container **bcn = NULL, *bcn_new = NULL;
#if SUPPORT_11AX_D3
    uint32_t heop_param = 0;
#else
    struct he_op_param heop_param = {0};
#endif
    struct heop_6g_param *heop_6g = NULL;
    u_int8_t *hecap_phy_info;

    bcn = (struct acs_debug_bcn_event_container **)&ic_acs->acs_debug_bcn_events;

    if (!bcn_raw) {
        qdf_info("There are no beacons sent from the tool to inject");

        /*
         * Even if there are no beacons to be injected, clear out the old ones
         */
        if (*bcn) {
            qdf_info("Clearing old beacon data");
            qdf_mem_free(*bcn);
            *bcn = NULL;
        }

        return ACSDBG_ERROR;
    }

    bcn_raw->event = (struct acs_debug_raw_bcn_event *)((void *)bcn_raw + sizeof(*bcn_raw));

    if((*bcn) && (bcn_raw->is_first_bcn_block)) {
        /*
         * On multiple invocations of the ACS tool, it will always reallocate
         * the existing space instead of allocating new memory
         */
        qdf_info("Clearing old beacon data");
        qdf_mem_free(*bcn);
        *bcn = NULL;
    }

    if (bcn_raw->is_first_bcn_block) {
        *bcn = qdf_mem_malloc(sizeof(**bcn) + (bcn_raw->nbss * sizeof(struct acs_debug_bcn_event)));
        if (!(*bcn)) {
            qdf_err("Beacon allocation failed!");
            return ACSDBG_ERROR;
        }

        (*bcn)->nbss  = 0;
        (*bcn)->event = (struct acs_debug_bcn_event *)((void *)(*bcn) + sizeof(**bcn));
    } else {
        /* Enter this path only if bcn is non-NULL */
        if (!(*bcn)) {
            qdf_err("Beacon data is not valid");
            return ACSDBG_ERROR;
        }

        bcn_new = qdf_mem_malloc(sizeof(**bcn) + ((*bcn)->nbss * sizeof(struct acs_debug_bcn_event)) +
                                  (bcn_raw->nbss * sizeof(struct acs_debug_bcn_event)));
        if (!bcn_new) {
            qdf_err("New beacon allocation failed");
            return ACSDBG_ERROR;
        }

        qdf_mem_copy(bcn_new, *bcn, (sizeof(**bcn) + ((*bcn)->nbss * sizeof(struct acs_debug_bcn_event))));
        qdf_mem_free(*bcn);
        *bcn    = bcn_new;
        (*bcn)->event = (struct acs_debug_bcn_event *)((void *)(*bcn) + sizeof(**bcn));
        bcn_new = NULL;
    }

    for (ix = 0; !ret && ix < bcn_raw->nbss; ix++) {
        index = ix;
        if (!bcn_raw->is_first_bcn_block) {
            /* If not the first block, then offset the index accordingly */
            index = ix + (*bcn)->nbss;
        }

        (*bcn)->event[index].is_dot11abg    = 0;
        (*bcn)->event[index].is_dot11acplus = 0;
        (*bcn)->event[index].is_dot11axplus = 0;
        (*bcn)->event[index].is_6ghz        = 0;
        (*bcn)->event[index].is_srp         = 0;
        (*bcn)->event[index].srp.sr_control = 0;

        /*
         * Initializing the heop params before processing the phymode:
         * This will be required to populate the secondary channel information
         * in the 6g opinfo of the HEOP IE
         */
#if SUPPORT_11AX_D3
	HEOP_PARAM_VHT_OP_INFO_SET(&heop_param,1);
	HEOP_PARAM_CO_LOCATED_BSS_SET(&heop_param,1);
	HEOP_PARAM_OP_6G_INFO_PRESENT_SET(&heop_param,1);
#else
	heop_param.vht_op_info_present = 1;
#endif
        qdf_mem_copy((*bcn)->event[index].heop.heop_param, &heop_param,
                     sizeof((*bcn)->event[index].heop.heop_param));

        if (process_phymode(ic_acs, &(*bcn)->event[index], bcn_raw->event[ix].phymode,
                            bcn_raw->event[ix].channel_number,
                            bcn_raw->band,
                            bcn_raw->event[ix].sec_chan_seg1,
                            bcn_raw->event[ix].sec_chan_seg2)) {
            qdf_info("Could not process phymode");
            ret = ACSDBG_ERROR;
            break;
        }

        qdf_mem_copy((*bcn)->event[index].ssid.ssid, bcn_raw->event[ix].ssid,
                     strlen(bcn_raw->event[ix].ssid));

        (*bcn)->event[index].freq = wlan_reg_chan_band_to_freq(ic_acs->acs_ic->ic_pdev_obj,
                                                               bcn_raw->event[ix].channel_number,
                                                               wlan_band_id_to_reg_wifi_band(bcn_raw->band));
        (*bcn)->event[index].ds.current_channel = bcn_raw->event[ix].channel_number;
        (*bcn)->event[index].htinfo.hi_ie.hi_ctrlchannel = bcn_raw->event[ix].channel_number;
        qdf_mem_copy((*bcn)->event[index].i_addr3, bcn_raw->event[ix].bssid, QDF_MAC_ADDR_SIZE);
        qdf_mem_copy((*bcn)->event[index].i_addr2, bcn_raw->event[ix].bssid, QDF_MAC_ADDR_SIZE);
        (*bcn)->event[index].rssi = bcn_raw->event[ix].rssi;
        (*bcn)->event[index].is_srp = bcn_raw->event[ix].srpen;

        if ((*bcn)->event[index].is_srp) {
            hecap_phy_info =
                 &(*bcn)->event[index].hecap.hecap_phyinfo[HECAP_PHYBYTE_IDX0];

            hecap_phy_info[HECAP_PHYBYTE_IDX7] |=
                                            bcn_raw->event[ix].srp_allowed;
            (*bcn)->event[index].srp.sr_control |=
                                     !bcn_raw->event[ix].client_srp_allowed &
                                     IEEE80211_PSR_DISALLOWED_MASK;
            (*bcn)->event[index].srp.sr_control |=
                             (!bcn_raw->event[ix].client_obsspd_allowed << 1) &
                             IEEE80211_SRP_NON_SRG_OBSS_PD_SR_DISALLOWED_MASK;
        }

        if ((*bcn)->event[index].is_6ghz) {
            heop_6g = ieee80211_get_he_6g_opinfo(&((*bcn)->event[index].heop));
            if (!heop_6g) {
                qdf_err("Could not retrieve HE 6g params");
                ret = ACSDBG_ERROR;
                break;
            }

            heop_6g->primary_channel = bcn_raw->event[ix].channel_number;
        }
    }

    if (!ret) {
        (*bcn)->nbss += bcn_raw->nbss;
        qdf_info("Populated ACS beacon events (debug framework)");
    } else {
        /*
         * In error cases, if there was memory allocated we are freeing them
         * here.
         */
        if (*bcn) {
            qdf_mem_free(*bcn);
            *bcn = NULL;
        }

        qdf_info("Could not populate ACS beacon events (debug framework)");
    }

    /*
     * Memory will not be freed here because it is kept in a debug structure
     * within the ic-level ACS structure. Until the wifi is unloaded or
     * if there is another report that is sent in from the userspace
     * the database will remain.
     */
    return ret;
}

/*
 * init_bcn:
 * Initializes all the IEs regardless of what is going to be added to the
 * particular beacon for IE ID and length which are static
 *
 * Parameters:
 * bcn: Pointer to the beacon database
 *
 * Returns:
 * None
 */
void init_bcn(struct acs_debug_bcn_event *bcn)
{
    bcn->ssid.ssid_id = WLAN_ELEMID_SSID;
    /* Keep the SSID IE length dynamic */
    bcn->ssid.ssid_len = strlen(bcn->ssid.ssid);

    bcn->rates.rate_id = WLAN_ELEMID_RATES;
    bcn->rates.rate_len = sizeof(struct ieee80211_ie_rates) - sizeof(struct ie_header);

    bcn->xrates.xrate_id = WLAN_ELEMID_XRATES;
    /*
     * We are selecting an arbitrary number between 0-255 so as to fit it
     * in the 8-bit unsigned xrate_len since the regular size is 256 bytes.
     * The framework is only concerned with the presence of the IE and not it's
     * content.
     */
    bcn->xrates.xrate_len = ACS_DEBUG_XRATES_NUM;

    bcn->ds.ie = WLAN_ELEMID_DSPARMS;
    bcn->ds.len = sizeof(struct ieee80211_ds_ie) - sizeof(struct ie_header);

    bcn->htinfo.hi_id = WLAN_ELEMID_HTINFO_ANA;
    bcn->htinfo.hi_len = sizeof(struct ieee80211_ie_htinfo) - sizeof(struct ie_header);

    bcn->htcap.hc_id = WLAN_ELEMID_HTCAP_ANA;
    bcn->htcap.hc_len = sizeof(struct ieee80211_ie_htcap) - sizeof(struct ie_header);

    bcn->vhtcap.elem_id = WLAN_ELEMID_VHTCAP;
    bcn->vhtcap.elem_len = sizeof(struct ieee80211_ie_vhtcap) - sizeof(struct ie_header);

    bcn->vhtop.elem_id = WLAN_ELEMID_VHTOP;
    bcn->vhtop.elem_len = sizeof(struct ieee80211_ie_vhtop) - sizeof(struct ie_header);

    bcn->srp.srp_id = WLAN_ELEMID_EXTN_ELEM;
    bcn->srp.srp_id_extn = WLAN_EXTN_ELEMID_SRP;
    bcn->srp.srp_len =  sizeof(struct ieee80211_ie_srp_extie) - sizeof(struct ie_header);

    bcn->hecap.elem_id = IEEE80211_ELEMID_EXTN;
    bcn->hecap.elem_id_ext = IEEE80211_ELEMID_EXT_HECAP;
    bcn->hecap.elem_len = sizeof(struct ieee80211_ie_hecap) - sizeof(struct ie_header);

    bcn->heop.elem_id = IEEE80211_ELEMID_EXTN;
    bcn->heop.elem_id_ext = IEEE80211_ELEMID_EXT_HEOP;
    bcn->heop.elem_len = sizeof(struct ieee80211_ie_heop) - sizeof(struct ie_header);
}

/*
 * acs_debug_add_bcn:
 * Injects the custom beacons into the ACS algorithm by creating a scan_entry
 * for the custom-user-defined BSSIDs
 *
 * Parameters:
 * soc: Pointer to the SoC object
 * ic : Pointer to the radio_level ic structure
 * ieee_chan_freq: Frequency of the current channel
 *
 * Return:
 * -1: Error
 *  0: Success
 */
int acs_debug_add_bcn(ol_ath_soc_softc_t *soc, struct ieee80211com *ic,
                      uint32_t ieee_chan_freq)
{
    struct wlan_objmgr_psoc *psoc = soc->psoc_obj;
    struct ie_header *ie;
    struct wlan_frame_hdr *hdr;
    struct mgmt_rx_event_params rx_param = {0};
    qdf_nbuf_t buf;

    uint32_t frame_len;
    uint8_t ix;
    int8_t  ret = 0;

    struct acs_debug_bcn_event_container *bcn =
                  (struct acs_debug_bcn_event_container *)ic->ic_acs->acs_debug_bcn_events;

    if (!bcn) {
        qdf_debug("%s: There are no custom-beacons to inject", __func__);
        return ACSDBG_ERROR;
    }


   for (ix = 0; !ret && ix < bcn->nbss; ix++) {

       if (bcn->event[ix].freq != ieee_chan_freq) {
           /* Skipping beacons which are not for this channel */
           continue;
       }

       init_bcn(&bcn->event[ix]);

       /* Setting the standard frame length for the custom beacon */
       frame_len = sizeof(struct wlan_frame_hdr) + sizeof(struct wlan_bcn_frame)
                   + bcn->event[ix].ssid.ssid_len
                   + sizeof(struct ieee80211_ie_rates);

       if (!bcn->event[ix].is_6ghz) {
           /* For 6GHz, channel id is taken from the HEOP IE */
           frame_len += sizeof(struct ieee80211_ds_ie);
       }

       if (!bcn->event[ix].is_dot11abg && !bcn->event[ix].is_6ghz) {
           frame_len += sizeof(struct ieee80211_ie_htcap)
                        + sizeof(struct ieee80211_ie_htinfo);
       }

       if (bcn->event[ix].is_dot11abg & IS_DOT_11G) {
           /*
            * Can't take the size of the IE directly since the size of the rates
            * array is 256 which is larger than what the 8-bit value of xrate_len
            * can hold.
            */
           frame_len += sizeof(struct ie_header) + bcn->event[ix].xrates.xrate_len;
       }

       if (bcn->event[ix].is_dot11acplus) {
           frame_len += sizeof(struct ieee80211_ie_vhtcap)
                        + sizeof(struct ieee80211_ie_vhtop);
       }

       if (bcn->event[ix].is_dot11axplus) {
           frame_len += sizeof(struct ieee80211_ie_hecap)
                      + sizeof(struct ieee80211_ie_heop);
       }

       if (bcn->event[ix].is_srp) {
           frame_len += sizeof(struct ieee80211_ie_srp_extie);
       }

       buf = qdf_nbuf_alloc(soc->qdf_dev, frame_len, 0, 0, FALSE);
       if (!buf) {
           qdf_info("%s: Buffer allocation failed", __func__);
           ret = ACSDBG_ERROR;
           continue;
       }

       qdf_nbuf_set_pktlen(buf, frame_len);
       qdf_mem_zero((uint8_t *)qdf_nbuf_data(buf), frame_len);

       hdr = (struct wlan_frame_hdr *)qdf_nbuf_data(buf);
       qdf_mem_copy(hdr->i_addr3, bcn->event[ix].i_addr3, QDF_MAC_ADDR_SIZE);
       qdf_mem_copy(hdr->i_addr2, bcn->event[ix].i_addr2, QDF_MAC_ADDR_SIZE);

       /*
        * NOTE: The ACS algorithm doesn't use RSSI anymore. Instead it
        * uses the SNR value from the scan entry.
        */
       rx_param.snr       = bcn->event[ix].rssi;
       /*
        * ICM algorithm uses the RSSI value. It is expected to be a negative
        * value, compared to the positive SNR value for ACS.
        */
       rx_param.rssi      = bcn->event[ix].rssi;
       rx_param.channel   = bcn->event[ix].ds.current_channel;
       rx_param.chan_freq = bcn->event[ix].freq;
       rx_param.pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);

       ie = (struct ie_header *)(((uint8_t *)qdf_nbuf_data(buf))
                                  + sizeof(struct wlan_frame_hdr)
                                  + offsetof(struct wlan_bcn_frame, ie));

       ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].ssid,  bcn->event[ix].ssid.ssid_len);
       ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].rates, bcn->event[ix].rates.rate_len);

       if (!bcn->event[ix].is_6ghz) {
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].ds, bcn->event[ix].ds.len);
       }

       if (!bcn->event[ix].is_dot11abg && !bcn->event[ix].is_6ghz) {
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].htcap,  bcn->event[ix].htcap.hc_len);
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].htinfo, bcn->event[ix].htinfo.hi_len);
       }

       if (bcn->event[ix].is_dot11abg & IS_DOT_11G) {
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].xrates, bcn->event[ix].xrates.xrate_len);
       }

       if (bcn->event[ix].is_dot11acplus) {
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].vhtcap, bcn->event[ix].vhtcap.elem_len);
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].vhtop,  bcn->event[ix].vhtop.elem_len);
       }

       if (bcn->event[ix].is_dot11axplus) {
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].hecap, bcn->event[ix].hecap.elem_len);
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].heop,  bcn->event[ix].heop.elem_len);
       }

       if (bcn->event[ix].is_srp) {
           ACS_DEBUG_POPULATE_IE(ie, bcn->event[ix].srp, bcn->event[ix].srp.srp_len);
       }

       if (tgt_scan_bcn_probe_rx_callback(psoc, NULL, buf, &rx_param,
                                          MGMT_BEACON)) {
           qdf_info("Could not send beacon \"%s\"", bcn->event[ix].ssid.ssid);
           ret = ACSDBG_ERROR;
           continue;
       }

   }

   /*
    * Memory will not be freed here because it is kept in a debug structure
    * within the ic-level ACS structure. Until the wifi is unloaded or
    * if there is another report that is sent in from the userspace
    * the database will remain.
    */
   return ret;
}

/*
 * acs_debug_create_chandb:
 * This API takes the channel information from the userspace and creates a
 * database of all the channel statistics which is kept ready to be injected
 * into the ACS algorithm
 *
 * Parameters:
 * ic_acs: Pointer to the ACS structure
 * chan_raw: Pointer to the raw channel information sent from the userspace
 *
 * Return:
 * -1: Error
 *  0: Success
 */
int acs_debug_create_chandb(ieee80211_acs_t ic_acs,
                            struct acs_debug_raw_chan_event_container *chan_raw)
{

    struct acs_debug_chan_event_container **chan = NULL, *chan_new = NULL;
    uint8_t ix, index;

    chan = (struct acs_debug_chan_event_container **)&ic_acs->acs_debug_chan_events;

    if (!chan_raw) {
        qdf_info("There are no channel events to inject");

        if (*chan) {
             /*
              * Even if there are no channel events, delete existing ones
              */
             qdf_info("Clearing old channel data");
             qdf_mem_free(*chan);
             *chan = NULL;
        }

        return ACSDBG_ERROR;
    }

    chan_raw->event = (struct acs_debug_raw_chan_event *)((void *)chan_raw + sizeof(*chan_raw));

    if ((*chan) && (chan_raw->is_first_chan_event_block)) {
        /*
         * If we are running the tool multiple times, it will delete the old
         * database before populating the new one, preventing excess memory
         * usage
         */
        qdf_info("Clearing old channel data");
        qdf_mem_free(*chan);
        *chan = NULL;
    }

    if (chan_raw->is_first_chan_event_block) {
        *chan = qdf_mem_malloc(sizeof(**chan) + (chan_raw->nchan * sizeof(struct acs_debug_chan_event)));
        if (!(*chan)) {
            qdf_err("Channel allocation failed");
            return ACSDBG_ERROR;
        }

        qdf_mem_zero(*chan, sizeof(**chan) + (chan_raw->nchan * sizeof(struct acs_debug_chan_event)));

        (*chan)->nchan = 0;
        (*chan)->event = (struct acs_debug_chan_event *)((void *)(*chan) + sizeof(**chan));
    } else {
        /* Enter this path only if chan is non-NULL */
        if (!(*chan)) {
            qdf_err("Channel event data is not valid");
            return ACSDBG_ERROR;
        }

        chan_new = qdf_mem_malloc(sizeof(**chan) + ((*chan)->nchan * sizeof(struct acs_debug_chan_event)) +
                                  (chan_raw->nchan * sizeof(struct acs_debug_chan_event)));
        if (!chan_new) {
            qdf_err("New channel allocation failed");
            return ACSDBG_ERROR;
        }
        qdf_mem_zero(chan_new, sizeof(**chan) + ((*chan)->nchan * sizeof(struct acs_debug_chan_event) + (chan_raw->nchan * sizeof(struct acs_debug_chan_event))));
        qdf_mem_copy(chan_new, *chan, (sizeof(**chan) + ((*chan)->nchan * sizeof(struct acs_debug_chan_event))));
        qdf_mem_free(*chan);
        *chan = chan_new;
        (*chan)->event = (struct acs_debug_chan_event *)((void *)(*chan) + sizeof(**chan));
        chan_new = NULL;
    }

    for (ix = 0; ix < chan_raw->nchan; ix++) {
        index = ix;
        if (!chan_raw->is_first_chan_event_block) {
            /* If not the first block, then offset the index accordingly */
            index = ix + (*chan)->nchan;
        }

        (*chan)->event[index].channel_freq = wlan_reg_chan_band_to_freq(
                                            ic_acs->acs_ic->ic_pdev_obj,
                                            chan_raw->event[ix].channel_number,
                                            wlan_band_id_to_reg_wifi_band(chan_raw->band));
        (*chan)->event[index].chan.cycle_cnt = ACS_DEBUG_DEFAULT_CYCLE_CNT_VAL;
        (*chan)->event[index].chan.chan_clr_cnt = (uint32_t)(chan_raw->event[ix].channel_load *
                                               (*chan)->event[index].chan.cycle_cnt) / 100;
        (*chan)->event[index].chan.chan_tx_power_tput = chan_raw->event[ix].txpower;
        (*chan)->event[index].chan.chan_tx_power_range = chan_raw->event[ix].txpower;
        (*chan)->event[index].noise_floor = chan_raw->event[ix].noise_floor;
        (*chan)->event[index].channel_rf_characterization = chan_raw->event[ix].channel_rf_characterization;
    }

    (*chan)->nchan += chan_raw->nchan;
    qdf_info("Populated ACS channel events (debug framework)");

    return ACSDBG_SUCCESS;
}

#if WLAN_SUPPORT_RF_CHARACTERIZATION
/*
 * acs_debug_add_rf_char_info:
 * Injects the Channel RF Characterization information into the ACS/ICM
 * algorithm by sending the custom values.
 *
 * Parameters:
 * ic_acs: Pointer to the ACS structure
 *
 * Returns:
 * -1: Error
 *  0: Success
 */
int acs_debug_add_rf_char_info(ieee80211_acs_t ic_acs)
{
    struct acs_debug_chan_event_container *chan = NULL;

    if (!ic_acs) {
        qdf_err("Pointer to ACS structure is not valid");
        return ACSDBG_ERROR;
    }
    chan = (struct acs_debug_chan_event_container *)ic_acs->acs_debug_chan_events;

    /* Adding RF characterization entries for ICM debug */
    if (chan && !chan->acs_debug_is_rf_char_entries_loaded &&
        (ic_acs->acs_ic->ic_set_chan_grade_info)) {
        ic_acs->acs_ic->ic_set_chan_grade_info(ic_acs->acs_ic, chan, chan->nchan);
        chan->acs_debug_is_rf_char_entries_loaded = 1;
    }
    return ACSDBG_SUCCESS;
}
#endif /* WLAN_SUPPORT_RF_CHARACTERIZATION */

/*
 * acs_debug_add_chan_event_acs:
 * Injects the channel events status into the ACS algorithm by sending the
 * custom values during the invocation of the WMI event handler when receiving
 * genuine statistics from the firmware.
 *
 * Parameters:
 * chan_stats: Pointer to the channel stats which are to be sent to the ACS
 *             algorithm
 * chan_nf   : Pointer to the value of the noise floor of the particular channel
 * ieee_chan : Channel number of the particular channel
 *
 * Returns:
 * -1: Error
 *  0: Success
 */
int acs_debug_add_chan_event_acs(struct ieee80211_chan_stats *chan_stats,
                             int16_t *chan_nf, uint32_t ieee_chan_freq,
                             ieee80211_acs_t ic_acs)
{
    struct acs_debug_chan_event_container *chan = NULL;
    uint8_t ix = 0, chan_ix = 0, channel_found = 0;
    int8_t ret = 0;

    chan = (struct acs_debug_chan_event_container *)ic_acs->acs_debug_chan_events;

    if (!chan) {
        return ACSDBG_SUCCESS;
    }

    for(chan_ix = 0; chan_ix < chan->nchan; chan_ix++) {
        if (ieee_chan_freq == chan->event[chan_ix].channel_freq) {
            ix = chan_ix;
            channel_found = 1;
            break;
        }
    }

    if (!channel_found) {
        /* Exit safely if the channel event is not found */
        qdf_err("Channel freq %uMHz not found in debug data", ieee_chan_freq);
        return ACSDBG_SUCCESS;
    }

    *chan_nf = chan->event[ix].noise_floor;
    qdf_mem_copy((void *)chan_stats, (void *)&(chan->event[ix].chan),
                  sizeof(struct ieee80211_chan_stats));

#if WLAN_SUPPORT_RF_CHARACTERIZATION
    if (acs_debug_add_rf_char_info(ic_acs) != ACSDBG_SUCCESS) {
        qdf_err("RF Information could not be updated");
        return ACSDBG_ERROR;
    }
#endif

    return ret;
}

/*
 * acs_debug_add_chan_event_icm:
 * Injects the channel events into the ICM algorithm by sending the
 * custom values, for each channel.
 *
 * Parameters:
 * chan_stats: Pointer to the channel stats which are received from the debug
 *             framework
 * chan_nf   : Pointer to the value of the noise floor of the particular channel
 * ieee_chan : Channel number of the particular channel
 * flags     : cmd flag
 * schan_info: Pointer to the channel information to be sent to ICM algorithm
 *
 * Returns:
 * -1: Error
 *  0: Success
 */
int acs_debug_add_chan_event_icm(struct ieee80211_chan_stats *chan_stats,
                                 int16_t *chan_nf, uint32_t ieee_chan_freq,
                                 u_int8_t flags,
                                 struct scan_chan_info *schan_info)
{
    if ((!schan_info) || (!chan_stats)) {
        return ACSDBG_ERROR;
    }

    schan_info->freq           = ieee_chan_freq;
    schan_info->cmd_flag       = flags;
    schan_info->noise_floor    = *chan_nf;
    schan_info->cycle_count    = chan_stats->cycle_cnt;
    schan_info->rx_clear_count = chan_stats->chan_clr_cnt;
    schan_info->tx_frame_count = ACS_DEBUG_DEFAULT_TX_FRAME_CNT;
    /* Setting clock frequency as 1 MHz */
    schan_info->clock_freq     = ACS_DEBUG_DEFAULT_CLOCK_FREQ;
    schan_info->tx_power_tput  = chan_stats->chan_tx_power_tput;
    schan_info->tx_power_range = chan_stats->chan_tx_power_range;

    return ACSDBG_SUCCESS;
}

/*
 * acs_debug_reset_flags:
 * Resets the beacon flag after every tun of the ACs so the database can be sent
 * in again.
 *
 * Parameters:
 * None
 *
 * Returns:
 * None
 */
void acs_debug_reset_flags(ieee80211_acs_t acs)
{
    struct acs_debug_bcn_event_container *bcn =
                             (struct acs_debug_bcn_event_container *)acs->acs_debug_bcn_events;
    struct acs_debug_chan_event_container *chan =
                             (struct acs_debug_chan_event_container *)acs->acs_debug_chan_events;

    if (!bcn) {
        /* There are no beacons */
        return;
    }

    if (chan) {
        chan->acs_debug_is_rf_char_entries_loaded = 0;
    }
}

/*
 * acs_debug_cleanup:
 * Clears all the occupied memory during the unload of the Wi-Fi module
 *
 * Parameters:
 * None
 *
 * Returns:
 * None
 */
void acs_debug_cleanup(ieee80211_acs_t ic_acs)
{
    struct acs_debug_bcn_event_container **bcn = (struct acs_debug_bcn_event_container **)&ic_acs->acs_debug_bcn_events;
    struct acs_debug_chan_event_container **chan = (struct acs_debug_chan_event_container **)&ic_acs->acs_debug_chan_events;

    if (!ic_acs) {
        qdf_err("Invalid ACS pointer! Skipping cleanup");
        return;
    }

    if ((*bcn) || (*chan)) {
        qdf_info("Freeing ACS debug data from ic: %p", ic_acs->acs_ic);
    }

    if (*bcn) {
        qdf_mem_free(*bcn);
        (*bcn) = NULL;
    }

    if (*chan) {
        qdf_mem_free(*chan);
        (*chan) = NULL;
    }
}
