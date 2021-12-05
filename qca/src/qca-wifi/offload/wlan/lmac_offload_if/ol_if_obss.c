/*
 * Copyright (c) 2011-2014,2017-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * copyright (c) 2011 Atheros Communications Inc.
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

#if OBSS_PD

#include <ol_if_obss.h>

/**
 * ol_ath_send_cfg_obss_spatial_reuse_param() - Sends obss_pd cmd to fw
 * @vdev: vdev object
 *
 * Return: 0 on success, other value on failure
 */
static int
ol_ath_send_cfg_obss_spatial_reuse_param(struct wlan_objmgr_vdev *vdev)
{
    struct wmi_host_obss_spatial_reuse_set_param obss_cmd;
    struct wmi_unified *pdev_wmi_handle = NULL;
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ieee80211com *ic;
    QDF_STATUS status;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || !vap->iv_ic) {
        qdf_err("vap or ic is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is null");
        return -EINVAL;
    }

    /* send obss_pd command */
    obss_cmd.enable = true;
    obss_cmd.obss_min = cfg_get(psoc, CFG_OL_SRP_SRG_OBSS_PD_MIN_OFFSET);
    obss_cmd.obss_max = cfg_get(psoc, CFG_OL_SRP_SRG_OBSS_PD_MAX_OFFSET);
    obss_cmd.vdev_id = wlan_vdev_get_id(vdev);

    status = wmi_unified_send_obss_spatial_reuse_set_cmd(pdev_wmi_handle,
                                                         &obss_cmd);
    return qdf_status_to_os_return(status);
}

int ol_ath_send_derived_obsee_spatial_reuse_param(struct ieee80211vap *vap)
{
    struct wmi_host_obss_spatial_reuse_set_param obss_cmd;
    struct ieee80211_node *ni = vap->iv_bss;
    struct ieee80211_spatial_reuse_handle *ni_srp = &ni->ni_srp;
    struct wmi_unified *pdev_wmi_handle;
    struct ieee80211com *ic = vap->iv_ic;
    QDF_STATUS status;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is null");
        return -EINVAL;
    }

    obss_cmd.enable = true;
    obss_cmd.obss_min = ni_srp->obss_min;
    obss_cmd.obss_max = ni_srp->obss_max;
    obss_cmd.vdev_id = wlan_vdev_get_id(vap->vdev_obj);

    status = wmi_unified_send_obss_spatial_reuse_set_cmd(pdev_wmi_handle,
                                                         &obss_cmd);
    return qdf_status_to_os_return(status);
}

bool ol_ath_is_spatial_reuse_enabled(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    struct wmi_unified *wmi_handle;

    wmi_handle = lmac_get_wmi_hdl(psoc);
    if (!wmi_handle) {
        qdf_err("wmi handle is null");
        return false;
    }

    if (wmi_service_enabled(wmi_handle, wmi_service_obss_spatial_reuse) &&
                            (IEEE80211_IS_CHAN_11AX(ic->ic_curchan)))
        return true;
    else
        return false;
}

static int ol_ath_vap_set_obss_pd_threshold(struct ieee80211vap *vap,
                                            int32_t threshold, enum srtype type)
{
    int retval;
    int temp_thresh;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (type == SR_TYPE_SRG_OBSS_PD && !ic->self_srg_psr_support) {
        qdf_err("SRG based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    /* OBSS Packet Detect threshold bounds for Spatial Reuse feature.
     * The parameter value is programmed into the spatial reuse
     * register, to specify how low the background signal strength
     * from neighboring BSS cells must be, for this AP to
     * employ spatial reuse.
     */
    if (threshold > SELF_OBSS_PD_UPPER_THRESH ||
        threshold < SELF_OBSS_PD_LOWER_THRESH) {
        qdf_err("Threshold must in the range [%d, %d] (both inclusive)",
                SELF_OBSS_PD_LOWER_THRESH, SELF_OBSS_PD_UPPER_THRESH);
        return -EINVAL;
    }

    temp_thresh = vap->iv_obss_pd_thresh;

    if (set_obss_pd_threshold(&temp_thresh, type, threshold)) {
        qdf_err("Unable to set obss pd threshold");
        return -EINVAL;
    }

    retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                    wmi_vdev_param_set_cmd_obss_pd_threshold, temp_thresh);
    if (retval) {
        qdf_err("WMI send for set cmd obss pd threshold failed");
    } else {
        vap->iv_obss_pd_thresh = temp_thresh;
    }

    return retval;
}

static int ol_ath_vap_set_obss_pd_enable_bit(struct ieee80211vap *vap,
                                             uint32_t enable, enum srtype type)
{
    int retval;
    int temp_thresh;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);

    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    /* Spatial Reuse Operation in FTM causes all incoming packets to be
     * dropped due to the BSS Color Register value being set to 0. Check
     * to see if in MM or FTM before setting SR variables. Disable SR
     * entirely if operating in FTM.
     */
    if (wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj,
                                   WLAN_SOC_F_TESTMODE_ENABLE)) {
            qdf_info("Self Spatial Reuse disabled in FTM");
            retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                            wmi_vdev_param_set_cmd_obss_pd_threshold, 0);
            if (retval)
                qdf_err("Could not set obss pd thresh enable to 0");

            vap->iv_obss_pd_thresh = 0;
            return retval;
    }

    if (type == SR_TYPE_SRG_OBSS_PD && !ic->self_srg_psr_support) {
        qdf_err("SRG based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    if (enable > 1) {
        qdf_err("OBSS_PD Threshold enable value should be either 0 or 1");
        return -EINVAL;
    }

    temp_thresh = vap->iv_obss_pd_thresh;

    if (set_obss_pd_enable_bit(&temp_thresh, type, enable)) {
        qdf_err("Unable to enable obss pd bit");
        return -EINVAL;
    }

    retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                    wmi_vdev_param_set_cmd_obss_pd_threshold, temp_thresh);
    if (retval) {
        qdf_err("WMI send for set cmd obss pd threshold failed");
    } else {
        vap->iv_obss_pd_thresh = temp_thresh;
    }

    return retval;
}

static int ol_ath_vap_set_sr_per_ac(struct ieee80211vap *vap,
                                    uint32_t value, enum srtype type)
{
    uint32_t temp_enable_sr;
    int retval;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (type == SR_TYPE_PSR && !ic->self_srg_psr_support) {
        qdf_err("PSR based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    /*
     * The value corresponds to a bitmap where only bits 0-3
     * are valid. Therefore, a value that is greater than 15
     * is invalid.
     */
    if (value > 15) {
        qdf_err("Value: %d is not a valid value for setting SR ACs", value);
        return -EINVAL;
    }

    temp_enable_sr = vap->iv_self_sr_enable_per_ac;

    if (set_sr_per_ac(&temp_enable_sr, type, value)) {
        qdf_err("Unable to set SR per AC");
        return -EINVAL;
    }

    retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                    wmi_vdev_param_set_cmd_obss_pd_per_ac, temp_enable_sr);
    if (retval)
        qdf_err("Error sending WMI for SR per AC");
    else
        vap->iv_self_sr_enable_per_ac = temp_enable_sr;

    return retval;
}

int ol_ath_vap_set_self_psr_tx_enable(struct ieee80211vap *vap,
                                      uint8_t enable)
{
    int retval = 0;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (!ic->self_srg_psr_support) {
        qdf_err("PSR based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    if (enable > 1) {
        qdf_err("PSR Tx enable field can either be 0 or 1");
        return -EINVAL;
    }

    retval = ol_ath_wmi_send_vdev_param(vap->vdev_obj,
                    wmi_vdev_param_enable_srp, enable);
    if (retval)
        qdf_err("WMI command failed, discarding the configuration");
    else
        vap->iv_psr_tx_enable = enable;

    return retval;
}

int ol_ath_vap_set_self_sr_config(
    struct ieee80211vap *vap, uint32_t param,
    void *data, uint32_t data_len, uint32_t value)
{
    int retval =    0;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    switch (param)
    {
        case SR_SELF_OBSS_PD_TX_ENABLE:
            retval = ol_ath_vap_set_obss_pd_enable_bit(
                     vap, value, ol_ath_extact_sr_type(data, data_len));
            break;

        case SR_SELF_OBSS_PD_THRESHOLD_DB:
            if (ic->self_srg_psr_support) {
                qdf_err("dB units are not supported for OBSS PD threshold on this radio, try the dBm command");
                return -EOPNOTSUPP;
            }

            retval = ol_ath_vap_set_obss_pd_threshold(
                     vap, value, ol_ath_extact_sr_type(data, data_len));
            break;

        case SR_SELF_OBSS_PD_THRESHOLD_DBM:
            if (!ic->self_srg_psr_support) {
                qdf_err("dBm units are not supported for OBSS PD threshold on this radio, try the dB command");
                return -EOPNOTSUPP;
            }

            retval = ol_ath_vap_set_obss_pd_threshold(
                     vap, value, ol_ath_extact_sr_type(data, data_len));
            break;

        case SR_SELF_ENABLE_PER_AC:
            retval = ol_ath_vap_set_sr_per_ac(
                     vap, value, ol_ath_extact_sr_type(data, data_len));
            break;

        case SR_SELF_PSR_TX_ENABLE:
            retval = ol_ath_vap_set_self_psr_tx_enable(vap, *(uint8_t*)data);
            break;

        default:
            qdf_err("Unhandled SR config command");
            return -EINVAL;
    }

    return retval;
}

int ol_ath_vap_get_self_sr_config(
    struct ieee80211vap *vap, uint8_t param, char value[], size_t length)
{
    uint8_t srg_val = 0, non_srg_val = 0;
    uint8_t enable_per_ac_obss_pd = 0, enable_per_ac_psr = 0;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    switch (param) {
        case SR_SELF_OBSS_PD_TX_ENABLE:
            if (get_obss_pd_enable_bit(vap->iv_obss_pd_thresh,
                                       SR_TYPE_NON_SRG_OBSS_PD, &non_srg_val))
                return -EINVAL;

            if (get_obss_pd_enable_bit(vap->iv_obss_pd_thresh,
                                       SR_TYPE_SRG_OBSS_PD, &srg_val))
                return -EINVAL;

            snprintf(value, length, " non-srg: %d, srg: %d",
                     non_srg_val, srg_val);
            break;

        case SR_SELF_OBSS_PD_THRESHOLD_DB:
            if (ic->self_srg_psr_support) {
                qdf_err("dB units are not supported for OBSS PD threshold on this radio, try the dBm command");
                return -EOPNOTSUPP;
            }

            if (get_obss_pd_threshold(vap->iv_obss_pd_thresh,
                                      SR_TYPE_NON_SRG_OBSS_PD, &non_srg_val))
                return -EINVAL;

            if (get_obss_pd_threshold(vap->iv_obss_pd_thresh,
                                      SR_TYPE_SRG_OBSS_PD, &srg_val))
                return -EINVAL;


            snprintf(value, length, " non-srg: %d, srg: %d",
                     (int8_t)non_srg_val, (int8_t)srg_val);
            break;

        case SR_SELF_OBSS_PD_THRESHOLD_DBM:
            if (!ic->self_srg_psr_support) {
                qdf_err("dBm units are not supported for OBSS PD threshold on this radio, try the dB command");
                return -EOPNOTSUPP;
            }

            if (get_obss_pd_threshold(vap->iv_obss_pd_thresh,
                                      SR_TYPE_NON_SRG_OBSS_PD, &non_srg_val))
                return -EINVAL;

            if (get_obss_pd_threshold(vap->iv_obss_pd_thresh,
                                      SR_TYPE_SRG_OBSS_PD, &srg_val))
                return -EINVAL;


            snprintf(value, length, " non-srg: %d, srg: %d",
                     (int8_t)non_srg_val, (int8_t)srg_val);
            break;

        case SR_SELF_ENABLE_PER_AC:
            if (get_sr_per_ac(vap->iv_self_sr_enable_per_ac,
                              SR_TYPE_OBSS_PD, &enable_per_ac_obss_pd))
                return -EINVAL;

            if (get_sr_per_ac(vap->iv_self_sr_enable_per_ac,
                              SR_TYPE_PSR, &enable_per_ac_psr))
                return -EINVAL;

            snprintf(value, length, " obss_pd: 0x%X psr: 0x%X",
                     enable_per_ac_obss_pd, enable_per_ac_psr);
            break;

        case SR_SELF_PSR_TX_ENABLE:
            snprintf(value, length, "%d", vap->iv_psr_tx_enable);
            break;

        default:
            qdf_info("Unhandled SR config command");
            return -EINVAL;
    }

    return 0;
}

int ol_ath_vap_set_he_sr_config(struct ieee80211vap *vap, uint8_t param,
                                uint8_t value, uint8_t data1, uint8_t data2)
{
    bool sr_ie_len_update             = false;
    uint8_t min_offset, max_offset;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (!ic->ic_he_sr_enable) {
        qdf_err("Spatial Reuse Parameter Set Element is not enabled on this radio");
        return -EINVAL;
    }

    switch (param) {
        case HE_SR_PSR_ENABLE:
            if (value > 1) {
                qdf_err("SR ctrl PSR_disallowed field can either be 0 or 1\n");
                return -EINVAL;
            }

            /* Skip updating the IE as the current value matches user
             * request. Note that this iv variable holds a 'NOT' of
             * user-requested value.
             */
            if(value == vap->iv_he_srctrl_psr_disallowed) {
                vap->iv_is_spatial_reuse_updated = true;
                vap->iv_he_srctrl_psr_disallowed = !value;
            } else {
                qdf_info("PSR Enabled already set to: %d", value);
            }
        break;

        case HE_SR_NON_SRG_OBSSPD_ENABLE:
            /*
             * This command configures the following fields in IC
             * 1. Non-SRG OBSS PD SR Disallowed
             * 2. Non-SRG OBSS PD Max offset
             */
            if (value > 1) {
                qdf_err("SR ctrl non_srg_obss_pd_disallowed field can"
                        "  either be 0 or 1\n");
                return -EINVAL;
            }

            max_offset = data1;

            if(max_offset > HE_SR_NON_SRG_OBSS_PD_MAX_THRESH_OFFSET_VAL) {
                qdf_err("Max OBSS PD Threshold Offset value must be"
                " <= %u", HE_SR_NON_SRG_OBSS_PD_MAX_THRESH_OFFSET_VAL);
                return -EINVAL;
            }

            /* Skip updating the IE as the current value matches user
             * request. Note that this iv variable holds a 'NOT' of
             * user-requested value.
             */
            if (value == vap->iv_he_srctrl_non_srg_obsspd_disallowed) {
                sr_ie_len_update = true;
                vap->iv_he_srctrl_non_srg_obsspd_disallowed = !value;
            }

            if (value) {
                if(max_offset != vap->iv_he_srp_ie_non_srg_obsspd_max_offset) {
                    if (!sr_ie_len_update) {
                            vap->iv_is_spatial_reuse_updated = true;
                    }
                    vap->iv_he_srp_ie_non_srg_obsspd_max_offset = max_offset;
                }
            } else {
                qdf_info("As Non-SRG OBSS PD Enable is being set to 0, forcing Non-SRG OBSS PD max offset to 0");
                vap->iv_he_srp_ie_non_srg_obsspd_max_offset = 0;
            }
        break;

        case HE_SR_SR15_ENABLE:
            if (value > 1) {
                qdf_err("SR ctrl SR15_allowed field can either be 0 or 1\n");
                return -EINVAL;
            }

            if(value != vap->iv_he_srctrl_sr15_allowed) {
                vap->iv_is_spatial_reuse_updated = true;
                vap->iv_he_srctrl_sr15_allowed = value;
            } else {
                qdf_info("SR15 Allowed Value already set to: %d", value);
            }

        break;

        case HE_SR_SRG_OBSSPD_ENABLE:
            /*
             * This command configures the following 3 fields in IC
             * 1. SRG information present
             * 2. SRG OBSS PD Min offset
             * 3. SRG OBSS PD Max offset
             */
            if (value > 1) {
                qdf_err("SRG INFO PRESENT field can either be 0 or 1\n");
                return -EINVAL;
            }

            min_offset = data1;
            max_offset = data2;

            if (min_offset > max_offset) {
                qdf_err("SRG OBSS PD min offset(%d) must be <= SRG OBSS"
                        "PD max offset(%d)", min_offset, max_offset);
                return -EINVAL;
            }

            if (min_offset > HE_SR_SRG_OBSS_PD_MAX_ALLOWED_OFFSET_VAL) {
                qdf_err("SRG OBSS PD min offset value must be <= maximum allowed offset(%d)",
                        HE_SR_SRG_OBSS_PD_MAX_ALLOWED_OFFSET_VAL);
                return -EINVAL;
            }

            if (max_offset > HE_SR_SRG_OBSS_PD_MAX_ALLOWED_OFFSET_VAL) {
                qdf_err("SRG OBSS PD max offset value must be <= maximum allowed offset(%d)",
                        HE_SR_SRG_OBSS_PD_MAX_ALLOWED_OFFSET_VAL);
                return -EINVAL;
            }

            if (value != vap->iv_he_srctrl_srg_info_present) {
                sr_ie_len_update = true;
                vap->iv_he_srctrl_srg_info_present = value;
            }

            if (value) {
                /* SRG OBSS PD Min offset */
                if(min_offset != vap->iv_he_srp_ie_srg_obsspd_min_offset) {
                    if (!sr_ie_len_update)
                        vap->iv_is_spatial_reuse_updated = true;
                    vap->iv_he_srp_ie_srg_obsspd_min_offset = min_offset;
                }

                /* SRG OBSS PD Max offset */
                if(max_offset != vap->iv_he_srp_ie_srg_obsspd_max_offset) {
                    if (!sr_ie_len_update)
                        vap->iv_is_spatial_reuse_updated = true;
                    vap->iv_he_srp_ie_srg_obsspd_max_offset = max_offset;
                }
            } else {
                qdf_info("As SRG OBSS PD Enable is being set to 0, forcing SRG OBSS PD min and max offsets to 0");
                vap->iv_he_srp_ie_srg_obsspd_min_offset = 0;
                vap->iv_he_srp_ie_srg_obsspd_max_offset = 0;
            }
            break;

        default:
            qdf_err("Unhandled SR config command");
            return -EINVAL;
    }

    if (sr_ie_len_update) {
        if (vap->iv_is_up)
            ieee80211_sr_ie_reset(vap);
    } else {
        if(vap->iv_is_spatial_reuse_updated)
            wlan_vdev_beacon_update(vap);
    }
    vap->iv_is_spatial_reuse_updated = false;

    return 0;
}

int ol_ath_vap_get_he_sr_config(struct ieee80211vap *vap,
                                uint8_t param, uint32_t *value)
{
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (!ic->ic_he_sr_enable) {
        qdf_err("Spatial Reuse Parameter Set Element is not enabled on this radio");
        return -EINVAL;
    }

    switch (param) {
        case HE_SR_PSR_ENABLE:
            value[0] = !vap->iv_he_srctrl_psr_disallowed;
        break;

        case HE_SR_NON_SRG_OBSSPD_ENABLE:
            value[0] = !vap->iv_he_srctrl_non_srg_obsspd_disallowed;
            value[1] = vap->iv_he_srp_ie_non_srg_obsspd_max_offset;
        break;

        case HE_SR_SR15_ENABLE:
            value[0] = vap->iv_he_srctrl_sr15_allowed;
        break;

        case HE_SR_SRG_OBSSPD_ENABLE:
            value[0] = vap->iv_he_srctrl_srg_info_present;
            value[1] = vap->iv_he_srp_ie_srg_obsspd_min_offset;
            value[2] = vap->iv_he_srp_ie_srg_obsspd_max_offset;
        break;

        default:
            qdf_err("Unhandled SR config command");
            return -EINVAL;
    }

    return 0;
}

int ol_ath_vap_set_he_srg_bitmap(struct ieee80211vap *vap,
                                 uint32_t *val, uint32_t param)
{
    int retv = 0;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (!ic->ic_he_sr_enable) {
        qdf_err("Spatial Reuse Parameter Set Element is not enabled on this radio");
        return -EINVAL;
    }

    if (!vap->iv_he_srctrl_srg_info_present) {
        qdf_err("SRG based OBSS PD is not enabled in SRP IE");
        return -EINVAL;
    }

    switch(param) {
        case HE_SRP_IE_SRG_BSS_COLOR_BITMAP:
            vap->iv_he_srp_ie_srg_bss_color_bitmap[0] = val[0];
            vap->iv_he_srp_ie_srg_bss_color_bitmap[1] = val[1];
        break;

        case HE_SRP_IE_SRG_PARTIAL_BSSID_BITMAP:
            vap->iv_he_srp_ie_srg_partial_bssid_bitmap[0] = val[0];
            vap->iv_he_srp_ie_srg_partial_bssid_bitmap[1] = val[1];
        break;
        default:
            qdf_err("Unsupported Param: %d", param);
            retv = EINVAL;
        break;
    }
    vap->iv_is_spatial_reuse_updated = true;
    wlan_vdev_beacon_update(vap);
    vap->iv_is_spatial_reuse_updated = false;
    return retv;
}

int ol_ath_vap_get_he_srg_bitmap(struct ieee80211vap *vap,
    uint32_t *val, uint32_t param)
{
    int retv = 0;
    struct ieee80211com *ic;

    if (!vap) {
        qdf_err("VAP is null");
        return -EINVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (!ic->ic_he_sr_enable) {
        qdf_err("Spatial Reuse Parameter Set Element is not enabled on this radio");
        return -EINVAL;
    }

    if (!vap->iv_he_srctrl_srg_info_present) {
        qdf_err("SRG based OBSS PD is not enabled in SRP IE");
        return -EINVAL;
    }

    switch(param) {
        case HE_SRP_IE_SRG_BSS_COLOR_BITMAP:
            val[0] = vap->iv_he_srp_ie_srg_bss_color_bitmap[0];
            val[1] = vap->iv_he_srp_ie_srg_bss_color_bitmap[1];
        break;

        case HE_SRP_IE_SRG_PARTIAL_BSSID_BITMAP:
            val[0] = vap->iv_he_srp_ie_srg_partial_bssid_bitmap[0];
            val[1] = vap->iv_he_srp_ie_srg_partial_bssid_bitmap[1];
        break;

        default:
            qdf_err("Unsupported Param: %d", param);
            retv = EINVAL;
        break;
    }

    return retv;
}

QDF_STATUS ol_ath_send_obss_spatial_reuse_param(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct wlan_objmgr_pdev *pdev = wlan_vdev_get_pdev(vdev);
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        qdf_err("VAP is null");
        return QDF_STATUS_E_FAILURE;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("ic is null");
        return QDF_STATUS_E_FAILURE;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn) {
        qdf_err("scn is null");
        return QDF_STATUS_E_FAILURE;
    }

    ol_ath_send_cfg_obss_spatial_reuse_param(vdev);

    /* Ensure that Spatial Reuse is disabled if both AP and STA VAPs
     * exist on same pdev for chipsets other than QCN9000
     */
    if (lmac_get_tgt_type(psoc) != TARGET_TYPE_QCN9000) {
        ol_ath_sr_validate_vap_config(ic, scn, SR_TYPE_NON_SRG_OBSS_PD);
        ol_ath_sr_validate_vap_config(ic, scn, SR_TYPE_SRG_OBSS_PD);
    }

    return QDF_STATUS_SUCCESS;
}

int ol_ath_sr_validate_vap_config(struct ieee80211com *ic,
                                  struct ol_ath_softc_net80211 *scn, enum srtype type)
{
    struct ieee80211_vap_opmode_count vap_opmode_count;
    uint32_t temp_thresh;
    int retval = EOK;
    uint8_t enabled;

    OS_MEMZERO(&vap_opmode_count, sizeof(struct ieee80211_vap_opmode_count));
    ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);

    temp_thresh = ic->ic_ap_obss_pd_thresh;

    if (get_obss_pd_enable_bit(temp_thresh, type, &enabled))
        return -EINVAL;

    if (enabled) {
        /* Since spatial reuse works on a pdev level,
         * once both STA vap and AP vap present, or any monitor vap,
         * then we must disable spatial reuse params if mesh mode is
         * disabled. This is because AP and STA share the same HW register,
         * so they will overwrite the same fields in that register.
         */
        if (!ic->ic_mesh_mode && vap_opmode_count.ap_count
                && vap_opmode_count.sta_count) {
            if (set_obss_pd_enable_bit(&temp_thresh, type, 0))
                return -EINVAL;

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                        wmi_pdev_param_set_cmd_obss_pd_threshold,
                        temp_thresh);

            QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                    "Setting OBSS PD type %d to 0 for Repeater", type);
        }

        if (vap_opmode_count.monitor_count &&
         !cfg_get(scn->soc->psoc_obj, CFG_OL_ALLOW_MON_VAPS_IN_SR)) {
            if (set_obss_pd_enable_bit(&temp_thresh, type, 0))
                return -EINVAL;

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                        wmi_pdev_param_set_cmd_obss_pd_threshold,
                        temp_thresh);

            QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
            "Disabling OBSS PD Spatial Reuse due to current VAP configuration");
        }

    } else {
        /* In the case when mesh mode is enabled, we enable SR on the Repeater
         * since the RootAP and Repeater AP will both have the same BSS color.
         */
        if (ic->ic_mesh_mode && vap_opmode_count.ap_count
                && vap_opmode_count.sta_count) {
            if (set_obss_pd_enable_bit(&temp_thresh, type, 1))
                return -EINVAL;

            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                        wmi_pdev_param_set_cmd_obss_pd_threshold,
                        temp_thresh);

            QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                    "Setting OBSS PD type %d to 1 for Mesh", type);
        }
    }

    if(retval) {
        qdf_err("Could not set obss pd thresh enable");
    } else {
        ic->ic_ap_obss_pd_thresh = temp_thresh;
        QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                "OBSS PD setting: 0x%x", ic->ic_ap_obss_pd_thresh);
    }

    return retval;
}

int ol_ath_set_obss_pd_enable_bit(struct ieee80211com *ic, uint32_t enable,
                                  struct ol_ath_softc_net80211 *scn, enum srtype type)
{
    int retval;
    int temp_thresh;

    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    /* Spatial Reuse Operation in FTM causes all incoming packets to be
     * dropped due to the BSS Color Register value being set to 0. Check
     * to see if in MM or FTM before setting SR variables. Disable SR
     * entirely if operating in FTM.
     */
    if (wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj,
                                   WLAN_SOC_F_TESTMODE_ENABLE)) {
            qdf_err("Self Spatial Reuse disabled in FTM");
            retval = ol_ath_pdev_set_param(scn->sc_pdev,
                        wmi_pdev_param_set_cmd_obss_pd_threshold, 0);
            if (retval)
                qdf_err("Could not set obss pd thresh enable to 0");

            /* Clear all the bits of ic_ap_obss_pd_thresh */
            ic->ic_ap_obss_pd_thresh = 0;
            return retval;
    }

    if (type == SR_TYPE_SRG_OBSS_PD && !ic->self_srg_psr_support) {
        qdf_err("SRG based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    if (enable > 1) {
        qdf_err("OBSS_PD Threshold enable value should be either 0 or 1");
        return -EINVAL;
    }

    temp_thresh = ic->ic_ap_obss_pd_thresh;

    if (set_obss_pd_enable_bit(&temp_thresh, type, enable))
        return -EINVAL;

    retval = ol_ath_pdev_set_param(scn->sc_pdev,
                    wmi_pdev_param_set_cmd_obss_pd_threshold, temp_thresh);
    if (retval) {
        qdf_err("Could not set obss pd thresh enable val");
    } else {
        ic->ic_ap_obss_pd_thresh = temp_thresh;
    }

    return retval;
}

int ol_ath_set_obss_pd_threshold(struct ieee80211com *ic, int32_t threshold,
                                 struct ol_ath_softc_net80211 *scn,
                                 enum srtype type)
{
    int retval;
    int temp_thresh;

    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (type == SR_TYPE_SRG_OBSS_PD && !ic->self_srg_psr_support) {
        qdf_err("SRG based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    /* OBSS Packet Detect threshold bounds for Spatial Reuse feature.
     * The parameter value is programmed into the spatial reuse
     * register, to specify how low the background signal strength
     * from neighboring BSS cells must be, for this AP to
     * employ spatial reuse.
     */
    if (threshold > SELF_OBSS_PD_UPPER_THRESH ||
        threshold < SELF_OBSS_PD_LOWER_THRESH) {
        qdf_err("Threshold must in the range [%d, %d] (both inclusive)",
                SELF_OBSS_PD_LOWER_THRESH, SELF_OBSS_PD_UPPER_THRESH);
        return -EINVAL;
    }

    temp_thresh = ic->ic_ap_obss_pd_thresh;

    if (set_obss_pd_threshold(&temp_thresh, type, threshold))
        return -EINVAL;

    retval = ol_ath_pdev_set_param(scn->sc_pdev,
                                   wmi_pdev_param_set_cmd_obss_pd_threshold,
                                   temp_thresh);
    if (retval)
        qdf_err("WMI send for set cmd obss pd threshold failed");
    else
        ic->ic_ap_obss_pd_thresh = temp_thresh;

    return retval;
}

int ol_ath_set_self_srg_bss_color_bitmap(struct ieee80211com *ic,
                                         uint32_t bitmap_0, uint32_t bitmap_1)
{
    struct wmi_unified *pdev_wmi_handle;
    uint8_t pdev_id;

    if (!ic->self_srg_psr_support) {
        qdf_err("SRG based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    pdev_id = lmac_get_pdev_idx(ic->ic_pdev_obj);
    if (pdev_id < 0) {
        qdf_err("pdev id is invalid");
        return -1;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);;
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is null");
        return -1;
    }

    if(wmi_unified_send_self_srg_bss_color_bitmap_set_cmd(
            pdev_wmi_handle, bitmap_0, bitmap_1, pdev_id)) {
        qdf_err("WMI send for set self srg bitmap failed, discarding the configuration");
            return -1;
    } else {
        ic->ic_srg_bss_color_bitmap[0] = bitmap_0;
        ic->ic_srg_bss_color_bitmap[1] = bitmap_1;
    }

    return 0;
}

int ol_ath_set_self_srg_partial_bssid_bitmap(struct ieee80211com *ic,
                                             uint32_t bitmap_0,
                                             uint32_t bitmap_1)
{
    struct wmi_unified *pdev_wmi_handle;
    uint8_t pdev_id;

    if (!ic->self_srg_psr_support) {
        qdf_err("SRG based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    pdev_id = lmac_get_pdev_idx(ic->ic_pdev_obj);
    if (pdev_id < 0) {
        qdf_err("pdev id is invalid");
        return -1;
    }

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(ic->ic_pdev_obj);
    if (!pdev_wmi_handle) {
        qdf_err("pdev wmi handle is null");
        return -1;
    }

    if (wmi_unified_send_self_srg_partial_bssid_bitmap_set_cmd(
            pdev_wmi_handle, bitmap_0, bitmap_1, pdev_id)) {
        qdf_err("WMI send for set self srg bitmap failed, discarding the configuration");
        return -1;
    } else {
        ic->ic_srg_partial_bssid_bitmap[0] = bitmap_0;
        ic->ic_srg_partial_bssid_bitmap[1] = bitmap_1;
    }

    return 0;
}

int ol_ath_set_sr_per_ac(struct ieee80211com *ic, uint32_t value,
                         enum srtype type)
{
    uint32_t temp_enable_sr;
    int retval;

    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (type == SR_TYPE_PSR && !ic->self_srg_psr_support) {
        qdf_err("PSR based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    /*
     * The value corresponds to a bitmap where only bits 0-3
     * are valid. Therefore, a value that is greater than 15
     * is invalid.
     */
    if (value > 15) {
        qdf_err("Value: %d is not a valid value for setting SR ACs", value);
        return -EINVAL;
    }

    temp_enable_sr = ic->ic_he_sr_enable_per_ac;

    if (set_sr_per_ac(&temp_enable_sr, type, value)) {
        qdf_err("Unable to set SR per AC");
        return -EINVAL;
    }

    retval = ol_ath_pdev_set_param(ic->ic_pdev_obj,
                                   wmi_pdev_param_set_cmd_obss_pd_per_ac,
                                   temp_enable_sr);

    if (retval)
        qdf_err("Error sending WMI for SR per AC");
    else
        ic->ic_he_sr_enable_per_ac = temp_enable_sr;

    return retval;
}

int ol_ath_set_self_psr_tx_enable(struct ieee80211com *ic, uint8_t enable)
{
    int retval = 0;

    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (!ic->self_srg_psr_support) {
        qdf_err("PSR based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    if (enable > 1) {
        qdf_err("PSR Tx enable field can either be 0 or 1");
        return -EINVAL;
    }

    retval = ol_ath_pdev_set_param(ic->ic_pdev_obj,
                                   wmi_pdev_param_enable_srp, enable);

    if (retval)
        qdf_err("WMI command failed, discarding the configuration");
    else
        ic->ic_psr_tx_enable = enable;

    return retval;
}

int ol_ath_set_self_safety_margin_psr(struct ieee80211com *ic, uint8_t margin)
{
    int retval = 0;

    if (!ic) {
        qdf_err("IC or scn is null");
        return -EINVAL;
    }

    if (!ic->self_srg_psr_support) {
        qdf_err("PSR based Spatial Reuse is not supported on this target");
        return -EINVAL;
    }

    if (margin > 5) {
        qdf_err("Safety margin should be in the range 0-5 (both inclusive)");
        return -EINVAL;
    }

    retval = ol_ath_pdev_set_param(ic->ic_pdev_obj,
                                   wmi_pdev_param_sr_trigger_margin, margin);

    if (retval)
        qdf_err("WMI command failed, discarding the configuration");
    else
        ic->ic_safety_margin_psr = margin;

    return retval;
}

int ol_ath_set_self_hesiga_sr15_enable(struct ieee80211com *ic, uint8_t enable)
{
    int retval = 0;

    if (!ic) {
        qdf_err("IC is null");
        return -EINVAL;
    }

    if (!ic->self_srg_psr_support) {
        qdf_err("This feature is not supported on this target");
        return -EINVAL;
    }

    if (enable > 1) {
        qdf_err("HESIGA SR15 enable field can either be 0 or 1");
        return -EINVAL;
    }

    /* Send WMI command */
    retval = ol_ath_pdev_set_param(ic->ic_pdev_obj,
                                   wmi_pdev_param_enable_sr_prohibit, enable);
    if (retval)
        qdf_err("WMI send to set HESIGA SR15 failed, discarding configuration");
    else
        ic->ic_hesiga_sr15_enable = enable;

    return retval;
}

void ol_ath_pdev_sr_init(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic;
    struct wmi_unified *wmi_handle;
    struct wlan_objmgr_psoc *psoc;
    struct target_psoc_info *tgt_hdl;

    if (!scn) {
        qdf_err("scn is null");
        return;
    }

    ic = &scn->sc_ic;

    psoc = scn->soc->psoc_obj;
    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    wmi_handle = target_psoc_get_wmi_hdl(tgt_hdl);

    ic->self_srg_psr_support = wmi_service_enabled(wmi_handle,
                                    wmi_service_srg_srp_spatial_reuse_support);
    /* Spatial Reuse Operation in FTM causes all incoming packets to be
     * dropped due to the BSS Color Register value being set to 0. Check
     * to see if in MM or FTM before setting SR variables. Disable SR
     * entirely if operating in FTM.
     */
    if (!wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_TESTMODE_ENABLE)) {
        /* Initialize Spatial Reuse Enable bit from INI */
        ic->ic_he_sr_enable = cfg_get(psoc, CFG_OL_SR_IE_ENABLE);

        /* Set SR ctrl HESIGA_Spatial_reuse_value15_allowed
         * in SR IE based off INI
         */
        ic->ic_he_srctrl_sr15_allowed =
                !!(cfg_get(psoc, CFG_OL_SRP_SR_CONTROL) &
                IEEE80211_SRP_HESIGA_SR_VALUE15_ALLOWED_MASK);

        /* Set SR ctrl PSR Disallowed field by reading its value from SRG
         * Control Field value in INI
         */
        ic->ic_he_srctrl_psr_disallowed =
                !!(cfg_get(psoc, CFG_OL_SRP_SR_CONTROL) &
                IEEE80211_PSR_DISALLOWED_MASK);

        /* Set SR ctrl Non-SRG OBSS PD SR Disallowed field of
         * SR IE by reading value from SRG Control Field in INI
         */
        ic->ic_he_srctrl_non_srg_obsspd_disallowed =
                !!(cfg_get(psoc, CFG_OL_SRP_SR_CONTROL) &
                IEEE80211_SRP_NON_SRG_OBSS_PD_SR_DISALLOWED_MASK);

        /* Set all SRG related fields in SR IE
         * based on value read from SRG Control Field value in INI
         */
        ic->ic_he_srctrl_srg_info_present =
                !!(cfg_get(psoc, CFG_OL_SRP_SR_CONTROL) &
                IEEE80211_SRP_SRG_INFO_PRESENT_MASK);

        /* Initialize Non-SRG OBSS PD MAX OFFSET from INI */
        ic->ic_he_non_srg_obsspd_max_offset =
                cfg_get(psoc, CFG_OL_SRP_NON_SRG_OBSS_PD_MAX_OFFSET);

        /* Initialize SRG OBSS PD MIN OFFSET from INI */
        ic->ic_he_srctrl_srg_obsspd_min_offset =
                cfg_get(psoc, CFG_OL_SRP_SRG_OBSS_PD_MIN_OFFSET);

        /* Initialize SRG OBSS PD MAX OFFSET from INI */
        ic->ic_he_srctrl_srg_obsspd_max_offset =
                cfg_get(psoc, CFG_OL_SRP_SRG_OBSS_PD_MAX_OFFSET);

        /* Initialize SRG BSS COLOR BITMAP from INI */
        ic->ic_he_srp_ie_srg_bss_color_bitmap[0] =
                    cfg_get(psoc, CFG_OL_SRP_SRG_BSS_COLOR_BITMAP_LOW);
        ic->ic_he_srp_ie_srg_bss_color_bitmap[1] =
                    cfg_get(psoc, CFG_OL_SRP_SRG_BSS_COLOR_BITMAP_HIGH);

        /* Initialize SRG PARTIAL BSSID BITMAP from INI */
        ic->ic_he_srp_ie_srg_partial_bssid_bitmap[0] =
                    cfg_get(psoc, CFG_OL_SRP_SRG_PARTIAL_BSSID_BITMAP_LOW);
        ic->ic_he_srp_ie_srg_partial_bssid_bitmap[1] =
                    cfg_get(psoc, CFG_OL_SRP_SRG_PARTIAL_BSSID_BITMAP_HIGH);

        if (ic->self_srg_psr_support) {
             /* Set the unit of OBSS PD threshold as dBm */
            set_obss_pd_threshold_unit(&ic->ic_ap_obss_pd_thresh,
                                       IEEE80211_SELF_OBSS_PD_THRESHOLD_IN_DBM);

            /* Set self Non-SRG OBSS PD Threshold */
            ol_ath_set_obss_pd_threshold(ic,
                     cfg_get(psoc, CFG_OL_SELF_NON_SRG_OBSS_PD_THRESHOLD_DBM),
                     scn, SR_TYPE_NON_SRG_OBSS_PD);

            /* Set self SRG OBSS PD Threshold */
            ol_ath_set_obss_pd_threshold(ic,
                 cfg_get(psoc, CFG_OL_SELF_SRG_OBSS_PD_THRESHOLD_DBM),
                 scn, SR_TYPE_SRG_OBSS_PD);

            /* Set self SRG OBSS PD Enable */
            ol_ath_set_obss_pd_enable_bit(ic,
                cfg_get(psoc, CFG_OL_SELF_SRG_OBSS_PD_ENABLE),
                scn, SR_TYPE_SRG_OBSS_PD);

            /* SR enabled per AC for PSR */
            set_sr_per_ac(&ic->ic_he_sr_enable_per_ac, SR_TYPE_PSR,
                          cfg_get(psoc, CFG_OL_SR_ENABLE_PER_AC));

            /* If the bit corresponding to an OBSS is set, then target can treat
             * that OBSS transmission as an SR opportunity for SRG and Non-SRG
             * based Spatial Reuse, otherwise the target doesn't see that OBSS
             * transmision as SR opportunity.
             */
            ic->ic_srg_obss_color_enable_bitmap[0] =
                IEEE80211_SELF_SRG_OBSS_COLOR_ENABLE_BITMAP;
            ic->ic_srg_obss_color_enable_bitmap[1] =
                IEEE80211_SELF_SRG_OBSS_COLOR_ENABLE_BITMAP;
            ic->ic_srg_obss_bssid_enable_bitmap[0] =
                IEEE80211_SELF_SRG_OBSS_BSSID_ENABLE_BITMAP;
            ic->ic_srg_obss_bssid_enable_bitmap[1] =
                IEEE80211_SELF_SRG_OBSS_BSSID_ENABLE_BITMAP;
            ic->ic_non_srg_obss_color_enable_bitmap[0] =
                IEEE80211_SELF_NON_SRG_OBSS_COLOR_ENABLE_BITMAP;
            ic->ic_non_srg_obss_color_enable_bitmap[1] =
                IEEE80211_SELF_NON_SRG_OBSS_COLOR_ENABLE_BITMAP;
            ic->ic_non_srg_obss_bssid_enable_bitmap[0] =
                IEEE80211_SELF_NON_SRG_OBSS_BSSID_ENABLE_BITMAP;
            ic->ic_non_srg_obss_bssid_enable_bitmap[1] =
                IEEE80211_SELF_NON_SRG_OBSS_BSSID_ENABLE_BITMAP;

            /* Read and configure PSR Tx enable */
            ol_ath_set_self_psr_tx_enable(ic,
                 cfg_get(psoc, CFG_OL_SELF_PSR_TX_ENABLE));

            /* Partial BSSID bitmap for Self SRG operation */
            ol_ath_set_self_srg_partial_bssid_bitmap(ic,
                 cfg_get(psoc, CFG_OL_SELF_SRG_PARTIAL_BSSID_BITMAP_LOW),
                 cfg_get(psoc, CFG_OL_SELF_SRG_PARTIAL_BSSID_BITMAP_HIGH));

            /* BSS color bitmap for Self SRG operation */
            ol_ath_set_self_srg_bss_color_bitmap(ic,
                 cfg_get(psoc, CFG_OL_SELF_SRG_BSS_COLOR_BITMAP_LOW),
                 cfg_get(psoc, CFG_OL_SELF_SRG_BSS_COLOR_BITMAP_HIGH));

            /* Enable/Disable HE SIGA SR15 for self */
            ol_ath_set_self_hesiga_sr15_enable(ic,
                 cfg_get(psoc, CFG_OL_SELF_HESIGA_SR15_ENABLE));

            ic->ic_safety_margin_psr = IEEE80211_SELF_PSR_SAFETY_MARGIN;
        } else {
             /* Set the unit of OBSS PD threshold as dB */
            set_obss_pd_threshold_unit(&ic->ic_ap_obss_pd_thresh,
                                       IEEE80211_SELF_OBSS_PD_THRESHOLD_IN_DB);

            /* Set self Non-SRG OBSS PD Threshold */
            ol_ath_set_obss_pd_threshold(ic,
                     cfg_get(psoc, CFG_OL_SELF_NON_SRG_OBSS_PD_THRESHOLD_DB),
                     scn, SR_TYPE_NON_SRG_OBSS_PD);
        }

        /* Self Non-SRG OBSS PD Enable */
        ol_ath_set_obss_pd_enable_bit(ic,
                cfg_get(psoc, CFG_OL_SELF_NON_SRG_OBSS_PD_ENABLE),
                scn, SR_TYPE_NON_SRG_OBSS_PD);

        /* SR Enabled ACs for OBSS PD */
        set_sr_per_ac(&ic->ic_he_sr_enable_per_ac, SR_TYPE_OBSS_PD,
                      cfg_get(psoc, CFG_OL_SR_ENABLE_PER_AC));
        ol_ath_pdev_set_param(scn->sc_pdev,
                              wmi_pdev_param_set_cmd_obss_pd_per_ac,
                              ic->ic_he_sr_enable_per_ac);
    } else {
        ic->ic_he_sr_enable = 0;
        ol_ath_set_obss_pd_enable_bit(ic, 0, scn, SR_TYPE_NON_SRG_OBSS_PD);
        ol_ath_set_obss_pd_enable_bit(ic, 0, scn, SR_TYPE_SRG_OBSS_PD);
    }
}
#endif /* OBSS_PD */
