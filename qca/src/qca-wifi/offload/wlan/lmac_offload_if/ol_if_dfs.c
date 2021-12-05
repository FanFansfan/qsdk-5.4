/*
 * Copyright (c) 2017-2018, 2020 Qualcomm Innovation Center, Inc.
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

/*
 * LMAC offload interface functions for UMAC - for power and performance offload model
 */

#if ATH_SUPPORT_DFS

#include "ol_if_athvar.h"
#include "target_type.h"
#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include "qdf_lock.h"  /* qdf_spinlock_* */
#include "qdf_types.h" /* qdf_vprint */
#include "ol_regdomain.h"
#include <wlan_osif_priv.h>
#include "init_deinit_lmac.h"
#include "target_if.h"

#if ATH_PERF_PWR_OFFLOAD

QDF_STATUS
ol_dfs_get_caps(struct wlan_objmgr_pdev *pdev,
        struct wlan_dfs_caps *dfs_caps)
{
    struct ol_ath_softc_net80211 *scn;
    struct pdev_osif_priv *osif_priv;

    osif_priv = wlan_pdev_get_ospriv(pdev);

    if (osif_priv == NULL) {
        qdf_print("%s : osif_priv is NULL", __func__);
        return QDF_STATUS_E_FAILURE;
    }

    scn = (struct ol_ath_softc_net80211 *)osif_priv->legacy_osif_priv;

    dfs_caps->wlan_dfs_combined_rssi_ok = 0;
    dfs_caps->wlan_dfs_ext_chan_ok = 0;
    dfs_caps->wlan_dfs_use_enhancement = 0;
    dfs_caps->wlan_strong_signal_diversiry = 0;
    dfs_caps->wlan_fastdiv_val = 0;
    dfs_caps->wlan_chip_is_bb_tlv = 1;
    dfs_caps->wlan_chip_is_over_sampled = 0;
    dfs_caps->wlan_chip_is_ht160 = 0;


    /*
     * Disable check for strong OOB radar as this
     * has side effect (IR 095628, 094131
     * Set the capability to off (0) by default.
     * We will turn this on once we have resolved
     * issue with the fix
     */

    dfs_caps->wlan_chip_is_false_detect = 0;
    switch (lmac_get_tgt_type(scn->soc->psoc_obj)) {
        case TARGET_TYPE_AR900B:
            break;

        case TARGET_TYPE_IPQ4019:
            dfs_caps->wlan_chip_is_false_detect = 0;
            break;

        case TARGET_TYPE_AR9888:
            /* Peregrine is over sampled */
            dfs_caps->wlan_chip_is_over_sampled = 1;
            break;

        case TARGET_TYPE_QCA9984:
        case TARGET_TYPE_QCA9888:
            /* Cascade and Besra supports 160MHz channel */
            dfs_caps->wlan_chip_is_ht160 = 1;
            break;
        default:
            break;
    }

    return(0);
}

/*
 * ic_dfs_enable - enable DFS
 *
 * For offload solutions, radar PHY errors will be enabled by the target
 * firmware when DFS is requested for the current channel.
 */
QDF_STATUS
ol_if_dfs_enable(struct wlan_objmgr_pdev *pdev, int *is_fastclk,
        struct wlan_dfs_phyerr_param *param,
        uint32_t dfsdomain)
{
    QDF_TRACE(QDF_MODULE_ID_DFS, QDF_TRACE_LEVEL_INFO,"%s: called", __func__);

    /*
     * XXX For peregrine, treat fastclk as the "oversampling" mode.
     *     It's on by default.  This may change at some point, so
     *     we should really query the firmware to find out what
     *     the current configuration is.
     */
    (* is_fastclk) = 1;

    return QDF_STATUS_SUCCESS;
}

/*
 * ic_dfs_disable
 */
QDF_STATUS
ol_if_dfs_disable(struct wlan_objmgr_pdev *pdev, int no_cac)
{
    QDF_TRACE(QDF_MODULE_ID_DFS, QDF_TRACE_LEVEL_INFO,"%s: called", __func__);

    return (0);
}

/*
 * ic_dfs_get_thresholds
 */
QDF_STATUS ol_if_dfs_get_thresholds(struct wlan_objmgr_pdev *pdev,
        struct wlan_dfs_phyerr_param *param)
{
    /*
     * XXX for now, the hardware has no API for fetching
     * the radar parameters.
     */
    param->pe_firpwr = 0;
    param->pe_rrssi = 0;
    param->pe_height = 0;
    param->pe_prssi = 0;
    param->pe_inband = 0;
    param->pe_relpwr = 0;
    param->pe_relstep = 0;
    param->pe_maxlen = 0;

    return 0;
}

/*
 * ic_get_ext_busy
 */
QDF_STATUS
ol_if_dfs_get_ext_busy(struct wlan_objmgr_pdev *pdev, int *ext_chan_busy)
{
    *ext_chan_busy = 0;
    return (0);
}

/*
 * XXX this doesn't belong here, but the DFS code requires that it exists.
 * Please figure out how to fix this!
 */
QDF_STATUS
ol_if_get_tsf64(struct wlan_objmgr_pdev *pdev, uint64_t *tsf64)
{
	/* XXX TBD */
	return (0);
}

#endif /* ATH_PERF_PWR_OFFLOAD */

/*
 * host_dfs_check_support
 */
#if defined(WLAN_DFS_PARTIAL_OFFLOAD) && defined(HOST_DFS_SPOOF_TEST)
QDF_STATUS
ol_if_is_host_dfs_check_support_enabled(struct wlan_objmgr_pdev * pdev,
        bool *enabled)
{
    struct wlan_objmgr_psoc *psoc = wlan_pdev_get_psoc(pdev);
    struct wmi_unified* wmi_handle = lmac_get_wmi_hdl(psoc);

    if (!wmi_handle) {
        qdf_print("%s : wmi_handle is NULL", __func__);
        return QDF_STATUS_E_FAILURE;
    }

    *enabled = wmi_service_enabled(wmi_handle,
            wmi_service_host_dfs_check_support) &&
            !ol_target_lithium(psoc);

    return QDF_STATUS_SUCCESS;
}
#endif /* HOST_DFS_SPOOF_TEST */

#ifdef QCA_SUPPORT_AGILE_DFS
QDF_STATUS ol_if_dfs_reset_agile_cac(struct ieee80211com *ic)
{
    struct wlan_objmgr_pdev *pdev;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wlan_lmac_if_dfs_tx_ops *dfs_tx_ops;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_tx_ops *tx_ops;

    pdev = ic->ic_pdev_obj;
    if(!pdev) {
        qdf_err("pdev is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    tx_ops = wlan_psoc_get_lmac_if_txops(psoc);
    if (!tx_ops) {
        qdf_err("tx_ops is NULL");
        return QDF_STATUS_E_FAILURE;
    }

    dfs_tx_ops = &tx_ops->dfs_tx_ops;
    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);

    if(!dfs_rx_ops) {
       qdf_err("rx_ops is NULL");
       return QDF_STATUS_E_FAILURE;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
        QDF_STATUS_SUCCESS) {
        qdf_err("could not get pdev ref for ID %d", WLAN_DFS_ID);
        return QDF_STATUS_E_FAILURE;
    }

    if (dfs_rx_ops->dfs_set_agile_precac_state)
        dfs_rx_ops->dfs_set_agile_precac_state(pdev, 0);

    /*send o-cac abort command*/
    if (dfs_rx_ops->dfs_agile_sm_deliver_evt)
        dfs_rx_ops->dfs_agile_sm_deliver_evt(pdev,
                                             DFS_AGILE_SM_EV_AGILE_STOP);

    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    return QDF_STATUS_SUCCESS;
}

void ol_ath_update_fw_adfs_support(struct ieee80211com *ic, uint32_t chainmask)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    struct wlan_psoc_host_service_ext_param *ext_param;
    struct target_psoc_info *tgt_hdl;
    struct target_pdev_info *tgt_pdev;
    uint8_t pdev_idx;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap = NULL;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap_arr = NULL;
    struct wlan_psoc_host_chainmask_table *table = NULL;
    uint32_t table_id = 0;
    bool fw_adfs_support_160 = false;
    bool fw_adfs_support_non_160 = false;
    int j = 0;

    psoc = wlan_pdev_get_psoc(pdev);

    tgt_hdl = wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_info("psoc target_psoc_info is null");
        return;
    }

    ext_param = &(tgt_hdl->info.service_ext_param);
    tgt_pdev = (struct target_pdev_info *)wlan_pdev_get_tgt_if_handle(pdev);
    pdev_idx = target_pdev_get_phy_idx(tgt_pdev);
    mac_phy_cap_arr = target_psoc_get_mac_phy_cap(tgt_hdl);
    if (mac_phy_cap_arr) {
        mac_phy_cap = &mac_phy_cap_arr[pdev_idx];
        /* get table ID for a given pdev */
        table_id = mac_phy_cap->chainmask_table_id;
    } else {
        qdf_err("mac phy cap arr is NULL");
        return;
    }

    /* table */
    table = &(ext_param->chainmask_table[table_id]);

    /* Return if table is null, usually should be false */
    if (!table->cap_list) {
        qdf_info("Returning due to null table");
        return;
    }

    for (j = 0; j < table->num_valid_chainmasks; j++) {
        if (table->cap_list[j].chainmask != chainmask) {
            continue;
        } else {
            fw_adfs_support_non_160 = table->cap_list[j].supports_aDFS;
            fw_adfs_support_160 = table->cap_list[j].supports_aDFS_160;
            break;
        }
    }

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (dfs_rx_ops && dfs_rx_ops->dfs_set_fw_adfs_support)
        dfs_rx_ops->dfs_set_fw_adfs_support(pdev,
                                            fw_adfs_support_160,
                                            fw_adfs_support_non_160);
}
#endif

int ol_if_dfs_pdev_reinit_post_hw_mode_switch(struct ieee80211com *ic)
{
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev;

    pdev = ic->ic_pdev_obj;
    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc)
        return -EINVAL;

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (dfs_rx_ops && dfs_rx_ops->dfs_reinit_timers) {
        dfs_rx_ops->dfs_reinit_timers(pdev);
    }

    /* UMAC channel list is reset. Reinit the preCAC channel tree with the
     * updated channel list.
     */
    ieee80211_dfs_reset_precaclists(ic);
    return 0;
}

int ol_if_dfs_pdev_deinit_pre_hw_mode_switch(struct ol_ath_softc_net80211
                                             *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    int status = 0;

    ieee80211_dfs_reset(ic);
    status = ol_if_dfs_reset_agile_cac(ic);

    return status;
}

void ol_if_dfs_psoc_deinit_pre_hw_mode_switch(struct
                                              wlan_objmgr_psoc *psoc)
{
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (dfs_rx_ops && dfs_rx_ops->dfs_reset_adfs_config) {
        dfs_rx_ops->dfs_reset_adfs_config(psoc);
    }

}

static QDF_STATUS
ol_if_fetch_5ghz_range_for_hw_mode(struct wlan_objmgr_pdev *pdev,
    uint8_t target_hw_mode, uint16_t *low_5ghz_freq, uint16_t *high_5ghz_freq)
{
    struct target_pdev_info *tgt_pdev;
    struct wlan_objmgr_psoc *psoc;
    struct  target_psoc_info *tgt_hdl;
    struct wlan_psoc_host_mac_phy_caps *mac_phy_cap;
    int32_t pdev_idx;
    QDF_STATUS status = QDF_STATUS_E_FAILURE;

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is null!");
        goto err;
    }

    tgt_hdl = (struct target_psoc_info *)wlan_psoc_get_tgt_if_handle(psoc);
    if (!tgt_hdl) {
        qdf_err("target_psoc_info is null");
        goto err;
    }

    mac_phy_cap = target_psoc_get_mac_phy_cap_for_mode(tgt_hdl, target_hw_mode);
    if (!mac_phy_cap) {
        qdf_err("mac phy cap is NULL");
        goto err;
    }

    tgt_pdev = (struct target_pdev_info *)wlan_pdev_get_tgt_if_handle(pdev);
    if (!tgt_pdev) {
       qdf_err("target_pdev_info is null");
       goto err;
    }

    pdev_idx = target_pdev_get_phy_idx(tgt_pdev);
    if (pdev_idx < 0) {
        qdf_err("pdev_idx is invalid");
        goto err;
    }

    if (!(mac_phy_cap[pdev_idx].supported_bands & WMI_HOST_WLAN_5G_CAPABILITY))
        goto err;

    *low_5ghz_freq = mac_phy_cap[pdev_idx].reg_cap_ext.low_5ghz_chan;
    *high_5ghz_freq = mac_phy_cap[pdev_idx].reg_cap_ext.high_5ghz_chan;
    status = QDF_STATUS_SUCCESS;

err:
    return status;
}

/*
 * @brief: Copy each pdev's NOL data to a temporary structure in DFS PSOC priv
 * based on the upcoming pdev's frequency range after mode switch.
 * @scn: Pointer to primary radio structure.
 * @target_hw_mode: The new hw mode requested for dynamic mode switch.
 *
 * Return: void.
 */
static void ol_if_dfs_deinit_nol(
        struct ol_ath_softc_net80211 *scn,
        uint8_t target_hw_mode)
{
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev;
    uint8_t pdev_id, num_radios, tmp_pdev_id;
    struct ieee80211com *ic = &scn->sc_ic;

    pdev = ic->ic_pdev_obj;
    if (!pdev) {
        qdf_err("pdev is null");
        return;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is null!");
        return;
    }

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);

    if (!dfs_rx_ops ||
        !dfs_rx_ops->dfs_save_dfs_nol_in_psoc ||
        !dfs_rx_ops->dfs_init_tmp_psoc_nol)
        return;

    pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
    num_radios = ol_ath_get_max_supported_radios(scn->soc);
    if (!num_radios) {
        qdf_err("Number of radios is 0!");
        return;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) != QDF_STATUS_SUCCESS) {
        qdf_err("Can't get pdev reference for DBG ID %d", WLAN_DFS_ID);
        return;
    }

    dfs_rx_ops->dfs_init_tmp_psoc_nol(pdev, num_radios);

    for (tmp_pdev_id = 0; tmp_pdev_id < num_radios; tmp_pdev_id++) {
        struct wlan_objmgr_pdev *tmp_pdev;
        struct ieee80211com *tmp_ic;

        tmp_pdev = wlan_objmgr_get_pdev_by_id(psoc, tmp_pdev_id, WLAN_DFS_ID);
        tmp_ic = wlan_pdev_get_mlme_ext_obj(pdev);
        if (!tmp_ic ||
            (!(tmp_ic->ic_supported_bands & WMI_HOST_WLAN_5G_CAPABILITY))) {
            wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
            continue;
        }
        if (dfs_rx_ops->dfs_save_dfs_nol_in_psoc)
            dfs_rx_ops->dfs_save_dfs_nol_in_psoc(tmp_pdev, tmp_pdev_id);
        wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
}

static void ol_if_dfs_reinit_precac_lists(
        struct ol_ath_softc_net80211 *scn,
        uint8_t target_hw_mode)
{
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev, *tmp_pdev;
    uint8_t num_radios, i;
    struct ieee80211com *ic = &scn->sc_ic;
    uint16_t low_5ghz_freq, high_5ghz_freq;

    pdev = ic->ic_pdev_obj;
    if (!pdev) {
        qdf_err("pdev is null");
        return;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is null!");
        return;
    }

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (!dfs_rx_ops)
        return;

    num_radios = ol_ath_get_max_supported_radios(scn->soc);
    if (!num_radios) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                  QDF_TRACE_LEVEL_ERROR, "Number of radios is 0!");
        return;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) != QDF_STATUS_SUCCESS) {
        qdf_err("Can't get pdev reference for DBG ID %d", WLAN_DFS_ID);
        return;
    }

    for (i = 0; i < num_radios; i++) {
        struct ieee80211com *tmp_ic;

        tmp_pdev = wlan_objmgr_get_pdev_by_id(psoc, i, WLAN_DFS_ID);
        if (!tmp_pdev || (tmp_pdev == pdev)) {
            wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
            continue;
        }

        tmp_ic = wlan_pdev_get_mlme_ext_obj(pdev);

        if (!tmp_ic ||
            (!(tmp_ic->ic_supported_bands & WMI_HOST_WLAN_5G_CAPABILITY))) {
            wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
            continue;
        }

        switch (target_hw_mode) {
            case WMI_HOST_HW_MODE_DBS:
            if (ol_if_fetch_5ghz_range_for_hw_mode(pdev, target_hw_mode,
                &low_5ghz_freq, &high_5ghz_freq) != QDF_STATUS_SUCCESS) {
                wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
                continue;
            }

            dfs_rx_ops->dfs_reinit_precac_lists(tmp_pdev, pdev,
                                                low_5ghz_freq, high_5ghz_freq);
            break;
            case WMI_HOST_HW_MODE_DBS_SBS:
            if (ol_if_fetch_5ghz_range_for_hw_mode(tmp_pdev, target_hw_mode,
                &low_5ghz_freq, &high_5ghz_freq) != QDF_STATUS_SUCCESS) {
                wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
                continue;
            }

            dfs_rx_ops->dfs_reinit_precac_lists(pdev, tmp_pdev,
                                                low_5ghz_freq, high_5ghz_freq);
            break;
            default:
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                      QDF_TRACE_LEVEL_ERROR, FL("Unhandled mode"));
            break;
        }
        wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
}

void ol_if_dfs_reinit_nol(
        struct ol_ath_softc_net80211 *scn,
        uint8_t target_hw_mode)
{
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev, *tmp_pdev;
    uint8_t pdev_id, num_radios, tmp_pdev_id;
    struct ieee80211com *ic = &scn->sc_ic;
    uint16_t pri_pdev_low_5ghz, pri_pdev_high_5ghz;

    pdev = ic->ic_pdev_obj;
    if (!pdev) {
        qdf_err("pdev is null");
        return;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is null!");
        return;
    }

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);

    if (!dfs_rx_ops)
        return;

    if (ol_if_fetch_5ghz_range_for_hw_mode(pdev,target_hw_mode,
           &pri_pdev_low_5ghz, &pri_pdev_high_5ghz) != QDF_STATUS_SUCCESS)
        return;

    pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
    num_radios = ol_ath_get_max_supported_radios(scn->soc);
    if (!num_radios) {
        qdf_err("Number of radios is 0!");
        return;
    }

    for (tmp_pdev_id = 0; tmp_pdev_id < num_radios; tmp_pdev_id++) {
        uint16_t low_5ghz_freq, high_5ghz_freq;
        struct ieee80211com *tmp_ic;

        tmp_pdev = wlan_objmgr_get_pdev_by_id(psoc, tmp_pdev_id, WLAN_DFS_ID);
        if (!tmp_pdev) {
            qdf_err("pdev is null");
            continue;
        }

        tmp_ic = wlan_pdev_get_mlme_ext_obj(pdev);
        if (!tmp_ic ||
            (!(tmp_ic->ic_supported_bands & WMI_HOST_WLAN_5G_CAPABILITY))) {
            wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
            continue;
        }

        switch (target_hw_mode) {
            case WMI_HOST_HW_MODE_DBS:
                /* We're switching from DBS_SBS to DBS. Copy each radio's
                 * DFS NOL data to the primary pdev DFS object.
                 */
                dfs_rx_ops->dfs_reinit_nol_from_psoc_copy(pdev, tmp_pdev_id,
                        pri_pdev_low_5ghz, pri_pdev_high_5ghz);
            break;

            case WMI_HOST_HW_MODE_DBS_SBS:
                /* Find the target pdev's low and high 5GHz frequency */
                if (ol_if_fetch_5ghz_range_for_hw_mode(tmp_pdev, target_hw_mode,
                        &low_5ghz_freq, &high_5ghz_freq) != QDF_STATUS_SUCCESS)
                    goto exit;

                /* We're switching from DBS to DBS_SBS. Copy primary radio's
                 * DFS NOL data to the radio of the corresponding band.
                 */
                dfs_rx_ops->dfs_reinit_nol_from_psoc_copy(tmp_pdev, pdev_id,
                        low_5ghz_freq, high_5ghz_freq);
            break;

            default:
            QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                      QDF_TRACE_LEVEL_ERROR, FL("Unhandled mode"));
            break;
        }
exit:
        wlan_objmgr_pdev_release_ref(tmp_pdev, WLAN_DFS_ID);
    }
    if (dfs_rx_ops->dfs_deinit_tmp_psoc_nol)
        dfs_rx_ops->dfs_deinit_tmp_psoc_nol(pdev);
}

QDF_STATUS ol_if_deinit_dfs_for_mode_switch_fast(
        struct ol_ath_softc_net80211 *scn,
        ol_ath_hw_mode_ctx_t *hw_mode_ctx)
{
    struct target_psoc_info  *tgt_hdl;
    struct wlan_objmgr_psoc *psoc;
    uint8_t num_radios, pdev_id;

    if (!hw_mode_ctx) {
        qdf_err("hardware mode context is null");
        return QDF_STATUS_E_FAILURE;
    }

    if (!scn) {
        qdf_err("scn is null!");
        return QDF_STATUS_E_FAILURE;
    }

    psoc = scn->soc->psoc_obj;

    if(!psoc) {
       qdf_err("psoc is null!");
       return QDF_STATUS_E_FAILURE;
    }

    tgt_hdl = (struct target_psoc_info *)
               wlan_psoc_get_tgt_if_handle(psoc);
    num_radios = target_psoc_get_num_radios(tgt_hdl);
    ol_if_dfs_deinit_nol(scn, hw_mode_ctx->target_mode);
    ieee80211_dfs_nol_reset(&scn->sc_ic);

    /*
     * Take the hw_mode_ctx and for every pdev in that hw_mode send the
     * STOP event to Agile SM (in function ol_if_dfs_reset_agile_cac).
     * Agile SM processes the STOP event for the current pdev and rejects
     * it for all other pdevs. Only one abort goes to F/W.
     */
    for (pdev_id = 0; pdev_id < num_radios; pdev_id++) {
            struct wlan_objmgr_pdev *pdev  = NULL;
            struct ieee80211com               *ic;
            struct ol_ath_softc_net80211 *l_scn;

            pdev = wlan_objmgr_get_pdev_by_id(psoc,
                                              pdev_id, WLAN_MLME_NB_ID);
            if (!pdev) {
                continue;
            }

            l_scn = (struct ol_ath_softc_net80211 *)lmac_get_pdev_feature_ptr(pdev);

            if (!l_scn) {
                wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
                continue;
            }

            ic = &l_scn->sc_ic;

            if (!ic) {
                wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
                continue;
            }

            if (hw_mode_ctx->target_band & ic->ic_supported_bands) {
                ol_if_dfs_reset_agile_cac(&l_scn->sc_ic);
            }
            wlan_objmgr_pdev_release_ref(pdev, WLAN_MLME_NB_ID);
    }

    ol_if_dfs_psoc_deinit_pre_hw_mode_switch(psoc);

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS ol_if_reinit_dfs_for_mode_switch_fast(
        struct ol_ath_softc_net80211 *scn,
        uint8_t target_hw_mode)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;


    ol_if_dfs_reinit_nol(scn, target_hw_mode);
    ol_if_dfs_reinit_precac_lists(scn, target_hw_mode);

    pdev = ic->ic_pdev_obj;
    if (!pdev) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                  QDF_TRACE_LEVEL_ERROR, FL("primary pdev is NULL!"));
        return QDF_STATUS_E_FAILURE;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
                  QDF_TRACE_LEVEL_ERROR, FL("psoc is NULL!"));
        return QDF_STATUS_E_FAILURE;
    }

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    if (!dfs_rx_ops)
        return QDF_STATUS_E_FAILURE;

    if (dfs_rx_ops->dfs_complete_deferred_tasks)
        dfs_rx_ops->dfs_complete_deferred_tasks(pdev);

#ifdef QCA_SUPPORT_AGILE_DFS
    if (dfs_rx_ops->dfs_agile_sm_deliver_evt)
        dfs_rx_ops->dfs_agile_sm_deliver_evt(pdev,
                                             DFS_AGILE_SM_EV_AGILE_START);
#endif
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS ol_if_hw_mode_switch_state(struct wlan_objmgr_pdev *pdev,
        bool *is_hw_mode_switch_in_progress)
{
    struct ieee80211com *ic = wlan_pdev_get_mlme_ext_obj(pdev);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_hw_mode_ctx_t *hw_mode_ctx;

    *is_hw_mode_switch_in_progress = false;
    if (!scn || !pdev)
        return QDF_STATUS_E_FAILURE;

    hw_mode_ctx = &scn->soc->hw_mode_ctx;
    if (hw_mode_ctx->primary_pdev == pdev && hw_mode_ctx->is_switch_in_progress)
        *is_hw_mode_switch_in_progress = true;

    return QDF_STATUS_SUCCESS;
}
#endif /* ATH_SUPPORT_DFS */
