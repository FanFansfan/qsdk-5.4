/*
 * Copyright (c) 2011,2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * Notifications and licenses are retained for attribution purposes only.
 */
/*
 * Copyright (c) 2002-2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2005-2006 Atheros Communications, Inc.
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the following conditions are met:
 * 1. The materials contained herein are unmodified and are used
 *    unmodified.
 * 2. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following NO
 *    ''WARRANTY'' disclaimer below (''Disclaimer''), without
 *    modification.
 * 3. Redistributions in binary form must reproduce at minimum a
 *    disclaimer similar to the Disclaimer below and any redistribution
 *    must be conditioned upon including a substantially similar
 *    Disclaimer requirement for further binary redistribution.
 * 4. Neither the names of the above-listed copyright holders nor the
 *    names of any contributors may be used to endorse or promote
 *    product derived from this software without specific prior written
 *    permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT,
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

#include "ol_if_athvar.h"

#include "athdefs.h"
#include "ol_defines.h"
#include "ol_if_ath_api.h"
#include "ol_helper.h"
#include "qdf_mem.h"
#include "target_if.h"

#include "ol_regdomain.h"
#include <wlan_osif_priv.h>
#include <wlan_lmac_if_api.h>
#include <wlan_reg_ucfg_api.h>
#include <init_deinit_lmac.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <ol_regdomain_common.h>

/* used throughout this file... */
#define    N(a)    (sizeof (a) / sizeof (a[0]))

/* Global configuration overrides */
static    const int countrycode = -1;
static    const int xchanmode = -1;
static    const int ath_outdoor = AH_FALSE;        /* enable outdoor use */
static    const int ath_indoor  = AH_FALSE;        /* enable indoor use  */

static u_int16_t getEepromRD(struct ol_regdmn* ol_regdmn_handle);

int
ol_ath_pdev_set_regdomain(struct ol_ath_softc_net80211 * scn,
        struct cur_regdmn_info *cur_regdmn)
{
    struct pdev_set_regdomain_params param;
    struct wmi_unified *pdev_wmi_handle;

    pdev_wmi_handle = lmac_get_pdev_wmi_handle(scn->sc_pdev);

    if (!pdev_wmi_handle) {
        qdf_err("pdev_wmi_handle is NULL");
        return -EINVAL;
    }

    qdf_mem_set(&param, sizeof(param), 0);
    param.currentRDinuse = cur_regdmn->regdmn_pair_id;
    param.currentRD2G = cur_regdmn->dmn_id_2g;
    param.currentRD5G = cur_regdmn->dmn_id_5g;
    param.ctl_2G = cur_regdmn->ctl_2g;
    param.ctl_5G = cur_regdmn->ctl_5g;
    param.dfsDomain = cur_regdmn->dfs_region;
    param.pdev_id = lmac_get_pdev_idx(scn->sc_pdev);

    return wmi_unified_pdev_set_regdomain_cmd_send(pdev_wmi_handle, &param);
}

bool ol_regdmn_set_regdomain(struct ol_regdmn* ol_regdmn_handle, uint16_t regdomain)
{
    ol_regdmn_handle->ol_regdmn_current_rd = regdomain;

    return true;
}

bool ol_regdmn_set_regdomain_ext(struct ol_regdmn* ol_regdmn_handle, uint16_t regdomain)
{
    ol_regdmn_handle->ol_regdmn_current_rd_ext = regdomain;
    return true;
}

static struct wlan_psoc_host_hal_reg_capabilities_ext *ol_regdmn_reg_cap(
			struct ol_ath_softc_net80211 * scn)
{
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap;

    reg_cap = ucfg_reg_get_hal_reg_cap(scn->soc->psoc_obj);
    return &reg_cap[lmac_get_pdev_idx(scn->sc_pdev)];
}

/* Helper function to get hardware wireless capabilities */
u_int ol_regdmn_getWirelessModes(struct ol_regdmn* ol_regdmn_handle)
{
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap;

    reg_cap = ol_regdmn_reg_cap(ol_regdmn_handle->scn_handle);

    return reg_cap->wireless_modes;
}

#ifdef OL_ATH_DUMP_RD_SPECIFIC_CHANNELS
void inline
ol_ath_dump_channel_entry(struct ieee80211_ath_channel * channel)
{
    qdf_info(
        "%4d %016llX      %02X     %03d         %02d       %02d"
        "       %02X         %02d     %02d   %02d   %02d ",
        channel->ic_freq,
        channel->ic_flags,
        channel->ic_flagext,
        channel->ic_ieee,
        channel->ic_maxregpower,
        channel->ic_maxpower,
        channel->ic_minpower,
        channel->ic_regClassId,
        channel->ic_antennamax,
        channel->ic_vhtop_ch_freq_seg1,
        channel->ic_vhtop_ch_freq_seg2
        );

    if( IEEE80211_IS_CHAN_TURBO(channel) )
    {
        qdf_info("TURBO ");
    }

    if( IEEE80211_IS_CHAN_CCK(channel) )
    {
        qdf_info("CCK ");
    }

    if( IEEE80211_IS_CHAN_OFDM(channel) )
    {
        qdf_info("OFDM ");
    }

    if( IEEE80211_IS_CHAN_2GHZ(channel) )
    {
        qdf_info("2G ");
    }

    if( IEEE80211_IS_CHAN_5GHZ(channel) )
    {
        qdf_info("5G ");
    }

    if( IEEE80211_IS_CHAN_PASSIVE(channel) )
    {
        qdf_info("PSV ");
    }

    if( IEEE80211_IS_CHAN_DYN(channel) )
    {
        qdf_info("DYN ");
    }

    if( IEEE80211_IS_CHAN_GFSK(channel) )
    {
        qdf_info("GFSK ");
    }

    if( IEEE80211_IS_CHAN_DFS_RADAR(channel) )
    {
        qdf_info("RDR ");
    }

    if( IEEE80211_IS_CHAN_STURBO(channel) )
    {
        qdf_info("STURBO ");
    }

    if( IEEE80211_IS_CHAN_HALF(channel) )
    {
        qdf_info("HALF ");
    }

    if( IEEE80211_IS_CHAN_QUARTER(channel) )
    {
        qdf_info("QUARTER ");
    }


    if( IEEE80211_IS_CHAN_BW_HT20(channel) )
    {
        qdf_info("HT20 ");
    }

    if( IEEE80211_IS_CHAN_BW_HT40PLUS(channel) )
    {
        qdf_info("HT40+ ");
    }

    if( IEEE80211_IS_CHAN_BW_HT40MINUS(channel) )
    {
        qdf_info("HT40- ");
    }

    if( IEEE80211_IS_CHAN_BW_HT40INTOL(channel) )
    {
        qdf_info("HT40INTOL ");
    }

    if( IEEE80211_IS_CHAN_BW_VHT20(channel) )
    {
        qdf_info("VHT20 ");
    }

    if( IEEE80211_IS_CHAN_BW_VHT40PLUS(channel) )
    {
        qdf_info("VHT40+ ");
    }

    if( IEEE80211_IS_CHAN_BW_VHT40MINUS(channel) )
    {
        qdf_info("VHT40- ");
    }


    if( IEEE80211_IS_CHAN_BW_VHT80(channel) )
    {
        qdf_info("VHT80 ");
    }

    if( IEEE80211_IS_CHAN_BW_VHT160(channel) )
    {
        qdf_info("VHT160 ");
    }

    if( IEEE80211_IS_CHAN_BW_VHT80_80(channel) )
    {
        qdf_info("VHT80_80 ");
    }

    if( IEEE80211_IS_CHAN_BW_HE20(channel) )
    {
        qdf_info("HE20 ");
    }

    if( IEEE80211_IS_CHAN_BW_HE40PLUS(channel) )
    {
        qdf_info("HE40PLUS ");
    }

    if( IEEE80211_IS_CHAN_BW_HE40MINUS(channel) )
    {
        qdf_info("HE40MINUS ");
    }

    if( IEEE80211_IS_CHAN_BW_HE40INTOL(channel) )
    {
        qdf_info("HE40INTOL ");
    }

    if( IEEE80211_IS_CHAN_BW_HE80(channel) )
    {
        qdf_info("HE80 ");
    }

    if( IEEE80211_IS_CHAN_BW_HE160(channel) )
    {
        qdf_info("HE160 ");
    }

    if( IEEE80211_CHAN_HE80_80(channel) )
    {
        qdf_info("HE80_80 ");
    }

    qdf_info("\n");
}

void inline ol_ath_dump_rd_specific_channels(
        struct ieee80211com *ic,
        uint16_t regdmn_pair_id)
{

    struct ieee80211_ath_channel *chans = ic->ic_channels;
    uint32_t i;
    char str[4];

    qdf_print("\tXXXXXX RegDomain specific channel list XXXXXX");

    ieee80211_getCurrentCountryISO(ic, str);
    qdf_print("Current RD in use : %x country code = %d country ISO = %s",
            regdmn_pair_id, ieee80211_getCurrentCountry(ic), str);

    qdf_print("freq    flags flagext IEEE No. maxregpwr "
            "maxtxpwr mintxpwr regclassID antmax "
            "seg1 seg2");

    for( i = 0; i < ic->ic_nchans; i++ )
    {
        ol_ath_dump_channel_entry( &chans[i] );
    }
}
#endif

int ol_regdmn_getchannels(struct ol_regdmn *ol_regdmn_handle, unsigned int cc,
                          bool outDoor, bool xchanMode,
                          IEEE80211_REG_PARAMETERS *reg_parm)
{
    struct ol_ath_softc_net80211 * scn_handle;
    struct ieee80211com *ic;
    struct ieee80211_ath_channel *chans;
    uint8_t regclassids[ATH_REGCLASSIDS_MAX];
    unsigned int nregclass = 0;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;
    struct cur_regdmn_info cur_regdmn;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;

    scn_handle = ol_regdmn_handle->scn_handle;
    ic = &scn_handle->sc_ic;

    pdev = ic->ic_pdev_obj;
    if (!pdev) {
        qdf_err("pdev is null");
        return -EINVAL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("psoc is null");
        return -EINVAL;
    }

    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);

    chans = ic->ic_channels;

    if (!chans) {
        qdf_nofl_info("%s: unable to allocate channel table\n", __func__);
        return -ENOMEM;
    }

    /*
     * remove some of the modes based on different compile time
     * flags.
     */

    ol_80211_channel_setup(ic, CLIST_UPDATE, regclassids, nregclass);

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
    if (!(reg_rx_ops && reg_rx_ops->reg_get_current_regdomain)) {
        qdf_print("%s : reg_rx_ops is NULL", __func__);
        return -EINVAL;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
            QDF_STATUS_SUCCESS) {
        return -EINVAL;
    }

    reg_rx_ops->reg_get_current_regdomain(pdev, &cur_regdmn);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
#ifdef OL_ATH_DUMP_RD_SPECIFIC_CHANNELS
    ol_ath_dump_rd_specific_channels(ic, cur_regdmn.regdmn_pair_id);
#endif

    ol_ath_pdev_set_regdomain(scn_handle, &cur_regdmn);

    if (dfs_rx_ops && dfs_rx_ops->dfs_get_radars) {
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                QDF_STATUS_SUCCESS) {
            return -EINVAL;
        }
        dfs_rx_ops->dfs_get_radars(pdev);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    }

    return 0;
}

void
ol_regdmn_start(struct ol_regdmn *ol_regdmn_handle, IEEE80211_REG_PARAMETERS *reg_parm )
{
    struct ol_ath_softc_net80211 * scn_handle;
    int error;
    struct ieee80211com *ic;
    uint16_t regdmn;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;

    scn_handle = ol_regdmn_handle->scn_handle;
    ic = &scn_handle->sc_ic;

    qdf_print(
            "%s: reg-domain param: regdmn=%X, countryName=%s, wModeSelect=%X, netBand=%X, extendedChanMode=%X.",
            __func__,
            reg_parm->regdmn,
            reg_parm->countryName,
            reg_parm->wModeSelect,
            reg_parm->netBand,
            reg_parm->extendedChanMode);

    if (reg_parm->regdmn) {
        /* Set interface regdmn configuration */
        wlan_set_regdomain(ic, reg_parm->regdmn);
    } else if (countrycode != -1) {
        ieee80211_reg_program_cc(ic, NULL, countrycode);
    } else if (reg_parm->countryName[0]) {
        ieee80211_reg_program_cc(ic, reg_parm->countryName, 0);
    } else {
        regdmn = getEepromRD(ol_regdmn_handle);

        pdev =  ic->ic_pdev_obj;
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
                QDF_STATUS_SUCCESS) {
            qdf_print("%s, %d unable to get reference", __func__, __LINE__);
            return;
        }

        psoc = wlan_pdev_get_psoc(pdev);
        if (psoc == NULL) {
            qdf_print("%s: psoc is NULL", __func__);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
            return;
        }

        reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
        if (!(reg_rx_ops && reg_rx_ops->reg_program_default_cc)) {
            qdf_print("%s : reg_rx_ops is NULL", __func__);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
            return;
        }

        reg_rx_ops->reg_program_default_cc(pdev, regdmn);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
    }

    if (xchanmode != -1) {
        ol_regdmn_handle->ol_regdmn_xchanmode = xchanmode;
    } else {
        ol_regdmn_handle->ol_regdmn_xchanmode = reg_parm->extendedChanMode;
    }

    ieee80211_reg_create_ieee_chan_list(ic);

    error = ol_regdmn_getchannels(ol_regdmn_handle,
            ieee80211_getCurrentCountry(ic),
            ath_outdoor,
            ol_regdmn_handle->ol_regdmn_xchanmode,
            reg_parm);

    if (error != 0) {
        qdf_nofl_info( "%s[%d]: Failed to get channel information! error[%d]\n", __func__, __LINE__, error );
    }

}

void
ol_regdmn_detach(struct ol_regdmn* ol_regdmn_handle)
{
    if (ol_regdmn_handle != NULL) {
        OS_FREE(ol_regdmn_handle);
        ol_regdmn_handle = NULL;
    }
}

static u_int16_t
getEepromRD(struct ol_regdmn* ol_regdmn_handle)
{
    return ol_regdmn_handle->ol_regdmn_current_rd &~ WORLDWIDE_ROAMING_FLAG;
}
#undef N

void
ol_80211_channel_setup(struct ieee80211com *ic,
		enum ieee80211_clist_cmd cmd,
		const u_int8_t *regclassids,
		u_int nregclass)
{

    /*
     * The DFS/NOL management is now done via ic_dfs_clist_update(),
     * rather than via the channel setup API.
     */
    if ((cmd == CLIST_DFS_UPDATE) || (cmd == CLIST_NOL_UPDATE)) {
        qdf_print("%s: cmd=%d, should not have gotten here!",
          __func__,
          cmd);
    }

    /* Copy regclass ids */
    ieee80211_set_regclassids(ic, regclassids, nregclass);
}

int ol_ath_set_opclass_tbl(struct ieee80211com *ic, uint8_t opclass)
{
    return ieee80211_reg_program_opclass_tbl(ic, opclass);
}

int ol_ath_get_opclass_tbl(struct ieee80211com *ic, uint8_t *opclass)
{
    return ieee80211_reg_get_opclass_tbl(ic, opclass);
}

static int
ol_ath_set_country(struct ieee80211com *ic,
                         char *isoName, u_int16_t cc, enum ieee80211_clist_cmd cmd)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int err = 0;
    wmi_unified_t wmi_handle;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;

    wmi_handle = lmac_get_wmi_hdl(scn->soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    qdf_event_reset(&ic->ic_wait_for_init_cc_response);
    err = ieee80211_reg_program_cc(ic, isoName, cc);
    if (err)
        return err;

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(scn->soc->psoc_obj);
    if (!(reg_rx_ops && reg_rx_ops->reg_enable_dfs_channels)) {
            IEEE80211_DPRINTF_IC_CATEGORY(ic,  IEEE80211_MSG_ANY,"reg_rx_ops is NULL");
        return -EINVAL;
    }

    if (!(wmi_service_enabled(wmi_handle, wmi_service_regulatory_db))) {
        reg_rx_ops->reg_enable_dfs_channels(ic->ic_pdev_obj, !scn->sc_is_blockdfs_set);
        err = ieee80211_reg_create_ieee_chan_list(ic);
        if (err)
            return err;
        ol_regdmn_getchannels(scn->ol_regdmn_handle,
                ieee80211_getCurrentCountry(ic),
                ath_outdoor,
                scn->ol_regdmn_handle->ol_regdmn_xchanmode,
                &ic->ic_reg_parm);
    } else {
        /* Wait for WMI_REG_CHAN_LIST_CC_EVENTID */
        ic->ic_set_country_failed = false;
        if (qdf_wait_single_event(&ic->ic_wait_for_init_cc_response,
                    REG_INIT_CC_RX_TIMEOUT)) {
            QDF_BUG(0);
            return A_ERROR;
        }
        reg_rx_ops->reg_enable_dfs_channels(ic->ic_pdev_obj, !scn->sc_is_blockdfs_set);
    }

    if (ic->ic_set_country_failed == true) {
        return -EINVAL;
    }

    /* Country code is changed, reset the dfs variables */
    ieee80211_dfs_reset(ic);
    ic->no_chans_available = 0;

    return 0;
}

int
ol_ath_set_regdomain(struct ieee80211com *ic, uint32_t regdomain, bool no_chanchange)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int ret;
    uint32_t orig_regdomain = 0;
    int err = 0;
    uint8_t ctry_iso[REG_ALPHA2_LEN + 1];
    wmi_unified_t wmi_handle;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;


    /* Backup original regdomain, if set regdomain failed, restore */
    orig_regdomain = ieee80211_get_regdomain(ic);

    qdf_event_reset(&ic->ic_wait_for_init_cc_response);

    ret = wlan_set_regdomain(ic, regdomain);
    if (ret) {
        /* set regdomain failed, reset with original regdomain */
        qdf_print("set regdomain failed, reset with original regdomain = %d",
                orig_regdomain);
        ret = wlan_set_regdomain(ic, orig_regdomain);
        if (ret) {
            qdf_print("%s: set regdomain failed", __func__);
            return -EINVAL;
        }
    }
   reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(scn->soc->psoc_obj);
   if (!(reg_rx_ops && reg_rx_ops->reg_enable_dfs_channels)) {
           IEEE80211_DPRINTF_IC_CATEGORY(ic,  IEEE80211_MSG_ANY,"reg_rx_ops is NULL");
       return -EINVAL;
   }
    wmi_handle = lmac_get_wmi_hdl(scn->soc->psoc_obj);
    if (!wmi_handle) {
        qdf_err("wmi_handle is null");
        return -EINVAL;
    }

    if (!(wmi_service_enabled(wmi_handle, wmi_service_regulatory_db))) {
        reg_rx_ops->reg_enable_dfs_channels(ic->ic_pdev_obj, !scn->sc_is_blockdfs_set);
        err = ieee80211_reg_create_ieee_chan_list(ic);
        if (err)
            return err;
        ol_regdmn_getchannels(scn->ol_regdmn_handle,
                ieee80211_getCurrentCountry(ic),
                ath_outdoor,
                scn->ol_regdmn_handle->ol_regdmn_xchanmode,
                &ic->ic_reg_parm);
    } else {
        /* Wait for WMI_REG_CHAN_LIST_CC_EVENTID */
        ic->ic_set_country_failed = false;
        if (!(ic->recovery_in_progress) && qdf_wait_single_event(&ic->ic_wait_for_init_cc_response,
                    REG_INIT_CC_RX_TIMEOUT)) {
            QDF_BUG(0);
            return A_ERROR;
        }
        if(ic->recovery_in_progress) {
            return A_ERROR;
        }
        reg_rx_ops->reg_enable_dfs_channels(ic->ic_pdev_obj, !scn->sc_is_blockdfs_set);
    }

    if (ic->ic_set_country_failed == true) {
        return -EINVAL;
    }

    /* regdomain is changed, reset the dfs variables */
    ieee80211_dfs_reset(ic);
    ic->no_chans_available = 0;

#if UMAC_SUPPORT_CFG80211
    ic->ic_cfg80211_update_channel_list(ic);
#endif

    /* update channel list */
    err = ieee80211_update_channellist(ic, 1, no_chanchange);
    if (err)
        return err;

    ieee80211_getCurrentCountryISO(ic, ctry_iso);
    ieee80211_build_countryie_all(ic, ctry_iso);

    return 0;
}

/*
 * Determine if the pdev supports 2.4GHZ.
 * This is done validating the wireless mode for the pdev
 * populated from FW during service ready.
 * @ic: Pointer to struct ieee80211com.
 */
bool ol_ath_pdev_is_2ghz_supported(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    u_int modesAvail;

    modesAvail = ol_regdmn_getWirelessModes(scn->ol_regdmn_handle);

    return (modesAvail && WIRELESS_MODES_2G);
}

/* Regdomain Initialization functions */
int
ol_regdmn_attach(struct ol_ath_softc_net80211 *scn_handle)
{
    struct ol_regdmn *ol_regdmn_handle;
    struct ieee80211com *ic = &scn_handle->sc_ic;

    ic->ic_set_country = ol_ath_set_country;
    ic->ic_set_regdomain = ol_ath_set_regdomain;
    ic->ic_pdev_is_2ghz_supported = ol_ath_pdev_is_2ghz_supported;

    ol_regdmn_handle = (struct ol_regdmn *)OS_MALLOC(scn_handle->sc_osdev, sizeof(struct ol_regdmn), GFP_ATOMIC);
    if (ol_regdmn_handle == NULL) {
        qdf_info("allocation of ol regdmn handle failed %zu", sizeof(struct ol_regdmn));
        return 1;
    }
    OS_MEMZERO(ol_regdmn_handle, sizeof(struct ol_regdmn));
    ol_regdmn_handle->scn_handle = scn_handle;
    ol_regdmn_handle->osdev = scn_handle->sc_osdev;

    scn_handle->ol_regdmn_handle = ol_regdmn_handle;

    ol_regdmn_handle->ol_regdmn_current_rd = 0; /* Current regulatory domain */
    ol_regdmn_handle->ol_regdmn_current_rd_ext = PEREGRINE_RDEXT_DEFAULT;    /* Regulatory domain Extension reg from EEPROM*/

    return 0;
}

bool ol_regdmn_set_ch144_eppovrd(struct ol_regdmn *ol_regdmn_handle, u_int ch144)
{
    if (ch144 >= 0){
        ol_regdmn_handle->ol_regdmn_ch144_eppovrd = (ch144 ? 1 : 0); /*user input shall act as bool*/
        return TRUE;
    } else
        return FALSE;
}



#if QCA_11AX_STUB_SUPPORT
/**
 * @brief Add 802.11ax modes to list of supported wireless modes
 *
 * @details
 *  This is only for test related stubbing purposes on chipsets that do not
 *  support 11ax.
 *
 * @param ol_regdmn_handle - Handle for offload regulatory domain instance
 */
void ol_regdmn_stub_add_11ax_modes(struct ol_regdmn* ol_regdmn_handle)
{
    struct ol_ath_softc_net80211 * scn_handle = NULL;
    struct wlan_psoc_host_hal_reg_capabilities_ext *reg_cap;

    qdf_assert_always((NULL != ol_regdmn_handle) &&
            (NULL != ol_regdmn_handle->scn_handle));

    scn_handle = ol_regdmn_handle->scn_handle;
    reg_cap = ol_regdmn_reg_cap(scn_handle);

    /* Shadow existing 2.4 GHz 11n wireless modes with 2.4 GHz 11ax ones.
     * Similarly, shadow existing 5 GHz 11ac wireless modes with 5 GHz 11ax ones.
     */

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11NG_HT20) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXG_HE20;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11NG_HT40PLUS) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXG_HE40PLUS;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11NG_HT40MINUS) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXG_HE40MINUS;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11AC_VHT20) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXA_HE20;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11AC_VHT40PLUS) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXA_HE40PLUS;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11AC_VHT40MINUS) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXA_HE40MINUS;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11AC_VHT80) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXA_HE80;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11AC_VHT160) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXA_HE160;
    }

    if (reg_cap->wireless_modes &
            WMI_HOST_REGDMN_MODE_11AC_VHT80_80) {
        reg_cap->wireless_modes |=
            WMI_HOST_REGDMN_MODE_11AXA_HE80_80;
    }
}

uint32_t ol_ath_get_chip_mode(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint32_t modesAvail;
    struct ol_regdmn *ol_regdmn_handle;

    ol_regdmn_handle = scn->ol_regdmn_handle;
    modesAvail = ol_regdmn_getWirelessModes(ol_regdmn_handle);

    return modesAvail;
}

#endif /* QCA_11AX_STUB_SUPPORT */

QDF_STATUS ol_regdmn_update_pdev_wireless_modes(struct ieee80211com *ic,
                                                uint32_t wireless_modes)
{
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct wlan_objmgr_psoc *psoc;
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc)
        return QDF_STATUS_E_FAILURE;

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);

    if (reg_rx_ops && reg_rx_ops->reg_update_pdev_wireless_modes) {
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
            QDF_STATUS_SUCCESS) {
            return QDF_STATUS_E_FAILURE;
        }

        status = reg_rx_ops->reg_update_pdev_wireless_modes(pdev, wireless_modes);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
    }

    if (status != QDF_STATUS_SUCCESS)
        return status;

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS ol_regdmn_reinit_post_hw_mode_switch(struct ieee80211com *ic)
{
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct wlan_objmgr_psoc *psoc;
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc)
        return QDF_STATUS_E_FAILURE;

    reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
    if (reg_rx_ops && reg_rx_ops->reg_modify_pdev_chan_range) {
        status = reg_rx_ops->reg_modify_pdev_chan_range(pdev);
    }

    if (status != QDF_STATUS_SUCCESS)
        goto exit;

    /* update channel list */
#if UMAC_SUPPORT_CFG80211
    ic->ic_cfg80211_update_channel_list(ic);
#endif

    /* Update ic_modecaps based on the new channel list */
    status = ieee80211_update_channellist(ic, 1, true);
exit:
    return status;
}

static void
ieee80211_update_node_channel(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211_ath_channel *ni_chan = (struct ieee80211_ath_channel *)arg;

    ni->ni_chan = ni_chan;
}

QDF_STATUS ol_ath_copy_curchan_params(struct ieee80211com *ic,
        ol_ath_hw_mode_ctx_t *hw_mode_ctx)
{
    enum ieee80211_phymode phymode;

    if (!ic->ic_curchan) {
        hw_mode_ctx->curchan_params.freq = 0;
        return QDF_STATUS_E_FAILURE;
    }
    /* Copy the current channel parameters. */
    hw_mode_ctx->curchan_params.freq = ic->ic_curchan->ic_freq;
    phymode = ieee80211_chan2mode(ic->ic_curchan);

    /* If target mode is DBS_SBS, reduce the bandwidth of the primary radio
     * to 80MHz if it was operating in a bandwidth greater than 80MHz.
     */
    if (hw_mode_ctx->target_mode == WMI_HOST_HW_MODE_DBS_SBS) {
        if (ieee80211_is_phymode_11ac_160or8080(phymode)) {
            phymode = IEEE80211_MODE_11AC_VHT80;
            hw_mode_ctx->is_bw_reduced_during_dms = true;
        } else if (ieee80211_is_phymode_11axa_160or8080(phymode)) {
            phymode = IEEE80211_MODE_11AXA_HE80;
            hw_mode_ctx->is_bw_reduced_during_dms = true;
        }
    }
    hw_mode_ctx->curchan_params.phymode = phymode;

    /* When the radios are disabled, if the mode switch command is issued,
     * the previous channel will not be initialized. In that case, do not try
     * reinitializing the previous channel. (indicated by frequency as 0).
     */
    if (!ic->ic_prevchan) {
        hw_mode_ctx->prevchan_params.freq = 0;
    } else {
        hw_mode_ctx->prevchan_params.freq = ic->ic_prevchan->ic_freq;
        hw_mode_ctx->prevchan_params.phymode =
                ieee80211_chan2mode(ic->ic_prevchan);
    }
    return QDF_STATUS_SUCCESS;
}

QDF_STATUS ol_ath_reinit_channel_params(struct ieee80211com *ic,
        ol_ath_hw_mode_ctx_t *hw_mode_ctx)
{
    struct chan_params stored_curchan = hw_mode_ctx->curchan_params;
    struct chan_params stored_prevchan = hw_mode_ctx->prevchan_params;
    struct ieee80211vap *vap = NULL, *tvap = NULL;

    if (!stored_curchan.freq)
        return QDF_STATUS_E_FAILURE;
    /* Reinit ic_curchan with current channel parameters. */
    ic->ic_curchan = ieee80211_find_dot11_channel(ic,
                                                  stored_curchan.freq,
                                                  0,
                                                  stored_curchan.phymode);
    if (!ic->ic_curchan) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG, QDF_TRACE_LEVEL_ERROR,
                  FL("Current channel is not present in new primary radio."
                     "Abort mode switch"));
        return QDF_STATUS_E_FAILURE;
    }
    if (stored_prevchan.freq)
        ic->ic_prevchan = ieee80211_find_dot11_channel(ic,
                                                       stored_prevchan.freq,
                                                       0,
                                                       stored_prevchan.phymode);

    /* If we can't find the previous channel in the updated channel list,
     * update it to default channel. */
    if (!ic->ic_prevchan || !stored_prevchan.freq)
        ic->ic_prevchan = &ic->ic_channels[0];

    /* Update ic_tx_next_ch with a random channel in the updated channel list */
    ieee80211_update_dfs_next_channel(ic);

    /* Update DFS current channel if bandwidth is reduced */
    if (hw_mode_ctx->is_bw_reduced_during_dms) {
        struct wlan_objmgr_pdev *pdev;
        struct wlan_objmgr_psoc *psoc;
        struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops;

        pdev = ic->ic_pdev_obj;
        if(!pdev) {
            qdf_err("%s : pdev is null", __func__);
            return QDF_STATUS_E_FAILURE;
        }

        psoc = wlan_pdev_get_psoc(pdev);

        if (!psoc) {
            qdf_err("%s : psoc is null", __func__);
            return QDF_STATUS_E_FAILURE;
        }

        dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
        if (dfs_rx_ops && dfs_rx_ops->dfs_set_current_channel_for_freq) {
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                QDF_STATUS_SUCCESS) {
                return QDF_STATUS_E_FAILURE;
            }
            dfs_rx_ops->dfs_set_current_channel_for_freq(pdev,
                    ic->ic_curchan->ic_freq,
                    ic->ic_curchan->ic_flags,
                    ic->ic_curchan->ic_flagext,
                    ic->ic_curchan->ic_ieee,
                    ic->ic_curchan->ic_vhtop_ch_num_seg1,
                    ic->ic_curchan->ic_vhtop_ch_num_seg2,
                    ic->ic_curchan->ic_vhtop_freq_seg1,
                    ic->ic_curchan->ic_vhtop_freq_seg2,
                    NULL);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
        }
    }

    /* Reset the vap channel structures as well. */
    if (!TAILQ_EMPTY(&ic->ic_vaps)) {
        TAILQ_FOREACH_SAFE(vap, &ic->ic_vaps, iv_next, tvap) {
            /* Update des_mode if bandwidth is reduced during mode switch. */
            if (hw_mode_ctx->is_bw_reduced_during_dms) {
                wlan_set_desired_phymode(vap, stored_curchan.phymode);
                vap->iv_cur_mode = stored_curchan.phymode;
            }

            vap->iv_bsschan = ic->ic_curchan;
            vap->iv_des_chan[vap->iv_des_mode] = ic->ic_curchan;

            wlan_iterate_station_list(vap,
                                      ieee80211_update_node_channel,
                                      ic->ic_curchan);
            /* Update VDEV SM channel structures. */
            ieee80211_update_vdev_chan(vap->vdev_obj->vdev_mlme.des_chan,
                                       ic->ic_curchan);
            ieee80211_update_vdev_chan(vap->vdev_obj->vdev_mlme.bss_chan,
                                       ic->ic_curchan);
            /* If the bandwidth of the primary pdev changes, update peer
             * channel width value in HOST and FW. */
            if (hw_mode_ctx->is_bw_reduced_during_dms)
                ieee80211_update_peer_cw(ic, vap);
        }
    }

    return QDF_STATUS_SUCCESS;
}
