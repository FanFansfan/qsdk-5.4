/*
 * Copyright (c) 2011-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2008 Atheros Communications Inc.
 * All Rights Reserved.
 */

/*
 *  all the IE parsing/processing routines.
 */
#include <ieee80211_var.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include "ieee80211_mlme_priv.h"
#include "ieee80211_proto.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"
#include "ol_if_athvar.h"
#include "ieee80211_mlme_dfs_dispatcher.h"
#include <wlan_lmac_if_api.h>
#include <wlan_objmgr_psoc_obj.h>

#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"

#include <wlan_son_pub.h>

#include <target_if.h>

#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"
#include <wlan_dfs_ioctl.h>
#include <wlan_mlme_dp_dispatcher.h>
#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_utils_api.h>
#endif
#include <wlan_utility.h>
#include "cfg_ucfg_api.h"
#include <ieee80211.h>
#include <ieee80211_defines.h>
#include <wlan_vdev_mlme.h>
#include <init_deinit_lmac.h>
#include <wlan_rnr.h>
#include <wlan_reg_services_api.h>
#include <wlan_reg_ucfg_api.h>
#include <reg_services_public_struct.h>
#include <ieee80211_ucfg.h>
#include <include/wlan_psoc_mlme.h>
#include <wlan_reg_ucfg_api.h>

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
#endif
#endif

#define	IEEE80211_ADDSHORT(frm, v) 	do {frm[0] = (v) & 0xff; frm[1] = (v) >> 8;	frm += 2;} while (0)
#define	IEEE80211_ADDSELECTOR(frm, sel) do {OS_MEMCPY(frm, sel, 4); frm += 4;} while (0)
#define IEEE80211_SM(_v, _f)    (((_v) << _f##_S) & _f)
#define IEEE80211_MS(_v, _f)    (((_v) & _f) >> _f##_S)
#define RX_MCS_SINGLE_STREAM_BYTE_OFFSET            (0)
#define RX_MCS_DUAL_STREAM_BYTE_OFFSET              (1)
#define RX_MCS_ALL_NSTREAM_RATES                    (0xff)

#define MAX_ABS_NEG_PWR   64  /* Maximum Absolute Negative power in dB*/
#define MAX_ABS_POS_PWR   63  /* Maximum Absolute Positive power in dB*/
#define TWICE_MAX_POS_PWR 127 /* Twice Maximum positive power in dB */
#define IEEE80211_EXTCAPIE_ENABLE_SAE_PWID 0x1
#define IEEE80211_EXTCAPIE_ENABLE_SAE_PWID_ALL 0x2

/* Elem ID list offset in Non-inheritance IE */
#define NON_INH_ELEM_ID_LIST_OFFSET 4
#define IEEE80211_MBSS_MAX_NTX_PER_PFL_SIZE 252 /* Out of 255 bytes, 2 bytes
                                                   will be gone for MBSSID IE
                                                   header, and one byte for
                                                   Max BSSID Indicator */

void ieee80211_savenie(osdev_t osdev,u_int8_t **iep,
        const u_int8_t *ie, u_int ielen);
void ieee80211_saveie(osdev_t osdev,u_int8_t **iep, const u_int8_t *ie);
u_int8_t * ieee80211_add_vht_wide_bw_switch(u_int8_t *frm,
        struct ieee80211_node *ni, struct ieee80211com *ic,
        u_int8_t subtype, int is_vendor_ie);
uint32_t ieee80211_get_security_vendor_ies(struct ieee80211vap *vap, uint8_t *buf,
                                           ieee80211_frame_type ftype,
                                           bool is_copy, bool is_security);

enum ieee80211_phymode
ieee80211_derive_max_phy(enum ieee80211_phymode des_mode,
                         struct ieee80211_ath_channel *chan);

uint8_t get_nss_frm_mcsnssmap(uint16_t map);

/*
 * Add a supported rates element id to a frame.
 */
u_int8_t *
ieee80211_add_rates(struct ieee80211vap *vap, u_int8_t *frm, const struct ieee80211_rateset *rs)
{
    int nrates = rs->rs_nrates;

    if (nrates > IEEE80211_RATE_SIZE)
        nrates = IEEE80211_RATE_SIZE;

    *frm++ = IEEE80211_ELEMID_RATES;
    if ((nrates < IEEE80211_RATE_SIZE) &&
        (vap->iv_sae_pwe == SAE_PWE_H2E)) {
        *frm++ = nrates + 1;
    } else {
        *frm++ = nrates;
    }
    OS_MEMCPY(frm, rs->rs_rates, nrates);
    frm += nrates;
    if ((nrates < IEEE80211_RATE_SIZE) &&
        (vap->iv_sae_pwe == SAE_PWE_H2E)) {
        *frm++ = 0x80 | IEEE80211_BSS_MEMBERSHIP_SELECTOR_SAE_H2E_ONLY;
    }
    return frm;
}

/*
 * Add an extended supported rates element id to a frame.
 */
u_int8_t *
ieee80211_add_xrates(struct ieee80211vap *vap, u_int8_t *frm, const struct ieee80211_rateset *rs)
{
    /*
     * Add an extended supported rates element if operating in 11g mode.
     */
    if ((rs->rs_nrates > IEEE80211_RATE_SIZE) ||
        ((rs->rs_nrates == IEEE80211_RATE_SIZE) &&
        (vap->iv_sae_pwe == SAE_PWE_H2E))) {
        int nrates = rs->rs_nrates - IEEE80211_RATE_SIZE;
        *frm++ = IEEE80211_ELEMID_XRATES;
        if (vap->iv_sae_pwe == SAE_PWE_H2E) {
            *frm++ = nrates + 1;
        } else {
            *frm++ = nrates;
        }
        OS_MEMCPY(frm, rs->rs_rates + IEEE80211_RATE_SIZE, nrates);
        frm += nrates;
        if (vap->iv_sae_pwe == SAE_PWE_H2E) {
            *frm++ = 0x80 | IEEE80211_BSS_MEMBERSHIP_SELECTOR_SAE_H2E_ONLY;
            vap->iv_mbss.is_xrates = true;
        }
    }
    return frm;
}

/*
 * Add an ssid elemet to a frame.
 */
u_int8_t *
ieee80211_add_ssid(u_int8_t *frm, const u_int8_t *ssid, u_int len)
{
    *frm++ = IEEE80211_ELEMID_SSID;
    *frm++ = len;
    OS_MEMCPY(frm, ssid, len);
    return frm + len;
}

/*
 * Add an erp element to a frame.
 */
u_int8_t *
ieee80211_add_erp(u_int8_t *frm, struct ieee80211com *ic)
{
    u_int8_t erp;

    *frm++ = IEEE80211_ELEMID_ERP;
    *frm++ = 1;
    erp = 0;
    if (ic->ic_nonerpsta != 0 )
        erp |= IEEE80211_ERP_NON_ERP_PRESENT;
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        erp |= IEEE80211_ERP_USE_PROTECTION;
    if (ic->ic_flags & IEEE80211_F_USEBARKER)
        erp |= IEEE80211_ERP_LONG_PREAMBLE;
    *frm++ = erp;
    return frm;
}

/*
 * Add a country information element to a frame.
 */
u_int8_t *
ieee80211_add_country(u_int8_t *frm, struct ieee80211vap *vap)
{
    uint64_t chanflags;
    struct ieee80211com *ic = vap->iv_ic;
    uint8_t ctry_iso[REG_ALPHA2_LEN + 1];

    /* add country code */
    if (IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        chanflags = IEEE80211_CHAN_2GHZ;
    else if (IEEE80211_IS_CHAN_5GHZ(vap->iv_bsschan))
        chanflags = IEEE80211_CHAN_5GHZ;
    else
        chanflags = IEEE80211_CHAN_6GHZ;

    ieee80211_getCurrentCountryISO(ic, ctry_iso);

    if (chanflags != vap->iv_country_ie_chanflags)
        ieee80211_build_countryie(vap, ctry_iso);

    if (vap->iv_country_ie_data.country_len) {
    	OS_MEMCPY(frm, (u_int8_t *)&vap->iv_country_ie_data,
	    	vap->iv_country_ie_data.country_len + 2);
	    frm +=  vap->iv_country_ie_data.country_len + 2;
    }

    return frm;
}

/* ieee80211_add_tpc_ie(): Add TPC Report IE in the frame.
 * @frm : frame to append the IE.
 * @vap : Pointer to struct ieee80211vap.
 * Returns pointer to the frame after appending the IE.
 */
u_int8_t *
ieee80211_add_tpc_ie(u_int8_t *frm, struct ieee80211vap *vap, uint8_t subtype)
{
    struct ieee80211com *ic;
    uint16_t txpower;
    bool is_ema_ap_enabled;
    bool is_non_tx_vap;

    if (!vap)
        return NULL;

    ic = vap->iv_ic;
    if (!ic)
        return NULL;

    is_non_tx_vap = IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
    is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                                                WLAN_PDEV_FEXT_EMA_AP_ENABLE);

    txpower = vap->iv_bss->ni_txpower;

    /* txpower is a radio param. It must be same acorss all vaps.
     * In case of ema_ap, honor the value from tx-vap only
     */
    if (is_ema_ap_enabled &&
            is_non_tx_vap &&
            ic->ic_mbss.transmit_vap) {
        txpower = ic->ic_mbss.transmit_vap->iv_bss->ni_txpower;
    }

    *frm++ = IEEE80211_ELEMID_TPCREP;
    *frm++ = IEEE80211_TPCREP_LEN;

    if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
        qdf_debug("vdev_id: %d", vap->iv_unit);
        qdf_debug("txpower: %d", txpower);
    }

    /* Current TX power of the chan */
    *frm++ = (int8_t)(txpower/2);
    *frm++ = IEEE80211_TPC_LINKMARGIN_VAL;

    return frm;
}

u_int8_t
ieee80211_get_rxstreams(struct ieee80211com *ic, struct ieee80211vap *vap)
{
    u_int8_t rx_streams = 0;

    rx_streams = ieee80211_getstreams(ic, ic->ic_rx_chainmask);
#if ATH_SUPPORT_WAPI
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)
      ) {
        if (rx_streams > ic->ic_num_wapi_rx_maxchains)
            rx_streams = ic->ic_num_wapi_rx_maxchains;
    }
#endif
    return rx_streams;
}

u_int8_t
ieee80211_is_sta(struct ieee80211vap *vap)
{
    return (vap->iv_opmode == IEEE80211_M_STA);
}

u_int8_t
ieee80211_get_txstreams(struct ieee80211com *ic, struct ieee80211vap *vap)
{
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    u_int8_t tx_streams = 0;

    if(vdev_mlme->proto.generic.nss != 0){
        tx_streams = MIN(vdev_mlme->proto.generic.nss,
                ieee80211_getstreams(ic, ic->ic_tx_chainmask));
    }else{
        tx_streams = ieee80211_getstreams(ic, ic->ic_tx_chainmask);
    }
#if ATH_SUPPORT_WAPI
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)
      ) {
        if (tx_streams > ic->ic_num_wapi_tx_maxchains)
            tx_streams = ic->ic_num_wapi_tx_maxchains;
    }
#endif
    return tx_streams;
}

/* add IE for WAPI in mgmt frames */
#if ATH_SUPPORT_WAPI
u_int8_t *
ieee80211_setup_wapi_ie(struct ieee80211vap *vap, u_int8_t *ie)
{
    return wlan_crypto_build_wapiie(vap->vdev_obj, ie);
}
#endif /*ATH_SUPPORT_WAPI*/

/*
 * Add a WME Info element to a frame.
 */
u_int8_t *
ieee80211_add_wmeinfo(u_int8_t *frm, struct ieee80211_node *ni,
                      u_int8_t wme_subtype, u_int8_t *wme_info, u_int8_t info_len)
{
    static const u_int8_t oui[4] = { WME_OUI_BYTES, WME_OUI_TYPE };
    struct ieee80211_ie_wme *ie = (struct ieee80211_ie_wme *) frm;
    struct ieee80211_wme_state *wme = &ni->ni_ic->ic_wme;
    struct ieee80211vap *vap = ni->ni_vap;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0;                             /* length filled in below */
    OS_MEMCPY(frm, oui, sizeof(oui));       /* WME OUI */
    frm += sizeof(oui);
    *frm++ = wme_subtype;          /* OUI subtype */
    switch (wme_subtype) {
    case WME_INFO_OUI_SUBTYPE:
        *frm++ = WME_VERSION;                   /* protocol version */
        /* QoS Info field depends on operating mode */
        ie->wme_info = 0;
        switch (vap->iv_opmode) {
        case IEEE80211_M_HOSTAP:
            *frm = wme->wme_bssChanParams.cap_info & WME_QOSINFO_COUNT;
            if (IEEE80211_VAP_IS_UAPSD_ENABLED(vap)) {
                *frm |= WME_CAPINFO_UAPSD_EN;
            }
            frm++;
            break;
        case IEEE80211_M_STA:
            /* Set the U-APSD flags */
            if (ieee80211_vap_wme_is_set(vap) && (ni->ni_ext_caps & IEEE80211_NODE_C_UAPSD)) {
                *frm |= vap->iv_uapsd;
            }
            frm++;
            break;
        default:
            *frm++ = 0;
        }
        break;
    case WME_TSPEC_OUI_SUBTYPE:
        *frm++ = WME_TSPEC_OUI_VERSION;        /* protocol version */
        OS_MEMCPY(frm, wme_info, info_len);
        frm += info_len;
        break;
    default:
        break;
    }

    ie->wme_len = (u_int8_t)(frm - &ie->wme_oui[0]);

    return frm;
}

/*
 * Add a WME Parameter element to a frame.
 */
u_int8_t *
ieee80211_add_wme_param(u_int8_t *frm, struct ieee80211_wme_state *wme,
                        int uapsd_enable)
{
    static const u_int8_t oui[4] = { WME_OUI_BYTES, WME_OUI_TYPE };
    struct ieee80211_wme_param *ie = (struct ieee80211_wme_param *) frm;
    int i;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0;				/* length filled in below */
    OS_MEMCPY(frm, oui, sizeof(oui));		/* WME OUI */
    frm += sizeof(oui);
    *frm++ = WME_PARAM_OUI_SUBTYPE;		/* OUI subtype */
    *frm++ = WME_VERSION;			/* protocol version */

    ie->param_qosInfo = 0;
    *frm = wme->wme_bssChanParams.cap_info & WME_QOSINFO_COUNT;
    if (uapsd_enable) {
        *frm |= WME_CAPINFO_UAPSD_EN;
    }
    frm++;
    *frm++ = 0;                             /* reserved field */
    for (i = 0; i < WME_NUM_AC; i++) {
        const struct wmeParams *ac =
            &wme->wme_bssChanParams.cap_wmeParams[i];
        *frm++ = IEEE80211_SM(i, WME_PARAM_ACI)
            | IEEE80211_SM(ac->wmep_acm, WME_PARAM_ACM)
            | IEEE80211_SM(ac->wmep_aifsn, WME_PARAM_AIFSN)
            ;
        *frm++ = IEEE80211_SM(ac->wmep_logcwmax, WME_PARAM_LOGCWMAX)
            | IEEE80211_SM(ac->wmep_logcwmin, WME_PARAM_LOGCWMIN)
            ;
        IEEE80211_ADDSHORT(frm, ac->wmep_txopLimit);
    }

    ie->param_len = frm - &ie->param_oui[0];

    return frm;
}

#if ATH_SUPPORT_UORA
u_int8_t *
ieee80211_add_uora_param(u_int8_t *frm, u_int8_t ocw_range)
{
     struct ieee80211_ie_uora *ie = (struct ieee80211_ie_uora *)frm;
     u_int8_t uora_ie_len = sizeof(struct ieee80211_ie_uora);

     ie->uora_id = IEEE80211_ELEMID_EXTN;
     ie->uora_len = IEEE80211_UORA_LENGTH;
     ie->uora_id_ext = IEEE80211_ELEMID_EXT_UORA_PARAM;
     ie->uora_ocwrange = ocw_range;
     return frm + uora_ie_len;
}
#endif


u_int8_t *
ieee80211_add_muedca_param(u_int8_t *frm, struct ieee80211_muedca_state *muedca)
{
    struct ieee80211_ie_muedca *ie = (struct ieee80211_ie_muedca *)frm;
    u_int8_t muedca_ie_len = sizeof(struct ieee80211_ie_muedca);
    int iter;

    ie->muedca_id = IEEE80211_ELEMID_EXTN;
    ie->muedca_len = IEEE80211_MUEDCA_LENGTH;
    ie->muedca_id_ext = IEEE80211_ELEMID_EXT_MUEDCA;
    ie->muedca_qosinfo = IEEE80211_SM(muedca->muedca_param_update_count,
            IEEE80211_MUEDCA_UPDATE_COUNT);

    for(iter = 0; iter < MUEDCA_NUM_AC; iter++) {
        ie->muedca_param_record[iter].aifsn_aci =
            IEEE80211_SM(muedca->muedca_paramList[iter].muedca_aifsn,
                    IEEE80211_MUEDCA_AIFSN) |
            IEEE80211_SM(muedca->muedca_paramList[iter].muedca_acm,
                    IEEE80211_MUEDCA_ACM) |
            IEEE80211_SM(iter, IEEE80211_MUEDCA_ACI);

        ie->muedca_param_record[iter].ecwminmax =
            IEEE80211_SM(muedca->muedca_paramList[iter].muedca_ecwmin,
                    IEEE80211_MUEDCA_ECWMIN) |
            IEEE80211_SM(muedca->muedca_paramList[iter].muedca_ecwmax,
                    IEEE80211_MUEDCA_ECWMAX);

        ie->muedca_param_record[iter].timer =
            muedca->muedca_paramList[iter].muedca_timer;

    }

    return frm + muedca_ie_len;
}

/*
 * Add an Atheros Advanaced Capability element to a frame
 */
u_int8_t *
ieee80211_add_athAdvCap(u_int8_t *frm, u_int8_t capability, u_int16_t defaultKey)
{
    static const u_int8_t oui[6] = {(ATH_OUI & 0xff), ((ATH_OUI >>8) & 0xff),
                                    ((ATH_OUI >> 16) & 0xff), ATH_OUI_TYPE, ATH_OUI_SUBTYPE, ATH_OUI_VERSION};
    struct ieee80211_ie_athAdvCap *ie = (struct ieee80211_ie_athAdvCap *) frm;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0;				/* Length filled in below */
    OS_MEMCPY(frm, oui, sizeof(oui));		/* Atheros OUI, type, subtype, and version for adv capabilities */
    frm += sizeof(oui);
    *frm++ = capability;

    /* Setup default key index in little endian byte order */
    *frm++ = (defaultKey & 0xff);
    *frm++ = ((defaultKey >> 8)& 0xff);
    ie->athAdvCap_len = frm - &ie->athAdvCap_oui[0];

    return frm;
}

/*
 *  Add a QCA bandwidth-NSS Mapping information element to a frame
 */
u_int8_t *
ieee80211_add_bw_nss_maping(u_int8_t *frm, struct ieee80211_bwnss_map *bw_nss_mapping)
{
    static const u_int8_t oui[6] = {(ATH_OUI & 0xff), ((ATH_OUI >>8) & 0xff),
                                   ((ATH_OUI >> 16) & 0xff),ATH_OUI_BW_NSS_MAP_TYPE,
                                       ATH_OUI_BW_NSS_MAP_SUBTYPE, ATH_OUI_BW_NSS_VERSION};
    struct ieee80211_bwnss_mapping *ie = (struct ieee80211_bwnss_mapping *) frm;

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 0x00;                            /* Length filled in below */
    OS_MEMCPY(frm, oui, IEEE80211_N(oui));    /* QCA OUI, type, sub-type, version, bandwidth NSS mapping Vendor specific IE  */
    frm += IEEE80211_N(oui);
    *frm++ = IEEE80211_BW_NSS_ADV_160(bw_nss_mapping->bw_nss_160); /* XXX: Add higher BW map if and when required */

    ie->bnm_len = (frm - &ie->bnm_oui[0]);
    return frm;
}

u_int8_t* add_chan_switch_ie(u_int8_t *frm, struct ieee80211_ath_channel *next_ch, u_int8_t tbtt_cnt)
{
    struct ieee80211_ath_channelswitch_ie *csaie = (struct ieee80211_ath_channelswitch_ie*)frm;
    int csaielen = sizeof(struct ieee80211_ath_channelswitch_ie);

    csaie->ie = IEEE80211_ELEMID_CHANSWITCHANN;
    csaie->len = 3; /* fixed len */
    csaie->switchmode = 1; /* AP forces STAs in the BSS to stop transmissions until the channel switch completes*/
    csaie->newchannel = next_ch->ic_ieee;
    csaie->tbttcount = tbtt_cnt;

    return frm + csaielen;
}

u_int8_t* add_sec_chan_offset_ie(u_int8_t *frm, struct ieee80211_ath_channel *next_ch)
{
    struct ieee80211_ie_sec_chan_offset *secie = (struct ieee80211_ie_sec_chan_offset*)frm;
    int secielen = sizeof(struct ieee80211_ie_sec_chan_offset);

    secie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;
    secie->len = 1;
    secie->sec_chan_offset = ieee80211_sec_chan_offset(next_ch);

    return frm + secielen;
}

u_int8_t* add_build_version_ie(u_int8_t *frm, struct ieee80211com *ic)
{
    struct ieee80211_build_version_ie *bvie =
        (struct ieee80211_build_version_ie*)frm;
    int bvielen = sizeof(struct ieee80211_build_version_ie);

    OS_MEMZERO(bvie->build_variant, sizeof(bvie->build_variant));
    OS_MEMCPY(bvie->build_variant, SW_BUILD_VARIANT, SW_BUILD_VARIANT_LEN);
    bvie->sw_build_version = SW_BUILD_VERSION;
    bvie->sw_build_maj_ver = SW_BUILD_MAJ_VER;
    bvie->sw_build_min_ver = SW_BUILD_MIN_VER;
    bvie->sw_build_rel_variant = SW_BUILD_REL_VARIANT;
    bvie->sw_build_rel_num = SW_BUILD_REL_NUM;
    bvie->chip_vendorid = htole32(ic->vendor_id);
    bvie->chip_devid = htole32(ic->device_id);

    return frm + bvielen;
}

u_int8_t *
ieee80211_add_sw_version_ie(u_int8_t *frm, struct ieee80211com *ic)
{
    u_int8_t *t_frm;
    u_int8_t ie_len;
    static const u_int8_t oui[QCA_OUI_LEN] = {
        (QCA_OUI & QCA_OUI_BYTE_MASK),
        ((QCA_OUI >> QCA_OUI_ONE_BYTE_SHIFT) & QCA_OUI_BYTE_MASK),
        ((QCA_OUI >> QCA_OUI_TWO_BYTE_SHIFT) & QCA_OUI_BYTE_MASK),
        QCA_OUI_GENERIC_TYPE_1, QCA_OUI_BUILD_INFO_SUBTYPE,
        QCA_OUI_BUILD_INFO_VERSION
    };

    t_frm = frm;
     /* reserving 2 bytes for the element id and element len*/
    frm += IE_LEN_ID_LEN;

    OS_MEMCPY(frm, oui, IEEE80211_N(oui));
    frm += IEEE80211_N(oui);

    frm = add_build_version_ie(frm, ic);

    ie_len = frm - t_frm - IE_LEN_ID_LEN;
    *t_frm++ = IEEE80211_ELEMID_VENDOR;
    *t_frm = ie_len;
    /* updating efrm with actual index*/
    t_frm = frm;

    return t_frm;
}

#define RESTRICTED_80P80_IDX    0          /* Restricted 80+80 MHz uses zeroth index in generic_capabilities array */
#define RESTRICTED_80P80_SUPPORT_POS   0   /* Restricted 80+80 MHz support enabled in zeroth bit of generic_capabilities[0] */

#define IEEE80211_SET_RESTRICTED_80P80_SUPPORT(capability) ((capability)[RESTRICTED_80P80_IDX] |= BIT(RESTRICTED_80P80_SUPPORT_POS))
#define IEEE80211_GET_RESTRICTED_80P80_SUPPORT(capability) ((capability)[RESTRICTED_80P80_IDX] & BIT(RESTRICTED_80P80_SUPPORT_POS))
#define IEEE80211_CLEAR_RESTRICTED_80P80_SUPPORT(capability) ((capability)[RESTRICTED_80P80_IDX] &= ~BIT(RESTRICTED_80P80_SUPPORT_POS))

u_int8_t * ieee80211_add_generic_capabilities(u_int8_t *frm,
                                              struct ieee80211com *ic)
{
    struct ieee80211_generic_capability_ie *capability =
        (struct ieee80211_generic_capability_ie *)frm;
    int len = sizeof(struct ieee80211_generic_capability_ie);
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;

    if (!frm) {
        qdf_err("null frm");
        return NULL;
    }

    if (!ic) {
        qdf_err("null ic");
        return NULL;
    }

    pdev = ic->ic_pdev_obj;
    if(!pdev) {
        qdf_err("null pdev");
        return NULL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("null psoc");
        return NULL;
    }

    qdf_mem_zero(capability, sizeof(*capability));

    if (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_RESTRICTED_80P80_SUPPORT)) {
        IEEE80211_SET_RESTRICTED_80P80_SUPPORT(capability->generic_capabilities);
    }

    return frm+len;
}

u_int8_t *
ieee80211_add_generic_vendor_capabilities_ie(u_int8_t *frm, struct ieee80211com *ic)
{
    u_int8_t *t_frm;
    u_int8_t ie_len;
    static const u_int8_t oui[QCA_OUI_LEN] = {
        (QCA_OUI & QCA_OUI_BYTE_MASK),
        ((QCA_OUI >> QCA_OUI_ONE_BYTE_SHIFT) & QCA_OUI_BYTE_MASK),
        ((QCA_OUI >> QCA_OUI_TWO_BYTE_SHIFT) & QCA_OUI_BYTE_MASK),
        QCA_OUI_GENERIC_TYPE_1, QCA_OUI_GENERIC_SUBTYPE_1,
        QCA_OUI_GENERIC_VERSION_1};

    if (!frm) {
        qdf_err("null frm");
        return NULL;
    }

    if (!ic) {
        qdf_err("null ic");
        return NULL;
    }

    t_frm = frm;
    /* reserving 2 bytes for the element id and element len*/
    frm += IE_LEN_ID_LEN;

    OS_MEMCPY(frm, oui, IEEE80211_N(oui));
    frm += IEEE80211_N(oui);

    frm = ieee80211_add_generic_capabilities(frm, ic);
    if (!frm)
        return NULL;

    ie_len = frm - t_frm - IE_LEN_ID_LEN;

    *t_frm++ = IEEE80211_ELEMID_VENDOR;
    *t_frm = ie_len;
    /* updating tfrm with actual index*/
    t_frm = frm;

    return t_frm;
}

/*
 *  Add next channel info in beacon vendor IE, this will be used when RE detects RADAR and Root does not
 *  RE send RCSAs to Root and CSAs to its clients and switches to the channel that was communicated by its
 *  parent through this vendor IE
 */
u_int8_t *
ieee80211_add_next_channel(u_int8_t *frm, struct ieee80211_node *ni, struct ieee80211com *ic, int subtype)
{
    u_int8_t *efrm;
    u_int8_t ie_len;
    u_int16_t chwidth;
    struct ieee80211_ie_wide_bw_switch *widebw = NULL;
    int widebw_len = sizeof(struct ieee80211_ie_wide_bw_switch);
    struct ieee80211_ath_channel *next_channel = ic->ic_tx_next_ch;
    static const u_int8_t oui[6] = {
        (QCA_OUI & 0xff), ((QCA_OUI >> 8) & 0xff), ((QCA_OUI >> 16) & 0xff),
        QCA_OUI_NC_TYPE, QCA_OUI_NC_SUBTYPE,
        QCA_OUI_NC_VERSION
    };
    /* preserving efrm pointer, if no sub element is present,
        Skip adding this element */
    efrm = frm;
     /* reserving 2 bytes for the element id and element len*/
    frm += 2;

    OS_MEMCPY(frm, oui, IEEE80211_N(oui));
    frm += IEEE80211_N(oui);

    frm = add_chan_switch_ie(frm, next_channel, ic->ic_chan_switch_cnt);

    frm = add_sec_chan_offset_ie(frm, next_channel);

    chwidth = ieee80211_get_chan_width(next_channel);

    if(IEEE80211_IS_CHAN_11AC(next_channel) && chwidth != CHWIDTH_VHT20) {
        /*If channel width not 20 then add Wideband and txpwr evlp element*/
        frm = ieee80211_add_vht_wide_bw_switch(frm, ni, ic, subtype, 1);
    }
    else {
        widebw = (struct ieee80211_ie_wide_bw_switch *)frm;
        OS_MEMSET(widebw, 0, sizeof(struct ieee80211_ie_wide_bw_switch));
        widebw->elem_id = QCA_UNHANDLED_SUB_ELEM_ID;
        widebw->elem_len = widebw_len - 2;
        frm += widebw_len;
    }

    /* If frame is filled with sub elements then add element id and len*/
    if((frm-2) != efrm)
    {
       ie_len = frm - efrm - 2;
       *efrm++ = IEEE80211_ELEMID_VENDOR;
       *efrm = ie_len;
       /* updating efrm with actual index*/
       efrm = frm;
    }
    return efrm;
}
/*
 * Add an Atheros extended capability information element to a frame
 */
u_int8_t *
ieee80211_add_athextcap(u_int8_t *frm, u_int16_t ath_extcap, u_int8_t weptkipaggr_rxdelim)
{
    static const u_int8_t oui[6] = {(ATH_OUI & 0xff),
                                        ((ATH_OUI >>8) & 0xff),
                                        ((ATH_OUI >> 16) & 0xff),
                                        ATH_OUI_EXTCAP_TYPE,
                                        ATH_OUI_EXTCAP_SUBTYPE,
                                        ATH_OUI_EXTCAP_VERSION};

    *frm++ = IEEE80211_ELEMID_VENDOR;
    *frm++ = 10;
    OS_MEMCPY(frm, oui, sizeof(oui));
    frm += sizeof(oui);
    *frm++ = ath_extcap & 0xff;
    *frm++ = (ath_extcap >> 8) & 0xff;
    *frm++ = weptkipaggr_rxdelim & 0xff;
    *frm++ = 0; /* reserved */
    return frm;
}
/*
 * Add 802.11h information elements to a frame.
 */
u_int8_t *
ieee80211_add_doth(u_int8_t *frm, struct ieee80211vap *vap)
{
    struct ieee80211_ath_channel *c;
    int    i, j, chancnt;
    u_int8_t *chanlist;
    u_int8_t prevchan;
    u_int8_t *frmbeg;
    struct ieee80211com *ic = vap->iv_ic;

    /* XXX ie structures */
    /*
     * Power Capability IE
     */
    chanlist = OS_MALLOC(ic->ic_osdev, sizeof(u_int8_t) * (IEEE80211_CHAN_MAX + 1), 0);
    if (chanlist == NULL) {
        qdf_nofl_info("%s[%d] chanlist is null  \n",__func__,__LINE__);
        return frm;
    }
    *frm++ = IEEE80211_ELEMID_PWRCAP;
    *frm++ = 2;
    *frm++ = vap->iv_bsschan->ic_minpower;
    *frm++ = vap->iv_bsschan->ic_maxpower;

	/*
	 * Supported Channels IE as per 802.11h-2003.
	 */
    frmbeg = frm;
    prevchan = 0;
    chancnt = 0;


    for (i = 0; i < ic->ic_nchans; i++)
    {
        c = &ic->ic_channels[i];

        /* Skip turbo channels */
        if (IEEE80211_IS_CHAN_TURBO(c))
            continue;

        /* Skip half/quarter rate channels */
        if (IEEE80211_IS_CHAN_HALF(c) || IEEE80211_IS_CHAN_QUARTER(c))
            continue;

        /* Skip previously reported channels */
        for (j=0; j < chancnt; j++) {
            if (c->ic_ieee == chanlist[j])
                break;
		}
        if (j != chancnt) /* found a match */
            continue;

        chanlist[chancnt] = c->ic_ieee;
        chancnt++;

        if ((c->ic_ieee > prevchan) && prevchan) {
            frm[1] = frm[1] + 1;
        } else {
            frm += 2;
            frm[0] =  c->ic_ieee;
            frm[1] = 1;
        }

        prevchan = c->ic_ieee;
    }

    frm += 2;

    if (chancnt) {
        frmbeg[0] = IEEE80211_ELEMID_SUPPCHAN;
        frmbeg[1] = (u_int8_t)(frm - frmbeg - 2);
    } else {
        frm = frmbeg;
    }

    OS_FREE(chanlist);
    return frm;
}

/*
 * Add ht supported rates to HT element.
 * Precondition: the Rx MCS bitmask is zero'd out.
 */
static void
ieee80211_set_htrates(struct ieee80211vap *vap, u_int8_t *rx_mcs, struct ieee80211com *ic)
{
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap),
             rx_streams = ieee80211_get_rxstreams(ic, vap);

    if (tx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        tx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    if (rx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        rx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    /* First, clear Supported MCS fields. Default to max 1 tx spatial stream */
    rx_mcs[IEEE80211_TX_MCS_OFFSET] &= ~IEEE80211_TX_MCS_SET;

    /* Set Tx MCS Set Defined */
    rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_MCS_SET_DEFINED;

    if (tx_streams != rx_streams) {
        /* Tx MCS Set != Rx MCS Set */
        rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_RX_MCS_SET_NOT_EQUAL;

        switch(tx_streams) {
        case 2:
            rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_2_SPATIAL_STREAMS;
            break;
        case 3:
            rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_3_SPATIAL_STREAMS;
            break;
        case 4:
            rx_mcs[IEEE80211_TX_MCS_OFFSET] |= IEEE80211_TX_4_SPATIAL_STREAMS;
            break;
        }
    }

    /* REVISIT: update bitmask if/when going to > 3 streams */
    switch (rx_streams) {
    default:
        /* Default to single stream */
    case 1:
        /* Advertise all single spatial stream (0-7) mcs rates */
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
    case 2:
        /* Advertise all single & dual spatial stream mcs rates (0-15) */
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
    case 3:
        /* Advertise all single, dual & triple spatial stream mcs rates (0-23) */
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_3_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
    case 4:
        rx_mcs[IEEE80211_RX_MCS_1_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_3_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        rx_mcs[IEEE80211_RX_MCS_4_STREAM_BYTE_OFFSET] = IEEE80211_RX_MCS_ALL_NSTREAM_RATES;
        break;
    }
    if(vap->iv_disable_htmcs) {
        rx_mcs[0] &= ~vap->iv_disabled_ht_mcsset[0];
        rx_mcs[1] &= ~vap->iv_disabled_ht_mcsset[1];
        rx_mcs[2] &= ~vap->iv_disabled_ht_mcsset[2];
        rx_mcs[3] &= ~vap->iv_disabled_ht_mcsset[3];
    }
}

/*
 * Add ht basic rates to HT element.
 */
static void
ieee80211_set_basic_htrates(u_int8_t *frm, const struct ieee80211_rateset *rs)
{
    int i;
    int nrates;

    nrates = rs->rs_nrates;
    if (nrates > IEEE80211_HT_RATE_SIZE)
        nrates = IEEE80211_HT_RATE_SIZE;

    /* set the mcs bit mask from the rates */
    for (i=0; i < nrates; i++) {
        if ((i < IEEE80211_RATE_MAXSIZE) &&
            (rs->rs_rates[i] & IEEE80211_RATE_BASIC))
            *(frm + IEEE80211_RV(rs->rs_rates[i]) / 8) |= 1 << (IEEE80211_RV(rs->rs_rates[i]) % 8);
    }
}

/*
 * Add 802.11n HT Capabilities IE
 */
static void
ieee80211_add_htcap_cmn(struct ieee80211_node *ni, struct ieee80211_ie_htcap_cmn *ie, u_int8_t subtype)
{
    struct ieee80211com       *ic = ni->ni_ic;
    struct ieee80211vap       *vap = ni->ni_vap;
    u_int16_t                 htcap, hc_extcap = 0;
    u_int8_t                  noht40 = 0;
    u_int8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap);

    if (rx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        rx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    if (tx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        tx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    /*
     * XXX : Temporarily overide the shortgi based on the htflags,
     * fix this later
     */
    htcap = ic->ic_htcap;
    htcap &= (((vap->iv_htflags & IEEE80211_HTF_SHORTGI40) && vap->iv_sgi) ?
                     ic->ic_htcap  : ~IEEE80211_HTCAP_C_SHORTGI40);
    htcap &= (((vap->iv_htflags & IEEE80211_HTF_SHORTGI20) && vap->iv_sgi) ?
                     ic->ic_htcap  : ~IEEE80211_HTCAP_C_SHORTGI20);

    htcap &= (((vap->vdev_mlme->proto.generic.ldpc & IEEE80211_HTCAP_C_LDPC_RX) &&
              (ieee80211com_get_ldpccap(ic) & IEEE80211_HTCAP_C_LDPC_RX)) ?
              ic->ic_htcap : ~IEEE80211_HTCAP_C_ADVCODING);
    /*
     * Adjust the TX and RX STBC fields based on the chainmask and configuration
     */
    htcap &= (((vap->iv_tx_stbc) && (tx_streams > 1)) ? ic->ic_htcap : ~IEEE80211_HTCAP_C_TXSTBC);
    htcap &= (((vap->iv_rx_stbc) && (rx_streams > 0)) ? ic->ic_htcap : ~IEEE80211_HTCAP_C_RXSTBC);

    /* If bss/regulatory does not allow HT40, turn off HT40 capability */
    if (!(vap->iv_sta_max_ch_cap &&
          get_chwidth_phymode(vap->iv_des_mode)) &&
        !(IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT40(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT80(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT160(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AC_VHT80_80(vap->iv_bsschan))&&
        !(IEEE80211_IS_CHAN_11AX_HE40(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AXA_HE80(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AXA_HE160(vap->iv_bsschan)) &&
        !(IEEE80211_IS_CHAN_11AXA_HE80_80(vap->iv_bsschan))) {
        noht40 = 1;

        /* Don't advertize any HT40 Channel width capability bit */
        /* Forcing sta mode to interop with 11N HT40 only AP removed*/
            htcap &= ~IEEE80211_HTCAP_C_CHWIDTH40;
    }

    if (IEEE80211_IS_CHAN_11NA(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11AXA(vap->iv_bsschan)) {
        htcap &= ~IEEE80211_HTCAP_C_DSSSCCK40;
    }

    /* Should we advertize HT40 capability on 2.4GHz channels? */
    if (IEEE80211_IS_CHAN_11NG(vap->iv_bsschan) ||
        IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan)) {
        if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
            noht40 = 1;
            htcap &= ~IEEE80211_HTCAP_C_CHWIDTH40;
        } else if (vap->iv_opmode == IEEE80211_M_STA) {
            if (!ic->ic_enable2GHzHt40Cap) {
                noht40 = 1;
                htcap &= ~IEEE80211_HTCAP_C_CHWIDTH40;
            }
        } else {
            if (!ic->ic_enable2GHzHt40Cap) {
                noht40 = 1;
                htcap &= ~IEEE80211_HTCAP_C_CHWIDTH40;
            } else if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                noht40 = 1;
            }
        }
    }

    if (noht40) {
        /* Don't advertize any HT40 capability bits */
        htcap &= ~(IEEE80211_HTCAP_C_DSSSCCK40 |
                   IEEE80211_HTCAP_C_SHORTGI40);
    }


    if (!ieee80211_vap_dynamic_mimo_ps_is_set(ni->ni_vap)) {
        /* Don't advertise Dynamic MIMO power save if not configured */
        htcap &= ~IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC;
        htcap |= IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED;
    }

    /* Set support for 20/40 Coexistence Management frame support */
    htcap |= (vap->iv_ht40_intolerant) ? IEEE80211_HTCAP_C_INTOLERANT40 : 0;

    ie->hc_cap = htole16(htcap);

    ie->hc_maxampdu	= ic->ic_maxampdu;
#if ATH_SUPPORT_WAPI
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)
	&& wlan_crypto_vdev_has_ucastcipher(vap->vdev_obj,
                           (1 << WLAN_CRYPTO_CIPHER_WAPI_SMS4))) {
        ie->hc_mpdudensity = 7;
    } else
#endif
    {
        /* MPDU Density : If User provided mpdudensity,
         * Take user configured value*/
        if(ic->ic_mpdudensityoverride) {
            ie->hc_mpdudensity = ic->ic_mpdudensityoverride >> 1;
        } else {
            /* WAR for MPDU DENSITY : In Beacon frame the mpdu density is set as zero. In association response and request if the peer txstreams
             * is 4 set the MPDU density to 16.
             */

           if (ic->ic_is_target_ar900b(ic) &&
                    (IEEE80211_IS_CHAN_5GHZ_6GHZ(vap->iv_bsschan)) &&
                    ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) || (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ)) &&
                    (MIN(ni->ni_txstreams, rx_streams) == IEEE80211_MAX_SPATIAL_STREAMS)) {
                ie->hc_mpdudensity = IEEE80211_HTCAP_MPDUDENSITY_16;
            } else {
                ie->hc_mpdudensity = ic->ic_mpdudensity;
            }
        }

    }
    ie->hc_reserved	= 0;

    /* Initialize the MCS bitmask */
    OS_MEMZERO(ie->hc_mcsset, sizeof(ie->hc_mcsset));

    /* Set supported MCS set */
    ieee80211_set_htrates(vap, ie->hc_mcsset, ic);
    if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)
      && wlan_crypto_is_htallowed(vap->vdev_obj, NULL)) {
        /*
         * WAR for Tx FIFO underruns with MCS15 in WEP mode. Exclude
         * MCS15 from rates if WEP encryption is set in HT20 mode
         */
        if (IEEE80211_IS_CHAN_11N_HT20(vap->iv_bsschan))
            ie->hc_mcsset[IEEE80211_RX_MCS_2_STREAM_BYTE_OFFSET] &= 0x7F;
    }

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if ((vap->iv_psta == 1)) {
        if ((ic->ic_proxystarxwar == 1) &&
            IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
                IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan)
	&& wlan_crypto_vdev_has_ucastcipher(vap->vdev_obj,
                           ((1 << WLAN_CRYPTO_CIPHER_TKIP)
                             | (1 << WLAN_CRYPTO_CIPHER_AES_CCM)
                             | (1 << WLAN_CRYPTO_CIPHER_AES_GCM)
                             | (1 << WLAN_CRYPTO_CIPHER_AES_CCM_256)
                             | (1 << WLAN_CRYPTO_CIPHER_AES_GCM_256)))) {
                ie->hc_mcsset[IEEE80211_RX_MCS_3_STREAM_BYTE_OFFSET] &= 0x7F;
        }
    }
#endif
#endif

#ifdef ATH_SUPPORT_TxBF
    ic->ic_set_txbf_caps(ic);       /* update txbf cap*/
    ie->hc_txbf.value = htole32(ic->ic_txbf.value);

    /* disable TxBF mode for SoftAP mode of win7*/
    if (vap->iv_opmode == IEEE80211_M_HOSTAP){
        if(vap->iv_txbfmode == 0 ){
            ie->hc_txbf.value = 0;
        }
    }

    if (ie->hc_txbf.value!=0) {
        hc_extcap |= IEEE80211_HTCAP_EXTC_HTC_SUPPORT;    /*enable +HTC support*/
    }
#else
    ie->hc_txbf    = 0;
#endif
    ie->hc_extcap  = htole16(hc_extcap);
    ie->hc_antenna = 0;
}

u_int8_t *
ieee80211_add_htcap(u_int8_t *frm, struct ieee80211_node *ni, u_int8_t subtype)
{
    struct ieee80211_ie_htcap_cmn *ie;
    int htcaplen;
    struct ieee80211_ie_htcap *htcap = (struct ieee80211_ie_htcap *)frm;

    htcap->hc_id      = IEEE80211_ELEMID_HTCAP_ANA;
    htcap->hc_len     = sizeof(struct ieee80211_ie_htcap) - 2;

    ie = &htcap->hc_ie;
    htcaplen = sizeof(struct ieee80211_ie_htcap);

    ieee80211_add_htcap_cmn(ni, ie, subtype);

    return frm + htcaplen;
}

u_int8_t *
ieee80211_add_htcap_vendor_specific(u_int8_t *frm, struct ieee80211_node *ni,u_int8_t subtype)
{
    struct ieee80211_ie_htcap_cmn *ie;
    int htcaplen;
    struct vendor_ie_htcap *htcap = (struct vendor_ie_htcap *)frm;

    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG, "%s: use HT caps IE vendor specific\n",
                      __func__);

    htcap->hc_id      = IEEE80211_ELEMID_VENDOR;
    htcap->hc_oui[0]  = (ATH_HTOUI >> 16) & 0xff;
    htcap->hc_oui[1]  = (ATH_HTOUI >>  8) & 0xff;
    htcap->hc_oui[2]  = ATH_HTOUI & 0xff;
    htcap->hc_ouitype = IEEE80211_ELEMID_HTCAP_VENDOR;
    htcap->hc_len     = sizeof(struct vendor_ie_htcap) - 2;

    ie = &htcap->hc_ie;
    htcaplen = sizeof(struct vendor_ie_htcap);

    ieee80211_add_htcap_cmn(ni, ie,subtype);

    return frm + htcaplen;
}

/*
 * Add 802.11n HT Information IE
 */
/* NB: todo: still need to handle the case for when there may be non-HT STA's on channel (extension
   and/or control) that are not a part of the BSS.  Process beacons for no HT IEs and
   process assoc-req for BS' other than our own */
void
ieee80211_update_htinfo_cmn(struct ieee80211_ie_htinfo_cmn *ie, struct ieee80211_node *ni)
{
    struct ieee80211com        *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t chwidth = 0;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    /*
     ** If the value in the VAP is set, we use that instead of the actual setting
     ** per Srini D.  Hopefully this matches the actual setting.
     */
    if( vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic_cw_width;
    }
    ie->hi_txchwidth = (chwidth == IEEE80211_CWM_WIDTH20) ?
        IEEE80211_HTINFO_TXWIDTH_20 : IEEE80211_HTINFO_TXWIDTH_2040;

    /*
     ** If the value in the VAP for the offset is set, use that per
     ** Srini D.  Otherwise, use the actual setting
     */

    if( vap->iv_chextoffset != 0 ) {
        switch( vap->iv_chextoffset ) {
            case 1:
                ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_NA;
                break;
            case 2:
                ie->hi_extchoff =  IEEE80211_HTINFO_EXTOFFSET_ABOVE;
                break;
            case 3:
                ie->hi_extchoff =  IEEE80211_HTINFO_EXTOFFSET_BELOW;
                break;
            default:
                break;
        }
    } else {
        if ((ic_cw_width == IEEE80211_CWM_WIDTH40)||(ic_cw_width == IEEE80211_CWM_WIDTH80) || (ic_cw_width == IEEE80211_CWM_WIDTH160)) {
            switch (ic->ic_cwm_get_extoffset(ic)) {
                case EXT_CHAN_OFFSET_ABOVE:
                    ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_ABOVE;
                    break;
                case EXT_CHAN_OFFSET_BELOW:
                    ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_BELOW;
                    break;
                case EXT_CHAN_OFFSET_NA:
                default:
                    ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_NA;
            }
        } else {
            ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_NA;
        }
    }
    if (vap->iv_disable_HTProtection) {
        /* Force HT40: no HT protection*/
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_PURE;
        ie->hi_obssnonhtpresent=IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode = IEEE80211_HTINFO_RIFSMODE_ALLOWED;
    }
    else if (ic->ic_sta_assoc > ic->ic_ht_sta_assoc) {
        /*
         * Legacy stations associated.
         */
        ie->hi_opmode =IEEE80211_HTINFO_OPMODE_MIXED_PROT_ALL;
        ie->hi_obssnonhtpresent = IEEE80211_HTINFO_OBSS_NONHT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_PROHIBITED;
    }
    else if (ieee80211_ic_non_ht_ap_is_set(ic)) {
        /*
         * Overlapping with legacy BSSs.
         */
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_MIXED_PROT_OPT;
        ie->hi_obssnonhtpresent =IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_PROHIBITED;
    }
    else if (ie->hi_txchwidth == IEEE80211_HTINFO_TXWIDTH_2040 && ic->ic_ht_sta_assoc > ic->ic_ht40_sta_assoc) {
        /*
         * HT20 Stations present in HT40 BSS.
         */
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_MIXED_PROT_40;
        ie->hi_obssnonhtpresent = IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_ALLOWED;
    } else {
        /*
         * all Stations are HT40 capable
         */
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_PURE;
        ie->hi_obssnonhtpresent=IEEE80211_HTINFO_OBSS_NONHT_NOT_PRESENT;
        ie->hi_rifsmode	= IEEE80211_HTINFO_RIFSMODE_ALLOWED;
    }

    if (((IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
          IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
          ieee80211vap_vhtallowed(vap)) ||
         (IEEE80211_IS_CHAN_HE(vap->iv_bsschan) &&
          ieee80211vap_heallowed(vap))) {

        /*
         *All VHT/HE AP should have RIFS bit set to 0
         */
        ie->hi_rifsmode = IEEE80211_HTINFO_RIFSMODE_PROHIBITED;
    }

    if (ic->ic_ht_sta_assoc > ic->ic_ht_gf_sta_assoc)
        ie->hi_nongfpresent = 1;
    else
        ie->hi_nongfpresent = 0;

    if (!ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        if ((ic_cw_width == IEEE80211_CWM_WIDTH160) && vap->iv_ext_nss_support &&
                 (!(nssmap.flag == IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW))) {
            HTINFO_CCFS2_SET(vap->iv_bsschan->ic_vhtop_ch_num_seg2, ie);
        }
    }

    if (vap->iv_csa_interop_bss_active) {
        ie->hi_opmode = IEEE80211_HTINFO_OPMODE_MIXED_PROT_ALL;
        ie->hi_extchoff = IEEE80211_HTINFO_EXTOFFSET_NA;
        ie->hi_txchwidth = IEEE80211_CWM_WIDTH20;
    }
}

static void
ieee80211_add_htinfo_cmn(struct ieee80211_node *ni, struct ieee80211_ie_htinfo_cmn *ie)
{
    struct ieee80211com        *ic = ni->ni_ic;
    struct ieee80211vap        *vap = ni->ni_vap;

    OS_MEMZERO(ie, sizeof(struct ieee80211_ie_htinfo_cmn));

    /* set control channel center in IE */
    ie->hi_ctrlchannel 	= ieee80211_chan2ieee(ic, vap->iv_bsschan);

    ieee80211_update_htinfo_cmn(ie,ni);
    /* Set the basic MCS Set */
    OS_MEMZERO(ie->hi_basicmcsset, sizeof(ie->hi_basicmcsset));
    ieee80211_set_basic_htrates(ie->hi_basicmcsset, &ni->ni_htrates);

    ieee80211_update_htinfo_cmn(ie, ni);
}

u_int8_t *
ieee80211_add_htinfo(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211_ie_htinfo_cmn *ie;
    int htinfolen;
    struct ieee80211_ie_htinfo *htinfo = (struct ieee80211_ie_htinfo *)frm;

    htinfo->hi_id      = IEEE80211_ELEMID_HTINFO_ANA;
    htinfo->hi_len     = sizeof(struct ieee80211_ie_htinfo) - 2;

    ie = &htinfo->hi_ie;
    htinfolen = sizeof(struct ieee80211_ie_htinfo);

    ieee80211_add_htinfo_cmn(ni, ie);

    return frm + htinfolen;
}

u_int8_t *
ieee80211_add_htinfo_vendor_specific(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211_ie_htinfo_cmn *ie;
    int htinfolen;
    struct vendor_ie_htinfo *htinfo = (struct vendor_ie_htinfo *) frm;

    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG, "%s: use HT info IE vendor specific\n",
                      __func__);

    htinfo->hi_id      = IEEE80211_ELEMID_VENDOR;
    htinfo->hi_oui[0]  = (ATH_HTOUI >> 16) & 0xff;
    htinfo->hi_oui[1]  = (ATH_HTOUI >>  8) & 0xff;
    htinfo->hi_oui[2]  = ATH_HTOUI & 0xff;
    htinfo->hi_ouitype = IEEE80211_ELEMID_HTINFO_VENDOR;
    htinfo->hi_len     = sizeof(struct vendor_ie_htinfo) - 2;

    ie = &htinfo->hi_ie;
    htinfolen = sizeof(struct vendor_ie_htinfo);

    ieee80211_add_htinfo_cmn(ni, ie);

    return frm + htinfolen;
}

static inline void ieee80211_add_twt_extcap(struct ieee80211_node *ni,
                                            uint8_t *ext_capflags4,
                                            uint8_t subtype)
{
#if WLAN_SUPPORT_TWT
    struct ieee80211com *ic  = ni->ni_ic;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    bool is_he_peer =  (IEEE80211_IS_CHAN_11AX(ic->ic_curchan)
                        && ieee80211vap_heallowed(ni->ni_vap)
                        && (ni->ni_ext_flags & IEEE80211_NODE_HE));

    /* Add TWT cap only if current mode is 11AX */
    if (!IEEE80211_IS_CHAN_11AX(ic->ic_curchan)) {
        return;
    }

    pdev = ic->ic_pdev_obj;
    if (pdev == NULL) {
        qdf_err("Invalid pdev in ic");
        return;
    }
    psoc = wlan_pdev_get_psoc(pdev);
    if (psoc == NULL) {
        qdf_err("Invalid psoc in pdev");
        return;
    }

    if (((subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
#if QCN_IE
                || ni->ni_qcn_ie 
#endif
                || is_he_peer) &&
        (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_CEXT_TWT_REQUESTER)))
        *ext_capflags4 |= IEEE80211_EXTCAPIE_TWT_REQ;

    if (((subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
#if QCN_IE
                || ni->ni_qcn_ie 
#endif
                || is_he_peer) &&
        (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_CEXT_TWT_RESPONDER)) &&
        (ni->ni_vap->iv_twt_rsp))
        *ext_capflags4 |= IEEE80211_EXTCAPIE_TWT_RESP;
#endif
}

static inline void ieee80211_add_obss_narrow_bw_ru(struct ieee80211_node *ni,
                                                   uint8_t *ext_capflags4,
                                                   uint8_t subtype)
{
    struct ieee80211com *ic       = NULL;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;

    if ((ni == NULL) || (ni->ni_ic == NULL)) {
        (!ni) ? qdf_err("Invalid ni") : qdf_err("Invalid ni_ic");
        return;
    }
    ic = ni->ni_ic;

    pdev = ic->ic_pdev_obj;
    if (pdev == NULL) {
        qdf_err("Invalid pdev in ic");
        return;
    }
    psoc = wlan_pdev_get_psoc(pdev);
    if (psoc == NULL) {
        qdf_err("Invalid psoc in pdev");
        return;
    }

    /* Flag is set only for beacons and probe responses and flag is supported
     * for 802.11ax only */
    if (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
        ((subtype == IEEE80211_FC0_SUBTYPE_BEACON) ||
        (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)) &&
        (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_CEXT_OBSS_NBW_RU))) {
        *ext_capflags4 |= IEEE80211_EXTCAPIE_OBSS_NBW_RU;
    }

}
/*
 * Add ext cap element.
 */
u_int8_t *
ieee80211_add_extcap(u_int8_t *frm,struct ieee80211_node *ni, uint8_t subtype)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_ie_ext_cap *ie = (struct ieee80211_ie_ext_cap *) frm;
    u_int32_t ext_capflags = 0;
    u_int32_t ext_capflags2 = 0;
    u_int8_t ext_capflags3 = 0;
    u_int8_t ext_capflags4 = 0;
    u_int8_t ext_capflags5 = 0;
    u_int8_t ext_capflags6 = 0;
    u_int32_t ie_elem_len = 0;
    u_int8_t fils_en = 0;

    if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
        ext_capflags |= IEEE80211_EXTCAPIE_2040COEXTMGMT;
    }
    ieee80211_wnm_add_extcap(ni, &ext_capflags);

#if UMAC_SUPPORT_PROXY_ARP
    if (ieee80211_vap_proxyarp_is_set(vap) &&
            vap->iv_opmode == IEEE80211_M_HOSTAP)
    {
        ext_capflags |= IEEE80211_EXTCAPIE_PROXYARP;
    }
#endif
#if ATH_SUPPORT_HS20
    if (vap->iv_hotspot_xcaps) {
        ext_capflags |= vap->iv_hotspot_xcaps;
    }
    if (vap->iv_hotspot_xcaps2) {
        ext_capflags2 |= vap->iv_hotspot_xcaps2;
    }
#endif

    if (vap->rtt_enable & RTT_RESPONDER_MODE) {
        ext_capflags3 |= IEEE80211_EXTCAPIE_FTM_RES;
    }

    if (vap->rtt_enable & RTT_INITIATOR_MODE) {
        ext_capflags3 |= IEEE80211_EXTCAPIE_FTM_INIT;
    }

    if (vap->lcr_enable) {
        ext_capflags |= IEEE80211_EXTCAPIE_CIVLOC;
    }

    if (vap->lci_enable) {
        ext_capflags |= IEEE80211_EXTCAPIE_GEOLOC;
    }

    if (vap->iv_enable_ecsaie) {
        ext_capflags |= IEEE80211_EXTCAPIE_ECSA;
    }

    if (vap->iv_beacon_prot) {
        ext_capflags5 |= IEEE80211_EXTCAPIE_BEACON_PROTECTION;
    }
    if (vap->iv_mscs) {
        ext_capflags5 |= IEEE80211_EXTCAPIE_MSCS;
    }

    /* IEEE80211_EXTCAPIE_SAE_PWID set to 1 if any of sae_password has pwid */
    /* IEEE80211_EXTCAPIE_SAE_PWID_ALL set to 1 if all sae_password has pwid */
    if (vap->iv_enable_sae_pwid & IEEE80211_EXTCAPIE_ENABLE_SAE_PWID) {
        ext_capflags5 |= IEEE80211_EXTCAPIE_SAE_PWID;
        if (vap->iv_enable_sae_pwid & IEEE80211_EXTCAPIE_ENABLE_SAE_PWID_ALL)
            ext_capflags5 |= IEEE80211_EXTCAPIE_SAE_PWID_ALL;
    }

      if (vap->iv_sae_pk_en) {
          ext_capflags6 |= IEEE80211_EXTCAPIE_SAE_PK;
      }

    if(wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                  WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        ext_capflags |= IEEE80211_EXTCAPIE_MBSSID;

        if (ic->ic_mbss.current_pp == 1) {
            /* complete list of NonTxBSSID profiles */
            ext_capflags5 |= IEEE80211_EXTCAPIE_MBSS_COMPL_LIST;
        }

        if (wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                WLAN_PDEV_FEXT_EMA_AP_ENABLE)) {
            ext_capflags5 |= IEEE80211_EXTCAPIE_MBSS_EMA_AP;
        }
    }

    if (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
        (IEEE80211_IS_CHAN_11NG(ic->ic_curchan) &&
        ieee80211vap_vhtallowed(vap)))
    {
        /* Support reception of Operating Mode notification */
        ext_capflags2 |= IEEE80211_EXTCAPIE_OP_MODE_NOTIFY;
    }

#if WLAN_SUPPORT_FILS
    fils_en = wlan_fils_is_enable(vap->vdev_obj);
#endif
    if(fils_en) {
        ext_capflags4 |= IEEE80211_EXTCAPIE_FILS;
    }

    ieee80211_add_twt_extcap(ni, &ext_capflags4, subtype);
    ieee80211_add_obss_narrow_bw_ru(ni, &ext_capflags4, subtype);

    if (ext_capflags || ext_capflags2 || (ext_capflags3) ||
       (ext_capflags4) || (ext_capflags5) || (ext_capflags6)) {

        if (ext_capflags6) {
            ie_elem_len = sizeof(struct ieee80211_ie_ext_cap);
        } else if (ext_capflags5) {
            ie_elem_len = sizeof(struct ieee80211_ie_ext_cap) - sizeof(ie->ext_capflags6);
        } else if (ext_capflags4) {
            ie_elem_len = sizeof(struct ieee80211_ie_ext_cap) - (sizeof(ie->ext_capflags5) + sizeof(ie->ext_capflags6));
        } else if (ext_capflags3) {
            ie_elem_len = sizeof(struct ieee80211_ie_ext_cap) -
                          (sizeof(ie->ext_capflags4) + sizeof(ie->ext_capflags5) + sizeof(ie->ext_capflags6));
        } else {
            ie_elem_len = sizeof(struct ieee80211_ie_ext_cap) -
                    (sizeof(ie->ext_capflags3) + sizeof(ie->ext_capflags4) +
                     sizeof(ie->ext_capflags5) + sizeof(ie->ext_capflags6));
        }

        qdf_mem_zero(ie, ie_elem_len);
        ie->elem_id = IEEE80211_ELEMID_XCAPS;
        ie->elem_len = ie_elem_len - 2;
        ie->ext_capflags = htole32(ext_capflags);
        ie->ext_capflags2 = htole32(ext_capflags2);
        ie->ext_capflags3 = ext_capflags3;
        ie->ext_capflags4 = ext_capflags4;
        ie->ext_capflags5 = ext_capflags5;
        ie->ext_capflags6 = ext_capflags6;
        return (frm + ie_elem_len);
    }
    else {
        return frm;
    }
}

void ieee80211_parse_extcap(struct ieee80211_node *ni, uint8_t *ie)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_ie_ext_cap *extcap = (struct ieee80211_ie_ext_cap *) ie;
    uint8_t len = extcap->elem_len;
    uint32_t ext_capflags = 0, ext_capflags2 = 0;
    uint8_t ext_capflags3 = 0, ext_capflags4 = 0;

    if (len >= sizeof(ext_capflags)) {
        ext_capflags = le32toh(extcap->ext_capflags);
        len -= sizeof(ext_capflags);
        if (len >= sizeof(ext_capflags2)) {
            ext_capflags2 = le32toh(extcap->ext_capflags2);
            len -= sizeof(ext_capflags2);
            if (len >= sizeof(ext_capflags3)) {
                ext_capflags3 = extcap->ext_capflags3;
                len -= sizeof(ext_capflags3);
                if (len >= sizeof(ext_capflags4)) {
                    ext_capflags4 = extcap->ext_capflags4;
                    len -= sizeof(ext_capflags4);
                }
            }
        }
    }

#if ATH_SUPPORT_HS20
    if (ext_capflags2 & IEEE80211_EXTCAPIE_QOS_MAP)
        ni->ni_qosmap_enabled = 1;
    else
        ni->ni_qosmap_enabled = 0;

    /* Copy first word only to node structure, only part used at the moment */
    ni->ext_caps.ni_ext_capabilities = ext_capflags;
#endif

    /* Add TWT cap to ni only if the current channel is 11AX */
    if (ext_capflags4 && IEEE80211_IS_CHAN_11AX(ic->ic_curchan)) {
        /* TWT */
#if WLAN_SUPPORT_TWT
        if ((ext_capflags4 & IEEE80211_EXTCAPIE_TWT_REQ)
#if QCN_IE
            && ni->ni_qcn_ie
#endif
        )
            ni->ni_ext_flags |= IEEE80211_NODE_TWT_REQUESTER;

        if ((ext_capflags4 & IEEE80211_EXTCAPIE_TWT_RESP)
#if QCN_IE
            && ni->ni_qcn_ie
#endif
        )
            ni->ni_ext_flags |= IEEE80211_NODE_TWT_RESPONDER;
#endif
    }
}

#if ATH_SUPPORT_HS20
u_int8_t *ieee80211_add_qosmapset(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_qos_map *qos_map = &vap->iv_qos_map;
    struct ieee80211_ie_qos_map_set *ie_qos_map_set =
        (struct ieee80211_ie_qos_map_set *)frm;
    u_int8_t *pos = ie_qos_map_set->qos_map_set;
    u_int8_t len, elem_len = 0;

    if (qos_map->valid && ni->ni_qosmap_enabled) {
        if (qos_map->num_dscp_except) {
            len = qos_map->num_dscp_except *
                  sizeof(struct ieee80211_dscp_exception);
            OS_MEMCPY(pos, qos_map->dscp_exception, len);
            elem_len += len;
            pos += len;
        }

        len = IEEE80211_MAX_QOS_UP_RANGE * sizeof(struct ieee80211_dscp_range);
        OS_MEMCPY(pos, qos_map->up, len);
        elem_len += len;
        pos += len;

        ie_qos_map_set->elem_id = IEEE80211_ELEMID_QOS_MAP;
        ie_qos_map_set->elem_len = elem_len;

        return pos;

    } else {
        /* QoS Map is not valid or not enabled */
        return frm;
    }
}
#endif /* ATH_SUPPORT_HS20 */

/*
 * Update overlapping bss scan element.
 */
void
ieee80211_update_obss_scan(struct ieee80211_ie_obss_scan *ie,
                           struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;

    if ( ie == NULL )
        return;

    ie->scan_interval = (vap->iv_chscaninit) ?
          htole16(vap->iv_chscaninit):htole16(IEEE80211_OBSS_SCAN_INTERVAL_DEF);
}

/*
 * Add overlapping bss scan element.
 */
u_int8_t *
ieee80211_add_obss_scan(u_int8_t *frm, struct ieee80211_node *ni)
{
    struct ieee80211_ie_obss_scan *ie = (struct ieee80211_ie_obss_scan *) frm;

    OS_MEMSET(ie, 0, sizeof(struct ieee80211_ie_obss_scan));
    ie->elem_id = IEEE80211_ELEMID_OBSS_SCAN;
    ie->elem_len = sizeof(struct ieee80211_ie_obss_scan) - 2;
    ieee80211_update_obss_scan(ie, ni);
    ie->scan_passive_dwell = htole16(IEEE80211_OBSS_SCAN_PASSIVE_DWELL_DEF);
    ie->scan_active_dwell = htole16(IEEE80211_OBSS_SCAN_ACTIVE_DWELL_DEF);
    ie->scan_passive_total = htole16(IEEE80211_OBSS_SCAN_PASSIVE_TOTAL_DEF);
    ie->scan_active_total = htole16(IEEE80211_OBSS_SCAN_ACTIVE_TOTAL_DEF);
    ie->scan_thresh = htole16(IEEE80211_OBSS_SCAN_THRESH_DEF);
    ie->scan_delay = htole16(IEEE80211_OBSS_SCAN_DELAY_DEF);
    return frm + sizeof (struct ieee80211_ie_obss_scan);
}

void
ieee80211_add_capability(u_int8_t * frm, struct ieee80211_node *ni)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    uint16_t capinfo;

    capinfo = IEEE80211_CAPINFO_ESS;

    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(vap->iv_bsschan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

    if (IEEE80211_VAP_IS_PUREB_ENABLED(vap)) {
        capinfo &= ~IEEE80211_CAPINFO_SHORT_SLOTTIME;
        rs = &ic->ic_sup_rates[IEEE80211_MODE_11B];
    } else if (IEEE80211_VAP_IS_PUREG_ENABLED(vap)) {
        ieee80211_setpuregbasicrates(rs);
    }

    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }

    *(u_int16_t *)frm = htole16(capinfo);
}


void
ieee80211_add_he_bsscolor_change_ie(struct ieee80211_beacon_offsets *bo,
                                    wbuf_t wbuf,
                                    struct ieee80211_node *ni,
                                    uint8_t subtype,
                                    int *len_changed) {
    struct ieee80211vap *vap                              = ni->ni_vap;
    struct ieee80211com *ic                               = vap->iv_ic;
    struct ieee80211_ie_hebsscolor_change *hebsscolor_chg =
                    (struct ieee80211_ie_hebsscolor_change *) bo->bo_bcca;
    uint8_t hebsscolor_ie_len                             =
                            sizeof(struct ieee80211_ie_hebsscolor_change);
    uint8_t *tempbuf                                      = NULL;

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
                                                "%s>>", __func__);

    if (hebsscolor_chg->elem_id == IEEE80211_ELEMID_EXTN
        && hebsscolor_chg->elem_id_ext == IEEE80211_ELEMID_EXT_BSSCOLOR_CHG) {
        hebsscolor_chg->color_switch_cntdown =
            ic->ic_he_bsscolor_change_tbtt - vap->iv_he_bsscolor_change_count;
    } else {
        /* Copy out trailer to open up a slot */
        tempbuf = qdf_mem_malloc(bo->bo_bcca_trailerlen);
        if(!tempbuf) {
            QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
                                    "%s<< tempbuf is NULL", __func__);
            return;
        }

        if (IS_MBSSID_EMA_EXT_ENABLED(ic) &&
                !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            if (vap->iv_available_bcn_cmn_space - hebsscolor_ie_len < 0) {
                qdf_mem_free(tempbuf);
                return;
            } else {
                vap->iv_available_bcn_cmn_space -= hebsscolor_ie_len;
            }
        }

        qdf_mem_copy(tempbuf, bo->bo_bcca, bo->bo_bcca_trailerlen);
        qdf_mem_copy(bo->bo_bcca + hebsscolor_ie_len,
                                tempbuf, bo->bo_bcca_trailerlen);
        qdf_mem_free(tempbuf);

        hebsscolor_chg->elem_id     = IEEE80211_ELEMID_EXTN;
        hebsscolor_chg->elem_len    = hebsscolor_ie_len - 2;
        hebsscolor_chg->elem_id_ext = IEEE80211_ELEMID_EXT_BSSCOLOR_CHG;
        hebsscolor_chg->color_switch_cntdown =
            ic->ic_he_bsscolor_change_tbtt - vap->iv_he_bsscolor_change_count;
        hebsscolor_chg->new_bss_color = ic->ic_bsscolor_hdl.selected_bsscolor;

        ieee80211_adjust_bos_for_bsscolor_change_ie(bo, hebsscolor_ie_len);

        /* Indicate new beacon length so other layers may
         * manage memory.
         */
        wbuf_append(wbuf, hebsscolor_ie_len);

        /* Indicate new beacon length so other layers may
         * manage memory.
         */
        *len_changed = 1;
    }

    if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
        vap->iv_he_bsscolor_change_count++;

        /* check change_count against change_tbtt + 1
         * so that BCCA with color switch countdown
         * can be completed
         */
        if (vap->iv_he_bsscolor_change_count ==
                ic->ic_he_bsscolor_change_tbtt + 1) {
            vap->iv_he_bsscolor_change_ongoing = false;

            /* check bsscolor change completion for
             * all vaps
             */
            if (!ieee80211_is_bcca_ongoing_for_any_vap(ic)) {
                /* BCCA completed for all vap. Enable
                 * BSS Color in HEOP
                 */
#if SUPPORT_11AX_D3
                ic->ic_he.heop_bsscolor_info &=
                                    ~IEEE80211_HEOP_BSS_COLOR_DISABLD_MASK;
#else
                ic->ic_he.heop_param         &=
                                    ~IEEE80211_HEOP_BSS_COLOR_DISABLD_MASK;
#endif
            }

            if (vap->iv_he_bsscolor_detcn_configd_vap) {
                /* re-configure bss color detection in fw */
                ic->ic_config_bsscolor_offload(vap, false);
            }

            /* remove BCCA ie */
            vap->iv_he_bsscolor_remove_ie = true;
            vap->iv_bcca_ie_status = BCCA_NA;

            /* configure FW with new bss color */
            if (ic->ic_vap_set_param) {
                if (ic->ic_vap_set_param(vap,
                      IEEE80211_CONFIG_HE_BSS_COLOR,
                      ic->ic_bsscolor_hdl.selected_bsscolor)) {
                    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_ERROR,
                              "%s: bsscolor update to fw failed for vdev "
                              "id: 0x%x", __func__,
                              wlan_vdev_get_id(vap->vdev_obj));
                }
            }
        } /* if tbtt */
    } /* if beacon */

    QDF_TRACE(QDF_MODULE_ID_BSSCOLOR, QDF_TRACE_LEVEL_DEBUG,
            "%s<< iv_he_bsscolor_change_count: 0x%x", __func__,
                                vap->iv_he_bsscolor_change_count);
}

static bool optie_present_in_appie(struct ieee80211vap *vap, int elem_id, int subtype)
{
    bool ret = false;
    struct app_ie_entry *ie_entry = NULL;

    IEEE80211_VAP_LOCK(vap);
    if (!STAILQ_EMPTY(&vap->iv_app_ie_list[subtype])) {
        STAILQ_FOREACH(ie_entry, &vap->iv_app_ie_list[subtype], link_entry) {
            if (ie_entry->app_ie.ie != NULL && ie_entry->app_ie.length > 0) {
                if (ie_entry->app_ie.ie[0] == elem_id) {
                    ret = true;
                }
            }
        } /* STAILQ_FOREACH */
    } /* if */
    IEEE80211_VAP_UNLOCK(vap);

    return ret;
}

/* function to add non-inheritance element IE */
uint8_t ieee80211_mbss_add_noninherit_ie(struct ieee80211vap *non_tvap,
                                                 uint8_t *frm, int subtype)
{
    struct ieee80211com *ic = non_tvap->iv_ic;
    struct ieee80211vap *tvap = ic->ic_mbss.transmit_vap;
    uint8_t * list_elem;

    /*
     * ---------------------------------------------------------------------
     *|  Element   | Length |  Elem ID  | Length |  Elem ID | List of Elem  |
     *|    ID      |        | Extension |        |   List   | ID extensions |
     * ----------------------------------------------------------------------
     *     1           1         1          1      1 or more   1 or more
     */

    if(ic->ic_mbss.non_inherit_enable)
    {
        list_elem = &frm[NON_INH_ELEM_ID_LIST_OFFSET];

        if(optie_present_in_appie(tvap,IEEE80211_ELEMID_RSN,subtype) &&
            !optie_present_in_appie(non_tvap,IEEE80211_ELEMID_RSN,subtype)) {
            *list_elem = IEEE80211_ELEMID_RSN;
            list_elem++;
        }

        if(tvap->iv_mbss.is_xrates && !non_tvap->iv_mbss.is_xrates) {
            *list_elem = IEEE80211_ELEMID_XRATES;
            list_elem++;
        }

        if(optie_present_in_appie(tvap,IEEE80211_ELEMID_RSNX,subtype) &&
            !optie_present_in_appie(non_tvap,IEEE80211_ELEMID_RSNX,subtype)) {
            *list_elem = IEEE80211_ELEMID_RSNX;
            list_elem++;
        }

        if (list_elem != (&frm[NON_INH_ELEM_ID_LIST_OFFSET])) {
            frm[0] = IEEE80211_ELEMID_EXTN;
            /* update element length */
            frm[1] = list_elem - (&frm[2]) + 1;
            frm[2] = IEEE80211_ELEMID_EXT_NON_INHERITANCE;
            /* update element ID list length */
            frm[3] = list_elem - (&frm[4]);

            /* Set ExtnID List len to 0 */
            frm[3+1+frm[3]] = 0;

            return (frm[1] + 2);
        }
    }
    return 0;
}

/*
 * Add a profile to 11ax MBSSID IE
 */
uint8_t *
ieee80211_mbss_add_profile(u_int8_t *frm,
                           struct ieee80211_mbss_ie_cache_node *node,
                           const struct ieee80211com *ic,
                           uint16_t offset, uint8_t subtype)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211_mbss_non_tx_profile_sub_ie *vap_profile;
    struct ieee80211_mbss_ie *mb;
    struct ieee80211vap *vap;
    struct wlan_objmgr_vdev *vdev;
    struct vdev_mlme_obj *vdev_mlme;
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    struct wlan_objmgr_psoc *psoc;
    ol_ath_soc_softc_t *soc;
    uint8_t *ie_len_pos;   /* points to the length field of mbss-ie */
    uint8_t *profile_len_pos; /* points to the length field of sub-elem ie */
    uint16_t profile_len;   /* length of non-tx profile */
    uint8_t min_elems_len; /* length of mandatory elements in non-tx profile */
    uint8_t bssid_idx_elm_offset; /* offset to bss-idx element in non-tx profile */
    uint8_t dtim_count_offset; /* offset to dtim-count subfield in non-tx profile */
    uint16_t len; /* place holder for temp-length used in misc. calculations */
    uint16_t vendor_ies_len, sec_ie_len;
    uint16_t rsvd_space_ntx_profiles;
    const int ie_header_len = sizeof(struct ieee80211_ie_header);
    struct wmeParams *txvap_wme = ic->ic_mbss.transmit_vap->iv_wmestate.wme_bssChanParams.cap_wmeParams;
    struct wmeParams *nontxvap_wme = NULL;
    bool wme_copy;
    struct ieee80211_node *ni;

    if (subtype == IEEE80211_FRAME_TYPE_BEACON)
        mbss_debug(":> frm:%pK", frm);

    if (!frm || !node) {
        mbss_err("%s is NULL", !frm ? "frm" : "node");
        return NULL;
    }

    if (*(uint8_t *)node != IEEE80211_MBSSID_SUB_ELEMID) {
        mbss_err("first byte of node doesn't contain VAP sub-element ID");
        return NULL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc,
                            node->vdev_id, WLAN_MISC_ID);
    if (vdev == NULL) {
        mbss_err("vdev object is NULL for vdev id:%d", node->vdev_id);
        return NULL;
    }

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap) {
        mbss_err("vap is NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
        return NULL;
    }

    nontxvap_wme = vap->iv_wmestate.wme_bssChanParams.cap_wmeParams;
    vdev_mlme = vap->vdev_mlme;
    ni = vap->iv_bss;
    if (!ni) {
        mbss_err("ni is NULL");
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
        return NULL;
    }

    /* retrieve soc */
    soc = scn->soc;

    profile_len = min_elems_len = 0;

    /*
     * 1. calculate the total space required for non-tx profile
     * 2. if profile can fit in current MBSSID IE, copy the contents over.
     *    else, add another MBSSID IE  and copy the contents
     */

    /* 1. total space = length of these fields:
     *    capability + ssid + mbssid index + security IE + vendor IEs +
     *    non-inheritance IE (if needed)
     */
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
        sec_ie_len = ieee80211_get_security_vendor_ies(vap, frm, IEEE80211_FRAME_TYPE_BEACON, 0, 1);
        if (sec_ie_len > IEEE80211_MAX_MBSS_NON_TX_PROFILE_SECURITY_LEN) {
             mbss_err("Security IE beyond %d bytes, skip adding profile for %s!",
                      IEEE80211_MAX_MBSS_NON_TX_PROFILE_SECURITY_LEN,
                      ether_sprintf(vap->iv_myaddr));
             mbss_info(":<");
             goto exit;
        }
        profile_len += sec_ie_len;
    }

    /* vap profile in cache */
    vap_profile = &node->non_tx_profile.ntx_pf;

    min_elems_len += ie_header_len;
    switch (subtype) {
            case IEEE80211_FRAME_TYPE_BEACON:
            min_elems_len += vap_profile->sub_elem.length;
            break;
        case IEEE80211_FRAME_TYPE_PROBERESP:
            /* DTIM period and count are not included in probe response,
             * so decrement length by 2 */
            min_elems_len += (vap_profile->sub_elem.length - 2);
            break;
        default:
            mbss_info("Invalid subtype %d", subtype);
            wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
            return NULL;
    }

    profile_len += min_elems_len;

    /* vendor IEs */
    vendor_ies_len = ieee80211_get_security_vendor_ies(vap, frm, IEEE80211_FRAME_TYPE_BEACON, 0, 0);

    if (ieee80211_vap_wme_is_set(vap)) {
        if ((wme_copy = qdf_mem_cmp(txvap_wme,
            nontxvap_wme,
            sizeof(struct wmeParams) * WME_NUM_AC)) != 0) {
            vendor_ies_len += sizeof(struct ieee80211_wme_param);
        }
    }

    if (vendor_ies_len > vap->iv_mbss.total_vendor_ie_size) {

         mbss_debug("Vendor IE for %s beyond %d bytes,"
                 " IE won't be added to profile!",
         ether_sprintf(vap->iv_myaddr),
         vap->iv_mbss.total_vendor_ie_size);
    } else {
         profile_len += vendor_ies_len;
    }

    /* non-inheritance element
     * currently, only security id is added
     */
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(ic->ic_mbss.transmit_vap) &&
        !IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
        /* elem ID + length + extension ID + security */
        profile_len += 4;
    }

    if (subtype == IEEE80211_FRAME_TYPE_BEACON) {
        /* No limit check required as in case of
         * probe response below as this condition
         * is already sanitized during boot as
         * part of soc_attach()
         */
        rsvd_space_ntx_profiles = (IEEE80211_MAX_MGMT_SIZE_LIMIT -
                                   (IEEE80211_MAX_BEACON_COMMON_PART_SIZE +
                                    soc->ema_ap_rnr_field_size_limit));
    } else if (subtype == IEEE80211_FRAME_TYPE_PROBERESP) {
        if (IEEE80211_MAX_MGMT_SIZE_LIMIT >
                (IEEE80211_MAX_PRB_RESP_COMMON_PART_SIZE +
                 soc->ema_ap_rnr_field_size_limit)) {
            rsvd_space_ntx_profiles = (IEEE80211_MAX_MGMT_SIZE_LIMIT -
                                      (IEEE80211_MAX_PRB_RESP_COMMON_PART_SIZE +
                                       soc->ema_ap_rnr_field_size_limit));
        } else {
            rsvd_space_ntx_profiles = 0;
        }
    }

    if (!rsvd_space_ntx_profiles ||
            (profile_len > IEEE80211_MBSS_MAX_NTX_PER_PFL_SIZE) ||
            (profile_len > (rsvd_space_ntx_profiles - offset))) {
         mbss_debug("Max frame size reached, cannot add profile for vap %d",
                    vap->iv_unit);
         mbss_debug(":<");
         wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
         return NULL;
    }

    /* 2. populate the MBSSID IE now.. */
    mb = (struct ieee80211_mbss_ie *) frm;
    if (offset == 0) {
        /* add the first MBSSID IE */
        IEEE80211_ADD_MBSS_IE_TAG(ic, mb);
    } else {
        /* skip past any MBSS IEs */
        while (*(frm + ie_header_len + mb->header.length)
                ==  IEEE80211_ELEMID_MBSSID) {
            frm += ie_header_len + mb->header.length;
            mb = (struct ieee80211_mbss_ie *) frm;
        }
    }

    /* frm points to final MBSS IE, so increment by length bytes */
    frm += ie_header_len + mb->header.length;

    /* add new MBSSID IE if profile can't fit in current IE */
    if (profile_len > (IEEE80211_MAX_IE_LEN - mb->header.length)) {
        mb = (struct ieee80211_mbss_ie *) frm;
        IEEE80211_ADD_MBSS_IE_TAG(ic, mb);
        frm += ie_header_len + mb->header.length;
    }

    ie_len_pos = &mb->header.length;

    /* copy capability, SSID, MBSSID index elements */
    qdf_mem_copy(frm, (uint8_t *) vap_profile, min_elems_len);
    profile_len_pos = frm + 1;

    bssid_idx_elm_offset = (3 * ie_header_len) +
                                vap_profile->cap_elem.hdr.length +
                                    vap_profile->ssid_elem.hdr.length;

    /* 'bssid_idx_elm_offset + ie_header_len + 2' will take us to
     * the 1 octet slot with 'dtim_count' as length of subfield
     * 'bss_idx' and 'dtim_period' is each 1 octent
     */
    dtim_count_offset    = bssid_idx_elm_offset + ie_header_len + 2;

    if (subtype == IEEE80211_FRAME_TYPE_PROBERESP) {
        /* DTIM period and count are not part of probe response,
         * adjust the profile and BSSID index length fields
         */
        *(frm + bssid_idx_elm_offset + 1) =
            min_elems_len - (4 * ie_header_len) -
            vap_profile->cap_elem.hdr.length
            - vap_profile->ssid_elem.hdr.length;
    } else {
        mbss_debug("vdev_id: %d dtim_count: %d", vap->iv_unit,
                *((uint8_t *)vap_profile + dtim_count_offset));
    }

    /* In hidden SSID case, SSID field needs to be filled in a probe
       response frame while responding to a unicast request */
    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) &&
        (subtype == IEEE80211_FRAME_TYPE_PROBERESP) &&
        ic->ic_mbss.prb_req_ssid_match_vap) {

        if (ic->ic_mbss.prb_req_ssid_match_vap->iv_unit == vap->iv_unit) {
            if (min_elems_len > 3) {

                uint8_t temp[3] = {0};
                uint8_t *ssid_offset = NULL;

                /* copy out 3 bytes including IE header and length fields of
                 * bssid index element that were copied from cache profile
                 */
                qdf_mem_copy(temp, frm + min_elems_len - 3, 3);
                ssid_offset =
                    frm + ie_header_len +
                    sizeof(struct ieee80211_mbss_ie_capability)
                    + ie_header_len;
                qdf_mem_copy(ssid_offset, ni->ni_essid, ni->ni_esslen);
                qdf_mem_copy(ssid_offset + ni->ni_esslen, temp, 3);

                min_elems_len += ni->ni_esslen;
                *(ssid_offset - 1) = ni->ni_esslen;
            }
        }
    } /*IEEE80211_VAP_IS_HIDESSID_ENABLED */

    frm += min_elems_len;
    *profile_len_pos = min_elems_len - ie_header_len;
    *ie_len_pos += min_elems_len;

    /* copy security IE */
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) && sec_ie_len) {
        len = ieee80211_get_security_vendor_ies(vap, frm, IEEE80211_FRAME_TYPE_BEACON, 1, 1);
        frm += len;
        *profile_len_pos += len;
        *ie_len_pos += len;
    }

    /* copy vendor IEs */
    if (vendor_ies_len <= vap->iv_mbss.total_vendor_ie_size) {
        uint8_t *tmp_frm = frm;

        len = ieee80211_get_security_vendor_ies(vap, frm, IEEE80211_FRAME_TYPE_BEACON, 1, 0);
        frm += len;
        vap->iv_mbss.available_vendor_ie_space =
            (vap->iv_mbss.total_vendor_ie_size - vendor_ies_len);

        /* WME param */
        if (ieee80211_vap_wme_is_set(vap)) {
            if (wme_copy) {
                frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate,
                                              IEEE80211_VAP_IS_UAPSD_ENABLED(vap));
            }
        }

        len = frm - tmp_frm;
        *profile_len_pos += len;
        *ie_len_pos += len;
    }

    /* copy non-inheritance IE */
    len = ieee80211_mbss_add_noninherit_ie(vap, frm, subtype);
    frm += len;
    *profile_len_pos += len;
    *ie_len_pos += len;

exit:
    if (vdev)
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);

    if (subtype == IEEE80211_FRAME_TYPE_BEACON)
        mbss_debug(":<");

    return frm;
}

/* SKB Layout
 * Size: 2K
 *
 *  ----------------   <-- 0
 * |   Head room    |
 * |----------------|  <-- 50
 * |                |
 * |   Section 1    |
 * | Beacon backup  |
 * |                |
 * |----------------|  <-- 850
 * |  Guard space   |
 * |----------------|  <-- 900
 * |                |
 * |   Section 2    |
 * |  Curr IE Pool  |
 * |                |
 * |----------------|  <-- 1700
 * |  Guard space   |
 * |----------------|  <-- 1750
 * |                |
 * |   Section 3    |
 * | Non-inherit IE |
 * |                |
 * |----------------|  <-- 1950
 * |   Tail room    |
 *  ----------------   <-- 2048
 *
 */
#define IEEE80211_NTX_PFL_BACKUP_OFFSET 50
#define IEEE80211_NTX_PFL_BUFFER_OFFSET 900
#define IEEE80211_NTX_PFL_NIE_OFFSET 1750
#define IEEE80211_NTX_PFL_IE_POOL_NON_INHERIT_IE_SIZE 200
#define IEEE80211_SPLIT_PFL_MAX_NTX_PFL_SIZE 250

#if QCA_SUPPORT_EMA_EXT
/*
 * Since we do greedy packing for probe response, we have to check whether
 * probe response frame has enough space for the IE or not, besides total
 * profile size checks
 */
static inline bool is_presp_total_size_available(struct ieee80211com *ic, ieee80211_frame_type ftype,
                                                 int ie_size)
{
    ic->ic_mbss.ema_ap_available_prb_non_tx_space -= ie_size;
    if (ic->ic_mbss.ema_ap_available_prb_non_tx_space < 0) {
        return false;
    }

    return true;
}

static inline int __calc_nie_size(uint8_t **nie, uint8_t **nie_end,
                                  uint8_t eid_x)
{
    int nie_size = 0;

    if ((*((*nie) - 2) == IEEE80211_ELEMID_EXT_NON_INHERITANCE) &&
            (*((*nie) - 4) == IEEE80211_ELEMID_EXTN) &&
            (*nie_end) == (((*nie)-4)+IEEE80211_NTX_PFL_IE_POOL_NON_INHERIT_IE_SIZE)) {
        nie_size += 3; /* Extension ID, len, non-inheritance IE ID */
        nie_size++; /* Length of ElemID list */
        nie_size++; /* Length of ExtnID list */
    }
    nie_size++; /* ID added to the ElemID or ExtnID list */
    return nie_size;
}
/*
 * Inheritance and Non-inheritance logic:
 *
 * If Tx VAP has the IE,
 *      - If Non-Tx VAP has the IE as well, add the IE to the buffer only if the payload is different; else, ignore.
 *      - If Non-Tx VAP has NOT the IE, add the IE to Non-inheritance IE.
 *
 * If Tx VAP has NOT the IE,
 *      - If Non-Tx VAP has the IE, add it to the buffer.
 *      - IF Non-Tx VAP has NOT the IE as well, ignore.
 */
static inline int __ieee80211_mbss_check_and_add(struct ieee80211com *ic, ieee80211_frame_type ftype, uint8_t *bo_x,
                                                 uint8_t eid_x, uint8_t xtid_x, uint8_t **curr_ie_pool,
                                                 uint8_t *iebuf, uint8_t **nie, uint8_t **nie_end,
                                                 uint16_t *profile_len, int32_t *remaining_space)
{
    const int ie_header_len = sizeof(struct ieee80211_ie_header);
    int nie_size = 0;
    int ret = 0;

    do {
        if (bo_x && (bo_x[0] == eid_x)) {
            /* Tx VAP has the IE */
            switch (eid_x) {
            case IEEE80211_ELEMID_EXTN:
                if (bo_x[2] != xtid_x) {
                    break;
                }
            default:
                if (!iebuf || iebuf[1] < 1) {
                    /* NonTx VAP does not have the IE; add element ID to
                     * non-inheritance IE, if space available
                     */
                    if (*nie && *nie_end) {
                        nie_size = __calc_nie_size(nie, nie_end, eid_x);
                        if ((ftype == IEEE80211_FRAME_TYPE_PROBERESP &&
                                    is_presp_total_size_available(ic, ftype, nie_size)) ||
                                    ftype == IEEE80211_FRAME_TYPE_BEACON) {
                            if ((*remaining_space - nie_size < 0)) {
                                ret = -ENOMEM;
                                goto exit;
                            }
                        } else {
                            ret = -ENOMEM;
                            goto exit;
                        }

                        if (eid_x == IEEE80211_ELEMID_EXTN) {
                            *(--(*nie_end)) = xtid_x;
                        } else {
                            *(*nie)++ = eid_x;
                        }
                        *remaining_space -= nie_size;
                    }
                } else {
                    /* NonTx VAP has the IE; add to curr_ie_pool if the payload
                     * is different than that of the Tx VAP, if space available
                     */
                    if ((bo_x[1] != iebuf[1]) ||
                            ((bo_x[1] == iebuf[1]) && qdf_mem_cmp(bo_x, iebuf, bo_x[1]+ie_header_len))) {
                        if ((ftype == IEEE80211_FRAME_TYPE_PROBERESP &&
                                    is_presp_total_size_available(ic, ftype, iebuf[1]+ie_header_len)) ||
                                    ftype == IEEE80211_FRAME_TYPE_BEACON) {
                                if (iebuf[0] == IEEE80211_ELEMID_RSN &&
                                        (iebuf[1]+ie_header_len) > IEEE80211_MAX_MBSS_NON_TX_PROFILE_SECURITY_LEN) {
                                    ret = -ENOMEM;
                                    goto exit;
                                } else if (iebuf[0] != IEEE80211_ELEMID_RSN &&
                                        (*remaining_space - (iebuf[1] + ie_header_len) < 0)) {
                                    ret = -ENOMEM;
                                    goto exit;
                                }
                        } else {
                            ret = -ENOMEM;
                            goto exit;
                        }
                        IE_MEM_COPY_MOVE_DESTN_UPD_LEN(*curr_ie_pool, iebuf,
                                iebuf[1]+ie_header_len, *profile_len);

                        if (iebuf[0] != IEEE80211_ELEMID_RSN)
                            *remaining_space -= (iebuf[1]+ie_header_len);
                    }
                    continue;
                }
            }
        }

        /* Tx VAP does not have the IE */
        if (iebuf && iebuf[1] >= 1) {
            /* NonTx VAP has the IE; add it to curr_ie_pool, if space
             * available
             */
            if ((ftype == IEEE80211_FRAME_TYPE_PROBERESP &&
                        is_presp_total_size_available(ic, ftype, iebuf[1]+ie_header_len)) ||
                    ftype == IEEE80211_FRAME_TYPE_BEACON) {
                if (iebuf[0] == IEEE80211_ELEMID_RSN &&
                        (iebuf[1]+ie_header_len) > IEEE80211_MAX_MBSS_NON_TX_PROFILE_SECURITY_LEN) {
                    ret = -ENOMEM;
                    goto exit;
                } else if (iebuf[0] != IEEE80211_ELEMID_RSN &&
                        (*remaining_space - (iebuf[1] + ie_header_len) < 0)) {
                    ret = -ENOMEM;
                    goto exit;
                }
            } else {
                ret = -ENOMEM;
                goto exit;
            }
            IE_MEM_COPY_MOVE_DESTN_UPD_LEN(*curr_ie_pool, iebuf,
                    iebuf[1]+ie_header_len, *profile_len);

            if (iebuf[0] != IEEE80211_ELEMID_RSN)
                *remaining_space -= (iebuf[1]+ie_header_len);
        }
    } while(0);

exit:
    return ret;
}

#define IEEE80211_ADD_NTX_PROFILE_TAG(frm, profile_len_pos) {\
    *(frm) = IEEE80211_MBSSID_SUB_ELEMID; /* NTx Profile subelement ID */\
    (frm)++;\
    *(frm) = 0; /* NTx Profile subelement Length */\
    (frm)++;\
    profile_len_pos = (frm) - 1; /* Pointer to subelement Length */\
}

static int ieee80211_mbss_check_and_add_ie(struct ieee80211com *ic, ieee80211_frame_type ftype, uint8_t eid_x,
                                                  uint8_t xtid_x, uint8_t *bo_x, int32_t *remaining_space,
                                                  uint8_t **curr_ie_pool, uint8_t *saved_iebuf, uint8_t **iebuf,
                                                  uint8_t **nie, uint8_t **nie_end, uint16_t *profile_len)
{
    int ret;

    ret = __ieee80211_mbss_check_and_add(ic, ftype, bo_x, eid_x, xtid_x, curr_ie_pool, saved_iebuf, nie,
            nie_end, profile_len, remaining_space);
    *iebuf = saved_iebuf;
    qdf_mem_zero(*iebuf, IEEE80211_MAX_IE_LEN);

    return ret;
}
#endif

static void ieee80211_add_vie_to_curr_ie_pool(uint8_t **curr_ie_pool,
                                              uint8_t *saved_iebuf,
                                              uint8_t **iebuf,
                                              uint16_t *len)
{
    if (!(*curr_ie_pool) || !saved_iebuf || !(*iebuf))
        return;

    IE_MEM_COPY_MOVE_DESTN_UPD_LEN(*curr_ie_pool, saved_iebuf,
            saved_iebuf[1]+2, *len);
    *iebuf = saved_iebuf;
    qdf_mem_zero(*iebuf, IEEE80211_MAX_IE_LEN);
}

static uint16_t ieee80211_mbss_add_vendor_ies(struct ieee80211_node *ni, ieee80211_frame_type ftype, uint8_t *curr_ie_pool, uint8_t *iebuf)
{
    uint8_t *saved_iebuf = iebuf;
    uint16_t len = 0;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
#if DBDC_REPEATER_SUPPORT
    struct global_ic_list *ic_list = ic->ic_global_list;
#endif

    qdf_mem_zero(iebuf, IEEE80211_MAX_IE_LEN);

    /* Ath Advertisement capabilities */
    if (vap->iv_ena_vendor_ie == 1) {
        if (vap->iv_bss && vap->iv_bss->ni_ath_flags) {
            iebuf = ieee80211_add_athAdvCap(iebuf, vap->iv_bss->ni_ath_flags,
                    vap->iv_bss->ni_ath_defkeyindex);
        } else {
            iebuf = ieee80211_add_athAdvCap(iebuf, 0, IEEE80211_INVAL_DEFKEY);
        }
        vap->iv_update_vendor_ie = 0;
        ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                &iebuf, &len);
    }

    /* Ath Extended Capabilities */
    if (ic->ic_ath_extcap) {
        iebuf = ieee80211_add_athextcap(iebuf, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);
        ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                &iebuf, &len);
    }

#if DBDC_REPEATER_SUPPORT
    /* Extender */
    if (ic_list->same_ssid_support) {
        iebuf = ieee80211_add_extender_ie(vap, ftype, iebuf);
        ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf, &iebuf,
                &len);
    }
#endif

    /* HT Cap and HT Info vendor IEs */
    switch (ftype) {
    case IEEE80211_FRAME_TYPE_BEACON:
        if ((!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
                 (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
                 IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
                 IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
                IEEE80211_IS_HTVIE_ENABLED(ic) && ieee80211vap_htallowed(vap)) {
            iebuf = ieee80211_add_htcap_vendor_specific(iebuf, ni, IEEE80211_FC0_SUBTYPE_BEACON);
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);

            iebuf = ieee80211_add_htinfo_vendor_specific(iebuf, ni);
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);
        } break;
    case IEEE80211_FRAME_TYPE_PROBERESP:
        if (ieee80211_vap_wme_is_set(vap) &&
                (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
                (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
                 IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
                 IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
                IEEE80211_IS_HTVIE_ENABLED(ic) && ieee80211vap_htallowed(vap)){
            iebuf = ieee80211_add_htcap_vendor_specific(iebuf, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);

            iebuf = ieee80211_add_htinfo_vendor_specific(iebuf, ni);
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);
        } break;
    default:
        qdf_info("%s:%d Invalid ftype", __func__, __LINE__);
        break;
    }

    /* MBO_OCE */
    if (ieee80211_vap_mbo_check(vap) || ieee80211_vap_oce_check(vap)) {
        if (ftype == IEEE80211_FRAME_TYPE_BEACON)
            iebuf = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_BEACON, vap, iebuf, ni);
        else if (ftype == IEEE80211_FRAME_TYPE_PROBERESP)
            iebuf = ieee80211_setup_mbo_ie(IEEE80211_FC0_SUBTYPE_PROBE_RESP, vap, iebuf, ni);
        ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf, &iebuf,
                &len);
    }

    if (ftype == IEEE80211_FRAME_TYPE_BEACON) {
        /* Next Channel */
        if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic)
                && IEEE80211_IS_CHAN_DFS(ic->ic_curchan) && ic->ic_tx_next_ch)
        {
            iebuf = ieee80211_add_next_channel(iebuf, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);
        }
    }

    /* Prop NSS Map IE if EXT NSS is not supported */
    if (!(vap->iv_ext_nss_support) &&
            ((ftype == IEEE80211_FRAME_TYPE_BEACON && (!(ic->ic_disable_bcn_bwnss_map))) ||
             (ftype == IEEE80211_FRAME_TYPE_PROBERESP)) &&
            !(ic->ic_disable_bwnss_adv)) {
        struct ieee80211_bwnss_map nssmap;
        uint8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

        qdf_mem_zero(&nssmap, sizeof(nssmap));

        if (!ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)){
            iebuf = ieee80211_add_bw_nss_maping(iebuf, &nssmap);
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);
        }
    }

#if QCN_IE
    {
        uint16_t qcn_ie_len = 0;
        /* QCN IE for the feature set */
        iebuf = ieee80211_add_qcn_info_ie(iebuf, vap, &qcn_ie_len,
                QCN_MAC_PHY_PARAM_IE_TYPE, NULL);
        ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf, &iebuf,
                &len);
    }
#endif

    /* SON mode IE which requires WDS as a prereq */
    if (IEEE80211_VAP_IS_WDS_ENABLED(vap) &&
            !son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY)) {
        if (ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, ftype,
                    IEEE80211_ELEMID_VENDOR, IEEE80211_ELEMID_VENDOR_SON_AP,
                    &iebuf, TYPE_APP_IE_BUF, NULL, true)) {
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);
        }
    }

    if (ftype == IEEE80211_FRAME_TYPE_BEACON) {
        /* VHT Vendor IE for 256QAM support in 2.4G Interop */
        if ((ieee80211_vap_wme_is_set(vap) &&
                    (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
                    IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
                ieee80211vap_vhtallowed(vap) &&
                ieee80211vap_11ng_vht_interopallowed(vap)) {
            /* Add VHT capabilities IE and VHT OP IE in Vendor specific IE*/
            iebuf = ieee80211_add_interop_vhtcap(iebuf, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON);
            ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf,
                    &iebuf, &len);
        }
    }

    /* WME param */
    if (ieee80211_vap_wme_is_set(vap) &&
            (vap->iv_opmode == IEEE80211_M_HOSTAP ||
             vap->iv_opmode == IEEE80211_M_BTAMP)) {
        iebuf = ieee80211_add_wme_param(iebuf, &vap->iv_wmestate,
                IEEE80211_VAP_IS_UAPSD_ENABLED(vap));

        if (ftype == IEEE80211_FRAME_TYPE_BEACON)
            ieee80211vap_clear_flag(vap, IEEE80211_F_WMEUPDATE);

        ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf, &iebuf, &len);
    }

    /* Hardware and Software version */
    iebuf = ieee80211_add_sw_version_ie(iebuf, ic);
    ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf, &iebuf, &len);

    /* Generic vendor capabilities */
    iebuf = ieee80211_add_generic_vendor_capabilities_ie(iebuf, ic);
    ieee80211_add_vie_to_curr_ie_pool(&curr_ie_pool, saved_iebuf, &iebuf, &len);

    /* Add vendor IEs from App IE List */
    len += ieee80211_get_security_vendor_ies(vap, curr_ie_pool, ftype, 1, 0);

    return len;
}

#if QCA_SUPPORT_EMA_EXT
static uint16_t ieee80211_get_vendore_ies_len_from_backup(uint8_t *backup, uint16_t len)
{
    const int ie_header_len = sizeof(struct ieee80211_ie_header);
    uint16_t vendor_ies_len = 0;
    uint8_t *temp = backup;

    if (!backup || !len)
        return 0;

    while ((temp + 1) < (backup + len)) {
        if (temp[0] != IEEE80211_ELEMID_VENDOR)
            break;
        else
            vendor_ies_len += temp[1] + ie_header_len;
        temp += temp[1] + ie_header_len;
    }

    return vendor_ies_len;
}

static uint8_t ieee80211_get_mandatory_ies_len_from_backup(uint8_t *backup, uint16_t vie_len, uint16_t pfl_len)
{
    const int ie_header_len = sizeof(struct ieee80211_ie_header);
    uint8_t *temp = NULL;
    uint8_t min_elems_len = 0;

    if (!backup || !pfl_len)
        return 0;

    temp = backup + vie_len;

    while ((temp + 1) < (backup + pfl_len)) {
        if (temp[0] == IEEE80211_ELEMID_MBSSID_NON_TRANS_CAP ||
                temp[0] == IEEE80211_ELEMID_SSID ||
                temp[0] == IEEE80211_ELEMID_MBSSID_INDEX)
            min_elems_len += temp[1] + ie_header_len;
        else
            break;
        temp += temp[1] + ie_header_len;
    }

    return min_elems_len;
}

static uint8_t *ieee80211_get_non_inherit_ie_from_backup(uint8_t *backup, uint16_t len)
{
    const int ie_header_len = sizeof(struct ieee80211_ie_header);
    uint8_t *nie = NULL;

    if (!backup || !len)
        return NULL;

    nie = backup + len;
    nie -= 3;

    while ((nie >= backup) && ((nie[0] != IEEE80211_ELEMID_EXTN) ||
                (nie[ie_header_len] != IEEE80211_ELEMID_EXT_NON_INHERITANCE))) {
        nie--;
    }

    if (nie < backup)
        nie = NULL;

    return nie;
}

static void ieee80211_add_to_mbss_ie(struct ieee80211vap *vap,
        struct ieee80211_mbss_ie **mb, uint8_t **frm, uint8_t *buffer, uint16_t tot_len,
        uint8_t **ie_len_pos, uint8_t **profile_len_pos)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint8_t *buf_start = buffer;
    bool pf_not_fit = false;
    const int ie_header_len = sizeof(struct ieee80211_ie_header);

    if (!buffer || !tot_len ||
            !(*mb) || !(*frm) ||
            !(*ie_len_pos) || !(*profile_len_pos))
        return;

    while ((buffer + 1) < (buf_start + tot_len)) {

        /* If profile length goes beyond IEEE80211_MAX_IE_LEN, create a new profile (split profile) */
        if ((buffer[1] + ie_header_len) > (IEEE80211_MAX_IE_LEN - *(*profile_len_pos) - ie_header_len)) {
            IEEE80211_ADD_NTX_PROFILE_TAG(*frm, *profile_len_pos);
            *(*ie_len_pos) += ie_header_len;
            pf_not_fit = true;
        }

        /* If the current MBSSID IE cannot accomodate the next IE, create a new MBSSID IE,
         * and add Non-Tx profile tag (split profile). If simply a Non-Tx profile tag is hanging in the
         * last MBSSID IE, undo it.
         */
        if ((buffer[1] + ie_header_len) > (IEEE80211_MAX_IE_LEN - (*mb)->header.length - ie_header_len)) {
            if (pf_not_fit) {
                *(*ie_len_pos) -= ie_header_len;
                *frm -= ie_header_len;
            }
            (*mb) = (struct ieee80211_mbss_ie *) (*frm);
            IEEE80211_ADD_MBSS_IE_TAG(ic, (*mb));
            *ie_len_pos = (*frm) + 1;
            *(*ie_len_pos) += ie_header_len;
            *frm += sizeof(struct ieee80211_mbss_ie); /* Skip ID, len, Max BSSID */
            IEEE80211_ADD_NTX_PROFILE_TAG(*frm, *profile_len_pos);
        }
        pf_not_fit = false;
        qdf_mem_copy(*frm, buffer, buffer[1] + ie_header_len);
        (*frm) += buffer[1] + ie_header_len;
        *(*ie_len_pos) += buffer[1] + ie_header_len;
        *(*profile_len_pos) += (buffer[1] + ie_header_len);
        buffer += buffer[1] + ie_header_len;
    }
}

static bool ieee80211_mbss_is_vendor_ie_size_valid(struct ieee80211vap *vap,
        ieee80211_frame_type ftype, int32_t *available_vendor_ie_space,
        uint16_t *vendor_ies_len, uint8_t *curr_ie_pool)
{
    if (*vendor_ies_len > vap->iv_mbss.total_vendor_ie_size) {
        mbss_debug("Vendor IE size %d for %s beyond %d bytes, IE won't be added to the profile for subtype=%u!",
                *vendor_ies_len,
                ether_sprintf(vap->iv_myaddr),
                vap->iv_mbss.total_vendor_ie_size,
                ftype);
        qdf_mem_zero(curr_ie_pool, *vendor_ies_len);
        *vendor_ies_len = 0;
        *available_vendor_ie_space = 0;
        return false;
    } else {
        *available_vendor_ie_space = vap->iv_mbss.total_vendor_ie_size - *vendor_ies_len;
        return true;
    }
}

static int ieee80211_add_ies_from_appie_buffer(struct ieee80211vap *vap,
                                               uint8_t eid_x, uint8_t xtid_x,
                                               uint8_t *bo_x,
                                               ieee80211_frame_type ftype,
                                               uint8_t **curr_ie_pool,
                                               uint8_t **nie, uint8_t **nie_end,
                                               uint8_t *saved_iebuf, uint8_t **iebuf,
                                               void *optie, int32_t *remaining_space,
                                               uint16_t *profile_len)
{
    struct ieee80211com *ic = vap->iv_ic;
    int ret = 0;
    ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, ftype, eid_x, xtid_x,
            iebuf, TYPE_ALL_BUF, (struct ieee80211_app_ie_t *)optie, true);
    ret = ieee80211_mbss_check_and_add_ie(ic, ftype, eid_x, xtid_x, bo_x,
                remaining_space, curr_ie_pool, saved_iebuf,
                iebuf, nie, nie_end, profile_len);
    return ret;
}

static int ieee80211_mbss_build_bcn_profile(struct ieee80211_node *ni,
                                            struct ieee80211_mbss_non_tx_profile_sub_ie *vap_profile,
                                            uint16_t *profile_len,
                                            uint8_t *min_elems_len, uint8_t *curr_ie_pool,
                                            uint8_t *iebuf,
                                            int32_t *available_bcn_optional_ie_space)
{
    uint8_t *non_inherit_ie = NULL, *nie = NULL, *nie_end = NULL;
    uint8_t *saved_iebuf = NULL;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    struct ieee80211_beacon_offsets *bo = NULL;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211vap *txvap = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;
    const int ie_header_len = sizeof(struct ieee80211_ie_header);

    txvap = ic->ic_mbss.transmit_vap;
    if (!txvap) {
        mbss_err("TxVAP is NULL");
        return -EINVAL;
    }

    if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE)
        rs = &(vap->iv_op_rates[wlan_get_desired_phymode(vap)]);

    avn = OL_ATH_VAP_NET80211(txvap);
    bo = &(avn->av_beacon_offsets);
    saved_iebuf = iebuf;

    /* Fill length and list length of Non-inheritane IE after population */
    if (ic->ic_mbss.non_inherit_enable) {
        non_inherit_ie = nie = vap->iv_mbss.non_tx_pfl_ie_pool->data + IEEE80211_NTX_PFL_NIE_OFFSET;
        nie_end = nie + IEEE80211_NTX_PFL_IE_POOL_NON_INHERIT_IE_SIZE;
        *nie++ = IEEE80211_ELEMID_EXTN;
        *nie++ = 1;
        *nie++ = IEEE80211_ELEMID_EXT_NON_INHERITANCE;
        nie++;
    }

    /* ---------- Mandatory elements ---------- */
    /* Capability, SSID, and MBSSID index elements */
    qdf_mem_copy(curr_ie_pool, (uint8_t *) vap_profile + ie_header_len,
            (*min_elems_len)-ie_header_len);
    curr_ie_pool += (*min_elems_len) - ie_header_len;
    (*profile_len) += (*min_elems_len) - ie_header_len;

    /* ---------- Optional elements ---------- */
    /* Supported Rates and BSS Membership Selectors
     *
     * The return values are not captured because it is taken care
     * of in ieee80211_mbss_check_and_add_ie() for inheritance
     * non-inheritance rules. This is followed throughout this
     * function and in ieee80211_mbss_build_prb_profile()
     */
    (void)ieee80211_add_rates(vap, iebuf, rs);

    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RATES, -1,
                bo->bo_rates, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Power Constraint */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        *iebuf++ = IEEE80211_ELEMID_PWRCNSTR;
        *iebuf++ = 1;
        *iebuf++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_PWRCNSTR, -1,
                bo->bo_pwrcnstr, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* TPC Report */
    if ((ieee80211_ic_doth_is_set(ic) &&
                ieee80211_vap_doth_is_set(vap)) ||
            ieee80211_vap_rrm_is_set(vap)) {
        (void)ieee80211_add_tpc_ie(iebuf, vap, IEEE80211_FC0_SUBTYPE_BEACON);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_TPCREP, -1,
                bo->bo_tpcreport, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Extended Supported Rates and BSS Membership Selectors */
    if (rs->rs_nrates >= IEEE80211_RATE_SIZE) {
            (void)ieee80211_add_xrates(vap, iebuf, rs);
    }

    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_XRATES, -1,
                bo->bo_xrates, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* RSN */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_RSN, -1,
                bo->bo_rsn, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* QBSS Load */
    if (ieee80211_vap_qbssload_is_set(vap)) {
        (void)ieee80211_add_qbssload_ie(vap, iebuf, ni);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_QBSS_LOAD, -1,
                    bo->bo_qbssload, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                    &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    } else {
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QBSS_LOAD, -1,
                    bo->bo_qbssload, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                    &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
            return -ENOMEM;
    }

    /* EDCA Parameter Set */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EDCA, -1,
                bo->bo_edca, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* QoS Capability */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QOS_CAP, -1,
                bo->bo_qos_cap, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* AP Channel Report */
    if (vap->ap_chan_rpt_enable) {
        (void)ieee80211_add_ap_chan_rpt_ie(iebuf, vap);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_AP_CHAN_RPT, -1,
                bo->bo_ap_chan_rpt, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* BSS Average Access Delay */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY, -1,
                bo->bo_bss_avg_delay, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Antenna */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_ANTENNA, -1,
                bo->bo_antenna, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* BSS Available Admission Capacity */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1,
                bo->bo_bss_adm_cap, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

#if !ATH_SUPPORT_WAPI
    /* BSS AC Access Delay */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1,
                bo->bo_bss_ac_acc_delay, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;
#endif /* !ATH_SUPPORT_WAPI */

    /* Measurement Pilot Transmissions */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1,
                bo->bo_msmt_pilot_tx, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* RM Enabled Capabilities */
    (void)ieee80211_add_rrm_cap_ie(iebuf, ni);
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RRM, -1,
                bo->bo_rrm, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Mobility Domain */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MOBILITY_DOMAIN, -1,
                bo->bo_mob_domain, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* DSE Registered Location */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_DSE_REG_LOCATION, -1,
                bo->bo_dse_reg_loc, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    if (ieee80211_vap_wme_is_set(vap) &&
            (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11N(vap->iv_bsschan)) &&
            ieee80211vap_htallowed(vap)) {
        /* 20/40 BSS Coexistence */
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_2040_COEXT, -1,
                    bo->bo_2040_coex, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                    &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
            return -ENOMEM;

        /* Overlapping BSS Scan Parameters */
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE))
            (void)ieee80211_add_obss_scan(iebuf, ni);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_OBSS_SCAN, -1,
                    bo->bo_obss_scan, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                    &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    }

    /* Extended Capabilities */
    (void)ieee80211_add_extcap(iebuf, ni, IEEE80211_FC0_SUBTYPE_BEACON);
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_XCAPS, -1,
                bo->bo_extcap, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

#if UMAC_SUPPORT_WNM
    /* FMS Descriptor */
    if (ieee80211_vap_wnm_is_set(vap) && ieee80211_wnm_fms_is_set(vap->wnm)) {
        uint8_t *fmsie = NULL;
        uint32_t fms_counter_mask = 0;
        uint8_t fmsie_len = 0;

        (void)ieee80211_wnm_setup_fmsdesc_ie(ni, 0, &fmsie, &fmsie_len, &fms_counter_mask);
        if (fmsie_len)
            qdf_mem_copy(iebuf, fmsie, fmsie_len);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_FMS_DESCRIPTOR, -1,
                bo->bo_fms_desc, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;
#endif /* UMAC_SUPPORT_WNM */

    /* QoS Traffic Capability */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1,
                bo->bo_qos_traffic, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Time Advertisement */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1,
                bo->bo_time_adv, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Interworking (Hotspot 2.0) */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_INTERWORKING, -1,
                bo->bo_interworking, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Advertisement Protocol (Hotspot 2.0) */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_ADVERTISEMENT_PROTO, -1,
                bo->bo_adv_proto, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Roaming Consortium (Hotspot 2.0) */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_ROAMING_CONSORTIUM, -1,
                bo->bo_roam_consortium, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Emergency Alert Identifier */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1,
                bo->bo_emergency_id, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh ID */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_ID, -1,
                bo->bo_mesh_id, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh Configuration */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_CONFIG, -1,
                bo->bo_mesh_conf, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh Awake window */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1,
                bo->bo_mesh_awake_win, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Beacon Timing */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BEACON_TIMING, -1,
                bo->bo_beacon_time, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* MCCAOP Advertisement Overview */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1,
                bo->bo_mccaop_adv_ov, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* MCCAOP Advertisement */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MCCAOP_ADV, -1,
                bo->bo_mccaop_adv, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh Channel Switch Parameters */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1,
                bo->bo_mesh_cs_param, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* QMF Policy */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QMF_POLICY, -1,
                bo->bo_qmf_policy, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* QLoad Report */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QLOAD_REPORT, -1,
                bo->bo_qload_rpt, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* HCCA TXOP Update Count */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_HCCA_TXOP_UPD_CNT, -1,
                bo->bo_hcca_upd_cnt, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Multi-band */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MULTIBAND, -1,
                bo->bo_multiband, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    if (ieee80211_vap_wme_is_set(vap) &&
            (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            (IEEE80211_IS_CHAN_11AX(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
             IEEE80211_IS_CHAN_11NG(vap->iv_bsschan)) &&
            ieee80211vap_vhtallowed(vap)){

        /* Extended BSS Load */
        if (ieee80211_vap_ext_bssload_is_set(vap))
            (void)ieee80211_add_ext_bssload_ie(vap, iebuf, ni);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EXT_BSS_LOAD, -1,
                bo->bo_ext_bssload, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Quiet Channel */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QUIET_CHANNEL, -1,
                bo->bo_quiet_chan, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Operating Mode Notification */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_OP_MODE_NOTIFY, -1,
                bo->bo_opt_mode_note, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* TVHT Operation */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TVHT_OP, -1,
                bo->bo_tvht, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

#if QCN_ESP_IE
    /* Estimated Service Parameters */
    if(ic->ic_esp_periodicity){
        uint16_t esp_ie_len = 0;
        (void)ieee80211_add_esp_info_ie(iebuf, ic, &esp_ie_len);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_ESP_ELEMID_EXTENSION, bo->bo_esp_ie, available_bcn_optional_ie_space,
                &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;
#endif /* QCN_ESP_IE */

    /* Future Channel Guidance */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_FUTURE_CHANNEL_GUIDE,
                bo->bo_future_chan, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Common Advertisement Group (CAG) Number */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_CAG_NUMBER, -1,
                bo->bo_cag_num, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* FILS Indication */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_FILS_INDICATION, -1,
                bo->bo_fils_ind, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* AP-CSN */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_AP_CSN, -1,
                bo->bo_ap_csn, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Differentiated Initial Link Setup */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1,
                bo->bo_diff_init_lnk, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Service Hint */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HINT,
                bo->bo_service_hint, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Service Hash */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_SERVICE_HASH,
                bo->bo_edca, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* RSN XE */
    if (vap->iv_rsnx_override) {
        (void)ieee80211_rsnx_override(iebuf, vap);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_RSNX, -1,
                    bo->bo_rsnx, available_bcn_optional_ie_space, &curr_ie_pool, saved_iebuf,
                    &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    } else {
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_RSNX, -1,
                    bo->bo_rsnx, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                    &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
            return -ENOMEM;
    }

    /* Note: WAPI in the context of EMA is unknown from the spec */

    /* TWT */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TWT, -1,
                bo->bo_twt, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

#if ATH_SUPPORT_UORA
    /* UORA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_uora_is_enabled(vap)) {
        (void)ieee80211_add_uora_param(iebuf, vap->iv_ocw_range);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_UORA_PARAM, bo->bo_uora_param, available_bcn_optional_ie_space,
                &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;
#endif /* ATH_SUPPORT_UORA */

    /* MU EDCA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap)) {
        (void)ieee80211_add_muedca_param(iebuf, &vap->iv_muedcastate);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_MUEDCA, bo->bo_muedca, available_bcn_optional_ie_space,
                &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* ESS Report */
    if (vap->iv_planned_ess) {
        (void)ieee80211_add_ess_rpt_ie(iebuf, vap);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_BEACON, IEEE80211_ELEMID_EXTN,
                    IEEE80211_ELEMID_EXT_ESS_REPORT, bo->bo_ess_rpt, available_bcn_optional_ie_space,
                    &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    } else {
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_ESS_REPORT,
                    bo->bo_ess_rpt, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                    &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
            return -ENOMEM;
    }

    /* NDP Feedback Report Parameter Set */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM,
                bo->bo_ndp_rpt_param, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* HE BSS Load */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN, IEEE80211_ELEMID_EXT_HE_BSS_LOAD,
                bo->bo_he_bss_load, IEEE80211_FRAME_TYPE_BEACON, &curr_ie_pool, &nie,
                &nie_end, saved_iebuf, &iebuf, NULL, available_bcn_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Copy Non-inheritance IE to the buffer
     *
     * Format of Non-inheritance IE
     * IE Header | ExtID | ElemID list len | list | ExtnID list len | list
     *
     * where ElemID list len and ExtnID list len fields are mandatory and
     * list fields are optional based on len fields
     */
    if (ic->ic_mbss.non_inherit_enable) {
        non_inherit_ie[3] = nie - (non_inherit_ie + 4);
        *nie = (non_inherit_ie + IEEE80211_NTX_PFL_IE_POOL_NON_INHERIT_IE_SIZE) - nie_end;
        non_inherit_ie[1] += non_inherit_ie[3] + (*nie);

        /* Add 2B to len of non-inheritance IE to account for len fields in the
         * ElemID list and ExtnID list
         */
        if (non_inherit_ie[3] != 0 || (*nie) != 0)
            non_inherit_ie[1] += 2;

        qdf_mem_move(nie+1, nie_end, *nie);
        if (non_inherit_ie[1] > 1) {
            qdf_mem_copy(curr_ie_pool, non_inherit_ie,
                    non_inherit_ie[1] + ie_header_len);
            curr_ie_pool += non_inherit_ie[1] + ie_header_len;
            (*profile_len) += non_inherit_ie[1] + ie_header_len;
        }
    }

    return 0;
}

static int ieee80211_mbss_build_prb_profile(struct ieee80211_node *ni,
                                            struct ieee80211_mbss_non_tx_profile_sub_ie *vap_profile,
                                            uint16_t *profile_len,
                                            uint8_t *min_elems_len, uint8_t *curr_ie_pool,
                                            uint8_t *iebuf, int32_t *available_prb_optional_ie_space,
                                            void *optie)
{
    uint8_t *non_inherit_ie = NULL, *nie = NULL, *nie_end = NULL;
    uint8_t *saved_iebuf = NULL;
    uint8_t bssid_idx_elm_offset = 0;
    const int ie_header_len = sizeof(struct ieee80211_ie_header);
    struct ieee80211_rateset *rs_op = NULL;
    struct ieee80211_beacon_offsets *po = NULL;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211vap *txvap = NULL;
    struct ol_ath_vap_net80211 *avn = NULL;

    txvap = ic->ic_mbss.transmit_vap;
    if (!txvap) {
        mbss_err("TxVAP is NULL");
        return -EINVAL;
    }

    avn = OL_ATH_VAP_NET80211(txvap);
    po = &(avn->av_prb_rsp_offsets);
    saved_iebuf = iebuf;

    /* Fill length and list length of Non-inheritane IE after population */
    if (ic->ic_mbss.non_inherit_enable) {
        non_inherit_ie = nie = vap->iv_mbss.non_tx_pfl_ie_pool->data + IEEE80211_NTX_PFL_NIE_OFFSET;
        nie_end = nie + IEEE80211_NTX_PFL_IE_POOL_NON_INHERIT_IE_SIZE;
        *nie++ = IEEE80211_ELEMID_EXTN;
        *nie++ = 1;
        *nie++ = IEEE80211_ELEMID_EXT_NON_INHERITANCE;
        nie++;
    }

    /* ---------- Mandatory elements ---------- */
    /* Capability, SSID, and MBSSID index elements */
    qdf_mem_copy(curr_ie_pool, (uint8_t *) vap_profile + ie_header_len,
            (*min_elems_len)-ie_header_len);

    bssid_idx_elm_offset = (3 * ie_header_len) +
        vap_profile->cap_elem.hdr.length +
        vap_profile->ssid_elem.hdr.length;

    /* DTIM period and count are not part of probe response,
     * adjust the BSSID index length field.
     */
    *(curr_ie_pool + bssid_idx_elm_offset - 1) -= 2;

    /* In hidden SSID case, SSID field needs to be filled in a probe
       response frame while responding to a unicast request */
    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) &&
            ic->ic_mbss.prb_req_ssid_match_vap) {

        if (ic->ic_mbss.prb_req_ssid_match_vap->iv_unit == vap->iv_unit) {
            if (*min_elems_len > 3) {

                uint8_t temp[3] = {0};
                uint8_t *ssid_offset = NULL;

                /* copy out 3 bytes including IE header and length fields of
                 * bssid index element that were copied from cache entry
                 */
                qdf_mem_copy(temp,
                        curr_ie_pool + (*min_elems_len - ie_header_len) - 3, 3);
                ssid_offset =
                    curr_ie_pool +
                    sizeof(struct ieee80211_mbss_ie_capability)
                    + ie_header_len;
                qdf_mem_copy(ssid_offset, ni->ni_essid, ni->ni_esslen);

                /* Copy back 3 bytes including IE header and BSSIS Index
                 * element to curr_ie_pool
                 */
                qdf_mem_copy(ssid_offset + ni->ni_esslen, temp, 3);

                (*min_elems_len) += ni->ni_esslen;
                *(ssid_offset - 1) = ni->ni_esslen;
            }
        }
    } /*IEEE80211_VAP_IS_HIDESSID_ENABLED */

    curr_ie_pool += (*min_elems_len) - ie_header_len;
    (*profile_len) += (*min_elems_len) - ie_header_len;

    ic->ic_mbss.ema_ap_available_prb_non_tx_space -= (*min_elems_len - ie_header_len);
    if (ic->ic_mbss.ema_ap_available_prb_non_tx_space < 0) {
        return -ENOMEM;
    }

    /* ---------- Optional elements ---------- */
    /* Supported Rates and BSS Membership Selectors */
    rs_op = &(vap->iv_op_rates[wlan_get_desired_phymode(vap)]);
    (void)ieee80211_add_rates(vap, iebuf, &vap->iv_bss->ni_rates);
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RATES, -1,
                po->bo_rates, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Power Constraint */
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        *iebuf++ = IEEE80211_ELEMID_PWRCNSTR;
        *iebuf++ = 1;
        *iebuf++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_PWRCNSTR, -1,
                po->bo_pwrcnstr, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Quiet */
    (void)ieee80211_add_quiet(vap, ic, iebuf);
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QUIET, -1,
                po->bo_quiet, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* TPC Report */
    if ((ieee80211_ic_doth_is_set(ic) &&
                ieee80211_vap_doth_is_set(vap)) ||
            ieee80211_vap_rrm_is_set(vap)) {
        (void)ieee80211_add_tpc_ie(iebuf, vap, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_TPCREP, -1,
                po->bo_tpcreport, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Extended Supported Rates and BSS Membership Selectors */
    (void)ieee80211_add_xrates(vap, iebuf, &vap->iv_bss->ni_rates);
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_XRATES, -1,
                po->bo_xrates, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* RSN */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_RSN, -1,
                po->bo_rsn, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* QBSS Load */
    if (ieee80211_vap_qbssload_is_set(vap)) {
        (void)ieee80211_add_qbssload_ie(vap, iebuf, ni);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_QBSS_LOAD, -1,
                    po->bo_qbssload, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                    &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    } else {
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QBSS_LOAD, -1,
                    po->bo_qbssload, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                    &nie, &nie_end, saved_iebuf, &iebuf, optie,
                    available_prb_optional_ie_space, profile_len))
            return -ENOMEM;
    }

    /* EDCA Parameter Set */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EDCA, -1,
                po->bo_edca, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Measurement Pilot Transmissions */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESUREMENT_PILOT_TX, -1,
                po->bo_msmt_pilot_tx, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* RM Enabled Capabilities */
    (void)ieee80211_add_rrm_cap_ie(iebuf, ni);
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RRM, -1,
                po->bo_rrm, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* AP Channel Report */
    if (vap->ap_chan_rpt_enable) {
        (void)ieee80211_add_ap_chan_rpt_ie(iebuf, vap);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_AP_CHAN_RPT, -1,
                po->bo_ap_chan_rpt, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* BSS Average Access Delay */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BSS_AVG_ACCESS_DELAY, -1,
                po->bo_bss_avg_delay, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Antenna */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_ANTENNA, -1,
                po->bo_antenna, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* BSS Available Admission Capacity */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BSS_ADMISSION_CAP, -1,
                po->bo_bss_adm_cap, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

#if !ATH_SUPPORT_WAPI
    /* BSS AC Access Delay */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BSS_AC_ACCESS_DELAY, -1,
                po->bo_bss_ac_acc_delay, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;
#endif /* !ATH_SUPPORT_WAPI */

    /* Mobility Domain */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MOBILITY_DOMAIN, -1,
                po->bo_mob_domain, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* DSE Registered Location */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_DSE_REG_LOCATION, -1,
                po->bo_dse_reg_loc, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    if (ieee80211_vap_wme_is_set(vap) &&
            (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
             IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
             IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
            ieee80211vap_htallowed(vap)) {
        /* 20/40 BSS Coexistence */
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_2040_COEXT, -1,
                    po->bo_2040_coex, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                    &nie, &nie_end, saved_iebuf, &iebuf, optie,
                    available_prb_optional_ie_space, profile_len))
            return -ENOMEM;

        /* Overlapping BSS Scan Parameters */
        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE))
            (void)ieee80211_add_obss_scan(iebuf, ni);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_OBSS_SCAN, -1,
                    po->bo_obss_scan, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                    &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    }

    /* Extended Capabilities */
    (void)ieee80211_add_extcap(iebuf, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_XCAPS, -1,
                po->bo_extcap, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* QoS Traffic Capability */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QOS_TRAFFIC_CAP, -1,
                po->bo_qos_traffic, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Channel Usage */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_CHANNEL_USAGE, -1,
                po->bo_chan_usage, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Time Advertisement */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TIME_ADVERTISEMENT, -1,
                po->bo_time_adv, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Time Zone */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TIME_ZONE, -1,
                po->bo_time_zone, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Interworking (Hotspot 2.0) */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_INTERWORKING, -1,
                po->bo_interworking, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Advertisement Protocol (Hotspot 2.0) */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_ADVERTISEMENT_PROTO, -1,
                po->bo_adv_proto, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Roaming Consortium (Hotspot 2.0) */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_ROAMING_CONSORTIUM, -1,
                po->bo_roam_consortium, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Emergency Alert Identifier */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EMERGENCY_ALERT_ID, -1,
                po->bo_emergency_id, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh ID */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_ID, -1,
                po->bo_mesh_id, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh Configuration */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_CONFIG, -1,
                po->bo_mesh_conf, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh Awake window */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_AWAKE_WINDOW, -1,
                po->bo_mesh_awake_win, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Beacon Timing */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_BEACON_TIMING, -1,
                po->bo_beacon_time, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* MCCAOP Advertisement Overview */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MCCAOP_ADV_OVERVIEW, -1,
                po->bo_mccaop_adv_ov, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* MCCAOP Advertisement */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MCCAOP_ADV, -1,
                po->bo_mccaop_adv, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Mesh Channel Switch Parameters */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MESH_CHANSWITCH_PARAM, -1,
                po->bo_mesh_cs_param, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* QMF Policy */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QMF_POLICY, -1,
                po->bo_qmf_policy, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* QLoad Report */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QLOAD_REPORT, -1,
                po->bo_qload_rpt, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Multi-band */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MULTIBAND, -1,
                po->bo_multiband, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* DMG Capabilities */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_DMG_CAP, -1,
                po->bo_dmg_cap, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* DMG Operation */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_DMG_OPERATION, -1,
                po->bo_dmg_op, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Multiple MAC Sublayers */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MULTIPLE_MAC_SUB, -1,
                po->bo_mul_mac_sub, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Antenna Sector ID Pattern */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_ANTENNA_SECT_ID_PAT, -1,
                po->bo_ant_sec_id, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    if (ieee80211_vap_wme_is_set(vap) &&
            (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) &&
            (IEEE80211_IS_CHAN_11AX(ic->ic_curchan) ||
             IEEE80211_IS_CHAN_11AC(ic->ic_curchan) ||
             IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
            ieee80211vap_vhtallowed(vap)){

        /* Extended BSS Load */
        if (ieee80211_vap_ext_bssload_is_set(vap))
            (void)ieee80211_add_ext_bssload_ie(vap, iebuf, ni);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXT_BSS_LOAD, -1,
                po->bo_ext_bssload, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* Quiet Channel */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_QUIET_CHANNEL, -1,
                po->bo_quiet_chan, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Operating Mode Notification */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_OP_MODE_NOTIFY, -1,
                po->bo_opt_mode_note, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* TVHT Operation */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TVHT_OP, -1,
                po->bo_tvht, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

#if QCN_ESP_IE
    /* Estimated Service Parameters */
    if(ic->ic_esp_periodicity){
        uint16_t esp_ie_len = 0;
        (void)ieee80211_add_esp_info_ie(iebuf, ic, &esp_ie_len);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_ESP_ELEMID_EXTENSION, po->bo_esp_ie, available_prb_optional_ie_space,
                &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;
#endif /* QCN_ESP_IE */

    /* Relay Capabilities */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_RELAY_CAP, -1,
                po->bo_relay_cap, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Common Advertisement Group (CAG) Number */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_CAG_NUMBER, -1,
                po->bo_cag_num, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* FILS Indication */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_FILS_INDICATION, -1,
                po->bo_fils_ind, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* AP-CSN */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_AP_CSN, -1,
                po->bo_ap_csn, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Differentiated Initial Link Setup */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_DIFF_INIT_LNK_SETUP, -1,
                po->bo_diff_init_lnk, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* RPS */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_RPS, -1,
                po->bo_rps, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Page Slice */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_PAGE_SLICE, -1,
                po->bo_page_slice, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Change Sequence */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_CHANGE_SEQ, -1,
                po->bo_chan_seq, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* TSF Timer Accuracy */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TSF_TIMER_ACC, -1,
                po->bo_tsf_timer_acc, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* S1G Relay Discovery */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_S1G_RELAY_DISCOVREY, -1,
                po->bo_s1g_relay_disc, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* S1G Capabilities */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_S1G_CAP, -1,
                po->bo_s1g_cap, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* S1G Operation */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_S1G_OP, -1,
                po->bo_s1g_op, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* MAD */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_MAD, -1,
                po->bo_mad, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Short Beacon Interval */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_SHORT_BEACON_INTVAL, -1,
                po->bo_short_bcn_int, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* S1G Open-Loop Link Margin Index */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_S1G_OPENLOOP_LINK_MARGIN, -1,
                po->bo_s1g_openloop_idx, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* S1G Relay element */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_S1G_RELAY, -1,
                po->bo_s1g_relay, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* CDMG Capaiblities */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXT_CDMG_CAP, -1,
                po->bo_cdmg_cap, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* Extended Cluster Report */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_EXTENDED_CLUSTER_RPT, po->bo_ext_cluster_rpt,
                IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool, &nie, &nie_end,
                saved_iebuf, &iebuf, optie, available_prb_optional_ie_space,
                profile_len))
        return -ENOMEM;

    /* CMMG Capabilities  */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_CMMG_CAP, po->bo_cmmg_cap,
                IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool, &nie, &nie_end,
                saved_iebuf, &iebuf, optie, available_prb_optional_ie_space,
                profile_len))
        return -ENOMEM;

    /* CMMG Operation */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_CMMG_OP, po->bo_cmmg_op,
                IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool, &nie, &nie_end,
                saved_iebuf, &iebuf, optie, available_prb_optional_ie_space,
                profile_len))
        return -ENOMEM;

    /* Service Hint */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_SERVICE_HINT, po->bo_service_hint,
                IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool, &nie, &nie_end,
                saved_iebuf, &iebuf, optie, available_prb_optional_ie_space,
                profile_len))
        return -ENOMEM;

    /* Service Hash */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_SERVICE_HASH, po->bo_service_hash,
                IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool, &nie, &nie_end,
                saved_iebuf, &iebuf, optie, available_prb_optional_ie_space,
                profile_len))
        return -ENOMEM;

    /* TWT */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_TWT, -1,
                po->bo_twt, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

#if ATH_SUPPORT_UORA
    /* UORA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_uora_is_enabled(vap)) {
        (void)ieee80211_add_uora_param(iebuf, vap->iv_ocw_range);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_UORA_PARAM, po->bo_uora_param, available_prb_optional_ie_space,
                &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;
#endif /* ATH_SUPPORT_UORA */

    /* MU EDCA Parameter Set */
    if(ieee80211_vap_wme_is_set(vap) &&
            ieee80211vap_heallowed(vap) &&
            IEEE80211_IS_CHAN_11AX(ic->ic_curchan) &&
            ieee80211vap_muedca_is_enabled(vap)) {
        (void)ieee80211_add_muedca_param(iebuf, &vap->iv_muedcastate);
    }
    if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_MUEDCA, po->bo_muedca, available_prb_optional_ie_space,
                &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
        return -ENOMEM;

    /* ESS Report */
    if (vap->iv_planned_ess) {
        (void)ieee80211_add_ess_rpt_ie(iebuf, vap);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_EXTN,
                    IEEE80211_ELEMID_EXT_ESS_REPORT, po->bo_ess_rpt, available_prb_optional_ie_space,
                    &curr_ie_pool, saved_iebuf, &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    } else {
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                    IEEE80211_ELEMID_EXT_ESS_REPORT, po->bo_ess_rpt,
                    IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool, &nie,
                    &nie_end, saved_iebuf, &iebuf, optie,
                    available_prb_optional_ie_space, profile_len))
            return -ENOMEM;
    }

    /* NDP Feedback Report Parameter Set */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_NDP_FEEDBACK_REPORT_PARAM,
                po->bo_ndp_rpt_param, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* HE BSS Load */
    if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_EXTN,
                IEEE80211_ELEMID_EXT_HE_BSS_LOAD, po->bo_he_bss_load,
                IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                &nie, &nie_end, saved_iebuf, &iebuf, optie,
                available_prb_optional_ie_space, profile_len))
        return -ENOMEM;

    /* RSN XE */
    if (vap->iv_rsnx_override) {
        (void)ieee80211_rsnx_override(iebuf, vap);
        if (ieee80211_mbss_check_and_add_ie(ic, IEEE80211_FRAME_TYPE_PROBERESP, IEEE80211_ELEMID_RSNX, -1,
                    po->bo_rsnx, available_prb_optional_ie_space, &curr_ie_pool, saved_iebuf,
                    &iebuf, &nie, &nie_end, profile_len))
            return -ENOMEM;
    } else {
        if (ieee80211_add_ies_from_appie_buffer(vap, IEEE80211_ELEMID_RSNX, -1,
                    po->bo_rsnx, IEEE80211_FRAME_TYPE_PROBERESP, &curr_ie_pool,
                    &nie, &nie_end, saved_iebuf, &iebuf, optie,
                    available_prb_optional_ie_space, profile_len))
            return -ENOMEM;
    }

    /* Note: WAPI in the context of EMA is unknown from the spec */

    /* Copy Non-inheritance IE to the buffer */
    if (ic->ic_mbss.non_inherit_enable) {
        non_inherit_ie[3] = nie - (non_inherit_ie + 4);
        *nie = (non_inherit_ie + IEEE80211_NTX_PFL_IE_POOL_NON_INHERIT_IE_SIZE) - nie_end;
        non_inherit_ie[1] += non_inherit_ie[3] + (*nie);

        /* Add 2B to len of non-inheritance IE to account for len fields in the
         * ElemID list and ExtnID list
         */
        if (non_inherit_ie[3] != 0 || (*nie) != 0)
            non_inherit_ie[1] += 2;

        qdf_mem_move(nie+1, nie_end, *nie);
        if (non_inherit_ie[1] > 1) {
            qdf_mem_copy(curr_ie_pool, non_inherit_ie,
                    non_inherit_ie[1] + ie_header_len);
            curr_ie_pool += non_inherit_ie[1] + ie_header_len;
            (*profile_len) += non_inherit_ie[1] + ie_header_len;
        }
    }

    return 0;
}
#endif

/*
 * Add a profile to 11ax MBSSID IE,
 * if EMA Ext is enabled
 */
static uint8_t *
ieee80211_mbss_add_profile_ema_ext(uint8_t *frm,
                                   struct ieee80211_mbss_ie_cache_node *node,
                                   struct ieee80211com *ic, uint16_t offset,
                                   uint8_t subtype, void *optie)
{
#if QCA_SUPPORT_EMA_EXT
    struct ieee80211_mbss_non_tx_profile_sub_ie *vap_profile;
    struct ieee80211_mbss_ie *mb;
    struct wlan_objmgr_psoc *psoc;
    struct ieee80211_node *ni;
    uint8_t iebuf[IEEE80211_MAX_IE_LEN];
    uint8_t *ie_len_pos;   /* points to the length field of mbss-ie */
    uint8_t *profile_len_pos; /* points to the length field of sub-elem ie */
    uint8_t bssid_idx_elm_offset; /* offset to bss-idx element in non-tx profile */
    uint8_t dtim_count_offset; /* offset to dtim-count subfield in non-tx profile */
    uint16_t vendor_ies_len;
    uint16_t profile_len = 0;   /* length of non-tx profile */
    uint8_t min_elems_len = 0; /* length of mandatory elements in non-tx profile */
    const int ie_header_len = sizeof(struct ieee80211_ie_header);
    struct ieee80211vap *vap = NULL;
    struct wlan_objmgr_vdev *vdev = NULL;
    uint8_t *curr_ie_pool = NULL;
    uint8_t *ntx_pf_backup = NULL, *ntx_pf_buffer = NULL, *non_inherit_ie = NULL;
    uint16_t nie_length = 0;
    uint8_t *ret = NULL;
    int32_t available_vendor_ie_space = 0,
            available_optional_ie_space = 0;
    int status = 0;

    if (!frm) {
        mbss_err("frm is NULL");
        ret = NULL;
        goto exit;
    }

    if (*(uint8_t *)node != IEEE80211_MBSSID_SUB_ELEMID) {
        mbss_err("first byte of node doesn't contain VAP sub-element ID");
        ret = NULL;
        goto exit;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc,
                            node->vdev_id, WLAN_MISC_ID);
    if (vdev == NULL) {
        mbss_err("vdev object is NULL for vdev id:%d", node->vdev_id);
        ret = NULL;
        goto exit;
    }

    vap = wlan_vdev_mlme_get_ext_hdl(vdev);
    if (!vap) {
        mbss_err("vap is NULL");
        ret = NULL;
        goto exit;
    }

    ni = vap->iv_bss;
    if (!ni) {
        mbss_err("ni is NULL");
        ret = NULL;
        goto exit;
    }

    if (!vap->iv_mbss.non_tx_pfl_ie_pool) {
        mbss_err("NonTx Profile IE Pool is NULL");
        ret = NULL;
        goto exit;
    }

    if (subtype == IEEE80211_FRAME_TYPE_BEACON)
        mbss_debug(":> frm:%pK", frm);

    /* Get the starting addresses of buffers from address offsets */
    ntx_pf_backup = vap->iv_mbss.non_tx_pfl_ie_pool->data + IEEE80211_NTX_PFL_BACKUP_OFFSET;
    ntx_pf_buffer = vap->iv_mbss.non_tx_pfl_ie_pool->data + IEEE80211_NTX_PFL_BUFFER_OFFSET;
    if (ic->ic_mbss.non_inherit_enable)
        non_inherit_ie = vap->iv_mbss.non_tx_pfl_ie_pool->data + IEEE80211_NTX_PFL_NIE_OFFSET;

    /* Vap profile in cache */
    vap_profile = &node->non_tx_profile.ntx_pf;

    min_elems_len += ie_header_len;
    switch (subtype) {
    case IEEE80211_FRAME_TYPE_BEACON:
        min_elems_len += vap_profile->sub_elem.length;
        break;
    case IEEE80211_FRAME_TYPE_PROBERESP:
        /*DTIM period and count are not included in probe response,*/
        /*so decrement length by 2 */
        min_elems_len += (vap_profile->sub_elem.length - 2);
        break;
    default:
        mbss_info("Invalid subtype %d", subtype);
        ret = NULL;
        goto exit;
    }

    available_vendor_ie_space = vap->iv_mbss.total_vendor_ie_size;
    available_optional_ie_space = vap->iv_mbss.total_optional_ie_size;

    curr_ie_pool = ntx_pf_buffer;
    /* ---------- Vendor elements ---------- */
    vendor_ies_len = ieee80211_mbss_add_vendor_ies(ni, subtype, curr_ie_pool, iebuf);
    qdf_mem_zero(iebuf, IEEE80211_MAX_IE_LEN);

    /* If not enough vendor IE space is available, all vendor IEs are to be inherited */
    if (ieee80211_mbss_is_vendor_ie_size_valid(vap, subtype,
                &available_vendor_ie_space, &vendor_ies_len, curr_ie_pool)) {
        curr_ie_pool += vendor_ies_len;
        profile_len += vendor_ies_len;
    }

    if (vendor_ies_len && subtype == IEEE80211_FRAME_TYPE_PROBERESP &&
            (vendor_ies_len > ic->ic_mbss.ema_ap_available_prb_non_tx_space)) {
        curr_ie_pool = ntx_pf_buffer;
        qdf_mem_zero(ntx_pf_buffer, vendor_ies_len);
        profile_len -= vendor_ies_len;
        vendor_ies_len = 0;
    } else {
        ((struct ieee80211com *)ic)->ic_mbss.ema_ap_available_prb_non_tx_space -= ((int)vendor_ies_len);
    }

    /* Build the local buffer and non-inheritance IE as applicable */
    if (subtype == IEEE80211_FRAME_TYPE_BEACON)
        status = ieee80211_mbss_build_bcn_profile(ni, vap_profile, &profile_len,
                &min_elems_len, curr_ie_pool, iebuf, &available_optional_ie_space);
    else
        status = ieee80211_mbss_build_prb_profile(ni, vap_profile, &profile_len,
                &min_elems_len, curr_ie_pool, iebuf, &available_optional_ie_space, optie);

    if (status == -ENOMEM) {
        if (subtype == IEEE80211_FRAME_TYPE_BEACON) {
            if (!vap->iv_mbss.backup_length) {
                mbss_debug("Max Beacon frame size reached; cannot add profile for vap %d",
                        vap->iv_unit);
                available_vendor_ie_space = available_optional_ie_space = 0;
                vap->iv_mbss.ie_overflow = true;
                vap->iv_mbss.ie_overflow_stats++;
                ret = NULL;
                goto exit;
            } else {
                uint16_t backup_optional_ie_size = 0;

                /* Restore backup */
                qdf_mem_zero(ntx_pf_buffer, profile_len);

                profile_len = vap->iv_mbss.backup_length;
                qdf_mem_copy(ntx_pf_buffer, ntx_pf_backup, profile_len);
                curr_ie_pool = ntx_pf_buffer;

                /* Update vendor IE len and non-inheritance IE from backup */
                vendor_ies_len = ieee80211_get_vendore_ies_len_from_backup(ntx_pf_buffer, profile_len);
                min_elems_len = ieee80211_get_mandatory_ies_len_from_backup(ntx_pf_buffer, vendor_ies_len, profile_len);
                non_inherit_ie = ieee80211_get_non_inherit_ie_from_backup(ntx_pf_buffer, profile_len);
                if (!ic->ic_mbss.non_inherit_enable && non_inherit_ie) {
                    profile_len -= (non_inherit_ie[1] + ie_header_len);
                    non_inherit_ie = NULL;
                }

                /* If backup has vendor IEs, check against current size limit,
                 * else ignore and maintain vendor IE overflow state like in
                 * backup
                 */
                if (vendor_ies_len) {
                    if (ieee80211_mbss_is_vendor_ie_size_valid(vap, subtype,
                                &available_vendor_ie_space, &vendor_ies_len, curr_ie_pool)) {
                        curr_ie_pool += vendor_ies_len;
                    } else {
                        qdf_mem_move(curr_ie_pool, curr_ie_pool + vendor_ies_len,
                                vendor_ies_len);
                        profile_len -= vendor_ies_len;
                    }
                } else {
                    available_vendor_ie_space = 0;
                }

                /* Calculate optional IE size from backup */
                backup_optional_ie_size =
                    profile_len - (min_elems_len + vendor_ies_len);
                if (non_inherit_ie)
                    backup_optional_ie_size -= (non_inherit_ie[1] + ie_header_len);

                if (backup_optional_ie_size > vap->iv_mbss.total_optional_ie_size) {
                    available_vendor_ie_space = available_optional_ie_space = 0;
                    vap->iv_mbss.ie_overflow = true;
                    vap->iv_mbss.ie_overflow_stats++;
                    ret = NULL;
                    goto exit;
                } else {
                    available_optional_ie_space =
                        vap->iv_mbss.total_optional_ie_size - backup_optional_ie_size;
                }

                if (min_elems_len)
                    min_elems_len += ie_header_len;

                mbss_debug("Max Beacon frame size reached; but backup found. Restored for vap %d",
                        vap->iv_unit);
                vap->iv_mbss.ntx_pfl_rollback_stats++;

                bssid_idx_elm_offset = (2 * ie_header_len) +
                    vap_profile->cap_elem.hdr.length +
                    vap_profile->ssid_elem.hdr.length;

                /* 'bssid_idx_elm_offset + ie_header_len + 2' will take us to
                 * the 1 octet slot with 'dtim_count' as length of subfield
                 * 'bss_idx' and 'dtim_period' is each 1 octet
                 */
                dtim_count_offset = bssid_idx_elm_offset + ie_header_len + 2;

                /* Update the particular node's dtim_count to value 0 to
                 * meet the fw requiremnt that a new profile added should
                 * have value 255 in the dtim_count field in the template
                 * sent from host to fw. If the profile exists already
                 * then the corresponding value should be 0.
                 *
                 * Mark always 0 here as the vap is already up
                 */
                *(ntx_pf_buffer + vendor_ies_len + dtim_count_offset) = 0;
                available_vendor_ie_space =
                        vap->iv_mbss.total_vendor_ie_size - vendor_ies_len;
            }
        } else {
            mbss_debug("Max Probe response frame size reached; ignoring the profile for vap=%d",
                    vap->iv_unit);

            /* Reset available space variables to zero, only if err is returned
             * due to per-profile size overflow. Ignore for probe response max
             * nonTx profiles space
             */
            if (ic->ic_mbss.ema_ap_available_prb_non_tx_space >= 0) {
                available_vendor_ie_space = available_optional_ie_space = 0;
            }

            vap->iv_mbss.ie_overflow = true;
            ret = NULL;
            goto exit;
        }
    } else if (status == -EINVAL) {
        ret = NULL;
        goto exit;
    }

    if (!non_inherit_ie || (non_inherit_ie && non_inherit_ie[1] == 1))
        nie_length = 0;
    else
        nie_length = non_inherit_ie[1] + ie_header_len;

    if (!ic->ic_mbss.mbss_split_profile_enabled &&
            profile_len > IEEE80211_SPLIT_PFL_MAX_NTX_PFL_SIZE) {
        mbss_debug("Max %s frame size reached; cannot fit the profile in one MBSSID IE for vap %d",
                (subtype == IEEE80211_FRAME_TYPE_BEACON) ? "Beacon" : "Probe response",
                vap->iv_unit);
        mbss_debug(":<");

        available_vendor_ie_space = available_optional_ie_space = 0;
        vap->iv_mbss.ie_overflow = true;
        if (subtype == IEEE80211_FRAME_TYPE_BEACON)
            vap->iv_mbss.ie_overflow_stats++;
        ret = NULL;
        goto exit;
    }

    if (subtype == IEEE80211_FRAME_TYPE_BEACON) {
        bssid_idx_elm_offset = (3 * ie_header_len) +
            vap_profile->cap_elem.hdr.length +
            vap_profile->ssid_elem.hdr.length;
        dtim_count_offset = bssid_idx_elm_offset + ie_header_len + 2;

        mbss_debug("vdev_id: %d dtim_count: %d", vap->iv_unit,
                *((uint8_t *)vap_profile + dtim_count_offset));
    }

    mb = (struct ieee80211_mbss_ie *) frm;
    if (offset == 0) {
        /* Add the first MBSSID IE */
        IEEE80211_ADD_MBSS_IE_TAG(ic, mb);
    } else {
        /* Skip past any MBSSID IEs */
        while (*(frm + ie_header_len + mb->header.length)
                ==  IEEE80211_ELEMID_MBSSID) {
            frm += ie_header_len + mb->header.length;
            mb = (struct ieee80211_mbss_ie *) frm;
        }
    }

    /* frm points to final MBSS IE, so increment by length bytes */
    frm += ie_header_len + mb->header.length;

    if (!ic->ic_mbss.mbss_split_profile_enabled) {
        /* If profile cannot fit into the current MBSSID IE, create a new one */
        if ((IEEE80211_MAX_IE_LEN - (mb->header.length + ie_header_len)) < profile_len) {
            mb = (struct ieee80211_mbss_ie *) frm;
            IEEE80211_ADD_MBSS_IE_TAG(ic, mb);
            frm += sizeof(struct ieee80211_mbss_ie);
        }
    } else {
        /* If there is no free space to add at least the first IE in
         * Non-Tx profile (Capability), create a new MBSSID IE.
         */
        if ((IEEE80211_MAX_IE_LEN - (mb->header.length + ie_header_len)) < (vap_profile->cap_elem.hdr.length + (2 * ie_header_len))) {
            mb = (struct ieee80211_mbss_ie *) frm;
            IEEE80211_ADD_MBSS_IE_TAG(ic, mb);
            frm += sizeof(struct ieee80211_mbss_ie);
        }
    }

    ie_len_pos = &mb->header.length;

    /* Add Non-Tx profile ID and length */
    IEEE80211_ADD_NTX_PROFILE_TAG(frm, profile_len_pos);
    *ie_len_pos += ie_header_len;

    /* Add mandatory IEs */
    ieee80211_add_to_mbss_ie(vap, &mb, &frm, ntx_pf_buffer + vendor_ies_len,
            min_elems_len - ie_header_len, &ie_len_pos, &profile_len_pos);

    /* Add optional IEs */
    ieee80211_add_to_mbss_ie(vap, &mb, &frm,
            ntx_pf_buffer + vendor_ies_len + min_elems_len - ie_header_len,
            profile_len - (nie_length + vendor_ies_len + min_elems_len - ie_header_len),
            &ie_len_pos, &profile_len_pos);

    /* Add vendor IEs */
    ieee80211_add_to_mbss_ie(vap, &mb, &frm, ntx_pf_buffer, vendor_ies_len,
            &ie_len_pos, &profile_len_pos);

    /* Add non-inheritance IE */
    if (nie_length > 0) {
        ieee80211_add_to_mbss_ie(vap, &mb, &frm,
                ntx_pf_buffer + profile_len - nie_length, nie_length,
                &ie_len_pos, &profile_len_pos);
    }
    ret = frm;

    /* Update backup with the new profile */
    if (subtype == IEEE80211_FRAME_TYPE_BEACON) {
        qdf_mem_copy(ntx_pf_backup, ntx_pf_buffer, profile_len);
        vap->iv_mbss.backup_length = profile_len;
    }
    qdf_mem_zero(ntx_pf_buffer, profile_len);

    if (non_inherit_ie)
        qdf_mem_zero(non_inherit_ie, IEEE80211_NTX_PFL_IE_POOL_NON_INHERIT_IE_SIZE);

exit:
    if (vap) {
        if (vap->iv_mbss.available_vendor_ie_space != available_vendor_ie_space)
            vap->iv_mbss.available_vendor_ie_space = available_vendor_ie_space;

        if (subtype == IEEE80211_FRAME_TYPE_BEACON &&
                vap->iv_mbss.available_bcn_optional_ie_space != available_optional_ie_space)
            vap->iv_mbss.available_bcn_optional_ie_space = available_optional_ie_space;

        if (subtype == IEEE80211_FRAME_TYPE_PROBERESP &&
                vap->iv_mbss.available_prb_optional_ie_space != available_optional_ie_space)
            vap->iv_mbss.available_prb_optional_ie_space = available_optional_ie_space;

    }

    if (vdev)
        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);

    if (subtype == IEEE80211_FRAME_TYPE_BEACON)
        mbss_debug(":<");

    return ret;
#else
    return frm;
#endif
}

static uint8_t ieee80211_retrieve_node_idx(
        struct ieee80211com *ic,
        struct ieee80211_mbss_ie_cache_node *node)
{
    struct wlan_objmgr_psoc *psoc;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE);
    uint8_t node_idx = scn->soc->ema_ap_num_max_vaps;
    uint64_t offset;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc) {
        goto OUT;
    }

    if (is_mbssid_enabled && node) {
        size_t mbss_cache_size;
        mbss_cache_size = sizeof(struct ieee80211_mbss_ie_cache_node) *
                                    (scn->soc->ema_ap_num_max_vaps);

        if (((uint8_t *)node >=
                    (uint8_t *)ic->ic_mbss.mbss_cache)
            &&
            ((uint8_t *)node <
             (uint8_t *)ic->ic_mbss.mbss_cache + mbss_cache_size)) {
            offset = (uint8_t *) node - (uint8_t *) ic->ic_mbss.mbss_cache;

            if (offset) {
                node_idx = qdf_do_div(offset,
                            sizeof(struct ieee80211_mbss_ie_cache_node));
            } else {
                node_idx = 0;
            }
        }
    }

OUT:
    return node_idx;
}

uint32_t ieee80211_add_mbss_ie(uint8_t *frm, struct ieee80211_node *ni,
                               uint8_t frm_subtype, bool is_bcast_req, void *optie)
{
    struct ieee80211vap *vap;
    struct ieee80211com *ic;
    struct vdev_mlme_obj *vdev_mlme;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_vdev *vdev;
    struct ieee80211_mbss_ie_cache_node *node = NULL;
    struct ieee80211_mbss_ie_cache_node *node_tx_vap = NULL;
    struct ol_ath_softc_net80211 *scn;
    uint8_t *new;
    /* beacon position in PP set in case
     * of ema ap */
    uint8_t pos = 0, node_idx;
    uint16_t mbss_offset = 0;
    bool found = false;
    bool is_mbssid_enabled, is_actual_pos = false;
    uint32_t known_bssids, bytes_added = 0;
    uint32_t curr_bss_idx = 0;

    if (!frm || !ni) {
        mbss_err("%s is NULL", !frm ? "frm" : "ni");
        return bytes_added;
    }

    new  = frm;
    vap  = ni->ni_vap;
    ic   = vap->iv_ic;
    pdev = ic->ic_pdev_obj;
    scn  = OL_ATH_SOFTC_NET80211(ic);
    psoc = wlan_pdev_get_psoc(pdev);
    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(pdev,
                                WLAN_PDEV_F_MBSS_IE_ENABLE);
    known_bssids =  ic->ic_mbss.known_bssid_map;

    if (!is_mbssid_enabled) {
        mbss_err("MBSSIE not enabled for this pdev");
        return bytes_added;
    }

    if (!ic->ic_mbss.mbss_cache) {
        mbss_err("mbss cache is null!!!");
        goto exit;
    }

    if (!ic->ic_mbss.transmit_vap) {
        mbss_err("transmit vap is null!!!");
        goto exit;
    }

    vdev_mlme = vap->vdev_mlme;
    if (!vdev_mlme) {
        mbss_err("vdev MLME object is NULL");
        goto exit;
    }

    wlan_rnr_clear_bss_idx();

    /* Derive node_idx of the tx-vap */
    node_idx = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                            scn->soc->ema_ap_num_max_vaps);
    /* Derive tx-vap node */
    node_tx_vap = &((struct ieee80211_mbss_ie_cache_node *)
                                    ic->ic_mbss.mbss_cache)[node_idx];

    if (frm_subtype == IEEE80211_FRAME_TYPE_BEACON) {
        mbss_debug("Add mabss_ie in the context of vap: %d", vap->iv_unit);
        mbss_debug("node_idx: %d", node_idx);
        /*
         * 1. Find the beacon template to use from node cache. One node
         *    exists for each non-tx VAP.
         * 2. Populate the MBSS IE with all non-tx VAP profiles from the
         *    beacon template found in step 1.
         */

        /* 1. find the beacon position in node cache */
        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            /* Derive node_idx of non-tx vap */
            node_idx = ieee80211_mbssid_get_non_tx_vap_node_idx(vap,
                       scn->soc->ema_ap_num_max_vaps);
            if (node_idx >= scn->soc->ema_ap_num_max_vaps) {
                mbss_err("Invalide node_idx %d", node_idx);
                goto exit;
            }

            mbss_debug("node_idx: %d", node_idx);
            /* get node for current vap in cache */
            node = &((struct ieee80211_mbss_ie_cache_node *)
                           ic->ic_mbss.mbss_cache)[node_idx];
            pos = node->pos;
            is_actual_pos = true;
            mbss_debug("called for Non-TX VAP id %d, node->pos:%d", vap->iv_unit,
                                                                   node->pos);
        } else {
            mbss_debug("called for TX VAP");

            /* for a transmitting VAP, go through node cache for each
             * beacon position and find the first non-tx VAP in UP state.
             */
            node = (struct ieee80211_mbss_ie_cache_node *)
                                        ic->ic_mbss.mbss_cache;
            node_idx = ieee80211_retrieve_node_idx(ic, node);
            while (!found && (node_idx < scn->soc->ema_ap_num_max_vaps)) {
                if (node->used) {
                    vdev = wlan_objmgr_get_vdev_by_id_from_psoc
                                (psoc, node->vdev_id, WLAN_MISC_ID);

                    if (vdev &&
                        (node->vdev_id != ic->ic_mbss.transmit_vap->iv_unit) &&
                        (wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS)) {
                        pos = node->pos;
                        found = true;
                    }

                    if (vdev) {
                        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
                    }
                }
                node++;
                node_idx = ieee80211_retrieve_node_idx(ic, node);
            } /* while */

            if (!found) {
                mbss_debug("no non-Tx vap to be added");
                goto exit;
            } else {
                mbss_debug("Called for TX VAP, found active VAP(s)"
                       " at beacon pos: %d", pos);
            }
        } /* else - NON_TRANSMIT_ENABLED */

        /* Jump to start offset in cache for VAP's beacon.
         * When EMA is disabled, mbss_offset is 0.
         */
        if (!ic->ic_mbss.mbss_offset)
            mbss_offset = 0;
        else
            mbss_offset = ic->ic_mbss.mbss_offset[pos];

        node = (struct ieee80211_mbss_ie_cache_node *)
                (ic->ic_mbss.mbss_cache + mbss_offset);

        mbss_debug("cache_start at: %pK", ic->ic_mbss.mbss_cache + mbss_offset);
        mbss_debug("node: %pK", node);

        node_idx = ieee80211_retrieve_node_idx(ic, node);;
        mbss_debug("node_idx: %d", node_idx);

        /* 2. populate MBSS IE with VAP profiles from cache */
        while ((node_idx < scn->soc->ema_ap_num_max_vaps) &&
               (node->pos == pos)) {
            if (node->used) {
                /* If the node represents the Tx-vap skip adding it.
                 * Look for the next non-Tx vap
                 */
                if (node->vdev_id == ic->ic_mbss.transmit_vap->iv_unit) {
                    node++;
                    node_idx = ieee80211_retrieve_node_idx(ic, node);
                    continue;
                }

                mbss_debug("node_idx: %d", node_idx);
                vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc,
                                        node->vdev_id, WLAN_MISC_ID);

                if (vdev && wlan_mbss_beaconing_vdev_up(vdev)) {
                    struct ieee80211_mbss_non_tx_profile_sub_ie *vap_profile;
                    uint8_t saved_node_dtim_count = 0;
                    uint8_t dtim_count_offset;    /* offset to dtim-count subfield in non-tx profile */
                    uint8_t bssid_idx_elm_offset; /* offset to bss-idx element in non-tx profile */
                    const int ie_header_len = sizeof(struct ieee80211_ie_header);

                    mbss_debug("Adding profile for VAP %d"
                                            " to MBSS IE", node->vdev_id);

                    /* Vap profile in cache */
                    vap_profile = &node->non_tx_profile.ntx_pf;
                    bssid_idx_elm_offset = (3 * ie_header_len) +
                                            vap_profile->cap_elem.hdr.length +
                                            vap_profile->ssid_elem.hdr.length;
                    dtim_count_offset = bssid_idx_elm_offset + ie_header_len + 2;

                    if (!is_actual_pos) {
                        saved_node_dtim_count = *((uint8_t *)vap_profile + dtim_count_offset);
                        *((uint8_t *)vap_profile + dtim_count_offset) = 0;
                    }

                    if (ic->ic_mbss.ema_ext_enabled) {
                        struct ieee80211vap *ntx_vap = NULL;

                        ntx_vap = wlan_vdev_mlme_get_ext_hdl(vdev);
                        if (!ntx_vap) {
                            new = NULL;
                            goto bcn_new_check;
                        }

                        if (!ntx_vap->iv_mbss.ie_overflow) {
                            IEEE80211_NTX_PFL_IE_POOL_LOCK(ntx_vap);
                            new = ieee80211_mbss_add_profile_ema_ext(frm, node, ic,
                                    new - frm, frm_subtype, optie);
                            IEEE80211_NTX_PFL_IE_POOL_UNLOCK(ntx_vap);
                        }
                    } else {
                        new = ieee80211_mbss_add_profile(frm, node, ic,
                                new - frm, frm_subtype);
                    }

                    if (!is_actual_pos) {
                        /* Restore dtim count */
                        *((uint8_t *)vap_profile + dtim_count_offset) = saved_node_dtim_count;
                    } else {
                        if (!ic->ic_mbss.transmit_vap->iv_is_up) {
                            *((uint8_t *)vap_profile + dtim_count_offset) = 0;
                        }
                    }
bcn_new_check:
                    if (new) {
                        bytes_added = (new - frm);

                        vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(vdev);
                        if (vdev_mlme) {
                            curr_bss_idx = vdev_mlme->mgmt.mbss_11ax.profile_idx;
                            wlan_rnr_set_bss_idx(curr_bss_idx);
                        }
                    } else {
                        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
                        goto exit;
                    }
                }

                if (vdev) {
                    wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
                }
            } /* if(node->used) */

            node++;
            node_idx = ieee80211_retrieve_node_idx(ic, node);
            if (node_idx >= scn->soc->ema_ap_num_max_vaps) {
                node_idx = 0;
                node = (struct ieee80211_mbss_ie_cache_node *) (ic->ic_mbss.mbss_cache);
            }
        } /* while */

        /*   end of beacon handling case */
    } else if (frm_subtype == IEEE80211_FRAME_TYPE_PROBERESP) {

        bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(
			ic->ic_pdev_obj, WLAN_PDEV_FEXT_EMA_AP_ENABLE);
        bool is_bss_known, is_valid_in_bcast_req;
        struct ieee80211vap *ssid_match_vap =
            ic->ic_mbss.prb_req_ssid_match_vap;

        if (known_bssids)
            mbss_debug("known_bssids map: 0x%x", known_bssids);

        /* if ssid in probe request matched with a non-tx vap, that profile
         * needs to be included in MBSS IE */
        if (ssid_match_vap) {
            int32_t ic_prb_non_tx_space = ic->ic_mbss.ema_ap_available_prb_non_tx_space;

            if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(ssid_match_vap) &&
                ssid_match_vap->iv_is_up) {
                vdev_mlme = ssid_match_vap->vdev_mlme;

                /* Get node_idx for the non-tx vap */
                node_idx = ieee80211_mbssid_get_non_tx_vap_node_idx(ssid_match_vap,
                           scn->soc->ema_ap_num_max_vaps);
                if (node_idx >= scn->soc->ema_ap_num_max_vaps) {
                    mbss_err("Invalide node_idx %d", node_idx);
                    goto exit;
                }

                mbss_debug("node_idx: %d", node_idx);
                /* Retrieve non-tx vap node */
                node = (((struct ieee80211_mbss_ie_cache_node *)
                         ic->ic_mbss.mbss_cache) + node_idx);
                mbss_debug("Add profile for idx %d",
                            vdev_mlme->mgmt.mbss_11ax.profile_idx);

                if (ic->ic_mbss.ema_ext_enabled) {
                    IEEE80211_NTX_PFL_IE_POOL_LOCK(ssid_match_vap);
                    new = ieee80211_mbss_add_profile_ema_ext(frm, node, ic,
                            new - frm,
                            IEEE80211_FRAME_TYPE_PROBERESP, optie);
                    IEEE80211_NTX_PFL_IE_POOL_UNLOCK(ssid_match_vap);
                } else {
                    new = ieee80211_mbss_add_profile(frm, node, ic,
                                                     new - frm,
                                                     IEEE80211_FRAME_TYPE_PROBERESP);
                }

                if (new) {
                    bytes_added = (new - frm);
                    curr_bss_idx = vdev_mlme->mgmt.mbss_11ax.profile_idx;
                    wlan_rnr_set_bss_idx(curr_bss_idx);
                } else {
                    ic->ic_mbss.ema_ap_available_prb_non_tx_space = ic_prb_non_tx_space;
                    goto exit;
                }
            }
        } /* ssid_match_vap */

        psoc = wlan_pdev_get_psoc(pdev);
        is_bss_known = is_valid_in_bcast_req = 0;
        pos = 0;

        /* populate the MBSS IEs beginning from first beacon template */
        while (pos < ic->ic_mbss.current_pp) {
            node = (struct ieee80211_mbss_ie_cache_node *) ic->ic_mbss.mbss_cache;
            node_idx = ieee80211_retrieve_node_idx(ic, node);

            /* Pack profile grouping them as per beacon-position */
            while (node_idx < scn->soc->ema_ap_num_max_vaps) {
                if (node->used && (node->pos == pos)) {
                    /* If the node represents the Tx-vap skip adding it.
                     * Look for the next non-Tx vap
                     */
                    if (node->vdev_id == ic->ic_mbss.transmit_vap->iv_unit) {
                        node++;
                        node_idx = ieee80211_retrieve_node_idx(ic, node);
                        continue;
                    }

                    vdev = wlan_objmgr_get_vdev_by_id_from_psoc(psoc,
                                                                node->vdev_id,
                                                                WLAN_MISC_ID);
                    if (vdev) {
                        vap = wlan_vdev_mlme_get_ext_hdl(vdev);
                        if (vap && (vap != ic->ic_mbss.prb_req_ssid_match_vap)) {

                            vdev_mlme = vap->vdev_mlme;

                            /* check if STA already knows about the BSS */
                            is_bss_known = is_ema_ap_enabled &&
                                (known_bssids &
                                 (1 << vdev_mlme->mgmt.mbss_11ax.profile_idx));
                            if (is_bss_known)
                                mbss_info("bit set for profile idx %d in Known BSSID"
                                          "element, node:%pK",
                                           vdev_mlme->mgmt.mbss_11ax.profile_idx, node);

                            /* as part of handling a broadcast probe request, each non-tx
                             * vap is checked if it's eligible to be part of MBSS IE by
                             * setting a bit - mbssid_send_bcast_probe_resp. If the bit
                             * is not set, profile is not included in MBSS IE as part of
                             * probe response.
                             */
                            if (is_bcast_req &&
                                !(vap->iv_mbss.mbssid_send_bcast_probe_resp)) {
                                is_valid_in_bcast_req = 0;
                            } else {
                                is_valid_in_bcast_req = 1;
                            }

                            /* add profile now */
                            if (!is_bss_known && is_valid_in_bcast_req &&
                                wlan_mbss_beaconing_vdev_up(vdev)) {

                                int32_t ic_prb_non_tx_space = ic->ic_mbss.ema_ap_available_prb_non_tx_space;
                                uint8_t *temp;

                                mbss_debug("Add profile for idx %d, node:%pK",
                                          vdev_mlme->mgmt.mbss_11ax.profile_idx, node);
                                if (ic->ic_mbss.ema_ext_enabled) {
                                    IEEE80211_NTX_PFL_IE_POOL_LOCK(vap);
                                    temp = new;
                                    new = ieee80211_mbss_add_profile_ema_ext(frm, node, ic,
                                                                     new - frm, frm_subtype, optie);
                                    IEEE80211_NTX_PFL_IE_POOL_UNLOCK(vap);
                                } else {
                                    new = ieee80211_mbss_add_profile(frm, node, ic,
                                                                     new - frm, frm_subtype);
                                }

                                if (new) {
                                    bytes_added = (new - frm);
                                    curr_bss_idx = vdev_mlme->mgmt.mbss_11ax.profile_idx;
                                    wlan_rnr_set_bss_idx(curr_bss_idx);
                                } else {
                                    if (ic->ic_mbss.ema_ext_enabled) {
                                        if (vap->iv_mbss.ie_overflow) {
                                            vap->iv_mbss.ie_overflow = false;
                                            new = temp;
                                            ic->ic_mbss.ema_ap_available_prb_non_tx_space = ic_prb_non_tx_space;
                                        }
                                    } else {
                                        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
                                        goto exit;
                                    }
                                }
                            }
                        } /* if vap */

                        wlan_objmgr_vdev_release_ref(vdev, WLAN_MISC_ID);
                    } /* if vdev */
                } /* if node->used */
                node++;
                /* retrieve node_idx for boundary check */
                node_idx = ieee80211_retrieve_node_idx(ic, node);
            } /* while node->pos == pos*/
            pos++;
        } /* while */

    } /* frametype probe_resp */

exit:

    if (known_bssids)
        ic->ic_mbss.known_bssid_map = 0;

    ic->ic_mbss.prb_req_ssid_match_vap = NULL;

    /* return number of bytes added */
    return bytes_added;
}

#if OBSS_PD

/* The following function will only be called when:
 *      ic->ic_is_spatial_reuse_enabled = 1
 *      vap->iv_he_srctrl_non_srg_obsspd_disallowed = 1
 *      vap->iv_he_srctrl_srg_info_present = 1
 * This means the IE has already been made and only
 * the values need to be updated dynamically. Since
 * non SRG field is not present, the SRG fields must
 * be offset by the size of the non SRG field so the
 * proper fields get updated and nothing gets overwritten.
 */
static void
ieee80211_update_srg_params(struct ieee80211vap *vap, uint8_t *frm)
{
    struct ieee80211_ie_spatial_reuse *ie =
                (struct ieee80211_ie_spatial_reuse *) frm;
    int offset  =   sizeof(ie->elem_id) +
                    sizeof(ie->elem_len) +
                    sizeof(ie->ext_id) +
                    sizeof(ie->sr_ctrl);
    uint8_t *pos = frm + offset;

    *pos = vap->iv_he_srp_ie_srg_obsspd_min_offset;
    pos += sizeof(vap->iv_he_srp_ie_srg_obsspd_min_offset);

    *pos = vap->iv_he_srp_ie_srg_obsspd_max_offset;
    pos += sizeof(vap->iv_he_srp_ie_srg_obsspd_max_offset);


    OS_MEMCPY((uint32_t *)pos,
            &vap->iv_he_srp_ie_srg_bss_color_bitmap[0], sizeof(uint32_t));
    OS_MEMCPY((uint32_t *)(pos + sizeof(uint32_t)),
            &vap->iv_he_srp_ie_srg_bss_color_bitmap[1], sizeof(uint32_t));

    pos += sizeof(vap->iv_he_srp_ie_srg_bss_color_bitmap);

    OS_MEMCPY((uint32_t *)pos,
            &vap->iv_he_srp_ie_srg_partial_bssid_bitmap[0], sizeof(uint32_t));
    OS_MEMCPY((uint32_t *)(pos + sizeof(uint32_t)),
            &vap->iv_he_srp_ie_srg_partial_bssid_bitmap[1], sizeof(uint32_t));

    return;
}

/* The offset frame numbers correspond to the octect number of the associated
 * control field in the control frame.
 */
#define IEEE80211_NON_SRG_OBSS_PD_FIELD_OFFSET 4
#define IEEE80211_SRG_OBSS_PD_FIELD_OFFSET     5
#define IEEE80211_SRG_OBSS_PD_TOTAL_FIELD_SIZE \
    (sizeof(ie->srg_obss_pd_min_offset) + \
        sizeof(ie->srg_obss_pd_max_offset) + \
        sizeof(ie->srg_obss_color_bitmap) + \
        sizeof(ie->srg_obss_color_partial_bitmap))


uint8_t *
ieee80211_add_srp_ie(struct ieee80211vap *vap, uint8_t *frm)
{
    struct ieee80211_ie_spatial_reuse *ie =
                    (struct ieee80211_ie_spatial_reuse *) frm;

    ie->elem_id = IEEE80211_ELEMID_EXTN;
    ie->ext_id = IEEE80211_ELEMID_EXT_SRP;

    /* Check B0 (SRP_DISALLOWED) field in SR Control Field
     * and update the associated IE field accordingly.
     */
    ie->sr_ctrl.srp_disallow =
            vap->iv_he_srctrl_psr_disallowed ?
            !!vap->iv_he_srctrl_psr_disallowed: 0;

    /* Check B1 (NON_SRG_OBSS_PD_DISALLOWED) field in SR Control Field
     * and update the value if a user configured
     * value exists, else keep current value.
     */
    ie->sr_ctrl.non_srg_obss_pd_sr_disallowed =
            vap->iv_he_srctrl_non_srg_obsspd_disallowed ?
            !!vap->iv_he_srctrl_non_srg_obsspd_disallowed : 0;

    /* Check B3 (SRG_INFORMATION_PRESENT) field in SR Control Field
     * and update the value if a user configured
     * value exists, else keep current value.
     */
    ie->sr_ctrl.srg_information_present =
            vap->iv_he_srctrl_srg_info_present ?
            !!vap->iv_he_srctrl_srg_info_present : 0;

    /* Check B4 (SR_CTRL_VALUE15_ALLOWED) field in SR Control Field
     * and update the associated IE field accordingly.
     */
    ie->sr_ctrl.HESIGA_sp_reuse_value15_allowed =
            vap->iv_he_srctrl_sr15_allowed ?
            !!vap->iv_he_srctrl_sr15_allowed : 0;

    /* If spatial reuse updated, then ie has already been
     * initialized and therefore should not alter the length of the IE.
     */
    if (vap->iv_is_spatial_reuse_updated &&
        vap->iv_he_srctrl_non_srg_obsspd_disallowed &&
        vap->iv_he_srctrl_srg_info_present) {
        ieee80211_update_srg_params(vap, frm);
    } else {
        ie->elem_len = (sizeof(struct ieee80211_ie_spatial_reuse) -
                                                    IEEE80211_IE_HDR_LEN);
        if (ie->sr_ctrl.non_srg_obss_pd_sr_disallowed)  {
                ie->sr_ctrl.non_srg_offset_present = false;

                /* subtract the length of Non-SRG OBSS PD Max Offset */
                ie->elem_len -= 1;
        } else {
            /* If NON_SRG_OBSSPD_DISALLOWED set to false, then non_srg_obsspd
             * based transmissions are allowed. Therefore, set all control fields
             * related to non_srg_obsspd to be present.
             */
            ie->non_srg_obss_pd_max_offset = vap->iv_he_srp_ie_non_srg_obsspd_max_offset;
            ie->sr_ctrl.non_srg_offset_present = true;
        }

        if (ie->sr_ctrl.srg_information_present) {
            ie->srg_obss_pd_min_offset =
                    vap->iv_he_srp_ie_srg_obsspd_min_offset;
            ie->srg_obss_pd_max_offset =
                    vap->iv_he_srp_ie_srg_obsspd_max_offset;

            OS_MEMCPY((uint32_t *)&ie->srg_obss_color_bitmap[0],
                    &vap->iv_he_srp_ie_srg_bss_color_bitmap[0], sizeof(uint32_t));
            OS_MEMCPY((uint32_t *)&ie->srg_obss_color_bitmap[4],
                    &vap->iv_he_srp_ie_srg_bss_color_bitmap[1], sizeof(uint32_t));

            OS_MEMCPY((uint32_t *)&ie->srg_obss_color_partial_bitmap[0],
                    &vap->iv_he_srp_ie_srg_partial_bssid_bitmap[0], sizeof(uint32_t));
            OS_MEMCPY((uint32_t *)&ie->srg_obss_color_partial_bitmap[4],
                    &vap->iv_he_srp_ie_srg_partial_bssid_bitmap[1], sizeof(uint32_t));

        } else {
            /* subtract the lengths of the following fields:
             * 1. SRG OBSS PD Min Offset
             * 2. SRG OBSS PD Max Offset
             * 3. SRG BSS Color Bitmap
             * 4. SRG Partial BSSID Bitmap
             */
            ie->elem_len -= (2*8 + 2);
        }

        /* If NON_SRG_OBSSPD control field is disabled but the SRG_OBSSPD control
         * field is set to present, then the frame pointer and ie->elem_len must
         * be updated accordingly to include these fields but not the
         * NON_SRG_OBSS_PD_MAX_OFFSET field. To do this, a memcpy is done to copy
         * the SRG_OBSSPD related fields to compensate for the gap in the IE.
         */
        if(vap->iv_he_srctrl_non_srg_obsspd_disallowed &&
                vap->iv_he_srctrl_srg_info_present) {
            OS_MEMCPY(frm + IEEE80211_NON_SRG_OBSS_PD_FIELD_OFFSET,
            frm + IEEE80211_SRG_OBSS_PD_FIELD_OFFSET,
            IEEE80211_SRG_OBSS_PD_TOTAL_FIELD_SIZE);
        }
    }
    /* advance the frame pointer by 2 octet ie-header + length of ie */
    return frm + ie->elem_len + 2;
}

void
ieee80211_parse_srpie(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_spatial_reuse *srp_ie = (struct ieee80211_ie_spatial_reuse *) ie;
    struct ieee80211_spatial_reuse_handle *ni_srp = &ni->ni_srp;

    ni_srp->obss_min = srp_ie->srg_obss_pd_min_offset;
    ni_srp->obss_max = srp_ie->srg_obss_pd_max_offset;

    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
       "%s SRP IE Params =%x non_srg_obss_pd_max_offset = %d,"
       "srg_obss_pd_min_offset = %d, srg_obss_pd_max_offset = %d\n",
        __func__, srp_ie->sr_ctrl.value,
       srp_ie->non_srg_obss_pd_max_offset,
       srp_ie->srg_obss_pd_min_offset,
       srp_ie->srg_obss_pd_max_offset);

}
#endif /* OBSS PD */

/*
 * routines to parse the IEs received from management frames.
 */
u_int8_t
ieee80211_parse_mpdudensity(u_int32_t mpdudensity)
{
    /*
     * 802.11n D2.0 defined values for "Minimum MPDU Start Spacing":
     *   0 for no restriction
     *   1 for 1/4 us
     *   2 for 1/2 us
     *   3 for 1 us
     *   4 for 2 us
     *   5 for 4 us
     *   6 for 8 us
     *   7 for 16 us
     */
    switch (mpdudensity) {
    case 0:
        return 0;
    case 1:
    case 2:
    case 3:
        /* Our lower layer calculations limit our precision to 1 microsecond */
        return 1;
    case 4:
        return 2;
    case 5:
        return 4;
    case 6:
        return 8;
    case 7:
        return 16;
    default:
        return 0;
    }
}

static void
ieee80211_update_smps_cap(struct ieee80211_node *ni, uint8_t smps)
{

    switch(smps) {
        case IEEE80211_SMPOWERSAVE_DISABLED:
            /*
             * Station just disabled SM Power Save therefore we can
             * send to it at full SM/MIMO.
             */
            ni->ni_updaterates = IEEE80211_NODE_SM_EN;
            IEEE80211_DPRINTF(ni->ni_vap,IEEE80211_MSG_POWER,"%s:SM"
                            " powersave disabled\n", __func__);
            break;
        case IEEE80211_SMPOWERSAVE_STATIC:
            /*
             * Station just enabled static SM power save therefore
             * we can only send to it at single-stream rates.
             */
            ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_STAT;
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_POWER,
                            "%s:switching to static SM power save\n", __func__);
            break;
        case IEEE80211_SMPOWERSAVE_DYNAMIC:
            /*
             * Station just enabled dynamic SM power save therefore
             * we should precede each packet we send to it with
             * an RTS.
             */
            ni->ni_updaterates = IEEE80211_NODE_SM_PWRSAV_DYN;
            IEEE80211_DPRINTF(ni->ni_vap,IEEE80211_MSG_POWER,
                            "%s:switching to dynamic SM power save\n",__func__);
            break;
    }
    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_POWER,
                "%s:calculated updaterates %#x\n",__func__, ni->ni_updaterates);
}

/*
 * ieee80211_parse_htcap:
 * Parse HT capability IEs from Rx management frames.
 *
 * Parameters:
 * @ni: Pointer to the peer node structure
 * @ie: Pointer to the IE buffer
 * @peer_update_required: Pointer to the peer_update_required flag
 * NOTE: peer_update_required is to be checked only once the caps have been
 * updated in the peer node's structure.
 *
 * Return:
 * 1: Success
 * 0: Failure
 */
int
ieee80211_parse_htcap(struct ieee80211_node *ni, u_int8_t *ie, bool *peer_update_required)
{
    struct ieee80211_ie_htcap_cmn *htcap = (struct ieee80211_ie_htcap_cmn *)ie;
    struct ieee80211com   *ic = ni->ni_ic;
    struct ieee80211vap   *vap = ni->ni_vap;
    u_int8_t rx_mcs;
    int                    htcapval, prev_htcap = ni->ni_htcap;
    u_int8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap);

    if (rx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        rx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    if (tx_streams > IEEE80211_MAX_11N_STREAMS)
    {
        tx_streams = IEEE80211_MAX_11N_STREAMS;
    }

    htcapval    = le16toh(htcap->hc_cap);
    rx_mcs = htcap->hc_mcsset[IEEE80211_TX_MCS_OFFSET];

    rx_mcs &= IEEE80211_TX_MCS_SET;

    if (rx_mcs & IEEE80211_TX_MCS_SET_DEFINED) {
        if( !(rx_mcs & IEEE80211_TX_RX_MCS_SET_NOT_EQUAL) &&
             (rx_mcs & (IEEE80211_TX_MAXIMUM_STREAMS_MASK |IEEE80211_TX_UNEQUAL_MODULATION_MASK))){
            return 0;
        }
    } else {
        if (rx_mcs & IEEE80211_TX_MCS_SET){
            return 0;
        }
    }

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        /*
         * Check if SM powersav state changed.
         * prev_htcap == 0 => htcap set for the first time.
         */
        if((htcapval & IEEE80211_HTCAP_C_SM_MASK) !=
                (ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK) || !prev_htcap) {
            ieee80211_update_smps_cap(ni, ((htcapval & IEEE80211_HTCAP_C_SM_MASK) >>
                                            IEEE80211_HTCAP_C_SMPOWERSAVE_S));
            ni->ni_htcap &= (~IEEE80211_HTCAP_C_SM_MASK);
            ni->ni_htcap |= (htcapval & IEEE80211_HTCAP_C_SM_MASK);
        }

        ni->ni_htcap = (htcapval & ~IEEE80211_HTCAP_C_SM_MASK) |
            (ni->ni_htcap & IEEE80211_HTCAP_C_SM_MASK);

        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_POWER, "%s: ni_htcap %#x\n",
                          __func__, ni->ni_htcap);

        if (htcapval & IEEE80211_HTCAP_C_GREENFIELD)
            ni->ni_htcap |= IEEE80211_HTCAP_C_GREENFIELD;

    } else {
        ni->ni_htcap = htcapval;
    }

    if (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40)
        ni->ni_htcap  = ni->ni_htcap & (((vap->iv_htflags & IEEE80211_HTF_SHORTGI40) && vap->iv_sgi)
                                    ? ni->ni_htcap  : ~IEEE80211_HTCAP_C_SHORTGI40);
    if (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI20)
        ni->ni_htcap  = ni->ni_htcap & (((vap->iv_htflags & IEEE80211_HTF_SHORTGI20) && vap->iv_sgi)
                                    ? ni->ni_htcap  : ~IEEE80211_HTCAP_C_SHORTGI20);

    if (ni->ni_htcap & IEEE80211_HTCAP_C_ADVCODING) {
        if (((vap->vdev_mlme->proto.generic.ldpc & IEEE80211_HTCAP_C_LDPC_TX) == 0) ||
            ((ieee80211com_get_ldpccap(ic) & IEEE80211_HTCAP_C_LDPC_TX) == 0))
            ni->ni_htcap &= ~IEEE80211_HTCAP_C_ADVCODING;
    }

    if (ni->ni_htcap & IEEE80211_HTCAP_C_TXSTBC) {
        ni->ni_htcap  = ni->ni_htcap & (((vap->iv_rx_stbc) && (rx_streams > 1)) ? ni->ni_htcap : ~IEEE80211_HTCAP_C_TXSTBC);
    }

    /* Tx on our side and Rx on the remote side should be considered for STBC with rate control */
    if (ni->ni_htcap & IEEE80211_HTCAP_C_RXSTBC) {
        ni->ni_htcap  = ni->ni_htcap & (((vap->iv_tx_stbc) && (tx_streams > 1)) ? ni->ni_htcap : ~IEEE80211_HTCAP_C_RXSTBC);
    }

    /* Note: when 11ac is enabled the VHTCAP Channel width will override this */
    if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
        ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
    } else {
        /* Channel width needs to be set to 40MHz for both 40MHz and 80MHz mode */
        if (ic->ic_cwm_get_width(ic) != IEEE80211_CWM_WIDTH20) {
            ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
        }
    }

    /* 11AX TODO: Recheck future 802.11ax drafts (>D1.0) on coex rules */
    if ((ni->ni_htcap & IEEE80211_HTCAP_C_INTOLERANT40) &&
        (IEEE80211_IS_CHAN_11N_HT40(vap->iv_bsschan) ||
         IEEE80211_IS_CHAN_11AX_HE40(vap->iv_bsschan))) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_POWER,
                 "%s: Received htcap with 40 intolerant bit set\n", __func__);
        ieee80211node_set_flag(ni, IEEE80211_NODE_40MHZ_INTOLERANT);
    }

    /*
     * The Maximum Rx A-MPDU defined by this field is equal to
     *      (2^^(13 + Maximum Rx A-MPDU Factor)) - 1
     * octets.  Maximum Rx A-MPDU Factor is an integer in the
     * range 0 to 3.
     */

    ni->ni_maxampdu = ((1u << (IEEE80211_HTCAP_MAXRXAMPDU_FACTOR + htcap->hc_maxampdu)) - 1);
    ni->ni_mpdudensity = ieee80211_parse_mpdudensity(htcap->hc_mpdudensity);

    ieee80211node_set_flag(ni, IEEE80211_NODE_HT);

#ifdef ATH_SUPPORT_TxBF

	ni->ni_txbf.value = le32toh(htcap->hc_txbf.value);
	//IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"==>%s:get remote txbf ie %x\n",__func__,ni->ni_txbf.value);
	ieee80211_match_txbfcapability(ic, ni);
	//IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,"==>%s:final result Com ExBF %d, NonCOm ExBF %d, ImBf %d\n",
	//  __func__,ni->ni_explicit_compbf,ni->ni_explicit_noncompbf,ni->ni_implicit_bf );

#endif
    if (ic->ic_set_ampduparams) {
        /* Notify LMAC of the ampdu params */
        ic->ic_set_ampduparams(ni);
    }

    if (peer_update_required &&
        ((prev_htcap & IEEE80211_HTCAP_C_SHORTGI40) != (ni->ni_htcap & IEEE80211_HTCAP_C_SHORTGI40))) {
        /* Currently mark for peer update only if the SGI values have updated */
        *peer_update_required = true;
    }

    return 1;
}

void
ieee80211_parse_htinfo(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_htinfo_cmn  *htinfo = (struct ieee80211_ie_htinfo_cmn *)ie;
    enum ieee80211_cwm_width    chwidth;
    int8_t extoffset;

    switch(htinfo->hi_extchoff) {
    case IEEE80211_HTINFO_EXTOFFSET_ABOVE:
        extoffset = 1;
        break;
    case IEEE80211_HTINFO_EXTOFFSET_BELOW:
        extoffset = -1;
        break;
    case IEEE80211_HTINFO_EXTOFFSET_NA:
    default:
        extoffset = 0;
    }

    chwidth = IEEE80211_CWM_WIDTH20;
    if (extoffset && (htinfo->hi_txchwidth == IEEE80211_HTINFO_TXWIDTH_2040)) {
        chwidth = IEEE80211_CWM_WIDTH40;
    }

    /* update node's recommended tx channel width */
    ni->ni_chwidth = chwidth;
}

#ifdef MU_CAP_WAR_ENABLED
int
ieee80211_check_mu_client_cap(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct      ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)ie;
    int         status = 0;

    ni->ni_mu_vht_cap = 0;
    ni->ni_vhtcap = le32toh(vhtcap->vht_cap_info);
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE)
    {
#if WAR_DISABLE_MU_2x2_STA
        /* Disable MU-MIMO for 2x2 Clients */
        if (((ni->ni_vhtcap & IEEE80211_VHTCAP_SOUND_DIM) >> IEEE80211_VHTCAP_SOUND_DIM_S) == 1) {
            return 0;
        }
#endif
        ni->ni_mu_vht_cap = 1;
        status = 1;
    }
    return status;
}
#endif

/*
 * ieee80211_parse_vhtcap:
 * Parse VHT capability IEs from Rx management frames.
 *
 * Parameters:
 * @ni: Pointer to the peer node structure
 * @ie: Pointer to the IE buffer
 * @peer_update_required: Pointer to the peer_update_required flag
 * NOTE: peer_update_required is to be checked only once the caps have been
 * updated in the peer node's structure to ensure peer update is carried out
 * only when the parsing has completed.
 *
 * Return:
 * None
 */
void
ieee80211_parse_vhtcap(struct ieee80211_node *ni, u_int8_t *ie, bool *peer_update_required)
{
    struct ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)ie;
    struct ieee80211com  *ic = ni->ni_ic;
    struct ieee80211vap  *vap = ni->ni_vap;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;

    u_int32_t ampdu_len = 0;
    u_int8_t chwidth = 0;
    u_int8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap);
    struct supp_tx_mcs_extnss tx_mcs_extnss_cap;
    u_int32_t prev_vhtcap = ni->ni_vhtcap;

    /* Negotiated capability set */
    ni->ni_vhtcap = le32toh(vhtcap->vht_cap_info);

    if (ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_80) {
        ni->ni_vhtcap  = ni->ni_vhtcap & ((vap->iv_sgi) ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_SHORTGI_80);
    }
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_160) {
        ni->ni_vhtcap = ni->ni_vhtcap & ((vap->iv_sgi) ? ni->ni_vhtcap : ~IEEE80211_VHTCAP_SHORTGI_160);
    }
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_RX_LDPC) {
        ni->ni_vhtcap  = ni->ni_vhtcap & ((vdev_mlme->proto.generic.ldpc & IEEE80211_HTCAP_C_LDPC_TX) ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_RX_LDPC);
    }
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_TX_STBC) {
        ni->ni_vhtcap  = ni->ni_vhtcap & (((vap->iv_rx_stbc) && (rx_streams > 1)) ? ni->ni_vhtcap : ~IEEE80211_VHTCAP_TX_STBC);
    }

    /* Tx on our side and Rx on the remote side should be considered for STBC with rate control */
    if (ni->ni_vhtcap & IEEE80211_VHTCAP_RX_STBC) {
        ni->ni_vhtcap  = ni->ni_vhtcap & (((vap->iv_tx_stbc) && (tx_streams > 1)) ? ni->ni_vhtcap : ~IEEE80211_VHTCAP_RX_STBC);
    }

    if (ni->ni_vhtcap & IEEE80211_VHTCAP_SU_BFORMEE) {
        ni->ni_vhtcap  = ni->ni_vhtcap & (vdev_mlme->proto.vht_info.subfer ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_SU_BFORMEE);
    }

    if (ni->ni_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE) {
        ni->ni_vhtcap  = ni->ni_vhtcap & ((vdev_mlme->proto.vht_info.mubfer
                            && vdev_mlme->proto.vht_info.subfer) ? ni->ni_vhtcap  : ~IEEE80211_VHTCAP_MU_BFORMEE);
    }

    if (ic->ic_ext_nss_capable) {
        ni->ni_ext_nss_support  = (ni->ni_vhtcap & IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_MASK) >>
                                    IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_S;
        if (ni->ni_ext_nss_support)
            ni->ni_prop_ie_used = 0;
    }

    OS_MEMCPY(&tx_mcs_extnss_cap, &vhtcap->tx_mcs_extnss_cap, sizeof(u_int16_t));
    *(u_int16_t *)&tx_mcs_extnss_cap = le16toh(*(u_int16_t*)&tx_mcs_extnss_cap);
    ni->ni_ext_nss_capable  = ((tx_mcs_extnss_cap.ext_nss_capable && ic->ic_ext_nss_capable) ? 1:0);

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic->ic_cwm_get_width(ic);
    }

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        ieee80211_update_ni_chwidth(chwidth, ni, vap);
    }

    if (ni->ni_chwidth == IEEE80211_CWM_WIDTH160) {
        ni->ni_160bw_requested = 1;
    }
    else {
        ni->ni_160bw_requested = 0;
    }

    /*
     * The Maximum Rx A-MPDU defined by this field is equal to
     *   (2^^(13 + Maximum Rx A-MPDU Factor)) - 1
     * octets.  Maximum Rx A-MPDU Factor is an integer in the
     * range 0 to 7.
     */

    ampdu_len = (le32toh(vhtcap->vht_cap_info) & IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP) >> IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S;
    ni->ni_maxampdu = (1u << (IEEE80211_VHTCAP_MAX_AMPDU_LEN_FACTOR + ampdu_len)) -1;
    ieee80211node_set_flag(ni, IEEE80211_NODE_VHT);
    ni->ni_tx_vhtrates = le16toh(vhtcap->tx_mcs_map);
    ni->ni_rx_vhtrates = le16toh(vhtcap->rx_mcs_map);
    ni->ni_tx_max_rate = (tx_mcs_extnss_cap.tx_high_data_rate);
    ni->ni_rx_max_rate = le16toh(vhtcap->rx_high_data_rate);

    /* Set NSS for 80+80 MHz same as that for 160 MHz if prop IE is used and AP/STA is capable of 80+80 MHz */
    if ((ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160) && ni->ni_prop_ie_used) {
        ni->ni_bw80p80_nss = ni->ni_bw160_nss;
    }

    if (peer_update_required &&
        (((prev_vhtcap & IEEE80211_VHTCAP_SHORTGI_80) != (ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_80)) ||
         ((prev_vhtcap & IEEE80211_VHTCAP_SHORTGI_160) != (ni->ni_vhtcap & IEEE80211_VHTCAP_SHORTGI_160)))) {
         /* Currently mark for peer update only if the SGI values have updated */
         *peer_update_required = true;
    }

}

void
ieee80211_parse_vhtop(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t *htinfo_ie)
{
    struct ieee80211_ie_vhtop *vhtop = (struct ieee80211_ie_vhtop *)ie;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    int ch_width;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    struct ieee80211_ie_htinfo_cmn  *htinfo = (struct ieee80211_ie_htinfo_cmn *)htinfo_ie;
    switch (vhtop->vht_op_chwidth) {
       case IEEE80211_VHTOP_CHWIDTH_2040:
           /* Exact channel width is already taken care of by the HT parse */
       break;
       case IEEE80211_VHTOP_CHWIDTH_80:
       if (ic->ic_ext_nss_capable) {
           if ((extnss_160_validate_and_seg2_indicate(&ni->ni_vhtcap, vhtop, htinfo)) ||
                        (extnss_80p80_validate_and_seg2_indicate(&ni->ni_vhtcap, vhtop, htinfo))) {
               ni->ni_chwidth =  IEEE80211_CWM_WIDTH160;
           } else {
               ni->ni_chwidth =  IEEE80211_CWM_WIDTH80;
           }
       } else if (IS_REVSIG_VHT160(vhtop) || IS_REVSIG_VHT80_80(vhtop)) {
           ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
       } else {
           ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
       }
       break;
       case IEEE80211_VHTOP_CHWIDTH_160:
       case IEEE80211_VHTOP_CHWIDTH_80_80:
           ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
       break;
       default:
           IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
                            "%s: Unsupported Channel Width\n", __func__);
       break;
    }

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        ch_width = vap->iv_chwidth;
    } else {
        ch_width = ic_cw_width;
    }
    /* Update ch_width only if it is within the user configured width*/
    if(ch_width < ni->ni_chwidth) {
        ni->ni_chwidth = ch_width;
    }
}

void
ieee80211_add_opmode(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype)
{
    struct ieee80211_ie_op_mode *opmode = (struct ieee80211_ie_op_mode *)frm;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int8_t nss = vap->vdev_mlme->proto.generic.nss;
    u_int8_t ch_width = 0;
    ieee80211_vht_rate_t ni_tx_vht_rates;


    if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
        (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Check negotiated Rx NSS and chwidth */
        ieee80211_get_vht_rates(ni->ni_tx_vhtrates, &ni_tx_vht_rates);
        rx_streams = MIN(rx_streams, ni_tx_vht_rates.num_streams);
        if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
            /* Set the station's maximum capable width, not the negotiated BW */
            ch_width = get_chwidth_phymode(vap->iv_des_mode);
        else
            /* Set negotiated BW */
            ch_width = ni->ni_chwidth;
    } else {
        /* Fill in default channel width */
        if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
            ch_width = vap->iv_chwidth;
        } else {
            ch_width = ic_cw_width;
        }
    }

    opmode->reserved = 0;
    opmode->rx_nss_type = 0; /* No beamforming */
    opmode->rx_nss = nss < rx_streams ? (nss-1) : (rx_streams -1); /* Supported RX streams */
    if (vap->iv_ext_nss_support && (ch_width == IEEE80211_CWM_WIDTH160 || ch_width == IEEE80211_CWM_WIDTH80_80)) {
        opmode->bw_160_80p80 = 1;
    } else {
        opmode->ch_width = ch_width;
    }
}

u_int8_t *
ieee80211_add_addba_ext(u_int8_t *frm, struct ieee80211vap *vap,
                         u_int8_t he_frag)
{
    struct ieee80211_ba_addbaext *addbaextension =
                                 (struct ieee80211_ba_addbaext *)frm;
    u_int8_t addba_ext_len = sizeof(struct ieee80211_ba_addbaext);

    qdf_mem_zero(addbaextension, addba_ext_len);

    addbaextension->elemid      = IEEE80211_ADDBA_EXT_ELEM_ID;
    addbaextension->length      = IEEE80211_ADDBA_EXT_ELEM_ID_LEN;
    addbaextension->no_frag_bit = 0;
    addbaextension->he_fragmentation =
        ((vap->iv_he_frag > he_frag) ? he_frag : vap->iv_he_frag);
    return frm + addba_ext_len;
}

u_int8_t *
ieee80211_add_opmode_notify(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype)
{
    struct ieee80211_ie_op_mode_ntfy *opmode = (struct ieee80211_ie_op_mode_ntfy *)frm;
    int opmode_notify_len = sizeof(struct ieee80211_ie_op_mode_ntfy);

    opmode->elem_id   = IEEE80211_ELEMID_OP_MODE_NOTIFY;
    opmode->elem_len  =  opmode_notify_len- 2;
    ieee80211_add_opmode((u_int8_t *)&opmode->opmode, ni, ic, subtype);
    return frm + opmode_notify_len;
}

int  ieee80211_intersect_extnss_160_80p80(struct ieee80211_node *ni)
{
    struct ieee80211com  *ic = ni->ni_ic;
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, ni->ni_vap);
    struct ieee80211_bwnss_map nssmap;
    ieee80211_vht_rate_t rx_rrs;

    ieee80211_get_vht_rates(ni->ni_rx_vhtrates, &rx_rrs);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    if (!ieee80211_get_bw_nss_mapping(ni->ni_vap, &nssmap, tx_streams)) {
        if (!ieee80211_derive_nss_from_cap(ni, &rx_rrs)) {
            return 0;
        }
        ni->ni_bw160_nss = MIN(nssmap.bw_nss_160, ni->ni_bw160_nss);
        ni->ni_bw80p80_nss = MIN(nssmap.bw_nss_160, ni->ni_bw80p80_nss);
    }
    return 1;
}

/**
 * This fucntion is specific to validate the HE mode BW chnages.
 * If OMN move to any BW is only possible if Association is done with
 * same or Higer BW in 11axa or HE mode.
 */
static bool ieee80211_is_bw_change_valid(struct ieee80211_node *ni)
{
    uint32_t he_width_mask = 0;
    uint8_t *hecap_phy_info, width_set = 0;
    bool status = true;

    /* For non-HE mode we need not handle here. */
    if (!(ni->ni_ext_flags & IEEE80211_NODE_HE)) {
        return status;
    }

    hecap_phy_info = (uint8_t *) &(ni->ni_he.hecap_phyinfo[HECAP_PHYBYTE_IDX0]);
    he_width_mask = HECAP_PHY_CBW_GET_FROM_IE(&hecap_phy_info);
    width_set = he_width_mask & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_HE160_HE80_80_MASK;

    if (!(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) ||
        !ni->ni_he.he_basic_txrxmcsnss_req_met_160) {
        status = false;
        qdf_err("Unsupported Channel width 3");
    }

    return status;
}

void
ieee80211_parse_opmode(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype)
{
    struct ieee80211_ie_op_mode *opmode = (struct ieee80211_ie_op_mode *)ie;
    struct ieee80211com  *ic = ni->ni_ic;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, ni->ni_vap);
    u_int8_t rx_nss = 0;
    enum ieee80211_cwm_width ch_width;
#if QCA_SUPPORT_SON
    bool generate_event = false;
#endif
    bool chwidth_change = false;

#if QCA_SUPPORT_SON
    struct ieee80211_opmode_update_data opmode_update_event_data = {0};
#endif

    /* Check whether this is a beamforming type */
    if (opmode->rx_nss_type == 1) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
                           "%s: Beamforming is unsupported\n", __func__);
        return;
    }

    ch_width = get_chwidth_phymode(ni->ni_phymode);

    if(opmode->ch_width > ch_width ||
       (opmode->bw_160_80p80 && (ch_width < IEEE80211_CWM_WIDTH160))) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
                          "%s: Unsupported new opmode channel width=%d; "
                          "opmode bw_160_80p80: %d; assoc. ni_chwidth=%d\n",
                          __func__,opmode->ch_width,opmode->bw_160_80p80,
                          ni->ni_chwidth);
        return;
    }

    /* Update ch_width for peer only if it is within the bw supported */
    if ((!ni->ni_ext_nss_support || !opmode->bw_160_80p80)
                   && (opmode->ch_width <= ic_cw_width) &&
                   (opmode->ch_width != ni->ni_chwidth)) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
            "%s:%d: Bandwidth changed from %d to %d \n",
             __func__, __LINE__, ni->ni_chwidth, opmode->ch_width);
        switch (opmode->ch_width) {
            case 0:
                ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                chwidth_change = true;
            break;

            case 1:
                ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                chwidth_change = true;
            break;

            case 2:
                ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                chwidth_change = true;
            break;

            case 3:
                if (!ic->ic_ext_nss_capable) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                    chwidth_change = true;
                }
            break;

            default:
                IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
                           "%s: Unsupported Channel Width\n", __func__);
                return;
            break;
        }
    }
    if (ni->ni_ext_nss_support && opmode->bw_160_80p80 &&
             (ic_cw_width >= IEEE80211_CWM_WIDTH160) && (ni->ni_chwidth != IEEE80211_CWM_WIDTH160)) {
        if (ieee80211_is_bw_change_valid(ni)) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
                              "%s:%d: Bandwidth changed from %d to 3 \n",
                              __func__, __LINE__, ni->ni_chwidth);
            chwidth_change = true;
            ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
        } else {
            /* Non-HE mode will never come to else part */
            if (ni->ni_chwidth != ch_width) {
                ni->ni_phymode = get_phymode_from_chwidth(ic, ni);
            }
            return;
        }
    }

    if (chwidth_change == true) {
        if ((subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_REQ) &&
            (subtype != IEEE80211_FC0_SUBTYPE_ASSOC_REQ)) {
            ic->ic_chwidth_change(ni);
#if QCA_SUPPORT_SON
            generate_event = true;
#endif
        }
    }

    /* Propagate the number of Spatial streams to the target */
    rx_nss = opmode->rx_nss + 1;
    if ((rx_nss != ni->ni_streams) && (rx_nss <= tx_streams)) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
             "%s: NSS changed from %d to %d \n", __func__, ni->ni_streams, opmode->rx_nss + 1);

        ni->ni_streams = rx_nss;

        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH160) && ni->ni_ext_nss_support && ni->ni_vap->iv_ext_nss_support){
             ieee80211_intersect_extnss_160_80p80(ni);
        }

        if ((subtype != IEEE80211_FC0_SUBTYPE_ASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_RESP) &&
            (subtype != IEEE80211_FC0_SUBTYPE_REASSOC_REQ) &&
            (subtype != IEEE80211_FC0_SUBTYPE_ASSOC_REQ) &&
            ieee80211node_has_extflag(ni, IEEE80211_NODE_ASSOC_RESP)) {
            ic->ic_nss_change(ni);
#if QCA_SUPPORT_SON
            generate_event = true;
#endif
        } else {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ACTION,
                              "%s: discard nss change. subtype=%d, assoc flag=%d\n",
                              __func__, subtype,
                              ieee80211node_has_extflag(ni, IEEE80211_NODE_ASSOC_RESP));
        }
    }

#if QCA_SUPPORT_SON
    if (generate_event) {
            opmode_update_event_data.max_chwidth = ni->ni_chwidth;
            opmode_update_event_data.num_streams = ni->ni_streams;
            qdf_mem_copy(opmode_update_event_data.macaddr, ni->ni_macaddr, QDF_MAC_ADDR_SIZE);
            IEEE80211_DELIVER_EVENT_OPMODE_UPDATE(ni->ni_vap, &opmode_update_event_data, sizeof(struct ieee80211_opmode_update_data));
    }
#endif

    /* Updating the node's opmode notify channel width */
    ni->ni_omn_chwidth = ni->ni_chwidth;
}

void
ieee80211_parse_opmode_notify(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype)
{
    struct ieee80211_ie_op_mode_ntfy *opmode = (struct ieee80211_ie_op_mode_ntfy *)ie;
    ieee80211_parse_opmode(ni, (u_int8_t *)&opmode->opmode, subtype);
}

int
ieee80211_parse_wmeparams(struct ieee80211vap *vap, u_int8_t *frm,
                          u_int8_t *qosinfo, int forced_update)
{
    struct ieee80211_wme_state *wme = &vap->iv_wmestate;
    u_int len = frm[1], qosinfo_count;
    int i;

    *qosinfo = 0;

    if (len < sizeof(struct ieee80211_wme_param) - 2) {
        /* XXX: TODO msg+stats */
        return -1;
    }

    *qosinfo = frm[__offsetof(struct ieee80211_wme_param, param_qosInfo)];
    qosinfo_count = *qosinfo & WME_QOSINFO_COUNT;

    if (!forced_update) {

        /* XXX do proper check for wraparound */
        if (qosinfo_count == (wme->wme_wmeChanParams.cap_info & WME_QOSINFO_COUNT))
            return 0;
    }

    frm += __offsetof(struct ieee80211_wme_param, params_acParams);
    for (i = 0; i < WME_NUM_AC; i++) {
        struct wmeParams *wmep =
            &wme->wme_wmeChanParams.cap_wmeParams[i];
        /* NB: ACI not used */
        wmep->wmep_acm = IEEE80211_MS(frm[0], WME_PARAM_ACM);
        wmep->wmep_aifsn = IEEE80211_MS(frm[0], WME_PARAM_AIFSN);
        wmep->wmep_logcwmin = IEEE80211_MS(frm[1], WME_PARAM_LOGCWMIN);
        wmep->wmep_logcwmax = IEEE80211_MS(frm[1], WME_PARAM_LOGCWMAX);
        wmep->wmep_txopLimit = LE_READ_2(frm+2);
        frm += 4;
    }
    wme->wme_wmeChanParams.cap_info = *qosinfo;

    return 1;
}

int
ieee80211_parse_wmeinfo(struct ieee80211vap *vap, u_int8_t *frm,
                        u_int8_t *qosinfo)
{
    struct ieee80211_wme_state *wme = &vap->iv_ic->ic_wme;
    u_int len = frm[1], qosinfo_count;

    *qosinfo = 0;

    if (len < sizeof(struct ieee80211_ie_wme) - 2) {
        /* XXX: TODO msg+stats */
        return -1;
    }

    *qosinfo = frm[__offsetof(struct ieee80211_wme_param, param_qosInfo)];
    qosinfo_count = *qosinfo & WME_QOSINFO_COUNT;

    /* XXX do proper check for wraparound */
    if (qosinfo_count == (wme->wme_wmeChanParams.cap_info & WME_QOSINFO_COUNT))
        return 0;

    wme->wme_wmeChanParams.cap_info = *qosinfo;

    return 1;
}

int
ieee80211_parse_muedcaie(struct ieee80211vap *vap, u_int8_t *frm)
{

    struct ieee80211_ie_muedca *iemuedca = (struct ieee80211_ie_muedca *)frm;
    struct ieee80211_muedca_state *muedca = &vap->iv_muedcastate;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_wme_state *wme = &ic->ic_wme;
    int i;
    u_int8_t qosinfo = frm[3];
    u_int8_t len = frm[1];

    if(len < (sizeof(struct ieee80211_ie_muedca) - 2)) {
        qdf_print("%s: Invalid length for MUEDCA params: %d.", __func__, len);
        return -EINVAL;
    }

    /* This check will set the 'iv_update_muedca_params'(update target)if there
     * is a change in the MUEDCA_UPDATE_COUNT in the qosinfo, irrespective of
     * whether the UPDATE_COUNT was incremented or decremented.
     */
    if(IEEE80211_MS(qosinfo, IEEE80211_MUEDCA_UPDATE_COUNT) !=
                muedca->muedca_param_update_count)
    {
        muedca->muedca_param_update_count =
            IEEE80211_MS(qosinfo, IEEE80211_MUEDCA_UPDATE_COUNT);

        if (vap->iv_he_ul_muofdma)
            vap->iv_update_muedca_params = 1;
    }

    for(i = 0; (i < MUEDCA_NUM_AC) && (vap->iv_update_muedca_params); i++) {

        muedca->muedca_paramList[i].muedca_ecwmin =
            IEEE80211_MS(iemuedca->muedca_param_record[i].ecwminmax,
                    IEEE80211_MUEDCA_ECWMIN);
        muedca->muedca_paramList[i].muedca_ecwmax =
            IEEE80211_MS(iemuedca->muedca_param_record[i].ecwminmax,
                    IEEE80211_MUEDCA_ECWMAX);
        muedca->muedca_paramList[i].muedca_aifsn =
            IEEE80211_MS(iemuedca->muedca_param_record[i].aifsn_aci,
                    IEEE80211_MUEDCA_AIFSN);
        muedca->muedca_paramList[i].muedca_acm =
            IEEE80211_MS(iemuedca->muedca_param_record[i].aifsn_aci,
                    IEEE80211_MUEDCA_ACM);
        muedca->muedca_paramList[i].muedca_timer =
            iemuedca->muedca_param_record[i].timer;

    }

    if(vap->iv_update_muedca_params) {

        if(wme->wme_update) {
            wme->wme_update(ic, vap, true);
        }
        vap->iv_update_muedca_params = 0;
    }

    return 1;

}

int
ieee80211_parse_tspecparams(struct ieee80211vap *vap, u_int8_t *frm)
{
    struct ieee80211_tsinfo_bitmap *tsinfo;

    tsinfo = (struct ieee80211_tsinfo_bitmap *) &((struct ieee80211_wme_tspec *) frm)->ts_tsinfo[0];

    if (tsinfo->tid == 6)
        OS_MEMCPY(&vap->iv_ic->ic_sigtspec, frm, sizeof(struct ieee80211_wme_tspec));
    else
        OS_MEMCPY(&vap->iv_ic->ic_datatspec, frm, sizeof(struct ieee80211_wme_tspec));

    return 1;
}

/*
 * used by STA when it receives a (RE)ASSOC rsp.
 */
int
ieee80211_parse_timeieparams(struct ieee80211vap *vap, u_int8_t *frm)
{
    struct ieee80211_ie_timeout_interval *tieinfo;

    tieinfo = (struct ieee80211_ie_timeout_interval *) frm;

    if (tieinfo->interval_type == IEEE80211_TIE_INTERVAL_TYPE_ASSOC_COMEBACK_TIME)
        vap->iv_assoc_comeback_time = tieinfo->value;
    else
        vap->iv_assoc_comeback_time = 0;

    return 1;
}

/*
 * used by HOST AP when it receives a (RE)ASSOC req.
 */
int
ieee80211_parse_wmeie(u_int8_t *frm, const struct ieee80211_frame *wh,
                      struct ieee80211_node *ni)
{
    u_int len = frm[1];
    u_int8_t ac;

    if (len != 7) {
        IEEE80211_DISCARD_IE(ni->ni_vap,
            IEEE80211_MSG_ELEMID | IEEE80211_MSG_WME,
            "WME IE", "too short, len %u", len);
        return -1;
    }
    ni->ni_uapsd = frm[WME_CAPINFO_IE_OFFSET];
    if (ni->ni_uapsd) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_UAPSD);
        switch (WME_UAPSD_MAXSP(ni->ni_uapsd)) {
        case 1:
            ni->ni_uapsd_maxsp = 2;
            break;
        case 2:
            ni->ni_uapsd_maxsp = 4;
            break;
        case 3:
            ni->ni_uapsd_maxsp = 6;
            break;
        default:
            ni->ni_uapsd_maxsp = WME_UAPSD_NODE_MAXQDEPTH;
        }
        for (ac = 0; ac < WME_NUM_AC; ac++) {
            ni->ni_uapsd_ac_trigena[ac] = (WME_UAPSD_AC_ENABLED(ac, ni->ni_uapsd)) ? 1:0;
            ni->ni_uapsd_ac_delivena[ac] = (WME_UAPSD_AC_ENABLED(ac, ni->ni_uapsd)) ? 1:0;
            wlan_peer_update_uapsd_ac_trigena(ni->peer_obj, ni->ni_uapsd_ac_trigena, sizeof(ni->ni_uapsd_ac_trigena));
            wlan_peer_update_uapsd_ac_delivena(ni->peer_obj, ni->ni_uapsd_ac_delivena, sizeof(ni->ni_uapsd_ac_delivena));
        }
        wlan_peer_set_uapsd_maxsp(ni->peer_obj, ni->ni_uapsd_maxsp);
    } else {
        ieee80211node_clear_flag(ni, IEEE80211_NODE_UAPSD);
    }

    IEEE80211_NOTE(ni->ni_vap, IEEE80211_MSG_POWER, ni,
            "UAPSD bit settings: %02x - vap-%d (%s) from STA %pM\n",
            ni->ni_uapsd, ni->ni_vap->iv_unit, ni->ni_vap->iv_netdev_name,
            ni->ni_macaddr);

    return 1;
}

void
ieee80211_savenie(osdev_t osdev,u_int8_t **iep, const u_int8_t *ie, u_int ielen)
{
    /*
    * Record information element for later use.
    */
    if (*iep == NULL || (*iep)[1] != ie[1])
    {
        if (*iep != NULL)
            OS_FREE(*iep);
		*iep = (void *) OS_MALLOC(osdev, ielen, GFP_KERNEL);
    }
    if (*iep != NULL)
        OS_MEMCPY(*iep, ie, ielen);
}

void
ieee80211_saveie(osdev_t osdev,u_int8_t **iep, const u_int8_t *ie)
{
    u_int ielen = ie[1]+2;
    ieee80211_savenie(osdev,iep, ie, ielen);
}

void
ieee80211_process_athextcap_ie(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_ath_extcap *athextcapIe =
        (struct ieee80211_ie_ath_extcap *) ie;
    u_int16_t remote_extcap = athextcapIe->ath_extcap_extcap;

    remote_extcap = LE_READ_2(&remote_extcap);

    /* We know remote node is an Atheros Owl or follow-on device */
    ieee80211node_set_flag(ni, IEEE80211_NODE_ATH);

    /* If either one of us is capable of OWL WDS workaround,
     * implement WDS mode block-ack corruption workaround
     */
    if (remote_extcap & IEEE80211_ATHEC_OWLWDSWAR) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_OWL_WDSWAR);
    }

    /* If device and remote node support the Atheros proprietary
     * wep/tkip aggregation mode, mark node as supporting
     * wep/tkip w/aggregation.
     * Save off the number of rx delimiters required by the destination to
     * properly receive tkip/wep with aggregation.
     */
    if (remote_extcap & IEEE80211_ATHEC_WEPTKIPAGGR) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_WEPTKIPAGGR);
    }
    /* Check if remote device, require extra delimiters to be added while
     * sending aggregates. Osprey 1.0 and earlier chips need this.
     */
    if (remote_extcap & IEEE80211_ATHEC_EXTRADELIMWAR) {
        ieee80211node_set_flag(ni, IEEE80211_NODE_EXTRADELIMWAR);
    }

}

uint32_t ieee80211_get_max_chan_switch_time(struct ieee80211_max_chan_switch_time_ie *mcst_ie)
{
    uint32_t  max_chan_switch_time = 0;
    uint8_t i;

    /* unpack the max_time in 3 octets/bytes. Little endian format */
    for(i = 0; i < SIZE_OF_MAX_TIME_INT; i++) {
        max_chan_switch_time  += (mcst_ie->switch_time[i] << (i * BITS_IN_A_BYTE));
    }
    return max_chan_switch_time;
}

struct ieee80211_ath_channel *
ieee80211_get_new_sw_chan (
    struct ieee80211_node                       *ni,
    struct ieee80211_ath_channelswitch_ie           *chanie,
    struct ieee80211_extendedchannelswitch_ie   *echanie,
    struct ieee80211_ie_sec_chan_offset         *secchanoffsetie,
    struct ieee80211_ie_wide_bw_switch         *widebwie,
    u_int8_t *cswarp
    )
{
    struct ieee80211_ath_channel *chan;
    struct ieee80211com *ic = ni->ni_ic;
    enum ieee80211_phymode phymode = IEEE80211_MODE_AUTO;
    u_int8_t    secchanoffset = 0;
    u_int8_t    primary_chan = 0, secondary_chan = 0;
    uint8_t wideband_chwidth = 0;
    enum ieee80211_cwm_width secoff_chwidth = IEEE80211_CWM_WIDTH20;
    enum ieee80211_cwm_width dest_chwidth = IEEE80211_CWM_WIDTH20;
    enum ieee80211_cwm_width max_allowed_chwidth = IEEE80211_CWM_WIDTH20;
    enum ieee80211_mode mode = IEEE80211_MODE_INVALID;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_objmgr_pdev *pdev;
    u_int16_t freq1, freq2;

    pdev = ic->ic_pdev_obj;
    if(!pdev) {
        qdf_err("pdev is null");
        return NULL;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if(!psoc) {
        qdf_err("psoc is null");
        return NULL;
    }

    if(echanie) {
        primary_chan = echanie->newchannel;
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
            "%s: E-CSA new channel = %d\n",
             __func__, echanie->newchannel);
    } else if (chanie) {
        primary_chan = chanie->newchannel;
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
            "%s: CSA new channel = %d\n",
             __func__, chanie->newchannel);
    }


   if(widebwie) {
        secondary_chan = widebwie->new_ch_freq_seg2;
        wideband_chwidth = widebwie->new_ch_width;
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
            "%s: wide bandwidth changed new vht chwidth = %d"
            " cfreq1: %d, cfreq2: %d\n", __func__, widebwie->new_ch_width,
            widebwie->new_ch_freq_seg1, secondary_chan);
    }

    if(secchanoffsetie) {
        secchanoffset = secchanoffsetie->sec_chan_offset;
        if ((secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCA) ||
            (secchanoffset == IEEE80211_SEC_CHAN_OFFSET_SCB)) {
            secoff_chwidth = IEEE80211_CWM_WIDTH40;
        } else {
            secchanoffset = IEEE80211_SEC_CHAN_OFFSET_SCN;
            secoff_chwidth = IEEE80211_CWM_WIDTH20;
        }
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_SCANENTRY,
                "%s: HT bandwidth changed new secondary channel offset = %d\n",
                __func__, secchanoffset);
    }

    /* Channel switch announcement can't be used to switch
     * between 11a/b/g/n/ac modes. Only channel and width can
     * be switched. So first find the current association
     * mode and then find channel width announced by AP and
     * mask it with maximum channel width allowed by user
     * configuration.
     * For finding a/b/g/n/ac.. modes, current operating
     * channel mode can be used.
     */

    /* Below algorithm is used to derive the best channel:
     * 1. Find current operating mode a/b/g/n/ac from current channel --> M.
     * 2. Find new channel width announced by AP --> W.
     * 3. Mask W with max user configured width and find desired chwidth--> X.
     * 4. Combine M and X to find new composite phymode --> C.
     * 5. Check composite phymode C is supported by device.
     * 6. If step 5 evaluates true, C is the destination composite phymode.
     * 7. If step 5 evaluates false, find a new composite phymode C from M and X/2.
     * 8. Repeat until a device supported phymode is found or all channel
          width combinations are exausted.
     * 9. Find the new channel with C, cfreq1 and cfreq2.
     */

    /* Find current mode */
    if (!ieee80211_ic_rpt_max_phy_is_set(ic))
        mode = ieee80211_get_mode(ic->ic_curchan);
    else
        mode = ni->ni_vap->iv_cur_mode;

    if (mode == IEEE80211_MODE_INVALID) {
        /* No valid mode found. */
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,
            IEEE80211_MSG_SCANENTRY, "%s : Invalid current mode\n", __func__);
        return NULL;
    }

    /* Calculate destination channel width */
    if (widebwie) {
        if (wideband_chwidth == IEEE80211_VHTOP_CHWIDTH_2040) {
            /* Wide band IE is never present for 20MHz */
            dest_chwidth = IEEE80211_CWM_WIDTH40;
        } else if ((wideband_chwidth == IEEE80211_VHTOP_CHWIDTH_80) ||
                   (wideband_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) ||
                   (wideband_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80)) {
            if (widebwie->new_ch_freq_seg2 == 0) {
                /* 80 MHz */
                dest_chwidth = IEEE80211_CWM_WIDTH80;
            } else if ((widebwie->new_ch_freq_seg2 > 0) &&
                    abs(widebwie->new_ch_freq_seg2 - widebwie->new_ch_freq_seg1) > 16) {
                /* 80+80 MHz */
                dest_chwidth = IEEE80211_CWM_WIDTH80_80;
            } else if ((widebwie->new_ch_freq_seg2 > 0) &&
                    abs(widebwie->new_ch_freq_seg2 - widebwie->new_ch_freq_seg1) == 8) {
                /* 160 MHz */
                dest_chwidth = IEEE80211_CWM_WIDTH160;
            }
        } else if (wideband_chwidth == IEEE80211_VHTOP_CHWIDTH_160) {
            dest_chwidth = IEEE80211_CWM_WIDTH160;
        } else if (wideband_chwidth == IEEE80211_VHTOP_CHWIDTH_80_80) {
            dest_chwidth = IEEE80211_CWM_WIDTH80_80;
        } else {
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
                    "%s : Invalid wideband channel width %d specified\n",
                    __func__, wideband_chwidth);
            return NULL;
        }
    } else if (secchanoffsetie) {
        dest_chwidth = secoff_chwidth;
    }

    /* Find maximum allowed chwidth */
    max_allowed_chwidth = ieee80211_get_vap_max_chwidth(ni->ni_vap);
    if ((dest_chwidth == IEEE80211_CWM_WIDTH80_80) && (max_allowed_chwidth == IEEE80211_CWM_WIDTH160)) {
        dest_chwidth = IEEE80211_CWM_WIDTH80;
    } else if ((dest_chwidth == IEEE80211_CWM_WIDTH160) && (max_allowed_chwidth == IEEE80211_CWM_WIDTH80_80)) {
        dest_chwidth = IEEE80211_CWM_WIDTH160;
    } else if (dest_chwidth > max_allowed_chwidth) {
        dest_chwidth = max_allowed_chwidth;
    }

    /* 11N and 11AX modes are supported on 5G, 6G and 2.4G bands.
     * Find which band AP is going to.
     */

    if (echanie && wlan_reg_is_6ghz_op_class(pdev, echanie->newClass)) {
        if (mode == IEEE80211_MODE_AX) {
            mode = IEEE80211_MODE_AXA;
        }
    } else {
        if (mode == IEEE80211_MODE_N) {
            if (primary_chan > 20) {
                mode = IEEE80211_MODE_NA;
            } else {
                mode = IEEE80211_MODE_NG;
            }
        } else if (mode == IEEE80211_MODE_AX) {
            if (primary_chan > 20) {
                mode = IEEE80211_MODE_AXA;
            } else {
                mode = IEEE80211_MODE_AXG;
            }
        }
    }

    if (echanie) {
        /* Get frequency from channel and opclass */
        freq1 = wlan_reg_chan_opclass_to_freq_auto(primary_chan,
                                                   echanie->newClass, false);
        freq2 = wlan_reg_chan_opclass_to_freq_auto(secondary_chan,
                                                   echanie->newClass, false);
    } else {
        /*
         * If echanie is not present then use legacy freq APIs which
         * don't require band information (Supports only 2G/5G).
         */
        freq1 = wlan_reg_legacy_chan_to_freq(ic->ic_pdev_obj, primary_chan);
        freq2 = wlan_reg_legacy_chan_to_freq(ic->ic_pdev_obj, secondary_chan);
    }

    do {
        /* Calculate destination composite Phymode and ensure device support */
        phymode = ieee80211_get_composite_phymode(mode, dest_chwidth, secchanoffset);
        if (ieee80211_is_phymode_auto(phymode)) {
            /* Could not find valid destination Phymode. */
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
            "%s : Could not find valid destination Phymode for mode: %d "
            "dest_chwidth: %d, secchanoffset: %d\n",__func__, mode, dest_chwidth,
            secchanoffset);
            return NULL;
        }
        if (IEEE80211_SUPPORT_PHY_MODE(ic, phymode)) {
            if (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_RESTRICTED_80P80_SUPPORT) &&
                (dest_chwidth == IEEE80211_CWM_WIDTH80_80) &&
                !(CHAN_WITHIN_RESTRICTED_80P80(freq1, freq2))) {
                /* Find next lower chwidth */
            } else {
                break;
            }
        }

        /* If composite phymode is not supported by device,
         * try finding next composite phymode having lower chwidth
         */
        if ((dest_chwidth == IEEE80211_CWM_WIDTH160) ||
                (dest_chwidth == IEEE80211_CWM_WIDTH80_80)) {
            dest_chwidth = IEEE80211_CWM_WIDTH80;
        } else {
            dest_chwidth -= 1;
        }

    } while (dest_chwidth >= IEEE80211_CWM_WIDTH20);

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
    "%s : New composite phymode is: %d", __func__, phymode);

    chan  =  ieee80211_find_dot11_channel(ic, freq1, freq2, phymode);

    if (!chan) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD, IEEE80211_MSG_SCANENTRY,
                "%s : Couldn't find new channel with phymode: %d, "
                "primary_chan: %d, secondary_chan: %d\n", __func__, phymode,
                primary_chan, secondary_chan);
        return chan;
    }

    /*
     * If the request is for wideband channel change, ensure wideband is
     * is supported by the repeater.
     */
    if (IEEE80211_ARE_CHANS_INTERWIDEBAND(ic->ic_curchan, chan) &&
        check_inter_band_switch_compatibility(ic)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_LOUD,
                             IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                             "%s: Wideband CSA unsupported", __func__);
        return NULL;
    }

    return chan;
}

/* Update the desired channel info on all vaps. This API is called before
 * sending VDEV START/RESTART to FW. Hence update only the desired channel
 * of the VAP. Once FW sends the START/RESTART response, bss channel is
 * updated(vap->iv_bsschan in mlme_vdev_start_continue_cb).
 * This is because if RESTART/START request fails for some reason,
 * there will be a mismatch between Host and Target channel.
 *
 */
void
ieee80211_vap_iter_update_des_chan(void *arg, struct ieee80211vap *vap)
{
    struct ieee80211_ath_channel *des_chan =
        (struct ieee80211_ath_channel *) arg;

    if (ieee80211_ic_rpt_max_phy_is_set(vap->iv_ic) &&
        (vap->iv_opmode == IEEE80211_M_STA)) {
        qdf_debug("set des_mode for rpt sta as %d", vap->iv_des_mode);
        vap->iv_des_mode = ieee80211_derive_max_phy(vap->iv_cur_mode, des_chan);
        vap->iv_des_chan[vap->iv_des_mode] = ieee80211_find_dot11_channel(vap->iv_ic, des_chan->ic_freq,
                                                                          des_chan->ic_vhtop_freq_seg2,
                                                                          vap->iv_des_mode);
    } else {
        vap->iv_des_chan[vap->iv_des_mode] = IEEE80211_CHAN_ANYC;
        vap->iv_des_mode = wlan_get_des_phymode(des_chan);
        vap->iv_des_chan[vap->iv_des_mode] = des_chan;
    }
}

/*
 * is_vap_start_success(): Return the status of vap's start response.
 * @vap: Pointer to vap structure.
 */
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
static bool is_vap_start_success(struct ieee80211vap *vap)
{
    return vap->vap_start_failure;
}
#else
static bool is_vap_start_success(struct ieee80211vap *vap)
{
    return true;
}
#endif

/**
 * ieee80211_set_nxt_radar_frequency() - Find a channel with user configured
 *                                       frequency and current mode.
 * @ic: Pointer to struct ieee80211com.
 * @ch_params: Pointer to struct ch_params.
 *
 * Return - A channel pointer of type ieee80211_ath_channel if channel
 *          exists else NULL.
 */

static struct ieee80211_ath_channel *
ieee80211_set_nxt_radar_frequency(struct ieee80211com *ic,
                                  struct ch_params *ch_params)
{
    struct ieee80211_ath_channel *ptarget_channel = NULL;

    if (ic->ic_radar_next_usr_freq) {
        qdf_freq_t target_chan_freq = ic->ic_radar_next_usr_freq;
        enum ieee80211_phymode chan_mode =
        ieee80211_get_target_channel_mode(ic, ch_params);

        if (mlme_dfs_is_freq_in_nol(ic->ic_pdev_obj, target_chan_freq)) {
            IEEE80211_DPRINTF_IC_CATEGORY(ic, IEEE80211_MSG_DFS,
                    "The configured frequency %u is in NOL",target_chan_freq);
            return NULL;
        }
        /* reset user configured freq on every radar detection */
        ic->ic_radar_next_usr_freq = 0;

        ptarget_channel =
            ieee80211_find_dot11_channel(ic, target_chan_freq, 0, chan_mode);
        if (ptarget_channel == NULL)
            ptarget_channel = ieee80211_find_dot11_channel(ic,
                                                           target_chan_freq,
                                                           0,
                                                           IEEE80211_MODE_AUTO);
    }
    return ptarget_channel;
}

/*
 * Execute radar channel change. This is called when a radar/dfs
 * signal is detected.  AP mode only. chan_failure indicates, whether
 * this API is invoked on restart resp failure. Return 1 on success, 0 on
 * failure.
 */
int
ieee80211_dfs_action(struct ieee80211vap *vap, struct
                     ieee80211_ath_channelswitch_ie *pcsaie,
                     bool chan_failure)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint16_t target_chan_freq = 0;
    struct ieee80211_ath_channel *ptarget_channel = NULL;
    struct ieee80211vap *tmp_vap = NULL;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc = NULL;
    struct ch_params ch_params;
    enum ieee80211_phymode chan_mode;
    struct wlan_lmac_if_dfs_rx_ops *dfs_rx_ops = NULL;
    bool bw_reduce = false;
    uint16_t flag = 0;

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        return 0;
    }

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_print("%s : pdev is null", __func__);
        return -1;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (psoc == NULL) {
	QDF_TRACE(QDF_MODULE_ID_DFS, QDF_TRACE_LEVEL_DEBUG, "psoc is null");
        return -1;
    }


    dfs_rx_ops = wlan_lmac_if_get_dfs_rx_ops(psoc);
    ieee80211_regdmn_get_des_chan_params(vap, &ch_params);

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
            QDF_STATUS_SUCCESS) {
        return -1;
    }

    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        ptarget_channel = ieee80211_set_nxt_radar_frequency(ic, &ch_params);
        if (ptarget_channel == NULL){
            if(IEEE80211_IS_CSH_OPT_APRIORI_NEXT_CHANNEL_ENABLED(ic) && ic->ic_tx_next_ch)
            {
                ptarget_channel = ic->ic_tx_next_ch;
            } else {
                /*
                 *  1) If nonDFS random is requested then first try selecting a nonDFS
                 *     channel, if not found try selecting a DFS channel.
                 *  2) By default the random selection from both DFS and nonDFS set.
                 */
                if (IEEE80211_IS_CSH_NONDFS_RANDOM_ENABLED(ic)) {
                    flag = DFS_RANDOM_CH_FLAG_NO_DFS_CH;

                    if (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_RESTRICTED_80P80_SUPPORT))
                        flag |= DFS_RANDOM_CH_FLAG_RESTRICTED_80P80_ENABLED;

                    target_chan_freq = mlme_dfs_random_channel(pdev, &ch_params,
                                                               flag);
                }

#if defined(QCA_SUPPORT_ADFS_RCAC)
                if (!target_chan_freq) {
                    /* Since RCAC was running and it had stored a channel by
                     * calling the random channel selection already, do not call
                     * random channel selection again, instead use the channel
                     * already stored by RCAC.
                     * The RCAC enabled check is inside the API.
                     */
                    target_chan_freq = mlme_dfs_get_rcac_channel(pdev, &ch_params);
                }
#endif

                if (!target_chan_freq) {
                    if (dfs_rx_ops && dfs_rx_ops->dfs_is_bw_reduction_needed) {

                        dfs_rx_ops->dfs_is_bw_reduction_needed(pdev, &bw_reduce);

                        if(bw_reduce)
                            target_chan_freq =
                                mlme_dfs_bw_reduced_channel(pdev, &ch_params);
                    }

                    if(!target_chan_freq) {
                        flag = 0;
                        if (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_RESTRICTED_80P80_SUPPORT))
                            flag |= DFS_RANDOM_CH_FLAG_RESTRICTED_80P80_ENABLED;
                        if (ic->ic_no_weather_radar_chan) {
                            flag |= DFS_RANDOM_CH_FLAG_NO_WEATHER_CH;
                        }

                        target_chan_freq =
                            mlme_dfs_random_channel(pdev, &ch_params, flag);
                    }
                }

                if (target_chan_freq) {
                    chan_mode = ieee80211_get_target_channel_mode(ic, &ch_params);
                    ptarget_channel =
                        ieee80211_find_dot11_channel(ic, target_chan_freq,
                                                     ch_params.mhz_freq_seg1,
                                                     chan_mode);
                } else {
                    ptarget_channel = NULL;
                    ic->no_chans_available = 1;
                    qdf_err("%s: vap-%d(%s) channel is not available, bringdown all the AP vaps",
                              __func__,vap->iv_unit,vap->iv_netdev_name);
                    osif_bring_down_vaps(ic, vap);
                }
            }
        }
    }

    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);

    /* If we do have a scan entry, make sure its not an excluded 11D channel.
       See bug 31246 */
    /* No channel was found via scan module, means no good scanlist
       was found */

    if (ptarget_channel)
    {
        if (IEEE80211_IS_CHAN_11AXA_HE160(ptarget_channel)) {
            qdf_print("Changing to HE160 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        } else if (IEEE80211_IS_CHAN_11AXA_HE80_80(ptarget_channel)) {
            qdf_print("Changing to HE80_80 Primary %s channel %d (%d MHz) secondary %s chan %d (center freq %d)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq,
                    IEEE80211_IS_CHAN_DFS_CFREQ2(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_vhtop_ch_num_seg2,
                    ptarget_channel->ic_vhtop_freq_seg2);
        } else if (IEEE80211_IS_CHAN_11AXA_HE80(ptarget_channel)) {
            qdf_print("Changing to HE80 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        } else if (IEEE80211_IS_CHAN_11AXA_HE40(ptarget_channel)) {
            qdf_print("Changing to HE40 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        } else if (IEEE80211_IS_CHAN_11AXA_HE20(ptarget_channel)) {
            qdf_print("Changing to HE20 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        } else if (IEEE80211_IS_CHAN_11AC_VHT160 (ptarget_channel)) {
            qdf_print("Changing to HT160 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        } else if (IEEE80211_IS_CHAN_11AC_VHT80_80(ptarget_channel)) {
            qdf_print("Changing to HT80_80 Primary %s channel %d (%d MHz) secondary %s chan %d (center freq %d)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq,
                    IEEE80211_IS_CHAN_DFS_CFREQ2(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_vhtop_ch_num_seg2,
                    ptarget_channel->ic_vhtop_freq_seg2);
        } else if (IEEE80211_IS_CHAN_11AC_VHT80(ptarget_channel)) {
            qdf_print("Changing to HT80 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        } else if (IEEE80211_IS_CHAN_11AC_VHT40(ptarget_channel)) {
            qdf_print("Changing to HT40 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        } else if (IEEE80211_IS_CHAN_11AC_VHT20(ptarget_channel)) {
            qdf_print("Changing to HT20 %s channel %d (%d MHz)",
                    IEEE80211_IS_CHAN_DFS(ptarget_channel) ? "DFS" : "non-DFS",
                    ptarget_channel->ic_ieee,
                    ptarget_channel->ic_freq);
        }
        /* In case of NOL failure in vap's start response(vap start req given
         * on NOL channel), though the vap is in run state, do not initiate
         * vdev restart on a new channel using CSA in beacon update as
         * transmission on NOL channel is a violation.
         */

        if ((wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) &&
            !(is_vap_start_success(vap)))
        {
            if (pcsaie) {
                ic->ic_chanchange_chan_freq = wlan_reg_chan_band_to_freq(vap->iv_ic->ic_pdev_obj, pcsaie->newchannel,
                                                   BIT(wlan_reg_freq_to_band(ic->ic_curchan->ic_freq)));
                ic->ic_chanchange_tbtt = pcsaie->tbttcount;
            } else {
                ic->ic_chanchange_channel = ptarget_channel;
                ic->ic_chanchange_secoffset =
                    ieee80211_sec_chan_offset(ic->ic_chanchange_channel);
                ic->ic_chanchange_chwidth =
                    ieee80211_get_chan_width(ic->ic_chanchange_channel);
                ic->ic_chanchange_chan_freq = ptarget_channel->ic_freq;
                ic->ic_chanchange_tbtt = ic->ic_chan_switch_cnt;
            }

            if (IEEE80211_IS_CHAN_11AC_VHT160(ptarget_channel)) {
                vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT160;
            }
            if (IEEE80211_IS_CHAN_11AC_VHT80_80(ptarget_channel)) {
                vap->iv_des_cfreq2 =  ptarget_channel->ic_vhtop_freq_seg2;
                vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT80_80;
            }
            if (IEEE80211_IS_CHAN_11AC_VHT80(ptarget_channel)) {
                vap->iv_des_mode   = IEEE80211_MODE_11AC_VHT80;
            }

#ifdef MAGPIE_HIF_GMAC
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                ic->ic_chanchange_cnt += ic->ic_chanchange_tbtt;
            }
#endif
            if (ic->ic_flags & IEEE80211_F_CHANSWITCH) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_DFS, "Channel change is already on");
                return -1;
            }

            ic->ic_flags |= IEEE80211_F_CHANSWITCH;

            wlan_iterate_vap_list(ic, ieee80211_vap_iter_update_des_chan,
                                  ptarget_channel);

            wlan_pdev_mlme_vdev_sm_notify_radar_ind(pdev, ptarget_channel);

        }
        else
        {
            /*
             * vap is not in run  state yet. so
             * change the channel here.
             */
            ic->ic_chanchange_chan_freq = ptarget_channel->ic_freq;

            /* update the bss channel of all the vaps */
            wlan_iterate_vap_list(ic, ieee80211_vap_iter_update_des_chan,
                                  ptarget_channel);
            ic->ic_prevchan = ic->ic_curchan;
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if (tmp_vap->iv_opmode == IEEE80211_M_MONITOR ||
                        (tmp_vap->iv_opmode == IEEE80211_M_HOSTAP)) {
                    if ((wlan_vdev_chan_config_valid(tmp_vap->vdev_obj) !=
                                                       QDF_STATUS_SUCCESS) &&
                        (qdf_atomic_read(&(tmp_vap->iv_is_start_sent)))) {
                        qdf_atomic_set(&(tmp_vap->iv_restart_pending), 1);
                    }
                }
            }
            if (chan_failure)
                 wlan_pdev_mlme_vdev_sm_notify_chan_failure(pdev, ptarget_channel);
            else
                 wlan_pdev_mlme_vdev_sm_notify_radar_ind(pdev, ptarget_channel);

            /*
             * Since Monitor vap is already up, on radar detect VDEV SM would
             * be in CSA restart state. CSA_COMPLETE is required to proceed with
             * multi-vdev restart of all the vdevs of this pdev.
             */
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if (tmp_vap->iv_opmode == IEEE80211_M_MONITOR)
                    mlme_vdev_sm_deliver_csa_complete(tmp_vap->vdev_obj);
            }
        }
    }
    else
    {
        /* should never come here? */
        qdf_print("Cannot change to any channel");
        return 0;
    }
    return 1;
}

void ieee80211_bringup_ap_vaps(struct ieee80211com *ic)
{
    struct ieee80211vap *vap;
    vap = TAILQ_FIRST(&ic->ic_vaps);
    vap->iv_evtable->wlan_bringup_ap_vaps(vap->iv_ifp);
    return;
}

#define IEEE80211_CHECK_IE_SIZE(__x, __y, __z) \
        (__x < sizeof(struct __z) || \
        (__y->length != (sizeof(struct __z) - sizeof(struct __y))))
/* Process CSA/ECSA IE and switch to new announced channel */
int
ieee80211_process_csa_ecsa_ie (
    struct ieee80211_node *ni,
    struct ieee80211_action * pia,
    uint32_t frm_len
    )
{
    struct ieee80211_extendedchannelswitch_ie * pecsaIe = NULL;
    struct ieee80211_ath_channelswitch_ie * pcsaIe = NULL;
    struct ieee80211_ie_sec_chan_offset *psecchanoffsetIe = NULL;
    struct ieee80211_ie_wide_bw_switch  *pwidebwie = NULL;
    struct ieee80211_ie_header *ie_header = NULL;
    u_int8_t *cswrap = NULL;


    struct ieee80211vap *vap = ni->ni_vap;
     struct ieee80211com *ic = ni->ni_ic;

    struct ieee80211_ath_channel* chan = NULL;

    u_int8_t * ptmp1 = NULL;
    int      err = (-EINVAL);

    ASSERT(pia);

    if(!(ic->ic_flags_ext & IEEE80211_FEXT_MARKDFS)){
        return EOK;
        /*Returning EOK to make sure that we dont get disconnect from AP */
    }
    ptmp1 = (u_int8_t *)pia + sizeof(struct ieee80211_action);

    if ((*ptmp1 != IEEE80211_ELEMID_CHANSWITCHANN) &&
            (*ptmp1 != IEEE80211_ELEMID_EXTCHANSWITCHANN)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY, "%s: Wrong IE [%d] received\n",
             __func__, *ptmp1);
        /* unknown CSA Action frame format, but do not disconnect immediately.
           Wait for CSA to be processed correctly in beacons if possible. */
        return EOK;
    }

    /* Find CSA/ECSA/SECOFFSET/WIDEBW IEs from received action frame */
    while (frm_len > 0)
    {
        if (frm_len <= sizeof(struct ieee80211_ie_header))
            break;
        ie_header = (struct ieee80211_ie_header *)ptmp1;

        if (ie_header->length == 0)
            break;

        switch (ie_header->element_id) {
        case IEEE80211_ELEMID_CHANSWITCHANN:
            /* Sanity check for size. */
            if (IEEE80211_CHECK_IE_SIZE(frm_len, ie_header, ieee80211_ath_channelswitch_ie)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s: Invalid IE (%d) size\n",
                        __func__, ie_header->element_id);
                return EOK;
            }
            pcsaIe = (struct ieee80211_ath_channelswitch_ie *)ptmp1;
            ptmp1 += sizeof(struct ieee80211_ath_channelswitch_ie);
            frm_len -= sizeof(struct ieee80211_ath_channelswitch_ie);
            break;
        case IEEE80211_ELEMID_EXTCHANSWITCHANN:
            /* Sanity check for size. */
            if (IEEE80211_CHECK_IE_SIZE(frm_len, ie_header, ieee80211_extendedchannelswitch_ie)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s: Invalid IE (%d) size\n",
                        __func__, ie_header->element_id);
                return EOK;
            }
            pecsaIe = (struct ieee80211_extendedchannelswitch_ie *)ptmp1;
            ptmp1 += sizeof(struct ieee80211_extendedchannelswitch_ie);
            frm_len -= sizeof(struct ieee80211_extendedchannelswitch_ie);
            break;
        case IEEE80211_ELEMID_SECCHANOFFSET:
            /* Sanity check for size. */
            if (IEEE80211_CHECK_IE_SIZE(frm_len, ie_header, ieee80211_ie_sec_chan_offset)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s: Invalid IE (%d) size\n",
                        __func__, ie_header->element_id);
                return EOK;
            }
            psecchanoffsetIe = (struct ieee80211_ie_sec_chan_offset *)ptmp1;
            ptmp1 += sizeof(struct ieee80211_ie_sec_chan_offset);
            frm_len -= sizeof(struct ieee80211_ie_sec_chan_offset);
            break;
        case IEEE80211_ELEMID_WIDE_BAND_CHAN_SWITCH:
            /* Sanity check for size. */
            if (IEEE80211_CHECK_IE_SIZE(frm_len, ie_header, ieee80211_ie_wide_bw_switch)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s: Invalid IE (%d) size\n",
                        __func__, ie_header->element_id);
                return EOK;
            }
            pwidebwie = (struct ieee80211_ie_wide_bw_switch *)ptmp1;
            ptmp1 += sizeof(struct ieee80211_ie_wide_bw_switch);
            frm_len -= sizeof(struct ieee80211_ie_wide_bw_switch);
            break;
        case IEEE80211_ELEMID_CHAN_SWITCH_WRAP:
            /* support is only for WIDEBW IE, iterating over the wrapper for now */
            cswrap = ptmp1;
            ptmp1 += sizeof(struct ieee80211_ie_header);
            frm_len -=  sizeof(struct ieee80211_ie_header);
            break;
        case IEEE80211_ELEMID_VHT_TX_PWR_ENVLP:
        case 118: /* MESH CHANNEL SWITCH PARAMETERS */
        case IEEE80211_ELEMID_COUNTRY:
            /* These IEs maybe received but are not processed for channel switch. iterating */
            ptmp1 += (ie_header->length + sizeof(struct ieee80211_ie_header));
            frm_len -= (ie_header->length + sizeof(struct ieee80211_ie_header));
            break;
        default:
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACTION, "%s: Invalid IE (%d) in CSA ACTION\n",
                    __func__, ie_header->element_id);
            return EOK;
            break;
        } /* End of switch case */
    }

    chan = ieee80211_get_new_sw_chan (ni, pcsaIe, pecsaIe, psecchanoffsetIe, pwidebwie, cswrap);
    ieee80211_mgmt_sta_send_csa_rx_nl_msg(ic, ni, chan, pcsaIe, pecsaIe, psecchanoffsetIe, pwidebwie);

    if(!chan)
        return EOK;

     /*
     * Set or clear flag indicating reception of channel switch announcement
     * in this channel. This flag should be set before notifying the scan
     * algorithm.
     * We should not send probe requests on a channel on which CSA was
     * received until we receive another beacon without the said flag.
     */
    if ((pcsaIe != NULL) || (pecsaIe != NULL)) {
        ic->ic_curchan->ic_flagext |= IEEE80211_CHAN_CSA_RECEIVED;
    }

    if (chan && (pcsaIe || pecsaIe)) {
        /*
         * For Station, just switch channel right away.
         */
        if (!IEEE80211_IS_CHAN_SWITCH_STARTED(ic) &&
            (chan != vap->iv_bsschan))
        {
            if (pcsaIe)
                    ni->ni_chanswitch_tbtt = pcsaIe->tbttcount;
            else if (pecsaIe)
                    ni->ni_chanswitch_tbtt = pecsaIe->tbttcount;

                    /*
             * Issue a channel switch request to resource manager.
             * If the function returns EOK (0) then its ok to change the channel synchronously
             * If the function returns EBUSY then resource manager will
             * switch channel asynchronously and post an event event handler registred by vap and
             * vap handler will inturn do the rest of the processing involved.
                     */
            err = ieee80211_resmgr_request_chanswitch(ic->ic_resmgr, vap, chan, MLME_REQ_ID);

            if (err == EOK) {
                /*
                 * Start channel switch timer to change the channel
                 */
                IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                               "%s: Received CSA action frame \n",__func__);
                ni->ni_capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;
                ieee80211_process_csa(ni, chan, pcsaIe, pecsaIe, NULL);
            } else if (err == EBUSY) {
                err = EOK;
            }
        }
    }
    IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                   "%s: Exited.\n",__func__
                   );

    return err;
}

u_int8_t *
ieee80211_add_mmie(struct ieee80211vap *vap, u_int8_t *bfrm, u_int32_t len)
{
    return wlan_crypto_add_mmie(vap->vdev_obj, bfrm, len);
}

void
ieee80211_set_vht_rates(struct ieee80211com *ic, struct ieee80211vap  *vap)
{
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap),
             rx_streams = ieee80211_get_rxstreams(ic, vap);
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t bcc_11ng_256qam_20mhz_s = 0;
    uint32_t iv_ldpc = vap->vdev_mlme->proto.generic.ldpc;

    bcc_11ng_256qam_20mhz_s = IEEE80211_IS_CHAN_11NG(ic->ic_curchan) &&
                                ieee80211_vap_256qam_is_set(vap) &&
                                (iv_ldpc == IEEE80211_HTCAP_C_LDPC_NONE) &&
                                (ic_cw_width == IEEE80211_CWM_WIDTH20);
    /* Adjust supported rate set based on txchainmask */
    switch (tx_streams) {
        default:
            /* Default to single stream */
        case 1:
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_9; /* MCS 0-9 */
            }
            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS1_MASK);
            }
        break;

        case 2:
            /* Dual stream */
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_9; /* MCS 0-9 */
            }
            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS2_MASK);
            }
        break;

        case 3:
            /* Tri stream */
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS3_MCS0_9; /* MCS 0-9 */
            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS3_MASK);
            }
        break;
        case 4:
        /* four stream */
             /*MCS9 is not supported for BCC, NSS=1,2,4 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_9; /* MCS 0-9 */
            }
            if (vap->iv_vht_tx_mcsmap) {
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS4_MASK);
            }
        break;
#if QCA_SUPPORT_5SS_TO_8SS
       /* 8 chain TODO: As of QCA8074, VHT in 2.4 GHz for NSS > 4 is not
        * supported. Hence this case is not treated separately. However, if
        * future chipsets add support, then add required processing for
        * tx_streams values 5-8 according to the applicable LDPC capabilities.
        */
        case 5:
        /* five stream */
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS5_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                    (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS5_MASK);
            }
        break;

        case 6:
        /* six stream */
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS6_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                    (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS6_MASK);
            }
        break;

        case 7:
        /* seven stream */
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS7_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                    (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS7_MASK);
            }
        break;

        case 8:
        /* eight stream */
            vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS8_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_tx_mcsmap) {
                vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map =
                    (vap->iv_vht_tx_mcsmap | VHT_MCSMAP_NSS8_MASK);
            }
        break;
#endif /* QCA_SUPPORT_5SS_TO_8SS */
    } /* end switch */

    /* Adjust rx rates based on the rx chainmask */
    switch (rx_streams) {
        default:
            /* Default to single stream */
        case 1:
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS1_MCS0_9;
            }
            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS1_MASK);
            }
        break;

        case 2:
            /* Dual stream */
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS2_MCS0_9;
            }
            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS2_MASK);
            }
        break;

        case 3:
            /* Tri stream */
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS3_MCS0_9;
            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS3_MASK);
            }
        break;
        case 4:
        /* four stream */
             /*MCS9 is not supported for BCC, NSS=1,2 in 20Mhz */
            /* if ldpc disabled, then allow upto MCS 8 */
            if(bcc_11ng_256qam_20mhz_s && !iv_ldpc) {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_8; /* MCS 0-8 */
            }
            else {
                 vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map = VHT_MCSMAP_NSS4_MCS0_9;
            }
            if (vap->iv_vht_rx_mcsmap) {
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS4_MASK);
            }
        break;
#if QCA_SUPPORT_5SS_TO_8SS
       /* 8 chain TODO: As of QCA8074, VHT in 2.4 GHz for NSS > 4 is not
        * supported. Hence this case is not treated separately. However, if
        * future chipsets add support, then add required processing for
        * tx_streams values 5-8 according to the applicable LDPC capabilities.
        */
        case 5:
        /* five stream */
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS5_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                    (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS5_MASK);
            }
        break;

        case 6:
        /* six stream */
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS6_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                    (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS6_MASK);
            }
        break;

        case 7:
        /* seven stream */
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS7_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                    (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS7_MASK);
            }
        break;

        case 8:
        /* eight stream */
            vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                VHT_MCSMAP_NSS8_MCS0_9; /* MCS 0-9 */

            if (vap->iv_vht_rx_mcsmap) {
                vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map =
                    (vap->iv_vht_rx_mcsmap | VHT_MCSMAP_NSS8_MASK);
            }
        break;
#endif /* QCA_SUPPORT_5SS_TO_8SS */
    }
    if(vap->iv_configured_vht_mcsmap) {
        /* rx and tx vht mcs will be same for iv_configured_vht_mcsmap option */
        /* Assign either rx or tx mcs map back to this variable so that iwpriv get operation prints exact value */
        vap->iv_configured_vht_mcsmap = vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map;
    }
    vap->iv_set_vht_mcsmap = true;
}

#ifdef MU_CAP_WAR_ENABLED
/*
 * This function updates the VHTCAP based on the
 * MU-CAP WAR variable status
 */
static inline u_int32_t mu_cap_war_probe_response_change(u_int32_t vhtcap_info,
                                             u_int8_t subtype,
                                             struct ieee80211vap  *vap,
                                             struct ieee80211_node *ni,
                                             struct ieee80211com *ic,
                                             u_int8_t *sta_mac_addr,
                                             MU_CAP_WAR *war)
{
    struct DEDICATED_CLIENT_MAC *dedicated_mac = NULL;
    int hash;
    u_int32_t vhtcap_info_modified = vhtcap_info;
    if (!war->mu_cap_war ||
        !war->modify_probe_resp_for_dedicated ||
        !ni->dedicated_client ||
        (subtype !=  IEEE80211_FC0_SUBTYPE_PROBE_RESP) ||
        (!(vhtcap_info&IEEE80211_VHTCAP_MU_BFORMER))) {

        /*
         * No need to change the existing VHT-CAP
         * or do any further processing
         */
        return vhtcap_info;
    }

    /*
     * Hacking the VHT-CAP so that
     * the dedicated client joins as SU-2x2
     */
    vhtcap_info_modified &= ~IEEE80211_VHTCAP_MU_BFORMER;

    if (sta_mac_addr == NULL) {
        ieee80211_note(vap, IEEE80211_MSG_ANY,
                      "ERROR!!! NULL STA_MAC_ADDR Passed to %s\n",
                      __func__);
        return vhtcap_info;
    }

    hash = IEEE80211_NODE_HASH(sta_mac_addr);
    LIST_FOREACH(dedicated_mac, &war->dedicated_client_list[hash], list) {
        if (IEEE80211_ADDR_EQ(dedicated_mac->macaddr, sta_mac_addr)) {

            /*
             * Entry already present, no need to add again
             */
            return vhtcap_info_modified;
        }
    }


    /*
     * Have at the most, twice as many floating ProbeResponse-hacked clients
     * as the number of clients supported
     * The multiply-by-2 is an arbitrary ceiling limit. To remove
     * this limit, there should be timer logic to periodically flush
     * out old Probe-Response-hacked clients from the database.
     * At this point this does not seem to be a priority.
     */
    if (war->dedicated_client_number >= (MAX_PEER_NUM*2)) {
        ieee80211_note(vap, IEEE80211_MSG_ANY,
                "ERROR!! Too many floating PR clients, we might run out of %s",
                "memory if we keep adding these clients to DB\n");
        return vhtcap_info;
    }

    /*
     * Maintain the list of clients to which
     * we send this 'hacked' VHTCAP in probe response
     */
    dedicated_mac =
        OS_MALLOC(ic->ic_osdev, sizeof(*dedicated_mac), 0);
    if (dedicated_mac == NULL) {
        ieee80211_note(vap, IEEE80211_MSG_ANY, "ERROR!! Memory allocation failed in %s\n",
                __func__);
        return vhtcap_info;
    }
    OS_MEMSET(dedicated_mac, 0, sizeof(*dedicated_mac));
    OS_MEMCPY(dedicated_mac->macaddr, sta_mac_addr,
            sizeof(dedicated_mac->macaddr));
    war->dedicated_client_number++;
    LIST_INSERT_HEAD(&war->dedicated_client_list[hash], dedicated_mac, list);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
            "Adding %s to modified probe-resp list\n",
                    ether_sprintf(sta_mac_addr));
    return vhtcap_info_modified;
}
#endif

u_int8_t *
ieee80211_add_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype,
                     struct ieee80211_framing_extractx *extractx,
                     u_int8_t *sta_mac_addr)
{
    int vhtcaplen = sizeof(struct ieee80211_ie_vhtcap);
    struct ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)frm;
    struct ieee80211vap  *vap = ni->ni_vap;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    u_int32_t vhtcap_info;
    u_int32_t ni_vhtbfeestscap;
    u_int8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap);
    ieee80211_vht_rate_t ni_tx_vht_rates;
    struct supp_tx_mcs_extnss tx_mcs_extnss_cap;
    u_int16_t temp;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);
    enum ieee80211_phymode cur_mode;
    struct wlan_objmgr_pdev *pdev = NULL;
    struct wlan_objmgr_psoc *psoc = NULL;
    u_int8_t chwidth = 0;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);

    pdev = ic->ic_pdev_obj;
    if (pdev) {
        psoc = wlan_pdev_get_psoc(pdev);
        if (!psoc)
            qdf_err("null psoc");
    } else {
        qdf_err("null pdev");
    }

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    vhtcap->elem_id   = IEEE80211_ELEMID_VHTCAP;
    vhtcap->elem_len  = sizeof(struct ieee80211_ie_vhtcap) - 2;

    /* Choose between the STA from advertising negotiated channel width
     * caps and advertising it's desired channel width caps */
    if (vap->iv_sta_max_ch_cap) {
        cur_mode = vap->iv_des_mode;
    } else {
        cur_mode = vap->iv_cur_mode;
    }

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic_cw_width;
    }

    /* Fill in the VHT capabilities info */
    vhtcap_info = ic->ic_vhtcap;

    /* Use firmware short GI capability if short GI is enabled on this vap.
     * Else clear short GI for both 80 and 160 MHz.
     */
    if (!vap->iv_sgi) {
        vhtcap_info &= ~(IEEE80211_VHTCAP_SHORTGI_80 | IEEE80211_VHTCAP_SHORTGI_160);
    } else if(chwidth <= IEEE80211_CWM_WIDTH80) {
        vhtcap_info &= ~(IEEE80211_VHTCAP_SHORTGI_160);
    }

    vhtcap_info &= ((vdev_mlme->proto.generic.ldpc & IEEE80211_HTCAP_C_LDPC_RX) ?
            ic->ic_vhtcap  : ~IEEE80211_VHTCAP_RX_LDPC);


    if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
        (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Check negotiated Rx NSS */
        ieee80211_get_vht_rates(ni->ni_rx_vhtrates, &ni_tx_vht_rates);
        rx_streams = MIN(rx_streams, ni_tx_vht_rates.num_streams);
    }

    /* Adjust the TX and RX STBC fields based on the chainmask and config status */
    vhtcap_info &= (((vap->iv_tx_stbc) && (tx_streams > 1)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_TX_STBC);
    vhtcap_info &= (((vap->iv_rx_stbc) && (rx_streams > 0)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_RX_STBC);

    /* Support WFA R1 test case -- beamformer & nss =1*/
    if(tx_streams > 1)
    {
        vhtcap_info &= ((vdev_mlme->proto.vht_info.subfer) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_SU_BFORMER);
    }else{
        vhtcap_info &= (((vdev_mlme->proto.vht_info.subfer) && (vdev_mlme->proto.vht_info.subfee)
                         && (vdev_mlme->proto.vht_info.mubfer == 0)
                         &&(vdev_mlme->proto.vht_info.mubfee == 0) && (vdev_mlme->proto.generic.nss == 1)) ?
                         ic->ic_vhtcap : ~IEEE80211_VHTCAP_SU_BFORMER);
    }
    vhtcap_info &= ((vdev_mlme->proto.vht_info.subfee) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_SU_BFORMEE);



    /* if SU Beamformer/Beamformee is not set then MU Beamformer/Beamformee need to be disabled */
    vhtcap_info &= (((vdev_mlme->proto.vht_info.subfer) && (vdev_mlme->proto.vht_info.mubfer)
                && (tx_streams > 1)) ?  ic->ic_vhtcap : ~IEEE80211_VHTCAP_MU_BFORMER);
#ifdef MU_CAP_WAR_ENABLED
    vhtcap_info = mu_cap_war_probe_response_change(vhtcap_info, subtype,
                                                   vap, ni, ic, sta_mac_addr,
                                                   &vap->iv_mu_cap_war);
    ni->dedicated_client = 0;
#endif

    /* For Lithium chipsets and above, don't limit/disable
     * MUBFEE capability based on total no of of rxstreams
     */
    if(ic->ic_no_bfee_limit) {
        vhtcap_info &= (((vdev_mlme->proto.vht_info.subfee)
                        && (vdev_mlme->proto.vht_info.mubfee)) ?
                        ic->ic_vhtcap : ~IEEE80211_VHTCAP_MU_BFORMEE);
    } else {
        vhtcap_info &= (((vdev_mlme->proto.vht_info.subfee)
                        && (vdev_mlme->proto.vht_info.mubfee) && (rx_streams < 3)) ?
                        ic->ic_vhtcap : ~IEEE80211_VHTCAP_MU_BFORMEE);
    }

    vhtcap_info &= ~(IEEE80211_VHTCAP_STS_CAP_M << IEEE80211_VHTCAP_STS_CAP_S);
    if ((extractx != NULL) &&
        (extractx->fectx_nstscapwar_reqd == true) &&
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Using client's NSTS CAP value for assoc response */
        ni_vhtbfeestscap = ((ni->ni_vhtcap >> IEEE80211_VHTCAP_STS_CAP_S) &
                                IEEE80211_VHTCAP_STS_CAP_M );
        vhtcap_info |= (((vdev_mlme->proto.vht_info.bfee_sts_cap <= ni_vhtbfeestscap) ? vdev_mlme->proto.vht_info.bfee_sts_cap:ni_vhtbfeestscap) << IEEE80211_VHTCAP_STS_CAP_S);
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_ASSOC, "%s:nsts war:: vap_stscap %#x,ni_stscap %#x,vhtcap:%#x\n",__func__, vdev_mlme->proto.vht_info.bfee_sts_cap,ni_vhtbfeestscap,vhtcap_info);
    }else {
        vhtcap_info |= vdev_mlme->proto.vht_info.bfee_sts_cap << IEEE80211_VHTCAP_STS_CAP_S;
    }
    vhtcap_info &= ~IEEE80211_VHTCAP_SOUND_DIM;
    if((vdev_mlme->proto.vht_info.subfer) && (tx_streams > 1)) {
        vhtcap_info |= ((vdev_mlme->proto.vht_info.sounding_dimension < (tx_streams - 1)) ?
                        vdev_mlme->proto.vht_info.sounding_dimension : (tx_streams - 1)) << IEEE80211_VHTCAP_SOUND_DIM_S;
    }

    /* Clear supported chanel width first */
    vhtcap_info &= ~(IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
                     IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 | IEEE80211_VHTCAP_EXT_NSS_BW_SUPPORT_MASK);

    /* Set supported chanel width as per current operating mode.
     * We don't need to check for HW/FW announced channel width
     * capability as this is already verified in service_ready_event.
     */

    if (!vap->iv_ext_nss_support ||
        (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ && !ni->ni_ext_nss_support)) {
        if (ieee80211_is_phymode_8080(cur_mode)) {
            vhtcap_info |= IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160;
        } else if (ieee80211_is_phymode_160(cur_mode)) {
            vhtcap_info |= IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160;
        }
    } else if (!ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
        /* If AP supports EXT NSS Signaling, set vhtcap ie to
         * IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE,
         * IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5,
         * IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1 or
         * IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE
         * as they are the only valid combination for our chipsets.
         */

        if (ieee80211_is_phymode_8080(cur_mode)) {
            if (nssmap.flag == IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW) {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1;
            } else if (nssmap.flag == IEEE80211_NSSMAP_1_2_FOR_160_AND_80_80) {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5;
            } else {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75;
            }
        } else if (ieee80211_is_phymode_160(cur_mode)) {
            if (nssmap.flag == IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW) {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE;
            } else if (nssmap.flag == IEEE80211_NSSMAP_1_2_FOR_160_AND_80_80) {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE;
            } else {
                vhtcap_info |= IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75;
            }
        }
    }

    /* We currently honor a 160 MHz association WAR request from callers only
     * for IEEE80211_FC0_SUBTYPE_PROBE_RESP and IEEE80211_FC0_SUBTYPE_ASSOC_RESP.
     */
    if ((extractx != NULL) &&
        (extractx->fectx_assocwar160_reqd == true) &&
        ((subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) ||
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP))) {
       /* Remove all indications of 160 MHz capability, to enable the STA to
        * associate.
        */
       vhtcap_info &= ~(IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 |
                        IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
                        IEEE80211_VHTCAP_SHORTGI_160);
    }

#if WAR_DISABLE_MU_2x2_STA
    /* If Disable MU-MIMO WAR is enabled, disable Beamformer in Assoc Resp */
    if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) &&
        (((ni->ni_vhtcap & IEEE80211_VHTCAP_SOUND_DIM) >> IEEE80211_VHTCAP_SOUND_DIM_S) == 1)) {
        vhtcap_info &= ~(IEEE80211_VHTCAP_SOUND_DIM | IEEE80211_VHTCAP_MU_BFORMER);
    }
#endif

    vhtcap->vht_cap_info = htole32(vhtcap_info);

    /* Fill in the VHT MCS info */
    ieee80211_set_vht_rates(ic,vap);
    vhtcap->rx_high_data_rate = htole16(vap->iv_vhtcap_max_mcs.rx_mcs_set.data_rate);
    tx_mcs_extnss_cap.tx_high_data_rate = (vap->iv_vhtcap_max_mcs.tx_mcs_set.data_rate);
    vhtcap->tx_mcs_map = htole16(vap->iv_vhtcap_max_mcs.tx_mcs_set.mcs_map);
    if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) {
        if(!((ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160)||
             (ni->ni_vhtcap & IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160))) {
            /* if not 160, advertise rx mcs map as per vap max */
            vhtcap->rx_mcs_map = htole16(vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map);
        } else {
            /* if 160 , advertise rx mcs map as of ni ( negotiated ap) rx mcs map*/
            vhtcap->rx_mcs_map = htole16(ni->ni_rx_vhtrates);
        }
    } else if((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) &&
                                    !(ni->ni_ext_nss_capable)) {
        /* Extended NSS capable client will determine 160MHz SS support
         * based on Extended NSS signaling in VHT cap.
         */
        vhtcap->rx_mcs_map = htole16(ni->ni_rx_vhtrates);
    } else {
        vhtcap->rx_mcs_map = htole16(vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map);
    }

    if ((subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) &&
        psoc && (cfg_get(psoc, CFG_OL_SET_MAX_RX_MCS_MAP))) {
        /* advertise rx mcs map as per vap max */
        vhtcap->rx_mcs_map = htole16(vap->iv_vhtcap_max_mcs.rx_mcs_set.mcs_map);
    }

    tx_mcs_extnss_cap.ext_nss_capable = !!(ic->ic_ext_nss_capable);
    tx_mcs_extnss_cap.reserved = 0;
    temp = htole16(*(u_int16_t *)&tx_mcs_extnss_cap);
    OS_MEMCPY(&vhtcap->tx_mcs_extnss_cap, &temp, sizeof(u_int16_t));
    return frm + vhtcaplen;
}

u_int8_t *
ieee80211_add_interop_vhtcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype)
{
    int vht_interopcaplen = sizeof(struct ieee80211_ie_interop_vhtcap);
    struct ieee80211_ie_interop_vhtcap *vht_interopcap = (struct ieee80211_ie_interop_vhtcap *)frm;
    static const u_int8_t oui[4] = { VHT_INTEROP_OUI_BYTES, VHT_INTEROP_TYPE};

    vht_interopcap->elem_id   = IEEE80211_ELEMID_VENDOR;
    if ((subtype == IEEE80211_FC0_SUBTYPE_BEACON)||(subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) ||
                                                   (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)) {
        vht_interopcap->elem_len  = sizeof(struct ieee80211_ie_interop_vhtcap) - 2;
        vht_interopcaplen =  sizeof(struct ieee80211_ie_interop_vhtcap);
    }
    else {
        vht_interopcap->elem_len  = sizeof(struct ieee80211_ie_interop_vhtcap) - 9; /* Eliminating Vht op IE */
        vht_interopcaplen =  sizeof(struct ieee80211_ie_interop_vhtcap) - 7;
    }

    /* Fill in the VHT capabilities info */
    memcpy(&vht_interopcap->vht_interop_oui,oui,sizeof(oui));
    vht_interopcap->sub_type = ni->ni_vhtintop_subtype;
    ieee80211_add_vhtcap(frm + 7 , ni, ic, subtype, NULL, NULL); /* Vht IE location Inside Vendor specific VHT IE*/


    if ((subtype == IEEE80211_FC0_SUBTYPE_BEACON)||(subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) ||
                                                   (subtype == IEEE80211_FC0_SUBTYPE_REASSOC_RESP)) {
       ieee80211_add_vhtop(frm + 21 , ni, ic, subtype, NULL); /* Adding Vht Op IE after Vht cap IE  inside Vendor VHT IE*/
    }
    return frm + vht_interopcaplen;
}


u_int8_t *
ieee80211_add_vhtop(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype,
                    struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_ie_vhtop *vhtop = (struct ieee80211_ie_vhtop *)frm;
    int vhtoplen = sizeof(struct ieee80211_ie_vhtop);
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t chwidth = 0, negotiate_bw = 0;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    qdf_mem_zero(&nssmap, sizeof(nssmap));

    vhtop->elem_id   = IEEE80211_ELEMID_VHTOP;
    vhtop->elem_len  = sizeof(struct ieee80211_ie_vhtop) - 2;

    ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask);

    if((ni->ni_160bw_requested == 1) && (IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) ||
                IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan)) &&
            (ni->ni_chwidth == IEEE80211_VHTOP_CHWIDTH_80) &&
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Set negotiated BW */
        chwidth = ni->ni_chwidth;
        negotiate_bw = 1;
    } else {
       if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
           chwidth = vap->iv_chwidth;
       } else {
           chwidth = ic_cw_width;
       }
    }

    /* Fill in the VHT Operation info */
    if (chwidth == IEEE80211_CWM_WIDTH160) {
        if (vap->iv_rev_sig_160w) {
            if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80;
            else
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_REVSIG_160;
        } else {
            if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_80_80;
            else
                vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_160;
        }
    }
    else if (chwidth == IEEE80211_CWM_WIDTH80)
        vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_80;
    else
        vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_2040;

    if (negotiate_bw == 1) {

            vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_num_seg1;
            /* Note: This is applicable only for 80+80Mhz mode */
            vhtop->vht_op_ch_freq_seg2 = 0;
    }
    else {
        if (chwidth == IEEE80211_CWM_WIDTH160) {

            if (vap->iv_rev_sig_160w) {
                /* Our internal channel structure is in sync with
                 * revised 160 MHz signalling. So use seg1 and
                 * seg2 directly for 80_80 and 160.
                 */
                if (vap->iv_ext_nss_support && (!(nssmap.flag == IEEE80211_NSSMAP_SAME_NSS_FOR_ALL_BW))) {
                    /* If EXT NSS is enabled in driver, vht_op_ch_freq_seq2
                     * has to be populated in htinfo IE, for the combination of NSS values
                     * for 80, 160 and 80+80 MHz which our hardware supports.
                     * Exception to this is when AP is forced to come up with same NSS value for
                     * both 80+80MHz and 160MHz */
                    vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_num_seg1;
                    vhtop->vht_op_ch_freq_seg2 = 0;
                } else {
                    vhtop->vht_op_ch_freq_seg1 =
                           vap->iv_bsschan->ic_vhtop_ch_num_seg1;

                    vhtop->vht_op_ch_freq_seg2 =
                        vap->iv_bsschan->ic_vhtop_ch_num_seg2;
                }
            } else {
                /* Use legacy 160 MHz signaling */
                if(IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan)) {
                    /* ic->ic_curchan->ic_vhtop_ch_num_seg2 is centre
                     * frequency for whole 160 MHz.
                     */
                    vhtop->vht_op_ch_freq_seg1 =
                        vap->iv_bsschan->ic_vhtop_ch_num_seg2;
                    vhtop->vht_op_ch_freq_seg2 = 0;
                } else {
                    /* 80 + 80 MHz */
                    vhtop->vht_op_ch_freq_seg1 =
                        vap->iv_bsschan->ic_vhtop_ch_num_seg1;

                    vhtop->vht_op_ch_freq_seg2 =
                        vap->iv_bsschan->ic_vhtop_ch_num_seg2;
                }
            }
       } else { /* 80MHZ or less */
            vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_num_seg1;
            vhtop->vht_op_ch_freq_seg2 = 0;
        }
    }


    /* We currently honor a 160 MHz association WAR request from callers only for
     * IEEE80211_FC0_SUBTYPE_PROBE_RESP and IEEE80211_FC0_SUBTYPE_ASSOC_RESP, and
     * check if our current channel is for 160/80+80 MHz.
     */
    if ((!vap->iv_rev_sig_160w) && (extractx != NULL) &&
        (extractx->fectx_assocwar160_reqd == true) &&
        ((subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) ||
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) &&
        (IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) ||
            IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))) {
       /* Remove all indications of 160 MHz capability, to enable the STA to
        * associate.
        *
        * Besides, we set vht_op_chwidth to IEEE80211_VHTOP_CHWIDTH_80 without
        * checking if preceeding code had set it to lower value negotiated with
        * STA. This is for logical conformance with older VHT AP behaviour
        * wherein width advertised would remain constant across probe response
        * and assocation response.
        */

        /* Downgrade to 80 MHz */
        vhtop->vht_op_chwidth = IEEE80211_VHTOP_CHWIDTH_80;

        vhtop->vht_op_ch_freq_seg1 = vap->iv_bsschan->ic_vhtop_ch_num_seg1;
        vhtop->vht_op_ch_freq_seg2 = 0;
    }

    /* Fill in the VHT Basic MCS set */
    vhtop->vhtop_basic_mcs_set =  htole16(ic->ic_vhtop_basic_mcs);

    if (vap->iv_csa_interop_bss_active) {
        vhtop->vht_op_chwidth = 0;
    }

    return frm + vhtoplen;
}

/**
* @ieee80211_get_tpe_count(): Calculate # of Tx Pwr values to be added based
*                             based on Tx Pwr count and interpretation
*
* @param txpwr_cnt            Max Tx Power count
* @param txpwr_intrprt        Max Tx Power interpretation
*
* @return calculated count value
*/
int8_t ieee80211_get_tpe_count(u_int8_t txpwr_intrprt, u_int8_t txpwr_cnt)
{
    switch (txpwr_intrprt) {
        case IEEE80211_TPE_LOCAL_EIRP:
        case IEEE80211_TPE_REG_EIRP:
            /* Max Tx Power Count subfield and corresponding
             * number of Tx Pwr values when Max Tx Power interpretation
             * subfield is IEEE80211_TPE_LOCAL_EIRP(0) or IEEE80211_TPE_REG_EIRP(2)
             *
             *    Count Subfield    |    # of Tx Pwr Values
             * -------------------------------------------------
             *          0           |    1 (Max Tx Pwr for 20MHz)
             *          1           |    2 (Max Tx Pwr for 20/40MHz)
             *          2           |    3 (Max Tx Pwr for 20/40/80MHz)
             *          3           |    4 (Max Tx Pwr for 20/40/80/160MHz)
             *         4-7          |    Reserved
             */
            if (txpwr_cnt > IEEE80211_TPE_EIRP_MAX_POWER_COUNT) {
                qdf_err("Invalid Tx Power count %d for Tx Power interpretation %d"
                        "Maximum Tx Power Count allowed: %d",
                        txpwr_cnt, txpwr_intrprt,
                        IEEE80211_TPE_EIRP_MAX_POWER_COUNT);
                return - EINVAL;
            }
            txpwr_cnt = txpwr_cnt + 1;
        break;

        case IEEE80211_TPE_LOCAL_EIRP_PSD:
        case IEEE80211_TPE_REG_EIRP_PSD:
            /* Max Tx Power Count subfield and corresponding
             * number of Tx Pwr values when Max Tx Power interpretation
             * subfield is IEEE80211_TPE_LOCAL_EIRP_PSD(1) or
             * IEEE80211_TPE_REG_EIRP_PSD(3).
             *
             *    Count Subfield    |    # of Tx Pwr Values
             * -------------------------------------------------
             *          0           |    1 (Same Max Tx Pwr for all 20MHz bands)
             *          1           |    1 (Max Tx Pwr per 20MHz)
             *          2           |    2 (Max Tx Pwr per 20MHz)
             *          3           |    4 (Max Tx Pwr per 20MHz)
             *          4           |    8 (Max Tx Pwr per 20MHz)
             *         5-7          |    Reserved
             */
            if (txpwr_cnt > IEEE80211_TPE_PSD_MAX_POWER_COUNT) {
                qdf_err("Invalid Tx Power count %d for Tx Power interpretation %d"
                        "Maximum Tx Power Count allowed: %d",
                        txpwr_cnt, txpwr_intrprt,
                        IEEE80211_TPE_EIRP_MAX_POWER_COUNT);
                return - EINVAL;
            }
            txpwr_cnt = txpwr_cnt ? (BIT(txpwr_cnt - 1)) : 1;
        break;

        default:
            qdf_err("Invalid Max Power Interpretation value: %d",
                    txpwr_intrprt);
        break;
    }

    return txpwr_cnt;
}

/**
* @ieee80211_add_tpe_info(): Add TPE IE
*
* @param frm            frame in which this sub element should be added
* @param count          Max Tx Power count
* @param intrprt        Max Tx Power interpretation
* @param category       Max Tx Power category
* @param tx_pwr         pointer to Max Tx Power values
*
* @return pointer       updated frm pointer
*/
u_int8_t *
ieee80211_add_tpe_info(u_int8_t *frm, u_int8_t count, u_int8_t intrprt,
                        u_int8_t category, u_int8_t *tx_pwr)
{
    struct ieee80211_ie_vht_txpwr_env *txpwr =
                        (struct ieee80211_ie_vht_txpwr_env *)frm;

    /* Since Max Tx Pwr Category field is invalid for 5G/2.4G,
     * clear the interpretation bits.
     */
    category = (category == REG_MAX_CLIENT_TYPE) ? 0 : category;

    txpwr->elem_id = IEEE80211_ELEMID_VHT_TX_PWR_ENVLP;

    txpwr->tpe_payload.tpe_info_cnt = count;
    txpwr->tpe_payload.tpe_info_intrpt = intrprt;
    txpwr->tpe_payload.tpe_info_cat = category;

    count = ieee80211_get_tpe_count(intrprt, count);
    qdf_mem_copy(txpwr->tpe_payload.local_max_txpwr, tx_pwr, count);

    txpwr->elem_len =
        ((sizeof(struct ieee80211_ie_vht_txpwr_env) - IEEE80211_IE_HDR_LEN) -
               (IEEE80211_TPE_NUM_POWER_SUPPORTED - count));

    frm = frm + (txpwr->elem_len + IEEE80211_IE_HDR_LEN);

    return frm;
}

/**
* @ieee80211_add_lower_band_tpe(): Derive TPE arguments for 5GHz/2.4GHz
*
* @param frm            frame in which this sub element should be added
* @param ic             pointer to iee80211com
* @param channel        pointer to channel information
*
* @return pointer       updated frm pointer
*/
u_int8_t *
ieee80211_add_lower_band_tpe(u_int8_t *frm, struct ieee80211com *ic,
                                struct ieee80211_ath_channel *channel)
{
    u_int8_t max_pwr_abs;  /* Absolute value of max regulatory tx power*/
    u_int8_t max_pwr_fe;   /* Final Encoded value of regulatory tx power */
    u_int8_t txpwr_count, txpwr_int, txpwr_cat;
    u_int8_t txpwr_val[IEEE80211_TPE_EIRP_NUM_POWER_SUPPORTED] = {};
    bool is_160_or_80p80_supported = false;
    uint8_t iter;

    /* Update Max Tx Pwr Information for adding lower band TPE IE */

    /* Default Max Tx Pwr Interpretation for 5GHz/2.4GHz is Local EIRP */
    txpwr_int = IEEE80211_TPE_LOCAL_EIRP;

    if (ic->ic_modecaps &
                ((1 << IEEE80211_MODE_11AC_VHT160) |
                 (1 << IEEE80211_MODE_11AC_VHT80_80))) {
        is_160_or_80p80_supported = true;
    }

    if (is_160_or_80p80_supported) {
        txpwr_count = IEEE80211_TPE_EIRP_MAX_POWER_COUNT;
    }
    else {
        txpwr_count = IEEE80211_TPE_EIRP_MAX_POWER_COUNT - 1;
    }

    /* Most architectures should use 2's complement, but we utilize an
     * encoding process that is architecture agnostic to be on the
     * safer side.
     */
    /* Tx Power is specified in 0.5dB steps 8-bit 2's complement
     * representation.
     */

    if (channel->ic_maxregpower < 0) {
        max_pwr_abs = -channel->ic_maxregpower;
        if (max_pwr_abs > MAX_ABS_NEG_PWR)
            max_pwr_fe = ~(MAX_ABS_NEG_PWR * 2) + 1;
        else
            max_pwr_fe = ~(max_pwr_abs * 2) + 1;
    } else {
        max_pwr_abs = channel->ic_maxregpower;
        if (max_pwr_abs > MAX_ABS_POS_PWR)
            max_pwr_fe = TWICE_MAX_POS_PWR;
        else
            max_pwr_fe = 2 * max_pwr_abs;
    }

    for (iter = 0; iter <= txpwr_count; iter++) {
        txpwr_val[iter] = max_pwr_fe;
    }
    /* Max Tx Power Category field is not valid for 5GHz/2.4GHz */
    txpwr_cat = REG_MAX_CLIENT_TYPE;

    return ieee80211_add_tpe_info(frm, txpwr_count, txpwr_int,
                                            txpwr_cat, txpwr_val);
}

/**
* @ieee80211_add_6g_tpe(): Derive TPE arguments for 6GHz
*
* @param frm            frame in which this sub element should be added
* @param ic             pointer to iee80211com
* @param vap            pointer to vap
* @param channel        pointer to channel information
* @param client_type    client type (Default/Subordinate)
*
* @return pointer       updated frm pointer
*/
u_int8_t *
ieee80211_add_6g_tpe(u_int8_t *frm, struct ieee80211com *ic,
                    struct ieee80211vap *vap,
                    struct ieee80211_ath_channel *channel,
                    u_int8_t client_type)
{
    u_int8_t txpwr_count, txpwr_int, txpwr_cat, txpwr_val;
    bool is_psd_pwr;
    uint16_t max_reg_eirp_psd_pwr;
    uint16_t max_reg_psd_pwr;


    /* Update Max Tx Pwr Information for adding 6GHz band TPE IE */
    /* Default Max Tx Pwr Interpretation for 6GHz is Regulatory EIRP PSD */
    txpwr_int = IEEE80211_TPE_REG_EIRP_PSD;
    /* Default Max Tx Pwr Count for 6GHz is '0' */
    txpwr_count = IEEE80211_TPE_DEFAULT_REG_EIRP_PSD_COUNT;
    txpwr_cat = client_type;
    /* Retrieve Regulatory Max Tx Pwr value */
    if (wlan_reg_get_client_power_for_6ghz_ap(ic->ic_pdev_obj,
                                              txpwr_cat,
                                              ic->ic_curchan->ic_freq,
                                              &is_psd_pwr, &max_reg_psd_pwr,
                                              &max_reg_eirp_psd_pwr) !=
                                              QDF_STATUS_SUCCESS) {
        qdf_err("Error retrieving Regulatory Max Tx Power");
        return frm;
    }
    /* The Max Tx Pwr value returned by the API is in dBm/MHz.
     * Convert to absolute value.
     */
    if (!is_psd_pwr)
        ieee80211_get_default_psd_power(vap, txpwr_cat,
                                        (uint8_t *)&max_reg_eirp_psd_pwr);

    txpwr_val = max_reg_eirp_psd_pwr * 2;

    return ieee80211_add_tpe_info(frm, txpwr_count, txpwr_int,
                                            txpwr_cat, &txpwr_val);
}

/**
* @ieee80211_add_vht_txpwr_envlp(): Adds VHT Max Tx Power Envelope IE
*
* @param frm            frame in which this sub element should be added
* @param ni             pointer to associated node structure
* @param ic             pointer to iee80211com
* @param subtype        frame subtype (beacon, probe resp etc.)
* @param is_subelement  flag to check if TPE is to be added as subelement
*
* @return pointer       updated frm pointer
*/
u_int8_t *
ieee80211_add_vht_txpwr_envlp(u_int8_t *frm, struct ieee80211_node *ni,
            struct ieee80211com *ic, u_int8_t subtype, u_int8_t is_subelement)
{
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t index;
    enum reg_6g_ap_type ap_device_type;
    struct ieee80211_ath_channel *channel = NULL;
    ieee80211_tpe_config_user_params *tpe_conf = &vap->iv_tpe_ie_config;

    if(!is_subelement) {
       channel = vap->iv_bsschan;
    }
    else {
       if(is_subelement == IEEE80211_TPE_IS_VENDOR_SUB_ELEMENT)
           channel = ic->ic_tx_next_ch;
       else
           channel = ic->ic_chanchange_channel;
    }

    if(!IEEE80211_IS_CHAN_6GHZ(channel)) {
        /* 5GHz/2.4GHz handling */
        frm = ieee80211_add_lower_band_tpe(frm, ic, channel);

    } else {
        /* 6GHz handling */

        /* API to get AP type might change after support for
         * Standard AP is introduced
         */
        ucfg_reg_get_cur_6g_ap_pwr_type(ic->ic_pdev_obj, &ap_device_type);
        switch(ap_device_type) {
            case REG_INDOOR_AP:
                if(subtype == IEEE80211_FC0_SUBTYPE_BEACON ||
                   subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
                    frm = ieee80211_add_6g_tpe(frm, ic, vap, channel,
                                               REG_SUBORDINATE_CLIENT);
                }
                /* Fall through: LPI AP needs to advertise Max Tx Pwr
                 * values for both Default and Subordinate clients.
                 */

            case REG_STANDARD_POWER_AP:
                frm = ieee80211_add_6g_tpe(frm, ic, vap, channel,
                                           REG_DEFAULT_CLIENT);
            break;

            default:
                qdf_err("Invalid AP type: %d", ap_device_type);
            break;
        }


        /* Update any user config TPE IEs for Beacon and Probe response frames */
        if(subtype == IEEE80211_FC0_SUBTYPE_BEACON ||
           subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
            for(index = 0; index < IEEE80211_TPE_LOCAL_CONFIG_MAX; index++) {
                if (tpe_conf->local_tpe_config & BIT(index)) {
                    frm = ieee80211_add_tpe_info(frm,
                            tpe_conf->tpe_config[index].tpe_payload.tpe_info_cnt,
                            tpe_conf->tpe_config[index].tpe_payload.tpe_info_intrpt,
                            tpe_conf->tpe_config[index].tpe_payload.tpe_info_cat,
                            tpe_conf->tpe_config[index].tpe_payload.local_max_txpwr);
                }
            }
        }
    }
    return frm;
}

/**
* @brief    Adds wide band sub element within channel switch wrapper IE.
*           If this function is to be used for 'Wide Bandwidth Channel Switch
*           element', then modifications will be required in function.
*
* @param frm        frame in which this sub element should be added
* @param ni         pointer to associated node structure
* @param ic         pointer to iee80211com
* @param subtype    frame subtype (beacon, probe resp etc.)
*
* @return pointer to post channel switch sub element
*/
u_int8_t*
ieee80211_add_vht_wide_bw_switch(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, int is_vendor_ie)
{
    struct ieee80211_ie_wide_bw_switch *widebw = (struct ieee80211_ie_wide_bw_switch *)frm;
    int widebw_len = sizeof(struct ieee80211_ie_wide_bw_switch);
    u_int8_t    new_ch_width = 0;
    enum ieee80211_phymode new_phy_mode;
    u_int16_t                     next_chwidth;
    struct ieee80211_ath_channel      *next_channel;
    struct ieee80211vap *vap = ni->ni_vap;

    if(is_vendor_ie)
    {
        next_chwidth = ieee80211_get_chan_width(ic->ic_tx_next_ch);
        next_channel = ic->ic_tx_next_ch;
    }
    else
    {
        next_chwidth = ic->ic_chanchange_chwidth;
        next_channel = ic->ic_chanchange_channel;
    }

    OS_MEMSET(widebw, 0, sizeof(struct ieee80211_ie_wide_bw_switch));

    widebw->elem_id   = IEEE80211_ELEMID_WIDE_BAND_CHAN_SWITCH;
    widebw->elem_len  = widebw_len - 2;

    /* 11AX TODO: Revisit HE related operations below for drafts later than
     * 802.11ax draft 2.0
     */

    /* New channel width */
    switch(next_chwidth)
    {
        case CHWIDTH_VHT40:
            new_ch_width = IEEE80211_VHTOP_CHWIDTH_2040;
            break;
        case CHWIDTH_VHT80:
            new_ch_width = IEEE80211_VHTOP_CHWIDTH_80;
            break;
        case CHWIDTH_VHT160:
            if (vap->iv_rev_sig_160w) {
                if (IEEE80211_IS_CHAN_160MHZ(next_channel)) {
                    new_ch_width = IEEE80211_VHTOP_CHWIDTH_REVSIG_160;
                } else if(IEEE80211_IS_CHAN_80_80MHZ(next_channel)) {
                    new_ch_width = IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80;
                }
            } else {
                if (IEEE80211_IS_CHAN_160MHZ(next_channel)) {
                    new_ch_width = IEEE80211_VHTOP_CHWIDTH_160;
                } else if(IEEE80211_IS_CHAN_80_80MHZ(next_channel)) {
                    new_ch_width = IEEE80211_VHTOP_CHWIDTH_80_80;
                }
            }
            break;
        default:
            qdf_nofl_info("%s: Invalid destination channel width %d specified\n",
                    __func__, next_chwidth);
            qdf_assert_always(0);
            break;
    }

    /* Channel Center frequency 1 */
    if(next_chwidth != CHWIDTH_VHT40) {

       widebw->new_ch_freq_seg1 = next_channel->ic_vhtop_ch_num_seg1;
       widebw->new_ch_freq_seg2 = 0;
       if (next_chwidth == CHWIDTH_VHT160) {
           if (vap->iv_rev_sig_160w) {
                   widebw->new_ch_freq_seg1 = next_channel->ic_vhtop_ch_num_seg1;
                   widebw->new_ch_freq_seg2 = next_channel->ic_vhtop_ch_num_seg2;
           } else {
               /* Use legacy 160 MHz signaling */
               if(IEEE80211_IS_CHAN_11AC_VHT160(next_channel) ||
                  IEEE80211_IS_CHAN_11AXA_HE160(next_channel)) {
                   /* ic->ic_curchan->ic_vhtop_ch_num_seg2 is centre
                    * frequency for whole 160 MHz.
                    */
                   widebw->new_ch_freq_seg1 = next_channel->ic_vhtop_ch_num_seg2;
                   widebw->new_ch_freq_seg2 = 0;
               } else {
                   /* 80 + 80 MHz */
                   widebw->new_ch_freq_seg1 = next_channel->ic_vhtop_ch_num_seg1;
                   widebw->new_ch_freq_seg2 = next_channel->ic_vhtop_ch_num_seg2;
               }
           }
       }
    } else {
        new_phy_mode = ieee80211_chan2mode(next_channel);

        if (ieee80211_is_phymode_11ac_vht40plus(new_phy_mode) ||
                ieee80211_is_phymode_11axa_he40plus(new_phy_mode)) {
            widebw->new_ch_freq_seg1 = next_channel->ic_ieee + 2;
        } else if (ieee80211_is_phymode_11ac_vht40minus(new_phy_mode) ||
                  ieee80211_is_phymode_11axa_he40minus(new_phy_mode)) {
            widebw->new_ch_freq_seg1 = next_channel->ic_ieee - 2;
        }
    }
    widebw->new_ch_width = new_ch_width;

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_DOTH,
         "%s: new_ch_width: %d, freq_seg1: %d, freq_seg2 %d\n", __func__,
         new_ch_width, widebw->new_ch_freq_seg1, widebw->new_ch_freq_seg2);

    return frm + widebw_len;
}

u_int8_t *
ieee80211_add_chan_switch_wrp(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype, u_int8_t extchswitch)
{
    struct ieee80211vap *vap = ni->ni_vap;
    u_int8_t *efrm;
    u_int8_t ie_len;
    /* preserving efrm pointer, if no sub element is present,
        Skip adding this element */
    efrm = frm;
     /* reserving 2 bytes for the element id and element len*/
    frm += 2;

    /* Country element is added if it is extended channel switch and countryie
     * is enabled. */
    if (extchswitch &&
        IEEE80211_IS_COUNTRYIE_AND_DOTH_ENABLED(ic, vap)) {
        frm = ieee80211_add_country(frm, vap);
    }
    /*If channel width not 20 then add Wideband and txpwr evlp element*/
    if(ic->ic_chanchange_chwidth != CHWIDTH_VHT20) {
        if (ic->ic_wb_subelem) {
            frm = ieee80211_add_vht_wide_bw_switch(frm, ni, ic, subtype, 0);
        }

        frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic, subtype,
                                    IEEE80211_TPE_IS_SUB_ELEMENT);
    }
    /* If frame is filled with sub elements then add element id and len*/
    if((frm-2) != efrm)
    {
       ie_len = frm - efrm - 2;
       *efrm++ = IEEE80211_ELEMID_CHAN_SWITCH_WRAP;
       *efrm = ie_len;
       /* updating efrm with actual index*/
       efrm = frm;
    }
    return efrm;
}

u_int8_t *
ieee80211_add_timeout_ie(u_int8_t *frm, struct ieee80211_node *ni, size_t ie_len, u_int32_t tsecs)
{
    struct ieee80211_ie_timeout *lifetime = (struct ieee80211_ie_timeout *) frm;

    OS_MEMSET(frm, 0, ie_len);
    lifetime->ie_type = IEEE80211_ELEMID_TIMEOUT_INTERVAL;
    lifetime->ie_len = sizeof(struct ieee80211_ie_timeout) - 2;
    lifetime->interval_type = 3;
    lifetime->value = qdf_cpu_to_le32(tsecs);

    return frm + ie_len;
}

/**
 * @brief  Process power capability IE
 *
 * @param [in] ni  the STA that sent the IE
 * @param [in] ie  the IE to be processed
 */
void ieee80211_process_pwrcap_ie(struct ieee80211_node *ni, u_int8_t *ie)
{
    u_int8_t len;

    if (!ni || !ie) {
        return;
    }

    len = ie[1];
    if (len != 2) {
        IEEE80211_DISCARD_IE(ni->ni_vap,
            IEEE80211_MSG_ELEMID,
            "Power Cap IE", "invalid len %u", len);
        return;
    }

    ni->ni_min_txpower = ie[2];
    ni->ni_max_txpower = ie[3];
}

/**
 * @brief  Channels supported  IE
 *
 * @param [in] ni  the STA that sent the IE
 * @param [in] ie  the IE to be processed
 */
void ieee80211_process_supp_chan_ie(struct ieee80211_node *ni, u_int8_t *ie)
{
        struct ieee80211_ie_supp_channels *supp_chan = NULL;

        if (!ni || !ie) {
            return;
        }

        supp_chan = (struct ieee80211_ie_supp_channels *)ie;

        if (supp_chan->supp_chan_len != 2) {
            IEEE80211_DISCARD_IE(ni->ni_vap, IEEE80211_MSG_ELEMID,
                                 "802.11h channel supported IE",
                                 "invalid len %u", supp_chan->supp_chan_len);
            return;
        }

        ni->ni_first_channel = supp_chan->first_channel;
        ni->ni_nr_channels = supp_chan->nr_channels;
}

/*
 * IC ppett16 and ppet8 values corresponding to each ru
 * and nss are extracted and input to pack module
 */
void
he_ppet16_ppet8_pack(u_int8_t *he_ppet, u_int8_t *byte_idx_p, u_int8_t *bit_pos_used_p, u_int8_t ppet)
{
    int lft_sht, rgt_sht;
    int byte_idx = *byte_idx_p, bit_pos_used = *bit_pos_used_p;
    u_int8_t mask;

    if (bit_pos_used <= HE_PPET_MAX_BIT_POS_FIT_IN_BYTE) {
        lft_sht = bit_pos_used;
        he_ppet[byte_idx] |= (ppet << lft_sht);
        bit_pos_used += HE_PPET_FIELD;
        if (bit_pos_used == HE_PPET_BYTE) {
            bit_pos_used = 0;
            byte_idx++;
        }
    } else {
        lft_sht = bit_pos_used ;
        he_ppet[byte_idx] |= (ppet << lft_sht);
        bit_pos_used = 0;
        byte_idx++;
        rgt_sht = HE_PPET_BYTE - lft_sht;
        mask = (rgt_sht == 2) ? HE_PPET_RGT_ONE_BIT:
                                HE_PPET_RGT_TWO_BIT;
        he_ppet[byte_idx] |= ((ppet & mask ) >> rgt_sht);
        bit_pos_used = HE_PPET_FIELD - rgt_sht ;
    }

    *byte_idx_p = byte_idx;
    *bit_pos_used_p = bit_pos_used;
}

/*
 * IC ppett16 and ppet8 values corresponding to each ru
 * and nss are extracted and input to pack module
 */
void
he_ppet16_ppet8_extract_pack(u_int8_t *he_ppet, u_int8_t tot_nss,
                         u_int32_t ru_mask, u_int32_t *ppet16_ppet8) {

    u_int8_t ppet8_val, ppet16_val, byte_idx=0;
    u_int8_t bit_pos_used = HE_CAP_PPET_NSS_RU_BITS_FIXED;
    u_int8_t tot_ru = HE_PPET_TOT_RU_BITS;
    u_int8_t nss, ru;
    u_int32_t temp_ru_mask;

    for(nss=0; nss < tot_nss ; nss++) {    /* loop NSS */
        temp_ru_mask = ru_mask;
        for(ru=1; ru <= tot_ru ; ru++) {   /* loop RU */

            if(temp_ru_mask & 0x1) {

                /* extract ppet16 & ppet8 from IC he ppet handle */
                ppet16_val = HE_GET_PPET16(ppet16_ppet8, ru, nss);
                ppet8_val  = HE_GET_PPET8(ppet16_ppet8, ru, nss);

                /* pack ppet16 & ppet8 in contiguous byte araay*/
                he_ppet16_ppet8_pack(he_ppet, &byte_idx, &bit_pos_used, ppet16_val);
                he_ppet16_ppet8_pack(he_ppet, &byte_idx, &bit_pos_used, ppet8_val);
            }
            temp_ru_mask = temp_ru_mask >> 1;
        }
    }
}

void
hecap_ie_set(u_int8_t *hecap, u_int8_t idx, u_int8_t tot_bits,
                 u_int32_t value)  {

    u_int8_t fit_bits=0, byte_cnt=0, prev_fit_bits=0;
    idx = idx % 8;
    fit_bits = 8 - idx;
    fit_bits = (tot_bits > fit_bits) ? 8 - idx: tot_bits;

    while ((idx + tot_bits) > 8 ) {
        /* clear the target bit */
        hecap[byte_cnt] = hecap[byte_cnt] & ~(((1 << (fit_bits)) - 1) << (idx));
        hecap[byte_cnt] |= (((value >> prev_fit_bits) & ((1 << (fit_bits)) - 1)) << (idx));
        tot_bits = tot_bits - fit_bits;
        idx = idx + fit_bits;
        if( idx == 8 ) {
            idx =0;
            byte_cnt ++;
        }
        prev_fit_bits = prev_fit_bits + fit_bits;
        fit_bits = 8 - idx;
        fit_bits = ( tot_bits > fit_bits) ? 8 - idx: tot_bits ;
    }

    if ((idx + tot_bits) <= 8 ) {
        /* clear the target bit */
        hecap[byte_cnt] = hecap[byte_cnt] & ~(((1 << (tot_bits)) - 1) << (idx));
        hecap[byte_cnt] |= (((value >> prev_fit_bits) & ((1 << (tot_bits)) - 1)) << (idx));
    }
}

void heop_param_set(u_int32_t *heop_param, u_int8_t idx, u_int8_t tot_bits,
                 u_int32_t value)
{
    /* Clear the target bits */
    *heop_param = *heop_param & ~(((1 << (tot_bits)) - 1) << (idx));
    /* Set the target bits */
    *heop_param |= (value << idx);
}

u_int32_t heop_param_get(u_int32_t heop_param, u_int8_t idx, u_int8_t tot_bits)
{
    return ((heop_param >> idx) & ((1 << tot_bits) - 1));
}

void heop_bsscolor_set(u_int8_t *bsscolor, u_int8_t idx, u_int8_t tot_bits,
                 u_int32_t value)
{
    /* Clear the target bits */
    *bsscolor = *bsscolor & ~(((1 << (tot_bits)) - 1) << (idx));
    /* Set the target bits */
    *bsscolor |= (value << idx);
}

u_int32_t heop_bsscolor_get(u_int8_t bsscolor, u_int8_t idx, u_int8_t tot_bits)
{
    return ((bsscolor >> idx) & ((1 << tot_bits) - 1));
}

static void
ieee80211_set_hecap_rates(struct ieee80211com *ic,
                          struct ieee80211vap  *vap,
                          struct ieee80211_node *ni,
                          struct ieee80211_ie_hecap *hecap, bool enable_log)
{
    struct ieee80211_bwnss_map nssmap;
    uint8_t tx_chainmask  = ieee80211com_get_tx_chainmask(ic);
    uint8_t rx_chainmask  = ieee80211com_get_rx_chainmask(ic);
    uint8_t rx_streams    = ieee80211_get_rxstreams(ic, vap);
    uint8_t tx_streams    = ieee80211_get_txstreams(ic, vap);
    uint8_t *hecap_txrx   = hecap->hecap_txrx;
    uint8_t unused_mcsnss_bytes = HE_UNUSED_MCSNSS_NBYTES;
    uint8_t chwidth;
    uint16_t rxmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint16_t txmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint8_t tx_streams_160 = 0;
    uint8_t rx_streams_160 = 0;

    chwidth = wlan_get_param(vap, IEEE80211_CHWIDTH);

    /* If STA configured in auto mode, ni_chwidth will be 0
     * In that case ic_chwidth used
     */
    if (vap->iv_opmode == IEEE80211_M_STA) {
        chwidth = ieee80211_get_vap_max_chwidth(vap);
    }

    /* Reset bw_nss_160 and bw_rxnss_160
     * since the following fn will not get
     * called when ni_phymode < IEEE80211_MODE_11AXA_HE160
     * and this variable will hold garbage at that point
     */
    nssmap.bw_nss_160 = 0;
    nssmap.bw_rxnss_160 = 0;

    /* Get the nss vs chainmask mapping by
     * calling ic->ic_get_bw_nss_mapping.
     * This function returns nss for a given
     * chainmask which is nss = (1/2)nstreams
     * for HE currently (if ni_phymode is
     * IEEE80211_MODE_11AXA_HE160 or IEEE80211_
     * MODE_11AXA_HE80_80) where nstreams is
     * the number of streams for that chainmask.
     */
    if(chwidth >= IEEE80211_CWM_WIDTH160 &&
            ic->ic_get_bw_nss_mapping) {
        if(ic->ic_get_bw_nss_mapping(vap, &nssmap, tx_chainmask)) {
            /* if error then reset nssmap */
            tx_streams_160 = 0;
        } else {
            tx_streams_160 = nssmap.bw_nss_160;
        }

        if(ic->ic_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
            /* if error then reset nssmap */
            rx_streams_160 = 0;
        } else {
            rx_streams_160 = nssmap.bw_rxnss_160;
        }
    }

    /* get the intersected (user-set vs target caps)
     * values of mcsnssmap */
    ieee80211vap_get_insctd_mcsnssmap(vap, rxmcsnssmap, txmcsnssmap);

    switch(chwidth) {
        /* STA comes up with Maximum width (IEEE80211_CWM_WIDTH80_80) in 11axa auto mode.
         * We need to fill HE MCS to NSS map accordingly.
         */
        case IEEE80211_CWM_WIDTH80_80:
        case IEEE80211_CWM_WIDTH160:
            if (ieee80211_is_phymode_11axa_he80_80(vap->iv_des_mode) ||
                 IEEE80211_IS_CHAN_11AXA_HE80_80(ic->ic_curchan)) {
                /* mcsnssmap for bw80p80 */
                /* For > 80 MHz BW we will pack mcs_nss info for only the current
                 * value of nss which is half the no of streams for the current
                 * value of the chainmask - retrieved by ic->ic_get_bw_nss_mapping()
                 */
                (void)qdf_set_u16((uint8_t *)&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX8],
                    HE_GET_MCS_NSS_BITS_TO_PACK(rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                        rx_streams_160));
                (void)qdf_set_u16((uint8_t *)&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX10],
                    HE_GET_MCS_NSS_BITS_TO_PACK(txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                        tx_streams_160));

                HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX8],
                        rx_streams_160);
                HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX10],
                        tx_streams_160);

                unused_mcsnss_bytes -= HE_NBYTES_MCS_NSS_FIELD_PER_BAND;
            }

            /* mcsnssmap for bw160 */
            /* For > 80 MHz BW we will pack mcs_nss info for only the current
             * value of nss which is half the no of streams for the current
             * value of the chainmask - retrieved by ic->ic_get_bw_nss_mapping()
             */
            (void)qdf_set_u16((uint8_t *)&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX4],
                HE_GET_MCS_NSS_BITS_TO_PACK(rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                    rx_streams_160));
            (void)qdf_set_u16((uint8_t *)&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX6],
                HE_GET_MCS_NSS_BITS_TO_PACK(txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                    tx_streams_160));

            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX4],
                    rx_streams_160);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX6],
                    tx_streams_160);

            unused_mcsnss_bytes -= HE_NBYTES_MCS_NSS_FIELD_PER_BAND;

            /* fall through */
        default:
            /* mcsnssmap for bw<=80 */
            /* For <= 80 MHz BW we will pack mcs_nss info for only the current
             * value of nss
             */
            (void)qdf_set_u16((uint8_t *)&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX0],
                HE_GET_MCS_NSS_BITS_TO_PACK(rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                     rx_streams));
            (void)qdf_set_u16((uint8_t *)&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX2],
                HE_GET_MCS_NSS_BITS_TO_PACK(txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                     tx_streams));

            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX0],
                     rx_streams);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX2],
                     tx_streams);

            unused_mcsnss_bytes -= HE_NBYTES_MCS_NSS_FIELD_PER_BAND;
            break;
    }

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s hecap->hecap_txrx[0]=%x hecap->hecap_txrx[1]=%x"
        " hecap->hecap_txrx[2]=%x hecap->hecap_txrx[3]=%x"
        " hecap->hecap_txrx[4]=%x hecap->hecap_txrx[5]=%x\n"
        " hecap->hecap_txrx[6]=%x hecap->hecap_txrx[7]=%x"
        " hecap->hecap_txrx[8]=%x hecap->hecap_txrx[9]=%x"
        " hecap->hecap_txrx[10]=%x hecap->hecap_txrx[11]=%x"
        " nss=%x *nss_160=%x, chwidth=%x"
        " \n",__func__,
         hecap_txrx[HECAP_TXRX_MCS_NSS_IDX0], hecap_txrx[HECAP_TXRX_MCS_NSS_IDX1],
         hecap_txrx[HECAP_TXRX_MCS_NSS_IDX2], hecap_txrx[HECAP_TXRX_MCS_NSS_IDX3],
         hecap_txrx[HECAP_TXRX_MCS_NSS_IDX4], hecap_txrx[HECAP_TXRX_MCS_NSS_IDX5],
         hecap_txrx[HECAP_TXRX_MCS_NSS_IDX6], hecap_txrx[HECAP_TXRX_MCS_NSS_IDX7],
         hecap_txrx[HECAP_TXRX_MCS_NSS_IDX8], hecap_txrx[HECAP_TXRX_MCS_NSS_IDX9],
         hecap_txrx[HECAP_TXRX_MCS_NSS_IDX10], hecap_txrx[HECAP_TXRX_MCS_NSS_IDX11],
         tx_streams, tx_streams_160, chwidth
         );
    }

    hecap->elem_len -= unused_mcsnss_bytes;
}

static void
hecap_override_channelwidth(struct ieee80211vap *vap,
                            u_int32_t *ch_width,
                            struct ieee80211_node *ni) {

    enum ieee80211_phymode des_mode = 0;
    u_int32_t width_mask = -1, band_width, width_val;
    u_int32_t ru_mask, ru_width;

    width_val = *ch_width;
    /* Use current mode for AP vaps and des_mode for Non-AP */
    if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
        des_mode = vap->iv_cur_mode;
    } else {
        des_mode = vap->iv_des_mode;
    }

    /* derive bandwidth mask */
    switch(des_mode)
    {
        case IEEE80211_MODE_11AXG_HE20:
        case IEEE80211_MODE_11AXA_HE20:
	    width_mask = IEEE80211_HECAP_PHY_CHWIDTH_11AX_HE20_MASK;
            break;
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40:
	    width_mask = IEEE80211_HECAP_PHY_CHWIDTH_11AXG_HE40_MASK;
            break;
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
	    width_mask = IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_MASK;
            break;
        case IEEE80211_MODE_11AXA_HE80:
	    width_mask = IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_MASK;
            break;
        case IEEE80211_MODE_11AXA_HE160:
	    width_mask = IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_HE160_MASK;
            break;
        case IEEE80211_MODE_11AXA_HE80_80:
	    width_mask = IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_HE160_HE80_80_MASK;
            break;
        default:
            break;
    }

    band_width = width_val & width_mask;

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        /* derive ru mask */
        ru_mask = IEEE80211_IS_CHAN_11AXG(vap->iv_bsschan) ?
                  IEEE80211_HECAP_PHY_CHWIDTH_11AXG_RU_MASK:
                  IEEE80211_HECAP_PHY_CHWIDTH_11AXA_RU_MASK;

        ru_width = width_val & ru_mask;
    }

    /* set right phymode bandwidth as per des mode (current mode in ap) */
    width_val =(width_val & IEEE80211_HECAP_PHY_CHWIDTH_11AX_BW_ONLY_ZEROOUT_MASK)
                  | band_width;

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        /* set right ru as per desired channel */
        width_val = ((width_val &
            IEEE80211_HECAP_PHY_CHWIDTH_11AX_RU_ONLY_ZEROOUT_MASK) | ru_width);
    } else {
        width_val = (width_val &
            IEEE80211_HECAP_PHY_CHWIDTH_11AX_RU_ONLY_ZEROOUT_MASK);
    }

    *ch_width = width_val;
}

u_int8_t *
ieee80211_add_mbssid_config(struct ieee80211vap *vap, uint8_t subtype,
                            uint8_t *frm)
{
    struct ieee80211_mbss_config_ie *mbssid_config =
                                    (struct ieee80211_mbss_config_ie *)frm;

    mbssid_config->hdr.element_id = IEEE80211_ELEMID_EXTN;
    mbssid_config->hdr.length     = sizeof(*mbssid_config) -
                                                IEEE80211_IE_HDR_LEN;
    mbssid_config->elem_id_ext    = IEEE80211_ELEMID_EXT_MBSSID_CONFIG;
    mbssid_config->bssid_count    = ieee80211_get_num_ap_vaps_up(vap->iv_ic);
    mbssid_config->profile_period = vap->iv_ic->ic_mbss.current_pp;

    return frm + (sizeof(*mbssid_config));
}

u_int8_t *
ieee80211_add_hecap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype)
{
    struct ieee80211_ie_hecap *hecap  = (struct ieee80211_ie_hecap *)frm;
    struct ieee80211_he_handle *ic_he = &ic->ic_he;
    struct ieee80211vap  *vap         = ni->ni_vap;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    u_int32_t *ic_hecap_phy, val, ru_mask;
    u_int32_t ic_hecap_mac_low, ic_hecap_mac_high;
    u_int8_t *he_ppet, *hecap_phy_info, *hecap_mac_info;
    u_int8_t ppet_pad_bits, ppet_tot_bits, ppet_bytes;
    u_int8_t ppet_present, ru_set_count = 0;
    u_int8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    u_int8_t tx_streams = ieee80211_get_txstreams(ic, vap);
    u_int8_t nss        = MIN(rx_streams, tx_streams);
    bool enable_log     = false;
    int hecaplen;
    uint8_t chwidth;

    pdev = ic->ic_pdev_obj;
    psoc = wlan_pdev_get_psoc(pdev);
    /* deduct the variable size fields before
     * memsetting hecap to 0
     */
    qdf_mem_zero(hecap,
            (sizeof(struct ieee80211_ie_hecap)
             - HECAP_TXRX_MCS_NSS_SIZE - HECAP_PPET16_PPET8_MAX_SIZE));

    hecap->elem_id     = IEEE80211_ELEMID_EXTN;
    /* elem id + len = 2 bytes  readjust based on
     *  mcs-nss and ppet fields
     */
    hecap->elem_len    = (sizeof(struct ieee80211_ie_hecap) -
                                         IEEE80211_IE_HDR_LEN);
    hecap->elem_id_ext = IEEE80211_ELEMID_EXT_HECAP;

    if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
        subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {

        enable_log = true;
    }

    qdf_mem_copy(&ic_hecap_mac_low, &ic_he->hecap_macinfo[HECAP_MACBYTE_IDX0], sizeof(ic_hecap_mac_low));
    qdf_mem_copy(&ic_hecap_mac_high, &ic_he->hecap_macinfo[HECAP_MACBYTE_IDX4], sizeof(ic_hecap_mac_high));
    hecap_mac_info = &hecap->hecap_macinfo[0];

    /* Fill in default from IC HE MAC Capabilities
       only four bytes are copied from IE HE cap */
    qdf_mem_copy(&hecap->hecap_macinfo, &ic_he->hecap_macinfo,
                 qdf_min(sizeof(hecap->hecap_macinfo),
                 sizeof(ic_he->hecap_macinfo)));

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
          "%s IC hecap_mac_info = %x \n",__func__, ic_he->hecap_macinfo);
    }


    /* If MAC config override required for various MAC params,
      override MAC cap fields based on the vap HE MAC configs
      Each MAC values are taken from from IC and packed
      to HE MAC cap byte field
    */

    /* The user configured iv_he_ctrl value is intersected with
     * the target-cap for this field. Hence we can use the user
     * configured value here.
     */
    val = vap->iv_he_ctrl;
    HECAP_MAC_HECTRL_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE Ctrl = %x \n",__func__, val, vap->iv_he_ctrl);
    }

    val = HECAP_MAC_TWTREQ_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_TWTREQ_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE TWT REQ = %x \n",__func__,
         val, vap->iv_he_twtreq);
    }

    /* the vap variable is initialized from the corresponding
     * field stored in ic at service_ready processing and can
     * be overwritten by user
     */
    val = (wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_CEXT_TWT_RESPONDER)) ?
           vap->iv_twt_rsp : 0;
    HECAP_MAC_TWTRSP_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE TWT RES = %x \n",__func__, val,
         vap->iv_he_twtres);
    }

    /* the user-configured he_frag value is intersected
     * with the target-cap for this field so that we
     * can directly use the user-configured value here.
     */
    val = vap->iv_he_frag;
    HECAP_MAC_HEFRAG_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE Frag = %x \n",__func__, val, vap->iv_he_frag);
    }

#if SUPPORT_11AX_D3
    val = vap->iv_he_max_frag_msdu;
    HECAP_MAC_MAXFRAGMSDUEXP_SET_TO_IE(&hecap_mac_info, val);
#else
    val = HECAP_MAC_MAXFRAGMSDU_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_MAXFRAGMSDU_SET_TO_IE(&hecap_mac_info, val);
#endif
    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE Max Frag MSDU = %x \n",__func__,
         val, vap->iv_he_max_frag_msdu);
    }

    val = vap->iv_he_min_frag_size;
    HECAP_MAC_MINFRAGSZ_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE MIN Frag size = %x \n",__func__,
         val, vap->iv_he_min_frag_size);
    }

    /* According to 11ax spec D3.0 section 9.4.2.237
     * the MAC Padding Duration field should be
     * reserved for an AP.
     */
    if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
        val = HE_MAC_TRIGPADDUR_VALUE_RESERVED;
    } else {
        val = HECAP_MAC_TRIGPADDUR_GET_FROM_IC(ic_hecap_mac_low);
    }
    HECAP_MAC_TRIGPADDUR_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s IC val = %x Trigger Pad Dur \n",__func__, val);
    }

#if SUPPORT_11AX_D3
    val = vap->iv_he_multi_tid_aggr;
    HECAP_MAC_MTIDRXSUP_SET_TO_IE(&hecap_mac_info, val);
#else
    val = HECAP_MAC_MTID_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_MTID_SET_TO_IE(&hecap_mac_info, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE Multi Tid Aggr  = %x \n",
         __func__, val, vap->iv_he_multi_tid_aggr);
    }

    /* According to 11ax spec D2.0 section 9.4.2.237
     * this particular capability should be enabled
     * only if +HTC-HE Support is enabled.
     */
    if (vap->iv_he_ctrl) {
        val = HECAP_MAC_HELKAD_GET_FROM_IC(ic_hecap_mac_low);
    } else {
        val = 0;
    }
    HECAP_MAC_HELKAD_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE Link Adapt  = %x \n",
         __func__, val, vap->iv_he_link_adapt);
    }

    val = HECAP_MAC_AACK_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_AACK_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE All Ack  = %x \n",
         __func__, val, vap->iv_he_all_ack);
    }

    /* According to 11ax spec D2.0/D3.0 section 9.4.2.237
     * this particular capability should be enabled
     * only if +HTC-HE Support is enabled. Moreover,
     * UMRS Rx is only expected in a STA. AP is not
     * UMRS RX capable.
     */
#if SUPPORT_11AX_D3
    if ((vap->iv_opmode == IEEE80211_M_STA) && vap->iv_he_ctrl) {
        val =  HECAP_MAC_TRSSUP_GET_FROM_IC(ic_hecap_mac_low);
    } else {
        val = 0;
    }
    HECAP_MAC_TRSSUP_SET_TO_IE(&hecap_mac_info, val);
#else
    if ((vap->iv_opmode == IEEE80211_M_STA) && vap->iv_he_ctrl) {
        val =  HECAP_MAC_ULMURSP_GET_FROM_IC(ic_hecap_mac_low);
    } else {
        val = 0;
    }
    HECAP_MAC_ULMURSP_SET_TO_IE(&hecap_mac_info, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE UL MU Resp Sced  = %x \n",
         __func__, val, vap->iv_he_ul_mu_sched);
    }

    /* According to 11ax spec D2.0 section 9.4.2.237
     * this particular capability should be enabled
     * only if +HTC-HE Support is enabled.
     */
    if ((vap->iv_he_ctrl) && (vap->iv_he_bsr_supp)){
        val = HECAP_MAC_BSR_GET_FROM_IC(ic_hecap_mac_low);
    } else {
        val = 0;
    }
    HECAP_MAC_BSR_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE Actrl BSR = %x \n",
         __func__, val, vap->iv_he_actrl_bsr);
    }

    val = HECAP_MAC_BCSTTWT_GET_FROM_IC(ic_hecap_mac_low);
    val &= wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_BCAST_TWT);
    HECAP_MAC_BCSTTWT_SET_TO_IE(&hecap_mac_info, val);

    val = HECAP_MAC_32BITBA_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_32BITBA_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE 32 Bit BA  = %x \n",
         __func__, val, vap->iv_he_32bit_ba);
    }

    val = HECAP_MAC_MUCASCADE_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_MUCASCADE_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE MU Cascade  = %x \n",
         __func__, val, vap->iv_he_mu_cascade);
    }

    val = HECAP_MAC_ACKMTIDAMPDU_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_ACKMTIDAMPDU_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x ACK Multi Tid Aggr\n",__func__, val);
    }

#if SUPPORT_11AX_D3
    /* According to 11ax spec doc D3.0 section 9.4.2.237.2 B24 of the
     * HE MAC cap is now a reserved bit */
    HECAP_MAC_RESERVED_SET_TO_IE(&hecap_mac_info, 0);
#else
    val = HECAP_MAC_GROUPMSTABA_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_GROUPMSTABA_SET_TO_IE(&hecap_mac_info, val);
#endif
    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x Group Addr Multi Sta BA DL MU \n",
         __func__, val);
    }

    /* OMI can only be sent as part of A-control in
     * HT Control field. So, +HTC-HE Support is mandatory
     * for OMI support.  Moreover, OMI RX is mandatory
     * for AP.
     */
    if (vap->iv_he_ctrl) {
        val = vap->iv_he_omi;
    } else {
        val = 0;
    }
    HECAP_MAC_OMI_SET_TO_IE(&hecap_mac_info, val);

    if (!val && (vap->iv_opmode == IEEE80211_M_HOSTAP)) {
        qdf_print("Mandatory AP MAC CAP OM Control is"
                  "being advertised as disabled");
    }

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE OMI = %x \n",
         __func__, val, vap->iv_he_omi);
    }

    val = HECAP_MAC_OFDMARA_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_OFDMARA_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE OMI = %x \n",
         __func__, val, vap->iv_he_ofdma_ra);
    }

#if SUPPORT_11AX_D3
    val = vap->iv_he_max_ampdu_len_exp;
    HECAP_MAC_MAXAMPDULEN_EXPEXT_SET_TO_IE(&hecap_mac_info, val);
#else
    val = HECAP_MAC_MAXAMPDULEN_EXP_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_MAXAMPDULEN_EXP_SET_TO_IE(&hecap_mac_info, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x  Max AMPDU Len Exp \n",__func__, val);
    }

    val = HECAP_MAC_AMSDUFRAG_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_AMSDUFRAG_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE AMSDU Frag  = %x \n",
         __func__, val, vap->iv_he_amsdu_frag);
    }

    val = HECAP_MAC_FLEXTWT_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_FLEXTWT_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x VAP HE Flex TWT= %x \n",
         __func__, val, vap->iv_he_flex_twt);
    }

    val = HECAP_MAC_MBSS_GET_FROM_IC(ic_hecap_mac_low);
    HECAP_MAC_MBSS_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x Rx Ctrl to Multi BSS\n",__func__, val);
    }

    val = HECAP_MAC_BSRP_BQRP_AMPDU_AGGR_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_BSRP_BQRP_AMPDU_AGGR_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x BSR AMPDU \n",__func__, val);
    }

    val = HECAP_MAC_QTP_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_QTP_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x QTP \n",__func__, val);
    }

    /* According to 11ax spec D2.0/D3.0 section 9.4.2.237
     * this particular capability should be enabled
     * only if +HTC-HE Support is enabled.
     */
    if (vap->iv_he_ctrl) {
        val = HECAP_MAC_ABQR_GET_FROM_IC(ic_hecap_mac_high);
    } else {
        val = 0;
    }
    HECAP_MAC_ABQR_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x Aggr BQR \n",__func__, val);
    }

#if SUPPORT_11AX_D3
    val = HECAP_MAC_SRPRESP_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_SRPRESP_SET_TO_IE(&hecap_mac_info, val);
#else
    val = HECAP_MAC_SRRESP_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_SRRESP_SET_TO_IE(&hecap_mac_info, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x SR Responder \n",__func__, val);
    }

    val = HECAP_MAC_NDPFDBKRPT_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_NDPFDBKRPT_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x NDK Feedback Report \n",__func__, val);
    }

    val = HECAP_MAC_OPS_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_OPS_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x OPS \n",__func__, val);
    }

    /* the vap variable is initialized from the corresponding
     * field stored in ic at service_ready processing and can
     * be overwritten by user
     */
    val = vap->iv_he_amsdu_in_ampdu_suprt;
    HECAP_MAC_AMSDUINAMPDU_SET_TO_IE(&hecap_mac_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x AMSDU in AMPDU \n",__func__, val);
    }

#if SUPPORT_11AX_D3
    val = vap->iv_he_multi_tid_aggr_tx;
    HECAP_MAC_MTIDTXSUP_SET_TO_IE(&hecap_mac_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x MTID AGGR TX Support \n",__func__, val);
    }

    val = HECAP_MAC_HESUBCHAN_TXSUP_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_HESUBCHAN_TXSUP_SET_TO_IE(&hecap_mac_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x HE Sub-channel Selective TX Support \n",__func__, val);
    }

    /* According to 11ax spec D3.3 section 9.4.2.242.2
     * the UL 2x996-tone RU Support field should be
     * reserved for an AP.
     */
    if(vap->iv_opmode != IEEE80211_M_HOSTAP) {
        val = HECAP_MAC_UL2X996TONERU_GET_FROM_IC(ic_hecap_mac_high);
    }
    else {
        val = 0;
    }
    HECAP_MAC_UL2X996TONERU_SET_TO_IE(&hecap_mac_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x UL 2X996-tone RU Support \n",__func__, val);
    }

    val = vap->iv_he_ulmu_data_disable_rx;
    HECAP_MAC_OMCTRLULMU_DISRX_SET_TO_IE(&hecap_mac_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x OM control UL MU Disable RX Support \n",__func__, val);
    }

    /* According to 11ax spec D3.3 section 9.4.2.242.2
     * the Dynamic SM Power Save field should be
     * reserved for an AP.
     */
    if(vap->iv_opmode != IEEE80211_M_HOSTAP) {
        val = HECAP_MAC_DYNAMICSMPS_GET_FROM_IC(ic_hecap_mac_high);
    }
    else {
        val = 0;
    }
    HECAP_MAC_DYNAMICSMPS_SET_TO_IE(&hecap_mac_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x HE Dynamic SM Power Save \n", __func__, val);
    }

    val = HECAP_MAC_PUNCSOUNDSUPP_GET_FROM_IC(ic_hecap_mac_high);
    HECAP_MAC_PUNCSOUNDSUPP_SET_TO_IE(&hecap_mac_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x Punctured Sounding Support \n", __func__, val);
    }

    /* According to 11ax spec D3.3 section 9.4.2.242.2
     * the HT And VHT Trigger Frame Rx Support field should be
     * reserved for an AP.
     */
    if(vap->iv_opmode != IEEE80211_M_HOSTAP) {
        val = HECAP_MAC_HTVHT_TFRXSUPP_GET_FROM_IC(ic_hecap_mac_high);
    }
    else {
        val = 0;
    }
    HECAP_MAC_HTVHT_TFRXSUPP_SET_TO_IE(&hecap_mac_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s IC val = %x HT & VHT Trigger Frame Rx Support \n", __func__, val);
    }

    HECAP_MAC_RESERVED_SET_TO_IE(&hecap_mac_info, 0);
#else
    HECAP_MAC_RESERVED_SET_TO_IE(&hecap_mac_info, 0);
#endif

    /* Fill HE PHY capabilities */
    ic_hecap_phy = &ic_he->hecap_phyinfo[IC_HECAP_PHYDWORD_IDX0];

    hecap_phy_info = &hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0];

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s IC hecap_phyinfo[0]=%x hecap_phyinfo[1]=%x hecap_phyinfo[2]=%x \n",
        __func__, ic_he->hecap_phyinfo[HECAP_PHYBYTE_IDX0],
        ic_he->hecap_phyinfo[HECAP_PHYBYTE_IDX1],
        ic_he->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }
#if SUPPORT_11AX_D3
    HECAP_PHY_RESERVED_SET_TO_IE(&hecap_phy_info, 0);
#else
    /* If PHY config override required for various phy params,
      override PHY cap fields based on the vap HE PHY configs
      Each PHy values are taken from from IC and packed
      to HE phy cap byte field
    */

    val = HECAP_PHY_DB_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_DB_SET_TO_IE(&hecap_phy_info, val);
#endif
    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
               "%s Dual Band Val=%x hecap->hecap_phyinfo[0]=%x \n",
                __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0]);
    }

    val = HECAP_PHY_CBW_GET_FROM_IC(ic_hecap_phy);
    hecap_override_channelwidth(vap, &val, ni);
    HECAP_PHY_CBW_SET_TO_IE(&hecap_phy_info, val);
    /* save chwidth as the same is required as
     * a check for bfee_sts_gt80 cap
     */
    chwidth = val;

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
                "%s Channel Width Val=%x hecap->hecap_phyinfo[0]=%x \n",
                 __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0]);
    }

    val = HECAP_PHY_PREAMBLEPUNCRX_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_PREAMBLEPUNCRX_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
              "%s RX Preamble Punc Val=%x hecap->hecap_phyinfo[1]=%x \n",
               __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

    val = HECAP_PHY_COD_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_COD_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
              "%s DCM Val=%x hecap->hecap_phyinfo[1]=%x \n",
               __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

    val = HECAP_PHY_LDPC_GET_FROM_IC(ic_hecap_phy);
    if (!(val && vap->vdev_mlme->proto.generic.ldpc)) {
        val = 0;
    }
    HECAP_PHY_LDPC_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
                    "%s LDPC Val=%x hecap->hecap_phyinfo[1]=%x \n",
                     __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

    /* the vap variable is initialized from the corresponding
     * field stored in ic at service_ready processing and can
     * be overwritten by user
     */
    val = vap->iv_he_su_ppdu_1x_ltf_800ns_gi;
    HECAP_PHY_SU_1XLTFAND800NSECSGI_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s LTF & GI Val=%x hecap->hecap_phyinfo[1]=%x\n"
             ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

#if SUPPORT_11AX_D3
    val = HECAP_PHY_MIDAMBLETXRXMAXNSTS_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_MIDAMBLETXRXMAXNSTS_SET_TO_IE(&hecap_phy_info, val);
#else
    val = HECAP_PHY_MIDAMBLERXMAXNSTS_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_MIDAMBLERXMAXNSTS_SET_TO_IE(&hecap_phy_info, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s Midamble Rx Max NSTS Val=%x hecap->hecap_phyinfo[0]=%x"
            " hecap->hecap_phyinfo[1]=%x\n"
             ,__func__, val,
             hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0],
             hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

    val = vap->iv_he_ndp_4x_ltf_3200ns_gi;
    HECAP_PHY_LTFGIFORNDP_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s LTF & GI NDP  Val=%x hecap->hecap_phyinfo[2]=%x\n"
          ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    if ((vap->iv_tx_stbc) && (tx_streams > 1) &&
             (vap->iv_opmode != IEEE80211_M_HOSTAP)) {
        val = HECAP_PHY_TXSTBC_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_TXSTBC_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
       "%s TXSTBC LTEQ 80 Val=%x hecap->hecap_phyinfo[2]=%x \n"
        ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    if((vap->iv_rx_stbc) && (rx_streams > 0)) {
        val = HECAP_PHY_RXSTBC_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_RXSTBC_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
       "%s RXSTBC LTEQ 80 Val=%x hecap->hecap_phyinfo[2]=%x \n"
        ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_TXDOPPLER_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_TXDOPPLER_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s TX Doppler Val=%x hecap->hecap_phyinfo[2]=%x \n"
         ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_RXDOPPLER_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_RXDOPPLER_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s RX Doppler Val=%x hecap->hecap_phyinfo[2]=%x \n"
          ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    if (vap->iv_he_ul_mumimo) {
        val = vap->iv_he_full_bw_ulmumimo;
    } else {
        val = 0;
    }
    HECAP_PHY_UL_MU_MIMO_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s UL MU MIMO Val=%x hecap->hecap_phyinfo[2]=%x \n"
        ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    if (vap->iv_he_ul_muofdma) {
        val = HECAP_PHY_ULOFDMA_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_ULOFDMA_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s UL OFDMA Val=%x  hecap->hecap_phyinfo[2]=%x \n",
         __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    /* According to 11ax Draft 4.2 DCM Max Constellation Tx
     * and DCM Max NSS Tx fields are reserved for an AP
     */
    if(vap->iv_opmode != IEEE80211_M_HOSTAP) {
        val = HECAP_PHY_DCMTX_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_DCMTX_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s TX DCM Val=%x  hecap->hecap_phyinfo[3]=%x \n",
        __func__, val,  hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    val = vap->iv_he_dcm_max_cons_rx;
    HECAP_PHY_DCMRX_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s RX DCM Val=%x  hecap->hecap_phyinfo[3]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    val = HECAP_PHY_ULHEMU_PPDU_PAYLOAD_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_ULHEMU_PPDU_PAYLOAD_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
           "%s UL HE MU PPDU Val=%x hecap->hecap_phyinfo[3]=%x  \n"
               ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    if (vap->iv_he_su_bfer) {
        val = HECAP_PHY_SUBFMR_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_SUBFMR_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s SU BFMR Val=%x hecap->hecap_phyinfo[3]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    /* the user-configured he_subfee value is intersected
     * with the target-cap for this field so that we
     * can directly use the user-configured value here.
     */
    val = vap->iv_he_su_bfee;
    HECAP_PHY_SUBFME_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s SU BFEE Val=%x hecap->hecap_phyinfo[4]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX4]);
    }

    /* According to 11ax draft D2.0 section 9.4.2.237.3,
     * mu_bfer capability can be enabled only if su_bfer
     * is already enabled
     */
    if (vap->iv_he_su_bfer && vap->iv_he_mu_bfer) {
        val = HECAP_PHY_MUBFMR_GET_FROM_IC(ic_hecap_phy);
    }
    else {
        val = 0;
    }
    HECAP_PHY_MUBFMR_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s MU BFMR Val=%x hecap->hecap_phyinfo[4]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX4]);
    }

    if (vap->iv_he_su_bfee) {
        /* the vap variable is initialized from the corresponding
         * field stored in ic at service_ready processing and can
         * be overwritten by user
         */
        val = vap->iv_he_subfee_sts_lteq80;
    } else {
        /* According to 11ax draft 3.3 section 9.4.2.242.3,
         * HE subfee_sts_lteq80 field is 0 if subfee role is
         * not supported
         */
        val = 0;
    }
    HECAP_PHY_BFMENSTSLT80MHZ_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s BFME STS LT 80 Mhz Val=%x hecap->hecap_phyinfo[4]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX4]);
    }

    /* chwidht was calculated during B1-B7 (channel width set)
     * population. A value > IEEE80211_CWM_WIDTH80  will indicate
     * support of >=80MHz BW support
     */
    if (vap->iv_he_su_bfee && chwidth > IEEE80211_CWM_WIDTH80) {
        /* the vap variable is initialized from the corresponding
         * field stored in ic at service_ready processing and can
         * be overwritten by user
         */
        val = vap->iv_he_subfee_sts_gt80;
    } else {
        /* According to 11ax draft 3.3 section 9.4.2.242.3,
         * HE subfee_sts_gt80 field is 0 if subfee role is
         * not supported or if the Channel Width Set field
         * does not indicate support for bandwidths greater
         * than 80
         */
        val = 0;
    }
    HECAP_PHY_BFMENSTSGT80MHZ_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s BFME STS GT 80 Mhz Val=%x hecap->hecap_phyinfo[5]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX5]);
    }

    if (vap->iv_he_su_bfer) {
        /* No of sounding dimension field should be based
         * on chainmask rather than nss. nss indicates
         * tx/rx caps. Whereas, sounding dimension can
         * be as many as the no. of chains present.
         */
        val = MIN(ieee80211_getstreams(ic, ic->ic_tx_chainmask) - 1,
                HECAP_PHY_NUMSOUNDLT80MHZ_GET_FROM_IC(ic_hecap_phy));
        HECAP_PHY_NUMSOUNDLT80MHZ_SET_TO_IE(&hecap_phy_info, val);
    } else {
        /* According to 11ax draft D3.0 section 9.4.2.237.3,
         * no_of_sound_dimnsn_lteq80 is reserved if SU Bfmer
         * field is 0
         */
        val = 0;
    }

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Noof Sound Dim LTEQ 80 Mhz Val=%x hecap->hecap_phyinfo[5]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX5]);
    }

    /* For an AP current mode will be same as the mode it was brought up in.
     * For a STA the current mode will initially be same as the desired mode
     * and on association to an AP, current mode will be updated as per the
     * connection.
     */
    if (vap->iv_he_su_bfer &&
           ieee80211_is_phymode_11axa_160or8080(vap->iv_cur_mode)) {
        /* No of sounding dimension field should be based
         * on chainmask rather than nss. nss indicates
         * tx/rx caps. Whereas, sounding dimension can
         * be as many as the no. of chains present.
         */
        val = MIN(ieee80211_getstreams(ic, ic->ic_tx_chainmask) - 1,
               HECAP_PHY_NUMSOUNDGT80MHZ_GET_FROM_IC(ic_hecap_phy));
    } else {
        /* According to 11ax draft D3.0 section 9.4.2.237.3,
         * no_of_sound_dimnsn_gt80 is reserved if SU Bfmer
         * field is 0
         */
        val = 0;
    }
    HECAP_PHY_NUMSOUNDGT80MHZ_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Noof Sound Dim GT 80 Mhz Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    if(vap->iv_he_su_bfee) {
        val = HECAP_PHY_NG16SUFEEDBACKLT80_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_NG16SUFEEDBACKLT80_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Ng16 SU Feedback Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    if(vap->iv_he_mu_bfee) {
        val = HECAP_PHY_NG16MUFEEDBACKGT80_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_NG16MUFEEDBACKGT80_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Ng16 MU Feeback Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    if(vap->iv_he_su_bfee) {
        val = HECAP_PHY_CODBK42SU_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_CODBK42SU_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s CB SZ 4_2 SU Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    if(vap->iv_he_mu_bfee) {
        val = HECAP_PHY_CODBK75MU_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_CODBK75MU_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s CB SZ 7_5 MU Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    val = HECAP_PHY_BFFEEDBACKTRIG_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_BFFEEDBACKTRIG_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s BF FB Trigg Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_HEERSU_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_HEERSU_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s HE ER SU PPDU Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_DLMUMIMOPARTIALBW_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_DLMUMIMOPARTIALBW_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s DL MUMIMO Par BW Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_PPETHRESPRESENT_GET_FROM_IC(ic_hecap_phy);
    ppet_present = val;
    HECAP_PHY_PPETHRESPRESENT_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s PPE Thresh present Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_SRPSPRESENT_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_SRPPRESENT_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s SRPS SR Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_PWRBOOSTAR_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_PWRBOOSTAR_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Power Boost AR Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    /* the vap variable is initialized from the corresponding
     * field stored in ic at service_ready processing and can
     * be overwritten by user
     */
    val = vap->iv_he_su_mu_ppdu_4x_ltf_800ns_gi;
    HECAP_PHY_4XLTFAND800NSECSGI_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s 4X HE-LTF & 0.8 GI HE PPDU Val=%x hecap->hecap_phyinfo[7]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    /* the vap variable is initialized from the corresponding
     * field stored in ic at service_ready processing and can
     * be overwritten by user
     */
    val = vap->iv_he_max_nc;
    HECAP_PHY_MAX_NC_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s MAX Nc=%x hecap->hecap_phyinfo[7]=%x \n", __func__,
        val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    if ((vap->iv_tx_stbc) && (tx_streams > 1) &&
            (chwidth > IEEE80211_CWM_WIDTH80) &&
            (vap->iv_opmode != IEEE80211_M_HOSTAP)) {
        val = HECAP_PHY_STBCTXGT80_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_STBCTXGT80_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s STBC Tx GT 80MHz=%x hecap->hecap_phyinfo[7]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    if((vap->iv_rx_stbc) && (rx_streams > 0) &&
          (chwidth > IEEE80211_CWM_WIDTH80)) {
        val = HECAP_PHY_STBCRXGT80_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_STBCRXGT80_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s STBC Rx GT 80MHz=%x hecap->hecap_phyinfo[7]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = vap->iv_he_er_su_ppdu_4x_ltf_800ns_gi;
    HECAP_PHY_ERSU_4XLTF800NSGI_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s ERSU 4x LTF 800 ns GI=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_HEPPDU20IN40MHZ2G_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_HEPPDU20IN40MHZ2G_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s HE PPDU 20 in 40 MHZ 2G=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_HEPPDU20IN160OR80P80MHZ_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_HEPPDU20IN160OR80P80MHZ_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s HE PPDU 20 in 160 or 80+80 MHZ=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_HEPPDU80IN160OR80P80MHZ_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_HEPPDU80IN160OR80P80MHZ_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s HE PPDU 80 in 160 or 80+80 MHZ=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = vap->iv_he_er_su_ppdu_1x_ltf_800ns_gi;
    HECAP_PHY_ERSU1XLTF800NSGI_SET_TO_IE(&hecap_phy_info, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s ERSU 1x LTF 800 ns GI=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

#if SUPPORT_11AX_D3
    val = HECAP_PHY_MIDAMBLETXRX2XAND1XLTF_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_MIDAMBLETXRX2XAND1XLTF_SET_TO_IE(&hecap_phy_info, val);
#else
    val = HECAP_PHY_MIDAMBLERX2XAND1XLTF_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_MIDAMBLERX2XAND1XLTF_SET_TO_IE(&hecap_phy_info, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Midamble Rx 2x and 1x LTF=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

#if SUPPORT_11AX_D3

    val = HECAP_PHY_DCMMAXBW_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_DCMMAXBW_SET_TO_IE(&hecap_phy_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s DCM Max BW=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_LT16HESIGBOFDMSYM_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_LT16HESIGBOFDMSYM_SET_TO_IE(&hecap_phy_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Longer Than 16 HE SIG-B OFDM Symbols Support=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = HECAP_PHY_NONTRIGCQIFDBK_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_NONTRIGCQIFDBK_SET_TO_IE(&hecap_phy_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Non- Triggered CQI Feedback=%x hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    if (vap->iv_opmode == IEEE80211_M_STA) {
        val =  HECAP_PHY_TX1024QAMLT242TONERU_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_TX1024QAMLT242TONERU_SET_TO_IE(&hecap_phy_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Tx 1024- QAM < 242-tone RU Support=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = vap->iv_he_1024qam_lt242ru_rx;
    HECAP_PHY_RX1024QAMLT242TONERU_SET_TO_IE(&hecap_phy_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Rx 1024- QAM < 242-tone RU Support=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = HECAP_PHY_RXFULLBWSUHEMUPPDU_COMPSIGB_GET_FROM_IC(ic_hecap_phy);
    HECAP_PHY_RXFULLBWSUHEMUPPDU_COMPSIGB_SET_TO_IE(&hecap_phy_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Rx Full BW SU Using HE MU PPDU With Compressed SIGB=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    if (vap->iv_opmode == IEEE80211_M_STA) {
        val = HECAP_PHY_RXFULLBWSUHEMUPPDU_NONCOMPSIGB_GET_FROM_IC(ic_hecap_phy);
    } else {
        val = 0;
    }
    HECAP_PHY_RXFULLBWSUHEMUPPDU_NONCOMPSIGB_SET_TO_IE(&hecap_phy_info, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Rx Full BW SU Using HE MU PPDU With Non-Compressed SIGB=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s IC HE PPET ru3_ru0[0]=%x ru3_ru0[1]=%x ru3_ru0[2]=%x"
        " ru3_ru0[3]=%x ru3_ru0[4]=%x ru3_ru0[5]=%x ru3_ru0[6]=%x"
        " ru3_ru0[7]=%x \n",__func__,
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[0],
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[1],
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[2],
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[3],
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[4],
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[5],
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[6],
         ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0[7]);
    }

     /* Fill in TxRx HE NSS & MCS support */
    ieee80211_set_hecap_rates(ic, vap, ni, hecap, enable_log);

    if(ppet_present) {

        /* Fill in default PPET Fields
           3 bits for no of SS + 4 bits for RU bit enabled
           count + no of SS * ru bit enabled count * 6 bits
           (3 bits for ppet16 and 3 bits for ppet8)
        */

        ru_mask = ic->ic_he.hecap_ppet.ru_mask;

        HE_GET_RU_BIT_SET_COUNT_FROM_RU_MASK(ru_mask, ru_set_count);

        ppet_tot_bits = HE_CAP_PPET_NSS_RU_BITS_FIXED +
                       (nss * ru_set_count * HE_TOT_BITS_PPET16_PPET8);

        ppet_pad_bits = HE_PPET_BYTE - (ppet_tot_bits % HE_PPET_BYTE);

        ppet_bytes = (ppet_tot_bits + ppet_pad_bits) / HE_PPET_BYTE;

        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s PET TOT Bits =%d PPET PAD Bits=%d PPET Bytes=%d \n", __func__,
            ppet_tot_bits, ppet_pad_bits, ppet_bytes);
        }

        if(ppet_bytes != HECAP_PPET16_PPET8_MAX_SIZE)  {
            /* readjusting length field as per ppet info */
            hecap->elem_len -= HECAP_PPET16_PPET8_MAX_SIZE - ppet_bytes;
        }

        /* mcs_nss is a variable field. Readjusting he_ppet
         * pointer according to mcs_nss field
         */
        he_ppet = ((uint8_t *) hecap + (hecap->elem_len -
                                 ppet_bytes + IEEE80211_IE_HDR_LEN));

        qdf_mem_zero(he_ppet, ppet_bytes);

        /* Fill no of SS*/
        he_ppet[0] = (nss-1) & IEEE80211_HE_PPET_NUM_SS;

        /* Fill RU Bit mask */
        he_ppet[0] |= (ic->ic_he.hecap_ppet.ru_mask << IEEE80211_HE_PPET_RU_COUNT_S);

        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
              "%s TOT NSS =%d  ru_mask=%x he_ppet[0]=%x \n",
               __func__, nss ,ic->ic_he.hecap_ppet.ru_mask, he_ppet[0]);
        }

        /* extract and pack PPET16 & PPET8 for each RU and for each NSS */
        he_ppet16_ppet8_extract_pack(he_ppet, nss,
                ic->ic_he.hecap_ppet.ru_mask,
                ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0);
    }

    /* elem id + len = 2 bytes */
    hecaplen = hecap->elem_len + IEEE80211_IE_HDR_LEN;

    if (enable_log)  {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
          "%s HE CAP Length=%d Hex length =%x \n",
           __func__, hecaplen, hecaplen);
    }

    return frm + hecaplen;
}

u_int8_t *
ieee80211_add_6g_bandcap(u_int8_t *frm, struct ieee80211_node *ni,
                     struct ieee80211com *ic, u_int8_t subtype)
{
    struct ieee80211_ie_he_6g_bandcap *hecap_6g =
                            (struct ieee80211_ie_he_6g_bandcap *)frm;
    struct ieee80211_he_handle *ic_he = &ic->ic_he;
    uint8_t he_6g_cap_len;
    u_int8_t *he_cap_6g_info, val;
    u_int16_t ic_6g_hecap;

    qdf_mem_zero(hecap_6g, sizeof(struct ieee80211_ie_he_6g_bandcap));

    hecap_6g->elem_id = IEEE80211_ELEMID_EXTN;
    hecap_6g->elem_len = (sizeof(struct ieee80211_ie_he_6g_bandcap) -
                                            IEEE80211_IE_HDR_LEN);
    hecap_6g->elem_id_ext = IEEE80211_ELEMID_EXT_6G_HECAP;

    qdf_mem_copy(&ic_6g_hecap, ic_he->he6g_bandcap, sizeof(ic_he->he6g_bandcap));
    he_cap_6g_info = &hecap_6g->he_6g_bandcap[0];

    val = HECAP_6G_MINMPDU_START_SPACING_GET_FROM_IC(ic_6g_hecap);
    HECAP_6G_MINMPDU_START_SPACING_SET_TO_IE(&he_cap_6g_info, val);

    val = HECAP_6G_MAXAMPDU_LEN_EXP_GET_FROM_IC(ic_6g_hecap);
    HECAP_6G_MAXAMPDU_LEN_EXP_SET_TO_IE(&he_cap_6g_info, val);

    val = HECAP_6G_MAXMPDU_LEN_GET_FROM_IC(ic_6g_hecap);
    HECAP_6G_MAXMPDU_LEN_SET_TO_IE(&he_cap_6g_info, val);

    if (!ieee80211_vap_dynamic_mimo_ps_is_set(ni->ni_vap)) {
        /* Don't advertise Dynamic MIMO power save if not configured */
        val = (IEEE80211_HTCAP_C_SMPOWERSAVE_DISABLED >>
                IEEE80211_HTCAP_C_SMPOWERSAVE_S);
    } else {
        val = HECAP_6G_SMPS_GET_FROM_IC(ic_6g_hecap);
    }
    HECAP_6G_SMPS_SET_TO_IE(&he_cap_6g_info, val);

    val = HECAP_6G_RD_RESP_GET_FROM_IC(ic_6g_hecap);
    HECAP_6G_RD_RESP_SET_TO_IE(&he_cap_6g_info, val);

    val = HECAP_6G_RXANTENNA_PATTERN_CONS_GET_FROM_IC(ic_6g_hecap);
    HECAP_6G_RXANTENNA_PATTERN_CONS_SET_TO_IE(&he_cap_6g_info, val);

    val = HECAP_6G_TXANTENNA_PATTERN_CONS_GET_FROM_IC(ic_6g_hecap);
    HECAP_6G_TXANTENNA_PATTERN_CONS_SET_TO_IE(&he_cap_6g_info, val);


    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE_6GHZ,
    "%s HE 6GHz Band Capabilities=0x%x%x", __func__,
    hecap_6g->he_6g_bandcap[HECAP_6GBYTE_IDX1],
    hecap_6g->he_6g_bandcap[HECAP_6GBYTE_IDX0]);

    he_6g_cap_len = hecap_6g->elem_len + IEEE80211_IE_HDR_LEN;
    return frm + he_6g_cap_len;
}

/*
 * NSS, RU , ppett16 and ppet8 are extracted from IE
 * and stored in corresponding ni HE structure
 */
void
he_ppet16_ppet8_parse( u_int32_t* out_ppet, u_int8_t* in_ppet) {

    uint8_t tot_nss, tot_ppet, mask1, mask2;
    uint8_t  ru_mask8, ru_mask16, ru_mask;
    int32_t tmp_ppet1, tmp_ppet2, ppet, ru_set_count=0;
    int byte_idx, start, nss, ru, bits_parsed;
    uint8_t  ppet8_idx=0, ppet16_idx=0;

    tot_nss = (in_ppet[0] & IEEE80211_HE_PPET_NUM_SS);
    ru_mask = ((in_ppet[0] & IEEE80211_HE_PPET_RU_MASK) >>
                 IEEE80211_HE_PPET_RU_COUNT_S) + 1;

    ru_mask8 = ru_mask16 = ru_mask;
    HE_GET_RU_BIT_SET_COUNT_FROM_RU_MASK(ru_mask, ru_set_count);

    /* 3 bits for no of SS + 4 bits for RU mask */
    bits_parsed = HE_CAP_PPET_NSS_RU_BITS_FIXED;
    tot_ppet = ru_set_count * HE_PPET16_PPET8;
    for (nss = 0; nss <= tot_nss; nss++) {
        for (ru = 1; ru <= tot_ppet; ru++) {
            start = bits_parsed + (nss * (tot_ppet * HE_PPET_FIELD)) +
                                                 (ru - 1) * HE_PPET_FIELD;
            byte_idx = start / HE_PPET_BYTE;
            start = start % HE_PPET_BYTE;

            mask1 = HE_PPET16_PPET8_MASK << start;
            if (start <= HE_PPET_MAX_BIT_POS_FIT_IN_BYTE) {
                /* parse ppet with in a byte*/
                ppet = (in_ppet[byte_idx] & mask1) >> start;
            } else {
                /* parse ppet in more than 1 byte*/
                tmp_ppet1 = (in_ppet[byte_idx] & mask1) >> start;
                mask2 = HE_PPET16_PPET8_MASK >> (HE_PPET_BYTE - start);
                tmp_ppet2 = (in_ppet[byte_idx + 1] & mask2) << (HE_PPET_BYTE - start);
                ppet = tmp_ppet1 | tmp_ppet2;
            }

            /* store in ni ppet field */
            if (ru % HE_PPET16_PPET8 == 1) {
                HE_NEXT_IDX_FROM_RU_MASK_AND_OLD_IDX(ru_mask8, ppet8_idx);
                HE_SET_PPET8(out_ppet, ppet,  ppet8_idx, nss);
            } else {
                HE_NEXT_IDX_FROM_RU_MASK_AND_OLD_IDX(ru_mask16, ppet16_idx);
                HE_SET_PPET16(out_ppet, ppet, ppet16_idx,  nss);
            }
        }
    }
}

/*
 * Phy capabilities values are extracted from IE
 * byte array based on idx & total bits
 */
u_int32_t
hecap_ie_get(u_int8_t *hecap, u_int8_t idx, u_int32_t
                tot_bits)  {

    u_int8_t fit_bits=0, byte_cnt=0, temp_val;
    u_int8_t cur_idx=0;
    u_int32_t val=0;

    temp_val = *(hecap);
    idx = idx % 8;
    fit_bits = 8 - idx;
    fit_bits = ( tot_bits > fit_bits) ? 8 - idx: tot_bits ;

    while (( tot_bits + idx) > 8 ) {
        val |= ((temp_val >> idx ) & ((1 << (fit_bits)) - 1)) << cur_idx;
        tot_bits = tot_bits - fit_bits;
        idx = idx + fit_bits;
        if( idx == 8 ) {
            idx = 0;
            byte_cnt ++;
            temp_val = *(hecap + byte_cnt);
        }
        cur_idx = cur_idx + fit_bits;

       fit_bits = 8 - idx;
       fit_bits = ( tot_bits > fit_bits) ? 8 - idx: tot_bits ;
    }

    if ((idx + tot_bits) <= 8 ) {
        val |= ((temp_val >> idx)  & ((1 << fit_bits) -1)) << cur_idx;
    }

    return val;
}

static bool
ieee80211_is_basic_mcsnss_requirement_met(uint16_t mcsnssmap,
                                          uint8_t basic_mcs,
                                          uint8_t basic_nss) {
    uint8_t peer_nss, peer_mcs, nss_count = 0;
    bool basic_mcsnss_req_met = true;

    HE_DERIVE_PEER_NSS_FROM_MCSMAP(mcsnssmap, peer_nss);

    /* if nss value derived from mcsnssmap is less
     * then the basic requirement of the bss then fail
     */
    if (peer_nss < basic_nss) {
        basic_mcsnss_req_met = false;
    }

    /* if mcs value for each of the streams that the peer
     * supports does not meet the basic requirement for
     * the bss then fail
     */
    for (nss_count = 0; ((nss_count < peer_nss) &&
        basic_mcsnss_req_met); nss_count++) {
        peer_mcs = mcsbits(mcsnssmap, nss_count+1);
        if ((peer_mcs == HE_INVALID_MCSNSSMAP) ||
              (peer_mcs < basic_mcs)) {
            basic_mcsnss_req_met = false;
        }
    }

    return basic_mcsnss_req_met;
}

bool
ieee80211_is_basic_txrx_mcsnss_requirement_met(struct ieee80211_node *ni,
                                               uint8_t mcsnss_idx) {
    struct ieee80211_he_handle *ni_he = &ni->ni_he;
    struct ieee80211vap *vap          = ni->ni_vap;

    if (vap->iv_opmode == IEEE80211_M_STA) {
        /* If the Basic MCS NSS requirement advertised by the AP
         * in HEOP itself is invalid switch to VHT mode.
         */
        if ((vap->iv_he_basic_mcs_for_bss & 0x03) == HE_MCS_VALUE_INVALID) {
            return false;
        }
    }

    return (ieee80211_is_basic_mcsnss_requirement_met(
                ni_he->hecap_txmcsnssmap[mcsnss_idx],
                vap->iv_he_basic_mcs_for_bss, vap->iv_he_basic_nss_for_bss)
           &&
           ieee80211_is_basic_mcsnss_requirement_met(
                ni_he->hecap_rxmcsnssmap[mcsnss_idx],
                vap->iv_he_basic_mcs_for_bss, vap->iv_he_basic_nss_for_bss));
}

/* store the max cap of the ni before intersection */
static void ieee80211_store_org_mcsnssmap(struct ieee80211_node *ni,
                                          struct ieee80211_he_handle *ni_he,
                                          uint8_t *hecap_txrx)

{
        int i;

        if (ni->ni_he_width_set_org & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) {
            i = HECAP_TXRX_MCS_NSS_IDX_80_80;
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX8],
                    &ni_he->hecap_rxmcsnssmap_org[i]);
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX10],
                    &ni_he->hecap_txmcsnssmap_org[i]);
        }

        if (ni->ni_he_width_set_org & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) {
            i = HECAP_TXRX_MCS_NSS_IDX_160;
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX4],
                    &ni_he->hecap_rxmcsnssmap_org[i]);
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX6],
                    &ni_he->hecap_txmcsnssmap_org[i]);
        }

        /*---------- Store hecap_txmcsnssmap_org for 20/40/80 BWs ---------*/

        i = HECAP_TXRX_MCS_NSS_IDX_80;
        (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX0],
                &ni_he->hecap_rxmcsnssmap_org[i]);
        (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX2],
                &ni_he->hecap_txmcsnssmap_org[i]);
}

static QDF_STATUS
ieee80211_hecap_parse_mcs_nss(struct ieee80211_node *ni,
                              struct ieee80211vap  *vap,
                              uint8_t *hecap_txrx,
                              bool enable_log,
                              uint8_t *mcsnssbytes) {
    struct ieee80211_bwnss_map nssmap;
    struct ieee80211_he_handle *ni_he = &ni->ni_he;
    struct ieee80211com *ic           = ni->ni_ic;
    uint8_t tx_chainmask              = ieee80211com_get_tx_chainmask(ic);
    uint8_t rx_chainmask              = ieee80211com_get_rx_chainmask(ic);
    uint8_t rx_streams                = ieee80211_get_rxstreams(ic, vap);
    uint8_t tx_streams                = ieee80211_get_txstreams(ic, vap);
    uint16_t temp_self_mcsnssmap;
    uint16_t temp_peer_mcsnssmap;
    uint16_t rxmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint16_t txmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint32_t ni_bw80p80_nss, ni_bw160_nss, ni_streams;
    uint8_t tx_streams_160 = 0;
    uint8_t rx_streams_160 = 0;
    uint8_t chwidth;

    if (!(ieee80211_is_phymode_allowed(ni->ni_phymode))) {
        ieee80211_note(vap, IEEE80211_MSG_HE,
              "%s WARNING!!! Unsupported ni_phymode=%x\n",
                      __func__, ni->ni_phymode);
        ni->ni_ext_flags &= ~IEEE80211_NODE_HE;
        qdf_mem_zero(&ni->ni_he, sizeof(struct ieee80211_he_handle));
        return QDF_STATUS_E_INVAL;
    }

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
          "%s ni->ni_phymode is = 0x%x \n",__func__, ni->ni_phymode);
    }

    ieee80211_store_org_mcsnssmap(ni, ni_he, hecap_txrx);

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic->ic_cwm_get_width(ic);
    }

    nssmap.bw_nss_160 = 0;
    nssmap.bw_rxnss_160 = 0;

    if(chwidth >= IEEE80211_CWM_WIDTH160 &&
            ic->ic_get_bw_nss_mapping) {
        if(ic->ic_get_bw_nss_mapping(vap, &nssmap, tx_chainmask)) {
            /* if error then reset nssmap */
            tx_streams_160 = 0;
        } else {
            tx_streams_160 = nssmap.bw_nss_160;
        }

        if(ic->ic_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
            /* if error then reset nssmap */
            rx_streams_160 = 0;
        } else {
            rx_streams_160 = nssmap.bw_rxnss_160;
        }
    }

    /* get the intersected (user-set vs target caps)
     * values of mcsnssmap */
    ieee80211vap_get_insctd_mcsnssmap(vap, rxmcsnssmap, txmcsnssmap);

    *mcsnssbytes = 0;
    switch(ni->ni_phymode) {
        case IEEE80211_MODE_11AXA_HE80_80:
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX8],
                        &ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80]);
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX10],
                        &ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80]);

            /* Set the bits for unsupported SS in the self RX map to Invalid */
            (void)qdf_get_u16((uint8_t *)&rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                              &temp_self_mcsnssmap);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
                    (uint8_t *)&temp_self_mcsnssmap, rx_streams_160);

            /* Convert self_mcsnssmap to LE format before performing intersection
             * with peer_mcsnssmap */
            temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
            temp_peer_mcsnssmap = ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80];

            /* Intersection of self Rx mcsnssmap and peer Tx mcsnssmap support
             * will indicate Tx MCS-NSS support for the peer.
             */
            ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80] =
                INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

            /* Set the bits for unsupported SS in the self TX map to Invalid */
            (void)qdf_get_u16((uint8_t *)&txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                        &temp_self_mcsnssmap);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
                    (uint8_t *)&temp_self_mcsnssmap, tx_streams_160);

            /* Convert self_mcsnssmap to LE format before performing intersection
             * with peer_mcsnssmap */
            temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
            temp_peer_mcsnssmap = ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80];

            /* Intersection of self Tx mcsnssmap and peer Rx mcsnssmap support
             * will indicate Rx MCS-NSS support for the peer.
             */
            ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80] =
                INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

            /* If mcsnssmap advertised by the peer does not meet
             * the basic mcsnss requirement as advertised in heop
             * then allow association only in VHT mode.
             */
            if (ieee80211_is_basic_txrx_mcsnss_requirement_met(
                        ni, HECAP_TXRX_MCS_NSS_IDX_80_80)) {
                HE_DERIVE_PEER_NSS_FROM_MCSMAP(
                    ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                    ni_bw80p80_nss);
                ni->ni_bw80p80_nss = QDF_MAX(ni->ni_bw80p80_nss, ni_bw80p80_nss);
                ni->ni_he.he_basic_txrxmcsnss_req_met_80_80 = true;
            } else {
                qdf_info("Basic mcsnss req failed for 80p80"
                         " - adjusting ni chwidth and phymode to 160MHz");
                ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                ni->ni_phymode = IEEE80211_MODE_11AXA_HE160;
                ni->ni_he.he_basic_txrxmcsnss_req_met_80_80 = false;
            }

            *mcsnssbytes += HE_NBYTES_MCS_NSS_FIELD_PER_BAND;

            /* fall through */
        case IEEE80211_MODE_11AXA_HE160:
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX4],
                        &ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160]);
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX6],
                        &ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160]);

            /* Set the bits for unsupported SS in the self RX map to Invalid */
            (void)qdf_get_u16((uint8_t *)&rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                              &temp_self_mcsnssmap);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
                    (uint8_t *)&temp_self_mcsnssmap, rx_streams_160);

            /* Convert self_mcsnssmap to LE format before performing intersection
             * with peer_mcsnssmap */
            temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
            temp_peer_mcsnssmap = ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160];

            /* Intersection of self Rx mcsnssmap and peer Tx mcsnssmap support
             * will indicate Tx MCS-NSS support for the peer.
             */
            ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160] =
                INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

            /* Set the bits for unsupported SS in the self TX map to Invalid */
            (void)qdf_get_u16((uint8_t *)&txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                              &temp_self_mcsnssmap);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
                    (uint8_t *)&temp_self_mcsnssmap, tx_streams_160);

            /* Convert self_mcsnssmap to LE format before performing intersection
             * with peer_mcsnssmap */
            temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
            temp_peer_mcsnssmap = ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160];

            /* Intersection of self Tx mcsnssmap and peer Rx mcsnssmap support
             * will indicate Rx MCS-NSS support for the peer.
             */
            ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160] =
                INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

            /* If mcsnssmap advertised by the peer does not meet
             * the basic mcsnss requirement as advertised in heop
             * then allow association only in VHT mode.
             */
            if (ieee80211_is_basic_txrx_mcsnss_requirement_met(
                        ni, HECAP_TXRX_MCS_NSS_IDX_160)) {
                HE_DERIVE_PEER_NSS_FROM_MCSMAP(
                    ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                    ni_bw160_nss);
                ni->ni_bw160_nss = QDF_MAX(ni->ni_bw160_nss, ni_bw160_nss);
                ni->ni_he.he_basic_txrxmcsnss_req_met_160 = true;
            } else {
                qdf_info("Basic mcsnss req failed for 160"
                         " - adjusting ni chwidth and phymode to 80Mhz");
                ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                ni->ni_phymode = IEEE80211_MODE_11AXA_HE80;
                ni->ni_he.he_basic_txrxmcsnss_req_met_160 = false;
            }

            *mcsnssbytes += HE_NBYTES_MCS_NSS_FIELD_PER_BAND;

            /* fall through */
        default:
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX0],
                        &ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80]);
            (void)qdf_get_u16(&hecap_txrx[HECAP_TXRX_MCS_NSS_IDX2],
                        &ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80]);

            /* Set the bits for unsupported SS in the self RX map to Invalid */
            (void)qdf_get_u16((uint8_t *)&rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                              &temp_self_mcsnssmap);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
                    (uint8_t *)&temp_self_mcsnssmap, rx_streams);

            /* Convert self_mcsnssmap to LE format before performing intersection
             * with peer_mcsnssmap */
            temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
            temp_peer_mcsnssmap = ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80];

            ni->ni_maxrxstreams = get_nss_frm_mcsnssmap(ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80]);
            ni->ni_maxtxstreams = get_nss_frm_mcsnssmap(ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80]);

            /* Intersection of self Rx mcsnssmap and peer Tx mcsnssmap support
             * will indicate Tx MCS-NSS support for the peer.
             */
            ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80] =
                INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);


            /* Set the bits for unsupported SS in the self TX map to Invalid */
            (void)qdf_get_u16((uint8_t *)&txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                              &temp_self_mcsnssmap);
            HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
                    (uint8_t *)&temp_self_mcsnssmap, tx_streams);

            /* Convert self_mcsnssmap to LE format before performing intersection
             * with peer_mcsnssmap */
            temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
            temp_peer_mcsnssmap = ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80];

            /* Intersection of self Tx mcsnssmap and peer Rx mcsnssmap support
             * will indicate Rx MCS-NSS support for the peer.
             */
            ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80] =
                INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

            /* If mcsnssmap advertised by the peer does not meet
             * the basic mcsnss requirement as advertised in heop
             * then allow association only in VHT mode.
             */
            if (ieee80211_is_basic_txrx_mcsnss_requirement_met(
                        ni, HECAP_TXRX_MCS_NSS_IDX_80)) {
                HE_DERIVE_PEER_NSS_FROM_MCSMAP(
                    ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                    ni_streams);
                ni->ni_streams = QDF_MAX(ni->ni_streams, ni_streams);
            } else {
                qdf_rl_err("%s peer HE mcsnssmap does not meet basic requirenment"
                          " for the bss. Allowing association only in VHT mode", __func__);
                ni->ni_ext_flags &= ~IEEE80211_NODE_HE;
                qdf_mem_zero(&ni->ni_he, sizeof(struct ieee80211_he_handle));
                return QDF_STATUS_E_INVAL;
            }

            *mcsnssbytes += HE_NBYTES_MCS_NSS_FIELD_PER_BAND;
            break;
    }

    if (enable_log || ((ni->ni_ext_flags & IEEE80211_NODE_HE) &&
            (ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160]
             == HE_INVALID_MCSNSSMAP ||
             ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160]
             == HE_INVALID_MCSNSSMAP))) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s ni_he->rxmcsnssmap[80MHz]=%x ni_he->txmcsnssmap[80MHz]=%x"
            " ni_he->rxmcsnssmap[160MHz]=%x ni_he->txmcsnssmap[160MHz]=%x"
            " ni_he->rxmcsnssmap[80_80MHz]=%x ni_he->txmcsnssmap[80_80MHz]=%x"
            " *mcsnssbytes=%x \n",__func__,
             ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
             ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
             ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
             ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
             ni_he->hecap_rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
             ni_he->hecap_txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
             *mcsnssbytes
             );
    }

    return QDF_STATUS_SUCCESS;
}

static void
hecap_parse_channelwidth(struct ieee80211_node *ni,
                         u_int32_t *in_width) {

    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;
    u_int32_t he_width = *in_width;
    u_int8_t chwidth, width_set;

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic->ic_cwm_get_width(ic);
    }

    /* 11AX TODO (Phase II) . Width parsing needs to be
       revisited for addressing grey areas in spec
     */
    switch(chwidth) {
        case IEEE80211_CWM_WIDTH20:
            ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            break;

        case IEEE80211_CWM_WIDTH40:
            width_set = he_width & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_MASK;
            if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                if(width_set) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                }
            } else {
                /* HTCAP Channelwidth will be set to max for 11ax */
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                } else {
                    /* width_set check not required */
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                }
            }
            break;

       case IEEE80211_CWM_WIDTH80:
            width_set = he_width & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_MASK;
            if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                if(width_set) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                }
            } else {
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                } else if (!(ni->ni_vhtcap)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                } else if(width_set) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                }
            }
            break;

       case IEEE80211_CWM_WIDTH160:
            width_set = he_width & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_HE160_HE80_80_MASK;
            if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                }
            } else {
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                } else if (!(ni->ni_vhtcap)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) {
                    if (ic->ic_ext_nss_capable && !ni->ni_ext_nss_capable)
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                    else
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) {
                    if (ic->ic_ext_nss_capable && !ni->ni_ext_nss_capable) {
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                    } else {
                        /* Since both current chwidth of 160 and 80+80 mode fall into
                         * this switch case, and because STA is not capable of 80+80
                         * mode, check if current mode is 80+80, then associate the
                         * station with only 80MHz because STA only supports 160 and
                         * not 80+80
                         */
                        if (ieee80211_is_phymode_11axa_he80_80(vap->iv_cur_mode)) {
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                        } else {
                            ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                        }
                    }
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                }
            }
            break;

        case IEEE80211_CWM_WIDTH80_80:
            width_set = he_width & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE40_HE80_HE160_HE80_80_MASK;
            if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80_80;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                }
            } else {
                if (!(ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
                } else if (!(ni->ni_vhtcap)) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) {
                    if (ic->ic_ext_nss_capable && !ni->ni_ext_nss_capable)
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                    else
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH80_80;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) {
                    if (ic->ic_ext_nss_capable && !ni->ni_ext_nss_capable)
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                    else
                        ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                } else if(width_set & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
                } else {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
                }
            }
            break;

        default:
            /* Do nothing */
        break;
    }
}


void
ieee80211_parse_hecap(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype)
{
    struct ieee80211_ie_hecap *hecap  = (struct ieee80211_ie_hecap *)ie;
    struct ieee80211_he_handle *ni_he = &ni->ni_he;
    struct ieee80211com *ic           = ni->ni_ic;
    struct ieee80211vap *vap          = ni->ni_vap;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    uint32_t *ni_ppet, val=0, *ni_hecap_phyinfo;
    uint32_t ni_hecap_macinfo;
    uint8_t *hecap_phy_ie, ppet_present, *hecap_mac_ie;
    uint8_t rx_streams = ieee80211_get_rxstreams(ic, vap);
    uint8_t tx_streams = ieee80211_get_txstreams(ic, vap);
    uint8_t mcsnssbytes;
    bool enable_log = false;
    uint32_t ampdu_len = 0;
    QDF_STATUS status = QDF_STATUS_E_INVAL;

    pdev = ic->ic_pdev_obj;
    if(!pdev) {
        qdf_err("null pdev");
        return;
    }

    psoc = wlan_pdev_get_psoc(pdev);
    if (!psoc) {
        qdf_err("null psoc");
        return;
    }

    /* Negotiated HE PHY Capability.
     * Parse & set to node HE handle
     */

    hecap_phy_ie = &hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0];

    ni_hecap_phyinfo = &ni_he->hecap_phyinfo[HECAP_PHYBYTE_IDX0];

    /* Fill in default from IE HE MAC Capabilities */
    qdf_mem_copy(&ni_he->hecap_macinfo, &hecap->hecap_macinfo,
                 qdf_min(sizeof(hecap->hecap_macinfo),
                 sizeof(ni_he->hecap_macinfo)));

    qdf_mem_copy(&ni_hecap_macinfo, &ni_he->hecap_macinfo[0],
                 sizeof(ni_hecap_macinfo));

    if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
         subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {

         enable_log = true;
    }

    /* Mark HE node */
    ni->ni_ext_flags |= IEEE80211_NODE_HE;

    hecap_mac_ie = &hecap->hecap_macinfo[HECAP_MACBYTE_IDX0];
#if SUPPORT_11AX_D3
    ampdu_len = HECAP_MAC_MAXAMPDULEN_EXPEXT_GET_FROM_IE(&hecap_mac_ie);
#else
    ampdu_len = HECAP_MAC_MAXAMPDULEN_EXP_GET_FROM_IE(&hecap_mac_ie);
#endif

    /* As per section 26.6.1 11ax Draft4.0, if the Max AMPDU Exponent Extension
     * in HE cap is zero, use the ni_maxampdu as calculated while parsing
     * VHT caps(if VHT caps is present) or HT caps (if VHT caps is not present).
     *
     * For non-zero value of Max AMPDU Extponent Extension in HE MAC caps,
     * if a HE STA sends VHT cap and HE cap IE in assoc request then, use
     * MAX_AMPDU_LEN_FACTOR as 20 to calculate max_ampdu length.
     * If a HE STA that does not send VHT cap, but HE and HT cap in assoc
     * request, then use MAX_AMPDU_LEN_FACTOR as 16 to calculate max_ampdu
     * length.
     */
    if(ampdu_len) {
        if (ni->ni_vhtcap) {
            ni->ni_maxampdu = (1u << (IEEE80211_HE_VHT_CAP_MAX_AMPDU_LEN_FACTOR + ampdu_len)) -1;
        } else if (ni->ni_htcap) {
            ni->ni_maxampdu = (1u << (IEEE80211_HE_HT_CAP_MAX_AMPDU_LEN_FACTOR + ampdu_len)) -1;
        } else if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            /* Incase of 6GHz, since the 6G band cap is parsed after HE caps
             * save the exponent extension from HE cap and add it while parsing
             * 6G band caps.
             */
            ni->ni_maxampdu = ampdu_len;
        }
    }

    val = HECAP_MAC_TWTREQ_GET_FROM_IE(&hecap_mac_ie);
    if (val)
        ni->ni_ext_flags |= IEEE80211_NODE_TWT_REQUESTER;

    val = HECAP_MAC_TWTRSP_GET_FROM_IE(&hecap_mac_ie);
    if (val)
        ni->ni_ext_flags |= IEEE80211_NODE_TWT_RESPONDER;

    val = HECAP_MAC_BCSTTWT_GET_FROM_IE(&hecap_mac_ie);
    val &= wlan_psoc_nif_feat_cap_get(psoc, WLAN_SOC_F_BCAST_TWT);
    if (val)
        ni->ni_ext_flags |= IEEE80211_NODE_BCAST_TWT;
    HECAP_MAC_BCSTTWT_SET_TO_IC(ni_hecap_macinfo, val);
    qdf_mem_copy(&ni_he->hecap_macinfo[0], &ni_hecap_macinfo, sizeof(ni_hecap_macinfo));

   /* Overriding Mac Capabilities based on vap configuration */


    /* Fill in default from IE HE PHY Capabilities */
#if !SUPPORT_11AX_D3
    val = HECAP_PHY_DB_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_DB_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
               "%s NI Dual Band Val=%x hecap->hecap_phyinfo[0]=%x \n",
                __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0]);
    }
#endif

    ni->ni_he_width_set_org = val = HECAP_PHY_CBW_GET_FROM_IE(&hecap_phy_ie);
    hecap_parse_channelwidth(ni, &val);
    HECAP_PHY_CBW_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
          "%s NI Channel Width Val=%x ni_widhth= %x"
          "hecap->hecap_phyinfo[0]=%x \n",
           __func__, val, ni->ni_chwidth,
           hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX0]);
    }

    val = HECAP_PHY_PREAMBLEPUNCRX_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_PREAMBLEPUNCRX_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
              "%s NI RX Preamble Punc Val=%x hecap->hecap_phyinfo[1]=%x \n",
               __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

    val = HECAP_PHY_COD_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_COD_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
              "%s NI DCM Val=%x hecap->hecap_phyinfo[1]=%x \n",
               __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

    val = HECAP_PHY_LDPC_GET_FROM_IE(&hecap_phy_ie);
    if (!(val && vap->vdev_mlme->proto.generic.ldpc)) {
        val = 0;
    }
    HECAP_PHY_LDPC_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
                    "%s NI LDPC Val=%x hecap->hecap_phyinfo[1]=%x \n",
                     __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

    val = HECAP_PHY_SU_1XLTFAND800NSECSGI_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_SU_1XLTFAND800NSECSGI_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s NI LTF & GI Val=%x hecap->hecap_phyinfo[1]=%x \n"
            ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1]);
    }

#if SUPPORT_11AX_D3
    val = HECAP_PHY_MIDAMBLETXRXMAXNSTS_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_MIDAMBLETXRXMAXNSTS_SET_TO_IC(ni_hecap_phyinfo, val);
#else
    val = HECAP_PHY_MIDAMBLERXMAXNSTS_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_MIDAMBLERXMAXNSTS_SET_TO_IC(ni_hecap_phyinfo, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s Midamble Rx Max NSTS Val=%x hecap->hecap_phyinfo[1]=%x"
            " hecap->hecap_phyinfo[2]=%x \n"
            ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX1],
            hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_LTFGIFORNDP_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_LTFGIFORNDP_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s NI LTF & GI NDP  Val=%x hecap->hecap_phyinfo[2]=%x \n"
         ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    /* Rx on our side and Tx on the remote side should be considered for STBC with rate control */
    val = HECAP_PHY_TXSTBC_GET_FROM_IE(&hecap_phy_ie);
    if (!(val && vap->iv_rx_stbc && (rx_streams > 1))) {
        val = 0;
    }
    HECAP_PHY_TXSTBC_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
       "%s NI TXSTBC Val=%x hecap->hecap_phyinfo[2]=%x \n"
        ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    /* Tx on our side and Rx on the remote side should be considered for STBC with rate control */
    val = HECAP_PHY_RXSTBC_GET_FROM_IE(&hecap_phy_ie);
    if (!(val && vap->iv_tx_stbc && (tx_streams > 1))) {
        val = 0;
    }
    HECAP_PHY_RXSTBC_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
       "%s NI RXSTBC Val=%x hecap->hecap_phyinfo[2]=%x \n"
        ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_TXDOPPLER_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_TXDOPPLER_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI TX Doppler Val=%x hecap->hecap_phyinfo[2]=%x \n"
         ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_RXDOPPLER_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_RXDOPPLER_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI RXDOPPLER Val=%x hecap->hecap_phyinfo[2]=%x \n"
          ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_UL_MU_MIMO_GET_FROM_IE(&hecap_phy_ie);
    if (!(val && vap->iv_he_ul_mumimo)) {
        val = 0;
    }
    HECAP_PHY_UL_MU_MIMO_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI UL MU MIMO Val=%x hecap->hecap_phyinfo[2]=%x \n"
        ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_ULOFDMA_GET_FROM_IE(&hecap_phy_ie);
    if (!(val && vap->iv_he_ul_muofdma)) {
        val = 0;
    }
    HECAP_PHY_ULOFDMA_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
         "%s UL OFDMA Val=%x  hecap->hecap_phyinfo[2]=%x \n",
         __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX2]);
    }

    val = HECAP_PHY_DCMTX_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_DCMTX_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
                "%s NI TX DCM Val=%x  hecap->hecap_phyinfo[3]=%x \n",
        __func__, val,  hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    val = HECAP_PHY_DCMRX_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_DCMRX_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI RX DCM Val=%x  hecap->hecap_phyinfo[3]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    val = HECAP_PHY_ULHEMU_PPDU_PAYLOAD_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_ULHEMU_PPDU_PAYLOAD_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
           "%s NI UL HE MU PPDU Val=%x hecap->hecap_phyinfo[3]=%x  \n"
               ,__func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    val = HECAP_PHY_SUBFMR_GET_FROM_IE(&hecap_phy_ie);
    if (!(val && vap->iv_he_su_bfee)) {
        val = 0;
    }
    HECAP_PHY_SUBFMR_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI SU BFMR Val=%x hecap->hecap_phyinfo[3]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX3]);
    }

    val = HECAP_PHY_SUBFME_GET_FROM_IE(&hecap_phy_ie);
    if (!(val && vap->iv_he_su_bfer)) {
        val = 0;
    }
    HECAP_PHY_SUBFME_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI SU BFEE Val=%x hecap->hecap_phyinfo[4]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX4]);
    }

    val = HECAP_PHY_MUBFMR_GET_FROM_IE(&hecap_phy_ie);
    if (!((vap->iv_opmode == IEEE80211_M_STA) && (val && vap->iv_he_mu_bfee))) {
        val = 0;
    }
    HECAP_PHY_MUBFMR_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI MU BFMR Val=%x hecap->hecap_phyinfo[4]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX4]);
    }

    val = HECAP_PHY_BFMENSTSLT80MHZ_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_BFMENSTSLT80MHZ_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI BFME STS LT 80 Mhz Val=%x hecap->hecap_phyinfo[4]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX4]);
    }

    val = HECAP_PHY_BFMENSTSGT80MHZ_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_BFMENSTSGT80MHZ_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI BFME STS GT 80 Mhz Val=%x hecap->hecap_phyinfo[5]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX5]);
    }

    val = HECAP_PHY_NUMSOUNDLT80MHZ_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_NUMSOUNDLT80MHZ_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI Noof Sound Dim LT 80 Mhz Val=%x hecap->hecap_phyinfo[5]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX5]);
    }

    val = HECAP_PHY_NUMSOUNDGT80MHZ_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_NUMSOUNDGT80MHZ_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI Noof Sound Dim GT 80 Mhz Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    val = HECAP_PHY_NG16SUFEEDBACKLT80_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_NG16SUFEEDBACKLT80_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI Ng16 SU Feedback Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    val = HECAP_PHY_NG16MUFEEDBACKGT80_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_NG16MUFEEDBACKGT80_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI Ng16 MU Feeback Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    val = HECAP_PHY_CODBK42SU_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_CODBK42SU_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI CB SZ 4_2 SU Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    val = HECAP_PHY_CODBK75MU_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_CODBK75MU_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI CB SZ 7_5 MU Val=%x hecap->hecap_phyinfo[6]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX6]);
    }

    val = HECAP_PHY_BFFEEDBACKTRIG_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_BFFEEDBACKTRIG_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI BF FB Trigg Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_HEERSU_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_HEERSU_SET_TO_IC(ni_hecap_phyinfo, val);
    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI HE ER SU PPDU Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_DLMUMIMOPARTIALBW_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_DLMUMIMOPARTIALBW_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI DL MUMIMO Par BW Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_PPETHRESPRESENT_GET_FROM_IE(&hecap_phy_ie);
    ppet_present = val;
    HECAP_PHY_PPETHRESPRESENT_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI PPE Thresh present Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_SRPSPRESENT_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_SRPPRESENT_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI SRPS SR Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_PWRBOOSTAR_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_PWRBOOSTAR_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI Power Boost AR Val=%x hecap->hecap_phyinfo[7]=%x \n",__func__,
         val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_4XLTFAND800NSECSGI_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_4XLTFAND800NSECSGI_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI 4X HE-LTF & 0.8 GI HE PPDU Val=%x hecap->hecap_phyinfo[7]=%x \n",
        __func__, val , hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_MAX_NC_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_MAX_NC_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s MAX Nc=%x hecap->hecap_phyinfo[7]=%x \n", __func__,
        val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_STBCTXGT80_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_STBCTXGT80_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s STBC Tx GT 80MHz=%x hecap->hecap_phyinfo[7]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_STBCRXGT80_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_STBCRXGT80_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s STBC Rx GT 80MHz=%x hecap->hecap_phyinfo[7]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX7]);
    }

    val = HECAP_PHY_ERSU_4XLTF800NSGI_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_ERSU_4XLTF800NSGI_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s ERSU 4x LTF 800 ns GI=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_HEPPDU20IN40MHZ2G_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_HEPPDU20IN40MHZ2G_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s HE PPDU 20 in 40 MHZ 2G=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_HEPPDU20IN160OR80P80MHZ_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_HEPPDU20IN160OR80P80MHZ_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s HE PPDU 20 in 160 or 80+80 MHZ=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_HEPPDU80IN160OR80P80MHZ_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_HEPPDU80IN160OR80P80MHZ_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s HE PPDU 80 in 160 or 80+80 MHZ=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_ERSU1XLTF800NSGI_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_ERSU1XLTF800NSGI_SET_TO_IC(ni_hecap_phyinfo, val);

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s ERSU 1x LTF 800 ns GI=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

#if SUPPORT_11AX_D3
    val = HECAP_PHY_MIDAMBLETXRX2XAND1XLTF_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_MIDAMBLETXRX2XAND1XLTF_SET_TO_IC(ni_hecap_phyinfo, val);
#else
    val = HECAP_PHY_MIDAMBLERX2XAND1XLTF_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_MIDAMBLERX2XAND1XLTF_SET_TO_IC(ni_hecap_phyinfo, val);
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Midamble Rx 2x and 1x LTF=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s NI hecap_macinfo = %x \n",__func__, ni_hecap_macinfo);
    }

#if SUPPORT_11AX_D3
    val = HECAP_PHY_DCMMAXBW_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_DCMMAXBW_SET_TO_IC(ni_hecap_phyinfo, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s DCM Max BW=%x hecap->hecap_phyinfo[8]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX8]);
    }

    val = HECAP_PHY_LT16HESIGBOFDMSYM_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_LT16HESIGBOFDMSYM_SET_TO_IC(ni_hecap_phyinfo, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Longer Than 16 HE SIG-B OFDM Symbols Support=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = HECAP_PHY_NONTRIGCQIFDBK_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_NONTRIGCQIFDBK_SET_TO_IC(ni_hecap_phyinfo, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Non- Triggered CQI Feedback=%x hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = HECAP_PHY_TX1024QAMLT242TONERU_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_TX1024QAMLT242TONERU_SET_TO_IC(ni_hecap_phyinfo, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Tx 1024- QAM < 242-tone RU Support=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = HECAP_PHY_RX1024QAMLT242TONERU_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_RX1024QAMLT242TONERU_SET_TO_IC(ni_hecap_phyinfo, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Rx 1024- QAM < 242-tone RU Support=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = HECAP_PHY_RXFULLBWSUHEMUPPDU_COMPSIGB_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_RXFULLBWSUHEMUPPDU_COMPSIGB_SET_TO_IC(ni_hecap_phyinfo, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Rx Full BW SU Using HE MU PPDU With Compressed SIGB=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }

    val = HECAP_PHY_RXFULLBWSUHEMUPPDU_NONCOMPSIGB_GET_FROM_IE(&hecap_phy_ie);
    HECAP_PHY_RXFULLBWSUHEMUPPDU_NONCOMPSIGB_SET_TO_IC(ni_hecap_phyinfo, val);

    if(enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s Rx Full BW SU Using HE MU PPDU With Non-Compressed SIGB=%x"
        "hecap->hecap_phyinfo[9]=%x \n",
        __func__, val, hecap->hecap_phyinfo[HECAP_PHYBYTE_IDX9]);
    }
#endif

    ieee80211_update_ht_vht_he_phymode(ic, ni);

    /* Parse NSS MCS info */
    status = ieee80211_hecap_parse_mcs_nss(ni, vap,
                                           hecap->hecap_txrx,
                                           enable_log,
                                           &mcsnssbytes);

    if (status != QDF_STATUS_SUCCESS)
        return;

    ni_ppet = ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0;

    if(ppet_present) {
        /* parse ie ppet and store in ni_ppet field */
        he_ppet16_ppet8_parse(ni_ppet, ((uint8_t *)hecap +
                    (HE_CAP_OFFSET_TO_PPET + mcsnssbytes)));

        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s NI HE PPET ru3_ru0[0] =%x  ru3_ru0[1]=%x _ru3_ru0[2]=%x \
             ru3_ru0[3]=%x ru3_ru0[4]=%x  ru3_ru0[5]=%x ru3_ru0[6]=%x ru3_ru0[7]=%x \n",
             __func__, ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[0],
             ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[1], ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[2],
             ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[3], ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[4],
             ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[5], ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[6],
             ni_he->hecap_ppet.ppet16_ppet8_ru3_ru0[7]);
        }
    }

}

void
ieee80211_parse_he_6g_bandcap(struct ieee80211_node *ni,
                                u_int8_t *ie, u_int8_t subtype)
{
    struct ieee80211vap *vap            = ni->ni_vap;
    struct ieee80211_ie_he_6g_bandcap *hecap_6g =
                                (struct ieee80211_ie_he_6g_bandcap *)ie;
    struct ieee80211_he_handle *ni_he   = &ni->ni_he;
    uint8_t *he_6g_bandcap_ie           = &hecap_6g->he_6g_bandcap[HECAP_6GBYTE_IDX0];
    uint16_t *ni_he6g_bandcap           = (uint16_t *)&ni_he->he6g_bandcap[HECAP_6GBYTE_IDX0];
    uint8_t val;

    val = HECAP_6G_MINMPDU_START_SPACING_GET_FROM_IE(&he_6g_bandcap_ie);
    HECAP_6G_MINMPDU_START_SPACING_SET_TO_IC(*ni_he6g_bandcap, val);
    ni->ni_mpdudensity = ieee80211_parse_mpdudensity(val);

    val = HECAP_6G_MAXAMPDU_LEN_EXP_GET_FROM_IE(&he_6g_bandcap_ie);
    HECAP_6G_MAXAMPDU_LEN_EXP_SET_TO_IC(*ni_he6g_bandcap, val);
    if(val < IEEE80211_MAX_AMPDU_LEN_EXP_MAX) {
        ni->ni_maxampdu = (1u << (IEEE80211_HE_6GCAP_MAX_AMPDU_LEN_FACTOR + val)) -1;
    } else {
        ni->ni_maxampdu = (1u << (IEEE80211_HE_6GCAP_MAX_AMPDU_LEN_FACTOR + val + ni->ni_maxampdu)) -1;
    }

    val = HECAP_6G_MAXMPDU_LEN_GET_FROM_IE(&he_6g_bandcap_ie);
    HECAP_6G_MAXMPDU_LEN_SET_TO_IC(*ni_he6g_bandcap, val);

    /* Check if the SMPS capability advertised by peer has updated */
    val = HECAP_6G_SMPS_GET_FROM_IE(&he_6g_bandcap_ie);
    if((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
            (val != ((*ni_he->he6g_bandcap &
                     IEEE80211_HE_6GBANDCAP_SMPOWERSAVE_MASK) >>
                     IEEE80211_HE_6GBANDCAP_SMPOWERSAVE_S))) {
        ieee80211_update_smps_cap(ni, val);
    }
    HECAP_6G_SMPS_SET_TO_IC(*ni_he6g_bandcap, val);

    val = HECAP_6G_RD_RESP_GET_FROM_IE(&he_6g_bandcap_ie);
    HECAP_6G_RD_RESP_SET_TO_IC(*ni_he6g_bandcap, val);

    val = HECAP_6G_RXANTENNA_PATTERN_CONS_GET_FROM_IE(&he_6g_bandcap_ie);
    HECAP_6G_RXANTENNA_PATTERN_CONS_SET_TO_IC(*ni_he6g_bandcap, val);

    val = HECAP_6G_TXANTENNA_PATTERN_CONS_GET_FROM_IE(&he_6g_bandcap_ie);
    HECAP_6G_TXANTENNA_PATTERN_CONS_SET_TO_IC(*ni_he6g_bandcap, val);

    IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE_6GHZ,
    "%s: NI 6GHz Bandcap: 0x%x\n", __func__,
    ni_he6g_bandcap[HECAP_6GBYTE_IDX0]);

}

static void
ieee80211_add_he_vhtop(u_int8_t *frm, struct ieee80211_node *ni,
                    struct ieee80211com *ic,  u_int8_t subtype,
                    struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211vap *vap = ni->ni_vap;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t chwidth = 0, negotiate_bw = 0;
    u_int8_t *frm_chwidth = frm, *frm_cfreq_seg1 = frm+1, *frm_cfreq_seg2 = frm+2;


    if((ni->ni_160bw_requested == 1) &&
       (IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan)) &&
        (ni->ni_chwidth == IEEE80211_VHTOP_CHWIDTH_80) &&
        (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) {
        /* Set negotiated BW */
        chwidth = ni->ni_chwidth;
        negotiate_bw = 1;
    } else {
       if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
           chwidth = vap->iv_chwidth;
       } else {
           chwidth = ic_cw_width;
       }
    }

    /* Fill in the VHT Operation info */
    if (chwidth == IEEE80211_CWM_WIDTH160) {
        if (vap->iv_rev_sig_160w) {
            if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                *frm_chwidth = IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80;
            else
               *frm_chwidth = IEEE80211_VHTOP_CHWIDTH_REVSIG_160;
        } else {
            if(IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                *frm_chwidth = IEEE80211_VHTOP_CHWIDTH_80_80;
            else
                *frm_chwidth = IEEE80211_VHTOP_CHWIDTH_160;
        }
    }
    else if (chwidth == IEEE80211_CWM_WIDTH80)
        *frm_chwidth = IEEE80211_VHTOP_CHWIDTH_80;
    else
        *frm_chwidth = IEEE80211_VHTOP_CHWIDTH_2040;

    if (negotiate_bw == 1) {

            *frm_cfreq_seg1 = vap->iv_bsschan->ic_vhtop_ch_num_seg1;
            /* Note: This is applicable only for 80+80Mhz mode */
            *frm_cfreq_seg2 = 0;
    }
    else {
        if (chwidth == IEEE80211_CWM_WIDTH160) {

            if (vap->iv_rev_sig_160w) {
                /* Our internal channel structure is in sync with
                 * revised 160 MHz signalling. So use seg1 and
                 * seg2 directly for 80_80 and 160.
                 */
                 *frm_cfreq_seg1=
                    vap->iv_bsschan->ic_vhtop_ch_num_seg1;

                *frm_cfreq_seg2 =
                    vap->iv_bsschan->ic_vhtop_ch_num_seg2;
            } else {
                /* Use legacy 160 MHz signaling */
                if(IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan)) {
                    /* ic->ic_curchan->ic_vhtop_ch_num_seg2 is centre
                     * frequency for whole 160 MHz.
                     */
                    *frm_cfreq_seg1 =
                        vap->iv_bsschan->ic_vhtop_ch_num_seg2;
                    *frm_cfreq_seg2 = 0;
                } else {
                    /* 80 + 80 MHz */
                    *frm_cfreq_seg1 =
                        vap->iv_bsschan->ic_vhtop_ch_num_seg1;

                    *frm_cfreq_seg2 =
                        vap->iv_bsschan->ic_vhtop_ch_num_seg2;
                }
            }
       } else { /* 80MHZ or less */
            *frm_cfreq_seg1 = vap->iv_bsschan->ic_vhtop_ch_num_seg1;
            *frm_cfreq_seg2 = 0;
        }
    }


    /* We currently honor a 160 MHz association WAR request from callers only for
     * IEEE80211_FC0_SUBTYPE_PROBE_RESP and IEEE80211_FC0_SUBTYPE_ASSOC_RESP, and
     * check if our current channel is for 160/80+80 MHz.
     */
    if ((!vap->iv_rev_sig_160w) && (extractx != NULL) &&
        (extractx->fectx_assocwar160_reqd == true) &&
        ((subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) ||
            (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)) &&
        (IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) ||
            IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))) {
       /* Remove all indications of 160 MHz capability, to enable the STA to
        * associate.
        *
        * Besides, we set vht_op_chwidth to IEEE80211_VHTOP_CHWIDTH_80 without
        * checking if preceeding code had set it to lower value negotiated with
        * STA. This is for logical conformance with older VHT AP behaviour
        * wherein width advertised would remain constant across probe response
        * and assocation response.
        */

        /* Downgrade to 80 MHz */
        *frm_chwidth = IEEE80211_VHTOP_CHWIDTH_80;

        *frm_cfreq_seg1 = vap->iv_bsschan->ic_vhtop_ch_num_seg1;
        *frm_cfreq_seg2 = 0;
    }

}

/**
* @brief    Sets the HE-Op Basic HE-MCS and NSS-Set.
*           This function sets the HE-MCS 'mcs' for the
*           requested number of spatial streams 'nss' in the
*           Basic HE-MCS and NSS Set in the HE-Op element.
*
* @param vap: handle to vap
* @param nss: number of ss for which HE-MCS 0-11 needs to be set
*
* @return 32 bit value containing the desired bit-pattern
*/
static uint16_t
ieee80211_set_heop_basic_mcs_nss_set(uint8_t mcs, uint8_t nss)
{
    u_int16_t heop_mcs_nss = 0x0;
    u_int8_t  i;

    if ((mcs < HE_MCS_VALUE_INVALID) && (nss < MAX_HE_NSS)) {
        for (i = 0; i < nss; i++) {
            /* Set the desired 2-bit value and left
             * shift by 2-bits if we are left with
             * another ss to set this value
             */
            heop_mcs_nss |= (mcs << (i*HE_NBITS_PER_SS_IN_HE_MCS_NSS_SET));
        }

        /* Clear nss*2 bits in the bit sequence
         * RESRVD_BITS_FOR_ALL_SS_IN_HE_MCS_NSS_SET
         * so that we can or resultant bit sequence
         * with heop_mcs_nss (set above)
         */
        heop_mcs_nss |= (HE_RESRVD_BITS_FOR_ALL_SS_IN_HE_MCS_NSS_SET &
                           (~((1 << i*HE_NBITS_PER_SS_IN_HE_MCS_NSS_SET) - 1)));
    } else {
        qdf_err("%s WARNING!!! SS more than %d not supported", __func__, MAX_HE_NSS);
    }

    return qdf_le16_to_cpu(heop_mcs_nss);
}

/**
* @brief    Get the default-max PE duration.
*           This function gets the default max PPE duration from
*           target sent hecap_ppet values
*
* @param tot_nss            total number of SS
* @param ru_mask            ru mask as sent by the target
* @param ppet16_ppet8       pointer to target sent ppet values
*
* @return 8 bit value containing the default-max PPE duration
*/
static u_int8_t
he_get_default_max_pe_duration(u_int8_t tot_nss,
                         u_int32_t ru_mask, u_int32_t *ppet16_ppet8) {

    u_int8_t ppet8_val, ppet16_val;
    u_int8_t tot_ru                  = HE_PPET_TOT_RU_BITS;
    u_int8_t default_max_pe_duration = IEEE80211_HE_PE_DURATION_NONE;
    u_int8_t nss, ru, ci;
    u_int32_t temp_ru_mask;

    /* Need to break out of both the loops as soon as the max
     * value is hit. Therefore, both the loop carries the check
     * against the max values
     */
    for(nss=0; nss < tot_nss &&
            default_max_pe_duration < IEEE80211_HE_PE_DURATION_MAX;
                nss++) {    /* loop NSS */
        temp_ru_mask = ru_mask;

        /* Break out of the loop as soon as max values is hit */
        for(ru=1; ru <= tot_ru &&
            default_max_pe_duration < IEEE80211_HE_PE_DURATION_MAX;
                ru++) {   /* loop RU */

            if(temp_ru_mask & 0x1) {

                /* extract ppet16 & ppet8 from IC he ppet handle */
                ppet16_val = HE_GET_PPET16(ppet16_ppet8, ru, nss);
                ppet8_val  = HE_GET_PPET8(ppet16_ppet8, ru, nss);

                /* Break out of the loop as soon as max values is hit */
                for (ci = 0; ci < HE_PPET_MAX_CI &&
                    default_max_pe_duration < IEEE80211_HE_PE_DURATION_MAX; ci++) {

                   /* Refer to Table 27-8: PPE thresholds per PPET8 and PPET16
                    * for the pe-duration derviation scheme used below
                    */
                    if ((ci >= ppet8_val) &&
                            ((ci < ppet16_val) || (ppet16_val == HE_PPET_NONE))) {
                        default_max_pe_duration = IEEE80211_HE_PE_DURATION_8US;
                    }

                    if (((ci > ppet8_val) ||
                        (ppet8_val == HE_PPET_NONE)) && (ci >= ppet16_val)) {
                        default_max_pe_duration = IEEE80211_HE_PE_DURATION_MAX;
                    }
                }

            }
            temp_ru_mask = temp_ru_mask >> 1;
        }
    }

    return default_max_pe_duration;
}

#if SUPPORT_11AX_D3
uint8_t ieee80211_get_he_bsscolor_info(struct ieee80211vap *vap) {
    uint8_t hebsscolor_info = 0;
    struct ieee80211com *ic = vap->iv_ic;
    int val;

    val = (ic->ic_he.heop_bsscolor_info & IEEE80211_HEOP_BSS_COLOR_MASK) >> IEEE80211_HEOP_BSS_COLOR_S;
    HEOP_BSSCOLORINFO_BSS_COLOR_SET(&hebsscolor_info, val);
    val = (ic->ic_he.heop_bsscolor_info & IEEE80211_HEOP_PARTIAL_BSS_COLOR_MASK) >> IEEE80211_HEOP_PARTIAL_BSS_COLOR_S;
    HEOP_BSSCOLORINFO_PART_BSS_COLOR_SET(&hebsscolor_info, val);
    val = (ic->ic_he.heop_bsscolor_info & IEEE80211_HEOP_BSS_COLOR_DISABLD_MASK) >> IEEE80211_HEOP_BSS_COLOR_DISABLD_S;
    HEOP_BSSCOLORINFO_BSS_COLOR_DIS_SET(&hebsscolor_info, val);

    /* Fill the bss color value from the IC as
     * it is the generic bss color for all VAPs -
     * ieee80211AX: Section 27.11.4 - "All APs
     * that are members of a multiple
     * BSSID set shall use the same BSS color".
     * The bss color set from the userspace
     * in the vap structure is taken care while
     * setting up the bss color in IC through
     * ieee80211_setup_bsscolor().
     */
    if (!vap->iv_he_bsscolor_change_ongoing) {
        HEOP_BSSCOLORINFO_BSS_COLOR_SET(&hebsscolor_info, ic->ic_bsscolor_hdl.selected_bsscolor);

        if (ieee80211_is_bcca_ongoing_for_any_vap(ic)) {
            HEOP_BSSCOLORINFO_BSS_COLOR_DIS_SET(&hebsscolor_info, IEEE80211_HE_BSS_COLOR_ENABLE);
        } else {
           /* The disabled bss color bit in the ic_heop_param is set and
            * assigned the value '1' when the user disables BSS color. This
            * assignment happens in the set bss color handler and the assigned
            * value is populated in the heop param here. */
	    val = (ic->ic_he.heop_bsscolor_info & IEEE80211_HEOP_BSS_COLOR_DISABLD_MASK) >> IEEE80211_HEOP_BSS_COLOR_DISABLD_S;
            HEOP_BSSCOLORINFO_BSS_COLOR_DIS_SET(&hebsscolor_info, val);
        }
    } else {
        /* Keep advertising disabled bss color till bsscolor change
         * switch count is 0
         */
        HEOP_BSSCOLORINFO_BSS_COLOR_SET(&hebsscolor_info, ic->ic_bsscolor_hdl.prev_bsscolor);
        HEOP_BSSCOLORINFO_BSS_COLOR_DIS_SET(&hebsscolor_info, !IEEE80211_HE_BSS_COLOR_ENABLE);
    }

   IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE,
    "%s he_bsscolor_info:> bss_color=%x, part_bss_color=%x, bss_color_dis=%x",
    __func__, HEOP_BSSCOLORINFO_BSS_COLOR_GET(hebsscolor_info), HEOP_BSSCOLORINFO_PART_BSS_COLOR_GET(hebsscolor_info),
    HEOP_BSSCOLORINFO_BSS_COLOR_DIS_GET(hebsscolor_info));

    return hebsscolor_info;
}
qdf_export_symbol(ieee80211_get_he_bsscolor_info);
#endif

void
ieee80211_add_6g_op_info(uint8_t *opinfo_6g, struct ieee80211_node *ni,
                                                struct ieee80211com *ic)
{
    struct heop_6g_param *heop_6g           = (struct heop_6g_param *)opinfo_6g;
    struct ieee80211vap *vap                = ni->ni_vap;
    enum ieee80211_cwm_width ic_cw_width    = ic->ic_cwm_get_width(ic);
    uint8_t chwidth;
    enum reg_6g_ap_type reg_cur_6g_ap_pwr_type;

    qdf_mem_zero(heop_6g, sizeof(struct heop_6g_param));
    heop_6g->primary_channel        = ic->ic_curchan->ic_ieee;

    if(vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic_cw_width;
    }

    switch(chwidth) {
        case IEEE80211_CWM_WIDTH20:
            heop_6g->channel_width = IEEE80211_6GOP_CHWIDTH_20;
            break;
        case IEEE80211_CWM_WIDTH40:
            heop_6g->channel_width = IEEE80211_6GOP_CHWIDTH_40;
            break;
        case IEEE80211_CWM_WIDTH80:
            heop_6g->channel_width = IEEE80211_6GOP_CHWIDTH_80;
            break;
        case IEEE80211_CWM_WIDTH160:
        case IEEE80211_CWM_WIDTH80_80:
            heop_6g->channel_width = IEEE80211_6GOP_CHWIDTH_160_80_80;
            break;
    }

    heop_6g->duplicate_beacon       = (ic->ic_non_ht_dup & IEEE80211_NON_HT_DUP_BEACON_M);
    heop_6g->chan_cent_freq_seg0    = ic->ic_curchan->ic_vhtop_ch_num_seg1;
    heop_6g->chan_cent_freq_seg1    = ic->ic_curchan->ic_vhtop_ch_num_seg2;

    if(vap->iv_6g_he_op_min_rate) {
        heop_6g->minimum_rate   = vap->iv_6g_he_op_min_rate;
    } else {
        heop_6g->minimum_rate   = IEEE80211_6G_HE_OP_DEFAULT_MIN_RATE;
    }

    /* Regulatory Info field interpretation:
     * 0 - Low Power Indoor AP
     * 1 - Standard AP
     */
    ucfg_reg_get_cur_6g_ap_pwr_type(ic->ic_pdev_obj, &reg_cur_6g_ap_pwr_type);
    heop_6g->regulatory_info = reg_cur_6g_ap_pwr_type;

}

#if SUPPORT_11AX_D3
uint32_t ieee80211_get_heop_param(struct ieee80211vap *vap) {
#else
struct he_op_param ieee80211_get_heop_param(struct ieee80211vap *vap) {
#endif
    struct ieee80211com *ic = vap->iv_ic;
    uint8_t rx_streams      = ieee80211_get_rxstreams(ic, vap);
    uint8_t tx_streams      = ieee80211_get_txstreams(ic, vap);
    uint8_t nss             = MIN(rx_streams, tx_streams);
#if SUPPORT_11AX_D3
    uint32_t heop_param = 0;
    uint32_t val;
#else
    struct he_op_param heop_param = {0};
#endif

#if SUPPORT_11AX_D3
    val = (ic->ic_he.heop_param & IEEE80211_HEOP_6GHZ_INFO_PRESENT_MASK) >> IEEE80211_HEOP_6GHZ_INFO_PRESENT_S;
    HEOP_PARAM_OP_6G_INFO_PRESENT_SET(&heop_param, val);

    val = vap->iv_he_er_su_disable;
    HEOP_PARAM_ER_SU_DISABLE_SET(&heop_param, val);

    val = vap->iv_he_rts_threshold;
    HEOP_PARAM_RTS_THRESHOLD_SET(&heop_param, val);

    val = he_get_default_max_pe_duration(nss, ic->ic_he.hecap_ppet.ru_mask, ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0);
    HEOP_PARAM_DEF_PE_DUR_SET(&heop_param, val);
#else
    heop_param.bss_color           = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_BSS_COLOR_MASK) >>
                                        IEEE80211_HEOP_BSS_COLOR_S;
   /* Fill in the default HE OP info from IC */
    heop_param.def_pe_dur          = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_DEFAULT_PE_DUR_MASK) >>
                                        IEEE80211_HEOP_DEFAULT_PE_DUR_S;
    heop_param.rts_threshold       = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_RTS_THRESHOLD_MASK) >>
                                        IEEE80211_HEOP_RTS_THRESHOLD_S;
    heop_param.part_bss_color      = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_PARTIAL_BSS_COLOR_MASK) >>
                                        IEEE80211_HEOP_PARTIAL_BSS_COLOR_S;
    heop_param.multiple_bssid_ap   = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_MULT_BSSID_AP_MASK) >>
                                        IEEE80211_HEOP_MULT_BSSID_AP_S;
    heop_param.tx_mbssid           = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_TX_MBSSID_MASK) >>
                                        IEEE80211_HEOP_TX_MBSSID_S;
    heop_param.reserved_1          = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_RESERVED1_MASK) >>
                                        IEEE80211_HEOP_RESERVED1_S;
    heop_param.bss_color_dis       = (ic->ic_he.heop_param &
                                     IEEE80211_HEOP_BSS_COLOR_DISABLD_MASK) >>
                                        IEEE80211_HEOP_BSS_COLOR_DISABLD_S;

   /* Fill the bss color value from the IC as
    * it is the generic bss color for all VAPs -
    * ieee80211AX: Section 27.11.4 - "All APs
    * that are members of a multiple
    * BSSID set shall use the same BSS color".
    * The bss color set from the userspace
    * in the vap structure is taken care while
    * setting up the bss color in IC through
    * ieee80211_setup_bsscolor().
    */
    if (!vap->iv_he_bsscolor_change_ongoing) {
        heop_param.bss_color = ic->ic_bsscolor_hdl.selected_bsscolor;

        if (ieee80211_is_bcca_ongoing_for_any_vap(ic)) {
            heop_param.bss_color_dis = IEEE80211_HE_BSS_COLOR_ENABLE;
        } else {
            /* The disabled bss color bit in the ic_heop_param is set and assigned
            * the value '1' when the user disables BSS color. This assignment happens
            * in the set bss color handler and the assigned value is populated in the
            * heop param here. */
            heop_param.bss_color_dis = (ic->ic_he.heop_param &
                                    IEEE80211_HEOP_BSS_COLOR_DISABLD_MASK) >>
                                    IEEE80211_HEOP_BSS_COLOR_DISABLD_S;
        }
    } else {
        /* Keep advertising disabled bss color till bsscolor change
         * switch count is 0
         */
        heop_param.bss_color = ic->ic_bsscolor_hdl.prev_bsscolor;
        heop_param.bss_color_dis = !IEEE80211_HE_BSS_COLOR_ENABLE;
    }
   /* Find the default max PPE duration from
    * target sent hecap_ppet values and fill
    * in as the default PE duration
    */
    heop_param.def_pe_dur = he_get_default_max_pe_duration(nss,
                                ic->ic_he.hecap_ppet.ru_mask,
                                    ic->ic_he.hecap_ppet.ppet16_ppet8_ru3_ru0);

    heop_param.rts_threshold = vap->iv_he_rts_threshold;
#endif

#if !SUPPORT_11AX_D3
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE,
    "%s heop_params:> bss_color=%x, default_pe_durn=%x, "
    "twt_required=%x, rts_thrshld=%x, part_bss_color=%x, "
    "vht_op_info_present=%x, reserved=%x, multiple_bssid_ap=%x, "
    "tx_mbssid=%x, bss_color_dis=%x, reserved_1=%x\n"
    , __func__, heop_param.bss_color, heop_param.def_pe_dur,
    heop_param.twt_required, heop_param.rts_threshold,
    heop_param.part_bss_color, heop_param.vht_op_info_present,
    heop_param.reserved, heop_param.multiple_bssid_ap,
    heop_param.tx_mbssid, heop_param.bss_color_dis,
    heop_param.reserved_1);
#else
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_HE,
    "%s heop_params:> default_pe_durn=%x, "
    "twt_required=%x, rts_thrshld=%x, "
    "vht_op_info_present=%x, er_su_disable=%x, co_located_bss=%x, "
    "reserved=%x\n"
    , __func__, HEOP_PARAM_DEF_PE_DUR_GET(heop_param),
    HEOP_PARAM_TWT_REQUIRED_GET(heop_param), HEOP_PARAM_RTS_THRESHOLD_GET(heop_param),
    HEOP_PARAM_VHT_OP_INFO_GET(heop_param),
    HEOP_PARAM_ER_SU_DISABLE_GET(heop_param), HEOP_PARAM_CO_LOCATED_BSS_GET(heop_param),
    HEOP_PARAM_RESERVED_GET(heop_param));
#endif

    return heop_param;
}
qdf_export_symbol(ieee80211_get_heop_param);

uint8_t *
ieee80211_add_heop(u_int8_t *frm, struct ieee80211_node *ni,
                  struct ieee80211com *ic, u_int8_t subtype,
                  struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211_ie_heop *heop = (struct ieee80211_ie_heop *)frm;
    struct ieee80211vap      *vap  = ni->ni_vap;
    bool enable_log      = false;
    int heoplen          = sizeof(struct ieee80211_ie_heop);
#if SUPPORT_11AX_D3
    uint8_t heop_bsscolor_info;
    uint32_t heop_param;
#else
    struct he_op_param heop_param;    
#endif
    uint16_t heop_mcs_nss;
    uint8_t *he_op = NULL;

    if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
         subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {

         enable_log = true;
    }

    heop->elem_id     = IEEE80211_ELEMID_EXTN;
    /* elem id + len = 2 bytes, readjust based on ppet */
    heop->elem_len    = sizeof(struct ieee80211_ie_heop) -
                                                IEEE80211_IE_HDR_LEN;
    heop->elem_id_ext = IEEE80211_ELEMID_EXT_HEOP;

    heop_param = ieee80211_get_heop_param(vap);
    OL_IF_MSG_COPY_CHAR_ARRAY(heop->heop_param, &heop_param, sizeof(heop->heop_param));

#if SUPPORT_11AX_D3
    heop_bsscolor_info = ieee80211_get_he_bsscolor_info(vap);
    qdf_mem_copy(&heop->heop_bsscolor_info, &heop_bsscolor_info,
            sizeof(heop->heop_bsscolor_info));

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s IC HE OP=%x Frame HE OP Params =%x%x%x%x\n"
        , __func__, ic->ic_he.heop_param, heop->heop_param[0],
        heop->heop_param[1], heop->heop_param[2], heop->heop_bsscolor_info);
    }
#else
    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s IC HE OP=%x Frame HE OP Params =%x%x%x%x\n"
        , __func__, ic->ic_he.heop_param, heop->heop_param[0],
        heop->heop_param[1], heop->heop_param[2], heop->heop_param[3]);
    }
#endif

    heop_mcs_nss = ieee80211_set_heop_basic_mcs_nss_set
                    (HE_MCS_VALUE_FOR_MCS_0_7, HE_DEFAULT_SS_IN_MCS_NSS_SET);

    qdf_mem_copy(heop->heop_mcs_nss, &heop_mcs_nss,
                                 sizeof(heop->heop_mcs_nss));

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
        "%s IC HE MCS NSS =%x HE OP MCS NSS =%x Frame HEOP= %x%x\n"
        , __func__, ic->ic_he.hecap_rxmcsnssmap, heop_mcs_nss,
                heop->heop_mcs_nss[0],heop->heop_mcs_nss[1]);
    }

    he_op = (uint8_t *)heop->heop_vht_opinfo;
#if SUPPORT_11AX_D3
    if(HEOP_PARAM_VHT_OP_INFO_GET(heop_param)) {
#else
    if(heop_param.vht_op_info_present) {
#endif
        /* Fill in VHT Operation - Width, Cfreq1, Cfreq2 */
        ieee80211_add_he_vhtop(heop->heop_vht_opinfo,
                                ni, ic, subtype, extractx);
        he_op += HEOP_VHT_OPINFO;
        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s Frame HE OP VHT Info Width =%x Cfre1=%x Cfreq2=%x\n"
            , __func__, heop->heop_vht_opinfo[0],
            heop->heop_vht_opinfo[1], heop->heop_vht_opinfo[2]);
        }
    } else {
        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s HE OP VHT Info not present\n", __func__);
        }
        heoplen        -= HEOP_VHT_OPINFO;
        heop->elem_len -= HEOP_VHT_OPINFO;
    }
#if SUPPORT_11AX_D3
    if(!HEOP_PARAM_CO_LOCATED_BSS_GET(heop_param)) {
#else
    if(!heop_param.multiple_bssid_ap) {
#endif
        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s HE OP Max BSSID indicator not present\n", __func__);
        }
        heoplen        -= HEOP_MAX_BSSID_INDICATOR;
        heop->elem_len -= HEOP_MAX_BSSID_INDICATOR;
    }

#if SUPPORT_11AX_D3
    if(HEOP_PARAM_OP_6G_INFO_PRESENT_GET(heop_param)) {
        ieee80211_add_6g_op_info(he_op, ni, ic);

        if(enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE_6GHZ,
            "%s: HE 6GHz Operation Information: heop_6g_info[0]: 0x%x "
            "heop_6g_info[1]: 0x%x heop_6g_info[2]: 0x%x "
            "heop_6g_info[3]: 0x%x heop_6g_info[4]: 0x%x\n",
            __func__, heop->heop_6g_info[0], heop->heop_6g_info[1],
            heop->heop_6g_info[2], heop->heop_6g_info[3],
            heop->heop_6g_info[4]);
        }

    } else {
        heoplen         -= HEOP_6G_INFO_SIZE;
        heop->elem_len  -= HEOP_6G_INFO_SIZE;
    }
#endif /* SUPPORT_11AX_D3 */

    return frm + heoplen;
}

static void
ieee80211_parse_he_vhtop(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    int ch_width;
    enum ieee80211_cwm_width ic_cw_width = ic->ic_cwm_get_width(ic);
    u_int8_t *vhtop_chwidth = ie, *vhtop_cfreq_seg1 = ie+1,  *vhtop_cfreq_seg2 = ie+2;

    switch (*vhtop_chwidth) {
       case IEEE80211_VHTOP_CHWIDTH_2040:
           /* Exact channel width is already taken care of by the HT parse */
       break;
       case IEEE80211_VHTOP_CHWIDTH_80:
       if(((*vhtop_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
          (*vhtop_cfreq_seg1 != 0) && (abs(*vhtop_cfreq_seg2 -
           *vhtop_cfreq_seg1) == 8)) ||
           ((*vhtop_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
           (*vhtop_cfreq_seg1 != 0) && (abs(*vhtop_cfreq_seg2 -
           *vhtop_cfreq_seg1) > 8))) {

           ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
       }
       else {
           ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
       }
       break;
       case IEEE80211_VHTOP_CHWIDTH_160:
       case IEEE80211_VHTOP_CHWIDTH_80_80:
           ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
       break;
       default:
           IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_DEBUG,
                            "%s: Unsupported Channel Width\n", __func__);
       break;
    }

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        ch_width = vap->iv_chwidth;
    } else {
        ch_width = ic_cw_width;
    }
    /* Update ch_width only if it is within the user configured width*/
    if(ch_width < ni->ni_chwidth) {
        ni->ni_chwidth = ch_width;
    }
}

static void
ieee80211_parse_he_6g_opinfo(struct ieee80211_node *ni, u_int8_t *he_6g_opinfo, uint8_t *update_beacon)
{
    struct heop_6g_param *heop_6g = (struct heop_6g_param *)he_6g_opinfo;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    uint8_t ni_ch_width = heop_6g->channel_width;
    uint8_t chwidth;
    uint32_t ni_hephycap = ni->ni_he.hecap_phyinfo[HECAP_PHYBYTE_IDX0];

    if(vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic->ic_cwm_get_width(ic);
    }

    switch(chwidth) {
        case IEEE80211_CWM_WIDTH20:
            ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            break;
        case IEEE80211_CWM_WIDTH40:
            if(ni_ch_width == IEEE80211_6GOP_CHWIDTH_20) {
                ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            } else {
                ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
            }
            break;
        case IEEE80211_CWM_WIDTH80:
            if(ni_ch_width == IEEE80211_6GOP_CHWIDTH_20) {
                ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            } else if(ni_ch_width == IEEE80211_6GOP_CHWIDTH_40) {
                ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
            } else {
                ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
            }
            break;
        case IEEE80211_CWM_WIDTH160:
        case IEEE80211_CWM_WIDTH80_80:
            if(ni_ch_width == IEEE80211_6GOP_CHWIDTH_20) {
                ni->ni_chwidth = IEEE80211_CWM_WIDTH20;
            } else if(ni_ch_width == IEEE80211_6GOP_CHWIDTH_40) {
                ni->ni_chwidth = IEEE80211_CWM_WIDTH40;
            } else if(ni_ch_width == IEEE80211_6GOP_CHWIDTH_80){
                ni->ni_chwidth = IEEE80211_CWM_WIDTH80;
            } else {
                if((ni_hephycap & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE160) &&
                      ni->ni_he.he_basic_txrxmcsnss_req_met_160) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH160;
                } else if((ni_hephycap & IEEE80211_HECAP_PHY_CHWIDTH_11AXA_HE80_80) &&
                           ni->ni_he.he_basic_txrxmcsnss_req_met_80_80 &&
                           ni->ni_he.he_basic_txrxmcsnss_req_met_160) {
                    ni->ni_chwidth = IEEE80211_CWM_WIDTH80_80;
                } else {
                    qdf_err("%s: Incorrect channel width setting", __func__);
                }
            }
            break;
    }
    ni->ni_minimumrate = heop_6g->minimum_rate;

    if (ni->ni_ap_power_type != heop_6g->regulatory_info) {
        ni->ni_ap_power_type = heop_6g->regulatory_info;
        /* inform regulatory to change the power table. To be revisited */
        if (update_beacon)
            *update_beacon = 1;
        ucfg_reg_set_cur_6g_ap_pwr_type(ic->ic_pdev_obj, heop_6g->regulatory_info);
    }

}

struct heop_6g_param * ieee80211_get_he_6g_opinfo(struct ieee80211_ie_heop *heop)
{
#define VHTOP_INFO_OFFSET                   3
#define CO_HOSTED_BSSID_INDICATOR_OFFSET    1
    uint8_t *he_6g_opinfo = NULL;
    uint8_t *ie = (uint8_t *)heop;
    uint8_t offset = sizeof(struct ieee80211_ie_heop) -
                     (sizeof(heop->heop_vht_opinfo) +
                     sizeof(heop->heop_max_bssid_indicator) +
                     sizeof(heop->heop_6g_info));
    uint32_t heop_param = 0;

    if (heop == NULL) {
        return NULL;
    }

    qdf_mem_copy(&heop_param, heop->heop_param, sizeof(heop->heop_param));

    he_6g_opinfo = (ie + offset);
    if (heop_param & IEEE80211_HEOP_VHTOP_PRESENT_MASK) {
        he_6g_opinfo += VHTOP_INFO_OFFSET;
    }

#if SUPPORT_11AX_D3
    if(heop_param & IEEE80211_HEOP_CO_LOCATED_BSS_MASK) {
        he_6g_opinfo += CO_HOSTED_BSSID_INDICATOR_OFFSET;
    }

    if (heop_param & IEEE80211_HEOP_6GHZ_INFO_PRESENT_MASK) {
        /* Negotiated HE 6GHz Operation Information */
        return (struct heop_6g_param *)he_6g_opinfo;
    }
#endif /* SUPPORT_11AX_D3*/
    return NULL;
}

void
ieee80211_update_basic_bss_mcs_nss_req(struct ieee80211_node *ni, u_int8_t *ie)
{
    struct ieee80211_ie_heop *heop    = (struct ieee80211_ie_heop *)ie;
    struct ieee80211vap *vap          = ni->ni_vap;
    uint16_t basic_mcsnssmap;

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        (void ) qdf_get_u16(heop->heop_mcs_nss, &basic_mcsnssmap);
        /* Derive basic mcs and nss requirement for the bss */
        HE_DERIVE_PEER_NSS_FROM_MCSMAP(basic_mcsnssmap,
                                    vap->iv_he_basic_nss_for_bss);
        /* Derive basic mcs requirement from first stream only.
         * Limiting it to first stream as of now as most AP vendors
         * advertises one stream mcsmap as the basic requirement.
         * In future, we may have to extend this if we encounter
         * HEOP with more than 1ss basic requirement.
         */
        vap->iv_he_basic_mcs_for_bss = basic_mcsnssmap & 0x03;
    }

}

void
ieee80211_parse_heop(struct ieee80211_node *ni, u_int8_t *ie, u_int8_t subtype, uint8_t *update_beacon)
{
#define VHTOP_INFO_OFFSET                   3
#define CO_HOSTED_BSSID_INDICATOR_OFFSET    1
    struct ieee80211_ie_heop *heop    = (struct ieee80211_ie_heop *)ie;
    struct ieee80211_he_handle *ni_he = &ni->ni_he;
    struct ieee80211vap *vap          = ni->ni_vap;
    uint16_t basic_mcsnssmap;
    uint8_t offset                    = sizeof(struct ieee80211_ie_heop) -
                                        (sizeof(heop->heop_vht_opinfo) +
                                         sizeof(heop->heop_max_bssid_indicator) +
                                         sizeof(heop->heop_6g_info));
    u_int8_t *he_6g_opinfo;
    bool enable_log = false;

    he_6g_opinfo = (ie + offset);

    if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
         subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
         enable_log = true;
    }

    /* Negotiated HE OP Params  */
    qdf_mem_copy(&ni_he->heop_param, heop->heop_param,
                                    sizeof(heop->heop_param));

#if SUPPORT_11AX_D3
    qdf_mem_copy(&ni_he->heop_bsscolor_info, &heop->heop_bsscolor_info,
                                    sizeof(heop->heop_bsscolor_info));
#endif

    if (enable_log) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
       "%s NI OP Params =%x \n", __func__, ni_he->heop_param);
    }

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        (void ) qdf_get_u16(heop->heop_mcs_nss, &basic_mcsnssmap);
        /* Derive basic mcs and nss requirement for the bss */
        HE_DERIVE_PEER_NSS_FROM_MCSMAP(basic_mcsnssmap,
                                    vap->iv_he_basic_nss_for_bss);
        /* Derive basic mcs requirement from first stream only.
         * Limiting it to first stream as of now as most AP vendors
         * advertises one stream mcsmap as the basic requirement.
         * In future, we may have to extend this if we encounter
         * HEOP with more than 1ss basic requirement.
         */
        vap->iv_he_basic_mcs_for_bss = basic_mcsnssmap & 0x03;
    }

    if (ni_he->heop_param & IEEE80211_HEOP_VHTOP_PRESENT_MASK) {
        /* Negotiated HE VHT OP */
        ieee80211_parse_he_vhtop(ni, heop->heop_vht_opinfo);
        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
           "%s NI OP Params =%x %x %x\n", __func__, heop->heop_vht_opinfo[0],
            heop->heop_vht_opinfo[1], heop->heop_vht_opinfo[2]);
        }
        he_6g_opinfo += VHTOP_INFO_OFFSET;
    } else {
        if (enable_log) {
            IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
           "%s HEOP VHT Info not present in IE\n", __func__);
        }
    }

#if SUPPORT_11AX_D3
    if(ni_he->heop_param & IEEE80211_HEOP_CO_LOCATED_BSS_MASK) {
        he_6g_opinfo += CO_HOSTED_BSSID_INDICATOR_OFFSET;
    }

    if (ni_he->heop_param & IEEE80211_HEOP_6GHZ_INFO_PRESENT_MASK) {
        /* Negotiated HE 6GHz Operation Information */
        ieee80211_parse_he_6g_opinfo(ni, he_6g_opinfo, update_beacon);
    }
#endif /* SUPPORT_11AX_D3*/
}

/* extnss_160_validate_and_seg2_indicate() - Validate vhtcap if EXT NSS supported
 * @arg2 - vhtcap
 * @arg3 - vhtop
 * @arg4 - htinfo
 *
 * Function to validate vht capability combination of "supported chwidth" and "ext nss support"
 * along with indicating appropriate location to retrieve seg2 from(either htinfo or vhtop).
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - 1 : If seg2 is to be extracted from vhtop
 *          2 : If seg2 is to be extracted from htinfo
 *          0 : Failure
 */
u_int8_t extnss_160_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo)
{

    if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE)) {
        return 0;
    }

    if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
        (vhtop->vht_op_ch_freq_seg2 != 0) &&
        (abs(vhtop->vht_op_ch_freq_seg2 - vhtop->vht_op_ch_freq_seg1) == 8)) {
            return 1;
        }
    } else if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
       if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
        (HTINFO_CCFS2_GET(htinfo) != 0) &&
        (abs(HTINFO_CCFS2_GET(htinfo) - vhtop->vht_op_ch_freq_seg1) == 8)) {
           return 2;
        }
    } else {
        return 0;
    }
      return 0;
}

/* extnss_80p80_validate_and_seg2_indicate() - Validate vhtcap if EXT NSS supported
 * @arg2 - vhtcap
 * @arg3 - vhtop
 * @arg4 - htinfo
 *
 * Function to validate vht capability combination of "supported chwidth" and "ext nss support"
 * along with along with indicating appropriate location to retrieve seg2 from(either htinfo or vhtop)
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - 1 : If seg2 is to be extracted from vhtop
 *          2 : If seg2 is to be extracted from htinfo
 *          0 : Failure
 */
u_int8_t extnss_80p80_validate_and_seg2_indicate(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo)
{

    if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
        (vhtop->vht_op_ch_freq_seg2 != 0) &&
        (abs(vhtop->vht_op_ch_freq_seg2 - vhtop->vht_op_ch_freq_seg1) > 16)) {
            return 1;
        }
    } else if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
        if ((vhtop->vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
        (HTINFO_CCFS2_GET(htinfo) != 0) &&
        (abs(HTINFO_CCFS2_GET(htinfo) - vhtop->vht_op_ch_freq_seg1) > 16)) {
            return 2;
        }
    } else {
        return 0;
    }
    return 0;
}

/*  retrieve_seg2_for_extnss_80p80() - Retrieve seg2 based on vhtcap
 * @arg1 - struct ieee80211vap
 * @arg2 - vhtcap
 * @arg3 - vhtop
 * @arg4 - htinfo
 *
 * Function to retrieve seg2 from either vhtop or htinfo based on the
 * vhtcap advertised by the AP.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - seg2 if present in vhtop or htinfo.
 */
u_int8_t  retrieve_seg2_for_extnss_80p80(u_int32_t *vhtcap, struct ieee80211_ie_vhtop *vhtop, struct ieee80211_ie_htinfo_cmn *htinfo)
{
    u_int8_t val;

    val = extnss_80p80_validate_and_seg2_indicate(vhtcap, vhtop, htinfo);
    if (val == 1) {
       return vhtop->vht_op_ch_freq_seg2;
    } else if (val == 2) {
       return  HTINFO_CCFS2_GET(htinfo);
    } else {
       return 0;
    }
}

/* validate_extnss_vhtcap() - Validate for valid combinations in vhtcap
 * @arg2 - vhtcap
 *
 * Function to validate vht capability combination of "supported chwidth"
 * and "ext nss support" advertised by STA.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - true : BW 160 supported
 *          false : Failure
 */
bool validate_extnss_vhtcap(u_int32_t *vhtcap)
{
        if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) ==  IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE ) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
                   return true;
        }
    return false;
}
/* ext_nss_160_supported() - Validate 160MHz support for EXT NSS supported STA
 * @arg2 - vhtcap
 *
 * Function to validate vht capability combination of "supported chwidth"
 * and "ext nss support" advertised by STA for 160MHz.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - true : BW 160 supported
 *          false : Failure
 */
bool ext_nss_160_supported(u_int32_t *vhtcap)
{
        if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) ==  IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE ) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
                   return true;
        }
    return false;
}

/* ext_nss_80p80_supported() - Validate 160MHz support for EXT NSS supported STA
 * @arg2 - vhtcap
 *
 * Function to validate vht capability combination of "supported chwidth"
 * and "ext nss support" advertised by STA fo 80+80 MHz.
 * This is a helper function. It assumed that non-NULL pointers are passed.
 *
 * Return - true : BW 80+80 supported
 *          false : Failure
 */
bool ext_nss_80p80_supported(u_int32_t *vhtcap)
{
        if (((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5 ) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
                ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
               ((*vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
                   return true;
        }
    return false;
}

/* peer_ext_nss_capable() - Validate peer EXT NSS capability
 * @arg1 - vhtcap
 *
 * Function to validate if peer is capable of EXT NSS Signaling
 *
 * Return - true : Peer is capable of EXT NSS
 *        - false : Peer not capable of EXT NSS
 */
bool peer_ext_nss_capable(struct ieee80211_ie_vhtcap * vhtcap)
{
    struct supp_tx_mcs_extnss tx_mcs_extnss_cap;
    OS_MEMCPY(&tx_mcs_extnss_cap, &vhtcap->tx_mcs_extnss_cap, sizeof(u_int16_t));
    *(u_int16_t *)&tx_mcs_extnss_cap = le16toh(*(u_int16_t*)&tx_mcs_extnss_cap);
    if (tx_mcs_extnss_cap.ext_nss_capable) {
        return true;
    }
    return false;
}

/* Parse TCLAS Mask element -
 * The AP processes this IE and deciphers the classifier type,
 * if it is IP or higher layer, ethernet or tcp/udp parameters.
 * Based on the classifier type, it looks at the classifier mask
 * which gives information about the mirror classifier parameters
 * that the AP needs to check whenever it gets an MSDU from the
 * corresponding STA.
 * If the MSCS request type is CHANGE, the AP will check these
 * mirror classifier parameters masked by the classifier mask and
 * replace the existing mask with this one.
 * Maximum number of TCLAS Mask that the AP can parse at a time, is
 * defined by the MAX_TCLAS_ELEM_SIZE.
 * @param mscs_tuple - MSCS tuple, that AP maintains for every node
 * @param tclas_mask - TCLAS Mask element
 * @param request_type - MSCS request type
 */

int ieee80211_parse_tclas_mask_elem(struct ieee80211_mscs_data *mscs_tuple,
    struct ieee80211_tclas_mask_elem *tclas_mask,u_int8_t request_type)
{
    bool valid_entry = 0;
    u_int8_t i = 0;
    u_int16_t retval = 0;
    u_int8_t ctr = mscs_tuple->tuple_ctr;
    u_int8_t elemid,ie_len;

    elemid = tclas_mask->elem_ext;
    ie_len = tclas_mask->ie_len;

    if (ctr >= IEEE80211_MSCS_MAX_TCLAS_ELEM_SIZE) {
        qdf_err("Cannot add more entries, Maximum limit reached");
        retval = IEEE80211_MSCS_INSUFFICIENT_TCLAS_PROCESSING_RESOURCES;
        return retval;
    }

    /*  Populating the entries inside the node data structure */
    for(i = 0;i < ctr;i++){
        /*Checking if the entry is present*/
        if(tclas_mask->tclas_mask_elem_type4.classifier_type ==
            mscs_tuple->node_service[i].classifier_type){
            mscs_tuple->node_service[i].classifier_mask =
              tclas_mask->tclas_mask_elem_type4.classifier_mask;
            valid_entry = 1;
            break;
        }
      }
    if (valid_entry == 0){
        /* Entry did not exist, add the new classifier type and mask */
        mscs_tuple->node_service[ctr].classifier_type =
          tclas_mask->tclas_mask_elem_type4.classifier_type;
        mscs_tuple->node_service[ctr].classifier_mask =
          tclas_mask->tclas_mask_elem_type4.classifier_mask;
        mscs_tuple->tuple_ctr++;
    }
    return 0;
}

#if WLAN_SUPPORT_MSCS
u_int8_t* ieee80211_add_mscs_ie(struct ieee80211_mscs_data *mscs_control_data,
    u_int8_t *frm)
{
    if (mscs_control_data->mscs_assoc.retval == IEEE80211_MSCS_SUCCESS) {
        *frm++ = IEEE80211_ELEMID_EXTN;
        *frm++ = 12;   /*Adding a static value of MSCS_IE_Len*/
        *frm++ = IEEE80211_ELEMID_EXT_MSCS_IE;
        *frm++ = IEEE80211_MSCS_ADD_RULE;
        qdf_mem_zero(frm, sizeof(mscs_control_data->node_stats));
        frm += sizeof(mscs_control_data->node_stats) - 2;
        *frm++ = 1;    /* The Sub_IE_Len is standard 2 bytes */
        *frm++ = sizeof(mscs_control_data->mscs_assoc.retval);
        memcpy(frm, &mscs_control_data->mscs_assoc.retval,
            sizeof(mscs_control_data->mscs_assoc.retval));
        frm += sizeof(mscs_control_data->mscs_assoc.retval);
    }
    /* As of now the AP sends successful status code
     * The code for rejecting the request and sending the response
     *is yet to be added
    */
    return frm;
}

/* Parse MSCS Descriptor element -
 * The AP processes this IE and deciphers the user priority control,
 * stream timeout and the TCLAS mask element for its associated STA.
 * If the request type is ADD, then the AP checks if the MSCS
 * session is already active for the STA, if yes, then it will reject
 * the request.
 * Presence of TCLAS Mask element is mandatory if the request is ADD
 * or CHANGE.
 * If the request type is REMOVE, the AP will terminate the MSCS
 * session.
 * @param ni - Node Data structure.
 * @param mscs_ie - MSCS Descriptor element
 */

int ieee80211_parse_mscs_ie(struct ieee80211_node *ni,
    struct ieee80211_mscs_descriptor *mscs_ie)
{
    u_int8_t request_type,tclas_ie_len;
    u_int16_t retval;
    u_int8_t ctr = 0;
    int8_t ie_len = mscs_ie->ie_len;
    request_type = mscs_ie->req_type;

    if (request_type == IEEE80211_MSCS_ADD_RULE) {
        /*Check if the entry is existing there or not*/
        if (ni->ni_mscs->mscs_active) {
          /*Entry exists, the AP should reject this MSCS request */
            retval = IEEE80211_MSCS_REQUEST_DECLINED;
            qdf_err("AP is declining this request: MSCS session is active");
            return retval;
        }
    }

    if (request_type == IEEE80211_MSCS_CHANGE_RULE ||
        request_type == IEEE80211_MSCS_REMOVE_RULE) {
        /* Check if the entry is existing there or not */
        if (!ni->ni_mscs->mscs_active) {
            /*Entry does not exist, AP should reject this request */
            retval = IEEE80211_MSCS_REQUEST_DECLINED;
            qdf_err("AP is declining this request: MSCS session inactive");
            return retval;
      }
    }

    if (request_type == IEEE80211_MSCS_ADD_RULE ||
        request_type == IEEE80211_MSCS_CHANGE_RULE) {
        /* Check if TCLAS Mask element is present or not */
        if (mscs_ie->tclas_mask_elem[ctr].elem_ext !=
            IEEE80211_ELEMID_EXT_TCLAS_MASK) {
            /* TCLAS Mask element is not present */
            retval = IEEE80211_MSCS_REQUEST_DECLINED;
            qdf_err("AP is declining this request: TCLAS Mask element absent");
            return retval;
        }
        /*Entry is not present, new entry to be created*/
        ni->ni_mscs->mscs_active = true;
        ni->ni_mscs->node_stats.user_priority_bitmap =
          mscs_ie->user_pri_ctrl.user_priority_bitmap;
        ni->ni_mscs->node_stats.user_priority_limit =
          mscs_ie->user_pri_ctrl.user_priority_limit;
        ni->ni_mscs->node_stats.stream_timeout = mscs_ie->stream_timeout;

        /* Move by the offset of 10, to parse the TCLAS Mask element */
        ie_len -= 10;

        while (ie_len > 0) {
            if (mscs_ie->tclas_mask_elem[ctr].elem_ext ==
                IEEE80211_ELEMID_EXT_TCLAS_MASK) {
                tclas_ie_len = mscs_ie->tclas_mask_elem[ctr].ie_len;
                /* This function has to run for every
                 * TCLAS Mask element present -
                 * So we are passing the tclas_mask_elem_data itself*/

                retval = ieee80211_parse_tclas_mask_elem(ni->ni_mscs,
                    &mscs_ie->tclas_mask_elem[ctr],request_type);
                if (retval ==
                    IEEE80211_MSCS_INSUFFICIENT_TCLAS_PROCESSING_RESOURCES) {
                    return retval;
                }
                ie_len -= (tclas_ie_len + 2);
                ctr++;
          } else {
                qdf_err("The given element is not a TCLAS Mask element");
                break;
          }
        }
    }

    if(request_type == IEEE80211_MSCS_REMOVE_RULE){
        retval = IEEE80211_MSCS_TCLAS_PROCESSING_TERMINATED;
        return retval;
    }

    return 0;
}
#endif

#if DBDC_REPEATER_SUPPORT

#define IE_CONTENT_SIZE 1

/*
 * Add Extender information element to a frame
 */
u_int8_t *
ieee80211_add_extender_ie(struct ieee80211vap *vap, ieee80211_frame_type ftype, u_int8_t *frm)
{
    u_int8_t *ie_len;
    u_int8_t i;
    struct ieee80211com *ic = vap->iv_ic;
    struct global_ic_list *ic_list = ic->ic_global_list;
    struct ieee80211com *tmp_ic = NULL;
    struct ieee80211vap *tmpvap = NULL;
    u_int8_t extender_info = ic_list->extender_info;
    u_int8_t apvaps_cnt = 0, stavaps_cnt = 0;
    u_int8_t *pos1, *pos2;
    static const u_int8_t oui[4] = {
        (QCA_OUI & 0xff), ((QCA_OUI >> 8) & 0xff), ((QCA_OUI >> 16) & 0xff),
        QCA_OUI_EXTENDER_TYPE
    };

    *frm++ = IEEE80211_ELEMID_VENDOR;
    ie_len = frm;
    *frm++ = sizeof(oui) + IE_CONTENT_SIZE;
    OS_MEMCPY(frm, oui, sizeof(oui));
    frm += sizeof(oui);
    *frm++ = extender_info;

    if (ftype == IEEE80211_FRAME_TYPE_ASSOCRESP) {
        pos1 = frm++;
        pos2 = frm++;
        *ie_len += 2;
        for (i = 0; i < MAX_RADIO_CNT; i++) {
            GLOBAL_IC_LOCK_BH(ic_list);
            tmp_ic = ic_list->global_ic[i];
            GLOBAL_IC_UNLOCK_BH(ic_list);
            if(tmp_ic) {
                TAILQ_FOREACH(tmpvap, &tmp_ic->ic_vaps, iv_next) {
                    if (tmpvap->iv_opmode == IEEE80211_M_HOSTAP) {
                        OS_MEMCPY(frm, tmpvap->iv_myaddr, QDF_MAC_ADDR_SIZE);
                        frm += QDF_MAC_ADDR_SIZE;
                        apvaps_cnt++;
                    }
                }
            }
        }
        for (i = 0; i < MAX_RADIO_CNT; i++) {
            GLOBAL_IC_LOCK_BH(ic_list);
            tmp_ic = ic_list->global_ic[i];
            GLOBAL_IC_UNLOCK_BH(ic_list);
            if(tmp_ic) {
                if (tmp_ic->ic_sta_vap) {
                    /*Copy only MPSTA mac address, not PSTA mac address*/
                    tmpvap = tmp_ic->ic_sta_vap;
                    OS_MEMCPY(frm, tmpvap->iv_myaddr, QDF_MAC_ADDR_SIZE);
                    frm += QDF_MAC_ADDR_SIZE;
                    stavaps_cnt++;
                }
            }
        }
        *pos1 = apvaps_cnt;
        *pos2 = stavaps_cnt;
        *ie_len += ((apvaps_cnt + stavaps_cnt) * QDF_MAC_ADDR_SIZE);
    }

    return frm;
}

void
ieee80211_process_extender_ie(struct ieee80211_node *ni, const u_int8_t *ie, ieee80211_frame_type ftype)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = vap->iv_ic;
    struct global_ic_list *ic_list = ic->ic_global_list;
    u_int8_t ie_len, i;
    u_int8_t *mac_list;
    u_int8_t extender_ie_content, extender_ie_type;
    u_int8_t apvaps_cnt = 0,stavaps_cnt = 0;

    ie++; /*to get ie len*/
    ie_len = *ie;
    ie += 4; /*to get extender ie content*/
    extender_ie_type = *ie++;
    extender_ie_content = *ie++;
    ie_len -= 5;
    if (ftype == IEEE80211_FRAME_TYPE_ASSOCREQ) {
        ni->is_extender_client = 1;
        GLOBAL_IC_LOCK_BH(ic_list);
        ic_list->num_rptr_clients++;
        GLOBAL_IC_UNLOCK_BH(ic_list);
    } else if (ftype == IEEE80211_FRAME_TYPE_ASSOCRESP) {
        ic->ic_extender_connection = 1;
        if (ic_list->num_stavaps_up == 0) {
            apvaps_cnt = *ie++;
            stavaps_cnt = *ie++;
            mac_list = (u_int8_t *)ic_list->preferred_list_stavap;
            for (i=0; ((i < apvaps_cnt)&&(i < MAX_RADIO_CNT)&&(ie_len > 0)); i++) {
                GLOBAL_IC_LOCK_BH(ic_list);
                IEEE80211_ADDR_COPY((mac_list+(i*QDF_MAC_ADDR_SIZE)), ie);
                GLOBAL_IC_UNLOCK_BH(ic_list);
                qdf_info("Preferred mac[%d]:%s",i,ether_sprintf(mac_list+(i*QDF_MAC_ADDR_SIZE)));
                ie += QDF_MAC_ADDR_SIZE;
                ie_len -= QDF_MAC_ADDR_SIZE;
            }
            mac_list = (u_int8_t *)ic_list->denied_list_apvap;
            for (i=0; ((i < stavaps_cnt)&&(i < MAX_RADIO_CNT)&&(ie_len > 0)); i++) {
                GLOBAL_IC_LOCK_BH(ic_list);
                IEEE80211_ADDR_COPY((mac_list+(i*QDF_MAC_ADDR_SIZE)), ie);
                GLOBAL_IC_UNLOCK_BH(ic_list);
                qdf_info("Denied mac[%d]:%s",i,ether_sprintf(mac_list+(i*QDF_MAC_ADDR_SIZE)));
                ie += QDF_MAC_ADDR_SIZE;
                ie_len -= QDF_MAC_ADDR_SIZE;
            }

            GLOBAL_IC_LOCK_BH(ic_list);
            ic_list->ap_preferrence = 2;
            GLOBAL_IC_UNLOCK_BH(ic_list);
        }
        if ((extender_ie_content & ROOTAP_ACCESS_MASK) == ROOTAP_ACCESS_MASK) {
            /*If connecting RE has RootAP access*/
            ic->ic_extender_connection = 2;
        }
    }

    return;
}

#endif

uint8_t *ieee80211_mgmt_add_chan_switch_ie(uint8_t *frm, struct ieee80211_node *ni,
                uint8_t subtype, uint8_t chanchange_tbtt)
{

        struct ieee80211vap *vap = ni->ni_vap;
        struct ieee80211_ath_channelswitch_ie *csaie = (struct ieee80211_ath_channelswitch_ie*)frm;
        struct ieee80211com *ic = ni->ni_ic;
        struct ieee80211_extendedchannelswitch_ie *ecsa_ie = NULL;
        struct ieee80211_max_chan_switch_time_ie *mcst_ie = NULL;
        uint8_t csa_ecsa_mcst_len = IEEE80211_CHANSWITCHANN_BYTES;
        uint8_t csmode = IEEE80211_CSA_MODE_STA_TX_ALLOWED;
        uint16_t chan_width;
        uint16_t behav_lim = 0;
        bool global_look_up = false;
        /* the length of csa, ecsa and max chan switch time(mcst) ies
         * is represented by csa_ecsa_mcst_len, but it is initialised
         * with csa length and based on the presence of ecsa and mcst
         * the length is increased.
         */

        if (vap->iv_csmode == IEEE80211_CSA_MODE_AUTO) {

            /* No user preference for csmode. Use default behavior.
             * If chan swith is triggered because of radar found
             * ask associated stations to stop transmission by
             * sending csmode as 1 else let them transmit as usual
             * by sending csmode as 0.
             */
            if (ic->ic_flags & IEEE80211_F_DFS_CHANSWITCH_PENDING) {
                /* Request STA's to stop transmission */
                csmode = IEEE80211_CSA_MODE_STA_TX_RESTRICTED;
            }
        } else {
            /* User preference for csmode is configured.
             * Use user preference
             */
            csmode = vap->iv_csmode;
        }

        /* CSA Action frame format:
         * [1] Category code - Spectrum management (0).
         * [1] Action code - Channel Switch Announcement (4).
         * [TLV] Channel Switch Announcement IE.
         * [TLV] Secondary Channel Offset IE.
         * [TLV] Wide Bandwidth IE.
         */

        /* Check if ecsa IE has to be added.
         * If yes, adjust csa_ecsa_mcst_len to include CSA IE len
         * and ECSA IE len.
         */
        if (vap->iv_enable_ecsaie) {
            ecsa_ie = (struct ieee80211_extendedchannelswitch_ie *)(frm + csa_ecsa_mcst_len);
            csa_ecsa_mcst_len += IEEE80211_EXTCHANSWITCHANN_BYTES;
        }

        /* Check if max chan switch time IE(mcst IE) has to be added.
         * If yes, adjust csa_ecsa_mcst_len to include CSA IE len,
         * ECSA IE len and mcst IE len.
         */
        if (vap->iv_enable_max_ch_sw_time_ie) {
            mcst_ie = (struct ieee80211_max_chan_switch_time_ie *)(frm + csa_ecsa_mcst_len);
            csa_ecsa_mcst_len += IEEE80211_MAXCHANSWITCHTIME_BYTES;
        }

        csaie->ie = IEEE80211_ELEMID_CHANSWITCHANN;
        csaie->len = 3; /* fixed len */
        csaie->switchmode = csmode;
        csaie->newchannel = wlan_reg_freq_to_chan(ic->ic_pdev_obj, ic->ic_chanchange_chan_freq);
        csaie->tbttcount = chanchange_tbtt;

        if (ecsa_ie) {
            ecsa_ie->ie = IEEE80211_ELEMID_EXTCHANSWITCHANN;
            ecsa_ie->len = 4; /* fixed len */
            ecsa_ie->switchmode = csmode;

            /* If user configured opClass is set, use it else
             * calculate new opClass from destination channel.
             */
            if (vap->iv_ecsa_opclass) {
                ecsa_ie->newClass = vap->iv_ecsa_opclass;
                ecsa_ie->newchannel =
                    wlan_reg_freq_to_chan(ic->ic_pdev_obj,
                                          ic->ic_chanchange_chan_freq);
            } else {
                /* Channel look-up tables should not change with CSA */
                global_look_up = false;
                wlan_get_bw_and_behav_limit(ic->ic_chanchange_channel,
                                            &chan_width, &behav_lim);

               /* Get new OpClass and Channel number from regulatory */
               wlan_reg_freq_width_to_chan_op_class_auto(ic->ic_pdev_obj,
                                                         ic->ic_chanchange_chan_freq,
                                                         chan_width,
                                                         global_look_up, behav_lim,
                                                         &ecsa_ie->newClass,
                                                         &ecsa_ie->newchannel);
            }

            ecsa_ie->tbttcount = chanchange_tbtt;
        }

        if (mcst_ie) {
            ieee80211_add_max_chan_switch_time(vap, (uint8_t *)mcst_ie);
        }

        frm += csa_ecsa_mcst_len;

        if (((IEEE80211_IS_CHAN_11N(vap->iv_bsschan) ||
                        IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
                        IEEE80211_IS_CHAN_11AX(vap->iv_bsschan)) &&
                    (ic->ic_chanchange_secoffset)) && ic->ic_sec_offsetie) {

            /* Add secondary channel offset element */
            struct ieee80211_ie_sec_chan_offset *sec_chan_offset_ie = NULL;

            sec_chan_offset_ie = (struct ieee80211_ie_sec_chan_offset *)frm;
            sec_chan_offset_ie->elem_id = IEEE80211_ELEMID_SECCHANOFFSET;

            /* Element has only one octet of info */
            sec_chan_offset_ie->len = 1;
            sec_chan_offset_ie->sec_chan_offset = ic->ic_chanchange_secoffset;
            frm += IEEE80211_SEC_CHAN_OFFSET_BYTES;
        }

        if ((IEEE80211_IS_CHAN_11AC(vap->iv_bsschan) ||
                IEEE80211_IS_CHAN_11AXA(vap->iv_bsschan)) &&
                ieee80211vap_vhtallowed(vap)
                && (ic->ic_chanchange_channel != NULL)) {
            /* Adding channel switch wrapper element */
            frm = ieee80211_add_chan_switch_wrp(frm, ni, ic, subtype,
                    /* When switching to new country by sending ECSA IE,
                     * new country IE should be also be added.
                     * As of now we dont support switching to new country
                     * without bringing down vaps so new country IE is not
                     * required.
                     */
                    (/*ecsa_ie ? IEEE80211_VHT_EXTCH_SWITCH :*/
                     !IEEE80211_VHT_EXTCH_SWITCH));
    }
    return frm;
}

/*
 * ieee80211_check_ie_of_type: Check whether the passed IE is of the given type
 *
 * @vap       : VAP Handle
 * @iebuf     : the IE whose type is to be checked
 * @element_id: Element ID of the expected IE
 * @sub_id    : Second level ID for Extension IEs
 *              For Vendor IEs:
 *                  0 for all Vendor IEs
 *                  1 for WPA
 *
 * Return: true if IE matches the ID, else false
 */
bool ieee80211_check_ie_of_type(struct ieee80211vap *vap, uint8_t *iebuf, uint8_t element_id, uint8_t sub_id)
{
    bool ret = false;
    struct wlan_crypto_params tmp_crypto_params;
    qdf_mem_zero(&tmp_crypto_params, sizeof(tmp_crypto_params));

    if (!iebuf || iebuf[0] != element_id)
        return ret;

    switch (element_id) {
        case IEEE80211_ELEMID_RSN:
            if (vap->iv_rsn_override ) {
                ret = true;
                break;
            }
            if (wlan_crypto_rsnie_check(
                        (struct wlan_crypto_params *)&tmp_crypto_params,
                        iebuf) == 0) {
                struct wlan_crypto_params *vdev_crypto_params;
                ret = true;
                vdev_crypto_params = wlan_crypto_vdev_get_crypto_params(vap->vdev_obj);
                if (!vdev_crypto_params)
                    qdf_mem_copy(vdev_crypto_params, &tmp_crypto_params, sizeof(struct wlan_crypto_params));
            }
            break;
        case IEEE80211_ELEMID_VENDOR:
            if (sub_id == IEEE80211_ELEMID_VENDOR_SON_REPT) {
                if (isqca_son_rept_oui(iebuf, QCA_OUI_WHC_REPT_INFO_SUBTYPE))
                    ret = true;
            }
            else if (sub_id == IEEE80211_ELEMID_VENDOR_SON_AP) {
                if (is_qca_son_oui(iebuf, QCA_OUI_WHC_AP_INFO_SUBTYPE))
                    ret = true;
            }
            else if (sub_id == IEEE80211_ELEMID_VENDOR_WPA && (iswpaoui(iebuf) && wlan_crypto_wpaie_check(
                     (struct wlan_crypto_params *)&tmp_crypto_params, iebuf) == 0)) {
                struct wlan_crypto_params *vdev_crypto_params;
                ret = true;
                vdev_crypto_params = wlan_crypto_vdev_get_crypto_params(vap->vdev_obj);
                if (!vdev_crypto_params)
                    qdf_mem_copy(vdev_crypto_params, &tmp_crypto_params, sizeof(struct wlan_crypto_params));
            }
            else if (sub_id == IEEE80211_ELEMID_VENDOR_ALL) {
                // since SON IEs are added separately in frame, to avoid duplication
                if ((isqca_son_rept_oui(iebuf, QCA_OUI_WHC_REPT_INFO_SUBTYPE)) ||
                    (is_qca_son_oui(iebuf, QCA_OUI_WHC_AP_INFO_SUBTYPE))) {
                    ret = false;
                }
                else {
                    ret = true;
                }
            }
            break;
        case IEEE80211_ELEMID_EXTN:
            if (iebuf[2] == sub_id)
                ret = true;
            break;
        default:
            ret = true; /* Rest of the IEs */
    }
    return ret;
}

/*
 * ieee80211_get_security_vendor_ies - copy security or vendor IEs based on a flag
 * @vap : vap pointer
 * @buf : buffer to populate the information if needed
 * @ftype : Frame type
 * @is_copy: if set, copy the app IE data into @buf
 * @is_security : if 0, copy the vendor IEs to @buf if @is_copy is set
 *                if 1, copy the RSN IE to @buf if @is_copy is set
 *
 * Return: length of IEs present or copied (if @is_copy is set)
 */
uint32_t ieee80211_get_security_vendor_ies(struct ieee80211vap *vap, uint8_t *buf,
                                           ieee80211_frame_type ftype, bool is_copy,
                                           bool is_security)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct app_ie_entry *ie_entry = NULL;
    uint32_t len = 0;
    enum ieee80211_phymode mode;
    uint8_t iebuf[IEEE80211_MAX_IE_LEN];
    struct ieee80211_node *ni = vap->iv_bss;
    struct ieee80211_rateset *rs = &ni->ni_rates;

    IEEE80211_VAP_LOCK(vap);
    if (!STAILQ_EMPTY(&vap->iv_app_ie_list[ftype])) {
        STAILQ_FOREACH(ie_entry, &vap->iv_app_ie_list[ftype], link_entry) {
            if (ie_entry->app_ie.ie != NULL && ie_entry->app_ie.length > 0) {
               switch (ie_entry->app_ie.ie[0]) {
               case IEEE80211_ELEMID_VENDOR:
                   if (!is_security) {
                       if (ic->ic_mbss.ema_ext_enabled) {
                           uint8_t *iebuf = ie_entry->app_ie.ie;

                           /* Skip SON vendor IEs when EMA Ext is enabled since
                            * the IEs would already be added during driver IEs
                            */
                           if (isqca_son_rept_oui(iebuf, QCA_OUI_WHC_REPT_INFO_SUBTYPE) ||
                                   is_qca_son_oui(iebuf, QCA_OUI_WHC_AP_INFO_SUBTYPE))
                               continue;
                       }
                       if (is_copy)
                           qdf_mem_copy(buf + len, ie_entry->app_ie.ie, ie_entry->app_ie.length);
                       len += ie_entry->app_ie.length;
                   }
                   break;
               case IEEE80211_ELEMID_RSNX:
               case IEEE80211_ELEMID_RSN:
                   if (is_security) {
                       if (is_copy)
                           qdf_mem_copy(buf + len, ie_entry->app_ie.ie, ie_entry->app_ie.length);
                       len += ie_entry->app_ie.length;
                   }
                   break;
               default:
                   break;
                } /* switch */
            }
        }
    }
    IEEE80211_VAP_UNLOCK(vap);

    if(is_security && (vap->iv_sae_pwe == 1)) {
        mode = wlan_get_desired_phymode(vap);
        if (vap->iv_flags_ext2 & IEEE80211_FEXT2_BR_UPDATE)
            rs = &(vap->iv_op_rates[mode]);

        OS_MEMSET(iebuf, 0, IEEE80211_MAX_IE_LEN);

        if (rs->rs_nrates >= IEEE80211_RATE_SIZE)
           (void)ieee80211_add_xrates(vap, iebuf, rs);
        else
           (void)ieee80211_add_rates(vap, iebuf, rs);

        if (iebuf[1]>0) {
             if(is_copy)
                 OS_MEMCPY(buf+len, iebuf, iebuf[1]+2);
             len += iebuf[1]+2;
         }
    }

    return len;
}
qdf_export_symbol(ieee80211_get_security_vendor_ies);

/**
 * ieee80211_add_or_retrieve_ie_from_app_opt_ies: Add all vendor IEs
 *                                                or Retrieve an IE from the IE buffer or list
 *
 * @vap       : logical representation of Virtual Access Point
 * @ftype     : Type of frame to which IEs are to be added
 * @element_id: Element ID of the IE to be added
 * @sub_id    : Second level ID for Extension IEs
 *              For Vendor IEs:
 *                  0 for all Vendor IEs
 *                  1 for WPA
 * @frm       : Address of frm pointer to add IEs in-place
 * @type      : Type of buffer from which IEs are added
 * @optie     : Opt IE Buffer passed to ieee80211_send_assocresp
 *              and ieee80211_send_proberesp
 * @retrieve  : true if specific IE is to be added,
 *              false if multiple IEs (vendor) to be added
 *
 * Return: the number of bytes (length) frm has moved
 */
uint8_t ieee80211_add_or_retrieve_ie_from_app_opt_ies(struct ieee80211vap *vap,
        ieee80211_frame_type ftype, uint8_t element_id, uint8_t sub_id,
        uint8_t **frm, uint8_t type, struct ieee80211_app_ie_t *optie, bool retrieve)
{
    uint8_t *iebuf = NULL, *iebuf_end = NULL;
    uint8_t length = 0;

    IEEE80211_VAP_LOCK(vap);
    length = __ieee80211_add_or_retrieve_ie_from_app_opt_ies(vap, ftype,
                 element_id, sub_id, frm, type, retrieve);
    IEEE80211_VAP_UNLOCK(vap);

    if (retrieve && length)
        return length;

    /* Separate optie passed to send_assocresp and send_proberesp */
    if ((type & TYPE_OPT_IE_BUF) == TYPE_OPT_IE_BUF && optie && optie->length) {
        iebuf = optie->ie;
        iebuf_end = iebuf + optie->length;
        while (iebuf + 1 < iebuf_end) {
            if (ieee80211_check_ie_of_type(vap, iebuf, element_id, sub_id)) {
                IE_MEM_COPY_MOVE_DESTN_UPD_LEN(*frm, iebuf, iebuf[1]+2, length);
                if (retrieve == true) /* Retrieve IE of the passed type */
                    if (element_id != IEEE80211_ELEMID_RIC_DATA)
                        return length;
            }
            iebuf += iebuf[1] + 2;
        }
    }

    return length;
}

/*
 * Note: Do NOT call this function directly without VAP lock. This function is
 * an internal function called by 'ieee80211_add_or_retrieve_ie_from_app_opt_ies'
 * with proper locks
 */
uint8_t __ieee80211_add_or_retrieve_ie_from_app_opt_ies(struct ieee80211vap *vap,
        ieee80211_frame_type ftype, uint8_t element_id, uint8_t sub_id,
        uint8_t **frm, uint8_t type, bool retrieve)
{
    uint8_t *iebuf = NULL, *iebuf_end = NULL;
    uint8_t length = 0;
    struct app_ie_entry *ie_entry = NULL;

    /* MLME App IE list */
    if ((type & TYPE_APP_IE_BUF) == TYPE_APP_IE_BUF && !STAILQ_EMPTY(&vap->iv_app_ie_list[ftype])) {
        STAILQ_FOREACH(ie_entry, &vap->iv_app_ie_list[ftype], link_entry) {
            if (ie_entry->app_ie.ie != NULL && ie_entry->app_ie.length > 0) {
                /* As per the specification, WPS should not be enabled,
                 * if Hidden SSID is enabled
                 */
                if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)
                        && (ftype == IEEE80211_FRAME_TYPE_BEACON)
                        && iswpsoui(ie_entry->app_ie.ie)) {
                    continue;
                } else {
                    iebuf = ie_entry->app_ie.ie;
                    if (ieee80211_check_ie_of_type(vap, iebuf, element_id, sub_id)) {
                        IE_MEM_COPY_MOVE_DESTN_UPD_LEN(*frm, iebuf, iebuf[1]+2, length);
                        if (retrieve == true) /* Retrieve IE of the passed type */
                            return length;
                    }
                }
            }
        }
    }

    /* Optional IE */
    if ((type & TYPE_OPT_IE_BUF) == TYPE_OPT_IE_BUF && vap->iv_opt_ie.length) {
        iebuf = vap->iv_opt_ie.ie;
        iebuf_end = iebuf + vap->iv_opt_ie.length;
        while (iebuf + 1 < iebuf_end) {
            if (ieee80211_check_ie_of_type(vap, iebuf, element_id, sub_id)) {
                IE_MEM_COPY_MOVE_DESTN_UPD_LEN(*frm, iebuf, iebuf[1]+2, length);
                if (retrieve == true) /* Retrieve IE of the passed type */
                    return length;
            }
            iebuf += iebuf[1] + 2;
        }
    }

    return length;
}

static uint8_t *ieee80211_rnr_cache_get_tx_vap_offset(uint8_t *buf,
                                                      uint32_t rnr_cnt,
                                                      uint8_t  *first_vap)
{
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    uint32_t count = 0;
    uint8_t *ptr = NULL;

    //skip 2 byte for elem id & size
    buf += 2;
    ap_info = (ieee80211_rnr_nbr_ap_info_t *)buf;
    tbtt_info = ap_info->tbtt_info;

    while (count < rnr_cnt) {
        if (tbtt_info->bss_params.tx_bssid == 1) {
            ptr = (uint8_t *)tbtt_info;
            if (count == 0)
                *first_vap = 1;
            break;
        }
        tbtt_info++;
        count++;
    }

    return ptr;
}

uint8_t *ieee80211_add_oob_rnr_ie(uint8_t *frm, struct ieee80211vap *vap, u_int8_t *ssid, u_int8_t ssid_len,
                                  int subtype, bool *rnr_filled)
{
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    int count = 1;
    struct wlan_objmgr_psoc *psoc;
    struct psoc_mlme_obj *mlme_psoc_priv_obj;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_6ghz_rnr_global_cache *rnr;
    u_int32_t self_short_ssid;
    u_int32_t short_ssid;
    uint8_t *org_frm;
    uint32_t tbtt_offset = 255;
    uint8_t *p_tx_vap = NULL, *buf_begin = NULL, *buf_end = NULL;
    uint32_t num_bytes_before, num_bytes_after;
    uint8_t first_vap = 0;
    uint32_t num_vaps_ie;
    bool is_tx_vap = !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
    bool is_mbssid_enable = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,WLAN_PDEV_F_MBSS_IE_ENABLE);

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(psoc);
    rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;

    org_frm = frm;

    /* Catch case of rnr_cnt !=0 as it is not memset to 0
     * by having extra check of IE element ID
     */
    if (rnr->rnr_cnt == 0 || *(uint8_t *)rnr->rnr_buf !=
        IEEE80211_ELEMID_REDUCED_NBR_RPT) {
    /* If self soc RNR cache is not present,
     * loop through all cache and find the rnr cache from
     * other Soc
     */
        wlan_fetch_inter_soc_rnr_cache(&rnr);
    }

    /* If rnr cache is not present at all in all soc, then return */
    if (!rnr || rnr->rnr_cnt == 0) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                  "rnr is null or count is zero!!");
        return org_frm;
    }

    if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) && !is_mbssid_enable) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                  "6G but not in MBSSID mode, no need to add RNR IE");
        return org_frm;
    }

    /* For 2/5Ghz VAPs add entire RNR cache,
     * for 6Ghz TX VAP add only Non Tx VAPs
     */
    if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) && is_tx_vap) {
        p_tx_vap = ieee80211_rnr_cache_get_tx_vap_offset(rnr->rnr_buf,
                                                     rnr->rnr_cnt, &first_vap);
        if (p_tx_vap) {
            buf_begin = rnr->rnr_buf;
            buf_end = rnr->rnr_buf + rnr->rnr_size + 2;
            num_bytes_before = p_tx_vap - buf_begin;
            p_tx_vap += sizeof(ieee80211_rnr_tbtt_info_set_t);
            num_bytes_after = buf_end - p_tx_vap;

            /* if only 1 VAP in RNR cache and it's the TX VAP */
            if (first_vap == 1 && num_bytes_after == 0) {
                QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                          "only 1 TX VAP in RNR cache, return...");
                return org_frm;
            }

            QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                      "rnr_buf=%p, p_tx_vap=%p",
                      rnr->rnr_buf, p_tx_vap);
            QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                      "rnr->rnr_size+2=%d, sizeof rnr tbtt info=%d, before=%d, after=%d",
                      rnr->rnr_size+2, (int)sizeof(ieee80211_rnr_tbtt_info_set_t),
                      num_bytes_before, num_bytes_after);
            /* copy buf until pointer to TX vap */
            if (num_bytes_before > 0)
                qdf_mem_copy(frm, rnr->rnr_buf, num_bytes_before);
            /* copy left buf after TX vap */
            if (num_bytes_after > 0)
                qdf_mem_copy(frm + num_bytes_before, p_tx_vap, num_bytes_after);

            /* Update IE len */
            *(org_frm+1) = num_bytes_before + num_bytes_after - 2;
            num_vaps_ie = rnr->rnr_cnt - 1;
            } else {
                qdf_mem_copy(frm, rnr->rnr_buf, rnr->rnr_size + 2);
                num_vaps_ie = rnr->rnr_cnt;
            }
    } else {
        qdf_mem_copy(frm, rnr->rnr_buf, rnr->rnr_size + 2);
        num_vaps_ie = rnr->rnr_cnt;
    }

    /* +2 is for element ID and length field (1 byte each) */
    frm+=2;

    ap_info = (ieee80211_rnr_nbr_ap_info_t *)frm;

    tbtt_info = ap_info->tbtt_info;

    ap_info->hdr_filtered_nbr_ap = 0;

    if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP &&
        !IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        /* Set tbtt offset value as unknown (255) in probe response.
         * Tbtt offset in probe response depends on Tx timestamp of prb
         * and the window it falls in between lower band tbtt and 6g tbtt.
         * Fixing the tbtt offset as unknown as it is not feasible to
         * figure out Tx time in HW at host
         */
        tbtt_offset = RNR_TBTT_OFFSET_UNKNOWN;
    } else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP &&
               IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        /* If frame is probe resp and reporting AP is 6Ghz, then
         * the reported vaps are Non Tx vaps. Tbtt offset would be
         * BI of Tx vap. This is applicable for Mbssid mode only.
         */
        tbtt_offset = vap->iv_bss->ni_intval;
    }

    self_short_ssid = htole32(ieee80211_construct_shortssid(vap->iv_bss->ni_essid,
                                vap->iv_bss->ni_esslen));
    short_ssid = htole32(ieee80211_construct_shortssid(ssid, ssid_len));

    ap_info->hdr_info_cnt = num_vaps_ie - 1;
    while (count <= num_vaps_ie) {
        if (tbtt_info->short_ssid == self_short_ssid)
            tbtt_info->bss_params.same_ssid = 1;
        if (tbtt_info->short_ssid == short_ssid)
            ap_info->hdr_filtered_nbr_ap = 1;
        /* Fill tbtt_offset of all RNR APs in frame with same value as for 6Ghz MBSSID is default */
        tbtt_info->tbtt_offset = tbtt_offset;
        tbtt_info++;
        count++;
    }

    /* RNR size has length of neighbor AP field and NOT element id + length field itself */
    frm+= *(org_frm+1);

    *rnr_filled = true;
    return frm;
}

uint8_t *ieee80211_add_selective_rnr(uint8_t *frm, struct ieee80211vap *vap, u_int8_t *ssid, u_int8_t ssid_len,
                                  int subtype, bool *rnr_filled)
{
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    int count = 1;
    struct wlan_objmgr_psoc *psoc;
    struct psoc_mlme_obj *mlme_psoc_priv_obj;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_vdev *rnr_vdev;
    struct wlan_6ghz_rnr_global_cache *rnr;
    u_int32_t self_short_ssid;
    u_int32_t short_ssid;
    uint8_t *org_frm;
    struct wlan_objmgr_pdev *cur_pdev = NULL;
    struct wlan_objmgr_vdev *cur_vdev;
    struct vdev_mlme_obj *rnr_vdev_mlme;
    struct vdev_mlme_mgmt *rnr_mlme_mgmt;
    uint32_t profile_idx = 0;
    uint8_t copied_count = 0;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(psoc);
    rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;

    org_frm = frm;

    /* Catch case of rnr_cnt !=0 as it is not memset to 0
     * by having extra check of IE element ID
     */
    if (rnr->rnr_cnt == 0 || *(uint8_t *)rnr->rnr_buf !=
        IEEE80211_ELEMID_REDUCED_NBR_RPT) {
    /* If self soc RNR cache is not present,
     * loop through all cache and find the rnr cache from
     * other Soc
     */
        wlan_fetch_inter_soc_rnr_cache(&rnr);
    }

    /* If rnr cache is not present at all in all soc, then return */
    if (!rnr || rnr->rnr_cnt == 0) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                  "rnr is null or count is zero!!");
        return org_frm;
    }

    /* Copy common part in RNR IE to frame
     * + 2 is added to copy Element ID and element length in IE
     * Advance the frm pointer by copied length
     */
    qdf_mem_copy(frm, rnr->rnr_buf, RNR_NBR_AP_INFO_SIZE + 2);
    frm+= RNR_NBR_AP_INFO_SIZE + 2;

    /* Point to first AP info in RNR cache,
     * +2 is for element ID and length field (1 byte each) */
    ap_info = (ieee80211_rnr_nbr_ap_info_t *)(rnr->rnr_buf + 2);
    tbtt_info = ap_info->tbtt_info;

    /* Copy AP info from RNR in a selective way.
     * Criteria for selection: Add those APs from RNR cache
     * that are not part of the MbssIE.
     * Store the bssid Idx of the APs added to MbssIE in a bitmap.
     * Compare the bssid Idx of AP from RNR cache and stored bitmap.
     * If there is a match, skip adding this AP info in RNR IE.
     */
    cur_vdev = vap->vdev_obj;
    cur_pdev = wlan_vdev_get_pdev(cur_vdev);
    while (count <= rnr->rnr_cnt) {
        rnr_vdev = wlan_objmgr_get_vdev_by_macaddr_from_pdev(cur_pdev,
                   tbtt_info->bssid, WLAN_MLME_NB_ID);
        rnr_vdev_mlme = wlan_vdev_mlme_get_cmpt_obj(rnr_vdev);
        if (!rnr_vdev_mlme) {
            tbtt_info++;
            count++;
            wlan_objmgr_vdev_release_ref(rnr_vdev, WLAN_MLME_NB_ID);
            continue;
	}
        rnr_mlme_mgmt = &rnr_vdev_mlme->mgmt;
        profile_idx = rnr_mlme_mgmt->mbss_11ax.profile_idx;

        /* Skip adding Tx vap to RNR IE. Among Non TX vaps
         * add only those that do not appear in Mbss IE.
         * Vaps addeed in Mbss IE are marked in bitmap based
         * on profile idx.
         */
        if ((!tbtt_info->bss_params.tx_bssid) &&
            !(wlan_rnr_get_bss_idx() & (1 << (profile_idx-1)))) {
            qdf_mem_copy(frm, tbtt_info, TBTT_INFO_FIELD_SIZE);
            frm += TBTT_INFO_FIELD_SIZE;
            copied_count++;
        }
        tbtt_info++;
        count++;
        wlan_objmgr_vdev_release_ref(rnr_vdev, WLAN_MLME_NB_ID);
    }

    if (!copied_count)
        return org_frm;
    /* Reset ap_info and tbtt_info to point to its
     * location in frm.
     */
    ap_info = (ieee80211_rnr_nbr_ap_info_t *)(org_frm+2);

    ap_info->hdr_info_cnt = copied_count - 1;
    tbtt_info = ap_info->tbtt_info;

    ap_info->hdr_filtered_nbr_ap = 0;

    self_short_ssid = htole32(ieee80211_construct_shortssid(vap->iv_bss->ni_essid,
                                vap->iv_bss->ni_esslen));
    short_ssid = htole32(ieee80211_construct_shortssid(ssid, ssid_len));

    /* Reset count to 1 */
    count = 1;
    while (count <= copied_count) {
        if (tbtt_info->short_ssid == self_short_ssid)
            tbtt_info->bss_params.same_ssid = 1;
        if (tbtt_info->short_ssid == short_ssid)
            ap_info->hdr_filtered_nbr_ap = 1;
        tbtt_info->tbtt_offset = vap->iv_bss->ni_intval;
        tbtt_info++;
        count++;
    }

    /* Reset frm to beginning of RNR IE */
    frm = org_frm;
    *(org_frm+1) = RNR_NBR_AP_INFO_SIZE + (TBTT_INFO_FIELD_SIZE * copied_count);
    frm+= *(org_frm+1) + 2;

    *rnr_filled = true;
    return frm;
}

/**
 * ieee80211_add_user_rnr_ie() - Add user rnr data to beacon and
 * probe response frame.
 *
 * First check if RNR IE is filled already for 6Ghz co-located Vaps
 * and fill user RNR data in remaining space. Else create first RNR IE.
 * If the RNR data size is less than remaining space, copy the data
 * to RNR IE.
 * If the RNR data is more than remaining space, split the RNR user
 * buffer and copy partially. Update the Tbtt information count(AP count)
 * in Tbtt information header subfield of the user data copied such that
 * it reflects APs partially copied. Mark this buffer as partially
 * copied and store remining APs to be copied.
 *
 * Create second RNR IE if user data is still present, and pick the user
 * data partially copied to fill remaining APs. Update Tbtt information
 * count(AP count) in Tbtt information header subfield. Carry on with
 * copying remaining user data.
 */
uint8_t *ieee80211_add_user_rnr_ie(uint8_t *frm, struct ieee80211vap *vap,
                                   uint8_t *rnr_offset, bool rnr_filled,
                                   int subtype)
{
    uint8_t *frm_rnr_start;
    uint8_t *rnr_ie_1 = rnr_offset;
    uint8_t curr_iebuf_len = 0;
    uint8_t *frm_rnr_end;
    uint8_t copy_ap_count = 0;
    struct ieee80211com *ic = vap->iv_ic;
    struct user_rnr_data *user_data;
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    bool is_rnrie_added = false;
    struct ol_ath_softc_net80211 *scn;
    int i;

    if (!ic) {
        qdf_err("IC is NULL");
        return frm;
    }
    scn = OL_ATH_SOFTC_NET80211(ic);

    /* Reset the uid list to remove partial copy markings */
    qdf_spin_lock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
    ieee80211_reset_user_rnr_list(ic);
    qdf_spin_unlock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);

    for (i=1; i <= scn->soc->max_rnr_ie_allowed; i++) {

        is_rnrie_added = false;
        if (i == 1 && rnr_filled) {
            /* Get the start and end of RNR IE 1 */
            frm_rnr_start = rnr_ie_1;
            curr_iebuf_len = *(frm_rnr_start + IEEE80211_IE_LEN_OFFSET);
            frm_rnr_end = frm_rnr_start + IE_LEN_ID_LEN + curr_iebuf_len;
        } else {
            frm_rnr_start = frm;
            frm_rnr_end = frm_rnr_start + IE_LEN_ID_LEN;
            curr_iebuf_len = 0;
        }

        /* Copy contents to frm_rnr_end point and modify the length in frm_start */
        TAILQ_FOREACH(user_data, &(ic->ic_user_neighbor_ap.user_rnr_data_list), user_rnr_next_uid) {

            if (user_data->is_copied) {
                /* Uid entry fully copied. Go to next Uid entry */
                if (user_data->uid_ap_remaining == 0) {
                    continue;
                } else {
                    /* UID has been partially copied. Copy remaining buffer portion.
                     * First copy only Tbtt info header and then remaining AP info.
                     */
                    qdf_mem_copy(frm_rnr_end, user_data->user_buf, RNR_NBR_AP_INFO_SIZE);
                    /* Change AP count in copied buffer to copied AP count - 1 */
                    ap_info = (ieee80211_rnr_nbr_ap_info_t *)frm_rnr_end;
                    ap_info->hdr_info_cnt = user_data->uid_ap_remaining - 1;
                    frm_rnr_end += RNR_NBR_AP_INFO_SIZE;
                    qdf_mem_copy(frm_rnr_end,
                             user_data->user_buf + RNR_NBR_AP_INFO_SIZE +
                             user_data->uid_ap_copied_cnt *
                             user_data->uid_hdr_ap_length,
                             user_data->uid_hdr_ap_length * user_data->uid_ap_remaining);
                    frm_rnr_end += user_data->uid_hdr_ap_length * user_data->uid_ap_remaining;
                    curr_iebuf_len += user_data->uid_hdr_ap_length *
                                      user_data->uid_ap_remaining +
                                      RNR_NBR_AP_INFO_SIZE;
                    is_rnrie_added = true;
                }
        } else {
                if (user_data->uid_buf_length <= (IEEE80211_MAX_IE_LEN - curr_iebuf_len)) {
                    qdf_mem_copy(frm_rnr_end, user_data->user_buf, user_data->uid_buf_length);
                    frm_rnr_end += user_data->uid_buf_length;
                    curr_iebuf_len += user_data->uid_buf_length;
                    qdf_spin_lock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
                    user_data->is_copied = true;
                    /* All APs in this Uid copied */
                    user_data->uid_ap_remaining = 0;
                    qdf_spin_unlock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
                    is_rnrie_added = true;
                } else {
                    copy_ap_count = ((IEEE80211_MAX_IE_LEN - curr_iebuf_len -
                                  RNR_NBR_AP_INFO_SIZE)/
                                 user_data->uid_hdr_ap_length);
                    if (copy_ap_count) {
                        /* Copy only partial buffer, and mark as partially copied */
                        qdf_mem_copy(frm_rnr_end, user_data->user_buf,
                                     RNR_NBR_AP_INFO_SIZE +
                                     copy_ap_count *
                                     user_data->uid_hdr_ap_length);
                        /* Change AP count to copied AP count - 1 as per standard */
                        ap_info = (ieee80211_rnr_nbr_ap_info_t *)frm_rnr_end;
                        ap_info->hdr_info_cnt = copy_ap_count - 1;
                        frm_rnr_end += RNR_NBR_AP_INFO_SIZE +
                                       copy_ap_count *
                                       user_data->uid_hdr_ap_length;
                        curr_iebuf_len += RNR_NBR_AP_INFO_SIZE +
                                          copy_ap_count *
                                          user_data->uid_hdr_ap_length;
                        qdf_spin_lock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
                        user_data->is_copied = true;
                        user_data->uid_ap_remaining = user_data->uid_org_ap_cnt - copy_ap_count;
                        user_data->uid_ap_copied_cnt = copy_ap_count;
                        qdf_spin_unlock_bh(&ic->ic_user_neighbor_ap.user_rnr_lock);
                        is_rnrie_added = true;
                    } /* if (copy_count) */
                } /* if partial copy */
            } /* if (is_copied) */
        } /* For each user uid data */

        if (is_rnrie_added) {
            /* Populate the IE hdr with tag and len */
            *frm_rnr_start = IEEE80211_ELEMID_REDUCED_NBR_RPT;
            *(frm_rnr_start + IEEE80211_IE_LEN_OFFSET) = curr_iebuf_len;
        } else {
            return frm;
        }

        frm_rnr_start = frm_rnr_start + curr_iebuf_len + IE_LEN_ID_LEN;
        if (frm_rnr_start != frm_rnr_end) {
            qdf_err("User RNR copy not successfull");
            return frm;
        }
        frm = frm_rnr_start;
    } /* for each RNR IE */

    return frm;
}

uint8_t *
ieee80211_add_6ghz_rnr_ie(struct ieee80211_node *ni,
                 struct ieee80211_beacon_offsets *bo,
                 uint8_t *frm,
                 uint8_t **temp_bo,
                 int subtype,
                 bool is_20tu_prb)
{
    bool rnr_filled          = false;
    bool is_usr_mode         = false;
    bool is_rnr_bcn_or_prb   = false;
    bool is_mbssid_enabled   = false;
    struct ieee80211com *ic  = NULL;
    struct ieee80211vap *vap = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;

    if (!ni)
        return NULL;

    if (!bo)
        return NULL;

    ic = ni->ni_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!ic || !scn)
        return NULL;

    vap = ni->ni_vap;
    if (!vap)
        return NULL;

    /* Initialize bo_rnr pointers */
    bo->bo_rnr = bo->bo_rnr2 = NULL;

    /* RNR user or driver mode? */
    is_usr_mode = WLAN_6GHZ_RNR_USR_MODE_IS_SET(ic->ic_6ghz_rnr_enable);

    /* RNR selected in beacon or probe response */
    if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
        is_rnr_bcn_or_prb = ic->ic_6ghz_rnr_enable &
                            (WLAN_RNR_IN_BCN);
    else
        is_rnr_bcn_or_prb = ic->ic_6ghz_rnr_enable &
                            (WLAN_RNR_IN_PRB);

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
            WLAN_PDEV_F_MBSS_IE_ENABLE);

    /* Adding RNR IE is only in case of usr mode (user has enabled
     * RNR advertisement and enabled this in beacon). If user mode
     * is disabled and driver mode is enabled, then AP adds RNR IE
     * as OOB is mandatory in co-located case.
     */
    if (!is_usr_mode || is_rnr_bcn_or_prb) {
        bool is_selective_rnr = (ic->ic_flags_ext2 &
                                IEEE80211_FEXT2_RNR_SELECTIVE_ADD);
        bo->bo_rnr = frm;
        *temp_bo = frm;
        if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            if ((wlan_lower_band_ap_cnt_get() == 0)
                    || scn->soc->rnr_6ghz_adv_override) {
                if (is_mbssid_enabled && is_selective_rnr) {
                    frm = ieee80211_add_selective_rnr(frm, vap,
                                vap->iv_bss->ni_essid,
                                vap->iv_bss->ni_esslen,
                                subtype, &rnr_filled);
                } else {
                    frm = ieee80211_add_oob_rnr_ie(frm,
                                vap, vap->iv_bss->ni_essid,
                                vap->iv_bss->ni_esslen,
                                subtype, &rnr_filled);
                } /* End of if (selective add enabled) */
            } /* End of if(rnr_6ghz_adv_override ||.. */
        } else {
            frm = ieee80211_add_oob_rnr_ie(frm, vap,
                     vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen,
                     subtype, &rnr_filled);
        } /* End of if (6ghz Ap) */
    }

    /* RNR selected in beacon or probe resposne */
    if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
        is_rnr_bcn_or_prb = ic->ic_user_rnr_frm_ctrl &
                        (WLAN_RNR_IN_BCN);
    else
        is_rnr_bcn_or_prb = ic->ic_user_rnr_frm_ctrl &
                        (WLAN_RNR_IN_PRB);

    /* Add user provided rnr_entries to RNR IE */
    if (!is_20tu_prb && (is_rnr_bcn_or_prb &&
        ic->ic_user_neighbor_ap.running_length != 0)) {
        bo->bo_rnr2 = frm;
        if (!*temp_bo)
            *temp_bo = frm;

        frm = ieee80211_add_user_rnr_ie(frm, vap, bo->bo_rnr,
              rnr_filled, subtype);
    }

    return frm;
}

void ieee80211_intersect_mcsnssmap(struct ieee80211vap *vap,
                                   struct ieee80211_node *ni)
{
    uint16_t temp_self_mcsnssmap;
    uint16_t temp_peer_mcsnssmap;
    struct ieee80211com *ic           = ni->ni_ic;
    struct ieee80211_he_handle *ni_he = &ni->ni_he;
    struct ieee80211_bwnss_map nssmap;
    uint16_t rxmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint16_t txmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint8_t tx_chainmask              = ieee80211com_get_tx_chainmask(ic);
    uint8_t rx_chainmask              = ieee80211com_get_rx_chainmask(ic);
    uint8_t tx_streams_160 = 0;
    uint8_t rx_streams_160 = 0;
    uint8_t rx_streams                = ieee80211_get_rxstreams(ic, vap);
    uint8_t tx_streams                = ieee80211_get_txstreams(ic, vap);
    uint8_t chwidth;

    nssmap.bw_nss_160 = 0;
    nssmap.bw_rxnss_160 = 0;

    if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
        chwidth = vap->iv_chwidth;
    } else {
        chwidth = ic->ic_cwm_get_width(ic);
    }

    if(chwidth >= IEEE80211_CWM_WIDTH160 &&
            ic->ic_get_bw_nss_mapping) {
        if(ic->ic_get_bw_nss_mapping(vap, &nssmap, tx_chainmask)) {
            /* if error then reset nssmap */
            tx_streams_160 = 0;
        } else {
            tx_streams_160 = nssmap.bw_nss_160;
        }

        if(ic->ic_get_bw_nss_mapping(vap, &nssmap, rx_chainmask)) {
            /* if error then reset nssmap */
            rx_streams_160 = 0;
        } else {
            rx_streams_160 = nssmap.bw_rxnss_160;
        }
    }

    /* AP's chip capability intersect with the User configured capabilities */
    ieee80211vap_get_insctd_mcsnssmap(vap, rxmcsnssmap, txmcsnssmap);



    /* -------------------- Handle 80+80 --------------------------- */

    /* Set the bits for unsupported SS in the self RX map to Invalid */
    (void)qdf_get_u16((uint8_t *)&rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                      &temp_self_mcsnssmap);
    if(vap->iv_cur_mode == IEEE80211_MODE_11AXA_HE80_80) {
        HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
            (uint8_t *)&temp_self_mcsnssmap, rx_streams_160);
    }

    /* Convert self_mcsnssmap to LE format before performing intersection
     * with peer_mcsnssmap */
    temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
    temp_peer_mcsnssmap = ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80_80];

    /* Intersection of self Rx mcsnssmap and peer Tx mcsnssmap support
     * will indicate Tx MCS-NSS support for the peer.
     */
    ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80_80] =
        INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

    /* Set the bits for unsupported SS in the self TX map to Invalid */
    (void)qdf_get_u16((uint8_t *)&txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                      &temp_self_mcsnssmap);
    if(vap->iv_cur_mode == IEEE80211_MODE_11AXA_HE80_80) {
        HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
            (uint8_t *)&temp_self_mcsnssmap, tx_streams_160);
    }

    /* Convert self_mcsnssmap to LE format before performing intersection
     * with peer_mcsnssmap */
    temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
    temp_peer_mcsnssmap = ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80_80];

    /* Intersection of self Tx mcsnssmap and peer Rx mcsnssmap support
     * will indicate Rx MCS-NSS support for the peer.
     */
    ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80_80] =
        INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);



    /* ------------------ Handle 160--------------------------------- */

    (void)qdf_get_u16((uint8_t *)&rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                      &temp_self_mcsnssmap);

    /* the 160 check is necessary else "temp_self_mcsnssmap" will contain no 160 mcs */
    if(vap->iv_cur_mode == IEEE80211_MODE_11AXA_HE160) {
        HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
            (uint8_t *)&temp_self_mcsnssmap, rx_streams_160);
    }

    /* Convert self_mcsnssmap to LE format before performing intersection
     * with peer_mcsnssmap */
    temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
    temp_peer_mcsnssmap = ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160];
    /* Intersection of self Rx mcsnssmap and peer Tx mcsnssmap support
     * will indicate Tx MCS-NSS support for the peer.
     */
    ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160] =
        INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

    /* Set the bits for unsupported SS in the self TX map to Invalid */
    (void)qdf_get_u16((uint8_t *)&txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                      &temp_self_mcsnssmap);

    /* the 160 check is necessary else "temp_self_mcsnssmap" will contain no 160 mcs */
    if(vap->iv_cur_mode == IEEE80211_MODE_11AXA_HE160) {
        HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
            (uint8_t *)&temp_self_mcsnssmap, tx_streams_160);
    }

    /* Convert self_mcsnssmap to LE format before performing intersection
     * with peer_mcsnssmap */
    temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
    temp_peer_mcsnssmap = ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160];

    /* Intersection of self Tx mcsnssmap and peer Rx mcsnssmap support
     * will indicate Rx MCS-NSS support for the peer.
     */
    ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160] =
        INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);



    /*---------  Handles Intersection for 20/40/80 BWs --------------------- */

    /* Set the bits for unsupported SS in the self RX map to Invalid */
    (void)qdf_get_u16((uint8_t *)&rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                      &temp_self_mcsnssmap);
    HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
            (uint8_t *)&temp_self_mcsnssmap, rx_streams);

    /* Convert self_mcsnssmap to LE format before performing intersection
     * with peer_mcsnssmap */
    temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
    temp_peer_mcsnssmap = ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80];

    /* Intersection of self Rx mcsnssmap and peer Tx mcsnssmap support
     * will indicate Tx MCS-NSS support for the peer.
     */
    ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80] =
        INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

    /* Set the bits for unsupported SS in the self TX map to Invalid */
    (void)qdf_get_u16((uint8_t *)&txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                      &temp_self_mcsnssmap);
    HE_RESET_MCS_VALUES_FOR_UNSUPPORTED_SS(
            (uint8_t *)&temp_self_mcsnssmap, tx_streams);

    /* Convert self_mcsnssmap to LE format before performing intersection
     * with peer_mcsnssmap */
    temp_self_mcsnssmap = qdf_cpu_to_le16(temp_self_mcsnssmap);
    temp_peer_mcsnssmap = ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80];

    /* Intersection of self Tx mcsnssmap and peer Rx mcsnssmap support
     * will indicate Rx MCS-NSS support for the peer.
     */
    ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80] =
        INTERSECT_11AX_MCSNSS_MAP(temp_self_mcsnssmap, temp_peer_mcsnssmap);

    if (((ni->ni_ext_flags & IEEE80211_NODE_HE) &&
            (ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160]
             == HE_INVALID_MCSNSSMAP ||
             ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160]
             == HE_INVALID_MCSNSSMAP))) {
        IEEE80211_DPRINTF(ni->ni_vap, IEEE80211_MSG_HE,
            "%s ni_he->rxmcsnssmap_org[80MHz]=%x ni_he->txmcsnssmap_org[80MHz]=%x"
            " ni_he->rxmcsnssmap_org[160MHz]=%x ni_he->txmcsnssmap_org[160MHz]=%x"
            " ni_he->rxmcsnssmap_org[80_80MHz]=%x ni_he->txmcsnssmap_org[80_80MHz]=%x \n",
            __func__,
             ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80],
             ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80],
             ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160],
             ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_160],
             ni_he->hecap_rxmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80_80],
             ni_he->hecap_txmcsnssmap_org[HECAP_TXRX_MCS_NSS_IDX_80_80]
             );
    }
}
