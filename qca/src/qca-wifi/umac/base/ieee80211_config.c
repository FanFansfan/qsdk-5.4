/*
 *
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
 *
 */

#include <ieee80211.h>
#include <ieee80211_api.h>
#include <ieee80211_var.h>
#include <ieee80211_config.h>
#include <ieee80211_rateset.h>
#include <ieee80211_channel.h>
#include <ieee80211_target.h>
#include <ieee80211_ioctl.h>
#include <ieee80211_defines.h>
#include "ieee80211_node_priv.h"
#include "qdf_lock.h"
#include "ol_if_athvar.h"
#include "target_type.h"
#include "mlme/ieee80211_mlme_priv.h"
#include <ieee80211_node.h>
#if QCA_LTEU_SUPPORT
#include <ieee80211_nl.h>
#endif
#include <ieee80211_rateset.h>    //ieee80211_vht_rate_t

#if ATH_PERF_PWR_OFFLOAD
#include <ol_if_athvar.h>
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_private.h>
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif
#include <wlan_son_pub.h>

#include <qdf_trace.h>
#include <wlan_lmac_if_api.h>
#include <dp_extap.h>
#include <dp_me.h>
#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_ucfg_api.h>
#include <wlan_fd_utils_api.h>
#endif /* WLAN_SUPPORT_FILS */
#include <wlan_mlme_dp_dispatcher.h>
#include <wlan_vdev_mgr_ucfg_api.h>
#include <wlan_vdev_mgr_utils_api.h>
#include <wlan_mlme_vdev_mgmt_ops.h>
#include <wlan_psoc_mlme.h>
#include <wlan_reg_ucfg_api.h>

#if ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION
#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif /* MESH_MODE_SUPPORT */
#include <rawsim_api_defs.h>
#endif /* ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION */

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
#endif
#endif


#define MAX_MON_FILTER_ENTRY 32
#define MIN_IDLE_INACTIVE_TIME_SECS(val)          ((val - 5)/2)
#define MAX_IDLE_INACTIVE_TIME_SECS(val)          (val - 5)
#define MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS  5
#define MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS  (u_int16_t)~0


int
check_valid_legacy_rate( int val)
{
    int valid_legacy_rate[] = {1000,2000,5500,6000,9000,11000,12000,18000,24000,36000,48000,54000};
    int i, array_size;
    array_size = sizeof(valid_legacy_rate)/sizeof(valid_legacy_rate[0]);
    for(i = 0; i < array_size; i++){
       if(val == valid_legacy_rate[i])
         break;
    }
    if(i == array_size) {
      return -EINVAL;
    }
    return val;
}
int
isvalid_vht_mcsmap(u_int16_t mcsmap)
{
    /* Valid VHT MCS MAP
      * 0xfffc: NSS=1 MCS 0-7, NSS=2 not supported, NSS=3 not supported
      * 0xfff0: NSS=1 MCS 0-7, NSS=2       MCS 0-7, NSS=3 not supported
      * 0xffc0: NSS=1 MCS 0-7, NSS=2       MCS 0-7, NSS=3       MCS 0-7
      * 0xfffd: NSS=1 MCS 0-8, NSS=2 not supported, NSS=3 not supported
      * 0xfff5: NSS=1 MCS 0-8, NSS=2       MCS 0-8, NSS=3 not supported
      * 0xffd5: NSS=1 MCS 0-8, NSS=2       MCS 0-8, NSS=3       MCS 0-8
      * 0xfffe: NSS=1 MCS 0-9, NSS=2 not supported, NSS=3 not supported
      * 0xfffa: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3 not supported
      * 0xffea: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3       MCS 0-9
      * 0xffda: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3       MCS 0-8
      * 0xffca: NSS=1 MCS 0-9, NSS=2       MCS 0-9, NSS=3       MCS 0-7
      * 0x0: use default setting
      * For 3SS, mcsmap include VHT_MCSMAP_NSS3_MASK mask then would be valid
      * For 4SS, mcsmap include VHT_MCSMAP_NSS4_MASK mask then would be valid
      * For 8SS, mcsmap which includes VHT_MCSMAP_NSS8_MASK mask would be valid.
      * However, VHT_MCSMAP_NSS8_MASK is 0x0000, so any mcsmap value is
      * acceptable when QCA_SUPPORT_5SS_TO_8SS is enabled.
      */
#if QCA_SUPPORT_5SS_TO_8SS
    return 1;
#else
    if (((mcsmap & VHT_MCSMAP_NSS4_MASK) == VHT_MCSMAP_NSS4_MASK) || (mcsmap == 0x0)) {
        return 1;
    }

    return 0;
#endif /* QCA_SUPPORT_5SS_TO_8SS */
}
bool tx_pow_mgmt_valid(int frame_subtype,int *tx_power)
{
    if (((frame_subtype & 0x0f)!= 0) || ((frame_subtype < IEEE80211_FC0_SUBTYPE_ASSOC_REQ) || (frame_subtype > IEEE80211_FCO_SUBTYPE_ACTION_NO_ACK))){
        qdf_nofl_info("Invalid frame subtype \n");
        return 0;
    }
    if (frame_subtype == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
        qdf_nofl_info("Cannot configure tx power for probe requests\n");
        return 0;
    }
    if ((*tx_power > 255) || (*tx_power < 0)){
        *tx_power = 255;
    }
    return 1;
}
bool tx_pow_valid(uint8_t frame_type, uint8_t frame_subtype,int *tx_power)
{
    if (((frame_subtype & 0x0f)!= 0) && (frame_subtype != 0xff)){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR, "Invalid frame subtype \n");
        return 0;
    }

    if ((frame_type != IEEE80211_FC0_TYPE_MGT) && (frame_type != IEEE80211_FC0_TYPE_CTL) && (frame_type != IEEE80211_FC0_TYPE_DATA)){
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR, "Invalid frame type \n");
        return 0;
    }
    if ((*tx_power > 255) || (*tx_power < 0)){
        *tx_power = 255;
    }
    return 1;
}

/* check whether mcs values 10 and 11 are
 * supported in 11ax mode or not
 */
bool
is_he_txrx_mcs10and11_supported(struct ieee80211vap *vap, uint8_t nss) {
    uint16_t rxmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint16_t txmcsnssmap[HEHANDLE_CAP_TXRX_MCS_NSS_SIZE];
    uint8_t maxrxmcs = HE_MCS_VALUE_INVALID;
    uint8_t maxtxmcs = HE_MCS_VALUE_INVALID;

    /* get the intersected (user-set vs target caps)
     * values of mcsnssmap */
    ieee80211vap_get_insctd_mcsnssmap(vap, rxmcsnssmap, txmcsnssmap);

    switch(vap->iv_des_mode) {
        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXG_HE20:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXG_HE40:
        case IEEE80211_MODE_11AXA_HE80:
            /* derive maxmcs value from rxmcsnssmap */
            HE_DERIVE_MAX_MCS_VALUE(rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                    nss, maxrxmcs);
            /* derive maxmcs value from txmcsnssmap */
            HE_DERIVE_MAX_MCS_VALUE(txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80],
                    nss, maxtxmcs);
        break;
        case IEEE80211_MODE_11AXA_HE160:
            /* derive maxmcs value from rxmcsnssmap */
            HE_DERIVE_MAX_MCS_VALUE(rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                    nss, maxrxmcs);
            /* derive maxmcs value from txmcsnssmap */
            HE_DERIVE_MAX_MCS_VALUE(txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_160],
                    nss, maxtxmcs);
        break;
        case IEEE80211_MODE_11AXA_HE80_80:
            /* derive maxmcs value from rxmcsnssmap */
            HE_DERIVE_MAX_MCS_VALUE(rxmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                    nss, maxrxmcs);
            /* derive maxmcs value from txmcsnssmap */
            HE_DERIVE_MAX_MCS_VALUE(txmcsnssmap[HECAP_TXRX_MCS_NSS_IDX_80_80],
                    nss, maxtxmcs);
        break;
        default:
            /* Nothing to be done for now */
        break;
    }

    if (maxrxmcs == HE_MCS_VALUE_FOR_MCS_0_11 ||
            maxtxmcs == HE_MCS_VALUE_FOR_MCS_0_11)
        return true;

    return false;
}

void wlan_send_omn_action(void *arg, wlan_node_t node)
{
    struct ieee80211_action_mgt_args actionargs;

    actionargs.category = IEEE80211_ACTION_CAT_VHT;
    actionargs.action   = IEEE80211_ACTION_VHT_OPMODE;
    actionargs.arg1     = 0;
    actionargs.arg2     = 0;
    actionargs.arg3     = 0;
    ieee80211_send_action(node, &actionargs, NULL);
}

static int wlan_set_run_inact_timeout(struct vdev_mlme_obj *vdev_mlme,
                              uint32_t val, bool disable_probe)
{
    u_int16_t  max_unresponsive_time_secs = val;
    /* AP starts probing a peer on expiry of MAX_INACTIVE_TIME,
     * if the peer doesn't respond to probing the AP deauths the peer
     * after expiry of MAX_UNRESPONSIVE_TIME.
     * To disable this probing behavior on AP, update the MAX_INACTIVE_TIME
     * to be equal to MAX_UNRESPONSIVE_TIME.
     */
    u_int16_t  max_idle_inactive_time_secs = disable_probe ?
                                        val : MAX_IDLE_INACTIVE_TIME_SECS(val);
    u_int16_t  min_idle_inactive_time_secs = MIN_IDLE_INACTIVE_TIME_SECS(val);
    struct wlan_vdev_mgr_cfg mlme_cfg;
    int retval = 0;

    if (val >= MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS &&
        val <= MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS) {
       /* Setting iv_inact_run, for retrieval using iwpriv get_inact command */

         mlme_cfg.value = max_unresponsive_time_secs;
         retval = vdev_mlme_set_param(
                                  vdev_mlme,
                                  WLAN_MLME_CFG_MAX_UNRESPONSIVE_INACTIVE_TIME,
                                  mlme_cfg);
         mlme_cfg.value = max_idle_inactive_time_secs;
         retval |= vdev_mlme_set_param(
                                  vdev_mlme,
                                  WLAN_MLME_CFG_MAX_IDLE_INACTIVE_TIME,
                                  mlme_cfg);
         mlme_cfg.value = min_idle_inactive_time_secs;
         retval |= vdev_mlme_set_param(
                                  vdev_mlme,
                                  WLAN_MLME_CFG_MIN_IDLE_INACTIVE_TIME,
                                  mlme_cfg);
         QDF_TRACE(QDF_MODULE_ID_INACT, QDF_TRACE_LEVEL_DEBUG,
             "Max Unresponsive Time setting: %d secs\n"
             "Max Inactive Time setting: %d secs\n"
             "Min Inactive Time setting: %d secs\n",
             max_unresponsive_time_secs,
             max_idle_inactive_time_secs, min_idle_inactive_time_secs);
     }
     else
     {
         QDF_TRACE(QDF_MODULE_ID_DEBUG, QDF_TRACE_LEVEL_DEBUG,
                   "Range allowed is : %d to %d",
                   MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS,
                   MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS);
     }

     return retval;
}

static uint32_t ieee80211com_he_target_supports_mac_cap
                            (struct ieee80211com *ic,
                             int *he_target_cap,
                             uint32_t maccap) {
    uint32_t ic_hecap_mac_low, ic_hecap_mac_high;
    qdf_mem_copy(&ic_hecap_mac_low,
            &ic->ic_he.hecap_macinfo[HECAP_MACBYTE_IDX0], sizeof(ic_hecap_mac_low));
    qdf_mem_copy(&ic_hecap_mac_high,
            &ic->ic_he.hecap_macinfo[HECAP_MACBYTE_IDX4], sizeof(ic_hecap_mac_high));

    switch (maccap) {
        case IEEE80211_CONFIG_HE_FRAGMENTATION:
            *he_target_cap = HECAP_MAC_HEFRAG_GET_FROM_IC(ic_hecap_mac_low);
        break;
        case IEEE80211_CONFIG_HE_HT_CTRL:
            *he_target_cap = HECAP_MAC_HECTRL_GET_FROM_IC(ic_hecap_mac_low);
        break;
#if SUPPORT_11AX_D3
        case IEEE80211_CONFIG_HE_MULTI_TID_AGGR:
            *he_target_cap = HECAP_MAC_MTIDRXSUP_GET_FROM_IC(ic_hecap_mac_low);
        break;
        case IEEE80211_CONFIG_HE_MULTI_TID_AGGR_TX:
            *he_target_cap = HECAP_MAC_MTIDTXSUP_GET_FROM_IC(ic_hecap_mac_high);
        break;
        case IEEE80211_CONFIG_HE_MAX_AMPDU_LEN_EXP:
            *he_target_cap =
                    HECAP_MAC_MAXAMPDULEN_EXPEXT_GET_FROM_IC(ic_hecap_mac_low);
        break;
        case IEEE80211_CONFIG_HE_MAX_FRAG_MSDU:
            *he_target_cap =
                    HECAP_MAC_MAXFRAGMSDUEXP_GET_FROM_IC(ic_hecap_mac_low);
        break;
#else

        case IEEE80211_CONFIG_HE_MULTI_TID_AGGR:
        case IEEE80211_CONFIG_HE_MULTI_TID_AGGR_TX:
        case IEEE80211_CONFIG_HE_MAX_AMPDU_LEN_EXP:
        case IEEE80211_CONFIG_HE_MAX_FRAG_MSDU:
            *he_target_cap = 0;
            return -EINVAL;
        break;
#endif
        case IEEE80211_CONFIG_HE_MIN_FRAG_SIZE:
            *he_target_cap = HECAP_MAC_MINFRAGSZ_GET_FROM_IC(ic_hecap_mac_low);
        break;
        case IEEE80211_CONFIG_HE_OMI:
            *he_target_cap = HECAP_MAC_OMI_GET_FROM_IC(ic_hecap_mac_low);
        break;
#if SUPPORT_11AX_D3
        case IEEE80211_CONFIG_HE_UL_MU_DATA_DIS_RX_SUPP:
            *he_target_cap = HECAP_MAC_OMCTRLULMU_DISRX_GET_FROM_IC(ic_hecap_mac_high);
        break;
#endif /* SUPPORT_11AX_D3 */
        default:
            qdf_err("Target cap check on invalid HE MAC capability");
            return -EINVAL;
        break;
    }
    return 0;
}

static uint32_t ieee80211com_he_target_supports_phy_cap
                            (struct ieee80211com *ic,
                             int *he_target_cap,
                             uint32_t phycap) {
    uint32_t *ic_hecap_phy;
    ic_hecap_phy = &ic->ic_he.hecap_phyinfo[IC_HECAP_PHYDWORD_IDX0];
    switch (phycap) {
        case IEEE80211_CONFIG_HE_SU_BFEE:
            *he_target_cap = HECAP_PHY_SUBFME_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_SU_BFER:
            *he_target_cap = HECAP_PHY_SUBFMR_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_MU_BFER:
            *he_target_cap = HECAP_PHY_MUBFMR_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_SU_PPDU_1X_LTF_800NS_GI:
            *he_target_cap =
                    HECAP_PHY_SU_1XLTFAND800NSECSGI_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_SU_MU_PPDU_4X_LTF_800NS_GI:
            *he_target_cap =
                    HECAP_PHY_4XLTFAND800NSECSGI_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_NDP_4X_LTF_3200NS_GI:
            *he_target_cap = HECAP_PHY_LTFGIFORNDP_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_ER_SU_PPDU_1X_LTF_800NS_GI:
            *he_target_cap =
                    HECAP_PHY_ERSU1XLTF800NSGI_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_ER_SU_PPDU_4X_LTF_800NS_GI:
            *he_target_cap =
                    HECAP_PHY_ERSU_4XLTF800NSGI_GET_FROM_IC(ic_hecap_phy);
        break;

#if SUPPORT_11AX_D3
        case IEEE80211_CONFIG_HE_1024QAM_LT242RU_RX_ENABLE:
            *he_target_cap =
                    HECAP_PHY_TX1024QAMLT242TONERU_GET_FROM_IC(ic_hecap_phy);
        break;
#endif /* SUPPORT_11AX_D3 */

        case IEEE80211_CONFIG_HE_FULL_BW_UL_MUMIMO:
            *he_target_cap =
                    HECAP_PHY_UL_MU_MIMO_GET_FROM_IC(ic_hecap_phy);
        break;

        case IEEE80211_CONFIG_HE_DCM_MAX_CONSTELLATION_RX:
            *he_target_cap =
                    HECAP_PHY_DCMRX_GET_FROM_IC(ic_hecap_phy);
        break;

        default:
            qdf_err("Target cap check on invalid HE PHY Capability");
            return -EINVAL;
        break;
    }
    return 0;
}

int
wlan_set_param(wlan_if_t vaphandle, ieee80211_param param, u_int32_t val)
{
    QDF_STATUS status;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic  = vap->iv_ic;
    int is2GHz               = IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan);
    int ldpcsupport          = IEEE80211_HTCAP_C_LDPC_NONE;
    uint8_t rx_streams       = ieee80211_get_rxstreams(ic, vap);
    uint8_t tx_streams       = ieee80211_get_txstreams(ic, vap);
    uint8_t nss              = MIN(rx_streams, tx_streams);
    uint32_t prev_val        = 0;
    int retv                 = 0;
    int is_up                = 0;
    int he_target_cap        = 0;
    cdp_config_param_type value = {0};
#if ATH_PERF_PWR_OFFLOAD
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#endif
    struct ol_ath_vap_net80211 *avn = NULL;
    bool update_beacon       = false;
    struct wlan_vdev_mgr_cfg mlme_cfg;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    struct dp_me_mcast_table *ht;
#endif
#endif
    ol_txrx_soc_handle soc = NULL;
    uint32_t inact_period;
    uint8_t vdev_id = wlan_vdev_get_id(vap->vdev_obj);
#if ATH_SUPPORT_IQUE
    uint32_t currval;
    uint8_t pdev_id;
#endif

    if ((vap->iv_opmode == IEEE80211_M_MONITOR)
        && (param != IEEE80211_RX_FILTER_NEIGHBOUR_PEERS_MONITOR)
        && (param != IEEE80211_SECOND_CENTER_FREQ)
        && (param != IEEE80211_RX_FILTER_MONITOR)
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
        && (param != IEEE80211_CHAN_UTIL_ENAB)
#endif
        && (param != IEEE80211_STATS_UPDATE_PERIOD)
	&& (!((vap->iv_lite_monitor) && (param == IEEE80211_CONFIG_M_COPY)))
        )
            return -EINVAL;

    switch (param) {
	case IEEE80211_SET_TXPWRADJUST:
        if(ic->ic_set_txPowerAdjust)
            ic->ic_set_txPowerAdjust(ic, 2*val, is2GHz);
        break;
    case IEEE80211_AUTO_ASSOC:
       if (val)
            IEEE80211_VAP_AUTOASSOC_ENABLE(vap);
        else
            IEEE80211_VAP_AUTOASSOC_DISABLE(vap);
        break;

    case IEEE80211_SAFE_MODE:
        if (val)
            IEEE80211_VAP_SAFEMODE_ENABLE(vap);
        else
            IEEE80211_VAP_SAFEMODE_DISABLE(vap);
        if (ic->ic_set_safemode) {
            ic->ic_set_safemode(vap, val);
        }
        break;

    case IEEE80211_SEND_80211:
        if (val)
            IEEE80211_VAP_SEND_80211_ENABLE(vap);
        else
            IEEE80211_VAP_SEND_80211_DISABLE(vap);
        break;

    case IEEE80211_RECEIVE_80211:
        if (val)
            IEEE80211_VAP_DELIVER_80211_ENABLE(vap);
        else
            IEEE80211_VAP_DELIVER_80211_DISABLE(vap);
        break;

    case IEEE80211_FEATURE_DROP_UNENC:
        if (val)
            IEEE80211_VAP_DROP_UNENC_ENABLE(vap);
        else
            IEEE80211_VAP_DROP_UNENC_DISABLE(vap);
        break;

    case IEEE80211_SHORT_PREAMBLE:
        if (val)
           IEEE80211_ENABLE_CAP_SHPREAMBLE(ic);
        else
           IEEE80211_DISABLE_CAP_SHPREAMBLE(ic);
         retv = EOK;
        break;

    case IEEE80211_SHORT_SLOT:
        if (val)
            ieee80211_set_shortslottime(ic, 1);
        else
            ieee80211_set_shortslottime(ic, 0);
        wlan_pdev_beacon_update(ic);
        break;

    case IEEE80211_RTS_THRESHOLD:
        /* XXX This may force us to flush any packets for which we are
           might have already calculated the RTS */
        if (val > IEEE80211_RTS_MAX) {
            mlme_cfg.value = IEEE80211_RTS_MAX;
        } else {
            mlme_cfg.value = (uint16_t)val;
        }
        wlan_vdev_set_rtsthreshold(vap->vdev_obj, (uint16_t) mlme_cfg.value);
        vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_RTS_THRESHOLD,
                mlme_cfg);
        break;

    case IEEE80211_FRAG_THRESHOLD:
        /* XXX We probably should flush our tx path when changing fragthresh */
        if (val > 2346)
            mlme_cfg.value = 2346;
        else if (val < 256)
            mlme_cfg.value = 256;
        else
            mlme_cfg.value = (u_int16_t)val;

        vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_FRAG_THRESHOLD,
                mlme_cfg);
        wlan_vdev_set_frag_threshold(vap->vdev_obj, (uint16_t)mlme_cfg.value);
        break;

    case IEEE80211_BEACON_INTVAL:
        {
            /*
             * The beacon interval should be atleast 40  if VAPs count is <=2 , atleast 100 if VAP count is <=8 and 200 if VAP count is <=16
             * If lp_iot vap then min is 25 only for that vap type.
             */
#if ATH_PERF_PWR_OFFLOAD
             if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
                 if (val < IEEE80211_BINTVAL_LP_IOT_DEFAULT) {
                     qdf_nofl_info("\n Invalid input:\n| Min. interval for this vap is 25msecs.\n");
                     return -EINVAL;
                 }
             } else if (ieee80211_vap_oce_check(vap)) {
                 if (val > IEEE80211_BINTVAL_MAX || val < IEEE80211_BINTVAL_MIN) {
                     qdf_print("\n Invalid input:\n| BEACON_INTERVAL should be within %d to %d",
                               IEEE80211_BINTVAL_MIN, IEEE80211_BINTVAL_MAX);
                     return -EINVAL;
                 }
             } else if (!((vap->iv_opmode == IEEE80211_M_HOSTAP) && MBSSID_BINTVAL_CHECK(val,ic->ic_num_ap_vaps,scn->bcn_mode))) {
                    qdf_nofl_info("\n Invalid input:\n| NoOfVAPS\t |  Min BINTVAL allowed |\n<=2\t\t40\n<=8\t\t100\n<=16(Bursted mode)\t\t100\n<=16(Staggered mode)\t\t200\n");
                    return -EINVAL;
             }
#endif
            /*
             * If it is direct attach update the bintval
             */
            if ((vap->iv_create_flags & IEEE80211_LP_IOT_VAP))  {
                vap->iv_bss->ni_intval = val;
                LIMIT_BEACON_PERIOD(vap->iv_bss->ni_intval);
                //ic->ic_set_beacon_interval(ic);
            } else {
                ic->ic_intval = (u_int16_t)val;
                LIMIT_BEACON_PERIOD(ic->ic_intval);
                mlme_cfg.value = ic->ic_intval;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_BEACON_INTERVAL,
                        mlme_cfg);
                ic->ic_set_beacon_interval(ic);
            }
        }
        break;

#if ATH_SUPPORT_AP_WDS_COMBO
    case IEEE80211_NO_BEACON:
        vap->iv_no_beacon = (u_int8_t) val;
        ic->ic_set_config(vap);
        break;
#endif
    case IEEE80211_LISTEN_INTVAL:
        LIMIT_LISTEN_INTERVAL(val);
        ic->ic_lintval = val;
        if (vap->iv_bss)
            vap->iv_bss->ni_lintval = ic->ic_lintval;

        mlme_cfg.value = val;
        vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_LISTEN_INTERVAL,
                mlme_cfg);
        break;

    case IEEE80211_ATIM_WINDOW:
        LIMIT_BEACON_PERIOD(val);
        vap->iv_atim_window = (u_int8_t)val;
        break;

    case IEEE80211_DTIM_INTVAL:
        {
            bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                     WLAN_PDEV_F_MBSS_IE_ENABLE);
            bool is_ema_ap_enabled =
                            wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                            WLAN_PDEV_FEXT_EMA_AP_ENABLE);
            bool is_non_tx_vap     =
                            IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
            /* sanitize DTIM value for ema ap */
            if (is_mbssid_enabled) {

                if (is_ema_ap_enabled && is_non_tx_vap) {
                    /* DTIM value must be multiple of max-PP.
                     * Value 256 in case of ema ap non-Tx vap
                     * indicate a special value of 1 as DTIM=1
                     * in that case is allowed as an exceptional
                     * case only
                     */
                    if ((val != IEEE80211_EMA_SPECIAL_DTIM_VALUE)
                            && (val % ic->ic_mbss.max_pp)) {
                        mbss_err("++++DTIM for non-Tx vap in case of EMA AP"
                                 " must be multiple of max-PP: %d",
                                 ic->ic_mbss.max_pp);
                        return -EINVAL;
                    } else
                        mbss_info("user-space update of DTIM: %d", val);

                    if (val == IEEE80211_EMA_SPECIAL_DTIM_VALUE) {
                        val = 1;
                        mbss_info("allow DTIM=1 as a special case only");
                    }
                } /* if is_ema_ap_enabled && is_non_tx_vap */
            } /* if WLAN_PDEV_F_MBSS_IE_ENABLE */

            LIMIT_DTIM_PERIOD(val);

            mlme_cfg.value = val;
            vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_DTIM_PERIOD,
                    mlme_cfg);

            if (is_ema_ap_enabled && is_non_tx_vap) {
                ieee80211_mbssid_update_mbssie_cache_entry(vap,
                                                    MBSS_CACHE_ENTRY_IDX);
                mbss_debug("setting non_tx_profile_change to true"
                          " for vdev: %d", vap->iv_unit);
                vap->iv_mbss.non_tx_profile_change = true;
            }
        }
        break;

    case IEEE80211_BMISS_COUNT_RESET:
        vap->iv_bmiss_count_for_reset = (u_int8_t)val;
        break;

    case IEEE80211_BMISS_COUNT_MAX:
        vap->iv_bmiss_count_max = (u_int8_t)val;
        break;

    case IEEE80211_TXPOWER:
        break;

    case IEEE80211_MULTI_DOMAIN:
        if(!ic->ic_country.isMultidomain)
            return -EINVAL;

        if (val)
            ic->ic_multiDomainEnabled = 1;
        else
            ic->ic_multiDomainEnabled = 0;
        break;

    case IEEE80211_FEATURE_WMM:
         {
              enum ieee80211_phymode mode = ieee80211_get_current_phymode(ic);

              if (!(ic->ic_caps & IEEE80211_C_WME))
                  return -EINVAL;

              if (ieee80211_is_phymode_not_basic(mode))
                  return -EINVAL;

              if (val)
                  ieee80211_vap_wme_set(vap);
              else
                  ieee80211_vap_wme_clear(vap);
         }
         break;

    case IEEE80211_FEATURE_PRIVACY:
        if (val) {
            IEEE80211_VAP_PRIVACY_ENABLE(vap);
            /*drop unencrypted frames by default*/
            wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 1);
        } else {
            IEEE80211_VAP_PRIVACY_DISABLE(vap);
            wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 0);
        }
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
        wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
        break;

    case IEEE80211_FEATURE_WMM_PWRSAVE:
        /*
         * NB: AP WMM power save is a compilation option,
         * and can not be turned on/off at run time.
         */
        if (vap->iv_opmode != IEEE80211_M_STA)
            return -EINVAL;

        if (val)
            ieee80211_set_wmm_power_save(vap, 1);
        else
            ieee80211_set_wmm_power_save(vap, 0);
        break;

    case IEEE80211_FEATURE_UAPSD:
		if (vap->iv_opmode == IEEE80211_M_STA) {
			if (vap->iv_opmode == IEEE80211_M_P2P_GO || vap->iv_opmode == IEEE80211_M_P2P_CLIENT || vap->iv_opmode == IEEE80211_M_P2P_DEVICE) {
				ieee80211_set_uapsd_flags(vap, (u_int8_t)(val & WME_CAPINFO_UAPSD_ALL) );
				return ieee80211_pwrsave_uapsd_set_max_sp_length(vap, ((val >> WME_CAPINFO_UAPSD_MAXSP_SHIFT) & WME_CAPINFO_UAPSD_MAXSP_MASK));
			} else {
				return -EINVAL;
			}
		}
		else {
			if (IEEE80211_IS_UAPSD_ENABLED(ic)) {
				if (val)
					IEEE80211_VAP_UAPSD_ENABLE(vap);
				else
					IEEE80211_VAP_UAPSD_DISABLE(vap);
			}
			else {
				return -EINVAL;
			}
		}
		break;

	case IEEE80211_WPS_MODE:
        if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                       WLAN_PDEV_F_MBSS_IE_ENABLE)) {
            struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
            ol_ath_soc_softc_t *soc           = scn->soc;
            bool is_ema_ap_enabled =
                    wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_FEXT_EMA_AP_ENABLE);

            if (!(is_ema_ap_enabled && soc->ema_ap_support_wps_6ghz)) {
                qdf_nofl_info("WPS is not allowed for a MBSS VAP");
                return -EINVAL;
            }
        }
        vap->iv_wps_mode = (u_int8_t)val;
        break;

    case IEEE80211_NOBRIDGE_MODE:
        if (val)
            IEEE80211_VAP_NOBRIDGE_ENABLE(vap);
        else
            IEEE80211_VAP_NOBRIDGE_DISABLE(vap);
        break;

    case IEEE80211_MIN_BEACON_COUNT:
    case IEEE80211_IDLE_TIME:
        break;

    case IEEE80211_FEATURE_COUNTER_MEASURES:
        if (val)
            IEEE80211_VAP_COUNTERM_ENABLE(vap);
        else
            IEEE80211_VAP_COUNTERM_DISABLE(vap);
        break;

    case IEEE80211_FEATURE_WDS:
        if (val)
            IEEE80211_VAP_WDS_ENABLE(vap);
        else
            IEEE80211_VAP_WDS_DISABLE(vap);
#ifdef HOST_OFFLOAD
        if(ic->ic_rx_intr_mitigation != NULL)
            ic->ic_rx_intr_mitigation(ic, val);
#else
        if (vap->iv_opmode == IEEE80211_M_STA)
        {
            if(ic->ic_rx_intr_mitigation != NULL)
                ic->ic_rx_intr_mitigation(ic, val);
        }
#endif
        ieee80211_update_vap_target(vap);
        break;

#if WDS_VENDOR_EXTENSION
    case IEEE80211_WDS_RX_POLICY:
        vap->iv_wds_rx_policy = val & WDS_POLICY_RX_MASK;
        break;
#endif
    case IEEE80211_FEATURE_VAP_ENHIND:
        if (val) {
            ieee80211_ic_enh_ind_rpt_set(vap->iv_ic);
        }
        else
        {
            ieee80211_ic_enh_ind_rpt_clear(vap->iv_ic);
        }
        break;

    case IEEE80211_FEATURE_HIDE_SSID:
        if (val)
            IEEE80211_VAP_HIDESSID_ENABLE(vap);
        else
            IEEE80211_VAP_HIDESSID_DISABLE(vap);
        break;
    case IEEE80211_FEATURE_PUREG:
        if (val)
            IEEE80211_VAP_PUREG_ENABLE(vap);
        else
            IEEE80211_VAP_PUREG_DISABLE(vap);
        break;
    case IEEE80211_FEATURE_PURE11N:
        if (val)
            IEEE80211_VAP_PURE11N_ENABLE(vap);
        else
            IEEE80211_VAP_PURE11N_DISABLE(vap);
        break;
    case IEEE80211_FEATURE_PURE11AC:
        if (val) {
            IEEE80211_VAP_PURE11AC_ENABLE(vap);
	    } else {
            IEEE80211_VAP_PURE11AC_DISABLE(vap);
        }
        break;
    case IEEE80211_FEATURE_STRICT_BW:
        if (val) {
            IEEE80211_VAP_STRICT_BW_ENABLE(vap);
	    } else {
            IEEE80211_VAP_STRICT_BW_DISABLE(vap);
        }
        break;
    case IEEE80211_FEATURE_BACKHAUL:
        if (val) {
            IEEE80211_VAP_BACKHAUL_ENABLE(vap);
        } else {
            IEEE80211_VAP_BACKHAUL_DISABLE(vap);
        }
        break;
    case IEEE80211_FEATURE_APBRIDGE:
        if (val == 0)
            IEEE80211_VAP_NOBRIDGE_ENABLE(vap);
        else
            IEEE80211_VAP_NOBRIDGE_DISABLE(vap);
        break;
    case IEEE80211_FEATURE_COPY_BEACON:
        if (val == 0)
            ieee80211_vap_copy_beacon_clear(vap);
        else
            ieee80211_vap_copy_beacon_set(vap);
        break;
    case IEEE80211_FIXED_RATE:
        if (val == IEEE80211_FIXED_RATE_NONE) {
             vap->iv_fixed_rate.mode = IEEE80211_FIXED_RATE_NONE;
             vap->iv_fixed_rateset = IEEE80211_FIXED_RATE_NONE;
             vap->iv_fixed_rate.series = IEEE80211_FIXED_RATE_NONE;
        } else {
             if (val & 0x80) {

                 /*
                  * do this check only for WEXT, for cfg80211 we do not have channel yet available
                  * till we do start ap.
                  */
#if UMAC_SUPPORT_CFG80211
                 if (!vap->iv_cfg80211_create)
#endif
                 {


                     if (!IEEE80211_IS_CHAN_VHT(ic->ic_curchan) && !IEEE80211_IS_CHAN_11N(ic->ic_curchan))
                     {
                         qdf_nofl_info("Rate is not allowed in current mode\n");
                         return -EINVAL;
                     }
                 }
                 vap->iv_fixed_rate.mode = IEEE80211_FIXED_RATE_MCS;
             } else {
                 vap->iv_fixed_rate.mode = IEEE80211_FIXED_RATE_LEGACY;
             }
             vap->iv_fixed_rateset = val;
             vap->iv_fixed_rate.series = val;
        }
        ic->ic_set_config(vap);
        break;
    case IEEE80211_FIXED_RETRIES:
        vap->iv_fixed_retryset = val;
        vap->iv_fixed_rate.retries = val;
        ic->ic_set_config(vap);
        break;
    case IEEE80211_MCAST_RATE:
        prev_val = vap->iv_mcast_fixedrate;
        if (!IEEE80211_IS_CHAN_VHT(ic->ic_curchan) && !IEEE80211_IS_CHAN_11N(ic->ic_curchan)
            && !IEEE80211_IS_CHAN_HE(ic->ic_curchan)){
           int value;
           value=check_valid_legacy_rate(val);
           if(value ==(-EINVAL)){
             qdf_nofl_info("Rate is not allowed in current mode:\n");
             return -EINVAL;
           }
        }
        vap->iv_mcast_fixedrate = val;
        ieee80211_set_mcast_rate(vap);
        break;
    case IEEE80211_BCAST_RATE:
        prev_val = vap->iv_bcast_fixedrate;
        if (!IEEE80211_IS_CHAN_VHT(ic->ic_curchan) && !IEEE80211_IS_CHAN_11N(ic->ic_curchan)){
           int value;
           value=check_valid_legacy_rate(val);
           if(value ==(-EINVAL)){
             qdf_nofl_info("Rate is not allowed in current mode:\n");
             return -EINVAL;
           }
        }
        vap->iv_bcast_fixedrate = val;
        ieee80211_set_mcast_rate(vap);
        break;
    case IEEE80211_SHORT_GI:
        if (val > IEEE80211_GI_3DOT2_US)
            return -EINVAL;

        if (val && val <= IEEE80211_GI_3DOT2_US) {
            /* For GI 800ns & 400ns */
            if(val == IEEE80211_GI_0DOT4_US) {
                /* Note: Leaving this logic intact for backward compatibility */
                /* With VHT it suffices if we just examine HT */
                if (ieee80211com_has_htcap(ic, IEEE80211_HTCAP_C_SHORTGI40 | IEEE80211_HTCAP_C_SHORTGI20)) {
                    if (ieee80211com_has_htcap(ic, IEEE80211_HTCAP_C_SHORTGI40))
                        ieee80211vap_set_htflags(vap, IEEE80211_HTF_SHORTGI40);

                    if (ieee80211com_has_htcap(ic, IEEE80211_HTCAP_C_SHORTGI20))
                        ieee80211vap_set_htflags(vap, IEEE80211_HTF_SHORTGI20);
                        /* For VHT mode only 800ns/0.8us or 400ns/0.4ns supported and
                         * for HE mode only 800ns/0.8us supported
                         */

                    if(ic->ic_he.hecap_info_internal &
                         (IEEE80211_HE_0DOT4US_IN_2XLTF_SUPP_BITS |
                          IEEE80211_HE_0DOT4US_IN_1XLTF_SUPP_BITS)) {
                        /* Allow setting of 400ns for 11ax mode if target indicates
                         * support for 400ns during Service Ready.
                         */
                        vap->iv_sgi = val;
                        vap->iv_data_sgi = val;
                        vap->iv_he_sgi = val;
                        vap->iv_he_data_sgi = val;
                    }
                    else if (!ieee80211_is_phymode_11ax(vap->iv_des_mode)) {
                        vap->iv_sgi = val;
                        vap->iv_data_sgi = val;
                    }
                    else {
                        qdf_err("%s: ShortGI setting %d not allowed\n", __func__, val);
                        return -EINVAL;
                    }
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
                    if (vap->iv_wrap == 1)
#else
                    if (dp_wrap_vdev_is_wrap(vap->vdev_obj))
#endif
                    {
                        if (!ieee80211_is_phymode_11ax(vap->iv_des_mode) ||
                            (vap->iv_cur_mode &&
                            !ieee80211_is_phymode_11ax(vap->iv_cur_mode)))
                            vap->iv_ic->ic_wrap_vap_sgi_cap = vap->iv_sgi;
                        else
                            vap->iv_ic->ic_wrap_vap_sgi_cap = vap->iv_he_sgi;
                    }
#endif
                } else  {
                    return -EINVAL;
                }
            /* For GI 1600ns & 3200ns */
            } else if(ic->ic_he_target) {
                vap->iv_he_data_sgi = val;
            }
        } else {
            ieee80211vap_clear_htflags(vap, IEEE80211_HTF_SHORTGI40 | IEEE80211_HTF_SHORTGI20);
            vap->iv_sgi = val;
            vap->iv_he_sgi = val;
            vap->iv_data_sgi = val;
            vap->iv_he_data_sgi = val;
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
            if (vap->iv_wrap == 1)
#else
            if (dp_wrap_vdev_is_wrap(vap->vdev_obj))
#endif
            {
                if (!ieee80211_is_phymode_11ax(vap->iv_des_mode) ||
                   (vap->iv_cur_mode &&
                    !ieee80211_is_phymode_11ax(vap->iv_cur_mode)))
                    vap->iv_ic->ic_wrap_vap_sgi_cap = vap->iv_sgi;
                else
                    vap->iv_ic->ic_wrap_vap_sgi_cap = vap->iv_he_sgi;
            }
#endif
        }
        ic->ic_set_config(vap);
        break;
     case IEEE80211_FEATURE_STAFWD:
     	if (vap->iv_opmode == IEEE80211_M_STA)
     	{
          if (val == 0)
              ieee80211_vap_sta_fwd_clear(vap);
          else
              ieee80211_vap_sta_fwd_set(vap);
     	}
         else
         {
             return -EINVAL;
         }
         break;
    case IEEE80211_HT40_INTOLERANT:
        vap->iv_ht40_intolerant = val;
        update_beacon = true;
        break;

    case IEEE80211_CHWIDTH:
        if ( val > 3 )
        {
            return -EINVAL;
        }
        if(val > ieee80211_get_chan_width_from_phymode(vap->iv_des_mode))
        {
            qdf_nofl_info("value should be less than or equal to vap channel width");
            return -EINVAL;
        }
        vap->iv_chwidth = val;
        update_beacon = true;
        break;

    case IEEE80211_CHEXTOFFSET:
	vap->iv_chextoffset = val;
        update_beacon = true;
        break;

    case IEEE80211_DISABLE_2040COEXIST:
        if (val) {
            ieee80211com_set_flags(ic, IEEE80211_F_COEXT_DISABLE);
        }
        else{
            //Resume to the state kept in registry key
            if (ic->ic_reg_parm.disable2040Coexist) {
                ieee80211com_set_flags(ic, IEEE80211_F_COEXT_DISABLE);
            } else {
                ieee80211com_clear_flags(ic, IEEE80211_F_COEXT_DISABLE);
            }
        }
        break;
    case IEEE80211_DISABLE_HTPROTECTION:
        vap->iv_disable_HTProtection = val;
        break;
#ifdef ATH_SUPPORT_QUICK_KICKOUT
    case IEEE80211_STA_QUICKKICKOUT:
        if(vap->iv_wnm != 1)
           vap->iv_sko_th = val;
           wlan_vdev_set_sko_th(vap->vdev_obj, val);
        break;
#endif
    case IEEE80211_CHSCANINIT:
        vap->iv_chscaninit = val;
        update_beacon = true;
        break;
    case IEEE80211_DRIVER_CAPS:
        ieee80211vap_set_cap(vap, val);
        break;
    case IEEE80211_FEATURE_COUNTRY_IE:
        if (val) {
            /* Enable the Country IE during tx of beacon and ProbeResp. */
            ieee80211_vap_country_ie_set(vap);
        } else {
            /* Disable the Country IE during tx of beacon and ProbeResp. */
            ieee80211_vap_country_ie_clear(vap);
        }
        update_beacon = true;
        break;
    case IEEE80211_FEATURE_IC_COUNTRY_IE:
        if (val) {
            IEEE80211_ENABLE_COUNTRYIE(ic);
        } else {
            IEEE80211_DISABLE_COUNTRYIE(ic);
        }
        break;
    case IEEE80211_FEATURE_DOTH:
        if (val) {
            /* Enable the dot h IE's for this VAP. */
            if (ieee80211_vap_doth_is_clear(vap)) {
                vap->iv_doth_updated = 1;
                update_beacon = true;
                ieee80211_vap_doth_set(vap);
                vap->iv_user_disabled_vap_doth = 0;
            }
        } else {
            /* Disable the dot h IE's for this VAP. */
            if (ieee80211_vap_doth_is_set(vap)) {
                vap->iv_doth_updated = 1;
                update_beacon = true;
                ieee80211_vap_doth_clear(vap);
                vap->iv_user_disabled_vap_doth = 1;
            }
        }
        break;

     case  IEEE80211_FEATURE_PSPOLL:
         retv = wlan_sta_power_set_pspoll(vap, val);
         break;

    case IEEE80211_FEATURE_CONTINUE_PSPOLL_FOR_MOREDATA:
         retv = wlan_sta_power_set_pspoll_moredata_handling(vap, val ?
										IEEE80211_CONTINUE_PSPOLL_FOR_MORE_DATA :
                                        IEEE80211_WAKEUP_FOR_MORE_DATA);
         break;

#if ATH_SUPPORT_IQUE
    case IEEE80211_ME:
        pdev_id = wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj);
        soc = wlan_psoc_get_dp_handle(wlan_vdev_get_psoc(vap->vdev_obj));
        if (dp_get_vdev_me_handle(soc, vdev_id)) {
            if(val  == MC_HYFI_ENABLE || val == MC_AMSDU_ENABLE || val == MC_ME_DISABLE) {
#ifndef QCA_OL_DMS_WAR
                if (val == MC_AMSDU_ENABLE) {
                    qdf_info("DMS AMSDU WAR is not enabled. Mcast AMSDU mode will not work");
                    return -EINVAL;
                }
#endif
                currval = dp_get_me_mode(soc, vdev_id);
                value.cdp_vdev_param_mcast_en = val;
                if (val && !currval) {
                        cdp_tx_me_alloc_descriptor(soc, pdev_id);
                        cdp_txrx_set_vdev_param(soc, vdev_id, CDP_ENABLE_MCAST_EN, value);
                        dp_set_me_mode(soc, vdev_id, val);
                } else if (!val && currval) {
                        dp_set_me_mode(soc, vdev_id, val);
                        cdp_txrx_set_vdev_param(soc, vdev_id, CDP_ENABLE_MCAST_EN, value);
                        cdp_tx_me_free_descriptor(soc, pdev_id);
                }
            } else {
                qdf_debug("Mode %d not supported. Only Mcast enhance mode 5 and 6 are supported.", val);
                return -EINVAL;
            }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            if (ic->nss_vops) {
                ic->nss_vops->ic_osif_nss_vdev_set_cfg(vap->iv_ifp, OSIF_NSS_VDEV_ENABLE_ME);
                /* If hifitbl already has entries, send them to NSS-FW */
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
                ht = dp_get_me_mcast_table(soc, vdev_id);

                if (!ht) {
                    return -EINVAL;
                }

                if ((dp_get_me_mode(soc, vdev_id)) && ht->entry_cnt && val != 0) {
                    osif_dev *osif;
                    osif = (osif_dev *)vap->iv_ifp;

                    qdf_info("Configure hifi  %d entry_cnt %d", __LINE__, ht->entry_cnt);
                    ic->nss_vops->ic_osif_nss_vdev_me_reset_snooplist(osif);
                    ic->nss_vops->ic_osif_nss_vdev_me_update_hifitlb(
                                        osif,
                                        dp_get_vdev_me_handle(soc, vdev_id));
                }
#endif
            }
#endif
        }
    break;
#endif /*ATH_SUPPORT_IQUE*/
    case IEEE80211_WEP_MBSSID:
        vap->iv_wep_mbssid = !!val;
        break;
    case IEEE80211_MGMT_RATE:
    case IEEE80211_RTSCTS_RATE:
        mlme_cfg.value = val;
        vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_TX_MGMT_RATE, mlme_cfg);
        break;
    case IEEE80211_NON_BASIC_RTSCTS_RATE:
        mlme_cfg.value = val;
        vdev_mlme_set_param(vdev_mlme,
                            WLAN_MLME_CFG_TX_RTSCTS_RATE, mlme_cfg);
        break;
    case IEEE80211_PRB_RATE:
        vap->iv_prb_rate = (u_int16_t)val;
        break;
    case IEEE80211_PRB_RETRY:
        vap->iv_prb_retry = (u_int16_t)val;
        break;
    case IEEE80211_FEATURE_AMPDU:
        wlan_vdev_set_ampdu_subframes(vap->vdev_obj, val);
        ic->ic_set_config(vap);
        /*
         * Disable or Enable with size limits A-MPDU per VDEV per AC
         * bits 7:0 -> Access Category (0x0=BE, 0x1=BK, 0x2=VI, 0x3=VO, 0xFF=All AC)
         * bits 31:8 -> Max number of subframes
         *
         * If the size is zero, A-MPDU is disabled for the VAP for the given AC.
         * Else, A-MPDU is enabled for the VAP for the given AC, but is limited
         * to the specified max number of sub frames.
         *
         * If Access Category is 0xff, the specified max number of subframes will
         * be applied for all the Access Categories. If not, max subframes
         * have to be applied per AC.
         *
         * This is only for TX subframe size. In RX path this new VDEV param shall
         * only be used to check, wherever needed, to see if AMPDU is enabled or
         * disabled for a given VAP.
         */
        if (ic->ic_set_config_enable(vap)) {
            mlme_cfg.value = val;
            vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_AMPDU,
                    mlme_cfg);
        }
        break;
    case IEEE80211_AMPDU_SET:
        if (ic->ic_set_config_enable(vap)) {
            if ((val >= 0) && (val <= CUSTOM_AGGR_MAX_AMPDU_SIZE)) {
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_AMPDU_SIZE,
                                    mlme_cfg);
                status = mlme_ext_vap_custom_aggr_size_send(vdev_mlme, false);
                retv = qdf_status_to_os_return(status);
            } else {
                qdf_err("Aggregation Size Limit is [0-255]");
                retv = -EINVAL;
            }
        } else {
            if (val >= 0 && val <= IEEE80211_AMPDU_SUBFRAME_MAX) {
            /* Default as of now: All AC (0x0=BE, 0x1=BK, 0x2=VI, 0x3=VO, 0xFF-All AC) */
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_AMPDU,
                        mlme_cfg);
            } else {
                qdf_err("AMPDU Range is 0 - %d",IEEE80211_AMPDU_SUBFRAME_MAX);
                retv = -EINVAL;
            }
        }
        return retv;
    case IEEE80211_AMSDU_SET:
        mlme_cfg.value = val;
        vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_AMSDU_SIZE,
                                      mlme_cfg);
        wlan_vdev_set_amsdu(vap->vdev_obj, val);
        ic->ic_set_config(vap);
        if (ic->ic_set_config_enable(vap)) {
            if ((val >= 0) && (val <= CUSTOM_AGGR_MAX_AMSDU_SIZE)) {
                status = mlme_ext_vap_custom_aggr_size_send(vdev_mlme, true);
                retv = qdf_status_to_os_return(status);
            } else {
                qdf_err("Aggregation Size Limit is [0-7]");
                retv = -EINVAL;
            }
        } else {
            if (val >= 0 && val <= 4) {
            /* Default as of now: All AC (0x0=BE, 0x1=BK, 0x2=VI, 0x3=VO, 0xFF-All AC) */
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_AMSDU,
                        mlme_cfg);
            } else {
                qdf_err("AMSDU Range is 0-4");
                retv = -EINVAL;
            }
        }
        break;
    case IEEE80211_MAX_AMPDU:
        ic->ic_maxampdu = val;
        break;
    case IEEE80211_VHT_MAX_AMPDU:
        ic->ic_vhtcap &= ~IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP;
        ic->ic_vhtcap |= (val << IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S);
        break;
    case IEEE80211_MIN_FRAMESIZE:
        ic->ic_minframesize = val;
        wlan_pdev_set_minframesize(ic->ic_pdev_obj, val);
        break;
    case IEEE80211_UAPSD_MAXSP:
        retv = ieee80211_pwrsave_uapsd_set_max_sp_length(vap,val);
    break;

    case IEEE80211_PROTECTION_MODE:
        vap->iv_protmode = val;
        wlan_vdev_set_prot_mode(vap->vdev_obj, val);
        break;

    case IEEE80211_AUTH_INACT_TIMEOUT:
        vap->iv_inact_auth = (val + IEEE80211_INACT_WAIT-1)/IEEE80211_INACT_WAIT;
        break;

    case IEEE80211_INIT_INACT_TIMEOUT:
        vap->iv_inact_init = (val + IEEE80211_INACT_WAIT-1)/IEEE80211_INACT_WAIT;
        break;

    case IEEE80211_RUN_INACT_TIMEOUT:
        /* Checking if vap is on offload radio or not */
        if (!wlan_get_HWcapabilities(ic,IEEE80211_CAP_PERF_PWR_OFLD))
        {
            if (val <= IEEE80211_RUN_INACT_TIMEOUT_THRESHOLD) {
                mlme_cfg.value = (val + IEEE80211_INACT_WAIT-1)/IEEE80211_INACT_WAIT;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_MAX_UNRESPONSIVE_INACTIVE_TIME,
                        mlme_cfg);
            }
            else {
                qdf_nofl_info("\nMaximum value allowed is : %d", IEEE80211_RUN_INACT_TIMEOUT_THRESHOLD);
            }
        }

        retv = wlan_set_run_inact_timeout(vdev_mlme, val, vap->iv_disable_inact_probe);
        break;

    case IEEE80211_PROBE_INACT_TIMEOUT:
        vap->iv_inact_probe = (val + IEEE80211_INACT_WAIT-1)/IEEE80211_INACT_WAIT;
        break;

    case IEEE80211_SESSION_TIMEOUT:
        vap->iv_session = (val + IEEE80211_SESSION_WAIT-1)/IEEE80211_SESSION_WAIT;
        break;

    case IEEE80211_QBSS_LOAD:
         if (val == 0) {
            ieee80211_vap_qbssload_clear(vap);
         } else {
            ieee80211_vap_qbssload_set(vap);
         }
         break;
#if ATH_SUPPORT_HS20
    case IEEE80211_HC_BSSLOAD:
        if (vap->iv_hc_bssload != val) {
            vap->iv_hc_bssload = val;
            update_beacon = true;
        }
        break;
    case IEEE80211_OSEN:
        vap->iv_osen = val;
        break;
#endif /* ATH_SUPPORT_HS20 */

#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    case IEEE80211_CHAN_UTIL_ENAB:
         vap->iv_chanutil_enab = val;
         break;
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
#if UMAC_SUPPORT_XBSSLOAD
    case IEEE80211_XBSS_LOAD:
         if (val == 0) {
             ieee80211_vap_ext_bssload_clear(vap);
         } else {
             ieee80211_vap_ext_bssload_set(vap);
         }
         break;
#endif
    case IEEE80211_RRM_CAP:
         if (val == 0) {
            ieee80211_vap_rrm_clear(vap);
         } else {
            ieee80211_vap_rrm_set(vap);
         }
         break;
    case IEEE80211_RRM_FILTER:
        ieee80211_set_rrmfilter(vap, val);
        break;
    case IEEE80211_WNM_FILTER:
        ieee80211_set_wnmfilter(vap, val);
        break;
    case IEEE80211_RRM_DEBUG:
         ieee80211_rrmdbg_set(vap, val);
         break;
    case IEEE80211_RRM_STATS:
         ieee80211_set_rrmstats(vap, val);
         break;
    case IEEE80211_WNM_STATS:
         ieee80211_set_wnmstats(vap, val);
         break;
    case IEEE80211_RRM_SLWINDOW:
         ieee80211_rrm_set_slwindow(vap,val);
         break;
    case IEEE80211_RRM_CAP_IE:
         if (vap->iv_opmode == IEEE80211_M_STA) {
             vap->iv_rrm_cap_ie = val;
         } else {
             qdf_err("Cammad applicable only for STA mode VAP!\n");
             retv = -EINVAL;
         }
         break;
#if ATH_SUPPORT_MBO
    case IEEE80211_MBO:
         retv = wlan_set_mbo_param(vap,IEEE80211_MBO,val);
         return retv;
    case IEEE80211_MBOCAP:
         retv = wlan_set_mbo_param(vap,IEEE80211_MBOCAP,val);
         return retv;
    case IEEE80211_MBO_ASSOC_DISALLOW:
         retv = wlan_set_mbo_param(vap,IEEE80211_MBO_ASSOC_DISALLOW,val);
         return retv;
    case IEEE80211_MBO_CELLULAR_PREFERENCE:
         retv = wlan_set_mbo_param(vap,IEEE80211_MBO_CELLULAR_PREFERENCE,val);
         return retv;
         break;
    case IEEE80211_MBO_TRANSITION_REASON:
         retv = wlan_set_mbo_param(vap,IEEE80211_MBO_TRANSITION_REASON,val);
         return retv;
         break;
    case IEEE80211_MBO_ASSOC_RETRY_DELAY:
        retv  = wlan_set_mbo_param(vap,IEEE80211_MBO_ASSOC_RETRY_DELAY,val);
        return retv;
        break;
    case IEEE80211_OCE:
         retv = wlan_set_oce_param(vap, IEEE80211_OCE, val);
         return retv;
    case IEEE80211_OCE_ASSOC_REJECT:
         retv = wlan_set_oce_param(vap, IEEE80211_OCE_ASSOC_REJECT, val);
         return retv;
    case IEEE80211_OCE_ASSOC_MIN_RSSI:
         retv = wlan_set_oce_param(vap, IEEE80211_OCE_ASSOC_MIN_RSSI, val);
         return retv;
    case IEEE80211_OCE_ASSOC_RETRY_DELAY:
         retv = wlan_set_oce_param(vap, IEEE80211_OCE_ASSOC_RETRY_DELAY, val);
         return retv;
    case IEEE80211_OCE_WAN_METRICS:
         retv = wlan_set_oce_param(vap, IEEE80211_OCE_WAN_METRICS, val);
         return retv;
    case IEEE80211_OCE_HLP:
         retv = wlan_set_oce_param(vap, IEEE80211_OCE_HLP, val);
         return retv;
    case IEEE80211_OCE_VERSION_OVERRIDE:
         retv = wlan_set_oce_param(vap, IEEE80211_OCE_VERSION_OVERRIDE, val);
         return retv;
#endif
#if UMAC_SUPPORT_WNM
    case IEEE80211_WNM_CAP:
         if((val == 1) && (ieee80211_ic_wnm_is_set(ic) == 0)) {
              return -EINVAL;
         }
         if (val == 0) {
            ieee80211_vap_wnm_clear(vap);
         } else {
            ieee80211_vap_wnm_set(vap);
         }
         break;
    case IEEE80211_WNM_BSS_CAP:
         retv = ieee80211_vap_update_wnm_bss_cap(vap, val);
         break;
    case IEEE80211_WNM_TFS_CAP:
         if(val == 1 && (ieee80211_vap_wnm_is_set(vap) == 0)) {
              return -EINVAL;
         }
         if (val == 0) {
            ieee80211_wnm_tfs_clear(vap->wnm);
         } else {
            ieee80211_wnm_tfs_set(vap->wnm);
         }
         break;
    case IEEE80211_WNM_TIM_CAP:
         if(val == 1 && (ieee80211_vap_wnm_is_set(vap) == 0)) {
              return -EINVAL;
         }
         if (val == 0) {
            ieee80211_wnm_tim_clear(vap->wnm);
         } else {
            ieee80211_wnm_tim_set(vap->wnm);
         }
         break;
    case IEEE80211_WNM_SLEEP_CAP:
         if(val == 1 && (ieee80211_vap_wnm_is_set(vap) == 0)) {
              return -EINVAL;
         }
         if (val == 0) {
            ieee80211_wnm_sleep_clear(vap->wnm);
         } else {
            ieee80211_wnm_sleep_set(vap->wnm);
         }
         break;
    case IEEE80211_WNM_FMS_CAP:
         if(val == 1 && (ieee80211_vap_wnm_is_set(vap) == 0)) {
             return -EINVAL;
         }
         if(ieee80211_wnm_fms_is_set(vap->wnm) == val) {
             return -EINVAL;
         }
         if (val == 0) {
             ieee80211_wnm_fms_clear(vap->wnm);
         } else {
             ieee80211_wnm_fms_set(vap->wnm);
         }
         break;
#endif
    case IEEE80211_FWD_ACTION_FRAMES_TO_APP:
        vap->iv_fwd_action_frames_to_app = val;
        break;
    case IEEE80211_AP_REJECT_DFS_CHAN:
        if (val == 0)
            ieee80211_vap_ap_reject_dfs_chan_clear(vap);
        else
            ieee80211_vap_ap_reject_dfs_chan_set(vap);
        break;
	case IEEE80211_WDS_AUTODETECT:
        if (!val) {
           IEEE80211_VAP_WDS_AUTODETECT_DISABLE(vap);
        } else {
           IEEE80211_VAP_WDS_AUTODETECT_ENABLE(vap);
        }
        break;
	case IEEE80211_WEP_TKIP_HT:
		if (!val) {
           ieee80211_ic_wep_tkip_htrate_clear(ic);
        } else {
           ieee80211_ic_wep_tkip_htrate_set(ic);
        }
        break;
	case IEEE80211_IGNORE_11DBEACON:
        if (!val) {
           IEEE80211_DISABLE_IGNORE_11D_BEACON(ic);
        } else {
           IEEE80211_ENABLE_IGNORE_11D_BEACON(ic);
        }
        break;

    case IEEE80211_FEATURE_MFP_TEST:
        if (!val) {
            ieee80211_vap_mfp_test_clear(vap);
        } else {
            ieee80211_vap_mfp_test_set(vap);
        }
        break;

    case IEEE80211_TRIGGER_MLME_RESP:
         if (val == 0) {
            ieee80211_vap_trigger_mlme_resp_clear(vap);
         } else {
            ieee80211_vap_trigger_mlme_resp_set(vap);
         }
         break;

#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_TXBF_AUTO_CVUPDATE:
        vap->iv_autocvupdate = val;
        break;
    case IEEE80211_TXBF_CVUPDATE_PER:
        vap->iv_cvupdateper = val;
        break;
#endif
    case IEEE80211_SMARTNET:
        if (val) {
            ieee80211_vap_smartnet_enable_set(vap);
        }else {
            ieee80211_vap_smartnet_enable_clear(vap);
        }
        wlan_vdev_set_smartnet_enable(vap->vdev_obj, val);
        break;
    case IEEE80211_WEATHER_RADAR:
            ic->ic_no_weather_radar_chan = !!val;
        break;
    case IEEE80211_WEP_KEYCACHE:
            vap->iv_wep_keycache = !!val;
            break;
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    case IEEE80211_REJOINT_ATTEMP_TIME:
            vap->iv_rejoint_attemp_time = val;
            break;
#endif
    case IEEE80211_SEND_DEAUTH:
            vap->iv_send_deauth = !!val;
            break;
#if UMAC_SUPPORT_PROXY_ARP
    case IEEE80211_PROXYARP_CAP:
         if (val == 0) {
            ieee80211_vap_proxyarp_clear(vap);
         } else {
            ieee80211_vap_proxyarp_set(vap);
         }
         break;
#if UMAC_SUPPORT_DGAF_DISABLE
    case IEEE80211_DGAF_DISABLE:
         if (val == 0) {
             ieee80211_vap_dgaf_disable_clear(vap);
         } else {
             ieee80211_vap_dgaf_disable_set(vap);
         }
         break;
#endif
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    case IEEE80211_NOPBN:
         if (val == 0) {
             ieee80211_vap_nopbn_clear(vap);
         } else {
             ieee80211_vap_nopbn_set(vap);
         }
        break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_DSCP_MAP_ID:
        vap->iv_dscp_map_id = val;
        wlan_vdev_set_dscp_map_id(vap->vdev_obj, val);
        break;
#endif

    case IEEE80211_EXT_ACS_IN_PROGRESS:
         if (val == 0) {
             ieee80211_vap_ext_acs_inprogress_clear(vap);
         } else {
             ieee80211_vap_ext_acs_inprogress_set(vap);
         }
         return EOK;
         break;

    case IEEE80211_SEND_ADDITIONAL_IES:
         if (val == 0) {
            ieee80211_vap_send_additional_ies_clear(vap);
         } else {
            ieee80211_vap_send_additional_ies_set(vap);
         }
         return EOK;
         break;

    case IEEE80211_FIXED_VHT_MCS:
         if(!ieee80211vap_vhtallowed(vap))
         {
            qdf_nofl_info("Rate is not allowed in current mode\n");
            return -EINVAL;
         }
         vap->iv_fixed_rate.mode   = IEEE80211_FIXED_RATE_NONE;

         if (val > 9 && !(ic->ic_he_target)) {
            /* Treat this as disabling fixed rate */
            return EOK;
         }

	 if (is2GHz && (val > 7) && (!ieee80211_vap_256qam_is_set(vap))) {
		 /* if 256 QAM is not set ignore MCS index 8, 9 */
		 return EOK;
	 }

	 /* MCS 9,10,11  supported in VHT mode */
         if (val > IEEE80211_HE_MCS_IDX_MAX) {
            /* Treat this as disabling fixed rate */
            return EOK;
         }

         vap->iv_fixed_rate.mode   = IEEE80211_FIXED_RATE_VHT;
         vap->iv_vht_fixed_mcs = val;
    break;

    case IEEE80211_FIXED_HE_MCS:
         if(!ieee80211vap_heallowed(vap))
         {
            qdf_print("HE Rates are not allowed in Non HE mode");
            return -EINVAL;
         }

         vap->iv_fixed_rate.mode  = IEEE80211_FIXED_RATE_NONE;

         if (val > vap->iv_he_max_mcs_supp) {
            /* Treat this as disabling fixed rate */
            qdf_err("HE MCS value cannot be greater than %d\n",
                    vap->iv_he_max_mcs_supp);
            return EOK;
         }

         vap->iv_fixed_rate.mode = IEEE80211_FIXED_RATE_HE;
         vap->iv_he_fixed_mcs = val;
    break;

    case IEEE80211_CONFIG_HE_MULTI_TID_AGGR:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_MULTI_TID_AGGR)) {
             qdf_info("11ax D3 not supported, so Multi TID Aggregation Rx is "
                             "disabled");

            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE Multi TID aggregation rx: %d must"
                        " be <= the target capability value: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_multi_tid_aggr = val;
    break;

    case IEEE80211_CONFIG_HE_MULTI_TID_AGGR_TX:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_MULTI_TID_AGGR_TX)) {
            qdf_info("11ax D3 not supported, so Multi TID Aggregation Tx is "
                            "disabled");
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE Multi TID aggregation tx: %d must"
                        " be <= the target capability value: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_multi_tid_aggr_tx = val;
    break;

    case IEEE80211_CONFIG_HE_MAX_AMPDU_LEN_EXP:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_MAX_AMPDU_LEN_EXP)) {
            qdf_info("11ax D3 not supported, so Max AMPDU Len Extension "
                            "Exponent is 0");

            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE Max Ampdu Lengh Exponent Extension: "
                "%d must be <= the target capability value: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_max_ampdu_len_exp = val;
    break;

    case IEEE80211_CONFIG_HE_SU_PPDU_1X_LTF_800NS_GI:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_SU_PPDU_1X_LTF_800NS_GI)) {
            qdf_info("11ax D3 not supported, so Maximum Number of Fragmented "
                            "MSDUs a STA can Rx is 0");

            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE SU PPDU with 1x ltf and 800ns GI:"
                    " %d must be <= target capability: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_su_ppdu_1x_ltf_800ns_gi = val;
    break;

    case IEEE80211_CONFIG_HE_SU_MU_PPDU_4X_LTF_800NS_GI:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                            IEEE80211_CONFIG_HE_SU_MU_PPDU_4X_LTF_800NS_GI)) {
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for SU MU PPDU with 4x ltf and 800ns GI:"
                    " %d must be <= target capability value: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_su_mu_ppdu_4x_ltf_800ns_gi = val;
    break;

    case IEEE80211_CONFIG_HE_MIN_FRAG_SIZE:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_MIN_FRAG_SIZE)) {
            return -EINVAL;
        }
        if ((val < he_target_cap) || (val > IEEE80211_HE_MIN_FRAG_SIZE_MAX)) {
            qdf_err("The user value for HE Minimum Fragment Size: %d must be: "
                    "%d <= value <= %d", val,
                    he_target_cap, IEEE80211_HE_MIN_FRAG_SIZE_MAX);
            return -EINVAL;
        }
        vap->iv_he_min_frag_size = val;
    break;

    case IEEE80211_CONFIG_HE_MAX_FRAG_MSDU:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_MAX_FRAG_MSDU)) {
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE Maximum number of fragmented "
                "MSDUs STA can rx: %d must be <= target capability value: %d",
                        val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_max_frag_msdu = val;
    break;

    case IEEE80211_CONFIG_HE_OMI:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_OMI)) {
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("HE OM Control Subfield value: %d must be <= target"
                        " capability value: %d", val, he_target_cap);
            return -EINVAL;
        }
        if (!(vap->iv_opmode == IEEE80211_M_STA)) {
            qdf_err("HE OMI Setting only configurable for STAs");
            return -EINVAL;
        }
        vap->iv_he_omi = val;
    break;

    case IEEE80211_CONFIG_HE_NDP_4X_LTF_3200NS_GI:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                            IEEE80211_CONFIG_HE_NDP_4X_LTF_3200NS_GI)) {
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE NDP with 4x ltf and 3200ns GI"
                    " setting: %d must be <= target capability value: %d",
                    val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_ndp_4x_ltf_3200ns_gi = val;
    break;

    case IEEE80211_CONFIG_HE_ER_SU_PPDU_1X_LTF_800NS_GI:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                            IEEE80211_CONFIG_HE_ER_SU_PPDU_1X_LTF_800NS_GI)) {
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE ER SU PPDU with 1x ltf and 800ns"
                " GI setting: %d must be <= target capability value"
                ": %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_er_su_ppdu_1x_ltf_800ns_gi = val;
    break;

    case IEEE80211_CONFIG_HE_ER_SU_PPDU_4X_LTF_800NS_GI:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                            IEEE80211_CONFIG_HE_ER_SU_PPDU_4X_LTF_800NS_GI)) {
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for HE ER SU PPDU with 4x ltf and 800ns GI"
                    " setting: %d must be <= target capability"
                    " value: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_er_su_ppdu_4x_ltf_800ns_gi = val;
    break;

    case IEEE80211_FIXED_NSS:
         if (val > ieee80211_getstreams(ic, ic->ic_tx_chainmask))
         return -EINVAL;

          mlme_cfg.value = val;
          vdev_mlme_set_param(vdev_mlme, WLAN_MLME_CFG_NSS,
                                        mlme_cfg);
    break;

    case IEEE80211_SUPPORT_LDPC:
        switch (val) {
            case IEEE80211_HTCAP_C_LDPC_NONE:
                /* According to 802.11ax specification,
                 * D2.0 (section 28.1.1) if BW > 20MHZ,
                 * or nss > 4 or if mcs 10 and 11 are
                 * supported then ldpc can not be disabled.
                 * The first check belsw is for the BW,
                 * 2nd for nss in he mode and the third
                 * for HE MCS 10 and 11.
                 */
                if (ieee80211_is_phymode_equal_or_above_11axa_he40plus(vap->iv_des_mode) ||
                   (ieee80211vap_ishemode(vap) && (nss > 4)) ||
                   is_he_txrx_mcs10and11_supported(vap, nss)) {
                    qdf_print("LDPC value %d is not supported"
                            " if any of the following is true:"
                            " is_bw_gt_20mhz: %s, is_nss_gt_4: %s"
                            " is_he_mcs_10_and_11: %s", val,
                            (vap->iv_des_mode > IEEE80211_MODE_11AXA_HE20) ?
                            "true" : "false", (nss > 4) ? "true" : "false",
                            is_he_txrx_mcs10and11_supported(vap, nss) ? "true" :
                            "false");
                    return -EINVAL;
                } else {
                    mlme_cfg.value = val;
                    vdev_mlme_set_param(vdev_mlme,
                            WLAN_MLME_CFG_LDPC,
                            mlme_cfg);
                }
            break;

            case IEEE80211_HTCAP_C_LDPC_RX:
                if (ieee80211_is_phymode_11ax(vap->iv_des_mode)) {
                    qdf_print("LDPC value %d is not"
                           " supported in HE mode."
                           " Try %d for disabling and"
                           " %d for enabling.",
                           IEEE80211_HTCAP_C_LDPC_RX,
                           IEEE80211_HTCAP_C_LDPC_NONE,
                           IEEE80211_HTCAP_C_LDPC_TXRX);
                    return -EINVAL;
                }

            case IEEE80211_HTCAP_C_LDPC_TX:
                if (ieee80211_is_phymode_11ax(vap->iv_des_mode)) {
                    qdf_print("LDPC value %d is not"
                           " supported in HE mode."
                           " Try %d for disabling and"
                           " %d for enabling.",
                           IEEE80211_HTCAP_C_LDPC_TX,
                           IEEE80211_HTCAP_C_LDPC_NONE,
                           IEEE80211_HTCAP_C_LDPC_TXRX);
                    return -EINVAL;
                }

            case IEEE80211_HTCAP_C_LDPC_TXRX:
                /* HT check is sufficient for VHT and HE both */
                ldpcsupport = ieee80211com_get_ldpccap(ic);
                if ((ldpcsupport & val) == val) {
                    mlme_cfg.value = val;
                    vdev_mlme_set_param(vdev_mlme,
                            WLAN_MLME_CFG_LDPC,
                            mlme_cfg);
                } else {
                    qdf_print("LDPC is not supported");
                    return -EINVAL;
                }

            break;

            default:
                return -EINVAL;
            break;
        }
    break;


    case IEEE80211_SUPPORT_TX_STBC:
        switch (val) {
            case 0:
                vap->iv_tx_stbc = val;
            break;

            case 1:
                 /* A check for HT will suffice for both VHT and HE modes
                  */
                if (ieee80211com_has_htcap(ic, IEEE80211_HTCAP_C_TXSTBC) &&
                    (vap->iv_des_mode >= IEEE80211_MODE_11NA_HT20)) {
                    vap->iv_tx_stbc = val;
                } else {
                    return -EINVAL;
                }
            break;

            default:
                return -EINVAL;
            break;
        }
    break;

    case IEEE80211_SUPPORT_RX_STBC:
        switch (val) {
            case 0:
                vap->iv_rx_stbc = val;
            break;

            case 1:
            case 2:
            case 3:
                if (((ic->ic_htcap & IEEE80211_HTCAP_C_RXSTBC) ||
                    (ic->ic_vhtcap & IEEE80211_VHTCAP_RX_STBC)) &&
                    (vap->iv_des_mode >= IEEE80211_MODE_11NA_HT20) &&
                    (vap->iv_des_mode < IEEE80211_MODE_11AXA_HE20)) {
                    vap->iv_rx_stbc = val;
                } else if (HECAP_PHY_RXSTBC_GET_FROM_IC((&(ic->ic_he.hecap_phyinfo[0])))) {
                    /* only value 1 is supported in HE */
                    vap->iv_rx_stbc = 1;
                } else {
                    return -EINVAL;
                }
            break;

            default:
                return -EINVAL;
            break;
        }
    break;

    case IEEE80211_CONFIG_HE_UL_SHORTGI:

        if ((val == IEEE80211_GI_0DOT4_US) ||
            (val > IEEE80211_GI_3DOT2_US))
        {
            qdf_err("%d not supported setting for HE UL Shortgi\n",
                    IEEE80211_GI_0DOT4_US);
            return -EINVAL;
        }

        vap->iv_he_ul_sgi = val;
        break;

    case IEEE80211_CONFIG_HE_UL_LTF:

        if (val <= IEEE80211_HE_LTF_4X) {
            vap->iv_he_ul_ltf = val;
        } else {
            qdf_err("HE LTF value should be less"
                    " than or equal to 0x%x\n", IEEE80211_HE_LTF_4X);
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_UL_NSS:

        if (val > ieee80211_getstreams(ic, ic->ic_rx_chainmask)) {
            qdf_err("NSS setting cannot be greater than rx chainmask");
            return -EINVAL;
        }

        vap->iv_he_ul_nss = val;

        /* BCC coding not supported for NSS greater than 4.
         * Switch to LDPC coding in Host as FW is going to switch to LDPC
         * coding internally under this condition for Trigger frame.
         */
        if(!(vap->iv_he_ul_ldpc) && (vap->iv_he_ul_nss > 4)) {
            vap->iv_he_ul_ldpc = 1;
        }
        break;

    case IEEE80211_CONFIG_HE_UL_PPDU_BW:

        if(val > IEEE80211_HE_BW_IDX_MAX) {
            qdf_err("Channel width value should be less than 3.\n");
            return -EINVAL;
        }

        vap->iv_he_ul_ppdu_bw = val;

        /* BCC coding not supported for BW greater than 20MHz.
         * Switch to LDPC coding in Host as FW is going to switch to LDPC
         * coding internally under this condition for Trigger frame.
         */
        if(!(vap->iv_he_ul_ldpc) && (vap->iv_he_ul_ppdu_bw > 0)) {
            vap->iv_he_ul_ldpc = 1;
        }
        break;

    case IEEE80211_CONFIG_HE_UL_LDPC:

        if(val > 1) {
            qdf_err("UL LDPC setting should either 0 or 1.\n");
            return -EINVAL;
        }

        vap->iv_he_ul_ldpc = val;
        break;

    case IEEE80211_CONFIG_HE_UL_FIXED_RATE:

        if (val > vap->iv_he_max_mcs_supp) {
            qdf_err("UL HE MCS value cannot be greater than %d\n",
                    vap->iv_he_max_mcs_supp);
            return -EINVAL;
        }

        vap->iv_he_ul_fixed_rate = val;

        /* BCC coding not supported for MCS greater than 9.
         * Switch to LDPC coding in Host as FW is going to switch to LDPC
         * coding internally under this condition for Trigger frame.
         */
        if(!(vap->iv_he_ul_ldpc) && (vap->iv_he_ul_fixed_rate > 9)) {
            vap->iv_he_ul_ldpc = 1;
        }
        break;

    case IEEE80211_CONFIG_HE_UL_STBC:

        if(val > 1) {
            qdf_err("UL STBC setting should either 0 or 1.\n");
                return -EINVAL;
        }

        vap->iv_he_ul_stbc = val;
        break;

    case IEEE80211_OPMODE_NOTIFY_ENABLE:
        /* TODO: This Op Mode Tx feature is not mandatory.
         * For now we will use this ioctl to trigger op mode notification
         * At a later date we will use the notify varibale to enable/disable
         * opmode notification dynamically (@runtime)
         */
        if (val) {
            struct ieee80211_node   *ni = NULL;
            if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
                /* create temporary node for broadcast */
                ni = ieee80211_tmp_node(vap, IEEE80211_GET_BCAST_ADDR(vap->iv_ic));
            } else {
                ni = vap->iv_bss;
            }

            if (ni != NULL) {
                wlan_send_omn_action(NULL, ni);

                if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
                    /* temporary node - decrement reference count so that the node will be
                     * automatically freed upon completion */
                    wlan_objmgr_delete_node(ni);
                }
            }
        }
        vap->iv_opmode_notify = val;
    break;

    case IEEE80211_ENABLE_RTSCTS:
         if (((val & (~0xff)) != 0) ||
             (((val & IEEE80211_RTS_CTS_MASK) == 0) &&
              (((val & IEEE80211_RTS_CTS_PROFILE_MASK) >> IEEE80211_RTS_CTS_PROFILE_SHIFT) != 0)) ||
             (((val & IEEE80211_RTS_CTS_MASK) != 0) &&
              (((val & IEEE80211_RTS_CTS_PROFILE_MASK) >> IEEE80211_RTS_CTS_PROFILE_SHIFT) == 0)) ) {
             qdf_nofl_info("%s: Invalid value for RTS-CTS: %x\n", __func__, val);
             return -EINVAL;
         }

         if (((val & IEEE80211_RTS_CTS_MASK) > IEEE80211_RTSCTS_FLAG_MAX_VALUE) ||
             (((val & IEEE80211_RTS_CTS_PROFILE_MASK) >> IEEE80211_RTS_CTS_PROFILE_SHIFT) > IEEE80211_RTSCTS_PROFILE_MAX_VALUE)) {
             qdf_nofl_info("%s: Not yet supported value for RTS-CTS: %x\n",
                     __func__, val);
             return -EINVAL;
         }

         vap->iv_rtscts_enabled = val;
    break;

    case IEEE80211_RC_NUM_RETRIES:
        if ((val & 0x1) == 1) { /* do not support odd numbers */
            return -EINVAL;
        }

        if (val == 0) {
            val = 2; /* Default case: use 2 retries - one for each rate-series. */
        }

        vap->iv_rc_num_retries = val;
    break;

    case IEEE80211_VHT_TX_MCSMAP:
         if (isvalid_vht_mcsmap(val)) {
             vap->iv_vht_tx_mcsmap = val;
         } else {
             return EINVAL;
         }
    break;
    case IEEE80211_VHT_RX_MCSMAP:
         if (isvalid_vht_mcsmap(val)) {
             vap->iv_vht_rx_mcsmap = val;
         } else {
             return EINVAL;
         }
    break;
    case IEEE80211_SUPPORT_IMPLICITBF:
        if(ic->ic_vhtcap & (IEEE80211_VHTCAP_MU_BFORMER|IEEE80211_VHTCAP_SU_BFORMER)) {
            if (val == 1 || val == 0) {
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_IMLICIT_BF,
                        mlme_cfg);
            } else {
                return -EINVAL;
            }
        } else {
            return -EINVAL;
        }
    break;

    case IEEE80211_VHT_SUBFEE:
        if(ic->ic_vhtcap & IEEE80211_VHTCAP_SU_BFORMEE) {
            if (val == 1 || val == 0) {
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_SUBFEE, mlme_cfg);
            } else {
                return -EINVAL;
            }
        } else {
            return -EINVAL;
        }
    break;

    case IEEE80211_VHT_MUBFEE:
        if((vap->iv_opmode == IEEE80211_M_STA) && (ic->ic_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE)) {
            if (val == 1 || val == 0) {
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_MUBFEE, mlme_cfg);
            } else {
                return -EINVAL;
            }
        } else {
            return -EINVAL;
        }
    break;

    case IEEE80211_VHT_SUBFER:
        if(ic->ic_vhtcap & IEEE80211_VHTCAP_SU_BFORMER) {
            if (val == 1 || val == 0) {
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_SUBFER, mlme_cfg);
            } else {
                return -EINVAL;
            }
        } else {
            return -EINVAL;
        }
    break;

    case IEEE80211_VHT_MUBFER:
        if((vap->iv_opmode == IEEE80211_M_HOSTAP) && (ic->ic_vhtcap & IEEE80211_VHTCAP_MU_BFORMER)) {
            if (val == 1 || val == 0) {
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_MUBFER, mlme_cfg);
            } else {
                return -EINVAL;
            }
        } else {
            return -EINVAL;
        }
    break;

    case IEEE80211_VHT_BF_STS_CAP:
        if(val >= 0 && val <= ((ic->ic_vhtcap >> IEEE80211_VHTCAP_STS_CAP_S) & IEEE80211_VHTCAP_STS_CAP_M))
        {
                mlme_cfg.value = val;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_BFEE_STS_CAP, mlme_cfg);
        } else {
            return -EINVAL;
        }
    break;

    case IEEE80211_VHT_BF_SOUNDING_DIM:
        if(val >= 0 && val <= ((ic->ic_vhtcap & IEEE80211_VHTCAP_SOUND_DIM) >> IEEE80211_VHTCAP_SOUND_DIM_S))
        {
            mlme_cfg.value = val;
            vdev_mlme_set_param(vdev_mlme,
                    WLAN_MLME_CFG_SOUNDING_DIM, mlme_cfg);
        } else {
            return -EINVAL;
        }
    break;
    case IEEE80211_CONFIG_VHT_MCS_10_11_SUPP:
        if(val <= 1) {
            if(val != vap->iv_vht_mcs10_11_supp) {
                vap->iv_vht_mcs10_11_supp = val;
            }
            else {
                qdf_info("VHT MCS 10/11 support already set to %d", val);
                return -EINVAL;
            }
        } else {
            qdf_err("VHT MCS10/11 support should be either 0 or 1");
            return -EINVAL;
        }
    break;
    case IEEE80211_CONFIG_HE_MCS_12_13_SUPP:
        if(val <= 1) {
            if(val != vap->iv_he_mcs12_13_supp) {
                vap->iv_he_mcs12_13_supp = val;
                retv = ENETRESET;
                return retv;
            }
            else {
                qdf_info("HE MCS 12/13 support already set to %d", val);
                return -EINVAL;
            }
        } else {
            qdf_err("HE MCS12/13 support should be either 0 or 1");
            return -EINVAL;
        }
    break;
    case IEEE80211_CONFIG_VHT_MCS_10_11_NQ2Q_PEER_SUPP:
        if(val <= 1) {
            if(val != vap->iv_vht_mcs10_11_nq2q_peer_supp) {
                vap->iv_vht_mcs10_11_nq2q_peer_supp = val;
            }
            else {
                qdf_info("VHT MCS 10/11 support already set to %d", val);
                return -EINVAL;
            }
        } else {
            qdf_err("VHT MCS10/11 support should be either 0 or 1");
            return -EINVAL;
        }
    break;
    case IEEE80211_CONFIG_MCAST_RC_STALE_PERIOD:
        if (val < 0) {
            qdf_err("Invalid value for mcast rc stale period");
            return -EINVAL;
        }
    break;
    case IEEE80211_START_ACS_REPORT:
        return (wlan_acs_start_scan_report(vap,true,param,(void *)&val));
    break;
    case IEEE80211_MIN_DWELL_ACS_REPORT:
        return (wlan_acs_start_scan_report(vap,true,param,(void *)&val));
    break;
    case IEEE80211_MAX_DWELL_ACS_REPORT:
        return (wlan_acs_start_scan_report(vap,true,param,(void *)&val));
    break;
    case IEEE80211_MAX_SCAN_TIME_ACS_REPORT:
        return (wlan_acs_start_scan_report(vap,true,param,(void *)&val));
    break;
    case IEEE80211_256QAM:
        if (val == 0) {
           ieee80211_vap_256qam_clear(vap);
        } else {
           ieee80211_vap_256qam_set(vap);
        }
     break;
     case IEEE80211_11NG_VHT_INTEROP:
        if (val == 0) {
           ieee80211_vap_11ng_vht_interop_clear(vap);
        } else {
           ieee80211_vap_11ng_vht_interop_set(vap);
        }
     break;
    case IEEE80211_ACS_CH_HOP_LONG_DUR:
    case IEEE80211_ACS_CH_HOP_NO_HOP_DUR:
    case IEEE80211_ACS_CH_HOP_CNT_WIN_DUR:
    case IEEE80211_ACS_CH_HOP_NOISE_TH:
    case IEEE80211_ACS_CH_HOP_CNT_TH:
    case IEEE80211_ACS_ENABLE_CH_HOP:
        retv = wlan_acs_param_ch_hopping(vaphandle,true,param,&val);
        return retv;
    break;
    case IEEE80211_MAX_SCANENTRY:
        wlan_scan_set_maxentry(vap->iv_ic, val);
        break;
    case IEEE80211_SCANENTRY_TIMEOUT:
        wlan_scan_set_timeout(vap->iv_ic, val);
        break;
#if ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_RAWMODE_SIM_TXAGGR:
        if ((val != 0) && (val < RAWSIM_MIN_FRAGS_PER_TX_MPDU)) {
            val = RAWSIM_MIN_FRAGS_PER_TX_MPDU;
            qdf_err("%s: Min value must be %d when amsdu is enabled defaulting it to min",__func__, RAWSIM_MIN_FRAGS_PER_TX_MPDU);
        } else if (val > MAX_FRAGS_PER_RAW_TX_MPDU) {
            val = MAX_FRAGS_PER_RAW_TX_MPDU;
            qdf_err("%s: Max value must be %d when amsdu is enabled defaulting it to max supported", __func__, MAX_FRAGS_PER_RAW_TX_MPDU);
        }
        /* simulation will package one MSDU per scatter/gather fragment */
        vap->iv_rawmodesim_txaggr = val;
        if (!wlan_update_rawsim_config(vap)) {
            vap->iv_rawmodesim_txaggr = 0;
            qdf_err("Failed to set rawmodesim_txaggr");
        }
        break;
    case IEEE80211_CLR_RAWMODE_PKT_SIM_STATS:
        if (ic->ic_vap_set_param)
            retv = ic->ic_vap_set_param(vap, IEEE80211_CLR_RAWMODE_PKT_SIM_STATS, val);
        break;
    case IEEE80211_RAWMODE_SIM_DEBUG_LEVEL:
        if ((val & 0x3) <= 2) {
            vap->iv_rawmodesim_debug_level = val & 0x3;
            if (!wlan_update_rawsim_config(vap)) {
                vap->iv_rawmodesim_debug_level = 0;
                qdf_err("Failed to set simulation debug level");
            }
        } else
            qdf_err("dbg level max value is 2");
        break;
    case IEEE80211_RAWSIM_DEBUG_NUM_ENCAP_FRAMES:
        vap->iv_num_encap_frames = val & (IEEE80211_MAX_32BIT_UNSIGNED_VALUE >> 1);
        if (vap->iv_num_encap_frames) {
            vap->iv_fixed_frm_cnt_flag |= FIXED_NUM_ENCAP_DUMP;
            qdf_info("encap: fixed frame count mode");
        } else {
            vap->iv_fixed_frm_cnt_flag &= ~FIXED_NUM_ENCAP_DUMP;
            qdf_info("encap: continuous log mode.");
        }

        if (!wlan_update_rawsim_encap_frame_count(vap)) {
            vap->iv_num_encap_frames = 0;
            vap->iv_fixed_frm_cnt_flag &= ~FIXED_NUM_ENCAP_DUMP;
            qdf_err("Failed to set no of encapped frames to dump");
        }
        break;
    case IEEE80211_RAWSIM_DEBUG_NUM_DECAP_FRAMES:
        vap->iv_num_decap_frames = val & (IEEE80211_MAX_32BIT_UNSIGNED_VALUE >> 1);
        if (vap->iv_num_decap_frames) {
            vap->iv_fixed_frm_cnt_flag |= FIXED_NUM_DECAP_DUMP;
            qdf_info("decap: fixed frame count mode");
        } else {
            vap->iv_fixed_frm_cnt_flag &= ~FIXED_NUM_DECAP_DUMP;
            qdf_info("decap: continuous log mode.");
        }

        if (!wlan_update_rawsim_decap_frame_count(vap)) {
            vap->iv_num_decap_frames = 0;
            vap->iv_fixed_frm_cnt_flag &= ~FIXED_NUM_DECAP_DUMP;
            qdf_err("Failed to set no of decapped frames to dump");
        }
        break;
#endif /* ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    case IEEE80211_SCAN_MAX_DWELL:
#define MAX_SCAN_DWELL_TIME 10000
#define DEFAULT_MAX_SCAN_DWELL_TIME 300
        if(val < MAX_SCAN_DWELL_TIME &&
                val >= DEFAULT_MAX_SCAN_DWELL_TIME) {
            vap->max_dwell_time_passive = val;
            retv = EOK ;
        }
        else  {
            retv = EINVAL;
        }
#undef MAX_SCAN_DWELL_TIME
#undef DEFAULT_MAX_SCAN_DWELL_TIME
        return retv;
    case IEEE80211_SCAN_MIN_DWELL:
#define MIN_SCAN_DWELL_TIME 50
#define DEFAULT_MIN_SCAN_DWELL_TIME 200
        if(val > MIN_SCAN_DWELL_TIME &&
                val <= DEFAULT_MIN_SCAN_DWELL_TIME) {
            vap->min_dwell_time_passive = val;
            retv = EOK ;
        } else {
            retv = EINVAL;
        }
#undef MIN_SCAN_DWELL_TIME
#undef DEFAULT_MIN_SCAN_DWELL_TIME
        return retv;
#if QCA_LTEU_SUPPORT
    case IEEE80211_SCAN_REPEAT_PROBE_TIME:
        mlme_cfg.value = val;
        vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_REPEAT_PROBE_TIME,
                mlme_cfg);
        break;
    case IEEE80211_SCAN_REST_TIME:
        vap->scan_rest_time = val;
        break;
    case IEEE80211_SCAN_IDLE_TIME:
        vap->scan_idle_time = val;
        break;
    case IEEE80211_SCAN_PROBE_DELAY:
        mlme_cfg.value = val;
        vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_PROBE_DELAY,
                mlme_cfg);
        break;
    case IEEE80211_SCAN_PROBE_SPACE_INTERVAL:
        {
            if (val > 0) {
                vap->scan_probe_spacing_interval = val;
            }
            else {
                vap->scan_probe_spacing_interval = LTEU_DEFAULT_PRB_SPC_INT;
            }
        }
        break;
    case IEEE80211_MU_DELAY:
        vap->mu_start_delay = val;
        break;
    case IEEE80211_WIFI_TX_POWER:
        if (val > 100)
            val = 15;
        vap->wifi_tx_power = val;
        break;
#endif
    case IEEE80211_VHT_SGIMASK:
         if (val > MAX_VHT_SGI_MASK) {
            return EINVAL;
         }
         vap->iv_vht_sgimask = val;
        break;
    case IEEE80211_VHT80_RATEMASK:
         if (val > MAX_VHT80_RATE_MASK) {
            return EINVAL;
         }
         vap->iv_vht80_ratemask = (val & MAX_VHT80_RATE_MASK);
        break;
    case IEEE80211_BW_NSS_RATEMASK:
         {
            u_int32_t bw, nss, ratemask, max_bw;
            uint32_t target_type;

            target_type = ic->ic_get_tgt_type(ic);

            bw = (val & 0xff000000) >> 24;
            nss = (val & 0x00ff0000) >> 16;
            ratemask = (val & 0xffff);

            /* 11AX TODO: Add support for 11ax here if required */

            if (ic->ic_modecaps &
                    ((1 << IEEE80211_MODE_11AC_VHT160) |
                     (1 << IEEE80211_MODE_11AC_VHT80_80))) {
                max_bw = 6;
            }
            else {
                max_bw = 5;
            }
            if (bw > max_bw) {
                qdf_nofl_info("%s: Not yet supported value for Band Width: %d\n",
                     __func__, bw);
                qdf_nofl_info("%s: Supported Band Width: %s VHT80 - 5, VHT40 - 4, VHT20 - 3, "
                        "HT40 - 2, HT20 - 1, OFDM/CCK - 0\n",
                        __func__,(max_bw == 6)?"VHT160 - 6,":"");
                return EINVAL;
            }
            else if ((bw <= max_bw) && (bw >= 3) && (ratemask > 0x3ff)) {
                qdf_nofl_info("%s: Invalid ratemask for VHT Band: 0x%x\n", __func__, ratemask);
                return EINVAL;
            } else if ((bw <= 2) && (bw >= 1) && (ratemask > 0xff)) {
                qdf_nofl_info("%s: Invalid ratemask for HT Band: 0x%x\n", __func__, ratemask);
                return EINVAL;
            } else if ((target_type == TARGET_TYPE_QCA9984) && (bw == 6) && (nss > 2)) {
                /* ExtServiceReadyCMaskConfig TODO: Handle max nss check as part
                 * of Ext Service Ready based chainmask configuration.
                 */
                qdf_nofl_info("%s: Invalid nss for 160-VHT Band: 0x%x, max nss: 0x2\n", __func__, nss);
                return EINVAL;
            } else if ((target_type == TARGET_TYPE_QCA9888) && (bw == 6) && (nss > 1)) {
                /* ExtServiceReadyCMaskConfig TODO: Handle max nss check as part
                 * of Ext Service Ready based chainmask configuration.
                 */
                qdf_nofl_info("%s: Invalid nss for 160-VHT Band: 0x%x, max nss: 0x2\n", __func__, nss);
                return EINVAL;
            } else if ((bw <= max_bw) && (bw >= 1) && ((nss > 4) || (nss == 0)))  {
                qdf_nofl_info("%s: Invalid nss for VHT/HT Band: %d\n", __func__, nss);
                return EINVAL;
            }
         }
        break;
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_VAP_DSCP_PRIORITY:
        vap->iv_vap_dscp_priority = val;
        break;
#endif

    case IEEE80211_SMART_MESH_CONFIG:
        vap->iv_smart_mesh_cfg = val;
        break;

#if MESH_MODE_SUPPORT
    case IEEE80211_MESH_CAPABILITIES:
        vap->iv_mesh_cap = val;
        break;

    case IEEE80211_CONFIG_MGMT_TX_FOR_MESH:
        if(vap->iv_mesh_vap_mode)
           vap->iv_mesh_mgmt_txsend_config = !!val;
         break;

    case IEEE80211_CONFIG_RX_MESH_FILTER:
    case IEEE80211_CONFIG_MESH_MCAST:
        if (ic->ic_vap_set_param)
           retv = ic->ic_vap_set_param(vap,param, val);
        break;
#endif
#ifdef VDEV_PEER_PROTOCOL_COUNT
    case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_COUNT:
    case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_DROP_MASK:
        if (ic->ic_vap_set_param)
            retv = ic->ic_vap_set_param(vap, param, val);
        break;
#endif

    case IEEE80211_CONFIG_ASSOC_WAR_160W:
        vap->iv_cfg_assoc_war_160w = (val &
                                      IEEE80211_VAP_CFG_ASSOC_WAR_160_MASK) ;
        break;
    case IEEE80211_FEATURE_SON:
        if (val)
                son_vdev_feat_capablity(vap->vdev_obj,
                                        SON_CAP_SET,
                                        WLAN_VDEV_F_SON);
        else
                son_vdev_feat_capablity(vap->vdev_obj,
                                        SON_CAP_CLEAR,
                                        WLAN_VDEV_F_SON);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_vops) {
            ic->nss_vops->ic_osif_nss_vdev_set_cfg((osif_dev *)vap->iv_ifp, OSIF_NSS_WIFI_VDEV_CFG_SON_CAP);
        }
#endif
        break;
    case IEEE80211_FEATURE_REPT_MULTI_SPECIAL:
        if (val)
            son_vdev_fext_capablity(vap->vdev_obj,
                                    SON_CAP_SET,
                                    WLAN_VDEV_FEXT_SON_SPL_RPT);
        else
            son_vdev_fext_capablity(vap->vdev_obj,
                                    SON_CAP_CLEAR,
                                    WLAN_VDEV_FEXT_SON_SPL_RPT);
        break;
    case IEEE80211_RAWMODE_PKT_SIM:
        vap->iv_rawmode_pkt_sim = val;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
        if (!wlan_update_rawsim_config(vap)) {
            vap->iv_rawmode_pkt_sim = 0;
            qdf_err("Failed to update rmode_pktsim");
        }
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
        break;

    case IEEE80211_CONFIG_RAW_DWEP_IND:
        vap->iv_cfg_raw_dwep_ind = !!val;
        break;
    case IEEE80211_CONFIG_DISABLE_SELECTIVE_HTMCS:
        if(!ieee80211vap_htallowed(vap)) {
            qdf_nofl_info("HT is not allowed for this vap\n");
            return -EINVAL;
        }
        vap->iv_disabled_ht_mcsset[0]= val & 0xFF;
        vap->iv_disabled_ht_mcsset[1]= ((val>>8) & 0xFF);
        vap->iv_disabled_ht_mcsset[2]= ((val>>16) & 0xFF);
        vap->iv_disabled_ht_mcsset[3]= ((val>>24) & 0xFF);
        if(val)
            vap->iv_disable_htmcs = 1;
        else
            vap->iv_disable_htmcs = 0;
        break;

    case IEEE80211_CONFIG_CONFIGURE_SELECTIVE_VHTMCS:
        if(!ieee80211vap_vhtallowed(vap))
        {
            qdf_nofl_info("VHT is not allowed for the current vap mode\n");
            return -EINVAL;
        }
        if (isvalid_vht_mcsmap(val)) {
            vap->iv_vht_rx_mcsmap = val;
            vap->iv_vht_tx_mcsmap = val;
            vap->iv_configured_vht_mcsmap = val;
            vap->iv_set_vht_mcsmap = true;
        } else {
            qdf_nofl_info("ERROR: Invalid vht mcs map\n");
            return EINVAL;
        }
        break;

    case IEEE80211_CONFIG_PARAM_CUSTOM_CHAN_LIST:
        {
            struct ieee80211_node *ni = vap->iv_bss;
            if (vap->iv_opmode == IEEE80211_M_STA) {
                ic->ic_use_custom_chan_list = val;
                if (ni && (ni->ni_associd > 0))
                    ieee80211_update_custom_scan_chan_list(vap, true);
                else
                    ieee80211_update_custom_scan_chan_list(vap, false);
            } else {
                qdf_print("ERROR: custom chan command not allowed in AP mode");
                return EINVAL;
            }
        }
        break;

#if UMAC_SUPPORT_ACFG
    case IEEE80211_CONFIG_DIAG_WARN_THRESHOLD:
        {
            if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
                int value = (int)val;
                if (value <= 0) {
                    qdf_nofl_info("Data rate should be a positive value \n");
                    return -EINVAL;
                }
                if (value <= vap->iv_diag_err_threshold) {
                    qdf_nofl_info("Warn threshold should be > err threshold\n");
                    return -EINVAL;
                }
                vap->iv_diag_warn_threshold = value;
            } else {
                qdf_nofl_info("Config valid only in HostAP mode\n");
                return -EINVAL;
            }
        }
        break;

    case IEEE80211_CONFIG_DIAG_ERR_THRESHOLD:
        {
            if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
                int value = (int)val;
                if(value <= 0) {
                    qdf_nofl_info("Data rate should be a positive value \n");
                    return -EINVAL;
                }
                if (value >= vap->iv_diag_warn_threshold) {
                    qdf_nofl_info("Err threshold should be < warn threshold\n");
                    return -EINVAL;
                }
                vap->iv_diag_err_threshold = value;
            } else {
                qdf_nofl_info("Config valid only in HostAP mode\n");
                return -EINVAL;
            }
        }
        break;
    case IEEE80211_CONFIG_RDG_ENABLE:
        {
            return -EINVAL;
        }
        break;
#if UMAC_SUPPORT_RRM
    case IEEE80211_CONFIG_CLEAR_QOS:
        wlan_clear_qos(vap, val);
        break;
#endif
#endif
   case IEEE80211_CONFIG_TRAFFIC_STATS:
        if (val){
            int bin;
            bin = (int)(ic->traf_interval/ic->traf_rate);
            if ((ic->traf_interval%ic->traf_rate)){
                ic->traf_bins = bin + 1;
            }else{
                ic->traf_bins = bin;
            }
            ic->bin_number = 0;
            OS_SET_TIMER(&ic->ic_noise_stats, ic->traf_rate * 1000);
            ic->traf_stats_enable = val;
        }
        else {
            ic->traf_stats_enable = val;
            ic->bin_number = 0;
            OS_CANCEL_TIMER(&ic->ic_noise_stats);
        }
        break;
   case IEEE80211_CONFIG_TRAFFIC_RATE:
#define MAX_TRAFFIC_RATE 100
        if ((val) && (val <= MAX_TRAFFIC_RATE)){
            int bin;
            ic->traf_rate = val;
            bin = (int)(ic->traf_interval/ic->traf_rate);
            if ((ic->traf_interval%ic->traf_rate)){
                ic->traf_bins = bin + 1;
            }else{
                ic->traf_bins = bin;
            }
        }
        else {
            return -EINVAL;
        }
#undef MAX_TRAFFIC_RATE
        break;
   case IEEE80211_CONFIG_TRAFFIC_INTERVAL:
#define MAX_TRAFFIC_INTERVAL 3600
        if((val) && (val <= MAX_TRAFFIC_INTERVAL)){
            int bin;
            ic->traf_interval = val;
            bin = (int)(ic->traf_interval/ic->traf_rate);
            if ((ic->traf_interval%ic->traf_rate)){
                ic->traf_bins = bin + 1;
            }else{
                ic->traf_bins = bin;
            }
        }
        else {
            return -EINVAL;
        }
#undef MAX_TRAFFIC_INTERVAL
        break;
    case IEEE80211_CONFIG_REV_SIG_160W:
        vap->iv_rev_sig_160w = val;
        break;
#ifdef MU_CAP_WAR_ENABLED
    case IEEE80211_CONFIG_MU_CAP_WAR:
    {
        MU_CAP_WAR *war = &vap->iv_mu_cap_war;

        if (val == ((u_int32_t) war->mu_cap_war)) {
            ieee80211_note(vap, IEEE80211_MSG_ANY,
                    "%s : No change in MU CAP WAR between old and new values\n",
                    __func__);
            break;
        }
        qdf_spin_lock_bh(&war->iv_mu_cap_lock);
        switch(val)
        {
            case 0:
                /*Disable WAR from enabled state*/
                if ((war->iv_mu_timer_state != MU_TIMER_PENDING) &&
                    (war->mu_cap_client_num[MU_CAP_DEDICATED_SU_CLIENT] > 0)) {
                    /*
                     * We are disabling the WAR here
                     * Kick out any Dedicated-SU clients
                     * and make them join based on our
                     * "normal" probe response and not
                     * "hacked" probe response
                     */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                            "Kick out DEDICATED-SU clients\n");
                    war->iv_mu_timer_state = MU_TIMER_PENDING;
                    war->mu_timer_cmd = MU_CAP_TIMER_CMD_KICKOUT_SU_CLIENTS;
                     /* enable timer in 10 seconds*/
                    OS_SET_TIMER(&war->iv_mu_cap_timer,10*1000);
                }
                war->mu_cap_war = val;
                war->modify_probe_resp_for_dedicated = val;
                break;
            case 1:
                /* Enable WAR from disabled state */
                if (war->iv_mu_timer_state == MU_TIMER_PENDING) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                    "ERROR!!Timer for the previous WAR-DISABLE cmd %s",
                    "is still running\n");
                    break;
                }
                if (ieee80211_mu_cap_dedicated_mu_kickout(war)) {
                    /*
                     * There is a lone MU-Dedicated client
                     * which can be kicked out to join as
                     * SU-2X2
                     */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                    "There is only 1 MU-Capable client %s",
                    "which is a dedicated client.\nKick out into SU client\n");
                    war->iv_mu_timer_state = MU_TIMER_PENDING;
                    war->mu_timer_cmd = MU_CAP_TIMER_CMD_KICKOUT_DEDICATED;
                    /* enable timer in 10 seconds*/
                    OS_SET_TIMER(&war->iv_mu_cap_timer,10*1000);
                    war->modify_probe_resp_for_dedicated = 0;
                } else if (get_mu_total_clients(war) == 0) {
                    /*
                     * allow the dedicated client
                     * to join as SU-2X2 ONLY if
                     * there are ZERO MU-CAP clients associated
                     */
                    war->modify_probe_resp_for_dedicated = val;
                } else {
                    war->modify_probe_resp_for_dedicated = 0;
                }
                war->mu_cap_war = val;
                break;
            default:
                ieee80211_note(vap, IEEE80211_MSG_ASSOC, "MU CAP WAR enable/disable"
                               " set 1/0 other value will be ignored\n");
                break;
        }
        qdf_spin_unlock_bh(&war->iv_mu_cap_lock);
        break;
    }
    case IEEE80211_CONFIG_MU_CAP_TIMER:
        vap->iv_mu_cap_war.mu_cap_timer_period = val;
        break;
#endif
    case IEEE80211_CONFIG_ASSOC_DENIAL_NOTIFICATION:
        {
           if (wlan_get_acl_policy(vap, IEEE80211_ACL_FLAG_ACL_LIST_1) != IEEE80211_MACCMD_POLICY_OPEN){
               qdf_nofl_info("Config invalid when ACL policy is OPEN. Config valid only when ACL policy ACCEPT/DENY\n");
               return -EINVAL;
           } else if ((val != 0) && (val != 1)){
               qdf_nofl_info("Invalid config. Valid config are 0:Disable 1:Enable\n");
               return -EINVAL;
           } else {
               vap->iv_assoc_denial_notify = val;
           }
        }
        break;
    case IEEE80211_CONFIG_WATERMARK_THRESHOLD:
        vap->watermark_threshold = val;
        break;

    case IEEE80211_CONFIG_MON_DECODER:
        /* monitor vap decoder header type, prism=0(default), radiotap=1 */
        ic->ic_mon_decoder_type = val;
        break;

    case IEEE80211_BEACON_RATE_FOR_VAP:
        {
            uint32_t bcn_rate;

            wlan_util_vdev_mlme_get_param(vdev_mlme,
                    WLAN_MLME_CFG_BCN_TX_RATE, &bcn_rate);
            prev_val = bcn_rate;
            mlme_cfg.value = val;
            vdev_mlme_set_param(vdev_mlme,
                    WLAN_MLME_CFG_BCN_TX_RATE, mlme_cfg);

        }
        break;

    case IEEE80211_CONFIG_DISABLE_SELECTIVE_LEGACY_RATE:
        {
           /*
            * If user is trying to disable the same rates which is already configured,
            * then don't go through all the proceedings of disabling rates.
            */
            if (vap->iv_disabled_legacy_rate_set == (val & 0xFFF)) {
                qdf_print("%s : This basic rate disable mask is already configured. Please try a different value.",__func__);
                return 0;
            }

            vap->iv_disabled_legacy_rate_set = (val & 0xFFF);
            if(!val) {
                /*
                 * If iv_mgt_rate is set during vap init then VAP will use that rate as mgmt rate.
                 * When users want to enable all the rates, they need to pass 0 via iwpriv and in that case
                 * iv_mgt_rate needs to be changed to 0; so that during vap initialization it will fetch
                 * the default value i.e: 1000 kbps (2G) and 6000 kbps (5G).
                 */
                mlme_cfg.value = 0;
                vdev_mlme_set_param(vdev_mlme,
                        WLAN_MLME_CFG_TX_MGMT_RATE, mlme_cfg);
                /*
                 * Since Beacon rates are configured separately,
                 * reset beacon rate to default.
                 */
                vdev_mlme_set_param(vap->vdev_mlme,
                                    WLAN_MLME_CFG_BCN_TX_RATE,
                                    mlme_cfg);
            }
        }
        break;

    case IEEE80211_CONFIG_NSTSCAP_WAR:
        vap->iv_cfg_nstscap_war = val;
        break;

    case IEEE80211_CONFIG_CHANNEL_SWITCH_MODE:
        if (val > IEEE80211_CSA_MODE_AUTO) {
            qdf_print("Only valid values are 0, 1,"
                "2(Auto csmode)");
            return -EINVAL;
        }
        vap->iv_csmode = val;
        break;

    case IEEE80211_CONFIG_ECSA_IE:
        if (vap->iv_enable_ecsaie != !!val) {
            vap->iv_enable_ecsaie = !!val;
            vap->iv_doth_updated = true;
        }
        break;

    case IEEE80211_CONFIG_SAE_PWID:
        vap->iv_enable_sae_pwid = val;
        break;

    case IEEE80211_CONFIG_ECSA_OPCLASS:
        vap->iv_ecsa_opclass = val;
        break;

    case IEEE80211_RX_FILTER_MONITOR:

        if ((FILTER_MODE(val) >= INVALID_FILTER) ||
            (MON_FILTER_TYPE_GET(val) > MON_FILTER_TYPE_LAST)) {
            return -EINVAL;
        }
        ic->ic_os_monrxfilter = val;
        wlan_set_monitor_filter(ic, val);
        break;

    case IEEE80211_CONFIG_HE_EXTENDED_RANGE:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE Extended Range is not allowed in current mode");
            return -EINVAL;
        }
        if (val == 1 || val == 0) {
            if (vap->iv_he_extended_range != val) {
                vap->iv_he_extended_range = val;
            } else {
                qdf_print(" HE Extended range already set with this value =%d ", val);
                return EOK;
            }
        } else {
              qdf_print(" HE Extended Range setting should be 0 or 1 ");
              return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_DCM:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE Extended Range is not allowed in current mode");
            return -EINVAL;
        }
        if (val == 1 || val == 0){
            if (vap->iv_he_dcm != val) {
                vap->iv_he_dcm = val;
            } else {
                qdf_print(" HE DCM already set with this value =%d ", val);
                return EOK;
            }
        } else {
              qdf_print(" HE DCM setting should be 0 or 1 ");
              return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_FRAGMENTATION:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_err("HE Fragmentation is not allowed in current mode");
            return -EINVAL;
        }

        if (!ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_FRAGMENTATION)) {
            if (val > he_target_cap) {
                qdf_err("Invalid input - HE Fragmentation value"
                        " expected to be <= %d", he_target_cap);
                return -EINVAL;
            }
            if (vap->iv_he_frag != val) {
                vap->iv_he_frag = val;
            } else {
                qdf_info("HE Fragmentation already set with"
                         " this value =%d ", he_target_cap);
                return EOK;
            }
        } else {
            qdf_err("HE Fragmentation not supported");
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_MU_EDCA:
        if(!ieee80211vap_heallowed(vap)) {
            qdf_err("MU EDCA is not allowed in current mode");
            return -EINVAL;
        }

        if(!(vap->iv_he_ul_mumimo) && !(vap->iv_he_ul_muofdma)) {
            qdf_err("MU EDCA requires UL MU enabled."
                      "Both UL OFDMA and UL MIMO disabled.");
            return -EINVAL;
        }

        if(val > 1) {
            qdf_err("HE MU EDCA setting should be 0 or 1 ");
            return -EINVAL;
        }

        if(vap->iv_he_muedca != val) {
            vap->iv_he_muedca = val;
        }
        else {
            qdf_err("HE MU EDCA already set with this value = %d", val);
            return EOK;
        }
        break;

    case IEEE80211_CONFIG_HE_DYNAMIC_MU_EDCA:
        if(!ieee80211vap_heallowed(vap)) {
            qdf_err("Dynamic MU-EDCA is not allowed in current mode");
            return -EINVAL;
        }

        if (!vap->iv_he_muedca) {
            qdf_err("MU EDCA is disabled");
            return -EINVAL;
        }
        if (vap->iv_ic->ic_muedca_mode_state != HEMUEDCA_HOST_DYNAMIC_MODE) {
            qdf_err("Dynamic host MU-EDCA not enabled");
            return -EINVAL;
        }
        if(val > 1) {
            qdf_err("Dynamic MU-EDCA setting should be 0 or 1 ");
            return -EINVAL;
        }

        if (val != (vap->iv_muedcastate.mu_edca_dynamic_state &
                    MUEDCA_DYNAMIC_ALGO_ENABLE_STATE_MASK)) {
            if (!val)
                vap->iv_muedcastate.mu_edca_dynamic_state &= val;
            else
                vap->iv_muedcastate.mu_edca_dynamic_state |=
                (MUEDCA_DYNAMIC_ALGO_ENABLE_STATE_MASK | MUEDCA_DYNAMIC_ALGO_UPDATE_STATE_MASK);
        } else {
            qdf_err("Dynamic MU-EDCA already set with this value = %d", val);
            return EOK;
        }
        break;

    case IEEE80211_CONFIG_HE_UL_MU_MIMO:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE Ul MU MIMO is not allowed in current mode");
            return -EINVAL;
        }
        if (val == 1 || val == 0){
            if (vap->iv_he_ul_mumimo != val) {
                vap->iv_he_ul_mumimo = val;
            } else {
                qdf_print(" HE UL MU MIMO already set with this value =%d ", val);
                return EOK;
            }
        } else {
              qdf_print(" HE UL MU MIMO setting should be 0 or 1 ");
              return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_UL_MU_OFDMA:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE Ul MU OFDMA is not allowed in current mode");
            return -EINVAL;
        }
        /* Target capability flag for UL muofdma feature support */
        if (!ic->ic_he_ul_muofdma) {
            qdf_err("HE Ul MU OFDMA is not supported on this target");
            return -EINVAL;
        }
        if (val == 1 || val == 0){
            if (vap->iv_he_ul_muofdma != val) {
                vap->iv_he_ul_muofdma = val;
            } else {
                qdf_print(" HE UL MU OFDMA already set with this value =%d ", val);
                return EOK;
            }
        } else {
              qdf_print(" HE UL MU OFDMA setting should be 0 or 1 ");
              return -EINVAL;
        }

        /* Enable MU-EDCA if UL OFDMA and WMM are enabled. */
        if((vap->iv_he_ul_muofdma) && (ieee80211_vap_wme_is_set(vap))) {
           vap->iv_he_muedca = 1;
        }

        break;

    case IEEE80211_CONFIG_HE_DL_MU_OFDMA:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE DL MU OFDMA is not allowed in current mode");
            return -EINVAL;
        }
        if (val == 1 || val == 0){
            if (vap->iv_he_dl_muofdma != val) {
                vap->iv_he_dl_muofdma = val;
            } else {
                qdf_print(" HE DL MU OFDMA already set with this value =%d ", val);
                return EOK;
            }
        } else {
              qdf_print(" HE DL MU OFDMA setting should be 0 or 1 ");
              return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_DL_MU_OFDMA_BFER:
        if (!vap->iv_he_dl_muofdma)
        {
            qdf_info("HE DL MUOFDMA + TxBF is not allowed with HE DL MUOFDMA disabled");
            return -EINVAL;
        }
        if ((val == 1) || (val == 0)){
            if (vap->iv_he_dl_muofdma_bfer != val) {
                vap->iv_he_dl_muofdma_bfer = val;
            } else {
                qdf_info(" HE DL MU OFDMA + TxBF already set with this value =%d ", val);
                return EOK;
            }
        } else {
              qdf_info(" HE DL MU OFDMA + TxBF setting should be 0 or 1 ");
              return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_SU_BFEE:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE SU BFEE is not allowed in current mode");
            return -EINVAL;
        }

        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_SU_BFEE)) {
            return -EINVAL;
        }

        if (he_target_cap) {
            if (vap->iv_he_su_bfee != val) {
                vap->iv_he_su_bfee = val;
            } else {
                qdf_info("HE SU BFEE already set with this value =%d ", val);
                return EOK;
            }
        } else {
            qdf_err(" HE SU BFEE is not supported by target ");
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_SU_BFER:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_err("HE SU BFER is not allowed in current mode");
            return -EINVAL;
        }

        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_SU_BFER)) {
            return -EINVAL;
        }

        if (he_target_cap) {
            if (val == 1 || val == 0) {
                if (vap->iv_he_su_bfer != val) {
                    vap->iv_he_su_bfer = val;
                } else {
                    qdf_info("HE SU BFER already set with this value =%d ", val);
                    return EOK;
                }
            } else {
                  qdf_err("HE SU BFER setting should be 0 or 1 ");
                  return -EINVAL;
            }
        } else {
            qdf_info(" HE SU BFER setting not supported in this target ");
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_MU_BFEE:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_err("HE MU BFEE is not allowed in current mode");
            return -EINVAL;
        }

        if (val <= 1){
            if (val && !vap->iv_he_su_bfee) {
                /* SU BFEE is mandatory for MU BFEE role */
                qdf_err("HE SU BFEE not enabled. Cmd failed");
                return -EINVAL;
            }

            if (vap->iv_he_mu_bfee != val) {
                vap->iv_he_mu_bfee = val;
            } else {
                qdf_info("HE MU BFEE already set with this value =%d ", val);
                return EOK;
            }
        } else {
              qdf_err("HE MU BFEE setting should be 0 or 1 ");
              return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_MU_BFER:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE MU BFER is not allowed in current mode");
            return -EINVAL;
        }

        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_MU_BFER)) {
            return -EINVAL;
        }

        if (he_target_cap) {
            if (val == 1 || val == 0) {
                if (vap->iv_he_mu_bfer != val) {
                    vap->iv_he_mu_bfer = val;
                } else {
                    qdf_info(" HE MU BFER already set with this value =%d ", val);
                    return EOK;
                }
            } else {
                  qdf_info(" HE MU BFER setting should be 0 or 1 ");
                  return -EINVAL;
            }
        } else {
            qdf_info(" HE MU BFER setting not supported in this target ");
            return -EINVAL;
        }
    break;

    case IEEE80211_CONFIG_6G_HE_OP_MIN_RATE:
        if(!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan))
        {
            qdf_err(" 6G HE operation minimum rate is not allowed in current band ");
            return -EINVAL;
        }

        if (val >= IEEE80211_6G_HE_OP_DEFAULT_MIN_RATE  &&
            val <= IEEE80211_6G_HE_OP_DEFAULT_MIN_RATE_MAX){
            if (vap->iv_6g_he_op_min_rate != val) {
                vap->iv_6g_he_op_min_rate = val;
                update_beacon = true;
            } else {
                qdf_info(" 6G HE operation minimum rates is already set to %d ", val);
                return EOK;
            }
        } else {
              qdf_info(" 6G HE operation mininum rate should be between 1 and 206 Mbps");
              return -EINVAL;
         }
    break;

    case IEEE80211_CONFIG_EXT_NSS_SUPPORT:
        if (!ic->ic_ext_nss_capable) {
            qdf_print("Host is not EXT NSS Signaling capable");
            return -EINVAL;
        }
        if ((ic->ic_get_tgt_type(ic)) == TARGET_TYPE_QCN9000) {
            qdf_nofl_err("Target is Incapable of this config");
            return -EINVAL;
        }
        if ((val != 0) && (val != 1)) {
            qdf_print("Valid values 1:Enable 0:Disable");
            return -EINVAL;
        }
        if (val != vap->iv_ext_nss_support) {
             vap->iv_ext_nss_support = val;
        }
        break;

    case IEEE80211_CONFIG_HE_LTF:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE LTF is not allowed in current mode");
            return -EINVAL;
        }

        if (val <= IEEE80211_HE_LTF_4X) {
            vap->iv_he_ltf = val;
        } else {
            qdf_print("HE LTF value should be less"
                      " than or equal to 0x%x", IEEE80211_HE_LTF_4X);
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_AR_GI_LTF:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("Set HE AUTORATE GI LTF is not allowed in current mode");
            return -EINVAL;
        }

        if (val) {
            uint8_t he_ar_ltf;
            uint8_t he_ar_sgi;

            he_ar_ltf = (val & IEEE80211_HE_AR_LTF_MASK);
            he_ar_sgi = (val & IEEE80211_HE_AR_SGI_MASK) >> IEEE80211_HE_AR_SGI_S;

            /* he_ar_ltf == 0 is invalid value for LTF values-set bitmask
             * in WMI_VDEV_PARAM_AUTORATE_MISC_CFG. We send the saved values
             * for LTF values-set in this case.
             */
            if (he_ar_ltf) {
                vap->iv_he_ar_gi_ltf =
                   ((vap->iv_he_ar_gi_ltf & ~IEEE80211_HE_AR_LTF_MASK)
                    | he_ar_ltf);
            }

            /* he_ar_sgi == 0 is invalid value for SGI values-set bitmask
             * in WMI_VDEV_PARAM_AUTORATE_MISC_CFG. We send the saved values
             * for SGI values-set in this case.
             */
            if (he_ar_sgi) {
                vap->iv_he_ar_gi_ltf =
                   ((vap->iv_he_ar_gi_ltf & ~IEEE80211_HE_AR_SGI_MASK) |
                    (he_ar_sgi << IEEE80211_HE_AR_SGI_S));
            }

            if (!(he_ar_sgi | he_ar_ltf)) {
                qdf_print("Invalid value. AURORATE GI & LTF"
                          " values-set cannot both be 0");
                return -EINVAL;
            }
        } else {
            qdf_print("Invalid value 0 for HE AURORATE GI LTF");
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_AR_LDPC:

        if(!ieee80211vap_heallowed(vap))
        {
            qdf_err("Set HE AUTORATE LDPC is not allowed in current mode");
            return -EINVAL;
        }
        if(val > 1){
          /* Value has to be either 0 or 1 */
             qdf_err("HE AUTORATE LDPC has to be either 0 or 1");
             return -EINVAL;
        }
        vap->iv_he_ar_ldpc = val;
        break;


    case IEEE80211_CONFIG_HE_RTSTHRSHLD:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE RTSTHRSHLD is not allowed in current mode");
            return -EINVAL;
        }

        if (val <= HEOP_PARAM_RTS_THRSHLD_DURATION_DISABLED_VALUE) {
            vap->iv_he_rts_threshold = val;
        } else {
            qdf_print("HE RTSTHRSHLD value should be less"
                      " than or equal to 0x%x",
                      HEOP_PARAM_RTS_THRSHLD_DURATION_DISABLED_VALUE);
            return -EINVAL;
        }
        break;

    case IEEE80211_FEATURE_DISABLE_CABQ:
        if (val) {
            IEEE80211_VAP_NOCABQ_ENABLE(vap);
        } else {
            IEEE80211_VAP_NOCABQ_DISABLE(vap);
        }
        break;

    case IEEE80211_SUPPORT_TIMEOUTIE:
        if (val) {
            vap->iv_assoc_comeback_time = val;
        }
        else
            vap->iv_assoc_comeback_time = 0;
        break;

    case IEEE80211_SUPPORT_PMF_ASSOC:
        if (val) {
            vap->iv_skip_pmf_reassoc_to_hostap = val;
        }
        else
            vap->iv_skip_pmf_reassoc_to_hostap = 0;
        break;

    case IEEE80211_CONFIG_CSL_SUPPORT:
        if ((val < 0) || (val > 15)) {
            qdf_print("Valid values 0 to 15 [3 bit value]\n"
                     "\t'0x1' : CSL\n\t'0x2' : MLME Events\n"
                     "\t'0x4' - Reserved\n"
                     "\t'0x8' - MISC Events");
            return -EINVAL;
        }
        if (val & LOG_CSL_MISC_EVENTS) {
            qdf_print("WARN: enabling CSL MISC events will flood logs");
        }

        wlan_csl_enable(vap, val);
        break;

#ifdef WLAN_SUPPORT_FILS
    case IEEE80211_FEATURE_FILS:
        ucfg_fils_config(vap->vdev_obj, val);
        /* Enabling FILS Discovery will disable Bcast Probe response
         * transmission if it was enabled. Update the Bcast probe response
         * enable flag to reflect Bcast probe resp Tx is now disabled.
         */
        if(IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) &&
                wlan_fils_is_enable(vap->vdev_obj)) {
            vap->iv_he_6g_bcast_prob_rsp = 0;
            vap->iv_he_6g_bcast_prob_rsp_intval = 0;
            /* Update the RNR cache to reflect the 20TU Probe response enable
             * bit correctly.
             */
            ic->ic_6ghz_rnr_unsolicited_prb_resp_active = 0;
            wlan_update_6ghz_rnr_cache(vap, 0);
            wlan_tmpl_update_lower_band_vdevs(wlan_pdev_get_psoc(ic->ic_pdev_obj));
            wlan_tmpl_update_6ghz_frm();
        }
        break;
#endif /* WLAN_SUPPORT_FILS */
    case IEEE80211_CONFIG_REFUSE_ALL_ADDBAS:
        if (val > 1) {
            return -EINVAL;
        }

        vap->iv_refuse_all_addbas = val;
        break;

    case IEEE80211_CONFIG_HE_TX_MCSMAP:
        vap->iv_he_tx_mcsnssmap = val;
        break;

    case IEEE80211_CONFIG_HE_RX_MCSMAP:
        vap->iv_he_rx_mcsnssmap = val;
        break;

    case IEEE80211_CONFIG_READ_RXPREHDR:
        if ((val < 0) || (val > 1)) {
            qdf_print("Valid values 0 to 1 ");
            return -EINVAL;
        }
        vap->iv_read_rxprehdr = val;
        break;

    case IEEE80211_CONFIG_BA_BUFFER_SIZE:
        if((val >= IEEE80211_MIN_BA_BUFFER_SIZE) &&
                (val <= IEEE80211_MAX_BA_BUFFER_SIZE)) {
            vap->iv_ba_buffer_size = val;
        }
        else {
            qdf_print("BA buffer size setting should not be greater 1 ");
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_HE_SOUNDING_MODE:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_print("HE/VHT Sounding mode is not allowed in current mode");
            return -EINVAL;
        }

        /* The user set value is a four
         * bit value as per the following
         * definition
         * -----------------------
         *  bit(0)   |    mode
         * -----------------------
         *        0  |  AC
         *        1  |  AX
         * -----------------------
         *
         *  bit(1)   |  Reserved
         *
         * -----------------------
         *  bit(2)   |  mode
         * -----------------------
         *        0  |  SU
         *        1  |  MU
         * -----------------------
         *  bit(3)   |  mode
         * -----------------------
         *        0  |  non -triggered
         *        1  |  triggered
         */
        if (val > 0xf) {
            qdf_print("Invalid value for HE/VHT sounding mode");
        }

        if (vap->iv_he_sounding_mode != val) {
            vap->iv_he_sounding_mode = val;
        } else {
            qdf_print("HE/VHT sounding mode is already set with this"
                      " value =%d ", val);
            return EOK;
        }

        break;

    case IEEE80211_SUPPORT_RSN_OVERRIDE:
            vap->iv_rsn_override = val;
        break;
    case IEEE80211_CONFIG_HE_HT_CTRL:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_err("HE HT Control is not allowed in current mode");
            return -EINVAL;
        }

        if(!ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_HT_CTRL)){
            if(val <= he_target_cap){
                if (vap->iv_he_ctrl != val) {
                    vap->iv_he_ctrl = val;
                }
                else {
                    qdf_info(" HE HT Control field has already been set"
                            "with this value =%d ", he_target_cap);
                    return EOK;
                }
            }
            else {
                qdf_err("HE HT Control setting should be either"
                        " 0(Disabled) or 1(Enabled)");
                return -EINVAL;
            }
        }
        else {
            qdf_err("HE HT Control value should be less than"
                    "equal to the value supported by target =%d",
                                he_target_cap);
            return -EINVAL;
        }
        break;
    case IEEE80211_CONFIG_FT_ENABLE:
            vap->iv_roam.iv_ft_enable = val;
        break;

    case IEEE80211_CONFIG_RAWMODE_OPEN_WAR:
        if ((val < 0) || (val > 1)) {
            qdf_err("Valid values for Raw mode war: 0 or 1 ");
            return -EINVAL;
        }
        vap->iv_rawmode_open_war = val;
        break;
    case IEEE80211_CONFIG_HE_BSR_SUPPORT:
        if(!ieee80211vap_heallowed(vap))
        {
            qdf_err("HE BSR Setting is not allowed in current mode");
            return -EINVAL;
        }

        if (val <= 1){
            if (vap->iv_he_bsr_supp != val) {
                vap->iv_he_bsr_supp = val;
            } else {
                qdf_info("HE BSR setting already set with value = %d", val);
                return EOK;
            }
        } else {
              qdf_err("HE BSR setting should be 0 or 1");
              return -EINVAL;
        }
        break;
    case IEEE80211_CONFIG_MAX_MTU_SIZE:
            vap->iv_max_mtu_size = val;
        break;
    case IEEE80211_CONFIG_6GHZ_BCAST_PROB_RSP:
        if(!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
            qdf_err("Bcast Probe Response is not supported in current band!");
            return -EINVAL;
        }

        avn = OL_ATH_VAP_NET80211(vap);
        if(!avn) {
            qdf_err("Net80211 vap is NULL");
            return -EINVAL;
        }
        if (val & (1 << WLAN_BCAST_PRB_RSP_ENABLE_BIT)) {
            val &= WLAN_BCAST_PRB_RSP_PERIOD_MASK;
            if (val == 0) {
                /* Set to default if prb response intval is 0 */
                val = MIN_20TU_INTVAL;
                qdf_err("Setting interval to 20TU");
            }
            if (val > MAX_BCAST_PRB_RSP_INTVAL) {
                qdf_err("Invalid: Intval cannot be more than 32ms");
                return -EINVAL;
            }
        } else {
            val = 0;
        }

        if(val) {
            vap->iv_he_6g_bcast_prob_rsp = 1;
            vap->iv_he_6g_bcast_prob_rsp_intval = val;
            /* Allocate the buffer and initialize Probe response template */
            if(val && ic->ic_prb_rsp_tmpl_alloc) {
                ic->ic_prb_rsp_tmpl_alloc(vap);
            }

            /* Send Probe response template to FW */
            if(val &&
               ieee80211_is_vap_state_running(vap) &&
               ic->ic_prb_rsp_tmpl_send) {
                if(QDF_STATUS_SUCCESS != ic->ic_prb_rsp_tmpl_send(vap->vdev_obj)) {
                    vap->iv_he_6g_bcast_prob_rsp = 0;
                    vap->iv_he_6g_bcast_prob_rsp_intval = 0;
                    qdf_err("Bcast Probe response template send failed");
                    return -EINVAL;
                }
            }
#ifdef WLAN_SUPPORT_FILS
            /* Enabling Bcast Probe response will disable FILS Discovery
             * transmission if it was enabled. Update the FILS enable flag
             * to reflect FD Tx is now disabled.
             */
            ucfg_fils_disable(vap->vdev_obj);
#endif /* WLAN_SUPPORT_FILS */
            wlan_vdev_mlme_feat_ext_cap_clear(vap->vdev_obj,
                          WLAN_VDEV_FEXT_FILS_DISC_6G_SAP);
        } else {
            if(!vap->iv_he_6g_bcast_prob_rsp) {
                qdf_err("Bcast Probe response is already disabled");
                return -EINVAL;
            }
            vap->iv_he_6g_bcast_prob_rsp = 0;
            vap->iv_he_6g_bcast_prob_rsp_intval = val;
            ic->ic_6ghz_rnr_unsolicited_prb_resp_active = 0;
            wlan_update_6ghz_rnr_cache(vap, 0);
            wlan_tmpl_update_lower_band_vdevs(wlan_pdev_get_psoc(ic->ic_pdev_obj));
            wlan_tmpl_update_6ghz_frm();
        }
        break;
    case IEEE80211_STATS_UPDATE_PERIOD:
        if(ic->ic_set_stats_update_period) {
            retv = ic->ic_set_stats_update_period(vap, val);
        } else {
            qdf_err("cmd not supported");
            return -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_ASSOC_MIN_RSSI:
        if ((val >= IEEE80211_ASSOC_MIN_RSSI_MIN) &&
            (val <= IEEE80211_ASSOC_MIN_RSSI_MAX)) {
            vap->iv_assoc_min_rssi_thrshld = val;
        } else {
            qdf_err("Invalid value for min-rssi."
                    "Accepted range %d <= val <= %d",
                    IEEE80211_ASSOC_MIN_RSSI_MIN,
                    IEEE80211_ASSOC_MIN_RSSI_MAX);
            retv = -EINVAL;
        }
        break;

    case IEEE80211_CONFIG_ENABLE_MSCS:
        vap->iv_mscs  = val;
        update_beacon = true;
        break;

    case IEEE80211_CONFIG_6G_SECURITY_COMP:
        vap->iv_6g_comp = val;
	break;

    case IEEE80211_CONFIG_6G_KEYMGMT_MASK:
        vap->iv_keymgmt_6g_mask = val;
	break;

#if SUPPORT_11AX_D3
    case IEEE80211_CONFIG_HE_ER_SU_DISABLE:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        he_target_cap = (ic->ic_he.heop_param &
                                IEEE80211_HEOP_ER_SU_DISABLE_MASK) >>
                                IEEE80211_HEOP_ER_SU_DISABLE_S;
        if(he_target_cap) {
            qdf_err("Target does not support HE ER SU reception");
            return -EINVAL;
        }
        if (val > 1) {
            qdf_err("The user value for HE ER SU disable must be <= 1");
            return -EINVAL;
        }
        vap->iv_he_er_su_disable = val;
        update_beacon = true;
    break;
#endif /* SUPPORT_11AX_D3 */

    case IEEE80211_CONFIG_HE_1024QAM_LT242RU_RX_ENABLE:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_1024QAM_LT242RU_RX_ENABLE)) {

            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for Rx 1024-QAM < 242-tone RU Support:"
                    " %d must be <= target capability: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_1024qam_lt242ru_rx = val;
        update_beacon = true;
    break;

    case IEEE80211_CONFIG_HE_UL_MU_DATA_DIS_RX_SUPP:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_mac_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_UL_MU_DATA_DIS_RX_SUPP)) {
            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for UL MU Data Disable RX Support:"
                    " %d must be <= target capability: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_ulmu_data_disable_rx = val;
        update_beacon = true;
    break;

    case IEEE80211_CONFIG_HE_FULL_BW_UL_MUMIMO:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_FULL_BW_UL_MUMIMO)) {

            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for Full Bandwidth UL MU-MIMO:"
                    " %d must be <= target capability: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_full_bw_ulmumimo = val;
        update_beacon = true;
    break;

    case IEEE80211_CONFIG_HE_DCM_MAX_CONSTELLATION_RX:
        if (!ieee80211vap_heallowed(vap)) {
            qdf_err("HE capabilities are not allowed in Non HE mode");
            return -EINVAL;
        }
        if (ieee80211com_he_target_supports_phy_cap(ic, &he_target_cap,
                                IEEE80211_CONFIG_HE_DCM_MAX_CONSTELLATION_RX)) {

            return -EINVAL;
        }
        if (val > he_target_cap) {
            qdf_err("The user value for DCM Max Constellation Rx:"
                    " %d must be <= target capability: %d", val, he_target_cap);
            return -EINVAL;
        }
        vap->iv_he_dcm_max_cons_rx = val;
        update_beacon = true;
    break;

    case IEEE80211_CONFIG_DISABLE_INACT_PROBING:
        if (ic->ic_get_tgt_type(ic) < TARGET_TYPE_QCA8074) {
            qdf_err("Disable FW Inactivity Probing supported only for Lithium targets");
            return -EINVAL;
        }
        if (val > 1) {
            qdf_err("Disable FW Inactivity Probing setting should be 0 or 1");
            return -EINVAL;
        }
        if (vap->iv_disable_inact_probe == val) {
            qdf_err("Disable FW Inactivity Probing already set to %d", val);
            return -EINVAL;
        } else {
            vap->iv_disable_inact_probe = val;
            /* To disable FW probing MAX_UNRESPONSIVE_TIME and
             * MAX_INACTIVITY_TIME should be set to the same value.
             * If Max BSS Idle Time feature is enabled, use the Max
             * BSS Idle time setting to update to FW, else use the
             * Inactivity timer setting.
             */
            if (ieee80211_vap_wnm_is_set(vap) && (vap->wnm) &&
                    (ieee80211_wnm_bss_is_set(vap->wnm))) {
                inact_period = vap->wnm->wnm_bss_max_idle_period;
            } else {
                wlan_util_vdev_mlme_get_param(vdev_mlme,
                    WLAN_MLME_CFG_MAX_UNRESPONSIVE_INACTIVE_TIME, &inact_period);
            }
            retv = wlan_set_run_inact_timeout(vdev_mlme, inact_period, val);
        }
    break;
    case IEEE80211_CONFIG_AP_MAX_AUTH_FAIL:
        vap->max_cont_auth_fail = val;
    break;

    default:
        break;
    }

    if (ic->ic_vap_set_param) {
        retv = ic->ic_vap_set_param(vap,param, val);
        /*
         * In case of failure restore the previous value, if the VAP was up.
         * If the VAP is not yet up these params will be restored after VAP up.
         * at the end of osif_vap_init function.
         */
        is_up = (wlan_vdev_mlme_is_active(vap->vdev_obj) == QDF_STATUS_SUCCESS);
        if (EOK != retv && is_up) {
            switch (param) {
                case IEEE80211_MCAST_RATE:
                    vap->iv_mcast_fixedrate = prev_val;
                    break;
                case IEEE80211_BCAST_RATE:
                    vap->iv_bcast_fixedrate = prev_val;
                    break;
                case IEEE80211_BEACON_RATE_FOR_VAP:
                    qdf_print("%s : This rate is not allowed. Please try a valid rate.",__func__);
                    mlme_cfg.value = prev_val;
                    vdev_mlme_set_param(vdev_mlme,
                            WLAN_MLME_CFG_BCN_TX_RATE, mlme_cfg);
                    break;
                default:
                    break;
            }
        }
    }

    if (update_beacon)
        wlan_vdev_beacon_update(vap);

    return retv;
}

void wlan_clear_sta_snr(void *arg, wlan_node_t node)
{
    node->ni_snr_min = node->ni_snr;
    node->ni_snr_max = node->ni_snr;
}

void ieee80211_clear_min_max_snr(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    wlan_iterate_station_list(vap, wlan_clear_sta_snr, NULL);
}

u_int32_t
wlan_get_param(wlan_if_t vaphandle, ieee80211_param param)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct wlan_objmgr_pdev *pdev;
    struct wlan_objmgr_psoc *psoc;
    struct wlan_lmac_if_reg_rx_ops *reg_rx_ops;
    u_int32_t val = 0;
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    ol_txrx_soc_handle soc;

    pdev = ic->ic_pdev_obj;

    switch (param) {
    case IEEE80211_AUTO_ASSOC:
        val = IEEE80211_VAP_IS_AUTOASSOC_ENABLED(vap) ? 1 : 0;
        break;

    case IEEE80211_GET_OPMODE:
        val = vap->iv_opmode;
        break;

    case IEEE80211_SAFE_MODE:
        val = IEEE80211_VAP_IS_SAFEMODE_ENABLED(vap) ? 1 : 0;
        break;

    case IEEE80211_SEND_80211:
        val = IEEE80211_VAP_IS_SEND_80211_ENABLED(vap) ? 1 : 0;
        break;

    case IEEE80211_RECEIVE_80211:
        val = IEEE80211_VAP_IS_DELIVER_80211_ENABLED(vap) ? 1 : 0;
        break;

    case IEEE80211_FEATURE_DROP_UNENC:
        val = IEEE80211_VAP_IS_DROP_UNENC(vap) ? 1 : 0;
        break;

    case IEEE80211_CONFIG_CAPTURE_LATENCY_ENABLE:
        val = ic->ic_capture_latency ? 1 : 0;
        break;
    case IEEE80211_SHORT_PREAMBLE:
        val = IEEE80211_IS_CAP_SHPREAMBLE_ENABLED(ic) ? 1 : 0;
        break;

    case IEEE80211_SHORT_SLOT:
        val = IEEE80211_IS_SHSLOT_ENABLED(ic) ? 1 : 0;
        break;

    case IEEE80211_RTS_THRESHOLD:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_RTS_THRESHOLD, &val);
        break;

    case IEEE80211_FRAG_THRESHOLD:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_FRAG_THRESHOLD, &val);
        break;

    case IEEE80211_BEACON_INTVAL:
        if (vap->iv_opmode == IEEE80211_M_STA) {
            if (vap->iv_bss)
                val = vap->iv_bss->ni_intval;
        } else {
            if ((vap->iv_bss) && (vap->iv_create_flags & IEEE80211_LP_IOT_VAP))
                val = vap->iv_bss->ni_intval;
            else
                val = ic->ic_intval;
        }
        break;

#if ATH_SUPPORT_AP_WDS_COMBO
    case IEEE80211_NO_BEACON:
        val = vap->iv_no_beacon;
        break;
#endif

    case IEEE80211_LISTEN_INTVAL:
        val = ic->ic_lintval;
        break;

    case IEEE80211_DTIM_INTVAL:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_DTIM_PERIOD, &val);
        break;

    case IEEE80211_BMISS_COUNT_RESET:
        val = vap->iv_bmiss_count_for_reset ;
        break;

    case IEEE80211_BMISS_COUNT_MAX:
        val = vap->iv_bmiss_count_max;
        break;

    case IEEE80211_ATIM_WINDOW:
        val = vap->iv_atim_window;
        break;

    case IEEE80211_TXPOWER:
        /*
         * here we'd better return ni_txpower for it's more accurate to
         * current txpower and it must be less than or equal to
         * ic_txpowlimit/ic_curchanmaxpwr, and it's in 0.5 dbm.
         * This value is updated when channel is changed or setTxPowerLimit
         * is called.
         */
        if (vap->iv_bss)
            val = vap->iv_bss->ni_txpower;
        break;

    case IEEE80211_MULTI_DOMAIN:
        val = ic->ic_multiDomainEnabled;
        break;

    case IEEE80211_FEATURE_WMM:
        val = ieee80211_vap_wme_is_set(vap) ? 1 : 0;
        break;

    case IEEE80211_FEATURE_PRIVACY:
        val =  IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) ? 1 : 0;
        break;

    case IEEE80211_FEATURE_WMM_PWRSAVE:
        val = ieee80211_get_wmm_power_save(vap) ? 1 : 0;
        break;

    case IEEE80211_FEATURE_UAPSD:
        if (vap->iv_opmode == IEEE80211_M_STA) {
            val = ieee80211_get_uapsd_flags(vap);
        }
        else {
            val = IEEE80211_VAP_IS_UAPSD_ENABLED(vap) ? 1 : 0;
        }
        break;
    case IEEE80211_FEATURE_IC_COUNTRY_IE:
	val = (IEEE80211_IS_COUNTRYIE_ENABLED(ic) != 0);
        break;
    case IEEE80211_PERSTA_KEYTABLE_SIZE:
        /*
         * XXX: We should return the number of key tables (each table has 4 key slots),
         * not the actual number of key slots. Use the node hash table size as an estimation
         * of max supported ad-hoc stations.
         */
        val = IEEE80211_NODE_HASHSIZE;
        break;

    case IEEE80211_WPS_MODE:
        val = vap->iv_wps_mode;
        break;

    case IEEE80211_MIN_BEACON_COUNT:
    case IEEE80211_IDLE_TIME:
        break;
    case IEEE80211_FEATURE_COUNTER_MEASURES:
        val = IEEE80211_VAP_IS_COUNTERM_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_WDS:
        val = IEEE80211_VAP_IS_WDS_ENABLED(vap) ? 1 : 0;
        if (val == 0) {
            val = dp_is_extap_enabled(vdev);
        }
        break;
#if WDS_VENDOR_EXTENSION
    case IEEE80211_WDS_RX_POLICY:
        val = vap->iv_wds_rx_policy;
        break;
#endif

    case IEEE80211_FEATURE_VAP_ENHIND:
        val =  ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic) ? 1 :0;
        break;

    case IEEE80211_FEATURE_HIDE_SSID:
        val = IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_PUREG:
        val = IEEE80211_VAP_IS_PUREG_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_PURE11N:
        val = IEEE80211_VAP_IS_PURE11N_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_PURE11AC:
        val = IEEE80211_VAP_IS_PURE11AC_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_STRICT_BW:
        val = IEEE80211_VAP_IS_STRICT_BW_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_BACKHAUL:
        val = IEEE80211_VAP_IS_BACKHAUL_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_APBRIDGE:
        val = IEEE80211_VAP_IS_NOBRIDGE_ENABLED(vap) ? 0 : 1;
        break;
     case  IEEE80211_FEATURE_PSPOLL:
         val = wlan_sta_power_get_pspoll(vap);
         break;

    case IEEE80211_FEATURE_CONTINUE_PSPOLL_FOR_MOREDATA:
         if (wlan_sta_power_get_pspoll_moredata_handling(vap) ==
             IEEE80211_CONTINUE_PSPOLL_FOR_MORE_DATA ) {
             val = true;
         } else {
             val = false;
         }
         break;
    case IEEE80211_MCAST_RATE:
        val = vap->iv_mcast_fixedrate;
        break;
    case IEEE80211_BCAST_RATE:
        val = vap->iv_bcast_fixedrate;
        break;
    case IEEE80211_HT40_INTOLERANT:
        val = vap->iv_ht40_intolerant;
        break;
    case IEEE80211_MAX_AMPDU:
        val = ic->ic_maxampdu;
        break;
    case IEEE80211_VHT_MAX_AMPDU:
        val = ((ic->ic_vhtcap & IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP) >>
                IEEE80211_VHTCAP_MAX_AMPDU_LEN_EXP_S);
        break;
    case IEEE80211_CHWIDTH:
        /*
        ** If the VAP parameter for chwidth is set, use that value, else
        ** return the chwidth based on current channel characteristics.
        */
        if (vap->iv_chwidth != IEEE80211_CWM_WIDTHINVALID) {
            val = vap->iv_chwidth;
        } else {
            val = ic->ic_cwm_get_width(ic);
        }
        break;
    case IEEE80211_CHEXTOFFSET:
        /*
        ** Extension channel is set through the channel mode selected by AP.  When configured
        ** through this interface, it's stored in the ic.
        */
        val = ic->ic_cwm_get_extoffset(ic);
        break;
    case IEEE80211_DISABLE_HTPROTECTION:
        val = vap->iv_disable_HTProtection;
        break;
#ifdef ATH_SUPPORT_QUICK_KICKOUT
    case IEEE80211_STA_QUICKKICKOUT:
        val = vap->iv_sko_th;
        break;
#endif
    case IEEE80211_CHSCANINIT:
        val = vap->iv_chscaninit;
        break;
    case IEEE80211_FEATURE_STAFWD:
        val = ieee80211_vap_sta_fwd_is_set(vap) ? 1 : 0;
        break;
     case IEEE80211_DYN_BW_RTS:
         val = vap->dyn_bw_rts;
         break;
    case IEEE80211_DRIVER_CAPS:
        val = vap->iv_caps;
        break;
    case IEEE80211_FEATURE_COUNTRY_IE:
        val = ieee80211_vap_country_ie_is_set(vap) ? 1 : 0;
        break;
    case IEEE80211_FEATURE_DOTH:
        val = ieee80211_vap_doth_is_set(vap) ? 1 : 0;
        break;
#if ATH_SUPPORT_IQUE
    case IEEE80211_IQUE_CONFIG:
        ic->ic_get_iqueconfig(ic);
        break;
    case IEEE80211_ME:
            soc = wlan_psoc_get_dp_handle(wlan_vdev_get_psoc(vap->vdev_obj));
            val = dp_get_me_mode(soc, wlan_vdev_get_id(vap->vdev_obj));
        break;
    case IEEE80211_IGMP_ME:
        val = ic->ic_vap_get_param(vap, IEEE80211_IGMP_ME);
        break;
#endif
    case IEEE80211_QBSS_LOAD:
        val = ieee80211_vap_qbssload_is_set(vap);
        break;
#if ATH_SUPPORT_HS20
    case IEEE80211_HC_BSSLOAD:
        val = vap->iv_hc_bssload;
        break;
#endif
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    case IEEE80211_CHAN_UTIL_ENAB:
        val = vap->iv_chanutil_enab;
        break;
    case IEEE80211_CHAN_UTIL:
        /* Calculate the percentage */
        val = (vap->chanutil_info.value * 100)/255;
        break;
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
#if UMAC_SUPPORT_XBSSLOAD
    case IEEE80211_XBSS_LOAD:
        val = ieee80211_vap_ext_bssload_is_set(vap);
        break;
#endif
#if ATH_SUPPORT_MBO
    case IEEE80211_MBO:
        val = wlan_get_mbo_param(vap,IEEE80211_MBO);
        break;
    case IEEE80211_MBOCAP:
        val = wlan_get_mbo_param(vap,IEEE80211_MBOCAP);
        break;
    case IEEE80211_MBO_ASSOC_DISALLOW:
        val = wlan_get_mbo_param(vap,IEEE80211_MBO_ASSOC_DISALLOW);
        break;
    case IEEE80211_MBO_CELLULAR_PREFERENCE:
        val = wlan_get_mbo_param(vap,IEEE80211_MBO_CELLULAR_PREFERENCE);
        break;
    case IEEE80211_MBO_TRANSITION_REASON:
        val  = wlan_get_mbo_param(vap,IEEE80211_MBO_TRANSITION_REASON);
        break;
    case IEEE80211_MBO_ASSOC_RETRY_DELAY:
        val  = wlan_get_mbo_param(vap,IEEE80211_MBO_ASSOC_RETRY_DELAY);
        break;
    case IEEE80211_OCE:
         val = wlan_get_oce_param(vap, IEEE80211_OCE);
         break;
    case IEEE80211_OCE_ASSOC_REJECT:
         val = wlan_get_oce_param(vap, IEEE80211_OCE_ASSOC_REJECT);
         break;
    case IEEE80211_OCE_ASSOC_MIN_RSSI:
         val = wlan_get_oce_param(vap, IEEE80211_OCE_ASSOC_MIN_RSSI);
         break;
    case IEEE80211_OCE_ASSOC_RETRY_DELAY:
         val = wlan_get_oce_param(vap, IEEE80211_OCE_ASSOC_RETRY_DELAY);
         break;
    case IEEE80211_OCE_WAN_METRICS:
         val = wlan_get_oce_param(vap, IEEE80211_OCE_WAN_METRICS);
         break;
    case IEEE80211_OCE_HLP:
         val = wlan_get_oce_param(vap, IEEE80211_OCE_HLP);
         break;
    case IEEE80211_OCE_VERSION_OVERRIDE:
         val = wlan_get_oce_param(vap, IEEE80211_OCE_VERSION_OVERRIDE);
         break;
#endif
    case IEEE80211_RRM_CAP:
        val = ieee80211_vap_rrm_is_set(vap);
        break;
    case IEEE80211_RRM_DEBUG:
        val = ieee80211_rrmdbg_get(vap);
        break;
    case IEEE80211_RRM_SLWINDOW:
        val = ieee80211_rrm_get_slwindow(vap);
        break;
    case IEEE80211_RRM_STATS:
        val = ieee80211_get_rrmstats(vap);
        break;
    case IEEE80211_WNM_STATS:
        val = ieee80211_get_wnmstats(vap);
        break;
    case IEEE80211_RRM_CAP_IE:
        if (vap->iv_opmode == IEEE80211_M_STA)
            val = vap->iv_rrm_cap_ie;
        else
            qdf_err("Cammad applicable only for STA mode VAP!\n");
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_WNM_CAP:
        val = ieee80211_vap_wnm_is_set(vap);
        break;
    case IEEE80211_WNM_BSS_CAP:
        val = ieee80211_wnm_bss_is_set(vap->wnm);
        break;
    case IEEE80211_WNM_TFS_CAP:
        val = ieee80211_wnm_tfs_is_set(vap->wnm);
        break;
    case IEEE80211_WNM_TIM_CAP:
        val = ieee80211_wnm_tim_is_set(vap->wnm);
        break;
    case IEEE80211_WNM_SLEEP_CAP:
        val = ieee80211_wnm_sleep_is_set(vap->wnm);
        break;
    case IEEE80211_WNM_FMS_CAP:
        val = ieee80211_wnm_fms_is_set(vap->wnm);
        break;
#endif
    case IEEE80211_FWD_ACTION_FRAMES_TO_APP:
        val = vap->iv_fwd_action_frames_to_app;
        break;
    case IEEE80211_SHORT_GI:
       if ((!ieee80211_is_phymode_auto(vap->iv_des_mode) &&
            !ieee80211_is_phymode_11ax(vap->iv_des_mode)) ||
           (!ieee80211_is_phymode_auto(vap->iv_cur_mode) &&
            !ieee80211_is_phymode_11ax(vap->iv_cur_mode)))
           val = vap->iv_data_sgi;
        else
           val = vap->iv_he_data_sgi;
        break;
    case IEEE80211_FIXED_RATE:
        val = vap->iv_fixed_rateset;
        break;
    case IEEE80211_FIXED_RETRIES:
        val = vap->iv_fixed_retryset;
        break;
    case IEEE80211_WEP_MBSSID:
        val = vap->iv_wep_mbssid;
        break;
    case IEEE80211_MGMT_RATE:
    case IEEE80211_RTSCTS_RATE:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_TX_MGMT_RATE, &val);
        break;
    case IEEE80211_NON_BASIC_RTSCTS_RATE:
        wlan_util_vdev_mlme_get_param(vdev_mlme, WLAN_MLME_CFG_TX_RTSCTS_RATE,
                                      &val);
        break;
    case IEEE80211_PRB_RATE:
        val = vap->iv_prb_rate;
        break;

    case IEEE80211_PRB_RETRY:
        val = vap->iv_prb_retry;
        break;

    case IEEE80211_MIN_FRAMESIZE:
        val = ic->ic_minframesize;
        break;
    case IEEE80211_RESMGR_VAP_AIR_TIME_LIMIT:
        val = ieee80211_resmgr_off_chan_sched_get_air_time_limit(ic->ic_resmgr, vap);
        break;
    case IEEE80211_PROTECTION_MODE:
        val = vap->iv_protmode;
		break;

    case IEEE80211_COMP:
        val = (vap->iv_ath_cap & IEEE80211_ATHC_COMP) != 0;
        break;
    case IEEE80211_FF:
        val = (vap->iv_ath_cap & IEEE80211_ATHC_FF) != 0;
        break;
    case IEEE80211_TURBO:
        val = (vap->iv_ath_cap & IEEE80211_ATHC_TURBOP) != 0;
        break;
    case IEEE80211_BURST:
        val = (vap->iv_ath_cap & IEEE80211_ATHC_BURST) != 0;
        break;
    case IEEE80211_AR:
        val = (vap->iv_ath_cap & IEEE80211_ATHC_AR) != 0;
        break;
	case IEEE80211_SLEEP:
        val = (vap->iv_bss) ? (vap->iv_bss->ni_flags & IEEE80211_NODE_PWR_MGT) : 0;
		break;
	case IEEE80211_EOSPDROP:
		val = IEEE80211_VAP_IS_EOSPDROP_ENABLED(vap) != 0;
		break;
	case IEEE80211_MARKDFS:
        val = (ic->ic_flags_ext & IEEE80211_FEXT_MARKDFS) != 0;
		break;
	case IEEE80211_DFSDOMAIN:
        if(pdev == NULL) {
            qdf_print("%s : pdev is null", __func__);
            return val;
        }

        psoc = wlan_pdev_get_psoc(pdev);
        if (psoc == NULL) {
            qdf_print("%s : psoc is null", __func__);
            return val;
        }

        reg_rx_ops = wlan_lmac_if_get_reg_rx_ops(psoc);
        if (!reg_rx_ops)
            return val;

        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_REGULATORY_SB_ID) !=
                QDF_STATUS_SUCCESS) {
            return val;
        }
        reg_rx_ops->get_dfs_region(pdev, &val);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_REGULATORY_SB_ID);
        break;
	case IEEE80211_WDS_AUTODETECT:
        val = IEEE80211_VAP_IS_WDS_AUTODETECT_ENABLED(vap) != 0;
		break;
	case IEEE80211_WEP_TKIP_HT:
		val = ieee80211_ic_wep_tkip_htrate_is_set(ic);
		break;
	case IEEE80211_ATH_RADIO:
        /*
        ** Extract the radio name from the ATH device object
        */
        //qdf_nofl_info("IC Name: %s\n",ic->ic_osdev->name);
        //val = ic->ic_dev->name[4] - 0x30;
		break;
	case IEEE80211_IGNORE_11DBEACON:
		val = IEEE80211_IS_11D_BEACON_IGNORED(ic) != 0;
		break;
        case IEEE80211_FEATURE_MFP_TEST:
            val = ieee80211_vap_mfp_test_is_set(vap) ? 1 : 0;
            break;
    case IEEE80211_TRIGGER_MLME_RESP:
        val = ieee80211_vap_trigger_mlme_resp_is_set(vap);
        break;
    case IEEE80211_AUTH_INACT_TIMEOUT:
        val = vap->iv_inact_auth * IEEE80211_INACT_WAIT;
        break;

    case IEEE80211_INIT_INACT_TIMEOUT:
        val = vap->iv_inact_init * IEEE80211_INACT_WAIT;
        break;

    case IEEE80211_RUN_INACT_TIMEOUT:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_MAX_UNRESPONSIVE_INACTIVE_TIME,
                &val);
        if(!wlan_get_HWcapabilities(ic,IEEE80211_CAP_PERF_PWR_OFLD)) {
                val *= IEEE80211_INACT_WAIT;
        }
        break;

    case IEEE80211_PROBE_INACT_TIMEOUT:
        val = vap->iv_inact_probe * IEEE80211_INACT_WAIT;
        break;

    case IEEE80211_SESSION_TIMEOUT:
        val = vap->iv_session * IEEE80211_SESSION_WAIT;
        break;

#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_TXBF_AUTO_CVUPDATE:
        val = vap->iv_autocvupdate;
        break;
    case IEEE80211_TXBF_CVUPDATE_PER:
        val = vap->iv_cvupdateper;
        break;
#endif
    case IEEE80211_WEATHER_RADAR:
        val = ic->ic_no_weather_radar_chan;
        break;

    case IEEE80211_WEP_KEYCACHE:
        val = vap->iv_wep_keycache;
        break;
    case IEEE80211_SMARTNET:
        val = ieee80211_vap_smartnet_enable_is_set(vap) ? 1 : 0;
        break;
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
   case IEEE80211_REJOINT_ATTEMP_TIME:
        val = vap->iv_rejoint_attemp_time;
        break;
#endif
   case IEEE80211_SEND_DEAUTH:
        val = vap->iv_send_deauth;
        break;
#if UMAC_SUPPORT_PROXY_ARP
    case IEEE80211_PROXYARP_CAP:
        val = ieee80211_vap_proxyarp_is_set(vap);
        break;
#if UMAC_SUPPORT_DGAF_DISABLE
    case IEEE80211_DGAF_DISABLE:
        val = ieee80211_vap_dgaf_disable_is_set(vap);
        break;
#endif
#endif
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    case IEEE80211_NOPBN:
        val = ieee80211_vap_nopbn_is_set(vap);
        break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
	case IEEE80211_DSCP_MAP_ID:
	val = vap->iv_dscp_map_id;
	break;
#endif

    case IEEE80211_EXT_ACS_IN_PROGRESS:
        val = ieee80211_vap_ext_acs_inprogress_is_set(vap);
        break;

    case IEEE80211_SEND_ADDITIONAL_IES:
        val = ieee80211_vap_send_additional_ies_is_set(vap);
        break;

    case IEEE80211_DESIRED_CHANNEL:
        {
            wlan_chan_t chan;
            chan = wlan_get_des_channel(vap);
            if (!chan || chan == IEEE80211_CHAN_ANYC) {
                val = 0;
            } else {
                val = wlan_channel_frequency(chan);
            }
        }
        break;

    case IEEE80211_DESIRED_PHYMODE:
        val = wlan_get_desired_phymode(vap);
        break;

    case IEEE80211_FIXED_VHT_MCS:
         if (vap->iv_fixed_rate.mode  == IEEE80211_FIXED_RATE_VHT) {
             val = vap->iv_vht_fixed_mcs;
         }
    break;

    case IEEE80211_FIXED_HE_MCS:
         if (vap->iv_fixed_rate.mode  == IEEE80211_FIXED_RATE_HE) {
             val = vap->iv_he_fixed_mcs;
         }
    break;

    case IEEE80211_CONFIG_HE_MULTI_TID_AGGR:
        val = vap->iv_he_multi_tid_aggr;
    break;

    case IEEE80211_CONFIG_HE_MULTI_TID_AGGR_TX:
        val = vap->iv_he_multi_tid_aggr_tx;
    break;

    case IEEE80211_CONFIG_HE_MAX_AMPDU_LEN_EXP:
        val = vap->iv_he_max_ampdu_len_exp;
    break;

    case IEEE80211_CONFIG_HE_SU_PPDU_1X_LTF_800NS_GI:
        val = vap->iv_he_su_ppdu_1x_ltf_800ns_gi;
    break;

    case IEEE80211_CONFIG_HE_SU_MU_PPDU_4X_LTF_800NS_GI:
        val = vap->iv_he_su_mu_ppdu_4x_ltf_800ns_gi;
    break;

    case IEEE80211_CONFIG_HE_MIN_FRAG_SIZE:
        val = vap->iv_he_min_frag_size;
    break;

    case IEEE80211_CONFIG_HE_MAX_FRAG_MSDU:
        val = vap->iv_he_max_frag_msdu;
    break;

    case IEEE80211_CONFIG_HE_OMI:
        val = vap->iv_he_omi;
    break;

    case IEEE80211_CONFIG_HE_NDP_4X_LTF_3200NS_GI:
        val = vap->iv_he_ndp_4x_ltf_3200ns_gi;
    break;

    case IEEE80211_CONFIG_HE_ER_SU_PPDU_1X_LTF_800NS_GI:
        val = vap->iv_he_er_su_ppdu_1x_ltf_800ns_gi;
    break;

    case IEEE80211_CONFIG_HE_ER_SU_PPDU_4X_LTF_800NS_GI:
        val = vap->iv_he_er_su_ppdu_4x_ltf_800ns_gi;
    break;

    case IEEE80211_FIXED_NSS:
         wlan_util_vdev_mlme_get_param(vdev_mlme,
                 WLAN_MLME_CFG_NSS, &val);
    break;

    case IEEE80211_SUPPORT_LDPC:
         wlan_util_vdev_mlme_get_param(vdev_mlme,
                 WLAN_MLME_CFG_LDPC, &val);
    break;

    case IEEE80211_SUPPORT_TX_STBC:
         val = vap->iv_tx_stbc;
    break;

    case IEEE80211_SUPPORT_RX_STBC:
         val = vap->iv_rx_stbc;
    break;

    case IEEE80211_CONFIG_HE_UL_SHORTGI:
        val = vap->iv_he_ul_sgi;
    break;

    case IEEE80211_CONFIG_HE_UL_LTF:
        val = vap->iv_he_ul_ltf;
    break;

    case IEEE80211_CONFIG_HE_UL_NSS:
        val = vap->iv_he_ul_nss;
    break;

    case IEEE80211_CONFIG_HE_UL_PPDU_BW:
        val = vap->iv_he_ul_ppdu_bw;
    break;

    case IEEE80211_CONFIG_HE_UL_LDPC:
        val = vap->iv_he_ul_ldpc;
    break;

    case IEEE80211_CONFIG_HE_UL_STBC:
        val = vap->iv_he_ul_stbc;
    break;

    case IEEE80211_CONFIG_HE_UL_FIXED_RATE:
        val = vap->iv_he_ul_fixed_rate;
    break;

    case IEEE80211_OPMODE_NOTIFY_ENABLE:
         val = vap->iv_opmode_notify;
    break;

    case IEEE80211_ENABLE_RTSCTS:
         val = vap->iv_rtscts_enabled;
    break;

    case IEEE80211_RC_NUM_RETRIES:
        val = vap->iv_rc_num_retries;
    break;

    case IEEE80211_VHT_TX_MCSMAP:
         val = vap->iv_vht_tx_mcsmap;
    break;
    case IEEE80211_VHT_RX_MCSMAP:
         val = vap->iv_vht_rx_mcsmap;
    break;
    case IEEE80211_START_ACS_REPORT:
        wlan_acs_start_scan_report(vap, false, param, (void *)&val);
    break;
    case IEEE80211_MIN_DWELL_ACS_REPORT:
        wlan_acs_start_scan_report(vap, false, param, (void *)&val);
    break;
    case IEEE80211_MAX_DWELL_ACS_REPORT:
        wlan_acs_start_scan_report(vap, false, param, (void *)&val);
    break;
    case IEEE80211_MAX_SCAN_TIME_ACS_REPORT:
        wlan_acs_start_scan_report(vap, false, param, (void *)&val);
    break;
    case IEEE80211_256QAM:
        val = ieee80211_vap_256qam_is_set(vap);
    break;
    case IEEE80211_11NG_VHT_INTEROP:
        val = ieee80211_vap_11ng_vht_interop_is_set(vap);
    break;
    case IEEE80211_ACS_CH_HOP_LONG_DUR:
    case IEEE80211_ACS_CH_HOP_NO_HOP_DUR:
    case IEEE80211_ACS_CH_HOP_CNT_WIN_DUR:
    case IEEE80211_ACS_CH_HOP_NOISE_TH:
    case IEEE80211_ACS_CH_HOP_CNT_TH:
    case IEEE80211_ACS_ENABLE_CH_HOP:
	    wlan_acs_param_ch_hopping(vaphandle, false, param, &val);
    break;
    case IEEE80211_MAX_SCANENTRY:
        val = wlan_scan_get_maxentry(vap->iv_ic);
        break;
    case IEEE80211_SCANENTRY_TIMEOUT:
        val = wlan_scan_get_timeout(vap->iv_ic);
        break;

    case IEEE80211_GET_ACS_STATE:
        val = wlan_autoselect_in_progress(vap);
        break;

    case IEEE80211_GET_CAC_STATE:
        if(wlan_vdev_mlme_get_state(vap->vdev_obj) == WLAN_VDEV_S_DFS_CAC_WAIT)
            val = 1;
        else
            val = 0;
        break;

    case IEEE80211_SCAN_MAX_DWELL:
        val = vap->max_dwell_time_passive;
        break;
    case IEEE80211_SCAN_MIN_DWELL:
        val = vap->min_dwell_time_passive;
        break;
#if QCA_LTEU_SUPPORT
    case IEEE80211_SCAN_REPEAT_PROBE_TIME:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_REPEAT_PROBE_TIME,
                &val);
        break;
    case IEEE80211_SCAN_REST_TIME:
        val = vap->scan_rest_time;
        break;
    case IEEE80211_SCAN_IDLE_TIME:
        val = vap->scan_idle_time;
        break;
    case IEEE80211_SCAN_PROBE_DELAY:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_PROBE_DELAY,
                &val);
        break;
    case IEEE80211_SCAN_PROBE_SPACE_INTERVAL:
        val = vap->scan_probe_spacing_interval;
        break;
    case IEEE80211_MU_DELAY:
        val = vap->mu_start_delay;
        break;
    case IEEE80211_WIFI_TX_POWER:
        val = vap->wifi_tx_power;
        break;
#endif
    case IEEE80211_VHT_SGIMASK:
         val = vap->iv_vht_sgimask;
        break;
    case IEEE80211_VHT80_RATEMASK:
         val = vap->iv_vht80_ratemask;
        break;

    case IEEE80211_SUPPORT_IMPLICITBF:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_IMLICIT_BF, &val);
        break;

    case IEEE80211_VHT_SUBFEE:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_SUBFEE, &val);
        break;

    case IEEE80211_VHT_MUBFEE:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_MUBFEE, &val);
        break;

    case IEEE80211_VHT_SUBFER:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_SUBFER, &val);
        break;

    case IEEE80211_VHT_MUBFER:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_MUBFER, &val);
        break;

    case IEEE80211_VHT_BF_STS_CAP:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_BFEE_STS_CAP, &val);
        break;

    case IEEE80211_VHT_BF_SOUNDING_DIM:
        wlan_util_vdev_mlme_get_param(vdev_mlme,
                WLAN_MLME_CFG_SOUNDING_DIM, &val);
        val = val < (ieee80211_get_txstreams(ic, vap) - 1) ?
                val : ieee80211_get_txstreams(ic, vap) - 1;
        break;

    case IEEE80211_CONFIG_MCAST_RC_STALE_PERIOD:
        val = vap->iv_mcast_rc_stale_period;
        break;

    case IEEE80211_CONFIG_ENABLE_MCAST_RC:
        val = vap->iv_enable_mcast_rc;
        break;

    case IEEE80211_CONFIG_VHT_MCS_10_11_SUPP:
        val = vap->iv_vht_mcs10_11_supp;
        break;

    case IEEE80211_CONFIG_HE_MCS_12_13_SUPP:
        val = vap->iv_he_mcs12_13_supp;
        break;

    case IEEE80211_CONFIG_VHT_MCS_10_11_NQ2Q_PEER_SUPP:
        val = vap->iv_vht_mcs10_11_nq2q_peer_supp;
        break;

#if ATH_PERF_PWR_OFFLOAD
    case IEEE80211_VAP_TX_ENCAP_TYPE:
        val = vap->iv_tx_encap_type;
        break;

    case IEEE80211_VAP_RX_DECAP_TYPE:
        val = vap->iv_rx_decap_type;
        break;

#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_RAWMODE_SIM_TXAGGR:
        val = vap->iv_rawmodesim_txaggr;
        break;

    case IEEE80211_RAWMODE_PKT_SIM_STATS:
        ic->ic_vap_get_param(vap, IEEE80211_RAWMODE_PKT_SIM_STATS);
        val = 0;
        break;

    case IEEE80211_RAWMODE_SIM_DEBUG_LEVEL:
        val = vap->iv_rawmodesim_debug_level;
        break;

    case IEEE80211_RAWSIM_DEBUG_NUM_ENCAP_FRAMES:
        val = vap->iv_num_encap_frames;
        break;

    case IEEE80211_RAWSIM_DEBUG_NUM_DECAP_FRAMES:
        val = vap->iv_num_decap_frames;
        break;

#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
#endif /* ATH_PERF_PWR_OFFLOAD */
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_VAP_DSCP_PRIORITY:
        val = vap->iv_vap_dscp_priority;
        break;
#endif
    case IEEE80211_SMART_MESH_CONFIG:
        val = vap->iv_smart_mesh_cfg;
        break;

#if MESH_MODE_SUPPORT
    case IEEE80211_MESH_CAPABILITIES:
        val = vap->iv_mesh_cap;
        break;
#endif

    case IEEE80211_CONFIG_ASSOC_WAR_160W:
        val = vap->iv_cfg_assoc_war_160w;
        break;
    case IEEE80211_FEATURE_SON:
            val = son_vdev_feat_capablity(vap->vdev_obj,
                                          SON_CAP_GET,
                                          WLAN_VDEV_F_SON);
        break;
    case IEEE80211_CONFIG_FEATURE_SON_NUM_VAP:
            val = son_vdev_get_count(vap->vdev_obj,
                                          SON_CAP_GET);
        break;
    case IEEE80211_FEATURE_REPT_MULTI_SPECIAL:
            val =  son_vdev_fext_capablity(vap->vdev_obj,
                                           SON_CAP_GET,
                                           WLAN_VDEV_FEXT_SON_SPL_RPT);
        break;
    case IEEE80211_RAWMODE_PKT_SIM:
        val = vap->iv_rawmode_pkt_sim;
        break;

    case IEEE80211_CONFIG_RAW_DWEP_IND:
        val = vap->iv_cfg_raw_dwep_ind;
        break;
    case IEEE80211_CONFIG_PARAM_CUSTOM_CHAN_LIST:
        val = ic->ic_use_custom_chan_list;
        break;

#if UMAC_SUPPORT_ACFG
    case IEEE80211_CONFIG_DIAG_WARN_THRESHOLD:
        if (vap->iv_opmode == IEEE80211_M_HOSTAP)
            val = vap->iv_diag_warn_threshold;
        break;

    case IEEE80211_CONFIG_DIAG_ERR_THRESHOLD:
        if (vap->iv_opmode == IEEE80211_M_HOSTAP)
            val = vap->iv_diag_err_threshold;
        break;
#endif
    case IEEE80211_CONFIG_REV_SIG_160W:
        val = vap->iv_rev_sig_160w;
        break;
#ifdef MU_CAP_WAR_ENABLED
    case IEEE80211_CONFIG_MU_CAP_WAR:
        val = vap->iv_mu_cap_war.mu_cap_war;
        {
            int total_mu_clients = 0;
            int cnt;
            MU_CAP_WAR *war = &vap->iv_mu_cap_war;
            qdf_spin_lock_bh(&war->iv_mu_cap_lock);
            for(cnt=0;cnt<MU_CAP_CLIENT_TYPE_MAX;cnt++) {
                total_mu_clients += war->mu_cap_client_num[cnt];
            }
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
            "Number of float-clients to which modified probe-resp sent: %d\n",
                           war->dedicated_client_number);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                    "ProbeResponse tweak status %d\n",
                    war->modify_probe_resp_for_dedicated);
            /*
             * Print out the complete list of clients
             * to which we have sent "hacked" probe-response
             * and which have not-yet associated with us
             */
            if (!war->modify_probe_resp_for_dedicated) {
                /*
                 * When this variable is turned off, theres is
                 * no risk of race condition between here and
                 * probe response processing where the list is
                 * updated, and where lock is not acquired
                 */
                struct DEDICATED_CLIENT_MAC *dedicated_mac;
                int cnt;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "Floating tweaked Probe-resp clients\n");
                for(cnt=0;
                    cnt<ARRAY_SIZE(war->dedicated_client_list);
                    cnt++) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                            "HASH Number:%d\n", cnt);
                    LIST_FOREACH(dedicated_mac,
                                 &war->dedicated_client_list[cnt],
                                 list) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,"%s\n",
                                ether_sprintf(dedicated_mac->macaddr));
                    }
                }
            }

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                    "Following are the list of MU-CAP clients\n");
            /*
             * Print the complete list of MU-Capable clients
             * and how they are classified by the WAR
             */
            for(cnt=0;cnt<total_mu_clients;cnt++) {
                char *client_type;
                struct ieee80211_node *ni =
                ieee80211_find_node(vap->iv_ic,
                                    war->mu_cap_client_addr[cnt], WLAN_MLME_SB_ID);
                if (ni == NULL) {
                    ieee80211_note(vap, IEEE80211_MSG_ASSOC,
                    "there is no ni for mac %s type %d\n",
                    ether_sprintf(war->mu_cap_client_addr[cnt]),
                    war->mu_cap_client_flag[cnt]);
                    continue;
                }
                switch(war->mu_cap_client_flag[cnt])
                {
                    case MU_CAP_CLIENT_NORMAL:
                        client_type = "MU-CAP";
                        break;
                    case MU_CAP_DEDICATED_SU_CLIENT:
                        client_type = "DEDICATED-SU";
                        break;
                    case MU_CAP_DEDICATED_MU_CLIENT:
                        client_type = "DEDICATED-MU";
                        break;
                    default:
                        client_type = "INVALID";
                        break;
                }

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,"%s %s %d\n",
                                ether_sprintf(war->mu_cap_client_addr[cnt]),
                                client_type, ni->ni_streams);
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            }
            qdf_spin_unlock_bh(&war->iv_mu_cap_lock);
        }
        break;
    case IEEE80211_CONFIG_MU_CAP_TIMER:
        val = vap->iv_mu_cap_war.mu_cap_timer_period;
        break;
#endif
    case IEEE80211_CONFIG_ASSOC_DENIAL_NOTIFICATION:
        val = vap->iv_assoc_denial_notify;
        break;

    case IEEE80211_CONFIG_DISABLE_SELECTIVE_HTMCS:
        val = vap->iv_disabled_ht_mcsset[0] | (vap->iv_disabled_ht_mcsset[1]<<8)  | (vap->iv_disabled_ht_mcsset[2]<<16)  | (vap->iv_disabled_ht_mcsset[3]<<24);
        qdf_nofl_info("ht mcs disabled map: 0x%8X\n",val);
        break;

    case IEEE80211_CONFIG_CONFIGURE_SELECTIVE_VHTMCS:
        val = vap->iv_configured_vht_mcsmap;
        qdf_nofl_info("vht configured mcs map : 0x%8X\n",val);
        break;
   case IEEE80211_CONFIG_RDG_ENABLE:
        val = 0;
        break;
    case IEEE80211_CONFIG_DFS_SUPPORT:
        val = 1;
        break;
    case IEEE80211_CONFIG_DFS_ENABLE:
        val = 1;
        break;
    case IEEE80211_CONFIG_ACS_SUPPORT:
        val = 1;
        break;
    case IEEE80211_CONFIG_SSID_STATUS:
        val = ieee80211_is_vap_state_running(vap);
        break;
    case IEEE80211_CONFIG_DL_QUEUE_PRIORITY_SUPPORT:
        val = 1;
        break;
    case IEEE80211_CONFIG_CLEAR_MIN_MAX_SNR:
        ieee80211_clear_min_max_snr(vap);
        val = 1;
        break;
    case IEEE80211_CONFIG_WATERMARK_THRESHOLD:
         val = vap->watermark_threshold;
        break;
    case IEEE80211_CONFIG_WATERMARK_REACHED:
         val = vap->watermark_threshold_reached;
        break;
    case IEEE80211_CONFIG_ASSOC_REACHED:
         val = vap->assoc_high_watermark;
        break;
    case IEEE80211_BEACON_RATE_FOR_VAP:
        {
            wlan_util_vdev_mlme_get_param(vdev_mlme,
                    WLAN_MLME_CFG_BCN_TX_RATE, &val);
            if (!val)
                wlan_util_vdev_mlme_get_param(vdev_mlme,
                        WLAN_MLME_CFG_TX_MGMT_RATE, &val);
        }
        break;
    case IEEE80211_CONFIG_DISABLE_SELECTIVE_LEGACY_RATE:
        val = vap->iv_disabled_legacy_rate_set;
        break;
    case IEEE80211_CONFIG_MON_DECODER:
        /* monitor vap decoder header type, prism=0(default), radiotap=1 */
        val = ic->ic_mon_decoder_type;
        break;
    case IEEE80211_CONFIG_NSTSCAP_WAR:
        val = vap->iv_cfg_nstscap_war;
        break;

    case IEEE80211_CONFIG_CHANNEL_SWITCH_MODE:
        val = vap->iv_csmode;
        break;

    case IEEE80211_CONFIG_ECSA_IE:
        val = vap->iv_enable_ecsaie;
        break;

    case IEEE80211_CONFIG_SAE_PWID:
        val = vap->iv_enable_sae_pwid;
        break;

    case IEEE80211_CONFIG_OCE_TX_POWER:
        val = vap->iv_tx_power_enable;
        break;

    case IEEE80211_CONFIG_ECSA_OPCLASS:
        val = vap->iv_ecsa_opclass;
        break;

    case IEEE80211_CONFIG_HE_EXTENDED_RANGE:
        val = vap->iv_he_extended_range;
        break;
    case IEEE80211_CONFIG_HE_DCM:
        val = vap->iv_he_dcm;
        break;
    case IEEE80211_CONFIG_HE_FRAGMENTATION:
        val = vap->iv_he_frag;
        break;
    case IEEE80211_CONFIG_HE_MU_EDCA:
        val = vap->iv_he_muedca;
        break;
    case IEEE80211_CONFIG_HE_DYNAMIC_MU_EDCA:
        val = vap->iv_muedcastate.mu_edca_dynamic_state & MUEDCA_DYNAMIC_ALGO_ENABLE_STATE_MASK;
        break;
    case IEEE80211_CONFIG_HE_UL_MU_MIMO:
        val = vap->iv_he_ul_mumimo;
        break;
    case IEEE80211_CONFIG_HE_UL_MU_OFDMA:
        val = vap->iv_he_ul_muofdma;
        break;
    case IEEE80211_CONFIG_HE_SU_BFEE:
        val = vap->iv_he_su_bfee;
        break;
    case IEEE80211_CONFIG_HE_SU_BFER:
        val = vap->iv_he_su_bfer;
        break;
    case IEEE80211_CONFIG_HE_MU_BFEE:
        val = vap->iv_he_mu_bfee;
        break;
    case IEEE80211_CONFIG_HE_MU_BFER:
        val = vap->iv_he_mu_bfer;
        break;
    case IEEE80211_CONFIG_HE_DL_MU_OFDMA:
        val = vap->iv_he_dl_muofdma;
        break;
    case IEEE80211_CONFIG_HE_DL_MU_OFDMA_BFER:
        val = vap->iv_he_dl_muofdma_bfer;
        break;
    case IEEE80211_CONFIG_6G_HE_OP_MIN_RATE:
        val = vap->iv_6g_he_op_min_rate;
        break;
    case IEEE80211_CONFIG_EXT_NSS_SUPPORT:
        /*
         * As QCN9000 supports true160, max-NSS value is the same for 80M and
         * 160M. The iv_ext_nss_support flag is not tuned to reflect this.
         */
        if ((ic->ic_get_tgt_type(ic)) != TARGET_TYPE_QCN9000)
            val = vap->iv_ext_nss_support;
        else
            val = 0;
        break;
    case IEEE80211_CONFIG_HE_LTF:
        val = vap->iv_he_ltf;
        break;
    case IEEE80211_CONFIG_HE_AR_GI_LTF:
        val = vap->iv_he_ar_gi_ltf;
        break;
    case IEEE80211_CONFIG_HE_AR_LDPC:
        val = vap->iv_he_ar_ldpc;
        break;
    case IEEE80211_CONFIG_HE_RTSTHRSHLD:
        val = vap->iv_he_rts_threshold;
        break;
    case IEEE80211_CONFIG_CSL_SUPPORT:
        val = vap->iv_csl_support;
        break;
    case IEEE80211_FEATURE_DISABLE_CABQ:
        val = IEEE80211_VAP_IS_NOCABQ_ENABLED(vap) ? 1 : 0;
        break;
    case IEEE80211_SUPPORT_TIMEOUTIE:
         val = vap->iv_assoc_comeback_time;
         break;
    case IEEE80211_SUPPORT_PMF_ASSOC:
         val = vap->iv_skip_pmf_reassoc_to_hostap;
         break;
#if WLAN_SUPPORT_FILS
    case IEEE80211_FEATURE_FILS:
        val = wlan_fils_is_enable(vap->vdev_obj);
        break;
#endif
    case IEEE80211_CONFIG_HE_TX_MCSMAP:
        val = vap->iv_he_tx_mcsnssmap;
        break;
    case IEEE80211_CONFIG_HE_RX_MCSMAP:
        val = vap->iv_he_rx_mcsnssmap;
        break;
    case IEEE80211_CONFIG_M_COPY:
        if (ic->ic_debug_sniffer == SNIFFER_M_COPY_MODE)
            val = MODE_M_COPY;
        else if (ic->ic_debug_sniffer == SNIFFER_EXT_M_COPY_MODE)
            val = MODE_EXT_M_COPY;
        else
            val = 0;
        break;
    case IEEE80211_CONFIG_BA_BUFFER_SIZE:
        val = vap->iv_ba_buffer_size;
        break;
    case IEEE80211_CONFIG_READ_RXPREHDR:
        val = vap->iv_read_rxprehdr;
        break;
    case IEEE80211_CONFIG_HE_SOUNDING_MODE:
        val = vap->iv_he_sounding_mode;
        break;
    case IEEE80211_SUPPORT_RSN_OVERRIDE:
        val = vap->iv_rsn_override;
        break;
    case IEEE80211_CONFIG_HE_HT_CTRL:
        val = vap->iv_he_ctrl;
        break;
    case IEEE80211_CONFIG_TX_CAPTURE:
        val = ic->ic_tx_capture;
        break;
    case IEEE80211_DRIVER_HW_CAPS:
        val = ic->ic_modecaps;
        break;
    case IEEE80211_CONFIG_FT_ENABLE:
        val = vap->iv_roam.iv_ft_enable;
        break;
    case IEEE80211_CONFIG_RAWMODE_OPEN_WAR:
        val = vap->iv_rawmode_open_war;
        break;
    case IEEE80211_CONFIG_HE_BSR_SUPPORT:
        val = vap->iv_he_bsr_supp;
        break;
    case IEEE80211_CONFIG_ENABLE_MULTI_GROUP_KEY:
        val = vap->enable_multi_group_key;
        break;
    case IEEE80211_CONFIG_MAX_GROUP_KEYS:
        val = vap->max_group_keys;
        break;
    case IEEE80211_CONFIG_MAX_MTU_SIZE:
        val = vap->iv_max_mtu_size;
        break;
    case IEEE80211_CONFIG_6GHZ_BCAST_PROB_RSP:
        val = vap->iv_he_6g_bcast_prob_rsp_intval;
        break;
    case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_COUNT:
    case IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_DROP_MASK:
        if (ic->ic_vap_get_param)
            val = ic->ic_vap_get_param(vap, param);
        break;
    case IEEE80211_CONFIG_ASSOC_MIN_RSSI:
        val = vap->iv_assoc_min_rssi_thrshld;
        break;
    case IEEE80211_CONFIG_ENABLE_MSCS:
        val = vap->iv_mscs;
        break;
    case IEEE80211_CONFIG_6G_SECURITY_COMP:
        val = vap->iv_6g_comp;
	break;
    case IEEE80211_CONFIG_6G_KEYMGMT_MASK:
        val = vap->iv_keymgmt_6g_mask;
	break;
    case IEEE80211_CONFIG_HE_ER_SU_DISABLE:
        val = vap->iv_he_er_su_disable;
        break;
    case IEEE80211_CONFIG_HE_1024QAM_LT242RU_RX_ENABLE:
        val = vap->iv_he_1024qam_lt242ru_rx;
        break;
    case IEEE80211_CONFIG_HE_UL_MU_DATA_DIS_RX_SUPP:
        val = vap->iv_he_ulmu_data_disable_rx;
        break;
    case IEEE80211_CONFIG_HE_FULL_BW_UL_MUMIMO:
        val = vap->iv_he_full_bw_ulmumimo;
        break;
    case IEEE80211_CONFIG_HE_DCM_MAX_CONSTELLATION_RX:
        val = vap->iv_he_dcm_max_cons_rx;
        break;
    case IEEE80211_CONFIG_DISABLE_INACT_PROBING:
        val = vap->iv_disable_inact_probe;
        break;
    case IEEE80211_VDEV_TSF:
        val = ic->ic_vap_get_param(vap, IEEE80211_VDEV_TSF);
        break;
    case IEEE80211_CONFIG_AP_MAX_AUTH_FAIL:
        val = vap->max_cont_auth_fail;
        break;
    default:
        break;
    }
    return val;
}

void wlan_clear_qos(struct ieee80211vap *vap, u_int32_t isbss)
{
#define DEFAULT_VI_TXOP (3008 >> 5)
#define DEFAULT_VO_TXOP (1504 >> 5)

    wlan_set_wmm_param(vap,WLAN_WME_CWMIN,isbss,WME_AC_BE,4);
    wlan_set_wmm_param(vap,WLAN_WME_CWMAX,isbss,WME_AC_BE,10);
    wlan_set_wmm_param(vap,WLAN_WME_AIFS,isbss,WME_AC_BE,3);
    wlan_set_wmm_param(vap,WLAN_WME_TXOPLIMIT,isbss,WME_AC_BE,0);

    wlan_set_wmm_param(vap,WLAN_WME_CWMIN,isbss,WME_AC_BK,4);
    wlan_set_wmm_param(vap,WLAN_WME_CWMAX,isbss,WME_AC_BK,10);
    wlan_set_wmm_param(vap,WLAN_WME_AIFS,isbss,WME_AC_BK,7);
    wlan_set_wmm_param(vap,WLAN_WME_TXOPLIMIT,isbss,WME_AC_BK,0);

    wlan_set_wmm_param(vap,WLAN_WME_CWMIN,isbss,WME_AC_VI,3);
    wlan_set_wmm_param(vap,WLAN_WME_CWMAX,isbss,WME_AC_VI,4);
    wlan_set_wmm_param(vap,WLAN_WME_AIFS,isbss,WME_AC_VI,2);
    wlan_set_wmm_param(vap,WLAN_WME_TXOPLIMIT,isbss,WME_AC_VI, DEFAULT_VI_TXOP);

    wlan_set_wmm_param(vap,WLAN_WME_CWMIN,isbss,WME_AC_VO,2);
    wlan_set_wmm_param(vap,WLAN_WME_CWMAX,isbss,WME_AC_VO,3);
    wlan_set_wmm_param(vap,WLAN_WME_AIFS,isbss,WME_AC_VO,2);
    wlan_set_wmm_param(vap,WLAN_WME_TXOPLIMIT,isbss,WME_AC_VO, DEFAULT_VO_TXOP);
}

/*
 * Set the txchainmask per sta
 * @param vaphandle  Vap interface handle
 * @param macaddress Macaddress of the sta
 * @param nss Nss value to be set for the particular station.
 */
int wlan_set_chainmask_per_sta(wlan_if_t vaphandle, u_int8_t *macaddr,u_int8_t nss)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;

    if (nss > ieee80211_getstreams(ic, ic->ic_tx_chainmask))
        return -EINVAL;

    ni = ieee80211_vap_find_node(vap, macaddr, WLAN_MLME_SB_ID);
    if (ni != NULL) {
        ni->ni_streams = nss;
        if ((ni->ni_chwidth == IEEE80211_CWM_WIDTH160) && ni->ni_ext_nss_support){
             ieee80211_intersect_extnss_160_80p80(ni);
        }
        ic->ic_nss_change(ni);
        ieee80211_free_node(ni, WLAN_MLME_SB_ID);
    }
    else {
        return -EINVAL;
    }
    return 0;

}

void wlan_set_peer_nss(void *arg, wlan_node_t node)
{
    struct ieee80211_node *ni = node;
    struct ieee80211vap *vap = ni->ni_vap ;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211req_athdbg *req = (struct ieee80211req_athdbg *)arg;

    if (req->data.param[1] > MIN(ieee80211_getstreams(ic, ic->ic_tx_chainmask),
                ieee80211_getstreams(ic, ic->ic_rx_chainmask))) {
        qdf_err("Peer NSS setting should be less than %d",
                MIN(ieee80211_getstreams(ic, ic->ic_tx_chainmask),
                    ieee80211_getstreams(ic, ic->ic_rx_chainmask)));
        return;
    }

    if ((ni->ni_associd == 0) ||
        (IEEE80211_AID(ni->ni_associd) != req->data.param[0])) {
        return;
    }
    if (!ieee80211node_has_extflag(ni, IEEE80211_NODE_ASSOC_RESP)) {
        IEEE80211_NOTE(vap, IEEE80211_MSG_ACTION, ni,
                                       "%s: discard opmode frame for sta %d as assoc not completed",
                                       __func__, ether_sprintf(ni->ni_macaddr));
        return;
    }

    wlan_set_chainmask_per_sta(vap, ni->ni_macaddr, req->data.param[1]);

}

int wlan_enable_frame_injector(wlan_if_t vaphandle, u_int32_t frametype,
                                u_int32_t enable, u_int32_t inject_period,
                                u_int32_t duration, u_int8_t *dstmac)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int ret_val = -EINVAL;

    switch(frametype) {
        case IEEE80211_FRAME_INJECTOR_TYPE_QOSNULL:
        case IEEE80211_FRAME_INJECTOR_TYPE_CTS_TO_SELF:
            if (enable > 1) {
                qdf_err("Enable arg should be 0 or 1");
                return -EINVAL;
            } else if (inject_period > vap->iv_bss->ni_intval) {
                qdf_err("Inject Period should be less than Beacon Interval: %dms",
                                                vap->iv_bss->ni_intval);
                return -EINVAL;
            } else if (duration > IEEE80211_FRAME_INJECTOR_MAX_DUR){
                qdf_err("Duration field should be <= %d",
                                        IEEE80211_FRAME_INJECTOR_MAX_DUR);
                return -EINVAL;
            } else {
                if (ic && ic->ic_frame_injector_config) {
                    ret_val = ic->ic_frame_injector_config(vap->vdev_obj, frametype,
                                                        enable, inject_period,
                                                        duration, dstmac);
                }
            }
        break;

        case IEEE80211_FRAME_INJECTOR_TYPE_MGMT:
            ret_val = ieee80211_inject_mgmt_frame(vap, enable, inject_period, dstmac);
        break;

        default:
            qdf_err("Injector frame type %d not supported", frametype);
            return -EINVAL;
        break;
    }

    return ret_val;
}

/**
* @wlan_validate_user_tpe_val(): Validate the user input for Max Tx Power
*                                   values against the regulatory Maximum Tx
*                                   Power allowed
*
* @param vap                  Pointer to vap
* @param txpwr_intrprt        Max Tx Power interpretation
* @param txpwr_cat            Max Tx Power category
* @param txpwr_val            Max Tx Power values
* @param txpwr_cnt            Max Tx Power count
*
* @return 0 on Success and -EINVAL on failure
*/
int wlan_validate_user_tpe_val(struct ieee80211vap *vap,
                                u_int8_t txpwr_intrprt, u_int8_t txpwr_cat,
                                u_int8_t *txpwr_val, u_int8_t txpwr_cnt)
{
    struct ieee80211com *ic = vap->iv_ic;
    int8_t max_reg_tx_pwr, user_input, iter;
    bool is_psd_pwr;
    uint16_t max_reg_eirp_psd_pwr;
    uint16_t max_reg_psd_pwr;

    if (!ic) {
        qdf_err("IC is NULL!");
        return -EINVAL;
    }

    switch (txpwr_intrprt) {
        case IEEE80211_TPE_LOCAL_EIRP:
        case IEEE80211_TPE_REG_EIRP:
            max_reg_tx_pwr = ic->ic_curchan->ic_maxregpower;
        break;
        case IEEE80211_TPE_LOCAL_EIRP_PSD:
        case IEEE80211_TPE_REG_EIRP_PSD:
            if (wlan_reg_get_client_power_for_6ghz_ap(ic->ic_pdev_obj,
                                              txpwr_cat,
                                              ic->ic_curchan->ic_freq,
                                              &is_psd_pwr, &max_reg_psd_pwr,
                                              &max_reg_eirp_psd_pwr) !=
                                              QDF_STATUS_SUCCESS) {
                qdf_err("Error retrieving Regulatory Max Tx Power");
                return -EINVAL;
             }

             if (!is_psd_pwr)
                 ieee80211_get_default_psd_power(vap, txpwr_cat,
                                                 (uint8_t *)&max_reg_eirp_psd_pwr);

             max_reg_tx_pwr = max_reg_eirp_psd_pwr;
        break;

        default:
            qdf_err("Invalid Interpretation value");
            return -EINVAL;
        break;
    }

    /* User input is an absolute value.
     * Convert max_reg_tx_pwr to absolute value.
     */
    max_reg_tx_pwr = 2 * max_reg_tx_pwr;
    for (iter = 0; iter < txpwr_cnt; iter++) {
        user_input = (int8_t)txpwr_val[iter];
        if(user_input > max_reg_tx_pwr) {
            qdf_err("Tx Power value should be less than %d(%ddbm/MHz)",
                    (int8_t)max_reg_tx_pwr, (int8_t)(max_reg_tx_pwr/2));
            return -EINVAL;
        }
    }

    return 0;
}

int wlan_add_tpe_ie(wlan_if_t vaphandle, u_int8_t txpwr_cnt,
                    u_int8_t txpwr_intrpt, u_int8_t txpwr_cat,
                    u_int8_t count, u_int8_t *txpwr_val)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osifp->netdev;
    ieee80211_tpe_config_user_params *tpe_conf = &vap->iv_tpe_ie_config;
    int8_t tx_pwr_val_count;
    u_int8_t index;
    int ret_val = -EINVAL;

    /* Currently user config TPE IE addition is supported
     * only for 6GHz. This could be extended in future to
     * support for 5GHz/2.4Ghz
     */
    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        qdf_err("User configured TPE addition supported for 6GHz only");
        return -EINVAL;
    }

    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        qdf_err("Add TPE IE cmd is not supported for non-Tx vap");
        return -EINVAL;
    }

    if (txpwr_intrpt > IEEE80211_TPE_LOCAL_EIRP_PSD) {
        qdf_err("User config supported only for local interpretation: \n"
                "IEEE80211_TPE_LOCAL_EIRP(%d) | "
                "IEEE80211_TPE_LOCAL_EIRP_PSD(%d)\n"
                "Invalid user input: %d", IEEE80211_TPE_LOCAL_EIRP,
                IEEE80211_TPE_LOCAL_EIRP_PSD, txpwr_intrpt);
        return -EINVAL;
    }

    if (txpwr_cat > REG_SUBORDINATE_CLIENT) {
        qdf_err("Invalid Tx Power Category: %d\n"
                "Valid input for Tx Power category:\n"
                "Default Device: %d | "
                "Subordinate Device: %d", txpwr_cat,
                REG_DEFAULT_CLIENT, REG_SUBORDINATE_CLIENT);
        return -EINVAL;
    }

    if (count > IEEE80211_TPE_NUM_POWER_SUPPORTED) {
        qdf_err("Invalid number of Tx Power values: %d\n"
                "Maximum number of Tx Power values allowed: %d", txpwr_cnt,
                IEEE80211_TPE_NUM_POWER_SUPPORTED);
        return -EINVAL;
    }

    /* Calculate total number of Tx Power values expected
     * for the given Tx Pwr interpretation and Tx Pwr count values
     */
    tx_pwr_val_count = ieee80211_get_tpe_count(txpwr_intrpt, txpwr_cnt);
    if (tx_pwr_val_count < 0) {
        return -EINVAL;
    } else if (tx_pwr_val_count != count) {
        qdf_err("Invalid number of Tx pwr values %d"
                " for current Max Txpwr count setting %d\n"
                "Number of Tx Pwr values expected: %d",
                count, txpwr_cnt, tx_pwr_val_count);
        return -EINVAL;
    }

    if (wlan_validate_user_tpe_val(vap, txpwr_intrpt, txpwr_cat,
                                                txpwr_val, count)) {
        qdf_err("Invalid Max Tx Power value");
        return -EINVAL;
    }

    /* Index calculation for user config TPE IE:
     * index = ((interpretation << 1) | category)
     *
     * Interpretation       Category       Index calculation
     *      0                  0            (0<<1) | 0 = 0
     *      0                  1            (0<<1) | 1 = 1
     *      1                  0            (1<<1) | 0 = 2
     *      1                  1            (1<<1) | 1 = 3
     */
    index = IEEE80211_DERIVE_TPE_CONFIG_IDX(txpwr_intrpt, txpwr_cat);

    if (tpe_conf->local_tpe_config & BIT(index)) {
        qdf_info("Overwriting existing TPE config for\n"
                 "Interpretation: %s\nCategory: %s",
                 txpwr_intrpt ? "Local EIRP PSD" : "Local EIRP",
                 txpwr_cat ? "Subordinate Device" : "Default Device");
    } else {
        tpe_conf->local_tpe_config |= BIT(index);
    }

    tpe_conf->tpe_config[index].tpe_payload.tpe_info_cnt = txpwr_cnt;
    tpe_conf->tpe_config[index].tpe_payload.tpe_info_intrpt = txpwr_intrpt;
    tpe_conf->tpe_config[index].tpe_payload.tpe_info_cat = txpwr_cat;
    qdf_mem_copy(tpe_conf->tpe_config[index].tpe_payload.local_max_txpwr,
                                                            txpwr_val, count);

    if (ic->ic_is_vdev_restart_sup && (vap->iv_opmode == IEEE80211_M_HOSTAP)) {
        ret_val = osif_vdev_restart(vap);
    } else {
        ret_val = osif_vap_init(dev, RESCAN);
    }
    return ret_val;
}

int wlan_del_tpe_ie(wlan_if_t vaphandle, u_int8_t txpwr_intrpt,
                    u_int8_t txpwr_cat)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osifp->netdev;
    ieee80211_tpe_config_user_params *tpe_conf = &vap->iv_tpe_ie_config;
    u_int8_t index;
    int ret_val = -EINVAL;

    if (!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
        qdf_err("User configured TPE deletion supported for 6GHz only");
        return -EINVAL;
    }

    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        qdf_err("Add TPE IE cmd is not supported for non-Tx vap");
        return -EINVAL;
    }

    /* Index calculation for user config TPE IE:
     * index = ((interpretation << 1) | category)
     *
     * Interpretation       Category       Index calculation
     *      0                  0            (0<<1) | 0 = 0
     *      0                  1            (0<<1) | 1 = 1
     *      1                  0            (1<<1) | 0 = 2
     *      1                  1            (1<<1) | 1 = 3
     */
    index = IEEE80211_DERIVE_TPE_CONFIG_IDX(txpwr_intrpt, txpwr_cat);

    if (!(tpe_conf->local_tpe_config & BIT(index))) {
        qdf_info("TPE IE with input Tx Pwr info is not present\n"
                 "Interpretation: %s\nCategory: %s",
                 txpwr_intrpt ? "Local EIRP" : "Local EIRP PSD",
                 txpwr_cat ? "Default Device" : " Subordinate Device");
        return EOK;
    } else {
        tpe_conf->local_tpe_config &= ~BIT(index);
        qdf_mem_zero(&tpe_conf->tpe_config[index],
                    sizeof(struct ieee80211_tpe_ie_config));
    }

    if (ic->ic_is_vdev_restart_sup && (vap->iv_opmode == IEEE80211_M_HOSTAP)) {
        ret_val = osif_vdev_restart(vap);
    } else {
        ret_val = osif_vap_init(dev, RESCAN);
    }
    return ret_val;
}

/*
 * test command for turning various knobs in firmware
 * @param vaphandle  Vap interface handle
 * @param test argument
 * @param test value
 */
int wlan_ar900b_fw_test(wlan_if_t vaphandle, u_int32_t arg, u_int32_t value)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int ret_val = -EINVAL;

    if (ic != NULL) {
        ic->ic_ar900b_fw_test(ic, arg, value);
        ret_val = 0;
    }

    return ret_val;
}

/*
 * test command for turning various knobs in firmware
 * @param vaphandle  Vap interface handle
 * @param test argument
 * @param test value
 */
int wlan_set_fw_unit_test_cmd(wlan_if_t vaphandle, struct ieee80211_fw_unit_test_cmd *fw_unit_test_cmd)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int ret_val = -EINVAL;

    if (ic != NULL) {
        ret_val = ic->ic_fw_unit_test(vap->vdev_obj, fw_unit_test_cmd);
    }

    return ret_val;
}

/*
 * Configure coex parameters in firmware
 * @param vaphandle Vap interface handle
 * @param coex_cfg  Config type and arguments
 */
int wlan_coex_cfg(wlan_if_t vaphandle, coex_cfg_t *coex_cfg)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int ret_val = -EINVAL;

    if (ic) {
        ret_val = ic->ic_coex_cfg(vap->vdev_obj, coex_cfg->type, coex_cfg->arg);
    }

    return ret_val;
}

#if UNIFIED_SMARTANTENNA
/*
 * Dynamically set the antenna switch
 * @param vaphandle  Vap interface handle
 * @param antenna control common1
 * @param antenna control common2
 */
int wlan_set_antenna_switch(wlan_if_t vaphandle, u_int32_t ctrl_cmd_1, u_int32_t ctrl_cmd_2)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = NULL;
    int ret_val = -EINVAL;

    if (vap != NULL) {
        ic = vap->iv_ic;

        if (ic != NULL) {
            ic->ic_set_ant_switch(ic, ctrl_cmd_1, ctrl_cmd_2);
            ret_val = 0;
        }
    }

    return ret_val;

}
#endif

/*
 * Set the User control table
 * @param vaphandle  Vap interface handle
 * @param user table
 * @param table size
 */
int wlan_set_ctl_table(wlan_if_t vaphandle, u_int8_t *ctl_array, u_int16_t ctl_len)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = NULL;
    int ret_val = -EINVAL;

    if (vap != NULL) {
        ic = vap->iv_ic;

        if (ic != NULL) {
            ic->ic_set_ctrl_table(ic, ctl_array, ctl_len);
            ret_val = 0;
        }
    }

    return ret_val;

}

int wlan_set_vap_cts2self_prot_dtim_bcn(wlan_if_t  vap, u_int8_t enable)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (vap->iv_cts2self_prot_dtim_bcn == enable)
        return 0;

    vap->iv_cts2self_prot_dtim_bcn = enable;

    qdf_print("Configuring cts2self protection for DTIM beacon : %s ",enable?"enable":"disable");
    /* Update in F/W as well. */
    ic->ic_vap_set_param(vap, IEEE80211_CTSPROT_DTIM_BCN_SET, 0);

    return 0;

}
#if ATH_SUPPORT_DSCP_OVERRIDE
int wlan_set_vap_priority_dscp_tid_map(wlan_if_t  vap, u_int8_t priority)
{
    int count = 0;
    u_int8_t tid = 0,priority_to_tid[4] = {2, 0, 4, 6};
    if ((priority < 0) || (priority > 3))
    {
        qdf_print("%s: Vap Priority should be chosen in between 0 and 3",__func__);
        return -1;
    }

    tid = priority_to_tid[priority];
    if((vap->iv_dscp_map_id != 0) && vap->iv_ic->ic_vap_set_param) {
        qdf_print("Configuring dscp_tid_map table %d to use tid %d",
                vap->iv_dscp_map_id, tid);
        while(count < WMI_HOST_DSCP_MAP_MAX) {
            vap->iv_ic->ic_dscp_tid_map[vap->iv_dscp_map_id][count] = tid;
            vap->iv_ic->ic_vap_set_param(vap, IEEE80211_DP_DSCP_MAP, (count << IP_DSCP_SHIFT));
            count++;
        }
        vap->iv_ic->ic_vap_set_param(vap, IEEE80211_DSCP_MAP_ID, 0);
    } else if(vap->iv_dscp_map_id != 0) {
        wlan_vdev_set_priority_dscp_tid_map(vap->vdev_obj, tid);
    }

    return 0;
}

int wlan_set_vap_dscp_tid_map(wlan_if_t  vap, u_int8_t tos, u_int8_t tid)
{
    if (tid < 0 || tid > 7)
        return -1;

    qdf_print(" Configuring tos: %d, dscp : %d  to tid %d", tos, (tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK, tid);
    if((vap->iv_dscp_map_id != 0) && vap->iv_ic->ic_vap_set_param) {
        vap->iv_ic->ic_dscp_tid_map[vap->iv_dscp_map_id][(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK] = tid;
        vap->iv_ic->ic_vap_set_param(vap, IEEE80211_DSCP_MAP_ID, 0);
        vap->iv_ic->ic_vap_set_param(vap, IEEE80211_DP_DSCP_MAP, tos);
    }
    return 0;

}
#endif /* ATH_SUPPORT_DSCP_OVERRIDE */

int wlan_get_vap_pcp_tid_map(wlan_if_t vap, uint32_t pcp)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t target_type = ic->ic_get_tgt_type(ic);

    if (!((target_type == TARGET_TYPE_QCA8074) ||
          (target_type == TARGET_TYPE_IPQ4019))) {
        qdf_info("Feature not supported for target");
        return -1;
    }
    if (pcp < 0 || pcp > 7) {
        qdf_info("Invalid input");
        return -1;
    }
    return (int)vap->iv_pcp_tid_map[pcp];
}

int wlan_set_vap_pcp_tid_map(wlan_if_t vap, uint32_t pcp, uint32_t tid)
{
    struct ieee80211com *ic = vap->iv_ic;

    if ((pcp < 0 || pcp > 7) || (tid < 0 || tid > 7)) {
        qdf_err("Invalid input");
        return -1;
    }

    /* Update vap tid map only if configured to use the same */
    if (vap->iv_tidmap_tbl_id)
        vap->iv_pcp_tid_map[pcp] = (uint8_t)tid;

    if (ic->ic_set_pcp_tid_map(vap->vdev_obj, pcp, tid)) {
        qdf_err("Unable to set mapping");
        return -1;
    }

    return 0;
}

int wlan_set_vap_tidmap_tbl_id(wlan_if_t vap, uint32_t mapid)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t map_prec;

    if (mapid < 0 || mapid > 1) {
        qdf_err("Invalid input");
        return -1;
    }
    vap->iv_tidmap_tbl_id = (uint8_t)mapid;
    if (ic->ic_set_tidmap_tbl_id(vap->vdev_obj, mapid)) {
        qdf_err("Unable to set mapping");
        return -1;
    }
    /*
     * Push pcp-tid map & tidmap_prec values also to target.
     * We can invoke the low-layer API for pcp '0' only as
     * the latter will send the complete map to the target.
     */
    ic->ic_set_pcp_tid_map(vap->vdev_obj, 0, vap->iv_pcp_tid_map[0]);
    if (mapid)
        map_prec = vap->iv_tidmap_prty;
    else
        map_prec = ic->ic_tidmap_prty;
    if (map_prec == OL_TIDMAP_PRTY_DSCP_HLOS_CVLAN ||
        map_prec == OL_TIDMAP_PRTY_SVLAN_DSCP_HLOS)
        ic->ic_set_tidmap_prty(vap->vdev_obj, map_prec);

    return 0;
}

int wlan_get_vap_tidmap_tbl_id(wlan_if_t vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t target_type = ic->ic_get_tgt_type(ic);

    if (!((target_type == TARGET_TYPE_QCA8074) ||
          (target_type == TARGET_TYPE_IPQ4019))) {
        qdf_info("Feature not supported for target");
        return -1;
    }

    return (int)vap->iv_tidmap_tbl_id;
}

int wlan_get_vap_tidmap_prty(wlan_if_t vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    uint32_t target_type = ic->ic_get_tgt_type(ic);

    if (!((target_type == TARGET_TYPE_QCA8074) ||
          (target_type == TARGET_TYPE_IPQ4019))) {
        qdf_info("Feature not supported for target");
        return -1;
    }

    return (int)vap->iv_tidmap_prty;
}

int wlan_set_vap_tidmap_prty(wlan_if_t vap, uint32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;

    /*
     * The priority value needs to be set for allowing the Vlan-pcp
     * to be used for deciding the TID number. The DSCP-based TID
     * mapping is the default value and doesnt need to be configured
     * explicitly.
     */
    if (val < OL_TIDMAP_PRTY_DSCP_HLOS_CVLAN ||
        val > OL_TIDMAP_PRTY_SVLAN_DSCP_HLOS) {
        qdf_err("Permissible value is 3-4");
        return -1;
    }
    if (ic->ic_set_tidmap_prty(vap->vdev_obj, val)) {
        qdf_err("Failed to set map precedence");
        return -1;
    }

    /* Update vap tidmap_prty if configured to use the same */
    if (vap->iv_tidmap_tbl_id)
        vap->iv_tidmap_prty = (uint8_t)val;

    return 0;
}

/**
* Function to configure verbose level for converged component debug prints
* @param val - Value containing both category and verbose level information
*/
int wlan_set_shared_print_ctrl_category_verbose(u_int32_t val)
{
    QDF_MODULE_ID category;
    QDF_TRACE_LEVEL trace_level;
    unsigned int qdf_print_idx;
    QDF_STATUS res;

    /* Shared print control object is derived from QDF module through
     * below API and used for setting the verbose level for a category
     */
    qdf_print_idx = qdf_get_pidx();

    /* Extract category and verbose level information from the value
     * configured by the user
     *
     * Upper 2-bytes : Category | Lower 2-bytes : Verbose Level
     */
    category = QDF_CATEGORY_INFO_U16(val);
    trace_level = QDF_TRACE_LEVEL_INFO_L16(val);

    res = qdf_print_set_category_verbose(qdf_print_idx, category,
                                         trace_level, true);
    if (res) {
        qdf_print("%s: Failed to set verbose for category",__func__);
        return -1;
    }

    return 0;
}

/**
 * Function to set the time-period for periodic flushing of host logs
 *
 * @param val - Value containing the time in milliseconds
 * @return 0 on success -ve on failure
 */
int wlan_set_qdf_flush_timer_period(u_int32_t val)
{
    return qdf_logging_set_flush_timer(val);
}

/**
 * Function to flush out the logs to user space one time
 */
void wlan_set_qdf_flush_logs(void)
{
    qdf_logging_flush_logs();
}

/**
 * Function to enable qdf_nofl_info call in QDF_TRACE
 *
 * @enable - Indicates whether qdf_nofl_info should be enabled
 */
void wlan_set_log_dump_at_kernel_level(bool enable)
{
    qdf_log_dump_at_kernel_level(enable);
}

/**
* Function to configure verbose level for converged component debug prints
* @param val - Value containing both category and verbose level information
*/
extern struct category_name_info g_qdf_category_name[MAX_SUPPORTED_CATEGORY];
int wlan_show_shared_print_ctrl_category_verbose_table()
{
    unsigned int qdf_print_idx;
    int i, j;
    QDF_MODULE_ID category;
    bool enabled;
    char trace_string[20];
    static const char * const VERBOSE_STR[] = { "  ", "F", "E", "W",
                                              "I", "IH", "IM", "IL",
                                              "D", "T" };

    qdf_print_idx = qdf_get_pidx();
    qdf_nofl_info(" Verbose Level Legend - 0:NONE      1:FATAL    2:ERROR    3:WARN  4:INFO\n"
                  "                        5:INFO_HIGH 6:INFO_MED 7:INFO_LOW 8:DEBUG 9:TRACE\n"
                  "                        A:ALL\n");
    qdf_nofl_info("----------------------------------------------------------------------------");
    qdf_nofl_info("|     Module Name     |     Module Idx     | Enabled |    Verbose Level    |");
    qdf_nofl_info("----------------------------------------------------------------------------");
    for (i = 0; i < MAX_SUPPORTED_CATEGORY; ++i) {
        category = i;
        trace_string[0] = '\0';
        enabled = qdf_print_is_category_enabled(qdf_print_idx, category);
        if (enabled) {
            for (j = 0; j < QDF_TRACE_LEVEL_ALL; ++j) {
                if (qdf_print_is_verbose_enabled(qdf_print_idx, category, j)) {
                    qdf_scnprintf(trace_string, sizeof(trace_string),
                                  "%s %s", trace_string, VERBOSE_STR[j]);
                }
            }
        }
        qdf_nofl_info("| %20s %12d(0x%04x) %8d %20s  | ",
                      g_qdf_category_name[i].category_name_str,
                      category, category, enabled, trace_string);
    }
    qdf_nofl_info("----------------------------------------------------------------------------");
    return 0;
}

/**
* Function to configure verbose level for UMAC debug prints
* @param verbose_level - verbose level of the print message
*/
int wlan_set_umac_verbose_level(u_int32_t verbose_level)
{
    asf_print_verb_set_by_name("IEEE80211_IC",verbose_level);
    asf_print_verb_set_by_name("IEEE80211",verbose_level);
    return 0;
}

int wlan_set_debug_flags(wlan_if_t vaphandle, u_int64_t val)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int category, debug_any = 0;

    for (category = 0; category < IEEE80211_MSG_MAX; category++) {
        int category_mask = (val >> category) & 0x1;
        asf_print_mask_set(&vap->iv_print, category, category_mask);
        asf_print_mask_set(&ic->ic_print, category, category_mask);
        debug_any = category_mask ? 1 : debug_any;
    }
    /* Update the IEEE80211_MSG_ANY debug mask bit */
    asf_print_mask_set(&vap->iv_print, IEEE80211_MSG_ANY, debug_any);
    asf_print_mask_set(&ic->ic_print, IEEE80211_MSG_ANY, debug_any);
#if DBG_LVL_MAC_FILTERING
    /* If dbgLVL mac filtering is enabled, inform user */
    if(vap->iv_print.dbgLVLmac_on)
    {
        qdf_nofl_info("Note: dbgLVL mac filtering is currently enabled.\n");
    }
#endif

    return 0;
}

u_int64_t wlan_get_debug_flags(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    u_int64_t res = 0;
    int byte_s, total_bytes = sizeof(res);
    u_int8_t *iv_print_ptr = &vap->iv_print.category_mask[0];

    for (byte_s = 0; byte_s < total_bytes; byte_s++) {
        res |= ((u_int64_t)iv_print_ptr[byte_s]) << (byte_s * 8);
    }
    return res;
}

int wlan_get_chanlist(wlan_if_t vaphandle, u_int8_t *chanlist)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    memcpy(chanlist, ic->ic_chan_active_2g_5g, sizeof(ic->ic_chan_active_2g_5g));
    return 0;
}

int wlan_get_chaninfo(wlan_if_t vaphandle, bool is_160chan_info,
                      struct ieee80211_ath_channel *chan,
                      struct ieee80211_channel_info *chan_info,
                      int *nchan)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    return wlan_radio_get_chan_info(ic, is_160chan_info, chan, chan_info, nchan);
}

int wlan_radio_get_chan_info(struct ieee80211com *ic,
                             bool is_160chan_info,
                             struct ieee80211_ath_channel *chan,
                             struct ieee80211_channel_info *chan_info,
                             int *nchan)
{
   ieee80211_get_channel_list(ic, chan, chan_info, nchan, is_160chan_info);
   return 0;
}

qdf_export_symbol(wlan_radio_get_chan_info);

u_int32_t
wlan_get_HWcapabilities(wlan_dev_t devhandle, ieee80211_cap cap)
{
    struct ieee80211com *ic = devhandle;
    u_int32_t val = 0;

    switch (cap) {
    case IEEE80211_CAP_SHSLOT:
        val = (ic->ic_caps & IEEE80211_C_SHSLOT) ? 1 : 0;
        break;

    case IEEE80211_CAP_SHPREAMBLE:
        val = (ic->ic_caps & IEEE80211_F_SHPREAMBLE) ? 1 : 0;
        break;

    case IEEE80211_CAP_MULTI_DOMAIN:
        val = (ic->ic_country.isMultidomain) ? 1 : 0;
        break;

    case IEEE80211_CAP_WMM:
        val = (ic->ic_caps & IEEE80211_C_WME) ? 1 : 0;
        break;

    case IEEE80211_CAP_HT:
        val = (ic->ic_caps & IEEE80211_C_HT) ? 1 : 0;
        break;

    case IEEE80211_CAP_PERF_PWR_OFLD:
        val = (ic->ic_caps_ext & IEEE80211_CEXT_PERF_PWR_OFLD) ? 1 : 0;
        break;

    case IEEE80211_CAP_11AC:
        val = (ic->ic_caps_ext & IEEE80211_CEXT_11AC) ? 1 : 0;
        break;

    default:
        break;
    }

    return val;
}

int wlan_get_current_phytype(struct ieee80211com *ic)
{
  return(ic->ic_phytype);
}

int
ieee80211_get_desired_ssid(struct ieee80211vap *vap, int index, ieee80211_ssid **ssid)
{
    if (index > vap->iv_des_nssid) {
        return -EOVERFLOW;
    }

    *ssid = &(vap->iv_des_ssid[index]);
    return 0;
}

int
ieee80211_get_desired_ssidlist(struct ieee80211vap *vap,
                               ieee80211_ssid *ssidlist,
                               int nssid)
{
    int i;

    if (nssid < vap->iv_des_nssid)
        return -EOVERFLOW;

    for (i = 0; i < vap->iv_des_nssid; i++) {
        ssidlist[i].len = vap->iv_des_ssid[i].len;
        OS_MEMCPY(ssidlist[i].ssid,
                  vap->iv_des_ssid[i].ssid,
                  ssidlist[i].len);
    }

    return vap->iv_des_nssid;
}

int
wlan_get_desired_ssidlist(wlan_if_t vaphandle, ieee80211_ssid *ssidlist, int nssid)
{
    return ieee80211_get_desired_ssidlist(vaphandle, ssidlist, nssid);
}

#if DBDC_REPEATER_SUPPORT
static int
same_ssid_support_check(struct ieee80211vap *vap, u_int8_t *ssid, int len)
{
    struct ieee80211com *ic= vap->iv_ic, *tmp_ic;
    struct global_ic_list *ic_list = ic->ic_global_list;
    struct ieee80211vap *tmp_vap;
    bool ret;
    int j;

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (ic->ic_mpsta_vap) {
        if(!vap->iv_mpsta && !vap->iv_wrap) {
#else
    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_WRAP_EN) ) {
        if(!dp_wrap_vdev_is_mpsta(vap->vdev_obj) && !dp_wrap_vdev_is_wrap(vap->vdev_obj)) {
#endif
            /* For PSTA, ssid check not needed
               Only needed for MPSTA and WRAP vap*/
            return 0;
        }
    }
#endif

    for (j=0; j < MAX_RADIO_CNT; j++) {
        GLOBAL_IC_LOCK_BH(ic_list);
        tmp_ic = ic_list->global_ic[j];
        GLOBAL_IC_UNLOCK_BH(ic_list);
        if (tmp_ic) {
            TAILQ_FOREACH(tmp_vap, &tmp_ic->ic_vaps, iv_next) {
                if ((tmp_vap != vap) && (vap->iv_opmode != tmp_vap->iv_opmode)) {
#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
                    if (tmp_ic->ic_mpsta_vap) {
                        if(!tmp_vap->iv_mpsta && !tmp_vap->iv_wrap) {
#else
    if (wlan_pdev_nif_feat_cap_get(tmp_ic->ic_pdev_obj, WLAN_PDEV_F_WRAP_EN) ) {
        if(!dp_wrap_vdev_is_mpsta(tmp_vap->vdev_obj) && !dp_wrap_vdev_is_wrap(tmp_vap->vdev_obj)) {
#endif
                            /* For PSTA, ssid check not needed
                               Only needed for MPSTA and WRAP vap*/
                            continue;
                        }
                    }
#endif
                    ret = ieee80211_vap_match_ssid(tmp_vap, ssid, len);
                    if (ret) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
#endif

int
wlan_set_desired_ssidlist(wlan_if_t vaphandle,
                          u_int16_t nssid,
                          ieee80211_ssid *ssidlist)
{

    struct ieee80211vap *vap = vaphandle;
    int i;
#if DBDC_REPEATER_SUPPORT
    struct ieee80211com *ic= vap->iv_ic, *tmp_ic;
    struct global_ic_list *ic_list = ic->ic_global_list;
    bool ret, son_enabled = 0;
    struct wlan_objmgr_pdev *tmp_pdev;
#endif

    if (nssid > IEEE80211_SCAN_MAX_SSID) {
        return -EOVERFLOW;
    }

#if DBDC_REPEATER_SUPPORT
    for (i=0; i < MAX_RADIO_CNT; i++) {
        tmp_ic = ic_list->global_ic[i];
        if (tmp_ic) {
            tmp_pdev = tmp_ic->ic_pdev_obj;
            if (wlan_son_is_pdev_enabled(tmp_pdev)) {
                son_enabled = 1;
                break;
            }
        }
    }
    if (son_enabled) {
        GLOBAL_IC_LOCK_BH(ic_list);
        if (ic_list->same_ssid_support == 1) {
            ic_list->same_ssid_support = 0;
        }
        GLOBAL_IC_UNLOCK_BH(ic_list);
    }
#endif
    for (i = 0; i < nssid; i++) {
        vap->iv_des_ssid[i].len = ssidlist[i].len;
        if (vap->iv_des_ssid[i].len) {
            qdf_mem_zero(vap->iv_des_ssid[i].ssid, sizeof(vap->iv_des_ssid[i].ssid));
            qdf_mem_copy(vap->iv_des_ssid[i].ssid,
                      ssidlist[i].ssid,
                      ssidlist[i].len);
#if DBDC_REPEATER_SUPPORT
           if ((!ic_list->same_ssid_disable) && (!(ic_list->same_ssid_support || son_enabled)))
           {
                ret = same_ssid_support_check(vap, vap->iv_des_ssid[i].ssid, vap->iv_des_ssid[i].len);
                if (ret) {
                   GLOBAL_IC_LOCK_BH(ic_list);
                   qdf_print("Enable same_ssid_support ssid:%s",vap->iv_des_ssid[i].ssid);
                   ic_list->same_ssid_support = 1;
                   GLOBAL_IC_UNLOCK_BH(ic_list);
               }
           }
#endif
        }
    }
    vap->iv_des_nssid = nssid;
    return 0;
}

void
wlan_get_bss_essid(wlan_if_t vaphandle, ieee80211_ssid *essid)
{
    struct ieee80211vap *vap = vaphandle;

    if (vap->iv_bss) {
        essid->len = vap->iv_bss->ni_esslen;
        OS_MEMCPY(essid->ssid,vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);
    }
}

int wlan_set_wmm_param(wlan_if_t vaphandle, wlan_wme_param param, u_int8_t isbss, u_int8_t ac, u_int32_t val)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int retval=EOK;
    struct ieee80211_wme_state *wme = &vap->iv_wmestate;
    enum ieee80211_phymode mode;
    int index = 0;

    if(isbss) {
        wme->wme_flags |= WME_F_BSSPARAM_UPDATED;
    }

    if (vap->iv_bsschan != IEEE80211_CHAN_ANYC) {
        mode = ieee80211_chan2mode(vap->iv_bsschan);
    } else {
        mode = IEEE80211_MODE_AUTO;
    }

    if(vap->iv_wmestate.wme_update != NULL) {
        index = mode;
    } else {
        /* VAP not started & mode not set.Copy to all indexes in ic table */
        index = 0;
        mode = (IEEE80211_MODE_MAX - 1);
        /* copy ic wme struct to initialize vap wme struct */
        memcpy(&vap->iv_wmestate,&ic->ic_wme, sizeof(ic->ic_wme));
    }

    for ( ;index <= mode; index++ )
    {
        switch (param)
        {
        case WLAN_WME_CWMIN:
            if (isbss)
            {
                wme->wme_wmeBssChanParams.cap_wmeParams[ac].wmep_logcwmin = val;
                if ((wme->wme_flags & WME_F_AGGRMODE) == 0)
                {
                    wme->wme_bssChanParams.cap_wmeParams[ac].wmep_logcwmin = val;
                }
                ic->bssPhyParamForAC[ac][index].logcwmin = val;
            }
            else
            {
                wme->wme_wmeChanParams.cap_wmeParams[ac].wmep_logcwmin = val;
                wme->wme_chanParams.cap_wmeParams[ac].wmep_logcwmin = val;
                ic->phyParamForAC[ac][index].logcwmin = val;
            }
            break;
        case WLAN_WME_CWMAX:
            if (isbss)
            {
                wme->wme_wmeBssChanParams.cap_wmeParams[ac].wmep_logcwmax = val;
                if ((wme->wme_flags & WME_F_AGGRMODE) == 0)
                {
                    wme->wme_bssChanParams.cap_wmeParams[ac].wmep_logcwmax = val;
                }
                ic->bssPhyParamForAC[ac][index].logcwmax = val;
            }
            else
            {
                wme->wme_wmeChanParams.cap_wmeParams[ac].wmep_logcwmax = val;
                wme->wme_chanParams.cap_wmeParams[ac].wmep_logcwmax = val;
                ic->phyParamForAC[ac][index].logcwmax = val;
            }
            break;
        case WLAN_WME_AIFS:
            if (isbss)
            {
                wme->wme_wmeBssChanParams.cap_wmeParams[ac].wmep_aifsn = val;
                if ((wme->wme_flags & WME_F_AGGRMODE) == 0)
                {
                    wme->wme_bssChanParams.cap_wmeParams[ac].wmep_aifsn = val;
                }
                ic->bssPhyParamForAC[ac][index].aifsn = val;
            }
            else
            {
                wme->wme_wmeChanParams.cap_wmeParams[ac].wmep_aifsn = val;
                wme->wme_chanParams.cap_wmeParams[ac].wmep_aifsn = val;
                ic->phyParamForAC[ac][index].aifsn = val;
            }
            break;
        case WLAN_WME_TXOPLIMIT:
            if (isbss)
            {
                wme->wme_wmeBssChanParams.cap_wmeParams[ac].wmep_txopLimit = val;
                if ((wme->wme_flags & WME_F_AGGRMODE) == 0)
                {
                    wme->wme_bssChanParams.cap_wmeParams[ac].wmep_txopLimit = val;
                }
                ic->bssPhyParamForAC[ac][index].txopLimit = val;
            }
            else
            {
                wme->wme_wmeChanParams.cap_wmeParams[ac].wmep_txopLimit = val;
                wme->wme_chanParams.cap_wmeParams[ac].wmep_txopLimit = val;
                ic->phyParamForAC[ac][index].txopLimit = val;
            }
            break;
        case WLAN_WME_ACM:
            if (!isbss)
                return -EINVAL;
            /* ACM bit applies to BSS case only */
            wme->wme_wmeBssChanParams.cap_wmeParams[ac].wmep_acm = val;
            if ((wme->wme_flags & WME_F_AGGRMODE) == 0)
                wme->wme_bssChanParams.cap_wmeParams[ac].wmep_acm = val;
            ic->bssPhyParamForAC[ac][index].acm = val;
            break;
        case WLAN_WME_ACKPOLICY:
            if (isbss)
                return -EINVAL;
            /* ack policy applies to non-BSS case only */
            wme->wme_wmeChanParams.cap_wmeParams[ac].wmep_noackPolicy = val;
            wme->wme_chanParams.cap_wmeParams[ac].wmep_noackPolicy = val;
            break;
        default:
            return retval;
        }
    }

    /* Copy local wme params in ic from vap to avoid inconsistency */
    memcpy(&ic->ic_wme.wme_chanParams, &wme->wme_chanParams, sizeof(wme->wme_chanParams));
    ieee80211_wme_updateparams(vap);
    return retval;
}

u_int32_t wlan_get_wmm_param(wlan_if_t vaphandle, wlan_wme_param param, u_int8_t isbss, u_int8_t ac)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_wme_state *wme = &vap->iv_wmestate;
    struct chanAccParams *chanParams = (isbss == 0) ?
            &(wme->wme_chanParams)
            : &(wme->wme_bssChanParams);

    switch (param)
    {
    case WLAN_WME_CWMIN:
        return chanParams->cap_wmeParams[ac].wmep_logcwmin;
        break;
    case WLAN_WME_CWMAX:
        return chanParams->cap_wmeParams[ac].wmep_logcwmax;
        break;
    case WLAN_WME_AIFS:
        return chanParams->cap_wmeParams[ac].wmep_aifsn;
        break;
    case WLAN_WME_TXOPLIMIT:
        return chanParams->cap_wmeParams[ac].wmep_txopLimit;
        break;
    case WLAN_WME_ACM:
        return wme->wme_wmeBssChanParams.cap_wmeParams[ac].wmep_acm;
        break;
    case WLAN_WME_ACKPOLICY:
        return wme->wme_wmeChanParams.cap_wmeParams[ac].wmep_noackPolicy;
        break;
    default:
        break;
    }
    return 0;
}

int wlan_set_muedca_param(wlan_if_t vaphandle, wlan_muedca_param param,
        u_int8_t ac, u_int8_t val)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_muedca_state *muedca = &vap->iv_muedcastate;
    struct ieee80211_wme_state *wme = NULL;

    if (vap->iv_ic->ic_muedca_mode_state != HEMUEDCA_MANUAL_MODE) {
            qdf_err("Manual Mu edca mode not selected");
            return -EINVAL;
    }

    switch(param) {

        case WLAN_MUEDCA_ECWMIN:
            muedca->muedca_paramList[ac].muedca_ecwmin = val;
            break;

        case WLAN_MUEDCA_ECWMAX:
            muedca->muedca_paramList[ac].muedca_ecwmax = val;
            break;

        case WLAN_MUEDCA_AIFSN:
            muedca->muedca_paramList[ac].muedca_aifsn = val;
            break;

        case WLAN_MUEDCA_ACM:
            muedca->muedca_paramList[ac].muedca_acm = val;
            break;

        case WLAN_MUEDCA_TIMER:
            muedca->muedca_paramList[ac].muedca_timer = val;
            break;

        default:
            break;

    }

    /* Increment update count every time a parameter is changed
     * while MU EDCA is enabled. This count will update the STA about any
     * parameter changes that may occur.
     *
     * As a WAR for WFA, the MUEDCA count is updated only in case any STA
     * is connected to the AP. */
    if((vap->iv_he_muedca == IEEE80211_MUEDCA_STATE_ENABLE) &&
            vap->iv_sta_assoc) {
        muedca->muedca_param_update_count =
            ((muedca->muedca_param_update_count + 1) & MUEDCA_MAX_UPDATE_CNT);
        wme = &vap->iv_wmestate;
        /* cap_info has bits set in WME_QOSINFO_COUNT and WME_QOSINFO_UAPSD.
         * Rest of the bits are reserved currently.
         */
        wme->wme_bssChanParams.cap_info = (muedca->muedca_param_update_count & WME_QOSINFO_COUNT) |
                                          (wme->wme_bssChanParams.cap_info & WME_QOSINFO_UAPSD);

        ieee80211vap_set_flag(vap, IEEE80211_F_WMEUPDATE);
    }
    /* Disable dynamic MUEDCA selection if manual selection is chosen.
     * User must explicitly enable to use dynamic muedca param selection.
     */
    muedca->mu_edca_dynamic_state &= ~MUEDCA_DYNAMIC_ALGO_ENABLE_STATE_MASK;
    return EOK;
}

u_int8_t wlan_get_muedca_param(wlan_if_t vaphandle, wlan_muedca_param param,
        u_int8_t ac)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_muedca_state *muedca = &vap->iv_muedcastate;

    if (vap->iv_ic->ic_muedca_mode_state != HEMUEDCA_MANUAL_MODE) {
        qdf_err("Manual Mu edca mode not selected");
        return -EINVAL;
    }

    switch (param) {

        case WLAN_MUEDCA_ECWMIN:
            return muedca->muedca_paramList[ac].muedca_ecwmin;
            break;

        case WLAN_MUEDCA_ECWMAX:
            return muedca->muedca_paramList[ac].muedca_ecwmax;
            break;

        case WLAN_MUEDCA_AIFSN:
            return muedca->muedca_paramList[ac].muedca_aifsn;
            break;

        case WLAN_MUEDCA_ACM:
            return muedca->muedca_paramList[ac].muedca_acm;
            break;

        case WLAN_MUEDCA_TIMER:
            return muedca->muedca_paramList[ac].muedca_timer;
            break;

        default:
            break;

    }
    return 0;
}

int wlan_set_clr_appopt_ie(wlan_if_t vaphandle)
{
    IEEE80211_VAP_LOCK(vaphandle);

    /* Free opt ie buffer */
    vaphandle->iv_opt_ie_maxlen = 0;
    if (vaphandle->iv_opt_ie.ie) {
        OS_FREE(vaphandle->iv_opt_ie.ie);
        vaphandle->iv_opt_ie.ie = NULL;
        vaphandle->iv_opt_ie.length = 0;
    }

    /* Free beacon copy buffer */
    if (vaphandle->iv_beacon_copy_buf) {
        OS_FREE(vaphandle->iv_beacon_copy_buf);
        vaphandle->iv_beacon_copy_buf = NULL;
        vaphandle->iv_beacon_copy_len = 0;
    }
    IEEE80211_VAP_UNLOCK(vaphandle);

    return 0;
}

int wlan_is_hwbeaconproc_active(wlan_if_t vaphandle)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    return ic->ic_is_hwbeaconproc_active(ic);
}
int
wlan_mon_addmac(wlan_if_t vaphandle, u_int8_t *mac)
{
    int hash;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_mac_filter_list *mac_en;
    hash = MON_MAC_HASH(mac);

    IEEE80211_VAP_LOCK(vap);
    LIST_FOREACH(mac_en, &vap->mac_filter_hash[hash], mac_entry) {
        if (IEEE80211_ADDR_EQ(mac,mac_en->mac_addr)){
            qdf_nofl_info("mac already present\n");
            IEEE80211_VAP_UNLOCK(vap);
            return -1;
        }
    }
    if (vap->mac_entries >= MAX_MON_FILTER_ENTRY) {
        qdf_nofl_info("\n cannot exceed more than 32 entries\n");
        IEEE80211_VAP_UNLOCK(vap);
        return -1;
    }
    mac_en = OS_MALLOC(vap->iv_ic->ic_osdev, sizeof( *mac_en), GFP_KERNEL);
    if (mac_en == NULL) {
        qdf_info("alloc failed: mac_en ");
        IEEE80211_VAP_UNLOCK(vap);
        return -1;
    }
    memcpy(mac_en->mac_addr, mac, QDF_MAC_ADDR_SIZE);
    LIST_INSERT_HEAD(&vap->mac_filter_hash[hash], mac_en, mac_entry);

    vap->mac_entries++;
    IEEE80211_VAP_UNLOCK(vap);

    return 0;
}

int
wlan_mon_listmac(wlan_if_t vaphandle)
{
    int hash;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_mac_filter_list *mac_en;
    int ret = -EINVAL;

    IEEE80211_VAP_LOCK(vap);
    for (hash = 0; hash < 32; hash++) {
        LIST_FOREACH(mac_en, &vap->mac_filter_hash[hash], mac_entry) {
            if (mac_en->mac_addr != NULL){
                qdf_nofl_info("THE MAC on hash %d is %02x:%02x:%02x:%02x:%02x:%02x\n",hash, mac_en->mac_addr[0],
                        mac_en->mac_addr[1],mac_en->mac_addr[2],mac_en->mac_addr[3],
                        mac_en->mac_addr[4], mac_en->mac_addr[5]);
		ret = 0;
            }
        }
    }
    IEEE80211_VAP_UNLOCK(vap);

    return ret;
}

int
wlan_mon_delmac(wlan_if_t vaphandle, u_int8_t *mac)
{
    int hash;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_mac_filter_list *mac_en, *temp_mac;
    int ret = -EINVAL;
    hash = MON_MAC_HASH(mac);

    IEEE80211_VAP_LOCK(vap);
    LIST_FOREACH_SAFE(mac_en, &vap->mac_filter_hash[hash], mac_entry, temp_mac) {
        if (IEEE80211_ADDR_EQ(mac,mac_en->mac_addr)){
            LIST_REMOVE(mac_en,mac_entry);
            qdf_nofl_info("rm the mac\n");
            OS_FREE(mac_en);
            vap->mac_entries--;
            ret = 0;
            break;
        }
    }
    IEEE80211_VAP_UNLOCK(vap);

    return ret;
}

void
wlan_mon_flush_maclist(wlan_if_t vaphandle)
{
    int hash;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_mac_filter_list *mac_en, *temp_mac;

    qdf_nofl_info("Flush %d mon_mac_filter entries", vap->mac_entries);
    IEEE80211_VAP_LOCK(vap);
    for (hash = 0; hash < 32; hash++) {
        if (!vap->mac_entries)
            break;
        LIST_FOREACH_SAFE(mac_en, &vap->mac_filter_hash[hash],
                          mac_entry, temp_mac) {
            if (mac_en->mac_addr != NULL) {
                LIST_REMOVE(mac_en,mac_entry);
                OS_FREE(mac_en);
                vap->mac_entries--;
            }
       }
    }
    IEEE80211_VAP_UNLOCK(vap);
}

void
wlan_get_vap_addr(wlan_if_t vaphandle, u_int8_t *mac)
{
    struct ieee80211vap *vap = vaphandle;

    memcpy(mac, vap->iv_myaddr, QDF_MAC_ADDR_SIZE);
}

/* set/get IQUE parameters */
#if ATH_SUPPORT_IQUE
int wlan_set_rtparams(wlan_if_t vaphandle, u_int8_t rt_index, u_int8_t per, u_int8_t probe_intvl)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    if(ic->ic_set_rtparams)
        ic->ic_set_rtparams(ic, rt_index, per, probe_intvl);
    return 0;
}

int wlan_set_acparams(wlan_if_t vaphandle, u_int8_t ac, u_int8_t use_rts, u_int8_t aggrsize_scaling, u_int32_t min_kbps)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    if(ic->ic_set_acparams)
        ic->ic_set_acparams(ic, ac, use_rts, aggrsize_scaling, min_kbps);
    return 0;
}

int wlan_set_hbrparams(wlan_if_t vaphandle, u_int8_t ac, u_int8_t enable, u_int8_t per_low)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    if(ic->ic_set_hbrparams)
        ic->ic_set_hbrparams(vap, ac, enable, per_low);
    return 0;
}

int wlan_set_me_denyentry(wlan_if_t vaphandle, int *denyaddr)
{
    return 0;
}
#endif /* ATH_SUPPORT_IQUE */


#if ATH_SUPPORT_DYNAMIC_VENDOR_IE
int wlan_set_vendorie(wlan_if_t vaphandle, enum ieee80211_vendor_ie_param param, void *vendor_ie)
{
    int ret = 0, ie_size;
    struct ieee80211vap *vap = vaphandle;
    struct wlan_mlme_app_ie* vie_handle = NULL;
    struct ieee80211_wlanconfig_vendorie *vie = (struct ieee80211_wlanconfig_vendorie *) vendor_ie;

    switch(param) {
        case IEEE80211_VENDOR_IE_PARAM_ADD:
        case IEEE80211_VENDOR_IE_PARAM_UPDATE:
                vie->ie.id = IEEE80211_ELEMID_VENDOR;
                ie_size = vie->ie.len + 2 ;  /* total ie elements size */

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: param=%d Vie_handle = %pK sizeof(vie->ie=%d vie->typemap=%2x\n",
                           __func__, param, vie_handle, sizeof(vie->ie), vie->ftype_map);

                if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
                    struct ieee80211com *ic = vap->iv_ic;

                    /* If EMA Ext is enabled, add IE to the AppIE list only if enough Non-Tx Profile space is available*/
                    if (IS_MBSSID_EMA_EXT_ENABLED(ic) &&
                            IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap) &&
                            ((vie->ftype_map & IEEE80211_VENDORIE_INCLUDE_IN_BEACON) ||
                             (vie->ftype_map & IEEE80211_VENDORIE_INCLUDE_IN_PROBE_RES))) {
                        if (ie_size > vap->iv_mbss.available_vendor_ie_space) {
                            qdf_err("Vendor IE size %d beyond available size %d."
                                    " Cannot add to beacon/probe response.",
                                    ie_size, vap->iv_mbss.available_vendor_ie_space);
                            ret = -ENOMEM;
                            break;
                        } else {
                            vap->iv_mbss.available_vendor_ie_space -= ie_size;
                        }
                    }

                    if(vie->ftype_map & IEEE80211_VENDORIE_INCLUDE_IN_BEACON) {
                        wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_BEACON, (u_int8_t*) &vie->ie, ie_size, DEFAULT_IDENTIFIER);
                    }

                    if(vie->ftype_map & IEEE80211_VENDORIE_INCLUDE_IN_ASSOC_RES) {
                        wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_ASSOCRESP, (u_int8_t*) &vie->ie, ie_size, DEFAULT_IDENTIFIER);
                    }
                    if(vie->ftype_map & IEEE80211_VENDORIE_INCLUDE_IN_PROBE_RES) {
                        wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_PROBERESP, (u_int8_t*) &vie->ie, ie_size, DEFAULT_IDENTIFIER);
                    }
                }
                if (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA) {
                    if(vie->ftype_map & IEEE80211_VENDORIE_INCLUDE_IN_ASSOC_REQ) {
                        wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_ASSOCREQ, (u_int8_t*) &vie->ie, ie_size, DEFAULT_IDENTIFIER);
                    }
                    if(vie->ftype_map & IEEE80211_VENDORIE_INCLUDE_IN_PROBE_REQ) {
                        wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_PROBEREQ, (u_int8_t*) &vie->ie, ie_size, DEFAULT_IDENTIFIER);
                    }
                }
             break;

        case IEEE80211_VENDOR_IE_PARAM_REMOVE:
             if(vap->vie_handle != NULL) {
                if (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP)
                {
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_BEACON, (u_int8_t*) &vie->ie);
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_ASSOCRESP, (u_int8_t*) &vie->ie);
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_PROBERESP, (u_int8_t*) &vie->ie);
                }
                if (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)
                {
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_ASSOCREQ, (u_int8_t*) &vie->ie);
                    wlan_mlme_app_ie_delete(vap->vie_handle, IEEE80211_FRAME_TYPE_PROBEREQ, (u_int8_t*) &vie->ie);
                }
             } else {
                qdf_nofl_info("Vendor IE is NUll , please add using wlanconfig command \n");
             }
            break;
        default:
            ret = -EINVAL;
    }

    return ret;
}

int wlan_get_vendorie(wlan_if_t vaphandle, void *vendor_ie, enum _ieee80211_frame_type ftype, u_int32_t *ie_len, u_int8_t *temp_buf)
{
    int retv = 0;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_wlanconfig_vendorie *vie = (struct ieee80211_wlanconfig_vendorie *) vendor_ie;

    if(vap->vie_handle != NULL) {
        retv = wlan_mlme_app_ie_get(vap->vie_handle, ftype , (u_int8_t *) &vie->ie, ie_len, MAX_VENDOR_BUF_LEN,temp_buf);

    } else {

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : Vendor IE is NUll , please add using wlanconfig command\n", __func__);
    }
    return retv;
}
#endif

/*
Monitor filter type definition:
    MON_FILTER_ALL_DISABLE          = 0x0,   //disable all filters
    MON_FILTER_ALL_EN               = 0x01,  //enable all filters
    MON_FILTER_TYPE_OSIF_MAC        = 0x02,  //enable osif MAC addr based filter
    MON_FILTER_TYPE_UCAST_DATA      = 0x04,  //enable htt unicast data filter
    MON_FILTER_TYPE_MCAST_DATA      = 0x08,  //enable htt multicast cast data filter
    MON_FILTER_TYPE_NON_DATA        = 0x10,  //enable htt non-data filter

    MON_FILTER_TYPE_LAST            = 0x1F,  //last
*/
int
wlan_set_monitor_filter(struct ieee80211com* ic, u_int32_t filter_type)
{
    if(filter_type & MON_FILTER_TYPE_OSIF_MAC){
        /*osif layer filter will filter based on matching MAC addr*/
        /*enable mon_filter_osif_mac only after add STA MAC via acfg_mon_addmac*/
        ic->mon_filter_osif_mac = 1;
    } else {
        ic->mon_filter_osif_mac = 0;
    }

    /*HTT RX layer filters will filter based on pkt types*/
    if(filter_type & MON_FILTER_TYPE_UCAST_DATA){
        ic->mon_filter_ucast_data = 1;
    } else {
        ic->mon_filter_ucast_data = 0;
    }

    if(filter_type & MON_FILTER_TYPE_MCAST_DATA){
        ic->mon_filter_mcast_data = 1;
    } else {
        ic->mon_filter_mcast_data = 0;
    }

    if(filter_type & MON_FILTER_TYPE_NON_DATA){
        ic->mon_filter_non_data = 1;
    } else {
        ic->mon_filter_non_data = 0;
    }

    if (filter_type == MON_FILTER_ALL_EN) {
        ic->mon_filter_mcast_data = 1;
        ic->mon_filter_ucast_data = 1;
        ic->mon_filter_non_data = 1;
    }

    if (ic->ic_set_rx_monitor_filter != NULL) {
        ic->ic_set_rx_monitor_filter(ic, filter_type & MON_FILTER_TYPE_LAST);
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops)
        ic->nss_vops->ic_osif_nss_wifi_monitor_set_filter(ic, filter_type);
#endif

    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                        "osif MAC filter=%d\n", ic->mon_filter_osif_mac);
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                        "ucast data filter=%d\n", ic->mon_filter_ucast_data);
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                        "mcast data filter=%d\n", ic->mon_filter_mcast_data);
    IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                        "Non data(mgmt/action etc.) filter=%d\n", ic->mon_filter_non_data);

    return 0;
}

int
ieee80211_set_rnr_bss_param(struct ieee80211com *ic,
        enum ieee80211_rnr_bss_param param_type, int value)
{
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    struct wlan_objmgr_psoc *psoc;
    struct psoc_mlme_obj *mlme_psoc_priv_obj;
    struct wlan_6ghz_rnr_global_cache *rnr;
    int count = 1;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(psoc);
    rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;

    if(!rnr || rnr->rnr_cnt == 0) {
        QDF_TRACE(QDF_MODULE_ID_6GHZ, QDF_TRACE_LEVEL_DEBUG,
                   "rnr is null !!");
        return -1;
    }

    ap_info = (ieee80211_rnr_nbr_ap_info_t *)&rnr->rnr_buf[2];

    tbtt_info = ap_info->tbtt_info;

     while (count <= rnr->rnr_cnt) {
         switch (param_type) {
             case RNR_BSS_PARAM_MEMBER_ESS_24G_5G_CO_LOCATED_AP:
                 tbtt_info->bss_params.colocated_lower_band_ess = value;
                break;
             case RNR_BSS_PARAM_UNSOLICITED_PROBE_RESPONSE_ACTIVE:
                 tbtt_info->bss_params.probe_resp_20tu_active = value;
                 break;
             default:
                 break;
         }
         tbtt_info++;
         count++;
     }

     /* Template update for legacy vaps and 6G vaps */
     wlan_tmpl_update_lower_band_vdevs(wlan_pdev_get_psoc(ic->ic_pdev_obj));

     wlan_tmpl_update_6ghz_frm();

    return 0;
}
qdf_export_symbol(ieee80211_set_rnr_bss_param);

void ieee80211_user_rnr_frm_update(struct ieee80211com *ic,
                                  int value, bool is_buf_update)
{
    struct ieee80211vap *tmp_vap;
    bool is_mbssid_enable = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                            WLAN_PDEV_F_MBSS_IE_ENABLE);

    if (is_buf_update ||
        WLAN_USER_RNR_BCN_UPDATE_CHECK(ic->ic_user_rnr_frm_ctrl,
                                       value)) {
        ic->ic_user_rnr_frm_ctrl = value;
        if (is_mbssid_enable && ic->ic_mbss.transmit_vap) {
            ic->ic_mbss.transmit_vap->iv_oob_update = 1;
            wlan_vdev_beacon_update(ic->ic_mbss.transmit_vap);
            ic->ic_mbss.transmit_vap->iv_oob_update = 0;
        } else {
            TAILQ_FOREACH(tmp_vap, &ic->ic_vaps, iv_next) {
                if (tmp_vap && tmp_vap->iv_opmode == IEEE80211_M_HOSTAP &&
                    ieee80211_is_vap_state_running(tmp_vap)) {
                    tmp_vap->iv_oob_update = 1;
                    wlan_vdev_beacon_update(tmp_vap);
                    tmp_vap->iv_oob_update = 0;
                }
            }
        }
    }
}
qdf_export_symbol(ieee80211_user_rnr_frm_update);

#if ATH_SUPPORT_NAC

#define NAC_STATUS_NO_FREE_SLOT         -2
#define NAC_STATUS_FAILED_ADD_OR_DEL    -1

static int
is_nac_valid_mac(char *addr)
{
    char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (IEEE80211_IS_MULTICAST(addr) ||
        IEEE80211_ADDR_EQ(addr, nullmac)) {
        return 0;
    }
    return 1;
}

static int wlan_nac_add_mac(wlan_if_t vap, struct ieee80211_nac_info vap_nac_maclist[],
           char *macaddr, int mac_listsize, uint8_t nac_type)
{
    int i, free_slot = -1;
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    struct ieee80211vap *tmpvap = NULL;

    /* For HKv2 check if this client is already self client */
    if (ic->ic_hw_nac_monitor_support && nac_type == IEEE80211_NAC_MACTYPE_CLIENT) {
        ni = ieee80211_find_node(ic, (uint8_t *)macaddr, WLAN_MLME_SB_ID);
        if (ni) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s: NAC client is Self client\n",__func__);
            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            return NAC_STATUS_FAILED_ADD_OR_DEL;
        }
    }

    /* Check if NAC addr is same as any self vaps addr and drop if so */
    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if (IEEE80211_ADDR_EQ(macaddr, tmpvap->iv_myaddr)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s: NAC addr is same as self Vap's addr\n",__func__);
            return NAC_STATUS_FAILED_ADD_OR_DEL;
        }
    }

    /* try to find repeater with the mac and update the caps */
    for(i = 0; i < mac_listsize; i++) {
        if (IEEE80211_ADDR_EQ(vap_nac_maclist[i].macaddr, macaddr)) {

            qdf_nofl_info("%s:Address byte[0][5]=%2x:%2x: is already added \n", __func__, macaddr[0], macaddr[5]);
            return NAC_STATUS_FAILED_ADD_OR_DEL;
        }
        if (!is_nac_valid_mac(vap_nac_maclist[i].macaddr)) {
            if (free_slot == -1)
                free_slot = i;
        }
    }
#if ATH_SUPPORT_NAC_RSSI
{
    struct ieee80211_nac_rssi *vap_nac_rssi = &vap->iv_nac_rssi;
    /*nac_rssi command cant be configured with nac at the same time. vap_nac_rssi->bssid_mac should be null*/
    if (is_nac_valid_mac(vap_nac_rssi->bssid_mac)) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: nac_rssi bssid configured \n",__func__);
        return NAC_STATUS_FAILED_ADD_OR_DEL;
    }
}
#endif

    if (free_slot == -1) {
        qdf_nofl_info("%s No free slot to Add addr bytes[0][5]=%2x:%2x \n",__func__, macaddr[0], macaddr[5]);
        return NAC_STATUS_NO_FREE_SLOT;
    } else {
         /* configure the NAC Addr */
        IEEE80211_ADDR_COPY(vap_nac_maclist[free_slot].macaddr, macaddr);
        vap_nac_maclist[free_slot].avg_rssi = 0;
	vap_nac_maclist[free_slot].rssi = 0;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s Macaddress Slot %d Added Bytes[0][5]=%2x %2x \n", __func__,
                     free_slot, vap_nac_maclist[free_slot].macaddr[0], vap_nac_maclist[free_slot].macaddr[5]);
        return free_slot;
    }
}

static int wlan_nac_del_mac(wlan_if_t vap, struct ieee80211_nac_info vap_nac_maclist[], char *macaddr, int mac_listsize)
{
    int i, empty_slot =-1;

    for(i = 0; i < mac_listsize; i++) {
        if (IEEE80211_ADDR_EQ(vap_nac_maclist[i].macaddr, macaddr)) {
            empty_slot =i;
            break;
        }
    }

    if (i == mac_listsize) {
        qdf_nofl_info("%s:Address %2x:%2x:%2x:%2x:%2x:%2x is not in nac list \n",__func__, macaddr[0],
               macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
        return NAC_STATUS_FAILED_ADD_OR_DEL;
    }

    /* clear table for the mac */
    OS_MEMZERO(vap_nac_maclist[i].macaddr, QDF_MAC_ADDR_SIZE);
    vap_nac_maclist[i].avg_rssi = 0;
    vap_nac_maclist[i].rssi = 0;
    vap_nac_maclist[i].rssi_measured_time = 0;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s Macaddress Slot %d removed:%2x %2x \n", __func__,
                         i,vap_nac_maclist[i].macaddr[0],vap_nac_maclist[i].macaddr[5]);
    return empty_slot;
}

int wlan_set_nac(wlan_if_t vaphandle, enum ieee80211_nac_param param, void *in_nac)
{
    int ret = 0, i;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_wlanconfig_nac *nac = (struct ieee80211_wlanconfig_nac *) in_nac;
    struct ieee80211_nac *vap_nac = &vap->iv_nac;
    int max_addrlimit = vap->iv_neighbour_get_max_addrlimit(vap, nac->mac_type);

    if (!max_addrlimit)
	return -EINVAL;

    switch(param) {
        case IEEE80211_NAC_PARAM_ADD:

            for(i=0; i < max_addrlimit; i++) {

                 if (!is_nac_valid_mac(nac->mac_list[i])) {
                     IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Idx %d - Not valid macaddres[0][5]-%2x%2x \n",
                                        __func__,i,nac->mac_list[i][0],nac->mac_list[i][5]);
                     continue;
                 }

                 if(nac->mac_type == IEEE80211_NAC_MACTYPE_BSSID) {
                     /* Return with success for HKv2 case even though
                      * we don't use BSSID. If sent to FW, it gets
                      * programmed to AST just as in HKv1 case, hence
                      * we avoid sending to FW.
                      */
                    if (vap->iv_ic->ic_hw_nac_monitor_support) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL | IEEE80211_MSG_NAC,
                                          "%s:Bssid not required for HKv2\n", __func__);
                         return 0;
                    }
                     /*  Bssid added to the vap nac bssid list  */
                     ret = wlan_nac_add_mac(vap, vap_nac->bssid, nac->mac_list[i],
                           max_addrlimit, nac->mac_type);

                     /* Fill in respective handler and  send to target for adding bssid  */
                     if(vap->iv_neighbour_rx && ret >= 0) {
                         /* Bssid idx starts from 1 in target */
                         vap->iv_neighbour_rx(vap , ret +1, IEEE80211_NAC_PARAM_ADD, IEEE80211_NAC_MACTYPE_BSSID, nac->mac_list[i]);
                     }

                 } else if (nac->mac_type == IEEE80211_NAC_MACTYPE_CLIENT) {

                     /*  client added to the vap nac bssid list  */
                     ret = wlan_nac_add_mac(vap, vap_nac->client, nac->mac_list[i],
                           max_addrlimit, nac->mac_type);

                     /* Fill in respective handler and  send to target for adding client */
                     if(vap->iv_neighbour_rx && ret >= 0) {
                         /* client idx starts from 1 in target */
                         vap->iv_neighbour_rx(vap , ret, IEEE80211_NAC_PARAM_ADD, IEEE80211_NAC_MACTYPE_CLIENT,
                                              nac->mac_list[i]);
                     }
                 }
             }

             break;

        case IEEE80211_NAC_PARAM_DEL:

            for(i=0 ; i < max_addrlimit; i++) {

                 if (!is_nac_valid_mac(nac->mac_list[i])) {
                     IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Idx %d - Not valid macaddres[0][5]-%2x%2x \n",
                                        __func__,i,nac->mac_list[i][0],nac->mac_list[i][5]);
                     continue;
                 }

                 if(nac->mac_type == IEEE80211_NAC_MACTYPE_BSSID) {

                     /*  Bssid deleted from vap nac bssid list */
                     ret = wlan_nac_del_mac(vap, vap_nac->bssid, nac->mac_list[i] , max_addrlimit );

                     /* Fill in respective handler and  send to target for deleting bssid  */
                     if(vap->iv_neighbour_rx && ret >= 0) {
                         /* Bssid idx starts from 1 in target */
                         vap->iv_neighbour_rx(vap ,ret+1, IEEE80211_NAC_PARAM_DEL, IEEE80211_NAC_MACTYPE_BSSID, nac->mac_list[i]);
                     }

                 } else if (nac->mac_type == IEEE80211_NAC_MACTYPE_CLIENT) {

                     /*  client deleted from vap nac bssid list */
                     ret = wlan_nac_del_mac(vap, vap_nac->client, nac->mac_list[i] , max_addrlimit );

                     if(vap->iv_neighbour_rx && ret >= 0) {
                         /* client idx starts from 1 in target */
                         vap->iv_neighbour_rx(vap , ret, IEEE80211_NAC_PARAM_DEL, IEEE80211_NAC_MACTYPE_CLIENT, nac->mac_list[i]);
                     }
                 }
            }
            break;

        default:
            ret = -EINVAL;
    }

    return ret;
}

int wlan_list_nac(wlan_if_t vaphandle, enum ieee80211_nac_param param, void *in_nac) {

    int i,j;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_wlanconfig_nac *nac = (struct ieee80211_wlanconfig_nac *) in_nac;
    struct ieee80211_nac_info  *nac_list;
    int max_addrlimit = vap->iv_neighbour_get_max_addrlimit(vap, nac->mac_type);

    if (!max_addrlimit)
	return -EINVAL;

    /* based on mac type point nac list to either bssid or client list */
    if ( nac->mac_type == IEEE80211_NAC_MACTYPE_BSSID ) {
        nac_list = vap->iv_nac.bssid;
    } else if ( nac->mac_type == IEEE80211_NAC_MACTYPE_CLIENT ) {
        nac_list = vap->iv_nac.client;
    } else {
       return -1;
    }

    for(i=0,j=0; i < max_addrlimit && j < max_addrlimit; i++) {

        if (!is_nac_valid_mac((char *) (nac_list +i)->macaddr)) {
            continue;
        }
        vap->iv_neighbour_rx(vap , i, IEEE80211_NAC_PARAM_LIST, IEEE80211_NAC_MACTYPE_CLIENT, (nac_list +i)->macaddr);
        OS_MEMCPY(nac->mac_list[j] , (nac_list +i)->macaddr, QDF_MAC_ADDR_SIZE);
        nac->rssi[j] = (nac_list + i)->avg_rssi;
        nac->ageSecs[j] = CONVERT_SYSTEM_TIME_TO_SEC(
            OS_GET_TIMESTAMP() - (nac_list + i)->rssi_measured_time);

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: Nac->mac_list[%d]=%2x%2x \n", __func__,j,nac->mac_list[j][0],nac->mac_list[j][5]);

        j++;
    }
    return 0;
}
#endif

#if ATH_SUPPORT_NAC_RSSI

static int wlan_nac_rssi_add_mac(wlan_if_t vap, char *bssid_macaddr, char *client_macaddr, u_int8_t  chan_num, int *chagrchan)
{
    struct ieee80211com *ic = vap->iv_ic;
    const struct ieee80211_ath_channel *c = ic->ic_curchan;
    struct ieee80211_nac_rssi *vap_nac_rssi_info =  &vap->iv_nac_rssi;
    char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    qdf_freq_t freq;

    *chagrchan = 0;
    freq = wlan_reg_legacy_chan_to_freq(ic->ic_pdev_obj, chan_num);
    if ((IEEE80211_IS_CHAN_5GHZ(c)) && (WLAN_REG_IS_24GHZ_CH_FREQ(freq))) {
        qdf_nofl_info("%s:chan num is worng in the vap \n", __func__);
        return -2;
    }
    if (IEEE80211_IS_CHAN_5GHZ(c)) {
        /*home channel is same as configured channel number, no need to switch channel*/
        if (c->ic_ieee !=  chan_num) {
            *chagrchan = 1;
        }
    }
    else if (IEEE80211_IS_CHAN_2GHZ(c)) {
        /*home channel is same as configured channel number, no need to switch channel*/
        if (c->ic_ieee !=  chan_num) {
            *chagrchan = 1;
        }
    } else {
        qdf_nofl_info("%s: no support in 6G \n", __func__);
        return -2;
    }

    vap_nac_rssi_info->chan_num = chan_num;
    if ((IEEE80211_ADDR_EQ(vap_nac_rssi_info->bssid_mac, nullmac)) &&
        (IEEE80211_ADDR_EQ(vap_nac_rssi_info->client_mac, nullmac))) {
        /* configure the NAC_RSSI Addr */
        IEEE80211_ADDR_COPY(vap_nac_rssi_info->bssid_mac, bssid_macaddr);
        IEEE80211_ADDR_COPY(vap_nac_rssi_info->client_mac, client_macaddr);

        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s  Added BSSID Bytes[0][5]"
            "=%2x %2x client Bytes[0][5]=%2x %2x \n", __func__, vap_nac_rssi_info->bssid_mac[0],
            vap_nac_rssi_info->bssid_mac[5], vap_nac_rssi_info->client_mac[0],
            vap_nac_rssi_info->client_mac[5], chan_num);

        /* Fill in respective handler and  send to target for adding bssid  */
        if(vap->iv_scan_nac_rssi) {
            /* Bssid idx starts from 1 in target */
            vap->iv_scan_nac_rssi(vap , IEEE80211_NAC_RSSI_PARAM_ADD,
                                 bssid_macaddr, client_macaddr, chan_num);
        }
    }
    else if (!(IEEE80211_ADDR_EQ(vap_nac_rssi_info->bssid_mac, bssid_macaddr)) ||
              !(IEEE80211_ADDR_EQ(vap_nac_rssi_info->client_mac, client_macaddr))) {

        qdf_nofl_info("%s:Existed entry: BSSID byte[0][5]=%2x:%2x  Client byte[0][5]=%2x:%2x\n",
                __func__, vap_nac_rssi_info->bssid_mac[0], vap_nac_rssi_info->bssid_mac[5],
                vap_nac_rssi_info->client_mac[0], vap_nac_rssi_info->client_mac[5]);
        return -1;
    }
    return 0;
}


static int wlan_nac_rssi_del_mac(wlan_if_t vap, char *bssid_macaddr, char *client_macaddr)
{
    struct ieee80211_nac_rssi *vap_nac_rssi_info =  &vap->iv_nac_rssi;

    if (!IEEE80211_ADDR_EQ(vap_nac_rssi_info->bssid_mac, bssid_macaddr)) {
        qdf_nofl_info("%s:BSSID Address byte[0][5]=%2x:%2x: was not added \n", __func__,
               bssid_macaddr[0], bssid_macaddr[5]);
        return -1;
    }
    if (!IEEE80211_ADDR_EQ(vap_nac_rssi_info->client_mac, client_macaddr)) {

        qdf_nofl_info("%s:client address byte[0][5]=%2x:%2x: was not added \n", __func__,
               client_macaddr[0], client_macaddr[5]);
        return -1;
    }

    /* clear table for the mac */
    OS_MEMZERO(vap_nac_rssi_info->bssid_mac, QDF_MAC_ADDR_SIZE);
    OS_MEMZERO(vap_nac_rssi_info->client_mac, QDF_MAC_ADDR_SIZE);
    vap_nac_rssi_info->chan_num =0;
    vap_nac_rssi_info->client_rssi = 0;
    vap_nac_rssi_info->client_rssi_valid = 0;
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s BSSID Bytes[0][5]=%2x %2x "
                      "client Bytes[0][5]=%2x %2x removed \n", __func__,
                      bssid_macaddr[0], bssid_macaddr[5], client_macaddr[0],
                      client_macaddr[5]);
     /* Fill in respective handler and  send to target for deleting bssid  */
     if(vap->iv_scan_nac_rssi ) {
         /* delete BSSID in target*/
         vap->iv_scan_nac_rssi(vap , IEEE80211_NAC_RSSI_PARAM_DEL, bssid_macaddr,
                               client_macaddr, 0);
     }
    return 0;
}

int wlan_nac_rssi_chanchgr(wlan_if_t vap, u_int8_t  chan_num)
{
    #define CHANNEL_LOAD_REQUESTED 2
    int ret = 0;
    u_int32_t val = 1;
    struct ieee80211com *ic = vap->iv_ic;
    const struct ieee80211_ath_channel *c = ic->ic_curchan;
    ieee80211_freqlist_t list;
    ieee80211_freqlist_t current_list;
    uint8_t band = WLAN_BAND_UNSPECIFIED;

    if (IEEE80211_IS_CHAN_5GHZ(c)) {
        /*home channel is same as configured channel number, no need to switch channel*/
        if (c->ic_ieee ==  chan_num) {
            return  ret;
        }
    }
    else if (IEEE80211_IS_CHAN_2GHZ(c)) {
        /*home channel is same as configured channel number, no need to switch channel*/
        if (c->ic_ieee ==  chan_num) {
            return  ret;
        }
    } else {
        qdf_nofl_info("%s: no support in 6G\n",__func__);
	return -EINVAL;
    }

    OS_MEMZERO(&list, sizeof (ieee80211_freqlist_t));
    OS_MEMZERO(&current_list, sizeof (ieee80211_freqlist_t));
    list.n_freqs = 1;
    list.freqs[0] = wlan_get_wlan_band_id_chan_to_freq(
            ic->ic_pdev_obj, chan_num, band);

    current_list.n_freqs = wlan_acs_get_user_chanlist(vap,current_list.freqs);
    if (wlan_acs_set_user_chanlist(vap, false, &list.freqs[0]) != EOK) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSSCAN,
                            "%s Failed to set user channel", __func__);
        return -EINVAL;
    }

    /* starting the ACS scan */
    if (wlan_acs_start_scan_report(vap, 1, IEEE80211_START_ACS_REPORT, (void *)&val) != EOK) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSSCAN,
                             "%s Failed to start ACS scan", __func__);
        return -EINVAL;
    }

    if (wlan_acs_set_user_chanlist(vap, false, &current_list.freqs[0]) != EOK) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSSCAN,
                             "%s Failed to set user channel after ", __func__);
        return -EINVAL;
    }

    return ret;
}

int wlan_set_nac_rssi(wlan_if_t vaphandle, enum ieee80211_nac_param param, void *in_nac)
{
    int ret = 0;
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_wlanconfig_nac_rssi *nac_rssi = (struct ieee80211_wlanconfig_nac_rssi *) in_nac;
    char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int changeChannel = 0;

    switch(param) {
        case IEEE80211_NAC_RSSI_PARAM_ADD:
#if ATH_SUPPORT_NAC
            {
                struct ieee80211_nac *vap_nac = &vap->iv_nac;
                int i;

                /*nac_rssi command cant be configured with nac at the same time. vap_nac->bssid should be null*/
                for(i=0; i < NAC_MAX_BSSID; i++) {

                     if (!IEEE80211_ADDR_EQ(vap_nac->bssid[i].macaddr, nullmac)) {
                         IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: nac bssid configured \n",__func__);
                         return -1;
                     }
                }
            }
#endif
            if (IEEE80211_IS_MULTICAST(nac_rssi->mac_bssid) ||
                            IEEE80211_ADDR_EQ((nac_rssi->mac_bssid), nullmac)) {
                qdf_nofl_info(" BSSID - Not valid macaddres, unicast macaddrs is required \n");
                return -1;
            }

            if (IEEE80211_IS_MULTICAST(nac_rssi->mac_client) ||
                           IEEE80211_ADDR_EQ((nac_rssi->mac_client), nullmac)) {
                qdf_nofl_info(" client - Not valid macaddres, unicast macaddrs is required \n");
                return -1;
            }

	    if (!(((nac_rssi->chan_num >= 30) && (nac_rssi->chan_num <= 165)) ||
                   ((nac_rssi->chan_num >= 1) && (nac_rssi->chan_num <= 14)))) {

                qdf_nofl_info("%s:chan num should be between 1~14, or 30~165 \n", __func__);
                return -1;
            }

	    ret = wlan_nac_rssi_add_mac(vap, nac_rssi->mac_bssid, nac_rssi->mac_client,
                                        nac_rssi->chan_num, &changeChannel);
            if ((0 != changeChannel) && (ret >= 0)) {
                ret = wlan_nac_rssi_chanchgr(vaphandle, nac_rssi->chan_num);
            }
            break;

        case IEEE80211_NAC_RSSI_PARAM_DEL:

            if (IEEE80211_IS_MULTICAST(nac_rssi->mac_bssid) ||
                            IEEE80211_ADDR_EQ((nac_rssi->mac_bssid), nullmac)) {
                qdf_nofl_info(" BSSID - Not valid macaddres, unicast macaddrs is required \n");
                return -1;
            }

            if (IEEE80211_IS_MULTICAST(nac_rssi->mac_client) ||
                           IEEE80211_ADDR_EQ((nac_rssi->mac_client), nullmac)) {
                qdf_nofl_info(" client - Not valid macaddres, unicast macaddrs is required \n");
                return -1;
            }

            /*  Bssid deleted from vap nac_rssi */
            ret = wlan_nac_rssi_del_mac(vap, nac_rssi->mac_bssid, nac_rssi->mac_client);
            break;
        case IEEE80211_NAC_RSSI_PARAM_LIST:
            break;
        default:
            ret = -EINVAL;
    }

    return ret;
}
int wlan_list_nac_rssi(wlan_if_t vaphandle, enum ieee80211_nac_param param, void *in_nac) {

    struct ieee80211vap *vap = vaphandle;
    struct ieee80211_wlanconfig_nac_rssi *nac_Rssi = (struct ieee80211_wlanconfig_nac_rssi *) in_nac;
    struct ieee80211_nac_rssi *vap_nac_rssi_info =  &vap->iv_nac_rssi;

    if(vap->iv_scan_nac_rssi) {
         /* Bssid idx starts from 1 in target */
         vap->iv_scan_nac_rssi(vap , IEEE80211_NAC_RSSI_PARAM_LIST,
                              vap_nac_rssi_info->bssid_mac,
                              vap_nac_rssi_info->client_mac, 0);
    }

    OS_MEMCPY(nac_Rssi->mac_bssid, vap->iv_nac_rssi.bssid_mac , QDF_MAC_ADDR_SIZE);
    OS_MEMCPY(nac_Rssi->mac_client, vap->iv_nac_rssi.client_mac, QDF_MAC_ADDR_SIZE);
    nac_Rssi->chan_num = vap->iv_nac_rssi.chan_num;
    nac_Rssi->client_rssi = vap->iv_nac_rssi.client_rssi;
    nac_Rssi->client_rssi_valid = vap->iv_nac_rssi.client_rssi_valid;

    return 0;
}
#endif

QDF_STATUS wlan_mesh_set_peer_latency_param_config(wlan_if_t vaphandle,
                struct ieee80211req_athdbg *req)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic  = NULL;
    uint32_t tid, service_interval, burst_size, add_or_sub, dl_ul_enable;

    if (!vap)
        return QDF_STATUS_E_INVAL;

    ic = vap->iv_ic;
    if (!ic)
        return QDF_STATUS_E_INVAL;
    tid = req->data.wlan_latency_info.tid;
    dl_ul_enable = req->data.wlan_latency_info.dl_ul_enable;
    service_interval = req->data.wlan_latency_info.service_interval;
    burst_size = req->data.wlan_latency_info.burst_size;
    add_or_sub = req->data.wlan_latency_info.burst_size_add_or_sub;

    if (tid > 7) {
        QDF_TRACE(QDF_MODULE_ID_MSCS, QDF_TRACE_LEVEL_ERROR,
            "Invalid tid. Valid id is 0 to 7 ");
        return QDF_STATUS_E_INVAL;
    }

    if (dl_ul_enable < 1 || dl_ul_enable > 2) {
        QDF_TRACE(QDF_MODULE_ID_MSCS, QDF_TRACE_LEVEL_ERROR,
            "Invalid operation. shoule be 1 for addition or 2 for substraction");
        return QDF_STATUS_E_INVAL;
    }

    if (add_or_sub < 1 || add_or_sub > 2) {
        QDF_TRACE(QDF_MODULE_ID_MSCS, QDF_TRACE_LEVEL_ERROR,
            "Invalid operation. shoule be 1 for addition or 2 for substraction");
        return QDF_STATUS_E_INVAL;
    }
    return ic->ic_set_peer_latency_param_config(ic,
			req->data.wlan_latency_info.peer_mac, tid,
            dl_ul_enable, service_interval, burst_size, add_or_sub);
}

#if QCA_SUPPORT_PEER_ISOLATION
static int peer_isolation_add_mac(u_int8_t *mac, struct peer_isolation_list *list)
{
    u_int32_t key;
    struct peer_isolation_entry *peer;
    struct ieee80211vap *vap = qdf_container_of(list,
                                                struct ieee80211vap,
                                                peer_isolation_list);

    /* Allocate peer entry */
    peer = qdf_mem_malloc(sizeof(struct peer_isolation_entry));
    if (!peer) {
        qdf_err("Memory allocation failed");
        return -ENOMEM;
    }

    qdf_spin_lock_bh(&list->lock);
    /* Check if peer already in the list */
    if (peer_isolation_find(mac, list)) {
        qdf_spin_unlock_bh(&list->lock);
        qdf_mem_free(peer);
        qdf_info("Peer alreary exists in Isolation list");
        return -EEXIST;
    }

    /* Check if list is full */
    if(list->num_peers >= vap->iv_ic->ic_def_num_clients) {
        qdf_spin_unlock_bh(&list->lock);
        qdf_mem_free(peer);
        qdf_err("Peer Isolation list full: %d clients", list->num_peers);
        return -ENOSPC;
    }

    qdf_mem_copy(&peer->mac, mac, QDF_MAC_ADDR_SIZE);

    /* Get the Key, Hash table will derive its own key using this */
    key = peer_isolation_hash_key(mac);

    /* Add to hash table */
    qdf_ht_add(list->peer_ht, &peer->node, key);
    list->num_peers++;
    qdf_spin_unlock_bh(&list->lock);

    return 0;
}

static int peer_isolation_del_mac(u_int8_t *mac, struct peer_isolation_list *list)
{
    struct peer_isolation_entry *peer;

    qdf_spin_lock_bh(&list->lock);
    peer = peer_isolation_find(mac, list);
    if (peer) {
        /* Remove from hash table */
        list->num_peers--;
        qdf_ht_remove(&peer->node);
        qdf_spin_unlock_bh(&list->lock);

        /* Free the buffer */
        qdf_mem_free(peer);
    } else {
        qdf_spin_unlock_bh(&list->lock);
        qdf_info("Peer not in Isolation list");
        return -ENOENT;
    }

    return 0;
}

int wlan_peer_isolation_add_mac(wlan_if_t vap, struct ieee80211_wlanconfig_isolation *peer)
{
    int status;

    /* Add to hash table */
    status = peer_isolation_add_mac(peer->mac, &vap->peer_isolation_list);
    if (status != 0)
        return status;

    /* Config the node */
    ieee80211_node_isolation(vap, IEEE80211_PEER_ISOLATION_ADD, peer->mac);

    return status;
}

int wlan_peer_isolation_del_mac(wlan_if_t vap, struct ieee80211_wlanconfig_isolation *peer)
{
    int status;

    /* Remove from hash table */
    status = peer_isolation_del_mac(peer->mac, &vap->peer_isolation_list);

    /* Config the node */
    ieee80211_node_isolation(vap, IEEE80211_PEER_ISOLATION_DEL, peer->mac);

    return status;
}

int wlan_peer_isolation_list(wlan_if_t vap, struct ieee80211_wlanconfig_isolation_list *out)
{
    struct peer_isolation_list *list = &vap->peer_isolation_list;
    struct peer_isolation_entry *peer;
    u_int32_t peer_cnt, bucket;
    u_int8_t *mac;

    mac = &out->buf[0];
    peer_cnt = out->mac_cnt;
    if (!peer_cnt)
        return -EINVAL;

    /* User read from hash table */
    qdf_spin_lock_bh(&list->lock);
    qdf_ht_for_each(list->peer_ht, bucket, peer, node) {
        qdf_mem_copy(mac, peer->mac, IEEE80211_ADDR_LEN);
        mac += IEEE80211_ADDR_LEN;

        if (!(--peer_cnt))
            break;
    }
    out->mac_cnt -= peer_cnt;
    qdf_spin_unlock_bh(&list->lock);

    return 0;
}

int wlan_peer_isolation_flush(wlan_if_t vap)
{
    struct peer_isolation_list *list = &vap->peer_isolation_list;
    struct peer_isolation_entry *peer;
    struct qdf_ht_entry *tmp;
    u_int32_t bucket;

    qdf_spin_lock_bh(&list->lock);
    qdf_ht_for_each_safe(list->peer_ht, bucket, tmp, peer, node) {
        /* Config the node */
        ieee80211_node_isolation(vap, IEEE80211_PEER_ISOLATION_DEL, peer->mac);

        /* Remove from hash table */
        list->num_peers--;
        qdf_ht_remove(&peer->node);

        /* Free the buffer */
        qdf_mem_free(peer);
    }
    qdf_spin_unlock_bh(&list->lock);

    return 0;
}
#endif
