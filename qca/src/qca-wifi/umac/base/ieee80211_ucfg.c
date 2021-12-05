/*
 * Copyright (c) 2016-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/* This is the unified configuration file for iw, acfg and netlink cfg, etc. */
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/if_arp.h>       /* XXX for ARPHRD_ETHER */
#include <net/iw_handler.h>

#include <asm/uaccess.h>

#include "if_media.h"
#include "_ieee80211.h"
#include <osif_private.h>
#include <wlan_opts.h>
#include <ieee80211_var.h>
#include "ieee80211_rateset.h"
#include "ieee80211_vi_dbg.h"
#include "../vendor/generic/ioctl/ioctl_vendor_generic.h"
#include <ol_if_athvar.h>
#include <ol_txrx_dbg.h>
#include "if_athproto.h"
#include "base/ieee80211_node_priv.h"
#include "mlme/ieee80211_mlme_priv.h"
#include "mlme/wlan_mlme_vdev_mgmt_ops.h"
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_vdev_if.h>
#endif
#if DBDC_REPEATER_SUPPORT
#include <qca_multi_link.h>
#endif
#include "ieee80211_crypto_nlshim_api.h"

#include "target_type.h"
#include "ieee80211_ucfg.h"
#include <dp_extap.h>
#include <dp_me.h>
#include <ieee80211_acl.h>
#include "ieee80211_mlme_dfs_dispatcher.h"

#include <wlan_son_ucfg_api.h>
#include <wlan_son_pub.h>
#include "rrm/ieee80211_rrm_priv.h"
#include <ieee80211_cfg80211.h>
#include <wlan_mlme_if.h>

#include <qdf_time.h>

#if QCA_AIRTIME_FAIRNESS
#include <wlan_atf_ucfg_api.h>
#endif /* QCA_AIRTIME_FAIRNESS */

#include <wlan_cmn.h>
#include <wlan_objmgr_cmn.h>
#include <wlan_objmgr_global_obj.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_objmgr_vdev_obj.h>
#include <wlan_objmgr_peer_obj.h>

#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_ucfg_api.h>
#include <wlan_fd_utils_api.h>
#endif /* WLAN_SUPPORT_FILS */

#include "wlan_crypto_global_def.h"
#include "wlan_crypto_global_api.h"

#if WLAN_SUPPORT_SPLITMAC
#include <wlan_splitmac.h>
#endif
#ifdef WLAN_SUPPORT_GREEN_AP
#include <wlan_green_ap_ucfg_api.h>
#endif
#if WLAN_CFR_ENABLE
#include <wlan_cfr_utils_api.h>
#include <wlan_cfr_ucfg_api.h>
#include <ieee80211_ioctl.h>
#endif

#if QCA_SUPPORT_GPR
#include "ieee80211_ioctl_acfg.h"
#endif

#include <wlan_vdev_mgr_utils_api.h>

#if ATH_ACS_DEBUG_SUPPORT
#include "acs_debug.h"
#endif

#ifdef WLAN_CFR_ENABLE
#include <wlan_cfr_public_structs.h>
#endif
#include <scheduler_api.h>
#include <wlan_cm_api.h>
#include <ieee80211_rtt.h>

#if ATH_SUPPORT_WRAP
#if !WLAN_QWRAP_LEGACY
#include "dp_wrap.h"
#endif
#endif

#define ONEMBPS 1000
#define HIGHEST_BASIC_RATE 24000
#define THREE_HUNDRED_FIFTY_MBPS 350000

#define APCHAN_RPT_SSID_FILTER 0b01
#define APCHAN_RPT_OPCLASS_FILTER 0b10

#if UMAC_SUPPORT_QUIET
/*
 * Quiet ie enable flag has 3 bits for now.
 * bit0-enable/disable, bit1-single-shot/continuos & bit3-include/skip
 * quiet ie in swba. So the maximum possible value for this flag is 7 for now.
 */
#define MAX_QUIET_ENABLE_FLAG 7
#endif
extern void set_quality(void *iq, u_int rssi, int16_t chan_nf);
extern int ol_ath_ucfg_get_user_position(wlan_if_t vaphandle, uint32_t aid);
extern int ol_ath_ucfg_get_peer_mumimo_tx_count(wlan_if_t vaphandle,
                                                uint32_t aid);
extern int ol_ath_ucfg_reset_peer_mumimo_tx_count(wlan_if_t vaphandle,
                                                  uint32_t aid);
extern int ieee80211_rate_is_valid_basic(struct ieee80211vap *, u_int32_t);
#if WLAN_SER_UTF
extern void wlan_ser_utf_main(struct wlan_objmgr_vdev *vdev, u_int8_t,
                              u_int32_t);
#endif
#if WLAN_SER_DEBUG
extern void wlan_ser_print_history(struct wlan_objmgr_vdev *vdev, u_int8_t,
                             u_int32_t);
#endif
#if WLAN_SCHED_HISTORY_SIZE
extern void sched_history_print(void);
#endif
#if SM_ENG_HIST_ENABLE
extern void wlan_mlme_print_all_sm_history(void);
#endif
#if MESH_MODE_SUPPORT
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
extern int wlan_update_rawsim_config(struct ieee80211vap *vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
int ieee80211_add_localpeer(wlan_if_t vap, char *params);
int ieee80211_authorise_local_peer(wlan_if_t vap, char *params);
#endif

#if IEEE80211_DEBUG_NODELEAK
void wlan_debug_dump_nodes_tgt(void);
#endif

#ifdef WLAN_DFS_PRECAC_AUTO_CHAN_SUPPORT
extern void ieee80211_autochan_switch_chan_change_csa(struct ieee80211com *ic,
                                                      uint16_t ch_freq,
                                                      uint16_t ch_width);
#endif

extern void wlan_send_omn_action(void *arg, wlan_node_t node);

#ifdef QCA_PARTNER_PLATFORM
extern int wlan_pltfrm_set_param(wlan_if_t vaphandle, u_int32_t val);
extern int wlan_pltfrm_get_param(wlan_if_t vaphandle);
#endif
int ieee80211_config_oce_ipsubnet_id(wlan_if_t vap, char *params);
int ieee80211_config_oce_ess_rpt_param(wlan_if_t vap, char *params);
int ieee80211_config_oce_tx_power(wlan_if_t vap, char *params);
static const int basic_11b_rate[] = {1000, 2000, 5500, 11000 };
static const int basic_11bgn_rate[] = {1000, 2000, 5500, 6000, 11000, 12000, 24000 };
static const int basic_11na_rate[] = {6000, 12000, 24000 };
static const int basic_11ax_6g_rate[] = {6000, 8600, 12000, 17200, 24000, 25800 };

#define HIGHEST_BASIC_RATE 24000    /* Highest rate that can be used for mgmt frames */

#if defined(WLAN_CFR_ENABLE) && defined(WLAN_ENH_CFR_ENABLE)
/**
 * rcc_filter : Flags to indicate the state of RCC filter
 * @rcc_filter_disable : All RCC capture methods are disabled
 * @rcc_filter_enable  : At least one RCC capture method is enabled
 * @rcc_filter_failure : While trying to commit the configuration for any
 *                       of the RCC capture methods, if the commit fails due to
 *                       any reason.
 */
enum rcc_filter {
    rcc_filter_disable = 0,
    rcc_filter_enable = 1,
    rcc_filter_failure = 2,
};
#endif

int ieee80211_config_rsnx(wlan_if_t vap, char *params);

/* Get mu tx blacklisted count for the peer */
void wlan_get_mu_tx_blacklist_cnt(ieee80211_vap_t vaphandle,int value)
{
    bool found = FALSE;

    /**
     * Currently there are no counters to know how long/how many times
     * the peer with the specified AID value has been blacklisted from MU
     * transmission. So as of now, check just if there exists a peer with
     * the specified AID value or not.
     */
    found = ieee80211_validate_aid(vaphandle->iv_ic, value);

    if (!found)
        qdf_err("Invalid AID value");
}

int ieee80211_ucfg_set_essid(wlan_if_t vap, ieee80211_ssid *data, bool is_vap_restart_required)
{
    osif_dev *osifp = (osif_dev *)vap->iv_ifp;
    struct net_device *dev = osifp->netdev;
    ieee80211_ssid   tmpssid;
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);

    if (osifp->is_delete_in_progress)
        return -EINVAL;

    if (opmode == IEEE80211_M_WDS)
        return -EOPNOTSUPP;

    if(data->len <= 0)
        return -EINVAL;

    OS_MEMZERO(&tmpssid, sizeof(ieee80211_ssid));

    if (data->len > IEEE80211_NWID_LEN)
        data->len = IEEE80211_NWID_LEN;

    tmpssid.len = data->len;
    OS_MEMCPY(tmpssid.ssid, data->ssid, data->len);
    /*
     * Deduct a trailing \0 since iwconfig passes a string
     * length that includes this.  Unfortunately this means
     * that specifying a string with multiple trailing \0's
     * won't be handled correctly.  Not sure there's a good
     * solution; the API is botched (the length should be
     * exactly those bytes that are meaningful and not include
     * extraneous stuff).
     */
     if (data->len > 0 &&
            tmpssid.ssid[data->len-1] == '\0')
        tmpssid.len--;

    wlan_set_desired_ssidlist(vap,1,&tmpssid);

    if (tmpssid.len) {
        qdf_nofl_info("DES SSID SET=%s", tmpssid.ssid);
    }


#ifdef ATH_SUPPORT_P2P
    /* For P2P supplicant we do not want start connnection as soon as ssid is set */
    /* The difference in behavior between non p2p supplicant and p2p supplicant need to be fixed */
    /* see EV 73753 for more details */
    if ((osifp->os_opmode == IEEE80211_M_P2P_CLIENT
                || osifp->os_opmode == IEEE80211_M_STA
                || osifp->os_opmode == IEEE80211_M_P2P_GO) && !vap->auto_assoc)
        return 0;
#endif

    if (!is_vap_restart_required) {
        return 0;
    }

    return (IS_UP(dev) &&
            ((osifp->os_opmode == IEEE80211_M_HOSTAP) || /* Call vap init for AP mode if netdev is UP */
             (vap->iv_ic->ic_roaming != IEEE80211_ROAMING_MANUAL))) ? osif_vap_init(dev, RESCAN) : 0;
}

int ieee80211_ucfg_get_essid(wlan_if_t vap, ieee80211_ssid *data, int *nssid)
{
    enum ieee80211_opmode opmode = wlan_vap_get_opmode(vap);

    if (opmode == IEEE80211_M_WDS)
        return -EOPNOTSUPP;

    *nssid = wlan_get_desired_ssidlist(vap, data, 1);
    if (*nssid <= 0)
    {
        if (opmode == IEEE80211_M_HOSTAP)
            data->len = 0;
        else
            wlan_get_bss_essid(vap, data);
    }

    return 0;
}

int ieee80211_ucfg_get_freq(wlan_if_t vap)
{
    osif_dev *osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osif->netdev;
    wlan_chan_t chan;
    int freq;

    if (dev->flags & (IFF_UP | IFF_RUNNING)) {
        chan = wlan_get_bss_channel(vap);
    } else {
        chan = wlan_get_current_channel(vap, true);
    }
    if (chan != IEEE80211_CHAN_ANYC) {
        freq = (int)chan->ic_freq;
    } else {
        freq = 0;
    }

    return freq;
}

int ieee80211_ucfg_set_freq(wlan_if_t vap, uint16_t freq)
{
    int ret;
    struct ieee80211com *ic = vap->iv_ic;

    /* Channel change from user and radar are serialized using IEEE80211_CHANCHANGE_MARKRADAR flag.
     */
    IEEE80211_CHAN_CHANGE_LOCK(ic);
    if (!IEEE80211_CHANCHANGE_STARTED_IS_SET(ic) && !IEEE80211_CHANCHANGE_MARKRADAR_IS_SET(ic)) {
        IEEE80211_CHANCHANGE_STARTED_SET(ic);
        IEEE80211_CHANCHANGE_MARKRADAR_SET(ic);
        IEEE80211_CHAN_CHANGE_UNLOCK(ic);
        ret = ieee80211_ucfg_set_freq_internal(vap, freq);
        IEEE80211_CHANCHANGE_STARTED_CLEAR(ic);
        IEEE80211_CHANCHANGE_MARKRADAR_CLEAR(ic);
    } else {
        IEEE80211_CHAN_CHANGE_UNLOCK(ic);
        qdf_print("Channel Change is already on, Please try later");
        ret = -EBUSY;
    }
    return ret;
}

#ifdef WLAN_DFS_PRECAC_AUTO_CHAN_SUPPORT
static int ieee80211_switch_to_intercac_chan(wlan_if_t vap, uint16_t *freq)
{
    struct wlan_objmgr_pdev *pdev = NULL;
    bool use_inter_chan = false, is_11ax_80_160 = false, is_11ac_80_160 = false;
    bool is_interchan_using_rcac = false;

    pdev = vap->iv_ic->ic_pdev_obj;

    if(pdev == NULL) {
        qdf_err("%s : pdev is null", __func__);
        return -EINVAL;
    }

    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
        QDF_STATUS_SUCCESS) {
        return -EINVAL;
    }

    if (!freq)
        return -EINVAL;

    /*
     * Intermediate chan usage is currently supported for 80MHz only using RCAC
     */
    if (mlme_dfs_is_agile_rcac_enabled(pdev) &&
        (ieee80211_get_chan_width_from_phymode(vap->iv_des_mode) == CH_WIDTH_80MHZ))
        is_interchan_using_rcac = true;

    if (ieee80211_is_phymode_11axa_he80(vap->iv_des_mode) ||
        ieee80211_is_phymode_11axa_he160(vap->iv_des_mode)) {
        is_11ax_80_160 = true;
    } else if (ieee80211_is_phymode_11ac_vht80(vap->iv_des_mode) ||
               ieee80211_is_phymode_11ac_vht160(vap->iv_des_mode)) {
        is_11ac_80_160 = true;
    }

    if (*freq && (mlme_dfs_is_legacy_precac_enabled(pdev) ||
                  mlme_dfs_is_agile_precac_enabled(pdev) ||
                  is_interchan_using_rcac) &&
        (ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) &&
        (is_11ax_80_160 || is_11ac_80_160)) {
        use_inter_chan =
            mlme_dfs_decide_precac_preferred_chan_for_freq(pdev,
                                                           freq,
                                                           phymode2convphymode[vap->iv_des_mode]);
        /*
         * If channel change is triggered in 160MHz,
         * Change mode to 80MHz to use intermediate channel, start precac
         * on configured channel. Send OMN to notify mode change.
         */
         if (ieee80211_is_phymode_160(vap->iv_des_mode) &&
             use_inter_chan) {
             qdf_info("Use intermediate channel in VHT80 mode");
             if (is_11ax_80_160)
                 wlan_set_desired_phymode(vap, IEEE80211_MODE_11AXA_HE80);
             else
                 wlan_set_desired_phymode(vap, IEEE80211_MODE_11AC_VHT80);
             if (vap->iv_is_up) {
                 uint16_t ifreq = *freq;

                 /* Send broadcast OMN*/
                 wlan_set_param(vap, IEEE80211_OPMODE_NOTIFY_ENABLE, 1);
                 /* Send unicast OMN*/
                 wlan_iterate_station_list(vap, wlan_send_omn_action, NULL);
                 if (is_11ax_80_160) {
                     ieee80211_autochan_switch_chan_change_csa(vap->iv_ic,
                                                               ifreq,
                                                               IEEE80211_MODE_11AXA_HE80);
                 } else {
                     ieee80211_autochan_switch_chan_change_csa(vap->iv_ic,
                                                               ifreq,
                                                               IEEE80211_MODE_11AC_VHT80);
                 }
		 wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
                 return EOK;
             }
         }
     }
     wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
     return 1;
}
#else
static inline int ieee80211_switch_to_intercac_chan(wlan_if_t vap, uint16_t *freq)
{
    return 1;
}
#endif

bool ieee80211_is_dot11_channel_mode_valid(struct ieee80211com *ic,
                                             int freq,
                                             int mode,
                                             int cfreq2)
{
    return (ieee80211_find_dot11_channel(ic, freq, cfreq2,
                                         mode | ic->ic_chanbwflag) != NULL);
}

/*
 * ieee80211_ucfg_wideband_channel_switch_sanity:
 * Check if wideband channel switch is supported.
 *
 * @vap        : Pointer to the ic structure
 * @target_freq: Value of the target frequency
 *
 * Return:
 * QDF_STATUS_SUCCESS: Successful
 * QDF_STATUS_E_INVAL: Failure
 */
QDF_STATUS ieee80211_ucfg_wideband_channel_switch_sanity(struct ieee80211vap *vap,
                                      struct ieee80211_ath_channel *target_chan)
{
    struct ieee80211com *ic = NULL;

    if (!vap) {
        qdf_err("vap is invalid");
        return QDF_STATUS_E_INVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("ic is invalid");
        return QDF_STATUS_E_INVAL;
    }

    if (IEEE80211_SKIP_WIDEBAND_SWITCH(vap, target_chan)) {
        qdf_debug("Wideband channel switch is not required");
        return QDF_STATUS_SUCCESS;
    }

    if (!ic->ic_wideband_capable) {
        qdf_err("Wideband not supported on radio");
        return QDF_STATUS_E_INVAL;
    }

    if (!IEEE80211_IS_CHAN_11AXA(ic->ic_curchan) ||
        !IEEE80211_IS_CHAN_11AXA(target_chan)) {
        qdf_err("Current and/or target channel not in 11AXA HE mode");
        return QDF_STATUS_E_INVAL;
    }

    /* The wideband security admission control is applicable only for
     * wideband switches from 5GHz to 6GHz */
    if (IEEE80211_IS_CHAN_6GHZ(target_chan) &&
        IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) &&
        wlan_cfg80211_mbssid_security_admission_control_sanity(ic, true)) {
        qdf_err("Wideband security admission control failed - "
                "sanity check failed");
        return QDF_STATUS_E_INVAL;
    }

    return QDF_STATUS_SUCCESS;
}

/*
 * ieee80211_ucfg_handle_wideband_switch:
 * Handle the wideband channel switch.
 *
 * @vap   : Pointer to the ic structure.
 * @target: Pointer to the desired target channel.
 *
 * Return:
 * QDF_STATUS_SUCCESS: Success
 * QDF_STATUS_E_NOMEM:
 * QDF_STATUS_E_INVAL: Failure
 */
QDF_STATUS ieee80211_ucfg_handle_wideband_channel_switch(struct ieee80211vap *vap,
                                      struct ieee80211_ath_channel *target_chan)
{
    int retval = 0;
    mbss_mode_t target_mode;
    struct ieee80211com *ic = NULL;

    if (!vap) {
        qdf_err("vap is invalid");
        return QDF_STATUS_E_INVAL;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("Invalid ic pointer");
        return QDF_STATUS_E_INVAL;
    }

    if (IEEE80211_SKIP_WIDEBAND_SWITCH(vap, target_chan)) {
        qdf_debug("Wideband channel switch is not required");
        return QDF_STATUS_SUCCESS;
    }

    target_mode = IEEE80211_IS_CHAN_6GHZ(target_chan) ? MBSS_MODE_MBSSID_EMA :
                                                        MBSS_MODE_COHOSTED;

    retval = ieee80211_mbss_switch_mode(ic, target_mode);
    switch (retval) {
        case MBSS_SWITCH_E_NORECOVER_INVAL:
            qdf_err("Could not recover from failed mode switch to %d"
                    "due to invalid params", target_mode);
            retval = QDF_STATUS_E_INVAL;
        break;
        case MBSS_SWITCH_E_NORECOVER_NOMEM:
            qdf_err("Could not recover from failed mode switch to %d "
                    "due to no memory", target_mode);
            retval = QDF_STATUS_E_NOMEM;
        break;
        case MBSS_SWITCH_E_RECOVER:
            qdf_err("Recovered from failed mode switch to %d", target_mode);
            ieee80211_bringup_all_vaps(ic, ALL_VDEVS);
            retval = QDF_STATUS_E_INVAL;
        break;
        case MBSS_SWITCH_SUCCESS:
            qdf_debug("Successfully switched mode to %d", target_mode);
            retval = QDF_STATUS_SUCCESS;
        break;
        default:
            qdf_debug("Invalid return value: %d", retval);
            retval = QDF_STATUS_E_INVAL;
    }

    return retval;
}

#define MAX_PHYMODE_STRLEN 30
static void print_radar_chan_info(struct ieee80211_ath_channel *channel)
{
    char mode_str[MAX_PHYMODE_STRLEN] = {0};
    uint16_t modestr_len;

    ieee80211_convert_phymode_to_string(ieee80211_chan2mode(channel),
                                        mode_str, &modestr_len);

    if (IEEE80211_IS_CHAN_80_80MHZ(channel)) {
        qdf_err("Radar found on chan mode: (%s), prim_freq: %d "
                "prim_80_cfreq: %d, sec_80_cfreq = %d\n",
                mode_str, channel->ic_freq,
                channel->ic_vhtop_freq_seg1, channel->ic_vhtop_freq_seg2);
    } else {
        qdf_err("Radar found on chan mode: (%s), prim_freq: %d\n", mode_str,
                channel->ic_freq);
    }
}

int ieee80211_ucfg_set_freq_internal(wlan_if_t vap, uint16_t freq)
{
    struct ieee80211com *ic = vap->iv_ic;
    osif_dev *osnetdev = (osif_dev *)vap->iv_ifp;
    int retval;
    struct ieee80211vap *tmpvap = NULL;
    struct ieee80211_ath_channel *channel = NULL;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct net_device *tmpdev = NULL;
    enum ieee80211_phymode cur_mode = vap->iv_des_mode;

    if ((freq == 0) && vap->iv_special_vap_mode) {
        /* ACS is not supported for special vap */
        if (!vap->iv_smart_monitor_vap) {
            qdf_err("ACS is not supported with special vap");
            return -EINVAL;
        }

        if (wlan_autoselect_in_progress(vap)) {
            qdf_info("vap = %d, acs in progress, return", vap->iv_unit);
            return 0;
        }
    }

    if (osnetdev->is_delete_in_progress)
        return -EINVAL;

#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
    if(ic->ic_primary_allowed_enable && (freq != 0) &&
                    !(ieee80211_check_allowed_prim_freqlist(ic, freq))) {
            qdf_err("channel freq %d is not a primary allowed channel", freq);
            return -EINVAL;
    }
#endif

    if (freq == 0)
        freq = IEEE80211_FREQ_ANY;

    retval = ieee80211_switch_to_intercac_chan(vap, (uint16_t *)&freq);
    if (retval != 1)
        return retval;

    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s : IBSS desired channel freq(%d)\n",
                __func__, freq);
        return wlan_set_desired_ibsschan(vap, freq);
    }
    else if (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_MONITOR)
    {
#if ATH_CHANNEL_BLOCKING
        struct ieee80211_ath_channel *tmp_channel;
#endif
        if (freq != (uint16_t)IEEE80211_FREQ_ANY) {
            channel = ieee80211_find_dot11_channel(ic, freq, vap->iv_des_cfreq2, vap->iv_des_mode | ic->ic_chanbwflag);
            if (channel == NULL)
            {
                if (wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj, WLAN_SOC_F_STRICT_CHANNEL) && ieee80211_get_num_ap_vaps_up(ic)) {
                    qdf_err("ERROR!! Channel(frequency) %d not compatible with current mode %d\n",
                            freq, vap->iv_des_mode);
                    return -EINVAL;
                }
                channel = ieee80211_find_dot11_channel(ic, freq, 0, IEEE80211_MODE_AUTO);
                if (channel == NULL)
                    return -EINVAL;
            }

            if(ieee80211_check_chan_mode_consistency(ic,vap->iv_des_mode,channel))
            {
                if(IEEE80211_VAP_IS_PUREG_ENABLED(vap))
                    IEEE80211_VAP_PUREG_DISABLE(vap);
                qdf_err("Chan mode consistency failed %d freq %d\n setting to AUTO mode", vap->iv_des_mode,freq);

                if (wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj, WLAN_SOC_F_STRICT_CHANNEL) && ieee80211_get_num_ap_vaps_up(ic)) {
                    qdf_err("ERROR!! Channel(frequency) %d not compatible with current mode %d \
                            failed consistency check\n",
                            freq, vap->iv_des_mode);

                    return -EINVAL;
                }

                TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                    tmpvap->iv_des_mode = IEEE80211_MODE_AUTO;
                    if (wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj, WLAN_SOC_F_STRICT_CHANNEL)) {
                        /*
                         * This needs to be set here.
                         * Start-ap checks iv_des_hw_mode and if it is anything
                         * other than AUTO, start_ap will use iv_des_hw_mode
                         * instead of the value coming through start_ap
                         *
                         * If iv_des_hw_mode is not set to AUTO, it remains in
                         * the older value. Thus when start_ap routine is
                         * called, it will fetch this older value and call
                         * the set_desired_phymode function thus resulting in
                         * failure in case of strict-mode
                         *
                         * Reaching here implies that all VAPs are in the down
                         * state. Refer the osif_num_ap_up_vaps call above
                         *
                         * This problem is unique to changing channel when VAP
                         * is in down state. If the VAP is in up state, then
                         * set_desired_phymode will be called in the MLME state
                         * machine, thereby making iv_des_mode and
                         * iv_des_hw_mode the same
                         *
                         */
                        tmpvap->iv_des_hw_mode = IEEE80211_MODE_AUTO;
                    }
                }
            }

#if ATH_CHANNEL_BLOCKING
            tmp_channel = channel;
            channel = wlan_acs_channel_allowed(vap, channel, vap->iv_des_mode);
            if (channel == NULL)
            {
                qdf_print("channel blocked by acs");
                return -EINVAL;
            }

            if(tmp_channel != channel && ieee80211_check_chan_mode_consistency(ic,vap->iv_des_mode,channel))
            {
                qdf_err("Chan mode consistency failed %x freq %d %d", vap->iv_des_mode, freq ,channel->ic_freq);
                return -EINVAL;
            }
#endif

            if(IEEE80211_IS_CHAN_RADAR(ic, channel))
            {
                print_radar_chan_info(channel);
                return -EINVAL;
            }

	    if (ic->ic_obss_done_freq != channel->ic_freq) {
                ic->ic_obss_done_freq = 0;
	    }
        }

        /*
         * In Monitor mode for auto channel, first valid channel is taken for configured mode.
         * In case of mutiple vaps with auto channel, AP VAP channel will be configured to monitor VAP.
         */

        if ((vap->iv_opmode == IEEE80211_M_MONITOR) && ((int)freq == IEEE80211_FREQ_ANY)) {
            retval = wlan_set_channel(vap, freq, vap->iv_des_cfreq2);
            return retval;
        }

        if (channel != NULL) {
            if (vap->iv_des_chan[cur_mode] == channel) {
                qdf_print("\n Channel is configured already!!");
                /*
                 * In MBSSID mode with monitor VAPs, monitor VAPS might
                 * remain unbroughtup with new desired frequency when chan
                 * set to auto. So consider to restart the monitor VAPs with
                 * new desired channel as same as this VAP
                 */
                retval = EOK;
                if (vap->iv_opmode != IEEE80211_M_MONITOR)
                    goto set_mon_des_chan;
                return retval;
            } else if ((ic->ic_curchan == channel) && (vap->iv_des_chan[vap->iv_des_mode] != channel) &&
                           (wlan_vdev_chan_config_valid(vap->vdev_obj) != QDF_STATUS_SUCCESS)) {
                    retval = wlan_set_channel(vap, freq, vap->iv_des_cfreq2);
                    return retval;
            }
        }

        /*
         * Check wideband channel switch sanity only if channel is not NULL.
         */
        if (ieee80211_ucfg_wideband_channel_switch_sanity(vap, channel)) {
            qdf_err("Wideband channel sanity failed - cannot continue with channel change");
            return -EINVAL;
        }

        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            if (tmpvap->iv_opmode == IEEE80211_M_STA) {
                struct ieee80211_node *ni = tmpvap->iv_bss;
                u_int16_t associd = ni->ni_associd;
                vap->iv_roam_inprogress = FALSE;
                IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(tmpvap, ni->ni_macaddr, associd, IEEE80211_STATUS_UNSPECIFIED);
            } else {
                wlan_mlme_stop_vdev(tmpvap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
            }
        }

        retval = wlan_pdev_wait_to_bringdown_all_vdevs(ic, ALL_VDEVS);
        if (retval == QDF_STATUS_E_INVAL)
            return -EINVAL;

        /*
         * Handle wideband mode switch only after VDEVs down and are applicable
         * only if wideband mode is supported.
         */
        retval = ieee80211_ucfg_handle_wideband_channel_switch(vap, channel);
        if (retval) {
            return retval;
        }

        retval = wlan_set_channel(vap, freq, vap->iv_des_cfreq2);

        if(!retval) {
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                /* Set the desired chan for other VAP to same a this VAP */
                /* Set des chan for all VAPs to be same */
                if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP ||
                        tmpvap->iv_opmode == IEEE80211_M_MONITOR ) {
                    tmpvap->iv_des_chan[vap->iv_des_mode] =
                        vap->iv_des_chan[vap->iv_des_mode];
                }
            }
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                /* Set the desired chan for other VAP to same a this VAP */
                /* Set des chan for all VAPs to be same */
                if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP ||
                        tmpvap->iv_opmode == IEEE80211_M_MONITOR ) {
                    if (IS_UP(tmpdev) && (vap->iv_novap_reset == 0)) {
                        retval = osif_vap_init(tmpdev, RESCAN);
                    } else if (wlan_psoc_nif_feat_cap_get(scn->soc->psoc_obj, WLAN_SOC_F_STRICT_CHANNEL) && (!IS_UP(tmpdev))) {
                        struct net_device *tmpdev;

                        tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                        IEEE80211_DELIVER_EVENT_CHANNEL_CHANGE(tmpvap, tmpvap->iv_des_chan[tmpvap->iv_des_mode]);
                        retval = 0;
                    } else {
                        retval = 0;
                    }
                }
            }
        }
        return retval;
    } else {
        retval = wlan_set_channel(vap, freq, vap->iv_des_cfreq2);
        return retval;
    }

set_mon_des_chan:
    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if (tmpvap->iv_opmode == IEEE80211_M_MONITOR) {
            wlan_mlme_stop_vdev(tmpvap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
        }
    }

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if (tmpvap->iv_opmode == IEEE80211_M_MONITOR) {
            tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            tmpvap->iv_des_chan[vap->iv_des_mode] = vap->iv_des_chan[vap->iv_des_mode];
            retval = (IS_UP(tmpdev) && (vap->iv_novap_reset == 0)) ? osif_vap_init(tmpdev, RESCAN) : EOK;
        }
    }
    return retval;
}

/**
 * ieee80211_get_csa_chwidth_from_cwm: Helper function to get internal CSA width
 * representation from CWM width
 * @cwm_width: CWM width
 * @pcsa_ch_width: Pointer to location where value of internal CSA width is to
 * be written (the value will be valid only if QDF_STATUS_SUCCESS is returned)
 *
 * Return: QDF_STATUS_SUCCESS on success, or a QDF_STATUS value providing the
 * error
 */
QDF_STATUS ieee80211_get_csa_chwidth_from_cwm(
        enum ieee80211_cwm_width cwm_width, u_int16_t *pcsa_ch_width)
{
    QDF_STATUS status = QDF_STATUS_E_FAILURE;

    if (NULL == pcsa_ch_width) {
        status = QDF_STATUS_E_INVAL;
        goto done;
    }

    if (cwm_width >= IEEE80211_CWM_WIDTH_MAX) {
        status = QDF_STATUS_E_INVAL;
        goto done;
    }

    switch (cwm_width) {
        case IEEE80211_CWM_WIDTH20:
            *pcsa_ch_width = CHWIDTH_20;
            status = QDF_STATUS_SUCCESS;
            break;
        case IEEE80211_CWM_WIDTH40:
            *pcsa_ch_width = CHWIDTH_40;
            status = QDF_STATUS_SUCCESS;
            break;
        case IEEE80211_CWM_WIDTH80:
            *pcsa_ch_width = CHWIDTH_80;
            status = QDF_STATUS_SUCCESS;
            break;
        case IEEE80211_CWM_WIDTH160:
        case IEEE80211_CWM_WIDTH80_80:
            *pcsa_ch_width = CHWIDTH_160;
            status = QDF_STATUS_SUCCESS;
            break;
        default:
            status = QDF_STATUS_E_INVAL;
            break;
    }

done:
    return status;
}

/*
 * ieee80211_validate_wideband_security_mode:
 * Ensure security mode is valid for wideband channel switching.
 *
 * Params:
 * ic: Pointer to ic
 *
 * Return:
 * 0        : Valid security mode
 * Otherwise: Invalid security mode
 */
QDF_STATUS ieee80211_validate_wideband_security_mode(struct ieee80211com *ic)
{
    struct ieee80211vap *tmpvap = NULL;
    int retval = 0;

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if (ic->ic_wideband_csa_support &&
            wlan_cfg80211_6ghz_security_check(tmpvap) != EOK) {
            retval = QDF_STATUS_E_INVAL;
        }
    }

    return retval;
}

void ieee80211_ucfg_set_chan_csa(wlan_if_t vap, struct ieee80211_ath_channel *chan)
{
     struct ieee80211com *ic = vap->iv_ic;
     struct ieee80211vap *tmpvap = NULL;
	 int retval;

     TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
         if (tmpvap->iv_opmode == IEEE80211_M_STA) {
             struct ieee80211_node *ni = tmpvap->iv_bss;
             u_int16_t associd = ni->ni_associd;
             vap->iv_roam_inprogress = FALSE;
             IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(tmpvap, ni->ni_macaddr, associd, IEEE80211_STATUS_UNSPECIFIED);
         } else {
             wlan_mlme_stop_vdev(tmpvap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
         }
     }

     retval = wlan_pdev_wait_to_bringdown_all_vdevs(ic, ALL_VDEVS);
     if (retval == QDF_STATUS_E_INVAL)
         return;

     wlan_set_desired_phymode(vap, ieee80211_chan2mode(chan));
     retval = wlan_set_ieee80211_channel(vap, chan);

     if(!retval) {
         TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
             /* Set the desired chan for other VAP to same a this VAP */
             /* Set des chan for all VAPs to be same */
             if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP ||
                     tmpvap->iv_opmode == IEEE80211_M_MONITOR ) {
                 wlan_set_desired_phymode(tmpvap, vap->iv_des_mode);
                 tmpvap->iv_des_chan[vap->iv_des_mode] =
                     vap->iv_des_chan[vap->iv_des_mode];
             }
         }
         TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
             struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
             /* Set the desired chan for other VAP to same a this VAP */
             /* Set des chan for all VAPs to be same */
             if(tmpvap->iv_opmode == IEEE80211_M_HOSTAP ||
                     tmpvap->iv_opmode == IEEE80211_M_MONITOR ) {
                 retval = (IS_UP(tmpdev) && (vap->iv_novap_reset == 0)) ? osif_vap_init(tmpdev, RESCAN) : 0;
             }
         }
     }
}

static void ieee80211_vap_iter_set_des_channel(void *arg, wlan_if_t vap)
{
    wlan_chan_t channel;

    if (arg == NULL)
        return;

    channel = (wlan_chan_t)arg;

    if(vap->iv_opmode == IEEE80211_M_HOSTAP ||
       vap->iv_opmode == IEEE80211_M_MONITOR ) {
        vap->iv_des_chan[vap->iv_des_mode] = channel;
    }
}

static void ieee80211_node_iter_band_compatibility(void *arg, wlan_node_t node)
{
    uint8_t WIDE_BAND_MASK = BIT(REG_BAND_5G) | BIT(REG_BAND_6G);
    uint8_t *wideband_unsupported_sta_present = (uint8_t *)arg;

    if (*wideband_unsupported_sta_present) {
        return;
    }

    if ((node->ni_supp_op_cl.bands_supported & WIDE_BAND_MASK)
            != WIDE_BAND_MASK) {
        *wideband_unsupported_sta_present = 1;
        IEEE80211_DPRINTF_IC(node->ni_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s[%d] Wideband unsupported station present, mac = %s,"
                " ni_supp_op_cl.bands_supported = 0x%x\n", __func__, __LINE__,
                ether_sprintf(node->ni_macaddr), node->ni_supp_op_cl.bands_supported);
        return;
    }

    if (!ieee80211_is_phymode_11ax(node->ni_phymode)) {
        *wideband_unsupported_sta_present = 1;
        IEEE80211_DPRINTF_IC(node->ni_ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s[%d] Sta phy mode is not compatible for switch, mac = %s, phymode = %d",
                __func__, __LINE__, ether_sprintf(node->ni_macaddr), node->ni_phymode);
        return;
    }

    return;
}

static void ieee80211_vap_iter_band_compatibility(void *arg, struct ieee80211vap *vap)
{
    uint8_t *wideband_unsupported_sta_present = (uint8_t *)arg;

    /* Loop only if unsupported sta present is not found yet */
    if (!(*wideband_unsupported_sta_present)) {
        wlan_iterate_station_list(vap, ieee80211_node_iter_band_compatibility, arg);
    }

    return;
}

static QDF_STATUS validate_node_compatibility(struct ieee80211com *ic)
{
    uint8_t wideband_unsupported_sta_present = 0;

    if (ic->ic_wideband_csa_support == WIDEBAND_CSA_DISABLED) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s[%d] Wideband is disabled\n", __func__, __LINE__);
        return QDF_STATUS_E_INVAL;
    }

    /*
     * If there is a STA VAP on the radio (i.e., repeater config),
     * ensure forced mode.
     */
    if (ic->ic_sta_vap) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL,
                         IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                         "%s[%d] STA VAP detected. Using forced mode\n",
                         __func__, __LINE__);
        return QDF_STATUS_SUCCESS;
    }

    /* If compatible switch is enabled, check if all stations support wideband */
    if (ic->ic_wideband_csa_support == WIDEBAND_CSA_COMPATIBILITY) {
        /* Assume unsupported stations are not present, in the beginning */

        wlan_iterate_vap_list(ic, ieee80211_vap_iter_band_compatibility,
                              (void*)(&wideband_unsupported_sta_present));
        if (wideband_unsupported_sta_present) {
            return QDF_STATUS_E_INVAL;
        }
    }

    return QDF_STATUS_SUCCESS;
}

static QDF_STATUS validate_mbssid_mode_compatibility(struct ieee80211com *ic)
{
    /* MBSSID check only applies if number of transmitting vaps is > 1 */
    if (ieee80211_get_num_ap_vaps_up(ic) > 1) {
        /* Switch only if MBSSID mode is EMA */
        if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)
            && (wlan_pdev_nif_feat_ext_cap_get(ic->ic_pdev_obj, WLAN_PDEV_FEXT_EMA_AP_ENABLE))) {
            return QDF_STATUS_SUCCESS;
        } else {
            return QDF_STATUS_E_INVAL;
        }
    }

    return QDF_STATUS_SUCCESS;
}

QDF_STATUS check_inter_band_switch_compatibility(struct ieee80211com *ic)
{
    /* Validate current phymode of radio */
    if (!IEEE80211_IS_CHAN_11AXA(ic->ic_curchan)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s[%d] Switch is not allowed in current mode, flag = %llx\n",
                __func__, __LINE__, ic->ic_curchan->ic_flags);
        return QDF_STATUS_E_INVAL;
    }

    /* If applicable, validate whether all nodes
     * support wideband and in proper phymode
     */
    if (validate_node_compatibility(ic) != 0) {
        return QDF_STATUS_E_INVAL;
    }

    /* If AP is in MBSSID mode, check if it is EMA.
     * As EMA is mandatory on 6GHz, MBSSID mode must be EMA for switch to happen
     */
    if (validate_mbssid_mode_compatibility(ic) != 0) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s[%d] EMA/MBSSID is disabled, Dropping the request\n",
                 __func__, __LINE__);
        return QDF_STATUS_E_INVAL;
    }

    /* If AP is not in a valid security mode, cancel the CSA */
    if (ieee80211_validate_wideband_security_mode(ic)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s[%d] Security mode is invalid, dropping the request\n",
                 __func__, __LINE__);
        return QDF_STATUS_E_INVAL;
    }

    return QDF_STATUS_SUCCESS;
}

int ieee80211_ucfg_set_chanswitch(wlan_if_t vaphandle, uint16_t chan_freq, u_int8_t tbtt, u_int16_t ch_width)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    u_int64_t flags = 0;
    struct ieee80211_ath_channel    *radar_channel = NULL;
    struct wlan_objmgr_pdev *pdev;
    enum reg_wifi_band target_band;
    int is_inter_band_switch = 0, retval = 0;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s : pdev is null", __func__);
        return -EINVAL;
    }

    if (vap->iv_special_vap_mode && !vap->iv_smart_monitor_vap) {
        qdf_err("CSA not supported with special vap");
        return -EINVAL;
    }

    /* doth_chswitch is not allowed when doth is disabled */
    if (!ic->ic_doth) {
            qdf_err("doth is disabled, channel switch is not allowed");
            return -EINVAL;
    }

    if (mlme_dfs_is_ap_cac_timer_running(pdev)) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s: CAC timer is running, doth_chanswitch is not allowed\n", __func__);
        return -EINVAL;
    }

    /* Ensure previous channel switch is not pending */
    if (ic->ic_flags & IEEE80211_F_CHANSWITCH) {
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_EXTIOCTL_CHANSWITCH,
                "%s: Error: Channel change already in progress\n", __func__);
        return -EINVAL;
    }

#if WLAN_SUPPORT_PRIMARY_ALLOWED_CHAN
    if(ic->ic_primary_allowed_enable &&
                    !ieee80211_check_allowed_prim_freqlist(ic, chan_freq)) {
            qdf_err("channel freq %d is not a primary allowed channel", chan_freq);
            return -EINVAL;
    }
#endif

    /* 11AX TODO: Recheck future 802.11ax drafts (>D1.0) on channel switching
     * rules */

    if (ic->ic_strict_doth && ic->ic_non_doth_sta_cnt) {
        qdf_err("strict_doth is enabled and non_doth_sta_cnt is %d"
                " Discarding channel switch request",
                ic->ic_non_doth_sta_cnt);
        return -EAGAIN;
    }

    target_band = wlan_reg_freq_to_band(chan_freq);
    if (target_band != wlan_reg_freq_to_band(ic->ic_curchan->ic_freq)) {
        is_inter_band_switch = 1;
    }

    ic->ic_chanchange_channel = NULL;
    flags = ieee80211_get_band_flag(chan_freq);

    if ((ch_width == 0) && (!is_inter_band_switch) &&
            (ieee80211_find_channel(ic, chan_freq, 0, ic->ic_curchan->ic_flags) == NULL)) {
        /* Switching between different modes is not allowed, print ERROR */
        qdf_err("Channel capabilities do not match, chan flags 0x%llx",
                ic->ic_curchan->ic_flags);
        return -EINVAL;
    } else {
        if (is_inter_band_switch) {
            retval = check_inter_band_switch_compatibility(ic);

            if (retval) {
                qdf_err("Interband switch restricted, err code = %d", retval);
                return -EINVAL;
            }

            if (ch_width != 0) {
                switch (ch_width) {
                    case CHWIDTH_20:
                        flags |= IEEE80211_CHAN_HE20;
                        break;
                    case CHWIDTH_40:
                        flags |= IEEE80211_CHAN_HE40PLUS;
                        if (ieee80211_find_channel(ic, chan_freq, 0, flags) == NULL) {
                            /* HE40PLUS is no good, try minus */
                            flags = ieee80211_get_band_flag(chan_freq);
                            flags |= IEEE80211_CHAN_HE40MINUS;
                        }
                        break;
                    case CHWIDTH_80:
                        flags |= IEEE80211_CHAN_HE80;
                        break;
                    case CHWIDTH_160:
                            flags |= IEEE80211_CHAN_HE160;
                        break;
                    default:
                        ch_width = CHWIDTH_20;
                        flags |= IEEE80211_CHAN_HE20;
                        break;
                }
            } else {
                if (IEEE80211_IS_CHAN_11AXA_HE20(ic->ic_curchan)) {
                    flags |= IEEE80211_CHAN_HE20;
                } else if (IEEE80211_IS_CHAN_11AXA_HE40(ic->ic_curchan)) {
                    flags |= IEEE80211_CHAN_HE40PLUS;
                    if (ieee80211_find_channel(ic, chan_freq, 0, flags) == NULL) {
                        /* HE40PLUS is no good, try minus */
                        flags = ieee80211_get_band_flag(chan_freq);
                        flags |= IEEE80211_CHAN_HE40MINUS;
                    }
                } else if (IEEE80211_IS_CHAN_11AXA_HE80(ic->ic_curchan)) {
                    flags |= IEEE80211_CHAN_HE80;
                } else if (IEEE80211_IS_CHAN_11AXA_HE160(ic->ic_curchan)) {
                    flags |= IEEE80211_CHAN_HE160;
                } else if (IEEE80211_IS_CHAN_11AXA_HE80_80(ic->ic_curchan)) {
                    flags |= IEEE80211_CHAN_HE80_80;
                }
            }
        } else if(ch_width != 0) {
            /* Set channel, chanflag, channel width from ch_width value */
            if (IEEE80211_IS_CHAN_11AXA(ic->ic_curchan)) {
                switch(ch_width){
                    case CHWIDTH_20:
                        flags |= IEEE80211_CHAN_HE20;
                        break;
                    case CHWIDTH_40:
                        flags |= IEEE80211_CHAN_HE40PLUS;
                        if (ieee80211_find_channel(ic, chan_freq, 0, flags) == NULL) {
                            /* HE40PLUS is no good, try minus */
                            flags = ieee80211_get_band_flag(chan_freq);
                            flags |= IEEE80211_CHAN_HE40MINUS;
                        }
                        break;
                    case CHWIDTH_80:
                        flags |= IEEE80211_CHAN_HE80;
                        break;
                    case CHWIDTH_160:
                            flags |= IEEE80211_CHAN_HE160;
                        break;
                    default:
                        ch_width = CHWIDTH_20;
                        flags |= IEEE80211_CHAN_HE20;
                        break;
                }
            } else if (IEEE80211_IS_CHAN_VHT(ic->ic_curchan)){
                switch(ch_width){
                    case CHWIDTH_20:
                        flags |= IEEE80211_CHAN_VHT20;
                        break;
                    case CHWIDTH_40:
                        flags |= IEEE80211_CHAN_VHT40PLUS;
                        if (ieee80211_find_channel(ic, chan_freq, 0, flags) == NULL) {
                            /*VHT40PLUS is no good, try minus*/
                            flags = ieee80211_get_band_flag(chan_freq);
                            flags |= IEEE80211_CHAN_VHT40MINUS;
                        }
                        break;
                    case CHWIDTH_80:
                        flags |= IEEE80211_CHAN_VHT80;
                        break;
                    case CHWIDTH_160:
                            flags |= IEEE80211_CHAN_VHT160;
                        break;
                    default:
                        ch_width = CHWIDTH_20;
                        flags |= IEEE80211_CHAN_VHT20;
                        break;
                }
            } else if(IEEE80211_IS_CHAN_11N(ic->ic_curchan)){
                switch(ch_width){
                    case CHWIDTH_20:
                        flags |= IEEE80211_CHAN_HT20;
                        break;
                    case CHWIDTH_40:
                        flags |= IEEE80211_CHAN_HT40PLUS;
                        if (ieee80211_find_channel(ic, chan_freq, 0, flags) == NULL) {
                            /*HT40PLUS is no good, try minus*/
                            flags = ieee80211_get_band_flag(chan_freq);
                            flags |= IEEE80211_CHAN_HT40MINUS;
                        }
                        break;
                    default:
                        ch_width = CHWIDTH_20;
                        flags |= IEEE80211_CHAN_HT20;
                        break;
                }
            } else {
                /*legacy doesn't support channel width change*/
                qdf_err("Legacy doesn't support channel width change");
                return -EINVAL;
            }
        } else {
            /* In the case of channel switch only, flags will be same as previous
             * channel */
            flags = ic->ic_curchan->ic_flags;
        }
    }
    ic->ic_chanchange_channel = ieee80211_find_channel(ic, chan_freq, vap->iv_des_cfreq2, flags);

    if (ic->ic_chanchange_channel == NULL) {
        /* Channel is not available for the ch_width */
        qdf_err("Channel is not available for the ch_width");
        return -EINVAL;
    }

    if (ic->ic_chanchange_channel == ic->ic_curchan) {
        /* If the new and old channels are the same, we are abandoning
         * the channel switch routine and returning without error. */
        qdf_err("Destination and current channels are the same. Exiting without error.");
        ic->ic_chanchange_channel = NULL;
        return 0;
    }

    if (ic->ic_chanchange_channel != NULL) {
        radar_channel = ic->ic_chanchange_channel;
    } else {
        radar_channel = ieee80211_find_channel(ic, chan_freq, vap->iv_des_cfreq2, ic->ic_curchan->ic_flags);
    }

    if (radar_channel){
        if (IEEE80211_IS_CHAN_RADAR(ic, radar_channel)) {
        qdf_err("Channel is Radar channel");
            return -EINVAL;
        }
    } else {
        qdf_err("Channel is null");
        return -EINVAL;
    }

    if (!ieee80211_vaps_ready(ic, IEEE80211_M_HOSTAP)) {
       qdf_info("Full channel change is invoked");
       ieee80211_ucfg_set_chan_csa(vap, radar_channel);
       ic->ic_chanchange_channel = NULL;
       return 0;
    }

    /* Find destination channel width */
    ic->ic_chanchange_channel = radar_channel;
    ic->ic_chanchange_chwidth = ieee80211_get_chan_width(ic->ic_chanchange_channel);
    ic->ic_chanchange_chanflag  = flags;
    ic->ic_chanchange_secoffset = ieee80211_sec_chan_offset(ic->ic_chanchange_channel);

    /*  flag the beacon update to include the channel switch IE */
    ic->ic_chanchange_chan_freq = chan_freq;
    if (tbtt) {
        ic->ic_chanchange_tbtt = tbtt;
    } else {
        ic->ic_chanchange_tbtt = IEEE80211_RADAR_11HCOUNT;
    }

    if (in_interrupt()) {
        /* In case of interrupt context deliver event directly
         * to vdev mlme sm, avoid serialization as it demands
         * a mutex to be held which is not possible in interrupt
         * context.Need revisit to better handle this scenario.*/
        wlan_pdev_mlme_vdev_sm_csa_restart(pdev, radar_channel);
    } else {
        /* Iterate over VAPs of the pdev and trigger CSA restart procedure */
        wlan_mlme_pdev_csa_restart(vap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);
    }

    /* Set des chan for all VAPs to be same */
    wlan_iterate_vap_list(ic, ieee80211_vap_iter_set_des_channel,
                          (void *)radar_channel);

/* The default value of this variable is false.When NOL violation is reported
 * by FW in vap's start response, during restart of the vap, it will be reset
 * to true in dfs_action. After this if user again tries to set another NOL
 * channel using iwpriv athx doth_chanswitch "NOL_chan" "tbtt_cnt", if is
 * variable is remains to set to true, no action will be taken on vap's start
 * failure from FW. Hence resetting it here.
 */
#if defined(WLAN_DFS_FULL_OFFLOAD) && defined(QCA_DFS_NOL_OFFLOAD)
    if (vap->vap_start_failure_action_taken)
        vap->vap_start_failure_action_taken = false;
#endif

    return 0;
}

wlan_chan_t ieee80211_ucfg_get_current_channel(wlan_if_t vaphandle, bool hwChan)
{
    return wlan_get_current_channel(vaphandle, hwChan);
}

wlan_chan_t ieee80211_ucfg_get_bss_channel(wlan_if_t vaphandle)
{
    return wlan_get_bss_channel(vaphandle);
}

int ieee80211_ucfg_delete_vap(wlan_if_t vap)
{
    int status = -1;
    osif_dev *osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osif->netdev;

    if (dev) {
        status = osif_ioctl_delete_vap(dev);
    }
    return status;
}

int ieee80211_ucfg_set_rts(wlan_if_t vap, u_int32_t val)
{
    osif_dev *osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osif->netdev;
    u_int32_t curval;

    curval = wlan_get_param(vap, IEEE80211_RTS_THRESHOLD);
    if (val != curval)
    {
        wlan_set_param(vap, IEEE80211_RTS_THRESHOLD, val);
        if (IS_UP(dev))
            return osif_vap_init(dev, RESCAN);
    }

    return 0;
}

int ieee80211_ucfg_set_frag(wlan_if_t vap, u_int32_t val)
{
    osif_dev *osif = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osif->netdev;
    u_int32_t curval;

    if(wlan_get_desired_phymode(vap) < IEEE80211_MODE_11NA_HT20)
    {
        curval = wlan_get_param(vap, IEEE80211_FRAG_THRESHOLD);
        if (val != curval)
        {
            wlan_set_param(vap, IEEE80211_FRAG_THRESHOLD, val);
            if (IS_UP(dev))
                return osif_vap_init(dev, RESCAN);
        }
    } else {
        qdf_print("WARNING: Fragmentation with HT mode NOT ALLOWED!!");
        return -EINVAL;
    }

    return 0;
}

int ieee80211_ucfg_set_txpow(wlan_if_t vaphandle, int txpow)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    int is2GHz = 0;
    int fixed = (ic->ic_flags & IEEE80211_F_TXPOW_FIXED) != 0;
    struct ieee80211_ath_channel *vap_cur_des_chan = vap->iv_des_chan[vap->iv_des_mode];
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if (ic->ic_is_ifce_allowed_in_dynamic_mode &&
        !ic->ic_is_ifce_allowed_in_dynamic_mode(scn)) {
        QDF_TRACE(QDF_MODULE_ID_DYNAMIC_MODE_CHG,
            QDF_TRACE_LEVEL_ERROR, FL("IF %s blocked - hw-mode: %d "
                                  "hw-mode-switch-in-progress %s"),
                                  scn->netdev->name,
                                  scn->soc->hw_mode_ctx.current_mode,
                                  scn->soc->hw_mode_ctx.is_switch_in_progress ?
                                                                "YES" : "NO");
        return -EINVAL;
    }

    if (txpow > 0) {
        if ((ic->ic_caps & IEEE80211_C_TXPMGT) == 0)
            return -EINVAL;
        /*
         * txpow is in dBm while we store in 0.5dBm units
         */
        if(ic->ic_set_txPowerLimit) {
        /* The channel is not initialized yet therefore the band(2.4Ghz or 5Ghz)
         * is unknown. Set both the 2.4Ghz and 5Ghz limits.
         */
            if ((vap_cur_des_chan == IEEE80211_CHAN_ANYC) ||
                (vap_cur_des_chan == NULL )) {
                ic->ic_set_txPowerLimit(ic->ic_pdev_obj, 2*txpow, 2*txpow, 1);
                ic->ic_set_txPowerLimit(ic->ic_pdev_obj, 2*txpow, 2*txpow, 0);
            }
            else {
                is2GHz = IEEE80211_IS_CHAN_2GHZ(vap_cur_des_chan);
                ic->ic_set_txPowerLimit(ic->ic_pdev_obj, 2*txpow, 2*txpow, is2GHz);
            }
        }
        ieee80211com_set_flags(ic, IEEE80211_F_TXPOW_FIXED);
    }
    else {
        if (!fixed) return EOK;

        if ((vap_cur_des_chan == IEEE80211_CHAN_ANYC) ||
            (vap_cur_des_chan == NULL )) {
            qdf_info("The channel is not set. Not setting the power value");
            return -EINVAL;
        }

        if(ic->ic_set_txPowerLimit)
           ic->ic_set_txPowerLimit(ic->ic_pdev_obj,
                                   2 * vap_cur_des_chan->ic_maxregpower,
                                   2 * vap_cur_des_chan->ic_maxregpower, is2GHz);

        ieee80211com_clear_flags(ic, IEEE80211_F_TXPOW_FIXED);
    }
    return EOK;
}

int ieee80211_ucfg_get_txpow(wlan_if_t vaphandle, int *txpow, int *fixed)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;

    *txpow = (vap->iv_bss) ? ((int16_t)vap->iv_bss->ni_txpower/2) : 0;
    *fixed = (ic->ic_flags & IEEE80211_F_TXPOW_FIXED) != 0;
    return 0;
}

int ieee80211_ucfg_get_txpow_fraction(wlan_if_t vaphandle, int *txpow, int *fixed)
{
    struct ieee80211vap *vap = vaphandle;
    struct ieee80211com *ic = vap->iv_ic;
    if (vap->iv_bss)
    qdf_print("vap->iv_bss->ni_txpower = %d", vap->iv_bss->ni_txpower);
   *txpow = (vap->iv_bss) ? ((vap->iv_bss->ni_txpower*100)/2) : 0;
   *fixed = (ic->ic_flags & IEEE80211_F_TXPOW_FIXED) != 0;
    return 0;
}


int ieee80211_ucfg_set_ap(wlan_if_t vap, u_int8_t (*des_bssid)[QDF_MAC_ADDR_SIZE])
{
    osif_dev *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osifp->netdev;
    u_int8_t zero_bssid[] = { 0,0,0,0,0,0 };
    int status = 0;

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_STA &&
        (u_int8_t)osifp->os_opmode != IEEE80211_M_P2P_DEVICE &&
        (u_int8_t)osifp->os_opmode != IEEE80211_M_P2P_CLIENT) {
        return -EINVAL;
    }

    if (IEEE80211_ADDR_EQ(des_bssid, zero_bssid)) {
        wlan_aplist_init(vap);
    } else {
        status = wlan_aplist_set_desired_bssidlist(vap, 1, des_bssid);
    }
    if (IS_UP(dev))
        return osif_vap_init(dev, RESCAN);

    return status;
}

int ieee80211_ucfg_get_ap(wlan_if_t vap, u_int8_t *addr)
{
    int status = 0;

    static const u_int8_t zero_bssid[QDF_MAC_ADDR_SIZE];
    u_int8_t bssid[QDF_MAC_ADDR_SIZE];

    if(wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
        status = wlan_vap_get_bssid(vap, bssid);
        if(status == EOK) {
            IEEE80211_ADDR_COPY(addr, bssid);
        }
    } else {
        IEEE80211_ADDR_COPY(addr, zero_bssid);
    }

    return status;
}
extern  A_UINT32 dscp_tid_map[64];

static const struct
    {
        char *name;
        int mode;
        int elementconfig;
    } mappings[] = {
    {"AUTO",IEEE80211_MODE_AUTO,0x090C09},
    {"11A",IEEE80211_MODE_11A,0x010C09},
    {"11B",IEEE80211_MODE_11B,0x090C09},
    {"11G",IEEE80211_MODE_11G,0x000C09},
    {"FH",IEEE80211_MODE_FH,0x090C09},
    {"TA",IEEE80211_MODE_TURBO_A,0x090C09},
    {"TG",IEEE80211_MODE_TURBO_G,0x090C09},
    {"11NAHT20",IEEE80211_MODE_11NA_HT20,0x010009},
    {"11NGHT20",IEEE80211_MODE_11NG_HT20,0x000009},
    {"11NAHT40PLUS",IEEE80211_MODE_11NA_HT40PLUS,0x010101},
    {"11NAHT40MINUS",IEEE80211_MODE_11NA_HT40MINUS,0x0101FF},
    {"11NGHT40PLUS",IEEE80211_MODE_11NG_HT40PLUS,0x000101},
    {"11NGHT40MINUS",IEEE80211_MODE_11NG_HT40MINUS,0x0001FF},
    {"11NGHT40",IEEE80211_MODE_11NG_HT40,0x000100},
    {"11NAHT40",IEEE80211_MODE_11NA_HT40,0x010100},
    {"11ACVHT20",IEEE80211_MODE_11AC_VHT20,0x010209},
    {"11ACVHT40PLUS",IEEE80211_MODE_11AC_VHT40PLUS,0x010301},
    {"11ACVHT40MINUS",IEEE80211_MODE_11AC_VHT40MINUS,0x0103FF},
    {"11ACVHT40",IEEE80211_MODE_11AC_VHT40,0x010300},
    {"11ACVHT80",IEEE80211_MODE_11AC_VHT80,0x010400},
    {"11ACVHT160",IEEE80211_MODE_11AC_VHT160,0x010500},
    {"11ACVHT80_80",IEEE80211_MODE_11AC_VHT80_80,0x010600},
    {"11AXA_HE20",IEEE80211_MODE_11AXA_HE20,0x010709},
    {"11AXG_HE20",IEEE80211_MODE_11AXG_HE20,0x000709},
    {"11AXA_HE40PLUS",IEEE80211_MODE_11AXA_HE40PLUS,0x010801},
    {"11AXA_HE40MINUS",IEEE80211_MODE_11AXA_HE40MINUS,0x0108FF},
    {"11AXG_HE40PLUS",IEEE80211_MODE_11AXG_HE40PLUS,0x000801},
    {"11AXG_HE40MINUS",IEEE80211_MODE_11AXG_HE40MINUS,0x0008FF},
    {"11AXA_HE40",IEEE80211_MODE_11AXA_HE40,0x010800},
    {"11AXG_HE40",IEEE80211_MODE_11AXG_HE40,0x000800},
    {"11AXA_HE80",IEEE80211_MODE_11AXA_HE80,0x010900},
    {"11AXA_HE160",IEEE80211_MODE_11AXA_HE160,0x010A00},
    {"11AXA_HE80_80",IEEE80211_MODE_11AXA_HE80_80,0x010B00},
};

struct elements{
#if _BYTE_ORDER == _BIG_ENDIAN
    char padd;
    char band;
    char bandwidth;
    char extchan;
#else
    char  extchan ;
    char  bandwidth;
    char  band;
    char  padd;
#endif
}  __attribute__ ((packed));

enum  {
      G = 0x0,
      A,
      B = 0x9,
};
enum  {
      HT20 =0x0,
      HT40,
      VHT20,
      VHT40,
      VHT80,
      VHT160,
      VHT80_80,
      HE20,
      HE40,
      HE80,
      HE160,
      HE80_80,
      NONHT,
};

#define EXT_CHAN_PLUS 0x1
#define EXT_CHAN_MINUS 0xFF
#define INVALID_ELEMENT 0x9
#define DEFAULT_EXT_CHAN 0x0
#define MAX_SUPPORTED_MODES 33

static int ieee80211_ucfg_set_extchan( wlan_if_t vap, int extchan )
{
      int elementconfig;
      struct elements *elem;
      int i =0;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      elem->extchan = extchan;
      for( i = 0; i< MAX_SUPPORTED_MODES ; i ++){
          if( elementconfig == mappings[i].elementconfig)
              break;
      }
      if (i == MAX_SUPPORTED_MODES) {
          qdf_print("unsupported config ");
          return -1;
      }

      phymode=i;
      return wlan_set_desired_phymode(vap,phymode);
}

static int ieee80211_ucfg_set_bandwidth( wlan_if_t vap, int bandwidth)
{
      int elementconfig;
      struct elements *elem;
      int i =0;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      elem->bandwidth = bandwidth ;

      if ((bandwidth == HT20) || (bandwidth == VHT20) || (bandwidth == HE20)) {
          elem->extchan = INVALID_ELEMENT;
      } else if ((bandwidth == HT40) || (bandwidth == VHT40) || (bandwidth == HE40)) {
          if (elem->extchan == INVALID_ELEMENT) {
              elem->extchan = DEFAULT_EXT_CHAN;
          }
      } else if ((bandwidth == VHT80) || (bandwidth == HE80) ||
                 (bandwidth == VHT160) || (bandwidth == HE160) ||
                 (bandwidth == VHT80_80) || (bandwidth == HE80_80)) {
          /* If current des_phy_mode is 40 +/- the extchan field of elem will be
             EXT_CHAN_PLUS/EXT_CHAN_MINUS. And when set BW is issued with BW =
             80/160/80P80 MHz, extchan should be set to DEFAULT_EXT_CHAN.
             Otherwise BW switch will fail due to invalid/unsupported
             configuration */
          elem->extchan = DEFAULT_EXT_CHAN;
      }

      if (bandwidth == NONHT) {
          elem->extchan = INVALID_ELEMENT;
      }

      for (i = 0; i< MAX_SUPPORTED_MODES; i++) {
          if (elementconfig == mappings[i].elementconfig)
              break;
      }
      if (i == MAX_SUPPORTED_MODES) {
          qdf_print("unsupported config ");
          return -1;
      }

      phymode=i;

      if (ieee80211_is_phymode_40(phymode)) {
          wlan_chan_t chan = wlan_get_current_channel(vap, false);
          struct ieee80211com *ic = vap->iv_ic;
          int numvaps_up = 0;

          if (chan == NULL) {
              qdf_nofl_info("chan is NULL for mode: %d\n", phymode);
              return -EINVAL;
          }

          if (chan != IEEE80211_CHAN_ANYC) {
              numvaps_up = ieee80211_get_num_vaps_up(ic);
              if ((numvaps_up) && (ic->ic_curchan != chan)) {
                  chan = ic->ic_curchan;
              }
              chan = ieee80211_find_dot11_channel(ic, chan->ic_freq,
                                                  chan->ic_vhtop_freq_seg2,
                                                  phymode);
              if (chan) {
                  phymode = ieee80211_chan2mode(chan);
              }
          }
      }
      return wlan_set_desired_phymode(vap,phymode);
}

static int ieee80211_ucfg_set_band( wlan_if_t vap, int band )
{
      int elementconfig;
      struct elements *elem;
      int i =0;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      elem->band = band;

      if((elem->bandwidth == VHT40 || elem->bandwidth == VHT80 || elem->bandwidth == VHT160 || elem->bandwidth == VHT80_80 )&& band == G)
      {
          elem->bandwidth = HT40;
      }
      if(elem->bandwidth == VHT20 && band == G)
      {
          elem->bandwidth = HT20;
      }
      if( band == B )
      {
          elem->bandwidth = NONHT;
          elem->extchan = INVALID_ELEMENT;
      }
      for( i = 0; i< MAX_SUPPORTED_MODES ; i ++){
          if( elementconfig == mappings[i].elementconfig)
              break;
      }
      if (i == MAX_SUPPORTED_MODES) {
          qdf_print("unsupported config ");
          return -1;
      }
      phymode=i;
      return wlan_set_desired_phymode(vap,phymode);
}

int ieee80211_ucfg_get_bandwidth( wlan_if_t vap)
{
      int elementconfig;
      struct elements *elem;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_current_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      return(elem->bandwidth);
}
#if ATH_SUPPORT_DSCP_OVERRIDE
int ieee80211_ucfg_vap_get_dscp_tid_map(wlan_if_t vap, u_int8_t tos)
{
     if(vap->iv_dscp_map_id)
         return vap->iv_ic->ic_dscp_tid_map[vap->iv_dscp_map_id][(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK];
     else
	 return dscp_tid_map[(tos >> IP_DSCP_SHIFT) & IP_DSCP_MASK];
}

#endif
int ieee80211_ucfg_get_band( wlan_if_t vap)
{
      int elementconfig;
      struct elements *elem;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_current_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      return(elem->band);
}

int ieee80211_ucfg_get_extchan( wlan_if_t vap)
{
      int elementconfig;
      struct elements *elem;
      enum ieee80211_phymode  phymode;
      phymode = wlan_get_desired_phymode(vap);
      elementconfig = mappings[phymode].elementconfig ;
      elem = (struct elements *)&elementconfig;
      return(elem->extchan);
}

struct find_wlan_node_req {
    wlan_node_t node;
    int assoc_id;
};

static void
find_wlan_node_by_associd(void *arg, wlan_node_t node)
{
    struct find_wlan_node_req *req = (struct find_wlan_node_req *)arg;
    if (req->assoc_id == IEEE80211_AID(wlan_node_get_associd(node))) {
        req->node = node;
    }
}

#define IEEE80211_BINTVAL_IWMAX       3500   /* max beacon interval */
#define IEEE80211_BINTVAL_IWMIN       40     /* min beacon interval */
#define IEEE80211_BINTVAL_LP_IOT_IWMIN 25    /* min beacon interval for LP IOT */
#define IEEE80211_SUBTYPE_TXPOW_SHIFT   8     /* left shift 8 bit subtype + txpower as combined value  */
#define IEEE80211_FRAMETYPE_TXPOW_SHIFT   16


int ieee80211_ucfg_set_beacon_interval(wlan_if_t vap, struct ieee80211com *ic,
        int value, bool is_vap_restart_required)
{
    int retv = 0;
    if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
        if (value > IEEE80211_BINTVAL_IWMAX || value < IEEE80211_BINTVAL_LP_IOT_IWMIN) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                    "BEACON_INTERVAL should be within %d to %d\n",
                    IEEE80211_BINTVAL_LP_IOT_IWMIN,
                    IEEE80211_BINTVAL_IWMAX);
            return -EINVAL;
        }
    } else if (ieee80211_vap_oce_check(vap)) {
        if (value > IEEE80211_BINTVAL_MAX || value < IEEE80211_BINTVAL_MIN) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                    "BEACON_INTERVAL should be within %d to %d\n",
                    IEEE80211_BINTVAL_MIN, IEEE80211_BINTVAL_MAX);
            return -EINVAL;
        }
    } else if (value > IEEE80211_BINTVAL_IWMAX || value < IEEE80211_BINTVAL_IWMIN) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "BEACON_INTERVAL should be within %d to %d\n",
                IEEE80211_BINTVAL_IWMIN,
                IEEE80211_BINTVAL_IWMAX);
        return -EINVAL;
    }
    retv = wlan_set_param(vap, IEEE80211_BEACON_INTVAL, value);
    if (retv == EOK) {
        wlan_if_t tmpvap;
        u_int8_t lp_vap_is_present = 0;
        u_int16_t lp_bintval = ic->ic_intval;

        /* Iterate to find if a LP IOT vap is there */
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            if (tmpvap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
                lp_vap_is_present = 1;
                /* If multiple lp iot vaps are present pick the least */
                if (lp_bintval > tmpvap->iv_bss->ni_intval)  {
                    lp_bintval = tmpvap->iv_bss->ni_intval;
                }
            }
        }

        /* Adjust regular beacon interval in ic to be a multiple of lp_iot beacon interval */
        if (lp_vap_is_present) {
            UP_CONVERT_TO_FACTOR_OF(ic->ic_intval, lp_bintval);
        }

        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            /* Adjust regular beacon interval in ni to be a multiple of lp_iot beacon interval */
            if (lp_vap_is_present) {
                if (!(tmpvap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
                    /* up convert vap beacon interval to a factor of LP vap */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                            "Current beacon interval %d: Checking if up conversion is needed as lp_iot vap is present. ", ic->ic_intval);
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                            "New beacon interval  %d \n", ic->ic_intval);
                    UP_CONVERT_TO_FACTOR_OF(tmpvap->iv_bss->ni_intval, lp_bintval);
                }
            }
        }
        if (is_vap_restart_required)
            retv = osif_pdev_restart_vaps(ic);
        else
            retv = 0;
    }

    return retv;
}
static uint32_t ieee80211_get_prbrsp_en_period(uint32_t value1, uint32_t value2)
{
    if (value1) {
        value1 = (1 << WLAN_BCAST_PRB_RSP_ENABLE_BIT);
        value2 &= WLAN_BCAST_PRB_RSP_PERIOD_MASK;
    } else {
        value2 = 0;
    }
    return (value1 | value2);
}

bool osif_radio_activity_update(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap;
    ol_txrx_soc_handle soc_txrx_handle;
    cdp_config_param_type value = {0};
    struct global_ic_list *ic_list = NULL;
    soc_txrx_handle = wlan_psoc_get_dp_handle(scn->soc->psoc_obj);
    cdp_txrx_get_pdev_param(soc_txrx_handle, wlan_objmgr_pdev_get_pdev_id(scn->sc_pdev),
            CDP_CONFIG_VOW, &value);

    ic_list = ic->ic_global_list;
#if DBDC_REPEATER_SUPPORT
    if (!value.cdp_pdev_param_cfg_vow && ic_list->num_stavaps_up <= 1)
#else
    if (!value.cdp_pdev_param_cfg_vow)
#endif
       return 1;

    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
        if (vap) {
             ((osif_dev *)vap->iv_ifp)->wifi3_0_rx_fast_path = 0;
	}

    return 0;
}
qdf_export_symbol(osif_radio_activity_update);

bool osif_vap_activity_update(wlan_if_t vap)
{
    struct wlan_objmgr_vdev *vdev = NULL;
    struct global_ic_list *ic_list = NULL;
    struct ieee80211com *ic = NULL;
    uint32_t target_type;
    struct wlan_objmgr_psoc *psoc = NULL;
    ol_txrx_soc_handle soc_txrx_handle = NULL;
    cdp_config_param_type value = {0};
    enum QDF_OPMODE opmode;
    struct vdev_osif_priv *vdev_osifp = NULL;
    void *osifp_handle;
    osif_dev *osdev;

    ic = vap->iv_ic;
    vdev = vap->vdev_obj;

    if (!vdev) {
        qdf_info("vdev is NULL");
        return 1;
    }

    vdev_osifp = wlan_vdev_get_ospriv(vdev);
    osifp_handle = vdev_osifp->legacy_osif_priv;
    osdev = (osif_dev *)osifp_handle;
    psoc = wlan_vdev_get_psoc(vdev);

    if (!psoc || !osdev) {
        qdf_info("psoc or osdev is NULL");
        return 1;
    }

    target_type = ic->ic_get_tgt_type(ic);
    opmode = wlan_vdev_mlme_get_opmode(vdev);
    soc_txrx_handle = wlan_psoc_get_dp_handle(psoc);
    cdp_txrx_get_psoc_param(soc_txrx_handle, CDP_CFG_PEER_EXT_STATS, &value);
    osdev->wifi3_0_rx_fast_path = 0;

    /*
     * 1. This sets up rx_fast path flag for features which are known
     *    at ol_ath_vap_create_post_init. These features need to be setup
     *    along with vap up eg: iv_wrap, iv_mesh_vap_mode, iv_smart_monitor_vap.
     * 2. We will call this function from multiple iwprivs to enable/disable
     *    this flag for features which are controlled on the fly using iwprivs.
     */
    if ((target_type != TARGET_TYPE_QCA8074V2) &&
        (target_type != TARGET_TYPE_QCA6018) &&
        (target_type != TARGET_TYPE_QCA5018) &&
        (target_type != TARGET_TYPE_QCN9000)) {
            osdev->wifi3_0_rx_fast_path = 0;
            return osdev->wifi3_0_rx_fast_path;
    }

    if ((opmode == QDF_SAP_MODE))
        osdev->wifi3_0_rx_fast_path = 1;

#if ATH_SUPPORT_WRAP
#if WLAN_QWRAP_LEGACY
    if (vap->iv_wrap || vap->iv_mpsta || vap->iv_psta) {
#else
    if (dp_wrap_vdev_is_wrap(vap->vdev_obj) || dp_wrap_vdev_is_mpsta(vap->vdev_obj) || dp_wrap_vdev_is_psta(vap->vdev_obj)) {
#endif
        osdev->wifi3_0_rx_fast_path = 0;
    }
#endif

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode) {
        osdev->wifi3_0_rx_fast_path = 0;
    }
#endif

#if ATH_SUPPORT_NAC
    if (vap->iv_smart_monitor_vap) {
        osdev->wifi3_0_rx_fast_path = 0;
    }
#endif

#if CONFIG_DP_TRACE || QCA_PARTNER_PLATFORM || ATH_DATA_RX_INFO_EN
    osdev->wifi3_0_rx_fast_path = 0;
#endif

    if (osdev->vlanID)
        osdev->wifi3_0_rx_fast_path = 0;

#if UMAC_VOW_DEBUG
    if(osdev->vow_dbg_en)
        osdev->wifi3_0_rx_fast_path = 0;
#endif

    if(dp_is_extap_enabled(vdev))
        osdev->wifi3_0_rx_fast_path = 0;

#ifdef QCA_PEER_EXT_STATS
    if (value.cdp_psoc_param_pext_stats) {
        osdev->wifi3_0_rx_fast_path = 0;
    }
#endif

    ic_list = vap->iv_ic->ic_global_list;
#if DBDC_REPEATER_SUPPORT
    if (ic_list->num_stavaps_up > 1)
        osdev->wifi3_0_rx_fast_path = 0;
#endif
    return osdev->wifi3_0_rx_fast_path;
}
qdf_export_symbol(osif_vap_activity_update);

QDF_STATUS ieee80211_configure_rtt_modes(struct vdev_mlme_obj *vdev_mlme,
        int value, struct wlan_vdev_mgr_cfg mlme_cfg)
{
    QDF_STATUS status = QDF_STATUS_SUCCESS;

    if (value & RTT_RESPONDER_MODE) {
        status = vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_ENABLE_DISABLE_RTT_RESPONDER_ROLE, mlme_cfg);
        if (QDF_IS_STATUS_ERROR(status)) {
            qdf_err("Failed to send RTT responder value to FW, value = %d", mlme_cfg.value);
            return status;
        }
    }

    if (value & RTT_INITIATOR_MODE) {
        status = vdev_mlme_set_param(vdev_mlme,
                WLAN_MLME_CFG_ENABLE_DISABLE_RTT_INITIATOR_ROLE, mlme_cfg);
        if (QDF_IS_STATUS_ERROR(status)) {
            qdf_err("Failed to send RTT initiator value to FW, value = %d", mlme_cfg.value);
            return status;
        }
    }

    return status;
}

/* ieee80211_update_vap_resource_profile: Update space reserved for
 * vendor and optional IEs for non-Tx VAP in MBSSID non-Tx profile.
 * @vap:             pointer to vap handle
 * @des_ven_ie_size: desired vendor IE size in bytes
 * @des_opt_ie_size: desired optional IE size in bytes
 * Return: 0 on success else error val
 */
static int ieee80211_update_vap_resource_profile(struct ieee80211vap *vap,
                                                 int des_ven_ie_size,
                                                 int des_opt_ie_size)
{
#define MAX_ALLOWED_VEN_IE_SIZE 256
    uint32_t max_allowed_vendor_ie_size;
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    bool is_mbssid_enabled =
        wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE);


    if (scn->soc->ema_ap_support_wps_6ghz) {
        max_allowed_vendor_ie_size =
                                IEEE80211_EMA_WPS_IE_OCTET_RESERVATION_BOUND;
    } else {
        max_allowed_vendor_ie_size = MAX_ALLOWED_VEN_IE_SIZE;
    }

    if(!is_mbssid_enabled) {
        qdf_info("MBSSID Disabled so no non-Tx vap config necessary");
        return QDF_STATUS_E_FAILURE;
    }

    if (ieee80211_get_num_beaconing_ap_vaps_up(ic)) {
        qdf_err("All Vaps must be in down state");
        return -EINVAL;
    } else if (vap == ic->ic_mbss.transmit_vap) {
        qdf_err("Vap resource profile update only allowed for non-tx vaps");
        return -EINVAL;
    } else if (des_ven_ie_size > max_allowed_vendor_ie_size) {
        qdf_err("Vendor IE size should be 0 <= val <= %d",
                max_allowed_vendor_ie_size);
        return -EINVAL;
    } else if (des_ven_ie_size + des_opt_ie_size >
               ic->ic_mbss.non_tx_profile_size) {
        qdf_err("Vendor IE size + Optional IE size must be <= max profile size: %d",
                ic->ic_mbss.non_tx_profile_size);
        return -EINVAL;
    } else {
        vap->iv_mbss.total_vendor_ie_size = des_ven_ie_size;
        vap->iv_mbss.total_optional_ie_size = des_opt_ie_size;
        IEEE80211_EMA_MBSS_FLAGS_SET(vap->iv_mbss.flags,
                                     IEEE80211_EMA_MBSS_FLAGS_USER_CONFIGD_RSRC_PFL);
        vap->iv_mbss.ie_overflow = false;
    }
    return 0;
}

int ieee80211_ucfg_setparam(wlan_if_t vap, int param, int value, char *extra)
{
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    struct net_device *dev = osifp->netdev;
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct wlan_objmgr_psoc *psoc;
    int retv = 0;
    int error = 0;
    int prev_state = 0;
    int new_state = 0;
    int *val = (int*)extra;
    int deschan_freq;
    int basic_valid_mask = 0;
    struct _rate_table {
        int *rates;
        int nrates;
    }rate_table;
    int found = 0;
    uint8_t frame_type ;
    uint8_t frame_subtype = val[1];
    int tx_power = val[2];
    u_int8_t transmit_power = 0;
    u_int32_t loop_index;
    struct wlan_objmgr_pdev *pdev;
    QDF_STATUS status;
    uint8_t skip_restart;
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
    uint32_t prb_rsp_en_period = 0;
#ifdef WLAN_SUPPORT_FILS
    uint32_t fils_en_period = 0;
#endif /* WLAN_SUPPORT_FILS */
    uint32_t ldpc = 0;
    uint32_t service_interval = 0;
    uint32_t burst_size = 0;
    uint8_t latency_tid = 0;
    uint8_t dl_ul_latency_enable = 0;
    uint8_t restart_vap = false;
    struct ieee80211vap *tmpvap = NULL;
    cdp_config_param_type buf = {0};
    struct wlan_vdev_mgr_cfg mlme_cfg = {0};
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    bool is_mbssid_enabled = false;

    if (osifp->is_delete_in_progress)
        return -EINVAL;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_print("%s : pdev is null", __func__);
        return -1;
    }

    psoc = wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj);
    if (psoc == NULL) {
             qdf_print("psoc is null");
             return -1;
    }

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(pdev, WLAN_PDEV_F_MBSS_IE_ENABLE);

    config_cmd_resp_log(scn->soc, CONFIG_TYPE_CMD, vap->iv_netdev_name, param, value);

    switch (param)
    {
    case IEEE80211_PARAM_PEER_TX_MU_BLACKLIST_COUNT:
        if (value <= 0) {
           qdf_print("Invalid AID value.");
           return -EINVAL;
        }
        wlan_get_mu_tx_blacklist_cnt(vap,value);
        break;
    case IEEE80211_PARAM_PEER_TX_COUNT:
        if (ic->ic_vap_set_param) {
	   retv = ic->ic_vap_set_param(vap, IEEE80211_PEER_TX_COUNT_SET, (u_int32_t)value);
        }
        break;
    case IEEE80211_PARAM_PEER_MUMIMO_TX_COUNT_RESET:
	if (ic->ic_vap_set_param) {
            retv = ic->ic_vap_set_param(vap, IEEE80211_PEER_MUMIMO_TX_COUNT_RESET_SET, (u_int32_t)value);
        }
        break;
    case IEEE80211_PARAM_PEER_POSITION:
        if (ic->ic_vap_set_param) {
	    retv = ic->ic_vap_set_param(vap, IEEE80211_PEER_POSITION_SET, (u_int32_t)value);
        }
	break;
    case IEEE80211_PARAM_SET_TXPWRADJUST:
        wlan_set_param(vap, IEEE80211_SET_TXPWRADJUST, value);
        break;
    case IEEE80211_PARAM_MAXSTA:
        /*
         * Set the maximum number of STAs that can associate with the specified
         * VAP. The value needs to be greater than 1 to ensure that at least
         * 1 client can associate with the VAP. The value also needs to be
         * less than or equal to the total STA support for the radio.
         *
         * The behavior of this command is different for EMA/MBSSID and legacy
         * cases.
         * - For EMA/MBSSID, the command will not reinitialize the AID
         * bitmap since the bitmap is shared by all VAPs in the MBSS group and
         * the changing the bitmap size will indirectly affect the AID space
         * for other VAPs as well. Therefore, the bitmap will remain as it was
         * during create time and only the soft-limit will change while
         * iv_max_aid will remain the same.
         * - For legacy cases, the command will reinitialize both the TIM and
         * the AID bitmap if the client limits are changed. This is possible
         * because the bitmaps are independent even in multi-VAP scenarios.
         */
        if ((value > ic->ic_num_clients) || (value < 1)) {
            qdf_err("Value beyond acceptable range of 1 and %d", ic->ic_num_clients);
            return -EINVAL;
        }

        if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
            qdf_err("Command is supported for AP mode only");
            return -EINVAL;
        }

        if (value < vap->iv_sta_assoc) {
            qdf_err("Value is lower than current num of connected clients (%d)",
                    vap->iv_sta_assoc);
            return -EINVAL;
        }

        if (is_mbssid_enabled) {
            if (!vap->iv_max_aid || !vap->iv_aid_bitmap) {
                /* This is an unlikely scenario */
                qdf_err("AID bitmap is empty");
                return -EINVAL;
            }

            /*
             * Value should range from (2 + (1 << ic->ic_mbss.max_bssid)) to
             * (ic_num_clients + 1 + (1 << ic->ic_mbss.max_bssid))
             */
            vap->iv_mbss_max_aid = value + (1 << ic->ic_mbss.max_bssid) + 1;
        } else {
            u_int16_t old_max_aid = vap->iv_max_aid;
            u_int16_t old_len = howmany(vap->iv_max_aid, 32) * sizeof(unsigned long);

            /*
             * Reject station when associated aid >= iv_max_aid, such that
             * max associated station should be value + 1
             */
            vap->iv_max_aid = value + 1;

            /* If interface is up, may need to reallocation bitmap(tim, aid) */
            if (IS_UP(dev)) {
                if (vap->iv_alloc_tim_bitmap) {
                    error = vap->iv_alloc_tim_bitmap(vap);
                }

                if(!error) {
                    if (wlan_node_alloc_aid_bitmap(vap, old_len)) {
                        qdf_err("Setting Max Stations fail");
                        vap->iv_max_aid = old_max_aid;
                        return -ENOMEM;
                    }
                }
            }
        }

        if(!error) {
            qdf_info("Setting Max Stations:%d", value);
        }
        break;
    case IEEE80211_PARAM_AUTO_ASSOC:
        wlan_set_param(vap, IEEE80211_AUTO_ASSOC, value);
        break;
    case IEEE80211_PARAM_VAP_COUNTRY_IE:
        wlan_set_param(vap, IEEE80211_FEATURE_COUNTRY_IE, value);
        break;
    case IEEE80211_PARAM_VAP_DOTH:
        wlan_set_param(vap, IEEE80211_FEATURE_DOTH, value);
        break;
    case IEEE80211_PARAM_HT40_INTOLERANT:
        wlan_set_param(vap, IEEE80211_HT40_INTOLERANT, value);
        break;
    case IEEE80211_PARAM_BSS_CHAN_INFO:
        if (value < BSS_CHAN_INFO_READ || value > BSS_CHAN_INFO_READ_AND_CLEAR)
        {
            qdf_print("Setting Param value to 1(read only)");
            value = BSS_CHAN_INFO_READ;
        }
        if (ic->ic_ath_bss_chan_info_stats)
            ic->ic_ath_bss_chan_info_stats(ic, value);
        else {
            qdf_print("Not supported for DA");
            return -EINVAL;
        }
        break;

    case IEEE80211_PARAM_CHWIDTH:
        retv = wlan_set_param(vap, IEEE80211_CHWIDTH, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_CHEXTOFFSET:
        wlan_set_param(vap, IEEE80211_CHEXTOFFSET, value);
        break;
#ifdef ATH_SUPPORT_QUICK_KICKOUT
    case IEEE80211_PARAM_STA_QUICKKICKOUT:
            wlan_set_param(vap, IEEE80211_STA_QUICKKICKOUT, value);
        break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_PARAM_VAP_DSCP_PRIORITY:
        retv = wlan_set_vap_priority_dscp_tid_map(vap,value);
        if(retv == EOK)
            retv = wlan_set_param(vap, IEEE80211_VAP_DSCP_PRIORITY, value);
        break;
#endif
    case IEEE80211_PARAM_CHSCANINIT:
        wlan_set_param(vap, IEEE80211_CHSCANINIT, value);
        break;

    case IEEE80211_PARAM_COEXT_DISABLE:
        ic->ic_user_coext_disable = value;
        skip_restart = 0;
        if (value)
        {
            if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE))
                 ieee80211com_set_flags(ic, IEEE80211_F_COEXT_DISABLE);
            else
                 skip_restart = 1;
        }
        else
        {
            if (ic->ic_flags & IEEE80211_F_COEXT_DISABLE)
                 ieee80211com_clear_flags(ic, IEEE80211_F_COEXT_DISABLE);
            else
                 skip_restart = 1;
        }
        if (!skip_restart) {
            ic->ic_need_vap_reinit = 1;
            osif_restart_for_config(ic, NULL, NULL);
        }

        break;

    case IEEE80211_PARAM_NR_SHARE_RADIO_FLAG:
#if UMAC_SUPPORT_RRM
        retv = ieee80211_set_nr_share_radio_flag(vap,value);
#endif
        break;

    case IEEE80211_PARAM_AUTHMODE:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_AUTHMODE to %s\n",
        (value == IEEE80211_AUTH_WPA) ? "WPA" : (value == IEEE80211_AUTH_8021X) ? "802.1x" :
        (value == IEEE80211_AUTH_OPEN) ? "open" : (value == IEEE80211_AUTH_SHARED) ? "shared" :
        (value == IEEE80211_AUTH_AUTO) ? "auto" : "unknown" );

        /* Note: The PARAM_AUTHMODE will not handle WPA , that will be taken
	 * care by PARAM_WPA, so we check and update authmode for AUTO as a
	 * combination of Open and Shared , and for all others we update the value
	 * except for WPA
	 */
        if (value == IEEE80211_AUTH_AUTO) {
            error = wlan_crypto_set_vdev_param(vap->vdev_obj,
                         WLAN_CRYPTO_PARAM_AUTH_MODE,
                         (uint32_t)((1 << WLAN_CRYPTO_AUTH_OPEN) | (1 << WLAN_CRYPTO_AUTH_SHARED)));
        } else if (value != IEEE80211_AUTH_WPA) {
            error = wlan_crypto_set_vdev_param(vap->vdev_obj,
                         WLAN_CRYPTO_PARAM_AUTH_MODE,
                         (uint32_t)(1 << value));
        }

        if (error == 0) {
            if (osifp->os_opmode != IEEE80211_M_STA || !vap->iv_roam.iv_ft_enable) {
                retv = ENETRESET;
            }
        } else {
            retv = error;
        }
        if (retv == ENETRESET)
            restart_vap = true;
        break;
    case IEEE80211_PARAM_MCASTKEYLEN:
        retv = 0;
        break;
    case IEEE80211_PARAM_UCASTCIPHERS:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_UCASTCIPHERS (0x%x) %s %s %s %s %s %s %s\n",
                value, (value & 1<<IEEE80211_CIPHER_WEP) ? "WEP" : "",
                (value & 1<<IEEE80211_CIPHER_TKIP) ? "TKIP" : "",
                (value & 1<<IEEE80211_CIPHER_AES_OCB) ? "AES-OCB" : "",
                (value & 1<<IEEE80211_CIPHER_AES_CCM) ? "AES-CCMP 128" : "",
                (value & 1<<IEEE80211_CIPHER_AES_CCM_256) ? "AES-CCMP 256" : "",
                (value & 1<<IEEE80211_CIPHER_AES_GCM) ? "AES-GCMP 128" : "",
                (value & 1<<IEEE80211_CIPHER_AES_GCM_256) ? "AES-GCMP 256" : "",
                (value & 1<<IEEE80211_CIPHER_CKIP) ? "CKIP" : "",
                (value & 1<<IEEE80211_CIPHER_WAPI) ? "WAPI" : "",
                (value & 1<<IEEE80211_CIPHER_NONE) ? "NONE" : "");
        {
            int count=0;
            if (value & 1<<IEEE80211_CIPHER_WEP)
                osifp->uciphers[count++] = IEEE80211_CIPHER_WEP;
            if (value & 1<<IEEE80211_CIPHER_TKIP)
                osifp->uciphers[count++] = IEEE80211_CIPHER_TKIP;
            if (value & 1<<IEEE80211_CIPHER_AES_CCM)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_CCM;
            if (value & 1<<IEEE80211_CIPHER_AES_CCM_256)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_CCM_256;
            if (value & 1<<IEEE80211_CIPHER_AES_GCM)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_GCM;
            if (value & 1<<IEEE80211_CIPHER_AES_GCM_256)
                osifp->uciphers[count++] = IEEE80211_CIPHER_AES_GCM_256;
            if (value & 1<<IEEE80211_CIPHER_CKIP)
                osifp->uciphers[count++] = IEEE80211_CIPHER_CKIP;
#if ATH_SUPPORT_WAPI
            if (value & 1<<IEEE80211_CIPHER_WAPI)
                osifp->uciphers[count++] = IEEE80211_CIPHER_WAPI;
#endif
            if (value & 1<<IEEE80211_CIPHER_NONE)
                osifp->uciphers[count++] = IEEE80211_CIPHER_NONE;
            error = wlan_set_ucast_ciphers(vap,osifp->uciphers,count);
            if (error == 0) {
                if (osifp->os_opmode != IEEE80211_M_STA || !vap->iv_roam.iv_ft_enable)
                    error = ENETRESET;
            }
            else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s Warning: wlan_set_ucast_cipher failed. cache the ucast cipher\n", __func__);
                error=0;
            }
            osifp->u_count=count;
        }
        retv = error;
        if (retv == ENETRESET)
            restart_vap = true;
        break;
    case IEEE80211_PARAM_UCASTCIPHER:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_UCASTCIPHER to %s\n",
                (value == IEEE80211_CIPHER_WEP) ? "WEP" :
                (value == IEEE80211_CIPHER_TKIP) ? "TKIP" :
                (value == IEEE80211_CIPHER_AES_OCB) ? "AES OCB" :
                (value == IEEE80211_CIPHER_AES_CCM) ? "AES CCM 128" :
                (value == IEEE80211_CIPHER_AES_CCM_256) ? "AES CCM 256" :
                (value == IEEE80211_CIPHER_AES_GCM) ? "AES GCM 128" :
                (value == IEEE80211_CIPHER_AES_GCM_256) ? "AES GCM 256" :
                (value == IEEE80211_CIPHER_CKIP) ? "CKIP" :
                (value == IEEE80211_CIPHER_WAPI) ? "WAPI" :
                (value == IEEE80211_CIPHER_NONE) ? "NONE" : "unknown");
        {
            ieee80211_cipher_type ctypes[1];
            ctypes[0] = (ieee80211_cipher_type) value;
            error = wlan_set_ucast_ciphers(vap,ctypes,1);
            /* save the ucast cipher info */
            osifp->uciphers[0] = ctypes[0];
            osifp->u_count=1;
            if (error == 0) {
                retv = ENETRESET;
                restart_vap = true;
            }
            else {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s Warning: wlan_set_ucast_cipher failed. cache the ucast cipher\n", __func__);
                error=0;
            }
        }
        retv = error;
        break;
    case IEEE80211_PARAM_MCASTCIPHER:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_MCASTCIPHER to %s\n",
                        (value == IEEE80211_CIPHER_WEP) ? "WEP" :
                        (value == IEEE80211_CIPHER_TKIP) ? "TKIP" :
                        (value == IEEE80211_CIPHER_AES_OCB) ? "AES OCB" :
                        (value == IEEE80211_CIPHER_AES_CCM) ? "AES CCM 128" :
                        (value == IEEE80211_CIPHER_AES_CCM_256) ? "AES CCM 256" :
                        (value == IEEE80211_CIPHER_AES_GCM) ? "AES GCM 128" :
                        (value == IEEE80211_CIPHER_AES_GCM_256) ? "AES GCM 256" :
                        (value == IEEE80211_CIPHER_CKIP) ? "CKIP" :
                        (value == IEEE80211_CIPHER_WAPI) ? "WAPI" :
                        (value == IEEE80211_CIPHER_NONE) ? "NONE" : "unknown");
        {
            ieee80211_cipher_type ctypes[1];
            ctypes[0] = (ieee80211_cipher_type) value;
            error = wlan_set_mcast_ciphers(vap, ctypes, 1);
            /* save the mcast cipher info */
            osifp->mciphers[0] = ctypes[0];
            osifp->m_count=1;
            if (error) {
                /*
                * ignore the error for now.
                * both the ucast and mcast ciphers
                * are set again when auth mode is set.
                */
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s", "Warning: wlan_set_mcast_cipher failed. cache the mcast cipher  \n");
                error=0;
            }
        }
        retv = error;
        break;
    case IEEE80211_PARAM_UCASTKEYLEN:
        retv = 0;
        break;
    case IEEE80211_PARAM_PRIVACY:
        retv = wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY,value);
        break;
    case IEEE80211_PARAM_COUNTERMEASURES:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_COUNTER_MEASURES, value);
        break;
    case IEEE80211_PARAM_HIDESSID:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_HIDE_SSID, value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_APBRIDGE:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_APBRIDGE, value);
        break;
    case IEEE80211_PARAM_KEYMGTALGS:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_KEYMGTALGS (0x%x) %s %s\n",
        value, (value & WPA_ASE_8021X_UNSPEC) ? "802.1x Unspecified" : "",
        (value & WPA_ASE_8021X_PSK) ? "802.1x PSK" : "");
         wlan_crypto_set_vdev_param(vap->vdev_obj,
				  WLAN_CRYPTO_PARAM_KEY_MGMT,
					value);
        retv = error;
        break;
    case IEEE80211_PARAM_RSNCAPS:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_RSNCAPS to 0x%x\n", value);
        if (value & RSN_CAP_MFP_ENABLED) {
            /*
             * 802.11w PMF is enabled so change hw MFP QOS bits
             */
            wlan_crypto_set_hwmfpQos(vap, 1);
        }
	error = wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_RSN_CAP, value);
	retv = error;
        break;
    case IEEE80211_PARAM_WPA:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set IEEE80211_IOC_WPA to %s\n",
        (value == 1) ? "WPA" : (value == 2) ? "RSN" :
        (value == 3) ? "WPA and RSN" : (value == 0)? "off" : "unknown");
        if (value > 3) {
            error = -EINVAL;
            break;
        } else {
	    uint32_t authmode;
            if (osifp->os_opmode == IEEE80211_M_STA ||
                osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
		error = wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_KEY_MGMT, (uint8_t)(WPA_ASE_8021X_PSK));
                if (!error) {
                    if ((value == 3) || (value == 2)) { /* Mixed mode or WPA2 */
                        authmode = (1 << IEEE80211_AUTH_RSNA);
                    } else { /* WPA mode */
                        authmode = (1 << IEEE80211_AUTH_WPA);
                    }
                }
            } else {
                if (value == 3) {
			authmode =  (1<< IEEE80211_AUTH_WPA) | (1 << IEEE80211_AUTH_RSNA);
                } else if (value == 2) {
                    authmode =  (1<< IEEE80211_AUTH_RSNA);
                } else {
                    authmode =  (1<< IEEE80211_AUTH_WPA);
                }
            }
            error = wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE, authmode);
        }
        retv = error;
        break;

    case IEEE80211_PARAM_CLR_APPOPT_IE:
        retv = wlan_set_clr_appopt_ie(vap);
        break;

    /*
    ** The setting of the manual rate table parameters and the retries are moved
    ** to here, since they really don't belong in iwconfig
    */

    case IEEE80211_PARAM_11N_RATE:
        retv = wlan_set_param(vap, IEEE80211_FIXED_RATE, value);
        break;

    case IEEE80211_PARAM_VHT_MCS:
        retv = wlan_set_param(vap, IEEE80211_FIXED_VHT_MCS, value);
    break;

    case IEEE80211_PARAM_HE_MCS:
        /* if ldpc is disabled then as per 802.11ax
         * specification, D2.0 (section 28.1.1) we
         * can not allow mcs values 10 and 11
         */
        ucfg_wlan_vdev_mgr_get_param(vdev, WLAN_MLME_CFG_LDPC, &ldpc);
        if (ieee80211vap_ishemode(vap) &&
            (ldpc == IEEE80211_HTCAP_C_LDPC_NONE) &&
            (value >= 10))
        {
            qdf_print("MCS 10 and 11 are not allowed in \
                    HE mode if LDPC is already diabled");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_FIXED_HE_MCS, value);
    break;

    case IEEE80211_PARAM_HE_MULTI_TID_AGGR:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_MULTI_TID_AGGR, value);

        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_MULTI_TID_AGGR_TX:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_MULTI_TID_AGGR_TX, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_MAX_AMPDU_LEN_EXP:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_MAX_AMPDU_LEN_EXP, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_SU_PPDU_1X_LTF_800NS_GI:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_SU_PPDU_1X_LTF_800NS_GI, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_SU_MU_PPDU_4X_LTF_800NS_GI:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_SU_MU_PPDU_4X_LTF_800NS_GI, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_MAX_FRAG_MSDU:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_MAX_FRAG_MSDU, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_MIN_FRAG_SIZE:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_MIN_FRAG_SIZE, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_OMI:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_OMI, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_NDP_4X_LTF_3200NS_GI:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
                        IEEE80211_CONFIG_HE_NDP_4X_LTF_3200NS_GI, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_ER_SU_PPDU_1X_LTF_800NS_GI:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
                        IEEE80211_CONFIG_HE_ER_SU_PPDU_1X_LTF_800NS_GI, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_ER_SU_PPDU_4X_LTF_800NS_GI:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
                        IEEE80211_CONFIG_HE_ER_SU_PPDU_4X_LTF_800NS_GI, value);
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

case IEEE80211_PARAM_NSS:
        if (value <= 0) {
            qdf_err("Invalid value for NSS");
            return -EINVAL;
        }

        /* if ldpc is disabled then as per 802.11ax
         * specification, D2.0 (section 28.1.1) we
         * can not allow nss value > 4
         */
        ucfg_wlan_vdev_mgr_get_param(vdev, WLAN_MLME_CFG_LDPC, &ldpc);
        if ((ldpc == IEEE80211_HTCAP_C_LDPC_NONE) &&
            (ieee80211vap_ishemode(vap) && (value > 4))) {
            qdf_print("NSS greater than 4 is not allowed in \
                    HE mode if LDPC is already diabled");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_FIXED_NSS, value);
        if (!retv) {
            wlan_vdev_mlme_set_nss(vdev, value);
        }
        /* if the novap reset is set for debugging
         * purpose we are not resetting the VAP
         */
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next)
                tmpvap->iv_set_vht_mcsmap = false;
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_HE_UL_SHORTGI:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("UL Shortgi setting is not allowed in current mode.");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_SHORTGI, value);
        break;

    case IEEE80211_PARAM_HE_UL_LTF:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("UL LTF setting is not allowed in current mode.");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_LTF, value);
        break;

    case IEEE80211_PARAM_HE_UL_NSS:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("UL NSS setting is not allowed in current mode.");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_NSS, value);
        break;

    case IEEE80211_PARAM_HE_UL_PPDU_BW:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("UL PPDU BW setting is not allowed in current mode.");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_PPDU_BW, value);
        break;

    case IEEE80211_PARAM_HE_UL_LDPC:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("UL LDPC setting is not allowed in current mode.");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_LDPC, value);
        break;

    case IEEE80211_PARAM_HE_UL_STBC:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("UL STBC setting is not allowed in current mode.");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_STBC, value);

        break;

    case IEEE80211_PARAM_HE_UL_FIXED_RATE:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("UL MCS setting is not allowed in current mode.");
            return -EPERM;
        }

        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_FIXED_RATE, value);
        break;

    case IEEE80211_PARAM_HE_AMSDU_IN_AMPDU_SUPRT:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("HE AMSDU in AMPDU support is not allowed in current mode.");
            return -EPERM;
        }

        if (value >= 0 && value <= 1)
            vap->iv_he_amsdu_in_ampdu_suprt = value;
        else {
            qdf_err("Invalid value");
            return -EPERM;
        }
        break;

    case IEEE80211_PARAM_HE_SUBFEE_STS_SUPRT:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("HE BFEE STS support is not allowed in current mode.");
            return -EPERM;
        }

        if (!vap->iv_he_su_bfee) {
            qdf_err("HE SUBFEE_STS fields are reserved if HE SU BFEE"
                    " role is not supported");
            return -EPERM;
        }

        if ((val[1] >= 0 && val[1] <= 7) &&
            (val[2] >= 0 && val[2] <=7)) {
            vap->iv_he_subfee_sts_lteq80 = val[1];
            vap->iv_he_subfee_sts_gt80   = val[2];
        } else {
            qdf_err("Invalid value");
            return -EPERM;
        }

        qdf_info("HE SUBFEE_STS: lteq80: %d gt80: %d", val[1], val[2]);
        break;

    case IEEE80211_PARAM_HE_4XLTF_800NS_GI_RX_SUPRT:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("HE 4x LTF & 800ns GI support is not allowed in current mode.");
            return -EPERM;
        }

        if (value >= 0 && value <= 1)
            vap->iv_he_4xltf_800ns_gi = value;
        else {
            qdf_err("Invalid value");
            return -EPERM;
        }
        break;

    case IEEE80211_PARAM_HE_1XLTF_800NS_GI_RX_SUPRT:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("HE 1x LTF & 800ns GI support is not allowed in current mode.");
            return -EPERM;
        }

        if (value >= 0 && value <= 1)
            vap->iv_he_1xltf_800ns_gi = value;
        else {
            qdf_err("Invalid value");
            return -EPERM;
        }
        break;

    case IEEE80211_PARAM_HE_MAX_NC_SUPRT:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("HE Max Nc GI support is not allowed in current mode.");
            return -EPERM;
        }

        if (value && !vap->iv_he_su_bfee) {
            qdf_err("HE MAX_NC fields are reserved if HE SU BFEE"
                    " role is not supported");
            return -EPERM;
        }

        if (value >= 0 && value <= 7)
            vap->iv_he_max_nc = value;
        else {
            qdf_err("Invalid value");
            return -EPERM;
        }
        break;

    case IEEE80211_PARAM_TWT_RESPONDER_SUPRT:

        if(!ieee80211vap_ishemode(vap)) {
            qdf_err("HE TWT support is not allowed in current mode.");
            return -EPERM;
        }

        if (!(wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_CEXT_TWT_RESPONDER))) {
            qdf_err("TWT support disabled");
            return -EPERM;
        }

        if (value >= 0 && value <= 1 && vap->iv_twt_rsp != value) {
            vap->iv_twt_rsp = value;
            wlan_vdev_beacon_update(vap);
        } else {
            qdf_err("Invalid value");
            return -EPERM;
        }
        break;

    case IEEE80211_PARAM_NO_VAP_RESET:
        vap->iv_novap_reset = !!value;
    break;

    case IEEE80211_PARAM_OPMODE_NOTIFY:
        retv = wlan_set_param(vap, IEEE80211_OPMODE_NOTIFY_ENABLE, value);
    break;

    case IEEE80211_PARAM_VHT_SGIMASK:
        retv = wlan_set_param(vap, IEEE80211_VHT_SGIMASK, value);
        if (retv == 0)
            retv = ENETRESET;
    break;

    case IEEE80211_PARAM_VHT80_RATEMASK:
        retv = wlan_set_param(vap, IEEE80211_VHT80_RATEMASK, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_BW_NSS_RATEMASK:
        retv = wlan_set_param(vap, IEEE80211_BW_NSS_RATEMASK, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_LDPC:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_LDPC, value);
        /* if the novap reset is set for debugging
         * purpose we are not resetting the VAP
         */
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_TX_STBC:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_TX_STBC, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_RX_STBC:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_RX_STBC, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_VHT_TX_MCSMAP:
        retv = wlan_set_param(vap, IEEE80211_VHT_TX_MCSMAP, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_VHT_RX_MCSMAP:
        retv = wlan_set_param(vap, IEEE80211_VHT_RX_MCSMAP, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_11N_RETRIES:
        if (value)
            retv = wlan_set_param(vap, IEEE80211_FIXED_RETRIES, value);
        break;
    case IEEE80211_PARAM_SHORT_GI :
        retv = wlan_set_param(vap, IEEE80211_SHORT_GI, value);
        /* if the novap reset is set for debugging
         * purpose we are not resetting the VAP
         */
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_BANDWIDTH :
        retv = ieee80211_ucfg_set_bandwidth(vap, value);
        break;
    case IEEE80211_PARAM_FREQ_BAND :
         retv = ieee80211_ucfg_set_band(vap, value);
         break;

    case IEEE80211_PARAM_EXTCHAN :
         retv = ieee80211_ucfg_set_extchan(vap, value);
         break;

    case IEEE80211_PARAM_SECOND_CENTER_FREQ :
         retv = wlan_set_param(vap, IEEE80211_SECOND_CENTER_FREQ, value);
         break;

    case IEEE80211_PARAM_ATH_SUPPORT_VLAN :
         if( value == 0 || value ==1) {
             vap->vlan_set_flags = value;
             if(value == 1) {
                 dev->features &= ~NETIF_F_HW_VLAN;
             }
             if(value == 0) {
                 dev->features |= NETIF_F_HW_VLAN;
             }
         }
         break;

    case IEEE80211_DISABLE_BCN_BW_NSS_MAP :
         if(value >= 0) {
             ic->ic_disable_bcn_bwnss_map = (value ? 1: 0);
             retv = EOK;
         }
         else
             retv = EINVAL;
         break;

    case IEEE80211_DISABLE_STA_BWNSS_ADV:
         if (value >= 0) {
             ic->ic_disable_bwnss_adv = (value ? 1: 0);
	     retv = EOK;
         } else
             retv = EINVAL;
	 break;
#if DBG_LVL_MAC_FILTERING
    case IEEE80211_PARAM_DBG_LVL_MAC:
          /* This takes 8 bytes as arguments <set/clear> <mac addr> <enable/disable>
          *  e.g. dbgLVLmac 1 0xaa 0xbb 0xcc 0xdd 0xee 0xff 1
          */
         retv = wlan_set_debug_mac_filtering_flags(vap, (unsigned char *)extra);
         break;
#endif

    case IEEE80211_PARAM_UMAC_VERBOSE_LVL:
        if (((value >= IEEE80211_VERBOSE_FORCE) && (value <= IEEE80211_VERBOSE_TRACE)) || (value == IEEE80211_VERBOSE_OFF)){
            wlan_set_umac_verbose_level(value);
        } else
            retv = EINVAL;
        break;

    case IEEE80211_PARAM_CONFIG_CATEGORY_VERBOSE:
         retv = wlan_set_shared_print_ctrl_category_verbose(value);
         break;

    case IEEE80211_PARAM_SET_VLAN_TYPE:
         ieee80211_ucfg_set_vlan_type(osifp, val[1], val[2]);
         break;

    case IEEE80211_PARAM_LOG_FLUSH_TIMER_PERIOD:
         retv = wlan_set_qdf_flush_timer_period(value);
         break;

    case IEEE80211_PARAM_LOG_FLUSH_ONE_TIME:
         wlan_set_qdf_flush_logs();
         break;

    case IEEE80211_PARAM_LOG_DUMP_AT_KERNEL_ENABLE:
         wlan_set_log_dump_at_kernel_level(value);
         break;

#ifdef QCA_OL_DMS_WAR
    case IEEE80211_PARAM_DMS_AMSDU_WAR:
         if(value < 0 || value > 1)
         {
             qdf_print("INVALID value. Please use 1 to enable and 0 to disable");
             break;
         }
         vap->dms_amsdu_war = value;
         /* Reset pkt_type set in CDP vdev->hdr_cache */
         if (!value) {
             wlan_set_param(vap, IEEE80211_VAP_TX_ENCAP_TYPE, htt_cmn_pkt_type_ethernet);
         } else {
             osifp->wifi3_0_fast_path = 0;
         }
         break;
#endif

    case IEEE80211_PARAM_DBG_LVL:
         /*
          * NB: since the value is size of integer, we could only set the 32
          * LSBs of debug mask
          */
         if (vap->iv_csl_support && LOG_CSL_BASIC) {
             value |= IEEE80211_MSG_CSL;
         }
         {
             u_int64_t old_val = wlan_get_debug_flags(vap);
             retv = wlan_set_debug_flags(vap,(old_val & 0xffffffff00000000) | (u_int32_t)(value));
         }
         break;

    case IEEE80211_PARAM_DBG_LVL_HIGH:
        /*
         * NB: This sets the upper 32 LSBs
         */
        {
            u_int64_t old = wlan_get_debug_flags(vap);
            retv = wlan_set_debug_flags(vap, (old & 0xffffffff) | ((u_int64_t) value << 32));
        }
        break;
	case IEEE80211_PARAM_WEATHER_RADAR_CHANNEL:
        retv = wlan_set_param(vap, IEEE80211_WEATHER_RADAR, value);
        /* Making it zero so that it gets updated in Beacon */
        if ( EOK == retv)
            vap->iv_country_ie_chanflags = 0;
		break;
    case IEEE80211_PARAM_SEND_DEAUTH:
        retv = wlan_set_param(vap,IEEE80211_SEND_DEAUTH,value);
        break;
    case IEEE80211_PARAM_WEP_KEYCACHE:
        retv = wlan_set_param(vap, IEEE80211_WEP_KEYCACHE, value);
        break;
    case IEEE80211_PARAM_SIFS_TRIGGER:
        if (ic->ic_vap_sifs_trigger) {
            retv = ic->ic_vap_sifs_trigger(vap, value);
        }
        break;
    case IEEE80211_PARAM_BEACON_INTERVAL:
        if (!(vap->iv_create_flags & IEEE80211_LP_IOT_VAP)) {
            retv = ieee80211_ucfg_set_beacon_interval(vap, ic, value, 1);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "Not updating beacon interval on IoT AP vap\n");
                retv = 0;
        }
        break;
#if ATH_SUPPORT_AP_WDS_COMBO
    case IEEE80211_PARAM_NO_BEACON:
        retv = wlan_set_param(vap, IEEE80211_NO_BEACON, value);
        break;
#endif
    case IEEE80211_PARAM_PUREG:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_PUREG, value);
        /* NB: reset only if we're operating on an 11g channel */
        if (retv == 0) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC &&
                (IEEE80211_IS_CHAN_ANYG(chan) ||
                IEEE80211_IS_CHAN_11NG(chan)))
                retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_PUREN:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_PURE11N, value);
        /* Reset only if we're operating on a 11ng channel */
        if (retv == 0) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC &&
            IEEE80211_IS_CHAN_11NG(chan))
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_PURE11AC:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_PURE11AC, value);
        /* Reset if the channel is valid */
        if (retv == EOK) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC) {
                retv = ENETRESET;
	        }
        }
        break;
    case IEEE80211_PARAM_STRICT_BW:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_STRICT_BW, value);
        /* Reset if the channel is valid */
        if (retv == EOK) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC) {
                retv = ENETRESET;
	        }
        }
        break;
    case IEEE80211_PARAM_WDS:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_WDS, value);
        if (retv == 0) {
            /* WAR: set the auto assoc feature also for WDS */
            if (value) {
                wlan_set_param(vap, IEEE80211_AUTO_ASSOC, 1);
                /* disable STA powersave for WDS */
                if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
                    (void) wlan_set_powersave(vap,IEEE80211_PWRSAVE_NONE);
                    (void) wlan_pwrsave_force_sleep(vap,0);
                }
            }
        }
        break;
    case IEEE80211_PARAM_DA_WAR_ENABLE:
        if ((ic->ic_get_tgt_type(ic) == TARGET_TYPE_QCA8074) &&
           (wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP)) {
            buf.cdp_vdev_param_da_war = value;
            if (cdp_txrx_set_vdev_param(wlan_psoc_get_dp_handle(psoc),
                                    wlan_vdev_get_id(vap->vdev_obj), CDP_ENABLE_DA_WAR,
                                    buf) != QDF_STATUS_SUCCESS)
                retv = EINVAL;
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "Valid only in HKv1 AP mode\n");
            retv = EINVAL;
        }
        break;
#if WDS_VENDOR_EXTENSION
    case IEEE80211_PARAM_WDS_RX_POLICY:
        retv = wlan_set_param(vap, IEEE80211_WDS_RX_POLICY, value);
        break;
#endif
    case IEEE80211_PARAM_VAP_PAUSE_SCAN:
        if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
            vap->iv_pause_scan = value ;
            retv = 0;
        } else retv =  EINVAL;
        break;
#if ATH_GEN_RANDOMNESS
    case IEEE80211_PARAM_RANDOMGEN_MODE:
        if(value < 0 || value > 2)
        {
         qdf_print("INVALID mode please use between modes 0 to 2");
         break;
        }
        ic->random_gen_mode = value;
        break;
#endif
    case IEEE80211_PARAM_VAP_ENHIND:
        if (value) {
            retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
        }
        else {
            retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
        }
        break;

#if ATH_SUPPORT_WAPI
    case IEEE80211_PARAM_SETWAPI:
        retv = wlan_setup_wapi(vap, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_WAPIREKEY_USK:
        retv = wlan_set_wapirekey_unicast(vap, value);
        break;
    case IEEE80211_PARAM_WAPIREKEY_MSK:
        retv = wlan_set_wapirekey_multicast(vap, value);
        break;
    case IEEE80211_PARAM_WAPIREKEY_UPDATE:
        retv = wlan_set_wapirekey_update(vap, (unsigned char*)&extra[4]);
        break;
#endif
#if WLAN_SUPPORT_GREEN_AP
    case IEEE80211_IOCTL_GREEN_AP_PS_ENABLE:
        if (value != 0 && value != WLAN_GREEN_AP_MODE_NO_STA && value != WLAN_GREEN_AP_MODE_NUM_STREAM)
        {
            qdf_warn("INVALID mode, please use mode as 0, 1 or 2\n");
            break;
        }
        if (ic_is_sta_vap(ic) && ((vap->iv_opmode == IEEE80211_M_HOSTAP) || !vap->iv_sm_gap_ps) && value!=0)
        {
            qdf_warn("Green AP can't be enabled if SM Powersave on STA vap is disabled\n");
            break;
        }
        ucfg_green_ap_config(pdev, value);
        retv = 0;
        break;

    case IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT:
        ucfg_green_ap_set_transition_time(pdev, ((value > 20) && (value < 0xFFFF)) ? value : 20);
        retv = 0;
        break;

    case IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT:
        ucfg_green_ap_enable_debug_prints(pdev, value?1:0);
        break;
#endif
    case IEEE80211_PARAM_WPS:
        retv = wlan_set_param(vap, IEEE80211_WPS_MODE, value);
        break;
    case IEEE80211_PARAM_EXTAP:
#ifdef QCA_SUPPORT_WDS_EXTENDED
        if (wlan_psoc_nif_feat_cap_get(wlan_vdev_get_psoc(vap->vdev_obj),
                                       WLAN_SOC_F_WDS_EXTENDED)) {
            qdf_err("EXTAP can't co-exist with WDS Extended mode");
            break;
            }
#endif
        if (value) {
            if (value == 3 /* dbg */) {
                if (ic->ic_miroot)
                    mi_tbl_dump(ic->ic_miroot);
                else
                    dp_extap_mitbl_dump(dp_get_extap_handle(vdev));
                break;
            }
            if (value == 2 /* dbg */) {
                dp_extap_disable(vdev);
                if (ic->ic_miroot)
                    mi_tbl_purge(&ic->ic_miroot);
                else
                    dp_extap_mitbl_purge(dp_get_extap_handle(vdev));
            }
            dp_extap_enable(vdev);
            /* Set the auto assoc feature for Extender Station */
            wlan_set_param(vap, IEEE80211_AUTO_ASSOC, 1);
            wlan_set_param(vap, IEEE80211_FEATURE_EXTAP, 1);
            if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
                (void) wlan_set_powersave(vap,IEEE80211_PWRSAVE_NONE);
                (void) wlan_pwrsave_force_sleep(vap,0);
                /* Enable enhanced independent repeater mode for EXTAP */
                retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
            }
        } else {
            dp_extap_disable(vdev);
            wlan_set_param(vap, IEEE80211_FEATURE_EXTAP, 0);
            if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
                retv = wlan_set_param(vap, IEEE80211_FEATURE_VAP_ENHIND, value);
            }
        }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops)
        ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_VDEV_EXTAP_CONFIG);
#endif
        break;
    case IEEE80211_PARAM_STA_FORWARD:
    retv = wlan_set_param(vap, IEEE80211_FEATURE_STAFWD, value);
    break;

    case IEEE80211_PARAM_DYN_BW_RTS:
        retv = ic->ic_vap_dyn_bw_rts(vap, value);
        if (retv == EOK) {
            vap->dyn_bw_rts = value;
        } else {
            return -EINVAL;
        }
        break;

    case IEEE80211_PARAM_CWM_EXTPROTMODE:
        if (value >= 0) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_EXTPROTMODE, value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CWM_EXTPROTSPACING:
        if (value >= 0) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_EXTPROTSPACING, value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        }
        else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CWM_ENABLE:
        if (value >= 0) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_ENABLE, value);
            if ((retv == EOK) && (vap->iv_novap_reset == 0)) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD:
        if (value >=0 && value <=100) {
            retv = wlan_set_device_param(ic,IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD, value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_DOTH:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_DOTH, value);
        if (retv == EOK) {
            retv = osif_pdev_restart_vaps(ic);
        }
        break;
    case IEEE80211_PARAM_SETADDBAOPER:
        if (value > 1 || value < 0) {
            return -EINVAL;
        }

        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_ADDBA_MODE, value);
        if((!retv) && (ic->ic_vap_set_param)) {
            retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_ADDBA_MODE,
                                        value);
        }
        break;
    case IEEE80211_PARAM_PROTMODE:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_PROTECTION_MODE, value);
        /* NB: if not operating in 11g this can wait */
        if (retv == EOK) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC &&
                (IEEE80211_IS_CHAN_ANYG(chan) ||
                IEEE80211_IS_CHAN_11NG(chan))) {
                retv = ENETRESET;
                restart_vap = true;
            }
        }
        break;
    case IEEE80211_PARAM_ROAMING:
        if (!(IEEE80211_ROAMING_DEVICE <= value &&
            value <= IEEE80211_ROAMING_MANUAL))
            return -EINVAL;
        ic->ic_roaming = value;
        if(value == IEEE80211_ROAMING_MANUAL)
            IEEE80211_VAP_AUTOASSOC_DISABLE(vap);
        else
            IEEE80211_VAP_AUTOASSOC_ENABLE(vap);
        break;
    case IEEE80211_PARAM_DROPUNENCRYPTED:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_DROP_UNENC, value);
        break;
    case IEEE80211_PARAM_DRIVER_CAPS:
        retv = wlan_set_param(vap, IEEE80211_DRIVER_CAPS, value); /* NB: for testing */
        break;
    case IEEE80211_PARAM_STA_MAX_CH_CAP:
        /* This flag will be enabled only on a STA VAP */
        if (vap->iv_opmode == IEEE80211_M_STA) {
            vap->iv_sta_max_ch_cap = !!value;
        } else {
            qdf_err("Config is for STA VAP only");
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_OBSS_NB_RU_TOLERANCE_TIME:
        if ((value >= IEEE80211_OBSS_NB_RU_TOLERANCE_TIME_MIN) &&
            (value <= IEEE80211_OBSS_NB_RU_TOLERANCE_TIME_MAX)) {
            ic->ic_obss_nb_ru_tolerance_time = value;
        } else {
            qdf_err("Invalid value for NB RU tolerance time\n");
            return -EINVAL;
        }
        break;
/*
* Support for Mcast Enhancement
*/
#if ATH_SUPPORT_IQUE
    case IEEE80211_PARAM_ME:
        wlan_set_param(vap, IEEE80211_ME, value);
        break;
    case IEEE80211_PARAM_IGMP_ME:
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            wlan_set_param(vap, IEEE80211_IGMP_ME, value);
	} else
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "Feature only valid in AP mode");
        break;
#endif

    case IEEE80211_PARAM_SCANVALID:
        if (vap->iv_opmode == IEEE80211_M_STA) {
            if (QDF_IS_STATUS_ERROR(wlan_scan_set_aging_time(psoc, value)))
                retv = -EINVAL;
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "Can not be used in mode %d\n",
                              osifp->os_opmode);
            retv = -EINVAL;
        }
        break;

    case IEEE80211_PARAM_DTIM_PERIOD:
        if (!(osifp->os_opmode == IEEE80211_M_HOSTAP))
            return -EINVAL;

        if (value > IEEE80211_DTIM_MAX ||
            value < IEEE80211_DTIM_MIN) {

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                              "DTIM_PERIOD should be within %d to %d\n",
                              IEEE80211_DTIM_MIN,
                              IEEE80211_DTIM_MAX);
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_DTIM_INTVAL, value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }

        break;
    case IEEE80211_PARAM_MACCMD:
        wlan_set_acl_policy(vap, value, IEEE80211_ACL_FLAG_ACL_LIST_1);
        break;
    case IEEE80211_PARAM_ENABLE_OL_STATS:
        /* This param should be eventually removed and re-used */
        qdf_print("Issue this command on parent device, like wifiX");
        break;
    case IEEE80211_PARAM_RTT_ENABLE:
        if ((value < DISABLE_RTT_RESPONDER_AND_INITIATOR_MODE) ||
                (value > RTT_RESPONDER_AND_INITIATOR_MODE)) {
            qdf_err("RTT value should be within 0 to 3,"
                    " 0-Disable RTT, 1-Enable RTT responder, 2-Enable RTT initiator,"
                    " 3-Enable both RTT responder and initiator modes");
            return -EINVAL;
        }

        if (vap->rtt_enable == value) {
            qdf_info("rtt_enable = %d already configured, skip configuration", value);
            return 0;
        }

        /* Clear previous configuration */
        mlme_cfg.value = 0;
        status = ieee80211_configure_rtt_modes(vdev_mlme, vap->rtt_enable, mlme_cfg);
        if (QDF_IS_STATUS_ERROR(status))
            return -EINVAL;

        /* Configure new RTT modes */
        vap->rtt_enable = value;
        mlme_cfg.value = !!value; /* Send either 0 or 1 to target */
        status = ieee80211_configure_rtt_modes(vdev_mlme, vap->rtt_enable, mlme_cfg);
        if (QDF_IS_STATUS_ERROR(status))
            return -EINVAL;
        vap->iv_rtt_update = true;
        wlan_vdev_beacon_update(vap);
        break;
    case IEEE80211_PARAM_LCI_ENABLE:
        qdf_print("KERN_DEBUG\n setting the lci enble flag");
        vap->lci_enable = !!value;
        break;
    case IEEE80211_PARAM_LCR_ENABLE:
        qdf_print("KERN_DEBUG\n setting the lcr enble flag");
        vap->lcr_enable = !!value;
        break;
    case IEEE80211_PARAM_MCAST_RATE:
        /*
        * value is rate in units of Kbps
        * min: 1Mbps max: 350Mbps
        */
        if (value < ONEMBPS || value > THREE_HUNDRED_FIFTY_MBPS)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_MCAST_RATE, value);
        }
        break;
    case IEEE80211_PARAM_BCAST_RATE:
        /*
        * value is rate in units of Kbps
        * min: 1Mbps max: 350Mbps
        */
        if (value < ONEMBPS || value > THREE_HUNDRED_FIFTY_MBPS)
            retv = -EINVAL;
        else {
        	retv = wlan_set_param(vap, IEEE80211_BCAST_RATE, value);
        }
        break;
    case IEEE80211_PARAM_MGMT_RATE:
        if(!ieee80211_rate_is_valid_basic(vap,value)){
            qdf_print("%s: rate %d is not valid. ",__func__,value);
            retv = -EINVAL;
            break;
        }
       /*
        * value is rate in units of Kbps
        * min: 1000 kbps max: 300000 kbps
        */
        if (value < 1000 || value > 300000)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_MGMT_RATE, value);
            /* Set beacon rate through separate vdev param */
            retv = wlan_set_param(vap, IEEE80211_BEACON_RATE_FOR_VAP, value);
        }
        break;
    case IEEE80211_PARAM_RTSCTS_RATE:
        retv = wlan_set_param(vap, IEEE80211_NON_BASIC_RTSCTS_RATE, value);
        break;
    case IEEE80211_PARAM_PRB_RATE:
        if(!ieee80211_rate_is_valid_basic(vap,value)){
            qdf_print("%s: rate %d is not valid. ", __func__, value);
            retv = -EINVAL;
            break;
        }
       /*
        * value is rate in units of Kbps
        * min: 1000 kbps max: 300000 kbps
        */
        if (value < 1000 || value > 300000)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_PRB_RATE, value);
        }
        break;
    case IEEE80211_PARAM_PRB_RETRY:
       /*
        * value is retry limit count
        * min: 1 max: 15
        */
        if (value < 1 || value > 15)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_PRB_RETRY, value);
        }
        break;
    case IEEE80211_RTSCTS_RATE:
        if (!ieee80211_rate_is_valid_basic(vap,value)) {
            qdf_print("%s: Rate %d is not valid. ",__func__,value);
            retv = -EINVAL;
            break;
        }
       /*
        * Here value represents rate in Kbps.
        * min: 1000 kbps max: 24000 kbps
        */
        if (value < ONEMBPS || value > HIGHEST_BASIC_RATE)
            retv = -EINVAL;
        else {
            retv = wlan_set_param(vap, IEEE80211_RTSCTS_RATE, value);
        }
        break;
    case IEEE80211_PARAM_CCMPSW_ENCDEC:
        if (value) {
            IEEE80211_VAP_CCMPSW_ENCDEC_ENABLE(vap);
        } else {
            IEEE80211_VAP_CCMPSW_ENCDEC_DISABLE(vap);
        }
        break;
    case IEEE80211_PARAM_NETWORK_SLEEP:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s set IEEE80211_IOC_POWERSAVE parameter %d \n",
                          __func__,value );
        do {
            ieee80211_pwrsave_mode ps_mode = IEEE80211_PWRSAVE_NONE;
            switch(value) {
            case 0:
                ps_mode = IEEE80211_PWRSAVE_NONE;
                break;
            case 1:
                ps_mode = IEEE80211_PWRSAVE_LOW;
                break;
            case 2:
                ps_mode = IEEE80211_PWRSAVE_NORMAL;
                break;
            case 3:
                ps_mode = IEEE80211_PWRSAVE_MAXIMUM;
                break;
            }
            error= wlan_set_powersave(vap,ps_mode);
        } while(0);
        break;

#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_SLEEP:
        if (wlan_wnm_vap_is_set(vap) && ieee80211_wnm_sleep_is_set(vap->wnm)) {
            ieee80211_pwrsave_mode ps_mode = IEEE80211_PWRSAVE_NONE;
            if (value > 0)
                ps_mode = IEEE80211_PWRSAVE_WNM;
            else
                ps_mode = IEEE80211_PWRSAVE_NONE;

            if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA)
                vap->iv_wnmsleep_intval = value > 0 ? value : 0;
            error = wlan_set_powersave(vap,ps_mode);
            qdf_print("set IEEE80211_PARAM_WNM_SLEEP mode = %d", ps_mode);
        } else
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: WNM not supported\n", __func__);
	break;

    case IEEE80211_PARAM_WNM_SMENTER:
        if (!wlan_wnm_vap_is_set(vap) || !ieee80211_wnm_sleep_is_set(vap->wnm)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: WNM not supported\n", __func__);
            return -EINVAL;
        }

        if (value % 2 == 0) {
            /* HACK: even interval means FORCE WNM Sleep: requires manual wnmsmexit */
            vap->iv_wnmsleep_force = 1;
        }

        ieee80211_wnm_sleepreq_to_app(vap, IEEE80211_WNMSLEEP_ACTION_ENTER, value);
        break;

    case IEEE80211_PARAM_WNM_SMEXIT:
        if (!wlan_wnm_vap_is_set(vap) || !ieee80211_wnm_sleep_is_set(vap->wnm)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s: WNM not supported\n", __func__);
            return -EINVAL;
        }
        vap->iv_wnmsleep_force = 0;
        ieee80211_wnm_sleepreq_to_app(vap, IEEE80211_WNMSLEEP_ACTION_EXIT, value);
	    break;
#endif

#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    case IEEE80211_PARAM_PERIODIC_SCAN:
        if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
            if (osifp->os_periodic_scan_period != value){
                if (value && (value < OSIF_PERIODICSCAN_MIN_PERIOD))
                    osifp->os_periodic_scan_period = OSIF_PERIODICSCAN_MIN_PERIOD;
                else
                    osifp->os_periodic_scan_period = value;

                retv = ENETRESET;
            }
        }
        break;
#endif
    case IEEE80211_PARAM_VENDOR_FRAME_FWD_MASK:
        osifp->wlan_vendor_fwd_mgmt_mask = value;
        break;

#if ATH_SW_WOW
    case IEEE80211_PARAM_SW_WOW:
        if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
            retv = wlan_set_wow(vap, value);
        }
        break;
#endif

    case IEEE80211_PARAM_UAPSDINFO:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_UAPSD, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
	break ;
#if defined(UMAC_SUPPORT_STA_POWERSAVE) || defined(ATH_PERF_PWR_OFFLOAD)
    /* WFD Sigma use these two to do reset and some cases. */
    case IEEE80211_PARAM_SLEEP:
        /* XXX: Forced sleep for testing. Does not actually place the
         *      HW in sleep mode yet. this only makes sense for STAs.
         */
        /* enable/disable force  sleep */
        wlan_pwrsave_force_sleep(vap,value);
        break;
#endif
     case IEEE80211_PARAM_COUNTRY_IE:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_IC_COUNTRY_IE, value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_2G_CSA:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_2G_CSA, value);
        break;
#if UMAC_SUPPORT_QBSSLOAD
    case IEEE80211_PARAM_QBSS_LOAD:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_QBSS_LOAD, value);
            if (retv == EOK) {
                retv = ENETRESET;
                restart_vap = true;
            }
        }
        break;
#if ATH_SUPPORT_HS20
    case IEEE80211_PARAM_HC_BSSLOAD:
        retv = wlan_set_param(vap, IEEE80211_HC_BSSLOAD, value);
        break;
    case IEEE80211_PARAM_OSEN:
        if (value > 1 || value < 0)
            return -EINVAL;
        else
            wlan_set_param(vap, IEEE80211_OSEN, value);
        break;
#endif /* ATH_SUPPORT_HS20 */
#endif /* UMAC_SUPPORT_QBSSLOAD */
#if UMAC_SUPPORT_XBSSLOAD
    case IEEE80211_PARAM_XBSS_LOAD:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_XBSS_LOAD, value);
            if (retv == EOK) {
                retv = ENETRESET;
                restart_vap = true;
            }
        }
        break;
#endif
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    case IEEE80211_PARAM_CHAN_UTIL_ENAB:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_CHAN_UTIL_ENAB, value);
            if (retv == EOK) {
                retv = ENETRESET;
                restart_vap = true;
            }
        }
        break;
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
#if UMAC_SUPPORT_QUIET
    case IEEE80211_PARAM_QUIET_PERIOD:
        if (vap->iv_bcn_offload_enable) {
            if (value > MAX_QUIET_ENABLE_FLAG || value < 0) {
                return -EINVAL;
            } else {
                retv = wlan_quiet_set_param(vap, value);
            }
        } else {
            if (value > 1 || value < 0) {
                return -EINVAL;
            } else {
                retv = wlan_quiet_set_param(vap, value);
                if (retv == EOK) {
                    retv = ENETRESET;
                    restart_vap = true;
                }
            }
        }
        break;
#endif /* UMAC_SUPPORT_QUIET */
    case IEEE80211_PARAM_START_ACS_REPORT:
        retv = wlan_set_param(vap, IEEE80211_START_ACS_REPORT, !!value);
        break;
    case IEEE80211_PARAM_MIN_DWELL_ACS_REPORT:
        retv = wlan_set_param(vap, IEEE80211_MIN_DWELL_ACS_REPORT, value);
        break;
    case IEEE80211_PARAM_MAX_DWELL_ACS_REPORT:
        retv = wlan_set_param(vap, IEEE80211_MAX_DWELL_ACS_REPORT, value);
        break;
    case IEEE80211_PARAM_SCAN_MIN_DWELL:
        retv = wlan_set_param(vap, IEEE80211_SCAN_MIN_DWELL, value);
       break;
    case IEEE80211_PARAM_SCAN_MAX_DWELL:
        retv = wlan_set_param(vap, IEEE80211_SCAN_MAX_DWELL, value);
       break;
    case IEEE80211_PARAM_MAX_SCAN_TIME_ACS_REPORT:
        retv = wlan_set_param(vap, IEEE80211_MAX_SCAN_TIME_ACS_REPORT, value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_LONG_DUR, value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_NO_HOP_DUR,value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_CNT_WIN_DUR, value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_NOISE_TH,value);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_TH:
        retv = wlan_set_param(vap,IEEE80211_ACS_CH_HOP_CNT_TH, value);
        break;
    case IEEE80211_PARAM_ACS_ENABLE_CH_HOP:
        retv = wlan_set_param(vap,IEEE80211_ACS_ENABLE_CH_HOP, value);
        break;
    case IEEE80211_PARAM_MBO:
        retv = wlan_set_param(vap, IEEE80211_MBO, !!value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_MBO_ASSOC_DISALLOW:
        retv = wlan_set_param(vap, IEEE80211_MBO_ASSOC_DISALLOW,value);
        break;
    case IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE:
        retv = wlan_set_param(vap,IEEE80211_MBO_CELLULAR_PREFERENCE,value);
        break;
    case IEEE80211_PARAM_MBO_TRANSITION_REASON:
        retv  = wlan_set_param(vap,IEEE80211_MBO_TRANSITION_REASON,value);
        break;
    case IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY:
        retv  = wlan_set_param(vap,IEEE80211_MBO_ASSOC_RETRY_DELAY,value);
        break;
    case IEEE80211_PARAM_MBO_CAP:
        retv = wlan_set_param(vap, IEEE80211_MBOCAP, value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_OCE:
        retv = wlan_set_param(vap, IEEE80211_OCE, !!value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_OCE_ASSOC_REJECT:
        retv = wlan_set_param(vap, IEEE80211_OCE_ASSOC_REJECT, !!value);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI:
        retv = wlan_set_param(vap, IEEE80211_OCE_ASSOC_MIN_RSSI, value);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY:
        retv = wlan_set_param(vap, IEEE80211_OCE_ASSOC_RETRY_DELAY, value);
        break;
    case IEEE80211_PARAM_OCE_WAN_METRICS:
        retv = wlan_set_param(vap, IEEE80211_OCE_WAN_METRICS, ((val[1] & 0xFFFF) << 16) | (val[2] & 0xFFFF));
        break;
    case IEEE80211_PARAM_OCE_HLP:
         retv = wlan_set_param(vap, IEEE80211_OCE_HLP, !!value);
         break;
    case IEEE80211_PARAM_ASSOC_MIN_RSSI:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ASSOC_MIN_RSSI, value);
        break;
    case IEEE80211_PARAM_NBR_SCAN_PERIOD:
        vap->nbr_scan_period = value;
        break;
    case IEEE80211_PARAM_RNR:
        vap->rnr_enable = !!value;
        if (vap->iv_bcn_offload_enable && !vap->rnr_enable)
            ieee80211vap_set_flag_ext2(vap, IEEE80211_FEXT2_MBO);
        break;
    case IEEE80211_PARAM_RNR_FD:
        vap->rnr_enable_fd = !!value;
        break;
    case IEEE80211_PARAM_RNR_TBTT:
        vap->rnr_enable_tbtt = !!value;
        break;
    case IEEE80211_PARAM_AP_CHAN_RPT:
        vap->ap_chan_rpt_enable = value;
        if (vap->iv_bcn_offload_enable && !vap->ap_chan_rpt_enable)
            ieee80211vap_set_flag_ext2(vap, IEEE80211_FEXT2_MBO);
        break;
    case IEEE80211_PARAM_AP_CHAN_RPT_FILTER:
        if (value & APCHAN_RPT_SSID_FILTER) {
            vap->ap_chan_rpt_ssid_filter = TRUE;
        } else {
            vap->ap_chan_rpt_ssid_filter = FALSE;
        }
        if (value & APCHAN_RPT_OPCLASS_FILTER) {
            vap->ap_chan_rpt_opclass_filter = TRUE;
        } else {
            vap->ap_chan_rpt_opclass_filter = FALSE;
        }
        wlan_vdev_beacon_update(vap);
        break;
    case IEEE80211_PARAM_RRM_CAP:
        retv = wlan_set_param(vap, IEEE80211_RRM_CAP, !!value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_RRM_FILTER:
        retv = wlan_set_param(vap, IEEE80211_RRM_FILTER, !!value);
        break;
    case IEEE80211_PARAM_RRM_DEBUG:
        retv = wlan_set_param(vap, IEEE80211_RRM_DEBUG, value);
        break;
    case IEEE80211_PARAM_RRM_STATS:
        retv = wlan_set_param(vap, IEEE80211_RRM_STATS, !!value);
	break;
    case IEEE80211_PARAM_WNM_STATS:
        retv = wlan_set_param(vap, IEEE80211_WNM_STATS, !!value);
	break;
    case IEEE80211_PARAM_RRM_SLWINDOW:
        retv = wlan_set_param(vap, IEEE80211_RRM_SLWINDOW, !!value);
        break;
    case IEEE80211_PARAM_RRM_CAP_IE:
        retv = wlan_set_param(vap, IEEE80211_RRM_CAP_IE, !!value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_CAP:
        if (value > 1 || value < 0) {
            qdf_print(" ERR :- Invalid value %d Value to be either 0 or 1 ", value);
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_WNM_CAP, value);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
         if (ic->nss_vops)
            ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_WIFI_VDEV_CFG_WNM_CAP);
#endif
            if (retv == EOK) {
                retv = ENETRESET;
                restart_vap = true;
            }
        }
        break;
     case IEEE80211_PARAM_WNM_FILTER:
         retv = wlan_set_param(vap, IEEE80211_WNM_FILTER, !!value);
         break;
     case IEEE80211_PARAM_WNM_BSS_CAP: /* WNM Max BSS idle */
         if (value > 1 || value < 0) {
             qdf_print(" ERR :- Invalid value %d Value to be either 0 or 1 ", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_BSS_CAP, value);
             if (retv == EOK) {
                 retv = ENETRESET;
                restart_vap = true;
             }
         }
         break;
     case IEEE80211_PARAM_WNM_TFS_CAP:
         if (value > 1 || value < 0) {
             qdf_print(" ERR :- Invalid value %d Value to be either 0 or 1 ", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_TFS_CAP, value);

            if (value) {
                osifp->wifi3_0_fast_path = 0;
            }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
         if (ic->nss_vops)
             ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_WIFI_VDEV_CFG_WNM_TFS);
#endif
             if (retv == EOK) {
                 retv = ENETRESET;
                restart_vap = true;
             }
         }
         break;
     case IEEE80211_PARAM_WNM_TIM_CAP:
         if (value > 1 || value < 0) {
             qdf_print(" ERR :- Invalid value %d Value to be either 0 or 1 ", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_TIM_CAP, value);
             if (retv == EOK) {
                 retv = ENETRESET;
                restart_vap = true;
             }
         }
         break;
     case IEEE80211_PARAM_WNM_SLEEP_CAP:
         if (value > 1 || value < 0) {
             qdf_print(" ERR :- Invalid value %d Value to be either 0 or 1 ", value);
             return -EINVAL;
         } else {
             retv = wlan_set_param(vap, IEEE80211_WNM_SLEEP_CAP, value);
             if (retv == EOK) {
                 retv = ENETRESET;
                 restart_vap = true;
             }
         }
         break;
    case IEEE80211_PARAM_WNM_FMS_CAP:
        if (value > 1 || value < 0) {
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_WNM_FMS_CAP, value);
            if (retv == EOK) {
                retv = ENETRESET;
                restart_vap = true;
             }
        }
        break;
#endif
    case IEEE80211_PARAM_FWD_ACTION_FRAMES_TO_APP:
        if (value > 1 || value < 0) {
            qdf_err("Invalid value %d, should be either 0 or 1", value);
            return -EINVAL;
        } else {
            retv = wlan_set_param(vap, IEEE80211_FWD_ACTION_FRAMES_TO_APP, value);
        }
        break;
    case IEEE80211_PARAM_PWRTARGET:
        retv = wlan_set_device_param(ic, IEEE80211_DEVICE_PWRTARGET, value);
        break;
    case IEEE80211_PARAM_WMM:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_WMM, value);
        if (retv != EOK)
            break;

        /* AMPDU should reflect changes to WMM */
        if (value && ic->ic_set_config_enable(vap))
            value = CUSTOM_AGGR_MAX_AMPDU_SIZE; //Lithium
        else if (value)
            value = IEEE80211_AMPDU_SUBFRAME_MAX;

        /* Notice fallthrough */
    case IEEE80211_PARAM_AMPDU:
        if (osifp->osif_is_mode_offload) {
            uint32_t ampdu;

            ucfg_wlan_vdev_mgr_get_param(vdev, WLAN_MLME_CFG_AMPDU, &ampdu);
            /* configure the max ampdu subframes */
                prev_state = ampdu ? 1:0;
            retv = wlan_set_param(vap, IEEE80211_AMPDU_SET, value);
            if (retv == -EINVAL)
                return -EINVAL;
            else {
                ucfg_wlan_vdev_mgr_get_param(vdev, WLAN_MLME_CFG_AMPDU, &ampdu);
                new_state = ampdu ? 1:0;
            }
        }

        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }

#if ATH_SUPPORT_IBSS_HT
        /*
         * config ic adhoc AMPDU capability
         */
        if (vap->iv_opmode == IEEE80211_M_IBSS) {

            wlan_dev_t ic = wlan_vap_get_devhandle(vap);

            if (value &&
               (ieee80211_ic_ht20Adhoc_is_set(ic) || ieee80211_ic_ht40Adhoc_is_set(ic))) {
                wlan_set_device_param(ic, IEEE80211_DEVICE_HTADHOCAGGR, 1);
                qdf_print("%s IEEE80211_PARAM_AMPDU = %d and HTADHOC enable", __func__, value);
            } else {
                wlan_set_device_param(ic, IEEE80211_DEVICE_HTADHOCAGGR, 0);
                qdf_print("%s IEEE80211_PARAM_AMPDU = %d and HTADHOC disable", __func__, value);
            }
            if ((prev_state) && (!new_state)) {
                retv = ENETRESET;
            } else {
                // don't reset
                retv = EOK;
            }
        }
#endif /* end of #if ATH_SUPPORT_IBSS_HT */

        break;
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    case IEEE80211_PARAM_REJOINT_ATTEMP_TIME:
        retv = wlan_set_param(vap,IEEE80211_REJOINT_ATTEMP_TIME,value);
        break;
#endif


    case IEEE80211_PARAM_RX_AMSDU:
        /*
         * API supports only maximum data tid values i.e. 0-7.
         */
        if (val[1] > 7 || !(val[2] == 0 || val[2] == 1)) {
            qdf_err("Usage: iwpriv athx tid <0/1>");
            return -EINVAL;
        }
        ieee80211com_set_rx_amsdu(ic, val[1], val[2]);
        break;

    case IEEE80211_PARAM_AMSDU:
#if defined(TEMP_AGGR_CFG)
        if (!value) {
            ieee80211vap_clear_flag_ext(vap, IEEE80211_FEXT_AMSDU);
        } else {
            ieee80211vap_set_flag_ext(vap, IEEE80211_FEXT_AMSDU);
        }

        if (osifp->osif_is_mode_offload) {
            /* configure the max amsdu subframes */
            retv = wlan_set_param(vap, IEEE80211_AMSDU_SET, value);
        }
#endif
        break;

        case IEEE80211_PARAM_RATE_DROPDOWN:
            if (osifp->osif_is_mode_offload) {
                if ((value >= 0) && (value <= RATE_DROPDOWN_LIMIT)) {
                        vap->iv_ratedrop = value;
                        retv = ic->ic_vap_set_param(vap, IEEE80211_RATE_DROPDOWN_SET, value);
                } else {
                        qdf_print("Rate Control Logic is [0-7]");
                        retv = -EINVAL;
                }
            } else {
                qdf_print("This Feature is Supported for Offload Mode Only");
                return -EINVAL;
            }
        break;

    case IEEE80211_PARAM_11N_TX_AMSDU:
        /* Enable/Disable Tx AMSDU for HT clients. Sanitise to 0 or 1 only */
        vap->iv_disable_ht_tx_amsdu = !!value;
        break;

    case IEEE80211_PARAM_CTSPROT_DTIM_BCN:
        retv = wlan_set_vap_cts2self_prot_dtim_bcn(vap, !!value);
        if (!retv)
            retv = EOK;
        else
            retv = -EINVAL;
       break;

    case IEEE80211_PARAM_VSP_ENABLE:
        /* Enable/Disable VSP for VOW */
        vap->iv_enable_vsp = !!value;
        break;

    case IEEE80211_PARAM_SHORTPREAMBLE:
        retv = wlan_set_param(vap, IEEE80211_SHORT_PREAMBLE, value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
       break;

    case IEEE80211_PARAM_CHANBW:
        switch (value)
        {
        case 0:
            ic->ic_chanbwflag = 0;
            break;
        case 1:
            ic->ic_chanbwflag = IEEE80211_CHAN_HALF;
            break;
        case 2:
            ic->ic_chanbwflag = IEEE80211_CHAN_QUARTER;
            break;
        default:
            retv = -EINVAL;
            break;
        }

       /*
        * bandwidth change need reselection of channel based on the chanbwflag
        * This is required if the command is issued after the freq has been set
        * neither the chanbw param does not take effect
        */
       if ( retv == 0 ) {
           deschan_freq = wlan_get_param(vap, IEEE80211_DESIRED_CHANNEL);
           retv  = wlan_set_channel(vap, deschan_freq, vap->iv_des_cfreq2);

           if (retv == 0) {
               /*Reinitialize the vap*/
               retv = ENETRESET ;
           }
       }
#if UMAC_SUPPORT_CFG80211
       wlan_cfg80211_update_channel_list(ic);
#endif
        break;

    case IEEE80211_PARAM_INACT:
        if(ieee80211_vap_wnm_is_set(vap) && (vap->wnm) &&
                (ieee80211_wnm_bss_is_set(vap->wnm)) &&
                (ic->ic_get_tgt_type(ic) >= TARGET_TYPE_QCA8074)) {
            /* If Max BSS Idle Time feature is enabled, the max inactive timer
             * value should be updated using 'setbssmax' command to update
             * the new value in Max BSS Idle Time IE
             */
            qdf_info("Max BSS Idle Time feature is enabled!\n"
                     "'inact' command is disallowed\n"
                     "Use 'setbssmax' command instead to increase inactivity timer.");
        } else {
            wlan_set_param(vap, IEEE80211_RUN_INACT_TIMEOUT, value);
        }
        break;
    case IEEE80211_PARAM_INACT_AUTH:
        wlan_set_param(vap, IEEE80211_AUTH_INACT_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_INACT_INIT:
        wlan_set_param(vap, IEEE80211_INIT_INACT_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_SESSION_TIMEOUT:
        wlan_set_param(vap, IEEE80211_SESSION_TIMEOUT, value);
        break;
    case IEEE80211_PARAM_WDS_AUTODETECT:
        wlan_set_param(vap, IEEE80211_WDS_AUTODETECT, value);
        break;
    case IEEE80211_PARAM_WEP_TKIP_HT:
		wlan_set_param(vap, IEEE80211_WEP_TKIP_HT, value);
        retv = ENETRESET;
        break;
    case IEEE80211_PARAM_IGNORE_11DBEACON:
        wlan_set_param(vap, IEEE80211_IGNORE_11DBEACON, value);
        break;
    case IEEE80211_PARAM_MFP_TEST:
        wlan_set_param(vap, IEEE80211_FEATURE_MFP_TEST, value);
        break;

#ifdef QCA_PARTNER_PLATFORM
    case IEEE80211_PARAM_PLTFRM_PRIVATE:
        retv = wlan_pltfrm_set_param(vap, value);
        if ( retv == EOK) {
                retv = ENETRESET;
        }
        break;
#endif

    case IEEE80211_PARAM_NO_STOP_DISASSOC:
        if (value)
                osifp->no_stop_disassoc = 1;
        else
                osifp->no_stop_disassoc = 0;
        break;
#if UMAC_SUPPORT_VI_DBG

    case IEEE80211_PARAM_DBG_CFG:
        osifp->vi_dbg = value;
        if (value) {
                osifp->wifi3_0_fast_path = 0;
        }
        ieee80211_vi_dbg_set_param(vap, IEEE80211_VI_DBG_CFG, value);
        break;

    case IEEE80211_PARAM_RESTART:
        ieee80211_vi_dbg_set_param(vap, IEEE80211_VI_RESTART, value);
        break;
    case IEEE80211_PARAM_RXDROP_STATUS:
        ieee80211_vi_dbg_set_param(vap, IEEE80211_VI_RXDROP_STATUS, value);
        break;
#endif
    case IEEE80211_IOC_WPS_MODE:
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                        "set IEEE80211_IOC_WPS_MODE to 0x%x\n", value);
        retv = wlan_set_param(vap, IEEE80211_WPS_MODE, value);
        break;

    case IEEE80211_IOC_SCAN_FLUSH:
#if ATH_SUPPORT_WRAP
        /*Avoid flushing scan results in proxysta case as proxysta needs to
          use the scan results of main-proxysta */
        if (vap->iv_no_event_handler) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set %s\n",
                "Bypass IEEE80211_IOC_SCAN_FLUSH for non main-proxysta");
            break;
        }
#endif
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "set %s\n",
                        "IEEE80211_IOC_SCAN_FLUSH");
        status = wlan_objmgr_pdev_try_get_ref(pdev, WLAN_OSIF_SCAN_ID);
        if (QDF_IS_STATUS_ERROR(status)) {
            scan_info("unable to get reference");
            retv = -EBUSY;
            break;
        }
        ucfg_scan_flush_results(pdev, NULL);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_OSIF_SCAN_ID);
        retv = 0; /* success */
        break;

#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_PARAM_TXBF_AUTO_CVUPDATE:
        wlan_set_param(vap, IEEE80211_TXBF_AUTO_CVUPDATE, value);
        ic->ic_set_config(vap);
        break;
    case IEEE80211_PARAM_TXBF_CVUPDATE_PER:
        wlan_set_param(vap, IEEE80211_TXBF_CVUPDATE_PER, value);
        ic->ic_set_config(vap);
        break;
#endif
    case IEEE80211_PARAM_SCAN_BAND:
        if ((value == OSIF_SCAN_BAND_2G_ONLY  && IEEE80211_SUPPORT_PHY_MODE(ic,IEEE80211_MODE_11G)) ||
            (value == OSIF_SCAN_BAND_5G_ONLY  && IEEE80211_SUPPORT_PHY_MODE(ic,IEEE80211_MODE_11A)) ||
            (value == OSIF_SCAN_BAND_ALL))
        {
            osifp->os_scan_band = value;
        }
        retv = 0;
        break;

    case IEEE80211_PARAM_SCAN_CHAN_EVENT:
        if (osifp->osif_is_mode_offload &&
            wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
            osifp->is_scan_chevent = !!value;
            retv = 0;
        } else {
            qdf_print("IEEE80211_PARAM_SCAN_CHAN_EVENT is valid only for 11ac "
                   "offload, and in IEEE80211_M_HOSTAP(Access Point) mode");
            retv = -EOPNOTSUPP;
        }
        break;

#if UMAC_SUPPORT_PROXY_ARP
    case IEEE80211_PARAM_PROXYARP_CAP:
        wlan_set_param(vap, IEEE80211_PROXYARP_CAP, value);
	    break;
#if UMAC_SUPPORT_DGAF_DISABLE
    case IEEE80211_PARAM_DGAF_DISABLE:
        wlan_set_param(vap, IEEE80211_DGAF_DISABLE, value);
        break;
#endif
#endif
#if UMAC_SUPPORT_HS20_L2TIF
    case IEEE80211_PARAM_L2TIF_CAP:
        value = value ? 0 : 1;
        wlan_set_param(vap, IEEE80211_FEATURE_APBRIDGE, value);
       break;
#endif
    case IEEE80211_PARAM_EXT_ACS_IN_PROGRESS:
        wlan_set_param(vap, IEEE80211_EXT_ACS_IN_PROGRESS, value);
        break;

    case IEEE80211_PARAM_SEND_ADDITIONAL_IES:
        wlan_set_param(vap, IEEE80211_SEND_ADDITIONAL_IES, value);
        break;

    case IEEE80211_PARAM_APONLY:
#if UMAC_SUPPORT_APONLY
        vap->iv_aponly = value ? true : false;
        ic->ic_aponly = vap->iv_aponly;
#else
        qdf_print("APONLY not enabled");
#endif
        break;
    case IEEE80211_PARAM_ONETXCHAIN:
        vap->iv_force_onetxchain = value ? true : false;
        break;

    case IEEE80211_PARAM_SET_CABQ_MAXDUR:
        if (value > 0 && value < 100)
            wlan_set_param(vap, IEEE80211_SET_CABQ_MAXDUR, value);
        else
            qdf_print("Percentage should be between 0 and 100");
        break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    case IEEE80211_PARAM_NOPBN:
        wlan_set_param(vap, IEEE80211_NOPBN, value);
        break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    case IEEE80211_PARAM_DSCP_MAP_ID:
        qdf_print("Set DSCP override %d",value);
        wlan_set_param(vap, IEEE80211_DSCP_MAP_ID, value);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops)
        ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_WIFI_VDEV_CFG_DSCP_OVERRIDE);
#endif
        break;
    case IEEE80211_PARAM_DSCP_TID_MAP:
        qdf_print("Set vap dscp tid map");
        wlan_set_vap_dscp_tid_map(osifp->os_if, val[1], val[2]);
        break;
#endif
    case IEEE80211_PARAM_TXRX_VAP_STATS:
	    retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_VAP_STATS, value);
        break;
    case IEEE80211_PARAM_TXRX_DBG:
	    retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_DBG_SET, value);
        break;
    case IEEE80211_PARAM_VAP_TXRX_FW_STATS:
        retv = ic->ic_vap_set_param(vap, IEEE80211_VAP_TXRX_FW_STATS, value);
        break;
    case IEEE80211_PARAM_TXRX_FW_STATS:
        retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_FW_STATS, value);
        break;
    case IEEE80211_PARAM_TXRX_FW_MSTATS:
        retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_FW_MSTATS, value);
        break;
    case IEEE80211_PARAM_VAP_TXRX_FW_STATS_RESET:
       retv = ic->ic_vap_set_param(vap, IEEE80211_VAP_TXRX_FW_STATS_RESET, value);
       break;
    case IEEE80211_PARAM_TXRX_FW_STATS_RESET:
       retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_FW_STATS_RESET, value);
       break;
    case IEEE80211_PARAM_TXRX_DP_STATS:
       retv = ic->ic_vap_set_param(vap, IEEE80211_TXRX_DP_STATS, value);
       break;
    case IEEE80211_PARAM_TX_PPDU_LOG_CFG:
        retv = ic->ic_vap_set_param(vap, IEEE80211_TX_PPDU_LOG_CFG_SET, value);
        break;
    case IEEE80211_PARAM_MAX_SCANENTRY:
        retv = wlan_set_param(vap, IEEE80211_MAX_SCANENTRY, value);
        break;
    case IEEE80211_PARAM_SCANENTRY_TIMEOUT:
        retv = wlan_set_param(vap, IEEE80211_SCANENTRY_TIMEOUT, value);
        break;
#if ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_PARAM_CLR_RAWMODE_PKT_SIM_STATS:
        retv = wlan_set_param(vap, IEEE80211_CLR_RAWMODE_PKT_SIM_STATS, value);
        break;
#endif /* ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    default:
        retv = -EOPNOTSUPP;
        if (retv) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "%s parameter 0x%x is "
                            "not supported retv=%d\n", __func__, param, retv);
        }
        break;

   case IEEE80211_PARAM_DFS_CACTIMEOUT:
#if ATH_SUPPORT_DFS
    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
            QDF_STATUS_SUCCESS) {
        return -1;
    }
    retv = mlme_dfs_override_cac_timeout(pdev, value);
    wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
    if (retv != 0)
        retv = -EOPNOTSUPP;
    break;
#else
        retv = -EOPNOTSUPP;
    break;
#endif /* ATH_SUPPORT_DFS */

   case IEEE80211_PARAM_ENABLE_RTSCTS:
       retv = wlan_set_param(vap, IEEE80211_ENABLE_RTSCTS, value);
   break;
    case IEEE80211_PARAM_MAX_AMPDU:
        if ((value >= IEEE80211_MAX_AMPDU_MIN) &&
            (value <= IEEE80211_MAX_AMPDU_MAX)) {
            retv = wlan_set_param(vap, IEEE80211_MAX_AMPDU, value);
 	        if ( retv == EOK ) {
                retv = ENETRESET;
                restart_vap = true;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_VHT_MAX_AMPDU:
        if ((value >= IEEE80211_VHT_MAX_AMPDU_MIN) &&
            (value <= IEEE80211_VHT_MAX_AMPDU_MAX)) {
            retv = wlan_set_param(vap, IEEE80211_VHT_MAX_AMPDU, value);
            if ( retv == EOK ) {
                retv = ENETRESET;
                restart_vap = true;
            }
        } else {
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_IMPLICITBF:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_IMPLICITBF, value);
        if ( retv == EOK ) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_VHT_SUBFEE:
        if (value == 0 ) {
            /* if SU is disabled, disable MU as well */
            wlan_set_param(vap, IEEE80211_VHT_MUBFEE, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_SUBFEE, value);
        if (retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_VHT_MUBFEE:
        if (value == 1) {
            /* if MU is enabled, enable SU as well */
            wlan_set_param(vap, IEEE80211_VHT_SUBFEE, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_MUBFEE, value);
        if (retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_VHT_SUBFER:
        if (value == 0 ) {
            /* if SU is disabled, disable MU as well */
            wlan_set_param(vap, IEEE80211_VHT_MUBFER, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_SUBFER, value);
        if (retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_VHT_MUBFER:
        if (value == 1 ) {
            /* if MU is enabled, enable SU as well */
            wlan_set_param(vap, IEEE80211_VHT_SUBFER, value);
        }
        retv = wlan_set_param(vap, IEEE80211_VHT_MUBFER, value);
        if (retv == 0 && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_VHT_STS_CAP:
        retv = wlan_set_param(vap, IEEE80211_VHT_BF_STS_CAP, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_VHT_SOUNDING_DIM:
        retv = wlan_set_param(vap, IEEE80211_VHT_BF_SOUNDING_DIM, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_VHT_MCS_10_11_SUPP:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_VHT_MCS_10_11_SUPP, value);
        if(retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_VHT_MCS_10_11_NQ2Q_PEER_SUPP:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_VHT_MCS_10_11_NQ2Q_PEER_SUPP, value);
        if(retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_MCAST_RC_STALE_PERIOD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_MCAST_RC_STALE_PERIOD, value);
        break;
    case IEEE80211_PARAM_ENABLE_MCAST_RC:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ENABLE_MCAST_RC, value);
        break;
    case IEEE80211_PARAM_RC_NUM_RETRIES:
        retv = wlan_set_param(vap, IEEE80211_RC_NUM_RETRIES, value);
        break;
    case IEEE80211_PARAM_256QAM_2G:
        retv = wlan_set_param(vap, IEEE80211_256QAM, value);
        if (retv == EOK) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_11NG_VHT_INTEROP:
        if (osifp->osif_is_mode_offload) {
            retv = wlan_set_param(vap, IEEE80211_11NG_VHT_INTEROP , value);
            if (retv == EOK) {
                retv = ENETRESET;
            }
        } else {
            qdf_print("Not supported in this vap ");
        }
        break;
#if UMAC_VOW_DEBUG
    case IEEE80211_PARAM_VOW_DBG_ENABLE:
        {
            osifp->vow_dbg_en = value;
            if (value) {
                osifp->wifi3_0_fast_path = 0;
            }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (ic->nss_vops)
            ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_WIFI_VDEV_VOW_DBG_MODE);
#endif
        }
        break;
#endif

#if WLAN_SUPPORT_SPLITMAC
    case IEEE80211_PARAM_SPLITMAC:
        splitmac_set_enabled_flag(vdev, !!value);

        if (splitmac_is_enabled(vdev)) {
            osifp->app_filter =  IEEE80211_FILTER_TYPE_ALL;
            wlan_set_param(vap, IEEE80211_TRIGGER_MLME_RESP, 1);
        } else {
            osifp->app_filter =  0;
            wlan_set_param(vap, IEEE80211_TRIGGER_MLME_RESP, 0);
        }
        break;
#endif
#if ATH_PERF_PWR_OFFLOAD
    case IEEE80211_PARAM_VAP_TX_ENCAP_TYPE:
        retv = wlan_set_param(vap, IEEE80211_VAP_TX_ENCAP_TYPE, value);
        if(retv == EOK) {
            if (value != htt_cmn_pkt_type_ethernet) {
                osifp->wifi3_0_fast_path = 0;
            }
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
    case IEEE80211_PARAM_VAP_RX_DECAP_TYPE:
        retv = wlan_set_param(vap, IEEE80211_VAP_RX_DECAP_TYPE, value);
        if(retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_PARAM_RAWMODE_SIM_TXAGGR:
        retv = wlan_set_param(vap, IEEE80211_RAWMODE_SIM_TXAGGR, value);
        break;
    case IEEE80211_PARAM_RAWMODE_SIM_DEBUG_LEVEL:
        retv = wlan_set_param(vap, IEEE80211_RAWMODE_SIM_DEBUG_LEVEL, value);
        break;
    case IEEE80211_PARAM_RAWSIM_DEBUG_NUM_ENCAP_FRAMES:
        retv = wlan_set_param(vap, IEEE80211_RAWSIM_DEBUG_NUM_ENCAP_FRAMES, value);
        break;
    case IEEE80211_PARAM_RAWSIM_DEBUG_NUM_DECAP_FRAMES:
        retv = wlan_set_param(vap, IEEE80211_RAWSIM_DEBUG_NUM_DECAP_FRAMES, value);
        break;
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
#endif /* ATH_PERF_PWR_OFFLOAD */
    case IEEE80211_PARAM_STA_FIXED_RATE:
        /* set a fixed data rate for an associated STA on a AP vap.
         * assumes that vap is already enabled for fixed rate, and
         * this setting overrides the vap's setting.
         *
         * encoding (legacey)  : ((aid << 8)  |
         *                          (preamble << 6) | ((nss-1) << 4) | mcs)
         * encoding (he_target): ((aid << 16) |
         *                          (preamble << 8) | ((nss-1) << 5) | mcs)
         * preamble (OFDM) = 0x0
         * preamble (CCK)  = 0x1
         * preamble (HT)   = 0x2
         * preamble (VHT)  = 0x3
         * preamble (HE)   = 0x4
         */
        if (osifp->os_opmode != IEEE80211_M_HOSTAP) {
            return -EINVAL;
        }

        if (IEEE80211_VAP_IN_FIXED_RATE_MODE(vap)) {
            struct find_wlan_node_req req;
            if (!ic->ic_he_target) {
                req.assoc_id = ((value >> RATECODE_LEGACY_RC_SIZE)
                                        & IEEE80211_ASSOC_ID_MASK);
            } else {
                req.assoc_id = ((value >> RATECODE_V1_RC_SIZE)
                                        & IEEE80211_ASSOC_ID_MASK);
            }
            req.node = NULL;
            wlan_iterate_station_list(vap, find_wlan_node_by_associd, &req);
            if (req.node) {
                uint32_t fixed_rate;
                if (!ic->ic_he_target) {
                    fixed_rate = value & RATECODE_LEGACY_RC_MASK;
                } else {
                    fixed_rate = value & RATECODE_V1_RC_MASK;
                    /* V1 rate code format is ((((1) << 28) |(pream) << 8)
                     * | ((nss) << 5) | (rate)). With this command, user
                     * will send us  16 bit _rate = (((_pream) << 8) | ((nss)
                     * << 5) | rate). We need to assemble user sent _rate as
                     * V1 rate = (((1) << 28) | _rate).
                     */
                    fixed_rate = V1_RATECODE_FROM_RATE(fixed_rate);
                }
                retv = wlan_node_set_fixed_rate(req.node, fixed_rate);
            } else {
                return -EINVAL;
            }
        }
        break;

#if QCA_AIRTIME_FAIRNESS
    case IEEE80211_PARAM_ATF_TXBUF_SHARE:
        retv = ucfg_atf_set_txbuf_share(vap->vdev_obj, value);
        break;
    case IEEE80211_PARAM_ATF_TXBUF_MAX:
        ucfg_atf_set_max_txbufs(vap->vdev_obj, value);
        break;
    case IEEE80211_PARAM_ATF_TXBUF_MIN:
        ucfg_atf_set_min_txbufs(vap->vdev_obj, value);
        break;
    case  IEEE80211_PARAM_ATF_OPT:
        if (value > 1) {
            qdf_print("update commit value(1) wrong ");
            return -EINVAL;
        }
        if (value)
            retv = ucfg_atf_set(vap->vdev_obj);
        else
            retv = ucfg_atf_clear(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT:
        ucfg_atf_set_airtime_tput(vap->vdev_obj, value);
        break;
    case  IEEE80211_PARAM_ATF_PER_UNIT:
        ucfg_atf_set_per_unit(ic->ic_pdev_obj);
        break;
    case  IEEE80211_PARAM_ATF_MAX_CLIENT:
        retv = ucfg_atf_set_maxclient(ic->ic_pdev_obj, value);
        break;
    case  IEEE80211_PARAM_ATF_SSID_GROUP:
        ucfg_atf_set_ssidgroup(ic->ic_pdev_obj, vap->vdev_obj, value);
        break;
    case IEEE80211_PARAM_ATF_SSID_SCHED_POLICY:
        retv = ucfg_atf_set_ssid_sched_policy(vap->vdev_obj, value);
        break;
    case IEEE80211_PARAM_ATF_ENABLE_STATS:
        if (ic->ic_is_target_lithium && ic->ic_is_target_lithium(psoc)) {
            retv = ucfg_atf_enable_stats(ic->ic_pdev_obj, value);
        } else {
            qdf_err("ATF STATS is not supported in this Target!\n");
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_ATF_STATS_TIMEOUT:
        if (ic->ic_is_target_lithium && ic->ic_is_target_lithium(psoc)) {
            retv = ucfg_atf_set_stats_timeout(ic->ic_pdev_obj, value);
        } else {
            qdf_err("ATF STATS is not supported in this Target!\n");
            return -EINVAL;
        }
        break;
#endif
#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)
    case IEEE80211_PARAM_VAP_SSID_CONFIG:
        return ucfg_son_set_ssid_steering_config(vap->vdev_obj,value);
        break;
#endif
    case IEEE80211_PARAM_RX_FILTER_MONITOR:
        if(IEEE80211_M_MONITOR != vap->iv_opmode && !vap->iv_smart_monitor_vap && !vap->iv_special_vap_mode) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not monitor VAP or Smart monitor VAP!\n");
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_RX_FILTER_MONITOR, value);
        break;
    case  IEEE80211_PARAM_RX_FILTER_NEIGHBOUR_PEERS_MONITOR:
        /* deliver configured bss peer packets, associated to smart
         * monitor vap and filter out other valid/invalid peers
         */
        if(!vap->iv_smart_monitor_vap) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not smart monitor VAP!\n");
            return -EINVAL;
        }
        retv = wlan_set_param(vap, IEEE80211_RX_FILTER_NEIGHBOUR_PEERS_MONITOR, value);
        break;
    case IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE:
        if(value < 0) {
            ic->ic_mpdudensityoverride = 0;
        } else if(value <= IEEE80211_HTCAP_MPDUDENSITY_MAX) {
            /* mpdudensityoverride
             * Bits
             * 7 --  4   3  2  1    0
             * +------------------+----+
             * |       |  MPDU    |    |
             * | Rsvd  | DENSITY  |E/D |
             * +---------------+-------+
             */
            ic->ic_mpdudensityoverride = 1;
            ic->ic_mpdudensityoverride |= ((u_int8_t)value & 0x07) << 1;
        } else {
            qdf_print("Usage:\n"
                    "-1 - Disable mpdu density override \n"
                    "%d - No restriction \n"
                    "%d - 1/4 usec \n"
                    "%d - 1/2 usec \n"
                    "%d - 1 usec \n"
                    "%d - 2 usec \n"
                    "%d - 4 usec \n"
                    "%d - 8 usec \n"
                    "%d - 16 usec ",
                    IEEE80211_HTCAP_MPDUDENSITY_NA,
                    IEEE80211_HTCAP_MPDUDENSITY_0_25,
                    IEEE80211_HTCAP_MPDUDENSITY_0_5,
                    IEEE80211_HTCAP_MPDUDENSITY_1,
                    IEEE80211_HTCAP_MPDUDENSITY_2,
                    IEEE80211_HTCAP_MPDUDENSITY_4,
                    IEEE80211_HTCAP_MPDUDENSITY_8,
                    IEEE80211_HTCAP_MPDUDENSITY_16);
            retv = EINVAL;
        }
        /* Reset VAP */
        if(retv != EINVAL) {
            wlan_chan_t chan = wlan_get_bss_channel(vap);
            if (chan != IEEE80211_CHAN_ANYC) {
                retv = ENETRESET;
                restart_vap = true;
            }
        }
        break;

    case IEEE80211_PARAM_SMART_MESH_CONFIG:
        retv = wlan_set_param(vap, IEEE80211_SMART_MESH_CONFIG, value);
        break;
#if MESH_MODE_SUPPORT
    case IEEE80211_PARAM_MESH_CAPABILITIES:
        retv = wlan_set_param(vap, IEEE80211_MESH_CAPABILITIES, value);
        break;
    case IEEE80211_PARAM_ADD_LOCAL_PEER:
        if (vap->iv_mesh_vap_mode) {
            qdf_print("adding local peer ");
            retv = ieee80211_add_localpeer(vap,extra);
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_SET_MHDR:
        if(vap && vap->iv_mesh_vap_mode) {
            qdf_print("setting mhdr %x",value);
            vap->mhdr = value;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
            wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_ALLOW_DATA:
        if (vap->iv_mesh_vap_mode) {
            qdf_print(" authorise keys ");
            retv = ieee80211_authorise_local_peer(vap,extra);
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_SET_MESHDBG:
        if(vap && vap->iv_mesh_vap_mode) {
            qdf_print("mesh dbg %x",value);
            vap->mdbg = value;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
            wlan_update_rawsim_config(vap);
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
        } else {
            return -EPERM;
        }
        break;
    case IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH:
        if (vap->iv_mesh_vap_mode) {
          retv = wlan_set_param(vap, IEEE80211_CONFIG_MGMT_TX_FOR_MESH, value);
        } else {
            return -EPERM;
        }
        break;

    case IEEE80211_PARAM_MESH_MCAST:
        if (vap->iv_mesh_vap_mode) {
          retv = wlan_set_param(vap, IEEE80211_CONFIG_MESH_MCAST, value);
        } else {
            return -EPERM;
        }
        break;

#if ATH_ACS_DEBUG_SUPPORT
    case IEEE80211_PARAM_ACS_DEBUG_SUPPORT:
        ic->ic_acs_debug_support = value ? 1 : 0;

        if (!value) {
            acs_debug_cleanup(ic->ic_acs);
        }
        break;
#endif

    case IEEE80211_PARAM_CONFIG_RX_MESH_FILTER:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_RX_MESH_FILTER, value);
        break;

#if ATH_DATA_RX_INFO_EN
    case IEEE80211_PARAM_RXINFO_PERPKT:
        vap->rxinfo_perpkt = !!value;
        break;
#endif
#endif

#ifdef VDEV_PEER_PROTOCOL_COUNT
    case IEEE80211_PARAM_VDEV_PEER_PROTOCOL_COUNT:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_COUNT,
                              value);
        osifp->peer_protocol_cnt = value;
        if (value) {
            osifp->wifi3_0_fast_path = 0;
        }
        break;
    case IEEE80211_PARAM_VDEV_PEER_PROTOCOL_DROP_MASK:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_DROP_MASK,
                              value);
        break;
#endif

    case IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W:
        if ((value == 0) || ASSOCWAR160_IS_VALID_CHANGE(value))
            retv = wlan_set_param(vap, IEEE80211_CONFIG_ASSOC_WAR_160W, value);
        else {
            qdf_print("Invalid value %d. Valid bitmap values are 0:Disable, 1:Enable VHT OP, 3:Enable VHT OP and VHT CAP",value);
            return -EINVAL;
        }
 break;
    case IEEE80211_PARAM_WHC_APINFO_SFACTOR:
        ucfg_son_set_scaling_factor(vap->vdev_obj, value);
        break;
    case IEEE80211_PARAM_WHC_SKIP_HYST:
        ucfg_son_set_skip_hyst(vap->vdev_obj, value);
        break;
    case IEEE80211_PARAM_WHC_APINFO_UPLINK_RATE:
        ucfg_son_set_uplink_rate(vap->vdev_obj, value);
        son_pdev_appie_update(ic);
        wlan_pdev_beacon_update(ic);
        break;
    case IEEE80211_PARAM_WHC_CAP_RSSI:
        ucfg_son_set_cap_rssi(vap->vdev_obj, value);
        break;
    case IEEE80211_PARAM_SON:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_SON, value);
        son_update_bss_ie(vap->vdev_obj);
        son_pdev_appie_update(ic);
        wlan_pdev_beacon_update(ic);
        break;
    case IEEE80211_PARAM_WHC_APINFO_OTHERBAND_BSSID:
        ucfg_son_set_otherband_bssid(vap->vdev_obj, &val[1]);
        son_update_bss_ie(vap->vdev_obj);
        son_pdev_appie_update(ic);
        wlan_pdev_beacon_update(ic);
        break;
    case IEEE80211_PARAM_WHC_APINFO_ROOT_DIST:
        ucfg_son_set_root_dist(vap->vdev_obj, value);
        son_update_bss_ie(vap->vdev_obj);
        son_pdev_appie_update(ic);
        wlan_pdev_beacon_update(ic);
        break;
    case IEEE80211_PARAM_REPT_MULTI_SPECIAL:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_REPT_MULTI_SPECIAL, value);
        son_pdev_appie_update(ic);
        break;
    case IEEE80211_PARAM_RAWMODE_PKT_SIM:
        retv = wlan_set_param(vap, IEEE80211_RAWMODE_PKT_SIM, value);
        break;
    case IEEE80211_PARAM_CONFIG_RAW_DWEP_IND:
        if ((value == 0) || (value == 1))
            retv = wlan_set_param(vap, IEEE80211_CONFIG_RAW_DWEP_IND, value);
        else {
            qdf_print("Invalid value %d. Valid values are 0:Disable, 1:Enable",value);
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_CUSTOM_CHAN_LIST:
        retv = wlan_set_param(vap,IEEE80211_CONFIG_PARAM_CUSTOM_CHAN_LIST, value);
        break;
#if UMAC_SUPPORT_ACFG
    case IEEE80211_PARAM_DIAG_WARN_THRESHOLD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_DIAG_WARN_THRESHOLD, value);
        break;
    case IEEE80211_PARAM_DIAG_ERR_THRESHOLD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_DIAG_ERR_THRESHOLD, value);
        break;
#endif
     case IEEE80211_PARAM_CONFIG_REV_SIG_160W:
        if(!wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_WAR_160W)){
            if ((value == 0) || (value == 1))
                retv = wlan_set_param(vap, IEEE80211_CONFIG_REV_SIG_160W, value);
            else {
                qdf_print("Invalid value %d. Valid values are 0:Disable, 1:Enable",value);
                return -EINVAL;
            }
        } else {
            qdf_print("revsig160 not supported with assocwar160");
            return -EINVAL;
        }
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_WAR:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_MU_CAP_WAR, value);
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_TIMER:
        if ((value >= 1) && (value <= 300))
            retv = wlan_set_param(vap, IEEE80211_CONFIG_MU_CAP_TIMER, value);
        else {
            IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                            "Invalid value %d. Valid value is between 1 and 300\n",value);
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            retv = wlan_set_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_HTMCS, value);
            if(retv == 0) {
                retv = ENETRESET;
                restart_vap = true;
            }
        } else {
            qdf_print("This iwpriv option disable_htmcs is valid only for AP mode vap");
        }
        break;
    case IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            if(value != 0) {
                retv = wlan_set_param(vap, IEEE80211_CONFIG_CONFIGURE_SELECTIVE_VHTMCS, value);
                if(retv == 0) {
                    retv = ENETRESET;
                    restart_vap = true;
                }
            }
        } else {
            qdf_print("This iwpriv option conf_11acmcs is valid only for AP mode vap");
        }
        break;
    case IEEE80211_PARAM_RDG_ENABLE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_RDG_ENABLE, value);
        break;
    case IEEE80211_PARAM_CLEAR_QOS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_CLEAR_QOS,value);
        break;
    case IEEE80211_PARAM_TRAFFIC_STATS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_TRAFFIC_STATS,value);
        break;
    case IEEE80211_PARAM_TRAFFIC_RATE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_TRAFFIC_RATE,value);
        break;
    case IEEE80211_PARAM_TRAFFIC_INTERVAL:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_TRAFFIC_INTERVAL,value);
        break;
    case IEEE80211_PARAM_WATERMARK_THRESHOLD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_WATERMARK_THRESHOLD,value);
        break;
    case IEEE80211_PARAM_ENABLE_VENDOR_IE:
	if( value == 0 || value == 1) {
	    if (vap->iv_ena_vendor_ie != value) {
                vap->iv_update_vendor_ie = 1;
            }
	    vap->iv_ena_vendor_ie = value;
	} else {
	    qdf_print("%s Enter 1: enable vendor ie, 0: disable vendor ie ",__func__);
	}
	break;
    case IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ASSOC_DENIAL_NOTIFICATION, value);
        break;
    case IEEE80211_PARAM_MACCMD_SEC:
        retv = wlan_set_acl_policy(vap, value, IEEE80211_ACL_FLAG_ACL_LIST_2);
        break;
    case IEEE80211_PARAM_CONFIG_MON_DECODER:
        if (IEEE80211_M_MONITOR != vap->iv_opmode) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not Monitor VAP!\n");
            return -EINVAL;
        }
        /* monitor vap decoder header type: radiotap=0(default) prism=1 */
        if (value != 0 && value != 1) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Invalid value! radiotap=0(default) prism=1 \n");
            return -EINVAL;
        }

        if (value == 0)
            dev->type = ARPHRD_IEEE80211_RADIOTAP;
        else
            dev->type = ARPHRD_IEEE80211_PRISM;

        wlan_set_param(vap, IEEE80211_CONFIG_MON_DECODER, value);
        break;
    case IEEE80211_PARAM_SIFS_TRIGGER_RATE:
        if (ic->ic_vap_set_param) {
           retv = ic->ic_vap_set_param(vap, IEEE80211_SIFS_TRIGGER_RATE, (u_int32_t)value);
        }
        break;
    case IEEE80211_PARAM_BEACON_RATE_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            int *rate_kbps = NULL;
            int i,j,rateKbps = 0;

            switch (vap->iv_des_mode)
            {
                case IEEE80211_MODE_11B:
                    {
                        rate_table.nrates = sizeof(basic_11b_rate)/sizeof(basic_11b_rate[0]);
                        rate_table.rates = (int *)&basic_11b_rate;
                        /* Checking the boundary condition for the valid rates */
                        if ((value < 1000) || (value > 11000)) {
                            qdf_print("%s : WARNING: Please try a valid rate between 1000 to 11000 kbps.",__func__);
                            return -EINVAL;
                        }
                    }
                    break;

                case IEEE80211_MODE_TURBO_G:
                case IEEE80211_MODE_11NG_HT20:
                case IEEE80211_MODE_11NG_HT40PLUS:
                case IEEE80211_MODE_11NG_HT40MINUS:
                case IEEE80211_MODE_11NG_HT40:
                case IEEE80211_MODE_11G:
                case IEEE80211_MODE_11AXG_HE20:
                case IEEE80211_MODE_11AXG_HE40PLUS:
                case IEEE80211_MODE_11AXG_HE40MINUS:
                case IEEE80211_MODE_11AXG_HE40:
                    {
                        rate_table.nrates = sizeof(basic_11bgn_rate)/sizeof(basic_11bgn_rate[0]);
                        rate_table.rates = (int *)&basic_11bgn_rate;
                        /* Checking the boundary condition for the valid rates */
                        if ((value < 1000) || (value > 24000)){
                            qdf_print("%s : WARNING: Please try a valid rate between 1000 to 24000 kbps.",__func__);
                            return -EINVAL;
                        }
                    }
                    break;

                case IEEE80211_MODE_11A:
                case IEEE80211_MODE_TURBO_A:
                case IEEE80211_MODE_11NA_HT20:
                case IEEE80211_MODE_11NA_HT40PLUS:
                case IEEE80211_MODE_11NA_HT40MINUS:
                case IEEE80211_MODE_11NA_HT40:
                case IEEE80211_MODE_11AC_VHT20:
                case IEEE80211_MODE_11AC_VHT40PLUS:
                case IEEE80211_MODE_11AC_VHT40MINUS:
                case IEEE80211_MODE_11AC_VHT40:
                case IEEE80211_MODE_11AC_VHT80:
                case IEEE80211_MODE_11AC_VHT160:
                case IEEE80211_MODE_11AC_VHT80_80:
                case IEEE80211_MODE_11AXA_HE20:
                case IEEE80211_MODE_11AXA_HE40PLUS:
                case IEEE80211_MODE_11AXA_HE40MINUS:
                case IEEE80211_MODE_11AXA_HE40:
                case IEEE80211_MODE_11AXA_HE80:
                case IEEE80211_MODE_11AXA_HE160:
                case IEEE80211_MODE_11AXA_HE80_80:
                    {
                        rate_table.nrates = (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) ?
                            sizeof(basic_11ax_6g_rate)/sizeof(basic_11ax_6g_rate[0]) :
                            sizeof(basic_11na_rate)/sizeof(basic_11na_rate[0]);
                        /* For 6GHz, check if the beacon rate setting is one of
                         * the basic rates or the allowed HE rates
                         */
                        rate_table.rates = (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) ?
                           ((int *)&basic_11ax_6g_rate) : ((int *)&basic_11na_rate);

                        /* Checking the boundary condition for the valid rates */
                        if ((value < 6000) || (value > 25800)){
                            qdf_print("%s : WARNING: Please try a valid rate between 6000 to 25800 kbps.",__func__);
                            return -EINVAL;
                        }
                    }
                    break;

                default:
                    {
                        qdf_print("%s : WARNING:Invalid channel mode.",__func__);
                        return -EINVAL;
                    }
            }
            rate_kbps = rate_table.rates;

            /* Check if the rate given by user is a valid basic rate.
             * If it is valid basic rate then go with that rate or else
             * if the rate passed by the user is not valid basic rate but
             * it falls inside the valid rate boundary corresponding to the
             * phy mode, then opt for the next valid basic rate.
             */
            for (i = 0; i < rate_table.nrates; i++) {
                if (value == *rate_kbps) {
                    rateKbps = *rate_kbps;
                } else if (value < *rate_kbps) {
                    rateKbps = *rate_kbps;
                    qdf_print("%s : MSG: Not a valid basic rate.",__func__);
                    qdf_print("Since the requested rate is below 24Mbps, moving forward and selecting the next valid basic rate : %d (Kbps)",rateKbps);
                }
                if (rateKbps) {
                    /* use the iv_op_rates, the VAP may not be up yet */
                    for (j = 0; j < vap->iv_op_rates[vap->iv_des_mode].rs_nrates; j++) {
                        if (rateKbps == (((vap->iv_op_rates[vap->iv_des_mode].rs_rates[j] & IEEE80211_RATE_VAL)* 1000) / 2)) {
                            found = 1;
                            break;
                        }
                    }

                    if(!found) {
                        /* Check if it is a valid 6GHz rate */
                        found = ieee80211_is_6g_valid_rate(vap, rateKbps);
                    }

                    if (!found) {
                        if (rateKbps == HIGHEST_BASIC_RATE) {
                            qdf_print("%s : MSG: Reached end of the table.",__func__);
                        } else {
                            value = *(rate_kbps+1);
                            qdf_print("%s : MSG: User opted rate is disabled. Hence going for the next rate: %d (Kbps)",__func__,value);
                        }
                    } else {
                        qdf_print("%s : Rate to be configured for beacon is: %d (Kbps)",__func__,rateKbps);
                        break;
                    }
                }
                rate_kbps++;
            }

            /* Suppose user has passed one rate and along with that rate the
             * higher rates are also not available in the rate table then
             * go with the lowest available basic rate.
             */
            if (!found) {
                uint32_t mgmt_rate;

                wlan_util_vdev_mlme_get_param(vap->vdev_mlme,
                        WLAN_MLME_CFG_TX_MGMT_RATE, &mgmt_rate);
                rateKbps = mgmt_rate;
                qdf_print("%s: MSG: The opted rate or higher rates are not available in node rate table.",__func__);
                qdf_print("MSG: Hence choosing the lowest available rate : %d (Kbps)",rateKbps);
            }
            retv = wlan_set_param(vap, IEEE80211_BEACON_RATE_FOR_VAP,rateKbps);
            if(retv == 0)
                retv = ENETRESET;
        } else {
            qdf_print("%s : WARNING: Setting beacon rate is allowed only for AP VAP ",__func__);
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {

            switch (vap->iv_des_mode)
            {
                case IEEE80211_MODE_11A:
                case IEEE80211_MODE_TURBO_A:
                case IEEE80211_MODE_11NA_HT20:
                case IEEE80211_MODE_11NA_HT40PLUS:
                case IEEE80211_MODE_11NA_HT40MINUS:
                case IEEE80211_MODE_11NA_HT40:
                case IEEE80211_MODE_11AC_VHT20:
                case IEEE80211_MODE_11AC_VHT40PLUS:
                case IEEE80211_MODE_11AC_VHT40MINUS:
                case IEEE80211_MODE_11AC_VHT40:
                case IEEE80211_MODE_11AC_VHT80:
                case IEEE80211_MODE_11AC_VHT160:
                case IEEE80211_MODE_11AC_VHT80_80:
                case IEEE80211_MODE_11AXA_HE20:
                case IEEE80211_MODE_11AXA_HE40PLUS:
                case IEEE80211_MODE_11AXA_HE40MINUS:
                case IEEE80211_MODE_11AXA_HE40:
                case IEEE80211_MODE_11AXA_HE80:
                case IEEE80211_MODE_11AXA_HE160:
                case IEEE80211_MODE_11AXA_HE80_80:
                   /* Mask has been set for rates: 24, 12 and 6 Mbps */
                    basic_valid_mask = 0x0150;
                    break;
                case IEEE80211_MODE_11B:
                   /* Mask has been set for rates: 11, 5.5, 2 and 1 Mbps */
                    basic_valid_mask = 0x000F;
                    break;
                case IEEE80211_MODE_TURBO_G:
                case IEEE80211_MODE_11NG_HT20:
                case IEEE80211_MODE_11NG_HT40PLUS:
                case IEEE80211_MODE_11NG_HT40MINUS:
                case IEEE80211_MODE_11NG_HT40:
                case IEEE80211_MODE_11AXG_HE20:
                case IEEE80211_MODE_11AXG_HE40PLUS:
                case IEEE80211_MODE_11AXG_HE40MINUS:
                case IEEE80211_MODE_11AXG_HE40:
                case IEEE80211_MODE_11G:
                   /* Mask has been set for rates: 24, 12, 6, 11, 5.5, 2 and 1 Mbps */
                    basic_valid_mask = 0x015F;
                    break;
                default:
                    break;
            }
           /*
            * Mask has been set as per the desired mode so that user will not be able to disable
            * all the supported basic rates.
            */

            if ((value & basic_valid_mask) != basic_valid_mask) {
                retv = wlan_set_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_LEGACY_RATE, value);
                if(retv == 0) {
                    retv = ENETRESET;
                    restart_vap = true;
                }
            } else {
                qdf_print("%s : WARNING: Disabling all basic rates is not permitted.",__func__);
            }
        } else {
            qdf_print("%s : WARNING: This iwpriv option dis_legacy is valid only for the VAP in AP mode",__func__);
        }
        break;

    case IEEE80211_PARAM_CONFIG_NSTSCAP_WAR:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_NSTSCAP_WAR,value);
    break;

    case IEEE80211_PARAM_TXPOW_MGMT:
    {
        frame_subtype = val[1];
        if(!tx_pow_mgmt_valid(frame_subtype,&tx_power))
            return -EINVAL;
        transmit_power = (tx_power &  0xFF);
        vap->iv_txpow_mgt_frm[(frame_subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)] = transmit_power;
        retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_VAP_TXPOW_MGMT, frame_subtype);
    }
    break;
     case IEEE80211_PARAM_TXPOW:
     {
        frame_type = val[1]>>IEEE80211_SUBTYPE_TXPOW_SHIFT;
        frame_subtype = (val[1]&0xff);
        if (!tx_pow_valid(frame_type, frame_subtype, &tx_power))
            return -EINVAL;

        transmit_power = (tx_power &  0xFF);
        if (0xff == frame_subtype) {
            for (loop_index = 0; loop_index < MAX_NUM_TXPOW_MGT_ENTRY; loop_index++) {
                vap->iv_txpow_frm[frame_type>>IEEE80211_FC0_TYPE_SHIFT][loop_index] = transmit_power;
            }
        } else {
            vap->iv_txpow_frm[frame_type >> IEEE80211_FC0_TYPE_SHIFT][(frame_subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)] = transmit_power;
        }

        qdf_print("TPC offload called");
        if (IEEE80211_FC0_TYPE_MGT == frame_type) {
            if (0xff != frame_subtype) {
                if ((IEEE80211_FC0_SUBTYPE_ACTION == frame_subtype) || (IEEE80211_FC0_SUBTYPE_PROBE_REQ == frame_subtype)) {
                    retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_VAP_TXPOW,
                                                (frame_type << IEEE80211_FRAMETYPE_TXPOW_SHIFT) + (frame_subtype << IEEE80211_SUBTYPE_TXPOW_SHIFT) + transmit_power);
                } else {
                    vap->iv_txpow_mgt_frm[(frame_subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)] = transmit_power;
                    retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_VAP_TXPOW_MGMT, frame_subtype);
                }
            } else {
                for (loop_index=0 ; loop_index < MAX_NUM_TXPOW_MGT_ENTRY; loop_index++) {
                    vap->iv_txpow_mgt_frm[loop_index] = transmit_power;
                    retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_VAP_TXPOW_MGMT, loop_index<<IEEE80211_FC0_SUBTYPE_SHIFT);
                }
                retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_VAP_TXPOW,
                                            (frame_type << IEEE80211_FRAMETYPE_TXPOW_SHIFT) + (frame_subtype << IEEE80211_SUBTYPE_TXPOW_SHIFT) + transmit_power);
            }
        } else {
            retv = ic->ic_vap_set_param(vap, IEEE80211_CONFIG_VAP_TXPOW,
                                        (frame_type << IEEE80211_FRAMETYPE_TXPOW_SHIFT) + (frame_subtype << IEEE80211_SUBTYPE_TXPOW_SHIFT) + transmit_power);
        }
    }
    break;
    case IEEE80211_PARAM_CHANNEL_SWITCH_MODE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_CHANNEL_SWITCH_MODE, value);
        break;

    case IEEE80211_PARAM_ENABLE_ECSA_IE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ECSA_IE, value);
        break;

    case IEEE80211_PARAM_SAE_PWID:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_SAE_PWID, value);
        break;

    case IEEE80211_PARAM_OCE_TX_POWER:
        retv = ieee80211_config_oce_tx_power(vap, extra);
        break;

    case IEEE80211_PARAM_OCE_IP_SUBNET_ID:
        retv = ieee80211_config_oce_ipsubnet_id(vap, extra);
        break;

    case IEEE80211_PARAM_OCE_ADD_ESS_RPT:
        retv = ieee80211_config_oce_ess_rpt_param(vap, extra);
        break;

    case IEEE80211_PARAM_RSNX_OVERRIDE:
        retv = ieee80211_config_rsnx(vap, extra);
        break;

    case IEEE80211_PARAM_ECSA_OPCLASS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ECSA_OPCLASS, value);
        break;

    case IEEE80211_PARAM_BACKHAUL:
        retv = wlan_set_param(vap, IEEE80211_FEATURE_BACKHAUL, value);
        break;

#if DYNAMIC_BEACON_SUPPORT
    case IEEE80211_PARAM_DBEACON_EN:
        if (value > 1  ||  value < 0) {
            qdf_print("Invalid value! value should be either 0 or 1 ");
            return -EINVAL;
        }
        if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
            if (vap->iv_dbeacon != value) {
                if (value == 0) { /*  value 0 */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Resume beacon \n");
                    qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
                    OS_CANCEL_TIMER(&vap->iv_dbeacon_suspend_beacon);
                    if (ieee80211_mlme_beacon_suspend_state(vap)) {
                        ieee80211_mlme_set_beacon_suspend_state(vap, false);
                    }
                    vap->iv_dbeacon = value;
                    qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
                } else { /*  value 1 */
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG, "Suspend beacon \n");
                    qdf_spin_lock_bh(&vap->iv_dbeacon_lock);
                    /*
                     * When suspending the beacon, set iv_dbeacon and continue
                     * with NETREST. Wait until mlme_ext_vap_up() to send the
                     * suspend command because FW will always reset beaconing
                     * to TX_ENABLE after VDEV restart. iv_dbeacon will ensure
                     * the suspend path is activated in the mlme_ext_vap_up()
                     * path. The resume path will remain since the host suspend
                     * state will need to be reset before iv_dbeacon is
                     * disabled.
                     */
                    vap->iv_dbeacon = value;
                    qdf_spin_unlock_bh(&vap->iv_dbeacon_lock);
                }
                retv = ENETRESET;
                break;
            }
            retv = EOK;
        } else {
            qdf_print("%s:%d: Dynamic beacon not allowed for vap-%d(%s)) as hidden ssid not configured. ",
                    __func__,__LINE__,vap->iv_unit,vap->iv_netdev_name);
            qdf_print("Enable hidden ssid before enable dynamic beacon ");
            return -EINVAL;
        }
        break;

    case IEEE80211_PARAM_DBEACON_SNR_THR:
        if (value < 10  ||  value > 100) { /* min:10  max:100 */
            qdf_print("Invalid value %d. Valid values are between 10  to 100 ",value);
            return -EINVAL;
        }
        vap->iv_dbeacon_snr_thr = (int8_t)value;
        break;

    case IEEE80211_PARAM_DBEACON_TIMEOUT:
        if (value < 30  ||  value > 3600) { /* min:30 secs  max:1hour */
            qdf_print("Invalid value %d. Valid values are between 30secs to 3600secs ",value);
            return -EINVAL;
        }
        vap->iv_dbeacon_timeout = value;
        break;

#endif
    case IEEE80211_PARAM_CONFIG_TX_CAPTURE:
        wlan_set_param(vap, IEEE80211_CONFIG_TX_CAPTURE, value);
        break;
#ifdef WLAN_SUPPORT_FILS
    case IEEE80211_PARAM_ENABLE_FILS:
        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
          qdf_err("FILS feature cannot be enabled for Non-Transmitting MBSS VAP!");
          return -EPERM;
        }
        if((!IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) ||
               (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) && IS_UP(dev))) {
            fils_en_period = ucfg_fd_get_enable_period(val[1], val[2]);
            retv = wlan_set_param(vap, IEEE80211_FEATURE_FILS, fils_en_period);
        }
        break;
#endif /* WLAN_SUPPORT_FILS */
    /* 11AX TODO ( Phase II) . Check ENETRESET
     * is really needed for all HE commands
     */
    case IEEE80211_PARAM_HE_EXTENDED_RANGE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_EXTENDED_RANGE, value);
        if (retv == 0)
            retv = ENETRESET;
    break;
    case IEEE80211_PARAM_HE_DCM:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_DCM, value);
        if (retv == 0) {
            retv = ENETRESET;
        }
    break;
    case IEEE80211_PARAM_HE_FRAGMENTATION:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_FRAGMENTATION, value);
        if (retv == 0) {
            retv = ENETRESET;
        }
    break;
    case IEEE80211_PARAM_HE_MU_EDCA:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_MU_EDCA, value);
        if(retv == 0) {
            retv = ENETRESET;
        }
    break;
    case IEEE80211_PARAM_HE_DYNAMIC_MU_EDCA:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_DYNAMIC_MU_EDCA, value);
    break;
    case IEEE80211_PARAM_HE_SU_BFEE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_SU_BFEE, value);
        if (retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_HE_SU_BFER:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_SU_BFER, value);
        if ( retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_HE_MU_BFEE:
        if(vap->iv_opmode == IEEE80211_M_STA) {
            retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_MU_BFEE, value);
            if ( retv == EOK && (vap->iv_novap_reset == 0)) {
                retv = ENETRESET;
                restart_vap = true;
            }
        } else {
            qdf_print("HE MU BFEE only supported in STA mode ");
            return -EINVAL;
        }
        break;

    case IEEE80211_PARAM_HE_MU_BFER:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_MU_BFER, value);
            if ( retv == EOK && (vap->iv_novap_reset == 0)) {
                retv = ENETRESET;
                restart_vap = true;
            }
        } else {
            qdf_print("HE MU BFER only supported in AP mode ");
            return -EINVAL;
        }
        break;

    case IEEE80211_PARAM_HE_DL_MU_OFDMA:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_DL_MU_OFDMA, value);
        if ( retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_HE_DL_MU_OFDMA_BFER:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_DL_MU_OFDMA_BFER, value);
        if ( retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_HE_UL_MU_OFDMA:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_MU_OFDMA, value);
        if (retv == EOK) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_HE_UL_MU_MIMO:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_UL_MU_MIMO, value);
        if ( retv == EOK && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
            restart_vap = true;
        }
    break;

    case IEEE80211_PARAM_6G_HE_OP_MIN_RATE:
        ic->ic_is_heop_param_updated = true;
        retv = wlan_set_param(vap, IEEE80211_CONFIG_6G_HE_OP_MIN_RATE, value);
        ic->ic_is_heop_param_updated = false;
    break;

    case IEEE80211_PARAM_EXT_NSS_SUPPORT:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_EXT_NSS_SUPPORT, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;
#if QCN_IE
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_ENABLE:
        /* Enable broadcast probe response feature only if its in HOSTAP mode
         * and hidden SSID is not enabled for this vap.
         */
        if (vap->iv_opmode == IEEE80211_M_HOSTAP && !IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
            if (!!value != vap->iv_bpr_enable) {
                vap->iv_bpr_enable = !!value;
                wlan_set_param(vap, IEEE80211_CONFIG_BCAST_PROBE_RESPONSE, vap->iv_bpr_enable);
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "Set the bpr_enable to %d\n", vap->iv_bpr_enable);
            }
        } else {
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                     "Invalid. Allowed only in HOSTAP mode & non-hidden SSID mode\n");
        }
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_DELAY:
        if (value < 1 || value > 255) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "Invalid value! Broadcast response delay should be between 1 and 255 \n");
            return -EINVAL;
        }
        vap->iv_bpr_delay = value;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_LATENCY_COMPENSATION:
        if (value < 1 || value > 10) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Invalid value!"
                "Broadcast response latency compensation should be between 1 and 10 \n");
            return -EINVAL;
        }
        ic->ic_bpr_latency_comp = value;
        break;
    case IEEE80211_PARAM_BEACON_LATENCY_COMPENSATION:
        if (value < 1 || value > 10) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Invalid value!"
                "Beacon latency compensation should be between 1 and 10 \n");
            return -EINVAL;
        }
        ic->ic_bcn_latency_comp = value;
        break;
#endif
#if ATH_ACL_SOFTBLOCKING
    case IEEE80211_PARAM_SOFTBLOCK_WAIT_TIME:
        if (value >= SOFTBLOCK_WAIT_TIME_MIN && value <= SOFTBLOCK_WAIT_TIME_MAX) {
            vap->iv_softblock_wait_time = value;
        }
        else {
            qdf_print("Allowed value between (%d, %d)",SOFTBLOCK_WAIT_TIME_MIN, SOFTBLOCK_WAIT_TIME_MAX);
            retv = -EINVAL;
        }
        break;

    case IEEE80211_PARAM_SOFTBLOCK_ALLOW_TIME:
        if (value >= SOFTBLOCK_ALLOW_TIME_MIN && value <= SOFTBLOCK_ALLOW_TIME_MAX) {
            vap->iv_softblock_allow_time = value;
        }
        else {
            qdf_print("Allowed value between (%d, %d)", SOFTBLOCK_ALLOW_TIME_MIN, SOFTBLOCK_ALLOW_TIME_MAX);
            retv = -EINVAL;
        }
        break;
#endif

    case IEEE80211_PARAM_QOS_ACTION_FRAME_CONFIG:
        ic->ic_qos_acfrm_config = value;
        break;

    case IEEE80211_PARAM_HE_LTF:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_LTF, value);
        /* if the novap reset is set for debugging
         * purpose we are not resetting the VAP
         */
        if ((retv == 0) && (vap->iv_novap_reset == 0)) {
            retv = ENETRESET;
        }
        break;

    case IEEE80211_PARAM_HE_AR_GI_LTF:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_AR_GI_LTF, value);
        break;

    case IEEE80211_PARAM_HE_AR_LDPC:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_AR_LDPC, value);
        break;

    case IEEE80211_PARAM_HE_RTSTHRSHLD:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_RTSTHRSHLD, value);
        if (retv == 0) {
            retv = ENETRESET;
            restart_vap = true;
        }
        break;

    case IEEE80211_PARAM_DFS_INFO_NOTIFY_APP:
        ic->ic_dfs_info_notify_channel_available = value;
        break;
    case IEEE80211_PARAM_RSN_OVERRIDE:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_RSN_OVERRIDE, value);
        break;
    case IEEE80211_PARAM_MAP:
        retv = son_vdev_map_capability_set(vap->vdev_obj, SON_MAP_CAPABILITY, value);
        break;
    case IEEE80211_PARAM_MAP_BSS_TYPE:
        retv = son_vdev_map_capability_set(vap->vdev_obj, SON_MAP_CAPABILITY_VAP_TYPE, value);
        break;
    case IEEE80211_PARAM_MAP2_BSTA_VLAN_ID:
        retv = son_vdev_map_capability_set(vap->vdev_obj, SON_MAP_CAPABILITY_BSTA_VLAN_ID, value);
        break;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    case IEEE80211_PARAM_NSSOL_VAP_INSPECT_MODE:
        if (osifp->nss_wifiol_ctx && ic->nss_vops) {
            ic->nss_vops->ic_osif_nss_vdev_set_inspection_mode(osifp, (uint32_t)value);
        }
        break;
#endif

    case IEEE80211_PARAM_DISABLE_CABQ :
        retv = wlan_set_param(vap, IEEE80211_FEATURE_DISABLE_CABQ, value);
        break;

    case IEEE80211_PARAM_CSL_SUPPORT:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_CSL_SUPPORT, value);
        break;

    case IEEE80211_PARAM_TIMEOUTIE:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_TIMEOUTIE, value);
        break;

    case IEEE80211_PARAM_PMF_ASSOC:
        retv = wlan_set_param(vap, IEEE80211_SUPPORT_PMF_ASSOC, value);
        break;

    case IEEE80211_PARAM_BEST_UL_HYST:
        ucfg_son_set_bestul_hyst(vap->vdev_obj, value);
        break;

    case IEEE80211_PARAM_HE_TX_MCSMAP:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_TX_MCSMAP, value);
        if (retv == 0)
            retv = ENETRESET;
        break;

    case IEEE80211_PARAM_HE_RX_MCSMAP:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_RX_MCSMAP, value);
        if (retv == 0)
            retv = ENETRESET;
        break;

    case IEEE80211_PARAM_CONFIG_M_COPY:
        wlan_set_param(vap, IEEE80211_CONFIG_M_COPY, value);

    case IEEE80211_PARAM_NSSOL_VAP_READ_RXPREHDR:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_READ_RXPREHDR, value);
        break;

    case IEEE80211_PARAM_CONFIG_CAPTURE_LATENCY_ENABLE:
        wlan_set_param(vap, IEEE80211_CONFIG_CAPTURE_LATENCY_ENABLE, value);
        break;

    case IEEE80211_PARAM_BA_BUFFER_SIZE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_BA_BUFFER_SIZE, value);
        break;

    case IEEE80211_PARAM_HE_SOUNDING_MODE:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_SOUNDING_MODE, value);
        break;

    case IEEE80211_PARAM_HE_HT_CTRL:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_HT_CTRL, value);
        if (retv == 0) {
            retv = ENETRESET;
        }
        break;
    case IEEE80211_PARAM_WIFI_DOWN_IND:
         retv = wlan_set_param(vap, IEEE80211_CONFIG_WIFI_DOWN_IND, value);
         break;

    case IEEE80211_PARAM_LOG_ENABLE_BSTEERING_RSSI:
        if(value == 0 || value == 1)
        {
            son_record_inst_rssi_log_enable(vap->vdev_obj, value);
        }
        else
            qdf_err("Incorrect value for bsteerrssi_log \n");
        break;

    case IEEE80211_PARAM_FT_ENABLE:
        if (!ic->ic_cfg80211_config) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "FT supported only with cfg80211\n");
            return -EINVAL;
        }

        if(vap->iv_opmode == IEEE80211_M_STA) {
            if (value > 1  ||  value < 0) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                    "Invalid value! value should be either 0 or 1\n");
                return -EINVAL;
            }
            retv = wlan_set_param(vap, IEEE80211_CONFIG_FT_ENABLE, value);
            if (retv == 0) {
                retv = ENETRESET;
            }
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "Valid only in STA mode\n");
            return -EINVAL;
        }
        break;
#if WLAN_SER_DEBUG
    case IEEE80211_PARAM_WLAN_SER_HISTORY:
        wlan_ser_print_history(vap->vdev_obj, value, val[2]);
        break;
#endif
    case IEEE80211_PARAM_WLAN_PRINT_RL:
        qdf_rl_print_count_set(value);
        qdf_rl_print_time_set(val[2]);
    case IEEE80211_PARAM_WLAN_SCHED_TIMEOUT:
        if (value < (10 * 1000)) {
           qdf_info("Please enter a scheduler timeout of more than 10 seconds");
        } else {
            scheduler_set_watchdog_timeout(value);
        }
        break;
    case IEEE80211_PARAM_BCN_STATS_RESET:
        if(vap->reset_bcn_stats)
            vap->reset_bcn_stats(vap);
        break;
#if WLAN_SER_UTF
    case IEEE80211_PARAM_WLAN_SER_TEST:
        wlan_ser_utf_main(vap->vdev_obj, value, val[2]);
        break;
#endif
#if QCA_SUPPORT_SON
     case IEEE80211_PARAM_SON_EVENT_BCAST:
         son_core_enable_disable_vdev_bcast_events(vap->vdev_obj, !!value);
         break;
     case IEEE80211_PARAM_WHC_BACKHAUL_TYPE:
         if(!son_set_backhaul_type_mixedbh(vap->vdev_obj, value)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
               "Error, in setting backhaul type and sonmode");
         } else {
             son_update_bss_ie(vap->vdev_obj);
             son_pdev_appie_update(ic);
             wlan_pdev_beacon_update(ic);
         }
         break;
     case IEEE80211_PARAM_WHC_MIXEDBH_ULRATE:
         if(!son_set_ul_mixedbh(vap->vdev_obj, value)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "Error, in setting uplink rate");
         }
         break;
#endif
    case IEEE80211_PARAM_RAWMODE_OPEN_WAR:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_RAWMODE_OPEN_WAR, !!value);
        break;
#if UMAC_SUPPORT_WPA3_STA
    case IEEE80211_PARAM_EXTERNAL_AUTH_STATUS:
        qdf_timer_sync_cancel(&vap->iv_sta_external_auth_timer);
        vap->iv_mlme_priv->im_request_type = 0;
        osifp->app_filter &= ~(IEEE80211_FILTER_TYPE_AUTH);
        IEEE80211_DELIVER_EVENT_MLME_AUTH_COMPLETE(vap, NULL, value);
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "external auth status %d",value);
        break;
    case IEEE80211_PARAM_SAE_AUTH_ATTEMPTS:
        vap->iv_sae_max_auth_attempts = !!value;
        retv = 0;
        break;
#endif
    case IEEE80211_PARAM_DPP_VAP_MODE:
        vap->iv_dpp_vap_mode = !!value;
        retv = 0;
        break;
    case IEEE80211_PARAM_HE_BSR_SUPPORT:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_BSR_SUPPORT, value);
        if((retv == 0) && (vap->iv_novap_reset == 0)){
            retv = ENETRESET;
        }
    break;
    case IEEE80211_PARAM_MAP_VAP_BEACONING:
        retv = son_vdev_map_capability_set(vap->vdev_obj,
                            SON_MAP_CAPABILITY_VAP_UP, value);
        break;
    case IEEE80211_PARAM_UNIFORM_RSSI:
        ic->ic_uniform_rssi = !!value;
        retv = 0;
        break;
    case IEEE80211_PARAM_CSA_INTEROP_PHY:
        vap->iv_csa_interop_phy = !!value;
        retv = 0;
        break;
    case IEEE80211_PARAM_CSA_INTEROP_BSS:
        vap->iv_csa_interop_bss = !!value;
        retv = 0;
        break;
    case IEEE80211_PARAM_CSA_INTEROP_AUTH:
        vap->iv_csa_interop_auth = !!value;
        retv = 0;
        break;
    case IEEE80211_PARAM_DEC_BCN_LOSS:
        vap->iv_dec_bcn_loss = !!value;
        retv = 0;
        break;
    case IEEE80211_PARAM_ENABLE_MULTI_GROUP_KEY:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ENABLE_MULTI_GROUP_KEY, value);
        retv = 0;
        break;
    case IEEE80211_PARAM_MAX_GROUP_KEYS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_MAX_GROUP_KEYS, value);
        retv = 0;
        break;
    case IEEE80211_PARAM_MAX_MTU_SIZE:
       if (value > IEEE80211_MTU_MIN && value < IEEE80211_MTU_MAX) {
           retv = wlan_set_param(vap, IEEE80211_CONFIG_MAX_MTU_SIZE, value);
       } else {
           qdf_err("Invalid value for MTU size: %d", value);
           retv = -EINVAL;
       }

       if(retv == 0)
           retv = ENETRESET;
       break;
    case IEEE80211_PARAM_HE_6GHZ_BCAST_PROB_RSP:
        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            qdf_err("Bcast Probe resp setting is valid only for Tx vap");
            return -EINVAL;
        }
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            prb_rsp_en_period = ieee80211_get_prbrsp_en_period(val[1], val[2]);
            retv = wlan_set_param(vap, IEEE80211_CONFIG_6GHZ_BCAST_PROB_RSP, prb_rsp_en_period);
        } else {
            qdf_err("20TU Bcast Probe response only supported in AP mode ");
            return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_VHT_MCS_12_13_SUPP:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_HE_MCS_12_13_SUPP, value);
        break;
    case IEEE80211_PARAM_SET_STATS_UPDATE_PERIOD:
        retv = wlan_set_param(vap, IEEE80211_STATS_UPDATE_PERIOD, value);
        break;
    case IEEE80211_PARAM_SEND_PROBE_REQ:
        ieee80211_ucfg_send_probereq(vap, value);
        break;
    case IEEE80211_PARAM_ENABLE_MSCS:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_ENABLE_MSCS, value);
        break;
    case IEEE80211_PARAM_OCE_VERSION_OVERRIDE:
        retv = wlan_set_param(vap, IEEE80211_OCE_VERSION_OVERRIDE, value);
        break;
    case IEEE80211_PARAM_6G_SECURITY_COMP:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_6G_SECURITY_COMP, value);
        break;
    case IEEE80211_PARAM_6G_KEYMGMT_MASK:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_6G_KEYMGMT_MASK, value);
        break;
    case IEEE80211_PARAM_MBSS_TXVDEV:
        if (!is_mbssid_enabled) {
            if (ic->ic_wideband_capable) {
                /*
                 * If MBSSID is disabled for wideband radio, set a target
                 * Tx VAP and use it if the wideband radio successfully
                 * enables MBSSID/EMA mode of operation
                 */
                if (value) {
                    qdf_err("Setting Tx-VAP for later EMA use");
                    ic->ic_mbss.target_transmit_vap = vap;
                } else {
                    ic->ic_mbss.target_transmit_vap = NULL;
                }
            } else {
                qdf_err("MBSSID is not enabled");
                return -EINVAL;
            }
        } else {
#if MESH_MODE_SUPPORT
            if (vap->iv_mesh_vap_mode) {
                qdf_err("Assigning mesh vap as Tx vap is not supported!");
                return -EINVAL;
            }
#endif
#if UMAC_SUPPORT_NAWDS
            if (vap->iv_nawds.mode != IEEE80211_NAWDS_DISABLED) {
                qdf_err("Assigning nawds vap as Tx vap is not supported!");
                return -EINVAL;
            }
#endif
            if (value)
               ieee80211_ucfg_set_txvap(vap);
            else
               ieee80211_ucfg_reset_txvap(vap, 0);
        }
        break;
    case IEEE80211_PARAM_HLOS_TID_OVERRIDE:
         retv = ieee80211_ucfg_set_hlos_tid_override(osifp, value, false);
         break;
    case IEEE80211_PARAM_HE_ER_SU_DISABLE:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_ER_SU_DISABLE, value);
        break;
    case IEEE80211_PARAM_HE_1024QAM_LT242RU_RX_ENABLE:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_1024QAM_LT242RU_RX_ENABLE, value);
        break;
    case IEEE80211_PARAM_HE_UL_MU_DATA_DIS_RX_SUPP:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_UL_MU_DATA_DIS_RX_SUPP, value);
        break;
    case IEEE80211_PARAM_HE_FULL_BW_UL_MUMIMO:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_FULL_BW_UL_MUMIMO, value);
        break;
    case IEEE80211_PARAM_HE_DCM_MAX_CONSTELLATION_RX:
        if (!ieee80211vap_ishemode(vap)) {
            qdf_err("Invalid setting for current mode");
            return -EINVAL;
        }
        retv = wlan_set_param(vap,
            IEEE80211_CONFIG_HE_DCM_MAX_CONSTELLATION_RX, value);
        break;
#if WLAN_OBJMGR_REF_ID_TRACE
    case IEEE80211_PARAM_VDEV_REF_LEAK_TEST:
        vap->iv_ref_leak_test_flag = !!value;
        break;
#endif  /* WLAN_OBJMGR_REF_ID_TRACE */
    case IEEE80211_PARAM_DISABLE_INACT_PROBING:
        retv = wlan_set_param(vap, IEEE80211_CONFIG_DISABLE_INACT_PROBING, value);
        break;
    case IEEE80211_PARAM_RTS:
        if (IEEE80211_RTS_MIN <= value && value <= IEEE80211_RTS_MAX) {
            int curval = wlan_get_param(vap, IEEE80211_RTS_THRESHOLD);

            if (value != curval) {
                retv = wlan_set_param(vap, IEEE80211_RTS_THRESHOLD, value);
                if (retv == 0) {
                    retv = ENETRESET;
                    restart_vap = true;
                }
            }
        } else {
            qdf_err("Invalid args!!");
            retv = -EINVAL;
        }
        break;
    case IEEE80211_PARAM_SM_GAP_PS_ENABLE:
        if (vap->iv_sm_gap_ps == value) {
            qdf_warn("Value already set to %d\n", value);
            break;
        }
        /* Allow the smps feature only for either RootAP or Repeater STA */
        if ((ic_is_sta_vap(ic) && (vap->iv_opmode == IEEE80211_M_HOSTAP)) ||
            (!(vap->iv_opmode == IEEE80211_M_STA) &&
            !(vap->iv_opmode == IEEE80211_M_HOSTAP))) {
            qdf_err("Invalid setting for current mode");
            break;
        }
        vap->iv_sm_gap_ps = !!value;
        vap->iv_static_mimo_ps = vap->iv_sm_gap_ps;
        if (ic_is_sta_vap(ic) && !vap->iv_sm_gap_ps)
            wlan_green_ap_stop(pdev);
        if (vap->iv_pwrsave_smps)
            ieee80211_pwrsave_smps_set_timer(vap->iv_pwrsave_smps);
        retv = 0;
        break;
    case IEEE80211_PARAM_VAP_MESH_TID_CONFIG:
         retv = ieee80211_ucfg_set_vap_mesh_tid(osifp, val[1]);
        break;
    case IEEE80211_PARAM_VAP_MESH_LATENCY_CONFIG:
         service_interval = val[1];
         burst_size = val[2];
         /*
          * Check if per peer latency tid config is enabled
          */
         if (!ieee80211_ucfg_get_peer_tid_latency_enable(osifp)) {
             ieee80211_ucfg_get_vap_mesh_tid(osifp, &latency_tid, &dl_ul_latency_enable);
             retv = ic->ic_vap_config_tid_latency_param(vap,
                    service_interval, burst_size, latency_tid, dl_ul_latency_enable);
             if (retv == EOK) {
                 retv = ENETRESET;
                 restart_vap = true;
             }
         }
         break;
    case IEEE80211_PARAM_PEER_TID_LATENCY_ENABLE:
         retv = ieee80211_ucfg_set_peer_tid_latency_enable(osifp, value);
         break;
    case IEEE80211_PARAM_AP_MAX_AUTH_FAIL:
         retv = wlan_set_param(vap, IEEE80211_CONFIG_AP_MAX_AUTH_FAIL, value);
         break;
    case IEEE80211_PARAM_VAP_PROFILE_CONFIG:
        retv = ieee80211_update_vap_resource_profile(vap, value, val[2]);
        break;
    break;
    }

    osif_vap_activity_update(vap);
    config_cmd_resp_log(scn->soc, CONFIG_TYPE_RESP, vap->iv_netdev_name, param, retv);
    /*
     * ic_is_vdev_restart_sup indicates vdev restart is supported by this
     * radio and retv set to ENETRESET indicates this config requires a vdev
     * restart.
     * restart_vap indicates that vdev restart optimization for config changes
     * is supported by FW.
     */
    if (retv == ENETRESET && IS_UP(dev)) {
        if (ic->ic_is_vdev_restart_sup &&
                (vap->iv_opmode == IEEE80211_M_HOSTAP) && restart_vap)
            retv = osif_vdev_restart(vap);
        else
            retv = osif_vap_init(dev, RESCAN);
    } else {
        retv = 0;
    }

    return retv;
}

static char num_to_char(u_int8_t n)
{
    if ( n >= 10 && n <= 15 )
        return n  - 10 + 'A';
    if ( n >= 0 && n <= 9 )
        return n  + '0';
    return ' '; //Blank space
}

/* convert MAC address in array format to string format
 * inputs:
 *     addr - mac address array
 * output:
 *     macstr - MAC address string format */
static void macaddr_num_to_str(u_int8_t *addr, char *macstr)
{
    int i, j=0;

    for ( i = 0; i < QDF_MAC_ADDR_SIZE; i++ ) {
        macstr[j++] = num_to_char(addr[i] >> 4);
        macstr[j++] = num_to_char(addr[i] & 0xF);
    }
}

int ieee80211_ucfg_getparam(wlan_if_t vap, int param, int *value)
{
    osif_dev  *osifp = (osif_dev *)wlan_vap_get_registered_handle(vap);
    wlan_dev_t ic = wlan_vap_get_devhandle(vap);
    struct wlan_objmgr_psoc *psoc;
    char *extra = (char *)value;
    int retv = 0;
    int *txpow_frm_subtype = value;
    u_int8_t frame_subtype;
    u_int8_t frame_type;
#if ATH_SUPPORT_DFS
    int tmp;
#endif
    struct wlan_objmgr_pdev *pdev;
#if WLAN_SUPPORT_SPLITMAC || defined(ATH_EXT_AP)
    struct wlan_objmgr_vdev *vdev = vap->vdev_obj;
#endif
    struct ieee80211_quality iq;
    bool is_mbssid_enabled;
    cdp_config_param_type val = {0};
#if SM_ENG_HIST_ENABLE
    cm_ext_t *cm_ext_handle = NULL;
#endif
    if (!osifp || osifp->is_delete_in_progress)
        return -EINVAL;

    pdev = ic->ic_pdev_obj;
    if(pdev == NULL) {
        qdf_print("%s : pdev is null", __func__);
        return -1;
    }

    psoc = wlan_pdev_get_psoc(vap->iv_ic->ic_pdev_obj);
    if (psoc == NULL) {
             qdf_print("psoc is null");
             return -1;
    }

    is_mbssid_enabled= wlan_pdev_nif_feat_cap_get(pdev,
                                                  WLAN_PDEV_F_MBSS_IE_ENABLE);
    switch (param)
    {
    case IEEE80211_PARAM_MAXSTA:
        *value = is_mbssid_enabled ?
                 (vap->iv_mbss_max_aid - 1 - (1 << ic->ic_mbss.max_bssid)) :
                 (vap->iv_max_aid - 1);
        qdf_info("Getting Max Stations: %d", *value);
        break;
    case IEEE80211_PARAM_AUTO_ASSOC:
        *value = wlan_get_param(vap, IEEE80211_AUTO_ASSOC);
        break;
    case IEEE80211_PARAM_VAP_COUNTRY_IE:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_COUNTRY_IE);
        break;
    case IEEE80211_PARAM_VAP_DOTH:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_DOTH);
        break;
    case IEEE80211_PARAM_HT40_INTOLERANT:
        *value = wlan_get_param(vap, IEEE80211_HT40_INTOLERANT);
        break;

    case IEEE80211_PARAM_CHWIDTH:
        *value = wlan_get_param(vap, IEEE80211_CHWIDTH);
        break;

    case IEEE80211_PARAM_CHEXTOFFSET:
        *value = wlan_get_param(vap, IEEE80211_CHEXTOFFSET);
        break;
#ifdef ATH_SUPPORT_QUICK_KICKOUT
    case IEEE80211_PARAM_STA_QUICKKICKOUT:
        *value = wlan_get_param(vap, IEEE80211_STA_QUICKKICKOUT);
        break;
#endif
    case IEEE80211_PARAM_CHSCANINIT:
        *value = wlan_get_param(vap, IEEE80211_CHSCANINIT);
        break;

    case IEEE80211_PARAM_COEXT_DISABLE:
        *value = ((ic->ic_flags & IEEE80211_F_COEXT_DISABLE) != 0);
        break;

    case IEEE80211_PARAM_NR_SHARE_RADIO_FLAG:
        *value = ic->ic_nr_share_radio_flag;
        break;

    case IEEE80211_PARAM_AUTHMODE:
        //fixme how it used to be done: *value = osifp->authmode;
        {
            int32_t authmode;
            authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
            if ( authmode == -1 ) {
                qdf_err("crypto_err while getting authmode params\n");
                retv = -1;
                break;
            }
            *value = 0;
            if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_WPA) | (1 << WLAN_CRYPTO_AUTH_RSNA)))
                *value = WLAN_CRYPTO_AUTH_WPA;
            else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_OPEN) | (1 << WLAN_CRYPTO_AUTH_SHARED)))
               *value = WLAN_CRYPTO_AUTH_AUTO;
            else {
                if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_OPEN)))
                   *value = WLAN_CRYPTO_AUTH_OPEN;
                else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_AUTO)))
                   *value = WLAN_CRYPTO_AUTH_AUTO;
                else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_NONE)))
                   *value = WLAN_CRYPTO_AUTH_NONE;
                else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_SHARED)))
                   *value = WLAN_CRYPTO_AUTH_SHARED;
                else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_WPA)))
                   *value = WLAN_CRYPTO_AUTH_WPA;
                else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_RSNA)))
                   *value = WLAN_CRYPTO_AUTH_RSNA;
                else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_8021X)))
                   *value = WLAN_CRYPTO_AUTH_8021X;
                else if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_CCKM)))
                   *value = WLAN_CRYPTO_AUTH_CCKM;
                else if (authmode & (uint32_t)(1 << WLAN_CRYPTO_AUTH_SAE))
                   *value = WLAN_CRYPTO_AUTH_SAE;
            }
        }
        break;
     case IEEE80211_PARAM_BANDWIDTH:
         {
           *value=ieee80211_ucfg_get_bandwidth(vap);
           break;
         }
     case IEEE80211_PARAM_FREQ_BAND:
         {
           *value=ieee80211_ucfg_get_band(vap);
           break;
         }
     case IEEE80211_PARAM_EXTCHAN:
        {
           *value=ieee80211_ucfg_get_extchan(vap);
           break;
        }
     case IEEE80211_PARAM_SECOND_CENTER_FREQ:
        {
            if (ieee80211_is_phymode_8080(vap->iv_des_mode)) {
                *value= vap->iv_bsschan->ic_vhtop_freq_seg2;
            }
            else {
                *value = 0;
                qdf_print(" center freq not present ");
            }
        }
        break;

     case IEEE80211_PARAM_ATH_SUPPORT_VLAN:
        {
            *value = vap->vlan_set_flags;   /* dev->flags to control VLAN tagged packets sent by NW stack */
            break;
        }

     case IEEE80211_DISABLE_BCN_BW_NSS_MAP:
        {
            *value = ic->ic_disable_bcn_bwnss_map;
            break;
        }
     case IEEE80211_DISABLE_STA_BWNSS_ADV:
        {
            *value = ic->ic_disable_bwnss_adv;
            break;
        }
     case IEEE80211_PARAM_MCS:
        {
            *value=-1;  /* auto rate */
            break;
        }
    case IEEE80211_PARAM_MCASTCIPHER:
        {
        int mcastcipher;
        mcastcipher = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_MCAST_CIPHER);
        if ( mcastcipher == -1 ) {
            qdf_err("crypto_err while getting mcastcipher params\n");
            retv = -1;
            break;
        }

            if (mcastcipher & 1<<IEEE80211_CIPHER_WEP)
                *value = IEEE80211_CIPHER_WEP;
            if (mcastcipher & 1<<IEEE80211_CIPHER_TKIP)
                *value = IEEE80211_CIPHER_TKIP;
            if (mcastcipher & 1<<IEEE80211_CIPHER_AES_CCM)
                *value = IEEE80211_CIPHER_AES_CCM;
            if (mcastcipher & 1<<IEEE80211_CIPHER_AES_CCM_256)
                *value = IEEE80211_CIPHER_AES_CCM_256;
            if (mcastcipher & 1<<IEEE80211_CIPHER_AES_GCM)
                *value = IEEE80211_CIPHER_AES_GCM;
            if (mcastcipher & 1<<IEEE80211_CIPHER_AES_GCM_256)
                *value = IEEE80211_CIPHER_AES_GCM_256;
            if (mcastcipher & 1<<IEEE80211_CIPHER_CKIP)
                *value = IEEE80211_CIPHER_CKIP;
#if ATH_SUPPORT_WAPI
            if (mcastcipher & 1<<IEEE80211_CIPHER_WAPI)
                *value = IEEE80211_CIPHER_WAPI;
#endif
            if (mcastcipher & 1<<IEEE80211_CIPHER_NONE)
                *value = IEEE80211_CIPHER_NONE;
        }
        break;
    case IEEE80211_PARAM_MCASTKEYLEN:
        qdf_print("Not supported in crypto convergence");
	*value = 0;
        break;
    case IEEE80211_PARAM_UCASTCIPHERS:
        *value = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_UCAST_CIPHER);
        if ( *value == -1 ) {
            qdf_err("crypto_error getting ucast params\n");
            retv = -1;
        }
        break;
    case IEEE80211_PARAM_UCASTCIPHER:
        *value = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_UCAST_CIPHER);
        if ( *value == -1 ) {
            qdf_err("crypto_error getting ucast params\n");
            retv = -1;
        }
        break;
    case IEEE80211_PARAM_UCASTKEYLEN:
        qdf_print("Not supported in crypto convergence");
	*value = 0;
        break;
    case IEEE80211_PARAM_PRIVACY:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PRIVACY);
        break;
    case IEEE80211_PARAM_COUNTERMEASURES:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_COUNTER_MEASURES);
        break;
    case IEEE80211_PARAM_HIDESSID:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_HIDE_SSID);
        break;
    case IEEE80211_PARAM_APBRIDGE:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_APBRIDGE);
        break;
    case IEEE80211_PARAM_KEYMGTALGS:
        *value = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_KEY_MGMT);
        if ( *value == -1 ) {
            qdf_err("crypto_error getting key_mgmt params\n");
            retv = -1;
        }
        break;
    case IEEE80211_PARAM_RSNCAPS:
        *value = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_RSN_CAP);
        if ( *value == -1 ) {
            qdf_err("crypto_error getting rsn_cap params\n");
            retv = -1;
        }
        break;
    case IEEE80211_PARAM_WPA:
        {
            int32_t authmode;
            authmode = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE);
            if ( authmode == -1 ) {
                qdf_err("crypto_err while getting authmode params\n");
                retv = -1;
                break;
            }

            *value = 0;
            if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_WPA)))
               *value |= 0x1;
            if (authmode & (uint32_t)((1 << WLAN_CRYPTO_AUTH_RSNA)))
               *value |= 0x2;
        }
        break;
#if DBG_LVL_MAC_FILTERING
    case IEEE80211_PARAM_DBG_LVL_MAC:
        *value = vap->iv_print.dbgLVLmac_on;
        break;
#endif

    case IEEE80211_PARAM_DUMP_RA_TABLE:
         dp_show_me_ra_table(wlan_psoc_get_dp_handle(psoc),
			     wlan_vdev_get_id(vap->vdev_obj));
         break;

    case IEEE80211_PARAM_CONFIG_CATEGORY_VERBOSE:
         *value = wlan_show_shared_print_ctrl_category_verbose_table();
         break;

#ifdef QCA_OL_DMS_WAR
    case IEEE80211_PARAM_DMS_AMSDU_WAR:
         *value = vap->dms_amsdu_war;
         break;
#endif

    case IEEE80211_PARAM_DBG_LVL:
        {
            char c[128];
            *value = (u_int32_t)wlan_get_debug_flags(vap);
            snprintf(c, sizeof(c), "0x%x", *value);
            strlcpy(extra, c, sizeof(c));
        }
        break;
    case IEEE80211_PARAM_DBG_LVL_HIGH:
        /* no need to show IEEE80211_MSG_ANY to user */
        *value = (u_int32_t)((wlan_get_debug_flags(vap) & 0x7fffffff00000000ULL) >> 32);
        break;
    case IEEE80211_PARAM_MIXED_MODE:
        *value = vap->mixed_encryption_mode;
        break;
	case IEEE80211_PARAM_WEATHER_RADAR_CHANNEL:
        *value = wlan_get_param(vap, IEEE80211_WEATHER_RADAR);
        break;
    case IEEE80211_PARAM_SEND_DEAUTH:
        *value = wlan_get_param(vap, IEEE80211_SEND_DEAUTH);
        break;
    case IEEE80211_PARAM_WEP_KEYCACHE:
        *value = wlan_get_param(vap, IEEE80211_WEP_KEYCACHE);
	break;
	case IEEE80211_PARAM_GET_ACS:
        *value = wlan_get_param(vap,IEEE80211_GET_ACS_STATE);
    break;
	case IEEE80211_PARAM_GET_CAC:
        *value = wlan_get_param(vap,IEEE80211_GET_CAC_STATE);
	break;
    case IEEE80211_PARAM_SIFS_TRIGGER:
        *value = vap->iv_sifs_trigger_time;
        break;
    case IEEE80211_PARAM_BEACON_INTERVAL:
        *value = wlan_get_param(vap, IEEE80211_BEACON_INTVAL);
        break;
#if ATH_SUPPORT_AP_WDS_COMBO
    case IEEE80211_PARAM_NO_BEACON:
        *value = wlan_get_param(vap, IEEE80211_NO_BEACON);
        break;
#endif
    case IEEE80211_PARAM_PUREG:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PUREG);
        break;
    case IEEE80211_PARAM_PUREN:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PURE11N);
        break;
    case IEEE80211_PARAM_PURE11AC:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PURE11AC);
        break;
    case IEEE80211_PARAM_STRICT_BW:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_STRICT_BW);
        break;
    case IEEE80211_PARAM_WDS:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_WDS);
        break;
    case IEEE80211_PARAM_DA_WAR_ENABLE:
        cdp_txrx_get_vdev_param(wlan_psoc_get_dp_handle(psoc),
                        wlan_vdev_get_id(vap->vdev_obj), CDP_ENABLE_DA_WAR,
                        &val);
        *value = val.cdp_vdev_param_da_war;
        break;
#if WDS_VENDOR_EXTENSION
    case IEEE80211_PARAM_WDS_RX_POLICY:
        *value = wlan_get_param(vap, IEEE80211_WDS_RX_POLICY);
        break;
#endif
#if WLAN_SUPPORT_GREEN_AP
    case IEEE80211_IOCTL_GREEN_AP_PS_ENABLE:
        {
        uint8_t ps_enable;
        ucfg_green_ap_get_ps_config(pdev, &ps_enable);
        *value = ps_enable;
        }
        break;
    case IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT:
        {
        uint32_t trans_time;
        ucfg_green_ap_get_transition_time(pdev, &trans_time);
        *value = trans_time;
        }
        break;
    case IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT:
        *value = ucfg_green_ap_get_debug_prints(pdev);
        break;
#endif
    case IEEE80211_PARAM_WPS:
        *value = wlan_get_param(vap, IEEE80211_WPS_MODE);
        break;
    case IEEE80211_PARAM_EXTAP:
        *value = dp_is_extap_enabled(vdev);
        break;


    case IEEE80211_PARAM_STA_FORWARD:
    *value  = wlan_get_param(vap, IEEE80211_FEATURE_STAFWD);
    break;

    case IEEE80211_PARAM_DYN_BW_RTS:
        *value = wlan_get_param(vap, IEEE80211_DYN_BW_RTS);
        break;

    case IEEE80211_PARAM_CWM_EXTPROTMODE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_EXTPROTMODE);
        break;
    case IEEE80211_PARAM_CWM_EXTPROTSPACING:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_EXTPROTSPACING);
        break;
    case IEEE80211_PARAM_CWM_ENABLE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_ENABLE);
        break;
    case IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD);
        break;
    case IEEE80211_PARAM_DOTH:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_DOTH);
        break;
    case IEEE80211_PARAM_WMM:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_WMM);
        break;
    case IEEE80211_PARAM_PROTMODE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_PROTECTION_MODE);
        break;
    case IEEE80211_PARAM_DRIVER_CAPS:
        *value = wlan_get_param(vap, IEEE80211_DRIVER_CAPS);
        break;
    case IEEE80211_PARAM_MACCMD:
        *value = wlan_get_acl_policy(vap, IEEE80211_ACL_FLAG_ACL_LIST_1);
        break;
    case IEEE80211_PARAM_DROPUNENCRYPTED:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_DROP_UNENC);
    break;
    case IEEE80211_PARAM_DTIM_PERIOD:
        *value = wlan_get_param(vap, IEEE80211_DTIM_INTVAL);
        break;
    case IEEE80211_PARAM_SHORT_GI:
        *value = wlan_get_param(vap, IEEE80211_SHORT_GI);
        break;
   case IEEE80211_PARAM_SHORTPREAMBLE:
        *value = wlan_get_param(vap, IEEE80211_SHORT_PREAMBLE);
        break;
   case IEEE80211_PARAM_CHAN_NOISE:
        *value = vap->iv_ic->ic_get_cur_chan_nf(vap->iv_ic);
        qdf_info("Run-time average NF_dBr = %d", *value);
        break;
   case IEEE80211_PARAM_STA_MAX_CH_CAP:
        *value = vap->iv_sta_max_ch_cap;
        break;
    case IEEE80211_PARAM_OBSS_NB_RU_TOLERANCE_TIME:
        *value = ic->ic_obss_nb_ru_tolerance_time;
        break;
    /*
    * Support to Mcast Enhancement
    */
#if ATH_SUPPORT_IQUE
    case IEEE80211_PARAM_ME:
        *value = wlan_get_param(vap, IEEE80211_ME);
        break;
    case IEEE80211_PARAM_IGMP_ME:
        *value = wlan_get_param(vap, IEEE80211_IGMP_ME);
        break;
    case IEEE80211_PARAM_GETIQUECONFIG:
        *value = wlan_get_param(vap, IEEE80211_IQUE_CONFIG);
        break;
#endif /*ATH_SUPPORT_IQUE*/

    case IEEE80211_PARAM_SCANVALID:
        *value = 0;
        if (vap->iv_opmode == IEEE80211_M_STA) {
                *value = wlan_scan_get_aging_time(psoc);
        }
        break;
    case IEEE80211_PARAM_COUNTRYCODE:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_COUNTRYCODE);
        break;
    case IEEE80211_PARAM_11N_RATE:
        *value = wlan_get_param(vap, IEEE80211_FIXED_RATE);
        qdf_print("Getting Rate Series: %x",*value);
        break;
    case IEEE80211_PARAM_VHT_MCS:
        *value = wlan_get_param(vap, IEEE80211_FIXED_VHT_MCS);
        qdf_print("Getting VHT Rate set: %x",*value);
        break;
    case IEEE80211_PARAM_HE_MCS:
        *value = wlan_get_param(vap, IEEE80211_FIXED_HE_MCS);
        qdf_print("Getting HE MCS Rate set: %x",*value);
        break;
    case IEEE80211_PARAM_HE_MULTI_TID_AGGR:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MULTI_TID_AGGR);
        qdf_info("Getting HE Multi TID Aggr: %d", *value);
        break;
    case IEEE80211_PARAM_HE_MULTI_TID_AGGR_TX:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MULTI_TID_AGGR_TX);
        qdf_info("Getting HE Multi TID Aggr TX: %d", *value);
        break;
    case IEEE80211_PARAM_HE_MAX_AMPDU_LEN_EXP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MAX_AMPDU_LEN_EXP);
        qdf_info("Getting HE Max AMPDU Len Exp: %d", *value);
        break;
    case IEEE80211_PARAM_HE_SU_PPDU_1X_LTF_800NS_GI:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_SU_PPDU_1X_LTF_800NS_GI);
        qdf_info("Getting HE SU PPDU 1x LTF with 800ns GI: %d", *value);
        break;
    case IEEE80211_PARAM_HE_SU_MU_PPDU_4X_LTF_800NS_GI:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_SU_MU_PPDU_4X_LTF_800NS_GI);
        qdf_info("Getting HE SU MU PPDU 4x LTF with 800ns GI: %d", *value);
        break;
    case IEEE80211_PARAM_HE_MAX_FRAG_MSDU:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MAX_FRAG_MSDU);
        qdf_info("Getting HE Max Frag MSDU: %d", *value);
        break;
    case IEEE80211_PARAM_HE_MIN_FRAG_SIZE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MIN_FRAG_SIZE);
        qdf_info("Getting HE Min Frag Size: %d", *value);
        break;
    case IEEE80211_PARAM_HE_OMI:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_OMI);
        qdf_info("Getting HE OMI: %d", *value);
        break;
    case IEEE80211_PARAM_HE_NDP_4X_LTF_3200NS_GI:
        *value = wlan_get_param(vap,
                        IEEE80211_CONFIG_HE_NDP_4X_LTF_3200NS_GI);
        qdf_info("Getting HE NDP 4x HE-LTF with 3200ns GI: %d", *value);
        break;
    case IEEE80211_PARAM_HE_ER_SU_PPDU_1X_LTF_800NS_GI:
        *value = wlan_get_param(vap,
                        IEEE80211_CONFIG_HE_ER_SU_PPDU_1X_LTF_800NS_GI);
        qdf_info("Getting HE ER SU PPDU 1x HE-LTF with 800ns GI: %d", *value);
        break;
    case IEEE80211_PARAM_HE_ER_SU_PPDU_4X_LTF_800NS_GI:
        *value = wlan_get_param(vap,
                        IEEE80211_CONFIG_HE_ER_SU_PPDU_4X_LTF_800NS_GI);
        qdf_info("Getting HE ER SU PPDU 4x HE-LTF with 800ns GI: %d", *value);
        break;
    case IEEE80211_PARAM_NSS:
        *value = wlan_get_param(vap, IEEE80211_FIXED_NSS);
        qdf_print("Getting Nss: %x",*value);
        break;
    case IEEE80211_PARAM_HE_UL_SHORTGI:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_SHORTGI);
        qdf_info("Getting UL Short GI: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_UL_LTF:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_LTF);
        qdf_info("Getting UL HE LTF: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_UL_NSS:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_NSS);
        qdf_info("Getting UL HE NSS: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_UL_PPDU_BW:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_PPDU_BW);
        qdf_info("Getting UL HE PPDU BW: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_UL_LDPC:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_LDPC);
        qdf_info("Getting UL HE LDPC: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_UL_STBC:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_STBC);
        qdf_info("Getting UL HE STBC: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_UL_FIXED_RATE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_FIXED_RATE);
        qdf_info("Getting UL HE MCS: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_AMSDU_IN_AMPDU_SUPRT:
        *value = vap->iv_he_amsdu_in_ampdu_suprt;
        qdf_info("Getting HE AMSDU in AMPDU support: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_SUBFEE_STS_SUPRT:
    {
        char c[128];
        *value       = vap->iv_he_subfee_sts_lteq80;
        *(value + 1) = vap->iv_he_subfee_sts_gt80;

        qdf_info("Getting HE SUBFEE STS support lteq80: %d gt80: %d\n", *value, *(value + 1));

        snprintf(c, sizeof(c), "0x%x 0x%x", *value, *(value + 1));
        strlcpy(extra, c, sizeof(c));
    }
    break;

    case IEEE80211_PARAM_HE_4XLTF_800NS_GI_RX_SUPRT:
        *value = vap->iv_he_4xltf_800ns_gi;
        qdf_info("Getting HE 4xltf+800ns support: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_1XLTF_800NS_GI_RX_SUPRT:
        *value = vap->iv_he_1xltf_800ns_gi;
        qdf_info("Getting HE 1xltf+800ns support: %d\n", *value);
    break;

    case IEEE80211_PARAM_HE_MAX_NC_SUPRT:
        *value = vap->iv_he_max_nc;
        qdf_info("Getting HE max_nc support: %d\n", *value);
    break;

    case IEEE80211_PARAM_TWT_RESPONDER_SUPRT:
        *value = vap->iv_twt_rsp;
        qdf_info("Getting twt responder support: %d\n", *value);
    break;

    case IEEE80211_PARAM_STA_COUNT:
        {
            int sta_count =0;
            if(osifp->os_opmode == IEEE80211_M_STA)
                return -EINVAL;

            sta_count = wlan_iterate_station_list(vap, NULL,NULL);
            *value = sta_count;
            break;
        }
    case IEEE80211_PARAM_NO_VAP_RESET:
        *value = vap->iv_novap_reset;
        qdf_print("Getting VAP reset: %x",*value);
        break;

    case IEEE80211_PARAM_VHT_SGIMASK:
        *value = wlan_get_param(vap, IEEE80211_VHT_SGIMASK);
        qdf_print("Getting VHT SGI MASK: %x",*value);
        break;

    case IEEE80211_PARAM_VHT80_RATEMASK:
        *value = wlan_get_param(vap, IEEE80211_VHT80_RATEMASK);
        qdf_print("Getting VHT80 RATE MASK: %x",*value);
        break;

    case IEEE80211_PARAM_OPMODE_NOTIFY:
        *value = wlan_get_param(vap, IEEE80211_OPMODE_NOTIFY_ENABLE);
        qdf_print("Getting Notify element status: %x",*value);
        break;

    case IEEE80211_PARAM_LDPC:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_LDPC);
        qdf_print("Getting LDPC: %x",*value);
        break;
    case IEEE80211_PARAM_TX_STBC:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_TX_STBC);
        qdf_print("Getting TX STBC: %x",*value);
        break;
    case IEEE80211_PARAM_RX_STBC:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_RX_STBC);
        qdf_print("Getting RX STBC: %x",*value);
        break;
    case IEEE80211_PARAM_VHT_TX_MCSMAP:
        *value = wlan_get_param(vap, IEEE80211_VHT_TX_MCSMAP);
        qdf_print("Getting VHT TX MCS MAP set: %x",*value);
        break;
    case IEEE80211_PARAM_VHT_RX_MCSMAP:
        *value = wlan_get_param(vap, IEEE80211_VHT_RX_MCSMAP);
        qdf_print("Getting VHT RX MCS MAP set: %x",*value);
        break;
    case IEEE80211_PARAM_11N_RETRIES:
        *value = wlan_get_param(vap, IEEE80211_FIXED_RETRIES);
        qdf_print("Getting Retry Series: %x",*value);
        break;
    case IEEE80211_PARAM_MCAST_RATE:
        *value = wlan_get_param(vap, IEEE80211_MCAST_RATE);
        break;
    case IEEE80211_PARAM_BCAST_RATE:
        *value = wlan_get_param(vap, IEEE80211_BCAST_RATE);
        break;
    case IEEE80211_PARAM_CCMPSW_ENCDEC:
        *value = vap->iv_ccmpsw_seldec;
        break;
    case IEEE80211_PARAM_UAPSDINFO:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_UAPSD);
        break;
    case IEEE80211_PARAM_STA_PWR_SET_PSPOLL:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_PSPOLL);
        break;
    case IEEE80211_PARAM_NETWORK_SLEEP:
        *value= (u_int32_t)wlan_get_powersave(vap);
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_SLEEP:
        *value= (u_int32_t)wlan_get_powersave(vap);
        break;
#endif
#if UMAC_SUPPORT_QBSSLOAD
    case IEEE80211_PARAM_QBSS_LOAD:
        *value = wlan_get_param(vap, IEEE80211_QBSS_LOAD);
	break;
#if ATH_SUPPORT_HS20
    case IEEE80211_PARAM_HC_BSSLOAD:
        *value = vap->iv_hc_bssload;
        break;
#endif /* ATH_SUPPORT_HS20 */
#endif /* UMAC_SUPPORT_QBSSLOAD */
#if UMAC_SUPPORT_XBSSLOAD
    case IEEE80211_PARAM_XBSS_LOAD:
        *value = wlan_get_param(vap, IEEE80211_XBSS_LOAD);
        qdf_info("Extended BSS Load: %s\n",*value? "Enabled":"Disabled");
        if (*value) {
            /* VHT IE is not present in 6Ghz mgmt frames. So,
             * rely on HE subfee capable to identify peer as
             * mu mimo capable or not.
             * HE cap does not have seperate cap for he mu bfee.
             * It is mandatory for HE peer to be dl mu mimo capable
             * if subfee is supported.
             */
            qdf_info("HE MU-MIMO capable STA Count: %d",
                         vap->iv_he_su_bformee_sta_assoc);
            qdf_info("VHT MU-MIMO capable STA Count: %d",
                         vap->iv_mu_bformee_sta_assoc);
#ifdef QCA_SUPPORT_CP_STATS
            qdf_info("Spatial Stream Underutilization: %d",
                     pdev_chan_stats_ss_under_util_get(ic->ic_pdev_obj));
            qdf_info("Observable secondary 20MHz Utilization: %d",
                     pdev_chan_stats_sec_20_util_get(ic->ic_pdev_obj));
            qdf_info("Observable secondary 40MHz Utilization: %d",
                     pdev_chan_stats_sec_40_util_get(ic->ic_pdev_obj));
            qdf_info("Observable secondary 80MHz Utilization: %d",
                     pdev_chan_stats_sec_80_util_get(ic->ic_pdev_obj));
#endif
        }
        break;
#endif /* UMAC_SUPPORT_XBSSLOAD */
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    case IEEE80211_PARAM_CHAN_UTIL_ENAB:
        *value = wlan_get_param(vap, IEEE80211_CHAN_UTIL_ENAB);
        break;
    case IEEE80211_PARAM_CHAN_UTIL:
        *value = wlan_get_param(vap, IEEE80211_CHAN_UTIL);
        break;
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
#if UMAC_SUPPORT_QUIET
    case IEEE80211_PARAM_QUIET_PERIOD:
        *value = wlan_quiet_get_param(vap);
        break;
#endif /* UMAC_SUPPORT_QUIET */
    case IEEE80211_PARAM_GET_OPMODE:
        *value = wlan_get_param(vap, IEEE80211_GET_OPMODE);
        break;
    case IEEE80211_PARAM_MBO:
        *value = wlan_get_param(vap, IEEE80211_MBO);
        break;
    case IEEE80211_PARAM_MBO_CAP:
        *value = wlan_get_param(vap, IEEE80211_MBOCAP);
        break;
    case IEEE80211_PARAM_MBO_ASSOC_DISALLOW:
        *value = wlan_get_param(vap,IEEE80211_MBO_ASSOC_DISALLOW);
        break;
    case IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE:
        *value = wlan_get_param(vap,IEEE80211_MBO_CELLULAR_PREFERENCE);
        break;
    case IEEE80211_PARAM_MBO_TRANSITION_REASON:
        *value = wlan_get_param(vap,IEEE80211_MBO_TRANSITION_REASON);
        break;
    case IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY:
        *value = wlan_get_param(vap,IEEE80211_MBO_ASSOC_RETRY_DELAY);
        break;
    case IEEE80211_PARAM_OCE:
        *value = wlan_get_param(vap, IEEE80211_OCE);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_REJECT:
        *value = wlan_get_param(vap, IEEE80211_OCE_ASSOC_REJECT);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI:
        *value = wlan_get_param(vap, IEEE80211_OCE_ASSOC_MIN_RSSI);
        break;
    case IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY:
        *value = wlan_get_param(vap, IEEE80211_OCE_ASSOC_RETRY_DELAY);
        break;
    case IEEE80211_PARAM_ASSOC_MIN_RSSI:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_MIN_RSSI);
        break;
    case IEEE80211_PARAM_OCE_WAN_METRICS:
        *value = wlan_get_param(vap, IEEE80211_OCE_WAN_METRICS);
        break;
    case IEEE80211_PARAM_OCE_HLP:
         *value = wlan_get_param(vap, IEEE80211_OCE_HLP);
         break;
    case IEEE80211_PARAM_NBR_SCAN_PERIOD:
        *value = vap->nbr_scan_period;
        break;
    case IEEE80211_PARAM_RNR:
        *value = vap->rnr_enable;
        break;
    case IEEE80211_PARAM_RNR_FD:
        *value = vap->rnr_enable_fd;
        break;
    case IEEE80211_PARAM_RNR_TBTT:
        *value = vap->rnr_enable_tbtt;
        break;
    case IEEE80211_PARAM_AP_CHAN_RPT:
        *value = vap->ap_chan_rpt_enable;
        break;
    case IEEE80211_PARAM_AP_CHAN_RPT_FILTER:
        *value = vap->ap_chan_rpt_ssid_filter | vap->ap_chan_rpt_opclass_filter;
        break;
    case IEEE80211_PARAM_MGMT_RATE:
        *value = wlan_get_param(vap, IEEE80211_MGMT_RATE);
        break;
    case IEEE80211_PARAM_RTSCTS_RATE:
        *value = wlan_get_param(vap, IEEE80211_NON_BASIC_RTSCTS_RATE);
        break;
    case IEEE80211_PARAM_PRB_RATE:
        *value = wlan_get_param(vap, IEEE80211_PRB_RATE);
        break;
    case IEEE80211_PARAM_PRB_RETRY:
        *value = wlan_get_param(vap, IEEE80211_PRB_RETRY);
        break;
    case IEEE80211_PARAM_RRM_CAP:
        *value = wlan_get_param(vap, IEEE80211_RRM_CAP);
        break;
    case IEEE80211_PARAM_START_ACS_REPORT:
        *value = wlan_get_param(vap, IEEE80211_START_ACS_REPORT);
        break;
    case IEEE80211_PARAM_MIN_DWELL_ACS_REPORT:
        *value = wlan_get_param(vap, IEEE80211_MIN_DWELL_ACS_REPORT);
        break;
    case IEEE80211_PARAM_MAX_SCAN_TIME_ACS_REPORT:
        *value = wlan_get_param(vap, IEEE80211_MAX_SCAN_TIME_ACS_REPORT);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_LONG_DUR);
        break;
    case IEEE80211_PARAM_SCAN_MIN_DWELL:
        *value = wlan_get_param(vap, IEEE80211_SCAN_MIN_DWELL);
        break;
    case IEEE80211_PARAM_SCAN_MAX_DWELL:
        *value = wlan_get_param(vap, IEEE80211_SCAN_MAX_DWELL);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR:
        *value = wlan_get_param(vap, IEEE80211_ACS_CH_HOP_NO_HOP_DUR);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_CNT_WIN_DUR);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_NOISE_TH);
        break;
    case IEEE80211_PARAM_ACS_CH_HOP_CNT_TH:
        *value = wlan_get_param(vap,IEEE80211_ACS_CH_HOP_CNT_TH);
        break;
    case IEEE80211_PARAM_ACS_ENABLE_CH_HOP:
        *value = wlan_get_param(vap,IEEE80211_ACS_ENABLE_CH_HOP);
        break;
    case IEEE80211_PARAM_MAX_DWELL_ACS_REPORT:
        *value = wlan_get_param(vap, IEEE80211_MAX_DWELL_ACS_REPORT);
        break;
    case IEEE80211_PARAM_RRM_DEBUG:
        *value = wlan_get_param(vap, IEEE80211_RRM_DEBUG);
	break;
    case IEEE80211_PARAM_RRM_SLWINDOW:
        *value = wlan_get_param(vap, IEEE80211_RRM_SLWINDOW);
	break;
    case IEEE80211_PARAM_RRM_STATS:
        *value = wlan_get_param(vap, IEEE80211_RRM_STATS);
	break;
    case IEEE80211_PARAM_WNM_STATS:
        *value = wlan_get_param(vap, IEEE80211_WNM_STATS);
	break;
    case IEEE80211_PARAM_RRM_CAP_IE:
        *value = wlan_get_param(vap, IEEE80211_RRM_CAP_IE);
        break;
#if UMAC_SUPPORT_WNM
    case IEEE80211_PARAM_WNM_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_CAP);
	break;
    case IEEE80211_PARAM_WNM_BSS_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_BSS_CAP);
        break;
    case IEEE80211_PARAM_WNM_TFS_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_TFS_CAP);
        break;
    case IEEE80211_PARAM_WNM_TIM_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_TIM_CAP);
        break;
    case IEEE80211_PARAM_WNM_SLEEP_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_SLEEP_CAP);
        break;
    case IEEE80211_PARAM_WNM_FMS_CAP:
        *value = wlan_get_param(vap, IEEE80211_WNM_FMS_CAP);
	break;
#endif
    case IEEE80211_PARAM_FWD_ACTION_FRAMES_TO_APP:
        *value = wlan_get_param(vap, IEEE80211_FWD_ACTION_FRAMES_TO_APP);
        break;
#ifdef ATHEROS_LINUX_PERIODIC_SCAN
    case IEEE80211_PARAM_PERIODIC_SCAN:
        *value = osifp->os_periodic_scan_period;
        break;
#endif
    case IEEE80211_PARAM_VENDOR_FRAME_FWD_MASK:
        *value = osifp->wlan_vendor_fwd_mgmt_mask;
        break;
#if ATH_SW_WOW
    case IEEE80211_PARAM_SW_WOW:
        *value = wlan_get_wow(vap);
        break;
#endif
    case IEEE80211_PARAM_AMPDU:
        ucfg_wlan_vdev_mgr_get_param(vdev, WLAN_MLME_CFG_AMPDU, value);
        break;
    case IEEE80211_PARAM_AMSDU:
        ucfg_wlan_vdev_mgr_get_param(vdev, WLAN_MLME_CFG_AMSDU, value);
        break;

    case IEEE80211_PARAM_RX_AMSDU:
        *value = ic->ic_rx_amsdu;
        break;

    case IEEE80211_PARAM_RATE_DROPDOWN:
        if (osifp->osif_is_mode_offload) {
           *value = vap->iv_ratedrop;
        } else {
           qdf_print("This Feature is Supported on Offload Mode Only");
           return -EINVAL;
        }
        break;
    case IEEE80211_PARAM_11N_TX_AMSDU:
        *value = vap->iv_disable_ht_tx_amsdu;
        break;
    case IEEE80211_PARAM_CTSPROT_DTIM_BCN:
        *value = vap->iv_cts2self_prot_dtim_bcn;
        break;
    case IEEE80211_PARAM_VSP_ENABLE:
        *value = vap->iv_enable_vsp;
        break;
    case IEEE80211_PARAM_MAX_AMPDU:
        *value = wlan_get_param(vap, IEEE80211_MAX_AMPDU);
        break;
    case IEEE80211_PARAM_VHT_MAX_AMPDU:
        *value = wlan_get_param(vap, IEEE80211_VHT_MAX_AMPDU);
        break;
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    case IEEE80211_PARAM_REJOINT_ATTEMP_TIME:
        *value = wlan_get_param(vap,IEEE80211_REJOINT_ATTEMP_TIME);
        break;
#endif
    case IEEE80211_PARAM_PWRTARGET:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_PWRTARGET);
        break;
    case IEEE80211_PARAM_COUNTRY_IE:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_IC_COUNTRY_IE);
        break;

    case IEEE80211_PARAM_2G_CSA:
        *value = wlan_get_device_param(ic, IEEE80211_DEVICE_2G_CSA);
        break;

    case IEEE80211_PARAM_CHANBW:
        switch(ic->ic_chanbwflag)
        {
        case IEEE80211_CHAN_HALF:
            *value = 1;
            break;
        case IEEE80211_CHAN_QUARTER:
            *value = 2;
            break;
        default:
            *value = 0;
            break;
        }
        break;
    case IEEE80211_PARAM_MFP_TEST:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_MFP_TEST);
        break;

    case IEEE80211_PARAM_INACT:
        *value = wlan_get_param(vap,IEEE80211_RUN_INACT_TIMEOUT );
        break;
    case IEEE80211_PARAM_INACT_AUTH:
        *value = wlan_get_param(vap,IEEE80211_AUTH_INACT_TIMEOUT );
        break;
    case IEEE80211_PARAM_INACT_INIT:
        *value = wlan_get_param(vap,IEEE80211_INIT_INACT_TIMEOUT );
        break;
    case IEEE80211_PARAM_SESSION_TIMEOUT:
        *value = wlan_get_param(vap,IEEE80211_SESSION_TIMEOUT );
        break;
    case IEEE80211_PARAM_COMPRESSION:
        *value = wlan_get_param(vap, IEEE80211_COMP);
        break;
    case IEEE80211_PARAM_FF:
        *value = wlan_get_param(vap, IEEE80211_FF);
        break;
    case IEEE80211_PARAM_TURBO:
        *value = wlan_get_param(vap, IEEE80211_TURBO);
        break;
    case IEEE80211_PARAM_BURST:
        *value = wlan_get_param(vap, IEEE80211_BURST);
        break;
    case IEEE80211_PARAM_AR:
        *value = wlan_get_param(vap, IEEE80211_AR);
        break;
#if UMAC_SUPPORT_STA_POWERSAVE
    case IEEE80211_PARAM_SLEEP:
        *value = wlan_get_param(vap, IEEE80211_SLEEP);
        break;
#endif
    case IEEE80211_PARAM_EOSPDROP:
        *value = wlan_get_param(vap, IEEE80211_EOSPDROP);
        break;
    case IEEE80211_PARAM_DFSDOMAIN:
        *value = wlan_get_param(vap, IEEE80211_DFSDOMAIN);
        break;
    case IEEE80211_PARAM_WDS_AUTODETECT:
        *value = wlan_get_param(vap, IEEE80211_WDS_AUTODETECT);
        break;
    case IEEE80211_PARAM_WEP_TKIP_HT:
        *value = wlan_get_param(vap, IEEE80211_WEP_TKIP_HT);
        break;
    /*
    ** Support for returning the radio number
    */
    case IEEE80211_PARAM_ATH_RADIO:
		*value = wlan_get_param(vap, IEEE80211_ATH_RADIO);
        break;
    case IEEE80211_PARAM_IGNORE_11DBEACON:
        *value = wlan_get_param(vap, IEEE80211_IGNORE_11DBEACON);
        break;
#if ATH_SUPPORT_WAPI
    case IEEE80211_PARAM_WAPIREKEY_USK:
        *value = wlan_get_wapirekey_unicast(vap);
        break;
    case IEEE80211_PARAM_WAPIREKEY_MSK:
        *value = wlan_get_wapirekey_multicast(vap);
        break;
#endif

#ifdef QCA_PARTNER_PLATFORM
    case IEEE80211_PARAM_PLTFRM_PRIVATE:
        *value = wlan_pltfrm_get_param(vap);
        break;
#endif
    case IEEE80211_PARAM_NO_STOP_DISASSOC:
        *value = osifp->no_stop_disassoc;
        break;
#if UMAC_SUPPORT_VI_DBG

    case IEEE80211_PARAM_DBG_CFG:
        *value = ieee80211_vi_dbg_get_param(vap, IEEE80211_VI_DBG_CFG);
        break;

    case IEEE80211_PARAM_RESTART:
        *value = ieee80211_vi_dbg_get_param(vap, IEEE80211_VI_RESTART);
        break;
    case IEEE80211_PARAM_RXDROP_STATUS:
        *value = ieee80211_vi_dbg_get_param(vap, IEEE80211_VI_RXDROP_STATUS);
        break;
#endif

#ifdef ATH_SUPPORT_TxBF
    case IEEE80211_PARAM_TXBF_AUTO_CVUPDATE:
        *value = wlan_get_param(vap, IEEE80211_TXBF_AUTO_CVUPDATE);
        break;
    case IEEE80211_PARAM_TXBF_CVUPDATE_PER:
        *value = wlan_get_param(vap, IEEE80211_TXBF_CVUPDATE_PER);
        break;
#endif
    case IEEE80211_PARAM_SCAN_BAND:
        *value = osifp->os_scan_band;
        break;

    case IEEE80211_PARAM_SCAN_CHAN_EVENT:
        if (osifp->osif_is_mode_offload &&
            wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
            *value = osifp->is_scan_chevent;
        } else {
            qdf_print("IEEE80211_PARAM_SCAN_CHAN_EVENT is valid only for 11ac "
                   "offload, and in IEEE80211_M_HOSTAP(Access Point) mode");
            retv = EOPNOTSUPP;
            *value = 0;
        }
        break;
    case IEEE80211_PARAM_ROAMING:
        *value = ic->ic_roaming;
        break;
#if UMAC_SUPPORT_PROXY_ARP
    case IEEE80211_PARAM_PROXYARP_CAP:
        *value = wlan_get_param(vap, IEEE80211_PROXYARP_CAP);
	    break;
#if UMAC_SUPPORT_DGAF_DISABLE
    case IEEE80211_PARAM_DGAF_DISABLE:
        *value = wlan_get_param(vap, IEEE80211_DGAF_DISABLE);
	    break;
#endif
#endif
#if UMAC_SUPPORT_HS20_L2TIF
    case IEEE80211_PARAM_L2TIF_CAP:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_APBRIDGE) ? 0 : 1;
        break;
#endif
    case IEEE80211_PARAM_EXT_ACS_IN_PROGRESS:
        *value = wlan_get_param(vap, IEEE80211_EXT_ACS_IN_PROGRESS);
        break;

    case IEEE80211_PARAM_SEND_ADDITIONAL_IES:
        *value = wlan_get_param(vap, IEEE80211_SEND_ADDITIONAL_IES);
        break;

    case IEEE80211_PARAM_DESIRED_CHANNEL:
        *value = wlan_get_param(vap, IEEE80211_DESIRED_CHANNEL);
        break;

    case IEEE80211_PARAM_DESIRED_PHYMODE:
        *value = wlan_get_param(vap, IEEE80211_DESIRED_PHYMODE);
        break;

    case IEEE80211_PARAM_GET_FREQUENCY:
        *value = ieee80211_ucfg_get_freq(vap);
        break;

    case IEEE80211_PARAM_APONLY:
#if UMAC_SUPPORT_APONLY
        *value = vap->iv_aponly;
#else
        qdf_print("APONLY not enabled");
#endif
        break;

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    case IEEE80211_PARAM_NOPBN:
        *value = wlan_get_param(vap, IEEE80211_NOPBN);
	break;
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
	case IEEE80211_PARAM_DSCP_MAP_ID:
		*value = wlan_get_param(vap, IEEE80211_DSCP_MAP_ID);
	break;
	case IEEE80211_PARAM_DSCP_TID_MAP:
		qdf_print("Get dscp_tid map");
		*value = ieee80211_ucfg_vap_get_dscp_tid_map(vap, value[1]);
	break;
        case IEEE80211_PARAM_VAP_DSCP_PRIORITY:
                *value = wlan_get_param(vap, IEEE80211_VAP_DSCP_PRIORITY);
        break;
#endif
#if ATH_SUPPORT_WRAP
    case IEEE80211_PARAM_PARENT_IFINDEX:
        *value = osifp->os_comdev->ifindex;
        break;

    case IEEE80211_PARAM_PROXY_STA:
#if WLAN_QWRAP_LEGACY
        *value = vap->iv_psta;
#else
        *value = dp_wrap_vdev_is_psta(vap->vdev_obj);
#endif
        break;
#endif
#if RX_CHECKSUM_OFFLOAD
    case IEEE80211_PARAM_RX_CKSUM_ERR_STATS:
	{
	    if(osifp->osif_is_mode_offload) {
                ic->ic_vap_get_param(vap, IEEE80211_RX_CKSUM_ERR_STATS_GET);
	    } else
		qdf_print("RX Checksum Offload Supported only for 11AC VAP ");
	    break;
	}
    case IEEE80211_PARAM_RX_CKSUM_ERR_RESET:
	{
	    if(osifp->osif_is_mode_offload) {
                ic->ic_vap_get_param(vap, IEEE80211_RX_CKSUM_ERR_RESET_GET);
	    } else
		qdf_print("RX Checksum Offload Supported only for 11AC VAP ");
	    break;
	}

#endif /* RX_CHECKSM_OFFLOAD */

#if HOST_SW_TSO_SG_ENABLE
    case IEEE80211_PARAM_TSO_STATS:
	{
	    if(osifp->osif_is_mode_offload) {
		ic->ic_vap_get_param(vap, IEEE80211_TSO_STATS_GET);
	    } else
		qdf_print("TSO Supported only for 11AC VAP ");
	    break;
	}
    case IEEE80211_PARAM_TSO_STATS_RESET:
	{
	    if(osifp->osif_is_mode_offload) {
                ic->ic_vap_get_param(vap, IEEE80211_TSO_STATS_RESET_GET);
	    } else
		qdf_print("TSO Supported only for 11AC VAP ");
	    break;
	}
#endif /* HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
    case IEEE80211_PARAM_SG_STATS:
	{
	    if(osifp->osif_is_mode_offload) {
		ic->ic_vap_get_param(vap, IEEE80211_SG_STATS_GET);
	    } else
		qdf_print("SG Supported only for 11AC VAP ");
	    break;
	}
    case IEEE80211_PARAM_SG_STATS_RESET:
	{
	    if(osifp->osif_is_mode_offload) {
		ic->ic_vap_get_param(vap, IEEE80211_SG_STATS_RESET_GET);
	    } else {
		qdf_print("SG Supported only for 11AC VAP ");
            }
	    break;
	}
#endif /* HOST_SW_SG_ENABLE */

    case IEEE80211_PARAM_MAX_SCANENTRY:
        *value = wlan_get_param(vap, IEEE80211_MAX_SCANENTRY);
        break;
    case IEEE80211_PARAM_SCANENTRY_TIMEOUT:
        *value = wlan_get_param(vap, IEEE80211_SCANENTRY_TIMEOUT);
        break;
#if ATH_PERF_PWR_OFFLOAD
    case IEEE80211_PARAM_VAP_TX_ENCAP_TYPE:
        *value = wlan_get_param(vap, IEEE80211_VAP_TX_ENCAP_TYPE);
        switch (*value)
        {
            case 0:
                qdf_print("Encap type: Raw");
                break;
            case 1:
                qdf_print("Encap type: Native Wi-Fi");
                break;
            case 2:
                qdf_print("Encap type: Ethernet");
                break;
            default:
                qdf_print("Encap type: Unknown");
                break;
        }
        break;
    case IEEE80211_PARAM_VAP_RX_DECAP_TYPE:
        *value = wlan_get_param(vap, IEEE80211_VAP_RX_DECAP_TYPE);
        switch (*value)
        {
            case 0:
                qdf_print("Decap type: Raw");
                break;
            case 1:
                qdf_print("Decap type: Native Wi-Fi");
                break;
            case 2:
                qdf_print("Decap type: Ethernet");
                break;
            default:
                qdf_print("Decap type: Unknown");
                break;
        }
        break;
#if QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    case IEEE80211_PARAM_RAWMODE_SIM_TXAGGR:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_SIM_TXAGGR);
        break;
    case IEEE80211_PARAM_RAWMODE_PKT_SIM_STATS:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_PKT_SIM_STATS);
        break;
    case IEEE80211_PARAM_RAWMODE_SIM_DEBUG_LEVEL:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_SIM_DEBUG_LEVEL);
        break;
    case IEEE80211_PARAM_RAWSIM_DEBUG_NUM_ENCAP_FRAMES:
        *value = wlan_get_param(vap, IEEE80211_RAWSIM_DEBUG_NUM_ENCAP_FRAMES);
        break;
    case IEEE80211_PARAM_RAWSIM_DEBUG_NUM_DECAP_FRAMES:
        *value = wlan_get_param(vap, IEEE80211_RAWSIM_DEBUG_NUM_DECAP_FRAMES);
        break;
#endif /* QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
#endif /* ATH_PERF_PWR_OFFLOAD */
 case IEEE80211_PARAM_VAP_ENHIND:
        *value  = wlan_get_param(vap, IEEE80211_FEATURE_VAP_ENHIND);
        break;
    case IEEE80211_PARAM_VAP_PAUSE_SCAN:
        *value = vap->iv_pause_scan;
        break;
#if ATH_GEN_RANDOMNESS
    case IEEE80211_PARAM_RANDOMGEN_MODE:
        *value = ic->random_gen_mode;
        break;
#endif
    case IEEE80211_PARAM_WHC_APINFO_WDS:
        *value = son_has_whc_apinfo_flag(
                vap->iv_bss->peer_obj, IEEE80211_NODE_WHC_APINFO_WDS);
        break;
    case IEEE80211_PARAM_WHC_APINFO_SON:
        *value = son_has_whc_apinfo_flag(
                vap->iv_bss->peer_obj, IEEE80211_NODE_WHC_APINFO_SON);
        break;
    case IEEE80211_PARAM_WHC_APINFO_ROOT_DIST:
        *value = ucfg_son_get_root_dist(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_WHC_APINFO_SFACTOR:
        *value =  ucfg_son_get_scaling_factor(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_WHC_SKIP_HYST:
        *value =  ucfg_son_get_skip_hyst(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_WHC_APINFO_BSSID:
    {
        char addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};
        ieee80211_ssid  *desired_ssid = NULL;
        int retval;
        struct wlan_ssid ssidname;

        OS_MEMSET(&ssidname, 0, sizeof(struct wlan_ssid));
        retval = ieee80211_get_desired_ssid(vap, 0,&desired_ssid);
        if (desired_ssid == NULL)
            return -EINVAL;

        OS_MEMCPY(&ssidname.ssid,&desired_ssid->ssid, desired_ssid->len);
        ssidname.length = desired_ssid->len;
        ucfg_son_find_best_uplink_bssid(vap->vdev_obj, addr,&ssidname);
        macaddr_num_to_str(addr, extra);
    }
    break;
    case IEEE80211_PARAM_WHC_APINFO_RATE:
        *value = (int)son_ucfg_rep_datarate_estimator(
            son_get_backhaul_rate(vap->vdev_obj, true),
            son_get_backhaul_rate(vap->vdev_obj, false),
            (ucfg_son_get_root_dist(vap->vdev_obj) - 1),
            ucfg_son_get_scaling_factor(vap->vdev_obj));
    break;
    case IEEE80211_PARAM_WHC_APINFO_CAP_BSSID:
    {
        u_int8_t addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

        son_ucfg_find_cap_bssid(vap->vdev_obj, addr);
        macaddr_num_to_str(addr, extra);
    }
    break;
    case IEEE80211_PARAM_WHC_APINFO_BEST_UPLINK_OTHERBAND_BSSID:
    {
	u_int8_t addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

        ucfg_son_get_best_otherband_uplink_bssid(vap->vdev_obj, addr);
        macaddr_num_to_str(addr, extra);
    }
    break;
    case IEEE80211_PARAM_WHC_APINFO_OTHERBAND_UPLINK_BSSID:
    {
        u_int8_t addr[QDF_MAC_ADDR_SIZE] = {0, 0, 0, 0, 0, 0};

	ucfg_son_get_otherband_uplink_bssid(vap->vdev_obj, addr);
	macaddr_num_to_str(addr, extra);
    }
    break;
#if QCA_SUPPORT_SON
    case IEEE80211_PARAM_WHC_APINFO_UPLINK_RATE:
        *value = ucfg_son_get_uplink_rate(vap->vdev_obj);
    break;
    case IEEE80211_PARAM_WHC_APINFO_UPLINK_SNR:
        *value = ucfg_son_get_uplink_snr(vap->vdev_obj);
    break;
#endif
    case IEEE80211_PARAM_WHC_CURRENT_CAP_RSSI:
	    ucfg_son_get_cap_snr(vap->vdev_obj, value);
    break;
    case IEEE80211_PARAM_WHC_CAP_RSSI:
        *value = ucfg_son_get_cap_rssi(vap->vdev_obj);
    break;
    case IEEE80211_PARAM_SON:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_SON);
    break;
    case IEEE80211_PARAM_SON_NUM_VAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_FEATURE_SON_NUM_VAP);
    break;
    case IEEE80211_PARAM_REPT_MULTI_SPECIAL:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_REPT_MULTI_SPECIAL);
    break;
    case IEEE80211_PARAM_RX_SIGNAL_DBM:
         IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"IEEE80211_PARAM_RX_SIGNAL_DBM is valid only for DA not supported for offload \n");
         retv = EOPNOTSUPP;
         *value = 0;
	break;
    default:
        retv = EOPNOTSUPP;
        break;

   case IEEE80211_PARAM_DFS_CACTIMEOUT:
#if ATH_SUPPORT_DFS
        if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_DFS_ID) !=
                QDF_STATUS_SUCCESS) {
            return -1;
        }
        retv = mlme_dfs_get_override_cac_timeout(pdev, &tmp);
        wlan_objmgr_pdev_release_ref(pdev, WLAN_DFS_ID);
        if (retv == 0)
            *value = tmp;
        else
            retv = EOPNOTSUPP;
        break;
#else
        retv = EOPNOTSUPP;
        break;
#endif /* ATH_SUPPORT_DFS */

   case IEEE80211_PARAM_ENABLE_RTSCTS:
       *value = wlan_get_param(vap, IEEE80211_ENABLE_RTSCTS);
       break;

   case IEEE80211_PARAM_RC_NUM_RETRIES:
       *value = wlan_get_param(vap, IEEE80211_RC_NUM_RETRIES);
       break;
   case IEEE80211_PARAM_256QAM_2G:
       *value = wlan_get_param(vap, IEEE80211_256QAM);
       break;
   case IEEE80211_PARAM_11NG_VHT_INTEROP:
       if (osifp->osif_is_mode_offload) {
            *value = wlan_get_param(vap, IEEE80211_11NG_VHT_INTEROP);
       } else {
            qdf_print("Not supported in this Vap");
       }
       break;
#if UMAC_VOW_DEBUG
    case IEEE80211_PARAM_VOW_DBG_ENABLE:
        *value = (int)osifp->vow_dbg_en;
        break;
#endif
#if WLAN_SUPPORT_SPLITMAC
    case IEEE80211_PARAM_SPLITMAC:
        *value = splitmac_get_enabled_flag(vdev);
        break;
#endif
    case IEEE80211_PARAM_IMPLICITBF:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_IMPLICITBF);
        break;

    case IEEE80211_PARAM_VHT_SUBFEE:
        *value = wlan_get_param(vap, IEEE80211_VHT_SUBFEE);
        break;

    case IEEE80211_PARAM_VHT_MUBFEE:
        *value = wlan_get_param(vap, IEEE80211_VHT_MUBFEE);
        break;

    case IEEE80211_PARAM_VHT_SUBFER:
        *value = wlan_get_param(vap, IEEE80211_VHT_SUBFER);
        break;

    case IEEE80211_PARAM_VHT_MUBFER:
        *value = wlan_get_param(vap, IEEE80211_VHT_MUBFER);
        break;

    case IEEE80211_PARAM_VHT_STS_CAP:
        *value = wlan_get_param(vap, IEEE80211_VHT_BF_STS_CAP);
        break;

    case IEEE80211_PARAM_VHT_SOUNDING_DIM:
        *value = wlan_get_param(vap, IEEE80211_VHT_BF_SOUNDING_DIM);
        break;

    case IEEE80211_PARAM_VHT_MCS_10_11_SUPP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_VHT_MCS_10_11_SUPP);
        break;

    case IEEE80211_PARAM_VHT_MCS_10_11_NQ2Q_PEER_SUPP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_VHT_MCS_10_11_NQ2Q_PEER_SUPP);
        break;
    case IEEE80211_PARAM_MCAST_RC_STALE_PERIOD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MCAST_RC_STALE_PERIOD);
        break;
    case IEEE80211_PARAM_ENABLE_MCAST_RC:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ENABLE_MCAST_RC);
        break;

#if QCA_AIRTIME_FAIRNESS
    case IEEE80211_PARAM_ATF_TXBUF_SHARE:
        *value = ucfg_atf_get_txbuf_share(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_ATF_TXBUF_MAX:
        *value = ucfg_atf_get_max_txbufs(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_ATF_TXBUF_MIN:
        *value = ucfg_atf_get_min_txbufs(vap->vdev_obj);
        break;
    case  IEEE80211_PARAM_ATF_OPT:
        *value = ucfg_atf_get(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT:
        *value =  ucfg_atf_get_airtime_tput(vap->vdev_obj);
        break;
    case  IEEE80211_PARAM_ATF_PER_UNIT:
        *value = ucfg_atf_get_per_unit(ic->ic_pdev_obj);
        break;
    case  IEEE80211_PARAM_ATF_MAX_CLIENT:
        {
            int val = ucfg_atf_get_maxclient(ic->ic_pdev_obj);
            if (val < 0)
                retv = EOPNOTSUPP;
            else
                *value = val;
        }
        break;
    case  IEEE80211_PARAM_ATF_SSID_GROUP:
        *value = ucfg_atf_get_ssidgroup(ic->ic_pdev_obj);
        break;
    case IEEE80211_PARAM_ATF_SSID_SCHED_POLICY:
        *value = ucfg_atf_get_ssid_sched_policy(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_ATF_ENABLE_STATS:
        *value = ucfg_atf_is_stats_enabled(ic->ic_pdev_obj);
        break;
    case IEEE80211_PARAM_ATF_STATS_TIMEOUT:
        *value = ucfg_atf_get_stats_timeout(ic->ic_pdev_obj);
        break;
#endif
#if (QCA_SUPPORT_SSID_STEERING && QCA_SUPPORT_SON)
    case IEEE80211_PARAM_VAP_SSID_CONFIG:
        if ((*value = ucfg_son_get_ssid_steering_config(vap->vdev_obj)) != -EINVAL) {
            qdf_info("This VAP's configuration value is %d ( %d-PRIVATE %d-PUBLIC )",
                    *value, SON_SSID_STEERING_PRIVATE_VDEV, SON_SSID_STEERING_PUBLIC_VDEV);
        }
        else
            return *value;
        break;
#endif

    case IEEE80211_PARAM_TX_MIN_POWER:
        *value = ic->ic_curchan->ic_minpower;
        qdf_print("Get IEEE80211_PARAM_TX_MIN_POWER *value=%d",*value);
        break;
    case IEEE80211_PARAM_TX_MAX_POWER:
        *value = ic->ic_curchan->ic_maxpower;
        qdf_print("Get IEEE80211_PARAM_TX_MAX_POWER *value=%d",*value);
        break;
    case IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE:
        if(ic->ic_mpdudensityoverride & 0x1) {
            *value = ic->ic_mpdudensityoverride >> 1;
        } else {
            *value = -1;
        }
        break;

    case IEEE80211_PARAM_SMART_MESH_CONFIG:
        *value = wlan_get_param(vap, IEEE80211_SMART_MESH_CONFIG);
        break;

#if MESH_MODE_SUPPORT
    case IEEE80211_PARAM_MESH_CAPABILITIES:
        *value = wlan_get_param(vap, IEEE80211_MESH_CAPABILITIES);
        break;

    case IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH:
         *value = wlan_get_param(vap, IEEE80211_CONFIG_MGMT_TX_FOR_MESH);
         break;

    case IEEE80211_PARAM_MESH_MCAST:
         *value = wlan_get_param(vap, IEEE80211_CONFIG_MESH_MCAST);
#endif

    case IEEE80211_PARAM_RX_FILTER_MONITOR:
        if(IEEE80211_M_MONITOR != vap->iv_opmode && !vap->iv_smart_monitor_vap && !vap->iv_special_vap_mode) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not monitor VAP or Smart Monitor VAP!\n");
            return -EINVAL;
        }
        if(osifp->osif_is_mode_offload) {
           *value =  (ic->mon_filter_osif_mac ? MON_FILTER_TYPE_OSIF_MAC : 0)|
                       ic->ic_vap_get_param(vap, IEEE80211_RX_FILTER_MONITOR);
        }
        IEEE80211_DPRINTF_IC(ic, IEEE80211_VERBOSE_NORMAL, IEEE80211_MSG_IOCTL,
                  "osif MAC filter=%d\n", ic->mon_filter_osif_mac);
        break;

    case IEEE80211_PARAM_RX_FILTER_SMART_MONITOR:
        if(vap->iv_smart_monitor_vap) {
            *value = 1;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Smart Monitor VAP!\n");
        } else {
            *value = 0;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not Smart Monitor VAP!\n");
        }
        break;
    case IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_WAR_160W);
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_WAR:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MU_CAP_WAR);
        break;
     case IEEE80211_PARAM_CONFIG_MU_CAP_TIMER:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MU_CAP_TIMER);
        break;
    case IEEE80211_PARAM_RAWMODE_PKT_SIM:
        *value = wlan_get_param(vap, IEEE80211_RAWMODE_PKT_SIM);
        break;
    case IEEE80211_PARAM_CONFIG_RAW_DWEP_IND:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_RAW_DWEP_IND);
        break;
    case IEEE80211_PARAM_CUSTOM_CHAN_LIST:
        *value = wlan_get_param(vap,IEEE80211_CONFIG_PARAM_CUSTOM_CHAN_LIST);
        break;
#if UMAC_SUPPORT_ACFG
    case IEEE80211_PARAM_DIAG_WARN_THRESHOLD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DIAG_WARN_THRESHOLD);
        break;
    case IEEE80211_PARAM_DIAG_ERR_THRESHOLD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DIAG_ERR_THRESHOLD);
        break;
#endif
    case IEEE80211_PARAM_CONFIG_REV_SIG_160W:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_REV_SIG_160W);
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_HTMCS);
        break;
    case IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CONFIGURE_SELECTIVE_VHTMCS);
        break;
    case IEEE80211_PARAM_RDG_ENABLE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_RDG_ENABLE);
        break;
    case IEEE80211_PARAM_DFS_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DFS_SUPPORT);
        break;
    case IEEE80211_PARAM_DFS_ENABLE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DFS_ENABLE);
        break;
    case IEEE80211_PARAM_ACS_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ACS_SUPPORT);
        break;
    case IEEE80211_PARAM_SSID_STATUS:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_SSID_STATUS);
        break;
    case IEEE80211_PARAM_DL_QUEUE_PRIORITY_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DL_QUEUE_PRIORITY_SUPPORT);
        break;
    case IEEE80211_PARAM_CLEAR_MIN_MAX_SNR:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CLEAR_MIN_MAX_SNR);
        break;
    case IEEE80211_PARAM_WATERMARK_THRESHOLD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_WATERMARK_THRESHOLD);
        break;
    case IEEE80211_PARAM_WATERMARK_REACHED:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_WATERMARK_REACHED);
        break;
    case IEEE80211_PARAM_ASSOC_REACHED:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_REACHED);
        break;
    case IEEE80211_PARAM_ENABLE_VENDOR_IE:
	 *value = vap->iv_ena_vendor_ie;
        break;
    case IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ASSOC_DENIAL_NOTIFICATION);
        break;
   case IEEE80211_PARAM_MACCMD_SEC:
        *value = wlan_get_acl_policy(vap, IEEE80211_ACL_FLAG_ACL_LIST_2);
        break;
    case IEEE80211_PARAM_CONFIG_MON_DECODER:
        if (IEEE80211_M_MONITOR != vap->iv_opmode && !vap->iv_smart_monitor_vap) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Not Monitor VAP!\n");
            return -EINVAL;
        }
        /* monitor vap decoder header type: radiotap=0(default) prism=1 */
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MON_DECODER);
        break;
    case IEEE80211_PARAM_BEACON_RATE_FOR_VAP:
        if(vap->iv_opmode == IEEE80211_M_HOSTAP) {
            *value = wlan_get_param(vap, IEEE80211_BEACON_RATE_FOR_VAP);
        }
        break;
    case IEEE80211_PARAM_SIFS_TRIGGER_RATE:
        *value = vap->iv_sifs_trigger_rate;
        break;
    case IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DISABLE_SELECTIVE_LEGACY_RATE);
        break;
    case IEEE80211_PARAM_CONFIG_NSTSCAP_WAR:
        *value = wlan_get_param(vap,IEEE80211_CONFIG_NSTSCAP_WAR);
        break;
    case IEEE80211_PARAM_CHANNEL_SWITCH_MODE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CHANNEL_SWITCH_MODE);
        break;

    case IEEE80211_PARAM_ENABLE_ECSA_IE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ECSA_IE);
        break;

    case IEEE80211_PARAM_SAE_PWID:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_SAE_PWID);
        break;

    case IEEE80211_PARAM_OCE_TX_POWER:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_OCE_TX_POWER);
        break;

    case IEEE80211_PARAM_ECSA_OPCLASS:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ECSA_OPCLASS);
        break;

    case IEEE80211_PARAM_BACKHAUL:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_BACKHAUL);
        break;

#if DYNAMIC_BEACON_SUPPORT
    case IEEE80211_PARAM_DBEACON_EN:
        *value = vap->iv_dbeacon;
        break;

    case IEEE80211_PARAM_DBEACON_SNR_THR:
        *value = vap->iv_dbeacon_snr_thr;
        break;

    case IEEE80211_PARAM_DBEACON_TIMEOUT:
        *value = vap->iv_dbeacon_timeout;
        break;
#endif
#if QCN_IE
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_ENABLE:
        *value = vap->iv_bpr_enable;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_LATENCY_COMPENSATION:
        *value = ic->ic_bpr_latency_comp;
        break;
    case IEEE80211_PARAM_BEACON_LATENCY_COMPENSATION:
        *value = ic->ic_bcn_latency_comp;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_DELAY:
        *value = vap->iv_bpr_delay;
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS:
        *value = 0;
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            QDF_TRACE(QDF_MODULE_ID_IOCTL, QDF_TRACE_LEVEL_FATAL,
                      "------------------------------------\n");
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR feature enabled        - %d  |\n", vap->iv_bpr_enable);

            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR Latency compensation   - %d ms |\n", ic->ic_bpr_latency_comp);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| Beacon Latency compensation- %d ms |\n", ic->ic_bcn_latency_comp);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR delay                  - %d ms |\n", vap->iv_bpr_delay);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| Current Timestamp          - %lld |\n",
                      qdf_ktime_to_ns(qdf_ktime_get()));
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| Next beacon Timestamp      - %lld |\n",
                      qdf_ktime_to_ns(vap->iv_next_beacon_tstamp));
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| Timer expires in           - %lld |\n",
                      qdf_ktime_to_ns(qdf_ktime_add(qdf_ktime_get(),
                      qdf_hrtimer_get_remaining(&vap->bpr_timer))));
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR timer start count      - %u |\n", vap->iv_bpr_timer_start_count);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR unicast probresp count - %u |\n", vap->iv_bpr_unicast_resp_count);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR timer resize count     - %u |\n", vap->iv_bpr_timer_resize_count);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR timer callback count   - %u |\n", vap->iv_bpr_callback_count);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "| BPR timer cancel count     - %u |\n", vap->iv_bpr_timer_cancel_count);
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "------------------------------------\n");
        } else {
            QDF_TRACE(QDF_MODULE_ID_DP, QDF_TRACE_LEVEL_FATAL,
                      "Invalid. Allowed only in HOSTAP mode\n");
        }
        break;
    case IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS_CLEAR:
        *value = 0;
        vap->iv_bpr_timer_start_count  = 0;
        vap->iv_bpr_timer_resize_count = 0;
        vap->iv_bpr_callback_count     = 0;
        vap->iv_bpr_unicast_resp_count = 0;
        vap->iv_bpr_timer_cancel_count = 0;
        break;
#endif
    case IEEE80211_PARAM_HE_ER_SU_DISABLE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_ER_SU_DISABLE);
        break;
    case IEEE80211_PARAM_HE_1024QAM_LT242RU_RX_ENABLE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_1024QAM_LT242RU_RX_ENABLE);
        break;
    case IEEE80211_PARAM_HE_UL_MU_DATA_DIS_RX_SUPP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_MU_DATA_DIS_RX_SUPP);
        break;
    case IEEE80211_PARAM_HE_FULL_BW_UL_MUMIMO:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_FULL_BW_UL_MUMIMO);
        break;
    case IEEE80211_PARAM_HE_DCM_MAX_CONSTELLATION_RX:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_DCM_MAX_CONSTELLATION_RX);
        break;
    case IEEE80211_PARAM_DISABLE_INACT_PROBING:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_DISABLE_INACT_PROBING);
        break;
    case IEEE80211_PARAM_TXPOW_MGMT:
        frame_subtype = txpow_frm_subtype[1];
        if (((frame_subtype & ~IEEE80211_FC0_SUBTYPE_MASK)!=0) || (frame_subtype < IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
                || (frame_subtype > IEEE80211_FC0_SUBTYPE_DEAUTH) ) {
            qdf_print("Invalid value entered for frame subtype");
            return -EINVAL;
        }
        *value = vap->iv_txpow_mgt_frm[(frame_subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)];
        break;
    case IEEE80211_PARAM_TXPOW:
        frame_type = txpow_frm_subtype[1] >> IEEE80211_SUBTYPE_TXPOW_SHIFT;
        frame_subtype = (txpow_frm_subtype[1] & 0xff);
        if (((frame_subtype & ~IEEE80211_FC0_SUBTYPE_MASK)!=0) || (frame_subtype < IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
                || (frame_subtype > IEEE80211_FC0_SUBTYPE_CF_END_ACK) || (frame_type > IEEE80211_FC0_TYPE_DATA) ) {
            return -EINVAL;
        }
        *value = vap->iv_txpow_frm[frame_type >>IEEE80211_FC0_TYPE_SHIFT][(frame_subtype >> IEEE80211_FC0_SUBTYPE_SHIFT)];
        break;
    case IEEE80211_PARAM_CONFIG_TX_CAPTURE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_TX_CAPTURE);
        break;

    case IEEE80211_PARAM_ENABLE_FILS:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_FILS);
    break;
    case IEEE80211_PARAM_HE_EXTENDED_RANGE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_EXTENDED_RANGE);
    break;
    case IEEE80211_PARAM_HE_DCM:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_DCM);
    break;
    case IEEE80211_PARAM_HE_FRAGMENTATION:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_FRAGMENTATION);
    break;
    case IEEE80211_PARAM_HE_MU_EDCA:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MU_EDCA);
    break;
    case IEEE80211_PARAM_HE_DYNAMIC_MU_EDCA:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_DYNAMIC_MU_EDCA);
    break;
    case IEEE80211_PARAM_HE_DL_MU_OFDMA:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_DL_MU_OFDMA);
    break;
    case IEEE80211_PARAM_HE_DL_MU_OFDMA_BFER:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_DL_MU_OFDMA_BFER);
    break;
    case IEEE80211_PARAM_HE_UL_MU_MIMO:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_MU_MIMO);
    break;
    case IEEE80211_PARAM_6G_HE_OP_MIN_RATE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_6G_HE_OP_MIN_RATE);
    break;
    case IEEE80211_PARAM_HE_UL_MU_OFDMA:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_UL_MU_OFDMA);
    break;
    case IEEE80211_PARAM_HE_SU_BFEE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_SU_BFEE);
    break;
    case IEEE80211_PARAM_HE_SU_BFER:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_SU_BFER);
    break;
    case IEEE80211_PARAM_HE_MU_BFEE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MU_BFEE);
    break;
    case IEEE80211_PARAM_HE_MU_BFER:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MU_BFER);
    break;
    case IEEE80211_PARAM_EXT_NSS_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_EXT_NSS_SUPPORT);
    break;
    case IEEE80211_PARAM_QOS_ACTION_FRAME_CONFIG:
        *value = ic->ic_qos_acfrm_config;
    break;
    case IEEE80211_PARAM_HE_LTF:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_LTF);
    break;
    case IEEE80211_PARAM_HE_AR_GI_LTF:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_AR_GI_LTF);
    break;
    case IEEE80211_PARAM_HE_AR_LDPC:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_AR_LDPC);
        if(*value == IEEE80211_HE_AR_LDPC_DEFAULT){
          qdf_err("HE Auto Rate LDPC will be set by FW based on BW, NSS and MCS settings");
          return -EINVAL;
        }
    break;
    case IEEE80211_PARAM_HE_RTSTHRSHLD:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_RTSTHRSHLD);
    break;
    case IEEE80211_PARAM_DFS_INFO_NOTIFY_APP:
        *value = ic->ic_dfs_info_notify_channel_available;
    break;
    case IEEE80211_PARAM_DISABLE_CABQ:
        *value = wlan_get_param(vap, IEEE80211_FEATURE_DISABLE_CABQ);
        break;
#if ATH_ACL_SOFTBLOCKING
    case IEEE80211_PARAM_SOFTBLOCK_WAIT_TIME:
        *value = vap->iv_softblock_wait_time;
        break;
    case IEEE80211_PARAM_SOFTBLOCK_ALLOW_TIME:
        *value = vap->iv_softblock_allow_time;
        break;
#endif
    case IEEE80211_PARAM_CSL_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CSL_SUPPORT);
    break;
    case IEEE80211_PARAM_TIMEOUTIE:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_TIMEOUTIE);
        break;
    case IEEE80211_PARAM_PMF_ASSOC:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_PMF_ASSOC);
        break;

    case IEEE80211_PARAM_BEST_UL_HYST:
        *value = ucfg_son_get_bestul_hyst(vap->vdev_obj);
        break;
    case IEEE80211_PARAM_HE_TX_MCSMAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_TX_MCSMAP);
        qdf_print("Getting HE TX MCS MAP set: %x",*value);
        break;
    case IEEE80211_PARAM_HE_RX_MCSMAP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_RX_MCSMAP);
        qdf_print("Getting HE RX MCS MAP set: %x",*value);
        break;
    case IEEE80211_PARAM_CONFIG_M_COPY:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_M_COPY);
        break;
    case IEEE80211_PARAM_CONFIG_CAPTURE_LATENCY_ENABLE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_CAPTURE_LATENCY_ENABLE);
        break;
    case IEEE80211_PARAM_BA_BUFFER_SIZE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_BA_BUFFER_SIZE);
        break;
    case IEEE80211_PARAM_NSSOL_VAP_READ_RXPREHDR:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_READ_RXPREHDR);
        break;
    case IEEE80211_PARAM_HE_SOUNDING_MODE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_SOUNDING_MODE);
        break;
    case IEEE80211_PARAM_RSN_OVERRIDE:
        *value = wlan_get_param(vap, IEEE80211_SUPPORT_RSN_OVERRIDE);
        break;
    case IEEE80211_PARAM_MAP:
        *value = son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY);
        break;
    case IEEE80211_PARAM_MAP_BSS_TYPE:
        *value = son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY_VAP_TYPE);
        break;
    case IEEE80211_PARAM_MAP2_BSTA_VLAN_ID:
        *value = son_vdev_map_capability_get(vap->vdev_obj, SON_MAP_CAPABILITY_BSTA_VLAN_ID);
        break;
    case IEEE80211_PARAM_HE_HT_CTRL:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_HT_CTRL);
        break;
    case IEEE80211_PARAM_RAWMODE_OPEN_WAR:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_RAWMODE_OPEN_WAR);
        break;
    case IEEE80211_PARAM_MODE:
        *value = wlan_get_param(vap, IEEE80211_DRIVER_HW_CAPS);
        break;
    case IEEE80211_PARAM_FT_ENABLE:
        if(vap->iv_opmode == IEEE80211_M_STA) {
            *value = wlan_get_param(vap, IEEE80211_CONFIG_FT_ENABLE);
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                "Valid only in STA mode\n");
            return -EINVAL;
        }
        break;
#if QCA_SUPPORT_SON
    case IEEE80211_PARAM_SON_EVENT_BCAST:
        *value = wlan_son_is_vdev_event_bcast_enabled(vap->vdev_obj);
	break;
    case IEEE80211_PARAM_WHC_MIXEDBH_ULRATE:
        *value = son_get_ul_mixedbh(vap->vdev_obj);
        break;
#endif
#if UMAC_SUPPORT_WPA3_STA
    case IEEE80211_PARAM_SAE_AUTH_ATTEMPTS:
        *value = vap->iv_sae_max_auth_attempts;
        break;
#endif
    case IEEE80211_PARAM_DPP_VAP_MODE:
        *value = vap->iv_dpp_vap_mode;
        break;
    case IEEE80211_PARAM_HE_BSR_SUPPORT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_BSR_SUPPORT);
    break;
    case IEEE80211_PARAM_MAP_VAP_BEACONING:
         *value = son_vdev_map_capability_get(vap->vdev_obj,
                                     SON_MAP_CAPABILITY_VAP_UP);
         break;
    case IEEE80211_PARAM_UNIFORM_RSSI:
        *value = ic->ic_uniform_rssi;
         break;
    case IEEE80211_PARAM_CSA_INTEROP_PHY:
        *value = vap->iv_csa_interop_phy;
        break;
    case IEEE80211_PARAM_CSA_INTEROP_BSS:
        *value = vap->iv_csa_interop_bss;
        break;
    case IEEE80211_PARAM_CSA_INTEROP_AUTH:
        *value = vap->iv_csa_interop_auth;
        break;
    case IEEE80211_PARAM_GET_RU26_TOLERANCE:
        *value = ic->ru26_tolerant;
        break;
#if SM_ENG_HIST_ENABLE
    case IEEE80211_PARAM_SM_HISTORY:
         wlan_mlme_print_all_sm_history();
         break;
#endif
#if WLAN_SCHED_HISTORY_SIZE
    case IEEE80211_PARAM_WLAN_SCHED_HISTORY:
        sched_history_print();
        break;
#endif
    case IEEE80211_PARAM_GET_MAX_RATE:
        *value = ieee80211_ucfg_get_maxphyrate(vap);
        break;
    case IEEE80211_PARAM_GET_SIGNAL_LEVEL:
        ieee80211_ucfg_get_quality(vap, (void *)&iq);
        *value = iq.level;
        break;
    case IEEE80211_PARAM_MAX_MTU_SIZE:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_MAX_MTU_SIZE);
        break;
    case IEEE80211_PARAM_HE_6GHZ_BCAST_PROB_RSP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_6GHZ_BCAST_PROB_RSP);
        break;
    case IEEE80211_PARAM_VHT_MCS_12_13_SUPP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_HE_MCS_12_13_SUPP);
        break;
#ifdef VDEV_PEER_PROTOCOL_COUNT
    case IEEE80211_PARAM_VDEV_PEER_PROTOCOL_COUNT:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_COUNT);
        break;
    case IEEE80211_PARAM_VDEV_PEER_PROTOCOL_DROP_MASK:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_VDEV_PEER_PROTOCOL_DROP_MASK);
        break;
#endif
    case IEEE80211_PARAM_FILS_IS_ENABLE:
        {
#if WLAN_SUPPORT_FILS
        struct ieee80211vap *tx_vap;

        tx_vap = vap;
        if (is_mbssid_enabled) {
            if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
                tx_vap = ic->ic_mbss.transmit_vap;
            }
        }

        if (tx_vap)
            *value = wlan_fils_is_enable(tx_vap->vdev_obj);
        else
            *value = 0;
#endif
        }
        break;
    case IEEE80211_PARAM_OCE_VERSION_OVERRIDE:
        *value = wlan_get_param(vap, IEEE80211_OCE_VERSION_OVERRIDE);
        break;
    case IEEE80211_PARAM_ENABLE_MSCS:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_ENABLE_MSCS);
        break;
    case IEEE80211_PARAM_CURRENT_PP:
        if (!is_mbssid_enabled) {
            *value = 0;
        }
        else {
            *value = ic->ic_mbss.current_pp;
        }
        break;
    case IEEE80211_PARAM_NO_ACT_VAPS:
        *value = ieee80211_get_num_ap_vaps_up(ic);
        break;
    case IEEE80211_PARAM_TX_VAP:
        {
            struct ieee80211vap *tx_vap = ic->ic_mbss.transmit_vap;

            if (tx_vap) {
                *value = wlan_vdev_get_id(tx_vap->vdev_obj);
            } else {
                *value = NO_TX_VAP;
            }
        }
        break;
    case IEEE80211_PARAM_HLOS_TID_OVERRIDE:
         *value = ieee80211_ucfg_get_hlos_tid_override(osifp);
        break;
    case IEEE80211_PARAM_6G_SECURITY_COMP:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_6G_SECURITY_COMP);
        break;
    case IEEE80211_PARAM_6G_KEYMGMT_MASK:
        *value = wlan_get_param(vap, IEEE80211_CONFIG_6G_KEYMGMT_MASK);
        break;
    case IEEE80211_PARAM_MBSS_TXVDEV:
        *value = 0;

        if (is_mbssid_enabled) {
            if ((ic->ic_mbss.transmit_vap) &&
                (ic->ic_mbss.transmit_vap == vap))
                *value = 1;
        } else {
            if (ic->ic_mbss.target_transmit_vap &&
                ic->ic_mbss.target_transmit_vap == vap)
                *value = 1;
        }
        break;
#if SM_ENG_HIST_ENABLE
    case IEEE80211_PARAM_CM_HISTORY:
         if (wlan_vap_get_opmode(vap) == IEEE80211_M_STA) {
             cm_ext_handle = wlan_cm_get_ext_hdl(vap->vdev_obj);
             if (!cm_ext_handle)
                 break;
             wlan_cm_sm_history_print(vap->vdev_obj);
             wlan_mlme_cm_action_print_history(&cm_ext_handle->cm_action_history);
             wlan_cm_req_history_print(vap->vdev_obj);
         } else {
             qdf_err("Cmd supported for STA mode only");
         }
         break;
#endif
    case IEEE80211_PARAM_RTS:
        *value = wlan_get_param(vap, IEEE80211_RTS_THRESHOLD);
        break;
    case IEEE80211_PARAM_SM_GAP_PS_ENABLE:
        *value = vap->iv_sm_gap_ps;
        break;
    case IEEE80211_PARAM_PEER_TID_LATENCY_ENABLE:
         *value = ieee80211_ucfg_get_peer_tid_latency_enable(osifp);
         break;
    case IEEE80211_PARAM_AP_MAX_AUTH_FAIL:
         *value = wlan_get_param(vap, IEEE80211_CONFIG_AP_MAX_AUTH_FAIL);
         break;
    }
    if (retv) {
        qdf_print("%s : parameter 0x%x not supported ", __func__, param);
        return -EOPNOTSUPP;
    }

    return retv;
}

int ieee80211_get_chan_nf(struct ieee80211com *ic, int16_t *nf_val)
{
    struct wlan_objmgr_psoc *psoc;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc) {
        qdf_err("psoc is null");
        return -EINVAL;
    }

    if (!ic->ic_is_target_lithium) {
        qdf_err("ic_is_target_lithium is null");
        return -EINVAL;
    }

    if (ic->ic_is_target_lithium(psoc)) {
        if (!ic->ic_get_cur_hw_nf) {
            qdf_err("ic_get_cur_hw_nf is null");
            return -EINVAL;
        }
        *nf_val = ic->ic_get_cur_hw_nf(ic);
    } else {
        if (!ic->ic_get_cur_chan_nf) {
            qdf_err("ic_get_cur_chan_nf is null");
            return -EINVAL;
        }
        *nf_val = ic->ic_get_cur_chan_nf(ic);
    }

    return 0;
}

int ieee80211_ucfg_get_quality(wlan_if_t vap, void *iq)
{
    wlan_snr_info snr_info;
    int16_t nf_val = 0;

    wlan_getsnr(vap, &snr_info, WLAN_SNR_RX);

    if (ieee80211_get_chan_nf(vap->iv_ic, &nf_val) < 0) {
        qdf_err("failed to get chan_nf");
        return -EINVAL;
    }

    set_quality(iq, snr_info.avg_snr, nf_val);

    return 0;
}

u_int32_t ieee80211_ucfg_get_maxphyrate(wlan_if_t vaphandle)
{
 struct ieee80211vap *vap = vaphandle;
 struct ieee80211com *ic = vap->iv_ic;

 if (!vap->iv_bss)
     return 0;

 /* Rate should show 0 if VAP is not UP.
  * Rates are returned as Kbps to avoid
  * signed overflow when using HE modes
  * or larger values of NSS.
  * All applications should handle this.
  */
 return((wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS) ? 0: ic->ic_get_maxphyrate(ic, vap->iv_bss));
}

#define IEEE80211_MODE_TURBO_STATIC_A   IEEE80211_MODE_MAX

int ieee80211_convert_mode(const char *mode)
{
#define TOUPPER(c) ((((c) > 0x60) && ((c) < 0x7b)) ? ((c) - 0x20) : (c))
    static const struct
    {
        char *name;
        int mode;
    } mappings[] = {
        /* NB: need to order longest strings first for overlaps */
        { "11AST" , IEEE80211_MODE_TURBO_STATIC_A },
        { "AUTO"  , IEEE80211_MODE_AUTO },
        { "11A"   , IEEE80211_MODE_11A },
        { "11B"   , IEEE80211_MODE_11B },
        { "11G"   , IEEE80211_MODE_11G },
        { "FH"    , IEEE80211_MODE_FH },
		{ "0"     , IEEE80211_MODE_AUTO },
		{ "1"     , IEEE80211_MODE_11A },
		{ "2"     , IEEE80211_MODE_11B },
		{ "3"     , IEEE80211_MODE_11G },
		{ "4"     , IEEE80211_MODE_FH },
		{ "5"     , IEEE80211_MODE_TURBO_STATIC_A },
	    { "TA"      , IEEE80211_MODE_TURBO_A },
	    { "TG"      , IEEE80211_MODE_TURBO_G },
	    { "11NAHT20"      , IEEE80211_MODE_11NA_HT20 },
	    { "11NGHT20"      , IEEE80211_MODE_11NG_HT20 },
	    { "11NAHT40PLUS"  , IEEE80211_MODE_11NA_HT40PLUS },
	    { "11NAHT40MINUS" , IEEE80211_MODE_11NA_HT40MINUS },
	    { "11NGHT40PLUS"  , IEEE80211_MODE_11NG_HT40PLUS },
	    { "11NGHT40MINUS" , IEEE80211_MODE_11NG_HT40MINUS },
        { "11NGHT40" , IEEE80211_MODE_11NG_HT40},
        { "11NAHT40" , IEEE80211_MODE_11NA_HT40},
        { "11ACVHT20", IEEE80211_MODE_11AC_VHT20},
        { "11ACVHT40PLUS", IEEE80211_MODE_11AC_VHT40PLUS},
        { "11ACVHT40MINUS", IEEE80211_MODE_11AC_VHT40MINUS},
        { "11ACVHT40", IEEE80211_MODE_11AC_VHT40},
        { "11ACVHT80", IEEE80211_MODE_11AC_VHT80},
        { "11ACVHT160", IEEE80211_MODE_11AC_VHT160},
        { "11ACVHT80_80", IEEE80211_MODE_11AC_VHT80_80},
        { "11AHE20" , IEEE80211_MODE_11AXA_HE20},
        { "11GHE20" , IEEE80211_MODE_11AXG_HE20},
        { "11AHE40PLUS" , IEEE80211_MODE_11AXA_HE40PLUS},
        { "11AHE40MINUS" , IEEE80211_MODE_11AXA_HE40MINUS},
        { "11GHE40PLUS" , IEEE80211_MODE_11AXG_HE40PLUS},
        { "11GHE40MINUS" , IEEE80211_MODE_11AXG_HE40MINUS},
        { "11AHE40" , IEEE80211_MODE_11AXA_HE40},
        { "11GHE40" , IEEE80211_MODE_11AXG_HE40},
        { "11AHE80" , IEEE80211_MODE_11AXA_HE80},
        { "11AHE160" , IEEE80211_MODE_11AXA_HE160},
        { "11AHE80_80" , IEEE80211_MODE_11AXA_HE80_80},
        { NULL }
    };
    int i, j;
    const char *cp;

    for (i = 0; mappings[i].name != NULL; i++) {
        cp = mappings[i].name;
        for (j = 0; j < strlen(mode) + 1; j++) {
            /* convert user-specified string to upper case */
            if (TOUPPER(mode[j]) != cp[j])
                break;
            if (cp[j] == '\0')
                return mappings[i].mode;
        }
    }
    return -1;
#undef TOUPPER
}

int ieee80211_ucfg_set_phymode(wlan_if_t vap, char *modestr, int len, bool reset_vap)
{
    char s[30];      /* big enough for ``11nght40plus'' */
    int mode;
    uint32_t ldpc;
    int retval;
    wlan_chan_t chan;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;
    enum ieee80211_phymode prev_des_mode, preset_vap_mode = vap->iv_cur_mode;

    ic = vap->iv_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    /* truncate the len if it shoots our buffer.
     * len does not include '\0'
     */
    if (len >= sizeof(s)) {
        len = sizeof(s) - 1;
    }

    /* Copy upto len characters and a '\0' enforced by strlcpy */
    if (strlcpy(s, modestr, len + 1) > sizeof(s)) {
        qdf_print("String too long to copy");
        return -EINVAL;
    }

    /*
    ** Convert mode name into a specific mode
    */

    mode = ieee80211_convert_mode(s);
    if (mode < 0)
        return -EINVAL;

    /* if ldpc is disabled then as per 802.11ax
     * specification, D2.0 (section 28.1.1) we
     * can not allow mode greater than 20 MHz
     */
    ucfg_wlan_vdev_mgr_get_param(vap->vdev_obj, WLAN_MLME_CFG_LDPC, &ldpc);
    if ((ldpc == IEEE80211_HTCAP_C_LDPC_NONE) &&
            ieee80211_is_phymode_equal_or_above_11axa_he40plus(mode)) {
        qdf_print("Mode %s is not allowed if LDPC is "
                "already disabled", s);
        return -EINVAL;
    }

    prev_des_mode = vap->iv_des_mode;
    retval = ieee80211_ucfg_set_wirelessmode(vap, mode);

    /* If there is no channel set,  ACS will be triggered later */
    chan = wlan_get_current_channel(vap, false);
    if ((ieee80211_convert_mode(s) == prev_des_mode) ||
            (!chan) || (chan == IEEE80211_CHAN_ANYC) ||
            ieee80211_is_phymode_auto(preset_vap_mode))
       return retval;

    ic = vap->iv_ic;

    /* Restart all the vaps to make the change take into effect */
    if (reset_vap) {
        if (osif_restart_for_config(ic, NULL, NULL))
            return -EFAULT;
    }

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

    return retval;
}

int ieee80211_ucfg_set_wirelessmode(wlan_if_t vap, int mode)
{
    struct ieee80211com *ic = vap->iv_ic;

    /* OBSS scanning should only be enabled in 40 Mhz 2.4G */

    /* 11AX TODO: Recheck future 802.11ax drafts (>D1.0) on coex rules */
    if (ieee80211_is_phymode_g40(mode)) {
        if (!ic->ic_user_coext_disable) {
            struct ieee80211vap *tmpvap = NULL;
            bool width40_vap_found = false;
            /*Check if already any VAP is configured with HT40 mode*/
            TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
                if((vap != tmpvap) && ieee80211_is_phymode_g40(tmpvap->iv_des_mode)) {
                    width40_vap_found = true;
                    break;
                }
            }
            /*
             * If any VAP is already configured with 40 width,
             * no need to clear disable coext flag,
             * as disable coext flag may be set by other VAP
             */
            if(!width40_vap_found)
                ieee80211com_clear_flags(ic, IEEE80211_F_COEXT_DISABLE);
        }
    } else {
        ieee80211com_set_flags(ic, IEEE80211_F_COEXT_DISABLE);
    }

#if ATH_SUPPORT_IBSS_HT
    /*
     * config ic adhoc ht capability
     */
    if (vap->iv_opmode == IEEE80211_M_IBSS) {

        wlan_dev_t ic = wlan_vap_get_devhandle(vap);

        switch (mode) {
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
            /* enable adhoc ht20 and aggr */
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT20ADHOC, 1);
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT40ADHOC, 0);
            break;
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            /* enable adhoc ht40 and aggr */
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT20ADHOC, 1);
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT40ADHOC, 1);
            break;
        /* TODO: With IBSS support add VHT fields as well */
        default:
            /* clear adhoc ht20, ht40, aggr */
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT20ADHOC, 0);
            wlan_set_device_param(ic, IEEE80211_DEVICE_HT40ADHOC, 0);
            break;
        } /* end of switch (mode) */
    }
#endif /* end of #if ATH_SUPPORT_IBSS_HT */

    return wlan_set_desired_phymode(vap, mode);
}

/*
* Get a key index from a request.  If nothing is
* specified in the request we use the current xmit
* key index.  Otherwise we just convert the index
* to be base zero.
*/
static int getkeyix(wlan_if_t vap, u_int16_t flags, u_int16_t *kix)
{
    int kid;

    kid = flags & IW_ENCODE_INDEX;
    if (kid < 1 || kid > IEEE80211_WEP_NKID)
    {
        kid = wlan_get_default_keyid(vap);
        if (kid == IEEE80211_KEYIX_NONE)
            kid = 0;
    }
    else
        --kid;
    if (0 <= kid && kid < IEEE80211_WEP_NKID)
    {
        *kix = kid;
        return 0;
    }
    else
        return -EINVAL;
}

/*
 * If authmode = IEEE80211_AUTH_OPEN, script apup would skip authmode setup.
 * Do default authmode setup here for OPEN mode.
 */
static int sencode_wep(struct net_device *dev)
{
    osif_dev            *osifp = ath_netdev_priv(dev);
    wlan_if_t           vap    = osifp->os_if;
    int                 error  = 0;
    error = wlan_crypto_set_vdev_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE, 1 << WLAN_CRYPTO_AUTH_OPEN);
    if (error == 0 ) {
        error = wlan_set_param(vap, IEEE80211_FEATURE_PRIVACY, 0);
        osifp->uciphers[0] = osifp->mciphers[0] = IEEE80211_CIPHER_NONE;
        osifp->u_count = osifp->m_count = 1;
    }

    return IS_UP(dev) ? -osif_vap_init(dev, RESCAN) : 0;
}

int ieee80211_ucfg_set_encode(wlan_if_t vap, u_int16_t length, u_int16_t flags, void *keybuf)
{
    osif_dev *osifp = (osif_dev *)vap->iv_ifp;
    struct net_device *dev = osifp->netdev;
    ieee80211_keyval key_val;
    u_int16_t kid;
    int error = -EOPNOTSUPP;
    u_int8_t keydata[IEEE80211_KEYBUF_SIZE];
    int wepchange = 0;

    if (ieee80211_crypto_wep_mbssid_enabled())
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 1);  /* wep keys will start from 4 in keycache for support wep multi-bssid */
    else
        wlan_set_param(vap, IEEE80211_WEP_MBSSID, 0);  /* wep keys will allocate index 0-3 in keycache */

    if ((flags & IW_ENCODE_DISABLED) == 0)
    {
        /*
         * Enable crypto, set key contents, and
         * set the default transmit key.
         */
        error = getkeyix(vap, flags, &kid);
        if (error)
            return error;
        if (length > IEEE80211_KEYBUF_SIZE)
            return -EINVAL;

        /* XXX no way to install 0-length key */
        if (length > 0)
        {

            /* WEP key length should be 40,104, 128 bits only */
            if(!((length == IEEE80211_KEY_WEP40_LEN) ||
                        (length == IEEE80211_KEY_WEP104_LEN) ||
                        (length == IEEE80211_KEY_WEP128_LEN)))
            {

                IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO, "WEP key is rejected due to key of length %d\n", length);
                osif_ioctl_delete_vap(dev);
                return -EINVAL;
            }

            /*
             * ieee80211_match_rsn_info() IBSS mode need.
             * Otherwise, it caused crash when tx frame find tx rate
             *   by node RateControl info not update.
             */
            if (osifp->os_opmode == IEEE80211_M_IBSS) {
                /* set authmode to IEEE80211_AUTH_OPEN */
                sencode_wep(dev);

                /* set keymgmtset to WPA_ASE_NONE */
         wlan_crypto_set_vdev_param(vap->vdev_obj,
				  WLAN_CRYPTO_PARAM_KEY_MGMT,
					WPA_ASE_NONE);
            }

            qdf_mem_copy(keydata, keybuf, length);
            qdf_mem_zero(&key_val, sizeof(ieee80211_keyval));
            key_val.keytype = IEEE80211_CIPHER_WEP;
            key_val.keydir = IEEE80211_KEY_DIR_BOTH;
            key_val.keylen = length;
            key_val.keydata = keydata;
            key_val.macaddr = (u_int8_t *)ieee80211broadcastaddr;

            if (wlan_set_key(vap, kid, &key_val) != 0) {
                /* Zero-out local key variables */
                qdf_mem_zero(keydata, IEEE80211_KEYBUF_SIZE);
                qdf_mem_zero(&key_val, sizeof(ieee80211_keyval));
                return -EINVAL;
            }
        }
        else
        {
            /*
             * When the length is zero the request only changes
             * the default transmit key.  Verify the new key has
             * a non-zero length.
             */
            if ( wlan_set_default_keyid(vap,kid) != 0  ) {
                qdf_print("\n Invalid Key is being Set. Bringing VAP down! ");
                osif_ioctl_delete_vap(dev);
                return -EINVAL;
            }
        }
        if (error == 0)
        {
            /*
             * The default transmit key is only changed when:
             * 1. Privacy is enabled and no key matter is
             *    specified.
             * 2. Privacy is currently disabled.
             * This is deduced from the iwconfig man page.
             */
            if (length == 0 ||
                    (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY)) == 0)
                wlan_set_default_keyid(vap,kid);
            wepchange = (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY)) == 0;
            wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY, 1);
        }
    }
    else
    {
        if (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY) == 0)
            return 0;
        wlan_set_param(vap,IEEE80211_FEATURE_PRIVACY, 0);
        wepchange = 1;
        error = 0;
    }
    if (error == 0)
    {
        /* Set policy for unencrypted frames */
        if ((flags & IW_ENCODE_OPEN) &&
                (!(flags & IW_ENCODE_RESTRICTED)))
        {
            wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 0);
        }
        else if (!(flags & IW_ENCODE_OPEN) &&
                (flags & IW_ENCODE_RESTRICTED))
        {
            wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 1);
        }
        else
        {
            /* Default policy */
            if (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY))
                wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 1);
            else
                wlan_set_param(vap,IEEE80211_FEATURE_DROP_UNENC, 0);
        }
    }
    if (error == 0 && IS_UP(dev) && wepchange)
    {
        /*
         * Device is up and running; we must kick it to
         * effect the change.  If we're enabling/disabling
         * crypto use then we must re-initialize the device
         * so the 802.11 state machine is reset.  Otherwise
         * the key state should have been updated above.
         */

        error = osif_vap_init(dev, RESCAN);
    }
    return error;
}

int ieee80211_ucfg_set_rate(wlan_if_t vap, int value)
{
    int retv;

    retv = wlan_set_param(vap, IEEE80211_FIXED_RATE, value);
    if (EOK == retv) {
        if (value != IEEE80211_FIXED_RATE_NONE) {
            /* set default retries when setting fixed rate */
            retv = wlan_set_param(vap, IEEE80211_FIXED_RETRIES, 4);
        }
        else {
            retv = wlan_set_param(vap, IEEE80211_FIXED_RETRIES, 0);
        }
    }
    return retv;
}

#define IEEE80211_MODE_TURBO_STATIC_A   IEEE80211_MODE_MAX
int ieee80211_ucfg_get_phymode(wlan_if_t vap, char *modestr, u_int16_t *length, int type)
{
    enum ieee80211_phymode  phymode;

    if(type == CURR_MODE){
        phymode = wlan_get_current_phymode(vap);
    }else if(type == PHY_MODE){
        phymode = wlan_get_desired_phymode(vap);
    }else{
        IEEE80211_DPRINTF(vap,  IEEE80211_MSG_ANY, "Function %s should be called with a valid type \n ",__func__);
        return -EINVAL;
    }

    ieee80211_convert_phymode_to_string(phymode, modestr, length);
    return 0;
}

void ieee80211_convert_phymode_to_string(enum ieee80211_phymode  phymode,
                                           char *modestr, u_int16_t *length)
{
    int i;
    static const struct
    {
        char *name;
        int mode;
    } mappings[] = {
        /* NB: need to order longest strings first for overlaps */
        { "11AST" , IEEE80211_MODE_TURBO_STATIC_A },
        { "AUTO"  , IEEE80211_MODE_AUTO },
        { "11A"   , IEEE80211_MODE_11A },
        { "11B"   , IEEE80211_MODE_11B },
        { "11G"   , IEEE80211_MODE_11G },
        { "FH"    , IEEE80211_MODE_FH },
        { "TA"      , IEEE80211_MODE_TURBO_A },
        { "TG"      , IEEE80211_MODE_TURBO_G },
        { "11NAHT20"        , IEEE80211_MODE_11NA_HT20 },
        { "11NGHT20"        , IEEE80211_MODE_11NG_HT20 },
        { "11NAHT40PLUS"    , IEEE80211_MODE_11NA_HT40PLUS },
        { "11NAHT40MINUS"   , IEEE80211_MODE_11NA_HT40MINUS },
        { "11NGHT40PLUS"    , IEEE80211_MODE_11NG_HT40PLUS },
        { "11NGHT40MINUS"   , IEEE80211_MODE_11NG_HT40MINUS },
        { "11NGHT40"        , IEEE80211_MODE_11NG_HT40},
        { "11NAHT40"        , IEEE80211_MODE_11NA_HT40},
        { "11ACVHT20"       , IEEE80211_MODE_11AC_VHT20},
        { "11ACVHT40PLUS"   , IEEE80211_MODE_11AC_VHT40PLUS},
        { "11ACVHT40MINUS"  , IEEE80211_MODE_11AC_VHT40MINUS},
        { "11ACVHT40"       , IEEE80211_MODE_11AC_VHT40},
        { "11ACVHT80"       , IEEE80211_MODE_11AC_VHT80},
        { "11ACVHT160"      , IEEE80211_MODE_11AC_VHT160},
        { "11ACVHT80_80"    , IEEE80211_MODE_11AC_VHT80_80},
        { "11AHE20"         , IEEE80211_MODE_11AXA_HE20},
        { "11GHE20"         , IEEE80211_MODE_11AXG_HE20},
        { "11AHE40PLUS"     , IEEE80211_MODE_11AXA_HE40PLUS},
        { "11AHE40MINUS"    , IEEE80211_MODE_11AXA_HE40MINUS},
        { "11GHE40PLUS"     , IEEE80211_MODE_11AXG_HE40PLUS},
        { "11GHE40MINUS"    , IEEE80211_MODE_11AXG_HE40MINUS},
        { "11AHE40"         , IEEE80211_MODE_11AXA_HE40},
        { "11GHE40"         , IEEE80211_MODE_11AXG_HE40},
        { "11AHE80"         , IEEE80211_MODE_11AXA_HE80},
        { "11AHE160"        , IEEE80211_MODE_11AXA_HE160},
        { "11AHE80_80"      , IEEE80211_MODE_11AXA_HE80_80},
        { NULL }
    };

    for (i = 0; mappings[i].name != NULL ; i++)
    {
        if (phymode == mappings[i].mode)
        {
            *length = strlen(mappings[i].name);
            strlcpy(modestr, mappings[i].name, *length + 1);
            break;
        }
    }
}

#undef IEEE80211_MODE_TURBO_STATIC_A

static size_t
sta_space(const wlan_node_t node, size_t *ielen, wlan_if_t vap)
{
    u_int8_t    ni_ie[IEEE80211_MAX_OPT_IE];
    u_int16_t ni_ie_len = IEEE80211_MAX_OPT_IE;
    u_int8_t *macaddr = wlan_node_getmacaddr(node);
    *ielen = 0;

    if(!wlan_node_getwpaie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getwmeie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getathie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getwpsie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_get_suppchanie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if (!wlan_node_get_opclassie(vap, macaddr, ni_ie, &ni_ie_len)) {
        *ielen += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }

    return roundup(sizeof(struct ieee80211req_sta_info) + *ielen,
        sizeof(u_int32_t));
}

void
get_sta_space(void *arg, wlan_node_t node)
{
    struct stainforeq *req = arg;
    size_t ielen;

    /* already ignore invalid nodes in UMAC */
    req->space += sta_space(node, &ielen, req->vap);
}

uint8_t get_phymode_from_chwidth(struct ieee80211com *ic,
                                        struct ieee80211_node *ni)
{
    enum ieee80211_phymode cur_mode = ni->ni_vap->iv_cur_mode;
    uint8_t curr_phymode = ni->ni_phymode;
    uint8_t mode;

    /* Mode will attain value of 1 for HE */
    mode = !!(ni->ni_ext_flags & IEEE80211_NODE_HE);
    /* Mode will attain value of 2 for VHT and 3 for HT */
    mode = mode ? mode : (!!(ni->ni_flags & IEEE80211_NODE_VHT) ? 2 : (!!(ni->ni_flags &
           IEEE80211_NODE_HT) ? 3 : mode));

    if (IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan) && mode != 1) {
        qdf_alert("Invalid mode %d for 6GHz", mode);
        return curr_phymode;
    }

    if (IEEE80211_IS_CHAN_5GHZ_6GHZ(ic->ic_curchan)) {
        switch(mode) {
            /* HE mode */
            case 1:
            {
                switch (ni->ni_chwidth) {
                    case IEEE80211_CWM_WIDTH20:
                        curr_phymode = IEEE80211_MODE_11AXA_HE20;
                    break;
                    case IEEE80211_CWM_WIDTH40:
                        curr_phymode = IEEE80211_MODE_11AXA_HE40;
                    break;
                    case IEEE80211_CWM_WIDTH80:
                        curr_phymode = IEEE80211_MODE_11AXA_HE80;
                    break;
                    case IEEE80211_CWM_WIDTH160:
                        return curr_phymode;
                    break;
                    default:
                        return curr_phymode;
                    break;
                }
            }
            break;
            /* VHT mode */
            case 2:
            {
                switch (ni->ni_chwidth) {
                    case IEEE80211_CWM_WIDTH20:
                        curr_phymode = IEEE80211_MODE_11AC_VHT20;
                    break;
                    case IEEE80211_CWM_WIDTH40:
                        curr_phymode = IEEE80211_MODE_11AC_VHT40;
                    break;
                    case IEEE80211_CWM_WIDTH80:
                        curr_phymode = IEEE80211_MODE_11AC_VHT80;
                    break;
                    case IEEE80211_CWM_WIDTH160:
                        if (ieee80211_is_phymode_160(curr_phymode)) {
                            curr_phymode = IEEE80211_MODE_11AC_VHT160;
                        } else if (ieee80211_is_phymode_8080(curr_phymode)) {
                            curr_phymode = IEEE80211_MODE_11AC_VHT80_80;
                        } else {
                            qdf_print("%s: Warning: Unexpected negotiated "
                            "ni_chwidth=%d for cur_mode=%d. Investigate! "
                            "The system may no longer function "
                            "correctly.",
                            __func__, ni->ni_chwidth, cur_mode);
                            return curr_phymode;
                        }
                    break;
                    default:
                        return curr_phymode;
                    break;
                }
            }
            break;
            /* HT mode */
            case 3:
            {
                switch (ni->ni_chwidth) {
                    case IEEE80211_CWM_WIDTH20:
                        curr_phymode = IEEE80211_MODE_11NA_HT20;
                    break;
                    case IEEE80211_CWM_WIDTH40:
                        curr_phymode = IEEE80211_MODE_11NA_HT40;
                    break;
                    default:
                        return curr_phymode;
                    break;
                }
            }
            break;
            default:
                return curr_phymode;
            break;
        }
    } else {
        switch (mode) {
            /* HE mode */
            case 1:
            {
                switch (ni->ni_chwidth) {
                    case IEEE80211_CWM_WIDTH20 :
                        curr_phymode = IEEE80211_MODE_11AXG_HE20;
                    break;
                    case IEEE80211_CWM_WIDTH40 :
                        curr_phymode = IEEE80211_MODE_11AXG_HE40;
                    break;
                    default:
                        return curr_phymode;
                    break;
                }
            }
            break;
            /* HT mode */
            case 3:
            {
                switch (ni->ni_chwidth) {
                    case IEEE80211_CWM_WIDTH20 :
                        curr_phymode = IEEE80211_MODE_11NG_HT20;
                    break;
                    case IEEE80211_CWM_WIDTH40 :
                        curr_phymode = IEEE80211_MODE_11NG_HT40;
                    break;
                    default:
                       return curr_phymode;
                    break;
                }
            }
            break;
            default:
                return curr_phymode;
            break;
        }
    }
    return curr_phymode;
}
qdf_export_symbol(get_phymode_from_chwidth);

void
get_sta_info(void *arg, wlan_node_t node)
{
    struct stainforeq *req = arg;
    wlan_if_t vap = req->vap;
    struct ieee80211req_sta_info *si;
    size_t ielen, len;
    u_int8_t *cp;
    u_int8_t    ni_ie[IEEE80211_MAX_OPT_IE];
    u_int16_t ni_ie_len = IEEE80211_MAX_OPT_IE;
    u_int8_t *macaddr = wlan_node_getmacaddr(node);
    wlan_snr_info snr_info;
    wlan_chan_t chan = wlan_node_get_chan(node);
    ieee80211_rate_info rinfo;
    u_int32_t jiffies_now=0, jiffies_delta=0, jiffies_assoc=0;
    struct wlan_objmgr_psoc *psoc;
    u_int32_t op_class=0, op_rates=0;
    ol_txrx_soc_handle soc_dp_handle;
    struct wlan_objmgr_pdev *pdev;
    QDF_STATUS status;
    cdp_peer_stats_param_t buf = {0};

    /* already ignore invalid nodes in UMAC */
    if (chan == IEEE80211_CHAN_ANYC) { /* XXX bogus entry */
        return;
    }
    if (!vap || !vap->iv_ic)
        return;

    pdev = vap->iv_ic->ic_pdev_obj;
    psoc = wlan_pdev_get_psoc(pdev);

    len = sta_space(node, &ielen, vap);
    if (len > req->space) {
        return;
    }

    si = req->si;
    si->awake_time = node->awake_time;
    si->ps_time = node->ps_time;
    /* if node state is currently in power save when the wlanconfig command is given,
       add time from previous_ps_time until current time to power save time */
    if(node->ps_state == 1)
    {
    si->ps_time += qdf_get_system_timestamp() - node->previous_ps_time;
    }
    /* if node state is currently in active state when the wlanconfig command is given,
       add time from previous_ps_time until current time to awake time */
    else if(node->ps_state == 0)
    {
    si->awake_time += qdf_get_system_timestamp() - node->previous_ps_time;
    }
    si->isi_assoc_time = wlan_node_get_assocuptime(node);
    jiffies_assoc = wlan_node_get_assocuptime(node);		/* Jiffies to timespec conversion for si->isi_tr069_assoc_time */
    jiffies_now = OS_GET_TICKS();
    jiffies_delta = jiffies_now - jiffies_assoc;
    jiffies_to_timespec(jiffies_delta, &si->isi_tr069_assoc_time);
    si->isi_len = len;
    si->isi_ie_len = ielen;
    si->isi_freq = wlan_channel_frequency(chan);
    si->isi_band = reg_wifi_band_to_wlan_band_id(wlan_reg_freq_to_band(si->isi_freq));
    if(!vap->iv_ic->ic_is_target_lithium){
        qdf_err("ic_is_target_lithium if null");
        return;
    }
    if(vap->iv_ic->ic_is_target_lithium(psoc)){
        if(!vap->iv_ic->ic_get_cur_hw_nf){
            qdf_err("ic_get_cur_hw_nf is null");
            return;
        }
        si->isi_nf = vap->iv_ic->ic_get_cur_hw_nf(vap->iv_ic);
    } else {
        if(!vap->iv_ic->ic_get_cur_chan_nf){
            qdf_err("ic_get_cur_hw_nf is null");
            return;
        }
        si->isi_nf = vap->iv_ic->ic_get_cur_chan_nf(vap->iv_ic);
    }
    si->isi_ieee = wlan_channel_ieee(chan);
    si->isi_flags = wlan_channel_flags(chan);
    si->isi_state = wlan_node_get_state_flag(node);
    si->isi_ps = node->ps_state;
    si->isi_authmode =  wlan_node_get_authmode(node);
    if (wlan_node_getsnr(node, &snr_info, WLAN_SNR_RX) == 0) {
        si->isi_rssi = snr_info.avg_snr;
        si->isi_min_rssi = node->ni_snr_min;
        si->isi_max_rssi = node->ni_snr_max;
    }
    si->isi_capinfo = wlan_node_getcapinfo(node);
#if ATH_BAND_STEERING
    si->isi_pwrcapinfo = wlan_node_getpwrcapinfo(node);
#endif
#if UMAC_SUPPORT_RRM
    OS_MEMCPY(si->isi_rrm_caps, node->ni_rrm_caps, sizeof(si->isi_rrm_caps));
#endif
    si->isi_athflags = wlan_node_get_ath_flags(node);
    si->isi_erp = wlan_node_get_erp(node);
    si->isi_operating_bands = wlan_node_get_operating_bands(node);
    si->isi_beacon_measurement_support = wlan_node_has_extflag(node, IEEE80211_NODE_BCN_MEASURE_SUPPORT);
    IEEE80211_ADDR_COPY(si->isi_macaddr, macaddr);

    if (wlan_node_txrate_info(node, &rinfo) == 0) {
        si->isi_txratekbps = rinfo.rate;
        si->isi_maxrate_per_client = rinfo.maxrate_per_client;
#if ATH_EXTRA_RATE_INFO_STA
        si->isi_tx_rate_mcs = rinfo.mcs;
        si->isi_tx_rate_flags = rinfo.flags;
#endif

    }

    /* supported operating classes */
    if (node->ni_supp_op_class_ie != NULL) {
        si->isi_curr_op_class = node->ni_supp_op_cl.curr_op_class;
        si->isi_num_of_supp_class = node->ni_supp_op_cl.num_of_supp_class;
        for(op_class = 0; op_class < node->ni_supp_op_cl.num_of_supp_class &&
            op_class < MAX_NUM_OPCLASS_SUPPORTED; op_class++) {
            si->isi_supp_class[op_class] = node->ni_supp_op_cl.supp_class[op_class];
        }
    }
    else {
          si->isi_num_of_supp_class = 0;
    }

    /* supported channels */
    if (node->ni_supp_chan_ie != NULL) {
        si->isi_first_channel = node->ni_first_channel;
        si->isi_nr_channels = node->ni_nr_channels;
    }
    else {
         si->isi_nr_channels = 0;
    }

    /* supported rates */
    for (op_rates = 0;op_rates < node->ni_rates.rs_nrates;op_rates++) {
         si->isi_rates[op_rates] = node->ni_rates.rs_rates[op_rates];
    }

    memset(&rinfo, 0, sizeof(rinfo));
    if (wlan_node_rxrate_info(node, &rinfo) == 0) {
        si->isi_rxratekbps = rinfo.rate;
#if ATH_EXTRA_RATE_INFO_STA
        si->isi_rx_rate_mcs = rinfo.mcs;
        si->isi_rx_rate_flags = rinfo.flags;
#endif

    }
    si->isi_associd = wlan_node_get_associd(node);
    si->isi_txpower = wlan_node_get_txpower(node);
    si->isi_vlan = wlan_node_get_vlan(node);
    si->isi_cipher = IEEE80211_CIPHER_NONE;
    if (wlan_get_param(vap, IEEE80211_FEATURE_PRIVACY)) {
        do {
            ieee80211_cipher_type uciphers[1];
            int count = 0;
            count = wlan_node_get_ucast_ciphers(node, uciphers, 1);
            if (count == 1) {
                si->isi_cipher |= 1<<uciphers[0];
            }
        } while (0);
    }
    wlan_node_get_txseqs(node, si->isi_txseqs, sizeof(si->isi_txseqs));
    wlan_node_get_rxseqs(node, si->isi_rxseqs, sizeof(si->isi_rxseqs));
    si->isi_uapsd = wlan_node_get_uapsd(node);
    si->isi_opmode = IEEE80211_STA_OPMODE_NORMAL;

    psoc = wlan_pdev_get_psoc(pdev);
    soc_dp_handle = wlan_psoc_get_dp_handle(psoc);
    if (!soc_dp_handle)
        return;

    status = cdp_txrx_get_peer_stats_param(soc_dp_handle,
                                     wlan_vdev_get_id(node->peer_obj->peer_objmgr.vdev),
                                     node->peer_obj->macaddr, cdp_peer_tx_inactive_time,
                                     &buf);
    if (QDF_IS_STATUS_ERROR(status))
        return;

    si->isi_inact = buf.tx_inactive_time;
    /* 11n */
    si->isi_htcap = wlan_node_get_htcap(node);
    si->isi_stamode= wlan_node_get_mode(node);
    si->isi_curr_mode = get_phymode_from_chwidth(vap->iv_ic, node);

#if ATH_SUPPORT_EXT_STAT
    si->isi_vhtcap = wlan_node_get_vhtcap(node);
    si->isi_chwidth = (u_int8_t) wlan_node_get_chwidth(node);
#endif

    /* Extended capabilities */
    si->isi_ext_cap = wlan_node_get_extended_capabilities(node);
    si->isi_ext_cap2 = wlan_node_get_extended_capabilities2(node);
    si->isi_ext_cap3 = wlan_node_get_extended_capabilities3(node);
    si->isi_ext_cap4 = wlan_node_get_extended_capabilities4(node);
    si->isi_nss = wlan_node_get_nss(node);
    si->isi_supp_nss = wlan_node_get_nss_capability(node);
    si->isi_is_256qam = wlan_node_get_256qam_support(node);
    si->isi_is_he = !!(IEEE80211_NODE_USE_HE(node));
    if (si->isi_is_he) {
        qdf_mem_copy(&si->isi_hecap_rxmcsnssmap,
                     &node->ni_he.hecap_rxmcsnssmap,
                     sizeof(u_int16_t) * HEHANDLE_CAP_TXRX_MCS_NSS_SIZE);
        qdf_mem_copy(&si->isi_hecap_txmcsnssmap,
                     &node->ni_he.hecap_txmcsnssmap,
                     sizeof(u_int16_t) * HEHANDLE_CAP_TXRX_MCS_NSS_SIZE);
        qdf_mem_copy(&si->isi_hecap_phyinfo,
                     &node->ni_he.hecap_phyinfo,
                     sizeof(u_int32_t) * HEHANDLE_CAP_PHYINFO_SIZE);
    }

    cp = (u_int8_t *)(si+1);

    if(!wlan_node_getwpaie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getwmeie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getathie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if(!wlan_node_getwpsie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if (!wlan_node_get_suppchanie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }
    if (!wlan_node_get_opclassie(vap, macaddr, ni_ie, &ni_ie_len)) {
        OS_MEMCPY(cp, ni_ie, ni_ie_len);
        cp += ni_ie_len;
        ni_ie_len = IEEE80211_MAX_OPT_IE;
    }

    req->si = (
    struct ieee80211req_sta_info *)(((u_int8_t *)si) + len);
    req->space -= len;
}
int ieee80211_ucfg_getstaspace(wlan_if_t vap)
{
    struct stainforeq req;


    /* estimate space required for station info */
    req.space = sizeof(struct stainforeq);
    req.vap = vap;
    wlan_iterate_station_list(vap, get_sta_space, &req);

    return req.space;

}
int ieee80211_ucfg_getstainfo(wlan_if_t vap, struct ieee80211req_sta_info *si, uint32_t *len)
{
    struct stainforeq req;


    if (*len < sizeof(struct ieee80211req_sta_info))
        return -EFAULT;

    /* estimate space required for station info */
    req.space = sizeof(struct stainforeq);
    req.vap = vap;

    if (*len > 0)
    {
        size_t space = *len;

        if (si == NULL)
            return -ENOMEM;

        req.si = si;
        req.space = *len;

        wlan_iterate_station_list(vap, get_sta_info, &req);
        *len = space - req.space;
    }
    else
        *len = 0;

    return 0;
}

#if ATH_SUPPORT_IQUE
int ieee80211_ucfg_rcparams_setrtparams(wlan_if_t vap, uint8_t rt_index, uint8_t per, uint8_t probe_intvl)
{
    if ((rt_index != 0 && rt_index != 1) || per > 100 ||
        probe_intvl > 100)
    {
        goto error;
    }
    wlan_set_rtparams(vap, rt_index, per, probe_intvl);
    return 0;

error:
    qdf_print("usage: rtparams rt_idx <0|1> per <0..100> probe_intval <0..100>");
    return -EINVAL;
}

int ieee80211_ucfg_rcparams_setratemask(wlan_if_t vap, uint8_t preamble,
        uint32_t mask_lower32, uint32_t mask_higher32, uint32_t mask_lower32_2)
{
    osif_dev *osifp = (osif_dev *)vap->iv_ifp;
    struct net_device *dev = osifp->netdev;
    struct ieee80211com *ic = vap->iv_ic;
    int retv = -EINVAL;

    if(osifp->osif_is_mode_offload) {
        switch(preamble)
        {
            case IEEE80211_LEGACY_PREAMBLE:
                if ((mask_lower32 > 0xFFF) ||
                       (mask_higher32 != 0) ||
                       (mask_lower32_2 != 0)) {
                    qdf_print("Invalid ratemask for CCK/OFDM");
                    return retv;
                } else {
                    break;
                }
            case IEEE80211_HT_PREAMBLE:
                if((mask_higher32 != 0) || (mask_lower32_2 != 0)) {
                    qdf_print("Invalid ratemask for HT");
                    return retv;
                } else {
                    break;
                }
            case IEEE80211_VHT_PREAMBLE:
                /* For HE targets, we now support MCS0-11 for upto NSS 8 for VHT.
                 * But for legacy targets we have support till MCS0-9 NSS 4.
                 * Hence the below check ensures the correct bitmask is sent
                 * depending on the target. */
                if (!(ic->ic_he_target) && ((mask_higher32 > 0xFF) ||
                                            (mask_lower32_2 != 0))) {
                    qdf_print("Invalid ratemask for VHT");
                    return retv;
                } else {
                    break;
                }
            case IEEE80211_HE_PREAMBLE:
                if(!ic->ic_he_target){
                    qdf_print("HE preamble not supported for this target.");
                    return retv;
                } else {
                    break;
                }
            default:
                qdf_print("Invalid preamble type");
                return retv;
        }
        retv = ic->ic_vap_set_ratemask(vap, preamble, mask_lower32,
                mask_higher32, mask_lower32_2);
        /*
         * ic_is_vdev_restart_sup indicates vdev restart is supported by this
         * radio and retv set to ENETRESET indicates this config requires a vdev
         * restart.
         * restart_vap indicates that vdev restart optimization for config changes
         * is supported by FW.
         */

        if (retv == ENETRESET && IS_UP(dev)) {
            if (ic->ic_is_vdev_restart_sup &&
                    (vap->iv_opmode == IEEE80211_M_HOSTAP))
                retv = osif_vdev_restart(vap);
            else
                retv = osif_vap_init(dev, RESCAN);
        } else {
            retv = 0;
        }
    }
    return retv;
}
#endif

static int
is_null_mac(char *addr)
{
	char nullmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	if (IEEE80211_ADDR_EQ(addr, nullmac))
		return 1;

	return 0;
}

#if WLAN_CFR_ENABLE
enum cfr_cwm_width ieee80211_convert_ieee_to_cfr_bw(
        enum ieee80211_cwm_width cwm_width)
{
    switch (cwm_width) {
        case IEEE80211_CWM_WIDTH20:
		return CFR_CWM_WIDTH20;
        case IEEE80211_CWM_WIDTH40:
		return CFR_CWM_WIDTH40;
        case IEEE80211_CWM_WIDTH80:
		return CFR_CWM_WIDTH80;
        case IEEE80211_CWM_WIDTH160:
		return CFR_CWM_WIDTH160;
        case IEEE80211_CWM_WIDTH80_80:
		return CFR_CWM_WIDTH80_80;
        default:
	    return CFR_CWM_WIDTHINVALID;
    }
}

int
ieee80211_ucfg_cfr_params(struct ieee80211com *ic, wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
    struct cfr_wlanconfig_param *cfr_params;
    struct ieee80211_node *ni = NULL;
    int retv = 0;
    struct cfr_capture_params cfr_req = {0};
    struct wlan_objmgr_pdev *pdev = NULL;
    struct qdf_mac_addr unassoc_mac = {0};

    pdev = vap->iv_ic->ic_pdev_obj;
    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID) !=
        QDF_STATUS_SUCCESS) {
            cfr_err("Getting pdev ref failed");
            return -EINVAL;
    }

    if (wlan_cfr_is_feature_disabled(pdev)) {
            cfr_err("cfr is disabled");
            wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);
            return QDF_STATUS_E_NOSUPPORT;
    }
    wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);

    cfr_params = &config->data.cfr_config;
    qdf_mem_copy(&unassoc_mac, &cfr_params->mac[0], sizeof(struct qdf_mac_addr));

    switch (config->cmdtype) {

        case IEEE80211_WLANCONFIG_CFR_START:
            ni = ieee80211_vap_find_node(vap, &(cfr_params->mac[0]), WLAN_MLME_SB_ID);
            if (ni == NULL) {
                if (cfr_params->capture_method == CFR_CAPTURE_METHOD_PROBE_RESPONSE ||
                    cfr_params->capture_method == CFR_CAPTURE_METHOD_AUTO) {
                    /* To remove complexity at user interface level, CFR capture
                     * for associated and un-associated clients use the same
                     * command. So if node is not found, trigger
                     * un-associated capture.
                     */
                    cfr_debug("Peer not found. Capture is enabled on Probe response");

                    cfr_req.period = cfr_params->periodicity;
                    cfr_req.bandwidth = cfr_params->bandwidth;
                    cfr_req.method = CFR_CAPTURE_METHOD_PROBE_RESPONSE;
                    pdev = vap->iv_ic->ic_pdev_obj;
                    if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID) !=
                            QDF_STATUS_SUCCESS) {
                        cfr_err("Getting pdev ref failed");
                        return -EINVAL;
                    }

                    retv = ucfg_cfr_start_capture_probe_req(pdev, &unassoc_mac, &cfr_req);
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);
                    return retv;
                } else {
                    cfr_err("Peer not found");
                    return -EINVAL;
                }
            }

            if (cfr_params->bandwidth > ieee80211_convert_ieee_to_cfr_bw(ni->ni_chwidth)) {
                cfr_err("Invalid bandwidth\n");
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                return -EINVAL;
            }
	    if (cfr_params->capture_method >= CFR_CAPTURE_METHOD_MAX) {
                cfr_err("Invalid capture method\n");
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                return -EINVAL;
            }

            pdev = vap->iv_ic->ic_pdev_obj;
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID) !=
                    QDF_STATUS_SUCCESS) {
                cfr_err("Getting pdev ref failed");
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                return -EINVAL;
            }

            cfr_req.period = cfr_params->periodicity;
            cfr_req.bandwidth = cfr_params->bandwidth;

            if (cfr_params->capture_method == CFR_CAPTURE_METHOD_AUTO) {
                /* Update the highest method for connected clients here */
                cfr_req.method = CFR_CAPTURE_METHOD_QOS_NULL_WITH_PHASE;
            } else {
                /* If method is not auto, honour the input if valid */
                if (cfr_params->capture_method < CFR_CAPTURE_METHOD_LAST_VALID) {
                    cfr_req.method = cfr_params->capture_method;
                } else {
                    cfr_err("Invalid capture method");
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                    wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);
                    return -EINVAL;
                }
            }

            retv = ucfg_cfr_start_capture(pdev, ni->peer_obj, &cfr_req);

            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);

            break;
        case IEEE80211_WLANCONFIG_CFR_STOP:
            ni = ieee80211_vap_find_node(vap, &(cfr_params->mac[0]), WLAN_MLME_SB_ID);
            if (ni == NULL) {
                /* To remove complexity at user interface level, CFR capture for
                 * associated and un-associated clients use the same command.
                 * So if node is not found, stop un-associated capture.
                 */
                cfr_debug("Peer not found. Try disabling on Probe Req Ack");

                pdev = vap->iv_ic->ic_pdev_obj;
                if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID) !=
                    QDF_STATUS_SUCCESS) {
                    cfr_err("Getting pdev ref failed");
                    return -EINVAL;
                }
                retv = ucfg_cfr_stop_capture_probe_req(pdev, &unassoc_mac);
		wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);
                return retv;
            }

            pdev = vap->iv_ic->ic_pdev_obj;
            if (wlan_objmgr_pdev_try_get_ref(pdev, WLAN_CFR_ID) !=
                    QDF_STATUS_SUCCESS) {
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                return -EINVAL;
            }

            retv = ucfg_cfr_stop_capture(pdev, ni->peer_obj);

            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
            wlan_objmgr_pdev_release_ref(pdev, WLAN_CFR_ID);

            break;
        case IEEE80211_WLANCONFIG_CFR_LIST_PEERS:
            break;
#ifdef WLAN_ENH_CFR_ENABLE
        case IEEE80211_WLANCONFIG_CFR_RCC_DIRECT_FTM:
            {
                    /*
                     * m_directed_ftm capture mode is not supported in Cypress.
                     * Hence currently, we return -1 instead of enabling the
                     * capture mode. However, mode setting has not been removed,
                     * since this code can be used in future, if this capture
                     * mode is going to be supported in either Cypress or any
                     * other chipsets.
                     */
                cfr_err("As of now m_directed_ftm mode is not supported\n");
                return -EACCES;


            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_DIRECT_NDPA_NDP:
            {
                retv = ucfg_cfr_set_rcc_mode(vap->vdev_obj,
                                             RCC_DIRECTED_NDPA_NDP_FILTER,
                                             (cfr_params->en_directed_ndpa_ndp)
                                             || !(cfr_params->dis_directed_ndpa_ndp));
            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_TA_RA_FLITER:
            {
                retv = ucfg_cfr_set_rcc_mode(vap->vdev_obj, RCC_TA_RA_FILTER,
                                             (cfr_params->en_ta_ra_filter) ||
                                             !(cfr_params->dis_ta_ra_filter));
            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_ALL_FTM_ACK:
            {

                    /*
                     * m_all_ftm_ack capture mode is not supported in Cypress.
                     * Hence currently, we return -1 instead of enabling the
                     * capture mode. However, mode setting has not been removed,
                     * since this code can be used in future, if this capture
                     * mode is going to be supported in either Cypress or any
                     * other chipsets.
                     */
                    cfr_err("As of now m_all_ftm_ack mode is not supported\n");
                    return -EACCES;

            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_NDPA_NDP_ALL:
            {

                retv = ucfg_cfr_set_rcc_mode(vap->vdev_obj,
                                             RCC_NDPA_NDP_ALL_FILTER,
                                             (cfr_params->en_ndpa_ndp_all) ||
                                             !(cfr_params->dis_ndpa_ndp_all));
            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_ALL_PKT:
            {

                    /**
                     * m_all_pkt capture mode is not supported in case of
                     * Cypress.Hence currently, we return -1 instead of
                     * enabling the capture mode. However, mode setting has not
                     * been removed, since this code can be used in future, if
                     * this capture mode is going to be supported in either
                     * Cypress or any other chipsets.
                     */
                    cfr_err("As of now m_all_pkt mode is not supported.\n");
                    return -EACCES;

            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_TA_RA_ADDR:
            {

                    retv = ucfg_cfr_set_tara_config(vap->vdev_obj, cfr_params);

            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_BW_NSS:
            {
                    retv = ucfg_cfr_set_bw_nss(vap->vdev_obj, cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_SUBTYPE:
            {
                    retv = ucfg_cfr_set_frame_type_subtype(vap->vdev_obj,
                                                           cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_CAPT_DUR:
            {
                    retv = ucfg_cfr_set_capture_duration(vap->vdev_obj,
                                                         cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_CAPT_INTVAL:
            {
                    retv = ucfg_cfr_set_capture_interval(vap->vdev_obj,
                                                         cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_TARA_FILTER_AS_FP:
            {
                    retv = ucfg_cfr_set_tara_filterin_as_fp(vap->vdev_obj,
                                                            cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_EN_CFG:
            {
                    retv = ucfg_cfr_set_en_bitmap(vap->vdev_obj, cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RESET_CFG:
            {
                    retv = ucfg_cfr_set_reset_bitmap(vap->vdev_obj, cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_UL_MU_USER_MASK:
            {
                    retv = ucfg_cfr_set_ul_mu_user_mask(vap->vdev_obj,
                                                        cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_FREEZE_TLV_DELAY_CNT:
            {
                    retv = ucfg_cfr_set_freeze_tlv_delay_cnt(vap->vdev_obj,
                                                             cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_DISABLE_ALL:
            {
                    retv = ucfg_cfr_set_rcc_mode(vap->vdev_obj,
                                                 RCC_DIS_ALL_MODE, 0);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_CAPT_COUNT:
            {
                    retv = ucfg_cfr_set_capture_count(vap->vdev_obj,
                                                      cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_CAPT_INTVAL_MODE_SEL:
            {
                    retv = ucfg_cfr_set_capture_interval_mode_sel(vap->vdev_obj,
                                                                  cfr_params);
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_RCC_COMMIT:
            {
                if (ic->ic_mon_vap &&
                    (wlan_vdev_mlme_is_active(ic->ic_mon_vap->vdev_obj) ==
                     QDF_STATUS_SUCCESS)) {
                    cfr_err("Block RCC since Monitor VAP is present");
                    return QDF_STATUS_E_NOSUPPORT;
                }
                if (ucfg_cfr_get_rcc_enabled(vap->vdev_obj)) {
                    wlan_set_param(vap, IEEE80211_CONFIG_CFR_RCC,
                                   rcc_filter_enable);
                } else {
                    wlan_set_param(vap, IEEE80211_CONFIG_CFR_RCC,
                                   rcc_filter_disable);
                }

                retv = ucfg_cfr_committed_rcc_config(vap->vdev_obj);
                if (retv != QDF_STATUS_SUCCESS) {
                    wlan_set_param(vap, IEEE80211_CONFIG_CFR_RCC,
                                   rcc_filter_failure);
                }
            }
            break;

        case IEEE80211_WLANCONFIG_CFR_GET_CFG:
            {
                    retv = ucfg_cfr_get_cfg(vap->vdev_obj);
            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_DBG_COUNTERS:
            {
                    retv = ucfg_cfr_rcc_dump_dbg_counters(vap->vdev_obj);
            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_CLR_COUNTERS:
            {
                    retv = ucfg_cfr_rcc_clr_dbg_counters(vap->vdev_obj);
            }
            break;
        case IEEE80211_WLANCONFIG_CFR_RCC_DUMP_LUT:
            {
                    retv = ucfg_cfr_rcc_dump_lut(vap->vdev_obj);
            }
            break;
#endif

        default:
            cfr_err("Invalid CFR command: %d \n", config->cmdtype);
            return -EIO;
    }
    return retv;
}
#endif

int
ieee80211_ucfg_rtt_params(struct ieee80211com *ic, wlan_if_t vap,
                          struct ieee80211_wlanconfig *config)
{
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;

    switch (config->cmdtype) {
        case IEEE80211_WLANCONFIG_LCR:
            if (!vap->lcr_enable) {
                qdf_err("enable_lcr command is disabled");
                return -1;
            }

            config->data.lcr_config.req_id = ic->ic_rtt_req_id;
            ic->ic_rtt_req_id++;

            return ic->ic_send_lcr_cmd(pdev, &config->data.lcr_config);
        case IEEE80211_WLANCONFIG_LCI:
            if (!vap->lci_enable) {
                qdf_err("enable_lci command is disabled");
                return -1;
            }

            config->data.lci_config.req_id = ic->ic_rtt_req_id;
            ic->ic_rtt_req_id++;

            return ic->ic_send_lci_cmd(pdev, &config->data.lci_config);
        case IEEE80211_WLANCONFIG_FTMRR:
            if (!(vap->rtt_enable & RTT_RESPONDER_MODE)) {
                qdf_err("Responder mode is disabled in enable_rtt command");
                return -1;
            }
            return ieee80211_send_ftmrr_frame(pdev, &config->data.ftmrr_config);
        default:
            qdf_err("Invalid RTT command : %d", config->cmdtype);
            return -EIO;
    }
}

int
ieee80211_ucfg_nawds(wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
	struct ieee80211_wlanconfig_nawds *nawds;
	nawds = &config->data.nawds;
	switch (config->cmdtype) {
		case IEEE80211_WLANCONFIG_NAWDS_SET_MODE:
			return wlan_nawds_set_param(vap, IEEE80211_NAWDS_PARAM_MODE, &nawds->mode);
		case IEEE80211_WLANCONFIG_NAWDS_SET_DEFCAPS:
			return wlan_nawds_set_param(vap, IEEE80211_NAWDS_PARAM_DEFCAPS, &nawds->defcaps);
		case IEEE80211_WLANCONFIG_NAWDS_SET_OVERRIDE:
			return wlan_nawds_set_param(vap, IEEE80211_NAWDS_PARAM_OVERRIDE, &nawds->override);
		case IEEE80211_WLANCONFIG_NAWDS_SET_ADDR:
			{
				int status;
				status = wlan_nawds_config_mac(vap, nawds->mac, nawds->caps);
				if( status == 0 ) {
					OS_SLEEP(250000);
				}
				return status;
			}
		case IEEE80211_WLANCONFIG_NAWDS_KEY:
			memcpy(vap->iv_nawds.psk, nawds->psk, strlen(nawds->psk));
			if (is_null_mac(nawds->mac)) {
				qdf_info("mac is NULL, psk set for learning RE\n");
				return 0;
			}
			return wlan_nawds_config_key(vap, nawds->mac, nawds->psk);
		case IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR:
			return wlan_nawds_delete_mac(vap, nawds->mac);
		case IEEE80211_WLANCONFIG_NAWDS_GET:
			wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_MODE, &nawds->mode);
			wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_DEFCAPS, &nawds->defcaps);
			wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_OVERRIDE, &nawds->override);
			if (wlan_nawds_get_mac(vap, nawds->num, &nawds->mac[0], &nawds->caps)) {
				qdf_print("failed to get NAWDS entry %d", nawds->num);
			}
			wlan_nawds_get_param(vap, IEEE80211_NAWDS_PARAM_NUM, &nawds->num);
			config->status = IEEE80211_WLANCONFIG_OK;
			break;
		default :
			return -EIO;
	}
	return 0;
}

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
int
ieee80211_ucfg_me_list(wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
	struct ieee80211_wlanconfig_me_list *me_list;
	ol_txrx_soc_handle soc = NULL;
	struct wlan_objmgr_pdev *pdev = NULL;
	u_int8_t ret;
	u_int8_t pdev_id;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        struct ieee80211com *ic = vap->iv_ic;
#endif

	pdev = wlan_vdev_get_pdev(vap->vdev_obj);
	soc = wlan_psoc_get_dp_handle(wlan_pdev_get_psoc(pdev));
	pdev_id = wlan_objmgr_pdev_get_pdev_id(pdev);
	me_list = &(config->data.me_list);
	switch (config->cmdtype) {
		case IEEE80211_WLANCONFIG_ME_LIST_ADD:
			if (me_list->me_list_type == IEEE80211_HMMC_LIST) {
				ret = dp_add_hmmc(soc, pdev_id, me_list->ip, me_list->mask);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
				if (!ret && ic->nss_vops) {
					ic->nss_vops->ic_osif_nss_vdev_me_add_hmmc_member((osif_dev *)vap->iv_ifp,
											  me_list->ip,
											  me_list->mask);
				}
#endif
			} else {
				ret = dp_add_deny_list(soc, pdev_id, me_list->ip, me_list->mask);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                                if (!ret && ic->nss_vops) {
					ic->nss_vops->ic_osif_nss_vdev_me_add_deny_member((osif_dev *)vap->iv_ifp,
											  me_list->ip,
											  me_list->mask);
                                }
#endif
			}
			break;
		case IEEE80211_WLANCONFIG_ME_LIST_DEL:
			if (me_list->me_list_type == IEEE80211_HMMC_LIST) {
				ret = dp_del_hmmc(soc, pdev_id, me_list->ip, me_list->mask);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
				if (!ret && ic->nss_vops) {
					ic->nss_vops->ic_osif_nss_vdev_me_del_hmmc_member((osif_dev *)vap->iv_ifp,
											  me_list->ip,
											  me_list->mask);
				}
#endif
			} else {
				ret = dp_del_deny_list(soc, pdev_id, me_list->ip, me_list->mask);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                                if (!ret && ic->nss_vops) {
					ic->nss_vops->ic_osif_nss_vdev_me_del_deny_member((osif_dev *)vap->iv_ifp, me_list->ip, me_list->mask);
                                }
#endif
			}
			break;
		case IEEE80211_WLANCONFIG_ME_LIST_DUMP:
			if (me_list->me_list_type == IEEE80211_HMMC_LIST)
				ret = dp_hmmc_dump(soc, pdev_id);
			else
				ret = dp_deny_list_dump(soc, pdev_id);
			break;
		default:
			ret = -EOPNOTSUPP;
	}

	return 0;
}
#endif
int
ieee80211_ucfg_ald(wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
    struct ieee80211_wlanconfig_ald *config_ald;
#if QCA_SUPPORT_SON
    u_int8_t ret = 0;
#endif
    config_ald = &(config->data.ald);
    switch (config->cmdtype) {
#if QCA_SUPPORT_SON
        case IEEE80211_WLANCONFIG_ALD_STA_ENABLE:
            ret = son_ald_sta_enable(vap->vdev_obj, config_ald->data.ald_sta.macaddr, config_ald->data.ald_sta.enable);
            break;
#endif
        default:
            OS_FREE(config);
            return -ENXIO;
    }

    return 0;
}
int
ieee80211_ucfg_hmwds(wlan_if_t vap, struct ieee80211_wlanconfig *config, int buffer_len)
{
    struct ieee80211_wlanconfig_hmwds *hmwds;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
    struct ieee80211_wlanconfig_wds_table *wds_table;
#endif
    int ret = 0;
    hmwds = &(config->data.hmwds);
    switch (config->cmdtype) {
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        case IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR:
            ret = wlan_hmwds_add_addr(vap, hmwds->wds_ni_macaddr, hmwds->wds_macaddr, hmwds->wds_macaddr_cnt);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_RESET_ADDR:
            ret = wlan_hmwds_reset_addr(vap, hmwds->wds_ni_macaddr);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE:
            ret = wlan_hmwds_reset_table(vap);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_READ_ADDR:
            hmwds->wds_macaddr_cnt = buffer_len - sizeof (*config);
            ret = wlan_hmwds_read_addr(vap, hmwds->wds_ni_macaddr, hmwds->wds_macaddr, &hmwds->wds_macaddr_cnt);
            if (ret)
                hmwds->wds_macaddr_cnt = 0;
            break;
        case IEEE80211_WLANCONFIG_HMWDS_READ_TABLE:
            wds_table = &config->data.wds_table;
            wds_table->wds_entry_cnt = buffer_len - sizeof (*config);
            ret = wlan_wds_read_table(vap, wds_table);
            if (ret)
                wds_table->wds_entry_cnt = 0;
            break;
        case IEEE80211_WLANCONFIG_HMWDS_SET_BRIDGE_ADDR:
            ret = wlan_hmwds_set_bridge_mac_addr(vap, hmwds->wds_macaddr);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR:
            ret = wlan_hmwds_remove_addr(vap, hmwds->wds_macaddr);
            break;
        case IEEE80211_WLANCONFIG_HMWDS_DUMP_WDS_ADDR:
            ret = wlan_wds_dump_wds_addr(vap);
            break;
#endif
        default:
            return -ENXIO;
    }
    return ret;
}

#if UMAC_SUPPORT_WNM
int
ieee80211_ucfg_wnm(wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
	struct ieee80211_wlanconfig_wnm *wnm;
	int status = 0;
	osif_dev *osifp = (osif_dev *)vap->iv_ifp;
	struct net_device *dev = osifp->netdev;

	if (!wlan_wnm_vap_is_set(vap))
		return -EFAULT;

	wnm = &(config->data.wnm);
	switch (config->cmdtype) {
		case IEEE80211_WLANCONFIG_WNM_SET_BSSMAX:
			status = wlan_wnm_set_bssmax(vap, &wnm->data.bssmax);
			if (status == 0) {
				status = IS_UP(dev) ? -osif_vap_init(dev, RESCAN) : 0;
			} else {
				return -EFAULT;
			}
			break;
		case IEEE80211_WLANCONFIG_WNM_GET_BSSMAX:
			status = wlan_wnm_get_bssmax(vap, &wnm->data.bssmax);
			config->status = (status == 0) ? IEEE80211_WLANCONFIG_OK : IEEE80211_WLANCONFIG_FAIL;
			break;
		case IEEE80211_WLANCONFIG_WNM_TFS_ADD:
			status = wlan_wnm_set_tfs(vap, &wnm->data.tfs);
			return status;

		case IEEE80211_WLANCONFIG_WNM_TFS_DELETE:
			/* since there is no tfs request elements its send the
			   TFS requestion action frame with NULL elements which
			   will delete the existing request on AP as per specification */
			status = wlan_wnm_set_tfs(vap, &wnm->data.tfs);
			return status;

		case IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY:
			status = wlan_wnm_set_fms(vap, &wnm->data.fms);
			return status;

		case IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST:
			status = wlan_wnm_set_timbcast(vap, &wnm->data.tim);
			return status;

		case IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST:
			status = wlan_wnm_get_timbcast(vap, &wnm->data.tim);
			config->status = (status == 0) ? IEEE80211_WLANCONFIG_OK : IEEE80211_WLANCONFIG_FAIL;
			break;

		case IEEE80211_WLANCONFIG_WNM_BSS_TERMINATION:

			/*
			 * For offload Architecture we have no way to get the MAC TSF as of now.
			 * Disabling this feature for offload untill we have a way to
			 * get the TSF.
			 */
			qdf_print("Disabled for Offload Architecture");
			return -EINVAL;

		default:
			break;
	}
	return 0;
}
#endif

int ieee80211_ucfg_addie(wlan_if_t vap, struct ieee80211_wlanconfig_ie *ie_buffer)
{
    int error = 0;

    switch (ie_buffer->ftype) {
        case IEEE80211_APPIE_FRAME_BEACON:
            wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_BEACON, (u_int8_t*)&ie_buffer->ie, ie_buffer->ie.len, ie_buffer->ie.elem_id);
            break;
        case IEEE80211_APPIE_FRAME_PROBE_RESP:
            wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_PROBERESP, (u_int8_t*)&ie_buffer->ie, ie_buffer->ie.len, ie_buffer->ie.elem_id);
            break;
        case IEEE80211_APPIE_FRAME_ASSOC_RESP:
            wlan_mlme_app_ie_set_check(vap, IEEE80211_FRAME_TYPE_ASSOCRESP, (u_int8_t*)&ie_buffer->ie, ie_buffer->ie.len, ie_buffer->ie.elem_id);
            break;
        default:
            QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR, "Frame type not supported\n");
            error = -ENXIO;
    }

    return error;
}

#if ATH_SUPPORT_DYNAMIC_VENDOR_IE
int
ieee80211_ucfg_vendorie(wlan_if_t vap, struct ieee80211_wlanconfig_vendorie *vie)
{
	int error;
	switch (vie->cmdtype) {
		case IEEE80211_WLANCONFIG_VENDOR_IE_ADD:
			error = wlan_set_vendorie(vap, IEEE80211_VENDOR_IE_PARAM_ADD, vie);
			break;

		case IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE:
			error = wlan_set_vendorie(vap, IEEE80211_VENDOR_IE_PARAM_UPDATE, vie);
			break;

		case IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE:
			error = wlan_set_vendorie(vap, IEEE80211_VENDOR_IE_PARAM_REMOVE, vie);
			break;

		default:
			error = -ENXIO;
	}
	return error;
}
#endif
#if ATH_SUPPORT_NAC_RSSI
int
ieee80211_ucfg_nac_rssi(wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
    struct ieee80211_wlanconfig_nac_rssi *nac_rssi;
    nac_rssi = &(config->data.nac_rssi);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"%s:cmd_type=%d BSSID:%2x:%2x:%2x:%2x:%2x:%2x, "
        "client:%2x:%2x:%2x:%2x:%2x:%2x channel: %d\n", __func__,
         config->cmdtype, nac_rssi->mac_bssid[0], nac_rssi->mac_bssid[1],
         nac_rssi->mac_bssid[2], nac_rssi->mac_bssid[3], nac_rssi->mac_bssid[4],
         nac_rssi->mac_bssid[5], nac_rssi->mac_client[0], nac_rssi->mac_client[1],
         nac_rssi->mac_client[2], nac_rssi->mac_client[3], nac_rssi->mac_client[4],
         nac_rssi->mac_client[5], nac_rssi->chan_num);

    switch (config->cmdtype) {
        case IEEE80211_WLANCONFIG_NAC_RSSI_ADDR_ADD:
            return wlan_set_nac_rssi(vap, IEEE80211_NAC_RSSI_PARAM_ADD, nac_rssi);

        case IEEE80211_WLANCONFIG_NAC_RSSI_ADDR_DEL:
            return wlan_set_nac_rssi(vap, IEEE80211_NAC_RSSI_PARAM_DEL, nac_rssi);

        case IEEE80211_WLANCONFIG_NAC_RSSI_ADDR_LIST:
            return wlan_list_nac_rssi(vap, IEEE80211_NAC_RSSI_PARAM_LIST, nac_rssi);

        default:
            return -ENXIO;
   }
}

#endif
#if ATH_SUPPORT_NAC
int
ieee80211_ucfg_nac(wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
	struct ieee80211_wlanconfig_nac *nac;
	nac = &(config->data.nac);

	switch (config->cmdtype) {
		case IEEE80211_WLANCONFIG_NAC_ADDR_ADD:
			return wlan_set_nac(vap, IEEE80211_NAC_PARAM_ADD, nac);

		case IEEE80211_WLANCONFIG_NAC_ADDR_DEL:
			return wlan_set_nac(vap, IEEE80211_NAC_PARAM_DEL, nac);

		case IEEE80211_WLANCONFIG_NAC_ADDR_LIST:
			wlan_list_nac(vap, IEEE80211_NAC_PARAM_LIST, nac);
			break;

		default:
			return -ENXIO;
	}
	return 0;

}
#endif

#if QCA_SUPPORT_PEER_ISOLATION
int
ieee80211_ucfg_isolation(wlan_if_t vap, struct ieee80211_wlanconfig *config)
{
    struct ieee80211_wlanconfig_isolation *isolation = &(config->data.isolation);
    struct ieee80211_wlanconfig_isolation_list *list;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL, "cmd_type=%d mac:%pM\n",
                      config->cmdtype, isolation->mac);

    switch (config->cmdtype) {
        case IEEE80211_WLANCONFIG_PEER_ISOLATION_ADDR_ADD:
            return wlan_peer_isolation_add_mac(vap, isolation);

        case IEEE80211_WLANCONFIG_PEER_ISOLATION_ADDR_DEL:
            return wlan_peer_isolation_del_mac(vap, isolation);

        case IEEE80211_WLANCONFIG_PEER_ISOLATION_ADDR_LIST:
            list = (struct ieee80211_wlanconfig_isolation_list *)(config + 1);
            return wlan_peer_isolation_list(vap, list);

        case IEEE80211_WLANCONFIG_PEER_ISOLATION_FLUSH_LIST:
            return wlan_peer_isolation_flush(vap);

        case IEEE80211_WLANCONFIG_PEER_ISOLATION_NUM_CLIENT:
            list = (struct ieee80211_wlanconfig_isolation_list *)(config + 1);
            list->mac_cnt = vap->peer_isolation_list.num_peers;
            return 0;

        default:
            return -ENXIO;
   }
}
#endif

int ieee80211_ucfg_scanlist(wlan_if_t vap)
{
	int retv = 0;
	osif_dev *osifp = (osif_dev *)vap->iv_ifp;
	struct scan_start_request *scan_params = NULL;
	int time_elapsed = OS_SIWSCAN_TIMEOUT;
	bool scan_pause;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	struct wlan_objmgr_vdev *vdev = NULL;

	vdev = osifp->ctrl_vdev;
	status = wlan_objmgr_vdev_try_get_ref(vdev, WLAN_OSIF_SCAN_ID);
	if (QDF_IS_STATUS_ERROR(status)) {
		scan_info("unable to get reference");
		return -EBUSY;
	}
	/* Increase timeout value for EIR since a rpt scan itself takes 12 seconds */
	if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic))
		time_elapsed = OS_SIWSCAN_TIMEOUT * SIWSCAN_TIME_ENH_IND_RPT;
	scan_pause =  (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) ?(vap->iv_pause_scan  ) : 0;
	/* start a scan */
	if ((time_after(OS_GET_TICKS(), osifp->os_last_siwscan + time_elapsed))
			&& (osifp->os_giwscan_count == 0) &&
			(vap->iv_opmode == IEEE80211_M_STA)&& !scan_pause) {
		if (ieee80211_ic_enh_ind_rpt_is_set(vap->iv_ic)) {
			scan_params = qdf_mem_malloc(sizeof(*scan_params));
			if (!scan_params) {
				wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
				return -ENOMEM;
			}
			status = wlan_update_scan_params(vap, scan_params, wlan_vap_get_opmode(vap), true, true, true, true, 0, NULL, 0);
			if (status) {
				wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
				scan_err("scan param init failed with status: %d", status);
				qdf_mem_free(scan_params);
				return -EINVAL;
			}
			scan_params->scan_req.scan_f_forced = true;
			scan_params->scan_req.min_rest_time = MIN_REST_TIME;
			scan_params->scan_req.max_rest_time = MAX_REST_TIME;
			scan_params->scan_req.dwell_time_active = MAX_DWELL_TIME_ACTIVE;
			osifp->os_last_siwscan = OS_GET_TICKS();

			status = wlan_ucfg_scan_start(vap, scan_params, osifp->scan_requestor,
					SCAN_PRIORITY_LOW, &(osifp->scan_id), 0, NULL);
			if (status) {
				scan_err("scan_start failed with status: %d", status);
			}
		}
	}

	wlan_objmgr_vdev_release_ref(vdev, WLAN_OSIF_SCAN_ID);
	osifp->os_giwscan_count = 0;
	return retv;
}

size_t
scan_space(wlan_scan_entry_t se, u_int16_t *ielen)
{
	u_int8_t ssid_len;
	uint8_t ssid_ie_len = 0;

	*ielen = 0;
	ssid_len = util_scan_entry_ssid(se)->length;
	*ielen =  util_scan_entry_ie_len(se);
	if (util_scan_entry_is_hidden_ap(se) && ssid_len) {
		ssid_ie_len = ssid_len + (sizeof(uint8_t) * 2);
	}
	return roundup(sizeof(struct ieee80211req_scan_result) +
			*ielen +  ssid_len + ssid_ie_len, sizeof(u_int32_t));
}

QDF_STATUS
get_scan_space(void *arg, wlan_scan_entry_t se)
{
	struct scanreq *req = arg;
	u_int16_t ielen;

	req->space += scan_space(se, &ielen);
	return 0;
}

QDF_STATUS
get_scan_space_rep_move(void *arg, wlan_scan_entry_t se)
{
	struct scanreq *req = arg;
	struct ieee80211vap *vap = req->vap;
	u_int16_t ielen;
	u_int8_t *ssid;
	u_int8_t ssid_len;
	u_int8_t *bssid;

	ssid_len = util_scan_entry_ssid(se)->length;
	ssid = util_scan_entry_ssid(se)->ssid;
	bssid = util_scan_entry_bssid(se);

	/* Calculate scan space only for those scan entries that match
	 * the SSID of the new Root AP
	 */
	if (ssid) {
	    if (!(strncmp(ssid, vap->iv_ic->ic_repeater_move.ssid.ssid,
	                  vap->iv_ic->ic_repeater_move.ssid.len))) {
		if(IEEE80211_ADDR_IS_VALID(vap->iv_ic->ic_repeater_move.bssid)) {
		    if (IEEE80211_ADDR_EQ(bssid, vap->iv_ic->ic_repeater_move.bssid)) {
		        req->space += scan_space(se, &ielen);
		    }
		} else {
	            req->space += scan_space(se, &ielen);
	        }
	    }
	}

	return 0;
}

QDF_STATUS
get_scan_result(void *arg, wlan_scan_entry_t se)
{
	struct scanreq *req = arg;
	struct ieee80211req_scan_result *sr;
	u_int16_t ielen, len, nr, nxr;
	u_int8_t *cp;
	u_int8_t ssid_len;
        struct ieee80211vap *vap = req->vap;
        bool des_ssid_found = 0;
	u_int8_t *rates, *ssid, *bssid;

	len = scan_space(se, &ielen);
	if (len > req->space)
		return 0;

	sr = req->sr;
	memset(sr, 0, sizeof(*sr));
	ssid_len = util_scan_entry_ssid(se)->length;
	ssid = util_scan_entry_ssid(se)->ssid;
	bssid = util_scan_entry_bssid(se);
	sr->isr_ssid_len = ssid_len;

        if (req->scanreq_type == SCANREQ_GIVE_ONLY_DESSIRED_SSID) {
            des_ssid_found = ieee80211_vap_match_ssid(vap->iv_ic->ic_sta_vap, ssid, ssid_len);
            if (!des_ssid_found) {
                return 0;
            } else {
                qdf_print("Getting desired ssid from scan result");
            }
        }
        if (req->scanreq_type == SCANREQ_GIVE_EXCEPT_DESSIRED_SSID) {
            des_ssid_found = ieee80211_vap_match_ssid(vap->iv_ic->ic_sta_vap, ssid, ssid_len);
            if (des_ssid_found) {
                return 0;
            }
        }

	if (vap->iv_ic->ic_repeater_move.state == REPEATER_MOVE_IN_PROGRESS) {
	    if (ssid == NULL)
	        return 0;

	    if (bssid == NULL)
	        return 0;

	    if ((strncmp(ssid, vap->iv_ic->ic_repeater_move.ssid.ssid,
	                 vap->iv_ic->ic_repeater_move.ssid.len)) != 0) {
	        return 0;
	    }

	    if(IEEE80211_ADDR_IS_VALID(vap->iv_ic->ic_repeater_move.bssid)) {
		if (!IEEE80211_ADDR_EQ(bssid, vap->iv_ic->ic_repeater_move.bssid))
		    return 0;
	    }
	}

	if (ielen > 65534 ) {
		ielen = 0;
	}
	sr->isr_ie_len = ielen;
	sr->isr_len = len;
	sr->isr_freq = wlan_channel_frequency(wlan_util_scan_entry_channel(se));
	sr->isr_flags = 0;
	sr->isr_rssi = util_scan_entry_snr(se);
	sr->isr_intval =  util_scan_entry_beacon_interval(se);
	sr->isr_capinfo = util_scan_entry_capinfo(se).value;
	sr->isr_erp =  util_scan_entry_erpinfo(se);
	IEEE80211_ADDR_COPY(sr->isr_bssid, util_scan_entry_bssid(se));
	rates = util_scan_entry_rates(se);
	nr = 0;
	if (rates) {
		nr = min((int)rates[1], IEEE80211_RATE_MAXSIZE);
		memcpy(sr->isr_rates, rates+2, nr);
	}

	rates = util_scan_entry_xrates(se);
	nxr=0;
	if (rates) {
		nxr = min((int)rates[1], IEEE80211_RATE_MAXSIZE - nr);
		memcpy(sr->isr_rates+nr, rates+2, nxr);
	}
	sr->isr_nrates = nr + nxr;

	cp = (u_int8_t *)(sr+1);
	if (ssid) {
		memcpy(cp,ssid, sr->isr_ssid_len);
	}
	cp += sr->isr_ssid_len;

	/* If AP is hidden, insert SSID IE at front of IE list */
	if (util_scan_entry_is_hidden_ap(se) && ssid_len) {
		*cp++ = WLAN_ELEMID_SSID;
		*cp++ = ssid_len;
		qdf_mem_copy(cp, ssid, ssid_len);
		cp += ssid_len;
	}

	if (ielen) {
		util_scan_entry_copy_ie_data(se,cp,&ielen);
		cp += ielen;
	}

	req->space -= len;
	req->sr = (struct ieee80211req_scan_result *)(((u_int8_t *)sr) + len);

	return 0;
}

void ieee80211_ucfg_setmaxrate_per_client(void *arg, wlan_node_t node)
{
	struct ieee80211_wlanconfig_setmaxrate *smr =
		(struct ieee80211_wlanconfig_setmaxrate *)arg;
	struct ieee80211_node *ni = node;
	struct ieee80211com *ic = ni->ni_ic;
	int i, rate_updated = 0;

	if (IEEE80211_ADDR_EQ(ni->ni_macaddr, smr->mac)) {
		ni->ni_maxrate = smr->maxrate;
		if (ni->ni_maxrate == 0xff) {
			ni->ni_rates.rs_nrates = ni->ni_maxrate_legacy;
			ni->ni_htrates.rs_nrates = ni->ni_maxrate_ht;
			/* set the default vht max rate info */
			ni->ni_maxrate_vht = 0xff;
			rate_updated = 1;
			goto end;
		}
		/* legacy rate */
		if (!(ni->ni_maxrate & 0x80)) {

			/* For VHT/HT capable station, do not allow user to set legacy rate as max rate */
			if ((ni->ni_vhtcap) || (ni->ni_htcap))
				return;

			for (i = 0; i < ni->ni_rates.rs_nrates; i++) {
				if ((ni->ni_maxrate & IEEE80211_RATE_VAL)
						<= (ni->ni_rates.rs_rates[i] & IEEE80211_RATE_VAL))
				{
					rate_updated = 1;
					ni->ni_rates.rs_nrates = i + 1;
					ni->ni_htrates.rs_nrates = 0;
					ni->ni_maxrate_vht = 0;
					break;
				}
			}
		}
		/* HT rate */
		else if (ni->ni_maxrate < 0xc0) {
			if (!ni->ni_htcap) {
				return;
			}
			/* For VHT capable station, do not allow user to set HT rate as max rate */
			if (ni->ni_vhtcap) {
				return;
			}
			for (i = 0; i < ni->ni_htrates.rs_nrates; i++) {
				if ((ni->ni_maxrate & 0x7f) <= ni->ni_htrates.rs_rates[i]) {
					rate_updated = 1;
					ni->ni_htrates.rs_nrates = i + 1;
					ni->ni_maxrate_vht = 0;
					break;
				}
			}
		}
		/* VHT rate */
		else if (ni->ni_maxrate >= 0xc0 && ni->ni_maxrate <= 0xf9) {
#define VHT_MAXRATE_IDX_MASK    0x0F
#define VHT_MAXRATE_IDX_SHIFT   4
			u_int8_t maxrate_vht_idx = (ni->ni_maxrate & VHT_MAXRATE_IDX_MASK) + 1;
			u_int8_t maxrate_vht_stream = (((ni->ni_maxrate & ~VHT_MAXRATE_IDX_MASK) - 0xc0)
					>> VHT_MAXRATE_IDX_SHIFT) + 1;
			if (!ni->ni_vhtcap)
				return;
			/* b0-b3: vht rate idx; b4-b7: # stream */
			ni->ni_maxrate_vht = (maxrate_vht_stream << VHT_MAXRATE_IDX_SHIFT) | maxrate_vht_idx;
			rate_updated = 1;
#undef VHT_MAXRATE_IDX_MASK
#undef VHT_MAXRATE_IDX_SHIFT
		}
		else {
			qdf_print("Unknown max rate 0x%x", ni->ni_maxrate);
			return;
		}

end:
		/* Calling ath_net80211_rate_node_update() for Updating the node rate */
		if (rate_updated) {
			ni->ni_set_max_rate = 1;
			ic->ic_rate_node_update(ni, 0);
		}

		if (ni->ni_maxrate == 0xff) {
			qdf_print("rateset initialized to negotiated rates");
		}
	}
}

int ieee80211_ucfg_set_peer_nexthop(void *osif, uint8_t *mac, int32_t if_num)
{
    int retv = 0;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (ic->nss_vops) {
        ic->nss_vops->ic_osif_nss_vdev_set_peer_next_hop(osifp, mac, if_num);
        retv = 1;
    }

    return retv;
#else
    qdf_print("Setting peer nexthop is only supported in NSS Offload mode");
    return retv;
#endif
}

int ieee80211_ucfg_set_vlan_type(void *osif, uint8_t default_vlan, uint8_t port_vlan)
{
    int retv = 0;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (ic->nss_vops) {
        ic->nss_vops->ic_osif_nss_vdev_set_vlan_type(osifp, default_vlan, port_vlan);
        retv = 1;
    }

#endif
    return retv;
}

/*
 * ieee80211_ucfg_set_hlos_tid_override()
 *  This API set the config to enable/disable hlos tid override
 */
int ieee80211_ucfg_set_hlos_tid_override(void *osif, uint8_t val, bool is_mscs)
{
    cdp_config_param_type buf = {0};
    osif_dev *osifp = (osif_dev *)osif;
    struct wlan_objmgr_psoc *psoc = NULL;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic) {
        return -1;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc) {
        return -1;
    }

    /*
     * Enable/disable hlos tid override in flag in dp vdev
     * Hlos tid override supported in both STA and AP vap for EasyMesh
     * Hlos tid override supported in only AP vap for MSCS
     */
    if ((wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP) && is_mscs) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,"Valid only when VAP in AP mode and MSCS enabled\n");
        return 1;
    }

    /*
     * Hlos tid override is valid for AP VAP
     */
    buf.cdp_vdev_param_hlos_tid_override = val;
    if (cdp_txrx_set_vdev_param(wlan_psoc_get_dp_handle(psoc),
            wlan_vdev_get_id(vap->vdev_obj), CDP_ENABLE_HLOS_TID_OVERRIDE,
            buf) != QDF_STATUS_SUCCESS) {
        return 1;

    }

   /*
    * Enable/disable hlos tid override in NSS FW
    */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (ic->nss_vops) {
        ic->nss_vops->ic_osif_nss_vdev_set_cfg(osifp, OSIF_NSS_WIFI_VDEV_ENABLE_HLOS_TID_OVERRIDE);
    }
#endif

    return 0;
}

/*
 * ieee80211_ucfg_get_hlos_tid_override()
 *  This API gets hlos tid override config
 */
int ieee80211_ucfg_get_hlos_tid_override(void *osif)
{
    cdp_config_param_type buf = {0};
    osif_dev *osifp = (osif_dev *)osif;
    struct wlan_objmgr_psoc *psoc = NULL;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic) {
        return -1;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    if (!psoc) {
        return -1;
    }

    /*
     * Enable/disable hlos tid override in flag in dp vdev
     */
    if (wlan_vap_get_opmode(vap) == IEEE80211_M_HOSTAP) {
        cdp_txrx_get_vdev_param(wlan_psoc_get_dp_handle(psoc),
            wlan_vdev_get_id(vap->vdev_obj), CDP_ENABLE_HLOS_TID_OVERRIDE,
            &buf);
    }

    return buf.cdp_vdev_param_hlos_tid_override;
}

/*
 * ieee80211_ucfg_set_vap_mesh_tid()
 *  This API mesh latency tid in vap
 */
int ieee80211_ucfg_set_vap_mesh_tid(void *osif, uint8_t val)
{
    cdp_config_param_type buf = {0};
    osif_dev *osifp = (osif_dev *)osif;
    struct wlan_objmgr_psoc *psoc = NULL;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic) {
        return -1;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc) {
        return -1;
    }

    buf.cdp_vdev_param_mesh_tid = val;
    if (cdp_txrx_set_vdev_param(wlan_psoc_get_dp_handle(psoc),
        wlan_vdev_get_id(vap->vdev_obj), CDP_SET_VAP_MESH_TID,
        buf) != QDF_STATUS_SUCCESS) {
        return 1;
    }
    return 0;
}

/*
 * ieee80211_ucfg_get_vap_mesh_tid()
 *  This API gets vap mesh tid
 */
int ieee80211_ucfg_get_vap_mesh_tid(void *osif,
    uint8_t *tid, uint8_t *dl_ul_enable)
{
    cdp_config_param_type buf = {0};
    osif_dev *osifp = (osif_dev *)osif;
    struct wlan_objmgr_psoc *psoc = NULL;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic) {
        return -1;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    if (!psoc) {
        return -1;
    }

    cdp_txrx_get_vdev_param(wlan_psoc_get_dp_handle(psoc),
        wlan_vdev_get_id(vap->vdev_obj), CDP_SET_VAP_MESH_TID,
        &buf);
    *tid = (buf.cdp_vdev_param_mesh_tid >> 4) & 0xF;
    *dl_ul_enable = buf.cdp_vdev_param_mesh_tid & 0xF;
    return 0;
}

/*
 * ieee80211_ucfg_set_peer_tid_latency_enable()
 *  This API set the config to enable/disable peer tid latency
 */
int ieee80211_ucfg_set_peer_tid_latency_enable(void *osif, uint8_t val)
{
    cdp_config_param_type buf = {0};
    osif_dev *osifp = (osif_dev *)osif;
    struct wlan_objmgr_psoc *psoc = NULL;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic) {
        return -1;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc) {
        return -1;
    }

    buf.cdp_vdev_param_peer_tid_latency_enable = val;
    if (cdp_txrx_set_vdev_param(wlan_psoc_get_dp_handle(psoc),
        wlan_vdev_get_id(vap->vdev_obj), CDP_ENABLE_PEER_TID_LATENCY,
        buf) != QDF_STATUS_SUCCESS) {
        return 1;

    }
    return 0;
}

/*
 * ieee80211_ucfg_get_peer_tid_latency_enable()
 *  This API gets peer tid latency
 */
int ieee80211_ucfg_get_peer_tid_latency_enable(void *osif)
{
    cdp_config_param_type buf = {0};
    osif_dev *osifp = (osif_dev *)osif;
    struct wlan_objmgr_psoc *psoc = NULL;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic) {
        return -1;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    if (!psoc) {
        return -1;
    }

    cdp_txrx_get_vdev_param(wlan_psoc_get_dp_handle(psoc),
        wlan_vdev_get_id(vap->vdev_obj), CDP_ENABLE_PEER_TID_LATENCY,
        &buf);

    return buf.cdp_vdev_param_peer_tid_latency_enable;
}

int ieee80211_ucfg_setwmmparams(void *osif, int wmmparam, int ac, int bss, int value)
{
    int retv = 0;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
#if defined (QCA_NSS_WIFI_OFFLOAD_SUPPORT) && defined (UMAC_VOW_DEBUG)
    struct ieee80211com *ic = vap->iv_ic;
#endif

    switch (wmmparam)
    {
        case IEEE80211_WMMPARAMS_CWMIN:
            if (value < 0 ||  value > 15) {
                retv = -EINVAL;
            } else if (value > ieee80211_ucfg_getwmmparams(
                                     osif, IEEE80211_WMMPARAMS_CWMAX, ac, bss)) {
                qdf_info("CWMIN can't be greater than CWMAX.");
                retv = -EINVAL;
            }
            else {
                retv = wlan_set_wmm_param(vap, WLAN_WME_CWMIN,
                        bss, ac, value);
            }
            break;
        case IEEE80211_WMMPARAMS_CWMAX:
            if (value < 0 ||  value > 15) {
                retv = -EINVAL;
            } else if (value < ieee80211_ucfg_getwmmparams(
                                     osif, IEEE80211_WMMPARAMS_CWMIN, ac, bss)) {
                qdf_info("CWMAX can't be lesser than CWMIN.");
                retv = -EINVAL;
            }
            else {
                retv = wlan_set_wmm_param(vap, WLAN_WME_CWMAX,
                        bss, ac, value);
            }
            break;
        case IEEE80211_WMMPARAMS_AIFS:
            if (value < 0 ||  value > 15) {
                retv = -EINVAL;
            }
            else {
                retv = wlan_set_wmm_param(vap, WLAN_WME_AIFS,
                        bss, ac, value);
            }
            break;
        case IEEE80211_WMMPARAMS_TXOPLIMIT:
            if (value < 0 ||  value > (8192 >> 5)) {
                retv = -EINVAL;
            }
            else {
                retv = wlan_set_wmm_param(vap, WLAN_WME_TXOPLIMIT,
                        bss, ac, value);
            }
            break;
        case IEEE80211_WMMPARAMS_ACM:
            if (value < 0 ||  value > 1) {
                retv = -EINVAL;
            }
            else {
                retv = wlan_set_wmm_param(vap, WLAN_WME_ACM,
                        bss, ac, value);
            }
            break;
        case IEEE80211_WMMPARAMS_NOACKPOLICY:
            if (value < 0 ||  value > 1) {
                retv = -EINVAL;
            }
            else {
                retv = wlan_set_wmm_param(vap, WLAN_WME_ACKPOLICY,
                        bss, ac, value);
            }
            break;
#if UMAC_VOW_DEBUG
        case IEEE80211_PARAM_VOW_DBG_CFG:
            {
                if(ac >= MAX_VOW_CLIENTS_DBG_MONITOR ) {
                    qdf_print("Invalid Parameter: Acceptable index range [0 - %d]",
                            MAX_VOW_CLIENTS_DBG_MONITOR-1);
                    retv = -EINVAL;
                } else {
                    osifp->tx_dbg_vow_peer[ac][0] = bss;
                    osifp->tx_dbg_vow_peer[ac][1] = value;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                    if (osifp->nss_wifiol_ctx && ic->nss_vops) {
                        ic->nss_vops->ic_osif_nss_vdev_vow_dbg_cfg(osifp, ac);
                    }
#endif
                }
            }
            break;
#endif

        default:
            return retv;
    }
    /* Reinitialise the vaps to update the wme params during runtime configuration  */
    if (!bss && retv == EOK) {
        retv = IS_UP(osifp->netdev) ? osif_vap_init(osifp->netdev,0) : 0;
    }
    /*
     * As we are not doing VAP reinit in case of (bss & retv == EOK),
     * we need to update beacon template
     */
    if (bss && retv == EOK) {

        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            vap->iv_mbss.non_tx_profile_change = true;
            vap->iv_mbss.mbssid_update_ie = true;
        }

        wlan_vdev_beacon_update(vap);
    }
    return retv;
}


int ieee80211_ucfg_getwmmparams(void *osif, int wmmparam, int ac, int bss)
{
    int value = 0;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;

    switch (wmmparam)
    {
        case IEEE80211_WMMPARAMS_CWMIN:
            value = wlan_get_wmm_param(vap, WLAN_WME_CWMIN,
                    bss, ac);
            break;
        case IEEE80211_WMMPARAMS_CWMAX:
            value = wlan_get_wmm_param(vap, WLAN_WME_CWMAX,
                    bss, ac);
            break;
        case IEEE80211_WMMPARAMS_AIFS:
            value = wlan_get_wmm_param(vap, WLAN_WME_AIFS,
                    bss, ac);
            break;
        case IEEE80211_WMMPARAMS_TXOPLIMIT:
            value = wlan_get_wmm_param(vap, WLAN_WME_TXOPLIMIT,
                    bss, ac);
            break;
        case IEEE80211_WMMPARAMS_ACM:
            value = wlan_get_wmm_param(vap, WLAN_WME_ACM,
                    bss, ac);
            break;
        case IEEE80211_WMMPARAMS_NOACKPOLICY:
            value = wlan_get_wmm_param(vap, WLAN_WME_ACKPOLICY,
                    bss, ac);
            break;
        default:
            value = -EINVAL;
            break;
    }

    return value;

}

int ieee80211_ucfg_set_muedcaparams(void *osif, uint8_t muedcaparam,
        uint8_t ac, uint8_t value)
{

    int ret = 0;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;

    /* Check for the lower and upper bounds for paramID */
    if((muedcaparam < IEEE80211_MUEDCAPARAMS_ECWMIN) &&
            (muedcaparam > IEEE80211_MUEDCAPARAMS_TIMER)) {
        qdf_print("%s: paramID should be between %d-%d.",
                __func__, IEEE80211_MUEDCAPARAMS_ECWMIN,
                IEEE80211_MUEDCAPARAMS_TIMER);
        ret = -EINVAL;
    }

    /* Check for the lower and upper bounds for AC */
    if(ac >= MUEDCA_NUM_AC) {
        qdf_print("%s: AC should be less than %d.",
                __func__, MUEDCA_NUM_AC);
        ret = -EINVAL;
    }

    switch (muedcaparam)
    {

        case IEEE80211_MUEDCAPARAMS_ECWMIN:
            if(value > MUEDCA_ECW_MAX) {
                qdf_print("%s: ECWMIN should be less than %d.",
                        __func__, MUEDCA_ECW_MAX);
                ret =  -EINVAL;
            }
            else {
                ret = wlan_set_muedca_param(vap, WLAN_MUEDCA_ECWMIN,
                        ac, value);
            }
            break;

        case IEEE80211_MUEDCAPARAMS_ECWMAX:
            if(value > MUEDCA_ECW_MAX) {
                qdf_print("%s: ECWMAX should be less than equal %d.",
                        __func__, MUEDCA_ECW_MAX);
                ret =  -EINVAL;
            }
            else {
                ret = wlan_set_muedca_param(vap, WLAN_MUEDCA_ECWMAX,
                        ac, value);
            }
            break;

        case IEEE80211_MUEDCAPARAMS_AIFSN:
            if(value > MUEDCA_AIFSN_MAX) {
                qdf_print("%s: AIFSN should less than equal to %d.",
                        __func__, MUEDCA_AIFSN_MAX);
                ret =  -EINVAL;
            }
            else {
                ret = wlan_set_muedca_param(vap, WLAN_MUEDCA_AIFSN,
                        ac, value);
            }
            break;

        /* ACM value set to 1 signifies admission control is enabled,
         * while a value of 0 signifies admission control is disabled for
         * the corresponding AC. */
        case IEEE80211_MUEDCAPARAMS_ACM:
            if(value > 1) {
                qdf_print("%s:ACM value should be 0 or 1.", __func__);
                ret =  -EINVAL;
            }
            else {
                ret = wlan_set_muedca_param(vap, WLAN_MUEDCA_ACM,
                        ac, value);
            }
            break;

        case IEEE80211_MUEDCAPARAMS_TIMER:
            if(value > MUEDCA_TIMER_MAX) {
                qdf_print("%s:Timer value should be less than equal to %d.",
                        __func__, MUEDCA_TIMER_MAX);
                ret =  -EINVAL;
            }
            else {
                ret = wlan_set_muedca_param(vap, WLAN_MUEDCA_TIMER,
                        ac, value);
            }
            break;

        default:
            ret = -EINVAL;
            break;

    }

    if(vap->iv_he_muedca == IEEE80211_MUEDCA_STATE_ENABLE) {
        if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
            vap->iv_mbss.mbssid_update_ie = true;
            vap->iv_mbss.non_tx_profile_change = true;
        }
        wlan_vdev_beacon_update(vap);
    }

    return ret;
}

int ieee80211_ucfg_get_muedcaparams(void *osif, uint8_t muedcaparam, uint8_t ac)
{
    int value = 0;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;

    /* Check for the lower and upper bounds for paramID */
    if((muedcaparam < IEEE80211_MUEDCAPARAMS_ECWMIN) &&
            (muedcaparam > IEEE80211_MUEDCAPARAMS_TIMER)) {
        qdf_print("%s: paramID should be between %d-%d.",
                __func__, IEEE80211_MUEDCAPARAMS_ECWMIN,
                IEEE80211_MUEDCAPARAMS_TIMER);
        value = -EINVAL;
    }

    /* Check for the lower and upper bounds for AC */
    if(ac >= MUEDCA_NUM_AC) {
        qdf_print("%s: AC should be less than %d.",
                __func__, MUEDCA_NUM_AC);
        value = -EINVAL;
    }

    switch (muedcaparam)
    {

        case IEEE80211_MUEDCAPARAMS_ECWMIN:
            value = wlan_get_muedca_param(vap, WLAN_MUEDCA_ECWMIN, ac);
            break;

        case IEEE80211_MUEDCAPARAMS_ECWMAX:
            value = wlan_get_muedca_param(vap, WLAN_MUEDCA_ECWMAX, ac);
            break;

        case IEEE80211_MUEDCAPARAMS_AIFSN:
            value = wlan_get_muedca_param(vap, WLAN_MUEDCA_AIFSN, ac);
            break;

        case IEEE80211_MUEDCAPARAMS_ACM:
            value = wlan_get_muedca_param(vap, WLAN_MUEDCA_ACM, ac);
            break;

        case IEEE80211_MUEDCAPARAMS_TIMER:
            value = wlan_get_muedca_param(vap, WLAN_MUEDCA_TIMER, ac);
            break;

        default:
            value = -EINVAL;
            break;
    }

    return value;

}

static void
domlme(void *arg, wlan_node_t node)
{
    struct mlmeop *op = (struct mlmeop *)arg;

    switch (op->mlme->im_op) {

        case IEEE80211_MLME_DISASSOC:
            ieee80211_try_mark_node_for_delayed_cleanup(node);
            wlan_mlme_disassoc_request(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason);
            break;
        case IEEE80211_MLME_DEAUTH:
            IEEE80211_DPRINTF(op->vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, domlme deauth reason %d\n",
                    __func__, ether_sprintf(wlan_node_getmacaddr(node)), op->mlme->im_reason);
            ieee80211_try_mark_node_for_delayed_cleanup(node);
            wlan_mlme_deauth_request(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason);
            break;
        case IEEE80211_MLME_ASSOC:
            wlan_mlme_assoc_resp(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason, 0, NULL);
            break;
        case IEEE80211_MLME_REASSOC:
            wlan_mlme_assoc_resp(op->vap,wlan_node_getmacaddr(node),op->mlme->im_reason, 1, NULL);
            break;
        default:
            break;
    }
}

int
ieee80211_ucfg_setmlme(struct ieee80211com *ic, void *osif, struct ieee80211req_mlme *mlme)
{
    struct ieee80211_app_ie_t optie;
    osif_dev *osifp = (osif_dev *)osif;
    wlan_if_t vap = osifp->os_if;
    struct ieee80211vap *tempvap = NULL;
    struct ieee80211_node *ni = NULL;

    if ((vap == NULL) || (ic == NULL) ) {
        return -EINVAL;
    }

    optie.ie = &mlme->im_optie[0];
    optie.length = mlme->im_optie_len;

    switch (mlme->im_op) {
        case IEEE80211_MLME_ASSOC:
            /* set dessired bssid when in STA mode accordingly */
            if (wlan_vap_get_opmode(vap) != IEEE80211_M_STA &&
                    osifp->os_opmode != IEEE80211_M_P2P_DEVICE &&
                    osifp->os_opmode != IEEE80211_M_P2P_CLIENT) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_IOCTL,
                        "[%s] non sta mode, skip to set bssid\n", __func__);
            } else {
                u_int8_t des_bssid[QDF_MAC_ADDR_SIZE];

                if (!IS_NULL_ADDR(mlme->im_macaddr)) {
                    /*If AP mac to which our sta vap is trying to connect has
                    same mac as one of our ap vaps ,dont set that as sta bssid */
                    TAILQ_FOREACH(tempvap, &ic->ic_vaps, iv_next) {
                        if (tempvap->iv_opmode == IEEE80211_M_HOSTAP && IEEE80211_ADDR_EQ(tempvap->iv_myaddr,mlme->im_macaddr)) {
                                qdf_print("[%s] Mac collision for [%s]",__func__,ether_sprintf(mlme->im_macaddr));
                                return -EINVAL;
                        }
                    }
                    IEEE80211_ADDR_COPY(des_bssid, &mlme->im_macaddr[0]);
                    wlan_aplist_set_desired_bssidlist(vap, 1, &des_bssid);
                    qdf_print("[%s] set desired bssid %02x:%02x:%02x:%02x:%02x:%02x",__func__,des_bssid[0],
                            des_bssid[1],des_bssid[2],des_bssid[3],des_bssid[4],des_bssid[5]);
                }
            }

            if (osifp->os_opmode == IEEE80211_M_STA ||
                    (u_int8_t)osifp->os_opmode == IEEE80211_M_P2P_GO ||
                    (u_int8_t)osifp->os_opmode == IEEE80211_M_P2P_CLIENT ||
                    osifp->os_opmode == IEEE80211_M_IBSS) {
                vap->iv_mlmeconnect=1;
#if UMAC_SUPPORT_WPA3_STA
                if (wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_AUTH_MODE)
                                          & (uint32_t)((1 << WLAN_CRYPTO_AUTH_SAE))) {
                   vap->iv_sta_external_auth_enabled = true;
                   osifp->app_filter |= IEEE80211_FILTER_TYPE_AUTH;
                } else {
                   vap->iv_sta_external_auth_enabled = false;
                }
#endif
                osif_vap_init(osifp->netdev, 0);
            }
            else if (osifp->os_opmode ==  IEEE80211_M_HOSTAP) {
                /* NB: the broadcast address means do 'em all */
                if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
                ni = ieee80211_vap_find_node(vap, mlme->im_macaddr, WLAN_MLME_SB_ID);
                if (ni == NULL)
                    return -EINVAL;
                else
                    ic = ni->ni_ic;
                if (ieee80211_is_pmf_enabled(vap, ni)
                        && vap->iv_opmode == IEEE80211_M_HOSTAP
                        && (vap->iv_skip_pmf_reassoc_to_hostap > 0)
                        && (ni->ni_flags & IEEE80211_NODE_AUTH)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "[%s] drop assoc resp for pmf client from hostapd\n",
                        __func__);
                } else {
                    wlan_mlme_assoc_resp(vap,mlme->im_macaddr,mlme->im_reason, 0, &optie);
                }
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                } else {
                    struct mlmeop iter_arg;
                    iter_arg.mlme = mlme;
                    iter_arg.vap = vap;
                    wlan_iterate_station_list(vap,domlme,&iter_arg);
                }
            }
            else
                return -EINVAL;
            break;
        case IEEE80211_MLME_REASSOC:
            if (osifp->os_opmode == IEEE80211_M_STA ||
                    osifp->os_opmode == IEEE80211_M_P2P_GO ||
                    osifp->os_opmode == IEEE80211_M_P2P_CLIENT) {
                osif_vap_init(osifp->netdev, 0);
            }
            else if (osifp->os_opmode ==  IEEE80211_M_HOSTAP) {
                /* NB: the broadcast address means do 'em all */
                if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
                ni = ieee80211_vap_find_node(vap, mlme->im_macaddr, WLAN_MLME_SB_ID);
                if (ni == NULL)
                    return -EINVAL;
                else
                    ic = ni->ni_ic;
                if(ieee80211_is_pmf_enabled(vap, ni) &&
                        vap->iv_opmode == IEEE80211_M_HOSTAP &&
                        (vap->iv_skip_pmf_reassoc_to_hostap > 0) &&
                        (ni->ni_flags & IEEE80211_NODE_AUTH))
                {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_ASSOC,
                        "[%s] drop assoc resp for pmf client from hostapd\n",
                        __func__);
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                    return 1; /* drop assoc resp for pmf client from hostapd */
                }
                    wlan_mlme_assoc_resp(vap,mlme->im_macaddr,mlme->im_reason, 1, &optie);
                    ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                } else {
                    struct mlmeop iter_arg;
                    iter_arg.mlme = mlme;
                    iter_arg.vap = vap;
                    wlan_iterate_station_list(vap,domlme,&iter_arg);
                }
            }
            else
                return -EINVAL;
            break;
        case IEEE80211_MLME_AUTH_FILS:
        case IEEE80211_MLME_AUTH:
            if (osifp->os_opmode != IEEE80211_M_HOSTAP) {
                return -EINVAL;
            }
            /* NB: ignore the broadcast address */
            if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
#if WLAN_SUPPORT_FILS
                if(mlme->im_op == IEEE80211_MLME_AUTH_FILS && wlan_fils_is_enable(vap->vdev_obj)) {
                    IEEE80211_DPRINTF(vap, IEEE80211_MSG_FILS,
                                "%s op : 0x%x ie.len : %d mac %s\n",
                                __func__, mlme->im_op, optie.length,
                                ether_sprintf(mlme->im_macaddr));
                    if (wlan_mlme_auth_fils(vap->vdev_obj, &mlme->fils_aad, mlme->im_macaddr)) {
                        qdf_print("%s: FILS crypto registration failed", __func__);
                    } else {
                        qdf_print("%s: FILS crypto registered successfully", __func__);
                    }
                }
#endif
                wlan_mlme_auth(vap,mlme->im_macaddr,mlme->im_seq,mlme->im_reason, NULL, 0, &optie);
            }
            break;
        case IEEE80211_MLME_DISASSOC:
        case IEEE80211_MLME_DEAUTH:
            switch (osifp->os_opmode) {
                case IEEE80211_M_STA:
                case IEEE80211_M_P2P_CLIENT:
                    //    if (mlme->im_op == IEEE80211_MLME_DISASSOC && !osifp->is_p2p_interface) {
                    //        return -EINVAL; /*fixme darwin does this, but linux did not before? */
                    //    }

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
                    if(wlan_mlme_is_stacac_running(vap)) {
                        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Do not stop the BSS STA CAC is on\n");
                        return -EINVAL;
                    } else {
                        osif_vap_stop(osifp->netdev);
                    }
#else
                    osif_vap_stop(osifp->netdev);
#endif
                    break;
                case IEEE80211_M_HOSTAP:
                case IEEE80211_M_IBSS:
                    if (ic){
                        /*No need to put  any check for Broadcast as for braodcast ni == NULL */
                        if (IEEE80211_ADDR_EQ(mlme->im_macaddr, vap->iv_myaddr)) {
                            qdf_print("Cannot send Disassoc to self ");
                            return -EINVAL;
                        }
                        ni = ieee80211_vap_find_node(vap, mlme->im_macaddr, WLAN_MLME_SB_ID);
                        if (ni) {
                            /* If DA is non_bss unicast address, mark this node
                             * delayed node cleanup candidate.
                             */
                            ieee80211_try_mark_node_for_delayed_cleanup(ni);
                            /* claim node immediately */
                            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                        }
                    }
                    /* the 'break' statement for this case is intentionally removed, to make sure that this fall through next statement */
                case IEEE80211_M_P2P_GO:
                    /* NB: the broadcast address means do 'em all */
                    if (!IEEE80211_ADDR_EQ(mlme->im_macaddr, ieee80211broadcastaddr)) {
                        if (mlme->im_op == IEEE80211_MLME_DEAUTH) {
                            wlan_mlme_deauth_request(vap,mlme->im_macaddr,mlme->im_reason);
                        }
                        if (mlme->im_op == IEEE80211_MLME_DISASSOC) {
                            wlan_mlme_disassoc_request(vap,mlme->im_macaddr,mlme->im_reason);
                        }
                    } else {
                        if (wlan_vap_is_pmf_enabled(vap)) {
                            if (mlme->im_op == IEEE80211_MLME_DEAUTH) {
                                IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH, "%s: sending DEAUTH to %s, mlme deauth reason %d\n",
                                        __func__, ether_sprintf(mlme->im_macaddr), mlme->im_reason);
                                wlan_mlme_deauth_request(vap,mlme->im_macaddr,mlme->im_reason);
                            }
                            if (mlme->im_op == IEEE80211_MLME_DISASSOC) {
                                wlan_mlme_disassoc_request(vap,mlme->im_macaddr,mlme->im_reason);
                            }
                        } else {
                            struct mlmeop iter_arg;
                            iter_arg.mlme = mlme;
                            iter_arg.vap = vap;
                            wlan_iterate_station_list(vap,domlme,&iter_arg);
                        }
                    }
                    break;
                default:
                    return -EINVAL;
            }
            break;
        case IEEE80211_MLME_AUTHORIZE:
        case IEEE80211_MLME_UNAUTHORIZE:
            if (osifp->os_opmode != IEEE80211_M_HOSTAP &&
                    osifp->os_opmode != IEEE80211_M_STA &&
                    osifp->os_opmode != IEEE80211_M_P2P_GO) {
                return -EINVAL;
            }
            if (mlme->im_op == IEEE80211_MLME_AUTHORIZE) {
                wlan_node_authorize(vap, 1, mlme->im_macaddr);
            } else {
                wlan_node_authorize(vap, 0, mlme->im_macaddr);
            }
            break;
        case IEEE80211_MLME_CLEAR_STATS:
#ifdef notyet

            if (vap->iv_opmode != IEEE80211_M_HOSTAP)
                return -EINVAL;
            ni = ieee80211_find_node(ic, mlme->im_macaddr, WLAN_MLME_SB_ID);
            if (ni == NULL)
                return -ENOENT;

            /* clear statistics */
            if (cdp_host_reset_peer_stats(wlan_pdev_get_psoc(ic->ic_pdev_obj),
                                      wlan_objmgr_pdev_get_pdev_id(ic->ic_pdev_obj)) != QDF_STATUS_SUCCESS) {
                ieee80211_free_node(ni, WLAN_MLME_SB_ID);
                return -EINVAL;
            }

            ieee80211_free_node(ni, WLAN_MLME_SB_ID);
#endif
            break;

        case IEEE80211_MLME_STOP_BSS:
#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
            if(wlan_mlme_is_stacac_running(vap)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "Do not stop the BSS STA CAC is on\n");
                return -EINVAL;
            } else {
                osif_vap_stop(osifp->netdev);
            }
#else
            osif_vap_stop(osifp->netdev);
#endif
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

#if QCA_SUPPORT_GPR
int ieee80211_ucfg_send_gprparams(wlan_if_t vap, uint8_t command)
{
    struct ieee80211com *ic = vap->iv_ic;
    int retv = -EINVAL;
#if UMAC_SUPPORT_ACFG
    acfg_netlink_pvt_t *acfg_nl;

    if ( !ic || !ic->ic_acfg_handle ) {
        return -EINVAL;
    }
    acfg_nl = (acfg_netlink_pvt_t *)ic->ic_acfg_handle;

    /* Give access to only one app on one radio */
    if(qdf_semaphore_acquire_intr(acfg_nl->sem_lock)){
        /*failed to acquire mutex*/
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_ANY,
                 "%s(): failed to acquire mutex!\n", __func__);
        return -EAGAIN;
    }
#endif

    switch (command)
    {
        case IEEE80211_GPR_DISABLE:
            if (ic->ic_gpr_enable) {
                if (vap->iv_opmode == IEEE80211_M_HOSTAP ) {
                    if (vap->iv_gpr_enable == 1) {
                        vap->iv_gpr_enable = 0;
                        ic->ic_gpr_enable_count--;
                    } else {
                        qdf_err("GPR already stopped on this vap or not started yet !\n");
                    }
                    if (ic->ic_gpr_enable_count == 0) {
                        qdf_hrtimer_kill(&ic->ic_gpr_timer);
                        qdf_mem_free(ic->acfg_frame);
                        ic->acfg_frame = NULL;
                        ic->ic_gpr_enable = 0;
                        qdf_err("\nStopping GPR timer as this is last vap with gpr \n");
                    }
                    retv = EOK;
                } else {
                    qdf_err("Invalid! Allowed only in HOSTAP mode\n");
                }
            } else {
                qdf_err("GPR not started on any of vap, start GPR first \n");
            }
            break;
        case IEEE80211_GPR_ENABLE:
            if (ic->ic_gpr_enable) {
                if (vap->iv_opmode == IEEE80211_M_HOSTAP ) {
                    if (vap->iv_gpr_enable == 0) {
                        vap->iv_gpr_enable = 1;
                        ic->ic_gpr_enable_count++;
                        retv = EOK;
                    } else {
                        qdf_err("GPR already started on this vap \n");
                    }
                } else {
                    qdf_err("Invalid! Allowed only in HOSTAP mode\n");
                }
            } else {
                qdf_err("GPR not started on any of vap, start GPR first \n");
            }
            break;
        case IEEE80211_GPR_PRINT_STATS:
            if (ic->ic_gpr_enable) {
                qdf_hrtimer_data_t *gpr_hrtimer = &ic->ic_gpr_timer;
                qdf_err("Timer STATS for GPR \n");
                if (vap->iv_opmode == IEEE80211_M_HOSTAP ) {
                    qdf_err("------------------------------------\n");
                    qdf_err("| GPR on this vap enabled    - %d   |\n", vap->iv_gpr_enable);
                    qdf_err("| GPR on radio enabled       - %d   |\n", ic->ic_gpr_enable);
                    qdf_err("| GPR state                  - %s   |\n",
                            (qdf_hrtimer_active(&ic->ic_gpr_timer))?"Active":
                            "Dormant");
                    qdf_err("| GPR Minimum Period         - %d   |\n", DEFAULT_MIN_GRATITOUS_PROBE_RESP_PERIOD);
                    qdf_err("| Current Timestamp          - %lld |\n",
                            qdf_ktime_to_ns(qdf_ktime_get()));
                    qdf_err("| Timer expires in           - %lld |\n",
                            qdf_ktime_to_ns(qdf_ktime_add(qdf_ktime_get(),
                                     qdf_hrtimer_get_remaining(gpr_hrtimer))));
                    qdf_err("| GPR timer start count      - %u   |\n", ic->ic_gpr_timer_start_count);
                    qdf_err("| GPR timer resize count     - %u   |\n", ic->ic_gpr_timer_resize_count);
                    qdf_err("| GPR timer send count       - %u   |\n", ic->ic_gpr_send_count);
                    qdf_err("| GPR timer user period      - %u   |\n", ic->ic_period);
                    qdf_err("| GPR enabled vap count      - %u   |\n", ic->ic_gpr_enable_count);
                    qdf_err("------------------------------------\n");
                    retv = EOK;
                } else {
                    qdf_err("Invalid! Allowed only in HOSTAP mode\n");
                }
            } else {
                qdf_err("GPR not running on any of the Vaps\n");
            }
            break;
        case IEEE80211_GPR_CLEAR_STATS:
            if (ic->ic_gpr_enable) {
                qdf_err("%s %d Timer CLEAR STATS for GPR \n",__func__,__LINE__);
                ic->ic_gpr_timer_start_count  = 0;
                ic->ic_gpr_timer_resize_count = 0;
                ic->ic_gpr_send_count         = 0;
                retv = EOK;
            } else {
                qdf_err("GPR not running on any of the Vaps\n");
            }
            break;
        default:
            qdf_err("Invalid command type\n");
    }
#if UMAC_SUPPORT_ACFG
    qdf_semaphore_release(acfg_nl->sem_lock);
#endif
    return retv;
}
#endif

int ieee80211_ucfg_send_probereq(wlan_if_t vap, int val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211_node *ni = NULL;
    u_int8_t da[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    u_int8_t bssid[IEEE80211_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    int retval = EOK;

    if (val == 1) {
        if (vap->iv_opmode == IEEE80211_M_STA) {
            if ((ic->ic_strict_pscan_enable &&
                IEEE80211_IS_CHAN_PASSIVE(ic->ic_curchan))) {
                    qdf_err("strict passive scan enabled cant sent probe ignoring");
                    retval = -EINVAL;
            } else {
                ni = ieee80211_ref_bss_node(vap, WLAN_OSIF_SCAN_ID);
                if (ni) {
                    retval = ieee80211_send_probereq(ni, vap->iv_myaddr, da,
                                bssid, ni->ni_essid, ni->ni_esslen,
                                vap->iv_opt_ie.ie, vap->iv_opt_ie.length);

                    ieee80211_free_node(ni, WLAN_OSIF_SCAN_ID);
                }
            }
        } else {
            qdf_err("VAP is not STA");
            retval = -EINVAL;
        }
    } else {
        qdf_err("Value must be 1");
        retval = -EINVAL;
    }

    return retval;
}

struct ieee80211vap *ieee80211_ucfg_get_txvap(struct ieee80211com *ic)
{
    bool is_mbssid_enabled = false;

    if (!ic) {
        /* Invalid ic */
        return NULL;
    }

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE);

    if (!is_mbssid_enabled) {
        if (ic->ic_wideband_capable) {
            if (ic->ic_mbss.target_transmit_vap)
                return ic->ic_mbss.target_transmit_vap;
            else
                goto find_first_ap_vap;
        } else {
            return NULL;
        }
    } else {
        return ic->ic_mbss.transmit_vap;
    }

find_first_ap_vap:
    return ieee80211_mbss_get_first_ap_vap(ic, true);
}

int ieee80211_ucfg_set_txvap(wlan_if_t vap)
{
    struct ieee80211com *ic;

    if (!vap) {
        mbss_err("vap is NULL");
        return -1;
    }

    ic = vap->iv_ic;
    if (!ic) {
        mbss_err("ic is NULL");
        return -1;
    }

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        mbss_debug("VAP%d is not AP VAP", vap->iv_unit);
        return 0;
    }
    else {
        if (vap->iv_smart_monitor_vap ||  vap->iv_special_vap_mode) {
            mbss_err("VAP%d is either smart monitor %d or special vap %d, not configuring",
                     vap->iv_unit, vap->iv_smart_monitor_vap,
                     vap->iv_special_vap_mode);
            return 0;
        }
    }

    if (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        mbss_err("MBSSID is not enabled");
        return -1;
    }

    if (ic->ic_mbss.transmit_vap) {
        mbss_info("vap%d is already configured as Tx vap",
                 ic->ic_mbss.transmit_vap->iv_unit);
        return -1;
    }

    if (ieee80211_mbssid_txvap_set(vap)) {
        mbss_err("vap%d MBSSID Tx vap setup failed", vap->iv_unit);
        return -1;
    }

    wlan_cfg80211_mbssid_tx_vdev_notification(vap);

    return 0;
}

int ieee80211_ucfg_reset_txvap(wlan_if_t vap, uint8_t force)
{
    struct ieee80211com *ic;
    struct ieee80211vap *tmpvap = NULL;

    if (!vap) {
        mbss_err("vap is NULL");
        return -1;
    }

    ic = vap->iv_ic;
    if (!ic) {
        mbss_err("ic is NULL");
        return -1;
    }

    if (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        mbss_err("MBSSID is not enabled");
        return -1;
    }

    if (!ic->ic_mbss.transmit_vap) {
        mbss_err("No vap is configured as Tx vap");
        return -1;
    }

    /* This if block prevents user to reset Tx VDEV if any VDEV's dev->flags
     * marked as IFF_UP, this is skipped, if tx vdev change requested
     * internally
     */
    if (!force) {
         TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
             if (tmpvap->iv_opmode == IEEE80211_M_HOSTAP) {
                 struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
                 if (IS_UP(tmpdev)) {
                     mbss_err("VAP %d is in UP processing, can't reset Tx vap", tmpvap->iv_unit);
                     return -1;
                 }
             }
         }
    }

    if (ieee80211_mbssid_txvap_reset(vap)) {
        mbss_err("vap%d MBSSID Tx vap reset failed", vap->iv_unit);
        return -1;
    }

    /*
     * If successful and this VAP was the temp Tx VAP, then clear it
     * NOTE: This behavior is applicable to wideband radios only.
     */
    if (ic->ic_wideband_capable &&
        (ic->ic_mbss.target_transmit_vap == vap)) {
        ic->ic_mbss.target_transmit_vap = NULL;
    }

    return 0;
}

int ieee80211_ucfg_bringdown_txvap(wlan_if_t vap)
{
     struct ieee80211com *ic = vap->iv_ic;
     struct ieee80211vap *tmpvap = NULL;
     struct ieee80211vap *lastvap = NULL;
     int retval;
     uint8_t active_vap_cnt = 0;

    if (!ic) {
        mbss_err("ic is NULL");
        return -1;
    }

    if (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                            WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        mbss_debug("MBSSID is not enabled");
        return -1;
    }

    if (ic->ic_mbss.transmit_vap != vap) {
        mbss_debug("VAP %d is not configured as Tx vap", vap->iv_unit);
        return -1;
    }

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if ((tmpvap->iv_opmode == IEEE80211_M_HOSTAP) &&
            ((vap == tmpvap) || (IS_UP(tmpdev)))) {
            wlan_mlme_stop_vdev(tmpvap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE);

            if ((ic->ic_mbss.transmit_vap) &&
                (ic->ic_mbss.transmit_vap != tmpvap)) {
                 lastvap = tmpvap;
                 mbss_err("last vap id %d", lastvap->iv_unit);
            }

            active_vap_cnt++;

            /* If auto mode is not configured, clear netdev flag for non-Tx vap, and return */
            if ((IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(tmpvap) ||
                !ic->ic_mbss.skip_dev_close) &&
                (ieee80211_ic_mbss_automode_is_clear(ic)) && (IS_UP(tmpdev))) {
                dev_close(tmpdev);
            }
        }

    }

    if (ic->ic_mbss.skip_dev_close)
        ic->ic_mbss.skip_dev_close = 0;

    retval = wlan_pdev_wait_to_bringdown_all_vdevs(ic, ALL_AP_VDEVS);
    if (retval == QDF_STATUS_E_INVAL) {
        mbss_err("Bring down all AP VAP failed");
        return -1;
    }

    /*
     * The Tx-VAP params need to be restored in the return paths for fail cases
     * below
     */
    if (!ieee80211_ic_mbss_automode_is_clear(ic) && lastvap) {
        ieee80211_ucfg_copy_txvap_param(vap, lastvap);
    }

    if (ieee80211_ucfg_reset_txvap(vap, 1)) {
        mbss_err("Reset Tx VAP %d is failed", vap->iv_unit);
        return -1;
    }

    if ((active_vap_cnt == 1) && (vap == lastvap))
        return 0;

    if (ieee80211_ic_mbss_automode_is_clear(ic) || !lastvap)
        return 0;

    if (ic->ic_wifi_down_ind) {
        mbss_info(" wifi down ind is set, new Tx vdev config is skipped");
        return 0;
    }

    if (ieee80211_ucfg_set_txvap(lastvap)) {
        mbss_err("set Tx VAP %d is failed", lastvap->iv_unit);
        return -1;
    }

    ic->ic_ema_config_init(ic);

    /* Bringup all remaining vaps */
    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        struct net_device *tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if ((tmpvap->iv_opmode == IEEE80211_M_HOSTAP) && (tmpvap != vap)) {
             retval = IS_UP(tmpdev) ? osif_vap_init(tmpdev, RESCAN) : 0;
        }
    }

    return 0;
}

/**
 * ieee80211_ucfg_copy_txvap_param: Helper function to copy Tx VDEV dependent
 * params from previous Tx VDEV to new Tx VDEV
 * @last_txvap:: Previous Tx VDEV
 * @vap: New Tx VDEV
 *
 * Return: void
 */
void ieee80211_ucfg_copy_txvap_param(struct ieee80211vap *last_txvap,
                                     struct ieee80211vap *vap)
{
    uint32_t prb_rsp_en_period = 0;
#ifdef WLAN_SUPPORT_FILS
    uint32_t fils_enable = 0;
    uint32_t fils_period = 0;
    uint32_t fils_en_period = 0;
#endif
#ifdef WLAN_SUPPORT_FILS
      /* Copy FILS enable period */
     fils_enable = wlan_get_param(last_txvap, IEEE80211_FEATURE_FILS);
     if (fils_enable) {
          fils_period = wlan_fd_get_fd_period(last_txvap->vdev_obj);
          fils_en_period = ucfg_fd_get_enable_period(fils_enable, fils_period);
          wlan_set_param(vap, IEEE80211_FEATURE_FILS, fils_en_period);
     }
#endif
     /* Copy Probe response period */
     vap->iv_he_6g_bcast_prob_rsp = last_txvap->iv_he_6g_bcast_prob_rsp;
     vap->iv_he_6g_bcast_prob_rsp_intval = wlan_get_param(last_txvap,
                                          IEEE80211_CONFIG_6GHZ_BCAST_PROB_RSP);
     prb_rsp_en_period = ieee80211_get_prbrsp_en_period(
                                   vap->iv_he_6g_bcast_prob_rsp,
                                   vap->iv_he_6g_bcast_prob_rsp_intval);
     if (prb_rsp_en_period) {
         /* Send a template to FW if bcast probe response is to be enabled */
         wlan_set_param(vap, IEEE80211_CONFIG_6GHZ_BCAST_PROB_RSP,
                        prb_rsp_en_period);
     }

}

int ieee80211_ucfg_reset_mesh_nawds_txvap(wlan_if_t vap)
{
    struct ieee80211com *ic;
    struct ieee80211vap *tx_vap;
    struct ieee80211_nawds *nawds;
    struct net_device *tx_dev;

    if (!vap) {
        mbss_err("vap is NULL");
        return -1;
    }

    ic = vap->iv_ic;
    if (!ic) {
        mbss_err("ic is NULL");
        return -1;
    }

    if (!wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        mbss_debug("MBSSID is not enabled");
        return -1;
    }

    tx_vap = ic->ic_mbss.transmit_vap;
    if (!tx_vap) {
        mbss_err("tx_vap is NULL");
        return -1;
    }

    nawds = &tx_vap->iv_nawds;
    tx_dev = ((osif_dev *)tx_vap->iv_ifp)->netdev;

    /* if vap's nawds mode is set to bridge or repeater (not DISABLED), OR
     * vap is configured as mesh, AND it is the first vap, then bring it down
     * and assign current (second) vap as tx vap. This avoids the scenario
     * of a non-beaconing tx vap since mesh/nawds vap can switch to
     * non-beaconing mode */
    if (IS_UP(tx_dev) &&
        (nawds->mode !=  IEEE80211_NAWDS_DISABLED
#if MESH_MODE_SUPPORT
        || tx_vap->iv_mesh_vap_mode
#endif
        ))
    {
        int ret;

        /* bring down the tx vap */
        ic->ic_mbss.skip_dev_close = 1;
        if (ieee80211_ucfg_bringdown_txvap(tx_vap))
            qdf_err("error with bringdown");

        /* set current vap as tx vap */
        ieee80211_ucfg_set_txvap(vap);

        /* bring up the previous mesh/nawds tx vap as a non-tx vap */
        ret = osif_vap_init(tx_dev, RESCAN);
        if (ret) {
            qdf_warn("Error starting %s, ret: %d!!", tx_dev->name, ret);
        }

        qdf_info("Done with bringing up mesh/nawds vap!");
    }

    return 0;

}
