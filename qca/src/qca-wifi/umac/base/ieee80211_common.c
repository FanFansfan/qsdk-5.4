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
 *
 */

#include <ieee80211_var.h>
#include <ieee80211_ucfg.h>
#include <ieee80211_channel.h>
#include <ieee80211_rateset.h>
#include <ieee80211_config.h>
#include <ieee80211_tsftimer.h>
#include <ieee80211_notify_tx_bcn.h>
#include <ieee80211P2P_api.h>
#include <ieee80211_wnm_proto.h>
#include <ieee80211_vi_dbg.h>
#include <ieee80211_bsscolor.h>
#include "ol_if_athvar.h"
#include "target_type.h"
#include <qdf_lock.h>
#include <ieee80211_mlme_dfs_dispatcher.h>
#include <wlan_objmgr_psoc_obj.h>
#include <wlan_objmgr_pdev_obj.h>
#include <wlan_mlme_dp_dispatcher.h>
#include <wlan_utility.h>
#ifdef QCA_SUPPORT_CP_STATS
#include <wlan_cp_stats_ic_utils_api.h>
#endif
#include <wlan_mlme_dispatcher.h>
#include <target_if.h>
#include <init_deinit_lmac.h>
#include <cfg_ucfg_api.h>
#include <wlan_vdev_mlme.h>
#include <include/wlan_psoc_mlme.h>
#include <wlan_objmgr_global_obj_i.h>
#include <wlan_mlme_if.h>
#include <wlan_reg_ucfg_api.h>
#include "ieee80211_crypto_nlshim_api.h"
#ifdef WLAN_SUPPORT_FILS
#include <wlan_fd_ucfg_api.h>
#endif /* WLAN_SUPPORT_FILS */

/* Support for runtime pktlog enable/disable */
unsigned int enable_pktlog_support = 1; /*Enable By Default*/
module_param(enable_pktlog_support, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(enable_pktlog_support,
        "Runtime pktlog enable/disable Support");

extern int acfg_attach(struct ieee80211com *ic);
extern void acfg_detach(struct ieee80211com *ic);
uint32_t acfg_event_workqueue_init(osdev_t osdev);

#if UMAC_SUPPORT_ACFG
extern int acfg_diag_attach(struct ieee80211com *ic);
extern int acfg_diag_detach(struct ieee80211com *ic);
#endif


int module_init_wlan(void);
void module_exit_wlan(void);


void print_vap_msg(struct ieee80211vap *vap, unsigned category, const char *fmt, ...)
{
     va_list ap;
     va_start(ap, fmt);
     if (vap) {
        asf_vprint_category(&vap->iv_print, category, fmt, ap);
     } else {
        qdf_vprint(fmt, ap);
     }
     va_end(ap);
}

void print_vap_verbose_msg(struct ieee80211vap *vap, unsigned verbose, unsigned category, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (vap) {
        asf_vprint(&vap->iv_print, category, verbose, fmt, args);
    } else {
        qdf_vprint(fmt, args);
    }
    va_end(args);
}

/**
* ASF print support function to print based on category for vap print control object
* @param vap - object of struct ieee80211vap in which asf print control object is declared
* @param category - category of the print message
*/
void IEEE80211_DPRINTF(struct ieee80211vap *vap, unsigned category, const char *fmt, ...)
{
     char                   tmp_buf[OS_TEMP_BUF_SIZE], *tmp;
     va_list                ap;
     struct ieee80211com    *ic = NULL;

     if ((vap) && ieee80211_msg(vap, category)) {
         ic = vap->iv_ic;
         tmp = tmp_buf + snprintf(tmp_buf,OS_TEMP_BUF_SIZE, "[%s] vap-%d(%s):",
                             msg_type_to_str(category), vap->iv_unit, vap->iv_netdev_name);
#if DBG_LVL_MAC_FILTERING
        if (!vap->iv_print.dbgLVLmac_on) {
#endif
             va_start(ap, fmt);
             vsnprintf (tmp,(OS_TEMP_BUF_SIZE - (tmp - tmp_buf)), fmt, ap);
             va_end(ap);
             print_vap_msg(vap, category, (const char *)tmp_buf, ap);
             ic->ic_log_text(ic,tmp_buf);
             OS_LOG_DBGPRINT("%s\n", tmp_buf);
#if DBG_LVL_MAC_FILTERING
        }
#endif
    }

}


/**
* ASF print support function to print based on category for vap print control object
* @param vap - object of struct ieee80211vap in which asf print control object is declared
* @param verbose - verbose level of the print message
* @param category - category of the print message
*/
void IEEE80211_DPRINTF_VB(struct ieee80211vap *vap, unsigned verbose, unsigned category, const char *fmt, ...)
{
     char                   tmp_buf[OS_TEMP_BUF_SIZE], *tmp;
     va_list                ap;
     struct ieee80211com    *ic = NULL;

     if ((vap) && (verbose <= vap->iv_print.verb_threshold) && ieee80211_msg(vap, category)) {
         ic = vap->iv_ic;
         tmp = tmp_buf + snprintf(tmp_buf,OS_TEMP_BUF_SIZE, "[%s] vap-%d(%s):",
                             msg_type_to_str(category), vap->iv_unit, vap->iv_netdev_name);
         va_start(ap, fmt);
         vsnprintf (tmp,(OS_TEMP_BUF_SIZE - (tmp - tmp_buf)), fmt, ap);
         va_end(ap);
         print_vap_verbose_msg(vap, verbose, category, (const char *)tmp_buf, ap);
         ic->ic_log_text(ic,tmp_buf);
         OS_LOG_DBGPRINT("%s\n", tmp_buf);
    }

}

/**
* ASF print support function tp print based on category for ic print control object
* @param ic - object of struct ieee80211com in which asf print control object is declared
* @param category - category of the print message
*/
void IEEE80211_DPRINTF_IC_CATEGORY(struct ieee80211com *ic, unsigned category, const char *fmt, ...)
{
    va_list args;

    if ( (ic) && ieee80211_msg_ic(ic, category)) {
        va_start(args, fmt);
        if (ic) {
            asf_vprint_category(&ic->ic_print, category, fmt, args);
        } else {
            qdf_vprint(fmt, args);
        }
        va_end(args);
    }

}

/**
* ASF print support function tp print based on category and verbose for ic print control object
* @param ic - object of struct ieee80211com in which asf print control object is declared
* @param verbose - verbose level of the print message
* @param category - category of the print message
*/
void IEEE80211_DPRINTF_IC(struct ieee80211com *ic, unsigned verbose, unsigned category, const char *fmt, ...)
{
    va_list args;

    if ((ic) && (verbose <= ic->ic_print.verb_threshold) && ieee80211_msg_ic(ic, category)) {
        va_start(args, fmt);
        if (ic) {
            asf_vprint(&(ic)->ic_print, category, verbose, fmt, args);
        } else {
            qdf_vprint(fmt, args);
        }
        va_end(args);
    }

}

/*
 * With WEP and TKIP encryption algorithms:
 * Disable 11n if IEEE80211_FEXT_WEP_TKIP_HTRATE is not set.
 * Check for Mixed mode, if CIPHER is set to TKIP
 */
int ieee80211vap_htallowed(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    int phymode;
    /* Disable HT if WMM/wme is disabled */
    if (!ieee80211_vap_wme_is_set(vap)) {
        return 0;
    }

    if(vap->iv_is_up)
       phymode = vap->iv_cur_mode;
    else
       phymode = vap->iv_des_mode;

    switch (phymode) {
    case IEEE80211_MODE_11A:
    case IEEE80211_MODE_11B:
    case IEEE80211_MODE_11G:
    case IEEE80211_MODE_FH:
    case IEEE80211_MODE_TURBO_A:
    case IEEE80211_MODE_TURBO_G:
        return 0;
    default:
        break;
    }

    if (!ieee80211_ic_wep_tkip_htrate_is_set(ic) &&
        IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) &&
        is_weptkip_htallowed(vap, NULL))
        return 0;
    else if (vap->iv_opmode == IEEE80211_M_IBSS)
        return (ieee80211_ic_ht20Adhoc_is_set(ic) || ieee80211_ic_ht40Adhoc_is_set(ic));
    else
        return 1;
}

int ieee80211vap_vhtallowed(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    int phymode;
    /* Don't allow VHT if HT is not allowed */
    if (!ieee80211vap_htallowed(vap)){
        return 0;
    }

    if(vap->iv_is_up)
       phymode = vap->iv_cur_mode;
    else
       phymode = vap->iv_des_mode;

    /* Don't allow VHT if mode is HT only  */
    switch (phymode) {
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
            return 0;
        break;
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
       case IEEE80211_MODE_11AXG_HE20:
       case IEEE80211_MODE_11AXG_HE40PLUS:
       case IEEE80211_MODE_11AXG_HE40MINUS:
       case IEEE80211_MODE_11AXG_HE40:
             /*VHT is allowed in 2G if 256 QAM is supported */
           if(!ieee80211_vap_256qam_is_set(vap))
            return 0;

        default:
            break;
    }

    if (ic->ic_vhtcap) {
        return 1;
    }

    return 0;
}

int ieee80211vap_6g_heallowed(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    int phymode;

    if(vap->iv_is_up)
       phymode = vap->iv_cur_mode;
    else
       phymode = vap->iv_des_mode;

    switch (phymode) {
        case IEEE80211_MODE_AUTO:
        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AXA_HE80_80:
            if (IEEE80211_IS_HECAP_MACINFO(ic->ic_he.hecap_macinfo)) {
                return 1;
            }
            break;
        default:
            return 0;
    }

    return 0;
}

int ieee80211vap_heallowed(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    int phymode;
    qdf_freq_t low_freq = 0, high_freq = 0;
    struct wlan_objmgr_pdev *pdev;
    QDF_STATUS status;

    pdev = ic->ic_pdev_obj;

    status = wlan_reg_get_freq_range(pdev, NULL, NULL, &low_freq, &high_freq);
    if (status)
        return 0;

    if (wlan_reg_is_range_only6g(low_freq, high_freq)) {
       return ieee80211vap_6g_heallowed(vap);
    }
    /* Don't allow HE if VHT & HT is not allowed */
    if (!ieee80211vap_htallowed(vap)){
        return 0;
    }

    if(vap->iv_is_up)
       phymode = vap->iv_cur_mode;
    else
       phymode = vap->iv_des_mode;

    switch (phymode) {
        case IEEE80211_MODE_11AXA_HE20:
        case IEEE80211_MODE_11AXA_HE40PLUS:
        case IEEE80211_MODE_11AXA_HE40MINUS:
        case IEEE80211_MODE_11AXA_HE40:
        case IEEE80211_MODE_11AXA_HE80:
        case IEEE80211_MODE_11AXA_HE160:
        case IEEE80211_MODE_11AXA_HE80_80:
            if (!ieee80211vap_vhtallowed(vap)){
                return 0;
            }
            break;
        default:
            break;
    }


    switch (phymode) {
        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            return 0;
            break;

        default:
            break;
    }

    if (IEEE80211_IS_HECAP_MACINFO(ic->ic_he.hecap_macinfo)) {
        return 1;
    }

    return 0;
}

IEEE80211_IS_PHYMODE_DEF(auto, AUTO);
IEEE80211_IS_PHYMODE_DEF(11a, 11A);
IEEE80211_IS_PHYMODE_DEF(turbo_a, TURBO_A);
IEEE80211_IS_PHYMODE_DEF(11b, 11B);
IEEE80211_IS_PHYMODE_DEF(11g, 11G);
IEEE80211_IS_PHYMODE_DEF(11na_ht20, 11NA_HT20);
IEEE80211_IS_PHYMODE_DEF(11na_ht40, 11NA_HT40);
IEEE80211_IS_PHYMODE_DEF(11ng_ht20, 11NG_HT20);
IEEE80211_IS_PHYMODE_DEF(11ng_ht40, 11NG_HT40);
IEEE80211_IS_PHYMODE_DEF(11axa_he40, 11AXA_HE40);
IEEE80211_IS_PHYMODE_DEF(11ac_vht40, 11AC_VHT40);
IEEE80211_IS_PHYMODE_DEF(11axg_he40, 11AXG_HE40);
IEEE80211_IS_PHYMODE_DEF(11ac_vht40minus, 11AC_VHT40MINUS);
IEEE80211_IS_PHYMODE_DEF(11ac_vht40plus, 11AC_VHT40PLUS);
IEEE80211_IS_PHYMODE_DEF(11axa_he40plus, 11AXA_HE40PLUS);
IEEE80211_IS_PHYMODE_DEF(11axa_he40minus, 11AXA_HE40MINUS);
IEEE80211_IS_PHYMODE_DEF(11ac_vht80, 11AC_VHT80);
IEEE80211_IS_PHYMODE_DEF(11ac_vht160, 11AC_VHT160);
IEEE80211_IS_PHYMODE_DEF(11ac_vht80_80, 11AC_VHT80_80);
IEEE80211_IS_PHYMODE_DEF(11axa_he80, 11AXA_HE80);
IEEE80211_IS_PHYMODE_DEF(11axa_he160, 11AXA_HE160);
IEEE80211_IS_PHYMODE_DEF(11axa_he80_80, 11AXA_HE80_80);

bool ieee80211_is_phymode_not_basic(uint32_t  mode)
{
    if (mode >= IEEE80211_MODE_11NA_HT20 && mode <= IEEE80211_MODE_11AXA_HE80_80) {
        return true;
    }
    return false;
}
qdf_export_symbol(ieee80211_is_phymode_not_basic);

bool ieee80211_is_phymode_g40(uint32_t mode)
{
    if (mode == IEEE80211_MODE_11NG_HT40PLUS ||
        mode == IEEE80211_MODE_11NG_HT40MINUS ||
        mode == IEEE80211_MODE_11NG_HT40 ||
        mode == IEEE80211_MODE_11AXG_HE40PLUS ||
        mode == IEEE80211_MODE_11AXG_HE40MINUS ||
        mode == IEEE80211_MODE_11AXG_HE40) {
        return true;
     }

     return false;
}
qdf_export_symbol(ieee80211_is_phymode_g40);

bool ieee80211_is_phymode_40(uint32_t mode)
{
    if (mode == IEEE80211_MODE_11NG_HT40 ||
        mode == IEEE80211_MODE_11NA_HT40 ||
        mode == IEEE80211_MODE_11AC_VHT40 ||
        mode == IEEE80211_MODE_11AXA_HE40 ||
        mode == IEEE80211_MODE_11AXG_HE40) {
       return true;
    }
    return false;
}
qdf_export_symbol(ieee80211_is_phymode_40);

bool ieee80211_is_phymode_40plus(uint32_t mode)
{
    if (mode == IEEE80211_MODE_11AXA_HE40PLUS ||
        mode == IEEE80211_MODE_11AXG_HE40PLUS ||
        mode == IEEE80211_MODE_11AC_VHT40PLUS ||
        mode == IEEE80211_MODE_11NA_HT40PLUS ||
        mode == IEEE80211_MODE_11NG_HT40PLUS) {
        return true;
    }
    return false;
}
qdf_export_symbol(ieee80211_is_phymode_40plus);

bool ieee80211_is_phymode_40minus(uint32_t mode)
{

    if (mode == IEEE80211_MODE_11AXA_HE40MINUS ||
        mode == IEEE80211_MODE_11AXG_HE40MINUS ||
        mode == IEEE80211_MODE_11AC_VHT40MINUS ||
        mode == IEEE80211_MODE_11NA_HT40MINUS ||
        mode == IEEE80211_MODE_11NG_HT40MINUS) {
        return true;
    }
    return false;
}
qdf_export_symbol(ieee80211_is_phymode_40minus);

bool ieee80211_is_phymode_11ac_160or8080(uint32_t mode)
{
    if (ieee80211_is_phymode_11ac_vht160(mode) ||
        ieee80211_is_phymode_11ac_vht80_80(mode)) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_11ac_160or8080);

bool ieee80211_is_phymode_11axa_160or8080(uint32_t mode)
{
    if (ieee80211_is_phymode_11axa_he160(mode) ||
        ieee80211_is_phymode_11axa_he80_80(mode)) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_11axa_160or8080);

bool ieee80211_is_phymode_160(uint32_t mode)
{
    if (ieee80211_is_phymode_11ac_vht160(mode) ||
        ieee80211_is_phymode_11axa_he160(mode)) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_160);

bool ieee80211_is_phymode_80(uint32_t mode)
{
    if (ieee80211_is_phymode_11ac_vht80(mode) ||
        ieee80211_is_phymode_11axa_he80(mode)) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_80);

bool ieee80211_is_phymode_8080(uint32_t mode)
{
    if (ieee80211_is_phymode_11ac_vht80_80(mode) ||
        ieee80211_is_phymode_11axa_he80_80(mode)) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_8080);

bool ieee80211_is_phymode_160_or_8080(uint32_t mode)
{
    if (ieee80211_is_phymode_11ac_160or8080(mode) ||
        ieee80211_is_phymode_11axa_160or8080(mode)) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_160_or_8080);

bool ieee80211_is_phymode_11ax(uint32_t mode)
{
    if (mode >= IEEE80211_MODE_11AXA_HE20  &&
        mode <= IEEE80211_MODE_11AXA_HE80_80) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_11ax);

bool ieee80211_is_phymode_11ac(uint32_t mode)
{
    if (mode >= IEEE80211_MODE_11AC_VHT20  &&
        mode <= IEEE80211_MODE_11AC_VHT80_80) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_11ac);

bool ieee80211_is_phymode_11na(uint32_t mode)
{
   switch(mode) {
      case IEEE80211_MODE_11NA_HT20:
      case IEEE80211_MODE_11NA_HT40PLUS:
      case IEEE80211_MODE_11NA_HT40MINUS:
      case IEEE80211_MODE_11NA_HT40:
           return true;
      default:
           return false;
   }
   return false;
}
qdf_export_symbol(ieee80211_is_phymode_11na);

bool ieee80211_is_phymode_11ng(uint32_t mode)
{
   switch(mode) {
      case IEEE80211_MODE_11NG_HT20:
      case IEEE80211_MODE_11NG_HT40PLUS:
      case IEEE80211_MODE_11NG_HT40MINUS:
      case IEEE80211_MODE_11NG_HT40:
           return true;
      default:
           return false;
   }
   return false;
}
qdf_export_symbol(ieee80211_is_phymode_11ng);

bool ieee80211_is_phymode_valid(uint32_t mode)
{
    if (mode > IEEE80211_MODE_AUTO && mode < IEEE80211_MODE_MAX) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_valid);


bool ieee80211_is_phymode_allowed(uint32_t mode)
{
    if (ieee80211_is_phymode_auto(mode) ||
        ieee80211_is_phymode_valid(mode)) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_allowed);

bool ieee80211_is_phymode_equal_or_above_11axa_he40plus(uint32_t mode)
{
    if (mode >= IEEE80211_MODE_11AXA_HE40PLUS) {
        return true;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_equal_or_above_11axa_he40plus);

bool ieee80211_is_phymode_2g(uint32_t mode)
{
    switch (mode) {
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_FH:
        case IEEE80211_MODE_TURBO_G:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11AXG_HE20:
        case IEEE80211_MODE_11AXG_HE40PLUS:
        case IEEE80211_MODE_11AXG_HE40MINUS:
        case IEEE80211_MODE_11AXG_HE40:
                return true;
        default:
                return false;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_2g);

bool ieee80211_is_phymode_5g_or_6g(uint32_t mode)
{
    switch (mode) {
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
                return true;
        default:
                return false;
    }

    return false;
}
qdf_export_symbol(ieee80211_is_phymode_5g_or_6g);

static void ieee80211_vap_iter_mlme_inact_timeout(void *arg, struct ieee80211vap *vap)
{
    mlme_inact_timeout(vap);
}

void ieee80211_vap_mlme_inact_erp_timeout(struct ieee80211com *ic)
{
    wlan_iterate_vap_list(ic, ieee80211_vap_iter_mlme_inact_timeout, NULL);
}

int ieee80211_vap_update_wnm_bss_cap(struct ieee80211vap *vap, bool enable) {

    struct ieee80211com *ic = vap->iv_ic;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    struct vdev_mlme_inactivity_params *inact_params;
    int retv = 0;

    if(!ic) {
        qdf_err("IC is NULL");
        return -EINVAL;
    }

    if(!vdev_mlme) {
        qdf_err("Vdev MLME obj is NULL");
        return -EINVAL;
    }

    inact_params = &vdev_mlme->mgmt.inactivity_params;
    if(!inact_params) {
        qdf_err("Inactivity Params structure is NULL");
        return -EINVAL;
    }

    if(enable == 1 && (ieee80211_vap_wnm_is_set(vap) == 0)) {
        return -EINVAL;
    }
    if(ieee80211_wnm_bss_is_set(vap->wnm) == enable) {
        return -EINVAL;
    }

    if (enable == 0) {
        ic->ic_wnm_bss_count--;
        ieee80211_wnm_bss_clear(vap->wnm);
        if(ic->ic_wnm_bss_count == 0 && ic->ic_wnm_bss_active == 1) {
            if(ic->ic_opmode != IEEE80211_M_STA) {
                if (ic->ic_get_tgt_type(ic) < TARGET_TYPE_QCA8074) {
                    /* For pre-lithium targets, Max BSS Idle Timer
                     * is maintained in Host. Cancel the timer when
                     * the feature is disabled.
                     */
                    OS_CANCEL_TIMER(&ic->ic_bssload_timer);
                } else {
                    /* For lithium targets, update the Inactivity Timer WMIs
                     * with the saved inactivity timer values if MAx BSS
                     * Idle Time feature is being disabled.
                     */
                    retv = wlan_set_param(vap, IEEE80211_RUN_INACT_TIMEOUT,
                            inact_params->keepalive_max_unresponsive_time_secs);
                }
            }
            ic->ic_wnm_bss_active = 0;
        }
    } else {
        ieee80211_wnm_bss_set(vap->wnm);
        ic->ic_wnm_bss_count++;
        if(ic->ic_wnm_bss_active == 0) {
            if(ic->ic_opmode != IEEE80211_M_STA) {
                if (ic->ic_get_tgt_type(ic) < TARGET_TYPE_QCA8074) {
                    /* For pre-lithium targets, Max BSS Idle Timer
                     * is maintained in Host. Update the timer value when
                     * the feature is enabled.
                     */
                    OS_SET_TIMER(&ic->ic_bssload_timer, IEEE80211_BSSLOAD_WAIT);
                } else {
                    /* For lithium targets, update the Inactivity Timer WMIs
                     * with the BSS Idle period value when Max BSS Idle Time
                     * feature is enabled.
                     */
                    retv = wlan_set_param(vap, IEEE80211_RUN_INACT_TIMEOUT,
                                            vap->wnm->wnm_bss_max_idle_period);
                }
            }
            ic->ic_wnm_bss_active = 1;
        }
    }

    return retv;
}

static OS_TIMER_FUNC(ic_cw_timeout)
{
     struct ieee80211com *ic = NULL;
     OS_GET_TIMER_ARG(ic,struct ieee80211com *);
     ic->ic_bss_to40(ic);
}

static OS_TIMER_FUNC(ieee80211_obss_nb_ru_tolerence_timeout)
{
    struct ieee80211com *ic;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    if (ic->ic_initialized == 1) {
        ic->ru26_tolerant = true;
        ic->ic_set_ru26_tolerant(ic, ic->ru26_tolerant);
    }
}

static os_timer_func(ieee80211_csa_max_rx_wait_timer)
{
    struct ieee80211com *ic;

    OS_GET_TIMER_ARG(ic, struct ieee80211com *);

    if (!ic)
        return;

    /* unsubscribe to ppdu stats */
    if (ic->ic_subscribe_csa_interop_phy) {
        ic->ic_subscribe_csa_interop_phy(ic, false);
        ic->ic_csa_interop_subscribed = false;
    }
}

#if UMAC_SUPPORT_WNM
static OS_TIMER_FUNC(ieee80211_bssload_timeout)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    ieee80211_wnm_bss_validate_inactivity(ic);
    OS_SET_TIMER(&ic->ic_bssload_timer, IEEE80211_BSSLOAD_WAIT);
}
#endif

static void update_noise_stats_iter_cb(void *arg, struct ieee80211_node *ni)
{
    uint8_t bin_index, median_index, temp_variable;
    struct ieee80211com *ic;
    uint8_t *median_array = (uint8_t *) arg;

    ic = ni->ni_ic;

    if (ni->ni_associd != 0) {
        if (ic->bin_number != 0) {
            ni->ni_noise_stats[ic->bin_number].noise_value = ni->ni_snr;
            for (bin_index = 0;bin_index <= ic->bin_number;bin_index++) {
                median_array[bin_index] = ni->ni_noise_stats[bin_index].noise_value;
            }
            for (bin_index = 0;bin_index <= ic->bin_number;bin_index++) {
                for (median_index = 0;median_index < (ic->bin_number - bin_index); median_index++) {
                    if (median_array[median_index] >= median_array[median_index+1]) {
                        temp_variable = median_array[median_index];
                        median_array[median_index] = median_array[median_index+1];
                        median_array[median_index+1] = temp_variable;
                    }
                }
            }

            if ((ic->bin_number) %2 == 0) {
                ni->ni_noise_stats[ic->bin_number].median_value = median_array[ic->bin_number/2];
            } else {
                ni->ni_noise_stats[ic->bin_number].median_value = median_array[(ic->bin_number/2) + 1];
            }

            if (ni->ni_noise_stats[ic->bin_number].noise_value <= ni->ni_noise_stats[ic->bin_number-1].min_value) {
                ni->ni_noise_stats[ic->bin_number].min_value = ni->ni_noise_stats[ic->bin_number].noise_value;
            } else {
                ni->ni_noise_stats[ic->bin_number].min_value = ni->ni_noise_stats[ic->bin_number-1].min_value;
            }
            if (ni->ni_noise_stats[ic->bin_number].noise_value >= ni->ni_noise_stats[ic->bin_number-1].max_value) {
                ni->ni_noise_stats[ic->bin_number].max_value = ni->ni_noise_stats[ic->bin_number].noise_value;
            } else {
                ni->ni_noise_stats[ic->bin_number].max_value = ni->ni_noise_stats[ic->bin_number-1].max_value;
            }
        } else {
            ni->ni_noise_stats[ic->bin_number].noise_value = ni->ni_snr;
            ni->ni_noise_stats[ic->bin_number].min_value = ni->ni_noise_stats[ic->bin_number].noise_value;
            ni->ni_noise_stats[ic->bin_number].max_value = ni->ni_noise_stats[ic->bin_number].noise_value;
            ni->ni_noise_stats[ic->bin_number].median_value = ni->ni_noise_stats[ic->bin_number].noise_value;
        }
    }
}

/*
 * @brief description
 *  function executed from the timer context to update the noise stats
 *  like noise value min value, max value and median value
 *  at the end of each traffic rate.
 *
 */
void update_noise_stats(struct ieee80211com *ic)
{
    u_int8_t   *median_array;

    median_array = (u_int8_t *)OS_MALLOC(ic->ic_osdev, (ic->bin_number + 1) * sizeof(u_int8_t), GFP_KERNEL);
    if (median_array == NULL){
        qdf_nofl_info("Memory allocation for median array failed \n");
        return;
    }

    wlan_mlme_iterate_node_list(ic, update_noise_stats_iter_cb,
                                (void *)median_array,
                                IEEE80211_NODE_ITER_F_ASSOC_STA);
    OS_FREE(median_array);
}

/*
 * brief description
 * Timer function which is used to record the noise statistics of each node
 * timer is called ath the end of each traffic rate and is measured until
 * the end of traffic interval
 */
static OS_TIMER_FUNC(ieee80211_noise_stats_update)
{
    struct ieee80211com *ic;
    OS_GET_TIMER_ARG(ic, struct ieee80211com *);
    update_noise_stats(ic);
    ic->bin_number++;
    if(ic->bin_number < ic->traf_bins){
        OS_SET_TIMER(&ic->ic_noise_stats,ic->traf_rate * 1000);
    }
}

#if SUPPORT_11AX_D3
void
ieee80211_heop_init(struct ieee80211com * ic) {
    /* In future we may have to fill in the
     * values of individual fields in heop_param and heop_bsscolor_info */
    ic->ic_he.heop_param = 0;
    ic->ic_he.heop_bsscolor_info = 0;
}
#else
void
ieee80211_heop_param_init(struct ieee80211com * ic) {
    /* In future we may have to fill in the
     * values of individual fields in heop_param */
    ic->ic_he.heop_param = 0;
}
#endif

/**
 * ieee80211_mbssid_get_num_vaps_in_mbss_cache(): Retrieve total number
 * of vaps that is occupying a cache-entry - lock held context. User
 * must ensure that this API is not called under the same lock
 * @ic - ic pointer
 *
 * return: number of vaps in mbss-cache
 */
uint8_t ieee80211_mbssid_get_num_vaps_in_mbss_cache(struct ieee80211com *ic)
{
    uint8_t num_vaps = 0;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE);

    if (is_mbssid_enabled) {
        /* acquire mbss_cache_lock */
        qdf_spin_lock_bh(&ic->ic_mbss.mbss_cache_lock);
        num_vaps = ic->ic_mbss.num_vaps;
        /* release mbss cache lock */
        qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
        mbss_info("num_vaps: %d", num_vaps);
    }

    return num_vaps;
}

void ieee80211_mbssid_update_mbssie_cache_entry(
        struct ieee80211vap *vap, uint8_t cache_entry)
{
    struct ieee80211com  *ic                            = vap->iv_ic;
    struct vdev_mlme_obj *vdev_mlme                     = vap->vdev_mlme;
    struct ieee80211_mbss_ie_cache_node *node           = NULL;
    struct ieee80211_mbss_non_tx_profile_sub_ie *ntx_pf = NULL;
    uint32_t node_idx;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_tx_vap         = !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
    const uint8_t ie_header_len = sizeof(struct ieee80211_ie_header);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

#if MBSS_CACHE_ENTRY_DEBUG
    uint8_t *p;
#endif

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        return;
    }

    mbss_debug(":> vdev_id: %d cache_entry: %d", vap->iv_unit, cache_entry);
    mbss_debug(":> is_tx_vap: %d ic->ic_mbss.rot_factor: %d",
                                         is_tx_vap, ic->ic_mbss.rot_factor);

    if (is_mbssid_enabled) {
        /* Acquire mbss_cache_lock */
        qdf_spin_lock_bh(&ic->ic_mbss.mbss_cache_lock);

        if (is_tx_vap) {
            node_idx = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                       scn->soc->ema_ap_num_max_vaps);
        } else {
            node_idx = ieee80211_mbssid_get_non_tx_vap_node_idx(vap,
                       scn->soc->ema_ap_num_max_vaps);
        }

        if (node_idx >= scn->soc->ema_ap_num_max_vaps) {
            mbss_err("Invalid node_idx: %d", node_idx);
            /* Release mbss cache lock */
            qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
            return;
        }

        mbss_debug("node_idx: %d", node_idx);

        node        = &((struct ieee80211_mbss_ie_cache_node *)
                                 ic->ic_mbss.mbss_cache)[node_idx];
        ntx_pf      = &node->non_tx_profile.ntx_pf;

        switch (cache_entry) {
            case MBSS_CACHE_ENTRY_POS:
            break;
            case MBSS_CACHE_ENTRY_CAP:
            {
                ieee80211_add_capability(
                        ntx_pf->cap_elem.non_tx_cap, vap->iv_bss);
            }
            break;
            case MBSS_CACHE_ENTRY_SSID:
            {
                void *start_of_relocatable_bytes;
                struct __ieee80211_mbss_ie_ssid *ssid_elem
                                                = &ntx_pf->ssid_elem;
                const uint8_t target_ssid_len   =
                                vdev_mlme->mgmt.generic.ssid_len;
                uint8_t target_ssid[WLAN_SSID_MAX_LEN + 1] = {0};
                const uint8_t offset_to_ssid_in_node =
                                ie_header_len +
                                sizeof(struct ieee80211_mbss_ie_capability);
                const uint8_t no_of_relocatable_bytes_in_node =
                                IEEE80211_MAX_NON_TX_PROFILE_SIZE -
                                (offset_to_ssid_in_node +
                                 /* ssid header */
                                 ie_header_len +
                                 target_ssid_len);

                mbss_debug("no_of_relocatable_bytes_in_node: %d",
                                    no_of_relocatable_bytes_in_node);

                /* Copy target_ssid */
                qdf_mem_copy(target_ssid,
                        vdev_mlme->mgmt.generic.ssid, target_ssid_len);

                /* Create hole of size ssid_elem->hdr.length.
                 * refer to the defn of
                 * struct ieee80211_mbss_ie_cache_node.
                 * ssid field in the ssid element is defined
                 * as a flexible array and hence a hole is
                 * required to be created to avoid overwriting
                 * data written previously
                 */
                if (!ssid_elem->hdr.length) {
                    start_of_relocatable_bytes = ssid_elem->ssid + 1;
                    if (*ssid_elem->ssid == IEEE80211_ELEMID_MBSSID_INDEX) {
                        /* In the case the cache entry was already updated
                         * for Hidden SSID case, the SSID element will only
                         * be 2bytes long moving the MBSSID index IE by 1byte.
                         * Re-adjust the start of relocatable bytes accordingly.
                         */
                        start_of_relocatable_bytes--;
                    }
                } else {
                    start_of_relocatable_bytes = ssid_elem->ssid +
                                                    ssid_elem->hdr.length;
                }

                if (!IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                    if (target_ssid_len && target_ssid_len <= 32) {

                        /* Relocate existing bytes in node to make
                         * adjustment for ssid based flexible array
                         */
                        qdf_mem_move(ssid_elem->ssid +
                                     target_ssid_len,
                                     start_of_relocatable_bytes,
                                     no_of_relocatable_bytes_in_node);

                        /* Copy target-ssid in the accommodated space */
                        qdf_mem_copy(ssid_elem->ssid,
                                     target_ssid, target_ssid_len);
                        mbss_debug("ssid: %s", target_ssid);

                        /* Subtract the current ssid length from
                         * the total non-tx profile size
                         */
                        if (ssid_elem->hdr.length)
                            ntx_pf->sub_elem.length -= ssid_elem->hdr.length;

                        /* Update the ssid sub ie length in non-tx
                         * profile
                         */
                        ssid_elem->hdr.length = target_ssid_len;

                        /* Updated non-tx profile subelement
                         * header length */
                        ntx_pf->sub_elem.length += target_ssid_len;
                    } /* if (target_ssid_len && target_ssid_len <= 32) */
                } else {
                    mbss_debug("Hidden ssid enabled case");

                    /* Subtract the current ssid length from
                     * the total non-tx profile size
                     */
                    if (ssid_elem->hdr.length) {
                        ntx_pf->sub_elem.length -= ssid_elem->hdr.length;
                        ssid_elem->hdr.length = 0;
                    }

                    /* Copy the relocatable bytes starting from the ssid
                     * field as there is no ssid byte in case of hidden-
                     * ssid
                     */
                    qdf_mem_copy(ssid_elem->ssid,
                                    start_of_relocatable_bytes,
                                        no_of_relocatable_bytes_in_node);
                } /* End if (!IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) */
            }
            break;
            case MBSS_CACHE_ENTRY_IDX:
            {
#define MBSS_OFFSET_TO_DTIM_PERIOD_FIELD 1
#define MBSS_OFFSET_TO_DTIM_COUNT_FIELD  2
                uint8_t *bufp;

                if (ntx_pf->ssid_elem.hdr.length) {
                    bufp =  (uint8_t *) &ntx_pf->ssid_elem;
                    bufp += (ie_header_len +
                            ntx_pf->ssid_elem.hdr.length + ie_header_len);
                }
                else
                    bufp = (uint8_t *) &ntx_pf->idx_elem.bssid_idx;

                *bufp = vdev_mlme->mgmt.mbss_11ax.profile_idx & 0xff;

                /* Update dtim-period field */
                *(bufp + MBSS_OFFSET_TO_DTIM_PERIOD_FIELD) =
                                        vdev_mlme->proto.generic.dtim_period;

                /* Update dtim-count field - fw requires the dtim count
                 * value to be 0 if the non-tx profile already exists in
                 * the beacon template. If a non-tx profile is being added
                 * for the first time then fw expects the dtim-count value
                 * to be 255 for that particular profile; so, we keep the
                 * dtim-count as 255 if the vap is in down state
                 */
                if (ieee80211_is_vap_state_running(vap))
                    *(bufp + MBSS_OFFSET_TO_DTIM_COUNT_FIELD) = 0;
                else
                    *(bufp + MBSS_OFFSET_TO_DTIM_COUNT_FIELD) = 255;

                mbss_debug("bssid_idx: %d dtim_period: %d"
                          " dtim_count: %d", *bufp,
                          *(bufp + MBSS_OFFSET_TO_DTIM_PERIOD_FIELD),
                          *(bufp + MBSS_OFFSET_TO_DTIM_COUNT_FIELD));
            }
            break;
            default:
                mbss_err("unknown cache_entry id: %d", cache_entry);
        } /* End switch */

#if MBSS_CACHE_ENTRY_DEBUG
        if (ntx_pf->ssid_elem.hdr.length) {
            p = (uint8_t *) &ntx_pf->ssid_elem;
            p += (2 + ntx_pf->ssid_elem.hdr.length + 2);
        }
        else
            p = (uint8_t *) &ntx_pf->idx_elem.bssid_idx;
        mbss_debug("bssid_idx: %d dtim_period: %d",*p, *(p + 1));
        mbss_debug("ntx_pf->sub_elem.length: %d", ntx_pf->sub_elem.length);
        mbss_debug("beacon_pos: %d", node->pos);
#endif

        /* Release mbss cache lock */
        qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
    } /* End if mbss_feature check block */

    mbss_debug(":<");
}

int ieee80211_mbssid_update_mbssie_cache(struct ieee80211vap *vap, bool add)
{
    struct ieee80211com  *ic                            = vap->iv_ic;
    struct vdev_mlme_obj *vdev_mlme                     = vap->vdev_mlme;
    struct ieee80211_mbss_ie_cache_node *node           = NULL;
    struct ieee80211_mbss_non_tx_profile_sub_ie *ntx_pf = NULL;
    struct ol_ath_softc_net80211 *scn;
    uint32_t node_idx;
    bool is_tx_vap;
    const size_t ie_header_len = sizeof(struct ieee80211_ie_header);

    mbss_debug(":>%d", add);

    if (vap->iv_opmode != IEEE80211_M_HOSTAP) {
        mbss_err("Not AP mode. Return");
        return -1;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);

    is_tx_vap = !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);
    /* If it is currently marked as non-Tx vap and if currently
     * no Tx-vap exists then check whether bssid-idx is invalid or
     * not. If invalid then we need to retrieve and clear the
     * corresponding node as Tx-vap as is not assigned a valid
     * bssid-idx yet. A valid bssid-idx will get assigned to this
     * vap only when a new Tx-vap is selected by user
     */
    if (!is_tx_vap) {
        if ((!ic->ic_mbss.transmit_vap) &&
                (vdev_mlme->mgmt.mbss_11ax.profile_idx
                == IEEE80211_INVALID_MBSS_BSSIDX(ic))) {
            is_tx_vap = true;
        }
    }

    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        /* acquire mbss_cache_lock */
        qdf_spin_lock_bh(&ic->ic_mbss.mbss_cache_lock);

        if (is_tx_vap) {
            node_idx = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                            scn->soc->ema_ap_num_max_vaps);
        } else {
            node_idx = ieee80211_mbssid_get_non_tx_vap_node_idx(vap,
                            scn->soc->ema_ap_num_max_vaps);
        }

        if (node_idx >= scn->soc->ema_ap_num_max_vaps) {
            mbss_err("Invalide node_idx: %d", node_idx);
            /* release mbss_cache_lock */
            qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
            return -1;
        }

        mbss_debug("node_idx: %d", node_idx);

        node = &((struct ieee80211_mbss_ie_cache_node *)
                             ic->ic_mbss.mbss_cache)[node_idx];
        ntx_pf = &node->non_tx_profile.ntx_pf;

        if (add) {
            if (node->used) {
                mbss_warn("mbss_ie_cache_node corresponding"
                        "to vdev_id: %d is already ocuppied",
                            wlan_vdev_get_id(vap->vdev_obj));
                /* release mbss_cache_lock */
                qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
                return -1;
            }

            /* position is already assigned at cache create
             * time during attach. By design position once
             * assigned does not change for the lifetime of
             * the node
             */
            node->used      = true;
            node->vdev_id   = wlan_vdev_get_id(vap->vdev_obj);
            mbss_debug("node_idx: %d vdev_id: %d", node_idx, node->vdev_id);
            mbss_debug("beacon_pos: %d", node->pos);

            /* assign non-tx subelement id */
            ntx_pf->sub_elem.element_id
                            = IEEE80211_MBSSID_SUB_ELEMID;

            ntx_pf->cap_elem.hdr.element_id
                            = IEEE80211_ELEMID_MBSSID_NON_TRANS_CAP;
            /* initialize length field accommodating
             * 16 bit long basic capability field
             */
            ntx_pf->cap_elem.hdr.length = 2;

            /* ssid is assigned to a vap at the time
             * of start_ap call from HOSTAPD. Defer
             * the ssid assignment till then
             */
            ntx_pf->ssid_elem.hdr.element_id = IEEE80211_ELEMID_SSID;
            ntx_pf->ssid_elem.hdr.length = 0;

            ntx_pf->idx_elem.hdr.element_id
                            = IEEE80211_ELEMID_MBSSID_INDEX;
            /* initialize length field accommodating
             * subfields bssidx, dtim period and
             * dtim count each of length one octet
             */
            ntx_pf->idx_elem.hdr.length = 3;
            ntx_pf->idx_elem.bssid_idx
                            = vdev_mlme->mgmt.mbss_11ax.profile_idx;
            ntx_pf->idx_elem.dtim_period
                            = vdev_mlme->proto.generic.dtim_period;
            /* initialize to 255 as fw requires
             * dtim-count value to be 255 for a
             * non-tx profile that gets added to
             * a beacon template for the first
             * time; the corresponding value is
             * 0 if the profile already exists
             * in fw
             */
            ntx_pf->idx_elem.dtim_count = 255;

            ntx_pf->sub_elem.length
                            = ie_header_len + ntx_pf->cap_elem.hdr.length +
                              ie_header_len + ntx_pf->ssid_elem.hdr.length +
                              ie_header_len + ntx_pf->idx_elem.hdr.length;

            /* update num_vaps */
            ic->ic_mbss.num_vaps++;
            qdf_assert(ic->ic_mbss.num_vaps <= scn->soc->ema_ap_num_max_vaps);
        } else {
            /* Mark cache-entry as stale as the vap occupying
             * this particular entry is getting deleted
             */
            node->used = false;

            if (ic->ic_mbss.num_vaps) {
                /* Update num_vaps */
                ic->ic_mbss.num_vaps--;

                /* If this was the last ap vap in MBSSID mode
                 * then re-init relevant params anticipating
                 * new MBSSID group creation initialted by
                 * user subsequently
                 */
                if (!ic->ic_mbss.num_vaps) {
                    /* Reassign ref_bssid if all ap-vaps are
                     * deleted
                     */
                    if (ic->ic_assign_mbssid_ref_bssid) {
                        /* Do not request partially random ref_bssid
                         * as we would like to adhere to base mac
                         * address (that assigned to the radio/physical
                         * interface) even after the MBSSID group is
                         * dissolved
                         */
                        ic->ic_assign_mbssid_ref_bssid(scn, false);
                    }

                    /* Reset rotation factor */
                    ic->ic_mbss.rot_factor = 0;
                }
            } /* end if (ic->ic_mbss.num_vaps) */
        }

        /* release mbss_cache_lock */
        qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);

        mbss_debug("ntx_pf->sub_elem.length: %d used: %d",
                ntx_pf->sub_elem.length, node->used);
    } /* endif if (mbssid_enabled) */

    return 0;
}

static int ieee80211_mbssid_assign_and_sanitize_bssid_idx(
                                    struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211vap *tx_vap;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    /* pointers to tx and non-tx vap bssids */
    uint8_t *tx_vap_bssid = NULL, *non_tx_vap_bssid;
    /* lsb n bit of tx vap; n is max bssid inidicator */
    uint8_t bssid_lsb_n_bit_tx_vap;
    /* lsb n bit of non-tx vap; n is max bssid inidicator */
    uint8_t bssid_lsb_n_bit_non_tx_vap;
    uint8_t bssid_idx;
    bool is_bssid_idx_occupied = false;

    if (!ic) {
        mbss_err("ic is null");
        return -1;
    }
    tx_vap = ic->ic_mbss.transmit_vap;

    if (!tx_vap) {
        /* Initially, first vap created is the virtual tx-vap
         * till user does not designate tx-vap from user space
         */
        struct ieee80211_mbss_ie_cache_node *node = NULL;
        struct ol_ath_softc_net80211 *scn;
        struct wlan_objmgr_vdev *tx_vdev;
        uint32_t node_idx = 0;

        scn = OL_ATH_SOFTC_NET80211(ic);
        if (!scn) {
            mbss_err("scn is NULL. Non-tx vap create failed");
            return -1;
        }
        node_idx = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                            scn->soc->ema_ap_num_max_vaps);

        node = &((struct ieee80211_mbss_ie_cache_node *)
                             ic->ic_mbss.mbss_cache)[node_idx];

        tx_vdev = wlan_objmgr_get_vdev_by_id_from_pdev(
                            ic->ic_pdev_obj, node->vdev_id, WLAN_MLME_NB_ID);
        if (!tx_vdev) {
            mbss_err("tx_vdev is NULL. Non-tx vap create failed");
            return -1;
        }
        tx_vap = wlan_vdev_mlme_get_ext_hdl(tx_vdev);

        if (!tx_vap) {
            mbss_err("tx_vap is NULL. Non-tx vap create failed");
            /* Release tx_vdev reference */
            wlan_objmgr_vdev_release_ref(tx_vdev, WLAN_MLME_NB_ID);
            return -1;
        }

        /* Retrieve tx-vap bssid */
        wlan_vdev_obj_lock(tx_vap->vdev_obj);
        tx_vap_bssid = wlan_vdev_mlme_get_macaddr(tx_vap->vdev_obj);
        wlan_vdev_obj_unlock(tx_vap->vdev_obj);
        /* Release tx_vdev reference */
        wlan_objmgr_vdev_release_ref(tx_vdev, WLAN_MLME_NB_ID);
    }

    /* Retrieve tx-vap bssid if not already done so */
    if (!tx_vap_bssid) {
        wlan_vdev_obj_lock(tx_vap->vdev_obj);
        tx_vap_bssid = wlan_vdev_mlme_get_macaddr(tx_vap->vdev_obj);
        wlan_vdev_obj_unlock(tx_vap->vdev_obj);
    }
    /* Retrieve non-tx vap bssid */
    wlan_vdev_obj_lock(vap->vdev_obj);
    non_tx_vap_bssid = wlan_vdev_mlme_get_macaddr(vap->vdev_obj);
    wlan_vdev_obj_unlock(vap->vdev_obj);
    mbss_debug("tx vap bssid: %s", ether_sprintf(tx_vap_bssid));
    mbss_debug("non-tx vap bssid: %s", ether_sprintf(non_tx_vap_bssid));

    /* Retrieve n bits of lsb octet of tx vap */
    bssid_lsb_n_bit_tx_vap = tx_vap_bssid[ATH_BSSID_INDEX] &
                                    ((1 << ic->ic_mbss.max_bssid) - 1);
    /* Retrieve n bits of lsb octet of non-tx vap */
    bssid_lsb_n_bit_non_tx_vap = non_tx_vap_bssid[ATH_BSSID_INDEX] &
                                ((1 << ic->ic_mbss.max_bssid) - 1);
    /* Get new bssid_idx of non-tx vap wrt. new tx vap */
    IEEE80211_MBSSID_GET_BSSID_IDX(bssid_lsb_n_bit_tx_vap,
                                   bssid_lsb_n_bit_non_tx_vap, bssid_idx);

    /* Sanitize the bssid_idx here,
     * 1. bssid_idx is in range [1..2^n-1]
     * 2. bssid_idx is not already occupied in pool
     */
    if (!bssid_idx || (bssid_idx > (MBSSID_GROUP_SIZE(ic) - 1))) {
        mbss_err("bssid_idx: %d found to be outside valid range"
                 " - check non-tx vap bssid: %s",
                 bssid_idx, ether_sprintf(non_tx_vap_bssid));
        return -1;
    }

    is_bssid_idx_occupied = qdf_test_bit((bssid_idx - 1),
            &ic->ic_mbss.bssid_index_bmap[IEEE80211_DEFAULT_MBSS_SET_IDX]);

    if (is_bssid_idx_occupied) {
        mbss_err("bssid_idx already occupied. Non-tx vap create failed");
        return -1;
    }

    /* Mark the bssid_idx as ocupied in the bssid_idx pool */
    qdf_set_bit(bssid_idx - 1,
            (unsigned long *)
            &ic->ic_mbss.bssid_index_bmap[IEEE80211_DEFAULT_MBSS_SET_IDX]);

    /* Assign bssid_idx to non-tx vap */
    vdev_mlme->mgmt.mbss_11ax.profile_idx = bssid_idx;

    mbss_info("bssid_idx is: %d", bssid_idx);
    return 0;
}

static void ieee80211_mbssid_init_vap_resource_profile(struct ieee80211vap *vap,
                                                       ol_ath_soc_softc_t *soc,
                                                       int mbssid_idx)
{
    int ven_ie_size = 0;
    struct ieee80211com *ic = vap->iv_ic;
    bool is_mbssid_enabled =
        wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE);

    if(!is_mbssid_enabled) {
        qdf_debug("MBSSID Disabled, no max-pp calc or beacon pos mapping necessary");
        return;
    }

    if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        if (!soc->ema_ap_support_wps_6ghz || !soc->ema_ap_ext_enabled) {
            if (mbssid_idx < IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX) {
                ven_ie_size = IEEE80211_EMA_GET_VENDOR_IE_SIZE_FROM_NTX_IDX(
                                soc->ema_ap_vendor_ie_config_low, mbssid_idx);
            } else {
                ven_ie_size = IEEE80211_EMA_GET_VENDOR_IE_SIZE_FROM_NTX_IDX(
                                soc->ema_ap_vendor_ie_config_high,
                                (mbssid_idx - IEEE80211_MBSSID_VENDOR_CFG_LOW_MAX_IDX));
            }
        } else {
            ven_ie_size = IEEE80211_EMA_VENDOR_IE_SECTION_BOUND_WITH_WPS;
        }
    } else {
        ven_ie_size = IEEE80211_MAX_VENDOR_IE_SIZE_LIMIT;
    }

    vap->iv_mbss.total_vendor_ie_size = ven_ie_size;
    vap->iv_mbss.available_vendor_ie_space = ven_ie_size;

    vap->iv_mbss.total_optional_ie_size =
                        soc->ema_ap_optional_ie_size;
    vap->iv_mbss.available_bcn_optional_ie_space =
                        soc->ema_ap_optional_ie_size;
    vap->iv_mbss.available_prb_optional_ie_space =
                        soc->ema_ap_optional_ie_size;
    return;
}

int ieee80211_mbssid_setup(struct ieee80211vap *vap)
{
    struct ieee80211vap *tmpvap;
    struct ieee80211com *ic;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    struct wlan_objmgr_psoc *psoc;
    uint8_t vap_count               = 0;
    uint8_t is_vap_created;
    ol_ath_soc_softc_t *soc;
    struct ol_ath_softc_net80211 *scn;

    ic = vap->iv_ic;
    if(!ic) {
        qdf_err("ic is NULL");
        return -EINVAL;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (psoc == NULL) {
        QDF_ASSERT(0);
        return -1;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn) {
        qdf_err("scn NULL");
        return -EINVAL;
    }

    soc = scn->soc;
    if (!soc) {
        qdf_err("Soc NULL");
        return -EINVAL;
    }

    /* If ieee80211_mbss_attach() or any of the core buffer alloc failed,
     * disallow VAP create
     */
    if (!ic->ic_mbss.mbssid_init || !ic->ic_mbss.mbss_cache ||
            !ic->ic_mbss.bcn_bo_mbss_ie || !ic->ic_mbss.prb_po_mbss_ie)
        return -EINVAL;

    vap->iv_mbss.mbss_set_id = IEEE80211_DEFAULT_MBSS_SET_IDX;

    /* Treat first VAP created as the virtual tx-VAP
     * till user designates a tx-VAP
     */
    if (!ieee80211_mbssid_get_num_vaps_in_mbss_cache(ic)) {
        vdev_mlme->mgmt.mbss_11ax.profile_idx = IEEE80211_INVALID_MBSS_BSSIDX(ic);
        if (!wlan_psoc_nif_fw_ext_cap_get(psoc,
                    WLAN_SOC_CEXT_MBSS_PARAM_IN_START)) {
            ic->ic_mbss.transmit_vap = vap;
            ic->ic_wifi_down_ind = 0;
            ic->ic_mbss.non_inherit_enable = 0;
            ic->ic_mbss.prb_req_ssid_match_vap = NULL;
        }

        qdf_mem_zero(
        (void *) &ic->ic_mbss.bssid_index_bmap[IEEE80211_DEFAULT_MBSS_SET_IDX],
         sizeof(ic->ic_mbss.bssid_index_bmap[IEEE80211_DEFAULT_MBSS_SET_IDX]));

        IEEE80211_VAP_MBSS_NON_TRANS_DISABLE(vap);

        ieee80211_mbssid_init_vap_resource_profile(vap, soc,
                                                   IEEE80211_INVALID_MBSS_BSSIDX(ic));

        mbss_info("Added first VAP (%pK), max_bssid_indicator:%d",
                                          vap, ic->ic_mbss.max_bssid);
    } else {
        vap_count = 0;
        is_vap_created = 0;
        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
           if (ieee80211_mbss_is_beaconing_ap(tmpvap)) {
               if (tmpvap == vap) {
                   /* If the VAP is already part of ic_vaps, then don't consider
                    * it when performing limit checks */
                   is_vap_created = 1;
               }
               vap_count++;
           }
        }

        if ((vap_count - is_vap_created) == (1 << ic->ic_mbss.max_bssid)) {
            mbss_err("Cannot add non-transmitting VAP, Max BSS number reached!");
            return -1;
        }

        if ((vap_count - is_vap_created) > ic->ic_mbss.max_non_transmit_vaps) {
            mbss_err("No space for non-Tx vap in tx-beacon"
                     " non-Tx vap not created");
            return -1;
        }

        /* Allocate a bssid_idx from bssid-idx pool if the bssid_idx
         * corresponding to the bssid of this non-tx vap is not alre
         * ady occupied. Fail vap cretate if bssid_idx is not found
         * free in bssid-idx pool
         */
        if (ieee80211_mbssid_assign_and_sanitize_bssid_idx(vap)) {
            return -1;
        }

        IEEE80211_VAP_MBSS_NON_TRANS_ENABLE(vap);

        ieee80211_mbssid_init_vap_resource_profile(vap, soc,
                            (vdev_mlme->mgmt.mbss_11ax.profile_idx - 1));

        mbss_info("Added non-transmitting VAP (%pK) with BSSID index:%d\n",
                  vap, vdev_mlme->mgmt.mbss_11ax.profile_idx);
    }

    /* allocate node from mbssie_cache */
    return ieee80211_mbssid_update_mbssie_cache(vap, true);
}

static void ieee80211_mbssid_get_cumulative_rot_factor(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    /* lsb n bit of previous tx vap; n is max bssid inidicator  */
    uint8_t bssid_lsb_n_bit_prev;
    /* lsb n bit of cur tx vap; n is max bssid inidicator  */
    uint8_t bssid_lsb_n_bit_cur;
    /* bssid of the new or current tx-vap */
    uint8_t *bssid;

    /* Retrieve bssid */
    wlan_vdev_obj_lock(vap->vdev_obj);
    bssid = wlan_vdev_mlme_get_macaddr(vap->vdev_obj);
    wlan_vdev_obj_unlock(vap->vdev_obj);

    /* Retrieve n bits of lsb octet of previous and new tx-vap
     * bssid idxes
     */
    bssid_lsb_n_bit_prev = ic->ic_mbss.ref_bssid[ATH_BSSID_INDEX] &
                                        ((1 << ic->ic_mbss.max_bssid) - 1);
    bssid_lsb_n_bit_cur  = bssid[ATH_BSSID_INDEX] &
                                        ((1 << ic->ic_mbss.max_bssid) - 1);

    /* Calculate cumulative rotation factor(rf) based on previous and
     * currnt tx-vap
     *     1. Add new value to previous to get cumulative rf
     *     2. Wrap it around by ema_ap_num_max_vaps
     */
    if (bssid_lsb_n_bit_prev > bssid_lsb_n_bit_cur) {
        ic->ic_mbss.rot_factor +=
                                (bssid_lsb_n_bit_prev - bssid_lsb_n_bit_cur);
    } else {
        ic->ic_mbss.rot_factor += (scn->soc->ema_ap_num_max_vaps -
                                abs(bssid_lsb_n_bit_prev - bssid_lsb_n_bit_cur));
    }
    ic->ic_mbss.rot_factor %= scn->soc->ema_ap_num_max_vaps;

    mbss_info("Rotation factor is: %d", ic->ic_mbss.rot_factor);
}

static void ieee80211_mbssid_refactor_bssid_idx(struct ieee80211vap *vap)
{
    struct ieee80211vap *tmpvap;
    struct ieee80211com *ic = vap->iv_ic;
    struct vdev_mlme_obj *vdev_mlme;
    /* lsb n bit of tx vap; n is max bssid inidicator */
    uint8_t bssid_lsb_n_bit_tx_vap;
    /* lsb n bit of non-tx vap; n is max bssid inidicator */
    uint8_t bssid_lsb_n_bit_non_tx_vap;
    uint8_t bssid_idx;
    /* bssid of tmpvap */
    uint8_t *tmpvap_bssid;
    /* bssid of tx-vap */
    uint8_t *tx_vap_bssid;
    struct net_device *tmpdev;

    /* Retrieve netdev of tx vap */
    tmpdev = ((osif_dev *)vap->iv_ifp)->netdev;
    /* Retrieve bssid of tx vap */
    wlan_vdev_obj_lock(vap->vdev_obj);
    tx_vap_bssid = wlan_vdev_mlme_get_macaddr(vap->vdev_obj);
    wlan_vdev_obj_unlock(vap->vdev_obj);

    /* Retrieve n bits of lsb octet of tx vap */
    bssid_lsb_n_bit_tx_vap = tx_vap_bssid[ATH_BSSID_INDEX] &
                                    ((1 << ic->ic_mbss.max_bssid) - 1);
    mbss_info("tx_vap: %s vdev_id: %d", tmpdev->name, vap->iv_unit);
    mbss_info("bssid_lsb_n_bit_tx_vap: 0x%x", bssid_lsb_n_bit_tx_vap);

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if (ieee80211_mbss_is_beaconing_ap(tmpvap) &&
            IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(tmpvap)) {

            /* Retrieve vdev_mlme pointer of non-tx vap */
            vdev_mlme = tmpvap->vdev_mlme;

            /* Retrieve bssid of non-tx vap */
            wlan_vdev_obj_lock(tmpvap->vdev_obj);
            tmpvap_bssid = wlan_vdev_mlme_get_macaddr(tmpvap->vdev_obj);
            wlan_vdev_obj_unlock(tmpvap->vdev_obj);

            /* Retrieve n bits of lsb octet of non-tx vap */
            bssid_lsb_n_bit_non_tx_vap = tmpvap_bssid[ATH_BSSID_INDEX] &
                                        ((1 << ic->ic_mbss.max_bssid) - 1);

            /* Retrieve netdev of tx vap */
            tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
            mbss_info("non_tx_vap: %s vdev_id: %d", tmpdev->name, tmpvap->iv_unit);
            mbss_info("bssid_lsb_n_bit_non_tx_vap: 0x%x", bssid_lsb_n_bit_non_tx_vap);

            /* Get new bssid_idx of non-tx vap wrt. new tx vap */
            IEEE80211_MBSSID_GET_BSSID_IDX(bssid_lsb_n_bit_tx_vap,
                                       bssid_lsb_n_bit_non_tx_vap, bssid_idx);

            /* Assign new bssid_idx to non-tx vap */
            vdev_mlme->mgmt.mbss_11ax.profile_idx = bssid_idx;

            mbss_info("bssid_idx: %d", bssid_idx);

            /* Update cache_entry corresponding to non-tx vap
             * with new value of bssid_idx
             */
            ieee80211_mbssid_update_mbssie_cache_entry(tmpvap, MBSS_CACHE_ENTRY_IDX);

            /* Mark entry in bssid-pool as occupied */
            qdf_set_bit(bssid_idx - 1,
                         (unsigned long *) ic->ic_mbss.bssid_index_bmap);
        }
    }
}

static void ieee80211_mbssid_refactor_aid_pool(struct ieee80211vap *vap,
                                               bool set)
{
    struct ieee80211vap *tmpvap;
    struct ieee80211com *ic = vap->iv_ic;
    bool is_mbssid_enabled  = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE);
    bool is_tx_vap = !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap);

    if (is_mbssid_enabled && is_tx_vap) {
        if (set) {
            unsigned long bm_size;

            KASSERT(vap->iv_max_aid != 0, ("0 max aid"));
            KASSERT(vap->iv_mbss_max_aid != 0, ("0 mbss max aid"));

            bm_size = howmany(vap->iv_max_aid,
                          sizeof(unsigned long) * BITS_PER_BYTE);

            vap->iv_aid_bitmap = qdf_mem_malloc(bm_size *
                                              sizeof(unsigned long));

            if (vap->iv_aid_bitmap == NULL) {
                /* XXX no way to recover */
                qdf_warn("no memory for AID bitmap!");
                vap->iv_max_aid      = 0;
                vap->iv_mbss_max_aid = 0;
                return;
            }
        } else {
            /*
             * free the current aid-pool
             * NOTE: There is no need to reset iv_max_aid and iv_mbss_max_aid
             * during reset since it might be required on bring-up again for
             * the same VAP context.
             */
            if (vap->iv_aid_bitmap) {
                OS_FREE(vap->iv_aid_bitmap);
                vap->iv_aid_bitmap = NULL;
            }
        }

        TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
            /* set or reset aid-pool of non-tx vaps */
            if (ieee80211_mbss_is_beaconing_ap(tmpvap) &&
                IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(tmpvap)) {
                tmpvap->iv_aid_bitmap   = set ? vap->iv_aid_bitmap : NULL;
                tmpvap->iv_max_aid      = set ? vap->iv_max_aid : ic->ic_num_clients + (1 << ic->ic_mbss.max_bssid) + 1;
                /*
                 * iv_mbss_max_aid should follow iv_max_aid unconditionally
                 * during refactoring.
                 */
                tmpvap->iv_mbss_max_aid = tmpvap->iv_max_aid;
            }
        }
    } /* end if (is_mbssid_enabled && is_tx_vap) */
}

static void ieee80211_mbssid_reassign_bcn_pos_of_last_mbss_node(
                                       struct ieee80211vap *vap)
{
    struct ieee80211_mbss_ie_cache_node *node, *node_tx_vap;
    struct ieee80211com *ic = vap->iv_ic;
    bool is_mbssid_enabled  = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint8_t idx = scn->soc->ema_ap_num_max_vaps - 1;

    /* If rotation factor is 0 then vap in the last node
     * is the tx-vap. In that case avoid this processing
     */
    if (is_mbssid_enabled && ic->ic_mbss.rot_factor) {
        /* acquire mbss_cache_lock */
        qdf_spin_lock_bh(&ic->ic_mbss.mbss_cache_lock);

        /* access last node */
        node = &((struct ieee80211_mbss_ie_cache_node *)
                            ic->ic_mbss.mbss_cache)[idx];
        if (node->used) {
            /* Derive node_idx of the tx-vap */
            idx = ieee80211_mbssid_get_tx_vap_node_idx(ic,
                            scn->soc->ema_ap_num_max_vaps);

            /* Derive tx-vap node */
            node_tx_vap = &((struct ieee80211_mbss_ie_cache_node *)
                                ic->ic_mbss.mbss_cache)[idx];

            qdf_assert(node_tx_vap->vdev_id == wlan_vdev_get_id(vap->vdev_obj));
            if (node_tx_vap->vdev_id != wlan_vdev_get_id(vap->vdev_obj)) {
                /* release mbss cache lock */
                qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
                return;
            }

            /* Assign beacon position of the tx vap to the
             * non-tx vap in the last entry of the MBSS cache
             */
            node->pos = node_tx_vap->pos;
        } else {
            mbss_info("No entry in last node of MBSS cache");
        }

        /* release mbss cache lock */
        qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);
        mbss_info("<< last node beacon_pos: %d", node->pos);
    }
}

/* Check and update the first created vap as non-tx
 * vap. First vap always resides in the last entry
 * of the MBSS cache
 */
static void ieee80211_mbssid_mark_first_created_vap_as_non_tx(
                                      struct ieee80211com *ic)
{
    struct ieee80211vap *vap_in_last_node = NULL;
    struct wlan_objmgr_vdev *vdev_in_last_node;
    struct ieee80211_mbss_ie_cache_node *node;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint8_t idx = scn->soc->ema_ap_num_max_vaps - 1;
    bool is_mbssid_enabled  = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                    WLAN_PDEV_F_MBSS_IE_ENABLE);

    if (is_mbssid_enabled) {
        /* acquire mbss_cache_lock */
        qdf_spin_lock_bh(&ic->ic_mbss.mbss_cache_lock);

        /* access last node */
        node = &((struct ieee80211_mbss_ie_cache_node *)
                            ic->ic_mbss.mbss_cache)[idx];

        if (node->used) {
            /* Mark last node as non-tx vap as it is not
             * same as the tx vap
             */
            vdev_in_last_node = wlan_objmgr_get_vdev_by_id_from_pdev(
                            ic->ic_pdev_obj, node->vdev_id, WLAN_MLME_NB_ID);

            if (vdev_in_last_node) {
                vap_in_last_node = wlan_vdev_mlme_get_ext_hdl(vdev_in_last_node);
                wlan_objmgr_vdev_release_ref(vdev_in_last_node, WLAN_MLME_NB_ID);

                if (vap_in_last_node) {
                    IEEE80211_VAP_MBSS_NON_TRANS_ENABLE(vap_in_last_node);
                }
            }
        } /* end if(node->used) */

        /* release mbss cache lock */
        qdf_spin_unlock_bh(&ic->ic_mbss.mbss_cache_lock);

        if (IS_MBSSID_EMA_EXT_ENABLED(ic)) {
            if (!vap_in_last_node) {
                qdf_debug("VAP corresponding to last node is NULL!");
                return;
            }

            if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap_in_last_node)) {
                vap_in_last_node->iv_mbss.non_tx_pfl_ie_pool =
                    qdf_nbuf_alloc(NULL, IEEE80211_NTX_PFL_IE_POOL_SIZE,
                                                            0, 0, false);
                if (!vap_in_last_node->iv_mbss.non_tx_pfl_ie_pool)
                    return;
                qdf_mem_zero(vap_in_last_node->iv_mbss.non_tx_pfl_ie_pool,
                        sizeof(vap_in_last_node->iv_mbss.non_tx_pfl_ie_pool));
                qdf_spinlock_create(&vap_in_last_node->iv_mbss.non_tx_pfl_ie_pool_lock);
                vap_in_last_node->iv_mbss.ntx_pfl_rollback_stats = 0;
                vap_in_last_node->iv_mbss.backup_length = 0;
            }
            vap_in_last_node->iv_mbss.ie_overflow_stats = 0;
            vap_in_last_node->iv_mbss.ie_overflow = false;
        }
    } /* end if (is_mbssid_enabled) */
}

int ieee80211_mbssid_txvap_set(struct ieee80211vap *vap)
{
    struct ieee80211com *ic;
    struct wlan_objmgr_psoc *psoc;
    struct vdev_mlme_obj *vdev_mlme;

    if (!vap) {
         mbss_err("vap is NULL");
         return -1;
    }
    ic = vap->iv_ic;
    vdev_mlme = vap->vdev_mlme;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (psoc == NULL) {
        QDF_ASSERT(0);
        return -1;
    }
    if (!wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_CEXT_MBSS_PARAM_IN_START)) {
        mbss_err("Tx vap set is not supported");
        return -1;
    }
    /* This vap is already configured as Tx VDEV */
    if (ic->ic_mbss.transmit_vap) {
        mbss_info(" Transmit valp is already configured");
        return -1;
    }

    vdev_mlme->mgmt.mbss_11ax.profile_idx = IEEE80211_INVALID_MBSS_BSSIDX(ic);
    ieee80211_mbssid_update_mbssie_cache_entry(vap, MBSS_CACHE_ENTRY_IDX);

    ic->ic_wifi_down_ind = 0;
    ic->ic_mbss.prb_req_ssid_match_vap = NULL;

    /* Designate new tx vap */
    ic->ic_mbss.transmit_vap = vap;

    if (ic->ic_mbss.transmit_vap)
        mbss_info("Tx VAP is set for vap%d", ic->ic_mbss.transmit_vap->iv_unit);

    if (!IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
        /* It is only possible to satisfy this condition if
         * user chose the first vap created as the tx-vap
         */
        mbss_info("First vap created is chosen as tx-vap");
        if (!vap->iv_aid_bitmap) {
            mbss_info("Initializing AID bit map");
            /* Initialize aid-pool for first vap */
            ieee80211_mbssid_refactor_aid_pool(vap, true);
        }
        qdf_assert(ic->ic_mbss.transmit_vap);
        return 0;
    } else {
        /* Initially, we start by marking first vap created
         * as the tx vap. We must reset it as non-tx if another
         * vap has been selected as tx vap
         */
        ieee80211_mbssid_mark_first_created_vap_as_non_tx(ic);
    }

    /* Mark vap as tx-vap */
    IEEE80211_VAP_MBSS_NON_TRANS_DISABLE(vap);

    /* Reset the bssid-idx pool */
    qdf_mem_zero(
        (void *) &ic->ic_mbss.bssid_index_bmap[IEEE80211_DEFAULT_MBSS_SET_IDX],
         sizeof(ic->ic_mbss.bssid_index_bmap[IEEE80211_DEFAULT_MBSS_SET_IDX]));

    /* Get cumulative rotation factor */
    ieee80211_mbssid_get_cumulative_rot_factor(vap);

    /* Refactor bssid idxes and bssid idx-pool with respect to
     * the bssid of the new tx vap
     */
    ieee80211_mbssid_refactor_bssid_idx(vap);

    /* Reassign ref_bssid. Not required to ensure 48-n bit
     * sanity here as user can set only an alreay created vap
     * as tx vap. And, all vap's bssid gets sanitized at create
     * time
     */
    wlan_vdev_obj_lock(vap->vdev_obj);
    IEEE80211_ADDR_COPY(ic->ic_mbss.ref_bssid,
                    wlan_vdev_mlme_get_macaddr(vap->vdev_obj));
    wlan_vdev_obj_unlock(vap->vdev_obj);

    /* Last node in MBSS cache will always occupy the beacon
     * position of the slot that the tx-vap held before getting
     * designated as the new tx-vap
     */
    ieee80211_mbssid_reassign_bcn_pos_of_last_mbss_node(vap);

    /* Reset DTIM value */
    if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
        vdev_mlme->proto.generic.dtim_period = IEEE80211_DTIM_DEFAULT_LP_IOT;
    } else {
        vdev_mlme->proto.generic.dtim_period = IEEE80211_DTIM_DEFAULT;
    }

    /* Reset aid-pool */
    ieee80211_mbssid_refactor_aid_pool(vap, true);

    /* Dealloc skb for non-Tx IE Pool when Tx-VAP changes.
     * If non_tx_pfl_ie_pool already exists when trying to
     * set Tx-VAP then this case is hit.
     */
    if ((ic->ic_mbss.ema_ext_enabled) &&
        (vap->iv_mbss.non_tx_pfl_ie_pool != NULL)) {
        IEEE80211_NTX_PFL_IE_POOL_LOCK(vap);
        qdf_nbuf_free(vap->iv_mbss.non_tx_pfl_ie_pool);
        vap->iv_mbss.non_tx_pfl_ie_pool = NULL;
        IEEE80211_NTX_PFL_IE_POOL_UNLOCK(vap);
        qdf_spinlock_destroy(&vap->iv_mbss.non_tx_pfl_ie_pool_lock);
        vap->iv_mbss.ie_overflow = false;
        vap->iv_mbss.ie_overflow_stats = 0;
    }

    mbss_info("Designated transmitting VAP (%pK), vdev_id: %d"
              " max_bssid_indicator: %d", vap, vap->iv_unit, ic->ic_mbss.max_bssid);

    qdf_assert(ic->ic_mbss.transmit_vap);
    return 0;
}

int ieee80211_mbssid_txvap_reset(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct vdev_mlme_obj *vdev_mlme = vap->vdev_mlme;
    struct wlan_objmgr_psoc *psoc;
    bool is_ema_ap_enabled = wlan_pdev_nif_feat_ext_cap_get(
                             ic->ic_pdev_obj, WLAN_PDEV_FEXT_EMA_AP_ENABLE);

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (psoc == NULL) {
        QDF_ASSERT(0);
        return -1;
    }
    if (!wlan_psoc_nif_fw_ext_cap_get(psoc, WLAN_SOC_CEXT_MBSS_PARAM_IN_START)) {
        mbss_err("Tx vap reset is not supported");
        return -1;
    }
    /* This vap is not configured as Tx VDEV */
    if (ic->ic_mbss.transmit_vap != vap) {
        mbss_info(" vap%d is not configured as Tx VAP", vap->iv_unit);
        return -1;
    }

    if (ic->ic_mbss.transmit_vap)
        mbss_info("Tx VAP is reset for vap%d", ic->ic_mbss.transmit_vap->iv_unit);

    ic->ic_mbss.transmit_vap = NULL;

    /* Reset aid-pool of all non-tx vaps */
    ieee80211_mbssid_refactor_aid_pool(vap, false);
    vap->iv_mbss.mbss_set_id = IEEE80211_DEFAULT_MBSS_SET_IDX;

    /* For FW recovery case, vap params are copied to create vap again
       after FW load, so not setting Non-Tx VDEV flag to store it in
       vap profile */
    if (!ic->recovery_in_progress) {
        IEEE80211_VAP_MBSS_NON_TRANS_ENABLE(vap);
        /* When Tx-VAP becomes a non-Tx VAP, allocate skb for
         * non_tx_pfl_ie_pool and create lock.
         */
        if (ic->ic_mbss.ema_ext_enabled) {
            vap->iv_mbss.non_tx_pfl_ie_pool =
                qdf_nbuf_alloc(NULL, IEEE80211_NTX_PFL_IE_POOL_SIZE, 0, 0, false);
            if (vap->iv_mbss.non_tx_pfl_ie_pool) {
                qdf_mem_zero(vap->iv_mbss.non_tx_pfl_ie_pool,
                             sizeof(vap->iv_mbss.non_tx_pfl_ie_pool));
                qdf_spinlock_create(&vap->iv_mbss.non_tx_pfl_ie_pool_lock);
            } else {
                mbss_err("Alloc failed for non_tx_pfl_ie_pool");
            }

            vap->iv_mbss.ntx_pfl_rollback_stats = 0;
            vap->iv_mbss.ie_overflow_stats = 0;
            vap->iv_mbss.ie_overflow = false;
            vap->iv_mbss.backup_length = 0;
        }

        /* Clear Tx-vap capabilities
         *
         * 1. FILS cap
         */
#ifdef WLAN_SUPPORT_FILS
        ucfg_fils_disable(vap->vdev_obj);
#endif
    }

    /* Reset current-pp */
    ic->ic_mbss.current_pp = 1;

    if (is_ema_ap_enabled) {
        uint8_t dtim_period;

        if (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) {
            dtim_period = qdf_roundup(IEEE80211_DTIM_DEFAULT_LP_IOT,
                                                ic->ic_mbss.max_pp);
        } else {
            dtim_period = qdf_roundup(IEEE80211_DTIM_DEFAULT,
                                                ic->ic_mbss.max_pp);
        }

        /* Reset DTIM value as per non-tx EMA vap */
        vdev_mlme->proto.generic.dtim_period =
                            qdf_roundup(dtim_period, ic->ic_mbss.max_pp);
    }

    return 0;
}

int ieee80211_mbssid_txvap_is_active(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ieee80211vap *txvap;

    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                WLAN_PDEV_F_MBSS_IE_ENABLE);

    if ((vap->iv_opmode != IEEE80211_M_HOSTAP) || !is_mbssid_enabled)
       return 1;

    if (is_mbssid_enabled && (ic->ic_mbss.transmit_vap)) {
         txvap = ic->ic_mbss.transmit_vap;
         if (wlan_vdev_is_up(txvap->vdev_obj) == QDF_STATUS_SUCCESS)
             return 1;
    }

    return 0;
}

bool ieee80211_mbss_is_beaconing_ap(struct ieee80211vap *vap)
{
    if ((vap->iv_opmode == IEEE80211_M_HOSTAP) &&
        !(vap->iv_smart_monitor_vap || vap->iv_special_vap_mode))
        return true;

    return false;
}

/*
 * ieee80211_mbssid_beacon_control:
 * Function to disable or enable beaconing for a MBSSID VAP.
 * It keeps track of number of times beaconing is  disabled/enabled.
 * If disabled multiple times, beaconing needs to be enabled equal number
 * of times. If it can't be enabled, then DISABLE is returned.
 *
 * @vap  : Pointer to the VAP structure
 * @bcn_cntrl : MBSS_BCN_ENABLE or MBSS_BCN_DISABLE
 *
 * Return: -1 if error, else state of VAP i.e. beaconing is enabled or disabled
 */

int ieee80211_mbssid_beacon_control(struct ieee80211vap *vap,
                                    uint8_t bcn_ctrl)
{
    struct ieee80211com *ic = vap->iv_ic;
    bool is_mbssid_enabled  = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                                    WLAN_PDEV_F_MBSS_IE_ENABLE);

    /* check for tx vap */
    if (!is_mbssid_enabled ||
        (is_mbssid_enabled && !IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap))) {
        qdf_err("Beacon control not supported in this mode");
        return -1;
    }

    switch (bcn_ctrl) {
    case MBSS_BCN_DISABLE:
        /* increment and return if disabled before */
        if (qdf_atomic_inc_return(&vap->iv_mbss.bcn_ctrl) > 1)
            return bcn_ctrl;
        break;
    case MBSS_BCN_ENABLE:
        if (qdf_atomic_read(&vap->iv_mbss.bcn_ctrl)) {
        /* decrement and return if still disabled,
         * otherwise resume beaconing */
            if (qdf_atomic_dec_return(&vap->iv_mbss.bcn_ctrl) >= 1)
                return MBSS_BCN_DISABLE;
        }
        break;
    default:
        return -1;;
    }

    /* send the template when going from DISABLE->ENABLE or ENABLE->DISABLE.
     * value of iv_mbss.bcn_ctrl goes 1->0 or 0->1 */
    vap->iv_mbss.mbssid_update_ie = true;
    ic->ic_vdev_beacon_template_update(vap);

    return bcn_ctrl;
}

bool wlan_mbss_beaconing_vdev_up(struct wlan_objmgr_vdev *vdev)
{
    struct ieee80211vap *vap;

    if (!vdev)
        return false;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap)
        return false;

    return (wlan_vdev_is_up(vdev) == QDF_STATUS_SUCCESS &&
            /* value of 0 indicates that beaconing is not suspended */
            !qdf_atomic_read(&vap->iv_mbss.bcn_ctrl));
}
qdf_export_symbol(wlan_mbss_beaconing_vdev_up);

static void ieee80211_user_rnr_init(struct ieee80211com *ic)
{
    ic->ic_user_neighbor_ap.running_length = 0;
    TAILQ_INIT(&ic->ic_user_neighbor_ap.user_rnr_data_list);
    qdf_spinlock_create(&ic->ic_user_neighbor_ap.user_rnr_lock);
}

void ieee80211_user_rnr_free(struct ieee80211com *ic)
{
    struct user_rnr_data *tmp_rnr_node = NULL, *tmp = NULL;

    ic->ic_user_neighbor_ap.running_length = 0;
    qdf_spinlock_destroy(&ic->ic_user_neighbor_ap.user_rnr_lock);
    TAILQ_FOREACH_SAFE(tmp_rnr_node, &ic->ic_user_neighbor_ap.user_rnr_data_list,
                       user_rnr_next_uid, tmp) {
        TAILQ_REMOVE(&ic->ic_user_neighbor_ap.user_rnr_data_list, tmp_rnr_node,
                     user_rnr_next_uid);
            qdf_mem_free(tmp_rnr_node->user_buf);
            qdf_mem_free(tmp_rnr_node);
    }
}

int
ieee80211_ifattach(struct ieee80211com *ic, IEEE80211_REG_PARAMETERS *ieee80211_reg_parm)
{
    u_int8_t bcast[QDF_MAC_ADDR_SIZE] = {0xff,0xff,0xff,0xff,0xff,0xff};
    int error = 0;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct target_psoc_info *psoc_info;
    target_resource_config* tgt_cfg;

    psoc_info = wlan_psoc_get_tgt_if_handle(scn->soc->psoc_obj);
    tgt_cfg = target_psoc_get_wlan_res_cfg(psoc_info);

#define DEFAULT_TRAFFIC_INTERVAL 1800
#define DEFAULT_TRAFFIC_RATE     300

    /* set up broadcast address */
    IEEE80211_ADDR_COPY(ic->ic_broadcast, bcast);

    if (wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
               WLAN_PDEV_F_MBSS_IE_ENABLE) && tgt_cfg) {
        mbss_debug("max_bssid_indicator: %d",  tgt_cfg->max_bssid_indicator);
        ic->ic_mbss.max_bssid = tgt_cfg->max_bssid_indicator;
    }

    /* initialize channel list */
    ieee80211_update_channellist(ic, 0, false);

    /* initialize rate set */
    ieee80211_init_rateset(ic);

#if SUPPORT_11AX_D3
    ieee80211_heop_init(ic);
#else
    ieee80211_heop_param_init(ic);
#endif

#ifdef ATH_SUPPORT_DFS
    ic->ic_dfs_start_tx_rcsa_and_waitfor_rx_csa = ieee80211_dfs_start_tx_rcsa_and_waitfor_rx_csa;
#endif

    /* validate ic->ic_curmode */
    if (!IEEE80211_SUPPORT_PHY_MODE(ic, ic->ic_curmode))
        ic->ic_curmode = IEEE80211_MODE_AUTO;

    /* setup initial channel settings */
    ic->ic_curchan = ieee80211_ath_get_channel(ic, 0); /* arbitrarily pick the first channel */

    /* Enable marking of dfs by default */
    IEEE80211_FEXT_MARKDFS_ENABLE(ic);

    if (ic->ic_reg_parm.htEnableWepTkip) {
        ieee80211_ic_wep_tkip_htrate_set(ic);
    } else {
        ieee80211_ic_wep_tkip_htrate_clear(ic);
    }

    if (ic->ic_reg_parm.htVendorIeEnable)
        IEEE80211_ENABLE_HTVIE(ic);

    /* whether to ignore 11d beacon */
    if (ic->ic_reg_parm.ignore11dBeacon)
        IEEE80211_ENABLE_IGNORE_11D_BEACON(ic);

    if (ic->ic_reg_parm.disallowAutoCCchange) {
        ieee80211_ic_disallowAutoCCchange_set(ic);
    }
    else {
        ieee80211_ic_disallowAutoCCchange_clear(ic);
    }

    (void) ieee80211_setmode(ic, ic->ic_curmode, ic->ic_opmode);

    ic->ic_he_bsscolor = IEEE80211_BSS_COLOR_INVALID;
    if (EOK != ieee80211_bsscolor_attach(ic)) {
        qdf_print("%s: BSS Color attach failed _investigate__ ",__func__);
    }

    ic->ic_intval = IEEE80211_BINTVAL_DEFAULT; /* beacon interval */
    ic->ic_set_beacon_interval(ic);

    ic->ic_lintval = 1;         /* listen interval */
    ic->ic_bmisstimeout = IEEE80211_BMISS_LIMIT * ic->ic_intval;
    TAILQ_INIT(&ic->ic_vaps);

    ic->ic_txpowlimit = IEEE80211_TXPOWER_MAX;

    /* Intialize WDS Auto Detect mode */
    ieee80211com_set_flags_ext(ic, IEEE80211_FEXT_WDS_AUTODETECT);

	/*
	** Enable the 11d country code IE by default
	*/

    ieee80211com_set_flags_ext(ic, IEEE80211_FEXT_COUNTRYIE);

    /* setup CWM configuration */
    ic->ic_cwm_set_mode(ic, ic->ic_reg_parm.cwmMode);
    ic->ic_cwm_set_extoffset(ic, ic->ic_reg_parm.cwmExtOffset);
    ic->ic_cwm_set_extprotmode(ic, ic->ic_reg_parm.cwmExtProtMode);
    ic->ic_cwm_set_extprotspacing(ic, ic->ic_reg_parm.cwmExtProtSpacing);

    ic->ic_cwm_set_enable(ic, ic->ic_reg_parm.cwmEnable);
    ic->ic_cwm_set_extbusythreshold(ic, ic->ic_reg_parm.cwmExtBusyThreshold);

    ic->ic_enable2GHzHt40Cap = ic->ic_reg_parm.enable2GHzHt40Cap;

    ic->ic_ignoreDynamicHalt = ic->ic_reg_parm.ignoreDynamicHalt;

    /* default to auto ADDBA mode */
    ic->ic_addba_mode = ADDBA_MODE_AUTO;
    wlan_pdev_set_addba_mode(ic->ic_pdev_obj, ADDBA_MODE_AUTO);

    if (ic->ic_reg_parm.ht20AdhocEnable) {
        /*
         * Support HT rates in Ad hoc connections.
         */
        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT20) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT20)) {
            ieee80211_ic_ht20Adhoc_set(ic);

            if (ic->ic_reg_parm.htAdhocAggrEnable) {
                ieee80211_ic_htAdhocAggr_set(ic);
            }
        }
    }

    if (ic->ic_reg_parm.ht40AdhocEnable) {
        /*
         * Support HT rates in Ad hoc connections.
         */
        if (IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40PLUS) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NA_HT40MINUS) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40PLUS) ||
            IEEE80211_SUPPORT_PHY_MODE(ic, IEEE80211_MODE_11NG_HT40MINUS)) {
            ieee80211_ic_ht40Adhoc_set(ic);

            if (ic->ic_reg_parm.htAdhocAggrEnable) {
                ieee80211_ic_htAdhocAggr_set(ic);
            }
        }
    }

    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_cw_timer), ic_cw_timeout,(void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    ic->ic_obss_nb_ru_tolerance_time = IEEE80211_OBSS_NB_RU_TOLERANCE_TIME_DEFVAL;
    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_obss_nb_ru_tolerance_timer), ieee80211_obss_nb_ru_tolerence_timeout, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
#if UMAC_SUPPORT_WNM
    /* Enable Host tracking of Max BSS Idle Timeout only for pre-lithium targets */
    if (target_psoc_get_target_type(psoc_info) < TARGET_TYPE_QCA8074) {
        OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_bssload_timer), ieee80211_bssload_timeout, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);
    }
#endif

    OS_INIT_TIMER(ic->ic_osdev, &(ic->ic_noise_stats), ieee80211_noise_stats_update, (void *) (ic), QDF_TIMER_TYPE_WAKE_APPS);

    qdf_timer_init(NULL, &ic->ic_csa_max_rx_wait_timer,
            ieee80211_csa_max_rx_wait_timer, (void *)(ic),
            QDF_TIMER_TYPE_WAKE_APPS);

    /* Initialization of traffic interval and traffic rate is 1800 and 300 seconds respectively */
    ic->traf_interval = DEFAULT_TRAFFIC_INTERVAL;
    ic->traf_rate = DEFAULT_TRAFFIC_RATE;
    ic->traf_bins = ic->traf_interval/ic->traf_rate;
    if (ic->ic_reg_parm.disable2040Coexist) {
        ieee80211com_set_flags(ic, IEEE80211_F_COEXT_DISABLE);
    } else {
        ieee80211com_clear_flags(ic, IEEE80211_F_COEXT_DISABLE);
    }

    /* setup other modules */

    /* The TSF Timer module is required when P2P or Off-channel support are required */
    ic->ic_tsf_timer = ieee80211_tsf_timer_attach(ic);

    ieee80211_p2p_attach(ic);
    ieee80211_node_attach(ic);
    ieee80211_proto_attach(ic);
    ieee80211_power_attach(ic);
    ieee80211_mlme_attach(ic);

#if ATH_SUPPORT_DFS
    ic->set_country = (struct assoc_sm_set_country*)qdf_mem_malloc(
            sizeof(struct assoc_sm_set_country));

    ATH_CREATE_WORK(&ic->dfs_cac_timer_start_work,
            ieee80211_dfs_cac_timer_start_async,
            (void *)ic);
    ATH_CREATE_WORK(&ic->assoc_sm_set_country_code,
            ieee80211_set_country_code_assoc_sm,
            (void *)ic);
    OS_INIT_TIMER(ic->ic_osdev,
            &(ic->ic_dfs_tx_rcsa_and_nol_ie_timer),
            ieee80211_dfs_tx_rcsa_task,
            (void *)(ic),
            QDF_TIMER_TYPE_WAKE_APPS);
    OS_INIT_TIMER(ic->ic_osdev,
            &(ic->ic_dfs_waitfor_csa_timer),
            ieee80211_dfs_waitfor_csa_task,
            (void *)(ic),
            QDF_TIMER_TYPE_WAKE_APPS);
#if QCA_DFS_NOL_VAP_RESTART
    OS_INIT_TIMER(ic->ic_osdev,
            &(ic->ic_dfs_nochan_vap_restart_timer),
            ieee80211_dfs_nochan_vap_restart,
            (void *)(ic),
            QDF_TIMER_TYPE_WAKE_APPS);
#endif
#endif /* ATH_SUPPORT_DFS */


    /*
     * By default overwrite probe response with beacon IE in scan entry.
     */
    ieee80211_ic_override_proberesp_ie_set(ic);

    ic->ic_resmgr = ieee80211_resmgr_create(ic, IEEE80211_RESMGR_MODE_SINGLE_CHANNEL);

#if ATH_ACS_DEBUG_SUPPORT
    ic->ic_acs_debug_support = 0;
#endif

    error = ieee80211_acs_attach(&(ic->ic_acs),
                          ic,
                          ic->ic_osdev);
    if (error) {
        /* detach and free already allocated memory for scan */
        ieee80211_node_detach(ic);
        return error;
    }

    error = ieee80211_cbs_attach(&(ic->ic_cbs),
                          ic,
                          ic->ic_osdev);
    if (error) {
        /* detach and free already allocated memory for scan */
        ieee80211_acs_detach(&(ic->ic_acs));
        ieee80211_node_detach(ic);
        return error;
    }

    ic->ic_notify_tx_bcn_mgr = ieee80211_notify_tx_bcn_attach(ic);
#if UMAC_SUPPORT_VI_DBG
    ieee80211_vi_dbg_attach(ic);
#endif
    ieee80211_quiet_attach(ic);
	ieee80211_admctl_attach(ic);

    /*
     * Perform steps that require multiple objects to be initialized.
     * For example, cross references between objects such as ResMgr and Scanner.
     */
    ieee80211_resmgr_create_complete(ic->ic_resmgr);

    ic->ic_get_ext_chan_info = ieee80211_get_extchaninfo;

#if ACFG_NETLINK_TX
    acfg_attach(ic);
#elif UMAC_SUPPORT_ACFG || UMAC_SUPPORT_ACFG_RECOVERY
    acfg_event_workqueue_init(ic->ic_osdev);
#endif
#if UMAC_SUPPORT_ACFG
    acfg_diag_attach(ic);
#endif

    ic->ic_chan_stats_th = IEEE80211_CHAN_STATS_THRESOLD;
    ic->ic_chan_switch_cnt = IEEE80211_RADAR_11HCOUNT;
    ic->ic_wb_subelem = 1;
    ic->ic_sec_offsetie = 1;

    /* initialization complete */
    ic->ic_initialized = 1;

    ic->ic_nr_share_radio_flag = 0;
    ic->ic_nr_share_enable = 0;
    if (ic->ic_cfg80211_config) {
        ic->ic_roaming = IEEE80211_ROAMING_MANUAL;
    }

    ic->ic_is_restart_on_same_chan = false;
    if (ic->ic_is_target_lithium(scn->soc->psoc_obj)) {
        ieee80211_user_rnr_init(ic);
    }

    ic->ic_mbss.ema_ext_enabled = scn->soc->ema_ap_ext_enabled;
    ic->ic_mbss.mbss_split_profile_enabled = scn->soc->mbss_split_profile_enabled;

    return 0;
#undef DEFAULT_TRAFFIC_INTERVAL
#undef DEFAULT_TRAFFIC_RATE
}

void
ieee80211_ifdetach(struct ieee80211com *ic)
{
    if (!ic->ic_initialized) {
        return;
    }

    /* Setting zero to aviod re-arming of ic_inact_timer timer */
    ic->ic_initialized = 0;

    /*
     * Preparation for detaching objects.
     * For example, remove and cross references between objects such as those
     * between ResMgr and Scanner.
     */
    ieee80211_resmgr_delete_prepare(ic->ic_resmgr);

    qdf_timer_free(&ic->ic_csa_max_rx_wait_timer);

    OS_FREE_TIMER(&ic->ic_inact_timer);
#if UMAC_SUPPORT_WNM
    OS_FREE_TIMER(&ic->ic_bssload_timer);
#endif

    OS_FREE_TIMER(&ic->ic_obss_nb_ru_tolerance_timer);

    OS_FREE_TIMER(&ic->ic_noise_stats);

#ifdef ATH_SUPPORT_DFS
    OS_CANCEL_TIMER(&ic->ic_dfs_tx_rcsa_and_nol_ie_timer);
    if(ic->ic_dfs_waitfor_csa_sched) {
        OS_CANCEL_TIMER(&ic->ic_dfs_waitfor_csa_timer);
        ic->ic_dfs_waitfor_csa_sched = 0;
    }
#endif

#if ATH_SUPPORT_DFS && QCA_DFS_NOL_VAP_RESTART
    OS_CANCEL_TIMER(&ic->ic_dfs_nochan_vap_restart_timer);
#endif

    /* all the vaps should have been deleted now */
    ASSERT(TAILQ_FIRST(&ic->ic_vaps) == NULL);

    ieee80211_node_detach(ic);
    ieee80211_quiet_detach(ic);
	ieee80211_admctl_detach(ic);

    ieee80211_proto_detach(ic);
    ieee80211_power_detach(ic);
    ieee80211_mlme_detach(ic);
    ieee80211_notify_tx_bcn_detach(ic->ic_notify_tx_bcn_mgr);
    ieee80211_resmgr_delete(ic->ic_resmgr);
    ieee80211_p2p_detach(ic);
    ieee80211_cbs_detach(&(ic->ic_cbs));
    ieee80211_acs_detach(&(ic->ic_acs));

    if( EOK != ieee80211_bsscolor_detach(ic)){
        qdf_print("%s: BSS Color detach failed ",__func__);
    }
#if UMAC_SUPPORT_VI_DBG
    ieee80211_vi_dbg_detach(ic);
#endif

#if UMAC_SUPPORT_ACFG
    acfg_diag_detach(ic);
#endif

#if ACFG_NETLINK_TX || UMAC_SUPPORT_ACFG_RECOVERY
    acfg_detach(ic);
#endif

    /* Detach TSF timer at the end to avoid assertion */
    if (ic->ic_tsf_timer) {
        ieee80211_tsf_timer_detach(ic->ic_tsf_timer);
        ic->ic_tsf_timer = NULL;
    }

#if QCA_SUPPORT_GPR
    if(ic->ic_gpr_enable) {
        qdf_hrtimer_kill(&ic->ic_gpr_timer);
        qdf_mem_free(ic->acfg_frame);
        ic->acfg_frame = NULL;
        qdf_err("\nStopping GPR timer as this is last vap with gpr \n");
    }
#endif

    spin_lock_destroy(&ic->ic_lock);
    spin_lock_destroy(&ic->ic_main_sta_lock);
    spin_lock_destroy(&ic->ic_addba_lock);
    IEEE80211_STATE_LOCK_DESTROY(ic);
    spin_lock_destroy(&ic->ic_beacon_alloc_lock);
    spin_lock_destroy(&ic->ic_diag_lock);
    spin_lock_destroy(&ic->ic_radar_found_lock);
    spin_lock_destroy(&ic->ic_radar_mode_switch_lock);
    qdf_spinlock_destroy(&ic->ic_channel_stats.lock);
}

/*
 * Start this IC
 */
void ieee80211_start_running(struct ieee80211com *ic)
{
    OS_SET_TIMER(&ic->ic_inact_timer, IEEE80211_INACT_WAIT*1000);
}

/*
 * Stop this IC
 */
void ieee80211_stop_running(struct ieee80211com *ic)
{
    OS_CANCEL_TIMER(&ic->ic_inact_timer);
}

int ieee80211com_register_event_handlers(struct ieee80211com *ic,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{
    int i;
    /* unregister if there exists one already */
    ieee80211com_unregister_event_handlers(ic,event_arg,evtable);
    IEEE80211_COMM_LOCK(ic);
    for (i=0;i<IEEE80211_MAX_DEVICE_EVENT_HANDLERS; ++i) {
        if ( ic->ic_evtable[i] == NULL) {
            ic->ic_evtable[i] = evtable;
            ic->ic_event_arg[i] = event_arg;
            IEEE80211_COMM_UNLOCK(ic);
            return 0;
        }
    }
    IEEE80211_COMM_UNLOCK(ic);
    return -ENOMEM;


}

int ieee80211com_unregister_event_handlers(struct ieee80211com *ic,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{
    int i;
    IEEE80211_COMM_LOCK(ic);
    for (i=0;i<IEEE80211_MAX_DEVICE_EVENT_HANDLERS; ++i) {
        if ( ic->ic_evtable[i] == evtable &&  ic->ic_event_arg[i] == event_arg) {
            ic->ic_evtable[i] = NULL;
            ic->ic_event_arg[i] = NULL;
            IEEE80211_COMM_UNLOCK(ic);
            return 0;
        }
    }
    IEEE80211_COMM_UNLOCK(ic);
    return -EEXIST;
}

/* Clear user defined ADDBA response codes for all nodes. */
static void
ieee80211_addba_clearresponse(void *arg, struct ieee80211_node *ni)
{
    struct ieee80211com *ic = (struct ieee80211com *) arg;
    ic->ic_addba_clearresponse(ni);
}

int wlan_device_register_event_handlers(wlan_dev_t devhandle,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{

    return ieee80211com_register_event_handlers(devhandle,event_arg,evtable);
}


int wlan_device_unregister_event_handlers(wlan_dev_t devhandle,
                                     void *event_arg,
                                     wlan_dev_event_handler_table *evtable)
{
    return ieee80211com_unregister_event_handlers(devhandle,event_arg,evtable);
}


int wlan_set_device_param(wlan_dev_t ic, ieee80211_device_param param, u_int32_t val)
{
    int retval=EOK;
    switch(param) {
    case IEEE80211_DEVICE_TX_CHAIN_MASK:
    case IEEE80211_DEVICE_TX_CHAIN_MASK_LEGACY:
	if(ic->ic_set_chain_mask(ic,param,val) == 0) {
            ic->ic_tx_chainmask = val;
            wlan_objmgr_update_txchainmask_to_allvdevs(ic);
        } else {
            retval=EINVAL;
        }
        break;
    case IEEE80211_DEVICE_RX_CHAIN_MASK:
    case IEEE80211_DEVICE_RX_CHAIN_MASK_LEGACY:
	if(ic->ic_set_chain_mask(ic,param,val) == 0) {
            ic->ic_rx_chainmask = val;
            wlan_objmgr_update_rxchainmask_to_allvdevs(ic);
        } else {
            retval=EINVAL;
        }
        break;

    case IEEE80211_DEVICE_PROTECTION_MODE:
        if (val > IEEE80211_PROT_RTSCTS) {
	    retval=EINVAL;
        } else {
	   ic->ic_protmode = val;
        }
        break;
    case IEEE80211_DEVICE_NUM_TX_CHAIN:
    case IEEE80211_DEVICE_NUM_RX_CHAIN:
    case IEEE80211_DEVICE_COUNTRYCODE:
       /* read only */
	retval=EINVAL;
        break;
    case IEEE80211_DEVICE_BMISS_LIMIT:
    	ic->ic_bmisstimeout = val * ic->ic_intval;
        break;
    case IEEE80211_DEVICE_GREEN_AP_ENABLE_PRINT:
        ic->ic_green_ap_set_print_level(ic, val);
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTMODE:
        if (val < IEEE80211_CWM_EXTPROTMAX) {
            ic->ic_cwm_set_extprotmode(ic, val);
        } else {
            retval = EINVAL;
        }
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTSPACING:
        if (val < IEEE80211_CWM_EXTPROTSPACINGMAX) {
            ic->ic_cwm_set_extprotspacing(ic, val);
        } else {
            retval = EINVAL;
        }
        break;
    case IEEE80211_DEVICE_CWM_ENABLE:
        ic->ic_cwm_set_enable(ic, val);
        break;
    case IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD:
        ic->ic_cwm_set_extbusythreshold(ic, val);
        break;
    case IEEE80211_DEVICE_DOTH:
        if (val == 0) {
            ieee80211_ic_doth_clear(ic);
        } else {
            ieee80211_ic_doth_set(ic);
        }
        break;
    case IEEE80211_DEVICE_ADDBA_MODE:
        ic->ic_addba_mode = val;
        wlan_pdev_set_addba_mode(ic->ic_pdev_obj, val);
        /*
        * Clear any user defined ADDBA response codes before switching modes.
        */
        wlan_mlme_iterate_node_list(ic, ieee80211_addba_clearresponse,
                                    (void *)ic,
                                    (IEEE80211_NODE_ITER_F_ASSOC_STA |
                                     IEEE80211_NODE_ITER_F_UNASSOC_STA));
        break;
    case IEEE80211_DEVICE_MULTI_CHANNEL:
        if (!val) {
            /* Disable Multi-Channel */
            retval = ieee80211_resmgr_setmode(ic->ic_resmgr, IEEE80211_RESMGR_MODE_SINGLE_CHANNEL);
        }
        else if (ic->ic_caps_ext & IEEE80211_CEXT_MULTICHAN) {
            retval = ieee80211_resmgr_setmode(ic->ic_resmgr, IEEE80211_RESMGR_MODE_MULTI_CHANNEL);
        }
        else {
            qdf_nofl_info("%s: Unable to enable Multi-Channel Scheduling since device/driver don't support it.\n", __func__);
            retval = EINVAL;
        }
        break;
    case IEEE80211_DEVICE_MAX_AMSDU_SIZE:
        ic->ic_amsdu_max_size = val;
        wlan_pdev_set_amsdu_max_size(ic->ic_pdev_obj, val);
        break;
#if ATH_SUPPORT_IBSS_HT
    case IEEE80211_DEVICE_HT20ADHOC:
        if (val == 0) {
            ieee80211_ic_ht20Adhoc_clear(ic);
        } else {
            ieee80211_ic_ht20Adhoc_set(ic);
        }
        break;
    case IEEE80211_DEVICE_HT40ADHOC:
        if (val == 0) {
            ieee80211_ic_ht40Adhoc_clear(ic);
        } else {
            ieee80211_ic_ht40Adhoc_set(ic);
        }
        break;
    case IEEE80211_DEVICE_HTADHOCAGGR:
        if (val == 0) {
            ieee80211_ic_htAdhocAggr_clear(ic);
        } else {
            ieee80211_ic_htAdhocAggr_set(ic);
        }
        break;
#endif /* end of #if ATH_SUPPORT_IBSS_HT */
    case IEEE80211_DEVICE_PWRTARGET:
        ieee80211com_set_curchanmaxpwr(ic, val);
        break;
    case IEEE80211_DEVICE_P2P:
        if (val == 0) {
            ieee80211_ic_p2pDevEnable_clear(ic);
        }
        else if (ic->ic_caps_ext & IEEE80211_CEXT_P2P) {
            ieee80211_ic_p2pDevEnable_set(ic);
        }
        else {
            qdf_nofl_info("%s: Unable to enable P2P since device/driver don't support it.\n", __func__);
            retval = EINVAL;
        }
        break;

    case IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE:
      if (val) {
          ieee80211_ic_override_proberesp_ie_set(ic);
      } else {
          ieee80211_ic_override_proberesp_ie_clear(ic);
      }
      break;
    case IEEE80211_DEVICE_2G_CSA:
        if (val == 0) {
            ieee80211_ic_2g_csa_clear(ic);
        } else {
            ieee80211_ic_2g_csa_set(ic);
        }
        break;

    default:
        qdf_nofl_info("%s: Error: invalid param=%d.\n", __func__, param);
    }
    return retval;

}

u_int32_t wlan_get_device_param(wlan_dev_t ic, ieee80211_device_param param)
{

    switch(param) {
    case IEEE80211_DEVICE_NUM_TX_CHAIN:
        return (ic->ic_num_tx_chain);
        break;
    case IEEE80211_DEVICE_NUM_RX_CHAIN:
        return (ic->ic_num_rx_chain);
        break;
    case IEEE80211_DEVICE_TX_CHAIN_MASK:
        return (ic->ic_tx_chainmask);
        break;
    case IEEE80211_DEVICE_RX_CHAIN_MASK:
        return (ic->ic_rx_chainmask);
        break;
    case IEEE80211_DEVICE_PROTECTION_MODE:
	return (ic->ic_protmode );
        break;
    case IEEE80211_DEVICE_BMISS_LIMIT:
    	return (ic->ic_bmisstimeout / ic->ic_intval);
        break;
    case IEEE80211_DEVICE_GREEN_AP_ENABLE_PRINT:
        return ic->ic_green_ap_get_print_level(ic);
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTMODE:
        return ic->ic_cwm_get_extprotmode(ic);
        break;
    case IEEE80211_DEVICE_CWM_EXTPROTSPACING:
        return ic->ic_cwm_get_extprotspacing(ic);
        break;
    case IEEE80211_DEVICE_CWM_ENABLE:
        return ic->ic_cwm_get_enable(ic);
        break;
    case IEEE80211_DEVICE_CWM_EXTBUSYTHRESHOLD:
        return ic->ic_cwm_get_extbusythreshold(ic);
        break;
    case IEEE80211_DEVICE_DOTH:
        return (ieee80211_ic_doth_is_set(ic));
        break;
    case IEEE80211_DEVICE_ADDBA_MODE:
        return ic->ic_addba_mode;
        break;
    case IEEE80211_DEVICE_COUNTRYCODE:
        return ieee80211_getCurrentCountry(ic);
        break;
    case IEEE80211_DEVICE_MULTI_CHANNEL:
        return (ieee80211_resmgr_getmode(ic->ic_resmgr)
                == IEEE80211_RESMGR_MODE_MULTI_CHANNEL);
        break;
    case IEEE80211_DEVICE_MAX_AMSDU_SIZE:
        return(ic->ic_amsdu_max_size);
        break;
#if ATH_SUPPORT_IBSS_HT
    case IEEE80211_DEVICE_HT20ADHOC:
        return (ieee80211_ic_ht20Adhoc_is_set(ic));
        break;
    case IEEE80211_DEVICE_HT40ADHOC:
        return (ieee80211_ic_ht40Adhoc_is_set(ic));
        break;
    case IEEE80211_DEVICE_HTADHOCAGGR:
        return (ieee80211_ic_htAdhocAggr_is_set(ic));
        break;
#endif /* end of #if ATH_SUPPORT_IBSS_HT */
    case IEEE80211_DEVICE_PWRTARGET:
        return (ieee80211com_get_curchanmaxpwr(ic));
        break;
    case IEEE80211_DEVICE_P2P:
        return (ieee80211_ic_p2pDevEnable_is_set(ic));
        break;
    case IEEE80211_DEVICE_OVERRIDE_SCAN_PROBERESPONSE_IE:
        return  ieee80211_ic_override_proberesp_ie_is_set(ic);
        break;
    case IEEE80211_DEVICE_2G_CSA:
        return (ieee80211_ic_2g_csa_is_set(ic));
        break;
    default:
        return 0;
    }
}

int wlan_get_device_mac_addr(wlan_dev_t ic, u_int8_t *mac_addr)
{
   IEEE80211_ADDR_COPY(mac_addr, ic->ic_myaddr);
   return EOK;
}

void wlan_device_note(struct ieee80211com *ic, const char *fmt, ...)
{
     char                   tmp_buf[OS_TEMP_BUF_SIZE];
     va_list                ap;
     va_start(ap, fmt);
     vsnprintf (tmp_buf,OS_TEMP_BUF_SIZE, fmt, ap);
     va_end(ap);
     qdf_nofl_info("%s",tmp_buf);
     ic->ic_log_text(ic,tmp_buf);
}

void wlan_get_vap_opmode_count(wlan_dev_t ic,
                               struct ieee80211_vap_opmode_count *vap_opmode_count)
{
    ieee80211_get_vap_opmode_count(ic, vap_opmode_count);
}

static void ieee80211_vap_iter_active_vaps(void *arg, struct ieee80211vap *vap)
{
    u_int16_t *pnactive = (u_int16_t *)arg;
       /* active vap check is used for assigning/updating vap channel with ic_curchan
	 so, it considers active vaps, and Vaps which are in CAC period */
    if (wlan_vdev_chan_config_valid(vap->vdev_obj) == QDF_STATUS_SUCCESS)
        ++(*pnactive);

}

static void ieee80211_vap_iter_vaps_up(void *arg, struct ieee80211vap *vap)
{
    u_int8_t *pnvaps_up = (u_int8_t *)arg;
    /* active vap check is used for assigning/updating vap channel with ic_curchan
       so, it considers active vaps, and Vaps which are in CAC period */
    if (vap->iv_opmode == IEEE80211_M_STA){
        if (wlan_vdev_chan_config_valid(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
            ++(*pnvaps_up);
        }
    } else {
        if (wlan_vdev_mlme_is_active(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
            ++(*pnvaps_up);
        }
    }
}

/* Returns the number of AP vaps up */
static void ieee80211_vap_iter_ap_vaps_up(void *arg, struct ieee80211vap *vap)
{
    u_int8_t *pnvaps_up = (u_int8_t *)arg;
    if ((wlan_vdev_mlme_is_active(vap->vdev_obj) == QDF_STATUS_SUCCESS)  &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP)) {
        ++(*pnvaps_up);
    }
}

/* Returns the number of STA vaps up */
static void ieee80211_vap_iter_sta_vaps_up(void *arg, struct ieee80211vap *vap)
{
    u_int8_t *pnvaps_up = (u_int8_t *)arg;
    if ((wlan_vdev_mlme_is_active(vap->vdev_obj) == QDF_STATUS_SUCCESS) &&
        (vap->iv_opmode == IEEE80211_M_STA)) {
        ++(*pnvaps_up);
    }
}

/*
 * returns number of vaps active.
 */
u_int16_t
ieee80211_vaps_active(struct ieee80211com *ic)
{
    u_int16_t nactive=0;
    wlan_iterate_vap_list_lock(ic,ieee80211_vap_iter_active_vaps,(void *) &nactive);
    return nactive;
}

/*
 * returns number of vaps active and up.
 */
u_int8_t
ieee80211_get_num_vaps_up(struct ieee80211com *ic)
{
    u_int8_t nvaps_up=0;

    if (ic)
        wlan_iterate_vap_list_lock(ic,
                ieee80211_vap_iter_vaps_up,(void *) &nvaps_up);

    return nvaps_up;
}

u_int32_t
ieee80211_get_rnr_count(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc;
    struct psoc_mlme_obj *mlme_psoc_priv_obj;
    struct wlan_6ghz_rnr_global_cache *rnr;
    u_int32_t rnr_cnt;

    if (!ic) {
        qdf_err("IC is NULL");
        return 0;
    }

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    if (!psoc) {
        qdf_err("Psoc is NULL");
        return 0;
    }
    mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(psoc);
    rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;
    rnr_cnt = rnr->rnr_cnt;

    return rnr_cnt;
}

void
ieee80211_display_rnr_stats(struct ieee80211com *ic)
{
    struct wlan_objmgr_psoc *psoc = NULL;
    struct psoc_mlme_obj *mlme_psoc_priv_obj = NULL;
    struct wlan_6ghz_rnr_global_cache *rnr = NULL;
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    u_int32_t rnr_cnt;
    u_int8_t *frm;
    u_int8_t count = 0;

    /* this function is invoked for 6 GHz radio */
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    if (!psoc) {
        qdf_err("psoc is NULL!!");
        return;
    }

    mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(psoc);

    if (!mlme_psoc_priv_obj) {
        qdf_err("mlme_psoc_priv_obj is NULL!!");
        return;
    }

    rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;
    rnr_cnt = rnr->rnr_cnt;

    frm = rnr->rnr_buf;

    frm += 2;
    /* Skip by Element Id and Element len */
    ap_info = (ieee80211_rnr_nbr_ap_info_t *)frm;
    tbtt_info = ap_info->tbtt_info;

    qdf_info("RNR NBR AP INFO RNR_CNT[%d] [HDR]:", rnr_cnt);
    qdf_info("   F_TYPE: %d, F_NBR_AP: %d, RESERV: %d, I_CNT: %d, I_LEN: %d",
             ap_info->hdr_field_type,
             ap_info->hdr_filtered_nbr_ap,
             ap_info->hdr_reserved,
             ap_info->hdr_info_cnt,
             ap_info->hdr_info_len);

    qdf_info("RNR NBR AP INFO [OP_CLASS, CHANNEL]: [0x%x, 0x%x]\n",
             ap_info->op_class, ap_info->channel);
    if (!rnr->rnr_cnt)
        return;

    while (count < rnr->rnr_cnt)
    {
        qdf_info(" RNR TBTT INFO SET [TBTT_OFFSET]: [0x%x]",
                 tbtt_info->tbtt_offset);
        qdf_info(" RNR TBTT INFO SET [BSSID]: [%pM]",
                 tbtt_info->bssid);
        qdf_info(" RNR TBTT INFO SET [S_SSID]: [0x%x]",
                 tbtt_info->short_ssid);
        qdf_info(" RNR TBTT INFO SET [BSS_PARAM]:");
        qdf_info("   OCT_REC: %d, S_SSID: %d, MBSSID_S: %d, TX_BSSID: %d",
                 tbtt_info->bss_params.oct_recommended,
                 tbtt_info->bss_params.same_ssid,
                 tbtt_info->bss_params.mbssid_set,
                 tbtt_info->bss_params.tx_bssid);
        qdf_info("   COLOC_LB: %d, PRB_R_20TU_A: %d, COLOC_AP: %d, RESERV: %d\n",
                 tbtt_info->bss_params.colocated_lower_band_ess,
                 tbtt_info->bss_params.probe_resp_20tu_active,
                 tbtt_info->bss_params.co_located_ap,
                 tbtt_info->bss_params.reserved);
        count++;
        tbtt_info++;
    }
}

/* ieee80211_vap_iter_beaconing_ap_vaps_up: iter function
 * to tell if AP is UP and beaconing
 * @arg: counter value to be updated
 * @vap: vap pointer of vap to check
 * Return: None
 */
static void ieee80211_vap_iter_beaconing_ap_vaps_up(void *arg, wlan_if_t vap)
{
    int *cnt = (int *)arg;
    if ((wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) &&
        ieee80211_mbss_is_beaconing_ap(vap)) {
        (*cnt)++;
    }
}

/* ieee80211_get_num_beaconing_ap_vaps_up: get count of AP VAPs
 * that are UP and HOSTAP and not special or monitor VAPs
 * @ic: ic handle
 * Return: count of beaconing AP vaps that are UP
 */
u_int8_t ieee80211_get_num_beaconing_ap_vaps_up(struct ieee80211com *ic)
{
    u_int8_t nvaps_up=0;
    wlan_iterate_vap_list_lock(ic,
                               ieee80211_vap_iter_beaconing_ap_vaps_up,
                               (void *) &nvaps_up);
    return nvaps_up;
}

/*
 * Returns number of ap vaps active and up.
 */
u_int8_t
ieee80211_get_num_ap_vaps_up(struct ieee80211com *ic)
{
    u_int8_t nvaps_up=0;
    wlan_iterate_vap_list_lock(ic,ieee80211_vap_iter_ap_vaps_up,(void *) &nvaps_up);
    return nvaps_up;
}

/*
 * Returns number of sta vaps active and up.
 */
u_int8_t ieee80211_get_num_sta_vaps_up(struct ieee80211com *ic)
{
    u_int8_t nvaps_up=0;
    wlan_iterate_vap_list_lock(ic, ieee80211_vap_iter_sta_vaps_up,
            (void *)&nvaps_up);
    return nvaps_up;
}

static void
ieee80211_iter_vap_opmode(void *arg, struct ieee80211vap *vaphandle)
{
    struct ieee80211_vap_opmode_count    *vap_opmode_count = arg;
    enum ieee80211_opmode                opmode = ieee80211vap_get_opmode(vaphandle);

    vap_opmode_count->total_vaps++;

    switch (opmode) {
    case IEEE80211_M_IBSS:
        vap_opmode_count->ibss_count++;
        break;

    case IEEE80211_M_STA:
        vap_opmode_count->sta_count++;
        break;

    case IEEE80211_M_WDS:
        vap_opmode_count->wds_count++;
        break;

    case IEEE80211_M_AHDEMO:
        vap_opmode_count->ahdemo_count++;
        break;

    case IEEE80211_M_HOSTAP:
        vap_opmode_count->ap_count++;
        break;

    case IEEE80211_M_MONITOR:
        vap_opmode_count->monitor_count++;
        break;

    case IEEE80211_M_BTAMP:
        vap_opmode_count->btamp_count++;
        break;

    default:
        vap_opmode_count->unknown_count++;

        qdf_nofl_info("%s vap=%pK unknown opmode=%d\n",
            __func__, vaphandle, opmode);
        break;
    }
}

void
ieee80211_get_vap_opmode_count(struct ieee80211com *ic,
                               struct ieee80211_vap_opmode_count *vap_opmode_count)
{
    wlan_iterate_vap_list_lock(ic, ieee80211_iter_vap_opmode, (void *) vap_opmode_count);
}

static void
ieee80211_vap_iter_associated(void *arg, struct ieee80211vap *vap)
{
    u_int8_t *pis_sta_associated = (u_int8_t *)arg;
    if (vap->iv_opmode == IEEE80211_M_STA) {
        if (wlan_vdev_allow_connect_n_tx(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
                (*pis_sta_associated) = 1;
        }
    }
}

/*
 * returns 1 if STA vap is not in associated state else 0
 */
u_int8_t
ieee80211_sta_assoc_in_progress(struct ieee80211com *ic)
{
    u_int8_t in_progress = 0;
    struct ieee80211_vap_opmode_count vap_opmode_count;

    OS_MEMZERO(&vap_opmode_count, sizeof(vap_opmode_count));
    ieee80211_get_vap_opmode_count(ic, &vap_opmode_count);
    if (vap_opmode_count.sta_count) {
        u_int8_t is_sta_associated = 0;

        wlan_iterate_vap_list_lock(ic,ieee80211_vap_iter_associated,(void *) &is_sta_associated);
        if (!is_sta_associated)
            in_progress = 1;
    }

    return in_progress;
}

struct ieee80211_iter_vaps_ready_arg {
    u_int8_t num_sta_vaps_ready;
    u_int8_t num_ibss_vaps_ready;
    u_int8_t num_ap_vaps_ready;
};

static void ieee80211_vap_iter_ready_vaps(void *arg, wlan_if_t vap)
{
    struct ieee80211_iter_vaps_ready_arg *params = (struct ieee80211_iter_vaps_ready_arg *) arg;
    if (wlan_vdev_is_up(vap->vdev_obj) == QDF_STATUS_SUCCESS) {
        switch(ieee80211vap_get_opmode(vap)) {
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_BTAMP:
            params->num_ap_vaps_ready++;
            break;

        case IEEE80211_M_IBSS:
            params->num_ibss_vaps_ready++;
            break;

        case IEEE80211_M_STA:
            params->num_sta_vaps_ready++;
            break;

        default:
            break;

        }
    }
}

/*
 * returns number of vaps ready.
 */
u_int16_t
ieee80211_vaps_ready(struct ieee80211com *ic, enum ieee80211_opmode opmode)
{
    struct ieee80211_iter_vaps_ready_arg params;
    u_int16_t nready = 0;
    OS_MEMZERO(&params, sizeof(params));
    wlan_iterate_vap_list_lock(ic,ieee80211_vap_iter_ready_vaps,(void *) &params);
    switch(opmode) {
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_BTAMP:
            nready = params.num_ap_vaps_ready;
            break;

        case IEEE80211_M_IBSS:
            nready = params.num_ibss_vaps_ready;
            break;

        case IEEE80211_M_STA:
            nready = params.num_sta_vaps_ready;
            break;

        default:
            break;
    }
    return nready;
}

static struct ath_fips_cmd* ol_ath_set_default_disa_buf(void)
{
    struct ath_fips_cmd *fips_buf = NULL;
    u_int8_t default_key[] = { 0xc9, 0x7c, 0x1f, 0x67,
                               0xce, 0x37, 0x11, 0x85,
                               0x51, 0x4a, 0x8a, 0x19,
                               0xf2, 0xbd, 0xd5, 0x2f
                             };
    u_int8_t default_pn[] = {0xB5, 0x03, 0x97, 0x76, 0xE7, 0x0C};
    u_int8_t default_mac_header[] = { 0x08, 0x48, 0xc3, 0x2c,
                                      0x0f, 0xd2, 0xe1, 0x28,
                                      0xa5, 0x7c, 0x50, 0x30,
                                      0xf1, 0x84, 0x44, 0x08,
                                      0xab, 0xae, 0xa5, 0xb8,
                                      0xfc, 0xba, 0x80, 0x33,
                                      0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00
                                    };
    u_int8_t default_payload[] = { 0xf8, 0xba, 0x1a, 0x55,
                                   0xd0, 0x2f, 0x85, 0xae,
                                   0x96, 0x7b, 0xb6, 0x2f,
                                   0xb6, 0xcd, 0xa8, 0xeb,
                                   0x7e, 0x78, 0xa0, 0x50
                                 };

    fips_buf = (struct ath_fips_cmd *) qdf_mem_malloc(sizeof(struct ath_fips_cmd)
                + (sizeof(default_payload) - sizeof(u_int32_t)));
    if (!fips_buf)  {
        return NULL;
    }
    fips_buf->fips_cmd = 1;    /* 1 - encrypt/ 2 - decrypt*/
    fips_buf->mode = 2;
    fips_buf->key_idx = 0;
    fips_buf->key_cipher = 4;
    fips_buf->key_len = sizeof(default_key);
    memcpy(fips_buf->key, default_key, fips_buf->key_len);
    fips_buf->header_len = sizeof(default_mac_header);
    memcpy(fips_buf->header, default_mac_header, fips_buf->header_len);
    memcpy(fips_buf->pn, default_pn, sizeof(default_pn));
    fips_buf->data_len = sizeof(default_payload);
    memcpy(fips_buf->data, default_payload, fips_buf->data_len);

    return fips_buf;
}

static struct ath_fips_cmd* ol_ath_set_default_fips_buf(void)
{
    struct ath_fips_cmd *fips_buf = NULL;
    u_int8_t default_key[] =  { 0x2b, 0x7e, 0x15, 0x16,
                                0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88,
                                0x09, 0xcf, 0x4f, 0x3c
                              };
    u_int8_t default_data[] = { 0xf0, 0xf1, 0xf2, 0xf3,
                                0xf4, 0xf5, 0xf6, 0xf7,
                                0xf8, 0xf9, 0xfa, 0xfb,
                                0xfc, 0xfd, 0xfe, 0xff
                              };
    u_int8_t default_iv[] =   { 0xf0, 0xf1, 0xf2, 0xf3,
                                0xf4, 0xf5, 0xf6, 0xf7,
                                0xf8, 0xf9, 0xfa, 0xfb,
                                0xfc, 0xfd, 0xfe, 0xff
                              };
    fips_buf = (struct ath_fips_cmd *) qdf_mem_malloc(sizeof(struct ath_fips_cmd)
                + (sizeof(default_data) - sizeof(u_int32_t)));
    if (!fips_buf)  {
        return NULL;
    }
    fips_buf->fips_cmd = 1;    /* 1 - encrypt/ 2 - decrypt*/
    fips_buf->mode = 1;
    fips_buf->key_len = sizeof(default_key);
    memcpy(fips_buf->key, default_key, fips_buf->key_len);
    fips_buf->data_len = sizeof(default_data);
    memcpy(fips_buf->data, default_data, fips_buf->data_len);
    memcpy(fips_buf->iv, default_iv, sizeof(default_iv));
    return fips_buf;
}

int wlan_set_fips(wlan_if_t vap, void *args)
{

    struct ath_fips_cmd *fips_buf = (struct ath_fips_cmd *)args;
    struct ieee80211com *ic = vap->iv_ic;
    int retval = -1;

    if (!ic || !ic->ic_fips_test) {
        qdf_nofl_info("\n %s:%d fips_test function not supported", __func__, __LINE__);
        return -EINVAL;
    }

    if (fips_buf != NULL) {
        if (fips_buf->mode == 1) {
            if((fips_buf->key == NULL) | (fips_buf->data == NULL) |
                   (fips_buf->iv == NULL)) {
                qdf_nofl_info("\n %s:%d fips input missing", __func__, __LINE__);
                return -EINVAL;
            }
        } else if (fips_buf->mode == 2) {
            if ((fips_buf->key == NULL) | (fips_buf->header == NULL) |
                    (fips_buf->pn == NULL) | (fips_buf->data == NULL)) {
                qdf_nofl_info("\n %s:%d disa input missing", __func__, __LINE__);
                return -EINVAL;
            }
        }
    }
    retval = ic->ic_fips_test(ic, vap, fips_buf);
    return retval;
}


static QDF_STATUS config_cmd_resp_show(qdf_debugfs_file_t file, void *arg)
{
    int index;
    int pos, count = MAX_CONFIG_COMMAND;
    uint64_t secs, usecs;
    config_cmd_log_cxt_t* config_cmd_cxt = (config_cmd_log_cxt_t*)arg;

    if(!config_cmd_cxt->init_flag)
        return QDF_STATUS_E_FAILURE;

    qdf_semaphore_acquire(&config_cmd_cxt->entry_lock);

    if(config_cmd_cxt->entry_count == 0) {
        qdf_semaphore_release(&config_cmd_cxt->entry_lock);
        qdf_debugfs_printf(file, "No entries in buffer\n");
        return QDF_STATUS_SUCCESS;
    }

    index = config_cmd_cxt->entry_index;
    if(config_cmd_cxt->entry_count < MAX_CONFIG_COMMAND){
        pos = index - 1;
        count = config_cmd_cxt->entry_count;
    } else {
        if(index == 0)
            pos = MAX_CONFIG_COMMAND - 1;
        else
            pos = index - 1;
    }

    /* Iterate through circular buffer and print entries*/
    while(count){
        config_entry_t* entry = &config_cmd_cxt->entry[pos];

        qdf_log_timestamp_to_secs(entry->time, &secs, &usecs);
        qdf_debugfs_printf(file, "\n TIME = [%llu.%06llu]\n",
                           secs, usecs);
        if(entry->type == CONFIG_TYPE_CMD)
            qdf_debugfs_printf(file, "CMD ");
        else if(entry->type == CONFIG_TYPE_RESP)
            qdf_debugfs_printf(file, "RESP ");

        qdf_debugfs_printf(file, "%s param %d val %d\n", entry->interface,
                           entry->param, entry->val);

        /* Reached the end, roll over */
        if(pos == 0)
            pos = MAX_CONFIG_COMMAND - 1;
        else
            pos--;

        count--;
    }

    qdf_semaphore_release(&config_cmd_cxt->entry_lock);

    return QDF_STATUS_SUCCESS;
}

void config_cmd_resp_log(ol_ath_soc_softc_t *soc, uint8_t type, char* interface, int id, int val)
{
    int index;
    config_entry_t* entry;
    config_cmd_log_cxt_t* config_cmd_cxt = &soc->config_cmd_cxt;

    if(!config_cmd_cxt->init_flag)
        return;

    qdf_semaphore_acquire(&config_cmd_cxt->entry_lock);
    index = config_cmd_cxt->entry_index;

    if(index == MAX_CONFIG_COMMAND) {
        index = 0;
        /* Reached end of circular buffer */
        config_cmd_cxt->entry_index = 0;
    }

    entry = &config_cmd_cxt->entry[index];

    entry->type = type;
    entry->param = id;
    entry->val = val;
    snprintf(entry->interface, sizeof(entry->interface), interface);
    entry->time = qdf_get_log_timestamp();

    config_cmd_cxt->entry_index++;
    config_cmd_cxt->entry_count++;
    qdf_semaphore_release(&config_cmd_cxt->entry_lock);
}

qdf_export_symbol(config_cmd_resp_log);

void config_cmd_resp_init(ol_ath_soc_softc_t *soc)
{
    char file[32];
    char dir[32];
    qdf_dentry_t ret;
    int  perm = (QDF_FILE_USR_READ | QDF_FILE_GRP_READ | QDF_FILE_OTH_READ);
    config_cmd_log_cxt_t* config_cmd_cxt = &soc->config_cmd_cxt;

    /* Check if feature is supported */
    config_cmd_cxt->feature_init = cfg_get(soc->psoc_obj, CFG_COMMAND_LOGGING_SUPPORT);
    if (!config_cmd_cxt->feature_init)
        return;

    config_cmd_cxt->entry = qdf_mem_malloc(sizeof(config_entry_t)*MAX_CONFIG_COMMAND);
    if(!config_cmd_cxt->entry)
        return;

    snprintf(dir, sizeof(dir), "CONFIG");
    snprintf(file, sizeof(file), "cmdresp");

    config_cmd_cxt->config_log_debugfs_dir = qdf_debugfs_create_dir(dir, NULL);

    config_cmd_cxt->ops.show = config_cmd_resp_show;
    config_cmd_cxt->ops.priv = config_cmd_cxt;

    ret = qdf_debugfs_create_file_simplified(file, perm,
                    config_cmd_cxt->config_log_debugfs_dir,
                    &config_cmd_cxt->ops);

    qdf_semaphore_init(&config_cmd_cxt->entry_lock);
    config_cmd_cxt->init_flag = 1;
}

void config_cmd_resp_deinit(ol_ath_soc_softc_t *soc)
{
    config_cmd_log_cxt_t* config_cmd_cxt = &soc->config_cmd_cxt;

    if(!config_cmd_cxt->init_flag)
        return;

    qdf_mem_free(config_cmd_cxt->entry);
    qdf_debugfs_remove_dir_recursive(config_cmd_cxt->config_log_debugfs_dir);
    qdf_semaphore_release(&config_cmd_cxt->entry_lock);
}
qdf_export_symbol(config_cmd_resp_init);
qdf_export_symbol(config_cmd_resp_deinit);

void wlan_find_vdev_by_bssid_pdev_cb(struct wlan_objmgr_psoc *psoc,
                void *msg,
                uint8_t index)
{
    struct wlan_objmgr_psoc_objmgr *psoc_objmgr;
    struct wlan_objmgr_pdev *pdev = NULL;
    int id = 0;
    wlan_dev_t ic;
    struct vdev_bssid_obj *vdev_bssid = (struct vdev_bssid_obj *)msg;

    psoc_objmgr = &psoc->soc_objmgr;
    /* Get pdev from pdev list */
    for (id=0;id<WLAN_UMAC_MAX_PDEVS;id++) {
        pdev = psoc_objmgr->wlan_pdev_list[id];
        if (pdev) {
            ic = wlan_pdev_get_mlme_ext_obj(pdev);
            if (ic && IEEE80211_IS_CHAN_6GHZ(ic->ic_curchan)) {
                vdev_bssid->vdev = wlan_objmgr_get_vdev_by_macaddr_from_pdev(pdev,
                                       vdev_bssid->bssid, WLAN_MLME_NB_ID);
                break;
            }
        }
    }
}

struct wlan_objmgr_vdev *wlan_find_vdev_from_psocs_by_macaddr(uint8_t* bssid)
{
    struct vdev_bssid_obj vdev_bssid;

    qdf_mem_copy(vdev_bssid.bssid, bssid, QDF_MAC_ADDR_SIZE);
    vdev_bssid.vdev = NULL;

    wlan_objmgr_iterate_psoc_list(wlan_find_vdev_by_bssid_pdev_cb, &vdev_bssid, WLAN_MLME_NB_ID);

    return vdev_bssid.vdev;
}

QDF_STATUS wlan_pdev_wait_to_bringdown_all_vdevs(struct ieee80211com *ic,
                                                 enum bring_updown_mode mode)
{
    qdf_bitmap(bringdown_pend_vdev_arr, WLAN_UMAC_PSOC_MAX_VDEVS);
    struct wlan_objmgr_pdev *pdev = ic->ic_pdev_obj;
    uint16_t waitcnt;
    qdf_event_t wait_event;

    qdf_mem_zero(&wait_event, sizeof(wait_event));

    qdf_event_create(&wait_event);
    qdf_event_reset(&wait_event);

    /* wait for vap stop event before letting the caller go */
    waitcnt = 0;
    while(waitcnt < OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
        /* Reset the bitmap */
        qdf_mem_zero(bringdown_pend_vdev_arr,
                     sizeof(bringdown_pend_vdev_arr));

        if (mode == ALL_AP_VDEVS) {
              wlan_pdev_chan_change_pending_ap_vdevs_down(pdev,
                      bringdown_pend_vdev_arr,
                      WLAN_MLME_SB_ID);
        }
        else {
              wlan_pdev_chan_change_pending_vdevs_down(pdev,
                      bringdown_pend_vdev_arr,
                      WLAN_MLME_SB_ID);
        }

        /* If all the pending vdevs goes down, this would fail,
           otherwise start timer */
        if (!wlan_util_map_is_any_index_set(bringdown_pend_vdev_arr,
                                            sizeof(bringdown_pend_vdev_arr)))
            return QDF_STATUS_SUCCESS;

        qdf_wait_single_event(&wait_event, OSIF_STOP_VAP_TIMEOUT);

        waitcnt++;
    }
    qdf_event_destroy(&wait_event);

    if (waitcnt >= OSIF_MAX_STOP_VAP_TIMEOUT_CNT) {
        qdf_err("VDEVs are not stopped, bitmap is as follows");
        qdf_trace_hex_dump(
                QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_ERROR,
                bringdown_pend_vdev_arr, sizeof(bringdown_pend_vdev_arr));
    }

    if (ic->recovery_in_progress) {
        qdf_err("FW Crash observed ...returning");
        return QDF_STATUS_E_INVAL;
    }

    return QDF_STATUS_SUCCESS;
}
qdf_export_symbol(wlan_pdev_wait_to_bringdown_all_vdevs);

int ieee80211_bringup_all_vaps(struct ieee80211com *ic,
                               enum bring_updown_mode mode)
{
    wlan_if_t tmpvap;
    struct net_device *tmpdev = NULL;
    int retval = EOK;

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if ((mode == ALL_AP_VDEVS) &&
            (tmpvap->iv_opmode != IEEE80211_M_HOSTAP)) {
                continue;
        }

        tmpdev = ((osif_dev *)tmpvap->iv_ifp)->netdev;
        if (tmpvap->iv_opmode == IEEE80211_M_STA) {
            retval = IS_UP(tmpdev) ?
                     wlan_mlme_cm_start(tmpvap->vdev_obj, CM_OSIF_CONNECT) : 0;
        } else {
            retval = (IS_UP(tmpdev) && (tmpvap->iv_novap_reset == 0)) ?
                       wlan_mlme_start_vdev(tmpvap->vdev_obj, 0, WLAN_MLME_NOTIFY_NONE) : 0;
        }

        if (retval) {
            qdf_err("Could not bring up vdev %d", tmpvap->iv_unit);
            break;
        }
    }

    return retval;
}

int ieee80211_bringdown_all_vaps(struct ieee80211com *ic,
                                 enum bring_updown_mode mode)
{
    struct ieee80211vap *tmpvap = NULL;
    int retval = EOK;

    TAILQ_FOREACH(tmpvap, &ic->ic_vaps, iv_next) {
        if ((mode == ALL_AP_VDEVS) &&
            (tmpvap->iv_opmode != IEEE80211_M_HOSTAP)) {
                continue;
        }

        if (tmpvap->iv_opmode == IEEE80211_M_STA) {
            retval = wlan_mlme_cm_stop(tmpvap->vdev_obj, CM_OSIF_CFG_DISCONNECT,
                                       REASON_STA_LEAVING, false);
        } else {
            retval = wlan_mlme_stop_vdev(tmpvap->vdev_obj, 0, 0);
        }

        if (retval) {
             qdf_err("Could not stop vdev %d", tmpvap->iv_unit);
             break;
        }
     }

    if (!retval && wlan_pdev_wait_to_bringdown_all_vdevs(ic, mode)) {
        qdf_err("Could not bring down VAPs");
        retval = -EINVAL;
    }

    if (!retval &&
        (((mode == ALL_AP_VDEVS) && ieee80211_get_num_ap_vaps_up(ic)) ||
         ((mode == ALL_VDEVS) && ieee80211_get_num_vaps_up(ic)))) {
        qdf_err("VAPs are still active");
        retval = -EINVAL;
    }

    return retval;
}

/* wlan_fetch_inter_soc_rnr_cache: Find a valid RNR cache by doing
 *  * lookup across all SoCs and return valid rnr cache
 *   *
 *    * @rnr: RNR cache associated with any SoC
 *     */
void wlan_fetch_inter_soc_rnr_cache(void *rnr)
{
    uint8_t index = 0;
    struct wlan_6ghz_rnr_global_cache **psoc_rnr;
    struct psoc_mlme_obj *mlme_psoc_priv_obj;

    psoc_rnr = (struct wlan_6ghz_rnr_global_cache **)rnr;
    while (index < WLAN_OBJMGR_MAX_DEVICES) {
        if (g_umac_glb_obj->psoc[index]) {
            mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(g_umac_glb_obj->psoc[index]);
            if (mlme_psoc_priv_obj) {
                *psoc_rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;
                if (*psoc_rnr && (*psoc_rnr)->rnr_cnt > 0){
                    break;
                }
	    }
        }
        index++;
    }
}

/**
 * wlan_update_6ghz_rnr_cache: Add 6Ghz AP info to RNR IE cache
 *
 * @vap: 6Ghz Vap to be added to cache
 * @is_vap_add: Indicate if vap is being added or change in RNR IE field
 *              1 - new vap added
 *              0 - Existing vap info change
 */
int wlan_update_6ghz_rnr_cache(struct ieee80211vap *vap, uint8_t is_vap_add)
{
    struct wlan_objmgr_psoc *psoc;
    struct ieee80211com *ic = vap->iv_ic;
    struct psoc_mlme_obj *mlme_psoc_priv_obj;
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    uint8_t *frm;
    uint8_t *org_frm;
    struct wlan_6ghz_rnr_global_cache *rnr;
    int count = 1;
    uint16_t chwidth, behav_lim;
    bool global_lookup = false;
    uint8_t op_class, prim_chan;
    bool is_psd_pwr;
    uint16_t max_reg_psd_pwr;
    uint16_t max_reg_eirp_psd_pwr;

    if (!ic) {
        qdf_debug("IC is NULL");
        return -1;
    }
    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);

    if (!psoc) {
        qdf_debug("Psoc is NULL");
        return -1;
    }
    mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(psoc);
    rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;
    frm = rnr->rnr_buf;
    org_frm = frm;

    /* Skip by Element Id and Element len */
    frm+=2;
    ap_info = (ieee80211_rnr_nbr_ap_info_t *)frm;

    wlan_get_bw_and_behav_limit(ic->ic_curchan,
                        &chwidth, &behav_lim);
    wlan_reg_freq_width_to_chan_op_class_auto(ic->ic_pdev_obj,
                        ic->ic_curchan->ic_freq, chwidth,
                        global_lookup, behav_lim,
                        &op_class, &prim_chan);
    tbtt_info = ap_info->tbtt_info;
    ap_info->op_class = op_class;
    ap_info->channel = prim_chan;

     if (!is_vap_add) {
       while (count <= rnr->rnr_cnt) {
           if (!vap->iv_he_6g_bcast_prob_rsp) {
               tbtt_info->bss_params.probe_resp_20tu_active = 0;
           } else {
               tbtt_info->bss_params.probe_resp_20tu_active =
                   ic->ic_6ghz_rnr_unsolicited_prb_resp_active;
           }
           count++;
           tbtt_info++;
       }
       return 0;
    }

   if (rnr->rnr_cnt < RNR_MAX_VAP_ADVERTISED) {
        tbtt_info += rnr->rnr_cnt;
    } else {
        qdf_debug("%s:%d: RNR Cache full", __func__, __LINE__);
        return -1;
    }
    tbtt_info->tbtt_offset = RNR_TBTT_OFFSET_UNKNOWN;
    IEEE80211_ADDR_COPY(tbtt_info->bssid, vap->iv_myaddr);
    tbtt_info->short_ssid = htole32(ieee80211_construct_shortssid(vap->iv_bss->ni_essid,
                    vap->iv_bss->ni_esslen));
    tbtt_info->bss_params.oct_recommended = 0;
    tbtt_info->bss_params.same_ssid = 0;
    tbtt_info->bss_params.mbssid_set = 0;
    if (ic && wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj, WLAN_PDEV_F_MBSS_IE_ENABLE)) {
        tbtt_info->bss_params.mbssid_set = 1;
    }
    tbtt_info->bss_params.tx_bssid = ((IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) ? 0 : 1);
    tbtt_info->bss_params.colocated_lower_band_ess = 0;
    tbtt_info->bss_params.co_located_ap = 1;

    wlan_reg_get_client_power_for_6ghz_ap(ic->ic_pdev_obj,
                                          REG_DEFAULT_CLIENT,
                                          ic->ic_curchan->ic_freq,
                                          &is_psd_pwr, &max_reg_psd_pwr,
                                          &max_reg_eirp_psd_pwr);

    if (is_psd_pwr) {
        tbtt_info->psd_20mhz = max_reg_eirp_psd_pwr * 2;
    } else {
        tbtt_info->psd_20mhz = REG_PSD_MAX_TXPOWER_FOR_DEFAULT_CLIENT * 2;
    }

    tbtt_info->bss_params.probe_resp_20tu_active = ic->ic_6ghz_rnr_unsolicited_prb_resp_active;

    if (rnr->rnr_cnt == 0) {
        ap_info->op_class = op_class;
        ap_info->channel = prim_chan;
        ap_info->hdr_field_type = 0;
        ap_info->hdr_filtered_nbr_ap = 0;
        ap_info->hdr_info_len = sizeof (ieee80211_rnr_tbtt_info_set_t);
    }

    rnr->rnr_cnt++;
    ap_info->hdr_info_cnt = rnr->rnr_cnt - 1;
    *org_frm = IEEE80211_ELEMID_REDUCED_NBR_RPT;
    *(org_frm+1) = rnr->rnr_cnt * sizeof(ieee80211_rnr_tbtt_info_set_t) +
                   sizeof (ieee80211_rnr_nbr_ap_info_t);
    /* RNR size has length of neighbor AP field and NOT element id + length field itself */
    rnr->rnr_size = *(org_frm + 1);

    return 0;
}

/**
 * wlan_remove_vap_from_6ghz_rnr_cache: Remove 6Ghz AP info from RNR IE cache
 *
 * @vap: 6Ghz Vap to be removed from cache
 */
int wlan_remove_vap_from_6ghz_rnr_cache(struct ieee80211vap *vap)
{
    struct wlan_objmgr_psoc *psoc;
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_rnr_nbr_ap_info_t *ap_info = NULL;
    ieee80211_rnr_tbtt_info_set_t *tbtt_info = NULL;
    struct psoc_mlme_obj *mlme_psoc_priv_obj;
    uint8_t *frm;
    uint8_t *org_frm;
    struct wlan_6ghz_rnr_global_cache *rnr;
    int count = 1;

    psoc = wlan_pdev_get_psoc(ic->ic_pdev_obj);
    mlme_psoc_priv_obj = wlan_get_psoc_mlme_obj(psoc);
    rnr = &mlme_psoc_priv_obj->rnr_6ghz_cache;
    frm = rnr->rnr_buf;
    org_frm = frm;

    /* Skip by Element Id and Element len */
    frm+=2;
    ap_info = (ieee80211_rnr_nbr_ap_info_t *)frm;
    tbtt_info = ap_info->tbtt_info;

    if (rnr->rnr_cnt == 0) {
        qdf_debug("%s:%d: No Vaps in RNR to delete", __func__, __LINE__);
        return -1;
    }

    while (count <= rnr->rnr_cnt)
    {
        if (!IEEE80211_ADDR_EQ(vap->iv_myaddr, tbtt_info->bssid)) {
            tbtt_info++;
            count ++;
        } else {
            OS_MEMZERO(tbtt_info, sizeof(ieee80211_rnr_tbtt_info_set_t));
            OS_MEMCPY(tbtt_info, tbtt_info+1,
                      (rnr->rnr_cnt - count) *
                      sizeof(ieee80211_rnr_tbtt_info_set_t));
            rnr->rnr_cnt--;
            rnr->rnr_size -= TBTT_INFO_FIELD_SIZE;
            ap_info->hdr_info_cnt = rnr->rnr_cnt - 1;
            break;
        }
    }
    /* Update overall IE size without element id and length fields */
    *(org_frm+1) -= TBTT_INFO_FIELD_SIZE;
    return 0;
}

uint8_t num_chain_from_chain_mask(uint32_t mask)
{
    uint8_t num_rf_chain = 0;
    mask &= 0xFF;

    while (mask) {
        if (mask & 0x1)
            num_rf_chain++;

        mask >>= 1;
    }

    return num_rf_chain;
}
qdf_export_symbol(num_chain_from_chain_mask);

void ieee80211_reset_user_rnr_list(struct ieee80211com *ic)
{
    struct user_rnr_data *user_rnr_uid;

    TAILQ_FOREACH(user_rnr_uid, &(ic->ic_user_neighbor_ap.user_rnr_data_list), user_rnr_next_uid) {
        user_rnr_uid->is_copied = false;
        user_rnr_uid->uid_ap_remaining = 0;
        user_rnr_uid->uid_ap_copied_cnt = 0;
    }
}

/*
 * ieee80211_get_first_ap_vap_iter_func:
 * Iteration function for finding the first AP VAP (capable of beaconing)
 * and/or the first AP VAP (capable of beaconing) which is UP as per the
 * netdevice flag
 *
 * @pdev  : Pointer to the PDEV structure
 * @object: Opaque handle to the current VAP
 * @arg   : Opaque handle to VAP list to populate
 *
 */
#define VAPLIST_FIRST_VAP 0
#define VAPLIST_FIRST_UP_VAP 1
#define VAPLIST_MAX_SIZE 2
static void ieee80211_get_first_ap_vap_iter_func(struct wlan_objmgr_pdev *pdev,
                                                 void *object,
                                                 void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
    struct ieee80211vap *vap = NULL;
    struct ieee80211vap **vap_list = (struct ieee80211vap **)arg;
    struct net_device *dev = NULL;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || !ieee80211_mbss_is_beaconing_ap(vap)) {
        return;
    }

    if (!vap_list[VAPLIST_FIRST_VAP]) {
        vap_list[VAPLIST_FIRST_VAP] = vap;
    }

    if (vap_list[VAPLIST_FIRST_UP_VAP]) {
        return;
    }

    dev = ((osif_dev *)vap->iv_ifp)->netdev;
    if (!dev) {
        return;
    }

    if (IS_UP(dev)) {
        vap_list[VAPLIST_FIRST_UP_VAP] = vap;
    }

    return;
}

/*
 * ieee80211_mbss_get_first_ap_vap:
 * Find the first AP VAP capable of beaconing in the list or the first AP
 * VAP which is marked as UP in the netdevice structure.
 *
 * @ic: Pointer to the ic structure
 * @first_first_up: Flag to find the first UP VAP.
 *
 * Return:
 * NULL: Could not find any VAP in the list
 * Else: Found either first UP VAP or the first VAP in the list
 */
struct ieee80211vap *ieee80211_mbss_get_first_ap_vap(struct ieee80211com *ic,
                                         bool find_first_up)
{
    struct ieee80211vap *vap_list[VAPLIST_MAX_SIZE] = {0};

    wlan_objmgr_pdev_iterate_obj_list(ic->ic_pdev_obj, WLAN_VDEV_OP,
                                      ieee80211_get_first_ap_vap_iter_func,
                                      vap_list, 0, WLAN_MLME_SB_ID);

    if (find_first_up && vap_list[VAPLIST_FIRST_UP_VAP]) {
        return vap_list[VAPLIST_FIRST_UP_VAP];
    } else if (vap_list[VAPLIST_FIRST_VAP]) {
        return vap_list[VAPLIST_FIRST_VAP];
    }

    return NULL;
}

/*
 * ieee80211_mbss_update_iter_func:
 * Iterate function per-VAP for update VAP parameters for EMA mode during
 * mode switching operations.
 *
 * @pdev  : Pointer to the PDEV structure
 * @object: Opaque handle to the VAP
 * @arg   : Opaque handle to the return value
 *
 * Return:
 * QDF_STATUS_SUCCESS: Successfully updated VAP parameters
 * QDF_STATUS_E_INVAL: Could not setup MBSSID entries
 */
static void ieee80211_mbss_update_iter_func(struct wlan_objmgr_pdev *pdev,
                                            void *object,
                                            void *arg)
{
    struct wlan_objmgr_vdev *vdev = (struct wlan_objmgr_vdev *)object;
    struct ieee80211vap *vap = NULL;
    struct mbss_iter_func_args *mbss_args = (struct mbss_iter_func_args *)arg;
    struct mbss_iter_func_mode_switch_ema_args *mode_switch_ema_args = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    ol_ath_soc_softc_t *soc = NULL;
    uint32_t aid_bitmap_size;
    uint32_t nontx_key;

    if (!pdev) {
        /* Invalid pdev */
        return;
    }

    if (!vdev) {
        /* Invalid vdev */
        return;
    }

    if (!mbss_args) {
        /* Invalid arguments */
        return;
    }

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap || (vap->iv_opmode != IEEE80211_M_HOSTAP) ||
        vap->iv_smart_monitor_vap ||
        vap->iv_special_vap_mode) {
        return;
    }

    if (mbss_args->retval) {
        /* Return value already marked as error */
        return;
    }

    scn = OL_ATH_SOFTC_NET80211(vap->iv_ic);
    soc = scn->soc;

    switch (mbss_args->purpose) {
        case MBSS_ITER_FUNC_PURPOSE_CACHE_INVALIDATION:
            mbss_args->retval = ieee80211_mbssid_update_mbssie_cache(vap, false);
            if (mbss_args->retval) {
                mbss_err("Failed to clear MBSSIE cache for VDEV%d", vap->iv_unit);
                return;
            }
        break;


        case MBSS_ITER_FUNC_PURPOSE_MODE_SWITCH_EMA:
            if (!mbss_args->args) {
                mbss_err("Invalid args for EMA mode switch");
                return;
            }
            mode_switch_ema_args =
                  (struct mbss_iter_func_mode_switch_ema_args *)mbss_args->args;

            /*
             * MBSSID cache entry update can happen in 2 ways:
             * (1) If the cache is empty, then MBSSID setup should be called to
             *     create new cache entries.
             * (2) If cache entry is not empty, then this iteration is called as
             *     part of the rollback operation. In that case, update the
             *     cache entry for the VAPs without sanitization since ref-BSSID
             *     is not changed and BSSID indices are the same.
             */
            if (mode_switch_ema_args->is_cache_empty) {
                IEEE80211_VAP_MBSS_NON_TRANS_DISABLE(vap);
                if (ieee80211_mbssid_setup(vap)) {
                    mbss_err("Could not setup MBSSID entry for VDEV%d",
                             vap->iv_unit);
                    mbss_args->retval = QDF_STATUS_E_INVAL;
                    return;
                }

                if (mode_switch_ema_args->is_first_vap) {
                    IEEE80211_ADDR_COPY(vap->iv_ic->ic_mbss.ref_bssid,
                                  wlan_vdev_mlme_get_macaddr(vap->vdev_obj));
                    mode_switch_ema_args->is_first_vap = false;
                }
            } else {
               if (ieee80211_mbssid_get_num_vaps_in_mbss_cache(vap->iv_ic) <
                       ieee80211_get_num_beacon_ap_vaps(vap->iv_ic)) {
                   if (vap == mode_switch_ema_args->tx_vap) {
                       IEEE80211_VAP_MBSS_NON_TRANS_DISABLE(vap);
                   } else {
                       IEEE80211_VAP_MBSS_NON_TRANS_ENABLE(vap);
                   }

                   if (ieee80211_mbssid_update_mbssie_cache(vap, true)) {
                       mbss_err("Could not update MBSSIE cache - not recoverable");
                       mbss_args->retval = QDF_STATUS_E_INVAL;
                       return;
                   }
                }
            }

            /*
             * Update the IE pool for non-TX profiles
             */
            if (IS_MBSSID_EMA_EXT_ENABLED(vap->iv_ic)) {
                if (IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap)) {
                    vap->iv_mbss.non_tx_pfl_ie_pool = qdf_nbuf_alloc(NULL,
                                                 IEEE80211_NTX_PFL_IE_POOL_SIZE,
                                                 0, 0, false);

                    if (!vap->iv_mbss.non_tx_pfl_ie_pool) {
                        mbss_args->retval = QDF_STATUS_E_NOMEM;
                        return;
                    }

                    qdf_spinlock_create(&vap->iv_mbss.non_tx_pfl_ie_pool_lock);
                    qdf_mem_zero(vap->iv_mbss.non_tx_pfl_ie_pool,
                                 sizeof(vap->iv_mbss.non_tx_pfl_ie_pool));
                    vap->iv_mbss.ntx_pfl_rollback_stats = 0;
                    vap->iv_mbss.backup_length = 0;
                }
                vap->iv_mbss.ie_overflow = false;
                vap->iv_mbss.ie_overflow_stats = 0;
            }

            /*
             * Update the AID parameters:
             * (1) Update max AID value
             * (2) Update max MBSS AID value (per-VAP limit in MBSS group)
             * (3) Free the AID bitmaps for co-hosted VAPs (txvap_set() will
             *     refactor AID pool)
             */
            vap->iv_max_aid = vap->iv_mbss_max_aid =
                 (vap->iv_ic->ic_num_clients + (1 << vap->iv_ic->ic_mbss.max_bssid) + 1);
            if (vap->iv_aid_bitmap) {
                qdf_mem_free(vap->iv_aid_bitmap);
                vap->iv_aid_bitmap = NULL;
            }

            /*
             * Update the DTIM period for both non-Tx VAPs and the Tx VAP
             */
            if (vap != mode_switch_ema_args->tx_vap) {
                vap->vdev_mlme->proto.generic.dtim_period =
                              (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) ?
                                    roundup(IEEE80211_DTIM_DEFAULT_LP_IOT,
                                            soc->ema_ap_max_pp) :
                                    roundup(IEEE80211_DTIM_DEFAULT,
                                            soc->ema_ap_max_pp);
            } else {
               vap->vdev_mlme->proto.generic.dtim_period =
                             (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) ?
                                            IEEE80211_DTIM_DEFAULT_LP_IOT :
                                            IEEE80211_DTIM_DEFAULT;
            }

            /*
             * Check the key management flags of the non-Tx VAP and compare it
             * with that of the selected Tx VAP. If non-TX VAP is open and the
             * Tx VAP is not open, then non-inheritance should be enabled for
             * the MBSS group.
             * This is to happen only if the cache entry was empty. If
             * not empty, non-inheritance was not updated in the first place so
             * there is no requirement for a check.
             */
            nontx_key = wlan_crypto_get_param(vap->vdev_obj, WLAN_CRYPTO_PARAM_KEY_MGMT);
            if (mode_switch_ema_args->is_cache_empty &&
                (nontx_key & (1 << WLAN_CRYPTO_KEY_MGMT_NONE)) &&
                !(mode_switch_ema_args->tx_key &
                                           (1 << WLAN_CRYPTO_KEY_MGMT_NONE)) &&
                !vap->iv_ic->ic_mbss.non_inherit_enable) {
                vap->iv_ic->ic_mbss.non_inherit_enable = true;
            }
        break;

        case MBSS_ITER_FUNC_PURPOSE_MODE_SWITCH_COHOSTED:
            /* Clear all IE pool data structures from VAPs */
            if (IS_MBSSID_EMA_EXT_ENABLED(vap->iv_ic) &&
                IEEE80211_VAP_IS_MBSS_NON_TRANSMIT_ENABLED(vap) &&
                (vap->iv_mbss.non_tx_pfl_ie_pool != NULL)) {
                IEEE80211_NTX_PFL_IE_POOL_LOCK(vap);
                qdf_nbuf_free(vap->iv_mbss.non_tx_pfl_ie_pool);
                vap->iv_mbss.non_tx_pfl_ie_pool = NULL;
                IEEE80211_NTX_PFL_IE_POOL_UNLOCK(vap);
                qdf_spinlock_destroy(&vap->iv_mbss.non_tx_pfl_ie_pool_lock);
                vap->iv_mbss.ie_overflow = false;
                vap->iv_mbss.ie_overflow_stats = 0;
            }

            /*
             * Reset VDEV MBSSID flags. These flags should be disabled for
             * co-hosted mode operation.
             */
            IEEE80211_VAP_MBSS_NON_TRANS_DISABLE(vap);

            /* Update DTIM period as per co-hosted mode requirement */
            vap->vdev_mlme->proto.generic.dtim_period =
                          (vap->iv_create_flags & IEEE80211_LP_IOT_VAP) ?
                                         IEEE80211_DTIM_DEFAULT_LP_IOT :
                                         IEEE80211_DTIM_DEFAULT;

            /* Reset max AID limit */
            vap->iv_max_aid = vap->iv_mbss_max_aid = (vap->iv_ic->ic_num_clients + 1);
            aid_bitmap_size = (howmany(vap->iv_max_aid,
                                       (sizeof(unsigned long) *
                                        BITS_PER_BYTE)) *
                               sizeof(unsigned long));

            /* Allocate a new AID bitmap for each VAP in co-hosted mode */
            vap->iv_aid_bitmap = qdf_mem_malloc(aid_bitmap_size);
            if (!vap->iv_aid_bitmap) {
                mbss_err("Could not allocate memory for AID bitmap for "
                        "VDEV%d - Rolling back", vap->iv_unit);
                mbss_args->retval = QDF_STATUS_E_NOMEM;
                return;
            }
        break;

        default:
            mbss_err("Invalid purpose (%d)", mbss_args->purpose);
    }

    return;
}

/*
 * ieee80211_mbss_update_flags:
 * Update the EMA/MBSSID flags for 6GHz PDEVs.
 *
 * @ic: Pointer to the ic structure
 * @target_mode: Value of the desired target mode
 *
 */
static inline void ieee80211_mbss_update_flags(struct ieee80211com *ic,
                                               mbss_mode_t target_mode)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_soc_softc_t *soc = scn->soc;

    soc->disable_6ghz_mbssid = !!target_mode;
    if (target_mode == MBSS_MODE_COHOSTED) {
        wlan_pdev_nif_feat_cap_clear(ic->ic_pdev_obj,
                                   WLAN_PDEV_F_MBSS_IE_ENABLE);
        wlan_pdev_nif_feat_ext_cap_clear(ic->ic_pdev_obj,
                                   WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    } else {
        wlan_pdev_nif_feat_cap_set(ic->ic_pdev_obj,
                                   WLAN_PDEV_F_MBSS_IE_ENABLE);
        wlan_pdev_nif_feat_ext_cap_set(ic->ic_pdev_obj,
                                       WLAN_PDEV_FEXT_EMA_AP_ENABLE);
    }
}

/*
 * ieee80211_mbss_switch_mode_to_ema:
 * Switch the MBSS mode to legacy EMA mode.
 *
 * @ic: Pointer to the ic structure
 * @target_txvap: Pointer to the current Tx-VAP
 *
 * Return:
 * MBSS_SWITCH_SUCCESS  : Successful switch to co-hosted mode
 * MBSS_SWITCH_E_RECOVER: Failed to switch but recovered to original mode
 * MBSS_SWITCH_GOTO_ROLLBACK: Notify caller for rollback operation (if applicable)
 */
static inline
mbss_switch_status_t ieee80211_mbss_switch_mode_to_ema(struct ieee80211com *ic,
                                              struct ieee80211vap *target_txvap)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    ol_ath_soc_softc_t *soc = NULL;
    struct mbss_iter_func_args iter_func_args = {0};
    struct mbss_iter_func_mode_switch_ema_args mode_switch_ema_args = {0};

    if (!ic) {
        qdf_err("ic is invalid, cannot recover");
        return MBSS_SWITCH_E_RECOVER;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    soc = scn->soc;

    /*
     * If the given target_txvap is NULL, if the caller could not find a Tx
     * VAP or if it is a rollback operation for a switch called when there is
     * no Tx VAP (if Tx VAP is down or deleted), the find for the first up Tx
     * VAP again. If a VAP is still not found, return with a rollback indication
     */
    if (!target_txvap) {
        target_txvap = ieee80211_mbss_get_first_ap_vap(ic, true);
        if (!target_txvap) {
            qdf_err("Could not find a Tx VAP");
            return MBSS_SWITCH_GOTO_ROLLBACK;
        }
    }

    /*
     * The following arguments are required by the iteration function:
     * (1) purpose       : Type of iteration routine for MBSS operation
     * (2) retval        : Return value to indicate success/failure/rollback.
     * (3) tx_vap        : VDEV ID of the selected Tx VAP for updating the DTIM period.
     * (4) tx_key        : Key management flags for the selected Tx VAP.
     * (5) is_cache_empty: Flag to allow iteration API to decide if cache entries
     *                     should be setup or added without sanitization.
     * (6) is_first_vap  : Flag to detect the first VAP in the iteration for
     *                     reassigning the reference BSSID to the first VAP setup.
     */
    iter_func_args.purpose       = MBSS_ITER_FUNC_PURPOSE_MODE_SWITCH_EMA;
    iter_func_args.retval        = QDF_STATUS_SUCCESS;
    mode_switch_ema_args.tx_vap  = target_txvap;
    mode_switch_ema_args.tx_key  = wlan_crypto_get_param(target_txvap->vdev_obj,
                                                    WLAN_CRYPTO_PARAM_KEY_MGMT);
    mode_switch_ema_args.is_cache_empty =
                              !ieee80211_mbssid_get_num_vaps_in_mbss_cache(ic);
    mode_switch_ema_args.is_first_vap = true;
    iter_func_args.args          = (void *)&mode_switch_ema_args;

    /*
     * Setup/Rollback the MBSSID cache entries, update AID bitmap, update DTIM
     * period and check for non-inheritance for each VAP.
     */
    wlan_objmgr_pdev_iterate_obj_list(ic->ic_pdev_obj, WLAN_VDEV_OP,
                                 ieee80211_mbss_update_iter_func,
                                 &iter_func_args, 0, WLAN_MLME_SB_ID);
    if (iter_func_args.retval) {
        if (iter_func_args.retval == QDF_STATUS_E_NOMEM) {
            return MBSS_SWITCH_E_NORECOVER_NOMEM;
        } else {
            return MBSS_SWITCH_GOTO_ROLLBACK;
        }
    }

    /*
     * Set Tx VAP:
     * Setting Tx VAP takes care of allocating AID pool for Tx VAP and
     * arrange for non-Tx vaps to share the same. It also takes care of
     * BSSID index re-assignment of each non-Tx VAP as per the new Tx VAP.
     */
    if (!ic->ic_mbss.transmit_vap && ieee80211_ucfg_set_txvap(target_txvap)) {
        qdf_err("Could not set Tx VAP");
        return MBSS_SWITCH_GOTO_ROLLBACK;
    }

    return MBSS_SWITCH_SUCCESS;
}

/*
 * ieee80211_mbss_switch_mode_to_cohosted:
 * Switch the MBSS mode to legacy co-hosted mode.
 *
 * @ic: Pointer to the ic structure
 * @current_txvap: Pointer to the current Tx-VAP
 *
 * Return:
 * MBSS_SWITCH_SUCCESS  : Successful switch to co-hosted mode
 * MBSS_SWITCH_E_RECOVER: Failed to switch but recovered to original mode
 * MBSS_SWITCH_GOTO_ROLLBACK: Notify caller for rollback operation (if applicable)
 */
static inline
mbss_switch_status_t ieee80211_mbss_switch_mode_to_cohosted(struct ieee80211com *ic,
                                             struct ieee80211vap *current_txvap)
{
    QDF_STATUS retval = QDF_STATUS_SUCCESS;
    struct mbss_iter_func_args iter_func_args = {0};
    uint8_t temp_ref_bssid[IEEE80211_ADDR_LEN];

    if (!ic) {
        qdf_err("ic is invalid, cannot recover");
        return MBSS_SWITCH_E_RECOVER;
    }

    /*
     * Reset the Tx VAP, if set:
     * Future switches to EMA mode requires a NULL transmit_vap pointer.
     * If transmit_vap is not NULL, current VAP should be used to reset the
     * Tx VAP.
     */
    if (ic->ic_mbss.transmit_vap && ieee80211_ucfg_reset_txvap(current_txvap, true)) {
        qdf_err("Could not reset Tx-VAP");
        return MBSS_SWITCH_E_RECOVER;
    }

    /*
     * Save the current ref-BSSID to reassign later on:
     * Creating VAPs in co-hosted mode should align to ref-BSSID rules of the
     * first VAP created in EMA mode.
     */
    IEEE80211_ADDR_COPY(temp_ref_bssid, ic->ic_mbss.ref_bssid);

    /*
     * Mark all the cache entries of the created VAPs are stale.
     * If invalidation fails, the sequence can rollback to original EMA mode.
     */
    iter_func_args.purpose = MBSS_ITER_FUNC_PURPOSE_CACHE_INVALIDATION;
    iter_func_args.retval  = QDF_STATUS_SUCCESS;
    iter_func_args.args    = NULL;
    wlan_objmgr_pdev_iterate_obj_list(ic->ic_pdev_obj, WLAN_VDEV_OP,
                                      ieee80211_mbss_update_iter_func,
                                      &iter_func_args, 0, WLAN_MLME_SB_ID);
    if (retval) {
        return MBSS_SWITCH_GOTO_ROLLBACK;
    }

    /*
     * Put back the original ref-BSSID:
     * MBSSID cache update API will reassign the ref-BSSID to a random MAC
     * after the last VAP is cleared. This will cause future created VAPs to
     * have a complete different MAC address than the rest of the MBSS group
     * members.
     */
    IEEE80211_ADDR_COPY(ic->ic_mbss.ref_bssid, temp_ref_bssid);

    /*
     * Iterate through all VAPs and update the AID bitmap and DTIM periods
     * as per co-hosted norms. If update fails, the sequence cannot rollback to
     * original EMA mode.
     */
    qdf_mem_zero(&iter_func_args, sizeof(struct mbss_iter_func_args));
    iter_func_args.purpose = MBSS_ITER_FUNC_PURPOSE_MODE_SWITCH_COHOSTED;
    iter_func_args.retval  = QDF_STATUS_SUCCESS;
    iter_func_args.args    = NULL;
    wlan_objmgr_pdev_iterate_obj_list(ic->ic_pdev_obj, WLAN_VDEV_OP,
                            ieee80211_mbss_update_iter_func,
                            &iter_func_args, 0, WLAN_MLME_SB_ID);
    if (retval) {
        return MBSS_SWITCH_E_NORECOVER_NOMEM;
    }

    /*
     * Reset the non-inherit flag when moving back to co-hosted mode.
     */
    ic->ic_mbss.non_inherit_enable = false;

    return MBSS_SWITCH_SUCCESS;
}

/*
 * ieee80211_mbss_switch_mode:
 * Switch the multi-BSS mode between co-hosted and EMA mode.
 *
 * @ic         : Pointer to the ic structure.
 * @target_mode: Value of the target multi-BSS mode.
 *
 * Return:
 * MBSS_SWITCH_SUCCESS: Successful
 * MBSS_SWITCH_E_RECOVER: Failed but rollback
 * MBSS_SWITCH_E_NORECOVER: Failed and rollback failed
 */
mbss_switch_status_t ieee80211_mbss_switch_mode(struct ieee80211com *ic,
                                                mbss_mode_t target_mode)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    ol_ath_soc_softc_t *soc = NULL;
    mbss_mode_t current_mode;
    bool is_mbssid_enabled = false;
    bool old_noninherit_enable = false;
    struct ieee80211vap *txvap = NULL;
    mbss_switch_status_t retval = MBSS_SWITCH_SUCCESS;

    if (!ic) {
        qdf_err("Invalid ic");
        return MBSS_SWITCH_E_RECOVER;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    soc = scn->soc;

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                          WLAN_PDEV_F_MBSS_IE_ENABLE);

    if (!ic->ic_wideband_capable) {
        qdf_err("Wideband is not supported - Aborting");
        return MBSS_SWITCH_E_RECOVER;
    }

    if (is_mbssid_enabled) {
        /*
         * Wideband radio requires EMA to be applied alongside the
         * MBSSID-IE flag. Since this function currently supports only the
         * wideband radio, MBSSID-IE support also implies EMA.
         */
        current_mode = MBSS_MODE_MBSSID_EMA;
    } else {
        current_mode = MBSS_MODE_COHOSTED;
    }

    if (target_mode == current_mode) {
        qdf_err("Current and target MBSS modes are the same - Skipping");
        return MBSS_SWITCH_SUCCESS;
    }

    /*
     * If current mode is COHOSTED  : Tx VAP points to target Tx VAP
     * If current mode is MBSSID_EMA: Tx VAP points to current Tx VAP
     */
    txvap = ieee80211_ucfg_get_txvap(ic);
    if (!txvap && (target_mode == MBSS_MODE_MBSSID_EMA)) {
        qdf_err("Could not find Tx-VAP for Co-hosted to EMA switch - Recovering");
        return MBSS_SWITCH_E_RECOVER;
    }

    /* Capture the old non-inherit state in case rollback in invoked */
    old_noninherit_enable = ic->ic_mbss.non_inherit_enable;

    if (target_mode == MBSS_MODE_COHOSTED) {
        retval = ieee80211_mbss_switch_mode_to_cohosted(ic, txvap);
        if ((retval == MBSS_SWITCH_E_RECOVER) ||
            (retval == MBSS_SWITCH_E_NORECOVER_INVAL) ||
            (retval == MBSS_SWITCH_E_NORECOVER_NOMEM)) {
            return retval;
        } else if (retval == MBSS_SWITCH_GOTO_ROLLBACK) {
            goto exit_backto_ema;
        }

        ieee80211_mbss_update_flags(ic, target_mode);
    } else {
        ieee80211_mbss_update_flags(ic, target_mode);

        retval = ieee80211_mbss_switch_mode_to_ema(ic, txvap);
        if ((retval == MBSS_SWITCH_E_RECOVER) ||
            (retval == MBSS_SWITCH_E_NORECOVER_INVAL) ||
            (retval == MBSS_SWITCH_E_NORECOVER_NOMEM)) {
            return retval;
        } else if (retval == MBSS_SWITCH_GOTO_ROLLBACK) {
            goto exit_backto_cohost;
        }

        /* Co-hosted to EMA switch */
    }

    qdf_info("Successfully switched to mode %d", target_mode);
    return MBSS_SWITCH_SUCCESS;

/* Rollback as per current mode */
exit_backto_cohost: /* Failed co-hosted to EMA switch. Try to revert back to co-hosted */
    if (current_mode == MBSS_MODE_COHOSTED) {
        retval = ieee80211_mbss_switch_mode_to_cohosted(ic, txvap);
        if ((retval == MBSS_SWITCH_E_RECOVER) ||
            (retval == MBSS_SWITCH_GOTO_ROLLBACK) ||
            (retval == MBSS_SWITCH_E_NORECOVER_INVAL) ||
            (retval == MBSS_SWITCH_E_NORECOVER_NOMEM)) {
            return MBSS_SWITCH_E_NORECOVER_INVAL;
        }

        ieee80211_mbss_update_flags(ic, current_mode);
    }

exit_backto_ema: /* Failed switch from EMA to co-hosted, move back to EMA */
    if (current_mode == MBSS_MODE_MBSSID_EMA) {
        retval = ieee80211_mbss_switch_mode_to_ema(ic, txvap);
        if ((retval == MBSS_SWITCH_E_RECOVER) ||
            (retval == MBSS_SWITCH_GOTO_ROLLBACK) ||
            (retval == MBSS_SWITCH_E_NORECOVER_INVAL) ||
            (retval == MBSS_SWITCH_E_NORECOVER_NOMEM)) {
            return MBSS_SWITCH_E_NORECOVER_INVAL;
        }
    }

    /* Revert the non_inherit_enable flag back to original value. */
    ic->ic_mbss.non_inherit_enable = old_noninherit_enable;

    mbss_info("Rollback to mode %d successful", current_mode);
    return MBSS_SWITCH_E_RECOVER;
}

/*
 * ieee80211_mbss_mode_switch_sanity:
 * Check if the current configuration supports switching the multi-VAP mode
 *
 * @ic: Pointer to the ic structure.
 * @value: Value of the desired target mode.
 *
 * Return:
 * QDF_STATUS_SUCCESS: Success
 * QDF_STATUS_E_INVAL: Failure
 */
QDF_STATUS ieee80211_mbss_mode_switch_sanity(struct ieee80211com *ic,
                                             uint32_t value)
{
    bool is_mbssid_enabled = false;

    if (!ic) {
        qdf_err("Invalid ic pointer");
        return QDF_STATUS_E_INVAL;
    }

    if (value > MBSS_MODE_MBSSID_EMA) {
        qdf_err("Invalid input value (%d)", value);
        return QDF_STATUS_E_INVAL;
    }

    if (!ic->ic_wideband_capable) {
        qdf_err("Radio does not support wideband (5-7GHz), cannot perform "
                "mode switch");
        return QDF_STATUS_E_INVAL;
    }

    is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                          WLAN_PDEV_F_MBSS_IE_ENABLE);
    if (((value == MBSS_MODE_COHOSTED) && !is_mbssid_enabled) ||
        ((value == MBSS_MODE_MBSSID_EMA) && is_mbssid_enabled)) {
        qdf_err("Current mode and target mode are the same, skipping mode "
                "switch");
        return QDF_STATUS_E_INVAL;
    }

    if ((value == MBSS_MODE_MBSSID_EMA) &&
        ieee80211_get_num_beacon_ap_vaps(ic) &&
        wlan_cfg80211_mbssid_security_admission_control_sanity(ic, false)) {
        qdf_err("Security validation for mode switch failed");
        return QDF_STATUS_E_INVAL;
    }

    qdf_debug("Sanity check for mode switch to mode %d passed", value);
    return QDF_STATUS_SUCCESS;
}

/*
 * ieee80211_mbss_handle_mode_switch:
 * Handle the mode switch including the VDEV state changes involved.
 *
 * @ic: Pointer to the ic structure
 * @target_mode: Value of the desired target MBSS mode
 *
 * Return:
 * QDF_STATUS_SUCCESS: Success
 * QDF_STATUS_E_INVAL:
 * QDF_STATUS_E_NOMEM: Failed to switch
 */
QDF_STATUS ieee80211_mbss_handle_mode_switch(struct ieee80211com *ic,
                                             mbss_mode_t target_mode)
{
    struct ol_ath_softc_net80211 *scn = NULL;
    ol_ath_soc_softc_t *soc = NULL;
    uint8_t retval = QDF_STATUS_SUCCESS;

    if (!ic) {
        qdf_err("Invalid ic pointer");
        return QDF_STATUS_E_INVAL;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    soc = scn->soc;

    if (!ieee80211_get_num_beacon_ap_vaps(ic)) {
        /*
         * If the VAP list is empty, perform the switch silently
         * by only changing the flags.
         */
        ieee80211_mbss_update_flags(ic, target_mode);
        qdf_info("Silently switched MBSS mode to %d", target_mode);
        return QDF_STATUS_SUCCESS;
    }

    if (ieee80211_bringdown_all_vaps(ic, ALL_AP_VDEVS)) {
        qdf_err("Could not bringdown AP vdevs");
        return QDF_STATUS_E_INVAL;
    }

    retval = ieee80211_mbss_switch_mode(ic, target_mode);

    switch (retval) {
        case MBSS_SWITCH_E_NORECOVER_INVAL:
            qdf_err("Could not recover from failed mode switch to %d"
                    "due to invalid params", target_mode);
            return QDF_STATUS_E_INVAL;
        break;
        case MBSS_SWITCH_E_NORECOVER_NOMEM:
            qdf_err("Could not recover from failed mode switch to %d "
                    "due to no memory", target_mode);
            return QDF_STATUS_E_NOMEM;
        break;
        case MBSS_SWITCH_E_RECOVER:
            qdf_err("Recovered from failed mode switch to %d", target_mode);
            retval = QDF_STATUS_E_INVAL;
        break;
        case MBSS_SWITCH_SUCCESS:
            qdf_debug("Successfully switched mode to %d", target_mode);
            retval = QDF_STATUS_SUCCESS;
        break;
        default:
            qdf_debug("Invalid return value: %d", retval);
            return QDF_STATUS_E_INVAL;
    }

    if (ieee80211_bringup_all_vaps(ic, ALL_AP_VDEVS)) {
        qdf_err("Could not bring up VAPs");
        retval = QDF_STATUS_E_INVAL;
    }

    return retval;
}

/*
 * ieee80211_get_beacon_vap_iter_func:
 * Iteration function for each VAP to check for number of beaconing AP VAPs.
 *
 * @arg: Opaque handle to the variable holding the count
 * @vap: Pointer to the current VAP structure
 */
static void ieee80211_get_beacon_vap_iter_func(void *arg,
                                               struct ieee80211vap *vap)
{
    uint8_t *beacon_vaps = (uint8_t *)arg;

    if (!vap || !vap->vdev_obj) {
        return;
    }

    if (!ieee80211_mbss_is_beaconing_ap(vap)) {
        return;
    }

    ++(*beacon_vaps);
}

/*
 * ieee80211_get_num_beacon_ap_vaps:
 * Get the number of created AP VAPs that are capable of beaconing
 * That is, all HOSTAP VAPs excluding special_mode_vap and smart_ap_monitor
 *
 * @ic: Pointer to the ic structure
 *
 * Return:
 * Number of VAPs
 */
uint8_t ieee80211_get_num_beacon_ap_vaps(struct ieee80211com *ic)
{
    uint8_t num_beacon_ap_vaps = 0;

    wlan_iterate_vap_list(ic,
                          ieee80211_get_beacon_vap_iter_func,
                          (void *)&num_beacon_ap_vaps);

    return num_beacon_ap_vaps;
}

uint16_t ieee80211_get_max_user_rnr_size_allowed(struct ieee80211com *ic)
{
    uint16_t max_size;
    bool is_mbssid_enabled = wlan_pdev_nif_feat_cap_get(ic->ic_pdev_obj,
                                WLAN_PDEV_F_MBSS_IE_ENABLE);
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* Max user rnr size allowed for Mbss case is determined by INI
     * (ema_ap_rnr_field_size_limit). This INI takes into account 2 bytes
     * per IE for tag and tag length. Subtract this tag, length field from
     * ema_ap_rnr_field_size_limit to get max user rnr allowed.
     */
    if (is_mbssid_enabled)
        max_size = scn->soc->ema_ap_rnr_field_size_limit -
                   RESERVED_6GHZ_RNR - (2 * scn->soc->max_rnr_ie_allowed);
    else
        max_size = (scn->soc->max_rnr_ie_allowed * IEEE80211_MAX_IE_LEN) -
                   RESERVED_6GHZ_RNR;

    return max_size;
}

int
module_init_wlan(void)
{
    return 0;
}

void
module_exit_wlan(void)
{
}
