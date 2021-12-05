/*
 * Copyright (c) 2011, 2018,2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 * 
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

#include <osdep.h>

#include <wlan_utility.h>
#include "ieee80211_var.h"

void
ieee80211_set_uapsd_flags(struct ieee80211vap *vap, u_int8_t flags)
{
    vap->iv_uapsd = (u_int8_t) (flags & WME_CAPINFO_UAPSD_ALL);
}

u_int8_t
ieee80211_get_uapsd_flags(struct ieee80211vap *vap)
{
    return (u_int8_t) vap->iv_uapsd;
}

void
ieee80211_set_wmm_power_save(struct ieee80211vap *vap, u_int8_t enable)
{
    vap->iv_wmm_power_save = !!enable;
}

u_int8_t
ieee80211_get_wmm_power_save(struct ieee80211vap *vap)
{
    return (u_int8_t) vap->iv_wmm_power_save;
}

void ieee80211_power_attach(struct ieee80211com *ic)
{
    if (ic->ic_power_attach) {
        ic->ic_power_attach(ic);
    }
}

void ieee80211_power_detach(struct ieee80211com *ic)
{
    if (ic->ic_power_detach) {
        ic->ic_power_detach(ic);
    }
}

void ieee80211_power_vattach(
        struct ieee80211vap *vap, 
        int fullsleep_enable, 
        u_int32_t sleepTimerPwrSaveMax, 
        u_int32_t sleepTimerPwrSave, 
        u_int32_t sleepTimePerf, 
        u_int32_t inactTimerPwrsaveMax, 
        u_int32_t inactTimerPwrsave, 
        u_int32_t inactTimerPerf, 
        u_int32_t smpsDynamic, 
        u_int32_t pspollEnabled)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (ic->ic_power_vattach) {
        ic->ic_power_vattach(vap, fullsleep_enable,
                sleepTimerPwrSaveMax, sleepTimerPwrSave, sleepTimePerf,
                inactTimerPwrsaveMax, inactTimerPwrsave, inactTimerPerf,
                smpsDynamic, pspollEnabled);
    }
}

void ieee80211_power_vdetach(struct ieee80211vap * vap)
{
    struct ieee80211com *ic = vap->iv_ic;

    if (ic->ic_power_vdetach) {
        ic->ic_power_vdetach(vap);
    }
}
