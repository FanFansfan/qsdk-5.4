/*
 * Copyright (c) 2011-2016,2017-2018,2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * 2011-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#include <ieee80211_var.h>
#include "ieee80211_wnm.h"

/**
 * @set max service period length filed in uapsd .
 * 
 *  @param vaphandle     : handle to the vap.
 *  @param max_sp_len    : max service period length (0:unlimited,2,4,6) 
 *  @return EOK  on success and non zero on failure.
 */
int ieee80211_pwrsave_uapsd_set_max_sp_length(struct ieee80211vap *vap,u_int8_t val)
{
    if (!(val < 4)) 
        return EINVAL;

    vap->iv_uapsd  &= ~(0x3 << WME_CAPINFO_UAPSD_MAXSP_SHIFT);
    vap->iv_uapsd  |= (val << WME_CAPINFO_UAPSD_MAXSP_SHIFT);

    return 0;
}

int
wlan_set_powersave(wlan_if_t vaphandle, ieee80211_pwrsave_mode mode)
{
    struct ieee80211vap      *vap = vaphandle;
    struct ieee80211com      *ic = vap->iv_ic;

    if (ic->ic_power_set_mode) {
        return ic->ic_power_set_mode(vap, mode);
    }

    return EOK;
}

ieee80211_pwrsave_mode
wlan_get_powersave(wlan_if_t vaphandle)
{
    struct ieee80211vap      *vap = vaphandle;
    struct ieee80211com      *ic = vap->iv_ic;

    if (ic->ic_power_get_mode) {
        return ic->ic_power_get_mode(vap);
    }

    return IEEE80211_PWRSAVE_NONE;
}

int wlan_sta_power_set_pspoll(wlan_if_t vaphandle, u_int32_t pspoll)
{
    struct ieee80211vap      *vap = vaphandle;
    struct ieee80211com      *ic = vap->iv_ic;

    if (ic->ic_power_sta_set_pspoll) {
        return ic->ic_power_sta_set_pspoll(vap, pspoll);
    }

    return ENXIO;

}

int wlan_sta_power_set_pspoll_moredata_handling(
        wlan_if_t vaphandle, 
        ieee80211_pspoll_moredata_handling mode)
{
    struct ieee80211vap      *vap = vaphandle;
    struct ieee80211com      *ic = vap->iv_ic;

    if (ic->ic_power_sta_set_pspoll_moredata_handling) {
        return ic->ic_power_sta_set_pspoll_moredata_handling(vap, mode);
    }

    return ENXIO;
}

u_int32_t wlan_sta_power_get_pspoll(wlan_if_t vaphandle)
{
    struct ieee80211vap      *vap = vaphandle;
    struct ieee80211com      *ic = vap->iv_ic;

    if (ic->ic_power_sta_get_pspoll) {
        return ic->ic_power_sta_get_pspoll(vap);
    }

    return 0;
}

ieee80211_pspoll_moredata_handling  
wlan_sta_power_get_pspoll_moredata_handling(wlan_if_t vaphandle)
{
    struct ieee80211vap      *vap = vaphandle;
    struct ieee80211com      *ic = vap->iv_ic;

    if (ic->ic_power_sta_get_pspoll_moredata_handling) {
        return ic->ic_power_sta_get_pspoll_moredata_handling(vap);
    }

    return IEEE80211_WAKEUP_FOR_MORE_DATA;
}

int
wlan_pwrsave_force_sleep(wlan_if_t vaphandle, bool enable)
{
    struct ieee80211vap      *vap = vaphandle;
    struct ieee80211com      *ic = vap->iv_ic;

    if (ic->ic_power_force_sleep) {
        return ic->ic_power_force_sleep(vap, enable);
    }

    return EOK;
}
