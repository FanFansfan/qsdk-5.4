/*
 * Copyright (c) 2011,2017-2018,2020-2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 */

#include <wlan_utility.h>
#include "wlan_green_ap_api.h"
#include "ieee80211_var.h"

#if UMAC_SUPPORT_STA_SMPS 

#define IEEE80211_PWRSAVE_TIMER_INTERVAL   1000 /* 1000 msec */
/*
 * SM power save state.  
 */  
typedef enum ieee80211_smps_state {
    IEEE80211_SM_PWRSAVE_WAIT,
    IEEE80211_SM_PWRSAVE_DISABLED,  
    IEEE80211_SM_PWRSAVE_ENABLED
} IEEE80211_SM_PWRSAVE_STATE;

/*  
 * SM power save state machine events  
 */  
typedef enum ieee80211_smpsevent {
    IEEE80211_SMPS_ENABLE,             /* SM power save can be enabled */
    IEEE80211_SMPS_DISABLE,            /* SM power save to be disabled */
    IEEE80211_SMPS_HW_SM_MODE,         /* Chip is out of SM power save */
    IEEE80211_SMPS_ACTION_FRAME_OK,    /* SM power save action frame successful */
    IEEE80211_SMPS_ACTION_FRAME_FAIL,  /* SM power save action frame failed */
    IEEE80211_SMPS_DISCONNECTION       /* Station disconnected */
} IEEE80211_SM_PWRSAVE_EVENT;

#define IEEE80211_CTS_SMPS 1
#define IEEE80211_SMPS_THRESH_DIFF   4
#define IEEE80211_SMPS_DATAHIST_NUM  5
struct ieee80211_pwrsave_smps {
    IEEE80211_SM_PWRSAVE_STATE  ips_smPowerSaveState;  /* Current dynamic MIMO power save state */
    u_int16_t               ips_smpsDataHistory[IEEE80211_SMPS_DATAHIST_NUM]; /* Throughput history buffer used for enabling MIMO ps */
    u_int8_t                ips_smpsCurrDataIndex;     /* Index in throughput history buffer to be updated */
    struct ieee80211vap     *ips_vap;
    u_int8_t                ips_connected;
    os_timer_t              ips_timer;                   /* to monitor vap activity */
    u_int8_t                ips_frame_resend;            /* to monitor and limit the number of time same frame is resent */
} ;

/* 
 * SM Power Save Management Action frame 
 */
static void
ieee80211_pwrsave_smps_action_frame(struct ieee80211vap *vap, int smpwrsave)
{
    struct ieee80211_action_mgt_args actionargs;
    
    actionargs.category     = IEEE80211_ACTION_CAT_HT;
    actionargs.action       = IEEE80211_ACTION_HT_SMPOWERSAVE;
    actionargs.arg1         = smpwrsave;    /* SM Power Save state */
    if (ieee80211_vap_dynamic_mimo_ps_is_set(vap)) {
        actionargs.arg2         = 1;            /* SM Mode - Dynamic */
    } else if (ieee80211_vap_static_mimo_ps_is_set(vap)) {
        actionargs.arg2         = 0;            /* SM Mode - Static */
    }
    actionargs.arg3         = 0;
    ieee80211_send_action(vap->iv_bss, &actionargs, NULL);
}

/*
 * SM Power Save state machine handler
 */
static void
ieee80211_pwrsave_smps_event(ieee80211_pwrsave_smps_t smps, IEEE80211_SM_PWRSAVE_EVENT event)
{
    struct ieee80211vap *vap = smps->ips_vap;
    struct ieee80211com *ic = vap->iv_ic;

    if (ieee80211_vap_dynamic_mimo_ps_is_clear(vap) &&
        ieee80211_vap_static_mimo_ps_is_clear(vap))
        return;

    switch (event) {
    case IEEE80211_SMPS_ENABLE:
        if (smps->ips_smPowerSaveState == IEEE80211_SM_PWRSAVE_DISABLED) {
            /* Send SMPS action frame to AP and wait till it gets ack'ed */
            smps->ips_frame_resend = 0;
            ieee80211_pwrsave_smps_action_frame(vap, 1);
           smps->ips_smPowerSaveState = IEEE80211_SM_PWRSAVE_WAIT;
        }
        break;
    case IEEE80211_SMPS_HW_SM_MODE:
        break;
    case IEEE80211_SMPS_DISABLE:
    case IEEE80211_SMPS_DISCONNECTION:
        if (smps->ips_smPowerSaveState != IEEE80211_SM_PWRSAVE_DISABLED) {
            if (event == IEEE80211_SMPS_DISABLE)
                ieee80211_pwrsave_smps_action_frame(vap, 0);
            ieee80211_vap_smps_clear(vap);                 /* Clear status flag */
            ic->ic_sm_pwrsave_update(vap->iv_bss, TRUE, FALSE, TRUE);
            smps->ips_smPowerSaveState = IEEE80211_SM_PWRSAVE_DISABLED;
            smps->ips_frame_resend = 0;
        }
        break;
    case IEEE80211_SMPS_ACTION_FRAME_OK:
        if (smps->ips_smPowerSaveState == IEEE80211_SM_PWRSAVE_WAIT) {
            ieee80211_vap_smps_set(vap);                 /* Clear status flag */
            ic->ic_sm_pwrsave_update(vap->iv_bss, FALSE, FALSE, TRUE);
            smps->ips_smPowerSaveState = IEEE80211_SM_PWRSAVE_ENABLED;
            smps->ips_frame_resend = 0;
        }
        break;
    case IEEE80211_SMPS_ACTION_FRAME_FAIL:
        if (smps->ips_smPowerSaveState == IEEE80211_SM_PWRSAVE_ENABLED) {
            /* Resend SMPS disable action frame */
            if (smps->ips_frame_resend == 0) {
                smps->ips_frame_resend++;
                ieee80211_pwrsave_smps_action_frame(vap, 0);
            } else {
                smps->ips_frame_resend = 0;
                ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_DISCONNECTION);
            }
        } else if (smps->ips_smPowerSaveState == IEEE80211_SM_PWRSAVE_WAIT) {
            if (smps->ips_frame_resend == 0) {
                smps->ips_frame_resend++;
                ieee80211_pwrsave_smps_action_frame(vap, 1);
            } else {
                smps->ips_frame_resend = 0;
                smps->ips_smPowerSaveState = IEEE80211_SM_PWRSAVE_DISABLED;
            }
        }
        break;
    default:
        break;
    }
}


void ieee80211_pwrsave_smps_txrx_event_handler (struct wlan_objmgr_vdev *vdev, ieee80211_vap_txrx_event *event, void *arg)
{
    ieee80211_pwrsave_smps_t smps = (ieee80211_pwrsave_smps_t) arg;

    if (!smps->ips_connected)
        return;

    if (event->u.status == 0) {
        ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_ACTION_FRAME_OK);
    } else {
        ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_ACTION_FRAME_FAIL);
    }
}

static bool 
ieee80211_pwrsave_smps_check(ieee80211_pwrsave_smps_t smps)
{
    u_int16_t i, throughput = 0, snr;
    struct ieee80211vap *vap = smps->ips_vap;
    struct ieee80211com *ic = vap->iv_ic;

    if (!smps->ips_connected ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        (vap->iv_opmode != IEEE80211_M_STA) ||
        (!ieee80211node_has_flag(vap->iv_bss, IEEE80211_NODE_HT))) {
        return FALSE;
    }

    /* SM power save check.
     * SM Power save is enabled if,
     * - There is no data traffic or
     * - Throughput is less than threshold and SNR is greater than threshold.
     */
    snr = ic->ic_node_getsnr(vap->iv_bss, -1, IEEE80211_SNR_BEACON);

    smps->ips_smpsDataHistory[smps->ips_smpsCurrDataIndex++] = throughput;
    smps->ips_smpsCurrDataIndex = smps->ips_smpsCurrDataIndex % IEEE80211_SMPS_DATAHIST_NUM;

    /* We calculate average throughput over the past samples */
    throughput = 0;
    for (i = 0; i < IEEE80211_SMPS_DATAHIST_NUM;i++) {
        throughput += smps->ips_smpsDataHistory[i];
    }
    throughput /= IEEE80211_SMPS_DATAHIST_NUM;

    /* 
     * We make the thresholds slightly different for SM power save enable & disable to get 
     * over the ping-pong effect when calculated throughput is close to the threshold value.
     * SMPS Enable Threshold = Registry Value
     * SMPS Disable Threshold = Registry Value + IEEE80211_SMPS_THRESH_DIFF
     */
    if (!throughput || ((throughput < vap->iv_smps_datathresh) &&
                        (snr > vap->iv_smps_snrthresh))) {
        /* Receive criteria met, do SM power save. */
        ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_ENABLE);
    } else if ((throughput > (vap->iv_smps_datathresh + IEEE80211_SMPS_THRESH_DIFF)) ||
               (snr < vap->iv_smps_snrthresh)) {
        ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_DISABLE);
    }
    return TRUE;
}

static bool
ieee80211_pwrsave_smps_gap_check(ieee80211_pwrsave_smps_t smps) {
    struct ieee80211vap *vap = smps->ips_vap;
    struct ieee80211com *ic = vap->iv_ic;

    if (!smps->ips_connected ||
        (wlan_vdev_is_up(vap->vdev_obj) != QDF_STATUS_SUCCESS) ||
        (vap->iv_opmode != IEEE80211_M_STA) ||
        (!ieee80211node_has_flag(vap->iv_bss, IEEE80211_NODE_HT))) {
        return FALSE;
    }

    if (wlan_green_ap_is_ps_waiting(ic->ic_pdev_obj) ||
        wlan_green_ap_is_ps_enabled(ic->ic_pdev_obj)) {
        ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_ENABLE);
    } else {
        ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_DISABLE);
    }

    return TRUE;
}

void ieee80211_pwrsave_smps_set_timer(void *arg)
{
    ieee80211_pwrsave_smps_t smps = (ieee80211_pwrsave_smps_t) arg;

    OS_SET_TIMER(&smps->ips_timer,IEEE80211_PWRSAVE_TIMER_INTERVAL);
}

static OS_TIMER_FUNC(ieee80211_pwrsave_smps_timer)
{
    ieee80211_pwrsave_smps_t smps;
    OS_GET_TIMER_ARG(smps, ieee80211_pwrsave_smps_t);
    if (ieee80211_vap_dynamic_mimo_ps_is_set(smps->ips_vap)) {
        if (ieee80211_pwrsave_smps_check(smps)) {
            OS_SET_TIMER(&smps->ips_timer,IEEE80211_PWRSAVE_TIMER_INTERVAL);
        }
    } else if (ieee80211_vap_sm_gap_ps_is_set(smps->ips_vap)) {
        if (ieee80211_pwrsave_smps_gap_check(smps)) {
            OS_SET_TIMER(&smps->ips_timer,IEEE80211_PWRSAVE_TIMER_INTERVAL);
        }
    }
}

static void ieee80211_pwrsave_smps_vap_event_handler (ieee80211_vap_t vap, ieee80211_vap_event *event, void *arg)
{
    ieee80211_pwrsave_smps_t smps = (ieee80211_pwrsave_smps_t) arg;

    switch(event->type) {
    case IEEE80211_VAP_UP:
        if (!smps->ips_connected ) {
            smps->ips_connected=TRUE;
            smps->ips_frame_resend = 0;
            OS_SET_TIMER(&smps->ips_timer,IEEE80211_PWRSAVE_TIMER_INTERVAL);
        } 
        break;
    case IEEE80211_VAP_FULL_SLEEP:
    case IEEE80211_VAP_DOWN:
        OS_CANCEL_TIMER(&smps->ips_timer);
        smps->ips_connected = FALSE;
        break;
    case IEEE80211_VAP_STOPPING:
        OS_CANCEL_TIMER(&smps->ips_timer);
        ieee80211_pwrsave_smps_event(smps, IEEE80211_SMPS_DISABLE);
        smps->ips_connected = FALSE;
        break;
    default:
        break;
    }
}


ieee80211_pwrsave_smps_t ieee80211_pwrsave_smps_attach(struct ieee80211vap *vap, u_int32_t smpsDynamic)
{
    ieee80211_pwrsave_smps_t smps;
    osdev_t os_handle = vap->iv_ic->ic_osdev;
    smps = (ieee80211_pwrsave_smps_t)OS_MALLOC(os_handle,sizeof(struct ieee80211_pwrsave_smps),0);

    if (smps) {
        OS_MEMZERO(smps, sizeof(struct ieee80211_pwrsave_smps));
        /*
         * Initialize pwrsave timer 
         */
        OS_INIT_TIMER(os_handle,
                      &smps->ips_timer,                         
                      ieee80211_pwrsave_smps_timer,
                      smps, QDF_TIMER_TYPE_WAKE_APPS);
        if (smpsDynamic && IEEE80211_HAS_DYNAMIC_SMPS_CAP(vap->iv_ic)) {
            ieee80211_vap_dynamic_mimo_ps_set(vap);
        } else {
            ieee80211_vap_dynamic_mimo_ps_clear(vap);
        }
        smps->ips_smPowerSaveState      = IEEE80211_SM_PWRSAVE_DISABLED;
        smps->ips_connected = false;
        smps->ips_vap =  vap;
        ieee80211_vap_register_event_handler(vap,ieee80211_pwrsave_smps_vap_event_handler,(void *)smps );
    }

    return smps;
}
qdf_export_symbol(ieee80211_pwrsave_smps_attach);

void ieee80211_pwrsave_smps_detach(ieee80211_pwrsave_smps_t smps)
{
    ieee80211_vap_unregister_event_handler(smps->ips_vap,ieee80211_pwrsave_smps_vap_event_handler,(void *)smps );
    OS_FREE_TIMER(&smps->ips_timer);                         
    OS_FREE(smps);
}
qdf_export_symbol(ieee80211_pwrsave_smps_detach);

#else
/* dummy declraration to keep compiler happy */
typedef int ieee80211_pwrsave_smps_dummy;

#endif
