/*
 * Copyright (c) 2011,2017-2018,2021 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * Copyright (c) 2005, Atheros Communications Inc.
 * All Rights Reserved.
 *
 */

#ifndef _IEEE80211_AME_API_H_
#define _IEEE80211_AME_API_H_

#include "ieee80211_api.h"

/*
 *  API for association state machine  to handle a stations association to
 *  an infrastructure network.
 */
struct _wlan_assoc_sm;
typedef struct _wlan_assoc_sm *wlan_assoc_sm_t;

typedef enum _wlan_assoc_sm_event_type {
     WLAN_ASSOC_SM_EVENT_SUCCESS,       /* the vap is succesfully assocated to the AP  */
     WLAN_ASSOC_SM_EVENT_FAILED,        /* the vap is failed to associate */
     WLAN_ASSOC_SM_EVENT_DISCONNECT,    /* disconnected upon request*/
     WLAN_ASSOC_SM_EVENT_REJOINING,     /* rejoining to the same AP (due to deauth/disassoc from the AP)*/
     WLAN_ASSOC_SM_EVENT_ASSOC_REJECT,  /* Assoc is reject by AP */
} wlan_assoc_sm_event_type;

typedef enum _wlan_assoc_sm_event_disconnect_reason {
     WLAN_ASSOC_SM_REASON_NONE,   /* no reason code */
     WLAN_ASSOC_SM_REASON_ASSOC_FAILED,   /* assoc failed */
     WLAN_ASSOC_SM_REASON_AUTH_FAILED,    /* auth failed */
     WLAN_ASSOC_SM_REASON_ASSOC_REJECT,   /* Assoc rejected by AP*/
     WLAN_ASSOC_SM_REASON_BEACON_MISS,    /* beacon miss */
     WLAN_ASSOC_SM_REASON_DEAUTH,         /* AP deauthed */
     WLAN_ASSOC_SM_REASON_DISASSOC,       /* AP disassoced */
} wlan_assoc_sm_event_disconnect_reason;

typedef struct _wlan_assoc_sm_event {
     wlan_assoc_sm_event_type        event;
     wlan_assoc_sm_event_disconnect_reason  reason;
     int  reasoncode;  /* 802.11 reason code */
} wlan_assoc_sm_event;

typedef enum _wlan_assoc_sm_param {
    PARAM_MAX_ASSOC_ATTEMPTS,/* numbers of assoc attmpts before failing */
    PARAM_MAX_AUTH_ATTEMPTS, /* numbers of auth attmpts before failing */
    PARAM_MAX_TSFSYNC_TIME,  /* in msec */
    PARAM_MAX_MGMT_TIME,     /* in msec */
    PARAM_CURRENT_STATE,     /* current state*/
} wlan_assoc_sm_param;

#define   WLAN_ASSOC_STATE_INIT  0
#define   WLAN_ASSOC_STATE_TXCHANSWITCH  1
#define   WLAN_ASSOC_STATE_REPEATER_CAC  2
#define   WLAN_ASSOC_STATE_AUTH  3
#define   WLAN_ASSOC_STATE_ASSOC  4
#define   WLAN_ASSOC_STATE_RUN  5
#define   WLAN_ASSOC_STATE_SCAN  6

/**
 * @creates a handle for connection staite machine for a given vap.
 * ARGS :
 *  wlan_if_t    : handle to the vap .
 * RETURNS:
 *  on success return an opaque handle to newly created sm.
 *  on failure returns NULL. there can only be one state machine
 *  per vap.
 */
wlan_assoc_sm_t wlan_assoc_sm_create(osdev_t oshandle, wlan_if_t vaphandle);

/**
 * @delete  a handle for stame machine.
 * ARGS :
 *  wlan_assoc_sm_t    : handle to the state machine .
 * RETURNS:
 */
void  wlan_assoc_sm_delete(wlan_assoc_sm_t smhandle);

/**
 * @start a state machine.
 * ARGS :
 *  wlan_assoc_sm_t   : handle to the state machine .
 *  wlan_scan_entry_t  : scan entry of the AP to associate.
 *  curbssid           : current bssid. if not null then the SM
 *                       will start with reassoc req.
 *
 * RETURNS:
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_assoc_sm_start(wlan_assoc_sm_t smhandle, wlan_scan_entry_t scan_entry, u_int8_t *curbssid);

/**
 * @stop a state machine.
 * ARGS :
 *  wlan_assoc_sm_t : handle to the state machine .
 *  disassoc        : if true then the SM will send disassoc
 *                    frame to AP.
 *
 * RETURNS:
 *  on success returns 0.
 *  on failure returns a negative value.
 */
int wlan_assoc_sm_stop(wlan_assoc_sm_t smhandle, u_int32_t flags);

/* flag definitions */
#define IEEE80211_ASSOC_SM_STOP_ASYNC 0x0     /* stop the sm asynchronously */
#define IEEE80211_ASSOC_SM_STOP_DISASSOC 0x1 /* send disassoc while stopping */
/*
 * stop the SM synchronously.runs the SM event handler in the context of the calling thread.
 * WARNING: this should only be used on operating systems that runa the driver in single thread.
 *       using this flags on multi threaded/SMP systems will be a disaster.
 *
 */
#define IEEE80211_ASSOC_SM_STOP_SYNC 0x2

/*
 *  API for connetion state machine  to handle a stations wireless connection.`
 *  this State Machine handles roaming case too.
 */
struct _wlan_connection_sm;
typedef struct _wlan_connection_sm *wlan_connection_sm_t;

typedef enum _wlan_connection_sm_event_type {
     WLAN_CONNECTION_SM_EVENT_CONNECTION_UP,      /* the connection/link is up and running */
     WLAN_CONNECTION_SM_EVENT_CONNECTION_DOWN,    /* the connection/link is down, */
     WLAN_CONNECTION_SM_EVENT_CONNECTION_LOST,    /* connection is lost but trying
                                                     to roam to a new AP  */
     WLAN_CONNECTION_SM_EVENT_ROAMING,            /* roaming to a new  AP */
     WLAN_CONNECTION_SM_EVENT_ROAM,               /* roamed to new AP and connection is UP again */
     WLAN_CONNECTION_SM_EVENT_CONNECTION_RESET,   /* rejoined to the same AP */
     WLAN_CONNECTION_SM_EVENT_REJOINING,          /* rejoining to the same AP */
     WLAN_CONNECTION_SM_EVENT_ENH_IND_STOP,     /* Enhanced Independent Repeater stop */
     WLAN_CONNECTION_SM_EVENT_ENH_IND_START,    /* Enhanced Independent Repeater start */
} wlan_connection_sm_event_type;

typedef enum _wlan_connection_sm_event_disconnect_reason {
     WLAN_CONNECTION_SM_CONNECT_TIMEDOUT,   /* connection timed out */
     WLAN_CONNECTION_SM_RECONNECT_TIMEDOUT, /* connection timed out */
     WLAN_CONNECTION_SM_DISCONNECT_REQUEST, /* connection timed out */
     WLAN_CONNECTION_SM_ASSOC_REJECT,       /* assoc reject  */
} wlan_connection_sm_event_disconnect_reason;

typedef struct _wlan_connection_sm_event {
     wlan_connection_sm_event_type           event;
     wlan_connection_sm_event_disconnect_reason  disconnect_reason;
     wlan_assoc_sm_event_disconnect_reason  assoc_reason;
     wlan_scan_entry_t  roam_ap; /* scan entry of the AP roaming to */
     int  reasoncode;  /* 802.11 reason code */
} wlan_connection_sm_event;

typedef void (*wlan_connection_sm_event_handler) (wlan_connection_sm_t smhandle, os_if_t vaphandle,
                wlan_connection_sm_event *smevent);

typedef enum _wlan_connection_sm_param {
    WLAN_CONNECTION_PARAM_BGSCAN_SNR_THRESH,         /* snr threshold for bg scan */
    WLAN_CONNECTION_PARAM_BGSCAN_SNR_FORCED_SCAN,    /* snr threshold below which the bg scan is a forced scan*/
    WLAN_CONNECTION_PARAM_BGSCAN_POLICY,             /* type of bg scan */
    WLAN_CONNECTION_PARAM_BGSCAN_PERIOD,             /* bg scan period in seconds  */
    WLAN_CONNECTION_PARAM_BGSCAN_MIN_DWELL_TIME,     /* bg scan mindwell in milli seconds  */
    WLAN_CONNECTION_PARAM_BGSCAN_MAX_DWELL_TIME,     /* bg scan maxdwell in milli seconds  */
    WLAN_CONNECTION_PARAM_BGSCAN_MIN_REST_TIME,      /* bg scan minrest in milli seconds  */
    WLAN_CONNECTION_PARAM_BGSCAN_MAX_REST_TIME,      /* bg scan maxrest in milli seconds  */
    WLAN_CONNECTION_PARAM_BGSCAN_SNR_CHANGE_THRESH,  /* change in snr value to trigger bg scan */
    WLAN_CONNECTION_PARAM_ROAM_THRESH,               /* rssi threshold for roaming  */
    WLAN_CONNECTION_PARAM_ROAM_CHECK_PERIOD,         /* how periodically need to check for roaming */
    WLAN_CONNECTION_PARAM_SCAN_CACHE_VALID_TIME,     /* time limit for scan cache validity */
    WLAN_CONNECTION_PARAM_CONNECT_TIMEOUT,           /* time limit for connection attempt */
    WLAN_CONNECTION_PARAM_RECONNECT_TIMEOUT,         /* time limit for re connection attempt */
    WLAN_CONNECTION_PARAM_CONNECTION_LOST_TIMEOUT,
					      /* time to wait after losing the connection and before sending the
						     connection lost notification */
    WLAN_CONNECTION_PARAM_CURRENT_STATE,
    WLAN_CONNECTION_PARAM_BAD_AP_TIMEOUT,            /* time in msec to wait before considering a bad AP */
                                                     /* bad AP is the AP with which an attempt to assoc has failed */
} wlan_connection_sm_param;

/*
 * default params.
 */
#define   DEFAULT_SNR_THRESH 20
#define   DEFAULT_SNR_CHANGE  4
#define   DEFAULT_BGSCAN_PERIOD 300000 /* 5 mins */
#define   MIN_BGSCAN_PERIOD  10000     /* 10 secs */
#define   DEFAULT_BGSCAN_MIN_DWELL_TIME 50
#define   DEFAULT_BGSCAN_MAX_DWELL_TIME 800
#define   DEFAULT_BGSCAN_MIN_REST_TIME 100
#define   DEFAULT_BGSCAN_MAX_REST_TIME 200
#define   DEFAULT_BGSCAN_POLICY WLAN_CONNECTION_BGSCAN_POLICY_PERIODIC
#define   DEFAULT_ROAM_THRESH   15
#define   DEFAULT_ROAM_CHECK_PERIOD  1000  /* 1 second */
#define   MIN_ROAM_CHECK_PERIOD  100       /* 100msec */
#define   DEFAULT_SCAN_CACHE_VALID_TIME 60000 /* 60 seconds */
#define   MIN_SCAN_CACHE_VALID_TIME 3000 /* 3 seconds */
#define   DEFAULT_CONNECT_TIMEOUT   6000 /* 6 seconds */
#define   DEFAULT_RECONNECT_TIMEOUT 6000 /* 6 seconds */
#define   DEFAULT_LOST_CONNECTION_NOTIFICATION_TIMEOUT 2000 /* 2 seconds */
#define   MIN_CONNECT_TIMEOUT     0
#define   MIN_RECONNECT_TIMEOUT   0
#define   MIN_CONNECTION_LOST_TIMEOUT   0 /* 0 seconds */
#define   DEFAULT_CONNECTION_LOST_TIMEOUT   2000 /* 2 seconds */
#define   SCAN_RESTART_TIME       3000
#ifdef CONFIG_WIFI_EMULATION_WIFI_3_0
#define   DEFAULT_BAD_AP_TIMEOUT  0 /* Disable on VP */
#else
#define   DEFAULT_BAD_AP_TIMEOUT  30000 /* 30 seconds */
#endif
#define   WLAN_CLEAR_LAST_SCAN_SNR_DELTA  10

typedef enum _wlan_connection_sm_bgscan_policy {
    WLAN_CONNECTION_BGSCAN_POLICY_NONE,        /* no bg scan */
    WLAN_CONNECTION_BGSCAN_POLICY_PERIODIC,    /* scan periodically as per the param BGSCAN_PERIOD  */
    WLAN_CONNECTION_BGSCAN_POLICY_SNR_CHANGE, /* scan only when SNR changes by the param BGSCAN_RSSI_CHANGE_THRESH */
    WLAN_CONNECTION_BGSCAN_POLICY_BOTH,        /* both the above policies */
    WLAN_CONNECTION_BGSCAN_POLICY_MAX,
} wlan_connection_sm_bgscan_policy;

/*
 * bg scan (back ground scans are done to keep the scan cache recent to be
 * used for quick roaming.the API allows different g scan policies.
 * 1) POLICY_PERIODIC: when the snr is below the value set by BGSCAN_SNR_THRESH
 *    bg scan is done periodically at the periodicity specified by PARAM_BGSCAN_PERIOD.
 * 2) POLICY_SNR_CHANGE : when the snr is below the value set by BGSCAN_SNR_THRESH
 *    bg scan is done only when the snr changes by PARAM_BGSCAN_SNR_CHANGE_THRESH from
 *    last scan.
 * 3) POLICY_BOTH: When the snr is below the value set by BGSCAN_SNR_THRESH
 *    bg scan is done when the snr changes by PARAM_BGSCAN_SNR_CHANGE_THRESH from
 *    last scan  and also done periodically.
 * no bg scans are triggered when the snr is above BGSCAN_SNR_THRESH .To run the
 * BG scan all the time , set the BGSCAN_SNR_THRESH to  a value > 128.
 */

/* flag definitions */
/*
 * stop the SM synchronously.runs the SM event handler in the context of the calling thread.
 * WARNING: this should only be used on operating systems that runa the driver in single thread.
 *       using this flags on multi threaded/SMP systems will be a disaster.
 *
 */
#define IEEE80211_CONNECTION_SM_STOP_ASYNC 0x0
#define IEEE80211_CONNECTION_SM_STOP_SYNC 0x1
#define IEEE80211_CONNECTION_SM_STOP_NO_DISASSOC 0x2

#if UMAC_SUPPORT_WPA3_STA
/**
 * @Set sae maximum auth retries(attempts)
 * ARGS:
 *  wlan_connection_sm_t : handle to set the state machine
 *  is_sae               : 1 if sae is enabled else 0
 */
void wlan_assoc_sm_sae_max_auth_retry(wlan_assoc_sm_t smhandle, bool is_sae);
#endif

#endif

void wlan_assoc_sm_msgq_drain(wlan_assoc_sm_t smhandle);

