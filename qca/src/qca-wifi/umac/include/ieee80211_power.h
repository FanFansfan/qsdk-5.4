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

#ifndef _NET80211_IEEE80211_POWER_H_
#define _NET80211_IEEE80211_POWER_H_

#include "ieee80211_var.h"
#include <ieee80211_data.h>

#define IEEE80211_HAS_DYNAMIC_SMPS_CAP(ic)     (((ic)->ic_htcap & IEEE80211_HTCAP_C_SM_MASK) == IEEE80211_HTCAP_C_SMPOWERSAVE_DYNAMIC)

struct ieee80211_sta_power;
typedef struct ieee80211_sta_power *ieee80211_sta_power_t;

struct ieee80211_pwrsave_smps;
typedef struct ieee80211_pwrsave_smps *ieee80211_pwrsave_smps_t;

struct ieee80211_power;
typedef struct ieee80211_power *ieee80211_power_t;

typedef enum {
    IEEE80211_POWER_STA_PAUSE_COMPLETE,
    IEEE80211_POWER_STA_UNPAUSE_COMPLETE,
    IEEE80211_POWER_STA_SLEEP, /* station entered sleep */
    IEEE80211_POWER_STA_AWAKE, /* station is awake */
}ieee80211_sta_power_event_type; 

typedef enum {
    IEEE80211_POWER_STA_STATUS_SUCCESS,
    IEEE80211_POWER_STA_STATUS_TIMED_OUT,
    IEEE80211_POWER_STA_STATUS_NULL_FAILED,
    IEEE80211_POWER_STA_STATUS_DISCONNECT,
}ieee80211_sta_power_event_status; 

typedef struct _ieee80211_sta_power_event {
    ieee80211_sta_power_event_type type; 
    ieee80211_sta_power_event_status status; 
}  ieee80211_sta_power_event; 

/*
 * station power save state.
 */
typedef enum {
    IEEE80211_PWRSAVE_INIT=0,
    IEEE80211_PWRSAVE_AWAKE,
    IEEE80211_PWRSAVE_FULL_SLEEP,
    IEEE80211_PWRSAVE_NETWORK_SLEEP
} IEEE80211_PWRSAVE_STATE;             


/* initialize functions */
void ieee80211_power_attach(struct ieee80211com *);
void ieee80211_power_detach(struct ieee80211com *);
void ieee80211_power_vattach(struct ieee80211vap *, int fullsleep_enable,
			     u_int32_t, u_int32_t, u_int32_t, u_int32_t,
			     u_int32_t, u_int32_t, u_int32_t, u_int32_t);
void ieee80211_power_vdetach(struct ieee80211vap *);

typedef void (*ieee80211_sta_power_event_handler) (struct ieee80211vap *vap, ieee80211_sta_power_event *event, void *arg);

void    ieee80211_set_uapsd_flags(struct ieee80211vap *vap, u_int8_t flags);
u_int8_t ieee80211_get_uapsd_flags(struct ieee80211vap *vap);
void     ieee80211_set_wmm_power_save(struct ieee80211vap *vap, u_int8_t enable);
u_int8_t ieee80211_get_wmm_power_save(struct ieee80211vap *vap);
int ieee80211_pwrsave_uapsd_set_max_sp_length(wlan_if_t vaphandle,u_int8_t max_sp_val  );

/*
 * power save functions for node save queue.
 */
enum ieee80211_node_saveq_param {
    IEEE80211_NODE_SAVEQ_DATA_Q_LEN,
    IEEE80211_NODE_SAVEQ_MGMT_Q_LEN
};

typedef struct _ieee80211_node_saveq_info {
    u_int16_t mgt_count;
    u_int16_t data_count;
    u_int16_t mgt_len;
    u_int16_t data_len;
    u_int16_t ps_frame_count; /* frames (null,pspoll) with ps bit set */
} ieee80211_node_saveq_info;

struct node_powersave_queue {
    spinlock_t  nsq_lock;
    u_int32_t   nsq_len; /* number of queued frames */
    u_int32_t   nsq_bytes; /* number of bytes queued  */
    wbuf_t      nsq_whead;
    wbuf_t      nsq_wtail;
    u_int16_t   nsq_max_len;
    u_int16_t   nsq_num_ps_frames; /* number of frames with PS bit set */
}; 

#define  IEEE80211_NODE_POWERSAVE_QUEUE(_q)  struct node_powersave_queue _q;

void ieee80211_node_saveq_attach(struct ieee80211_node *ni);
void ieee80211_node_saveq_detach(struct ieee80211_node *ni);
int ieee80211_node_saveq_send(struct ieee80211_node *ni, int frame_type);
int ieee80211_node_saveq_drain(struct ieee80211_node *ni);
int ieee80211_node_saveq_age(struct ieee80211_node *ni);
void ieee80211_node_saveq_queue(struct ieee80211_node *ni, wbuf_t wbuf, u_int8_t frame_type);
void ieee80211_node_saveq_flush(struct ieee80211_node *ni);
void ieee80211_node_saveq_cleanup(struct ieee80211_node *ni);
void ieee80211_node_saveq_get_info(struct ieee80211_node *ni, ieee80211_node_saveq_info *info);
void ieee80211_node_saveq_set_param(struct ieee80211_node *ni, enum ieee80211_node_saveq_param param, u_int32_t val);

#if UMAC_SUPPORT_STA_SMPS
ieee80211_pwrsave_smps_t ieee80211_pwrsave_smps_attach(struct ieee80211vap *vap, u_int32_t smpsDynamic);
void ieee80211_pwrsave_smps_detach(ieee80211_pwrsave_smps_t smps);
void ieee80211_pwrsave_smps_txrx_event_handler (struct wlan_objmgr_vdev *vdev, ieee80211_vap_txrx_event *event, void *arg);
void ieee80211_pwrsave_smps_set_timer(void *arg);
#else
#define ieee80211_pwrsave_smps_attach(vap,smpsDynamic) NULL
#define ieee80211_pwrsave_smps_detach(smps)  NULL/**/
#define ieee80211_pwrsave_smps_txrx_event_handler(vdev, event, arg) NULL
#define void ieee80211_pwrsave_smps_set_timer(void *arg) NULL
#endif

#endif /* _NET80211_IEEE80211_POWER_H_ */
