/*
* Copyright (c) 2011, 2018, 2020 Qualcomm Innovation Center, Inc.
* All Rights Reserved.
* Confidential and Proprietary - Qualcomm Innovation Center, Inc.
*
*/

/*
 *  Copyright (c) 2008 Atheros Communications Inc. 
 * All Rights Reserved.
 * 
 * 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */
#include "ieee80211_options.h"

#ifndef _IEEE80211_IE_UTILS_H
#define _IEEE80211_IE_UTILS_H

/**
 * for a given management frame type, return pointer pointing to the begining of ie data 
 * in the frame  
 * @param wbuf    : wbuf containing the frame.
 * @param subtype : subtye of the management frame.
 * @return pointer to the begining of ie data.
*/
u_int8_t *ieee80211_mgmt_iedata(wbuf_t wbuf, int subtype);

/**
 * Add user RNR entry into database
 * @param ic:   radio
 * @param uid:  unique id
 * @param buf:  buffer of RNR entry
 * @param len:  buffer length
 * @return:     0-success, -1-fail
*/
int ieee80211_add_user_rnr_entry(struct ieee80211com *ic, u_int8_t uid,
                                 u_int8_t *buf, u_int32_t len);

/**
 * Delete user RNR entry from database
 * @param ic:   radio
 * @param uid:  unique id
 * @return:     0-success, -1-fail
*/
int ieee80211_del_user_rnr_entry(struct ieee80211com *ic, u_int8_t uid);

/**
 * Dump all user RNR entries in database
 * @param ic:   radio
*/
void ieee80211_dump_user_rnr_entries(struct ieee80211com *ic);


#endif
