/*
* Copyright (c) 2011, 2018 Qualcomm Innovation Center, Inc.
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

#ifndef _NET80211_IEEE80211_RSN_H_
#define _NET80211_IEEE80211_RSN_H_

#include <osdep.h>
#include <ieee80211_defines.h>

u_int8_t *ieee80211_rsnx_override(u_int8_t *frm, struct ieee80211vap *vap);
ieee80211_cipher_type ieee80211_get_current_mcastcipher(struct ieee80211vap *vap);
bool ieee80211_auth_mode_needs_upper_auth( struct ieee80211vap *vap );
#endif /* _NET80211_IEEE80211_RSN_H_ */
