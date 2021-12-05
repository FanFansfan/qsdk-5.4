/*
 * Copyright (c) 2011-2014,2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * copyright (c) 2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef OL_IF_UTILITY_H
#define OL_IF_UTILITY_H

#include <ol_if_athvar.h>
#include <ieee80211_var.h>
#include <init_deinit_lmac.h>
#include <ol_if_pdev.h>
#include <target_if.h>

/**
 * ol_ath_get_phymode() - gets phymode for the chan
 * @vdev: vdev object
 * @chan: pointer to the channel
 *
 * Return: QDF_STATUS_SUCCESS on success, other status on failure
 */
QDF_STATUS ol_ath_get_phymode(struct wlan_objmgr_vdev *vdev,
                              struct ieee80211_ath_channel *chan);

/**
 * ol_get_rate_code() - Gets rate code for the chan
 * @chan: pointer to the channel
 * @val: value
 *
 * Return: the rate code if success, inavlid value if failure
 */
int ol_get_rate_code(struct ieee80211_ath_channel *chan, int val);

#endif /* OL_IF_UTILITY_H */
