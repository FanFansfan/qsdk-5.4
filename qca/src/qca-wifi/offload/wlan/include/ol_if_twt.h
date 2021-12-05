/*
 * Copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
 * All Rights Reserved
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 * Copyright (c) 2011, Atheros Communications Inc.
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

#ifndef __OL_IF_TWT_H
#define __OL_IF_TWT_H

#include <ol_if_athvar.h>
#include <target_type.h>
#include <init_deinit_lmac.h>
#include <target_if.h>
#include <ol_ath_ucfg.h>
#include <cfg_ucfg_api.h>

#ifdef WLAN_SUPPORT_TWT
/**
 * init_twt_default_config - Populate the cfg values of twt
 * @sc: soc handle
 *
 * This function used to populate the cfg vlaues of twt
 * parameters.
 *
 * Return: none
 */
void init_twt_default_config(ol_ath_soc_softc_t *soc);

/**
 * ol_ath_twt_enable_command - Sends the twt enable command
 * @scn: Pointer to net80211 softc object
 *
 * This function used to send twt enable command to fw.
 *
 * Return: 0 on success
 */
int ol_ath_twt_enable_command(struct ol_ath_softc_net80211 *scn);

/**
 * ol_ath_twt_attach - twt function
 * @ic: pointer to ieee80211com struct
 *
 * This function used to initialize twt.
 *
 * Return: none
 */
void ol_ath_twt_attach(struct ieee80211com *ic);

/**
 * ol_ath_soc_twt_attach - twt function
 * @soc: soc_handle
 *
 * This function used to initialize twt.
 *
 * Return: none
 */
void ol_ath_soc_twt_attach(ol_ath_soc_softc_t *soc);

#else
static inline void init_twt_default_config(ol_ath_soc_softc_t *soc)
{
}

static inline int ol_ath_twt_enable_command(struct ol_ath_softc_net80211 *scn)
{
        return 0;
}

static inline void ol_ath_twt_attach(struct ieee80211com *ic)
{
}

static inline void ol_ath_soc_twt_attach(ol_ath_soc_softc_t *soc)
{
}
#endif /* WLAN_SUPPORT_TWT */
#endif
