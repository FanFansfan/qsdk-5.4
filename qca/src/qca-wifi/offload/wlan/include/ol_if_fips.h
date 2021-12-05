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

#ifndef OL_IF_FIPS_H
#define OL_IF_FIPS_H

#include <ol_if_athvar.h>
#include <ieee80211_var.h>
#include <init_deinit_lmac.h>
#include <ol_if_pdev.h>
#include <target_if.h>

/**
 * ol_ath_fips_event_handler() - FIPS event handler
 * @sc:
 * @evt_buf: event buffer
 * @datalen: data length
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_fips_event_handler(ol_soc_t sc, u_int8_t *evt_buf, u_int32_t datalen);

/**
 * ol_ath_encrypt_decrypt_data_rsp_event_handler() - Encrypt/Decrypt FIPS data event handler
 * @sc:
 * @evt_buf: event buffer
 * @datalen: data length
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_encrypt_decrypt_data_rsp_event_handler(ol_scn_t sc, u_int8_t *evt_buf, u_int32_t datalen);

/**
 * ol_ath_fips_test() - Check and proceed with fips data according to the fips mode
 * @ic: ic variable
 * @vap: vap structure
 * @fips_buf: FIPS buffer
 *
 * Return: 0 if success, other value if failure
 */
int ol_ath_fips_test(struct ieee80211com *ic, wlan_if_t vap, struct ath_fips_cmd *fips_buf);

#endif /* OL_IF_FIPS_H */
