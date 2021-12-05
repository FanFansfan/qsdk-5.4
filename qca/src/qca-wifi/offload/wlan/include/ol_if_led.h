/*
 * copyright (c) 2017-2020 Qualcomm Innovation Center, Inc.
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

#ifndef __OL_IF_LED_H
#define __OL_IF_LED_H

#include <ol_if_athvar.h>
#include <target_type.h>
#include <init_deinit_lmac.h>
#include <target_if.h>
#include <wlan_reg_ucfg_api.h>
#include <ol_regdomain_common.h>
#include <ol_ath.h>
#include <hif.h>

#if CONFIG_LEDS_IPQ
#include <drivers/leds/leds-ipq.h>
#endif

#if OL_ATH_SUPPORT_LED

#define HAWKEYE_2G_LED 3
#define HAWKEYE_5G_LED 4

/**
 * ol_ath_led_init - init function
 *
 * @scn: Pointer to net80211 softc object
 * @soc: soc soft context object
 * @target_type: unsigned int to represent target
 *
 * This function is used to configure the gpio for output
 * mode and initialized the led blink and poll timer.
 *
 * Return: None
 */
void ol_ath_led_init(struct ol_ath_soc_softc *soc,
		     struct ol_ath_softc_net80211 *scn,
                     uint32_t target_type);

/**
 * ol_ath_led_event - Tx and Rx event
 *
 * @scn: Pointer to net80211 softc object
 * @event: enum type to represent tx and rx
 *
 * This function is used to capture the tx and rx events
 * and determines the on and off duration from the blinking
 * rate table.
 *
 * Return: None
 */
void ol_ath_led_event(struct ol_ath_softc_net80211 *scn, OL_LED_EVENT event);

/**
 * ol_ath_clear_led_params() - Clear led parameters
 *
 * @scn: Pointer to net80211 softc object
 *
 * This function is used to clear the led parameters
 *
 * Return: None
 */
void ol_ath_clear_led_params(struct ol_ath_softc_net80211 *scn);
#endif
#endif
