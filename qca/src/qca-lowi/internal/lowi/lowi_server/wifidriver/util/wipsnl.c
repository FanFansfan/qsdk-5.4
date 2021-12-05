/*====*====*====*====*====*====*====*====*====*====*====*====*====*====*====*

   WiFi Positioning NL80211 Interface - C style functions

   GENERAL DESCRIPTION
   This file contains components fow NL80211 interface which are left in
   C instead of C++.

   Copyright (c) 2012-2013, 2016-2018 Qualcomm Technologies, Inc.
   All Rights Reserved.
   Confidential and Proprietary - Qualcomm Technologies, Inc.

   (c) 2012-2013 Qualcomm Atheros, Inc.
   All Rights Reserved.
   Qualcomm Atheros Confidential and Proprietary.

   Copyright (c) 2007, 2008        Johannes Berg
   Copyright (c) 2007              Andy Lutomirski
   Copyright (c) 2007              Mike Kershaw
   Copyright (c) 2008-2009         Luis R. Rodriguez

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

* Driver interaction with Linux nl80211/cfg80211
 * Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
=============================================================================*/

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>
#include <stdbool.h>
#include "wipsiw.h"

#undef LOG_TAG
#define LOG_TAG "LOWI-Scan"

/*=============================================================================================
 * Function description:
 *   Callback function with family and group info of the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
int wips_family_handler(struct nl_msg *msg, void *arg)
{
  struct handler_args *grp = (struct handler_args *)arg;
  struct nlattr *tb[CTRL_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *mcgrp;
  int rem_mcgrp;

  nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb[CTRL_ATTR_MCAST_GROUPS])
    return NL_SKIP;

  nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
    struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

    nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
              (struct nlattr *)nla_data(mcgrp), nla_len(mcgrp), NULL);

    if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
        !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
        continue;

    if (strncmp((const char *)nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
      continue;

    grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
    break;
  }

  return NL_SKIP;
}

/*=============================================================================================
 * Function description:
 *   Callback function with wiphy info of the NL80211 Interface.
 *
 * Parameters:
 *   msg: pointer to the msg that contains the requested info
 *   arg: data passed when set up the callback
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
int wiphy_info_handler(struct nl_msg *msg, void *arg)
{
  struct nlattr *tb[NL80211_ATTR_MAX + 1];

  struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
  struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *nl_band;
  struct nlattr *nl_freq;
  int rem_band;
  int rem_freq;
  uint32_t freq;

  static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
    [NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
    [NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
    [NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = { .type = NLA_FLAG },
    [NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
    [NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
  };

  s_ch_info* ch_info = (s_ch_info*)arg;
  nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
      genlmsg_attrlen(gnlh, 0), NULL);

  if (!tb[NL80211_ATTR_WIPHY_BANDS])
  {
    return NL_SKIP;
  }

  nla_for_each_nested (nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band)
  {
    nla_parse(tb_band, NL80211_BAND_ATTR_MAX, (struct nlattr *)nla_data(nl_band),
        nla_len(nl_band), NULL);
    nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq)
    {
      nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, (struct nlattr *)nla_data(nl_freq),
          nla_len(nl_freq), freq_policy);
      if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
      {
        continue;
      }
      freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
      if (freq <= 3000)
      {
        // 2G frequency
        ch_info->arr_2g_ch[ch_info->num_2g_ch++] = freq;
      }
      else if (freq > 4000 && freq < 6000)
      {
        // 5G frequency
        ch_info->arr_5g_ch[ch_info->num_5g_ch++] = freq;
      }
    }
  }

  return NL_SKIP;
}

/*=============================================================================================
 * Function description:
 *   Parse nested NL attribute to BSS fields
 *
 * Parameters:
 *   nla: Nested NL attributes
 *   bss: Parsed bss fields
 *
 * Return value:
 *    error code: NL error code
 =============================================================================================*/
int wips_parse_bss(struct nlattr *bss[], struct nlattr *nla)
{
  static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
                [NL80211_BSS_TSF] = { .type = NLA_U64 },
                [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
                [NL80211_BSS_BSSID] = { .type = NLA_UNSPEC },
                [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
                [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
                [NL80211_BSS_INFORMATION_ELEMENTS] = { .type = NLA_UNSPEC },
                [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
                [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
                [NL80211_BSS_STATUS] = { .type = NLA_U32 },
                [NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
                [NL80211_BSS_BEACON_IES] = { .type = NLA_UNSPEC },
  };

  return nla_parse_nested(bss, NL80211_BSS_MAX, nla, bss_policy);
}
