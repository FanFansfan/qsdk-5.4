/*
 * Copyright (c) 2017,2019,2021 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 * Notifications and licenses are retained for attribution purposes only
 *
 * Copyright (c) 2008 Atheros Communications Inc.
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
 *
 * This is to be used for MBL only. In future we shall remove all RTR specific
 * definitions and use common definitions for both rtr/mbl.
 */

#ifndef ICM_RTR_DRIVER

#define TRUE 1
#define FALSE 0

/*
 * Channels are specified by frequency and attributes.
 */
struct ieee80211_ath_channel {
    u_int16_t       ic_freq;        /* setting in Mhz */
    u_int64_t       ic_flags;       /* see below */
    u_int16_t       ic_flagext;     /* see below */
    u_int8_t        ic_ieee;        /* IEEE channel number */
    int8_t          ic_maxregpower; /* maximum regulatory tx power in dBm */
    int8_t          ic_maxpower;    /* maximum tx power in dBm */
    int8_t          ic_minpower;    /* minimum tx power in dBm */
    u_int8_t        ic_regClassId;  /* regClassId of this channel */
    u_int8_t        ic_antennamax;  /* antenna gain max from regulatory */

    u_int8_t        ic_vhtop_ch_num_seg1;         /* Seg1 center channel index */
    u_int8_t        ic_vhtop_ch_num_seg2;         /* Seg2 center channel index for 80+80 MHz mode or
                                                     center channel index of operating span for 160 MHz mode */
    uint16_t        ic_vhtop_freq_seg1;           /* Seg1 center channel frequency */
    uint16_t        ic_vhtop_freq_seg2;           /* Seg2 center channel frequency index for 80+80 MHz mode or
                                                     center channel frequency of operating span for 160 MHz mode */
};
#endif /* ICM_RTR_DRIVER */


#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_6GHZ (1 << 4)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_A (1 << 5)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_B (1 << 6)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_G (1 << 7)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_PUREG (1 << 8)
#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_FHSS (1 << 9)

#define QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_EXT_PSC (1 << 10)

#define VENDOR_CHAN_FLAG2(_flag)  \
    ((uint64_t)(_flag) << 32)

#define ICM_IEEE80211_IS_CHAN_FHSS(_c) \
    ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_FHSS))

#define ICM_IEEE80211_IS_CHAN_A(_c) \
    ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_A))

#define ICM_IEEE80211_IS_CHAN_B(_c) \
    ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_B))

#define ICM_IEEE80211_IS_CHAN_PUREG(_c) \
    ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_PUREG))

#define ICM_IEEE80211_IS_CHAN_G(_c) \
    ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_G))

#define ICM_IEEE80211_IS_CHAN_2GHZ(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_2GHZ)

#define ICM_IEEE80211_IS_CHAN_5GHZ(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_5GHZ)

#define ICM_IEEE80211_IS_CHAN_6GHZ(_c) \
    ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_6GHZ))

#define ICM_IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ(_c) || ICM_IEEE80211_IS_CHAN_6GHZ(_c))

#define ICM_IEEE80211_IS_CHAN_TURBO(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_TURBO)

#define ICM_IEEE80211_IS_CHAN_HALF(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HALF)

#define ICM_IEEE80211_IS_CHAN_QUARTER(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_QUARTER)

#define ICM_IEEE80211_IS_CHAN_PASSIVE(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_PASSIVE)

#define ICM_IEEE80211_IS_CHAN_DFS(_c) \
    ((_c)->ic_flagext & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_EXT_DFS)

#define ICM_IEEE80211_IS_CHAN_PSC(_c) \
    ((_c)->ic_flagext & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_EXT_PSC)

#define ICM_IEEE80211REQ_IS_CHAN_HT20(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HT20)

#define ICM_IEEE80211REQ_IS_CHAN_HT40PLUS(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HT40PLUS)

#define ICM_IEEE80211REQ_IS_CHAN_HT40MINUS(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HT40MINUS)

#define ICM_IEEE80211_IS_CHAN_11N(_c) \
    (ICM_IEEE80211REQ_IS_CHAN_HT20(_c) || \
     ICM_IEEE80211REQ_IS_CHAN_HT40PLUS(_c) || \
     ICM_IEEE80211REQ_IS_CHAN_HT40MINUS(_c))

#define ICM_IEEE80211_IS_CHAN_11NG(_c) \
    (ICM_IEEE80211_IS_CHAN_2GHZ(_c) && ICM_IEEE80211_IS_CHAN_11N(_c))

#define ICM_IEEE80211_IS_CHAN_11NA(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ(_c) && ICM_IEEE80211_IS_CHAN_11N(_c))

#define ICM_IEEE80211_IS_CHAN_11N_CTL_CAPABLE(_c) ICM_IEEE80211REQ_IS_CHAN_HT20(_c)

#define ICM_IEEE80211_IS_CHAN_11N_CTL_U_CAPABLE(_c) ICM_IEEE80211REQ_IS_CHAN_HT40PLUS(_c)

#define ICM_IEEE80211_IS_CHAN_11N_CTL_L_CAPABLE(_c) ICM_IEEE80211REQ_IS_CHAN_HT40MINUS(_c)

#define ICM_IEEE80211_IS_CHAN_VHT40PLUS(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_VHT40PLUS)

#define ICM_IEEE80211_IS_CHAN_11AC_VHT40PLUS(_c) \
     (ICM_IEEE80211_IS_CHAN_5GHZ(_c) && ICM_IEEE80211_IS_CHAN_VHT40PLUS(_c))

#define ICM_IEEE80211REQ_IS_CHAN_VHT40MINUS(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_VHT40MINUS)

#define ICM_IEEE80211_IS_CHAN_11AC_VHT40MINUS(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_VHT40MINUS(_c))

#define ICM_IEEE80211_IS_CHAN_VHT80(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_VHT80)

#define ICM_IEEE80211_IS_CHAN_11AC_VHT80(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ(_c) && ICM_IEEE80211_IS_CHAN_VHT80(_c))

#define ICM_IEEE80211REQ_IS_CHAN_VHT160(_c) \
    ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_VHT160)

#define ICM_IEEE80211_IS_CHAN_11AC_VHT160(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_VHT160(_c))

#define ICM_IEEE80211REQ_IS_CHAN_VHT80_80(_c) \
     ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_VHT80_80)

#define ICM_IEEE80211_IS_CHAN_11AC_VHT80_80(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_VHT80_80(_c))

#define ICM_IEEE80211REQ_IS_CHAN_HE20(_c) \
     ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HE20)

#define ICM_IEEE80211_IS_CHAN_11AXA_HE20(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_HE20(_c))

#define ICM_IEEE80211REQ_IS_CHAN_HE40PLUS(_c) \
     ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HE40PLUS)

#define ICM_IEEE80211_IS_CHAN_11AXA_HE40PLUS(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_HE40PLUS(_c))

#define ICM_IEEE80211REQ_IS_CHAN_HE40MINUS(_c) \
     ((_c)->ic_flags & QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HE40MINUS)

#define ICM_IEEE80211_IS_CHAN_11AXA_HE40MINUS(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_HE40MINUS(_c))

#define ICM_IEEE80211REQ_IS_CHAN_HE80(_c) \
     ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HE80))

#define ICM_IEEE80211_IS_CHAN_11AXA_HE80(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_HE80(_c))

#define ICM_IEEE80211REQ_IS_CHAN_HE160(_c) \
     ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HE160))

#define ICM_IEEE80211_IS_CHAN_11AXA_HE160(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_HE160(_c))

#define ICM_IEEE80211REQ_IS_CHAN_HE80_80(_c) \
     ((_c)->ic_flags & VENDOR_CHAN_FLAG2(QCA_WLAN_VENDOR_CHANNEL_PROP_FLAG_HE80_80))

#define ICM_IEEE80211_IS_CHAN_11AXA_HE80_80(_c) \
    (ICM_IEEE80211_IS_CHAN_5GHZ_6GHZ(_c) && ICM_IEEE80211REQ_IS_CHAN_HE80_80(_c))
