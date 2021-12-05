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

#include <ol_if_utility.h>

QDF_STATUS ol_ath_get_phymode(struct wlan_objmgr_vdev *vdev,
                                     struct ieee80211_ath_channel *chan)
{
    struct ieee80211vap *vap = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct vdev_mlme_obj *vdev_mlme = NULL;
    int chan_mode;

    vap = wlan_vdev_get_mlme_ext_obj(vdev);
    if (!vap) {
        qdf_err("vap is null");
        return QDF_STATUS_E_FAILURE;
    }

    ic = vap->iv_ic;
    if (!ic) {
        qdf_err("ic is null");
        return QDF_STATUS_E_FAILURE;
    }

    vdev_mlme = vap->vdev_mlme;
    if (!vdev_mlme) {
        qdf_err("vdev mlme is null");
        return QDF_STATUS_E_FAILURE;
    }

    scn = OL_ATH_SOFTC_NET80211(ic);
    if (!scn) {
        qdf_err("scn is null");
        return QDF_STATUS_E_FAILURE;
    }

    chan_mode = ieee80211_chan2mode(chan);
    vdev_mlme->mgmt.generic.phy_mode =
                 ol_get_phymode_info(scn, chan_mode, vap->iv_256qam);

    return QDF_STATUS_SUCCESS;
}

/*
 * legacy rate table for the MCAST/BCAST rate. This table is specific to peregrine
 * chip, so its implemented here in the ol layer instead of the ieee layer.

 * This table is created according to the discription mentioned in the
 * wmi_unified.h file.

 * Here the left hand side specify the rate and the right hand side specify the
 * respective values which the target understands.
 */

static const int legacy_11b_rate_ol[][2] = {
    {1000, 0x083},
    {2000, 0x082},
    {5500, 0x081},
    {11000, 0x080},
};

static const int legacy_11a_rate_ol[][2] = {
    {6000, 0x003},
    {9000, 0x007},
    {12000, 0x002},
    {18000, 0x006},
    {24000, 0x001},
    {36000, 0x005},
    {48000, 0x000},
    {54000, 0x004},
};

static const int legacy_11bg_rate_ol[][2] = {
    {1000, 0x083},
    {2000, 0x082},
    {5500, 0x081},
    {6000, 0x003},
    {9000, 0x007},
    {11000, 0x080},
    {12000, 0x002},
    {18000, 0x006},
    {24000, 0x001},
    {36000, 0x005},
    {48000, 0x000},
    {54000, 0x004},
};

static const int ht20_11n_rate_ol[][2] = {
    {6500,  0x100},
    {13000, 0x101},
    {19500, 0x102},
    {26000, 0x103},
    {39000, 0x104},
    {52000, 0x105},
    {58500, 0x106},
    {65000, 0x107},

    {13000,  0x110},
    {26000,  0x111},
    {39000,  0x112},
    {52000,  0x113},
    {78000,  0x114},
    {104000, 0x115},
    {117000, 0x116},
    {130000, 0x117},

    {19500,  0x120},
    {39000,  0x121},
    {58500,  0x122},
    {78000,  0x123},
    {117000, 0x124},
    {156000, 0x125},
    {175500, 0x126},
    {195000, 0x127},

    {26000,  0x130},
    {52000,  0x131},
    {78000,  0x132},
    {104000, 0x133},
    {156000, 0x134},
    {208000, 0x135},
    {234000, 0x136},
    {260000, 0x137},
};

static const int ht20_11ac_rate_ol[][2] = {
/* VHT MCS0-9 NSS 1 20 MHz */
    { 6500, 0x180},
    {13000, 0x181},
    {19500, 0x182},
    {26000, 0x183},
    {39000, 0x184},
    {52000, 0x185},
    {58500, 0x186},
    {65000, 0x187},
    {78000, 0x188},
    {86500, 0x189},

/* VHT MCS0-9 NSS 2 20 MHz */
    { 13000, 0x190},
    { 26000, 0x191},
    { 39000, 0x192},
    { 52000, 0x193},
    { 78000, 0x194},
    {104000, 0x195},
    {117000, 0x196},
    {130000, 0x197},
    {156000, 0x198},
    {173000, 0x199},

 /* VHT MCS0-9 NSS 3 20 MHz */
    { 19500, 0x1a0},
    { 39000, 0x1a1},
    { 58500, 0x1a2},
    { 78000, 0x1a3},
    {117000, 0x1a4},
    {156000, 0x1a5},
    {175500, 0x1a6},
    {195000, 0x1a7},
    {234000, 0x1a8},
    {260000, 0x1a9},

 /* VHT MCS0-9 NSS 4 20 MHz */
    { 26000, 0x1b0},
    { 52000, 0x1b1},
    { 78000, 0x1b2},
    {104000, 0x1b3},
    {156000, 0x1b4},
    {208000, 0x1b5},
    {234000, 0x1b6},
    {260000, 0x1b7},
    {312000, 0x1b8},
    {344000, 0x1b9},
};

static const int ht20_11ax_rate_ol[][2] = {
/* HE MCS0-11 NSS 1 20 MHz */
      {8600, 0x200},
     {17200, 0x201},
     {25800, 0x202},
     {34400, 0x203},
     {51600, 0x204},
     {68800, 0x205},
     {77400, 0x206},
     {86000, 0x207},
    {103200, 0x208},
    {114700, 0x209},
    {129000, 0x20a},
    {143400, 0x20b},

/* HE MCS0-11 NSS 2 20 MHz */
     {17200, 0x210},
     {34400, 0x211},
     {51600, 0x212},
     {68800, 0x213},
    {103200, 0x214},
    {137600, 0x215},
    {154900, 0x216},
    {172100, 0x217},
    {206500, 0x218},
    {229400, 0x219},
    {258100, 0x21a},
    {286800, 0x21b},

/* HE MCS0-11 NSS 3 20 MHz */
     {25800, 0x220},
     {51600, 0x221},
     {77400, 0x222},
    {103200, 0x223},
    {154900, 0x224},
    {206500, 0x225},
    {232300, 0x226},
    {258100, 0x227},
    {309700, 0x228},
    {344100, 0x229},
    {387100, 0x22a},
    {430100, 0x22b},

/* HE MCS0-11 NSS 4 20 MHz */
     {34400, 0x230},
     {68800, 0x231},
    {103200, 0x232},
    {137600, 0x233},
    {206500, 0x234},
    {275300, 0x235},
    {309700, 0x236},
    {344100, 0x237},
    {412900, 0x238},
    {458800, 0x239},
    {516300, 0x23a},
    {573500, 0x23b},

/* HE MCS0-11 NSS 5 20 MHz */
     {43000, 0x240},
     {86000, 0x241},
    {129000, 0x242},
    {172100, 0x243},
    {258100, 0x244},
    {344100, 0x245},
    {387100, 0x246},
    {430100, 0x247},
    {516200, 0x248},
    {573500, 0x249},
    {645200, 0x24a},
    {716900, 0x24b},

/* HE MCS0-11 NSS 6 20 MHz */
     {51600, 0x250},
    {103200, 0x251},
    {154900, 0x252},
    {206500, 0x253},
    {309700, 0x254},
    {412900, 0x255},
    {464600, 0x256},
    {516200, 0x257},
    {619400, 0x258},
    {688200, 0x259},
    {774300, 0x25a},
    {860300, 0x25b},

/* HE MCS0-11 NSS 7 20 MHz */
     {60200, 0x260},
    {120400, 0x261},
    {180700, 0x262},
    {240900, 0x263},
    {361300, 0x264},
    {481800, 0x265},
    {542000, 0x266},
    {602200, 0x267},
    {722600, 0x268},
    {802900, 0x269},
    {903300, 0x26a},
   {1003700, 0x26b},

/* HE MCS0-11 NSS 8 20 MHz */
     {68800, 0x270},
    {137600, 0x271},
    {206500, 0x272},
    {275300, 0x273},
    {412900, 0x274},
    {550600, 0x275},
    {619400, 0x276},
    {688200, 0x277},
    {825900, 0x278},
    {917600, 0x279},
   {1032400, 0x27a},
   {1147100, 0x27b},
};

#define NUM_RATE_TABS 4
int ol_get_rate_code(struct ieee80211_ath_channel *chan, int val)
{
    uint32_t chan_mode;
    int i = 0, j = 0, found = 0, array_size = 0;
    int *rate_code = NULL;

    struct ol_rate_table {
        int *table;
        int size;
    } rate_table [NUM_RATE_TABS];

    if (!chan) {
        qdf_err("Channel is NULL\n");
        return EINVAL;
    }

    OS_MEMZERO(&rate_table[0], sizeof(rate_table));

    chan_mode = ieee80211_chan2mode(chan);

    switch (chan_mode)
    {
        case IEEE80211_MODE_11B:
            {
                /* convert rate to index */
                rate_table[3].size = sizeof(legacy_11b_rate_ol)/sizeof(legacy_11b_rate_ol[0]);
                rate_table[3].table = (int *)&legacy_11b_rate_ol;
            }
            break;

        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_G:
            {
                /* convert rate to index */
                rate_table[3].size = sizeof(legacy_11bg_rate_ol)/sizeof(legacy_11bg_rate_ol[0]);
                rate_table[3].table = (int *)&legacy_11bg_rate_ol;
            }
            break;

        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
            {
                /* convert rate to index */
                rate_table[3].size = sizeof(legacy_11a_rate_ol)/sizeof(legacy_11a_rate_ol[0]);
                rate_table[3].table = (int *)&legacy_11a_rate_ol;
            }
            break;

        case IEEE80211_MODE_11AXG_HE20      :
        case IEEE80211_MODE_11AXA_HE40PLUS  :
        case IEEE80211_MODE_11AXA_HE20      :
        case IEEE80211_MODE_11AXA_HE40MINUS :
        case IEEE80211_MODE_11AXG_HE40PLUS  :
        case IEEE80211_MODE_11AXG_HE40MINUS :
        case IEEE80211_MODE_11AXA_HE40      :
        case IEEE80211_MODE_11AXG_HE40      :
        case IEEE80211_MODE_11AXA_HE80      :
        case IEEE80211_MODE_11AXA_HE160     :
        case IEEE80211_MODE_11AXA_HE80_80   :
            {
                if (IEEE80211_IS_CHAN_6GHZ(chan)) {
                    rate_table[2].size = sizeof(ht20_11ax_rate_ol)/sizeof(ht20_11ax_rate_ol[0]);
                    rate_table[2].table = (int *)&ht20_11ax_rate_ol;
                } else {
                    rate_table[0].size = sizeof(ht20_11ax_rate_ol)/sizeof(ht20_11ax_rate_ol[0]);
                    rate_table[0].table = (int *)&ht20_11ax_rate_ol;
                }
            }

        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            {
                if (!IEEE80211_IS_CHAN_6GHZ(chan)) {
                    rate_table[1].size = sizeof(ht20_11ac_rate_ol)/sizeof(ht20_11ac_rate_ol[0]);
                    rate_table[1].table = (int *)&ht20_11ac_rate_ol;
                }
            }

        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
            {
                if (!IEEE80211_IS_CHAN_6GHZ(chan)) {
                    rate_table[2].size = sizeof(ht20_11n_rate_ol)/sizeof(ht20_11n_rate_ol[0]);
                    rate_table[2].table = (int *)&ht20_11n_rate_ol;
                }
            }

            if (IEEE80211_IS_CHAN_5GHZ(chan)) {
                rate_table[3].size = sizeof(legacy_11a_rate_ol)/sizeof(legacy_11a_rate_ol[0]);
                rate_table[3].table = (int *)&legacy_11a_rate_ol;
            } else {
                rate_table[3].size = sizeof(legacy_11bg_rate_ol)/sizeof(legacy_11bg_rate_ol[0]);
                rate_table[3].table = (int *)&legacy_11bg_rate_ol;
            }

            break;

        default:
        {
            qdf_info("Invalid channel mode 0x%x", chan_mode);
            break;
        }
    }

    for (j = NUM_RATE_TABS - 1; ((j >= 0) && !found) && rate_table[j].table; j--) {
        array_size = rate_table[j].size;
        rate_code = rate_table[j].table;
        for (i = 0; i < array_size; i++) {
            /* Array Index 0 has the rate and 1 has the rate code.
             * The variable rate has the rate code which must be converted to actual rate*/
            if (val == *rate_code) {
                val = *(rate_code + 1);
                found = 1;
                break;
            }
            rate_code += 2;
        }
    }

    if(!found) {
        qdf_err("Rate code not found\n");
        return EINVAL;
    }
    return val;
}
