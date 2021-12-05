/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#define IsEqualMACAddrs(arg1, arg2) (!memcmp(arg1, arg2, ETH_ALEN))
#define MACAddFmt(_sep) "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X"
#define __lbMidx(_arg, _i) (((u_int8_t *)_arg)[_i])
#define MACAddData(_arg) __lbMidx(_arg, 0), __lbMidx(_arg, 1), __lbMidx(_arg, 2), __lbMidx(_arg, 3), __lbMidx(_arg, 4), __lbMidx(_arg, 5)

#define MEGA_BITS 1000000
#define KILO_BITS 1000

void usage(void);

static const unsigned NL80211_ATTR_MAX_INTERNAL = 256;

struct wdev_info {
    enum nl80211_iftype nlmode;
    char name[IFNAMSIZ];
    int freq;
};

enum all_interface_modes {
    GET_ALL_INTERFACE_FREQUENCY=0,
    GET_ALL_2G_INTERFACE,
};
